#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Connector IPsec — przenośne GUI do libreswana (IKEv1 aggressive + XAUTH).

Bez instalacji. Uruchom jako zwykły użytkownik:

    ./vpn-connector-ipsec.py

Wszystko, co wymaga roota (zapis /etc/ipsec.d, ipsec, ip, systemctl), robi ten
sam plik uruchomiony ponownie przez pkexec w trybie --helper. GUI nigdy nie
działa z uprawnieniami roota.

Wszystkie dane lądują w folderze "dane/" obok tego skryptu:
    dane/profile.json      — profile bez haseł
    dane/sekrety.enc       — hasła, zaszyfrowane AES-256 (openssl, PBKDF2)
    dane/stan.json         — stan połączenia
    dane/ostatni-log.txt   — log ostatniej sesji
    dane/tray.pid          — PID wskaźnika w trayu (KDE Plasma), jedna instancja

GUI przy starcie odpala też wskaźnik w trayu (ten sam plik, tryb --tray) —
żyje niezależnie od okna, dopóki nie wybierzesz w nim "Zamknij".
"""

import base64
import getpass
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time

APP_ID = "org.example.vpnconnectoripsec"
SELF = os.path.abspath(__file__)
APP_DIR = os.path.dirname(SELF)

CONF_DIR = "/etc/ipsec.d"
IPSEC_CONF = "/etc/ipsec.conf"
PREFIX = "bvpn-"
POLICY_INCLUDE = "/etc/crypto-policies/back-ends/libreswan.config"

NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
ID_RE = re.compile(r"^[@%]?[A-Za-z0-9._:@-]{1,80}$")
USER_RE = re.compile(r"^[A-Za-z0-9._@-]{1,64}$")
ALGO_RE = re.compile(r"^[A-Za-z0-9;,_+.-]{1,200}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9._@:-]{1,32}$")
NUM_RE = re.compile(r"^[0-9]{1,9}$")

# (etykieta, ike, phase2alg)
PRESETS = [
    ("AES-256 / SHA-512 / ECP-256  (Twoja działająca konfiguracja)",
     "aes256-sha512;ecp256", "aes256-sha512"),
    ("AES-256 / SHA-256 / MODP-2048", "aes256-sha256;modp2048", "aes256-sha256"),
    ("AES-256 / SHA-256 / ECP-256", "aes256-sha256;ecp256", "aes256-sha256"),
    ("AES-128 / SHA-256 / MODP-2048", "aes128-sha256;modp2048", "aes128-sha256"),
    ("AES-256 / SHA-1 / MODP-1024  (stare FortiGate)", "aes256-sha1;modp1024", "aes256-sha1"),
    ("AES-128 / SHA-1 / MODP-1024  (stare FortiGate)", "aes128-sha1;modp1024", "aes128-sha1"),
    ("3DES / SHA-1 / MODP-1024  (ostateczność)", "3des-sha1;modp1024", "3des-sha1"),
]
CUSTOM_LABEL = "Własne (edytuj pola poniżej)"

CRYPT_MODES = ["machine", "master", "none"]
CRYPT_LABELS = [
    "Klucz powiązany z komputerem (bez pytania o hasło)",
    "Hasło główne (pytane raz po starcie aplikacji)",
    "Nie zapisuj haseł w ogóle",
]

DEFAULT_PROFILE = {
    "name": "nowy-profil",
    "right": "",
    "rightsubnet": "10.0.0.0/8",
    "leftid": "@moj-klucz",
    "rightid": "@moj-klucz",
    "username": "",
    "iface": "auto",
    "vpn_ip": "auto",
    "ike": "aes256-sha512;ecp256",
    "phase2alg": "aes256-sha512",
    "pfs": True,
    "aggressive": True,
    "encapsulation": True,
    "ikelifetime": "86400",
    "salifetime": "43200",
    "dpddelay": "5",
    "dpdtimeout": "15",
    "restart_service": True,
    "setup_routes": True,
}


class Fatal(Exception):
    pass


# ==========================================================================
#  ŚCIEŻKI — wszystko obok skryptu
# ==========================================================================

def data_dir():
    """Folder 'dane' obok skryptu. Gdy nie da się tam pisać — ~/.config."""
    candidate = os.path.join(APP_DIR, "dane")
    try:
        os.makedirs(candidate, exist_ok=True)
        probe = os.path.join(candidate, ".zapis-test")
        with open(probe, "w") as fh:
            fh.write("")
        os.unlink(probe)
        return candidate
    except OSError:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
        fallback = os.path.join(base, "vpn-connector-ipsec")
        try:
            os.makedirs(fallback, exist_ok=True)
        except OSError:
            pass
        return fallback


DATA_DIR = data_dir()
PROFILES_FILE = os.path.join(DATA_DIR, "profile.json")
SECRETS_FILE = os.path.join(DATA_DIR, "sekrety.enc")
STATE_FILE = os.path.join(DATA_DIR, "stan.json")
LOG_FILE = os.path.join(DATA_DIR, "ostatni-log.txt")
TRAY_PID_FILE = os.path.join(DATA_DIR, "tray.pid")
TRAY_ICON_DIR = os.path.join(DATA_DIR, "icons")

# Własne ikonki trayu, niezależne od motywu ikon (Breeze na KDE nie ma
# nazw w stylu "network-vpn-disabled-symbolic" z Adwaity — szukanie ich po
# nazwie w motywie użytkownika nie trafiało, więc tray zostawał przy ostatnio
# poprawnie znalezionej ikonce niezależnie od stanu połączenia).
_TRAY_ICON_ON_SVG = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">\n'
    '  <circle cx="12" cy="12" r="9" fill="#26a269"/>\n'
    '</svg>\n'
)
_TRAY_ICON_OFF_SVG = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">\n'
    '  <circle cx="12" cy="12" r="8.5" fill="none" stroke="#9a9996" stroke-width="3"/>\n'
    '</svg>\n'
)
TRAY_ICON_ON = "vpn-connector-ipsec-on"
TRAY_ICON_OFF = "vpn-connector-ipsec-off"


def _ensure_tray_icons():
    """Zapisuje własne SVG-ki trayu do dane/icons/, jeśli jeszcze nie ma."""
    try:
        os.makedirs(TRAY_ICON_DIR, exist_ok=True)
        for name, svg in ((TRAY_ICON_ON, _TRAY_ICON_ON_SVG), (TRAY_ICON_OFF, _TRAY_ICON_OFF_SVG)):
            path = os.path.join(TRAY_ICON_DIR, name + ".svg")
            if not os.path.exists(path):
                with open(path, "w") as fh:
                    fh.write(svg)
    except OSError:
        pass


def read_state():
    try:
        with open(STATE_FILE) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _tray_acquire_lock():
    """Jedna instancja trayu naraz: plik z PID w dane/. Jeśli proces z tego
    PID-u wciąż żyje, ktoś inny już trzyma ikonkę."""
    try:
        with open(TRAY_PID_FILE) as fh:
            old_pid = int(fh.read().strip())
        os.kill(old_pid, 0)
        return False
    except (OSError, ValueError):
        pass
    try:
        with open(TRAY_PID_FILE, "w") as fh:
            fh.write(str(os.getpid()))
    except OSError:
        pass
    return True


def _tray_release_lock():
    try:
        with open(TRAY_PID_FILE) as fh:
            if int(fh.read().strip()) == os.getpid():
                os.unlink(TRAY_PID_FILE)
    except (OSError, ValueError):
        pass


def _spawn_tray():
    """Odpala wskaźnik w trayu jako proces odklejony od GUI (start_new_session) —
    zamknięcie okna aplikacji nie ma go zabijać. tray_main() sam pilnuje, żeby nie
    powstały dwie ikonki naraz."""
    try:
        subprocess.Popen([sys.executable, SELF, "--tray"],
                          start_new_session=True,
                          stdin=subprocess.DEVNULL,
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL)
    except OSError:
        pass


def policy_status():
    """(problem, opis) — problem=True gdy aktywny include crypto-policies."""
    if not os.path.exists(IPSEC_CONF):
        return False, "Brak %s" % IPSEC_CONF
    try:
        with open(IPSEC_CONF) as fh:
            for raw in fh:
                line = raw.strip()
                if line.startswith("#"):
                    continue
                if line.startswith("include") and "libreswan.config" in line:
                    return True, line
    except OSError as exc:
        return False, "Nie można odczytać %s (%s)" % (IPSEC_CONF, exc)
    return False, "include crypto-policies jest wyłączony"


# ==========================================================================
#  SZYFROWANIE HASEŁ  (openssl AES-256-CBC + PBKDF2, bez zewnętrznych bibliotek)
# ==========================================================================

PBKDF2_ITER = 240000


def openssl_available():
    return shutil.which("openssl") is not None


def machine_passphrase():
    """Klucz związany z tym komputerem i użytkownikiem.

    To obfuskacja, nie forteca: kto ma roota na tej maszynie, odtworzy go.
    Chroni przed odczytaniem haseł po skopiowaniu folderu na inny komputer
    i przed przypadkowym zerknięciem do pliku.
    """
    parts = ["vpn-connector-ipsec/v1"]
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(path) as fh:
                parts.append(fh.read().strip())
                break
        except OSError:
            continue
    try:
        parts.append(getpass.getuser())
    except Exception:  # noqa: BLE001
        parts.append(str(os.getuid()))
    parts.append(str(os.getuid()))
    return "|".join(parts)


def _openssl(args, data, passphrase):
    r_fd, w_fd = os.pipe()
    try:
        os.write(w_fd, passphrase.encode("utf-8") + b"\n")
    finally:
        os.close(w_fd)
    try:
        proc = subprocess.run(
            ["openssl"] + args + ["-pass", "fd:%d" % r_fd],
            input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(r_fd,), timeout=60)
    finally:
        os.close(r_fd)
    if proc.returncode != 0:
        raise Fatal((proc.stderr or b"").decode("utf-8", "replace").strip()
                    or "openssl zwrócił błąd")
    return proc.stdout


def encrypt_blob(obj, passphrase):
    plain = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    out = _openssl(["enc", "-aes-256-cbc", "-md", "sha256", "-pbkdf2",
                    "-iter", str(PBKDF2_ITER), "-salt"], plain, passphrase)
    return base64.b64encode(out).decode("ascii")


def decrypt_blob(b64, passphrase):
    raw = base64.b64decode(b64.encode("ascii"))
    out = _openssl(["enc", "-d", "-aes-256-cbc", "-md", "sha256", "-pbkdf2",
                    "-iter", str(PBKDF2_ITER)], raw, passphrase)
    return json.loads(out.decode("utf-8"))


def load_secrets(passphrase):
    """{nazwa_profilu: {'psk':…, 'xauth':…}}"""
    if not os.path.exists(SECRETS_FILE):
        return {}
    with open(SECRETS_FILE) as fh:
        payload = json.load(fh)
    if payload.get("format") != "openssl-aes256-pbkdf2":
        raise Fatal("Nieznany format pliku %s" % SECRETS_FILE)
    return decrypt_blob(payload["data"], passphrase)


def save_secrets(secrets, passphrase):
    payload = {
        "format": "openssl-aes256-pbkdf2",
        "iter": PBKDF2_ITER,
        "data": encrypt_blob(secrets, passphrase),
    }
    tmp = SECRETS_FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp, SECRETS_FILE)
    try:
        os.chmod(SECRETS_FILE, 0o600)
    except OSError:
        pass


# ==========================================================================
#  WALIDACJA I GENEROWANIE KONFIGURACJI
# ==========================================================================

def v_match(rx, value, field):
    value = str(value or "").strip()
    if not rx.match(value):
        raise Fatal("Nieprawidłowa wartość pola '%s': %r" % (field, value))
    return value


def v_host(value, field):
    value = str(value or "").strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if re.match(r"^[A-Za-z0-9.-]{1,253}$", value) and "." in value:
        return value
    raise Fatal("Pole '%s' musi być adresem IP lub nazwą hosta: %r" % (field, value))


def v_net(value, field):
    value = str(value or "").strip()
    try:
        if "/" not in value:
            raise ValueError("brak maski")
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise Fatal("Pole '%s' musi być siecią w formacie CIDR: %r" % (field, value))
    return value


def v_ip(value, field):
    value = str(value or "").strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        raise Fatal("Pole '%s' musi być adresem IP: %r" % (field, value))
    return value


def clean(profile):
    """Profil ze zwalidowanymi polami. Rzuca Fatal przy śmieciach."""
    p = {}
    p["name"] = v_match(NAME_RE, profile.get("name"), "nazwa profilu")
    p["right"] = v_host(profile.get("right"), "brama VPN")
    p["rightsubnet"] = v_net(profile.get("rightsubnet") or "10.0.0.0/8", "sieć zdalna")
    p["leftid"] = v_match(ID_RE, profile.get("leftid") or "@moj-klucz", "leftid")
    p["rightid"] = v_match(ID_RE, profile.get("rightid") or p["leftid"], "rightid")
    p["username"] = v_match(USER_RE, profile.get("username"), "użytkownik XAUTH")
    p["ike"] = v_match(ALGO_RE, profile.get("ike") or "aes256-sha512;ecp256", "szyfry IKE")
    p["phase2alg"] = v_match(ALGO_RE, profile.get("phase2alg") or "aes256-sha512", "szyfry ESP")
    p["ikelifetime"] = v_match(NUM_RE, profile.get("ikelifetime") or "86400", "ikelifetime")
    p["salifetime"] = v_match(NUM_RE, profile.get("salifetime") or "43200", "salifetime")
    p["dpddelay"] = v_match(NUM_RE, profile.get("dpddelay") or "5", "dpddelay")
    p["dpdtimeout"] = v_match(NUM_RE, profile.get("dpdtimeout") or "15", "dpdtimeout")
    p["pfs"] = "yes" if profile.get("pfs", True) else "no"
    p["aggressive"] = "yes" if profile.get("aggressive", True) else "no"
    p["encapsulation"] = "yes" if profile.get("encapsulation", True) else "no"
    p["keyexchange"] = "ikev2" if str(profile.get("keyexchange", "ikev1")) == "ikev2" else "ikev1"

    iface = str(profile.get("iface") or "auto").strip()
    p["iface"] = "auto" if iface == "auto" else v_match(IFACE_RE, iface, "interfejs")

    vip = str(profile.get("vpn_ip") or "auto").strip()
    p["vpn_ip"] = "auto" if vip == "auto" else v_ip(vip, "adres VPN")

    p["psk"] = str(profile.get("psk") or "")
    p["xauth"] = str(profile.get("xauth") or "")
    p["keep_secrets"] = bool(profile.get("keep_secrets", False))
    p["restart_service"] = bool(profile.get("restart_service", True))
    p["setup_routes"] = bool(profile.get("setup_routes", True))
    return p


def conn_name(p):
    return PREFIX + p["name"]


def conf_path(p):
    return os.path.join(CONF_DIR, PREFIX + p["name"] + ".conf")


def secrets_path(p):
    return os.path.join(CONF_DIR, PREFIX + p["name"] + ".secrets")


def build_conf(p):
    return "\n".join([
        "# Wygenerowane przez VPN Connector IPsec — ręczne zmiany zostaną nadpisane.",
        "conn %s" % conn_name(p),
        "    keyexchange=%s" % p["keyexchange"],
        "    aggressive=%s" % p["aggressive"],
        "    leftupdown=/usr/bin/true",
        "    leftid=%s" % p["leftid"],
        "    rightid=%s" % p["rightid"],
        "    authby=secret",
        "    leftxauthclient=yes",
        "    leftmodecfgclient=yes",
        "    modecfgpull=yes",
        "    leftusername=%s" % p["username"],
        "    left=%defaultroute",
        "    right=%s" % p["right"],
        "    rightsubnet=%s" % p["rightsubnet"],
        "    rightxauthserver=yes",
        "    rightmodecfgserver=yes",
        "    ike=%s" % p["ike"],
        "    phase2alg=%s" % p["phase2alg"],
        "    pfs=%s" % p["pfs"],
        "    encapsulation=%s" % p["encapsulation"],
        "    ikelifetime=%s" % p["ikelifetime"],
        "    salifetime=%s" % p["salifetime"],
        "    dpddelay=%s" % p["dpddelay"],
        "    dpdtimeout=%s" % p["dpdtimeout"],
        "",
    ])


def build_secrets(p):
    psk = p["psk"].replace("\\", "\\\\").replace('"', '\\"')
    xauth = p["xauth"].replace("\\", "\\\\").replace('"', '\\"')
    return (
        "# Wygenerowane przez VPN Connector IPsec.\n"
        '%s %s : PSK "%s"\n'
        '%%any %s : XAUTH "%s"\n' % (p["leftid"], p["right"], psk, p["username"], xauth)
    )


# ==========================================================================
#  TRYB HELPERA (root, uruchamiany przez pkexec)
# ==========================================================================

def log(msg):
    sys.stdout.write(str(msg).rstrip() + "\n")
    sys.stdout.flush()


def result(ok, **kw):
    kw["ok"] = bool(ok)
    sys.stdout.write("##RESULT## " + json.dumps(kw) + "\n")
    sys.stdout.flush()
    sys.exit(0 if ok else 1)


def run(cmd, check=False, quiet=False, timeout=120):
    if not quiet:
        log("$ " + " ".join(cmd))
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           text=True, timeout=timeout)
    except FileNotFoundError:
        log("  ! brak polecenia: %s" % cmd[0])
        if check:
            raise Fatal("Brak polecenia %s — czy libreswan jest zainstalowany?" % cmd[0])
        return 127, ""
    except subprocess.TimeoutExpired:
        log("  ! przekroczono limit czasu: %s" % " ".join(cmd))
        if check:
            raise Fatal("Przekroczono limit czasu: %s" % " ".join(cmd))
        return 124, ""
    out = p.stdout or ""
    if out.strip() and not quiet:
        for line in out.rstrip().splitlines():
            log("  " + line)
    if check and p.returncode != 0:
        raise Fatal("Polecenie nie powiodło się (rc=%d): %s" % (p.returncode, " ".join(cmd)))
    return p.returncode, out


def write_private(path, content):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def shred(path):
    if not os.path.exists(path):
        return
    try:
        size = os.path.getsize(path)
        with open(path, "r+b") as fh:
            fh.write(b"\x00" * size)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError:
        pass
    try:
        os.unlink(path)
    except OSError:
        pass


def detect_iface():
    _, out = run(["ip", "-o", "route", "show", "default"], quiet=True)
    for line in out.splitlines():
        m = re.search(r"\bdev\s+(\S+)", line)
        if m:
            return m.group(1)
    return None


def detect_vpn_ip(p):
    """Adres przydzielony przez modecfg — czytany ze stanu libreswana."""
    name = conn_name(p)
    remote = p["right"]
    for _ in range(10):
        _, out = run(["ipsec", "status"], quiet=True)
        for line in out.splitlines():
            if name not in line:
                continue
            for m in re.finditer(r"(\d+\.\d+\.\d+\.\d+)/32===", line):
                if m.group(1) != remote:
                    return m.group(1)
            m = re.search(r"received (?:IPv4 )?lease ['\"]?(\d+\.\d+\.\d+\.\d+)", line)
            if m:
                return m.group(1)
        time.sleep(0.5)
    return None


def ip_addr_present(iface, addr):
    _, out = run(["ip", "-o", "addr", "show", "dev", iface], quiet=True)
    return re.search(r"\b%s/" % re.escape(addr), out) is not None


def wait_for_pluto(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rc, _ = run(["ipsec", "status"], quiet=True, timeout=15)
        if rc == 0:
            return True
        time.sleep(0.5)
    return False


def save_state(data):
    try:
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, STATE_FILE)
        os.chmod(STATE_FILE, 0o644)
    except OSError:
        pass


def cleanup_orphans(known):
    """Kasuje pliki bvpn-*.conf/.secrets profili, których już nie ma na liście."""
    keep = set()
    for name in known or []:
        try:
            keep.add(v_match(NAME_RE, name, "nazwa profilu"))
        except Fatal:
            continue
    removed = []
    try:
        entries = sorted(os.listdir(CONF_DIR))
    except OSError:
        return removed
    for fname in entries:
        if not fname.startswith(PREFIX):
            continue
        for suffix in (".conf", ".secrets"):
            if fname.endswith(suffix):
                name = fname[len(PREFIX):-len(suffix)]
                if name in keep:
                    break
                path = os.path.join(CONF_DIR, fname)
                if suffix == ".secrets":
                    shred(path)
                else:
                    try:
                        os.unlink(path)
                    except OSError:
                        break
                removed.append(fname)
                break
    if removed:
        log("Usunięto osierocone pliki: %s" % ", ".join(removed))
    return removed


def cmd_cleanup(profile):
    removed = cleanup_orphans(profile.get("known"))
    if not removed:
        log("Nie ma czego sprzątać — w %s nie ma osieroconych plików bvpn-*." % CONF_DIR)
    result(True, removed=removed)


def cmd_check_policy():
    problem, detail = policy_status()
    if problem:
        log("UWAGA: aktywny include crypto-policies (%s)." % detail)
        log("Wstrzykuje chacha20_poly1305 do IKEv1 i uniemożliwia start usługi.")
    else:
        log(detail)
    result(True, policy_problem=problem, detail=detail)


def cmd_fix_policy():
    problem, detail = policy_status()
    if not problem:
        log("Nie ma czego naprawiać: " + detail)
        result(True, changed=False, policy_problem=False)
    backup = IPSEC_CONF + ".bvpn-backup"
    if not os.path.exists(backup):
        shutil.copy2(IPSEC_CONF, backup)
        log("Kopia zapasowa: %s" % backup)
    with open(IPSEC_CONF) as fh:
        lines = fh.readlines()
    out = []
    for raw in lines:
        s = raw.strip()
        if not s.startswith("#") and s.startswith("include") and "libreswan.config" in s:
            out.append("# wyłączone przez VPN Connector IPsec\n#" + raw)
            log("Zakomentowano: " + s)
        else:
            out.append(raw)
    with open(IPSEC_CONF, "w") as fh:
        fh.writelines(out)
    result(True, changed=True, policy_problem=False)


def cmd_up(profile):
    p = clean(profile)
    name = conn_name(p)

    problem, _ = policy_status()
    if problem:
        raise Fatal(
            "W /etc/ipsec.conf jest aktywny 'include %s'. Wstrzykuje chacha20_poly1305 "
            "do IKEv1 i blokuje start tunelu. Użyj przycisku „Napraw” w oknie aplikacji."
            % POLICY_INCLUDE)

    iface = p["iface"]
    if iface == "auto":
        iface = detect_iface()
        if not iface:
            raise Fatal("Nie udało się wykryć interfejsu z trasą domyślną.")
        log("Wykryty interfejs: %s" % iface)

    os.makedirs(CONF_DIR, exist_ok=True)
    log("=== [VPN] Zapis konfiguracji ===")
    write_private(conf_path(p), build_conf(p))
    os.chmod(conf_path(p), 0o644)
    write_private(secrets_path(p), build_secrets(p))
    log("  %s" % conf_path(p))
    log("  %s (0600, kasowany po zestawieniu tunelu)" % secrets_path(p))

    log("=== [VPN] Czyszczenie starych tras i adresów ===")
    run(["ip", "route", "del", p["rightsubnet"], "dev", iface])
    old = read_state().get("vpn_ip")
    if old:
        run(["ip", "addr", "del", old + "/32", "dev", iface])

    if p["restart_service"]:
        log("=== [VPN] Restart usługi ipsec ===")
        run(["systemctl", "restart", "ipsec"], check=True)
        if not wait_for_pluto():
            raise Fatal("Usługa ipsec nie wstała. Sprawdź: journalctl -u ipsec -n 50")

    log("=== [VPN] Uruchamianie tunelu IPsec ===")
    run(["ipsec", "rereadsecrets"])
    run(["ipsec", "add", name], check=True)
    rc, out = run(["ipsec", "up", name], timeout=90)
    if rc != 0:
        low = out.lower()
        hint = ""
        if "no acceptable" in low or "no proposal" in low:
            hint = " Brama odrzuciła zestaw algorytmów — sprawdź szyfry IKE/ESP."
        elif "xauth" in low and ("fail" in low or "rejected" in low):
            hint = " Odrzucone dane XAUTH — sprawdź login i hasło."
        elif "authentication failed" in low or ("psk" in low and "fail" in low):
            hint = " Nie zgadza się PSK albo leftid/rightid."
        shred(secrets_path(p))
        raise Fatal("Nie udało się zestawić tunelu (rc=%d).%s" % (rc, hint))

    vpn_ip = p["vpn_ip"]
    if vpn_ip == "auto":
        vpn_ip = detect_vpn_ip(p)
        if not vpn_ip:
            shred(secrets_path(p))
            raise Fatal("Tunel wstał, ale nie udało się odczytać adresu z modecfg. "
                        "Wpisz go ręcznie w polu „Adres VPN”.")
        log("Adres z modecfg: %s" % vpn_ip)

    if p["setup_routes"]:
        log("=== [VPN] Adresacja i split tunneling ===")
        if not ip_addr_present(iface, vpn_ip):
            run(["ip", "addr", "add", vpn_ip + "/32", "dev", iface])
        run(["ip", "route", "replace", p["rightsubnet"], "dev", iface, "src", vpn_ip])

    if not p["keep_secrets"]:
        shred(secrets_path(p))
        log("Plik z sekretami usunięty z dysku.")

    cleanup_orphans(profile.get("known") or [p["name"]])

    save_state({"connected": True, "profile": p["name"], "conn": name, "iface": iface,
                "vpn_ip": vpn_ip, "subnet": p["rightsubnet"], "since": int(time.time())})
    log("=== [VPN] POŁĄCZONO ===")
    result(True, vpn_ip=vpn_ip, iface=iface, conn=name)


def cmd_down(profile):
    p = clean(profile)
    name = conn_name(p)
    st = read_state()
    iface = p["iface"] if p["iface"] != "auto" else (st.get("iface") or detect_iface() or "")
    vpn_ip = p["vpn_ip"] if p["vpn_ip"] != "auto" else st.get("vpn_ip")

    log("=== [VPN] Rozłączanie ===")
    run(["ipsec", "down", name])
    run(["ipsec", "delete", name])
    if p["restart_service"]:
        run(["systemctl", "restart", "ipsec"])

    if iface:
        log("=== [VPN] Sprzątanie adresów i tras na %s ===" % iface)
        if vpn_ip:
            run(["ip", "route", "del", p["rightsubnet"], "dev", iface, "src", vpn_ip])
            run(["ip", "addr", "del", vpn_ip + "/32", "dev", iface])
        run(["ip", "route", "del", p["rightsubnet"], "dev", iface])

    shred(secrets_path(p))
    save_state({"connected": False, "profile": p["name"], "since": int(time.time())})
    log("=== [VPN] ROZŁĄCZONO ===")
    result(True)


def cmd_status(profile):
    p = clean(profile) if profile.get("name") else None
    _, out = run(["ipsec", "status"], quiet=True)
    connected = False
    if p:
        name = conn_name(p)
        for line in out.splitlines():
            if name in line and ("IPsec SA established" in line or "erouted" in line):
                connected = True
                break
    _, traffic = run(["ipsec", "trafficstatus"], quiet=True)
    result(True, connected=connected, status=out[-8000:], traffic=traffic[-4000:])


def helper_main(argv):
    if os.geteuid() != 0:
        result(False, error="Tryb --helper wymaga roota (uruchamiany przez pkexec).")
    if not argv:
        result(False, error="Brak komendy.")
    cmd = argv[0]

    profile = {}
    if cmd in ("up", "down", "status", "cleanup"):
        raw = sys.stdin.read()
        try:
            profile = json.loads(raw) if raw.strip() else {}
        except ValueError as exc:
            result(False, error="Nieprawidłowy JSON na wejściu: %s" % exc)

    try:
        if cmd == "up":
            cmd_up(profile)
        elif cmd == "down":
            cmd_down(profile)
        elif cmd == "status":
            cmd_status(profile)
        elif cmd == "cleanup":
            cmd_cleanup(profile)
        elif cmd == "check-policy":
            cmd_check_policy()
        elif cmd == "fix-policy":
            cmd_fix_policy()
        else:
            result(False, error="Nieznana komenda: %s" % cmd)
    except Fatal as exc:
        log("BŁĄD: %s" % exc)
        result(False, error=str(exc))
    except Exception as exc:  # noqa: BLE001
        log("BŁĄD WEWNĘTRZNY: %r" % exc)
        result(False, error=repr(exc))


# ==========================================================================
#  GUI (zwykły użytkownik)
# ==========================================================================

def gui_main(auto_shutdown=False):
    import gi
    gi.require_version("Gtk", "4.0")
    gi.require_version("Adw", "1")
    from gi.repository import Adw, GLib, Gio, Gtk, Pango

    def load_store():
        try:
            with open(PROFILES_FILE) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = {}
        profiles = []
        for item in data.get("profiles", []):
            p = dict(DEFAULT_PROFILE)
            p.update({k: v for k, v in item.items() if k in DEFAULT_PROFILE})
            profiles.append(p)
        settings = {"crypt_mode": "machine"}
        settings.update(data.get("settings") or {})
        if settings.get("crypt_mode") not in CRYPT_MODES:
            settings["crypt_mode"] = "machine"
        return profiles, settings

    def save_store(profiles, settings):
        tmp = PROFILES_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"settings": settings, "profiles": profiles},
                      fh, indent=2, ensure_ascii=False)
        os.replace(tmp, PROFILES_FILE)
        try:
            os.chmod(PROFILES_FILE, 0o600)
        except OSError:
            pass

    def list_interfaces():
        out = ["auto"]
        try:
            for name in sorted(os.listdir("/sys/class/net")):
                if name != "lo":
                    out.append(name)
        except OSError:
            pass
        return out

    # -- uruchamianie helpera przez pkexec --------------------------------

    class Helper:
        """pkexec python3 <ten plik> --helper <cmd>; logi linia po linii."""

        def __init__(self, command, profile, on_line, on_done):
            self.on_line = on_line
            self.on_done = on_done
            self.result = None
            python = sys.executable or "/usr/bin/python3"
            argv = ["pkexec", python, SELF, "--helper", command]
            launcher = Gio.SubprocessLauncher.new(
                Gio.SubprocessFlags.STDIN_PIPE
                | Gio.SubprocessFlags.STDOUT_PIPE
                | Gio.SubprocessFlags.STDERR_MERGE)
            try:
                self.proc = launcher.spawnv(argv)
            except GLib.Error as exc:
                on_line("BŁĄD: nie udało się uruchomić pkexec (%s)" % exc.message)
                on_done(False, {"error": exc.message})
                return

            stdin = self.proc.get_stdin_pipe()
            try:
                stdin.write_all(json.dumps(profile).encode("utf-8"), None)
                stdin.close(None)
            except GLib.Error:
                pass

            self.stream = Gio.DataInputStream.new(self.proc.get_stdout_pipe())
            self._read()
            self.proc.wait_async(None, self._finished)

        def _read(self):
            self.stream.read_line_async(GLib.PRIORITY_DEFAULT, None, self._got_line)

        def _got_line(self, stream, res):
            try:
                data, _ = stream.read_line_finish(res)
            except GLib.Error:
                return
            if not data:
                # Koniec strumienia: GLib w C zwraca tu NULL, ale przez wadliwą
                # adnotację introspekcji PyGObject potrafi to być puste b"" zamiast
                # None — bez sprawdzenia obu przypadków _read() dzwoni się w kółko
                # (idle-dispatch bez blokowania), co zawiesza GTK i grzeje CPU.
                return
            line = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
            if line.startswith("##RESULT## "):
                try:
                    self.result = json.loads(line[len("##RESULT## "):])
                except ValueError:
                    self.result = {}
            else:
                self.on_line(line)
            self._read()

        def _finished(self, proc, res):
            try:
                proc.wait_finish(res)
                code = proc.get_exit_status()
            except GLib.Error:
                code = 1
            data = self.result or {}
            if code == 126:
                data.setdefault("error", "Autoryzacja anulowana.")
            elif code == 127 and not data:
                data.setdefault("error", "Nie znaleziono pkexec (pakiet polkit).")
            self.on_done(bool(data.get("ok")) and code == 0, data)

    # -- okno -------------------------------------------------------------

    class Window(Adw.ApplicationWindow):

        def __init__(self, app):
            super().__init__(application=app, title="VPN Connector IPsec")
            self.set_default_size(960, 740)

            self.profiles, self.settings = load_store()
            if not self.profiles:
                first = dict(DEFAULT_PROFILE)
                first["name"] = "profil-1"
                self.profiles = [first]
            self.current = 0
            self.busy = False
            self._loading = False
            self._save_source = 0
            self._preset_busy = False
            self.master = None          # hasło główne w pamięci (tryb "master")
            self.secrets = None         # {profil: {psk, xauth}} albo None = niewczytane
            self.log_lines = []

            self.toasts = Adw.ToastOverlay()
            self.set_content(self.toasts)
            toolbar = Adw.ToolbarView()
            self.toasts.set_child(toolbar)
            toolbar.add_top_bar(self._build_header())
            toolbar.set_content(self._build_body())

            self._build_profile_list()
            self._unlock_if_easy()
            self._load_profile(0)
            self._check_policy_banner()
            GLib.timeout_add_seconds(3, self._poll_state)
            self.connect("close-request", self._on_close)

        # -- sekrety ------------------------------------------------------

        def _mode(self):
            return self.settings.get("crypt_mode", "machine")

        def _passphrase(self):
            """Hasło do szyfrowania albo None, gdy trzeba o nie zapytać."""
            mode = self._mode()
            if mode == "machine":
                return machine_passphrase()
            if mode == "master":
                return self.master
            return None

        def _unlock_if_easy(self):
            """W trybie 'machine' wczytujemy sekrety od razu, bez pytania."""
            if self._mode() != "machine":
                self.secrets = {} if self._mode() == "none" else None
                return
            if not openssl_available():
                self.secrets = {}
                return
            try:
                self.secrets = load_secrets(machine_passphrase())
            except (Fatal, OSError, ValueError):
                self.secrets = {}

        def _ensure_secrets(self, then):
            """Wywołuje then() gdy self.secrets jest gotowe (może zapytać o hasło)."""
            if self.secrets is not None:
                then()
                return
            if self._mode() != "master":
                self.secrets = {}
                then()
                return
            self._ask_master(then)

        def _ask_master(self, then, setting_up=False):
            exists = os.path.exists(SECRETS_FILE)
            heading = "Ustaw hasło główne" if (setting_up or not exists) else "Hasło główne"
            body = ("Będzie szyfrować zapisane hasła VPN w pliku dane/sekrety.enc."
                    if (setting_up or not exists)
                    else "Odblokuj zapisane hasła VPN.")
            dialog = Adw.MessageDialog(transient_for=self, heading=heading, body=body)
            entry = Gtk.PasswordEntry(show_peek_icon=True, activates_default=True)
            entry.set_placeholder_text("Hasło główne")
            dialog.set_extra_child(entry)
            dialog.add_response("cancel", "Anuluj")
            dialog.add_response("ok", "OK")
            dialog.set_default_response("ok")
            dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)

            def resp(dlg, response):
                if response != "ok":
                    return
                pw = entry.get_text()
                if not pw:
                    self._toast("Puste hasło — pominięto.")
                    return
                if not os.path.exists(SECRETS_FILE):
                    self.master = pw
                    self.secrets = {}
                    then()
                    return
                try:
                    self.secrets = load_secrets(pw)
                    self.master = pw
                    then()
                except Fatal:
                    self._toast("Złe hasło główne.")
                except (OSError, ValueError) as exc:
                    self._toast("Nie udało się odczytać sekretów: %s" % exc)

            dialog.connect("response", resp)
            dialog.present()

        def _persist_secrets(self):
            if self._mode() == "none":
                return
            if self.secrets is None:
                return
            if not openssl_available():
                self._toast("Brak openssl — hasła nie zostaną zapisane.")
                return
            pw = self._passphrase()
            if not pw:
                return
            try:
                save_secrets(self.secrets, pw)
            except (Fatal, OSError) as exc:
                self._toast("Nie udało się zapisać haseł: %s" % exc)

        # -- budowa interfejsu --------------------------------------------

        def _build_header(self):
            header = Adw.HeaderBar()
            self.title = Adw.WindowTitle(title="VPN Connector IPsec", subtitle="rozłączony")
            header.set_title_widget(self.title)

            add = Gtk.Button(icon_name="list-add-symbolic", tooltip_text="Nowy profil")
            add.connect("clicked", self._on_add)
            header.pack_start(add)

            menu = Gio.Menu()
            menu.append("Duplikuj profil", "win.duplicate")
            menu.append("Usuń profil", "win.delete")
            menu.append("Sprawdź crypto-policies", "win.checkpolicy")
            menu.append("Posprzątaj /etc/ipsec.d", "win.cleanup")
            menu.append("Gdzie są dane?", "win.where")
            header.pack_end(Gtk.MenuButton(icon_name="open-menu-symbolic", menu_model=menu))

            self.log_toggle = Gtk.ToggleButton(icon_name="utilities-terminal-symbolic",
                                               tooltip_text="Logi")
            self.log_toggle.connect(
                "toggled", lambda b: self.log_revealer.set_reveal_child(b.get_active()))
            header.pack_end(self.log_toggle)

            for name, cb in (("duplicate", self._on_duplicate),
                             ("delete", self._on_delete),
                             ("checkpolicy", self._on_check_policy),
                             ("cleanup", self._on_cleanup),
                             ("where", self._on_where)):
                act = Gio.SimpleAction.new(name, None)
                act.connect("activate", cb)
                self.add_action(act)
            return header

        def _build_body(self):
            outer = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

            self.banner = Adw.Banner(title="", button_label="Napraw", revealed=False)
            self.banner.connect("button-clicked", self._on_fix_policy)
            outer.append(self.banner)

            split = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, vexpand=True)
            outer.append(split)

            self.listbox = Gtk.ListBox(selection_mode=Gtk.SelectionMode.SINGLE)
            self.listbox.add_css_class("navigation-sidebar")
            self.listbox.connect("row-selected", self._on_row_selected)
            sw = Gtk.ScrolledWindow(hscrollbar_policy=Gtk.PolicyType.NEVER, width_request=230)
            sw.set_child(self.listbox)
            split.append(sw)
            split.append(Gtk.Separator(orientation=Gtk.Orientation.VERTICAL))

            right = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, hexpand=True)
            split.append(right)
            right.append(self._build_form())
            right.append(self._build_actionbar())

            self.log_revealer = Gtk.Revealer(
                transition_type=Gtk.RevealerTransitionType.SLIDE_UP)
            self.log_view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True)
            self.log_view.set_wrap_mode(Pango.WrapMode.WORD_CHAR)
            log_sw = Gtk.ScrolledWindow(height_request=190)
            log_sw.set_child(self.log_view)
            log_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            log_box.append(Gtk.Separator())
            log_box.append(log_sw)
            self.log_revealer.set_child(log_box)
            outer.append(self.log_revealer)
            return outer

        def _entry(self, group, title, key, subtitle=None, password=False):
            row = Adw.PasswordEntryRow(title=title) if password else Adw.EntryRow(title=title)
            if subtitle:
                row.set_tooltip_text(subtitle)
            row.connect("changed", self._on_field_changed, key)
            group.add(row)
            self.rows[key] = row
            return row

        def _switch(self, group, title, subtitle, key):
            row = Adw.ActionRow(title=title, subtitle=subtitle)
            sw = Gtk.Switch(valign=Gtk.Align.CENTER)
            sw.connect("notify::active", self._on_switch_changed, key)
            row.add_suffix(sw)
            row.set_activatable_widget(sw)
            group.add(row)
            self.rows[key] = sw
            return row

        def _build_form(self):
            self.rows = {}
            page = Adw.PreferencesPage()

            g1 = Adw.PreferencesGroup(title="Połączenie")
            page.add(g1)
            self._entry(g1, "Nazwa profilu", "name", "Litery, cyfry, myślnik, podkreślnik")
            self._entry(g1, "Brama VPN (right)", "right", "np. 203.0.113.1")
            self._entry(g1, "Sieć zdalna (rightsubnet)", "rightsubnet", "np. 10.0.0.0/8")
            self._entry(g1, "Użytkownik XAUTH", "username")

            g5 = Adw.PreferencesGroup(
                title="Hasła",
                description="Zapisywane w dane/sekrety.enc — AES-256-CBC, klucz z PBKDF2 "
                            "(%d iteracji). W profile.json haseł nie ma." % PBKDF2_ITER)
            page.add(g5)
            self.psk_row = Adw.PasswordEntryRow(title="Klucz PSK")
            self.psk_row.connect("changed", self._on_secret_changed, "psk")
            g5.add(self.psk_row)
            self.xauth_row = Adw.PasswordEntryRow(title="Hasło XAUTH")
            self.xauth_row.connect("changed", self._on_secret_changed, "xauth")
            g5.add(self.xauth_row)
            self.crypt_row = Adw.ComboRow(title="Ochrona zapisanych haseł",
                                          model=Gtk.StringList.new(CRYPT_LABELS))
            self.crypt_row.set_selected(CRYPT_MODES.index(self._mode()))
            self.crypt_row.connect("notify::selected", self._on_crypt_mode)
            g5.add(self.crypt_row)

            g2 = Adw.PreferencesGroup(title="Szyfrowanie tunelu")
            page.add(g2)
            self.preset_row = Adw.ComboRow(
                title="Zestaw algorytmów",
                model=Gtk.StringList.new([p[0] for p in PRESETS] + [CUSTOM_LABEL]))
            self.preset_row.connect("notify::selected", self._on_preset)
            g2.add(self.preset_row)
            self._entry(g2, "Faza 1 — IKE (ike=)", "ike", "szyfr-hash;grupaDH")
            self._entry(g2, "Faza 2 — ESP (phase2alg=)", "phase2alg", "szyfr-hash")
            self._switch(g2, "PFS", "Perfect Forward Secrecy dla fazy 2", "pfs")
            self._switch(g2, "Aggressive mode", "Wymagane przez FortiGate w IKEv1", "aggressive")
            self._switch(g2, "Enkapsulacja NAT-T", "encapsulation=yes", "encapsulation")

            g3 = Adw.PreferencesGroup(title="Tożsamość i sieć")
            page.add(g3)
            self._entry(g3, "leftid", "leftid", "np. @moj-klucz")
            self._entry(g3, "rightid", "rightid", "np. @moj-klucz")
            self.iface_row = Adw.ComboRow(title="Interfejs",
                                          subtitle="„auto” — z trasy domyślnej",
                                          model=Gtk.StringList.new(list_interfaces()))
            self.iface_row.connect("notify::selected", self._on_iface)
            g3.add(self.iface_row)
            self._entry(g3, "Adres VPN", "vpn_ip",
                        "„auto” — odczyt z modecfg, albo wpisz na sztywno")

            g4 = Adw.PreferencesGroup(title="Zaawansowane")
            page.add(g4)
            self._entry(g4, "ikelifetime (s)", "ikelifetime")
            self._entry(g4, "salifetime (s)", "salifetime")
            self._entry(g4, "dpddelay (s)", "dpddelay")
            self._entry(g4, "dpdtimeout (s)", "dpdtimeout")
            self._switch(g4, "Restart usługi ipsec",
                         "Przed połączeniem i po rozłączeniu", "restart_service")
            self._switch(g4, "Ustawiaj adres i trasy",
                         "Split tunneling po zestawieniu tunelu", "setup_routes")

            sw = Gtk.ScrolledWindow(vexpand=True)
            sw.set_child(page)
            return sw

        def _build_actionbar(self):
            bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            bar.set_margin_top(10)
            bar.set_margin_bottom(10)
            bar.set_margin_start(16)
            bar.set_margin_end(16)

            self.status_icon = Gtk.Image.new_from_icon_name("network-vpn-disabled-symbolic")
            self.status_label = Gtk.Label(label="Rozłączony", xalign=0)
            self.status_label.add_css_class("dim-label")
            self.spinner = Gtk.Spinner()
            bar.append(self.status_icon)
            bar.append(self.status_label)
            bar.append(self.spinner)
            bar.append(Gtk.Box(hexpand=True))

            self.btn_disconnect = Gtk.Button(label="Rozłącz")
            self.btn_disconnect.connect("clicked", self._on_disconnect)
            bar.append(self.btn_disconnect)

            self.btn_connect = Gtk.Button(label="Połącz")
            self.btn_connect.add_css_class("suggested-action")
            self.btn_connect.connect("clicked", self._on_connect)
            bar.append(self.btn_connect)

            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
            box.append(Gtk.Separator())
            box.append(bar)
            return box

        # -- profile ------------------------------------------------------

        def _build_profile_list(self):
            self._loading = True
            child = self.listbox.get_first_child()
            while child:
                nxt = child.get_next_sibling()
                self.listbox.remove(child)
                child = nxt
            for p in self.profiles:
                self.listbox.append(Adw.ActionRow(title=p["name"],
                                                  subtitle=p.get("right") or "brak bramy"))
            self._loading = False
            row = self.listbox.get_row_at_index(self.current)
            if row:
                self.listbox.select_row(row)

        def _on_row_selected(self, box, row):
            if self._loading or row is None:
                return
            idx = row.get_index()
            if idx != self.current:
                self._collect()
                self._load_profile(idx)

        def _load_profile(self, idx):
            self._loading = True
            self.current = idx
            p = self.profiles[idx]
            for key, widget in self.rows.items():
                val = p.get(key, DEFAULT_PROFILE.get(key))
                if isinstance(widget, Gtk.Switch):
                    widget.set_active(bool(val))
                else:
                    widget.set_text(str(val or ""))
            sec = (self.secrets or {}).get(p["name"], {})
            self.psk_row.set_text(sec.get("psk", ""))
            self.xauth_row.set_text(sec.get("xauth", ""))
            ifaces = list_interfaces()
            want = p.get("iface", "auto")
            if want not in ifaces:
                ifaces.append(want)
                self.iface_row.set_model(Gtk.StringList.new(ifaces))
            self.iface_row.set_selected(ifaces.index(want))
            self._sync_preset()
            self.title.set_title(p["name"])
            self._loading = False
            self._refresh_status()

        def _collect(self):
            p = self.profiles[self.current]
            old_name = p["name"]
            for key, widget in self.rows.items():
                if isinstance(widget, Gtk.Switch):
                    p[key] = widget.get_active()
                else:
                    p[key] = widget.get_text().strip()
            model = self.iface_row.get_model()
            sel = self.iface_row.get_selected()
            if model and 0 <= sel < model.get_n_items():
                p["iface"] = model.get_string(sel)
            if self.secrets is not None:
                if old_name != p["name"] and old_name in self.secrets:
                    self.secrets[p["name"]] = self.secrets.pop(old_name)
                self.secrets[p["name"]] = {"psk": self.psk_row.get_text(),
                                           "xauth": self.xauth_row.get_text()}
            return p

        def _on_field_changed(self, row, key):
            if self._loading:
                return
            if key in ("ike", "phase2alg"):
                self._sync_preset()
            if key == "name":
                self.title.set_title(row.get_text().strip() or "—")
            self._schedule_save()

        def _on_secret_changed(self, row, key):
            if self._loading:
                return
            if self.secrets is None:
                self._ensure_secrets(lambda: None)
            self._schedule_save()

        def _on_switch_changed(self, sw, pspec, key):
            if not self._loading:
                self._schedule_save()

        def _on_iface(self, row, pspec):
            if not self._loading:
                self._schedule_save()

        def _on_crypt_mode(self, row, pspec):
            if self._loading:
                return
            new = CRYPT_MODES[row.get_selected()]
            old = self._mode()
            if new == old:
                return
            self._collect()
            keep = dict(self.secrets or {})
            self.settings["crypt_mode"] = new
            if new == "none":
                self.secrets = {}
                try:
                    if os.path.exists(SECRETS_FILE):
                        os.unlink(SECRETS_FILE)
                except OSError:
                    pass
                self._toast("Hasła nie będą zapisywane; plik sekrety.enc usunięty.")
                self._do_save()
                return
            if new == "master":
                self.master = None
                self.secrets = keep

                def after():
                    self.secrets = keep
                    self._persist_secrets()
                    self._toast("Hasła przeszyfrowane hasłem głównym.")
                    self._do_save()

                self._ask_master(after, setting_up=True)
                return
            self.secrets = keep
            self._persist_secrets()
            self._toast("Hasła zaszyfrowane kluczem tego komputera.")
            self._do_save()

        def _sync_preset(self):
            """Ustawia listę zestawów pod to, co jest w polach ike/phase2alg.

            Nigdy nie wołane w środku obsługi zmiany samej listy — set_selected()
            wewnątrz własnego notify::selected zawiesza GtkSingleSelection.
            """
            if self._preset_busy:
                return
            ike = self.rows["ike"].get_text().strip()
            esp = self.rows["phase2alg"].get_text().strip()
            idx = len(PRESETS)
            for i, (_, a, b) in enumerate(PRESETS):
                if a == ike and b == esp:
                    idx = i
                    break
            if self.preset_row.get_selected() == idx:
                return
            self._preset_busy = True
            try:
                self.preset_row.set_selected(idx)
            finally:
                self._preset_busy = False

        def _on_preset(self, row, pspec):
            if self._loading or self._preset_busy:
                return
            idx = row.get_selected()
            if idx >= len(PRESETS):
                return
            _, ike, esp = PRESETS[idx]
            self._preset_busy = True
            try:
                self.rows["ike"].set_text(ike)
                self.rows["phase2alg"].set_text(esp)
            finally:
                self._preset_busy = False
            self._schedule_save()

        def _schedule_save(self):
            if self._save_source:
                GLib.source_remove(self._save_source)
            self._save_source = GLib.timeout_add(900, self._do_save)

        def _do_save(self):
            self._save_source = 0
            self._collect()
            try:
                save_store(self.profiles, self.settings)
            except OSError as exc:
                self._toast("Nie udało się zapisać profili: %s" % exc)
            self._persist_secrets()
            row = self.listbox.get_row_at_index(self.current)
            if row:
                p = self.profiles[self.current]
                row.set_title(p["name"] or "—")
                row.set_subtitle(p.get("right") or "brak bramy")
            return False

        def _on_add(self, *_a):
            self._collect()
            p = dict(DEFAULT_PROFILE)
            p["name"] = "profil-%d" % (len(self.profiles) + 1)
            self.profiles.append(p)
            self._build_profile_list()
            self._load_profile(len(self.profiles) - 1)
            self._do_save()

        def _on_duplicate(self, *_a):
            src = dict(self._collect())
            src["name"] = (src["name"] + "-kopia")[:48]
            self.profiles.append(src)
            self._build_profile_list()
            self._load_profile(len(self.profiles) - 1)
            self._do_save()

        def _on_delete(self, *_a):
            if len(self.profiles) <= 1:
                self._toast("Musi zostać przynajmniej jeden profil.")
                return
            dialog = Adw.MessageDialog(
                transient_for=self, heading="Usunąć profil?",
                body="Profil „%s” zostanie skasowany." % self.profiles[self.current]["name"])
            dialog.add_response("cancel", "Anuluj")
            dialog.add_response("delete", "Usuń")
            dialog.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)
            dialog.connect("response", self._delete_response)
            dialog.present()

        def _delete_response(self, dialog, response):
            if response != "delete":
                return
            name = self.profiles[self.current]["name"]
            del self.profiles[self.current]
            if self.secrets:
                self.secrets.pop(name, None)
            self.current = max(0, self.current - 1)
            self._build_profile_list()
            self._load_profile(self.current)
            self._do_save()

        def _on_where(self, *_a):
            self._toast("Dane: %s" % DATA_DIR)

        def _on_cleanup(self, *_a):
            self._collect()
            known = [p["name"] for p in self.profiles]

            def done(ok, res):
                removed = res.get("removed") or []
                if not ok:
                    self._toast(res.get("error", "Nie udało się posprzątać."))
                elif removed:
                    self._toast("Usunięto %d osieroconych plików." % len(removed))
                else:
                    self._toast("Nie było czego sprzątać.")

            self._run("cleanup", {"known": known},
                      "Sprzątanie /etc/ipsec.d…", done)

        # -- status -------------------------------------------------------

        def _refresh_status(self):
            st = read_state()
            p = self.profiles[self.current]
            connected = bool(st.get("connected")) and st.get("profile") == p["name"]
            if connected:
                self.status_icon.set_from_icon_name("network-vpn-symbolic")
                self.status_label.set_label("Połączony  ·  %s na %s"
                                            % (st.get("vpn_ip", "?"), st.get("iface", "?")))
                self.title.set_subtitle("połączony")
            else:
                self.status_icon.set_from_icon_name("network-vpn-disabled-symbolic")
                self.status_label.set_label("Rozłączony")
                self.title.set_subtitle("rozłączony")
            self.btn_connect.set_sensitive(not self.busy and not connected)
            self.btn_disconnect.set_sensitive(not self.busy and connected)

        def _poll_state(self):
            if not self.busy:
                self._refresh_status()
            return True

        def _check_policy_banner(self):
            problem, _ = policy_status()
            if problem:
                self.banner.set_title("W /etc/ipsec.conf aktywny jest include "
                                      "crypto-policies — blokuje IKEv1 (chacha20_poly1305).")
                self.banner.set_revealed(True)
            else:
                self.banner.set_revealed(False)

        def _on_check_policy(self, *_a):
            self._check_policy_banner()
            if not self.banner.get_revealed():
                self._toast("crypto-policies OK — include jest wyłączony.")

        def _on_fix_policy(self, *_a):
            def done(ok, res):
                self._check_policy_banner()
                self._toast("Poprawione." if ok else res.get("error", "Nie udało się."))
            self._run("fix-policy", {}, "Naprawianie /etc/ipsec.conf…", done)

        # -- akcje --------------------------------------------------------

        def _log(self, line):
            self.log_lines.append(line)
            buf = self.log_view.get_buffer()
            buf.insert(buf.get_end_iter(), line + "\n")
            mark = buf.create_mark(None, buf.get_end_iter(), False)
            self.log_view.scroll_mark_onscreen(mark)
            buf.delete_mark(mark)

        def _flush_log(self):
            try:
                with open(LOG_FILE, "w") as fh:
                    fh.write("\n".join(self.log_lines[-2000:]) + "\n")
            except OSError:
                pass

        def _toast(self, text):
            self.toasts.add_toast(Adw.Toast(title=text, timeout=4))

        def _set_busy(self, busy, label=None):
            self.busy = busy
            if busy:
                self.spinner.start()
                if label:
                    self.status_label.set_label(label)
                self.btn_connect.set_sensitive(False)
                self.btn_disconnect.set_sensitive(False)
            else:
                self.spinner.stop()
                self._refresh_status()

        def _run(self, command, payload, busy_label, done_cb):
            self._set_busy(True, busy_label)
            self.log_toggle.set_active(True)
            self._log("")
            self._log("──── %s ────" % busy_label)

            def on_done(ok, res):
                self._set_busy(False)
                if not ok and res.get("error"):
                    self._log("BŁĄD: " + res["error"])
                self._flush_log()
                done_cb(ok, res)

            Helper(command, payload, self._log, on_done)

        def _payload(self):
            p = dict(self._collect())
            p["psk"] = self.psk_row.get_text()
            p["xauth"] = self.xauth_row.get_text()
            p["keep_secrets"] = False
            p["known"] = [q["name"] for q in self.profiles]
            return p

        def _on_connect(self, *_a):
            def go():
                p = self._payload()
                if not p.get("right") or not p.get("username"):
                    self._toast("Uzupełnij bramę VPN i użytkownika XAUTH.")
                    return
                if not p.get("psk") or not p.get("xauth"):
                    self._ask_secrets(p)
                    return
                self._do_connect(p)
            self._ensure_secrets(go)

        def _ask_secrets(self, p):
            dialog = Adw.MessageDialog(transient_for=self, heading="Dane logowania",
                                       body="Profil „%s”" % p["name"])
            box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            psk = Gtk.PasswordEntry(show_peek_icon=True)
            psk.set_placeholder_text("Klucz PSK")
            psk.set_text(p.get("psk", ""))
            xa = Gtk.PasswordEntry(show_peek_icon=True)
            xa.set_placeholder_text("Hasło XAUTH")
            xa.set_text(p.get("xauth", ""))
            box.append(psk)
            box.append(xa)
            dialog.set_extra_child(box)
            dialog.add_response("cancel", "Anuluj")
            dialog.add_response("ok", "Połącz")
            dialog.set_default_response("ok")
            dialog.set_response_appearance("ok", Adw.ResponseAppearance.SUGGESTED)

            def resp(dlg, response):
                if response != "ok":
                    return
                p["psk"] = psk.get_text()
                p["xauth"] = xa.get_text()
                self._do_connect(p)

            dialog.connect("response", resp)
            dialog.present()

        def _do_connect(self, p):
            def done(ok, res):
                self._toast(("Połączono — %s" % res.get("vpn_ip", "")) if ok
                            else res.get("error", "Nie udało się połączyć."))
            self._run("up", p, "Łączenie z %s…" % p["name"], done)

        def _on_disconnect(self, *_a):
            def done(ok, res):
                self._toast("Rozłączono." if ok else res.get("error", "Błąd rozłączania."))
            self._run("down", self._payload(), "Rozłączanie…", done)

        def shutdown_after_disconnect(self):
            """Wywoływane z trayu (akcja 'rozlacz-i-zamknij') albo z --auto-shutdown:
            rozłącz aktywny profil (jeśli jest połączony) i dopiero potem zamknij okno."""
            st = read_state()
            if not st.get("connected"):
                self.close()
                return
            idx = next((i for i, p in enumerate(self.profiles)
                        if p["name"] == st.get("profile")), None)
            if idx is not None and idx != self.current:
                self._load_profile(idx)

            def done(ok, res):
                if not ok:
                    self._toast(res.get("error", "Błąd rozłączania."))
                self.close()
            self._run("down", self._payload(), "Rozłączanie…", done)

        def _on_close(self, *_a):
            if self._save_source:
                GLib.source_remove(self._save_source)
                self._save_source = 0
            self._do_save()
            self._flush_log()
            return False

    class App(Adw.Application):
        def __init__(self):
            super().__init__(application_id=APP_ID, flags=Gio.ApplicationFlags.FLAGS_NONE)
            action = Gio.SimpleAction.new("rozlacz-i-zamknij", None)
            action.connect("activate", self._on_rozlacz_i_zamknij)
            self.add_action(action)

        def _on_rozlacz_i_zamknij(self, _action, _param):
            win = self.props.active_window
            if win:
                win.shutdown_after_disconnect()

        def do_activate(self):
            first = self.props.active_window is None
            win = self.props.active_window or Window(self)
            win.present()
            if first:
                if not os.environ.get("BVPN_SELFTEST"):
                    _spawn_tray()
                if auto_shutdown:
                    def _start_auto_shutdown():
                        win.shutdown_after_disconnect()
                        return False
                    GLib.idle_add(_start_auto_shutdown)
            if os.environ.get("BVPN_SELFTEST"):
                GLib.timeout_add(400, _selftest, self, win)

    def _selftest(app, win):
        """Przeklikanie okna bez udziału użytkownika (BVPN_SELFTEST=1)."""
        try:
            win.rows["right"].set_text("203.0.113.1")
            win.rows["username"].set_text("testuser")
            win.psk_row.set_text("psk-testowy")
            win.xauth_row.set_text("xauth-testowe")
            win._on_add()
            win.rows["name"].set_text("drugi-profil")
            win.rows["right"].set_text("10.20.30.40")
            win.psk_row.set_text("drugi-psk")
            win._do_save()
            win.preset_row.set_selected(4)
            assert win.rows["ike"].get_text() == "aes256-sha1;modp1024", "preset nie ustawił ike"
            win.rows["ike"].set_text("aes256-sha512;ecp256")
            win.rows["phase2alg"].set_text("aes256-sha512")
            assert win.preset_row.get_selected() == 0, "preset nie wrócił do zestawu 0"
            win._on_duplicate()
            win.listbox.select_row(win.listbox.get_row_at_index(0))
            win._load_profile(0)
            assert win.psk_row.get_text() == "psk-testowy", "sekret nie wrócił po zmianie profilu"
            win._on_delete()
            win.crypt_row.set_selected(0)
            win._do_save()
            win._log("selftest: log działa")
            win._flush_log()
            win._toast("selftest")
            win._refresh_status()
            data = json.load(open(PROFILES_FILE))
            names = [p["name"] for p in data["profiles"]]
            blob = open(SECRETS_FILE).read()
            sec = load_secrets(machine_passphrase())
            assert "psk-testowy" not in blob, "hasło jawne w pliku!"
            assert sec[names[0]]["psk"] == "psk-testowy", "sekret nie zaszyfrował się poprawnie"
            print("SELFTEST OK — profile: %s, sekrety: %s" % (names, sorted(sec)))
        except Exception as exc:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            print("SELFTEST BŁĄD: %r" % exc)
        app.quit()
        return False

    return App().run([sys.argv[0]])


# ==========================================================================
#  TRAY (wskaźnik połączenia w KDE Plasma) — osobny proces, osobny GTK 3
# ==========================================================================

def tray_main():
    """Ikonka w trayu: startowana przez GUI przy pierwszym uruchomieniu,
    ale żyje niezależnie od okna (start_new_session). Czyta dane/stan.json,
    nie dotyka libreswana ani pkexec bezpośrednio — do rozłączenia zawsze
    prosi działającą (albo dopiero startowaną) instancję GUI.

    Wymaga libayatana-appindicator-gtk3 (albo starszego libappindicator-gtk3).
    Ta biblioteka wystawia menu jako Gtk.Menu z GTK 3 — stąd osobny proces,
    żeby nigdy nie ładować GTK 3 i GTK 4 razem w jednym interpreterze co GUI.
    """
    if not _tray_acquire_lock():
        return 0

    try:
        import gi
        gi.require_version("Gtk", "3.0")
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            from gi.repository import AyatanaAppIndicator3 as AppIndicator3
        except ValueError:
            gi.require_version("AppIndicator3", "0.1")
            from gi.repository import AppIndicator3
        from gi.repository import Gtk, GLib, Gio
    except (ImportError, ValueError) as exc:
        sys.stderr.write(
            "Brak wskaźnika trayu (%s).\n"
            "Fedora: sudo dnf install libayatana-appindicator-gtk3\n" % exc)
        _tray_release_lock()
        return 1

    def gui_bus_owned():
        try:
            bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
            proxy = Gio.DBusProxy.new_sync(
                bus, Gio.DBusProxyFlags.NONE, None,
                "org.freedesktop.DBus", "/org/freedesktop/DBus",
                "org.freedesktop.DBus", None)
            res = proxy.call_sync("NameHasOwner", GLib.Variant("(s)", (APP_ID,)),
                                   Gio.DBusCallFlags.NONE, -1, None)
            return bool(res.unpack()[0])
        except GLib.Error:
            return False

    def launch_gui(extra_arg=None):
        argv = [sys.executable, SELF] + ([extra_arg] if extra_arg else [])
        try:
            subprocess.Popen(argv, start_new_session=True,
                              stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
        except OSError:
            pass

    quit_state = {"watch_id": None, "timeout_id": None, "seen_appeared": 0}

    def on_show(_item):
        launch_gui()

    def _quit_watch_stop():
        if quit_state["watch_id"] is not None:
            Gio.bus_unwatch_name(quit_state["watch_id"])
            quit_state["watch_id"] = None
        if quit_state["timeout_id"] is not None:
            GLib.source_remove(quit_state["timeout_id"])
            quit_state["timeout_id"] = None
        quit_state["seen_appeared"] = 0

    def _quit_finish():
        _quit_watch_stop()
        _tray_release_lock()
        Gtk.main_quit()

    def _quit_give_up():
        # Coś nie zadziałało w rozsądnym czasie (np. rozłączanie się zawiesiło) —
        # nie czekamy w nieskończoność, można spróbować "Zamknij" jeszcze raz.
        _quit_watch_stop()
        return False

    def _quit_on_appeared(_conn, _name, _owner):
        quit_state["seen_appeared"] += 1

    def _quit_on_vanished(_conn, _name):
        # g_bus_watch_name woła vanished-handler też jako stan początkowy, gdy
        # nazwa jeszcze nie ma właściciela — ignorujemy to, liczy się tylko
        # zniknięcie PO tym, jak GUI faktycznie się pojawiło na magistrali.
        if quit_state["seen_appeared"] > 0:
            _quit_finish()

    def on_quit(_item):
        if quit_state["watch_id"] is not None:
            return
        if gui_bus_owned():
            try:
                bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
                group = Gio.DBusActionGroup.get(bus, APP_ID, "/" + APP_ID.replace(".", "/"))
                group.activate_action("rozlacz-i-zamknij", None)
            except GLib.Error:
                launch_gui("--auto-shutdown")
        else:
            launch_gui("--auto-shutdown")
        quit_state["watch_id"] = Gio.bus_watch_name(
            Gio.BusType.SESSION, APP_ID, Gio.BusNameWatcherFlags.NONE,
            _quit_on_appeared, _quit_on_vanished)
        quit_state["timeout_id"] = GLib.timeout_add_seconds(120, _quit_give_up)

    _ensure_tray_icons()
    indicator = AppIndicator3.Indicator.new(
        APP_ID, TRAY_ICON_OFF,
        AppIndicator3.IndicatorCategory.APPLICATION_STATUS)
    indicator.set_icon_theme_path(TRAY_ICON_DIR)
    indicator.set_status(AppIndicator3.IndicatorStatus.ACTIVE)

    menu = Gtk.Menu()
    item_show = Gtk.MenuItem(label="Pokaż")
    item_show.connect("activate", on_show)
    menu.append(item_show)
    item_quit = Gtk.MenuItem(label="Zamknij")
    item_quit.connect("activate", on_quit)
    menu.append(item_quit)
    menu.show_all()
    indicator.set_menu(menu)

    def refresh(*_a):
        st = read_state()
        if st.get("connected"):
            indicator.set_icon_full(TRAY_ICON_ON, "Połączony — %s" % st.get("profile", ""))
        else:
            indicator.set_icon_full(TRAY_ICON_OFF, "Rozłączony")
        return True

    refresh()
    GLib.timeout_add_seconds(2, refresh)
    Gtk.main()
    _quit_watch_stop()
    _tray_release_lock()
    return 0


# ==========================================================================

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--helper":
        helper_main(sys.argv[2:])
        return 0
    if len(sys.argv) > 1 and sys.argv[1] == "--tray":
        return tray_main()
    if len(sys.argv) > 1 and sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0
    auto_shutdown = len(sys.argv) > 1 and sys.argv[1] == "--auto-shutdown"
    try:
        return gui_main(auto_shutdown=auto_shutdown)
    except (ImportError, ValueError) as exc:
        sys.stderr.write(
            "Brakuje GTK4/libadwaita dla Pythona (%s).\n"
            "Fedora:  sudo dnf install python3-gobject gtk4 libadwaita\n" % exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
