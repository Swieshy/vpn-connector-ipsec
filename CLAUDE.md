# CLAUDE.md — VPN Connector IPsec: guide and notes for the next session

This file is both user documentation and technical notes for the next Claude
Code session — deliberately kept in one file. Read this before changing
anything. User: Rafał, Fedora + KDE Plasma. The project's language is now
English — documentation, GUI text, and code comments should be in English
(the user may still write to Claude in Polish in chat; that's fine, this is
about the project artifacts, not the chat language).

## Installation and running

A portable GUI (GTK4 + libadwaita) for libreswan in IKEv1 aggressive + XAUTH
mode — what Rafał's earlier bash script did, just with profiles, cipher
selection, and log preview.

**No installer.** Unpack anywhere and run:

```bash
chmod +x vpn-connector-ipsec.py
./vpn-connector-ipsec.py
```

Requirements (Fedora usually has these out of the box): `libreswan`, `polkit`,
`openssl`, `python3-gobject`, `gtk4`, `libadwaita`. If anything is missing:

```bash
sudo dnf install libreswan polkit openssl python3-gobject gtk4 libadwaita
```

The tray icon (described below) additionally needs GTK 3 and AppIndicator —
on a clean Fedora you usually need to install:

```bash
sudo dnf install libayatana-appindicator-gtk3
```

Without this package the app still works normally — the tray just won't show
up (a message about the missing library will appear in the terminal).

## Where this came from

Rafał had a working, hand-tuned libreswan configuration for the company's
FortiGate: IKEv1 + aggressive mode + XAUTH + modecfg + split tunneling on
`10.0.0.0/8`, plus a bash `connect`/`disconnect` script. He asked for a GUI
with profiles and the ability to change ciphers. Further refinements made
along the way:

1. "it should be lightweight, so it doesn't bog things down" → GTK4 +
   libadwaita via PyGObject (already present on Fedora, single process, no
   background daemon).
2. "better without an installer, make it a portable application" → a single
   `.py` file, no `install.sh`, no polkit policy in `/usr/share`.
3. "all data saved in a folder next to the file, passwords hashed if
   possible" → a `dane/` directory next to the script, passwords encrypted
   (not hashed — hashing is one-way, and libreswan needs plaintext; this was
   explained to Rafał).
4. "cleanup is fine — for profiles no longer on the list" → automatic
   deletion of orphaned `bvpn-*.conf/.secrets` after a successful connection,
   plus a menu item.
5. "a tray icon, so you can see whether the VPN is active" → a separate
   `--tray` process (KDE Plasma, AppIndicator), launched together with the
   GUI, closed independently from the icon's menu (see "Tray icon" below and
   point 7 in "Things that are easy to break").

**Do not suggest an installer, an RPM package, or a systemd service without
an explicit request.** Portability is a deliberate choice.

## Where the data lands

Everything next to the script, in the `dane/` folder:

| File | What's inside |
|---|---|
| `dane/profile.json` | profiles — **no passwords**, chmod 600 |
| `dane/sekrety.enc` | PSK and XAUTH passwords, AES-256-CBC, key from PBKDF2 (240,000 iterations), chmod 600 |
| `dane/stan.json` | connection state (for the indicator in the window and in the tray) |
| `dane/tray.pid` | PID of the tray indicator — guards a single instance at a time |
| `dane/ostatni-log.txt` | log of the last action |

If the folder containing the script is read-only, the app falls back to
`~/.config/vpn-connector-ipsec/`. The menu → "Where is the data?" shows the
current path.

Outside this folder, only the files libreswan itself requires are created —
see "libreswan files" below.

## Password protection

Menu, "Passwords" section, three modes (`settings.crypt_mode` in
`profile.json`):

- **Key tied to this computer** (`machine`, default) — no prompt for
  anything. The key is derived from `/etc/machine-id` + username + UID.
  Copying `dane/` to another computer or to a colleague's account gets you
  nothing; whoever has root on *this* machine can reconstruct the key. This
  is protection against accidental glancing and against a lost USB stick,
  **not against an admin** — that's how it's described here and that's how
  it should be explained to Rafał, not sold as full security.
- **Master password** (`master`) — asked once after the app starts, kept
  only in the process's memory (`self.master`). Real protection, at the cost
  of one dialog per session.
- **Don't save passwords** (`none`) — the `sekrety.enc` file is deleted, the
  app asks for the PSK and XAUTH password on every connection.

Passwords never end up in `profile.json` or in the logs.

## Tray icon (KDE Plasma)

On the GUI's first startup it also launches the tray indicator — a separate
process (`./vpn-connector-ipsec.py --tray`), independent of the window:
closing the app window (via the X button) does **not** close the tray, and
that's the point — the icon is meant to show connection status even when you
don't have the window open.

The icon: a green circle when connected, a gray empty circle when not. These
are **our own SVGs, not names from the system icon theme** — the first
version tried Adwaita names (`network-vpn-symbolic` /
`network-vpn-disabled-symbolic` / `network-vpn-disconnected-symbolic`), but
Breeze (KDE) doesn't have those "disabled" variants, so looking them up by
name didn't match, and the tray always kept the last icon it had
successfully found — it looks like "the icon doesn't change," regardless of
connection state. Hence `_ensure_tray_icons()` writes two small SVGs (built
into the code as `_TRAY_ICON_ON_SVG`/`_TRAY_ICON_OFF_SVG`) to `dane/icons/`
when the tray starts, and `indicator.set_icon_theme_path(TRAY_ICON_DIR)`
points AppIndicator there — 100% independent of whatever icon theme the user
has. If you change how the icons look, edit those two constants; don't try
to go back to names from the system theme. Right-click menu:

- **Show** — opens (or raises, if already running) the app window.
- **Close** — opens the window, disconnects the active profile (if
  connected), and only once disconnecting is finished closes both the window
  and the tray. This is the only way to turn off the icon — closing just the
  window doesn't touch it.

The tray never touches `pkexec`/`ipsec` directly — to disconnect it always
asks the running (or just-started) GUI instance. A single tray instance at a
time is guarded by the `dane/tray.pid` file. A technical description of the
tray ↔ GUI protocol is in point 7 of the "Things that are easy to break"
section.

The tray is only tested on **KDE Plasma** (native StatusNotifierItem/
AppIndicator). On GNOME Shell it would need the "AppIndicator and
KStatusNotifierItem Support" extension — untested, don't assume it works
without it.

## Permissions

The GUI runs as a regular user. When root is needed, it launches **this same
file** again: `pkexec python3 vpn-connector-ipsec.py --helper <command>`. The
profile configuration goes to it as JSON over stdin, and the helper
validates every field with a regex before it touches `/etc/ipsec.d`, `ipsec`,
`ip`, or `systemctl`. polkit caches authorization for a few minutes by
default, so it doesn't prompt on every click. Technical details (why
`pkexec python3 <file>` and not `pkexec <file>`) are in the "Architecture"
section below.

## libreswan files

Each profile has its own pair, recreated on every connection:

- `/etc/ipsec.d/bvpn-<profile>.conf` — overwritten with the form's contents
  on "Connect", stays on disk (chmod 644, nothing sensitive).
- `/etc/ipsec.d/bvpn-<profile>.secrets` — created (chmod 600) right before
  `ipsec up`, zeroed out and deleted right after the tunnel is established.

The `bvpn-` prefix means the app will never touch Rafał's manual `.conf` file
that predates this GUI — it remains as a fallback.

Profile files that are no longer on the list are automatically deleted after
every successful connection, and on demand from the menu →
"Clean up /etc/ipsec.d".

## First run

1. If `/etc/ipsec.conf` has an active
   `include /etc/crypto-policies/back-ends/libreswan.config`, a bar with a
   **Fix** button will appear at the top of the window — clicking it
   comments out that line and leaves a copy at `/etc/ipsec.conf.bvpn-backup`.
   This is the same step 1 that Rafał used to do manually.
2. Fill in a profile (the default one is named `profile-1`): gateway (e.g.
   `203.0.113.1`), network `10.0.0.0/8`, XAUTH user, `leftid`/`rightid` (e.g.
   `@my-key`), PSK, and XAUTH password. Leave the interface at `auto` (it
   takes it from the default route, so it works both over wifi and over
   cable); leave **VPN address** at `auto` too (it reads what modecfg
   assigns; if that read fails, enter the address assigned by the gateway
   manually).
3. **Connect**.

## What "Connect" does

The sequence from Rafał's original script, just tidied up:

1. write `bvpn-<profile>.conf` and `.secrets`,
2. delete routes and addresses left from the previous connection,
3. `systemctl restart ipsec` + wait for pluto to actually come up,
4. `ipsec rereadsecrets`, `ipsec add`, `ipsec up`,
5. read the address assigned by modecfg,
6. `ip addr add <vpn_ip>/32` + `ip route replace 10.0.0.0/8 dev <iface> src <vpn_ip>`,
7. delete the `.secrets` file and any orphaned files from removed profiles.

"Disconnect" does the same thing in reverse.

## Changing the encryption

The "Tunnel encryption" section: a list of ready-made sets (Rafał's
`aes256-sha512;ecp256` is first) or manual editing of `ike=` and
`phase2alg=`, plus switches for PFS, aggressive mode, and NAT-T. If the
gateway rejects the proposal, the app recognizes `no acceptable proposal`
and states plainly that it's about the algorithms.

## Application menu shortcut (optional)

Menu → **"Add to application menu"** writes
`~/.local/share/applications/vpn-connector-ipsec.desktop` with this file's real
location, so nothing has to be edited by hand. Run it again after moving the
folder and the path is rewritten. Nothing else gets installed on the system, and
no root is involved.

`install_desktop_entry()` invokes `python3` explicitly rather than the script
itself, so the entry keeps working even without the `+x` bit. Note that `Exec=`
is **not** passed through a shell: `$HOME`, `~` and `${VAR}` are never expanded,
which is exactly why the shipped `.desktop` used to carry a hand-edited
placeholder path. A `%` in the path has to be doubled, or it is read as a field
code (`%f`, `%U`), and arguments containing spaces need double quotes — see
`_desktop_quote()`, which quotes only when needed because some launchers dislike
a quoted program name.

The shipped `vpn-connector-ipsec.desktop` is kept as a reference only; it routes
through `sh -c` so that `$HOME` can be expanded at all.

## Diagnostics

| Symptom | What to check |
|---|---|
| `The ipsec service did not come up` | `journalctl -u ipsec -n 50` — usually crypto-policies |
| `no acceptable proposal` | the cipher set in the Encryption section |
| XAUTH rejected | username and password; `leftusername` must match the XAUTH entry |
| Tunnel comes up, no traffic | `ip route get 10.0.0.1` — is the route going through the right interface |
| Address not read from modecfg | enter **VPN address** manually |
| Forgotten master password | delete `dane/sekrety.enc` and re-enter the passwords |
| Window hangs, CPU heats up | collect a traceback: `PYTHONFAULTHANDLER=1 timeout -s ABRT 25 ./vpn-connector-ipsec.py` — see "Testing without a VPN" |
| Tray doesn't show up | check whether `libayatana-appindicator-gtk3` is installed; the terminal message will say what's missing |

## Uninstalling

Delete the folder. Optionally clean up after libreswan:

```bash
sudo rm -f /etc/ipsec.d/bvpn-*
sudo mv /etc/ipsec.conf.bvpn-backup /etc/ipsec.conf   # if you want to undo "Fix"
```

## Note on the original script

In `podsumowanievpn.md` the script has broken escaping after the heredoc —
`"\(VPN_IP/32"` instead of `"$VPN_IP/32"`, and `dev "INTERFACE" src "VPN_IP"`
without `$`. The app reproduces the intended logic correctly and uses
`ip route replace` instead of `add`, so it doesn't fail when the route
already exists.

The generated `.conf` matches Rafał's working file byte for byte (verified
with a diff) — only the `conn` name changes, to `bvpn-<profile>`.

## Architecture

A single file, `vpn-connector-ipsec.py`, with three roles:

- **GUI** (`gui_main()`) — regular user, GTK4/libadwaita. Never has root.
- **helper** (`helper_main()`, invoked as `--helper <cmd>`) — root, launched
  via `pkexec python3 <this file> --helper <cmd>`.
- **tray** (`tray_main()`, invoked as `--tray`) — regular user, GTK **3**
  (deliberately different from the GUI — see point 7 below). The KDE Plasma
  tray icon.

Why `pkexec python3 <file>` and not `pkexec <file>`: pkexec refuses to run a
program that isn't owned by root and writable by others. A script in the
home directory isn't like that, but `/usr/bin/python3` already is — and
pkexec only checks the executable, not its arguments. This means nothing
needs to be installed under `/usr`. Having no dedicated polkit action means
the default `org.freedesktop.policykit.exec` is used (`auth_admin_keep` for
the active session — password once every few minutes).

**Security consequence to keep in mind:** whoever can write to
`vpn-connector-ipsec.py` will, after pkexec authorization, run their code as
root. This is the same level of trust as your own script run via sudo. Don't
put this file in a directory writable by others.

### GUI ↔ helper protocol

- the profile goes to the helper's **stdin** as JSON,
- the helper streams logs line by line to **stdout** (the GUI shows them
  live),
- the last line is `##RESULT## {json}` — the structured result,
- exit code: 0 = OK, 126 = pkexec authorization canceled, 127 = pkexec not found.

The `Helper` class in the GUI uses `Gio.SubprocessLauncher` +
`read_line_async`, so the window doesn't block.

### Helper commands

`up`, `down`, `status`, `cleanup`, `check-policy`, `fix-policy`.

## Things that are easy to break

### 1. The generated `.conf` must stay consistent with the working configuration

`build_conf()` produces exactly the same lines as Rafał's manual file
(verified with a diff — zero differences, aside from the `conn
bvpn-<profile>` name). If you change anything there, run it through this
test:

```python
gen = [l for l in build_conf(clean(profile)).splitlines()
       if l.strip() and not l.startswith(("#", "conn"))]
# compare against the block from podsumowanievpn.md
```

In particular: `leftupdown=/usr/bin/true` (without this, libreswan pokes at
routes on its own and breaks split tunneling), `modecfgpull=yes`,
`encapsulation=yes`.

### 2. Adw.ComboRow: don't call `set_selected()` inside `notify::selected`

This **hangs** the app hard (not an exception — a lock inside
GtkSingleSelection; caught with the faulthandler during testing). Hence the
`self._preset_busy` flag and the early returns in `_sync_preset()` /
`_on_preset()`. If you add another ComboRow with two-way synchronization,
apply the same pattern.

### 3. Validation in the helper is the only barrier

The helper runs as root and receives data from the GUI. Every field goes
through a regex (`NAME_RE`, `ID_RE`, `USER_RE`, `ALGO_RE`, `IFACE_RE`,
`NUM_RE`) or through `ipaddress`. All system calls go as an argument list to
`subprocess.run` — **never `shell=True`**. When adding a new field, add
validation in `clean()`; don't trust the GUI.

Tested and rejected: `8.8.8.8; rm -rf /`, `` aes256`whoami` ``, `wlo1;ls`,
`../../etc/passwd`, `user$(id)`, `@my-key && reboot`.

### 4. Password encryption

`openssl enc -aes-256-cbc -pbkdf2 -iter 240000`, the password passed via
`-pass fd:N` (`pass_fds` in subprocess) — not via argv or env, so it isn't
visible in `ps`. Deliberately **without** the `cryptography` library: openssl
is present on every Fedora, and an external dependency would hurt
portability. The modes are described in the "Password protection" section
above.

### 5. Address from modecfg

`detect_vpn_ip()` parses `ipsec status`, looking for `<ip>/32===` in lines
containing the connection name, polling 10 × 0.5 s. This is the most
fragile part of the whole thing — the output format depends on the
libreswan version. If Rafał reports "the tunnel comes up, but the address
isn't read," ask for `sudo ipsec status | grep bvpn-` and adjust the regex.
As a fallback there's the **VPN address** field for entering it manually (in
Rafał's case, the specific address assigned by his gateway).

### 6. crypto-policies

Fedora injects `chacha20_poly1305` into IKEv1 via
`include /etc/crypto-policies/back-ends/libreswan.config` in
`/etc/ipsec.conf`, which prevents the service from starting. `policy_status()`
detects this (reading without root), `fix-policy` comments out the line and
makes a `.bvpn-backup` backup. This was step 1 of Rafał's manual instructions
and the most common cause of "it doesn't work."

### 7. Tray — why a separate process, and the EOF trap in `Helper._got_line`

The tray icon (`tray_main()`, `--tray`) uses `AyatanaAppIndicator3`, and that
library exposes its menu as a `Gtk.Menu` from **GTK 3** — it can't be called
from the same interpreter as the GUI (GTK 4/libadwaita). That's why the tray
is a separate process, launched by `_spawn_tray()` with
`start_new_session=True`, living independently of the GUI window. A single
instance is guarded by the `dane/tray.pid` file
(`_tray_acquire_lock`/`_tray_release_lock`).

Tray → GUI communication goes through a **GAction exported over D-Bus**, not
a new channel: `App` registers the `"rozlacz-i-zamknij"` action
(`Gio.SimpleAction`), and GApplication automatically exposes it under
`/org/example/vpnconnectoripsec` (dots → slashes from `APP_ID`). The tray
checks `org.freedesktop.DBus.NameHasOwner` for `APP_ID`: if the GUI is
already running, it calls
`Gio.DBusActionGroup.get(...).activate_action("rozlacz-i-zamknij", None)`;
if not, it starts `vpn-connector-ipsec.py --auto-shutdown`, which itself
calls `Window.shutdown_after_disconnect()` after showing the window. "Show"
from the tray is just launching `vpn-connector-ipsec.py` with no arguments —
the uniqueness of `APP_ID` in `Gio.Application` (default flags, no
`NON_UNIQUE`) activates the existing window on its own instead of creating a
second one.

**A trap that was already hit and fixed** (see `Helper._got_line`, the class
the GUI uses to read logs from the helper): end of stream
(`read_line_finish`) in GLib returns `NULL` in C, but due to a faulty
PyGObject introspection annotation it can come through as an empty `b""`
instead of `None`. The condition `if data is None: return` doesn't catch
this — `self._read()` calls itself over and over via `g_idle_dispatch`
without blocking, which pegs one thread at 100% and freezes the window
(visible as a hung GUI + a hot CPU, even though the VPN operation itself
physically finishes, since the helper is a separate process). This was found
via `PYTHONFAULTHANDLER=1 timeout -s ABRT 25` — the captured traceback showed
the main thread in the loop `g_main_context_iteration → g_idle_dispatch →
... → _got_line`. Fix: `if not data: return` (catches both cases). If you add
another similar asynchronous stream read, use the same pattern — never `is
None` on its own.

**A second trap, also found and fixed: "Close" sometimes didn't finish
closing the tray.** The first version detected the end of the
disconnect-and-close sequence by polling `NameHasOwner` on D-Bus every 2
seconds (the same timer as the icon refresh) with a simple 0→1→2 phase state
machine. The problem: if the GUI finished faster than those 2 seconds — which
is exactly what happens when the profile wasn't connected at the time,
because `shutdown_after_disconnect()` then calls `self.close()` almost
immediately — the tray never managed to sample at a moment when the name was
still on the bus. Phase 1 never advanced to phase 2, so the condition
"disappeared after it appeared" never got confirmed, and the tray stayed
around forever (until the 120 s "fuse" timeout, which only gave up on the
attempt, without closing the icon). Fix: instead of polling — an
event-driven `Gio.bus_watch_name()` on `APP_ID`, with a `seen_appeared`
counter (because `g_bus_watch_name` also calls the `vanished` handler as an
initial state, when the name doesn't have an owner yet — that has to be
ignored; only a disappearance *after* at least one `appeared` counts). This
eliminates the timing gap entirely, regardless of how fast the GUI closes.
If you add similar "wait until something on D-Bus finishes" logic, use this
pattern, not timer-based polling.

### 8. The XAUTH index in `.secrets` must be an ID (`@user`), not a bare name

`build_secrets()` writes two lines: the PSK, indexed by `leftid` + gateway
address, and the XAUTH password, indexed by the XAUTH user. That second index
**has to carry the `@`**:

```
@my-group 203.0.113.1 : PSK "..."
@vpn-user : XAUTH "..."
```

pluto looks the XAUTH password up through `lsw_get_xauthsecret()`, which builds
an `ID_FQDN` out of `leftusername`. A bare `vpn-user` is parsed as a hostname,
libreswan reports

```
ERROR "/etc/ipsec.d/bvpn-<profile>.secrets" line 3: index "vpn-user" not a
numeric IPv4 address and name lookup failed (no validation performed)
```

and the entry then never matches. The failure is misleading: phase 1 comes up
fine (`ISAKMP SA established`), then pluto answers the XAUTH challenge with an
empty password three times, and the gateway responds with `Delete SA`. It reads
exactly like a wrong password or a token prompt, so the app's own hint
("XAUTH rejected by the gateway") points in the wrong direction. If XAUTH fails,
**read the `rereadsecrets` output in the log first** — that `ERROR` line is the
tell.

This bug hid for a long time because Rafał's oldest profile also matched his
hand-written `/etc/ipsec.d/<name>.secrets` (no `bvpn-` prefix, so neither
`cleanup_orphans` nor `purge_generated` ever touches it), which has the correct
syntax. That one profile worked; every new one failed. When a profile "works
only for the original connection," check for legacy secrets files supplying
what the generated one doesn't.

## Testing without a VPN

The code has a headless self-test — it clicks through the window and checks
assertions:

```bash
rm -rf dane && BVPN_SELFTEST=1 xvfb-run -a timeout 40 python3 -u vpn-connector-ipsec.py
# expected: "SELFTEST OK — profiles: [...], secrets: [...]"
```

It checks: adding/duplicating/switching profiles, secrets coming back after
switching profiles, two-way preset synchronization, no plaintext password in
`sekrety.enc`, correct decryption. The tray is disabled in this mode
(`BVPN_SELFTEST` skips `_spawn_tray()`), so the test doesn't leave an
orphaned process behind.

If the GUI hangs: `PYTHONFAULTHANDLER=1` + `timeout -s ABRT 25` gives a
traceback from where it's stuck. That's how the ComboRow trap and the EOF
trap in `Helper._got_line` (point 7 above) were found.

The helper can be tested without libreswan — it degrades gracefully with
sensible messages:

```bash
echo '{"name":"t","right":"1.2.3.4","rightsubnet":"10.0.0.0/8","username":"u"}' \
  | sudo python3 vpn-connector-ipsec.py --helper up
```

Note: `pyflakes` passes cleanly — keep it that way.

## What's still missing (candidates for next steps)

- The tray icon is only on KDE Plasma (see above) — untested on GNOME Shell.
- Auto-reconnect after a drop (DPD is already configured on the tunnel side).
- Importing an existing `/etc/ipsec.d/*.conf` into a profile.
- IKEv2 — `clean()` already accepts `keyexchange`, but the GUI doesn't expose
  it and it hasn't been tested.
- A preview of `ipsec trafficstatus` in the window (the helper's `status`
  command already returns this data, the GUI doesn't use it).
- The connection state in `dane/stan.json` is written by root, so the file
  is owned by root. The user can delete it (the directory is theirs), but if
  the data were moved to FAT/a USB stick, `chmod` would silently fail — this
  is handled with `try/except`.

## Working style with this user

Rafał adds requirements as he goes — he reads responses as they come and
asks follow-up technical questions ("where do you save that?", "does a new
profile mean new files?"). Answer concretely and briefly, no marketing. He
appreciates it when you point out an error in his material — e.g. the broken
escaping `"\(VPN_IP/32"` and `dev "INTERFACE" src "VPN_IP"` (missing `$`) in
`podsumowanievpn.md`, resulting from the heredoc.
