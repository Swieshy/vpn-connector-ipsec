# CLAUDE.md — VPN Connector IPsec: instrukcja i notatki dla kolejnej sesji

Ten plik jest jednocześnie dokumentacją użytkownika i notatkami technicznymi
dla kolejnej sesji Claude Code — świadomie trzymane w jednym pliku. Czytaj to,
zanim cokolwiek zmienisz. Użytkownik: Rafał, Fedora + KDE Plasma,
mówi po polsku — odpowiadaj po polsku. Komentarze w kodzie, teksty w GUI i
dokumentacja też po polsku.

## Instalacja i uruchomienie

Przenośne GUI (GTK4 + libadwaita) do libreswana w trybie IKEv1 aggressive +
XAUTH — to, co robił wcześniejszy skrypt bashowy Rafała, tylko z profilami,
wyborem szyfrów i podglądem logów.

**Bez instalatora.** Rozpakuj gdzie chcesz i uruchom:

```bash
chmod +x vpn-connector-ipsec.py
./vpn-connector-ipsec.py
```

Wymagania (Fedora ma to zwykle z pudełka): `libreswan`, `polkit`, `openssl`,
`python3-gobject`, `gtk4`, `libadwaita`. Gdyby czegoś brakowało:

```bash
sudo dnf install libreswan polkit openssl python3-gobject gtk4 libadwaita
```

Ikonka w trayu (opisana niżej) potrzebuje dodatkowo GTK 3 i AppIndicator —
na czystej Fedorze zwykle trzeba doinstalować:

```bash
sudo dnf install libayatana-appindicator-gtk3
```

Bez tego pakietu apka nadal działa normalnie — po prostu tray się nie pokaże
(w terminalu pojawi się komunikat o brakującej bibliotece).

## Skąd się to wzięło

Rafał miał działającą, ręcznie dopieszczoną konfigurację libreswana do firmowego
FortiGate: IKEv1 + aggressive mode + XAUTH + modecfg + split tunneling na
`10.0.0.0/8`. Do tego skrypt bashowy `connect`/`disconnect`. Poprosił o GUI z
profilami i możliwością zmiany szyfrów. Kolejne doprecyzowania w trakcie pracy:

1. „ma być lekkie, żeby nie zamulało” → GTK4 + libadwaita przez PyGObject
   (na Fedorze już jest, jeden proces, brak demona w tle).
2. „lepiej bez installera, niech to będzie aplikacja przenośna” → jeden plik
   `.py`, brak `install.sh`, brak polityki polkit w `/usr/share`.
3. „wszystkie dane zapisywane w folderze obok pliku, hasła zahaszowane możliwie”
   → katalog `dane/` obok skryptu, hasła szyfrowane (nie hashowane — hash jest
   jednokierunkowy, a libreswan potrzebuje plaintextu; zostało to Rafałowi
   wyjaśnione).
4. „sprzątanie może być — tych których nie ma na liście profili” → automatyczne
   kasowanie osieroconych `bvpn-*.conf/.secrets` po udanym połączeniu + pozycja
   w menu.
5. „ikonka w trayu, żeby było widać czy VPN jest aktywny” → osobny proces
   `--tray` (KDE Plasma, AppIndicator), startowany razem z GUI, zamykany
   niezależnie z menu ikonki (patrz „Ikonka w trayu” niżej i pkt 7 w „Rzeczy,
   które łatwo zepsuć”).

**Nie proponuj instalatora, pakietu RPM ani usługi systemd bez wyraźnej prośby.**
Przenośność jest świadomym wyborem.

## Gdzie lądują dane

Wszystko obok skryptu, w folderze `dane/`:

| Plik | Co w środku |
|---|---|
| `dane/profile.json` | profile — **bez haseł**, chmod 600 |
| `dane/sekrety.enc` | PSK i hasła XAUTH, AES-256-CBC, klucz z PBKDF2 (240 000 iteracji), chmod 600 |
| `dane/stan.json` | stan połączenia (dla wskaźnika w oknie i w trayu) |
| `dane/tray.pid` | PID wskaźnika w trayu — pilnuje jednej instancji naraz |
| `dane/ostatni-log.txt` | log ostatniej akcji |

Jeśli folder ze skryptem jest tylko do odczytu, aplikacja przechodzi na
`~/.config/vpn-connector-ipsec/`. Bieżącą ścieżkę pokazuje menu → „Gdzie są dane?”.

Poza tym folderem powstają tylko pliki, których wymaga sam libreswan —
patrz „Pliki libreswana” niżej.

## Ochrona haseł

Menu w sekcji „Hasła”, trzy tryby (`settings.crypt_mode` w `profile.json`):

- **Klucz powiązany z komputerem** (`machine`, domyślnie) — bez pytania o
  cokolwiek. Klucz wyprowadzany z `/etc/machine-id` + nazwy użytkownika + UID.
  Skopiowanie `dane/` na inny komputer albo na konto kolegi nic nie da; kto ma
  roota na *tej* maszynie, odtworzy klucz. To zabezpieczenie przed przypadkowym
  zerknięciem i przed wyciekiem pendrive'a, **nie przed adminem** — tak jest to
  opisane tutaj i tak trzeba o tym mówić Rafałowi, nie sprzedawać jako pełnego
  bezpieczeństwa.
- **Hasło główne** (`master`) — pytane raz po starcie aplikacji, trzymane tylko
  w pamięci procesu (`self.master`). Realna ochrona, kosztem jednego okienka
  na sesję.
- **Nie zapisuj haseł** (`none`) — plik `sekrety.enc` jest kasowany, aplikacja
  pyta o PSK i hasło XAUTH przy każdym połączeniu.

Hasła nigdy nie trafiają do `profile.json` ani do logów.

## Ikonka w trayu (KDE Plasma)

Przy pierwszym uruchomieniu GUI odpala też wskaźnik w trayu — osobny proces
(`./vpn-connector-ipsec.py --tray`), niezależny od okna: zamknięcie okna aplikacji
(krzyżykiem) **nie** zamyka trayu, bo o to chodzi — ikonka ma pokazywać stan
połączenia, nawet gdy nie masz otwartego okna.

Ikonka: zielone kółko gdy połączony, szary pusty okrąg gdy nie. To **własne
SVG-ki, nie nazwy z motywu ikon systemu** — pierwsza wersja próbowała nazw
z Adwaity (`network-vpn-symbolic` / `network-vpn-disabled-symbolic` /
`network-vpn-disconnected-symbolic`), ale Breeze (KDE) tych „wyłączonych”
wariantów nie ma, więc wyszukiwanie po nazwie nie trafiało i tray zawsze
zostawał przy ostatnio poprawnie znalezionej ikonce — wygląda jak „ikonka się
nie zmienia”, niezależnie od stanu połączenia. Stąd `_ensure_tray_icons()`
zapisuje dwa małe SVG (wbudowane w kod jako `_TRAY_ICON_ON_SVG`/`_TRAY_ICON_OFF_SVG`)
do `dane/icons/` przy starcie trayu, a `indicator.set_icon_theme_path(TRAY_ICON_DIR)`
wskazuje tam AppIndicator — 100% niezależne od tego, jaki motyw ikon ma
użytkownik. Jeśli będziesz zmieniać wygląd ikonek, edytuj te dwie stałe, nie
próbuj wracać do nazw z motywu systemowego. Menu pod prawym klawiszem:

- **Pokaż** — otwiera (albo podnosi, jeśli już działa) okno aplikacji.
- **Zamknij** — otwiera okno, rozłącza aktywny profil (jeśli jest połączony)
  i dopiero po zakończeniu rozłączania zamyka i okno, i tray. To jedyny sposób
  na wyłączenie ikonki — zamykanie samego okna jej nie dotyka.

Tray nigdy nie dotyka `pkexec`/`ipsec` bezpośrednio — do rozłączenia zawsze
prosi działającą (albo dopiero startowaną) instancję GUI. Jedna instancja
trayu naraz jest pilnowana plikiem `dane/tray.pid`. Techniczny opis protokołu
tray ↔ GUI jest w pkt 7 sekcji „Rzeczy, które łatwo zepsuć”.

Tray jest testowany tylko na **KDE Plasma** (natywny StatusNotifierItem/
AppIndicator). Na GNOME Shell wymagałby rozszerzenia „AppIndicator and
KStatusNotifierItem Support” — nie testowane, nie zakładaj, że działa bez niego.

## Uprawnienia

GUI działa jako zwykły użytkownik. Kiedy trzeba roota, uruchamia **ten sam plik**
ponownie: `pkexec python3 vpn-connector-ipsec.py --helper <komenda>`. Konfiguracja
profilu idzie do niego JSON-em przez stdin, helper waliduje każde pole regexem,
zanim dotknie `/etc/ipsec.d`, `ipsec`, `ip` czy `systemctl`. polkit domyślnie
cache'uje autoryzację na kilka minut, więc nie pyta przy każdym kliknięciu.
Szczegóły techniczne (dlaczego `pkexec python3 <plik>`, a nie `pkexec <plik>`)
są w sekcji „Architektura” niżej.

## Pliki libreswana

Każdy profil ma swoją parę, odtwarzaną przy każdym połączeniu:

- `/etc/ipsec.d/bvpn-<profil>.conf` — nadpisywany przy „Połącz” zawartością
  formularza, zostaje na dysku (chmod 644, nic wrażliwego).
- `/etc/ipsec.d/bvpn-<profil>.secrets` — tworzony (chmod 600) tuż przed
  `ipsec up`, zaraz po zestawieniu tunelu zerowany i kasowany.

Prefiks `bvpn-` sprawia, że aplikacja nigdy nie dotknie ręcznego pliku `.conf`
Rafała sprzed tego GUI — zostaje jako droga awaryjna.

Pliki profili, których już nie ma na liście, są kasowane automatycznie po każdym
udanym połączeniu, a na żądanie z menu → „Posprzątaj /etc/ipsec.d”.

## Pierwsze uruchomienie

1. Jeśli w `/etc/ipsec.conf` wisi aktywny
   `include /etc/crypto-policies/back-ends/libreswan.config`, u góry okna pojawi
   się pasek z przyciskiem **Napraw** — kliknięcie komentuje tę linię i zostawia
   kopię `/etc/ipsec.conf.bvpn-backup`. To ten sam krok 1, który Rafał robił
   ręcznie.
2. Wypełnij profil (domyślny nazywa się `profil-1`):
   brama (np. `203.0.113.1`), sieć `10.0.0.0/8`, użytkownik XAUTH,
   `leftid`/`rightid` (np. `@moj-klucz`), PSK i hasło XAUTH.
   Interfejs zostaw na `auto` (bierze z trasy domyślnej, więc działa i po wifi,
   i po kablu), **Adres VPN** też `auto` (czyta to, co przydzieli modecfg;
   gdyby odczyt zawiódł, wpisz adres przydzielony przez bramę na sztywno).
3. **Połącz**.

## Co robi „Połącz”

Sekwencja z oryginalnego skryptu Rafała, tylko doprowadzona do porządku:

1. zapis `bvpn-<profil>.conf` i `.secrets`,
2. skasowanie tras i adresów z poprzedniego połączenia,
3. `systemctl restart ipsec` + czekanie, aż pluto faktycznie wstanie,
4. `ipsec rereadsecrets`, `ipsec add`, `ipsec up`,
5. odczyt adresu przydzielonego przez modecfg,
6. `ip addr add <vpn_ip>/32` + `ip route replace 10.0.0.0/8 dev <iface> src <vpn_ip>`,
7. skasowanie pliku `.secrets` i osieroconych plików po usuniętych profilach.

„Rozłącz” robi to samo w drugą stronę.

## Zmiana szyfrowania

Sekcja „Szyfrowanie tunelu”: lista gotowych zestawów (`aes256-sha512;ecp256`
Rafała jest pierwszy) albo ręczna edycja `ike=` i `phase2alg=`, plus przełączniki
PFS, aggressive mode i NAT-T. Jak brama odrzuci propozycję, aplikacja rozpozna
`no acceptable proposal` i napisze wprost, że chodzi o algorytmy.

## Skrót w menu aplikacji (opcjonalnie)

W paczce jest `vpn-connector-ipsec.desktop`. Popraw w nim ścieżkę `Exec=` na swoją i:

```bash
mkdir -p ~/.local/share/applications
cp vpn-connector-ipsec.desktop ~/.local/share/applications/
```

Nic więcej nie jest instalowane w systemie.

## Diagnostyka

| Objaw | Co sprawdzić |
|---|---|
| `Usługa ipsec nie wstała` | `journalctl -u ipsec -n 50` — najczęściej crypto-policies |
| `no acceptable proposal` | zestaw algorytmów w sekcji Szyfrowanie |
| XAUTH odrzucone | login i hasło; `leftusername` musi pasować do wpisu XAUTH |
| Tunel wstaje, brak ruchu | `ip route get 10.0.0.1` — czy trasa idzie właściwym interfejsem |
| Nie odczytano adresu z modecfg | wpisz **Adres VPN** ręcznie |
| Zapomniane hasło główne | skasuj `dane/sekrety.enc` i wpisz hasła od nowa |
| Okno zawiesza się, CPU się grzeje | zbierz traceback: `PYTHONFAULTHANDLER=1 timeout -s ABRT 25 ./vpn-connector-ipsec.py` — patrz „Testowanie bez VPN-a” |
| Tray się nie pokazuje | sprawdź czy jest `libayatana-appindicator-gtk3`; komunikat w terminalu powie, czego brakuje |

## Odinstalowanie

Skasuj folder. Ewentualnie posprzątaj po libreswanie:

```bash
sudo rm -f /etc/ipsec.d/bvpn-*
sudo mv /etc/ipsec.conf.bvpn-backup /etc/ipsec.conf   # jeśli chcesz cofnąć „Napraw”
```

## Uwaga do oryginalnego skryptu

W `podsumowanievpn.md` skrypt ma połamane escapowanie po heredocu —
`"\(VPN_IP/32"` zamiast `"$VPN_IP/32"` i `dev "INTERFACE" src "VPN_IP"` bez `$`.
Aplikacja odtwarza zamierzoną logikę poprawnie i używa `ip route replace`
zamiast `add`, więc nie wywala się, gdy trasa już istnieje.

Wygenerowany `.conf` jest bajt w bajt zgodny z działającym plikiem Rafała
(zweryfikowane diffem) — zmienia się tylko nazwa `conn` na `bvpn-<profil>`.

## Architektura

Jeden plik `vpn-connector-ipsec.py`, trzy role:

- **GUI** (`gui_main()`) — zwykły użytkownik, GTK4/libadwaita. Nigdy nie ma roota.
- **helper** (`helper_main()`, wywołanie `--helper <cmd>`) — root, uruchamiany
  przez `pkexec python3 <ten plik> --helper <cmd>`.
- **tray** (`tray_main()`, wywołanie `--tray`) — zwykły użytkownik, GTK **3**
  (celowo inny niż GUI — patrz pkt 7 niżej). Ikonka w trayu KDE Plasma.

Dlaczego `pkexec python3 <plik>`, a nie `pkexec <plik>`: pkexec odmawia
uruchomienia programu, który nie jest własnością roota i zapisywalny dla innych.
Skrypt w katalogu domowym takim nie jest, ale `/usr/bin/python3` już tak —
a pkexec sprawdza tylko wykonywalny plik, nie jego argumenty. Dzięki temu nie
trzeba niczego instalować w `/usr`. Brak własnej akcji polkit oznacza użycie
domyślnej `org.freedesktop.policykit.exec` (`auth_admin_keep` dla aktywnej
sesji — hasło raz na kilka minut).

**Konsekwencja bezpieczeństwa, o której trzeba pamiętać:** kto może pisać do
`vpn-connector-ipsec.py`, ten po autoryzacji pkexec wykona swój kod jako root.
To ten sam poziom zaufania co własny skrypt uruchamiany przez sudo. Nie kładź
tego pliku w katalogu zapisywalnym dla innych.

### Protokół GUI ↔ helper

- profil leci JSON-em na **stdin** helpera,
- helper streamuje logi linia po linii na **stdout** (GUI pokazuje je na żywo),
- ostatnia linia to `##RESULT## {json}` — wynik strukturalny,
- kod wyjścia: 0 = OK, 126 = anulowana autoryzacja pkexec, 127 = brak pkexec.

Klasa `Helper` w GUI używa `Gio.SubprocessLauncher` + `read_line_async`, więc
okno się nie blokuje.

### Komendy helpera

`up`, `down`, `status`, `cleanup`, `check-policy`, `fix-policy`.

## Rzeczy, które łatwo zepsuć

### 1. Wygenerowany `.conf` musi zostać zgodny z działającą konfiguracją

`build_conf()` produkuje dokładnie te same linie co ręczny plik Rafała
(zweryfikowane diffem — zero różnic, poza nazwą `conn bvpn-<profil>`).
Jeśli coś tam zmieniasz, przepuść to przez ten test:

```python
gen = [l for l in build_conf(clean(profil)).splitlines()
       if l.strip() and not l.startswith(("#", "conn"))]
# porównaj z blokiem z podsumowanievpn.md
```

Szczególnie: `leftupdown=/usr/bin/true` (bez tego libreswan sam grzebie w
trasach i psuje split tunneling), `modecfgpull=yes`, `encapsulation=yes`.

### 2. Adw.ComboRow: nie wołaj `set_selected()` wewnątrz `notify::selected`

To **zawiesza** aplikację na twardo (nie wyjątek — blokada w GtkSingleSelection;
złapane faulthandlerem podczas testów). Stąd flaga `self._preset_busy` i
wczesne wyjścia w `_sync_preset()` / `_on_preset()`. Jeśli dodajesz kolejne
ComboRow z dwukierunkową synchronizacją, zastosuj ten sam wzorzec.

### 3. Walidacja w helperze to jedyna bariera

Helper działa jako root i dostaje dane z GUI. Każde pole przechodzi przez regex
(`NAME_RE`, `ID_RE`, `USER_RE`, `ALGO_RE`, `IFACE_RE`, `NUM_RE`) albo przez
`ipaddress`. Wszystkie wywołania systemowe idą listą argumentów do
`subprocess.run` — **nigdy `shell=True`**. Dodając nowe pole, dopisz walidację
w `clean()`, nie ufaj GUI.

Przetestowane i odrzucane: `8.8.8.8; rm -rf /`, `` aes256`whoami` ``, `wlo1;ls`,
`../../etc/passwd`, `user$(id)`, `@moj-klucz && reboot`.

### 4. Szyfrowanie haseł

`openssl enc -aes-256-cbc -pbkdf2 -iter 240000`, hasło podawane przez
`-pass fd:N` (`pass_fds` w subprocess) — nie przez argv ani env, żeby nie było
widoczne w `ps`. Świadomie **bez** biblioteki `cryptography`: openssl jest na
każdej Fedorze, a zależność zewnętrzna psułaby przenośność. Tryby opisane
w sekcji „Ochrona haseł” wyżej.

### 5. Adres z modecfg

`detect_vpn_ip()` parsuje `ipsec status` szukając `<ip>/32===` w liniach
zawierających nazwę połączenia, z pollingiem 10 × 0,5 s. To najbardziej kruchy
element całości — format wyjścia zależy od wersji libreswana. Jeśli Rafał zgłosi
„tunel wstaje, ale nie odczytuje adresu”, poproś o `sudo ipsec status | grep
bvpn-` i dopasuj regex. Awaryjnie jest pole „Adres VPN” do wpisania na sztywno
(u Rafała to konkretny adres przydzielony przez jego bramę).

### 6. crypto-policies

Fedora wstrzykuje `chacha20_poly1305` do IKEv1 przez
`include /etc/crypto-policies/back-ends/libreswan.config` w `/etc/ipsec.conf`,
co uniemożliwia start usługi. `policy_status()` to wykrywa (odczyt bez roota),
`fix-policy` komentuje linię i robi backup `.bvpn-backup`. To był krok 1
ręcznej instrukcji Rafała i najczęstsza przyczyna „nie działa”.

### 7. Tray — dlaczego osobny proces, i pułapka z EOF w `Helper._got_line`

Ikonka w trayu (`tray_main()`, `--tray`) używa `AyatanaAppIndicator3`, a ta
biblioteka wystawia menu jako `Gtk.Menu` z **GTK 3** — nie da się jej wołać
z tego samego interpretera co GUI (GTK 4/libadwaita). Dlatego tray to osobny
proces uruchamiany przez `_spawn_tray()` z `start_new_session=True`, żyjący
niezależnie od okna GUI. Jedna instancja pilnowana plikiem `dane/tray.pid`
(`_tray_acquire_lock`/`_tray_release_lock`).

Komunikacja tray → GUI idzie przez **GAction eksportowany po D-Bus**, nie
przez nowy kanał: `App` rejestruje akcję `"rozlacz-i-zamknij"`
(`Gio.SimpleAction`), GApplication automatycznie wystawia ją pod
`/org/example/vpnconnectoripsec` (kropki → slashe z `APP_ID`). Tray sprawdza
`org.freedesktop.DBus.NameHasOwner` dla `APP_ID`: jeśli GUI już działa, woła
`Gio.DBusActionGroup.get(...).activate_action("rozlacz-i-zamknij", None)`;
jeśli nie, startuje `vpn-connector-ipsec.py --auto-shutdown`, co samo wywoła
`Window.shutdown_after_disconnect()` po pokazaniu okna. „Pokaż” z trayu to
zwykłe odpalenie `vpn-connector-ipsec.py` bez argumentów — unikalność `APP_ID`
w `Gio.Application` (domyślne flagi, bez `NON_UNIQUE`) sama aktywuje istniejące
okno zamiast tworzyć drugie.

**Pułapka, na którą już się natknięto i naprawiono** (zob. `Helper._got_line`,
klasa używana przez GUI do czytania logów z helpera): koniec strumienia
(`read_line_finish`) w GLib po C zwraca `NULL`, ale przez wadliwą adnotację
introspekcji PyGObject bywa to puste `b""` zamiast `None`. Warunek
`if data is None: return` tego nie łapie — `self._read()` woła się w kółko
przez `g_idle_dispatch` bez blokowania, co w 100% zajmuje jeden wątek i
zamraża okno (widoczne jako zawieszone GUI + rozgrzany CPU, mimo że sama
operacja VPN fizycznie się kończy, bo helper to osobny proces). Znaleziono to
przez `PYTHONFAULTHANDLER=1 timeout -s ABRT 25` — trafiony traceback pokazywał
główny wątek w pętli `g_main_context_iteration → g_idle_dispatch → ... →
_got_line`. Poprawka: `if not data: return` (łapie oba przypadki). Jeśli
dodajesz kolejny podobny odczyt strumienia asynchronicznego, stosuj ten sam
wzorzec — nigdy `is None` samo w sobie.

**Druga pułapka, też znaleziona i naprawiona: „Zamknij” czasem nie kończył
trayu.** Pierwsza wersja wykrywała koniec sekwencji rozłącz-i-zamknij przez
odpytywanie `NameHasOwner` na D-Busie co 2 sekundy (ten sam timer co odświeżanie
ikonki) z prostym automatem faz 0→1→2. Problem: jeśli GUI kończyło się szybciej
niż te 2 sekundy — a dokładnie tak jest, gdy profil akurat nie był połączony,
bo `shutdown_after_disconnect()` wtedy woła `self.close()` praktycznie od razu
— tray nigdy nie zdążył próbkować w momencie, gdy nazwa była jeszcze na
magistrali. Faza 1 nigdy nie awansowała do fazy 2, więc warunek „zniknęła po
tym jak się pojawiła” nigdy się nie potwierdzał i tray zostawał w trayu na
zawsze (do czasu 120 s „bezpiecznika”, który tylko poddawał próbę, nie zamykał
ikonki). Poprawka: zamiast odpytywania — zdarzeniowe `Gio.bus_watch_name()` na
`APP_ID`, z licznikiem `seen_appeared` (bo `g_bus_watch_name` woła
`vanished`-handler też jako stan startowy, gdy nazwa jeszcze nie ma właściciela
— to trzeba zignorować, liczy się tylko zniknięcie *po* co najmniej jednym
`appeared`). To eliminuje dziurę czasową całkowicie, niezależnie od tego, jak
szybko GUI się zamyka. Jeśli dodajesz kolejną logikę „czekaj aż coś na D-Busie
się skończy”, użyj tego wzorca, nie odpytywania na timerze.

## Testowanie bez VPN-a

W kodzie jest headless self-test — przeklikuje okno i sprawdza asercje:

```bash
rm -rf dane && BVPN_SELFTEST=1 xvfb-run -a timeout 40 python3 -u vpn-connector-ipsec.py
# oczekiwane: "SELFTEST OK — profile: [...], sekrety: [...]"
```

Sprawdza: dodawanie/duplikowanie/przełączanie profili, powrót sekretów po
zmianie profilu, synchronizację presetów w obie strony, brak jawnego hasła
w `sekrety.enc`, poprawność odszyfrowania. Tray jest w tym trybie wyłączony
(`BVPN_SELFTEST` pomija `_spawn_tray()`), żeby test nie zostawiał osieroconego
procesu.

Przy zawieszeniu GUI: `PYTHONFAULTHANDLER=1` + `timeout -s ABRT 25` daje
traceback z miejsca blokady. Tak znalazła się pułapka z ComboRow i pułapka
z EOF w `Helper._got_line` (pkt 7 wyżej).

Helper da się testować bez libreswana — degraduje się z sensownymi komunikatami:

```bash
echo '{"name":"t","right":"1.2.3.4","rightsubnet":"10.0.0.0/8","username":"u"}' \
  | sudo python3 vpn-connector-ipsec.py --helper up
```

Uwaga: `pyflakes` przechodzi na czysto — utrzymaj ten stan.

## Czego jeszcze nie ma (kandydaci na następne kroki)

- Ikona w trayu jest tylko na KDE Plasma (patrz wyżej) — na GNOME Shell nie
  testowane.
- Autoreconnect po zerwaniu (DPD już jest skonfigurowane po stronie tunelu).
- Import istniejącego `/etc/ipsec.d/*.conf` do profilu.
- IKEv2 — `clean()` przyjmuje już `keyexchange`, ale GUI tego nie wystawia
  i nie było testowane.
- Podgląd `ipsec trafficstatus` w oknie (komenda `status` w helperze zwraca
  już te dane, GUI ich nie używa).
- Stan połączenia w `dane/stan.json` jest pisany przez roota, więc plik ma
  właściciela root. Usunąć go może użytkownik (katalog jest jego), ale gdyby
  przenosić dane na FAT/pendrive, `chmod` cicho zawiedzie — jest to obsłużone
  `try/except`.

## Styl pracy z tym użytkownikiem

Rafał dorzuca wymagania w trakcie — czyta odpowiedzi na bieżąco i dopytuje
o szczegóły techniczne („gdzie to zapisujesz?”, „nowy profil to nowe pliki?”).
Odpowiadaj konkretnie i krótko, bez marketingu. Docenia, gdy wskażesz błąd
w jego materiale — np. połamane escapowanie `"\(VPN_IP/32"` i `dev "INTERFACE"
src "VPN_IP"` (brak `$`) w `podsumowanievpn.md`, wynikające z heredoca.
