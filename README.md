# VPN Connector IPsec

Przenośne GUI (GTK4 + libadwaita) do libreswana — IKEv1 aggressive mode + XAUTH,
z profilami, wyborem szyfrów i podglądem logów.

## Wymagania

```bash
sudo dnf install libreswan polkit openssl python3-gobject gtk4 libadwaita
```

Opcjonalnie, dla ikonki w trayu (KDE Plasma):

```bash
sudo dnf install libayatana-appindicator-gtk3
```

## Uruchomienie

Bez instalatora — rozpakuj gdzie chcesz i odpal:

```bash
chmod +x vpn-connector-ipsec.py
./vpn-connector-ipsec.py
```

## Co to robi

Dodaj profil (brama, sieć, `leftid`/`rightid`, login i hasło XAUTH, PSK) i kliknij
**Połącz**. Aplikacja generuje konfigurację libreswana, podnosi tunel przez
`ipsec`, ustawia trasy i pokazuje stan w oknie oraz w trayu. **Rozłącz** robi to
samo w drugą stronę.

Dane (profile, zaszyfrowane hasła, logi) trzymane są lokalnie w folderze
`dane/` obok skryptu — nic nie wychodzi poza tę maszynę.
