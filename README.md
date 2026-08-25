# VPN Connector IPsec

Portable GTK4 + libadwaita GUI for libreswan — IKEv1 aggressive mode + XAUTH,
with profiles, cipher selection, and live log view.

## Requirements

```bash
sudo dnf install libreswan polkit openssl python3-gobject gtk4 libadwaita
```

Optional, for the tray icon (KDE Plasma):

```bash
sudo dnf install libayatana-appindicator-gtk3
```

## Running

No installer — unpack anywhere and run:

```bash
chmod +x vpn-connector-ipsec.py
./vpn-connector-ipsec.py
```

## What it does

Add a profile (gateway, network, `leftid`/`rightid`, XAUTH login/password, PSK)
and click **Connect**. The app generates a libreswan config, brings up the
tunnel via `ipsec`, sets up routes, and shows connection status in the window
and the tray. **Disconnect** reverses all of it.

Data (profiles, encrypted passwords, logs) is kept locally in the `dane/`
folder next to the script — nothing leaves this machine.
