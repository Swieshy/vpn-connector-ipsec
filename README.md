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
chmod +x vpn-connector-ipsec
./vpn-connector-ipsec
```

To get an entry in your application launcher, pick **"Add to application menu"**
from the app's menu — it writes the `.desktop` file with the correct path itself.

Or run `./install.sh`, which does that *and* symlinks the app into
`~/.local/bin`, so you can start it by typing `vpn-connector-ipsec` anywhere.
Nothing is copied into the system and no root is needed; `./install.sh
--uninstall` removes both again and leaves your `dane/` folder alone.

## What it does

Add a profile (gateway, network, `leftid`/`rightid`, XAUTH login/password, PSK)
and click **Connect**. The app generates a libreswan config, brings up the
tunnel via `ipsec`, sets up routes, and shows connection status in the window
and the tray. **Disconnect** reverses all of it.

Several profiles can be connected at the same time, as long as their remote
networks don't overlap — the app refuses the second one if they do. Connected
profiles are marked with a green dot in the list, the tray icon shows two circles
when more than one tunnel is up, and the menu's **"Disconnect everything"** hangs
them all up at once.

Data (profiles, encrypted passwords, logs) is kept locally in the `dane/`
folder next to the script — nothing leaves this machine.
