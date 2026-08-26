#!/bin/sh
#
# Makes VPN Connector IPsec look and behave like an installed program, without
# actually installing anything into the system:
#
#   * a symlink in ~/.local/bin, so `vpn-connector-ipsec` works from any shell
#   * a .desktop entry, so it shows up in the application launcher
#
# Nothing is copied, nothing lands under /usr, and no root is involved. The app
# still runs from wherever you unpacked it, and its data still lives in dane/
# next to the real file. Undo everything with:  ./install.sh --uninstall
#
# Why not a real binary or an RPM: the app gets root through
# `pkexec python3 <this file>`, which works precisely because the *interpreter*
# is root-owned. pkexec would refuse a user-owned binary, so a self-contained
# executable would have to live in /usr/bin — i.e. a real installation, which
# this project deliberately avoids.

set -eu

APP_NAME="vpn-connector-ipsec"
SRC_DIR=$(cd "$(dirname "$0")" && pwd)
APP="$SRC_DIR/$APP_NAME"

BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
LINK="$BIN_DIR/$APP_NAME"
DESKTOP_FILE="${XDG_DATA_HOME:-$HOME/.local/share}/applications/$APP_NAME.desktop"

if [ "$(id -u)" = "0" ]; then
    echo "Run this as your normal user, not as root — it only touches \$HOME." >&2
    exit 1
fi

uninstall() {
    removed=0
    if [ -L "$LINK" ] || [ -e "$LINK" ]; then
        rm -f "$LINK"
        echo "removed  $LINK"
        removed=1
    fi
    if [ -e "$DESKTOP_FILE" ]; then
        rm -f "$DESKTOP_FILE"
        echo "removed  $DESKTOP_FILE"
        removed=1
    fi
    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "$(dirname "$DESKTOP_FILE")" 2>/dev/null || true
    fi
    [ "$removed" = "1" ] || echo "Nothing to remove."
    echo
    echo "Your profiles and passwords in $SRC_DIR/dane are untouched."
    echo "To get rid of those too, delete the whole folder."
}

case "${1:-}" in
    --uninstall|-u) uninstall; exit 0 ;;
    --help|-h)
        echo "Usage: $0 [--uninstall]"
        exit 0 ;;
    "") ;;
    *)
        echo "Unknown option: $1  (try --help)" >&2
        exit 1 ;;
esac

[ -f "$APP" ] || { echo "Cannot find $APP — run this script from the project folder." >&2; exit 1; }

chmod +x "$APP"

mkdir -p "$BIN_DIR"
ln -sfn "$APP" "$LINK"
echo "linked   $LINK -> $APP"

# The app writes the entry itself: Exec= is not shell-expanded and needs the spec's
# own quoting rules (a '%' has to be doubled, paths with spaces need quotes), and
# that logic already exists in install_desktop_entry().
if entry=$("$APP" --install-desktop 2>/dev/null); then
    echo "created  $entry"
else
    echo "warning: could not create the launcher entry (is python3-gobject installed?)" >&2
fi

echo
case ":$PATH:" in
    *":$BIN_DIR:"*)
        echo "Done. Run it with:  $APP_NAME" ;;
    *)
        echo "Done, but $BIN_DIR is not in your PATH, so the command will not be found."
        echo "Add it with:"
        echo "    echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc"
        echo "and open a new shell. The launcher entry works either way." ;;
esac
echo
echo "To undo all of this:  $0 --uninstall"
