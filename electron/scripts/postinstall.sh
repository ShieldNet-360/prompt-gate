#!/bin/sh
# Electron deb/rpm postinstall.
# The Electron app manages the Go agent as a child process — no systemd
# service is needed. This script only:
#   1. Creates a data directory for the managed agent.
#   2. Updates the desktop database so the app appears in launchers.
#   3. Symlinks the binary to /usr/local/bin for CLI convenience.

set -e

# Data directory for the managed agent's config + database.
mkdir -p /var/lib/prompt-gate
chmod 0750 /var/lib/prompt-gate

# Refresh desktop database so GNOME/KDE pick up the .desktop file.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi

# Refresh icon cache.
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
fi

exit 0
