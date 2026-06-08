#!/bin/sh
# Electron deb/rpm postinstall.
# The Electron app manages the Go agent as a child process — no systemd
# service is needed. This script:
#   1. Creates a data directory for the managed agent.
#   2. Installs the PolicyKit policy so pkexec shows a branded dialog
#      when the app needs to install the CA cert or configure DNS/proxy.
#   3. Updates the desktop database so the app appears in launchers.

set -e

# Data directory for the managed agent's config + database.
mkdir -p /var/lib/prompt-gate
chmod 0750 /var/lib/prompt-gate

# Install the PolicyKit policy (allows pkexec to show a proper dialog
# instead of a generic "an application wants to run as root").
POLICY_SRC="/opt/prompt-gate/resources/resources/linux/com.shieldnet360.promptgate.policy"
POLICY_DST="/usr/share/polkit-1/actions/com.shieldnet360.promptgate.policy"
if [ -f "$POLICY_SRC" ]; then
    cp "$POLICY_SRC" "$POLICY_DST" 2>/dev/null || true
fi

# Refresh desktop database so GNOME/KDE pick up the .desktop file.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi

# Refresh icon cache.
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor || true
fi

exit 0
