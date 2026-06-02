#!/bin/sh
# Post-install script for the prompt-gate-agent .deb package.
# Reloads systemd, enables the unit, and starts the service.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable prompt-gate.service || true
    systemctl restart prompt-gate.service || true
fi

# Ensure the state directory exists for the singleton SQLite DB.
mkdir -p /var/lib/prompt-gate
chmod 0750 /var/lib/prompt-gate

exit 0
