#!/bin/sh
# Electron deb/rpm preremove.
# Cleans up PolicyKit policy, desktop cache, and running processes.

set -e

# Kill any running Prompt Gate Electron process so the uninstall
# doesn't leave orphaned agent child processes.
pkill -f "prompt-gate" 2>/dev/null || true

# Remove the PolicyKit policy.
rm -f /usr/share/polkit-1/actions/com.shieldnet360.promptgate.policy 2>/dev/null || true

# Remove the CA from the system trust store (if installed).
if [ -f /usr/local/share/ca-certificates/prompt-gate-ca.crt ]; then
    rm -f /usr/local/share/ca-certificates/prompt-gate-ca.crt
    update-ca-certificates --fresh 2>/dev/null || true
elif [ -f /etc/pki/ca-trust/source/anchors/prompt-gate-ca.crt ]; then
    rm -f /etc/pki/ca-trust/source/anchors/prompt-gate-ca.crt
    update-ca-trust extract 2>/dev/null || true
fi

# Refresh desktop database.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi

exit 0
