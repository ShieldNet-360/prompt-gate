#!/bin/sh
# Electron deb/rpm preremove.
# Cleans up data directory and desktop cache entries.

set -e

# Kill any running Prompt Gate Electron process so the uninstall
# doesn't leave orphaned agent child processes.
pkill -f "prompt-gate" 2>/dev/null || true

# Refresh desktop database.
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database /usr/share/applications || true
fi

exit 0
