#!/usr/bin/env bash
# Prompt Gate macOS postinstall script.
#
# Runs as root after pkgbuild lays the payload onto the target. Tasks:
#   1. Reload the LaunchDaemon so launchd discovers the new plist.
#   2. Hand DNS over to the agent (127.0.0.1).
#   3. Stamp /var/lib/prompt-gate so the agent can persist its SQLite
#      database after first boot.
#
# A failure in this script will cause Installer.app to surface an error
# to the user — so any operation that can fail is tolerated only when
# rolling it back makes sense (e.g. DNS).

set -euo pipefail

PLIST="/Library/LaunchDaemons/com.shieldnet360.promptgate.plist"
LIB_DIR="/var/lib/prompt-gate"

mkdir -p "${LIB_DIR}"
chmod 0750 "${LIB_DIR}"
chown root:wheel "${LIB_DIR}"

# Make sure no stale daemon is left from a previous version.
launchctl bootout system "${PLIST}" 2>/dev/null || true
launchctl bootstrap system "${PLIST}"

# Apply DNS handoff. Failure is non-fatal — a manual `configure-dns.sh
# apply` recovers the user.
if [ -x "/usr/local/share/prompt-gate/configure-dns.sh" ]; then
  /usr/local/share/prompt-gate/configure-dns.sh apply || true
elif [ -x "$(dirname "$0")/configure-dns.sh" ]; then
  "$(dirname "$0")/configure-dns.sh" apply || true
fi

exit 0
