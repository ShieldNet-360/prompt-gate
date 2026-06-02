#!/usr/bin/env bash
# Install the Prompt Gate Native Messaging host manifest into Chrome's
# (or Chromium's) per-user NativeMessagingHosts directory.
#
# Usage:
#   ./install.sh chrome-extension://<EXTENSION_ID>/
#
# The argument is the chrome-extension:// origin for the installed
# companion extension. Run after the extension is loaded so you can
# copy the ID out of chrome://extensions.

set -euo pipefail

ORIGIN="${1:-}"
if [ -z "$ORIGIN" ]; then
  echo "usage: $0 chrome-extension://<EXTENSION_ID>/" >&2
  exit 2
fi

AGENT_BIN="${SECURE_EDGE_AGENT_BIN:-/usr/local/bin/prompt-gate-agent}"
HOST_NAME="com.shieldnet360.promptgate"

# Chrome's Native Messaging protocol invokes the host binary with the
# caller's chrome-extension://<id>/ origin as the only positional
# argument and offers no way to inject custom flags through the host
# manifest. The agent binary detects that calling convention in main()
# and routes to Native Messaging mode automatically, so the manifest
# "path" can point directly at the production daemon binary without
# a wrapper script.

# Resolve the platform-specific install directory for Chrome stable.
# Other Chromium variants (Edge, Brave, Chromium, Opera) live in
# different per-vendor paths; users with those browsers should set
# DESTINATION manually.
case "$(uname -s)" in
  Darwin)
    DEFAULT_DEST="${HOME}/Library/Application Support/Google/Chrome/NativeMessagingHosts"
    ;;
  Linux)
    DEFAULT_DEST="${HOME}/.config/google-chrome/NativeMessagingHosts"
    ;;
  *)
    echo "Unsupported platform: $(uname -s)" >&2
    exit 1
    ;;
esac

DEST="${DESTINATION:-$DEFAULT_DEST}"
mkdir -p "$DEST"
TARGET="${DEST}/${HOST_NAME}.json"

cat > "$TARGET" <<EOF
{
  "name": "${HOST_NAME}",
  "description": "Prompt Gate DLP companion native messaging host",
  "path": "${AGENT_BIN}",
  "type": "stdio",
  "allowed_origins": ["${ORIGIN}"]
}
EOF

chmod 0644 "$TARGET"
echo "Installed ${HOST_NAME} manifest to ${TARGET}"
echo "  agent binary: ${AGENT_BIN}"
echo "  origin:       ${ORIGIN}"
