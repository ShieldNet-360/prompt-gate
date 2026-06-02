#!/bin/sh
# Pre-remove script for the prompt-gate-agent .deb package.
# Stops and disables the systemd unit before files are removed.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop prompt-gate.service || true
    systemctl disable prompt-gate.service || true
fi

exit 0
