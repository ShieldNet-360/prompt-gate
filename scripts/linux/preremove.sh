#!/bin/sh
# Linux preremove (.deb / .rpm).
# Stops and disables the systemd unit, restores DNS.

set -e

if [ -x /usr/share/prompt-gate/configure-dns.sh ]; then
    /usr/share/prompt-gate/configure-dns.sh restore || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop prompt-gate.service || true
    systemctl disable prompt-gate.service || true
fi

exit 0
