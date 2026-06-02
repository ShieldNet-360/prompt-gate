#!/bin/sh
# Linux postinstall (.deb / .rpm).
# Enables and starts the systemd unit and applies DNS handoff.
# Idempotent: re-running on an already-installed box is harmless.

set -e

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
    systemctl enable prompt-gate.service || true
    systemctl restart prompt-gate.service || true
fi

mkdir -p /var/lib/prompt-gate
chmod 0750 /var/lib/prompt-gate

if [ -x /usr/share/prompt-gate/configure-dns.sh ]; then
    /usr/share/prompt-gate/configure-dns.sh apply || true
fi

exit 0
