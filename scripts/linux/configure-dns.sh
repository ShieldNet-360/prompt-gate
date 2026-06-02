#!/usr/bin/env bash
# scripts/linux/configure-dns.sh
#
# Point Linux DNS at the local Prompt Gate resolver (127.0.0.1) or restore
# the original /etc/resolv.conf. Detects systemd-resolved at runtime and
# uses `resolvectl` when present; otherwise rewrites /etc/resolv.conf
# (after taking a one-time backup).
#
# Usage:
#   sudo ./configure-dns.sh apply
#   sudo ./configure-dns.sh restore

set -euo pipefail

DNS_IP="${DNS_IP:-127.0.0.1}"
RESOLV_CONF="/etc/resolv.conf"
BACKUP="/etc/resolv.conf.prompt-gate.bak"

has_resolved() {
  command -v resolvectl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved
}

default_link() {
  # Pick the link associated with the default IPv4 route.
  ip -4 route show default 2>/dev/null | awk '{print $5; exit}'
}

apply_resolved() {
  local link
  link="$(default_link)"
  if [ -z "$link" ]; then
    echo "configure-dns.sh: no default route; cannot infer interface." >&2
    exit 1
  fi
  echo "prompt-gate: setting DNS for link '$link' -> $DNS_IP via systemd-resolved"
  resolvectl dns "$link" "$DNS_IP"
  resolvectl domain "$link" '~.'
}

restore_resolved() {
  local link
  link="$(default_link)"
  [ -n "$link" ] || return 0
  echo "prompt-gate: reverting systemd-resolved DNS on link '$link'"
  resolvectl revert "$link" || true
}

apply_resolv_conf() {
  if [ -f "$RESOLV_CONF" ] && [ ! -f "$BACKUP" ]; then
    cp -p "$RESOLV_CONF" "$BACKUP"
  fi
  cat >"$RESOLV_CONF" <<EOF
# Managed by Prompt Gate. Original backed up at $BACKUP.
nameserver $DNS_IP
options edns0
EOF
}

restore_resolv_conf() {
  if [ -f "$BACKUP" ]; then
    mv "$BACKUP" "$RESOLV_CONF"
  else
    echo "prompt-gate: no backup at $BACKUP; leaving $RESOLV_CONF alone." >&2
  fi
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "configure-dns.sh: re-run with sudo." >&2
    exit 1
  fi

  case "${1:-apply}" in
    apply)
      if has_resolved; then apply_resolved; else apply_resolv_conf; fi
      ;;
    restore)
      if has_resolved; then restore_resolved; else restore_resolv_conf; fi
      ;;
    *)
      echo "Usage: $0 [apply|restore]" >&2
      exit 2
      ;;
  esac
}

main "$@"
