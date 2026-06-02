#!/usr/bin/env bash
# scripts/macos/configure-dns.sh
#
# Point macOS network services at the local Prompt Gate resolver
# (127.0.0.1) or restore the system defaults.
#
# Usage:
#   sudo ./configure-dns.sh apply      # set DNS to 127.0.0.1 for all active services
#   sudo ./configure-dns.sh restore    # restore "Empty" (DHCP-provided) DNS
#
# Requires sudo because `networksetup -setdnsservers` modifies system network
# configuration.

set -euo pipefail

DNS_IP="${DNS_IP:-127.0.0.1}"

list_services() {
  # Skip the header line and any disabled services (prefixed with "*").
  networksetup -listallnetworkservices \
    | tail -n +2 \
    | sed '/^\*/d'
}

apply_dns() {
  list_services | while IFS= read -r svc; do
    [ -n "$svc" ] || continue
    echo "prompt-gate: setting DNS for \"$svc\" -> $DNS_IP"
    networksetup -setdnsservers "$svc" "$DNS_IP" || true
  done
}

restore_dns() {
  list_services | while IFS= read -r svc; do
    [ -n "$svc" ] || continue
    echo "prompt-gate: restoring default DNS for \"$svc\""
    networksetup -setdnsservers "$svc" "Empty" || true
  done
}

main() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "configure-dns.sh: this script targets macOS (Darwin)." >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "configure-dns.sh: re-run with sudo." >&2
    exit 1
  fi

  case "${1:-apply}" in
    apply)   apply_dns ;;
    restore) restore_dns ;;
    *)
      echo "Usage: $0 [apply|restore]" >&2
      exit 2
      ;;
  esac
}

main "$@"
