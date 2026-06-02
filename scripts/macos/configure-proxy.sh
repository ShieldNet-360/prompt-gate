#!/usr/bin/env bash
# scripts/macos/configure-proxy.sh
#
# Point macOS network services at the local Prompt Gate MITM proxy
# (127.0.0.1:8443) or restore the default direct-connect.
#
# Usage:
#   sudo ./configure-proxy.sh apply
#   sudo ./configure-proxy.sh restore
#
# Requires sudo because `networksetup -setsecurewebproxy` modifies
# system network configuration.

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8443}"

list_services() {
  networksetup -listallnetworkservices \
    | tail -n +2 \
    | sed '/^\*/d'
}

apply_proxy() {
  list_services | while IFS= read -r svc; do
    [ -n "$svc" ] || continue
    echo "prompt-gate: setting HTTPS proxy on \"$svc\" -> $PROXY_HOST:$PROXY_PORT"
    networksetup -setsecurewebproxy "$svc" "$PROXY_HOST" "$PROXY_PORT" || true
    # Also set HTTP proxy so plaintext API calls (rare on Tier-2 AI
    # endpoints, but possible) flow through the same listener.
    networksetup -setwebproxy "$svc" "$PROXY_HOST" "$PROXY_PORT" || true
  done
}

restore_proxy() {
  list_services | while IFS= read -r svc; do
    [ -n "$svc" ] || continue
    echo "prompt-gate: disabling proxy on \"$svc\""
    networksetup -setsecurewebproxystate "$svc" off || true
    networksetup -setwebproxystate "$svc" off || true
  done
}

main() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "configure-proxy.sh: this script targets macOS (Darwin)." >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "configure-proxy.sh: re-run with sudo." >&2
    exit 1
  fi

  case "${1:-apply}" in
    apply)   apply_proxy ;;
    restore) restore_proxy ;;
    *)
      echo "Usage: $0 [apply|restore]" >&2
      exit 2
      ;;
  esac
}

main "$@"
