#!/usr/bin/env bash
# scripts/macos/install-ca.sh
#
# Trust (or untrust) the Prompt Gate per-device Root CA in the system
# keychain. Browsers and other TLS clients on macOS follow the system
# keychain by default, so a single install-ca run is enough to make
# Tier-2 MITM transparent to Safari, Chrome, and curl.
#
# Usage:
#   sudo ./install-ca.sh install <path-to-ca.crt>
#   sudo ./install-ca.sh remove  <path-to-ca.crt>

set -euo pipefail

KEYCHAIN="/Library/Keychains/System.keychain"
COMMON_NAME="Prompt Gate Local CA"

usage() {
  echo "Usage: $0 install <ca.crt> | remove <ca.crt>" >&2
  exit 2
}

install_ca() {
  local ca_path="$1"
  if [ ! -f "$ca_path" ]; then
    echo "install-ca.sh: cert not found at $ca_path" >&2
    exit 1
  fi
  echo "prompt-gate: trusting $ca_path in $KEYCHAIN"
  security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$ca_path"
  # Confirm the cert is reachable from the system keychain. -c picks
  # the right entry by Common Name without leaking it to stdout.
  if ! security find-certificate -c "$COMMON_NAME" "$KEYCHAIN" >/dev/null 2>&1; then
    echo "install-ca.sh: cert installed but not found by name; check $KEYCHAIN" >&2
    exit 1
  fi
  echo "prompt-gate: CA installed."
}

remove_ca() {
  local ca_path="$1"
  if [ -f "$ca_path" ]; then
    echo "prompt-gate: removing trust for $ca_path"
    security remove-trusted-cert -d "$ca_path" || true
  fi
  # Best-effort: delete by Common Name in case the file path has
  # since changed but the keychain entry is still there.
  if security find-certificate -c "$COMMON_NAME" "$KEYCHAIN" >/dev/null 2>&1; then
    security delete-certificate -c "$COMMON_NAME" "$KEYCHAIN" || true
  fi
  echo "prompt-gate: CA removed."
}

main() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "install-ca.sh: this script targets macOS (Darwin)." >&2
    exit 1
  fi
  if [ "$(id -u)" -ne 0 ]; then
    echo "install-ca.sh: re-run with sudo." >&2
    exit 1
  fi

  local cmd="${1:-}"
  local ca_path="${2:-}"
  if [ -z "$cmd" ] || [ -z "$ca_path" ]; then
    usage
  fi

  case "$cmd" in
    install) install_ca "$ca_path" ;;
    remove)  remove_ca  "$ca_path" ;;
    *)       usage ;;
  esac
}

main "$@"
