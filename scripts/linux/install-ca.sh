#!/usr/bin/env bash
# scripts/linux/install-ca.sh
#
# Trust (or untrust) the Prompt Gate per-device Root CA in the
# system trust pool. Targets Debian / Ubuntu (update-ca-certificates)
# and Fedora / RHEL (update-ca-trust). The script auto-detects which
# is available.
#
# Usage:
#   sudo ./install-ca.sh install <path-to-ca.crt>
#   sudo ./install-ca.sh remove  <path-to-ca.crt>

set -euo pipefail

# Filename is intentionally fixed so `remove` knows where to look
# regardless of where the source cert lived on disk.
DEB_DEST="/usr/local/share/ca-certificates/prompt-gate-ca.crt"
RHEL_DEST="/etc/pki/ca-trust/source/anchors/prompt-gate-ca.crt"

usage() {
  echo "Usage: $0 install <ca.crt> | remove <ca.crt>" >&2
  exit 2
}

# Returns "deb", "rhel", or empty.
detect_distro() {
  if command -v update-ca-certificates >/dev/null 2>&1; then
    echo "deb"
  elif command -v update-ca-trust >/dev/null 2>&1; then
    echo "rhel"
  else
    echo ""
  fi
}

install_ca() {
  local ca_path="$1"
  if [ ! -f "$ca_path" ]; then
    echo "install-ca.sh: cert not found at $ca_path" >&2
    exit 1
  fi

  local distro
  distro="$(detect_distro)"
  case "$distro" in
    deb)
      echo "prompt-gate: installing $ca_path to $DEB_DEST"
      install -m 0644 "$ca_path" "$DEB_DEST"
      update-ca-certificates
      ;;
    rhel)
      echo "prompt-gate: installing $ca_path to $RHEL_DEST"
      install -m 0644 "$ca_path" "$RHEL_DEST"
      update-ca-trust extract
      ;;
    *)
      echo "install-ca.sh: no recognised ca-cert manager (need update-ca-certificates or update-ca-trust)." >&2
      exit 1
      ;;
  esac
  echo "prompt-gate: CA installed."
  echo "(Reminder: Firefox / Chromium snaps may keep their own trust store. Re-import in the browser if needed.)"
}

remove_ca() {
  local distro
  distro="$(detect_distro)"
  case "$distro" in
    deb)
      if [ -f "$DEB_DEST" ]; then
        echo "prompt-gate: removing $DEB_DEST"
        rm -f "$DEB_DEST"
        update-ca-certificates --fresh
      else
        echo "prompt-gate: no installed CA at $DEB_DEST"
      fi
      ;;
    rhel)
      if [ -f "$RHEL_DEST" ]; then
        echo "prompt-gate: removing $RHEL_DEST"
        rm -f "$RHEL_DEST"
        update-ca-trust extract
      else
        echo "prompt-gate: no installed CA at $RHEL_DEST"
      fi
      ;;
    *)
      echo "install-ca.sh: no recognised ca-cert manager." >&2
      exit 1
      ;;
  esac
  echo "prompt-gate: CA removed."
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "install-ca.sh: re-run with sudo." >&2
    exit 1
  fi

  local cmd="${1:-}"
  local ca_path="${2:-}"
  case "$cmd" in
    install)
      [ -n "$ca_path" ] || usage
      install_ca "$ca_path"
      ;;
    remove)
      remove_ca
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
