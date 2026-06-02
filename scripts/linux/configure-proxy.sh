#!/usr/bin/env bash
# scripts/linux/configure-proxy.sh
#
# Point Linux system + GUI proxy settings at the local Prompt Gate
# MITM listener on 127.0.0.1:8443. Three configurations are touched
# best-effort:
#
#   * GNOME / GTK apps via `gsettings`           (if user session)
#   * KDE / Plasma apps via `kwriteconfig5/6`    (if installed)
#   * CLI / systemd via /etc/profile.d/prompt-gate-proxy.sh
#
# Browsers that read their own config (Firefox by default; Chromium
# with --proxy-server) are not touched here.
#
# Usage:
#   sudo ./configure-proxy.sh apply
#   sudo ./configure-proxy.sh restore

set -euo pipefail

PROXY_HOST="${PROXY_HOST:-127.0.0.1}"
PROXY_PORT="${PROXY_PORT:-8443}"
PROFILE_FILE="/etc/profile.d/prompt-gate-proxy.sh"

apply_gnome() {
  command -v gsettings >/dev/null 2>&1 || return 0
  [ -n "${DBUS_SESSION_BUS_ADDRESS:-}${XDG_RUNTIME_DIR:-}" ] || return 0
  echo "prompt-gate: setting GNOME HTTPS proxy -> $PROXY_HOST:$PROXY_PORT"
  gsettings set org.gnome.system.proxy mode 'manual' || true
  gsettings set org.gnome.system.proxy.https host "$PROXY_HOST" || true
  gsettings set org.gnome.system.proxy.https port "$PROXY_PORT" || true
  gsettings set org.gnome.system.proxy.http host "$PROXY_HOST" || true
  gsettings set org.gnome.system.proxy.http port "$PROXY_PORT" || true
}

restore_gnome() {
  command -v gsettings >/dev/null 2>&1 || return 0
  [ -n "${DBUS_SESSION_BUS_ADDRESS:-}${XDG_RUNTIME_DIR:-}" ] || return 0
  echo "prompt-gate: restoring GNOME proxy mode -> none"
  gsettings set org.gnome.system.proxy mode 'none' || true
}

# Prefer kwriteconfig6 on Plasma 6; fall back to kwriteconfig5.
kde_writer() {
  if command -v kwriteconfig6 >/dev/null 2>&1; then echo "kwriteconfig6"; return; fi
  if command -v kwriteconfig5 >/dev/null 2>&1; then echo "kwriteconfig5"; return; fi
  echo ""
}

apply_kde() {
  local bin
  bin="$(kde_writer)"
  [ -n "$bin" ] || return 0
  echo "prompt-gate: setting KDE HTTPS proxy via $bin"
  $bin --file kioslaverc --group 'Proxy Settings' --key 'httpsProxy' "http://$PROXY_HOST:$PROXY_PORT" || true
  $bin --file kioslaverc --group 'Proxy Settings' --key 'httpProxy'  "http://$PROXY_HOST:$PROXY_PORT" || true
  $bin --file kioslaverc --group 'Proxy Settings' --key 'ProxyType' '1' || true
}

restore_kde() {
  local bin
  bin="$(kde_writer)"
  [ -n "$bin" ] || return 0
  echo "prompt-gate: restoring KDE proxy type -> 0 (no proxy)"
  $bin --file kioslaverc --group 'Proxy Settings' --key 'ProxyType' '0' || true
}

apply_profile() {
  echo "prompt-gate: writing $PROFILE_FILE"
  cat >"$PROFILE_FILE" <<EOF
# Managed by Prompt Gate. Removed by configure-proxy.sh restore.
export HTTP_PROXY=http://$PROXY_HOST:$PROXY_PORT
export HTTPS_PROXY=http://$PROXY_HOST:$PROXY_PORT
export http_proxy=http://$PROXY_HOST:$PROXY_PORT
export https_proxy=http://$PROXY_HOST:$PROXY_PORT
export NO_PROXY=localhost,127.0.0.1,::1
export no_proxy=localhost,127.0.0.1,::1
EOF
  chmod 0644 "$PROFILE_FILE"
}

restore_profile() {
  if [ -f "$PROFILE_FILE" ]; then
    echo "prompt-gate: removing $PROFILE_FILE"
    rm -f "$PROFILE_FILE"
  fi
}

main() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "configure-proxy.sh: re-run with sudo." >&2
    exit 1
  fi

  case "${1:-apply}" in
    apply)
      apply_gnome
      apply_kde
      apply_profile
      ;;
    restore)
      restore_gnome
      restore_kde
      restore_profile
      ;;
    *)
      echo "Usage: $0 [apply|restore]" >&2
      exit 2
      ;;
  esac
}

main "$@"
