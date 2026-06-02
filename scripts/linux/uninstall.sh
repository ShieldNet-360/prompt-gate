#!/usr/bin/env bash
# Completely remove Prompt Gate from a Linux machine.
#
# Covers BOTH install shapes:
#   - Electron app (AppImage / .deb) + auto-spawned agent + per-user
#     "~/.prompt-gate" state.
#   - systemd service variant (/usr/bin + /etc/prompt-gate).
#
# And every system side effect either shape can leave behind — the same
# teardown surface as scripts/macos/uninstall.sh:
#   - stale prompt-gate-agent processes
#   - a root-owned ~/.prompt-gate the user can no longer write
#   - a dangling system/GUI proxy (GNOME gsettings, KDE kioslaverc,
#     /etc/profile.d/prompt-gate-proxy.sh) pointed at a dead agent
#   - custom DNS left in resolv.conf
#   - the trusted "prompt-gate-ca.crt" root cert in the system trust pool
#
# Best-effort and idempotent. Run as root: `sudo ./uninstall.sh`.

set -u

if [ "$(id -u)" -ne 0 ]; then
  echo "This uninstaller needs root for service / trust-store / proxy cleanup."
  echo "Re-run as:  sudo bash $0"
  exit 1
fi

HERE="$(cd "$(dirname "$0")" && pwd)"

# The Electron state + GUI proxy live in the *invoking* user's session,
# not root's. Resolve the real user so we clean the right home + dbus.
TARGET_USER="${SUDO_USER:-$(whoami)}"
TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
[ -n "${TARGET_HOME}" ] || TARGET_HOME="/home/${TARGET_USER}"
USER_CONFIG_DIR="${TARGET_HOME}/.prompt-gate"

DEB_CA="/usr/local/share/ca-certificates/prompt-gate-ca.crt"
RHEL_CA="/etc/pki/ca-trust/source/anchors/prompt-gate-ca.crt"
PROFILE_PROXY="/etc/profile.d/prompt-gate-proxy.sh"

step() { echo "==> $*"; }

# Run a command in the target user's session (for gsettings/dbus).
as_user() {
  local uid
  uid="$(id -u "${TARGET_USER}" 2>/dev/null)" || return 0
  sudo -u "${TARGET_USER}" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" \
    XDG_RUNTIME_DIR="/run/user/${uid}" \
    "$@" 2>/dev/null || true
}

# ----------------------------------------------------------------------------
# 1. Stop the service and any auto-spawned agent first.
# ----------------------------------------------------------------------------
step "Stopping service and agents"
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop prompt-gate.service 2>/dev/null || true
  systemctl disable prompt-gate.service 2>/dev/null || true
fi
pkill -f "prompt-gate-agent" 2>/dev/null || true
pkill -f "Prompt Gate" 2>/dev/null || true
sleep 1

# ----------------------------------------------------------------------------
# 2. Restore proxy + DNS while the helper scripts are still on disk.
# ----------------------------------------------------------------------------
step "Restoring system/GUI proxy"
if [ -x "${HERE}/configure-proxy.sh" ]; then
  # configure-proxy.sh touches per-user gsettings/KDE; run it as the user.
  as_user "${HERE}/configure-proxy.sh" restore
  # The /etc/profile.d file is system-wide; remove it as root regardless.
  rm -f "${PROFILE_PROXY}"
else
  rm -f "${PROFILE_PROXY}"
  as_user gsettings set org.gnome.system.proxy mode none
fi

step "Restoring DNS"
for dns in "${HERE}/configure-dns.sh" "/usr/share/prompt-gate/configure-dns.sh"; do
  if [ -x "${dns}" ]; then "${dns}" restore || true; break; fi
done

# ----------------------------------------------------------------------------
# 3. Untrust + remove the Root CA from whichever trust pool exists.
# ----------------------------------------------------------------------------
step "Removing trusted Root CA"
if [ -f "${DEB_CA}" ]; then
  rm -f "${DEB_CA}"
  command -v update-ca-certificates >/dev/null 2>&1 && update-ca-certificates --fresh >/dev/null 2>&1 || true
fi
if [ -f "${RHEL_CA}" ]; then
  rm -f "${RHEL_CA}"
  command -v update-ca-trust >/dev/null 2>&1 && update-ca-trust extract >/dev/null 2>&1 || true
fi

# ----------------------------------------------------------------------------
# 4. Remove the systemd service variant.
# ----------------------------------------------------------------------------
step "Removing service-variant files"
rm -f /usr/bin/prompt-gate-agent
rm -f /lib/systemd/system/prompt-gate.service /etc/systemd/system/prompt-gate.service
rm -rf /etc/prompt-gate /var/lib/prompt-gate /usr/share/prompt-gate
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload 2>/dev/null || true

# ----------------------------------------------------------------------------
# 5. Remove the Electron app (.deb-managed or /opt) + per-user state.
# ----------------------------------------------------------------------------
step "Removing Electron app (if installed via package manager)"
if command -v apt-get >/dev/null 2>&1 && dpkg -s prompt-gate >/dev/null 2>&1; then
  apt-get remove -y prompt-gate >/dev/null 2>&1 || true
elif command -v dnf >/dev/null 2>&1 && rpm -q prompt-gate >/dev/null 2>&1; then
  dnf remove -y prompt-gate >/dev/null 2>&1 || true
fi
rm -rf "/opt/Prompt Gate" /opt/prompt-gate

step "Removing per-user state ${USER_CONFIG_DIR}"
rm -rf "${USER_CONFIG_DIR}"
rm -rf "${TARGET_HOME}/.config/Prompt Gate"
rm -rf "${TARGET_HOME}/.config/promptgate"

echo
echo "Prompt Gate fully uninstalled."
echo "  - service stopped, agents killed, proxy + DNS restored"
echo "  - Root CA removed from the system trust pool"
echo "  - app, service files, and ~/.prompt-gate removed"
echo
echo "Note: an AppImage you downloaded manually is not tracked — delete the"
echo "Prompt Gate.AppImage file yourself. Firefox/Chromium snaps may keep their"
echo "own CA trust + the browser extension; remove those in-browser."
exit 0
