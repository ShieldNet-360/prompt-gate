#!/usr/bin/env bash
# Completely remove Prompt Gate from a macOS machine.
#
# Covers BOTH install shapes:
#   - Electron app bundle ("/Applications/Prompt Gate.app") + auto-spawned
#     agent + per-user "~/.prompt-gate" state.
#   - PKG / LaunchDaemon variant (/usr/local/bin + /etc/prompt-gate).
#
# And every system-level side effect either shape can leave behind — the
# recurring launch-week breakages this script exists to make impossible:
#   - stale prompt-gate-agent processes holding the API/DNS port
#   - a root-owned ~/.prompt-gate the user can no longer write
#   - a dangling system HTTP/HTTPS proxy pointed at a dead agent
#   - custom DNS servers left set on every network service
#   - the pf "com.prompt-gate" anchor still dropping :443 UDP
#   - the privileged proxy-helper LaunchDaemon + binary + socket
#   - the "Prompt Gate Local CA" root cert still trusted in the System keychain
#
# Best-effort: every step continues past its own failure so one stuck
# resource can't strand the rest. Re-running is safe (idempotent).
#
# Usage:  sudo bash uninstall.sh
#
# Removing the CA trust and turning the system proxy off are reversals of
# protections the app installed; they are intentionally unconditional here
# because the whole point is a clean machine. Nothing is enabled.

set -u

# ----------------------------------------------------------------------------
# Identifiers — keep in lockstep with the Go source so this never drifts:
#   helper label / paths : agent/internal/sysconf/helper_darwin.go
#   socket / CA CN / pf   : agent/cmd/proxy-helper/run_darwin.go
#   config dir / db       : agent/cmd/agent/main.go, electron/main.ts
#   PKG daemon            : scripts/macos/postinstall.sh
# ----------------------------------------------------------------------------
APP_BUNDLE="/Applications/Prompt Gate.app"

HELPER_PLIST="/Library/LaunchDaemons/com.shieldnet360.promptgate.proxy-helper.plist"
HELPER_BIN="/Library/PrivilegedHelperTools/com.shieldnet360.promptgate.proxy-helper"
HELPER_SOCKET="/var/run/prompt-gate-proxy.sock"
HELPER_LOG="/var/log/prompt-gate-proxy-helper.log"

CA_COMMON_NAME="Prompt Gate Local CA"
SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"
PF_ANCHOR="com.prompt-gate"
PF_RULES_FILE="/tmp/prompt-gate-pf.conf"

# PKG / LaunchDaemon variant.
PKG_PLIST="/Library/LaunchDaemons/com.shieldnet360.promptgate.plist"
PKG_BINARY="/usr/local/bin/prompt-gate-agent"
PKG_CONFIG_DIR="/etc/prompt-gate"
PKG_LIB_DIR="/var/lib/prompt-gate"
PKG_SHARE_DIR="/usr/local/share/prompt-gate"

if [ "$(id -u)" -ne 0 ]; then
  echo "This uninstaller needs root for system proxy / keychain / LaunchDaemon cleanup."
  echo "Re-run as:  sudo bash $0"
  exit 1
fi

# The Electron state dir lives in the *invoking* user's home, not root's.
# When run under sudo, resolve the real user so we clean the right ~.
TARGET_USER="${SUDO_USER:-$(whoami)}"
TARGET_HOME="$(/usr/bin/dscl . -read "/Users/${TARGET_USER}" NFSHomeDirectory 2>/dev/null | awk '{print $2}')"
[ -n "${TARGET_HOME}" ] || TARGET_HOME="/Users/${TARGET_USER}"
USER_CONFIG_DIR="${TARGET_HOME}/.prompt-gate"

step() { echo "==> $*"; }

# ----------------------------------------------------------------------------
# 1. Stop the app and any agent it spawned, so nothing reconfigures the
#    system out from under us mid-uninstall.
# ----------------------------------------------------------------------------
step "Quitting Prompt Gate and stopping agents"
/usr/bin/osascript -e 'tell application "Prompt Gate" to quit' >/dev/null 2>&1 || true
/usr/bin/pkill -f "Prompt Gate.app/Contents/MacOS" 2>/dev/null || true
# Only kill processes whose argv0 is actually a prompt-gate-agent.
/usr/bin/pkill -f "prompt-gate-agent" 2>/dev/null || true
sleep 1

# ----------------------------------------------------------------------------
# 2. Restore the system proxy / DNS / pf BEFORE we remove the helper, while
#    networksetup + pfctl are still trivially available. These are no-ops if
#    the app never touched them.
# ----------------------------------------------------------------------------
step "Turning off any system proxy and restoring DNS"
SERVICES="$(/usr/sbin/networksetup -listallnetworkservices 2>/dev/null | tail -n +2 | sed 's/^\*//')"
IFS=$'\n'
for svc in ${SERVICES}; do
  [ -n "${svc}" ] || continue
  /usr/sbin/networksetup -setsecurewebproxystate "${svc}" off 2>/dev/null || true
  /usr/sbin/networksetup -setwebproxystate "${svc}" off 2>/dev/null || true
  # "Empty" clears any custom DNS the agent set, reverting to DHCP.
  /usr/sbin/networksetup -setdnsservers "${svc}" Empty 2>/dev/null || true
done
unset IFS

step "Flushing pf anchor ${PF_ANCHOR}"
/sbin/pfctl -a "${PF_ANCHOR}" -F all 2>/dev/null || true
rm -f "${PF_RULES_FILE}"

# ----------------------------------------------------------------------------
# 3. Remove the trusted Root CA. Loop until find-certificate misses, in case
#    repeated installs left duplicate entries (matches helper REMOVE_CA).
# ----------------------------------------------------------------------------
step "Removing trusted Root CA \"${CA_COMMON_NAME}\""
while /usr/bin/security find-certificate -c "${CA_COMMON_NAME}" "${SYSTEM_KEYCHAIN}" >/dev/null 2>&1; do
  /usr/bin/security delete-certificate -c "${CA_COMMON_NAME}" "${SYSTEM_KEYCHAIN}" >/dev/null 2>&1 || break
done

# ----------------------------------------------------------------------------
# 4. Tear down the privileged proxy-helper LaunchDaemon.
# ----------------------------------------------------------------------------
step "Removing privileged proxy-helper"
launchctl bootout system "${HELPER_PLIST}" 2>/dev/null || true
launchctl unload "${HELPER_PLIST}" 2>/dev/null || true
rm -f "${HELPER_PLIST}" "${HELPER_BIN}" "${HELPER_SOCKET}" "${HELPER_LOG}"

# ----------------------------------------------------------------------------
# 5. Remove the PKG / LaunchDaemon agent variant, if present.
# ----------------------------------------------------------------------------
step "Removing PKG/daemon agent variant (if installed)"
if [ -x "${PKG_SHARE_DIR}/configure-dns.sh" ]; then
  "${PKG_SHARE_DIR}/configure-dns.sh" restore 2>/dev/null || true
fi
launchctl bootout system "${PKG_PLIST}" 2>/dev/null || true
rm -f "${PKG_PLIST}" "${PKG_BINARY}"
rm -rf "${PKG_CONFIG_DIR}" "${PKG_LIB_DIR}" "${PKG_SHARE_DIR}"

# ----------------------------------------------------------------------------
# 6. Remove the app bundle and the per-user state dir. The state dir is the
#    one that has bitten users when a prior root-spawned agent left it
#    root-owned — rm -rf as root clears it regardless of owner.
# ----------------------------------------------------------------------------
step "Removing app bundle ${APP_BUNDLE}"
rm -rf "${APP_BUNDLE}"

step "Removing per-user state ${USER_CONFIG_DIR}"
rm -rf "${USER_CONFIG_DIR}"

# Electron's own caches/prefs (appId com.shieldnet360.promptgate), best-effort.
rm -rf "${TARGET_HOME}/Library/Application Support/Prompt Gate" 2>/dev/null || true
rm -rf "${TARGET_HOME}/Library/Caches/com.shieldnet360.promptgate" 2>/dev/null || true
rm -f  "${TARGET_HOME}/Library/Preferences/com.shieldnet360.promptgate.plist" 2>/dev/null || true
rm -rf "${TARGET_HOME}/Library/Saved Application State/com.shieldnet360.promptgate.savedState" 2>/dev/null || true

echo
echo "Prompt Gate fully uninstalled."
echo "  - system proxy off, DNS restored to DHCP, pf anchor flushed"
echo "  - Root CA \"${CA_COMMON_NAME}\" untrusted and removed"
echo "  - privileged helper, app bundle, and ~/.prompt-gate removed"
echo
echo "Note: the browser extension (if installed) must be removed from the"
echo "browser separately — open chrome://extensions and remove Prompt Gate."
exit 0
