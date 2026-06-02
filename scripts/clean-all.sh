#!/usr/bin/env bash
# clean-all.sh — Full cleanup of Prompt Gate for testing.
# Usage: bash scripts/clean-all.sh
set -euo pipefail

APP_NAME="Prompt Gate"
AGENT_NAME="prompt-gate-agent"
HELPER_NAME="prompt-gate-proxy-helper"
CA_CN="Prompt Gate Local CA"
BUNDLE_ID="com.prompt-gate.app"
LOGIN_KC="$HOME/Library/Keychains/login.keychain-db"
SYSTEM_KC="/Library/Keychains/System.keychain"

echo "==> Killing all Prompt Gate processes..."
pkill -f "$AGENT_NAME" 2>/dev/null || true
pkill -f "$HELPER_NAME" 2>/dev/null || true
pkill -f "$BUNDLE_ID" 2>/dev/null || true
pkill -f "Prompt Gate" 2>/dev/null || true
sleep 1
# Force kill any survivors
pkill -9 -f "$AGENT_NAME" 2>/dev/null || true
pkill -9 -f "$HELPER_NAME" 2>/dev/null || true
pkill -9 -f "$BUNDLE_ID" 2>/dev/null || true

echo "==> Removing CA certificates from login keychain..."
while security find-certificate -c "$CA_CN" "$LOGIN_KC" >/dev/null 2>&1; do
  security delete-certificate -c "$CA_CN" "$LOGIN_KC" 2>/dev/null || break
done

echo "==> Removing CA certificates from system keychain (needs admin)..."
if security find-certificate -c "$CA_CN" "$SYSTEM_KC" >/dev/null 2>&1; then
  while security find-certificate -c "$CA_CN" "$SYSTEM_KC" >/dev/null 2>&1; do
    sudo security delete-certificate -c "$CA_CN" "$SYSTEM_KC" 2>/dev/null || break
  done
fi

echo "==> Removing ~/.prompt-gate..."
rm -rf "$HOME/.prompt-gate"

echo "==> Removing Electron user data (localStorage, caches)..."
rm -rf "$HOME/Library/Application Support/Prompt Gate"
rm -rf "$HOME/Library/Caches/Prompt Gate"
rm -rf "$HOME/Library/Preferences/com.prompt-gate.app.plist"

echo "==> Removing from /Applications..."
rm -rf "/Applications/Prompt Gate.app"

echo "==> Removing dist/bin..."
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
rm -rf "$SCRIPT_DIR/dist/bin"

echo "==> Removing electron/release..."
rm -rf "$SCRIPT_DIR/electron/release"

echo "==> Removing electron/resources/bin..."
rm -rf "$SCRIPT_DIR/electron/resources/bin"

echo "==> Checking /Volumes for Prompt Gate..."
if [ -d "/Volumes/Prompt Gate" ]; then
  echo "    Ejecting /Volumes/Prompt Gate..."
  hdiutil detach "/Volumes/Prompt Gate" -force 2>/dev/null || true
fi

echo "==> Removing proxy-helper launchd service..."
sudo launchctl bootout system/com.shieldnet360.promptgate.proxy-helper 2>/dev/null || true
sudo rm -f /Library/LaunchDaemons/com.shieldnet360.promptgate.proxy-helper.plist
sudo rm -f /usr/local/bin/prompt-gate-proxy-helper

echo "==> Restoring system proxy settings..."
for svc in $(networksetup -listallnetworkservices | tail -n +2 | grep -v '^\*'); do
  networksetup -setsecurewebproxystate "$svc" off 2>/dev/null || true
  networksetup -setwebproxystate "$svc" off 2>/dev/null || true
done

echo ""
echo "✅ Prompt Gate fully cleaned."
