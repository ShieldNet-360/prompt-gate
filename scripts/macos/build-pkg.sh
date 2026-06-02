#!/usr/bin/env bash
# Build a macOS .pkg installer for the Prompt Gate agent + rules.
#
# Stages:
#   1. Assemble a payload tree under build/macos/root/ that mirrors the
#      layout we want on the target machine.
#   2. pkgbuild the component package (binary + config + rules).
#   3. productbuild a distribution package that bundles the component
#      package(s) and a postinstall script.
#
# Required: pkgbuild, productbuild (ships with Xcode CLT).
# Optional env: SECURE_EDGE_AGENT_BIN (defaults to ./agent/prompt-gate-agent),
#               SECURE_EDGE_VERSION   (defaults to 0.1.0).

set -euo pipefail

VERSION="${SECURE_EDGE_VERSION:-0.1.0}"
AGENT_BIN="${SECURE_EDGE_AGENT_BIN:-./agent/prompt-gate-agent}"
IDENTIFIER="com.shieldnet.promptgate"
PKG_NAME="prompt-gate-${VERSION}.pkg"

REPO_ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
OUT_DIR="${REPO_ROOT}/dist/macos"
BUILD_ROOT="${REPO_ROOT}/build/macos/root"
SCRIPTS_DIR="${REPO_ROOT}/build/macos/scripts"

if [ ! -f "${AGENT_BIN}" ]; then
  echo "build-pkg.sh: agent binary not found at ${AGENT_BIN}" >&2
  echo "build the darwin/amd64 (or darwin/arm64) binary first." >&2
  exit 2
fi

rm -rf "${BUILD_ROOT}" "${SCRIPTS_DIR}"
mkdir -p "${OUT_DIR}" \
         "${BUILD_ROOT}/usr/local/bin" \
         "${BUILD_ROOT}/Library/LaunchDaemons" \
         "${BUILD_ROOT}/etc/prompt-gate/rules" \
         "${SCRIPTS_DIR}"

# Layout: binary, plist, rule files, default config.
install -m 0755 "${AGENT_BIN}" "${BUILD_ROOT}/usr/local/bin/prompt-gate-agent"
install -m 0644 "${REPO_ROOT}/scripts/macos/com.shieldnet360.promptgate.plist" \
                "${BUILD_ROOT}/Library/LaunchDaemons/com.shieldnet360.promptgate.plist"
if [ -d "${REPO_ROOT}/rules" ]; then
  cp -R "${REPO_ROOT}/rules/." "${BUILD_ROOT}/etc/prompt-gate/rules/"
fi
cat > "${BUILD_ROOT}/etc/prompt-gate/config.yaml" <<'EOF'
upstream_dns: 1.1.1.1:53
dns_listen:   127.0.0.1:15353
api_listen:   127.0.0.1:9191
db_path:      /var/lib/prompt-gate/prompt-gate.db
rule_paths:
  - /etc/prompt-gate/rules/ai_chat_blocked.txt
  - /etc/prompt-gate/rules/ai_code_blocked.txt
  - /etc/prompt-gate/rules/ai_allowed.txt
  - /etc/prompt-gate/rules/ai_chat_dlp.txt
  - /etc/prompt-gate/rules/phishing.txt
  - /etc/prompt-gate/rules/social.txt
  - /etc/prompt-gate/rules/news.txt
rules_dir:    /etc/prompt-gate/rules
dlp_patterns:   /etc/prompt-gate/rules/dlp_patterns.json
dlp_exclusions: /etc/prompt-gate/rules/dlp_exclusions.json
rule_update_url:      ""
rule_update_interval: 6h
EOF

install -m 0755 "${REPO_ROOT}/scripts/macos/postinstall.sh" \
                "${SCRIPTS_DIR}/postinstall"

# Build the component package (single payload, no choices outline).
COMPONENT="${OUT_DIR}/prompt-gate-component.pkg"
pkgbuild \
  --root "${BUILD_ROOT}" \
  --identifier "${IDENTIFIER}" \
  --version "${VERSION}" \
  --scripts "${SCRIPTS_DIR}" \
  --install-location "/" \
  "${COMPONENT}"

# Wrap in a distribution package so users see a familiar .pkg UI and so
# we can sign it with productbuild later.
productbuild \
  --identifier "${IDENTIFIER}.distribution" \
  --version "${VERSION}" \
  --package "${COMPONENT}" \
  "${OUT_DIR}/${PKG_NAME}"

rm -f "${COMPONENT}"
echo "build-pkg.sh: wrote ${OUT_DIR}/${PKG_NAME}"
