#!/usr/bin/env bash
# Build .deb and .rpm packages of the Prompt Gate agent using nfpm.
#
# Required env / inputs:
#   SECURE_EDGE_VERSION (optional, default: tag-derived or 0.1.0)
#   SECURE_EDGE_ARCH    (optional, default: amd64)
#   SECURE_EDGE_AGENT_BIN (optional, default: ./agent/prompt-gate-agent)
#
# Requires `nfpm` >= 2.30 on PATH (https://nfpm.goreleaser.com/).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
OUT_DIR="${REPO_ROOT}/dist/linux"
NFPM_CONFIG="${REPO_ROOT}/agent/nfpm.yaml"
VERSION="${SECURE_EDGE_VERSION:-1.0.0}"
ARCH="${SECURE_EDGE_ARCH:-amd64}"
AGENT_BIN="${SECURE_EDGE_AGENT_BIN:-${REPO_ROOT}/agent/prompt-gate-agent}"

if ! command -v nfpm >/dev/null 2>&1; then
    echo "build-packages.sh: nfpm not found on PATH" >&2
    echo "install: https://nfpm.goreleaser.com/install/" >&2
    exit 2
fi
if [ ! -f "${AGENT_BIN}" ]; then
    echo "build-packages.sh: agent binary not found at ${AGENT_BIN}" >&2
    exit 2
fi

# nfpm.yaml has a relative `src: ./prompt-gate-agent` so it expects the
# binary to live next to the config when run from agent/. Stage it.
ln -sf "${AGENT_BIN}" "${REPO_ROOT}/agent/prompt-gate-agent"

mkdir -p "${OUT_DIR}"

export SECURE_EDGE_VERSION="${VERSION}"
export SECURE_EDGE_ARCH="${ARCH}"

# Two-pass build: deb and rpm both consume the same nfpm.yaml.
cd "${REPO_ROOT}/agent"
nfpm pkg --packager deb --config "${NFPM_CONFIG}" --target "${OUT_DIR}/"
nfpm pkg --packager rpm --config "${NFPM_CONFIG}" --target "${OUT_DIR}/"

echo "build-packages.sh: wrote artefacts under ${OUT_DIR}/"
ls -1 "${OUT_DIR}"
