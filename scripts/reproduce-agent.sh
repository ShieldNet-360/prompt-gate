#!/usr/bin/env bash
#
# reproduce-agent.sh — independently rebuild the Prompt Gate agent binaries
# and prove they match a published release, bit-for-bit.
#
# The agent binaries are reproducible: each one is a pure function of
#   (source content + Go toolchain version + GOOS/GOARCH + build flags).
# This script rebuilds all five with the exact flags the Release workflow
# uses, prints their SHA-256, and (optionally) diffs them against a
# release SHA256SUMS file.
#
# Byte-identical reproduction REQUIRES the same Go toolchain that built the
# release — the version pinned in agent/go.mod (CI installs it via
# setup-go's go-version-file). Using a different Go version will produce a
# valid but differently-hashed binary.
#
# Usage:
#   scripts/reproduce-agent.sh [VERSION] [SHA256SUMS]
#
#   VERSION     git tag embedded via -ldflags -X main.version (default: `git describe`)
#   SHA256SUMS  optional path to a release SHA256SUMS file to compare against
#
# Example (verify the published v1.0.0):
#   git checkout v1.0.0
#   curl -fsSLO https://github.com/ShieldNet-360/prompt-gate/releases/download/v1.0.0/SHA256SUMS
#   scripts/reproduce-agent.sh v1.0.0 SHA256SUMS

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")"/.. && pwd)"
VERSION="${1:-$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null || echo dev)}"
SUMS="${2:-}"
OUT="${REPO_ROOT}/dist/reproduce"

mkdir -p "$OUT"
cd "$REPO_ROOT/agent"

# Warn if the local toolchain differs from the one go.mod pins.
want_go="$(awk '/^go /{print $2; exit}' go.mod)"
have_go="$(go env GOVERSION | sed 's/^go//')"
if [ "$want_go" != "$have_go" ]; then
  echo "WARNING: go.mod pins Go ${want_go} but you have ${have_go}." >&2
  echo "         Bit-identical reproduction needs the pinned toolchain." >&2
fi

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1"; else shasum -a256 "$1"; fi; }

build() {
  local goos="$1" goarch="$2" ext="${3:-}"
  local name="prompt-gate-agent-${goos}-${goarch}${ext}"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o "${OUT}/${name}" ./cmd/agent
  sha "${OUT}/${name}" | sed "s#${OUT}/##"
}

echo "==> Rebuilding agent ${VERSION} with Go ${have_go}"
{
  build linux   amd64
  build linux   arm64
  build darwin  amd64
  build darwin  arm64
  build windows amd64 .exe
} | tee "${OUT}/REPRODUCED_SHA256"

if [ -n "$SUMS" ]; then
  echo "==> Comparing against ${SUMS}"
  rc=0
  while read -r want name; do
    name="${name#\*}"
    case "$name" in prompt-gate-agent-*) ;; *) continue ;; esac
    have="$(awk -v n="$name" '$2==n || $2=="*"n {print $1}' "${OUT}/REPRODUCED_SHA256")"
    if [ -z "$have" ]; then continue; fi
    if [ "$want" = "$have" ]; then echo "OK   $name"; else echo "DIFF $name (release=$want rebuilt=$have)"; rc=1; fi
  done < "$SUMS"
  [ "$rc" -eq 0 ] && echo "==> All agent binaries reproduced exactly." || { echo "==> MISMATCH — see above." >&2; exit 1; }
fi
