# Reproducible builds & the end-to-end trust chain

Prompt Gate's core promise is that the agent **persists nothing** about user
activity — no per-event content, domains, IPs, or identifiers (see the
[whitepaper §8](whitepaper.md#8-privacy-model)). A promise is only worth as much
as your ability to check it. This page shows how you can verify it **end to
end** — from the source you can read, to the exact bytes running on your
machine — without trusting us.

## The chain

```
 ┌────────────┐   privacy test    ┌──────────────┐  reproducible build  ┌────────────┐
 │  Source    │ ───────────────▶  │ "this source │ ───────────────────▶ │  Published │
 │ (auditable)│   proves          │  persists    │  proves bytes match  │  binary    │
 └────────────┘   no-persistence  │  nothing"    │  the source          └────────────┘
                                   └──────────────┘                            │
                                          ▲                                    │ SLSA provenance
                                          └──────────── same artifact ─────────┘ + Sigstore
                                                                                  prove CI built it
                                                                                  from the tagged commit
```

Each link is independently checkable:

| Link | What it proves | How you check it |
|---|---|---|
| **1. Open source** | You can read every line that handles data | Browse the repo |
| **2. Privacy invariant test** | The *source* writes nothing forbidden to disk | `go test ./internal/store/ -run TestPrivacy -v` |
| **3. Reproducible build** | The *published binary* is exactly that source compiled | `scripts/reproduce-agent.sh` (below) |
| **4. SLSA provenance** | CI built that binary from the tagged commit | `gh attestation verify …` |
| **5. Checksums + Sigstore** | The download wasn't tampered with in transit | `sha256sum --check SHA256SUMS` |

Link 3 is the one that closes the loop: without it, an audited *source* and a
shipped *binary* are two unconnected things. With it, the binary you run is
provably the source whose privacy test you just watched pass.

## Verify it yourself

```bash
# 1. Get the exact source for the release
git clone https://github.com/ShieldNet-360/prompt-gate.git
cd prompt-gate && git checkout v1.0.0

# 2. Watch the privacy invariant pass on that source
go test ./agent/internal/store/ -run TestPrivacy -v   # (run from agent/ dir)

# 3. Rebuild the agent and compare to the published binaries, bit-for-bit
curl -fsSLO https://github.com/ShieldNet-360/prompt-gate/releases/download/v1.0.0/SHA256SUMS
scripts/reproduce-agent.sh v1.0.0 SHA256SUMS
#   → "OK prompt-gate-agent-darwin-arm64", … "All agent binaries reproduced exactly."

# 4. Confirm CI built it from this repo's tagged commit
gh attestation verify prompt-gate-agent-darwin-arm64 --repo ShieldNet-360/prompt-gate
```

## How reproducibility is achieved

The agent binaries are compiled as a **pure function** of
`(source content + Go toolchain version + GOOS/GOARCH + flags)`:

- `CGO_ENABLED=0` — no host C toolchain enters the build.
- `-trimpath` — strips local filesystem paths from the binary.
- `-buildvcs=false` — drops Go's embedded VCS stamp, so the output does not
  depend on your `.git` state (the commit is still bound to the artifact via
  SLSA provenance, link 4).
- The toolchain is **pinned in `agent/go.mod`** (`go 1.25.9`); CI installs
  exactly that via `setup-go`'s `go-version-file`.

Every release runs a **`Verify reproducible agent build`** CI job that rebuilds
all five binaries in a clean runner and fails if any SHA-256 differs from the
artifact that shipped — so reproducibility is enforced, not just claimed.

!!! note "Toolchain matters"
    Byte-identical reproduction requires the **same Go version** that built the
    release (the one in `go.mod`). A different Go version produces a valid but
    differently-hashed binary. `reproduce-agent.sh` warns you if your local
    toolchain differs.

## Scope — what's covered, honestly

- **Covered: the Go agent** (`prompt-gate-agent-*`). This is the component that
  resolves DNS, runs the DLP engine, and owns *all* persistence — i.e. exactly
  the code the "persist nothing" claim is about. It is reproducible and
  CI-verified.
- **Not bit-reproducible: the Electron tray installers** (`.dmg`/`.exe`/
  `.AppImage`). Electron-builder embeds timestamps and OS-specific packaging
  metadata. The tray is a thin loopback UI that talks to the agent over
  `127.0.0.1` and never persists user data — the privacy boundary lives in the
  agent, which *is* reproducible. Tray installer integrity is covered by
  checksums + SLSA provenance (links 4–5).
