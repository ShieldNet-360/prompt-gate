# Installation

Prompt Gate ships a Go agent, a browser companion, and an Electron tray. Pick the
path that suits you — all artifacts for the current release are on the
[v1.0.1 release page](https://github.com/ShieldNet-360/prompt-gate/releases/tag/v1.0.1).

!!! note "Code-signing status"
    Builds are **not yet Apple-notarized / Authenticode-signed**, so Gatekeeper
    (macOS) and SmartScreen (Windows) will warn. macOS workaround:
    `xattr -cr "/Applications/Prompt Gate.app"`. Signed builds are tracked as
    owed release work.

## Download a release (fastest)

Grab the asset for your platform from the
[latest release](https://github.com/ShieldNet-360/prompt-gate/releases/latest):

| Platform | Asset |
|---|---|
| macOS (Apple Silicon) | `Prompt.Gate-<version>-arm64.dmg` |
| Windows | `Prompt.Gate.Setup.<version>.exe` |
| Linux (desktop) | `Prompt.Gate-<version>.AppImage` |
| Linux (Debian/Ubuntu) | `prompt-gate_<version>_amd64.deb` |
| Agent only (any OS) | `prompt-gate-agent-<os>-<arch>` |
| Browser extension | `prompt-gate-{chrome,firefox,safari}-<version>.zip` / `.xpi` |

Always verify what you downloaded — see [Verify](#verify) below.

## Package managers

Manifests are published in the repository ([`packaging/`](https://github.com/ShieldNet-360/prompt-gate/tree/main/packaging))
with hashes verified against the release `SHA256SUMS`, and they are kept in sync
with every release automatically.

**Homebrew (macOS, Apple Silicon):**

```bash
# from a checkout (works today)
brew install --cask ./packaging/homebrew/prompt-gate.rb

# once the tap is published
brew install --cask ShieldNet-360/tap/prompt-gate
```

**winget (Windows):**

```powershell
# from a checkout (works today)
winget install --manifest .\packaging\winget\

# once accepted into winget-pkgs
winget install ShieldNet360.PromptGate
```

> Public Homebrew-tap and winget-pkgs listings are in progress; the one-line
> commands above light up once those are merged (smoother after code-signing).

## Build from source

```bash
git clone https://github.com/ShieldNet-360/prompt-gate.git
cd prompt-gate && make dist
./agent/prompt-gate-agent --config config.yaml
```

See the [Quick Start](quickstart.md) for the minimal config and a first scan,
and the [Install Guide](admin-guide.md) for per-platform packaging and managed
deployment.

## Verify

Prompt Gate is built to be checkable, not just trusted:

- **Integrity & provenance** — [Verifying releases](verifying-releases.md)
  (`sha256sum --check SHA256SUMS`, `gh attestation verify …`).
- **Reproducibility** — rebuild the agent bit-for-bit and confirm it matches the
  published binary: [Reproducible builds](reproducible-builds.md).
- **SBOM** — each release ships `prompt-gate-agent.cyclonedx.json`.
