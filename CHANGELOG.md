# Changelog

All notable changes to Prompt Gate are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2]

### Added

- Auto-update flow: checks GitHub releases at startup, notifies the user,
  downloads and installs on consent (electron-updater + `publish` block).
- `performUpdateQuit()` — clean shutdown before auto-update install so the
  `before-quit` handler doesn't block `will-quit` (the installer trigger).
- Non-blocking agent startup: tray, IPC handlers, auto-update check, and
  helper installation all run immediately instead of waiting for the Go agent.
- Parallelized initial agent reachability checks (`agentConfigured` +
  `agentReachable` via `Promise.all`).
- Faster agent-ready polling (200ms interval, was 300ms).
- Centralized version: UI reads version dynamically from `package.json` via
  `getVersion` IPC handler instead of hardcoding.
- Makefile now injects `VERSION` into the Go agent binary via ldflags.

### Changed

- Version bump across all packaging, docs, and UI to 1.0.2.

## [1.0.1]

### Changed

- Added support email contact (Support@shieldnet360.com) to About Us page.
- Version bump across all packaging and documentation.

## [1.0.0] — initial public release

First public release of Prompt Gate — an open-source, privacy-first AI
Data Loss Prevention tool for the desktop. It keeps secrets and sensitive
data from leaving your machine through AI tools, while persisting nothing
about what you do.

### Highlights

- **Category-based DNS blocking.** An embedded DNS resolver enforces
  allow / inspect / block policies per domain category, returning
  NXDOMAIN for blocked AI and other flagged destinations. Negligible CPU
  and memory footprint; runs as a minimal system-tray app.
- **Layered on-device DLP pipeline.** An Aho-Corasick + regex
  deterministic core paired with accuracy layers — adversary-resistant
  normalisation (zero-width strip, homoglyph fold, NFKC, inline base64
  decode), a multi-piece session correlator, a public-example bloom
  filter, and a placeholder-shape router — plus source-context scoring
  bias driven by the optional paste destination. Ships **163+** real-world
  detection patterns across cloud, version control, AI/ML, payment, CI/CD,
  messaging, auth, language ecosystems, databases, keys/JWTs, and PII.
  Sub-millisecond per scan with no ML dependency.
- **Browser extension.** Chrome / Firefox / Safari companion that
  intercepts pastes, drag-and-drop, form submissions, and network bodies
  on AI-tool hosts, scanning content through the local agent before it
  leaves the browser, and surfacing an in-page block toast.
- **Desktop tray app.** An Electron tray application for status, policy
  configuration, the optional MITM proxy wizard, and a read-only rule
  viewer.
- **Privacy by design.** Zero per-event persistence — only aggregate
  integer counters and policy configuration ever reach disk. No content,
  domain names, IP addresses, or user identifiers are stored. The
  feedback allowlist stores only per-install-salted SHA-256 hashes; any
  optional history feature is consent-gated and off by default.
- **Enterprise features.** Managed-mode configuration profiles,
  Ed25519-signed policy distribution, OS DNS/proxy tamper detection,
  optional aggregate-only heartbeat, admin override mechanism, and signed
  agent self-update.
- **Supply-chain hardening.** Reproducible Go agent builds, CycloneDX
  SBOM per release, OpenSSF Scorecard, CodeQL, signed and verifiable
  release artifacts, and Homebrew / winget packaging.

[1.0.2]: https://github.com/ShieldNet-360/prompt-gate/releases/tag/v1.0.2
[1.0.1]: https://github.com/ShieldNet-360/prompt-gate/releases/tag/v1.0.1
[1.0.0]: https://github.com/ShieldNet-360/prompt-gate/releases/tag/v1.0.0
