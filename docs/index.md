---
hide:
  - navigation
  - toc
---

<div class="se-hero" markdown>

# Stop AI data leakage at the source

Open-source, privacy-first AI Data Loss Prevention for desktop. Block unauthorized AI tools at DNS. Inspect content sent to approved ones. Persist **nothing** about user access.

<div class="se-hero-shields">
  <a href="https://github.com/ShieldNet-360/prompt-gate/releases/latest"><img src="https://img.shields.io/github/v/release/ShieldNet-360/prompt-gate?label=release&color=0a84ff" alt="Latest release"></a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ShieldNet-360/prompt-gate/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/actions/workflows/codeql.yml"><img src="https://github.com/ShieldNet-360/prompt-gate/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
  <a href="https://scorecard.dev/viewer/?uri=github.com/ShieldNet-360/prompt-gate"><img src="https://api.scorecard.dev/projects/github.com/ShieldNet-360/prompt-gate/badge" alt="OpenSSF Scorecard"></a>
  <a href="https://www.bestpractices.dev/projects/13075"><img src="https://www.bestpractices.dev/projects/13075/badge" alt="OpenSSF Best Practices"></a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/attestations"><img src="https://img.shields.io/badge/provenance-SLSA%20build-blue" alt="SLSA build provenance"></a>
  <img src="https://img.shields.io/badge/signed-Sigstore-0a84ff" alt="Signed with Sigstore">
  <a href="reproducible-builds/"><img src="https://img.shields.io/badge/agent%20build-reproducible-2b6cb0" alt="Reproducible build"></a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow" alt="MIT"></a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/stargazers"><img src="https://img.shields.io/github/stars/ShieldNet-360/prompt-gate?style=flat&color=gold" alt="Stars"></a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/releases"><img src="https://img.shields.io/github/downloads/ShieldNet-360/prompt-gate/total?label=downloads&color=brightgreen" alt="Downloads"></a>
  <img src="https://img.shields.io/badge/platforms-win%20%7C%20mac%20%7C%20linux-green" alt="Platforms">
  <img src="https://img.shields.io/badge/browsers-chrome%20%7C%20firefox%20%7C%20safari-blue" alt="Browsers">
  <img src="https://img.shields.io/badge/DLP%20patterns-165-cyan" alt="DLP patterns">
  <img src="https://img.shields.io/badge/categories-14-blueviolet" alt="Categories">
  <img src="https://img.shields.io/badge/privacy%20invariant-tested-brightgreen" alt="Privacy invariant tested">
  <img src="https://img.shields.io/badge/OWASP_Agentic-ASI--02_%2B_ASI--06_endpoint-orange" alt="OWASP scoped">
</div>

```
git clone https://github.com/ShieldNet-360/prompt-gate.git && cd prompt-gate && make dist
```

<div class="se-hero-badges">
  <a href="installation/">📦 Install</a>
  <a href="quickstart/">🚀 Quick Start</a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/releases/latest">⬇️ Download v1.1.1</a>
  <a href="https://github.com/ShieldNet-360/prompt-gate">💻 GitHub</a>
  <a href="admin-guide/">⚙️ Admin Guide</a>
  <a href="user-guide/">👤 User Guide</a>
</div>

<div class="se-stats">
  <div class="se-stat"><span class="se-stat-value">165</span><span class="se-stat-label">DLP Patterns</span></div>
  <div class="se-stat"><span class="se-stat-value">14</span><span class="se-stat-label">Categories</span></div>
  <div class="se-stat"><span class="se-stat-value">3</span><span class="se-stat-label">Operating Systems</span></div>
  <div class="se-stat"><span class="se-stat-value">3</span><span class="se-stat-label">Browsers</span></div>
  <div class="se-stat"><span class="se-stat-value">&lt;1ms</span><span class="se-stat-label">DLP Scan Budget</span></div>
</div>

</div>

<div class="se-section" markdown>

## Why Prompt Gate

<div class="se-cards">
<div class="se-card">
<span class="se-card-icon">🔒</span>
<span class="se-card-body"><span class="se-card-title">Privacy by design</span>
<span class="se-card-desc">Zero per-event logs. Only aggregate integer counters ever touch disk — enforced by a CI column-sweep test, not a promise.</span></span>
</div>
<div class="se-card">
<span class="se-card-icon">⚡</span>
<span class="se-card-body"><span class="se-card-title">On-device & fast</span>
<span class="se-card-desc">A single static Go binary. 165 patterns scanned in &lt;1ms, no cloud round-trip, no account, no telemetry.</span></span>
</div>
<div class="se-card">
<span class="se-card-icon">🧩</span>
<span class="se-card-body"><span class="se-card-title">Layered & optional</span>
<span class="se-card-desc">DNS blocking, browser companion, and selective MITM stack independently. Run one layer or all four.</span></span>
</div>
<div class="se-card">
<span class="se-card-icon">📖</span>
<span class="se-card-body"><span class="se-card-title">Open & verifiable</span>
<span class="se-card-desc">MIT-licensed. Sigstore-signed releases with SLSA build provenance — verify every artifact with one command.</span></span>
</div>
</div>

</div>

<div class="se-section" markdown>

## The problem

Your users paste customer data, source code, API keys, and internal docs into ChatGPT, Claude, Copilot, and a dozen other AI tools every day. SaaS DLP sees an encrypted blob heading for a cloud provider — too late. Network DLP can't decrypt browser-pinned TLS. You need answers to three questions:

**1. What is actually leaving the endpoint?** A keystroke-by-keystroke browser hook is intrusive and laggy. A network tap can't see inside HTTPS. Prompt Gate intercepts at the **paste / form / fetch / drag / clipboard** boundary in the browser and through a selective MITM proxy for non-browser apps.

**2. Will it leave a trail of who said what?** Traditional DLP logs every prompt — that's its own privacy problem, and it makes employees route around the tool. Prompt Gate persists **only aggregate counters**, never per-event content, domains, URLs, or user identifiers. Verified by a column-sweep test in CI.

**3. Can it be stopped *before* the network call?** DNS-layer blocking refuses queries for unauthorized AI hosts (`NXDOMAIN`); the browser companion + on-device pipeline scan content for approved hosts; blocks happen client-side before bytes leave.

</div>

<div class="se-section" markdown>

## Block leakage in three commands

Install once. Configure the tier list. Run.

```bash
git clone https://github.com/ShieldNet-360/prompt-gate.git
cd prompt-gate && make dist
./agent/prompt-gate-agent --config config.yaml
```

Prefer a packaged build? Grab a [v1.1.1 release](https://github.com/ShieldNet-360/prompt-gate/releases/latest)
for your OS, or use a package manager — see **[Installation](installation/)** for
Homebrew / winget and how to verify what you install.

The agent exposes a loopback API at `127.0.0.1:9191`. The browser extension and tray app pick it up automatically.

```yaml
# config.yaml — minimal
upstream_dns: "8.8.8.8:53"
dns_listen:   "127.0.0.1:15353"
api_listen:   "127.0.0.1:9191"
rule_paths:
  - rules/ai_chat_blocked.txt    # Tier 3 — DNS block
  - rules/ai_chat_dlp.txt        # Tier 2 — inspect with DLP
  - rules/ai_allowed.txt         # Tier 1 — pass through
dlp_patterns:   rules/dlp_patterns.json
dlp_exclusions: rules/dlp_exclusions.json
```

```bash
# Test the DLP pipeline
$ curl -s -X POST http://127.0.0.1:9191/api/dlp/scan \
    -H 'Content-Type: application/json' \
    -d '{"content":"AKIAIOSFODNN7EXAMPLE is my real key"}'
{"blocked":true,"pattern_name":"aws_access_key_id","score":0.95}

$ curl -s -X POST http://127.0.0.1:9191/api/dlp/scan \
    -H 'Content-Type: application/json' \
    -d '{"content":"hello, what is the weather"}'
{"blocked":false,"pattern_name":"","score":0.0}
```

No per-event log written. Counters tick: `dlp_scans_total++` and `dlp_blocks_total++`.

</div>

<div class="se-section" markdown>

## How it works

``` mermaid
flowchart LR
    U["👤 User"] -->|paste / form / fetch| EXT["Browser<br>Companion"]
    U -->|HTTP via system proxy| PRX["MITM Proxy<br>(Tier-2 only)"]
    EXT -->|/api/dlp/scan| AGENT
    PRX -->|in-process| AGENT
    APP["🖥 Other apps"] -->|DNS query| DNS["DNS Resolver<br>:53"]
    DNS --> AGENT
    subgraph AGENT [" Prompt Gate Agent "]
        direction LR
        POL["Policy Engine<br>Tier 1-4"]
        DLP["DLP Pipeline<br>5 stages"]
        STATS["Aggregate<br>Counters"]
        POL --> DLP --> STATS
    end
    AGENT -->|Allow| OUT["☁️ Cloud AI"]
    AGENT -->|Block| X["⛔ NXDOMAIN<br>or 403"]
```

Every layer is optional. DNS alone gives you allow-listed AI. Add the extension for content inspection on approved hosts. Add the MITM proxy if you need non-browser coverage. Add a signed enterprise profile to lock policy across a fleet.

</div>

<div class="se-section" markdown>

## Components

<div class="se-cards">
<a class="se-card" data-pkg="dlp" href="dlp-pattern-authoring-guide/">
<span class="se-card-icon">🛡️</span>
<span class="se-card-body"><span class="se-card-title">DLP Pipeline</span>
<span class="se-card-desc">5 stages: classifier · Aho-Corasick · regex · scoring · threshold. 165 patterns, &lt;1ms.</span></span>
</a>
<a class="se-card" data-pkg="dns" href="admin-guide/">
<span class="se-card-icon">🌐</span>
<span class="se-card-body"><span class="se-card-title">DNS Resolver</span>
<span class="se-card-desc">O(1) rule lookup. NXDOMAIN on Tier 3/4. Forward + counter for Tier 1/2.</span></span>
</a>
<a class="se-card" data-pkg="api" href="https://github.com/ShieldNet-360/prompt-gate/blob/main/ARCHITECTURE.md">
<span class="se-card-icon">⚡</span>
<span class="se-card-body"><span class="se-card-title">HTTP API</span>
<span class="se-card-desc">Loopback-only, Origin allowlist, optional Bearer token. /api/{status,dlp,policies,proxy,profile}.</span></span>
</a>
<a class="se-card" data-pkg="proxy" href="admin-guide/">
<span class="se-card-icon">🔐</span>
<span class="se-card-body"><span class="se-card-title">MITM Proxy</span>
<span class="se-card-desc">Per-device ECDSA CA. Decrypts only Tier-2 hosts; tunnels everything else opaquely.</span></span>
</a>
<a class="se-card" data-pkg="policy" href="admin-guide/">
<span class="se-card-icon">📜</span>
<span class="se-card-body"><span class="se-card-title">Policy Engine</span>
<span class="se-card-desc">4 tiers per category. Profile-locked under managed mode (403 on policy edits).</span></span>
</a>
<a class="se-card" data-pkg="rules" href="rule-contribution-guide/">
<span class="se-card-icon">📚</span>
<span class="se-card-body"><span class="se-card-title">Rule Engine</span>
<span class="se-card-desc">Ed25519-verified manifest updates. Atomic temp-file rename. Hot-reload.</span></span>
</a>
<a class="se-card" data-pkg="tamper" href="https://github.com/ShieldNet-360/prompt-gate/blob/main/ARCHITECTURE.md">
<span class="se-card-icon">🛰️</span>
<span class="se-card-body"><span class="se-card-title">Tamper Detector</span>
<span class="se-card-desc">DNS / proxy probes per OS. Bumps counter on transitions only; no event log.</span></span>
</a>
<a class="se-card" data-pkg="extension" href="user-guide/">
<span class="se-card-icon">🧩</span>
<span class="se-card-body"><span class="se-card-title">Browser Companion</span>
<span class="se-card-desc">Manifest V3 for Chrome / Firefox / Safari. Catches paste, form, fetch, drag, clipboard.</span></span>
</a>
</div>
</div>

<div class="se-section" markdown>

## Platforms

| OS / Browser | Package | Install |
|---|---|---|
| 🍏 **macOS** | `.pkg` (notarized at v1.0) | `bash scripts/macos/build-pkg.sh` |
| 🐧 **Linux** | `.deb` + `.rpm` | `bash scripts/linux/build-packages.sh` |
| 🪟 **Windows** | `.msi` (Authenticode at v1.0) | `pwsh scripts/windows/build-msi.ps1` |
| 🌐 **Chrome / Edge** | MV3 extension | Load `extension/dist` unpacked, or Web Store at v1.0 |
| 🦊 **Firefox** | MV3 extension | Load `extension/dist` temporary, or AMO at v1.0 |
| 🧭 **Safari** | MV3 extension | Bundled via Xcode wrapper (planned v1.1) |

</div>

<div class="se-section" markdown>

## Configuration presets

Three enforcement modes ship in the repo root. Pick one, edit, deploy.

| Preset | Default action | Override policy | Tamper response | Audience |
|---|---|---|---|---|
| `config.personal.example.yaml` | Allow + DLP | Editable in tray UI | Counter only | Individuals |
| `config.team.example.yaml`     | Block + DLP | Editable, ephemeral | Counter + tray balloon | Small teams |
| `config.managed.example.yaml`  | Block + DLP | **Locked by Ed25519 profile** | Counter + heartbeat (opt-in) | Enterprise / MDM |

</div>

<div class="se-section" markdown>

## Privacy invariant

Three things persist on disk. Nothing else.

```
✓ Policy configuration       ← what categories are allowed / blocked
✓ Aggregate counters         ← integers: dns_queries_total, dlp_blocks_total, …
✓ Rule files                 ← domain lists + DLP patterns
✗ Domain names               ← NEVER
✗ URLs                       ← NEVER
✗ IP addresses               ← NEVER
✗ User identifiers           ← NEVER
✗ Per-event timestamps       ← NEVER
✗ Scanned content            ← NEVER (in-memory only, GC'd post-scan)
```

Enforced by `agent/internal/store/privacy_test.go` — a CI test that sweeps every text column of the SQLite database and asserts these values cannot reach disk.

</div>

<div class="se-section" markdown>

## Scope vs adjacent tooling

| Question | Prompt Gate | Microsoft [AGT](https://github.com/microsoft/agent-governance-toolkit) | Network DLP |
|---|---|---|---|
| Subject | Human user | Autonomous agent | Traffic |
| Enforcement layer | DNS + browser ext + MITM | Function-call wrapper | Network gateway |
| Sees inside browser-pinned TLS | ✅ via MITM | n/a | ❌ |
| Privacy of users | **No per-event log** | Tamper-evident audit | Full session log |
| Best for | Endpoint, BYOD | Agent fleets | Egress monitoring |

Most teams will run **both** Prompt Gate (human → cloud AI) and AGT (agent → tools). See [the comparison doc](https://github.com/ShieldNet-360/prompt-gate/blob/main/ARCHITECTURE.md) for the full breakdown.

</div>

<div class="se-section" markdown>

## Standards alignment

| Standard | Coverage |
|---|---|
| [OWASP Agentic AI Top 10](https://owasp.org/www-project-agentic-ai-top-10/) | **Endpoint slice** — ASI-02 (Tool Misuse, outbound) and ASI-06 (Context Poisoning, paste-time). Full agent-runtime coverage is out of scope; pair with [AGT](https://github.com/microsoft/agent-governance-toolkit). |
| GDPR (privacy-by-design) | No per-event PII persisted; column-sweep CI test enforces invariant. |
| MIT License | Free to fork, embed, and ship in commercial products. |
| SBOM | Generated per release (planned v1.0). |

</div>

<div class="se-section" markdown>

## Verify a release

Every release artifact ships with a Sigstore-backed SLSA build provenance attestation and a `SHA256SUMS` file — no long-lived signing key to trust.

```bash
# provenance: confirms the binary was built by this repo's Release workflow
gh attestation verify prompt-gate-agent-darwin-arm64 --repo ShieldNet-360/prompt-gate

# integrity
sha256sum --check SHA256SUMS
```

See [Verifying releases](verifying-releases/) for the full story.

</div>

<div class="se-section" markdown>

## Engineering reports & foundations

Every number below is regenerated from tests — not hand-entered.

<div class="se-cards">
<a class="se-card" href="whitepaper/">
<span class="se-card-icon">📐</span>
<span class="se-card-body"><span class="se-card-title">Whitepaper & Math</span>
<span class="se-card-desc">Engine design: normalization, Aho-Corasick complexity, Shannon entropy, scoring/threshold model, precision/recall.</span></span>
</a>
<a class="se-card" href="reports/qa/">
<span class="se-card-icon">✅</span>
<span class="se-card-body"><span class="se-card-title">Test & QA</span>
<span class="se-card-desc">15 packages passing under -race, 55.8% total / 86.9% engine coverage, vet + staticcheck.</span></span>
</a>
<a class="se-card" href="reports/performance/">
<span class="se-card-icon">⚡</span>
<span class="se-card-body"><span class="se-card-title">Performance & Stress</span>
<span class="se-card-desc">15.9µs/scan, 40.8 MB/s on large inputs, ~537k fuzz execs with 0 crashers.</span></span>
</a>
<a class="se-card" href="reports/security/">
<span class="se-card-icon">🔐</span>
<span class="se-card-body"><span class="se-card-title">Security</span>
<span class="se-card-desc">0 reachable vulns, 100% precision / 0% FP, adversarial-evasion + privacy-invariant proofs.</span></span>
</a>
</div>

</div>

<div class="se-section" markdown>

## Get involved

Prompt Gate is open source under the MIT license and built in the open.

<div class="se-hero-badges">
  <a href="https://github.com/ShieldNet-360/prompt-gate">⭐ Star on GitHub</a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/releases/latest">⬇️ Download v1.1.1</a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/blob/main/CONTRIBUTING.md">🤝 Contribute</a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/issues">🐛 Report an issue</a>
  <a href="https://github.com/ShieldNet-360/prompt-gate/security/policy">🔐 Security policy</a>
</div>

- **Add a DLP pattern** — see the [pattern authoring guide](dlp-pattern-authoring-guide/).
- **Harden a platform** — packaging scripts live under `scripts/{macos,linux,windows}`.
- **Found a vulnerability?** — please follow the [security policy](https://github.com/ShieldNet-360/prompt-gate/security/policy) for coordinated disclosure.

</div>
