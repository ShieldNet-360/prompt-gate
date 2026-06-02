# Prompt Gate

<!-- Build & quality -->
[![CI](https://github.com/ShieldNet-360/prompt-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/ShieldNet-360/prompt-gate/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ShieldNet-360/prompt-gate)](https://goreportcard.com/report/github.com/ShieldNet-360/prompt-gate)
[![Coverage: agent/internal/dlp ≥ 80%](https://img.shields.io/badge/coverage-%E2%89%A580%25-brightgreen)](./.github/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ShieldNet-360/prompt-gate/agent.svg)](https://pkg.go.dev/github.com/ShieldNet-360/prompt-gate/agent)
[![Docs](https://img.shields.io/badge/docs-online-blue)](https://shieldnet-360.github.io/prompt-gate/)
<!-- Supply-chain & process -->
[![CodeQL](https://github.com/ShieldNet-360/prompt-gate/actions/workflows/codeql.yml/badge.svg)](https://github.com/ShieldNet-360/prompt-gate/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ShieldNet-360/prompt-gate/badge)](https://scorecard.dev/viewer/?uri=github.com/ShieldNet-360/prompt-gate)
[![SLSA Provenance](https://img.shields.io/badge/SLSA-build%20provenance-2b6cb0)](./docs/verifying-releases.md)
[![Signed with Sigstore](https://img.shields.io/badge/signed-Sigstore-0a84ff)](./docs/verifying-releases.md)
[![Reproducible build](https://img.shields.io/badge/agent%20build-reproducible-2b6cb0)](https://shieldnet-360.github.io/prompt-gate/reproducible-builds/)
[![Tests](https://img.shields.io/badge/tests-15%20packages%20passing-brightgreen)](https://shieldnet-360.github.io/prompt-gate/reports/qa/)
[![Vulnerabilities](https://img.shields.io/badge/govulncheck-0-brightgreen)](https://shieldnet-360.github.io/prompt-gate/reports/security/)
[![DLP precision](https://img.shields.io/badge/DLP%20precision-100%25-brightgreen)](https://shieldnet-360.github.io/prompt-gate/reports/security/)
[![Whitepaper](https://img.shields.io/badge/whitepaper-engine%20math-7c3aed)](https://shieldnet-360.github.io/prompt-gate/whitepaper/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13075/badge)](https://www.bestpractices.dev/projects/13075)
<!-- Release & meta -->
[![Latest release](https://img.shields.io/github/v/release/ShieldNet-360/prompt-gate?sort=semver)](https://github.com/ShieldNet-360/prompt-gate/releases)
[![Downloads](https://img.shields.io/github/downloads/ShieldNet-360/prompt-gate/total)](https://github.com/ShieldNet-360/prompt-gate/releases)
[![Stars](https://img.shields.io/github/stars/ShieldNet-360/prompt-gate?style=flat)](https://github.com/ShieldNet-360/prompt-gate/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Platform: macOS | Windows | Linux](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-blue)](https://github.com/ShieldNet-360/prompt-gate/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/ShieldNet-360/prompt-gate?filename=agent%2Fgo.mod)](agent/go.mod)
[![Privacy: zero data persisted](https://img.shields.io/badge/privacy-zero%20data%20persisted-14b8a6)](./docs/PRIVACY-AUDIT.md)

**Open-source, privacy-first AI Data Leakage Prevention for desktop.**

Most secret scanners stop at "does this look like an AWS key." Secure
Edge starts there and keeps going — it normalises away the tricks a
human or LLM uses to sneak a secret past a regex, scores matches
against where they're going, and lets the user say "never block
this specific value again" without sending anything off-device.

Try it in 30 seconds:

```bash
go install github.com/ShieldNet-360/prompt-gate/agent/cmd/prompt-gate@latest
echo "leaked: AKIA9P2QRMZNL5CVXBT4" | prompt-gate scan
```

```json
{
  "blocked": true,
  "pattern_name": "AWS Access Key",
  "score": 2
}
```

Now the same value with a single Cyrillic **А** swapped in (looks
identical to your eye, invisible to a naive regex):

```bash
printf 'leaked: \xd0\x90KIA9P2QRMZNL5CVXBT4\n' | prompt-gate scan
```

```json
{
  "blocked": true,
  "pattern_name": "AWS Access Key",
  "score": 2
}
```

Still caught. The normaliser folds ~50 Cyrillic and Greek
homoglyphs to Latin ASCII, strips zero-width characters, decodes
inline base64, and runs NFKC — all before the pattern matcher
sees the input.

### Bench (real source code)

On 1,000,000 lines of source code sampled from a real `~/Developer`
directory (5,676 files across Go / Python / TS / Java / YAML /
Terraform / JSON / Markdown), the layered scoring delivers
measurable FP reduction over a regex-only baseline. We report two
numbers, because the source-context `code_host: −2` bias depends on
where the content is going:

| Generation | Total blocks | Δ vs prev | p50 latency |
|---|--:|--:|--:|
| regex baseline                     | 211 | — | 23 µs |
| + accuracy layers                  | 206 | — | 23 µs |
| + source-context bias, **realistic destination mix** | **161** | **−22 %** | **37 µs** |
| + source-context bias, worst-case (every line `code_host`) | **41** | **−80 %** | 36 µs |

The **realistic-mix** number is what production actually feels:
destinations sampled 40 % `ai_chat`, 30 % `code_host`, 20 %
`ai_code`, 10 % programmatic exfil. The **worst-case** number is
the ceiling under the assumption that every paste goes to GitHub.
About 75 % of the worst-case 80 % was bench artifact — the
source-context bias only fires when the paste target is a code host, and in real
production that's one destination among several.

Reproduce with `agent/cmd/dlp-bench --destination-mix=realistic`;
full snapshot + per-pattern breakdown + methodology lives in
[BENCHMARKS.md](./BENCHMARKS.md).

### The product

Prompt Gate is more than the CLI above. It's a cross-platform
desktop agent (Windows, macOS, Linux) that blocks unauthorised AI
tools at the DNS level and inspects content sent to approved AI
tools via the same layered DLP pipeline. Content reaches the
pipeline through a Chrome/Firefox/Safari browser extension or, for
non-browser traffic, an optional local MITM proxy that decrypts
only Tier-2 domains and tunnels everything else opaquely. It runs
as a minimal system-tray app, consumes negligible CPU and memory,
and **logs nothing** about user access — only running aggregate
counters.

The DLP pipeline pairs an Aho-Corasick + regex deterministic core
with four accuracy layers — adversary-resistant normalisation,
a per-tab multi-piece correlator, a public-example bloom,
and a placeholder-shape router — and source-context bias layers
(destination bias, path bias, and an opt-in feedback allowlist).
The launch-day benchmark over the
in-repo FP corpus is **precision 100 % / recall 73 % / FP rate 0 %**
at under 1 ms per scan with no ML dependency.

## Privacy First

The agent stores only:

- **Policy configuration** — which categories are allowed, inspected, or blocked
- **Anonymous aggregate counters** — `dns_queries_total`, `dns_blocks_total`,
  `dlp_scans_total`, `dlp_blocks_total` (integers only, no per-event timestamps)
- **Rule files** — domain lists and DLP patterns

No domain names, URLs, IP addresses, user identifiers, or per-event timestamps are ever written
to disk. DLP block notifications are shown in real time and discarded. The
[`store/privacy_test.go`](./agent/internal/store/privacy_test.go) test sweeps every text column
in the SQLite database and asserts none of those values reach disk.

## Policy Tiers

| Tier | Action | Mechanism |
|------|--------|-----------|
| 1 | Allow | Pass-through, no inspection |
| 2 | Allow + DLP | Forwarded, inspected by the layered DLP pipeline |
| 3 | Block (AI) | DNS resolver returns NXDOMAIN |
| 4 | Block (Other) | DNS resolver returns NXDOMAIN |

## Quick Start

```bash
git clone https://github.com/ShieldNet-360/prompt-gate.git
cd prompt-gate

# Build and run the Go agent (DNS listener + local API on 127.0.0.1:9191).
cd agent
make build
./prompt-gate-agent --config ../config.yaml      # or omit --config for defaults

# In a second shell, install and run the Electron tray app.
cd electron
npm install
npm run build
npm start
```

The default `dns_listen` port is `127.0.0.1:15353` — no `sudo` required.

Example `config.yaml`:

```yaml
upstream_dns: "8.8.8.8:53"
dns_listen: "127.0.0.1:15353"
api_listen: "127.0.0.1:9191"
db_path: "prompt-gate.db"
stats_flush_interval: 60s
rule_paths:
  - rules/ai_chat_blocked.txt
  - rules/ai_code_blocked.txt
  - rules/ai_allowed.txt
  - rules/ai_chat_dlp.txt
  - rules/phishing.txt
  - rules/social.txt
  - rules/news.txt
dlp_patterns: rules/dlp_patterns.json     # optional — enables /api/dlp/*
dlp_exclusions: rules/dlp_exclusions.json # optional

# Rule updater. Leaving rule_update_url blank disables the
# updater; everything else (DNS, policies, DLP) keeps working.
rule_update_url: ""                       # e.g. https://example.com/manifest.json
rule_update_interval: 6h                  # cadence; default 6h
rules_dir: rules                          # output dir for downloaded rule files

# Local MITM proxy. proxy_enabled=false (default) leaves the
# listener stopped — /api/proxy/enable can start it at runtime.
proxy_listen: "127.0.0.1:8443"
proxy_enabled: false
ca_cert_path: ""                          # default ~/.prompt-gate/ca.crt
ca_key_path: ""                           # default ~/.prompt-gate/ca.key
proxy_pinning_bypass: []                  # hostnames to tunnel even if Tier-2
                                          # (e.g. apps that pin a specific CA)

# DLP engine tuning. Omitting a field keeps the built-in default.
# large_content_threshold: 51200   # bytes; skip low/medium patterns above this
# dlp_cache_ttl_seconds: 5         # 0 disables the scan-result cache
# dlp_cache_capacity: 256          # max cache entries
# dlp_rate_limit_per_sec: 100      # 0 disables the /api/dlp/scan rate limiter
# dlp_disabled_categories: []      # e.g. ["PII"] to disable a category

# Agent self-update. Both fields required to enable.
# agent_update_manifest_url: ""    # e.g. https://github.com/.../manifest.json
# agent_update_public_key: ""      # hex-encoded Ed25519 public key
```

Leaving `dlp_patterns` blank disables the DLP pipeline and returns `503` from
the `/api/dlp/*` endpoints; everything else (DNS, policies, stats) keeps
working. Likewise, leaving `rule_update_url` blank returns `503` from
`/api/rules/*`.

## Project Structure

```
prompt-gate/
├── README.md            ARCHITECTURE.md  CHANGELOG.md
├── CONTRIBUTING.md      SECURITY.md  SECURITY_RULES.md  LICENSE
├── ROADMAP.md           GOVERNANCE.md  SUPPORT.md
├── agent/                            # Go backend (single static binary)
│   ├── cmd/agent/main.go
│   ├── internal/
│   │   ├── api/                      # HTTP API server + handlers + ratelimit.go (token bucket)
│   │   ├── config/                   # YAML configuration loader
│   │   ├── dlp/                      # Layered DLP pipeline + cache.go (LRU)
│   │   │                             #   + normalize.go / correlator.go
│   │   │                             #   / bloom.go / codecontext.go
│   │   │                             #   + testdata/fp_corpus/ + fp_corpus_test.go
│   │   ├── dns/                      # Embedded DNS resolver (miekg/dns)
│   │   ├── heartbeat/                # Optional outbound heartbeat
│   │   ├── policy/                   # Policy engine
│   │   ├── profile/                  # Enterprise profile loader + lock
│   │   ├── proxy/                    # Selective MITM proxy
│   │   ├── rules/                    # Rule-file parser + lookup + updater + admin override
│   │   ├── stats/                    # Anonymous aggregate counters
│   │   ├── store/                    # SQLite (modernc.org/sqlite, WAL)
│   │   ├── tamper/                   # OS DNS/proxy tamper detector
│   │   └── updater/                  # Agent self-update
│   ├── nfpm.yaml                     # .deb packaging
│   ├── scripts/{post,pre}*.sh
│   ├── go.mod / go.sum
│   └── Makefile                      # build / test / lint targets
├── electron/                         # System-tray app (Electron + React)
│   ├── main.ts                       # Tray icon, health polling, BrowserWindow
│   ├── preload.ts                    # Secure contextBridge
│   ├── src/
│   │   ├── pages/{Settings,Status,ProxySettings,Rules,Setup}.tsx
│   │   ├── components/{CategoryToggle,StatsCard}.tsx
│   │   └── api/agent.ts              # HTTP client for the Go agent
│   ├── package.json
│   └── electron-builder.yml
├── extension/                        # Chrome / Firefox / Safari Manifest V3 companion
│   ├── manifest.json                 # Chrome MV3
│   ├── manifest.firefox.json         # Firefox MV3 (browser_specific_settings)
│   ├── manifest.safari.json          # Safari Web Extension (wrapped via xcrun)
│   ├── native-messaging/             # Native Messaging host manifest + installers
│   ├── src/
│   │   ├── background/               # service-worker.ts, native-messaging.ts, dynamic-hosts.ts
│   │   ├── content/                  # paste-, form-, network-, drag-, clipboard-* interceptors + scan-client.ts + toast.ts
│   │   ├── options/                  # Extension options page
│   │   └── popup/                    # Toolbar popup status UI
│   ├── tests/integration/            # Playwright smoke tests
│   ├── scripts/{build-firefox,build-safari}.mjs
│   ├── package.json
│   └── tsconfig.json
├── rules/                            # Bundled domain lists + DLP rules
│   ├── ai_chat_blocked.txt   ai_chat_dlp.txt   ai_code_blocked.txt
│   ├── ai_allowed.txt        phishing.txt      social.txt
│   ├── news.txt              manifest.json
│   ├── dlp_patterns.json
│   └── dlp_exclusions.json
├── docs/                             # Operator + contributor documentation
│   ├── admin-guide.md
│   ├── user-guide.md
│   ├── rule-contribution-guide.md
│   ├── dlp-pattern-authoring-guide.md
│   └── accessibility.md
├── scripts/                          # Platform install / DNS / proxy scripts
│   ├── macos/                        # build-pkg.sh, postinstall.sh, uninstall.sh,
│   │                                 # configure-dns.sh, install-ca.sh,
│   │                                 # configure-proxy.sh,
│   │                                 # com.shieldnet360.promptgate.plist
│   ├── windows/                      # prompt-gate.wxs, build-msi.ps1,
│   │                                 # postinstall.ps1, uninstall.ps1,
│   │                                 # configure-dns.ps1, register-service.ps1,
│   │                                 # install-ca.ps1, configure-proxy.ps1
│   └── linux/                        # build-packages.sh, postinstall.sh,
│                                     # preremove.sh, uninstall.sh,
│                                     # configure-dns.sh, install-ca.sh,
│                                     # configure-proxy.sh, prompt-gate.service
└── .github/
    ├── ISSUE_TEMPLATE/               # bug_report.md + feature_request.md
    ├── PULL_REQUEST_TEMPLATE.md
    └── workflows/
        ├── ci.yml                    # Go + Electron + extension typecheck + tests
        └── release.yml               # multi-arch builds + GitHub Release on tags
```

## API

Local HTTP API on `127.0.0.1:9191` (configurable):

| Method | Path                       | Description |
|--------|----------------------------|-------------|
| GET    | `/api/status`              | Agent status, uptime, version, Go runtime stats, DLP pattern count, rule file mtimes |
| GET    | `/api/policies`            | List `[category, action]` rows |
| PUT    | `/api/policies/:category`  | Update an action; triggers policy reload |
| GET    | `/api/stats`               | Aggregate counters (integers only) |
| POST   | `/api/stats/reset`         | Reset all counters to zero |
| POST   | `/api/dlp/scan`            | Scan `{content, session_id?}` through the DLP pipeline; returns `{blocked, pattern_name, score}`. When `session_id` is supplied (the browser extension generates a per-tab opaque UUID), the correlator reassembles secrets split across consecutive pastes in the same tab. Content is processed in memory and never persisted. |
| GET    | `/api/dlp/config`          | Current DLP scoring weights and per-severity thresholds |
| PUT    | `/api/dlp/config`          | Update DLP scoring weights and thresholds |
| POST   | `/api/rules/update`        | Trigger an immediate rule-manifest check; returns `{updated, version, files_downloaded}` |
| GET    | `/api/rules/status`        | Current rule version + last/next check time + manifest URL |
| POST   | `/api/proxy/enable`        | Generate the per-device CA if missing and start the local MITM proxy; returns `{ca_cert_path}` for OS trust install |
| POST   | `/api/proxy/disable`       | Stop the local MITM proxy; pass `{"remove_ca": true}` to also delete the CA files |
| GET    | `/api/proxy/status`        | `{running, ca_installed, listen_addr, dlp_scans_total, dlp_blocks_total}` |
| GET    | `/api/profile`             | Current enterprise profile, or 404 if none is loaded |
| POST   | `/api/profile/import`      | Import a profile from `{url}` or `{profile}` body and apply it; locks local policy edits when `managed=true` |
| GET    | `/api/tamper/status`       | `{dns_ok, proxy_ok, last_check, detections_total}` from the tamper detector |
| GET    | `/api/stats/export`        | Downloadable JSON envelope `{agent_version, os_type, os_arch, exported_at, stats}` |
| GET    | `/api/rules/override`      | List the admin allow/block override sets |
| POST   | `/api/rules/override`      | Add `{domain, list:"allow"\|"block"}` to the override store; moves between lists if needed |
| DELETE | `/api/rules/override/:domain` | Remove an override regardless of list |
| GET    | `/api/agent/update-check`  | Check whether a newer agent release is published on the configured manifest channel. Returns 503 when no updater is wired. |
| POST   | `/api/agent/update`        | Download the latest agent release, verify its SHA-256 + Ed25519 signature, and stage it for restart. |

`action` is one of `allow`, `allow_with_dlp`, `deny`.

The DLP endpoints return `503 Service Unavailable` when the agent is started
without a `dlp_patterns` config entry (DNS-only deployments). The `/api/rules/*`
endpoints return `503` when `rule_update_url` is blank. The `/api/proxy/*`
endpoints return `503` when the proxy controller has not been configured (e.g.
agents built without `proxy_listen`).

The extension prefers to reach the agent through Chrome Native Messaging
(no CORS, survives air-gapped networks) and falls back to direct HTTP to
`127.0.0.1:9191` when the native host is unavailable. Install the host
manifest with `extension/native-messaging/install.sh` (macOS/Linux) or
`install.ps1` (Windows). Safari Web Extensions have no Native Messaging,
so the Safari port uses the HTTP fallback exclusively; the agent's CORS
allowlist accepts `chrome-extension://`, `moz-extension://`, and
`safari-web-extension://` origins.

## Enterprise Features

Optional features for managed deployments — every one of them
honours the same privacy invariant as the base agent.

- **Configuration profiles.** Set `profile_path` or `profile_url` in
  `config.yaml`; the JSON profile (`name`, `version`, `managed`,
  `categories`, `dlp`) is applied on startup. When `managed=true`,
  `PUT /api/policies/:category` and `PUT /api/dlp/config` return
  `403 Forbidden` and the Electron settings UI disables every input.
- **Tamper detection.** Background goroutine (default 60s) checks
  that OS DNS still points at the agent and, when the local MITM
  proxy is enabled, that the system proxy still points at
  `127.0.0.1:8443`. Transitions bump `tamper_detections_total` in
  the existing `aggregate_stats` row; the tray surfaces an
  ephemeral balloon — *no* per-event log on disk.
- **Optional heartbeat.** Set `heartbeat_url` to enable. Payload is
  exactly `{agent_version, os_type, os_arch, aggregate_counters}`
  — no URL, domain, IP, or DLP-match data is ever serialised. Tests
  in `agent/internal/heartbeat/heartbeat_test.go` assert this on
  the JSON wire format.
- **Admin overrides.** Drop files into `rules/local/` (allow.txt,
  block.txt, dlp_patterns_override.json, dlp_exclusions_override.json)
  to add company-specific rules without touching bundled files. The
  Electron Settings page has an allow/block UI that writes through
  `POST /api/rules/override` and DLP threshold sliders that hit
  `PUT /api/dlp/config`.
- **Stats export.** `GET /api/stats/export` returns the counter
  snapshot with a `Content-Disposition: attachment` envelope —
  counters only, no access data.

## Testing

```bash
cd agent
make test                 # runs `go test -race ./...`, includes DLP + proxy unit + integration tests
make lint                 # runs `go vet ./...`
make dlp-bench            # runs TestFPCorpus and prints precision / recall / F1 / FP rate
                          # against agent/internal/dlp/testdata/fp_corpus/

cd ../electron
npm run typecheck         # TypeScript strict mode against renderer + main

cd ../extension
npm install && npm run typecheck   # browser-extension Manifest V3 typecheck
npm test                            # node --test on content + background scripts
npm run build:firefox               # Firefox bundle in dist-firefox/
npm run build:safari                # Safari Web Extension (macOS-only; uses xcrun)
```

DLP coverage includes one `*_test.go` per pipeline component
(`classifier`, `ahocorasick`, `regex`, `hotword`, `entropy`, `exclusion`,
`scorer`, `threshold`) plus a `pipeline_test.go` integration test exercising
real AWS keys with hotword context (block), the AWS docs example key
`AKIAIOSFODNN7EXAMPLE` (exclude), benign prose (allow), empty content, and
large content embedding a real-looking key.

The enterprise-feature tests live alongside their packages: `profile/`,
`tamper/`, `heartbeat/`, and `rules/override_test.go` / `dlp/override_test.go`
verify the loader-lock interaction, platform-isolated tamper probes
(via build tags), the heartbeat payload shape (assertion: no access /
domain / IP / DLP-match fields ever leak), and admin override
merging without corrupting bundled rules. Performance benchmarks
for the DLP pipeline, DNS resolver, and stats counter live in
`*_bench_test.go` files — see [BENCHMARKS.md](./BENCHMARKS.md).

The accuracy layers add `bloom_test.go`, `codecontext_test.go`,
`normalize_test.go`, `correlator_test.go`, and
`fp_corpus_test.go` (precision / recall / F1 / FP rate against the
labelled corpus under `agent/internal/dlp/testdata/fp_corpus/`). The
FP-corpus test gates CI at `precision ≥ 90 %` and `recall ≥ 60 %`;
launch-day measurement is precision 100 %, recall 73 %, FP rate 0 %.

## DLP Coverage

Prompt Gate ships **163** real-world detection patterns across **13**
JSON categories: cloud providers (AWS, Azure, GCP, Google Services),
cloud infrastructure (Cloudflare, DigitalOcean, Vercel, Netlify,
Supabase, Pulumi, Helm, Terraform, Docker, K8s), version control
(GitHub, GitLab, Bitbucket), AI/ML platforms (OpenAI, Anthropic,
HuggingFace, Cohere, Replicate, Pinecone, Mistral, W&B, LangSmith,
Together, Groq), payment processors (Stripe, PayPal, Square,
Braintree, Adyen, Plaid, Coinbase), CI/CD (CircleCI, Travis,
Jenkins), messaging (Slack, Discord, Telegram, Twilio, SendGrid,
Vonage, Mailchimp), auth/identity (Auth0, Okta, OneLogin, Keycloak,
Firebase Admin, Supabase JWT, Clerk), language ecosystems (Java,
Rust, JS/TS, Swift, Kotlin, Dart, Go, Python), mobile (iOS APNs,
Android signing, Flutter / React Native), databases (Postgres,
MySQL, MongoDB, Redis, MSSQL, SQLite, Cassandra, Elasticsearch),
PEM/private keys, JWTs, generic password-in-code, and PII (SSN,
credit cards, emails, phones).

See [SECURITY_RULES.md](./SECURITY_RULES.md) for the complete per-pattern
table (name, severity, prefix, hotword requirement).

## Documentation

**Architecture & reference**

- [FAQ.md](./FAQ.md) — why was my request blocked, and how to send troubleshooting questions safely (mask secrets with `[PLACEHOLDER]`)
- [ARCHITECTURE.md](./ARCHITECTURE.md) — components, DB schema, API, integration
- [CHANGELOG.md](./CHANGELOG.md) — release-by-release summary
- [CONTRIBUTING.md](./CONTRIBUTING.md) — development setup, PR process, coding standards
- [SECURITY.md](./SECURITY.md) — responsible-disclosure policy
- [ROADMAP.md](./ROADMAP.md) — product & engineering direction
- [GOVERNANCE.md](./GOVERNANCE.md) — roles, decision-making, becoming a maintainer
- [SUPPORT.md](./SUPPORT.md) — where to get help
- [BENCHMARKS.md](./BENCHMARKS.md) — DLP pipeline, DNS resolver, and stats counter benchmarks
- [SECURITY_RULES.md](./SECURITY_RULES.md) — per-pattern reference table
- [docs/admin-guide.md](./docs/admin-guide.md) — installation, configuration, profiles, overrides
- [docs/user-guide.md](./docs/user-guide.md) — what the tray icon means, false-positive reporting, privacy summary
- [docs/rule-contribution-guide.md](./docs/rule-contribution-guide.md) — how to add domains and categories
- [docs/dlp-pattern-authoring-guide.md](./docs/dlp-pattern-authoring-guide.md) — DLP schema, scoring, hotwords, entropy, exclusions
- [docs/accessibility.md](./docs/accessibility.md) — Electron UI accessibility audit + verification steps

## Contributing

Contributions are welcome under the MIT license. See [CONTRIBUTING.md](./CONTRIBUTING.md)
for development setup, the PR process, coding standards, and test requirements.

Good first contributions:

- **Rule lists** — add domains (one per line, leading `.` for "include subdomains") to
  `rules/*.txt`.
- **DLP patterns / exclusions** — `rules/dlp_patterns.json`, `rules/dlp_exclusions.json`.
- **Bug reports** — use the GitHub Issues template at
  [`.github/ISSUE_TEMPLATE/bug_report.md`](./.github/ISSUE_TEMPLATE/bug_report.md).

Report security vulnerabilities via the process in [SECURITY.md](./SECURITY.md) — please
do not file public issues for security reports.

## License

[MIT](./LICENSE)
