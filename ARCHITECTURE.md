# Prompt Gate — Technical Architecture

## System Overview

```
┌─────────────────────────── Desktop Agent ────────────────────────────┐
│                                                                       │
│   ┌──────────────────┐  HTTP localhost  ┌──────────────────────┐     │
│   │ Electron Tray UI │ ───────────────► │  Go Backend Service  │     │
│   └──────────────────┘                  └──────────┬───────────┘     │
│                                                    ▼                  │
│                                          ┌────────────────────┐       │
│                                          │   Policy Engine    │       │
│                                          └─┬────────┬─────────┘       │
│                                            │        │                 │
│                                            ▼        ▼                 │
│                          ┌─────────────────────┐  ┌───────────────┐  │
│                          │  SQLite (config +   │  │ Rule Updater  │  │
│                          │   counters only)    │  │               │  │
│                          └─────────────────────┘  └───┬───────┬───┘  │
│                                                       │       │      │
│                                       HTTPS GET ◄─────┘       │ or   │
│                                  GitHub Releases / CDN        │      │
│                                                               ▼      │
│                                                    Local Rule Files  │
└───────────────────────────────────────────────────────────────────────┘

┌──── Layer 1 — DNS Blocking ────────────────────────────────────────┐
│   ┌────────────────────────┐                                       │
│   │ Embedded DNS Resolver  │ ◄── policy: NXDOMAIN for Tier 3+4    │
│   │       (miekg/dns)      │     policy: Forward   for Tier 1+2   │
│   └────────────────────────┘                                       │
└────────────────────────────────────────────────────────────────────┘

┌──── Layer 2 — DLP Inspection ──────────────────────────────────────┐
│   ┌───────────────────┐   Native Messaging                         │
│   │ Browser Extension │ ──────────────────►  Go Backend Service    │
│   │  (Chrome / FF /   │      (HTTP fallback)        │              │
│   │      Safari)      │                             ▼              │
│   └───────────────────┘                  ┌─────────────────────┐  │
│                                          │     DLP Scanner     │  │
│                                          │  (layered pipeline) │  │
│                                          └─────┬─────────┬─────┘  │
│                              score ≥ threshold │         │ below  │
│                                                ▼         ▼        │
│                              Block + ephemeral notify   Allow     │
└────────────────────────────────────────────────────────────────────┘

┌──── Layer 3 — MITM Proxy (optional) ───────────────────────────────┐
│   ┌─────────────────────────────────────┐                          │
│   │  Local MITM Proxy 127.0.0.1:8443    │                          │
│   │            (goproxy)                │                          │
│   └──────┬─────────────────────┬────────┘                          │
│   CONNECT, Tier-2:             │ CONNECT, non-Tier-2:              │
│   decrypt body ────► DLP       │ opaque tunnel ───► Policy Engine  │
│                       │                                            │
│                       ▼                                            │
│              Block on score (HTTP 451)                             │
└────────────────────────────────────────────────────────────────────┘
```

## Privacy Architecture

### Data Flow Principle: Process, Don't Persist

Every access event (DNS query, HTTP request, DLP scan) follows this flow:

```
                                  ┌─► allow ─────────────► Forward (no trace)
                                  │
   Incoming  ──► Policy check ────┼─► block ─────────────► Block + counter++
   request                        │                          dns_blocks++
                                  │                          (no domain stored)
                                  │
                                  └─► dlp scan ──► Layered DLP pipeline
                                                        │
                                       score below ◄────┤
                                       threshold        │
                                          │             ▼
                                          ▼      score above threshold
                                       Forward    │
                                                  ▼
                                          Block + ephemeral notify
                                          + counter++ dlp_blocks++
                                            (no content stored)
```

**Key invariant:** At no point in the default-config data flow is a
domain name, URL, IP address, or request content written to any
persistent storage (disk, database, log file). Counters are bare
integers. DLP scan content is processed in-memory and garbage-
collected immediately after the response is sent.

The invariant has **two carve-outs**, both documented in the privacy doc
and both gated:

1. **Feedback allowlist** (`dlp_allowlist`). Salted SHA-256
   hashes only; per-install salt at `~/.prompt-gate/allowlist-salt`
   (0600 perms) defeats cross-install lookup. Raw values touch
   memory only.
2. **Opt-in block_events history** (`block_events`). Records
   destination domain + pattern name + timestamp per block, but
   only when the user has explicitly toggled
   `agent_preferences.block_events_enabled = 1` via Settings →
   Privacy → "Enable history". Default OFF. The gate lives in
   `Store.InsertBlockEvent` so every present and future writer
   (proxy hot path, future transports, tests) inherits it
   automatically. Privacy tests
   (`TestPrivacy_DLPScanContentNotPersisted`,
   `TestPrivacy_BlockEventsRespectConsentGate`) exercise both
   halves of the gate. Enterprise profiles with `managed=true`
   reject `PUT /api/preferences/block-events` with 403, pinning
   the toggle.

### What Gets Stored (Exhaustive List)

```
SQLite Database (~8 KB default; ~32 KB with block_events at cap):
├── category_policies     # category → action mapping (e.g., "AI Chat" → "deny")
├── rulesets              # rule file metadata (name, type, path, category)
├── aggregate_stats       # dns_blocks_total: 142, dlp_blocks_total: 7, dns_queries_total: 50321
├── rule_versions         # manifest version string for update tracking
├── dlp_config            # threshold + scoring-weight tunables (singleton row)
├── dlp_allowlist         # salted SHA-256 of user-blessed values (feedback allowlist)
├── agent_preferences     # opt-in flags (singleton row; block_events default OFF)
└── block_events          # last-500 destination domains, ONLY when consent flag = 1

Per-install salt (~64 bytes, 0600 perms):
└── ~/.prompt-gate/allowlist-salt

Rule Files (~500 KB):
├── ai_chat_blocked.txt   # domain lists (these are the RULES, not access logs)
├── phishing.txt
├── dlp_patterns.json     # DLP patterns with hotwords, entropy thresholds, scoring weights
└── dlp_exclusions.json   # exclusion rules to suppress false positives

Configuration file (~1 KB):
└── config.yaml           # upstream DNS, ports, update URL
```

**There is no `alert_events` table. There is no log file. There is no
access history by default.** The `block_events` table exists in the
schema but is empty on a fresh install and stays empty until the
user opts in through the Settings → Privacy consent dialog.

## Component Details

### 1. Go Backend Service

The core of the agent. A single statically-compiled Go binary providing:

| Subsystem | Library | Purpose |
|-----------|---------|---------|
| DNS Resolver | `github.com/miekg/dns` | Listens on `127.0.0.1:15353`, resolves queries against policy engine |
| HTTP API | `net/http` (stdlib) | Local REST API on `127.0.0.1:{PORT}` for Electron UI and browser extension |
| SQLite Store | `modernc.org/sqlite` | Pure Go SQLite — stores policies, counters, rule metadata. No CGO. No access logs. |
| DLP Pipeline | In-process (see below) | Layered scanner: Aho-Corasick + regex + hotwords + entropy + exclusions + scoring |
| Rule Updater | `net/http` (stdlib) | Polls `manifest.json` for rule version, downloads changed files |
| MITM Proxy | `github.com/elazarl/goproxy` | Optional. Local proxy for Tier 2 non-browser inspection |
| CA Generator | `crypto/x509` (stdlib) | Optional. Generates per-device Root CA for MITM proxy |
| Self-Updater | `crypto/ed25519`, `net/http` | Optional. Polls release manifest, verifies SHA-256 + Ed25519 signature, stages binary |
| Rate Limiter | In-process token bucket | Configurable req/s limit on `/api/dlp/scan` |
| Scan Cache | In-process LRU | Short-lived (5s) dedup cache keyed on content SHA-256; never persists |

**Memory profile:** ~15 MB RSS at idle + ~200 KB for DLP automaton and exclusion sets. DNS server is event-driven (goroutine-per-request, no pre-allocated pools). SQLite WAL mode for minimal lock contention.

**Logging policy:** The Go binary writes operational logs to stderr (startup, errors, config changes). It NEVER logs domain names, URLs, IP addresses, or DLP match content from user traffic. Log level is configurable; in production, only errors are logged.

### 2. Layered DLP Pipeline

The DLP scanner is the core accuracy component. Instead of running all regex patterns against all
content (O(n × p) for n content length and p patterns), it uses a multi-stage pipeline.

On top of the deterministic core sit four accuracy layers —
adversary-resistant normalisation, a multi-piece
session correlator, a public-example bloom, and a code-template
placeholder router — plus two scoring-bias layers
that read the optional `SourceContext` the extension forwards on every
scan, plus a per-user feedback allowlist (H) that lets a user say "never
block this exact value again" via a salted SHA-256 hash. All layers are
pure functions of `(content, source, allowlist)`; none add I/O on the hot
path:

```
   Content arrives (paste / submit / fetch · optional session_id · optional source)
                            │
                            ▼
   ╔════════════════════════════════════════════════════════════╗
   ║ Normalize                                                  ║
   ║   zero-width strip · NFKC · homoglyph fold ·               ║
   ║   inline base64 decode                                     ║
   ╚════════════════════════╤═══════════════════════════════════╝
                            ▼
   ╔════════════════════════════════════════════════════════════╗
   ║ Correlator (optional)                                      ║
   ║   prepend prior paste tail when session_id supplied        ║
   ╚════════════════════════╤═══════════════════════════════════╝
                            ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Step 1 · Content Classifier             <10 µs             │
   └────────────────────────╤───────────────────────────────────┘
                            ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Step 2 · Aho-Corasick — O(n) prefix scan over all patterns │
   └────────────────────────╤───────────────────────────────────┘
                            ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Adaptive filter                                            │
   │   drop disabled categories + low/medium for large payloads │
   └────────────────────────╤───────────────────────────────────┘
                            ▼
   ┌────────────────────────────────────────────────────────────┐
   │ Step 3 · Regex revalidation (candidates only)              │
   └────────────────────────╤───────────────────────────────────┘
                            ▼
   ╔════════════════════════════════════════════════════════════╗
   ║ Public-example bloom                                       ║
   ║   SHA-256 hash table — match.Value in set ⇒ auto-skip      ║
   ╚════════════════════════╤═══════════════════════════════════╝
                            ▼
   ╔════════════════════════════════════════════════════════════╗
   ║ Placeholder-shape router                                   ║
   ║   <YOUR_KEY> / {{var}} / ${VAR} / xxxxxx / your-here ⇒    ║
   ║   auto-skip                                                ║
   ╚════════════════════════╤═══════════════════════════════════╝
                            ▼
   ╠══════════════════════════════════════════════════════════════╣
   ║ Feedback allowlist (optional)                                ║
   ║   SHA-256(per-install-salt ‖ normalize(match.Value))         ║
   ║   ∈ dlp_allowlist ⇒ auto-skip                                ║
   ╠══════════════════════════╤═══════════════════════════════════╣
                              ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ Step 4 · Per-pattern scoring                                 │
   │   hotword + entropy + exclusion + multi-match                │
   └──────────────────────────╤───────────────────────────────────┘
                              ▼
   ╠══════════════════════════════════════════════════════════════╣
   ║ Destination context bias                                     ║
   ║   destination_kind ∈ {ai_chat, code_host, ai_code, …}        ║
   ║     code_host: −2 · network_body: +1                         ║
   ║   element_kind ∈ {paste_target, network_body, file_upload}   ║
   ║   in_code_fence (markdown): low/medium −1                    ║
   ║   per-pattern ContextBias map overrides defaults             ║
   ╠══════════════════════════╤═══════════════════════════════════╣
                              ▼
   ╠══════════════════════════════════════════════════════════════╣
   ║ Path context bias                                            ║
   ║   path_hint matches *_test.* / fixtures/ / __tests__/ /      ║
   ║     mocks/ / spec/ AND destination_kind=code_host ⇒ −1       ║
   ║   (stacks with it so committed test fixtures fall below      ║
   ║    threshold even at high pattern severity)                  ║
   ╠══════════════════════════╤═══════════════════════════════════╣
                              ▼
   ┌──────────────────────────────────────────────────────────────┐
   │ Step 5 · Threshold check                                     │
   └──────────┬───────────────────────────────────┬───────────────┘
        score ≥ threshold                  score < threshold
              │                                   │
              ▼                                   ▼
   Block + ephemeral notify                    Allow
   + counter++                                    │
   + opt-in block_events INSERT                   │
     (only when                                   │
     agent_preferences.block_events_enabled = 1)  │
              │                                   │
              └────────────────┬──────────────────┘
                               ▼
         Content + canonical form + session tail
         discarded from memory (no disk write)
```

(Double-bordered ╔═╗ boxes are the accuracy layers. The
later double-bordered ╠═╣ boxes are the source-context additions: the
feedback allowlist inside the per-match loop, then the destination + path context bias around scoring. The
inner single-bordered boxes are the deterministic
core. The opt-in `block_events INSERT` lives at the Store layer —
see §"Privacy Architecture" and `Store.InsertBlockEvent` — and is
a silent no-op when consent is off.)

Performance budget: <1 ms hard end-to-end. Typical wall-clock cost is
~800 µs for the full accuracy-layer stack on a 4 KiB paste; the source-context bias adds
~13 µs at p50 for the source-context bias lookup. Snapshot of the
1M-line real-source bench lives in [BENCHMARKS.md](./BENCHMARKS.md).

#### Source-context layer summary

| Layer | Source file | Privacy posture |
|---|---|---|
| **Destination context** | `agent/internal/dlp/scorer_context.go` | `source.surrounding_hash` + `source.page_url_hash` are SHA-256 hashes; raw URL/content never crosses the wire. |
| **Path context** | as above (`path_hint` field) | `source.path_hint` is a hash of the in-IDE path; never raw. |
| **Feedback allowlist** | `agent/internal/dlp/allowlist.go`, `agent/internal/dlp/salt.go` | `dlp_allowlist.salted_hash = SHA-256(salt ‖ normalize(value))`; per-install salt at `~/.prompt-gate/allowlist-salt` (0600 perms) defeats cross-install lookup. |

#### Step 0a: Adversary-Resistant Normalisation

`agent/internal/dlp/normalize.go`. Runs before any pattern matching so
every downstream stage operates on a single canonical form:

| Pass | Defeats | Cost |
|------|---------|------|
| Zero-width / format-character strip (ZWSP, ZWNJ, ZWJ, LRM, RLM, BOM, soft hyphen, …) | `AK​IA…` style inline obfuscation | ~30 µs |
| Homoglyph fold (~50 Cyrillic + Greek confusables → Latin) | `АKIA…` with Cyrillic A | ~20 µs |
| NFKC normalisation (`golang.org/x/text/unicode/norm`) | full-width Latin, ligatures, compatibility forms | ~30 µs |
| Inline base64 decode (16 ≤ len ≤ 4096, padding-aligned, ≥80 % printable, decoded text appended to scan buffer with a `\n` separator, capped at 32 KiB) | `QUtJQUlPU0ZP…` blocks pasted next to plain text | ~20 µs |

Cache keys remain the *raw* content so callers get deterministic
per-input results; the canonical form is local to one scan and freed
when `Scan` returns.

#### Step 0b: Multi-Piece Exfil Correlator (optional)

`agent/internal/dlp/correlator.go`. Enabled when `ScanSession(ctx,
content, sessionID)` is called with a non-empty `sessionID` (the
browser extension generates one per tab and forwards it with every
`POST /api/dlp/scan`).

| Property | Value |
|----------|-------|
| Per-session state | last 256 bytes of the most recent paste + `lastSeen` timestamp |
| TTL | 30 s sliding (configurable via `NewCorrelator`) |
| Cap | 4 096 simultaneous sessions; oldest evicted when full |
| Persistence | none — pure in-memory map, lost on agent restart |
| Privacy | session IDs are opaque caller-supplied tokens; the correlator never derives or stores user identifiers |

When a second paste arrives in the same session, the correlator prepends
the prior tail (separated by `\n`) to the current content before
classification. A secret split across two pastes (`AKIA1234` …
`5678ABCDEF12345678`) is reassembled and matched by the existing
patterns without any new rule work. The cache is bypassed for session
scans so the same content in two different sessions cannot collide.

#### Step 1: Content Type Classification

Fast heuristic classification (< 10 μs) to select the appropriate pattern subset:

| Content Type | Detection Heuristic | Pattern Set |
|-------------|-------------------|-------------|
| Source code | Lines starting with `import`, `function`, `def`, `class`, `const`, `#include` | Internal URLs, env vars, private function names, API keys |
| Structured data | Contains `{`+`}` or consistent CSV delimiters | PII fields, database connection strings |
| Credentials block | Key-value pairs with `=` or `:` | API keys, tokens, passwords |
| Natural language | High space ratio, low symbol density | SSN, phone numbers, bulk email addresses |

**Benefit:** Reduces the active pattern set by 60-70%, both improving speed and reducing false positives from mismatched pattern types.

#### Step 2: Aho-Corasick Multi-Pattern Scan

Instead of running 20+ regexes sequentially, extract the fixed-string prefixes from all patterns
and build an Aho-Corasick automaton at rule load time:

```
Prefixes: "AKIA", "ghp_", "gho_", "sk-", "-----BEGIN", "xox", "eyJ", ...
```

Single-pass scan of content → candidate locations in O(n). Only candidates proceed to Step 3.

**Cost:** ~100 KB memory for automaton (100 patterns). Built once at rule load (~1 ms).

#### Step 3: Regex Validation

Full regex runs only on the candidate substrings identified by Aho-Corasick, not on the entire
content. This reduces regex work by 80%+ for typical content.

#### Step 3.5a: Public-Example Bloom

`agent/internal/dlp/bloom.go`. Before scoring, each match's `Value` is
normalised (whitespace, dashes, underscores stripped; ASCII lowercased)
and SHA-256 hashed against a curated set of well-known public examples
— the AWS docs canonical key, Stripe test keys, RFC 4122 documentation
UUIDs, PCI test card numbers, the jwt.io canonical token, and so on.
A hit short-circuits the match (never blocks).

Privacy invariant: stored as SHA-256 hashes only; the literal example
values do not ship in the binary. Each entry's trailing comment names
the source value for auditability. Cost: ~5 µs per match.

#### Step 3.5b: Placeholder-Shape Router

`agent/internal/dlp/codecontext.go`. Catches template/placeholder
values that have plausible entropy and pattern shape but are never
real secrets:

- Bracket templates: `<YOUR_API_KEY>`, `<INSERT_HERE>`, `<API_KEY>`
- Interpolation syntax: `{{var}}`, `${VAR}`
- Marker substrings (case-insensitive): `your_`, `your-`, `insert_`,
  `replace_`, `example_`, `_here`, `placeholder`, `todo_`, `fixme`,
  `sample_`, `dummy_`, `my_secret`, `redacted`
- Repeated mask characters: `xxxxxxxxxxxx`, `***********`, `●●●●●●●●●`

A hit short-circuits the match. Pure string-in/bool-out — no state, no
I/O. Cost: ~3 µs per match.

#### Step 4: Per-Match Scoring

Each validated match receives a score from multiple signals:

| Signal | Default Weight | Description |
|--------|---------------|-------------|
| Regex match (base) | `score_weight` (default +1) | Pattern matched; per-pattern override via `score_weight` |
| Hotword proximity | `+hotword_boost` (default +2) | Context keyword within N chars (e.g., "aws" near `AKIA...`); per-pattern override via `hotword_boost` |
| High entropy (≥ `entropy_min`) | +1 | Shannon entropy above per-pattern `entropy_min` (likely real secret) |
| Low entropy (< `entropy_min`) | -2 | Low randomness suggests placeholder/example |
| Multiple matches | +1 each (capped) | Bulk data indicator; requires `min_matches` for some patterns |
| Structured format | +1 | Match is inside a key-value or JSON structure |
| Exclusion word nearby | -3 | "example", "test", "placeholder", "dummy", "sample" nearby |
| Known false positive | -5 | Match is in exclusion dictionary |

All weights are configurable in the `dlp_config` SQLite table (see Database Schema below).

#### Scoring Formula

```
score(match) = score_weight
             + (hotword_present ? hotword_boost : 0)
             + (entropy >= entropy_min ? +entropy_boost : entropy_penalty)
             + (in_structured_context ? +1 : 0)
             + multi_match_boost * min(num_matches - 1, multi_match_cap)
             + (exclusion_word_nearby ? exclusion_penalty : 0)
             + (in_exclusion_dictionary ? -5 : 0)

block if score >= threshold[severity]
```

If a pattern sets `require_hotword: true`, the match is suppressed entirely when no hotword is present (regardless of score). This is useful for patterns like "Generic API Key" which would otherwise match any 20+ char alphanumeric string.

#### Step 5: Threshold Decision

Each severity level has a configurable threshold:

```json
{
  "thresholds": {
    "critical": 1,
    "high": 2,
    "medium": 3,
    "low": 4
  }
}
```

A "critical" pattern (like an AWS secret key) blocks with just a base match. A "medium" pattern
(like email addresses) requires additional corroboration (multiple matches, hotword, structured format).

#### Performance Budget

| Step | Time Budget | Memory Budget |
|------|------------|---------------|
| Normalisation (zero-width + homoglyph + NFKC + base64 decode) | < 100 μs | per-scan only (canonical string) |
| Session combine (when `session_id` supplied) | < 30 μs | 256 B/session × ≤ 4 096 sessions ≈ 1 MB worst case |
| Content classification | < 10 μs | 0 (stack only) |
| Aho-Corasick scan | < 100 μs (typical paste) | ~100 KB (automaton, built once) |
| Adaptive filter + Regex validation (candidates only) | < 500 μs | negligible |
| Public-example bloom + placeholder router | < 10 μs per match | ~3 KB (SHA-256 hash table) |
| Scoring (hotwords + entropy + exclusions) | < 200 μs | ~100 KB (exclusion hash sets) |
| **Total per scan** | **< 1 ms hard** (typical ≈ 800 μs) | **~200 KB shared + per-scan transient** |

All scan content (raw input, canonical form, prior session tail, scoring
state) is held in Go-managed memory only and released for GC
immediately after the response is sent. No content reaches disk,
SQLite, or any log.

#### DLP Pattern Format (Extended)

```json
{
  "patterns": [
    {
      "name": "AWS Access Key",
      "regex": "AKIA[0-9A-Z]{16}",
      "prefix": "AKIA",
      "severity": "critical",
      "score_weight": 1,
      "hotwords": ["aws", "access_key", "credentials", "iam", "secret"],
      "hotword_window": 200,
      "hotword_boost": 2,
      "require_hotword": false,
      "entropy_min": 3.5
    },
    {
      "name": "Generic API Key",
      "regex": "(?i)(api[_-]?key|apikey)\\s*[:=]\\s*['\"]?[A-Za-z0-9_\\-]{20,}",
      "prefix": "api",
      "severity": "high",
      "score_weight": 1,
      "hotwords": ["api", "key", "token", "secret"],
      "hotword_window": 50,
      "hotword_boost": 2,
      "require_hotword": true,
      "entropy_min": 3.0
    },
    {
      "name": "Email Addresses (bulk)",
      "regex": "([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+)",
      "prefix": "@",
      "severity": "medium",
      "score_weight": 1,
      "min_matches": 5,
      "hotwords": ["email", "contact", "user", "customer"],
      "hotword_window": 500,
      "hotword_boost": 1,
      "require_hotword": false,
      "entropy_min": 0
    },
    {
      "name": "GitHub Personal Access Token",
      "regex": "ghp_[A-Za-z0-9_]{36}",
      "prefix": "ghp_",
      "severity": "critical",
      "score_weight": 1,
      "hotwords": ["github", "token", "auth"],
      "hotword_window": 200,
      "hotword_boost": 2,
      "require_hotword": false,
      "entropy_min": 4.0
    },
    {
      "name": "Private Key Block",
      "regex": "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
      "prefix": "-----BEGIN",
      "severity": "critical",
      "score_weight": 2,
      "hotwords": [],
      "hotword_window": 0,
      "hotword_boost": 0,
      "require_hotword": false,
      "entropy_min": 0
    }
  ]
}
```

#### DLP Exclusion Format

```json
{
  "exclusions": [
    {
      "applies_to": "Email Addresses (bulk)",
      "type": "regex",
      "pattern": "@(example\\.com|test\\.com|localhost|mailinator\\.com)"
    },
    {
      "applies_to": "*",
      "type": "dictionary",
      "words": ["placeholder", "example", "test", "dummy", "sample", "xxx", "your-", "CHANGEME"],
      "window": 50
    },
    {
      "applies_to": "AWS Access Key",
      "type": "dictionary",
      "words": ["AKIAIOSFODNN7EXAMPLE"],
      "match_type": "exact"
    },
    {
      "applies_to": "GitHub Actions Secret Template",
      "type": "regex",
      "pattern": "\\$\\{\\{\\s*secrets\\.[A-Z0-9_]+\\s*\\}\\}",
      "suppress": true
    }
  ]
}
```

`match_type` accepts `exact` or `proximity` (default) and is honoured for
dictionary exclusions. `window` is optional on dictionary exclusions and
restricts the suppression to a byte window around the match; regex
exclusions match the secret span directly. The optional `suppress` field
on a regex exclusion fully suppresses the match (instead of merely
applying `ExclusionPenalty`); this is useful for known placeholder
formats such as `${{ secrets.NAME }}` in GitHub Actions YAML.

Community can contribute exclusions via PR to reduce false positives without modifying core patterns.

#### Accuracy on the FP Benchmark Corpus

`agent/internal/dlp/fp_corpus_test.go` runs the production
`rules/dlp_patterns.json` against the 99-entry labelled corpus under
`agent/internal/dlp/testdata/fp_corpus/` (public examples,
placeholders, benign prose, clear secrets, obfuscated secrets) and
reports precision / recall / F1 / FP rate. Run with:

```bash
cd agent && make dlp-bench
```

As of the launch-day build the pipeline reports **precision 100 % /
recall 73 % / FP rate 0 %**. The test gates CI at `precision ≥ 90 %`
and `recall ≥ 60 %`. The wider `TestDLPAccuracyCorpus`
(`accuracy_test.go`) enforces a budget of `FP rate < 10 %` and
`FN rate < 5 %` on a separate 50-entry real-world corpus.

#### Shipped Pattern Coverage

The repository ships **165** patterns across **14** JSON categories — see
[`SECURITY_RULES.md`](./SECURITY_RULES.md) for the full reference table.
Categories include cloud providers (AWS, Azure, GCP), cloud
infrastructure (Cloudflare, DigitalOcean, Vercel, Netlify, Supabase,
Pulumi, Helm, Terraform, Docker, Kubernetes), version control (GitHub,
GitLab, Bitbucket), AI/ML platforms (OpenAI, Anthropic, HuggingFace,
Cohere, Replicate, Pinecone, Mistral, W&B, LangSmith, Together, Groq),
payment processors (Stripe, PayPal, Square, Braintree, Adyen, Plaid,
Coinbase), CI/CD (CircleCI, Travis, Jenkins, Azure DevOps), messaging
(Slack, Discord, Telegram, Twilio, SendGrid, Vonage, Mailchimp),
auth/identity (Auth0, Okta, OneLogin, Keycloak, Firebase Admin SDK,
Supabase JWT, Clerk), language ecosystems (Java JDBC / Maven / Spring /
Keystore, Rust Cargo / Rocket, JS/TS / React / Next / Vite / Angular /
Webpack, Swift, Kotlin, Dart Flutter, Go, Python), desktop (Electron
Forge / Builder, Tauri signing), mobile (iOS APNs / Cocoapods / Xcode
Cloud / App Store Connect, Android signing / `google-services.json` /
`local.properties`, Expo / EAS / Fastlane Match / CodePush),
databases (Postgres, MySQL, MongoDB SRV, Redis, MSSQL, SQLite PRAGMA,
Cassandra, Elasticsearch), private keys (PEM), JWTs, generic
password-in-code patterns, and PII (SSN, credit cards, emails, phones).
Accuracy is enforced by
[`agent/internal/dlp/accuracy_test.go`](./agent/internal/dlp/accuracy_test.go)
with budgets `FP < 10%` and `FN < 5%`.

### 3. Local MITM Proxy (Optional)

Optional component for Tier 2 coverage of non-browser AI clients (CLI tools, IDE plugins, native
apps). Disabled by default; opt-in via the Electron Settings "Advanced DLP" wizard or directly
through `POST /api/proxy/enable`.

```
agent/internal/proxy/
├── proxy.go         # goproxy.ProxyHttpServer wired with policy + DLP
├── ca.go            # per-device ECDSA P-256 Root CA + 1 h leaf cache
├── controller.go    # Enable / Disable / Status lifecycle
├── proxy_test.go  ca_test.go  controller_test.go
└── integration_test.go   # end-to-end + log-scrubbing privacy test
```

| Capability | Library / Approach |
|------------|--------------------|
| Local HTTPS proxy | `github.com/elazarl/goproxy` on `127.0.0.1:8443` |
| Per-device Root CA | `crypto/x509` + `crypto/ecdsa` (P-256), generated at first run, persisted to `~/.prompt-gate/ca.{crt,key}` |
| Leaf certificates | Generated on demand, signed by the Root CA, cached in-memory for 1 h |
| Policy hook | `policy.Engine.CheckDomain == AllowWithDLP` → MITM-decrypt; everything else passes through as an opaque CONNECT tunnel |
| Pinning bypass | `proxy_pinning_bypass` config list forces opaque pass-through for hostnames whose apps pin a specific CA |
| DLP integration | Decrypted request bodies are run through the same `dlp.Pipeline` used by the extension path (in-memory only) |
| Block response | HTTP 451 with `{"blocked": true, "pattern_name": "..."}`; the original request is never forwarded |
| Counters | `dlp_scans_total` / `dlp_blocks_total` shared with the extension path |
| Lifecycle | `proxy.Controller` owns Enable/Disable/Status; the agent main process exposes those as `/api/proxy/{enable,disable,status}` |

**Privacy invariant for the proxy:** decrypted content paths terminate at the DLP scan and are
then released for GC. The proxy itself emits no per-request logs and writes no request/response
bodies. `integration_test.go` regression-tests this by capturing stdout + stderr during a
Tier-2 request and asserting that neither the request body nor the Host header sentinel ever
appears in the captured stream.

### 3b. Enterprise Configuration Profiles

Optional, server-distributed policy bundles for managed deployments.

```
agent/internal/profile/
├── profile.go   # Profile struct + Holder (current/locked state)
├── loader.go    # LoadFromFile, LoadFromURL (1 MiB cap, 30s timeout)
├── apply.go     # Apply(): write through to store; PolicyStore interface
└── profile_test.go
```

| Capability | Approach |
|------------|----------|
| Schema | `{name, version, managed, categories:{...}, dlp:{...}, rule_update_url}` JSON |
| Source | Local file (`profile_path`) or HTTPS GET (`profile_url`); `profile_path` takes precedence when both are set |
| Size cap | 1 MiB, enforced in `loader.go` so a malicious server cannot OOM the agent |
| Apply | Iterates `categories` → `store.SetPolicy`; copies `dlp` block → `store.SetDLPConfig` |
| Lock | `Holder.Locked()` returns `managed`; consulted by `PUT /api/policies/:cat` and `PUT /api/dlp/config` to return `403 Forbidden` |
| API | `GET /api/profile`, `POST /api/profile/import` (body is `{url}` or `{profile}`) |

The profile holder lives in `api.Server`; locking is enforced at the
HTTP handler, not at the store level, so a profile import that fails
to apply leaves the existing on-disk config untouched.

### 3c. Tamper Detection

Periodic OS-level check that the device is still routing through the
agent. Runs as a goroutine started by `main.go`.

```
agent/internal/tamper/
├── detector.go            # core loop + Status; Reporter interface bumps counter
├── dns_unix.go            # Linux/BSD/macOS DNS probe (resolv.conf + networksetup)
├── dns_windows.go         # netsh interface ipv4 show dnsservers
├── proxy_check.go         # cross-platform shared helpers + env-var fallback
├── proxy_darwin.go        # networksetup -getwebproxy / -getsecurewebproxy
├── proxy_windows.go       # netsh winhttp show proxy
├── proxy_other.go         # build-tag stubs for non-darwin/non-windows
└── detector_test.go
```

| Capability | Approach |
|------------|----------|
| Cadence | 60s by default; `CheckNow()` for one-shot |
| DNS probe | Compares the active resolver list against the expected `dns_listen` host |
| Proxy probe | Compares the active system proxy against `proxy_listen`; uses platform CLI when available, falls back to `HTTP(S)_PROXY` env vars on Linux/BSD |
| Counter | `Reporter.IncrementTamperDetections()` is called **only on transitions** (steady-state tamper does not double-count) |
| Notification | Electron polls `GET /api/tamper/status` every 10s and shows an ephemeral tray balloon on rising-edge; no on-disk event log |

### 3d. Agent Heartbeat (Optional)

Disabled by default. Set `heartbeat_url` in `config.yaml` to enable.

```
agent/internal/heartbeat/
├── heartbeat.go      # New / BuildPayload / SendOnce / Start
└── heartbeat_test.go # asserts payload shape + no access fields leak
```

| Capability | Approach |
|------------|----------|
| Cadence | 1h by default; `heartbeat_interval` overrides |
| Payload | Exactly `{agent_version, os_type, os_arch, aggregate_counters}` — nothing else |
| Transport | `http.Client` with a 30s timeout; HTTP errors are logged to stderr and otherwise swallowed |
| Privacy guarantee | A unit test deserialises the payload and asserts no key matches `/url|domain|ip|match|host|pattern/i` |

### 3e. Admin Override Mechanism

```
agent/internal/rules/override.go         # OverrideStore: rules/local/allow.txt + block.txt
agent/internal/dlp/override.go           # MergePatternsFromDir, MergeExclusionsFromDir
```

| File | Behaviour |
|------|-----------|
| `rules/local/allow.txt` | Domains forced into the `allow_admin` category |
| `rules/local/block.txt` | Domains forced into the `block_admin` category |
| `rules/local/dlp_patterns_override.json` | Patterns with the same `name` replace bundled; others append |
| `rules/local/dlp_exclusions_override.json` | Exclusions deduplicated by `(type, applies_to, pattern, words)` |

The override store enforces mutual exclusivity (adding a domain to
allow removes it from block, and vice versa) and uses atomic temp
file + rename writes so a crash mid-write cannot corrupt the list.
Bundled rule files are never mutated; the merge happens in memory at
load time.

### 3f. Agent Self-Update

```
agent/internal/updater/self.go      # Self.CheckLatest, Self.DownloadAndStage
agent/internal/updater/self_test.go # SHA-256 + Ed25519 verification under httptest
```

The self-updater is opt-in: it remains inert unless both
`agent_update_manifest_url` and `agent_update_public_key` (a
hex-encoded Ed25519 public key) are set in `config.yaml`. When wired,
the updater polls a release manifest, verifies the SHA-256 hash of
the downloaded binary, then verifies the Ed25519 signature over the
hash, and only then stages the binary for the next agent restart. A
verification failure aborts the update; no partial binary is ever
written to the live install path.

### 3g. Rate Limiter

```
agent/internal/api/ratelimit.go        # token-bucket middleware
```

A token-bucket middleware sits in front of `/api/dlp/scan`. Defaults
are 100 req/s with a burst of 100, configurable via
`dlp_rate_limit_per_sec` in `config.yaml`. The bucket is shared
across all callers — the goal is to protect the agent from a
misbehaving extension, not to enforce per-tab fairness.

### 3h. Scan-Result Cache

```
agent/internal/dlp/cache.go        # ScanCache: TTL-bounded LRU
```

A short-lived (5 s by default) LRU cache deduplicates identical
content hashes inside `Pipeline.Scan`. The cache keys on a SHA-256
of the content and stores only the resulting `ScanResult`. Raw
content is *never* held in the cache. The cache is bounded by entry
count and TTL; it does not persist to disk.

### 4. Electron Tray Application

Minimal Electron shell for system tray presence and settings UI.

```
electron/
├── main.ts              # Main process: tray icon, IPC, window management
├── preload.ts           # Secure bridge to renderer
├── src/
│   ├── pages/
│   │   ├── Settings.tsx       # Policy toggles + DLP config + admin overrides
│   │   ├── Status.tsx         # Agent health + anonymous aggregate stats + recent blocks
│   │   ├── ProxySettings.tsx  # MITM proxy wizard
│   │   ├── Rules.tsx          # read-only rule viewer
│   │   └── Setup.tsx          # first-run wizard
│   ├── components/
│   │   ├── CategoryToggle.tsx # Three-state: Allow / Allow+Inspect / Block
│   │   └── StatsCard.tsx      # Display aggregate counters
│   └── api/
│       └── agent.ts           # HTTP client to Go backend on localhost
├── package.json
└── electron-builder.yml
```

**Resource strategy:**
- Tray icon created immediately (near-zero overhead)
- `BrowserWindow` created only when user clicks "Open Settings"
- Window is **destroyed** (not hidden) on close to free Chromium memory
- No background renderer processes when window is closed
- Estimated overhead: ~35 MB when window is open, ~5 MB tray-only

**No Reports page.** Since we don't log access events, there is no detailed reports page.
The Status page shows only anonymous counters: "Total blocks: 142 | DLP blocks: 7 | Uptime: 3d 14h".

### 5. Browser Extension (Chrome + Firefox + Safari)

TypeScript extension using Manifest V3 for Chrome (`manifest.json`), Firefox
(`manifest.firefox.json` — `browser_specific_settings.gecko`), and Safari
(`manifest.safari.json` — `browser_specific_settings.safari`). `npm run
build:firefox` produces a Firefox-ready bundle in `dist-firefox/`; `npm run
build:safari` produces `dist-safari/` and wraps it with `xcrun
safari-web-extension-converter` into an Xcode project under
`dist-safari-xcode/` (macOS-only).

Safari Web Extensions do not implement `chrome.runtime.connectNative`, so the
Safari port skips Native Messaging entirely and uses the HTTP fallback
(`POST 127.0.0.1:9191/api/dlp/scan`) exclusively. The agent's CORS allowlist
accepts `chrome-extension://`, `moz-extension://`, and
`safari-web-extension://<UUID>` origins.

**Capabilities:**
- Five content scripts injected on the Tier 2 AI tool domains:
  - `paste-interceptor.ts` — captures `paste` events
  - `form-interceptor.ts`  — captures `<form>` `submit` events; concatenates
    textarea + text-input values before scanning
  - `network-interceptor.ts` — monkey-patches `window.fetch` and
    `XMLHttpRequest.prototype.send` to scan outbound bodies > 50 bytes
  - `drag-interceptor.ts` — captures `drop` events, routes text through scan-client
  - `clipboard-monitor.ts` — optional, pre-scans clipboard on tab focus (off by default)
- Background `dynamic-hosts.ts` polls `/api/rules/status` and dynamically
  registers content scripts for custom Tier-2 hosts surfaced by the admin
  override mechanism, so newly admin-added domains light up without an
  extension reinstall.
- `src/options/` ships the extension options page exposing agent connection
  status, the verbose-toast toggle, and the clipboard-monitor toggle.
- Content scripts route DLP scans through the background service worker.
  The service worker prefers Chrome Native Messaging
  (`chrome.runtime.connectNative('com.shieldnet360.promptgate')`) and falls back to
  direct HTTP (`POST 127.0.0.1:9191/api/dlp/scan`) when the native host is
  unavailable. Both paths share the same `dlp.Pipeline.Scan()` on the agent.
- Every scan carries a per-tab `session_id` generated once at
  content-script load (`crypto.randomUUID()` with a `Math.random`
  fallback). The agent's correlator uses it to reassemble secrets
  split across consecutive pastes from the same tab. The token is
  opaque, in-memory only, and never sent to any host other than the
  loopback agent — see [`extension/src/content/scan-client.ts`](./extension/src/content/scan-client.ts).
- Shows an ephemeral toast on block (pattern name only, never the matched
  content). The toast is sanitised to printable ASCII so the page cannot
  trivially trigger XSS via a hostile pattern name.
- Falls open (allows the action) on any agent error or timeout so a crashed
  agent never blocks productivity.

**Native Messaging host manifest:** `extension/native-messaging/com.shieldnet360.promptgate.json`
is installed per-user by `install.sh` (macOS/Linux) or `install.ps1`
(Windows). On Chrome it lives under
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` (macOS),
`~/.config/google-chrome/NativeMessagingHosts/` (Linux), or
`HKCU\Software\Google\Chrome\NativeMessagingHosts\com.shieldnet360.promptgate`
(Windows). The agent binary launched with `--native-messaging` serves the
Chrome protocol (4-byte little-endian length prefix + JSON payload) on
stdin/stdout without standing up the DNS / API server.

**Privacy:** The extension does not store any history of scanned content. When the DLP pipeline
blocks content, the notification displays the pattern name (e.g., "AWS Access Key detected") but
does NOT include the actual key or matched content. After the user dismisses the notification, no
trace remains.

### 5b. Rule Updater

`agent/internal/rules/updater.go` polls a configurable manifest URL on a
configurable cadence (default 6 h) and applies delta updates to the on-disk
rule bundle.

**Flow:**
1. `GET` the manifest URL configured via `config.yaml`'s `rule_update_url`.
   The manifest is JSON: `{version: string, files: [{name, sha256, url?}]}`.
2. For each file, compute the SHA256 of the existing copy in `rules_dir`. If
   it already matches the manifest entry, skip the file (delta optimisation).
3. Otherwise, download the file into a temporary path next to its
   destination, verify the SHA256, then `os.Rename` it onto the destination
   path. `os.Rename` is atomic on POSIX filesystems and NTFS, so a partially
   downloaded file can never be observed by the rest of the agent.
4. After any file was replaced, invoke the reload callback wired by
   `cmd/agent/main.go` — this calls `policy.Engine.Reload(ctx)` to
   re-ingest the domain lookup map and `dlp.Pipeline.Rebuild(...)` to
   reconstruct the Aho-Corasick automaton from the new patterns +
   exclusions.
5. Append the new version string to the `rule_versions` SQLite table for
   audit, and update the in-memory `currentVersion` / `lastCheck` /
   `nextCheck` fields used by `GET /api/rules/status`.

**Safety:** the manifest's `files[].name` is rejected if it contains a path
separator, parent reference (`..`), or starts with a dot. URLs are resolved
against the manifest's own URL when relative, and downloads happen through
the same `http.Client` (configurable timeout) so a network stall cannot
hang the updater past its poll interval.

### 6. SQLite Database Schema

```sql
-- Rule file metadata
CREATE TABLE rulesets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid        TEXT UNIQUE NOT NULL,
    name        TEXT NOT NULL,
    rule_type   TEXT NOT NULL DEFAULT 'dstdomain',
    file_path   TEXT NOT NULL,
    category    TEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Policy configuration (three-state: allow / allow_with_dlp / deny)
CREATE TABLE category_policies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT UNIQUE NOT NULL,
    action      TEXT NOT NULL DEFAULT 'deny',  -- 'allow', 'allow_with_dlp', 'deny'
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Anonymous aggregate counters (NO domain, NO IP, NO timestamp per event)
CREATE TABLE aggregate_stats (
    id                       INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    dns_queries_total        INTEGER NOT NULL DEFAULT 0,
    dns_blocks_total         INTEGER NOT NULL DEFAULT 0,
    dlp_scans_total          INTEGER NOT NULL DEFAULT 0,
    dlp_blocks_total         INTEGER NOT NULL DEFAULT 0,
    tamper_detections_total  INTEGER NOT NULL DEFAULT 0,
    last_reset_at            DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Rule update tracking
CREATE TABLE rule_versions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    manifest_version TEXT NOT NULL,
    updated_at       DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- DLP scoring configuration
CREATE TABLE dlp_config (
    id                      INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    threshold_critical      INTEGER NOT NULL DEFAULT 1,
    threshold_high          INTEGER NOT NULL DEFAULT 2,
    threshold_medium        INTEGER NOT NULL DEFAULT 3,
    threshold_low           INTEGER NOT NULL DEFAULT 4,
    hotword_boost           INTEGER NOT NULL DEFAULT 2,
    entropy_boost           INTEGER NOT NULL DEFAULT 1,
    entropy_penalty         INTEGER NOT NULL DEFAULT -2,
    exclusion_penalty       INTEGER NOT NULL DEFAULT -3,
    multi_match_boost       INTEGER NOT NULL DEFAULT 1,
    updated_at              DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Feedback allowlist — per-user "never block this value again" allowlist.
-- The agent stores ONLY salted SHA-256 hashes plus a small amount of
-- metadata (scope, optional pattern_name for the settings UI,
-- timestamps). The salt is per-install at ~/.prompt-gate/allowlist-salt
-- (0600 perms) — see agent/internal/dlp/salt.go — so a stolen DB alone
-- cannot be reverse-looked up against a wordlist of common secret values.
-- Raw values touch memory only, never disk.
CREATE TABLE dlp_allowlist (
    salted_hash  TEXT PRIMARY KEY,             -- hex of SHA-256(salt || normalize(value))
    scope        TEXT NOT NULL DEFAULT '*',    -- '*' or a destination_kind (e.g. 'code_host')
    pattern_name TEXT NOT NULL DEFAULT '',     -- display metadata for the Settings UI
    expires_at   INTEGER NOT NULL DEFAULT 0,   -- 0 = never expires
    created_at   INTEGER NOT NULL,
    last_hit     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX dlp_allowlist_expiry ON dlp_allowlist(expires_at);

-- Opt-in event log consent. The block_events table writes
-- destination hostnames to disk, which is a privacy-invariant violation
-- unless the user has explicitly consented. Default = 0 (disabled).
-- The gate lives in Store.InsertBlockEvent (NOT the recorder adapter
-- in cmd/agent/main.go) so every present and future writer — proxy hot
-- path, future transports, tests — inherits it automatically. Setting
-- consent OFF is one click; the consented_at timestamp is preserved
-- across disable so the Settings UI can show "last consented YYYY-MM-DD".
CREATE TABLE agent_preferences (
    id                         INTEGER PRIMARY KEY CHECK (id = 1),  -- singleton row
    block_events_enabled       INTEGER NOT NULL DEFAULT 0,
    block_events_consented_at  INTEGER NOT NULL DEFAULT 0,
    updated_at                 DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Local-only block-history feature, populated ONLY when
-- agent_preferences.block_events_enabled = 1. Last 500 events;
-- older rows trimmed on every INSERT. Read via GET /api/block-events,
-- cleared via DELETE /api/block-events.
--
-- Privacy carve-out: the host column stores plaintext destination
-- domains. This is the second of two carve-outs from the no-per-event-
-- data invariant (the first being dlp_allowlist's salted hashes); the
-- opt-in consent gate is what makes it acceptable.
CREATE TABLE block_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type   TEXT NOT NULL DEFAULT 'dlp',     -- 'dlp' or 'category'
    host         TEXT NOT NULL DEFAULT '',       -- plaintext destination hostname
    pattern_name TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL DEFAULT 'blocked'
);

-- NOTE: There is deliberately NO alert_events table.
-- NOTE: There is deliberately NO access_log table.
-- NOTE: The block_events table above is the ONE exception, and it is
--       a no-op until the user opts in via Settings → Privacy.
-- These are privacy design decisions, not oversights. See
-- docs/PRIVACY-AUDIT.md for the privacy & data-handling design.
```

### 7. DNS Resolver Flow

```
   DNS Query arrives
         │
         ├──► dns_queries_total++  (no domain stored)
         │
         ▼
   Domain in rule files? ──────► No ──► Forward to upstream DNS ──► Return resolved IP
         │
         ▼ Yes
   Category policy action?
         │
         ├──► allow           ──► Forward to upstream DNS ──► Return resolved IP
         ├──► allow_with_dlp  ──► Forward to upstream DNS ──► Return resolved IP
         └──► deny            ──► Return NXDOMAIN
                                    │
                                    └──► dns_blocks_total++  (no domain stored)
```

**Implementation detail:** The DNS resolver maintains an in-memory hash map of blocked domains
loaded from rule files. Lookup is O(1). Rule files are re-read only when the updater detects a
new version. Counters are atomically incremented in-memory and flushed to SQLite periodically
(e.g., every 60 seconds) to minimize disk I/O.

### 8. Platform-Specific Integration

#### macOS
| Capability | Approach | Admin Required |
|---|---|---|
| DNS override | `networksetup -setdnsservers Wi-Fi 127.0.0.1` | Yes (one-time) |
| System proxy (opt) | `networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 8443` | Yes (one-time) |
| CA trust (opt) | `security add-trusted-cert` to System Keychain | Yes (one-time) |
| Auto-start | LaunchDaemon plist in `/Library/LaunchDaemons/` | Yes (installer) |
| Installer | `.pkg` via `pkgbuild` + `productbuild` | Standard |

#### Windows
| Capability | Approach | Admin Required |
|---|---|---|
| DNS override | `netsh` or WMI adapter DNS setting | Yes (one-time) |
| System proxy (opt) | Registry `HKCU\...\Internet Settings\ProxyServer` | No (user-level) |
| CA trust (opt) | `certutil -addstore -f "Root" ca.crt` | Yes (UAC prompt) |
| Auto-start | Windows Service via `golang.org/x/sys/windows/svc` | Yes (installer) |
| Installer | MSI via WiX Toolset | Standard |

#### Linux
| Capability | Approach | Admin Required |
|---|---|---|
| DNS override | Modify `/etc/resolv.conf` or `systemd-resolved` | Yes (root) |
| Transparent redirect (opt) | `iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8443` | Yes (root) |
| CA trust (opt) | Copy to `/usr/local/share/ca-certificates/` + `update-ca-certificates` | Yes (root) |
| Auto-start | systemd unit file | Yes (root) |
| Installer | `.deb` + `.rpm` + `AppImage` via electron-builder | Standard |

### 9. Communication Diagram

### Scenario 1 — Configure policy from the tray UI

```
User                Electron Tray       Go Agent              SQLite
 │  click "Settings"   │                   │                    │
 │ ───────────────────►│                   │                    │
 │                     │  GET /api/policies│                    │
 │                     │ ──────────────────►│ SELECT category_  │
 │                     │                   │   policies         │
 │                     │                   │ ──────────────────►│
 │                     │                   │◄────── rows ───────│
 │                     │◄── JSON response ─│                    │
 │◄── render UI ───────│                   │                    │
 │                     │                   │                    │
 │ toggle "AI Chat" →  │                   │                    │
 │     Block           │                   │                    │
 │ ───────────────────►│  PUT /api/policies│                    │
 │                     │   /ai_chat        │                    │
 │                     │  {action:"deny"}  │                    │
 │                     │ ──────────────────►│ UPDATE category_  │
 │                     │                   │  policies          │
 │                     │                   │ ──► Reload domain  │
 │                     │                   │     set (DNS)      │
 │                     │◄────── 200 OK ────│                    │
```

### Scenario 2 — DNS block (e.g. user visits a blocked AI domain)

```
User              DNS Resolver         Go Agent             SQLite
 │ DNS query:        │                    │                    │
 │ deepseek.com      │                    │                    │
 │ ─────────────────►│   check policy     │                    │
 │                   │ ──────────────────►│                    │
 │                   │◄── NXDOMAIN ───────│ aggregate_stats:   │
 │                   │   (blocked)        │ dns_blocks_total++ │
 │                   │                    │ ──────────────────►│
 │                   │                    │  (no domain name   │
 │                   │                    │   stored — counter │
 │                   │                    │   only)            │
 │◄── NXDOMAIN ──────│                    │                    │
```

### Scenario 3 — DLP block from a browser paste (full accuracy-layer path)

```
User           Browser Ext         Go Agent              DLP Pipeline       SQLite
 │ paste code      │                  │                       │                │
 │ into            │                  │                       │                │
 │ chat.openai.com │                  │                       │                │
 │ ───────────────►│ POST /api/dlp/   │                       │                │
 │                 │   scan           │                       │                │
 │                 │ {content,        │                       │                │
 │                 │  session_id}     │                       │                │
 │                 │ ────────────────►│  normalize            │                │
 │                 │                  │  (zero-width strip,   │                │
 │                 │                  │   homoglyph fold,     │                │
 │                 │                  │   NFKC,               │                │
 │                 │                  │   base64 decode)      │                │
 │                 │                  │                       │                │
 │                 │                  │  prepend prior        │                │
 │                 │                  │  paste tail for       │                │
 │                 │                  │  session_id           │                │
 │                 │                  │ ─────────────────────►│                │
 │                 │                  │                       │ Classify →     │
 │                 │                  │                       │ "source code"  │
 │                 │                  │                       │ AC prefix scan │
 │                 │                  │                       │ → candidates   │
 │                 │                  │                       │ Regex validate │
 │                 │                  │                       │ bloom skip     │
 │                 │                  │                       │   (none hit)   │
 │                 │                  │                       │ placeholder    │
 │                 │                  │                       │   skip (none)  │
 │                 │                  │                       │ Score:         │
 │                 │                  │                       │   hotword +    │
 │                 │                  │                       │   entropy +    │
 │                 │                  │                       │   exclusion    │
 │                 │                  │                       │ Score 4 ≥      │
 │                 │                  │                       │ critical=1     │
 │                 │                  │                       │ → BLOCK        │
 │                 │                  │◄──── {blocked: true,──│                │
 │                 │                  │  pattern_name: "AWS  │                │
 │                 │                  │  Access Key",        │                │
 │                 │                  │  score: 4}           │                │
 │                 │                  │                      │                 │
 │                 │                  │  raw content +      │                 │
 │                 │                  │  canonical form +   │                 │
 │                 │                  │  session tail       │                 │
 │                 │                  │  discarded (no      │                 │
 │                 │                  │  disk write)        │                 │
 │                 │                  │                     │ aggregate_stats:│
 │                 │                  │                     │ dlp_blocks_     │
 │                 │                  │                     │ total++         │
 │                 │                  │ ────────────────────────────────────►│
 │                 │                  │                     │ (no content     │
 │                 │                  │                     │  stored —       │
 │                 │                  │                     │  counter only)  │
 │                 │◄─── {blocked,────│                     │                 │
 │                 │ pattern_name}    │                     │                 │
 │◄── block paste, │                  │                     │                 │
 │   show          │                  │                     │                 │
 │   ephemeral     │                  │                     │                 │
 │   notification  │                  │                     │                 │
```

### 10. API Endpoints

| Method | Path | Description | Privacy Notes |
|--------|------|-------------|---------------|
| `GET` | `/api/status` | Agent health, uptime | No user data |
| `GET` | `/api/policies` | List category policies | Config only |
| `PUT` | `/api/policies/:category` | Update policy action | Config only |
| `GET` | `/api/stats` | Anonymous aggregate counters | Integers only, no domains/IPs |
| `POST` | `/api/stats/reset` | Reset counters to zero | — |
| `POST` | `/api/dlp/scan` | Scan `{content, session_id?, source?}` through the layered DLP pipeline. `session_id` engages the correlator; `source` (the `SourceContext` — `destination_kind`, `destination_host`, `element_kind`, `in_code_fence`, `language_hint`, `path_hint`, `surrounding_hash`, `page_url_hash`) drives the source-context (destination + path) scoring bias. All content-derived `*_hash` fields are SHA-256 hashes; the raw URL/content/path never crosses the wire. | Content processed in-memory, never persisted; per-session tail held for 30 s in RAM. |
| `GET` | `/api/dlp/config` | Get DLP scoring thresholds | Config only |
| `PUT` | `/api/dlp/config` | Update DLP scoring thresholds | Config only |
| `GET` | `/api/dlp/allowlist` | List feedback-allowlist entries (`{salted_hash, scope, pattern_name, expires_at, created_at, last_hit}` per row). Salted hashes only — no raw values. | Hashes + metadata only. |
| `POST` | `/api/dlp/allowlist` | Add an entry from `{value, scope?, pattern_name?, ttl?}`. The raw value is normalised + salt-hashed in the handler and discarded; only the hash persists. 403 under a managed enterprise profile. | Raw value touches memory only; persists as `SHA-256(salt ‖ normalize(value))`. |
| `DELETE` | `/api/dlp/allowlist/:salted_hash` | Remove a specific entry by its hash. 403 under a managed profile. | Hash only. |
| `GET` | `/api/rules/status` | Current rule version, last/next check, manifest URL | Metadata only |
| `POST` | `/api/rules/update` | Trigger immediate manifest check; returns `{updated, version, files_downloaded}` | — |
| `POST` | `/api/proxy/enable` | Generate the per-device Root CA (if missing) and start the local MITM proxy; returns `{ca_cert_path}` | No user data; cert path is a local filesystem location |
| `POST` | `/api/proxy/disable` | Stop the local MITM proxy; pass `{"remove_ca": true}` to also delete the CA files | — |
| `GET` | `/api/proxy/status` | `{running, ca_installed, listen_addr, dlp_scans_total, dlp_blocks_total}` | Integers + booleans only |
| `GET` | `/api/profile` | Current enterprise profile (404 if none loaded) | Config only |
| `POST` | `/api/profile/import` | Import a profile from `{url}` or `{profile}` body; applies it and locks local edits when `managed=true` | Profile content + URL only; no access data |
| `GET` | `/api/tamper/status` | `{dns_ok, proxy_ok, last_check, detections_total}` | Booleans + counter only |
| `GET` | `/api/stats/export` | Counter snapshot wrapped in `{agent_version, os_type, os_arch, exported_at, stats}`, `Content-Disposition: attachment` | Same fields as `/api/stats` |
| `GET` | `/api/rules/override` | List admin allow/block override sets | Config only |
| `POST` | `/api/rules/override` | Add `{domain, list:"allow"\|"block"}`; moves between lists if needed | Config only |
| `DELETE` | `/api/rules/override/:domain` | Remove an override regardless of list | Config only |
| `GET` | `/api/preferences` | Returns `{block_events_enabled, block_events_consented_at, managed}`. `managed` reflects whether an enterprise profile has locked the agent. | Flags + integer timestamp only. |
| `PUT` | `/api/preferences/block-events` | Flip the opt-in `block_events` consent gate with `{enabled: bool}`. 403 under a managed profile. Enabling stamps `consented_at` with the current unix-seconds; disabling preserves it so the UI can show "last consented YYYY-MM-DD". | Flag only; the audit timestamp is the only added durable state. |
| `GET` | `/api/block-events` | List the most recent persisted block events (up to 500). Returns an empty array when the consent gate is off. Optional `?limit=N`. | Returns plaintext destination hostnames when the gate is ON — this is the opt-in carve-out. Returns `[]` when OFF. |
| `DELETE` | `/api/block-events` | Drop all rows from `block_events`. Allowed regardless of consent state (lets a user wipe history without first re-enabling). | — |

**There is no `/api/alerts` endpoint. There is no `/api/logs` endpoint.**
The four `block_events` / `preferences` endpoints are the opt-in
carve-out (default OFF, gated by `agent_preferences.block_events_enabled`,
documented in [docs/PRIVACY-AUDIT.md](./docs/PRIVACY-AUDIT.md)).
This is by design.
