# Privacy & data handling

Prompt Gate is built so that, in its default configuration, **nothing about what
you access is written to disk or sent off your device**. This page documents
exactly what is and isn't persisted, and how the guarantees are enforced and tested.

## The privacy invariant

The agent never persists per-event content, destination hostnames, URLs, IP
addresses, or user identifiers, and it never transmits them off-device. DLP scan
content is processed **in memory** and garbage-collected immediately after the
verdict is returned. Operational errors may go to stderr; nothing about user
activity does.

## What *is* stored locally

| Data | Where | Notes |
|---|---|---|
| Policy configuration | local SQLite | which categories are allowed/blocked |
| Anonymous aggregate counters | local SQLite | bare integers (e.g. total blocks/queries) — no timestamps, domains, or contents |
| Rule files | on disk | domain lists + DLP patterns/exclusions |
| Agent configuration | `config.yaml` | upstream DNS, ports, rule-update URL |
| Feedback allowlist (`dlp_allowlist`) | local SQLite | **salted SHA-256 hashes only** (per-install salt at `~/.prompt-gate/allowlist-salt`) — never raw values |

## Opt-in carve-out: block-events history

There is **one** optional feature that can persist destination hostnames: a local
"recently blocked" history view. It is **off by default** and gated by an explicit
consent flag (`agent_preferences.block_events_enabled`, default `false`):

- With consent **off**, `InsertBlockEvent` is a silent no-op — the gate lives at the
  storage layer, so every current and future writer inherits it automatically and
  cannot accidentally write hostnames to disk.
- With consent **on**, the user has explicitly enabled the history via
  **Settings → Privacy**; `GET /api/block-events` then returns the local rows, and
  `DELETE /api/block-events` clears them at any time.
- Enterprise `managed=true` profiles can pin the toggle off.

There is deliberately **no** `alert_events` table, **no** `access_log` table, and
**no** `/api/alerts` or `/api/logs` endpoint.

## How it's verified

- **Column-sweep test** — `agent/internal/store/privacy_test.go` exercises the
  block-events write path with consent off and asserts that no destination data
  reaches disk, and that no stored column ever contains a matched value.
- **Security report** — see [reports/security.md](reports/security.md) for the
  privacy-invariant result alongside the broader security checks.

These run in CI on every push and pull request.
