# Admin Guide

This guide is for administrators who deploy Prompt Gate across an
organization. End-user documentation lives in [user-guide.md](./user-guide.md).

## 1. Installation

Prompt Gate ships as a single Go binary plus an Electron tray app. The
release artifacts are produced by the `release.yml` GitHub Actions workflow and
attached to GitHub Releases. See the **[Installation](installation.md)** page for
the full set of options (release download, Homebrew cask, winget, build from
source) and how to verify what you install.

| Platform | Install |
| --- | --- |
| macOS (Apple Silicon) | `Prompt.Gate-<version>-arm64.dmg`, or `brew install --cask ./packaging/homebrew/prompt-gate.rb` |
| Windows | `Prompt.Gate.Setup.<version>.exe`, or `winget install --manifest .\packaging\winget\` |
| Linux (desktop) | `Prompt.Gate-<version>.AppImage` |
| Linux (Debian/Ubuntu) | `prompt-gate_<version>_amd64.deb` |
| Any OS (agent only) | `prompt-gate-agent-<os>-<arch>` |

> Builds are **not yet code-signed/notarized** — Gatekeeper/SmartScreen will warn
> (`xattr -cr` on macOS). Always [verify](verifying-releases.md) the download.

All builds embed a build-time SHA-256 of `rules/manifest.json` so tamper
detection works even before the first rule update.

## 2. Configuration (`config.yaml`)

The agent looks for `config.yaml` in the following locations, in order:

1. `$PROMPT_GATE_CONFIG` (env var, if set)
2. `$XDG_CONFIG_HOME/prompt-gate/config.yaml`
3. `~/.config/prompt-gate/config.yaml` (Linux/macOS) or
   `%APPDATA%\prompt-gate\config.yaml` (Windows)
4. `/etc/prompt-gate/config.yaml` (managed install)

Minimal example:

```yaml
upstream_dns:
  - 1.1.1.1
  - 9.9.9.9
listen_dns: 127.0.0.1:53053
listen_proxy: 127.0.0.1:8443
listen_api: 127.0.0.1:7878
rules_dir: ~/.local/share/prompt-gate/rules
log_level: info
```

Full reference is in `agent/internal/config/config.go`.

## 3. Enterprise Profiles (managed mode)

Managed-mode profiles support enrolled fleets. A profile is a YAML
file with the same shape as `config.yaml` plus an `overrides` block. It is
loaded from `profile_path` or fetched from `profile_url` on agent start and on
every rule update.

```yaml
# profile.yaml
profile_id: acme-prod-2026q2
profile_version: 7
overrides:
  category_policies:
    "AI Chat (Unsanctioned)": deny
    "Code Hosting": allow_with_dlp
  thresholds:
    critical: 1
    high: 2
  managed: true   # disables local toggles in the tray UI
```

Set `profile_url: https://mdm.example.com/profiles/prompt-gate.yaml` to fetch
the profile over HTTPS. Validation runs on every load — a malformed profile
falls back to the last good profile and logs a single line to the agent log
(no profile body is logged).

### Auto-refresh (central fleet management)

Set `profile_update_interval` (e.g. `15m`) alongside `profile_url` to have the
agent **periodically re-fetch and re-apply** the profile without a restart:

```yaml
profile_url: "https://mdm.example.com/profiles/prompt-gate.yaml"
profile_update_interval: 15m   # 0 (default) = fetch once at startup only
```

Edit the one JSON on your server and every agent picks it up within the
interval — MDM-style central management. The fetch uses HTTP conditional
requests (`If-None-Match` / `If-Modified-Since`), so an unchanged profile is a
zero-work `304 Not Modified` no-op. A failed fetch keeps the last applied
profile (the agent never reverts to an empty policy). The same SSRF guard as
the startup fetch applies. `GET /api/profile` reflects the active version.

When `managed: true`, the Electron tray UI hides the category toggles and the
Settings page shows a read-only banner with the profile ID + version.

## 4. Rule Updates

Two mechanisms:

- **Automatic**: the agent polls `manifest.json` at the configured
  `update_url` on the `update_interval` cadence (default 24h). Each entry in
  the manifest carries a SHA-256; the agent only swaps in a new rule file if
  the SHA-256 matches.
- **Manual**: `POST /api/rules/update` triggers an immediate fetch. The
  response is `{"updated":true,"version":"..."}` on success.

Both paths use the same loader, so they share the same tamper checks
(see §6).

## 5. Admin Overrides (`rules/local/`)

For per-host customization, place files under `rules_dir/local/`:

```
rules/local/
├── allow_domains.txt        # extra Tier 1 domains (one per line)
├── block_domains.txt        # extra Tier 3 domains
└── dlp_patterns_local.json  # extra DLP patterns (same schema as dlp_patterns.json)
```

Local rules are loaded after the shipped rules and override on a key-by-key
basis. Local rules are not signed and not in the manifest — they're meant for
per-host one-offs, not for fleet distribution.

## 6. Tamper Detection

On start and on every rule load, the agent recomputes the SHA-256 of every
shipped rule file and compares against `manifest.json`. A mismatch:

1. Refuses to load the modified file (the agent keeps running with the
   previous good copy).
2. Increments `tamper_detections_total` in the aggregate stats.
3. Surfaces a red tray icon and a `GET /api/status` field
   (`"tamper_state": "detected"`).

The integrity check ignores `rules/local/` so per-host overrides do not trip
the alarm.

## 7. Heartbeat

When `heartbeat_url` is set in `config.yaml` or the enterprise profile, the
agent posts a JSON heartbeat on a fixed interval (default 5 min):

```json
{
  "profile_id": "acme-prod-2026q2",
  "profile_version": 7,
  "agent_version": "0.5.0",
  "manifest_version": "rules-2026-05-13",
  "stats": {
    "dns_queries_total": 50321,
    "dns_blocks_total": 142,
    "dlp_scans_total": 8901,
    "dlp_blocks_total": 7,
    "tamper_detections_total": 0
  }
}
```

The heartbeat carries only aggregate counters — no domain names, no URLs, no
user identifiers. The receiving endpoint should reply 200 OK; non-200 responses
are retried with exponential backoff. See `agent/internal/heartbeat/`.

## 7b. Threshold alerting (SIEM / Slack webhooks)

Where the heartbeat is a *scheduled* aggregate push for dashboards, the alerter
is an *event-driven* push for incident response: it fires a webhook the moment
DLP blocks spike. Enable it in `config.yaml` (or an enterprise profile):

```yaml
alert_webhook_url: "https://hooks.slack.com/services/…"   # blank = disabled
alert_threshold_blocks: 10   # new blocks within a window that trigger an alert (min 5)
alert_interval: 5m           # polling cadence
```

When the number of new DLP blocks since the last alert reaches the threshold,
the agent POSTs:

```json
{
  "alert_type": "dlp_block_threshold",
  "agent_version": "1.0.2",
  "os_type": "darwin",
  "os_arch": "arm64",
  "blocks_in_window": 12,
  "exported_at": 1750000000
}
```

The payload is **counters-only** — no domain names, URLs, IPs, matched values,
or pattern names ever leave the device (same privacy invariant as the
heartbeat, enforced by a test). `GET /api/alerter/status` reports
`{enabled, threshold_blocks, last_fired_at, fires_total}`. HTTPS-only;
private/loopback hosts are rejected. See `agent/internal/alerter/`.

## 8. Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| Tray icon is red | Tamper detected, or agent service is down | Check `GET /api/status`; reinstall the binary if SHA-256 mismatch persists. |
| Toggle does nothing / agent never starts | `~/.prompt-gate` has wrong owner or permissions (leftover from a prior install or a run as a different user), so the agent can't read its config and exits at launch | `sudo chown -R $(whoami) ~/.prompt-gate && chmod -R u+rwX ~/.prompt-gate`, or wipe with `sudo rm -rf ~/.prompt-gate` and relaunch (the app recreates it). |
| DNS queries fail with NXDOMAIN for known-good domain | Domain is in an active blocklist | Add to `rules/local/allow_domains.txt`. |
| DLP false-positive blocks | Pattern fires on documentation/test value | File a `false_positive` issue on the GitHub repo; add a temporary exclusion in `rules/local/dlp_patterns_local.json`. |
| Profile not applied | `profile_url` returned non-200, or YAML invalid | Check the agent log for the single line emitted on profile load failure; the agent falls back to the last good profile. |
| High CPU | Likely DLP scanning very large clipboard pastes | The pipeline has a hard cap (`pipeline.maxScanBytes`) — confirm it's not been raised in a custom build. |

For deeper debugging, the agent supports `LOG_LEVEL=debug` to print per-step
pipeline timing (without logging scan content).
