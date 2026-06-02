# Quick Start

Get Prompt Gate running locally in under five minutes.

## Prerequisites

- macOS, Linux, or Windows
- Go 1.25+ (to build from source; or grab a signed installer from Releases)
- Node.js 22+ for the tray app and browser extension

## Build and run

```bash
git clone https://github.com/ShieldNet-360/prompt-gate.git
cd prompt-gate/agent
make build
./prompt-gate-agent --config ../config.yaml
```

In a second shell, run the tray app:

```bash
cd ../electron
npm install && npm run build && npm start
```

!!! note "Privileged DNS port"
    The default `dns_listen` port is `127.0.0.1:15353` — no `sudo` required.

## Minimal `config.yaml`

```yaml
upstream_dns: "8.8.8.8:53"
dns_listen:   "127.0.0.1:15353"
api_listen:   "127.0.0.1:9191"
db_path:      "prompt-gate.db"
rule_paths:
  - rules/ai_chat_blocked.txt
  - rules/ai_code_blocked.txt
  - rules/ai_allowed.txt
  - rules/ai_chat_dlp.txt
  - rules/phishing.txt
  - rules/social.txt
  - rules/news.txt
dlp_patterns:   rules/dlp_patterns.json
dlp_exclusions: rules/dlp_exclusions.json
```

## Enforcement presets

Three presets ship in the repo root:

| Preset | File | Audience |
|--------|------|----------|
| Personal | `config.personal.example.yaml` | Individuals, fail-open defaults |
| Team | `config.team.example.yaml` | Small teams, balanced |
| Managed | `config.managed.example.yaml` | Enterprise, fail-closed, locked policy |

## Next steps

- [Admin Guide](admin-guide.md) — installation, configuration, profiles, MDM
- [User Guide](user-guide.md) — tray icon, false-positive reporting, privacy summary
- [DLP Pattern Authoring](dlp-pattern-authoring-guide.md) — schema, scoring, hotwords, entropy, exclusions
- [Rule Contributions](rule-contribution-guide.md) — how to add domains and categories
