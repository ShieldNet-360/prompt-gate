# Policy as code

Export the agent's category policies and DLP scoring config as a versioned
YAML file, review changes in a PR, and apply them — "terraform plan/apply for
DLP policy". Catches silent policy drift (a developer relaxing a category "just
for testing" that never gets reviewed).

## Commands

```bash
# Dump the running agent's policy to a file
prompt-gate policy export > prompt-gate-policy.yaml

# Show what would change if you applied a file (exit 1 if there are changes)
prompt-gate policy diff prompt-gate-policy.yaml

# Apply a file to the running agent
prompt-gate policy apply prompt-gate-policy.yaml
```

Flags: `--api-addr` (default `127.0.0.1:9191`), `--token` (default
`~/.prompt-gate/api-token`), and `--fail-on-relaxation` (see below).

## File format

```yaml
version: 1
categories:
  AI Chat Blocked: deny
  AI Chat DLP: allow_with_dlp
  AI Allowed: allow
dlp:
  threshold_critical: 1
  threshold_high: 2
  threshold_medium: 3
  threshold_low: 4
  hotword_boost: 2
  entropy_boost: 1
  entropy_penalty: -2
  exclusion_penalty: -3
  multi_match_boost: 1
```

The `dlp:` block is optional — omit it to manage categories only.

## CI gate

`diff` exits non-zero when the running policy differs from the committed file,
so it doubles as a drift check. `--fail-on-relaxation` narrows that to **only**
fail when a category is loosened (e.g. `deny → allow`), letting CI allow
tightening but block silent relaxations:

```yaml
- run: prompt-gate policy diff prompt-gate-policy.yaml --fail-on-relaxation
```

Action strictness order (strictest → loosest):
`deny` > `redact` > `allow_with_dlp` > `allow`.

Under an enterprise-managed (locked) profile, `apply` returns a clear `403` —
the central deployment owns those knobs.
