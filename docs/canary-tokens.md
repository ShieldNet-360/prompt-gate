# Canary tokens

AI coding agents run with broad filesystem access. Claude Code's
`--dangerously-skip-permissions`, Cursor's workspace indexing, and similar modes
let an agent read files you never intended it to — `.env`, a secrets export, a
private config — and fold the contents into a model's context window. The read
leaves no trace, and the secret is already in the context before any paste-time
DLP check runs.

**Canary tokens** are a tripwire for exactly this. You generate a fake,
key-shaped token, plant it in a file an agent should never touch, and forget
about it. If the token ever shows up in content scanned by the DLP pipeline,
Prompt Gate blocks it on-device and tells you **which** canary fired — a
specific, named, file-level signal that an agent reached somewhere it shouldn't.

This inverts the usual DLP posture: instead of only blocking *known* secrets
(reactive), a canary *detects unexpected AI context access* (active).

## How it works

A canary is just a DLP pattern with an exact-literal match and a reserved
`Canary:<label>` name, so it flows through the normal
classifier → Aho-Corasick → regex → scoring → threshold path. A match scores
high enough to block on its own — a planted canary in a prompt is unambiguous.

Canaries are stored in the local SQLite database (`dlp_canaries`) and reloaded
into the live pipeline on every agent start, so they survive restarts. Creating
or deleting one updates the running pipeline immediately — no restart needed.

### The token format

```
PGCRY <8 hex: label hash> <16 base32: random>
```

e.g. `PGCRYc79d3810KIG3L7DMAB5DJN6W`. The `PGCRY` prefix is distinctive and does
not collide with any bundled pattern prefix. The random suffix carries 80 bits
of entropy, so tokens are unguessable and collision-free.

> **Note:** the token is *not* a real secret — it's your own tripwire value, safe
> to store and to display. Unlike the feedback allowlist (which stores only
> salted hashes), the canary table stores the token in plaintext so the UI can
> show it back for copy-to-clipboard.

## API

All endpoints are local-only (`127.0.0.1:9191`) and require the agent bearer
token.

### Create a canary

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  -X POST http://127.0.0.1:9191/api/dlp/canary \
  -d '{"label":"prod_db_password_file"}'
```

```json
{
  "id": "2e4f26de693bc3342a1b8c0c8371d984",
  "label": "prod_db_password_file",
  "token": "PGCRYc79d3810KIG3L7DMAB5DJN6W",
  "created_at": 1781399968,
  "last_triggered": 0,
  "trigger_count": 0
}
```

Copy the `token` and paste it into the file you want to watch.

### List canaries

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  http://127.0.0.1:9191/api/dlp/canary
```

Returns `{"canaries": [...]}`, each with its `trigger_count` and
`last_triggered` (Unix seconds; `0` = never).

### Delete a canary

```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  -X DELETE http://127.0.0.1:9191/api/dlp/canary/<id>
```

Removes the row and deregisters the tripwire from the live pipeline.

## What happens when a canary fires

When scanned content contains a canary token, the scan returns:

```json
{"blocked": true, "pattern_name": "Canary:prod_db_password_file", "score": 100}
```

The agent bumps that canary's `trigger_count` and `last_triggered`. Attribution
is by label — the scan result carries only the pattern name, never the token, so
the privacy invariant (no scanned content persisted) holds.

## Limits & notes

- Up to **200** active canaries (each adds one pattern to the automaton).
- Labels are capped at 128 characters.
- Under an enterprise-managed (locked) profile, creating or deleting canaries
  returns `403` — the central deployment owns that surface.
- A canary's value is a tripwire, not protection: it tells you an agent *read* a
  file, it does not stop the read.
