# DLP Pattern Authoring Guide

This guide explains how to write a DLP pattern that lands in
[`rules/dlp_patterns.json`](../rules/dlp_patterns.json) and exclusions that
land in [`rules/dlp_exclusions.json`](../rules/dlp_exclusions.json).

For non-DLP rule changes (domains, categories) see
[rule-contribution-guide.md](./rule-contribution-guide.md).

## 1. Pipeline at a glance

The DLP pipeline runs eleven steps per scan. Four accuracy layers wrap
the original seven — you do **not** need
to handle anything they already cover in your pattern's regex.

1. **A1 normalise** — strips zero-width characters, folds
   ~50 Cyrillic/Greek homoglyphs to Latin ASCII, applies NFKC, and
   appends the decoded plaintext of any inline base64 blocks. **Your
   regex sees the canonical form** — don't pre-emptively widen it for
   obfuscation, because A1 has already handled the common tricks.
2. **A2 correlate** *(optional)* — when the caller supplies a
   `session_id`, the prior paste's tail is prepended so secrets split
   across consecutive pastes line up under your pattern. No pattern
   work required.
3. **Classifier** — short-circuits obviously-empty input.
4. **Aho-Corasick** — single-pass O(n) scan for all pattern prefixes.
5. **Regex revalidation** — runs the pattern's regex on a window around each
   AC hit; eliminates AC's false positives.
6. **C1 public-example bloom** — auto-suppresses matches
   whose value is in the curated SHA-256 hash table of well-known docs
   examples (AWS canonical, Stripe test keys, RFC 4122 documentation
   UUIDs, PCI test card numbers, the jwt.io canonical token). **Do
   not add `EXAMPLE` placeholders to your exclusion list** if they're
   already in `agent/internal/dlp/bloom.go` — add them there instead.
7. **C2 placeholder shape** — auto-suppresses
   `<YOUR_KEY>`, `{{var}}`, `${VAR}`, common marker substrings
   (`your-`, `_here`, `placeholder`, `todo_`, `fixme`, `dummy_`,
   `redacted`, …), and repeated mask characters (`xxxxx`, `*****`,
   `●●●●●`). **Skip the `placeholder` / `your-` words in your
   exclusion dictionary** — C2 already handles them globally.
8. **Hotword proximity** — checks whether any of the pattern's `hotwords`
   appear within `hotword_window` bytes of the match.
9. **Entropy** — computes the Shannon entropy of `match.Value`. Values
   below `entropy_min` are penalised.
10. **Exclusion** — looks up dictionary and regex exclusions; the result is
    either *Hit* (subtracts `ExclusionPenalty`) or *SuppressEntirely*.
11. **Thresholding** — compares the aggregated score to the per-severity
    threshold (`critical=1`, `high=2`, `medium=3`, `low=4` by default).

Architecture details: [ARCHITECTURE.md](../ARCHITECTURE.md).

## 2. The pattern JSON schema

Every entry in `rules/dlp_patterns.json` is an object with these fields:

| Field | Type | Purpose |
| --- | --- | --- |
| `name` | string | Human-readable label. Must be unique across the file. Shown in tray notifications. |
| `regex` | string | Go [RE2](https://github.com/google/re2/wiki/Syntax) regex. Compiled once at load. |
| `prefix` | string | Aho-Corasick prefix. **Lowercase**, **literal** (no metacharacters). Pick the longest invariant prefix of `regex` — e.g. `AKIA` for AWS keys, `sk-ant-api03-` for Anthropic. |
| `severity` | string | One of `critical`, `high`, `medium`, `low`. Drives the threshold check. |
| `score_weight` | int | Base score contribution. Conventionally `1` for single-shot patterns, `2` for patterns whose match is structurally narrow (e.g. typed UUID-shaped key IDs). |
| `hotwords` | []string | Words that, when present near the match, **boost** the score by `hotword_boost`. Lower-cased at evaluation. |
| `hotword_window` | int | How many bytes either side of the match to look for hotwords. Defaults to 200; widen for patterns that live deep inside config files. |
| `hotword_boost` | int | Score delta when at least one hotword fires. Conventionally `2`. |
| `require_hotword` | bool | When `true`, **no** block is issued unless at least one hotword matched. Use for patterns whose regex shape is shared with benign text (e.g. generic `password = "..."`). |
| `entropy_min` | float | Below this Shannon entropy the score is **penalised** by `EntropyPenalty`. Set `0` to disable the entropy gate. |
| `min_matches` | int | (optional) Require this many distinct matches in the same content before scoring; useful for low-signal regex like 16-digit credit card shapes. |

### Example: a high-signal cloud key

```json
{
  "name": "Anthropic API Key",
  "regex": "sk-ant-api03-[A-Za-z0-9_\\-]{80,}",
  "prefix": "sk-ant-api03-",
  "severity": "critical",
  "score_weight": 1,
  "hotwords": ["anthropic", "claude"],
  "hotword_window": 200,
  "hotword_boost": 2,
  "require_hotword": false,
  "entropy_min": 4.0
}
```

### Example: a low-signal generic shape

```json
{
  "name": "Java Password Literal",
  "regex": "(?i)String\\s+(?:password|passwd|pwd|secret|apiKey)\\s*=\\s*\\\"[^\\\"\\s]{8,}\\\"",
  "prefix": "String",
  "severity": "high",
  "score_weight": 1,
  "hotwords": ["java", "class", "import", "private", "public"],
  "hotword_window": 300,
  "hotword_boost": 2,
  "require_hotword": true,
  "entropy_min": 3.0
}
```

Note `require_hotword: true` — without it the regex would flag any `String x =
"abcdefgh"` literal in any text file.

## 3. Choosing a prefix

The Aho-Corasick pass is the hot path. It scans content in O(n) for **every
prefix in the rule set at once**. A good prefix is:

- **Literal** — no `[a-z]`, no `(?:foo|bar)`, no anchors. The AC trie can't
  represent them.
- **Lower-case** — the AC scan is case-insensitive only for the lowercase
  trie. Build your prefix in lowercase.
- **As long as possible while still always present in real matches**. For
  AWS keys, `AKIA` (4 chars) is the longest invariant. For Stripe live keys,
  `sk_live_` (8 chars). Longer prefixes → fewer false hits in the AC pass →
  fewer regex calls downstream.
- **Distinctive**. Don't use `api` or `key` as a prefix — every config file
  has those words. Use the actual token prefix.

If the regex genuinely has no invariant prefix (e.g. UUIDs), omit `prefix`.
The pattern will then run via the full-content fallback path, which is slower
but still correct.

## 4. When to use `require_hotword`

Set `require_hotword: true` whenever the regex alone is **ambiguous**.
Good candidates:

- Generic password assignments (`password = "..."`).
- Bare base64-shaped strings that could be JWT bodies, signatures, or
  unrelated content.
- 16/32-hex-char shapes (`[0-9a-f]{32}`) that also match commit SHAs and
  hashed identifiers.
- Patterns whose prefix is a common word (`secret`, `token`, `key`).

If `require_hotword` is set, populate `hotwords` with terms that always
appear in legitimate use of the secret — language keywords (`fn`, `class`,
`import`), config-file conventions (`spring.datasource`, `[registries]`), or
the platform name (`anthropic`, `auth0`, `clerk`).

## 5. Setting `entropy_min`

Shannon entropy of the matched string is a cheap "is this random?" check.

| Pattern shape | Recommended `entropy_min` |
| --- | --- |
| Long base62/base64 random strings | `4.0` — `4.5` |
| Hex strings | `3.0` — `3.5` |
| Short typed IDs (e.g. 10-char Apple Team ID) | `0` (disable) |
| Username / shape-only matches | `0` (disable) |
| Mixed alpha + URL chars | `3.0` |

When in doubt, leave `entropy_min: 0`. The hotword and exclusion machinery is
usually enough to keep FP rates within budget.

## 6. Writing an exclusion

Exclusions live in `rules/dlp_exclusions.json`. Two types:

### Dictionary exclusion

```json
{
  "applies_to": "AWS Access Key",
  "type": "dictionary",
  "words": ["AKIAIOSFODNN7EXAMPLE", "AKIA1234567890123456"],
  "match_type": "exact"
}
```

- `match_type: "exact"` — `match.Value` must equal one of `words`. Suppresses
  the match entirely.
- `match_type: "proximity"` (default) — any word appearing within `window`
  bytes of the match **subtracts** `ExclusionPenalty` from the score. Does
  not suppress entirely.

`applies_to` can be `"*"` to apply to every pattern.

### Regex exclusion

```json
{
  "applies_to": "Google API Key",
  "type": "regex",
  "pattern": "AIza[A-Za-z0-9_\\-]*(?:EXAMPL|TEST|DEMO|TUTORIAL|FAKE|DummyKey)",
  "suppress": true
}
```

When `suppress: true`, a regex hit on `match.Value` removes the match
entirely (same effect as an exact dictionary hit). Without `suppress`, the
regex hit subtracts `ExclusionPenalty`.

Use the suppressing form **only** when the regex unambiguously describes
docs-only content (e.g. tokens whose body contains literal `EXAMPLE`).

## 7. Scoring formula

For each `(pattern, match)` pair the pipeline computes:

```
score = pattern.score_weight
      + (hotword_present ? HotwordBoost : 0)
      + (entropy >= entropy_min ? EntropyBoost : EntropyPenalty)
      + (exclusion_hit ? ExclusionPenalty : 0)
      + (num_matches - 1) * MultiMatchBoost
```

Defaults (from `DefaultScoreWeights` in
[`agent/internal/dlp/types.go`](../agent/internal/dlp/types.go)):

```
HotwordBoost     = +2
EntropyBoost     = +1
EntropyPenalty   = -2
ExclusionPenalty = -3
MultiMatchBoost  = +1
```

A match blocks iff `score >= threshold(severity)`. Thresholds default to
`critical=1, high=2, medium=3, low=4` and are configurable at runtime via
`PUT /api/dlp/config`.

## 8. Testing your pattern locally

Add a test case to
[`agent/internal/dlp/patterns_extended_test.go`](../agent/internal/dlp/patterns_extended_test.go).
Pattern: 2+ true-positive cases, 1+ false-positive (benign content) case.

```go
{
    label: "My new pattern - happy path",
    content: "...real-looking secret...",
    allowedPatterns: []string{"My New Pattern"},
},
```

Run only your new case:

```bash
cd agent && go test -race -count=1 -v ./internal/dlp/ \
    -run 'TestExtendedPatterns_TruePositives/My_new_pattern'
```

Then run the full corpus to confirm the FP/FN budget is still met:

```bash
cd agent && go test -race -count=1 ./internal/dlp/ \
    -run TestDLPAccuracyCorpus
```

The accuracy test asserts FP rate < 10% and FN rate < 5%.

### 8a. Run the FP-corpus benchmark

A labelled corpus lives under
[`agent/internal/dlp/testdata/fp_corpus/`](../agent/internal/dlp/testdata/fp_corpus/):

| File | Expectation |
| --- | --- |
| `public_examples_must_not_trigger.txt` | Auto-handled by C1 — if your pattern's well-known doc value isn't here, add the hash to `agent/internal/dlp/bloom.go` (not to this file). |
| `placeholders_must_not_trigger.txt` | Auto-handled by C2 — extend C2 only when a new placeholder shape appears that the marker list doesn't catch. |
| `benign_must_not_trigger.txt` | The classic FP source — prose, code with `import` / `package`, markdown links, etc. |
| `clear_secrets_must_trigger.txt` | High-signal real-looking secrets — your TPs land here. |
| `obfuscated_must_trigger.txt` | Same secrets after homoglyph swap, zero-width injection, or base64 wrap — A1 should reassemble them and your pattern should still hit. |

Run the benchmark from `agent/`:

```bash
make dlp-bench
```

Output:

```
Precision : 100.0 %  (TP / TP+FP)
Recall    :  73.0 %  (TP / TP+FN)
F1        :  84.4 %
FP rate   :   0.00 % (FP / FP+TN)
```

CI gates at `precision ≥ 90 %` and `recall ≥ 60 %`. If your new
pattern moves either past those floors, either tighten the regex,
add a hotword requirement, or extend the C1/C2 layers — do not
weaken the floors.

### 8b. Adding well-known public examples

If a real ecosystem ships a canonical "this is the docs example
value" string (the AWS `AKIAIOSFODNN7EXAMPLE` style), don't write a
dictionary exclusion — add the hash to
[`agent/internal/dlp/bloom.go`](../agent/internal/dlp/bloom.go).
That layer auto-suppresses the value across every pattern at once
and ships only the hash, not the literal string, in the binary.

Compute the hash in Go:

```go
sha256.Sum256([]byte(normalizeForBloom(value)))
```

…or pop a quick `go test ./internal/dlp/ -run TestBloom_HashHelper -v`
after wiring a one-line helper. Add a trailing comment on the map
entry naming the source value for auditability — this is the *only*
place the literal appears in the repo.

## 9. Updating the manifest

After editing `dlp_patterns.json` or `dlp_exclusions.json`, regenerate the
SHA-256 entries in `rules/manifest.json`:

```bash
cd rules
python3 - <<'PY'
import hashlib, json, pathlib
m = json.loads(pathlib.Path("manifest.json").read_text())
for f in m["files"]:
    path = pathlib.Path(f["name"])
    if path.exists():
        f["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
pathlib.Path("manifest.json").write_text(json.dumps(m, indent=2) + "\n")
PY
```

Bump `manifest_version` if the changes are user-visible.

## Contributing a pattern (the corpus gate)

Pattern contributions are welcome and **gated automatically** to protect the
precision-first invariant. When you open a PR that touches
`rules/dlp_patterns.json`, `rules/dlp_exclusions.json`, or the engine, the
**DLP corpus gate** runs:

1. Add your pattern to `rules/dlp_patterns.json`.
2. Add a real positive sample to
   `agent/internal/dlp/testdata/fp_corpus/clear_secrets_must_trigger.txt`
   (or `obfuscated_must_trigger.txt`).
3. Add any legitimate-but-safe-looking forms — values your pattern must **not**
   block — to a `*_must_not_trigger.txt` file.
4. Run it locally:
   ```bash
   cd agent && go test ./internal/dlp/ -run 'TestFPCorpus|TestDLPAccuracyCorpus' -v
   ```

The gate **fails the PR on any false positive** (a block on a known-safe value)
and on precision/recall dropping below the floors. This is what lets the project
accept community patterns safely: recall goes up for everyone, and the 0%
false-positive promise is mechanically enforced.
