# Redaction verdict — design note

Status: **proposal** (no code yet). Adds a third DLP action —
**redact** — alongside the existing `allow` / `block` so a request with
a sensitive token can proceed with the secret replaced by a typed
placeholder, instead of being rejected outright.

Motivation: blocking is all-or-nothing and punishes false positives.
Redaction lets the legit 99% of a paste through while still keeping the
secret off the wire. See the two user-raised concerns in §5 (integrity)
and §6 (history) — both are load-bearing and shape the design.

**Safety posture.** The bar for shipping is that redaction can **never
leak a secret it was meant to remove** and can **never silently corrupt
the message in a way that hides a leak**. §7 is the safety contract:
fail-closed on anything ambiguous, verify the output before it can be
sent, and never persist a value. Everything else (UX, token style) is
secondary to those guarantees.

Related: [ARCHITECTURE.md](../ARCHITECTURE.md) ·
the source-context scoring layer in `agent/internal/dlp/scorer_context.go`
(plumbing this reuses).

---

## 1. What redaction does

```
user paste → DLP scan → verdict
                         ├─ allow   → send original, untouched
                         ├─ block   → reject (today's behaviour)
                         └─ redact  → send a transformed copy:
                                      secrets swapped for typed tokens
```

Example:

| | Text |
|---|---|
| original | `deploy with AKIAIOSFODNN7EXAMPLE, ping jane@acme.com` |
| redacted | `deploy with [AWS_KEY_1], ping [EMAIL_1]` |

**Typed tokens, not blanket `****`.** `[AWS_KEY_1]` preserves the
*shape* of the request so the model can still reason ("there is an AWS
key here"); identical values map to the same token within one scan so
coreference survives. This is the single most important integrity lever
(§5).

---

## 2. Engine signature (pure, additive)

`dlp.Pipeline.Scan` stays **unchanged** — the engine-portability
invariant (`Scan` is a pure function, no I/O, compiles in every host)
is preserved. Redaction is a new sibling method, also pure:

```go
// types.go
type Redaction struct {
    PatternName string `json:"pattern_name"` // which pattern fired
    Start       int    `json:"start"`        // offset in the RETURNED text
    End         int    `json:"end"`
    Token       string `json:"token"`        // e.g. "[AWS_KEY_1]"
    // NOTE: the original matched value is deliberately NOT a field.
}

type RedactionResult struct {
    Action          string      `json:"action"`           // "allow" | "block" | "redact"
    RedactedContent string      `json:"redacted_content"` // empty unless Action=="redact"
    Redactions      []Redaction `json:"redactions,omitempty"`
    // Embeds the same decision a Scan would have produced, so callers
    // that only care about block/allow can read these directly.
    Blocked     bool   `json:"blocked"`
    PatternName string `json:"pattern_name"`
    Score       int    `json:"score"`
}

// Redact runs the same pipeline as ScanWithContext, then applies the
// redaction policy. Pure: no I/O, no globals. source may be zero.
func (p *Pipeline) Redact(ctx context.Context, content, sessionID string,
    source SourceContext) RedactionResult
```

`Redact` shares `scanImpl` with `Scan` — same Aho-Corasick + regex +
scoring path — and only diverges *after* matches are produced.

---

## 3. The offset-space gotcha (the hard part)

`Match.Start/End` (types.go:138) index into **`canonical`** — the
output of `NormalizeContent` (zero-width stripped, homoglyphs folded,
NFKC, base64-decoded blocks **appended**). They do **not** index into
the user's original `content`. Normalization is not a bijection
(base64 decode invents bytes that aren't in the original; NFKC can
change length), so we cannot naively splice tokens into the original at
those offsets — that would corrupt the message far beyond the secret.

**Rule: redact by verbatim re-location, else fall back to block.**

```
for each match m:
    idx := indexOf(original, m.Value)      // literal search in ORIGINAL
    if idx < 0:
        # the secret only exists in normalized form — e.g. it was
        # homoglyph-obfuscated or base64-hidden. We cannot safely
        # locate it in the original without risking a partial leak.
        → downgrade this scan's Action to "block"
    else:
        record Redaction{Start: idx, End: idx+len(m.Value), Token: ...}
```

This is a deliberate **fail-closed** choice: if redaction can't prove
where the secret sits in the exact bytes we're about to send, it blocks
instead of guessing. Obfuscated secrets (the normalization targets)
are precisely the adversarial case where a sloppy splice would leak a
prefix/suffix — so they hard-block, same as today.

Token assignment: a per-scan counter keyed by `(PatternName, Value)` so
the same value reuses its token (`[AWS_KEY_1]` everywhere) and distinct
values increment (`[AWS_KEY_2]`). Counter is **per-request** — it does
not persist (see §6) and there is no cross-request vault in v1 (§7).

---

## 4. Policy + API wiring (back-compatible)

### Policy

Reuse the `category_policies` map (today: `allow` /
`deny`(block) / `allow_with_dlp`). Add **`redact`** as a fourth value.
Per-category, so an org can block API keys but redact emails:

```yaml
category_policies:
  "Cloud Credentials": deny
  "PII (Email)":       redact
  "Internal Hostnames": redact
```

The redaction token template lives in pattern metadata
(`SECURITY_RULES.md` schema), default `[<CATEGORY_SLUG>_<n>]`.

### Wire (`POST /api/dlp/scan`)

Per invariant #3 (back-compat on the wire), every change is **additive
and optional**:

| Field | Direction | Notes |
|---|---|---|
| `mode` | request | `"block"` (default) \| `"redact"`. Omitted ⇒ today's behaviour exactly. |
| `action` | response | `"allow"`/`"block"`/`"redact"`. Old clients ignore it and read `blocked`. |
| `redacted_content` | response | present only when `action=="redact"`. |
| `redactions[]` | response | spans + tokens, **never the original value**. |

Old extension + old agent both keep working: an old client never sends
`mode`, so the agent runs `Scan` and returns the legacy
`{blocked,pattern_name,score}` shape. A new client talking to an old
agent gets no `redacted_content` and falls back to block. The handler
keeps the existing `req.Content = ""` drop-after-scan discipline
(handlers.go:582) — `redacted_content` is built in the same stack frame
and never persisted.

---

## 5. Concern #1 — integrity

Redaction *does* alter what the model sees; this is unavoidable for any
irreversible mask. Mitigations, in priority order:

1. **Typed, structure-preserving tokens** — `[AWS_KEY_1]` keeps the
   request intelligible; `****` does not.
2. **Stable within a scan** — repeated values share a token, so
   "use the same key as above" still resolves.
3. **Per-category policy** — redact only the categories where a
   placeholder is harmless (PII, hostnames); keep `deny` for things the
   model would need verbatim to be useful anyway (rare).
4. **Fail-closed on obfuscation** (§3) — never emit a partially-redacted
   secret.

Honest framing for the docs/UI: *redaction trades correctness for
safety.* If the model genuinely needed the real value, its answer will
be wrong — that's the cost of not leaking it. The only way to buy
correctness back is reversible tokenization (§7), and that only works on
the proxy path.

---

## 6. Concern #2 — history (reuses the block_events consent gate)

**You can have an audit trail of *what type* was redacted and *where it
went* — but never the value itself.** Storing the original (or the
masked) content would breach the privacy invariant and defeat the
product's purpose; it would need a design doc + new carve-out and I'd
refuse it by default.

The metadata trail fits the **existing** opt-in `block_events`
mechanism exactly (store.go:532, default OFF, gated in the Store layer,
trimmed to 500 rows). The `block_events.action` column is already a free
string (today always `'blocked'`). Add a sibling writer that shares the
same consent flag and table:

```go
// store.go — same gate (block_events_enabled), same table, action='redacted'
func (s *Store) InsertRedactEvent(ctx context.Context,
    eventType, host, patternName string) error
```

Recorded per redact: `timestamp, event_type, host, pattern_name,
action='redacted'`. **Not** recorded: the secret, the token, the
content, any offset. So the history can say *"a Cloud-Credentials
pattern was redacted before going to chatgpt.com at 14:03"* and nothing
more.

Privacy coverage: extend
`TestPrivacy_BlockEventsRespectConsentGate` to assert (a) redact rows
are suppressed when the gate is off, and (b) no redact row ever contains
the matched value. Add a row to the carve-out list in
[the privacy doc](PRIVACY-AUDIT.md).

Enterprise `managed=true` profiles can pin the toggle off via the
existing enterprise lockdown — no new mechanism.

---

## 7. Safety contract

These are the guarantees that gate shipping. A redactor that is fast and
pretty but violates any of these is not shippable. Each has a test.

### 7.1 Never emit a partial secret (fail-closed)

The §3 verbatim-relocation rule already blocks when a match can't be
located in the original. Two more fail-closed edges:

- **Overlapping / adjacent matches** are merged into one span before
  tokenising, so two patterns covering different slices of the same
  secret can't leave an un-redacted sliver between them.
- **Any error in the redact path** (token build, span splice, encoding)
  → return `block`, never the original. There is no "redact failed so
  send it anyway" branch.

### 7.2 Verify the output before it can leave (the key net)

After building `redacted_content`, **re-scan it through the same
pipeline**. If the re-scan still produces any match, the redaction was
incomplete → discard the redacted copy and return `block`. This is the
single most important safety check: it makes a leak require *two*
independent failures (the redactor missing a span *and* the scanner
missing it on the second pass), and it catches encoding/normalisation
surprises automatically.

```
redacted = splice(original, spans)
if Scan(redacted).Blocked:        # belt-and-braces re-scan
    return block                   # incomplete redaction — do not send
return redact(redacted, ...)
```

### 7.3 Never persist a value

Unchanged from §6: history stores `host + pattern_name + action` only —
never the value, token, content, or offsets — and is OFF by default,
gated in the Store layer. `req.Content` is dropped after the scan
(handlers.go:582); `redacted_content` lives only in the response stack
frame. Privacy test asserts no redact row ever contains a matched value.

### 7.4 Tokens can't be confused with content

- Tokens use a delimiter set that the scanner treats as inert
  (`[CATEGORY_n]`), and the redactor refuses a token template that would
  itself match a DLP pattern (checked once at rule load).
- If the original text already contains a literal `[AWS_KEY_1]`, the
  per-scan counter still allocates a fresh, unused token id so a real
  secret can't be aliased onto a pre-existing string.

### 7.5 Bounded & deterministic

- The existing `maxScanBytes` cap (handlers.go) still applies; redaction
  adds at most one extra pipeline pass (§7.2), so worst-case cost is 2×
  a scan — measure it in `dlp-bench` and keep it under the latency
  budget.
- Same input + same policy ⇒ same output (per-scan counter is
  deterministic in match order). Required so the verify-pass and tests
  are reproducible.

### 7.6 No new egress

Redaction changes *what* the user sends, never *that* something is sent
on its own. The agent still only ever returns a verdict to the local
client; it does not call out. The no-telemetry invariant in the privacy doc is
untouched.

### 7.7 Ship gates

1. Fail-closed paths (§7.1) covered, incl. an overlapping-match test.
2. Verify-pass (§7.2) implemented; test feeds a crafted input that the
   first redact misses and asserts it ends in `block`, not a leak.
3. Privacy test: redact history is value-free and consent-gated.
4. Token-collision test (§7.4).
5. `dlp-bench` shows the 2× pass stays within the latency budget.

---

## 8. Out of scope for v1 (noted for later)

- **Reversible tokenization (proxy-only).** Hold an in-memory
  `token → original` vault, redact on the request, swap originals back
  into the model's *response*. Preserves round-trip correctness — but
  only for MITM-proxy-mediated flows (not manual pastes the proxy never
  sees), adds a stateful per-session map, and that map is the most
  sensitive thing in the system (it *is* the cleartext secrets). Safety
  bar before it can ship: in-memory only (never persisted), per-session
  scoped, TTL-expired, and zeroised on session end. The stateless v1 is
  strictly safer because no such map exists — default to it.
- **Cross-request token stability.** v1 resets the counter per scan; a
  durable vault would let `[AWS_KEY_1]` mean the same thing across
  pastes, at the cost of holding cleartext mappings longer (same
  caveat).

---

## 9. Build order (when greenlit)

**Engine + API (functional core)**
1. `Redaction` / `RedactionResult` types + pure `Pipeline.Redact`
   (with the §3 verbatim-relocation + fail-closed rule) + unit tests
   incl. an obfuscation case that must downgrade to block.
2. `redact` policy value in `category_policies` + token template in
   pattern metadata.
3. Additive API fields (`mode` req; `action`/`redacted_content`/
   `redactions` resp) + a back-compat test (old request shape ⇒ legacy
   response).

**Safety nets (§7)**
4. Verify-pass re-scan (§7.2) + overlapping-span merge (§7.1) + their
   tests, incl. a crafted input the first redact misses that must end in
   `block`.
5. Token-collision guard + rule-load check that a token template can't
   itself match a pattern (§7.4).

**History + privacy gate**
6. `InsertRedactEvent` on the shared consent gate + extend the privacy
   test (value-free + gated).

**Client + docs**
7. Extension: send `mode:"redact"`, apply `redacted_content` to the
   outgoing field, surface a non-blocking "N items redacted" toast.
8. Docs: `SECURITY_RULES.md` token templates, `admin-guide.md` policy
   table, privacy-doc carve-out amendment, link this note from the doc map.

**Deferred**
9. Reversible proxy vault (§8) — only after the in-memory/TTL/zeroise
   safety bar is met.
