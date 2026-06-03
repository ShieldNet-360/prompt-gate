# Whitepaper & Engine Foundations

*Prompt Gate DLP engine — design and mathematics. Revision 2026-05-31.*

This document describes the detection engine precisely enough to reason about
and reproduce its behaviour. Every measured figure is cross-linked to the
[Security](reports/security.md) and [Performance](reports/performance.md)
reports, which regenerate the numbers from tests.

## 1. Problem

Pattern-based DLP fails in two directions at once. Naïve regex over-fires on
documentation keys and placeholders, training users to dismiss warnings; tuned-
down regex misses obfuscated secrets. Prompt Gate is engineered **precision-
first**: keep the false-positive rate at zero on a realistic negative corpus,
then raise recall by adding patterns — never the reverse.

The engine is a pure function

```
Scan : (content) → { blocked: bool, score: int, pattern: string }
```

with no I/O and no per-event persistence (§6). This purity is what makes it
testable, fuzzable, and privacy-safe.

## 2. Pipeline

Content flows through five stages. Each stage can only *reduce* the chance of a
false block relative to raw regex:

```
content
  │  C0  Normalization        canonicalize evasion forms
  ▼
  │  C1  Public-example filter suppress known-safe sample values
  ▼
  │  C2  Aho-Corasick prematch single-pass literal hotword scan
  ▼
  │  C3  Pattern match + entropy regex on survivors, Shannon entropy
  ▼
  │  C4  Scoring + threshold    weighted evidence vs severity bar
  ▼
verdict
```

## 3. C0 — Normalization

Let `N(·)` be the normalizer. It folds homoglyphs to their ASCII skeleton,
strips zero-width / format characters (U+200B, U+2060, …), lowercases, and
expands base64 segments. The key property is **idempotence**:

```
N(N(s)) = N(s)
```

so matching on `N(s)` is stable, and an attacker cannot gain anything by
pre-applying any transform the normalizer already inverts. This is why the
`obfuscated_must_trigger` corpus scores **6/6** (homoglyph `А→A`, zero-width
splits, base64-wrapped keys all collapse to the same skeleton before matching).
Cost: 158 ns (ASCII) to 765 ns (homoglyph fold) per call — see
[Performance](reports/performance.md).

## 4. C1 — Public-example suppression

A curated set `H` holds `SHA-256` digests of well-known public sample values
(AWS docs key `AKIAIOSFODNN7EXAMPLE`, Stripe test keys, PCI test PANs, RFC 4122
documentation UUIDs, the jwt.io canonical token):

```
H = { SHA256(norm(v)) : v ∈ public examples }
isPublicExample(x) = SHA256(norm(x)) ∈ H        // O(1) average
```

`norm(·)` strips spaces, dashes, and underscores and lowercases, so
`4111 1111 1111 1111`, `4111-1111-1111-1111`, and `4111111111111111` collide to
one digest. This is an **exact-membership** set — only digests are stored, never
the raw values — so it has **zero false positives by construction** (no
probabilistic Bloom error term). It is the layer that keeps documentation keys
out of the block path, contributing directly to the measured 0 % FP rate.

## 5. C2/C3 — Matching and entropy

**Aho-Corasick.** Literal hotwords across all patterns are compiled once into a
single automaton (24.4 µs build, amortized at load). Scanning is one pass:

```
build : O(Σ |pᵢ|)           over all pattern literals pᵢ
scan  : O(n + z)            n = |content|, z = number of matches
```

i.e. independent of the *number* of patterns at scan time — adding patterns
grows the automaton, not the per-scan cost. This is why 165 patterns scan in
15.9 µs.

**Shannon entropy.** For survivors, the engine measures byte-level entropy to
distinguish high-randomness secrets (API keys, tokens) from prose:

```
H(s) = − Σ_{b=0}^{255} p_b · log₂ p_b ,   p_b = count(b)/|s|
```

with `0 ≤ H(s) ≤ 8` bits/byte. Low-entropy English prose sits well below
random-looking key material; `H` feeds the scoring step as a boost or penalty.

## 6. C4 — Scoring and threshold

Each candidate accumulates an integer score from additive evidence weights
(defaults, tunable in `dlp_config`):

| Signal | Weight |
|---|---|
| Hotword present (`HotwordBoost`) | +2 |
| High entropy (`EntropyBoost`) | +1 |
| Low entropy (`EntropyPenalty`) | −2 |
| Exclusion term present (`ExclusionPenalty`) | −3 |
| Corroborating second match (`MultiMatchBoost`) | +1 |

```
score(x) = Σ wᵢ · 1[signalᵢ(x)]
```

A pattern carries a **severity**; the verdict is

```
block(x) ⇔ score(x) ≥ τ(severity),   τ = { Critical:1, High:2, Medium:3, Low:4 }
```

More severe categories have a **lower** bar (block on weaker evidence); low-
severity categories require corroboration (score ≥ 4) before blocking. Unknown
severities fall back to the highest threshold, so unrecognized input errs toward
*allow* — surprise blocks are rare by design.

## 7. Accuracy

With `TP, FP, TN, FN` from the labelled corpus:

```
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 · Precision · Recall / (Precision + Recall)
```

Measured on `agent/internal/dlp/testdata/fp_corpus/` (16 TP, 0 FP, 77 TN, 6 FN):

```
Precision = 16/16   = 100.0 %
Recall    = 16/22   =  72.7 %
F1        = 84.2 %
FP rate   = 0/77    =   0.00 %
```

The precision-first stance is explicit: the 6 false-negatives are footer-only or
truncated secrets; none of the 77 negatives produced a false block. See the
[Security report](reports/security.md) to regenerate.

## 8. Privacy model

The engine is a pure function (§1); the surrounding agent upholds a
**zero-persistence invariant**. Let `D` be the on-disk state. The invariant is

```
D ⊆ { policy config, aggregate integer counters, rule files,
      salted allowlist hashes, opt-in consent-gated block events }
```

and, crucially, for any per-event content `c`, domain `d`, IP `a`, or user
identifier `u`:

```
c, d, a, u  ∉  D
```

This is asserted by `TestPrivacy_*`, which sweeps every text column of the
SQLite store after running scans and fails if any forbidden value appears (see
[Security report → Privacy invariant](reports/security.md#privacy-invariant)).
Scanned content lives only in memory and is garbage-collected after the verdict.

## 9. Reproducibility

Every claim here is backed by a test or benchmark:

```bash
cd agent
go test -race ./...                                            # correctness (§2–§6)
go test ./internal/dlp/ -run 'TestFPCorpus' -v                 # accuracy (§7)
go test ./internal/store/ -run TestPrivacy -v                  # privacy (§8)
go test ./internal/dlp/ -run='^$' -bench=. -benchmem           # performance (§3,§5)
go test ./internal/dlp/ -run='^$' -fuzz=FuzzPipelineScan -fuzztime=30s  # robustness
```
