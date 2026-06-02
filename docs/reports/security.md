# Security Report

*Generated 2026-05-31 · agent commit on `main` · Go 1.26.3.*
*All results below are reproducible with the commands shown.*

## Summary

| Check | Result |
|---|---|
| `govulncheck` (reachable vulnerabilities) | **0** |
| CodeQL (Go + JS/TS) | workflow green |
| OpenSSF Scorecard | published via workflow (badge resolves after first analysis) |
| Supply-chain: SHA-pinned actions, Dependabot, SLSA provenance, Sigstore | enabled |
| DLP false-positive rate (77 negatives) | **0.00 %** |
| DLP precision | **100 %** |
| Adversarial evasion (homoglyph / zero-width / base64 / obfuscated) | all detected |
| Privacy invariant (column-sweep test) | **PASS** |

## Dependency & code scanning

```bash
cd agent
govulncheck ./...     # go install golang.org/x/vuln/cmd/govulncheck@latest
```

`govulncheck` result: **"No vulnerabilities found. Your code is affected by 0
vulnerabilities."** It additionally notes 2 vulnerabilities in imported packages
and 6 in required modules that are **not reachable** from Prompt Gate's call
graph (we don't call the affected symbols).

- **CodeQL** runs on every push/PR over both the Go agent and the
  JS/TS extension + tray (`.github/workflows/codeql.yml`).
- **OpenSSF Scorecard** runs weekly + on push (`.github/workflows/scorecard.yml`)
  and publishes to the public Scorecard API.
- All GitHub Actions are **SHA-pinned**; **Dependabot** keeps them and the
  gomod/npm dependency trees current.

## Detection accuracy & adversarial resistance

The labelled false-positive corpus
(`agent/internal/dlp/testdata/fp_corpus/`) splits into `*_must_trigger` and
`*_must_not_trigger` files:

```bash
go test ./internal/dlp/ -run 'TestFPCorpus|TestDLPAccuracyCorpus' -v
```

| Corpus file | Expectation | TP | FP | TN | FN |
|---|---|---|---|---|---|
| `clear_secrets_must_trigger.txt` | BLOCK | 10 | 0 | 0 | 6 |
| `obfuscated_must_trigger.txt` | BLOCK | 6 | 0 | 0 | 0 |
| `public_examples_must_not_trigger.txt` | ALLOW | 0 | 0 | 24 | 0 |
| `placeholders_must_not_trigger.txt` | ALLOW | 0 | 0 | 29 | 0 |
| `benign_must_not_trigger.txt` | ALLOW | 0 | 0 | 24 | 0 |

```
Precision : 100.0 %  (16 / 16)
Recall    :  72.7 %  (16 / 22)
F1        :  84.2 %
FP rate   :  0.00 %  (0 / 77)
```

**Adversarial evasion** is handled at the normalization stage — homoglyph
folding, zero-width stripping, and base64 decoding all run before matching, so
`obfuscated_must_trigger.txt` scores **6/6 detected** and public sample keys
(e.g. `AKIAIOSFODNN7EXAMPLE`) are correctly **allowed** via the public-example
hash set. The math behind precision/recall and normalization is documented in
the [Whitepaper](../whitepaper.md).

**Why recall is 72.7 %, honestly:** the 6 false-negatives are footer-only or
truncated secrets (e.g. a lone `-----END RSA PRIVATE KEY-----` line, a
fragment of a JWT). Prompt Gate is tuned **precision-first** — a 0 % false-
positive rate is what keeps users from training themselves to ignore the tool.
Recall improves as patterns are added; precision is the invariant we protect.

## Privacy invariant {#privacy-invariant}

The core privacy guarantee — the agent persists **zero** per-event content,
domains, IPs, or user identifiers — is enforced by tests, not documentation:

```bash
go test ./internal/store/ -run TestPrivacy -v
```

| Test | Asserts |
|---|---|
| `TestPrivacy_NoAccessTablesAndNoDomainsPersisted` | no access/domain rows reach disk |
| `TestPrivacy_DLPScanContentNotPersisted` | scanned content is never written |
| `TestPrivacy_BlockEventsRespectConsentGate` | block-event log stays empty unless explicitly opted in |

All three **PASS**. Only aggregate integer counters, salted allowlist hashes,
and (opt-in) consent-gated block events may ever be persisted.

## Coordinated disclosure

Vulnerabilities should be reported per
[`SECURITY.md`](https://github.com/ShieldNet-360/prompt-gate/security/policy).
Please do not open public issues for security reports.
