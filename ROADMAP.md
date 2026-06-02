# Roadmap

This roadmap describes the **product and engineering** direction of Prompt Gate.
It is a living document — priorities shift with community input. Dates are
intentionally omitted; items move by readiness, not calendar.

Discuss or propose changes in
[GitHub Discussions](https://github.com/ShieldNet-360/prompt-gate/discussions)
or by opening an issue.

## Now (in progress)

- **Detection recall.** Raise recall beyond the current 72.7% without sacrificing
  the 0% false-positive rate — the precision-first invariant is non-negotiable.
  Focus: footer-only / truncated secrets that the regex+entropy path misses today.
- **Distribution.** First-class installs via package managers (Homebrew cask,
  winget) and published browser-extension store listings.
- **Supply-chain hardening.** SBOM per release, OS code-signing + notarization,
  and raising the OpenSSF Scorecard score.

## Next

- **Classifier stage.** A lightweight on-device classifier after the regex/entropy
  stages to catch obfuscated and partial secrets, keeping the engine a pure,
  testable function (see the [whitepaper](docs/whitepaper.md)).
- **Community pattern contributions.** Make `rules/dlp_patterns.json` PR-able with
  an automatic false-positive-corpus gate, so every contributed pattern is
  regression-tested against the negative corpus before merge.
- **Fleet / managed mode.** Document and harden MDM deployment, central
  Ed25519-signed policy profiles, and consent-gated aggregate audit for teams.
- **Integrations.** Privacy-safe (aggregate-only) alerting to SIEM / Slack /
  webhooks; policy-as-code that users can version in their own repos.

## Later / exploring

- **Reproducible builds for the tray** (currently only the Go agent is
  bit-reproducible; see [reproducible-builds](docs/reproducible-builds.md)).
- **Additional platforms / browsers** beyond the current macOS/Windows/Linux +
  Chrome/Firefox/Safari matrix.
- **Third-party security audit** and published report.

## Out of scope

- Server-side / cloud logging of user activity. Prompt Gate persists **nothing**
  per-event by design ([privacy model](docs/whitepaper.md#8-privacy-model));
  features that would break that invariant are out of scope.

## Principles

1. **Precision over recall.** A false block teaches users to ignore the tool.
2. **Verifiable, not promised.** Privacy and integrity claims ship with tests
   and reproducible builds that anyone can check.
3. **Optional layers.** DNS, browser companion, and MITM proxy stack
   independently — run one or all.
