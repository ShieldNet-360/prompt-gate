# Governance

Prompt Gate is an open-source project under the MIT license. This document
describes how decisions are made and how contributors can take on more
responsibility over time.

## Roles

### Contributors

Anyone who opens an issue, joins a discussion, improves docs, or sends a pull
request. No formal process — see [CONTRIBUTING.md](CONTRIBUTING.md) to get
started. Good entry points are issues labelled
[`good first issue`](https://github.com/ShieldNet-360/prompt-gate/labels/good%20first%20issue)
and [`help wanted`](https://github.com/ShieldNet-360/prompt-gate/labels/help%20wanted).

### Maintainers

Contributors with merge rights and release responsibility. Maintainers:

- review and merge pull requests,
- triage issues and shepherd discussions,
- cut releases and uphold the security and privacy invariants,
- mentor new contributors.

### Becoming a maintainer

There is no quota. A contributor who has landed several non-trivial,
well-reviewed changes and shown good judgement on others' PRs may be invited by
the existing maintainers. The path is sustained, quality contribution — not a
single large patch.

## Decision-making

- **Lazy consensus.** Most changes are decided in the PR/issue. If no maintainer
  objects within a reasonable window, the change proceeds.
- **Disagreement.** Substantive disagreements are resolved by discussion among
  maintainers, seeking consensus. Where consensus cannot be reached, the
  maintainers decide.
- **Invariants are not up for casual change.** The privacy model (persist
  nothing per-event) and the precision-first detection stance are foundational.
  Changes that weaken them require an explicit, documented rationale and broad
  maintainer agreement.

## Changes to governance

This document evolves via pull request like any other file. Propose changes in
[Discussions](https://github.com/ShieldNet-360/prompt-gate/discussions) first
when they affect roles or decision-making.

## Security

Security issues follow coordinated disclosure — see
[SECURITY.md](SECURITY.md). Do not report vulnerabilities in public issues or
discussions.
