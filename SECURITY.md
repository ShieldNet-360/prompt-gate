# Security policy

## Reporting a vulnerability

If you discover a security vulnerability in Prompt Gate, please
report it privately so we can investigate and ship a fix before any
public disclosure.

**Contact:** open a draft GitHub security advisory at
<https://github.com/ShieldNet-360/prompt-gate/security/advisories/new>.

If you can't use GitHub's security advisories, file a public issue
that says only "security report — please contact me" and we'll
respond with an alternate contact channel. **Do not include any
exploit details in a public issue.**

We aim to acknowledge new reports within **two business days** and
ship a fix within **30 days** of confirmation. Reports that affect
the privacy guarantees in [the threat model](#threat-model) — for
example, anything that causes scanned content, domain names, or
IP addresses to leak off-device — are treated as high-severity and
prioritised accordingly.

## Supported versions

Until Prompt Gate reaches 1.0.0, only the latest minor release is
supported with security fixes. Older 0.x releases will not receive
back-ported patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

## Threat model

Prompt Gate runs entirely on the user's device. The security
guarantees that we consider in-scope for this policy are:

1. **Privacy invariants** — the DLP pipeline must never persist
   scanned content, domain names, URLs, or IP addresses. The DNS
   resolver must never log queried names. Violations of this
   invariant are treated as **critical**, even if no remote code
   execution is involved.
2. **Local API confinement** — the local HTTP API on
   `127.0.0.1:9191` must reject requests from any non-loopback
   origin. Bypasses of the loopback check are **high-severity**.
3. **Self-update authenticity** — the agent's self-update path must
   reject release binaries whose SHA-256 or Ed25519 signature does
   not match the published manifest. Any path that lets an attacker
   inject a binary is **critical**.
4. **MITM proxy CA confinement** — the proxy's per-installation CA
   must be installed only in the user's trust store, must be
   removable via the GUI, and must not be re-used across
   installations. Issues here are **high-severity**.

The following are explicitly **out of scope**:

- Vulnerabilities in upstream Go, Node.js, or Electron releases. We
  pick them up with our next dependency bump rather than filing
  duplicate advisories.
- Issues that require physical access to the device or root-level
  write access to the agent's binary directory.
- Denial-of-service attacks from the same loopback origin (a
  misbehaving local browser extension could overwhelm the agent;
  the documented mitigation is the rate limiter on
  `/api/dlp/scan`).
- Side-channel attacks against the local CPU.

## Responsible disclosure

If your report is valid and we ship a fix, we will credit you in
the release notes unless you ask us not to. Please do not publish
the details of the vulnerability before we publish the fix.
