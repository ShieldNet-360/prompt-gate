# Verifying releases

Every Prompt Gate release artifact is published with a **Sigstore-backed
SLSA build provenance attestation** and a `SHA256SUMS` checksum file. The
provenance is generated keylessly in CI (GitHub OIDC → Fulcio → Rekor),
so there is no long-lived signing key to trust or leak.

## Verify provenance

Requires the GitHub CLI (`gh`):

```bash
gh attestation verify prompt-gate-agent-darwin-arm64 \
  --repo ShieldNet-360/prompt-gate
```

A successful check confirms the binary was built by this repo's
`Release` workflow from the tagged commit — not rebuilt or tampered with
after the fact. It prints the source repo, the workflow that produced it,
and the commit SHA.

## Verify checksums

```bash
# from the directory containing the downloaded artifacts + SHA256SUMS
sha256sum --check SHA256SUMS
```

## What this does and doesn't cover

- **Covers:** artifact integrity (checksums) and build provenance (who/
  what/where built it), cryptographically signed via Sigstore.
- **Does not yet cover:** OS-level code signing. macOS builds are not
  Apple Developer ID signed/notarized yet, so Gatekeeper will still warn
  (`xattr -cr <app>` to clear the quarantine flag). Windows builds are
  not Authenticode signed. Both are tracked as owed release work.
