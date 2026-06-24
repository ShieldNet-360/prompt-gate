# Signed attestation

`GET /api/attestation` returns a signed, **offline-verifiable** statement of
which Prompt Gate build is running on a machine and how it is configured. It lets
a fleet admin or auditor prove an endpoint is protected — **without collecting any
user data**. Cloud-routed DLP tools can't offer this; on-device attestation is
unique to a local agent.

## What's attested

A small JSON payload — no scanned content, URLs, or hostnames:

| Field | Meaning |
|-------|---------|
| `agent_version` | running agent version |
| `os_type`, `os_arch` | platform |
| `exported_at_unix` | when the attestation was produced |
| `dlp_pattern_count` | number of active detection patterns |
| `dlp_rules_sha256` | SHA-256 of the active rule bundle |
| `scans_total`, `blocks_total` | anonymous lifetime counters |
| `tamper_ok` | DNS + proxy enforcement intact |

## How it's signed

On first use the agent generates a per-install **Ed25519** key at
`~/.prompt-gate/attestation.key` (mode `0600`) and reuses it thereafter. The
payload is canonical JSON; the signature is over those raw bytes. The response is
an envelope:

```json
{
  "payload_b64": "<base64 of the canonical JSON payload>",
  "signature_hex": "<ed25519 signature>",
  "public_key_hex": "<verifying public key>"
}
```

The private key confers **no privilege** — it only signs attestations. Losing it
just means a new one is generated; no user data is ever at risk.

## Verify it (offline)

```sh
curl -s -H "Authorization: Bearer $(cat ~/.prompt-gate/api-token)" \
  http://127.0.0.1:9191/api/attestation | go run docs/verify-attestation.go
```

Output on success:

```
SIGNATURE VALID
device key fingerprint: b0ac9b0d6cf824bb
{"agent_version":"...","dlp_rules_sha256":"...","tamper_ok":true, ...}
```

A tampered payload prints `SIGNATURE INVALID` and exits non-zero. The verifier
(`docs/verify-attestation.go`) is standalone — no dependencies beyond the Go
standard library — so auditors can run it independently.

## Fleet use

Collect one attestation per machine (e.g. via your MDM running the curl above)
and verify them centrally. The `public_key_hex` fingerprint identifies each
device; `dlp_rules_sha256` confirms every endpoint runs the same approved rule
bundle; `tamper_ok` confirms enforcement is intact — all without any telemetry
leaving the device.
