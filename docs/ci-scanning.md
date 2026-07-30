# CI scanning & SARIF

Run the Prompt Gate DLP engine over a whole repository in CI and surface
findings as native **GitHub Code Scanning** alerts — same on-device engine,
same patterns, no desktop app required.

## Directory scan

```bash
# Recursively scan a tree; JSON summary
prompt-gate scan --dir .

# Emit SARIF 2.1.0 for GitHub Code Scanning
prompt-gate scan --dir . --sarif > prompt-gate.sarif

# Quiet gate: exit 1 if anything is blocked
prompt-gate scan --dir . --quiet
```

JSON summary shape:

```json
{
  "scanned": 128,
  "blocked": 1,
  "findings": [
    {"file": "src/config.go", "blocked": true,
     "pattern_name": "AWS Access Key", "score": 4}
  ]
}
```

Binary files (NUL byte in the first 8 KiB) and files over 1 MiB are skipped,
along with `.git`, `node_modules`, `vendor`, `.hg`, and `.svn` directories.

> **Privacy:** SARIF output references the **file and pattern name only** —
> never the matched value. Findings are reported at file granularity
> (`startLine: 1`); the engine does not emit secret offsets.

## GitHub Actions

Use the bundled composite action — it installs the CLI, fetches the rule set
at the pinned ref, scans, and writes SARIF:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - id: pg
    uses: ShieldNet-360/prompt-gate@v1.1.1
    with:
      path: '.'
      sarif-file: 'prompt-gate.sarif'
  - uses: github/codeql-action/upload-sarif@v3
    if: always()
    with:
      sarif_file: 'prompt-gate.sarif'
  - if: steps.pg.outputs.blocked == 'true'
    run: exit 1
```

A complete, copy-pasteable workflow lives at
`.github/workflows/dlp-scan-example.yml`. The action exposes a `blocked`
output (`true`/`false`) so you decide whether a finding fails the build.
