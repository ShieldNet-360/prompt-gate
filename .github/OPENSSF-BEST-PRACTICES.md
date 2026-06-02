# OpenSSF Best Practices — registration answers (passing level)

Prep sheet for https://www.bestpractices.dev. Register the project, then
copy these answers. After you get a project id, uncomment the badge in
`README.md` and fill the id. Mark anything below honestly — do not claim
a criterion that isn't actually met.

**Project URL:** https://github.com/ShieldNet-360/prompt-gate (update to
the final public URL — target `github.com/shieldnet360/prompt-gate`).

| Criterion | Status | Evidence / answer |
|---|---|---|
| Project homepage | MET | README + docs site (`shieldnet-360.github.io/prompt-gate`) |
| FLOSS license (OSI-approved) | MET | MIT, `LICENSE` at repo root |
| License in standard location | MET | `LICENSE` |
| Basic documentation | MET | README, `docs/` (quickstart, admin-guide, user-guide), ARCHITECTURE.md |
| Documentation of interfaces | MET | API in ARCHITECTURE.md; `docs/dlp-pattern-authoring-guide.md` |
| Public version-controlled source | MET | GitHub (git) |
| Unique version numbering | MET | SemVer annotated tags (`vMAJOR.MINOR.PATCH`) |
| Release notes per release | MET | `CHANGELOG.md` + GitHub auto-generated notes |
| Bug-reporting process | MET | GitHub Issues + `.github/ISSUE_TEMPLATE/{bug_report,feature_request}.md` |
| Vulnerability report process | MET | `SECURITY.md` (private disclosure policy) |
| Vulnerability report response | TODO | Confirm a monitored security contact / response SLA before launch |
| Working build system | MET | `make build` (Go), `npm run build` (electron/extension) |
| Automated test suite | MET | `go test -race ./...` (14 pkgs), run in `ci.yml` |
| Tests added with new functionality | MET | Repo convention: one `*_test.go` per pipeline layer |
| Compiler/lint warning flags | MET | `go vet`, staticcheck, TS typecheck in CI |
| Secure development knowledge | MET | Privacy invariant + threat boundaries documented (ARCHITECTURE.md, PRIVACY-AUDIT.md) |
| Good cryptographic practices | MET | scrypt (ops auth), Sigstore-signed releases; no home-rolled crypto in engine |
| Delivery against MITM | MET | HTTPS (GitHub Releases) + Sigstore/SLSA provenance (`docs/verifying-releases.md`) |
| Publicly-known vulns fixed | MET | govulncheck clean; CVE GO-2026-4559 patched (x/net bump) |
| Static analysis | MET | CodeQL (`codeql.yml`) + `go vet` + staticcheck |
| Dynamic analysis | MET | `FuzzPipelineScan` (627k+ execs, 0 crashers) |
| Two-person/secure CI | PARTIAL | CI green; branch protection on `main` recommended before launch |
| Signed releases | PARTIAL | Sigstore build provenance MET; **OS code-signing (Apple/Authenticode) still owed** |

**Gaps to close for a clean passing badge:**
1. Confirm + publish a monitored security response contact + target response time.
2. Enable branch protection on `main` (required reviews) — also raises OpenSSF Scorecard.
3. OS code-signing (Developer ID / Authenticode) — the one remaining "signed release" gap.

Everything else is satisfied by the current repo state.
