# Contributing to Prompt Gate

Thanks for considering a contribution. Prompt Gate is a privacy-first
local agent, so the bar for changes that touch the data path is high:
nothing scanned by the DLP pipeline or resolved by the DNS resolver
may ever be persisted to disk or transmitted off the device. Please
keep that invariant in mind as you read the rest of this guide.

## Code of conduct

By participating, you agree to abide by the project's
[Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).
We expect a professional, respectful tone in issues, pull requests,
and reviews.

## Development environment

You will need:

- Go 1.22+
- Node.js 20+ and npm 10+
- A POSIX shell (bash, zsh) — Windows users can use WSL or Git Bash
- Optional: GNU make, ripgrep, jq for the helper scripts

After cloning:

```sh
# Agent
cd agent
make build
make test

# Electron tray
cd ../electron
npm install
npm run typecheck
npm run build

# Browser extension
cd ../extension
npm install
npm run typecheck
npm run build
npm test
```

The agent listens on `127.0.0.1:9191` by default for the local HTTP
API and `127.0.0.1:15353` for DNS. Both are bound to loopback only.

## Pull request process

1. **Discuss large changes first** — open an issue describing the
   problem and the proposed direction before sending a 1000-line PR.
2. **Branch from `main`** with a descriptive name. The maintainers
   use `devin/<timestamp>-<short-description>`; community
   contributors can use any convention.
3. **Keep PRs focused.** One logical change per PR. If your branch
   does five things, please split it.
4. **Pass CI before requesting review.** The pipeline runs:
   - `go test -race -coverprofile` on the agent (the DLP package has
     an 80% coverage floor enforced in CI).
   - `npm run typecheck` and the unit test suite for both the
     Electron tray and the browser extension.
   - `go vet` and `gofmt` checks.
5. **Document the change** — update the relevant `.md` files, add or
   modify tests, and (if user-visible) add a CHANGELOG entry.
6. **Open the PR using the template.** The repo ships a PR template
   (`.github/PULL_REQUEST_TEMPLATE.md`) with a privacy-invariant
   checkbox; you must tick it.

Reviewers will look for: code that follows the existing style, tests
that cover the new behaviour, and a clear description of why the
change is needed.

## Coding standards

### Go

- `gofmt` and `go vet` clean — both run in CI.
- One package per directory; package names match the directory name.
- Public APIs are documented with godoc-style comments. Comments
  explain *why*, not *what*.
- Exported types in `internal/dlp/` MUST NOT echo scanned content
  through their wire fields. See the `FuzzPipelineScan` test for the
  invariant we enforce automatically.
- Tests use the table-driven pattern where it improves clarity.
- Avoid `interface{}` / `any`; prefer concrete types or small
  interfaces.

### TypeScript

- `tsc --strict` clean — strict mode is required in both
  `electron/tsconfig.json` and `extension/tsconfig.json`.
- No `any`. If you genuinely need an escape hatch, document why.
- Prefer functional React components and hooks over class components.
- No runtime dependencies for the extension content scripts unless
  absolutely necessary — every byte ships to every visited page.

### Tests

- Add unit tests for any new logic. Integration tests are encouraged
  but not required for trivial changes.
- The DLP package has a coverage floor of 80% enforced in CI; any
  PR that drops below it will fail.
- Tests must not depend on network access. Use `httptest.NewServer`
  for HTTP fakes and an in-process mock for DNS.

## Commit message format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short summary>

<optional body>
```

Common types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`,
`perf`. Scopes track the top-level directory the change touches:
`agent`, `electron`, `extension`, `rules`, `ci`, `docs`.

Examples:

- `feat(agent): add /api/agent/update-check endpoint`
- `fix(extension): handle paste events in shadow DOM`
- `docs: clarify dark-mode verification steps`

## A note on the hardcoded loopback bearer token

The string `prompt-gate-local-token-2025` appears as a hardcoded
bearer in three places:

- `agent/internal/api/server.go` (default `bearerToken` value for the
  local HTTP API)
- `electron/src/api/agent.ts` (the tray's API client)
- `agent/internal/api/handlers_test.go` (test fixture)

This is **intentional and not a credential leak.** The agent only
ever binds to `127.0.0.1`, and the token's job is to act as a
constant-time CSRF defense against drive-by browser requests to the
loopback API — not as a secret. Anyone with access to the host can
already read the binary, the tray bundle, or the agent's own
in-process memory; secrecy of this token gives no additional
protection. Treat it as a magic constant, not a password.

If you want a real authentication boundary for an enterprise
deployment, that belongs at the configuration-profile layer
(`config.yaml` + managed profiles), not here.

## Security

If you discover a vulnerability, please follow the disclosure
process in [SECURITY.md](SECURITY.md). Do not file a public issue.
