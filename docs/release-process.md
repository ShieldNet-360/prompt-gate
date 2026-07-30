# Release & hotfix process

How a Prompt Gate release is cut, what the CI does, and how to ship a
hotfix without breaking the trunk. Read alongside the root
[CHANGELOG.md](../CHANGELOG.md).

## Branch & tag model

| Ref | Role |
|---|---|
| `develop` | Working trunk. Direct push allowed. Everything lands here first. |
| `main` | Release line. Reserved for release merges + tags. |
| `config-{e,f,g,h,l}` | Long-lived engine variants. **Never** merged across configs. |
| `v{major}.{minor}.{patch}` | Annotated release tags (`git tag -a`). |
| `v{x}.{y}.{z}-config-{c}` | Per-config release tags. |

SemVer applies from `1.0.0` onward. The `0.x` line was pre-release
iteration where feature releases could break compatibility.

## What triggers what

| Workflow | Trigger | Produces |
|---|---|---|
| `release.yml` | push of any **`v*` tag** | agents ×5 platforms, electron dmg/exe/AppImage/deb, extensions (Chrome/FF/Safari), installers, **a GitHub Release** |
| `ci.yml` | push to **`main`** only | tests / vet / build gate |
| `docs.yml` | docs changes | GitHub Pages docs site |

> **Pushing to `develop` builds nothing.** Neither workflow has
> `workflow_dispatch` — the *only* way to produce a build is to cut a
> `v*` tag. CI does not run on `develop`, so run `make test` locally
> before tagging.

## Cutting a normal release

1. **Land everything on `develop`** and confirm green locally:
   ```
   cd agent && make test && make lint && make build
   make dlp-bench          # precision/recall must hold
   ```
2. **Finalize the CHANGELOG.** Move `[Unreleased]` content into a
   `## [x.y.z] — YYYY-MM-DD` section; leave a fresh empty `[Unreleased]`.
3. **Promote to `main`** (release line):
   ```
   git checkout main && git merge --no-ff develop
   git push origin main          # runs ci.yml
   ```
4. **Tag** (annotated) once CI on `main` is green:
   ```
   git tag -a vX.Y.Z -m "release: vX.Y.Z — <headline>"
   git push origin vX.Y.Z        # runs release.yml → builds + Release
   ```
5. **Edit the GitHub Release** body. `action-gh-release` runs with
   `generate_release_notes: true` (auto commit list); replace/prepend it
   with the human-written notes (template lives with the release draft).
6. **Smoke the artifacts** — download one per OS, install, toggle
   protection, confirm the agent starts.

> The release job runs under GitHub Actions with `contents: write`; no
> personal account is involved. For manual maintainer pushes, ensure your
> `gh` account has push access to the repo (a 404 on push usually means
> the active account lacks access — switch with `gh auth switch`).

## Cutting a hotfix (`x.y.Z+1`)

For an urgent fix against an already-released version:

1. **Branch from the release tag**, not from a drifted `develop`:
   ```
   git checkout -b hotfix/x.y.z+1 vX.Y.Z
   ```
2. Make the **smallest** fix. Add/adjust a regression test. Run
   `make test`.
3. Add a `## [x.y.z+1] — YYYY-MM-DD` CHANGELOG section.
4. Merge the hotfix branch into `main`, tag `vX.Y.(Z+1)`, push the tag
   (triggers the build + Release).
5. **Back-merge into `develop`** so the fix isn't lost on the next
   release:
   ```
   git checkout develop && git merge --no-ff hotfix/x.y.z+1
   git push origin develop
   ```
6. Delete the hotfix branch.

A false-positive flood is the most likely launch-day hotfix trigger;
the FP issue template feeds it. Keep the `v1.1.1` window pre-planned.

## Rolling back a bad release

The published binaries can't be un-downloaded, but you can stop new
users from getting a broken build:

1. **Mark the GitHub Release as "pre-release"** (or delete it) so it
   stops being "Latest".
2. **Delete the bad tag** if you'll re-cut the same number, or just move
   forward to the next patch (preferred — tags are cheap, history is
   clearer):
   ```
   git push origin :refs/tags/vX.Y.Z   # delete remote tag (only if re-cutting)
   ```
3. Ship the fix as a **new patch** via the hotfix flow. Don't reuse a
   tag that ever had a published Release object.
4. Note the bad version in the CHANGELOG ("yanked").

## Signing status (gap)

Builds from `release.yml` are currently **unsigned** — CI reports
"0 valid identities found" and code signing is skipped:

- **macOS:** Gatekeeper warns; users run
  `xattr -cr "/Applications/Prompt Gate.app"`.
- **Windows:** SmartScreen warns until reputation accrues.

To close this, add Developer ID / Authenticode creds as repo secrets
(`CSC_LINK`, `CSC_KEY_PASSWORD`, `APPLE_ID`,
`APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID`) and wire the electron
signing/notarize step. Until then, every release note must carry the
unsigned-install caveat.

## Gotchas the pipeline has already bitten us on

| Symptom | Cause | Fix (already in tree) |
|---|---|---|
| All 3 electron jobs crash `Cannot read properties of null (reading 'channel')` | missing `repository` field in `electron/package.json` (electron-updater needs it to resolve a publish channel) | keep the `repository` field |
| `Installer (macos)` dies `GH_TOKEN is not set` | the `make electron` path tried to auto-publish on tag | `--publish never` pinned in the `package` script; `action-gh-release` owns upload |
| Tag pushed but no Release appears | tag didn't match `v*`, or a build job failed | check Actions; the `release` job `needs` all build jobs |

**Lesson:** when changing electron-builder config, verify the
`make {macos,linux}` installer path end-to-end, not just
`electron-builder --mac` — the installer path differs from the
standalone electron jobs.

## Pre-tag checklist

The Critical column of the pre-launch checklist must be green before the
first `v*` tag: signed binaries, CHANGELOG finalized, privacy invariant
CI green on `main`, telemetry off-by-default verified, release notes
drafted, social-preview image. See the launch tracker for the live list.
