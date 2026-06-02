# Packaging

Package-manager manifests for installing Prompt Gate. Hashes are taken from the
release `SHA256SUMS` and verified against the published assets.

## Homebrew (macOS, Apple Silicon)

The cask lives at [`homebrew/prompt-gate.rb`](homebrew/prompt-gate.rb).

**Install directly from a checkout:**

```bash
brew install --cask ./packaging/homebrew/prompt-gate.rb
```

**Publish for `brew install --cask ShieldNet-360/tap/prompt-gate`:**

1. Create a tap repo `ShieldNet-360/homebrew-tap`.
2. Copy the cask to `Casks/prompt-gate.rb` there.
3. Users then run `brew tap ShieldNet-360/tap && brew install --cask prompt-gate`.

> Currently Apple-Silicon only (the release ships an `arm64` `.dmg`). An Intel
> cask can be added once an `x86_64` build is published. Builds are not yet
> notarized — see the cask's caveats for the Gatekeeper workaround.

## winget (Windows)

The multi-file manifest lives in [`winget/`](winget/).

**Install directly from a checkout:**

```powershell
winget install --manifest .\packaging\winget\
```

**Publish for `winget install ShieldNet360.PromptGate`:**

Submit the three manifest files to
[microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) under
`manifests/s/ShieldNet360/PromptGate/1.0.0/`. winget validation strongly prefers
an Authenticode-signed installer; landing OS code-signing first will make the
submission smooth.

## Updating for a new release

Both manifests pin a version + SHA-256. On each release:

1. Grab the hashes from the release `SHA256SUMS`:
   ```bash
   gh release download <tag> -R ShieldNet-360/prompt-gate -p SHA256SUMS
   ```
2. Update `version` + `sha256` in `homebrew/prompt-gate.rb` and
   `PackageVersion` + `InstallerSha256` (uppercase hex) + the URL in
   `winget/*.yaml`.

This can be automated later (e.g. a release-triggered workflow that opens the
tap/winget-pkgs PRs); doing it by hand keeps the first releases simple and
reviewable.
