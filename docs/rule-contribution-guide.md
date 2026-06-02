# Rule Contribution Guide

This guide explains how to add domains, categories, and policy actions to the
shipped ruleset. For DLP pattern changes see
[dlp-pattern-authoring-guide.md](./dlp-pattern-authoring-guide.md).

## 1. Rule files at a glance

All rule files live under [`rules/`](../rules):

```
rules/
├── manifest.json              # signed inventory (name, type, SHA-256, version)
├── ai_chat_blocked.txt        # Tier-3 AI Chat blocks
├── ai_chat_inspected.txt      # Tier-2 inspected AI Chat
├── phishing.txt               # Tier-3 phishing
├── crypto_wallets.txt         # Tier-3 crypto
├── code_hosting.txt           # Tier-2 inspected code hosting
├── ...
├── dlp_patterns.json          # DLP regex/AC patterns
└── dlp_exclusions.json        # DLP false-positive exclusions
```

Domain list files are plain text. One domain per line. Comments start with
`#`. Lines may have a **leading dot** to match the domain and all subdomains:

```
# block the entire deepseek.com tree
.deepseek.com
# block only the bare apex of evil.com
evil.com
```

Trailing whitespace, blank lines, and `#`-prefixed comments are ignored.

## 2. The three-state action model

Each category in `manifest.json` maps to one of three actions:

| Action | DNS layer | Proxy/Extension layer |
| --- | --- | --- |
| `allow` | resolve | pass-through |
| `inspect` (`allow_with_dlp`) | resolve | DLP pipeline runs on body |
| `deny` | NXDOMAIN | n/a (blocked at DNS) |

Per-category defaults are encoded in `manifest.json`:

```json
{
  "categories": [
    { "name": "AI Chat (Unsanctioned)", "default_action": "deny" },
    { "name": "AI Chat (Sanctioned)", "default_action": "inspect" },
    { "name": "Code Hosting", "default_action": "inspect" }
  ]
}
```

Users (or enterprise profiles) can override the default in
`category_policies`.

## 3. Adding a domain

1. Find the right list file under `rules/`, matching the category you want
   to extend.
2. Add the domain in alphabetical order with a leading `.` if you want
   subdomain coverage.
3. Update `manifest.json`'s `version` field and regenerate the SHA-256 for
   the list file you edited:

   ```bash
   sha256sum rules/ai_chat_blocked.txt
   ```

4. Open a PR. The CI re-verifies every checksum in `manifest.json`.

## 4. Adding a category

1. Append a new entry to `manifest.json.categories` with a clear name and
   the appropriate `default_action`.
2. Create the corresponding `.txt` file under `rules/` and add a SHA-256
   entry under `manifest.json.files`.
3. Add a brief mention in your PR description so the category purpose
   is documented.
4. If the category needs DLP coverage too, follow
   [dlp-pattern-authoring-guide.md](./dlp-pattern-authoring-guide.md).

## 5. Testing your changes locally

```bash
# unit tests cover loaders, AC, regex, hotword, entropy, exclusion,
# scoring, threshold, and pipeline integration
cd agent && make test

# manifest checksum integrity
cd agent && go test -run TestManifest ./internal/rules
```

The accuracy and integration tests in `agent/internal/dlp/` exercise the full
pattern set against the production `rules/*.json` — they will flag any
duplicate names, malformed regex, or missing required fields.

## 6. Submitting a PR

1. Branch from `main`. Use a descriptive branch name
   (`add-domain-foo`, `tighten-stripe-pattern`).
2. Keep PRs focused — one category or pattern family per PR is ideal.
3. Update [`CHANGELOG.md`](../CHANGELOG.md) if the change is
   user-visible (e.g. a new category, a behaviour change in scoring).
4. CI runs the full agent test suite, electron typecheck, and extension
   typecheck/build. PRs cannot land until CI is green.

## 7. Removing or relaxing a rule

The bar for **removing** a domain or **softening** a category is higher than
adding. Please include:

- A short rationale (e.g. *Tier-3 → Tier-2 because the domain is now widely
  used for sanctioned dev workflows*).
- Any FP/FN evidence you have (issue links, support tickets).
- A test that demonstrates the new behaviour, where applicable.

Patterns we remove or relax should leave a stub entry in the changelog so
operators know which version stopped catching the old shape.
