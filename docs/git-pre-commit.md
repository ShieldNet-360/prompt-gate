# Git pre-commit integration

Run the Prompt Gate DLP engine on every commit, so a secret never reaches
git history. Same engine, same 165 patterns, same adversary-aware
normalization as the browser extension and agent — on-device, nothing leaves
your machine.

## Quick install (one command)

From inside a git repository:

```bash
prompt-gate git-hook install
```

This writes a `pre-commit` hook to `.git/hooks/pre-commit`. From now on every
`git commit` scans the **staged diff** (added lines only) and aborts the
commit if any added line matches a DLP rule — printing the file and pattern
name, never the matched value.

```
$ git commit -m "wip"
prompt-gate: commit blocked — staged content matched a DLP rule.
  Review:  git diff --cached | prompt-gate scan --diff
  Bypass:  PROMPT_GATE_SKIP=1 git commit ...
```

Manage the hook:

```bash
prompt-gate git-hook status      # is it installed?
prompt-gate git-hook uninstall   # remove it (only removes a prompt-gate hook)
prompt-gate git-hook install --force   # overwrite a pre-existing pre-commit hook
```

The installed hook **fails open**: if the `prompt-gate` binary isn't on
`PATH` it exits 0, so committing a shared repo's hook never breaks teammates
who haven't installed Prompt Gate.

## Using the pre-commit framework

If your team uses [pre-commit](https://pre-commit.com), add to
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/ShieldNet-360/prompt-gate
    rev: v1.0.1
    hooks:
      - id: prompt-gate
```

Then `pre-commit install`. The hook definition lives in
`.pre-commit-hooks.yaml` at the repo root.

## Scanning diffs directly (CI)

The hook is built on two `scan` modes you can use anywhere:

```bash
# Scan the staged diff (runs `git diff --cached` for you)
prompt-gate scan --staged

# Scan any unified diff from stdin — handy in CI
git diff origin/main...HEAD | prompt-gate scan --diff

# Quiet mode: no output, exit 1 if anything is blocked (for gates)
git diff --cached | prompt-gate scan --diff --quiet
```

Both emit JSON of the form:

```json
{
  "blocked": true,
  "findings": [
    {"file": "src/config.go", "line": 42, "blocked": true,
     "pattern_name": "AWS Access Key", "score": 4}
  ]
}
```

Only **added** lines are scanned (removed and context lines are ignored), so
the hook flags new secrets without re-flagging history.
