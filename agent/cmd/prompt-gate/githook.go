package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// hookSentinel marks a pre-commit hook as written by prompt-gate so
// uninstall never removes a hook the user wrote themselves.
const hookSentinel = "# installed by prompt-gate git-hook"

// preCommitScript is the POSIX-sh pre-commit hook. It pipes the staged
// diff through `prompt-gate scan --diff --quiet`, which exits non-zero
// when an added line matches a DLP rule. PROMPT_GATE_SKIP=1 bypasses it
// (for CI environments or deliberate overrides). It fails open (exit 0)
// if the prompt-gate binary isn't on PATH, so a shared repo's committed
// hook never breaks teammates who haven't installed it.
const preCommitScript = `#!/bin/sh
` + hookSentinel + `
# remove with: prompt-gate git-hook uninstall
[ -n "$PROMPT_GATE_SKIP" ] && exit 0
command -v prompt-gate >/dev/null 2>&1 || exit 0
git diff --cached --unified=0 --no-color --diff-filter=ACM | prompt-gate scan --diff --quiet || {
  echo "prompt-gate: commit blocked — staged content matched a DLP rule." >&2
  echo "  Review:  git diff --cached | prompt-gate scan --diff" >&2
  echo "  Bypass:  PROMPT_GATE_SKIP=1 git commit ..." >&2
  exit 1
}
`

func cmdGitHook(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "prompt-gate git-hook: expected 'install', 'uninstall', or 'status'")
		return 2
	}
	action := args[0]
	fs := flag.NewFlagSet("git-hook", flag.ContinueOnError)
	fs.SetOutput(stderr)
	hooksDir := fs.String("hooks-dir", "", "hooks directory (default: <repo>/.git/hooks)")
	force := fs.Bool("force", false, "overwrite an existing non-prompt-gate pre-commit hook")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}

	dir, err := resolveHooksDir(*hooksDir)
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	hookPath := filepath.Join(dir, "pre-commit")

	switch action {
	case "install":
		return hookInstall(hookPath, *force)
	case "uninstall":
		return hookUninstall(hookPath)
	case "status":
		return hookStatus(hookPath)
	default:
		fmt.Fprintf(stderr, "prompt-gate git-hook: unknown action %q\n", action)
		return 2
	}
}

// resolveHooksDir returns the explicit --hooks-dir if set, otherwise
// asks git for the repo's git-dir and appends /hooks.
func resolveHooksDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	out, err := exec.Command("git", "rev-parse", "--git-dir").Output()
	if err != nil {
		return "", fmt.Errorf("not a git repository (run inside a repo or pass --hooks-dir): %w", err)
	}
	return filepath.Join(strings.TrimSpace(string(out)), "hooks"), nil
}

func hookInstall(hookPath string, force bool) int {
	if existing, err := os.ReadFile(hookPath); err == nil {
		if !strings.Contains(string(existing), hookSentinel) && !force {
			fmt.Fprintf(stderr, "prompt-gate: a pre-commit hook already exists at %s\n", hookPath)
			fmt.Fprintln(stderr, "  re-run with --force to overwrite it.")
			return 1
		}
	}
	if err := os.MkdirAll(filepath.Dir(hookPath), 0o755); err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	if err := os.WriteFile(hookPath, []byte(preCommitScript), 0o755); err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	fmt.Fprintf(stdout, "prompt-gate: installed pre-commit hook at %s\n", hookPath)
	return 0
}

func hookUninstall(hookPath string) int {
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(stdout, "prompt-gate: no pre-commit hook installed")
			return 0
		}
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	if !strings.Contains(string(existing), hookSentinel) {
		fmt.Fprintln(stderr, "prompt-gate: pre-commit hook was not installed by prompt-gate; leaving it untouched")
		return 1
	}
	if err := os.Remove(hookPath); err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	fmt.Fprintln(stdout, "prompt-gate: removed pre-commit hook")
	return 0
}

func hookStatus(hookPath string) int {
	existing, err := os.ReadFile(hookPath)
	if err != nil {
		fmt.Fprintf(stdout, "prompt-gate: not installed (%s)\n", hookPath)
		return 0
	}
	if strings.Contains(string(existing), hookSentinel) {
		fmt.Fprintf(stdout, "prompt-gate: installed at %s\n", hookPath)
	} else {
		fmt.Fprintf(stdout, "prompt-gate: a non-prompt-gate pre-commit hook exists at %s\n", hookPath)
	}
	return 0
}
