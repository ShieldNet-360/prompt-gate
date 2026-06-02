// Command prompt-gate is the standalone CLI for the Prompt Gate DLP
// engine. It scans content from a file or stdin against the same
// 163-pattern library the agent uses, with the full A1/A2/C1/C2 +
// F/F2 layers active.
//
// Quick start:
//
//	go install github.com/ShieldNet-360/prompt-gate/agent/cmd/prompt-gate@latest
//	echo "AKIA9P2QRMZNL5CVXBT4" | prompt-gate scan
//
// Subcommands:
//
//	scan     — read content from a file or stdin, run it through the
//	           DLP pipeline, and emit the verdict as JSON.
//	version  — print build version.
//
// Default rule files (rules/dlp_patterns.json + rules/dlp_exclusions.json)
// are auto-located by walking up from the executable or working
// directory. Override with --patterns / --exclusions when running
// from elsewhere.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// version is set at link time via -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan":
		os.Exit(cmdScan(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println("prompt-gate", version)
		os.Exit(0)
	case "help", "-h", "--help":
		usage(os.Stdout)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "prompt-gate: unknown subcommand %q\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "prompt-gate — privacy-first, adversary-aware DLP scanner")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  prompt-gate scan [flags] [file]")
	fmt.Fprintln(w, "  prompt-gate version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "If [file] is omitted or '-', content is read from stdin.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Run 'prompt-gate scan -h' for scan flags.")
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	patternsPath := fs.String("patterns", "", "path to dlp_patterns.json (default: bundled rules/)")
	exclusionsPath := fs.String("exclusions", "", "path to dlp_exclusions.json (default: bundled rules/)")
	quiet := fs.Bool("quiet", false, "exit 1 on block, 0 on allow, no output")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	patPath, excPath, err := resolveRulePaths(*patternsPath, *exclusionsPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prompt-gate:", err)
		return 2
	}

	pipeline, err := buildPipeline(patPath, excPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prompt-gate:", err)
		return 2
	}

	content, err := readContent(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "prompt-gate:", err)
		return 2
	}

	result := pipeline.Scan(context.Background(), content)
	if *quiet {
		if result.Blocked {
			return 1
		}
		return 0
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
	if result.Blocked {
		return 1
	}
	return 0
}

func resolveRulePaths(patFlag, excFlag string) (string, string, error) {
	if patFlag != "" && excFlag != "" {
		return patFlag, excFlag, nil
	}
	root, err := findBundledRules()
	if err != nil {
		return "", "", err
	}
	pat := patFlag
	if pat == "" {
		pat = filepath.Join(root, "rules", "dlp_patterns.json")
	}
	exc := excFlag
	if exc == "" {
		exc = filepath.Join(root, "rules", "dlp_exclusions.json")
	}
	return pat, exc, nil
}

// findBundledRules walks up from the executable, the cwd, and the
// source file until it finds a directory containing rules/. Lets the
// CLI work whether it was `go install`-ed alongside the rules/ dir,
// `go run`-from-checkout, or built into a standalone binary in
// `/usr/local/bin` (in which case the user should pass --patterns).
func findBundledRules() (string, error) {
	candidates := []string{}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Dir(exe))
	}
	if cwd, err := os.Getwd(); err == nil {
		candidates = append(candidates, cwd)
	}
	if _, thisFile, _, ok := runtime.Caller(0); ok {
		candidates = append(candidates, filepath.Dir(thisFile))
	}
	seen := map[string]struct{}{}
	for _, c := range candidates {
		dir := c
		for i := 0; i < 8; i++ {
			if _, dup := seen[dir]; !dup {
				seen[dir] = struct{}{}
				if _, err := os.Stat(filepath.Join(dir, "rules", "dlp_patterns.json")); err == nil {
					return dir, nil
				}
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return "", errors.New("could not locate bundled rules/dlp_patterns.json — pass --patterns and --exclusions explicitly")
}

func buildPipeline(patternsPath, exclusionsPath string) (*dlp.Pipeline, error) {
	patterns, err := dlp.LoadPatterns(patternsPath)
	if err != nil {
		return nil, fmt.Errorf("load patterns: %w", err)
	}
	exclusions, err := dlp.LoadExclusions(exclusionsPath)
	if err != nil {
		return nil, fmt.Errorf("load exclusions: %w", err)
	}
	p := dlp.NewPipeline(dlp.DefaultScoreWeights(), dlp.NewThresholdEngine(dlp.DefaultThresholds()))
	p.Rebuild(patterns, exclusions)
	return p, nil
}

func readContent(arg string) (string, error) {
	if arg == "" || arg == "-" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return "", fmt.Errorf("read stdin: %w", err)
		}
		return string(data), nil
	}
	data, err := os.ReadFile(arg)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", arg, err)
	}
	return string(data), nil
}
