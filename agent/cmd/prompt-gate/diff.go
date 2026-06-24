package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// fileChunk holds the added (`+`) lines of one file from a unified
// diff, plus the new-file line number of the first added line (for
// human-readable finding locations).
type fileChunk struct {
	File      string
	FirstLine int
	Added     []string
}

// parseUnifiedDiff extracts added lines per file from a unified diff
// stream (e.g. `git diff --cached --unified=0`). Removed and context
// lines are ignored; only `+` lines (excluding the `+++` header) are
// collected, which is exactly the content a commit introduces. Line
// numbers track the NEW file via the `@@ -a,b +c,d @@` hunk headers.
func parseUnifiedDiff(r io.Reader) ([]fileChunk, error) {
	var chunks []fileChunk
	byFile := map[string]int{} // file -> index into chunks
	cur := ""                  // current file path
	newLine := 0               // current line number in the new file

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "+++ "):
			// "+++ b/path" or "+++ /dev/null"
			p := strings.TrimPrefix(line, "+++ ")
			p = strings.TrimPrefix(p, "b/")
			if p == "/dev/null" {
				cur = ""
				continue
			}
			cur = p
		case strings.HasPrefix(line, "--- "):
			// old-file header; ignore.
			continue
		case strings.HasPrefix(line, "@@"):
			// @@ -a,b +c,d @@ — parse c (new-file start line).
			newLine = parseHunkNewStart(line)
		case strings.HasPrefix(line, "+"):
			if cur == "" {
				continue
			}
			idx, ok := byFile[cur]
			if !ok {
				chunks = append(chunks, fileChunk{File: cur, FirstLine: newLine})
				idx = len(chunks) - 1
				byFile[cur] = idx
			}
			chunks[idx].Added = append(chunks[idx].Added, strings.TrimPrefix(line, "+"))
			newLine++
		case strings.HasPrefix(line, "-"):
			// removed line — does not advance the new-file counter.
			continue
		default:
			// context line (present without --unified=0): advances new file.
			newLine++
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read diff: %w", err)
	}
	return chunks, nil
}

// parseHunkNewStart pulls the new-file start line out of a hunk header
// like "@@ -12,0 +13,4 @@ func foo()". Returns 1 on any parse miss so
// findings still get a sane line number.
func parseHunkNewStart(header string) int {
	plus := strings.Index(header, "+")
	if plus < 0 {
		return 1
	}
	rest := header[plus+1:]
	// rest = "13,4 @@ ..." or "13 @@ ..."
	end := strings.IndexAny(rest, ", ")
	if end >= 0 {
		rest = rest[:end]
	}
	n, err := strconv.Atoi(rest)
	if err != nil || n < 1 {
		return 1
	}
	return n
}

// diffFinding is one blocked file in a diff scan.
type diffFinding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	Blocked     bool   `json:"blocked"`
	PatternName string `json:"pattern_name"`
	Score       int    `json:"score"`
}

// diffResult is the aggregate JSON emitted by --staged / --diff.
type diffResult struct {
	Blocked  bool          `json:"blocked"`
	Findings []diffFinding `json:"findings"`
}

// scanDiff parses a unified diff from r, scans each file's added lines,
// and prints the verdict. With quiet, it suppresses output. Returns the
// process exit code: 1 if any file is blocked, 0 if clean, 2 on error.
func scanDiff(p *dlp.Pipeline, r io.Reader, quiet bool) int {
	chunks, err := parseUnifiedDiff(r)
	if err != nil {
		fmt.Fprintln(stderr, "prompt-gate:", err)
		return 2
	}
	res := diffResult{Findings: []diffFinding{}}
	for _, c := range chunks {
		if len(c.Added) == 0 {
			continue
		}
		sr := p.Scan(context.Background(), strings.Join(c.Added, "\n"))
		if sr.Blocked {
			res.Blocked = true
			res.Findings = append(res.Findings, diffFinding{
				File: c.File, Line: c.FirstLine, Blocked: true,
				PatternName: sr.PatternName, Score: sr.Score,
			})
		}
	}
	if !quiet {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(stdout, string(out))
	}
	if res.Blocked {
		return 1
	}
	return 0
}
