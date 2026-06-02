// Package rules parses one-domain-per-line rule files and provides an
// in-memory lookup keyed by domain. The file format is:
//
//	# comments and blank lines are ignored
//	example.com         # exact match only
//	.example.com        # include all subdomains
package rules

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// ParseFile reads a rule file and returns its raw entries. Entries that
// begin with a leading "." retain the dot to signal "match subdomains too".
func ParseFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open rule file %q: %w", path, err)
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow trailing comments after whitespace.
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
			if line == "" {
				continue
			}
		}
		out = append(out, strings.ToLower(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read rule file %q: %w", path, err)
	}
	return out, nil
}
