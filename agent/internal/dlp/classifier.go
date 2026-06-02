// Content classifier for the DLP pipeline (step 1).
//
// Fast heuristic classification (< 10 μs target). Used to narrow the
// active pattern set in later pipeline steps. The classifier is
// intentionally simple and order-dependent: code → structured →
// credentials → natural language, with a "best effort" fallback to
// NaturalLanguage when no other heuristic fires.

package dlp

import (
	"regexp"
	"strings"
)

var (
	// codeLineRE matches the start of a typical source-code line.
	// Anchored at start-of-line (multiline) for cheap scanning.
	codeLineRE = regexp.MustCompile(`(?m)^\s*(import\s+\S|from\s+\S+\s+import\s|def\s+\w+|class\s+\w+|function\s+\w+|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=|#include\s*[<"]|package\s+\w+|fn\s+\w+\(|public\s+class)`)
	// kvLineRE matches `key = value`, `key: value` and `key=value`
	// where the key is identifier-like. Useful for credential blocks
	// like .env files.
	kvLineRE = regexp.MustCompile(`(?m)^\s*[A-Za-z_][A-Za-z0-9_.\-]*\s*[:=]\s*\S`)
)

// ClassifyContent returns the best-effort content type for c. The
// classifier never returns an empty string.
func ClassifyContent(c string) ContentType {
	if c == "" {
		return NaturalLanguage
	}

	// Step 1: source code wins if we see at least two recognisable
	// import / def / class / include / package lines.
	if len(codeLineRE.FindAllStringIndex(c, 2)) >= 2 {
		return CodeContent
	}

	// Step 2: structured data — JSON-like {} blocks or consistent
	// CSV (≥3 lines with the same number of commas, ≥1 comma each).
	if looksLikeJSON(c) || looksLikeCSV(c) {
		return StructuredData
	}

	// Step 3: credentials block — many key=value lines and low
	// natural-language signal.
	kvMatches := kvLineRE.FindAllStringIndex(c, -1)
	if len(kvMatches) >= 3 && spaceRatio(c) < 0.18 {
		return CredentialsBlock
	}

	// Step 4: natural language fallback. Prose has lots of spaces
	// and low symbol density; we use a loose threshold so anything
	// short or whitespace-heavy lands here.
	return NaturalLanguage
}

// looksLikeJSON is a cheap shape check: both `{` and `}` appear and at
// least one `":"` follows a `"`.
func looksLikeJSON(c string) bool {
	if !strings.ContainsRune(c, '{') || !strings.ContainsRune(c, '}') {
		return false
	}
	return strings.Contains(c, `":`) || strings.Contains(c, `" :`)
}

// looksLikeCSV is true when at least three non-empty lines each contain
// the same number of commas (≥1).
func looksLikeCSV(c string) bool {
	lines := strings.Split(c, "\n")
	var counts []int
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		n := strings.Count(ln, ",")
		if n == 0 {
			continue
		}
		counts = append(counts, n)
	}
	if len(counts) < 3 {
		return false
	}
	first := counts[0]
	for _, n := range counts[1:] {
		if n != first {
			return false
		}
	}
	return true
}

// spaceRatio returns the fraction of runes in c that are spaces. A
// stable proxy for "prose-like" content.
func spaceRatio(c string) float64 {
	if c == "" {
		return 0
	}
	var spaces, total int
	for _, r := range c {
		total++
		if r == ' ' || r == '\t' {
			spaces++
		}
	}
	return float64(spaces) / float64(total)
}
