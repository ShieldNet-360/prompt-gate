// Code-context router — placeholder-shape layer in the DLP pipeline.
//
// IsPlaceholderShape returns true if a value looks like a template
// placeholder rather than a real secret:
//   - Bracket templates: <YOUR_API_KEY>, <INSERT_HERE>
//   - Common markers: "your-", "_here", "PLACEHOLDER", "INSERT_", "REPLACE_",
//     "TODO", "FIXME", "EXAMPLE_"
//   - Masked literals: xxxxxxxxxx, ●●●●●●●●, **********
//
// Placeholders that have plausible entropy and pattern shape are
// invisible to entropy filters alone — this function complements
// entropy by catching "your-secret-here" and "<API_KEY>" style values
// that the deterministic core would otherwise score above threshold.
//
// Privacy invariant: pure string-in/bool-out, no state, no I/O.

package dlp

import (
	"strings"
	"unicode"
)

// placeholderMarkers lists case-insensitive substrings that strongly
// indicate a value is a template placeholder, not a real secret.
var placeholderMarkers = []string{
	"your_", "your-", "yourkey", "your.key",
	"insert_", "insert-",
	"replace_", "replace-",
	"example_", "example-", "_example",
	"_here", "-here",
	"placeholder",
	"todo_", "todo-", "_todo",
	"fixme",
	"sample_", "sample-",
	"dummy_", "dummy-",
	"my_secret", "my-secret",
	"redacted",
}

// maskChars is the set of common masking characters that, when
// repeated, indicate a redacted or template value.
var maskChars = "xXoO*#●•⋆⁂_"

// IsPlaceholderShape reports whether value is a recognisable template
// placeholder.
func IsPlaceholderShape(value string) bool {
	if len(value) < 4 {
		return false
	}

	// 1. <YOUR_KEY> / <INSERT> — bracketed template
	if strings.HasPrefix(value, "<") && strings.HasSuffix(value, ">") && len(value) >= 5 {
		inner := value[1 : len(value)-1]
		if isTemplateContent(inner) {
			return true
		}
	}

	// 2. {{var}} / ${var} — interpolation syntax
	if (strings.HasPrefix(value, "{{") && strings.HasSuffix(value, "}}")) ||
		(strings.HasPrefix(value, "${") && strings.HasSuffix(value, "}")) {
		return true
	}

	// 3. Substring marker match — case-insensitive
	lower := strings.ToLower(value)
	for _, m := range placeholderMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}

	// 4. Repeated mask character — "xxxxxxxxxxxxxxxx", "***********"
	if isAllSameMaskChar(value) {
		return true
	}

	return false
}

// isTemplateContent returns true if s looks like a template name —
// uppercase ASCII letters, digits, underscores, hyphens, spaces only,
// with at least one letter (so "1234" is rejected but "API_KEY" passes).
func isTemplateContent(s string) bool {
	if s == "" {
		return false
	}
	hasLetter := false
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			hasLetter = true
		case r >= 'a' && r <= 'z':
			hasLetter = true
		case r >= '0' && r <= '9', r == '_', r == '-', r == ' ', r == '.':
			// allowed
		default:
			return false
		}
	}
	return hasLetter
}

// isAllSameMaskChar returns true if value, after ignoring separators,
// consists of a single recognised mask character repeated at least 6
// times.
func isAllSameMaskChar(value string) bool {
	var first rune
	n := 0
	for _, r := range value {
		if r == ' ' || r == '-' || r == '_' || r == '\t' || r == '.' {
			continue
		}
		if n == 0 {
			first = r
			if !strings.ContainsRune(maskChars, first) && !isControlOrPunct(first) {
				// not a recognised mask character — bail
				return false
			}
		} else if r != first {
			return false
		}
		n++
	}
	return n >= 6
}

func isControlOrPunct(r rune) bool {
	return unicode.IsControl(r) || unicode.IsPunct(r) || unicode.IsSymbol(r)
}
