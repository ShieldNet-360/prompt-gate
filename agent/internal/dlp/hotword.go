// Hotword proximity checker (pipeline step 4a).
//
// Many DLP patterns benefit from contextual confirmation: an "AKIA..."
// string is much more likely to be a real AWS key when the word "aws"
// or "access_key" appears nearby. The hotword check looks N bytes
// around each match for any of the pattern's configured hotwords.

package dlp

import "strings"

// CheckHotwords returns true if any of pattern.Hotwords appears within
// pattern.HotwordWindow bytes of the match. The match itself is excluded
// from the haystack so the hotword cannot accidentally be the matched
// substring. Matching is case-insensitive.
//
// A pattern with no hotwords or hotword_window == 0 returns false (no
// boost). Callers (the scorer) decide what to do with that result —
// patterns with require_hotword=true should be filtered out higher up.
func CheckHotwords(content string, match Match, pattern Pattern) bool {
	if len(pattern.Hotwords) == 0 || pattern.HotwordWindow <= 0 {
		return false
	}
	if match.Start < 0 || match.End > len(content) || match.Start >= match.End {
		return false
	}

	start := match.Start - pattern.HotwordWindow
	if start < 0 {
		start = 0
	}
	end := match.End + pattern.HotwordWindow
	if end > len(content) {
		end = len(content)
	}

	before := strings.ToLower(content[start:match.Start])
	after := strings.ToLower(content[match.End:end])

	for _, hw := range pattern.Hotwords {
		hw = strings.ToLower(strings.TrimSpace(hw))
		if hw == "" {
			continue
		}
		if strings.Contains(before, hw) || strings.Contains(after, hw) {
			return true
		}
	}
	return false
}
