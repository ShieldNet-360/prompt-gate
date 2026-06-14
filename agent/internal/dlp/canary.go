package dlp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// Canary tokens are user-planted tripwires: a fake, key-shaped string
// seeded into a sensitive file (.env, a secrets export, a private
// config). The token guards nothing — it exists only so that if an AI
// coding agent reads that file and folds the contents into a prompt,
// the DLP pipeline catches the token and tells the user WHICH file was
// read. This inverts the usual DLP posture from "block known secrets"
// to "detect unexpected AI context access".
//
// A canary is just a DLP Pattern with an exact-literal regex and a
// reserved name prefix, so it flows through the existing scan →
// threshold → block path unchanged. The reserved prefix lets the UI
// and the trigger-counter recognise a canary hit.

// CanaryNamePrefix is prepended to a canary's user label to form the
// Pattern.Name. The block-notification path keys on this prefix to
// render canary hits distinctively and to attribute a trigger back to
// the canary's label.
const CanaryNamePrefix = "Canary:"

// canaryTokenPrefix is the literal prefix of every generated canary
// token. It is deliberately distinctive (and absent from
// rules/dlp_patterns.json) so canary tokens never collide with a
// real-pattern prefix in the Aho-Corasick automaton.
const canaryTokenPrefix = "PGCRY"

// canaryRandBytes is the number of crypto/rand bytes in the random
// suffix. base32 (no padding) expands 10 bytes → 16 chars.
const canaryRandBytes = 10

// canaryB32 is RawStd base32 without padding, uppercased — matches the
// key-shaped look of real cloud credentials.
var canaryB32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateCanaryToken returns a fresh, unguessable canary token of the
// form PGCRY<8-hex label hash><16-char random>. The label hash makes
// the token weakly self-describing for debugging without revealing the
// label; the random suffix (80 bits) makes collisions and guessing
// infeasible. Returns an error only if the system CSPRNG fails.
func GenerateCanaryToken(label string) (string, error) {
	sum := sha256.Sum256([]byte(label))
	labelHash := hex.EncodeToString(sum[:4]) // 8 hex chars

	buf := make([]byte, canaryRandBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("canary token: read random: %w", err)
	}
	return canaryTokenPrefix + labelHash + canaryB32.EncodeToString(buf), nil
}

// CanaryName returns the Pattern.Name for a canary with the given
// label.
func CanaryName(label string) string { return CanaryNamePrefix + label }

// IsCanaryName reports whether a Pattern.Name (or a ScanResult's
// PatternName) belongs to a canary, and returns the user label.
func IsCanaryName(name string) (label string, ok bool) {
	if rest, found := strings.CutPrefix(name, CanaryNamePrefix); found {
		return rest, true
	}
	return "", false
}

// CanaryPattern builds the exact-match DLP Pattern for a canary. The
// regex is the literal token (QuoteMeta'd), severity is critical, and
// the score weight is high enough to block on a single match with no
// hotword required — a canary in a prompt is unambiguous exfil.
//
// The regex is pre-compiled: unlike file-loaded patterns (which
// LoadPatterns compiles), a canary pattern is built directly, so it
// must arrive at the pipeline with a non-nil Compiled field or
// matchRegex skips it. QuoteMeta output is always a valid regexp, so
// MustCompile cannot panic here.
func CanaryPattern(token, label string) *Pattern {
	quoted := regexp.QuoteMeta(token)
	return &Pattern{
		Name:           CanaryName(label),
		Regex:          quoted,
		Prefix:         canaryTokenPrefix,
		Severity:       SeverityCritical,
		ScoreWeight:    100,
		RequireHotword: false,
		Category:       "canary",
		Compiled:       regexp.MustCompile(quoted),
	}
}
