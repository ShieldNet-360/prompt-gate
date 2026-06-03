// Package dlp implements the layered Data Loss Prevention (DLP)
// pipeline described in ARCHITECTURE.md section 2. The pipeline is:
//
//	classifier → Aho-Corasick prefix scan → regex validation
//	→ hotword proximity → entropy → exclusion → scoring → threshold
//
// Privacy invariant: scan content stays in process memory only. No
// domain names, URLs, IP addresses, or matched substrings are ever
// written to disk, logged, or persisted in SQLite. Only anonymous
// integer counters (dlp_scans_total, dlp_blocks_total) cross the
// SQLite boundary.
package dlp

import "regexp"

// ContentType is the coarse classification produced by ClassifyContent.
// It is used to narrow the active pattern set for the rest of the
// pipeline.
type ContentType string

const (
	// CodeContent is source code (imports / function / class lines).
	CodeContent ContentType = "code"
	// StructuredData is JSON, CSV, key-value blocks.
	StructuredData ContentType = "structured"
	// CredentialsBlock is a block of key=value or key: value secrets.
	CredentialsBlock ContentType = "credentials"
	// NaturalLanguage is prose-like text.
	NaturalLanguage ContentType = "natural"
)

// Severity is the per-pattern severity level. Each severity has its
// own configurable threshold in the dlp_config SQLite table.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Pattern is a single DLP pattern loaded from rules/dlp_patterns.json.
// The compiled regex is filled in by LoadPatterns; callers should not
// mutate Pattern values after loading.
type Pattern struct {
	Name           string   `json:"name"`
	Regex          string   `json:"regex"`
	Prefix         string   `json:"prefix"`
	Severity       Severity `json:"severity"`
	ScoreWeight    int      `json:"score_weight"`
	MinMatches     int      `json:"min_matches,omitempty"`
	Hotwords       []string `json:"hotwords"`
	HotwordWindow  int      `json:"hotword_window"`
	HotwordBoost   int      `json:"hotword_boost"`
	RequireHotword bool     `json:"require_hotword"`
	EntropyMin     float64  `json:"entropy_min"`

	// Disabled marks a pattern as off by default. The pattern is
	// still loaded and available for override files or API toggles,
	// but LoadPatterns strips it from the active set unless an
	// override explicitly re-enables it.
	Disabled bool `json:"disabled,omitempty"`

	// Category groups patterns for selective enable/disable
	// ("PII", "cloud", "auth", …). Patterns loaded without a
	// category default to CategoryUncategorized so the toggle UI
	// still sees them.
	Category string `json:"category,omitempty"`

	// ContextBias is the source-context score. Per-pattern additive score
	// delta keyed by SourceContext.DestinationKind. Empty / missing
	// = no bias (default scoring behaviour). Example:
	//   "context_bias": { "code_host": -2, "paste_bin": +1 }
	// Pattern-level entries override the global scorer rules in
	// agent/internal/dlp/scorer.go.
	ContextBias map[string]int `json:"context_bias,omitempty"`

	// Compiled is populated by LoadPatterns; nil until compiled.
	Compiled *regexp.Regexp `json:"-"`
}

// SourceContext describes WHERE a scan
// request originates so the scorer can bias verdicts by destination
// (e.g. the same AKIA-shaped value pasted to chat.openai.com is
// exfil; the same value in a *_test.go on github.com is a fixture).
//
// Every field is optional. The browser extension fills what it can
// per interceptor (see extension/src/content/scan-client.ts); the
// agent uses what it gets. A zero-value SourceContext
// behaves identically to the plain Scan path.
//
// Privacy invariant: SurroundingHash and PageURLHash are SHA-256
// truncated to 64 bits (16 hex chars). No raw URL, no surrounding
// text, and no user identifier ever crosses this boundary.
type SourceContext struct {
	DestinationKind string `json:"destination_kind,omitempty"`
	DestinationHost string `json:"destination_host,omitempty"`
	ElementKind     string `json:"element_kind,omitempty"`
	InCodeFence     bool   `json:"in_code_fence,omitempty"`

	// LanguageHint is a code-block language tag (e.g. "yaml",
	// "javascript", "go"). Populated from a `<code
	// class="language-…">` ancestor on the focused element.
	LanguageHint string `json:"language_hint,omitempty"`

	// PathHint is the path-hint axis. A coarse classification of the
	// file path the user is interacting with on code-host
	// destinations. Values: "test" / "fixture" / "spec" / "mock" /
	// "docs" / "src" / "" (unknown). Derived by the extension from
	// the URL pathname so the agent never sees the raw path.
	//
	// The scorer adds a -1 bias when destination_kind == code_host
	// AND PathHint ∈ {test, fixture, spec, mock} — stacks with the
	// global code_host destination delta to suppress the dominant
	// real-world FP class (committed test fixtures).
	PathHint string `json:"path_hint,omitempty"`

	SurroundingHash string `json:"surrounding_hash,omitempty"`
	PageURLHash     string `json:"page_url_hash,omitempty"`
}

// IsZero reports whether source carries no information. Equivalent
// to `source == SourceContext{}` but reads better at call sites.
func (s SourceContext) IsZero() bool {
	return s == SourceContext{}
}

// CategoryUncategorized is the fallback category for patterns that
// did not declare one in dlp_patterns.json. It is exposed so callers
// (UI, tests) can refer to it without a magic string.
const CategoryUncategorized = "uncategorized"

// Candidate is a (offset, pattern) pair emitted by the Aho-Corasick
// scanner. Offsets are byte offsets into the scanned content.
type Candidate struct {
	Offset  int
	Pattern *Pattern
}

// Match is a regex-validated hit: a Pattern matched the content at
// [Start, End). The raw matched substring is held only in memory and
// must never be persisted.
type Match struct {
	Pattern *Pattern
	Start   int
	End     int
	Value   string
}

// ExclusionType is the discriminator for Exclusion entries.
type ExclusionType string

const (
	ExclusionDictionary ExclusionType = "dictionary"
	ExclusionRegex      ExclusionType = "regex"
)

// DictionaryMatchType describes how Exclusion.Words are evaluated.
type DictionaryMatchType string

const (
	// ExactMatch — the Match.Value must equal one of Words.
	ExactMatch DictionaryMatchType = "exact"
	// ProximityMatch — any of Words must appear within Window
	// bytes of the match (default mode when not specified).
	ProximityMatch DictionaryMatchType = "proximity"
)

// Exclusion is a rule that suppresses or penalises matches that look
// like known false positives (e.g. "AKIAIOSFODNN7EXAMPLE", emails on
// @example.com, the literal word "placeholder" within 50 chars).
type Exclusion struct {
	AppliesTo string              `json:"applies_to"`
	Type      ExclusionType       `json:"type"`
	Words     []string            `json:"words,omitempty"`
	Pattern   string              `json:"pattern,omitempty"`
	Window    int                 `json:"window,omitempty"`
	MatchType DictionaryMatchType `json:"match_type,omitempty"`

	// Suppress, when true on a regex exclusion, fully drops the match
	// instead of subtracting ExclusionPenalty. Use for known-doc
	// patterns such as AIza...EXAMPL... that should never count even
	// if all other signals (hotwords, entropy) line up.
	Suppress bool `json:"suppress,omitempty"`

	// Compiled is populated by LoadExclusions for regex exclusions.
	Compiled *regexp.Regexp `json:"-"`
}

// ScoreWeights holds the per-instance scoring multipliers loaded from
// the dlp_config SQLite table.
type ScoreWeights struct {
	HotwordBoost     int
	EntropyBoost     int
	EntropyPenalty   int
	ExclusionPenalty int
	MultiMatchBoost  int
}

// DefaultScoreWeights mirrors the defaults seeded into dlp_config.
func DefaultScoreWeights() ScoreWeights {
	return ScoreWeights{
		HotwordBoost:     2,
		EntropyBoost:     1,
		EntropyPenalty:   -2,
		ExclusionPenalty: -3,
		MultiMatchBoost:  1,
	}
}

// Thresholds maps each severity to the minimum score that triggers a
// block. Values mirror the dlp_config SQLite singleton.
type Thresholds struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// DefaultThresholds mirrors the defaults seeded into dlp_config.
func DefaultThresholds() Thresholds {
	return Thresholds{Critical: 1, High: 2, Medium: 3, Low: 4}
}
