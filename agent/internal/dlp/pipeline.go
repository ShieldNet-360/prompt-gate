// DLP pipeline orchestrator.
//
// The Pipeline owns the compiled patterns, exclusions, Aho-Corasick
// automaton, scoring weights, and threshold engine. Scan(content) runs
// every step from classification through the threshold check and
// returns the final block decision plus the pattern responsible.
//
// Privacy invariant: the only state held by Pipeline that depends on
// the scanned content is local to Scan — it returns to the caller and
// is then garbage-collected. Nothing about the scanned content is
// persisted to disk or logged.

package dlp

import (
	"context"
	"runtime"
	"sort"
	"sync"
)

// LargeContentThreshold is the byte threshold above which Pipeline
// drops low-severity patterns from the candidate set. Configurable per
// pipeline via SetLargeContentThreshold; the default matches the
// `large_content_threshold` setting in config.yaml.
const LargeContentThreshold = 50 * 1024

// ConcurrentEvalThreshold is the byte threshold above which the
// pipeline evaluates per-pattern groups concurrently. Below this the
// sequential path is cheaper because of goroutine setup overhead.
const ConcurrentEvalThreshold = 10 * 1024

// ScanResult is what Pipeline.Scan returns. PatternName is empty when
// Blocked is false. Score is the highest score across all matches.
type ScanResult struct {
	Blocked     bool   `json:"blocked"`
	PatternName string `json:"pattern_name"`
	Score       int    `json:"score"`
}

// Pipeline ties all the DLP pipeline steps together.
type Pipeline struct {
	mu sync.RWMutex

	patterns       []*Pattern
	automaton      *Automaton
	exclusions     []Exclusion
	weights        ScoreWeights
	threshold      *ThresholdEngine
	largeThreshold int

	// disabledCategories holds the set of pattern categories that
	// should be skipped at scan time. Empty by default (all
	// categories active).
	disabledCategories map[string]struct{}

	// cache deduplicates identical pastes that arrive in rapid
	// succession (paste + form-submit + fetch interceptors).
	cache *ScanCache

	// correlator carries a short tail of the most recent paste per
	// session, enabling multi-piece exfil detection. Optional;
	// nil disables correlation (default).
	correlator *Correlator

	// allowlist is the per-user feedback store.
	// When set, every match value is checked against it after the
	// public-example/placeholder short-circuits and BEFORE scoring; a hit drops the
	// match silently. Nil disables H (default).
	allowlist *Allowlist
}

// NewPipeline returns an empty pipeline. Callers must call Rebuild
// before Scan returns useful results — Scan on an empty pipeline always
// returns Blocked=false.
func NewPipeline(weights ScoreWeights, threshold *ThresholdEngine) *Pipeline {
	if threshold == nil {
		threshold = NewThresholdEngine(DefaultThresholds())
	}
	return &Pipeline{
		weights:        weights,
		threshold:      threshold,
		largeThreshold: LargeContentThreshold,
	}
}

// SetLargeContentThreshold updates the byte threshold above which the
// pipeline switches to "critical/high only" scanning. Zero or negative
// values restore the default LargeContentThreshold. Safe to call
// concurrently with Scan. The scan cache is reset alongside the
// update so cached verdicts produced under the previous threshold
// cannot leak past the change.
func (p *Pipeline) SetLargeContentThreshold(n int) {
	if n <= 0 {
		n = LargeContentThreshold
	}
	p.mu.Lock()
	p.largeThreshold = n
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// LargeContentThreshold returns the current threshold in bytes.
func (p *Pipeline) LargeContentThreshold() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.largeThreshold <= 0 {
		return LargeContentThreshold
	}
	return p.largeThreshold
}

// SetDisabledCategories replaces the set of disabled pattern
// categories. Pass an empty slice to re-enable all categories. The
// agent UI uses this to let operators turn off PII or low-severity
// pattern groups without editing the rule file. The scan cache is
// reset alongside the update so verdicts produced before a category
// was disabled (or re-enabled) cannot survive the change.
func (p *Pipeline) SetDisabledCategories(categories []string) {
	disabled := make(map[string]struct{}, len(categories))
	for _, c := range categories {
		if c == "" {
			continue
		}
		disabled[c] = struct{}{}
	}
	p.mu.Lock()
	p.disabledCategories = disabled
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// DisabledCategories returns the current set of disabled categories.
// The returned slice is a snapshot and safe for the caller to mutate.
func (p *Pipeline) DisabledCategories() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]string, 0, len(p.disabledCategories))
	for c := range p.disabledCategories {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Categories returns the sorted list of distinct pattern categories
// currently loaded. Used by the Electron UI's Rules page.
func (p *Pipeline) Categories() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	seen := make(map[string]struct{}, 16)
	for _, pat := range p.patterns {
		c := pat.Category
		if c == "" {
			c = CategoryUncategorized
		}
		seen[c] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for c := range seen {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Rebuild atomically swaps in a new pattern set, automaton, and
// exclusion list. Called on agent startup and whenever rule files are
// updated (POST /api/rules/update or future automatic rule sync).
func (p *Pipeline) Rebuild(patterns []*Pattern, exclusions []Exclusion) {
	auto := BuildAutomaton(patterns)
	p.mu.Lock()
	p.patterns = patterns
	p.automaton = auto
	p.exclusions = exclusions
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// EnableCache attaches a ScanCache to the pipeline. Passing nil
// disables caching (useful for tests). Safe to call concurrently with
// Scan.
func (p *Pipeline) EnableCache(c *ScanCache) {
	p.mu.Lock()
	p.cache = c
	p.mu.Unlock()
}

// Cache returns the attached ScanCache, or nil if caching is disabled.
func (p *Pipeline) Cache() *ScanCache {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cache
}

// SetWeights atomically updates the scoring weights. The scan cache
// is reset alongside the update so verdicts produced under the
// previous weights cannot leak past the change — otherwise a PUT
// /api/dlp/config that raises a hotword/entropy boost would only
// take effect after the cache TTL expired.
func (p *Pipeline) SetWeights(w ScoreWeights) {
	p.mu.Lock()
	p.weights = w
	cache := p.cache
	p.mu.Unlock()
	cache.Reset()
}

// ResetCache drops every cached scan result. Exposed so callers that
// mutate state outside the pipeline's setters — most notably
// Threshold().Set() on the embedded ThresholdEngine — can keep the
// cache in sync with the live policy. A nil cache is a no-op.
func (p *Pipeline) ResetCache() {
	p.mu.RLock()
	cache := p.cache
	p.mu.RUnlock()
	cache.Reset()
}

// Threshold returns the threshold engine. Used by the API to expose
// GET /api/dlp/config and PUT /api/dlp/config.
func (p *Pipeline) Threshold() *ThresholdEngine { return p.threshold }

// Patterns returns a snapshot of the loaded patterns. Used for tests
// and introspection only — callers must not mutate the slice.
func (p *Pipeline) Patterns() []*Pattern {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*Pattern, len(p.patterns))
	copy(out, p.patterns)
	return out
}

// EnableCorrelator turns on multi-piece detection. Pass nil to
// disable. Safe to call concurrently with Scan.
func (p *Pipeline) EnableCorrelator(c *Correlator) {
	p.mu.Lock()
	p.correlator = c
	p.mu.Unlock()
}

// Correlator returns the active multi-piece correlator, or nil if correlation
// is disabled.
func (p *Pipeline) Correlator() *Correlator {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.correlator
}

// EnableAllowlist turns on per-user feedback suppression.
// Pass nil to disable. Safe to call concurrently with Scan.
func (p *Pipeline) EnableAllowlist(a *Allowlist) {
	p.mu.Lock()
	p.allowlist = a
	cache := p.cache
	p.mu.Unlock()
	// Reset the scan cache because allowlist additions can flip a
	// previously-blocked content into allowed and vice versa.
	cache.Reset()
}

// Allowlist returns the active allowlist, or nil if H is disabled.
func (p *Pipeline) Allowlist() *Allowlist {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.allowlist
}

// Scan runs the full DLP pipeline on content and returns the highest
// scoring match's decision. ctx is honoured at the entry point only;
// individual pipeline steps are bounded and complete quickly.
func (p *Pipeline) Scan(ctx context.Context, content string) ScanResult {
	return p.scanImpl(ctx, content, "", SourceContext{})
}

// ScanSession is the session-aware variant of Scan. When sessionID is
// non-empty and a correlator is enabled (see EnableCorrelator), content
// is combined with the session's prior paste tail so that
// secrets split across consecutive pastes can be detected. Pass an
// empty sessionID to behave identically to Scan.
func (p *Pipeline) ScanSession(ctx context.Context, content, sessionID string) ScanResult {
	return p.scanImpl(ctx, content, sessionID, SourceContext{})
}

// ScanWithContext is the source-context entrypoint. It accepts the
// SourceContext the caller (typically the browser extension)
// collected about WHERE the scan is happening — destination host /
// kind, DOM element type, code-fence flag, language hint, and
// content-derived hashes. The scorer biases verdicts by this
// context (the scoring stage wires source through but the
// consult it). Pass an empty SourceContext{} to behave identically
// to ScanSession.
func (p *Pipeline) ScanWithContext(
	ctx context.Context,
	content, sessionID string,
	source SourceContext,
) ScanResult {
	return p.scanImpl(ctx, content, sessionID, source)
}

func (p *Pipeline) scanImpl(
	ctx context.Context,
	content, sessionID string,
	source SourceContext,
) ScanResult {
	if err := ctx.Err(); err != nil {
		return ScanResult{}
	}

	p.mu.RLock()
	auto := p.automaton
	exclusions := p.exclusions
	weights := p.weights
	threshold := p.threshold
	largeThreshold := p.largeThreshold
	disabledCats := p.disabledCategories
	cache := p.cache
	correlator := p.correlator
	allowlist := p.allowlist
	p.mu.RUnlock()

	// Cache only valid for stateless / context-free scans — same
	// content in different sessions, different source contexts
	// (source context), or with an allowlist present (scope
	// matching is destination-aware so we cannot dedupe by content
	// alone) may produce different verdicts. The cache key is
	// `content` only, so any caller-supplied state must bypass the
	// lookup AND the write below.
	cacheable := cache != nil && sessionID == "" && source.IsZero() && allowlist == nil
	if cacheable {
		if cached, ok := cache.Lookup(content); ok {
			return cached
		}
	}

	if auto == nil || threshold == nil {
		return ScanResult{}
	}
	if largeThreshold <= 0 {
		largeThreshold = LargeContentThreshold
	}

	// Normalize content (strip zero-width, fold homoglyphs,
	// NFKC, append base64-decoded blocks). Downstream stages
	// operate on the canonical form; cache keys remain the raw
	// input so callers get deterministic per-input results.
	canonical := NormalizeContent(content)

	// If the correlator is enabled and a session_id is supplied,
	// prepend the session's prior paste tail so split-across-pastes
	// secrets can be reassembled. No-op when correlator is nil or
	// sessionID is empty.
	if correlator != nil && sessionID != "" {
		canonical, _ = correlator.Combine(sessionID, canonical)
	}

	// Step 1: classify content — currently used to short-circuit
	// scans of obviously-empty input and to label the result for
	// future per-class pattern subsets.
	_ = ClassifyContent(canonical)

	// Step 2: Aho-Corasick prefix scan.
	candidates := auto.Scan(canonical)

	// Adaptive scanning + category filter: drop candidates whose
	// patterns are disabled by category or de-prioritised for very
	// large payloads.
	candidates = filterCandidates(candidates, len(canonical), largeThreshold, disabledCats)

	// Step 3: regex validation of candidates.
	matches := ValidateCandidates(canonical, candidates)
	if len(matches) == 0 {
		if cacheable {
			cache.Put(content, ScanResult{})
		}
		return ScanResult{}
	}

	// Group by pattern for the multi_match_boost.
	perPattern := make(map[*Pattern][]Match)
	for _, m := range matches {
		perPattern[m.Pattern] = append(perPattern[m.Pattern], m)
	}

	// For large payloads we evaluate the per-pattern groups in
	// parallel. The pipeline state we read above is captured by value
	// so each worker can run without further locking.
	var best ScanResult
	if len(canonical) >= ConcurrentEvalThreshold && len(perPattern) > 1 {
		best = scanConcurrent(canonical, perPattern, exclusions, weights, threshold, source, allowlist)
	} else {
		for pat, ms := range perPattern {
			res := evaluatePattern(canonical, pat, ms, exclusions, weights, threshold, source, allowlist)
			if res.Blocked && (!best.Blocked || res.Score > best.Score) {
				best = res
			}
		}
	}

	if cacheable {
		cache.Put(content, best)
	}
	return best
}

// evaluatePattern runs steps 4a-4d and the threshold check for a
// single pattern group. Pure function with no shared state — safe to
// invoke from worker goroutines in the concurrent path.
//
// Source is consulted once topScore is computed,
// via ScoreBiasFromContext, to apply the per-destination /
// per-element / per-fence / per-language bias rules.
//
// The allowlist (if non-nil) is consulted per-match
// after the public-example/placeholder short-circuits and BEFORE scoring. A hit drops
// the match silently — same effect as the user clicking "never
// block this" on the toast.
func evaluatePattern(
	content string,
	pat *Pattern,
	ms []Match,
	exclusions []Exclusion,
	weights ScoreWeights,
	threshold *ThresholdEngine,
	source SourceContext,
	allowlist *Allowlist,
) ScanResult {
	if pat.MinMatches > 0 && len(ms) < pat.MinMatches {
		return ScanResult{}
	}

	var (
		hotwordSeen bool
		topScore    int
		haveScored  bool
	)
	for _, m := range ms {
		if IsPublicExample(m.Value) {
			continue // known public example, never block
		}
		if IsPlaceholderShape(m.Value) {
			continue // template placeholder, never block
		}
		if allowlist.Allows(m.Value, source.DestinationKind) {
			continue // H: user-blessed, never block
		}
		hotword := CheckHotwords(content, m, *pat)
		excl := CheckExclusion(content, m, exclusions)
		if excl.SuppressEntirely {
			continue
		}
		ent := ShannonEntropy(m.Value)
		score := ScoreMatch(ScoreInput{
			Pattern:        *pat,
			Match:          m,
			HotwordPresent: hotword,
			Entropy:        ent,
			NumMatches:     len(ms),
			ExclusionHit:   excl.Hit,
			Weights:        weights,
		})
		if !haveScored || score > topScore {
			topScore = score
			haveScored = true
		}
		if hotword {
			hotwordSeen = true
		}
	}
	if !haveScored {
		return ScanResult{}
	}
	if pat.RequireHotword && !hotwordSeen {
		return ScanResult{}
	}

	// Apply source-context bias before the
	// threshold check. ScoreBiasFromContext returns 0 when source
	// is zero-valued so the no-source path is bit-identical.
	biasedScore := topScore + ScoreBiasFromContext(*pat, source)

	if !threshold.ShouldBlock(biasedScore, string(pat.Severity)) {
		return ScanResult{}
	}
	return ScanResult{Blocked: true, PatternName: pat.Name, Score: biasedScore}
}

// scanConcurrent fans the per-pattern groups out to a small worker
// pool and reduces the per-group results into the single best block
// decision. The number of workers is bounded by GOMAXPROCS so we never
// oversubscribe the CPU.
func scanConcurrent(
	content string,
	perPattern map[*Pattern][]Match,
	exclusions []Exclusion,
	weights ScoreWeights,
	threshold *ThresholdEngine,
	source SourceContext,
	allowlist *Allowlist,
) ScanResult {
	type job struct {
		pat *Pattern
		ms  []Match
	}
	jobs := make([]job, 0, len(perPattern))
	for pat, ms := range perPattern {
		jobs = append(jobs, job{pat: pat, ms: ms})
	}

	workers := runtime.GOMAXPROCS(0)
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers < 1 {
		workers = 1
	}

	results := make(chan ScanResult, len(jobs))
	jobCh := make(chan job, len(jobs))
	for _, j := range jobs {
		jobCh <- j
	}
	close(jobCh)

	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := range jobCh {
				results <- evaluatePattern(content, j.pat, j.ms, exclusions, weights, threshold, source, allowlist)
			}
		}()
	}
	wg.Wait()
	close(results)

	best := ScanResult{}
	for r := range results {
		if r.Blocked && (!best.Blocked || r.Score > best.Score) {
			best = r
		}
	}
	return best
}

// filterCandidates implements adaptive scanning and category
// filtering. For payloads larger than largeThreshold we drop candidates
// whose Pattern severity is "low" or "medium" — large pastes pay the
// per-candidate regex cost on critical/high patterns only.
func filterCandidates(
	in []Candidate,
	contentLen int,
	largeThreshold int,
	disabledCategories map[string]struct{},
) []Candidate {
	if len(in) == 0 {
		return in
	}
	large := contentLen >= largeThreshold
	if !large && len(disabledCategories) == 0 {
		return in
	}
	out := in[:0]
	for _, c := range in {
		pat := c.Pattern
		if pat == nil {
			continue
		}
		if len(disabledCategories) > 0 {
			cat := pat.Category
			if cat == "" {
				cat = CategoryUncategorized
			}
			if _, off := disabledCategories[cat]; off {
				continue
			}
		}
		if large {
			switch pat.Severity {
			case SeverityCritical, SeverityHigh:
				// keep
			default:
				continue
			}
		}
		out = append(out, c)
	}
	return out
}
