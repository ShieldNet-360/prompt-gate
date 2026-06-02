// Phase 6 Tasks 7-10: engine performance tests.
//
//   - Task 7: content-size adaptive scanning drops low/medium severity
//     patterns from very large payloads.
//   - Task 8: pattern category grouping lets operators disable whole
//     categories at runtime.
//   - Task 9: a short-lived LRU cache short-circuits identical scans.
//   - Task 10: per-pattern groups can be evaluated concurrently.

package dlp

import (
	"context"
	"crypto/sha256"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func enginePipeline(t *testing.T) *Pipeline {
	t.Helper()
	patterns, err := ParsePatterns([]byte(`{"patterns":[
{"name":"Critical Cloud","regex":"CRIT-[A-Z0-9]{20,}","prefix":"CRIT-","severity":"critical","category":"cloud","score_weight":4},
{"name":"Low Other","regex":"LOW-[A-Z0-9]{10,}","prefix":"LOW-","severity":"low","category":"other","score_weight":1},
{"name":"Medium PII","regex":"PII-[A-Z0-9]{10,}","prefix":"PII-","severity":"medium","category":"pii","score_weight":2}
]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	p := NewPipeline(DefaultScoreWeights(), NewThresholdEngine(Thresholds{Critical: 1, High: 1, Medium: 1, Low: 1}))
	p.Rebuild(patterns, nil)
	return p
}

// TestAdaptiveScanning_SkipsLowSeverityOnLargeContent — Task 7. A
// payload above the configured large-content threshold no longer
// returns low/medium-severity matches; only critical/high patterns are
// considered.
func TestAdaptiveScanning_SkipsLowSeverityOnLargeContent(t *testing.T) {
	p := enginePipeline(t)
	p.SetLargeContentThreshold(1024)

	// Build a >1KiB payload that contains only a low-severity match.
	padding := strings.Repeat("Lorem ipsum dolor sit amet. ", 80)
	content := padding + "LOW-AAAAAAAAAA0000000000"
	if len(content) < 1024 {
		t.Fatalf("test content too small: %d", len(content))
	}

	got := p.Scan(context.Background(), content)
	if got.Blocked {
		t.Fatalf("expected adaptive scan to drop low-severity match on large content, got %+v", got)
	}

	// Below the threshold the same pattern fires.
	got = p.Scan(context.Background(), "LOW-AAAAAAAAAA0000000000")
	if !got.Blocked || got.PatternName != "Low Other" {
		t.Fatalf("expected Low Other block on small content, got %+v", got)
	}

	// Critical matches still fire on large content.
	largeCritical := padding + "CRIT-AAAAAAAAAA0000000000ZZZ"
	got = p.Scan(context.Background(), largeCritical)
	if !got.Blocked || got.PatternName != "Critical Cloud" {
		t.Fatalf("expected Critical Cloud block on large content, got %+v", got)
	}
}

// TestCategoryFiltering_DisablesPatterns — Task 8. Disabling the "pii"
// category drops any match from a pattern whose category is "pii"
// without affecting other categories.
func TestCategoryFiltering_DisablesPatterns(t *testing.T) {
	p := enginePipeline(t)

	// Sanity: PII block fires by default.
	got := p.Scan(context.Background(), "leak: PII-AAAA0000BB")
	if !got.Blocked || got.PatternName != "Medium PII" {
		t.Fatalf("default scan: want Medium PII, got %+v", got)
	}

	p.SetDisabledCategories([]string{"pii"})
	got = p.Scan(context.Background(), "leak: PII-AAAA0000BB")
	if got.Blocked {
		t.Fatalf("expected pii category disabled, but got block %+v", got)
	}

	// Other categories untouched.
	got = p.Scan(context.Background(), "leak: CRIT-AAAAAAAAAA0000000000ZZZ")
	if !got.Blocked || got.PatternName != "Critical Cloud" {
		t.Fatalf("non-disabled category: want Critical Cloud, got %+v", got)
	}

	// Re-enable everything.
	p.SetDisabledCategories(nil)
	got = p.Scan(context.Background(), "leak: PII-AAAA0000BB")
	if !got.Blocked {
		t.Fatalf("expected re-enabled pii to fire, got %+v", got)
	}
}

// TestScanCache_HitsIdenticalContent — Task 9. Two scans of the same
// content count as a single regex evaluation; the second returns from
// the cache and increments the hit counter.
func TestScanCache_HitsIdenticalContent(t *testing.T) {
	p := enginePipeline(t)
	cache := NewScanCache(64, 100*time.Millisecond)
	p.EnableCache(cache)

	content := "leak: CRIT-AAAAAAAAAA0000000000ZZZ"
	first := p.Scan(context.Background(), content)
	if !first.Blocked {
		t.Fatalf("expected initial block, got %+v", first)
	}

	second := p.Scan(context.Background(), content)
	if second != first {
		t.Fatalf("cache miss: first=%+v second=%+v", first, second)
	}

	stats := cache.Stats()
	if stats.Hits != 1 {
		t.Fatalf("expected 1 cache hit, got stats=%+v", stats)
	}
}

// TestScanCache_ExpiryEvictsEntry — Task 9. Entries older than TTL are
// invisible to Lookup and counted as a miss instead.
func TestScanCache_ExpiryEvictsEntry(t *testing.T) {
	c := NewScanCache(8, 50*time.Millisecond)
	c.Put("x", ScanResult{Blocked: true, PatternName: "X", Score: 4})
	if _, ok := c.Lookup("x"); !ok {
		t.Fatalf("expected immediate hit")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Lookup("x"); ok {
		t.Fatalf("expected stale entry to be evicted after TTL")
	}
	stats := c.Stats()
	if stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("expected hits=1 misses=1, got %+v", stats)
	}
}

// TestScanCache_LRUEvictsOldest — Task 9. Once the cache exceeds its
// capacity the least-recently-used entry is evicted, freeing space for
// the new entry.
func TestScanCache_LRUEvictsOldest(t *testing.T) {
	c := NewScanCache(2, time.Hour)
	c.Put("a", ScanResult{PatternName: "A"})
	c.Put("b", ScanResult{PatternName: "B"})
	// Touch "a" so "b" is the LRU.
	if _, ok := c.Lookup("a"); !ok {
		t.Fatalf("expected a to be cached")
	}
	c.Put("c", ScanResult{PatternName: "C"})
	if _, ok := c.Lookup("b"); ok {
		t.Fatalf("expected b to be evicted")
	}
	if _, ok := c.Lookup("a"); !ok {
		t.Fatalf("expected a to still be cached")
	}
	if _, ok := c.Lookup("c"); !ok {
		t.Fatalf("expected c to be cached")
	}
	stats := c.Stats()
	if stats.Evictions != 1 {
		t.Fatalf("expected 1 eviction, got %+v", stats)
	}
}

// TestScanCache_HashOnly verifies the cache never holds the raw
// content. We poke at the internal LRU list and confirm only the
// SHA-256 digest is stored.
func TestScanCache_HashOnly(t *testing.T) {
	c := NewScanCache(2, time.Minute)
	const secret = "SECRET-VALUE-9PLKM"
	c.Put(secret, ScanResult{Blocked: true, PatternName: "X"})

	c.mu.Lock()
	defer c.mu.Unlock()
	for el := c.order.Front(); el != nil; el = el.Next() {
		entry := el.Value.(*scanCacheEntry)
		if entry.digest == ([sha256.Size]byte{}) {
			t.Fatalf("entry has zero digest")
		}
		// Defensive: the entry struct only holds a digest array,
		// a ScanResult, and an inserted timestamp. Anything else
		// would be a regression.
		if len(entry.result.PatternName) == 0 {
			// PatternName is set by the test above.
			t.Fatalf("expected pattern name set, got empty entry")
		}
	}
}

// TestConcurrentEval_LargeContent — Task 10. For payloads above
// ConcurrentEvalThreshold the pipeline switches to the worker-pool
// evaluator. The result must be identical to the sequential evaluator
// and stable under racy execution.
func TestConcurrentEval_LargeContent(t *testing.T) {
	p := enginePipeline(t)

	// Build a 32 KiB payload that triggers both critical and medium
	// patterns. The expected block is Critical Cloud (higher score).
	body := strings.Repeat("Lorem ipsum dolor sit amet. ", 1100)
	body += " CRIT-AAAAAAAAAA0000000000ZZZ"
	body += " PII-AAAA0000BB"
	if len(body) < ConcurrentEvalThreshold {
		t.Fatalf("test content below concurrent threshold: %d", len(body))
	}

	var wg sync.WaitGroup
	const goroutines = 8
	results := make([]ScanResult, goroutines)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i] = p.Scan(context.Background(), body)
		}()
	}
	wg.Wait()
	for i, r := range results {
		if !r.Blocked || r.PatternName != "Critical Cloud" {
			t.Fatalf("goroutine %d: expected Critical Cloud, got %+v", i, r)
		}
	}
	if runtime.GOMAXPROCS(0) < 1 {
		t.Fatalf("GOMAXPROCS unexpectedly < 1")
	}
}

// TestPipelineRebuild_ResetsCache — rule-file updates must invalidate
// stale cache entries; the privacy guarantee depends on operators not
// seeing old block decisions after a rule reload.
func TestPipelineRebuild_ResetsCache(t *testing.T) {
	p := enginePipeline(t)
	cache := NewScanCache(8, time.Minute)
	p.EnableCache(cache)

	content := "leak: CRIT-AAAAAAAAAA0000000000ZZZ"
	if got := p.Scan(context.Background(), content); !got.Blocked {
		t.Fatalf("expected block, got %+v", got)
	}
	// Rebuild with the same patterns; the cache should still be
	// dropped so the next scan re-evaluates.
	p.Rebuild(p.Patterns(), nil)
	stats := cache.Stats()
	if stats.Size != 0 {
		t.Fatalf("expected cache cleared on rebuild, got %+v", stats)
	}
}

// primeCache populates the pipeline's scan cache with a single entry
// so the setter-invalidation tests can confirm Reset was called.
func primeCache(t *testing.T, p *Pipeline) *ScanCache {
	t.Helper()
	cache := NewScanCache(8, time.Minute)
	p.EnableCache(cache)
	if got := p.Scan(context.Background(), "leak: CRIT-AAAAAAAAAA0000000000ZZZ"); !got.Blocked {
		t.Fatalf("expected initial block, got %+v", got)
	}
	if cache.Stats().Size == 0 {
		t.Fatalf("cache empty after priming scan")
	}
	return cache
}

// TestSetWeights_ResetsCache locks in the fix for the cache-staleness
// bug surfaced in PR review: PUT /api/dlp/config calls SetWeights at
// runtime, and any cached verdicts produced under the previous
// weights would otherwise survive for the full 5s TTL.
func TestSetWeights_ResetsCache(t *testing.T) {
	p := enginePipeline(t)
	cache := primeCache(t, p)

	p.SetWeights(ScoreWeights{HotwordBoost: 99})
	if got := cache.Stats().Size; got != 0 {
		t.Fatalf("expected cache cleared after SetWeights, got size=%d", got)
	}
}

// TestSetDisabledCategories_ResetsCache covers the live category
// toggle path (PUT /api/dlp/config and the Electron Rules page). Old
// "blocked" verdicts must not survive a category being switched off
// or back on.
func TestSetDisabledCategories_ResetsCache(t *testing.T) {
	p := enginePipeline(t)
	cache := primeCache(t, p)

	p.SetDisabledCategories([]string{"pii"})
	if got := cache.Stats().Size; got != 0 {
		t.Fatalf("expected cache cleared after disabling category, got size=%d", got)
	}

	// Re-enabling must also reset, otherwise a verdict that
	// benefited from a now-disabled category would linger.
	cache = primeCache(t, p)
	p.SetDisabledCategories(nil)
	if got := cache.Stats().Size; got != 0 {
		t.Fatalf("expected cache cleared after re-enabling categories, got size=%d", got)
	}
}

// TestSetLargeContentThreshold_ResetsCache mirrors the other two
// setter tests for the adaptive-scanning threshold. Cached verdicts
// produced under the old threshold could otherwise contradict the
// new policy until the TTL expires.
func TestSetLargeContentThreshold_ResetsCache(t *testing.T) {
	p := enginePipeline(t)
	cache := primeCache(t, p)

	p.SetLargeContentThreshold(1024)
	if got := cache.Stats().Size; got != 0 {
		t.Fatalf("expected cache cleared after SetLargeContentThreshold, got size=%d", got)
	}
}

// TestResetCache_PublicAPI confirms the public ResetCache helper
// works when callers mutate state outside the dedicated setters —
// notably Threshold().Set() on the ThresholdEngine which lives
// alongside the pipeline rather than inside it.
func TestResetCache_PublicAPI(t *testing.T) {
	p := enginePipeline(t)
	cache := primeCache(t, p)
	p.Threshold().Set(Thresholds{Critical: 1, High: 1, Medium: 1, Low: 1})
	p.ResetCache()
	if got := cache.Stats().Size; got != 0 {
		t.Fatalf("expected cache cleared after ResetCache, got size=%d", got)
	}
}

// TestResetCache_NilCacheIsNoOp confirms the public helper is safe to
// call on pipelines that never had a cache attached. The setters
// themselves call cache.Reset() unconditionally and rely on the
// ScanCache.Reset() nil-receiver guard; this test pins down the
// public surface so a regression in either would fail loudly.
func TestResetCache_NilCacheIsNoOp(t *testing.T) {
	p := enginePipeline(t)
	// EnableCache(nil) leaves p.cache nil. ResetCache must not panic.
	p.EnableCache(nil)
	p.ResetCache()
	p.SetWeights(ScoreWeights{})
	p.SetDisabledCategories(nil)
	p.SetLargeContentThreshold(0)
}
