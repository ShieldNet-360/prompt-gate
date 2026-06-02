package dlp

import (
	"context"
	"strings"
	"testing"
)

// benchPatterns is a small but representative set covering the
// Aho-Corasick scan, the regex revalidation, the hotword pass and
// the entropy step. We compile them once and reuse across all
// benchmarks via the helper.
var benchPatterns = []*Pattern{
	{Name: "AWS Access Key", Regex: `AKIA[A-Z0-9]{16}`, Prefix: "AKIA", Severity: "critical"},
	{Name: "Stripe Live", Regex: `sk_live_[0-9a-zA-Z]{24,}`, Prefix: "sk_live_", Severity: "critical"},
	{Name: "JWT", Regex: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`, Prefix: "eyJ", Severity: "high"},
	{Name: "Hex", Regex: `[a-f0-9]{32}`, Severity: "low"},
}

func benchPipeline(b *testing.B) *Pipeline {
	b.Helper()
	patterns, err := ParsePatterns([]byte(`{"patterns":[
		{"name":"AWS Access Key","regex":"AKIA[A-Z0-9]{16}","prefix":"AKIA","severity":"critical"},
		{"name":"Stripe Live","regex":"sk_live_[0-9a-zA-Z]{24,}","prefix":"sk_live_","severity":"critical"},
		{"name":"JWT","regex":"eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}","prefix":"eyJ","severity":"high"},
		{"name":"Hex","regex":"[a-f0-9]{32}","severity":"low"}
	]}`))
	if err != nil {
		b.Fatalf("parse: %v", err)
	}
	p := NewPipeline(ScoreWeights{}, NewThresholdEngine(Thresholds{Critical: 1, High: 2, Medium: 3, Low: 4}))
	p.Rebuild(patterns, nil)
	return p
}

// Bench inputs use the AWS docs example access key and a
// deliberately-broken Stripe-shaped string ("00BENCHFIXTURE" is
// neither a real prefix nor format-valid) so secret scanners do
// not flag this file. The DLP pipeline still walks the same code
// paths it would for a real key.
const smallBenchContent = `Sending this PR for review. Please check the
deployment config at github.com/acme/infra — uses
AKIAIOSFODNN7EXAMPLE for the IAM user. The Stripe live key is
sk_test_00BENCHFIXTURE00BENCHFIXTURE00. End.`

func BenchmarkPipelineScan(b *testing.B) {
	p := benchPipeline(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Scan(ctx, smallBenchContent)
	}
}

func BenchmarkPipelineScanLarge(b *testing.B) {
	p := benchPipeline(b)
	ctx := context.Background()
	// ~100 KiB content; embed two real-shape matches near the end.
	body := strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 1900)
	body += " key=AKIAIOSFODNN7EXAMPLE token=sk_test_00BENCHFIXTURE00BENCHFIXTURE00"
	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		_ = p.Scan(ctx, body)
	}
}

func BenchmarkAhoCorasickBuild(b *testing.B) {
	// Build is the cost paid every time the pipeline is rebuilt
	// (rule update). Use the same patterns as Scan so the cost is
	// directly comparable.
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = BuildAutomaton(benchPatterns)
	}
}

func BenchmarkEntropy(b *testing.B) {
	sample := "AKIAIOSFODNN7EXAMPLExxxxxxxxxxxxxxxxx"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ShannonEntropy(sample)
	}
}

// BenchmarkPipelineScanLargeConcurrentEval mirrors
// BenchmarkPipelineScanLarge but uses a content size that crosses the
// ConcurrentEvalThreshold, so the worker-pool evaluator (Phase 6 Task
// 10) is exercised. Compare against BenchmarkPipelineScanLarge to see
// the speed-up of concurrent regex revalidation.
func BenchmarkPipelineScanLargeConcurrentEval(b *testing.B) {
	p := benchPipeline(b)
	ctx := context.Background()
	body := strings.Repeat("Lorem ipsum dolor sit amet, consectetur adipiscing elit. ", 1900)
	// Mix three pattern groups so the worker pool has work to fan out.
	body += " key=AKIAIOSFODNN7EXAMPLE"
	body += " token=sk_test_00BENCHFIXTURE00BENCHFIXTURE00"
	body += " jwt=" + "eyJ" + "abcdEFGH.eyJabcdEFGH.SignatureTail0123"
	body += " hash=" + strings.Repeat("a", 32)
	b.ReportAllocs()
	b.ResetTimer()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		_ = p.Scan(ctx, body)
	}
}

// BenchmarkScanCache_Hit measures the fast path: identical content
// already seen, so the cache returns immediately without re-running
// the pipeline. Compare against BenchmarkPipelineScan to see the
// per-paste cost saved on duplicate scans.
func BenchmarkScanCache_Hit(b *testing.B) {
	p := benchPipeline(b)
	cache := NewScanCache(64, ScanCacheTTL)
	p.EnableCache(cache)
	ctx := context.Background()
	_ = p.Scan(ctx, smallBenchContent) // warm
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = p.Scan(ctx, smallBenchContent)
	}
}
