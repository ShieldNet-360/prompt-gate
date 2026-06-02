# Performance & Stress Report

*Generated 2026-05-31 · Go 1.26.3 · darwin/arm64 · Apple M1 Max · GOMAXPROCS=10.*
*Numbers are `go test -bench` output, reproducible with the commands shown.*

## Summary

| Workload | Result |
|---|---|
| Typical scan (`BenchmarkPipelineScan`) | **15.9 µs/op** · 1262 B · 14 allocs |
| Throughput (single core, typical input) | **≈ 62,700 scans/sec** |
| Large input (`BenchmarkPipelineScanLarge`) | 2.66 ms/op · **40.8 MB/s** |
| Large input, concurrent eval | 2.60 ms/op · **41.7 MB/s** |
| Scan-cache hit (`BenchmarkScanCache_Hit`) | **255 ns/op** · 1 alloc |
| Content normalization (ASCII) | 158 ns/op · 0 allocs |
| Content normalization (homoglyph fold) | 765 ns/op |
| Content normalization (base64 decode) | 175 ns/op |
| Aho-Corasick automaton build | 24.4 µs (one-time, at load) |
| Fuzzing | **~537k execs, 0 crashers** |

The product's stated **&lt;1 ms scan budget** holds with wide margin for typical
inputs (15.9 µs ≈ 1/60th of the budget). Inputs above the large-content
threshold (50 KB) take longer but sustain ~41 MB/s and switch to concurrent
evaluation above 10 KB.

## How to reproduce

```bash
cd agent
# Latency / throughput
go test ./internal/dlp/ -run='^$' -benchmem -benchtime=2s \
  -bench='BenchmarkPipelineScan|BenchmarkAhoCorasick|BenchmarkScanCache|BenchmarkNormalize'

# Robustness (no crashers expected)
go test ./internal/dlp/ -run='^$' -fuzz='FuzzPipelineScan' -fuzztime=30s
```

## Raw benchmark output

```
BenchmarkNormalizeContent/ascii_passthrough-10   14251724    157.9 ns/op      0 B/op    0 allocs/op
BenchmarkNormalizeContent/homoglyph_fold-10       3112471    764.5 ns/op    112 B/op    3 allocs/op
BenchmarkNormalizeContent/base64_decode-10       13690766    175.0 ns/op    112 B/op    3 allocs/op
BenchmarkPipelineScan-10                           150132  15938   ns/op   1262 B/op   14 allocs/op
BenchmarkPipelineScanLarge-10                         937 2657469  ns/op  40.78 MB/s 118727 B/op  17 allocs/op
BenchmarkPipelineScanLargeConcurrentEval-10           900 2604168  ns/op  41.65 MB/s 119209 B/op  17 allocs/op
BenchmarkAhoCorasickBuild-10                        99352  24356   ns/op  75304 B/op   54 allocs/op
BenchmarkScanCache_Hit-10                         9313563    255.5 ns/op    208 B/op    1 allocs/op
```

## Stress & robustness

- **Fuzzing.** `FuzzPipelineScan` drives arbitrary/malformed byte input through
  the full pipeline. Across runs totalling **~537,000 executions** and **181
  interesting inputs**, **zero crashers** were produced (no panics, no
  `testdata/fuzz/` crash artifacts). The pipeline degrades gracefully on garbage
  input rather than faulting.
- **Concurrency.** All packages pass under `-race` (see the [QA report](qa.md)).
  Large inputs are evaluated concurrently above the 10 KB threshold with no race
  conditions detected.
- **Allocations.** The hot path holds at **14 allocations / 1.3 KB per typical
  scan**, and a cache hit is a single allocation — bounded, predictable memory
  behaviour suited to a constantly-running desktop agent.

## Notes & honesty

- Benchmarks are single-machine (Apple M1 Max). Absolute numbers vary by CPU;
  the *ratios* (scan ≪ 1 ms budget, cache hit ≈ 60× faster than a cold scan) are
  the durable claims.
- A live HTTP load test against `POST /api/dlp/scan` is gated by the API's
  default rate limiter (≈100 req/s, returns `429` above that); the figures above
  measure the **engine**, which is the component under test. End-to-end HTTP
  throughput is bounded by the configured rate limit, not the engine.
