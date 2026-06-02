// dlp-bench — corpus generator + comparison runner for the DLP
// pipeline. Two subcommands:
//
//   build-corpus  Walk a source-tree, sample up to N lines into a
//                 corpus file with `path|line|content` format. The
//                 path is preserved so the bench can synthesise a
//                 plausible SourceContext per line.
//
//   run           Read a corpus file and run the Phase 8 pipeline
//                 against every line in TWO modes back-to-back:
//                   - phase7        (Pipeline.Scan; no source)
//                   - phase8        (Pipeline.ScanWithContext;
//                                    source synthesised from path)
//                 Reports per-mode FP count, p50/p99 latency, and
//                 throughput. Without ground-truth labels we treat
//                 every block as a "FP candidate" (the bench's job
//                 is to compare the two configs, not to claim
//                 absolute accuracy).
//
// Privacy invariant: the corpus stays on the operator's machine.
// The bench process never sends content anywhere; it merely calls
// the in-process Pipeline.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	iofs "io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "build-corpus":
		if err := buildCorpus(os.Args[2:]); err != nil {
			fail("build-corpus", err)
		}
	case "run":
		if err := runBench(os.Args[2:]); err != nil {
			fail("run", err)
		}
	case "-h", "--help", "help":
		usage()
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `dlp-bench — DLP corpus + comparison runner

USAGE:
  dlp-bench build-corpus --source DIR --out FILE [--target N] [--seed N]
  dlp-bench run          --corpus FILE --patterns FILE --exclusions FILE [--out FILE]

COMMANDS:
  build-corpus  Walk source-tree DIR and sample up to TARGET lines
                (default 1,000,000) into FILE. Skips node_modules,
                .git, vendor, dist, build, .venv, target,
                __pycache__, and binary files.

  run           Read the corpus, run the DLP pipeline twice
                (phase7 = no source; phase8 = source from path),
                and print a comparison table. Optional --out
                writes a JSON report.

`)
}

func fail(cmd string, err error) {
	fmt.Fprintf(os.Stderr, "dlp-bench %s: %v\n", cmd, err)
	os.Exit(1)
}

// ────────────────────────────────────────────────────────────────
//  build-corpus
// ────────────────────────────────────────────────────────────────

var skipDirs = map[string]struct{}{
	"node_modules": {}, ".git": {}, "vendor": {},
	"dist": {}, "build": {}, ".venv": {}, "venv": {},
	"target": {}, "__pycache__": {}, ".next": {},
	"out": {}, "tmp": {}, ".cache": {},
}

var sampleExts = map[string]struct{}{
	".go": {}, ".py": {}, ".js": {}, ".ts": {}, ".tsx": {}, ".jsx": {},
	".java": {}, ".kt": {}, ".rb": {}, ".rs": {}, ".swift": {},
	".c": {}, ".h": {}, ".cc": {}, ".cpp": {}, ".cs": {},
	".yaml": {}, ".yml": {}, ".json": {}, ".toml": {}, ".ini": {},
	".sh": {}, ".bash": {}, ".zsh": {},
	".tf": {}, ".tfvars": {}, ".hcl": {},
	".sql": {}, ".env": {},
	".md": {}, ".txt": {},
	".php": {}, ".pl": {},
}

const (
	maxLineBytes = 16 * 1024
	minLineBytes = 4
)

func buildCorpus(args []string) error {
	fs := flag.NewFlagSet("build-corpus", flag.ContinueOnError)
	source := fs.String("source", "", "source directory to walk")
	out := fs.String("out", "", "output corpus file")
	target := fs.Int("target", 1_000_000, "max number of lines")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *source == "" || *out == "" {
		return fmt.Errorf("--source and --out are required")
	}

	f, err := os.Create(*out)
	if err != nil {
		return fmt.Errorf("create corpus: %w", err)
	}
	defer f.Close()
	bw := bufio.NewWriterSize(f, 1<<20)
	defer bw.Flush()

	written := 0
	scanned := 0
	filesSeen := 0
	startedAt := time.Now()

	err = filepath.WalkDir(*source, func(path string, d iofs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip {
				return filepath.SkipDir
			}
			return nil
		}
		if _, ok := sampleExts[strings.ToLower(filepath.Ext(d.Name()))]; !ok {
			return nil
		}
		filesSeen++
		fh, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer fh.Close()

		// Cap per-file scan so a single huge file can't dominate.
		const perFileCap = 50_000

		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 0, maxLineBytes), maxLineBytes)
		lineNo := 0
		fromFile := 0
		for sc.Scan() {
			lineNo++
			if fromFile >= perFileCap {
				break
			}
			line := sc.Text()
			if len(line) < minLineBytes || len(line) > maxLineBytes {
				continue
			}
			if written >= *target {
				return io.EOF
			}
			scanned++
			fromFile++
			rel, _ := filepath.Rel(*source, path)
			if rel == "" {
				rel = path
			}
			// Replace pipe in content with a tab — the format is
			// path|line|content with pipe as the only delimiter.
			safe := strings.ReplaceAll(line, "|", "\t")
			if _, err := fmt.Fprintf(bw, "%s|%d|%s\n", rel, lineNo, safe); err != nil {
				return err
			}
			written++
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return err
	}

	took := time.Since(startedAt)
	fmt.Printf("build-corpus: walked %d files, scanned %d lines, wrote %d lines in %s (%.1fk lines/s)\n",
		filesSeen, scanned, written, took.Round(time.Millisecond),
		float64(written)/took.Seconds()/1000)
	return nil
}

// ────────────────────────────────────────────────────────────────
//  run
// ────────────────────────────────────────────────────────────────

type corpusEntry struct {
	path    string
	lineNo  int
	content string
}

// blockRecord identifies a single blocked match. (path,lineNo,pattern)
// is the deduplication key used for set-difference between modes —
// if the same line/pattern blocks in BOTH phase7 and phase8 we treat
// it as a stable detection; if phase8 dropped it we count it as a
// suppression. fpLikely is derived from path_hint at corpus-read
// time (paths that classify as test/fixture/spec/mock/docs are
// taken to be FP candidates).
type blockRecord struct {
	path        string
	lineNo      int
	patternName string
	score       int
	fpLikely    bool
}

type modeStats struct {
	name       string
	blocks     int
	scanned    int
	durations  []time.Duration // sampled (1-in-100 to keep memory bounded)
	totalScan  time.Duration
	startedAt  time.Time
	finishedAt time.Time
	// Per-pattern block counts for quick attribution.
	perPattern map[string]int
	// Per-block records keyed by (path|line|pattern). Used to
	// segment FP-likely vs TP-candidate when comparing modes.
	records map[string]blockRecord
}

func newModeStats(name string) *modeStats {
	return &modeStats{
		name:       name,
		startedAt:  time.Now(),
		perPattern: map[string]int{},
		durations:  make([]time.Duration, 0, 32*1024),
		records:    make(map[string]blockRecord, 256),
	}
}

// recordKey is the dedup key for blockRecord.
func recordKey(path string, line int, pattern string) string {
	return fmt.Sprintf("%s|%d|%s", path, line, pattern)
}

func (m *modeStats) finish() {
	m.finishedAt = time.Now()
}

// p returns the p-th percentile of the sampled durations.
func (m *modeStats) p(q float64) time.Duration {
	if len(m.durations) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), m.durations...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * q)
	if idx < 0 {
		idx = 0
	}
	return sorted[idx]
}

func (m *modeStats) throughput() float64 {
	if m.finishedAt.IsZero() || m.scanned == 0 {
		return 0
	}
	took := m.finishedAt.Sub(m.startedAt)
	if took <= 0 {
		return 0
	}
	return float64(m.scanned) / took.Seconds()
}

type benchReport struct {
	Corpus         string                `json:"corpus"`
	Patterns       string                `json:"patterns"`
	CorpusLen      int                   `json:"corpus_len"`
	DestinationMix string                `json:"destination_mix"`
	Seed           int64                 `json:"seed"`
	Modes          map[string]modeReport `json:"modes"`
}

type modeReport struct {
	Blocks     int            `json:"blocks"`
	Scanned    int            `json:"scanned"`
	FPRatePct  float64        `json:"fp_rate_pct"`
	Throughput float64        `json:"lines_per_sec"`
	P50us      float64        `json:"p50_us"`
	P99us      float64        `json:"p99_us"`
	TopPattern []patternCount `json:"top_patterns"`
}

type patternCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func runBench(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	corpusPath := fs.String("corpus", "", "corpus file produced by build-corpus")
	patternsPath := fs.String("patterns", "", "path to dlp_patterns.json")
	exclusionsPath := fs.String("exclusions", "", "path to dlp_exclusions.json (optional)")
	outPath := fs.String("out", "", "optional JSON report output")
	dumpSuppressedTP := fs.String("dump-suppressed-tp", "",
		"optional path — write the suppressed-TP-candidate records (in p7 but not p8, "+
			"on non-test paths) so they can be manually reviewed for recall regressions")
	mix := fs.String("destination-mix", "worst",
		"how to synthesize the destination axis of the Phase 8 SourceContext: "+
			"`worst` = code_host for every line (maximum F bias, useful for worst-case ceiling); "+
			"`realistic` = sample per line from a production-shaped distribution "+
			"(40% ai_chat, 30% code_host, 20% ai_code, 10% ai_chat+network_body) — "+
			"answers the question 'how much of phase 8's block reduction is bench artifact?'")
	seed := fs.Int64("seed", 1, "RNG seed for the realistic mix sampler (deterministic for reproducible runs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" || *patternsPath == "" {
		return fmt.Errorf("--corpus and --patterns are required")
	}
	if *mix != "worst" && *mix != "realistic" {
		return fmt.Errorf("--destination-mix must be `worst` or `realistic`, got %q", *mix)
	}

	patterns, err := dlp.LoadPatterns(*patternsPath)
	if err != nil {
		return fmt.Errorf("load patterns: %w", err)
	}
	var exclusions []dlp.Exclusion
	if *exclusionsPath != "" {
		exclusions, err = dlp.LoadExclusions(*exclusionsPath)
		if err != nil {
			return fmt.Errorf("load exclusions: %w", err)
		}
	}

	p := dlp.NewPipeline(dlp.DefaultScoreWeights(), dlp.NewThresholdEngine(dlp.DefaultThresholds()))
	p.Rebuild(patterns, exclusions)
	// Intentionally NOT enabling the scan-cache or correlator or
	// allowlist: we want each line scored in isolation so the only
	// difference between the two modes is the SourceContext.

	corpus, err := readCorpus(*corpusPath)
	if err != nil {
		return fmt.Errorf("read corpus: %w", err)
	}
	fmt.Printf("dlp-bench: loaded %d corpus entries · %d patterns · %d exclusions · destination-mix=%s\n",
		len(corpus), len(patterns), len(exclusions), *mix)

	ctx := context.Background()

	// Independent RNGs per mode so phase7 and phase8 see the SAME
	// per-line destination sample. phase7 ignores the source anyway
	// (Pipeline.Scan, no context), so this only affects phase8 — but
	// keeping the seed paired makes the comparison reproducible.
	rng7 := rand.New(rand.NewSource(*seed))
	rng8 := rand.New(rand.NewSource(*seed))

	phase7 := runMode(ctx, "phase7", p, corpus, false, *mix, rng7)
	phase8 := runMode(ctx, "phase8", p, corpus, true, *mix, rng8)

	printComparison(phase7, phase8, len(corpus))

	if *dumpSuppressedTP != "" {
		// Build the suppressed-TP set: in phase7's blocks, not in
		// phase8's, AND on a non-test path. Dump full records so a
		// human can decide what's a real recall regression vs an
		// FP the heuristic missed.
		suppressed := setDiff(phase7.records, phase8.records)
		f, err := os.Create(*dumpSuppressedTP)
		if err != nil {
			return fmt.Errorf("dump tp: %w", err)
		}
		defer f.Close()
		bw := bufio.NewWriter(f)
		defer bw.Flush()
		fmt.Fprintln(bw, "# path\tline\tpattern\tscore\tfp_likely(heuristic)\tcontent_excerpt")
		// Sort for stable diffs across runs.
		keys := make([]string, 0, len(suppressed))
		for k := range suppressed {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		// Build a corpus index so we can print the offending line
		// content alongside the metadata.
		byLoc := make(map[string]string, len(corpus))
		for _, e := range corpus {
			byLoc[fmt.Sprintf("%s|%d", e.path, e.lineNo)] = e.content
		}
		for _, k := range keys {
			r := suppressed[k]
			if r.fpLikely {
				continue // we want non-test-path suppressions only
			}
			content := byLoc[fmt.Sprintf("%s|%d", r.path, r.lineNo)]
			if len(content) > 200 {
				content = content[:197] + "..."
			}
			content = strings.ReplaceAll(content, "\t", " ")
			fmt.Fprintf(bw, "%s\t%d\t%s\t%d\t%t\t%s\n",
				r.path, r.lineNo, r.patternName, r.score, r.fpLikely, content)
		}
		fmt.Printf("\nsuppressed TP-candidate records written to %s\n", *dumpSuppressedTP)
	}

	if *outPath != "" {
		rep := benchReport{
			Corpus:         *corpusPath,
			Patterns:       *patternsPath,
			CorpusLen:      len(corpus),
			DestinationMix: *mix,
			Seed:           *seed,
			Modes: map[string]modeReport{
				"phase7": toReport(phase7),
				"phase8": toReport(phase8),
			},
		}
		out, err := os.Create(*outPath)
		if err != nil {
			return fmt.Errorf("create report: %w", err)
		}
		defer out.Close()
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rep)
		fmt.Printf("\nreport written to %s\n", *outPath)
	}
	return nil
}

func readCorpus(path string) ([]corpusEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, maxLineBytes*2), maxLineBytes*2)
	var entries []corpusEntry
	for sc.Scan() {
		line := sc.Text()
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		ln, _ := strconv.Atoi(parts[1])
		entries = append(entries, corpusEntry{
			path: parts[0], lineNo: ln, content: parts[2],
		})
	}
	return entries, sc.Err()
}

func runMode(ctx context.Context, name string, p *dlp.Pipeline,
	corpus []corpusEntry, withSource bool, mix string, rng *rand.Rand) *modeStats {
	m := newModeStats(name)
	const sampleEvery = 100
	for i, e := range corpus {
		start := time.Now()
		var res dlp.ScanResult
		if withSource {
			src := synthSource(e.path, mix, rng)
			res = p.ScanWithContext(ctx, e.content, "", src)
		} else {
			res = p.Scan(ctx, e.content)
		}
		took := time.Since(start)
		if i%sampleEvery == 0 {
			m.durations = append(m.durations, took)
		}
		m.scanned++
		if res.Blocked {
			m.blocks++
			m.perPattern[res.PatternName]++
			pathClass := classifyPath(e.path)
			m.records[recordKey(e.path, e.lineNo, res.PatternName)] = blockRecord{
				path:        e.path,
				lineNo:      e.lineNo,
				patternName: res.PatternName,
				score:       res.Score,
				fpLikely:    pathClass != "",
			}
		}
	}
	m.finish()
	return m
}

// synthSource builds a plausible SourceContext for a corpus entry.
// The path_hint is always derived from the file path (the corpus
// was built by walking a source tree, so the path represents where
// the content originated). The destination_kind axis depends on
// `mix`:
//
//   - "worst"     : every line gets destination_kind=code_host, the
//                   worst case for Phase 8 recall (maximum F bias).
//                   This is the conservative ceiling — useful for
//                   saying "even if every paste went to GitHub,
//                   phase 8 still blocks X".
//
//   - "realistic" : sample per line from a production-shaped
//                   distribution. The agent's production
//                   destination_kind is set by the EXTENSION based
//                   on the paste TARGET, not the content's file
//                   origin — so a corpus drawn from disk and then
//                   replayed needs an external prior on where those
//                   pastes would go. The shipped distribution is:
//
//                       40%  ai_chat        (chat.openai.com, claude.ai, …)
//                       30%  code_host      (github.com, gitlab.com, …)
//                       20%  ai_code        (copilot.microsoft.com, cursor.com)
//                       10%  ai_chat + element_kind=network_body
//                            (programmatic exfil into an AI chat session)
//
//                   These weights are an educated estimate of where
//                   a real engineering team's "paste this content
//                   somewhere" actions land — they should be tuned
//                   against telemetry once the agent has any. Until
//                   then the realistic mix's headline number is
//                   "an FP-reduction reality check," not a precise
//                   production simulation.
func synthSource(path string, mix string, rng *rand.Rand) dlp.SourceContext {
	pathHint := classifyPath(path)
	if mix == "worst" {
		return dlp.SourceContext{
			DestinationKind: dlp.DestinationKindCodeHost,
			DestinationHost: "github.com",
			ElementKind:     dlp.ElementKindContentEditable,
			PathHint:        pathHint,
		}
	}
	// realistic: weighted sample.
	r := rng.Float64()
	switch {
	case r < 0.40:
		// ai_chat — the dominant paste-into-LLM case. No F bias.
		host := aiChatHosts[rng.Intn(len(aiChatHosts))]
		return dlp.SourceContext{
			DestinationKind: dlp.DestinationKindAIChat,
			DestinationHost: host,
			ElementKind:     dlp.ElementKindContentEditable,
			PathHint:        pathHint,
		}
	case r < 0.70:
		// code_host — F's −2 bias applies here, plus F2's −1 on
		// fixture-shaped paths.
		host := codeHostHosts[rng.Intn(len(codeHostHosts))]
		return dlp.SourceContext{
			DestinationKind: dlp.DestinationKindCodeHost,
			DestinationHost: host,
			ElementKind:     dlp.ElementKindContentEditable,
			PathHint:        pathHint,
		}
	case r < 0.90:
		// ai_code — no F bias today.
		host := aiCodeHosts[rng.Intn(len(aiCodeHosts))]
		return dlp.SourceContext{
			DestinationKind: dlp.DestinationKindAICode,
			DestinationHost: host,
			ElementKind:     dlp.ElementKindContentEditable,
			PathHint:        pathHint,
		}
	default:
		// 10% programmatic exfil — element_kind=network_body
		// triggers F's +1 bias on top of the ai_chat destination.
		host := aiChatHosts[rng.Intn(len(aiChatHosts))]
		return dlp.SourceContext{
			DestinationKind: dlp.DestinationKindAIChat,
			DestinationHost: host,
			ElementKind:     dlp.ElementKindNetworkBody,
			PathHint:        pathHint,
		}
	}
}

// Realistic-mix host lists. Picked to match the extension's
// classifyDestination() Tier-2 host buckets so the host/destination_kind
// pairs are consistent with what the production extension would emit.
var (
	aiChatHosts = []string{
		"chat.openai.com", "chatgpt.com", "claude.ai",
		"gemini.google.com", "perplexity.ai", "mistral.ai",
		"poe.com", "you.com",
	}
	codeHostHosts = []string{
		"github.com", "gitlab.com", "bitbucket.org",
		"codeberg.org", "sourcehut.org",
	}
	aiCodeHosts = []string{
		"copilot.microsoft.com", "cursor.com",
		"codeium.com", "tabnine.com",
	}
)

var (
	pathTest    = regexp.MustCompile(`(?i)(?:/|^)(?:tests?|__tests__|testdata)(?:/|$)|_test\.|\.test\.`)
	pathFixture = regexp.MustCompile(`(?i)(?:/|^)fixtures?(?:/|$)|\.fixture\.`)
	pathSpec    = regexp.MustCompile(`(?i)(?:/|^)specs?(?:/|$)|_spec\.|\.spec\.`)
	pathMock    = regexp.MustCompile(`(?i)(?:/|^)mocks?(?:/|$)|(?:/|^)__mocks__(?:/|$)|\.mock\.`)
	pathDocs    = regexp.MustCompile(`(?i)(?:/|^)(?:docs?|documentation|examples?|samples?)(?:/|$)`)
)

func classifyPath(p string) string {
	switch {
	case pathTest.MatchString(p):
		return "test"
	case pathFixture.MatchString(p):
		return "fixture"
	case pathSpec.MatchString(p):
		return "spec"
	case pathMock.MatchString(p):
		return "mock"
	case pathDocs.MatchString(p):
		return "docs"
	}
	return ""
}

// ────────────────────────────────────────────────────────────────
//  reporting
// ────────────────────────────────────────────────────────────────

func toReport(m *modeStats) modeReport {
	r := modeReport{
		Blocks:     m.blocks,
		Scanned:    m.scanned,
		Throughput: m.throughput(),
		P50us:      float64(m.p(0.50).Microseconds()),
		P99us:      float64(m.p(0.99).Microseconds()),
	}
	if m.scanned > 0 {
		r.FPRatePct = float64(m.blocks) * 100 / float64(m.scanned)
	}
	r.TopPattern = topPatterns(m.perPattern, 5)
	return r
}

func topPatterns(m map[string]int, k int) []patternCount {
	out := make([]patternCount, 0, len(m))
	for n, c := range m {
		out = append(out, patternCount{Name: n, Count: c})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	if len(out) > k {
		out = out[:k]
	}
	return out
}

func printComparison(p7, p8 *modeStats, corpusLen int) {
	r7 := toReport(p7)
	r8 := toReport(p8)
	deltaBlocks := r7.Blocks - r8.Blocks
	deltaPct := 0.0
	if r7.Blocks > 0 {
		deltaPct = float64(deltaBlocks) * 100 / float64(r7.Blocks)
	}

	fmt.Println()
	fmt.Println("================================================================")
	fmt.Printf(" Corpus: %d entries\n", corpusLen)
	fmt.Println("================================================================")
	fmt.Printf(" %-12s   %12s   %12s   %12s   %10s   %10s\n",
		"mode", "blocks", "block rate", "lines/s", "p50 µs", "p99 µs")
	fmt.Printf(" %-12s   %12d   %12s   %12s   %10.1f   %10.1f\n",
		"phase7", r7.Blocks, fmt.Sprintf("%.4f%%", r7.FPRatePct),
		fmt.Sprintf("%.0f", r7.Throughput), r7.P50us, r7.P99us)
	fmt.Printf(" %-12s   %12d   %12s   %12s   %10.1f   %10.1f\n",
		"phase8", r8.Blocks, fmt.Sprintf("%.4f%%", r8.FPRatePct),
		fmt.Sprintf("%.0f", r8.Throughput), r8.P50us, r8.P99us)
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf(" Δ total blocks: %d (%.1f%% vs phase7)\n", deltaBlocks, deltaPct)
	fmt.Println("================================================================")

	// ── FP-vs-TP segmentation ──────────────────────────────────────
	//
	// We don't have ground-truth labels, so use the path as a proxy:
	// any block on a path classified as test/fixture/spec/mock/docs
	// is considered FP-likely (a committed fixture is, by intent,
	// not real exfil). Everything else is TP-candidate — could be a
	// real secret OR a deeper FP class that the path heuristic
	// misses; manual review is the only way to be sure.
	p7FP, p7TP := segment(p7.records)
	p8FP, p8TP := segment(p8.records)

	suppressed := setDiff(p7.records, p8.records) // in p7 but not p8
	suppFP, suppTP := segment(suppressed)
	// Detections that newly appear in p8 but not in p7. Should be
	// empty in practice (p8's bias is monotone non-positive on score)
	// but we print it for safety so any future regression that
	// EXPOSES new hits is visible.
	exposed := setDiff(p8.records, p7.records)
	expFP, expTP := segment(exposed)

	fmt.Println()
	fmt.Println("FP vs TP segmentation (path heuristic: test/fixture/spec/mock/docs = FP-likely)")
	fmt.Println("----------------------------------------------------------------")
	fmt.Printf(" %-12s   %14s   %14s   %14s\n",
		"mode", "FP-likely", "TP-candidate", "total")
	fmt.Printf(" %-12s   %14d   %14d   %14d\n",
		"phase7", len(p7FP), len(p7TP), len(p7FP)+len(p7TP))
	fmt.Printf(" %-12s   %14d   %14d   %14d\n",
		"phase8", len(p8FP), len(p8TP), len(p8FP)+len(p8TP))
	fmt.Println("----------------------------------------------------------------")

	fpDropPct := 0.0
	if len(p7FP) > 0 {
		fpDropPct = float64(len(p7FP)-len(p8FP)) * 100 / float64(len(p7FP))
	}
	tpDropPct := 0.0
	if len(p7TP) > 0 {
		tpDropPct = float64(len(p7TP)-len(p8TP)) * 100 / float64(len(p7TP))
	}
	fmt.Printf(" FP-likely drop:    %d → %d (%.1f%% reduction)\n",
		len(p7FP), len(p8FP), fpDropPct)
	fmt.Printf(" TP-candidate drop: %d → %d (%.1f%% — ideally near 0%%)\n",
		len(p7TP), len(p8TP), tpDropPct)
	fmt.Println()
	fmt.Printf(" Suppressed by phase8 (in p7, not in p8): %d total\n", len(suppressed))
	fmt.Printf("   ├─ on FP-likely paths:    %d\n", len(suppFP))
	fmt.Printf("   └─ on TP-candidate paths: %d  ← recall risk if nonzero\n",
		len(suppTP))
	if len(exposed) > 0 {
		fmt.Printf(" Newly exposed by phase8 (not in p7): %d total\n", len(exposed))
		fmt.Printf("   ├─ FP-likely: %d\n", len(expFP))
		fmt.Printf("   └─ TP-cand:   %d\n", len(expTP))
	}
	fmt.Println()
	fmt.Println("Top patterns by block count (phase7):")
	for _, pc := range r7.TopPattern {
		fmt.Printf("  %-30s  %d\n", trunc(pc.Name, 30), pc.Count)
	}
	fmt.Println()
	fmt.Println("Top patterns by block count (phase8):")
	for _, pc := range r8.TopPattern {
		fmt.Printf("  %-30s  %d\n", trunc(pc.Name, 30), pc.Count)
	}
}

// segment splits a record map into FP-likely + TP-candidate slices.
func segment(rs map[string]blockRecord) (fp []blockRecord, tp []blockRecord) {
	for _, r := range rs {
		if r.fpLikely {
			fp = append(fp, r)
		} else {
			tp = append(tp, r)
		}
	}
	return fp, tp
}

// setDiff returns the records in a but not in b.
func setDiff(a, b map[string]blockRecord) map[string]blockRecord {
	out := make(map[string]blockRecord, len(a))
	for k, v := range a {
		if _, in := b[k]; !in {
			out[k] = v
		}
	}
	return out
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
