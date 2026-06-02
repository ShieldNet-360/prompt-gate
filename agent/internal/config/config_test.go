package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestLoad_NoFile(t *testing.T) {
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load(empty): %v", err)
	}
	want := Default()
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("Load(empty) = %#v, want %#v", cfg, want)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "no-such-file.yaml"))
	if err != nil {
		t.Fatalf("Load(missing): %v", err)
	}
	if !reflect.DeepEqual(cfg, Default()) {
		t.Fatalf("Load(missing) = %#v, want defaults", cfg)
	}
}

func TestLoad_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := `upstream_dns: "1.1.1.1:53"
api_listen: "127.0.0.1:9090"
rule_paths:
  - /tmp/a.txt
  - /tmp/b.txt
stats_flush_interval: 30s
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.UpstreamDNS != "1.1.1.1:53" {
		t.Errorf("UpstreamDNS = %q", cfg.UpstreamDNS)
	}
	if cfg.APIListen != "127.0.0.1:9090" {
		t.Errorf("APIListen = %q", cfg.APIListen)
	}
	if cfg.DNSListen != "127.0.0.1:15353" {
		t.Errorf("DNSListen = %q, want default", cfg.DNSListen)
	}
	if cfg.DBPath != "prompt-gate.db" {
		t.Errorf("DBPath = %q, want default", cfg.DBPath)
	}
	if cfg.StatsFlushInterval != 30*time.Second {
		t.Errorf("StatsFlushInterval = %v", cfg.StatsFlushInterval)
	}
	if len(cfg.RulePaths) != 2 {
		t.Errorf("RulePaths = %v", cfg.RulePaths)
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("not: [valid"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(bad yaml): expected error")
	}
}

func TestLoad_InvalidValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	// Negative durations fail validation; an empty upstream is rejected too.
	if err := os.WriteFile(path, []byte("stats_flush_interval: -1s\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load(invalid): expected error")
	}
}

// TestLoad_DLPIntFields_ExplicitZeroDisables locks in the DLP int-field
// "zero disables" semantics for the four DLP int fields. Writing an
// explicit `0` in YAML must override the built-in default — a previous
// implementation used `!= 0` merge guards that silently dropped the
// override and kept the operator on the default value.
func TestLoad_DLPIntFields_ExplicitZeroDisables(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "zero.yaml")
	content := `large_content_threshold: 0
dlp_cache_ttl_seconds: 0
dlp_cache_capacity: 0
dlp_rate_limit_per_sec: 0
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LargeContentThreshold != 0 {
		t.Errorf("LargeContentThreshold = %d, want explicit 0", cfg.LargeContentThreshold)
	}
	if cfg.DLPCacheTTLSeconds != 0 {
		t.Errorf("DLPCacheTTLSeconds = %d, want explicit 0", cfg.DLPCacheTTLSeconds)
	}
	if cfg.DLPCacheCapacity != 0 {
		t.Errorf("DLPCacheCapacity = %d, want explicit 0", cfg.DLPCacheCapacity)
	}
	if cfg.DLPRateLimitPerSec != 0 {
		t.Errorf("DLPRateLimitPerSec = %d, want explicit 0", cfg.DLPRateLimitPerSec)
	}
}

// TestLoad_DLPIntFields_OmittedKeepsDefault confirms the corollary:
// when the operator omits the fields entirely, the documented
// defaults survive. Together with the explicit-zero test above this
// pins down the "omitted vs explicit 0" distinction.
func TestLoad_DLPIntFields_OmittedKeepsDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "omit.yaml")
	// No DLP int keys at all.
	content := "upstream_dns: \"1.1.1.1:53\"\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defaults := Default()
	if cfg.LargeContentThreshold != defaults.LargeContentThreshold {
		t.Errorf("LargeContentThreshold = %d, want default %d",
			cfg.LargeContentThreshold, defaults.LargeContentThreshold)
	}
	if cfg.DLPCacheTTLSeconds != defaults.DLPCacheTTLSeconds {
		t.Errorf("DLPCacheTTLSeconds = %d, want default %d",
			cfg.DLPCacheTTLSeconds, defaults.DLPCacheTTLSeconds)
	}
	if cfg.DLPCacheCapacity != defaults.DLPCacheCapacity {
		t.Errorf("DLPCacheCapacity = %d, want default %d",
			cfg.DLPCacheCapacity, defaults.DLPCacheCapacity)
	}
	if cfg.DLPRateLimitPerSec != defaults.DLPRateLimitPerSec {
		t.Errorf("DLPRateLimitPerSec = %d, want default %d",
			cfg.DLPRateLimitPerSec, defaults.DLPRateLimitPerSec)
	}
}

// TestLoad_DLPIntFields_PartialOverride confirms that mixing
// explicit overrides with omitted fields keeps each independent: the
// set fields take the operator's value (including zero) while the
// rest fall back to defaults.
func TestLoad_DLPIntFields_PartialOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mixed.yaml")
	content := "dlp_rate_limit_per_sec: 0\n" + // disable limiter
		"dlp_cache_ttl_seconds: 30\n" // longer cache
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	defaults := Default()
	if cfg.DLPRateLimitPerSec != 0 {
		t.Errorf("DLPRateLimitPerSec = %d, want 0", cfg.DLPRateLimitPerSec)
	}
	if cfg.DLPCacheTTLSeconds != 30 {
		t.Errorf("DLPCacheTTLSeconds = %d, want 30", cfg.DLPCacheTTLSeconds)
	}
	if cfg.LargeContentThreshold != defaults.LargeContentThreshold {
		t.Errorf("LargeContentThreshold = %d, want default %d",
			cfg.LargeContentThreshold, defaults.LargeContentThreshold)
	}
	if cfg.DLPCacheCapacity != defaults.DLPCacheCapacity {
		t.Errorf("DLPCacheCapacity = %d, want default %d",
			cfg.DLPCacheCapacity, defaults.DLPCacheCapacity)
	}
}

// TestLoad_DLPIntFields_NegativeRejected confirms validation rejects
// negative values for the DLP ints. They have no useful meaning
// — the consumer code branches on positive vs zero only — so a
// negative reaches no production code path.
func TestLoad_DLPIntFields_NegativeRejected(t *testing.T) {
	dir := t.TempDir()
	for _, key := range []string{
		"large_content_threshold",
		"dlp_cache_ttl_seconds",
		"dlp_cache_capacity",
		"dlp_rate_limit_per_sec",
	} {
		path := filepath.Join(dir, key+".yaml")
		if err := os.WriteFile(path, []byte(key+": -1\n"), 0o600); err != nil {
			t.Fatalf("write %s: %v", key, err)
		}
		if _, err := Load(path); err == nil {
			t.Errorf("Load(%s: -1): expected error", key)
		}
	}
}
