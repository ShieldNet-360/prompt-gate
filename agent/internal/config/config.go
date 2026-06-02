// Package config loads and validates the YAML configuration for the
// Prompt Gate agent. Defaults are applied when fields are omitted, and a
// missing config file is treated as "use all defaults".
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the runtime configuration for the agent.
type Config struct {
	UpstreamDNS        string        `yaml:"upstream_dns"`
	DNSListen          string        `yaml:"dns_listen"`
	APIListen          string        `yaml:"api_listen"`
	RulePaths          []string      `yaml:"rule_paths"`
	DBPath             string        `yaml:"db_path"`
	StatsFlushInterval time.Duration `yaml:"stats_flush_interval"`

	// DLPPatternsPath is the path to the rules/dlp_patterns.json file.
	// Optional — leaving it blank disables DLP at agent startup.
	DLPPatternsPath string `yaml:"dlp_patterns"`

	// DLPExclusionsPath is the path to the rules/dlp_exclusions.json
	// file. Optional; when blank, no exclusions are loaded.
	DLPExclusionsPath string `yaml:"dlp_exclusions"`

	// RuleUpdateURL is the absolute HTTP(S) URL of a manifest.json
	// that the agent polls for rule-bundle updates. An empty value
	// disables the updater.
	RuleUpdateURL string `yaml:"rule_update_url"`

	// RuleUpdateInterval is the polling cadence. Defaults to 6h.
	RuleUpdateInterval time.Duration `yaml:"rule_update_interval"`

	// RuleUpdatePublicKey is the hex-encoded Ed25519 public key used
	// to verify the X-Signature header on rule manifest responses
	// (SE-03). When blank, signature verification is skipped.
	RuleUpdatePublicKey string `yaml:"rule_update_public_key"`

	// RulesDir is the on-disk directory the updater writes rule
	// files into. Defaults to the dirname of the first RulePaths
	// entry, or "./rules" when RulePaths is empty.
	RulesDir string `yaml:"rules_dir"`

	// ProxyListen is the local MITM proxy listen address. Defaults
	// to 127.0.0.1:8443. Always loopback only; binding a public
	// interface is unsupported.
	ProxyListen string `yaml:"proxy_listen"`

	// ProxyEnabled toggles whether the MITM proxy auto-starts with
	// the agent. Off by default; the Electron UI / API also flips it
	// at runtime via POST /api/proxy/enable.
	ProxyEnabled bool `yaml:"proxy_enabled"`

	// CACertPath / CAKeyPath are where the per-device Root CA is
	// persisted. Defaults to ~/.prompt-gate/ca.crt and ca.key.
	CACertPath string `yaml:"ca_cert_path"`
	CAKeyPath  string `yaml:"ca_key_path"`

	// ProxyPinningBypass is the list of hostnames the proxy should
	// pass through opaquely even when the policy engine would
	// classify them as Tier 2 — used as an escape hatch for apps
	// that pin certificates and break under MITM.
	ProxyPinningBypass []string `yaml:"proxy_pinning_bypass"`

	// ProfilePath is the path to a local enterprise profile JSON
	// file. Optional — leave blank to skip local profile loading.
	ProfilePath string `yaml:"profile_path"`

	// ProfileURL is the URL of an enterprise profile JSON document.
	// When set, the agent fetches the profile on startup. ProfilePath
	// takes precedence over ProfileURL when both are set.
	ProfileURL string `yaml:"profile_url"`

	// HeartbeatURL is the URL the agent POSTs an aggregate heartbeat
	// to. Empty (default) disables the heartbeat. The payload is
	// strictly {agent_version, os_type, os_arch, aggregate_counters}
	// — no access data ever leaves the device.
	HeartbeatURL string `yaml:"heartbeat_url"`

	// HeartbeatInterval is the cadence at which heartbeats are sent
	// when HeartbeatURL is non-empty. Defaults to 1h.
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`

	// LocalRulesDir is the override directory for admin-managed
	// allow/block lists and DLP overrides. Defaults to RulesDir/local
	// when blank. Files in this directory are merged on top of the
	// bundled rules without modifying them.
	LocalRulesDir string `yaml:"local_rules_dir"`

	// LargeContentThreshold is the byte size above which the DLP
	// pipeline drops low/medium-severity patterns and only runs
	// critical/high. Defaults to 51200 (50 KiB). Explicitly setting
	// this to 0 in YAML disables adaptive scanning so every payload
	// runs the full pattern set; omitting the field keeps the
	// default. Negative values are rejected at load time.
	LargeContentThreshold int `yaml:"large_content_threshold"`

	// DLPCacheTTLSeconds is the lifetime of the in-memory scan
	// result cache. Explicitly setting this to 0 in YAML disables
	// caching entirely; omitting the field keeps the 5s default.
	// Negative values are rejected at load time.
	DLPCacheTTLSeconds int `yaml:"dlp_cache_ttl_seconds"`

	// DLPCacheCapacity is the maximum number of entries the scan
	// cache holds. Defaults to 1024 when omitted. Explicitly setting
	// this to 0 in YAML also keeps the built-in default — the cache
	// always retains at least one slot so it can dedupe back-to-back
	// scans of the same content.
	DLPCacheCapacity int `yaml:"dlp_cache_capacity"`

	// DLPRateLimitPerSec is the per-process rate limit applied to
	// POST /api/dlp/scan. Defaults to 100 requests per second when
	// omitted. Explicitly setting this to 0 in YAML disables the
	// limiter entirely so synthetic load tests can opt out. Negative
	// values are rejected at load time.
	DLPRateLimitPerSec int `yaml:"dlp_rate_limit_per_sec"`

	// DLPDisabledCategories is the list of pattern categories
	// (e.g. "pii", "code_secret") that should be ignored when
	// scanning. Empty by default — all categories are active.
	DLPDisabledCategories []string `yaml:"dlp_disabled_categories"`

	// AgentUpdateManifestURL is the HTTPS URL of the release
	// manifest used by /api/agent/update-check. Leave blank to
	// disable agent self-update entirely (endpoints return 503).
	AgentUpdateManifestURL string `yaml:"agent_update_manifest_url"`

	// AgentUpdatePublicKey is the hex-encoded Ed25519 public key
	// used to verify release signatures. Required when
	// AgentUpdateManifestURL is set; without it the endpoints
	// remain 503 — an unverified release path would defeat the
	// entire self-update threat model.
	AgentUpdatePublicKey string `yaml:"agent_update_public_key"`
}

// Default returns a Config populated with the documented defaults.
func Default() Config {
	return Config{
		UpstreamDNS:           "8.8.8.8:53",
		DNSListen:             "127.0.0.1:15353",
		APIListen:             "127.0.0.1:9191",
		RulePaths:             nil,
		DBPath:                "prompt-gate.db",
		StatsFlushInterval:    60 * time.Second,
		RuleUpdateURL:         "",
		RuleUpdateInterval:    6 * time.Hour,
		ProxyListen:           "127.0.0.1:8443",
		ProxyEnabled:          false,
		HeartbeatInterval:     time.Hour,
		LargeContentThreshold: 50 * 1024,
		DLPCacheTTLSeconds:    5,
		DLPCacheCapacity:      1024,
		DLPRateLimitPerSec:    100,
	}
}

// Load reads a YAML config file and applies defaults for any unset fields.
// If path is empty or the file does not exist, the returned config is the
// default configuration.
func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return cfg, nil
		}
		return Config{}, fmt.Errorf("read config: %w", err)
	}

	var parsed Config
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	// Re-decode the int fields that have explicit "zero disables"
	// semantics into pointer-typed shadow fields. YAML unmarshal
	// folds an omitted field and an explicit `0` into the same Go
	// zero value on an `int`, so merge() cannot tell them apart on
	// the regular Config view alone.
	var overlay dlpIntOverlay
	if err := yaml.Unmarshal(data, &overlay); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}

	merged := merge(cfg, parsed)
	overlay.apply(&merged)
	if err := merged.validate(); err != nil {
		return Config{}, err
	}
	return merged, nil
}

// dlpIntOverlay re-decodes the four DLP int fields whose
// documented behaviour distinguishes "omitted" from "explicit 0".
// A pointer field lets the YAML decoder give us a nil value when
// the key is absent and a `*int` pointing at zero when the operator
// wrote `: 0` explicitly. This is the only way to recover that
// distinction without changing the public Config struct's field
// types and rippling through every consumer.
type dlpIntOverlay struct {
	LargeContentThreshold *int `yaml:"large_content_threshold"`
	DLPCacheTTLSeconds    *int `yaml:"dlp_cache_ttl_seconds"`
	DLPCacheCapacity      *int `yaml:"dlp_cache_capacity"`
	DLPRateLimitPerSec    *int `yaml:"dlp_rate_limit_per_sec"`
}

// apply copies any explicitly-set overlay values onto cfg. nil
// pointers (omitted keys) are skipped so the default seeded by
// merge() survives.
func (o dlpIntOverlay) apply(cfg *Config) {
	if o.LargeContentThreshold != nil {
		cfg.LargeContentThreshold = *o.LargeContentThreshold
	}
	if o.DLPCacheTTLSeconds != nil {
		cfg.DLPCacheTTLSeconds = *o.DLPCacheTTLSeconds
	}
	if o.DLPCacheCapacity != nil {
		cfg.DLPCacheCapacity = *o.DLPCacheCapacity
	}
	if o.DLPRateLimitPerSec != nil {
		cfg.DLPRateLimitPerSec = *o.DLPRateLimitPerSec
	}
}

func merge(defaults, override Config) Config {
	out := defaults
	if override.UpstreamDNS != "" {
		out.UpstreamDNS = override.UpstreamDNS
	}
	if override.DNSListen != "" {
		out.DNSListen = override.DNSListen
	}
	if override.APIListen != "" {
		out.APIListen = override.APIListen
	}
	if len(override.RulePaths) > 0 {
		out.RulePaths = override.RulePaths
	}
	if override.DBPath != "" {
		out.DBPath = override.DBPath
	}
	if override.StatsFlushInterval != 0 {
		out.StatsFlushInterval = override.StatsFlushInterval
	}
	if override.DLPPatternsPath != "" {
		out.DLPPatternsPath = override.DLPPatternsPath
	}
	if override.DLPExclusionsPath != "" {
		out.DLPExclusionsPath = override.DLPExclusionsPath
	}
	if override.RuleUpdateURL != "" {
		out.RuleUpdateURL = override.RuleUpdateURL
	}
	if override.RuleUpdateInterval != 0 {
		out.RuleUpdateInterval = override.RuleUpdateInterval
	}
	if override.RulesDir != "" {
		out.RulesDir = override.RulesDir
	}
	if override.ProxyListen != "" {
		out.ProxyListen = override.ProxyListen
	}
	if override.ProxyEnabled {
		out.ProxyEnabled = true
	}
	if override.CACertPath != "" {
		out.CACertPath = override.CACertPath
	}
	if override.CAKeyPath != "" {
		out.CAKeyPath = override.CAKeyPath
	}
	if len(override.ProxyPinningBypass) > 0 {
		out.ProxyPinningBypass = override.ProxyPinningBypass
	}
	if override.ProfilePath != "" {
		out.ProfilePath = override.ProfilePath
	}
	if override.ProfileURL != "" {
		out.ProfileURL = override.ProfileURL
	}
	if override.HeartbeatURL != "" {
		out.HeartbeatURL = override.HeartbeatURL
	}
	if override.HeartbeatInterval != 0 {
		out.HeartbeatInterval = override.HeartbeatInterval
	}
	if override.LocalRulesDir != "" {
		out.LocalRulesDir = override.LocalRulesDir
	}
	// The four DLP int fields with "zero disables" semantics are
	// handled by dlpIntOverlay.apply() after merge() runs, so
	// they are intentionally not copied here — a `!= 0` guard would
	// silently drop the operator's explicit `0`.
	if len(override.DLPDisabledCategories) > 0 {
		out.DLPDisabledCategories = override.DLPDisabledCategories
	}
	if override.AgentUpdateManifestURL != "" {
		out.AgentUpdateManifestURL = override.AgentUpdateManifestURL
	}
	if override.AgentUpdatePublicKey != "" {
		out.AgentUpdatePublicKey = override.AgentUpdatePublicKey
	}
	return out
}

func (c Config) validate() error {
	if c.UpstreamDNS == "" {
		return errors.New("upstream_dns must not be empty")
	}
	if c.DNSListen == "" {
		return errors.New("dns_listen must not be empty")
	}
	if c.APIListen == "" {
		return errors.New("api_listen must not be empty")
	}
	if c.DBPath == "" {
		return errors.New("db_path must not be empty")
	}
	if c.StatsFlushInterval <= 0 {
		return errors.New("stats_flush_interval must be positive")
	}
	if c.RuleUpdateInterval < 0 {
		return errors.New("rule_update_interval must not be negative")
	}
	if c.HeartbeatInterval < 0 {
		return errors.New("heartbeat_interval must not be negative")
	}
	if c.ProxyListen == "" {
		return errors.New("proxy_listen must not be empty")
	}
	if c.LargeContentThreshold < 0 {
		return errors.New("large_content_threshold must not be negative")
	}
	if c.DLPCacheTTLSeconds < 0 {
		return errors.New("dlp_cache_ttl_seconds must not be negative")
	}
	if c.DLPCacheCapacity < 0 {
		return errors.New("dlp_cache_capacity must not be negative")
	}
	if c.DLPRateLimitPerSec < 0 {
		return errors.New("dlp_rate_limit_per_sec must not be negative")
	}

	// SE-12: Validate that listen addresses bind to loopback only.
	for _, pair := range []struct{ name, addr string }{
		{"dns_listen", c.DNSListen},
		{"api_listen", c.APIListen},
		{"proxy_listen", c.ProxyListen},
	} {
		if err := validateLoopback(pair.name, pair.addr); err != nil {
			return err
		}
	}
	return nil
}

// validateLoopback ensures addr is a loopback address (127.0.0.1, ::1,
// or the hostname "localhost"). Non-loopback binds would expose internal
// services to the network.
func validateLoopback(name, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if strings.ToLower(host) != "localhost" {
			return fmt.Errorf("%s %q: must bind to a loopback address", name, addr)
		}
		return nil
	}
	if !ip.IsLoopback() {
		return fmt.Errorf("%s %q: must bind to a loopback address, not %s", name, addr, ip)
	}
	return nil
}
