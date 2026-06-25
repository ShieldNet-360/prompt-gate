// Command agent runs the Prompt Gate agent: DNS resolver +
// policy engine + SQLite-backed config/stats + local HTTP API.
package main

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/alerter"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/api"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/config"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/dns"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/heartbeat"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/logging"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/mcp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/notify"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/policy"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/profile"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/proxy"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/rules"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/tamper"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/updater"
)

// version is overridable at build time via -ldflags.
var version = "0.1.0"

// log is a convenience alias for the global logger.
var log = logging.Log

func main() {
	configPath := flag.String("config", "config.yaml", "path to YAML config file")
	nativeMode := flag.Bool("native-messaging", false,
		"run as a Chrome Native Messaging host on stdin/stdout instead of a daemon")
	mcpMode := flag.Bool("mcp", false,
		"run as a Model Context Protocol (MCP) stdio tool server instead of a daemon")
	flag.Parse()

	api.Version = version

	// Chrome / Firefox launch the Native Messaging host with the
	// caller's chrome-extension:// (or moz-extension://) origin as the
	// first positional argument and no flags. Auto-detect that calling
	// convention so the same host manifest can point straight at the
	// agent binary without needing a wrapper script.
	if !*nativeMode && isNativeMessagingArgv(flag.Args()) {
		*nativeMode = true
	}

	if *nativeMode {
		if err := runNativeMessaging(*configPath); err != nil {
			log.Errorf("agent (native): %v", err)
			os.Exit(1)
		}
		return
	}

	if *mcpMode {
		if err := runMCP(*configPath); err != nil {
			log.Errorf("agent (mcp): %v", err)
			os.Exit(1)
		}
		return
	}

	if err := run(*configPath); err != nil {
		log.Errorf("agent: %v", err)
		os.Exit(1)
	}
}

// isNativeMessagingArgv reports whether the positional arguments look
// like a browser Native Messaging invocation. Chrome passes the
// caller's extension origin as argv[1] (e.g.
// "chrome-extension://<id>/"); Firefox uses "moz-extension://<UUID>/"
// and additionally appends the extension ID on Windows. Returns true
// when the first positional arg matches either scheme.
func isNativeMessagingArgv(args []string) bool {
	if len(args) == 0 {
		return false
	}
	first := args[0]
	return strings.HasPrefix(first, "chrome-extension://") ||
		strings.HasPrefix(first, "moz-extension://")
}

// runNativeMessaging serves the Chrome Native Messaging protocol on
// stdin/stdout. It mirrors daemon mode's DLP setup so scan results
// match the HTTP fallback: configured ScoreWeights and Thresholds are
// loaded from the SQLite store (falling back to defaults when the
// store has no row yet) and the same pattern / exclusion files are
// rebuilt into the pipeline. DNS and API servers are intentionally
// skipped — Chrome spawns one host process per extension session and
// tears it down on disconnect.
func runNativeMessaging(configPath string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pipeline, statsStore, err := buildStdioPipeline(ctx, configPath)
	if err != nil {
		return err
	}
	if statsStore != nil {
		defer statsStore.Close()
	}
	return api.ServeNativeMessaging(ctx, pipeline, statsStore, os.Stdin, os.Stdout)
}

// runMCP serves the Prompt Gate DLP engine as a Model Context Protocol
// (MCP) tool server over stdio (newline-delimited JSON-RPC). Like Native
// Messaging it is a one-shot stdio transport: DNS / API / proxy servers
// are skipped, and the same DLP pipeline setup is reused so verdicts
// match every other transport. Configure it as an `mcpServers` entry in
// Claude Code / Cursor / Windsurf — see docs/mcp-integration.md.
func runMCP(configPath string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pipeline, statsStore, err := buildStdioPipeline(ctx, configPath)
	if err != nil {
		return err
	}
	if statsStore != nil {
		defer statsStore.Close()
	}
	return mcp.NewServer(pipeline, version).Serve(ctx, os.Stdin, os.Stdout)
}

// buildStdioPipeline loads config and assembles a DLP pipeline for the
// stdio transports (Native Messaging and MCP). It mirrors daemon-mode
// DLP setup so scan results match the HTTP fallback: ScoreWeights and
// Thresholds come from the SQLite store (falling back to defaults when
// the store has no row yet) and the same pattern / exclusion files are
// rebuilt into the pipeline. DNS and API servers are intentionally
// skipped. The returned store may be nil; when non-nil the caller owns
// it and must Close it.
func buildStdioPipeline(ctx context.Context, configPath string) (*dlp.Pipeline, *store.Store, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load config: %w", err)
	}
	resolveLocalRulesDir(&cfg)
	if cfg.DLPPatternsPath == "" {
		return nil, nil, fmt.Errorf("stdio transport requires dlp_patterns in config")
	}

	weights := dlp.DefaultScoreWeights()
	thresholds := dlp.DefaultThresholds()
	var statsStore *store.Store
	if cfg.DBPath != "" {
		s, err := store.Open(cfg.DBPath)
		if err != nil {
			return nil, nil, fmt.Errorf("open store: %w", err)
		}
		dlpCfg, err := s.GetDLPConfig(ctx)
		if err != nil {
			s.Close()
			return nil, nil, fmt.Errorf("read dlp_config: %w", err)
		}
		weights = dlp.ScoreWeights{
			HotwordBoost:     dlpCfg.HotwordBoost,
			EntropyBoost:     dlpCfg.EntropyBoost,
			EntropyPenalty:   dlpCfg.EntropyPenalty,
			ExclusionPenalty: dlpCfg.ExclusionPenalty,
			MultiMatchBoost:  dlpCfg.MultiMatchBoost,
		}
		thresholds = dlp.Thresholds{
			Critical: dlpCfg.ThresholdCritical,
			High:     dlpCfg.ThresholdHigh,
			Medium:   dlpCfg.ThresholdMedium,
			Low:      dlpCfg.ThresholdLow,
		}
		statsStore = s
	}

	patterns, err := dlp.MergePatternsFromDir(cfg.DLPPatternsPath, cfg.LocalRulesDir)
	if err != nil {
		if statsStore != nil {
			statsStore.Close()
		}
		return nil, nil, err
	}
	var exclusions []dlp.Exclusion
	if cfg.DLPExclusionsPath != "" {
		exclusions, err = dlp.MergeExclusionsFromDir(cfg.DLPExclusionsPath, cfg.LocalRulesDir)
		if err != nil {
			if statsStore != nil {
				statsStore.Close()
			}
			return nil, nil, err
		}
	}
	pipeline := dlp.NewPipeline(weights, dlp.NewThresholdEngine(thresholds))
	applyDLPRuntimeConfig(pipeline, cfg)
	pipeline.Rebuild(patterns, exclusions)
	if statsStore != nil {
		enableAllowlist(ctx, pipeline, statsStore.DB())
	}
	return pipeline, statsStore, nil
}

// loadCanaryPatterns reads the persisted canary tripwires from the
// store, builds their DLP patterns, and registers them on the live
// pipeline. Kept separate from Rebuild so a rule-file reload never
// drops canaries (the pipeline holds them as an overlay). A nil store
// or empty set is a no-op.
func loadCanaryPatterns(ctx context.Context, s *store.Store, p *dlp.Pipeline) error {
	if s == nil {
		return nil
	}
	canaries, err := s.ListCanaries(ctx)
	if err != nil {
		return err
	}
	patterns := make([]*dlp.Pattern, 0, len(canaries))
	for _, c := range canaries {
		patterns = append(patterns, dlp.CanaryPattern(c.Token, c.Label))
	}
	p.SetCanaryPatterns(patterns)
	return nil
}

// applyDLPRuntimeConfig copies the runtime tunables from the
// loaded YAML config into the pipeline. Called from both daemon and
// native-messaging paths so each transport observes the same defaults.
//
// The four DLP int fields all distinguish "omitted" (keep default)
// from "explicit 0" (disable / opt out) at the config layer; we
// preserve that distinction here so the documented semantics hold
// end-to-end.
func applyDLPRuntimeConfig(p *dlp.Pipeline, cfg config.Config) {
	switch {
	case cfg.LargeContentThreshold > 0:
		p.SetLargeContentThreshold(cfg.LargeContentThreshold)
	case cfg.LargeContentThreshold == 0:
		// Explicit 0 → disable adaptive scanning. The pipeline
		// has no native "never trigger" flag, so pass a ceiling
		// that no realistic payload will exceed.
		p.SetLargeContentThreshold(math.MaxInt)
	}
	if len(cfg.DLPDisabledCategories) > 0 {
		p.SetDisabledCategories(cfg.DLPDisabledCategories)
	}
	if cfg.DLPCacheTTLSeconds > 0 {
		ttl := time.Duration(cfg.DLPCacheTTLSeconds) * time.Second
		p.EnableCache(dlp.NewScanCache(cfg.DLPCacheCapacity, ttl))
	}
	// cfg.DLPCacheTTLSeconds == 0 → leave the pipeline cacheless.

	// Enable the multi-piece correlator. The browser companion
	// supplies session_id (per-tab opaque token); the agent uses it
	// to reassemble secrets split across consecutive pastes.
	// Defaults: 30s session TTL, 256-byte tail, 4096 max sessions.
	p.EnableCorrelator(dlp.NewCorrelator(0, 0, 0))
}

// enableAllowlist wires up the feedback allowlist — per-user "never block
// this value again". Salt is persisted alongside the bearer token in
// ~/.prompt-gate/allowlist-salt; first run creates it. Failure is
// logged but non-fatal — the engine just runs without H.
func enableAllowlist(ctx context.Context, p *dlp.Pipeline, db *sql.DB) {
	saltPath, err := allowlistSaltPath()
	if err != nil {
		log.Errorf("allowlist salt path: %v", err)
		return
	}
	salt, err := dlp.LoadOrGenerateSalt(saltPath)
	if err != nil {
		log.Errorf("load allowlist salt: %v", err)
		return
	}
	a, err := dlp.NewAllowlist(ctx, db, salt, nil)
	if err != nil {
		log.Errorf("init allowlist: %v", err)
		return
	}
	p.EnableAllowlist(a)
}

func run(configPath string) error {
	log.Infof("starting agent v%s", version)
	log.Debugf("loading config from %s", configPath)
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	resolveLocalRulesDir(&cfg)
	log.Debugf("config loaded: dns=%s api=%s proxy=%s db=%s", cfg.DNSListen, cfg.APIListen, cfg.ProxyListen, cfg.DBPath)

	log.Debug("opening SQLite store")
	s, err := store.Open(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()
	log.Debug("SQLite store opened")

	// Build the rule sources from config. Each rule_path entry is taken
	// as the category file path; the category name is derived from the
	// basename for human-friendly display.
	var sources []rules.RuleSource
	for _, p := range cfg.RulePaths {
		sources = append(sources, rules.RuleSource{
			Category: categoryFromPath(p),
			Path:     p,
		})
	}
	log.Debugf("building policy engine with %d rule sources", len(sources))
	engine, err := policy.New(s, sources)
	if err != nil {
		return fmt.Errorf("build policy engine: %w", err)
	}
	log.Debug("policy engine ready")

	counter := stats.New(storeAdapter{s})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logging.Go("stats-flush", func() { counter.Run(ctx, cfg.StatsFlushInterval) })

	log.Debugf("starting DNS resolver on %s (upstream %s)", cfg.DNSListen, cfg.UpstreamDNS)
	forwarder := &dns.MiekgForwarder{Upstream: cfg.UpstreamDNS, Timeout: 3 * time.Second}
	resolver := dns.New(cfg.DNSListen, engine, counter, forwarder)
	if err := resolver.Start(); err != nil {
		// DNS on port 53 requires root. When launched from the Electron
		// app as a normal user this will fail — that's OK, the API and
		// proxy can still operate without local DNS interception.
		log.Warnf("DNS resolver failed to start (non-fatal): %v", err)
	} else {
		log.Infof("DNS resolver listening on %s", cfg.DNSListen)
		defer func() { _ = resolver.Shutdown() }()
	}

	apiServer := api.NewServer(s, engine, counter)

	// Shared notifier: the proxy pushes DLP block events and the API
	// server streams them to Electron via SSE (/api/events).
	notifier := notify.New()
	apiServer.SetNotifier(notifier)

	// SE-02: Persist the per-session bearer token so the Electron app
	// (and other local callers) can authenticate mutating requests.
	if tokenPath, err := apiTokenPath(); err == nil {
		if err := apiServer.WriteTokenFile(tokenPath); err != nil {
			log.Errorf("write api token: %v", err)
		}
	}

	// Apply configured /api/dlp/scan rate limit.
	// Explicit 0 disables the limiter entirely so operators can opt
	// out for synthetic load tests; the config loader already
	// rejects negative values.
	if cfg.DLPRateLimitPerSec > 0 {
		apiServer.SetScanRateLimit(float64(cfg.DLPRateLimitPerSec), cfg.DLPRateLimitPerSec)
	} else {
		apiServer.SetScanRateLimit(0, 1)
	}

	// Expose rule-file mtimes through /api/status.
	// Missing files are tolerated by collectRuleFileInfo on the server
	// side, so we can pass the configured paths unfiltered.
	apiServer.SetRuleFiles(ruleFilesForStatus(cfg))

	// Optional self-updater. Builds without a
	// manifest URL or a valid Ed25519 public key omit the updater
	// entirely, and /api/agent/update* return 503.
	if cfg.AgentUpdateManifestURL != "" && cfg.AgentUpdatePublicKey != "" {
		pubBytes, err := hex.DecodeString(cfg.AgentUpdatePublicKey)
		if err == nil && len(pubBytes) == ed25519.PublicKeySize {
			self, err := updater.New(updater.Options{
				ManifestURL: cfg.AgentUpdateManifestURL,
				Current:     version,
				PublicKey:   ed25519.PublicKey(pubBytes),
			})
			if err == nil {
				apiServer.SetAgentUpdater(agentUpdaterAdapter{self: self})
			}
		}
	}

	// Optional DLP pipeline: only stand it up when rules/dlp_patterns.json
	// is configured. Minimal deployments leave both DLP paths blank and
	// the /api/dlp/* endpoints return 503 service-unavailable. The
	// pipeline is hoisted to function scope so the startup profile
	// loader (below) can push its merged DLP thresholds and weights
	// straight into the live pipeline — otherwise a profile imported
	// at boot would persist to SQLite but only take effect after the
	// next restart, silently diverging from GET /api/dlp/config.
	var pipeline *dlp.Pipeline
	if cfg.DLPPatternsPath != "" {
		log.Debug("initialising DLP pipeline")
		dlpCfg, err := s.GetDLPConfig(ctx)
		if err != nil {
			return fmt.Errorf("read dlp_config: %w", err)
		}
		thresholds := dlp.Thresholds{
			Critical: dlpCfg.ThresholdCritical,
			High:     dlpCfg.ThresholdHigh,
			Medium:   dlpCfg.ThresholdMedium,
			Low:      dlpCfg.ThresholdLow,
		}
		weights := dlp.ScoreWeights{
			HotwordBoost:     dlpCfg.HotwordBoost,
			EntropyBoost:     dlpCfg.EntropyBoost,
			EntropyPenalty:   dlpCfg.EntropyPenalty,
			ExclusionPenalty: dlpCfg.ExclusionPenalty,
			MultiMatchBoost:  dlpCfg.MultiMatchBoost,
		}
		patterns, err := dlp.MergePatternsFromDir(cfg.DLPPatternsPath, cfg.LocalRulesDir)
		if err != nil {
			return err
		}
		var exclusions []dlp.Exclusion
		if cfg.DLPExclusionsPath != "" {
			exclusions, err = dlp.MergeExclusionsFromDir(cfg.DLPExclusionsPath, cfg.LocalRulesDir)
			if err != nil {
				return err
			}
		}
		pipeline = dlp.NewPipeline(weights, dlp.NewThresholdEngine(thresholds))
		applyDLPRuntimeConfig(pipeline, cfg)
		pipeline.Rebuild(patterns, exclusions)
		enableAllowlist(ctx, pipeline, s.DB())
		apiServer.SetDLP(pipeline)
		apiServer.SetCanaryRegistrar(pipeline)
		// Load any persisted canary tripwires into the live pipeline so
		// they survive restarts. Best-effort: a load failure leaves the
		// pipeline running without canaries rather than failing startup.
		if err := loadCanaryPatterns(ctx, s, pipeline); err != nil {
			log.Warnf("canary load failed: %v", err)
		}
		log.Infof("DLP pipeline ready (patterns=%s)", cfg.DLPPatternsPath)

		// Wire the local MITM proxy. The controller is constructed
		// unconditionally so the API surface always has a real
		// implementation behind /api/proxy/*; the listener itself
		// only starts when proxy_enabled=true (auto-start) or the
		// caller hits POST /api/proxy/enable.
		log.Debug("building MITM proxy controller")
		caCertPath, caKeyPath := resolveCAPaths(cfg)
		log.Debugf("proxy CA cert=%s key=%s", caCertPath, caKeyPath)
		pinning := buildPinningSet(cfg.ProxyPinningBypass)
		log.Debugf("proxy pinning bypass hosts: %d entries", len(pinning))
		controller, err := proxy.NewController(proxy.ControllerConfig{
			ListenAddr:       cfg.ProxyListen,
			CertPath:         caCertPath,
			KeyPath:          caKeyPath,
			UpstreamCABundle: cfg.ProxyUpstreamCABundle,
			Policy: proxy.PolicyCheckerFunc(func(host string) proxy.PolicyAction {
				if _, bypass := pinning[strings.ToLower(host)]; bypass {
					return proxy.PolicyAllow
				}
				switch engine.CheckDomain(host) {
				case policy.AllowWithDLP:
					return proxy.PolicyAllowDLP
				case policy.Deny:
					return proxy.PolicyDeny
				default:
					// Categorized but currently allowed: MITM so the
					// proxy re-checks the live policy on every request.
					if engine.IsCategorized(host) {
						return proxy.PolicyMonitor
					}
					return proxy.PolicyAllow
				}
			}),
			Scanner:  pipeline,
			Stats:    proxyStats{s},
			Notifier: notifier,
			Recorder: storeRecorder{s},
		})
		if err != nil {
			return fmt.Errorf("build proxy controller: %w", err)
		}
		log.Debugf("proxy controller created (listen=%s)", cfg.ProxyListen)
		apiServer.SetProxyController(&proxyAdapter{c: controller})
		apiServer.SetConfigPatcher(func(addr string) error {
			return config.UpdateProxyListen(configPath, addr)
		})
		if cfg.ProxyEnabled {
			log.Infof("auto-enabling proxy on %s", cfg.ProxyListen)
			if _, err := controller.Enable(ctx); err != nil {
				// A port conflict on the proxy listener (a stale or
				// duplicate agent still holding the address) must NOT
				// abort the whole agent — DNS, the API surface, and the
				// DLP scan endpoint are all still useful. Log an
				// actionable warning and keep running; the caller can
				// retry POST /api/proxy/enable once the conflict clears.
				if errors.Is(err, proxy.ErrAddrInUse) {
					log.Warnf("auto-enable proxy skipped: %v", err)
				} else {
					return fmt.Errorf("auto-enable proxy: %w", err)
				}
			} else {
				log.Info("proxy enabled successfully")
				defer func() {
					shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
					defer c()
					_ = controller.Disable(shutdownCtx, false)
				}()
			}
		}

		// Recover from a prior non-graceful exit: if the system proxy was
		// left pointing at us but no listener is serving, restore network
		// settings so the user isn't silently black-holed (the "blocked
		// with no clear reason" bug). Loads persisted sysconf flags too so
		// a later graceful shutdown restores correctly.
		api.ReconcileSysConfOnStartup(controller.Status().Running)

		// Wire the rule updater after the pipeline so the reload
		// callback can refresh both the policy engine's lookup table
		// and the DLP automaton from the freshly-downloaded files.
		if cfg.RuleUpdateURL != "" {
			rulesDir := cfg.RulesDir
			if rulesDir == "" {
				rulesDir = defaultRulesDir(cfg.RulePaths)
			}
			// The updater writes downloads as rulesDir/<basename>; the
			// reload callback below reads cfg.DLPPatternsPath /
			// cfg.RulePaths verbatim. If any of those paths point
			// outside rulesDir we'd download new bytes that the live
			// pipeline never reads — a silent staleness bug. Fail loud
			// at startup instead of letting POST /api/rules/update lie.
			if err := validateRulesAlignment(rulesDir, cfg.RulePaths,
				cfg.DLPPatternsPath, cfg.DLPExclusionsPath); err != nil {
				return fmt.Errorf("rule_update_url is set but %w", err)
			}
			var ruleUpdatePubKey ed25519.PublicKey
			if cfg.RuleUpdatePublicKey != "" {
				pubBytes, err := hex.DecodeString(cfg.RuleUpdatePublicKey)
				if err != nil || len(pubBytes) != ed25519.PublicKeySize {
					return fmt.Errorf("rule_update_public_key: invalid Ed25519 key (want %d hex-encoded bytes)", ed25519.PublicKeySize)
				}
				ruleUpdatePubKey = ed25519.PublicKey(pubBytes)
			}
			updater, err := rules.New(rules.Options{
				ManifestURL:  cfg.RuleUpdateURL,
				PollInterval: cfg.RuleUpdateInterval,
				RulesDir:     rulesDir,
				Store:        s,
				PublicKey:    ruleUpdatePubKey,
				Reload: func(ctx context.Context) error {
					if err := engine.Reload(ctx); err != nil {
						return err
					}
					p, err := dlp.MergePatternsFromDir(cfg.DLPPatternsPath, cfg.LocalRulesDir)
					if err != nil {
						return err
					}
					var ex []dlp.Exclusion
					if cfg.DLPExclusionsPath != "" {
						ex, err = dlp.MergeExclusionsFromDir(cfg.DLPExclusionsPath, cfg.LocalRulesDir)
						if err != nil {
							return err
						}
					}
					pipeline.Rebuild(p, ex)
					return nil
				},
			})
			if err != nil {
				return fmt.Errorf("build updater: %w", err)
			}
			apiServer.SetRuleUpdater(updater)
			logging.Go("rule-updater", func() { updater.Start(ctx) })
		}
	}

	// Admin rule override store. An empty
	// local_rules_dir disables overrides; otherwise the store always
	// exposes both override files (empty placeholders are created
	// on first run), and we register them with the policy engine
	// here so a later POST/DELETE /api/rules/override Reload picks
	// them up without requiring a restart.
	overrideStore, err := rules.NewOverrideStore(cfg.LocalRulesDir)
	if err != nil {
		return fmt.Errorf("init override store: %w", err)
	}
	apiServer.SetRuleOverride(overrideStore)
	if overrides := overrideStore.Sources(); len(overrides) > 0 {
		engine.SetSources(append(append([]rules.RuleSource(nil), sources...), overrides...))
		if err := engine.Reload(ctx); err != nil {
			return fmt.Errorf("reload with overrides: %w", err)
		}
	}

	// Enterprise profile holder. Profiles arrive
	// via /api/profile/import or are loaded eagerly from
	// cfg.ProfilePath / cfg.ProfileURL on startup.
	holder := profile.NewHolder(nil)
	applyStore := &profileApplyAdapter{store: s}
	apiServer.SetProfile(holder, applyStore)
	if err := loadProfileOnStartup(ctx, cfg, holder, applyStore, engine, pipeline); err != nil {
		log.Errorf("profile load failed: %v", err)
	}
	// Optional enterprise-profile auto-refresh: re-fetch + re-apply the
	// profile from profile_url on an interval, with an ETag/Last-Modified
	// delta check, so fleet policy changes propagate without a restart.
	if cfg.ProfileURL != "" && cfg.ProfileUpdateInterval > 0 {
		refresher := profile.NewRefresher(holder, cfg.ProfileURL, cfg.ProfileUpdateInterval,
			func(ctx context.Context, p *profile.Profile) error {
				if err := p.Apply(ctx, profileApplyOptions(applyStore, engine, pipeline)); err != nil {
					return err
				}
				return holder.Set(p)
			})
		go refresher.Start(ctx, func(format string, args ...interface{}) { log.Infof(format, args...) })
		log.Infof("enterprise profile auto-refresh enabled (every %s)", cfg.ProfileUpdateInterval)
	}

	// Tamper detector goroutine.
	if cfg.DNSListen != "" {
		expectedDNS, _ := splitHostPort(cfg.DNSListen)
		// Only assert the system proxy is wired through us when the MITM
		// proxy is actually enabled. Otherwise the detector would
		// transition from its initialised ProxyOK=true to false on the
		// first tick and increment tamper_detections_total on every
		// agent startup that doesn't enable the proxy.
		expectedProxy := ""
		if cfg.ProxyEnabled {
			expectedProxy = cfg.ProxyListen
		}
		detector := tamper.New(tamper.Options{
			ExpectedDNSServer: expectedDNS,
			ExpectedProxyAddr: expectedProxy,
			Reporter:          counter,
		})
		apiServer.SetTamperReporter(tamperAdapter{detector: detector})
		logging.Go("tamper-detector", func() { detector.Start(ctx) })
	}

	// Optional heartbeat. URL=="" disables it.
	hb, err := heartbeat.New(heartbeat.Options{
		URL:          cfg.HeartbeatURL,
		AgentVersion: version,
		Interval:     cfg.HeartbeatInterval,
		Stats:        counter,
	})
	if err != nil {
		return fmt.Errorf("init heartbeat: %w", err)
	}
	if hb != nil {
		logging.Go("heartbeat", func() {
			hb.Start(ctx, func(format string, args ...interface{}) {
				log.Infof(format, args...)
			})
		})
	}

	// Optional threshold webhook alerter. URL=="" disables it.
	al, err := alerter.New(alerter.Options{
		URL:             cfg.AlertWebhookURL,
		AgentVersion:    version,
		ThresholdBlocks: int64(cfg.AlertThresholdBlocks),
		Interval:        cfg.AlertInterval,
		Stats:           counter,
	})
	if err != nil {
		return fmt.Errorf("init alerter: %w", err)
	}
	if al != nil {
		apiServer.SetAlertReporter(alertAdapter{a: al})
		go al.Start(ctx, func(format string, args ...interface{}) {
			log.Infof(format, args...)
		})
	}

	httpServer, err := apiServer.ListenAndServe(cfg.APIListen)
	if err != nil {
		return fmt.Errorf("start API: %w", err)
	}
	defer func() {
		shutdownCtx, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		_ = httpServer.Shutdown(shutdownCtx)
	}()

	log.Infof("agent ready (dns=%s api=%s proxy=%s)", cfg.DNSListen, cfg.APIListen, cfg.ProxyListen)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Info("agent shutting down")
	api.RestoreAllSysConf()
	return nil
}

// validateRulesAlignment checks that every rule file the live agent
// reads at runtime resolves to a sibling of rulesDir. The updater
// writes downloaded bytes to rulesDir/<basename>, then calls the
// reload callback which re-reads cfg.DLPPatternsPath /
// cfg.DLPExclusionsPath / cfg.RulePaths verbatim. Misaligned paths
// therefore land in a directory the pipeline never reads, so
// POST /api/rules/update would happily return {updated: true} while
// every scan keeps using the on-disk file from the original install.
//
// Comparison is against the absolute-cleaned form of rulesDir so
// "./rules" and "/etc/prompt-gate/rules/" with a trailing slash both
// behave the same way as canonical paths.
func validateRulesAlignment(rulesDir string, rulePaths []string, dlpPatternsPath, dlpExclusionsPath string) error {
	absDir, err := filepath.Abs(rulesDir)
	if err != nil {
		return fmt.Errorf("resolve rules_dir %q: %w", rulesDir, err)
	}
	absDir = filepath.Clean(absDir)
	check := func(field, p string) error {
		if p == "" {
			return nil
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return fmt.Errorf("resolve %s %q: %w", field, p, err)
		}
		if filepath.Dir(filepath.Clean(abs)) != absDir {
			return fmt.Errorf("%s = %q is not directly inside rules_dir = %q; "+
				"the rule updater writes downloaded files into rules_dir but the "+
				"live pipeline keeps reading the original path, so updates would "+
				"silently never take effect. Move the file into rules_dir, or set "+
				"rules_dir to the file's parent directory",
				field, p, rulesDir)
		}
		return nil
	}
	for _, p := range rulePaths {
		if err := check("rule_paths entry", p); err != nil {
			return err
		}
	}
	if err := check("dlp_patterns", dlpPatternsPath); err != nil {
		return err
	}
	if err := check("dlp_exclusions", dlpExclusionsPath); err != nil {
		return err
	}
	return nil
}

// resolveLocalRulesDir applies the documented "RulesDir/local"
// fallback when local_rules_dir is blank, mirroring how callers
// resolve RulesDir at use-site. Without this the override store
// would receive an empty path and silently reject every Add/Remove
// with "store disabled (no directory configured)", so the admin
// override UI and POST /api/rules/override would 500 unless the
// user had explicitly set local_rules_dir in config.yaml.
func resolveLocalRulesDir(cfg *config.Config) {
	if cfg.LocalRulesDir != "" {
		return
	}
	base := cfg.RulesDir
	if base == "" {
		base = defaultRulesDir(cfg.RulePaths)
	}
	cfg.LocalRulesDir = filepath.Join(base, "local")
}

// defaultRulesDir derives the directory rule files live in when the
// caller did not set RulesDir explicitly. Each RulePaths entry is
// typically RulesDir/<category>.txt, so the parent of the first entry
// is a safe default. Returns "rules" if RulePaths is empty.
func defaultRulesDir(rulePaths []string) string {
	if len(rulePaths) == 0 {
		return "rules"
	}
	dir := rulePaths[0]
	for i := len(dir) - 1; i >= 0; i-- {
		if dir[i] == '/' || dir[i] == '\\' {
			return dir[:i]
		}
	}
	return "."
}

// categoryAcronyms lists rule-file words that should be emitted in all
// uppercase so the derived category name matches the seeded categories
// in store.seedDefaults. Keep this list in sync with that seed.
var categoryAcronyms = map[string]bool{
	"ai":  true,
	"dlp": true,
}

// categoryFromPath turns "rules/ai_chat_blocked.txt" into "AI Chat Blocked".
// Words are split on '_' / '-'; recognized acronyms are uppercased and other
// words are title-cased so the result matches store.seedDefaults entries.
func categoryFromPath(path string) string {
	base := path
	if idx := strings.LastIndexAny(base, "/\\"); idx >= 0 {
		base = base[idx+1:]
	}
	if idx := strings.LastIndexByte(base, '.'); idx >= 0 {
		base = base[:idx]
	}
	words := strings.FieldsFunc(base, func(r rune) bool {
		return r == '_' || r == '-'
	})
	for i, w := range words {
		lower := strings.ToLower(w)
		if categoryAcronyms[lower] {
			words[i] = strings.ToUpper(lower)
			continue
		}
		words[i] = strings.ToUpper(lower[:1]) + lower[1:]
	}
	return strings.Join(words, " ")
}

// storeAdapter bridges store.Store to stats.Store, converting between
// store.AggregateStats and stats.Snapshot (they have identical fields).
type storeAdapter struct{ s *store.Store }

func (a storeAdapter) GetStats(ctx context.Context) (stats.Snapshot, error) {
	v, err := a.s.GetStats(ctx)
	if err != nil {
		return stats.Snapshot{}, err
	}
	return stats.Snapshot{
		DNSQueriesTotal:       v.DNSQueriesTotal,
		DNSBlocksTotal:        v.DNSBlocksTotal,
		DLPScansTotal:         v.DLPScansTotal,
		DLPBlocksTotal:        v.DLPBlocksTotal,
		TamperDetectionsTotal: v.TamperDetectionsTotal,
	}, nil
}

func (a storeAdapter) AddStats(ctx context.Context, delta stats.Snapshot) error {
	return a.s.AddStats(ctx, store.AggregateStats{
		DNSQueriesTotal:       delta.DNSQueriesTotal,
		DNSBlocksTotal:        delta.DNSBlocksTotal,
		DLPScansTotal:         delta.DLPScansTotal,
		DLPBlocksTotal:        delta.DLPBlocksTotal,
		TamperDetectionsTotal: delta.TamperDetectionsTotal,
	})
}

// proxyStats adapts store.Store to proxy.StatsBumper. The proxy can't
// import store directly without inflating the package's dependency
// graph; this tiny adapter keeps the wiring private to main.
type proxyStats struct{ s *store.Store }

func (p proxyStats) BumpDLP(ctx context.Context, blocked bool) error {
	if p.s == nil {
		return nil
	}
	delta := store.AggregateStats{DLPScansTotal: 1}
	if blocked {
		delta.DLPBlocksTotal = 1
	}
	return p.s.AddStats(ctx, delta)
}

// storeRecorder adapts store.Store to proxy.EventRecorder so block
// events are persisted to SQLite.
type storeRecorder struct{ s *store.Store }

func (r storeRecorder) RecordBlockEvent(ctx context.Context, eventType, host, patternName string) error {
	if r.s == nil {
		return nil
	}
	return r.s.InsertBlockEvent(ctx, eventType, host, patternName)
}

// proxyAdapter bridges the proxy.Controller's StatusSnapshot to the
// api.ProxyController interface. Keeping the wire shape in the api
// package (not the proxy package) avoids the proxy package having to
// import api just to produce its own JSON.
type proxyAdapter struct{ c *proxy.Controller }

func (p *proxyAdapter) Enable(ctx context.Context) (string, error) {
	return p.c.Enable(ctx)
}

func (p *proxyAdapter) Disable(ctx context.Context, removeCA bool) error {
	return p.c.Disable(ctx, removeCA)
}

func (p *proxyAdapter) Status() api.ProxyStatus {
	snap := p.c.Status()
	return api.ProxyStatus{
		Running:         snap.Running,
		CAInstalled:     snap.CAInstalled,
		ProxyConfigured: snap.ProxyConfigured,
		ListenAddr:      snap.ListenAddr,
		CACertPath:      snap.CACertPath,
		DLPScansTotal:   snap.DLPScansTotal,
		DLPBlocksTotal:  snap.DLPBlocksTotal,
	}
}

func (p *proxyAdapter) SetListenAddr(ctx context.Context, addr string) error {
	return p.c.SetListenAddr(ctx, addr)
}

func (p *proxyAdapter) SetUpstreamCA(pem []byte) ([]string, error) {
	return p.c.SetUpstreamCA(pem)
}

func (p *proxyAdapter) ClearUpstreamCA() error { return p.c.ClearUpstreamCA() }

func (p *proxyAdapter) UpstreamCAStatus() (bool, []string) {
	return p.c.UpstreamCAStatus()
}

// allowlistSaltPath returns the path where the per-install feedback-allowlist
// salt is written (~/.prompt-gate/allowlist-salt). Returns an error
// when HOME cannot be determined.
func allowlistSaltPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".prompt-gate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "allowlist-salt"), nil
}

// apiTokenPath returns the path where the per-session bearer token is
// written (~/.prompt-gate/api-token). Returns an error when HOME
// cannot be determined.
func apiTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(home, ".prompt-gate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	return filepath.Join(dir, "api-token"), nil
}

// resolveCAPaths returns the CA cert / key paths, falling back to
// ~/.prompt-gate/ca.{crt,key} when the config leaves them blank.
// When HOME cannot be resolved (rare on CI containers) the fallback
// is "./prompt-gate-ca.{crt,key}" relative to the agent's working
// directory.
func resolveCAPaths(cfg config.Config) (string, string) {
	cert := cfg.CACertPath
	key := cfg.CAKeyPath
	if cert != "" && key != "" {
		return cert, key
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		if cert == "" {
			cert = "prompt-gate-ca.crt"
		}
		if key == "" {
			key = "prompt-gate-ca.key"
		}
		return cert, key
	}
	dir := filepath.Join(home, ".prompt-gate")
	if cert == "" {
		cert = filepath.Join(dir, "ca.crt")
	}
	if key == "" {
		key = filepath.Join(dir, "ca.key")
	}
	return cert, key
}

// buildPinningSet turns the configured proxy_pinning_bypass list into
// a lowercased lookup set for O(1) hostname checks on the proxy hot
// path.
func buildPinningSet(hosts []string) map[string]struct{} {
	if len(hosts) == 0 {
		return map[string]struct{}{}
	}
	out := make(map[string]struct{}, len(hosts))
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h != "" {
			out[h] = struct{}{}
		}
	}
	return out
}

func (a storeAdapter) ResetStats(ctx context.Context) error { return a.s.ResetStats(ctx) }

// profileApplyAdapter adapts *store.Store to profile.PolicyStore.
// The interface uses profile.DLPConfigSnapshot for layering reasons —
// profile/ cannot import store/ without an import cycle once the
// store consumes the profile package.
type profileApplyAdapter struct{ store *store.Store }

func (a *profileApplyAdapter) SetPolicy(ctx context.Context, category, action string) error {
	return a.store.SetPolicy(ctx, category, action)
}

func (a *profileApplyAdapter) GetDLPConfig(ctx context.Context) (profile.DLPConfigSnapshot, error) {
	cfg, err := a.store.GetDLPConfig(ctx)
	if err != nil {
		return profile.DLPConfigSnapshot{}, err
	}
	return profile.DLPConfigSnapshot{
		ThresholdCritical: cfg.ThresholdCritical,
		ThresholdHigh:     cfg.ThresholdHigh,
		ThresholdMedium:   cfg.ThresholdMedium,
		ThresholdLow:      cfg.ThresholdLow,
		HotwordBoost:      cfg.HotwordBoost,
		EntropyBoost:      cfg.EntropyBoost,
		EntropyPenalty:    cfg.EntropyPenalty,
		ExclusionPenalty:  cfg.ExclusionPenalty,
		MultiMatchBoost:   cfg.MultiMatchBoost,
	}, nil
}

func (a *profileApplyAdapter) SetDLPConfig(ctx context.Context, c profile.DLPConfigSnapshot) error {
	return a.store.SetDLPConfig(ctx, store.DLPConfig{
		ThresholdCritical: c.ThresholdCritical,
		ThresholdHigh:     c.ThresholdHigh,
		ThresholdMedium:   c.ThresholdMedium,
		ThresholdLow:      c.ThresholdLow,
		HotwordBoost:      c.HotwordBoost,
		EntropyBoost:      c.EntropyBoost,
		EntropyPenalty:    c.EntropyPenalty,
		ExclusionPenalty:  c.ExclusionPenalty,
		MultiMatchBoost:   c.MultiMatchBoost,
	})
}

// tamperAdapter bridges the *tamper.Detector to the api.TamperReporter
// interface, mapping tamper.Status field-for-field to api.TamperStatus.
type alertAdapter struct{ a *alerter.Alerter }

func (x alertAdapter) AlertStatus() api.AlertStatus {
	st := x.a.Status()
	return api.AlertStatus{
		Enabled:         st.Enabled,
		ThresholdBlocks: st.ThresholdBlocks,
		LastFiredAt:     st.LastFiredAt,
		FiresTotal:      st.FiresTotal,
	}
}

type tamperAdapter struct{ detector *tamper.Detector }

func (a tamperAdapter) Status() api.TamperStatus {
	st := a.detector.Status()
	return api.TamperStatus{
		DNSOK:           st.DNSOK,
		ProxyOK:         st.ProxyOK,
		LastCheck:       st.LastCheck,
		DetectionsTotal: st.DetectionsTotal,
	}
}

// loadProfileOnStartup applies cfg.ProfilePath or cfg.ProfileURL if
// either is set. ProfilePath takes precedence over ProfileURL when
// both are configured (per the config.Config doc comment) — an
// operator-supplied local file overrides any server-distributed
// profile. Errors are propagated so the caller can decide whether to
// fail the boot.
func loadProfileOnStartup(ctx context.Context, cfg config.Config, h *profile.Holder, ps profile.PolicyStore, engine *policy.Engine, pipeline *dlp.Pipeline) error {
	var p *profile.Profile
	var err error
	switch {
	case cfg.ProfilePath != "":
		p, err = profile.LoadFromFile(cfg.ProfilePath)
	case cfg.ProfileURL != "":
		p, err = profile.LoadFromURL(ctx, nil, cfg.ProfileURL)
	default:
		return nil
	}
	if err != nil {
		return err
	}
	if err := p.Apply(ctx, profileApplyOptions(ps, engine, pipeline)); err != nil {
		return err
	}
	return h.Set(p)
}

// profileApplyOptions builds the ApplyOptions used to apply an
// enterprise profile, including the DLPSink that pushes merged
// thresholds/weights into the live pipeline so a profile takes effect
// without a restart. Shared by startup and the auto-refresher.
func profileApplyOptions(ps profile.PolicyStore, engine *policy.Engine, pipeline *dlp.Pipeline) profile.ApplyOptions {
	opts := profile.ApplyOptions{PolicyStore: ps, Reloader: engine}
	if pipeline != nil {
		opts.DLPSink = func(c profile.DLPConfigSnapshot) {
			pipeline.Threshold().Set(dlp.Thresholds{
				Critical: c.ThresholdCritical,
				High:     c.ThresholdHigh,
				Medium:   c.ThresholdMedium,
				Low:      c.ThresholdLow,
			})
			pipeline.SetWeights(dlp.ScoreWeights{
				HotwordBoost:     c.HotwordBoost,
				EntropyBoost:     c.EntropyBoost,
				EntropyPenalty:   c.EntropyPenalty,
				ExclusionPenalty: c.ExclusionPenalty,
				MultiMatchBoost:  c.MultiMatchBoost,
			})
		}
	}
	return opts
}

// splitHostPort returns the host portion of an addr like "127.0.0.1:53".
// Falls back to addr unchanged when no port is present.
func splitHostPort(addr string) (string, string) {
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return addr, ""
	}
	return addr[:idx], addr[idx+1:]
}

// ruleFilesForStatus returns the rule file paths that should be
// reported through GET /api/status's rules[] section. Best-effort:
// the API server silently skips missing entries.
func ruleFilesForStatus(cfg config.Config) []string {
	paths := append([]string{}, cfg.RulePaths...)
	if cfg.DLPPatternsPath != "" {
		paths = append(paths, cfg.DLPPatternsPath)
	}
	if cfg.DLPExclusionsPath != "" {
		paths = append(paths, cfg.DLPExclusionsPath)
	}
	return paths
}

// agentUpdaterAdapter bridges *updater.Self to api.AgentSelfUpdater so
// the API handlers can return their own wire types without importing
// the updater package (which would create a cycle if updater ever
// needed to import api).
type agentUpdaterAdapter struct{ self *updater.Self }

func (a agentUpdaterAdapter) CheckLatest(ctx context.Context) (api.AgentUpdateCheck, error) {
	r, err := a.self.CheckLatest(ctx)
	if err != nil {
		return api.AgentUpdateCheck{}, err
	}
	return api.AgentUpdateCheck{
		Latest:          r.Latest,
		Current:         r.Current,
		UpdateAvailable: r.UpdateAvailable,
		DownloadURL:     r.DownloadURL,
	}, nil
}

func (a agentUpdaterAdapter) DownloadAndStage(ctx context.Context) (api.AgentUpdateStage, error) {
	r, err := a.self.DownloadAndStage(ctx)
	if err != nil {
		return api.AgentUpdateStage{}, err
	}
	return api.AgentUpdateStage{
		Version:   r.Version,
		StagedAt:  r.StagedAt,
		BytesSize: r.BytesSize,
	}, nil
}
