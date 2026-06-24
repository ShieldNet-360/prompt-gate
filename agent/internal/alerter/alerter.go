// Package alerter sends an optional, privacy-safe outbound webhook when
// the agent's DLP-block counter climbs past a configurable threshold
// within a polling window. It is the event-driven complement to the
// heartbeat package: heartbeat reports aggregate counters on a fixed
// schedule for dashboards; alerter pushes a notification the moment
// activity spikes, for Slack / PagerDuty / SIEM incident response.
//
// Privacy by construction — identical invariant to the heartbeat:
//   - No access data: no domain names, URLs, IPs, matched values, or
//     pattern names ever appear in the payload.
//   - Counters only: the payload carries the number of blocks in the
//     window plus build metadata (version, OS, arch) and a send time.
//
// Disabled by default; an empty URL skips the goroutine entirely.
// Failures are logged and swallowed — alerting must never interfere
// with the agent's primary work.
package alerter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
)

// DefaultInterval is the polling cadence when Options.Interval is zero.
const DefaultInterval = 5 * time.Minute

// DefaultThresholdBlocks is the per-window block count that triggers a
// webhook when Options.ThresholdBlocks is zero.
const DefaultThresholdBlocks = 10

// minThresholdBlocks guards against a misconfigured threshold spamming
// the endpoint on every tick.
const minThresholdBlocks = 5

// AlertType is the only event kind emitted today.
const AlertType = "dlp_block_threshold"

// Payload is the webhook body. The JSON shape is the public contract —
// counters and build metadata only, never access data.
type Payload struct {
	AlertType      string `json:"alert_type"`
	AgentVersion   string `json:"agent_version"`
	OSType         string `json:"os_type"`
	OSArch         string `json:"os_arch"`
	BlocksInWindow int64  `json:"blocks_in_window"`
	ExportedAt     int64  `json:"exported_at"`
}

// StatsView is the subset of stats.Counter the alerter reads.
type StatsView interface {
	GetStats(ctx context.Context) (stats.Snapshot, error)
}

// Status is the snapshot returned by GET /api/alerter/status — all
// aggregate, no access data.
type Status struct {
	Enabled         bool  `json:"enabled"`
	ThresholdBlocks int64 `json:"threshold_blocks"`
	LastFiredAt     int64 `json:"last_fired_at"` // unix seconds; 0 = never
	FiresTotal      int64 `json:"fires_total"`
}

// Options configures an Alerter.
type Options struct {
	URL             string
	AgentVersion    string
	ThresholdBlocks int64
	Interval        time.Duration
	Stats           StatsView
	HTTPClient      *http.Client
	Now             func() time.Time
}

// Alerter polls the block counter and POSTs a Payload when the delta
// since the last fire (or baseline) reaches the threshold.
type Alerter struct {
	opts Options

	baseline    int64 // block count at last fire / start (atomic)
	firesTotal  int64 // atomic
	lastFiredAt int64 // atomic, unix seconds
}

// checkURL is swappable so tests can target httptest loopback servers.
var checkURL = strictCheckURL

func strictCheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("alerter: invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("alerter: URL scheme %q must be https", u.Scheme)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return fmt.Errorf("alerter: URL host must not be a private/loopback address")
	}
	return nil
}

// New constructs an Alerter and validates Options. URL=="" returns nil
// so callers can skip Start() without a nil check.
func New(opts Options) (*Alerter, error) {
	if opts.URL == "" {
		return nil, nil
	}
	if err := checkURL(opts.URL); err != nil {
		return nil, err
	}
	if opts.Stats == nil {
		return nil, errors.New("alerter: Stats is required")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.ThresholdBlocks <= 0 {
		opts.ThresholdBlocks = DefaultThresholdBlocks
	}
	if opts.ThresholdBlocks < minThresholdBlocks {
		opts.ThresholdBlocks = minThresholdBlocks
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.AgentVersion == "" {
		opts.AgentVersion = "0.0.0"
	}
	return &Alerter{opts: opts}, nil
}

// Enabled reports whether the alerter will send anything.
func (a *Alerter) Enabled() bool { return a != nil && a.opts.URL != "" }

// Status returns the current aggregate status.
func (a *Alerter) Status() Status {
	if !a.Enabled() {
		return Status{}
	}
	return Status{
		Enabled:         true,
		ThresholdBlocks: a.opts.ThresholdBlocks,
		LastFiredAt:     atomic.LoadInt64(&a.lastFiredAt),
		FiresTotal:      atomic.LoadInt64(&a.firesTotal),
	}
}

// setBaseline initialises the block-count baseline (called once at
// Start so the first window measures from "now", not from total).
func (a *Alerter) setBaseline(ctx context.Context) error {
	snap, err := a.opts.Stats.GetStats(ctx)
	if err != nil {
		return err
	}
	atomic.StoreInt64(&a.baseline, snap.DLPBlocksTotal)
	return nil
}

// checkOnce reads the counter and fires if the delta since the baseline
// reached the threshold. Returns whether it fired. Exported semantics
// for deterministic tests via Check.
func (a *Alerter) checkOnce(ctx context.Context) (bool, error) {
	snap, err := a.opts.Stats.GetStats(ctx)
	if err != nil {
		return false, err
	}
	cur := snap.DLPBlocksTotal
	delta := cur - atomic.LoadInt64(&a.baseline)
	if delta < a.opts.ThresholdBlocks {
		return false, nil // keep accumulating toward the threshold
	}
	if err := a.fire(ctx, delta); err != nil {
		return false, err
	}
	atomic.StoreInt64(&a.baseline, cur)
	atomic.AddInt64(&a.firesTotal, 1)
	atomic.StoreInt64(&a.lastFiredAt, a.opts.Now().Unix())
	return true, nil
}

// Check runs a single threshold evaluation. Exposed for tests.
func (a *Alerter) Check(ctx context.Context) (bool, error) {
	if !a.Enabled() {
		return false, nil
	}
	return a.checkOnce(ctx)
}

func (a *Alerter) fire(ctx context.Context, blocks int64) error {
	p := Payload{
		AlertType:      AlertType,
		AgentVersion:   a.opts.AgentVersion,
		OSType:         runtime.GOOS,
		OSArch:         runtime.GOARCH,
		BlocksInWindow: blocks,
		ExportedAt:     a.opts.Now().Unix(),
	}
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("alerter: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.opts.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("alerter: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "prompt-gate-agent/"+p.AgentVersion)
	resp, err := a.opts.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("alerter: POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("alerter: POST status %d", resp.StatusCode)
	}
	return nil
}

// Start sets the baseline, then evaluates the threshold every Interval
// until ctx is cancelled. Errors are routed through logFn (nil =
// discarded) so this package never imports a logger.
func (a *Alerter) Start(ctx context.Context, logFn func(format string, args ...interface{})) {
	if !a.Enabled() {
		return
	}
	if logFn == nil {
		logFn = func(string, ...interface{}) {}
	}
	if err := a.setBaseline(ctx); err != nil {
		logFn("alerter: baseline read failed: %v\n", err)
	}
	ticker := time.NewTicker(a.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := a.checkOnce(ctx); err != nil {
				logFn("alerter: check failed: %v\n", err)
			}
		}
	}
}
