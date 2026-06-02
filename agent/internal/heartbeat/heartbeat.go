// Package heartbeat sends an optional periodic POST to a central
// telemetry endpoint configured by the deployment. The payload is
// strictly {agent_version, os_type, os_arch, aggregate_counters} —
// it is privacy-safe by construction:
//
//   - No access data: domain names, URLs, IPs, and DLP match
//     content never appear in the payload.
//   - No per-event timestamps: only running counters that are
//     already exposed via /api/stats.
//
// The heartbeat is disabled by default; an empty URL skips the
// goroutine entirely. Failures are logged to stderr and otherwise
// swallowed — telemetry must never interfere with the agent's
// primary responsibilities.
package heartbeat

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
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
)

// DefaultInterval is the cadence used when Options.Interval is zero.
const DefaultInterval = time.Hour

// Payload is the body sent on each beat. The JSON shape is the
// public contract — only counters and identifying build metadata.
type Payload struct {
	AgentVersion string         `json:"agent_version"`
	OSType       string         `json:"os_type"`
	OSArch       string         `json:"os_arch"`
	Counters     stats.Snapshot `json:"aggregate_counters"`
}

// StatsView is the subset of stats.Counter the heartbeat reads. Keep
// it tight so this package never reaches deeper into the stats /
// store layer than necessary.
type StatsView interface {
	GetStats(ctx context.Context) (stats.Snapshot, error)
}

// Options configures a Heartbeat.
type Options struct {
	URL          string
	AgentVersion string
	Interval     time.Duration
	Stats        StatsView
	HTTPClient   *http.Client
	Now          func() time.Time
}

// Heartbeat periodically POSTs a Payload to Options.URL.
type Heartbeat struct {
	opts Options
}

// checkURL validates the heartbeat URL. Exposed as a package-level
// var so tests that need to run against httptest loopback servers
// can swap it out (see relaxURLCheckForTest in heartbeat_test.go).
// The default — strictCheckURL — enforces the SE-04 invariants and
// is what production callers see.
var checkURL = strictCheckURL

func strictCheckURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("heartbeat: invalid URL: %w", err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("heartbeat: URL scheme %q must be https", u.Scheme)
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return fmt.Errorf("heartbeat: URL host must not be a private/loopback address")
	}
	return nil
}

// New constructs a Heartbeat and validates Options. URL=="" returns
// nil — callers can safely skip Start() without nil-checking the
// returned pointer.
func New(opts Options) (*Heartbeat, error) {
	if opts.URL == "" {
		return nil, nil
	}
	if err := checkURL(opts.URL); err != nil {
		return nil, err
	}
	if opts.Stats == nil {
		return nil, errors.New("heartbeat: Stats is required")
	}
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.AgentVersion == "" {
		opts.AgentVersion = "0.0.0"
	}
	return &Heartbeat{opts: opts}, nil
}

// Enabled reports whether the heartbeat will send anything.
func (h *Heartbeat) Enabled() bool {
	return h != nil && h.opts.URL != ""
}

// BuildPayload assembles a Payload from the current stats snapshot.
// Exported for tests so they can assert the shape without spinning
// up the full Start() goroutine.
func (h *Heartbeat) BuildPayload(ctx context.Context) (Payload, error) {
	snap, err := h.opts.Stats.GetStats(ctx)
	if err != nil {
		return Payload{}, err
	}
	return Payload{
		AgentVersion: h.opts.AgentVersion,
		OSType:       runtime.GOOS,
		OSArch:       runtime.GOARCH,
		Counters:     snap,
	}, nil
}

// SendOnce builds and sends a single heartbeat. Exported so tests
// can drive the cycle deterministically without involving the ticker.
func (h *Heartbeat) SendOnce(ctx context.Context) error {
	if !h.Enabled() {
		return nil
	}
	p, err := h.BuildPayload(ctx)
	if err != nil {
		return fmt.Errorf("heartbeat: build payload: %w", err)
	}
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("heartbeat: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.opts.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("heartbeat: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "prompt-gate-agent/"+p.AgentVersion)

	resp, err := h.opts.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat: POST: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("heartbeat: POST status %d", resp.StatusCode)
	}
	return nil
}

// Start runs SendOnce on the current goroutine, then ticks every
// Interval until ctx is cancelled. Errors are logged via the
// supplied logFn (nil — discarded) so callers can route them to
// their preferred stderr sink without this package importing the
// log package directly.
func (h *Heartbeat) Start(ctx context.Context, logFn func(format string, args ...interface{})) {
	if !h.Enabled() {
		return
	}
	if logFn == nil {
		logFn = func(string, ...interface{}) {}
	}
	if err := h.SendOnce(ctx); err != nil {
		logFn("heartbeat: initial send failed: %v\n", err)
	}
	ticker := time.NewTicker(h.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := h.SendOnce(ctx); err != nil {
				logFn("heartbeat: send failed: %v\n", err)
			}
		}
	}
}
