// Package tamper monitors the OS for evidence that the local DNS
// resolver or the MITM proxy configuration has been pointed away from
// the Prompt Gate agent. The intent is to surface user-driven
// tampering (a curious user editing /etc/resolv.conf, flipping system
// proxy off) so the Electron tray can warn that the agent is no
// longer in the request path — not to forensically log the event.
//
// Privacy invariant: the detector touches OS configuration only. It
// never enumerates open connections, captured DNS queries, or any
// per-event data. The Status returned to /api/tamper/status is
// {dns_ok, proxy_ok, last_check, detections_total} — the boolean
// shape is intentional so admins cannot reconstruct user behaviour
// from the response.
package tamper

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultInterval is the cadence between DNS / proxy checks. 60s
// is rare enough not to add measurable overhead.
const DefaultInterval = 60 * time.Second

// Status is the data exposed to GET /api/tamper/status.
type Status struct {
	DNSOK           bool      `json:"dns_ok"`
	ProxyOK         bool      `json:"proxy_ok"`
	LastCheck       time.Time `json:"last_check"`
	DetectionsTotal int64     `json:"detections_total"`
}

// Reporter is the subset of the stats package the detector needs to
// bump the persistent tamper counter. Keeping it as an interface
// avoids a tamper→stats import cycle.
type Reporter interface {
	IncrementTamperDetections()
}

// DNSCheck reports whether the OS DNS is still pointed at the Secure
// Edge agent. Implementations are platform-specific; tests inject
// their own. The expected value (returned in expectedServer) is the
// host portion of cfg.DNSListen ("127.0.0.1" by default).
type DNSCheck func(ctx context.Context, expectedServer string) (ok bool, err error)

// ProxyCheck reports whether the OS system proxy is still pointed at
// the local MITM proxy (when the proxy is enabled).
type ProxyCheck func(ctx context.Context, expectedAddr string) (ok bool, err error)

// Options configures a new Detector.
type Options struct {
	// ExpectedDNSServer is the host portion of cfg.DNSListen — the
	// IP the OS should be using as its primary resolver. Defaults
	// to "127.0.0.1".
	ExpectedDNSServer string

	// ExpectedProxyAddr is the full host:port the OS should be
	// using as its HTTP/HTTPS proxy. When empty the proxy check is
	// skipped (Phase 1-3 deployments without the MITM proxy).
	ExpectedProxyAddr string

	// Interval defaults to DefaultInterval when zero.
	Interval time.Duration

	// DNSCheck / ProxyCheck — leave nil to use the platform default.
	DNSCheck   DNSCheck
	ProxyCheck ProxyCheck

	// Reporter is bumped once per detection event. May be nil to
	// disable counter persistence (useful for tests).
	Reporter Reporter

	// OnTamper is an optional callback invoked once per detection.
	// The Electron tray uses this to fire a notification. The
	// callback runs on the detector goroutine and must not block.
	OnTamper func(reason string)

	// Now is injected for tests. Defaults to time.Now.
	Now func() time.Time
}

// Detector encapsulates the periodic tamper check. Status is safe for
// concurrent reads.
type Detector struct {
	opts Options

	mu   sync.RWMutex
	last Status

	detections atomic.Int64
}

// New constructs a Detector and applies defaults to opts.
func New(opts Options) *Detector {
	if opts.Interval == 0 {
		opts.Interval = DefaultInterval
	}
	if opts.ExpectedDNSServer == "" {
		opts.ExpectedDNSServer = "127.0.0.1"
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.DNSCheck == nil {
		opts.DNSCheck = platformDNSCheck
	}
	if opts.ProxyCheck == nil {
		opts.ProxyCheck = platformProxyCheck
	}
	return &Detector{opts: opts, last: Status{DNSOK: true, ProxyOK: true}}
}

// Status returns the most recent check snapshot. Safe for concurrent
// use; satisfies api.TamperReporter once wrapped in an adapter.
func (d *Detector) Status() Status {
	d.mu.RLock()
	defer d.mu.RUnlock()
	cp := d.last
	cp.DetectionsTotal = d.detections.Load()
	return cp
}

// CheckNow runs one tamper check immediately. Exported so callers
// (and tests) can drive the cycle without waiting on the timer.
func (d *Detector) CheckNow(ctx context.Context) Status {
	now := d.opts.Now()

	dnsOK := true
	if d.opts.DNSCheck != nil {
		ok, err := d.opts.DNSCheck(ctx, d.opts.ExpectedDNSServer)
		// Errors are treated as "unknown but assume OK" so a
		// transient OS hiccup does not flap the detector.
		if err == nil {
			dnsOK = ok
		}
	}

	proxyOK := true
	if d.opts.ExpectedProxyAddr != "" && d.opts.ProxyCheck != nil {
		ok, err := d.opts.ProxyCheck(ctx, d.opts.ExpectedProxyAddr)
		if err == nil {
			proxyOK = ok
		}
	}

	prev := d.Status()
	tampered := (!dnsOK && prev.DNSOK) || (!proxyOK && prev.ProxyOK)

	d.mu.Lock()
	d.last = Status{
		DNSOK:     dnsOK,
		ProxyOK:   proxyOK,
		LastCheck: now,
	}
	d.mu.Unlock()

	if tampered {
		d.detections.Add(1)
		if d.opts.Reporter != nil {
			d.opts.Reporter.IncrementTamperDetections()
		}
		if d.opts.OnTamper != nil {
			reason := "dns"
			if !proxyOK {
				reason = "proxy"
			}
			d.opts.OnTamper(reason)
		}
	}
	return d.Status()
}

// Start runs CheckNow on the current goroutine immediately, then
// again every Interval until ctx is cancelled.
func (d *Detector) Start(ctx context.Context) {
	_ = d.CheckNow(ctx)
	ticker := time.NewTicker(d.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = d.CheckNow(ctx)
		}
	}
}
