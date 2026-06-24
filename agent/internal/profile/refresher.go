package profile

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// Refresher periodically re-fetches the enterprise profile from a URL
// and re-applies it in-memory when it changes — enabling MDM-style
// central fleet management without an agent restart. It uses HTTP
// conditional requests (ETag / Last-Modified), so steady state (the
// remote unchanged) is a zero-work 304 no-op. A fetch failure keeps the
// last applied profile; the agent never reverts to an empty policy.
type Refresher struct {
	holder   *Holder
	url      string
	interval time.Duration
	client   *http.Client
	apply    func(ctx context.Context, p *Profile) error
	now      func() time.Time

	mu           sync.Mutex
	etag         string
	lastModified string
	lastCheckAt  int64
	lastChangeAt int64
	checksTotal  int64
	changesTotal int64
}

// RefresherStatus is the aggregate, non-sensitive status surfaced to the
// API. It never includes the profile URL or any profile content.
type RefresherStatus struct {
	Enabled         bool  `json:"auto_refresh_enabled"`
	IntervalSeconds int   `json:"interval_seconds"`
	LastCheckAt     int64 `json:"last_check_at"`
	LastChangeAt    int64 `json:"last_change_at"`
	ChecksTotal     int64 `json:"checks_total"`
	ChangesTotal    int64 `json:"changes_total"`
}

// NewRefresher builds a Refresher. apply is invoked with each newly
// fetched profile (it should apply policy + DLP config and update the
// Holder); a nil url or non-positive interval is allowed but Start is a
// no-op then.
func NewRefresher(h *Holder, url string, interval time.Duration, apply func(context.Context, *Profile) error) *Refresher {
	return &Refresher{holder: h, url: url, interval: interval, apply: apply, now: time.Now}
}

// Enabled reports whether the refresher will poll.
func (r *Refresher) Enabled() bool {
	return r != nil && r.url != "" && r.interval > 0 && r.apply != nil
}

// Status returns the current aggregate status.
func (r *Refresher) Status() RefresherStatus {
	if r == nil {
		return RefresherStatus{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return RefresherStatus{
		Enabled:         r.url != "" && r.interval > 0,
		IntervalSeconds: int(r.interval / time.Second),
		LastCheckAt:     r.lastCheckAt,
		LastChangeAt:    r.lastChangeAt,
		ChecksTotal:     r.checksTotal,
		ChangesTotal:    r.changesTotal,
	}
}

// checkOnce performs a single conditional fetch and applies the profile
// if it changed. Returns whether a change was applied.
func (r *Refresher) checkOnce(ctx context.Context) (bool, error) {
	r.mu.Lock()
	etag, lastMod := r.etag, r.lastModified
	r.mu.Unlock()

	res, err := LoadFromURLConditional(ctx, r.client, r.url, etag, lastMod)

	r.mu.Lock()
	r.checksTotal++
	r.lastCheckAt = r.now().Unix()
	r.mu.Unlock()
	if err != nil {
		return false, err
	}

	// Always remember the latest validators so the next poll can 304.
	r.mu.Lock()
	r.etag, r.lastModified = res.ETag, res.LastModified
	r.mu.Unlock()

	if !res.Changed {
		return false, nil
	}
	if err := r.apply(ctx, res.Profile); err != nil {
		return false, err
	}
	r.mu.Lock()
	r.changesTotal++
	r.lastChangeAt = r.now().Unix()
	r.mu.Unlock()
	return true, nil
}

// Start polls every interval until ctx is cancelled. Errors are routed
// through logFn (nil = discarded); a failed fetch leaves the active
// profile in place.
func (r *Refresher) Start(ctx context.Context, logFn func(format string, args ...interface{})) {
	if !r.Enabled() {
		return
	}
	if logFn == nil {
		logFn = func(string, ...interface{}) {}
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if changed, err := r.checkOnce(ctx); err != nil {
				logFn("profile: auto-refresh check failed: %v\n", err)
			} else if changed {
				logFn("profile: auto-refresh applied a new profile\n")
			}
		}
	}
}
