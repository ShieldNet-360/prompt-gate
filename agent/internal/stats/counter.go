// Package stats maintains the anonymous aggregate counters for the agent.
// Increments happen in-memory using atomics; counters are flushed
// periodically to SQLite as deltas, then the in-memory counters are reset
// to zero. There is no per-event timestamp, domain, or other identifier
// stored anywhere — only running totals.
package stats

import (
	"context"
	"sync/atomic"
	"time"
)

// Snapshot is the consolidated view of the counters (in-memory plus the
// last persisted total). It mirrors store.AggregateStats but is local to
// this package to avoid a dependency cycle.
type Snapshot struct {
	DNSQueriesTotal       int64 `json:"dns_queries_total"`
	DNSBlocksTotal        int64 `json:"dns_blocks_total"`
	DLPScansTotal         int64 `json:"dlp_scans_total"`
	DLPBlocksTotal        int64 `json:"dlp_blocks_total"`
	TamperDetectionsTotal int64 `json:"tamper_detections_total"`
}

// Store is the subset of the persistence layer that Counter needs. Defined
// as an interface so that tests can swap in fakes without pulling in the
// SQLite driver.
type Store interface {
	GetStats(ctx context.Context) (storeStats, error)
	AddStats(ctx context.Context, delta storeStats) error
	ResetStats(ctx context.Context) error
}

// storeStats mirrors store.AggregateStats. We declare a local type alias
// to keep the interface independent of the store package; the agent wires
// the two together with a thin adapter.
type storeStats = Snapshot

// Counter is the in-memory counter set.
type Counter struct {
	dnsQueries int64
	dnsBlocks  int64
	dlpScans   int64
	dlpBlocks  int64
	tamperHits int64

	store Store
}

// New returns a Counter that flushes deltas to the given store.
func New(s Store) *Counter { return &Counter{store: s} }

// IncrementDNSQueries adds one to the DNS queries counter.
func (c *Counter) IncrementDNSQueries() { atomic.AddInt64(&c.dnsQueries, 1) }

// IncrementDNSBlocks adds one to the DNS blocks counter.
func (c *Counter) IncrementDNSBlocks() { atomic.AddInt64(&c.dnsBlocks, 1) }

// IncrementDLPScans adds one to the DLP scans counter.
func (c *Counter) IncrementDLPScans() { atomic.AddInt64(&c.dlpScans, 1) }

// IncrementDLPBlocks adds one to the DLP blocks counter.
func (c *Counter) IncrementDLPBlocks() { atomic.AddInt64(&c.dlpBlocks, 1) }

// IncrementTamperDetections adds one to the tamper detections counter.
func (c *Counter) IncrementTamperDetections() { atomic.AddInt64(&c.tamperHits, 1) }

// MemorySnapshot returns the in-memory delta values (not yet flushed).
func (c *Counter) MemorySnapshot() Snapshot {
	return Snapshot{
		DNSQueriesTotal:       atomic.LoadInt64(&c.dnsQueries),
		DNSBlocksTotal:        atomic.LoadInt64(&c.dnsBlocks),
		DLPScansTotal:         atomic.LoadInt64(&c.dlpScans),
		DLPBlocksTotal:        atomic.LoadInt64(&c.dlpBlocks),
		TamperDetectionsTotal: atomic.LoadInt64(&c.tamperHits),
	}
}

// GetStats returns the union of the persisted totals plus the in-memory
// deltas. This is the value the API returns to callers.
func (c *Counter) GetStats(ctx context.Context) (Snapshot, error) {
	persisted, err := c.store.GetStats(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	mem := c.MemorySnapshot()
	return Snapshot{
		DNSQueriesTotal:       persisted.DNSQueriesTotal + mem.DNSQueriesTotal,
		DNSBlocksTotal:        persisted.DNSBlocksTotal + mem.DNSBlocksTotal,
		DLPScansTotal:         persisted.DLPScansTotal + mem.DLPScansTotal,
		DLPBlocksTotal:        persisted.DLPBlocksTotal + mem.DLPBlocksTotal,
		TamperDetectionsTotal: persisted.TamperDetectionsTotal + mem.TamperDetectionsTotal,
	}, nil
}

// Flush atomically extracts the in-memory deltas, adds them to the
// persisted totals, and zeroes the in-memory counters.
func (c *Counter) Flush(ctx context.Context) error {
	delta := Snapshot{
		DNSQueriesTotal:       atomic.SwapInt64(&c.dnsQueries, 0),
		DNSBlocksTotal:        atomic.SwapInt64(&c.dnsBlocks, 0),
		DLPScansTotal:         atomic.SwapInt64(&c.dlpScans, 0),
		DLPBlocksTotal:        atomic.SwapInt64(&c.dlpBlocks, 0),
		TamperDetectionsTotal: atomic.SwapInt64(&c.tamperHits, 0),
	}
	if delta == (Snapshot{}) {
		return nil
	}
	if err := c.store.AddStats(ctx, delta); err != nil {
		// Best-effort restore so we do not lose increments on transient
		// persistence errors.
		atomic.AddInt64(&c.dnsQueries, delta.DNSQueriesTotal)
		atomic.AddInt64(&c.dnsBlocks, delta.DNSBlocksTotal)
		atomic.AddInt64(&c.dlpScans, delta.DLPScansTotal)
		atomic.AddInt64(&c.dlpBlocks, delta.DLPBlocksTotal)
		atomic.AddInt64(&c.tamperHits, delta.TamperDetectionsTotal)
		return err
	}
	return nil
}

// Reset zeroes both the in-memory and the persisted counters.
func (c *Counter) Reset(ctx context.Context) error {
	atomic.StoreInt64(&c.dnsQueries, 0)
	atomic.StoreInt64(&c.dnsBlocks, 0)
	atomic.StoreInt64(&c.dlpScans, 0)
	atomic.StoreInt64(&c.dlpBlocks, 0)
	atomic.StoreInt64(&c.tamperHits, 0)
	return c.store.ResetStats(ctx)
}

// Run flushes the counters every interval until ctx is done. It calls
// Flush once more on shutdown so transient increments are not lost.
func (c *Counter) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 60 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			// Use a fresh context so the final flush is not aborted.
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = c.Flush(flushCtx)
			cancel()
			return
		case <-ticker.C:
			_ = c.Flush(ctx)
		}
	}
}
