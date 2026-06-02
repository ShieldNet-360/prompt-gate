package stats

import (
	"context"
	"sync/atomic"
	"testing"
)

type benchStore struct {
	persisted Snapshot
	mu        atomic.Int64
}

func (s *benchStore) GetStats(_ context.Context) (Snapshot, error) {
	return s.persisted, nil
}
func (s *benchStore) AddStats(_ context.Context, d Snapshot) error {
	s.persisted.DNSQueriesTotal += d.DNSQueriesTotal
	s.persisted.DNSBlocksTotal += d.DNSBlocksTotal
	s.persisted.DLPScansTotal += d.DLPScansTotal
	s.persisted.DLPBlocksTotal += d.DLPBlocksTotal
	s.persisted.TamperDetectionsTotal += d.TamperDetectionsTotal
	s.mu.Add(1)
	return nil
}
func (s *benchStore) ResetStats(_ context.Context) error {
	s.persisted = Snapshot{}
	return nil
}

func BenchmarkIncrementDNSQueries(b *testing.B) {
	c := New(&benchStore{})
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.IncrementDNSQueries()
	}
}

func BenchmarkIncrementDNSQueriesParallel(b *testing.B) {
	c := New(&benchStore{})
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			c.IncrementDNSQueries()
		}
	})
}

func BenchmarkFlush(b *testing.B) {
	c := New(&benchStore{})
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Seed the counters so Flush actually writes through.
		for j := 0; j < 100; j++ {
			c.IncrementDNSQueries()
			c.IncrementDLPScans()
		}
		_ = c.Flush(ctx)
	}
}
