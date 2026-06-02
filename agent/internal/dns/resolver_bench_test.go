package dns

import (
	"context"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/policy"
)

type benchStats struct{ q, b int64 }

func (s *benchStats) IncrementDNSQueries() { atomic.AddInt64(&s.q, 1) }
func (s *benchStats) IncrementDNSBlocks()  { atomic.AddInt64(&s.b, 1) }

type benchForwarder struct{}

func (benchForwarder) Forward(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	m := new(mdns.Msg)
	m.SetReply(req)
	return m, nil
}

func newBenchResolver(actions map[string]policy.Action) *Resolver {
	pol := &fakePolicy{actions: actions}
	return New(":0", pol, &benchStats{}, benchForwarder{})
}

func makeQuery(name string) *mdns.Msg {
	req := new(mdns.Msg)
	req.SetQuestion(mdns.Fqdn(name), mdns.TypeA)
	return req
}

func BenchmarkDNSLookupAllowed(b *testing.B) {
	r := newBenchResolver(map[string]policy.Action{})
	req := makeQuery("allowed.example.com.")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.HandleQuery(req)
	}
}

func BenchmarkDNSLookupBlocked(b *testing.B) {
	r := newBenchResolver(map[string]policy.Action{"blocked.example.com": policy.Deny})
	req := makeQuery("blocked.example.com.")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.HandleQuery(req)
	}
}
