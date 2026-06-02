package dns

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	mdns "github.com/miekg/dns"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/policy"
)

type fakePolicy struct {
	actions map[string]policy.Action
}

func (f *fakePolicy) CheckDomain(domain string) policy.Action {
	if a, ok := f.actions[domain]; ok {
		return a
	}
	return policy.Allow
}

type fakeStats struct {
	queries int64
	blocks  int64
}

func (f *fakeStats) IncrementDNSQueries() { atomic.AddInt64(&f.queries, 1) }
func (f *fakeStats) IncrementDNSBlocks()  { atomic.AddInt64(&f.blocks, 1) }

type fakeForwarder struct {
	called int64
	resp   *mdns.Msg
	err    error
}

func (f *fakeForwarder) Forward(_ context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	atomic.AddInt64(&f.called, 1)
	if f.err != nil {
		return nil, f.err
	}
	if f.resp != nil {
		f.resp.SetReply(req)
		return f.resp, nil
	}
	m := new(mdns.Msg)
	m.SetReply(req)
	m.Answer = append(m.Answer, mustRR(req.Question[0].Name+" 30 IN A 1.2.3.4"))
	return m, nil
}

func mustRR(s string) mdns.RR {
	rr, err := mdns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

func buildQuery(domain string) *mdns.Msg {
	m := new(mdns.Msg)
	m.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
	return m
}

func TestResolverDenyReturnsNXDomainAndIncrementsBlocks(t *testing.T) {
	pol := &fakePolicy{actions: map[string]policy.Action{"blocked.example.com": policy.Deny}}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New("127.0.0.1:0", pol, st, fwd)

	resp := r.HandleQuery(buildQuery("blocked.example.com"))
	if resp.Rcode != mdns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN (%d)", resp.Rcode, mdns.RcodeNameError)
	}
	if atomic.LoadInt64(&fwd.called) != 0 {
		t.Fatalf("forwarder unexpectedly called for blocked domain")
	}
	if atomic.LoadInt64(&st.queries) != 1 {
		t.Fatalf("queries = %d", st.queries)
	}
	if atomic.LoadInt64(&st.blocks) != 1 {
		t.Fatalf("blocks = %d", st.blocks)
	}
}

func TestResolverAllowForwardsAndDoesNotBlock(t *testing.T) {
	pol := &fakePolicy{actions: map[string]policy.Action{"allowed.example.com": policy.Allow}}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New("127.0.0.1:0", pol, st, fwd)

	resp := r.HandleQuery(buildQuery("allowed.example.com"))
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %d, want SUCCESS", resp.Rcode)
	}
	if atomic.LoadInt64(&fwd.called) != 1 {
		t.Fatalf("forwarder calls = %d", fwd.called)
	}
	if atomic.LoadInt64(&st.queries) != 1 || atomic.LoadInt64(&st.blocks) != 0 {
		t.Fatalf("counters = %+v", st)
	}
	if len(resp.Answer) == 0 {
		t.Fatalf("expected answer records")
	}
}

func TestResolverAllowWithDLPForwards(t *testing.T) {
	pol := &fakePolicy{actions: map[string]policy.Action{"dlp.example.com": policy.AllowWithDLP}}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New("127.0.0.1:0", pol, st, fwd)

	resp := r.HandleQuery(buildQuery("dlp.example.com"))
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
	if fwd.called != 1 {
		t.Fatalf("forwarder calls = %d", fwd.called)
	}
}

func TestResolverUpstreamErrorReturnsServfail(t *testing.T) {
	pol := &fakePolicy{actions: map[string]policy.Action{"err.example.com": policy.Allow}}
	st := &fakeStats{}
	fwd := &fakeForwarder{err: errors.New("boom")}
	r := New("127.0.0.1:0", pol, st, fwd)

	resp := r.HandleQuery(buildQuery("err.example.com"))
	if resp.Rcode != mdns.RcodeServerFailure {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
}

func TestResolverUnknownDomainAllowed(t *testing.T) {
	pol := &fakePolicy{}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New("127.0.0.1:0", pol, st, fwd)

	resp := r.HandleQuery(buildQuery("random.example.org"))
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %d", resp.Rcode)
	}
	if fwd.called != 1 {
		t.Fatalf("forwarder calls = %d", fwd.called)
	}
}

func TestResolverNilRequestReturnsNilWithoutPanic(t *testing.T) {
	pol := &fakePolicy{}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New("127.0.0.1:0", pol, st, fwd)

	resp := r.HandleQuery(nil)
	if resp != nil {
		t.Fatalf("expected nil response for nil request, got %+v", resp)
	}
	if atomic.LoadInt64(&st.queries) != 1 {
		t.Fatalf("queries counter not incremented: %d", st.queries)
	}
	if atomic.LoadInt64(&fwd.called) != 0 {
		t.Fatalf("forwarder unexpectedly called for nil request")
	}
}

func TestResolverEmptyQuestionReturnsFormatError(t *testing.T) {
	pol := &fakePolicy{}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New("127.0.0.1:0", pol, st, fwd)

	req := new(mdns.Msg)
	resp := r.HandleQuery(req)
	if resp == nil {
		t.Fatal("expected non-nil response for empty-question request")
	}
	if resp.Rcode != mdns.RcodeFormatError {
		t.Fatalf("rcode = %d, want FORMERR", resp.Rcode)
	}
	if atomic.LoadInt64(&fwd.called) != 0 {
		t.Fatalf("forwarder unexpectedly called for empty question")
	}
}
