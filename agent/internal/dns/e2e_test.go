package dns

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/policy"
)

// TestResolver_EndToEnd_BlockedReturnsNXDOMAIN starts the resolver
// bound to a real ephemeral UDP port, sends a query via a stock
// miekg/dns client, and verifies the resolver returns NXDOMAIN for a
// blocked domain. The upstream forwarder is a fake — we want to
// observe two things end-to-end:
//
//   - the resolver answers on the wire (not just in HandleQuery), and
//   - the block path increments the stats counter exposed to
//     /api/stats consumers.
//
// End-to-end tests for the DNS resolver.
func TestResolver_EndToEnd_BlockedReturnsNXDOMAIN(t *testing.T) {
	addr, r, _, st := startE2EResolver(t, map[string]policy.Action{
		"blocked.example.com": policy.Deny,
	})
	defer func() { _ = r.Shutdown() }()

	resp, err := dialDNS(t, addr, "blocked.example.com")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if resp.Rcode != mdns.RcodeNameError {
		t.Fatalf("rcode = %d, want NXDOMAIN (%d)", resp.Rcode, mdns.RcodeNameError)
	}
	if got := atomic.LoadInt64(&st.queries); got < 1 {
		t.Errorf("queries counter = %d, want >= 1", got)
	}
	if got := atomic.LoadInt64(&st.blocks); got < 1 {
		t.Errorf("blocks counter = %d, want >= 1", got)
	}
}

// TestResolver_EndToEnd_AllowedForwarded verifies the resolver
// proxies allowed queries through the upstream forwarder.
func TestResolver_EndToEnd_AllowedForwarded(t *testing.T) {
	addr, r, fwd, _ := startE2EResolver(t, nil)
	defer func() { _ = r.Shutdown() }()

	resp, err := dialDNS(t, addr, "allowed.example.com")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if resp.Rcode != mdns.RcodeSuccess {
		t.Fatalf("rcode = %d, want NOERROR", resp.Rcode)
	}
	if got := atomic.LoadInt64(&fwd.called); got != 1 {
		t.Fatalf("forwarder called %d times, want 1", got)
	}
}

func startE2EResolver(t *testing.T, deny map[string]policy.Action) (string, *Resolver, *fakeForwarder, *fakeStats) {
	t.Helper()
	// Reserve an ephemeral UDP port without holding it. We can't ask
	// the resolver itself to bind to :0 because Start() doesn't
	// surface the resolved port back.
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := c.LocalAddr().String()
	_ = c.Close()
	_, portStr, _ := net.SplitHostPort(addr)
	if _, err := strconv.Atoi(portStr); err != nil {
		t.Fatalf("port parse: %v", err)
	}

	pol := &fakePolicy{actions: deny}
	st := &fakeStats{}
	fwd := &fakeForwarder{}
	r := New(addr, pol, st, fwd)
	if err := r.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	return addr, r, fwd, st
}

func dialDNS(t *testing.T, addr, domain string) (*mdns.Msg, error) {
	t.Helper()
	q := new(mdns.Msg)
	q.SetQuestion(mdns.Fqdn(domain), mdns.TypeA)
	c := &mdns.Client{Net: "udp", Timeout: 2 * time.Second}
	resp, _, err := c.ExchangeContext(context.Background(), q, addr)
	return resp, err
}
