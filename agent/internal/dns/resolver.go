// Package dns implements the embedded DNS resolver. It listens on the
// configured loopback address, consults the policy engine for each
// incoming query, and either returns NXDOMAIN (deny) or forwards the
// query to the configured upstream resolver (allow / allow_with_dlp).
//
// Domain names and IP addresses are never logged. Only operational
// errors are written to stderr.
package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	mdns "github.com/miekg/dns"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/logging"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/policy"
)

// PolicyChecker is the subset of policy.Engine that the resolver needs.
type PolicyChecker interface {
	CheckDomain(domain string) policy.Action
}

// StatsCounter is the subset of stats.Counter that the resolver needs.
type StatsCounter interface {
	IncrementDNSQueries()
	IncrementDNSBlocks()
}

// Forwarder forwards a DNS query to an upstream resolver. The default
// implementation uses the miekg/dns client; tests inject fakes.
type Forwarder interface {
	Forward(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error)
}

// MiekgForwarder is the production Forwarder implementation backed by
// github.com/miekg/dns.
type MiekgForwarder struct {
	Upstream string
	Timeout  time.Duration
}

// Forward sends the request to the upstream resolver.
func (m *MiekgForwarder) Forward(ctx context.Context, req *mdns.Msg) (*mdns.Msg, error) {
	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := &mdns.Client{Net: "udp", Timeout: timeout}
	// Honour any earlier ctx deadline.
	if deadline, ok := ctx.Deadline(); ok {
		if d := time.Until(deadline); d > 0 && d < timeout {
			client.Timeout = d
		}
	}
	resp, _, err := client.Exchange(req, m.Upstream)
	return resp, err
}

// Resolver is the embedded DNS server.
type Resolver struct {
	listen    string
	policy    PolicyChecker
	stats     StatsCounter
	forwarder Forwarder

	mu      sync.Mutex
	servers []*mdns.Server
}

// New constructs a Resolver.
func New(listen string, p PolicyChecker, s StatsCounter, f Forwarder) *Resolver {
	return &Resolver{listen: listen, policy: p, stats: s, forwarder: f}
}

// Start spins up the UDP and TCP listeners. It returns once both
// listeners are bound and serving. Use Shutdown to stop them.
func (r *Resolver) Start() error {
	udp := &mdns.Server{
		Addr:    r.listen,
		Net:     "udp",
		Handler: mdns.HandlerFunc(r.handle),
	}
	tcp := &mdns.Server{
		Addr:    r.listen,
		Net:     "tcp",
		Handler: mdns.HandlerFunc(r.handle),
	}

	udpReady := make(chan error, 1)
	udp.NotifyStartedFunc = func() { udpReady <- nil }
	tcpReady := make(chan error, 1)
	tcp.NotifyStartedFunc = func() { tcpReady <- nil }

	r.mu.Lock()
	r.servers = []*mdns.Server{udp, tcp}
	r.mu.Unlock()

	go func() {
		if err := udp.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(stderr, "dns: udp listener error: %v\n", err)
		}
	}()
	go func() {
		if err := tcp.ListenAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
			fmt.Fprintf(stderr, "dns: tcp listener error: %v\n", err)
		}
	}()

	select {
	case <-udpReady:
	case <-time.After(5 * time.Second):
		return errors.New("dns: udp listener did not start in time")
	}
	select {
	case <-tcpReady:
	case <-time.After(5 * time.Second):
		return errors.New("dns: tcp listener did not start in time")
	}
	return nil
}

// Shutdown stops both listeners.
func (r *Resolver) Shutdown() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var firstErr error
	for _, s := range r.servers {
		if err := s.Shutdown(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	r.servers = nil
	return firstErr
}

// HandleQuery exposes the query handler for in-process testing.
func (r *Resolver) HandleQuery(req *mdns.Msg) *mdns.Msg {
	return r.respond(req)
}

func (r *Resolver) handle(w mdns.ResponseWriter, req *mdns.Msg) {
	// miekg/dns serves each query in its own goroutine and does NOT
	// recover panics — an unhandled panic here (malformed message,
	// upstream edge case) would crash the whole agent and take DNS +
	// proxy down with it. Contain it to the single query.
	defer logging.Recover("dns.handle")
	resp := r.respond(req)
	if resp == nil {
		return
	}
	if err := w.WriteMsg(resp); err != nil {
		// We must not log the question, just the operational error.
		fmt.Fprintf(stderr, "dns: write response: %v\n", err)
	}
}

func (r *Resolver) respond(req *mdns.Msg) *mdns.Msg {
	r.stats.IncrementDNSQueries()

	// A nil request can reach respond() via HandleQuery; mdns.Msg.SetRcode
	// dereferences its first argument, so we cannot pass nil to it.
	if req == nil {
		return nil
	}
	if len(req.Question) == 0 {
		m := new(mdns.Msg)
		m.SetRcode(req, mdns.RcodeFormatError)
		return m
	}

	q := req.Question[0]
	domain := strings.TrimSuffix(q.Name, ".")
	action := r.policy.CheckDomain(domain)

	if action == policy.Deny {
		r.stats.IncrementDNSBlocks()
		m := new(mdns.Msg)
		m.SetRcode(req, mdns.RcodeNameError) // NXDOMAIN
		m.Authoritative = true
		return m
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := r.forwarder.Forward(ctx, req)
	if err != nil || resp == nil {
		// Operational error — return SERVFAIL without exposing the
		// queried name.
		fmt.Fprintf(stderr, "dns: upstream error: %v\n", sanitiseErr(err))
		m := new(mdns.Msg)
		m.SetRcode(req, mdns.RcodeServerFailure)
		return m
	}
	return resp
}

// sanitiseErr strips any embedded hostnames from net errors so the
// upstream error message does not leak the queried domain.
func sanitiseErr(err error) error {
	if err == nil {
		return nil
	}
	// net.OpError exposes Net and Op which are safe (e.g. "udp", "read").
	// We deliberately drop the Addr / Source which may contain the
	// upstream IP. The stripped value is fine for operational debugging.
	var op *net.OpError
	if errors.As(err, &op) {
		return fmt.Errorf("%s %s: I/O failure", op.Op, op.Net)
	}
	return errors.New("upstream failure")
}
