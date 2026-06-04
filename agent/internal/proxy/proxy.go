// Local MITM proxy with selective TLS decryption.
//
// The proxy listens on a loopback address and is reached because the
// system proxy settings (or a process-level env var) point HTTPS at
// it. Behaviour per CONNECT target:
//
//   - Tier 2 hosts                  decrypt TLS, inspect request body
//     with the same DLP pipeline the
//     extension uses, return HTTP 451
//     {"blocked":true,"pattern_name":...}
//     if the pipeline blocks, otherwise
//     forward upstream untouched.
//   - All other hosts               pass-through CONNECT tunnel; bytes
//     are forwarded verbatim and TLS is
//     never terminated locally.
//
// Privacy invariant: this package must never log request bodies,
// URLs, hostnames, IP addresses, or matched DLP content. Only the
// anonymous aggregate counters (dlp_scans_total / dlp_blocks_total)
// cross the SQLite boundary, and they are bumped via the same
// stats.Counter the browser-extension path uses.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/elazarl/goproxy"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// DefaultListenAddr is the default proxy listen address. Loopback
// only — never bind a public interface or another machine could
// route its TLS through us and trip the DLP pipeline on third-party
// traffic.
const DefaultListenAddr = "127.0.0.1:8443"

// maxScanBytes mirrors the cap on POST /api/dlp/scan. Larger request
// bodies are forwarded verbatim and counted, but only the first
// maxScanBytes go through the DLP pipeline so a multi-MB upload
// can't blow up agent memory.
const maxScanBytes = 4 * 1024 * 1024

// PolicyAction is the resolved policy decision for a proxy CONNECT target.
type PolicyAction string

const (
	PolicyAllow    PolicyAction = "allow"
	PolicyAllowDLP PolicyAction = "allow_with_dlp"
	PolicyDeny     PolicyAction = "deny"
	// PolicyMonitor is used for categorized domains whose current policy
	// is "allow". The CONNECT is MITM'd so DoFunc runs on every
	// request and re-checks the live policy — if the admin flips the
	// category to "deny", the very next request is blocked without
	// waiting for Chrome to tear down the keep-alive connection.
	PolicyMonitor PolicyAction = "monitor"
)

// PolicyChecker reports the resolved action for a given hostname.
// The agent wires policy.Engine in here:
//   - AllowWithDLP  → MITM-decrypt and DLP-scan the traffic
//   - Deny          → reject the connection with a block page
//   - Allow         → opaque tunnel (pass-through)
type PolicyChecker interface {
	CheckHost(host string) PolicyAction
}

// PolicyCheckerFunc adapts a function to PolicyChecker.
type PolicyCheckerFunc func(host string) PolicyAction

// CheckHost implements PolicyChecker.
func (f PolicyCheckerFunc) CheckHost(host string) PolicyAction { return f(host) }

// DLPScanner is the subset of dlp.Pipeline the proxy needs.
type DLPScanner interface {
	Scan(ctx context.Context, content string) dlp.ScanResult
}

// StatsBumper is the subset of store.Store we need to keep
// dlp_scans_total / dlp_blocks_total in sync with the extension
// path. A nil StatsBumper is acceptable — the proxy still runs but
// scans don't contribute to aggregate counters.
type StatsBumper interface {
	BumpDLP(ctx context.Context, blocked bool) error
}

// Notifier delivers user-visible notifications when the proxy blocks
// a request. A nil Notifier is acceptable — the proxy still blocks
// but no notification is shown.
type Notifier interface {
	NotifyBlock(patternName, host string)
}

// EventRecorder persists block events to durable storage so the UI
// can display a history. A nil recorder is acceptable — events are
// simply not recorded.
type EventRecorder interface {
	RecordBlockEvent(ctx context.Context, eventType, host, patternName string) error
}

// Server is the local MITM proxy. Construct via New; start with
// ListenAndServe; stop with Shutdown.
type Server struct {
	policy   PolicyChecker
	dlp      DLPScanner
	stats    StatsBumper
	notifier Notifier
	recorder EventRecorder
	ca       *CA

	httpProxy *goproxy.ProxyHttpServer

	mu       sync.Mutex
	httpSrv  *http.Server
	listenOn string
	running  atomic.Bool

	// Anonymous in-memory counters. These mirror dlp_scans_total /
	// dlp_blocks_total without depending on a SQLite store being
	// configured — useful for tests and for GET /api/proxy/status.
	scans  atomic.Int64
	blocks atomic.Int64
}

// New constructs a Server. The CA must be ready (NewCA returned
// without error). policy and dlp are required; stats is optional —
// nil disables aggregate counter updates.
func New(ca *CA, policy PolicyChecker, scanner DLPScanner, stats StatsBumper) (*Server, error) {
	if ca == nil {
		return nil, errors.New("proxy: ca is required")
	}
	if policy == nil {
		return nil, errors.New("proxy: policy is required")
	}
	if scanner == nil {
		return nil, errors.New("proxy: dlp scanner is required")
	}

	s := &Server{
		policy: policy,
		dlp:    scanner,
		stats:  stats,
		ca:     ca,
	}

	caCert := ca.TLSCertificate()

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = false
	// goproxy's default Logger logs every CONNECT target — explicitly
	// route to io.Discard so a misconfiguration can't leak hostnames
	// to stderr. The proxy must remain content-blind beyond the
	// aggregate scan/block counters.
	proxy.Logger = noopLogger{}

	// When the proxy can't reach or can't verify the upstream, return a
	// clear, actionable page instead of a blank failure — so a user who
	// enabled the proxy understands what happened (e.g. a corporate CA
	// they need to trust) rather than seeing the site silently break.
	proxy.ConnectionErrHandler = writeUpstreamErrorPage

	tlsConfig := goproxy.TLSConfigFromCA(&caCert)

	proxy.OnRequest().HandleConnectFunc(func(host string, _ *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		hostname := stripPort(host)
		action := s.policy.CheckHost(hostname)
		switch action {
		case PolicyDeny, PolicyAllowDLP, PolicyMonitor:
			// MITM so DoFunc sees every request and can enforce
			// the live policy (block pages, DLP scans, or simple
			// pass-through for monitored-allow domains).
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectMitm,
				TLSConfig: tlsConfig,
			}, host
		default:
			// Truly uncategorized: opaque CONNECT tunnel.
			return &goproxy.ConnectAction{
				Action:    goproxy.ConnectAccept,
				TLSConfig: tlsConfig,
			}, host
		}
	})

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		// On the MITM forward path, goproxy drops the connection on a
		// transport error (e.g. an unverifiable upstream certificate),
		// leaving the user with a blank failure. Wrap the round-trip so
		// such errors become a clear, actionable page instead.
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(r *http.Request, _ *goproxy.ProxyCtx) (*http.Response, error) {
			resp, err := s.httpProxy.Tr.RoundTrip(r)
			if err != nil {
				return upstreamErrorResponse(r, err), nil
			}
			return resp, nil
		})

		hostname := stripPort(req.Host)
		// Re-check the LIVE policy on every request. This is
		// critical for PolicyMonitor connections: the CONNECT
		// was established when the category was "allow", but
		// the admin may have since flipped it to "deny".
		action := s.policy.CheckHost(hostname)

		// Deny: return an HTML block page immediately.
		if action == PolicyDeny {
			s.recordEvent(req.Context(), "category", hostname, "denied")
			return req, deniedResponse(req, hostname)
		}

		// Monitor or plain Allow: pass through without DLP scan.
		if action != PolicyAllowDLP {
			return req, nil
		}

		body, replacement, err := readScanBody(req)
		if err != nil {
			return req, badGateway(req)
		}
		if replacement != nil {
			req.Body = replacement
		}
		if len(body) == 0 {
			return req, nil
		}

		scanText := decodeScanBody(req, body)
		result := s.dlp.Scan(req.Context(), scanText)
		// Wipe the raw body as soon as the scan completes. The DLP
		// pipeline copies any matched ranges into ScanResult fields
		// (just the pattern name) before returning, so the request
		// bytes — which may contain a secret — have no further reason
		// to live in this goroutine. Zero them rather than just
		// dropping the reference so the values don't linger in memory.
		for i := range body {
			body[i] = 0
		}
		s.scans.Add(1)
		s.bumpStats(req.Context(), result.Blocked)

		if !result.Blocked {
			return req, nil
		}
		s.blocks.Add(1)
		s.notifyBlock(result.PatternName, hostname)
		s.recordEvent(req.Context(), "dlp", hostname, result.PatternName)
		return req, blockedResponse(req, result)
	})

	// Inject a tiny script into HTML responses on DLP-monitored domains.
	// The script monkey-patches fetch() and XMLHttpRequest so that when
	// the proxy returns HTTP 451 (DLP block), the user sees a visible
	// overlay instead of a silent failure in the site's JS console.
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil || ctx.Req == nil {
			return resp
		}
		// Only inject into HTML page loads (not XHR/fetch responses).
		ct := resp.Header.Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			return resp
		}
		// Only for DLP-monitored domains.
		hostname := stripPort(ctx.Req.Host)
		action := s.policy.CheckHost(hostname)
		if action != PolicyAllowDLP {
			return resp
		}
		return injectBlockInterceptor(resp)
	})

	s.httpProxy = proxy
	// Upstream TLS verification is ON by default: when the proxy MITM's a
	// request and re-originates to the destination host, it verifies the
	// upstream certificate against the system trust store. This prevents
	// an on-path attacker from feeding the proxy a forged upstream cert.
	// Deployments behind a corporate CA or with internal upstreams add
	// extra roots via SetUpstreamCABundle (proxy_upstream_ca_bundle).
	return s, nil
}

// SetUpstreamRootCAs makes the proxy verify upstream TLS connections
// against exactly the given roots (instead of the system trust store)
// when it MITM's a request. Used by tests and as the primitive behind
// SetUpstreamCABundle. A nil pool is a no-op.
func (s *Server) SetUpstreamRootCAs(pool *x509.CertPool) {
	if s == nil || s.httpProxy == nil || pool == nil {
		return
	}
	tr := s.httpProxy.Tr
	if tr == nil {
		tr = http.DefaultTransport.(*http.Transport).Clone()
	} else {
		tr = tr.Clone()
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	tr.TLSClientConfig.RootCAs = pool
	tr.TLSClientConfig.InsecureSkipVerify = false
	s.httpProxy.Tr = tr
}

// SetUpstreamCABundle adds the CA certificates in the PEM file at path to
// the set the proxy trusts when verifying upstream TLS connections,
// alongside the host's system trust store. Use it for deployments behind
// a corporate TLS-inspecting proxy or with internal/self-signed upstreams
// (the proxy_upstream_ca_bundle config option). An empty path is a no-op
// (system roots only). Verification stays ON — this only widens trust, it
// never disables checking.
func (s *Server) SetUpstreamCABundle(path string) error {
	if s == nil || path == "" {
		return nil
	}
	pemData, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("proxy: read upstream CA bundle %q: %w", path, err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return fmt.Errorf("proxy: no PEM certificates found in upstream CA bundle %q", path)
	}
	s.SetUpstreamRootCAs(pool)
	return nil
}

// ResetUpstreamVerification reverts upstream TLS verification to the
// system trust store only (dropping any imported CA bundle). Verification
// stays on.
func (s *Server) ResetUpstreamVerification() {
	if s == nil || s.httpProxy == nil {
		return
	}
	tr := s.httpProxy.Tr
	if tr == nil {
		return
	}
	tr = tr.Clone()
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	} else {
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
	}
	tr.TLSClientConfig.RootCAs = nil
	tr.TLSClientConfig.InsecureSkipVerify = false
	s.httpProxy.Tr = tr
}

// Handler exposes the underlying http.Handler. Tests and the API
// layer can drive the proxy with httptest without binding a real
// port.
func (s *Server) Handler() http.Handler { return s.httpProxy }

// ListenAddr returns the address the proxy was started on, or "" if
// not currently running.
func (s *Server) ListenAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listenOn
}

// Running reports whether the proxy is currently accepting
// connections.
func (s *Server) Running() bool { return s.running.Load() }

// ScansTotal returns the anonymous DLP-scan counter (same number
// surfaced via aggregate_stats).
func (s *Server) ScansTotal() int64 { return s.scans.Load() }

// BlocksTotal returns the anonymous DLP-block counter.
func (s *Server) BlocksTotal() int64 { return s.blocks.Load() }

// ListenAndServe starts the proxy on addr. The server runs in a
// background goroutine; this call returns after the listener is
// established (or with an error if listen failed within a short
// window).
func (s *Server) ListenAndServe(addr string) error {
	if addr == "" {
		addr = DefaultListenAddr
	}
	s.mu.Lock()
	if s.httpSrv != nil {
		s.mu.Unlock()
		return errors.New("proxy: already running")
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.httpProxy,
		ReadHeaderTimeout: 10 * time.Second,
	}
	s.httpSrv = srv
	s.listenOn = addr
	s.mu.Unlock()

	errCh := make(chan error, 1)
	go func() {
		s.running.Store(true)
		// Always reset lifecycle state when the listener exits so a
		// late ListenAndServe failure (after the 100ms startup window
		// below) does not leave httpSrv/listenOn populated, which
		// would make subsequent Enable calls report "already running"
		// until Disable is invoked.
		defer func() {
			s.running.Store(false)
			s.mu.Lock()
			if s.httpSrv == srv {
				s.httpSrv = nil
				s.listenOn = ""
			}
			s.mu.Unlock()
		}()
		err := srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		// The deferred cleanup inside the goroutine also clears
		// httpSrv/listenOn, but it races with this read from errCh.
		// Clear synchronously here so a caller that retries Enable
		// immediately after observing the error never sees a stale
		// httpSrv pointer.
		s.mu.Lock()
		if s.httpSrv == srv {
			s.httpSrv = nil
			s.listenOn = ""
		}
		s.mu.Unlock()
		return err
	case <-time.After(100 * time.Millisecond):
	}
	return nil
}

// Shutdown gracefully stops the proxy. Safe to call when not
// running.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	srv := s.httpSrv
	s.httpSrv = nil
	s.listenOn = ""
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// SetNotifier sets the notifier used to deliver OS notifications on
// DLP blocks. Safe to call before or after ListenAndServe.
func (s *Server) SetNotifier(n Notifier) {
	s.mu.Lock()
	s.notifier = n
	s.mu.Unlock()
}

func (s *Server) notifyBlock(patternName, host string) {
	s.mu.Lock()
	n := s.notifier
	s.mu.Unlock()
	if n != nil {
		go n.NotifyBlock(patternName, host)
	}
}

// SetRecorder sets the event recorder used to persist block events.
func (s *Server) SetRecorder(r EventRecorder) {
	s.mu.Lock()
	s.recorder = r
	s.mu.Unlock()
}

func (s *Server) recordEvent(ctx context.Context, eventType, host, patternName string) {
	s.mu.Lock()
	r := s.recorder
	s.mu.Unlock()
	if r != nil {
		// Fire-and-forget in a goroutine so a slow DB write
		// doesn't block the proxy hot path.
		go r.RecordBlockEvent(ctx, eventType, host, patternName)
	}
}

func (s *Server) bumpStats(ctx context.Context, blocked bool) {
	if s.stats == nil {
		return
	}
	// Errors here are intentionally swallowed — a SQLite hiccup must
	// not bubble out to the caller and break the proxy. The same
	// policy applies to the extension-side counter bump.
	_ = s.stats.BumpDLP(ctx, blocked)
}

// readScanBody drains up to maxScanBytes from req.Body. It returns
// the captured bytes plus a replacement io.ReadCloser that the
// downstream goproxy machinery can use to forward the request body
// to the upstream server unchanged. Returns nil bytes and a nil
// replacement when req.Body is nil or empty.
func readScanBody(req *http.Request) ([]byte, io.ReadCloser, error) {
	if req == nil || req.Body == nil || req.Body == http.NoBody {
		return nil, nil, nil
	}

	body := req.Body
	defer body.Close()

	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := body.Read(tmp)
		if n > 0 {
			if len(buf)+n > maxScanBytes {
				// Trim to the cap and keep reading so the upstream
				// still receives the entire body — we just don't
				// scan past the limit. Concatenating the rest into
				// an io.Reader chain is enough to forward it.
				keep := maxScanBytes - len(buf)
				if keep < 0 {
					keep = 0
				}
				buf = append(buf, tmp[:keep]...)
				remaining, rErr := io.ReadAll(body)
				if rErr != nil {
					return nil, nil, rErr
				}
				replacement := io.NopCloser(combineReaders(buf, tmp[keep:n], remaining))
				return buf, replacement, nil
			}
			buf = append(buf, tmp[:n]...)
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, err
		}
	}
	replacement := io.NopCloser(strings.NewReader(bytesToString(buf)))
	return buf, replacement, nil
}

func combineReaders(parts ...[]byte) io.Reader {
	readers := make([]io.Reader, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		readers = append(readers, strings.NewReader(bytesToString(p)))
	}
	return io.MultiReader(readers...)
}

// decodeScanBody converts the raw request body bytes into a string
// suitable for DLP scanning. For application/x-www-form-urlencoded
// bodies (used by Gemini, ChatGPT, and similar SPA front-ends) the
// percent-encoded values are decoded so the DLP regex patterns can
// match the actual text. For all other content types the raw bytes
// are returned as-is.
func decodeScanBody(req *http.Request, body []byte) string {
	ct := ""
	if req != nil {
		ct = req.Header.Get("Content-Type")
	}
	raw := bytesToString(body)
	if !strings.Contains(ct, "application/x-www-form-urlencoded") {
		return raw
	}
	// Parse form values and concatenate all decoded values separated
	// by newlines. This preserves every user-supplied string while
	// stripping the key= framing and percent encoding.
	vals, err := url.ParseQuery(raw)
	if err != nil {
		// Fall back to a simple percent-decode of the entire body.
		if decoded, e := url.QueryUnescape(raw); e == nil {
			return decoded
		}
		return raw
	}
	var sb strings.Builder
	for _, vs := range vals {
		for _, v := range vs {
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(v)
		}
	}
	if sb.Len() == 0 {
		return raw
	}
	return sb.String()
}

// deniedResponse builds an HTTP 403 reply for domains blocked by
// category policy (e.g. Social set to "deny"). This is distinct from
// the DLP-triggered 451 blockedResponse.
func deniedResponse(req *http.Request, hostname string) *http.Response {
	body := deniedHTML(hostname)
	reader := strings.NewReader(body)
	resp := &http.Response{
		Status:        "403 Forbidden",
		StatusCode:    http.StatusForbidden,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        make(http.Header),
		Body:          io.NopCloser(reader),
		ContentLength: int64(reader.Len()),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")
	return resp
}

func deniedHTML(host string) string {
	host = html.EscapeString(host)
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Site Blocked — Prompt Gate</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 2rem;
  }
  .card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 16px;
    max-width: 520px;
    width: 100%;
    padding: 2.5rem;
    text-align: center;
    box-shadow: 0 25px 50px rgba(0,0,0,0.4);
  }
  .icon {
    width: 64px;
    height: 64px;
    margin: 0 auto 1.5rem;
    background: #b91c1c;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 32px;
  }
  h1 { font-size: 1.5rem; font-weight: 700; color: #f8fafc; margin-bottom: 0.75rem; }
  .subtitle { color: #94a3b8; font-size: 0.95rem; line-height: 1.6; margin-bottom: 1.5rem; }
  .detail {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    text-align: left;
  }
  .detail-row { display: flex; justify-content: space-between; padding: 0.35rem 0; font-size: 0.85rem; }
  .detail-label { color: #64748b; }
  .detail-value { color: #f1f5f9; font-weight: 500; }
  .btn {
    display: inline-block; margin-top: 1.25rem; padding: 0.6rem 1.5rem;
    background: #3b82f6; color: #fff; border: none; border-radius: 8px;
    font-size: 0.9rem; font-weight: 500; cursor: pointer; text-decoration: none;
  }
  .btn:hover { background: #2563eb; }
  .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #475569; }
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#x1F6AB;</div>
  <h1>Site Blocked</h1>
  <p class="subtitle">
    Access to this site has been restricted by your organization's policy.
  </p>
  <div class="detail">
    <div class="detail-row">
      <span class="detail-label">Destination</span>
      <span class="detail-value">` + host + `</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Action</span>
      <span class="detail-value">Denied by category policy</span>
    </div>
  </div>
  <p class="subtitle">
    If you believe this is a mistake, contact your IT administrator.
  </p>
  <a class="btn" href="javascript:history.back()">Go Back</a>
  <div class="footer">Secured by Prompt Gate</div>
</div>
</body>
</html>`
}

// blockedResponse builds the HTTP 451 reply with an HTML block page
// so the user sees a clear warning in their browser.
func blockedResponse(req *http.Request, result dlp.ScanResult) *http.Response {
	patternName := result.PatternName
	if patternName == "" {
		patternName = "Sensitive Content"
	}
	html := blockedHTML(patternName, req.Host)
	reader := strings.NewReader(html)
	resp := &http.Response{
		Status:        "451 Unavailable For Legal Reasons",
		StatusCode:    http.StatusUnavailableForLegalReasons,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        make(http.Header),
		Body:          io.NopCloser(reader),
		ContentLength: int64(reader.Len()),
		Close:         true,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")
	// Expose pattern name so the injected interceptor script can
	// read it from fetch/XHR responses without parsing the HTML body.
	resp.Header.Set("X-SE-Pattern", patternName)
	resp.Header.Set("Access-Control-Expose-Headers", "X-SE-Pattern")
	return resp
}

func blockedHTML(patternName, host string) string {
	patternName = html.EscapeString(patternName)
	host = html.EscapeString(host)
	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Blocked by Prompt Gate</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    padding: 2rem;
  }
  .card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 16px;
    max-width: 520px;
    width: 100%;
    padding: 2.5rem;
    text-align: center;
    box-shadow: 0 25px 50px rgba(0,0,0,0.4);
  }
  .icon {
    width: 64px;
    height: 64px;
    margin: 0 auto 1.5rem;
    background: #dc2626;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 32px;
  }
  h1 {
    font-size: 1.5rem;
    font-weight: 700;
    color: #f8fafc;
    margin-bottom: 0.75rem;
  }
  .subtitle {
    color: #94a3b8;
    font-size: 0.95rem;
    line-height: 1.6;
    margin-bottom: 1.5rem;
  }
  .detail {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 1rem;
    margin-bottom: 1.5rem;
    text-align: left;
  }
  .detail-row {
    display: flex;
    justify-content: space-between;
    padding: 0.35rem 0;
    font-size: 0.85rem;
  }
  .detail-label { color: #64748b; }
  .detail-value { color: #f1f5f9; font-weight: 500; }
  .tag {
    display: inline-block;
    background: #7f1d1d;
    color: #fca5a5;
    font-size: 0.75rem;
    font-weight: 600;
    padding: 0.25rem 0.75rem;
    border-radius: 999px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  .btn {
    display: inline-block;
    margin-top: 1.25rem;
    padding: 0.6rem 1.5rem;
    background: #3b82f6;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 500;
    cursor: pointer;
    text-decoration: none;
  }
  .btn:hover { background: #2563eb; }
  .footer {
    margin-top: 1.5rem;
    font-size: 0.75rem;
    color: #475569;
  }
</style>
</head>
<body>
<div class="card">
  <div class="icon">&#x1F6E1;</div>
  <h1>Request Blocked</h1>
  <p class="subtitle">
    Prompt Gate detected sensitive data in your request and blocked it
    to protect your organization.
  </p>
  <div class="detail">
    <div class="detail-row">
      <span class="detail-label">Policy</span>
      <span class="tag">` + patternName + `</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Destination</span>
      <span class="detail-value">` + host + `</span>
    </div>
    <div class="detail-row">
      <span class="detail-label">Action</span>
      <span class="detail-value">Blocked</span>
    </div>
  </div>
  <p class="subtitle">
    If you believe this is a mistake, contact your IT administrator.
  </p>
  <a class="btn" href="javascript:history.back()">Go Back</a>
  <div class="footer">Secured by Prompt Gate</div>
</div>
</body>
</html>`
}

func badGateway(req *http.Request) *http.Response {
	resp := &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader("")),
		ContentLength: 0,
		Close:         true,
	}
	return resp
}

// isUpstreamCertError reports whether err is an upstream TLS certificate
// verification failure (as opposed to a generic connection error).
func isUpstreamCertError(err error) bool {
	if err == nil {
		return false
	}
	var cve *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	return errors.As(err, &cve) || errors.As(err, &ua) ||
		errors.As(err, &hn) || errors.As(err, &ci)
}

// upstreamErrorTitleMessage maps an upstream transport error to a
// user-facing title + message. It names no host or URL (privacy
// invariant). message may contain trusted inline HTML.
func upstreamErrorTitleMessage(err error) (title, message string) {
	if isUpstreamCertError(err) {
		return "Couldn't securely verify this site",
			"Prompt Gate could not verify the security certificate of the site you're connecting to, so it stopped the connection to keep your data safe. " +
				"If you're on a corporate or school network, your organization's certificate may need to be trusted — add it under <b>Settings → Proxy → Upstream certificates</b> (or set <code>proxy_upstream_ca_bundle</code>)."
	}
	return "Couldn't reach this site",
		"Prompt Gate couldn't establish a connection to the site you're connecting to. Check your network connection and try again."
}

// upstreamErrorResponse is a synthetic HTTP response carrying the clear
// error page, returned from the MITM round-tripper when the forward to
// the upstream fails (so the user sees an explanation, not a blank page).
func upstreamErrorResponse(req *http.Request, err error) *http.Response {
	body := upstreamErrorHTML(upstreamErrorTitleMessage(err))
	h := make(http.Header)
	h.Set("Content-Type", "text/html; charset=utf-8")
	return &http.Response{
		Status:        "502 Bad Gateway",
		StatusCode:    http.StatusBadGateway,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Request:       req,
		Header:        h,
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Close:         true,
	}
}

// writeUpstreamErrorPage is goproxy's ConnectionErrHandler for the
// non-MITM proxy paths: it writes the same clear page directly to the
// client connection. Writes only to the client — never to a log.
func writeUpstreamErrorPage(conn io.Writer, _ *goproxy.ProxyCtx, err error) {
	body := upstreamErrorHTML(upstreamErrorTitleMessage(err))
	fmt.Fprintf(conn,
		"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

func upstreamErrorHTML(title, message string) string {
	return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>` + html.EscapeString(title) + ` — Prompt Gate</title>` +
		`<style>body{font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;background:#f6f9fc;color:#1a2230;` +
		`display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}` +
		`.card{max-width:460px;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:32px;text-align:center;` +
		`box-shadow:0 6px 24px rgba(11,31,58,.06)}h1{font-size:19px;color:#0b1f3a;margin:0 0 10px}` +
		`p{font-size:14px;line-height:1.55;color:#42526e;margin:0 0 18px}code{background:#eef2f7;padding:1px 5px;border-radius:4px;font-size:12px}` +
		`.btn{display:inline-block;background:#0a84ff;color:#fff;text-decoration:none;padding:9px 18px;border-radius:8px;font-weight:600;font-size:14px}` +
		`.f{margin-top:18px;font-size:11px;color:#90a0b5}</style></head><body><div class="card">` +
		`<h1>` + html.EscapeString(title) + `</h1><p>` + message + `</p>` +
		`<a class="btn" href="javascript:history.back()">Go Back</a>` +
		`<div class="f">Secured by Prompt Gate</div></div></body></html>`
}

func stripPort(host string) string {
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		// IPv6 hosts are bracketed, e.g. "[::1]:443" — keep the
		// bracketed form so callers can still match string literals.
		if j := strings.LastIndexByte(host, ']'); j > i {
			return host
		}
		return host[:i]
	}
	return host
}

// bytesToString does what its name says without allocating. Used on
// hot scan paths where the slice is only read by string-accepting
// APIs (json.Marshal, strings.NewReader).
func bytesToString(b []byte) string { return string(b) }

// noopLogger silences goproxy's per-CONNECT host logging. Calls that
// require a side effect (panics, etc.) are still surfaced; the
// trivial Printf path used by goproxy.Logger.Printf is what we want
// to suppress.
type noopLogger struct{}

func (noopLogger) Printf(format string, v ...any) {
	// intentionally empty — never emit per-connection metadata. The
	// fmt args might include hostnames or URLs, which violates the
	// privacy invariant of this package.
	_ = fmt.Sprintf
}

// injectBlockInterceptor rewrites an HTML response to prepend a small
// <script> that monkey-patches fetch() and XMLHttpRequest. When either
// receives a 451 response from the proxy, the script shows a
// full-screen overlay explaining that the request was blocked.
func injectBlockInterceptor(resp *http.Response) *http.Response {
	if resp.Body == nil {
		return resp
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(strings.NewReader(""))
		return resp
	}

	script := blockInterceptorScript()
	html := string(body)

	// Insert the script right after <head> (or at the start if no <head>).
	idx := strings.Index(strings.ToLower(html), "<head>")
	if idx >= 0 {
		insertAt := idx + len("<head>")
		html = html[:insertAt] + script + html[insertAt:]
	} else {
		html = script + html
	}

	resp.Body = io.NopCloser(strings.NewReader(html))
	resp.ContentLength = int64(len(html))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(html)))
	// Remove Content-Security-Policy that might block inline scripts.
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	return resp
}

func blockInterceptorScript() string {
	return `<script data-se-intercept="1">(function(){
if(window.__seBlock) return;
window.__seBlock=1;
var S='position:fixed;top:0;left:0;width:100%;height:100%;z-index:2147483647;'+
'background:rgba(15,23,42,0.92);display:flex;align-items:center;justify-content:center;'+
'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;';
function showOverlay(info){
var d=document.createElement('div');
d.setAttribute('style',S);
d.innerHTML='<div style="background:#1e293b;border:1px solid #334155;border-radius:16px;'+
'max-width:480px;width:90%;padding:2.5rem;text-align:center;color:#e2e8f0;'+
'box-shadow:0 25px 50px rgba(0,0,0,0.5)">'+
'<div style="width:56px;height:56px;margin:0 auto 1.2rem;background:#dc2626;'+
'border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px">'+
'\u{1F6E1}</div>'+
'<h2 style="font-size:1.35rem;font-weight:700;color:#f8fafc;margin:0 0 .6rem">Request Blocked</h2>'+
'<p style="color:#94a3b8;font-size:.9rem;line-height:1.6;margin:0 0 1.2rem">'+
'Prompt Gate detected sensitive data in your request and blocked it to protect your organization.</p>'+
'<div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:.8rem 1rem;'+
'margin:0 0 1.2rem;text-align:left;font-size:.82rem">'+
'<div style="display:flex;justify-content:space-between;padding:.3rem 0">'+
'<span style="color:#64748b">Policy</span>'+
'<span style="background:#7f1d1d;color:#fca5a5;font-size:.72rem;font-weight:600;'+
'padding:.2rem .6rem;border-radius:999px;text-transform:uppercase">'+info.pattern+'</span></div>'+
'<div style="display:flex;justify-content:space-between;padding:.3rem 0">'+
'<span style="color:#64748b">Action</span>'+
'<span style="color:#f1f5f9;font-weight:500">Blocked</span></div></div>'+
'<button onclick="this.parentElement.parentElement.remove()" '+
'style="padding:.55rem 1.4rem;background:#3b82f6;color:#fff;border:none;border-radius:8px;'+
'font-size:.88rem;font-weight:500;cursor:pointer">Dismiss</button>'+
'<div style="margin-top:1rem;font-size:.72rem;color:#475569">Secured by Prompt Gate</div></div>';
document.body.appendChild(d);
setTimeout(function(){if(d.parentNode)d.remove()},15000);
}
var origFetch=window.fetch;
window.fetch=function(){
return origFetch.apply(this,arguments).then(function(r){
if(r.status===451){
var p=r.headers.get('X-SE-Pattern')||'Sensitive Content';
showOverlay({pattern:p});
}
return r;
});
};
var origOpen=XMLHttpRequest.prototype.open;
var origSend=XMLHttpRequest.prototype.send;
XMLHttpRequest.prototype.open=function(){this.__seMethod=arguments[0];this.__seUrl=arguments[1];return origOpen.apply(this,arguments);};
XMLHttpRequest.prototype.send=function(){
var xhr=this;
xhr.addEventListener('load',function(){
if(xhr.status===451){
var p=xhr.getResponseHeader('X-SE-Pattern')||'Sensitive Content';
showOverlay({pattern:p});
}
});
return origSend.apply(this,arguments);
};
})();</script>`
}
