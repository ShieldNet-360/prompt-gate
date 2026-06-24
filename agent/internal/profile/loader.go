package profile

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"time"
)

// maxProfileBytes caps the profile document size at 1 MiB. A profile
// is a small JSON document — anything larger is almost certainly a
// misconfigured rule file or a hostile response that should not be
// silently buffered into memory.
const maxProfileBytes = 1 << 20 // 1 MiB

// DefaultHTTPTimeout is the timeout used by LoadFromURL when callers
// don't supply their own *http.Client.
const DefaultHTTPTimeout = 30 * time.Second

// LoadFromFile reads a profile JSON document from disk and validates it.
func LoadFromFile(path string) (*Profile, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("profile: load path is empty")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("profile: read %q: %w", path, err)
	}
	return Parse(raw)
}

// LoadFromURL fetches a profile JSON document from rawURL via HTTP GET
// and validates it. client may be nil; the default client uses
// DefaultHTTPTimeout.
func LoadFromURL(ctx context.Context, client *http.Client, rawURL string) (*Profile, error) {
	if strings.TrimSpace(rawURL) == "" {
		return nil, errors.New("profile: url is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("profile: parse url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("profile: url scheme %q is not http(s)", u.Scheme)
	}

	// SE-01: Reject URLs whose host resolves to private/loopback/link-local
	// addresses to prevent SSRF against cloud metadata, internal services, etc.
	if err := rejectPrivateHost(u.Hostname()); err != nil {
		return nil, err
	}

	if client == nil {
		client = newGuardedClient()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("profile: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("profile: GET %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("profile: GET %q: status %d", rawURL, resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("profile: read body: %w", err)
	}
	if len(raw) > maxProfileBytes {
		return nil, fmt.Errorf("profile: response exceeds %d bytes", maxProfileBytes)
	}
	return Parse(raw)
}

// FetchResult carries a conditional fetch outcome. When Changed is
// false the remote returned 304 Not Modified and Profile is nil; ETag
// and LastModified echo back the validators to reuse on the next poll.
type FetchResult struct {
	Profile      *Profile
	ETag         string
	LastModified string
	Changed      bool
}

// LoadFromURLConditional fetches the profile with HTTP conditional
// headers (If-None-Match / If-Modified-Since). On 304 it returns
// Changed=false and a nil Profile so the caller can keep the active
// profile untouched — making steady-state polling a zero-work no-op.
// It applies the same scheme check, SSRF guard, size cap, and guarded
// client as LoadFromURL.
func LoadFromURLConditional(ctx context.Context, client *http.Client, rawURL, etag, lastModified string) (FetchResult, error) {
	if strings.TrimSpace(rawURL) == "" {
		return FetchResult{}, errors.New("profile: url is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return FetchResult{}, fmt.Errorf("profile: parse url %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return FetchResult{}, fmt.Errorf("profile: url scheme %q is not http(s)", u.Scheme)
	}
	if err := rejectPrivateHost(u.Hostname()); err != nil {
		return FetchResult{}, err
	}
	if client == nil {
		client = newGuardedClient()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, fmt.Errorf("profile: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return FetchResult{}, fmt.Errorf("profile: GET %q: %w", rawURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return FetchResult{ETag: etag, LastModified: lastModified, Changed: false}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return FetchResult{}, fmt.Errorf("profile: GET %q: status %d", rawURL, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxProfileBytes+1))
	if err != nil {
		return FetchResult{}, fmt.Errorf("profile: read body: %w", err)
	}
	if len(raw) > maxProfileBytes {
		return FetchResult{}, fmt.Errorf("profile: response exceeds %d bytes", maxProfileBytes)
	}
	p, err := Parse(raw)
	if err != nil {
		return FetchResult{}, err
	}
	return FetchResult{
		Profile:      p,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		Changed:      true,
	}, nil
}

// rejectPrivateHost resolves host and returns an error if any resolved
// IP falls in a private, loopback, or link-local range (SE-01).
//
// Exposed as a package-level var (rather than a plain func) so tests
// driving the loader against httptest.NewServer (which binds to
// loopback) can swap it for a no-op. The SE-01 guarantee itself is
// exercised by the security_exploit tests in package_test files.
var rejectPrivateHost = strictRejectPrivateHost

func strictRejectPrivateHost(host string) error {
	ips, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("profile: resolve host %q: %w", host, err)
	}
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip != nil && isPrivateIP(ip) {
			return fmt.Errorf("profile: host resolves to private/reserved IP")
		}
	}
	return nil
}

// isPrivateIP returns true when ip is loopback, link-local, or in an
// RFC-1918 / RFC-4193 private range.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate()
}

// newGuardedClient builds the default HTTP client used when the caller
// supplies none. Its dialer validates the *connected* IP at dial time,
// closing the DNS-rebinding / TOCTOU gap that the host pre-check
// (rejectPrivateHost) leaves open: rejectPrivateHost resolves the host
// once, but client.Do resolves again before connecting, so a low-TTL
// attacker could rebind a public hostname to a private/reserved IP
// between the two. The Control hook runs on the exact address the socket
// is about to connect to, so the SSRF guard cannot be raced.
func newGuardedClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: DefaultHTTPTimeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("profile: refusing to dial unresolved address %q", address)
			}
			if isPrivateIP(ip) {
				return fmt.Errorf("profile: refusing to connect to private/reserved IP %s", ip)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: DefaultHTTPTimeout,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           dialer.DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
}
