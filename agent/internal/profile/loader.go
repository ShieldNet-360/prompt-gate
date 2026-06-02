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
		client = &http.Client{Timeout: DefaultHTTPTimeout}
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
