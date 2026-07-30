// Controller bridges the proxy.Server's lifecycle (CA generation,
// listener start/stop) to the api.ProxyController interface that
// /api/proxy/* endpoints depend on.
//
// The controller owns:
//   - the on-disk CA paths (so it can generate / remove them)
//   - the proxy.Server (started lazily on first Enable)
//
// It is safe for concurrent use; the mutex guards lifecycle state
// transitions (Enable / Disable) only, not per-request hot paths.
package proxy

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
)

// ControllerConfig captures everything Controller needs to manage a
// proxy lifecycle.
type ControllerConfig struct {
	ListenAddr string
	CertPath   string
	KeyPath    string

	// PolicyChecker / Scanner / Stats are the dependencies passed to
	// proxy.New when the listener is brought up. Required at config
	// time so the controller can be wired into the API server before
	// the proxy is actually started.
	Policy         PolicyChecker
	Scanner        DLPScanner
	Stats          StatsBumper
	Notifier       Notifier
	Recorder       EventRecorder
	ActionProvider ActionProvider

	// UpstreamCABundle is an optional path to a PEM file of extra CA
	// certificates to trust (alongside the system store) when verifying
	// upstream TLS connections. Empty = system roots only. Verification
	// is always on.
	UpstreamCABundle string
}

// StatusSnapshot mirrors api.ProxyStatus without importing the api
// package (and creating an import cycle). The api package marshals
// this verbatim into its own ProxyStatus when it asks.
type StatusSnapshot struct {
	Running         bool
	CAInstalled     bool
	ProxyConfigured bool
	ListenAddr      string
	CACertPath      string
	DLPScansTotal   int64
	DLPBlocksTotal  int64
}

// Controller is the orchestration object behind /api/proxy/*.
type Controller struct {
	cfg ControllerConfig

	mu     sync.Mutex
	ca     *CA
	server *Server
}

// NewController constructs a Controller. It does not generate the CA
// or start the listener — Enable does both.
func NewController(cfg ControllerConfig) (*Controller, error) {
	if cfg.ListenAddr == "" {
		return nil, errors.New("proxy: controller listen addr required")
	}
	if cfg.CertPath == "" || cfg.KeyPath == "" {
		return nil, errors.New("proxy: controller ca paths required")
	}
	if cfg.Policy == nil {
		return nil, errors.New("proxy: controller policy required")
	}
	if cfg.Scanner == nil {
		return nil, errors.New("proxy: controller scanner required")
	}
	return &Controller{cfg: cfg}, nil
}

// buildServer constructs a new proxy Server from the controller config.
// Caller must hold c.mu and c.ca must be non-nil.
func (c *Controller) buildServer() (*Server, error) {
	srv, err := New(c.ca, c.cfg.Policy, c.cfg.Scanner, c.cfg.Stats)
	if err != nil {
		return nil, err
	}
	if c.cfg.Notifier != nil {
		srv.SetNotifier(c.cfg.Notifier)
	}
	if c.cfg.Recorder != nil {
		srv.SetRecorder(c.cfg.Recorder)
	}
	if c.cfg.ActionProvider != nil {
		srv.SetActionProvider(c.cfg.ActionProvider)
	}
	// Apply the upstream CA bundle from config, or a previously
	// imported one persisted at the managed path (so it survives
	// agent restarts without a config edit).
	bundle := c.cfg.UpstreamCABundle
	if bundle == "" {
		if p := c.upstreamCAPath(); fileExists(p) {
			bundle = p
		}
	}
	if err := srv.SetUpstreamCABundle(bundle); err != nil {
		return nil, err
	}
	return srv, nil
}

// Enable generates the CA if it does not already exist, constructs
// the proxy server if not already constructed, and starts the
// listener if not already running. Returns the CA cert path so the
// caller can hand it to the install-ca script.
func (c *Controller) Enable(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.ca == nil {
		ca, err := NewCA(c.cfg.CertPath, c.cfg.KeyPath)
		if err != nil {
			return "", err
		}
		c.ca = ca
	}
	if c.server == nil {
		srv, err := c.buildServer()
		if err != nil {
			return "", err
		}
		c.server = srv
	}
	if !c.server.Running() {
		if err := c.server.ListenAndServe(c.cfg.ListenAddr); err != nil {
			return "", err
		}
	}
	return c.ca.CertPath(), nil
}

// SetListenAddr updates the proxy listen address. If the listener is
// currently running it is stopped, the address is updated, and the
// listener is restarted on the new address. If the proxy is stopped
// only the address is updated; the next Enable() will use it.
func (c *Controller) SetListenAddr(ctx context.Context, addr string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	wasRunning := c.server != nil && c.server.Running()
	if wasRunning {
		if err := c.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("proxy: shutdown for addr change: %w", err)
		}
	}
	c.server = nil // rebuild on next Enable or below
	c.cfg.ListenAddr = addr

	if wasRunning && c.ca != nil {
		srv, err := c.buildServer()
		if err != nil {
			return err
		}
		if err := srv.ListenAndServe(c.cfg.ListenAddr); err != nil {
			return fmt.Errorf("proxy: restart on %s: %w", addr, err)
		}
		c.server = srv
	}
	return nil
}

// Disable stops the listener if running. When removeCA is true the
// on-disk CA cert + key are deleted; the in-memory CA is also
// dropped so the next Enable generates a fresh keypair.
func (c *Controller) Disable(ctx context.Context, removeCA bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.server != nil && c.server.Running() {
		if err := c.server.Shutdown(ctx); err != nil {
			return err
		}
	}
	if removeCA {
		_ = os.Remove(c.cfg.CertPath)
		_ = os.Remove(c.cfg.KeyPath)
		c.ca = nil
		// Drop the server too so its goproxy instance (which closed
		// over the old CA cert) is not silently reused on the next
		// Enable — a stale CA would mean the trust install on disk
		// no longer matches what the proxy hands out.
		c.server = nil
	}
	return nil
}

// Status reports the current proxy lifecycle state.
func (c *Controller) Status() StatusSnapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	running := c.server != nil && c.server.Running()
	caInstalled := fileExists(c.cfg.CertPath)
	configured := running && c.ca != nil

	snap := StatusSnapshot{
		Running:         running,
		CAInstalled:     caInstalled,
		ProxyConfigured: configured,
		ListenAddr:      c.cfg.ListenAddr,
	}
	if c.ca != nil {
		snap.CACertPath = c.ca.CertPath()
	} else if caInstalled {
		snap.CACertPath = c.cfg.CertPath
	}
	if c.server != nil {
		snap.DLPScansTotal = c.server.ScansTotal()
		snap.DLPBlocksTotal = c.server.BlocksTotal()
	}
	return snap
}

// Handler returns the running proxy's http.Handler, or nil when the
// listener has not been started. Test-only helper.
func (c *Controller) Handler() http.Handler {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.server == nil {
		return nil
	}
	return c.server.Handler()
}

// upstreamCAPath is the managed location for an imported upstream CA
// bundle — kept next to the proxy CA so it shares the agent's data dir.
func (c *Controller) upstreamCAPath() string {
	return filepath.Join(filepath.Dir(c.cfg.CertPath), "upstream-ca.pem")
}

// SetUpstreamCA validates a PEM bundle (must contain at least one
// certificate), persists it at the managed path, and applies it to the
// running proxy and all future Enables, so the proxy trusts these CAs —
// alongside the system trust store — when verifying upstream TLS. It
// returns the imported certificates' subject common names.
func (c *Controller) SetUpstreamCA(pemData []byte) ([]string, error) {
	subjects, err := parseCASubjects(pemData)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	path := c.upstreamCAPath()
	if err := os.WriteFile(path, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("proxy: persist upstream CA bundle: %w", err)
	}
	c.cfg.UpstreamCABundle = path
	if c.server != nil {
		if err := c.server.SetUpstreamCABundle(path); err != nil {
			return nil, err
		}
	}
	return subjects, nil
}

// ClearUpstreamCA removes the imported bundle and reverts upstream
// verification to the system trust store only.
func (c *Controller) ClearUpstreamCA() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := os.Remove(c.upstreamCAPath()); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("proxy: remove upstream CA bundle: %w", err)
	}
	c.cfg.UpstreamCABundle = ""
	if c.server != nil {
		c.server.ResetUpstreamVerification()
	}
	return nil
}

// UpstreamCAStatus reports whether an upstream CA bundle is configured
// and the subject common names of the certificates in it.
func (c *Controller) UpstreamCAStatus() (bool, []string) {
	c.mu.Lock()
	path := c.cfg.UpstreamCABundle
	if path == "" {
		path = c.upstreamCAPath()
	}
	c.mu.Unlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return false, nil
	}
	subjects, err := parseCASubjects(data)
	if err != nil {
		return false, nil
	}
	return true, subjects
}

// parseCASubjects decodes a PEM bundle and returns the subject common
// names of every CERTIFICATE block, erroring if none are valid.
func parseCASubjects(pemData []byte) ([]string, error) {
	var subjects []string
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("proxy: invalid certificate in CA bundle: %w", err)
		}
		name := cert.Subject.CommonName
		if name == "" {
			name = cert.Subject.String()
		}
		subjects = append(subjects, name)
	}
	if len(subjects) == 0 {
		return nil, errors.New("proxy: no PEM certificates found in CA bundle")
	}
	return subjects, nil
}
