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
	"errors"
	"net/http"
	"os"
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
	Policy   PolicyChecker
	Scanner  DLPScanner
	Stats    StatsBumper
	Notifier Notifier
	Recorder EventRecorder

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
		srv, err := New(c.ca, c.cfg.Policy, c.cfg.Scanner, c.cfg.Stats)
		if err != nil {
			return "", err
		}
		if c.cfg.Notifier != nil {
			srv.SetNotifier(c.cfg.Notifier)
		}
		if c.cfg.Recorder != nil {
			srv.SetRecorder(c.cfg.Recorder)
		}
		if err := srv.SetUpstreamCABundle(c.cfg.UpstreamCABundle); err != nil {
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
