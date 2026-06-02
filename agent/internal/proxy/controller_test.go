package proxy

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func newTestController(t *testing.T, addr string) *Controller {
	t.Helper()
	dir := t.TempDir()
	c, err := NewController(ControllerConfig{
		ListenAddr: addr,
		CertPath:   filepath.Join(dir, "ca.crt"),
		KeyPath:    filepath.Join(dir, "ca.key"),
		Policy:     PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow }),
		Scanner:    &fakeScanner{},
	})
	if err != nil {
		t.Fatalf("NewController: %v", err)
	}
	return c
}

func TestController_RejectsBadConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  ControllerConfig
	}{
		{"missing addr", ControllerConfig{CertPath: "c", KeyPath: "k", Policy: PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow }), Scanner: &fakeScanner{}}},
		{"missing cert", ControllerConfig{ListenAddr: "127.0.0.1:0", KeyPath: "k", Policy: PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow }), Scanner: &fakeScanner{}}},
		{"missing key", ControllerConfig{ListenAddr: "127.0.0.1:0", CertPath: "c", Policy: PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow }), Scanner: &fakeScanner{}}},
		{"missing policy", ControllerConfig{ListenAddr: "127.0.0.1:0", CertPath: "c", KeyPath: "k", Scanner: &fakeScanner{}}},
		{"missing scanner", ControllerConfig{ListenAddr: "127.0.0.1:0", CertPath: "c", KeyPath: "k", Policy: PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllow })}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewController(tc.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestController_EnableGeneratesCAAndStartsListener(t *testing.T) {
	addr := "127.0.0.1:" + freeControllerPort(t)
	c := newTestController(t, addr)

	caPath, err := c.Enable(context.Background())
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if caPath == "" {
		t.Fatal("Enable returned empty CA path")
	}
	if !fileExists(caPath) {
		t.Fatalf("CA was not written to %s", caPath)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.Disable(ctx, false)
	}()

	snap := c.Status()
	if !snap.Running {
		t.Error("Running should be true after Enable")
	}
	if !snap.CAInstalled {
		t.Error("CAInstalled should be true after Enable")
	}
	if snap.ListenAddr != addr {
		t.Errorf("ListenAddr = %q, want %q", snap.ListenAddr, addr)
	}
}

func TestController_DisableStopsListener(t *testing.T) {
	addr := "127.0.0.1:" + freeControllerPort(t)
	c := newTestController(t, addr)
	if _, err := c.Enable(context.Background()); err != nil {
		t.Fatalf("Enable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Disable(ctx, false); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	snap := c.Status()
	if snap.Running {
		t.Error("Running should be false after Disable")
	}
	// CA stays on disk until removeCA=true.
	if !snap.CAInstalled {
		t.Error("CAInstalled should still be true after Disable(false)")
	}
}

func TestController_DisableWithRemoveCA(t *testing.T) {
	addr := "127.0.0.1:" + freeControllerPort(t)
	c := newTestController(t, addr)
	caPath, err := c.Enable(context.Background())
	if err != nil {
		t.Fatalf("Enable: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.Disable(ctx, true); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	if fileExists(caPath) {
		t.Errorf("CA cert at %s should have been removed", caPath)
	}
	snap := c.Status()
	if snap.CAInstalled {
		t.Error("CAInstalled should be false after Disable(removeCA=true)")
	}
}

func TestController_EnableIsIdempotent(t *testing.T) {
	addr := "127.0.0.1:" + freeControllerPort(t)
	c := newTestController(t, addr)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = c.Disable(ctx, false)
	}()
	if _, err := c.Enable(context.Background()); err != nil {
		t.Fatalf("Enable #1: %v", err)
	}
	if _, err := c.Enable(context.Background()); err != nil {
		t.Fatalf("Enable #2: %v", err)
	}
	if !c.Status().Running {
		t.Fatal("Running should remain true after duplicate Enable")
	}
}

func freeControllerPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen 0: %v", err)
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	return port
}
