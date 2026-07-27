package api

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/sysconf"
)

// sysProxyState tracks whether the system proxy is currently applied.
// The agent itself is the source of truth since it's the one toggling
// OS settings.
var (
	sysProxyOn bool
	sysDNSOn   bool
	sysConfMu  sync.Mutex
)

type sysConfRequest struct {
	Action string `json:"action"` // "apply" or "restore"
}

type sysConfResponse struct {
	OK      bool   `json:"ok"`
	Active  bool   `json:"active"`
	Message string `json:"message,omitempty"`
}

// handleSystemProxy handles POST /api/system/proxy { "action": "apply"|"restore" }
// and GET /api/system/proxy (returns current state).
func (s *Server) handleSystemProxy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sysConfMu.Lock()
		on := sysProxyOn
		sysConfMu.Unlock()
		writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Active: on})

	case http.MethodPost:
		var req sysConfRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: "invalid JSON"})
			return
		}
		sysConfMu.Lock()
		defer sysConfMu.Unlock()

		switch req.Action {
		case "apply":
			host, port := proxyListenParts(s)
			caPath := ""
			if s.Proxy != nil {
				caPath = s.Proxy.Status().CACertPath
			}
			// ApplyProxyWithCA trusts the CA (if not already trusted) and
			// applies the proxy under one admin prompt — see fix for the
			// "permission prompt on every click" UX bug.
			if err := sysconf.ApplyProxyWithCA(host, port, caPath); err != nil {
				log.Printf("sysconf: proxy apply error: %v", err)
				writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
				return
			}
			sysProxyOn = true
			persistSysConfState()
			writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Active: true, Message: "System proxy enabled."})

		case "restore":
			if err := sysconf.RestoreProxy(); err != nil {
				log.Printf("sysconf: proxy restore error: %v", err)
				writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
				return
			}
			sysProxyOn = false
			persistSysConfState()
			writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Active: false, Message: "System proxy disabled."})

		default:
			writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: `action must be "apply" or "restore"`})
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleSystemDNS handles POST /api/system/dns { "action": "apply"|"restore" }
// and GET /api/system/dns (returns current state).
func (s *Server) handleSystemDNS(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		sysConfMu.Lock()
		on := sysDNSOn
		sysConfMu.Unlock()
		writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Active: on})

	case http.MethodPost:
		var req sysConfRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: "invalid JSON"})
			return
		}
		sysConfMu.Lock()
		defer sysConfMu.Unlock()

		switch req.Action {
		case "apply":
			if err := sysconf.ApplyDNS("127.0.0.1"); err != nil {
				log.Printf("sysconf: dns apply error: %v", err)
				writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
				return
			}
			sysDNSOn = true
			persistSysConfState()
			writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Active: true, Message: "System DNS set to 127.0.0.1."})

		case "restore":
			if err := sysconf.RestoreDNS(); err != nil {
				log.Printf("sysconf: dns restore error: %v", err)
				writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
				return
			}
			sysDNSOn = false
			persistSysConfState()
			writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Active: false, Message: "System DNS restored to default."})

		default:
			writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: `action must be "apply" or "restore"`})
		}

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type caRequest struct {
	Action string `json:"action"` // "install" or "remove"
	CAPath string `json:"ca_path"`
}

// handleSystemCA handles POST /api/system/ca { "action": "install"|"remove", "ca_path": "..." }
func (s *Server) handleSystemCA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req caRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: "invalid JSON"})
		return
	}
	if req.CAPath == "" {
		writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: "ca_path is required"})
		return
	}

	switch req.Action {
	case "install":
		if err := sysconf.InstallCA(req.CAPath); err != nil {
			log.Printf("sysconf: CA install error: %v", err)
			writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
			return
		}
		
		// Auto-configure Firefox to trust OS certificates
		if err := sysconf.PatchFirefoxProfiles(); err != nil {
			log.Printf("sysconf: Warning: failed to patch Firefox profiles: %v", err)
			// We don't fail the overall install if Firefox patching fails (e.g. Firefox not installed)
		}

		writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Message: "CA certificate installed."})

	case "remove":
		if err := sysconf.RemoveCA(req.CAPath); err != nil {
			log.Printf("sysconf: CA remove error: %v", err)
			writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, sysConfResponse{OK: true, Message: "CA certificate removed."})

	default:
		writeJSON(w, http.StatusBadRequest, sysConfResponse{OK: false, Message: `action must be "install" or "remove"`})
	}
}

// RestoreAllSysConf restores system proxy and DNS to defaults. Call
// this during agent shutdown to ensure the user doesn't lose internet
// if the agent exits while system proxy/DNS are pointing at it.
func RestoreAllSysConf() {
	sysConfMu.Lock()
	defer sysConfMu.Unlock()
	if sysProxyOn {
		if err := sysconf.RestoreProxy(); err != nil {
			log.Printf("sysconf: shutdown proxy restore error: %v", err)
		} else {
			log.Println("sysconf: system proxy restored on shutdown")
		}
		sysProxyOn = false
	}
	if sysDNSOn {
		if err := sysconf.RestoreDNS(); err != nil {
			log.Printf("sysconf: shutdown dns restore error: %v", err)
		} else {
			log.Println("sysconf: system DNS restored on shutdown")
		}
		sysDNSOn = false
	}
	persistSysConfState()
}

// sysconfState mirrors which OS-level mutations the agent currently has
// applied. It is persisted to disk so the agent can recover after a
// non-graceful exit (crash / SIGKILL / reboot), where the in-memory
// flags would otherwise reset to false and the agent would never know
// it had left the system proxy pointing at a dead listener.
type sysconfState struct {
	Proxy bool `json:"proxy"`
	DNS   bool `json:"dns"`
}

// sysConfStatePath returns ~/.prompt-gate/sysconf-state.json.
func sysConfStatePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".prompt-gate", "sysconf-state.json"), nil
}

// persistSysConfState writes the current in-memory flags to disk.
// Callers must hold sysConfMu. Best-effort: a write failure is logged
// but never blocks the toggle the user just performed.
func persistSysConfState() {
	p, err := sysConfStatePath()
	if err != nil {
		log.Printf("sysconf: resolve state path: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		log.Printf("sysconf: mkdir state dir: %v", err)
		return
	}
	b, err := json.Marshal(sysconfState{Proxy: sysProxyOn, DNS: sysDNSOn})
	if err != nil {
		log.Printf("sysconf: marshal state: %v", err)
		return
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		log.Printf("sysconf: write state: %v", err)
	}
}

// loadSysConfState reads the persisted flags. A missing or unreadable
// file is treated as "nothing applied".
func loadSysConfState() sysconfState {
	var st sysconfState
	p, err := sysConfStatePath()
	if err != nil {
		return st
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(b, &st)
	return st
}

// ReconcileSysConfOnStartup recovers from a prior non-graceful exit. It
// loads the persisted flags into the in-memory state so a later
// graceful shutdown restores correctly, then checks the dangerous case:
// the disk says the system proxy was applied but no MITM listener is
// serving (proxyServing == false). In that state every HTTPS request is
// black-holed at the dead proxy address with no error shown to the user
// — the "blocked with no clear reason" bug — so we restore the system
// proxy to defaults. DNS is not auto-restored here because the agent's
// own resolver is already up by the time this runs.
func ReconcileSysConfOnStartup(proxyServing bool) {
	sysConfMu.Lock()
	st := loadSysConfState()
	sysProxyOn = st.Proxy
	sysDNSOn = st.DNS
	needRestore := st.Proxy && !proxyServing
	sysConfMu.Unlock()

	if !needRestore {
		return
	}
	// Restore off the startup path so a password prompt (networksetup
	// needs admin) doesn't block the rest of daemon init.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("sysconf: startup reconcile panic recovered: %v", r)
			}
		}()
		sysConfMu.Lock()
		defer sysConfMu.Unlock()
		if err := sysconf.RestoreProxy(); err != nil {
			log.Printf("sysconf: startup reconcile restore error: %v", err)
			return
		}
		log.Println("sysconf: stale system proxy detected on startup (agent exited without cleanup) — system network settings restored")
		sysProxyOn = false
		persistSysConfState()
	}()
}

type helperStatusResponse struct {
	Installed bool `json:"installed"`
	Running   bool `json:"running"`
}

// handleSysConfHelper handles GET/POST /api/system/helper.
//
// GET  → returns {"installed": bool, "running": bool}
// POST → installs the privileged proxy-helper daemon (one admin prompt on
//
//	macOS, then zero prompts forever). Returns {"installed": true} on success.
func (s *Server) handleSysConfHelper(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, helperStatusResponse{
			Installed: sysconf.HelperInstalled(),
			Running:   sysconf.HelperRunning(),
		})

	case http.MethodPost:
		if sysconf.HelperInstalled() && sysconf.HelperRunning() {
			writeJSON(w, http.StatusOK, helperStatusResponse{Installed: true, Running: true})
			return
		}
		binSrc, err := sysconf.FindHelperBin()
		if err != nil {
			writeJSON(w, http.StatusNotFound, sysConfResponse{OK: false, Message: "helper binary not found: " + err.Error()})
			return
		}
		if err := sysconf.InstallHelper(binSrc); err != nil {
			log.Printf("sysconf: helper install error: %v", err)
			writeJSON(w, http.StatusInternalServerError, sysConfResponse{OK: false, Message: err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, helperStatusResponse{Installed: true, Running: sysconf.HelperRunning()})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// proxyListenParts extracts the host and port from the proxy's listen
// address. Falls back to 127.0.0.1:8443 if the proxy controller is nil.
func proxyListenParts(s *Server) (string, int) {
	if s.Proxy != nil {
		st := s.Proxy.Status()
		if st.ListenAddr != "" {
			// Parse "host:port"
			for i := len(st.ListenAddr) - 1; i >= 0; i-- {
				if st.ListenAddr[i] == ':' {
					host := st.ListenAddr[:i]
					port := 0
					for _, c := range st.ListenAddr[i+1:] {
						port = port*10 + int(c-'0')
					}
					if host != "" && port > 0 {
						return host, port
					}
				}
			}
		}
	}
	return "127.0.0.1", 8443
}
