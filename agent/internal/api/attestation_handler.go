package api

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/attestation"
)

// handleAttestation serves GET /api/attestation: a signed, offline-
// verifiable statement of the running build and configuration (agent
// version, OS, rule-bundle hash, tamper status, anonymous counters).
// The payload carries no scanned content, URLs, or hostnames. See
// docs/attestation.md for the verification procedure.
func (s *Server) handleAttestation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	dir, err := attestationDir()
	if err != nil {
		http.Error(w, "attestation: "+err.Error(), http.StatusInternalServerError)
		return
	}
	priv, _, err := attestation.EnsureKey(dir)
	if err != nil {
		http.Error(w, "attestation: "+err.Error(), http.StatusInternalServerError)
		return
	}

	p := attestation.Payload{
		AgentVersion:   Version,
		OSType:         runtime.GOOS,
		OSArch:         runtime.GOARCH,
		ExportedAtUnix: time.Now().Unix(),
		DLPRulesSHA256: s.ruleFilesSHA256(),
	}
	if s.DLP != nil {
		p.DLPPatternCount = len(s.DLP.Patterns())
	}
	if s.Stats != nil {
		if snap, err := s.Stats.GetStats(r.Context()); err == nil {
			p.ScansTotal = uint64(snap.DLPScansTotal)
			p.BlocksTotal = uint64(snap.DLPBlocksTotal)
		}
	}
	if s.Tamper != nil {
		ts := s.Tamper.Status()
		p.TamperOK = ts.DNSOK && ts.ProxyOK
	}

	env, err := attestation.Sign(priv, p)
	if err != nil {
		http.Error(w, "attestation: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(env)
}

// ruleFilesSHA256 hashes the concatenated contents of the configured
// rule files so the attestation pins the exact rule bundle in effect.
// Returns "" when no rule files are configured.
func (s *Server) ruleFilesSHA256() string {
	if len(s.RuleFiles) == 0 {
		return ""
	}
	h := sha256.New()
	for _, p := range s.RuleFiles {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func attestationDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".prompt-gate"), nil
}
