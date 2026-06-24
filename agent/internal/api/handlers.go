package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/profile"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/proxy"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/stats"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/sysconf"
)

// osStat is a thin indirection so tests can stub the filesystem. The
// default points at os.Stat; tests can replace it to drive
// collectRuleFileInfo against an in-memory fixture.
var osStat = func(name string) (os.FileInfo, error) { return os.Stat(name) }

// maxScanBytes caps the body size accepted by /api/dlp/scan. Pastes
// well beyond this size are typically not what a user is sending to an
// AI tool, and an unbounded body is a memory-exhaustion vector.
const maxScanBytes = 4 * 1024 * 1024 // 4 MiB

// StatusResponse is the body for GET /api/status.
// Both `uptime` (human-readable) and `uptime_seconds` (machine-readable)
// are emitted so the Electron tray and the browser extension don't have
// to parse the formatted string. The optional `runtime` and `rules`
// All embedded values are
// non-sensitive operational metadata — no scan content, domains, URLs,
// IPs, or user identifiers ever appear here.
type StatusResponse struct {
	Status        string         `json:"status"`
	Uptime        string         `json:"uptime"`
	UptimeSeconds int64          `json:"uptime_seconds"`
	Version       string         `json:"version"`
	Runtime       RuntimeStats   `json:"runtime,omitempty"`
	Rules         []RuleFileInfo `json:"rules,omitempty"`
	DLPPatterns   int            `json:"dlp_patterns,omitempty"`
}

// RuntimeStats captures Go runtime counters surfaced via /api/status.
// All fields are derived from runtime.MemStats / runtime.NumGoroutine
// and contain no user-derived data.
type RuntimeStats struct {
	GoVersion    string `json:"go_version"`
	NumGoroutine int    `json:"num_goroutine"`
	NumCPU       int    `json:"num_cpu"`
	HeapAllocKB  uint64 `json:"heap_alloc_kb"`
	HeapInuseKB  uint64 `json:"heap_inuse_kb"`
	SysKB        uint64 `json:"sys_kb"`
	NumGC        uint32 `json:"num_gc"`
	GoMaxProcs   int    `json:"gomaxprocs"`
}

// RuleFileInfo carries the modification time and byte size of a rule
// file. Paths are echoed back unchanged so callers know which file is
// which.
type RuleFileInfo struct {
	Path         string    `json:"path"`
	SizeBytes    int64     `json:"size_bytes"`
	LastModified time.Time `json:"last_modified"`
}

// PolicyUpdate is the request body for PUT /api/policies/:category.
type PolicyUpdate struct {
	Action string `json:"action"`
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// writeErrorRedacted logs the full error to stderr but returns only
// the user-safe message to the client (SE-10).
func writeErrorRedacted(w http.ResponseWriter, code int, userMsg string, err error) {
	fmt.Fprintf(os.Stderr, "api: %s: %v\n", userMsg, err)
	writeJSON(w, code, map[string]string{"error": userMsg})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	since := time.Since(s.startedAt)
	if since < 0 {
		since = 0
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rt := RuntimeStats{
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		NumCPU:       runtime.NumCPU(),
		HeapAllocKB:  ms.HeapAlloc / 1024,
		HeapInuseKB:  ms.HeapInuse / 1024,
		SysKB:        ms.Sys / 1024,
		NumGC:        ms.NumGC,
		GoMaxProcs:   runtime.GOMAXPROCS(0),
	}

	resp := StatusResponse{
		Status:        "running",
		Uptime:        formatUptime(since),
		UptimeSeconds: int64(since / time.Second),
		Version:       Version,
		Runtime:       rt,
	}
	if s.DLP != nil {
		resp.DLPPatterns = len(s.DLP.Patterns())
	}
	if len(s.RuleFiles) > 0 {
		resp.Rules = collectRuleFileInfo(s.RuleFiles)
	}
	writeJSON(w, http.StatusOK, resp)
}

// ruleFileEntry is the wire shape for a single rule file in the
// /api/rules/files response. It includes the file content.
type ruleFileEntry struct {
	Name         string    `json:"name"`
	Path         string    `json:"path"`
	Content      string    `json:"content"`
	SizeBytes    int64     `json:"size_bytes"`
	LastModified time.Time `json:"last_modified"`
}

// handleRuleFiles handles GET /api/rules/files — returns every
// configured rule file with its content so the UI can display and
// edit them.
func (s *Server) handleRuleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	entries := make([]ruleFileEntry, 0, len(s.RuleFiles))
	for _, p := range s.RuleFiles {
		fi, err := osStat(p)
		if err != nil {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		entries = append(entries, ruleFileEntry{
			Name:         filepath.Base(p),
			Path:         p,
			Content:      string(data),
			SizeBytes:    fi.Size(),
			LastModified: fi.ModTime(),
		})
	}
	writeJSON(w, http.StatusOK, entries)
}

// handleRuleFileItem handles GET/PUT /api/rules/files/:name.
// GET returns the single file's content; PUT overwrites it and triggers
// a policy reload.
func (s *Server) handleRuleFileItem(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/rules/files/")
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "/") || strings.Contains(name, "..") {
		writeError(w, http.StatusBadRequest, "invalid file name")
		return
	}
	// Find the full path by matching the base name.
	var fullPath string
	for _, p := range s.RuleFiles {
		if filepath.Base(p) == name {
			fullPath = p
			break
		}
	}
	if fullPath == "" {
		writeError(w, http.StatusNotFound, "rule file not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		data, err := os.ReadFile(fullPath)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "read failed")
			return
		}
		fi, _ := osStat(fullPath)
		writeJSON(w, http.StatusOK, ruleFileEntry{
			Name:         name,
			Path:         fullPath,
			Content:      string(data),
			SizeBytes:    fi.Size(),
			LastModified: fi.ModTime(),
		})
	case http.MethodPut:
		var body struct {
			Content string `json:"content"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if err := os.WriteFile(fullPath, []byte(body.Content), 0o600); err != nil {
			writeError(w, http.StatusInternalServerError, "write failed")
			return
		}
		// Trigger policy reload so changes take effect immediately.
		if s.Policy != nil {
			if err := s.Policy.Reload(r.Context()); err != nil {
				writeError(w, http.StatusInternalServerError, "policy reload failed")
				return
			}
		}
		fi, _ := osStat(fullPath)
		writeJSON(w, http.StatusOK, ruleFileEntry{
			Name:         name,
			Path:         fullPath,
			Content:      body.Content,
			SizeBytes:    fi.Size(),
			LastModified: fi.ModTime(),
		})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// collectRuleFileInfo gathers mtime + size for each rule file path
// the agent was started with. Missing files are silently skipped so a
// partial deployment (e.g. an upcoming rule file not yet present)
// doesn't break the status endpoint.
func collectRuleFileInfo(paths []string) []RuleFileInfo {
	out := make([]RuleFileInfo, 0, len(paths))
	for _, p := range paths {
		fi, err := osStat(p)
		if err != nil {
			continue
		}
		out = append(out, RuleFileInfo{
			Path:         p,
			SizeBytes:    fi.Size(),
			LastModified: fi.ModTime(),
		})
	}
	return out
}

func formatUptime(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int(d / time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh %dm", days, hours, mins)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

func (s *Server) handlePoliciesCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	pols, err := s.Store.ListPolicies(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list policies failed")
		return
	}
	if pols == nil {
		pols = []store.CategoryPolicy{}
	}
	writeJSON(w, http.StatusOK, pols)
}

func (s *Server) handlePolicyItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	category := strings.TrimPrefix(r.URL.Path, "/api/policies/")
	category = strings.TrimSpace(category)
	if category == "" {
		writeError(w, http.StatusBadRequest, "category is required")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	var body PolicyUpdate
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Store.SetPolicy(r.Context(), category, body.Action); err != nil {
		if errors.Is(err, store.ErrInvalidAction) {
			writeError(w, http.StatusBadRequest, "invalid action")
			return
		}
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	if err := s.Policy.Reload(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "policy reload failed")
		return
	}
	writeJSON(w, http.StatusOK, store.CategoryPolicy{Category: category, Action: body.Action})
}

// protectionPlanRequest is the body for POST /api/protection-plan.
// The plan field must be "extra" or "light".
type protectionPlanRequest struct {
	Plan string `json:"plan"`
}

// handleProtectionPlan applies a high-level protection preset by
// updating the AI-related category policies in bulk:
//
//	"extra"  — Allow AI Sites & Tools but inspect with DLP:
//	           AI Chat DLP → allow_with_dlp
//	           AI Chat Blocked → allow_with_dlp
//	           AI Code Blocked → allow_with_dlp
//
//	"light"  — Block risky AI sites, no DLP inspection:
//	           AI Chat DLP → deny
//	           AI Chat Blocked → deny
//	           AI Code Blocked → deny
func (s *Server) handleProtectionPlan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}

	var body protectionPlanRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	type catAction struct {
		Category string
		Action   string
	}

	var updates []catAction
	switch body.Plan {
	case "extra":
		updates = []catAction{
			{"AI Chat DLP", store.ActionAllowWithDLP},
			{"AI Chat Blocked", store.ActionAllowWithDLP},
			{"AI Code Blocked", store.ActionAllowWithDLP},
		}
	case "light":
		updates = []catAction{
			{"AI Chat DLP", store.ActionDeny},
			{"AI Chat Blocked", store.ActionDeny},
			{"AI Code Blocked", store.ActionDeny},
		}
	default:
		writeError(w, http.StatusBadRequest, `plan must be "extra" or "light"`)
		return
	}

	for _, u := range updates {
		if err := s.Store.SetPolicy(r.Context(), u.Category, u.Action); err != nil {
			writeError(w, http.StatusInternalServerError, "update failed")
			return
		}
	}

	if s.Policy != nil {
		if err := s.Policy.Reload(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "policy reload failed")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]string{"plan": body.Plan, "status": "applied"})
}

func (s *Server) handleBlockEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit := 50
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 {
				limit = n
			}
		}
		events, err := s.Store.ListBlockEvents(r.Context(), limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list block events failed")
			return
		}
		if events == nil {
			events = []store.BlockEvent{}
		}
		writeJSON(w, http.StatusOK, events)
	case http.MethodDelete:
		if err := s.Store.ClearBlockEvents(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "clear block events failed")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// preferencesResponse is the wire shape for GET /api/preferences. The
// `managed` field lets the Electron UI grey out the consent toggle
// when an enterprise profile has locked the agent.
type preferencesResponse struct {
	BlockEventsEnabled     bool  `json:"block_events_enabled"`
	BlockEventsConsentedAt int64 `json:"block_events_consented_at"`
	RedactEnabled          bool  `json:"redact_enabled"`
	Managed                bool  `json:"managed"`
}

func (s *Server) handlePreferences(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	prefs, err := s.Store.GetAgentPreferences(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read preferences failed")
		return
	}
	resp := preferencesResponse{
		BlockEventsEnabled:     prefs.BlockEventsEnabled,
		BlockEventsConsentedAt: prefs.BlockEventsConsentedAt,
		RedactEnabled:          prefs.RedactEnabled,
		Managed:                s.Profile != nil && s.Profile.Locked(),
	}
	writeJSON(w, http.StatusOK, resp)
}

// redactModeBody is the PUT body for /api/preferences/redact-mode.
// {"enabled": true} switches the DLP action on a detected secret from
// block (default) to redact. Enterprise-locked profiles refuse the
// change so an org can pin block-only.
type redactModeBody struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleRedactMode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	var body redactModeBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Store.SetRedactEnabled(r.Context(), body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, "update preferences failed")
		return
	}
	prefs, err := s.Store.GetAgentPreferences(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read preferences failed")
		return
	}
	writeJSON(w, http.StatusOK, preferencesResponse{
		BlockEventsEnabled:     prefs.BlockEventsEnabled,
		BlockEventsConsentedAt: prefs.BlockEventsConsentedAt,
		RedactEnabled:          prefs.RedactEnabled,
		Managed:                false,
	})
}

// blockEventsConsent is the PUT body for /api/preferences/block-events.
// The user must send {"enabled": true} explicitly — there is no
// default-on path. Once enabled, the proxy's existing
// InsertBlockEvent calls (via Store.InsertBlockEvent) stop short-
// circuiting and per-event hostnames begin to land in SQLite.
type blockEventsConsent struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleBlockEventsConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	var body blockEventsConsent
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Store.SetBlockEventsEnabled(r.Context(), body.Enabled, time.Now().Unix()); err != nil {
		writeError(w, http.StatusInternalServerError, "update preferences failed")
		return
	}
	prefs, err := s.Store.GetAgentPreferences(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read preferences failed")
		return
	}
	writeJSON(w, http.StatusOK, preferencesResponse{
		BlockEventsEnabled:     prefs.BlockEventsEnabled,
		BlockEventsConsentedAt: prefs.BlockEventsConsentedAt,
		Managed:                false,
	})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	snap, err := s.Stats.GetStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats unavailable")
		return
	}
	writeJSON(w, http.StatusOK, snap)
}

func (s *Server) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if err := s.Stats.Reset(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "reset failed")
		return
	}
	writeJSON(w, http.StatusOK, stats.Snapshot{})
}

// dlpScanRequest is the body for POST /api/dlp/scan.
//
// SessionID is optional. When supplied (typically by the browser
// extension as a per-tab opaque token), the multi-piece correlator
// is engaged: secrets split across consecutive pastes in the same
// session are reassembled and detected.
//
// Source is optional. When supplied, the agent's
// scorer biases verdicts by destination + element + path context.
// Missing or zero-valued Source preserves default scoring behaviour exactly,
// so old extensions continue to work unchanged.
type dlpScanRequest struct {
	Content   string             `json:"content"`
	SessionID string             `json:"session_id,omitempty"`
	Source    *dlp.SourceContext `json:"source,omitempty"`
}

func (s *Server) handleDLPScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.DLP == nil {
		writeError(w, http.StatusServiceUnavailable, "DLP pipeline not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxScanBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	var req dlpScanRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	var source dlp.SourceContext
	if req.Source != nil {
		source = *req.Source
	}

	// User decision: block (default) vs redact. Read per request so a
	// toggle takes effect immediately. A read failure falls back to the
	// safe default (block) inside Store.RedactEnabled.
	redactMode := s.Store != nil && s.Store.RedactEnabled(r.Context())

	// Privacy invariant: req.Content lives in this stack frame only.
	// It is not logged and not persisted; the response carries the
	// decision plus the pattern name (never the match itself). In
	// redact mode the response additionally carries redacted_content —
	// also built and held only in this frame.
	if redactMode {
		// Redact embeds the same scan + the redacted copy. The
		// function is fail-closed: anything it can't safely mask comes
		// back as action="block".
		result := s.DLP.Redact(r.Context(), req.Content, req.SessionID, source)
		req.Content = ""
		req.SessionID = ""
		req.Source = nil
		if s.Stats != nil {
			_ = bumpDLPStats(r.Context(), s.Store, result.Blocked)
		}
		writeJSON(w, http.StatusOK, result)
		return
	}

	var result dlp.ScanResult
	switch {
	case req.Source != nil && !req.Source.IsZero():
		// Caller supplied destination/element/path
		// context. ScanWithContext folds session + source into the
		// existing pipeline.
		result = s.DLP.ScanWithContext(r.Context(), req.Content, req.SessionID, source)
	case req.SessionID != "":
		result = s.DLP.ScanSession(r.Context(), req.Content, req.SessionID)
	default:
		result = s.DLP.Scan(r.Context(), req.Content)
	}
	req.Content = ""   // drop reference promptly.
	req.SessionID = "" // drop reference promptly.
	req.Source = nil   // drop reference promptly.

	// Increment anonymous DLP counters.
	if s.Stats != nil {
		_ = bumpDLPStats(r.Context(), s.Store, result.Blocked)
	}

	writeJSON(w, http.StatusOK, result)
}

// dlpConfigResponse is the wire shape of GET /api/dlp/config and the
// expected body of PUT /api/dlp/config. We just reflect the SQLite
// dlp_config columns so callers can round-trip the value.
type dlpConfigResponse = store.DLPConfig

func (s *Server) handleDLPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleDLPConfigGet(w, r)
	case http.MethodPut:
		s.handleDLPConfigPut(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleDLPConfigGet(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.Store.GetDLPConfig(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dlp config unavailable")
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (s *Server) handleDLPConfigPut(w http.ResponseWriter, r *http.Request) {
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	var body store.DLPConfig
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Store.SetDLPConfig(r.Context(), body); err != nil {
		writeError(w, http.StatusInternalServerError, "update failed")
		return
	}
	s.applyLiveDLP(dlpConfigToSnapshot(body))
	writeJSON(w, http.StatusOK, body)
}

// applyLiveDLP propagates the given snapshot's thresholds and
// scoring weights into the live DLP pipeline. Used by PUT
// /api/dlp/config, POST /api/profile/import, and the startup
// profile loader so all three paths stay in sync with what's
// persisted in SQLite — without this, weight/threshold changes
// would only take effect after an agent restart, silently
// diverging from the values returned by GET /api/dlp/config and
// GET /api/profile. A nil DLP pipeline (no DLP wired)
// short-circuits to a no-op.
//
// Threshold is set first and the weights setter is invoked last on
// purpose: SetWeights resets the pipeline's scan-result cache, so a
// PUT /api/dlp/config invalidates any cached verdicts produced under
// the previous policy before the next /api/dlp/scan can hit them.
func (s *Server) applyLiveDLP(c profile.DLPConfigSnapshot) {
	if s == nil || s.DLP == nil {
		return
	}
	s.DLP.Threshold().Set(dlp.Thresholds{
		Critical: c.ThresholdCritical,
		High:     c.ThresholdHigh,
		Medium:   c.ThresholdMedium,
		Low:      c.ThresholdLow,
	})
	s.DLP.SetWeights(dlp.ScoreWeights{
		HotwordBoost:     c.HotwordBoost,
		EntropyBoost:     c.EntropyBoost,
		EntropyPenalty:   c.EntropyPenalty,
		ExclusionPenalty: c.ExclusionPenalty,
		MultiMatchBoost:  c.MultiMatchBoost,
	})
}

// dlpConfigToSnapshot mirrors the field-for-field shape between
// store.DLPConfig and profile.DLPConfigSnapshot. The two types are
// kept separate to avoid a profile→store import cycle.
func dlpConfigToSnapshot(c store.DLPConfig) profile.DLPConfigSnapshot {
	return profile.DLPConfigSnapshot{
		ThresholdCritical: c.ThresholdCritical,
		ThresholdHigh:     c.ThresholdHigh,
		ThresholdMedium:   c.ThresholdMedium,
		ThresholdLow:      c.ThresholdLow,
		HotwordBoost:      c.HotwordBoost,
		EntropyBoost:      c.EntropyBoost,
		EntropyPenalty:    c.EntropyPenalty,
		ExclusionPenalty:  c.ExclusionPenalty,
		MultiMatchBoost:   c.MultiMatchBoost,
	}
}

// bumpDLPStats increments dlp_scans_total (+1) and optionally
// dlp_blocks_total (+1 when blocked). Errors are intentionally
// swallowed by the caller — counter updates must not break a scan.
func bumpDLPStats(ctx context.Context, s *store.Store, blocked bool) error {
	if s == nil {
		return nil
	}
	delta := store.AggregateStats{DLPScansTotal: 1}
	if blocked {
		delta.DLPBlocksTotal = 1
	}
	return s.AddStats(ctx, delta)
}

// Compile-time check: dlp.ScanResult must remain JSON-encodable
// without referencing user content. If anyone adds a field here that
// might leak content, this var will need to be updated explicitly.
var _ = dlp.ScanResult{Blocked: false, PatternName: "", Score: 0}

// Suppress the unused import warning when none of the type's fields
// are referenced (it is used via the s.DLP interface).
var _ = stats.Snapshot{}

// handleRulesUpdate handles POST /api/rules/update. It triggers an
// immediate manifest check and waits for the result before responding.
// 503 is returned when no updater was wired (older
// deployments). The reply matches rules.Result so callers can decide
// whether to flash a "rules updated" toast in the tray UI.
func (s *Server) handleRulesUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RuleUpdater == nil {
		writeError(w, http.StatusServiceUnavailable, "rule updater not configured")
		return
	}
	res, err := s.RuleUpdater.CheckNow(r.Context())
	if err != nil {
		writeErrorRedacted(w, http.StatusBadGateway, "rule update failed", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleRulesStatus handles GET /api/rules/status. Returns the
// updater's current bookkeeping fields. 503 is returned when no
// updater was wired so callers can suppress the rules section in the
// tray UI on legacy installs.
func (s *Server) handleRulesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.RuleUpdater == nil {
		// No remote updater configured — fall back to the version
		// persisted in the local database so the UI still shows it.
		ver := ""
		if s.Store != nil {
			ver, _ = s.Store.CurrentRuleVersion(r.Context())
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"current_version": ver,
			"update_url":      "",
		})
		return
	}
	writeJSON(w, http.StatusOK, s.RuleUpdater.Status())
}

// proxyEnableResponse is the body of POST /api/proxy/enable.
type proxyEnableResponse struct {
	CACertPath string `json:"ca_cert_path"`
}

// proxyDisableRequest is the body of POST /api/proxy/disable. Both
// fields are optional; empty body is equivalent to remove_ca=false.
type proxyDisableRequest struct {
	RemoveCA bool `json:"remove_ca"`
}

// handleProxyEnable triggers CA generation (if needed) and starts the
// proxy listener. Returns 503 when no proxy controller is wired.
func (s *Server) handleProxyEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	caPath, err := s.Proxy.Enable(r.Context())
	if err != nil {
		// A port conflict is operator-actionable and leaks nothing
		// sensitive, so return the real reason instead of the opaque
		// redacted message — the tray can tell the user another agent is
		// already holding the proxy port.
		if errors.Is(err, proxy.ErrAddrInUse) {
			fmt.Fprintf(os.Stderr, "api: enable proxy failed: %v\n", err)
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeErrorRedacted(w, http.StatusInternalServerError, "enable proxy failed", err)
		return
	}
	// Best-effort: set shell env vars for CLI tools in terminals.
	// caPath is exported too (NODE_EXTRA_CA_CERTS etc.) so CLIs that
	// ignore the OS keychain still trust the MITM cert.
	status := s.Proxy.Status()
	if status.ListenAddr != "" {
		if err := sysconf.ApplyShellProxy("http://"+status.ListenAddr, caPath); err != nil {
			log.Printf("sysconf: shell proxy apply (non-fatal): %v", err)
		}
	}
	writeJSON(w, http.StatusOK, proxyEnableResponse{CACertPath: caPath})
}

// handleProxyDisable stops the proxy listener and optionally removes
// the on-disk CA when remove_ca=true is set in the body.
func (s *Server) handleProxyDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	// Always attempt to decode; treat io.EOF (empty body in any
	// transfer encoding) as a no-op equivalent to remove_ca=false.
	// Gating on r.ContentLength is unsafe because net/http reports
	// -1 when no Content-Length header is present (e.g. chunked
	// transfer encoding or a plain POST without the header).
	var body proxyDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if err := s.Proxy.Disable(r.Context(), body.RemoveCA); err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "disable proxy failed", err)
		return
	}
	// Best-effort: unset shell env vars so CLI tools stop using the proxy.
	if err := sysconf.RemoveShellProxy(); err != nil {
		log.Printf("sysconf: shell proxy remove (non-fatal): %v", err)
	}
	writeJSON(w, http.StatusOK, s.Proxy.Status())
}

// proxyListenRequest is the body of PUT /api/proxy/listen.
type proxyListenRequest struct {
	ListenAddr string `json:"listen_addr"`
}

// handleProxyListen handles GET/PUT /api/proxy/listen.
//
//	GET  → current listen address from status snapshot.
//	PUT  → update listen address; validates loopback-only; if the proxy
//	       is running it stops and restarts on the new address. The new
//	       address is also persisted to the config file via ConfigPatcher.
func (s *Server) handleProxyListen(w http.ResponseWriter, r *http.Request) {
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"listen_addr": s.Proxy.Status().ListenAddr})
	case http.MethodPut:
		var body proxyListenRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		host, portStr, err := net.SplitHostPort(body.ListenAddr)
		if err != nil {
			writeError(w, http.StatusBadRequest, "listen_addr must be host:port (e.g. 127.0.0.1:8443)")
			return
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			writeError(w, http.StatusBadRequest, "only loopback addresses are supported (127.x.x.x or ::1)")
			return
		}
		portNum, _ := strconv.Atoi(portStr)
		if portNum < 1024 || portNum > 65535 {
			writeError(w, http.StatusBadRequest, "port must be between 1024 and 65535")
			return
		}
		if err := s.Proxy.SetListenAddr(r.Context(), body.ListenAddr); err != nil {
			writeErrorRedacted(w, http.StatusInternalServerError, "set listen addr failed", err)
			return
		}
		if s.ConfigPatcher != nil {
			if err := s.ConfigPatcher(body.ListenAddr); err != nil {
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"listen_addr": body.ListenAddr,
					"warning":     "in-memory change applied; config persist failed: " + err.Error(),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"listen_addr": body.ListenAddr})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleProxyStatus returns the current proxy lifecycle snapshot.
func (s *Server) handleProxyStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.Proxy.Status())
}

// maxUpstreamCABytes caps the size of an imported upstream CA bundle.
const maxUpstreamCABytes = 256 * 1024 // 256 KiB — a few certs at most.

// upstreamCARequest is the POST body for /api/proxy/upstream-ca: a PEM
// bundle of CA certificates to trust for upstream TLS verification.
type upstreamCARequest struct {
	PEM string `json:"pem"`
}

// upstreamCAResponse reports whether a bundle is configured and the
// subject common names of its certificates.
type upstreamCAResponse struct {
	Configured bool     `json:"configured"`
	Subjects   []string `json:"subjects,omitempty"`
}

// handleProxyUpstreamCA manages the proxy's extra upstream CA bundle:
//
//	GET    → current status (configured + subjects)
//	POST   → import a PEM bundle ({"pem": "..."}); trusted alongside the
//	         system store. Verification stays on; this only widens trust.
//	DELETE → remove the bundle, reverting to the system store only.
func (s *Server) handleProxyUpstreamCA(w http.ResponseWriter, r *http.Request) {
	if s.Proxy == nil {
		writeError(w, http.StatusServiceUnavailable, "proxy not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		configured, subjects := s.Proxy.UpstreamCAStatus()
		writeJSON(w, http.StatusOK, upstreamCAResponse{Configured: configured, Subjects: subjects})
	case http.MethodPost:
		var body upstreamCARequest
		if err := json.NewDecoder(io.LimitReader(r.Body, maxUpstreamCABytes)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		subjects, err := s.Proxy.SetUpstreamCA([]byte(body.PEM))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, upstreamCAResponse{Configured: true, Subjects: subjects})
	case http.MethodDelete:
		if err := s.Proxy.ClearUpstreamCA(); err != nil {
			writeErrorRedacted(w, http.StatusInternalServerError, "clear upstream CA failed", err)
			return
		}
		writeJSON(w, http.StatusOK, upstreamCAResponse{Configured: false})
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// maxProfileBytes caps the size of a profile uploaded via
// /api/profile/import to keep an unbounded body from exhausting
// memory. Profiles are tiny JSON documents in practice.
const maxProfileBytes = 1 << 20 // 1 MiB

// profileImportRequest is the body for POST /api/profile/import. A
// non-empty URL takes precedence over an inline Profile body — the
// agent downloads the profile and applies it.
type profileImportRequest struct {
	URL     string           `json:"url,omitempty"`
	Profile *profile.Profile `json:"profile,omitempty"`
}

// handleProfileGet returns the active enterprise profile or 404 if
// none is loaded.
func (s *Server) handleProfileGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile == nil {
		writeError(w, http.StatusNotFound, "no profile loaded")
		return
	}
	p := s.Profile.Get()
	if p == nil {
		writeError(w, http.StatusNotFound, "no profile loaded")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// handleProfileImport accepts either a URL to fetch the profile from
// or an inline JSON profile body, validates it, applies it to the
// store (which can flip Managed=true and lock the device), and
// returns the active profile.
func (s *Server) handleProfileImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile == nil {
		writeError(w, http.StatusServiceUnavailable, "profile holder not configured")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxProfileBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}

	var req profileImportRequest
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	var p *profile.Profile
	switch {
	case strings.TrimSpace(req.URL) != "":
		p, err = profile.LoadFromURL(r.Context(), nil, req.URL)
		if err != nil {
			writeErrorRedacted(w, http.StatusBadGateway, "fetch profile failed", err)
			return
		}
	case req.Profile != nil:
		if err := req.Profile.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		p = req.Profile
	default:
		writeError(w, http.StatusBadRequest, "url or profile required")
		return
	}

	if s.ProfileApply != nil {
		if err := p.Apply(r.Context(), profile.ApplyOptions{
			PolicyStore: s.ProfileApply,
			Reloader:    s.Policy,
			DLPSink:     s.applyLiveDLP,
		}); err != nil {
			writeErrorRedacted(w, http.StatusInternalServerError, "apply profile failed", err)
			return
		}
	}
	if err := s.Profile.Set(p); err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "store profile failed", err)
		return
	}
	writeJSON(w, http.StatusOK, s.Profile.Get())
}

// handleTamperStatus surfaces the tamper detector's most recent check.
func (s *Server) handleTamperStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Tamper == nil {
		writeError(w, http.StatusServiceUnavailable, "tamper detector not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.Tamper.Status())
}

// statsExportResponse adds the human / runtime context that turns a
// raw counter dump into a usable export. Nothing sensitive is added
// — only the build/OS metadata an admin needs to correlate the
// counters with the device.
type statsExportResponse struct {
	AgentVersion string         `json:"agent_version"`
	OSType       string         `json:"os_type"`
	OSArch       string         `json:"os_arch"`
	ExportedAt   time.Time      `json:"exported_at"`
	Stats        stats.Snapshot `json:"stats"`
}

// handleStatsExport returns the same counters as /api/stats wrapped
// with a small envelope so the export file is self-describing. The
// response has a Content-Disposition header so the Electron UI can
// surface "Save as…" naturally.
func (s *Server) handleStatsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	snap, err := s.Stats.GetStats(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stats unavailable")
		return
	}
	body := statsExportResponse{
		AgentVersion: Version,
		OSType:       runtime.GOOS,
		OSArch:       runtime.GOARCH,
		ExportedAt:   time.Now().UTC(),
		Stats:        snap,
	}
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"prompt-gate-stats-%s.json\"",
			body.ExportedAt.Format("20060102-150405")))
	writeJSON(w, http.StatusOK, body)
}

// ruleOverrideRequest is the body for POST /api/rules/override.
type ruleOverrideRequest struct {
	Domain string `json:"domain"`
	// List is "allow" or "block". Anything else returns 400.
	List string `json:"list"`
}

// ruleOverrideResponse is the body returned by the override
// endpoints; ListAllow / ListBlock reflect the merged-on-disk state
// after the call.
type ruleOverrideResponse struct {
	Allow []string `json:"allow"`
	Block []string `json:"block"`
}

// handleRuleOverride adds (POST) or lists (GET) admin allow/block
// override entries. Writes through to rules/local/*.txt and then
// triggers a policy reload so the change is picked up immediately.
func (s *Server) handleRuleOverride(w http.ResponseWriter, r *http.Request) {
	if s.Rules == nil {
		writeError(w, http.StatusServiceUnavailable, "rule overrides not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		a, b := s.Rules.List()
		writeJSON(w, http.StatusOK, ruleOverrideResponse{Allow: a, Block: b})
	case http.MethodPost:
		var body ruleOverrideRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
		if strings.TrimSpace(body.Domain) == "" {
			writeError(w, http.StatusBadRequest, "domain is required")
			return
		}
		if body.List != "allow" && body.List != "block" {
			writeError(w, http.StatusBadRequest, "list must be allow or block")
			return
		}
		if err := s.Rules.Add(body.Domain, body.List); err != nil {
			writeErrorRedacted(w, http.StatusInternalServerError, "add override failed", err)
			return
		}
		// Surface reload errors instead of silently 200ing. The
		// override file has already been persisted; if reload fails
		// the on-disk state is ahead of the in-memory engine and the
		// caller needs to know the change isn't live yet. Same
		// contract as handlePolicyItem above.
		if s.Policy != nil {
			if err := s.Policy.Reload(r.Context()); err != nil {
				writeError(w, http.StatusInternalServerError, "policy reload failed")
				return
			}
		}
		a, b := s.Rules.List()
		writeJSON(w, http.StatusOK, ruleOverrideResponse{Allow: a, Block: b})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleRuleOverrideItem handles DELETE /api/rules/override/:domain.
func (s *Server) handleRuleOverrideItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Rules == nil {
		writeError(w, http.StatusServiceUnavailable, "rule overrides not configured")
		return
	}
	domain := strings.TrimPrefix(r.URL.Path, "/api/rules/override/")
	domain = strings.TrimSpace(domain)
	if domain == "" {
		writeError(w, http.StatusBadRequest, "domain is required")
		return
	}
	if err := s.Rules.Remove(domain); err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "remove override failed", err)
		return
	}
	// See handleRuleOverride: a failed reload after a successful
	// on-disk removal must not return 200, otherwise the caller
	// thinks the override is gone while DNS still applies it.
	if s.Policy != nil {
		if err := s.Policy.Reload(r.Context()); err != nil {
			writeError(w, http.StatusInternalServerError, "policy reload failed")
			return
		}
	}
	a, b := s.Rules.List()
	writeJSON(w, http.StatusOK, ruleOverrideResponse{Allow: a, Block: b})
}

// handleAgentUpdateCheck reports whether a newer agent release is
// published on the configured manifest channel. Returns 503 if no
// updater is wired (builds without a release channel).
func (s *Server) handleAgentUpdateCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.AgentUpdate == nil {
		writeError(w, http.StatusServiceUnavailable, "agent updater not configured")
		return
	}
	res, err := s.AgentUpdate.CheckLatest(r.Context())
	if err != nil {
		writeErrorRedacted(w, http.StatusBadGateway, "update check failed", err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleAgentUpdate downloads the latest agent release, verifies its
// SHA256 + Ed25519 signature, and stages it for restart. Returns 503
// when no updater is wired.
func (s *Server) handleAgentUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.AgentUpdate == nil {
		writeError(w, http.StatusServiceUnavailable, "agent updater not configured")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	staged, err := s.AgentUpdate.DownloadAndStage(r.Context())
	if err != nil {
		writeErrorRedacted(w, http.StatusBadGateway, "stage failed", err)
		return
	}
	writeJSON(w, http.StatusOK, staged)
}

// ── Feedback allowlist — /api/dlp/allowlist endpoints ──────────────

// dlpAllowlistAddRequest is the body for POST /api/dlp/allowlist.
// Value is held only in this stack frame and dropped after the
// hash + store step; the agent never persists the raw value.
type dlpAllowlistAddRequest struct {
	Value       string `json:"value"`
	Scope       string `json:"scope,omitempty"`        // destination_kind or "*" / ""
	PatternName string `json:"pattern_name,omitempty"` // optional display hint
	TTLSeconds  int64  `json:"ttl_seconds,omitempty"`  // 0 = never
}

type dlpAllowlistAddResponse struct {
	SaltedHash string `json:"salted_hash"`
}

func (s *Server) handleDLPAllowlistCollection(w http.ResponseWriter, r *http.Request) {
	if s.DLP == nil || s.DLP.Allowlist() == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.handleAllowlistList(w, r)
	case http.MethodPost:
		s.handleAllowlistAdd(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleDLPAllowlistItem(w http.ResponseWriter, r *http.Request) {
	if s.DLP == nil || s.DLP.Allowlist() == nil {
		writeError(w, http.StatusServiceUnavailable, "allowlist not configured")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	hash := strings.TrimPrefix(r.URL.Path, "/api/dlp/allowlist/")
	if hash == "" {
		writeError(w, http.StatusBadRequest, "missing salted_hash in path")
		return
	}
	ok, err := s.DLP.Allowlist().Remove(r.Context(), hash)
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "remove failed", err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such allowlist entry")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

func (s *Server) handleAllowlistList(w http.ResponseWriter, r *http.Request) {
	entries, err := s.DLP.Allowlist().List(r.Context())
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	if entries == nil {
		entries = []dlp.AllowlistEntry{}
	}
	writeJSON(w, http.StatusOK, entries)
}

func (s *Server) handleAllowlistAdd(w http.ResponseWriter, r *http.Request) {
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxScanBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	var req dlpAllowlistAddRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Value == "" {
		writeError(w, http.StatusBadRequest, "value is required")
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	hash, err := s.DLP.Allowlist().Add(r.Context(), req.Value, req.Scope, req.PatternName, ttl)
	// Drop the raw value reference as early as possible.
	req.Value = ""
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "add failed", err)
		return
	}
	writeJSON(w, http.StatusCreated, dlpAllowlistAddResponse{SaltedHash: hash})
}
