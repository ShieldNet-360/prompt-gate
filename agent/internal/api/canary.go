package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
)

// CanaryRegistrar is the subset of dlp.Pipeline the canary handlers
// need: a sink that swaps in the full set of active canary patterns.
// Wired in SetCanaryRegistrar so the API package depends only on the
// interface, not the concrete pipeline.
type CanaryRegistrar interface {
	SetCanaryPatterns(patterns []*dlp.Pattern)
}

// maxCanaries caps the number of active tripwires. Each adds a pattern
// to the Aho-Corasick automaton; the cap keeps a runaway client from
// bloating the active set.
const maxCanaries = 200

// maxCanaryLabelLen bounds the user-supplied label.
const maxCanaryLabelLen = 128

type canaryCreateRequest struct {
	Label string `json:"label"`
}

// handleCanaryCollection serves GET (list) and POST (create) on
// /api/dlp/canary.
func (s *Server) handleCanaryCollection(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil || s.Canaries == nil {
		writeError(w, http.StatusServiceUnavailable, "canary store not configured")
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.listCanaries(w, r)
	case http.MethodPost:
		s.createCanary(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// handleCanaryItem serves DELETE on /api/dlp/canary/:id.
func (s *Server) handleCanaryItem(w http.ResponseWriter, r *http.Request) {
	if s.Store == nil || s.Canaries == nil {
		writeError(w, http.StatusServiceUnavailable, "canary store not configured")
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
	id := strings.TrimPrefix(r.URL.Path, "/api/dlp/canary/")
	if id == "" {
		writeError(w, http.StatusBadRequest, "missing canary id in path")
		return
	}
	ok, err := s.Store.DeleteCanary(r.Context(), id)
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "delete failed", err)
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "no such canary")
		return
	}
	if err := s.refreshCanaryPatterns(r.Context()); err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "canary reload failed", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

func (s *Server) listCanaries(w http.ResponseWriter, r *http.Request) {
	canaries, err := s.Store.ListCanaries(r.Context())
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "list failed", err)
		return
	}
	if canaries == nil {
		canaries = []store.Canary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"canaries": canaries})
}

func (s *Server) createCanary(w http.ResponseWriter, r *http.Request) {
	if s.Profile != nil && s.Profile.Locked() {
		writeError(w, http.StatusForbidden, "profile is locked by enterprise policy")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4096))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "request too large")
		return
	}
	var req canaryCreateRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	label := strings.TrimSpace(req.Label)
	if label == "" {
		writeError(w, http.StatusBadRequest, "label is required")
		return
	}
	if len(label) > maxCanaryLabelLen {
		writeError(w, http.StatusBadRequest, "label too long")
		return
	}

	existing, err := s.Store.ListCanaries(r.Context())
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "create failed", err)
		return
	}
	if len(existing) >= maxCanaries {
		writeError(w, http.StatusConflict, "canary limit reached")
		return
	}

	token, err := dlp.GenerateCanaryToken(label)
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "token generation failed", err)
		return
	}
	c, err := s.Store.CreateCanary(r.Context(), label, token, time.Now().Unix())
	if err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "create failed", err)
		return
	}
	if err := s.refreshCanaryPatterns(r.Context()); err != nil {
		writeErrorRedacted(w, http.StatusInternalServerError, "canary reload failed", err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

// noteCanaryTrigger bumps the trigger counters when a block was caused
// by a canary pattern. Best-effort and non-fatal: it is called from
// the scan hot path, so a write failure must never affect the scan
// response. The scan result carries only the pattern name
// (Canary:<label>), never the token, so attribution is by label.
func (s *Server) noteCanaryTrigger(ctx context.Context, blocked bool, patternName string) {
	if !blocked || s.Store == nil {
		return
	}
	label, ok := dlp.IsCanaryName(patternName)
	if !ok {
		return
	}
	_ = s.Store.RecordCanaryTrigger(ctx, label, time.Now().Unix())
}

// refreshCanaryPatterns rebuilds the full canary pattern set from the
// store and swaps it into the live pipeline. Called after every create
// and delete so the active tripwires always mirror the persisted set.
func (s *Server) refreshCanaryPatterns(ctx context.Context) error {
	canaries, err := s.Store.ListCanaries(ctx)
	if err != nil {
		return err
	}
	patterns := make([]*dlp.Pattern, 0, len(canaries))
	for _, c := range canaries {
		patterns = append(patterns, dlp.CanaryPattern(c.Token, c.Label))
	}
	s.Canaries.SetCanaryPatterns(patterns)
	return nil
}
