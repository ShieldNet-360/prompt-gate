package api

import (
	"fmt"
	"net/http"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/notify"
)

// SetNotifier wires the SSE event notifier into the API server.
func (s *Server) SetNotifier(n *notify.Notifier) {
	s.Notifier = n
}

// handleEvents serves an SSE stream of real-time agent events (DLP
// blocks, etc.). The Electron main process subscribes here and shows
// native desktop notifications.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.Notifier == nil {
		http.Error(w, "events not available", http.StatusServiceUnavailable)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ch := s.Notifier.Subscribe()
	defer s.Notifier.Unsubscribe(ch)

	// Send an initial keepalive so the client knows the connection
	// is established.
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-ch:
			if !ok {
				return
			}
			w.Write(notify.MarshalEvent(evt))
			flusher.Flush()
		}
	}
}
