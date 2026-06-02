// Package notify provides real-time event delivery for Prompt Gate.
//
// DLP block events are broadcast to all connected SSE clients (the
// Electron UI). The Electron app shows native desktop notifications
// and in-app toasts. Direct OS notification calls are not used because
// the agent typically runs as root / a system service and cannot reach
// the user's desktop session.
package notify

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// faqURL is the FAQ a blocked user is pointed at — it explains best
// practice (e.g. replace a key in a troubleshooting question with
// [PLACEHOLDER]) rather than auto-redacting. Hosted in-repo for now;
// swap this constant if a dedicated landing page is added later.
const faqURL = "https://github.com/ShieldNet-360/prompt-gate/blob/develop/FAQ.md"

// Event is a single notification event pushed to SSE subscribers.
type Event struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	PatternName string `json:"pattern_name,omitempty"`
	Host        string `json:"host,omitempty"`
	// FAQURL, when set, is opened in the browser if the user clicks the
	// desktop notification. Optional on the wire (older UIs ignore it).
	FAQURL    string `json:"faq_url,omitempty"`
	Timestamp string `json:"timestamp"`
}

// Notifier broadcasts events to connected SSE clients.
type Notifier struct {
	mu      sync.Mutex
	clients map[chan Event]struct{}
}

// New creates a Notifier with an empty client set.
func New() *Notifier {
	return &Notifier{
		clients: make(map[chan Event]struct{}),
	}
}

// Subscribe registers a new SSE client and returns a channel that
// receives events. The caller must call Unsubscribe when done.
func (n *Notifier) Subscribe() chan Event {
	ch := make(chan Event, 16)
	n.mu.Lock()
	n.clients[ch] = struct{}{}
	n.mu.Unlock()
	return ch
}

// Unsubscribe removes a client channel and closes it.
func (n *Notifier) Unsubscribe(ch chan Event) {
	n.mu.Lock()
	delete(n.clients, ch)
	n.mu.Unlock()
	close(ch)
}

// broadcast sends an event to all connected clients (non-blocking).
func (n *Notifier) broadcast(evt Event) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for ch := range n.clients {
		select {
		case ch <- evt:
		default:
			// Slow client — drop the event to avoid blocking the proxy.
		}
	}
}

// NotifyBlock broadcasts a DLP block event to all SSE subscribers.
func (n *Notifier) NotifyBlock(patternName, host string) {
	evt := Event{
		Type:        "dlp_block",
		Title:       "Prompt Gate — Request Blocked",
		Body:        fmt.Sprintf("Sensitive data (%s) was blocked from being sent to %s.", patternName, host),
		PatternName: patternName,
		Host:        host,
		FAQURL:      faqURL,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	}
	n.broadcast(evt)
	// Platform-specific send is a no-op (agent runs as root).
	send(evt.Title, evt.Body)
}

// MarshalEvent serialises an Event to SSE data format.
func MarshalEvent(evt Event) []byte {
	data, _ := json.Marshal(evt)
	// SSE format: "data: <json>\n\n"
	return []byte("data: " + string(data) + "\n\n")
}
