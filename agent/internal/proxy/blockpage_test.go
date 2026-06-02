package proxy

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

func TestBlockedResponse_StatusAndContentType(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://chat.openai.com/api/chat", nil)
	result := dlp.ScanResult{Blocked: true, PatternName: "AWS Access Key"}

	resp := blockedResponse(req, result)

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Errorf("status = %d, want 451", resp.StatusCode)
	}
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	cc := resp.Header.Get("Cache-Control")
	if cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
}

func TestBlockedResponse_HTMLContainsPatternAndHost(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://gemini.google.com/chat", nil)
	req.Host = "gemini.google.com"
	result := dlp.ScanResult{Blocked: true, PatternName: "GitHub Token"}

	resp := blockedResponse(req, result)
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	checks := []string{
		"Request Blocked",
		"GitHub Token",
		"gemini.google.com",
		"Prompt Gate",
		"Go Back",
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestBlockedResponse_DefaultPatternName(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	result := dlp.ScanResult{Blocked: true, PatternName: ""}

	resp := blockedResponse(req, result)
	body, _ := io.ReadAll(resp.Body)

	if !strings.Contains(string(body), "Sensitive Content") {
		t.Error("empty PatternName should fall back to 'Sensitive Content'")
	}
}

func TestBlockedResponse_XSSEscaping(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	req.Host = `evil.com"><script>alert(1)</script>`
	result := dlp.ScanResult{
		Blocked:     true,
		PatternName: `<img src=x onerror=alert(1)>`,
	}

	resp := blockedResponse(req, result)
	body, _ := io.ReadAll(resp.Body)
	html := string(body)

	if strings.Contains(html, "<script>") {
		t.Error("host not escaped — XSS via <script> tag")
	}
	if strings.Contains(html, "<img ") {
		t.Error("patternName not escaped — XSS via <img> tag")
	}
	// The escaped forms should be present.
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Error("host should contain HTML-escaped <script>")
	}
}

func TestBlockedResponse_ContentLengthMatchesBody(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.com", nil)
	result := dlp.ScanResult{Blocked: true, PatternName: "Test Pattern"}

	resp := blockedResponse(req, result)
	body, _ := io.ReadAll(resp.Body)

	if int64(len(body)) != resp.ContentLength {
		t.Errorf("ContentLength=%d but body is %d bytes", resp.ContentLength, len(body))
	}
}
