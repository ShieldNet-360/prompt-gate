package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// realKey is a realistic (non-example) AWS access-key id. Unlike the
// canonical AKIAIOSFODNN7EXAMPLE, this one is NOT on the DLP allowlist,
// so the production ruleset blocks it. Paired with hotwords nearby so it
// clears the score threshold.
const realKey = "AKIA9F2D1JK4X8P0QRTM"

// buildProdPipeline loads the SHIPPED rules/dlp_patterns.json so the test
// exercises the real detection engine, not a stub.
func buildProdPipeline(t *testing.T) *dlp.Pipeline {
	t.Helper()
	// agent/internal/proxy -> repo-root/rules/dlp_patterns.json
	patternFile := filepath.Join("..", "..", "..", "rules", "dlp_patterns.json")
	patterns, err := dlp.LoadPatterns(patternFile)
	if err != nil {
		t.Fatalf("LoadPatterns(%s): %v", patternFile, err)
	}
	pipeline := dlp.NewPipeline(dlp.DefaultScoreWeights(), dlp.NewThresholdEngine(dlp.DefaultThresholds()))
	pipeline.Rebuild(patterns, nil)
	return pipeline
}

// TestIntegration_RealDLP_FileUploadVariantsBlocked drives the FULL stack
// — production rules + real pipeline + MITM proxy — and confirms that the
// fake AWS key is caught no matter how the text file is wrapped on its way
// to an LLM: plain multipart, base64-encoded multipart, gzipped body, and
// inline base64 in a JSON chat request. Covers both the browser-prompt and
// CLI/SDK upload shapes, including encoded text files.
func TestIntegration_RealDLP_FileUploadVariantsBlocked(t *testing.T) {
	// Surround the key with hotwords so the production scorer blocks it
	// (the bare AWS-key pattern has a low base weight + hotword boost).
	const leak = "aws access_key for deploy: " + realKey

	multipartPlain, mpCT := multipartFile(t, "file", "creds.txt", []byte(leak))

	b64 := base64.StdEncoding.EncodeToString([]byte(leak))
	multipartB64, mpB64CT := multipartFile(t, "file", "creds.txt.b64", []byte(b64))

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(leak))
	_ = zw.Close()

	jsonInline := `{"messages":[{"role":"user","content":[{"type":"document","source":{"type":"base64","data":"` + b64 + `"}}]}]}`

	cases := []struct {
		name    string
		path    string
		ct      string
		enc     string
		body    []byte
		comment string
	}{
		{"multipart text file (Files API)", "/v1/files", mpCT, "", multipartPlain, "claude/openai/grok CLI + browser attach"},
		{"base64-encoded multipart file", "/v1/files", mpB64CT, "", multipartB64, "encoded text file upload"},
		{"gzip-compressed body", "/v1/chat", "text/plain", "gzip", gz.Bytes(), "transport-compressed upload"},
		{"inline base64 in JSON chat", "/v1/messages", "application/json", "", []byte(jsonInline), "browser prompt with attached file data"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamCalls := atomic.Int64{}
			upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				upstreamCalls.Add(1)
			}))
			defer upstream.Close()

			policy := PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP })
			srv, _ := newServer(t, policy, buildProdPipeline(t), &fakeStats{})
			proxySrv := httptest.NewServer(srv.Handler())
			defer proxySrv.Close()

			client := proxyClient(t, proxySrv.URL, nil)
			req, _ := http.NewRequest(http.MethodPost, upstream.URL+tc.path, bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", tc.ct)
			if tc.enc != "" {
				req.Header.Set("Content-Encoding", tc.enc)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			defer resp.Body.Close()
			_, _ = io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusUnavailableForLegalReasons {
				t.Fatalf("%s: status = %d, want 451 (leak should be caught by real DLP)", tc.comment, resp.StatusCode)
			}
			if upstreamCalls.Load() != 0 {
				t.Errorf("%s: upstream hit %d times — leak escaped the gate", tc.comment, upstreamCalls.Load())
			}
		})
	}
}

// TestIntegration_RealDLP_AllowlistedExampleKeyPasses is the negative
// control: the canonical documentation key is allowlisted, so an upload
// containing it must NOT be blocked — proving the upload scanner reuses
// the real allowlist rather than naively matching the regex.
func TestIntegration_RealDLP_AllowlistedExampleKeyPasses(t *testing.T) {
	upstreamCalls := atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	policy := PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP })
	srv, _ := newServer(t, policy, buildProdPipeline(t), &fakeStats{})
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	body, ct := multipartFile(t, "file", "example.txt",
		[]byte("Example key (do not use): AKIAIOSFODNN7EXAMPLE"))
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/files", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (allowlisted example key must pass)", resp.StatusCode)
	}
	if upstreamCalls.Load() != 1 {
		t.Errorf("clean upload reached upstream %d times, want 1", upstreamCalls.Load())
	}
}
