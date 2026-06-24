package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeSecret is AWS's canonical documentation access-key id — a safe
// stand-in for a leaked credential in tests.
const fakeSecret = "AKIAIOSFODNN7EXAMPLE"

func reqWith(ct, enc string) *http.Request {
	h := http.Header{}
	if ct != "" {
		h.Set("Content-Type", ct)
	}
	if enc != "" {
		h.Set("Content-Encoding", enc)
	}
	return &http.Request{Header: h}
}

// multipartFile builds a one-part multipart/form-data body and returns
// the bytes plus the matching Content-Type (with boundary).
func multipartFile(t *testing.T, field, filename string, content []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

func TestDecodeScanBody_Gzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("here is my key " + fakeSecret + " do not leak"))
	_ = zw.Close()

	got := decodeScanBody(reqWith("text/plain", "gzip"), buf.Bytes())
	if !strings.Contains(got, fakeSecret) {
		t.Fatalf("gzip body not decompressed for scan: %q", got)
	}
}

func TestDecodeScanBody_MultipartTextFile(t *testing.T) {
	body, ct := multipartFile(t, "file", "creds.txt", []byte("aws_key="+fakeSecret+"\n"))
	got := decodeScanBody(reqWith(ct, ""), body)
	if !strings.Contains(got, fakeSecret) {
		t.Fatalf("multipart text part not extracted: %q", got)
	}
	if !strings.Contains(got, "creds.txt") {
		t.Errorf("filename not surfaced for scanning: %q", got)
	}
}

func TestDecodeScanBody_MultipartBase64Part(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("secret file containing " + fakeSecret))
	body, ct := multipartFile(t, "file", "blob.b64", []byte(enc))
	got := decodeScanBody(reqWith(ct, ""), body)
	if !strings.Contains(got, fakeSecret) {
		t.Fatalf("base64-encoded multipart part not decoded: %q", got)
	}
}

func TestDecodeScanBody_JSONInlineBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("config token = " + fakeSecret))
	body := `{"type":"document","source":{"type":"base64","media_type":"text/plain","data":"` + enc + `"}}`
	got := decodeScanBody(reqWith("application/json", ""), []byte(body))
	if !strings.Contains(got, fakeSecret) {
		t.Fatalf("inline base64 in JSON not decoded: %q", got)
	}
}

func TestDecodeScanBody_WholeBodyBase64(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("file contents with " + fakeSecret + " inside"))
	got := decodeScanBody(reqWith("application/octet-stream", ""), []byte(enc))
	if !strings.Contains(got, fakeSecret) {
		t.Fatalf("whole-body base64 text not decoded: %q", got)
	}
}

func TestDecodeScanBody_GzipMultipartCombined(t *testing.T) {
	// A gzipped multipart upload — both layers must be peeled.
	mpBody, ct := multipartFile(t, "file", "secret.env", []byte("KEY="+fakeSecret))
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(mpBody)
	_ = zw.Close()

	got := decodeScanBody(reqWith(ct, "gzip"), buf.Bytes())
	if !strings.Contains(got, fakeSecret) {
		t.Fatalf("gzip+multipart not fully peeled: %q", got)
	}
}

func TestDecodeScanBody_CleanJSONUnchanged(t *testing.T) {
	// A clean JSON chat prompt must pass through byte-for-byte — the
	// base64 path must never mangle ordinary content.
	body := `{"text":"hello world, no secrets here at all"}`
	got := decodeScanBody(reqWith("application/json", ""), []byte(body))
	if got != body {
		t.Fatalf("clean JSON mangled: got %q want %q", got, body)
	}
}

func TestDecodeScanBody_CapsAtMaxScanBytes(t *testing.T) {
	big := strings.Repeat("a", maxScanBytes+1024)
	got := decodeScanBody(reqWith("text/plain", ""), []byte(big))
	if len(got) > maxScanBytes {
		t.Fatalf("scan text not capped: len=%d max=%d", len(got), maxScanBytes)
	}
}

func TestIsTexty(t *testing.T) {
	if !isTexty([]byte("plain readable text")) {
		t.Error("readable text should be texty")
	}
	if isTexty([]byte{0x00, 0x01, 0x02, 0xff, 0xfe, 0x03, 0x04, 0x05, 0x06}) {
		t.Error("binary bytes should not be texty")
	}
	if isTexty([]byte("short")) {
		t.Error("too-short input should be rejected")
	}
}

// End-to-end: a multipart file upload carrying the secret is blocked
// (451) before it reaches the upstream — covering the Files-API path
// (api.openai.com/v1/files, api.x.ai/v1/files, api.anthropic.com/v1/files)
// and browser attachment posts.
func TestServer_MultipartUploadBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must never be reached on a blocked upload")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: fakeSecret, patternName: "AWS Access Key"}
	srv, err := New(ca, PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	body, ct := multipartFile(t, "file", "secret.txt", []byte("aws_key="+fakeSecret))
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/files", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451 (multipart upload should be scanned)", resp.StatusCode)
	}
	if srv.BlocksTotal() != 1 {
		t.Errorf("BlocksTotal = %d, want 1", srv.BlocksTotal())
	}
}

// End-to-end: a gzip-compressed body carrying the secret is blocked.
func TestServer_GzipUploadBlocked(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("upstream must never be reached on a blocked upload")
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: fakeSecret, patternName: "AWS Access Key"}
	srv, err := New(ca, PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte("leaking " + fakeSecret))
	_ = zw.Close()
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/chat", bytes.NewReader(gz.Bytes()))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnavailableForLegalReasons {
		t.Fatalf("status = %d, want 451 (gzip body should be decompressed and scanned)", resp.StatusCode)
	}
}

// End-to-end negative: a clean upload (no secret) is forwarded to the
// upstream untouched — the inspection must not over-block.
func TestServer_CleanUploadPassesThrough(t *testing.T) {
	reached := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("stored"))
	}))
	defer upstream.Close()

	ca := newTestCA(t)
	scanner := &fakeScanner{blockOn: fakeSecret, patternName: "AWS Access Key"}
	srv, err := New(ca, PolicyCheckerFunc(func(string) PolicyAction { return PolicyAllowDLP }), scanner, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	proxySrv := httptest.NewServer(srv.Handler())
	defer proxySrv.Close()

	client := proxyClient(t, proxySrv.URL, nil)
	body, ct := multipartFile(t, "file", "notes.txt", []byte("just some harmless notes"))
	req, _ := http.NewRequest(http.MethodPost, upstream.URL+"/v1/files", bytes.NewReader(body))
	req.Header.Set("Content-Type", ct)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (clean upload must pass)", resp.StatusCode)
	}
	if !reached {
		t.Error("clean upload never reached upstream")
	}
}
