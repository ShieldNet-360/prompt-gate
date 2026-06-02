package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"path/filepath"
	"testing"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
	"github.com/ShieldNet-360/prompt-gate/agent/internal/store"
)

// fakeScanner is a DLPScanner that returns a fixed result.
type fakeScanner struct {
	result   dlp.ScanResult
	lastSeen string
}

func (f *fakeScanner) Scan(_ context.Context, content string) dlp.ScanResult {
	f.lastSeen = content
	return f.result
}
func (f *fakeScanner) ScanSession(_ context.Context, content string, _ string) dlp.ScanResult {
	f.lastSeen = content
	return f.result
}
func (f *fakeScanner) ScanWithContext(_ context.Context, content, _ string, _ dlp.SourceContext) dlp.ScanResult {
	f.lastSeen = content
	return f.result
}
func (f *fakeScanner) Redact(_ context.Context, content, _ string, _ dlp.SourceContext) dlp.RedactionResult {
	f.lastSeen = content
	return dlp.RedactionResult{ScanResult: f.result, Action: dlp.ActionAllow, RedactedContent: content}
}
func (f *fakeScanner) Threshold() *dlp.ThresholdEngine { return nil }
func (f *fakeScanner) SetWeights(_ dlp.ScoreWeights)   {}
func (f *fakeScanner) Patterns() []*dlp.Pattern        { return nil }
func (f *fakeScanner) Allowlist() *dlp.Allowlist       { return nil }

func frame(t *testing.T, msg any) []byte {
	t.Helper()
	body, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := make([]byte, 4+len(body))
	binary.LittleEndian.PutUint32(out[:4], uint32(len(body)))
	copy(out[4:], body)
	return out
}

// readFrames splits a serialised stream produced by ServeNativeMessaging
// into its individual length-prefixed JSON payloads.
func readFrames(t *testing.T, r io.Reader) []NativeMessageResponse {
	t.Helper()
	var out []NativeMessageResponse
	for {
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			if err == io.EOF {
				return out
			}
			t.Fatalf("readFrames len: %v", err)
		}
		n := binary.LittleEndian.Uint32(lenBuf[:])
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			t.Fatalf("readFrames body: %v", err)
		}
		var resp NativeMessageResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			t.Fatalf("readFrames decode: %v", err)
		}
		out = append(out, resp)
	}
}

func TestNativeMessaging_ScanRoundTrip(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "aws_access_key_id", Score: 9}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 42, Kind: "scan", Content: "AKIAEXAMPLE"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	frames := readFrames(t, &out)
	if len(frames) != 1 {
		t.Fatalf("got %d frames, want 1", len(frames))
	}
	if frames[0].ID != 42 {
		t.Errorf("id = %d, want 42", frames[0].ID)
	}
	if frames[0].Result == nil || !frames[0].Result.Blocked {
		t.Errorf("result = %+v, want Blocked=true", frames[0].Result)
	}
	if frames[0].Result.PatternName != "aws_access_key_id" {
		t.Errorf("pattern = %q", frames[0].Result.PatternName)
	}
	if scanner.lastSeen != "AKIAEXAMPLE" {
		t.Errorf("scanner saw %q", scanner.lastSeen)
	}
}

func TestNativeMessaging_MultipleFrames(t *testing.T) {
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "hello"}))
	in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "scan", Content: "world"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	frames := readFrames(t, &out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].ID != 1 || frames[1].ID != 2 {
		t.Errorf("ids = %d/%d", frames[0].ID, frames[1].ID)
	}
}

func TestNativeMessaging_NilScanner(t *testing.T) {
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 7, Kind: "scan", Content: "x"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), nil, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 || frames[0].Error == "" {
		t.Fatalf("expected error response, got %+v", frames)
	}
	if frames[0].Result != nil {
		t.Errorf("result should be nil when error set")
	}
}

func TestNativeMessaging_UnknownKind(t *testing.T) {
	scanner := &fakeScanner{}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "frobnicate", Content: ""}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 || frames[0].Error == "" {
		t.Fatalf("expected error response, got %+v", frames)
	}
}

func TestNativeMessaging_MalformedJSON(t *testing.T) {
	var in bytes.Buffer
	body := []byte("not json")
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], uint32(len(body)))
	in.Write(lenBuf[:])
	in.Write(body)

	scanner := &fakeScanner{}
	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 1 || frames[0].Error == "" {
		t.Fatalf("expected error response, got %+v", frames)
	}
}

func TestNativeMessaging_OverlargeMessageRejected(t *testing.T) {
	// Forge a length prefix above the cap; readNativeMessage should error.
	var lenBuf [4]byte
	binary.LittleEndian.PutUint32(lenBuf[:], MaxNativeMessageBytes+1)
	var in bytes.Buffer
	in.Write(lenBuf[:])

	scanner := &fakeScanner{}
	var out bytes.Buffer
	err := ServeNativeMessaging(context.Background(), scanner, nil, &in, &out)
	if err == nil {
		t.Fatalf("expected error for oversize frame")
	}
}

func TestNativeMessaging_ContextCanceledBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already done

	scanner := &fakeScanner{}
	var in bytes.Buffer
	var out bytes.Buffer
	if err := ServeNativeMessaging(ctx, scanner, nil, &in, &out); err != nil {
		t.Fatalf("err: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("no writes expected when ctx cancelled before read, got %d bytes", out.Len())
	}
}

func TestNativeMessaging_FramingRoundTripsWithReader(t *testing.T) {
	// Drive ServeNativeMessaging with a pipe so we exercise the
	// length-prefix decoder against a real io.Reader. Send two
	// requests, close the writer, then confirm both responses came
	// back through.
	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "github_pat", Score: 7}}
	pr, pw := io.Pipe()
	defer pr.Close()

	var out bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- ServeNativeMessaging(context.Background(), scanner, nil, pr, &out)
	}()

	for i, id := range []int{10, 11} {
		_ = i
		if _, err := pw.Write(frame(t, NativeMessageRequest{ID: id, Kind: "scan", Content: "ghp_token"})); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("serve err: %v", err)
	}
	frames := readFrames(t, &out)
	if len(frames) != 2 {
		t.Fatalf("got %d frames, want 2", len(frames))
	}
	if frames[0].Result == nil || !frames[0].Result.Blocked {
		t.Fatalf("first response missing block: %+v", frames[0])
	}
}

// TestNativeMessaging_StatsCountersBump verifies the Native Messaging
// transport bumps the same dlp_scans_total / dlp_blocks_total counters
// that the HTTP /api/dlp/scan handler bumps. Without this, the Status
// page silently undercounts whenever Chrome picks NM over the HTTP
// fallback (which is the default once the host manifest is installed).
func TestNativeMessaging_StatsCountersBump(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nm-stats.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: true, PatternName: "aws_access_key_id", Score: 9}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "AKIA00000000000000000"}))
	in.Write(frame(t, NativeMessageRequest{ID: 2, Kind: "scan", Content: "AKIA11111111111111111"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, s, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	got, err := s.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	// Both frames were blocked by fakeScanner, so dlp_scans_total
	// and dlp_blocks_total should both have advanced by exactly 2.
	if got.DLPScansTotal != 2 {
		t.Errorf("dlp_scans_total = %d, want 2", got.DLPScansTotal)
	}
	if got.DLPBlocksTotal != 2 {
		t.Errorf("dlp_blocks_total = %d, want 2", got.DLPBlocksTotal)
	}
	if got.DNSQueriesTotal != 0 || got.DNSBlocksTotal != 0 {
		t.Errorf("DNS counters touched: %+v", got)
	}
}

// TestNativeMessaging_StatsCountersBumpOnAllow confirms that an
// unblocked scan only increments dlp_scans_total, not dlp_blocks_total.
func TestNativeMessaging_StatsCountersBumpOnAllow(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nm-stats-allow.db")
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer s.Close()

	scanner := &fakeScanner{result: dlp.ScanResult{Blocked: false}}
	var in bytes.Buffer
	in.Write(frame(t, NativeMessageRequest{ID: 1, Kind: "scan", Content: "harmless"}))

	var out bytes.Buffer
	if err := ServeNativeMessaging(context.Background(), scanner, s, &in, &out); err != nil {
		t.Fatalf("ServeNativeMessaging: %v", err)
	}

	got, err := s.GetStats(context.Background())
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if got.DLPScansTotal != 1 {
		t.Errorf("dlp_scans_total = %d, want 1", got.DLPScansTotal)
	}
	if got.DLPBlocksTotal != 0 {
		t.Errorf("dlp_blocks_total = %d, want 0 (allow path)", got.DLPBlocksTotal)
	}
}
