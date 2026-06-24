package mcp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// fakeScanner blocks any content containing the sentinel substring, so
// the MCP wiring can be tested without building a full pipeline.
type fakeScanner struct{}

func (fakeScanner) Scan(_ context.Context, content string) dlp.ScanResult {
	if strings.Contains(content, "AKIA") {
		return dlp.ScanResult{Blocked: true, PatternName: "AWS Access Key", Score: 2}
	}
	return dlp.ScanResult{}
}

// drive runs one JSON-RPC line through the server and returns the decoded
// response object (nil for notifications that produce no output).
func drive(t *testing.T, line string) map[string]any {
	t.Helper()
	s := NewServer(fakeScanner{}, "test")
	var out strings.Builder
	if err := s.Serve(context.Background(), strings.NewReader(line+"\n"), &out); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	raw := strings.TrimSpace(out.String())
	if raw == "" {
		return nil
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(raw), &resp); err != nil {
		t.Fatalf("decode response %q: %v", raw, err)
	}
	return resp
}

func TestInitialize(t *testing.T) {
	resp := drive(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	result, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("no result: %v", resp)
	}
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], ProtocolVersion)
	}
}

func TestToolsListExposesScanTool(t *testing.T) {
	resp := drive(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	result := resp["result"].(map[string]any)
	tools := result["tools"].([]any)
	if len(tools) != 1 {
		t.Fatalf("want 1 tool, got %d", len(tools))
	}
	if name := tools[0].(map[string]any)["name"]; name != ToolName {
		t.Errorf("tool name = %v, want %s", name, ToolName)
	}
}

func TestToolsCallBlocksSecret(t *testing.T) {
	resp := drive(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"scan_for_secrets","arguments":{"content":"key AKIA9P2QRMZNL5CVXBT4"}}}`)
	result := resp["result"].(map[string]any)
	sc := result["structuredContent"].(map[string]any)
	if sc["blocked"] != true {
		t.Errorf("blocked = %v, want true", sc["blocked"])
	}
	if sc["pattern_name"] != "AWS Access Key" {
		t.Errorf("pattern_name = %v", sc["pattern_name"])
	}
	// content[0].text must also carry the verdict JSON
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"blocked":true`) {
		t.Errorf("text verdict missing blocked: %s", text)
	}
}

func TestToolsCallAllowsBenign(t *testing.T) {
	resp := drive(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"scan_for_secrets","arguments":{"content":"how do I sort a slice"}}}`)
	sc := resp["result"].(map[string]any)["structuredContent"].(map[string]any)
	if sc["blocked"] != false {
		t.Errorf("blocked = %v, want false", sc["blocked"])
	}
}

func TestNotificationProducesNoResponse(t *testing.T) {
	if resp := drive(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`); resp != nil {
		t.Errorf("notification should produce no response, got %v", resp)
	}
}

func TestUnknownMethodErrors(t *testing.T) {
	resp := drive(t, `{"jsonrpc":"2.0","id":5,"method":"does/not/exist"}`)
	if resp["error"] == nil {
		t.Errorf("want error for unknown method, got %v", resp)
	}
}

func TestUnknownToolErrors(t *testing.T) {
	resp := drive(t, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"nope","arguments":{}}}`)
	if resp["error"] == nil {
		t.Errorf("want error for unknown tool, got %v", resp)
	}
}
