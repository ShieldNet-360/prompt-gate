// Package mcp serves the Prompt Gate DLP engine as a Model Context
// Protocol (MCP) tool server over stdio. MCP is the universal interface
// for agentic coding tools (Claude Code, Cursor, Windsurf, Continue,
// Copilot Chat); exposing the on-device scanner as an MCP tool lets any
// of them screen content for secrets before it reaches a model — with
// no proxy, no MITM CA, and no DNS change.
//
// Transport: newline-delimited JSON-RPC 2.0 on stdin/stdout (the MCP
// stdio transport). One tool is exposed: scan_for_secrets.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"

	"github.com/ShieldNet-360/prompt-gate/agent/internal/dlp"
)

// ProtocolVersion is the MCP spec revision this server implements.
const ProtocolVersion = "2024-11-05"

// ToolName is the single tool exposed by this server.
const ToolName = "scan_for_secrets"

// Scanner is the subset of *dlp.Pipeline the server needs. Defining it
// as an interface keeps the server unit-testable without a full
// pipeline.
type Scanner interface {
	Scan(ctx context.Context, content string) dlp.ScanResult
}

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server implements the MCP stdio protocol around a Scanner.
type Server struct {
	scanner Scanner
	version string
}

// NewServer builds an MCP server exposing scanner. version is reported
// in the initialize handshake's serverInfo.
func NewServer(scanner Scanner, version string) *Server {
	return &Server{scanner: scanner, version: version}
}

// Serve reads newline-delimited JSON-RPC messages from r and writes
// responses to w until r is exhausted or ctx is cancelled. Notifications
// (messages without an id) receive no response, per JSON-RPC.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	// Tool payloads (file contents, bash output) can be large; raise the
	// line limit well above bufio's 64 KiB default.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	enc := json.NewEncoder(w)

	for sc.Scan() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcError{Code: -32700, Message: "parse error"}})
			continue
		}
		resp, respond := s.handle(ctx, &req)
		if !respond {
			continue
		}
		if err := enc.Encode(resp); err != nil {
			return err
		}
	}
	return sc.Err()
}

// handle dispatches one request. The second return value is false when
// the message is a notification (no response should be written).
func (s *Server) handle(ctx context.Context, req *rpcRequest) (rpcResponse, bool) {
	isNotification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		return s.ok(req.ID, map[string]any{
			"protocolVersion": ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "prompt-gate", "version": s.version},
		}), true

	case "notifications/initialized", "initialized", "notifications/cancelled":
		return rpcResponse{}, false

	case "ping":
		return s.ok(req.ID, map[string]any{}), true

	case "tools/list":
		return s.ok(req.ID, map[string]any{"tools": []any{toolSchema()}}), true

	case "tools/call":
		return s.handleToolCall(ctx, req), true

	default:
		if isNotification {
			return rpcResponse{}, false
		}
		return s.err(req.ID, -32601, "method not found: "+req.Method), true
	}
}

func (s *Server) handleToolCall(ctx context.Context, req *rpcRequest) rpcResponse {
	var p struct {
		Name      string `json:"name"`
		Arguments struct {
			Content string `json:"content"`
		} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil {
		return s.err(req.ID, -32602, "invalid params")
	}
	if p.Name != ToolName {
		return s.err(req.ID, -32602, "unknown tool: "+p.Name)
	}

	res := s.scanner.Scan(ctx, p.Arguments.Content)
	verdict, _ := json.Marshal(res)

	// MCP tool results carry a content array; we return the verdict both
	// as human-readable text and as structuredContent so agents can
	// branch on `blocked` programmatically.
	return s.ok(req.ID, map[string]any{
		"content": []any{
			map[string]any{"type": "text", "text": string(verdict)},
		},
		"structuredContent": res,
		"isError":           false,
	})
}

func toolSchema() map[string]any {
	return map[string]any{
		"name": ToolName,
		"description": "Scan text for secrets and sensitive data (API keys, access tokens, " +
			"credentials, private keys, PII) BEFORE it is sent to an AI model or written into an " +
			"agent's context window. Runs fully on-device and persists nothing. Returns whether the " +
			"content should be blocked, the matched pattern name, and a confidence score.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"content": map[string]any{
					"type":        "string",
					"description": "The text to scan for secrets.",
				},
			},
			"required": []string{"content"},
		},
	}
}

func (s *Server) ok(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

func (s *Server) err(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}
