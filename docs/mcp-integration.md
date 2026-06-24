# MCP integration

Prompt Gate can run as a [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) tool server, so any MCP-capable coding agent — **Claude Code, Cursor,
Windsurf, Continue, Copilot Chat** — can screen content for secrets **before** it
is sent to a model. It runs fully on-device, needs no proxy, no MITM CA, and no
DNS change.

The server exposes one tool:

```
scan_for_secrets(content: string) -> { blocked, pattern_name, score }
```

It is the same engine (and the same verdicts) as the browser extension and the
local HTTP API — just reached over the MCP stdio transport.

## Run it

```sh
prompt-gate-agent --mcp --config /path/to/config.yaml
```

`--mcp` speaks newline-delimited JSON-RPC 2.0 on stdin/stdout and skips the DNS,
API, and proxy servers — it is a lightweight, one-process-per-session transport.

Quick smoke test:

```sh
echo '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan_for_secrets","arguments":{"content":"AKIA9P2QRMZNL5CVXBT4"}}}' \
  | prompt-gate-agent --mcp --config /path/to/config.yaml
# -> {"jsonrpc":"2.0","id":1,"result":{... "structuredContent":{"blocked":true,"pattern_name":"AWS Access Key","score":2}}}
```

## Configure your agent

### Claude Code

Add it as an MCP server (replace the paths):

```sh
claude mcp add prompt-gate -- prompt-gate-agent --mcp --config ~/.config/prompt-gate/config.yaml
```

…or edit `~/.claude/settings.json` directly:

```json
{
  "mcpServers": {
    "prompt-gate": {
      "command": "prompt-gate-agent",
      "args": ["--mcp", "--config", "~/.config/prompt-gate/config.yaml"]
    }
  }
}
```

To **hard-block** instead of merely offering the tool, add a `PreToolUse` hook
that calls `scan_for_secrets` on tool input and aborts on `blocked: true`. The
agent ships a ready-made hook script; see the Claude Code hooks docs.

### Cursor

Create `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "prompt-gate": {
      "command": "prompt-gate-agent",
      "args": ["--mcp", "--config", "~/.config/prompt-gate/config.yaml"]
    }
  }
}
```

### Windsurf / Continue

Both read the same `mcpServers` shape. Point the `command` at `prompt-gate-agent`
with `--mcp --config <path>` as above (Windsurf: `~/.codeium/windsurf/mcp_config.json`;
Continue: the `mcpServers` block in `~/.continue/config.json`).

## Notes

- **Protocol version:** `2024-11-05`.
- **Performance:** scans are sub-millisecond, so synchronous `PreToolUse` use adds
  no perceptible latency.
- **Two paths, one engine:** if you already run the agent as a daemon, you can call
  `POST http://127.0.0.1:9191/api/dlp/scan` over HTTP instead of the stdio MCP
  server — both share the exact same pipeline and verdicts.
- **Privacy:** nothing is sent off-device and no scanned content is persisted.
