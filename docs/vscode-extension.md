# VS Code / Cursor / Windsurf extension

The `extension-vscode/` extension brings Prompt Gate's on-device DLP into the
editor — the surface where AI-assisted development actually happens. It scans
editor content through the local agent and warns before a secret can be pasted
into Copilot, Cursor Composer, Continue, or any in-IDE assistant. Because Cursor
and Windsurf are VS Code forks, publishing to **Open VSX** covers all three.

## What it does

- **Scan on edit** — debounced scan of incoming edits (≥ 50 bytes); a warning
  notification fires when a secret is detected. Each edit is judged independently.
- **Scan selection** — command `Prompt Gate: Scan selection for secrets` checks the
  current selection (or whole file) on demand.
- **Status bar** — a shield item shows the extension is active and flips when a
  secret is detected.
- **Fail-open** — if the agent isn't running, the editor is never blocked.

It talks to the same local endpoint as the browser extension
(`POST 127.0.0.1:9191/api/dlp/scan`), authenticated with the agent's loopback
bearer token (`~/.prompt-gate/api-token`). Same engine, same verdicts. Nothing
leaves the device.

## Requirements

The Prompt Gate desktop app (or `prompt-gate-agent` daemon) must be running so the
local API is reachable.

## Build

```sh
cd extension-vscode
npm install
npm run compile          # tsc -> out/
npm run package          # vsce package -> prompt-gate-<version>.vsix  (needs @vscode/vsce)
```

Install the `.vsix` via **Extensions → … → Install from VSIX** in VS Code, Cursor,
or Windsurf.

## Settings

| Setting | Default | Meaning |
|---------|---------|---------|
| `promptGate.agentUrl` | `http://127.0.0.1:9191` | local agent base URL |
| `promptGate.scanOnEdit` | `true` | scan edits as you type |

## Coverage note

This covers content **inside the editor**. The browser extension covers web AI
chats (`chat.openai.com`, etc.); the two are complementary and don't overlap.
Some closed in-IDE agents (e.g. Copilot's inline completions) use private APIs
the document-change hook can't intercept directly — the edit scan still catches
the secret as it is typed/pasted into the document.

## Publish

VS Code Marketplace **and** Open VSX Registry (for Cursor / Windsurf) under
`shieldnet-360.prompt-gate`.
