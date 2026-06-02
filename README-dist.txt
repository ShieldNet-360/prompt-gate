===========================================================
  Prompt Gate — Quick Start Guide
===========================================================

CONTENTS
--------
  bin/prompt-gate-agent   Go agent binary (DNS + API + proxy)
  config/config.yaml      Default configuration file
  rules/                  Rule lists and DLP pattern files
  scripts/                OS-specific setup scripts
  electron/               Electron tray app (UI)
  extension/              Chrome browser extension

1. START THE AGENT
------------------
  # Run with the bundled config:
  ./bin/prompt-gate-agent -config config/config.yaml

  The agent starts:
    - DNS resolver on   127.0.0.1:15353
    - HTTP API on       127.0.0.1:9191
    - MITM proxy on     127.0.0.1:8443  (when enabled)

2. CONFIGURE DNS (requires sudo)
---------------------------------
  # macOS:
  sudo scripts/configure-dns.sh apply

  # To restore system defaults:
  sudo scripts/configure-dns.sh restore

3. ENABLE THE MITM PROXY (optional)
------------------------------------
  a) Generate CA & start the proxy via the Electron UI,
     or POST to the API:
       curl -X POST http://127.0.0.1:9191/api/proxy/enable \
         -H "Authorization: Bearer prompt-gate-local-token-2025"

  b) Trust the CA certificate:
       # macOS:
       sudo scripts/install-ca.sh install ~/.prompt-gate/ca.crt

  c) Point system HTTPS proxy at the agent:
       # macOS:
       sudo scripts/configure-proxy.sh apply

4. LAUNCH THE ELECTRON TRAY APP
--------------------------------
  cd electron && npx electron .

  The tray icon appears in the menu bar. Use it to view
  status, change policies, and manage the proxy.

5. INSTALL THE BROWSER EXTENSION
----------------------------------
  a) Open Chrome → chrome://extensions
  b) Enable "Developer mode"
  c) Click "Load unpacked" → select the extension/ folder

6. USEFUL API ENDPOINTS
------------------------
  GET  /api/status            Agent health & version
  GET  /api/policies          Current category policies
  PUT  /api/policies/:cat     Update a category policy
  GET  /api/stats             DNS/DLP statistics
  POST /api/proxy/enable      Start MITM proxy
  POST /api/proxy/disable     Stop MITM proxy
  POST /api/dlp/scan          Scan text for sensitive data
  GET  /api/rules/override    List domain overrides
  POST /api/rules/override    Add a domain override

  Mutating endpoints (POST/PUT/DELETE) require:
    Authorization: Bearer prompt-gate-local-token-2025

7. STOP / UNINSTALL
---------------------
  # Stop the agent:
  Ctrl+C or kill the process.

  # Restore DNS:
  sudo scripts/configure-dns.sh restore

  # Restore proxy:
  sudo scripts/configure-proxy.sh restore

  # Remove CA trust (macOS):
  sudo scripts/install-ca.sh uninstall ~/.prompt-gate/ca.crt

  # Full uninstall:
  sudo scripts/uninstall.sh

===========================================================
