# ──────────────────────────────────────────────────────────────────
# Prompt Gate — Justfile (cross-platform, works on Windows)
#
# Install `just` on Windows: winget install just
# Or: choco install just
# Or: cargo install just
#
# Usage:
#   just                     # build everything into dist/bin
#   just build              # build Go agent (dev layout)
#   just win                # Windows NSIS installer (.exe)
#   just macos              # macOS .dmg
#   just linux              # Linux .deb (or .tar.gz fallback)
#   just test               # run all tests
#   just clean              # remove all build artifacts
#   just agent              # Go agent binary (release)
#   just agent-debug        # Go agent binary (debug)
#   just electron           # Electron app only
#   just extension          # Browser extension only
#   just help               # show this help
# ──────────────────────────────────────────────────────────────────

# ── Configuration ──────────────────────────────────────────────────
AGENT_BINARY  := "prompt-gate-agent"
AGENT_BIN_EXT := "prompt-gate-agent.exe"
DIST          := "dist"
BIN           := DIST + "/bin"
EXT_OUT       := DIST + "/extension"
RES_BIN       := "electron/resources/bin"
RES_RULES     := "electron/resources/rules"
VERSION        := "1.0.0"
LINUX_STG     := DIST + "/_linux"
DEB_NAME      := "prompt-gate_" + VERSION + "_amd64.deb"
TAR_NAME      := "prompt-gate-" + VERSION + "-linux-amd64.tar.gz"

# Detect host OS using just's built-in os() function
os := os()

# .exe suffix on Windows, empty string otherwise
ext := if os() == "windows" { ".exe" } else { "" }

# ── Default recipe ──────────────────────────────────────────────────
default: all

# ── Helper: write config.yaml ──────────────────────────────────────
# Writes a default config.yaml to the given directory
[no-cd]
write-config dir:
    #/usr/bin/env bash -c 'cat > "$1/config.yaml" << 'EOF'
    #/ Prompt Gate agent configuration
    #/
    #/ upstream_dns: "8.8.8.8:53"
    #/ dns_listen: "127.0.0.1:15353"
    #/ api_listen: "127.0.0.1:9191"
    #/ proxy_listen: "127.0.0.1:8443"
    #/
    #/ db_path: "prompt-gate.db"
    #/
    #/ rule_paths:
    #/   - rules/ai_chat_blocked.txt
    #/   - rules/ai_code_blocked.txt
    #/   - rules/ai_chat_dlp.txt
    #/   - rules/ai_allowed.txt
    #/   - rules/phishing.txt
    #/   - rules/social.txt
    #/
    #/ dlp_patterns: rules/dlp_patterns.json
    #/ dlp_exclusions: rules/dlp_exclusions.json
    #/
    #/ proxy_enabled: false
    #/ heartbeat_interval: 1h
    #/ stats_flush_interval: 60s
    #/ rule_update_interval: 6h
    #/EOF'
    mkdir -p {{dir}}
    printf '%s\n' \
        '# Prompt Gate agent configuration' \
        '' \
        'upstream_dns: "8.8.8.8:53"' \
        'dns_listen: "127.0.0.1:15353"' \
        'api_listen: "127.0.0.1:9191"' \
        'proxy_listen: "127.0.0.1:8443"' \
        '' \
        'db_path: "prompt-gate.db"' \
        '' \
        'rule_paths:' \
        '  - rules/ai_chat_blocked.txt' \
        '  - rules/ai_code_blocked.txt' \
        '  - rules/ai_chat_dlp.txt' \
        '  - rules/ai_allowed.txt' \
        '  - rules/phishing.txt' \
        '  - rules/social.txt' \
        '' \
        'dlp_patterns: rules/dlp_patterns.json' \
        'dlp_exclusions: rules/dlp_exclusions.json' \
        '' \
        'proxy_enabled: false' \
        'heartbeat_interval: 1h' \
        'stats_flush_interval: 60s' \
        'rule_update_interval: 6h' \
        > {{dir}}/config.yaml

# ── Agent (Go) ─────────────────────────────────────────────────────
agent: agent-release

agent-release:
    #!/bin/bash
    echo "==> Building Go agent (release)..."
    mkdir -p {{BIN}}/rules
    cd agent && go build -trimpath -ldflags "-s -w" -o ../{{BIN}}/prompt-gate-agent{{ext}} ./cmd/agent
    cp rules/*.txt rules/*.json {{BIN}}/rules/ 2>/dev/null || true
    just write-config {{BIN}}

agent-debug:
    #!/bin/bash
    echo "==> Building Go agent (debug)..."
    mkdir -p {{BIN}}/rules
    cd agent && go build -tags debug -o ../{{BIN}}/prompt-gate-agent{{ext}} ./cmd/agent
    cp rules/*.txt rules/*.json {{BIN}}/rules/ 2>/dev/null || true
    just write-config {{BIN}}

# ── Build ──────────────────────────────────────────────────────────
# Build Go agent binary in-place (agent/prompt-gate-agent), matching
# the original agent/Makefile behaviour. Cross-platform.
build:
    #!/bin/bash
    cd agent && go build -o prompt-gate-agent{{ext}} ./cmd/agent

# ── Electron tray app ───────────────────────────────────────────────
electron-deps:
    #!/bin/bash
    if [ ! -d "electron/node_modules" ]; then \
        echo "==> Installing Electron dependencies..."; \
        cd electron && npm ci; \
    fi

electron: electron-deps
    #!/bin/bash
    echo "==> Building & packaging Electron app..."
    cd electron && npm run package
    mkdir -p {{BIN}}
    if [ "$(os)" = "windows" ]; then \
        electron_exe=$(find electron/release -name "*.exe" -type f 2>/dev/null | head -1); \
        if [ -n "$electron_exe" ]; then \
            cp "$electron_exe" {{BIN}}/PromptGate.exe; \
            echo "==> Packaged: {{BIN}}/PromptGate.exe"; \
        else \
            echo "WARN: .exe not found in electron/release/"; \
        fi; \
    elif [ "$(os)" = "macos" ]; then \
        app=$(find electron/release -maxdepth 2 -name "*.app" -not -path "*/Contents/*" -type d 2>/dev/null | head -1); \
        if [ -n "$app" ]; then \
            cp -R "$app" {{BIN}}/PromptGate.app; \
            echo "==> Packaged: {{BIN}}/PromptGate.app"; \
        else \
            echo "WARN: .app bundle not found in electron/release/"; \
        fi; \
    else \
        img=$(find electron/release -name "*.AppImage" -type f 2>/dev/null | head -1); \
        if [ -n "$img" ]; then \
            cp "$img" {{BIN}}/PromptGate.AppImage; \
            chmod +x {{BIN}}/PromptGate.AppImage; \
            echo "==> Packaged: {{BIN}}/PromptGate.AppImage"; \
        else \
            echo "WARN: AppImage not found in electron/release/"; \
        fi; \
    fi

# ── Browser extension ───────────────────────────────────────────────
extension-deps:
    #!/bin/bash
    if [ ! -d "extension/node_modules" ]; then \
        echo "==> Installing extension dependencies..."; \
        cd extension && npm ci; \
    fi

extension: extension-deps
    #!/bin/bash
    echo "==> Building browser extension..."
    cd extension && npm run build
    mkdir -p {{EXT_OUT}}
    cp -R extension/dist/* {{EXT_OUT}}/
    cp extension/manifest.json {{EXT_OUT}}/

# ── Dist (dev layout) ───────────────────────────────────────────────
dist: agent electron extension
    echo ""
    echo "==> Dev distribution assembled in {{DIST}}/"

all: dist

# ── macOS ───────────────────────────────────────────────────────────
macos: electron-deps
    #!/bin/bash
    echo "==> [1/3] Building Go agent (release)..."
    mkdir -p {{RES_BIN}} {{RES_RULES}}
    cd agent && go build -trimpath -ldflags "-s -w" -o ../{{RES_BIN}}/prompt-gate-agent ./cmd/agent
    cp rules/*.txt rules/*.json {{RES_RULES}}/ 2>/dev/null || true
    echo "==> [2/3] Building Electron renderer + main..."
    cd electron && npm run build
    echo "==> [3/3] Packaging macOS DMG..."
    cd electron && npx electron-builder --mac --publish never
    touch electron/release/.metadata_never_index
    echo ""
    echo "==> Done! DMG:"
    ls -lh electron/release/*.dmg 2>/dev/null || echo "    (no .dmg found — check output above)"

# ── Windows ─────────────────────────────────────────────────────────
# Build an NSIS installer for Windows. Cross-compiles from macOS/Linux
# or builds natively on Windows (Git Bash / WSL / cmd / PowerShell).
# Install on Windows: winget install just
win: windows

windows: electron-deps
    #!/bin/bash
    echo "==> [1/3] Building Go agent for Windows..."
    mkdir -p {{RES_BIN}} {{RES_RULES}}
    if [ "$(os)" = "windows" ]; then \
        cd agent && go build -trimpath -ldflags "-s -w" -o ../{{RES_BIN}}/prompt-gate-agent.exe ./cmd/agent; \
    else \
        cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../{{RES_BIN}}/prompt-gate-agent.exe ./cmd/agent; \
    fi
    cp rules/*.txt rules/*.json {{RES_RULES}}/ 2>/dev/null || true
    echo "==> [2/3] Building Electron renderer + main..."
    cd electron && npm run build
    echo "==> [3/3] Packaging Windows installer..."
    cd electron && npx electron-builder --win --publish never
    echo ""
    echo "==> Done! Installer:"
    ls -lh electron/release/*.exe 2>/dev/null || echo "    (no .exe found — check output above)"

# ── Linux ────────────────────────────────────────────────────────────
linux: agent
    #!/bin/bash
    echo "==> Assembling Linux package ..."
    rm -rf {{LINUX_STG}}
    mkdir -p {{LINUX_STG}}/usr/bin
    cp {{BIN}}/prompt-gate-agent {{LINUX_STG}}/usr/bin/
    mkdir -p {{LINUX_STG}}/etc/prompt-gate/rules
    just write-config {{LINUX_STG}}/etc/prompt-gate
    cp rules/*.txt rules/*.json {{LINUX_STG}}/etc/prompt-gate/rules/
    mkdir -p {{LINUX_STG}}/usr/share/prompt-gate
    cp scripts/linux/*.sh {{LINUX_STG}}/usr/share/prompt-gate/
    chmod +x {{LINUX_STG}}/usr/share/prompt-gate/*.sh
    cp README-dist.txt {{LINUX_STG}}/usr/share/prompt-gate/README.txt
    mkdir -p {{LINUX_STG}}/lib/systemd/system
    cp scripts/linux/prompt-gate.service {{LINUX_STG}}/lib/systemd/system/
    if command -v dpkg-deb >/dev/null 2>&1; then \
        mkdir -p {{LINUX_STG}}/DEBIAN; \
        printf '%s\n' \
          'Package: prompt-gate' \
          'Version: {{VERSION}}' \
          'Architecture: amd64' \
          'Maintainer: PromptGate Team <admin@promptgate.dev>' \
          'Description: Prompt Gate DNS + DLP agent with local MITM proxy' \
          ' DNS-level filtering, DLP scanning, and HTTPS inspection agent' \
          ' for enterprise AI-tool governance.' \
          'Section: net' \
          'Priority: optional' \
          > {{LINUX_STG}}/DEBIAN/control; \
        cp scripts/linux/postinstall.sh {{LINUX_STG}}/DEBIAN/postinst; \
        chmod 0755 {{LINUX_STG}}/DEBIAN/postinst; \
        dpkg-deb --build --root-owner-group {{LINUX_STG}} {{DIST}}/{{DEB_NAME}}; \
        echo ""; \
        echo "==> {{DIST}}/{{DEB_NAME}} ready!"; \
        echo "    Install: sudo dpkg -i {{DIST}}/{{DEB_NAME}}"; \
    else \
        echo "==> dpkg-deb not found, creating .tar.gz instead ..."; \
        tar -czf {{DIST}}/{{TAR_NAME}} -C {{LINUX_STG}} .; \
        echo ""; \
        echo "==> {{DIST}}/{{TAR_NAME}} ready!"; \
        echo "    Extract: sudo tar -xzf {{TAR_NAME}} -C /"; \
        echo "    Then run: sudo scripts/linux/postinstall.sh"; \
    fi
    rm -rf {{LINUX_STG}} {{BIN}}

# ── Tests ────────────────────────────────────────────────────────────
test: test-agent test-extension

test-agent:
    cd agent && go test -race ./...

test-extension: extension-deps
    echo "==> Running extension tests..."
    cd extension && npm test

# ── Lint ─────────────────────────────────────────────────────────────
lint:
    go vet ./...

# ── Benchmarks ───────────────────────────────────────────────────────
dlp-bench:
    go test -v ./internal/dlp -run TestFPCorpus

# ── Tidy ─────────────────────────────────────────────────────────────
tidy:
    go mod tidy

# ── Clean ────────────────────────────────────────────────────────────
clean:
    #!/bin/bash
    echo "==> Cleaning..."
    rm -rf {{DIST}} agent-bin
    rm -f agent/prompt-gate-agent agent/prompt-gate-agent.exe
    cd electron && rm -rf dist release resources/bin resources/rules
    cd extension && rm -rf dist dist-firefox dist-safari

# ── Help ─────────────────────────────────────────────────────────────
help:
    @grep -E '^# ─|^[a-z]' {{justfile()}} | sed -e 's/^# ─\{3,\}.*/\n&/' | grep -v '^[ ]*#'
