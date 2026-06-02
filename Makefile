# ──────────────────────────────────────────────────────────────────
# Prompt Gate — top-level Makefile
#
# Usage:
#   make              # build everything into dist/bin
#   make macos        # macOS .dmg (drag-to-Applications)
#   make win          # Windows NSIS installer (.exe)
#   make portable-win # portable ZIP for Windows (agent + rules + config)
#   make linux        # self-contained installer in dist/linux/
#   make agent        # Go agent binary (release, default)
#   make agent-debug  # Go agent binary (debug — logs to edge_<date>.log)
#   make electron     # Electron app only
#   make extension    # Browser extension only
#   make test         # run all tests
#   make clean        # remove all build artifacts
# ──────────────────────────────────────────────────────────────────

SHELL   := /bin/bash
DIST    := dist
BIN     := $(DIST)/bin
EXT_OUT := $(DIST)/extension

# Detect host OS
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  PLATFORM := macos
else ifeq ($(UNAME_S),Linux)
  PLATFORM := linux
else
  PLATFORM := windows
endif

# ──────────────── default ────────────────
.PHONY: all
all: dist

# ──────────────── agent (Go) ────────────────
.PHONY: agent
agent: agent-release

.PHONY: agent-release
agent-release:
	@echo "==> Building Go agent (release)..."
	@mkdir -p $(BIN)/rules
	cd agent && go build -trimpath -ldflags "-s -w" -o ../$(BIN)/prompt-gate-agent ./cmd/agent
	@cp rules/*.txt rules/*.json $(BIN)/rules/ 2>/dev/null || true
	$(call write_config,$(BIN))

.PHONY: agent-debug
agent-debug:
	@echo "==> Building Go agent (debug)..."
	@mkdir -p $(BIN)/rules
	cd agent && go build -tags debug -o ../$(BIN)/prompt-gate-agent ./cmd/agent
	@cp rules/*.txt rules/*.json $(BIN)/rules/ 2>/dev/null || true
	$(call write_config,$(BIN))

# ──────────────── electron tray app ────────────────
.PHONY: electron-deps
electron-deps:
	@if [ ! -d electron/node_modules ]; then \
		echo "==> Installing Electron dependencies..."; \
		cd electron && npm ci; \
	fi

.PHONY: electron
electron: electron-deps
	@echo "==> Building & packaging Electron app..."
	cd electron && npm run package
	@mkdir -p $(BIN)
ifeq ($(PLATFORM),macos)
	@app=$$(find electron/release -maxdepth 2 -name "*.app" -not -path "*/Contents/*" -type d 2>/dev/null | head -1); \
	if [ -n "$$app" ]; then \
		cp -R "$$app" $(BIN)/PromptGate.app; \
		echo "==> Packaged: $(BIN)/PromptGate.app"; \
	else \
		echo "WARN: .app bundle not found in electron/release/"; \
	fi
else ifeq ($(PLATFORM),linux)
	@img=$$(find electron/release -name "*.AppImage" -type f 2>/dev/null | head -1); \
	if [ -n "$$img" ]; then \
		cp "$$img" $(BIN)/PromptGate.AppImage; \
		chmod +x $(BIN)/PromptGate.AppImage; \
		echo "==> Packaged: $(BIN)/PromptGate.AppImage"; \
	else \
		echo "WARN: AppImage not found in electron/release/"; \
	fi
endif

# ──────────────── browser extension ────────────────
.PHONY: extension-deps
extension-deps:
	@if [ ! -d extension/node_modules ]; then \
		echo "==> Installing extension dependencies..."; \
		cd extension && npm ci; \
	fi

.PHONY: extension
extension: extension-deps
	@echo "==> Building browser extension..."
	cd extension && npm run build
	@mkdir -p $(EXT_OUT)
	cp -R extension/dist/* $(EXT_OUT)/
	cp extension/manifest.json $(EXT_OUT)/

# ──────────────── dist (dev layout) ────────────────
.PHONY: dist
dist: agent electron extension
	@echo ""
	@echo "==> Dev distribution assembled in $(DIST)/"

# ──────────────── helper: write config.yaml ────────
define write_config
	@printf '%s\n' \
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
	  > $(1)/config.yaml
endef

# ──────────────── make macos ────────────────
# Builds a single .dmg with drag-to-Applications. The Go agent binary
# + rules are staged into electron/resources/{bin,rules} so
# electron-builder's extraResources picks them up automatically.
# The managed-agent lifecycle in main.ts generates config.yaml at
# runtime (~/.prompt-gate/agent-managed.yaml), so we do NOT ship a
# static config — only the binary and rule files.
VERSION    ?= 1.0.0
RES_BIN    := electron/resources/bin
RES_RULES  := electron/resources/rules
.PHONY: macos
macos: electron-deps
	@echo "==> [1/3] Building Go agent + proxy-helper (release)..."
	@mkdir -p $(RES_BIN) $(RES_RULES)
	cd agent && go build -trimpath -ldflags "-s -w" -o ../$(RES_BIN)/prompt-gate-agent ./cmd/agent
	cd agent && go build -trimpath -ldflags "-s -w" -o ../$(RES_BIN)/prompt-gate-proxy-helper ./cmd/proxy-helper
	@cp rules/*.txt rules/*.json $(RES_RULES)/ 2>/dev/null || true
	@echo "==> [2/3] Building Electron renderer + main..."
	cd electron && npm run build
	@echo "==> [3/3] Packaging macOS DMG..."
	cd electron && npx electron-builder --mac --publish never
	@touch electron/release/.metadata_never_index
	@mkdir -p $(DIST)
	@cp electron/release/*.dmg $(DIST)/ 2>/dev/null || true
	@echo ""
	@echo "==> Done! Output in $(DIST)/:"
	@ls -lh $(DIST)/*.dmg 2>/dev/null || echo "    (no .dmg found — check output above)"

# ──────────────── make win / make windows ────────────────
# Build an NSIS installer for Windows. Works natively on Windows
# (Git Bash / WSL) or cross-compiles from macOS / Linux.
# The installer creates a desktop shortcut + Start Menu entry and
# launches the app after install. Double-click the .exe → done.
.PHONY: win windows
win: windows
windows: electron-deps
	@echo "==> [1/3] Building Go agent for Windows..."
	@mkdir -p $(RES_BIN) $(RES_RULES)
ifeq ($(PLATFORM),windows)
	cd agent && go build -trimpath -ldflags "-s -w" -o ../$(RES_BIN)/prompt-gate-agent.exe ./cmd/agent
else
	cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../$(RES_BIN)/prompt-gate-agent.exe ./cmd/agent
endif
	@cp rules/*.txt rules/*.json $(RES_RULES)/ 2>/dev/null || true
	@echo "==> [2/3] Building Electron renderer + main..."
	cd electron && npm run build
	@echo "==> [3/3] Packaging Windows installer..."
	cd electron && npx electron-builder --win --x64 --publish never
	@mkdir -p $(DIST)
	@cp electron/release/*.exe $(DIST)/ 2>/dev/null || true
	@cp electron/release/*.zip $(DIST)/ 2>/dev/null || true
	@echo ""
	@echo "==> Done! Output in $(DIST)/:"
	@ls -lh $(DIST)/*.exe $(DIST)/*.zip 2>/dev/null || echo "    (no artifacts found — check output above)"

# ──────────────── make portable-win ────────────────
# Build a portable ZIP for Windows (full Electron UI + bundled agent
# + rules). No installer — just unzip and double-click "Prompt Gate.exe".
# Cross-compiles from macOS / Linux.
.PHONY: portable-win
portable-win: electron-deps
	@echo "==> [1/3] Cross-compiling Go agent for Windows amd64..."
	@mkdir -p $(RES_BIN) $(RES_RULES)
ifeq ($(PLATFORM),windows)
	cd agent && go build -trimpath -ldflags "-s -w" -o ../$(RES_BIN)/prompt-gate-agent.exe ./cmd/agent
else
	cd agent && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ../$(RES_BIN)/prompt-gate-agent.exe ./cmd/agent
endif
	@cp rules/*.txt rules/*.json $(RES_RULES)/ 2>/dev/null || true
	@echo "==> [2/3] Building Electron renderer + main..."
	cd electron && npm run build
	@echo "==> [3/3] Packaging portable ZIP (electron-builder --win zip)..."
	cd electron && npx electron-builder --win zip --x64 --publish never
	@mkdir -p $(DIST)
	@cp electron/release/*.zip $(DIST)/ 2>/dev/null || true
	@echo ""
	@echo "==> Done! Output in $(DIST)/:"
	@ls -lh $(DIST)/*.zip 2>/dev/null || echo "    (no .zip found — check output above)"

# ──────────────── make linux ────────────────
# Produces a .deb on Linux (dpkg-deb) or a .tar.gz fallback on macOS.
DEB_NAME  := prompt-gate_$(VERSION)_amd64.deb
TAR_NAME  := prompt-gate-$(VERSION)-linux-amd64.tar.gz
LINUX_STG := $(DIST)/_linux
.PHONY: linux
linux: agent
	@echo "==> Assembling Linux package ..."
	@rm -rf $(LINUX_STG)
	@# -- binary
	@mkdir -p $(LINUX_STG)/usr/bin
	cp $(BIN)/prompt-gate-agent $(LINUX_STG)/usr/bin/
	@# -- config
	@mkdir -p $(LINUX_STG)/etc/prompt-gate/rules
	$(call write_config,$(LINUX_STG)/etc/prompt-gate)
	cp rules/*.txt rules/*.json $(LINUX_STG)/etc/prompt-gate/rules/
	@# -- helper scripts
	@mkdir -p $(LINUX_STG)/usr/share/prompt-gate
	cp scripts/linux/*.sh $(LINUX_STG)/usr/share/prompt-gate/
	chmod +x $(LINUX_STG)/usr/share/prompt-gate/*.sh
	cp README-dist.txt $(LINUX_STG)/usr/share/prompt-gate/README.txt
	@# -- systemd unit
	@mkdir -p $(LINUX_STG)/lib/systemd/system
	cp scripts/linux/prompt-gate.service $(LINUX_STG)/lib/systemd/system/
	@# -- build .deb or fall back to .tar.gz
	@if command -v dpkg-deb >/dev/null 2>&1; then \
		mkdir -p $(LINUX_STG)/DEBIAN; \
		printf '%s\n' \
		  'Package: prompt-gate' \
		  'Version: $(VERSION)' \
		  'Architecture: amd64' \
		  'Maintainer: Prompt Gate maintainers <288552490+brianalle@users.noreply.github.com>' \
		  'Description: Prompt Gate DNS + DLP agent with local MITM proxy' \
		  ' DNS-level filtering, DLP scanning, and HTTPS inspection agent' \
		  ' for enterprise AI-tool governance.' \
		  'Section: net' \
		  'Priority: optional' \
		  > $(LINUX_STG)/DEBIAN/control; \
		cp scripts/linux/postinstall.sh $(LINUX_STG)/DEBIAN/postinst; \
		chmod 0755 $(LINUX_STG)/DEBIAN/postinst; \
		dpkg-deb --build --root-owner-group $(LINUX_STG) $(DIST)/$(DEB_NAME); \
		echo ""; \
		echo "==> $(DIST)/$(DEB_NAME) ready!"; \
		echo "    Install: sudo dpkg -i $(DIST)/$(DEB_NAME)"; \
	else \
		echo "==> dpkg-deb not found, creating .tar.gz instead ..."; \
		tar -czf $(DIST)/$(TAR_NAME) -C $(LINUX_STG) .; \
		echo ""; \
		echo "==> $(DIST)/$(TAR_NAME) ready!"; \
		echo "    Extract: sudo tar -xzf $(TAR_NAME) -C /"; \
		echo "    Then run: sudo scripts/linux/postinstall.sh"; \
	fi
	@rm -rf $(LINUX_STG) $(BIN)

# ──────────────── test ────────────────
.PHONY: test
test: test-agent test-extension

.PHONY: test-agent
test-agent:
	@echo "==> Running agent tests..."
	cd agent && go test -race ./...

.PHONY: test-extension
test-extension: extension-deps
	@echo "==> Running extension tests..."
	cd extension && npm test

# ──────────────── clean ────────────────
.PHONY: clean
clean:
	@echo "==> Cleaning..."
	rm -rf $(DIST) agent-bin
	cd agent && rm -f prompt-gate-agent
	cd electron && rm -rf dist release resources/bin resources/rules
	cd extension && rm -rf dist dist-firefox dist-safari
