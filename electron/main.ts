// Prompt Gate — Electron main process.
//
// Responsibilities:
//   * Create the system tray on app ready (no visible window on startup).
//   * Provide a tray context menu (Status / Open Settings / Quit).
//   * Create a BrowserWindow on-demand and DESTROY it on close to free
//     Chromium memory (per ARCHITECTURE.md).
//   * Poll the Go agent's /api/status endpoint every 10s and reflect the
//     reachability state in the tray icon and tray tooltip.

import { app, BrowserWindow, Menu, Tray, dialog, nativeImage, ipcMain, session, shell, Notification } from 'electron';
import { spawn, execSync, ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as os from 'os';

import { autoUpdater } from 'electron-updater';

const AGENT_PORT = Number(process.env.SECURE_EDGE_AGENT_PORT ?? 9191);
const AGENT_HOST = process.env.SECURE_EDGE_AGENT_HOST ?? '127.0.0.1';
// The MITM proxy listen port. Must match proxy_listen in writeManagedConfig.
// A stale prompt-gate-agent left holding this port makes POST
// /api/proxy/enable fail with 409 "address already in use"; clearStaleProxy
// frees it so the toggle can retry.
const PROXY_PORT = Number(process.env.SECURE_EDGE_PROXY_PORT ?? 8443);
const HEALTH_INTERVAL_MS = 10_000;

// Old agentBinDir / spawnAgent / killAgent removed — replaced by the
// managed agent lifecycle below (startManagedAgent / stopManagedAgent).

type View = 'status' | 'settings' | 'proxy';

let tray: Tray | null = null;
let window: BrowserWindow | null = null;
let agentProcess: ChildProcess | null = null;
let healthTimer: NodeJS.Timeout | null = null;
let eventSource: ReturnType<typeof connectEventStream> | null = null;
type TrayState = 'error' | 'off' | 'on';
let lastTrayState: TrayState | null = null;
let updateAvailable = false;
let proxyRunning: boolean | null = null;
let lastTamperDetections: number | null = null;
// Agent supervision. agentStopping is set while we deliberately stop the
// agent (quit / restart) so the exit handler doesn't treat it as a crash.
// The crash-window fields back off respawns so a binary that crashes on
// startup can't spin in a tight loop.
let agentStopping = false;
let restarting = false;
let recentCrashes: number[] = []; // timestamps (ms) of unexpected exits
const CRASH_WINDOW_MS = 60_000;
const CRASH_BURST_LIMIT = 5;

function rendererPath(): string {
  // In production main.ts is compiled to dist/main.js and the renderer
  // is at dist/renderer/index.html relative to it.
  return path.join(__dirname, 'renderer', 'index.html');
}

// Tray icon file names for 3 states:
//   error → agent unreachable (red exclamation badge)
//   off   → agent OK, proxy OFF (white checkmark badge)
//   on    → agent OK, proxy ON (green checkmark badge)
const TRAY_ICON_FILE: Record<TrayState, string> = {
  error: 'tray-icon-error.png',
  off:   'tray-icon.png',
  on:    'tray-icon-on.png',
};

function trayIconPath(state: TrayState): string {
  const name = TRAY_ICON_FILE[state];
  const res = process.resourcesPath ?? '';
  // Order matters: the asarUnpacked path MUST come first. Electron's
  // patched fs.existsSync can see files inside app.asar, but native
  // code (nativeImage / macOS Tray) cannot read them — only real
  // filesystem paths work.  asarUnpack in electron-builder.yml extracts
  // tray-*.png into app.asar.unpacked/resources/.
  const candidates = [
    path.join(res, 'app.asar.unpacked', 'resources', name),
    path.join(__dirname, '..', 'resources', name),               // dev mode
  ];
  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return candidates[0];
}

function buildTrayImage(state: TrayState) {
  const img = nativeImage.createFromPath(trayIconPath(state));
  if (img.isEmpty()) {
    // Tiny fallback so the tray still shows *something* during dev.
    return nativeImage.createFromDataURL(
      'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAPklEQVQ4T2P8z8BQz0BAwMjAwPCfgYGBkRACGBkZQWrBaiDqwGIY/jMwgDQxEjIErAakBuwORDcAbBKxfgAAbQ4YEX/IORAAAAAASUVORK5CYII=',
    );
  }
  return img;
}

function showView(view: View) {
  if (!window) {
    window = new BrowserWindow({
      width: 460,
      height: 640,
      show: false,
      resizable: true,
      title: 'Prompt Gate',
      webPreferences: {
        preload: path.join(__dirname, 'preload.js'),
        contextIsolation: true,
        nodeIntegration: false,
      },
    });
    window.removeMenu();
    window.on('close', () => {
      // Destroy the window so Chromium fully releases its memory.
      window?.destroy();
      window = null;
    });

    window.once('ready-to-show', () => window?.show());

    const devURL = process.env.VITE_DEV_SERVER_URL;
    if (devURL) {
      window.loadURL(`${devURL}#${view}`);
    } else {
      window.loadFile(rendererPath(), { hash: view });
    }
  } else {
    window.webContents.send('navigate', view);
    if (!window.isVisible()) window.show();
    window.focus();
  }
}

function buildMenu(): Menu {
  // Render a non-clickable status line for the proxy. "unknown" means
  // the /api/proxy/status poll has not returned yet (older agents
  // return 503, in which case we display "unavailable").
  let proxyLabel = 'Proxy: …';
  if (proxyRunning === true) proxyLabel = 'Proxy: Active';
  else if (proxyRunning === false) proxyLabel = 'Proxy: Inactive';

  const template: Electron.MenuItemConstructorOptions[] = [
    { label: 'Status', click: () => showView('status') },
    { label: 'Open Settings', click: () => showView('settings') },
    { label: 'Advanced DLP (Proxy)', click: () => showView('proxy') },
    { type: 'separator' },
    { label: proxyLabel, enabled: false },
  ];
  if (updateAvailable) {
    template.push({ type: 'separator' });
    template.push({
      label: 'Update available — install and restart',
      click: () => autoUpdater.quitAndInstall(),
    });
  }
  template.push({ type: 'separator' });
  template.push({ label: 'Quit', role: 'quit' });
  return Menu.buildFromTemplate(template);
}

function refreshTrayMenu(): void {
  tray?.setContextMenu(buildMenu());
}

const TRAY_TOOLTIP: Record<TrayState, string> = {
  error: 'Prompt Gate: agent unreachable',
  off:   'Prompt Gate: proxy off',
  on:    'Prompt Gate: protected',
};

function updateTrayIcon(state: TrayState) {
  if (!tray) return;
  if (state === lastTrayState) return;
  lastTrayState = state;
  tray.setImage(buildTrayImage(state));
  tray.setToolTip(TRAY_TOOLTIP[state]);
}

function pingAgent(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/status',
        method: 'GET',
        timeout: 2000,
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

// pingProxy returns true when the agent reports the local MITM proxy
// as running AND the system proxy is actively routing traffic through it.
// Tray icon should only be green when both conditions are met.
function pingProxy(): Promise<boolean> {
  return new Promise((resolve) => {
    // 1. Check proxy listener is running.
    const req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/proxy/status',
        method: 'GET',
        timeout: 2000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(false);
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body) as { running?: boolean };
            if (parsed.running !== true) {
              resolve(false);
              return;
            }
            // 2. Also check system proxy is active.
            const req2 = http.request(
              { host: AGENT_HOST, port: AGENT_PORT, path: '/api/system/proxy', method: 'GET', timeout: 2000 },
              (res2) => {
                if (res2.statusCode !== 200) { res2.resume(); resolve(false); return; }
                let b2 = '';
                res2.setEncoding('utf8');
                res2.on('data', (c: string) => { b2 += c; });
                res2.on('end', () => {
                  try {
                    const p2 = JSON.parse(b2) as { active?: boolean };
                    resolve(p2.active === true);
                  } catch { resolve(false); }
                });
              },
            );
            req2.on('error', () => resolve(false));
            req2.on('timeout', () => { req2.destroy(); resolve(false); });
            req2.end();
          } catch {
            resolve(false);
          }
        });
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

// pingTamper returns the tamper detector's running count, or null
// when the endpoint is unavailable (older agents return 503).
function pingTamper(): Promise<number | null> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/tamper/status',
        method: 'GET',
        timeout: 2000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => {
          body += chunk;
        });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body) as { detections_total?: number };
            resolve(typeof parsed.detections_total === 'number' ? parsed.detections_total : null);
          } catch {
            resolve(null);
          }
        });
      },
    );
    req.on('error', () => resolve(null));
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.end();
  });
}

async function tickHealth() {
  const [ok, proxyOk, tamper] = await Promise.all([pingAgent(), pingProxy(), pingTamper()]);
  updateTrayIcon(ok ? (proxyOk ? 'on' : 'off') : 'error');
  // Recovery net: the agent is unreachable and we hold no live child
  // handle (its exit fired without us, or we attached to an external
  // agent that has since died). Bring it back. The exit-handler path
  // covers the common crash; this covers the rest. `restarting` guards
  // against double-spawns.
  if (!ok && !agentProcess && !agentStopping && !restarting) {
    console.error('health: agent unreachable with no live process — restarting');
    void restartManagedAgent();
  }
  if (proxyOk !== proxyRunning) {
    proxyRunning = proxyOk;
    refreshTrayMenu();
  }
  if (tamper !== null) {
    if (lastTamperDetections !== null && tamper > lastTamperDetections) {
      // Surface an ephemeral notification — no persistent log of the
      // event, per the privacy invariant. The tray tooltip already
      // reflects the elevated detections count via the menu.
      tray?.displayBalloon?.({
        title: 'Prompt Gate',
        content: 'Possible tamper detected — DNS or proxy configuration changed',
      });
    }
    lastTamperDetections = tamper;
  }
}

function startHealthPolling() {
  if (healthTimer) return;
  void tickHealth();
  healthTimer = setInterval(() => void tickHealth(), HEALTH_INTERVAL_MS);
}

function stopHealthPolling() {
  if (!healthTimer) return;
  clearInterval(healthTimer);
  healthTimer = null;
}

// ──────────────── SSE event stream from agent ────────────────
// The agent pushes real-time events (DLP blocks, etc.) via SSE at
// /api/events. We subscribe from the main process and show native
// desktop notifications + forward to the renderer for in-app toasts.

interface AgentEvent {
  type: string;
  title: string;
  body: string;
  pattern_name?: string;
  host?: string;
  faq_url?: string;
  timestamp: string;
}

function connectEventStream(): { destroy: () => void } {
  let destroyed = false;
  let req: http.ClientRequest | null = null;
  let reconnectTimer: NodeJS.Timeout | null = null;

  function connect() {
    if (destroyed) return;
    req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/events',
        method: 'GET',
        headers: { Accept: 'text/event-stream' },
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          scheduleReconnect();
          return;
        }
        res.setEncoding('utf8');
        let buffer = '';
        res.on('data', (chunk: string) => {
          buffer += chunk;
          // SSE events are delimited by double newlines.
          const parts = buffer.split('\n\n');
          buffer = parts.pop() ?? '';
          for (const part of parts) {
            if (part.startsWith('data: ')) {
              try {
                const evt = JSON.parse(part.slice(6)) as AgentEvent;
                handleAgentEvent(evt);
              } catch {
                // Malformed event — skip.
              }
            }
          }
        });
        res.on('end', () => scheduleReconnect());
        res.on('error', () => scheduleReconnect());
      },
    );
    req.on('error', () => scheduleReconnect());
    req.on('timeout', () => {
      req?.destroy();
      scheduleReconnect();
    });
    req.end();
  }

  function scheduleReconnect() {
    if (destroyed) return;
    reconnectTimer = setTimeout(connect, 3000);
  }

  connect();

  return {
    destroy() {
      destroyed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      req?.destroy();
    },
  };
}

// Rate-limit notifications so a site that triggers many blocks
// (e.g. Gemini background requests) doesn't flood the UI.
const NOTIF_COOLDOWN_MS = 10_000; // suppress duplicates for 10 s
const recentNotifs = new Map<string, number>(); // key → timestamp

function notifKey(evt: AgentEvent): string {
  return `${evt.type}|${evt.host ?? ''}|${evt.pattern_name ?? ''}`;
}

function handleAgentEvent(evt: AgentEvent) {
  const key = notifKey(evt);
  const now = Date.now();
  const last = recentNotifs.get(key);
  if (last && now - last < NOTIF_COOLDOWN_MS) return; // deduplicate
  recentNotifs.set(key, now);

  // Evict stale entries periodically so the map doesn't grow unbounded.
  if (recentNotifs.size > 200) {
    for (const [k, ts] of recentNotifs) {
      if (now - ts > NOTIF_COOLDOWN_MS) recentNotifs.delete(k);
    }
  }

  // 1. Native macOS / Windows system notification.
  if (Notification.isSupported()) {
    const iconPath = trayIconPath('on');
    const notif = new Notification({
      title: evt.title,
      body: evt.body,
      silent: false,
      icon: fs.existsSync(iconPath) ? iconPath : undefined,
    });
    // A blocked user clicking the notification lands on the SN360 FAQ
    // (best-practice guidance, e.g. mask keys with [PLACEHOLDER]); fall
    // back to the in-app Status view when no link is attached.
    notif.on('click', () => {
      if (evt.faq_url) {
        void shell.openExternal(evt.faq_url);
      } else {
        showView('status');
      }
    });
    notif.show();
  }

  // 2. Forward to renderer (if window is open) for in-app toast.
  if (window && !window.isDestroyed()) {
    window.webContents.send('prompt-gate:event', evt);
  }
}

function connectAgentEvents() {
  if (eventSource) return;
  eventSource = connectEventStream();
}

function disconnectEventStream() {
  eventSource?.destroy();
  eventSource = null;
}

// Ensure Electron bypasses the system proxy for localhost connections.
// Without this, turning on the system proxy (127.0.0.1:8443) would route
// the agent API calls through the MITM proxy and break connectivity.
app.commandLine.appendSwitch('proxy-bypass-list', '127.0.0.1,localhost');

// Set the app user model id so macOS notification center shows
// "Prompt Gate" instead of "Electron" for system notifications.
app.setName('Prompt Gate');
if (process.platform === 'win32') {
  app.setAppUserModelId('com.shieldnet360.promptgate');
}

// ──────────────────────────────────────────────────────────────────
// Managed agent lifecycle.
//
// For a one-click experience the tray app starts (and stops) its own
// Go agent — the user never runs a separate process. If an agent is
// already serving on the API port (e.g. a system daemon), we attach to
// it instead of spawning a duplicate.
// ──────────────────────────────────────────────────────────────────

// Locate the bundled (production) or repo (dev) agent binary.
function agentBinaryPath(): string | null {
  const name = process.platform === 'win32' ? 'prompt-gate-agent.exe' : 'prompt-gate-agent';
  const res = process.resourcesPath ?? '';
  const candidates = [
    path.join(res, 'app.asar.unpacked', 'resources', 'bin', name), // packaged (asarUnpack)
    path.join(res, 'resources', 'bin', name),
    path.join(res, 'bin', name),
    path.join(__dirname, '..', 'resources', 'bin', name),          // dev: electron/resources/bin
    path.join(__dirname, '..', '..', 'dist', 'bin', name),         // repo dist/bin
    path.join(__dirname, '..', '..', 'agent', name),               // repo agent/<bin>
  ];
  return candidates.find((p) => p && fs.existsSync(p)) ?? null;
}

// Locate the bundled/repo rules directory (must contain dlp_patterns.json
// — that file is what wires the proxy controller in the agent).
function rulesDirPath(): string | null {
  const res = process.resourcesPath ?? '';
  const candidates = [
    path.join(res, 'app.asar.unpacked', 'resources', 'rules'),
    path.join(res, 'resources', 'rules'),
    path.join(__dirname, '..', 'resources', 'rules'),
    path.join(__dirname, '..', '..', 'rules'),
  ];
  return candidates.find((p) => p && fs.existsSync(path.join(p, 'dlp_patterns.json'))) ?? null;
}

// Write a managed config. DNS listens on a high port so the spawned
// agent never needs root (the proxy/DLP path the tray uses doesn't
// require :53). proxy_enabled stays false — the user's toggle turns it on.
function writeManagedConfig(rulesDir: string): string {
  const dir = path.join(os.homedir(), '.prompt-gate');
  fs.mkdirSync(dir, { recursive: true });
  const cfgPath = path.join(dir, 'agent-managed.yaml');
  const q = (p: string) => JSON.stringify(p); // YAML-safe double-quoted scalar
  const ruleFiles = ['ai_chat_blocked.txt', 'ai_code_blocked.txt', 'ai_chat_dlp.txt', 'ai_allowed.txt', 'phishing.txt', 'social.txt']
    .map((f) => path.join(rulesDir, f))
    .filter((p) => fs.existsSync(p));
  const lines = [
    '# Generated by Prompt Gate tray — managed agent instance.',
    'dns_listen: "127.0.0.1:15353"',
    `api_listen: "${AGENT_HOST}:${AGENT_PORT}"`,
    'proxy_listen: "127.0.0.1:8443"',
    `db_path: ${q(path.join(dir, 'prompt-gate.db'))}`,
    'rule_paths:',
    ...ruleFiles.map((p) => `  - ${q(p)}`),
    `dlp_patterns: ${q(path.join(rulesDir, 'dlp_patterns.json'))}`,
    `dlp_exclusions: ${q(path.join(rulesDir, 'dlp_exclusions.json'))}`,
    'proxy_enabled: false',
    '',
  ];
  fs.writeFileSync(cfgPath, lines.join('\n'), { mode: 0o600 });
  return cfgPath;
}

// Resolve true if anything is already answering on the agent API port.
function agentReachable(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      { host: AGENT_HOST, port: AGENT_PORT, path: '/api/proxy/status', method: 'GET', timeout: 1500 },
      (res) => { res.resume(); resolve((res.statusCode ?? 0) > 0); },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

// Resolve true only when the agent answering on the port has the DLP
// proxy actually wired (proxy_configured). A stale or dev agent started
// without dlp_patterns answers on the port but reports
// proxy_configured:false — attaching to it leaves the toggle dead, which
// is the "nothing happens when I click" failure. We use this (not bare
// reachability) to decide whether the running agent is healthy.
function agentConfigured(): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.request(
      { host: AGENT_HOST, port: AGENT_PORT, path: '/api/proxy/status', method: 'GET', timeout: 1500 },
      (res) => {
        if (res.statusCode !== 200) { res.resume(); resolve(false); return; }
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => { body += c; });
        res.on('end', () => {
          try {
            const j = JSON.parse(body) as { proxy_configured?: boolean };
            resolve(j.proxy_configured === true);
          } catch { resolve(false); }
        });
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });
}

// Kill any prompt-gate-agent process holding the API port. Used when a
// stale/misconfigured instance (crashed prior run, leftover dev build)
// occupies the port — we must clear it before our managed agent can bind.
// Only kills processes whose command line is a prompt-gate-agent, never
// arbitrary port owners. POSIX only; best-effort.
function killStaleAgents(): void {
  killStaleAgentsOnPort(AGENT_PORT);
}

// Kill any prompt-gate-agent listening on `port`, except `exceptPid` (our
// own managed agent). Used to free the API port (stale instance) and the
// proxy port (a leftover agent still holding 8443 → enable returns 409).
function killStaleAgentsOnPort(port: number, exceptPid?: number): void {
  if (process.platform === 'win32') return;
  try {
    const pids = execSync(`lsof -ti tcp:${port} -sTCP:LISTEN`, {
      stdio: ['ignore', 'pipe', 'ignore'],
    }).toString().trim();
    for (const pid of pids.split('\n')) {
      const p = pid.trim();
      if (!p) continue;
      if (exceptPid && Number(p) === exceptPid) continue;
      let cmd = '';
      try {
        cmd = execSync(`ps -p ${p} -o command=`, { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      } catch { /* process gone */ }
      if (cmd.includes('prompt-gate-agent')) {
        try {
          process.kill(Number(p), 'SIGTERM');
        } catch (err: any) {
          // EPERM → process is owned by root; ask for admin permission.
          if (err?.code === 'EPERM' && process.platform === 'darwin') {
            try {
              execSync(
                `osascript -e 'do shell script "kill ${p}" with administrator privileges'`,
                { stdio: 'ignore' },
              );
            } catch { /* user cancelled the prompt or process already gone */ }
          }
        }
      }
    }
  } catch { /* nothing listening on the port */ }
}

// Ensure ~/.prompt-gate exists and is writable by the current user. A
// leftover folder owned by root (e.g. from a prior `sudo` run) makes the
// agent exit at launch with "permission denied" — the agent never starts,
// the toggle is dead. Returns true when usable. When not, the caller
// repairs ownership.
function configDirWritable(): { ok: boolean; dir: string } {
  const dir = path.join(os.homedir(), '.prompt-gate');
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.accessSync(dir, fs.constants.W_OK);
    return { ok: true, dir };
  } catch {
    return { ok: false, dir };
  }
}

// Repair a root-owned config dir by chowning it back to the user. One
// clear admin prompt; only triggered in the rare leftover-permissions
// case, never on a clean install.
function repairConfigDirPermissions(dir: string): Promise<void> {
  if (process.platform === 'win32') return Promise.resolve();
  const user = os.userInfo().username;
  const script =
    `do shell script "chown -R ${user} '${dir}' && chmod -R u+rwX '${dir}'" ` +
    `with administrator privileges`;
  return new Promise((resolve) => {
    try {
      const p = spawn('osascript', ['-e', script], { stdio: 'ignore' });
      p.on('exit', () => resolve());
      p.on('error', () => resolve());
    } catch { resolve(); }
  });
}

// Start the bundled agent and guarantee it comes up healthy. Self-heals
// the two failure modes that otherwise leave the toggle dead:
//   1. a stale/misconfigured agent already holding the port,
//   2. a broken ~/.prompt-gate (root-owned) the agent can't write.
// Best-effort: on failure the tray simply shows the unreachable state.
async function startManagedAgent(): Promise<void> {
  // A properly-configured agent is already serving → attach to it.
  if (await agentConfigured()) return;

  // Something may be answering but misconfigured (no proxy wired). Clear
  // it so our managed agent can bind the port.
  if (await agentReachable()) {
    killStaleAgents();
    await new Promise<void>((r) => setTimeout(r, 500));
  }

  // Make sure the config dir is usable; repair root-owned leftovers.
  let { ok, dir } = configDirWritable();
  if (!ok) {
    await repairConfigDirPermissions(dir);
    ({ ok } = configDirWritable());
    if (!ok) {
      dialog.showErrorBox(
        'Prompt Gate could not start',
        `The settings folder ${dir} is not writable and could not be repaired.\n\n` +
        `Open Terminal and run:\n  sudo rm -rf ${dir}\n\nthen reopen Prompt Gate.`,
      );
      return;
    }
  }

  const bin = agentBinaryPath();
  const rulesDir = rulesDirPath();
  if (!bin || !rulesDir) {
    console.error('managed agent: could not locate binary or rules', { bin, rulesDir });
    return;
  }
  try {
    const cfg = writeManagedConfig(rulesDir);
    if (process.platform !== 'win32') {
      try { fs.chmodSync(bin, 0o755); } catch { /* may already be executable */ }
    }
    // macOS: remove quarantine attribute so Gatekeeper doesn't block the
    // unsigned agent binary copied from the DMG.
    if (process.platform === 'darwin') {
      try { execSync(`xattr -rd com.apple.quarantine "${path.dirname(bin)}"`, { stdio: 'ignore' }); } catch { /* best-effort */ }
    }
    agentStopping = false; // we are bringing it up; future exits are crashes
    agentProcess = spawn(bin, ['-config', cfg], { stdio: 'ignore', detached: false });
    agentProcess.on('exit', () => { agentProcess = null; onAgentExit(); });
    agentProcess.on('error', (err) => { console.error('managed agent spawn error:', err); agentProcess = null; onAgentExit(); });
  } catch (err) {
    console.error('managed agent: failed to start:', err);
    return;
  }

  // Wait until it reports a configured proxy, so the first toggle works.
  for (let i = 0; i < 20; i++) {
    if (await agentConfigured()) return;
    await new Promise<void>((r) => setTimeout(r, 300));
  }
  console.error('managed agent: did not become configured within timeout');
}

// onAgentExit handles an UNEXPECTED agent exit (a crash). It is the
// counterpart to the privileged helper's watchdog: the helper fails the
// network open within ~30s if we don't recover, while this respawns the
// agent so the app (and protection) come back on their own. We
// deliberately do NOT auto-re-enable the proxy after a crash — the
// respawned agent's startup reconcile restores connectivity (fail-open)
// and the user re-arms protection — so a crash-on-block bug can't loop
// the user between blackout and restart.
function onAgentExit(): void {
  if (agentStopping) return; // intentional stop (quit / restart teardown)

  const now = Date.now();
  recentCrashes = recentCrashes.filter((t) => now - t < CRASH_WINDOW_MS);
  recentCrashes.push(now);
  updateTrayIcon('error');

  if (recentCrashes.length > CRASH_BURST_LIMIT) {
    console.error(`managed agent crashed ${recentCrashes.length}x in ${CRASH_WINDOW_MS / 1000}s — backing off`);
    notifyAgentDown(true);
    return; // stop the loop; the helper watchdog still guarantees internet
  }

  console.error(`managed agent exited unexpectedly (crash #${recentCrashes.length}) — restarting`);
  notifyAgentDown(false);
  // Backoff grows with consecutive crashes (1s, 2s, 3s …, capped).
  const delay = Math.min(recentCrashes.length * 1000, 5000);
  setTimeout(() => { void restartManagedAgent(); }, delay);
}

// restartManagedAgent brings the agent back up after a crash (or on
// demand). Guarded by `restarting` so overlapping triggers (exit handler
// + health poll) don't spawn duplicates.
async function restartManagedAgent(): Promise<void> {
  if (restarting) return;
  if (agentProcess) return; // already running again
  restarting = true;
  try {
    await startManagedAgent();
  } finally {
    restarting = false;
  }
}

// notifyAgentDown surfaces a clear, actionable message. `fatal` means we
// stopped auto-restarting after a crash burst.
function notifyAgentDown(fatal: boolean): void {
  const body = fatal
    ? 'Prompt Gate stopped after repeated crashes. Your internet is restored (protection is OFF). Reopen the app to try again.'
    : 'Prompt Gate is restarting after an unexpected stop. Your internet is unaffected.';
  if (Notification.isSupported()) {
    new Notification({ title: 'Prompt Gate', body, silent: true }).show();
  }
  if (window && !window.isDestroyed()) {
    window.webContents.send('prompt-gate:event', {
      type: 'agent_down',
      title: 'Prompt Gate',
      body,
      timestamp: new Date().toISOString(),
    });
  }
}

// ensureHelperInstalled waits for the agent to be ready (it was just spawned),
// then asks it to install the privileged proxy-helper daemon if not already
// present. macOS only — one admin prompt, then zero prompts forever.
async function ensureHelperInstalled(): Promise<void> {
  if (process.platform !== 'darwin') return;

  // Wait up to 6 s for the agent to respond.
  for (let i = 0; i < 12; i++) {
    if (await agentReachable()) break;
    await new Promise<void>((r) => setTimeout(r, 500));
  }
  if (!(await agentReachable())) return;

  let token: string | null = null;
  try {
    token = fs.readFileSync(path.join(os.homedir(), '.prompt-gate', 'api-token'), 'utf-8').trim();
  } catch { /* no token yet */ }

  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = `Bearer ${token}`;

  // Check current status.
  const statusOk = await new Promise<boolean>((resolve) => {
    const req = http.request(
      { host: AGENT_HOST, port: AGENT_PORT, path: '/api/system/helper', method: 'GET', timeout: 2000, headers },
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (c: string) => { body += c; });
        res.on('end', () => {
          try {
            const j = JSON.parse(body) as { installed?: boolean; running?: boolean };
            resolve(j.installed === true && j.running === true);
          } catch { resolve(false); }
        });
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.end();
  });

  if (statusOk) return; // already installed and running

  // Trigger install — user sees exactly one admin prompt.
  await new Promise<void>((resolve) => {
    const body = '';
    const req = http.request(
      { host: AGENT_HOST, port: AGENT_PORT, path: '/api/system/helper', method: 'POST', timeout: 60000, headers },
      (res) => { res.resume(); resolve(); },
    );
    req.on('error', (err) => { console.error('helper install request error:', err); resolve(); });
    req.on('timeout', () => { req.destroy(); resolve(); });
    req.end(body);
  });
}

// Stop the agent we spawned (no-op if we attached to an external one).
function stopManagedAgent(): void {
  // Mark the stop as intentional so onAgentExit() doesn't treat it as a
  // crash and respawn the agent we just asked to quit.
  agentStopping = true;
  if (!agentProcess || agentProcess.killed) { agentProcess = null; return; }
  const pid = agentProcess.pid;
  try { agentProcess.kill('SIGTERM'); } catch { /* already gone */ }
  // Force-kill after 3 s if it hasn't exited.
  const timer = setTimeout(() => {
    if (agentProcess && !agentProcess.killed) {
      try { agentProcess.kill('SIGKILL'); } catch { /* already gone */ }
    }
  }, 3000);
  agentProcess.once('exit', () => clearTimeout(timer));
  agentProcess = null;
}

// ── Single-instance lock ──
// Only one Prompt Gate instance may run at a time. A second instance
// would fight over the agent API port, system proxy settings, and DNS
// configuration. If the lock is already held, focus the existing
// window and quit this duplicate process.
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.on('second-instance', () => {
    // A second instance was launched — bring the existing window to front.
    if (window) {
      if (window.isMinimized()) window.restore();
      window.focus();
    } else {
      showView('status');
    }
  });
}

app.whenReady().then(async () => {
  // Show the app in the Dock so users on notched MacBooks (where menu
  // bar space is limited) can click the Dock icon to open the UI.
  // The tray icon still appears in the menu bar for quick status.
  if (process.platform === 'darwin' && app.dock) {
    const res = process.resourcesPath ?? '';
    const iconCandidates = [
      path.join(res, 'app.asar.unpacked', 'resources', 'icon.png'),
      path.join(__dirname, '..', 'resources', 'icon.png'),
    ];
    const dockIcon = iconCandidates.find((p) => fs.existsSync(p));
    if (dockIcon) {
      app.dock.setIcon(nativeImage.createFromPath(dockIcon));
    }
  }

  // Set session-level proxy config so renderer fetch() calls to the
  // agent bypass the system proxy even after the user turns it on.
  void session.defaultSession.setProxy({
    proxyBypassRules: '127.0.0.1,localhost',
  });

  // Register IPC handlers early — the renderer calls these as soon as
  // a window opens, which can happen before startManagedAgent finishes
  // (e.g. via Dock click during the up-to-6s agent startup wait).
  ipcMain.handle('prompt-gate:get-agent-base', () =>
    `http://${AGENT_HOST}:${AGENT_PORT}`,
  );

  ipcMain.handle('prompt-gate:get-agent-token', () => {
    try {
      const tokenPath = path.join(os.homedir(), '.prompt-gate', 'api-token');
      return fs.readFileSync(tokenPath, 'utf-8').trim();
    } catch {
      return null;
    }
  });

  // Free the proxy port from a stale prompt-gate-agent (not our own) so the
  // renderer can retry POST /api/proxy/enable after a 409 "address already
  // in use". Only kills prompt-gate-agent processes, never arbitrary owners.
  ipcMain.handle('prompt-gate:clear-stale-proxy', () => {
    killStaleAgentsOnPort(PROXY_PORT, agentProcess?.pid ?? undefined);
    return true;
  });

  // Open a URL in the user's default browser. Restricted to http(s) so a
  // crafted event can't launch arbitrary schemes (file://, etc.).
  ipcMain.handle('prompt-gate:open-external', (_e, url: unknown) => {
    if (typeof url === 'string' && /^https:\/\//i.test(url)) {
      void shell.openExternal(url);
    }
  });

  // Native file picker for importing an upstream CA bundle. The main
  // process reads the file and returns its PEM text so the renderer can
  // POST it to the agent — the agent never receives a filesystem path.
  ipcMain.handle('prompt-gate:pick-upstream-ca', async () => {
    const res = await dialog.showOpenDialog({
      title: 'Select your organization’s certificate',
      properties: ['openFile'],
      filters: [
        { name: 'Certificates', extensions: ['pem', 'crt', 'cer', 'ca-bundle'] },
        { name: 'All files', extensions: ['*'] },
      ],
    });
    if (res.canceled || res.filePaths.length === 0) {
      return null;
    }
    try {
      const pem = fs.readFileSync(res.filePaths[0], 'utf-8');
      return { name: path.basename(res.filePaths[0]), pem };
    } catch {
      return null;
    }
  });

  // ── Auto-start at login (macOS / Windows / Linux) ──
  // Renderer can query/toggle this via IPC. On first install we
  // default to ON so the user is protected from boot.
  ipcMain.handle('prompt-gate:get-open-at-login', () => {
    return app.getLoginItemSettings().openAtLogin;
  });

  ipcMain.handle('prompt-gate:set-open-at-login', (_e, enabled: unknown) => {
    const on = enabled === true;
    app.setLoginItemSettings({
      openAtLogin: on,
      openAsHidden: true,
    });
    return on;
  });

  // Default to ON in production builds so the user is protected from boot.
  if (app.isPackaged && !app.getLoginItemSettings().openAtLogin) {
    app.setLoginItemSettings({
      openAtLogin: true,
      openAsHidden: true,
    });
  }

  tray = new Tray(buildTrayImage('error'));
  tray.setToolTip('Prompt Gate');
  tray.setContextMenu(buildMenu());
  tray.on('click', () => showView('status'));

  // Bring up the agent. This can take up to 6s; the tray and IPC
  // handlers are already live so the UI is responsive during the wait.
  await startManagedAgent();

  // ── Safety net: restore system proxy to OFF on startup ──
  // If the app was force-killed or crashed while the proxy was active,
  // the system proxy still points at 127.0.0.1:8443 with nothing
  // listening — the user loses internet. Always restore on launch so
  // connectivity is guaranteed. The user can re-enable via the toggle.
  void restoreSystemProxy().then((ok) => {
    if (ok) console.log('startup: system proxy restored to OFF');
    proxyRunning = false;
    refreshTrayMenu();
  }).catch(() => { /* agent not reachable yet — no-op */ });

  // Install the privileged proxy-helper daemon in the background.
  void ensureHelperInstalled();

  startHealthPolling();
  connectAgentEvents();

  // electron-updater wiring. The auto-update feed URL comes from
  // electron-builder.yml's publish.github block. We surface availability
  // in the tray menu but never silently install — the user explicitly
  // clicks "Update available" to apply. The "install and restart" menu
  // item only appears after `update-downloaded` fires, because
  // autoUpdater.quitAndInstall() requires the update file on disk;
  // `update-available` only signals that metadata was fetched.
  autoUpdater.autoDownload = true;
  autoUpdater.autoInstallOnAppQuit = false;
  autoUpdater.on('update-downloaded', () => {
    updateAvailable = true;
    refreshTrayMenu();
  });
  autoUpdater.on('error', (err) => {
    // Update failures are not fatal — log to stderr and continue.
    console.error('auto-update error:', err);
  });
  // Dev runs (no packaged app) cannot self-update; suppress the call.
  if (app.isPackaged) {
    void autoUpdater.checkForUpdatesAndNotify().catch((err) => {
      console.error('checkForUpdatesAndNotify failed:', err);
    });
  }
});

// Keep the tray (and main process) alive when the settings window closes.
// The standard Electron behaviour on macOS already does this; on other
// platforms we simply do nothing in the handler.
app.on('window-all-closed', () => {
  // intentional no-op: the tray/dock icon is the entrypoint to the app.
});

// macOS Dock click → open the status view.
app.on('activate', () => {
  showView('status');
});

// Tracks whether the user has already answered the "disable proxy on
// quit?" dialog. Without this guard the second `before-quit` (fired
// after we call app.quit() again) would loop the dialog.
let quitConfirmed = false;

// Restore the system proxy settings by calling the Go agent directly.
// Returns true on success. Best-effort: if the agent is already gone
// we still let the quit proceed because nothing the Electron process
// can do from here will further help.
function restoreSystemProxy(): Promise<boolean> {
  return new Promise((resolve) => {
    let token: string | null = null;
    try {
      token = fs
        .readFileSync(path.join(os.homedir(), '.prompt-gate', 'api-token'), 'utf-8')
        .trim();
    } catch {
      // No token file — try unauthenticated; older agents allow it on
      // loopback. Falls through.
    }
    const body = JSON.stringify({ action: 'restore' });
    const req = http.request(
      {
        host: AGENT_HOST,
        port: AGENT_PORT,
        path: '/api/system/proxy',
        method: 'POST',
        timeout: 4000,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(body),
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
      },
      (res) => {
        res.resume();
        resolve(res.statusCode === 200);
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.write(body);
    req.end();
  });
}

app.on('before-quit', (e) => {
  // First pass: if the proxy is active, intercept the quit, ask the
  // user what to do, then re-quit ourselves. Once the user has
  // answered (quitConfirmed = true) subsequent before-quit firings
  // fall through to the cleanup tail.
  if (!quitConfirmed && proxyRunning) {
    e.preventDefault();
    const choice = dialog.showMessageBoxSync({
      type: 'warning',
      title: 'Prompt Gate proxy is still active',
      message: 'The MITM proxy is still routing your system traffic.',
      detail:
        'If you quit without disabling it, your network settings will keep pointing at 127.0.0.1:8443. ' +
        'With the agent gone, every HTTPS request will fail — usually with no clear error, just a blank or hung page.\n\n' +
        '“Disable proxy and quit” restores your network settings first. ' +
        '“Quit anyway” leaves the proxy on; you can disable it later from System Settings → Network → Proxies, ' +
        'or by reopening Prompt Gate.',
      buttons: ['Disable proxy and quit', 'Quit anyway', 'Cancel'],
      defaultId: 0,
      cancelId: 2,
      noLink: true,
    });
    if (choice === 2) {
      // User cancelled — leave the app running.
      return;
    }
    quitConfirmed = true;
    if (choice === 0) {
      // Best-effort restore, then re-quit. Timeboxed by the request
      // timeout above so a stuck agent doesn't hang shutdown.
      void restoreSystemProxy().finally(() => {
        proxyRunning = false;
        app.quit();
      });
    } else {
      // Quit anyway — fire the quit immediately. The cleanup branch
      // below runs from the next before-quit event.
      app.quit();
    }
    return;
  }
  // Confirmed quit (or proxy was never running) — clean shutdown tail.
  // Always restore system proxy settings before killing the agent, so
  // macOS network config doesn't point at a dead localhost:8443.
  e.preventDefault();
  quitConfirmed = true;
  void restoreSystemProxy().finally(() => {
    stopHealthPolling();
    disconnectEventStream();
    stopManagedAgent();
    app.exit(0);
  });
});

// Safety net: ensure the spawned agent is stopped even on an
// unexpected exit path.
app.on('will-quit', stopManagedAgent);
