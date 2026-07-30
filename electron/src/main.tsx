import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { SetupIcon } from './components/SetupIcon';
import { ToastContainer, ToastMessage } from './components/Toast';
import { agent } from './api/agent';
import { ProxySettings } from './pages/ProxySettings';
import { Rules } from './pages/Rules';
import { Setup, isSetupPending } from './pages/Setup';
import './styles.css';

/* ── Menu icon (top-left hamburger) ── */
function MenuIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </svg>
  );
}

/* ── Filter icon (used in settings menu) ── */
function FilterIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <line x1="4" y1="6" x2="20" y2="6" />
      <line x1="8" y1="12" x2="16" y2="12" />
      <line x1="11" y1="18" x2="13" y2="18" />
    </svg>
  );
}

/* ── Info icon ── */
function InfoIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <line x1="12" y1="16" x2="12" y2="12" />
      <line x1="12" y1="8" x2="12.01" y2="8" />
    </svg>
  );
}

/* ── Book icon ── */
function BookIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M4 19.5A2.5 2.5 0 016.5 17H20" />
      <path d="M4 4.5A2.5 2.5 0 016.5 2H20v20H6.5A2.5 2.5 0 014 19.5v-15z" />
    </svg>
  );
}

/* ── Gear icon (top-right) ── */
function GearIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
    </svg>
  );
}

/* ── License icon ── */
function LicenseIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M9 12h6M9 16h6M13 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9l-7-7z" />
      <polyline points="13 2 13 9 20 9" />
    </svg>
  );
}

/* ── Dropdown menu from the hamburger icon ── */
function HamburgerMenu({ onAbout, onGuideline, onLicense }: {
  onAbout: () => void;
  onGuideline: () => void;
  onLicense: () => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button type="button" className="dash-icon-btn" aria-label="Menu" onClick={() => setOpen((v) => !v)}>
        <MenuIcon />
      </button>
      {open && (
        <div className="hamburger-dropdown">
          <button type="button" className="hamburger-item" onClick={() => { setOpen(false); onAbout(); }}>
            <InfoIcon />
            <span>About Us</span>
          </button>
          <button type="button" className="hamburger-item" onClick={() => { setOpen(false); onGuideline(); }}>
            <BookIcon />
            <span>Guideline</span>
          </button>
          <button type="button" className="hamburger-item" onClick={() => { setOpen(false); onLicense(); }}>
            <LicenseIcon />
            <span>License</span>
          </button>
        </div>
      )}
    </div>
  );
}

/* ── Dashboard page 0: protection toggle ── */
function DashTogglePage() {
  const [proxyRunning, setProxyRunning] = useState(false);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [ps, sp] = await Promise.all([
        agent.getProxyStatus().catch(() => null),
        agent.getSystemProxy().catch(() => null),
      ]);
      setProxyRunning((ps?.running && sp?.active) ?? false);
    } catch { /* agent offline */ }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 3000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggle = useCallback(async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (proxyRunning) {
        // ── Turn OFF ──
        await agent.setSystemProxy('restore').catch(() => {});
        await agent.disableProxy(false).catch(() => {});
        setProxyRunning(false);
      } else {
        // ── Turn ON: full setup flow ──
        // 1. Start the MITM listener if it isn't running (also generates CA key).
        let ps = await agent.getProxyStatus().catch(() => null);
        if (!ps?.running) {
          await agent.enableProxy();
          // Re-fetch status so we have the cert path and ca_installed flag.
          ps = await agent.getProxyStatus().catch(() => null);
        }

        // 2. Install CA to keychain with "Always Trust" if not already trusted.
        //    On macOS this triggers a one-time SecurityAgent dialog.
        const caPath = ps?.ca_cert_path;
        if (caPath && !ps?.ca_installed) {
          await agent.installSystemCA('install', caPath).catch(() => {});
        }

        // 3. Route traffic through the proxy (may trigger a second admin
        //    prompt when the privileged helper is not installed).
        await agent.setSystemProxy('apply');
        setProxyRunning(true);
      }
    } catch {
      await refresh();
    } finally {
      setBusy(false);
    }
  }, [busy, proxyRunning, refresh]);

  return (
    <div className="dash-toggle-page">
      <div className="dash-toggle-area">
        <button
          type="button"
          className={`dash-toggle ${proxyRunning ? 'on' : 'off'}`}
          aria-pressed={proxyRunning}
          aria-label={proxyRunning ? 'Disable Safe Browsing' : 'Enable Safe Browsing'}
          onClick={toggle}
          disabled={busy}
        >
          <span className="dash-toggle-track">
            <span className="dash-toggle-thumb" />
          </span>
        </button>
      </div>
      {proxyRunning && (
        <div className="dash-status-label">
          <span className="dash-status-dot" />
          Safe Browsing
        </div>
      )}
    </div>
  );
}

/* ── Dashboard page 1: protection overview (moved from Settings → General) ── */
function DashOverviewPage() {
  const [openAtLogin, setOpenAtLogin] = useState<boolean | null>(null);
  const [loginBusy, setLoginBusy] = useState(false);
  const [proxyOn, setProxyOn] = useState(false);
  const [stats, setStats] = useState<{ dns_blocks_total: number; dlp_scans_total: number; dlp_blocks_total: number; dns_queries_total: number } | null>(null);
  const [events, setEvents] = useState<Array<{ id: number; timestamp: string; host: string; pattern_name: string; event_type: string }>>([]);
  const [agentVer, setAgentVer] = useState<string | null>(null);
  const [resetting, setResetting] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [ps, sp, st, ev, status] = await Promise.all([
        agent.getProxyStatus().catch(() => null),
        agent.getSystemProxy().catch(() => null),
        agent.getStats().catch(() => null),
        agent.getBlockEvents(5).catch(() => []),
        agent.getStatus().catch(() => null),
      ]);
      setProxyOn((ps?.running && sp?.active) ?? false);
      if (st) setStats(st);
      setEvents(ev as Array<{ id: number; timestamp: string; host: string; pattern_name: string; event_type: string }>);
      if (status) setAgentVer(status.version);
    } catch { /* offline */ }
  }, []);

  useEffect(() => {
    void window.secureEdge?.getOpenAtLogin?.().then((v) => setOpenAtLogin(v));
    void refresh();
    const t = setInterval(() => void refresh(), 5000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggleLogin = useCallback(async () => {
    if (openAtLogin === null || loginBusy) return;
    setLoginBusy(true);
    try {
      const next = await window.secureEdge?.setOpenAtLogin?.(!openAtLogin);
      if (next !== undefined) setOpenAtLogin(next);
    } finally {
      setLoginBusy(false);
    }
  }, [openAtLogin, loginBusy]);

  const resetStats = useCallback(async () => {
    setResetting(true);
    try { await agent.resetStats(); await refresh(); } finally { setResetting(false); }
  }, [refresh]);

  function timeAgo(ts: string): string {
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return `${Math.floor(h / 24)}d ago`;
  }

  return (
    <div className="dash-inner-page">
      <div className={`ov-hero ${proxyOn ? 'on' : 'off'}`}>
        <div className={`ov-hero-status ${proxyOn ? 'on' : 'off'}`}>
          <span className="ov-hero-dot" />
          <span className="ov-hero-badge-text">{proxyOn ? 'Protection On' : 'Protection Off'}</span>
        </div>
        <SetupIcon size={44} />
        <div className="ov-hero-title">{proxyOn ? "You're protected" : 'Protection off'}</div>
        <div className="ov-hero-sub">
          {proxyOn
            ? 'Sensitive data is blocked before it leaves this device'
            : 'Swipe right to the toggle and enable the proxy'}
        </div>
      </div>

      <div className="ov-stats-grid">
        <div className="ov-stat">
          <div className="ov-stat-value">{stats?.dlp_scans_total?.toLocaleString() ?? '\u2014'}</div>
          <div className="ov-stat-label">Prompts scanned</div>
        </div>
        <div className="ov-stat">
          <div className="ov-stat-value">{stats?.dlp_blocks_total?.toLocaleString() ?? '\u2014'}</div>
          <div className="ov-stat-label">Secrets blocked</div>
        </div>
        <div className="ov-stat">
          <div className="ov-stat-value">{stats?.dns_blocks_total?.toLocaleString() ?? '\u2014'}</div>
          <div className="ov-stat-label">Sites blocked</div>
        </div>
        <div className="ov-stat">
          <div className="ov-stat-value">{stats?.dns_queries_total?.toLocaleString() ?? '\u2014'}</div>
          <div className="ov-stat-label">DNS queries</div>
        </div>
      </div>

      {events.length > 0 && (
        <div className="general-activity">
          <div className="general-activity-heading">RECENT ACTIVITY</div>
          {events.map((e) => (
            <div key={e.id} className="general-activity-row">
              <div className={`general-activity-dot ${e.event_type}`} />
              <div className="general-activity-info">
                <div className="general-activity-name">{e.pattern_name || e.host}</div>
                <div className="general-activity-meta">{e.host} &middot; {timeAgo(e.timestamp)}</div>
              </div>
              <span className="general-activity-badge">Blocked</span>
            </div>
          ))}
        </div>
      )}

      {agentVer && <div className="general-agent-info">Agent v{agentVer}</div>}

      <button
        type="button"
        className="ov-reset-btn"
        onClick={() => void resetStats()}
        disabled={resetting}
      >
        <svg className={`ov-reset-icon${resetting ? ' spinning' : ''}`} viewBox="0 0 24 24" fill="none"
          stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" />
          <path d="M3 3v5h5" />
        </svg>
        {resetting ? 'Resetting…' : 'Reset all counters'}
      </button>

      <div className="general-toggle-row">
        <div className="general-toggle-text">
          <div className="general-toggle-title">Launch at login</div>
          <div className="general-toggle-desc">Start automatically when you log in</div>
        </div>
        {openAtLogin === null ? (
          <span className="general-toggle-loading">&hellip;</span>
        ) : (
          <button
            type="button"
            className={`dash-toggle small ${openAtLogin ? 'on' : 'off'}`}
            aria-pressed={openAtLogin}
            onClick={() => void toggleLogin()}
            disabled={loginBusy}
          >
            <span className="dash-toggle-track"><span className="dash-toggle-thumb" /></span>
          </button>
        )}
      </div>
    </div>
  );
}

/* ── Dashboard page 2: block history ── */
function DashStatsPage() {
  const [reachable, setReachable] = useState(true);
  const [events, setEvents] = useState<Array<{ id: number; timestamp: string; event_type: string; host: string; pattern_name: string }>>([]);
  const [prefs, setPrefs] = useState<{ block_events_enabled: boolean } | null>(null);
  const [clearing, setClearing] = useState(false);

  const load = useCallback(async () => {
    try {
      const [ev, pr] = await Promise.all([
        agent.getBlockEvents(50).catch(() => []),
        agent.getPreferences().catch(() => null),
      ]);
      setReachable(true);
      setEvents(ev as Array<{ id: number; timestamp: string; event_type: string; host: string; pattern_name: string }>);
      setPrefs(pr as { block_events_enabled: boolean } | null);
    } catch {
      setReachable(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const t = setInterval(() => void load(), 5000);
    return () => clearInterval(t);
  }, [load]);

  const clearHistory = useCallback(async () => {
    setClearing(true);
    try { await agent.clearBlockEvents(); setEvents([]); } finally { setClearing(false); }
  }, []);

  function fmtTime(ts: string) {
    const diff = Date.now() - new Date(ts).getTime();
    const m = Math.floor(diff / 60000);
    if (m < 1) return 'just now';
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    return new Date(ts).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  return (
    <div className="dash-inner-page">
      <div className="bh-header">
        <span className="bh-title">Block History</span>
        {events.length > 0 && (
          <button
            type="button"
            className="clear-history-btn"
            onClick={() => void clearHistory()}
            disabled={clearing || !reachable}
          >
            {clearing ? 'Clearing\u2026' : (
              <><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="3 6 5 6 21 6" />
                <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
              </svg> Clear</>
            )}
          </button>
        )}
      </div>

      {events.length > 0 && (
        <div className="bh-count">{events.length} event{events.length !== 1 ? 's' : ''}</div>
      )}

      {prefs && !prefs.block_events_enabled ? (
        <div className="bh-empty-state">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="bh-empty-icon">
            <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
            <path d="M7 11V7a5 5 0 0110 0v4" />
          </svg>
          <p className="bh-empty-text">Block history is off</p>
          <p className="bh-empty-sub">Enable in <strong>Settings &rarr; Privacy</strong> to see what gets blocked.</p>
        </div>
      ) : events.length === 0 ? (
        <div className="bh-empty-state">
          <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="bh-empty-icon">
            <path d="M22 11.08V12a10 10 0 11-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
          <p className="bh-empty-text">All clear</p>
          <p className="bh-empty-sub">No block events recorded yet.</p>
        </div>
      ) : (
        <div className="bh-list">
          {events.map((e) => (
            <div key={e.id} className="bh-card">
              <div className="bh-card-header">
                <span className={`event-badge event-badge-${e.event_type}`}>
                  {e.event_type === 'dlp' ? 'DLP' : 'Cat'}
                </span>
                <span className="bh-pattern">{e.pattern_name || '\u2014'}</span>
              </div>
              <div className="bh-card-meta">
                <span className="bh-host">{e.host}</span>
                <span className="bh-time">{fmtTime(e.timestamp)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ── Dashboard: 3-page swipeable main screen ── */
function Dashboard({ onOpenSettings, onOpenAbout, onOpenGuideline, onOpenLicense }: {
  onOpenSettings: () => void;
  onOpenAbout: () => void;
  onOpenGuideline: () => void;
  onOpenLicense: () => void;
}) {
  const [pageIdx, setPageIdx] = useState(0);
  const containerRef = useRef<HTMLDivElement>(null);
  const [dragDx, setDragDx] = useState(0);
  const [isDragging, setIsDragging] = useState(false);
  const PAGES = 3;

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    let start: { x: number; y: number } | null = null;
    let dragging = false;

    function onMove(e: PointerEvent) {
      if (!start) return;
      const dx = e.clientX - start.x;
      const dy = e.clientY - start.y;
      if (!dragging) {
        if (Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(dy)) {
          dragging = true;
          setIsDragging(true);
        }
        return;
      }
      setDragDx(dx);
    }

    function onUp(e: PointerEvent) {
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
      if (dragging && start && el) {
        const w = el.offsetWidth;
        const dx = e.clientX - start.x;
        setPageIdx((p) => {
          if (dx < -w * 0.2 && p < 3 - 1) return p + 1;
          if (dx > w * 0.2 && p > 0) return p - 1;
          return p;
        });
        setDragDx(0);
        setIsDragging(false);
        dragging = false;
      }
      start = null;
    }

    function onDown(e: PointerEvent) {
      if (e.button !== 0) return;
      if ((e.target as HTMLElement).closest('.swipe-arrow')) return;
      start = { x: e.clientX, y: e.clientY };
      dragging = false;
      window.addEventListener('pointermove', onMove);
      window.addEventListener('pointerup', onUp);
      window.addEventListener('pointercancel', onUp);
    }

    el.addEventListener('pointerdown', onDown);
    return () => {
      el.removeEventListener('pointerdown', onDown);
      window.removeEventListener('pointermove', onMove);
      window.removeEventListener('pointerup', onUp);
      window.removeEventListener('pointercancel', onUp);
    };
  }, []);

  // translateX % is relative to the track's own width (PAGES \u00d7 container)
  const basePct = -(pageIdx * 100) / PAGES;
  const tx = isDragging && dragDx !== 0 ? `calc(${basePct}% + ${dragDx}px)` : `${basePct}%`;

  return (
    <div className="dashboard">
      <div className="dash-topbar" style={{ padding: '18px 20px 0' }}>
        <HamburgerMenu onAbout={onOpenAbout} onGuideline={onOpenGuideline} onLicense={onOpenLicense} />
        <SetupIcon size={48} />
        <button type="button" className="dash-icon-btn" aria-label="Settings" onClick={onOpenSettings}>
          <GearIcon />
        </button>
      </div>

      <div
        ref={containerRef}
        className="dash-swipe-container"
      >
        {pageIdx > 0 && (
          <button type="button" className="swipe-arrow swipe-arrow-left"
            onClick={() => setPageIdx((p) => p - 1)}
            onPointerDown={(e) => e.stopPropagation()}
            aria-label="Previous page">
            <svg className="swipe-ch swipe-ch-a" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="12 4 4 12 12 20"/></svg>
            <svg className="swipe-ch swipe-ch-b" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="12 4 4 12 12 20"/></svg>
            <svg className="swipe-ch swipe-ch-c" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="12 4 4 12 12 20"/></svg>
          </button>
        )}
        {pageIdx < PAGES - 1 && (
          <button type="button" className="swipe-arrow swipe-arrow-right"
            onClick={() => setPageIdx((p) => p + 1)}
            onPointerDown={(e) => e.stopPropagation()}
            aria-label="Next page">
            <svg className="swipe-ch swipe-ch-a" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 4 12 12 4 20"/></svg>
            <svg className="swipe-ch swipe-ch-b" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 4 12 12 4 20"/></svg>
            <svg className="swipe-ch swipe-ch-c" viewBox="0 0 16 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="4 4 12 12 4 20"/></svg>
          </button>
        )}
        <div
          className="dash-swipe-track"
          style={{
            width: `${PAGES * 100}%`,
            transform: `translateX(${tx})`,
            transition: isDragging ? 'none' : 'transform 0.3s cubic-bezier(0.4,0,0.2,1)',
          }}
        >
          <div className="dash-swipe-page"><DashTogglePage /></div>
          <div className="dash-swipe-page"><DashOverviewPage /></div>
          <div className="dash-swipe-page"><DashStatsPage /></div>
        </div>
      </div>

      <div className="dash-page-dots">
        {Array.from({ length: PAGES }, (_, i) => (
          <button
            key={i}
            type="button"
            className={`dash-page-dot ${pageIdx === i ? 'active' : ''}`}
            onClick={() => setPageIdx(i)}
            aria-label={`Page ${i + 1}`}
          />
        ))}
      </div>
    </div>
  );
}

/* ── Back button shared by settings sub-pages ── */
function BackButton({ onClick, label = 'Back' }: { onClick: () => void; label?: string }) {
  return (
    <button type="button" className="dash-icon-btn" onClick={onClick} aria-label={label}>
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
        strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="15 18 9 12 15 6" />
      </svg>
    </button>
  );
}

/* ── Chevron right icon for menu items ── */
function ChevronRight() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" className="menu-chevron">
      <polyline points="9 18 15 12 9 6" />
    </svg>
  );
}

/* ── Menu icons ── */
function ShieldIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function GridIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="3" y="3" width="7" height="7" />
      <rect x="14" y="3" width="7" height="7" />
      <rect x="3" y="14" width="7" height="7" />
      <rect x="14" y="14" width="7" height="7" />
    </svg>
  );
}

/* ── Settings sub-pages ── */
type SettingsSubPage = 'menu' | 'policy' | 'overrides' | 'proxy' | 'privacy';

/* ── Protection presets ── */
type ProtectionLevel = 'extra' | 'light' | 'custom';
type PolicyAction = 'allow' | 'allow_with_dlp' | 'deny';

interface CategoryRule {
  category: string;
  action: PolicyAction;
}

const EXTRA_PRESET: Record<string, PolicyAction> = {
  'AI Chat DLP': 'allow_with_dlp',
  'AI Chat Blocked': 'allow_with_dlp',
  'AI Code Blocked': 'allow_with_dlp',
  'AI Allowed': 'allow',
  'Phishing': 'deny',
  'Social': 'allow',
  'News': 'allow',
};

const LIGHT_PRESET: Record<string, PolicyAction> = {
  'AI Chat DLP': 'deny',
  'AI Chat Blocked': 'deny',
  'AI Code Blocked': 'deny',
  'AI Allowed': 'allow',
  'Phishing': 'deny',
  'Social': 'allow',
  'News': 'allow',
};

const ACTION_OPTIONS: Array<{ action: PolicyAction; label: string }> = [
  { action: 'allow', label: 'Allow' },
  { action: 'allow_with_dlp', label: 'Inspect' },
  { action: 'deny', label: 'Block' },
];

function detectLevel(rules: CategoryRule[]): ProtectionLevel {
  const map: Record<string, PolicyAction> = {};
  for (const r of rules) map[r.category] = r.action;
  const matchesPreset = (preset: Record<string, PolicyAction>) =>
    Object.entries(preset).every(([cat, act]) => map[cat] === act);
  if (matchesPreset(EXTRA_PRESET)) return 'extra';
  if (matchesPreset(LIGHT_PRESET)) return 'light';
  return 'custom';
}

/* Policy Level sub-page — protection radios + editable category rules */
function PolicyLevelPage({ onBack }: { onBack: () => void }) {
  const [level, setLevel] = useState<ProtectionLevel>('extra');
  const [rules, setRules] = useState<CategoryRule[]>([]);
  const [saving, setSaving] = useState(false);
  const [loaded, setLoaded] = useState(false);

  // Load current policies from the agent
  useEffect(() => {
    (async () => {
      try {
        const policies = await agent.getPolicies();
        const mapped = policies
          .filter((p) => !p.category.startsWith('allow_') && !p.category.startsWith('block_'))
          .map((p) => ({ category: p.category, action: p.action as PolicyAction }));
        setRules(mapped);
        setLevel(detectLevel(mapped));
      } catch {
        // Fallback: use extra preset
        setRules(Object.entries(EXTRA_PRESET).map(([category, action]) => ({ category, action })));
        setLevel('extra');
      }
      setLoaded(true);
    })();
  }, []);

  // When user picks a preset, apply its rules
  const selectPreset = (preset: ProtectionLevel) => {
    setLevel(preset);
    if (preset === 'custom') return;
    const presetMap = preset === 'extra' ? EXTRA_PRESET : LIGHT_PRESET;
    setRules((prev) =>
      prev.map((r) => presetMap[r.category] !== undefined
        ? { ...r, action: presetMap[r.category] }
        : r
      ),
    );
  };

  // When user manually changes a rule, auto-switch to custom
  const changeRule = (category: string, action: PolicyAction) => {
    const next = rules.map((r) => r.category === category ? { ...r, action } : r);
    setRules(next);
    setLevel(detectLevel(next));
  };

  const save = async () => {
    setSaving(true);
    try {
      // Apply each rule
      for (const r of rules) {
        await agent.updatePolicy(r.category, r.action);
      }
      try { localStorage.setItem('secureEdge.protection', level); } catch { /* noop */ }
    } catch { /* agent offline */ }
    setSaving(false);
    onBack();
  };

  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} />
        <h1 className="settings-title">Policy Level</h1>
      </div>
      <p className="settings-subtitle">Choose your protection level.</p>

      <div className="sw-options">
        <label className={`sw-option ${level === 'extra' ? 'selected' : ''}`}>
          <input type="radio" name="protection" value="extra" checked={level === 'extra'}
            onChange={() => selectPreset('extra')} className="sr-only" />
          <span className={`sw-radio ${level === 'extra' ? 'checked' : ''}`} />
          <div className="sw-option-text">
            <strong>Extra Protection</strong>
            <span>Allow AI sites but inspect for sensitive data</span>
          </div>
        </label>
        <label className={`sw-option ${level === 'light' ? 'selected' : ''}`}>
          <input type="radio" name="protection" value="light" checked={level === 'light'}
            onChange={() => selectPreset('light')} className="sr-only" />
          <span className={`sw-radio ${level === 'light' ? 'checked' : ''}`} />
          <div className="sw-option-text">
            <strong>Light Protection</strong>
            <span>Block risky AI sites, no inspection</span>
          </div>
        </label>
        <label className={`sw-option ${level === 'custom' ? 'selected' : ''}`}>
          <input type="radio" name="protection" value="custom" checked={level === 'custom'}
            onChange={() => selectPreset('custom')} className="sr-only" />
          <span className={`sw-radio ${level === 'custom' ? 'checked' : ''}`} />
          <div className="sw-option-text">
            <strong>Custom</strong>
            <span>Configure each category individually</span>
          </div>
        </label>
      </div>

      {/* Category rules */}
      {loaded && (
        <div className="policy-rules">
          <h2 className="policy-rules-heading">Category Rules</h2>
          {rules.map((r) => (
            <div key={r.category} className="policy-rule-row">
              <span className="policy-rule-name">{r.category}</span>
              <div className="policy-rule-actions">
                {ACTION_OPTIONS.map((opt) => (
                  <button
                    key={opt.action}
                    type="button"
                    className={`policy-rule-btn ${r.action === opt.action ? 'active' : ''}`}
                    onClick={() => changeRule(r.category, opt.action)}
                  >
                    {opt.label}
                  </button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="settings-footer">
        <button type="button" className="sw-cta" onClick={save} disabled={saving}>
          {saving ? 'Saving…' : 'Save'}
        </button>
      </div>
    </div>
  );
}


/* Rules sub-page — clean allow/block domain override management */
function OverridesPage({ onBack }: { onBack: () => void }) {
  const [overrides, setOverrides] = useState<{ allow: string[]; block: string[] } | null>(null);
  const [domain, setDomain] = useState('');
  const [list, setList] = useState<'allow' | 'block'>('block');
  const [tab, setTab] = useState<'block' | 'allow'>('block');
  const [feedback, setFeedback] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);
  const [adding, setAdding] = useState(false);
  const [showRuleFiles, setShowRuleFiles] = useState(false);

  useEffect(() => {
    agent.listOverrides().then(setOverrides).catch(() => {});
  }, []);

  const add = useCallback(async () => {
    const d = domain.trim().toLowerCase();
    if (!d) return;
    setAdding(true);
    try {
      const next = await agent.addOverride(d, list);
      setOverrides(next);
      setDomain('');
      setTab(list);
      setFeedback({ kind: 'success', message: `Added ${d} to ${list} list` });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setAdding(false);
    }
  }, [domain, list]);

  const remove = useCallback(async (d: string) => {
    try {
      const next = await agent.removeOverride(d);
      setOverrides(next);
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  const current = overrides ? (tab === 'allow' ? overrides.allow : overrides.block) : [];

  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} />
        <h1 className="settings-title">Rules</h1>
      </div>
      <p className="settings-subtitle">Allow or block individual domains</p>

      {feedback && (
        <div className={`feedback feedback-${feedback.kind}`} role="status">{feedback.message}</div>
      )}

      {/* Add domain */}
      <div className="rules-add-form">
        <input
          type="text"
          className="rules-domain-input"
          placeholder="example.com"
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => { if (e.key === 'Enter') void add(); }}
          aria-label="Domain to add"
        />
        <div className="rules-list-toggle">
          <button
            type="button"
            className={`rules-list-btn ${list === 'block' ? 'block-active' : ''}`}
            onClick={() => setList('block')}
          >Block</button>
          <button
            type="button"
            className={`rules-list-btn ${list === 'allow' ? 'allow-active' : ''}`}
            onClick={() => setList('allow')}
          >Allow</button>
        </div>
        <button
          type="button"
          className="rules-add-btn"
          onClick={() => void add()}
          disabled={adding || !domain.trim()}
        >
          {adding ? '…' : 'Add'}
        </button>
      </div>

      {/* Tabs */}
      <div className="rules-tabs">
        <button
          type="button"
          className={`rules-tab ${tab === 'block' ? 'active' : ''}`}
          onClick={() => setTab('block')}
        >
          Blocked{overrides ? ` (${overrides.block.length})` : ''}
        </button>
        <button
          type="button"
          className={`rules-tab ${tab === 'allow' ? 'active' : ''}`}
          onClick={() => setTab('allow')}
        >
          Allowed{overrides ? ` (${overrides.allow.length})` : ''}
        </button>
      </div>

      {/* Domain list */}
      <div className="rules-list">
        {overrides === null ? (
          <div className="rules-empty">Loading…</div>
        ) : current.length === 0 ? (
          <div className="rules-empty">
            No {tab === 'block' ? 'blocked' : 'allowed'} domains yet.
            Add one above to override the default rules.
          </div>
        ) : (
          current.map((d) => (
            <div key={d} className={`rules-domain-row ${tab}`}>
              <div className={`rules-domain-dot ${tab}`} />
              <span className="rules-domain-name">{d}</span>
              <button
                type="button"
                className="rules-remove-btn"
                onClick={() => void remove(d)}
                aria-label={`Remove ${d}`}
              >×</button>
            </div>
          ))
        )}
      </div>

      {/* Rule files — collapsible section */}
      <div className="rules-files-section">
        <button
          type="button"
          className="rules-files-toggle"
          onClick={() => setShowRuleFiles((v) => !v)}
        >
          <span className="rules-files-heading">RULE FILES</span>
          <svg
            width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
            strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            className={`rules-files-chevron ${showRuleFiles ? 'open' : ''}`}
            aria-hidden="true"
          >
            <polyline points="9 18 15 12 9 6" />
          </svg>
        </button>
        {showRuleFiles && <Rules />}
      </div>
    </div>
  );
}

/* Privacy sub-page — block event history opt-in */
function PrivacyPage({ onBack }: { onBack: () => void }) {
  const [prefs, setPrefs] = useState<AgentPreferences | null>(null);
  const [showConsent, setShowConsent] = useState(false);
  const [feedback, setFeedback] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  useEffect(() => {
    agent.getPreferences().then(setPrefs).catch(() => {});
  }, []);

  const enableHistory = async () => {
    try {
      const updated = await agent.setBlockEventsEnabled(true);
      setPrefs(updated);
      setShowConsent(false);
      setFeedback({ kind: 'success', message: 'Block event history enabled.' });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  };

  const disableHistory = async () => {
    try {
      const updated = await agent.setBlockEventsEnabled(false);
      setPrefs(updated);
      setFeedback({ kind: 'success', message: 'Block event history disabled.' });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  };

  const changeDLPAction = async (action: 'block' | 'mask' | 'bypass') => {
    try {
      const updated = await agent.setDLPAction(action);
      setPrefs(updated);
      const labels: Record<string, string> = {
        block: 'DLP behavior set to Block Request (default).',
        mask: 'DLP behavior set to Auto-hide Secrets (**).',
        bypass: 'DLP behavior set to Bypass.',
      };
      setFeedback({ kind: 'success', message: labels[action] || 'DLP behavior updated.' });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  };

  const currentAction = prefs?.dlp_action || (prefs?.redact_enabled ? 'mask' : 'block');

  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} />
        <h1 className="settings-title">Privacy</h1>
      </div>
      <p className="settings-subtitle">
        Prompt Gate persists nothing about your traffic by default — only anonymous aggregate counters.
      </p>

      {feedback && (
        <div className={`feedback feedback-${feedback.kind}`} role="status">{feedback.message}</div>
      )}

      {prefs && (
        <>
          <div className="privacy-card">
            <div className="privacy-card-header">
              <div>
                <div className="privacy-card-title">Block event history</div>
                <div className="privacy-card-desc">
                  Records the destination domain and pattern name of each blocked event
                  in local SQLite (last 500 events). Never uploaded.
                </div>
                {prefs.block_events_consented_at > 0 && !prefs.block_events_enabled && (
                  <div className="privacy-card-meta">
                    Last consented {new Date(prefs.block_events_consented_at * 1000).toLocaleString()}
                  </div>
                )}
              </div>
              <div className="privacy-card-toggle">
                {prefs.managed ? (
                  <span className="privacy-managed-badge">Managed</span>
                ) : (
                  <button
                    type="button"
                    className={`dash-toggle small ${prefs.block_events_enabled ? 'on' : 'off'}`}
                    aria-pressed={prefs.block_events_enabled}
                    onClick={() => prefs.block_events_enabled ? void disableHistory() : setShowConsent(true)}
                  >
                    <span className="dash-toggle-track">
                      <span className="dash-toggle-thumb" />
                    </span>
                  </button>
                )}
              </div>
            </div>
          </div>

          <div className="privacy-card" style={{ marginTop: '16px' }}>
            <div className="privacy-card-header" style={{ flexDirection: 'column', alignItems: 'flex-start', gap: '12px' }}>
              <div>
                <div className="privacy-card-title">Secret Detection Behavior</div>
                <div className="privacy-card-desc">
                  Choose how Prompt Gate handles prompts containing detected secret keys:
                </div>
              </div>
              <div className="policy-rule-actions" style={{ width: '100%', gap: '8px' }}>
                <button
                  type="button"
                  className={`policy-rule-btn ${currentAction === 'block' ? 'active' : ''}`}
                  onClick={() => void changeDLPAction('block')}
                  disabled={prefs.managed}
                >
                  🛑 Block (Default)
                </button>
                <button
                  type="button"
                  className={`policy-rule-btn ${currentAction === 'mask' ? 'active' : ''}`}
                  onClick={() => void changeDLPAction('mask')}
                  disabled={prefs.managed}
                >
                  🙈 Auto-hide (**)
                </button>
                <button
                  type="button"
                  className={`policy-rule-btn ${currentAction === 'bypass' ? 'active' : ''}`}
                  onClick={() => void changeDLPAction('bypass')}
                  disabled={prefs.managed}
                >
                  ⏩ Bypass
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {showConsent && (
        <div className="modal-backdrop" role="dialog" aria-modal="true" onClick={() => setShowConsent(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Enable block event history</h3>
            <p>For every block, this will record:</p>
            <ul className="consent-list">
              <li>The timestamp</li>
              <li>The destination domain (e.g. <code>chat.openai.com</code>)</li>
              <li>The pattern name that triggered the block</li>
            </ul>
            <p>
              Stored locally in SQLite. Last 500 events; older entries are auto-deleted.
              The data never leaves your device.
            </p>
            <div className="modal-actions">
              <button type="button" onClick={() => setShowConsent(false)}>Cancel</button>
              <button type="button" className="primary" onClick={() => void enableHistory()}>Enable history</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

/* Proxy Settings sub-page — wraps existing ProxySettings page */
function ProxySettingsPage({ onBack }: { onBack: () => void }) {
  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} />
        <h1 className="settings-title">Proxy Settings</h1>
      </div>
      <ProxySettings />
    </div>
  );
}

function SettingsPage({ onBack }: { onBack: () => void }) {
  const [sub, setSub] = useState<SettingsSubPage>('menu');

  if (sub === 'policy') return <PolicyLevelPage onBack={() => setSub('menu')} />;
  if (sub === 'overrides') return <OverridesPage onBack={() => setSub('menu')} />;
  if (sub === 'proxy') return <ProxySettingsPage onBack={() => setSub('menu')} />;
  if (sub === 'privacy') return <PrivacyPage onBack={() => setSub('menu')} />;

  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} label="Back to dashboard" />
        <h1 className="settings-title">Settings</h1>
      </div>
      <p className="settings-subtitle">Follow steps below to continue set up.</p>

      <div className="settings-menu">
        <button type="button" className="settings-menu-item" onClick={() => setSub('policy')}>
          <span className="settings-menu-icon"><ShieldIcon /></span>
          <span className="settings-menu-label">Policy Level</span>
          <ChevronRight />
        </button>
        <button type="button" className="settings-menu-item" onClick={() => setSub('overrides')}>
          <span className="settings-menu-icon"><FilterIcon /></span>
          <span className="settings-menu-label">Rules</span>
          <ChevronRight />
        </button>
        <button type="button" className="settings-menu-item" onClick={() => setSub('proxy')}>
          <span className="settings-menu-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="10" />
              <line x1="2" y1="12" x2="22" y2="12" />
              <path d="M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z" />
            </svg>
          </span>
          <span className="settings-menu-label">Proxy Settings</span>
          <ChevronRight />
        </button>
        <button type="button" className="settings-menu-item" onClick={() => setSub('privacy')}>
          <span className="settings-menu-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
              <circle cx="12" cy="12" r="3" />
            </svg>
          </span>
          <span className="settings-menu-label">Privacy</span>
          <ChevronRight />
        </button>
      </div>
    </div>
  );
}

/* ── About Us page ── */
function AboutUsPage({ onBack }: { onBack: () => void }) {
  const [version, setVersion] = useState('…');
  useEffect(() => {
    window.secureEdge?.getVersion?.().then(setVersion).catch(() => {});
  }, []);
  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} label="Back to dashboard" />
        <h1 className="settings-title">About Us</h1>
      </div>
      <div className="about-content">
        <div className="about-logo-area">
          <SetupIcon size={64} />
        </div>
        <h2 className="about-heading">Prompt Gate</h2>
        <p className="about-version">Version {version}</p>
        <div className="about-section">
          <p>
            Built by <strong>ShieldNet 360</strong> — a small team passionate about
            privacy, security, and giving people control over their own data.
          </p>
          <p>
            Prompt Gate is a local-first Data Loss Prevention (DLP) tool that
            monitors outbound traffic to AI services and other destinations,
            helping you catch sensitive information before it leaves your device.
          </p>
        </div>
        <div className="about-section">
          <h3>Contact</h3>
          <p>GitHub: <a href="https://github.com/ShieldNet-360/prompt-gate" className="about-link">github.com/ShieldNet-360/prompt-gate</a></p>
          <p>Issues &amp; questions: <a href="https://github.com/ShieldNet-360/prompt-gate/issues" className="about-link">open an issue</a></p>
          <p>Email: <a href="mailto:Support@shieldnet360.com" className="about-link">Support@shieldnet360.com</a></p>
        </div>
        <div className="about-section">
          <p className="about-copy">&copy; 2026 ShieldNet 360. All rights reserved.</p>
        </div>
      </div>
    </div>
  );
}

/* ── Guideline page ── */
function GuidelinePage({ onBack }: { onBack: () => void }) {
  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} label="Back to dashboard" />
        <h1 className="settings-title">Guideline</h1>
      </div>
      <div className="guide-content">
        <div className="guide-section">
          <h2 className="guide-heading">What is Prompt Gate?</h2>
          <p>
            Prompt Gate is a local proxy-based DLP tool that sits between your
            browser and the internet. It scans outbound requests in real time
            for sensitive data patterns — credit card numbers, API keys,
            personal identifiers, and more — and blocks them before they reach
            external services.
          </p>
        </div>

        <div className="guide-section">
          <h2 className="guide-heading">Getting Started</h2>
          <ol className="guide-steps">
            <li><strong>Enable the proxy</strong> — Toggle the switch on the dashboard. The first time, you will be asked to trust the Prompt Gate CA certificate.</li>
            <li><strong>Browse normally</strong> — Visit any AI chat or website. Prompt Gate works silently in the background.</li>
            <li><strong>Review blocks</strong> — When sensitive data is detected, a notification appears. Check the <em>Statistics</em> page for history.</li>
          </ol>
        </div>

        <div className="guide-section">
          <h2 className="guide-heading">Key Features</h2>
          <ul className="guide-list">
            <li><strong>MITM Proxy</strong> — Transparent HTTPS interception with a locally generated CA.</li>
            <li><strong>DLP Scanning</strong> — Pattern-based detection of secrets, PII, and credentials.</li>
            <li><strong>Policy Levels</strong> — Choose between Relaxed, Balanced, or Strict protection.</li>
            <li><strong>Site Overrides</strong> — Allow or block specific domains manually.</li>
            <li><strong>Chrome Extension</strong> — Companion extension for paste/form/clipboard scanning on AI chat sites.</li>
          </ul>
        </div>

        <div className="guide-section">
          <h2 className="guide-heading">Disabling the Proxy</h2>
          <p>
            Toggle the switch off on the dashboard, or quit the app. Prompt Gate
            will restore your original network settings automatically. If the
            app was force-killed, it recovers on the next launch.
          </p>
        </div>

        <div className="guide-section">
          <h2 className="guide-heading">Troubleshooting</h2>
          <ul className="guide-list">
            <li><strong>Red tray icon / toggle does nothing</strong> — The Go agent is not running. Most often the config folder <code>~/.prompt-gate</code> has wrong ownership or permissions (left over from a previous install or run as another user), so the agent can't read its config and exits immediately. Fix it by running <code>sudo chown -R $(whoami) ~/.prompt-gate &amp;&amp; chmod -R u+rwX ~/.prompt-gate</code> in Terminal, or wipe it with <code>sudo rm -rf ~/.prompt-gate</code> and relaunch — the app recreates it. Then restart the application.</li>
            <li><strong>"Certificate not trusted" errors</strong> — Re-enable the proxy to reinstall the CA certificate.</li>
            <li><strong>No internet after quit</strong> — Open System Settings &rarr; Network &rarr; Proxies and disable the HTTPS proxy, or relaunch Prompt Gate.</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

/* ── License page ── */
function LicensePage({ onBack }: { onBack: () => void }) {
  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} label="Back to dashboard" />
        <h1 className="settings-title">License</h1>
      </div>
      <div className="about-content">
        <div className="about-logo-area">
          <LicenseIcon />
        </div>
        <h2 className="about-heading">MIT License</h2>
        <div className="about-section">
          <p>Copyright &copy; 2026 ShieldNet 360</p>
        </div>
        <div className="about-section" style={{ textAlign: 'left' }}>
          <p>
            Permission is hereby granted, free of charge, to any person obtaining a copy
            of this software and associated documentation files (the &ldquo;Software&rdquo;), to deal
            in the Software without restriction, including without limitation the rights
            to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
            copies of the Software, and to permit persons to whom the Software is
            furnished to do so, subject to the following conditions:
          </p>
          <p>
            The above copyright notice and this permission notice shall be included in all
            copies or substantial portions of the Software.
          </p>
          <p style={{ fontSize: '0.82rem', color: '#666' }}>
            THE SOFTWARE IS PROVIDED &ldquo;AS IS&rdquo;, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
            IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
            FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
            AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
            LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
            OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
            SOFTWARE.
          </p>
        </div>
        <div className="about-section">
          <h3>Third-Party Licenses</h3>
          <ul style={{ textAlign: 'left', fontSize: '0.85rem', lineHeight: 1.7 }}>
            <li><strong>Electron</strong> &mdash; MIT License</li>
            <li><strong>React</strong> &mdash; MIT License</li>
            <li><strong>Go standard library</strong> &mdash; BSD 3-Clause</li>
            <li><strong>modernc.org/sqlite</strong> &mdash; BSD 3-Clause</li>
          </ul>
        </div>
        <div className="about-section">
          <p className="about-copy">
            Full license text:&nbsp;
            <a href="https://github.com/ShieldNet-360/prompt-gate/blob/main/LICENSE" className="about-link">
              github.com/ShieldNet-360/prompt-gate/LICENSE
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}

/* ── Root app ── */
function App() {
  const [page, setPage] = useState<'dashboard' | 'settings' | 'about' | 'guideline' | 'license'>('dashboard');
  const [showSetup, setShowSetup] = useState<boolean>(isSetupPending);
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  useEffect(() => {
    const off = window.secureEdge?.onNavigate?.((v) => {
      // 'proxy' navigates to Settings so the user can reach Proxy Settings.
      // 'status' / 'settings' / anything else: just raise the window and
      // restore whatever page the user had open last — no forced navigation.
      if (v === 'proxy') setPage('settings');
    });
    const MAX_TOASTS = 3;
    const offEvent = window.secureEdge?.onEvent?.((evt) => {
      setToasts((prev) => {
        const next = [
          ...prev,
          {
            id: `${Date.now()}-${Math.random()}`,
            title: evt.title,
            body: evt.body,
            type: evt.type === 'dlp_block' ? 'error' as const : 'warning' as const,
            faqUrl: evt.faq_url,
          },
        ];
        // Keep only the most recent toasts to avoid UI flood.
        return next.length > MAX_TOASTS ? next.slice(-MAX_TOASTS) : next;
      });
    });
    return () => {
      off?.();
      offEvent?.();
    };
  }, []);

  if (showSetup) {
    return <Setup onComplete={() => setShowSetup(false)} />;
  }

  return (
    <>
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
      {page === 'dashboard' && (
        <Dashboard
          onOpenSettings={() => setPage('settings')}
          onOpenAbout={() => setPage('about')}
          onOpenGuideline={() => setPage('guideline')}
          onOpenLicense={() => setPage('license')}
        />
      )}
      {page === 'settings' && <SettingsPage onBack={() => setPage('dashboard')} />}
      {page === 'about' && <AboutUsPage onBack={() => setPage('dashboard')} />}
      {page === 'guideline' && <GuidelinePage onBack={() => setPage('dashboard')} />}
      {page === 'license' && <LicensePage onBack={() => setPage('dashboard')} />}
    </>
  );
}

const root = createRoot(document.getElementById('root')!);
root.render(<React.StrictMode><App /></React.StrictMode>);
