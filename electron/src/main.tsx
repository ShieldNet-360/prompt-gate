import React, { useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { SetupIcon } from './components/SetupIcon';
import { ToastContainer, ToastMessage } from './components/Toast';
import { agent } from './api/agent';
import { ProxySettings } from './pages/ProxySettings';
import { Rules } from './pages/Rules';
import { Setup, isSetupPending } from './pages/Setup';
import { Status } from './pages/Status';
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

/* ── Dashboard: large toggle + Safe Browsing indicator ── */
function Dashboard({ onOpenSettings, onOpenAbout, onOpenGuideline, onOpenLicense }: {
  onOpenSettings: () => void;
  onOpenAbout: () => void;
  onOpenGuideline: () => void;
  onOpenLicense: () => void;
}) {
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
    <div className="dashboard">
      {/* Top bar */}
      <div className="dash-topbar">
        <HamburgerMenu onAbout={onOpenAbout} onGuideline={onOpenGuideline} onLicense={onOpenLicense} />
        <SetupIcon size={48} />
        <button type="button" className="dash-icon-btn" aria-label="Settings" onClick={onOpenSettings}>
          <GearIcon />
        </button>
      </div>

      {/* Large toggle */}
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

      {/* Status label */}
      {proxyRunning && (
        <div className="dash-status-label">
          <span className="dash-status-dot" />
          Safe Browsing
        </div>
      )}
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
type SettingsSubPage = 'menu' | 'general' | 'policy' | 'statistics' | 'overrides' | 'proxy' | 'privacy';

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

/* Statistics sub-page — agent status, counters, and block history */
function StatisticsPage({ onBack }: { onBack: () => void }) {
  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} />
        <h1 className="settings-title">Statistics</h1>
      </div>
      <Status />
    </div>
  );
}

/* Allow / Block overrides sub-page — wraps existing Rules page */
function OverridesPage({ onBack }: { onBack: () => void }) {
  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} />
        <h1 className="settings-title">Allow / Block Sites</h1>
      </div>
      <Rules />
    </div>
  );
}

/* Privacy sub-page — block event history opt-in */
function PrivacyPage({ onBack }: { onBack: () => void }) {
  const [prefs, setPrefs] = useState<{ block_events_enabled: boolean; block_events_consented_at: number; managed: boolean } | null>(null);
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

/* ── Settings page — menu list matching the design ── */
/* ── General settings sub-page (startup toggle, etc.) ── */
function GeneralPage({ onBack }: { onBack: () => void }) {
  const [openAtLogin, setOpenAtLogin] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void window.secureEdge?.getOpenAtLogin?.().then((v) => setOpenAtLogin(v));
  }, []);

  const toggle = useCallback(async () => {
    if (openAtLogin === null || busy) return;
    setBusy(true);
    try {
      const next = await window.secureEdge?.setOpenAtLogin?.(!openAtLogin);
      if (next !== undefined) setOpenAtLogin(next);
    } finally {
      setBusy(false);
    }
  }, [openAtLogin, busy]);

  return (
    <div className="settings-page">
      <div className="settings-header">
        <BackButton onClick={onBack} label="Back to settings" />
        <h1 className="settings-title">General</h1>
      </div>
      <div className="page" style={{ paddingTop: 0 }}>
        <section className="privacy-section">
          <div className="privacy-row">
            <div className="privacy-row-text">
              <div className="privacy-row-title">Run at startup</div>
              <div className="privacy-row-desc">
                Automatically launch Prompt Gate when you log in so you are
                always protected. Works on macOS, Windows, and Linux.
              </div>
            </div>
            <div className="privacy-row-control">
              {openAtLogin === null ? (
                <span style={{ color: '#888', fontSize: '0.85rem' }}>Loading…</span>
              ) : openAtLogin ? (
                <button
                  type="button"
                  className="privacy-toggle privacy-toggle-on"
                  onClick={() => void toggle()}
                  disabled={busy}
                  aria-pressed="true"
                >
                  On
                </button>
              ) : (
                <button
                  type="button"
                  className="privacy-toggle privacy-toggle-off"
                  onClick={() => void toggle()}
                  disabled={busy}
                  aria-pressed="false"
                >
                  Off
                </button>
              )}
            </div>
          </div>
        </section>
      </div>
    </div>
  );
}

function SettingsPage({ onBack }: { onBack: () => void }) {
  const [sub, setSub] = useState<SettingsSubPage>('menu');

  if (sub === 'general') return <GeneralPage onBack={() => setSub('menu')} />;
  if (sub === 'policy') return <PolicyLevelPage onBack={() => setSub('menu')} />;
  if (sub === 'statistics') return <StatisticsPage onBack={() => setSub('menu')} />;
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
        <button type="button" className="settings-menu-item" onClick={() => setSub('general')}>
          <span className="settings-menu-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="12" cy="12" r="3" />
              <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 01-2.83 2.83l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
            </svg>
          </span>
          <span className="settings-menu-label">General</span>
          <ChevronRight />
        </button>
        <button type="button" className="settings-menu-item" onClick={() => setSub('policy')}>
          <span className="settings-menu-icon"><ShieldIcon /></span>
          <span className="settings-menu-label">Policy Level</span>
          <ChevronRight />
        </button>
        <button type="button" className="settings-menu-item" onClick={() => setSub('statistics')}>
          <span className="settings-menu-icon">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
              strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <line x1="18" y1="20" x2="18" y2="10" />
              <line x1="12" y1="20" x2="12" y2="4" />
              <line x1="6" y1="20" x2="6" y2="14" />
            </svg>
          </span>
          <span className="settings-menu-label">Statistics</span>
          <ChevronRight />
        </button>
        <button type="button" className="settings-menu-item" onClick={() => setSub('overrides')}>
          <span className="settings-menu-icon"><FilterIcon /></span>
          <span className="settings-menu-label">Allow / Block specific sites</span>
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
        <p className="about-version">Version 1.0.1</p>
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
      if (v === 'status' || v === 'settings' || v === 'proxy' || v === 'rules') {
        setPage('settings');
      }
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
