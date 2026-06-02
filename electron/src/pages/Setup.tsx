import { useState } from 'react';
import { agent } from '../api/agent';
import { SetupIcon } from '../components/SetupIcon';

const COMPLETION_KEY = 'secureEdge.setup.completed';

const STEPS = [
  { label: 'Choose protection that suits your needs.' },
  { label: 'Install CA certificate' },
];

export function Setup({ onComplete }: { onComplete?: () => void }) {
  // 0 = welcome, 1 = overview, 2 = choose protection, 3 = install CA
  const [step, setStep] = useState(0);
  const [protection, setProtection] = useState<'extra' | 'light'>('extra');
  const [completed, setCompleted] = useState<boolean[]>(new Array(STEPS.length).fill(false));
  const [installing, setInstalling] = useState(false);
  const [caStatus, setCaStatus] = useState<'idle' | 'ok' | 'error'>('idle');
  const [caError, setCaError] = useState('');

  const doneCount = completed.filter(Boolean).length;

  const markDone = (idx: number) => {
    setCompleted((prev) => {
      const next = [...prev];
      next[idx] = true;
      return next;
    });
  };

  const finish = () => {
    try {
      window.localStorage.setItem(COMPLETION_KEY, 'true');
      window.localStorage.setItem('secureEdge.protection', protection);
      if (protection === 'extra') {
        window.localStorage.setItem('secureEdge.dlp.optIn', 'true');
      }
    } catch {
      // Storage unavailable — non-fatal.
    }
    onComplete?.();
  };

  const installCertificate = async () => {
    setInstalling(true);
    setCaStatus('idle');
    setCaError('');
    try {
      // Ensure proxy is running (generates the CA key + cert).
      const ps = await agent.getProxyStatus().catch(() => null);
      let caPath = ps?.ca_cert_path;
      if (!ps?.running) {
        const res = await agent.enableProxy();
        caPath = res.ca_cert_path;
      }
      if (!caPath) {
        // Try fetching status again to get the cert path.
        const status = await agent.getProxyStatus();
        caPath = status.ca_cert_path;
      }
      if (!caPath) throw new Error('CA certificate path not available');
      // Install to OS trust store.
      const result = await agent.installSystemCA('install', caPath);
      if (!result.ok) throw new Error(result.message ?? 'Installation failed');
      setCaStatus('ok');
      markDone(1);
    } catch (err) {
      setCaStatus('error');
      setCaError(String(err));
    } finally {
      setInstalling(false);
    }
  };

  /* ── Step 0: Welcome Screen ── */
  if (step === 0) {
    return (
      <div className="sw sw-welcome" aria-labelledby="sw-heading">
        <div className="sw-welcome-content">
          <SetupIcon size={80} />
          <h1 id="sw-heading" className="sw-welcome-title">
            Welcome to<br />Prompt Gate
          </h1>
          <p className="sw-welcome-subtitle">
            We'll help secure your team's AI usage.<br />
            Click Get Started to continue.
          </p>
        </div>
        <div className="sw-footer">
          <button type="button" className="sw-cta" onClick={() => setStep(1)}>
            Get Started
          </button>
        </div>
      </div>
    );
  }

  /* ── Step 1: Get Started overview ── */
  if (step === 1) {
    return (
      <div className="sw" aria-labelledby="sw-heading">
        <div className="sw-header">
          <button type="button" className="sw-back" aria-label="Back" onClick={() => setStep(0)}>
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M13 15L8 10L13 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </button>
          <SetupIcon size={44} />
        </div>

        <h1 id="sw-heading" className="sw-title">Get Started</h1>
        <p className="sw-subtitle">Follow steps below to continue set up.</p>

        <ul className="sw-step-list">
          {STEPS.map((s, i) => (
            <li key={i} className="sw-step-item" onClick={() => setStep(i + 2)} role="button" tabIndex={0}>
              <span className={`sw-step-dot ${completed[i] ? 'done' : ''}`}>
                {completed[i] ? (
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M3 7L6 10L11 4" stroke="#3b82f6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>
                ) : (
                  <svg width="14" height="14" viewBox="0 0 14 14" fill="none"><circle cx="7" cy="7" r="5" stroke="#cbd5e1" strokeWidth="1.5" strokeDasharray="2 2"/></svg>
                )}
              </span>
              <span className="sw-step-label">{s.label}</span>
              <svg className="sw-step-arrow" width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M6 4L10 8L6 12" stroke="#94a3b8" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/></svg>
            </li>
          ))}
        </ul>

        <div className="sw-footer">
          <button
            type="button"
            className="sw-cta"
            onClick={() => setStep(2)}
          >
            Get Started
          </button>
        </div>
      </div>
    );
  }

  /* ── Step 2: Choose Protection ── */
  if (step === 2) {
    return (
      <div className="sw" aria-labelledby="sw-heading">
        <div className="sw-header">
          <button type="button" className="sw-back" aria-label="Back" onClick={() => setStep(1)}>
            <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M13 15L8 10L13 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
          </button>
          <SetupIcon size={44} />
          <span className="sw-progress">{doneCount}/{STEPS.length} Done</span>
        </div>

        <h1 id="sw-heading" className="sw-title">Choose Protection</h1>
        <p className="sw-subtitle">Configure how you want to protect.</p>

        <div className="sw-options">
          <label className={`sw-option ${protection === 'extra' ? 'selected' : ''}`}>
            <input
              type="radio"
              name="protection"
              value="extra"
              checked={protection === 'extra'}
              onChange={() => setProtection('extra')}
              className="sr-only"
            />
            <span className={`sw-radio ${protection === 'extra' ? 'checked' : ''}`} />
            <div className="sw-option-text">
              <strong>Extra Protection</strong>
              <span>Allow AI Sites and Tools but check for sensitive and personal data</span>
            </div>
          </label>

          <label className={`sw-option ${protection === 'light' ? 'selected' : ''}`}>
            <input
              type="radio"
              name="protection"
              value="light"
              checked={protection === 'light'}
              onChange={() => setProtection('light')}
              className="sr-only"
            />
            <span className={`sw-radio ${protection === 'light' ? 'checked' : ''}`} />
            <div className="sw-option-text">
              <strong>Light Protection</strong>
              <span>Block risky AI sites, no inspection</span>
            </div>
          </label>
        </div>

        <div className="sw-footer">
          <button
            type="button"
            className="sw-cta"
            onClick={async () => {
              try { await agent.applyProtectionPlan(protection); } catch { /* agent may not be running yet */ }
              markDone(0); setStep(3);
            }}
          >
            Confirm and Continue
          </button>
        </div>
      </div>
    );
  }

  /* ── Step 3: Install CA Certificate ── */
  return (
    <div className="sw" aria-labelledby="sw-heading">
      <div className="sw-header">
        <button type="button" className="sw-back" aria-label="Back" onClick={() => setStep(2)}>
          <svg width="20" height="20" viewBox="0 0 20 20" fill="none"><path d="M13 15L8 10L13 5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/></svg>
        </button>
        <SetupIcon size={44} />
        <span className="sw-progress">{doneCount}/{STEPS.length} Done</span>
      </div>

      <h1 id="sw-heading" className="sw-title">Install CA certificate</h1>
      <p className="sw-subtitle">
        Allow Prompt Gate to install CA Certificate to enable traffic inspection.
      </p>

      <div className="sw-card">
        <p>
          Prompt Gate uses a locally generated CA certificate to inspect
          encrypted HTTPS traffic. You will be prompted to authorize the
          installation.
        </p>
        {caStatus === 'ok' && (
          <div className="sw-ca-status sw-ca-ok">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <circle cx="8" cy="8" r="7" fill="#22c55e" />
              <path d="M5 8L7 10L11 6" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            </svg>
            CA certificate installed and trusted.
          </div>
        )}
        {caStatus === 'error' && (
          <div className="sw-ca-status sw-ca-error">
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
              <circle cx="8" cy="8" r="7" fill="#ef4444" />
              <path d="M6 6L10 10M10 6L6 10" stroke="white" strokeWidth="1.5" strokeLinecap="round"/>
            </svg>
            {caError || 'Failed to install CA certificate.'}
          </div>
        )}
      </div>

      <div className="sw-footer">
        {caStatus === 'ok' ? (
          <button type="button" className="sw-cta" onClick={finish}>
            Finish Setup
          </button>
        ) : (
          <button
            type="button"
            className="sw-cta"
            disabled={installing}
            onClick={installCertificate}
          >
            {installing ? 'Installing…' : 'Install Certificate'}
          </button>
        )}
      </div>
    </div>
  );
}

/** True when the user has not yet completed the setup wizard. */
export function isSetupPending(): boolean {
  try {
    return window.localStorage.getItem(COMPLETION_KEY) !== 'true';
  } catch {
    return false;
  }
}
