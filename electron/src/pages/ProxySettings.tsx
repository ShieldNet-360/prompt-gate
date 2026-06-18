import { useCallback, useEffect, useState } from 'react';
import { agent, ProxyStatus } from '../api/agent';

// ProxySettings drives the "Advanced DLP" wizard. The actual MITM
// listener lives in the Go agent (`/api/proxy/*`); this component
// only orchestrates the lifecycle and shows install instructions.

type Feedback = { kind: 'success' | 'error'; message: string };
type BusyState = 'enable' | 'install-ca' | 'remove-ca' | 'proxy-toggle' | null;

function CheckCircle() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

export function ProxySettings() {
  const [status, setStatus] = useState<ProxyStatus | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [busy, setBusy] = useState<BusyState>(null);
  const [proxyOn, setProxyOn] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [s, sp] = await Promise.all([
        agent.getProxyStatus(),
        agent.getSystemProxy().catch(() => null),
      ]);
      setStatus(s);
      if (sp) setProxyOn(sp.active);
    } catch (err) {
      const msg = String(err);
      if (msg.includes('503')) {
        setStatus(null);
        setFeedback({ kind: 'error', message: 'Proxy is not configured on this agent.' });
      } else {
        setFeedback({ kind: 'error', message: msg });
      }
    }
  }, []);

  useEffect(() => {
    void refresh();
    const t = setInterval(() => void refresh(), 5000);
    return () => clearInterval(t);
  }, [refresh]);

  const toggleSystemProxy = useCallback(async () => {
    // Block turning ON when the MITM proxy listener isn't running —
    // otherwise all traffic routes to 127.0.0.1:8443 with nothing
    // listening and the user loses internet.
    if (!proxyOn && !status?.running) {
      setFeedback({ kind: 'error', message: 'Complete steps 1 & 2 before enabling system proxy.' });
      return;
    }
    setBusy('proxy-toggle');
    setFeedback(null);
    const action = proxyOn ? 'restore' : 'apply';
    try {
      const res = await agent.setSystemProxy(action);
      if (res.ok) {
        setProxyOn(res.active);
        setFeedback({ kind: 'success', message: res.message ?? (res.active ? 'System proxy enabled.' : 'System proxy disabled.') });
      } else {
        setFeedback({ kind: 'error', message: res.message ?? 'Failed to toggle system proxy.' });
      }
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setBusy(null);
    }
  }, [proxyOn, status]);

  const enable = useCallback(async () => {
    setBusy('enable');
    setFeedback(null);
    try {
      await agent.enableProxy();
      setFeedback({ kind: 'success', message: 'Proxy started. Now install the CA certificate (step 2).' });
      await refresh();
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setBusy(null);
    }
  }, [refresh]);

  const installCA = useCallback(async () => {
    setBusy('install-ca');
    setFeedback(null);
    try {
      const caPath = status?.ca_cert_path ?? '~/.prompt-gate/ca.crt';
      const res = await agent.installSystemCA('install', caPath);
      setFeedback({ kind: res.ok ? 'success' : 'error', message: res.message ?? 'CA installed.' });
      await refresh();
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setBusy(null);
    }
  }, [status, refresh]);

  const removeCA = useCallback(async () => {
    setBusy('remove-ca');
    setFeedback(null);
    try {
      const caPath = status?.ca_cert_path ?? '~/.prompt-gate/ca.crt';
      const res = await agent.installSystemCA('remove', caPath);
      setFeedback({ kind: res.ok ? 'success' : 'error', message: res.message ?? 'CA removed.' });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setBusy(null);
    }
  }, [status]);

  const step1Done = status?.running ?? false;
  const step2Done = status?.ca_installed ?? false;
  const step3Done = proxyOn;

  return (
    <div className="page">
      {/* Status summary card */}
      <div className={`proxy-summary-card ${proxyOn ? 'on' : 'off'}`}>
        <div className="proxy-summary-left">
          <div className={`proxy-summary-dot ${proxyOn ? 'on' : 'off'}`} />
          <div>
            <div className="proxy-summary-title">
              {proxyOn ? 'Proxy active' : 'Proxy inactive'}
            </div>
            <div className="proxy-summary-addr">
              {status?.listen_addr ?? '127.0.0.1:8443'}
            </div>
          </div>
        </div>
        <div className="proxy-summary-stats">
          <div className="proxy-summary-stat">
            <span className="proxy-summary-val">{status?.dlp_scans_total ?? 0}</span>
            <span className="proxy-summary-label">Scans</span>
          </div>
          <div className="proxy-summary-stat">
            <span className="proxy-summary-val">{status?.dlp_blocks_total ?? 0}</span>
            <span className="proxy-summary-label">Blocks</span>
          </div>
        </div>
      </div>

      {feedback && (
        <div
          className={`feedback feedback-${feedback.kind}`}
          role={feedback.kind === 'error' ? 'alert' : 'status'}
          aria-live={feedback.kind === 'error' ? 'assertive' : 'polite'}
        >
          {feedback.message}
        </div>
      )}

      {/* Step cards */}
      <div className="proxy-steps">
        {/* Step 1 */}
        <div className={`proxy-step-card ${step1Done ? 'done' : 'pending'}`}>
          <div className={`proxy-step-num ${step1Done ? 'done' : ''}`}>
            {step1Done ? <CheckCircle /> : '1'}
          </div>
          <div className="proxy-step-body">
            <div className="proxy-step-title">Start proxy listener</div>
            <div className="proxy-step-desc">
              Generate a CA key and start the MITM listener on port 8443
            </div>
          </div>
          <button
            type="button"
            className={`proxy-step-btn ${step1Done ? 'secondary' : 'primary'}`}
            onClick={() => void enable()}
            disabled={busy !== null}
          >
            {busy === 'enable' ? 'Starting…' : step1Done ? 'Regenerate' : 'Start'}
          </button>
        </div>

        {/* Step 2 */}
        <div className={`proxy-step-card ${step2Done ? 'done' : 'pending'}`}>
          <div className={`proxy-step-num ${step2Done ? 'done' : ''}`}>
            {step2Done ? <CheckCircle /> : '2'}
          </div>
          <div className="proxy-step-body">
            <div className="proxy-step-title">Install CA certificate</div>
            <div className="proxy-step-desc">
              Trust the local CA in your OS keychain so HTTPS inspection works
            </div>
            {status?.ca_cert_path && (
              <code className="proxy-step-path">{status.ca_cert_path}</code>
            )}
          </div>
          <div className="proxy-step-actions">
            <button
              type="button"
              className={`proxy-step-btn ${step2Done ? 'secondary' : 'primary'}`}
              onClick={() => void installCA()}
              disabled={busy !== null || !step1Done}
              title={!step1Done ? 'Start the proxy first' : undefined}
            >
              {busy === 'install-ca' ? 'Installing…' : step2Done ? 'Reinstall' : 'Install'}
            </button>
            {step2Done && (
              <button
                type="button"
                className="proxy-step-btn danger"
                onClick={() => void removeCA()}
                disabled={busy !== null}
              >
                {busy === 'remove-ca' ? 'Removing…' : 'Remove'}
              </button>
            )}
          </div>
        </div>

        {/* Step 3 */}
        <div className={`proxy-step-card ${step3Done ? 'done' : 'pending'}`}>
          <div className={`proxy-step-num ${step3Done ? 'done' : ''}`}>
            {step3Done ? <CheckCircle /> : '3'}
          </div>
          <div className="proxy-step-body">
            <div className="proxy-step-title">Enable system proxy</div>
            <div className="proxy-step-desc">
              Route HTTPS traffic through the local proxy for DLP inspection
            </div>
          </div>
          <button
            type="button"
            className={`proxy-step-btn ${step3Done ? 'danger' : 'primary'}`}
            onClick={() => void toggleSystemProxy()}
            disabled={busy !== null || (!step3Done && !step1Done)}
            title={!step3Done && !step1Done ? 'Complete steps 1 & 2 first' : undefined}
          >
            {busy === 'proxy-toggle' ? 'Switching…' : step3Done ? 'Disable' : 'Enable'}
          </button>
        </div>
      </div>
    </div>
  );
}
