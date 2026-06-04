import { useCallback, useEffect, useState } from 'react';
import { agent, ProxyStatus } from '../api/agent';

// ProxySettings drives the "Advanced DLP" wizard. The actual MITM
// listener lives in the Go agent (`/api/proxy/*`); this component
// only orchestrates the lifecycle and shows install instructions.

type Feedback = { kind: 'success' | 'error'; message: string };
type BusyState =
  | 'enable'
  | 'install-ca'
  | 'remove-ca'
  | 'proxy-toggle'
  | null;

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
        setFeedback({
          kind: 'error',
          message: 'Proxy is not configured on this agent.',
        });
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
      setFeedback({ kind: 'error', message: 'Start the proxy listener first (step 1) before enabling system proxy.' });
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
      setFeedback({ kind: 'success', message: 'CA certificate generated. Now install it into the OS trust store (step 2).' });
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

  return (
    <div className="page">
      <div className="proxy-header">
        <div>
          <h2>Advanced DLP (Local Proxy)</h2>
          <p className="page-hint">
            Inspect Tier-2 AI traffic via a local MITM proxy on{' '}
            <code>127.0.0.1:8443</code>.
          </p>
        </div>
        <button
          type="button"
          className={`proxy-toggle ${proxyOn ? 'proxy-toggle-on' : 'proxy-toggle-off'}`}
          onClick={() => void toggleSystemProxy()}
          disabled={busy !== null || (!proxyOn && !status?.running)}
          title={!proxyOn && !status?.running ? 'Start the proxy listener first (step 1)' : undefined}
        >
          {busy === 'proxy-toggle'
            ? 'Switching...'
            : proxyOn
              ? 'Proxy ON'
              : 'Proxy OFF'}
        </button>
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

      <section className="proxy-status">
        <h3>Status</h3>
        <ul>
          <li>
            Running: <strong>{status?.running ? 'yes' : 'no'}</strong>
          </li>
          <li>
            CA on disk: <strong>{status?.ca_installed ? 'yes' : 'no'}</strong>
          </li>
          <li>
            System proxy: <strong>{proxyOn ? 'active' : 'off'}</strong>
          </li>
          <li>
            Listen address: <code>{status?.listen_addr ?? '127.0.0.1:8443'}</code>
          </li>
          <li>
            DLP scans / blocks via proxy:{' '}
            <strong>
              {status?.dlp_scans_total ?? 0} / {status?.dlp_blocks_total ?? 0}
            </strong>
          </li>
        </ul>
      </section>

      <section className="proxy-wizard">
        <h3>Setup</h3>
        <ol>
          <li>
            <button
              type="button"
              onClick={() => void enable()}
              disabled={busy !== null}
            >
              {status?.running ? 'Regenerate CA' : 'Generate CA certificate'}
            </button>
          </li>
          <li>
            <span>Install the CA cert into your OS trust store:</span>
            <div className="proxy-buttons" style={{ marginTop: 6 }}>
              <button
                type="button"
                onClick={() => void installCA()}
                disabled={busy !== null || !status?.ca_installed}
              >
                {busy === 'install-ca' ? 'Installing...' : 'Install CA certificate'}
              </button>
              <button
                type="button"
                onClick={() => void removeCA()}
                disabled={busy !== null || !status?.ca_installed}
                style={{ marginLeft: 8 }}
              >
                {busy === 'remove-ca' ? 'Removing...' : 'Remove CA certificate'}
              </button>
            </div>
            {!status?.ca_installed && (
              <small style={{ color: '#888' }}>Start the proxy first to generate the CA.</small>
            )}
          </li>
        </ol>
      </section>
    </div>
  );
}
