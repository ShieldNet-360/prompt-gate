import { useCallback, useEffect, useState } from 'react';
import {
  agent,
  AgentPreferences,
  AgentProfile,
  CategoryPolicy,
  DLPConfig,
  PolicyAction,
  RuleOverrideLists,
} from '../api/agent';
import { CategoryToggle } from '../components/CategoryToggle';

// Redaction is built end-to-end in the engine + API, but the browser
// extension and MITM proxy don't yet consume `redacted_content` — so a
// "Redact" verdict isn't enforced on the wire. Hide the toggle until both
// consumers are wired, so users can't enable a setting that silently still
// blocks. Flip to true once extension + proxy apply redacted_content.
const REDACT_UI_ENABLED = false;

type FeedbackKind = 'success' | 'error';

interface Feedback {
  kind: FeedbackKind;
  message: string;
}

const DLP_KEYS: Array<{ key: keyof DLPConfig; label: string; min: number; max: number }> = [
  { key: 'threshold_critical', label: 'Critical threshold', min: 1, max: 10 },
  { key: 'threshold_high', label: 'High threshold', min: 1, max: 10 },
  { key: 'threshold_medium', label: 'Medium threshold', min: 1, max: 10 },
  { key: 'threshold_low', label: 'Low threshold', min: 1, max: 10 },
  { key: 'hotword_boost', label: 'Hotword boost', min: 0, max: 5 },
  { key: 'entropy_boost', label: 'Entropy boost', min: 0, max: 5 },
  { key: 'entropy_penalty', label: 'Entropy penalty', min: -5, max: 0 },
  { key: 'exclusion_penalty', label: 'Exclusion penalty', min: -5, max: 0 },
  { key: 'multi_match_boost', label: 'Multi-match boost', min: 0, max: 5 },
];

export function Settings() {
  const [policies, setPolicies] = useState<CategoryPolicy[] | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [profile, setProfile] = useState<AgentProfile | null>(null);
  const [dlp, setDLP] = useState<DLPConfig | null>(null);
  const [overrides, setOverrides] = useState<RuleOverrideLists | null>(null);
  const [overrideDomain, setOverrideDomain] = useState('');
  const [overrideList, setOverrideList] = useState<'allow' | 'block'>('block');
  const [prefs, setPrefs] = useState<AgentPreferences | null>(null);
  const [showConsent, setShowConsent] = useState(false);

  const load = useCallback(async () => {
    try {
      const [p, prof, cfg, ov, pr] = await Promise.all([
        agent.getPolicies(),
        agent.getProfile().catch(() => null),
        agent.getDLPConfig().catch(() => null),
        agent.listOverrides().catch(() => null),
        agent.getPreferences().catch(() => null),
      ]);
      setPolicies(p);
      setProfile(prof);
      setDLP(cfg);
      setOverrides(ov);
      setPrefs(pr);
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const locked = profile?.managed ?? false;

  const update = useCallback(
    async (category: string, action: PolicyAction) => {
      setPending(category);
      try {
        const updated = await agent.updatePolicy(category, action);
        setPolicies((prev) =>
          prev ? prev.map((p) => (p.category === category ? updated : p)) : prev,
        );
        setFeedback({ kind: 'success', message: `Saved: ${category}` });
      } catch (err) {
        setFeedback({ kind: 'error', message: String(err) });
      } finally {
        setPending(null);
      }
    },
    [],
  );

  const updateDLPField = useCallback(
    async (key: keyof DLPConfig, value: number) => {
      if (!dlp) return;
      const next: DLPConfig = { ...dlp, [key]: value };
      setDLP(next);
      try {
        const saved = await agent.updateDLPConfig(next);
        setDLP(saved);
        setFeedback({ kind: 'success', message: `Saved DLP ${key}` });
      } catch (err) {
        setFeedback({ kind: 'error', message: String(err) });
      }
    },
    [dlp],
  );

  const addOverride = useCallback(async () => {
    const domain = overrideDomain.trim();
    if (!domain) return;
    try {
      const next = await agent.addOverride(domain, overrideList);
      setOverrides(next);
      setOverrideDomain('');
      setFeedback({ kind: 'success', message: `Added ${domain} to ${overrideList}` });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, [overrideDomain, overrideList]);

  const removeOverride = useCallback(async (domain: string) => {
    try {
      const next = await agent.removeOverride(domain);
      setOverrides(next);
      setFeedback({ kind: 'success', message: `Removed ${domain}` });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  // Privacy carve-out: opt into the block-event history. The toggle
  // never flips on directly — clicking "Enable" opens a consent
  // modal that spells out exactly what gets persisted, and the user
  // has to confirm. Disable is one click (no modal) so revoking
  // consent is always frictionless.
  const requestEnableBlockEvents = useCallback(() => {
    setShowConsent(true);
  }, []);

  const confirmEnableBlockEvents = useCallback(async () => {
    try {
      const updated = await agent.setBlockEventsEnabled(true);
      setPrefs(updated);
      setShowConsent(false);
      setFeedback({ kind: 'success', message: 'Block event history enabled.' });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  const disableBlockEvents = useCallback(async () => {
    try {
      const updated = await agent.setBlockEventsEnabled(false);
      setPrefs(updated);
      setFeedback({ kind: 'success', message: 'Block event history disabled.' });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  // DLP action: block (default) vs redact. One click either way — the
  // agent's redactor is fail-closed, so anything it can't safely mask
  // still blocks even with redaction on.
  const setRedact = useCallback(async (enabled: boolean) => {
    try {
      const updated = await agent.setRedactEnabled(enabled);
      setPrefs(updated);
      setFeedback({
        kind: 'success',
        message: enabled
          ? 'Redaction on — secrets are masked and the rest is sent.'
          : 'Redaction off — detected secrets are blocked.',
      });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    }
  }, []);

  if (policies === null) {
    return <div className="page">Loading policies…</div>;
  }

  return (
    <div className="page">
      <h2>Categories</h2>
      {locked && (
        <div className="feedback feedback-error">
          Policies are managed by enterprise profile <strong>{profile?.name}</strong>.
          Local changes are disabled.
        </div>
      )}
      <p className="page-hint">
        Choose which traffic categories are allowed or blocked at the DNS layer.
      </p>
      {feedback && (
        <div
          className={`feedback feedback-${feedback.kind}`}
          role={feedback.kind === 'error' ? 'alert' : 'status'}
          aria-live={feedback.kind === 'error' ? 'assertive' : 'polite'}
        >
          {feedback.message}
        </div>
      )}
      <div className="category-list" role="list" aria-label="Traffic categories">
        {policies.map((p) => (
          <CategoryToggle
            key={p.category}
            policy={p}
            disabled={locked || pending === p.category}
            onChange={(action) => void update(p.category, action)}
          />
        ))}
      </div>

      {dlp && (
        <section className="dlp-section">
          <h2>DLP Scoring</h2>
          <p className="page-hint">
            Tune how aggressively the DLP pipeline classifies leaks. Higher
            thresholds make the agent stricter; boosts increase a match's
            score, penalties reduce it.
          </p>
          <div className="dlp-grid">
            {DLP_KEYS.map(({ key, label, min, max }) => (
              <label className="dlp-row" key={key}>
                <span>{label}</span>
                <input
                  type="range"
                  min={min}
                  max={max}
                  value={dlp[key]}
                  disabled={locked}
                  onChange={(e) => void updateDLPField(key, Number(e.target.value))}
                />
                <span className="dlp-value">{dlp[key]}</span>
              </label>
            ))}
          </div>
        </section>
      )}

      {overrides && (
        <section className="override-section">
          <h2>Admin Overrides</h2>
          <p className="page-hint">
            Allow or block individual domains regardless of category rules.
            Overrides live in <code>rules/local/</code> and survive bundled
            rule updates.
          </p>
          <div className="override-add" role="group" aria-label="Add domain override">
            <label htmlFor="override-domain-input" className="sr-only">
              Domain to override
            </label>
            <input
              id="override-domain-input"
              type="text"
              placeholder="example.com"
              value={overrideDomain}
              onChange={(e) => setOverrideDomain(e.target.value)}
              disabled={locked}
              aria-label="Domain to override"
              onKeyDown={(e) => {
                if (e.key === 'Enter') void addOverride();
              }}
            />
            <label htmlFor="override-list-select" className="sr-only">
              Override list
            </label>
            <select
              id="override-list-select"
              value={overrideList}
              disabled={locked}
              onChange={(e) => setOverrideList(e.target.value as 'allow' | 'block')}
              aria-label="Add to allow or block list"
            >
              <option value="allow">Allow</option>
              <option value="block">Block</option>
            </select>
            <button
              type="button"
              disabled={locked}
              onClick={() => void addOverride()}
              aria-label={`Add ${overrideDomain || 'domain'} to ${overrideList} list`}
            >
              Add
            </button>
          </div>

          <div className="override-lists">
            <div>
              <h3>Allow ({overrides.allow.length})</h3>
              <ul>
                {overrides.allow.map((d) => (
                  <li key={`a-${d}`}>
                    <code>{d}</code>
                    <button
                      type="button"
                      disabled={locked}
                      onClick={() => void removeOverride(d)}
                      aria-label={`Remove ${d} from allow list`}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h3>Block ({overrides.block.length})</h3>
              <ul>
                {overrides.block.map((d) => (
                  <li key={`b-${d}`}>
                    <code>{d}</code>
                    <button
                      type="button"
                      disabled={locked}
                      onClick={() => void removeOverride(d)}
                      aria-label={`Remove ${d} from block list`}
                    >
                      Remove
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>
      )}

      {REDACT_UI_ENABLED && prefs && (
        <section className="privacy-section">
          <h2>DLP action</h2>
          <p className="page-hint">
            What happens when a secret is detected in something you send to
            an AI tool.
          </p>

          <div className="privacy-row">
            <div className="privacy-row-text">
              <div className="privacy-row-title">
                {prefs.redact_enabled ? 'Redact secrets' : 'Block (default)'}
              </div>
              <div className="privacy-row-desc">
                {prefs.redact_enabled ? (
                  <>
                    The secret is replaced with a typed placeholder (e.g.{' '}
                    <code>[AWS_KEY_1]</code>) and the rest of your message is
                    sent. If a secret can&apos;t be safely masked, the message
                    is blocked instead.
                  </>
                ) : (
                  <>
                    The whole message is blocked when a secret is found.
                    Turn on redaction to mask just the secret and let the rest
                    through.
                  </>
                )}
              </div>
            </div>
            <div className="privacy-row-control">
              {prefs.managed ? (
                <span className="privacy-row-locked">Managed</span>
              ) : prefs.redact_enabled ? (
                <button
                  type="button"
                  className="privacy-toggle privacy-toggle-on"
                  onClick={() => void setRedact(false)}
                  aria-pressed="true"
                >
                  Redact
                </button>
              ) : (
                <button
                  type="button"
                  className="privacy-toggle privacy-toggle-off"
                  onClick={() => void setRedact(true)}
                  aria-pressed="false"
                >
                  Block
                </button>
              )}
            </div>
          </div>
        </section>
      )}

      {prefs && (
        <section className="privacy-section">
          <h2>Privacy</h2>
          <p className="page-hint">
            Prompt Gate persists nothing about your traffic by default — only
            anonymous aggregate counters. These controls let you opt into
            features that store more.
          </p>

          <div className="privacy-row">
            <div className="privacy-row-text">
              <div className="privacy-row-title">Block event history</div>
              <div className="privacy-row-desc">
                Records the destination domain and pattern name of each
                blocked event in local SQLite (last 500 events). Lets the
                Status page show what was blocked recently. Never uploaded.
                {prefs.block_events_consented_at > 0 && !prefs.block_events_enabled && (
                  <span className="privacy-row-meta">
                    {' '}Last consented{' '}
                    {new Date(prefs.block_events_consented_at * 1000).toLocaleString()}.
                  </span>
                )}
              </div>
            </div>
            <div className="privacy-row-control">
              {prefs.managed ? (
                <span className="privacy-row-locked">Managed</span>
              ) : prefs.block_events_enabled ? (
                <button
                  type="button"
                  className="privacy-toggle privacy-toggle-on"
                  onClick={() => void disableBlockEvents()}
                  aria-pressed="true"
                >
                  On
                </button>
              ) : (
                <button
                  type="button"
                  className="privacy-toggle privacy-toggle-off"
                  onClick={requestEnableBlockEvents}
                  aria-pressed="false"
                >
                  Off
                </button>
              )}
            </div>
          </div>
        </section>
      )}

      {showConsent && (
        <div
          className="modal-backdrop"
          role="dialog"
          aria-modal="true"
          aria-labelledby="consent-title"
          onClick={() => setShowConsent(false)}
        >
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3 id="consent-title">Enable block event history</h3>
            <p>For every block, this will record:</p>
            <ul className="consent-list">
              <li>The timestamp</li>
              <li>
                The destination domain (e.g. <code>chat.openai.com</code>)
              </li>
              <li>The pattern name that triggered the block</li>
            </ul>
            <p>
              Stored locally in SQLite. Last 500 events; older entries are
              auto-deleted. The data never leaves your device.
            </p>
            <p>
              You can disable this at any time from this Settings page. The
              privacy invariant for anonymous aggregate counters is unchanged.
            </p>
            <div className="modal-actions">
              <button type="button" onClick={() => setShowConsent(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="primary"
                onClick={() => void confirmEnableBlockEvents()}
              >
                Enable history
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
