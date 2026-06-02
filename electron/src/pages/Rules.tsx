import { useCallback, useEffect, useState } from 'react';
import { agent, AgentStatus, RulesStatus, RuleFile } from '../api/agent';

type FeedbackKind = 'success' | 'error';
interface Feedback {
  kind: FeedbackKind;
  message: string;
}

export function Rules() {
  const [status, setStatus] = useState<AgentStatus | null>(null);
  const [rulesStatus, setRulesStatus] = useState<RulesStatus | null>(null);
  const [files, setFiles] = useState<RuleFile[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<Feedback | null>(null);

  const load = useCallback(async () => {
    try {
      const [s, rs, rf] = await Promise.all([
        agent.getStatus(),
        agent.getRulesStatus(),
        agent.getRuleFiles().catch(() => null),
      ]);
      setStatus(s);
      setRulesStatus(rs);
      if (rf) setFiles(rf);
      setLoading(false);
    } catch (err) {
      setError(String(err));
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 30000);
    return () => clearInterval(id);
  }, [load]);

  const toggle = (name: string) => {
    setExpanded((prev) => (prev === name ? null : name));
  };

  const handleDraftChange = (name: string, content: string) => {
    setDrafts((prev) => ({ ...prev, [name]: content }));
  };

  const save = useCallback(async (name: string) => {
    const content = drafts[name];
    if (content === undefined) return;
    setSaving(name);
    try {
      const updated = await agent.updateRuleFile(name, content);
      setFiles((prev) =>
        prev ? prev.map((f) => (f.name === name ? updated : f)) : prev,
      );
      setDrafts((prev) => {
        const next = { ...prev };
        delete next[name];
        return next;
      });
      setFeedback({ kind: 'success', message: `Saved ${name}` });
    } catch (err) {
      setFeedback({ kind: 'error', message: String(err) });
    } finally {
      setSaving(null);
    }
  }, [drafts]);

  if (loading) {
    return (
      <div className="page">
        <h2>Rules</h2>
        <p className="page-hint">Loading…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="page">
        <h2>Rules</h2>
        <p className="page-hint" role="alert">
          Could not reach the agent: {error}
        </p>
      </div>
    );
  }

  return (
    <div className="page">
      <h2>Rules</h2>
      <p className="page-hint">
        View and edit domain rule files. Changes are saved to disk and
        applied immediately.
      </p>

      {feedback && (
        <div
          className={`feedback feedback-${feedback.kind}`}
          role={feedback.kind === 'error' ? 'alert' : 'status'}
        >
          {feedback.message}
        </div>
      )}

      <div className="stats-grid">
        <div className="stats-card">
          <div className="stats-card-value">{rulesStatus?.current_version || 'local'}</div>
          <div className="stats-card-label">Rule manifest version</div>
        </div>
        <div className="stats-card">
          <div className="stats-card-value">{status?.dlp_patterns ?? '—'}</div>
          <div className="stats-card-label">DLP patterns loaded</div>
        </div>
      </div>

      <h3>Rule files</h3>
      {(!files || files.length === 0) ? (
        <p className="page-hint">No rule files reported by the agent.</p>
      ) : (
        <div className="category-list" role="list" aria-label="Rule files">
          {files.map((f) => {
            const isOpen = expanded === f.name;
            const draft = drafts[f.name];
            const dirty = draft !== undefined && draft !== f.content;
            const isSaving = saving === f.name;
            return (
              <div key={f.name} className="rule-file-card" role="listitem">
                <button
                  type="button"
                  className="rule-file-header"
                  onClick={() => toggle(f.name)}
                  aria-expanded={isOpen}
                >
                  <span className="rule-file-name">{f.name}</span>
                  <span className="page-hint">
                    {(f.size_bytes / 1024).toFixed(1)} KiB ·{' '}
                    {new Date(f.last_modified).toLocaleString()}
                  </span>
                  <span className="rule-file-chevron">{isOpen ? '▾' : '▸'}</span>
                </button>
                {isOpen && (
                  <div className="rule-file-body">
                    <textarea
                      className="rule-file-editor"
                      value={draft ?? f.content}
                      onChange={(e) => handleDraftChange(f.name, e.target.value)}
                      spellCheck={false}
                      rows={Math.min(Math.max((draft ?? f.content).split('\n').length + 1, 6), 24)}
                    />
                    <div className="rule-file-actions">
                      {dirty && (
                        <button
                          type="button"
                          className="btn-discard"
                          onClick={() =>
                            setDrafts((prev) => {
                              const next = { ...prev };
                              delete next[f.name];
                              return next;
                            })
                          }
                        >
                          Discard
                        </button>
                      )}
                      <button
                        type="button"
                        disabled={!dirty || isSaving}
                        onClick={() => void save(f.name)}
                      >
                        {isSaving ? 'Saving…' : 'Save'}
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
