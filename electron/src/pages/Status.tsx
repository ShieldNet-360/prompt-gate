import { useCallback, useEffect, useState } from 'react';
import { agent, AgentPreferences, AgentStatus, BlockEvent, Stats } from '../api/agent';
import { StatsCard } from '../components/StatsCard';

interface Snapshot {
  status: AgentStatus | null;
  stats: Stats | null;
  reachable: boolean;
  error?: string;
}

const empty: Snapshot = { status: null, stats: null, reachable: false };
const EVENT_LIMIT = 50;

export function Status() {
  const [snap, setSnap] = useState<Snapshot>(empty);
  const [events, setEvents] = useState<BlockEvent[]>([]);
  const [prefs, setPrefs] = useState<AgentPreferences | null>(null);
  const [resetting, setResetting] = useState(false);
  const [clearing, setClearing] = useState(false);

  const load = useCallback(async () => {
    try {
      const [status, stats, ev, pr] = await Promise.all([
        agent.getStatus(),
        agent.getStats(),
        agent.getBlockEvents(EVENT_LIMIT).catch(() => [] as BlockEvent[]),
        agent.getPreferences().catch(() => null),
      ]);
      setSnap({ status, stats, reachable: true });
      setEvents(ev);
      setPrefs(pr);
    } catch (err) {
      setSnap((prev) => ({ ...prev, reachable: false, error: String(err) }));
    }
  }, []);

  useEffect(() => {
    void load();
    const id = setInterval(() => void load(), 5000);
    return () => clearInterval(id);
  }, [load]);

  const reset = useCallback(async () => {
    setResetting(true);
    try {
      await agent.resetStats();
      await load();
    } finally {
      setResetting(false);
    }
  }, [load]);

  const clearHistory = useCallback(async () => {
    setClearing(true);
    try {
      await agent.clearBlockEvents();
      setEvents([]);
    } finally {
      setClearing(false);
    }
  }, []);

  return (
    <div className="page">
      <h2>Agent Status</h2>
      <div
        className={`status-banner status-banner-${snap.reachable ? 'ok' : 'error'}`}
        role="status"
        aria-live="polite"
      >
        {snap.reachable && snap.status
          ? `Running · v${snap.status.version} · uptime ${snap.status.uptime}`
          : `Agent unreachable${snap.error ? ` — ${snap.error}` : ''}`}
      </div>

      <h3>Anonymous Counters</h3>
      <p className="page-hint">
        Running totals persisted in the agent database.
      </p>
      <div className="stats-grid" role="list" aria-label="Anonymous counters">
        <StatsCard label="DNS queries" value={snap.stats?.dns_queries_total ?? '—'} />
        <StatsCard label="DNS blocks" value={snap.stats?.dns_blocks_total ?? '—'} />
        <StatsCard label="DLP scans" value={snap.stats?.dlp_scans_total ?? '—'} />
        <StatsCard label="DLP blocks" value={snap.stats?.dlp_blocks_total ?? '—'} />
      </div>
      <button
        type="button"
        className="reset-button"
        onClick={() => void reset()}
        disabled={resetting || !snap.reachable}
        aria-label="Reset all anonymous counters to zero"
      >
        {resetting ? 'Resetting…' : 'Reset Counters'}
      </button>

      <div className="block-history-header">
        <h3>Block History</h3>
        {events.length > 0 && (
          <button
            type="button"
            className="clear-history-btn"
            onClick={() => void clearHistory()}
            disabled={clearing || !snap.reachable}
          >
            {clearing ? (
              'Clearing…'
            ) : (
              <>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                  strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="3 6 5 6 21 6" />
                  <path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
                </svg>
                Clear
              </>
            )}
          </button>
        )}
      </div>

      {prefs && !prefs.block_events_enabled ? (
        <div className="block-history-disabled">
          <p className="page-hint">
            Block event history is <strong>off</strong> — the agent persists
            only anonymous aggregate counters, which is how it ships by
            default.
          </p>
          <p className="page-hint">
            To see what was blocked recently, enable the history toggle in{' '}
            <strong>Settings → Privacy</strong>. Stored locally; never
            uploaded.
          </p>
        </div>
      ) : (
        <>
          <p className="page-hint">
            Last {EVENT_LIMIT} block events. Includes DLP content blocks
            and category-deny blocks.
          </p>
          {events.length === 0 ? (
            <p className="page-hint">No block events recorded yet.</p>
          ) : (
            <div className="block-events-scroll">
              <table className="block-events-table" aria-label="Block event history">
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Type</th>
                    <th>Host</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((e) => (
                    <tr key={e.id}>
                      <td className="block-events-time">
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td>
                        <span className={`event-badge event-badge-${e.event_type}`}>
                          {e.event_type === 'dlp' ? 'DLP' : 'Category'}
                        </span>
                      </td>
                      <td className="block-events-host">{e.host}</td>
                      <td className="block-events-detail">{e.pattern_name}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
