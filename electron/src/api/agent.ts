// Thin HTTP client for the Go agent on localhost. Works both inside
// Electron (uses the secure preload bridge) and in a vanilla browser
// dev environment (falls back to a sensible default URL).

export type PolicyAction = 'allow' | 'allow_with_dlp' | 'deny';

export interface CategoryPolicy {
  category: string;
  action: PolicyAction;
}

export interface Stats {
  dns_queries_total: number;
  dns_blocks_total: number;
  dlp_scans_total: number;
  dlp_blocks_total: number;
  tamper_detections_total?: number;
}

export interface DLPConfig {
  threshold_critical: number;
  threshold_high: number;
  threshold_medium: number;
  threshold_low: number;
  hotword_boost: number;
  entropy_boost: number;
  entropy_penalty: number;
  exclusion_penalty: number;
  multi_match_boost: number;
}

export interface TamperStatus {
  dns_ok: boolean;
  proxy_ok: boolean;
  last_check: string;
  detections_total: number;
}

export interface RuleOverrideLists {
  allow: string[];
  block: string[];
}

export interface AgentProfile {
  name: string;
  version: string;
  managed: boolean;
  categories?: Record<string, PolicyAction>;
}

export interface AgentStatus {
  status: string;
  uptime: string;
  version: string;
  runtime?: {
    go_version: string;
    num_goroutine: number;
    num_cpu: number;
    heap_alloc_kb: number;
    heap_inuse_kb: number;
    sys_kb: number;
    num_gc: number;
    gomaxprocs: number;
  };
  rules?: Array<{ path: string; size_bytes: number; last_modified: string }>;
  dlp_patterns?: number;
}

// RulesStatus mirrors agent.api / rules.Status. Used by the Rules
// page to show the active rule version and the next check time.
export interface RulesStatus {
  current_version: string;
  last_check: string;
  next_check: string;
  update_url: string;
}

// Rule file with content for the Rules editor.
export interface RuleFile {
  name: string;
  path: string;
  content: string;
  size_bytes: number;
  last_modified: string;
}

// Block event persisted to SQLite by the agent. Only emitted when
// AgentPreferences.block_events_enabled is true — see the consent
// flow on the Settings page.
export interface BlockEvent {
  id: number;
  timestamp: string;
  event_type: string; // "dlp" or "category"
  host: string;
  pattern_name: string;
  action: string;
}

// AgentPreferences mirrors the singleton agent_preferences row plus
// the read-only `managed` flag derived from the loaded enterprise
// profile. The UI uses `managed` to grey out the toggle.
export interface AgentPreferences {
  block_events_enabled: boolean;
  block_events_consented_at: number; // unix seconds; 0 = never consented
  redact_enabled: boolean; // false = block (default); true = mask + send
  managed: boolean;
}

// ProxyStatus mirrors agent.api.ProxyStatus on the wire.
export interface ProxyStatus {
  running: boolean;
  ca_installed: boolean;
  proxy_configured: boolean;
  listen_addr: string;
  ca_cert_path?: string;
  dlp_scans_total: number;
  dlp_blocks_total: number;
}

export interface ProxyEnableResponse {
  ca_cert_path: string;
}

const DEFAULT_BASE =
  (typeof window !== 'undefined' && (window as { __SECURE_EDGE_AGENT__?: string }).__SECURE_EDGE_AGENT__) ||
  'http://127.0.0.1:9191';

async function baseURL(): Promise<string> {
  if (typeof window !== 'undefined' && window.secureEdge?.getAgentBase) {
    try {
      return await window.secureEdge.getAgentBase();
    } catch {
      /* fall through */
    }
  }
  return DEFAULT_BASE;
}

const AGENT_TOKEN = 'prompt-gate-local-token-2025';

async function agentToken(): Promise<string> {
  return AGENT_TOKEN;
}

async function http<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${await baseURL()}${path}`;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string> ?? {}),
  };
  // SE-02/SE-06: attach bearer token. Mutating requests require it
  // (SE-02), and null-origin GET requests need it too (SE-06 —
  // Electron renderer loaded from file:// sends Origin: null).
  const token = await agentToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  // Timeout: 15 s prevents the UI from hanging indefinitely when the
  // agent is unreachable or a privileged call (e.g. CA install) blocks.
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 15_000);
  let res: Response;
  try {
    res = await fetch(url, {
      ...init,
      headers,
      signal: controller.signal,
    });
  } catch (err: any) {
    clearTimeout(timer);
    if (err?.name === 'AbortError') {
      throw new Error(`Agent unreachable: request to ${path} timed out after 15 s`);
    }
    throw new Error(`Agent unreachable: ${err?.message ?? err}`);
  }
  clearTimeout(timer);
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`Agent ${res.status}: ${text || res.statusText}`);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

export const agent = {
  async getStatus(): Promise<AgentStatus> {
    return http<AgentStatus>('/api/status');
  },
  async getPolicies(): Promise<CategoryPolicy[]> {
    return http<CategoryPolicy[]>('/api/policies');
  },
  async updatePolicy(category: string, action: PolicyAction): Promise<CategoryPolicy> {
    return http<CategoryPolicy>(
      `/api/policies/${encodeURIComponent(category)}`,
      { method: 'PUT', body: JSON.stringify({ action }) },
    );
  },
  async getStats(): Promise<Stats> {
    return http<Stats>('/api/stats');
  },
  async resetStats(): Promise<Stats> {
    return http<Stats>('/api/stats/reset', { method: 'POST' });
  },
  async getProxyStatus(): Promise<ProxyStatus> {
    return http<ProxyStatus>('/api/proxy/status');
  },
  async enableProxy(): Promise<ProxyEnableResponse> {
    return http<ProxyEnableResponse>('/api/proxy/enable', { method: 'POST' });
  },
  async disableProxy(removeCA: boolean): Promise<ProxyStatus> {
    return http<ProxyStatus>('/api/proxy/disable', {
      method: 'POST',
      body: JSON.stringify({ remove_ca: removeCA }),
    });
  },

  // Phase 5: DLP scoring threshold tuning.
  async getDLPConfig(): Promise<DLPConfig> {
    return http<DLPConfig>('/api/dlp/config');
  },
  async updateDLPConfig(cfg: DLPConfig): Promise<DLPConfig> {
    return http<DLPConfig>('/api/dlp/config', {
      method: 'PUT',
      body: JSON.stringify(cfg),
    });
  },

  // Phase 5: tamper detection.
  async getTamperStatus(): Promise<TamperStatus> {
    return http<TamperStatus>('/api/tamper/status');
  },

  // Phase 5: enterprise profile.
  async getProfile(): Promise<AgentProfile | null> {
    try {
      return await http<AgentProfile>('/api/profile');
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Agent 404')) {
        return null;
      }
      throw err;
    }
  },

  // Phase 5: admin allow/block override list.
  async listOverrides(): Promise<RuleOverrideLists> {
    return http<RuleOverrideLists>('/api/rules/override');
  },
  async addOverride(domain: string, list: 'allow' | 'block'): Promise<RuleOverrideLists> {
    return http<RuleOverrideLists>('/api/rules/override', {
      method: 'POST',
      body: JSON.stringify({ domain, list }),
    });
  },
  async removeOverride(domain: string): Promise<RuleOverrideLists> {
    return http<RuleOverrideLists>(`/api/rules/override/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
    });
  },

  // System CA install/remove — calls the Go agent which manages the OS trust store directly.
  async installSystemCA(action: 'install' | 'remove', caPath: string): Promise<{ ok: boolean; message?: string }> {
    return http<{ ok: boolean; message?: string }>('/api/system/ca', {
      method: 'POST',
      body: JSON.stringify({ action, ca_path: caPath }),
    });
  },

  // System proxy on/off — calls the Go agent which configures the OS directly.
  async getSystemProxy(): Promise<{ ok: boolean; active: boolean; message?: string }> {
    return http<{ ok: boolean; active: boolean; message?: string }>('/api/system/proxy');
  },
  async setSystemProxy(action: 'apply' | 'restore'): Promise<{ ok: boolean; active: boolean; message?: string }> {
    return http<{ ok: boolean; active: boolean; message?: string }>('/api/system/proxy', {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
  },

  // System DNS on/off — calls the Go agent which configures the OS directly.
  async getSystemDNS(): Promise<{ ok: boolean; active: boolean; message?: string }> {
    return http<{ ok: boolean; active: boolean; message?: string }>('/api/system/dns');
  },
  async setSystemDNS(action: 'apply' | 'restore'): Promise<{ ok: boolean; active: boolean; message?: string }> {
    return http<{ ok: boolean; active: boolean; message?: string }>('/api/system/dns', {
      method: 'POST',
      body: JSON.stringify({ action }),
    });
  },

  // Phase 6: read-only rules viewer for the Electron Rules page.
  async getRulesStatus(): Promise<RulesStatus | null> {
    try {
      return await http<RulesStatus>('/api/rules/status');
    } catch (err) {
      if (err instanceof Error && err.message.startsWith('Agent 503')) {
        // No updater wired on this build — show "n/a" in the UI.
        return null;
      }
      throw err;
    }
  },

  // Rule file content viewer/editor.
  async getRuleFiles(): Promise<RuleFile[]> {
    return http<RuleFile[]>('/api/rules/files');
  },
  async updateRuleFile(name: string, content: string): Promise<RuleFile> {
    return http<RuleFile>(`/api/rules/files/${encodeURIComponent(name)}`, {
      method: 'PUT',
      body: JSON.stringify({ content }),
    });
  },

  // Persisted block event history. Empty array unless the user has
  // opted in via setBlockEventsEnabled — the agent silently drops
  // every write while preferences.block_events_enabled is false.
  async getBlockEvents(limit = 50): Promise<BlockEvent[]> {
    return http<BlockEvent[]>(`/api/block-events?limit=${limit}`);
  },
  async clearBlockEvents(): Promise<void> {
    await http('/api/block-events', { method: 'DELETE' });
  },

  // Privacy-invariant carve-out: opt-in event-log consent.
  async getPreferences(): Promise<AgentPreferences> {
    return http<AgentPreferences>('/api/preferences');
  },
  async setBlockEventsEnabled(enabled: boolean): Promise<AgentPreferences> {
    return http<AgentPreferences>('/api/preferences/block-events', {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
  },

  // DLP action on a detected secret: block (default) vs redact (mask
  // the secret, send the rest). Persisted in agent_preferences.
  async setRedactEnabled(enabled: boolean): Promise<AgentPreferences> {
    return http<AgentPreferences>('/api/preferences/redact-mode', {
      method: 'PUT',
      body: JSON.stringify({ enabled }),
    });
  },

  // Setup wizard: apply a protection plan preset ("extra" or "light").
  async applyProtectionPlan(plan: 'extra' | 'light'): Promise<{ plan: string; status: string }> {
    return http<{ plan: string; status: string }>('/api/protection-plan', {
      method: 'POST',
      body: JSON.stringify({ plan }),
    });
  },
};
