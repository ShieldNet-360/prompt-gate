// Dynamic Tier-2 host updates (Phase 6 Task 12).
//
// The companion extension ships with a static manifest match list for
// the well-known AI tools, but enterprise users can add their own
// Tier-2 domains through the agent's rule file. On startup and at a
// fixed polling interval the background worker fetches
// /api/rules/status, diffs the returned Tier-2 host list against
// `TIER2_HOSTNAMES`, and uses chrome.scripting.registerContentScripts
// to inject the existing content scripts into the new hosts WITHOUT
// requiring the extension to be reloaded.
//
// Privacy invariant: the only state persisted across runs is the host
// list itself (via chrome.storage.session). We never persist scan
// content, scan results, or per-host counters.

import { AGENT_BASE, TIER2_HOSTNAMES } from "../shared.js";

/** How often to poll the agent for rule updates. The agent itself
 *  refreshes every 6 hours by default, so 15 minutes here is a
 *  comfortable overshoot. */
const POLL_INTERVAL_MS = 15 * 60 * 1000;

/** Scripting registration ID for the dynamic Tier-2 content scripts.
 *  Single registration is replaced wholesale on each successful poll. */
const DYNAMIC_SCRIPT_ID = "prompt-gate-tier2-dynamic";

interface RulesStatus {
    rule_version?: string;
    tier2_hosts?: string[];
}

let pollTimer: ReturnType<typeof setInterval> | null = null;

/** Start the polling loop. Idempotent. */
export function startDynamicHostUpdater(): void {
    if (pollTimer !== null) return;
    void pollOnce();
    pollTimer = setInterval(() => void pollOnce(), POLL_INTERVAL_MS);
    // In a Node test harness the interval would keep the event loop
    // alive and time the test runner out. unref() is a no-op in the
    // service worker so this is safe in production.
    const t = pollTimer as { unref?: () => void };
    if (typeof t.unref === "function") t.unref();
}

/** Stop the polling loop. Used by tests. */
export function stopDynamicHostUpdater(): void {
    if (pollTimer !== null) {
        clearInterval(pollTimer);
        pollTimer = null;
    }
}

export async function pollOnce(): Promise<string[]> {
    let body: RulesStatus | null = null;
    try {
        const r = await fetch(`${AGENT_BASE}/api/rules/status`, {
            mode: "cors",
            credentials: "omit",
        });
        if (!r.ok) return [];
        body = (await r.json()) as RulesStatus;
    } catch {
        return [];
    }
    const dynamic = diffHosts(body?.tier2_hosts ?? []);
    if (dynamic.length === 0) {
        await unregisterDynamic();
        return [];
    }
    await registerDynamic(dynamic);
    return dynamic;
}

export function diffHosts(remote: ReadonlyArray<string>): string[] {
    const known = new Set(TIER2_HOSTNAMES.map((h) => h.toLowerCase()));
    const out: string[] = [];
    for (const h of remote) {
        const lower = h.trim().toLowerCase();
        if (!lower || known.has(lower)) continue;
        if (!isLikelyHostname(lower)) continue;
        out.push(lower);
    }
    return out;
}

function isLikelyHostname(s: string): boolean {
    // very small sanity filter — reject schemes, paths, wildcards and
    // anything that does not look like a registrable host.
    if (s.includes("/") || s.includes(" ") || s.includes("\t")) return false;
    if (!s.includes(".")) return false;
    return /^[a-z0-9.\-]+$/.test(s);
}

async function registerDynamic(hosts: string[]): Promise<void> {
    const scripting = chrome.scripting;
    if (!scripting || !scripting.registerContentScripts) return;
    const matches = hosts.map((h) => `https://${h}/*`);
    try {
        await scripting.unregisterContentScripts({ ids: [DYNAMIC_SCRIPT_ID] });
    } catch {
        // not registered yet — ignore.
    }
    try {
        await scripting.registerContentScripts([
            {
                id: DYNAMIC_SCRIPT_ID,
                matches,
                js: [
                    "dist/content/paste-interceptor.js",
                    "dist/content/form-interceptor.js",
                    "dist/content/drag-interceptor.js",
                ],
                runAt: "document_idle",
                allFrames: false,
            },
        ]);
    } catch {
        // unrecoverable — surfaced on next poll if it persists.
    }
}

async function unregisterDynamic(): Promise<void> {
    const scripting = chrome.scripting;
    if (!scripting || !scripting.unregisterContentScripts) return;
    try {
        await scripting.unregisterContentScripts({ ids: [DYNAMIC_SCRIPT_ID] });
    } catch {
        // already gone — ignore.
    }
}

export const __test__ = { diffHosts, isLikelyHostname };
