// Shared DLP-scan helper for every content-script interceptor.
//
// Each interceptor (paste, form, fetch/XHR) calls scanContent(text)
// and treats `null` as "fall open" (allow the action). The transport
// preference is:
//
//   1. chrome.runtime.sendMessage to the background service worker,
//      which tries Native Messaging first and falls back to HTTP.
//      This avoids CORS on Tier-2 AI pages entirely — the worker
//      runs in the extension origin, not the page origin.
//   2. Direct fetch() to http://127.0.0.1:9191/api/dlp/scan from the
//      content script. Works when the background worker is asleep
//      and the page's origin is in the agent's CORS allowlist.
//
// Either path returning a non-null ScanResult is authoritative.

import { AGENT_BASE, ScanReply, ScanRequest, ScanResult, SourceContext } from "../shared.js";

/** Single-scan timeout. The Tier-2 AI pages are interactive — if
 *  the agent doesn't answer within this budget we fall open so we
 *  don't freeze the user's typing / submission. */
const SCAN_TIMEOUT_MS = 1500;

/** Maximum content size sent to the agent. Anything larger is
 *  silently allowed — not a realistic prompt and an obvious
 *  memory-exhaustion vector for the agent. */
export const MAX_SCAN_BYTES = 1 * 1024 * 1024; // 1 MiB

/** Per-tab session ID generated once at content-script load. Sent with
 *  every scan request so the agent's correlator can reassemble
 *  secrets split across consecutive pastes from the same tab.
 *
 *  Each content script (paste/form/network/drag/clipboard) loads once
 *  per tab navigation, giving exactly one session per tab+URL. The
 *  identifier is opaque, in-memory only, and never sent to any host
 *  other than the local loopback agent.
 */
export const SESSION_ID: string = generateSessionID();

function generateSessionID(): string {
    // The session id is a per-tab correlation token (opaque, in-memory,
    // sent only to the local loopback agent) — not a security secret. We
    // still source it from Web Crypto so there is no weak randomness in
    // the codebase. crypto is always present in an extension content
    // script (a secure context); the non-random tail is an unreachable
    // safety net, never Math.random.
    if (typeof crypto !== "undefined") {
        if (typeof crypto.randomUUID === "function") {
            return crypto.randomUUID();
        }
        if (typeof crypto.getRandomValues === "function") {
            const b = new Uint8Array(16);
            crypto.getRandomValues(b);
            return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
        }
    }
    return Date.now().toString(36) + "-" + performance.now().toString(36);
}

/** Scan `content` through the local agent's DLP pipeline.
 *  Returns null on any transport failure (fall-open).
 *
 *  source is the destination/element/path context.
 *  Optional — when absent, the agent runs the default scoring path
 *  unchanged. Each interceptor builds its own via
 *  buildSourceContext() in ./source-context.ts. */
export async function scanContent(
    content: string,
    source?: SourceContext,
): Promise<ScanResult | null> {
    if (content.length === 0 || content.length > MAX_SCAN_BYTES) return null;

    // Path 1: route through the background service worker so Native
    // Messaging is tried before HTTP. The worker owns the long-lived
    // port; content scripts can't open connectNative() themselves.
    const viaWorker = await scanViaWorker(content, source);
    if (viaWorker !== undefined) return viaWorker;

    // Path 2: direct loopback fetch. Same shape as the worker's HTTP
    // fallback, but inlined so a sleeping worker doesn't lose us a scan.
    return scanViaHTTP(content, source);
}

async function scanViaWorker(
    content: string,
    source: SourceContext | undefined,
): Promise<ScanResult | null | undefined> {
    const runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    if (!runtime || typeof runtime.sendMessage !== "function") return undefined;
    try {
        const req: ScanRequest = {
            kind: "scan",
            content,
            session_id: SESSION_ID,
            ...(source ? { source } : {}),
        };
        const reply = (await runtime.sendMessage(req)) as ScanReply | undefined;
        if (reply && reply.kind === "scan-result") return reply.result;
    } catch {
        // service worker not listening, no receiving end, etc. —
        // fall through to HTTP.
    }
    return undefined;
}

async function scanViaHTTP(
    content: string,
    source: SourceContext | undefined,
): Promise<ScanResult | null> {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), SCAN_TIMEOUT_MS);
    try {
        const body: Record<string, unknown> = {
            content,
            session_id: SESSION_ID,
        };
        if (source) body.source = source;
        const r = await fetch(`${AGENT_BASE}/api/dlp/scan`, {
            method: "POST",
            mode: "cors",
            credentials: "omit",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
            signal: ctl.signal,
        });
        if (!r.ok) return null;
        return (await r.json()) as ScanResult;
    } catch {
        return null;
    } finally {
        clearTimeout(timer);
    }
}

// Export for tests; not part of the production entrypoint surface.
export const __test__ = { scanViaWorker, scanViaHTTP, SCAN_TIMEOUT_MS, generateSessionID };
