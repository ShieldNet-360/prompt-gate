// Background service worker for the Prompt Gate companion extension.
//
// Responsibilities (MV3):
//   1. Reply to popup "ping" requests with the agent /api/status payload.
//   2. Reply to content-script "scan" requests by trying Native Messaging
//      first, falling back to HTTP. This is the only place in the
//      extension that owns the chrome.runtime.connectNative port — content
//      scripts cannot open native connections themselves.
//   3. Surface a clear connection error when the local agent is down.

import {
    AGENT_BASE,
    PopupRequest,
    PopupReply,
    ScanRequest,
    ScanReply,
    ScanResult,
    SourceContext,
    StatusResponse,
} from "../shared.js";
import { scanViaNativeMessaging } from "./native-messaging.js";
import { startDynamicHostUpdater } from "./dynamic-hosts.js";

// Boot the dynamic Tier-2 host updater. Polls /api/rules/status and
// registers content scripts for any custom hosts the agent's rule
// file adds at runtime — no extension reload needed (Phase 6 Task 12).
try {
    startDynamicHostUpdater();
} catch {
    // chrome.scripting may be unavailable in the test harness; the
    // catch keeps service-worker boot quiet in that environment.
}

type IncomingMessage = PopupRequest | ScanRequest;
type OutgoingReply = PopupReply | ScanReply;

chrome.runtime.onMessage.addListener(
    (msg: IncomingMessage, _sender, sendResponse: (reply: OutgoingReply) => void) => {
        if (msg && msg.kind === "ping") {
            void pingAgent().then(sendResponse);
            return true; // keep the channel open for the async reply
        }
        if (msg && msg.kind === "scan") {
            void handleScan(msg.content, msg.session_id, msg.source).then((result) =>
                sendResponse({ kind: "scan-result", result }),
            );
            return true;
        }
        sendResponse({ kind: "error", message: `unknown message: ${JSON.stringify(msg)}` });
        return false;
    },
);

async function pingAgent(): Promise<PopupReply> {
    try {
        const r = await fetch(`${AGENT_BASE}/api/status`, {
            method: "GET",
            mode: "cors",
            credentials: "omit",
        });
        if (!r.ok) {
            return { kind: "error", message: `agent returned HTTP ${r.status}` };
        }
        const body = (await r.json()) as StatusResponse;
        return {
            kind: "ok",
            version: body.version ?? "unknown",
            uptime_seconds: body.uptime_seconds ?? 0,
        };
    } catch (err) {
        return {
            kind: "error",
            message: err instanceof Error ? err.message : "agent unreachable",
        };
    }
}

/** Try Native Messaging first, fall back to loopback HTTP. Returns
 *  null on any failure so the content script can fall open. sessionID
 *  is the content-script's per-tab token (see scan-client SESSION_ID)
 *  and is forwarded unchanged to whichever transport the worker uses.
 *  source is the Phase 8 Config F destination/element/path context;
 *  forwarded to HTTP only (Native Messaging schema lives in
 *  agent/internal/api/nativemsg.go and is extended separately if /
 *  when the same source plumbing is needed there). */
export async function handleScan(
    content: string,
    sessionID?: string,
    source?: SourceContext,
): Promise<ScanResult | null> {
    const native = await scanViaNativeMessaging(content);
    if (native !== null) return native;
    return scanViaHTTP(content, sessionID, source);
}

async function scanViaHTTP(
    content: string,
    sessionID?: string,
    source?: SourceContext,
): Promise<ScanResult | null> {
    try {
        const body: Record<string, unknown> = { content };
        if (sessionID) {
            body.session_id = sessionID;
        }
        if (source) {
            body.source = source;
        }
        const r = await fetch(`${AGENT_BASE}/api/dlp/scan`, {
            method: "POST",
            mode: "cors",
            credentials: "omit",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(body),
        });
        if (!r.ok) return null;
        return (await r.json()) as ScanResult;
    } catch {
        return null;
    }
}
