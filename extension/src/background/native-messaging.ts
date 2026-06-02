// Native Messaging client for the Prompt Gate agent.
//
// Chrome lets MV3 extensions talk to a "native messaging host" via a
// long-lived chrome.runtime.Port. The host is a separately-installed
// program registered in the user's NativeMessagingHosts directory.
// We use it from the service worker to avoid CORS entirely — the
// HTTP fallback always has to deal with whatever Tier-2 AI page's
// CORS posture happens to be.
//
// All public functions return null on any error (no native host
// installed, port disconnect, response timeout) so callers can
// trivially fall through to the HTTP path.

import { NATIVE_HOST, ScanResult } from "../shared.js";

/** Per-request timeout. Same budget as the HTTP fallback so a slow
 *  native host is no worse than a slow loopback. */
const REQUEST_TIMEOUT_MS = 1500;

interface PendingRequest {
    resolve: (r: ScanResult | null) => void;
    timer: ReturnType<typeof setTimeout>;
}

interface NativeMessage {
    id?: number;
    result?: ScanResult;
    error?: string;
}

let port: chrome.runtime.Port | null = null;
let nextId = 1;
const pending = new Map<number, PendingRequest>();
let portUnsupported = false;

function ensurePort(): chrome.runtime.Port | null {
    if (port) return port;
    if (portUnsupported) return null;
    const runtime = typeof chrome !== "undefined" ? chrome.runtime : undefined;
    if (!runtime || typeof runtime.connectNative !== "function") {
        portUnsupported = true;
        return null;
    }
    try {
        port = runtime.connectNative(NATIVE_HOST);
    } catch {
        portUnsupported = true;
        return null;
    }
    port.onMessage.addListener((raw: unknown) => {
        const msg = raw as NativeMessage;
        if (typeof msg.id !== "number") return;
        const req = pending.get(msg.id);
        if (!req) return;
        pending.delete(msg.id);
        clearTimeout(req.timer);
        if (msg.error) {
            req.resolve(null);
            return;
        }
        req.resolve(msg.result ?? null);
    });
    port.onDisconnect.addListener(() => {
        port = null;
        for (const r of pending.values()) {
            clearTimeout(r.timer);
            r.resolve(null);
        }
        pending.clear();
    });
    return port;
}

/** Send `content` to the Native Messaging host for a DLP scan.
 *  Returns null when the host is unavailable, disconnects mid-request,
 *  or exceeds REQUEST_TIMEOUT_MS. Never throws. */
export function scanViaNativeMessaging(content: string): Promise<ScanResult | null> {
    const p = ensurePort();
    if (!p) return Promise.resolve(null);
    const id = nextId++;
    return new Promise<ScanResult | null>((resolve) => {
        const timer = setTimeout(() => {
            if (pending.delete(id)) resolve(null);
        }, REQUEST_TIMEOUT_MS);
        pending.set(id, { resolve, timer });
        try {
            p.postMessage({ id, kind: "scan", content });
        } catch {
            pending.delete(id);
            clearTimeout(timer);
            resolve(null);
        }
    });
}

/** Test-only helpers. Reset the singleton state between cases. */
export const __test__ = {
    reset(): void {
        port = null;
        nextId = 1;
        portUnsupported = false;
        for (const r of pending.values()) {
            clearTimeout(r.timer);
            r.resolve(null);
        }
        pending.clear();
    },
    pendingSize: (): number => pending.size,
};
