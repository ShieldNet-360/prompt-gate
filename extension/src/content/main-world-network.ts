// MAIN-world fetch / XHR bridge.
//
// Chrome MV3 content scripts run in an isolated world by default, so
// patches to `window.fetch` or `XMLHttpRequest.prototype.send` from an
// isolated-world script are invisible to the page's own JavaScript:
// the page keeps using its own un-patched copies and our DLP scan
// never fires. This module therefore runs as a separate content_scripts
// entry with `"world": "MAIN"` and patches the page's real globals.
//
// MAIN-world scripts cannot use `chrome.runtime`, so the bridge talks
// to the isolated-world `network-interceptor.ts` via `window.postMessage`.
// The isolated-world script owns the runtime port to the background
// service worker (which in turn talks to the local agent via Native
// Messaging or HTTP loopback).
//
// XHR send is *deferred* until the scan resolves: calling the original
// `send(body)` before knowing the verdict puts bytes on the wire that
// `xhr.abort()` cannot recall. The page-visible side-effects of
// readystatechange still fire normally because the actual network write
// happens once the scan returns "allowed".
//
// This file is intentionally free of runtime imports so it can be
// loaded as a classic script into the page's world; only `import type`
// declarations are used, which TS erases at compile time.

import type { ScanResult } from "../shared.js";

/** Bodies below this size are skipped — not enough material to carry
 *  a DLP-worthy secret. Mirrors the isolated-world threshold. */
export const MIN_SCAN_BYTES = 50;

/** Maximum time to wait for the isolated-world script to reply with a
 *  scan verdict before falling open and allowing the request. */
export const SCAN_TIMEOUT_MS = 1500;

/** Channel tags. The page itself can observe `window.postMessage` so
 *  these tags are best-effort identification, not security tokens. */
export const BRIDGE_SOURCE = "prompt-gate-bridge";
export const ISO_SOURCE = "prompt-gate-iso";

export type ScanRequestMessage = {
    source: typeof BRIDGE_SOURCE;
    kind: "scan-req";
    id: string;
    content: string;
};

export type ScanResponseMessage = {
    source: typeof ISO_SOURCE;
    kind: "scan-resp";
    id: string;
    result: ScanResult | null;
};

function isScanResponse(data: unknown): data is ScanResponseMessage {
    if (!data || typeof data !== "object") return false;
    const d = data as { source?: unknown; kind?: unknown; id?: unknown };
    return d.source === ISO_SOURCE && d.kind === "scan-resp" && typeof d.id === "string";
}

function genId(): string {
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 11)}`;
}

/** A minimal window-like surface used by patchFetch / patchXHR. Exposing
 *  it lets the unit tests inject a fake transport without faking the
 *  global `window`. */
export interface BridgeWindow {
    postMessage(message: unknown, targetOrigin: string): void;
    addEventListener(type: "message", listener: (ev: MessageEvent) => void): void;
    removeEventListener(type: "message", listener: (ev: MessageEvent) => void): void;
}

/** Ask the isolated-world content script to scan `content`. Resolves
 *  to null on timeout / no-listener so the caller can fall open. */
export function requestScan(
    win: BridgeWindow,
    content: string,
    timeoutMs: number = SCAN_TIMEOUT_MS,
): Promise<ScanResult | null> {
    return new Promise((resolve) => {
        const id = genId();
        let settled = false;
        const finish = (result: ScanResult | null) => {
            if (settled) return;
            settled = true;
            win.removeEventListener("message", onMessage);
            clearTimeout(timer);
            resolve(result);
        };
        const onMessage = (ev: MessageEvent) => {
            if (!isScanResponse(ev.data) || ev.data.id !== id) return;
            finish(ev.data.result);
        };
        const timer = setTimeout(() => finish(null), timeoutMs);
        win.addEventListener("message", onMessage);
        const req: ScanRequestMessage = { source: BRIDGE_SOURCE, kind: "scan-req", id, content };
        const origin = typeof location !== "undefined" ? location.origin : "*";
        win.postMessage(req, origin);
    });
}

/** Patch fetch on `target`. Idempotent: re-patching is a no-op so the
 *  bridge can be loaded twice without stacking wrappers. */
export function patchFetch(
    target: { fetch: typeof fetch },
    win: BridgeWindow = window as unknown as BridgeWindow,
): () => void {
    const original = target.fetch;
    if ((original as { __secureEdgePatched?: boolean }).__secureEdgePatched) {
        return () => { /* already patched */ };
    }
    const wrapped: typeof fetch = async (...args) => {
        const body = extractFetchBody(args);
        if (body.length >= MIN_SCAN_BYTES) {
            const result = await requestScan(win, body);
            if (result && result.blocked) {
                throw new Error("Prompt Gate: blocked by DLP");
            }
        }
        return original.apply(target, args);
    };
    (wrapped as { __secureEdgePatched?: boolean }).__secureEdgePatched = true;
    target.fetch = wrapped;
    return () => {
        target.fetch = original;
    };
}

/** Patch XMLHttpRequest.prototype.send so the original send is invoked
 *  only after the DLP scan resolves, closing the send-before-scan race. */
export function patchXHR(
    XHR: { prototype: XMLHttpRequest },
    win: BridgeWindow = window as unknown as BridgeWindow,
): () => void {
    const proto = XHR.prototype as unknown as {
        send: (body?: unknown) => void;
        __secureEdgePatched?: boolean;
    };
    if (proto.__secureEdgePatched) return () => { /* already patched */ };
    const original = proto.send;
    proto.send = function patchedSend(this: XMLHttpRequest, body?: unknown) {
        const text = bodyToText(body);
        if (text.length < MIN_SCAN_BYTES) {
            return original.call(this, body as Document | XMLHttpRequestBodyInit | null | undefined);
        }
        // Defer the network write until the scan resolves. XHR is
        // asynchronous from the page's perspective; readystatechange
        // still fires once the deferred original.send completes.
        const xhr = this;
        const safeSend = () => {
            try {
                original.call(xhr, body as Document | XMLHttpRequestBodyInit | null | undefined);
            } catch {
                // xhr was aborted by the caller between patched send()
                // returning and the scan resolving. Nothing to do.
            }
        };
        requestScan(win, text).then((result) => {
            if (result && result.blocked) {
                try { xhr.abort(); } catch { /* ignore */ }
                return;
            }
            safeSend();
        }, safeSend);
    };
    proto.__secureEdgePatched = true;
    return () => {
        proto.send = original;
        proto.__secureEdgePatched = false;
    };
}

/** Pull a string body out of fetch()'s argument tuple. Returns "" when
 *  the body is not extractable (FormData / Blob / ReadableStream). */
export function extractFetchBody(args: Parameters<typeof fetch>): string {
    const init = args[1];
    if (!init || init.body === undefined || init.body === null) return "";
    const body = init.body;
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
    }
    return "";
}

/** Convert an XHR body argument into a scannable string. */
export function bodyToText(body: unknown): string {
    if (body === undefined || body === null) return "";
    if (typeof body === "string") return body;
    if (typeof URLSearchParams !== "undefined" && body instanceof URLSearchParams) {
        return body.toString();
    }
    return "";
}

// Install the patches when running inside a real browser. Tests import
// the patch functions directly with mock globals.
if (typeof window !== "undefined") {
    patchFetch(window as unknown as { fetch: typeof fetch });
    if (typeof XMLHttpRequest !== "undefined") {
        patchXHR(XMLHttpRequest as unknown as { prototype: XMLHttpRequest });
    }
}

export const __test__ = {
    patchFetch,
    patchXHR,
    extractFetchBody,
    bodyToText,
    requestScan,
    MIN_SCAN_BYTES,
    SCAN_TIMEOUT_MS,
    BRIDGE_SOURCE,
    ISO_SOURCE,
};
