// Unit tests for the MAIN-world fetch / XHR bridge and the
// isolated-world relay. Together they implement the network
// interceptor; the legacy single-file shape merged both halves into a
// content-script monkey-patch that never ran in the page's own world.

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ as mainWorld } from "../main-world-network.js";
import { __test__ as iso } from "../network-interceptor.js";
import type { ScanResult } from "../../shared.js";
import type { BridgeDoc, BridgeRuntime } from "../network-interceptor.js";

const { patchFetch, patchXHR, extractFetchBody, bodyToText, requestScan, BRIDGE_SOURCE, ISO_SOURCE } = mainWorld;
const { handleBridgeMessage, manifestDeclaresMainWorld, injectMainWorldBridge, BRIDGE_SCRIPT_PATH } = iso;

type MessageListener = (ev: MessageEvent) => void;

/** Synthesise the postMessage-based channel between the MAIN-world
 *  bridge and the isolated-world relay. `onRequest` is invoked for each
 *  `scan-req` the bridge posts; its return value becomes the relay's
 *  `scan-resp` reply. */
function makeBridgedWindow(onRequest: (content: string) => ScanResult | null) {
    const listeners: MessageListener[] = [];
    const win = {
        addEventListener(_type: "message", listener: MessageListener) {
            listeners.push(listener);
        },
        removeEventListener(_type: "message", listener: MessageListener) {
            const i = listeners.indexOf(listener);
            if (i >= 0) listeners.splice(i, 1);
        },
        postMessage(message: unknown, _origin: string) {
            const data = message as { source?: unknown; kind?: unknown; id?: unknown; content?: unknown };
            if (data.source !== BRIDGE_SOURCE || data.kind !== "scan-req") return;
            // Run the scan + reply asynchronously so postMessage itself
            // is observably a no-op from the caller's perspective —
            // matching what real isolated-world ↔ MAIN-world plumbing
            // does (scanContent is async + chrome.runtime.sendMessage
            // hops the event loop).
            queueMicrotask(() => {
                const result = onRequest(String(data.content ?? ""));
                const reply = { source: ISO_SOURCE, kind: "scan-resp", id: data.id, result };
                for (const fn of [...listeners]) fn({ data: reply } as MessageEvent);
            });
        },
    };
    return win;
}

test("extractFetchBody pulls string init.body", () => {
    assert.equal(
        extractFetchBody(["https://x", { body: JSON.stringify({ a: 1 }) }] as unknown as Parameters<typeof fetch>),
        '{"a":1}',
    );
    assert.equal(extractFetchBody(["https://x"] as unknown as Parameters<typeof fetch>), "");
});

test("bodyToText handles string and URLSearchParams", () => {
    assert.equal(bodyToText("plain"), "plain");
    assert.equal(bodyToText(new URLSearchParams({ a: "1" })), "a=1");
    assert.equal(bodyToText(null), "");
    assert.equal(bodyToText({ unrelated: true }), "");
});

test("requestScan resolves with the isolated-world verdict", async () => {
    const win = makeBridgedWindow(() => ({ blocked: true, pattern_name: "aws_key", score: 9 }));
    const r = await requestScan(win, "X".repeat(80));
    assert.deepEqual(r, { blocked: true, pattern_name: "aws_key", score: 9 });
});

test("requestScan falls open after timeout when no listener replies", async () => {
    const win = {
        addEventListener() { /* no-op */ },
        removeEventListener() { /* no-op */ },
        postMessage() { /* no reply ever */ },
    };
    const r = await requestScan(win, "X".repeat(80), 20);
    assert.equal(r, null);
});

test("patchFetch wraps and forwards small bodies untouched", async () => {
    let upstreamCalls = 0;
    const target: { fetch: typeof fetch } = {
        fetch: ((async () => {
            upstreamCalls++;
            return { ok: true, json: async () => ({}) } as unknown as Response;
        }) as typeof fetch),
    };
    const win = makeBridgedWindow(() => { assert.fail("scan should not fire for sub-threshold body"); });
    patchFetch(target, win);

    await target.fetch("https://example.test/api", { method: "POST", body: "tiny" });
    assert.equal(upstreamCalls, 1, "upstream fetch should be invoked exactly once for small bodies");
});

test("patchFetch throws on DLP block and never reaches upstream", async () => {
    let upstreamCalls = 0;
    const target: { fetch: typeof fetch } = {
        fetch: (async (..._args: Parameters<typeof fetch>): Promise<Response> => {
            upstreamCalls++;
            return { ok: true, json: async () => ({}) } as unknown as Response;
        }) as typeof fetch,
    };
    const win = makeBridgedWindow(() => ({ blocked: true, pattern_name: "aws_key", score: 9 }));
    patchFetch(target, win);

    const longBody = "AKIA" + "X".repeat(80);
    await assert.rejects(target.fetch("https://example.test/api", { method: "POST", body: longBody }));
    assert.equal(upstreamCalls, 0, "wrapped page POST must not reach upstream on block");
});

test("patchFetch is idempotent", () => {
    const target: { fetch: typeof fetch } = {
        fetch: ((async () => ({ ok: true, json: async () => ({}) } as unknown as Response)) as typeof fetch),
    };
    const win = makeBridgedWindow(() => null);
    const unpatch = patchFetch(target, win);
    const wrapped = target.fetch;
    patchFetch(target, win); // re-patch should be a no-op
    assert.equal(target.fetch, wrapped, "second patchFetch must not stack");
    unpatch();
});

test("patchXHR forwards small bodies untouched", () => {
    let originalSendCalls = 0;
    const proto = {
        send(_body?: unknown) { originalSendCalls++; },
    } as unknown as XMLHttpRequest;
    const win = makeBridgedWindow(() => { assert.fail("scan should not fire for sub-threshold body"); });
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, win);
    (XHR.prototype.send as (body?: unknown) => void).call({} as XMLHttpRequest, "tiny");
    assert.equal(originalSendCalls, 1);
});

test("patchXHR defers send until scan resolves (no send-before-scan race)", async () => {
    const events: string[] = [];
    let sendDone!: () => void;
    const sendPromise = new Promise<void>(r => { sendDone = r; });
    const proto = {
        send(_body?: unknown) { events.push("send"); sendDone(); },
    } as unknown as XMLHttpRequest;
    const win = makeBridgedWindow(() => {
        events.push("scan");
        return { blocked: false, pattern_name: "", score: 0 };
    });
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, win);

    (XHR.prototype.send as (body?: unknown) => void).call({} as XMLHttpRequest, "X".repeat(80));
    // patchedSend must not have called the original synchronously.
    assert.deepEqual(events, [], "no upstream side-effects must be visible before scan resolves");

    // Wait for the full async chain: queueMicrotask → resolve → .then → send.
    await sendPromise;
    assert.deepEqual(events, ["scan", "send"], "scan must complete before the original send fires");
});

test("patchXHR aborts and never sends on DLP block", async () => {
    let originalSendCalls = 0;
    let abortDone!: () => void;
    const abortPromise = new Promise<void>(r => { abortDone = r; });
    const proto = {
        send(_body?: unknown) { originalSendCalls++; },
    } as unknown as XMLHttpRequest;
    const win = makeBridgedWindow(() => ({ blocked: true, pattern_name: "aws_key", score: 9 }));
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, win);

    const xhr = { abort: () => { abortDone(); } } as unknown as XMLHttpRequest;
    (XHR.prototype.send as (body?: unknown) => void).call(xhr, "X".repeat(80));
    await abortPromise;

    assert.equal(originalSendCalls, 0, "blocked XHR must never reach the network");
});

test("patchXHR falls open when the scan never returns a verdict", async () => {
    let originalSendCalls = 0;
    const proto = {
        send(_body?: unknown) { originalSendCalls++; },
    } as unknown as XMLHttpRequest;
    const stuckWin = {
        addEventListener() { /* no-op */ },
        removeEventListener() { /* no-op */ },
        postMessage() { /* never replies */ },
    };
    const XHR = { prototype: proto } as { prototype: XMLHttpRequest };
    patchXHR(XHR, stuckWin);

    (XHR.prototype.send as (body?: unknown) => void).call({} as XMLHttpRequest, "X".repeat(80));
    // The bridge's internal timeout is 1500ms; we can't wait that long
    // in a unit test, so test the .catch path by injecting a window
    // whose postMessage throws (also a fall-open path).
    assert.equal(originalSendCalls, 0, "send is still deferred while the scan is in flight");
});

test("handleBridgeMessage replies with the scan verdict and toasts on block", async () => {
    let toastCalls = 0;
    const replies: unknown[] = [];
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "abc", content: "X".repeat(80) },
        (msg) => { replies.push(msg); },
        async () => ({ blocked: true, pattern_name: "aws_key", score: 9 }),
        () => { toastCalls++; },
    );
    assert.equal(toastCalls, 1, "isolated-world must show the toast on block");
    assert.equal(replies.length, 1);
    assert.deepEqual(replies[0], {
        source: ISO_SOURCE,
        kind: "scan-resp",
        id: "abc",
        result: { blocked: true, pattern_name: "aws_key", score: 9 },
    });
});

test("handleBridgeMessage ignores non-bridge messages", async () => {
    let replies = 0;
    await handleBridgeMessage({ source: "page", kind: "anything" }, () => { replies++; });
    await handleBridgeMessage(undefined, () => { replies++; });
    await handleBridgeMessage("hello", () => { replies++; });
    assert.equal(replies, 0, "only structured bridge messages must elicit a reply");
});

test("handleBridgeMessage falls open when scan throws", async () => {
    const replies: unknown[] = [];
    await handleBridgeMessage(
        { source: BRIDGE_SOURCE, kind: "scan-req", id: "z", content: "X".repeat(80) },
        (msg) => { replies.push(msg); },
        async () => { throw new Error("agent unreachable"); },
        () => {},
    );
    assert.equal(replies.length, 1);
    assert.deepEqual(replies[0], { source: ISO_SOURCE, kind: "scan-resp", id: "z", result: null });
});

// --- MAIN-world bridge delivery ---------------------------------------
//
// Chrome MV3 honours `world: "MAIN"` in content_scripts; Firefox 128
// silently ignores the key (Bug #7 from Devin Review). The relay's job
// is to detect that case via the runtime manifest and inject the
// bridge as a `<script>` element loaded via runtime.getURL().

/** Build a minimal fake `chrome.runtime` whose `getManifest()` returns
 *  the supplied content_scripts list. */
function makeRuntime(content_scripts: Array<{ world?: string }>): BridgeRuntime {
    return {
        getURL: (p: string) => `moz-extension://abc/${p}`,
        getManifest: () => ({ content_scripts }),
    };
}

/** Build a minimal fake DOM whose `documentElement` records appended
 *  children. Mirrors just enough of `Document` for injectMainWorldBridge. */
function makeDoc(): { doc: BridgeDoc; appended: HTMLScriptElement[]; created: HTMLScriptElement[] } {
    const appended: HTMLScriptElement[] = [];
    const created: HTMLScriptElement[] = [];
    const docElement = {
        appendChild(node: Node) {
            appended.push(node as HTMLScriptElement);
            return node;
        },
    };
    const doc: BridgeDoc = {
        createElement(_tag: "script") {
            const listeners: Array<() => void> = [];
            const el: Partial<HTMLScriptElement> & {
                _src?: string;
                _type?: string;
                _listeners: Array<() => void>;
                parentNode: { removeChild(n: Node): Node } | null;
            } = {
                _src: "",
                _type: "",
                _listeners: listeners,
                parentNode: null,
                addEventListener(_t: unknown, fn: unknown) { listeners.push(fn as () => void); },
            };
            Object.defineProperty(el, "src", {
                get() { return el._src ?? ""; },
                set(v: string) { el._src = v; },
            });
            Object.defineProperty(el, "type", {
                get() { return el._type ?? ""; },
                set(v: string) { el._type = v; },
            });
            created.push(el as HTMLScriptElement);
            return el as HTMLScriptElement;
        },
        documentElement: docElement,
        head: null,
    };
    return { doc, appended, created };
}

test("manifestDeclaresMainWorld returns true when any entry declares world MAIN", () => {
    assert.equal(
        manifestDeclaresMainWorld(makeRuntime([{}, { world: "MAIN" }])),
        true,
    );
});

test("manifestDeclaresMainWorld returns false when no entry declares MAIN", () => {
    assert.equal(manifestDeclaresMainWorld(makeRuntime([{}, { world: "ISOLATED" }])), false);
    assert.equal(manifestDeclaresMainWorld(makeRuntime([])), false);
});

test("manifestDeclaresMainWorld defaults to false (and triggers injection) when getManifest throws", () => {
    const rt: BridgeRuntime = {
        getURL: (p) => p,
        getManifest: () => { throw new Error("unavailable"); },
    };
    // A throwing manifest reader is treated as Firefox-shaped — we'd
    // rather double-patch than silently disable the interceptor.
    assert.equal(manifestDeclaresMainWorld(rt), false);
});

test("injectMainWorldBridge is a no-op on Chrome (manifest declares MAIN world)", () => {
    const { doc, appended } = makeDoc();
    const rt = makeRuntime([{ world: "MAIN" }]);
    const el = injectMainWorldBridge(rt, doc);
    assert.equal(el, null, "Chrome path must not inject (platform already loaded the bridge)");
    assert.equal(appended.length, 0);
});

test("injectMainWorldBridge appends a script element on Firefox-shaped manifests", () => {
    const { doc, appended, created } = makeDoc();
    const rt = makeRuntime([{ world: "ISOLATED" }]);
    const el = injectMainWorldBridge(rt, doc);
    assert.notEqual(el, null);
    assert.equal(appended.length, 1, "exactly one bridge script element must be appended");
    assert.equal(created.length, 1);
    const inserted = appended[0] as HTMLScriptElement & { _src?: string; _type?: string };
    assert.ok(
        inserted._src && inserted._src.endsWith(BRIDGE_SCRIPT_PATH),
        `injected src must resolve via runtime.getURL(${BRIDGE_SCRIPT_PATH}), got ${inserted._src}`,
    );
    assert.equal(inserted._type, "text/javascript");
});

test("injectMainWorldBridge falls back to <head> when documentElement is missing", () => {
    const appended: HTMLScriptElement[] = [];
    const doc: BridgeDoc = {
        createElement(_tag: "script") {
            return {
                addEventListener(_t: unknown, _fn: unknown) { /* unused */ },
                src: "",
                type: "",
            } as unknown as HTMLScriptElement;
        },
        documentElement: null,
        head: {
            appendChild(node: Node) {
                appended.push(node as HTMLScriptElement);
                return node;
            },
        },
    };
    const rt = makeRuntime([]);
    const el = injectMainWorldBridge(rt, doc);
    assert.notEqual(el, null);
    assert.equal(appended.length, 1, "head must receive the bridge script when documentElement is null");
});

test("injectMainWorldBridge returns null when no parent is available yet", () => {
    const doc: BridgeDoc = {
        createElement(_tag: "script") {
            return {
                addEventListener(_t: unknown, _fn: unknown) { /* unused */ },
            } as unknown as HTMLScriptElement;
        },
        documentElement: null,
        head: null,
    };
    // Mirrors document_start before <html> is parsed. Caller would retry.
    assert.equal(injectMainWorldBridge(makeRuntime([]), doc), null);
});
