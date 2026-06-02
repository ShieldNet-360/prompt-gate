// Isolated-world relay for the MAIN-world fetch / XHR bridge.
//
// The actual fetch / XMLHttpRequest patches live in
// main-world-network.ts and run in the page's own JavaScript context
// (so SPAs' native `fetch` and `XMLHttpRequest.prototype.send` are
// intercepted; see that file for the why). MAIN-world scripts cannot
// use `chrome.runtime`, so this isolated-world relay:
//
//   * Listens for `scan-req` messages the bridge posts to `window`.
//   * Runs the body through the existing `scanContent` helper, which
//     talks to the background service worker (Native Messaging first,
//     loopback HTTP fallback) and ultimately to the local agent.
//   * Posts a `scan-resp` back to `window` with the verdict.
//   * Renders the ephemeral block toast on the page when the agent
//     returns `blocked: true` — the bridge throws / aborts the request
//     but doesn't touch the DOM itself.
//
// On Chrome the bridge is loaded as a separate content_scripts entry
// with `"world": "MAIN"`, so the page-world script is already running
// by the time this relay starts. Firefox MV3 silently ignores the
// `"world": "MAIN"` key (it's still Chrome-only as of Firefox 128),
// so the manifest entry would load the bridge into the isolated world
// — patching the relay's own `fetch`/`XHR` instead of the page's,
// rendering the interceptor a no-op. To stay portable, this relay
// inspects the runtime manifest: if no content_scripts entry declared
// `world: "MAIN"`, we synthesise that delivery by appending a
// `<script src=runtime.getURL(...)>` element at document_start, which
// the page evaluates in its own world. The Firefox manifest omits the
// MAIN-world entry and lists `dist/content/main-world-network.js`
// under `web_accessible_resources` so this URL is loadable from the
// page. Chrome's manifest is unchanged; its declared MAIN-world entry
// suppresses the dynamic injection.
//
// Fall-open semantics match the rest of the extension: any scan-side
// error returns `result: null`, which the bridge treats as "allow".

import type { ScanResult, SourceContext } from "../shared.js";
import { scanContent } from "./scan-client.js";
import { buildSourceContext, ElementKind } from "./source-context.js";
import { showBlockedToast } from "./toast.js";

const BRIDGE_SOURCE = "prompt-gate-bridge";
const ISO_SOURCE = "prompt-gate-iso";

/** Path the page-world bridge is shipped at, relative to the
 *  extension root. Must match what `build-firefox.mjs` lays down and
 *  what `manifest.firefox.json`'s `web_accessible_resources` allows. */
const BRIDGE_SCRIPT_PATH = "dist/content/main-world-network.js";

interface ScanRequestMessage {
    source: typeof BRIDGE_SOURCE;
    kind: "scan-req";
    id: string;
    content: string;
}

interface ScanResponseMessage {
    source: typeof ISO_SOURCE;
    kind: "scan-resp";
    id: string;
    result: ScanResult | null;
}

function isScanRequest(data: unknown): data is ScanRequestMessage {
    if (!data || typeof data !== "object") return false;
    const d = data as { source?: unknown; kind?: unknown; id?: unknown; content?: unknown };
    return d.source === BRIDGE_SOURCE
        && d.kind === "scan-req"
        && typeof d.id === "string"
        && typeof d.content === "string";
}

type ToastFn = (patternName: string) => void;
type ReplyFn = (msg: ScanResponseMessage) => void;

/** Handle a single bridge message. Exported for unit tests so we can
 *  exercise the relay without standing up a real `window`.
 *
 *  Source context: the relay always tags scans from here with
 *  element_kind=network_body so the agent's scorer can apply the
 *  +1 "programmatic exfil intent" bias (see
 *  agent/internal/dlp/scorer_context.go). */
export async function handleBridgeMessage(
    data: unknown,
    reply: ReplyFn,
    scan: (content: string, source?: SourceContext) => Promise<ScanResult | null> = scanContent,
    toast: ToastFn = (p) => showBlockedToast(p, "request"),
): Promise<void> {
    if (!isScanRequest(data)) return;
    const { id, content } = data;
    let source: SourceContext | undefined;
    try {
        source = await buildSourceContext({
            elementKind: ElementKind.NetworkBody,
            target: null,
            content,
        });
    } catch {
        // Source build is best-effort; the scan still runs without it.
    }
    let result: ScanResult | null;
    try {
        result = await scan(content, source);
    } catch {
        result = null;
    }
    if (result && result.blocked) {
        toast(result.pattern_name);
    }
    reply({ source: ISO_SOURCE, kind: "scan-resp", id, result });
}

/** Minimal slice of `chrome.runtime` / `browser.runtime` used here.
 *  Extracted so unit tests can pass a fake without leaning on any
 *  ambient `chrome` global. */
export interface BridgeRuntime {
    getURL(path: string): string;
    getManifest(): { content_scripts?: Array<{ world?: string }> | undefined };
}

/** Minimal slice of the DOM used for injection. Lets tests verify the
 *  element shape without standing up jsdom. */
export interface BridgeDoc {
    createElement(tag: "script"): HTMLScriptElement;
    documentElement: { appendChild(node: Node): Node } | null;
    head: { appendChild(node: Node): Node } | null;
}

/** True when at least one content_scripts entry in the live manifest
 *  declares `world: "MAIN"`. Chrome MV3 honours that key (the page-
 *  world bridge is loaded by the platform); Firefox 128 ignores it
 *  and we have to inject manually. */
export function manifestDeclaresMainWorld(runtime: BridgeRuntime): boolean {
    let manifest: { content_scripts?: Array<{ world?: string }> | undefined };
    try {
        manifest = runtime.getManifest();
    } catch {
        // If getManifest itself throws we assume the safer default
        // (inject) — better a double-patched fetch than a silent
        // bypass.
        return false;
    }
    const entries = manifest.content_scripts ?? [];
    for (const cs of entries) {
        if (cs && cs.world === "MAIN") return true;
    }
    return false;
}

/** Append a `<script src=runtime.getURL(BRIDGE_SCRIPT_PATH)>` element
 *  to the document so the page evaluates the bridge in its own world.
 *  Returns the appended element on success, or null when neither the
 *  manifest declares MAIN-world content_scripts (Firefox path) nor a
 *  parent element is ready yet. The caller decides whether to retry. */
export function injectMainWorldBridge(
    runtime: BridgeRuntime,
    doc: BridgeDoc,
): HTMLScriptElement | null {
    if (manifestDeclaresMainWorld(runtime)) {
        // Platform-loaded path (Chrome MV3). Injecting a second copy
        // would also work — patchFetch/patchXHR are idempotent — but
        // it wastes a network round-trip on every navigation.
        return null;
    }
    const parent = doc.documentElement ?? doc.head;
    if (!parent) return null;
    const el = doc.createElement("script");
    el.src = runtime.getURL(BRIDGE_SCRIPT_PATH);
    el.type = "text/javascript";
    // Once the bridge has installed its patches the script element is
    // no longer needed in the DOM tree.
    el.addEventListener("load", () => {
        if (el.parentNode) el.parentNode.removeChild(el);
    });
    parent.appendChild(el);
    return el;
}

declare const browser: unknown;

function pickRuntime(): BridgeRuntime | null {
    interface RuntimeHost { runtime?: BridgeRuntime }
    const b = (typeof browser !== "undefined" ? browser : undefined) as RuntimeHost | undefined;
    const c = (typeof chrome !== "undefined" ? chrome : undefined) as RuntimeHost | undefined;
    const candidate = b?.runtime ?? c?.runtime;
    if (!candidate || typeof candidate.getURL !== "function" || typeof candidate.getManifest !== "function") {
        return null;
    }
    return candidate;
}

if (typeof window !== "undefined") {
    window.addEventListener("message", (ev: MessageEvent) => {
        if (ev.source && ev.source !== window) return;
        void handleBridgeMessage(ev.data, (msg) => window.postMessage(msg, location.origin));
    });
    const rt = pickRuntime();
    if (rt && typeof document !== "undefined") {
        injectMainWorldBridge(rt, document as unknown as BridgeDoc);
    }
}

export const __test__ = {
    handleBridgeMessage,
    isScanRequest,
    manifestDeclaresMainWorld,
    injectMainWorldBridge,
    BRIDGE_SOURCE,
    ISO_SOURCE,
    BRIDGE_SCRIPT_PATH,
};
