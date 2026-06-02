// Drag-and-drop interceptor content script (Phase 6 Task 11).
//
// Some AI tools accept drag-and-drop of text payloads (snippets, log
// files, transcripts) straight into the prompt textarea. Drops bypass
// the `paste` event listener so a separate `drop` listener is wired
// up here and routes the dragged text through the same scan-client
// the paste interceptor uses.
//
// Privacy invariant: dragged content stays in memory only. When a
// block decision arrives we never log the dragged text — only the
// pattern name surfaces through the toast.

import { scanContent, MAX_SCAN_BYTES } from "./scan-client.js";
import { buildSourceContext, ElementKind } from "./source-context.js";
import { showBlockedToast } from "./toast.js";

if (typeof document !== "undefined") {
    document.addEventListener("drop", (ev) => void onDrop(ev), { capture: true });
}

/**
 * Handle a drop event. We only care about plain-text payloads — file
 * drops are out of scope for the DLP companion (and are usually
 * uploaded over the page's own fetch path which the network-interceptor
 * already covers).
 */
export async function onDrop(ev: DragEvent): Promise<void> {
    const data = ev.dataTransfer;
    if (!data) return;
    const text = data.getData("text/plain");
    if (!text || text.length === 0) return;
    if (text.length > MAX_SCAN_BYTES) return;

    ev.preventDefault();
    ev.stopPropagation();

    const target = ev.target as EventTarget | null;
    const source = await buildSourceContext({
        elementKind: ElementKind.DragDrop,
        target,
        content: text,
    });
    const result = await scanContent(text, source);
    if (result === null || !result.blocked) {
        await resumeDrop(target, text);
        return;
    }
    showBlockedToast(result.pattern_name, "drop");
}

async function resumeDrop(target: EventTarget | null, text: string): Promise<void> {
    // Cast through `unknown` to avoid pulling in DOM lib types like
    // HTMLElement, which are not part of the Node test runtime.
    const el = (target ?? document.activeElement) as
        | (HTMLInputElement & HTMLTextAreaElement)
        | null;
    if (!el || typeof el.focus !== "function") return;
    el.focus();
    if (document.queryCommandSupported && document.queryCommandSupported("insertText")) {
        document.execCommand("insertText", false, text);
        return;
    }
    if (typeof el.value === "string" && "selectionStart" in el) {
        const start = el.selectionStart ?? el.value.length;
        const end = el.selectionEnd ?? el.value.length;
        el.value = el.value.slice(0, start) + text + el.value.slice(end);
        el.selectionStart = el.selectionEnd = start + text.length;
        el.dispatchEvent(new Event("input", { bubbles: true }));
    }
}

export const __test__ = { onDrop };
