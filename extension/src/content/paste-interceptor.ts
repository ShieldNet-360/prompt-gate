// Paste interceptor content script.
//
// Listens for `paste` events on Tier-2 AI tool pages, extracts the
// pasted text, and asks the local Prompt Gate agent's DLP pipeline
// (POST /api/dlp/scan, or Native Messaging when available) whether to
// allow it. On block, the paste is suppressed and an ephemeral toast
// surfaces the matched pattern name (never the matched content) and
// auto-dismisses after 5 seconds.
//
// Failure modes (agent unreachable, slow response, non-2xx) fall open:
// the paste proceeds so an outage of the agent does not break the
// user's workflow. The popup surfaces an offline indicator.

import { scanContent } from "./scan-client.js";
import { buildSourceContext, detectElementKind } from "./source-context.js";
import { showBlockedToast } from "./toast.js";

const MAX_PASTE_BYTES = 1 * 1024 * 1024; // 1 MiB — silently allow huge pastes.

if (typeof document !== "undefined") {
    document.addEventListener("paste", (ev) => void onPaste(ev), { capture: true });
}

export async function onPaste(ev: ClipboardEvent): Promise<void> {
    const data = ev.clipboardData;
    if (!data) return;
    const text = data.getData("text/plain");
    if (!text || text.length === 0) return;
    if (text.length > MAX_PASTE_BYTES) return;

    // Stop the paste while we ask the agent. We re-emit the paste
    // manually if the agent allows it (see resumePaste below).
    ev.preventDefault();
    ev.stopPropagation();

    const target = ev.target as EventTarget | null;
    const source = await buildSourceContext({
        elementKind: detectElementKind(target),
        target,
        content: text,
    });
    const result = await scanContent(text, source);

    if (result === null) {
        // Agent unreachable → fall open: complete the paste.
        await resumePaste(target, text);
        return;
    }
    if (!result.blocked) {
        await resumePaste(target, text);
        return;
    }
    showBlockedToast(result.pattern_name, "paste");
}

async function resumePaste(target: EventTarget | null, text: string): Promise<void> {
    // Insert the text into the focused element. Two cases:
    //   1. <input> / <textarea> — set selectionStart/End and use
    //      document.execCommand('insertText') so the page sees the
    //      same event-stream it would have seen from a normal paste.
    //   2. contenteditable / rich editor — same insertText API.
    const el = (target instanceof HTMLElement ? target : document.activeElement) as HTMLElement | null;
    if (!el) return;
    el.focus();
    if (document.queryCommandSupported && document.queryCommandSupported("insertText")) {
        document.execCommand("insertText", false, text);
        return;
    }
    // Fallback for inputs/textareas without execCommand support.
    if (el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) {
        const start = el.selectionStart ?? el.value.length;
        const end = el.selectionEnd ?? el.value.length;
        el.value = el.value.slice(0, start) + text + el.value.slice(end);
        el.selectionStart = el.selectionEnd = start + text.length;
        el.dispatchEvent(new Event("input", { bubbles: true }));
    }
}

// Export for tests; not used by the content-script entry path.
export const __test__ = { onPaste };
