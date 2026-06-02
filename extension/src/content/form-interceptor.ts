// Form-submit interceptor content script.
//
// Listens for `submit` events on Tier-2 AI tool pages, concatenates
// the values of every <textarea> and text <input>, and asks the local
// agent's DLP pipeline whether the submission is safe. If the agent
// blocks, the submission is suppressed and an ephemeral toast surfaces
// the matched pattern name. If the agent is unreachable we fall open
// — an outage of the agent must not break the user's workflow.
//
// Tests cover the pure pieces (text extraction + handleSubmit) by
// passing duck-typed mocks; the document-level listener is only wired
// up in a real DOM environment.

import { scanContent } from "./scan-client.js";
import { buildSourceContext, ElementKind } from "./source-context.js";
import { showBlockedToast } from "./toast.js";

/** Concatenate every textual <textarea> and text <input> value in
 *  document order. Non-text inputs (file, password, checkbox, …)
 *  are intentionally skipped — the DLP pipeline is targeted at
 *  free-form prompts, not credentials or attachments. */
export function extractFormText(form: HTMLFormElement): string {
    const parts: string[] = [];
    const elements = form.elements;
    for (let i = 0; i < elements.length; i++) {
        const el = elements.item(i);
        if (!el) continue;
        const tag = (el.tagName || "").toUpperCase();
        if (tag === "TEXTAREA") {
            const ta = el as HTMLTextAreaElement;
            if (ta.value) parts.push(ta.value);
            continue;
        }
        if (tag === "INPUT") {
            const inp = el as HTMLInputElement;
            const type = (inp.type || "text").toLowerCase();
            if (type === "text" || type === "search" || type === "url") {
                if (inp.value) parts.push(inp.value);
            }
        }
    }
    return parts.join("\n");
}

/** Handle one `submit` event. Exposed for tests. */
export async function handleSubmit(ev: SubmitEvent): Promise<void> {
    const target = ev.target;
    if (!target || (target as { tagName?: string }).tagName?.toUpperCase() !== "FORM") return;
    const form = target as unknown as HTMLFormElement;

    const text = extractFormText(form);
    if (text.length === 0) return;

    // Block the native submit while we ask the agent. On allow / fall
    // open we re-submit programmatically; on block we leave the form
    // intact so the user can edit before retrying.
    ev.preventDefault();
    ev.stopPropagation();

    const source = await buildSourceContext({
        elementKind: ElementKind.FormSubmit,
        target: form,
        content: text,
    });
    const result = await scanContent(text, source);
    if (result === null || !result.blocked) {
        try {
            form.submit();
        } catch {
            // Some pages wrap forms with non-standard submit() impls;
            // we've already cancelled the native submit so there's
            // nothing more we can safely do here.
        }
        return;
    }
    showBlockedToast(result.pattern_name, "submission");
}

if (typeof document !== "undefined") {
    document.addEventListener("submit", (ev) => void handleSubmit(ev as SubmitEvent), {
        capture: true,
    });
}

export const __test__ = { extractFormText, handleSubmit };
