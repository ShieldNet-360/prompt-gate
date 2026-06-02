// In-page ephemeral toast renderer for DLP-blocked actions.
//
// All Tier-2 content scripts share this helper so the user sees a
// consistent "Prompt Gate blocked …" message regardless of which
// interceptor (paste / form / fetch / XHR) tripped the pipeline.
//
// The toast displays the matched pattern *name* only — never the
// matched content — and disappears after NOTIFICATION_TTL_MS.

export type BlockedKind = "paste" | "submission" | "request" | "drop" | "clipboard";

const NOTIFICATION_TTL_MS = 5000;
const TOAST_ID = "prompt-gate-blocked-toast";

/** Render an ephemeral toast announcing a DLP block. No-op in
 *  non-DOM environments (e.g. node test runner). */
export function showBlockedToast(patternName: string, kind: BlockedKind = "paste"): void {
    if (typeof document === "undefined" || !document.body) return;

    document.getElementById(TOAST_ID)?.remove();

    const toast = document.createElement("div");
    toast.id = TOAST_ID;
    toast.setAttribute("role", "status");
    toast.style.cssText = [
        "position:fixed",
        "right:16px",
        "bottom:16px",
        "z-index:2147483647",
        "background:#fef2f2",
        "color:#7f1d1d",
        "border:1px solid #fecaca",
        "border-radius:6px",
        "padding:10px 14px",
        "font:13px/1.4 system-ui,sans-serif",
        "box-shadow:0 4px 16px rgba(0,0,0,.15)",
        "max-width:320px",
    ].join(";");
    toast.textContent = `Prompt Gate blocked this ${kind} (${sanitise(patternName)}).`;

    document.body.appendChild(toast);
    setTimeout(() => toast.remove(), NOTIFICATION_TTL_MS);
}

/** Strip non-printable / non-ASCII characters from a pattern name so
 *  a tampered rule file cannot inject HTML or break out of the toast.
 *  Caps the length to keep the toast a single line. */
export function sanitise(s: string): string {
    return s.replace(/[^\x20-\x7e]/g, "").slice(0, 80);
}
