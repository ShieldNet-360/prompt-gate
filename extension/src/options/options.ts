// Options page script (Phase 6 Task 13).
//
// Surfaces three things to the user:
//   1. Toggle: verbose toast notifications (off by default).
//   2. Toggle: clipboard monitor (off by default, Task 14).
//   3. Read-only: agent connection status + rule version.
//
// Settings persist in chrome.storage.local so the background service
// worker and content scripts can observe them. The page never talks to
// the agent directly — connection info is fetched through the service
// worker, same as the popup, so there is exactly one fetch path.

import {
    AGENT_BASE,
    PopupReply,
    PopupRequest,
} from "../shared.js";

const KEY_VERBOSE = "secureEdge:verboseToast";
const KEY_CLIPBOARD = "secureEdge:clipboardMonitor";

function $(id: string): HTMLElement {
    const el = document.getElementById(id);
    if (!el) throw new Error(`missing #${id}`);
    return el;
}

async function init(): Promise<void> {
    const verbose = $("opt-verbose") as HTMLInputElement;
    const clipboard = $("opt-clipboard") as HTMLInputElement;

    const stored = await chrome.storage.local.get([KEY_VERBOSE, KEY_CLIPBOARD]);
    verbose.checked = Boolean(stored[KEY_VERBOSE]);
    clipboard.checked = Boolean(stored[KEY_CLIPBOARD]);

    verbose.addEventListener("change", () => {
        void chrome.storage.local.set({ [KEY_VERBOSE]: verbose.checked });
    });
    clipboard.addEventListener("change", () => {
        void chrome.storage.local.set({ [KEY_CLIPBOARD]: clipboard.checked });
    });

    await refreshConnection();
}

async function refreshConnection(): Promise<void> {
    const status = $("conn-status");
    const version = $("conn-version");
    const rules = $("conn-rules");

    try {
        const req: PopupRequest = { kind: "ping" };
        const reply = (await chrome.runtime.sendMessage(req)) as PopupReply;
        if (reply.kind === "ok") {
            status.textContent = `agent online (${AGENT_BASE})`;
            status.classList.add("ok");
            version.textContent = `version: ${reply.version}`;
        } else {
            status.textContent = "agent offline";
            status.classList.add("bad");
            version.textContent = `error: ${reply.message}`;
        }
    } catch (e) {
        status.textContent = "agent offline";
        status.classList.add("bad");
        version.textContent = `error: ${String(e)}`;
    }

    // Rule version is best-effort — pull it via a direct loopback fetch.
    try {
        const r = await fetch(`${AGENT_BASE}/api/rules/status`, {
            mode: "cors",
            credentials: "omit",
        });
        if (r.ok) {
            const j = (await r.json()) as { rule_version?: string };
            rules.textContent = `rules: ${j.rule_version ?? "unknown"}`;
        } else {
            rules.textContent = "rules: unavailable";
        }
    } catch {
        rules.textContent = "rules: unavailable";
    }
}

void init();

export const __test__ = { KEY_VERBOSE, KEY_CLIPBOARD };
