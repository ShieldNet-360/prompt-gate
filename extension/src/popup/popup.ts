// Popup script — asks the service worker for the current agent status
// and renders the result. No direct network access; the service worker
// owns the loopback fetch.

import { PopupReply, PopupRequest } from "../shared.js";

const $ = (id: string): HTMLElement => {
    const el = document.getElementById(id);
    if (!el) throw new Error(`missing #${id}`);
    return el;
};

async function refresh(): Promise<void> {
    const status = $("agent-status");
    const version = $("agent-version");
    const uptime = $("agent-uptime");

    const req: PopupRequest = { kind: "ping" };
    const reply: PopupReply = await chrome.runtime.sendMessage(req);

    if (reply.kind === "ok") {
        status.textContent = "online";
        status.classList.remove("bad");
        status.classList.add("ok");
        version.textContent = reply.version;
        uptime.textContent = formatUptime(reply.uptime_seconds);
    } else {
        status.textContent = "offline";
        status.classList.remove("ok");
        status.classList.add("bad");
        version.textContent = "—";
        uptime.textContent = reply.message;
    }
}

function formatUptime(seconds: number): string {
    if (!Number.isFinite(seconds) || seconds <= 0) return "—";
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    return `${h}h ${m}m ${s}s`;
}

void refresh();
