// Shared types and constants for the Prompt Gate companion extension.

/** Default agent endpoint. Must remain loopback. */
export const AGENT_BASE = "http://127.0.0.1:9191";

/** Wire shape returned by POST /api/dlp/scan. Must match
 * agent/internal/dlp.ScanResult and the OpenAPI-ish JSON contract. */
export interface ScanResult {
    blocked: boolean;
    pattern_name: string;
    score: number;
}

/** Wire shape returned by GET /api/status. */
export interface StatusResponse {
    status: string;
    version: string;
    uptime_seconds: number;
}

/** Wire shape of messages sent from the popup to the service worker. */
export type PopupRequest = { kind: "ping" };

/** Wire shape of replies from the service worker to the popup. */
export type PopupReply =
    | { kind: "ok"; version: string; uptime_seconds: number }
    | { kind: "error"; message: string };

/** SourceContext captures the scan's origin. Describes WHERE a scan is
 *  happening so the agent's scorer can bias verdicts by destination,
 *  element kind, code-fence presence, and language hint. Mirrors
 *  agent/internal/dlp/types.go::SourceContext — every field is
 *  optional; a missing or zero-valued source preserves the default
 *  scoring behaviour exactly.
 *
 *  Privacy invariant: surrounding_hash and page_url_hash are
 *  SHA-256 truncated to 64 bits (16 hex chars). No raw URL, no
 *  surrounding text, and no user identifier ever crosses the
 *  boundary. */
export interface SourceContext {
    destination_kind?: string;
    destination_host?: string;
    element_kind?: string;
    in_code_fence?: boolean;
    /** Code-block language tag, e.g. "yaml" / "javascript" / "go". */
    language_hint?: string;
    /** Path-hint axis. Coarse classification of the URL pathname
     *  for code-host destinations. Values: "test" / "fixture" /
     *  "spec" / "mock" / "docs" / "src" / "" (unknown). */
    path_hint?: string;
    surrounding_hash?: string;
    page_url_hash?: string;
}

/** Wire shape of scan-proxy requests sent from a content script to the
 *  background service worker. The worker tries Native Messaging first
 *  and falls back to HTTP fetch — both paths produce the same reply.
 *
 *  session_id is the per-tab opaque token the agent's session
 *  correlator uses to reassemble secrets split across consecutive
 *  pastes from the same tab. Optional — when absent, correlation is
 *  bypassed (each scan is treated as a fresh session).
 *
 *  source is the destination/element/path context.
 *  Optional — when absent, the agent's default scoring path runs. */
export type ScanRequest = {
    kind: "scan";
    content: string;
    session_id?: string;
    source?: SourceContext;
};

/** Wire shape of the reply to a ScanRequest. result === null means
 *  "fall open" (agent unreachable / scan failed). */
export type ScanReply = { kind: "scan-result"; result: ScanResult | null };

/** Tier-2 AI tool host suffixes — kept in sync with the
 *  content_scripts.matches list in extension/manifest.json. Used by
 *  the network interceptor to decide which requests to inspect. */
export const TIER2_HOSTNAMES: ReadonlyArray<string> = [
    "chat.openai.com",
    "chatgpt.com",
    "claude.ai",
    "gemini.google.com",
    "copilot.microsoft.com",
    "www.bing.com",
    "you.com",
    "www.perplexity.ai",
    "huggingface.co",
    "poe.com",
];

/** Native Messaging host application identifier. Must match the
 *  "name" field in extension/native-messaging/com.shieldnet360.promptgate.json
 *  installed by the user's OS. */
export const NATIVE_HOST = "com.shieldnet360.promptgate";
