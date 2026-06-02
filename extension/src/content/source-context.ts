// Source-context builder.
//
// Each interceptor calls buildSourceContext(opts) to produce the
// SourceContext that ride along with every /api/dlp/scan request.
// The agent's scorer (slice 2) consumes the result to bias verdicts
// — see agent/internal/dlp/scorer_context.go.
//
// Privacy invariant: the two `_hash` fields are SHA-256 truncated to
// 64 bits (16 hex chars). No raw URL, no surrounding text, no user
// identifier ever crosses the localhost boundary. The hashes are
// content-derived but truncated so even brute-force is expensive
// without a target plaintext.

import type { SourceContext } from "../shared.js";

// ── element_kind values ────────────────────────────────────────────
// Mirror the Go-side enum constants in scorer_context.go. Strings
// (not const enums) because they cross the JSON wire.
export const ElementKind = {
    Input: "input",
    Textarea: "textarea",
    ContentEditable: "contenteditable",
    FormSubmit: "form_submit",
    NetworkBody: "network_body",
    DragDrop: "drag_drop",
    Clipboard: "clipboard",
} as const;
export type ElementKindValue = (typeof ElementKind)[keyof typeof ElementKind];

// ── destination_kind buckets ───────────────────────────────────────
// Small built-in classification so the agent doesn't have to round-
// trip every host through its rule files. The agent re-derives this
// authoritatively from its own rule files when needed (a future release may
// move the canonical map into a shared signed pack).
const AI_CHAT_HOSTS = new Set<string>([
    "chat.openai.com", "chatgpt.com",
    "claude.ai",
    "gemini.google.com", "bard.google.com",
    "copilot.microsoft.com", "www.bing.com",
    "you.com", "www.perplexity.ai",
    "huggingface.co", "poe.com",
    "chat.mistral.ai", "chat.qwen.ai",
]);
const AI_CODE_HOSTS = new Set<string>([
    "copilot.github.com",
    "labs.openai.com",
    "cursor.so",
    "v0.dev",
]);
const CODE_HOSTS = new Set<string>([
    "github.com", "gist.github.com",
    "gitlab.com",
    "bitbucket.org",
    "codeberg.org",
    "sr.ht", "git.sr.ht",
]);
const PASTE_BIN_HOSTS = new Set<string>([
    "pastebin.com", "paste.ee", "hastebin.com",
    "gist.github.com",
    "0bin.net",
]);
const SOCIAL_HOSTS = new Set<string>([
    "twitter.com", "x.com",
    "facebook.com", "www.facebook.com",
    "linkedin.com", "www.linkedin.com",
    "reddit.com", "www.reddit.com",
]);
const EMAIL_HOSTS = new Set<string>([
    "mail.google.com",
    "outlook.live.com", "outlook.office.com",
    "mail.yahoo.com",
]);

export function classifyDestination(host: string): string {
    if (!host) return "unknown";
    // gist.github.com is in both PASTE_BIN_HOSTS and CODE_HOSTS by
    // convention — paste_bin wins because the exfil intent there is
    // closer to "paste a snippet" than "commit a repo file".
    if (PASTE_BIN_HOSTS.has(host)) return "paste_bin";
    if (CODE_HOSTS.has(host)) return "code_host";
    if (AI_CODE_HOSTS.has(host)) return "ai_code";
    if (AI_CHAT_HOSTS.has(host)) return "ai_chat";
    if (SOCIAL_HOSTS.has(host)) return "social";
    if (EMAIL_HOSTS.has(host)) return "email";
    return "unknown";
}

// ── element_kind detection from a DOM target ───────────────────────

export function detectElementKind(
    target: EventTarget | null | undefined,
): ElementKindValue {
    if (!target) return ElementKind.ContentEditable;
    const el = target as Element & { isContentEditable?: boolean; tagName?: string };
    const tag = (el.tagName || "").toUpperCase();
    if (tag === "TEXTAREA") return ElementKind.Textarea;
    if (tag === "INPUT") return ElementKind.Input;
    if (el.isContentEditable) return ElementKind.ContentEditable;
    return ElementKind.ContentEditable;
}

// ── code-fence detection ───────────────────────────────────────────

export function detectInCodeFence(target: EventTarget | null | undefined): boolean {
    if (!target) return false;
    const el = target as Element & { closest?: (s: string) => Element | null };
    if (typeof el.closest !== "function") return false;
    return Boolean(
        el.closest("pre") ||
        el.closest("code") ||
        el.closest(".monaco-editor") ||
        el.closest(".CodeMirror") ||
        el.closest(".cm-editor"),
    );
}

// ── language-hint detection ────────────────────────────────────────

// Path-hint axis — match test-suite-flavoured paths to classify
// pathnames as test / fixture / spec / mock / docs / src / "".
// Two alternations per category:
//   * Directory-style: a path segment named tests/specs/fixtures/
//     mocks/__tests__/__mocks__/testdata.
//   * Filename-style: _test. / .test. / .spec. / .fixture. anywhere
//     in the path (covers Go's foo_test.go, JS/TS's foo.test.ts,
//     RSpec's foo_spec.rb, etc.).
//
// The filename alternation makes the GitHub /blob/<ref>/ prefix
// transparent — we don't need to strip it because the suffix
// matches regardless.
const TEST_PATH_PATTERN = /(?:\/(?:tests?|__tests__|testdata)(?:\/|$)|_test\.|\.test\.)/i;
const FIXTURE_PATH_PATTERN = /(?:\/fixtures?(?:\/|$)|\.fixture\.)/i;
const SPEC_PATH_PATTERN = /(?:\/specs?(?:\/|$)|_spec\.|\.spec\.)/i;
const MOCK_PATH_PATTERN = /(?:\/mocks?(?:\/|$)|\/__mocks__(?:\/|$)|\.mock\.)/i;
const DOCS_PATH_PATTERN = /\/(?:docs?|documentation|examples?|samples?)(?:\/|$)/i;

/** Path-hint helper. Classify a URL pathname into a coarse
 *  bucket the agent's scorer consumes. Order matters: test wins
 *  over docs when both match, because committed test files are the
 *  dominant FP class. */
export function detectPathHint(pathname: string): string {
    if (!pathname) return "";
    if (TEST_PATH_PATTERN.test(pathname)) return "test";
    if (FIXTURE_PATH_PATTERN.test(pathname)) return "fixture";
    if (SPEC_PATH_PATTERN.test(pathname)) return "spec";
    if (MOCK_PATH_PATTERN.test(pathname)) return "mock";
    if (DOCS_PATH_PATTERN.test(pathname)) return "docs";
    return "";
}

/** Look for a `<code class="language-X">` ancestor on the focused
 *  element. Returns the language tag (e.g. "yaml") or "". This is
 *  now PURE — path-based detection moved to detectPathHint. */
export function detectLanguageHint(
    target: EventTarget | null | undefined,
): string {
    if (!target) return "";
    const el = target as Element & {
        closest?: (s: string) => Element | null;
        className?: string;
    };
    if (typeof el.closest !== "function") return "";
    const codeEl = el.closest("code[class*='language-']") as
        | (Element & { className?: string })
        | null;
    if (codeEl && codeEl.className) {
        const m = String(codeEl.className).match(/\blanguage-([^\s]+)/);
        if (m) return m[1];
    }
    return "";
}

// ── 64-bit SHA-256 hex ─────────────────────────────────────────────

async function sha256Hex64(input: string): Promise<string> {
    try {
        const c = (typeof crypto !== "undefined" ? crypto : undefined) as
            | (Crypto & { subtle?: SubtleCrypto })
            | undefined;
        if (!c || !c.subtle) return "";
        const bytes = new TextEncoder().encode(input);
        const buf = await c.subtle.digest("SHA-256", bytes);
        const view = new Uint8Array(buf, 0, 8);
        let out = "";
        for (let i = 0; i < view.length; i++) {
            out += view[i].toString(16).padStart(2, "0");
        }
        return out;
    } catch {
        return "";
    }
}

// ── public builder ─────────────────────────────────────────────────

export interface BuildSourceContextOptions {
    elementKind: string;
    target?: EventTarget | null;
    content?: string;
}

export async function buildSourceContext(
    opts: BuildSourceContextOptions,
): Promise<SourceContext> {
    const loc = (typeof window !== "undefined" && window.location)
        ? window.location
        : { hostname: "", pathname: "" } as Pick<Location, "hostname" | "pathname">;

    const host = loc.hostname || "";
    const pathname = loc.pathname || "";

    const [surroundingHash, pageURLHash] = await Promise.all([
        sha256Hex64(`${opts.content ?? ""}|${host}|${opts.elementKind}`),
        sha256Hex64(`${host}${pathname}`),
    ]);

    return {
        destination_kind: classifyDestination(host),
        destination_host: host,
        element_kind: opts.elementKind,
        in_code_fence: detectInCodeFence(opts.target),
        language_hint: detectLanguageHint(opts.target),
        path_hint: detectPathHint(pathname),
        surrounding_hash: surroundingHash,
        page_url_hash: pageURLHash,
    };
}

// Test-only export.
export const __test__ = {
    sha256Hex64,
    TEST_PATH_PATTERN,
    AI_CHAT_HOSTS,
    CODE_HOSTS,
};
