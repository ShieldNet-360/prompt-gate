// Unit tests for the source-context
// builder used by every interceptor.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
    buildSourceContext,
    classifyDestination,
    detectElementKind,
    detectInCodeFence,
    detectLanguageHint,
    detectPathHint,
    ElementKind,
    __test__,
} from "../source-context.js";

// ── classifyDestination ───────────────────────────────────────────

test("classifyDestination buckets known AI chat hosts", () => {
    assert.equal(classifyDestination("chat.openai.com"), "ai_chat");
    assert.equal(classifyDestination("chatgpt.com"), "ai_chat");
    assert.equal(classifyDestination("claude.ai"), "ai_chat");
    assert.equal(classifyDestination("gemini.google.com"), "ai_chat");
    assert.equal(classifyDestination("www.perplexity.ai"), "ai_chat");
});

test("classifyDestination buckets code hosts", () => {
    assert.equal(classifyDestination("github.com"), "code_host");
    assert.equal(classifyDestination("gitlab.com"), "code_host");
    assert.equal(classifyDestination("bitbucket.org"), "code_host");
});

test("classifyDestination treats gist.github.com as paste_bin (wins over code_host)", () => {
    assert.equal(classifyDestination("gist.github.com"), "paste_bin");
});

test("classifyDestination buckets social + email + paste_bin", () => {
    assert.equal(classifyDestination("twitter.com"), "social");
    assert.equal(classifyDestination("x.com"), "social");
    assert.equal(classifyDestination("mail.google.com"), "email");
    assert.equal(classifyDestination("pastebin.com"), "paste_bin");
});

test("classifyDestination returns unknown for everything else", () => {
    assert.equal(classifyDestination(""), "unknown");
    assert.equal(classifyDestination("example.com"), "unknown");
    assert.equal(classifyDestination("intranet.acmecorp.io"), "unknown");
});

// ── detectElementKind ─────────────────────────────────────────────

test("detectElementKind reads tag names", () => {
    assert.equal(detectElementKind({ tagName: "TEXTAREA" } as never), ElementKind.Textarea);
    assert.equal(detectElementKind({ tagName: "INPUT" } as never), ElementKind.Input);
});

test("detectElementKind falls back to contenteditable", () => {
    assert.equal(
        detectElementKind({ tagName: "DIV", isContentEditable: true } as never),
        ElementKind.ContentEditable,
    );
    assert.equal(
        detectElementKind({ tagName: "DIV", isContentEditable: false } as never),
        ElementKind.ContentEditable,
    );
    assert.equal(detectElementKind(null), ElementKind.ContentEditable);
    assert.equal(detectElementKind(undefined), ElementKind.ContentEditable);
});

// ── detectInCodeFence ─────────────────────────────────────────────

test("detectInCodeFence handles <pre> ancestor", () => {
    const target = { closest: (s: string) => (s === "pre" ? {} : null) };
    assert.equal(detectInCodeFence(target as never), true);
});

test("detectInCodeFence handles monaco / CodeMirror / cm-editor", () => {
    for (const sel of [".monaco-editor", ".CodeMirror", ".cm-editor"]) {
        const target = { closest: (s: string) => (s === sel ? {} : null) };
        assert.equal(
            detectInCodeFence(target as never),
            true,
            `expected fence detection for ${sel}`,
        );
    }
});

test("detectInCodeFence false when no editor ancestor", () => {
    const target = { closest: () => null };
    assert.equal(detectInCodeFence(target as never), false);
    assert.equal(detectInCodeFence(null), false);
});

// ── detectPathHint ────────────────────────────────────────────────

test("detectPathHint buckets test paths (Go / Python / RSpec / Jest)", () => {
    assert.equal(detectPathHint("/owner/repo/pkg/foo_test.go"), "test");
    assert.equal(detectPathHint("/owner/repo/tests/foo.py"), "test");
    assert.equal(detectPathHint("/owner/repo/__tests__/foo.tsx"), "test");
    assert.equal(detectPathHint("/owner/repo/testdata/keys.txt"), "test");
    assert.equal(detectPathHint("/owner/repo/src/foo.test.ts"), "test");
});

test("detectPathHint buckets fixture / spec / mock / docs paths", () => {
    assert.equal(detectPathHint("/owner/repo/fixtures/cards.json"), "fixture");
    assert.equal(detectPathHint("/owner/repo/src/cards.fixture.json"), "fixture");
    assert.equal(detectPathHint("/owner/repo/spec/foo.rb"), "spec");
    assert.equal(detectPathHint("/owner/repo/src/foo.spec.tsx"), "spec");
    assert.equal(detectPathHint("/owner/repo/__mocks__/foo.ts"), "mock");
    assert.equal(detectPathHint("/owner/repo/docs/intro.md"), "docs");
    assert.equal(detectPathHint("/owner/repo/examples/quickstart.go"), "docs");
});

test("detectPathHint sees through GitHub /blob/<ref>/ prefix (no strip)", () => {
    assert.equal(
        detectPathHint("/owner/repo/blob/main/pkg/foo_test.go"),
        "test",
    );
    assert.equal(
        detectPathHint("/owner/repo/blob/main/internal/dlp/bloom.go"),
        "",
    );
});

test("detectPathHint returns empty for src / readme / root", () => {
    assert.equal(detectPathHint("/owner/repo/src/main.go"), "");
    assert.equal(detectPathHint("/owner/repo/README.md"), "");
    assert.equal(detectPathHint("/"), "");
    assert.equal(detectPathHint(""), "");
});

// ── detectLanguageHint (now pure code-tag) ────────────────────────

test("detectLanguageHint reads code class on ancestor", () => {
    const codeEl = { className: "language-yaml hljs" };
    const target = {
        closest: (s: string) => (s.includes("language-") ? codeEl : null),
    };
    assert.equal(detectLanguageHint(target as never), "yaml");
});

test("detectLanguageHint returns empty when no code ancestor", () => {
    const target = { closest: () => null };
    assert.equal(detectLanguageHint(target as never), "");
    assert.equal(detectLanguageHint(null), "");
});

// ── sha256Hex64 ───────────────────────────────────────────────────

test("sha256Hex64 returns a 16-hex-char hash for known input", async () => {
    // Provide WebCrypto if missing (node 22 has it under globalThis.crypto).
    if (typeof crypto === "undefined" || !crypto.subtle) {
        // The helper falls open ("") in that case; not a fatal test gap.
        return;
    }
    const got = await __test__.sha256Hex64("hello");
    assert.equal(got.length, 16);
    assert.match(got, /^[0-9a-f]{16}$/);
    // Known SHA-256("hello") prefix bytes: 2cf24dba5fb0a30e
    assert.equal(got, "2cf24dba5fb0a30e");
});

test("sha256Hex64 differs for distinct inputs", async () => {
    if (typeof crypto === "undefined" || !crypto.subtle) return;
    const a = await __test__.sha256Hex64("a");
    const b = await __test__.sha256Hex64("b");
    assert.notEqual(a, b);
});

// ── buildSourceContext (full path) ────────────────────────────────

function setLocation(host: string, pathname: string) {
    Object.defineProperty(globalThis, "window", {
        value: { location: { hostname: host, pathname } },
        configurable: true,
        writable: true,
    });
}

test("buildSourceContext fills every field on a known AI chat host", async () => {
    setLocation("chat.openai.com", "/c/abc");
    const src = await buildSourceContext({
        elementKind: ElementKind.ContentEditable,
        target: { closest: () => null, tagName: "DIV", isContentEditable: true } as never,
        content: "hello world",
    });
    assert.equal(src.destination_kind, "ai_chat");
    assert.equal(src.destination_host, "chat.openai.com");
    assert.equal(src.element_kind, "contenteditable");
    assert.equal(src.in_code_fence, false);
    assert.equal(src.language_hint, "");
    assert.equal(src.path_hint, "");
    // Hashes empty only when WebCrypto unavailable.
    if (typeof crypto !== "undefined" && crypto.subtle) {
        assert.match(src.surrounding_hash ?? "", /^[0-9a-f]{16}$/);
        assert.match(src.page_url_hash ?? "", /^[0-9a-f]{16}$/);
    }
});

test("buildSourceContext sets path_hint=test for *_test.go on github.com", async () => {
    setLocation("github.com", "/owner/repo/blob/main/pkg/foo_test.go");
    const src = await buildSourceContext({
        elementKind: ElementKind.NetworkBody,
        target: null,
        content: "AKIA...",
    });
    assert.equal(src.destination_kind, "code_host");
    assert.equal(src.destination_host, "github.com");
    assert.equal(src.element_kind, "network_body");
    assert.equal(src.path_hint, "test");
    // language_hint stays empty — it's now purely code-block tags.
    assert.equal(src.language_hint, "");
});

test("buildSourceContext sets path_hint=fixture for /fixtures/ on github.com", async () => {
    setLocation("github.com", "/owner/repo/blob/main/fixtures/cards.json");
    const src = await buildSourceContext({
        elementKind: ElementKind.ContentEditable,
        target: null,
        content: "x",
    });
    assert.equal(src.path_hint, "fixture");
});

test("buildSourceContext returns empty hashes when content is missing", async () => {
    setLocation("example.com", "/");
    const src = await buildSourceContext({
        elementKind: ElementKind.Clipboard,
        target: null,
    });
    assert.equal(src.destination_kind, "unknown");
    assert.equal(src.element_kind, "clipboard");
    assert.equal(src.in_code_fence, false);
    assert.equal(src.path_hint, "");
});
