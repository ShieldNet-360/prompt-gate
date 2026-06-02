// Safari Web Extensions do not expose chrome.runtime.connectNative.
// When the API is undefined (or throws on call), scanViaNativeMessaging
// must return null so service-worker.ts falls through to the HTTP
// fallback at POST /api/dlp/scan. These tests pin that contract.
//
// service-worker.ts registers chrome.runtime.onMessage.addListener at
// module load, so we install a Safari-shaped chrome shim before
// importing it.

import { test } from "node:test";
import assert from "node:assert/strict";

interface SafariRuntime {
    onMessage: { addListener(fn: (...args: unknown[]) => unknown): void };
    connectNative?: (host: string) => never;
}

function installSafariChrome(opts?: { connectNativeThrows?: boolean }): SafariRuntime {
    const runtime: SafariRuntime = {
        onMessage: { addListener: () => undefined },
    };
    if (opts?.connectNativeThrows) {
        runtime.connectNative = () => {
            throw new Error("native messaging not supported");
        };
    }
    (globalThis as unknown as { chrome: { runtime: SafariRuntime } }).chrome = {
        runtime,
    };
    return runtime;
}

function clearChrome(): void {
    delete (globalThis as unknown as { chrome?: unknown }).chrome;
}

test("Safari: scanViaNativeMessaging returns null when connectNative is undefined", async () => {
    installSafariChrome();
    const nm = await import("../native-messaging.js");
    nm.__test__.reset();
    const r = await nm.scanViaNativeMessaging("payload");
    assert.equal(r, null);
    clearChrome();
});

test("Safari: scanViaNativeMessaging returns null when connectNative throws", async () => {
    installSafariChrome({ connectNativeThrows: true });
    const nm = await import("../native-messaging.js");
    nm.__test__.reset();
    const r = await nm.scanViaNativeMessaging("payload");
    assert.equal(r, null);
    clearChrome();
});

test("Safari: handleScan falls back to HTTP when native messaging is unavailable", async () => {
    installSafariChrome();
    const nm = await import("../native-messaging.js");
    nm.__test__.reset();
    const sw = await import("../service-worker.js");

    const originalFetch = globalThis.fetch;
    let fetchedURL: string | undefined;
    let fetchedBody: string | undefined;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        fetchedURL = typeof input === "string" ? input : input.toString();
        fetchedBody = typeof init?.body === "string" ? init.body : undefined;
        return new Response(
            JSON.stringify({ blocked: true, pattern_name: "AWS Access Key", score: 5 }),
            { status: 200, headers: { "Content-Type": "application/json" } },
        );
    }) as typeof fetch;

    try {
        const result = await sw.handleScan("placeholder secret payload");
        assert.deepEqual(result, {
            blocked: true,
            pattern_name: "AWS Access Key",
            score: 5,
        });
        assert.ok(fetchedURL?.endsWith("/api/dlp/scan"),
            `expected /api/dlp/scan, got ${fetchedURL}`);
        assert.ok(fetchedBody?.includes("placeholder secret payload"),
            "request body must carry the scan content");
    } finally {
        globalThis.fetch = originalFetch;
        clearChrome();
    }
});
