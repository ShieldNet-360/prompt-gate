// Clipboard monitor unit tests (Phase 6 Task 14).

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ } from "../clipboard-monitor.js";

const { maybeScanClipboard, fingerprint, STORAGE_KEY } = __test__;

function setOptIn(value: boolean) {
    (globalThis as { chrome?: unknown }).chrome = {
        storage: {
            local: {
                get: async (_key: string) => ({ [STORAGE_KEY]: value }),
            },
        },
    };
}

function setClipboard(value: string, throws?: Error) {
    // Node 22 exposes `navigator` as a getter with no setter, so plain
    // assignment is silently ignored. defineProperty replaces the
    // accessor with a data property the tests can drive.
    Object.defineProperty(globalThis, "navigator", {
        value: {
            clipboard: {
                readText: async () => {
                    if (throws) throw throws;
                    return value;
                },
            },
        },
        configurable: true,
        writable: true,
    });
}

function mockFetch(reply: unknown, ok = true) {
    globalThis.fetch = (async () =>
        ({
            ok,
            json: async () => reply,
        }) as unknown as Response) as typeof fetch;
}

test("fingerprint is stable on identical strings and varies otherwise", () => {
    assert.equal(fingerprint("hello"), fingerprint("hello"));
    assert.notEqual(fingerprint("hello"), fingerprint("HELLO"));
    assert.notEqual(fingerprint("hello"), fingerprint("hellp"));
});

test("fingerprint distinguishes secrets with the same length and first/last chars", () => {
    // Two synthetic AWS-style keys that share length, prefix and
    // suffix characters. The old length+first+last fingerprint
    // collided on these; FNV-1a does not.
    const a = "AKIAIOSFODNN7EXAMPLEF";
    const b = "AKIAJOTHERKEYNN7XAMPF";
    assert.equal(a.length, b.length);
    assert.equal(a[0], b[0]);
    assert.equal(a[a.length - 1], b[b.length - 1]);
    assert.notEqual(fingerprint(a), fingerprint(b));

    // A middle-byte difference must also change the fingerprint.
    const c = "abcdefghijklmnopqrstuvwxyz";
    const d = "abcdefghijklXnopqrstuvwxyz";
    assert.equal(c.length, d.length);
    assert.equal(c[0], d[0]);
    assert.equal(c[c.length - 1], d[d.length - 1]);
    assert.notEqual(fingerprint(c), fingerprint(d));
});

test("maybeScanClipboard is a no-op when the opt-in flag is off", async () => {
    setOptIn(false);
    let clipboardReads = 0;
    Object.defineProperty(globalThis, "navigator", {
        value: {
            clipboard: {
                readText: async () => {
                    clipboardReads++;
                    return "AKIA-XXX";
                },
            },
        },
        configurable: true,
        writable: true,
    });
    await maybeScanClipboard();
    assert.equal(clipboardReads, 0);
});

test("maybeScanClipboard scans the clipboard when opt-in is on", async () => {
    setOptIn(true);
    setClipboard("AKIA-test-key");
    let fetched = false;
    globalThis.fetch = (async () => {
        fetched = true;
        return { ok: true, json: async () => ({ blocked: false, pattern_name: "", score: 0 }) } as unknown as Response;
    }) as typeof fetch;
    await maybeScanClipboard();
    assert.ok(fetched, "expected scan request when opt-in is on");
});

test("maybeScanClipboard tolerates clipboard read failures", async () => {
    setOptIn(true);
    setClipboard("", new Error("permission denied"));
    let fetched = false;
    globalThis.fetch = (async () => {
        fetched = true;
        return { ok: true, json: async () => ({}) } as unknown as Response;
    }) as typeof fetch;
    // Must not throw even when clipboard read fails.
    await maybeScanClipboard();
    assert.equal(fetched, false, "no scan when clipboard read fails");
});

test("maybeScanClipboard tolerates a missing clipboard API", async () => {
    setOptIn(true);
    Object.defineProperty(globalThis, "navigator", {
        value: { clipboard: undefined },
        configurable: true,
        writable: true,
    });
    let fetched = false;
    globalThis.fetch = (async () => {
        fetched = true;
        return { ok: true, json: async () => ({}) } as unknown as Response;
    }) as typeof fetch;
    await maybeScanClipboard();
    assert.equal(fetched, false);
});

// The blocked-toast path is intentionally not asserted from a unit test
// — it touches DOM via `toast.ts`. Form/paste interceptor tests cover
// the same code path with the same scan-client.
void mockFetch;
