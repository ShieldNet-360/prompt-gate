// Drag-and-drop interceptor unit tests (Phase 6 Task 11).
//
// Mocks globalThis.fetch so the scan-client takes the HTTP path
// (no chrome.runtime in the node test process).

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ } from "../drag-interceptor.js";

const { onDrop } = __test__;

function makeDropEvent(text: string): { ev: DragEvent; preventCalls: { count: number }; insertedText: string[] } {
    const insertedText: string[] = [];
    const preventCalls = { count: 0 };
    const stopCalls = { count: 0 };
    const dataTransfer = {
        getData: (kind: string) => (kind === "text/plain" ? text : ""),
    } as unknown as DataTransfer;
    const target = {
        focus: () => {},
        // dispatchEvent unused because execCommand path is taken
    } as unknown as HTMLElement;
    // Stub execCommand on the document so the resume path is exercised.
    (globalThis as { document?: unknown }).document = {
        queryCommandSupported: () => true,
        execCommand: (_cmd: string, _ui: boolean, value: string) => {
            insertedText.push(value);
            return true;
        },
        activeElement: target,
    } as unknown as Document;

    const ev = {
        dataTransfer,
        target,
        preventDefault: () => {
            preventCalls.count++;
        },
        stopPropagation: () => {
            stopCalls.count++;
        },
    } as unknown as DragEvent;
    return { ev, preventCalls, insertedText };
}

function mockFetch(response: { ok: boolean; body?: unknown; err?: unknown }) {
    const calls: Array<{ url: string }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL): Promise<Response> => {
        calls.push({ url: String(input) });
        if (response.err) throw response.err;
        return { ok: response.ok, json: async () => response.body } as unknown as Response;
    }) as typeof fetch;
    return calls;
}

test("onDrop blocks and does NOT resume insert when DLP says blocked", async () => {
    mockFetch({ ok: true, body: { blocked: true, pattern_name: "aws_key", score: 8 } });
    const { ev, preventCalls, insertedText } = makeDropEvent("AKIA-secret");
    await onDrop(ev);
    assert.equal(preventCalls.count, 1, "preventDefault must fire on block");
    assert.equal(insertedText.length, 0, "no text should be inserted on block");
});

test("onDrop falls open and inserts text on fetch failure", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    const { ev, insertedText } = makeDropEvent("harmless");
    await onDrop(ev);
    assert.equal(insertedText[0], "harmless", "text should be inserted on fall-open");
});

test("onDrop allows text through when DLP returns blocked=false", async () => {
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const { ev, insertedText } = makeDropEvent("prose");
    await onDrop(ev);
    assert.equal(insertedText[0], "prose");
});

test("onDrop ignores empty drops", async () => {
    const calls = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const { ev } = makeDropEvent("");
    await onDrop(ev);
    assert.equal(calls.length, 0, "no scan should be issued for an empty drop");
});
