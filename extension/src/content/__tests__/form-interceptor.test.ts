// Unit tests for the form-submit interceptor.
//
// Run with: `cd extension && npm test`. Mocks `globalThis.fetch` so the
// scan-client falls through to the HTTP path (no `chrome.runtime`
// global is defined in the test process). `chrome` typings are not
// referenced from this file so it typechecks under both
// tsconfig.json and tsconfig.test.json.

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__ } from "../form-interceptor.js";

const { extractFormText, handleSubmit } = __test__;

interface FakeInput {
    tagName: string;
    type?: string;
    value?: string;
}

function makeForm(inputs: FakeInput[], submitSpy: () => void): HTMLFormElement {
    return {
        elements: {
            length: inputs.length,
            item: (i: number): Element | null => (inputs[i] as unknown as Element | undefined) ?? null,
        },
        submit: submitSpy,
        tagName: "FORM",
    } as unknown as HTMLFormElement;
}

function makeEvent(target: HTMLFormElement): {
    ev: SubmitEvent;
    preventCalls: { count: number };
    stopCalls: { count: number };
} {
    const preventCalls = { count: 0 };
    const stopCalls = { count: 0 };
    const ev = {
        target,
        preventDefault: () => {
            preventCalls.count++;
        },
        stopPropagation: () => {
            stopCalls.count++;
        },
    } as unknown as SubmitEvent;
    return { ev, preventCalls, stopCalls };
}

function mockFetch(response: { ok: boolean; body?: unknown; err?: unknown }) {
    const calls: Array<{ url: string; init: RequestInit | undefined }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        calls.push({ url: String(input), init });
        if (response.err) throw response.err;
        return {
            ok: response.ok,
            json: async () => response.body,
        } as unknown as Response;
    }) as typeof fetch;
    return calls;
}

test("extractFormText concatenates textarea + text input values", () => {
    const form = makeForm(
        [
            { tagName: "TEXTAREA", value: "hello" },
            { tagName: "INPUT", type: "text", value: "world" },
            { tagName: "INPUT", type: "password", value: "secret" }, // skipped
            { tagName: "BUTTON" }, // skipped
        ],
        () => {},
    );
    assert.equal(extractFormText(form), "hello\nworld");
});

test("handleSubmit blocks and skips re-submit when DLP returns blocked=true", async () => {
    mockFetch({ ok: true, body: { blocked: true, pattern_name: "aws_key", score: 8 } });
    let submitCalls = 0;
    const form = makeForm([{ tagName: "TEXTAREA", value: "AKIA..." }], () => {
        submitCalls++;
    });
    const { ev, preventCalls, stopCalls } = makeEvent(form);

    await handleSubmit(ev);

    assert.equal(preventCalls.count, 1, "preventDefault should fire on block");
    assert.equal(stopCalls.count, 1, "stopPropagation should fire on block");
    assert.equal(submitCalls, 0, "form.submit() must NOT be called on block");
});

test("handleSubmit falls open (re-submits) when fetch throws", async () => {
    mockFetch({ ok: false, err: new Error("agent down") });
    let submitCalls = 0;
    const form = makeForm([{ tagName: "TEXTAREA", value: "hello" }], () => {
        submitCalls++;
    });
    const { ev, preventCalls } = makeEvent(form);

    await handleSubmit(ev);

    assert.equal(preventCalls.count, 1);
    assert.equal(submitCalls, 1, "form.submit() must be called on fall-open");
});

test("handleSubmit re-submits when DLP returns blocked=false", async () => {
    mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    let submitCalls = 0;
    const form = makeForm([{ tagName: "TEXTAREA", value: "harmless prose" }], () => {
        submitCalls++;
    });
    const { ev } = makeEvent(form);

    await handleSubmit(ev);

    assert.equal(submitCalls, 1, "form.submit() must be called on allow");
});

test("handleSubmit ignores non-form targets", async () => {
    const calls = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const ev = {
        target: { tagName: "DIV" },
        preventDefault: () => assert.fail("should not preventDefault on non-form"),
        stopPropagation: () => {},
    } as unknown as SubmitEvent;

    await handleSubmit(ev);

    assert.equal(calls.length, 0, "no scan should fire");
});

test("handleSubmit ignores empty forms", async () => {
    const calls = mockFetch({ ok: true, body: { blocked: false, pattern_name: "", score: 0 } });
    const form = makeForm([{ tagName: "TEXTAREA", value: "" }], () => {});
    const { ev, preventCalls } = makeEvent(form);
    await handleSubmit(ev);
    assert.equal(preventCalls.count, 0, "empty form should not preventDefault");
    assert.equal(calls.length, 0);
});
