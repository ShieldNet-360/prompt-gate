// Dynamic Tier-2 host updater unit tests (Phase 6 Task 12).

import { test } from "node:test";
import assert from "node:assert/strict";

import { __test__, pollOnce } from "../dynamic-hosts.js";

const { diffHosts, isLikelyHostname } = __test__;

test("diffHosts strips known and invalid hostnames", () => {
    const out = diffHosts([
        "chat.openai.com", // already known
        "internal-ai.example.com", // accept
        "https://bad.example.com", // scheme present → reject
        " ", // empty after trim → reject
        "no-tld", // no dot → reject
        "Mixed.Case.Example.COM", // lowercased
    ]);
    assert.deepEqual(out, ["internal-ai.example.com", "mixed.case.example.com"]);
});

test("isLikelyHostname rejects glob and path payloads", () => {
    assert.equal(isLikelyHostname("foo.com"), true);
    assert.equal(isLikelyHostname("foo.com/bar"), false);
    assert.equal(isLikelyHostname("*.foo.com"), false);
    assert.equal(isLikelyHostname("foo .com"), false);
    assert.equal(isLikelyHostname(""), false);
});

test("pollOnce registers dynamic content scripts when the agent reports new Tier-2 hosts", async () => {
    const registered: unknown[] = [];
    const unregistered: unknown[] = [];
    (globalThis as { chrome?: unknown }).chrome = {
        scripting: {
            registerContentScripts: async (s: unknown) => {
                registered.push(s);
            },
            unregisterContentScripts: async (s: unknown) => {
                unregistered.push(s);
            },
        },
    };
    globalThis.fetch = (async () =>
        ({
            ok: true,
            json: async () => ({
                rule_version: "2025-01-01",
                tier2_hosts: ["chat.openai.com", "internal-ai.example.com"],
            }),
        }) as unknown as Response) as typeof fetch;

    const dynamic = await pollOnce();
    assert.deepEqual(dynamic, ["internal-ai.example.com"]);
    assert.equal(registered.length, 1, "expected one registerContentScripts call");
});

test("pollOnce unregisters dynamic scripts when the agent reports no extra hosts", async () => {
    const unregistered: unknown[] = [];
    (globalThis as { chrome?: unknown }).chrome = {
        scripting: {
            registerContentScripts: async () => {},
            unregisterContentScripts: async (s: unknown) => {
                unregistered.push(s);
            },
        },
    };
    globalThis.fetch = (async () =>
        ({
            ok: true,
            json: async () => ({ tier2_hosts: ["chat.openai.com"] }),
        }) as unknown as Response) as typeof fetch;

    const dynamic = await pollOnce();
    assert.deepEqual(dynamic, []);
    assert.equal(unregistered.length, 1, "expected dynamic scripts to be removed");
});

test("pollOnce returns [] on transport failure", async () => {
    globalThis.fetch = (async () => {
        throw new Error("agent down");
    }) as typeof fetch;
    const out = await pollOnce();
    assert.deepEqual(out, []);
});
