#!/usr/bin/env node
// Bundle the MAIN-world fetch / XHR bridge into a classic-script IIFE.
//
// The source file `src/content/main-world-network.ts` is shaped like an
// ES module — it has `export const`, `export function`, and an
// `export const __test__ = { ... }` block — because the unit tests
// import its internals through tsx. tsc faithfully preserves those
// `export` statements into `dist/content/main-world-network.js`, which
// is the same artifact the extension ships to the browser.
//
// At runtime, the browser loads that file two ways:
//
//   * Chrome MV3 declares it as a `content_scripts` entry with
//     `"world": "MAIN"`. Chrome loads content_scripts as classic
//     scripts.
//   * Firefox MV3 has no `world: MAIN` support; the isolated-world
//     relay (`network-interceptor.ts`) appends a `<script
//     src=runtime.getURL('dist/content/main-world-network.js')>`
//     element at `document_start` so the page evaluates the bridge in
//     its own world. That is also a classic script.
//
// `export` statements in a classic script throw `SyntaxError` before
// any side-effects run, so the bridge would never install. esbuild
// emits an IIFE with all `export`s removed, which loads cleanly in
// both contexts.
//
// The tests are unaffected: they import `../main-world-network.js`
// from the source directory, which tsx resolves to the original .ts
// file (exports intact).

import { build } from "esbuild";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const entry = join(root, "src/content/main-world-network.ts");
const outfile = join(root, "dist/content/main-world-network.js");

await build({
    entryPoints: [entry],
    outfile,
    bundle: true,
    format: "iife",
    target: "es2022",
    platform: "browser",
    legalComments: "none",
    write: true,
    logLevel: "info",
});

console.log(`bundle-main-world: wrote IIFE bundle to ${outfile}`);
