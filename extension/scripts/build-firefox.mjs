#!/usr/bin/env node
// Build the Firefox WebExtension bundle.
//
// Reuses the Chrome MV3 sources under src/ — same TypeScript compiles
// to the same dist/ tree — but swaps manifest.firefox.json in for
// manifest.json so Firefox's add-on validator sees the gecko-specific
// browser_specific_settings block.
//
// Output: dist-firefox/{manifest.json,dist/}

import { cpSync, mkdirSync, rmSync, copyFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(root, "dist-firefox");

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// Copy the compiled extension code. Caller must run `npm run build`
// first so dist/ exists.
const dist = join(root, "dist");
if (!existsSync(dist)) {
    console.error("build-firefox: dist/ not found; run `npm run build` first.");
    process.exit(1);
}
cpSync(dist, join(out, "dist"), { recursive: true });

// Copy popup HTML so Firefox's action.default_popup resolves.
const popup = join(root, "src", "popup");
if (existsSync(popup)) {
    cpSync(popup, join(out, "src", "popup"), { recursive: true });
}

// Drop the Firefox manifest in as the active manifest.json.
copyFileSync(join(root, "manifest.firefox.json"), join(out, "manifest.json"));

console.log(`build-firefox: wrote bundle to ${out}`);
