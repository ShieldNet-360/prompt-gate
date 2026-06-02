#!/usr/bin/env node
// Build the Safari WebExtension bundle.
//
// Reuses the Chrome MV3 sources under src/ — same TypeScript compiles
// to the same dist/ tree — but swaps manifest.safari.json in for
// manifest.json. Safari does not expose chrome.runtime.connectNative,
// so the background service worker always falls through to the HTTP
// path (POST 127.0.0.1:9191/api/dlp/scan); native messaging keys are
// intentionally absent from manifest.safari.json's permissions list.
//
// Safari Web Extensions ship inside a macOS app bundle, so when the
// `xcrun safari-web-extension-converter` CLI is present we also
// generate the Xcode project wrapper. On non-macOS runners the wrapper
// step is skipped (the dist-safari/ tree is still a valid extension
// payload that the converter can pick up later).
//
// Output: dist-safari/{manifest.json,dist/} (+ dist-safari-xcode/ on macOS)

import { cpSync, mkdirSync, rmSync, copyFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const out = join(root, "dist-safari");
const xcodeOut = join(root, "dist-safari-xcode");

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// Copy the compiled extension code. Caller must run `npm run build`
// first so dist/ exists.
const dist = join(root, "dist");
if (!existsSync(dist)) {
    console.error("build-safari: dist/ not found; run `npm run build` first.");
    process.exit(1);
}
cpSync(dist, join(out, "dist"), { recursive: true });

// Copy popup HTML so Safari's action.default_popup resolves.
const popup = join(root, "src", "popup");
if (existsSync(popup)) {
    cpSync(popup, join(out, "src", "popup"), { recursive: true });
}

// Drop the Safari manifest in as the active manifest.json.
copyFileSync(join(root, "manifest.safari.json"), join(out, "manifest.json"));

console.log(`build-safari: wrote bundle to ${out}`);

// Optionally wrap the bundle in an Xcode project. The converter only
// ships with Xcode (macOS); skip silently on Linux / Windows so the
// extension/typecheck CI job stays cross-platform.
if (process.platform !== "darwin") {
    console.log("build-safari: skipping Xcode wrapper (non-darwin host).");
    process.exit(0);
}

const which = spawnSync("xcrun", ["--find", "safari-web-extension-converter"], {
    encoding: "utf8",
});
if (which.status !== 0) {
    console.log("build-safari: safari-web-extension-converter not installed; skipping Xcode wrapper.");
    process.exit(0);
}

rmSync(xcodeOut, { recursive: true, force: true });
const r = spawnSync(
    "xcrun",
    [
        "safari-web-extension-converter",
        out,
        "--project-location",
        xcodeOut,
        "--app-name",
        "Prompt Gate",
        "--bundle-identifier",
        "com.shieldnet360.promptgate.extension",
        "--no-open",
        "--force",
    ],
    { stdio: "inherit" },
);
if (r.status !== 0) {
    console.error("build-safari: safari-web-extension-converter failed.");
    process.exit(r.status ?? 1);
}
console.log(`build-safari: wrote Xcode project to ${xcodeOut}`);
