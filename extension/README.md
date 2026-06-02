# Prompt Gate browser extension

Manifest V3 companion extension that intercepts pastes, form submissions, and
outbound requests on the Tier-2 AI tool pages listed in the manifests, and
runs them through the local Prompt Gate DLP pipeline.

Same TypeScript sources build a Chrome / Edge / Chromium bundle, a Firefox
add-on, and a Safari Web Extension.

## Manifests

| File                     | Target browsers                | Native messaging |
|--------------------------|--------------------------------|------------------|
| `manifest.json`          | Chrome, Edge, Chromium         | yes (preferred)  |
| `manifest.firefox.json`  | Firefox 128+                   | yes              |
| `manifest.safari.json`   | Safari 17+ (macOS / iOS)       | no — HTTP only   |

Safari Web Extensions do not expose `chrome.runtime.connectNative`. The
service worker's `scanViaNativeMessaging` returns null when the API is
absent, and the scan falls through to `POST 127.0.0.1:9191/api/dlp/scan`.
This is why the Safari manifest omits the `nativeMessaging` permission.

## Builds

```bash
npm install
npm run build           # Chrome / Chromium bundle
npm run build:firefox   # → dist-firefox/
npm run build:safari    # → dist-safari/ (+ dist-safari-xcode/ on macOS)
```

The Safari build only generates the Xcode project wrapper when run on
macOS — `xcrun safari-web-extension-converter` ships with Xcode and is
not available on Linux / Windows. Releases run the wrapper step from the
`macos-latest` GitHub Actions runner.

## Tests

```bash
npm test          # node:test, no browser required
npm run typecheck
```
