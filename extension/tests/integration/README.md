# Extension integration tests

These Playwright-based smoke tests load the built extension into a
real Chromium instance, navigate to an in-memory mock AI-tool page,
paste a fake secret, and assert that the Prompt Gate block toast
fires. They are intentionally **not** part of the default `npm test`
run because they require a headed Chromium binary (~200 MB) and a
running agent.

## Prerequisites

- The extension is built (`npm run build` writes `extension/dist/`).
- The Prompt Gate agent is running on `http://127.0.0.1:9191` with
  DLP enabled.
- Playwright is installed *out of band* — it is not pinned in
  `package.json` to keep the default install footprint small:

```sh
cd extension
npm install --no-save playwright
npx playwright install chromium
```

## Running

```sh
node --import tsx tests/integration/block-toast.test.ts
```

The script is a vanilla Node test, not a Jest/Vitest suite — it uses
the same `node --test` runner the rest of the extension already uses
in `package.json`.

## What it covers

- Acceptance: the extension's block toast appears
  for an AI-tool host when a known-bad token is pasted into a
  textarea, and the form submission is blocked.

## What it does NOT cover

- Real production hosts. The integration test serves its own minimal
  fixture page from `file://` rather than driving chat.openai.com etc.
  Driving real hosts would need a long-lived bot account and is left
  to manual QA.
