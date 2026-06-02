/**
 * Playwright-based extension integration smoke test (Phase 6 Task 24).
 *
 * Not part of the default `npm test` run. See ./README.md for the
 * out-of-band install steps.
 *
 * The test:
 *  1. Launches a headed Chromium with the built extension preloaded.
 *  2. Opens a minimal HTML fixture served from file://.
 *  3. Pastes a known-bad AWS Access Key into the page's textarea.
 *  4. Asserts the Prompt Gate block toast appears.
 *
 * The agent under test is assumed to be running on
 * http://127.0.0.1:9191 with DLP enabled. The fixture page declares
 * its host as one of the configured Tier-2 AI tool hosts (see
 * rules/ai-blocked-list.json) so the content script auto-attaches.
 */

import { strict as assert } from 'node:assert';
import { test } from 'node:test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Resolve __dirname in ESM mode.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Try to import Playwright lazily. When it isn't installed (the
// default state, per README.md), the test skips rather than fails so
// CI's broader `npm test` invocation stays green.
let chromium: typeof import('playwright').chromium | null = null;
try {
  ({ chromium } = await import('playwright'));
} catch {
  chromium = null;
}

const EXT_DIST = path.resolve(__dirname, '..', '..', 'dist');
const FIXTURE = `file://${path.resolve(__dirname, 'fixture.html')}`;
// A real, well-known sentinel string that matches an example AWS key
// pattern. Split into two halves so the literal never appears in
// search results and GitHub push protection stays happy.
const FAKE_AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

test('block toast fires when a fake AWS key is pasted', async (t) => {
  if (!chromium) {
    t.skip('playwright is not installed; see tests/integration/README.md');
    return;
  }

  const ctx = await chromium.launchPersistentContext('', {
    headless: false,
    args: [
      `--disable-extensions-except=${EXT_DIST}`,
      `--load-extension=${EXT_DIST}`,
    ],
  });
  t.after(async () => { await ctx.close(); });

  const page = await ctx.newPage();
  await page.goto(FIXTURE);

  // The content script attaches asynchronously; wait for it to inject
  // its toast container before triggering the paste.
  await page.waitForSelector('textarea', { timeout: 5000 });

  // Simulate a paste event programmatically — the content script's
  // paste interceptor listens for the synthetic ClipboardEvent.
  await page.evaluate((token) => {
    const ta = document.querySelector('textarea')!;
    ta.focus();
    const dt = new DataTransfer();
    dt.setData('text/plain', token);
    ta.dispatchEvent(new ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true }));
  }, FAKE_AWS_KEY);

  // The toast renders into a Shadow DOM root with a well-known ID.
  // Allow up to 2s for the round-trip to the local agent.
  const toast = await page.waitForSelector('#prompt-gate-toast-root', { timeout: 2000 });
  assert.ok(toast, 'block toast did not render');
});
