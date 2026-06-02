# User Guide

This guide is for end-users of Prompt Gate.

## 1. The tray icon

A small shield icon sits in your system tray.

- **Green shield** — agent running, all rules loaded, no integrity issues.
- **Red shield** — agent is offline or a tamper alert is active. Open the tray
  menu and click **Status** to see the cause (e.g. service stopped, rule file
  modified).

Clicking the tray icon opens a small menu:

- **Status** — quick view of agent health and aggregate counters.
- **Settings** — managed-mode banner if your org enrolled this host, otherwise
  category toggles (Allow / Inspect / Block) for each policy tier.
- **Quit** — stops the agent.

The agent is designed to be invisible during normal use. You only see the tray
icon and, occasionally, a block notification.

## 2. Block notifications

When you paste or upload content that matches a DLP rule, you'll see a small
ephemeral notification in the corner of your screen:

> 🛡 **Blocked**: your message contained an API token (pattern: *GitHub PAT*).

A few things to know:

- The notification fades after a few seconds. There is **no record** of which
  content was blocked beyond a single counter (`dlp_blocks_total`).
- The text you tried to send is **never** stored, logged, or transmitted.
- The block happens at the browser extension or proxy layer — the destination
  service never receives the content.

If you believe the block was wrong, you can **report a false positive** (see
§4).

## 3. What data the agent does / does not collect

The agent **does** persist:

- A small SQLite database (~4 KB) of policy configuration and **integer**
  aggregate counters: `dns_queries_total`, `dns_blocks_total`,
  `dlp_scans_total`, `dlp_blocks_total`, `tamper_detections_total`.
- Rule files (domain lists, DLP patterns) — these are the rules themselves,
  not access logs.

The agent **does not** persist:

- Domain names you visited
- URLs, IPs, ports
- Content you typed or pasted
- DLP scan content or matched-pattern names
- Timestamps of per-event activity

The [`store/privacy_test.go`](../agent/internal/store/privacy_test.go) test
sweeps every text column in the SQLite database and asserts that none of those
values reach disk. The same test runs in CI on every PR.

## 4. Reporting a false positive

If a block looks wrong:

1. **Note the pattern name** shown in the tray notification (e.g.
   *Stripe Secret Key*).
2. Open a **False Positive** issue on the [GitHub repo](https://github.com/ShieldNet-360/prompt-gate/issues/new?template=false_positive.md).
3. Include the pattern name and a **redacted snippet** of the content that
   triggered the block. Do **not** paste the actual secret-looking string —
   replace the secret-shaped part with `<redacted>` or generic placeholders.
4. The rule contributor team will triage and either tighten the pattern
   regex, add an exclusion, or close the issue with an explanation.

We track FP/FN rates against a 50-sample corpus in
[`agent/internal/dlp/accuracy_test.go`](../agent/internal/dlp/accuracy_test.go).
The budget is **FP < 10%** and **FN < 5%**; we will not merge a pattern that
takes us out of budget.

## 5. Browser extension behaviour

If the browser extension is installed:

- It hooks the paste and form-submit events for the Tier-2 domains in the
  active ruleset.
- Tier-1 domains are passed through with no inspection.
- Tier-3/Tier-4 domains never resolve (DNS NXDOMAIN), so the extension never
  sees them.

The extension speaks to the agent over native messaging on `127.0.0.1`. It
does not call out to any external service. Source code lives in
[`extension/`](../extension/) — TypeScript with content scripts, background
worker, and unit tests.

## 6. Disabling the agent

Use the tray menu's **Quit** entry to stop the agent. Re-launch it via the
desktop shortcut, the macOS Login Items list, or systemd. If your org
enrolled this host in managed mode, the agent will re-launch automatically
within ~30 seconds.
