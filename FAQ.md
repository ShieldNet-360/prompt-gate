# Prompt Gate — FAQ

Short answers to the questions people hit most, especially **"why was my
request blocked?"** and **"what do I do about it?"**

## Why was my request blocked?

Prompt Gate spotted something in what you were about to send (to an AI
chat, a code host, or another destination) that looks like a **secret** —
an API key, access token, password, private key, or similar credential.
By default Prompt Gate **blocks** the request so the secret never leaves
your machine.

## I was just asking a question — how do I send it safely?

Best practice: **take the secret out of the message and put a placeholder
in its place**, then send again. For example, instead of:

```
Why does this fail? AWS_KEY=AKIAIOSFODNN7EXAMPLE
```

send:

```
Why does this fail? AWS_KEY=[PLACEHOLDER]
```

The AI almost always has everything it needs from the *shape* of your
question — it doesn't need the real key. Replacing the value with
`[PLACEHOLDER]` (or `[REDACTED]`, `xxxxx`, etc.) keeps the credential on
your machine while you still get help.

This applies to anything sensitive: passwords, connection strings, tokens,
private keys. Swap the value, keep the structure.

## Is this a false positive?

Sometimes a value just *looks* like a secret. If you're confident it isn't
one (for example a public sample key, or a random string that isn't a real
credential), you can resend with the value masked as above, or — if it
comes up repeatedly for a domain you trust — add that domain to your
**allow list** in Prompt Gate → Settings.

## Can I turn blocking off, or allow a specific site?

Yes. Open Prompt Gate from the menu bar / system tray → **Settings**:

- **Categories** — choose what's allowed, inspected, or blocked.
- **Allow / Block lists** — exempt (or always-block) specific domains.

If your device is managed by your organization, some of these may be
locked by policy.

## Does Prompt Gate send my data anywhere?

No. Prompt Gate is privacy-first: it processes content **in memory** and
persists **zero** per-event content, domain names, IP addresses, or user
identifiers — only aggregate counters. Nothing about your traffic is
uploaded. (One optional, off-by-default setting lets *you* keep a local
history of blocks on your own machine; it's never sent anywhere.)

## How do I report a false positive or a missed secret?

Open an issue on the repository. Please **do not paste the real secret** —
describe the pattern or share a masked example.

## Where do I get help or read more?

See the project README and the docs in the repository.
