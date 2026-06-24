# Over-engineering audit (2026-06-24)

Read-only audit of `main` @ `138b631`. "Lazy senior dev" lens — the best code is
code never written. No behavior changes; this is the work-list for a
deletion-first cleanup.

**Backup branch:** `backup/pre-cleanup-2026-06-24` (snapshot of `main` before any
cleanup). **Working branch:** `chore/over-engineering-cleanup`.

Rung = the most-damning rung the finding fails:
1 YAGNI/dead · 2 duplicate-in-repo · 3 stdlib · 4 native platform · 5 existing dep · 6 one-liner.

Sorted by impact. ~2,400 deletable lines + 1 dependency.

| file:line | rung | problem | simpler approach (+ ~lines) |
|---|---|---|---|
| `electron/src/pages/Settings.tsx` (whole, 483) | 1 | Orphaned — `main.tsx` reimplements settings inline, never imports it. | Delete. −483 |
| `scripts/{macos,linux,windows}/build-*`, `prompt-gate.wxs`, `agent/nfpm.yaml` | 2 | Second packaging path rebuilds the same artifacts `electron-builder.yml` ships; unreferenced in CI. | Delete. −280 |
| `Justfile` (whole, 310) | 2 | Near line-for-line twin of root `Makefile`. | Drop one. −310 |
| `electron/src/pages/Status.tsx` (whole, 177) | 1 | Orphaned — `main.tsx` reimplements status/history. | Delete. −177 |
| `proxy/proxy.go:738-826 & 884-1016` | 6 | `deniedHTML` / `blockedHTML` are two ~130-line near-identical block pages. | One templated builder. −190 |
| `dlp/classifier.go:28` (+ `pipeline.go:365`, `types.go:16`) | 1 | `ClassifyContent` result discarded (`_ = ClassifyContent(canonical)`); enum narrows nothing. | Delete file + type + call. −140 |
| `electron/src/components/Logo.tsx` (whole, 135) | 1 | Imported nowhere; screens use `SetupIcon`. | Delete. −135 |
| `electron/src/main.tsx:124-465` | 2 | `DashOverviewPage`/`DashStatsPage` duplicate `Status.tsx` + two `timeAgo`/`fmtTime` copies. | One set + one `timeAgo`. −120 |
| `Makefile`/`Justfile`/`scripts` (config.yaml literal) | 3 | `config.yaml` body re-emitted via `printf` in 4-5 places though checked in. | `cp config.yaml`. −80 |
| `config/config.go:245-327` | 6 | `merge()` = 80 lines of per-field `if override.X != ""`. | Decode YAML onto `Default()`-seeded struct. −75 |
| `electron/src/main.tsx:480-540` | 4 | Hand-rolled pointer-drag swipe state machine for a 3-page pager. | CSS `scroll-snap`. −80 |
| `.github/workflows/notify-ntfy-downloads.yml` | 1 | Daily cron + Actions-cache dance to track download totals (vanity metric). | Drop. −70 |
| `electron/StatsCard.tsx + CategoryToggle.tsx` | 1 | Only used by the orphaned pages; dead once those go. | Delete after orphans. −70 |
| `electron/src/main.tsx:11-78,605-647` | 6 | ~12 inline hand-typed SVG icon components. | Icon module / set. −60 |
| `electron/src/api/agent.ts:234-270` | 1 | `getUpstreamCA/set/clear/getTamperStatus/getProxyListenAddr` never called by a page. | Drop unused surface. −45 |
| `.github/workflows/dlp-patterns.yml:43-79` | 6 | `gh pr diff`+grep scope-detector runs every PR to report green on non-DLP PRs. | Native `paths:` filter. −40 |
| `config/config.go:195-243` | 3 | `dlpIntOverlay` + second full YAML `Unmarshal` only to tell omitted-vs-0 for 4 ints. | `*int` fields. −35 |
| `dlp/cache.go:131-157` | 1 | Hit/miss/eviction telemetry "for /api/status" read only by a perf test. | Drop counters + `Stats()`. −35 |
| `agent/Makefile` (26) | 2 | Targets duplicate root Makefile + Justfile. | Keep one. −27 |
| `dlp/pipeline.go:139-253` | 1 | `DisabledCategories()/Cache()/ResetCache()/Correlator()` no non-test callers. | Drop. −25 |
| `dlp/pipeline.go:423-452` | 5 | `evaluatePatternSafe` per-pattern `recover()` though worker already wraps in `logging.Recover`. | Rely on goroutine recover (if per-job result not load-bearing). −22 |
| `dlp/correlator.go:116-134` | 1 | `Forget`/`ActiveSessions` used only by tests. | Remove until wired. −20 |
| `dlp/allowlist.go:220-236` | 1 | `Cleanup` called only by tests; `Allows` already honors expiry. | Remove until scheduled. −17 |
| `dlp/scorer_context.go:42-62` | 1 | 10+ `DestinationKind*`/`ElementKind*` consts; only `CodeHost`/`NetworkBody` read. | Drop unread members. −16 |
| `heartbeat/heartbeat.go:73-85` | 2 | `strictCheckURL` re-implements the SSRF guard in `profile.rejectPrivateHost` (3-way drift w/ alerter). | Shared `httpguard`. −15 + de-drift |
| `api/handle_sysconf.go:348-368` | 3 | `proxyListenParts` hand-rolls host:port split + digit accumulator. | `net.SplitHostPort`+`strconv.Atoi`. −15 |
| `extension/src/content/scan-client.ts:40-58` | 3 | `generateSessionID` 3 fallback tiers in an always-secure context. | `crypto.randomUUID()`. −12 |
| `proxy/proxy.go:614-623` | 6 | `combineReaders` 9-line wrapper over `io.MultiReader`, one caller. | Inline. −9 |
| `extension/.../main-world-network.ts:181-195` | 2 | `extractFetchBody` and `bodyToText` are the same logic twice. | One helper. −8 |
| `dlp/salt.go:69-86` | 3 | `parseSaltHex` manual `\r\n` trim loop + length recheck. | `bytes.TrimRight`+`hex.Decode`. −8 |
| `agent/internal/logging/*` (logrus, `go.mod:9`) | 5 | logrus (3 files) only for leveled logging + `WithField` + TextFormatter. | stdlib `log/slog`. −1 dep |
| `proxy/proxy.go:1120` | 6 | `bytesToString` wrapper; "no alloc" comment false (`string(b)` copies). | Inline `string(buf)`. −5 |
| `store/store.go:71-75` | 1 | Dead `dir := filepath.Dir(path)` block ending in `_ = dir`. | Delete. −5 |
| `extension/src/options/options.ts:19,32` | 1 | "verbose toast" toggle stored but never read. | Remove (or wire). −10 |
| `.github/workflows/{ci,docs,release}.yml` | 1 | `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: true` transitional no-op. | Delete 3 stanzas. −6 |
| `api/server.go:232` | 1 | `Server.once sync.Once` declared, never used. | Delete field. −1 |
| `dlp/bloom.go` (whole) | 1 | Named a "bloom layer" but is a plain `map[string]struct{}` exact set. | Rename to `publicexample`; drop bloom framing. doc-only |

## Top 5 (do first, deletion-only, near-zero risk)
1. **Dead Electron UI** — `Settings.tsx`+`Status.tsx`+`Logo.tsx`+`StatsCard`/`CategoryToggle`, dedupe `main.tsx` dashboard. ~900 lines. *(verified unimported)*
2. **Second packaging path** — `scripts/*/build-*` + `.wxs` + `nfpm.yaml`. ~280. *(verified unreferenced)*
3. **One of Makefile/Justfile/agent/Makefile** + `cp config.yaml`. ~340.
4. **Collapse the two proxy block-pages** into one builder. ~190.
5. **Delete `classifier.go`** — result discarded. ~140. *(verified)*

Honorable mention (bug-risk, not just lines): `config.go` `merge()`+`dlpIntOverlay` double-unmarshal (~110) — likeliest spot for an omitted-vs-zero bug.

### Left alone deliberately (not over-engineering)
per-OS `notify` no-op stubs · `*Adapter` import-cycle breakers · redaction engine (intentionally feature-hidden, fail-closed) · SSRF/path-traversal guards · a11y `role`/`aria` code.
