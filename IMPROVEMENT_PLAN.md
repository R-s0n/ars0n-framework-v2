# Ars0n Framework v2 — Improvement Plan

> Rebuilt 2026-05-31 after a working-tree loss. This is the single source of truth for the work ahead. It covers **five goals**, each broken into **~1-day steps ("Days")** so we can execute one at a time. We start with **Goal 1 — Day 1**.

---

## The Five Goals

1. **Front-end performance & scale** — keep the UI responsive with **10,000+ subdomains / live web servers** per target. (Today it crawls / freezes at scale.)
2. **Auto Scan survives a browser refresh** — move the Wildcard auto-scan orchestration server-side so it keeps running when the browser is refreshed/closed.
3. **Concurrent multi-target scanning** — run scans against multiple scope targets at once and move freely between targets/flows, safely.
4. **Notifications / Toasts** — toast on **every scan completion**, and one unified high-visibility toast system (top-right, red background, black text, stacked).
5. **Gaps & hardening** — the issues found in a full top-to-bottom review: security (RCE/SSRF/SQLi/secrets), resilience (stuck/orphaned scans, crashes), data lifecycle (unbounded growth, unsafe migrations), the MCP server, and a testing safety net.

## Guiding Constraints & Decisions (preserve these)

- **No functional changes** except three the user explicitly requested: (a) auto-scan must survive refresh (Goal 2 — a fix), (b) the toast restyle (Goal 4), (c) the Launch Pad workshop ad no longer auto-opens (keep its code). Everything else must be **behavior-preserving** — same workflows, same data, same ROI scores, just faster/safer.
- **Concurrency = Model A (locked):** keep the shared per-tool containers; add a **scan queue + per-tool concurrency limit** (default 1 for shared-container tools, higher for `docker run --rm` tools) + a global ceiling. Per-scan ephemeral containers (Model B) are deferred.
- **Verification approach (hard-won):** verify from the **shell** — `docker compose build` (compile), `curl`, `docker logs`, `docker exec … psql`. The **pentest-mcp browser is unreliable** — it drops during the multi-minute rebuilds between steps; treat it as best-effort and, per the standing rule, **if it fails twice, assume the change worked and move on**. To verify *scale* (Goal 1) we need a large dataset loaded — import a big `.rs0n` from the scan-data repo (e.g. Grammarly).
- **Test targets:** Company = `FloQast`, Wildcard = `floqast.app`, URL = `https://www.floqast.app`.
- **Safety rails:** work on a branch (keep `main` clean), **commit after each verified Day**, and never run destructive/irreversible changes blind — DB data-migrations (FK adds, retention/pruning) can crash startup or delete data and need backups + care.
- **Stack control:** `docker compose up --build -d` brings up all 25 containers; rebuild a single service (`docker compose build api` / `... client`) to compile-check fast. `ai_service` is `profiles:[ai]`-gated and does not start by default.

## Current Architecture (as-built)

React 19 SPA (`client/src`, CRA) → nginx (strips one `/api`, **no gzip**) → Go API (`gorilla/mux`, `server/`) → PostgreSQL (pgx v5). Plus ~20 tool Docker containers driven via the host Docker socket, and a Node MCP server (`docker/mcp-server`). `App.js` is **9,308 lines** (~350 `useState`, 59 `useEffect`, **0 `useMemo`/`useCallback`**). No virtualization or data-fetching library. Scan orchestration (auto-scan) runs **in the browser**; the Go backend runs each tool as a detached `context.Background()` goroutine and is otherwise a passive store.

---

## Goal 1 — Front-end performance & scale (the diagnosis)

The UI dies at 10k because of, in order of impact:
1. **The `target-urls` mega-payload** (`GetTargetURLsForScopeTarget`, `server/utils/liveWebServers.go:1206`): returns **every row with the full HTTP body + base64 screenshot + all headers/katana/ffuf/findings** — GBs at 10k — and the ROI/MetaData/Screenshot screens load it all, parse on the main thread, render screenshots inline (`App.js:4009/4027`, `ScreenshotResultsModal.js`). **#1 killer.**
2. **No compression** anywhere (nginx + Go).
3. **No virtualization** — several modals `.map()` the whole array (Screenshot grid renders *all* base64 images; LiveWebServers "Metadata" tab; `ExploreAttackSurfaceModal`; `ManageEndpoints`).
4. **Polling-timer leak** — ~31 `monitor*ScanStatus` effects keyed on `[activeTarget]`, recursive `setTimeout`, **no cleanup, no `AbortController`** (`monitorScanStatus.js:45`); stale responses overwrite current state.
5. **Client-side ROI scoring** — `calculateROIScore` runs ~40 regexes over the whole array on every open (`ROIReport.js`).
6. **Target-switch request storm** — ~60 fetches fire on every switch (`App.js:1344`), incl. a triplicated effect + duplicate monitor; backend **N+1** (`GetAttackSurfaceAssets`, `consolidateAttackSurface.go:3450`) and **missing indexes** (O(n²) subdomain ingest, `amassUtils.go:733`).

### Goal 1 — Day-by-day
- **Day 1 — `G1.1` Lean `target-urls` list (BE).** Add a default lean projection (drop `http_response`/`screenshot`/headers/katana/ffuf/findings; return `id,url,status,tech,roi_score,has_screenshot`) + `?limit/offset` pagination + `(scope_target_id, roi_score, id)` index. *Verify: `curl` payload size GB→MB.*
- **Day 2 — `G1.2` Per-row endpoints (BE).** `GET /target-urls/{id}` (full detail) + `GET /target-urls/{id}/screenshot` (image on demand). *Verify: `curl` one row / one image.*
- **Day 3 — `G1.3` ROI report — lazy screenshots (FE). DONE (partial).** ROI list fetch now uses `?screenshot=false`; the report lazy-loads the current target's image via `GET /target-urls/{id}/screenshot` instead of carrying every base64 PNG. **Deferred:** "read `roi_score` from the DB / stop recomputing regexes" is **not possible yet** — the DB `roi_score` is a constant `50` (`INTEGER DEFAULT 50`, never written back by the client); the real score is computed client-side. So the report still ships `http_response`/headers/katana/ffuf to score on the main thread. Making the list fully lean requires server-side scoring — moved to **G1.11–G1.13** (port `calculateROIScore` to Go + one-time re-score). *Verify: open ROI report; scores unchanged, payload drops the screenshots.*
- **Day 4 — `G1.4` MetaData + Screenshot modals (FE). DONE.** Screenshots render as `<img loading="lazy" src=…/screenshot>` (no inline base64) in all three screens. ScreenshotResultsModal now consumes the **lean** list (`?lean=true`). MetaDataModal still needs the heavy analytical fields (katana/ffuf/DNS/headers/findings for its filter/sort/expand), so it fetches `?screenshot=false&response=false` (drops the two biggest blobs, keeps the rest). **Deferred:** making MetaData *fully* lean (per-row counts in the list + lazy detail-on-expand) belongs with virtualization — **G1.6/G1.10**. Backend: `GetTargetURLsForScopeTarget` gained opt-in `?screenshot=false` / `?response=false` + an always-present `has_screenshot` flag (default payload unchanged). *Verify: open both modals at scale; images load lazily.*
- **Day 5 — `G1.5` Build `VirtualizedTable`/`VirtualizedList` (FE). DONE.** Added `react-window` (+ `client/.npmrc` `legacy-peer-deps=true` so it installs on React 19) and two shared components in `client/src/components/`: `VirtualizedList` (dynamic-height, auto-measures rows via ResizeObserver, auto-sizes its own viewport — handles variable/expandable content) and `VirtualizedTable` (sticky flex header + virtualized flex-row body, built on `VirtualizedList`). *Verify: constant DOM nodes at 10k.*
- **Day 6 — `G1.6` Apply virtualization (FE). DONE (4 of 4).** All four target screens virtualized: **ScreenshotResultsModal** (→ `VirtualizedList`; expand state in parent), **ExploreAttackSurfaceModal** (→ `VirtualizedTable`; columns now flex-weighted/even), and — completing the two deferred Accordion screens — **ManageEndpointsModal** (`EndpointAccordion`) and the **LiveWebServers "Metadata" tab** (`LiveWebServersResultsModal`). For the two Accordion screens, the per-item Bootstrap `<Accordion>` expand state was **lifted to the parent** (ManageEndpoints: single `expandedId`, matching the old one-open-at-a-time Accordion; LiveWebServers metadata: a `Set` of `expandedMetadataIds`, since those rows were independent accordions and multiple could be open) so a row stays expanded when it scrolls out of and back into the virtualized window. Each item became a clickable header (with a chevron) + a conditional body, rendered through `VirtualizedList`. Nested inner accordions (katana/ffuf sub-lists) inside the metadata body were left as-is. *(The standalone MetaDataModal and the LiveWebServers "Live Servers" tab are already paginated at 25/page, so they didn't need this.)* *Verify: smooth 10k scroll; expand a row, scroll away and back — it stays expanded.*
- **Day 7 — `G1.7` react-query layer (FE). DONE.** Added `@tanstack/react-query` + a `QueryClientProvider` at the root (`index.js`, tuned defaults: staleTime 30s, gcTime 5m, retry 1, no refetch-on-focus). New `client/src/hooks/useTargetURLs.js` wraps every heavy target-urls read with AbortSignal **cancel-on-switch**, in-flight **de-dup**, and **caching**, keyed by `(scopeTargetId, projection)` where projection ∈ full/lean/no-screenshot/meta. Migrated all four heavy reads: **ScreenshotResultsModal** uses the hook directly; **Metadata / ROI / Metadata-config** are driven from `App.js` via show-flag-gated queries mirrored into the existing shared `targetURLs` state (modals unchanged). Optimistic edits (row delete, scan-complete refresh) go through wrapped setters that also write the query cache, so a reopen can't resurrect a deleted row. *Verify: switch targets with a modal open → no stale data; reopen → instant from cache.*
- **Day 8 — `G1.8` Migrate remaining fetches + kill the storm (FE). DONE (dedup); monitor migration folded into G1.9.** Removed the duplicate work that fired on every target switch: the **triplicate Amass-Enum-Company effect** (3 byte-identical effects → 1; each fired ~3 requests), the **duplicate Metabigor company monitor** effect (was running two identical recursive pollers), and a **triple-duplicate config load** (`loadAmassEnumConfig/IntelConfig/DNSxConfig` were called both in dedicated effects and again in the big load effect). Net: ~13 fewer requests + 4 fewer recursive polling chains per switch, behavior-preserving (the removed effects were exact copies of ones that remain). **Note:** the heavy fetches (target-urls) were already moved to react-query in G1.7; migrating the **~31 recursive `setTimeout` monitors** to a managed layer is **G1.9's job** (the unified cancelable poller) — doing it here then rewriting there would be double work. The remaining one-shot count/load fetches are left as-is for now (low payoff, high churn; revisit with testing). *Verify: count in-flight requests on switch — should be materially lower.*
- **Day 9 — `G1.9` Unified cancelable scan poller (FE). DONE.** New `client/src/utils/scanPolling.js` exports `pollTimeout()` (a cancelable, epoch-tagged drop-in for `setTimeout`) + `cancelAllScanPolls()`. All **36** `monitor*ScanStatus` utils were codemodded to reschedule through `pollTimeout` instead of `setTimeout` (zero logic change — only how the next tick is scheduled). `App.js` gained one effect whose cleanup calls `cancelAllScanPolls()` on every `activeTarget` change/unmount; React runs cleanups before setups, so a target's old recursive chains are killed before the new target's monitors restart. Fixes the **timer leak** (chains used to accumulate forever — effects had no cleanup) and the recurring **stale-write races** (cancelled chains stop fetching+setState for a target you left). *Residual:* a single in-flight fetch at switch-time resolves once, immediately corrected by the new target's pollers. *Behavior note:* background polling of a **non-active** target now stops on switch (it was only ever surfaced via the leak); cross-target completion is Goal 2 (server orchestrator) + Goal 4 (toasts). *Verify: `getPendingScanPollCount()` stays bounded across many target switches.*
- **Day 10 — `G1.10` Debounce + memoize + stable keys (FE). DONE.** New `client/src/hooks/useDebounce.js`. Wired debounce (250ms) into all four filterable result modals so typing stays instant but the filter/sort over (up to 10k) rows only runs after the user pauses: **MetaDataModal** & **LiveWebServersResultsModal** (already `useMemo`'d — fed the debounced filters via a shadowed local + dep swap), **ManageEndpointsModal** (debounced `searchTerm` feeding its filter effect) and **ExploreAttackSurfaceModal** (debounced the filters array feeding `applyFiltersAndSort`). The filter inputs stay bound to the immediate state (responsive); only the derivations key off the debounced copy. **Stable keys:** fixed the three `key={index}` table rows in LiveWebServersResultsModal (network ranges → `cidr_block`, discovered IPs → `ip_address`, live servers → `url`); the other modals' main rows already key by `id` via the G1.6 `VirtualizedList`/`VirtualizedTable` `itemKey`/`getRowKey`. *(Derivations: MetaData/LiveWebServers use `useMemo`; ManageEndpoints/ExploreAttackSurface keep dep-gated effects — also only recompute on real dep changes — left as effects to avoid churn. Remaining `key={index}` are static inner sub-lists (badges, DNS rows) that don't reorder.)* *Verify: type in a filter at 10k — keystrokes stay responsive, results settle ~250ms after typing stops.*
- **Day 11 — `G1.11`+`G1.12`+`G1.13` (mixed). G1.12 + G1.13 DONE; G1.11 needs a tested pass.**
  - **`G1.13` DONE (BE).** `GetAttackSurfaceAssets` no longer runs 1 + N queries (10k+1). Added `fetchAssetRelationshipsBatch` — one query with `parent_asset_id = ANY($1::uuid[]) OR child_asset_id = ANY($1::uuid[])`, grouped in Go into a `map[assetID][]rel` and attached to each asset (to both parent and child, matching the old per-asset query). *Verify: 1 relationships query regardless of asset count.* (Old per-asset `fetchAssetRelationships` left in place, now unused — harmless in Go.)
  - **`G1.12` DONE (FE).** ROI report no longer freezes: `calculateROIScore` (~40 regexes/target) was running over all targets synchronously in a `useMemo`, blocking the main thread for seconds at 10k. Now scored in **200-row chunks that yield to the browser** between chunks (cancelable on close/target change), so the modal + spinner stay responsive. Logic unchanged (no extraction). *(A true web worker / server-side scoring would be off-thread entirely — deferred to avoid a risky 360-line scoring extraction; server-side also unblocks G1.3's DB roi_score.)* *Verify: open ROI on a large dataset — no freeze; spinner then results.*
  - **`G1.11` NOT done — needs a build+browser-tested pass (FE).** The ~70 modals are **always-mounted** (`<XModal show={...} />`, not `{show && <XModal/>}`) — so converting imports to `lazy()` alone wouldn't defer anything (the chunk still loads on mount); it only code-splits the main bundle. True on-demand loading additionally requires converting each render site to **conditional rendering**, which changes Bootstrap modal mount/unmount lifecycle + per-modal data-fetch effects — high regression surface across ~70 components, **no safe fallback** (a missed Suspense boundary or a fetch-on-mount modal = crash/behavior change). Recommend doing this as its own focused pass with a rebuild + browser check, ideally on the heaviest result modals first. *Verify: smaller initial bundle; modals still open/fetch correctly.*
- **Days 12–16 — `G1.14` Decompose `App.js` (FE). STARTED (safe first increment); bulk deferred to post-testing.** First increment (zero behavior change): pulled the pure scan-metric helpers out of App.js into `client/src/utils/scanMetrics.js` (`getHttpxResultsCount`, `calculateEstimatedScanTime`) and **deleted 3 dead module-level functions** that had no call sites — `getAmassIntelNetworkRangesCount`, `getMetabigorNetworkRangesCount`, and App.js's **own** simpler `calculateROIScore` (~108 lines; the real ROI scoring is the elaborate one in `ROIReport.js`). Net: App.js −158 lines, no runtime change. **The bulk — feature modules + scoped contexts so a state change re-renders one panel not the whole app — is the highest-risk work in Goal 1, has no safe fallback, and overlaps Goal 3 / G3.4a (per-target state).** Recommend doing it incrementally *after* G1.1–G1.13 are validated in the browser, so this big refactor doesn't contaminate that test run. *Verify: a state change re-renders one panel, not the whole app.*

**Goal 1 ≈ 14–17 days.**

---

## Goal 2 — Auto Scan survives a browser refresh (the diagnosis)

The 19-step Wildcard auto-scan is a **for-loop in the browser** (`wildcardAutoScan.js:401`); the backend just stores the `current_step` the client POSTs (`updateAutoScanState`, `main.go:780`) — there is **no server-side sequencer**. On refresh the loop dies; the in-flight tool finishes (detached goroutine) but nothing advances. The resume effect (`App.js:1606`) has `[]` deps guarded on async `activeTarget`, so it **never fires on a hard refresh**. Tables exist (`auto_scan_sessions`, `auto_scan_state`, global-singleton `auto_scan_config`) and the durable per-tool goroutine model already exists — so the fix is **relocating the loop into Go**.

### Goal 2 — Day-by-day
- **Day 1 — `G2.1a` Server orchestrator skeleton (BE).** `RunAutoScanOrchestrator` goroutine launched from `session/start`: sequences the 19 steps (port step list + config→step map), calls existing `ExecuteX` in-process, persists `current_step` + `steps_run`. *Verify: scan advances with no browser open.*
- **Day 2 — `G2.1b` Limits + pause/cancel + config snapshot (BE).** Port `max_consolidated_subdomains`/`max_live_web_servers` checks + pause/cancel honoring into the orchestrator; use per-session `config_snapshot`, not the global singleton. *Verify: limit-pause works server-side.*
- **Day 3 — `G2.2` Crash/restart recovery (BE).** On startup, resume `status='running'` sessions from `steps_run`. *Verify: restart API mid-scan → it keeps going.*
- **Day 4 — `G2.3` Real cancellation (BE).** Cancelable context per scan so cancel actually kills the running tool process. *Verify: cancel → container process stops.*
- **Day 5 — `G2.4a` Thin client (FE).** Start = POST `session/start`; UI subscribes to server state; delete the in-browser loop (`startAutoScan`/`resumeAutoScan`/`waitForScanCompletion`/`getAutoScanSteps`). *Verify: refresh mid-scan → progress persists.*
- **Day 6 — `G2.4b` Pause/cancel/refresh UI from server status (FE).** Derive controls + "Cancelling…" from server state, not in-memory flags. *Verify: pause/cancel work after a refresh.*

**Goal 2 ≈ 6 days.**

---

## Goal 3 — Concurrent multi-target scanning (the diagnosis)

Two layers are broken. **Front-end:** everything is keyed to one `activeTarget`; ~40 per-tool state slots are single globals (`App.js:406-738`); `handleActiveSelect` (`:1995`) blind-resets ~70 of them; no `AbortController`, so a still-running monitor for target A writes A's data into the slots now showing B. **Back-end (the deceptive trap):** most tools `docker exec` into a **shared per-tool container** writing to **FIXED paths** (`nucleiUtils.go:218-477` `/output.jsonl`; `urlScanUtils.go:1929` `/tmp/ffuf-output.json`; `bruteForceUtils.go:157/238/503` `/tmp/shuffledns-temp`,`/tmp/cewl-temp`; subdomainizer) with cleanup that `rm`s peers' files — so two concurrent same-tool scans **silently corrupt** each other. There are **no concurrency guards/limits**, and `auto_scan_config`/`user_settings` are global singletons. The safe pattern already exists (`scan_id`-keyed paths: httpx `liveWebServers.go:235`, arjun, x8). **Back-end safety must land before the UI can launch concurrent scans.**

### Goal 3 — Day-by-day
- **Day 1 — `G3.1a` scan_id-key nuclei paths (BE).** vuln/ssl/tech/screenshot → per-scan in-container paths + scoped cleanup. *Verify: two concurrent nuclei scans don't collide.*
- **Day 2 — `G3.1b` scan_id-key ffuf/shuffledns/cewl/subdomainizer (BE).** *Verify: two concurrent same-tool scans OK.*
- **Day 3 — `G3.2a` Scan queue + limits + start-guard (BE).** Per-tool concurrency limit + global ceiling + idempotent start-guard (reject duplicate tool+target running). *Verify: excess scans queue, don't collide.*
- **Day 4 — `G3.2b` Route all `Run*Scan` through the queue (BE).** Expose queue position. *Verify: every tool obeys the limit.*
- **Day 5 — `G3.3` DB write safety (BE).** `target_urls` upsert keyed by `(url, scope_target_id)` (B7); serialize per-target consolidation (C9). *Verify: overlapping-URL targets don't corrupt each other.*
- **Days 6–7 — `G3.4a` Per-target scan-state store (FE).** Keyed-by-target map = the `ScanStateContext`; migrate core scan state off the globals. **Shares G1.14.** *Verify: two targets show independent state.*
- **Day 8 — `G3.4b` `activeTarget` = view selector (FE).** Stop the `handleActiveSelect` blind-reset; add `AbortController` guards so old-target writes can't land on the new target. *Verify: switch targets mid-scan, no bleed.*
- **Day 9 — `G3.5` Active-scans registry + multi-target poller (FE).** Track all targets with running scans, not just the viewed one (builds on G1.9). *Verify: a background target's completion updates the right target.*
- **Day 10 — `G3.6` Running-scans dashboard + concurrent-start UI (FE).** *Verify: start 3 targets, all tracked.*
- **Days 11–12 — `G3.7` Wildfire/Slowburn server-side (BE+FE).** Batch orchestrator that enqueues per-target runs; browser monitors (needs G2.1a + G3.2). *Verify: a batch survives a refresh.*

**Goal 3 ≈ 11–12 days.**

---

## Goal 4 — Notifications / Toasts (the diagnosis)

Today there is **one** dark, easy-to-miss toast at bottom-center (`App.js:5880-5918`, `.custom-toast` in `index.css:144-168`, white body text), driven by 47 call-sites; **separate** toast impls live in `SettingsModal`/`GlobalScansModal`/`ScopeTargetDetails`; it's a single-boolean model (a new toast overwrites the last); and **no scan completion ever raises a toast**.

### Goal 4 — Day-by-day
- **Day 1 — `G4.1` `ToastProvider` + `useToast` (FE).** Array-based (stacking, not a single boolean), one top-right container, **red background / black text / bold**, slide-in, per-variant duration. *Verify: stack two toasts; styling matches.*
- **Day 2 — `G4.2` Migrate all toasts (FE).** Move the 47 App.js call-sites + the `SettingsModal`/`GlobalScansModal`/`ScopeTargetDetails` toasts to `useToast`; delete the duplicate containers. *Verify: existing messages appear top-right; no duplicate containers.*
- **Day 3 — `G4.3` Scan-completion toasts (FE).** Emit from the unified poller/registry on a terminal status transition, naming **target + tool + outcome + metric** (e.g. "✓ httpx — example.com — 1,234 live servers"); plus auto-scan run/step completion. Needs **G1.9 / G3.5**. *Verify: finish a scan → correct toast, including for a non-viewed target.*

**Goal 4 ≈ 3 days.**

---

## Goal 5 — Gaps & hardening (the diagnosis)

A full review found: **Security** — unauth command injection → root RCE (Metabigor `sh -c`, `metabigorCompanyUtils.go:153+`; custom header/UA `bash -c`, `screenshotUtils.go:177`/`metaDataUtils.go:398`), `.rs0n` import **SQLi** (raw identifiers, `dbImportExport.go:1252`), **SSRF** (import-from-URL, `:610`), **secrets logged in cleartext** (`main.go:1655-1657/1693`), no auth + `CORS:*`, docker socket mounted. **Resilience** — **no timeout/reaper** so scans hang `pending`/`running` forever; restart **DELETEs** pending scans (`database.go:1604`); only 1/25 goroutines `recover()` (one panic crashes the whole API); cancel doesn't kill the tool; pool defaults; no HTTP timeouts; tool errors discard the Go `err`. **Data lifecycle** — unbounded scan-row growth (no retention); **orphan tables** with no FK (`subdomains`/`dns_records`/`ips`/`asns`/`subnets`, `database.go:830-875`); base64 screenshots in the DB + a broken `rm "*"` cleanup; ad-hoc `log.Fatalf` migrations; export OOM; partial-commit import. **MCP server** — schema-drift queries that silently return empty; in-memory "truncation" with no SQL `LIMIT`; no auth. **Testing** — essentially zero tests; no CI; tool versions pinned `@latest`/`:latest` (breaks output parity across rebuilds); 2,117 ad-hoc `log.Printf`; `/health` is a stub.

> Note: most of Goal 5 was prototyped once before the loss (15 commits), so these have **proven implementations** and should go fast.

### Goal 5 — Day-by-day
- **Day 1 — `G5.1` Command injection → argv (BE).** Metabigor (6 sites) + custom header/UA nuclei screenshot+metadata, via argv + `cmd.Stdin`, no shell. *Verify: scans still run; 0 `sh -c`/`bash -c` with user input.*
- **Day 2 — `G5.2` Input-handling hardening (BE).** Stop logging API-key secrets; SSRF guard on import-from-URL (block internal/reserved IPs + redirects); gzip-bomb decompression cap; scope-target input validation. *Verify: secret absent from logs; internal URL rejected; bomb rejected; FloQast targets still accepted.*
- **Day 3 — `G5.3` `.rs0n` import SQLi (BE).** Table allow-list + identifier sanitization (`pgx.Identifier`); report real inserted/failed counts. *Verify: malicious column key rejected; legit `.rs0n` still imports.*
- **Day 4 — `G5.4` Crash-safety (FE+BE).** Top-level `ErrorBoundary`; `/health` pings the DB; `http.Server` read-header/idle timeouts (no write-timeout). *Verify: bad render → fallback; `/health` 503 when DB down.*
- **Day 5 — `G5.5` Goroutine resilience (BE).** `recover()` on **all ~39** scan goroutines (helper + one-line defer each); startup marks interrupted `pending`/`running` scans `error` instead of deleting. *Verify: forced panic doesn't crash API; staged rows flip to error on restart.*
- **Day 6 — `G5.6` Timeouts + reaper (BE).** `exec.CommandContext` per-tool timeout + a periodic stale-scan reaper. *Verify: a hung/old scan transitions to error.*
- **Day 7 — `G5.7` Compression + indexes + pool (BE).** gzip (nginx + Go); `subdomains(scan_id,subdomain)` (O(n²) fix) + `scope_target_id` indexes on the ~40 scan tables; pool `MaxConns`. **Overlaps Goal 1.** *Verify: `Content-Encoding: gzip`; indexes in `pg_indexes`.*
- **Day 8 — `G5.8` Cleanup (FE+BE).** Delete dead `ScopeTargetDetails.js`; strip `console.*` in prod; remove the duplicate/triplicate effects (**overlaps G1.8**); add a `/version` endpoint + build stamp. *Verify: build clean; no console spam.*
- **Day 9 — `G5.9` MCP server (MCP).** Fix the schema-drift queries (align columns/tables; stop swallowing errors); push real SQL `LIMIT`/keyset; add an auth token to the SSE transport. *Verify: MCP query tools return correct, bounded data.*
- **Days 10–12 — `G5.10` Testing safety net.** Seeded 10k/25k/50k dataset; characterization tests for the Go parsers/consolidation/ROI; API-contract tests; one smoke test per workflow; CI (`go build/vet/test` + `npm build/test`); **pin every tool + `postgres` version**. *Verify: CI green; rebuilds reproducible.*
- **Days 13–14 — `G5.11` Data lifecycle (RISKY — backups first).** Retention/pruning of old scans; add the missing FKs (+ orphan sweep first, or the migration crash-loops); screenshots to files (keep only path). *Verify: on a copy: prune works, FK add succeeds, old screenshots load.*
- **Day 15 — `G5.12` Auth + CORS (needs your decision).** Lock CORS to the client origin, bind to localhost by default, add an auth scheme. *Verify: unauth request rejected; client still works.*

**Goal 5 ≈ 15 days.**

---

## Totals, overlaps & sequencing

| Goal | Days |
|---|---|
| 1 — Front-end perf/scale | ~14–17 |
| 2 — Auto-scan survives refresh | ~6 |
| 3 — Concurrent multi-target | ~11–12 |
| 4 — Toasts | ~3 |
| 5 — Gaps & hardening | ~15 |
| **Total (less overlaps)** | **~45–50 focused engineering-days** |

**Overlaps (don't double-count):** G1.14 (App.js decomposition) ≈ G3.4a (per-target state) — same refactor. G1.9 (unified poller) is the base for G3.5 and G4.3. G5.7 (gzip + indexes) overlaps Goal 1; G5.8 cleanup overlaps G1.8.

**Recommended order:** Goal 1 Days 1–4 first (kill the mega-payload — biggest visible win, mostly shell-verifiable) → G1.9 poller → G1.5/6 virtualization → G1.7/8 react-query → Goal 3 backend safety (G3.1–G3.3) → per-target state (G3.4, which also advances G1.14) → G3.5/6 → Goal 4 (needs the poller/registry) → Goal 2 (largely independent — slot in anytime) → Goal 5 hardening interleaved (do **G5.10 testing scaffold early** to protect the refactors; **G5.1–G5.6 security/resilience** are quick proven wins) → G3.7 and G5.11/G5.12 last.

**We start with Goal 1 — Day 1 (`G1.1`).**

---

## Appendix — key file:line hotspots
- Mega-payload: `server/utils/liveWebServers.go:1206`; consumers `App.js:4009/4027`, `ScreenshotResultsModal.js`.
- Polling leak: `client/src/utils/monitorScanStatus.js:45`; ~31 effects `App.js:1367-1538`; no `AbortController` anywhere.
- Single-target state: `App.js:406-738` (slots), `handleActiveSelect` `App.js:1995`.
- Auto-scan: client loop `wildcardAutoScan.js:401`; passive backend `main.go:780/1058`; dead resume effect `App.js:1606`; tables `database.go:23-34/98-135`.
- Concurrency collisions: `nucleiUtils.go:218-477`, `urlScanUtils.go:1929`, `bruteForceUtils.go:157/238/503`, `javaScriptLinkDiscovery.go:525-641`; safe pattern `liveWebServers.go:235`.
- Toasts: `App.js:5880-5918`, `index.css:144-168`, 47 call-sites; dup impls in `SettingsModal`/`GlobalScansModal`/`ScopeTargetDetails`.
- Security: `metabigorCompanyUtils.go:153+`, `screenshotUtils.go:177`, `metaDataUtils.go:398`, `dbImportExport.go:610/1252`, `main.go:1655-1657`, `scopeTargetUtils.go:47`.
- Resilience: `database.go:1604` (restart DELETE), `amassUtils.go:646` (err dropped), `main.go:40/391` (pool/listen), `katanaCompanyUtils.go:121` (only recover).
- Data lifecycle: orphan tables `database.go:830-875`; screenshot cleanup `screenshotUtils.go:310`; migrations `database.go:1599`.
