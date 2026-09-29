# Session Refresh: interactive, MFA / OAuth aware refresh

Status: ALL PHASES (0-5) IMPLEMENTED (2026-09-28). Server builds, Go unit tests pass, 349 MCP tests
pass, 15 client session-modal tests pass. See "Implementation status" below for what each phase
shipped.

Phase 1 shipped: `auth_flow_steps.interaction` column + `session_refresh_runs` table; the resumable
runner in `server/utils/sessionRefreshInteractive.go` (pause at an input step -> awaiting_input ->
resume without re-running earlier steps); `/session-tokens/{id}/refresh` returns needs_input with a
run_id; `POST /session-refresh-runs/{run_id}/input|cancel`, `GET /session-refresh-runs/{run_id}`;
step-annotation UI in ManualAuthFlowModal (with auto-suggestion via DetectStepInteraction); the
interactive prompt in RefreshSessionModal; MCP `check_session_tokens` actions
provide_refresh_input / refresh_status / cancel_refresh and `interaction` on the add/update step
tools. Verified: unit tests, an end-to-end pause/resume/substitution integration test, the
non-interactive path unchanged, and the client renders with no console errors.

An adversarial review workflow (3 dimensions x verify) then ran over the Phase 1 diff and confirmed 6
low-severity defects, all since fixed and re-verified: (1) per-token concurrency - a per-token mutex
now serialises start and resume so two concurrent refreshes/inputs cannot race or double-submit;
(2) the replay_failed gate is now guarded by startedFrom==0 so a resume never falsely reports "every
step failed"; (3) resume now continues from the EXACT vars/set-cookies/bodies persisted at the pause
(new captured/set_cookies/bodies columns) instead of re-deriving them from the sanitized stored
bodies; (4) ManualAuthFlowModal preserves a non-input interaction on save instead of wiping it;
(5) the Cancel handler is wrapped in try/catch/finally; (6) bulk "Refresh all expired" cancels a run
that pauses for a code and tells the operator to refresh it individually instead of leaving an
un-answerable paused run. Concurrency + persisted-resume both re-tested end to end.

## Implementation status (2026-09-28)

All phases are in the tree on the working branch. What each one shipped:

- Phase 0 (honest routing + re-paste + companions): `token_role` companion classification
  (`reCompanionCookie` / `classifyCookieRole` in sessionTokens.go, applied in the Set-Cookie and
  Cookie-header parsers); companions refreshed WITH the credential (refreshCompanionCookies);
  active-but-expired counting (`sessionTokenLooksDead` + `sessionTokenRejectedStatuses`, surfaced as
  `counts.expired`); the auth flow made optional on a token; Paste re-paste in both modals.

- Phase 1 (interactive replay for MFA/OTP/password): as described above.

- Phase 2 (TOTP auto-generation): `interaction.kind = totp_auto` with a stored base32 secret;
  `hotp`/`generateTOTP`/`cleanBase32Secret` (RFC 4226/6238, vectors under test); the runner computes
  the code inline at the step, no pause; editor field in ManualAuthFlowModal; MCP `totp_secret`.

- Phase 3 (out-of-band actions): `interaction.kind = action`, `action_kind` approve | magic_link; the
  runner pauses with a no-value Continue (approve) or a URL input (magic_link); `refreshStepPause`;
  RefreshSessionModal renders both; MCP `action_kind` + `provide_refresh_input` with `no_value`.

- Phase 4 (browser re-capture, the OAuth / Cloudflare answer): `RecaptureSessionToken` +
  `freshestCapturedCookieHeader` read the newest manual-crawl capture for the token's host and upsert
  it; `POST /session-tokens/{id}/refresh-recapture` with a `since` guard; the Browser panel in
  RefreshSessionModal; MCP `recapture` action with `since`.

- Phase 5 (grouping + auto-refresh + full parity): `session_tokens.auto_refresh` column, wired through
  the struct/scan/view/payload/create/update SQL; `autoRefreshDue` (pure, unit-tested gate: opted in +
  active + refresh_proven via last_refreshed_at + flow classifies "replay" + near expiry or rejected)
  and `StartSessionAutoRefreshLoop` (a one-minute ticker started from main.go, a no-op until a token
  opts in, with a 15-minute per-token cooldown); `ClassifyFlowRefreshability` +
  `GetFlowRefreshClassification` + `detectFlowProvider` label each flow replay / interactive /
  browser_only; the auto-refresh switch (replay flows only) and companion note in RefreshSessionModal;
  companion + auto badges in ManageSessionsModal; MCP `auto_refresh` on manage_session_tokens and a new
  `classify_auth_flow_refresh` tool (with guidance entry).

Refreshability classification and auto-refresh are deliberately conservative: auto-refresh only ever
fires on a pure-replay flow that has already been refreshed once by hand. It is opt-in per token and
off by default; with nothing opted in the loop does nothing. This is a convenience over the manual
refresh, never a guardrail on it: the manual Refresh, Paste, Browser re-capture and replay paths run
whatever the operator points them at, unrestricted.

## Adversarial review of Phases 0-5 (2026-09-28)

A 6-dimension review workflow (each finding then adversarially verified by 3 skeptics, majority-refute
kills) ran over the whole subsystem diff. It surfaced 5 confirmed correctness defects (0 false
positives; none were the forbidden scope/guardrail non-findings). All 5 are fixed and verified:

1. (high) `ClassifyFlowRefreshability` did not treat a non-runnable interaction kind ("browser") as
   non-replay, so a flow with a browser hand-off step classified as "replay" and the unattended
   auto-refresh loop could send its earlier credential-bearing steps to the live target before the
   runner refused the hand-off step. Fixed: the classifier now flags any step whose kind is not in
   `interactionKindsRunnable` as browser_only, mirroring the runner's guard. Unit test added; verified
   live (a browser-step flow now returns browser_only).
2. (med) The "every step failed" short-circuit compared `failed`(refusals+send-errors) against
   `sent`(attempts), firing when refusals equalled successes and discarding a genuinely refreshed token.
   Fixed: replaced with an explicit `succeeded` counter; the guard is now `succeeded == 0 && failed > 0`.
3. (med) `resumeSessionRefreshRun` only checked the run was still awaiting, not that the pause being
   answered was the one the caller saw, so a stale/double /input could satisfy a later approve-continue
   or store an OTP under the wrong var. Fixed: the /input request now carries `step_id`; resume rejects
   a mismatch. Wired through the client (echoes input_request.step_id) and MCP (`step_id` param).
4. (med) `freshestCapturedCookieHeader` dropped the `since` freshness filter silently when the
   timestamp did not parse, so a malformed `since` (reachable via the MCP recapture action) returned a
   stale capture as success. Fixed: fail closed; the recapture handler returns 400 on a bad `since`.
   Verified live.
5. (med) In ManualAuthFlowModal, `editingId` was never set after creating a new flow, so a retry after
   a partial step-save failure POSTed a duplicate flow and split the steps. Fixed: `setEditingId` is
   called as soon as the flow is created, before the step loop.

## Problem

Refresh today = replay a linked auth flow headlessly. That works for a password login that
issues a session cookie, but not for the logins most real targets use:

- MFA (TOTP / SMS / email OTP / push) needs a code or an approval at replay time.
- OAuth / federated (Google, Microsoft, Okta) needs an interactive third-party login.
- CAPTCHA / Turnstile / Cloudflare needs a browser-solved challenge (and `cf_clearance`).
- Magic link needs the operator to click an emailed link.
- Single-use OAuth codes are dead on the first replay.

The verdict must never be "cannot be replayed." It is "this refresh needs user action X" - a code,
an approval, a browser step, or a re-paste - and the framework's job is to identify which, separate
the cases, and facilitate the user supplying exactly that, through the UI and MCP.

## Model

Refresh becomes a resumable, human-in-the-loop run:

```
running -> awaiting_input(request)  --provide-->  running -> completed
       \-> awaiting_browser(handoff) --capture--/         \-> failed / cancelled
```

The existing `{{af:NAME}}` variable machinery is the injection point: a user-supplied MFA code is
just a variable added to the map before the step that needs it.

### Step interaction kinds (`auth_flow_steps.interaction` JSONB)

| kind         | meaning                                            | user does                         | auto? |
|--------------|----------------------------------------------------|-----------------------------------|-------|
| `none`       | replay verbatim (+ CSRF substitution)              | nothing                           | yes   |
| `totp_auto`  | framework computes TOTP from a stored secret       | nothing (secret stored once)      | yes   |
| `input`      | needs a value (`totp`/`otp`/`password`/`text`/...) | type the value                    | no    |
| `action`     | push approval / magic link                         | approve or click, then continue   | no    |
| `browser`    | CAPTCHA / Cloudflare / federated IdP               | complete in-browser; framework captures | no |

### Flow refresh strategy (derived from steps, overridable)

- `replay` - all steps `none`/`totp_auto` -> fully automatic.
- `interactive_replay` - some steps need input/action -> pauses for them.
- `browser_recapture` - cannot be replayed at all -> refresh = re-capture the session in the browser.

### Token refresh mode

Inherits from the linked flow. A flowless token is `manual_paste` or `browser_recapture`. This is
where companions (`cf_clearance`, `*csrf*`, routing cookies) refresh WITH the credential rather than
demanding their own flow.

## Identifying the requirement

1. Operator annotation (authoritative), set when building / recording / importing a flow.
2. Static auto-detection at save/import (suggests the annotation): MFA/OTP prompt language,
   CAPTCHA/Turnstile scripts, Cloudflare 403 / `cf_clearance`, redirects to a known IdP host,
   single-use value shapes / placeholders.
3. Dynamic detection at refresh time (catches un-annotated flows): the runner inspects each step's
   response and pauses to ask when it sees a challenge it did not expect.

## UI and MCP

- UI: Refresh Session becomes interactive - a code input, an "approved, continue" button, a
  "paste landed URL", a "refresh in browser" handoff, or a "paste fresh value". The flow builder /
  recorder annotates each step with its interaction (auto-suggested).
- MCP: `manage_session_refresh` is multi-turn - `start` returns completed / needs_input / needs_browser,
  `provide_input` resumes, `status` / `cancel`. TOTP-with-secret resolves server-side; the agent never
  holds the secret. `needs_browser` is surfaced to the human.

## Phases

- Phase 0 - honest routing + re-paste: companion classification; interactivity classifier + warnings;
  "paste fresh value" as refresh on the Refresh Session row.
- Phase 1 (THIS ONE) - interactive replay for user-supplied values (MFA/OTP/password):
  `auth_flow_steps.interaction` + `session_refresh_runs` + resumable runner; step-annotation UI;
  Refresh Session prompts and resumes; MCP `manage_session_refresh` start/provide_input/status/cancel.
- Phase 2 - TOTP auto-generation from a stored secret (RFC 6238).
- Phase 3 - out-of-band actions: push approval + magic link.
- Phase 4 - browser-assisted re-capture (the OAuth / Cloudflare answer) via the extension.
- Phase 5 - session grouping (credential + companions), auto-refresh once refresh_proven, full MCP
  parity, provider labelling.

## Phase 1 contract (implementation reference)

- `auth_flow_steps.interaction` JSONB, default `{}` (== `none`). Shape:
  `{ "kind": "none"|"input", "var_name": "mfa_code", "input_kind": "otp"|"totp"|"password"|"text"|"url"|"token",
     "prompt": "Enter the 6-digit code", "optional": false }`
  Phase 1 implements `none` and `input`; the other kinds validate but are handled in later phases.
- `session_refresh_runs`: id, token_id, scope_target_id, auth_flow_id, status
  (running|awaiting_input|completed|failed|cancelled), current_step (the step_order paused before),
  input_request JSONB, provided JSONB ({var_name: value}), outcome_status, outcome_detail,
  new_value_set, trace JSONB, timestamps.
- Runner: extends the existing refresh replay. Resumes WITHOUT re-running earlier steps - it seeds the
  cookie jar and the `{{af:}}` var map from the already-stored responses of steps before the pause
  (the `replayStepByID` pattern), so a one-time MFA challenge issued by an earlier step stays valid.
- `/session-tokens/{id}/refresh` goes through the runner: completes in one shot (classic shape) when
  no step needs input, or returns `status: needs_input` with `run_id` + `input_request`. New routes:
  `POST /session-refresh-runs/{run_id}/input`, `GET /session-refresh-runs/{run_id}`,
  `POST /session-refresh-runs/{run_id}/cancel`.

STANDING: this is authorized testing. The runner sends the operator's session wherever the flow
points, by design; MFA codes / TOTP secrets are the operator's own. No scope/exclusion framing.
