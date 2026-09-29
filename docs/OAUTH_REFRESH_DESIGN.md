# OAuth Access/Refresh Token Capture and the Creation/Refresh Flow Split

Status: design. ALL OAuth Phases 1-6 IMPLEMENTED (2026-09-28/29). (Plus a test-harness single-source-of-truth
fix, utils.AuthSessionSchema, so DB-backed tests can no longer drift from the production migration.)

## OAuth Phases 5-6 implemented (2026-09-29)

Phase 5 (surface):
- MCP: manage_session_tokens now shows credential_kind + the four refresh_* fields (only when set) and
  accepts refresh_flow_id/refresh_strategy/refresh_transport on update; new check_session_tokens action
  capture_oauth (promote the corpus's freshest token response); new tool build_refresh_flow (adopt a
  captured refresh request as a refresh flow and link the anchor). Guidance + census updated.
- Client: RefreshSessionModal gained a "Capture OAuth tokens" button and a per-row refresh-flow hint
  (refresh_strategy / refresh_transport). ManageSessionsModal shows a "refresh secret" badge (token_role
  refresh) and an "OAuth access" badge (credential_kind oauth_access_token), and suppresses "expired" for a
  refresh row (it is not graded like a credential).
- Deferred (noted): a per-flow OAuthRole on the detected-flows FlowSummary (summarizeFlow is body-blind);
  the actionable candidate-level oauth_role (Phase 4) already drives adoption.

Phase 6 (BFF/Cloudflare fallback):
- refresh_transport is derived when a refresh flow is adopted (deriveRefreshTransport: a pure-replay flow is
  headless, anything else browser_only) and stored on the anchor, so the operator sees whether the container
  can run the refresh or it must go through the browser. Browser-driven refresh is the shipped
  RecaptureSessionToken; auto-refresh eligibility already gates on the refresh flow classifying replay
  (Phase 3), so a browser_only refresh naturally stays out of the unattended loop. Nebius resolves to
  refresh_flow_id=NULL / browser-recapture, exactly as the design predicted.

Verified: full utils suite green; MCP 349 tests; 15 client modal tests; TestAdoptSetsRefreshTransportHeadless.
Live on Nebius: capture_oauth no-ops (BFF), candidates carry oauth_role. All three containers rebuilt.

Adversarial review (3 dimensions x 3-vote verify) found 3 confirmed findings, all fixed: (1+2, med) both the
MCP compactToken field and the client "OAuth access" badge read t.credential_kind, but credential_kind was a
profile-only column (surfaced as profile.kind), never top-level on SessionTokenView, so it never populated;
fixed by serializing credential_kind top-level (added to sessionTokenCols + SessionToken + scan +
SessionTokenView + view, read-only), so both the MCP and the client read it unchanged (verified live: all
Nebius rows now carry credential_kind=opaque_session_id). (3, low) the ManageSessions header expired-count
did not apply the refresh-role exclusion the per-row badge uses, so a refresh secret was counted expired but
not badged; fixed to mirror the badge. Regression coverage via the existing session-token read tests.

## OAuth Phase 4 implemented (2026-09-28)

Detection + adoption, in server/utils/sessionOAuthDetect.go (+ AuthFlowCandidate.OAuthRole in
captureBridgeUtils.go + a route in main.go):
- Body-aware detection: extractGrantType reads grant_type from a form or JSON request body (no existing
  helper did); oauthCaptureRole classifies a captured request as "refresh_request"
  (grant_type=refresh_token, or a /session/renew|/auth/refresh path) or "creation_exchange"
  (grant_type=authorization_code, a single-use ?code=/?state=, an IdP host, /oauth2/authorize). grant_type
  is the primary signal because /oauth2/token serves both grants; a /token call with no grant_type stays
  ambiguous ("") rather than mis-labelled.
- AuthFlowCandidate.OAuthRole surfaces this in the candidates list so the operator can spot the app's own
  silent-refresh request. classifyAuthCapture is untouched (a separate helper, no signature ripple).
- Adoption: POST /auth-flows/{id}/refresh-from-captures (BuildRefreshFlowFromCaptures) builds a
  flow_purpose='refresh' flow from the selected captures, rewrites the captured refresh_token literal to
  {{token:refresh_token}} (requires >=1 seeded), attaches OAuth response extractions, and links the flow as
  the anchor token's refresh_flow_id + refresh_strategy (default oauth_refresh_grant), checking RowsAffected.
  From then on refreshFlowIDFor routes refresh through it (Phase 3).

DEFERRED to Phase 5 (UI): surfacing a per-flow OAuthRole on the detected-flows FlowSummary. summarizeFlow is
deliberately body-blind (FlowCapture carries no bodies), so populating it inline needs FlowCapture +both
SELECTs +the scan extended, or a sidecar map; that is UI-surfacing work and belongs with the badge in Phase 5.

Verified: pure tests for the three detectors; an end-to-end test (TestAdoptRefreshFlowThenRefresh) that
adopts a captured refresh request, confirms the templatized body + anchor link, then runs a refresh through
the adopted flow (Phase 3) and confirms it spends the stored refresh token, mints, and rotates. Live on
Nebius: 30 of 65 candidates correctly tagged creation_exchange, 0 refresh_request (a BFF has no browser
refresh request), and refresh-from-captures rejects bad input. Full utils suite green (SSTI oracle gap
accepted). api rebuilt.

Adversarial review (3 dimensions x 3-vote verify) found 2 confirmed findings, both fixed: (1, med) the form
refresh_token seed regex was unanchored, so it over-matched any field whose name ends in refresh_token
(x_refresh_token, device_refresh_token), corrupting an unrelated field or defeating the >=1-seeded gate;
fixed by requiring a leading delimiter (^|[&?;]). (2, low) extractGrantType form-parsed a JSON body first,
so an embedded &grant_type= inside a JSON string value (a redirect_uri query) produced a spurious
grant_type; fixed by trying JSON first and never form-parsing a valid JSON object. Regression tests added.

## OAuth Phase 3 implemented (2026-09-28)

Headless refresh execution, so a stored refresh token actually renews the session:
- {{token:NAME}} placeholder namespace (authFlowsVariables.go), sibling of {{af:NAME}}, resolving from
  STORED session tokens (reserved vars keys "token:"+NAME). A refresh flow uses
  grant_type=refresh_token&refresh_token={{token:refresh_token}}. executeSessionRefreshRun seeds
  token:credential / token:access_token (the anchor value) and token:refresh_token (the linked refresh
  row); a missing value stays unresolved so the step is refused, never sent empty.
- writebackRefreshResponse: after the run, if the final response is an OAuth token response, writes the
  new access_token onto the anchor AND the ROTATED refresh_token onto the linked refresh row (WHERE
  token_role='refresh'), closing the rotation gap (issuers that invalidate the old refresh token on use).
  Falls through to the existing single-value extraction for cookie-session flows.
- Routing: refreshFlowIDFor(token) = refresh_flow_id when set, else auth_flow_id. startSessionRefreshRun,
  RefreshSessionToken's no_flow gate, runDueAutoRefreshes, and autoRefreshDue all use it, so a token whose
  creation flow is browser_only but whose refresh flow is a pure replay is refreshable and auto-refresh
  eligible via the refresh flow.

Verified: end-to-end test (TestOAuthRefreshGrantEndToEnd) with a mock token endpoint proves the runner
spends the stored refresh token, mints the new access token, rotates the refresh token, and a SECOND
refresh succeeds using the rotated one; plus pure tests for the namespace and routing. Full utils suite
green (with the unrelated SSTI oracle facility gap accepted). api rebuilt.

Adversarial review (3 dimensions x 3-vote verify) found 1 confirmed finding, fixed: writebackRefreshResponse
(and the fallback UPDATE) ignored RowsAffected, and pgx returns nil error for a 0-row UPDATE, so a rotation
UPDATE that matched 0 rows (the linked refresh row's role edited away from 'refresh', or the row deleted
mid-run) reported rotation success and silently dropped the freshly rotated refresh token, so the next
refresh would spend the invalidated one. Fixed: both writeback UPDATEs and the fallback UPDATE now check
RowsAffected; a 0-row anchor write falls through / fails honestly, and a 0-row rotation warns (the current
refresh still succeeded, but the operator is told the rotated token could not be stored and the next
refresh may fail). Regression test TestOAuthRefreshRotationZeroRowsIsNotFalseSuccess added.

## OAuth Phase 2 implemented (2026-09-28)

Shipped in server/utils/sessionOAuthCapture.go (+ route in main.go): captureOAuthTriad promotes a token
endpoint response into durable rows: the refresh token (token_role='refresh', never sent) and the access
token (credential, sent as Authorization: Bearer), linked by refresh_token_id. expires_in becomes a real
absolute expiry (ttlToExpiry, from the capture's observation time, UTC); a JWT's own exp is the fallback.
CaptureOAuthTriadForTarget scans the corpus for the freshest access + refresh and promotes them; POST
/session-tokens/target/{id}/capture-oauth exposes it. The id_token is deliberately deferred (it must
never go on the wire and its correct non-wired role is a later-phase decision). Verified: full utils
suite green; live on Nebius the endpoint correctly no-ops (BFF, no browser token).

Adversarial review (4 dimensions x 3-vote verify) found 3 confirmed findings, all fixed:
1. (high) The access-row upsert keyed on credential_kind, which the read-path reprofiler (GetSessionTokens
   -> AttachSessionTokenProfiles) rewrites from the token's bytes (a JWT access token becomes 'jwt'), so a
   re-capture missed the row, inserted a DUPLICATE, and orphaned the prior still-sendable access token.
   Fixed: identity is now the stable per-kind name (which nothing else rewrites); credential_kind is an
   INSERT-only hint left to the profiler thereafter. Regression test added.
2. (med) Same root cause from the wire-safety angle (orphaned access token stays on the wire). Same fix.
3. (med) The corpus scan discarded the capture timestamp, so a stale capture's opaque token got
   now+expires_in instead of capture_time+expires_in, storing a dead token as live. Fixed: expiry is
   computed from each capture's observation time; a token seen 3h ago with expires_in=3600 stores an
   already-passed expiry (so it is never attached to a scan). Regression test added.


## OAuth Phase 1 implemented (2026-09-28)

Shipped: token_role 'refresh' (a secret spent to mint, never on the wire, never graded) + tokenStatusRefresh;
the five session_tokens columns (refresh_token_id, refresh_flow_id, refresh_strategy, refresh_transport,
refresh_material_key), refresh_token_id/refresh_flow_id as UUID-string columns with FK ON DELETE SET NULL;
auth_flows.flow_purpose (default creation); credential_kind consts oauth_refresh_token and id_token; the
full read/write plumbing (struct, payload, cols, scan, insert, update, apply, view). Migrations live in BOTH
database.go (real DB) and SessionTokenProfileSchema (the list the throwaway test DB applies) with identical
definitions, because the test DB is not provisioned by createTables (a column added only to createTables reads
as "does not exist" in DB-backed tests; that is a pre-existing infra gap that also hid auto_refresh and
auth_flow_steps.interaction, worth a proper harness fix).

Adversarial review (4 dimensions x 3-vote verify) found 7 confirmed findings, all one root cause: the
per-token AuthMaterial/QueryParam/ApplyToURL refresh guards only cover the VALIDATION path, but FOUR other
paths read session_tokens directly and had no role filter, so a refresh secret would have been put on the
wire or mis-graded. All fixed and tested: (1) ApplySessionTokens (the real scan/crawl credential builder)
now excludes token_role='refresh'; (2) triageFreshCredential.sessionTokenCandidates excludes it; (3)
SessionStillHonoured excludes it from the query and skips a refresh verdict in the switch (no longer aborts
a scan); (4) credentialIsSendable (the ApplySessionTokens mirror behind the Authentication card counts)
reports a refresh row not-sendable. DB-backed test TestARefreshRoleSecretIsNeverAttachedToAScan pins the
scan path; pure tests cover wiring/validation/normalize/sendable. Verified on the real DB (columns + 3-value
CHECK + flow_purpose applied; existing tokens load unchanged).

---

Author scope: server (Go), client (React), MCP (Node).
Standing rules honored throughout: design for ANY app (Nebius is a test case, not the spec);
no scope/exclusion/deny/rate guards on any send/replay/refresh path (the only sanctioned internal
gate is the opt-in auto-refresh loop); capturing tokens/PII is the point, so values are stored in
the clear; no emdashes.

This plan EXTENDS the shipped session-lifecycle work (Manage/Refresh Sessions Phases 0-5, the
resumable refresh runner, ClassifyFlowRefreshability, RecaptureSessionToken, the profile engine,
flow detection). It does not redesign any of it. Every new capability is additive: a row that has
only `auth_flow_id` and `token_role='credential'` behaves exactly as it does today.

---

## 0. The problem, in one paragraph

A full interactive login (Google federation + Cloudflare + MFA) is `browser_only` and cannot be
replayed headlessly. But a live app keeps its own session alive WITHOUT redoing that login: a silent
token refresh (an OAuth `refresh_token` grant, a `/auth/refresh` or `/oauth2/token` call, an OIDC
`prompt=none` silent SSO, or a cookie-based session-renew request). Today the model has one flow per
token (`auth_flow_id`) and "refresh" means "replay that one flow," so it conflates the rare
interactive CREATION event with the recurring, ideally-headless REFRESH event. It also throws away
the OAuth `refresh_token` and `id_token` values that a login response carries (they live only as
transient in-memory `p.Attributes` and are never persisted). This design captures the OAuth triad as
distinct durable rows, links them, splits creation from refresh at the schema level, seeds a stored
refresh token into a headless refresh request, and writes back a rotated refresh token so the next
refresh does not fail. It degrades correctly to browser-recapture for confidential-client BFF apps
(Nebius) that never put a token in the browser.

---

## 1. Data model

Two orthogonal axes already describe a `session_tokens` row: `token_type` (HOW it travels:
header/cookie/api_key/bearer/query) and `token_role` (WHAT it is: credential/companion). We add one
role value, two credential kinds, one flow-purpose axis on `auth_flows`, and a small set of nullable
columns on `session_tokens`. No new tables.

### 1.1 New `token_role = 'refresh'` (one CHECK rewrite)

A `refresh` row is a stored secret SPENT to MINT another credential. It is NEVER attached to a
resource request, and it is NEVER graded by an honoured/not-honoured comparison; it is graded only by
whether it still mints (which `RecordRefreshProof` already handles). Its own `expires_at` IS tracked,
because a dead refresh token means the whole session is dead.

- `server/utils/sessionTokens.go:51-57`: add `tokenRoleRefresh = "refresh"` to the consts and to
  `validSessionTokenRoles`. `normalizeTokenRole` (`:64`) then accepts it, still defaulting empty to
  credential.
- `server/database.go:2993-2996`: the current block only ADDs `session_tokens_token_role_check` when
  absent (guarded by a `pg_constraint` SELECT), so it will not widen an existing DB. Replace it with
  the drop-and-recreate pattern the codebase already uses for `auth_flows_category_check` at
  `database.go:2875-2877`:
  ```sql
  ALTER TABLE session_tokens DROP CONSTRAINT IF EXISTS session_tokens_token_role_check;
  ALTER TABLE session_tokens ADD CONSTRAINT session_tokens_token_role_check
    CHECK (token_role IN ('credential','companion','refresh'));
  ```
- Behavior changes that MUST accompany the role:
  - `AuthMaterial` / `QueryParam` / `ApplyToURL` (`sessionTokens.go:1701-1760`) return nil / skip for
    a `refresh` row. A refresh token is never placed onto a resource request. This mirrors how the
    render layer must not send a credential the app never sends.
  - `normalizeSessionTokenWiring` (`:1772-1836`) validates that a `refresh` row carries a value but
    is never wired to a header/cookie/query slot.
  - Validation grading: treat `refresh` like `companion` in the not-graded-as-a-credential path
    (`sessionTokenLooksDead` and the validation verdict), but keep the `expires_at` check live.
  - `token_role` is not authoritative from a cookie NAME (on Nebius, `cf_clearance` and the CSRF
    cookie are stored as `credential` because a storing path set it explicitly). So the `refresh`
    role is assigned DELIBERATELY at capture time (by the token-response promoter in section 2.1),
    never inferred from a name.

### 1.2 New `credential_kind` values (Go-side only, no CHECK)

`credential_kind` is a free `VARCHAR(32)` profile column, so this is a pure enum change in
`server/utils/sessionTokenProfile.go:136-185`:
```go
CredentialKindOAuthRefresh CredentialKind = "oauth_refresh_token" // durable secret, spent to mint
CredentialKindOAuthID      CredentialKind = "id_token"            // names the principal, informational
```
`oauth_access_token` already exists. An `id_token` row is stored `token_role='companion'`
(informational, already JWT-parseable by `jwtExpiry`) unless the app actually sends it as the session
bearer, in which case it is a `credential`.

### 1.3 New columns on `session_tokens` (idempotent, via `SessionTokenProfileSchema`)

Add these to the idempotent `ADD COLUMN IF NOT EXISTS` list at
`server/utils/sessionTokenProfile.go:3462-3503`. None touch a CHECK. Add each to the `SessionToken`
struct (`sessionTokens.go:108-145`), the all-pointer `sessionTokenPayload` (`:150-170`), and
`sessionTokenCols` (`:172`).

```sql
-- The token -> token link. The ONLY token grouping today is a shared scope_target_id; this is the
-- first token->token FK in the schema. A derived credential (access token, and optionally the id
-- token) points at the durable refresh-role row that renews it. The refresh row's own
-- refresh_token_id is NULL. Reverse lookup ("all rows this refresh token renews") is
-- WHERE refresh_token_id = $refreshRowID. ON DELETE SET NULL so deleting the refresh token never
-- cascades away a working access-token row.
ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_token_id UUID
  REFERENCES session_tokens(id) ON DELETE SET NULL;

-- The creation/refresh flow split, the direct answer to "each session needs both an auth flow where
-- the session is created and a session refresh flow." auth_flow_id (database.go:2941, unchanged)
-- STAYS the CREATION flow (usually browser_only). refresh_flow_id is the headless REFRESH flow.
ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_flow_id UUID
  REFERENCES auth_flows(id) ON DELETE SET NULL;

-- The chosen executable renewal plan, distinct from refresh_mechanism (which names corpus evidence).
-- oauth_refresh_grant | replay_request | browser_recapture | none. Derived from detection, editable.
ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_strategy VARCHAR(24) DEFAULT '';

-- The honest Cloudflare answer, a CAPABILITY fact, never a permission gate.
-- headless | browser_only | unknown. See section 6.
ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_transport VARCHAR(16) DEFAULT '';

-- OPTIONAL writeback override: which JSON key in the refresh response updates THIS row. Empty means
-- derive the field from credential_kind (oauth_access_token->access_token,
-- oauth_refresh_token->refresh_token, id_token->id_token). Present only for apps that use
-- non-standard field names.
ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS refresh_material_key VARCHAR(64) DEFAULT '';
```

Note on the refresh token's OWN lifetime: because the refresh-role row is itself a `session_tokens`
row, its lifetime (from `OAuthTokenResponse.RefreshTTL`, i.e. `refresh_token_expires_in`) lands in
that row's existing `expires_at` / `measured_expires_at` / `ttl_seconds` columns. No separate
`refresh_ttl_seconds` column is needed. The parsed value that was thrown away as a transient
attribute now has a durable home on the correct row.

### 1.4 New `flow_purpose` on `auth_flows` (no CHECK touched)

`auth_flows.category` describes the auth ACTION (register/login/mfa_otp/magic_link/reset,
`database.go:2816`). Creation-vs-refresh is a DIFFERENT axis (a refresh flow could still be
"login"-category), so we do not overload `category`. Add an orthogonal column:
```sql
ALTER TABLE auth_flows ADD COLUMN IF NOT EXISTS flow_purpose VARCHAR(16) NOT NULL DEFAULT 'creation';
-- creation | refresh
```
`creation` is the safe default so every existing flow keeps its meaning. A flow the detector builds
from a silent-refresh capture is written `flow_purpose='refresh'`. This is what lets the auto-refresh
loop know which flow is the one safe to fire unattended, and lets the UI label the two.

### 1.5 No new tables; the session-lifecycle object is computed on read

We deliberately do NOT add a `sessions` table. The lifecycle object is filled on the read path,
exactly as `AttachSessionTokenProfiles` attaches the profile and as `RootKind`/`Source` are recomputed
on detected flows. A new `SessionLifecycle` struct (new file `server/utils/sessionLifecycle.go`) is
filled per `token_role='credential'` anchor row:

```go
type SessionLifecycle struct {
    AnchorTokenID    string        // the credential row
    CreationFlowID   string        // auth_flow_id
    CreationKind     string        // ClassifyFlowRefreshability(creation) -> usually browser_only
    RefreshFlowID    string        // refresh_flow_id
    RefreshKind      string        // ClassifyFlowRefreshability(refresh) -> replay for a real one
    RefreshStrategy  string        // oauth_refresh_grant | replay_request | browser_recapture | none
    RefreshTransport string        // headless | browser_only | unknown
    Linked           []LinkedToken // refresh + id tokens + companions (refresh_token_id + scope_target)
    Timeline         []Event       // session_token_events, kind create/refresh/validate
}
```
This reuses shipped grouping rather than a migration-heavy table. The user's "creation event vs
refresh event" maps onto `session_token_events` (a `create` kind at first establishment; `refresh`
events already exist).

### 1.6 Detected-flow OAuth role is recomputed on read, not stored (core plan)

Detected flows are re-segmented on every read with no stable row (`seeded_from_flow_id` is TEXT, not
an FK). So the per-flow OAuth role is COMPUTED on read (like `RootKind`), surfaced as a new
`FlowSummary.OAuthRole` field (`replayRequestFlows.go:200-267`). We persist NOTHING for a detected
flow until the operator ADOPTS one, at which point a real `auth_flows` row (with
`flow_purpose='refresh'`) is materialized. A `detected_flow_oauth` cache table keyed by `EncodeFlowID`
(the pattern `detected_flow_names` uses at `detectedFlowNames.go:75-90`) is a documented FOLLOW-UP if
per-read classification over a large corpus proves slow; it is not in the core plan.

---

## 2. Capture and detection

### 2.1 Capture the OAuth triad as three durable rows (SPA / public-client apps)

The parser already exists and is unused for storage: `ParseOAuthTokenResponse` yields
`OAuthTokenResponse{AccessToken, RefreshToken, IDToken, ExpiresIn, RefreshTTL}`
(`sessionTokenProfile.go:2037-2072`). Today its output only becomes transient `p.Attributes` in
`applyTokenResponseEvidence` (`:2370-2422`, which sets `oauth_refresh_token`, `oauth_id_token`,
`oauth_refresh_token_expires_in`) and `p.Attributes` is NEVER persisted (`SaveSessionTokenProfile`
writes 27 fixed fields; `LoadSessionTokenProfile` always returns `Attributes={}`).

New work: `captureOAuthTriad(ctx, scopeTargetID, capture)` in `sessionTokenProfile.go`, next to
`applyTokenResponseEvidence`. When a `manual_crawl_captures` or `auth_flow_steps` response body parses
as a token response, upsert through the existing identity-keyed `upsertParsedSessionToken`
(`sessionTokens.go:1093-1159`):
- access token: `token_role='credential'`, `credential_kind='oauth_access_token'`, `expires_at`
  derived from `expires_in` (see 3.3).
- refresh token: `token_role='refresh'`, `credential_kind='oauth_refresh_token'`, `expires_at`
  from `RefreshTTL`. The access row's `refresh_token_id` is set to this row's id.
- id token: `token_role='companion'`, `credential_kind='id_token'`, `refresh_token_id` set to the
  refresh row.

This is the concrete fix for the biggest model gap: the refresh/id values stop being transient and
become durable, linked rows. Reused: `ParseOAuthTokenResponse`, `jsonSeconds`,
`upsertParsedSessionToken`, `collectJSONStrings`. New: the promoter (~40 lines) and the two
`credential_kind` writes. Values stored in the clear (capturing them is the point).

### 2.2 BFF / confidential-client apps (Nebius): nothing token-shaped to capture

Grounded in the corpus (scope_target 313cbc0d-...): 0 response bodies contain `access_token`,
`refresh_token`, or `id_token`; 0 requests carry `Authorization: Bearer`. Nebius exchanges the code
server-side and the browser holds only the opaque HttpOnly `__Host-app_session` cookie. So
`captureOAuthTriad` creates NO refresh row for Nebius, and that is correct. The credential is captured
off the 864 subsequent request `Cookie` headers, which is exactly what `RecaptureSessionToken`
(`sessionTokens.go:951`) reads.

Known capture gap (upstream, called out honestly, not fixed by this plan's core): the session-birth
`Set-Cookie` is folded into `manual_crawl_captures.redirect_chain`, which stores only
`{from, location, statusCode}` with no headers, so all 20 `__Host-app_session` Set-Cookie rows in the
corpus are deletions. The design reads the credential off subsequent request `Cookie` headers (what
works) rather than depending on capturing the mint. An OPTIONAL later fix (section 6) promotes
redirect hops to carry per-hop response headers.

### 2.3 Body-aware refresh detection (creation vs refresh)

`findRefreshEndpoint` (`sessionTokenProfile.go:3324`, returns
`(bool, RefreshMechanism, string, string)`) matches URL only, so it cannot tell
`grant_type=refresh_token` (refresh) from `grant_type=authorization_code` (creation) at the same
`/oauth2/token`. Body inspection of `grant_type` is the single signal that separates the two events
and is NOT optional.

New work: `findRefreshEndpointForFlow(ctx, scopeTargetID, flowID)` reads request `post_data` via
`loadFlowDetectionBodies` + `NormalizeFlowTuple` (`flowDetectionActive.go:616`, already indexes bodies
by method+host+path, so the body-blind `FlowCapture` projection at `replayRequestFlows.go:136` is NOT
widened). It returns a role alongside the mechanism:
- `refresh` when the body carries `grant_type=refresh_token`, OR the path matches the silent-renew
  patterns (`refreshEndpointPatterns`, `:3159-3170`, which already enumerate `/oauth2/token`,
  `/(auth|session|token)s?/refresh`, `/(silent|renew)`, and `/authorize?...prompt=none`), OR a
  non-login response re-issues the session cookie with a fresh (not `Max-Age=0`) value.
- `creation` when the body carries `grant_type=authorization_code`, OR a hop crosses an IdP host
  (`reIdPHost`, `sessionRefreshInteractive.go:265`), OR the redirect carries a single-use
  `?code=`/`?state=` (`reSingleUse`, `:266`), OR a `reBrowserChallenge` (`:264`) is present.

`DetectRefreshCapability` (`:3189`) then reports mechanism and grant_type accurately. The strict
Available-vs-Proven ledger (`RecordRefreshProof`, two differing fingerprints) is unchanged.

### 2.4 Per-flow OAuth role classifier and new capture categories

- `classifyFlowOAuthRole(flow captureFlow, bodies) FlowOAuthClass`, called from `segmentCaptureFlows`
  / `captureFlow` (`replayRequestFlows.go:271-330`) right where `FlowSummary` is built, populating the
  new `FlowSummary.OAuthRole` (`creation_exchange | refresh_request | session_renew | none`). It uses
  the body-aware signals from 2.3 plus the three `ClassifyFlowRefreshability` discriminators. The
  redirect-continuation rule (`flowRedirectFollowSeconds=15`, `:64,450`) already stitches an
  authorize->callback->app chain into ONE flow, so recognition is co-located and needs no cross-flow
  join. The cross-host case matters: the session cookie set by an OAuth callback is often set on the
  APP host after the redirect while authorize/callback hops are on the IdP host, so the Set-Cookie
  recognizer looks across hosts within the one flow.
- `classifyAuthCapture` (`captureBridgeUtils.go:304`) currently suggests
  `login/register/mfa_otp/reset`. Its regexes already match `oauth|oidc|authorize|token|refresh` and
  `grant_type|refresh_token|access_token|id_token|client_secret`. Add two suggested categories,
  `oauth` and `oauth_refresh`, and a `grant_type` sub-branch: `grant_type=refresh_token` ->
  `oauth_refresh`; `grant_type=authorization_code` or `code=` -> `oauth`.

Reused: `ParseOAuthTokenResponse`, `refreshEndpointPatterns`, `reIdPHost`/`reBrowserChallenge`/
`reSingleUse`, `authFormFieldPattern`/`authBodyFieldPattern`, `loadFlowDetectionBodies`,
`NormalizeFlowTuple`, `segmentCaptureFlows`. New: `classifyFlowOAuthRole`, `FlowOAuthClass`,
`FlowSummary.OAuthRole`, `findRefreshEndpointForFlow`, two capture categories.

---

## 3. Refresh execution

All four changes are localized to the shipped runner and its helpers. The resumable state machine,
the shared cookie jar, the extraction engine, and the pause/resume logic are reused unchanged.

### 3.1 Seed the stored refresh token into the runner (the one genuinely new wire)

`executeSessionRefreshRun` (`sessionRefreshInteractive.go:716`) seeds `vars` only from prior-step
extractions (`run.Captured`), operator input (`run.Provided`, seeded at `:756`), and `totp_auto`.
Nothing seeds a STORED token value, so a one-step refresh flow cannot carry the stored refresh token.

New work: before the step loop, add a seeding pass. If the token has a `refresh_token_id`, load that
refresh row's `token_value` and expose it, plus the anchor, under a NEW placeholder namespace
`{{token:NAME}}` (a sibling of `{{af:NAME}}`, `authFlowsVariables.go:32`):
- `{{token:refresh_token}}` resolves to the linked refresh row's value.
- `{{token:credential}}` resolves to the anchor credential's value.

`substituteAuthFlowVars` / `prepareStepRequest` (`authFlowsVariables.go:244/383`) resolve it exactly
like `{{af:}}`, keeping the refuse-on-unresolved guard. A refresh flow can then be a single step:
`POST /oauth2/token` with `grant_type=refresh_token&refresh_token={{token:refresh_token}}&client_id=...`.
Reason to add a distinct namespace rather than seed a `{{af:}}` var: it is self-documenting and cannot
collide with a var a step legitimately extracted under the same name.

### 3.2 Multi-value writeback (fixes refresh-token ROTATION, the biggest correctness risk)

Today the tail of `executeSessionRefreshRun` (`:854-880`) pulls exactly ONE value via
`extractRefreshedTokenValue` (`sessionTokens.go:1566`) and updates only the credential. With
refresh-token rotation (common), the stored refresh token goes stale after the first refresh and the
NEXT refresh fails.

New work: after the step loop, add `writebackRefreshResponse(run, anchor)`. Parse the final
token-endpoint response with `ParseOAuthTokenResponse`, then for the anchor and each row linked by
`refresh_token_id` write the field named by that row's `refresh_material_key` (or, when empty, derived
from `credential_kind`): the new `access_token` to the credential row (as today), the ROTATED
`refresh_token` back onto the linked refresh row, the new `id_token` onto the id row. This generalizes
the shipped precedent `refreshCompanionCookies` (`sessionTokens.go:1416`), which already updates
several rows from one response but only by Set-Cookie name, into a body-key-to-row sibling. Prefer
driving the field-to-row mapping from the refresh flow's `extractions` (`AuthFlowExtraction`,
`authFlowsVariables.go:35`) so it stays declarative and testable. Reused:
`tokenValueFromBodies`/`collectJSONStrings`/`normalizeTokenKey` (`:1631/1661/1687`); extend
`sessionTokenBodyKeys` (`:1614`) to include `refresh_token`, `expires_in`, `refresh_expires_in`.

### 3.3 Honor `expires_in`

`DeriveSessionTokenExpiry(value, explicit)` (`fuzzCredentials.go:202`) honors an explicit expiry, else
parses a JWT `exp`; an opaque `access_token` that arrived with `expires_in:3600` gets a NULL expiry,
which reads as never-expires everywhere and defeats the auto-refresh lead-window trigger. Add a
relative-seconds branch (`now + expires_in`) fed by the parsed `OAuthTokenResponse.ExpiresIn`.
`ExpiryStyle` for these is `absolute`, `ttl_provenance=parsed`. The tidy way is to pass the computed
absolute time as the `explicit` argument so the existing "explicit always wins" branch handles it, and
to add the relative branch inside `DeriveSessionTokenExpiry` for the extraction path.

### 3.4 Route refresh to the refresh flow, then fall back

`RefreshSessionToken` (`sessionTokens.go:1376`) and `startSessionRefreshRun`
(`sessionRefreshInteractive.go:638`) resolve the flow in this order: `refresh_flow_id` when set
(headless), else `auth_flow_id` (today's behavior; may pause / `browser_only`), else the existing
`no_flow` message which points at recapture. `SessionRefreshRun.AuthFlowID` is seeded from whichever
was chosen, so `executeSessionRefreshRun` needs no structural change. `ClassifyFlowRefreshability`
runs on the REFRESH flow: a single `/token` POST has no IdP host, no challenge, no single-use code, so
it classifies `replay` and becomes auto-refresh eligible with NO new gating.

### 3.5 Auto-refresh: nothing new, no new gate

`autoRefreshDue` (`sessionRefreshInteractive.go:1019`) already requires `flowKind ==
flowRefreshReplay` plus a prior hand refresh, so a `browser_only` refresh naturally stays out of the
unattended loop. A materialized token-endpoint refresh flow classifies `replay` and becomes eligible
with the existing opt-in gate. The one sanctioned internal gate (the opt-in loop not sending
unsanctioned traffic) is untouched. No scope/exclusion/deny/rate guard is added anywhere on the
send/replay/refresh path; `refresh_mint_in_scope` remains a reporting label, not a send-blocker.

---

## 4. Turning a detected refresh mechanism into a replayable refresh flow

This is the payoff, and it reuses the shipped capture-to-flow builder:
1. Detection tags a flow `refresh_request` (or `session_renew`) via `classifyFlowOAuthRole` (2.4).
2. The Session Manager offers, on the session card, "Build refresh flow from detected request."
   Accepting calls the existing `CreateAuthFlowFromCaptures` path (`/auth-flows/{scope_target_id}/
   from-captures`, `main.go:691`), seeded from that flow's request(s), and writes the new flow with
   `flow_purpose='refresh'`.
3. The builder attaches automatically:
   - an extraction rule set (`AuthFlowExtraction`, `authFlowsVariables.go:35`, run by
     `runAuthFlowExtractions`) on the token-endpoint step capturing `access_token`, `refresh_token`,
     `id_token`, `expires_in` from the response body;
   - the `{{token:refresh_token}}` placeholder in the request body so the stored secret is injected at
     replay (3.1).
4. `session_tokens.refresh_flow_id` is set to the new flow; `refresh_strategy='oauth_refresh_grant'`
   (or `replay_request` for a cookie-renew).
5. The session now has the two-flow shape the user asked for: `auth_flow_id` = the interactive
   creation flow (`browser_only`), `refresh_flow_id` = the headless silent-refresh flow. Refresh uses
   the latter; when there is none (Nebius), refresh falls back to recapture.

For the BFF/opaque-cookie case (Nebius), there is no `grant_type` body and no token in any response,
so the classifier lands on `session_renew` only if a cookie-renewal request exists, and Nebius exposes
none. The correct outcome is `refresh_flow_id=NULL`, `refresh_strategy='browser_recapture'`,
`refresh_transport='browser_only'`, and refresh routes to `RecaptureSessionToken`. The model allows a
session whose refresh is recapture-only because every new column is nullable and the recapture path is
unchanged.

---

## 5. UI and MCP surface

### 5.1 Client (`client/src/modals/`)

- `ManageSessionsModal.js`: each `credential` card gains a Lifecycle section: "Created by: [creation
  flow] (browser-only)" and "Stays alive by: [refresh strategy]" with a transport badge (Headless /
  Browser only / Recapture only). The linked refresh and id tokens render as child rows under the
  anchor (via `refresh_token_id`), labeled by role and kind, never masked. A `refresh`-role row shows
  a distinct chip and is not graded like a resource credential.
- `RefreshSessionModal.js`: branch on `refresh_transport`. `headless` shows Replay (drives
  `executeSessionRefreshRun` on the refresh flow). `browser_only` shows "Refresh in browser"
  (Recapture) as the PRIMARY action and explains why headless is blocked, using the shared
  `REJECTED_STATUSES` vocabulary. Never present both as equals. A detected-but-unaccepted refresh
  request shows as "Proposed refresh flow: accept?".
- `AuthFlowModal.js` / `ManualAuthFlowModal.js`: allow linking a flow as the REFRESH flow (not just
  creation) and show `ClassifyFlowRefreshability` per slot, so the operator sees "creation =
  browser-only, refresh = replay" at a glance.
- `RequestFlowsModal.js` / `RecordAuthFlowsModal.js` (detected flows): show the `OAuthRole` badge and
  the "Adopt as refresh flow for <credential>" action that materializes the flow (section 4).

No new warnings or gates: validate over warn per the standing UX rule.

### 5.2 MCP (`docker/mcp-server/src/tools/`)

- `authsessions.js` (`manage_session_tokens`): expose and accept `token_role` (incl. `refresh`),
  `credential_kind`, `refresh_token_id`, `refresh_flow_id`, `refresh_strategy`, `refresh_transport`,
  `refresh_material_key`, and the child linked tokens. Add a `capture_oauth` action (run the
  promoter + materializer from a capture/flow id) and a `link_refresh` action.
- `authflows.js` (`classify_auth_flow_refresh`): also report `oauth_role` (creation vs refresh) and,
  when a refresh flow exists, its id.
- `requestflows.js` (`manage_detected_flows`): expose per-flow `oauth_role`, `mechanism`,
  `grant_type`, `token_endpoint`, and a `build_refresh_flow` action mirroring the UI adopt.
- `guidance/data.js`: one teaching note that the creation flow is usually `browser_only` and the
  refresh flow is the headless one; that a `refresh`-role token is SPENT to mint and never attached;
  and that an opaque-cookie BFF session refreshes by recapture, not replay. Remember the
  session-snapshot trap: new tools/fields appear only after an mcp-server rebuild in a fresh session.

---

## 6. Honest limits: Cloudflare, BFF, and browser-driven refresh

Two facts constrain any correct design, both grounded in the corpus:

1. Nebius is a confidential-client BFF: OAuth tokens NEVER reach the browser (0 bodies with
   refresh_token/id_token, 0 grant_type in post_data). There is nothing token-shaped to harvest, so
   the refresh legitimately reduces to recapture of the opaque `__Host-app_session` cookie via
   `RecaptureSessionToken`. The model must allow a session whose refresh flow is recapture-only; it
   does (nullable columns, unchanged recapture path).
2. Cloudflare 403s the framework's datacenter container IPs regardless of a valid session
   (`flowResponseBlocked`, `flowDetectionActive.go:560` already detects this). So ANY headless replay
   of Nebius (creation or refresh) is transport-blocked, even when the credential is perfectly valid
   and the refresh endpoint is correctly detected.

`refresh_transport` represents this honestly, as a CAPABILITY fact, not a permission gate:
- `headless`: the refresh request replays from the container (SPA `grant_type=refresh_token` on a
  non-fronted host).
- `browser_only`: the mechanism is known and documented, but the container cannot execute it. Set when
  `ClassifyFlowRefreshability(refresh_flow)=browser_only`, OR when a headless replay of an in-scope,
  well-formed refresh endpoint returns a bot-management challenge. The `refresh_flow_id` is still
  stored (it documents WHAT the app does); the executable path is just not the container.
- `unknown`: not yet determined.

Three honest fallbacks for `browser_only`, in order of automation:
1. Browser-recapture (shipped): `RecaptureSessionToken` reads the freshest captured `Cookie` header
   and upserts the credential and companions. Nebius's only correct renewal; needs a recent live
   capture but no re-login while the session is alive.
2. Browser-driven refresh (later phase): drive the operator's own browser (the extension auth-recording
   / manual-crawl path) to hit the detected refresh endpoint from the real IP with real Cloudflare
   clearance, then re-capture the rotated cookie. The tier between headless replay and manual
   re-login. Reuses the extension recording path plus `RecaptureSessionToken` for writeback.
3. Manual re-login (creation flow): only when the session has actually lapsed. This is the
   `browser_only` creation flow, i.e. what the operator does by hand today.

Verification consequence: the mint-and-rotate path (sections 2.1, 3.1-3.3, and the auto-refresh
eligibility) MUST be verified end to end against a NON-Cloudflare public-client OAuth app whose token
endpoint returns JSON. Nebius cannot exercise it (no browser token, transport-blocked) and validates
only the detection/degradation shapes: it must tag the auth.nebius.com authorize/callback chain
`creation_exchange`, find no `grant_type` body, and report refresh as recapture-only rather than
inventing a token grant.

Optional upstream capture fix (not core): promote redirect hops in `manual_crawl_captures.redirect_chain`
to carry per-hop response headers (`database.go:1884` defines the column;
`ManualCrawlResultsModal.js:799` renders it) so the session-birth `Set-Cookie` becomes recoverable and
the server session TTL can be read from data. Until then, reading the credential off subsequent request
`Cookie` headers is the path that works, and no part of this design depends on capturing the mint.

---

## 7. Reuse vs new (ledger)

Reused unchanged: `ParseOAuthTokenResponse`/`OAuthTokenResponse`/`jsonSeconds`
(`sessionTokenProfile.go:2011-2090`); `refreshEndpointPatterns` (`:3159`); `reIdPHost`/
`reBrowserChallenge`/`reSingleUse` (`sessionRefreshInteractive.go:264-266`);
`ClassifyFlowRefreshability` (`:286`); the resumable `executeSessionRefreshRun` state machine
(`:716`), `seedJar`, `sendRawRequest`; `runAuthFlowExtractions`/`AuthFlowExtraction`
(`authFlowsVariables.go`); `substituteAuthFlowVars`/`prepareStepRequest` (`:244/383`);
`tokenValueFromBodies`/`collectJSONStrings`/`normalizeTokenKey`/`sessionTokenBodyKeys`
(`sessionTokens.go:1631/1661/1687/1614`); `upsertParsedSessionToken`/`insertSessionToken`
(`:1093/1898`); `refreshCompanionCookies` (`:1416`, as precedent, still running);
`RecaptureSessionToken` (`:951`); `RecordRefreshProof` and the Available-vs-Proven ledger (`:3392`);
`DetectRefreshCapability` (`:3189`); `segmentCaptureFlows`/`captureFlow` (`replayRequestFlows.go:299`);
`loadFlowDetectionBodies`/`NormalizeFlowTuple` (`flowDetectionActive.go:616`);
`CreateAuthFlowFromCaptures` (`main.go:691`); `session_token_events`; the `DO $$` /
drop-and-recreate CHECK migration patterns (`database.go:2875-2877`); the idempotent
`SessionTokenProfileSchema` list (`:3462`); the `detected_flow_names` side-storage pattern
(`detectedFlowNames.go:75`); `classifyCookieRole` and the credential/companion plumbing; the
auto-refresh loop.

Extended: `token_role`/`credential_kind` enums; `findRefreshEndpoint` (per-flow, body-aware);
`extractRefreshedTokenValue` (single -> multi writeback via `writebackRefreshResponse`);
`DeriveSessionTokenExpiry` (+`expires_in` branch); `executeSessionRefreshRun` (+refresh-token seed);
`prepareStepRequest`/`substituteAuthFlowVars` (+`{{token:}}` namespace); `AuthMaterial`/
`normalizeSessionTokenWiring` (skip `refresh` role); `SessionToken`/`sessionTokenPayload`/
`sessionTokenCols`; `FlowSummary` (+`OAuthRole`); `classifyAuthCapture` (+`oauth`/`oauth_refresh`,
body-aware); `RefreshSessionToken`/`startSessionRefreshRun` (refresh-flow-first routing).

New: the `refresh` role + CHECK rewrite; two `credential_kind` strings; five `session_tokens` columns
(`refresh_token_id`, `refresh_flow_id`, `refresh_strategy`, `refresh_transport`,
`refresh_material_key`); `auth_flows.flow_purpose`; `captureOAuthTriad`; `classifyFlowOAuthRole` +
`FlowOAuthClass` + `findRefreshEndpointForFlow`; `writebackRefreshResponse`; the `SessionLifecycle`
read-path struct (`sessionLifecycle.go`); the "build refresh flow" wiring; the UI two-flow card /
detect / adopt actions; the MCP fields and actions; the guidance note. No new tables in the core plan.

---

## 8. Phased build order (concrete first steps)

The shipped Manage/Refresh Sessions Phases 0-5 are the baseline. These OAuth phases are additive.

OAuth Phase 1 (schema + role plumbing, no behavior change to existing refresh). First steps:
1. `sessionTokens.go:51-57`: add `tokenRoleRefresh`, extend `validSessionTokenRoles`.
2. `database.go:2993-2996`: replace the guarded ADD with DROP + ADD for
   `session_tokens_token_role_check` (include `'refresh'`).
3. `sessionTokenProfile.go:3462-3503`: append the five `ADD COLUMN IF NOT EXISTS` statements.
4. `database.go`: add the `auth_flows.flow_purpose` idempotent `ADD COLUMN`.
5. `sessionTokenProfile.go:136-185`: add the two `credential_kind` consts.
6. Wire the five columns into `SessionToken`, `sessionTokenPayload`, `sessionTokenCols`.
7. Teach `AuthMaterial`/`QueryParam`/`ApplyToURL`/`normalizeSessionTokenWiring` and the grading path
   to skip a `refresh` row (keep its `expires_at` check).
   Verify: migrations idempotent; existing rows still validate; a manually-inserted `refresh` row is
   never wired to a request.

OAuth Phase 2 (SPA capture). `captureOAuthTriad` upserts access/refresh/id as linked rows; the
`expires_in` branch in `DeriveSessionTokenExpiry`. Unit test: a `{access_token, refresh_token,
id_token, expires_in}` body produces three linked rows with the right roles, kinds, and expiries, and
the access row's `refresh_token_id` points at the refresh row. This alone makes the currently-transient
refresh token durable. Verifiable on any JSON-token app; on Nebius it is a correct no-op (no refresh
row).

OAuth Phase 3 (SPA headless refresh end to end). The `{{token:...}}` seed in `executeSessionRefreshRun`;
`writebackRefreshResponse` multi-value writeback (rotation fix); `refresh_flow_id`-first routing in
`RefreshSessionToken`. Extend `sessionRefreshInteractive_test.go` / `sessionTokens_test.go`: a refresh
flow with `{{token:refresh_token}}` mints a new access token AND writes back a rotated refresh token;
`TestExtractRefreshedTokenValue` gains an `expires_in` assertion. Verify end to end on a NON-Cloudflare
public-client OAuth target (Nebius cannot exercise this).

OAuth Phase 4 (detection + materialize). Body-aware `findRefreshEndpointForFlow`; `classifyFlowOAuthRole`
+ `FlowSummary.OAuthRole`; the two `classifyAuthCapture` categories; the "build refresh flow from
detected request" wiring via `CreateAuthFlowFromCaptures` (writes `flow_purpose='refresh'`, sets
`refresh_flow_id`, attaches extractions + `{{token:}}`). Verify against the Nebius corpus: tag the
authorize/callback chain `creation_exchange`; with no `grant_type` body, report refresh as
recapture-only (`session_renew` or none), never invent a grant.

OAuth Phase 5 (surface). `SessionLifecycle` read-path struct + `sessionLifecycle.go`; the
ManageSessions two-flow Lifecycle card; the RefreshSession transport branch; the AuthFlow refresh-slot
linking; the detected-flows `OAuthRole` badge + adopt action; the MCP fields and `capture_oauth` /
`build_refresh_flow` / `link_refresh` actions; the guidance note.

OAuth Phase 6 (BFF / Cloudflare fallback + auto-refresh confirm). `refresh_transport` derivation and
`browser_only` routing; browser-driven refresh through the extension + `RecaptureSessionToken`; confirm
a built token-endpoint refresh flow classifies `replay` and becomes `autoRefreshDue`-eligible with the
existing opt-in gate (no new gate). Optional: per-hop response headers in `redirect_chain`.

Phases 1-3 make the SPA/public-client case fully headless. Phase 6 makes the BFF/Nebius case honest
(recapture, browser-driven, or documented-but-blocked) rather than silently failing.

---

## 9. Correctness risks this design closes, and the ones it cannot

Closed: refresh/id token values now persist as durable linked rows (not transient `p.Attributes`);
refresh-token ROTATION no longer breaks the next refresh (multi-value writeback); opaque access tokens
get a real TTL (`expires_in` branch) so the auto-refresh lead window works; the same `/oauth2/token`
URL is no longer conflated across creation and refresh (`grant_type` body inspection); creation and
refresh are distinct on the session (`auth_flow_id` vs `refresh_flow_id`, `flow_purpose`); a refresh
token is never attached to a resource request (role skip); token grouping is explicit
(`refresh_token_id`, the first token->token FK).

Cannot be closed here and stated honestly: for a confidential-client BFF (Nebius) no OAuth token ever
reaches the browser, so refresh legitimately reduces to recapture of the opaque cookie; Cloudflare 403s
the datacenter container IPs, so any headless replay of Nebius is transport-blocked regardless of
correctness. The design is validated on Nebius only for the detection and degradation shapes and must
be validated for the OAuth-refresh-grant path on a non-Cloudflare public-client target. Upstream and
not fixed by the core: the session-minting `Set-Cookie` is folded into `redirect_chain` with no per-hop
headers, so the mint stays invisible; the design reads the credential off subsequent request `Cookie`
headers rather than depending on the mint.
