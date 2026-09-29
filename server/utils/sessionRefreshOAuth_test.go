package utils

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTokenNamespaceSubstitution pins the {{token:NAME}} namespace: it resolves from the reserved
// "token:" vars keys, is a separate namespace from {{af:NAME}} (no collision), and an unseeded token
// placeholder is reported unresolved as {{token:NAME}} (not {{af:...}}).
func TestTokenNamespaceSubstitution(t *testing.T) {
	vars := map[string]string{
		tokenVarKeyPrefix + "refresh_token": "RT-secret",
		"client_id":                         "cid-123",
	}
	raw := "POST /oauth2/token HTTP/1.1\r\nHost: h\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"grant_type=refresh_token&refresh_token={{token:refresh_token}}&client_id={{af:client_id}}"
	out, used, unresolved := substituteAuthFlowVars(raw, vars)
	if len(unresolved) != 0 {
		t.Fatalf("nothing should be unresolved, got %v", unresolved)
	}
	if !strings.Contains(out, "refresh_token=RT-secret") {
		t.Fatalf("{{token:refresh_token}} did not resolve: %s", out)
	}
	if !strings.Contains(out, "client_id=cid-123") {
		t.Fatalf("{{af:client_id}} did not resolve: %s", out)
	}
	if len(used) != 2 {
		t.Fatalf("expected 2 used vars, got %v", used)
	}

	// Collision guard: an {{af:refresh_token}} extraction must NOT pick up the seeded token: value.
	raw2 := "POST /x HTTP/1.1\r\nHost: h\r\n\r\nrt={{af:refresh_token}}"
	_, _, unresolved2 := substituteAuthFlowVars(raw2, vars)
	if len(unresolved2) != 1 || unresolved2[0] != "refresh_token" {
		t.Fatalf("{{af:refresh_token}} must be unresolved (separate namespace), got %v", unresolved2)
	}
	if ph := asPlaceholders([]string{tokenVarKeyPrefix + "refresh_token", "some_af"}); ph[0] != "{{token:refresh_token}}" || ph[1] != "{{af:some_af}}" {
		t.Fatalf("asPlaceholders rendered wrong forms: %v", ph)
	}
}

func TestRefreshFlowIDFor(t *testing.T) {
	if got := refreshFlowIDFor(SessionToken{RefreshFlowID: "R", AuthFlowID: "A"}); got != "R" {
		t.Fatalf("refresh flow must win when set, got %s", got)
	}
	if got := refreshFlowIDFor(SessionToken{AuthFlowID: "A"}); got != "A" {
		t.Fatalf("creation flow is the fallback, got %s", got)
	}
	if got := refreshFlowIDFor(SessionToken{}); got != "" {
		t.Fatalf("neither linked must be empty, got %s", got)
	}
}

// oauthRefreshApp is a mock OAuth token endpoint that honours a refresh_token grant and ROTATES both
// tokens on every call, so the test can prove the runner spends the stored refresh token and stores the
// rotated one.
type oauthRefreshApp struct {
	server       *httptest.Server
	hostPort     string
	calls        int
	sawRefresh   string // the refresh_token value the client actually sent last
	lastAccess   string
	lastRefresh  string
	requireMatch string // if set, only mint when the sent refresh_token equals this
}

func newOAuthRefreshApp(t *testing.T) *oauthRefreshApp {
	t.Helper()
	a := &oauthRefreshApp{}
	a.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth2/token" {
			w.WriteHeader(404)
			return
		}
		body, _ := io.ReadAll(r.Body)
		vals := parseFormBodyForTest(string(body))
		a.sawRefresh = vals["refresh_token"]
		if a.requireMatch != "" && vals["refresh_token"] != a.requireMatch {
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		a.calls++
		a.lastAccess = fmt.Sprintf("access-minted-%d", a.calls)
		a.lastRefresh = fmt.Sprintf("refresh-rotated-%d", a.calls)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"access_token":%q,"refresh_token":%q,"expires_in":3600,"token_type":"Bearer"}`,
			a.lastAccess, a.lastRefresh)))
	}))
	t.Cleanup(a.server.Close)
	a.hostPort = strings.TrimPrefix(a.server.URL, "http://")
	return a
}

func parseFormBodyForTest(body string) map[string]string {
	out := map[string]string{}
	for _, pair := range strings.Split(body, "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			out[kv[0]] = kv[1]
		}
	}
	return out
}

// TestOAuthRefreshGrantEndToEnd is the Phase 3 proof: a refresh flow that POSTs the stored refresh token
// to a token endpoint mints a new access token AND the rotated refresh token is written back, so the
// NEXT refresh would use the rotated one.
func TestOAuthRefreshGrantEndToEnd(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newOAuthRefreshApp(t)
	app.requireMatch = "refresh-orig" // the mint only works if the ORIGINAL stored refresh token is sent
	target := refreshProofTarget(t, ctx, app.server.URL)

	// A refresh flow: one step that spends the stored refresh token at the token endpoint.
	step := "POST /oauth2/token HTTP/1.1\r\nHost: " + app.hostPort + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"grant_type=refresh_token&refresh_token={{token:refresh_token}}"
	var refreshFlowID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO auth_flows (scope_target_id, category, name, base_url, flow_purpose)
		VALUES ($1,'login','oauth refresh',$2,'refresh') RETURNING id::text`,
		target, app.server.URL).Scan(&refreshFlowID); err != nil {
		t.Fatalf("insert refresh flow: %v", err)
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO auth_flow_steps (auth_flow_id, step_order, name, raw_request)
		VALUES ($1,1,'token',$2)`, refreshFlowID, step); err != nil {
		t.Fatalf("insert step: %v", err)
	}

	// The refresh row (spent to mint) and the access row (the anchor) linked to it and to the refresh flow.
	var refreshTokenID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, token_value, is_active, credential_kind)
		VALUES ($1,'OAuth refresh token (captured)','bearer','refresh','refresh-orig',TRUE,'oauth_refresh_token') RETURNING id::text`,
		target).Scan(&refreshTokenID); err != nil {
		t.Fatalf("insert refresh token: %v", err)
	}
	var accessTokenID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, header_name, value_prefix,
		  token_value, is_active, credential_kind, refresh_flow_id, refresh_token_id)
		VALUES ($1,'OAuth access token (captured)','bearer','credential','Authorization','Bearer ',
		  'access-orig',TRUE,'oauth_access_token',$2,$3) RETURNING id::text`,
		target, nullUUID(refreshFlowID), nullUUID(refreshTokenID)).Scan(&accessTokenID); err != nil {
		t.Fatalf("insert access token: %v", err)
	}

	anchor, err := loadSessionToken(accessTokenID)
	if err != nil {
		t.Fatalf("load anchor: %v", err)
	}
	run, err := startSessionRefreshRun(anchor)
	if err != nil {
		t.Fatalf("start refresh: %v", err)
	}
	if run.OutcomeStatus != "refreshed" {
		t.Fatalf("refresh did not succeed: status=%s detail=%s", run.OutcomeStatus, run.OutcomeDetail)
	}
	// The runner spent the ORIGINAL stored refresh token (proves {{token:refresh_token}} seeding).
	if app.sawRefresh != "refresh-orig" {
		t.Fatalf("the token endpoint received %q, not the stored refresh token 'refresh-orig'", app.sawRefresh)
	}
	// The anchor now holds the newly minted access token.
	if v := refreshProofStoredValue(t, ctx, accessTokenID); v != app.lastAccess {
		t.Fatalf("access token not updated: stored %q, minted %q", v, app.lastAccess)
	}
	// ROTATION: the refresh row now holds the rotated refresh token, so the next refresh uses it.
	if v := refreshProofStoredValue(t, ctx, refreshTokenID); v != app.lastRefresh {
		t.Fatalf("rotated refresh token not written back: stored %q, rotated %q", v, app.lastRefresh)
	}

	// A SECOND refresh must now succeed using the rotated token (the mock still requires the value it
	// last handed out), proving the writeback closed the rotation gap.
	app.requireMatch = app.lastRefresh
	anchor2, _ := loadSessionToken(accessTokenID)
	run2, err := startSessionRefreshRun(anchor2)
	if err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	if run2.OutcomeStatus != "refreshed" {
		t.Fatalf("second refresh failed, so rotation writeback did not close the gap: %s", run2.OutcomeDetail)
	}
}

// Regression for the review finding: if the linked refresh row is no longer a refresh row (e.g. an
// operator edited its role), the rotation UPDATE matches 0 rows. pgx returns nil error for a 0-row
// UPDATE, so the code must NOT report rotation success and must NOT silently drop the rotated token.
func TestOAuthRefreshRotationZeroRowsIsNotFalseSuccess(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newOAuthRefreshApp(t)
	app.requireMatch = "refresh-orig"
	target := refreshProofTarget(t, ctx, app.server.URL)

	step := "POST /oauth2/token HTTP/1.1\r\nHost: " + app.hostPort + "\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\n\r\n" +
		"grant_type=refresh_token&refresh_token={{token:refresh_token}}"
	var refreshFlowID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO auth_flows (scope_target_id, category, name, base_url, flow_purpose)
		VALUES ($1,'login','oauth refresh',$2,'refresh') RETURNING id::text`,
		target, app.server.URL).Scan(&refreshFlowID); err != nil {
		t.Fatalf("insert refresh flow: %v", err)
	}
	if _, err := dbPool.Exec(ctx, `INSERT INTO auth_flow_steps (auth_flow_id, step_order, name, raw_request) VALUES ($1,1,'token',$2)`, refreshFlowID, step); err != nil {
		t.Fatalf("insert step: %v", err)
	}
	// The linked row exists and holds the refresh secret, but its role has been changed to credential.
	var refreshTokenID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, token_value, is_active, credential_kind)
		VALUES ($1,'OAuth refresh token (captured)','bearer','credential','refresh-orig',TRUE,'oauth_refresh_token') RETURNING id::text`,
		target).Scan(&refreshTokenID); err != nil {
		t.Fatalf("insert refresh row: %v", err)
	}
	var accessTokenID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, header_name, value_prefix,
		  token_value, is_active, credential_kind, refresh_flow_id, refresh_token_id)
		VALUES ($1,'OAuth access token (captured)','bearer','credential','Authorization','Bearer ',
		  'access-orig',TRUE,'oauth_access_token',$2,$3) RETURNING id::text`,
		target, nullUUID(refreshFlowID), nullUUID(refreshTokenID)).Scan(&accessTokenID); err != nil {
		t.Fatalf("insert access token: %v", err)
	}

	anchor, _ := loadSessionToken(accessTokenID)
	run, err := startSessionRefreshRun(anchor)
	if err != nil {
		t.Fatalf("start refresh: %v", err)
	}
	// The access token was still minted, so the refresh SUCCEEDS...
	if run.OutcomeStatus != "refreshed" {
		t.Fatalf("access mint should still succeed, got %s: %s", run.OutcomeStatus, run.OutcomeDetail)
	}
	if v := refreshProofStoredValue(t, ctx, accessTokenID); v != app.lastAccess {
		t.Fatalf("access not updated: %q", v)
	}
	// ...but rotation did NOT happen (0 rows), so the row keeps the old value and the detail WARNS
	// instead of falsely claiming rotation.
	if v := refreshProofStoredValue(t, ctx, refreshTokenID); v != "refresh-orig" {
		t.Fatalf("the non-refresh row must not have been rotated, got %q", v)
	}
	if !strings.Contains(run.OutcomeDetail, "WARNING") {
		t.Fatalf("a rotation that stored nothing must warn, not claim success: %q", run.OutcomeDetail)
	}
	if strings.Contains(run.OutcomeDetail, "Rotated the stored refresh token.") {
		t.Fatalf("must not claim rotation when 0 rows were updated: %q", run.OutcomeDetail)
	}
}
