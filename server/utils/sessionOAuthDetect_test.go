package utils

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestExtractGrantType(t *testing.T) {
	cases := map[string]string{
		"grant_type=refresh_token&refresh_token=abc":       "refresh_token",
		"grant_type=authorization_code&code=xyz":           "authorization_code",
		`{"grant_type":"refresh_token","refresh_token":"a"}`: "refresh_token",
		`{"grant_type":"authorization_code"}`:              "authorization_code",
		"client_id=x&scope=openid":                         "", // no grant_type
		"":                                                 "",
		"not a body at all":                                "",
	}
	for body, want := range cases {
		if got := extractGrantType(body); got != want {
			t.Errorf("extractGrantType(%q) = %q, want %q", body, got, want)
		}
	}
}

func TestOAuthCaptureRole(t *testing.T) {
	cases := []struct {
		url, method, body, want string
	}{
		{"https://app.test/oauth2/token", "POST", "grant_type=refresh_token&refresh_token=x", oauthRoleRefresh},
		{"https://app.test/oauth2/token", "POST", "grant_type=authorization_code&code=abcdef", oauthRoleCreation},
		{"https://app.test/oauth2/authorize?response_type=code", "GET", "", oauthRoleCreation},
		{"https://app.test/auth/callback?code=SINGLE_USE_CODE_123&state=abcdefghij", "GET", "", oauthRoleCreation},
		{"https://accounts.google.com/o/oauth2/v2/auth", "GET", "", oauthRoleCreation},
		{"https://app.test/session/renew", "POST", "", oauthRoleRefresh},
		{"https://app.test/auth/refresh", "POST", "", oauthRoleRefresh},
		{"https://app.test/api/widgets", "GET", "", ""}, // not OAuth
		{"https://app.test/oauth2/token", "POST", "", ""}, // /token with no grant_type is ambiguous -> unknown
	}
	for _, c := range cases {
		if got := oauthCaptureRole(c.url, c.method, c.body); got != c.want {
			t.Errorf("oauthCaptureRole(%q,%q,%q) = %q, want %q", c.url, c.method, c.body, got, c.want)
		}
	}
}

func TestSeedRefreshTokenPlaceholder(t *testing.T) {
	form, ok := seedRefreshTokenPlaceholder("grant_type=refresh_token&refresh_token=SECRET123&client_id=cid")
	if !ok || form != "grant_type=refresh_token&refresh_token={{token:refresh_token}}&client_id=cid" {
		t.Fatalf("form seed wrong: %q ok=%v", form, ok)
	}
	js, ok := seedRefreshTokenPlaceholder(`{"grant_type":"refresh_token","refresh_token":"SECRET123"}`)
	if !ok || js != `{"grant_type":"refresh_token","refresh_token":"{{token:refresh_token}}"}` {
		t.Fatalf("json seed wrong: %q ok=%v", js, ok)
	}
	if _, ok := seedRefreshTokenPlaceholder("grant_type=client_credentials&client_id=x"); ok {
		t.Fatal("a body with no refresh_token must report ok=false")
	}
	// Idempotent: an already-seeded body stays seeded.
	if out, ok := seedRefreshTokenPlaceholder("refresh_token={{token:refresh_token}}"); !ok || out != "refresh_token={{token:refresh_token}}" {
		t.Fatalf("already-seeded body changed: %q ok=%v", out, ok)
	}
}

// TestAdoptRefreshFlowThenRefresh is the Phase 4 end-to-end: adopt a captured refresh request as a refresh
// flow, then run a refresh through it (Phase 3) and confirm it spends the stored refresh token, mints the
// new access token, and rotates the refresh token. Ties detection/adopt (Phase 4) to execution (Phase 3).
func TestAdoptRefreshFlowThenRefresh(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newOAuthRefreshApp(t)
	app.requireMatch = "refresh-orig"
	target := refreshProofTarget(t, ctx, app.server.URL)

	// A captured refresh request at the mock's token endpoint, with the original refresh token in the body.
	var sessionID string
	if err := dbPool.QueryRow(ctx,
		`INSERT INTO manual_crawl_sessions (scope_target_id, target_url, status) VALUES ($1,$2,'completed') RETURNING id::text`,
		target, app.server.URL).Scan(&sessionID); err != nil {
		t.Fatalf("create session: %v", err)
	}
	var captureID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO manual_crawl_captures (session_id, scope_target_id, url, endpoint, method, headers, post_data, response_body, status_code, timestamp)
		VALUES ($1,$2,$3,$4,'POST',$5,$6,$7,200,NOW()) RETURNING id::text`,
		sessionID, target, app.server.URL+"/oauth2/token", "/oauth2/token",
		[]byte(`{"Content-Type":"application/x-www-form-urlencoded"}`),
		"grant_type=refresh_token&refresh_token=refresh-orig",
		`{"access_token":"access-old","refresh_token":"refresh-old","expires_in":3600}`).Scan(&captureID); err != nil {
		t.Fatalf("insert capture: %v", err)
	}

	// The refresh row (spent to mint) and the anchor access token linked to it. No refresh_flow_id yet.
	var refreshTokenID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, token_value, is_active, credential_kind)
		VALUES ($1,'OAuth refresh token (captured)','bearer','refresh','refresh-orig',TRUE,'oauth_refresh_token') RETURNING id::text`,
		target).Scan(&refreshTokenID); err != nil {
		t.Fatalf("insert refresh row: %v", err)
	}
	var anchorID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, header_name, value_prefix,
		  token_value, is_active, credential_kind, refresh_token_id)
		VALUES ($1,'OAuth access token (captured)','bearer','credential','Authorization','Bearer ',
		  'access-orig',TRUE,'oauth_access_token',$2) RETURNING id::text`,
		target, nullUUID(refreshTokenID)).Scan(&anchorID); err != nil {
		t.Fatalf("insert anchor: %v", err)
	}

	// Adopt: call the handler.
	body, _ := json.Marshal(map[string]interface{}{
		"name": "adopted refresh", "capture_ids": []string{captureID}, "anchor_token_id": anchorID,
	})
	req := httptest.NewRequest("POST", "/auth-flows/"+target+"/refresh-from-captures", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"scope_target_id": target})
	rec := httptest.NewRecorder()
	BuildRefreshFlowFromCaptures(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("adopt failed: %d %s", rec.Code, rec.Body.String())
	}
	var adopt struct {
		ID           string `json:"id"`
		FlowPurpose  string `json:"flow_purpose"`
		LinkedAnchor bool   `json:"linked_anchor"`
	}
	json.Unmarshal(rec.Body.Bytes(), &adopt)
	if adopt.ID == "" || adopt.FlowPurpose != "refresh" || !adopt.LinkedAnchor {
		t.Fatalf("adopt result wrong: %+v", adopt)
	}

	// The step body was templatized, and the anchor is linked to the refresh flow.
	var stepBody, linkedFlow string
	if err := dbPool.QueryRow(ctx, `SELECT raw_request FROM auth_flow_steps WHERE auth_flow_id=$1 ORDER BY step_order LIMIT 1`, adopt.ID).Scan(&stepBody); err != nil {
		t.Fatalf("read step: %v", err)
	}
	if !bytes.Contains([]byte(stepBody), []byte("{{token:refresh_token}}")) {
		t.Fatalf("step body was not templatized: %s", stepBody)
	}
	if err := dbPool.QueryRow(ctx, `SELECT COALESCE(refresh_flow_id::text,'') FROM session_tokens WHERE id=$1`, anchorID).Scan(&linkedFlow); err != nil {
		t.Fatalf("read anchor link: %v", err)
	}
	if linkedFlow != adopt.ID {
		t.Fatalf("anchor not linked to the adopted flow: %q vs %q", linkedFlow, adopt.ID)
	}

	// Now run a refresh THROUGH the adopted flow (Phase 3) and confirm it works end to end.
	anchor, _ := loadSessionToken(anchorID)
	run, err := startSessionRefreshRun(anchor)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if run.OutcomeStatus != "refreshed" {
		t.Fatalf("adopted flow did not refresh: %s / %s", run.OutcomeStatus, run.OutcomeDetail)
	}
	if app.sawRefresh != "refresh-orig" {
		t.Fatalf("the adopted flow did not spend the stored refresh token; endpoint saw %q", app.sawRefresh)
	}
	if v := refreshProofStoredValue(t, ctx, anchorID); v != app.lastAccess {
		t.Fatalf("access not minted: %q", v)
	}
	if v := refreshProofStoredValue(t, ctx, refreshTokenID); v != app.lastRefresh {
		t.Fatalf("refresh not rotated: %q", v)
	}
}

// Regression for the review findings.
func TestSeedRefreshTokenPlaceholderDoesNotOverMatch(t *testing.T) {
	// A distinct field whose name ENDS in refresh_token must NOT be templatized; only the real one.
	got, ok := seedRefreshTokenPlaceholder("x_refresh_token=A&grant_type=refresh_token&refresh_token=B")
	if !ok {
		t.Fatal("the real refresh_token should still seed")
	}
	if got != "x_refresh_token=A&grant_type=refresh_token&refresh_token={{token:refresh_token}}" {
		t.Fatalf("over-matched a longer field name: %q", got)
	}
	// A body with ONLY a longer field (no bare refresh_token) must report ok=false, so the adopt gate
	// (>=1 seeded, else 400) correctly rejects it.
	if out, ok := seedRefreshTokenPlaceholder("device_refresh_token=abc123&foo=bar"); ok {
		t.Fatalf("a body without a real refresh_token field must not seed, got %q", out)
	}
	// A refresh_token at the very start of the body still seeds.
	if out, ok := seedRefreshTokenPlaceholder("refresh_token=X&grant_type=refresh_token"); !ok || out != "refresh_token={{token:refresh_token}}&grant_type=refresh_token" {
		t.Fatalf("start-of-body refresh_token not seeded: %q ok=%v", out, ok)
	}
}

func TestExtractGrantTypeJSONWithEmbeddedAmpersand(t *testing.T) {
	// A JSON body whose string value contains &grant_type=... must not be misread by a form parse.
	body := `{"grant_type":"authorization_code","redirect_uri":"https://a.com/cb?a=1&grant_type=refresh_token"}`
	if got := extractGrantType(body); got != "authorization_code" {
		t.Fatalf("JSON body misparsed as form: got %q, want authorization_code", got)
	}
	// A valid JSON object with no top-level grant_type returns "", not a form-parsed value.
	if got := extractGrantType(`{"foo":"a&grant_type=refresh_token"}`); got != "" {
		t.Fatalf("expected empty for JSON without top-level grant_type, got %q", got)
	}
}

// Phase 6: the adopt path derives refresh_transport from the built flow and stores it on the anchor.
func TestAdoptSetsRefreshTransportHeadless(t *testing.T) {
	ctx := triageTestDB(t)
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("schema: %v", err)
	}
	app := newOAuthRefreshApp(t)
	target := refreshProofTarget(t, ctx, app.server.URL)

	var sessionID string
	dbPool.QueryRow(ctx, `INSERT INTO manual_crawl_sessions (scope_target_id, target_url, status) VALUES ($1,$2,'completed') RETURNING id::text`, target, app.server.URL).Scan(&sessionID)
	var captureID string
	if err := dbPool.QueryRow(ctx, `
		INSERT INTO manual_crawl_captures (session_id, scope_target_id, url, endpoint, method, headers, post_data, response_body, status_code, timestamp)
		VALUES ($1,$2,$3,$4,'POST',$5,$6,$7,200,NOW()) RETURNING id::text`,
		sessionID, target, app.server.URL+"/oauth2/token", "/oauth2/token",
		[]byte(`{"Content-Type":"application/x-www-form-urlencoded"}`),
		"grant_type=refresh_token&refresh_token=refresh-orig",
		`{"access_token":"a","refresh_token":"r","expires_in":3600}`).Scan(&captureID); err != nil {
		t.Fatalf("insert capture: %v", err)
	}
	var refreshTokenID, anchorID string
	dbPool.QueryRow(ctx, `INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, token_value, is_active) VALUES ($1,'r','bearer','refresh','refresh-orig',TRUE) RETURNING id::text`, target).Scan(&refreshTokenID)
	dbPool.QueryRow(ctx, `INSERT INTO session_tokens (scope_target_id, name, token_type, token_role, token_value, is_active, refresh_token_id) VALUES ($1,'a','bearer','credential','access-orig',TRUE,$2) RETURNING id::text`, target, nullUUID(refreshTokenID)).Scan(&anchorID)

	body, _ := json.Marshal(map[string]interface{}{"capture_ids": []string{captureID}, "anchor_token_id": anchorID})
	req := httptest.NewRequest("POST", "/x", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"scope_target_id": target})
	rec := httptest.NewRecorder()
	BuildRefreshFlowFromCaptures(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("adopt failed: %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ RefreshTransport string `json:"refresh_transport"` }
	json.Unmarshal(rec.Body.Bytes(), &out)
	if out.RefreshTransport != "headless" {
		t.Fatalf("a pure /oauth2/token refresh flow should be headless, got %q", out.RefreshTransport)
	}
	var stored string
	dbPool.QueryRow(ctx, `SELECT COALESCE(refresh_transport,'') FROM session_tokens WHERE id=$1`, anchorID).Scan(&stored)
	if stored != "headless" {
		t.Fatalf("refresh_transport not stored on anchor: %q", stored)
	}
}
