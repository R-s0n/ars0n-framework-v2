package utils

import (
	"context"
	"testing"
	"time"
)

// oauthRow reads the fields a captured OAuth row is asserted on.
func oauthRow(t *testing.T, ctx context.Context, id string) (role, kind, refreshID, value string, expires *time.Time) {
	t.Helper()
	if err := dbPool.QueryRow(ctx,
		`SELECT token_role, COALESCE(credential_kind,''), COALESCE(refresh_token_id::text,''), token_value, expires_at
		 FROM session_tokens WHERE id = $1`, id).Scan(&role, &kind, &refreshID, &value, &expires); err != nil {
		t.Fatalf("read oauth row %s: %v", id, err)
	}
	return role, kind, refreshID, value, expires
}

func oauthTokenCount(t *testing.T, ctx context.Context, target string) int {
	t.Helper()
	var n int
	if err := dbPool.QueryRow(ctx, `SELECT count(*) FROM session_tokens WHERE scope_target_id = $1`, target).Scan(&n); err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	return n
}

func oauthCaptureTestSetup(t *testing.T) (context.Context, string) {
	t.Helper()
	ctx := triageTestDB(t)
	// credential_kind is a profile column; captureOAuthTriad keys on it, so ensure it exists.
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		t.Fatalf("profile schema: %v", err)
	}
	return ctx, triageTestTarget(t, ctx)
}

func TestCaptureOAuthTriadStoresAccessAndRefreshLinked(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)

	body := `{"access_token":"opaque-access-xyz","refresh_token":"opaque-refresh-abc","expires_in":3600,"token_type":"Bearer"}`
	res, ok, err := captureOAuthTriad(ctx, target, "app.test", body, time.Now())
	if err != nil || !ok {
		t.Fatalf("captureOAuthTriad ok=%v err=%v", ok, err)
	}
	if res.AccessTokenID == "" || res.RefreshTokenID == "" || !res.HasRefresh {
		t.Fatalf("expected both tokens stored and linked, got %+v", res)
	}
	if n := oauthTokenCount(t, ctx, target); n != 2 {
		t.Fatalf("expected exactly 2 rows (access + refresh), got %d", n)
	}

	// Refresh row: refresh role, refresh kind, no onward link, its value.
	role, kind, refreshID, value, _ := oauthRow(t, ctx, res.RefreshTokenID)
	if role != tokenRoleRefresh || kind != string(CredentialKindOAuthRefresh) || refreshID != "" || value != "opaque-refresh-abc" {
		t.Fatalf("refresh row wrong: role=%s kind=%s link=%q value=%q", role, kind, refreshID, value)
	}

	// Access row: credential role, access kind, LINKED to the refresh row, expiry from expires_in.
	role, kind, refreshID, value, expires := oauthRow(t, ctx, res.AccessTokenID)
	if role != tokenRoleCredential || kind != string(CredentialKindOAuthAccess) || value != "opaque-access-xyz" {
		t.Fatalf("access row wrong: role=%s kind=%s value=%q", role, kind, value)
	}
	if refreshID != res.RefreshTokenID {
		t.Fatalf("access row not linked to refresh row: got %q want %q", refreshID, res.RefreshTokenID)
	}
	if expires == nil {
		t.Fatal("an opaque access token with expires_in:3600 must get a real expiry, got nil")
	}
	if d := time.Until(*expires); d < 55*time.Minute || d > 65*time.Minute {
		t.Fatalf("expiry should be ~1h out (from expires_in:3600), got %s", d)
	}
}

func TestCaptureOAuthTriadRecaptureUpdatesInPlace(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)

	first := `{"access_token":"access-v1","refresh_token":"refresh-v1","expires_in":3600}`
	if _, ok, err := captureOAuthTriad(ctx, target, "app.test", first, time.Now()); err != nil || !ok {
		t.Fatalf("first capture ok=%v err=%v", ok, err)
	}
	// A renewed session: a fresh token response. Must update the same two rows, not add two more.
	second := `{"access_token":"access-v2","refresh_token":"refresh-v2","expires_in":3600}`
	res, ok, err := captureOAuthTriad(ctx, target, "app.test", second, time.Now())
	if err != nil || !ok {
		t.Fatalf("second capture ok=%v err=%v", ok, err)
	}
	if n := oauthTokenCount(t, ctx, target); n != 2 {
		t.Fatalf("re-capture must update in place, expected 2 rows, got %d", n)
	}
	if _, _, _, value, _ := oauthRow(t, ctx, res.AccessTokenID); value != "access-v2" {
		t.Fatalf("access value not refreshed: %q", value)
	}
	if _, _, _, value, _ := oauthRow(t, ctx, res.RefreshTokenID); value != "refresh-v2" {
		t.Fatalf("refresh value not refreshed: %q", value)
	}
}

func TestCaptureOAuthTriadAccessOnly(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)

	body := `{"access_token":"just-an-access-token","token_type":"Bearer"}`
	res, ok, err := captureOAuthTriad(ctx, target, "app.test", body, time.Now())
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if res.HasRefresh || res.RefreshTokenID != "" {
		t.Fatalf("no refresh_token in the body, but one was stored: %+v", res)
	}
	if n := oauthTokenCount(t, ctx, target); n != 1 {
		t.Fatalf("expected exactly 1 row (access only), got %d", n)
	}
	if _, _, refreshID, _, _ := oauthRow(t, ctx, res.AccessTokenID); refreshID != "" {
		t.Fatalf("access row should have no refresh link, got %q", refreshID)
	}
}

func TestCaptureOAuthTriadIgnoresNonTokenBody(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)
	for _, body := range []string{
		`{"message":"hello","status":"ok"}`, // valid JSON, no tokens
		`<html>not json</html>`,             // not JSON
		`{"refresh_token":"only-refresh"}`,  // no access_token to anchor
	} {
		res, ok, err := captureOAuthTriad(ctx, target, "app.test", body, time.Now())
		if err != nil {
			t.Fatalf("body %q errored: %v", body, err)
		}
		if ok || res.AccessTokenID != "" {
			t.Fatalf("body %q was wrongly promoted: ok=%v res=%+v", body, ok, res)
		}
	}
	if n := oauthTokenCount(t, ctx, target); n != 0 {
		t.Fatalf("no rows should have been created, got %d", n)
	}
}

func TestTTLToExpiry(t *testing.T) {
	if ttlToExpiry(time.Now(), 0, false) != nil {
		t.Fatal("no declared TTL must yield nil")
	}
	if ttlToExpiry(time.Now(), 0, true) != nil {
		t.Fatal("a zero TTL must yield nil, not now")
	}
	got := ttlToExpiry(time.Now(), 3600*time.Second, true)
	if got == nil {
		t.Fatal("a known 1h TTL must yield an expiry")
	}
	if d := time.Until(*got); d < 55*time.Minute || d > 65*time.Minute {
		t.Fatalf("expiry should be ~1h out, got %s", d)
	}
}

func TestCaptureOAuthTriadForTargetScansCorpus(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)

	// Create a crawl session and two captures: an older login (access-old + refresh) and a newer
	// refresh-grant response (access-new, no refresh). The stored pair must be the NEWEST access and the
	// refresh from whichever capture carried it.
	var sessionID string
	if err := dbPool.QueryRow(ctx,
		`INSERT INTO manual_crawl_sessions (scope_target_id, target_url, status) VALUES ($1,$2,'completed') RETURNING id::text`,
		target, "https://app.test/").Scan(&sessionID); err != nil {
		t.Fatalf("create crawl session: %v", err)
	}
	insertCap := func(body string, ts time.Time) {
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO manual_crawl_captures (session_id, scope_target_id, url, endpoint, method, response_body, status_code, timestamp)
			VALUES ($1,$2,$3,$4,'POST',$5,200,$6)`,
			sessionID, target, "https://app.test/oauth2/token", "/oauth2/token", body, ts); err != nil {
			t.Fatalf("insert capture: %v", err)
		}
	}
	now := time.Now().UTC()
	insertCap(`{"access_token":"access-old","refresh_token":"refresh-current","expires_in":3600}`, now.Add(-10*time.Minute))
	insertCap(`{"access_token":"access-new","expires_in":3600}`, now.Add(-1*time.Minute))

	res, promoted, err := CaptureOAuthTriadForTarget(ctx, target)
	if err != nil || !promoted {
		t.Fatalf("CaptureOAuthTriadForTarget promoted=%v err=%v", promoted, err)
	}
	if !res.HasRefresh || res.AccessTokenID == "" || res.RefreshTokenID == "" {
		t.Fatalf("expected access + refresh stored and linked, got %+v", res)
	}
	// Newest access wins; the refresh comes from the earlier capture; they are linked.
	if _, _, refreshID, value, _ := oauthRow(t, ctx, res.AccessTokenID); value != "access-new" || refreshID != res.RefreshTokenID {
		t.Fatalf("access row should be the newest value linked to the refresh row: value=%q link=%q", value, refreshID)
	}
	if _, _, _, value, _ := oauthRow(t, ctx, res.RefreshTokenID); value != "refresh-current" {
		t.Fatalf("refresh row should carry the refresh from the login capture, got %q", value)
	}
	if n := oauthTokenCount(t, ctx, target); n != 2 {
		t.Fatalf("expected 2 rows, got %d", n)
	}
}

// Regression for the review finding: the access-row identity must survive the read-path reprofiler
// rewriting credential_kind. Before the fix the upsert keyed on credential_kind='oauth_access_token';
// once the profiler changed it to 'jwt' a re-capture inserted a duplicate access row and orphaned the
// prior (still-sendable) one. Name-based identity must keep it to one access row.
func TestCaptureOAuthTriadSurvivesReprofile(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)

	first := `{"access_token":"access-v1","refresh_token":"refresh-v1","expires_in":3600}`
	if _, ok, err := captureOAuthTriad(ctx, target, "app.test", first, time.Now()); err != nil || !ok {
		t.Fatalf("first capture ok=%v err=%v", ok, err)
	}
	// Simulate the profiler re-measuring the access token from its bytes (a JWT becomes 'jwt', an opaque
	// token 'opaque_bearer'), which is exactly what AttachSessionTokenProfiles does on the read path.
	if _, err := dbPool.Exec(ctx,
		`UPDATE session_tokens SET credential_kind = 'jwt' WHERE scope_target_id = $1 AND token_role = 'credential'`,
		target); err != nil {
		t.Fatalf("simulate reprofile: %v", err)
	}
	// Re-capture a renewed session.
	second := `{"access_token":"access-v2","refresh_token":"refresh-v2","expires_in":3600}`
	if _, ok, err := captureOAuthTriad(ctx, target, "app.test", second, time.Now()); err != nil || !ok {
		t.Fatalf("second capture ok=%v err=%v", ok, err)
	}
	if n := oauthTokenCount(t, ctx, target); n != 2 {
		t.Fatalf("re-capture after a reprofile must still update in place (2 rows), got %d (duplicate/orphan)", n)
	}
	// The single access row carries the fresh value; no stale orphan remains on the wire.
	var value string
	if err := dbPool.QueryRow(ctx,
		`SELECT token_value FROM session_tokens WHERE scope_target_id = $1 AND token_role = 'credential'`,
		target).Scan(&value); err != nil {
		t.Fatalf("expected exactly one credential row: %v", err)
	}
	if value != "access-v2" {
		t.Fatalf("access row not updated in place: %q", value)
	}
}

// Regression for the stale-capture finding: a token captured N hours ago with expires_in=3600 must be
// stored with an expiry ~1h after the CAPTURE time, i.e. already in the past for an old capture, not
// now+1h, so a dead token is never handed to a scan as live.
func TestCaptureOAuthTriadExpiryFromObservedTime(t *testing.T) {
	ctx, target := oauthCaptureTestSetup(t)
	threeHoursAgo := time.Now().UTC().Add(-3 * time.Hour)
	body := `{"access_token":"opaque-stale","expires_in":3600}` // 1h token, seen 3h ago -> dead
	res, ok, err := captureOAuthTriad(ctx, target, "app.test", body, threeHoursAgo)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	_, _, _, _, expires := oauthRow(t, ctx, res.AccessTokenID)
	if expires == nil {
		t.Fatal("expiry should be set from observedAt+expires_in, got nil")
	}
	if !expires.Before(time.Now()) {
		t.Fatalf("a 1h token captured 3h ago must be stored expired, got expiry %s (future)", expires)
	}
}
