package utils

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStepInteractionValidation(t *testing.T) {
	cases := []struct {
		name    string
		si      *StepInteraction
		wantErr bool
	}{
		{"nil is none", nil, false},
		{"empty kind is none", &StepInteraction{}, false},
		{"none is fine", &StepInteraction{Kind: "none"}, false},
		{"valid input", &StepInteraction{Kind: "input", VarName: "mfa_code", InputKind: "otp", Prompt: "Enter the code"}, false},
		{"input needs var_name", &StepInteraction{Kind: "input", Prompt: "Enter the code"}, true},
		{"input needs prompt", &StepInteraction{Kind: "input", VarName: "mfa_code"}, true},
		{"bad var_name", &StepInteraction{Kind: "input", VarName: "mfa code!", Prompt: "x"}, true},
		{"bad input_kind", &StepInteraction{Kind: "input", VarName: "c", InputKind: "nope", Prompt: "x"}, true},
		{"unknown kind", &StepInteraction{Kind: "wat"}, true},
	}
	for _, c := range cases {
		got := validateStepInteraction(c.si)
		if (got != "") != c.wantErr {
			t.Errorf("%s: validate=%q wantErr=%v", c.name, got, c.wantErr)
		}
	}
}

func TestStepInteractionNormalize(t *testing.T) {
	// none -> {}
	if j, problem := normalizeStepInteractionJSON(nil); problem != "" || string(j) != "{}" {
		t.Fatalf("nil should normalise to {} with no problem, got %q / %q", j, problem)
	}
	if j, problem := normalizeStepInteractionJSON(&StepInteraction{Kind: "none"}); problem != "" || string(j) != "{}" {
		t.Fatalf("none should normalise to {}, got %q / %q", j, problem)
	}
	// input with no input_kind defaults to text
	j, problem := normalizeStepInteractionJSON(&StepInteraction{Kind: "input", VarName: "mfa_code", Prompt: "Enter"})
	if problem != "" {
		t.Fatalf("valid input rejected: %q", problem)
	}
	var back StepInteraction
	if err := json.Unmarshal(j, &back); err != nil {
		t.Fatalf("normalised interaction did not round-trip: %v", err)
	}
	if back.Kind != "input" || back.VarName != "mfa_code" || back.InputKind != "text" {
		t.Fatalf("unexpected normalised interaction: %+v", back)
	}
	// a rejected interaction returns a problem and no JSON
	if _, problem := normalizeStepInteractionJSON(&StepInteraction{Kind: "input"}); problem == "" {
		t.Fatalf("an input with no var_name should be rejected")
	}
}

func TestStepInteractionNoneAndNeedsInput(t *testing.T) {
	var nilSI *StepInteraction
	if !nilSI.isNone() || nilSI.needsInput() {
		t.Fatalf("nil interaction should be none and not need input")
	}
	in := &StepInteraction{Kind: "input", VarName: "c", Prompt: "p"}
	if in.isNone() || !in.needsInput() {
		t.Fatalf("input interaction should need input and not be none")
	}
	fut := &StepInteraction{Kind: "browser"}
	if fut.isNone() || fut.needsInput() {
		t.Fatalf("a future kind is neither none nor input")
	}
}

func TestDetectStepInteraction(t *testing.T) {
	// A step that submits an OTP code should be suggested as needing input.
	otpStep := AuthFlowStep{RawRequest: "POST /login/mfa HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\notp=123456&remember=1"}
	if s := DetectStepInteraction(otpStep); s == nil || !s.needsInput() {
		t.Fatalf("a step posting otp= should be suggested as input, got %+v", s)
	}
	// A JSON body with a verification_code field.
	jsonStep := AuthFlowStep{RawRequest: "POST /verify HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/json\r\n\r\n{\"verification_code\":\"\"}"}
	if s := DetectStepInteraction(jsonStep); s == nil {
		t.Fatalf("a step posting a verification_code should be suggested")
	}
	// A plain credential POST should NOT be flagged (username/password is not a one-time code).
	plain := AuthFlowStep{RawRequest: "POST /login HTTP/1.1\r\nHost: app.test\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=carlos&password=hunter2"}
	if s := DetectStepInteraction(plain); s != nil {
		t.Fatalf("a plain credential post should not be flagged, got %+v", s)
	}
}

func TestClassifyCookieRole(t *testing.T) {
	companion := []string{"cf_clearance", "__cf_bm", "__Host-psifi.x-csrf-token", "csrf_token", "XSRF-TOKEN", "AWSALB", "AWSALBCORS", "incap_ses_123_456", "ak_bmsc", "ARRAffinity", "myapp_affinity"}
	for _, n := range companion {
		if classifyCookieRole(n) != tokenRoleCompanion {
			t.Errorf("%q should be classified as companion", n)
		}
	}
	credential := []string{"__Host-app_session", "session", "sid", "JSESSIONID", "access_token", "auth", "connect.sid"}
	for _, n := range credential {
		if classifyCookieRole(n) != "" {
			t.Errorf("%q should stay a credential (got companion)", n)
		}
	}
}

func TestClassifyFlowRefreshability(t *testing.T) {
	// A plain two-step flow is replay.
	plain := []AuthFlowStep{
		{StepOrder: 1, RawRequest: "GET /login HTTP/1.1\r\nHost: app.test\r\n\r\n"},
		{StepOrder: 2, RawRequest: "POST /login HTTP/1.1\r\nHost: app.test\r\n\r\nuser=a&pass=b"},
	}
	if kind, _, _ := ClassifyFlowRefreshability(plain); kind != "replay" {
		t.Fatalf("plain flow should be replay, got %s", kind)
	}
	// An MFA input step makes it interactive.
	mfa := append([]AuthFlowStep{}, plain...)
	mfa = append(mfa, AuthFlowStep{StepOrder: 3, RawRequest: "POST /mfa HTTP/1.1\r\nHost: app.test\r\n\r\notp=x", Interaction: &StepInteraction{Kind: "input", VarName: "mfa_code", Prompt: "code"}})
	if kind, _, _ := ClassifyFlowRefreshability(mfa); kind != "interactive" {
		t.Fatalf("mfa flow should be interactive, got %s", kind)
	}
	// A federated IdP host or a single-use code makes it browser_only.
	oauth := []AuthFlowStep{
		{StepOrder: 1, RawRequest: "GET /oauth2/authorize?client_id=x&response_type=code HTTP/1.1\r\nHost: auth.app.test\r\n\r\n"},
		{StepOrder: 2, RawRequest: "GET /login/oauth2/code/google?code=SINGLE_USE_CODE&state=abcdefghij HTTP/1.1\r\nHost: accounts.google.com\r\n\r\n"},
	}
	if kind, _, reasons := ClassifyFlowRefreshability(oauth); kind != "browser_only" || len(reasons) == 0 {
		t.Fatalf("oauth/federated flow should be browser_only with reasons, got %s / %v", kind, reasons)
	}
	// A non-runnable interaction kind ("browser") makes the flow browser_only even when nothing in the
	// request/response content trips the challenge/IdP/single-use regexes. Without this the unattended
	// auto-refresh loop would classify such a flow as "replay" and send its earlier credential-bearing
	// steps to the live target before the runner refuses the hand-off step.
	handoff := append([]AuthFlowStep{}, plain...)
	handoff = append(handoff, AuthFlowStep{StepOrder: 3, RawRequest: "GET /verify-device HTTP/1.1\r\nHost: app.test\r\n\r\n", Interaction: &StepInteraction{Kind: "browser"}})
	if kind, _, reasons := ClassifyFlowRefreshability(handoff); kind != "browser_only" || len(reasons) == 0 {
		t.Fatalf("a browser hand-off step should make the flow browser_only, got %s / %v", kind, reasons)
	}
}

func TestHOTPRFC4226Vectors(t *testing.T) {
	// RFC 4226 Appendix D: secret "12345678901234567890", counters 0..3.
	key := []byte("12345678901234567890")
	want := []string{"755224", "287082", "359152", "969429"}
	for i, w := range want {
		if got := hotp(key, uint64(i)); got != w {
			t.Errorf("hotp counter %d: got %s want %s", i, got, w)
		}
	}
}

func TestGenerateTOTPAndClean(t *testing.T) {
	// base32("12345678901234567890") = GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code, err := generateTOTP(secret)
	if err != nil || len(code) != 6 {
		t.Fatalf("expected a 6-digit code, got %q err %v", code, err)
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			t.Fatalf("TOTP code is not numeric: %q", code)
		}
	}
	// Lower-case, spaces and padding are tolerated (same decoded key -> same code).
	messy := "gezd gnbv gy3t qojq gezd gnbv gy3t qojq="
	code2, err := generateTOTP(messy)
	if err != nil || code2 != code {
		t.Fatalf("normalised secret should give the same code: %q vs %q (err %v)", code2, code, err)
	}
	if _, err := generateTOTP("not!base32!"); err == nil {
		t.Fatalf("an invalid base32 secret should error")
	}
}

func TestRefreshStepPause(t *testing.T) {
	none := AuthFlowStep{ID: "s0", StepOrder: 1}
	if refreshStepPause(none, map[string]string{}, map[string]string{}) != nil {
		t.Fatalf("a step with no interaction should not pause")
	}
	// input: pauses when the value is missing, not when present.
	inp := AuthFlowStep{ID: "s1", StepOrder: 2, Interaction: &StepInteraction{Kind: "input", VarName: "mfa_code", InputKind: "otp", Prompt: "code"}}
	if p := refreshStepPause(inp, map[string]string{}, map[string]string{}); p == nil || p.VarName != "mfa_code" || p.NoValue {
		t.Fatalf("input step should pause for mfa_code with a value, got %+v", p)
	}
	if refreshStepPause(inp, map[string]string{"mfa_code": "123"}, map[string]string{}) != nil {
		t.Fatalf("input step should not pause once the value is present")
	}
	// action approve: a no-value pause, resolved by a continue recorded under __continue:<id>.
	appr := AuthFlowStep{ID: "s2", StepOrder: 3, Interaction: &StepInteraction{Kind: "action", ActionKind: "approve", Prompt: "approve"}}
	p := refreshStepPause(appr, map[string]string{}, map[string]string{})
	if p == nil || !p.NoValue || p.ActionKind != "approve" || p.VarName != "__continue:s2" {
		t.Fatalf("approve should pause with no_value and a continue key, got %+v", p)
	}
	if refreshStepPause(appr, map[string]string{}, map[string]string{"__continue:s2": "1"}) != nil {
		t.Fatalf("approve should not pause once continued")
	}
	// action magic_link: pauses for a URL value.
	ml := AuthFlowStep{ID: "s3", StepOrder: 4, Interaction: &StepInteraction{Kind: "action", ActionKind: "magic_link", VarName: "link_url", Prompt: "click"}}
	if p := refreshStepPause(ml, map[string]string{}, map[string]string{}); p == nil || p.InputKind != "url" || p.NoValue {
		t.Fatalf("magic_link should pause for a url value, got %+v", p)
	}
}

func TestExtractRefreshedTokenValue(t *testing.T) {
	// A cookie credential is taken from Set-Cookie, last value wins.
	cookieTok := SessionToken{TokenType: tokenTypeCookie, CookieName: "sess"}
	val, _, src := extractRefreshedTokenValue(cookieTok, []string{"sess=OLD; Path=/", "sess=NEW; Path=/; HttpOnly"}, nil)
	if val != "NEW" || src == "" {
		t.Fatalf("expected the last Set-Cookie value NEW, got %q from %q", val, src)
	}
	// Nothing issued -> empty.
	if val, _, _ := extractRefreshedTokenValue(cookieTok, []string{"other=x"}, nil); val != "" {
		t.Fatalf("a cookie not present in Set-Cookie should return empty, got %q", val)
	}
	// A bearer/header token is taken from a response body.
	bearer := SessionToken{TokenType: tokenTypeBearer, Name: "access_token"}
	val, _, src = extractRefreshedTokenValue(bearer, nil, []string{`{"access_token":"abc.def.ghi","expires_in":3600}`})
	if val != "abc.def.ghi" || src == "" {
		t.Fatalf("expected the body access_token, got %q from %q", val, src)
	}
}

func TestAutoRefreshDue(t *testing.T) {
	now := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	soon := now.Add(2 * time.Minute)  // inside the 5-minute lead window
	later := now.Add(2 * time.Hour)   // well outside it
	refreshed := now.Add(-time.Hour)  // a prior successful hand refresh

	// The fully eligible baseline: opted in, active, linked flow, proven refresh, replay flow, near expiry.
	base := SessionToken{
		AutoRefresh: true, IsActive: true, AuthFlowID: "flow-1",
		LastRefreshedAt: &refreshed, ExpiresAt: &soon,
	}

	cases := []struct {
		name    string
		mut     func(*SessionToken)
		flow    string
		wantDue bool
	}{
		{"eligible near expiry", nil, flowRefreshReplay, true},
		{"auto_refresh off", func(t *SessionToken) { t.AutoRefresh = false }, flowRefreshReplay, false},
		{"inactive", func(t *SessionToken) { t.IsActive = false }, flowRefreshReplay, false},
		{"no linked flow", func(t *SessionToken) { t.AuthFlowID = "" }, flowRefreshReplay, false},
		{"never refreshed by hand", func(t *SessionToken) { t.LastRefreshedAt = nil }, flowRefreshReplay, false},
		{"interactive flow excluded", nil, flowRefreshInteractive, false},
		{"browser-only flow excluded", nil, flowRefreshBrowserOnly, false},
		{"not near expiry, no rejection", func(t *SessionToken) { t.ExpiresAt = &later }, flowRefreshReplay, false},
		{"far expiry but rejected verdict", func(t *SessionToken) {
			t.ExpiresAt = &later
			t.LastValidationStatus = "expired"
		}, flowRefreshReplay, true},
		{"no expiry, rejected verdict", func(t *SessionToken) {
			t.ExpiresAt = nil
			t.LastValidationStatus = "unauthorized"
		}, flowRefreshReplay, true},
		{"no expiry, no verdict", func(t *SessionToken) { t.ExpiresAt = nil }, flowRefreshReplay, false},
		{"already lapsed", func(t *SessionToken) { t.ExpiresAt = &past }, flowRefreshReplay, true},
	}
	for _, c := range cases {
		tok := base
		if c.mut != nil {
			c.mut(&tok)
		}
		got, reason := autoRefreshDue(tok, c.flow, now)
		if got != c.wantDue {
			t.Errorf("%s: due=%v want=%v (reason %q)", c.name, got, c.wantDue, reason)
		}
	}
}
