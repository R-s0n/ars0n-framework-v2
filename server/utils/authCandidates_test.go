package utils

import "testing"

// The classifier feeds the auth-flow import, so what it misses the operator has to hand-type, and
// what it wrongly includes ends up as a dead step in the middle of a flow.

// The live SMS login's first step was the one request the classifier did not return, which made the
// imported flow start by verifying a code nobody had asked the server to send.
func TestPasswordlessFlowOpenerIsRecognised(t *testing.T) {
	cases := []struct{ url, method, body string }{
		{"https://auth.example.com/cookieless/start", "POST", `{"phone_number":"+15550001111"}`},
		{"https://auth.example.com/v1/otp/initiate", "POST", `{"phone":"+15550001111"}`},
		{"https://auth.example.com/login/begin", "POST", `{"email":"a@b.com"}`},
		{"https://auth.example.com/api/send-code", "POST", `{"msisdn":"+15550001111"}`},
	}
	for _, c := range cases {
		reason, _ := classifyAuthCapture(c.url, c.method, c.body)
		if reason == "" {
			t.Errorf("%s was not recognised as an auth candidate", c.url)
		}
	}
}

// A phone-first or passcode login carries credentials just as plainly as a password one.
func TestPhoneAndPasscodeBodiesCount(t *testing.T) {
	cases := []string{
		`{"phone_number":"+15550001111","otp":"123456"}`,
		`{"passcode":"1108","email":"a@b.com"}`,
		`{"pin":"4821"}`,
		`phone_number=%2B15550001111&otp=123456`,
	}
	for _, body := range cases {
		// A deliberately unremarkable path, so only the body can be doing the work.
		reason, _ := classifyAuthCapture("https://api.example.com/v2/submit", "POST", body)
		if reason == "" {
			t.Errorf("body %q was not recognised as carrying credentials", body)
		}
	}
}

// CORS preflights are not steps. They carry no credentials and replaying one authenticates nobody.
func TestPreflightsAreNotCandidates(t *testing.T) {
	for _, u := range []string{
		"https://auth.example.com/cookieless/verify",
		"https://auth.example.com/login",
		"https://auth.example.com/oauth/token",
	} {
		if reason, _ := classifyAuthCapture(u, "OPTIONS", ""); reason != "" {
			t.Errorf("OPTIONS %s was offered as a candidate (%s)", u, reason)
		}
		// The same path under a real verb still is one.
		if reason, _ := classifyAuthCapture(u, "POST", `{"password":"x"}`); reason == "" {
			t.Errorf("POST %s was not offered as a candidate", u)
		}
	}
}

// The classifier must not start dragging in ordinary application traffic. "start" is a common word,
// so it only counts as a path segment, not as a substring.
func TestOrdinaryTrafficIsStillExcluded(t *testing.T) {
	cases := []struct{ url, method, body string }{
		{"https://api.example.com/v1/products", "GET", ""},
		{"https://api.example.com/v1/orders/8842719", "GET", ""},
		{"https://cdn.example.com/app.bundle.js", "GET", ""},
		{"https://api.example.com/v1/restart-status", "GET", ""},
		{"https://api.example.com/v1/upstart", "GET", ""},
	}
	for _, c := range cases {
		if reason, _ := classifyAuthCapture(c.url, c.method, c.body); reason != "" {
			t.Errorf("%s %s was wrongly classified as auth (%s)", c.method, c.url, reason)
		}
	}
}

// Static assets whose name happens to contain an auth word remain excluded.
func TestStaticAssetsNamedLikeAuthAreExcluded(t *testing.T) {
	for _, u := range []string{
		"https://cdn.example.com/assets/login-hero.png",
		"https://cdn.example.com/js/auth.min.js",
	} {
		if reason, _ := classifyAuthCapture(u, "GET", ""); reason != "" {
			t.Errorf("%s was classified as auth (%s)", u, reason)
		}
	}
}
