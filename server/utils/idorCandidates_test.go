package utils

import (
	"strings"
	"testing"
)

func TestIDORCookieTrackingBlacklist(t *testing.T) {
	blocked := []string{
		"AMP_MKTG_d6814239bf", "AMP_d6814239bf", "__stripe_mid", "__stripe_sid",
		"_rdt_uuid", "_rdt_em", "_gcl_au",
		"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser",
		"intercom-session-p7a9jdob", "intercom-device-id-p7a9jdob",
		"onfido-token", "gdpr_consent",
	}
	for _, n := range blocked {
		if !idorCookieTrackingBlacklist(n) {
			t.Errorf("expected %q to be blacklisted", n)
		}
	}
	for _, n := range []string{"account_id", "owner_id", "id", "suffix", "name", ""} {
		if idorCookieTrackingBlacklist(n) {
			t.Errorf("did not expect %q to be blacklisted", n)
		}
	}
}

func TestIDORIsIDLikeParam(t *testing.T) {
	cases := []struct {
		name, value string
		want        bool
	}{
		{"account_id", "edd0edb9-7562-4c9f-a5cb-5c70d5996c08", true}, // uuid value
		{"someref", "edd0edb9-7562-4c9f-a5cb-5c70d5996c08", true},    // uuid value, any name
		{"id", "660352", true},                                          // numeric + id-ish name
		{"annual_income_max", "50000", false},                           // numeric but a form field
		{"__stripe_mid", "edd0edb9-7562-4c9f-a5cb-5c70d5996c08", false}, // blacklisted name beats value
		{"name", "watchlist one", false},                                // ordinary data
	}
	for _, c := range cases {
		if got := idorIsIDLikeParam(c.name, c.value); got != c.want {
			t.Errorf("idorIsIDLikeParam(%q,%q)=%v want %v", c.name, c.value, got, c.want)
		}
	}
}

func TestIDGuessTier(t *testing.T) {
	cases := []struct {
		value, want string
	}{
		{"4f37f03e-0f5e-4383-a581-c71445aae9e1", idGuessUUIDv4}, // path ids on the Alpaca estate
		{"f47ac10b-58cc-11e4-8b00-0800200c9a66", idGuessUUIDv1}, // v1 is enumerable
		{"660352", idGuessSequential},                           // sequential internal id
		{"507f1f77bcf86cd799439011", idGuessObjectID},           // 24-hex mongo object id
		{"", idGuessUnknown},
	}
	for _, c := range cases {
		if got := idGuessTier(c.value); got != c.want {
			t.Errorf("idGuessTier(%q)=%q want %q", c.value, got, c.want)
		}
	}
}

func TestIDORCandidateGate(t *testing.T) {
	// id-bearing path, owner field, auth, a 200: admitted.
	if !idorCandidateGate(true, true, false, true, true) {
		t.Error("owner+auth+200 should pass")
	}
	// PII only (no owner) still passes the gate: it is a surface admitter.
	if !idorCandidateGate(true, false, true, true, true) {
		t.Error("pii+auth+200 should pass")
	}
	// Missing auth, missing owner/pii, missing 200, and not id-bearing each fail.
	if idorCandidateGate(true, true, true, false, true) {
		t.Error("no auth must fail")
	}
	if idorCandidateGate(true, false, false, true, true) {
		t.Error("no owner and no pii must fail")
	}
	if idorCandidateGate(true, true, true, true, false) {
		t.Error("no observed 200 must fail")
	}
	if idorCandidateGate(false, true, true, true, true) {
		t.Error("not id-bearing must fail")
	}
}

func TestScoreIDORCandidateOwnerAndEnumerable(t *testing.T) {
	c := IDORCandidate{
		HasOwnerField: true, GuessTier: idGuessSequential, KnownIDValue: "660352",
		IdentityPatternID: "p1", AuthClientSent: true,
	}
	score, reasons := scoreIDORCandidate(c)
	// owner(3) + enumerable(3) + known value(1) + pattern(2) = 9.
	if score != 9 {
		t.Errorf("score=%d want 9", score)
	}
	if !reasonsContain(reasons, "concrete id to swap") {
		t.Error("owner reason missing")
	}
}

func TestScoreIDORCandidateUUIDv4NeedsLeakThenLeaked(t *testing.T) {
	base := IDORCandidate{HasOwnerField: true, GuessTier: idGuessUUIDv4, AuthClientSent: true}
	noLeak, noLeakReasons := scoreIDORCandidate(base)

	leaked := base
	leaked.IDLeaked = true
	leaked.IDLeakSource = "/api/v1/accounts"
	leakedScore, leakedReasons := scoreIDORCandidate(leaked)

	// uuid_v4 itself scores nothing; the leak adds its own points and offsets the needs-leak note.
	if leakedScore != noLeak+2 {
		t.Errorf("leaked score %d should be needs-leak score %d plus 2", leakedScore, noLeak)
	}
	if !reasonsContain(noLeakReasons, "needs a leaked id") {
		t.Error("a non-leaked uuid_v4 must say it needs a leaked id")
	}
	if reasonsContain(leakedReasons, "needs a leaked id") {
		t.Error("a leaked uuid_v4 must not say it needs a leaked id")
	}
	if !reasonsContain(leakedReasons, "id-acquisition primitive") {
		t.Error("a leaked candidate must name the id-acquisition primitive")
	}
}

func TestScorePIISchemaNeverInflates(t *testing.T) {
	without := IDORCandidate{HasOwnerField: true, GuessTier: idGuessUUIDv4, AuthClientSent: true}
	with := without
	with.HasPII = true
	s0, _ := scoreIDORCandidate(without)
	s1, reasons := scoreIDORCandidate(with)
	if s0 != s1 {
		t.Errorf("a PII schema must not change the score: %d vs %d", s0, s1)
	}
	if !reasonsContain(reasons, "surface signal only, not scored") {
		t.Error("the PII reason must say it is a surface signal only")
	}
}

func TestScoreAuthIsClientSentNotEnforced(t *testing.T) {
	_, reasons := scoreIDORCandidate(IDORCandidate{
		HasOwnerField: true, GuessTier: idGuessUUIDv4, AuthClientSent: true,
	})
	if !reasonsContain(reasons, idorAuthCaveat) {
		t.Error("auth reason must use the client-sent caveat")
	}
	for _, r := range reasons {
		if strings.Contains(strings.ToLower(r), "enforced") && !strings.Contains(r, idorAuthCaveat) {
			t.Errorf("no reason may claim auth is enforced: %q", r)
		}
		if strings.Contains(strings.ToLower(r), "owned by") {
			t.Errorf("no reason may assert ownership: %q", r)
		}
	}
}

func reasonsContain(reasons []string, substr string) bool {
	for _, r := range reasons {
		if strings.Contains(r, substr) {
			return true
		}
	}
	return false
}
