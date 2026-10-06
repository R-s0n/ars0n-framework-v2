package utils

import "testing"

// SuffixesByEffect is what derives the keeper's egress allowlist, so it has to split the in-scope
// (header-bearing) side from the auth-only side correctly and never let a deny leak into either.
func TestSuffixesByEffectSplitsInScopeFromAuth(t *testing.T) {
	s := &ScanScope{
		primary:   "app.example.com",
		domains:   map[string]bool{"example.com": true},
		extra:     map[string]bool{"api.example.net": true},
		authHosts: map[string]bool{"cognito-idp.us-east-1.amazonaws.com": true},
		refused:   map[string]int{},
		rules: []ScopeRule{
			{Effect: EffectAuth, Kind: KindSubdomains, Value: "okta.com", Enabled: true},
			{Effect: EffectAllow, Kind: KindSubtree, Value: "partner.example.org", Enabled: true},
			{Effect: EffectDeny, Kind: KindSubtree, Value: "cdn.example.com", Enabled: true},
			{Effect: EffectAuth, Kind: KindContains, Value: "amazoncognito", Enabled: true}, // wide, omitted
			{Effect: EffectAllow, Kind: KindSubtree, Value: "disabled.example.com", Enabled: false},
		},
	}
	allow, auth := s.SuffixesByEffect()

	has := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}

	for _, want := range []string{"app.example.com", "example.com", "api.example.net", "partner.example.org"} {
		if !has(allow, want) {
			t.Errorf("allow side missing %q: %v", want, allow)
		}
	}
	for _, want := range []string{"okta.com", "cognito-idp.us-east-1.amazonaws.com"} {
		if !has(auth, want) {
			t.Errorf("auth side missing %q: %v", want, auth)
		}
	}
	// A deny value must never appear on either side.
	if has(allow, "cdn.example.com") || has(auth, "cdn.example.com") {
		t.Error("a deny rule value leaked into the egress allowlist")
	}
	// A wide contains rule cannot be flattened to a suffix and must be omitted.
	if has(auth, "amazoncognito") {
		t.Error("a wide contains rule leaked into the allowlist as a bogus suffix")
	}
	// A disabled rule contributes nothing.
	if has(allow, "disabled.example.com") {
		t.Error("a disabled rule leaked into the allowlist")
	}
	// An auth-only host must not appear on the in-scope (header-bearing) side.
	if has(allow, "okta.com") || has(allow, "cognito-idp.us-east-1.amazonaws.com") {
		t.Error("an auth-only host appeared on the in-scope side; it would wrongly get the attribution header")
	}
}

// keeperGeneration must be stable for the same seed and change when the cookie seed changes, so the
// keeper re-seeds its profile exactly when it should and not on every reconcile tick.
func TestKeeperGenerationChangesWithSeed(t *testing.T) {
	base := keeperDesired{
		TargetURL: "https://app.example.com",
		Allowlist: []string{"app.example.com", "cognito-idp.us-east-1.amazonaws.com"},
		Cookies:   []keeperCookie{{Name: "sid", Value: "v1", Domain: "example.com"}},
	}
	g1 := keeperGeneration(base)
	g2 := keeperGeneration(base)
	if g1 != g2 || g1 == "" {
		t.Fatalf("generation must be stable and non-empty: %q %q", g1, g2)
	}

	rotated := base
	rotated.Cookies = []keeperCookie{{Name: "sid", Value: "v2-rotated", Domain: "example.com"}}
	if keeperGeneration(rotated) == g1 {
		t.Error("a rotated cookie value must change the generation so the keeper re-seeds")
	}

	movedURL := base
	movedURL.TargetURL = "https://other.example.com"
	if keeperGeneration(movedURL) == g1 {
		t.Error("a changed target_url must change the generation")
	}
}

func TestKeeperStatusValidation(t *testing.T) {
	for _, s := range []string{"pending", "seeding", "live", "needs_recapture", "stopped", "error"} {
		if !keeperStatusValid(s) {
			t.Errorf("%q should be a valid keeper status", s)
		}
	}
	if keeperStatusValid("bogus") {
		t.Error("an unknown status must be rejected so a bad keeper report cannot write garbage")
	}
}
