package utils

import "testing"

// The scope judgement behind the access bypass, GraphQL, sensitive leak and exposed git handovers.
//
// Every test here FAILS against the judgement this replaced, which compared the last two labels of
// the hostname and, by its own comment, "deliberately errs towards INCLUDING rather than excluding".
// That is not a style preference on this code path: an in_scope badge is what an operator marks a
// target from, and nomore403 spends roughly a thousand requests on each one.

// scopeRulesFor parses the operator's own rule text the same way the store does, so a test cannot
// assert against a rule shape the parser would never produce.
func scopeRulesFor(t *testing.T, lines ...string) []ScopeRule {
	t.Helper()
	out := make([]ScopeRule, 0, len(lines))
	for _, line := range lines {
		r, err := ParseScopeRule(line)
		if err != nil {
			t.Fatalf("scope rule %q does not parse: %v", line, err)
		}
		r.Enabled = true
		out = append(out, r)
	}
	compiled, err := CompileScopeRules(out)
	if err != nil {
		t.Fatalf("scope rules do not compile: %v", err)
	}
	return compiled
}

// THE CASE THIS FIX EXISTS FOR, taken from a live engagement.
//
// The scope target is one named host, app.staging-v2.tradetalk.us, and the programme names twelve
// assets with no wildcard. The operator has one enabled scope rule, "=app.staging-v2.tradetalk.us",
// and because authored rules REPLACE the legacy boundary rather than adding to it, every other host
// is default_deny. The old judgement never consulted that rule: it compared "tradetalk.us" and
// handed back authx, data, wallet-api, paper-api, api-wallet-alpacax and stream.data all badged
// in_scope=true. None of them is in scope, and two of them are an auth provider.
func TestBypassScopeHonoursExactHostRule(t *testing.T) {
	scope := newScanScope("app.staging-v2.tradetalk.us", nil,
		scopeRulesFor(t, "=app.staging-v2.tradetalk.us"))
	judge := bypassScopeJudgeFor(scope, nil)

	if !judge.InScope("https://app.staging-v2.tradetalk.us/v1/account") {
		t.Fatal("the scope target's own host must be offered")
	}

	// Every one of these was badged in_scope=true by the last-two-labels comparison.
	for _, out := range []string{
		"https://authx.staging-v2.tradetalk.us/oauth/token",
		"https://data.staging-v2.tradetalk.us/v2/stocks",
		"https://wallet-api.staging-v2.tradetalk.us/v1/transfers",
		"https://paper-api.staging-v2.tradetalk.us/v2/orders",
		"https://api-wallet-alpacax.staging-v2.tradetalk.us/health",
		"https://stream.data.staging-v2.tradetalk.us/v2/sip",
		"https://tradetalk.us/",
	} {
		if judge.InScope(out) {
			t.Errorf("%s is outside this programme's scope and must not be badged in_scope", out)
		}
	}
}

// A WILDCARD PROGRAMME MUST NOT BE NARROWED. Inverting the old heuristic would have broken every
// wildcard engagement, which is the reason this consults ScanScope instead of holding a second
// opinion: for *.countr.one the boundary really is the registrable domain, and it still is.
func TestBypassScopeStillAdmitsWildcardSubdomains(t *testing.T) {
	// What LoadScanScope builds for a Wildcard scope target: scope_target is "*.countr.one", so
	// scopeTargetHost yields that literally and RegistrableDomain widens it to countr.one.
	scope := newScanScope("*.countr.one", nil, nil)
	judge := bypassScopeJudgeFor(scope, nil)

	for _, in := range []string{
		"https://countr.one/admin",
		"https://mercury-dev.countr.one/admin",
		"https://global.cdn.mercury-dev.countr.one/admin",
	} {
		if !judge.InScope(in) {
			t.Errorf("%s is inside the wildcard and must still be offered", in)
		}
	}
	for _, out := range []string{
		"https://dev-partner-auth.one.app/admin",
		"https://notcountr.one/admin", // a suffix match would wrongly admit this
	} {
		if judge.InScope(out) {
			t.Errorf("%s is not inside the wildcard", out)
		}
	}
}

// AN EXPLICIT OPERATOR DENY BEATS AN ALLOW, by both routes the operator has.
func TestBypassScopeDenyBeatsAllow(t *testing.T) {
	// Route one: an authored deny rule alongside a wide allow. DecideScope gives deny precedence
	// unconditionally, with no specificity override.
	rules := scopeRulesFor(t, "tradetalk.us", "!authx.staging-v2.tradetalk.us")
	judge := bypassScopeJudgeFor(newScanScope("app.staging-v2.tradetalk.us", nil, rules), nil)
	if !judge.InScope("https://app.staging-v2.tradetalk.us/x") {
		t.Fatal("the allow rule must still admit the target's own host")
	}
	if judge.InScope("https://authx.staging-v2.tradetalk.us/oauth/token") {
		t.Error("an authored deny must beat a wider allow")
	}

	// Route two: scope_target_scope_hosts at in_scope=false, with NO authored rules at all, so the
	// legacy domain boundary would otherwise admit the host. This is the check that is not
	// redundant with the boundary, and it is the one detectedFlowRun.go makes first.
	denied := map[string]bool{"authx.staging-v2.tradetalk.us": true}
	legacy := bypassScopeJudgeFor(newScanScope("app.staging-v2.tradetalk.us", nil, nil), denied)
	if !legacy.InScope("https://app.staging-v2.tradetalk.us/x") {
		t.Fatal("the target's own host is not excluded")
	}
	if legacy.InScope("https://authx.staging-v2.tradetalk.us/oauth/token") {
		t.Error("a host marked in_scope=false must never be badged in scope")
	}
	// The exclusion covers children of an excluded host too, the same parent walk the flow runner
	// uses: excluding a host and then offering a subdomain of it honours the letter of the
	// operator's decision and breaks its meaning.
	if legacy.InScope("https://idp.authx.staging-v2.tradetalk.us/x") {
		t.Error("a subdomain of an excluded host must be excluded with it")
	}
}

// A TARGET WITH NO RULES AND NO EXCLUSIONS MUST NOT REGRESS. The legacy boundary is the scope
// target's registrable domain, and this change leaves it alone: the fix is that a boundary now
// EXISTS to consult, not that every target got narrower.
func TestBypassScopeNoRulesKeepsLegacyBoundary(t *testing.T) {
	judge := bypassScopeJudgeFor(newScanScope("app.dailypay.com", nil, nil), nil)

	for _, in := range []string{
		"https://app.dailypay.com/admin",
		"https://api.dailypay.com/admin",
		"https://dailypay.com/admin",
		"https://iam.staging.dailypay.com/admin",
	} {
		if !judge.InScope(in) {
			t.Errorf("%s was offered before this change and must still be offered", in)
		}
	}
	for _, out := range []string{
		"https://dailypay.extole.io/x",
		"https://dailypaympniug.dataplane.rudderstack.com/x",
	} {
		if judge.InScope(out) {
			t.Errorf("%s is a third party", out)
		}
	}

	// An operator-named host the crawl observed is inside the boundary, exactly as ScanScope has
	// it: api.dpfriday.com is a real in_scope=true row on that target.
	withExtra := bypassScopeJudgeFor(
		newScanScope("app.dailypay.com", []string{"api.dpfriday.com"}, nil), nil)
	if !withExtra.InScope("https://api.dpfriday.com/x") {
		t.Error("a host the operator marked in scope must be offered")
	}
}

// THE FAIL-CLOSED DIRECTION, which is the reversal. Each of these returned TRUE before.
func TestBypassScopeFailsClosed(t *testing.T) {
	// A scope target whose row names no host: no boundary can be established, so nothing is
	// offered. The old code treated an unknown boundary as permission for everything.
	if bypassScopeJudgeFor(newScanScope("", nil, nil), nil).InScope("https://anything.example.com/x") {
		t.Error("with no boundary established nothing may be badged in scope")
	}

	// The zero judge, which is what a failed exclusion read returns.
	var unloaded bypassScopeJudge
	if unloaded.InScope("https://app.staging-v2.tradetalk.us/x") {
		t.Error("a judge that never loaded a boundary must admit nothing")
	}
	if bypassScopeJudgeFor(nil, nil).InScope("https://app.staging-v2.tradetalk.us/x") {
		t.Error("a nil ScanScope means unscoped to ScanScope.Allows and must mean refused here")
	}

	// Junk in the URL column. The endpoint tables carry XML namespaces and OAuth grant-type URNs,
	// not only endpoints.
	judge := bypassScopeJudgeFor(newScanScope("app.staging-v2.tradetalk.us", nil,
		scopeRulesFor(t, "=app.staging-v2.tradetalk.us")), nil)
	for _, junk := range []string{
		"",
		"   ",
		"not a url",
		"http://auth0.com/oauth/grant-type/password-realm",
		"://broken",
		"https://",
	} {
		if judge.InScope(junk) {
			t.Errorf("%q must not be badged in scope", junk)
		}
	}

	// Every enabled rule switched off is an EMPTY boundary, not a fallback to the legacy list.
	// ScanScope.Allows takes the rules branch whenever any rule exists.
	disabled := scopeRulesFor(t, "=app.staging-v2.tradetalk.us")
	disabled[0].Enabled = false
	off := bypassScopeJudgeFor(newScanScope("app.staging-v2.tradetalk.us", nil, disabled), nil)
	if off.InScope("https://app.staging-v2.tradetalk.us/x") {
		t.Error("with every rule disabled the boundary is empty, matching ScanScope.Allows")
	}
}

// The badge and the sentence next to it must describe the same boundary. An operator reconciling a
// list of targets against a boundary that is not the one in force either stops trusting the control
// or approves a run wider than they believe.
func TestBypassScopeDescribesTheBoundaryInForce(t *testing.T) {
	judge := bypassScopeJudgeFor(
		newScanScope("app.staging-v2.tradetalk.us", nil, scopeRulesFor(t, "=app.staging-v2.tradetalk.us")),
		map[string]bool{"authx.staging-v2.tradetalk.us": true})

	got := judge.Describe()
	want := "authored scope rules: =app.staging-v2.tradetalk.us; " +
		"excluded by the operator: authx.staging-v2.tradetalk.us"
	if got != want {
		t.Errorf("boundary description\n got: %s\nwant: %s", got, want)
	}

	var unloaded bypassScopeJudge
	if d := unloaded.Describe(); d == "unrestricted" || d == "" {
		t.Errorf("a judge with no boundary must not describe itself as unrestricted: %q", d)
	}
}

// The boundary this judges against is the SAME object the request-issuing paths gate on. If these
// two ever disagree, an operator can mark a target the scanner will then refuse to send to, or
// worse, the reverse.
func TestBypassScopeAgreesWithScanScope(t *testing.T) {
	scope := newScanScope("app.staging-v2.tradetalk.us", []string{"api.dpfriday.com"},
		scopeRulesFor(t, "tradetalk.us", "!authx.staging-v2.tradetalk.us"))
	judge := bypassScopeJudgeFor(scope, nil)

	for _, host := range []string{
		"app.staging-v2.tradetalk.us",
		"authx.staging-v2.tradetalk.us",
		"api.dpfriday.com",
		"tradetalk.us",
		"example.com",
	} {
		if got, want := judge.InScope("https://"+host+"/x"), scope.Allows(host); got != want {
			t.Errorf("%s: judge says %v, ScanScope.Allows says %v", host, got, want)
		}
	}
}

// TestNamedHostIsNotAWildcardForTheBypassJudge pins the D1 regression an adversarial review found in
// the first version of this fix. ScanScope.extra is "Hosts the operator named explicitly", and
// Allows walks it a second time as a wildcard domain. That promotion is load-bearing for Allows'
// own callers (dfrScope("example.com") relies on it, and narrowing Allows broke three
// detected-flow-runner tests), so it stays. AllowsNarrow is the version the bypass judge uses, and
// this is the difference.
func TestNamedHostIsNotAWildcardForTheBypassJudge(t *testing.T) {
	scope := newScanScope("primary.example.com", []string{"other.example"}, nil)

	if !scope.AllowsNarrow("primary.example.com") {
		t.Fatal("the scope target's own host must always be allowed")
	}
	if !scope.AllowsNarrow("other.example") {
		t.Fatal("a host the operator named explicitly must still be allowed, exactly")
	}
	// The regression: Allows admits all three, because it walks the named host as a domain.
	for _, host := range []string{"sub.other.example", "never.seen.other.example", "deep.sub.other.example"} {
		if scope.AllowsNarrow(host) {
			t.Errorf("AllowsNarrow must not admit %q: a named host is not a wildcard domain", host)
		}
		if !scope.Allows(host) {
			t.Errorf("precondition failed: Allows was expected to still admit %q, so this test is "+
				"pinning a real difference rather than agreeing with itself", host)
		}
	}

	// The wildcard half must be untouched, or every Wildcard scope target loses its subdomains.
	wild := newScanScope("example.com", nil, nil)
	wild.domains["example.com"] = true
	if !wild.AllowsNarrow("sub.example.com") {
		t.Fatal("a registrable domain in `domains` must still admit its subdomains under AllowsNarrow")
	}

	// And a boundary that was never established refuses, where Allows on a nil receiver admits.
	var none *ScanScope
	if none.AllowsNarrow("anything.example.com") {
		t.Error("a nil boundary must refuse: failing to establish scope is not opting out of it")
	}
}
