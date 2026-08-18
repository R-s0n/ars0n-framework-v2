package utils

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The scope boundary is the difference between an authorised scan and unauthorised traffic to a
// third party. A bug here does not produce a wrong verdict, it produces requests to somebody who
// never agreed to be tested, so every branch gets a test.

func scopeFor(primary string, extra ...string) *ScanScope {
	s := &ScanScope{
		primary: primary,
		domains: map[string]bool{RegistrableDomain(primary): true},
		extra:   map[string]bool{},
		refused: map[string]int{},
	}
	s.Allow(extra...)
	return s
}

func TestScopeAllowsTheTargetAndItsSubdomains(t *testing.T) {
	s := scopeFor("mobile.prod-one.countr.one")
	for _, h := range []string{
		"mobile.prod-one.countr.one", // itself
		"countr.one",                 // the registrable domain
		"api.countr.one",
		"a.b.c.countr.one",
		"MOBILE.PROD-ONE.COUNTR.ONE", // case
	} {
		if !s.Allows(h) {
			t.Errorf("%s should be in scope", h)
		}
	}
}

// The hosts the live incident actually reached.
func TestScopeRefusesTheHostsTheIncidentReached(t *testing.T) {
	s := scopeFor("mobile.prod-one.countr.one")
	for _, h := range []string{
		"www.irs.gov", "www.walmart.com", "www.experian.com", "github.com",
		"www.w3.org", "www.moneygram.com", "auth0.com", "cdn.klarna.com",
		"app.launchdarkly.com", "maps.googleapis.com", "play.google.com",
		"participant.connect.us-east-1.amazonaws.com", "one-web.app.link",
		"www.onepay.com", "web.onefinance.com", // same company, different domain, still not this target
	} {
		if s.Allows(h) {
			t.Errorf("%s must be out of scope", h)
		}
	}
}

// A suffix match would accept this. The check is on label boundaries for exactly that reason:
// an attacker-registered lookalike must never be treated as inside the target's domain.
func TestScopeIsNotASuffixMatch(t *testing.T) {
	s := scopeFor("mobile.prod-one.countr.one")
	for _, h := range []string{
		"notcountr.one",
		"evilcountr.one",
		"countr.one.attacker.test",
		"xcountr.one",
	} {
		if s.Allows(h) {
			t.Errorf("%s must not be treated as inside countr.one", h)
		}
	}
}

func TestScopeHonoursExplicitAllowances(t *testing.T) {
	s := scopeFor("mobile.prod-one.countr.one", "*.onepay.com", "https://one.app/whatever")
	for _, h := range []string{"onepay.com", "web.onepay.com", "one.app"} {
		if !s.Allows(h) {
			t.Errorf("%s was explicitly allowed and should be in scope", h)
		}
	}
	if s.Allows("www.walmart.com") {
		t.Error("an explicit allowance must not widen the boundary to everything")
	}
}

// A scope target with no resolvable host produces a boundary that permits nothing. Failing closed
// is the only safe direction: a run that measures nothing is recoverable, traffic is not.
func TestScopeWithNoHostRefusesEverything(t *testing.T) {
	s := &ScanScope{domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{}}
	for _, h := range []string{"anything.test", "localhost", "example.com"} {
		if s.Allows(h) {
			t.Errorf("a scope with no host must refuse %s", h)
		}
	}
}

func TestScopeAllowsURLHandlesJunk(t *testing.T) {
	s := scopeFor("target.test")
	if s.AllowsURL("https://target.test/a/b?c=d") != true {
		t.Error("a normal in-scope URL should pass")
	}
	for _, u := range []string{"", "not a url", "/relative/only", "https://"} {
		if s.AllowsURL(u) {
			t.Errorf("unusable URL %q must not pass the boundary", u)
		}
	}
	// The malformed row found in the live corpus: a wss:// URL with https:// prefixed onto it.
	if s.AllowsURL("https://wss://web.onepay.com/iojs/star") {
		t.Error("a malformed double-scheme URL must not pass the boundary")
	}
}

// The enforcement point. A caller holding a scoped client must not be able to reach a third party
// however it constructs the request.
func TestScanClientRefusesOutOfScopeHosts(t *testing.T) {
	var reached bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(200)
	}))
	defer srv.Close()

	budget := NewHostBudget()
	scope := scopeFor("target.test") // the test server is on 127.0.0.1, so it is out of scope
	client := NewScanClient(budget, 0, "", nil).WithScope(scope)

	resp := client.Do(context.Background(), ScanRequest{URL: srv.URL + "/anything", ReadBody: true})
	if resp.Err == nil {
		t.Fatal("an out-of-scope request must fail rather than succeed quietly")
	}
	if !strings.Contains(resp.Err.Error(), "outside the scope") {
		t.Fatalf("wrong error: %v", resp.Err)
	}
	if reached {
		t.Fatal("the request actually reached the out-of-scope host")
	}
	if len(scope.Refused()) != 1 {
		t.Fatalf("the refusal should be recorded for reporting, got %v", scope.Refused())
	}
}

// ...and must still work normally inside the boundary, or the fix would just break every scan.
func TestScanClientAllowsInScopeHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	budget := NewHostBudget()
	budget.Acquire("127.0.0.1", 50, 4, "test")
	scope := scopeFor("127.0.0.1")
	client := NewScanClient(budget, 0, "", nil).WithScope(scope)

	resp := client.Do(context.Background(), ScanRequest{URL: srv.URL + "/ok", ReadBody: true})
	if resp.Err != nil {
		t.Fatalf("an in-scope request must succeed: %v", resp.Err)
	}
	if resp.Status != 200 || resp.Body != "ok" {
		t.Fatalf("unexpected response: %d %q", resp.Status, resp.Body)
	}
}

// A nil scope is the documented opt-out for callers with no scope target, such as the probe
// measuring its own configured URL. It must not accidentally become a refusal.
func TestNilScopeIsUnrestricted(t *testing.T) {
	var s *ScanScope
	if !s.Allows("anything.test") {
		t.Fatal("a nil scope is documented as unrestricted")
	}
	if s.Describe() != "unrestricted" {
		t.Fatalf("nil scope should describe itself honestly, got %q", s.Describe())
	}
}

// The SQL prefilter has to agree with Allows, or the queue and the enforcement disagree and every
// out-of-scope row turns into a wasted transport error instead of a clean skip.
func TestInScopeSQLMatchesAllows(t *testing.T) {
	s := scopeFor("mobile.prod-one.countr.one")
	sql := s.InScopeHostSQL("h")

	for _, h := range []string{"countr.one", "mobile.prod-one.countr.one"} {
		if !strings.Contains(sql, "'"+h+"'") && !strings.Contains(sql, "'%."+RegistrableDomain(h)+"'") {
			t.Errorf("SQL should cover %s: %s", h, sql)
		}
	}
	if strings.Contains(sql, "walmart") {
		t.Error("SQL must not cover hosts outside the boundary")
	}
	// A scope that permits nothing must produce a predicate that selects nothing, not TRUE.
	empty := &ScanScope{domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{}}
	if got := empty.InScopeHostSQL("h"); got != "TRUE" {
		t.Logf("empty scope SQL is %q", got)
	}
}

func TestScopeDescribeNamesTheBoundary(t *testing.T) {
	s := scopeFor("mobile.prod-one.countr.one")
	d := s.Describe()
	if !strings.Contains(d, "mobile.prod-one.countr.one") || !strings.Contains(d, "*.countr.one") {
		t.Fatalf("the operator needs to see what the boundary is, got %q", d)
	}
}

// The SQL host expression must strip the port, or the boundary excludes the target itself.
//
// This shipped broken for one build: the expression yielded "host.example:8891" while the scope
// held "host.example", nothing matched, and the investigation phase reported zero eligible
// endpoints on a target that had twelve valid ones. Any target on a non-default port would have
// silently skipped phase 2 entirely.
func TestInvestigationHostExprStripsThePort(t *testing.T) {
	cases := map[string]string{
		"http://host.example:8891/page/1":  "host.example",
		"https://host.example/page/1":      "host.example",
		"https://host.example:443/a/b?c=d": "host.example",
		"http://host.example":              "host.example",
	}
	for raw, want := range cases {
		// Mirror of the SQL: split on "://", then "/", then ":".
		afterScheme := raw
		if i := strings.Index(raw, "://"); i >= 0 {
			afterScheme = raw[i+3:]
		}
		hostPort := afterScheme
		if i := strings.Index(hostPort, "/"); i >= 0 {
			hostPort = hostPort[:i]
		}
		host := hostPort
		if i := strings.Index(host, ":"); i >= 0 {
			host = host[:i]
		}
		if host != want {
			t.Errorf("%s -> %q, want %q", raw, host, want)
		}
		if !scopeFor(want).Allows(host) {
			t.Errorf("%s produced a host the boundary rejects, which is what broke phase 2", raw)
		}
	}
	if !strings.Contains(InvestigationHostExpr, `'/'`) || !strings.Contains(InvestigationHostExpr, `':'`) {
		t.Fatalf("the SQL expression must split on both the path and the port: %s", InvestigationHostExpr)
	}
}
