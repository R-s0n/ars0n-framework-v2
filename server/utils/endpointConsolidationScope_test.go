package utils

import (
	"encoding/json"
	"testing"
)

// Every case here is a row that a real run against http://10.0.0.18:3000 actually produced and
// stored as attack surface, or the mechanism that let it in.
//
// The scope objects are built by hand rather than through newConsolidationScope, which reads the
// scope_targets row and the operator's host decisions out of Postgres. What is under test is the
// admission decision, and it is a separate function precisely so it can be checked without a
// database and without a live target.

func ipScope(host string, port int) *consolidationScope {
	return &consolidationScope{
		host:     host,
		port:     port,
		hostIsIP: true,
		allowed:  map[string]bool{host: true},
	}
}

func domainScope(host string, port int) *consolidationScope {
	return &consolidationScope{
		host: host,
		port: port,
		scope: &ScanScope{
			primary: host,
			domains: map[string]bool{RegistrableDomain(host): true},
			extra:   map[string]bool{},
		},
	}
}

func admitURL(t *testing.T, c *consolidationScope, raw, scheme string) (bool, string) {
	t.Helper()
	id, ok := CanonicalizeEndpoint(raw, "GET", scheme)
	if !ok {
		t.Fatalf("canonicalize refused %q, so this case cannot exercise the scope check", raw)
	}
	return c.admit(id)
}

// gau returned nine URLs on http://10.0.0.18:80 for a target scoped to http://10.0.0.18:3000. Port
// 80 is a different service on the same machine: it served login.cfm and Content/Default.asp, which
// the Juice Shop on :3000 does not have. All nine were consolidated as real endpoints.
func TestConsolidationRefusesOtherPortOnTheTargetHost(t *testing.T) {
	c := ipScope("10.0.0.18", 3000)

	for _, raw := range []string{
		"http://10.0.0.18:80/login.cfm",
		"http://10.0.0.18/Content/Default.asp",
		"http://10.0.0.18:80/Animal_Mineral_Vegetable/exercise1_config.jsp",
		"http://10.0.0.18:8080/status/index.html",
	} {
		admitted, reason := admitURL(t, c, raw, "http")
		if admitted {
			t.Errorf("%s was admitted; it is not the service this target names", raw)
		}
		if reason != exclusionOutOfPort {
			t.Errorf("%s refused as %q, want %q", raw, reason, exclusionOutOfPort)
		}
	}
}

// The port that the target does name still goes in, over either transport, because scheme is not
// part of endpoint identity.
func TestConsolidationAdmitsTheTargetHostAndPort(t *testing.T) {
	c := ipScope("10.0.0.18", 3000)

	for _, raw := range []string{
		"http://10.0.0.18:3000/api/Users",
		"https://10.0.0.18:3000/rest/products/search?q=apple",
		"http://10.0.0.18:3000/ftp/acquisitions.md",
	} {
		if admitted, reason := admitURL(t, c, raw, "http"); !admitted {
			t.Errorf("%s was refused as %q; it is the target itself", raw, reason)
		}
	}
}

// A target that names no port keeps the pre-existing behaviour: the port clause is a constraint the
// operator opted into by writing one, not something invented for every target.
func TestConsolidationWithoutATargetPortDoesNotConstrainPorts(t *testing.T) {
	c := domainScope("example.com", 0)

	for _, raw := range []string{"https://example.com/a", "https://example.com:8443/a"} {
		if admitted, reason := admitURL(t, c, raw, "https"); !admitted {
			t.Errorf("%s was refused as %q, but this target names no port", raw, reason)
		}
	}
}

// "http://.10.18/robots.txt" survived a whole consolidation and was stored as an endpoint row. Its
// host has an empty leading label, so no resolver could ever answer for it. It was caught only much
// later, by the request layer, as skipped.out_of_scope.
func TestConsolidationRefusesSyntacticallyImpossibleHosts(t *testing.T) {
	c := ipScope("10.0.0.18", 3000)

	admitted, reason := admitURL(t, c, "http://.10.18/robots.txt", "http")
	if admitted {
		t.Fatal(".10.18 was admitted; that host cannot exist")
	}
	if reason != exclusionInvalidHost {
		t.Fatalf(".10.18 refused as %q, want %q", reason, exclusionInvalidHost)
	}

	// An impossible host is refused whatever the boundary is, including when no boundary could be
	// established at all. Otherwise a target with an unreadable scope row would still store garbage.
	unbounded := &consolidationScope{unbounded: true, allowed: map[string]bool{}}
	if admitted, reason := admitURL(t, unbounded, "http://.10.18/robots.txt", "http"); admitted {
		t.Errorf(".10.18 was admitted by an unbounded scope, reason %q", reason)
	}
	if admitted, _ := admitURL(t, unbounded, "http://10.0.0.18/anything", "http"); !admitted {
		t.Error("an unbounded scope refused a real host; it must record rather than empty the corpus")
	}
}

func TestHostIsSyntacticallyValid(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"10.0.0.18", true},
		{"example.com", true},
		{"api.dev.countr.one", true},
		{"localhost", true},
		{"xn--80ak6aa92e.com", true},
		{"my_service.internal", true},
		{"::1", true},
		{"2001:db8::1", true},

		{"", false},
		{".10.18", false},           // empty leading label, the row that was actually stored
		{"10.0.18", false},          // not an address and no top-level label can be all digits
		{"a..b.com", false},         // empty interior label
		{"3000", false},             // a port that arrived where a host belongs
		{"-bad.example.com", false}, // a label cannot start with a hyphen
		{"bad-.example.com", false},
		{"has space.com", false},
		{"has%20escape.com", false},
		{"2001:db8::zz", false}, // colon means address, and this one does not parse
	}
	for _, tc := range cases {
		if got := hostIsSyntacticallyValid(tc.host); got != tc.want {
			t.Errorf("hostIsSyntacticallyValid(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// The boundary rendered as "*.0.18, 10.0.0.18" because RegistrableDomain takes the last two labels of
// anything that is not a known two-label public suffix, and an IP literal is not a domain. That
// widening would admit any host ending in ".0.18". An IP-literal target is the exact host.
func TestConsolidationIPTargetDoesNotWidenToARegistrableDomain(t *testing.T) {
	// This used to assert rd == "0.18", encoding the upstream mis-parse as a fact because the fix
	// lived in a file that change did not own. The fix has since landed in scanCredentials.go, so
	// the assertion is inverted: an address is its own boundary.
	//
	// The consolidation guard below is NOT redundant now. It refuses an out-of-scope address at the
	// import boundary with a reason on the row, which is a different job from ScanScope refusing to
	// send traffic there. Both are asserted because either one alone leaves a hole.
	if rd := RegistrableDomain("10.0.0.18"); rd != "10.0.0.18" {
		t.Fatalf("RegistrableDomain(\"10.0.0.18\") = %q, want the address itself; %q would widen the "+
			"boundary to admit any host ending in that suffix", rd, rd)
	}

	// The target is recognised as an address, which is what routes admission away from ScanScope and
	// its "*.0.18" domain. Reverting that recognition is the whole defect.
	c := parseConsolidationScopeBase("http", "http://10.0.0.18:3000")
	if !c.hostIsIP {
		t.Fatal("10.0.0.18 was not recognised as an address, so the boundary would widen to *.0.18")
	}
	if c.host != "10.0.0.18" || c.port != 3000 {
		t.Fatalf("parsed host=%q port=%d, want 10.0.0.18 and 3000", c.host, c.port)
	}
	if c.scope != nil {
		t.Fatal("an address target must not carry a registrable-domain boundary")
	}

	// Neighbours on the same /24 are addresses in their own right, and none of them is the target.
	c = ipScope("10.0.0.18", 3000)
	for _, raw := range []string{"http://10.0.0.180:3000/x", "http://110.0.0.18:3000/x"} {
		admitted, reason := admitURL(t, c, raw, "http")
		if admitted {
			t.Errorf("%s was admitted; an address has no subdomains", raw)
		}
		if reason != exclusionOutOfHost {
			t.Errorf("%s refused as %q, want %q", raw, reason, exclusionOutOfHost)
		}
	}

	// The one shape "*.0.18" would actually have admitted is refused a step earlier, because a
	// top-level label of "18" cannot exist. Both guards have to hold for the boundary to mean
	// anything, so the reason is asserted rather than only the refusal.
	if admitted, reason := admitURL(t, c, "http://evil.0.18:3000/x", "http"); admitted || reason != exclusionInvalidHost {
		t.Errorf("evil.0.18 admitted=%v reason=%q, want refused as %q", admitted, reason, exclusionInvalidHost)
	}
}

// The crawlers read these off the Juice Shop page. scanScope.go already calls a link on a page
// "evidence of nothing", and none of them are the target.
func TestConsolidationRefusesCrawlerNoiseButKeepsTheTargetsOwnDomain(t *testing.T) {
	c := domainScope("juice.example.com", 0)

	for _, raw := range []string{
		"https://fonts.googleapis.com/css",
		"http://www.w3.org/2000/svg",
		"https://www.youtube.com/watch?v=9PnbKL3wuH4",
		"https://testnets.opensea.io/assets/mumbai/0xf4817631372dca68a25a18eb7a0b36d54f3dbcf7/0",
		"http://js.maxmind.com/js/apis/geoip2/v2.1/geoip2.js",
	} {
		admitted, reason := admitURL(t, c, raw, "https")
		if admitted {
			t.Errorf("%s was admitted as this target's attack surface", raw)
		}
		if reason != exclusionOutOfHost {
			t.Errorf("%s refused as %q, want %q", raw, reason, exclusionOutOfHost)
		}
	}

	// A named-host target keeps its registrable domain. Narrowing that would drop the API host of
	// every application whose front end and back end live on different subdomains.
	for _, raw := range []string{
		"https://juice.example.com/rest/products",
		"https://api.example.com/v2/orders",
		"https://example.com/",
	} {
		if admitted, reason := admitURL(t, c, raw, "https"); !admitted {
			t.Errorf("%s was refused as %q; it is inside the target's own registrable domain", raw, reason)
		}
	}

	// Label boundary, not suffix match: notexample.com is a different company.
	if admitted, _ := admitURL(t, c, "https://notexample.com/", "https"); admitted {
		t.Error("notexample.com was admitted into example.com's scope")
	}
}

// The reason has to be the useful one. Checking the port first reported www.w3.org and
// fonts.googleapis.com on the Juice Shop target as "out_of_scope_port", which is technically true
// and tells an operator nothing: those hosts are not the application on any port.
func TestARefusedThirdPartyHostReadsAsAHostProblemNotAPortProblem(t *testing.T) {
	c := ipScope("10.0.0.18", 3000)

	for _, raw := range []string{
		"http://www.w3.org/2000/svg",
		"https://fonts.googleapis.com",
		"http://js.maxmind.com/js/apis/geoip2/v2.1/geoip2.js",
		"https://owasp-juice.shop",
	} {
		admitted, reason := admitURL(t, c, raw, "http")
		if admitted {
			t.Errorf("%s was admitted", raw)
		}
		if reason != exclusionOutOfHost {
			t.Errorf("%s refused as %q, want %q: it is not this application on any port",
				raw, reason, exclusionOutOfHost)
		}
	}

	// And the converse still holds: the target's own host on the wrong port is a port problem.
	if _, reason := admitURL(t, c, "http://10.0.0.18:80/login.cfm", "http"); reason != exclusionOutOfPort {
		t.Errorf("10.0.0.18:80 refused as %q, want %q", reason, exclusionOutOfPort)
	}
}

// An operator who explicitly authorised a host keeps it, even on an IP-literal target, because
// newConsolidationScope seeds `allowed` from InScopeCrawlHosts.
func TestConsolidationHonoursExplicitlyAuthorisedHosts(t *testing.T) {
	c := ipScope("10.0.0.18", 3000)
	c.allowed["auth.internal"] = true

	if admitted, reason := admitURL(t, c, "http://auth.internal:3000/login", "http"); !admitted {
		t.Errorf("an authorised host was refused as %q", reason)
	}
}

// "excluded=1 with no way to see which row" was itself reported as a defect, so the run has to carry
// the URL, not just the count, all the way back out of the status endpoint.
func TestExcludedRowsAreRetrievableFromTheRunResult(t *testing.T) {
	log := newExclusionLog()
	for _, raw := range []string{
		"http://10.0.0.18:80/login.cfm",
		"http://10.0.0.18:80/nctabs.html",
	} {
		id, ok := CanonicalizeEndpoint(raw, "GET", "http")
		if !ok {
			t.Fatalf("canonicalize refused %q", raw)
		}
		log.record(raw, id, "gau", exclusionOutOfPort)
	}
	id, _ := CanonicalizeEndpoint("http://.10.18/robots.txt", "GET", "http")
	log.record("http://.10.18/robots.txt", id, "gau", exclusionInvalidHost)

	if log.Total != 3 {
		t.Fatalf("total = %d, want 3", log.Total)
	}
	if log.ByReason[exclusionOutOfPort] != 2 || log.ByReason[exclusionInvalidHost] != 1 {
		t.Fatalf("by_reason = %v", log.ByReason)
	}
	// Host and port together, because "two rows on 10.0.0.18" hides the whole point.
	if log.ByHost["10.0.0.18"] != 2 {
		t.Fatalf("by_host = %v, want two rows attributed to 10.0.0.18", log.ByHost)
	}

	// The round trip the operator actually sees: run result JSON in, refused URLs out.
	stored, err := json.Marshal(map[string]interface{}{"endpoint_count": 0, "excluded": log})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw := string(stored)
	back := consolidationExclusionsFromResult(&raw)
	if back.Total != 3 || len(back.Samples) != 3 {
		t.Fatalf("round trip lost rows: total=%d samples=%d", back.Total, len(back.Samples))
	}
	found := false
	for _, s := range back.Samples {
		if s.URL == "http://.10.18/robots.txt" && s.Reason == exclusionInvalidHost && s.Source == "gau" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the impossible host is not retrievable from the run result: %+v", back.Samples)
	}

	// A run from before scope enforcement existed reads as zero, never as null.
	if empty := consolidationExclusionsFromResult(nil); empty == nil || empty.Total != 0 || empty.ByReason == nil {
		t.Fatalf("a missing result must decode to an empty log, got %+v", empty)
	}
	legacy := `{"endpoint_count":172,"rows_read":517,"skipped":{"unusable_url":11}}`
	if old := consolidationExclusionsFromResult(&legacy); old == nil || old.Total != 0 || old.ByHost == nil {
		t.Fatalf("a pre-enforcement result must decode to an empty log, got %+v", old)
	}
}

// The sample list is bounded, because an archive source can emit tens of thousands of out-of-scope
// rows and the whole thing is stored as one JSON blob on the run.
func TestExclusionSamplesAreBoundedButTheCountsAreNot(t *testing.T) {
	log := newExclusionLog()
	id, _ := CanonicalizeEndpoint("http://10.0.0.18/x", "GET", "http")
	for i := 0; i < maxExclusionSamples+50; i++ {
		log.record("http://10.0.0.18/x", id, "gau", exclusionOutOfPort)
	}
	if len(log.Samples) != maxExclusionSamples {
		t.Fatalf("samples = %d, want %d", len(log.Samples), maxExclusionSamples)
	}
	if !log.Truncated {
		t.Fatal("truncation was not reported, so the list would read as complete")
	}
	if log.Total != maxExclusionSamples+50 {
		t.Fatalf("total = %d; the count must not be capped with the samples", log.Total)
	}
}
