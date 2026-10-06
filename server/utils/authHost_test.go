package utils

import (
	"strings"
	"testing"
)

// The auth-host classification has one defining property: a host marked as an auth host is reachable
// by the refresh path and refused by every scanner, and those two answers come from DIFFERENT
// predicates so they can never drift. Allows() (what every scanner asks) must still refuse it;
// AllowsForAuth() (what only the refresh guards ask) must admit it. These tests pin that asymmetry
// without a database by setting the private authHosts set directly.

func authTestScope() *ScanScope {
	s := &ScanScope{
		domains: map[string]bool{},
		extra:   map[string]bool{},
		refused: map[string]int{},
		primary: "app.example.com",
		authHosts: map[string]bool{
			"cognito-idp.us-east-1.amazonaws.com": true,
			"idp.example.net":                     true,
		},
	}
	s.Allow("example.com")
	return s
}

func TestAuthHostIsRefusedByScannersButAdmittedForAuth(t *testing.T) {
	s := authTestScope()

	// The auth host sits outside the scan boundary, and it must STAY outside it for scanning.
	if s.Allows("cognito-idp.us-east-1.amazonaws.com") {
		t.Fatal("Allows() admitted an auth host; a scanner would then send attack traffic to it")
	}
	// But the refresh predicate admits it, which is the whole point of the classification.
	if !s.AllowsForAuth("cognito-idp.us-east-1.amazonaws.com") {
		t.Fatal("AllowsForAuth() refused an auth host; the refresh path could never reach it")
	}
}

func TestAuthClassificationNeverWidensTheScanBoundaryForOtherHosts(t *testing.T) {
	s := authTestScope()

	// A plain third-party host that is NOT classified as auth is refused by BOTH predicates. The auth
	// flag must not have become a general "let anything through" switch.
	for _, pred := range []struct {
		name string
		fn   func(string) bool
	}{{"Allows", s.Allows}, {"AllowsForAuth", s.AllowsForAuth}} {
		if pred.fn("analytics.thirdparty.io") {
			t.Fatalf("%s admitted an unrelated third-party host", pred.name)
		}
	}

	// An in-scope host is allowed by both, unchanged.
	if !s.Allows("app.example.com") || !s.AllowsForAuth("app.example.com") {
		t.Fatal("an in-scope host must be allowed by both predicates")
	}
}

func TestIsAuthFlowHostWalksParentDomainsAndStripsPorts(t *testing.T) {
	set := map[string]bool{"example.net": true, "okta.com": true}

	if !IsAuthFlowHost(set, "idp.example.net") {
		t.Error("a subdomain of a classified auth domain should be treated as auth")
	}
	if !IsAuthFlowHost(set, "login.okta.com:443") {
		t.Error("a port on the candidate must not defeat the auth match")
	}
	if IsAuthFlowHost(set, "notexample.net") {
		t.Error("a sibling label must NOT match (label-boundary, not suffix)")
	}
	if IsAuthFlowHost(nil, "idp.example.net") || IsAuthFlowHost(map[string]bool{}, "idp.example.net") {
		t.Error("an empty auth set admits nothing")
	}
}

// requestFlowScopeRefusal is the built-flow replay guard. An auth host must bypass the in_scope=false
// deny and the scope boundary there (so a built refresh flow can reach it), but NOT a path exclusion:
// an exclusion is the operator's "this path texts a real customer" and is a stronger statement.
func TestRequestFlowScopeRefusalAdmitsAuthHostPastDenyAndScope(t *testing.T) {
	s := authTestScope()

	// An auth host is in the in_scope=false deny set by construction. It must still be allowed here.
	rails := flowSendRails{
		Scope:  s,
		Denied: map[string]bool{"cognito-idp.us-east-1.amazonaws.com": true},
	}
	step := "POST /oauth2/token HTTP/1.1\r\nHost: cognito-idp.us-east-1.amazonaws.com\r\n\r\n"
	if host, refusal := requestFlowScopeRefusal(step, "", rails); refusal != "" {
		t.Fatalf("an auth-host step was refused (host %q): %s", host, refusal)
	}

	// A non-auth out-of-scope host is still refused.
	other := "GET /collect HTTP/1.1\r\nHost: analytics.thirdparty.io\r\n\r\n"
	if _, refusal := requestFlowScopeRefusal(other, "", rails); refusal == "" {
		t.Fatal("a non-auth third-party host was allowed through the built-flow guard")
	}
}

func TestRequestFlowScopeRefusalStillHonoursAnExclusionOnAnAuthHost(t *testing.T) {
	s := authTestScope()
	rails := flowSendRails{
		Scope: s,
		Exclusions: []FlowExclusion{
			{ID: "e1", Pattern: "cognito-idp.us-east-1.amazonaws.com/oauth2/token",
				Reason: "do not replay the token mint in this run"},
		},
	}
	step := "POST /oauth2/token HTTP/1.1\r\nHost: cognito-idp.us-east-1.amazonaws.com\r\n\r\n"
	_, refusal := requestFlowScopeRefusal(step, "", rails)
	if refusal == "" {
		t.Fatal("an exclusion rule on an auth host was ignored; the exclusion must still win")
	}
	if !strings.Contains(refusal, "exclusion") {
		t.Errorf("the refusal should name the exclusion, got: %s", refusal)
	}
}
