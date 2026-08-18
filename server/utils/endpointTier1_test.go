package utils

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The unauthenticated differential is the highest-value single request in the workflow, and it is
// also the easiest to get wrong in a way that produces a confident falsehood. These pin its four
// outcomes and the budget behaviour around them.

func tier1Ctx(host string) (*HostBudget, *ScopedAuthContext) {
	budget := NewHostBudget()
	budget.Acquire(host, 50, 4, "test")
	auth := &ScopedAuthContext{
		byHost: map[string]*ScopedAuthMaterial{
			host: {Host: host, Cookies: "session=valid"},
		},
		byDomain: map[string]*ScopedAuthMaterial{},
	}
	return budget, auth
}

func TestDifferentialFindsAnEndpointThatIgnoresAuthorization(t *testing.T) {
	// The bug: identical content whether or not a session is presented.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"user_id":1042,"email":"a@b.test","first_name":"Ada","account_id":9}`)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	sigs, _ := RunTier1(context.Background(), budget, auth, DefaultTier1Config(),
		[]Tier1Target{{
			EndpointID: "e1", URL: srv.URL + "/api/me", Method: "GET", Score: 100,
			Status: validationStatusValid, ContentType: "application/json", Authenticated: true,
		}}, ResponseFingerprint{}, false, nil)

	found := sigKinds(sigs["e1"])["authz_public_identical"]
	if found.Kind == "" {
		t.Fatalf("an endpoint returning identical bytes with and without a session must be reported, got %+v", sigs["e1"])
	}
	if found.Severity != "p0" {
		t.Errorf("the response carries personal-looking fields, so this should be p0, got %s", found.Severity)
	}
}

func TestDifferentialStaysQuietWhenAuthorizationIsEnforced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Cookie"), "session=valid") {
			w.WriteHeader(403)
			fmt.Fprint(w, `{"error":"forbidden"}`)
			return
		}
		fmt.Fprint(w, `{"secret":"only for members"}`)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	sigs, _ := RunTier1(context.Background(), budget, auth, DefaultTier1Config(),
		[]Tier1Target{{
			EndpointID: "e1", URL: srv.URL + "/api/private", Score: 50,
			Status: validationStatusValid, ContentType: "application/json", Authenticated: true,
		}}, ResponseFingerprint{}, false, nil)

	kinds := sigKinds(sigs["e1"])
	if _, bad := kinds["authz_public_identical"]; bad {
		t.Fatal("a 403 to the anonymous arm is authorization working, not a finding")
	}
	if s, ok := kinds["authz_enforced"]; !ok || s.Severity != "p3" {
		t.Fatalf("enforcement should be recorded as informational, got %+v", kinds)
	}
}

func TestDifferentialNotesPartialDisclosure(t *testing.T) {
	// Same status either way, different body. The endpoint answers anonymously and decides what to
	// show rather than whether to answer, which is where partial disclosure hides.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.Header.Get("Cookie"), "session=valid") {
			fmt.Fprint(w, `{"items":[1,2,3],"private":"yes","extra":"lots more content here"}`)
			return
		}
		fmt.Fprint(w, `{"items":[1]}`)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	sigs, _ := RunTier1(context.Background(), budget, auth, DefaultTier1Config(),
		[]Tier1Target{{
			EndpointID: "e1", URL: srv.URL + "/api/items", Score: 50,
			Status: validationStatusValid, ContentType: "application/json", Authenticated: true,
		}}, ResponseFingerprint{}, false, nil)

	if _, ok := sigKinds(sigs["e1"])["authz_same_status_different_body"]; !ok {
		t.Fatalf("expected the partial-disclosure signal, got %+v", sigs["e1"])
	}
}

func TestDifferentialIsSkippedWhenTheRunHasNoCredentials(t *testing.T) {
	// Both arms would be anonymous, so the comparison is meaningless and the request is wasted.
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.RunHostProbes = false
	cfg.RunMethods = false
	cfg.RunCORS = false

	RunTier1(context.Background(), budget, auth, cfg, []Tier1Target{{
		EndpointID: "e1", URL: srv.URL + "/x", Score: 10,
		Status: validationStatusValid, Authenticated: false, // Tier 0 had no credentials
	}}, ResponseFingerprint{}, false, nil)

	if atomic.LoadInt32(&hits) != 0 {
		t.Fatalf("no request should be spent on a differential that cannot mean anything, sent %d", hits)
	}
}

func TestDifferentialIsSkippedForEndpointsValidateRuledOut(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.RunHostProbes, cfg.RunMethods, cfg.RunCORS = false, false, false

	RunTier1(context.Background(), budget, auth, cfg, []Tier1Target{{
		EndpointID: "e1", URL: srv.URL + "/x", Score: 10,
		Status: validationStatusRuledOut, Authenticated: true,
	}}, ResponseFingerprint{}, false, nil)

	if atomic.LoadInt32(&hits) != 0 {
		t.Fatal("comparing two fetches of a catch-all page says nothing about authorization")
	}
}

// ---- CORS ---------------------------------------------------------------------------------------

func TestCORSReflectionWithCredentialsIsP0(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin) // echoes anything
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.RunDifferential, cfg.RunHostProbes, cfg.RunMethods = false, false, false

	sigs, _ := RunTier1(context.Background(), budget, auth, cfg, []Tier1Target{{
		EndpointID: "e1", URL: srv.URL + "/api/data", Score: 50,
		Status: validationStatusValid, ContentType: "application/json",
	}}, ResponseFingerprint{}, false, nil)

	s := sigKinds(sigs["e1"])["cors_origin_reflected"]
	if s.Kind == "" {
		t.Fatalf("an echoed Origin must be reported, got %+v", sigs["e1"])
	}
	if s.Severity != "p0" {
		t.Errorf("echoing an arbitrary origin WITH credentials lets any site read this, expected p0, got %s", s.Severity)
	}
}

func TestCORSProbeUsesAnUnregistrableOrigin(t *testing.T) {
	// The probe origin must be a host nobody can ever own. .invalid is reserved by RFC 6761.
	if !strings.HasSuffix(corsProbeOrigin, ".invalid") {
		t.Fatalf("the CORS probe origin must be unregistrable, got %q", corsProbeOrigin)
	}
}

func TestCORSStaysQuietWhenTheServerDoesNotEcho(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.RunDifferential, cfg.RunHostProbes, cfg.RunMethods = false, false, false

	sigs, _ := RunTier1(context.Background(), budget, auth, cfg, []Tier1Target{{
		EndpointID: "e1", URL: srv.URL + "/api/data", Score: 50,
		Status: validationStatusValid, ContentType: "application/json",
	}}, ResponseFingerprint{}, false, nil)

	if _, bad := sigKinds(sigs["e1"])["cors_origin_reflected"]; bad {
		t.Fatal("a fixed allowlist is not a reflection and must not be reported as one")
	}
}

// ---- method surface -------------------------------------------------------------------------------

func TestOptionsRevealsWriteVerbsWithoutSendingThem(t *testing.T) {
	var sentVerbs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sentVerbs = append(sentVerbs, r.Method)
		w.Header().Set("Allow", "GET, HEAD, OPTIONS, PUT, DELETE")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(204)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.RunDifferential, cfg.RunHostProbes, cfg.RunCORS = false, false, false

	sigs, _ := RunTier1(context.Background(), budget, auth, cfg, []Tier1Target{{
		EndpointID: "e1", URL: srv.URL + "/api/keys/7", Score: 50,
		Status: validationStatusValid, ContentType: "application/json",
	}}, ResponseFingerprint{}, false, nil)

	if _, ok := sigKinds(sigs["e1"])["method_write_surface"]; !ok {
		t.Fatalf("advertised write verbs are a lead worth recording, got %+v", sigs["e1"])
	}
	for _, v := range sentVerbs {
		if v == "PUT" || v == "DELETE" || v == "POST" || v == "PATCH" {
			t.Fatalf("a write verb was actually sent at the target: %s", v)
		}
	}
}

// ---- budget ---------------------------------------------------------------------------------------

func TestTier1StopsAtItsRequestCeilingAndSaysSo(t *testing.T) {
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.MaxRequests = 6
	cfg.RunHostProbes, cfg.RunMethods, cfg.RunCORS = false, false, false

	var targets []Tier1Target
	for i := 0; i < 50; i++ {
		targets = append(targets, Tier1Target{
			EndpointID: fmt.Sprintf("e%d", i), URL: fmt.Sprintf("%s/x%d", srv.URL, i),
			Score: i, Status: validationStatusValid, Authenticated: true,
		})
	}

	_, notes := RunTier1(context.Background(), budget, auth, cfg, targets, ResponseFingerprint{}, false, nil)

	if got := atomic.LoadInt32(&hits); got > 8 {
		t.Fatalf("the ceiling was 6 requests, the server saw %d", got)
	}
	if len(notes) == 0 || !strings.Contains(strings.Join(notes, " "), "not probed") {
		t.Fatalf("a truncated tier must disclose what it skipped, notes: %v", notes)
	}
}

func TestTier1RunsHighestScoringEndpointsFirst(t *testing.T) {
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		order = append(order, r.URL.Path)
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.MaxRequests = 4
	cfg.RunHostProbes, cfg.RunMethods, cfg.RunCORS = false, false, false

	targets := []Tier1Target{
		{EndpointID: "low", URL: srv.URL + "/boring", Score: 1, Status: validationStatusValid, Authenticated: true},
		{EndpointID: "high", URL: srv.URL + "/interesting", Score: 900, Status: validationStatusValid, Authenticated: true},
	}
	RunTier1(context.Background(), budget, auth, cfg, targets, ResponseFingerprint{}, false, nil)

	if len(order) == 0 || order[0] != "/interesting" {
		t.Fatalf("a truncated run must spend its requests on the interesting endpoints first, order: %v", order)
	}
}

func TestHostProbesRunOncePerHostNotPerEndpoint(t *testing.T) {
	var robots int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			atomic.AddInt32(&robots, 1)
			fmt.Fprint(w, "User-agent: *\nDisallow: /admin\nDisallow: /internal\n")
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	host := hostOf(srv.URL)
	budget, auth := tier1Ctx(host)
	cfg := DefaultTier1Config()
	cfg.RunDifferential, cfg.RunMethods, cfg.RunCORS = false, false, false

	var targets []Tier1Target
	for i := 0; i < 10; i++ {
		targets = append(targets, Tier1Target{
			EndpointID: fmt.Sprintf("e%d", i), URL: fmt.Sprintf("%s/p%d", srv.URL, i),
			Score: 1, Status: validationStatusValid,
		})
	}
	sigs, _ := RunTier1(context.Background(), budget, auth, cfg, targets, ResponseFingerprint{}, false, nil)

	if got := atomic.LoadInt32(&robots); got != 1 {
		t.Fatalf("robots.txt is the same answer for every endpoint on a host, fetched %d times", got)
	}
	s := sigKinds(sigs["host:"+host])["host_robots"]
	if !strings.Contains(s.Evidence, "/admin") {
		t.Errorf("Disallow entries name the paths the operator did not want found: %q", s.Evidence)
	}
}

func TestSourcemapIsNeverFetchedCrossOrigin(t *testing.T) {
	// Chasing a source map reference off-origin would send a request to a host the operator never
	// put in scope.
	if got := resolveAgainst("https://target.test/app.js", "https://evil.test/app.js.map"); got != "" {
		t.Fatalf("a cross-origin source map must not be fetched, resolved to %q", got)
	}
	if got := resolveAgainst("https://target.test/static/app.js", "app.js.map"); got != "https://target.test/static/app.js.map" {
		t.Fatalf("a same-origin relative map should resolve, got %q", got)
	}
}
