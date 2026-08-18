package utils

import (
	"strings"
	"testing"
)

// Identity is what decides whether 4,000 rows are 4,000 endpoints or 400. Every case here is one
// the six discovery sources actually produce.

func key(t *testing.T, raw, method string) EndpointIdentity {
	t.Helper()
	id, ok := CanonicalizeEndpoint(raw, method, "https")
	if !ok {
		t.Fatalf("canonicalize refused %q", raw)
	}
	return id
}

func TestSchemeIsNotIdentity(t *testing.T) {
	// gau returns http:// and katana returns https:// for the same resource. Two rows for one
	// endpoint doubles every count on the card.
	a := key(t, "http://target.test/admin", "GET")
	b := key(t, "https://target.test/admin", "GET")
	if a.Key != b.Key {
		t.Fatalf("http and https must be one endpoint: %s vs %s", a.Key, b.Key)
	}
}

func TestExplicitDefaultPortIsNotIdentity(t *testing.T) {
	// The framework stores scope targets as https://host:443 while crawlers emit no port.
	a := key(t, "https://target.test:443/admin", "GET")
	b := key(t, "https://target.test/admin", "GET")
	if a.Key != b.Key {
		t.Fatal("an explicit :443 must not create a second endpoint")
	}
	c := key(t, "https://target.test:8443/admin", "GET")
	if c.Key == a.Key {
		t.Fatal("a non-default port is a different service and must stay distinct")
	}
}

func TestTrailingSlashAndDuplicateSlashesFold(t *testing.T) {
	a := key(t, "https://target.test/docs/", "GET")
	b := key(t, "https://target.test/docs", "GET")
	c := key(t, "https://target.test//docs", "GET")
	if a.Key != b.Key || b.Key != c.Key {
		t.Fatalf("these address one resource: %s %s %s", a.Key, b.Key, c.Key)
	}
}

func TestPathCaseIsIdentityBearing(t *testing.T) {
	// nginx denying /admin while an IIS origin serves /Admin is a real authorisation bypass.
	// Folding case here destroys the finding before anyone can see it.
	a := key(t, "https://target.test/admin", "GET")
	b := key(t, "https://target.test/Admin", "GET")
	if a.Key == b.Key {
		t.Fatal("path case must stay distinct; it is a proxy-vs-origin bypass primitive")
	}
	if a.CaseGroupKey != b.CaseGroupKey {
		t.Fatal("the two must still be linked by case_group_key so the pair is reportable")
	}
}

func TestIndexFilesAreLinkedNotMerged(t *testing.T) {
	a := key(t, "https://target.test/docs/index.html", "GET")
	b := key(t, "https://target.test/docs", "GET")
	if a.Key == b.Key {
		t.Fatal("index.html must not be folded into its directory")
	}
	if a.IndexSiblingOf != "/docs" {
		t.Fatalf("index sibling not recorded, got %q", a.IndexSiblingOf)
	}
}

func TestEncodedSlashIsNeverDecoded(t *testing.T) {
	// %2f is a path-traversal and ACL-bypass primitive. Decoding it merges the bypass into the
	// thing it bypasses.
	a := key(t, "https://target.test/api/user%2f..%2fadmin", "GET")
	if !strings.Contains(a.CanonicalPath, "%2F") {
		t.Fatalf("encoded slash was decoded: %s", a.CanonicalPath)
	}
	b := key(t, "https://target.test/api/user/../admin", "GET")
	if a.Key == b.Key {
		t.Fatal("an encoded traversal and a real one are different requests")
	}
}

func TestDotSegmentsResolve(t *testing.T) {
	a := key(t, "https://target.test/a/b/../c", "GET")
	if a.CanonicalPath != "/a/c" {
		t.Fatalf("dot segments unresolved: %s", a.CanonicalPath)
	}
}

func TestTrackingParametersAreDropped(t *testing.T) {
	// One page shared on social media returns as hundreds of gau rows differing only in utm tags.
	a := key(t, "https://target.test/post?utm_source=twitter&utm_campaign=x&fbclid=abc", "GET")
	b := key(t, "https://target.test/post", "GET")
	if a.Key != b.Key {
		t.Fatal("tracking parameters must not create endpoints")
	}
	if len(a.DroppedParams) != 3 {
		t.Fatalf("the removal must stay auditable, dropped: %v", a.DroppedParams)
	}
}

func TestValueBearingParamsCollapseButIdentityBearingDoNot(t *testing.T) {
	// /search?q=shoes and /search?q=hats are one endpoint.
	a := key(t, "https://target.test/search?page=1", "GET")
	b := key(t, "https://target.test/search?page=2", "GET")
	if a.Key != b.Key {
		t.Fatal("a paging value must not fork the endpoint")
	}

	// /index.php?action=admin and ?action=home are not.
	c := key(t, "https://target.test/index.php?action=admin", "GET")
	d := key(t, "https://target.test/index.php?action=home", "GET")
	if c.Key == d.Key {
		t.Fatal("a router parameter selects the resource and is identity-bearing")
	}
}

func TestSPARouteIsIdentityBearingButAnchorIsNot(t *testing.T) {
	a := key(t, "https://target.test/app#/dashboard", "GET")
	b := key(t, "https://target.test/app#/settings", "GET")
	if a.Key == b.Key {
		t.Fatal("hash routes address different views")
	}
	c := key(t, "https://target.test/page#section-3", "GET")
	d := key(t, "https://target.test/page", "GET")
	if c.Key != d.Key {
		t.Fatal("a scroll anchor is the same page")
	}
}

func TestMethodIsIdentityBearing(t *testing.T) {
	a := key(t, "https://target.test/api/users", "GET")
	b := key(t, "https://target.test/api/users", "POST")
	if a.Key == b.Key {
		t.Fatal("endpoint+verb is the unit; GET and POST are different endpoints")
	}
}

func TestNonHTTPSchemesAreRejected(t *testing.T) {
	// linkfinder pulls these straight out of JavaScript.
	for _, raw := range []string{"mailto:a@b.test", "javascript:alert(1)",
		"data:text/html;base64,PGI+", "tel:+15551234"} {
		if _, ok := CanonicalizeEndpoint(raw, "GET", "https"); ok {
			t.Errorf("%q is not an endpoint and must be refused", raw)
		}
	}
}

func TestSchemeRelativeAndBareHostAdoptTheTargetScheme(t *testing.T) {
	// The previous implementation forced https:// onto everything, which broke http-only targets.
	a, ok := CanonicalizeEndpoint("//cdn.target.test/app.js", "GET", "http")
	if !ok || a.Scheme != "http" {
		t.Fatalf("scheme-relative must adopt the target scheme, got %q", a.Scheme)
	}
	b, ok := CanonicalizeEndpoint("target.test/admin", "GET", "http")
	if !ok || b.Scheme != "http" {
		t.Fatalf("bare host must adopt the target scheme, got %q", b.Scheme)
	}
}

func TestTemplatingGroupsIdentifiersWithoutLosingTheConcreteURL(t *testing.T) {
	a := key(t, "https://target.test/user/1001/profile", "GET")
	b := key(t, "https://target.test/user/2002/profile", "GET")
	if a.TemplateKey != b.TemplateKey {
		t.Fatal("numeric ids must group")
	}
	if a.Key == b.Key {
		t.Fatal("but the concrete endpoints stay separate; an IDOR needs both ids")
	}
	if a.TemplatedPath != "/user/{id}/profile" {
		t.Fatalf("templated path wrong: %s", a.TemplatedPath)
	}

	u := key(t, "https://target.test/o/3f2504e0-4f89-11d3-9a0c-0305e82c3301/x", "GET")
	if u.TemplatedPath != "/o/{id}/x" {
		t.Fatalf("uuid segment not templated: %s", u.TemplatedPath)
	}
}

func TestSlugsAreNotMistakenForIdentifiers(t *testing.T) {
	// /blog/how-to-secure-your-api is real surface, not an object id. Templating it away would
	// merge every article into one row and hide any that behaves differently.
	a := key(t, "https://target.test/blog/how-to-secure-your-api", "GET")
	if strings.Contains(a.TemplatedPath, "{id}") {
		t.Fatalf("a word slug must not be templated: %s", a.TemplatedPath)
	}
}

func TestFilenamesAreNotTemplated(t *testing.T) {
	a := key(t, "https://target.test/reports/2024.pdf", "GET")
	if strings.Contains(a.TemplatedPath, "{id}") {
		t.Fatalf("a numeric filename is a document: %s", a.TemplatedPath)
	}
}

func TestContentClassification(t *testing.T) {
	cases := map[string]string{
		"https://target.test/logo.png":     "static",
		"https://target.test/app.js":       "script",
		"https://target.test/api/v1/users": "api",
		"https://target.test/graphql":      "api",
		"https://target.test/data.json":    "api",
		"https://target.test/about":        "page",
	}
	for raw, want := range cases {
		if got := key(t, raw, "GET").ContentClass; got != want {
			t.Errorf("%s classified %q, want %q", raw, got, want)
		}
	}
}

func TestUserinfoIsStrippedAndFlagged(t *testing.T) {
	a := key(t, "https://admin:hunter2@target.test/panel", "GET")
	if strings.Contains(a.CanonicalURL, "hunter2") {
		t.Fatal("credentials must never survive into a stored URL")
	}
	if !a.Flags["had_userinfo"] {
		t.Fatal("the fact that credentials were present is itself worth recording")
	}
}

func TestControlCharactersAreRefused(t *testing.T) {
	if _, ok := CanonicalizeEndpoint("https://target.test/a\x00b", "GET", "https"); ok {
		t.Fatal("a NUL byte means a corrupted row, and Postgres will reject it downstream anyway")
	}
}

func TestDirectoryFamilyForControls(t *testing.T) {
	if got := EndpointDirectory("/api/v1/users"); got != "/api/v1" {
		t.Fatalf("directory wrong: %s", got)
	}
	if got := EndpointDirectory("/admin"); got != "/" {
		t.Fatalf("root directory wrong: %s", got)
	}
	if got := ExtensionClass("/data.json"); got != "data" {
		t.Fatalf("extension class wrong: %s", got)
	}
}
