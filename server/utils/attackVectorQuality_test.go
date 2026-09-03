package utils

import (
	"strings"
	"testing"
)

// Two defects measured on a real Juice Shop run, both of which made the vector list overstate what it
// covers. Everything asserted below is a number or a path taken from that run, not an invented case.

// THIRTY-ONE VECTORS ON NINE PATHS THAT ARE ONE ROUTE EACH.
//
// classifyInputValue only calls a run of digits an id at four digits or more, so every REST object the
// operator opened kept its own row: /api/Products/1, /api/Products/6 and /api/Products/24 were three
// vectors, and the route they share, which is the thing an operator actually tests, was not in the
// list at all.
func TestARestIdentifierCollapsesToOneRoute(t *testing.T) {
	first, signals := templateVectorPath("/api/Products/1")
	if first != "/api/Products/{id}" {
		t.Fatalf("a REST id was left literal, so every product is its own vector: %q", first)
	}
	if len(signals) == 0 || signals[0] != SignalNumericID {
		t.Errorf("the row does not say why it was templated: %v", signals)
	}
	for _, path := range []string{"/api/Products/6", "/api/Products/24", "/api/Products/12345"} {
		if got, _ := templateVectorPath(path); got != first {
			t.Errorf("%s templated to %q, which is a second vector for the same route", path, got)
		}
	}

	// Every ID-bearing path the run recorded literally, and the route each of them is.
	for path, want := range map[string]string{
		"/api/BasketItems/12":              "/api/BasketItems/{id}",
		"/api/Addresss/7":                  "/api/Addresss/{id}",
		"/api/Cards/8":                     "/api/Cards/{id}",
		"/api/Quantitys/1":                 "/api/Quantitys/{id}",
		"/rest/basket/6":                   "/rest/basket/{id}",
		"/rest/products/1/reviews":         "/rest/products/{id}/reviews",
		"/rest/basket/6/coupon/rs0nsdfsdf": "/rest/basket/{id}/coupon/rs0nsdfsdf",
	} {
		if got, _ := templateVectorPath(path); got != want {
			t.Errorf("%s -> %q, want %q", path, got, want)
		}
	}
}

// Different collections must not be merged by the same fix. /api/Products/1 and /api/Cards/1 are two
// routes and collapsing them would lose one.
func TestTemplatingAnIdKeepsTheCollectionApart(t *testing.T) {
	products, _ := templateVectorPath("/api/Products/1")
	cards, _ := templateVectorPath("/api/Cards/1")
	if products == cards {
		t.Fatalf("two collections collapsed into one route: %q", products)
	}
}

// THE OTHER DIRECTION, WHICH IS THE DANGEROUS ONE.
//
// /rest/admin/application-configuration was templated to /rest/admin/{token}. It is a fixed route
// name. It matched only because it is 25 characters of [A-Za-z-] with Shannon entropy 3.513, and its
// sibling /rest/admin/application-version, entropy 3.577, survived purely because it is 19 characters
// against a 20-character floor. The rule was measuring length rather than identity, so the pluralised
// name below is what the old rule would have merged into the same row as its sibling: one of two real
// admin routes would then never have been tested.
func TestAFixedRouteSegmentIsNotAnIdentifier(t *testing.T) {
	for _, path := range []string{
		"/rest/admin/application-configuration",
		"/rest/admin/application-versions",
		"/rest/admin/applicationConfiguration",
		"/rest/user/security-question",
		"/rest/continue-code-findIt",
	} {
		got, signals := templateVectorPath(path)
		if got != path {
			t.Errorf("route %s was templated away to %q, which merges it with its siblings", path, got)
		}
		if len(signals) != 0 {
			t.Errorf("%s reported %v, so it is being treated as an identifier", path, signals)
		}
	}

	// The two sibling admin routes stay two rows, which is the whole point.
	a, _ := templateVectorPath("/rest/admin/application-configuration")
	b, _ := templateVectorPath("/rest/admin/application-versions")
	if a == b {
		t.Fatalf("two admin routes collapsed into one vector: %q", a)
	}
}

// Real generated identifiers must still collapse, or the fix above has traded one defect for another.
func TestGeneratedIdentifiersStillCollapse(t *testing.T) {
	for _, c := range []struct{ path, want, signal string }{
		{"/users/user.dedc6ad0-1e5a-4b1f-9c33-2b7c6d0f4a11",
			"/users/user.{uuid}", SignalUUID},
		{"/global-wallet/v1/accounts/7c6a6574f0110dee9ab3f011",
			"/global-wallet/v1/accounts/{token}", SignalHighEntropy},
		{"/session/aB3xK9zQ1mR7tY2wL5nP",
			"/session/{token}", SignalHighEntropy},
	} {
		got, signals := templateVectorPath(c.path)
		if got != c.want {
			t.Errorf("%s -> %q, want %q", c.path, got, c.want)
		}
		if len(signals) == 0 || signals[0] != c.signal {
			t.Errorf("%s reported %v, want %s", c.path, signals, c.signal)
		}
	}
}

// The path rule is looser about digits than the VALUE rule on purpose, and the value rule must not
// drift with it: ?page=1 is a page number, and calling it an object id would put a numeric_id signal
// on most of the query list.
func TestTheLooserPathRuleDoesNotReachParameterValues(t *testing.T) {
	if kind := classifyInputValue("1"); kind != "" {
		t.Errorf("?page=1 now reads as %q, so ordinary numbers look like identifiers", kind)
	}
	if kind := classifyPathSegment("1", 1); kind != SignalNumericID {
		t.Errorf("a number under a collection segment is an id, got %q", kind)
	}
	// Nothing precedes a first segment to make it an id, so the four-digit floor still applies there.
	if kind := classifyPathSegment("2", 0); kind != "" {
		t.Errorf("a bare /2 root was templated as an id: %q", kind)
	}
	if kind := classifyPathSegment("12345", 0); kind != SignalNumericID {
		t.Errorf("the old four-digit rule was lost at position 0: %q", kind)
	}
}

// The Socket.IO handshake produced a header vector whose only parameter was "upgrade", the value the
// BROWSER writes to ask for a WebSocket. It was one of only two distinct names in 43 header vectors.
func TestTheWebSocketHandshakeHeaderIsNotAnInput(t *testing.T) {
	names, _ := appHeaderInputs(
		`{"connection":"Upgrade","upgrade":"websocket","authorization":"Bearer ey.aa.bb","x-own":"1"}`)
	for _, name := range names {
		if name == "upgrade" {
			t.Fatalf("the WebSocket handshake header is being tested as user input: %v", names)
		}
	}
	// The two the application really does read are still there.
	if len(names) != 2 || names[0] != "authorization" || names[1] != "x-own" {
		t.Fatalf("an application header was dropped with it: %v", names)
	}
}

// SEVENTY-SEVEN COOKIE VECTORS ON FIFTY-FIVE ENDPOINTS.
//
// GET /, GET /api/Challenges/ and eight others each appeared three times, once per state of the
// browser's cookie jar: before the consent banner, after it, and after login. Each set is a strict
// subset of the next, so the largest already puts a payload in every name the other two would.
func TestAGrowingCookieJarIsOneVectorNotThree(t *testing.T) {
	base := attackVector{Method: "GET", Domain: "10.0.0.18", Port: 3000, Path: "/api/Challenges/",
		InsertionPoint: "cookie"}
	jars := [][]string{
		{"continueCode", "language", "welcomebanner_status"},
		{"continueCode", "cookieconsent_status", "language", "welcomebanner_status"},
		{"continueCode", "cookieconsent_status", "language", "token", "welcomebanner_status"},
	}
	group := []attackVector{}
	for _, jar := range jars {
		v := base
		v.Parameters = jar
		group = append(group, v)
	}

	kept := maximalAmbientObservations(group)
	if len(kept) != 1 {
		t.Fatalf("the same endpoint kept %d cookie vectors for one jar that grew during the crawl",
			len(kept))
	}
	if len(kept[0].Parameters) != 5 {
		t.Fatalf("the row kept is not the one that covers every name: %v", kept[0].Parameters)
	}
	// Dropped, never unioned: these rows carry parameters_origin 'observed'.
	for _, name := range kept[0].Parameters {
		if !contains(jars[2], name) { // package helper from endpointConsolidationUtils.go
			t.Errorf("%q was never sent together with the rest, so the row is a fabricated set", name)
		}
	}
}

// A capture repeated with the identical jar must leave one row, not zero. Equal sets contain each
// other, so without a tie-break every row is dropped by the row beside it and the endpoint loses its
// cookie vector entirely.
func TestIdenticalJarsLeaveExactlyOneVector(t *testing.T) {
	v := attackVector{Method: "GET", Domain: "10.0.0.18", Path: "/", InsertionPoint: "cookie",
		Parameters: []string{"language", "token"}}
	kept := maximalAmbientObservations([]attackVector{v, v, v})
	if len(kept) != 1 {
		t.Fatalf("three identical jars left %d rows, want 1", len(kept))
	}
}

// Two jars neither of which contains the other are two real observations and both are kept. Reporting
// only one, or unioning them, would claim a combination that was never sent.
func TestIncomparableJarsAreBothKept(t *testing.T) {
	base := attackVector{Method: "GET", Domain: "10.0.0.18", Path: "/", InsertionPoint: "cookie"}
	a, b := base, base
	a.Parameters = []string{"language", "token"}
	b.Parameters = []string{"language", "continueCode"}
	if kept := maximalAmbientObservations([]attackVector{a, b}); len(kept) != 2 {
		t.Fatalf("an observation was lost or invented: %d rows kept, want 2", len(kept))
	}
}

// THE IDENTITY IS NOT UP FOR NEGOTIATION. The same cookie jar on two endpoints is two vectors,
// because a payload in that cookie has to be sent to each of them and they will not answer alike.
// The grouping key above must never reach across a path, a verb, a host or an insertion point.
func TestTheSameJarOnTwoEndpointsStaysTwoVectors(t *testing.T) {
	base := attackVector{Method: "GET", Domain: "10.0.0.18", Port: 3000, InsertionPoint: "cookie",
		Parameters: []string{"language", "token"}}
	a, b := base, base
	a.Path, b.Path = "/rest/user/whoami", "/api/Challenges/"

	if ambientVectorGroupKey(a) == ambientVectorGroupKey(b) {
		t.Fatal("two endpoints share an ambient group, so one would swallow the other")
	}
	if kept := maximalAmbientObservations([]attackVector{a, b}); len(kept) != 2 {
		t.Fatalf("two endpoints collapsed to %d vector(s); that is a redefinition of identity", len(kept))
	}
	if a.key() == b.key() {
		t.Fatal("vector identity no longer includes the path")
	}

	// Verb, host and insertion point are each part of the group as well.
	for _, mutate := range []func(v *attackVector){
		func(v *attackVector) { v.Method = "POST" },
		func(v *attackVector) { v.Domain = "other.example.com" },
		func(v *attackVector) { v.Port = 8443 },
		func(v *attackVector) { v.InsertionPoint = "header" },
	} {
		c := a
		mutate(&c)
		if ambientVectorGroupKey(c) == ambientVectorGroupKey(a) {
			t.Errorf("the ambient group key ignores a component of identity: %+v", c)
		}
	}
}

// The whole batch, in the shape the run produced it: ten endpoints each captured in all three jar
// states, interleaved as the crawl saw them rather than grouped. Thirty held observations, ten rows.
func TestTheWholeAmbientBatchCollapsesPerEndpointOnly(t *testing.T) {
	jars := [][]string{
		{"continueCode", "language", "welcomebanner_status"},
		{"continueCode", "cookieconsent_status", "language", "welcomebanner_status"},
		{"continueCode", "cookieconsent_status", "language", "token", "welcomebanner_status"},
	}
	paths := []string{"/", "/api/Challenges/", "/api/Quantitys/", "/assets/i18n/en.json",
		"/rest/admin/application-version", "/rest/admin/{token}", "/socket.io/", "/rest/languages",
		"/rest/products/search", "/rest/user/whoami"}

	var held []attackVector
	for _, jar := range jars { // jar state outermost: the order the operator browsed in
		for _, path := range paths {
			held = append(held, attackVector{Method: "GET", Domain: "10.0.0.18", Port: 3000,
				Path: path, InsertionPoint: "cookie", Parameters: jar})
		}
	}

	kept := maximalAmbientObservations(held)
	if len(kept) != len(paths) {
		t.Fatalf("%d observations left %d rows, want one per endpoint (%d)",
			len(held), len(kept), len(paths))
	}
	seen := map[string]bool{}
	for _, v := range kept {
		if seen[v.Path] {
			t.Errorf("%s kept more than one row", v.Path)
		}
		seen[v.Path] = true
		if len(v.Parameters) != 5 {
			t.Errorf("%s kept the %d-name jar rather than the one that covers every name",
				v.Path, len(v.Parameters))
		}
	}
	for _, path := range paths {
		if !seen[path] {
			t.Errorf("%s lost its cookie vector entirely", path)
		}
	}
}

// THE WIRING, WHICH IS WHERE THIS NEARLY GOT AWAY. A mutation that sent every cookie and header
// observation straight to the database passed all of the tests above, because they reach the
// subsumption rule directly and nothing reached the CALL to it. So this asserts the routing: which
// bucket each insertion point lands in, on one capture.
func TestCookiesAndHeadersAreHeldAndNothingElseIs(t *testing.T) {
	capture := manualCrawlCapture{
		Method: "POST", URL: "http://10.0.0.18:3000/rest/products/1/reviews?d=1",
		GetParams:  `{"d":"1"}`,
		PostParams: `{"author":"a","message":"m"}`,
		Headers: `{"cookie":"language=en; token=eyJhbGciOi.aaaaaa.bbbbbb","authorization":"Bearer x",` +
			`"user-agent":"Mozilla/5.0","content-type":"application/json"}`,
		PostData: `{"author":"a","message":"m"}`, BodyType: "application/json",
		ResponseHeaders: `{}`,
	}

	immediate, ambient, ok := manualCrawlCaptureVectors(capture)
	if !ok {
		t.Fatal("a well-formed capture produced no vectors at all")
	}

	got := map[string]int{}
	for _, v := range immediate {
		got["immediate:"+v.InsertionPoint]++
	}
	for _, v := range ambient {
		got["ambient:"+v.InsertionPoint]++
	}
	for _, want := range []string{"immediate:query", "immediate:body", "immediate:path",
		"ambient:cookie", "ambient:header"} {
		if got[want] != 1 {
			t.Errorf("%s: got %d, want 1 (buckets were %v)", want, got[want], got)
		}
	}
	// The two the browser fills must NOT be stored on sight, or the jar is recorded once per capture
	// and the subsumption rule never sees them.
	for _, unwanted := range []string{"immediate:cookie", "immediate:header",
		"ambient:query", "ambient:body", "ambient:path"} {
		if got[unwanted] != 0 {
			t.Errorf("%s should not exist: %v", unwanted, got)
		}
	}
	// And the path was templated on the way through, so the review route is one vector rather than
	// one per product.
	for _, v := range immediate {
		if v.Path != "/rest/products/{id}/reviews" {
			t.Errorf("the capture kept a literal product id: %q", v.Path)
		}
	}
}

// A cookie the SERVER set from a request parameter must be stored on sight. It is not an observation
// of the ambient jar, and holding it would let the jar's larger set swallow the one cookie vector on
// the row worth having: on the target this framework was developed against that cookie was a second
// injection carrier for the one input with confirmed SQL injection.
func TestAServerSetCookieIsNotHeldWithTheJar(t *testing.T) {
	capture := manualCrawlCapture{
		Method: "GET", URL: "https://ginandjuice.shop/catalog?category=Gifts",
		GetParams: `{"category":"Gifts"}`, PostParams: `{}`,
		Headers:         `{"cookie":"session=abc; category=Gifts; TrackingId=xyz"}`,
		ResponseHeaders: `{"set-cookie":"category=Gifts; Path=/"}`,
	}

	immediate, ambient, ok := manualCrawlCaptureVectors(capture)
	if !ok {
		t.Fatal("the capture produced no vectors")
	}

	echoed := false
	for _, v := range immediate {
		if v.InsertionPoint == "cookie" && len(v.Parameters) == 1 && v.Parameters[0] == "category" {
			echoed = true
		}
	}
	if !echoed {
		t.Fatal("the server-set cookie was not stored on sight, so the jar's larger set swallows it")
	}
	// The jar itself is still held, and it does contain "category", which is exactly why the echoed
	// row had to travel by the other route.
	if len(ambient) != 1 || !ambientNameSet(ambient[0])["category"] {
		t.Fatalf("the ambient jar is not what this test assumes: %+v", ambient)
	}
	// And the counterfactual, which is the reason for the split. Held together with the jar, the
	// echoed cookie is a subset of it and is dropped, leaving one row and losing the only cookie
	// vector on this capture that is attacker-controlled rather than ambient.
	var bothHeld []attackVector
	bothHeld = append(bothHeld, ambient...)
	for _, v := range immediate {
		if v.InsertionPoint == "cookie" {
			bothHeld = append(bothHeld, v)
		}
	}
	if len(bothHeld) != 2 {
		t.Fatalf("expected a jar row and an echoed row to compare, got %d", len(bothHeld))
	}
	if kept := maximalAmbientObservations(bothHeld); len(kept) != 1 {
		t.Fatalf("the counterfactual no longer holds: holding both left %d rows, so this test is no "+
			"longer testing anything", len(kept))
	}
}

// The count on its own reads as input variety and is not. 77 cookie vectors carrying five names means
// a clean result rules out five things, and the number invites the reader to believe it ruled out 77.
func TestAReplicatedInsertionPointSaysSoInWords(t *testing.T) {
	note := attackVectorDiversityNote(attackVectorPointDiversity{
		InsertionPoint: "cookie", Vectors: 77, Endpoints: 55, DistinctNames: 5})
	if note == "" {
		t.Fatal("77 cookie vectors carrying 5 names were reported as a bare count")
	}
	for _, want := range []string{"77", "5", "55", "cookie"} {
		if !strings.Contains(note, want) {
			t.Errorf("the note leaves out %q: %s", want, note)
		}
	}

	// A list where most names appear once or twice is not replication and must stay quiet, or the
	// warning is on every row and means nothing.
	if n := (attackVectorDiversityNote(attackVectorPointDiversity{
		InsertionPoint: "body", Vectors: 41, Endpoints: 31, DistinctNames: 55})); n != "" {
		t.Errorf("an ordinary body list was flagged as replicated: %s", n)
	}
	// Path vectors carry no parameter name by construction; that is not a finding.
	if n := (attackVectorDiversityNote(attackVectorPointDiversity{
		InsertionPoint: "path", Vectors: 10, Endpoints: 10})); n != "" {
		t.Errorf("path vectors were flagged for having no parameter names: %s", n)
	}
}
