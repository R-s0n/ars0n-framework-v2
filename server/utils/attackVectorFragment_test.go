package utils

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// The four shapes a fragment comes in, and what each one has to become.
//
// Written as a table because the distinction between them is the whole feature: an anchor and an
// implicit-grant fragment are both "a hash on a URL" and are triaged completely differently, and if
// parseFragment ever collapses them the row stops carrying the fact that matters.
func TestParseFragmentShapes(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantOK    bool
		wantRoute string
		wantNames []string
		wantKind  string
	}{
		{
			name: "hash slash route", in: "#/dashboard/overview", wantOK: true,
			wantRoute: "/dashboard/overview", wantKind: fragmentKindRoute,
		},
		{
			name: "hashbang route", in: "!/users/settings", wantOK: true,
			wantRoute: "!/users/settings", wantKind: fragmentKindRoute,
		},
		{
			// The identifier collapses, or a crawl of fifty orders puts fifty rows in the list.
			name: "route identifier is templated", in: "#/orders/12345", wantOK: true,
			wantRoute: "/orders/{id}", wantKind: fragmentKindRoute,
		},
		{
			name: "route with its own query", in: "#/connect/edit?token=abc&tab=scopes", wantOK: true,
			wantRoute: "/connect/edit", wantNames: []string{"token", "tab"},
			wantKind: fragmentKindRoute,
		},
		{
			// The OAuth implicit grant. No route, no question mark, key=value pairs: the fragment IS
			// the parameter list, and the reason the flow uses a fragment at all is so the token
			// never reaches the server.
			name: "implicit grant", in: "#access_token=ey.aa.bb&token_type=bearer&expires_in=3600",
			wantOK: true, wantRoute: "",
			wantNames: []string{"access_token", "token_type", "expires_in"},
			wantKind:  fragmentKindImplicit,
		},
		{
			// A scroll anchor is still a vector: client code reads location.hash whether or not a
			// developer meant it as a route. It is NOT templated, because #2024 addresses a place on
			// the page and #{id} would merge it with every other numeric anchor.
			name: "scroll anchor", in: "#billing", wantOK: true,
			wantRoute: "billing", wantKind: fragmentKindAnchor,
		},
		{name: "empty", in: "", wantOK: false},
		{name: "bare hash", in: "#", wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseFragment(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got.Route != tc.wantRoute {
				t.Errorf("route = %q, want %q", got.Route, tc.wantRoute)
			}
			if got.Kind != tc.wantKind {
				t.Errorf("kind = %q, want %q", got.Kind, tc.wantKind)
			}
			if len(tc.wantNames) == 0 && len(got.Names) != 0 {
				t.Errorf("names = %v, want none", got.Names)
			}
			for _, want := range tc.wantNames {
				found := false
				for _, n := range got.Names {
					if n == want {
						found = true
					}
				}
				if !found {
					t.Errorf("name %q missing from %v", want, got.Names)
				}
			}
		})
	}
}

// A bearer token in a fragment has to be visible AS a token, or the row reads like a tab name and
// nobody looks at it. The implicit grant is the case this exists for.
func TestFragmentCarriesValueSignals(t *testing.T) {
	got, ok := parseFragment("#access_token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln&state=abc")
	if !ok {
		t.Fatal("an implicit-grant fragment produced nothing")
	}
	if len(got.Signals) == 0 {
		t.Fatalf("a JWT in the fragment produced no signal at all: %+v", got)
	}
	found := false
	for _, s := range got.Signals {
		if s == SignalJWT {
			found = true
		}
	}
	if !found {
		t.Errorf("signals = %v, want one of them to be %q", got.Signals, SignalJWT)
	}
}

// A malformed percent escape must cost that ONE pair and nothing else.
//
// This is why url.ParseQuery is not used here: it fails the whole string, so a single stray percent
// sign written by client code that was never required to encode anything would silently drop every
// name in an OAuth callback and the vector would claim no parameters at all.
func TestFragmentSurvivesABadEscape(t *testing.T) {
	names, _ := fragmentQueryInputs("access_token=abc&bad=100%&state=xyz")
	for _, want := range []string{"access_token", "bad", "state"} {
		found := false
		for _, n := range names {
			if n == want {
				found = true
			}
		}
		if !found {
			t.Errorf("name %q lost to a bad escape: got %v", want, names)
		}
	}
}

// Two fragments on ONE path are two vectors, and the same fragment twice is one.
//
// #/billing and #/profile are two client-side views; a payload read in one says nothing about the
// other. Without the fragment in the key they would share an identity and the second would be
// swallowed as a repeat sighting of the first.
func TestFragmentVectorsOnOnePathStayApart(t *testing.T) {
	base := attackVector{Method: "GET", Domain: "app.example.com", Path: "/settings"}

	billing, _ := fragmentVectorFrom(base, "/billing")
	profile, _ := fragmentVectorFrom(base, "/profile")
	again, _ := fragmentVectorFrom(base, "/billing")

	if billing.key() == profile.key() {
		t.Error("two different client routes on one path collapsed into one vector")
	}
	if billing.key() != again.key() {
		t.Error("the same client route seen twice produced two vectors")
	}

	// And an identifier inside the route still collapses, because the route is templated first.
	one, _ := fragmentVectorFrom(base, "/orders/12345")
	two, _ := fragmentVectorFrom(base, "/orders/67890")
	if one.key() != two.key() {
		t.Error("two orders under one client route did not collapse; the route is not being templated")
	}
}

// A fragment vector must not collide with the query vector for the same path, and no EXISTING key
// may change.
//
// The second half is the one that would have hurt. The fragment joins the key only when it is
// non-empty: appending an empty component unconditionally would have rehashed every row already in
// the database, orphaning all 230 vectors measured on the live target behind keys nothing computes
// any more and re-inserting each of them under a new identity on the next consolidation.
func TestFragmentKeyIsAdditiveOnly(t *testing.T) {
	query := attackVector{Method: "GET", Domain: "app.example.com", Path: "/settings",
		InsertionPoint: "query", Parameters: []string{"tab"}}
	fragment := attackVector{Method: "GET", Domain: "app.example.com", Path: "/settings",
		InsertionPoint: "fragment", Fragment: "/billing", Parameters: []string{"tab"}}
	if query.key() == fragment.key() {
		t.Error("a fragment vector collided with the query vector on the same path")
	}

	// The exact hash a PRE-CHANGE row has, pinned rather than recomputed, because recomputing it with
	// the current code would agree with itself no matter what the code did. Produced by the
	// pre-change expression on 2026-09-17, sha256 over method, host, path, insertion point and the
	// parameter set, NUL separated, with no sixth component:
	//
	//	sha256("GET\x00app.example.com\x00/settings\x00query\x00tab")
	const legacyKey = "823e757222553d80638db03edc7df25d69198d72bb77f5beec6ad8bbd4c7aef9"
	if query.key() != legacyKey {
		t.Errorf("the key of a vector with no fragment changed: got %s, want %s. Every row already "+
			"stored is now unreachable, and consolidation will insert a duplicate of each of them.",
			query.key(), legacyKey)
	}
}

// The routing: a captured URL with a fragment must produce a fragment vector in the IMMEDIATE
// bucket, alongside the query and body vectors and not held with the ambient ones.
//
// Held here for the reason the comment on manualCrawlCaptureVectors gives: a builder is easy to
// cover and the wiring is not, and the wiring is where the last two defects in this file lived.
func TestCaptureWithAFragmentProducesAFragmentVector(t *testing.T) {
	capture := manualCrawlCapture{
		Method: "GET", URL: "https://app.example.com/settings?tab=general#/billing?invoice=42",
		GetParams: `{"tab":"general"}`, PostParams: `{}`,
		Headers:  `{"cookie":"sid=abc","user-agent":"Mozilla/5.0"}`,
		BodyType: "", ResponseHeaders: `{}`,
	}

	immediate, ambient, ok := manualCrawlCaptureVectors(capture)
	if !ok {
		t.Fatal("a well-formed capture produced no vectors at all")
	}

	var frag *attackVector
	for i := range immediate {
		if immediate[i].InsertionPoint == "fragment" {
			frag = &immediate[i]
		}
	}
	if frag == nil {
		t.Fatalf("no fragment vector in the immediate bucket: %v", insertionPointsOf(immediate))
	}
	for _, v := range ambient {
		if v.InsertionPoint == "fragment" {
			t.Error("a fragment was held with the ambient jar; it is not something the browser attached")
		}
	}
	if frag.Fragment != "/billing" {
		t.Errorf("fragment = %q, want %q", frag.Fragment, "/billing")
	}
	if !reflect.DeepEqual(frag.Parameters, []string{"invoice"}) {
		t.Errorf("parameters = %v, want [invoice]", frag.Parameters)
	}
	// The query parameter lives in the QUERY vector. A fragment vector claiming it would say a
	// payload in tab is a client-side one, which it is not.
	for _, name := range frag.Parameters {
		if name == "tab" {
			t.Error("the fragment vector claimed the query string's parameter")
		}
	}
	if frag.InsertionConfidence != "observed" {
		t.Errorf("insertion_confidence = %q; a fragment is seen by a browser or not at all",
			frag.InsertionConfidence)
	}
}

// A URL with no fragment must produce no fragment vector.
//
// Stated as a test because the alternative shape, emitting a fragment slot for every URL on the
// grounds that every URL has one, would have produced a row per endpoint carrying no evidence that
// anything reads it. The count on a target with no observed fragments has to be zero.
func TestCaptureWithoutAFragmentProducesNone(t *testing.T) {
	capture := manualCrawlCapture{
		Method: "GET", URL: "https://app.example.com/dashboard/overview?tab=positions",
		GetParams: `{"tab":"positions"}`, PostParams: `{}`,
		Headers: `{"user-agent":"Mozilla/5.0"}`, ResponseHeaders: `{}`,
	}
	immediate, ambient, ok := manualCrawlCaptureVectors(capture)
	if !ok {
		t.Fatal("a well-formed capture produced no vectors at all")
	}
	for _, v := range append(append([]attackVector{}, immediate...), ambient...) {
		if v.InsertionPoint == "fragment" {
			t.Fatalf("a URL with no fragment produced a fragment vector: %+v", v)
		}
	}
}

// A fragment on a static asset is not input. Nothing parses the hash of a script URL.
func TestStaticAssetGetsNoFragmentVector(t *testing.T) {
	capture := manualCrawlCapture{
		Method: "GET", URL: "https://app.example.com/static/js/main.4f2a.js#sourceMappingURL",
		GetParams: `{}`, PostParams: `{}`, Headers: `{"user-agent":"Mozilla/5.0"}`,
		ResponseHeaders: `{}`,
	}
	immediate, _, _ := manualCrawlCaptureVectors(capture)
	for _, v := range immediate {
		if v.InsertionPoint == "fragment" {
			t.Errorf("a .js URL produced a fragment vector: %+v", v)
		}
	}
}

// THE ORDER THE URL IS REBUILT IN, which is the difference between testing the fragment and testing
// the query string.
//
// /settings#/billing?tab=x puts tab=x INSIDE the fragment, where no server sees it.
// /settings?tab=x#/billing is a query parameter and a client route. domdig is handed one string and
// cannot report that it was given the wrong one.
func TestFragmentTargetURLPutsTheHashLast(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/settings",
		InsertionPoint: "fragment", Fragment: "/billing",
		EvidenceURL: "https://app.example.com/settings?tab=general#/billing",
	}
	got := v.TargetURL()
	want := "https://app.example.com/settings?tab=general#/billing"
	if got != want {
		t.Errorf("TargetURL() = %q, want %q", got, want)
	}
	if strings.Index(got, "#") < strings.Index(got, "?") {
		t.Errorf("the hash came before the query string, so the query is inside the fragment: %q", got)
	}
}

// Only domdig may claim the fragment, and every HTTP tool must refuse it with a reason that says
// nothing was missed.
//
// This is the assertion that stops the whole feature becoming a liability. A fragment vector handed
// to sqlmap would be scanned, exit 0, and be recorded as a clean test of a container sqlmap cannot
// reach. Same failure the eligibility layer was written for, one insertion point later.
func TestOnlyDomdigReachesTheFragment(t *testing.T) {
	domdig, ok := VectorToolByKey("domdig")
	if !ok {
		t.Fatal("domdig is not registered")
	}
	if !VectorToolCanReach(domdig, "fragment") {
		t.Error("domdig fuzzes the hash and must be able to reach a fragment vector")
	}

	claimed := []string{}
	for _, tool := range vectorRegistry {
		if tool.Key == "domdig" {
			continue
		}
		if VectorToolCanReach(tool, "fragment") {
			claimed = append(claimed, tool.Key)
			continue
		}
		reason := vectorSkipReason(tool, "fragment")
		if !strings.Contains(strings.ToLower(reason), "fragment") {
			t.Errorf("%s refuses a fragment without saying so: %q", tool.Key, reason)
		}
	}
	if len(claimed) > 0 {
		t.Errorf("these tools speak HTTP and cannot put a payload in a fragment, but claim they "+
			"can, so vectors would be handed to them and silently reported clean: %v", claimed)
	}
}

// insertionPointsOf is a test helper: what came out, in a form a failure message can print.
func insertionPointsOf(vectors []attackVector) []string {
	out := []string{}
	for _, v := range vectors {
		out = append(out, v.InsertionPoint)
	}
	return out
}

// THE FRAGMENT HAS TO SURVIVE INTO THE ARGV, not just into the request preview.
//
// This is the test that was missing, and its absence let a fail-open back in one layer below the one
// it was removed from. TestFragmentTargetURLPutsTheHashLast covers a BARE ROUTE only, and a bare
// route is the one shape that happens to live entirely in v.Fragment. Every other shape puts its
// content in v.Parameters, the composer read only v.Fragment, and domdig was handed a URL with no
// hash on it at all: it navigated, found nothing, and the row was filed as a clean fragment test.
//
// So the assertion is made against ComposeDomdig rather than TargetURL. domdig is the only tool in
// the framework that reaches a fragment, its argv is what actually leaves this process, and asserting
// on the composed URL alone would not have caught the case where a later stage drops it.
func TestComposedArgvCarriesTheWholeFragment(t *testing.T) {
	const c = VectorCanary
	cases := []struct {
		name        string
		fragment    string
		parameters  []string
		evidenceURL string
		want        string
	}{
		{
			// The shape the old test covered. Kept here so the table is the full set.
			name: "bare route", fragment: "/billing",
			evidenceURL: "https://app.example.com/settings?tab=general#/billing",
			want:        "https://app.example.com/settings?tab=general#/billing",
		},
		{
			// A client route carrying its own query. The names live in Parameters and the old
			// composer dropped every one of them, so #/connect/edit?token=x&tab=y went out as
			// #/connect/edit and the two inputs the row exists for were never written.
			name: "route with its own query", fragment: "/connect/edit",
			parameters:  []string{"token", "tab"},
			evidenceURL: "https://app.example.com/app#/connect/edit?token=abc&tab=scopes",
			want:        "https://app.example.com/app#/connect/edit?token=" + c + "&tab=" + c,
		},
		{
			name: "scroll anchor", fragment: "billing",
			evidenceURL: "https://privatealps.net/dashboard/settings#billing",
			want:        "https://privatealps.net/dashboard/settings#billing",
		},
		{
			// The OAuth implicit grant, which is the case the insertion point exists for. Route is
			// empty and EVERY name is in Parameters, so the old composer produced a URL with no hash
			// whatsoever and domdig scanned the bare callback.
			name: "oauth implicit grant", fragment: "",
			parameters:  []string{"access_token", "token_type", "expires_in"},
			evidenceURL: "https://app.example.com/callback#access_token=ey&token_type=bearer",
			want: "https://app.example.com/callback#access_token=" + c +
				"&token_type=" + c + "&expires_in=" + c,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := VectorInput{
				Method: "GET", Scheme: "https", InsertionPoint: "fragment",
				Fragment: tc.fragment, Parameters: tc.parameters, EvidenceURL: tc.evidenceURL,
			}
			parsed := strings.SplitN(strings.TrimPrefix(tc.want, "https://"), "/", 2)
			v.Domain = parsed[0]
			v.Path = "/" + strings.SplitN(strings.SplitN(parsed[1], "?", 2)[0], "#", 2)[0]

			args, _ := ComposeDomdig(v, map[string]any{}, "")
			got := args[len(args)-1]
			if got != tc.want {
				t.Errorf("domdig argv URL = %q, want %q", got, tc.want)
			}
			// Split at the hash and check the halves separately, because the two ways this can be
			// wrong read identically in a diff. Everything BEFORE the hash is what the server is
			// asked for; everything after it is what only the browser sees.
			head, frag, found := strings.Cut(got, "#")
			wantHead, wantFrag, _ := strings.Cut(tc.want, "#")
			if !found || frag == "" {
				t.Errorf("domdig was handed a URL with NO FRAGMENT at all: %q", got)
			}
			if head != wantHead {
				t.Errorf("the part the server sees is %q, want %q: a query string that ended up "+
					"after the hash is never sent", head, wantHead)
			}
			if frag != wantFrag {
				t.Errorf("the fragment is %q, want %q", frag, wantFrag)
			}
		})
	}
}

// The preview and the composed URL have to agree, because the preview is what tells the operator
// what was sent. They disagreed: appendFragmentParts rendered #access_token=FUZZ&token_type=FUZZ
// under the request while the composer sent no hash at all, so the operator was shown a fragment the
// scanner never wrote. They now share fragmentSpans, and this asserts the sharing rather than
// trusting it.
//
// IT HAS TO CALL BOTH CALLERS, and an earlier version of this test did not. It compared
// fragmentSpans to fragmentString, which is DEFINED as the join of fragmentSpans, so it held
// whatever either caller did. Proved by mutation: appendFragmentParts was drifted back to its own
// renderer, emitting #/connect/edit&token=FUZZ while the composer sent ?token=, and the whole suite
// stayed green. A test that cannot fail pins nothing, which is the shape of the fail-open it was
// written to stop. This version starts at appendFragmentParts and VectorInput.TargetURL, the two
// functions that actually feed the operator and the tool.
func TestPreviewAndComposedFragmentAgree(t *testing.T) {
	cases := []attackVector{
		{InsertionPoint: "fragment", Fragment: "/billing"},
		{InsertionPoint: "fragment", Fragment: "/connect/edit", Parameters: []string{"token", "tab"}},
		{InsertionPoint: "fragment", Fragment: "billing"},
		{InsertionPoint: "fragment", Parameters: []string{"access_token", "token_type"}},
	}
	for _, v := range cases {
		v.Scheme, v.Domain, v.Path = "https", "app.example.com", "/app"

		// The preview, through the real preview path, stripped of its framing so what is left is
		// the fragment as the operator reads it.
		var preview strings.Builder
		for _, p := range appendFragmentParts(v) {
			preview.WriteString(p.Text)
		}
		_, shown, ok := strings.Cut(preview.String(), "#")
		if !ok {
			t.Errorf("%+v: the preview shows no hash at all", v)
			continue
		}
		shown = strings.TrimSuffix(shown, "\n")
		// The preview writes a slot token and the composer writes the canary. Normalising one into
		// the other is the ONLY licence this test grants: everything else has to match byte for
		// byte, including which side of the ? each name lands on.
		shown = strings.ReplaceAll(shown, attackVectorSlot, VectorCanary)

		// The composed URL, through the real composer.
		in := VectorInput{
			Method: "GET", Scheme: v.Scheme, Domain: v.Domain, Path: v.Path,
			InsertionPoint: v.InsertionPoint, Parameters: v.Parameters, Fragment: v.Fragment,
		}
		_, sent, ok := strings.Cut(in.TargetURL(), "#")
		if !ok {
			t.Errorf("%+v: the composed URL carries no hash, and the preview showed %q", v, shown)
			continue
		}
		if shown != sent {
			t.Errorf("%+v: the operator is shown #%s and the tool is handed #%s", v, shown, sent)
		}
	}
}

// A FRAGMENT VECTOR WITH NO FRAGMENT IS A CLEAN RESULT FILED AGAINST NOTHING.
//
// The create handler refused one and the edit handler did not, and the edit modal offered "fragment"
// in the insertion-point select with no field to put a fragment in. Switching a query vector across
// stored insertion_point fragment with an empty fragment, and from then on the row was eligible
// for domdig, scanned, and recorded clean at a point nothing was ever written to.
//
// The two handlers now share one rule, and the edit adds the one thing it can check that the create
// cannot: the parameters already on a row belong to the point it is LEAVING.
func TestTheEditPathRefusesAFragmentItCannotSupply(t *testing.T) {
	cases := []struct {
		name          string
		newPoint      string
		oldPoint      string
		fragment      string
		parameters    []string
		fragmentGiven bool
		wantRefused   bool
	}{
		{
			// The reported defect, exactly: a query vector switched to fragment, carrying the query
			// parameter names and no hash.
			name:     "query switched to fragment with no fragment supplied",
			newPoint: "fragment", oldPoint: "query", parameters: []string{"tab"},
			wantRefused: true,
		},
		{
			name:     "query switched to fragment WITH a fragment supplied",
			newPoint: "fragment", oldPoint: "query", fragment: "/billing", fragmentGiven: true,
		},
		{
			// An existing OAuth implicit-grant row being edited for something else entirely. Its
			// route is legitimately empty and every name is a fragment name, so refusing this would
			// make the most important shape uneditable.
			name:     "an existing implicit grant row is still editable",
			newPoint: "fragment", oldPoint: "fragment",
			parameters: []string{"access_token", "token_type"},
		},
		{
			name:     "an existing fragment row with nothing in it at all is refused",
			newPoint: "fragment", oldPoint: "fragment",
			wantRefused: true,
		},
		{
			name:     "moving AWAY from the fragment is never refused",
			newPoint: "query", oldPoint: "fragment", parameters: []string{"a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msg := fragmentUpdateError(tc.newPoint, tc.oldPoint, tc.fragment, tc.parameters,
				tc.fragmentGiven)
			if (msg != "") != tc.wantRefused {
				t.Errorf("fragmentUpdateError = %q, refused=%v, want refused=%v",
					msg, msg != "", tc.wantRefused)
			}
		})
	}
}

// The create handler states the rule through the same function, so the two cannot drift again.
func TestCreateStillRefusesAnEmptyFragmentVector(t *testing.T) {
	_, errs := attackVectorsFromRequest(attackVectorRequest{
		URL: "https://app.example.com/settings", InsertionPoint: "fragment",
	})
	if len(errs) == 0 {
		t.Fatal("a fragment vector with no fragment was accepted")
	}
	if want := fragmentVectorError("fragment", "", nil); errs[len(errs)-1] != want {
		t.Errorf("create said %q, the shared rule says %q", errs[len(errs)-1], want)
	}

	// And a fragment typed into its own field is enough on its own, which is what makes refusing the
	// empty one reasonable rather than a dead end.
	got, errs := attackVectorsFromRequest(attackVectorRequest{
		URL: "https://app.example.com/settings", InsertionPoint: "fragment", Fragment: "#/billing",
	})
	if len(errs) != 0 {
		t.Fatalf("a supplied fragment was refused: %v", errs)
	}
	if len(got) != 1 || got[0].Fragment != "/billing" {
		t.Errorf("fragment field produced %+v", got)
	}
}

// "hash" IN A SKIP REASON IS NOT ALWAYS THE URL HASH.
//
// mentionsFragment decides whether a tool's own skip reason wins over the shared one. It matched the
// bare substring "hash", so any future catch-all mentioning a response hash, a password hash, a hash
// parameter or hashcat would have suppressed the accurate fragment explanation and returned the
// catch-all instead: "SQLiDetector can only test a query parameter", which reads as a shape
// limitation an operator might work around rather than as the fact that nothing SQLiDetector sends
// can carry a fragment. Latent rather than live when it was found, and latent is when it is cheap.
func TestOnlyAURLHashCountsAsMentioningTheFragment(t *testing.T) {
	yes := []string{
		"domdig fuzzes the query string and the URL hash. A path segment is neither.",
		"Only a fragment vector can be tested here.",
		"The payload goes after the # and is never sent.",
		"domdig injects into the hash in the URL.",
	}
	no := []string{
		"SQLiDetector compares the response hash and can only test a query parameter.",
		"hashcat is not wired into this section.",
		"The hash parameter is a cache buster, not an input.",
		"This tool only reads a stored password hash.",
	}
	for _, r := range yes {
		if !mentionsFragment(r) {
			t.Errorf("a reason that IS about the fragment was overridden by the shared text: %q", r)
		}
	}
	for _, r := range no {
		if mentionsFragment(r) {
			t.Errorf("a catch-all suppressed the fragment explanation because it said hash: %q", r)
		}
	}
}

// THE CLIENT-ROUTE PATH, DRIVEN WITHOUT A DATABASE.
//
// client_route is non-empty on 0 rows database-wide, so this whole branch has never run against
// data: the port pointer, the empty-domain guard, the path templating, the signal order and the
// 'union' origin were all unexercised. The query cannot be tested here; everything it hands to the
// builder can.
func TestClientRouteRowsBecomeFragmentVectors(t *testing.T) {
	port := 8443
	cases := []struct {
		name        string
		domain      string
		port        *int
		path        string
		clientRoute string
		sources     []string
		wantOK      bool
		wantPath    string
		wantFrag    string
		wantParams  []string
		wantPort    int
	}{
		{
			name: "a hash route becomes a fragment vector", domain: "app.example.com",
			path: "/app", clientRoute: "/dashboard/overview",
			wantOK: true, wantPath: "/app", wantFrag: "/dashboard/overview",
		},
		{
			// Both halves are templated, and by the same rule, so #/orders/12345 and #/orders/67890
			// are one vector seen twice rather than one row per object the operator opened.
			name: "identifiers collapse on both sides of the hash", domain: "app.example.com",
			path: "/tenants/98765", clientRoute: "/orders/12345",
			wantOK: true, wantPath: "/tenants/{id}", wantFrag: "/orders/{id}",
		},
		{
			name:   "a route with its own query names the parameters inside it",
			domain: "app.example.com", path: "/app", clientRoute: "/connect/edit?token=x&tab=scopes",
			wantOK: true, wantPath: "/app", wantFrag: "/connect/edit",
			wantParams: []string{"token", "tab"},
		},
		{
			name: "a non-default port is carried", domain: "app.example.com", port: &port,
			path: "/app", clientRoute: "/dashboard",
			wantOK: true, wantPath: "/app", wantFrag: "/dashboard", wantPort: 8443,
		},
		{
			// A row with no host cannot be scanned by anything, and a vector that names no host
			// would be composed against whatever the runner defaulted to.
			name: "a row with no domain is excluded", domain: "", path: "/app",
			clientRoute: "/dashboard",
		},
		{
			name: "an empty client route produces nothing", domain: "app.example.com",
			path: "/app", clientRoute: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, ok := clientRouteVector("https://app.example.com"+tc.path+"#"+tc.clientRoute,
				"GET", "", tc.domain, tc.port, tc.path, "https", tc.sources, tc.clientRoute)
			if ok != tc.wantOK {
				t.Fatalf("built=%v, want %v (%+v)", ok, tc.wantOK, v)
			}
			if !ok {
				return
			}
			if v.InsertionPoint != "fragment" {
				t.Errorf("insertion point %q, want fragment", v.InsertionPoint)
			}
			if v.Path != tc.wantPath {
				t.Errorf("path %q, want %q", v.Path, tc.wantPath)
			}
			if v.Fragment != tc.wantFrag {
				t.Errorf("fragment %q, want %q", v.Fragment, tc.wantFrag)
			}
			if tc.wantParams != nil && !reflect.DeepEqual(v.Parameters, tc.wantParams) {
				t.Errorf("parameters %v, want %v", v.Parameters, tc.wantParams)
			}
			if v.Port != tc.wantPort {
				t.Errorf("port %d, want %d", v.Port, tc.wantPort)
			}
			// Consolidation merges every sighting of an endpoint, so the combination was not
			// necessarily in one address bar at one moment. Only a manual crawl can say that.
			if v.ParametersOrigin != "union" {
				t.Errorf("parameters_origin %q, want union: a consolidated row is not one sighting",
					v.ParametersOrigin)
			}
			if v.MethodConfidence != "implied" {
				t.Errorf("method_confidence %q, want implied for a row with none recorded",
					v.MethodConfidence)
			}
			if len(v.Sources) == 0 {
				t.Error("a vector with no source cannot be traced back to what found it")
			}
			// The composed URL has to be scannable, which is the whole point of the row existing.
			in := VectorInput{
				Method: v.Method, Scheme: v.Scheme, Domain: v.Domain, Port: v.Port, Path: v.Path,
				InsertionPoint: v.InsertionPoint, Parameters: v.Parameters, Fragment: v.Fragment,
				EvidenceURL: v.EvidenceURL,
			}
			if !strings.Contains(in.TargetURL(), "#") {
				t.Errorf("a client-route vector composed a URL with no hash: %q", in.TargetURL())
			}
		})
	}
}

// THE GUARDS HAVE TO BE CALLED, not merely to exist.
//
// fragmentUpdateError and fragmentVectorError are pure functions, and the tests above drive them
// directly. That is not enough, and a review proved it: the guard call was DELETED from
// UpdateAttackVector, the whole suite was run, and nothing failed. Every rule the edit path is
// supposed to enforce was unenforced and green. A pure function nobody calls is a comment.
//
// So this reads the handler source and asserts the wiring. It is the cheapest thing that fails when
// a call site disappears, and it is the same technique the bypass and flow tests already use for
// their own call sites. It cannot check behaviour, and it is not trying to: it checks that the
// functions the behaviour tests cover are on the path a request actually takes.
func TestTheFragmentGuardsAreWiredIntoTheHandlers(t *testing.T) {
	src, err := os.ReadFile("attackVectorsAPI.go")
	if err != nil {
		t.Fatalf("reading attackVectorsAPI.go: %v", err)
	}
	body := func(name string) string {
		start := strings.Index(string(src), "\nfunc "+name+"(")
		if start < 0 {
			t.Fatalf("%s is gone from attackVectorsAPI.go", name)
		}
		rest := string(src)[start+1:]
		if end := strings.Index(rest, "\nfunc "); end > 0 {
			return rest[:end]
		}
		return rest
	}

	cases := []struct {
		fn   string
		want string
		why  string
	}{
		{"UpdateAttackVector", "fragmentUpdateError(",
			"the edit path stops refusing a move to fragment with no fragment, and stores one that " +
				"composes the plain URL and is then scanned and filed clean"},
		{"attackVectorsFromRequest", "fragmentVectorError(",
			"the create path stops refusing a fragment vector that carries no fragment"},
		{"attackVectorsFromRequest", `wantedPoint != "fragment"`,
			"a pasted query string lends its parameter names to an explicit fragment vector, which " +
				"slips past fragmentVectorError and composes a hash out of names nothing reads"},
		{"UpdateAttackVector", `cur.InsertionPoint == "fragment"`,
			"an update carrying a fragment overwrites a NON fragment row's parameters with the " +
				"fragment's names, re-keys the row, and supersedes the key consolidation needs"},
	}
	for _, c := range cases {
		if !strings.Contains(body(c.fn), c.want) {
			t.Errorf("%s no longer contains %s: %s", c.fn, c.want, c.why)
		}
	}
}

// A QUERY STRING MUST NOT LEND ITS PARAMETER NAMES TO AN EXPLICIT FRAGMENT VECTOR.
//
// Measured before the fix: POSTing https://h.example.com/x?a=1 with insertion_point=fragment was
// ACCEPTED, stored as fragment="" parameters=[a] with insertion_confidence "observed", and composed
// #a=rs0n. Every part of that is invented. fragmentVectorError did not fire because its test for
// "this vector carries something" is a non-empty fragment OR a parameter, and the query string had
// quietly supplied the parameter.
//
// The names in a query string are query names. An operator who picks `fragment` is saying the
// payload goes somewhere the server never sees, which those names have nothing to do with. It is
// the same rule fragmentUpdateError applies to an edit, on the create side.
func TestAQueryStringDoesNotFillAnExplicitFragmentVector(t *testing.T) {
	cases := []struct {
		name        string
		req         attackVectorRequest
		wantRefused bool
		wantFrag    string
		wantParams  []string
	}{
		{
			name:        "query names must not become fragment names",
			req:         attackVectorRequest{URL: "https://h.example.com/x?a=1", InsertionPoint: "fragment"},
			wantRefused: true,
		},
		{
			name: "the fragment's OWN names are kept when the point is stated",
			req: attackVectorRequest{URL: "https://h.example.com/app?a=1#/connect/edit?token=abc",
				InsertionPoint: "fragment"},
			wantFrag: "/connect/edit", wantParams: []string{"token"},
		},
		{
			name: "an implicit grant with the point stated keeps its names",
			req: attackVectorRequest{URL: "https://h.example.com/callback#access_token=ey&token_type=bearer",
				InsertionPoint: "fragment"},
			wantParams: []string{"access_token", "token_type"},
		},
		{
			// The ordinary path is untouched: no insertion point named, so the query string still
			// names the parameters and still selects `query`.
			name:       "a plain URL still takes its names from the query",
			req:        attackVectorRequest{URL: "https://h.example.com/x?a=1&b=2"},
			wantParams: []string{"a", "b"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, errs := attackVectorsFromRequest(tc.req)
			if tc.wantRefused {
				if len(errs) == 0 {
					t.Fatalf("accepted, as %+v. A fragment vector was stored for a hash nobody "+
						"observed, and domdig will fuzz it.", got)
				}
				return
			}
			if len(errs) > 0 {
				t.Fatalf("refused: %v", errs)
			}
			if len(got) != 1 {
				t.Fatalf("got %d vectors, want 1", len(got))
			}
			if got[0].Fragment != tc.wantFrag {
				t.Errorf("fragment = %q, want %q", got[0].Fragment, tc.wantFrag)
			}
			if !reflect.DeepEqual(got[0].Parameters, tc.wantParams) {
				t.Errorf("parameters = %v, want %v", got[0].Parameters, tc.wantParams)
			}
		})
	}
}
