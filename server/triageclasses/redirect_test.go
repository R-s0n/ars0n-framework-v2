package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

const rdrTestBase = "http://app.example.test/a/b?next=x"

// rdrTestMarker is a marker-shaped token. It is not minted by the allocator and it does not have
// to be: every detector in this class is a function of the probe's own marker as a STRING, and the
// stripe arithmetic is the runner's and the vault's business, which those layers test.
const rdrTestMarker triage.Marker = "zqj0000000000abc"

// rdrObs builds one of this class's own observations, as the vault would hand it over.
//
// The fields set here are exactly the ones the class reads: the payload record (so the wire check
// passes), the status, and the raw Location. Anything else left zero is a field this class does
// not look at, and if that ever stops being true a test written against this helper fails loudly
// rather than quietly reading a zero.
func rdrObs(id triage.ProbeID, status int, location string) faOwnObs {
	o := triage.Observation{
		Status:   status,
		FinalURL: rdrTestBase,
		Payload: triage.PayloadWire{
			Logical:  []byte("payload-for-" + string(id)),
			Wire:     []byte("payload-for-" + string(id)),
			Survived: triage.WireSurvivalIntact,
		},
	}
	if location != "" {
		o.RedirectChain = []triage.Hop{{Status: status, Location: location}}
	}
	return faOwnObs{ProbeID: id, Ordinal: 18, Marker: rdrTestMarker, Obs: o}
}

func TestTheRedirectClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassRedirect)
	if !ok {
		t.Fatal("the redirect classifier did not register itself, so the class produces no rows at all and no row looks the same as no bug")
	}
	if c.ID() != triage.ClassRedirect {
		t.Fatalf("registered under %s but reports %s", triage.ClassRedirect, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes with REDIRECT registered", rep.ClassesChecked, rep.ProbesChecked)
}

// EVERY PAYLOAD SPELLS THE MARKER PLACEHOLDER, and that is not decoration.
//
// Marker placement by the runner is OPT-IN: only a class declaring RunnerPlacesMarkers gets one
// prepended, and this class deliberately does not declare it, because a 16-byte prefix in front of
// "http://" makes the payload a relative path and tests nothing. So the marker has to be spelled,
// and a payload that forgot would go out bare, resolve to a host with no marker in it, and be
// silently unscorable by rdrOwnHost.
func TestEveryRedirectPayloadCarriesTheMarkerPlaceholder(t *testing.T) {
	for _, p := range (redirectClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("probe %s payload %q spells no marker placeholder, so it goes out bare and nothing it produces can be attributed to this probe on this slot",
				p.ID, p.Logical)
		}
		if p.MarkerPos != "" {
			t.Errorf("probe %s declares MarkerPos %q while spelling its own marker. The runner only honours MarkerPos for an opted-in class, so the declaration is a promise nothing keeps and a reader would believe it",
				p.ID, p.MarkerPos)
		}
	}
}

// This class MUST NOT opt into runner-placed markers, and the assertion is structural rather than
// a comment: the interface is satisfied by declaring the method, so a future edit that adds it
// would silently prepend sixteen bytes to "http://" on every probe.
func TestTheRedirectClassDoesNotOptIntoRunnerPlacedMarkers(t *testing.T) {
	var c any = redirectClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("REDIRECT opted into runner-placed markers. A prefixed marker turns http://host/ into a relative path and every payload in this class would test nothing")
	}
}

// THE TABLE THAT DECIDES WHETHER THIS CLASS WORKS. Each row is a Location a server might write and
// the two readings this class takes of it. The measured behaviour of net/url is what makes rows
// three to six browser-only, and the last three rows are the false positives the class exists to
// refuse.
func TestTheTwoResolutionModelsReadTheMeasuredTable(t *testing.T) {
	host := string(rdrTestMarker) + rdrHostSuffix
	for _, c := range []struct {
		name            string
		location        string
		strict, browser bool
	}{
		{"absolute", "http://" + host + "/", true, true},
		{"scheme relative", "//" + host + "/", true, true},
		{"four slashes", "////" + host + "/", false, true},
		{"scheme without slashes", "https:" + host + "/", false, true},
		{"backslash slash twice", `\/\/` + host + "/", false, true},
		{"slash backslash slash", `/\/` + host + "/", false, true},
		{"userinfo", "https://app.example.test@" + host + "/", true, true},

		{"bare hostname is relative", host + "/", false, false},
		{"origin absolute path", "/" + string(rdrTestMarker) + "-rdr-local", false, false},
		{"marker in the query of an on-origin location", "/login?next=%2F%2F" + host, false, false},
		{"marker in the path of an on-origin location", "/redir/" + host, false, false},
		{"a different host entirely", "https://somewhere.else.test/", false, false},
	} {
		hits := rdrRead([]faOwnObs{rdrObs(rdrA1, 302, c.location)})
		if len(hits) != 1 {
			t.Fatalf("%s: rdrRead returned %d readings", c.name, len(hits))
		}
		h := hits[0]
		if h.strictOff != c.strict || h.browserOff != c.browser {
			t.Errorf("%s: Location %q read as strict=%v browser=%v, want strict=%v browser=%v (%s)",
				c.name, c.location, h.strictOff, h.browserOff, c.strict, c.browser,
				pxDescribeResolutions(h.strict, h.browser))
		}
	}
}

// A Location on a NON-3xx is not a redirect and must not be scored as one. A 200 carrying a
// Location is not followed by any browser, and a class that read one would report a finding on
// every API that echoes a Location into a successful response.
func TestALocationOnANonRedirectStatusIsNotScored(t *testing.T) {
	host := string(rdrTestMarker) + rdrHostSuffix
	hits := rdrRead([]faOwnObs{rdrObs(rdrA1, 200, "http://"+host+"/")})
	if hits[0].strictOff || hits[0].browserOff {
		t.Error("a Location on a 200 was scored as a redirect")
	}
	if hits[0].location != "" {
		t.Errorf("a Location on a 200 was kept as a redirect target: %q", hits[0].location)
	}
}

// Attribution is by THIS probe's own marker. A Location naming a host built from a different
// marker is another probe's, another run's, or a cached response, and none of those is evidence
// about this request.
func TestARedirectToAnotherMarkersHostIsNotThisProbesFinding(t *testing.T) {
	other := "zqj9999999999xyz" + rdrHostSuffix
	hits := rdrRead([]faOwnObs{rdrObs(rdrA1, 302, "http://"+other+"/")})
	if hits[0].strictOff || hits[0].browserOff {
		t.Error("a redirect to a host carrying a DIFFERENT marker was scored as this probe's finding, so a cached response from an earlier run would read as a live bug")
	}
}

// Round 0 is two requests and the second of them is the reach control, because the reach control
// is what decides between a clean, a filtered sink and an unknown.
func TestTheRedirectLadderSpendsTwoRequestsOnTheCommonPath(t *testing.T) {
	ids := rdrRound0()
	if len(ids) != 2 {
		t.Fatalf("round 0 plans %d probes, want 2", len(ids))
	}
	seen := map[triage.ProbeID]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen[rdrA1] || !seen[rdrNC2] {
		t.Errorf("round 0 is %v; it must carry the base payload and the inert reach control", ids)
	}
	// Every planned probe must be declared, or it would never have been isolation-checked.
	c := redirectClassifier{}
	all := append(rdrPlanFor(rdrRound0(), "query:q"), rdrPlanFor(rdrRound1(), "query:q")...)
	if err := triage.PlannedProbesAreDeclared(c, all); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
}

// The ladder does not fire on nothing. With no evidence that the slot touches the Location, round
// 1 is not planned, and that is the decision that keeps the class at one or two requests a slot
// across a corpus of 1860 of them.
func TestTheRedirectLadderStaysShutWithNoEvidence(t *testing.T) {
	ctx := triage.PlanCtx{
		Slot:  triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1},
		Round: 1,
	}
	if rdrLadderIsWorthIt(ctx) {
		t.Error("the bypass ladder was planned with no route control, no observations and no evidence of any kind")
	}
	if reqs := (redirectClassifier{}).Plan(ctx); len(reqs) != 0 {
		t.Errorf("Plan returned %d probes on an unresolved route; nothing may be sent without a control to compare against", len(reqs))
	}
}

// With no observations at all the class says an UNKNOWN and names which one. Not one path through
// Classify with an empty own-set may produce a clean.
func TestRedirectWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1}
	vs := (redirectClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if len(vs) == 0 {
		t.Fatal("no verdict at all, so the slot reads as untouched")
	}
	for _, v := range vs {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
		if v.State.CountsAsClean() {
			t.Errorf("clean with nothing sent: %q", v.Reason)
		}
		if !v.State.IsUnknown() {
			t.Errorf("state %q is not an unknown, so an aggregate counts it as a measurement", v.State)
		}
		if v.Class != triage.ClassRedirect || v.SlotKey != slot.Key {
			t.Errorf("verdict is stamped %s/%s, want %s/%s", v.Class, v.SlotKey, triage.ClassRedirect, slot.Key)
		}
	}
}

// The fragment is not_reachable with a reason, and it costs nothing. A class that simply produced
// no row there would leave "ruled out" and "nobody wired this up" as the same pixel.
func TestRedirectOnAFragmentIsNotReachableAtZeroCost(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindFragment, Key: "fragment:tab", Name: "tab", SegmentIndex: -1}
	c := redirectClassifier{}
	if reqs := c.Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
		t.Errorf("planned %d probes into a fragment, which never leaves the browser", len(reqs))
	}
	vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts for a fragment, want exactly one", len(vs))
	}
	if vs[0].State.CountsAsClean() {
		t.Error("a fragment produced a clean")
	}
	if strings.TrimSpace(vs[0].Reason) == "" {
		t.Error("the fragment row carries no reason")
	}
}

// Both host-building helpers are per probe and per marker, so two probes on one slot cannot be
// confused with each other.
func TestTheRedirectHostIsBuiltFromTheProbesOwnMarker(t *testing.T) {
	if got := rdrOwnHost(rdrTestMarker); got != string(rdrTestMarker)+rdrHostSuffix {
		t.Errorf("rdrOwnHost = %q", got)
	}
	if got := rdrOwnHost(""); got != "" {
		t.Errorf("rdrOwnHost with no marker returned %q; a probe with no marker must be unscorable rather than matched against a bare suffix", got)
	}
}

// The oracle cases declare at least one route that must make the class FIRE and at least one that
// must make it STAY SILENT. A detector only ever observed firing scores the same as one that
// always returns true, which is the argument the whole oracle-case surface exists for.
func TestTheRedirectOracleCasesDeclareAFireRouteAndASilentRoute(t *testing.T) {
	cases := (redirectClassifier{}).OracleCases()
	pos, neg, clean := 0, 0, 0
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
			if c.WantState.CountsAsClean() {
				clean++
			}
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("oracle case %s carries no reason, so nobody building the route knows what it is for", c.Name)
		}
		if !c.WantState.Known() {
			t.Errorf("oracle case %s wants unrecognised state %q", c.Name, c.WantState)
		}
	}
	if pos == 0 {
		t.Error("no positive oracle case: the detector has never been shown to fire")
	}
	if neg == 0 {
		t.Error("no negative oracle case: the detector has never been shown to stay silent, which is the one that matters")
	}
	if clean == 0 {
		t.Error("no negative case expects CLEAN. A class whose negatives all expect an unknown has never been shown able to say nothing-found")
	}
	t.Logf("%d oracle cases: %d positive, %d negative, %d of them expecting clean", len(cases), pos, neg, clean)
}

// THE FALSE POSITIVE THE ORACLE RUN CAUGHT, KEPT AS A TEST.
//
// The document arm used to ask only "is this probe's host in the authority position of a URL in
// the body". This class sends a URL, so an application that merely ECHOES the parameter satisfies
// that, and on the first full-registry run against the canary oracle the class reported
// document_redirect_reflection on /xss?q=, a pure reflection route that emits no Location, no
// Refresh and no meta refresh. That is rank 7 wearing rank 5's coat, which is the exact thing the
// class's own header comment spends a paragraph refusing, and a comment did not stop it.
//
// The negatives here outnumber the positives because each of them is a real page shape that
// contains our URL and navigates nobody.
func TestTheDocumentArmNeedsARedirectConstructAndNotAnEcho(t *testing.T) {
	host := string(rdrTestMarker) + rdrHostSuffix
	for _, c := range []struct {
		name string
		body string
		want bool
	}{
		{"meta refresh", `<meta http-equiv="refresh" content="0;url=http://` + host + `/">`, true},
		{"meta refresh with the attributes reversed", `<meta content="2; url=http://` + host + `/" http-equiv=Refresh>`, true},
		{"window location assignment", `<script>window.location = "http://` + host + `/";</script>`, true},
		{"location href", `<script>location.href="//` + host + `/x"</script>`, true},
		{"location replace", `<script>location.replace('http://` + host + `/')</script>`, true},

		{"a plain echo of the parameter", `<p>you searched for http://` + host + `/</p>`, false},
		{"echoed into an input value", `<input name=next value="http://` + host + `/">`, false},
		{"an ordinary link", `<a href="http://` + host + `/">click</a>`, false},
		{"a link whose text is the word location", `<a href="http://` + host + `/">location</a>`, false},
		{"a url query parameter called url", `<p>see /go?url=http://` + host + `/ for details</p>`, false},
		{"a script source", `<script src="http://` + host + `/a.js"></script>`, false},
		{"an image", `<img src="//` + host + `/pixel.gif">`, false},
		{"the word location far away", `<p>location</p>` + strings.Repeat("x", 400) + `<p>http://` + host + `/</p>`, false},
		{"nothing at all", `<p>hello</p>`, false},
	} {
		h := rdrHit{obs: rdrObs(rdrA1, 200, "")}
		h.obs.Obs.Body = []byte(c.body)
		where, got := rdrDocumentRedirect(h)
		if got != c.want {
			t.Errorf("%s: rdrDocumentRedirect = %v (%s), want %v\n  body: %s", c.name, got, where, c.want, c.body)
		}
	}

	// The response-header half needs no construct test: a Refresh header IS the construct.
	h := rdrHit{obs: rdrObs(rdrA1, 200, "")}
	h.obs.Obs.RespHeaders = [][2]string{{"Refresh", "0;url=http://" + host + "/"}}
	if _, ok := rdrDocumentRedirect(h); !ok {
		t.Error("a Refresh response header naming our authority did not fire the document arm")
	}
}
