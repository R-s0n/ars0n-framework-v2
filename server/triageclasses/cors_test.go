package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// corsTestMarker is a marker-shaped token. It is not minted by the allocator and it does not need
// to be: every detector in this class is a function of the probe's own marker AS A STRING, and the
// stripe arithmetic is the runner's and the vault's business, which those layers test. The same
// reasoning is written out in redirect_test.go and it holds here for the same reason.
const corsTestMarker triage.Marker = "zqj0000000000abc"

func corsTestHost() string { return string(corsTestMarker) + corsHostSuffix }

// corsObs builds one of this class's own observations as the vault would hand it over.
//
// The fields set here are exactly the ones the class reads: the payload record so the wire check
// passes, and the response headers. Nothing sets a body, deliberately: if a body ever becomes
// load-bearing in this class, a test written against this helper fails loudly rather than quietly
// reading a nil.
func corsObs(id triage.ProbeID, sent string, headers ...[2]string) faOwnObs {
	o := triage.Observation{
		ObsID: "obs-" + string(id), Status: 200, BodyLen: 1,
		Payload: triage.PayloadWire{
			Logical: []byte(sent), Wire: []byte(sent), Survived: triage.WireSurvivalIntact,
		},
	}
	o.RespHeaders = append(o.RespHeaders, headers...)
	return faOwnObs{ProbeID: id, Ordinal: 28, Marker: corsTestMarker, Obs: o}
}

func TestTheCORSClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassCORS)
	if !ok {
		t.Fatal("the CORS classifier did not register itself, so the class produces no rows at all, and no row looks exactly the same as no bug")
	}
	if c.ID() != triage.ClassCORS {
		t.Fatalf("registered under %s but reports %s", triage.ClassCORS, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes with CORS registered", rep.ClassesChecked, rep.ProbesChecked)
}

// ID 28 IS THE CLAIM THIS CLASS MAKES ON THE REGISTER AND IT IS ASSERTED RATHER THAN ASSUMED. The
// id is also the marker's ordinal stripe, so a future edit that moved it onto an existing class's
// number would make every CORS marker attributable to that class by arithmetic, silently.
func TestCORSTookTheNextFreeIDAfterCSVI(t *testing.T) {
	if triage.ClassCORS != triage.ClassCSVI+1 {
		t.Errorf("CORS is id %d and CSVI is id %d; CORS was assigned as the next free id after CSVI and a gap or an overlap means the register was edited without reading why",
			triage.ClassCORS, triage.ClassCSVI)
	}
	if !triage.ClassCORS.Known() {
		t.Error("ClassCORS is not in triageClassNames, so String() would render it as class(28) and RegisterClassifier would have panicked")
	}
	if triage.ClassCORS.String() != "CORS" {
		t.Errorf("ClassCORS renders as %q", triage.ClassCORS.String())
	}
	if uint64(triage.ClassCORS) >= triage.ClassStripeModulus {
		t.Errorf("id %d is not below the stripe modulus %d", triage.ClassCORS, triage.ClassStripeModulus)
	}
}

// EVERY PAYLOAD SPELLS THE MARKER PLACEHOLDER. Marker placement by the runner is OPT-IN and this
// class deliberately does not opt in, because a 16-byte prefix in front of "https://" makes the
// value something that is not an origin at all. So the marker has to be spelled, and a payload
// that forgot would go out naming a host with no marker in it, which is unattributable to this
// probe and therefore unscorable.
func TestEveryCORSPayloadCarriesTheMarkerPlaceholder(t *testing.T) {
	for _, p := range (corsClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("probe %s payload %q spells no marker placeholder, so nothing it produces can be attributed to this probe on this slot",
				p.ID, p.Logical)
		}
		if p.MarkerPos != "" {
			t.Errorf("probe %s declares MarkerPos %q while spelling its own marker. The runner honours MarkerPos only for an opted-in class, so the declaration is a promise nothing keeps",
				p.ID, p.MarkerPos)
		}
	}
}

func TestTheCORSClassDoesNotOptIntoRunnerPlacedMarkers(t *testing.T) {
	var c any = corsClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("CORS opted into runner-placed markers. A prefixed marker in front of https:// makes the Origin header a value that is not an origin, and every payload in this class would test the control's question instead of its own")
	}
}

// THE MARKER MUST BE A LEGAL DNS LABEL OR THE WHOLE ATTRIBUTION SCHEME IS FICTION. The class
// builds "<marker>.cors.invalid" and calls the result an origin. That only works because a marker
// is 16 bytes over [0-9a-z] with a letter first.
func TestTheMarkerIsALegalDNSLabelSoTheOriginIsSyntacticallyValid(t *testing.T) {
	m := string(corsTestMarker)
	if len(m) > 63 {
		t.Errorf("a marker is %d bytes and a DNS label caps at 63", len(m))
	}
	if m[0] < 'a' || m[0] > 'z' {
		t.Errorf("marker %q does not start with a letter, so it is not a legal label", m)
	}
	for i := 0; i < len(m); i++ {
		b := m[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'z') {
			t.Errorf("marker byte %q at %d is outside the DNS label alphabet", b, i)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE ORACLE TABLE. THE NEGATIVES ARE THE ROWS THAT DECIDE WHETHER THIS IS A DETECTOR.
// ---------------------------------------------------------------------------------------------

func TestTheCORSOracleReadsTheMeasuredTable(t *testing.T) {
	sent := "https://" + corsTestHost()
	self := "https://app.example.test"
	for _, c := range []struct {
		name                       string
		acao                       string
		hasACAO                    bool
		exact, ourHost, star, null bool
	}{
		{"exact reflection", sent, true, true, false, false, false},
		{"reflection with different case", strings.ToUpper(sent), true, true, false, false, false},
		{"the application's own origin", self, true, false, false, false, false},
		{"a wildcard", "*", true, false, false, true, false},
		{"the null origin", "null", true, false, false, false, true},
		{"no header at all", "", false, false, false, false, false},
		{"an empty header", "", true, false, false, false, false},
		{"our host without a scheme, which is not what we sent", corsTestHost(), true, false, false, false, false},
		{"our host as a subdomain of somebody else", "https://" + corsTestHost() + ".evil.test", true, false, false, false, false},
		{"a different marker's host", "https://zqj9999999999xyz" + corsHostSuffix, true, false, false, false, false},
	} {
		var hdrs [][2]string
		if c.hasACAO {
			hdrs = append(hdrs, [2]string{corsACAO, c.acao})
		}
		rs := corsRead([]faOwnObs{corsObs(corsA1, sent, hdrs...)}, self)
		if len(rs) != 1 {
			t.Fatalf("%s: corsRead returned %d readings", c.name, len(rs))
		}
		r := rs[0]
		if r.reflectedExact != c.exact || r.reflectedOurHost != c.ourHost || r.wildcard != c.star || r.null != c.null {
			t.Errorf("%s: %s=%q read as exact=%v ourHost=%v wildcard=%v null=%v, want exact=%v ourHost=%v wildcard=%v null=%v",
				c.name, corsACAO, c.acao, r.reflectedExact, r.reflectedOurHost, r.wildcard, r.null,
				c.exact, c.ourHost, c.star, c.null)
		}
	}
}

// THE LIST PROBE'S SECOND ENTRY COUNTS. CORS-A4 sends two origins; a server that answers with the
// SECOND one has not reflected what we sent byte for byte and has still handed us a grant to a
// host we named. reflectedOurHost is the reading that catches it, and it goes through
// pxHostInAuthorityPosition rather than a substring search.
func TestTheSecondEntryOfTheOriginListIsStillOurHost(t *testing.T) {
	sent := "https://" + corsTestHost() + ", https://x" + corsTestHost()
	rs := corsRead([]faOwnObs{corsObs(corsA4, sent,
		[2]string{corsACAO, "https://x" + corsTestHost()})}, "https://app.example.test")
	if !rs[0].reflectedOurHost {
		t.Errorf("a grant naming the SECOND origin of the list we sent was not read as our host; a server that parses a list the protocol never produces is exactly what CORS-A4 is for")
	}
	if rs[0].reflectedExact {
		t.Error("a grant naming only the second entry is not byte-equal to what we sent and must not read as an exact reflection")
	}
}

// A DIFFERENT PROBE'S MARKER IS NOT THIS PROBE'S EVIDENCE. A grant naming a host built from
// another marker is another probe's, another run's, or a cached response.
func TestAGrantNamingAnotherMarkersHostIsNotThisProbesFinding(t *testing.T) {
	sent := "https://" + corsTestHost()
	other := "https://zqj9999999999xyz" + corsHostSuffix
	rs := corsRead([]faOwnObs{corsObs(corsA1, sent, [2]string{corsACAO, other})}, "")
	if rs[0].reflectedExact || rs[0].reflectedOurHost {
		t.Error("a grant to a host carrying a DIFFERENT marker scored as this probe's finding, so a cached response from an earlier run would read as a live bug")
	}
}

// ---------------------------------------------------------------------------------------------
// SEVERITY. FIVE BUGS, FIVE ANSWERS, AND THE ORDER IS LOAD-BEARING.
// ---------------------------------------------------------------------------------------------

func corsRunArms(t *testing.T, rs []corsReading) (triage.ClassVerdict, bool) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassCORS, "header:origin", state, reason, oracle, grade, ords, ann, corsLabel(ann))
	}
	v, ok := corsPositive(rs, triage.ClassifyCtx{}, ann, []uint64{28}, nil, one)
	if !ok {
		return triage.ClassVerdict{}, false
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("verdict failed its own contract: %v", err)
	}
	return v[0], true
}

func TestCORSSeverityIsDecidedByCredentialsAndTheArmsAreOrdered(t *testing.T) {
	sent := "https://" + corsTestHost()
	base := func(acao string, creds bool, id triage.ProbeID) corsReading {
		return corsReading{probe: id, ordinal: 28, sent: sent, acao: acao, acaoPresent: true,
			credentials: creds, reflectedExact: strings.EqualFold(acao, sent),
			wildcard: acao == "*", null: strings.EqualFold(acao, "null")}
	}
	for _, c := range []struct {
		name      string
		rs        []corsReading
		wantState triage.TriageState
		wantGrade triage.TriageGrade
		wantOracl string
	}{
		{"reflected with credentials", []corsReading{base(sent, true, corsA1)},
			triage.StateFinding, triage.GradeHigh, "reflected_origin_with_credentials"},
		{"reflected without credentials", []corsReading{base(sent, false, corsA1)},
			triage.StateFinding, triage.GradeMedium, "reflected_origin_without_credentials"},
		{"null with credentials", []corsReading{base("null", true, corsA1)},
			triage.StateFinding, triage.GradeHigh, "null_origin_allowed"},
		{"null without credentials", []corsReading{base("null", false, corsA1)},
			triage.StateFinding, triage.GradeMedium, "null_origin_allowed"},
		{"wildcard with credentials", []corsReading{base("*", true, corsA1)},
			triage.StateSuspicious, triage.GradeLow, "wildcard_with_credentials"},
		{"the control echoed", []corsReading{{probe: corsNC1, sent: corsTestHost(), acao: corsTestHost(),
			acaoPresent: true, reflectedExact: true}},
			triage.StateFinding, triage.GradeHigh, "origin_echoed_without_parsing"},

		// THE ORDER. A response that does both must be reported as the worse of the two, because a
		// critical cross-origin read filed under "no credentials" is a report nobody actions.
		{"credentials outranks no credentials", []corsReading{base(sent, false, corsA2), base(sent, true, corsA1)},
			triage.StateFinding, triage.GradeHigh, "reflected_origin_with_credentials"},
	} {
		v, fired := corsRunArms(t, c.rs)
		if !fired {
			t.Errorf("%s: no arm fired at all", c.name)
			continue
		}
		if v.State != c.wantState || v.Grade != c.wantGrade || v.Oracle != c.wantOracl {
			t.Errorf("%s: got state=%s grade=%s oracle=%s, want state=%s grade=%s oracle=%s",
				c.name, v.State, v.Grade, v.Oracle, c.wantState, c.wantGrade, c.wantOracl)
		}
	}
}

// THE TWO SHAPES THAT MUST STAY SILENT. This is the test that separates a detector from a
// header-presence alarm, and a class that failed it would fire on a large fraction of correctly
// configured APIs.
func TestTheCorrectCORSImplementationsFireNothing(t *testing.T) {
	self := "https://app.example.test"
	for _, c := range []struct {
		name string
		rs   []corsReading
	}{
		{"the server grants only its own origin, whatever we sent", []corsReading{
			{probe: corsA1, sent: "https://" + corsTestHost(), acao: self, acaoPresent: true, credentials: true},
			{probe: corsA2, sent: "http://" + corsTestHost(), acao: self, acaoPresent: true, credentials: true},
			{probe: corsNC1, sent: corsTestHost(), acao: self, acaoPresent: true, credentials: true},
		}},
		{"the server emits no CORS header at all", []corsReading{
			{probe: corsA1, sent: "https://" + corsTestHost()},
			{probe: corsA2, sent: "http://" + corsTestHost()},
			{probe: corsNC1, sent: corsTestHost()},
		}},
		{"a bare wildcard with no credentials, which is public-data CORS", []corsReading{
			{probe: corsA1, sent: "https://" + corsTestHost(), acao: "*", acaoPresent: true, wildcard: true},
		}},
	} {
		if v, fired := corsRunArms(t, c.rs); fired {
			t.Errorf("%s: an arm fired (%s / %s: %s). Correct CORS must be silent, or this class reports a finding on every well-configured API in the corpus",
				c.name, v.State, v.Oracle, v.Reason)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE SHARED-CACHE SAFETY GATE
// ---------------------------------------------------------------------------------------------

// THE GATE REFUSES ON EVIDENCE OF CACHING, NOT ON ABSENCE OF A PROHIBITION, and this table is the
// correction the full-registry run forced. The first cut treated "no Cache-Control at all" as
// storable, which silenced CORS and HOSTHDR on every vector of the oracle fixture: planned=0
// sent=0 for both, against CRLF's 24 on the same slots. A gate that refuses everywhere is a
// silent zero with a good motive.
func TestTheCacheGateRefusesOnEvidenceAndNotOnAbsence(t *testing.T) {
	obs := func(method string, status int, hdrs [][2]string, cookies int, reqHdrs [][2]string) triage.Observation {
		o := triage.Observation{ObsID: "route", Status: status, BodyLen: 1, ReqMethod: method,
			RespHeaders: hdrs, ReqHeaders: reqHdrs}
		for i := 0; i < cookies; i++ {
			o.SetCookies = append(o.SetCookies, triage.CookieObs{Name: "s"})
		}
		return o
	}
	cc := func(v string) [][2]string { return [][2]string{{"Cache-Control", v}} }
	auth := [][2]string{{"Authorization", "Bearer x"}}

	for _, c := range []struct {
		name  string
		o     triage.Observation
		risky bool
	}{
		// POSITIVE EVIDENCE. Each of these says a shared cache is or will be involved.
		{"public", obs("GET", 200, cc("public, max-age=600"), 0, nil), true},
		{"a non-zero max-age with no private", obs("GET", 200, cc("max-age=60"), 0, nil), true},
		{"s-maxage on its own", obs("GET", 200, cc("s-maxage=30"), 0, nil), true},
		{"it is already being served from a cache", obs("GET", 200, [][2]string{{"Age", "12"}}, 0, nil), true},
		{"a CDN says it hit", obs("GET", 200, [][2]string{{"X-Cache", "HIT"}}, 0, nil), true},
		{"Cloudflare says it hit", obs("GET", 200, [][2]string{{"CF-Cache-Status", "HIT"}}, 0, nil), true},
		{"an Expires header", obs("GET", 200, [][2]string{{"Expires", "Wed, 21 Oct 2026 07:28:00 GMT"}}, 0, nil), true},
		{"public overrides the Authorization exemption, as RFC 9111 3.5 says", obs("GET", 200, cc("public, max-age=600"), 0, auth), true},

		// NO EVIDENCE. These must be probed, and the first row is the one that mattered.
		{"NO CACHE HEADERS AT ALL, which is the common case and must not be refused", obs("GET", 200, nil, 0, nil), false},
		{"no-store", obs("GET", 200, cc("no-store"), 0, nil), false},
		{"private", obs("GET", 200, cc("max-age=600, private"), 0, nil), false},
		{"no-cache", obs("GET", 200, cc("no-cache"), 0, nil), false},
		{"max-age=0 is not permission", obs("GET", 200, cc("max-age=0"), 0, nil), false},
		{"an unparseable max-age is not permission", obs("GET", 200, cc("max-age=banana"), 0, nil), false},
		{"CDN-Cache-Control overrides with no-store", obs("GET", 200, [][2]string{{"CDN-Cache-Control", "no-store"}}, 0, nil), false},
		{"the response sets a cookie", obs("GET", 200, nil, 1, nil), false},
		{"a POST is not stored", obs("POST", 200, cc("public, max-age=600"), 0, nil), false},
		{"a 500 is not heuristically cacheable", obs("GET", 500, nil, 0, nil), false},
		{"a 401 is not heuristically cacheable", obs("GET", 401, nil, 0, nil), false},
		{"the request carried Authorization and nothing re-permits storage", obs("GET", 200, cc("max-age=600"), 0, auth), false},
		{"the request carried a Cookie and nothing re-permits storage", obs("GET", 200, nil, 0, [][2]string{{"Cookie", "sid=1"}}), false},
		{"it already varies on Origin, so the cache keys on it", obs("GET", 200, [][2]string{{"Vary", "Accept-Encoding, Origin"}, {"Age", "5"}}, 0, nil), false},
		{"it varies on the routing header HOSTHDR perturbs", obs("GET", 200, [][2]string{{"Vary", "X-Forwarded-Host"}, {"Age", "5"}}, 0, nil), false},
		{"Vary: * is never reused", obs("GET", 200, [][2]string{{"Vary", "*"}, {"Age", "5"}}, 0, nil), false},
	} {
		why, risky := pcSharedCacheRiskOf(c.o)
		if risky != c.risky {
			t.Errorf("%s: risky=%v want %v (%s)", c.name, risky, c.risky, why)
		}
		if risky && why == "" {
			t.Errorf("%s: refused with no reason, which is a not_probed row an operator cannot act on", c.name)
		}
		if !risky && why != "" {
			t.Errorf("%s: allowed and still produced a reason %q, which would read as a refusal", c.name, why)
		}
	}
}

// IT FAILS CLOSED ON THE ONE THING IT CANNOT SEE AT ALL. No control, or a control that never came
// back, is no evidence about the endpoint, and that is different from evidence of no caching.
func TestTheCacheGateFailsClosedOnlyWhenItCannotLook(t *testing.T) {
	if why, risky := pcSharedCacheRisk(triage.Replay{}); !risky || why == "" {
		t.Error("Plan's gate allowed an unresolved route control. Could-not-look and safe are different answers and only one of them may send a request")
	}
	if _, risky := pcSharedCacheRiskOf(triage.Observation{TransportErr: triage.TransportTimeout}); !risky {
		t.Error("an undelivered route control was treated as evidence of no caching")
	}
	// Classify asks a different question and must NOT turn an unresolved control into a cache
	// refusal: nothing about caching was learned there, and route_unresolved is the fact.
	if why, risky := pcSharedCacheRiskOfResolved(triage.Replay{}); risky || why != "" {
		t.Error("Classify's gate reported a cache refusal on a vector whose control never resolved, which names the wrong reason on the row")
	}
}

// With no route control nothing is planned and the verdict names the CONTROL as the problem
// rather than the cache, because that is what actually happened.
func TestCORSPlansNothingWithNoControlAndSaysWhichUnknownItIs(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindHeader, Key: "header:origin", Name: "origin",
		ServerReachable: true, SegmentIndex: -1}
	if reqs := (corsClassifier{}).Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
		t.Errorf("planned %d probes with no route control; nothing may be sent without evidence about this endpoint's cacheability", len(reqs))
	}
	vs := (corsClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts, want exactly one row", len(vs))
	}
	if vs[0].State.CountsAsClean() {
		t.Error("a slot with no control rendered as clean")
	}
	if !strings.Contains(vs[0].Reason, "route_unresolved") {
		t.Errorf("the verdict names the wrong unknown: %q", vs[0].Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// ELIGIBILITY AT ZERO REQUEST COST
// ---------------------------------------------------------------------------------------------

func TestCORSIsNotApplicableEverywhereButTheOriginHeaderAndItCostsNothing(t *testing.T) {
	c := corsClassifier{}
	for _, slot := range []triage.Slot{
		{Kind: triage.KindHeader, Key: "header:x-real-ip", Name: "x-real-ip", ServerReachable: true, SegmentIndex: -1},
		{Kind: triage.KindQuery, Key: "query:q", Name: "q", ServerReachable: true, SegmentIndex: -1},
		{Kind: triage.KindCookie, Key: "cookie:sid", Name: "sid", ServerReachable: true, SegmentIndex: -1},
		{Kind: triage.KindPath, Key: "path:0:*", SegmentIndex: 0, ServerReachable: true},
		{Kind: triage.KindFragment, Key: "fragment:tab", Name: "tab", SegmentIndex: -1},
	} {
		if reqs := c.Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
			t.Errorf("%s: planned %d probes on a slot this class is not defined on", slot.Key, len(reqs))
		}
		vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
		if len(vs) != 1 {
			t.Fatalf("%s: got %d verdicts, want one", slot.Key, len(vs))
		}
		v := vs[0]
		if err := v.Validate(); err != nil {
			t.Errorf("%s: verdict failed its own contract: %v", slot.Key, err)
		}
		if v.State.CountsAsClean() {
			t.Errorf("%s: rendered clean on a slot this class never tested", slot.Key)
		}
		if v.Reason == "" {
			t.Errorf("%s: no reason, so an operator cannot tell 'ruled out' from 'nobody wired this up'", slot.Key)
		}
		if v.Class != triage.ClassCORS || v.SlotKey != slot.Key {
			t.Errorf("verdict stamped %s/%s, want %s/%s", v.Class, v.SlotKey, triage.ClassCORS, slot.Key)
		}
	}
}

// With no observations at all the class says an UNKNOWN and names which one. Not one path through
// Classify with an empty own-set may produce a clean.
func TestCORSWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindHeader, Key: "header:origin", Name: "origin",
		ServerReachable: true, SegmentIndex: -1}
	vs := (corsClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
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
	}
}

func TestEveryCORSProbeThePlannerAsksForIsDeclared(t *testing.T) {
	c := corsClassifier{}
	slot := triage.Slot{Kind: triage.KindHeader, Key: "header:origin", Name: "origin",
		ServerReachable: true, SegmentIndex: -1}
	all := append(corsPlanFor(corsRound0(), slot), corsPlanFor(corsRound1(), slot)...)
	if err := triage.PlannedProbesAreDeclared(c, all); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
	if len(all) != len(corsAllProbeIDs()) {
		t.Errorf("the two rounds plan %d probes and the class declares %d; a probe that is declared and never planned is dead weight in the cost model, and one planned and not declared was never isolation-checked",
			len(all), len(corsAllProbeIDs()))
	}
}

// EVERY REACHES ANSWER THAT IS NOT ALWAYS CARRIES A REASON. ValidateClassifier asserts it too;
// this asserts the reason is a SENTENCE rather than a token, because the reason becomes the
// not_applicable text an operator reads.
func TestEveryCORSReachabilityRefusalExplainsItself(t *testing.T) {
	c := corsClassifier{}
	for _, k := range triage.AllSlotKinds() {
		r := c.Reaches(k, "application/json")
		if r.Reach == triage.ReachAlways {
			t.Errorf("%s: this class is conditional everywhere it applies and never unconditional", k)
		}
		if len(r.Reason) < 40 {
			t.Errorf("%s: reason %q is too short to tell an operator anything", k, r.Reason)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE EXTENSION SURFACE
// ---------------------------------------------------------------------------------------------

// A CLASS WITH NO NEGATIVE ORACLE CASE HAS NOT BEEN TESTED, IT HAS BEEN DEMONSTRATED. The two
// negatives here are also the ones no naive implementation passes.
func TestCORSOracleCasesCarryAPositiveAndANegative(t *testing.T) {
	cases := (corsClassifier{}).OracleCases()
	var pos, neg, clean int
	seen := map[triage.ProbeID]bool{}
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if c.WantState == triage.StateClean {
			clean++
		}
		if c.Route == "" || c.Why == "" || c.WantState == "" {
			t.Errorf("oracle case %q is incomplete", c.Name)
		}
		for _, p := range c.Probes {
			seen[p] = true
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("%d positive and %d negative oracle cases; both are required", pos, neg)
	}
	if clean == 0 {
		t.Error("no oracle case expects CLEAN. A class whose fixtures only ever make it fire scores the same as one whose detector always returns true")
	}
	for _, id := range corsAllProbeIDs() {
		if !seen[id] {
			t.Errorf("probe %s appears in no oracle case, so nothing would ever verify it", id)
		}
	}
}

// THE BLIND SPOTS MUST BE ON EVERY VERDICT THAT GOT PAST ELIGIBILITY, including clean, or a clean
// from this class is read as covering prefix matching, the preflight and the null allowlist, none
// of which it measured.
//
// It is tested against corsBlindSpots directly rather than through Classify, because a test in
// this package cannot build a resolved route control and so cannot reach the rows that carry
// them. That is the same limitation corsBlindSpots exists to work around, and testing the
// function is what stops the sentences being deleted by a refactor nobody notices.
func TestCORSBlindSpotsAreStampedAndSayWhy(t *testing.T) {
	ann := map[string]any{}
	corsBlindSpots(ann)
	for _, key := range corsBlindSpotKeys() {
		v, ok := ann[key]
		if !ok {
			t.Errorf("corsBlindSpots did not stamp %q, so a clean from this class would be read as covering it", key)
			continue
		}
		text, _ := v.(string)
		if len(text) < 80 {
			t.Errorf("%s is %q, which is a label rather than an explanation. The point of the annotation is that an operator reading a clean can see what it does not cover", key, text)
		}
	}
	if len(ann) != len(corsBlindSpotKeys()) {
		t.Errorf("corsBlindSpots stamped %d annotations and corsBlindSpotKeys names %d; the two must not drift", len(ann), len(corsBlindSpotKeys()))
	}
}

// ---------------------------------------------------------------------------------------------
// FAIL FIRST: THE ROUND-1 GATE WITHHOLDS THE ONE PROBE THAT REACHES A LIST-PARSING ALLOWLIST
// ---------------------------------------------------------------------------------------------

// A DECLARED POSITIVE NO SENT PROBE CAN REACH IS A CLEAN WAITING TO HAPPEN. For every route this
// class declares as a positive, at least one of the probes it names must be in the set that goes
// out when round 0 found nothing at all, because a route whose bug is only reachable by a gated
// probe produces exactly the round-0 nothing that closes the gate.
func TestEveryCORSDeclaredPositiveHasAProbeThatIsSentWithoutAPriorHit(t *testing.T) {
	sent := map[triage.ProbeID]bool{}
	for _, id := range corsRound0() {
		sent[id] = true
	}
	// This mirrors Plan's round 1 exactly. An empty PlanCtx carries no round-0 response, which is
	// the state a route whose only sink needs a comma list leaves the gate in.
	for _, id := range corsRound1For(corsSawAnyReflection(triage.PlanCtx{})) {
		sent[id] = true
	}
	for _, c := range (corsClassifier{}).OracleCases() {
		if c.Expect != faExpectPositive {
			continue
		}
		reached := false
		for _, p := range c.Probes {
			if sent[p] {
				reached = true
			}
		}
		if !reached {
			t.Errorf("oracle case %q on %s is DECLARED A POSITIVE and names probes %v, not one of which is sent when round 0 found nothing. A route whose only bug is reachable by a gated probe answers round 0 with exactly the silence that closes the gate, so this class reports CLEAN on a positive it never sent a probe at",
				c.Name, c.Route, c.Probes)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE ROUND-1 GATE IS PER PROBE, BECAUSE ROUND 1 HOLDS TWO DIFFERENT KINDS OF PROBE
// ---------------------------------------------------------------------------------------------

// CORS-A3 IS DETAIL AND CORS-A4 IS A SECOND REFLECTION MECHANISM, and a gate that cannot tell
// them apart withholds the mechanism on exactly the evidence the mechanism exists to produce.
func TestTheCORSRoundOneGateIsPerProbeAndNotPerRound(t *testing.T) {
	has := func(ids []triage.ProbeID, want triage.ProbeID) bool {
		for _, id := range ids {
			if id == want {
				return true
			}
		}
		return false
	}

	withoutAHit := corsRound1For(false)
	if !has(withoutAHit, corsA4) {
		t.Errorf("round 1 with no round-0 reflection plans %v, which withholds %s. /cors/originlist sets %s ONLY when it can split the Origin header on a comma and parse the second entry, so round 0 is answered with no CORS header at all and a gate on 'did round 0 see a reflection' closes on the one route the probe exists for. Measured before the fix: clean, oracle no_acao_at_all, sent=3",
			withoutAHit, corsA4, corsACAO)
	}
	if has(withoutAHit, corsA3) {
		t.Errorf("round 1 with no round-0 reflection plans %s, which asks whether a port survived a grant that nothing returned. Ungating the detail probe as well would spend a request on a question that does not exist, and the gate is worth keeping for exactly the probe it is right about",
			corsA3)
	}

	withAHit := corsRound1For(true)
	for _, want := range []triage.ProbeID{corsA3, corsA4} {
		if !has(withAHit, want) {
			t.Errorf("round 1 after a reflection plans %v and omits %s", withAHit, want)
		}
	}
	if len(withAHit) != len(corsRound1()) {
		t.Errorf("corsRound1For(true) plans %d probes and corsRound1 names %d; the two must be the same set or the declaration check and the planner disagree", len(withAHit), len(corsRound1()))
	}
	for _, g := range corsRound1Gated() {
		for _, u := range corsRound1Ungated() {
			if g == u {
				t.Errorf("%s is both gated and ungated, so which behaviour it gets depends on the order the two lists are read", g)
			}
		}
	}
}

// A PROBE THAT IS THE ONLY WAY TO REACH A SINK MUST NOT SIT ABOVE THE TIER THE OPERATOR BOUGHT.
// The round gate and the tier were two independent ways to withhold the same probe, and fixing
// one while leaving the other would move the silent zero rather than close it.
func TestTheCORSListProbeIsAtTheTierTheOperatorActuallyGets(t *testing.T) {
	spec := map[triage.ProbeID]triage.ProbeSpec{}
	for _, p := range (corsClassifier{}).Probes() {
		spec[p.ID] = p
	}
	if got := spec[corsA4].Tier; got != triage.TierReduced {
		t.Errorf("%s is at tier %q. It is the only probe in this class that can reach a list-parsing allowlist, so at any tier above reduced an operator running a reduced sweep gets a clean on /cors/originlist and nothing on the coverage row says a mechanism was skipped",
			corsA4, got)
	}
	if got := spec[corsA3].Tier; got != triage.TierFull {
		t.Errorf("%s is at tier %q. It is detail about a reflection another probe already found, which is what the full tier is for; promoting it buys a request and no new sink", corsA3, got)
	}
}

// ---------------------------------------------------------------------------------------------
// NO CLEAN WHILE A DECLARED POSITIVE WAS NEVER PROBED AT
// ---------------------------------------------------------------------------------------------

func TestTheDeclaredPositiveGateNamesRoutesNoProbeReached(t *testing.T) {
	cases := []faOracleCase{
		{Name: "list", Route: "/cors/originlist", Expect: faExpectPositive, Probes: []triage.ProbeID{corsA4}},
		{Name: "port", Route: "/cors/portblind", Expect: faExpectPositive, Probes: []triage.ProbeID{corsA1, corsA3}},
		{Name: "correct", Route: "/cors/allowlist", Expect: faExpectNegative, Probes: []triage.ProbeID{corsA1}},
		{Name: "elsewhere", Route: "/hosthdr/nohttp", Expect: faExpectPositive, Probes: []triage.ProbeID{"HH-U2"}},
	}
	obs := func(ids ...triage.ProbeID) []faOwnObs {
		var out []faOwnObs
		for _, id := range ids {
			out = append(out, corsObs(id, "https://"+corsTestHost()))
		}
		return out
	}
	planned := []triage.ProbeID{corsA1, corsA2, corsA3, corsA4, corsNC1}

	for _, c := range []struct {
		name   string
		honest []faOwnObs
		want   int
		names  string
	}{
		{"every probe reached the wire", obs(corsA1, corsA2, corsA3, corsA4, corsNC1), 0, ""},
		{"the list probe never went out", obs(corsA1, corsA2, corsNC1), 1, "/cors/originlist"},
		{"one of the two probes behind a route is enough", obs(corsA1, corsA4), 0, ""},
		{"nothing at all went out", nil, 2, "/cors/originlist"},
	} {
		got := pcUnprobedDeclaredPositives(cases, planned, c.honest)
		if len(got) != c.want {
			t.Errorf("%s: %d unprobed positives %v, want %d", c.name, len(got), got, c.want)
			continue
		}
		if c.names != "" && !strings.Contains(strings.Join(got, " "), c.names) {
			t.Errorf("%s: the gate fired and did not name %s: %v", c.name, c.names, got)
		}
		// A NEGATIVE ROUTE IS NEVER THE REASON FOR AN UNKNOWN. The rule is about positives: a
		// route built to keep the class silent tells us nothing when no probe reached it.
		if strings.Contains(strings.Join(got, " "), "/cors/allowlist") {
			t.Errorf("%s: the gate named a route declared as a NEGATIVE, which would turn 'we did not test the silent route' into an unknown on every slot", c.name)
		}
		// A ROUTE NO PROBE OF THIS SLOT CAN REACH IS NOT THIS SLOT'S QUESTION.
		if strings.Contains(strings.Join(got, " "), "/hosthdr/") {
			t.Errorf("%s: the gate named a route whose probes are not planned on this slot at all: %v", c.name, got)
		}
	}
}

// A PROBE IS SCORED ONLY AGAINST HOSTS IT ACTUALLY SENT, IN BOTH DIRECTIONS. The x-prefixed host
// is the second entry of CORS-A4's list and appears in no other payload. Offering it to every
// probe gives the other four an oracle they never put on the wire, which is the same defect
// HOSTHDR's control had, pointing the other way: there it lost a hit, here it would invent one.
func TestOnlyTheListProbeIsScoredAgainstTheListsSecondHost(t *testing.T) {
	second := "https://x" + corsTestHost()
	for _, id := range []triage.ProbeID{corsA1, corsA2, corsA3, corsNC1} {
		rs := corsRead([]faOwnObs{corsObs(id, "https://"+corsTestHost(), [2]string{corsACAO, second})}, "")
		if rs[0].reflectedOurHost {
			t.Errorf("%s never sends %s and was scored as having had it granted. No application can build that host out of what this probe sent, so a hit is a rewrite or a foreign response and never this probe's finding",
				id, second)
		}
	}
	rs := corsRead([]faOwnObs{corsObs(corsA4,
		"https://"+corsTestHost()+", "+second, [2]string{corsACAO, second})}, "")
	if !rs[0].reflectedOurHost {
		t.Errorf("%s does send %s as the second entry of its list, and a grant naming it is the whole point of the probe", corsA4, second)
	}
}
