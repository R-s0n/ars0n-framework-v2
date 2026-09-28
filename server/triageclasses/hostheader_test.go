package triageclasses

import (
	"strconv"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

const hhTestMarker triage.Marker = "zqj0000000000def"

const hhTestBase = "http://app.example.test/reset"

func hhTestHost() string { return string(hhTestMarker) + hhHostSuffix }

// hhObs builds one of this class's own observations as the vault would hand it over. The body,
// the status and the Location are the three things every detector in this class reads.
func hhObs(id triage.ProbeID, sent string, status int, body, location string) faOwnObs {
	o := triage.Observation{
		ObsID: "obs-" + string(id), Status: status, FinalURL: hhTestBase,
		Body: []byte(body), BodyLen: len(body),
		Payload: triage.PayloadWire{
			Logical: []byte(sent), Wire: []byte(sent), Survived: triage.WireSurvivalIntact,
		},
	}
	if location != "" {
		o.RedirectChain = []triage.Hop{{Status: status, Location: location}}
	}
	return faOwnObs{ProbeID: id, Ordinal: 20, Marker: hhTestMarker, Obs: o}
}

func TestTheHostHeaderClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassHostHeader)
	if !ok {
		t.Fatal("the HOSTHDR classifier did not register itself, so the class produces no rows and no row looks the same as no bug")
	}
	if c.ID() != triage.ClassHostHeader {
		t.Fatalf("registered under %s but reports %s", triage.ClassHostHeader, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes with HOSTHDR registered", rep.ClassesChecked, rep.ProbesChecked)
}

func TestEveryHostHeaderPayloadCarriesTheMarkerPlaceholder(t *testing.T) {
	for _, p := range (hostHeaderClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("probe %s payload %q spells no marker placeholder, so the host it names carries no attribution and nothing it produces can be scored",
				p.ID, p.Logical)
		}
		if p.MarkerPos != "" {
			t.Errorf("probe %s declares MarkerPos %q while spelling its own marker; the runner honours MarkerPos only for an opted-in class", p.ID, p.MarkerPos)
		}
	}
}

func TestTheHostHeaderClassDoesNotOptIntoRunnerPlacedMarkers(t *testing.T) {
	var c any = hostHeaderClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("HOSTHDR opted into runner-placed markers. A prefixed marker turns a bare authority into a different hostname and https:// into a relative path, so every payload would name a host the oracle is not looking for")
	}
}

// ---------------------------------------------------------------------------------------------
// THE ORACLE TABLE. POSITION IS THE WHOLE CLASS.
// ---------------------------------------------------------------------------------------------

// THIS IS THE TEST THAT DECIDES WHETHER HOSTHDR IS A DETECTOR OR A REFLECTION ALARM. Every row
// below contains our exact host somewhere in the body. Only the ones where it is the AUTHORITY of
// a URL may score, and the rest are the false positives a naive implementation ships.
func TestTheHostHeaderOracleScoresAuthorityPositionAndNothingElse(t *testing.T) {
	h := hhTestHost()
	for _, c := range []struct {
		name      string
		body      string
		authority bool
	}{
		{"an absolute https URL", `<a href="https://` + h + `/reset?t=1">reset</a>`, true},
		{"an absolute http URL", `click http://` + h + `/x`, true},
		{"a scheme-relative URL", `<script src="//` + h + `/a.js">`, true},
		{"userinfo in front of our host", `https://app.example.test@` + h + `/`, true},
		{"a bare form action", `<form action="https://` + h + `">`, true},

		{"printed into a debug block", `X-Forwarded-Host: ` + h, false},
		{"printed as a JSON string field", `{"host":"` + h + `"}`, false},
		{"printed inside prose", `the host you asked for was ` + h + ` and we do not serve it`, false},
		{"our host as the PATH of an on-origin URL", `https://app.example.test/redir/` + h, false},
		{"our host in a query value", `https://app.example.test/go?to=` + h, false},
		{"our host as the head of a longer name", `https://` + h + `.evil.test/`, false},
		{"a different marker's host in authority position", `https://zqj9999999999xyz` + hhHostSuffix + `/`, false},
		{"nothing at all", `nothing to see here`, false},
	} {
		rs := hhRead([]faOwnObs{hhObs(hhA1, h, 200, c.body, "")})
		if len(rs) != 1 {
			t.Fatalf("%s: hhRead returned %d readings", c.name, len(rs))
		}
		if rs[0].inBodyAuthority != c.authority {
			t.Errorf("%s: body %q read as authority=%v, want %v. Our host printed as text and our host as a URL's authority are the same bytes, and the difference is the entire class",
				c.name, c.body, rs[0].inBodyAuthority, c.authority)
		}
	}
}

// A Location is scored only on a redirect status. Without this rule the class fires on every API
// that echoes a Location into a successful response, and no browser follows one.
func TestAHostHeaderLocationIsOnlyScoredOnARedirectStatus(t *testing.T) {
	h := hhTestHost()
	loc := "https://" + h + "/next"
	if rs := hhRead([]faOwnObs{hhObs(hhA1, h, 302, "", loc)}); !rs[0].inLocationAuthority {
		t.Error("a 302 whose Location names our host was not scored")
	}
	if rs := hhRead([]faOwnObs{hhObs(hhA1, h, 200, "", loc)}); rs[0].inLocationAuthority {
		t.Error("a Location on a 200 was scored as a redirect. No browser follows it, and scoring it makes every API that echoes a Location into a successful response a finding")
	}
	if rs := hhRead([]faOwnObs{hhObs(hhA1, h, 304, "", loc)}); rs[0].inLocationAuthority {
		t.Error("a 304 was treated as a redirect; Not Modified carries no Location and every conditional GET on a cached asset would read as one")
	}
	// An on-origin Location is the correct behaviour and must stay silent.
	if rs := hhRead([]faOwnObs{hhObs(hhA1, h, 302, "", "/login?next=%2F%2F"+h)}); rs[0].inLocationAuthority {
		t.Error("an origin-absolute Location carrying our host inside a QUERY VALUE was scored; the marker being in the Location is not the marker being the Location's authority")
	}
}

// Reflection without authority is a CLEAN with a stronger annotation, never a finding. The two
// readings are deliberately separate fields for exactly this reason.
func TestReflectionWithoutAuthorityIsRecordedAndNotScored(t *testing.T) {
	h := hhTestHost()
	rs := hhRead([]faOwnObs{hhObs(hhA1, h, 200, "you asked for "+h, "")})
	if rs[0].inBodyAuthority {
		t.Fatal("plain reflection scored as an authority")
	}
	if !rs[0].inBodyAnywhere {
		t.Error("plain reflection was not even recorded, so a clean could not tell 'the application does not read this header' from 'it reads it and prints it safely', which are different facts")
	}
}

// ---------------------------------------------------------------------------------------------
// PER-HEADER PAYLOAD CHOICE
// ---------------------------------------------------------------------------------------------

// A BARE AUTHORITY IN X-Original-URL IS A RELATIVE PATH AND TESTS NOTHING, and an absolute URL in
// Host is not an authority. The class must not spend a request asking a header a question it
// cannot be asked.
func TestHostHeaderPayloadsAreChosenByHeaderShape(t *testing.T) {
	for _, c := range []struct {
		header string
		want   []triage.ProbeID
	}{
		{"host", []triage.ProbeID{hhA1, hhNC1}},
		{"x-forwarded-host", []triage.ProbeID{hhA1, hhNC1}},
		{"x-original-host", []triage.ProbeID{hhA1, hhNC1}},
		{"x-host", []triage.ProbeID{hhA1, hhNC1}},
		{"x-forwarded-server", []triage.ProbeID{hhA1, hhNC1}},
		{"x-original-url", []triage.ProbeID{hhU1, hhNC1}},
		{"x-rewrite-url", []triage.ProbeID{hhU1, hhNC1}},
		{"X-Forwarded-Host", []triage.ProbeID{hhA1, hhNC1}}, // names arrive lowercased, but the match must not depend on it
		{"x-real-ip", nil},
		{"user-agent", nil},
		{"", nil},
	} {
		got := hhProbesFor(c.header, 0)
		if len(got) != len(c.want) {
			t.Errorf("%s: round 0 plans %v, want %v", c.header, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: round 0 plans %v, want %v", c.header, got, c.want)
				break
			}
		}
	}
	// Every probe the class declares must be planned somewhere, or it is dead weight in the cost
	// model and was isolation-checked for nothing.
	planned := map[triage.ProbeID]bool{}
	for _, h := range append(hhAuthorityHeaders(), hhURLHeaders()...) {
		for _, id := range hhPlannedFor(h) {
			planned[id] = true
		}
	}
	for _, id := range hhAllProbeIDs() {
		if !planned[id] {
			t.Errorf("probe %s is declared and planned on no header at all", id)
		}
	}
}

func TestEveryHostHeaderProbeThePlannerAsksForIsDeclared(t *testing.T) {
	c := hostHeaderClassifier{}
	for _, h := range append(hhAuthorityHeaders(), hhURLHeaders()...) {
		slot := triage.Slot{Kind: triage.KindHeader, Key: triage.SlotKey("header:" + h), Name: h,
			ServerReachable: true, SegmentIndex: -1}
		reqs := append(hhPlanFor(hhProbesFor(h, 0), slot), hhPlanFor(hhProbesFor(h, 1), slot)...)
		if err := triage.PlannedProbesAreDeclared(c, reqs); err != nil {
			t.Errorf("%s: PlannedProbesAreDeclared: %v", h, err)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// ELIGIBILITY AND THE UNKNOWNS
// ---------------------------------------------------------------------------------------------

func TestHostHeaderIsNotApplicableOffItsHeadersAtZeroCost(t *testing.T) {
	c := hostHeaderClassifier{}
	for _, slot := range []triage.Slot{
		{Kind: triage.KindHeader, Key: "header:user-agent", Name: "user-agent", ServerReachable: true, SegmentIndex: -1},
		{Kind: triage.KindQuery, Key: "query:next", Name: "next", ServerReachable: true, SegmentIndex: -1},
		{Kind: triage.KindCookie, Key: "cookie:sid", Name: "sid", ServerReachable: true, SegmentIndex: -1},
		{Kind: triage.KindFragment, Key: "fragment:tab", Name: "tab", SegmentIndex: -1},
	} {
		if reqs := c.Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
			t.Errorf("%s: planned %d probes on a slot this class is not defined on", slot.Key, len(reqs))
		}
		vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
		if len(vs) != 1 {
			t.Fatalf("%s: got %d verdicts, want one", slot.Key, len(vs))
		}
		if vs[0].State.CountsAsClean() {
			t.Errorf("%s: rendered clean on a slot this class never tested", slot.Key)
		}
		if err := vs[0].Validate(); err != nil {
			t.Errorf("%s: verdict failed its own contract: %v", slot.Key, err)
		}
	}
}

func TestHostHeaderWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindHeader, Key: "header:x-forwarded-host", Name: "x-forwarded-host",
		ServerReachable: true, SegmentIndex: -1}
	vs := (hostHeaderClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
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
			t.Errorf("state %q is not an unknown", v.State)
		}
		if v.Class != triage.ClassHostHeader || v.SlotKey != slot.Key {
			t.Errorf("verdict stamped %s/%s, want %s/%s", v.Class, v.SlotKey, triage.ClassHostHeader, slot.Key)
		}
	}
}

// With no route control nothing is planned, and the verdict names the CONTROL as the problem
// rather than the cache. The gate itself is tested exhaustively in cors_test.go, where
// pcSharedCacheRiskOf lives; the row asserted here is that HOSTHDR asks it and that an unresolved
// control does not become a cache refusal with the wrong reason on it.
func TestHostHeaderPlansNothingWithNoControlAndSaysWhichUnknownItIs(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindHeader, Key: "header:x-forwarded-host", Name: "x-forwarded-host",
		ServerReachable: true, SegmentIndex: -1}
	if reqs := (hostHeaderClassifier{}).Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
		t.Errorf("planned %d probes with no route control and therefore no cacheability evidence", len(reqs))
	}
	vs := (hostHeaderClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if vs[0].State.CountsAsClean() {
		t.Error("a slot with no control rendered as clean")
	}
	if !strings.Contains(vs[0].Reason, "route_unresolved") {
		t.Errorf("the verdict names the wrong unknown: %q", vs[0].Reason)
	}
}

// AND THE GATE MUST NOT SILENCE THIS CLASS ON AN ORDINARY ENDPOINT. This is the regression the
// full-registry run caught: planned=0 sent=0 for HOSTHDR and CORS on every vector, because the
// first cut of the gate refused any response that did not explicitly forbid caching. A response
// with no cache directives at all is the common case and must be probed.
func TestHostHeaderIsNotSilencedByTheCacheGateOnAnOrdinaryEndpoint(t *testing.T) {
	plain := triage.Observation{ObsID: "route", Status: 200, BodyLen: 1, ReqMethod: "GET"}
	if why, risky := pcSharedCacheRiskOf(plain); risky {
		t.Errorf("a plain 200 with no cache headers was refused (%s). That refusal silenced this class on every vector of the oracle fixture, and an operator who enables a class and sees nothing reads it as 'no bug of this class here'", why)
	}
}

// ---------------------------------------------------------------------------------------------
// THE HONEST BLIND SPOT
// ---------------------------------------------------------------------------------------------

// THE EMAIL SIDE CHANNEL IS THE MOST VALUABLE FORM OF THIS BUG AND IT IS INVISIBLE HERE. The class
// must SAY so rather than let a clean imply coverage, and the sentence must be long enough to be
// an explanation rather than a label.
func TestTheEmailBlindSpotIsStatedRatherThanImplied(t *testing.T) {
	var found *faConfirmer
	for i, c := range (hostHeaderClassifier{}).Confirmers() {
		if strings.Contains(c.Name, "email") {
			cs := (hostHeaderClassifier{}).Confirmers()
			found = &cs[i]
		}
	}
	if found == nil {
		t.Fatal("no confirmer requires the email blind spot to be annotated. Without it a clean from this class is read as covering the password-reset exploit, which is the form of this bug that actually gets paid")
	}
	if !strings.Contains(strings.ToLower(found.Rule), "clean") {
		t.Errorf("the email confirmer does not say the annotation belongs on a CLEAN, which is the only state where its absence misleads: %q", found.Rule)
	}
	var e *faEvidencer
	for i, x := range (hostHeaderClassifier{}).Evidencers() {
		if x.Name == "email_side_channel_not_measured" {
			es := (hostHeaderClassifier{}).Evidencers()
			e = &es[i]
		}
	}
	if e == nil {
		t.Error("the email blind spot is in no evidencer, so it would not reach the operator's view of the row")
	}
}

func TestHostHeaderOracleCasesCarryAPositiveAndANegative(t *testing.T) {
	cases := (hostHeaderClassifier{}).OracleCases()
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
		t.Error("no oracle case expects CLEAN. A detector only ever observed firing scores the same as one that always returns true")
	}
	for _, id := range hhAllProbeIDs() {
		if !seen[id] {
			t.Errorf("probe %s appears in no oracle case", id)
		}
	}
}

func TestEveryHostHeaderReachabilityRefusalExplainsItself(t *testing.T) {
	c := hostHeaderClassifier{}
	for _, k := range triage.AllSlotKinds() {
		r := c.Reaches(k, "application/json")
		if r.Reach == triage.ReachAlways {
			t.Errorf("%s: this class is conditional where it applies and never unconditional", k)
		}
		if len(r.Reason) < 40 {
			t.Errorf("%s: reason %q is too short to tell an operator anything", k, r.Reason)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// FAIL FIRST: THE INERT CONTROL'S ORACLE SEARCHES FOR A STRING THE INERT CONTROL NEVER SENDS
// ---------------------------------------------------------------------------------------------

// HH-NC1's payload is "hh-<marker>-inert". hhRead builds the needle as "<marker>.hh.invalid" for
// EVERY probe, so the control's detector looks for bytes the control did not put on the wire and
// cannot match whatever the application does. MEASURED against the oracle: /hosthdr/wrapinert
// answers {"site":"https://hh-<marker>-inert/"} and the control still reads as not fired.
func TestTheInertControlIsScoredAgainstWhatItActuallySent(t *testing.T) {
	inert := "hh-" + string(hhTestMarker) + "-inert"
	body := `{"ok":true,"site":"https://` + inert + `/"}`
	rs := hhRead([]faOwnObs{hhObs(hhNC1, inert, 200, body, "")})
	if !rs[0].inBodyAuthority {
		t.Errorf("the inert control's value %q came back as the AUTHORITY of a URL in %q and the reading is inBodyAuthority=false. The needle hhRead searched for is %q, which HH-NC1 never sends, so the control gate is structurally unreachable and a control that can never fire reads as a control that passed",
			inert, body, string(hhTestMarker)+hhHostSuffix)
	}
	loc := "https://" + inert + "/account/reset"
	rl := hhRead([]faOwnObs{hhObs(hhNC1, inert, 302, "", loc)})
	if !rl[0].inLocationAuthority {
		t.Errorf("the inert control's value is the authority of a 302 Location (%q) and the reading is inLocationAuthority=false, for the same reason", loc)
	}
}

// EVERY PROBE IS SCORED AGAINST ITS OWN PAYLOAD, AND THE TABLE IS DERIVED FROM THE DECLARATIONS
// RATHER THAN RETYPED. A needle rebuilt from the marker is right for four of the five probes and
// silently wrong for the fifth, which is precisely the failure that made the control unreachable,
// so the assertion has to run over the probe list and not over a hand-picked example.
func TestEveryHostHeaderProbeIsScoredAgainstTheAuthorityItActuallySends(t *testing.T) {
	m := string(hhTestMarker)
	want := map[triage.ProbeID]string{
		hhA1:  m + hhHostSuffix,
		hhA2:  m + hhHostSuffix,
		hhU1:  m + hhHostSuffix,
		hhU2:  m + hhHostSuffix,
		hhNC1: "hh-" + m + "-inert",
	}
	for _, p := range (hostHeaderClassifier{}).Probes() {
		sent := strings.ReplaceAll(string(p.Logical), triage.MarkerPlaceholder, m)
		got := hhAuthorityNeedle(sent, hhTestMarker)
		if got != want[p.ID] {
			t.Errorf("%s sends %q and is scored against %q, want %q. A probe scored against a string it does not send has an oracle that cannot match whatever the application does",
				p.ID, sent, got, want[p.ID])
		}
		if got == "" || !strings.Contains(got, m) {
			t.Errorf("%s is scored against %q, which carries no marker, so a hit could not be attributed to this probe", p.ID, got)
		}
		// AND THE BODY THE APPLICATION WOULD BUILD FROM IT MUST SCORE. This is the end-to-end
		// version of the same claim: wrap what the probe sent in a scheme and the reading must
		// come back true, for every probe in the class rather than for the four that happen to
		// name a host under the suffix.
		body := `{"ok":true,"site":"https://` + got + `/next"}`
		rs := hhRead([]faOwnObs{hhObs(p.ID, sent, 200, body, "")})
		if !rs[0].inBodyAuthority {
			t.Errorf("%s: %q wrapped into %q did not read as an authority", p.ID, sent, body)
		}
	}
}

// A needle must not be invented out of a response that carries no marker of ours, and a probe
// whose payload was rewritten into something unattributable scores nothing rather than guessing.
func TestTheHostHeaderNeedleRefusesAnUnattributableValue(t *testing.T) {
	if got := hhAuthorityNeedle("https://somebody.else.test/", hhTestMarker); got != "" {
		t.Errorf("a value carrying none of this probe's marker was scored against %q; a hit on that is another probe's, another run's, or the application's own host", got)
	}
	if got := hhAuthorityNeedle("", hhTestMarker); got != "" {
		t.Errorf("an empty payload produced the needle %q", got)
	}
	if got := hhAuthorityNeedle("https://user@"+hhTestHost()+":8443/x?y#z", hhTestMarker); got != hhTestHost() {
		t.Errorf("userinfo, port, path, query and fragment were not stripped: %q", got)
	}
}

// ---------------------------------------------------------------------------------------------
// THE CONTROL'S TWO ANSWERS
// ---------------------------------------------------------------------------------------------

func hhRunControl(t *testing.T, rs []hhReading) (triage.ClassVerdict, bool) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHostHeader, "header:x-forwarded-host", state, reason, oracle, grade, ords, ann, hhLabel(ann))
	}
	v, ok := hhControlVerdict(rs, "x-forwarded-host", ann, []uint64{20}, nil, one)
	if !ok {
		return triage.ClassVerdict{}, false
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("verdict failed its own contract: %v", err)
	}
	return v[0], true
}

// A CONTROL THAT WRAPS AND A CONTROL THAT IS REWRITTEN ARE DIFFERENT FACTS AND GET DIFFERENT
// ANSWERS. The old code had one arm for both, reachable by neither.
func TestTheControlSeparatesARewriteFromAnUnvalidatedSink(t *testing.T) {
	inert := "hh-" + string(hhTestMarker) + "-inert"
	nc := func(mut func(*hhReading)) hhReading {
		r := hhReading{probe: hhNC1, ordinal: 20, sent: inert, host: inert, isControl: true, status: 200}
		mut(&r)
		return r
	}
	payload := hhReading{probe: hhA1, ordinal: 21, sent: hhTestHost(), host: hhTestHost(),
		status: 200, inBodyAuthority: true, inBodyAnywhere: true}

	for _, c := range []struct {
		name      string
		rs        []hhReading
		fires     bool
		wantState triage.TriageState
		wantGrade triage.TriageGrade
		wantOracl string
		reasonHas string
	}{
		{
			name:  "the control's own value became an authority in the body",
			rs:    []hhReading{nc(func(r *hhReading) { r.inBodyAuthority = true; r.inBodyAnywhere = true }), payload},
			fires: true, wantState: triage.StateFinding, wantGrade: triage.GradeHigh,
			wantOracl: "routing_header_in_url_authority_unconditional",
			reasonHas: "not a hostname",
		},
		{
			name: "the control's own value became the authority of a 302 Location",
			rs: []hhReading{nc(func(r *hhReading) {
				r.status = 302
				r.inLocationAuthority = true
				r.location = "https://" + inert + "/account/reset"
			})},
			fires: true, wantState: triage.StateFinding, wantGrade: triage.GradeHigh,
			wantOracl: "routing_header_in_location_unconditional",
			reasonHas: "Location",
		},
		{
			name:  "a host we never sent appeared in an authority",
			rs:    []hhReading{nc(func(r *hhReading) { r.fabricatedSuffix = true })},
			fires: true, wantState: triage.StateCannotDetermine, wantGrade: triage.GradeUnrated,
			wantOracl: "", reasonHas: "value_rewritten",
		},
		{
			name:  "a rewrite outranks an unvalidated sink, because nothing on the slot is trustworthy",
			rs:    []hhReading{nc(func(r *hhReading) { r.fabricatedSuffix = true; r.inBodyAuthority = true })},
			fires: true, wantState: triage.StateCannotDetermine, wantGrade: triage.GradeUnrated,
			wantOracl: "", reasonHas: "value_rewritten",
		},
		{
			name:  "THE NEGATIVE: the control came back as plain text and never as an authority",
			rs:    []hhReading{nc(func(r *hhReading) { r.inBodyAnywhere = true }), payload},
			fires: false,
		},
		{
			name:  "THE OTHER NEGATIVE: the control did not come back at all",
			rs:    []hhReading{nc(func(r *hhReading) {}), payload},
			fires: false,
		},
		{
			name:  "a PAYLOAD probe in authority position is not the control firing",
			rs:    []hhReading{payload},
			fires: false,
		},
	} {
		v, fired := hhRunControl(t, c.rs)
		if fired != c.fires {
			t.Errorf("%s: fired=%v want %v (%s / %s)", c.name, fired, c.fires, v.State, v.Oracle)
			continue
		}
		if !c.fires {
			continue
		}
		if v.State != c.wantState || v.Grade != c.wantGrade || v.Oracle != c.wantOracl {
			t.Errorf("%s: got state=%s grade=%s oracle=%s, want state=%s grade=%s oracle=%s",
				c.name, v.State, v.Grade, v.Oracle, c.wantState, c.wantGrade, c.wantOracl)
		}
		if !strings.Contains(v.Reason, c.reasonHas) {
			t.Errorf("%s: the reason does not say %q: %s", c.name, c.reasonHas, v.Reason)
		}
	}
}

// AN UNCONDITIONAL SINK IS STILL A FINDING AND THE REASON MUST SAY WHAT IT COSTS. A verdict that
// claimed the URL was built from a host-shaped payload would be claiming attribution the route
// cannot give; one that said cannot_determine would silence the commonest real form of this bug.
func TestTheUnconditionalFindingStatesTheAttributionItCannotMake(t *testing.T) {
	inert := "hh-" + string(hhTestMarker) + "-inert"
	v, fired := hhRunControl(t, []hhReading{
		{probe: hhNC1, ordinal: 20, sent: inert, host: inert, isControl: true, status: 200, inBodyAuthority: true},
		{probe: hhA1, ordinal: 21, sent: hhTestHost(), host: hhTestHost(), status: 200, inBodyAuthority: true},
	})
	if !fired {
		t.Fatal("the unconditional arm did not fire")
	}
	if v.State != triage.StateFinding {
		t.Errorf("state %s. /hosthdr/absurl and /hosthdr/wrapinert are the same handler shape, measured by hand, so a cannot_determine here is a cannot_determine on the password-reset template that concatenates the header with no check, which is the form of this bug that gets paid", v.State)
	}
	for _, phrase := range []string{"attribution", "unconditional"} {
		if !strings.Contains(strings.ToLower(v.Reason), phrase) {
			t.Errorf("the reason does not say %q, so a reader would take the finding as proof the sink is selective about our host: %s", phrase, v.Reason)
		}
	}
	arms, _ := v.Annotations["payload_arms_that_also_reached_an_authority"].([]string)
	if len(arms) != 1 || !strings.Contains(arms[0], string(hhA1)) {
		t.Errorf("the payload arm that also reached an authority was not recorded (%v), so the arm the class would have reported on a selective sink is lost behind the control's answer", arms)
	}
	if v.Evidence.Ordinal != 20 {
		t.Errorf("the evidence points at ordinal %d rather than at the control's response, which is the one that carries the proof", v.Evidence.Ordinal)
	}
}

// THE DECLARED-POSITIVE GATE IS SCOPED TO THE HEADER THIS SLOT PLANS. Without the scope it would
// demand HH-U1 and HH-U2 on X-Forwarded-Host, where they are never planned, and turn every clean
// on an authority header into an unknown.
func TestTheHostHeaderDeclaredPositiveGateIsScopedToThePlannedHeader(t *testing.T) {
	cases := (hostHeaderClassifier{}).OracleCases()
	obs := func(ids ...triage.ProbeID) []faOwnObs {
		var out []faOwnObs
		for _, id := range ids {
			out = append(out, hhObs(id, hhTestHost(), 200, "", ""))
		}
		return out
	}
	if got := pcUnprobedDeclaredPositives(cases, hhPlannedFor("x-forwarded-host"), obs(hhA1, hhA2, hhNC1)); len(got) != 0 {
		t.Errorf("an authority header with every probe it plans on the wire was still told it had missed a declared positive: %v", got)
	}
	if got := pcUnprobedDeclaredPositives(cases, hhPlannedFor("x-rewrite-url"), obs(hhU1, hhU2, hhNC1)); len(got) != 0 {
		t.Errorf("a URL header with every probe it plans on the wire was still told it had missed a declared positive: %v", got)
	}
	// AND IT MUST STILL FIRE WHEN THE HEADER'S OWN FAMILY NEVER WENT OUT.
	got := pcUnprobedDeclaredPositives(cases, hhPlannedFor("x-rewrite-url"), obs(hhNC1))
	if len(got) == 0 {
		t.Error("a URL header where neither HH-U1 nor HH-U2 reached the wire was allowed to reach a clean; nothing was measured about the only sink those probes can reach")
	}
}

// ---------------------------------------------------------------------------------------------
// ROUND 8: THE CLEAN MAY NOT DENY WHAT THIS CLASS'S OWN PLANNER SAW
// ---------------------------------------------------------------------------------------------

// hhRunClean drives the negative half of Classify the way hhRunControl drives the control half,
// and for the same reason: a test in this package cannot build a resolved Replay, so a block
// living inline in Classify can only be read by eye. An arm that could only be read by eye is
// exactly the arm this round is here to fix.
func hhRunClean(t *testing.T, rs []hhReading, sent int) (triage.ClassVerdict, map[string]any) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade,
		ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHostHeader, "header:x-forwarded-host", state, reason,
			oracle, grade, ords, ann, hhLabel(ann))
	}
	v := hhCleanVerdict(rs, "x-forwarded-host", sent, ann, []uint64{20}, nil, one)
	if len(v) != 1 {
		t.Fatalf("want exactly one verdict row, got %d", len(v))
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("verdict failed its own contract: %v", err)
	}
	return v[0], ann
}

// THE CLASS CONTRADICTED ITSELF INSIDE ONE VERDICT.
//
// MATRIX B /hosthdr/loc200: the handler is hostHdrLocationHandler(http.StatusOK), which sets
// "Location: https://" + the routing header + "/account/reset" and answers 200. Curled by hand:
// X-Forwarded-Host: canary.example comes back as Location: https://canary.example/account/reset.
// The class reported clean at oracle no_authority_from_this_header, whose reason reads "Nothing
// we put in this header came back in any form".
//
// It is not a reading the class failed to take. hhSawAnyReach reads Location ungated by status,
// returned true, and bought round 1 on the strength of it, which is why that cell shows sent=11
// against sent=10 on a route where nothing came back. The class spent two extra requests because
// it saw the value, and then reported that it saw nothing.
func TestTheHostHeaderCleanDoesNotDenyALocationItActuallyGot(t *testing.T) {
	h := hhTestHost()
	loc := "https://" + h + "/account/reset"
	inert := "hh-" + string(hhTestMarker) + "-inert"
	rs := hhRead([]faOwnObs{
		hhObs(hhA1, h, 200, `{"ok":true}`, loc),
		hhObs(hhNC1, inert, 200, `{"ok":true}`, "https://"+inert+"/account/reset"),
		hhObs(hhA2, h+":8443", 200, `{"ok":true}`, "https://"+h+":8443/account/reset"),
	})
	v, ann := hhRunClean(t, rs, 3)
	if strings.Contains(v.Reason, "Nothing we put in this header came back in any form") {
		t.Errorf("the clean still says nothing came back, on a route that answered every probe with "+
			"a Location whose authority is the host we named: %s", v.Reason)
	}
	if v.Oracle == "no_authority_from_this_header" {
		t.Errorf("the clean still files this under the weaker oracle that means the application may "+
			"not read the header. It reads it and builds an absolute URL out of it: %s", v.Reason)
	}
	for _, want := range []string{"Location", "200"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("the clean does not name %q, so a reader cannot tell which channel carried the "+
				"value or why it was not scored: %s", want, v.Reason)
		}
	}
	lines, _ := ann["clean_preconditions"].([]string)
	joined := strings.Join(lines, " | ")
	if strings.Contains(joined, "no response carried a Location resolving, under either model, to a host under") {
		t.Errorf("the precondition list asserts that no response carried such a Location. One did, "+
			"on a status no client follows, and a precondition is read as a check that passed: %s", joined)
	}
}

// AND THE STATE STAYS CLEAN, WHICH IS A DECISION ABOUT THE PROTOCOL AND NOT A GUESS. 300, 301,
// 302, 303, 305, 307 and 308 are the statuses a client follows a Location on. /hosthdr/loc200 is
// the negative control for exactly that line, and promoting it would make every API that echoes a
// Location into a successful response a row an operator has to read.
func TestALocationOnANonRedirectIsStillNotAFinding(t *testing.T) {
	h := hhTestHost()
	rs := hhRead([]faOwnObs{hhObs(hhA1, h, 200, `{"ok":true}`, "https://"+h+"/account/reset")})
	v, _ := hhRunClean(t, rs, 2)
	if !v.State.CountsAsClean() {
		t.Errorf("state %s. No client acts on a Location carried by a 200, so there is no redirect "+
			"to report and this route is the class's own negative control for that: %s",
			v.State, v.Reason)
	}
}

// THE OTHER DIRECTION, AND IT IS THE ONE THAT KEEPS THE ROW WORTH READING. On a route where
// nothing came back at all, the sentence that says so is TRUE and must survive.
func TestTheHostHeaderCleanStillSaysNothingCameBackWhenNothingDid(t *testing.T) {
	h := hhTestHost()
	rs := hhRead([]faOwnObs{
		hhObs(hhA1, h, 200, `{"ok":true,"items":[]}`, ""),
		hhObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert", 200, `{"ok":true,"items":[]}`, ""),
	})
	v, _ := hhRunClean(t, rs, 2)
	if v.Oracle != "no_authority_from_this_header" {
		t.Errorf("oracle %q, want no_authority_from_this_header on a route that echoed nothing: %s",
			v.Oracle, v.Reason)
	}
	if !strings.Contains(v.Reason, "Nothing we put in this header came back in any form") {
		t.Errorf("the weaker clean lost the sentence that is true here: %s", v.Reason)
	}
}

// AND A PLAIN BODY REFLECTION KEEPS ITS OWN ORACLE. /hosthdr/echo is the most important negative
// in the class and this round must not move it.
func TestTheHostHeaderReflectionCleanIsUnchanged(t *testing.T) {
	h := hhTestHost()
	rs := hhRead([]faOwnObs{
		hhObs(hhA1, h, 200, `{"debug":{"forwarded_host":"`+h+`"}}`, ""),
		hhObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert", 200, `{"debug":{}}`, ""),
	})
	v, _ := hhRunClean(t, rs, 2)
	if v.Oracle != "reflected_but_never_an_authority" {
		t.Errorf("oracle %q, want reflected_but_never_an_authority: %s", v.Oracle, v.Reason)
	}
}

// THE THIRD CHANNEL. A value that comes back in an ordinary response header and nowhere else is
// neither silence nor a URL authority, and the shipped clean had no word for it either.
func TestTheHostHeaderCleanNamesAResponseHeaderThatCarriedOurValue(t *testing.T) {
	h := hhTestHost()
	o := hhObs(hhA1, h, 200, `{"ok":true}`, "")
	o.Obs.RespHeaders = [][2]string{
		{"Content-Type", "application/json"},
		{"X-Upstream-Host", h},
		{"Date", "Sun, 20 Sep 2026 07:39:10 GMT"},
	}
	rs := hhRead([]faOwnObs{o})
	v, ann := hhRunClean(t, rs, 2)
	if v.Oracle != "reflected_in_a_response_header_never_an_authority" {
		t.Errorf("oracle %q: the value came back in x-upstream-host and the clean filed it under "+
			"the oracle that means the application may not read this header at all: %s",
			v.Oracle, v.Reason)
	}
	if !strings.Contains(v.Reason, "x-upstream-host") {
		t.Errorf("the clean does not name the header that carried our value: %s", v.Reason)
	}
	if strings.Count(v.Reason, "x-upstream-host") != 1 {
		t.Errorf("the clean names the same header twice, so two branches both wrote the header "+
			"clause and the row reads as two findings: %s", v.Reason)
	}
	names, _ := ann["value_reaches_these_response_headers"].([]string)
	if len(names) != 1 || names[0] != "x-upstream-host" {
		t.Errorf("value_reaches_these_response_headers = %v, want exactly [x-upstream-host]: a "+
			"volatile header or a header that did not carry the marker must not be counted", names)
	}
}

// AND THE MATCH IS ON THIS PROBE'S OWN MARKER, which is what separates this witness from the
// difference-based one in deser.go. A header that merely changed, or a rotating token, cannot
// satisfy it, and the reason string is allowed to say so only because of this.
func TestTheHostHeaderHeaderWitnessNeedsThisProbesOwnMarker(t *testing.T) {
	o := hhObs(hhA1, hhTestHost(), 200, `{"ok":true}`, "")
	o.Obs.RespHeaders = [][2]string{{"Set-Cookie", "sid=b7f21c9e0a4d; Path=/"}}
	if got := hhHeaderEchoes(o.Obs, hhTestMarker); len(got) != 0 {
		t.Errorf("hhHeaderEchoes = %v on a rotating session cookie that carries none of our bytes", got)
	}
	o.Obs.RespHeaders = [][2]string{{"Set-Cookie", "last_host=" + hhTestHost() + "; Path=/"}}
	if got := hhHeaderEchoes(o.Obs, hhTestMarker); len(got) != 1 || got[0] != "set-cookie" {
		t.Errorf("hhHeaderEchoes = %v, want [set-cookie]: an endpoint that puts our value straight "+
			"into a cookie is exactly the case this witness is for, and set-cookie is deliberately "+
			"not on this layer's volatile list", got)
	}
}

// AND THE CONTROL LINE IS ONLY PRINTED WHERE THERE WAS A CONTROL. Reaching the clean with no
// HH-NC1 reading means nobody checked whether the positional test would have been true of any
// value at all, and a precondition list is read as a list of checks that passed.
func TestTheHostHeaderCleanDoesNotClaimAControlItNeverRead(t *testing.T) {
	h := hhTestHost()
	rs := hhRead([]faOwnObs{hhObs(hhA1, h, 200, `{"ok":true,"items":[]}`, "")})
	_, ann := hhRunClean(t, rs, 1)
	joined := strings.Join(ann["clean_preconditions"].([]string), " | ")
	if strings.Contains(joined, "produced no authority a client would act on") {
		t.Errorf("the clean asserts what the inert control produced on a slot where the control "+
			"was never read: %s", joined)
	}
	if !strings.Contains(joined, "NOT CHECKED: HH-NC1") {
		t.Errorf("the clean does not say the control check was skipped: %s", joined)
	}
}

// =================================================================================================
// THE BLOCK FLOOR: A CLEAN THAT RESTED ON A GATE THAT COULD NOT RUN
// =================================================================================================
//
// pxUniformBlock is the last thing Classify asks before this class writes a clean, and its floor
// is faUniformBlockMin distinct payloads sharing one non-baseline response. THIS CLASS COULD
// NEVER REACH THAT FLOOR ON THE ONE SHAPE THE GATE EXISTS FOR.
//
//	round 0 on any routing header is TWO values: a payload and HH-NC1 (hhProbesFor).
//	round 1's third value was bought only by hhSawAnyReachIn, which asks whether round 0's
//	value came back anywhere.
//	a filter that answers every routing-header value with the same page is exactly the case
//	where nothing comes back.
//
// So the gate's precondition was destroyed by the condition it was written to detect: two
// payloads, a floor of three, the gate silent, and Classify falling through to the weakest clean
// it has, whose sentence is "the application may not read the header". On a filtered endpoint
// that is a sentence about the filter and the state is not true.
//
// IT IS THE SAME SHAPE AS THE HH-NC1 CONTROL THAT COULD NEVER FIRE, which this class shipped
// once. A gate whose precondition cannot be met reads exactly like a gate that was asked and
// passed. The two fixes are asserted below: Plan buys the third value when round 0 is
// block-shaped, and Classify refuses where the floor is still unmet.

// hhBlockedObs is one probe's answer from an endpoint that answered every value identically with
// a page that is not the control's: the shape of something in front rather than of a URL builder
// behind.
func hhBlockedObs(id triage.ProbeID, sent string) faOwnObs {
	return hhObs(id, sent, 403, `{"error":"request blocked","ref":"waf"}`, "")
}

const hhTestBaselineBody = `{"ok":true,"items":[]}`

// THE FIRST FIX. Round 0 on a blocked routing header must buy round 1, because round 1's third
// distinct value is what lets pxUniformBlock speak at all.
func TestRoundOneIsBoughtWhenRoundZeroIsBlockShaped(t *testing.T) {
	own := []faOwnObs{
		hhBlockedObs(hhA1, hhTestHost()),
		hhBlockedObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert"),
	}
	base := []byte(hhTestBaselineBody)

	// The premise, asserted rather than assumed: at two payloads the gate CANNOT answer.
	if faUniformBlock(faObsOf(own), base) {
		t.Fatal("faUniformBlock answered at two payloads, so faUniformBlockMin is not what this test assumes")
	}
	if hhSawAnyReachIn(own) {
		t.Fatal("the blocked fixture reflects the marker, so it is not the shape this test is about")
	}

	ok, why := hhRound1IsWorthSending(own, base)
	if !ok {
		t.Errorf("round 1 was refused on a uniformly blocked routing header. Round 0 is two values, "+
			"pxUniformBlock needs %d, and with round 1 refused the floor can never be met: the gate "+
			"stays silent and Classify writes the weakest clean it has on an endpoint that answered "+
			"every host we named with the same page. Gate said: %s", faUniformBlockMin, why)
	}
	if !strings.Contains(why, "block-shaped") {
		t.Errorf("round 1 was bought for the wrong reason, so the gate is not measuring what it says: %s", why)
	}

	// AND THE THIRD VALUE ACTUALLY CLOSES IT. With round 1's probe in hand the floor is met and
	// pxUniformBlock owns the answer, which is what makes buying the request worth a request.
	withR1 := append(own, hhBlockedObs(hhA2, hhTestHost()+":8443"))
	if !faUniformBlock(faObsOf(withR1), base) {
		t.Error("the third distinct value did not let faUniformBlock answer, so buying round 1 bought nothing")
	}
}

// AND THE ORIGINAL ARM IS UNCHANGED IN BOTH DIRECTIONS. A route that ignored the header entirely,
// answering every probe with the control's own body, must not buy a round: that is the honest
// clean and spending a request on it would be a cost with no answer attached.
func TestRoundOneIsStillRefusedWhereTheEndpointIgnoredTheHeader(t *testing.T) {
	own := []faOwnObs{
		hhObs(hhA1, hhTestHost(), 200, hhTestBaselineBody, ""),
		hhObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert", 200, hhTestBaselineBody, ""),
	}
	ok, why := hhRound1IsWorthSending(own, []byte(hhTestBaselineBody))
	if ok {
		t.Errorf("round 1 was bought on a route that answered every probe with the unperturbed "+
			"control's own body. Nothing was blocked and nothing came back, so there is no third "+
			"value worth sending: %s", why)
	}
}

// AND WHERE THE VALUE DID COME BACK, ROUND 1 IS BOUGHT FOR THE ORIGINAL REASON.
func TestRoundOneIsStillBoughtWhereTheValueCameBack(t *testing.T) {
	h := hhTestHost()
	own := []faOwnObs{hhObs(hhA1, h, 200, `{"debug":{"forwarded_host":"`+h+`"}}`, "")}
	ok, why := hhRound1IsWorthSending(own, []byte(hhTestBaselineBody))
	if !ok {
		t.Errorf("round 1 was refused although round 0's value came back: %s", why)
	}
	if !strings.Contains(why, "came back") {
		t.Errorf("round 1 was bought for the wrong reason: %s", why)
	}
}

// THE SECOND FIX, AND IT IS THE FAIL-CLOSED ONE. Round 1 can still be refused by the operator's
// tier, by the risk ceiling, by the budget or by the encoder. Where the floor is unmet and the
// evidence is block-shaped anyway, the class REFUSES rather than writing a clean.
func TestAUniformlyBlockedRoutingHeaderIsRefusedRatherThanCleaned(t *testing.T) {
	own := []faOwnObs{
		hhBlockedObs(hhA1, hhTestHost()),
		hhBlockedObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert"),
	}
	v, fired := hhRunFloor(t, own, []byte(hhTestBaselineBody))
	if !fired {
		t.Fatal("the floor refusal did not fire on two distinct values that produced one identical " +
			"non-baseline response. pxUniformBlock cannot answer at two, so with this arm silent the " +
			"class falls through to a clean whose sentence is about a filter it never saw")
	}
	if v.State.CountsAsClean() {
		t.Errorf("a blocked routing header rendered as clean: %s", v.Reason)
	}
	if v.State != triage.StateCannotDetermine {
		t.Errorf("state %q, want cannot_determine: not knowing is not clean and it is not a block either", v.State)
	}
	if !strings.Contains(v.Reason, "block_floor_unmet") {
		t.Errorf("the refusal does not name itself: %s", v.Reason)
	}
	// THE REASON MAY NOT ASSERT MORE THAN THE WITNESS MEASURED. It knows the responses were
	// identical and not the control's, and it knows the floor. It does not know there is a WAF.
	for _, overclaim := range []string{"a WAF", "the application blocked", "is blocked"} {
		if strings.Contains(v.Reason, overclaim) {
			t.Errorf("the refusal asserts %q, which nothing here measured: %s", overclaim, v.Reason)
		}
	}
	if !strings.Contains(v.Reason, strconv.Itoa(faUniformBlockMin)) {
		t.Errorf("the refusal does not say what floor was unmet, so an operator cannot act on it: %s", v.Reason)
	}
}

// AND IT STANDS DOWN WHERE pxUniformBlock CAN SPEAK. Three identical non-baseline responses are
// the gate's own case, and two arms answering one question is how a class contradicts itself.
func TestTheFloorRefusalStandsDownWhereTheBlockGateCanSpeak(t *testing.T) {
	own := []faOwnObs{
		hhBlockedObs(hhA1, hhTestHost()),
		hhBlockedObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert"),
		hhBlockedObs(hhA2, hhTestHost()+":8443"),
	}
	base := []byte(hhTestBaselineBody)
	if !faUniformBlock(faObsOf(own), base) {
		t.Fatal("the three-value fixture does not reach faUniformBlock, so this test is asserting nothing")
	}
	if f := hhBlockFloorOf(own, base); !f.Met() || f.Unmet() {
		t.Errorf("the floor reports Met=%v Unmet=%v at three identical non-baseline responses, so this "+
			"arm and pxUniformBlock would both answer the same slot", f.Met(), f.Unmet())
	}
}

// AND IT STANDS DOWN WHERE THE ENDPOINT TOLD OUR VALUES APART. /hosthdr/echo answers each probe
// with that probe's own value in a debug block, which is the most important negative in the
// class, and an arm that refused there would convert it into an unknown.
func TestTheFloorRefusalStandsDownWhereTheEndpointToldOurValuesApart(t *testing.T) {
	h := hhTestHost()
	inert := "hh-" + string(hhTestMarker) + "-inert"
	own := []faOwnObs{
		hhObs(hhA1, h, 200, `{"debug":{"forwarded_host":"`+h+`"}}`, ""),
		hhObs(hhNC1, inert, 200, `{"debug":{"forwarded_host":"`+inert+`"}}`, ""),
	}
	if _, fired := hhRunFloor(t, own, []byte(hhTestBaselineBody)); fired {
		t.Error("the floor refusal fired on /hosthdr/echo's shape, where every probe got a DIFFERENT " +
			"response. That is an endpoint discriminating between our values, which is the opposite of " +
			"a uniform block, and refusing there turns the class's most important negative into an unknown")
	}
}

// AND IT STANDS DOWN WHERE EVERY RESPONSE IS THE CONTROL'S. This is the shape of the nine /cors/*
// routes and of /hosthdr/loc200: the body is byte-identical to the unperturbed control on every
// probe. Nothing moved, so there is nothing uniform to be suspicious of, and the clean below is
// the honest answer. Refusing here would be faUniformBlock(own, nil) all over again, which
// converted an endpoint that correctly ignores its input into an unknown.
func TestTheFloorRefusalStandsDownWhereEveryResponseIsTheControl(t *testing.T) {
	own := []faOwnObs{
		hhObs(hhA1, hhTestHost(), 200, hhTestBaselineBody, ""),
		hhObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert", 200, hhTestBaselineBody, ""),
	}
	if _, fired := hhRunFloor(t, own, []byte(hhTestBaselineBody)); fired {
		t.Error("the floor refusal fired where every probe came back byte-identical to the unperturbed " +
			"control. That is an endpoint ignoring the header, which is the honest clean this class owes " +
			"on nine /cors/* routes and on /hosthdr/loc200")
	}
}

// THE EMPTY-BODIED BLOCK, WHICH IS THE COMMONEST ONE THERE IS AND WHICH faUniformBlock SKIPS.
// This is the one place hhBlockFloorOf deliberately diverges from it, and the divergence is a
// measurement rather than a preference: a 403 with no body to every value is exactly "something
// in front answered".
func TestTheBlockFloorCountsAnEmptyBodiedRefusal(t *testing.T) {
	own := []faOwnObs{
		hhObs(hhA1, hhTestHost(), 403, "", ""),
		hhObs(hhNC1, "hh-"+string(hhTestMarker)+"-inert", 403, "", ""),
	}
	base := []byte(hhTestBaselineBody)
	if faUniformBlock(faObsOf(own), base) {
		t.Fatal("faUniformBlock now reads empty bodies, so this divergence note is stale and should be removed")
	}
	if f := hhBlockFloorOf(own, base); !f.Unmet() {
		t.Errorf("an endpoint that answered every value with an empty-bodied 403 was not read as "+
			"block-shaped (OffBaseline=%d Biggest=%d), so this class would write a clean about a "+
			"response it never got", f.OffBaseline, f.Biggest)
	}
}

// AND THE OTHER DIVERGENCE, WHICH IS WHY THIS PREDICATE DOES NOT GROUP ON THE DIGEST. Nothing in
// this package can mint an Observation.BodySHA256, so a fixture leaves it at its zero value and
// every response hashes to one key. A predicate that grouped on it would report a uniform block
// on the route that answered every probe differently, which is the failure mode it exists to
// prevent, and no test in this package could ever have caught it.
func TestTheBlockFloorIsNotFooledByAnUnsetBodyDigest(t *testing.T) {
	h := hhTestHost()
	inert := "hh-" + string(hhTestMarker) + "-inert"
	own := []faOwnObs{
		hhObs(hhA1, h, 200, `{"a":1}`, ""),
		hhObs(hhNC1, inert, 200, `{"b":2}`, ""),
		hhObs(hhA2, h+":8443", 200, `{"c":3}`, ""),
	}
	for _, o := range own {
		if o.Obs.BodySHA256 != ([32]byte{}) {
			t.Fatal("the fixture now carries a digest, so this test no longer covers the case it was written for")
		}
	}
	if f := hhBlockFloorOf(own, []byte(hhTestBaselineBody)); f.Biggest != 1 {
		t.Errorf("three different bodies grouped together (Biggest=%d), so the predicate is keying on "+
			"something a fixture cannot set", f.Biggest)
	}
}

// hhRunFloor drives the floor arm the way hhRunClean drives the clean one.
func hhRunFloor(t *testing.T, own []faOwnObs, baseline []byte) (triage.ClassVerdict, bool) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade,
		ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHostHeader, "header:x-forwarded-host", state, reason,
			oracle, grade, ords, ann, hhLabel(ann))
	}
	v, fired := hhFloorRefusal(own, baseline, "x-forwarded-host", ann, []uint64{20}, nil, one)
	if !fired {
		return triage.ClassVerdict{}, false
	}
	if len(v) != 1 {
		t.Fatalf("want exactly one verdict row, got %d", len(v))
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("verdict failed its own contract: %v", err)
	}
	return v[0], true
}

// =================================================================================================
// THE NOTHING-SENT LADDER
// =================================================================================================

// not_planned is unreachable in this class's ladder, and after this round that is a PROPERTY OF
// THE PLANNER rather than a side effect of arm order. hhEligible refuses any slot hhProbesFor has
// nothing for, so by the time the ladder runs the derivation is always non-empty. If somebody
// adds a routing header to one list and not to hhProbesFor, this fails rather than the class
// quietly reporting a planner gap as a budget one.
func TestEveryRoutingHeaderThisClassAcceptsHasAPlannedRoundZero(t *testing.T) {
	for _, name := range append(hhAuthorityHeaders(), hhURLHeaders()...) {
		slot := triage.Slot{Kind: triage.KindHeader, Key: triage.SlotKey("header:" + name),
			Name: name, ServerReachable: true, SegmentIndex: -1}
		if _, ok := hhEligible(slot); !ok {
			t.Errorf("%s is in this class's header lists and hhEligible refuses it", name)
			continue
		}
		if n := len(hhProbesFor(name, 0)); n == 0 {
			t.Errorf("%s passes hhEligible and hhProbesFor derives nothing for round 0. The nothing-sent "+
				"ladder would then report not_planned, which is right, but the class would have accepted "+
				"a slot it can never probe", name)
		}
	}
}
