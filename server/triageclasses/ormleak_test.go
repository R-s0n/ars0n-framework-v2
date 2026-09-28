package triageclasses

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// ormTestMarker is a marker-shaped token whose ordinal stripe is THIS class's.
//
// The layout is [anchor 3][run id 4][ordinal 6][checksum 3], so the six characters at offset 7
// are the ordinal in base36: "00000t" is 29, and 29 mod 64 is ORM-LEAK's id. The claim is not
// left as arithmetic in a comment; TestTheORMFixtureMarkerIsInThisClassesStripe asserts it.
//
// Every detector in this class is a function of the marker as a STRING, so the stripe is not what
// makes these tests work. It is here because a future reader copying this fixture into a runner
// test would otherwise copy a marker that attributes to somebody else.
const ormTestMarker triage.Marker = "zqj000000000tabc"

// ormTok is what every signature in this class expects to find quoted.
var ormTok = string(ormTestMarker) + ormOwnedLiteral

// ormObs builds one of this class's own observations, as the vault would hand it over.
//
// Only the fields this class reads are set: the payload record so the wire check passes, the
// status, and the body. Anything left zero is a field this class does not look at, and if that
// stops being true a test written against this helper fails loudly instead of reading a zero.
func ormObs(id triage.ProbeID, status int, body string) faOwnObs {
	return faOwnObs{
		ProbeID: id,
		Ordinal: 29,
		Marker:  ormTestMarker,
		Obs: triage.Observation{
			Status: status,
			Body:   []byte(body),
			Payload: triage.PayloadWire{
				Logical:  []byte(ormTok),
				Wire:     []byte(ormTok),
				Survived: triage.WireSurvivalIntact,
			},
		},
	}
}

// ormCtx is a ClassifyCtx with an eligible slot and nothing else, for the arms that do not need a
// route control. The arms that DO need one say so by taking a status.
func ormCtx() triage.ClassifyCtx {
	return triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Slot: triage.Slot{
			Kind: triage.KindQuery, Key: "query:sort", Name: "sort", Value: "asc",
			Method: "GET", ServerReachable: true, Constraints: triage.NewSlotConstraints(),
		},
	}}
}

func ormOnly(t *testing.T, vs []triage.ClassVerdict) triage.ClassVerdict {
	t.Helper()
	if len(vs) != 1 {
		t.Fatalf("want exactly one verdict row, got %d", len(vs))
	}
	if err := vs[0].Validate(); err != nil {
		t.Fatalf("the verdict this class emitted does not satisfy ClassVerdict.Validate: %v", err)
	}
	return vs[0]
}

func TestTheORMLeakClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassORMLeak)
	if !ok {
		t.Fatal("the ORM Leak classifier did not register itself, so the class produces no rows at all, and no row looks exactly like no bug")
	}
	if c.ID() != triage.ClassORMLeak {
		t.Fatalf("registered under %s but reports %s", triage.ClassORMLeak, c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes with ORM-LEAK registered", rep.ClassesChecked, rep.ProbesChecked)
}

// The fixture marker must be in this class's own stripe, or a reader copying it elsewhere copies
// a marker that attributes to somebody else.
func TestTheORMFixtureMarkerIsInThisClassesStripe(t *testing.T) {
	if !ormTestMarker.WellFormed() {
		t.Fatalf("fixture marker %q is not marker-shaped, so ormToken returns empty and every detector test below would be testing nothing", ormTestMarker)
	}
	if !ormTestMarker.BelongsTo(triage.ClassORMLeak) {
		owner, _ := ormTestMarker.ClassID()
		t.Fatalf("fixture marker %q is in stripe %s, not ORM-LEAK's", ormTestMarker, owner)
	}
}

// EVERY PAYLOAD SPELLS THE MARKER PLACEHOLDER. Marker placement by the runner is opt-in and this
// class deliberately does not opt in, so a payload that forgot to spell it would go out with no
// marker, the signature table would search for a keyword nobody sent, and the class would read
// that silence as the target's answer.
func TestEveryORMPayloadCarriesTheMarkerPlaceholderAndThisClassesLiteral(t *testing.T) {
	for _, p := range (ormLeakClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("probe %s payload %q spells no marker placeholder, so nothing it produces can be attributed to this probe", p.ID, p.Logical)
		}
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder+ormOwnedLiteral) {
			t.Errorf("probe %s payload %q does not carry the marker followed by this class's own literal %q, so the keyword it sends is a BARE marker and collides with the obvious shape of every future inert control",
				p.ID, p.Logical, ormOwnedLiteral)
		}
		if p.MarkerPos != "" {
			t.Errorf("probe %s declares MarkerPos %q while spelling its own marker; the runner honours MarkerPos only for an opted-in class, so the declaration is a promise nothing keeps", p.ID, p.MarkerPos)
		}
	}
}

func TestTheORMClassDoesNotOptIntoRunnerPlacedMarkers(t *testing.T) {
	var c any = ormLeakClassifier{}
	if opt, ok := c.(interface{ RunnerPlacesMarkers() bool }); ok && opt.RunnerPlacesMarkers() {
		t.Error("ORM-LEAK opted into runner-placed markers. Its payloads already spell the marker, so the runner would prepend a second one and the keyword sent would not be the keyword searched for")
	}
}

// THE GUARD AGAINST THE THREE ARMS THAT ARE NOT SHIPPED.
//
// The harvest's append payloads need the OBSERVED PARAMETER NAME inside the payload bytes and the
// runner has no token for it. If somebody adds one of them later by spelling a token the runner
// does not substitute, the token reaches the wire, the probe tests nothing, and the class reads
// the silence. This test fails on any angle-bracket token in a payload that is not the one token
// the runner substitutes for every class.
func TestNoORMPayloadSpellsATokenTheRunnerWillNotSubstitute(t *testing.T) {
	for _, p := range (ormLeakClassifier{}).Probes() {
		rest := strings.ReplaceAll(string(p.Logical), triage.MarkerPlaceholder, "")
		for _, tok := range []string{"<", "${", "~~"} {
			if strings.Contains(rest, tok) {
				t.Errorf("probe %s payload %q carries %q, and the runner substitutes nothing but %s for this class (triageUsesDollarTokens and triageUsesAngleTokens name seven classes and ORM-LEAK is not one of them). The token would go out raw and the probe would test nothing",
					p.ID, p.Logical, tok, triage.MarkerPlaceholder)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE DETECTOR, AGAINST THE MEASURED BYTES
// ---------------------------------------------------------------------------------------------

// THE MEASUREMENT THIS WHOLE CLASS IS BUILT ON, Django 6.1.1, with the harvest's marker swapped
// for this fixture's. The column list must come back out whole.
func TestTheDjangoFieldErrorIsReadVerbatimAndHandsOverTheColumnList(t *testing.T) {
	body := "FieldError at /api/items\nCannot resolve keyword '" + ormTok + "' into field. " +
		"Choices are: created_by, created_by_id, id, title\nRequest Method: GET\n"
	h, ok := ormScan(ormObs(ormD1, 500, body))
	if !ok {
		t.Fatal("the measured Django 6.1.1 FieldError did not fire this class's detector, which means the class cannot find the bug it was written for")
	}
	if h.Dialect != ormDialectDjangoField {
		t.Errorf("dialect %q, want %q", h.Dialect, ormDialectDjangoField)
	}
	if h.Fields != "created_by, created_by_id, id, title" {
		t.Errorf("leaked field list came back as %q, want the four columns; the payoff of this class is that clause and a truncated one is a report nobody can act on", h.Fields)
	}
	if h.QuoteForm != "apostrophe" {
		t.Errorf("quote form %q, want apostrophe", h.QuoteForm)
	}
}

// THE ESCAPED FORM, WHICH IS THE ONE A REAL DEBUG PAGE EMITS. Django's technical 500 page runs
// the exception value through html.escape, so the apostrophes arrive as &#x27;. A matcher that
// only knew the raw apostrophe would be silent on exactly the deployment where the oracle exists.
func TestTheHTMLEscapedApostropheFormIsMatched(t *testing.T) {
	for _, q := range []struct{ name, open string }{
		{"html_numeric_hex", "&#x27;"},
		{"html_numeric_dec", "&#39;"},
		{"html_named", "&apos;"},
		{"double_quote", `"`},
		{"html_double_quote", "&quot;"},
	} {
		body := "<pre>Cannot resolve keyword " + q.open + ormTok + q.open +
			" into field. Choices are: id, email, password</pre>"
		h, ok := ormScan(ormObs(ormD1, 500, body))
		if !ok {
			t.Errorf("%s: the escaped FieldError did not fire, so this class would be silent on a rendered Django debug page", q.name)
			continue
		}
		if h.QuoteForm != q.name {
			t.Errorf("%s: matched under quote form %q", q.name, h.QuoteForm)
		}
		if h.Fields != "id, email, password" {
			t.Errorf("%s: fields %q, want the three columns; the clause must stop at the tag and not swallow it", q.name, h.Fields)
		}
	}
}

// THE NEGATIVE CONTROL THE HARVEST REQUIRES, AND IT IS A FIXTURE RATHER THAN A PROBE ON PURPOSE:
// no payload can make an application emit a FieldError about a keyword we did not send.
func TestAFieldErrorNamingADifferentKeywordDoesNotFire(t *testing.T) {
	for _, body := range []string{
		"Cannot resolve keyword 'created_at' into field. Choices are: id, title",
		"Cannot resolve keyword 'zqj0000000000abc' into field. Choices are: id, title",
		"Cannot resolve keyword '" + string(ormTestMarker) + "' into field. Choices are: id",
		"Unsupported lookup 'iexact' for CharField or join on the field not permitted.",
		"Unknown argument 'orderBy'. Available options are listed in green.",
	} {
		if h, ok := ormScan(ormObs(ormD1, 500, body)); ok {
			t.Errorf("the detector fired on %q (dialect %s). The phrase is the CONTEXT and the quoted token is the EVIDENCE; firing on somebody else's keyword makes this class fire on every Django app that has ever logged a bad query", body, h.Dialect)
		}
	}
}

// The third case above is the subtle one and gets its own name: the marker ALONE is not the
// keyword. Without this class's literal the payload would be a bare marker, and a bare marker is
// the shape half a dozen future inert controls will have.
func TestTheBareMarkerWithoutThisClassesLiteralIsNotTheKeyword(t *testing.T) {
	body := "Cannot resolve keyword '" + string(ormTestMarker) + "' into field. Choices are: id"
	if _, ok := ormScan(ormObs(ormD1, 500, body)); ok {
		t.Error("a FieldError quoting the bare marker fired this class's detector, so any class whose payload is a bare marker would be attributed here")
	}
}

func TestTheLookupArmNamesTheFieldTypeAndFlagsARelation(t *testing.T) {
	body := "FieldError: Unsupported lookup '" + ormTok + "' for ForeignKey or join on the field not permitted."
	h, ok := ormScan(ormObs(ormD1, 500, body))
	if !ok {
		t.Fatal("the Unsupported lookup message did not fire; an application that prefixes our key onto a field of its own is a real shape and this arm is how it is seen")
	}
	if h.Dialect != ormDialectDjangoLookup {
		t.Fatalf("dialect %q, want %q", h.Dialect, ormDialectDjangoLookup)
	}
	if h.FieldType != "ForeignKey" {
		t.Errorf("field type %q, want ForeignKey and nothing after it; the sentence continues 'or join on the field not permitted.' and swallowing it makes the annotation useless", h.FieldType)
	}
	vs := ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, body)}, 0, false)
	v := ormOnly(t, vs)
	if v.State != triage.StateFinding {
		t.Fatalf("state %s, want finding", v.State)
	}
	if rel, _ := v.Annotations["field_is_a_relation"].(bool); !rel {
		t.Error("a ForeignKey was not annotated as a relation, and the relation is the precondition for the whole relational-leak chain")
	}
}

func TestThePrismaArmFiresAndSaysItIsUnverified(t *testing.T) {
	body := `{"error":"Unknown argument '` + ormTok + `'. Did you mean 'title'?"}`
	h, ok := ormScan(ormObs(ormD2, 400, body))
	if !ok {
		t.Fatal("the Prisma rejection did not fire")
	}
	if h.Dialect != ormDialectPrisma {
		t.Fatalf("dialect %q, want %q", h.Dialect, ormDialectPrisma)
	}
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD2, 400, body)}, 0, false))
	if v.State != triage.StateFinding {
		t.Fatalf("state %s, want finding: the keyword quoted is this probe's own and nothing else can have produced it", v.State)
	}
	if !strings.Contains(v.Reason, "cited rather than measured") {
		t.Error("the Prisma reason does not say the dialect row is cited rather than measured. No Node was available when the payloads were verified and the report must not read as if one was")
	}
}

func TestTheChoicesClauseIsCappedAndStopsAtTheFirstTerminator(t *testing.T) {
	long := strings.Repeat("column_name, ", 200)
	body := "Cannot resolve keyword '" + ormTok + "' into field. Choices are: " + long
	h, ok := ormScan(ormObs(ormD1, 500, body))
	if !ok {
		t.Fatal("did not fire")
	}
	if len(h.Fields) > ormChoicesMaxRun {
		t.Errorf("the choices clause came back %d bytes, over the %d cap; an unterminated clause must be truncated into an annotation rather than carried whole into a verdict row", len(h.Fields), ormChoicesMaxRun)
	}
	// A message with no choices clause at all is still a finding: reachability is proven.
	short := "Cannot resolve keyword '" + ormTok + "' into field."
	h2, ok := ormScan(ormObs(ormD1, 500, short))
	if !ok || h2.Fields != "" {
		t.Errorf("the short Django form did not read as a hit with an empty field list (ok=%v fields=%q)", ok, h2.Fields)
	}
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, short)}, 0, false))
	if v.State != triage.StateFinding {
		t.Errorf("state %s, want finding: the column list is the payoff and the resolution is the bug", v.State)
	}
}

// ---------------------------------------------------------------------------------------------
// THE VERDICT LADDER
// ---------------------------------------------------------------------------------------------

// An echo of the parameter name is what EVERY echo endpoint does. It is recorded and it is clean.
func TestAnEchoOfTheKeywordWithNoORMErrorIsCleanAndSaysSo(t *testing.T) {
	body := `{"error":"unknown query parameter: ` + ormTok + `","status":"ignored"}`
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 200, body)}, 200, true))
	if v.State != triage.StateClean {
		t.Fatalf("state %s, want clean: an echo is not an ORM error and never has been", v.State)
	}
	if echoed, _ := v.Annotations["keyword_echoed_in_a_response"].(bool); !echoed {
		t.Error("the echo was not annotated, so the operator cannot tell this clean from the one where nothing came back at all")
	}
	if !strings.Contains(v.Reason, "keyword_echoed_no_orm_error") {
		t.Errorf("reason %q does not name the echo arm", v.Reason)
	}
}

// THE FALSE CLEAN THIS CLASS WOULD HAVE SHIPPED WITHOUT ITS STATUS LADDER.
//
// faUniformBlock needs three distinct payloads and this class sends at most two, so the guard
// every sibling uses is arithmetically dead here. Without a replacement, a WAF's 403 falls
// through to "no ORM error surface" and the operator is told the endpoint is clean of a class
// that was never tested on it.
func TestAWAFRefusalIsNotACleanAndNamesWhichLayerAnswered(t *testing.T) {
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 403, "Access denied by policy")}, 200, true))
	if v.State.CountsAsClean() {
		t.Fatal("a 403 against a 200 control was recorded as CLEAN. A filter answered and the queryset was never reached; this is the false clean the status ladder exists to stop")
	}
	if v.State != triage.StateCannotDetermine {
		t.Fatalf("state %s, want cannot_determine", v.State)
	}
	if !strings.Contains(v.Reason, "request_refused_before_the_view") {
		t.Errorf("reason %q does not name the refusal", v.Reason)
	}
}

// A 400 to an unknown parameter name is a real defence and a better answer than clean.
func TestAnUnknownParameterRejectionIsNotExploitableRatherThanClean(t *testing.T) {
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 400, `{"detail":"unexpected field"}`)}, 200, true))
	if v.State != triage.StateNotExploitable {
		t.Fatalf("state %s, want not_exploitable: the endpoint validates parameter NAMES, which is a named defence", v.State)
	}
	if v.Annotations["defence"] == nil {
		t.Error("not_exploitable was emitted with no named defence in the annotations, which is the one thing that state is not allowed to do")
	}
}

// Production Django: a 500 with no keyword in the body. Suspicious, never finding, never clean,
// and the reason must carry BOTH readings because this class cannot separate them from here.
func TestTheProductionDjangoStatusDifferentialIsSuspiciousAndCarriesBothReadings(t *testing.T) {
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, "<h1>Server Error (500)</h1>")}, 200, true))
	if v.State != triage.StateSuspicious {
		t.Fatalf("state %s, want suspicious", v.State)
	}
	if v.Grade == triage.GradeHigh {
		t.Error("a status differential with no keyword in the body was graded high. Nothing in it is attributable to this probe")
	}
	for _, want := range []string{"DEBUG=False", "required the parameter we renamed"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("reason does not carry the reading %q, so a reader would take the one this class happens to have written first as the answer: %s", want, v.Reason)
		}
	}
}

// A 500 carrying our keyword but no phrase this table knows is the Ransack case and every wrapped
// ORM error. It is suspicious and it is never dropped.
func TestAMarkerBearing5xxWithNoKnownPhraseIsSuspicious(t *testing.T) {
	body := "NoMethodError: undefined method `" + ormTok + "' for an instance of Item"
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, body)}, 200, true))
	if v.State != triage.StateSuspicious {
		t.Fatalf("state %s, want suspicious", v.State)
	}
	if v.Oracle != "orm_error_unclassified" {
		t.Errorf("oracle %q, want orm_error_unclassified", v.Oracle)
	}
}

// An endpoint that 500s on its own captured request cannot be read at all.
func TestAnEndpointThatErrorsWithoutUsIsJunkSensitiveAndNotClean(t *testing.T) {
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, "boom")}, 500, true))
	if v.State.CountsAsClean() || v.State == triage.StateSuspicious {
		t.Fatalf("state %s: a 500 differential cannot be taken against a control that is already failing", v.State)
	}
	if !strings.Contains(v.Reason, "junk_sensitive") {
		t.Errorf("reason %q does not name junk_sensitive", v.Reason)
	}
}

// A finding survives a control that is already failing, because the keyword is attributable and
// the differential is not.
func TestAFindingOutranksTheJunkSensitiveGate(t *testing.T) {
	body := "Cannot resolve keyword '" + ormTok + "' into field. Choices are: id, secret"
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, body)}, 500, true))
	if v.State != triage.StateFinding {
		t.Fatalf("state %s, want finding: /clean/dberror is the route that proves a marker-anchored oracle survives an application that errors on every request", v.State)
	}
	if v.Grade != triage.GradeHigh {
		t.Errorf("grade %q, want high", v.Grade)
	}
}

// A probe that never reached the wire is not a probe that found nothing.
func TestAProbeThatNeverReachedTheWireIsNeverClean(t *testing.T) {
	o := ormObs(ormD1, 200, "ok")
	o.Obs.Payload.Survived = triage.WireSurvivalDropped
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{o}, 200, true))
	if v.State.CountsAsClean() {
		t.Fatal("a dropped payload was recorded as clean, which is a class reporting on bytes no socket carried")
	}
	if !strings.Contains(v.Reason, "no_probe_reached_the_wire") {
		t.Errorf("reason %q does not name the wire failure", v.Reason)
	}
	if len(v.Untested) == 0 {
		t.Error("the dropped probe produced no Untested row, so the coverage report cannot name what was not measured")
	}
}

func TestORMWithNothingSentIsNeverClean(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:sort", Name: "sort", ServerReachable: true,
		Constraints: triage.NewSlotConstraints()}
	c := ormLeakClassifier{}
	if reqs := c.Plan(triage.PlanCtx{Slot: slot}); len(reqs) != 0 {
		t.Errorf("Plan returned %d requests with no resolved route control", len(reqs))
	}
	v := ormOnly(t, c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}}))
	if !v.State.IsUnknown() {
		t.Fatalf("state %s with nothing sent, which asserts a measurement that never happened", v.State)
	}
	if strings.TrimSpace(v.Reason) == "" {
		t.Error("an unknown with no reason is how a check that never ran becomes a clean")
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY AND PLANNING
// ---------------------------------------------------------------------------------------------

func TestORMCannotReachAHeaderCookiePathOrFragmentAndSaysWhy(t *testing.T) {
	c := ormLeakClassifier{}
	for _, k := range []triage.SlotKind{triage.KindHeader, triage.KindCookie, triage.KindPath, triage.KindFragment} {
		r := c.Reaches(k, "application/json")
		if r.Reach != triage.ReachNever {
			t.Errorf("%s: reach %s, want never. A filter keyword is a map KEY and none of these slots has a key the application unpacks", k, r.Reach)
		}
		if strings.TrimSpace(r.Reason) == "" {
			t.Errorf("%s: ReachNever with no reason, so an operator cannot tell 'ruled out' from 'nobody wired this up'", k)
		}
	}
	for _, k := range []triage.SlotKind{triage.KindQuery, triage.KindBody} {
		if c.Reaches(k, "application/json").Reach == triage.ReachNever {
			t.Errorf("%s: reach never, but this class's whole surface is the name in a query or a body map", k)
		}
	}
}

// Plan must not aim the name-slot encoder at a slot with no name. On a live run 971 probes were
// planned that way and every one cost an ordinal, a budget slot and a fidelity row before being
// refused inside the process.
//
// It is ormProbesForSlot that is driven here rather than Plan, because Plan's other gates need a
// resolved route control and no test in this package can build one: NewReplay takes the runner
// capability and a classifier may not import it. The gate that CAN be driven, "no control means
// nothing is sent", is asserted in TestORMWithNothingSentIsNeverClean.
func TestEachProbeIsPlannedOnlyWhereItsEncoderCanRender(t *testing.T) {
	for _, tc := range []struct {
		name string
		slot triage.Slot
		want []triage.ProbeID
	}{
		{
			name: "query parameter: the name is the payload",
			slot: triage.Slot{Kind: triage.KindQuery, Key: "query:sort", Name: "sort", ServerReachable: true},
			want: []triage.ProbeID{ormD1},
		},
		{
			name: "urlencoded form field: the same edit against the body",
			slot: triage.Slot{Kind: triage.KindBody, Key: "body:status", Name: "status",
				BodyMedia: triage.BodyForm, ServerReachable: true},
			want: []triage.ProbeID{ormD1},
		},
		{
			name: "JSON node, which has no name to rename",
			slot: triage.Slot{Kind: triage.KindBody, Key: "body:/filters:node", FieldPath: "/filters",
				BodyMedia: triage.BodyJSON, ServerReachable: true},
			want: []triage.ProbeID{ormD2},
		},
		{
			name: "a body slot with no declared media is JSON, which is how the encoder resolves it",
			slot: triage.Slot{Kind: triage.KindBody, Key: "body:/q:node", FieldPath: "/q", ServerReachable: true},
			want: []triage.ProbeID{ormD2},
		},
		{
			name: "header: no key the application unpacks",
			slot: triage.Slot{Kind: triage.KindHeader, Key: "header:x-tenant", Name: "x-tenant", ServerReachable: true},
			want: nil,
		},
		{
			name: "credential cookie: never probed by anything",
			slot: triage.Slot{Kind: triage.KindCookie, Key: "cookie:session", Name: "session", ServerReachable: true,
				Constraints: triage.SlotConstraints{IsCredential: true}},
			want: nil,
		},
		{
			name: "a query slot the capture gave no name",
			slot: triage.Slot{Kind: triage.KindQuery, Key: "query:", ServerReachable: true},
			want: nil,
		},
	} {
		got := ormProbesForSlot(tc.slot)
		if len(got) != len(tc.want) {
			t.Errorf("%s: planned %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: planned %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

// A multipart body is neither a renameable form field nor a JSON node, and claiming either would
// send a probe the encoder refuses.
func TestAMultipartBodySlotIsPlannedForNeitherProbe(t *testing.T) {
	s := triage.Slot{Kind: triage.KindBody, Key: "body:file", Name: "file",
		BodyMedia: triage.BodyMultipart, ServerReachable: true}
	if got := ormProbesForSlot(s); len(got) != 0 {
		t.Errorf("planned %v on a multipart body; the name-slot encoder edits a urlencoded pair list and the node encoder edits a JSON document, and a multipart body is neither", got)
	}
}

func TestTheORMOracleCasesDeclareAFireRouteAndASilentRoute(t *testing.T) {
	cases := (ormLeakClassifier{}).OracleCases()
	var pos, neg int
	for _, c := range cases {
		switch c.Expect {
		case faExpectPositive:
			pos++
		case faExpectNegative:
			neg++
		}
		if strings.TrimSpace(c.Why) == "" || strings.TrimSpace(c.Route) == "" {
			t.Errorf("oracle case %q is missing a route or a reason, so the oracle pass gets a wish list rather than a build list", c.Name)
		}
		if c.WantState == triage.StateClean && c.Expect == faExpectPositive {
			t.Errorf("oracle case %q expects the detector to fire and wants clean", c.Name)
		}
	}
	if pos == 0 || neg == 0 {
		t.Fatalf("%d positive and %d negative oracle cases; a detector only ever observed FIRING scores the same as one that always returns true", pos, neg)
	}
	// The foreign-FieldError route is the one that proves the anchor. It must be declared.
	found := false
	for _, c := range cases {
		if strings.Contains(c.Why, "different keyword") {
			found = true
		}
	}
	if !found {
		t.Error("no oracle case asks for a route that returns a REAL FieldError about somebody else's keyword, which is the single case that separates this detector from a grep for the phrase")
	}
}

// ---------------------------------------------------------------------------------------------
// FIXTURE HELPERS
// ---------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------
// THE TENTH DOOR: A PHRASE THAT WAS ABSENT FROM A BODY THAT DID NOT EXIST
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THE ORACLE BEFORE THE FIX, exam of 2026-09-19 over 80 routes: this class reported
// CLEAN on /clean/empty204 (204, no body) and /clean/nothing (200, no body), with the reason
// "neither the keyword nor any ORM error phrase appeared". Both halves of that sentence were
// true and neither was a measurement: ormScan reads FieldError, Unknown argument and Unknown
// column out of RESPONSE BYTES, and there were none.
//
// /clean/always500 was never one of them, and the reason is worth keeping in sight: this class
// already refuses a 5xx control with junk_sensitive. Half the rule was here and the other half
// was missing.

func TestORMLeakWillNotReportCleanWhenThereWasNoBodyForItsPhraseToBeAbsentFrom(t *testing.T) {
	for _, c := range []struct {
		name   string
		status int
	}{
		{"a 204 with no body at all", 204},
		{"a 200 with an empty body, which is not the same route and is the same absence", 200},
	} {
		t.Run(c.name, func(t *testing.T) {
			v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{
				ormObs(ormD1, c.status, ""),
				ormObs(ormD2, c.status, ""),
			}, 200, true))
			if v.State.CountsAsClean() {
				t.Errorf("state %s. Every oracle in this class reads an error phrase out of a response "+
					"body and there was no body, so nothing was read and the silence is ours: %s",
					v.State, v.Reason)
			}
			if v.State != triage.StateCannotDetermine {
				t.Errorf("state %s, want cannot_determine", v.State)
			}
			if !strings.Contains(v.Reason, "no_body_to_read") {
				t.Errorf("the reason does not name no_body_to_read, so a reader cannot tell it apart "+
					"from a measured negative: %s", v.Reason)
			}
			if !strings.Contains(v.Reason, "2 of this class's own delivered probes") {
				t.Errorf("the reason does not report the count that fired: %s", v.Reason)
			}
		})
	}
}

// THE OTHER HALF. A body that exists and carries no phrase is still a real negative and this
// class keeps the highest conclusion rate in the exam, so the guard must not touch it.
func TestORMLeakStillReportsCleanWhenThereWasABodyAndTheReasonNamesItsDenominator(t *testing.T) {
	body := `{"results":[{"id":1,"title":"Rosewood Gin"}],"count":1}`
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 200, body)}, 200, true))
	if v.State != triage.StateClean {
		t.Fatalf("state %s on a normal JSON answer with no ORM error in it, which is this class's true "+
			"negative: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "bytes of response body") {
		t.Errorf("the clean does not say how many bytes it searched. \"No phrase appeared\" and \"no "+
			"phrase appeared in the N bytes I read\" are the same sentence until N is zero: %s", v.Reason)
	}
	if got := v.Annotations["body_bytes_searched"]; got != len(body) {
		t.Errorf("body_bytes_searched = %v, want %d", got, len(body))
	}
}

// AND THE STATUS ARMS ABOVE THE GUARD MUST KEEP WORKING ON AN EMPTY RESPONSE. A 500 with no body
// against a control that did not 500 is a real differential, and the guard is asked last
// precisely so that it cannot suppress one.
func TestAnEmptyBodied500StillReachesTheStatusDifferentialAndIsNotSwallowedByTheBodyGuard(t *testing.T) {
	v := ormOnly(t, ormDecide(ormCtx(), []faOwnObs{ormObs(ormD1, 500, "")}, 200, true))
	if v.State != triage.StateSuspicious {
		t.Errorf("state %s, want suspicious. The status arm needs no body and the no-body guard must "+
			"not reach it: %s", v.State, v.Reason)
	}
	if v.Oracle != "orm_500_differential" {
		t.Errorf("oracle %q, want orm_500_differential", v.Oracle)
	}
}

// ---------------------------------------------------------------------------------------------
// ROUND 8: THE 4xx ARM THIS CLASS CAN NEVER SATISFY
// ---------------------------------------------------------------------------------------------

// ormWireObs is ormObs with the three fields faCompare needs to compare anything: an ObsID, a
// BodyLen and a normalised-body hash. ormObs leaves all three at zero, which makes every
// comparison read faCmpUnmeasured, and a witness that can only return "unknown" cannot be the
// witness in a test about what the witness measured.
func ormWireObs(id triage.ProbeID, status int, body string) faOwnObs {
	o := ormObs(id, status, body)
	o.Obs.ObsID = "obs-" + string(id)
	o.Obs.BodyLen = len(body)
	o.Obs.Proj.NormBodySHA256 = sha256.Sum256([]byte(body))
	return o
}

func ormWireCtl(status int, body string) triage.Observation {
	return triage.Observation{
		ObsID: "route-control", Status: status, Body: []byte(body), BodyLen: len(body),
		Proj: triage.Projections{NormBodySHA256: sha256.Sum256([]byte(body))},
	}
}

func ormTail(t *testing.T, honest []faOwnObs, control triage.Observation,
	haveControl bool) (triage.ClassVerdict, map[string]any) {
	t.Helper()
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade,
		ords []uint64) []triage.ClassVerdict {
		return []triage.ClassVerdict{{
			Class: triage.ClassORMLeak, SlotKey: "query:sort", State: state, Reason: reason,
			Oracle: oracle, Grade: grade, Ordinals: ords, Annotations: ann,
		}}
	}
	v := ormNegative(honest, control, haveControl, ann, []uint64{29}, nil, one)
	if len(v) != 1 {
		t.Fatalf("want exactly one verdict row, got %d", len(v))
	}
	return v[0], ann
}

// THE ARM THAT COULD NEVER FIRE, AND THE CLEAN THAT WAS STANDING ON IT.
//
// pxBodySurfaceUnreadable refuses a 4xx control only once pxDifferentialWitnessFloor (2) of a
// class's own delivered probes have reproduced it. This class delivers ONE probe on a query slot,
// by design, so s.Flat is 1 at its ceiling and the shared arm is arithmetically dead there. That
// is the same defect as HOSTHDR's control that could never fire.
//
// MEASURED, canary oracle, MATRIX A: /trav/append answers 404 with the same 30 bytes to
// ?file=hello, ?file=zzqq99 and ?file=../../etc/passwd. LFI and DESER both refuse it with
// control_refuses_everyone. ORM-LEAK reported clean / no_orm_error_surface at sent=1.
func TestORMLeakWillNotCallCleanOverARefusalItCannotWitnessTwice(t *testing.T) {
	const page = `{"detail":"Not found."}`
	v, _ := ormTail(t, []faOwnObs{ormWireObs(ormD1, 404, page)}, ormWireCtl(404, page), true)

	if v.State.CountsAsClean() {
		t.Errorf("state %s on a route that answered the unperturbed control and this class's only "+
			"probe with the same %d-byte 404. The body this class searched for a FieldError is the "+
			"page this endpoint hands a request it is refusing, and the arm that says so needs two "+
			"witnesses this class can never deliver on a query slot: %s", v.State, len(page), v.Reason)
	}
	if v.State != triage.StateCannotDetermine {
		t.Errorf("state %s, want cannot_determine", v.State)
	}
	for _, want := range []string{
		"control_refuses_everyone_unwitnessed",
		"404",
		"1 of this class's 1 delivered probe(s)",
	} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("the refusal does not contain %q, so a reader cannot check the measurement it "+
				"rests on: %s", want, v.Reason)
		}
	}
	if !strings.Contains(v.Reason, "WHAT THIS DOES NOT CLAIM") {
		t.Errorf("the refusal does not say what it is NOT asserting, and it is asserting less than "+
			"the two-witness arm does: %s", v.Reason)
	}
}

// THE NARROWNESS, AND IT IS THE WHOLE REASON THIS IS NOT A BARE STATUS TEST. A 404 to the observed
// value is an ordinary answer. A probe that MOVED the endpoint off it was handed a real body, and
// refusing there would delete true negatives rather than false ones.
func TestTheORMRefusalLeavesAnEndpointThatAnsweredThePayloadAlone(t *testing.T) {
	const page = `{"detail":"Not found."}`
	v, _ := ormTail(t, []faOwnObs{ormWireObs(ormD1, 200, `{"results":[],"count":0}`)},
		ormWireCtl(404, page), true)
	if v.State != triage.StateClean {
		t.Errorf("state %s. This endpoint 404s a request carrying none of our bytes and answered 200 "+
			"to the renamed parameter, so there is a real body here and the silence of the three "+
			"phrase searches is a measurement: %s", v.State, v.Reason)
	}
}

// AND A 2xx CONTROL IS NOT THIS ARM'S BUSINESS. This class has no value_insensitive guard and
// this round does not add one; firing here would silence the highest conclusion rate in the exam
// on a fact nobody measured.
func TestTheORMRefusalDoesNotFireOnATwoHundredControl(t *testing.T) {
	const page = `{"results":[{"id":1,"title":"Rosewood Gin"}],"count":1}`
	v, _ := ormTail(t, []faOwnObs{ormWireObs(ormD1, 200, page)}, ormWireCtl(200, page), true)
	if v.State != triage.StateClean {
		t.Errorf("state %s, want clean: the control answered 200 and nothing in this round's arm is "+
			"about a 200: %s", v.State, v.Reason)
	}
}

// WHERE THE FLOOR IS MEETABLE THE SHARED ARM MUST STILL BE THE ONE THAT ANSWERS, with its own
// stronger sentence. A JSON body slot that carries both a renameable name and a node pointer gets
// two probes, and there the shared rule works exactly as written.
func TestWhereTwoProbesReachedTheSharedFourHundredArmStillAnswers(t *testing.T) {
	const page = `{"detail":"Not found."}`
	v, _ := ormTail(t, []faOwnObs{
		ormWireObs(ormD1, 404, page),
		ormWireObs(ormD2, 404, page),
	}, ormWireCtl(404, page), true)
	if v.State != triage.StateCannotDetermine {
		t.Fatalf("state %s, want cannot_determine: %s", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "control_refuses_everyone:") {
		t.Errorf("with the floor met, the shared two-witness arm must be the one that answers and it "+
			"is not: %s", v.Reason)
	}
}

// A CLEAN MAY NOT LIST A CONTROL FACT ON A SLOT THAT HAD NO CONTROL. Both guards above skip
// silently without one, and the shipped precondition list asserted both of them unconditionally.
func TestTheORMCleanDoesNotClaimControlFactsWhenThereWasNoControl(t *testing.T) {
	const page = `{"results":[],"count":0}`
	v, ann := ormTail(t, []faOwnObs{ormWireObs(ormD1, 200, page)}, triage.Observation{}, false)
	if v.State != triage.StateClean {
		t.Fatalf("state %s, want clean: with no route control neither guard can fire, and refusing "+
			"here would delete every clean on a slot whose control did not resolve: %s",
			v.State, v.Reason)
	}
	lines, _ := ann["clean_preconditions"].([]string)
	if len(lines) == 0 {
		t.Fatal("the clean carries no preconditions at all")
	}
	joined := strings.Join(lines, " | ")
	if strings.Contains(joined, "the unperturbed route control resolved and did not itself return 5xx") ||
		strings.Contains(joined, "NOT REFUSING EVERYONE") {
		t.Errorf("the clean lists a control fact on a slot that had no control, so it prints two "+
			"checks that did not run: %s", joined)
	}
	if !strings.Contains(joined, "NOT CHECKED on this slot") {
		t.Errorf("the clean does not say which checks were skipped for want of a control: %s", joined)
	}
}

// A CLEAN MAY NOT CALL A 400 "ANSWERED NORMALLY".
//
// MEASURED, 80-route exam: /clean/echomongo answers 400 with {"received":"hello"} to the observed
// value and 400 with {"received":""} to the renamed parameter. The bodies differ, so this class
// read a real answer and its clean is earned; the words it shipped were "the request was answered
// normally", over a Bad Request. A status is a fact and "normally" is an opinion about somebody
// else's API.
func TestTheORMCleanNamesTheStatusItGotInsteadOfCallingItNormal(t *testing.T) {
	v, _ := ormTail(t, []faOwnObs{ormWireObs(ormD1, 400, `{"ok":false,"received":""}`)},
		ormWireCtl(400, `{"ok":false,"received":"hello"}`), true)
	if v.State != triage.StateClean {
		t.Fatalf("state %s, want clean: the endpoint answered the renamed parameter with a "+
			"different body, so there was a real answer to read: %s", v.State, v.Reason)
	}
	if strings.Contains(v.Reason, "answered normally") {
		t.Errorf("the clean calls a 400 a normal answer: %s", v.Reason)
	}
	if !strings.Contains(v.Reason, "the endpoint answered 400") {
		t.Errorf("the clean does not name the status it got: %s", v.Reason)
	}
}

// =================================================================================================
// THE NOTHING-SENT LADDER ASKS THE PLANNER BEFORE IT ASKS THE BUDGET
// =================================================================================================
//
// ORM-LEAK IS THE CLASS WHERE THIS ONE ACTUALLY MOVES VERDICTS. ormProbesForSlot genuinely
// returns nothing for some eligible slots: ORM-D1's encoder needs a parameter name to replace and
// ORM-D2's needs a JSON body, and a slot can offer neither. While the budget arm sat ABOVE the
// default, every one of those rows read "probe_budget_exhausted: the cap was reached before this
// class sent its one request" on any capped run, because TriageBudget.Exhausted() is true on every
// run whose per-run cap has bitten by scoring time. The operator raises the cap, the row does not
// move, and the planner gap stays invisible.
//
// ormNothingSent itself cannot be driven from this package: it asks !ctx.Route.Resolved() first
// and triage.NewReplay takes the runner capability. So the two halves are asserted where they can
// be reached: ormProbesForSlot for the derived count, pxNothingSentTail for what is done with it.
func TestTheORMNothingSentLadderReportsAPlannerGapAsAPlannerGap(t *testing.T) {
	exhausted := triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Budget: triage.TriageBudget{PerSlot: 24, PerRun: 100, RemainingPerSlot: 24, RemainingPerRun: 0},
	}}
	if !exhausted.Budget.Exhausted() {
		t.Fatal("the fixture budget does not read exhausted, so this test asserts nothing")
	}

	// A header slot: no key the application unpacks, so neither encoder renders and the planner
	// derives nothing. This is the row that used to read "raise the cap".
	noneDerived := triage.Slot{Kind: triage.KindHeader, Key: "header:x-tenant", Name: "x-tenant", ServerReachable: true}
	if got := ormProbesForSlot(noneDerived); len(got) != 0 {
		t.Fatalf("ormProbesForSlot(%s) = %v, want nothing; this fixture is meant to be the planner-gap case",
			noneDerived.Key, got)
	}
	state, reason := pxNothingSentTail(exhausted, len(ormProbesForSlot(noneDerived)), "this class's one request",
		"no ORM-leak probe was derived for this slot")
	if state != triage.StateNotPlanned {
		t.Errorf("a slot this class derives NOTHING for reported %q on a capped run. not_planned is a "+
			"planner gap and probe_budget_exhausted is a pacing one, and an operator acts on them "+
			"differently: %s", state, reason)
	}
	if strings.Contains(reason, "probe_budget_exhausted") {
		t.Errorf("the planner gap still offers the cap as its reason: %s", reason)
	}

	// And a query slot, where ORM-D1 does render: the budget arm must still be the answer there,
	// or the fix would be the same defect pointing the other way.
	derived := triage.Slot{Kind: triage.KindQuery, Key: "query:sort", Name: "sort", ServerReachable: true}
	if got := ormProbesForSlot(derived); len(got) == 0 {
		t.Fatalf("ormProbesForSlot(%s) derived nothing, so this half of the test asserts nothing", derived.Key)
	}
	state, reason = pxNothingSentTail(exhausted, len(ormProbesForSlot(derived)), "this class's one request",
		"no ORM-leak probe was derived for this slot")
	if state != triage.StateNotRun {
		t.Errorf("state %q on a slot with a derivable probe and an exhausted budget, want not_run: %s", state, reason)
	}
	if strings.Contains(strings.ToLower(reason), "the cap was reached before") {
		t.Errorf("the budget arm still dates the cap to before this class planned, which ctx.Budget "+
			"cannot witness: %s", reason)
	}

	// AND THE LADDER IN ormleak.go MUST BE WIRED TO THAT COUNT rather than to a literal. The two
	// halves above are both reachable from a test and the join between them is not, because
	// ormNothingSent asks !ctx.Route.Resolved() first. So the join is read out of the source. A
	// hand-written count here would pass every assertion above and still report a planner gap as
	// a pacing problem on the one slot shape where the count is zero.
	src, err := os.ReadFile(filepath.Join(packageDirOf(t), "ormleak.go"))
	if err != nil {
		t.Fatalf("read ormleak.go: %v", err)
	}
	if !strings.Contains(string(src), "pxNothingSentTail(ctx, len(ormProbesForSlot(ctx.Slot))") {
		t.Error("ormNothingSent does not hand pxNothingSentTail the count ormProbesForSlot derives, so " +
			"the not_planned arm this test exercises is not the one the class actually reaches")
	}
}
