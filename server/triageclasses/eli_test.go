package triageclasses

import (
	"bytes"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// Tests for the ELI classifier.
//
// WHAT THESE TESTS ARE FOR, AND IT IS NOT COVERAGE. Every rule here has to be shown doing two
// things: firing on the true shape, and STAYING SILENT on each named false positive. A detector
// that has only ever been observed firing is exactly as unverified as one that has only ever been
// observed staying silent, and CATALOGUE 6.1 says out loud that this class is currently in the
// second state because the oracle rig has no /eli route. These tests are the part of that gap that
// can be closed without a container.
//
// The third thing every path has to be shown doing is REFUSING TO SAY CLEAN. This codebase has
// shipped "a tool that never ran, recorded as a pass" repeatedly, so each way this class can fail
// to get an answer gets a row that asserts the state is an unknown.

// eliTestMarker is a well-formed marker whose ordinal stripe really is ELI's.
//
// The layout is anchor(3) + run id(4) + ordinal base36(6) + checksum(3). The ordinal digits a2q
// are 10*1296 + 2*36 + 26 = 13058, and 13058 = 204*64 + 2, so the stripe is 2, which is
// triage.ClassELI. The checksum digits are filler: nothing in this file recomputes a checksum, and
// what every assertion below depends on is the SHAPE and the STRIPE. Both are asserted in
// TestTheTestMarkerReallyBelongsToThisClass, so a hand-written literal cannot quietly drift into
// another class's stripe and leave the whole file passing while testing nothing.
const eliTestMarker = "zqj" + "t3st" + "000a2q" + "zzz"

func eliMarkerForTest(t *testing.T) string {
	if t != nil {
		t.Helper()
		if len(eliTestMarker) != triage.MarkerLen {
			t.Fatalf("the test marker is %d bytes, and a marker is %d", len(eliTestMarker), triage.MarkerLen)
		}
	}
	return eliTestMarker
}

// TestTheTestMarkerReallyBelongsToThisClass is a test about the other tests.
//
// Every adjacency assertion below is meaningless if the token it anchors on is not a marker this
// class would ever be handed. A literal that looks marker-shaped and strips to another class's
// ordinal would make the whole file pass while testing nothing.
func TestTheTestMarkerReallyBelongsToThisClass(t *testing.T) {
	m := triage.Marker(eliMarkerForTest(t))
	if !m.WellFormed() {
		t.Fatalf("the test marker %q is not well formed, so no rule in this file is being exercised against a real marker shape", m)
	}
	owner, ok := m.ClassID()
	if !ok {
		t.Fatalf("the test marker %q has no parseable ordinal", m)
	}
	if owner != triage.ClassELI {
		t.Fatalf("the test marker %q strips to class %s, not ELI, so every adjacency assertion in this file is anchored on another class's stripe", m, owner)
	}
}

// -------------------------------------------------------------------------------------------
// Registration and the isolation law
// -------------------------------------------------------------------------------------------

// TestTheELIClassifierRegistersItselfAndSatisfiesTheContract.
//
// A class that does not register produces no rows at all, and no row looks exactly the same as no
// bug. This is the cheapest possible test and it guards the most expensive silent failure.
func TestTheELIClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassELI)
	if !ok {
		t.Fatal("ELI did not register itself from init(), so the whole class would be missing from every report with no error anywhere")
	}
	if c.ID() != triage.ClassELI {
		t.Errorf("registered under ELI but reports id %s", c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	if err := triage.PlannedProbesAreDeclared(c, c.Plan(triage.PlanCtx{})); err != nil {
		t.Errorf("PlannedProbesAreDeclared on an empty ctx: %v", err)
	}
}

// TestEveryELIProbeIsDeclaredBeforeItCanBePlanned walks every round of the ladder against a slot
// with the gates open, and asserts that nothing Plan emits was conjured at run time.
//
// A payload conjured at run time was never seen by the isolation check, so the law would hold over
// the declared set and mean nothing about what actually went on the wire.
func TestEveryELIProbeIsDeclaredBeforeItCanBePlanned(t *testing.T) {
	c := eliClassifier{}
	for round := 0; round < 6; round++ {
		ctx := eliOpenPlanCtx()
		ctx.Round = round
		for _, hit := range []triage.ProbeID{"", eliProbeEL1, eliProbeEL5, eliProbeEL6} {
			for _, str := range []bool{false, true} {
				if err := triage.PlannedProbesAreDeclared(c, eliPlanRound(ctx, hit, str)); err != nil {
					t.Errorf("round %d after hit %q (string hit %v): %v", round, hit, str, err)
				}
			}
		}
	}
}

// TestNoELIPayloadCarriesALiteralMarker.
//
// The CATALOGUE prints each row with its marker inline, and copying that into Logical is the
// obvious mistake: the printed literals do not strip to class 2 (zqj2f3q000a1kx9m has ordinal
// stripe 24, which is DESER), so the build would fail isolation check I1d with a message about
// another class entirely. The marker belongs at MarkerPos and is minted by the runner.
func TestNoELIPayloadCarriesALiteralMarker(t *testing.T) {
	for _, p := range (eliClassifier{}).Probes() {
		if bytes.Contains(bytes.ToLower(p.Logical), []byte(triage.DefaultMarkerAnchor)) &&
			!bytes.Contains(p.Logical, []byte("zqjNoSuchMethod")) {
			t.Errorf("probe %s carries the marker anchor in its logical bytes: %q", p.ID, p.Logical)
		}
		if p.MarkerPos != triage.MarkerPrefix {
			t.Errorf("probe %s uses marker position %q; prefix is what keeps a 16-byte field truncation attributable", p.ID, p.MarkerPos)
		}
	}
}

// TestEveryELIPayloadIsDistinctFromEveryOther.
//
// The registry check only compares ACROSS classes. Two byte-equal payloads inside one class are
// legal and are still a bug: one of them is a request spent measuring something already measured,
// and worse, the ladder cannot tell which of the two produced a hit.
func TestEveryELIPayloadIsDistinctFromEveryOther(t *testing.T) {
	seen := map[string]triage.ProbeID{}
	for _, p := range (eliClassifier{}).Probes() {
		k := string(p.Logical)
		if prev, dup := seen[k]; dup {
			t.Errorf("probes %s and %s ship byte-equal payloads %q, so a hit cannot be attributed to either", p.ID, prev, k)
		}
		seen[k] = p.ID
		if len(p.Logical) == 0 && !p.IsControl {
			t.Errorf("probe %s has no bytes, so it sends nothing and would then record clean", p.ID)
		}
	}
}

// TestTheRegistryStillPassesTheIsolationLaw runs the law over whatever is registered alongside
// this class. With sibling classes landing in the same package this is the check that catches a
// collision on the day it appears rather than on the day somebody reads a report.
func TestTheRegistryStillPassesTheIsolationLaw(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
}

// TestTheEmptyExpressionControlsAvoidSSTIsBytesOnPurpose records a decision that would otherwise
// look like an omission to the next reader.
//
// The natural empty-expression control is ${}, and SSTI-NC3 owns those bytes. Shipping them here
// would be the isolation law's first violation. These three delimiters are ELI-exclusive and test
// the same property.
func TestTheEmptyExpressionControlsAvoidSSTIsBytesOnPurpose(t *testing.T) {
	want := map[triage.ProbeID]string{
		eliProbeNC5a: "%{}",
		eliProbeNC5b: "@{}",
		eliProbeNC5c: "${{}}",
	}
	for _, p := range (eliClassifier{}).Probes() {
		if w, ok := want[p.ID]; ok {
			if string(p.Logical) != w {
				t.Errorf("control %s ships %q, want %q", p.ID, p.Logical, w)
			}
			delete(want, p.ID)
		}
		if string(p.Logical) == "${}" {
			t.Errorf("probe %s ships the bare bytes ${}, which SSTI-NC3 owns; two classes shipping byte-equal payloads is the law's first violation", p.ID)
		}
	}
	for id := range want {
		t.Errorf("empty-expression control %s is missing, so the detector was never shown staying silent on a valid delimiter with nothing in it", id)
	}
}

// -------------------------------------------------------------------------------------------
// The primary oracle: int32 overflow
// -------------------------------------------------------------------------------------------

// eliObs builds an observation with a body and a recorded wire payload.
//
// THE WIRE FORM IS NOT THE LOGICAL FORM AND THESE FIXTURES HAD TO LEARN THAT THE HARD WAY. The
// first version of this helper put the logical bytes straight into Payload.Wire, and four tests
// then failed against eliWireAssertionFailed with "went out with a RAW + on a query slot", which
// is the assertion doing exactly its job: those fixtures described a request the runner must never
// send. The helper now applies the two substitutions a correct query encoder applies, so the
// fixtures describe a legal request and the assertion is exercised on purpose by its own table
// rather than by accident everywhere else.
func eliObs(body string, sentLogical string) triage.Observation {
	wire := strings.ReplaceAll(sentLogical, "%{", "%25{")
	wire = strings.ReplaceAll(wire, "+", "%2B")
	return triage.Observation{
		Body: []byte(body),
		Payload: triage.PayloadWire{
			Logical:  []byte(sentLogical),
			Wire:     []byte(wire),
			Survived: triage.WireSurvivalIntact,
		},
		TransportErr: triage.TransportOK,
	}
}

// TestTheOverflowRuleFiresOnTheTrueShapeAndStaysSilentOnEveryNamedFalsePositive.
//
// The false-positive rows are first-class here, one per mode named in iso-eval ELI 5. They are the
// half of the rule that decides whether the operator trusts any row this class emits.
func TestTheOverflowRuleFiresOnTheTrueShapeAndStaysSilentOnEveryNamedFalsePositive(t *testing.T) {
	m := eliMarkerForTest(t)

	cases := []struct {
		name     string
		body     string
		sent     string
		baseline string
		want     bool
		why      string
	}{
		{
			name: "the answer immediately after this probe's own marker is the true shape",
			body: "<p>" + m + "-494967296</p>", sent: "${1*((1).valueOf('1900000000')+1900000000)}",
			want: true,
			why:  "a Java 32-bit int evaluated the expression, which is the whole oracle",
		},
		{
			name: "up to eight whitespace bytes between the marker and the answer still counts",
			body: m + "    -494967296", sent: "${x}", want: true,
			why: "an HTML template puts whitespace between an echoed value and a computed one",
		},
		{
			name: "more than eight whitespace bytes is two unrelated things on one page",
			body: m + strings.Repeat(" ", 9) + "-494967296", sent: "${x}", want: false,
			why: "without the cap, a marker at the top of a page and a number at the bottom match",
		},
		{
			name: "the UNWRAPPED answer is a different evaluator and must not fire this rule",
			body: m + "3800000000", sent: "${x}", want: false,
			why: "3800000000 is Python, JavaScript, Ruby, PHP or a JVM long. Claiming a JVM int from it is " +
				"over-claiming, and it has its own weaker state",
		},
		{
			name: "the verbatim echo of the payload must not fire",
			body: m + "${1*((1).valueOf('1900000000')+1900000000)}",
			sent: "${1*((1).valueOf('1900000000')+1900000000)}", want: false,
			why: "the echo contains 1900000000 twice and the answer never. Reflection is not injection",
		},
		{
			name: "a longer digit run swallowing the answer must not fire",
			body: m + "-4949672960", sent: "${x}", want: false,
			why: "-4949672960 is a different number and the trailing-digit boundary is what tells them apart",
		},
		{
			name: "the answer preceded by a digit inside a longer token must not fire",
			body: m + "1-494967296", sent: "${x}", want: false,
			why: "the answer has to be adjacent to the marker, not merely somewhere after it",
		},
		{
			name: "a marker glued to the end of a longer alphanumeric token must not fire",
			body: "abc" + m + "-494967296", sent: "${x}", want: false,
			why: "the left boundary stops a token that merely ends in the marker from anchoring a hit",
		},
		{
			name: "NC2: the answer sent as literal text must be suppressed by the wire guard",
			body: m + "-494967296", sent: "-494967296", want: false,
			why: "this is the control that verifies the GUARD rather than the regex, and the guard is what stops " +
				"every echoing endpoint in the world reading as a finding",
		},
		{
			name: "the answer already present in the unperturbed baseline must be suppressed",
			body: m + "-494967296", sent: "${x}", baseline: "account balance -494967296 cents", want: false,
			why: "a page that already carries the number cannot be evidence that the number was computed",
		},
		{
			name: "an uppercased reflection of the marker still anchors the hit",
			body: strings.ToUpper(m) + "-494967296", sent: "${x}", want: true,
			why: "an application that upper-cases a display name would otherwise be a silent false negative",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := eliMatchOverflow(eliObs(tc.body, tc.sent), m, eliWrapped, []byte(tc.baseline))
			if got != tc.want {
				t.Errorf("rule fired = %v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestTheOverflowRuleAlsoSearchesResponseHeaders.
//
// An EL expression interpolated into a Location or a Set-Cookie is a real sink, and the echo of a
// payload into a header can never contain the computed answer, so the extra surface costs nothing.
func TestTheOverflowRuleAlsoSearchesResponseHeaders(t *testing.T) {
	m := eliMarkerForTest(t)
	o := eliObs("nothing here", "${x}")
	o.RespHeaders = [][2]string{{"Location", "/next?u=" + m + "-494967296"}}
	if _, ok := eliMatchOverflow(o, m, eliWrapped, nil); !ok {
		t.Error("the rule missed the answer in a response header, so an expression interpolated into a Location is invisible to this class")
	}
}

// TestTheBareProbeIsCappedByHavingNoAnchorAtAll.
//
// EL6 carries no marker by construction, because a 16-byte prefix turns the value into
// <marker>1*(...), which is a parse error in every dialect. The rule therefore runs unanchored,
// and the two absence guards are all that stand between it and the page's own numbers.
func TestTheBareProbeIsCappedByHavingNoAnchorAtAll(t *testing.T) {
	o := eliObs("result: -494967296", "1*((1).valueOf('1900000000')+1900000000)")
	h, ok := eliMatchOverflow(o, "", eliWrapped, nil)
	if !ok {
		t.Fatal("the unanchored form did not fire, so the single most commonly missed EL sink is untestable")
	}
	if h.Anchored {
		t.Error("the unanchored hit reported itself as anchored, which would let it be graded high on no attribution at all")
	}
	if _, ok := eliMatchOverflow(eliObs("result: -494967296", "x"), "", eliWrapped, []byte("-494967296")); ok {
		t.Error("the unanchored form fired against a baseline that already carried the answer, which is its only real guard")
	}
}

// -------------------------------------------------------------------------------------------
// The independent string oracle
// -------------------------------------------------------------------------------------------

// TestTheStringRuleSeparatesAFullReplacementFromAPartialOneAndFromItsOwnEcho.
//
// The string oracle exists because it fails for DIFFERENT reasons than the arithmetic one: a
// method allow-list on valueOf kills the first and leaves this; a WAF rule on .replace( does the
// reverse. It is therefore verified on its own and not as a corroboration.
func TestTheStringRuleSeparatesAFullReplacementFromAPartialOneAndFromItsOwnEcho(t *testing.T) {
	m := eliMarkerForTest(t)

	cases := []struct {
		name       string
		body, sent string
		baseline   string
		wantOracle string
		why        string
	}{
		{
			name: "both replacements applied is the finding shape",
			body: m + "qm7vbn7w", sent: "${'qmkvbnkw'.replace('k','7')}", wantOracle: eliOracleString,
			why: "a method resolved and ran, which is an evaluator and not a formatter",
		},
		{
			name: "the verbatim echo contains the token and the digit and never the answer",
			body: m + "'qmkvbnkw'.replace('k','7')", sent: "${'qmkvbnkw'.replace('k','7')}", wantOracle: "",
			why: "this is the reason the guard of iso-eval 1.2 was applied to the draw: the answer is not a " +
				"substring of the expression that computes it",
		},
		{
			name: "one of two replacements applied is replaceFirst, a different mechanism",
			body: m + "qm7vbnkw", sent: "${'qmkvbnkw'.replace('k','7')}", wantOracle: eliOraclePartial,
			why: "a method ran, but not the one asked for. Reporting it as the finding would be rounding up",
		},
		{
			name: "NC3: the answer sent as literal text must be suppressed by the wire guard",
			body: m + "qm7vbn7w", sent: "qm7vbn7w", wantOracle: "",
			why: "the same guard as NC2, for the second oracle",
		},
		{
			name: "the answer already in the baseline must be suppressed",
			body: m + "qm7vbn7w", sent: "${x}", baseline: "token qm7vbn7w", wantOracle: "",
			why: "a page that already carries the token cannot be evidence the token was computed",
		},
		{
			name: "the toUpperCase confirmation resolves a second, different method",
			body: m + "QMKVBNKW", sent: "${'qmkvbnkw'.toUpperCase()}", wantOracle: eliOracleString,
			why: "two distinct method invocations is what separates an expression evaluator from a String.format " +
				"or a message interpolator with a narrow API",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, ok := eliMatchString(eliObs(tc.body, tc.sent), m, []byte(tc.baseline))
			got := ""
			if ok {
				got = h.Oracle
			}
			if got != tc.wantOracle {
				t.Errorf("oracle = %q, want %q. %s", got, tc.wantOracle, tc.why)
			}
		})
	}
}

// -------------------------------------------------------------------------------------------
// The unwrapped answer, which is the trap this class was designed around
// -------------------------------------------------------------------------------------------

// TestTheUnwrappedAnswerIsItsOwnWeakerStateAndNeverAFinding.
//
// This is the whole reason the operands were chosen the way they were. An implementation that only
// looks for -494967296 records CLEAN on a real long-typed JVM EL sink, which is a live
// configuration. An implementation that accepts either records a finding it cannot support: 3800000000
// is what Python, JavaScript, Ruby and PHP all answer, and none of them is a JVM EL engine.
func TestTheUnwrappedAnswerIsItsOwnWeakerStateAndNeverAFinding(t *testing.T) {
	m := eliMarkerForTest(t)

	if _, ok := eliMatchOverflow(eliObs(m+"3800000000", "${x}"), m, eliWrapped, nil); ok {
		t.Error("the primary rule fired on the unwrapped answer, so this class would claim a Java int type system it never observed")
	}
	h, ok := eliMatchUnwrapped(eliObs(m+"3800000000", "${x}"), m, nil)
	if !ok {
		t.Fatal("the unwrapped answer produced nothing at all, so a long-typed JVM EL sink would read as clean")
	}
	if h.Oracle != eliOracleUnwrapped {
		t.Errorf("oracle = %q, want %q", h.Oracle, eliOracleUnwrapped)
	}

	// NC4 sends 3800000000 as literal text. It must fire neither rule, and it must NOT be recorded
	// as el_overflow_unwrapped either, because it was transmitted rather than computed.
	if _, ok := eliMatchUnwrapped(eliObs(m+"3800000000", "3800000000"), m, nil); ok {
		t.Error("NC4's transmitted answer was recorded as an unwrapped computation, so the weaker state has the same false-positive mode the strong one was guarded against")
	}

	// And the verdict it produces is suspicious, never a finding.
	v := eliVerdict(eliOpenClassifyCtx(), []eliOwn{
		eliOwnProbe(eliProbeEL1, 66, m, eliObs(m+"3800000000", "${x}")),
		eliOwnProbe(eliProbeELS1, 130, m, eliObs("nothing", "${x}")),
		eliOwnProbe(eliProbeELE, 194, m, eliObs("nothing", "${x}")),
	})
	if v[0].State != triage.StateSuspicious {
		t.Errorf("state = %s, want suspicious: a non-JVM evaluator is SSTI's finding to make from SSTI's own probes, not this class's to claim", v[0].State)
	}
	if v[0].Oracle != eliOracleUnwrapped {
		t.Errorf("oracle = %q, want %q", v[0].Oracle, eliOracleUnwrapped)
	}
}

// -------------------------------------------------------------------------------------------
// The error oracle, and ruling R1
// -------------------------------------------------------------------------------------------

// TestTheErrorRuleIsBaselineDifferencedPerSignatureAndNotPerResponse.
//
// A Struts application with struts.devMode=true prints a Problem Report on every bad request
// including the ones in the baseline. Without the subtraction this class reports a finding on
// every slot of every such application, forever. The subtraction is per SIGNATURE: a baseline
// carrying ognl.OgnlException disables that one and leaves ognl.ParseException live, because the
// second one is still new information.
func TestTheErrorRuleIsBaselineDifferencedPerSignatureAndNotPerResponse(t *testing.T) {
	cases := []struct {
		name        string
		body        string
		baseline    string
		wantFire    bool
		wantDialect string
		why         string
	}{
		{
			name: "a SpEL evaluation exception absent from the baseline fires and names the dialect",
			body: "EL1008E: Property or field 'x' cannot be found", wantFire: true, wantDialect: "spel",
			why: "the numbered SpEL codes are the three to rely on",
		},
		{
			name: "an OGNL exception names OGNL",
			body: "ognl.MethodFailedException: target is null", wantFire: true, wantDialect: "ognl",
			why: "the error oracle identifies as well as detects, which is what makes rank 4 worth a request here",
		},
		{
			name: "an MVEL exception names MVEL",
			body: "org.mvel2.PropertyAccessException: unable to resolve", wantFire: true, wantDialect: "mvel",
			why: "MVEL has no sstimap plugin, so naming it changes the label the operator gets",
		},
		{
			name:     "a devMode Problem Report already in the baseline is disabled for that endpoint",
			body:     "Struts Problem Report: there was an error",
			baseline: "Struts Problem Report: there was an error", wantFire: false,
			why: "this is the subtraction, and without it every slot of every devMode application is a finding",
		},
		{
			name:     "a baseline carrying one OGNL signature leaves the others live",
			body:     "ognl.ParseException at line 1",
			baseline: "ognl.OgnlException in the footer of every page", wantFire: true, wantDialect: "ognl",
			why: "the subtraction is per signature, because a second, different exception is still new information",
		},
		{
			name: "a generic 500 with no catalogue signature fires nothing",
			body: "<h1>500 Internal Server Error</h1>", wantFire: false,
			why: "the rule fires on the SIGNATURE and not on the status; a 500 alone is not evidence of a parser",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, ok := eliMatchError(eliObs(tc.body, "${x}"), []byte(tc.baseline))
			if ok != tc.wantFire {
				t.Fatalf("fired = %v, want %v. %s", ok, tc.wantFire, tc.why)
			}
			if ok && h.Dialect != tc.wantDialect {
				t.Errorf("dialect = %q, want %q", h.Dialect, tc.wantDialect)
			}
		})
	}
}

// TestTheErrorCatalogueNamesNoOtherClasssEngine is ruling R1 as a test.
//
// The defect R1 rules on: SSTI's verdict depended on ELI's signature catalogue and ELI's on
// SSTI's, and on a Spring Boot page with Thymeleaf BOTH classes reported "not tested" on an
// application where a template expression demonstrably reached an evaluator. A class never reads,
// and never needs to know the existence of, another class's catalogue, not even to fail closed.
func TestTheErrorCatalogueNamesNoOtherClasssEngine(t *testing.T) {
	foreign := []string{
		"freemarker", "jinja2", "twig", "velocity", "smarty", "mustache", "handlebars",
		"nunjucks", "pebble", "razor", "liquid", "erb", "haml", "jade", "pug",
	}
	for _, s := range eliSignatures {
		lower := strings.ToLower(s.Literal)
		for _, f := range foreign {
			if strings.Contains(lower, f) {
				t.Errorf("signature %s carries the foreign engine name %q. Ruling R1 deletes that coupling entirely: this class's own ELE and ELS1 probes are what disambiguate", s.ID, f)
			}
		}
	}
}

// TestSSTIsExpectedAnswerFiresNeitherOfThisClasssRules is CATALOGUE 1.2's NC6.
//
// It is a FIXTURE and not a probe on purpose: the body has to contain another class's marker, and
// a ProbeSpec carrying one fails isolation check I1d at build time. The two classes' expected
// answers have to be provably disjoint, and this is where that is proven.
func TestSSTIsExpectedAnswerFiresNeitherOfThisClasssRules(t *testing.T) {
	// SSTI's operands are 1721*913 and its expected answer is 1571273. That answer, and SSTI's
	// grouped rendering of it, must mean nothing to either of this class's rules.
	for _, body := range []string{
		"zqj1f3q000a1kx9m1571273",
		"zqj1f3q000a1kx9m 1,571,273",
		"zqj1f3q000a1kx9m49660049", // and CSTI's, while we are here
	} {
		o := eliObs(body, "${x}")
		if _, ok := eliMatchOverflow(o, eliMarkerForTest(t), eliWrapped, nil); ok {
			t.Errorf("the overflow rule fired on %q, so another class's answer is being read as this class's", body)
		}
		if _, ok := eliMatchString(o, eliMarkerForTest(t), nil); ok {
			t.Errorf("the string rule fired on %q", body)
		}
		if _, ok := eliMatchError(o, nil); ok {
			t.Errorf("the error rule fired on %q", body)
		}
	}
}

// -------------------------------------------------------------------------------------------
// Every unreachable and undecidable path yields an unknown, never a clean
// -------------------------------------------------------------------------------------------

func eliOpenPlanCtx() triage.PlanCtx {
	return triage.PlanCtx{
		Slot: triage.Slot{
			VectorID:        "v1",
			Kind:            triage.KindQuery,
			Key:             "query:sort",
			Name:            "sort",
			Value:           "asc",
			ValueOrigin:     triage.ValueObserved,
			ServerReachable: true,
			SegmentIndex:    -1,
			Constraints:     triage.NewSlotConstraints(),
		},
		Vector:   triage.TriageVector{ID: "v1", Method: "GET", ComposedURL: "https://example.test/list?sort=asc"},
		Baseline: triage.BaselineModel{Samples: 5, Stable: true},
		Prelude:  triage.PreludeTokenNotRequired,
		Budget:   triage.TriageBudget{PerSlot: 24, PerRun: 5000, RemainingPerSlot: 24, RemainingPerRun: 5000},
	}
}

func eliOpenClassifyCtx() triage.ClassifyCtx {
	return triage.ClassifyCtx{PlanCtx: eliOpenPlanCtx()}
}

func eliOwnProbe(id triage.ProbeID, ordinal uint64, marker string, o triage.Observation) eliOwn {
	return eliOwn{Probe: id, Ordinal: ordinal, Marker: marker, Obs: o}
}

// eliSilentRun is a full, well-behaved run in which nothing fired: all three arms delivered, the
// census reflected, every payload proven on the wire. It is the ONLY shape entitled to clean, and
// the tests below mutate one thing at a time away from it.
func eliSilentRun(m string) []eliOwn {
	census := eliObs("<p>hello "+m+"-eli-census</p>", m+"-eli-census")
	quiet := eliObs("<p>hello</p>", "${x}")
	return []eliOwn{
		eliOwnProbe(eliProbeCensus, 2, m, census),
		eliOwnProbe(eliProbeEL1, 66, m, quiet),
		eliOwnProbe(eliProbeELS1, 130, m, quiet),
		eliOwnProbe(eliProbeELE, 194, m, quiet),
	}
}

// TestThisClassCanReachACleanAndOnlyUnderItsStatedPreconditions.
//
// A class that cannot reach clean is as useless as one that reaches it too easily: the operator
// learns nothing from a report in which every row is an unknown. So the green case is asserted
// too, along with the fact that it still carries its two structural gaps.
func TestThisClassCanReachACleanAndOnlyUnderItsStatedPreconditions(t *testing.T) {
	m := eliMarkerForTest(t)
	v := eliVerdict(eliOpenClassifyCtx(), eliSilentRun(m))
	if len(v) != 1 {
		t.Fatalf("got %d verdicts, want exactly one per slot", len(v))
	}
	if v[0].State != triage.StateClean {
		t.Fatalf("state = %s (%s), want clean: every precondition held and every oracle stayed silent", v[0].State, v[0].Reason)
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("the clean verdict fails its own contract: %v", err)
	}
	if len(v[0].Ordinals) == 0 {
		t.Error("a clean with zero probe ordinals asserts a measurement that never happened, and it is a hard error rather than a warning")
	}
	gaps := map[string]bool{}
	for _, u := range v[0].Untested {
		gaps[string(u.ProbeID)] = true
	}
	if !gaps["ELI-EL3N"] {
		t.Error("the clean row does not carry param_name_ognl. A report that names a gap only on the noisy rows hides it on the quiet ones, which are the majority")
	}
	if !gaps["ELI-NONJVM"] {
		t.Error("the clean row does not carry non_jvm_el")
	}
}

// TestEveryWayThisClassCanFailToGetAnAnswerIsAnUnknown is the table that matters most.
//
// Each row breaks exactly one precondition of the silent run above. None of them may come back
// clean. "A tool that never ran, recorded as a pass" is the bug this whole layer exists to stop
// and this codebase has shipped it repeatedly.
func TestEveryWayThisClassCanFailToGetAnAnswerIsAnUnknown(t *testing.T) {
	m := eliMarkerForTest(t)

	cases := []struct {
		name     string
		mutate   func(*triage.ClassifyCtx, *[]eliOwn)
		wantWord string
		why      string
	}{
		{
			name: "a fragment slot is not applicable, because every dialect here runs on the server",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Slot.Kind = triage.KindFragment
				c.Slot.ServerReachable = false
			},
			wantWord: "fragment",
			why:      "RFC 3986 section 3.5: the browser strips it before the request goes out",
		},
		{
			name: "a credential slot is refused rather than probed",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Slot.Constraints.IsCredential = true
			},
			wantWord: "credential_slot",
			why:      "a 401 from an injected Authorization header is a differential that looks exactly like a finding",
		},
		{
			name: "an unobtained prelude token means every probe failed validation identically",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Prelude = triage.PreludeTokenUnobtainable
			},
			wantWord: "prelude_failed",
			why:      "identical validation failures read as a stable endpoint with no differential, which reads as clean",
		},
		{
			name: "an unmeasured prelude is not a prelude that was not needed",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Prelude = triage.PreludeUnknown
			},
			wantWord: "prelude_failed",
			why:      "the zero value of PreludeState is unknown, and unknown fails closed",
		},
		{
			name: "a signed wrapper fails its MAC before any parser sees the payload",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Slot.Wrapper = triage.WrapSigned
			},
			wantWord: "signed_wrapper",
			why:      "javax.faces.ViewState is exactly this case, and a null result on it is not evidence about the sink",
		},
		{
			name: "a degraded baseline makes the absence guards unevaluable",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Baseline.Degraded = true
			},
			wantWord: "baseline_degraded",
			why:      "both computation rules depend on the answer being absent from the baseline",
		},
		{
			name: "an exhausted budget is not_run, and it names itself",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Budget.RemainingPerSlot = 0
			},
			wantWord: "probe_budget_exhausted",
			why:      "a cap that bites produces a named unknown and never a shortened clean",
		},
		{
			name: "a canary-valued slot probed a resource that does not exist",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Slot.ValueOrigin = triage.ValueCanary
			},
			wantWord: "canary_resource",
			why:      "a tool pointed at a 404 that comes back with nothing found is not a clean scan of the endpoint",
		},
		{
			name: "a synthesized value did not take the route a real request takes",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Slot.ValueOrigin = triage.ValueSynthesized
			},
			wantWord: "synthesized_value",
			why:      "the value was invented to have something to perturb",
		},
		{
			name: "an unstable endpoint cannot separate a silent oracle from its own noise",
			mutate: func(c *triage.ClassifyCtx, _ *[]eliOwn) {
				c.Baseline.Stable = false
				c.Baseline.GateReason = "too_volatile"
			},
			wantWord: "endpoint_not_stable",
			why:      "the stability gate is what makes a silence mean anything",
		},
		{
			name: "the census never coming back is no_reflection, and this class has nothing else",
			mutate: func(_ *triage.ClassifyCtx, own *[]eliOwn) {
				(*own)[0].Obs = eliObs("<p>hello</p>", eliMarkerForTest(nil)+"-eli-census")
			},
			wantWord: "no_reflection",
			why: "there is no out-of-band payload and no timing oracle in this class, so a fully blind EL sink is " +
				"honestly undecidable. CATALOGUE 7.1 names it as an admission",
		},
		{
			name: "a transport refusal is could-not-send, never a quiet response",
			mutate: func(_ *triage.ClassifyCtx, own *[]eliOwn) {
				o := (*own)[1].Obs
				o.TransportErr = triage.TransportInvalidHeader
				(*own)[1].Obs = o
			},
			wantWord: "transport_refused",
			why:      "a NUL byte in a header value produces an error at send time and that probe tested nothing",
		},
		{
			name: "an unproven wire survival is not a survived one",
			mutate: func(_ *triage.ClassifyCtx, own *[]eliOwn) {
				o := (*own)[1].Obs
				o.Payload.Survived = triage.WireSurvivalUnknown
				(*own)[1].Obs = o
			},
			wantWord: "payload_not_proven_on_wire",
			why: "Go's cookie sanitizer silently drops the quote, the backslash and the semicolon, and a mangled " +
				"payload is indistinguishable after the fact from a defended one",
		},
		{
			name: "the string arm never delivered means the silence is not the class's silence",
			mutate: func(_ *triage.ClassifyCtx, own *[]eliOwn) {
				*own = []eliOwn{(*own)[0], (*own)[1], (*own)[3]}
			},
			wantWord: "arm_not_delivered",
			why: "a method allow-list on valueOf kills the overflow arm and leaves the string arm standing; a " +
				"silence from one arm is not a silence from the class",
		},
		{
			name: "the error arm never delivered is the same failure from the other side",
			mutate: func(_ *triage.ClassifyCtx, own *[]eliOwn) {
				*own = (*own)[:3]
			},
			wantWord: "arm_not_delivered",
			why:      "three arms were declared and three have to run",
		},
		{
			name: "no probe derived at all is not_planned and says so",
			mutate: func(_ *triage.ClassifyCtx, own *[]eliOwn) {
				*own = nil
			},
			wantWord: "no_probe_derived",
			why:      "a slot with no row reads as untouched, which is the same pixel as a slot nobody wrote code for",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := eliOpenClassifyCtx()
			own := eliSilentRun(m)
			tc.mutate(&ctx, &own)

			var v []triage.ClassVerdict
			if _, closed := eliCheckGates(ctx.PlanCtx); closed {
				v = (eliClassifier{}).Classify(ctx)
			} else {
				v = eliVerdict(ctx, own)
			}

			if len(v) != 1 {
				t.Fatalf("got %d verdicts, want exactly one", len(v))
			}
			if v[0].State.CountsAsClean() {
				t.Fatalf("state is CLEAN with reason %q. %s", v[0].Reason, tc.why)
			}
			if !v[0].State.IsUnknown() {
				t.Fatalf("state %s is not an unknown, so an aggregate would count it as a measurement. %s", v[0].State, tc.why)
			}
			if !strings.Contains(v[0].Reason, tc.wantWord) {
				t.Errorf("reason %q does not name %q, and an unknown whose reason does not say what stopped the measurement is how a check that never ran becomes a clean", v[0].Reason, tc.wantWord)
			}
			if err := v[0].Validate(); err != nil {
				t.Errorf("verdict fails its own contract: %v", err)
			}
		})
	}
}

// -------------------------------------------------------------------------------------------
// The control set, the wire assertions and the block detector
// -------------------------------------------------------------------------------------------

// TestAFiredNegativeControlVoidsTheWholeSlotEvenWhenSomethingElseHit.
//
// A detector that fires on its own inert echo has not detected anything, so this outranks a hit.
// The alternative is reporting a finding produced by a rule that was demonstrably matching the
// wrong thing on that exact slot.
func TestAFiredNegativeControlVoidsTheWholeSlotEvenWhenSomethingElseHit(t *testing.T) {
	m := eliMarkerForTest(t)
	own := eliSilentRun(m)
	// A real hit on EL1.
	own[1].Obs = eliObs(m+"-494967296", "${1*((1).valueOf('1900000000')+1900000000)}")
	// And NC1, the inert echo, firing the same rule. The echo contains no answer, so the only way
	// this happens is a rule matching unanchored.
	own = append(own, eliOwnProbe(eliProbeNC1, 258, m, eliObs(m+"-494967296", "x24x7Bnothing")))

	v := eliVerdict(eliOpenClassifyCtx(), own)
	if v[0].State != triage.StateCannotDetermine {
		t.Fatalf("state = %s, want cannot_determine: a control fired, so the detector was never shown staying silent here", v[0].State)
	}
	if !strings.Contains(v[0].Reason, "detector_unverified") {
		t.Errorf("reason %q does not say detector_unverified", v[0].Reason)
	}
}

// TestAnEmptyExpressionControlThatMerelyERRORSIsNotAControlFailure.
//
// NC5a, NC5b and NC5c send valid delimiters with nothing inside. An error from one of them is a
// legitimate E-D3 hit and iso-eval ELI 4 says so explicitly. Treating it as a control failure
// would void every slot on every application that reports parse errors.
func TestAnEmptyExpressionControlThatMerelyERRORSIsNotAControlFailure(t *testing.T) {
	m := eliMarkerForTest(t)
	own := eliSilentRun(m)
	own = append(own, eliOwnProbe(eliProbeNC5a, 258, m, eliObs("ognl.ParseException: unexpected token", "%{}")))

	if _, fired := eliFiredControl(own, nil); fired {
		t.Error("an empty-expression control that produced a parse error was counted as a control failure, which would void the slot on every application that reports parse errors")
	}
}

// TestARawPercentOrARawPlusOnTheWireIsALoudRunnerBugAndNeverAVerdict.
//
// These are the two silent killers of CATALOGUE 1.2. A %{ sent raw on a query slot makes Go's
// QueryUnescape error and Java's URLDecoder throw, and the resulting 400 on every probe reads as a
// WAF block when in fact nothing was tested. A + sent raw between the operands decodes to SPACE,
// the expression becomes two integers with a space between them, and the class records a parse
// error where it should have recorded an evaluation.
func TestARawPercentOrARawPlusOnTheWireIsALoudRunnerBugAndNeverAVerdict(t *testing.T) {
	m := eliMarkerForTest(t)

	cases := []struct {
		name string
		kind triage.SlotKind
		wire string
		want bool
		why  string
	}{
		{
			name: "a raw %{ on a query slot is the bug", kind: triage.KindQuery,
			wire: m + "%{1*(@java.lang.Integer@valueOf('1900000000')%2B1900000000)}", want: true,
			why: "the percent has to be %25 on query, form and path",
		},
		{
			name: "a raw %{ on a HEADER slot is correct and must not be flagged", kind: triage.KindHeader,
			wire: m + "%{1*(@java.lang.Integer@valueOf('1900000000')+1900000000)}", want: false,
			why: "percent is legal raw in a field-vchar, which is why the header is the best OGNL slot in the class",
		},
		{
			name: "a raw + anywhere in a query payload is the second bug", kind: triage.KindQuery,
			wire: m + "$%7B1*((1).valueOf('1900000000')+1900000000)%7D", want: true,
			why: "PHP, Python parse_qs, Go ParseQuery, Java and Rails all decode it to SPACE. Note that the two " +
				"operands are NOT adjacent in the rendered payload, which is why the check cannot look for " +
				"1900000000+1900000000",
		},
		{
			name: "a raw + on a PATH slot is correct and must not be flagged", kind: triage.KindPath,
			wire: m + "$%7B1*((1).valueOf('1900000000')+1900000000)%7D", want: false,
			why: "in a path segment the plus is a sub-delim and a literal plus, which is the opposite rule for the same byte",
		},
		{
			name: "a correctly escaped query payload is not flagged", kind: triage.KindQuery,
			wire: m + "$%7B1*((1).valueOf('1900000000')%2B1900000000)%7D", want: false,
			why: "this is what the encoder is supposed to produce",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := eliObs("whatever", "")
			o.Payload.Wire = []byte(tc.wire)
			slot := triage.Slot{Kind: tc.kind, Key: "k"}
			bad, why := eliWireAssertionFailed(slot, []eliOwn{eliOwnProbe(eliProbeEL3, 66, m, o)})
			if (bad != "") != tc.want {
				t.Errorf("flagged = %v (%s), want %v. %s", bad != "", why, tc.want, tc.why)
			}
		})
	}
}

// TestABareProbeThatWentOutCarryingAMarkerIsNotClean.
//
// There is no MarkerPos value that means "no marker": prefix, suffix and inline all attach one.
// The requirement is declared in the ProbeRequest Variant and VERIFIED here, because if the runner
// does not honour it the bare expression becomes <marker>1*(...), which is a parse error in every
// dialect, and the single most commonly missed EL sink would be recorded as tested.
func TestABareProbeThatWentOutCarryingAMarkerIsNotClean(t *testing.T) {
	m := eliMarkerForTest(t)
	own := eliSilentRun(m)
	spoiled := eliObs("<p>hello</p>", m+"1*((1).valueOf('1900000000')+1900000000)")
	own = append(own, eliOwnProbe(eliProbeEL6, 322, m, spoiled))

	if bad := eliBareProbeCarriedAMarker(own); bad != eliProbeEL6 {
		t.Fatalf("the check returned %q, want %s: a marker in the bytes that actually went out means the expression was a parse error", bad, eliProbeEL6)
	}
	v := eliVerdict(eliOpenClassifyCtx(), own)
	if v[0].State.CountsAsClean() {
		t.Error("the slot came back clean although the bare-expression probe tested a parse error rather than a sink")
	}
	if !strings.Contains(v[0].Reason, "bare_expression_marker_attached") {
		t.Errorf("reason %q does not name the failure, so nobody would know to fix the runner", v[0].Reason)
	}

	// And the requirement is actually declared, not only checked.
	if eliVariantFor(eliProbeEL6)["marker_placement"] != "omitted" {
		t.Error("EL6's request does not declare marker_placement=omitted, so the runner has no way to honour it")
	}
	if eliVariantFor(eliProbeCF6)["marker_placement"] != "omitted" {
		t.Error("CF6 is a confirmation AND a bare probe; it has to declare the omission too or the confirmation tests a parse error")
	}
	if eliVariantFor(eliProbeCF6)["expected"] != eliWrapped2 {
		t.Error("CF6 does not carry the fresh expected answer, so a reproduction could be a cached copy of the first response")
	}
}

// TestThreeIdenticalRepliesToThreeDistinctPayloadsIsABlockAndNotASilence.
//
// Foundations 5.8, computed from THIS class's own payloads only. A filter answering identically is
// not the application staying quiet, and the difference is the whole verdict.
func TestThreeIdenticalRepliesToThreeDistinctPayloadsIsABlockAndNotASilence(t *testing.T) {
	m := eliMarkerForTest(t)
	blocked := eliObs("<h1>403 Forbidden</h1>", "${x}")
	blocked.BodySHA256 = [32]byte{0xbb}

	own := []eliOwn{
		eliOwnProbe(eliProbeCensus, 2, m, eliObs("<p>hello "+m+"-eli-census</p>", m+"-eli-census")),
		eliOwnProbe(eliProbeEL1, 66, m, blocked),
		eliOwnProbe(eliProbeEL3, 130, m, blocked),
		eliOwnProbe(eliProbeELS1, 194, m, blocked),
		eliOwnProbe(eliProbeELE, 258, m, blocked),
	}
	if !eliUniformBlock(own, []byte("<p>hello</p>")) {
		t.Fatal("four distinct payloads produced one byte-identical non-baseline response and it was not read as a block")
	}

	// With NO baseline in hand the same four responses mean nothing: three identical replies from
	// a stable page look exactly like three identical replies from a filter, and calling that a
	// block would turn every quiet endpoint into an unknown.
	if eliUniformBlock(own, nil) {
		t.Error("a block was declared with no baseline to differ from, which would make every stable endpoint read as filtered")
	}

	// And responses that simply match the baseline are the page answering, not a filter.
	same := eliObs("<p>hello</p>", "${x}")
	quiet := []eliOwn{
		eliOwnProbe(eliProbeEL1, 66, m, same),
		eliOwnProbe(eliProbeEL3, 130, m, same),
		eliOwnProbe(eliProbeELS1, 194, m, same),
	}
	if eliUniformBlock(quiet, []byte("<p>hello</p>")) {
		t.Error("three responses identical to the BASELINE were read as a block; that is the endpoint being stable, which is the condition a clean needs")
	}
}

// -------------------------------------------------------------------------------------------
// The positive end to end, including the label, which is what this layer exists to produce
// -------------------------------------------------------------------------------------------

// TestAConfirmedOverflowHitIsAFindingAndTheLabelNamesTheDialectAndThePlugin.
//
// The verdict word is the less useful half. "Point sstimap at this slot with -e ognl" is what
// saves the operator the cold start, and CATALOGUE 1.0 is explicit that the label is what the
// class feeds forward.
func TestAConfirmedOverflowHitIsAFindingAndTheLabelNamesTheDialectAndThePlugin(t *testing.T) {
	m := eliMarkerForTest(t)
	own := eliSilentRun(m)
	own[1].Obs = eliObs("<p>"+m+"-494967296</p>", "${1*((1).valueOf('1900000000')+1900000000)}")
	own = append(own,
		eliOwnProbe(eliProbeCF1, 322, m, eliObs("<p>"+m+"-694967296</p>", "${1*((1).valueOf('1800000000')+1800000000)}")),
		eliOwnProbe(eliProbeIDOgnlDollar, 386, m, eliObs("<p>"+m+"-494967296</p>", "${1*(@java.lang.Integer@valueOf('1900000000')+1900000000)}")),
	)

	v := eliVerdict(eliOpenClassifyCtx(), own)
	if v[0].State != triage.StateFinding {
		t.Fatalf("state = %s (%s), want finding: the answer reproduced with fresh operands", v[0].State, v[0].Reason)
	}
	if v[0].Grade != triage.GradeHigh {
		t.Errorf("grade = %q, want high: rank 1 oracle, guard asserted, reproduced with a fresh marker and fresh operands", v[0].Grade)
	}
	if v[0].Oracle != eliOracleOverflow {
		t.Errorf("oracle = %q, want %q", v[0].Oracle, eliOracleOverflow)
	}
	if v[0].Label.Dialect != "ognl" {
		t.Errorf("dialect = %q, want ognl: the @java.lang@ identification body evaluated", v[0].Label.Dialect)
	}
	if v[0].Label.Hints["sstimap_engine"] != "ognl" {
		t.Errorf("sstimap_engine = %q, want ognl", v[0].Label.Hints["sstimap_engine"])
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("the finding fails its own contract: %v", err)
	}
}

// TestAnUnconfirmedOverflowHitStopsAtSuspicious.
//
// One measurement is not a measurement. The confirmation uses fresh OPERANDS and not merely a
// fresh marker, so a reproduction cannot be a cached copy of the first response.
func TestAnUnconfirmedOverflowHitStopsAtSuspicious(t *testing.T) {
	m := eliMarkerForTest(t)
	own := eliSilentRun(m)
	own[1].Obs = eliObs("<p>"+m+"-494967296</p>", "${1*((1).valueOf('1900000000')+1900000000)}")

	v := eliVerdict(eliOpenClassifyCtx(), own)
	if v[0].State != triage.StateSuspicious {
		t.Fatalf("state = %s, want suspicious with no confirmation in hand", v[0].State)
	}
	if v[0].Grade == triage.GradeHigh {
		t.Error("an unconfirmed hit was graded high, and high requires reproduction with a fresh marker")
	}

	// A confirmation that came back with the OLD answer is a cached body, not a reproduction.
	own = append(own, eliOwnProbe(eliProbeCF1, 322, m, eliObs("<p>"+m+"-494967296</p>", "${1*((1).valueOf('1800000000')+1800000000)}")))
	v = eliVerdict(eliOpenClassifyCtx(), own)
	if v[0].State == triage.StateFinding {
		t.Error("a confirmation that reproduced the OLD answer was accepted, which promotes a cached response to a finding")
	}
}

// -------------------------------------------------------------------------------------------
// Reachability and the ladder
// -------------------------------------------------------------------------------------------

// TestReachesAnswersWithAReasonWhereverOneIsRequired.
//
// ValidateClassifier enforces this at registration, where a failure is a panic out of an init() in
// a package the reader never opened. Running it here turns that into a named failure next to the
// class.
func TestReachesAnswersWithAReasonWhereverOneIsRequired(t *testing.T) {
	c := eliClassifier{}
	for _, k := range triage.AllSlotKinds() {
		for _, mt := range []triage.MediaType{"", "application/json", "application/x-www-form-urlencoded",
			"multipart/form-data", "application/xml", "application/graphql", "text/html"} {
			r := c.Reaches(k, mt)
			if r.Reach != triage.ReachAlways && strings.TrimSpace(r.Reason) == "" {
				t.Errorf("Reaches(%s, %q) returned %s with no reason, and an operator cannot tell ruled out from nobody wired this up", k, mt, r.Reach)
			}
		}
	}
	if r := c.Reaches(triage.KindFragment, "text/html"); r.Reach != triage.ReachNever {
		t.Error("the fragment is reachable, but it never leaves the browser and every dialect in this class runs on the server")
	}
	for _, k := range []triage.SlotKind{triage.KindQuery, triage.KindHeader, triage.KindCookie, triage.KindPath} {
		if c.Reaches(k, "").Reach != triage.ReachAlways {
			t.Errorf("%s is not always reached. iso-eval ELI 7 refuses the Java-stack gate: the banner describes the edge and not the origin, and this class costs about fourteen requests", k)
		}
	}
}

// TestTheLadderSendsTheCensusFirstAndNeverExitsEarlyOnSilence.
//
// CATALOGUE 2.1 for this class: no early exit on "nothing yet". EL1 being silent says nothing
// whatever about EL6, which reaches a completely different sink shape.
func TestTheLadderSendsTheCensusFirstAndNeverExitsEarlyOnSilence(t *testing.T) {
	r0 := eliPlanRound(eliPlanCtxAtRound(0), "", false)
	if len(r0) != 2 || r0[0].Spec != eliProbeCensus || r0[1].Spec != eliProbeDecode {
		t.Fatalf("round 0 planned %v, want the census and this class's own decode control", eliSpecs(r0))
	}
	r1 := eliPlanRound(eliPlanCtxAtRound(1), "", false)
	if len(r1) != 1 || r1[0].Spec != eliProbeEL1 {
		t.Fatalf("round 1 planned %v, want the primary alone", eliSpecs(r1))
	}
	// Round 2 with nothing found. The whole rest of the battery must still go out.
	r2 := eliPlanRound(eliPlanCtxAtRound(2), "", false)
	got := map[triage.ProbeID]bool{}
	for _, r := range r2 {
		got[r.Spec] = true
	}
	for _, want := range []triage.ProbeID{eliProbeEL2, eliProbeEL3, eliProbeEL4, eliProbeEL5,
		eliProbeEL6, eliProbeEL6m, eliProbeEL7, eliProbeEL8, eliProbeELS1, eliProbeELS2, eliProbeELE} {
		if !got[want] {
			t.Errorf("round 2 did not plan %s after a silent primary. A negative from EL1 says nothing about it", want)
		}
	}
}

// TestAClosedGateSendsNotOneByte.
//
// Zero requests is the right answer when the route is unresolved or the prelude failed, and the
// verdict has to say WHICH, because "no probes" with no reason is how a check that never ran
// becomes a clean.
func TestAClosedGateSendsNotOneByte(t *testing.T) {
	c := eliClassifier{}
	ctx := eliOpenPlanCtx()
	ctx.Prelude = triage.PreludeTokenUnobtainable
	if reqs := c.Plan(ctx); len(reqs) != 0 {
		t.Errorf("planned %d requests with the prelude unobtainable; the token would fail on every one of them", len(reqs))
	}
	ctx = eliOpenPlanCtx()
	ctx.Slot.Constraints.IsCredential = true
	if reqs := c.Plan(ctx); len(reqs) != 0 {
		t.Errorf("planned %d requests into a credential slot", len(reqs))
	}
	// And the route gate, which Plan applies LAST because it is the one that costs a request.
	// eliOpenPlanCtx cannot carry a resolved Replay (only the triage package can mint one), so
	// every ctx in this file is route-unresolved and Plan must therefore refuse all of them.
	if reqs := c.Plan(eliOpenPlanCtx()); len(reqs) != 0 {
		t.Errorf("planned %d requests with the route control unresolved; there would be nothing to difference against", len(reqs))
	}
	if _, closed := eliRouteGate(eliOpenPlanCtx()); !closed {
		t.Error("the route gate reported open on a ctx carrying no route control at all")
	}
}

// TestTheBudgetTruncatesTheBatteryRatherThanTheClassPretendingItRanIt.
func TestTheBudgetTruncatesTheBatteryRatherThanTheClassPretendingItRanIt(t *testing.T) {
	ctx := eliPlanCtxAtRound(2)
	ctx.Budget.PerSlot = 3
	ctx.Budget.RemainingPerSlot = 3
	reqs := eliPlanRound(ctx, "", false)
	if len(reqs) != 3 {
		t.Fatalf("planned %d requests against a remaining budget of 3", len(reqs))
	}
	if reqs[0].Spec != eliProbeEL3 {
		t.Errorf("the truncated battery starts with %s; the OGNL, bare-sink and string probes are the three the reduced tier keeps", reqs[0].Spec)
	}
}

func eliPlanCtxAtRound(round int) triage.PlanCtx {
	c := eliOpenPlanCtx()
	c.Round = round
	return c
}

func eliSpecs(reqs []triage.ProbeRequest) []triage.ProbeID {
	out := make([]triage.ProbeID, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Spec)
	}
	return out
}

// -------------------------------------------------------------------------------------------
// The declarations the oracle pass reads
// -------------------------------------------------------------------------------------------

// TestTheOracleCasesDeclareAPositiveAndANegativeAndNameWhatIsMissing.
//
// A detector never shown to STAY SILENT is not verified, and neither is one never shown firing.
// CATALOGUE 6.1 records that this class is currently in the second state, so the declaration has
// to name the routes that would fix it.
func TestTheOracleCasesDeclareAPositiveAndANegativeAndNameWhatIsMissing(t *testing.T) {
	cases := (eliClassifier{}).OracleCases()
	var pos, neg, missing int
	for _, c := range cases {
		switch c.Expect {
		case "positive":
			pos++
		case "negative":
			neg++
		default:
			t.Errorf("route %s declares expectation %q, which is neither positive nor negative", c.Route, c.Expect)
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("route %s carries no reason, so whoever builds it does not know what it is for", c.Route)
		}
		if len(c.Probes) == 0 {
			t.Errorf("route %s names no probe, so nothing would be run against it", c.Route)
		}
		if strings.Contains(c.Why, "MISSING") {
			missing++
		}
	}
	if pos == 0 {
		t.Error("no positive oracle route is declared, so the detectors would ship having only been seen staying silent")
	}
	if neg == 0 {
		t.Error("no negative oracle route is declared, and the silent route is the one that actually tests a detector")
	}
	if missing == 0 {
		t.Error("nothing is marked MISSING, but CATALOGUE 6.1 records that this class has no positive control in the rig today. Hiding that makes the gap invisible to the oracle pass")
	}
	t.Logf("declared %d positive and %d negative oracle routes, %d of which do not exist yet", pos, neg, missing)
}

// TestEveryConfirmerAndEvidencerPointsAtADeclaredProbeAndANamedOracle.
func TestEveryConfirmerAndEvidencerPointsAtADeclaredProbeAndANamedOracle(t *testing.T) {
	declared := map[triage.ProbeID]bool{}
	for _, p := range (eliClassifier{}).Probes() {
		declared[p.ID] = true
	}
	for _, cf := range (eliClassifier{}).Confirmers() {
		if !declared[cf.After] {
			t.Errorf("confirmer fires after undeclared probe %s", cf.After)
		}
		for _, s := range cf.Send {
			if !declared[s] {
				t.Errorf("confirmer after %s sends undeclared probe %s", cf.After, s)
			}
		}
		if cf.Downgrades == "" {
			t.Errorf("confirmer after %s names no downgrade, and what happens when a confirmation does NOT reproduce is the half that keeps a cached body out of the findings", cf.After)
		}
	}
	known := map[string]bool{
		eliOracleOverflow: true, eliOracleGrouped: true, eliOracleUnwrapped: true,
		eliOracleString: true, eliOraclePartial: true, eliOracleError: true,
	}
	seen := map[string]bool{}
	for _, e := range (eliClassifier{}).Evidencers() {
		if !known[e.Oracle] {
			t.Errorf("evidencer names oracle %q, which no rule in this class emits", e.Oracle)
		}
		seen[e.Oracle] = true
	}
	for o := range known {
		if !seen[o] {
			t.Errorf("oracle %q is emitted by a rule and described by no evidencer, so the report has nothing to print next to it", o)
		}
	}
}

// TestSettleIsANoOpAndSaysWhy.
//
// This class has no out-of-band payload, no collaborator subdomain, no delayed read-back and no
// stored write, so there is nothing to come back later for. The absence is a method rather than a
// silence because it is also the reason a fully blind EL sink is undecidable here.
func TestSettleIsANoOpAndSaysWhy(t *testing.T) {
	if reqs := (eliClassifier{}).Settle(eliOpenClassifyCtx()); len(reqs) != 0 {
		t.Errorf("Settle planned %d deferred requests; this class has no out-of-band oracle to settle", len(reqs))
	}
}

// TestNoPayloadInThisClassIsDestructive is the safety floor, asserted rather than trusted.
//
// Every payload here writes a value the application already accepts into a field it already reads.
// Nothing creates or deletes a record, nothing forks, nothing writes to disk, nothing loops and
// nothing reaches a third party. The one probe that touches the JVM reads java.version, which is a
// read with no side effect, and it is opt-in and sent once per vector after a confirmed finding.
func TestNoPayloadInThisClassIsDestructive(t *testing.T) {
	forbidden := []string{
		"DROP ", "DELETE ", "INSERT ", "UPDATE ", "TRUNCATE",
		"exec(", "exit(", "halt(", "shutdown", "Runtime", "ProcessBuilder",
		"FileOutputStream", "FileWriter", "delete()", "renameTo", "System.exit",
		"http://", "https://", "ldap://", "rmi://", "jndi:",
	}
	for _, p := range (eliClassifier{}).Probes() {
		body := string(p.Logical)
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				t.Errorf("probe %s contains %q, which is outside what a triage probe may do: %q", p.ID, f, body)
			}
		}
		if p.Risk == triage.RiskR3 {
			t.Errorf("probe %s is R3. Nothing in this class needs to be destructive or noisy", p.ID)
		}
	}
	// java.version is the one reflective read, and it has to be opt-in.
	for _, p := range (eliClassifier{}).Probes() {
		if p.ID == eliProbeJVM && p.Tier != triage.TierOptIn {
			t.Errorf("the java.version read is tier %q; it reads a system property and belongs behind the operator's choice", p.Tier)
		}
	}
}
