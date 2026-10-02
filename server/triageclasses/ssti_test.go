package triageclasses

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// Tests for the SSTI classifier.
//
// WHAT THESE TESTS ARE FOR, AND IT IS NOT COVERAGE. A detector that has only ever been observed
// FIRING is not a verified detector: it is indistinguishable from one that always says yes. Every
// rule below therefore gets two tables, one of shapes it must catch and one of shapes it must
// stay silent on, and the silent table carries every false positive the research names by number.
//
// THE SECOND THING THEY ARE FOR is the rule that an unknown never becomes a clean. This codebase
// has shipped a tool that never ran being recorded as a pass, repeatedly, for a week. Every path
// by which this class can fail to get an answer has a row in TestNoPathToCleanWithoutEvidence.
//
// WHAT THEY CANNOT DO. A classifier cannot build a ClassifyCtx carrying responses: a Perturbed is
// minted by the vault under a capability whose type lives in server/utils/internal/triagecap, and
// this package sits outside server/utils precisely so it cannot spell that import. That is the
// isolation law working, and it means the ladder is tested through sstiCompose, which takes the
// scorecard the scorer would have produced, rather than through Classify with a live context.

// sstiTestMarker builds a well-formed marker in THIS class's ordinal stripe. It uses the exported
// checksum function rather than a hardcoded literal, so a change to the checksum cannot leave the
// tests passing against markers the runner would never mint.
func sstiTestMarker(t *testing.T, runID string, ordinal uint64) triage.Marker {
	t.Helper()
	if ordinal%triage.ClassStripeModulus != uint64(triage.ClassSSTI) {
		t.Fatalf("ordinal %d has stripe %d, which is not class SSTI, so a marker built from it would attribute to another class",
			ordinal, ordinal%triage.ClassStripeModulus)
	}
	digits := strconv.FormatUint(ordinal, 36)
	digits = strings.Repeat("0", triage.MarkerOrdinalLen-len(digits)) + digits
	prefix := triage.DefaultMarkerAnchor + runID + digits
	sum, err := triage.MarkerChecksumFor(prefix)
	if err != nil {
		t.Fatalf("MarkerChecksumFor(%q): %v", prefix, err)
	}
	m := triage.Marker(prefix + sum)
	if !m.WellFormed() || m.Integrity() != triage.MarkerValid || !m.BelongsTo(triage.ClassSSTI) {
		t.Fatalf("built %q, which is not a valid SSTI marker", m)
	}
	return m
}

// ---------------------------------------------------------------------------------------------
// registration and the contract
// ---------------------------------------------------------------------------------------------

func TestSSTIClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassSSTI)
	if !ok {
		t.Fatal("SSTI did not register itself, so the class would be silently absent from every report and no error would say so anywhere")
	}
	if c.ID() != triage.ClassSSTI {
		t.Fatalf("registered under SSTI but reports id %s", c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassSSTI {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
		if len(p.Logical) == 0 && !p.IsControl {
			t.Errorf("probe %s has no bytes, so it sends nothing and would still record a measurement", p.ID)
		}
		if p.MarkerPos != triage.MarkerPrefix {
			t.Errorf("probe %s does not put the marker at the prefix, so a sixteen-byte field truncation would leave nothing attributable", p.ID)
		}
		if p.Risk != triage.RiskR1 {
			t.Errorf("probe %s is graded %s; every payload in this class writes a value the app already accepts and nothing more", p.ID, p.Risk)
		}
	}
}

func TestSSTIRegistryStillPassesTheIsolationLaw(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
}

// Every delimiter family is a DIFFERENT PAYLOAD. ${7*7}, {{7*7}} and <%=7*7%> are three grammars
// reaching disjoint engine sets, not three spellings of one probe, and a table that collapsed two
// of them would silently drop whole language ecosystems while still reporting a clean.
func TestSSTIEveryDelimiterFamilyShipsItsOwnPayload(t *testing.T) {
	seen := map[string]triage.ProbeID{}
	for _, p := range (sstiClassifier{}).Probes() {
		k := string(triage.NormaliseMarkers(p.Logical))
		if prev, dup := seen[k]; dup {
			t.Errorf("probes %s and %s ship byte-equal payloads, so a block or a rejection cannot be attributed to either family", prev, p.ID)
		}
		seen[k] = p.ID
	}
	for _, want := range []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF7, sstiF8, sstiF9, sstiF10, sstiF11} {
		if _, ok := sstiSpecByID()[want]; !ok {
			t.Errorf("family %s is missing, and the engines it alone reaches would be recorded clean", want)
		}
	}
}

func TestSSTIEveryFamilyNamesTheEnginesItReaches(t *testing.T) {
	for _, fam := range []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF7, sstiF8, sstiF9, sstiF10, sstiF11, sstiC1} {
		if len(sstiFamilyEngines[fam]) == 0 {
			t.Errorf("family %s identifies no engine, so a hit could not tell the operator which tool to run", fam)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// RULE COMPUTATION: the true shape
// ---------------------------------------------------------------------------------------------

func TestSSTITheComputationRuleFiresOnTheTrueShape(t *testing.T) {
	m := sstiTestMarker(t, "1f3q", 65)
	cases := []struct {
		name string
		body string
		gap  int
	}{
		{"the answer immediately after the marker", string(m) + "1571273", 0},
		{"inside a larger page", "<html><p>hello " + string(m) + "1571273</p></html>", 0},
		{"one space of gap, which a few engines emit", string(m) + " 1571273", 1},
		{"a newline and an indent, the reason the gap exists at all", string(m) + "\n    1571273", 5},
		{"en_US grouping, which is how FreeMarker renders by default", string(m) + "1,571,273", 0},
		{"de_CH apostrophe grouping", string(m) + "1'571'273", 0},
		{"Indic lakh grouping", string(m) + "15,71,273", 0},
		{"a no-break space separator", string(m) + "1 571 273", 0},
		{"the marker uppercased by the application", strings.ToUpper(string(m)) + "1571273", 0},
		{"followed by a non-digit", string(m) + "1571273</td>", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hit, ok := sstiComputationHit([]byte(tc.body), m, sstiExpected)
			if !ok {
				t.Fatalf("the computation rule stayed silent on %q, which is a false negative on a real evaluation", tc.body)
			}
			if hit.GapBytes != tc.gap {
				t.Errorf("gap_bytes %d, want %d; the gap is what decides whether the hit grades high", hit.GapBytes, tc.gap)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// RULE COMPUTATION: every named false positive, as a first-class row
// ---------------------------------------------------------------------------------------------

func TestSSTITheComputationRuleStaysSilentOnEveryNamedFalsePositive(t *testing.T) {
	m := sstiTestMarker(t, "1f3q", 65)
	other := sstiTestMarker(t, "1f3q", 129)
	cases := []struct {
		name string
		body string
		why  string
	}{
		{
			"a verbatim echo of the payload",
			string(m) + "${1721*913}",
			"iso-eval SSTI 5 mode 1: the echo carries both operands adjacent to the marker and never the product",
		},
		{
			"the HTML-entity-encoded echo",
			string(m) + "&#36;{1721*913}",
			"same mode, through an escaping layer",
		},
		{
			"the answer somewhere else on the page",
			"total 1571273 items<br>" + string(m) + " reflected",
			"mode 1 again: an unanchored search for a seven-digit number in a 40 KB page is a coin flip, and adjacency is the whole defence",
		},
		{
			"a longer digit run that contains the answer on the left",
			string(m) + "21571273",
			"the marker's own left guard cannot see this, so the answer has to be matched as a whole token",
		},
		{
			"a longer digit run that contains the answer on the right",
			string(m) + "15712730",
			"the explicit right guard is what excludes it",
		},
		{
			"a decimal number whose digits contain the answer",
			string(m) + "1571273.4",
			"the right guard again, through a decimal point",
		},
		{
			"a decimal with a separator at ONE grouping boundary",
			string(m) + "1571.273",
			"CATALOGUE 1.1 names this as a must-not-match, and its own regex matches it: an optional separator at each boundary independently accepts one separator at one boundary. Requiring every boundary of a scheme to carry the SAME separator is what actually excludes it",
		},
		{
			"a decimal with a separator at the other boundary",
			string(m) + "1.571273",
			"the same defect from the other side",
		},
		{
			"a European decimal whose integer part is the answer",
			string(m) + "1571273,4",
			"the same defect through a decimal comma, which half the world writes",
		},
		{
			"formatted reflection of one operand",
			string(m) + "1,721",
			"iso-eval SSTI 5 mode 4: the app parsed the parameter as a number and echoed it formatted. The expected value is the PRODUCT and 1,721 is not it",
		},
		{
			"a gap wider than the budget",
			string(m) + "         1571273",
			"nine spaces. Past eight bytes the marker and the value are not adjacent, and the placement list is what resolves that, not a wider gap",
		},
		{
			"markup between the marker and the answer",
			string(m) + "</span><span>1571273",
			"if the engine wrapped the value the two are in different text nodes and this is not adjacency",
		},
		{
			"the marker as the tail of a longer token",
			"x" + string(m) + "1571273",
			"the left guard: a marker that is part of a longer alphanumeric run was not delivered as a marker",
		},
		{
			"another probe's marker carrying the answer",
			string(other) + "1571273",
			"iso-eval SSTI 5 mode 7: a stored reflection from an earlier probe. The ordinal identifies the probe, so this is this probe's silence",
		},
		{
			"the client-side case, where the raw response still holds the expression",
			string(m) + "{{1721*913}}",
			"mode 3: AngularJS or Vue would render this in the browser. That is CSTI's finding and claiming it here would be a fabricated one",
		},
		{
			"nothing at all",
			"<html>ordinary page</html>",
			"the ordinary negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if hit, ok := sstiComputationHit([]byte(tc.body), m, sstiExpected); ok {
				t.Errorf("the computation rule FIRED on %q (matched %q). %s", tc.body, hit.Matched, tc.why)
			}
		})
	}
}

// The grouping matcher gets its own table because it is the one line that decides whether the most
// common Java template engine in the world is found or recorded clean.
func TestSSTITheGroupingMatcherAcceptsRealLocalesAndRefusesDecimals(t *testing.T) {
	cases := []struct {
		in   string
		want bool
		why  string
	}{
		{"1571273", true, "ungrouped, which is every engine that does not localise"},
		{"1,571,273", true, "en_US, and this is FreeMarker's default rendering"},
		{"1.571.273", true, "de_DE"},
		{"1 571 273", true, "fr_FR with a plain space"},
		{"1'571'273", true, "de_CH"},
		{"15,71,273", true, "hi_IN lakh grouping"},
		{"1571.273", false, "a decimal. No number formatter groups only one of two boundaries"},
		{"1.571273", false, "a decimal from the other side"},
		{"1,571273", false, "half-grouped, which no formatter produces"},
		{"157127", false, "not the answer"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			n, ok := sstiGroupedNumberAt([]byte(tc.in), 0, sstiExpected)
			if ok != tc.want {
				t.Errorf("matched=%v want %v (consumed %d). %s", ok, tc.want, n, tc.why)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// RULE CONSUMPTION: the only oracle a logic-less engine has
// ---------------------------------------------------------------------------------------------

func TestSSTITheConsumptionRuleFiresOnlyWhenADelimiterWasActuallyConsumed(t *testing.T) {
	m1 := sstiTestMarker(t, "1f3q", 65)
	m2, ok := sstiSiblingMarker(m1, 1)
	if !ok {
		t.Fatal("could not reconstruct the second marker, so the consumption rule has no markers to work with")
	}
	m3, ok := sstiSiblingMarker(m1, 2)
	if !ok {
		t.Fatal("could not reconstruct the third marker")
	}

	cases := []struct {
		name string
		body string
		want bool
		why  string
	}{
		{
			"the engine consumed the expression",
			"<p>" + string(m1) + string(m3) + "</p>",
			true,
			"M1 adjacent to M3 with M2 gone is what a parser leaves behind",
		},
		{
			"a sanitizer deleted the braces",
			string(m1) + string(m2) + string(m3),
			false,
			"iso-eval SSTI 5 mode 8. A stripper leaves M1M2 and M2M3 adjacent and never M1M3, and requiring M2 to be ABSENT is what makes the difference explicit",
		},
		{
			"the field truncated mid payload",
			string(m1) + "{{" + string(m2)[:8],
			false,
			"mode 9. No prefix of the payload contains M1 adjacent to M3, which is the whole reason for three distinct markers",
		},
		{
			"M2 came back base64 encoded elsewhere on the page",
			string(m1) + string(m3) + "<!-- enpqMWYzcTAwMDAzbHh5eg== -->",
			true,
			"a base64 blob that is not this marker must not suppress the hit",
		},
		{
			"the engine echoed the variable name instead of consuming it",
			string(m1) + string(m2) + string(m3),
			false,
			"mode 11: some engines render an undefined reference as its own name. That is echo_undefined, useful information, and not a finding",
		},
		{
			"nothing came back",
			"<html>ordinary page</html>",
			false,
			"the ordinary negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := sstiConsumptionHit([]byte(tc.body), m1, m2, m3)
			if got != tc.want {
				t.Errorf("consumption fired=%v want %v on %q. %s", got, tc.want, tc.body, tc.why)
			}
		})
	}

	t.Run("M2 present in any transform form suppresses the hit", func(t *testing.T) {
		for _, form := range sstiAllMarkerForms(m2) {
			body := string(m1) + string(m3) + " leftover:" + form
			if _, ok := sstiConsumptionHit([]byte(body), m1, m2, m3); ok {
				t.Errorf("the rule fired with M2 present as %q, so a re-encoding application reads as a parsing one", form)
			}
		}
	})
}

// The sibling markers are RECONSTRUCTED, not minted, and they have to land in this class's stripe
// or the runner would be attributing this class's own probe to somebody else.
func TestSSTIReconstructedSiblingMarkersStayInThisClassStripe(t *testing.T) {
	m := sstiTestMarker(t, "1f3q", 65)
	for n := uint64(1); n <= 3; n++ {
		sib, ok := sstiSiblingMarker(m, n)
		if !ok {
			t.Fatalf("sibling %d could not be reconstructed", n)
		}
		if !sib.BelongsTo(triage.ClassSSTI) {
			t.Errorf("sibling %d is %q, whose stripe is not SSTI's", n, sib)
		}
		if sib.Integrity() != triage.MarkerValid {
			t.Errorf("sibling %d is %q, whose checksum does not verify, so the runner's own mint would not produce it", n, sib)
		}
		if sib.RunID() != m.RunID() {
			t.Errorf("sibling %d changed the run id, which would make it read as a cached body", n)
		}
	}
	if _, ok := sstiSiblingMarker("not-a-marker", 1); ok {
		t.Error("a malformed marker produced a sibling, so a corrupted token could be turned into a confident one")
	}
}

// ---------------------------------------------------------------------------------------------
// RULE ERROR SIGNATURE
// ---------------------------------------------------------------------------------------------

func TestSSTITheErrorOracleIsBaselineDifferencedAndReadsOnlyThisClassCatalogue(t *testing.T) {
	cases := []struct {
		name string
		body string
		base string
		want string
		why  string
	}{
		{
			"a FreeMarker parse error that is new",
			"500 freemarker.core.ParseException: on line 1",
			"<html>ordinary page</html>",
			"ftl.parse",
			"the ordinary positive",
		},
		{
			"the same banner already on every page",
			"500 freemarker.core.ParseException: on line 1",
			"debug footer: freemarker.core.ParseException sample",
			"",
			"foundations T10. An application whose every page carries a template banner makes a naive matcher score a hundred percent on a corpus where nothing is vulnerable",
		},
		{
			"a Spring expression error, which belongs to the ELI class",
			"EL1008E: Property or field 'x' cannot be found on object",
			"<html>ordinary page</html>",
			"",
			"ruling R1. This class never reads another class's catalogue, not even to fail closed. It sends its own division triple instead",
		},
		{
			"a Postgres error, which belongs to the SQL class",
			"org.postgresql.util.PSQLException: syntax error at or near",
			"<html>ordinary page</html>",
			"",
			"same ruling. The quote in S1 can break a SQL statement, and reading the DBMS trace as a template error is the exact coupling R1 abolished",
		},
		{
			"a Jinja2 syntax error",
			"jinja2.exceptions.TemplateSyntaxError: unexpected end of template",
			"",
			"jinja.syntax",
			"the Python side of the catalogue",
		},
		{
			"a Go template parse error, which needs two literals together",
			`template: page:1: executing "page" at <.>: bad`,
			"",
			"go.tmpl.exec",
			"a single literal would match ordinary prose, which is why the row carries two",
		},
		{
			"an ordinary page",
			"<html>nothing here</html>",
			"",
			"",
			"the ordinary negative",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sig, ok := sstiErrorSignatureIn(sstiErrorCatalogue, []byte(tc.body), []byte(tc.base))
			got := ""
			if ok {
				got = sig.ID
			}
			if got != tc.want {
				t.Errorf("signature %q, want %q. %s", got, tc.want, tc.why)
			}
		})
	}
}

// The division triple is what separates "the engine parsed my delimiters" from "the engine
// EVALUATED my expression", and those are different findings with different tool recommendations.
func TestSSTITheDivisionTripleProvesAnEvaluatorRatherThanAParser(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{"ZeroDivisionError: division by zero", "arith.python"},
		{"java.lang.ArithmeticException: / by zero", "arith.java"},
		{"DivisionByZeroError: Division by zero", "arith.php8"},
		{"ZeroDivisionError: divided by 0", "arith.python"},
		{"Arithmetic operation failed: 1721 / 0", "arith.freemarker"},
		{"<html>ordinary page</html>", ""},
	} {
		sig, ok := sstiErrorSignatureIn(sstiArithmeticCatalogue, []byte(tc.body), nil)
		got := ""
		if ok {
			got = sig.ID
		}
		if got != tc.want {
			t.Errorf("on %q got %q, want %q", tc.body, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// RULE DISTINCTIVE CONTENT
// ---------------------------------------------------------------------------------------------

func TestSSTITheDistinctiveContentOracleNamesTheEngineAndRefusesTheBaseline(t *testing.T) {
	m := sstiTestMarker(t, "1f3q", 65)
	cases := []struct {
		name  string
		probe triage.ProbeID
		body  string
		base  string
		want  string
	}{
		{"Smarty answers with its version", sstiD1, string(m) + "4.3.1", "", "Smarty 4.3.1"},
		{"a version already in the baseline", sstiD1, string(m) + "4.3.1", "powered by Smarty 4.3.1", ""},
		{"Go prints its root value", sstiD2, string(m) + "<no value>", "", "Go template"},
		{"an app that echoes no value anyway", sstiD2, string(m) + "<no value>", "the field said <no value> earlier", ""},
		{"FreeMarker's computer format", sstiD3, string(m) + sstiExpected, "", "FreeMarker"},
		{"the grouped form, which does NOT prove ?c ran", sstiD3, string(m) + "1,571,273", "", ""},
		{"nothing", sstiD1, "<html>plain</html>", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, engine, ok := sstiDistinctiveHit(tc.probe, []byte(tc.body), []byte(tc.base), m)
			got := ""
			if ok {
				got = engine
			}
			if got != tc.want {
				t.Errorf("engine %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER: nothing unknown ever becomes a clean
// ---------------------------------------------------------------------------------------------

func sstiTestScorecard() sstiScorecard {
	// A scorecard in the state a completely clean slot reaches: probes answered, the census
	// reflected, the decode probe positive, every oracle silent.
	return sstiScorecard{
		planned:  20,
		answered: map[triage.ProbeID]triage.Observation{sstiS0: {}},
		markers:  map[triage.ProbeID]triage.Marker{},
		reflects: true,
		// censusMarkerOnWire belongs in the BASELINE fixture and not only in the cases that test
		// it, because a marker that came back was self-evidently sent. A fixture that says
		// reflects=true and onWire=false describes a response nobody can have received, and every
		// case built on it would have been measuring the census-instrumentation branch by
		// accident instead of the branch it named.
		censusMarkerOnWire: true,
		reflectMeasure:     true,
		decodeDepth:        1,
	}
}

func TestSSTINoPathToCleanWithoutEvidence(t *testing.T) {
	ords := []uint64{65}
	cases := []struct {
		name   string
		mutate func(*sstiScorecard, *sstiEnv)
		want   triage.TriageState
		reason string
		why    string
	}{
		{
			"the runner did not substitute a marker token",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.runnerBug = "marker_substitution_unsupported: probe SSTI-C1" },
			triage.StateCannotDetermine, "runner_bug",
			"the payload that went out is not the payload this class declared, so its silence is about some other bytes",
		},
		{
			"a negative control fired",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.controlFired = sstiNC1 },
			triage.StateCannotDetermine, "detector_unverified",
			"a detector shown firing on a payload that computes nothing has been shown broken, and every verdict on the slot is void",
		},
		{
			"a marker from another run came back",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.staleMarker = true },
			triage.StateCannotDetermine, "stale_marker",
			"a cache or a replay is serving these bodies",
		},
		{
			"three payloads got the same block page",
			func(_ *sstiScorecard, env *sstiEnv) { env.blocked = true },
			triage.StateCannotDetermine, "blocked",
			"the silence is the WAF's and not the application's",
		},
		{
			"the application moved under the probes",
			func(_ *sstiScorecard, env *sstiEnv) { env.drifted = true },
			triage.StateCannotDetermine, "drift",
			"every differential taken in the window is unattributable",
		},
		{
			"the response changed and nothing in this class explains it",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.perturbedUnexplained = true },
			triage.StateCannotDetermine, "unattributed_error",
			"ruling R1's replacement for the abolished foreign-error state",
		},
		{
			"the marker only came back re-encoded",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.reEncodedOnly = true },
			triage.StateCannotDetermine, "marker_form_unmatched",
			"if the marker was transformed then anything computed was transformed too, and the adjacency rule had nothing to measure",
		},
		{
			"a returned marker failed its checksum",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.corruptMarker = true },
			triage.StateCannotDetermine, "marker_corrupted",
			"attribution is unsafe, so no silence here is this slot's silence",
		},
		{
			"the transport refused to send",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.notDelivered = []triage.ProbeID{sstiF2} },
			triage.StateCannotDetermine, "could_not_send",
			"a probe that never left the process cannot have been answered",
		},
		{
			"the census never ran",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.reflectMeasure = false },
			triage.StateCannotDetermine, "census_not_run",
			"whether the computation oracle was even available here was never measured",
		},
		{
			"the bare marker never came back",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.reflects = false },
			triage.StateCannotDetermine, "no_reflection",
			"the rank 1 oracle was structurally unavailable rather than silent, and a blind template sink looks exactly like this",
		},
		{
			// The half of no_reflection that used to be reported AS no_reflection. A census probe
			// that carried no marker searched for bytes nobody sent, so its silence is this
			// class's own instrumentation and says nothing whatever about the endpoint. Same
			// state, different sentence, and the sentence is the part the operator acts on.
			"the census probe carried no marker at all",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.reflects = false; sc.censusMarkerOnWire = false },
			triage.StateCannotDetermine, "census_marker_not_sent",
			"a silence measured on a marker that was never in the request is not the application's silence",
		},
		{
			"a family did not fit the field",
			func(sc *sstiScorecard, _ *sstiEnv) { sc.truncated = []triage.ProbeID{sstiF11} },
			triage.StateCannotDetermine, "truncated",
			"Go coverage was lost on this slot and the report has to say so",
		},
		{
			"the slot does not percent-decode",
			func(sc *sstiScorecard, env *sstiEnv) { sc.decodeDepth = 0; env.percentRelevant = true },
			triage.StateCannotDetermine, "decode_depth_0",
			"no brace ever reached a template engine, so the silence is the encoder's",
		},
		{
			"the decode probe was inconclusive",
			func(sc *sstiScorecard, env *sstiEnv) { sc.decodeDepth = -1; env.percentRelevant = true },
			triage.StateCannotDetermine, "decode_depth_unknown",
			"whether the delimiters arrived as delimiters was never established",
		},
		{
			"the slot was probed at a fabricated identifier",
			func(_ *sstiScorecard, env *sstiEnv) { env.canaryValue = true },
			triage.StateCannotDetermine, "canary_resource",
			"a scan of a resource that does not exist is not a clean scan of the endpoint",
		},
		{
			"the endpoint is too volatile to judge",
			func(_ *sstiScorecard, env *sstiEnv) { env.unstable = true; env.gateReason = "too_volatile" },
			triage.StateCannotDetermine, "too_volatile",
			"a silence cannot be told from noise",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := sstiTestScorecard()
			env := sstiEnv{}
			tc.mutate(&sc, &env)
			vs := sstiCompose("query:q", sc, ords, nil, nil, map[string]any{}, env)
			if len(vs) != 1 {
				t.Fatalf("got %d verdicts, want exactly one composed verdict", len(vs))
			}
			v := vs[0]
			if err := v.Validate(); err != nil {
				t.Errorf("the verdict failed its own contract: %v", err)
			}
			if v.State.CountsAsClean() {
				t.Fatalf("this path rendered as CLEAN. %s", tc.why)
			}
			if !v.State.IsUnknown() {
				t.Errorf("state %q is not an unknown, so an aggregate would count it as a measurement", v.State)
			}
			if v.State != tc.want {
				t.Errorf("state %q, want %q", v.State, tc.want)
			}
			if !strings.Contains(v.Reason, tc.reason) {
				t.Errorf("reason %q does not name %q, and an operator cannot act on an unknown that does not say what happened", v.Reason, tc.reason)
			}
			if v.Grade != triage.GradeUnrated {
				t.Errorf("an unknown carries grade %q, but only a fired oracle carries a grade", v.Grade)
			}
		})
	}
}

// The other half: a clean IS reachable, because a class that can never say clean is as useless as
// one that always does. It requires every precondition, and it carries its probe ordinals.
func TestSSTIACleanIsReachableAndCarriesItsOrdinals(t *testing.T) {
	vs := sstiCompose("query:q", sstiTestScorecard(), []uint64{65, 129}, nil, nil, map[string]any{}, sstiEnv{})
	if len(vs) != 1 {
		t.Fatalf("got %d verdicts", len(vs))
	}
	v := vs[0]
	if err := v.Validate(); err != nil {
		t.Fatalf("the clean verdict failed its own contract: %v", err)
	}
	if !v.State.CountsAsClean() {
		t.Fatalf("state %q with reason %q: a class whose clean is unreachable tells the operator nothing", v.State, v.Reason)
	}
	if len(v.Ordinals) == 0 {
		t.Error("a clean with zero probe ordinals asserts a measurement that never happened, and CATALOGUE 4.3 makes that a hard error")
	}

	t.Run("an incomplete battery blocks the clean", func(t *testing.T) {
		skips := []triage.ProbeSkip{{ProbeID: sstiF5, Reason: "not_run"}}
		got := sstiCompose("query:q", sstiTestScorecard(), []uint64{65}, skips, []triage.ProbeID{sstiF5}, map[string]any{}, sstiEnv{})
		if got[0].State.CountsAsClean() {
			t.Error("a slot where Razor was never sent reported clean, which is the shortened-battery bug this layer exists to stop")
		}
	})
}

// A hit that has not been reproduced with a fresh marker and fresh operands is not a high-grade
// finding, because a cached page reproduces the first probe perfectly.
func TestSSTIAnUnconfirmedComputationHitIsSuspiciousAndNotAFinding(t *testing.T) {
	base := sstiTestScorecard()
	base.computeFamily = sstiF2
	base.computeHit = sstiHit{MarkerForm: "raw"}
	base.answered[sstiF2] = triage.Observation{Payload: triage.PayloadWire{Survived: triage.WireSurvivalIntact}}

	unconfirmed := sstiCompose("query:q", base, []uint64{65}, nil, nil, map[string]any{}, sstiEnv{})[0]
	if unconfirmed.State != triage.StateSuspicious {
		t.Errorf("an unconfirmed hit is %q, want suspicious", unconfirmed.State)
	}
	if unconfirmed.Grade == triage.GradeHigh {
		t.Error("an unconfirmed hit graded high, so a cached body would be reported as a confirmed finding")
	}

	confirmed := base
	confirmed.confirmed = true
	v := sstiCompose("query:q", confirmed, []uint64{65, 129}, nil, nil, map[string]any{}, sstiEnv{})[0]
	if v.State != triage.StateFinding || v.Grade != triage.GradeHigh {
		t.Errorf("a confirmed hit is %q graded %q, want a finding graded high", v.State, v.Grade)
	}
	if v.Oracle != "computation" {
		t.Errorf("oracle %q, want computation", v.Oracle)
	}
	if len(v.Label.Tools) == 0 {
		t.Error("the finding names no tool, and pointing the tool here is the entire job of this layer")
	}
}

// A consumption hit says the sink PARSES the delimiter. It does not say the sink EVALUATES, and
// the verdict has to keep the two apart because they earn different tool runs.
func TestSSTIAConsumptionHitClaimsParsingAndNotEvaluation(t *testing.T) {
	sc := sstiTestScorecard()
	sc.consumeFamily = sstiC1
	v := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, sstiEnv{})[0]
	if v.State != triage.StateFinding {
		t.Errorf("state %q, want a finding: a consumed delimiter is exactly what points tinja at the slot", v.State)
	}
	if v.Annotations["evaluation_unproven"] != true {
		t.Error("the verdict does not carry evaluation_unproven, so it claims more than it showed")
	}
	if v.Grade == triage.GradeHigh {
		t.Error("a rank 7 oracle graded high")
	}

	sc.stripper = true
	stripped := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, sstiEnv{})[0]
	if stripped.State.CountsAsClean() || stripped.State == triage.StateFinding {
		t.Errorf("a brace-stripping sanitizer produced %q; it is neither a finding nor a clean", stripped.State)
	}
	if !strings.Contains(stripped.Reason, "stripper") {
		t.Errorf("reason %q does not name the stripper", stripped.Reason)
	}
}

// Every verdict, in every state, carries the two gaps this class knows it does not cover.
func TestSSTIEveryVerdictNamesTheGapsThisClassDoesNotCover(t *testing.T) {
	c := sstiClassifier{}
	for _, slot := range []triage.Slot{
		{Key: "fragment:tab", Kind: triage.KindFragment},
		{Key: "cookie:session", Kind: triage.KindCookie, ServerReachable: true, Constraints: triage.SlotConstraints{IsCredential: true}},
		{Key: "query:q", Kind: triage.KindQuery, ServerReachable: true},
	} {
		vs := c.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
		for _, v := range vs {
			if v.Annotations["custom_delimiters_untested"] != true {
				t.Errorf("slot %s: the verdict does not carry custom_delimiters_untested, so an engine with rewritten delimiters is invisible AND unmentioned", slot.Key)
			}
			if v.Annotations["second_request_rendering_untested"] != true {
				t.Errorf("slot %s: the verdict does not say a stored-then-rendered value is out of reach", slot.Key)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY AND THE REFUSALS
// ---------------------------------------------------------------------------------------------

func TestSSTITheRefusalsCarryTheRightStateAndAreNeverClean(t *testing.T) {
	c := sstiClassifier{}
	cases := []struct {
		name string
		ctx  triage.PlanCtx
		want triage.TriageState
		says string
	}{
		{
			"a fragment slot",
			triage.PlanCtx{Slot: triage.Slot{Key: "fragment:tab", Kind: triage.KindFragment}},
			triage.StateNotApplicable, "fragment",
		},
		{
			"a credential slot",
			triage.PlanCtx{Slot: triage.Slot{Key: "cookie:sid", Kind: triage.KindCookie, ServerReachable: true,
				Constraints: triage.SlotConstraints{IsCredential: true}}},
			triage.StateNotProbed, "credential_slot",
		},
		{
			"a route that did not resolve",
			triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery, ServerReachable: true}},
			triage.StateCannotDetermine, "route_unresolved",
		},
		{
			"a body slot whose prelude token could not be obtained",
			triage.PlanCtx{
				Slot:    triage.Slot{Key: "body:/name", Kind: triage.KindBody, ServerReachable: true},
				Prelude: triage.PreludeTokenUnobtainable,
			},
			triage.StateCannotDetermine, "route_unresolved",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reqs := c.Plan(tc.ctx); len(reqs) != 0 {
				t.Errorf("planned %d probes on a slot it must not touch", len(reqs))
			}
			vs := c.Classify(triage.ClassifyCtx{PlanCtx: tc.ctx})
			if len(vs) == 0 {
				t.Fatal("no verdict at all, so the slot reads as untouched and nothing says the class declined it")
			}
			v := vs[0]
			if err := v.Validate(); err != nil {
				t.Errorf("verdict failed its own contract: %v", err)
			}
			if v.State.CountsAsClean() {
				t.Fatal("a slot this class refused to probe reported CLEAN")
			}
			if v.State != tc.want {
				t.Errorf("state %q, want %q", v.State, tc.want)
			}
			if !strings.Contains(v.Reason, tc.says) {
				t.Errorf("reason %q does not name %q", v.Reason, tc.says)
			}
		})
	}
}

func TestSSTIReachesAnswersWithAReasonWhereverOneIsRequired(t *testing.T) {
	c := sstiClassifier{}
	for _, k := range triage.AllSlotKinds() {
		for _, mt := range []triage.MediaType{"", "application/json", "application/xml", "text/html", "multipart/form-data"} {
			r := c.Reaches(k, mt)
			if r.Reach != triage.ReachAlways && strings.TrimSpace(r.Reason) == "" {
				t.Errorf("Reaches(%s, %q) is %s with no reason, and an operator cannot tell a ruled-out slot from a forgotten one", k, mt, r.Reach)
			}
		}
	}
	if r := c.Reaches(triage.KindFragment, "text/html"); r.Reach != triage.ReachNever {
		t.Error("the fragment is reachable, but RFC 3986 section 3.5 says it is never transmitted and the client-side analogue is the CSTI class")
	}
	if r := c.Reaches(triage.KindBody, "application/xml"); !strings.Contains(r.Reason, "xml_cdata") {
		t.Errorf("the XML body reason %q does not mention the CDATA mode the angle-bracket families need", r.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER'S PLANNING RULES
// ---------------------------------------------------------------------------------------------

// A negative from F1 says NOTHING about F5. They are different grammars reaching disjoint engine
// sets, and an early exit on "nothing found yet" would be a silent zero for every engine below
// the first family tried.
func TestSSTITheBatteryRoundNeverStopsBecauseNothingHasFiredYet(t *testing.T) {
	ctx := triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery, ServerReachable: true}, Round: 1}
	got := map[triage.ProbeID]bool{}
	for _, r := range sstiPlanBatteries(ctx) {
		got[r.Spec] = true
	}
	for _, want := range []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF7, sstiF8, sstiF9, sstiF10, sstiF10w, sstiF11,
		sstiC1, sstiC2, sstiC3, sstiC4, sstiC5, sstiS2} {
		if !got[want] {
			t.Errorf("round 1 did not plan %s, so the engines that family alone reaches were never tested", want)
		}
	}
}

func TestSSTITheCensusRoundSendsThisClassOwnDecodeProbeOnlyWherePercentMatters(t *testing.T) {
	for _, tc := range []struct {
		kind triage.SlotKind
		want bool
		why  string
	}{
		{triage.KindQuery, true, "a query value is percent-encoded, so whether the app decodes decides whether a brace ever arrives"},
		{triage.KindPath, true, "as query, plus the path slot's own pct_rejected question"},
		{triage.KindCookie, true, "the space-bearing families depend on it"},
		{triage.KindHeader, false, "ruling R6: zero cost on a header, where no payload in this class needs percent-encoding at all"},
	} {
		ctx := triage.PlanCtx{Slot: triage.Slot{Key: "k", Kind: tc.kind, ServerReachable: true}}
		got := false
		for _, r := range sstiPlanCensus(ctx) {
			if r.Spec == sstiDEC {
				got = true
			}
		}
		if got != tc.want {
			t.Errorf("%s: decode probe planned=%v want %v. %s", tc.kind, got, tc.want, tc.why)
		}
	}
}

func TestSSTIAFamilyTooLongForTheFieldIsNamedRatherThanDropped(t *testing.T) {
	slot := triage.Slot{Key: "query:q", Kind: triage.KindQuery, ServerReachable: true,
		Constraints: triage.SlotConstraints{FieldLimit: 40, DecodeDepth: 1}}
	ctx := triage.PlanCtx{Slot: slot, Round: 1}
	for _, r := range sstiPlanBatteries(ctx) {
		if r.Spec == sstiF11 {
			t.Fatal("the 106-byte Go family was planned into a 40-byte field, so it would be truncated and its silence read as a clean")
		}
	}
	skips, _ := sstiUntested(triage.ClassifyCtx{PlanCtx: ctx}, sstiScorecard{answered: map[triage.ProbeID]triage.Observation{}})
	named := false
	for _, s := range skips {
		if s.ProbeID == sstiF11 {
			named = true
			if !strings.Contains(s.Reason, "truncated") {
				t.Errorf("F11 was skipped with reason %q, which does not say the field could not carry it", s.Reason)
			}
		}
	}
	if !named {
		t.Error("the Go family was dropped with no Untested row, so a report would show a battery that looks complete")
	}
}

func TestSSTIASpaceBearingPayloadIsHeldBackFromAnUndecodedCookieAndSaidSo(t *testing.T) {
	slot := triage.Slot{Key: "cookie:theme", Kind: triage.KindCookie, ServerReachable: true,
		Constraints: triage.SlotConstraints{DecodeDepth: 0}}
	for _, r := range sstiPlanBatteries(triage.PlanCtx{Slot: slot, Round: 1}) {
		if r.Spec == sstiF9 {
			t.Fatal("the space-bearing Liquid form was sent to a cookie that does not percent-decode, where SPACE is not a cookie-octet")
		}
	}
	got := false
	for _, r := range sstiPlanBatteries(triage.PlanCtx{Slot: slot, Round: 1}) {
		if r.Spec == sstiF9c {
			got = true
		}
	}
	if !got {
		t.Error("the space-free Liquid fallback was not sent either, so the cookie slot has no Liquid coverage and nothing says so")
	}
	skips, _ := sstiUntested(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}}, sstiScorecard{answered: map[triage.ProbeID]triage.Observation{}})
	for _, s := range skips {
		if s.ProbeID == sstiF9 && !strings.Contains(s.Reason, "cookie_space") {
			t.Errorf("F9 skipped with reason %q, which does not name the space", s.Reason)
		}
	}
}

func TestSSTIPlanNeverSendsAProbeItDidNotDeclare(t *testing.T) {
	c := sstiClassifier{}
	for round := 0; round < 5; round++ {
		ctx := triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery, ServerReachable: true}, Round: round}
		if err := triage.PlannedProbesAreDeclared(c, c.Plan(ctx)); err != nil {
			t.Errorf("round %d: %v", round, err)
		}
	}
	for _, reqs := range [][]triage.ProbeRequest{
		sstiPlanCensus(triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery}}),
		sstiPlanBatteries(triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery}, Round: 1}),
		sstiPlanEscalation(triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery}, Round: 2}),
		sstiPlanFinishers(triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery}, Round: 3}),
	} {
		if err := triage.PlannedProbesAreDeclared(c, reqs); err != nil {
			t.Error(err)
		}
	}
}

// The three probe families that need runner cooperation say so on the request, so a runner that
// has not implemented the substitution can refuse loudly rather than send a payload with a literal
// token in it.
func TestSSTIProbesNeedingRunnerSubstitutionDeclareItOnTheRequest(t *testing.T) {
	specs := sstiSpecByID()
	for id, row := range specs {
		needsSiblings := strings.Contains(row.logical, sstiTokenM2) || strings.Contains(row.logical, sstiTokenM3)
		if needsSiblings && row.variant[sstiVariantSiblings] == "" {
			t.Errorf("probe %s carries a sibling-marker token and does not ask the runner for sibling markers", id)
		}
		if strings.Contains(row.logical, sstiTokenPctMarker) && row.variant[sstiVariantPctMark] == "" {
			t.Errorf("probe %s carries the percent-marker token and does not ask the runner to render it", id)
		}
	}
	got := false
	for _, r := range sstiPlanBatteries(triage.PlanCtx{Slot: triage.Slot{Key: "query:q", Kind: triage.KindQuery}, Round: 1}) {
		if r.Spec == sstiC1 {
			got = true
			if r.Variant[sstiVariantSiblings] != "2" {
				t.Errorf("the consumption probe went out asking for %q sibling markers, want 2", r.Variant[sstiVariantSiblings])
			}
		}
	}
	if !got {
		t.Error("the consumption battery was not planned at all")
	}
}

// ---------------------------------------------------------------------------------------------
// THE DECLARATIONS
// ---------------------------------------------------------------------------------------------

func TestSSTITheOracleCasesDeclareBothAPositiveAndANegative(t *testing.T) {
	cases := sstiClassifier{}.OracleCases()
	var pos, neg, missing int
	for _, c := range cases {
		switch c.Expect {
		case "positive":
			pos++
		case "negative":
			neg++
		default:
			t.Errorf("oracle case %q expects %q, which is neither positive nor negative", c.Name, c.Expect)
		}
		if c.Why == "" {
			t.Errorf("oracle case %q says nothing about what it tests", c.Name)
		}
		if !c.Exists {
			missing++
		}
	}
	if pos == 0 || neg == 0 {
		t.Fatalf("%d positive and %d negative oracle cases: a detector never shown STAYING SILENT is not a verified detector", pos, neg)
	}
	t.Logf("%d oracle cases, %d of them needing routes that do not exist yet", len(cases), missing)
}

func TestSSTIEveryOracleAndEveryConfirmationIsDeclared(t *testing.T) {
	c := sstiClassifier{}
	oracles := map[string]bool{}
	for _, e := range c.Evidencers() {
		oracles[e.Oracle] = true
		if len(e.Probes) == 0 {
			t.Errorf("oracle %q names no probe, so nothing can ever fire it", e.Oracle)
		}
		if e.Why == "" {
			t.Errorf("oracle %q says nothing about why it is worth a request", e.Oracle)
		}
	}
	for _, want := range []string{"computation", "consumption", "error_signature", "distinctive_content"} {
		if !oracles[want] {
			t.Errorf("oracle %q is not declared, so the report cannot say which rule fired", want)
		}
	}

	specs := sstiSpecByID()
	for _, conf := range c.Confirmers() {
		if _, ok := specs[conf.First]; !ok {
			t.Errorf("confirmation is declared for %s, which is not a declared probe", conf.First)
		}
		for _, id := range conf.Confirm {
			if _, ok := specs[id]; !ok {
				t.Errorf("%s names confirmation probe %s, which is not declared", conf.First, id)
			}
			if id == conf.First {
				t.Errorf("%s confirms itself, and re-sending the first probe confirms a cache rather than a finding", conf.First)
			}
		}
	}

	// Every computation family must have one, or a hit there could never grade high.
	for _, fam := range []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF7, sstiF8, sstiF9, sstiF10, sstiF11} {
		if len(sstiConfirmFor[fam]) == 0 {
			t.Errorf("family %s has no confirmation, so a hit there can never be reproduced with a fresh marker and can never grade high", fam)
		}
	}
}

// The confirmation operands have to satisfy the same guard as the first draw, and iso-eval's own
// worked example (4643-1129 = 3514) does not: it is four digits, and the document's own rule in
// section 1.2 sets a six-digit minimum.
func TestSSTITheConfirmationOperandsSatisfyTheSixDigitGuard(t *testing.T) {
	for _, tc := range []struct{ name, a, b, expected string }{
		{"the primary draw", sstiA, sstiB, sstiExpected},
		{"the confirmation draw", sstiConfA, sstiConfB, sstiConfExpected},
		{"the Django sum", sstiDjangoA, sstiDjangoB, sstiDjangoExpected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if len(tc.expected) < 6 {
				t.Errorf("expected answer %q has %d digits; below six it is a plausible page constant", tc.expected, len(tc.expected))
			}
			wire := tc.a + tc.b
			if strings.Contains(wire, tc.expected) {
				t.Errorf("the answer %q is a substring of the operands %q, so an echo of the payload would fire the oracle", tc.expected, wire)
			}
			if tc.expected == tc.a+tc.b || tc.expected == tc.a+tc.a {
				t.Errorf("the answer %q is a digit concatenation of the operands, which cannot be told from string repetition", tc.expected)
			}
		})
	}
	if sstiExpected == "49" || strings.Contains(sstiExpected, "49") && len(sstiExpected) == 2 {
		t.Error("the expected answer is 49, which appears in prices, pixel counts and ids on almost every page ever rendered")
	}
	for _, e := range []string{sstiGoExpected, sstiGoConfExpected} {
		if len(e) != 6 {
			t.Errorf("the Go len-chain answer %q is not six digits, and the chain length is what makes it six", e)
		}
	}
}

// The label has to tell the operator the truth about the tool, including when there is no plugin.
func TestSSTITheLabelSaysWhenNoToolHasAPluginForTheEngine(t *testing.T) {
	sc := sstiTestScorecard()
	sc.computeFamily = sstiF11
	sc.distinctEngine = "Go template"
	l := sstiLabel(sc)
	if _, hasPlugin := sstiPlugin["Go template"]; hasPlugin {
		t.Fatal("this test assumes Go templates have no sstimap plugin; the map now says otherwise and the assertion below is meaningless")
	}
	if l.Hints["no_sstimap_plugin"] == "" {
		t.Error("the label does not say there is no sstimap plugin, so the operator spends a tool run for a guaranteed nothing")
	}
	for _, tool := range l.Tools {
		if tool == "sstimap" {
			t.Error("the label still points at sstimap for an engine it has no plugin for")
		}
	}

	sc2 := sstiTestScorecard()
	sc2.computeFamily = sstiF2
	sc2.distinctEngine = "Jinja2"
	if got := sstiLabel(sc2).Hints["sstimap_engine"]; got != "jinja2" {
		t.Errorf("sstimap_engine hint is %q, want jinja2; the plugin name is what makes the tool run cheaper than a cold start", got)
	}
}

// No emdash anywhere in this class's own bytes. The repo forbids them and a payload is bytes.
func TestSSTINoPayloadOrProseCarriesAnEmdash(t *testing.T) {
	for _, p := range (sstiClassifier{}).Probes() {
		if strings.ContainsRune(string(p.Logical), '—') || strings.ContainsRune(p.Notes, '—') {
			t.Errorf("probe %s carries an emdash", p.ID)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE BLIND ARM. THE ONLY ORACLE HERE THAT ANSWERS ON A ROUTE THAT ECHOES NOTHING
// ---------------------------------------------------------------------------------------------

// sstiBlindObs builds one observation the blind arm can compare. NormBody is what the arm
// measures, and a fixture that leaves it nil is a fixture the arm correctly refuses to read, so
// every case below has to fill it deliberately.
func sstiBlindObs(id triage.ProbeID, status int, norm string) triage.Observation {
	return triage.Observation{
		ObsID: string(id), RunID: "ssti-blind", Status: status, Kind: triage.ObsProbe,
		Class: triage.ClassSSTI, Body: []byte(norm), BodyLen: len(norm),
		Proj:    triage.Projections{NormBody: []byte(norm)},
		Payload: triage.PayloadWire{Wire: []byte(id), Survived: triage.WireSurvivalEncoded},
	}
}

// sstiBlindStable is the environment the arm requires: a measured, stable, undegraded model.
func sstiBlindStable() sstiEnv { return sstiEnv{stable: true} }

// sstiBlindSet is a whole arm's worth of responses with every one of them identical, which is
// what a route with no template engine returns. Individual cases then move the ones they mean to.
func sstiBlindSet(body string) map[triage.ProbeID]triage.Observation {
	out := map[triage.ProbeID]triage.Observation{}
	for _, id := range []triage.ProbeID{
		sstiBN1, sstiBN2, sstiBOK1, sstiBER1, sstiBOK2, sstiBER2, sstiBOK3, sstiBER3, sstiBOK4, sstiBER4,
	} {
		out[id] = sstiBlindObs(id, 200, body)
	}
	return out
}

// THE POSITIVE. A route that renders the valid member and raises on the invalid one, in both pairs
// of one family, in the same direction. This is the case the whole arm exists for and it needs
// NOTHING to come back: no marker, no echo, no computed product.
func TestTheBlindArmFiresWhenBothPairsOfAFamilySeparateTheSameWay(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true,\"items\":[]}")
	// A rendering engine: the valid expressions render a value and the invalid ones raise a 500.
	set[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"items\":[],\"v\":6.0}")
	set[sstiBER3] = sstiBlindObs(sstiBER3, 500, "{\"error\":\"template\"}")
	set[sstiBOK4] = sstiBlindObs(sstiBOK4, 200, "{\"ok\":true,\"items\":[],\"v\":7.0}")
	set[sstiBER4] = sstiBlindObs(sstiBER4, 500, "{\"error\":\"template\"}")

	got := sstiBlindArm(set, sstiBlindStable())
	if got.Outcome != sstiBlindDifferentiated {
		t.Fatalf("the blind arm did not fire on a route that answers 200 to the valid expression and 500 to "+
			"the invalid one in BOTH pairs of a family: %+v", got)
	}
	if got.Family != "brace_brace" {
		t.Errorf("fired on family %q, want brace_brace: naming the wrong delimiter family sends the operator "+
			"to the wrong engine set", got.Family)
	}
	if !strings.Contains(got.Why, "SUSPICIOUS and not a finding") {
		t.Errorf("the reason %q does not say the verdict is capped. A differential proves a parser, not an "+
			"evaluation, and a row that does not say so will be read as proof", got.Why)
	}
}

// ONE PAIR IS NOT ENOUGH, and this is the single assertion that separates this arm from a
// did-the-page-change detector. Any route answers two different strings differently now and then.
func TestTheBlindArmRefusesToFireOnOnePairAlone(t *testing.T) {
	// Pair 1 separates by LENGTH and pair 2 does not. The move is made on the VALID member, not
	// on the error member, so the two syntax-error payloads stay in the same status class and
	// control A is satisfied: this is the arm running with every precondition held.
	set := sstiBlindSet("{\"ok\":true}")
	set[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"v\":6.0}")
	got := sstiBlindArm(set, sstiBlindStable())
	if got.Outcome == sstiBlindDifferentiated {
		t.Fatalf("one pair moved and the arm fired: %+v. PATT ships two pairs precisely so external "+
			"interference cannot produce a verdict, and a single-pair rule throws that away", got)
	}
	if got.Outcome != sstiBlindSilent {
		t.Errorf("outcome %v, want silent: every precondition held here, so this is the arm running and "+
			"finding nothing, not the arm refusing to run", got.Outcome)
	}
}

// The two pairs have to move the SAME WAY. Opposite directions are the endpoint being arbitrary.
func TestTheBlindArmRefusesTwoPairsThatMoveInOppositeDirections(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true}")
	set[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"v\":6.0}") // valid LARGER
	set[sstiBER3] = sstiBlindObs(sstiBER3, 200, "{\"ok\":true}")
	set[sstiBOK4] = sstiBlindObs(sstiBOK4, 200, "{\"ok\":true}") // valid SMALLER
	set[sstiBER4] = sstiBlindObs(sstiBER4, 200, "{\"ok\":true,\"noise\":\"xxxx\"}")
	if got := sstiBlindArm(set, sstiBlindStable()); got.Outcome == sstiBlindDifferentiated {
		t.Errorf("both pairs moved in OPPOSITE directions and the arm fired: %+v. A rendering engine cannot "+
			"make the valid expression both longer and shorter than the invalid one", got)
	}
}

// THE LENGTH CONTROL. BN1 and BN2 are inert plain text six bytes apart. If the endpoint's response
// length tracks its input length, every pair fires for that reason and none of them means
// anything, so the arm must disable itself rather than report.
func TestTheBlindArmDisablesItselfOnALengthSensitiveEndpoint(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true}")
	// The endpoint echoes the value, so the longer inert control returns the longer body.
	set[sstiBN1] = sstiBlindObs(sstiBN1, 200, "{\"echo\":\"q4jv7nx2wr\"}")
	set[sstiBN2] = sstiBlindObs(sstiBN2, 200, "{\"echo\":\"q4jv7nx2wr6zc38f\"}")
	// And the pairs separate, exactly as they would on any echoing route.
	set[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"v\":6.0}")
	set[sstiBER3] = sstiBlindObs(sstiBER3, 500, "{\"e\":1}")
	set[sstiBOK4] = sstiBlindObs(sstiBOK4, 200, "{\"ok\":true,\"v\":7.0}")
	set[sstiBER4] = sstiBlindObs(sstiBER4, 500, "{\"e\":1}")

	got := sstiBlindArm(set, sstiBlindStable())
	if got.Outcome != sstiBlindNotRun {
		t.Fatalf("outcome %v (%s): the inert length control moved and the arm still produced a verdict. "+
			"On a length-sensitive endpoint every pair separates and none of it is about parsing",
			got.Outcome, got.Why)
	}
	if !strings.Contains(got.Why, "length_sensitive_endpoint") {
		t.Errorf("the reason %q does not name the control that failed", got.Why)
	}
}

// CONTROL A. The two syntax-error members of a family are both garbage. A route that answers them
// in different status classes answers ANY unusual input differently, and cannot carry this arm.
func TestTheBlindArmDisablesItselfWhenTheTwoGarbagePayloadsDisagree(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true}")
	set[sstiBER3] = sstiBlindObs(sstiBER3, 400, "{\"e\":\"bad\"}")
	set[sstiBER4] = sstiBlindObs(sstiBER4, 200, "{\"ok\":true}")
	got := sstiBlindArm(set, sstiBlindStable())
	if got.Outcome != sstiBlindNotRun || !strings.Contains(got.Why, "junk_sensitive") {
		t.Errorf("got %+v: the two payloads no engine parses came back 400 and 200, so this endpoint "+
			"discriminates on unusualness and a valid-versus-invalid differential measures that", got)
	}
}

// THE NOISE MODEL IS NOT OPTIONAL. A rank 6 differential on an endpoint nobody measured is a coin
// toss with a verdict attached, and the harvest that produced these payloads says so in the same
// words.
func TestTheBlindArmWillNotRunWithoutAStabilityGate(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true}")
	set[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"v\":6.0}")
	set[sstiBER3] = sstiBlindObs(sstiBER3, 500, "{\"e\":1}")
	set[sstiBOK4] = sstiBlindObs(sstiBOK4, 200, "{\"ok\":true,\"v\":7.0}")
	set[sstiBER4] = sstiBlindObs(sstiBER4, 500, "{\"e\":1}")

	for _, tc := range []struct {
		name, want string
		env        sstiEnv
	}{
		{"no model at all", "noise_model_absent", sstiEnv{}},
		{"the gate named a reason", "too_volatile", sstiEnv{gateReason: "too_volatile"}},
		{"a degraded comparison", "comparison_degraded", sstiEnv{stable: true, degraded: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sstiBlindArm(set, tc.env)
			if got.Outcome != sstiBlindNotRun {
				t.Fatalf("the arm produced %v on an endpoint with no usable model: %s", got.Outcome, got.Why)
			}
			if !strings.Contains(got.Why, tc.want) {
				t.Errorf("the reason %q does not name %q", got.Why, tc.want)
			}
		})
	}
}

// A NORMALISED BODY IS THE ONLY LENGTH THIS ARM WILL READ. Falling back to the raw body would put
// the request id, the timestamp and the CSRF token back into a two-byte differential.
func TestTheBlindArmRefusesAProbeWhoseNormalisedBodyWasNeverBuilt(t *testing.T) {
	set := sstiBlindSet("{\"ok\":true}")
	raw := sstiBlindObs(sstiBOK3, 200, "{\"ok\":true}")
	raw.Proj.NormBody = nil
	set[sstiBOK3] = raw
	got := sstiBlindArm(set, sstiBlindStable())
	if got.Outcome != sstiBlindNotRun || !strings.Contains(got.Why, "family_incomplete") {
		t.Errorf("got %+v: a probe with no normalised body is not comparable, and a pair with one member "+
			"missing is not a pair", got)
	}
}

// AND THE RULE THAT KEEPS THE WHOLE THING HONEST: the arm may never produce a clean. A silent arm
// leaves the verdict where it was and changes only the sentence.
func TestASilentBlindArmChangesTheSentenceAndNotTheState(t *testing.T) {
	sc := sstiTestScorecard()
	sc.reflects = false
	sc.answered = sstiBlindSet("{\"ok\":true}")
	sc.answered[sstiS0] = triage.Observation{}
	env := sstiBlindStable()

	v := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, env)
	if len(v) != 1 {
		t.Fatalf("got %d verdicts, want 1", len(v))
	}
	if v[0].State != triage.StateCannotDetermine {
		t.Fatalf("state %q: a tier 6 differential that stayed quiet eliminates two delimiter families and "+
			"nothing else, and it may never be rounded up to a clean", v[0].State)
	}
	if !strings.Contains(v[0].Reason, "no_reflection") {
		t.Errorf("the row stopped saying no_reflection: %q", v[0].Reason)
	}
	if !strings.Contains(v[0].Reason, "blind_arm_ran_and_was_silent") {
		t.Errorf("the row does not say the second arm RAN: %q. That is the difference between an oracle that "+
			"was unavailable and one that was available and quiet, and an operator spends differently on "+
			"the two", v[0].Reason)
	}
}

// And when it fires, the row is suspicious at grade low, with the family named, and it is NOT
// reported as an unattributed perturbation: the syntax-error members are what moved the response
// and this class knows it.
func TestAFiringBlindArmTakesTheRowFromUnattributedErrorToBooleanDifferential(t *testing.T) {
	sc := sstiTestScorecard()
	sc.reflects = false
	sc.perturbedUnexplained = true // which is exactly what the ERR members cause
	sc.answered = sstiBlindSet("{\"ok\":true}")
	sc.answered[sstiS0] = triage.Observation{}
	sc.answered[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"v\":6.0}")
	sc.answered[sstiBER3] = sstiBlindObs(sstiBER3, 500, "{\"e\":1}")
	sc.answered[sstiBOK4] = sstiBlindObs(sstiBOK4, 200, "{\"ok\":true,\"v\":7.0}")
	sc.answered[sstiBER4] = sstiBlindObs(sstiBER4, 500, "{\"e\":1}")

	v := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, sstiBlindStable())
	if v[0].State != triage.StateSuspicious {
		t.Fatalf("state %q with reason %q, want suspicious", v[0].State, v[0].Reason)
	}
	if v[0].Grade != triage.GradeLow {
		t.Errorf("grade %q, want low: the harvest that produced these payloads rates the differential low to "+
			"medium on a real route and says it must ship at grade low", v[0].Grade)
	}
	if v[0].Oracle != "boolean_differential" {
		t.Errorf("oracle %q, want boolean_differential", v[0].Oracle)
	}
	if strings.Contains(v[0].Reason, "unattributed_error") {
		t.Errorf("the row was reported as an unattributed perturbation: %q. The thing that perturbed it was "+
			"this class's own syntax-error member and this class knows that", v[0].Reason)
	}
	if v[0].State.CountsAsClean() {
		t.Error("a boolean differential produced a clean")
	}
}

// The declared bytes are the measurement. Each pair must be length-matched inside the pair, or a
// length differential between its members can be the echo rather than the engine.
func TestEveryBlindPairIsLengthMatchedWithinThePair(t *testing.T) {
	rows := sstiSpecByID()
	for fam, pairs := range sstiBlindFamilies() {
		for _, pr := range pairs {
			ok, okFound := rows[pr.OK]
			bad, badFound := rows[pr.Err]
			if !okFound || !badFound {
				t.Fatalf("family %s names %s/%s and one of them is not a declared probe", fam, pr.OK, pr.Err)
			}
			if len(ok.logical) != len(bad.logical) {
				t.Errorf("%s (%s) is %d bytes and %s (%s) is %d: an endpoint that merely ECHOES the value "+
					"returns two different lengths for these two, and the arm's length oracle would fire on "+
					"every reflecting slot in the corpus",
					pr.OK, ok.logical, len(ok.logical), pr.Err, bad.logical, len(bad.logical))
			}
		}
	}
	// The two inert controls must NOT be length-matched to each other: their whole job is to be
	// the widest length gap in the arm, so a length-tracking endpoint shows up on them first.
	if len(rows[sstiBN1].logical) == len(rows[sstiBN2].logical) {
		t.Error("SSTI-BN1 and SSTI-BN2 are the same length, so the length control cannot detect an endpoint " +
			"whose response length tracks its input length")
	}
}

// The blind arm must not be planned on a slot that reflects: there the rank 1 computation oracle
// is available and ten requests of tier 6 differential buy nothing.
func TestTheBlindArmIsOnlyEarnedWhereTheComputationOracleCouldNotRun(t *testing.T) {
	blind := map[triage.ProbeID]bool{
		sstiBOK1: true, sstiBER1: true, sstiBOK2: true, sstiBER2: true,
		sstiBOK3: true, sstiBER3: true, sstiBOK4: true, sstiBER4: true, sstiBN1: true, sstiBN2: true,
	}
	for _, id := range []triage.ProbeID{sstiBOK1, sstiBOK3, sstiBN1, sstiBN2} {
		if !sstiIsEscalationOnly(id) {
			t.Errorf("%s is not marked escalation-only, so an Untested row for it says the budget ran out "+
				"when the truth is that nothing on the slot earned it", id)
		}
	}
	_ = blind
}

// The Untested row for the blind arm has to say the TRUE reason, and the true reason is not the
// one the escalation probes carry.
//
// MEASURED, canary oracle, first cut of this change: all ten blind probes came back in Untested
// reading "this probe is only earned by a first hit, and nothing on this slot earned it". That is
// the exact opposite of why the arm exists, it points the operator at nothing, and it hid the one
// fact worth knowing: at the default per-slot cap of 24 this class spends the whole allowance in
// rounds 0 and 1 and the arm's ten requests never leave.
func TestTheBlindArmsUntestedRowNamesTheRealReasonItDidNotRun(t *testing.T) {
	for _, tc := range []struct {
		name string
		sc   sstiScorecard
		want string
	}{
		// THE FIXTURES NOW SET reflectMeasure WHERE THE SCORECARD COULD ONLY HAVE IT SET, and
		// that is the substance of this case rather than tidying. sc.reflects is written in one
		// place, the SSTI-S0 arm of sstiScore, which sets reflectMeasure on the line above it, so
		// {reflects: true, reflectMeasure: false} is a state no run can produce and a fixture in
		// it was testing a branch order against an impossible slot.
		//
		// AND THE COMPUTED-FAMILY ROW CHANGED ITS ANSWER, because the old one was false about
		// time. Reaching it means the census answered and its marker did not come back, which IS
		// sstiBlindArmEarned, so this class requested all ten probes in round 1; the family
		// computed on a round 1 or later probe and declined the round 2 RETRY only. No round 0
		// probe can set computeFamily (sstiPlanCensus sends S0, DEC and the four error
		// polyglots, and none of those rows carries an expected computation or the control
		// flag), so a family can never be the reason the round 1 gate decided anything.
		{"a family computed after the gate was already met",
			sstiScorecard{reflectMeasure: true, computeFamily: sstiF1}, "requested_then_superseded"},
		{"the slot reflects, so this arm is dead weight",
			sstiScorecard{reflectMeasure: true, reflects: true}, "slot_reflects"},
		{"the gate was met and the ten probes are absent",
			sstiScorecard{reflectMeasure: true}, "requested_and_absent"},
		{"the census never answered, so this class never asked for the arm",
			sstiScorecard{}, "census_unanswered"},
		// The census never answered AND a family computed on a battery probe anyway. The gate
		// needs reflectMeasure, so it was never met and the arm was never requested: the census
		// fact outranks the family, and it outranks it because it is the fact the gate read.
		{"a family computed but the census still never answered",
			sstiScorecard{computeFamily: sstiF1}, "census_unanswered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sstiBlindSkipReason(tc.sc)
			if !strings.Contains(got, tc.want) {
				t.Errorf("sstiBlindSkipReason = %q, want it to name %q", got, tc.want)
			}
			if strings.Contains(got, "earned by a first hit") {
				t.Errorf("the blind arm's skip reason still carries the escalation sentence: %q. This arm is "+
					"earned by the ABSENCE of a hit", got)
			}
		})
	}
	for _, id := range []triage.ProbeID{sstiBOK1, sstiBER4, sstiBN1, sstiBN2} {
		if !sstiIsBlindArm(id) {
			t.Errorf("%s is not recognised as part of the blind arm, so its Untested row falls through to the "+
				"escalation sentence", id)
		}
	}
	for _, id := range []triage.ProbeID{sstiCF1, sstiZ1, sstiD1} {
		if sstiIsBlindArm(id) {
			t.Errorf("%s was claimed by the blind arm and it is an escalation probe", id)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// WHY THE BLIND ARM DID NOT RUN, AND THE TWO REASONS IT DID NOT
//
// MEASURED, canary oracle, 2026-09-19, whole registry at full tier, per-slot cap 48, and on the
// operator's live JSON REST API at the default cap of 24. Two separate causes, one symptom:
//
//	/ssti/blind    cannot_determine "blocked: three or more of this class's own distinct payloads
//	               produced byte-identical responses that differ from the route control". That
//	               route is THIS CLASS'S OWN DECLARED POSITIVE for the blind arm. Round 1 returns
//	               nil on a uniform block, the runner retires a class on the first round that
//	               plans nothing, so round 2 was never called and none of the ten probes went out.
//	live target    "blind_arm_not_run (length_control_not_measured)" on every slot, because
//	               rounds 0 and 1 spend all 24 probes and the arm is requested in round 2.
// ---------------------------------------------------------------------------------------------

func sstiTestFamilies() []triage.ProbeID {
	return []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF7, sstiF8, sstiF9, sstiF10, sstiF10w, sstiF11}
}

func sstiIndexOf(ids []triage.ProbeID, want triage.ProbeID) int {
	for i, id := range ids {
		if id == want {
			return i
		}
	}
	return -1
}

// THE ARM GOES OUT FIRST WHEN THE CENSUS HAS ALREADY SAID THE SLOT DOES NOT REFLECT, because the
// twelve computation families behind it all need a value back that will not come, and at the
// default per-slot cap they are what spends the allowance the arm never gets.
func TestRoundOneSendsTheBlindArmBeforeTheBatteryOnASlotThatDoesNotReflect(t *testing.T) {
	order := sstiRound1Order(triage.KindQuery, sstiTestFamilies(), false, true)
	iBN1, iBN2 := sstiIndexOf(order, sstiBN1), sstiIndexOf(order, sstiBN2)
	if iBN1 < 0 || iBN2 < 0 {
		t.Fatalf("round 1 did not request the arm's length control at all: %v", order)
	}
	for _, fam := range sstiTestFamilies() {
		i := sstiIndexOf(order, fam)
		if i < 0 {
			t.Errorf("%s fell out of round 1 entirely. This is an ORDERING change and never a "+
				"suppression: every battery probe is still requested and whichever ones the cap cuts "+
				"are named in Untested", fam)
			continue
		}
		if i < iBN1 || i < iBN2 {
			t.Errorf("%s is requested at %d, ahead of the inert length control at %d/%d. Losing a "+
				"delimiter pair costs the arm one family; losing BN1 or BN2 costs it the right to read "+
				"ANY pair, so the controls go first", fam, i, iBN1, iBN2)
		}
	}
	for _, id := range sstiBlindArmOrder() {
		if sstiIndexOf(order, id) < 0 {
			t.Errorf("%s was not requested", id)
		}
	}
}

// AND IT DOES NOT GO OUT AT ALL ON A SLOT THAT REFLECTS, where the rank 1 computation oracle is
// available and ten requests of tier 6 differential buy nothing.
func TestRoundOneLeavesTheBlindArmOutWhenTheSlotReflects(t *testing.T) {
	order := sstiRound1Order(triage.KindQuery, sstiTestFamilies(), false, false)
	for _, id := range sstiBlindArmOrder() {
		if sstiIndexOf(order, id) >= 0 {
			t.Errorf("%s was requested on a slot whose value comes back, where the computation oracle "+
				"has already answered", id)
		}
	}
	if sstiIndexOf(order, sstiF1) != 0 {
		t.Errorf("the battery no longer leads round 1 on a reflecting slot: %v", order)
	}
}

// THE UNIFORM-BLOCK GATE SUPPRESSES THE BATTERY AND NOT THE ARM. Returning nil here does not
// suppress round 1, it retires the class, and everything the class had left was in round 2.
func TestAUniformBlockSuppressesTheBatteryAndPlansTheBlindArmInstead(t *testing.T) {
	order := sstiRound1Order(triage.KindQuery, sstiTestFamilies(), true, true)
	if len(order) == 0 {
		t.Fatal("a uniform block planned nothing, which retires this class for the slot and makes round " +
			"2 unreachable. That is how /ssti/blind, this class's own positive for the arm, came back " +
			"'blocked' with none of the arm's ten probes sent")
	}
	want := sstiBlindArmOrder()
	if len(order) != len(want) {
		t.Fatalf("a uniform block planned %d probes, want exactly the arm's %d: the battery must stay "+
			"suppressed, which is what the gate is for. Got %v", len(order), len(want), order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("a uniform block planned %v, want the arm in its own order %v", order, want)
		}
	}
	if none := sstiRound1Order(triage.KindQuery, sstiTestFamilies(), true, false); len(none) != 0 {
		t.Errorf("a uniform block on a slot that DOES reflect planned %v: the arm is earned by the "+
			"absence of the rank 1 oracle, and nothing else survives a block", none)
	}
}

// THE BLOCK READING LOSES TO A SEPARATION AND TO NOTHING ELSE. A filter refuses the expression
// that parses and the one that does not alike, because both carry the delimiters it is refusing,
// so it cannot separate a pair. Both pairs of a family separating, in the same direction, over
// same-length members, on an endpoint whose inert length control held, is a statement a block
// page cannot make.
func TestAUniformBlockDoesNotOutrankABlindArmThatSeparated(t *testing.T) {
	blocked := sstiBlindStable()
	blocked.blocked = true

	t.Run("a separation wins", func(t *testing.T) {
		sc := sstiTestScorecard()
		sc.reflects = false
		sc.answered = sstiBlindSet("{\"ok\":true,\"items\":[]}")
		sc.answered[sstiBOK3] = sstiBlindObs(sstiBOK3, 200, "{\"ok\":true,\"items\":[],\"v\":6.0}")
		sc.answered[sstiBER3] = sstiBlindObs(sstiBER3, 500, "{\"error\":\"render_failed\"}")
		sc.answered[sstiBOK4] = sstiBlindObs(sstiBOK4, 200, "{\"ok\":true,\"items\":[],\"v\":7.0}")
		sc.answered[sstiBER4] = sstiBlindObs(sstiBER4, 500, "{\"error\":\"render_failed\"}")

		v := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, blocked)
		if len(v) != 1 {
			t.Fatalf("got %d verdicts, want 1", len(v))
		}
		if v[0].State != triage.StateSuspicious || v[0].Oracle != "boolean_differential" {
			t.Fatalf("state %q oracle %q: this is /ssti/blind's exact shape - the valid member renders and "+
				"the invalid one raises, in both pairs - and the uniform-block heuristic reads it as a "+
				"filter. Reason: %s", v[0].State, v[0].Oracle, v[0].Reason)
		}
		if v[0].Grade != triage.GradeLow {
			t.Errorf("grade %q: a differential proves a parser and never an evaluation", v[0].Grade)
		}
		if !strings.Contains(v[0].Reason, "uniform block") {
			t.Errorf("the row does not tell the reader that the endpoint also looked like a uniform block "+
				"and why the arm outranked that reading: %s", v[0].Reason)
		}
	})

	t.Run("a silent arm leaves the block exactly where it was, and says so", func(t *testing.T) {
		sc := sstiTestScorecard()
		sc.reflects = false
		sc.answered = sstiBlindSet("{\"ok\":true,\"items\":[]}")
		v := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, blocked)
		if v[0].State != triage.StateCannotDetermine || !strings.Contains(v[0].Reason, "blocked:") {
			t.Fatalf("state %q reason %q: a silent arm eliminates two delimiter families and says nothing "+
				"about whether a filter answered", v[0].State, v[0].Reason)
		}
		if !strings.Contains(v[0].Reason, "blind_arm_ran_and_was_silent") {
			t.Errorf("the blocked row does not say what the one arm that needs nothing back did here, which "+
				"is the difference between 'nothing was tried' and 'the arm ran and was quiet': %s", v[0].Reason)
		}
	})
}

// THE LENGTH CONTROL'S REFUSAL NAMES WHICH PROBE AND WHY. "At least one of them produced no
// comparable response" was one phrase covering four causes, and the one that was true on every
// slot of the live run - the probes were never sent - is a number in the settings document and
// not a property of the target. An operator reading the old sentence goes looking at the endpoint.
func TestTheLengthControlRefusalNamesTheProbeAndTheCause(t *testing.T) {
	for _, tc := range []struct {
		name, want string
		mutate     func(set map[triage.ProbeID]triage.Observation)
	}{
		{"never sent", "NEVER SENT", func(set map[triage.ProbeID]triage.Observation) {
			delete(set, sstiBN1)
		}},
		{"transport refused", "transport refused it", func(set map[triage.ProbeID]triage.Observation) {
			o := set[sstiBN1]
			o.TransportErr = triage.TransportConnect
			set[sstiBN1] = o
		}},
		{"truncated", "TRUNCATED", func(set map[triage.ProbeID]triage.Observation) {
			o := set[sstiBN1]
			o.BodyTruncated = true
			set[sstiBN1] = o
		}},
		{"no normalised body", "no normalised body", func(set map[triage.ProbeID]triage.Observation) {
			o := set[sstiBN1]
			o.Proj.NormBody = nil
			set[sstiBN1] = o
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := sstiBlindSet("{\"ok\":true}")
			tc.mutate(set)
			got := sstiBlindArm(set, sstiBlindStable())
			if got.Outcome != sstiBlindNotRun {
				t.Fatalf("outcome %v: the arm read a length off a control it could not measure", got.Outcome)
			}
			if !strings.Contains(got.Why, "length_control_not_measured") {
				t.Fatalf("the reason %q does not name the precondition that failed", got.Why)
			}
			if !strings.Contains(got.Why, string(sstiBN1)) {
				t.Errorf("the reason %q does not say WHICH of the two controls was the problem", got.Why)
			}
			if !strings.Contains(got.Why, tc.want) {
				t.Errorf("the reason %q does not carry %q, so the operator cannot tell a setting they can "+
					"raise from a fact about the endpoint", got.Why, tc.want)
			}
			if !strings.Contains(got.Why, string(sstiBN2)+" was measured") {
				t.Errorf("the reason %q does not say that the OTHER control was fine, so it reads as both "+
					"of them having failed", got.Why)
			}
		})
	}
}

// =================================================================================================
// THE NON-ERROR POLYGLOT: WHAT ITS BYTES COMING BACK CHANGED ACTUALLY MEANS
// =================================================================================================
//
// THE MEASUREMENT THESE TESTS ENCODE. On the 80-route canary exam this class reported suspicious
// on 30 routes and clean on none. Twenty-nine of the 30 came from ONE comparison: the bytes after
// SSTI-S2's marker were not byte-equal to the bytes sent, and the row said "something parsed the
// delimiters". Every one of the 29 was read back off the oracle and named, and not one was a
// template engine: twenty-one were html.EscapeString on the way out, two were a JSON string, one
// was an endpoint that never percent-decodes, three were a field that cut the value, and two were
// a regexp that deletes braces.
//
// The old rule fails every escaped row below. It is a raw bytes.Equal on the tail, so an
// entity-escaped copy, a JSON-quoted copy and a percent-kept copy are all "modified" to it, and
// each row asserts that the old rule really does fire before asserting the new one does not.

func sstiTestS2Row(t *testing.T) sstiRow {
	t.Helper()
	r, ok := sstiSpecByID()[sstiS2]
	if !ok {
		t.Fatal("SSTI-S2 is not in this class's own probe table, so the polyglot has no declared bytes")
	}
	return r
}

func sstiTestObs(m triage.Marker, body string) triage.Observation {
	return triage.Observation{Marker: m, Status: 200, Body: []byte(body)}
}

// sstiOldPolyglotModified is the rule this round replaced, copied verbatim so the regression is
// visible in the same run rather than remembered from a transcript.
func sstiOldPolyglotModified(obs triage.Observation, r sstiRow) bool {
	m := obs.Marker
	if m == "" {
		return false
	}
	hay := sstiSearchSpace(obs)
	i := bytes.Index(hay, []byte(m))
	if i < 0 {
		return false
	}
	tail := hay[i+len(m):]
	want := []byte(r.logical)
	if len(tail) < len(want) {
		return true
	}
	return !bytes.Equal(tail[:len(want)], want)
}

func TestThePolyglotComparisonDoesNotCallAnEscaperATemplateEngine(t *testing.T) {
	m := sstiTestMarker(t, "1f3q", 65)
	row := sstiTestS2Row(t)
	sent := row.logical

	entity := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&#34;", "'", "&#39;").Replace(sent)
	jsonish := strings.ReplaceAll(sent, `"`, `\"`)
	pct := strings.NewReplacer(" ", "%20", `"`, "%22", ">", "%3E", "[", "%5B", "]", "%5D",
		"$", "%24", "{", "%7B", "}", "%7D").Replace(sent)

	cases := []struct {
		name string
		body string
		want sstiPolyglotOutcome
		why  string
	}{
		{"the bytes came back as the bytes, measured on /clean/echo",
			string(m) + sent + "\n", sstiPolyglotIntact,
			"a text/plain echo returns the polyglot unchanged, and that is the only shape that may support a clean"},
		{"html.EscapeString, measured on 21 routes including /clean/echoparser and /xss/encoded",
			"<p>Nothing matched " + string(m) + entity + ".</p>", sstiPolyglotEncoded,
			"an HTML escaper leaves every delimiter in the response, entity-encoded. It is a defence working, not a parse"},
		{"a JSON string, measured on /clean/echomongo and /csti/inscript",
			`{"received":"` + string(m) + jsonish + `"}`, sstiPolyglotEncoded,
			"strconv.Quote escapes the quote and nothing else this payload carries"},
		{"never percent-decoded, measured on /csti/pct-literal",
			"<div>" + string(m) + pct + "</div>", sstiPolyglotEncoded,
			"the braces came back as %7B, which is the value arriving undecoded and not an engine consuming it"},
		{"the delimiters were DELETED, measured on /csti/escaped",
			"<div>" + string(m) + "p \"&gt;[[$1]]</div>", sstiPolyglotDiverged,
			"a regexp that strips every brace produces the same bytes an engine would, and this class may not choose between them"},
		{"the field CUT the value, measured on /cmdi",
			string(m) + "p: 56 data bytes", sstiPolyglotDiverged,
			"a truncated value means the closing delimiters never reached whatever reads this field"},
		{"the marker never came back",
			"<div>nothing here</div>", sstiPolyglotUnread,
			"with no marker in the response there is no tail to compare and nothing was measured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := sstiTestObs(m, tc.body)
			old := sstiOldPolyglotModified(obs, row)
			if tc.want == sstiPolyglotEncoded && !old {
				t.Fatal("this row does not reproduce the OLD behaviour, so it is not the regression it claims to be")
			}
			if tc.want == sstiPolyglotEncoded {
				t.Logf("OLD RULE: modified=true on this body, which shipped as suspicious (grade low), reason \"something parsed the delimiters\"")
			}
			got := sstiPolyglotReturn(obs, row)
			if got != tc.want {
				t.Errorf("polyglot outcome %q, want %q: %s", got, tc.want, tc.why)
			}
		})
	}
}

// AN ESCAPED POLYGLOT MAY NOT BE A POINTER, AND A DIVERGED ONE MAY NOT BE A CLEAN.
//
// These are the two halves of retiring the arm. The first is the noise: 29 rows of grade-low
// suspicion on a mostly-negative corpus, which teaches an operator to ignore the class. The
// second is the half that must not be traded away with it: if this class's own polyglot did not
// survive, the delimiters every other payload in the battery carries did not survive either, and
// a silence measured through changed bytes is not the application's silence.
func TestAnEscapedPolyglotIsEvidenceAndADivergedOneIsARefusal(t *testing.T) {
	for _, tc := range []struct {
		name    string
		out     sstiPolyglotOutcome
		clean   bool
		phrase  string
		because string
	}{
		{"intact", sstiPolyglotIntact, true, "",
			"the polyglot survived, so the battery's delimiters reached the application and a silence is the application's"},
		{"encoded", sstiPolyglotEncoded, true, "",
			"an entity-encoded copy has every delimiter still in it. Escaping is a defence working and must not cost the class its clean"},
		{"diverged", sstiPolyglotDiverged, false, "polyglot_diverged",
			"an engine, a brace-deleting sanitizer and a field that cut the value all produce these bytes, and one response cannot separate them"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := sstiTestScorecard()
			sc.polyglot = tc.out
			v := sstiCompose("query:q", sc, []uint64{65}, nil, nil, map[string]any{}, sstiEnv{})[0]
			if v.State == triage.StateSuspicious {
				t.Fatalf("polyglot %q produced a suspicious pointer: %s", tc.out, v.Reason)
			}
			if tc.clean != v.State.CountsAsClean() {
				t.Fatalf("polyglot %q produced state %q (%s), and clean=%v was expected: %s",
					tc.out, v.State, v.Reason, tc.clean, tc.because)
			}
			if tc.phrase != "" && !strings.Contains(v.Reason, tc.phrase) {
				t.Errorf("the reason %q does not carry %q, so the row does not say what fired", v.Reason, tc.phrase)
			}
		})
	}
}

// =================================================================================================
// RULING R1: AN ECHO IS NOT AN UNATTRIBUTED ERROR
// =================================================================================================
//
// MEASURED: /clean/echo, whose own OracleCases say the verdict must be CLEAN with its ordinals,
// reported cannot_determine (unattributed_error) on the exam, and so did /xss, /lfi, /redirect,
// /eli/echo and /deser/pickle. The trigger was "any non-control probe whose body differs from the
// route control", and on an endpoint that echoes, every probe differs for the one reason this
// class already knows: the page printed the payload.
func TestAnEchoedPayloadIsNotAnUnattributedError(t *testing.T) {
	m := sstiTestMarker(t, "1f3q", 65)
	route := triage.Observation{Status: 200, Body: []byte("echo\n")}
	for _, tc := range []struct {
		name      string
		obs       triage.Observation
		explained bool
		why       string
	}{
		{"the marker came back and the status class did not move",
			triage.Observation{Marker: m, Status: 200, Body: []byte("echo\n" + string(m) + "p\n")}, true,
			"this class's own census probe proved the slot reflects, so the moved body is the echo of its own payload"},
		{"the marker came back uppercased by the application",
			triage.Observation{Marker: m, Status: 200, Body: []byte("echo\n" + strings.ToUpper(string(m)) + "p\n")}, true,
			"a marker form this class already recognises elsewhere must not be read as an absence here"},
		{"the status class moved, measured on /sqli/mssql",
			triage.Observation{Marker: m, Status: 500, Body: []byte("error near " + string(m))}, false,
			"an endpoint that echoed AND changed its status class did more than echo, and R1 is exactly for that"},
		{"the marker is not in the response at all",
			triage.Observation{Marker: m, Status: 200, Body: []byte("Unhandled exception")}, false,
			"nothing observed says the change came from this class's value, so it stays unexplained"},
		{"the probe carried no marker",
			triage.Observation{Status: 200, Body: []byte("echo\n")}, false,
			"with no marker there is no way to observe an echo, and an assumption is not an observation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sstiEchoExplains(tc.obs, route); got != tc.explained {
				t.Errorf("sstiEchoExplains = %v, want %v: %s", got, tc.explained, tc.why)
			}
		})
	}
}

// =================================================================================================
// BATTERY_INCOMPLETE COUNTS WHAT WAS ACTUALLY LOST
// =================================================================================================
//
// MEASURED on /clean/echo: 45 Untested rows, of which 34 were escalation-only probes earned by a
// hit that never came, 10 were the blind arm correctly not run because the slot reflects, and one
// was SSTI-F9c, the cookie-only sibling of a Liquid family that DID go out on this slot. Zero
// engines were left untested and the rung read len(untested) > 0, so it fired, and its sentence
// said "45 of this class's families were not sent". Both the state and the number were wrong, and
// that rung sits directly above the clean, which is why this class had no reachable clean at all.
func TestBatteryIncompleteCountsGapsAndNotEveryUntestedRow(t *testing.T) {
	slot := triage.Slot{Key: "query:q", Kind: triage.KindQuery, ServerReachable: true,
		Constraints: triage.SlotConstraints{DecodeDepth: 1}}
	ctx := triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}}

	// A slot that reflects, where the whole base ladder was answered and nothing fired. That is
	// the shape of every clean this class will ever say.
	sc := sstiScorecard{answered: map[triage.ProbeID]triage.Observation{}, decodeDepth: 1,
		reflectMeasure: true, reflects: true, censusMarkerOnWire: true}
	for _, r := range sstiProbeTable() {
		if sstiIsBlindArm(r.id) || sstiIsEscalationOnly(r.id) {
			continue
		}
		if !sstiPointsInclude(r.points, slot.Kind) {
			continue
		}
		sc.answered[r.id] = triage.Observation{Status: 200}
	}
	// The five negative controls are escalation-only in the table and ARE earned on this slot, so
	// they are deliberately left out of the answered set above: they are the gap this asserts.
	untested, gaps := sstiUntested(ctx, sc)
	if len(untested) == 0 {
		t.Fatal("nothing was reported untested on a slot that skipped the whole escalation ladder, so the Untested list stopped naming gaps at all")
	}
	byID := map[triage.ProbeID]string{}
	for _, u := range untested {
		byID[u.ProbeID] = u.Reason
	}
	inGaps := map[triage.ProbeID]bool{}
	for _, g := range gaps {
		inGaps[g] = true
	}
	for _, id := range []triage.ProbeID{sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4} {
		if !inGaps[id] {
			t.Errorf("%s is earned on a reflecting slot with no hit and did not go out, and it is not counted as a gap: the clean would rest on a matcher nothing verified", id)
		}
		if strings.Contains(byID[id], "only earned by a first hit") {
			t.Errorf("%s carries the sentence %q, which stopped being true when the controls became earned by reflection", id, byID[id])
		}
	}
	for _, id := range []triage.ProbeID{sstiCF1, sstiI1, sstiD1, sstiEPJava} {
		if inGaps[id] {
			t.Errorf("%s is a confirmation or an identification finisher earned by a first hit, and counting it as a gap makes every clean unreachable forever", id)
		}
	}
	for _, id := range []triage.ProbeID{sstiBOK1, sstiBER1, sstiBN1} {
		if inGaps[id] {
			t.Errorf("%s is the blind arm, which is correctly not run on a slot that reflects, so it leaves nothing untested", id)
		}
	}
	if inGaps[sstiF9c] {
		t.Error("SSTI-F9c is the cookie-only sibling of a Liquid family that went out on this query slot, so its absence leaves no engine untested")
	}

	// THE OLD RUNG, INLINE: it read len(untested) > 0 and would have refused this slot.
	if len(untested) == 0 {
		t.Fatal("this case does not reproduce the old behaviour")
	}
	t.Logf("OLD RUNG: len(untested)=%d, so battery_incomplete fired and said %d families were not sent. NEW: %d real gaps",
		len(untested), len(untested), len(gaps))

	// And with the controls answered too, the slot has no gap left and the clean is reachable.
	for _, id := range []triage.ProbeID{sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4} {
		sc.answered[id] = triage.Observation{Status: 200}
	}
	untested, gaps = sstiUntested(ctx, sc)
	if len(gaps) != 0 {
		t.Fatalf("a slot whose whole deliverable battery was answered still reports %d gaps (%v), so the clean stays structurally unreachable", len(gaps), gaps)
	}
	v := sstiCompose(slot.Key, sc, []uint64{65}, untested, gaps, map[string]any{}, sstiEnv{})[0]
	if !v.State.CountsAsClean() {
		t.Fatalf("state %q with reason %q on a slot with nothing left untested: this class must be able to say clean or it cannot contribute to a stated-clean report", v.State, v.Reason)
	}
	if len(v.Untested) == 0 {
		t.Error("the clean dropped the Untested list, so the escalation probes that were never earned became invisible")
	}
}

// THE CONTROLS ARE EARNED BY A SLOT THAT REFLECTS AND NOTHING ELSE, which is the slot whose
// silence is about to be reported as the application's.
//
// THE DEFECT: until this round the five were requested from ONE place, the branch earned by a
// computation hit. On the slot heading for a clean they never left, sc.controlFired was empty
// because nothing was sent, and the clean's own stated precondition ("its own four controls
// stayed silent") was a claim about requests that did not happen. Four of this class's own
// OracleCases point NC1, NC2, NC3a and NC4 at /clean/echo, and that verification had never run.
func TestTheNegativeControlsAreEarnedBeforeACleanAndNotOnlyAfterAHit(t *testing.T) {
	base := sstiScorecard{answered: map[triage.ProbeID]triage.Observation{}, reflectMeasure: true, reflects: true}
	if !sstiControlsEarned(base) {
		t.Fatal("a reflecting slot with no hit does not earn this class's own negative controls, so its clean rests on a matcher that was never shown able to stay silent")
	}
	hit := base
	hit.computeFamily = sstiF1
	if sstiControlsEarned(hit) {
		t.Error("the controls were earned twice on a slot that hit: the branch above already sends them and a duplicate request is a wasted probe")
	}
	blind := base
	blind.reflects = false
	if sstiControlsEarned(blind) {
		t.Error("the controls were earned on a slot that does not reflect, where NC2's whole design (send the answer next to the marker and watch the guard suppress it) cannot be observed at all")
	}
}

// =================================================================================================
// A REASON MAY NOT REPORT A FACT THAT DID NOT EXIST WHEN THE DECISION IT EXPLAINS WAS TAKEN
//
// THE DEFECT, reproduced on a real row. sstiBlindGateSentence tested computeFamily BEFORE
// reflects, so on a slot where the gate declined because THE CENSUS MARKER CAME BACK, the
// sentence read "SSTI-F2 computed, so the strongest oracle in this class had already answered by
// the round in which the arm would have been planned", and sstiBlindAbsenceCause escalated that
// into "THIS CLASS NEVER ASKED FOR THE PROBE(S) NAMED (SSTI-F2 computed...)".
//
// Both halves are wrong about TIME, and no grep over reason strings can see it, because every
// word in the sentence is true of the scorecard at the moment it was written. What is false is
// the claim about WHEN each fact was read. The gate is asked in round 1 and again in round 2. At
// the round 1 gate the scorecard holds round 0's answers and nothing else.
// =================================================================================================

// sstiCensusProbeSet is the round 0 menu, taken from sstiPlanCensus.
func sstiCensusProbeSet() map[triage.ProbeID]bool {
	return map[triage.ProbeID]bool{
		sstiS0: true, sstiDEC: true, sstiS1: true, sstiS1q: true, sstiS1s: true, sstiS1b: true,
	}
}

// THE PREMISE OF THE FIX, PINNED SO IT CANNOT ROT.
//
// The corrected branch order rests on one property of the probe table: NO ROUND 0 PROBE CAN SET
// computeFamily. sstiScore reaches sc.computeFamily only through the RULE COMPUTATION block,
// which needs row.variant[sstiVariantExpected] to be set or row.control to be true. If someone
// later gives SSTI-DEC an expected computation, a family becomes a round 0 fact, the round 1
// gate can genuinely have declined on it, and the sentence this file just corrected becomes
// wrong in the other direction. That is a two-line edit in a table three thousand lines away
// from the sentence it would falsify, which is exactly the kind of drift this test exists for.
func TestNoRoundZeroProbeCanSetAComputedFamily(t *testing.T) {
	census := sstiCensusProbeSet()
	seen := 0
	for _, r := range sstiProbeTable() {
		if !census[r.id] {
			continue
		}
		seen++
		if r.control {
			t.Errorf("%s is a round 0 probe and is marked control, so sstiScore scores it against this "+
				"class's canonical expected answer and it can set computeFamily. The blind arm's gate "+
				"sentence says a computed family is always a round 1 or later fact, and that would stop "+
				"being true", r.id)
		}
		if want := r.variant[sstiVariantExpected]; want != "" {
			t.Errorf("%s is a round 0 probe and declares an expected computation %q, so it can set "+
				"computeFamily before the blind arm's gate is first asked. sstiBlindGateSentence and "+
				"sstiBlindSkipReason both state that a computed family cannot be the reason the round 1 "+
				"gate decided; fix them together or revert this row", r.id, want)
		}
	}
	if seen != len(census) {
		t.Fatalf("matched %d of the %d round 0 probes in the table, so this test is checking less than it "+
			"claims", seen, len(census))
	}
}

// AND THE MENU THIS TEST CALLS ROUND 0 IS THE ONE sstiPlanCensus ACTUALLY SENDS.
func TestTheRoundZeroMenuIsWhatThisFileCallsRoundZero(t *testing.T) {
	census := sstiCensusProbeSet()
	for _, kind := range triage.AllSlotKinds() {
		ctx := triage.PlanCtx{Slot: triage.Slot{
			VectorID: "v1", Key: "query:q", Name: "q", Value: "alice", Kind: kind,
			ServerReachable: true, Method: "GET", SegmentIndex: -1,
			Constraints: triage.NewSlotConstraints(),
		}}
		for _, r := range sstiPlanCensus(ctx) {
			if !census[r.Spec] {
				t.Errorf("sstiPlanCensus sends %s in round 0 on a %s slot and the round 0 set in this file "+
					"does not name it, so TestNoRoundZeroProbeCanSetAComputedFamily is checking the wrong "+
					"menu", r.Spec, kind)
			}
		}
	}
}

// THE GATE SENTENCE REPORTS THE FACT THE GATE READ, AT THE ROUND THE GATE WAS ASKED.
func TestTheBlindGateSentenceNamesTheFactThatDecidedItAndNotALaterOne(t *testing.T) {
	for _, tc := range []struct {
		name   string
		sc     sstiScorecard
		want   []string
		forbid []string
	}{
		{
			// The case that was measured wrong. Reflection is a round 0 fact and it is what the
			// gate read; the family is a round 1 fact and is not.
			name:   "the census marker came back and a family later computed",
			sc:     sstiScorecard{reflectMeasure: true, reflects: true, computeFamily: sstiF2},
			want:   []string{"not requested", "census marker CAME BACK"},
			forbid: []string{string(sstiF2), "by the round in which the arm would have been planned"},
		},
		{
			// The case a bare reorder does NOT fix, and the reason "satisfy yourself it fixes all
			// of them" is in the brief. reflectMeasure true with reflects false IS the gate met,
			// so the arm was requested in round 1 whatever computed afterwards.
			name:   "the census did not reflect and a family computed anyway",
			sc:     sstiScorecard{reflectMeasure: true, computeFamily: sstiF2},
			want:   []string{"requested", "gate WAS met in round 1", string(sstiF2), "round 2 retry"},
			forbid: []string{"not requested"},
		},
		{
			name:   "the census never answered",
			sc:     sstiScorecard{},
			want:   []string{"not requested", string(sstiS0)},
			forbid: []string{"computed"},
		},
		{
			name:   "the gate was met and nothing computed",
			sc:     sstiScorecard{reflectMeasure: true},
			want:   []string{"requested", "round 1 and again in round 2"},
			forbid: []string{"not requested"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sstiBlindGateSentence(tc.sc)
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("the gate sentence does not say %q:\n  %s", w, got)
				}
			}
			for _, f := range tc.forbid {
				if strings.Contains(got, f) {
					t.Errorf("the gate sentence still carries %q, which is not what the gate read:\n  %s", f, got)
				}
			}
			// And the escalation the annotation actually prints has to agree with it. This is
			// where the defect was visible on the live row: the gate said one thing and
			// sstiBlindAbsenceCause turned it into "THIS CLASS NEVER ASKED".
			cause := sstiBlindAbsenceCause(got)
			asked := strings.Contains(cause, "DID ASK")
			neverAsked := strings.Contains(cause, "NEVER ASKED")
			if asked == neverAsked {
				t.Fatalf("the absence cause says neither or both:\n  %s", cause)
			}
			if wantAsked := !strings.HasPrefix(got, "not requested: "); asked != wantAsked {
				t.Errorf("the absence cause disagrees with the gate sentence beside it:\n  gate : %s\n  cause: %s", got, cause)
			}
		})
	}
}

// AND THE UNTESTED ROW AND THE GAP FLAG MAY NOT CONTRADICT EACH OTHER.
//
// sstiBlindSkipIsBudget used to return false for a computed family, which paired a row saying
// "the arm was requested and nothing came back" with a flag saying nothing was missing. The two
// are read by different halves of the report.
//
// THE PREDICATE IS DELIBERATELY WIDER THAN THE ROW IN ONE DIRECTION AND THAT IS NOT A
// CONTRADICTION. Its own comment argues it: census_unanswered is counted as a gap even though
// that row says this class never requested the arm, because narrowing it is the one edit here
// that could turn a refusal into a clean. So the property pinned is one-sided: a row saying the
// arm was correctly not needed (slot_reflects) may NEVER be a gap, and a row saying the arm was
// requested MUST be one.
func TestTheBlindArmsGapFlagDoesNotContradictItsUntestedRow(t *testing.T) {
	for _, sc := range []sstiScorecard{
		{reflectMeasure: true, reflects: true, computeFamily: sstiF2},
		{reflectMeasure: true, reflects: true},
		{reflectMeasure: true, computeFamily: sstiF2},
		{reflectMeasure: true},
		{},
	} {
		row := sstiBlindSkipReason(sc)
		gap := sstiBlindSkipIsBudget(sc)
		switch {
		case strings.Contains(row, "slot_reflects") && gap:
			t.Errorf("the row says the rank 1 oracle was available so the arm bought nothing, and the gap "+
				"flag counts it against the clean anyway:\n  %s", row)
		case strings.Contains(row, "requested_") && !gap:
			t.Errorf("the row says this class asked for the arm and no observation came back, and the gap "+
				"flag says nothing is missing:\n  %s", row)
		}
	}
}

// sstiDecodeDepthFrom must read the percent-literal before counting raw markers. The runner places
// the raw marker for attribution, so an endpoint that reflects the value in two output locations
// returns it twice with nothing decoded, and a bare count >= 2 used to read that as a decode
// (depth 1). That skipped the decode_depth_0 rung and let a brace payload that arrived
// percent-encoded as literal %7B read as clean, which is the fail-open this layer exists to stop.
func TestSSTIDecodeDepthReadsThePercentLiteralBeforeCountingReflections(t *testing.T) {
	m := triage.Marker("ssti0marker00042")
	raw := []byte(m)
	pct := sstiTestPctLiteral(m)
	sep := []byte(" ... ")

	// Does NOT decode, reflected in TWO locations: raw marker twice, percent literal present.
	two := bytes.Join([][]byte{raw, pct, sep, raw, pct}, nil)
	if got := sstiDecodeDepthFrom(two, m); got != 0 {
		t.Errorf("two reflections with nothing decoded: decode depth = %d, want 0 (did not decode)", got)
	}
	// Does NOT decode, single reflection: raw marker once, percent literal present.
	single := bytes.Join([][]byte{raw, sep, pct}, nil)
	if got := sstiDecodeDepthFrom(single, m); got != 0 {
		t.Errorf("single reflection with nothing decoded: decode depth = %d, want 0", got)
	}
	// DOES decode: the encoded copy came back as a second raw marker and the percent literal is gone.
	decoded := bytes.Join([][]byte{raw, sep, raw}, nil)
	if got := sstiDecodeDepthFrom(decoded, m); got != 1 {
		t.Errorf("the encoded copy decoded: decode depth = %d, want 1 (decodes)", got)
	}
	// Neither form present: unknown, never a decode.
	if got := sstiDecodeDepthFrom([]byte("nothing to see here"), m); got != -1 {
		t.Errorf("neither form present: decode depth = %d, want -1 (unknown)", got)
	}
}

// sstiTestPctLiteral mirrors the production percent-encoding (lowercase %XX per byte) without
// pulling fmt into the test file.
func sstiTestPctLiteral(m triage.Marker) []byte {
	const hexd = "0123456789abcdef"
	var b []byte
	for i := 0; i < len(m); i++ {
		b = append(b, '%', hexd[m[i]>>4], hexd[m[i]&0x0f])
	}
	return b
}
