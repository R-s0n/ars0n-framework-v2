package triageclasses

import (
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
		planned:        20,
		answered:       map[triage.ProbeID]triage.Observation{sstiS0: {}},
		markers:        map[triage.ProbeID]triage.Marker{},
		reflects:       true,
		reflectMeasure: true,
		decodeDepth:    1,
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
			vs := sstiCompose("query:q", sc, ords, nil, map[string]any{}, env)
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
	vs := sstiCompose("query:q", sstiTestScorecard(), []uint64{65, 129}, nil, map[string]any{}, sstiEnv{})
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
		got := sstiCompose("query:q", sstiTestScorecard(), []uint64{65}, skips, map[string]any{}, sstiEnv{})
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

	unconfirmed := sstiCompose("query:q", base, []uint64{65}, nil, map[string]any{}, sstiEnv{})[0]
	if unconfirmed.State != triage.StateSuspicious {
		t.Errorf("an unconfirmed hit is %q, want suspicious", unconfirmed.State)
	}
	if unconfirmed.Grade == triage.GradeHigh {
		t.Error("an unconfirmed hit graded high, so a cached body would be reported as a confirmed finding")
	}

	confirmed := base
	confirmed.confirmed = true
	v := sstiCompose("query:q", confirmed, []uint64{65, 129}, nil, map[string]any{}, sstiEnv{})[0]
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
	v := sstiCompose("query:q", sc, []uint64{65}, nil, map[string]any{}, sstiEnv{})[0]
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
	stripped := sstiCompose("query:q", sc, []uint64{65}, nil, map[string]any{}, sstiEnv{})[0]
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
	skips := sstiUntested(triage.ClassifyCtx{PlanCtx: ctx}, sstiScorecard{answered: map[triage.ProbeID]triage.Observation{}})
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
	skips := sstiUntested(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}}, sstiScorecard{answered: map[triage.ProbeID]triage.Observation{}})
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
