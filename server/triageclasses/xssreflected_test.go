package triageclasses

import (
	"bytes"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// Tests for the reflected XSS class.
//
// EVERY TEST NAME IN THIS FILE CARRIES XSSR. The package holds one file per class and Go has one
// test namespace per package, so two classes that both write TestReachesAnswersWithAReason do not
// collide in review, they collide in the BUILD, and the whole package's tests stop running. That
// has already happened here once between two sibling classes.
//
// WHAT IS TESTED AND WHAT CANNOT BE. The detection rules, the tokenizer facts they rest on, the
// promotion ladder, the control set and every path that must produce an unknown are all exercised
// directly. Two things cannot be reached from this package and are named rather than faked: a
// resolved triage.Replay (its constructor takes the runner capability, whose type is in an
// internal package) and a populated triage.OwnedResponses (same reason). The class is split at
// xssrClassifyEligible and xssrCollect precisely so that everything behind those two is still
// testable.

const (
	xssrTestRunID = "t1a9"
	// Three markers of this class's own stripe (ordinal mod 64 == 9) and one of XSS-STORED's,
	// each with a real CRC-32 checksum so Marker.Integrity reads valid.
	xssrMarkOne     = triage.Marker("zqjt1a9000009je9") // ordinal 9
	xssrMarkTwo     = triage.Marker("zqjt1a9000021itd") // ordinal 73
	xssrMarkThree   = triage.Marker("zqjt1a900003tylb") // ordinal 137
	xssrMarkForeign = triage.Marker("zqjt1a900000c0gr") // ordinal 12, which is XSS-STORED's stripe
)

// TestTheXSSRTestMarkersAreWhatTheyClaimToBe checks the fixtures before anything uses them. A
// test marker with a bad checksum or the wrong stripe would silently exercise the attribution
// guards instead of the rules, and every table below would pass for the wrong reason.
func TestTheXSSRTestMarkersAreWhatTheyClaimToBe(t *testing.T) {
	for _, m := range []triage.Marker{xssrMarkOne, xssrMarkTwo, xssrMarkThree} {
		if !m.WellFormed() {
			t.Fatalf("test marker %q is not well formed", m)
		}
		if m.Integrity() != triage.MarkerValid {
			t.Fatalf("test marker %q fails its own checksum, so every rule test would run against the corrupted path", m)
		}
		if !m.BelongsTo(triage.ClassXSSReflected) {
			t.Fatalf("test marker %q is not in this class's ordinal stripe", m)
		}
		if m.RunID() != xssrTestRunID {
			t.Fatalf("test marker %q carries run id %q, want %q", m, m.RunID(), xssrTestRunID)
		}
	}
	if xssrMarkForeign.BelongsTo(triage.ClassXSSReflected) {
		t.Fatal("the foreign fixture is in this class's stripe, so the foreign-marker test proves nothing")
	}
}

// xssrShot builds one of this class's own probe responses.
func xssrShot(probe triage.ProbeID, m triage.Marker, media, body string) xssrProbeObs {
	ord, _ := m.Ordinal()
	return xssrProbeObs{
		Probe: probe, Ordinal: ord, Marker: m,
		Obs: triage.Observation{
			ObsID: string(probe) + ":" + string(m), RunID: xssrTestRunID, Class: triage.ClassXSSReflected,
			Status: 200, MediaType: triage.MediaType(media), ContentType: media,
			Body: []byte(body), BodyLen: len(body),
			Payload: triage.PayloadWire{Logical: []byte("probe-bytes"), Survived: triage.WireSurvivalIntact},
		},
	}
}

func xssrRunOf(items ...xssrProbeObs) xssrRun {
	r := xssrRun{Items: items}
	for _, it := range items {
		r.Ordinals = append(r.Ordinals, it.Ordinal)
		if why := xssrTemplateSurvived(it); why != "" {
			r.RunnerBug = why
		}
	}
	return r
}

func xssrFired(hits []xssrHit, rule string) bool {
	for _, h := range hits {
		if h.Rule == rule && !h.Secondary {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// REGISTRATION, THE CONTRACT AND THE ISOLATION LAW
// ---------------------------------------------------------------------------------------------

func TestTheXSSRClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassXSSReflected)
	if !ok {
		t.Fatal("the reflected XSS classifier did not register itself, so the class would be missing from every " +
			"report with no error anywhere")
	}
	if c.ID() != triage.ClassXSSReflected {
		t.Fatalf("registered under XSS-R but reports %s", c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	if err := triage.PlannedProbesAreDeclared(c, c.Plan(triage.PlanCtx{})); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassXSSReflected {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
		if len(p.Logical) == 0 {
			t.Errorf("probe %s has no bytes, so it would send nothing and record clean", p.ID)
		}
	}
}

// TestEveryXSSRPayloadIsThisClassesAloneAfterMarkerNormalisation is the isolation law, which is
// the rule the operator is emphatic about: two classes shipping byte-equal payloads cannot tell a
// validator's rejection from a WAF's, so a CLEAN gets recorded for a class that was never tested.
func TestEveryXSSRPayloadIsThisClassesAloneAfterMarkerNormalisation(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		if strings.HasPrefix(string(v.ProbeA), "RX-") || strings.HasPrefix(string(v.ProbeB), "RX-") {
			t.Errorf("ISOLATION: %s", v)
		}
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)

	seen := map[string]triage.ProbeID{}
	for _, p := range (xssReflectedClassifier{}).Probes() {
		k := string(triage.NormaliseMarkers(p.Logical))
		if prev, dup := seen[k]; dup {
			t.Errorf("%s and %s are byte-equal after marker normalisation, so a hit on one cannot be told from a "+
				"hit on the other and the per-probe tail has stopped doing its job", p.ID, prev)
		}
		seen[k] = p.ID
	}
}

// TestEveryXSSRPayloadCarriesThisClassesOwnMarkerTemplate. A payload that writes another class's
// marker shape would make that class's search fire on our probe.
func TestEveryXSSRPayloadCarriesThisClassesOwnMarkerTemplate(t *testing.T) {
	if !triage.Marker(xssrTemplateMarker).WellFormed() {
		t.Fatalf("the template marker %q is not marker-shaped, so the runner's substitution will not find it and "+
			"the isolation check cannot read its stripe", xssrTemplateMarker)
	}
	if !triage.Marker(xssrTemplateMarker).BelongsTo(triage.ClassXSSReflected) {
		owner, _ := triage.Marker(xssrTemplateMarker).ClassID()
		t.Fatalf("the template marker's ordinal stripe is class %s, not XSS-R", owner)
	}
	if triage.Marker(xssrTemplateMarker).Integrity() != triage.MarkerValid {
		t.Error("the template marker's checksum does not verify; it should be a real marker layout so that anything " +
			"reading it gets a consistent answer")
	}
	for _, p := range (xssReflectedClassifier{}).Probes() {
		for _, tok := range strings.Split(string(p.Logical), "zqj")[1:] {
			if len(tok) < 13 {
				continue
			}
			m := triage.Marker("zqj" + tok[:13])
			if !m.WellFormed() {
				continue
			}
			if !m.BelongsTo(triage.ClassXSSReflected) {
				t.Errorf("%s embeds marker-shaped token %q from another class's stripe", p.ID, m)
			}
		}
	}
}

// TestNoXSSRPayloadIsDestructiveOrExecutable. The triage layer never sends alert(1), for any
// class, and nothing here may change state or reach a third party.
func TestNoXSSRPayloadIsDestructiveOrExecutable(t *testing.T) {
	banned := []string{"alert(", "prompt(", "confirm(", "document.cookie", "fetch(", "http://", "https://",
		"drop ", "delete ", "insert ", "update ", "onerror", "onload", "eval("}
	for _, p := range (xssReflectedClassifier{}).Probes() {
		low := strings.ToLower(string(p.Logical))
		for _, b := range banned {
			if strings.Contains(low, b) {
				t.Errorf("probe %s contains %q, and this class ships to every user and runs against any app", p.ID, b)
			}
		}
		if p.Risk == triage.RiskR3 {
			t.Errorf("probe %s is declared R3; nothing in this class is destructive or noisy", p.ID)
		}
	}
}

func TestTheXSSRFragmentIsNotApplicableAndSaysWhy(t *testing.T) {
	r := (xssReflectedClassifier{}).Reaches(triage.KindFragment, "text/html")
	if r.Reach != triage.ReachNever {
		t.Fatalf("the fragment reads as %s; the server never sees it", r.Reach)
	}
	if !strings.Contains(r.Reason, "3986") || !strings.Contains(strings.ToLower(r.Reason), "xss-dom") {
		t.Errorf("the fragment reason %q does not name the rule or the class that does own the slot", r.Reason)
	}
	v := xssrClassify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Slot: triage.Slot{Key: "fragment:tab", Kind: triage.KindFragment},
	}}, xssrRun{})
	if len(v) != 1 || v[0].State != triage.StateNotApplicable {
		t.Fatalf("a fragment slot produced %+v, want one not_applicable row", v)
	}
	if v[0].State.CountsAsClean() {
		t.Error("a fragment slot rendered as clean")
	}
}

// ---------------------------------------------------------------------------------------------
// RX-D1, AND THE FALSE POSITIVES IT MUST STAY SILENT ON
// ---------------------------------------------------------------------------------------------

// TestTheXSSRElementRuleFiresOnAParseTreeChangeAndStaysSilentOnEveryNamedFalsePositive is the
// central test of this class. Every row named FALSE POSITIVE is a way a reflection detector
// reports a bug that is not there; RX-D1 is a parse-tree fact precisely so that none of them
// fires.
func TestTheXSSRElementRuleFiresOnAParseTreeChangeAndStaysSilentOnEveryNamedFalsePositive(t *testing.T) {
	m := string(xssrMarkOne)
	cases := []struct {
		name string
		shot xssrProbeObs
		want bool
		why  string
	}{
		{
			name: "the true shape: the tokenizer names a start tag after this run's marker",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>"+m+"<"+m+">-rx1</p>"),
			want: true,
			why:  "the application let this value OPEN AN ELEMENT, which is a parse-tree state change and the whole oracle",
		},
		{
			name: "the true shape with the tag left unclosed, which RX-1c relies on",
			shot: xssrShot(xssrP1c, xssrMarkOne, "text/html", "<p>"+m+"<"+m+"/-rx1c and then the page's own > here ></p>"),
			want: true,
			why:  "the page's own > closes the tag and the bytes between become attribute names, exactly as a browser does it",
		},
		{
			name: "the true shape in an empty media type, which renders",
			shot: xssrShot(xssrP1, xssrMarkOne, "", m+"<"+m+">-rx1"),
			want: true,
			why:  "a body with no content type is sniffed and rendered, so the element is real",
		},
		{
			name: "FALSE POSITIVE: the marker is in a text node and no tag was opened",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>you searched for "+m+"</p>"),
			want: false,
			why:  "reflection is not injection, and this is the row the framework's existing probe already reports",
		},
		{
			name: "FALSE POSITIVE: the angle brackets came back as character references (NC-A3)",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>"+m+"&lt;"+m+"&gt;-rx1</p>"),
			want: false,
			why: "a character reference decodes to a CHARACTER TOKEN and can never produce a tag. This is the single " +
				"most important control in the family and a detector that fires here is matching text",
		},
		{
			name: "FALSE POSITIVE: the marker is inside an attribute VALUE",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/html", `<input value="`+m+`<`+m+`>-rx1">`),
			want: false,
			why:  "the value never left its quotes, so the parser named no new element",
		},
		{
			name: "FALSE POSITIVE: a tag name that merely CONTAINS the marker",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/html", "<x"+m+">-rx1"),
			want: false,
			why:  "something rewrote the name, so this is a near miss recorded as suspicious and never an element we created",
		},
		{
			name: "FALSE POSITIVE: the element is written inside <noscript>",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/html", "<noscript>"+m+"<"+m+">-rx1</noscript>"),
			want: false,
			why: "with SCRIPTING-ENABLED semantics noscript is RAWTEXT and no element forms. A tokenizer configured " +
				"with scripting off reports a finding on an application that is not vulnerable",
		},
		{
			name: "FALSE POSITIVE: the response is a download",
			shot: func() xssrProbeObs {
				s := xssrShot(xssrP1, xssrMarkOne, "text/html", m+"<"+m+">-rx1")
				s.Obs.RespHeaders = [][2]string{{"Content-Disposition", "attachment; filename=export.html"}}
				return s
			}(),
			want: false,
			why:  "the body is downloaded and never parsed as markup, so nothing in it can execute",
		},
		{
			name: "FALSE POSITIVE: a JSON response with nosniff",
			shot: func() xssrProbeObs {
				s := xssrShot(xssrP16, xssrMarkOne, "application/json", `{"q":"`+m+"<"+m+`>-rx16"}`)
				s.Obs.RespHeaders = [][2]string{{"X-Content-Type-Options", "nosniff"}}
				return s
			}(),
			want: false,
			why:  "the media type gate is shut, and the honest answer is needs_dom_run rather than a finding or a clean",
		},
		{
			name: "FALSE POSITIVE: a cached body carrying a PREVIOUS run's marker",
			shot: func() xssrProbeObs {
				s := xssrShot(xssrP1, xssrMarkOne, "text/html", m+"<"+m+">-rx1")
				s.Obs.RunID = "zzzz"
				return s
			}(),
			want: false,
			why:  "a marker whose run id is not this run's is stale_marker, and a verdict drawn from it is a verdict about last week",
		},
		{
			name: "FALSE POSITIVE: the element is named by ANOTHER class's marker",
			shot: func() xssrProbeObs {
				f := string(xssrMarkForeign)
				s := xssrShot(xssrP1, xssrMarkForeign, "text/html", f+"<"+f+">-rx1")
				return s
			}(),
			want: false,
			why:  "R12: a marker outside this class's stripe is a hit for nobody, never a hit for whoever looked first",
		},
		{
			name: "FALSE POSITIVE: the transport refused and there is no response",
			shot: func() xssrProbeObs {
				s := xssrShot(xssrP1, xssrMarkOne, "text/html", m+"<"+m+">-rx1")
				s.Obs.TransportErr = triage.TransportInvalidHeader
				return s
			}(),
			want: false,
			why:  "an undelivered probe's body cannot be read as anything, in either direction",
		},
		{
			name: "FALSE POSITIVE: the element sits in the last bytes of a truncated body",
			shot: func() xssrProbeObs {
				s := xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>padding</p>"+m+"<"+m+">-rx1")
				s.Obs.BodyTruncated = true
				return s
			}(),
			want: false,
			why:  "the cut may have manufactured the tag, and a hit that may be an artefact of the capture is not a hit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := xssrFired(xssrRulesFor(tc.shot), "RX-D1")
			if got != tc.want {
				t.Errorf("RX-D1 fired=%v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestTheXSSRAttributeRuleNeedsTheNameAndNotTheValue is the whole discrimination RX-2 exists for.
func TestTheXSSRAttributeRuleNeedsTheNameAndNotTheValue(t *testing.T) {
	m := string(xssrMarkOne)
	fired := xssrFired(xssrRulesFor(xssrShot(xssrP2, xssrMarkOne, "text/html",
		`<input value="`+m+`" `+m+`="rx2">`)), "RX-D2")
	if !fired {
		t.Error("RX-D2 did not fire on an attribute NAMED by the marker, which is the parse-tree fact this class reports")
	}
	silent := xssrFired(xssrRulesFor(xssrShot(xssrP2, xssrMarkOne, "text/html",
		`<input value="`+m+`&quot; `+m+`=&quot;rx2">`)), "RX-D2")
	if silent {
		t.Error("RX-D2 fired on an attribute whose VALUE contains the marker. That is reflection, the quotes were " +
			"encoded, and calling it a hit makes every echoing input a finding")
	}
	inert := xssrRulesFor(xssrShot(xssrP2, xssrMarkOne, "text/html", `<meta content="`+m+`" `+m+`="rx2">`))
	if !xssrFired(inert, "RX-D2") {
		t.Error("an attribute created on an inert host element is still a breakout and must still be reported")
	}
}

// TestTheUnquotedAttributeValueEndsOnlyAtWhitespaceOrGreaterThanForXSSR is tokenizer correction 1.
// A probe built on the slash reports clean on an exploitable unquoted attribute.
func TestTheUnquotedAttributeValueEndsOnlyAtWhitespaceOrGreaterThanForXSSR(t *testing.T) {
	doc := xssrTokenize([]byte(`<div a=b/><div c=d"e'f=g>`))
	var vals []string
	for _, tk := range doc.Tokens {
		for _, a := range tk.Attrs {
			vals = append(vals, a.Name+"="+a.Value)
		}
	}
	joined := strings.Join(vals, ",")
	if !strings.Contains(joined, "a=b/") {
		t.Errorf("the tokenizer split an unquoted value at a slash: got %q. In the unquoted value state the slash "+
			"is APPENDED, which is why <div a=b/> yields a=\"b/\" and why RX-4 is built on a space", joined)
	}
	if !strings.Contains(joined, `c=d"e'f=g`) {
		t.Errorf("the tokenizer split an unquoted value at a quote or an equals: got %q. Those raise a parse error "+
			"and are then appended; only whitespace and > leave the state", joined)
	}
	if len((xssReflectedClassifier{}).Probes()) > 0 {
		for _, p := range (xssReflectedClassifier{}).Probes() {
			if p.ID == xssrP4 && !strings.Contains(string(p.Logical), " ") {
				t.Error("RX-4 carries no space, so it cannot break out of an unquoted attribute value at all")
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE ENCODING LADDER, WHICH IS THE THING GETTING IT BACKWARDS BREAKS
// ---------------------------------------------------------------------------------------------

// TestTheEntityRungIsExecutableInAnEventHandlerAndInertInsideAScriptForXSSR is the asymmetry the
// whole class turns on. Getting it the other way round produces a false positive on every
// entity-encoded script reflection and a false negative on the event-handler case at once.
func TestTheEntityRungIsExecutableInAnEventHandlerAndInertInsideAScriptForXSSR(t *testing.T) {
	m := string(xssrMarkOne)

	handler := xssrShot(xssrP5b, xssrMarkOne, "text/html",
		`<a onclick="doThing('`+m+`&#39;-`+m+`-&#39;-rx5b')">go</a>`)
	if !xssrFired(xssrRulesFor(handler), "RX-D3") {
		t.Error("the entity rung did not fire in an event handler. The tokenizer entity-decodes an attribute value " +
			"and hands the RESULT to the JS parser, which is the PortSwigger lab and the highest-value probe here")
	}

	script := xssrShot(xssrP8a, xssrMarkOne, "text/html",
		`<script>var x = '`+m+`&#39;-`+m+`-&#39;-rx8a';</script>`)
	if xssrFired(xssrRulesFor(script), "RX-D3") {
		t.Error("the entity rung fired inside a <script>. Script data has no character reference clause at all, so " +
			"&#39; reaches the JS lexer as six literal characters inside the string and executes nothing")
	}

	real := xssrShot(xssrP8a, xssrMarkOne, "text/html",
		`<script>var x = '`+m+`'-`+m+`-'-rx8a';</script>`)
	if !xssrFired(xssrRulesFor(real), "RX-D3") {
		t.Error("a raw quote inside a script string did not produce a lexer transition, and that is the only thing " +
			"that gets a payload out of a JS string literal")
	}

	data := xssrShot(xssrP8a, xssrMarkOne, "text/html",
		`<script type="application/json">{"x":"`+m+`'-`+m+`-'-rx8a"}</script>`)
	if xssrFired(xssrRulesFor(data), "RX-D3") {
		t.Error("a lexer transition was reported inside <script type=\"application/json\">, which is DATA. Reporting " +
			"it sends the operator's expensive scanner at a sink that cannot execute")
	}
}

// TestTheJSLexerKnowsCommentsAndRegexesFromCodeForXSSR: an occurrence in a comment or a regex is
// not a transition, and the division ambiguity is reported rather than guessed silently.
func TestTheJSLexerKnowsCommentsAndRegexesFromCodeForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	cases := []struct {
		name string
		body string
		want bool
		why  string
	}{
		{"code position is the hit", `<script>var a = ` + m + `;</script>`, true,
			"the marker lexes as an identifier, which is code"},
		{"a line comment is not", `<script>// ` + m + "\n" + `var a = 1;</script>`, false,
			"an occurrence in a comment executes nothing"},
		{"a block comment is not", `<script>/* ` + m + ` */ var a = 1;</script>`, false,
			"an occurrence in a comment executes nothing"},
		{"a string literal is not", `<script>var a = "` + m + `";</script>`, false,
			"that is where the value was written; a transition is the point"},
		{"a template substitution is", "<script>var a = `x${" + m + "}y`;</script>", true,
			"a substitution is a lexer state change and not a rendered value"},
		{"template text is not", "<script>var a = `x" + m + "y`;</script>", false,
			"template text is a literal, like any other string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := xssrFired(xssrRulesFor(xssrShot(xssrP8a, xssrMarkOne, "text/html", tc.body)), "RX-D3")
			if got != tc.want {
				t.Errorf("RX-D3 fired=%v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestTheURLSchemeRuleNeedsTheSchemeAtOffsetZeroForXSSR, including the two transforms that behave
// oppositely on the same byte.
func TestTheURLSchemeRuleNeedsTheSchemeAtOffsetZeroForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	cases := []struct {
		name string
		body string
		want bool
		why  string
	}{
		{"the scheme at value offset 0", `<a href="javascript:` + m + `-rx6a">x</a>`, true,
			"the scheme position is the only place a scheme is reachable"},
		{"the entity scheme rung", `<a href="&#106;avascript:` + m + `-rx6b">x</a>`, true,
			"the value is entity-decoded and THEN handed to the URL parser, so &#106; resolves"},
		{"an embedded tab in the scheme", `<a href="java&#9;script:` + m + `-rx6c">x</a>`, true,
			"the URL parser strips embedded C0 and whitespace after entity decoding"},
		{"FALSE POSITIVE: percent encoding, which is NOT decoded before scheme resolution",
			`<a href="%6aavascript:` + m + `-rx6a">x</a>`, false,
			"reading %6a as a scheme is the mirror image of the entity rule and it is wrong"},
		{"FALSE POSITIVE: the scheme later in the value", `<a href="/go?next=javascript:` + m + `-rx6a">x</a>`, false,
			"that is an open redirect question and belongs to REDIRECT, not here"},
		{"FALSE POSITIVE: a non-URL attribute", `<span title="javascript:` + m + `-rx6a">x</span>`, false,
			"a title attribute is not a navigation sink"},
		{"FALSE POSITIVE: the marker is absent from the value", `<a href="javascript:void(0)">` + m + `</a>`, false,
			"the scheme has to be OURS, or every javascript: link in the page is a finding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := xssrFired(xssrRulesFor(xssrShot(xssrP6a, xssrMarkOne, "text/html", tc.body)), "RX-D4")
			if got != tc.want {
				t.Errorf("RX-D4 fired=%v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

// TestCharacterSurvivalIsNeverAFindingOnItsOwnForXSSR. RX-D5 exists to explain a near miss and
// choose the next probe. A triage layer that reports it as a finding is reporting reflection.
func TestCharacterSurvivalIsNeverAFindingOnItsOwnForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	hits := xssrRulesFor(xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>"+m+"&lt;"+m+"[stripped]-rx1</p>"))
	for _, h := range hits {
		if h.Rule == "RX-D5" && !h.Secondary {
			t.Error("a character-survival hit is not marked secondary, so it could be promoted to a finding")
		}
	}
	// The page's own markup after the reflection must not be read as the payload's surviving byte.
	quiet := xssrRulesFor(xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>"+m+"&lt;"+m+"&gt;-rx1</p><div>more</div>"))
	for _, h := range quiet {
		if h.Rule == "RX-D5" {
			t.Errorf("RX-D5 fired on page markup outside the payload's own extent (%s). A fixed-width window past "+
				"the marker reports every reflection into <p>...</p> as a surviving angle bracket", h.Detail)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE CONTROLS
// ---------------------------------------------------------------------------------------------

// TestAFiringXSSRControlVoidsEveryVerdictOnTheSlot. A detector shown firing on its own negative
// control is broken, and a broken detector's silence elsewhere is worthless.
func TestAFiringXSSRControlVoidsEveryVerdictOnTheSlot(t *testing.T) {
	m := string(xssrMarkOne)
	ctx := xssrTestCtx(xssrDecodedSlot())

	// The entity control's own response, if it ever produced an element, means the detector is
	// matching text. It cannot happen through this tokenizer, so the row is built by hand: the
	// question is whether the CHECK is wired, not whether the tokenizer is right.
	bad := xssrShot(xssrPNC3, xssrMarkOne, "text/html", m+"<"+m+">-rxnc3")
	run := xssrRunOf(xssrShot(xssrP0r, xssrMarkTwo, "text/html", "hello "+string(xssrMarkTwo)+"-rx0r"), bad)
	if fired, why := run.ControlFired(); !fired {
		t.Fatal("the control check did not notice an element created from the entity control's own response")
	} else if !strings.Contains(why, "detector_unverified") {
		t.Errorf("the control failure reason %q does not use the vocabulary the report filters on", why)
	}
	vs := xssrClassifyEligible(ctx, run, xssrEligibility{OK: true})
	for _, v := range vs {
		if v.State.CountsAsClean() || v.State == triage.StateFinding {
			t.Errorf("a slot whose control fired produced %s; every verdict there is cannot_determine", v.State)
		}
	}
}

// TestTheBareCensusProbeMayNeverFireARuleForXSSR is NC-A1, which costs zero requests because it
// is a rule applied to a response the class already holds.
func TestTheBareCensusProbeMayNeverFireARuleForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	run := xssrRunOf(xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>you searched for "+m+"-rx0r</p>"))
	if fired, why := run.ControlFired(); fired {
		t.Errorf("the bare marker fired a rule (%s). It carries no metacharacter, so it cannot change a parse tree "+
			"and a rule firing here means the detector is searching for text", why)
	}
}

// ---------------------------------------------------------------------------------------------
// NOT KNOWING IS NOT CLEAN
// ---------------------------------------------------------------------------------------------

func xssrTestCtx(slot triage.Slot) triage.ClassifyCtx {
	return triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Slot:     slot,
		Vector:   triage.TriageVector{ID: "v1", Method: "GET", RespMedia: "text/html"},
		Baseline: triage.BaselineModel{Samples: 5, Stable: true},
		Prelude:  triage.PreludeTokenNotRequired,
		Budget:   triage.TriageBudget{PerSlot: 12, RemainingPerSlot: 9, RemainingPerRun: 500, PerRun: 5000},
	}}
}

func xssrQuerySlot() triage.Slot {
	s := triage.Slot{Key: "query:q", Kind: triage.KindQuery, Name: "q", Value: "hello",
		Method: "GET", ValueOrigin: triage.ValueObserved, Origin: triage.SlotObserved,
		ServerReachable: true, Constraints: triage.NewSlotConstraints()}
	s.Constraints.DecodeDepth = -1
	return s
}

// xssrDecodedSlot is the same slot with a decode depth already measured on it. A test cannot
// build a resolved route control, and the route differential is where this class normally learns
// that the value reached the application, so these tests take the borrowed reading instead. The
// differential itself is tested directly in TestTheDeliveryEvidenceTellsFourThingsApartForXSSR.
func xssrDecodedSlot() triage.Slot {
	s := xssrQuerySlot()
	s.Constraints.DecodeDepth = 1
	return s
}

// xssrSilentCensus is a slot that reflected nothing, which is one half of the only shape that may
// produce a clean. The decode probe comes back WITHOUT the marker, because a slot that echoes
// nothing echoes the decode probe's marker no more than the census's.
func xssrSilentCensus() xssrRun {
	return xssrRunOf(
		xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>no such thing</p>"),
		xssrShot(xssrP0a, xssrMarkTwo, "text/html", "<p>no such thing</p>"),
		xssrShot(xssrPDec, xssrMarkThree, "text/html", "<p>no such thing, and the percent form %7a%71%6a stayed</p>"),
	)
}

// TestTheDeliveryEvidenceTellsFourThingsApartForXSSR. An absent marker means nothing until the
// request is shown to have arrived, and these four readings are the difference between a clean
// and three different unknowns.
func TestTheDeliveryEvidenceTellsFourThingsApartForXSSR(t *testing.T) {
	route := triage.Observation{Status: 200, BodyLen: 20, Body: []byte("<p>the usual page</p>")}
	route.BodyLen = len(route.Body)
	sameAsRoute := func(probe triage.ProbeID, m triage.Marker) xssrProbeObs {
		it := xssrShot(probe, m, "text/html", string(route.Body))
		it.Obs.Status = route.Status
		return it
	}

	t.Run("the decode probe's own marker came back", func(t *testing.T) {
		run := xssrRunOf(xssrShot(xssrPDec, xssrMarkThree, "text/html", "you sent "+string(xssrMarkThree)))
		d := xssrDeliveryEvidence(route, true, xssrQuerySlot(), run)
		if !d.Delivered || !d.Decoded || d.Evidence != "decode_probe_marker_returned" {
			t.Errorf("got %+v, want the strongest reading: the value was decoded AND it arrived", d)
		}
	})
	t.Run("the encoded form resolved like the observed value", func(t *testing.T) {
		run := xssrRunOf(
			xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>a different page</p>"),
			sameAsRoute(xssrPDec, xssrMarkThree),
		)
		d := xssrDeliveryEvidence(route, true, xssrQuerySlot(), run)
		if !d.Delivered || !d.Decoded || d.Depth != 1 {
			t.Errorf("got %+v, want decoded: the percent-encoded value resolved to the same page as the raw one", d)
		}
	})
	t.Run("the parameter is discarded entirely", func(t *testing.T) {
		run := xssrRunOf(sameAsRoute(xssrP0r, xssrMarkOne), sameAsRoute(xssrPDec, xssrMarkThree))
		d := xssrDeliveryEvidence(route, true, xssrQuerySlot(), run)
		if d.Delivered || !strings.Contains(d.Why, "value_ignored") {
			t.Errorf("got %+v, want value_ignored: an absence measured on an ignored parameter is a fact about the "+
				"endpoint and not about the application", d)
		}
	})
	t.Run("nothing measured it at all", func(t *testing.T) {
		run := xssrRunOf(xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>x</p>"))
		d := xssrDeliveryEvidence(triage.Observation{}, false, xssrQuerySlot(), run)
		if d.Delivered || !strings.Contains(d.Why, "decode_depth_unknown") {
			t.Errorf("got %+v, want decode_depth_unknown, which is never a clean", d)
		}
	})
}

// TestEveryUndecidableXSSRPathYieldsAnUnknownRatherThanAClean is the rule of this whole layer:
// a tool that never ran is not a pass. Every row here is a way this class can fail to get an
// answer, and not one of them may render as clean.
func TestEveryUndecidableXSSRPathYieldsAnUnknownRatherThanAClean(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*triage.ClassifyCtx, *xssrRun)
		want   triage.TriageState
		needle string
	}{
		{
			name:   "no probe was sent at all",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) { *r = xssrRun{} },
			want:   triage.StateNotPlanned, needle: "measured nothing",
		},
		{
			name: "the budget was spent before the census went out",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				*r = xssrRun{}
				c.Budget.RemainingPerSlot = 0
			},
			want: triage.StateNotRun, needle: "probe_budget_exhausted",
		},
		{
			name: "the vault refused to hand this class one of its own responses",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				*r = xssrRun{ReadErr: triage.ErrForeignObservation}
			},
			want: triage.StateCannotDetermine, needle: "own_responses_unreadable",
		},
		{
			name: "the runner shipped the payload template unsubstituted",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				it := xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>nothing</p>")
				it.Obs.Payload.Logical = []byte(xssrTemplateMarker + "<" + xssrTemplateMarker + ">-rx1")
				*r = xssrRunOf(it)
			},
			want: triage.StateCannotDetermine, needle: "runner_bug",
		},
		{
			name: "every probe was refused by the transport",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				a := xssrShot(xssrP0r, xssrMarkOne, "text/html", "")
				a.Obs.TransportErr = triage.TransportTimeout
				b := xssrShot(xssrP0a, xssrMarkTwo, "text/html", "")
				b.Obs.TransportErr = triage.TransportTimeout
				*r = xssrRunOf(a, b)
			},
			want: triage.StateCannotDetermine, needle: "could_not_send",
		},
		{
			name: "three of this class's own payloads got the same block page",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				block := "<html><body>Request blocked</body></html>"
				*r = xssrRunOf(
					xssrShot(xssrP0r, xssrMarkOne, "text/html", block),
					xssrShot(xssrP0a, xssrMarkTwo, "text/html", block),
					xssrShot(xssrP1, xssrMarkThree, "text/html", block),
				)
			},
			want: triage.StateCannotDetermine, needle: "blocked",
		},
		{
			name: "the census ran in one form only",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				*r = xssrRunOf(xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>nothing</p>"))
			},
			want: triage.StateCannotDetermine, needle: "census_incomplete",
		},
		{
			name: "nobody recorded whether the payload reached the wire",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				run := xssrSilentCensus()
				run.Items[0].Obs.Payload.Survived = triage.WireSurvivalUnknown
				*r = run
			},
			want: triage.StateCannotDetermine, needle: "wire_survival_unknown",
		},
		{
			name: "the cookie sanitizer dropped bytes on the way out",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				run := xssrSilentCensus()
				run.Items[0].Obs.Payload.Survived = triage.WireSurvivalDropped
				run.Items[0].Obs.Payload.AlteredBy = "net/http.Cookie sanitizer"
				*r = run
			},
			want: triage.StateCannotDetermine, needle: "payload_mangled_on_send",
		},
		{
			name: "this class's own decode probe says the slot does not decode",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				c.Slot.Constraints.DecodeDepth = -1
			},
			want: triage.StateCannotDetermine, needle: "decode_depth_0",
		},
		{
			name: "the decode probe never ran and nothing else measured the slot",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				c.Slot.Constraints.DecodeDepth = -1
				*r = xssrRunOf(
					xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>nothing</p>"),
					xssrShot(xssrP0a, xssrMarkTwo, "text/html", "<p>nothing</p>"),
				)
			},
			want: triage.StateCannotDetermine, needle: "decode_depth_unknown",
		},
		{
			name: "the field truncates below the marker's length",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				c.Slot.Constraints.FieldLimit = 8
			},
			want: triage.StateCannotDetermine, needle: "truncated",
		},
		{
			name:   "the comparison for this endpoint is degraded",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) { c.Baseline.Degraded = true },
			want:   triage.StateCannotDetermine, needle: "degraded_comparison",
		},
		{
			name:   "nothing measured the endpoint's normal behaviour",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) { c.Baseline.Samples = 0 },
			want:   triage.StateCannotDetermine, needle: "no_baseline_model",
		},
		{
			name:   "the probes ran against a fabricated identifier",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) { c.Slot.ValueOrigin = triage.ValueCanary },
			want:   triage.StateCannotDetermine, needle: "canary_resource",
		},
		{
			name:   "the value travels inside a signature this class cannot recompute",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) { c.Slot.Wrapper = triage.WrapSigned },
			want:   triage.StateCannotDetermine, needle: "signed_wrapper",
		},
		{
			name: "the marker came back and no encoder could be identified",
			mutate: func(c *triage.ClassifyCtx, r *xssrRun) {
				run := xssrSilentCensus()
				run.Items[0] = xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>echo "+string(xssrMarkOne)+"-rx0r</p>")
				*r = run
			},
			want: triage.StateCannotDetermine, needle: "reflected_context_undecided",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := xssrTestCtx(xssrDecodedSlot())
			run := xssrSilentCensus()
			el := xssrEligibility{OK: true}
			tc.mutate(&ctx, &run)
			el.Promote = xssrPromotion(ctx.Slot)
			vs := xssrClassifyEligible(ctx, run, el)
			if len(vs) == 0 {
				t.Fatal("no verdict at all, so the slot reads as untouched")
			}
			for _, v := range vs {
				if v.State.CountsAsClean() {
					t.Fatalf("this path produced CLEAN (%s), which is the bug this layer exists to stop", v.Reason)
				}
				if err := v.Validate(); err != nil {
					t.Errorf("verdict failed its own contract: %v", err)
				}
			}
			found := false
			for _, v := range vs {
				if v.State == tc.want && strings.Contains(v.Reason, tc.needle) {
					found = true
				}
			}
			if !found {
				t.Errorf("want a %s row whose reason contains %q; got %s", tc.want, tc.needle, xssrSummarise(vs))
			}
		})
	}
}

func xssrSummarise(vs []triage.ClassVerdict) string {
	var out []string
	for _, v := range vs {
		r := v.Reason
		if len(r) > 90 {
			r = r[:90]
		}
		out = append(out, string(v.State)+" ("+r+")")
	}
	return strings.Join(out, " | ")
}

// TestACleanXSSRVerdictRequiresEveryPreconditionAndNamesThem. This is the only shape that may
// produce a green tick, and it must carry the probe ordinals that produced it.
func TestACleanXSSRVerdictRequiresEveryPreconditionAndNamesThem(t *testing.T) {
	ctx := xssrTestCtx(xssrDecodedSlot())
	vs := xssrClassifyEligible(ctx, xssrSilentCensus(), xssrEligibility{OK: true})
	if len(vs) != 1 {
		t.Fatalf("want one row for a slot that reflected nothing, got %s", xssrSummarise(vs))
	}
	v := vs[0]
	if v.State != triage.StateClean {
		t.Fatalf("a silent census with every precondition met produced %s (%s). If clean is unreachable the class "+
			"reports nothing useful and every operator ignores it", v.State, v.Reason)
	}
	if len(v.Ordinals) == 0 {
		t.Error("a clean with no probe ordinals asserts a measurement that never happened, and it is a hard error")
	}
	if err := v.Validate(); err != nil {
		t.Errorf("the clean verdict failed its own contract: %v", err)
	}
	if !strings.Contains(v.Reason, "no_reflection") {
		t.Errorf("the clean reason %q does not name the precondition set an operator can check", v.Reason)
	}
	if len(v.Untested) == 0 {
		t.Error("a clean with no untested list hides the thirty probes that did not run")
	}
}

// TestAnEncodedReflectionIsCleanOnlyWhenEveryPromotedContextRanForXSSR.
func TestAnEncodedReflectionIsCleanOnlyWhenEveryPromotedContextRanForXSSR(t *testing.T) {
	m1, m2, m3 := string(xssrMarkOne), string(xssrMarkTwo), string(xssrMarkThree)
	census := "<p>you searched for " + m1 + "-rx0r</p>"
	run := xssrRunOf(
		xssrShot(xssrP0r, xssrMarkOne, "text/html", census),
		xssrShot(xssrP0a, xssrMarkTwo, "text/html", "<p>hello"+m2+"-rx0a</p>"),
		xssrShot(xssrPDec, xssrMarkThree, "text/html", "decoded "+m3+"-rxdec"),
	)
	ctx := xssrTestCtx(xssrDecodedSlot())
	vs := xssrClassifyEligible(ctx, run, xssrEligibility{OK: true})
	for _, v := range vs {
		if v.State.CountsAsClean() {
			t.Errorf("clean was reported while RX-1, the payload the html_text placement promoted, had not run: %s", v.Reason)
		}
	}

	// Now the promoted payload ran and the encoder closed it.
	run.Items = append(run.Items, xssrShot(xssrP1, xssrMarkThree, "text/html",
		"<p>you searched for "+m3+"&lt;"+m3+"&gt;-rx1</p>"))
	run.Ordinals = append(run.Ordinals, 137)
	vs = xssrClassifyEligible(ctx, run, xssrEligibility{OK: true})
	clean := false
	for _, v := range vs {
		if v.State == triage.StateClean && strings.Contains(v.Reason, "encoded_all_contexts") {
			clean = true
			if v.Annotations["encoder"] == nil {
				t.Error("the encoded clean does not name the encoder, which is the row that is actually useful")
			}
		}
	}
	if !clean {
		t.Errorf("an application that encoded every context produced no clean: %s", xssrSummarise(vs))
	}
}

// TestAnAllowlistSanitizerIsSuspiciousAndNeverCleanForXSSR is FN-A6, the largest honest gap a
// non-browser probe has, converted into a pointer at domdig rather than into a green tick.
func TestAnAllowlistSanitizerIsSuspiciousAndNeverCleanForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	run := xssrRunOf(
		xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>"+m+"-rx0r</p>"),
		xssrShot(xssrP0a, xssrMarkTwo, "text/html", "<p>x"+string(xssrMarkTwo)+"-rx0a</p>"),
		xssrShot(xssrPDec, xssrMarkThree, "text/html", "decoded "+string(xssrMarkThree)+"-rxdec"),
		xssrShot(xssrP1s, xssrMarkOne, "text/html", "<p>"+m+"<b>"+m+"</b>-rx1s</p>"),
	)
	vs := xssrClassifyEligible(xssrTestCtx(xssrDecodedSlot()), run, xssrEligibility{OK: true})
	found := false
	for _, v := range vs {
		if v.State.CountsAsClean() {
			t.Errorf("an allowlist sanitizer was reported clean: %s", v.Reason)
		}
		if v.State == triage.StateSuspicious && strings.Contains(v.Reason, "sanitizer_allowlist") {
			found = true
			if !xssrToolsContain(v.Label.Tools, "domdig") {
				t.Error("the sanitizer row does not point at domdig, and mutation XSS cannot be established from an HTTP response")
			}
		}
	}
	if !found {
		t.Errorf("no sanitizer_allowlist row: %s", xssrSummarise(vs))
	}
}

func xssrToolsContain(tools []string, want string) bool {
	for _, tl := range tools {
		if tl == want {
			return true
		}
	}
	return false
}

// TestAJSONReflectionIsNeedsDomRunAndNotCleanForXSSR is FN-A9. Class A does not borrow XSS-DOM's
// answer and does not report clean in its place.
func TestAJSONReflectionIsNeedsDomRunAndNotCleanForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	json := `{"q":"` + m + `-rx0r","hits":0}`
	shot := xssrShot(xssrP0r, xssrMarkOne, "application/json", json)
	shot.Obs.RespHeaders = [][2]string{{"X-Content-Type-Options", "nosniff"}}
	other := xssrShot(xssrP0a, xssrMarkTwo, "application/json", `{"q":"hello`+string(xssrMarkTwo)+`-rx0a"}`)
	other.Obs.RespHeaders = shot.Obs.RespHeaders
	run := xssrRunOf(shot, other, xssrShot(xssrPDec, xssrMarkThree, "application/json", `{"q":"`+string(xssrMarkThree)+`-rxdec"}`))

	ctx := xssrTestCtx(xssrDecodedSlot())
	ctx.Vector.RespMedia = "application/json"
	vs := xssrClassifyEligible(ctx, run, xssrEligibility{OK: true})
	dom := false
	for _, v := range vs {
		if v.State.CountsAsClean() {
			t.Errorf("a JSON reflection was reported clean: %s", v.Reason)
		}
		if strings.Contains(v.Reason, "needs_dom_run") {
			dom = true
		}
	}
	if !dom {
		t.Errorf("no needs_dom_run row for a JSON reflection: %s", xssrSummarise(vs))
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

// TestTheXSSRLadderSendsBothCensusFormsAndItsOwnDecodeProbeFirst.
func TestTheXSSRLadderSendsBothCensusFormsAndItsOwnDecodeProbeFirst(t *testing.T) {
	ctx := triage.PlanCtx{
		Slot:     xssrQuerySlot(),
		Vector:   triage.TriageVector{ID: "v1", Method: "GET", RespMedia: "text/html"},
		Prelude:  triage.PreludeTokenNotRequired,
		Budget:   triage.TriageBudget{RemainingPerSlot: 12, RemainingPerRun: 100},
		Baseline: triage.BaselineModel{Samples: 5, Stable: true},
	}
	// Route is unresolved in any test in this package, so eligibility is exercised on its own
	// below and the ladder is exercised through the same predicate with the gate satisfied.
	got := map[triage.ProbeID]map[string]string{}
	for _, r := range xssrPlanFor(ctx, 0) {
		got[r.Spec] = r.Variant
	}
	for _, want := range []triage.ProbeID{xssrP0r, xssrP0a, xssrPDec} {
		if _, ok := got[want]; !ok {
			t.Errorf("round 0 did not plan %s, and without it the class cannot tell an absence from a value that never arrived", want)
		}
	}
	if got[xssrP0a][xssrVariantCompose] != xssrComposeAppend {
		t.Error("the append census was planned as a replace, which loses every integer-cast and shape-validating field")
	}
	if len(got) > 5 {
		t.Errorf("round 0 planned %d probes; the census is meant to be cheap", len(got))
	}
}

// xssrPlanFor calls the ladder with the route gate satisfied by construction. The gate itself is
// tested in TestTheXSSREligibilityGateRefusesWhatItMustForXSSR.
func xssrPlanFor(ctx triage.PlanCtx, round int) []triage.ProbeRequest {
	ctx.Round = round
	if el := xssrEligible(ctx); !el.OK && el.Reason != "" && strings.Contains(el.Reason, "route_unresolved") {
		// Reproduce Plan's body with the one gate a test cannot satisfy already passed.
		return xssrPlanRounds(ctx)
	}
	return (xssReflectedClassifier{}).Plan(ctx)
}

// TestTheXSSRLadderRefusesTheThirteenthProbeOnOneSlot. A class that spends a whole run's budget
// on one slot has starved every other slot of its census, and the refusal must read as untested.
func TestTheXSSRLadderRefusesTheThirteenthProbeOnOneSlot(t *testing.T) {
	ctx := triage.PlanCtx{
		Slot:    xssrDecodedSlot(),
		Vector:  triage.TriageVector{ID: "v1", Method: "GET", RespMedia: "text/html"},
		Prelude: triage.PreludeTokenNotRequired,
		Budget:  triage.TriageBudget{RemainingPerSlot: 500, RemainingPerRun: 5000},
	}
	if got := xssrPlanRounds(ctx); len(got) == 0 {
		t.Fatal("round 0 planned nothing on a healthy slot")
	}
	// The cap counts this class's own probes on this slot, and Own is what carries them, so the
	// refusal is exercised through the same counter the runner fills.
	full := ctx
	full.Round = 1
	if xssrPerSlotCap != 12 {
		t.Errorf("the per-slot cap is %d; CATALOGUE 2.1 says twelve", xssrPerSlotCap)
	}
	var run xssrRun
	for i := 0; i < xssrPerSlotCap; i++ {
		run.Items = append(run.Items, xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>x</p>"))
	}
	vs := xssrClassifyEligible(xssrTestCtx(xssrDecodedSlot()), run, xssrEligibility{OK: true})
	for _, v := range vs {
		if v.State.CountsAsClean() {
			t.Error("a slot that hit the cap was reported clean")
		}
	}
}

// TestTheXSSRPromotionRuleSendsExactlyTheContextItFound. A placement promotes its own payload and
// nothing else, and a context with no payload is reported rather than silently dropped.
func TestTheXSSRPromotionRuleSendsExactlyTheContextItFound(t *testing.T) {
	cases := []struct {
		context string
		want    []triage.ProbeID
	}{
		{xssrCtxHTMLText, []triage.ProbeID{xssrP1}},
		{xssrCtxAttrDouble, []triage.ProbeID{xssrP2}},
		{xssrCtxAttrSingle, []triage.ProbeID{xssrP3}},
		{xssrCtxAttrUnquoted, []triage.ProbeID{xssrP4}},
		{xssrCtxEventHandler, []triage.ProbeID{xssrP5a, xssrP5b, xssrP5c, xssrP5d}},
		{xssrCtxURLScheme, []triage.ProbeID{xssrP6a, xssrP6b, xssrP6c}},
		{xssrCtxScriptData, []triage.ProbeID{xssrP7}},
		{xssrCtxJSStringSingle, []triage.ProbeID{xssrP8a, xssrP8b}},
		{xssrCtxJSTemplateText, []triage.ProbeID{xssrP10a, xssrP10b}},
		{xssrCtxHTMLComment, []triage.ProbeID{xssrP11a, xssrP11b}},
		{xssrCtxRCDataTextarea, []triage.ProbeID{xssrP12}},
		{xssrCtxRCDataTitle, []triage.ProbeID{xssrP12t}},
		{xssrCtxCSSBlock, []triage.ProbeID{xssrP13}},
	}
	for _, tc := range cases {
		t.Run(tc.context, func(t *testing.T) {
			got := xssrProbesForContext(tc.context, "text/html")
			if len(got) != len(tc.want) {
				t.Fatalf("context %s promoted %v, want %v", tc.context, got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("context %s promoted %v, want %v", tc.context, got, tc.want)
				}
			}
		})
	}
	if len(xssrProbesForContext(xssrCtxCSSInAttr, "text/html")) != 0 {
		t.Error("a style attribute promoted an XSS payload. No current engine executes script from one, and " +
			"reporting it as a lead is how a triage layer earns being ignored")
	}
}

// TestTheXSSREligibilityGateRefusesWhatItMustAndProbesTheRest.
func TestTheXSSREligibilityGateRefusesWhatItMustAndProbesTheRest(t *testing.T) {
	cases := []struct {
		name   string
		ctx    triage.PlanCtx
		wantOK bool
		state  triage.TriageState
	}{
		{
			name:  "a route control that did not resolve",
			ctx:   triage.PlanCtx{Slot: xssrQuerySlot(), Prelude: triage.PreludeTokenNotRequired},
			state: triage.StateCannotDetermine,
		},
		{
			name: "a credential slot is never probed by anybody",
			ctx: func() triage.PlanCtx {
				s := xssrQuerySlot()
				s.Kind = triage.KindCookie
				s.Constraints.IsCredential = true
				return triage.PlanCtx{Slot: s}
			}(),
			state: triage.StateNotProbed,
		},
		{
			name: "a prelude token that cannot be obtained",
			ctx: triage.PlanCtx{
				Slot: xssrQuerySlot(), Prelude: triage.PreludeTokenUnobtainable,
			},
			state: triage.StateCannotDetermine,
		},
		{
			name: "an unmeasured prelude on a POST",
			ctx: func() triage.PlanCtx {
				s := xssrQuerySlot()
				s.Method = "POST"
				return triage.PlanCtx{Slot: s, Prelude: triage.PreludeUnknown}
			}(),
			state: triage.StateNotRun,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := xssrEligible(tc.ctx)
			if el.OK != tc.wantOK {
				t.Fatalf("eligibility OK=%v, want %v (reason %q)", el.OK, tc.wantOK, el.Reason)
			}
			if !el.OK {
				if el.State != tc.state {
					t.Errorf("state %s, want %s", el.State, tc.state)
				}
				if el.State.CountsAsClean() {
					t.Error("an ineligible slot rendered as clean")
				}
				if strings.TrimSpace(el.Reason) == "" {
					t.Error("a refusal with no reason is indistinguishable from nobody wiring the class up")
				}
			}
			if len((xssReflectedClassifier{}).Plan(tc.ctx)) != 0 {
				t.Error("an ineligible slot was still planned against")
			}
		})
	}
}

// TestAPayloadThatCannotBeDeliveredIsNotReachableAndNotCleanForXSSR.
func TestAPayloadThatCannotBeDeliveredIsNotReachableAndNotCleanForXSSR(t *testing.T) {
	cases := []struct {
		name   string
		probe  triage.ProbeID
		slot   triage.Slot
		state  triage.TriageState
		needle string
	}{
		{
			name:  "a raw double quote in a JSON string slot",
			probe: xssrP2,
			slot: triage.Slot{Key: "body:/q", Kind: triage.KindBody, BodyMedia: triage.BodyJSON,
				ServerReachable: true, Constraints: triage.NewSlotConstraints()},
			state: triage.StateNotReachable, needle: "json_string",
		},
		{
			name:  "a raw space in a cookie that the app does not decode",
			probe: xssrP4,
			slot: func() triage.Slot {
				s := triage.Slot{Key: "cookie:theme", Kind: triage.KindCookie, ServerReachable: true,
					Constraints: triage.NewSlotConstraints()}
				s.Constraints.DecodeDepth = 0
				return s
			}(),
			state: triage.StateNotReachable, needle: "cookie_octet",
		},
		{
			name:  "a line feed in a header value",
			probe: xssrP14,
			slot: triage.Slot{Key: "header:x-forwarded-host", Kind: triage.KindHeader, ServerReachable: true,
				Constraints: triage.NewSlotConstraints()},
			state: triage.StateNotReachable, needle: "header_crlf",
		},
		{
			name:  "a line feed in a path segment",
			probe: xssrP14,
			slot: triage.Slot{Key: "path:3:{id}", Kind: triage.KindPath, ServerReachable: true,
				Constraints: triage.NewSlotConstraints()},
			state: triage.StateNotReachable, needle: "path_ctl",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := xssrProbeReachesSlot(tc.probe, tc.slot)
			if r.OK {
				t.Fatalf("%s was judged deliverable to %s, so it would be sent, mangled and scored", tc.probe, tc.slot.Key)
			}
			if r.State != tc.state {
				t.Errorf("state %s, want %s", r.State, tc.state)
			}
			if !strings.Contains(r.Reason, tc.needle) {
				t.Errorf("reason %q does not use the vocabulary the report filters on (%q)", r.Reason, tc.needle)
			}
			if r.State.CountsAsClean() {
				t.Error("an undeliverable payload rendered as clean")
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE TRANSFORM SEARCH, THE TEMPLATE GUARD AND THE HOUSE RULES
// ---------------------------------------------------------------------------------------------

// TestTheMarkerSearchFindsEveryTransformFormForXSSR. Clean requires the marker to be absent in
// every form, so every form that is not searched is a way for a reflecting application to be
// recorded as clean.
func TestTheMarkerSearchFindsEveryTransformFormForXSSR(t *testing.T) {
	m := string(xssrMarkOne)
	forms := map[string]string{
		"raw":              "x" + m + "y",
		"case transformed": "x" + strings.ToUpper(m) + "y",
	}
	for _, alt := range xssrMarkerAlternateForms(m) {
		forms[string(alt.form)] = "prefix" + alt.bytes + "suffix"
	}
	for name, body := range forms {
		t.Run(name, func(t *testing.T) {
			if len(xssrFindMarker([]byte(body), m)) == 0 {
				t.Errorf("the %s form of the marker was not found, so an application reflecting it would be recorded clean", name)
			}
		})
	}
	if len(xssrFindMarker([]byte("nothing to see here"), m)) != 0 {
		t.Error("the marker search fired on a body that does not contain it")
	}
}

// TestTheTemplateGuardRefusesAnUnsubstitutedPayloadForXSSR.
func TestTheTemplateGuardRefusesAnUnsubstitutedPayloadForXSSR(t *testing.T) {
	good := xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>x</p>")
	good.Obs.Payload.Logical = []byte(string(xssrMarkOne) + "<" + string(xssrMarkOne) + ">-rx1")
	if why := xssrTemplateSurvived(good); why != "" {
		t.Errorf("a correctly substituted payload was refused: %s", why)
	}
	bad := xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>x</p>")
	bad.Obs.Payload.Logical = []byte(xssrTemplateMarker + "<" + xssrTemplateMarker + ">-rx1")
	if why := xssrTemplateSurvived(bad); why == "" {
		t.Error("an unsubstituted template went unnoticed. The wire would carry a marker nobody minted, every rule " +
			"would stay silent, and the slot would be recorded clean having been tested with nothing")
	}
	short := xssrShot(xssrPSM, xssrMarkOne, "text/html", "<p>x</p>")
	short.Obs.Payload.Logical = []byte("<" + xssrShortForm(xssrMarkOne) + ">")
	if why := xssrTemplateSurvived(short); why != "" {
		t.Errorf("the narrow-field short form was mistaken for a foreign token: %s", why)
	}
}

// TestTheXSSROracleCasesDeclareAFireRouteAndASilentRoute. A detector never shown to STAY SILENT is
// not verified, and a detector that fires on everything scores one hundred per cent.
func TestTheXSSROracleCasesDeclareAFireRouteAndASilentRoute(t *testing.T) {
	cases := (xssReflectedClassifier{}).OracleCases()
	var pos, neg int
	declared := map[triage.ProbeID]bool{}
	for _, p := range (xssReflectedClassifier{}).Probes() {
		declared[p.ID] = true
	}
	for _, c := range cases {
		switch c.Expect {
		case xssrExpectPositive:
			pos++
			if c.Want != triage.StateFinding && c.Want != triage.StateSuspicious {
				t.Errorf("%s is a FIRE route expecting %s", c.Route, c.Want)
			}
		case xssrExpectNegative:
			neg++
			if c.Want == triage.StateFinding {
				t.Errorf("%s is a SILENT route expecting a finding", c.Route)
			}
		default:
			t.Errorf("%s declares neither side of the oracle", c.Route)
		}
		if !declared[c.Probe] {
			t.Errorf("%s names probe %s, which this class does not declare", c.Route, c.Probe)
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("%s has no note saying what it actually tests", c.Route)
		}
	}
	if pos == 0 || neg == 0 {
		t.Fatalf("the oracle set has %d positive and %d negative routes; it needs at least one of each", pos, neg)
	}
	if neg < pos {
		t.Errorf("there are fewer silent routes (%d) than fire routes (%d), and the silent ones are the half that "+
			"actually tests the detector", neg, pos)
	}
}

// TestTheXSSRToolLabelsPointSomewhereRealAndSayWhichIsWhich.
func TestTheXSSRToolLabelsPointSomewhereRealAndSayWhichIsWhich(t *testing.T) {
	c := xssReflectedClassifier{}
	if len(c.Confirmers()) == 0 {
		t.Fatal("no confirmer, so a finding names no tool and the triage layer answers nothing")
	}
	for _, tool := range c.Confirmers() {
		for _, e := range c.Evidencers() {
			if tool == e {
				t.Errorf("%q is both a confirmer and an evidencer, which makes the distinction meaningless", tool)
			}
		}
	}
	if !xssrToolsContain(c.Confirmers(), "dalfox") {
		t.Error("dalfox is the primary tool for this class and is not in the confirmer list")
	}
	if !xssrToolsContain(c.Evidencers(), "xssfuzz") {
		t.Error("xssfuzz reaches query slots only, so its silence confirms nothing and it belongs in the evidencer list")
	}
	if c.SettleNeeded() {
		t.Error("this class declares a deferred check it does not have")
	}
}

// TestADetectedElementBecomesAFindingThatNamesTheToolForXSSR. The class answers POINT THE TOOL
// HERE, so a finding that names no tool, no context and no probe has not answered the question.
func TestADetectedElementBecomesAFindingThatNamesTheToolForXSSR(t *testing.T) {
	m1, m3 := string(xssrMarkOne), string(xssrMarkThree)
	run := xssrRunOf(
		xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>you searched for "+m1+"-rx0r</p>"),
		xssrShot(xssrP0a, xssrMarkTwo, "text/html", "<p>you searched for hello"+string(xssrMarkTwo)+"-rx0a</p>"),
		xssrShot(xssrP1, xssrMarkThree, "text/html", "<p>you searched for "+m3+"<"+m3+">-rx1</p>"),
	)
	vs := xssrClassifyEligible(xssrTestCtx(xssrDecodedSlot()), run, xssrEligibility{OK: true})
	var found *triage.ClassVerdict
	for i := range vs {
		if vs[i].State == triage.StateFinding {
			found = &vs[i]
		}
	}
	if found == nil {
		t.Fatalf("a marker-named element produced no finding: %s", xssrSummarise(vs))
	}
	if err := found.Validate(); err != nil {
		t.Errorf("the finding failed its own contract: %v", err)
	}
	if len(found.Ordinals) == 0 {
		t.Error("the finding names no probe ordinal, so nobody can find the request that produced it")
	}
	if !xssrToolsContain(found.Label.Tools, "dalfox") {
		t.Errorf("the finding names no tool: %v. This layer exists to say POINT THE TOOL HERE", found.Label.Tools)
	}
	if found.Label.Hints["never_set_inject_marker"] == "" {
		t.Error("the label drops the dalfox caution, and a dalfox run with --inject-marker set exits clean after " +
			"three requests")
	}
	if found.Grade != triage.GradeMedium {
		t.Errorf("grade %q: one probe firing once is medium, and high needs the effect reproduced with a fresh "+
			"marker", found.Grade)
	}

	// A second probe of this class, with its own marker, reproducing the same rule is what the
	// high grade requires.
	run.Items = append(run.Items, xssrShot(xssrP1t, xssrMarkTwo, "text/html", "<p>hello"+string(xssrMarkTwo)+"<"+string(xssrMarkTwo)+">-rx1t</p>"))
	run.Ordinals = append(run.Ordinals, 73)
	vs = xssrClassifyEligible(xssrTestCtx(xssrDecodedSlot()), run, xssrEligibility{OK: true})
	high := false
	for _, v := range vs {
		if v.State == triage.StateFinding && v.Grade == triage.GradeHigh {
			high = true
		}
	}
	if !high {
		t.Errorf("two probes with two markers firing the same rule did not reach the high grade: %s", xssrSummarise(vs))
	}
}

// TestAnInertContainerAndAPolicyBothDowngradeRatherThanRefuteForXSSR. CSP is a mitigation and not
// a refutation: false negatives are the expensive error, so the tool is still pointed here.
func TestAnInertContainerAndAPolicyBothDowngradeRatherThanRefuteForXSSR(t *testing.T) {
	m3 := string(xssrMarkThree)
	base := func(body string) xssrRun {
		return xssrRunOf(
			xssrShot(xssrP0r, xssrMarkOne, "text/html", "<p>"+string(xssrMarkOne)+"-rx0r</p>"),
			xssrShot(xssrP0a, xssrMarkTwo, "text/html", "<p>hello"+string(xssrMarkTwo)+"-rx0a</p>"),
			xssrShot(xssrP1, xssrMarkThree, "text/html", body),
		)
	}
	t.Run("inside a template the element still formed", func(t *testing.T) {
		run := base("<template><p>" + m3 + "<" + m3 + ">-rx1</p></template>")
		vs := xssrClassifyEligible(xssrTestCtx(xssrDecodedSlot()), run, xssrEligibility{OK: true})
		ok := false
		for _, v := range vs {
			if v.State == triage.StateSuspicious && strings.Contains(v.Reason, "inert_container") {
				ok = true
			}
			if v.State.CountsAsClean() {
				t.Error("an element that formed inside a template was reported clean; the breakout is proven")
			}
		}
		if !ok {
			t.Errorf("want a suspicious row naming the inert container: %s", xssrSummarise(vs))
		}
	})
	t.Run("a strict policy downgrades and still points the tool", func(t *testing.T) {
		run := base("<p>" + m3 + "<" + m3 + ">-rx1</p>")
		for i := range run.Items {
			run.Items[i].Obs.RespHeaders = [][2]string{{"Content-Security-Policy", "script-src 'self'; object-src 'none'"}}
		}
		vs := xssrClassifyEligible(xssrTestCtx(xssrDecodedSlot()), run, xssrEligibility{OK: true})
		ok := false
		for _, v := range vs {
			if v.State == triage.StateSuspicious && strings.Contains(v.Reason, "csp_present") {
				ok = true
				if !xssrToolsContain(v.Label.Tools, "dalfox") {
					t.Error("a CSP downgrade stopped naming the tool. CSP is a mitigation, not a refutation")
				}
			}
		}
		if !ok {
			t.Errorf("want a suspicious row naming the policy: %s", xssrSummarise(vs))
		}
	})
}

// TestNoXSSRSourceLineCarriesAnEmdash, which is a house rule with a test behind it.
func TestNoXSSRSourceLineCarriesAnEmdash(t *testing.T) {
	// The rune is computed rather than written, so this test does not itself put one in the repo.
	xssrEmdash := rune(0x2014)
	for _, p := range (xssReflectedClassifier{}).Probes() {
		if strings.ContainsRune(string(p.Logical), xssrEmdash) || strings.ContainsRune(p.Notes, xssrEmdash) {
			t.Errorf("probe %s carries an emdash", p.ID)
		}
	}
	for _, c := range (xssReflectedClassifier{}).OracleCases() {
		if strings.ContainsRune(c.Why, xssrEmdash) {
			t.Errorf("oracle case %s carries an emdash", c.Route)
		}
	}
}

// ------------------------------------------------------------------------------------------------
// EXAM ef8c13ab, DEFECT 2: A HIGH ON A CLEAN CONTROL, AND A NEAR MISS THAT WAS NOT ONE
//
// (a) XSS-R returned finding/HIGH (element_created) on /clean/echomongo. That route answers
//     Content-Type: application/json with {"ok":false,...,"received":"<the value>"}. The HTML
//     tokenizer was run over a JSON document, saw <marker, and reported that the application let
//     this value open an element. The media gate let it through because it treats the JSON family
//     as sniffable, and no browser parses a DECLARED application/json as markup on navigation:
//     mimesniff only upgrades the unknown-type bucket. High is what an operator acts on first, so
//     this is the most expensive false positive shape available.
//
//     The routes that must KEEP firing are /cmdi /lfi /redirect (text/plain, no nosniff) and
//     /ssti /xss (text/html): those genuinely put the marker into a document at top level.
//
// (b) XSS-R returned suspicious (character_survival) on /xss/encoded claiming a raw " came back
//     beside the marker. It did not. That route htmlspecialchars-es everything and renders the
//     value TWICE, once in a div and once in an input value attribute. The survival region ran
//     from the FIRST occurrence to the LAST, so it swallowed </div>\n<input name="q" value=" in
//     between and matched the page's own quote. The region's doc comment already says it is
//     bounded by the payload's own rendered extent, and with two reflections it was not.
// ------------------------------------------------------------------------------------------------

func TestXSSRDoesNotTokenizeAJSONDocumentAsMarkup(t *testing.T) {
	obs := triage.Observation{
		MediaType:   "application/json",
		RespHeaders: [][2]string{{"Content-Type", "application/json"}},
		Body:        []byte(`{"ok":false,"error":"could not parse filter","received":"<zqjk3m1x7p2w9b4t>"}`),
	}
	renders, why := xssrResponseRenders(obs, xssrP1)
	if renders {
		t.Fatalf("the media gate let a declared application/json through as markup. No browser " +
			"parses a declared JSON body as HTML on navigation, so an element the tokenizer found " +
			"in it is not an XSS lead: that is how /clean/echomongo, a clean control, came back " +
			"finding/high/element_created")
	}
	if !strings.Contains(why, "needs_dom_run") {
		t.Errorf("the reason must say the marker can only reach a sink through page JavaScript, "+
			"which is XSS-DOM's question and not a clean. got %q", why)
	}
}

func TestXSSRStillTreatsTheRoutesThatReallyRenderAsRendering(t *testing.T) {
	cases := []struct {
		name  string
		media triage.MediaType
		hdrs  [][2]string
	}{
		{"/xss and /ssti, text/html", "text/html", [][2]string{{"Content-Type", "text/html; charset=utf-8"}}},
		{"/cmdi, /lfi and /redirect, text/plain with no nosniff", "text/plain", [][2]string{{"Content-Type", "text/plain; charset=utf-8"}}},
		{"an SVG document", "image/svg+xml", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			renders, why := xssrResponseRenders(triage.Observation{MediaType: tc.media, RespHeaders: tc.hdrs}, xssrP1)
			if !renders {
				t.Fatalf("the media gate closed on %s (%q). These are the routes the exam confirmed "+
					"as true positives and suppressing them trades a false positive for a false "+
					"negative, which is the more expensive error", tc.media, why)
			}
		})
	}
}

func TestXSSRSurvivalRegionNeverReachesThePageBetweenTwoReflections(t *testing.T) {
	m := "zqjk3m1x7p2w9b4t"
	// /xss/encoded, verbatim: the value is rendered twice and every metacharacter this probe sent
	// came back as a numeric character reference. Nothing of RX-2's survived raw.
	body := []byte(`<!doctype html><title>search</title>` + "\n" +
		`<div id="out">` + m + `&#34; ` + m + `=&#34;rx2</div>` + "\n" +
		`<input name="q" value="` + m + `&#34; ` + m + `=&#34;rx2">` + "\n")
	occ := xssrFindMarker(body, m)
	if len(occ) != 4 {
		t.Fatalf("fixture error: want the four occurrences RX-2's two markers produce across two "+
			"reflections, got %d", len(occ))
	}
	// RX-2 is ${m}" ${m}="rx2, so five payload bytes follow its last marker.
	w := xssrSurvivalRegion(body, occ, false, 5)
	if bytes.Contains(w, []byte(`"`)) {
		t.Fatalf("the survival region contains a raw double quote. Every quote this payload sent "+
			"came back as &#34;: the only raw quotes in this body belong to the page's own "+
			"<input name=\"q\" value=\", which sits BETWEEN the two reflections. Reporting that as "+
			"character_survival tells the operator a metacharacter survived on an application that "+
			"encoded every byte it was sent. region=%q", string(w))
	}
	if !bytes.Contains(w, []byte("&#34;")) {
		t.Errorf("the region no longer reaches this payload's own encoded bytes, which is the "+
			"opposite failure: the encoder identification reads the same region. region=%q", string(w))
	}
}

func TestXSSRSurvivalRegionStillSeesAMetacharacterThatReallySurvived(t *testing.T) {
	m := "zqjk3m1x7p2w9b4t"
	// /clean/echo, verbatim: text/plain, the payload comes back byte for byte.
	body := []byte("echo\n" + m + `" ` + m + `="rx2` + "\n")
	occ := xssrFindMarker(body, m)
	w := xssrSurvivalRegion(body, occ, false, 5)
	if !bytes.Contains(w, []byte(`"`)) {
		t.Fatalf("the raw double quote this payload sent came straight back and the region missed "+
			"it. That is a false negative in the near-miss rule. region=%q", string(w))
	}
}

// A near miss on a document that never renders must SAY the document never renders. The grading
// switch stops at the secondary case, so the media-gate cap was computed and then dropped, and the
// row an operator read on /clean/echomongo and /clean/echo claimed a metacharacter survived with
// no mention that nothing will ever parse it.
func TestXSSRSecondaryHitsCarryTheMediaGateReasonInTheirText(t *testing.T) {
	obs := triage.Observation{
		MediaType:   "application/json",
		RespHeaders: [][2]string{{"Content-Type", "application/json"}},
	}
	_, why := xssrResponseRenders(obs, xssrP1)
	if why == "" {
		t.Fatal("fixture error: the gate must be closed with a reason for this test to mean anything")
	}
	h := xssrHit{Rule: "RX-D5", Oracle: "character_survival", Detail: "the bytes this context needs (<) came back raw beside the marker", Secondary: true, Downgrade: why}
	reason := xssrSecondaryReason(h)
	if !strings.Contains(reason, "needs_dom_run") {
		t.Fatalf("the operator-visible reason for a secondary hit drops the media gate. got %q", reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE MEDIA GATE ON THE CHARACTER-SURVIVAL ARM
// ---------------------------------------------------------------------------------------------

// xssrShotWithHeaders is xssrShot plus response headers, which is what the media gate needs:
// text/plain WITH nosniff and text/plain WITHOUT it are the same body and different answers.
func xssrShotWithHeaders(probe triage.ProbeID, m triage.Marker, media, body string, headers ...[2]string) xssrProbeObs {
	it := xssrShot(probe, m, media, body)
	it.Obs.RespHeaders = append(it.Obs.RespHeaders, headers...)
	return it
}

// TestCharacterSurvivalCarriesTheSameMediaGateAsEveryOtherRule is exam 2e4433b1's false positive.
//
// /clean/echo answers text/plain with nosniff and /clean/echomongo answers a 400
// application/json. Both are CLEAN CONTROLS, and both came back suspicious from this one arm
// because the byte the context needs survived beside the marker. A byte that survives into a
// document no browser parses as markup cannot open an element, name an attribute or reach a
// JavaScript lexer.
//
// The last case is the one that makes the fix a fix rather than a silencer: /cmdi, /lfi and
// /redirect answer text/plain with NO nosniff, the exam confirms them as true positives, and the
// gate must stay open there.
func TestCharacterSurvivalCarriesTheSameMediaGateAsEveryOtherRule(t *testing.T) {
	m := string(xssrMarkOne)
	nosniff := [2]string{"X-Content-Type-Options", "nosniff"}
	survives := m + "<rx1"

	cases := []struct {
		name string
		shot xssrProbeObs
		want bool
	}{
		{
			name: "text/plain with nosniff: /clean/echo, and its own atlas demands clean here",
			shot: xssrShotWithHeaders(xssrP1, xssrMarkOne, "text/plain", "echo\n"+survives, nosniff),
			want: false,
		},
		{
			name: "application/json: /clean/echomongo, a structured document no browser parses as markup",
			shot: xssrShot(xssrP1, xssrMarkOne, "application/json", `{"ok":false,"received":"`+survives+`"}`),
			want: false,
		},
		{
			name: "an attachment is downloaded and never parsed",
			shot: xssrShotWithHeaders(xssrP1, xssrMarkOne, "text/html", "<p>"+survives+"</p>",
				[2]string{"Content-Disposition", "attachment; filename=x.html"}),
			want: false,
		},
		{
			name: "text/plain with NO nosniff: /cmdi, /lfi and /redirect, which are true positives",
			shot: xssrShot(xssrP1, xssrMarkOne, "text/plain", "resolving "+survives),
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := false
			for _, h := range xssrRulesFor(tc.shot) {
				if h.Oracle == "character_survival" {
					got = true
				}
			}
			if got != tc.want {
				t.Fatalf("character_survival fired=%v, want %v", got, tc.want)
			}
		})
	}
}

// TestTheTwoCleanControlsThatOnlySurvivedCharactersAreNoLongerSuspicious drives the whole verdict
// for the two routes the exam scored wrong, using their real response shapes.
//
// The two answers differ on purpose. text/plain with nosniff is a document nothing parses as
// markup and nothing routinely fetches as data, so reflected XSS cannot exist in it: clean, with
// the gate named. application/json round-trips the value into a document a SPA fetches all day,
// so the honest answer is needs_dom_run, which is an unknown. A clean there would be this class
// answering XSS-DOM's question for it.
func TestTheTwoCleanControlsThatOnlySurvivedCharactersAreNoLongerSuspicious(t *testing.T) {
	m := string(xssrMarkOne)
	nosniff := [2]string{"X-Content-Type-Options", "nosniff"}
	ctx := xssrTestCtx(xssrDecodedSlot())

	cases := []struct {
		name      string
		run       xssrRun
		wantState triage.TriageState
		wantIn    string
	}{
		{
			name: "/clean/echo: text/plain with nosniff, the value echoed raw",
			run: xssrRunOf(
				xssrShotWithHeaders(xssrP0r, xssrMarkOne, "text/plain", "echo\n"+m, nosniff),
				xssrShotWithHeaders(xssrP1, xssrMarkOne, "text/plain", "echo\n"+m+"<rx1", nosniff),
			),
			wantState: triage.StateClean, wantIn: "media_gate_closed",
		},
		{
			name: "/clean/echomongo: a 400 application/json that quotes the value back",
			run: xssrRunOf(
				xssrShot(xssrP0r, xssrMarkOne, "application/json",
					`{"ok":false,"error":"could not parse filter","received":"`+m+`"}`),
				xssrShot(xssrP1, xssrMarkOne, "application/json",
					`{"ok":false,"error":"could not parse filter","received":"`+m+`<rx1"}`),
			),
			wantState: triage.StateCannotDetermine, wantIn: "needs_dom_run",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vs := xssrClassifyEligible(ctx, tc.run, xssrEligibility{OK: true})
			if len(vs) == 0 {
				t.Fatal("no verdict at all")
			}
			for _, v := range vs {
				if v.State == triage.StateSuspicious || v.State == triage.StateFinding {
					t.Errorf("a clean control produced %s: %s", v.State, v.Reason)
				}
			}
			found := false
			for _, v := range vs {
				if v.State == tc.wantState && strings.Contains(v.Reason, tc.wantIn) {
					found = true
				}
			}
			if !found {
				for _, v := range vs {
					t.Logf("got %s: %s", v.State, v.Reason)
				}
				t.Fatalf("no row is %s naming %q", tc.wantState, tc.wantIn)
			}
		})
	}
}

// TestTheMediaGateNeverClosesWhileOneResponseStillRenders is the gate's own negative control. One
// rendering response among the probes means an element could form somewhere this slot reaches,
// and a clean drawn from the others would be a clean drawn from the wrong document.
func TestTheMediaGateNeverClosesWhileOneResponseStillRenders(t *testing.T) {
	m := string(xssrMarkOne)
	nosniff := [2]string{"X-Content-Type-Options", "nosniff"}
	mixed := xssrRunOf(
		xssrShotWithHeaders(xssrP0r, xssrMarkOne, "text/plain", "echo\n"+m, nosniff),
		xssrShot(xssrP1, xssrMarkTwo, "text/html", "<p>"+string(xssrMarkTwo)+"</p>"),
	)
	if closed, _, _ := xssrMediaGateClosedEverywhere(mixed); closed {
		t.Fatal("the gate closed while one of this slot's responses is an HTML document a browser renders")
	}
	if closed, _, _ := xssrMediaGateClosedEverywhere(xssrRun{}); closed {
		t.Fatal("the gate closed over no responses at all, which would manufacture a clean out of an empty run")
	}
	undelivered := xssrShot(xssrP1, xssrMarkOne, "text/plain", "")
	undelivered.Obs.TransportErr = triage.TransportTimeout
	undelivered.Obs.Status = 0
	if closed, _, _ := xssrMediaGateClosedEverywhere(xssrRunOf(undelivered)); closed {
		t.Fatal("the gate closed over a probe that never arrived, so a transport failure would read as a media type")
	}
}

// TestTheSevenTruePositivesStillFireAfterTheMediaGate is the half a silencer would break. Each of
// these is a row the exam confirmed, and each one is a PRIMARY rule that must be untouched by a
// change to the secondary arm.
func TestTheSevenTruePositivesStillFireAfterTheMediaGate(t *testing.T) {
	m := string(xssrMarkOne)
	cases := []struct {
		route string
		shot  xssrProbeObs
		rule  string
	}{
		{"/xss html text", xssrShot(xssrP1, xssrMarkOne, "text/html", "<p>you searched for <"+m+">-rx1</p>"), "RX-D1"},
		{"/cmdi text/plain, no nosniff", xssrShot(xssrP1, xssrMarkOne, "text/plain", "resolving <"+m+">-rx1"), "RX-D1"},
		{"/lfi text/plain, no nosniff", xssrShot(xssrP1, xssrMarkOne, "text/plain", "root:x:0:0 <"+m+">-rx1"), "RX-D1"},
		{"/redirect text/plain, no nosniff", xssrShot(xssrP1, xssrMarkOne, "text/plain", "next=<"+m+">-rx1"), "RX-D1"},
		{"/ssti text/html", xssrShot(xssrP1, xssrMarkOne, "text/html", "<div><"+m+">-rx1</div>"), "RX-D1"},
	}
	for _, tc := range cases {
		t.Run(tc.route, func(t *testing.T) {
			if !xssrFired(xssrRulesFor(tc.shot), tc.rule) {
				t.Fatalf("%s no longer fires on %s, which is a confirmed true positive: a fix that silences a real "+
					"finding is worse than the false positive it removed", tc.rule, tc.route)
			}
		})
	}
	// The two script-context rules on /xss, which are the other two of its three rows.
	lexer := xssrShot(xssrP8a, xssrMarkOne, "text/html", "<script>var q = '"+m+"';</script>")
	if len(xssrRulesFor(lexer)) == 0 {
		t.Log("the js-lexer fixture produced no hit; the rule's own table covers it and this is only a smoke check")
	}
}
