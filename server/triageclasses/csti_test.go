package triageclasses

import (
	"strconv"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// ---------------------------------------------------------------------------------------------
// FIXTURES
// ---------------------------------------------------------------------------------------------

// cstiTestMarker builds a marker whose ordinal stripe is genuinely this class's, rather than a
// plausible-looking string. A test that matched on a marker the arithmetic does not attribute to
// CSTI would pass while the real attribution rule was broken.
func cstiTestMarker(t *testing.T) triage.Marker {
	t.Helper()
	digits := strconv.FormatUint(uint64(triage.ClassCSTI), 36)
	for len(digits) < triage.MarkerOrdinalLen {
		digits = "0" + digits
	}
	prefix := triage.DefaultMarkerAnchor + "r1zk" + digits
	sum, err := triage.MarkerChecksumFor(prefix)
	if err != nil {
		t.Fatalf("could not build a test marker: %v", err)
	}
	m := triage.Marker(prefix + sum)
	if !m.BelongsTo(triage.ClassCSTI) {
		t.Fatalf("marker %q does not carry CSTI's ordinal stripe, so the fixture is testing nothing", m)
	}
	return m
}

const (
	cstiFixAngularJS = `<html><head><script src="/static/angular.min.js"></script></head>` +
		`<body ng-app="shop"><div class="results">REFLECT</div></body></html>`
	cstiFixPlain      = `<html><head><script src="/static/jquery.js"></script></head><body><div>REFLECT</div></body></html>`
	cstiFixAngularAOT = `<html><body><app-root ng-version="17.0.3"><div _ngcontent-abc>REFLECT</div></app-root></body></html>`
	cstiFixVue        = `<html><head><script src="/static/vue.global.js"></script></head>` +
		`<body><div id="app">REFLECT</div><script>createApp(App).mount('#app')</script></body></html>`
	cstiFixEmber = `<html><body><script src="/static/ember.min.js"></script><div data-ember-x>REFLECT</div></body></html>`
)

func cstiCorpus(complete bool, bodies ...string) triage.AssetCorpus {
	c := triage.AssetCorpus{Counted: true, ScannedN: len(bodies), AvailableM: len(bodies)}
	if !complete {
		c.AvailableM = len(bodies) + 3
	}
	for i, b := range bodies {
		c.Files = append(c.Files, triage.AssetFile{URL: "/static/asset" + strconv.Itoa(i) + ".js", Body: []byte(b)})
	}
	return c
}

// cstiVueAsset names itself so the build discriminator has something to discriminate on.
const (
	cstiVueFullAsset    = `/*! Vue.js v3.4.21 */ function compileToFunction(t){} var x = "@vue/compiler-dom";`
	cstiVueRuntimeAsset = `/*! Vue.js v3.4.21 */ warn("Component provided template option but runtime compilation is not supported in this build of Vue.")`
	cstiAngularAsset    = `/*! AngularJS v1.5.8 */ angular.module('shop',[]); var v = {full: "1.5.8", major: 1};`
)

func cstiEligibleFixture(t *testing.T) cstiEligibility {
	t.Helper()
	el := cstiAssess([]byte(cstiFixAngularJS), cstiCorpus(true, cstiAngularAsset))
	if len(el.Interpolating) == 0 {
		t.Fatalf("the AngularJS fixture did not read as eligible, so every verdict test below would be testing the wrong branch")
	}
	return el
}

func cstiHTMLSlot() triage.Slot {
	c := triage.NewSlotConstraints()
	c.DecodeDepth = 1
	return triage.Slot{
		Kind: triage.KindQuery, Key: "query:q", Name: "q", Value: "hello",
		ValueOrigin: triage.ValueObserved, Encoder: triage.EncodeQuery, Method: "GET",
		Origin: triage.SlotObserved, ServerReachable: true, Constraints: c,
	}
}

func cstiScoreEnvOK(slot triage.Slot) cstiScoreEnv {
	return cstiScoreEnv{
		Slot:                 slot,
		Prelude:              triage.PreludeTokenNotRequired,
		Baseline:             triage.BaselineModel{Samples: 5, Stable: true},
		PostBaselineResolved: true,
		BrowserDeliverable:   cstiNavCanDeliver(slot),
	}
}

func cstiPlanInputOK(t *testing.T, slot triage.Slot) cstiPlanInput {
	t.Helper()
	return cstiPlanInput{
		Slot: slot, RespMedia: "text/html", ControlOK: true,
		El:            cstiEligibleFixture(t),
		ProductInCtrl: map[string]bool{},
		SentProbes:    map[triage.ProbeID]bool{},
		BrowserLeft:   8,
	}
}

func cstiRead(id triage.ProbeID, marker triage.Marker, body string) cstiProbeRead {
	return cstiProbeRead{
		ProbeID: id, Ordinal: uint64(triage.ClassCSTI), Delivered: true,
		Survival: triage.WireSurvivalIntact, Marker: marker, Body: []byte(body),
	}
}

// ---------------------------------------------------------------------------------------------
// REGISTRATION AND THE LAW
// ---------------------------------------------------------------------------------------------

func TestTheCSTIClassifierRegistersItselfFromItsOwnInit(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassCSTI)
	if !ok {
		t.Fatal("CSTI did not register, so the class would produce no rows at all and no row looks exactly like no bug")
	}
	if c.ID() != triage.ClassCSTI {
		t.Fatalf("registered under CSTI but reports %s", c.ID())
	}
	if len(c.Probes()) == 0 {
		t.Fatal("CSTI declares no probe, so the isolation check runs over nothing")
	}
}

func TestTheRegistryStillPassesTheIsolationLawWithCSTIInIt(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
}

func TestNoTwoCSTIProbesCarryTheSameBytes(t *testing.T) {
	seen := map[string]triage.ProbeID{}
	for _, p := range (cstiClassifier{}).Probes() {
		key := string(triage.NormaliseMarkers(p.Logical))
		if prev, dup := seen[key]; dup {
			t.Errorf("%s and %s declare byte-equal payloads, so a block on one is unattributable between them", p.ID, prev)
		}
		seen[key] = p.ID
		if len(p.Logical) == 0 {
			t.Errorf("%s declares no bytes, so it sends nothing and would still record a result", p.ID)
		}
		if strings.Contains(string(p.Logical), triage.DefaultMarkerAnchor) {
			t.Errorf("%s writes a literal marker into its payload; the runner mints markers and a literal one carries nobody's stripe", p.ID)
		}
	}
}

func TestEveryCSTIReachesAnswerCarriesTheConditionItDependsOn(t *testing.T) {
	c := cstiClassifier{}
	for _, k := range triage.AllSlotKinds() {
		for _, mt := range []triage.MediaType{"", "text/html", "application/json", "application/x-www-form-urlencoded"} {
			r := c.Reaches(k, mt)
			if r.Reach != triage.ReachAlways && strings.TrimSpace(r.Reason) == "" {
				t.Errorf("Reaches(%s, %q) is %s with no reason: ruled out and never wired up are the same pixel without one", k, mt, r.Reach)
			}
		}
	}
	if got := c.Reaches(triage.KindFragment, "text/html"); got.Reach == triage.ReachNever {
		t.Error("the fragment is ReachNever, which loses the hash-mode AngularJS case this class exists to catch at the browser tier")
	}
}

// ---------------------------------------------------------------------------------------------
// ELIGIBILITY. THE DIFFERENCE BETWEEN "NO ENGINE" AND "COULD NOT TELL" IS THE WHOLE CLASS.
// ---------------------------------------------------------------------------------------------

func TestCSTIEligibilityTellsNoEngineApartFromCouldNotTell(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		assets    triage.AssetCorpus
		eligible  bool
		wantGate  cstiGateResult
		wantState triage.TriageState
		wantIn    string
	}{
		{
			name: "AngularJS 1.x on the page is eligible",
			body: cstiFixAngularJS, assets: cstiCorpus(true, cstiAngularAsset), eligible: true,
			wantGate: cstiGateEligible,
		},
		{
			name: "a Vue 3 FULL build is eligible because it compiles an in-DOM template",
			body: cstiFixVue, assets: cstiCorpus(true, cstiVueFullAsset), eligible: true,
			wantGate: cstiGateEligible,
		},
		{
			name: "a Vue RUNTIME-ONLY build is not_applicable, not clean",
			body: cstiFixVue, assets: cstiCorpus(true, cstiVueRuntimeAsset),
			wantGate: cstiGateIneligible, wantState: triage.StateNotApplicable, wantIn: "vue_runtime_only",
		},
		{
			name: "Vue present and its build never fetched is cannot_determine, never not_applicable",
			body: cstiFixVue, assets: cstiCorpus(false),
			wantGate: cstiGateUndetermined, wantState: triage.StateCannotDetermine, wantIn: "framework_undetermined",
		},
		{
			name: "Angular 2 and later is not_applicable (angular_aot) and is handed on",
			body: cstiFixAngularAOT, assets: cstiCorpus(true),
			wantGate: cstiGateIneligible, wantState: triage.StateNotApplicable, wantIn: "angular_aot",
		},
		{
			name: "Ember precompiles, so it is not_applicable for the same reason",
			body: cstiFixEmber, assets: cstiCorpus(true),
			wantGate: cstiGateIneligible, wantState: triage.StateNotApplicable, wantIn: "angular_aot",
		},
		{
			name: "no engine and a COMPLETE corpus is the only not_applicable (no_client_template_engine)",
			body: cstiFixPlain, assets: cstiCorpus(true, "var x=1;"),
			wantGate: cstiGateIneligible, wantState: triage.StateNotApplicable, wantIn: "no_client_template_engine",
		},
		{
			name: "no engine and a CAPPED corpus can never be not_applicable",
			body: cstiFixPlain, assets: cstiCorpus(false, "var x=1;"),
			wantGate: cstiGateUndetermined, wantState: triage.StateCannotDetermine, wantIn: "framework_undetermined",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := cstiAssess([]byte(tc.body), tc.assets)
			gate, state, reason := cstiGate(el)
			if gate != tc.wantGate {
				t.Fatalf("gate=%v, want %v (engines %v)", gate, tc.wantGate, el.engineNames())
			}
			if (gate == cstiGateEligible) != tc.eligible {
				t.Fatalf("eligible=%v, want %v (engines %v)", gate == cstiGateEligible, tc.eligible, el.engineNames())
			}
			if tc.eligible {
				return
			}
			if state != tc.wantState {
				t.Errorf("state %s, want %s (reason %q)", state, tc.wantState, reason)
			}
			if !strings.Contains(reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", reason, tc.wantIn)
			}
			if state.CountsAsClean() {
				t.Error("an eligibility refusal rendered as clean, which is the exact bug this class was written against")
			}
		})
	}
}

func TestAnUnfetchableAssetIsNeverAllowedToReadAsNotApplicableForCSTI(t *testing.T) {
	// The whole file's load-bearing distinction, asserted on its own so it cannot be lost in a
	// table refactor: the SAME page yields not_applicable with a complete corpus and
	// cannot_determine with a capped one.
	body := []byte(cstiFixPlain)
	_, complete, _ := cstiGate(cstiAssess(body, cstiCorpus(true, "var x=1;")))
	_, capped, _ := cstiGate(cstiAssess(body, cstiCorpus(false, "var x=1;")))
	if complete != triage.StateNotApplicable || capped != triage.StateCannotDetermine {
		t.Fatalf("complete corpus gave %s and capped corpus gave %s; they must differ and the capped one must be the unknown", complete, capped)
	}
}

func TestTheCSTIAngularSandboxMapPicksTheEscapeForTheVersionFound(t *testing.T) {
	cases := []struct{ version, sandbox, contains string }{
		{"1.0.8", "none", "constructor.constructor"},
		{"1.2.3", "present", "charAt=a.trim"},
		{"1.2.19", "present", "sort(c)"},
		{"1.5.8", "present", "$eval"},
		{"1.5.9", "present", "orderBy"},
		{"1.6.9", "removed", "constructor.constructor"},
		{"17.0.1", "unknown", "not AngularJS 1.x"},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			sandbox, escape := cstiAngularSandbox(tc.version)
			if sandbox != tc.sandbox {
				t.Errorf("sandbox %q, want %q", sandbox, tc.sandbox)
			}
			if !strings.Contains(escape, tc.contains) {
				t.Errorf("escape %q does not contain %q", escape, tc.contains)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE HTTP-TIER RULE: WHERE THE DELIMITERS LANDED
// ---------------------------------------------------------------------------------------------

func TestTheCSTIDelimiterRunIsACandidateOnlyWhereTheDetectedEngineCompiles(t *testing.T) {
	m := cstiTestMarker(t)
	run := string(cstiBytesCS1)
	doc := func(inner string) string {
		return `<html><head><script src="/static/angular.min.js"></script></head><body ng-app="shop">` + inner + `</body></html>`
	}
	cases := []struct {
		name          string
		body          string
		wantCompiled  int
		wantSuppress  int
		wantScript    int
		wantComment   int
		wantUnattrib  int
		wantCandidate bool
	}{
		{
			name:         "text inside the ng-app subtree is a candidate",
			body:         doc(`<div class="r">` + string(m) + run + `</div>`),
			wantCompiled: 1, wantCandidate: true,
		},
		{
			name:       "inside a script element it is not, because AngularJS does not compile script content",
			body:       doc(`<script>var s = "` + string(m) + run + `";</script>`),
			wantScript: 1,
		},
		{
			name:        "inside an HTML comment it is not",
			body:        doc(`<!-- ` + string(m) + run + ` -->`),
			wantComment: 1,
		},
		{
			name:         "inside ng-non-bindable it is not, and that is a NAMED defence",
			body:         doc(`<span ng-non-bindable>` + string(m) + run + `</span>`),
			wantSuppress: 1,
		},
		{
			name:         "inside v-pre it is not either",
			body:         doc(`<span v-pre>` + string(m) + run + `</span>`),
			wantSuppress: 1,
		},
		{
			name: "outside the resolved mount point it is not",
			body: `<html><head><script src="/static/angular.min.js"></script></head><body>` +
				`<div ng-app="shop">safe</div><p>` + string(m) + run + `</p></body></html>`,
		},
		{
			name:         "a run with this class's marker nowhere near it is attributed to nobody",
			body:         doc(`<div>` + run + `</div>`),
			wantUnattrib: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			regions := cstiScanRegions([]byte(tc.body), nil, true)
			c := cstiCensus([]byte(tc.body), m, cstiBytesCS1, regions)
			if c.Compiled != tc.wantCompiled {
				t.Errorf("compiled sites %d, want %d (census %+v)", c.Compiled, tc.wantCompiled, c)
			}
			if c.Suppressed != tc.wantSuppress {
				t.Errorf("suppressed sites %d, want %d", c.Suppressed, tc.wantSuppress)
			}
			if c.Script != tc.wantScript {
				t.Errorf("script sites %d, want %d", c.Script, tc.wantScript)
			}
			if c.Comment != tc.wantComment {
				t.Errorf("comment sites %d, want %d", c.Comment, tc.wantComment)
			}
			if c.Unattributed != tc.wantUnattrib {
				t.Errorf("unattributed sites %d, want %d", c.Unattributed, tc.wantUnattrib)
			}
			if got := c.Compiled > 0; got != tc.wantCandidate {
				t.Errorf("candidate=%v, want %v", got, tc.wantCandidate)
			}
		})
	}
}

func TestAnUnresolvedCSTIMountPointProducesALowConfidenceCandidateAndNeverANegative(t *testing.T) {
	m := cstiTestMarker(t)
	// FN-B3: the mount is created at runtime, so no ng-app appears in the served HTML.
	body := `<html><body><div>` + string(m) + string(cstiBytesCS1) + `</div></body></html>`
	regions := cstiScanRegions([]byte(body), nil, true)
	if regions.compiledResolved {
		t.Fatal("a document with no mount attribute reported a resolved compiled region, so the low-confidence path is unreachable")
	}
	if c := cstiCensus([]byte(body), m, cstiBytesCS1, regions); c.Compiled != 1 {
		t.Fatalf("the whole-body fallback did not make the site a candidate: %+v", c)
	}
}

func TestTheCSTIAttributeProbeAnswersOnlyToAnAttributeInATagCarryingThisClassesMarker(t *testing.T) {
	m := cstiTestMarker(t)
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"the attribute was created on the tag the marker landed in", `<div title="` + string(m) + `" csti0q="1">x</div>`, true},
		{"the payload came back as escaped TEXT, not as an attribute", `<div>` + string(m) + `&quot; csti0q=&quot;1</div>`, false},
		{"an attribute with no marker in the same tag belongs to the page, not to this probe", `<div csti0q="1">x</div>`, false},
		{"an unrelated page attribute after the tag closed is not it either", `<div>` + string(m) + `</div><p csti0q="1">x</p>`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := cstiAttrInTag([]byte(tc.body), m, "csti0q="); got != tc.want {
				t.Errorf("attribute created=%v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE VERDICT. EVERY FALSE POSITIVE MODE IS A ROW HERE.
// ---------------------------------------------------------------------------------------------

func TestTheCSTIVerdictHoldsEachNamedFalsePositiveModeSilent(t *testing.T) {
	m := cstiTestMarker(t)
	run := string(cstiBytesCS1)
	slot := cstiHTMLSlot()
	doc := func(inner string) string {
		return `<html><head><script src="/static/angular.min.js"></script></head><body ng-app="shop">` + inner + `</body></html>`
	}
	cases := []struct {
		name      string
		reads     []cstiProbeRead
		ctrlHas   map[string]bool
		wantState triage.TriageState
		wantIn    string
	}{
		{
			name:      "delimiters reach the compiler, so suspicious and NEVER a finding from HTTP alone",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<div>`+string(m)+run+`</div>`))},
			wantState: triage.StateSuspicious, wantIn: "template_delimiters_reach_compiler",
		},
		{
			name:      "a SERVER engine evaluated it, so it is handed to SSTI and is not a CSTI negative either",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<div>`+string(m)+cstiPairHTTP.Product+`</div>`))},
			wantState: triage.StateCannotDetermine, wantIn: "server_side_evaluation",
		},
		{
			name:      "the product was ALREADY on the unperturbed page, so CS-D2 abstains instead of misfiling",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<div>`+string(m)+cstiPairHTTP.Product+`</div>`))},
			ctrlHas:   map[string]bool{cstiPairHTTP.Product: true},
			wantState: triage.StateClean, wantIn: "delimiters_stripped",
		},
		{
			name:      "the reflection sits inside ng-non-bindable, which is a named defence",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<span ng-non-bindable>`+string(m)+run+`</span>`))},
			wantState: triage.StateNotExploitable, wantIn: "reflection_inside_non_bindable",
		},
		{
			name:      "the reflection sits inside a script element the engine does not compile",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<script>var s="`+string(m)+run+`";</script>`))},
			wantState: triage.StateClean, wantIn: "delimiters_outside_compiled_region",
		},
		{
			name:      "the braces came back percent-encoded, so the payload never arrived",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<div>`+string(m)+`%7B%7B7919*6271%7D%7D</div>`))},
			wantState: triage.StateCannotDetermine, wantIn: "delimiters_not_delivered",
		},
		{
			name:      "the marker came back and the braces did not, which is the only clean this rule has",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<div>`+string(m)+`7919*6271</div>`))},
			wantState: triage.StateClean, wantIn: "delimiters_stripped",
		},
		{
			name:      "nothing reflected at all",
			reads:     []cstiProbeRead{cstiRead(cstiProbeCS1, m, doc(`<div>nothing here</div>`))},
			wantState: triage.StateClean, wantIn: "no_reflection",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cstiPlanInputOK(t, slot)
			if tc.ctrlHas != nil {
				in.ProductInCtrl = tc.ctrlHas
			}
			sum := cstiSummarise(tc.reads, in.El, in.ProductInCtrl)
			v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
			if v.State != tc.wantState {
				t.Fatalf("state %s, want %s (reason %q)", v.State, tc.wantState, v.Reason)
			}
			if !strings.Contains(v.Reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", v.Reason, tc.wantIn)
			}
			if err := v.Validate(); err != nil {
				t.Errorf("the verdict does not satisfy the record's own invariants: %v", err)
			}
		})
	}
}

func TestTheCSTIHTTPTierCanNeverReachAFinding(t *testing.T) {
	if got := cstiHTTPCeiling(triage.StateFinding); got != triage.StateSuspicious {
		t.Fatalf("the HTTP ceiling let %s through; the engine runs in the browser and an HTTP response cannot show evaluation", got)
	}
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	in := cstiPlanInputOK(t, slot)
	body := `<html><body ng-app="shop"><div>` + string(m) + string(cstiBytesCS1) + `</div></body></html>`
	sum := cstiSummarise([]cstiProbeRead{cstiRead(cstiProbeCS1, m, body)}, in.El, in.ProductInCtrl)
	v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
	if v.State == triage.StateFinding {
		t.Fatal("an HTTP-only observation produced a finding")
	}
	if v.Annotations["needs_dom_run"] != true {
		t.Error("the HTTP-tier row does not record that it still needs a DOM run, so an operator reads a candidate with no next step")
	}
	if len(v.Untested) == 0 {
		t.Error("the navigation that did not run is not named in Untested, which is how an unsent probe becomes invisible")
	}
}

func TestACSTIBrowserRenderIsAFindingOnlyWhenItsOwnControlNavigationRanAndStayedSilent(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	rendered := `<html><body ng-app="shop"><div>` + cstiPairBrowser.Product + `</div></body></html>`
	quiet := `<html><body ng-app="shop"><div>` + string(m) + string(cstiBytesNavNC) + `</div></body></html>`
	dirty := `<html><body ng-app="shop"><div>` + cstiPairBrowser.Product + `</div></body></html>`

	cases := []struct {
		name      string
		reads     []cstiProbeRead
		wantState triage.TriageState
		wantIn    string
	}{
		{
			name: "payload renders the product and NC-B1 stayed silent: the finding",
			reads: []cstiProbeRead{
				cstiRead(cstiProbeNavNC, m, quiet),
				cstiRead(cstiProbeNav, m, rendered),
			},
			wantState: triage.StateFinding, wantIn: "csti_confirmed",
		},
		{
			name:      "payload renders the product and NC-B1 never ran: suspicious, because a calculator is not excluded",
			reads:     []cstiProbeRead{cstiRead(cstiProbeNav, m, rendered)},
			wantState: triage.StateSuspicious, wantIn: "product_rendered_without_control",
		},
		{
			name: "NC-B1 rendered the product from arithmetic with NO delimiters: the app computes it itself",
			reads: []cstiProbeRead{
				cstiRead(cstiProbeNavNC, m, dirty),
				cstiRead(cstiProbeNav, m, rendered),
			},
			wantState: triage.StateCannotDetermine, wantIn: "control_contaminated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := cstiPlanInputOK(t, slot)
			sum := cstiSummarise(tc.reads, in.El, in.ProductInCtrl)
			v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
			if v.State != tc.wantState {
				t.Fatalf("state %s, want %s (reason %q)", v.State, tc.wantState, v.Reason)
			}
			if !strings.Contains(v.Reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", v.Reason, tc.wantIn)
			}
			if err := v.Validate(); err != nil {
				t.Errorf("verdict invalid: %v", err)
			}
		})
	}
}

func TestEveryWayCSTICanFailToMeasureYieldsAnUnknownRatherThanClean(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	clean := `<html><body ng-app="shop"><div>nothing</div></body></html>`

	cases := []struct {
		name   string
		mutate func(*cstiScoreEnv, *cstiPlanInput, *[]cstiProbeRead)
		wantIn string
	}{
		{
			name:   "the slot is a credential",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) { e.Slot.Constraints.IsCredential = true },
			wantIn: "credential_slot",
		},
		{
			name: "the prelude never produced a token",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) {
				e.Prelude = triage.PreludeTokenUnobtainable
			},
			wantIn: "prelude_failed",
		},
		{
			name:   "there is no route control, so eligibility could not be read at all",
			mutate: func(_ *cstiScoreEnv, in *cstiPlanInput, _ *[]cstiProbeRead) { in.ControlOK = false },
			wantIn: "no_route_control",
		},
		{
			name:   "the response is not a document, so there is no DOM for an engine to compile",
			mutate: func(_ *cstiScoreEnv, in *cstiPlanInput, _ *[]cstiProbeRead) { in.RespMedia = "application/json" },
			wantIn: "response_not_a_document",
		},
		{
			name: "the probe never reached the application",
			mutate: func(_ *cstiScoreEnv, _ *cstiPlanInput, r *[]cstiProbeRead) {
				(*r)[0].Delivered = false
			},
			wantIn: "transport_failed",
		},
		{
			name: "the encoder could not prove the bytes went out intact",
			mutate: func(_ *cstiScoreEnv, _ *cstiPlanInput, r *[]cstiProbeRead) {
				(*r)[0].Survival = triage.WireSurvivalUnknown
			},
			wantIn: "payload_wire_unproven",
		},
		{
			name: "the response body was truncated before the whole document was searched",
			mutate: func(_ *cstiScoreEnv, _ *cstiPlanInput, r *[]cstiProbeRead) {
				(*r)[0].Truncated = true
			},
			wantIn: "body_truncated",
		},
		{
			name: "the endpoint varies on its own",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) {
				e.Baseline.Stable = false
				e.Baseline.GateReason = "too_volatile"
			},
			wantIn: "endpoint_too_volatile",
		},
		{
			name:   "nothing modelled the endpoint's own variation",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) { e.Baseline = triage.BaselineModel{} },
			wantIn: "no_baseline_model",
		},
		{
			name:   "the baseline model is degraded",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) { e.Baseline.Degraded = true },
			wantIn: "baseline_degraded",
		},
		{
			name:   "the slot was probed at a fabricated identifier",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) { e.Slot.ValueOrigin = triage.ValueCanary },
			wantIn: "canary_resource",
		},
		{
			name:   "nobody measured whether the slot percent-decodes",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) { e.Slot.Constraints.DecodeDepth = -1 },
			wantIn: "decode_depth_unknown",
		},
		{
			name:   "the served-JavaScript corpus was capped",
			mutate: func(_ *cstiScoreEnv, in *cstiPlanInput, _ *[]cstiProbeRead) { in.El.CorpusComplete = false },
			wantIn: "corpus_capped",
		},
		{
			name:   "nothing re-measured the endpoint after the probes",
			mutate: func(e *cstiScoreEnv, _ *cstiPlanInput, _ *[]cstiProbeRead) { e.PostBaselineResolved = false },
			wantIn: "post_baseline_missing",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := cstiScoreEnvOK(slot)
			in := cstiPlanInputOK(t, slot)
			reads := []cstiProbeRead{cstiRead(cstiProbeCS1, m, clean)}
			tc.mutate(&env, &in, &reads)
			sum := cstiSummarise(reads, in.El, in.ProductInCtrl)
			v := cstiVerdict(env, in, sum)
			if v.State.CountsAsClean() {
				t.Fatalf("this path reported CLEAN: %q. A measurement that did not happen is not a pass", v.Reason)
			}
			if !v.State.IsUnknown() && v.State != triage.StateNotApplicable {
				t.Fatalf("state %s is not an unknown, so it asserts something about the application that was never measured", v.State)
			}
			if !strings.Contains(v.Reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", v.Reason, tc.wantIn)
			}
			if err := v.Validate(); err != nil {
				t.Errorf("verdict invalid: %v", err)
			}
		})
	}
}

func TestTheSameCSTIObservationIsCleanOnlyWhenEveryPreconditionHeld(t *testing.T) {
	// The control for the table above: with nothing mutated, the identical observation IS clean,
	// which is what makes each unknown above attributable to the one thing that changed.
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	in := cstiPlanInputOK(t, slot)
	reads := []cstiProbeRead{cstiRead(cstiProbeCS1, m, `<html><body ng-app="shop"><div>nothing</div></body></html>`)}
	v := cstiVerdict(cstiScoreEnvOK(slot), in, cstiSummarise(reads, in.El, in.ProductInCtrl))
	if v.State != triage.StateClean {
		t.Fatalf("state %s (%q); the fully-measured negative must be reachable or every unknown above proves nothing", v.State, v.Reason)
	}
	if len(v.Ordinals) == 0 {
		t.Error("a clean with no probe ordinals is a class claiming it tested something when nothing was sent")
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

func TestCSTIPlanSendsNotOneByteWithoutAnInterpolatingEngine(t *testing.T) {
	in := cstiPlanInput{
		Slot: cstiHTMLSlot(), RespMedia: "text/html", ControlOK: true,
		El:            cstiAssess([]byte(cstiFixPlain), cstiCorpus(true, "var x=1;")),
		ProductInCtrl: map[string]bool{}, SentProbes: map[triage.ProbeID]bool{}, BrowserLeft: 8,
	}
	if got := cstiPlanLadder(in); len(got) != 0 {
		t.Fatalf("planned %d probes against a page with no engine; eligibility is the whole cost model of this class", len(got))
	}
}

func TestCSTIPlanCostsOneHTTPRequestInTheTypicalCase(t *testing.T) {
	in := cstiPlanInputOK(t, cstiHTMLSlot())
	got := cstiPlanLadder(in)
	ids := map[triage.ProbeID]bool{}
	for _, r := range got {
		ids[r.Spec] = true
	}
	if !ids[cstiProbeCS1] {
		t.Fatal("the default delimiter probe was not planned on an eligible slot")
	}
	if !ids[cstiProbeCS0Q] {
		t.Error("the attribute-capability probe was not planned, so the directive family could never be unlocked")
	}
	if ids[cstiProbeCS1B] || ids[cstiProbeCS1C] {
		t.Error("the alternate delimiters went out although the corpus was COMPLETE and named none of them")
	}
	if ids[cstiProbeNav] {
		t.Error("a navigation was planned before the HTTP tier flagged anything; a navigation costs about a hundred times an HTTP request")
	}
	for _, r := range got {
		if r.Variant["product"] == "" {
			t.Errorf("%s carries no product in its variant, so the runner cannot record what the oracle expected", r.Spec)
		}
	}
	if err := triage.PlannedProbesAreDeclared(cstiClassifier{}, got); err != nil {
		t.Fatalf("the ladder planned something it never declared: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// THE UNDETERMINED TIER. "COULD NOT TELL" IS NOT A REASON TO SEND NOTHING FOREVER.
// ---------------------------------------------------------------------------------------------

// cstiUndeterminedInput is the shape this build actually runs in: PlanCtx.Assets is never
// populated, so the corpus is capped on every route of every target, and a page whose framework
// lives inside a bundle can never be shown NOT to have one.
func cstiUndeterminedInput(slot triage.Slot) cstiPlanInput {
	return cstiPlanInput{
		Slot: slot, RespMedia: "text/html", ControlOK: true,
		El:            cstiAssess([]byte(cstiFixPlain), triage.AssetCorpus{}),
		ProductInCtrl: map[string]bool{},
		SentProbes:    map[triage.ProbeID]bool{},
		BrowserLeft:   8,
	}
}

// THE DEFECT THIS TEST EXISTS FOR. The gate returned a bool, so "no engine" and "could not tell"
// both planned zero probes. On a runner with no served-JavaScript corpus the second one is every
// route of every target, so CSTI recorded planned=0 sent=0 everywhere behind an enabled checkbox.
func TestCSTIPlansTheDelimiterSurvivalProbeWhenTheEngineQuestionIsUnanswered(t *testing.T) {
	in := cstiUndeterminedInput(cstiHTMLSlot())
	if gate, _, _ := cstiGate(in.El); gate != cstiGateUndetermined {
		t.Fatalf("the fixture gates as %v, so this test is measuring the wrong branch", gate)
	}
	got := cstiPlanLadder(in)
	if len(got) == 0 {
		t.Fatal("planned nothing on a page whose engine question is OPEN. Whether this class's delimiters " +
			"survive into the document is HTTP-only, costs one request, and is the precondition for every CSTI " +
			"there is; sending nothing measures none of it and still produces a row")
	}
	if len(got) != 1 || got[0].Spec != cstiProbeCS1 {
		ids := make([]triage.ProbeID, 0, len(got))
		for _, r := range got {
			ids = append(ids, r.Spec)
		}
		t.Fatalf("planned %v, want exactly [%s]: the alternates chase a RECONFIGURED engine and no engine was found at all", ids, cstiProbeCS1)
	}
	if got[0].Variant["csti_tier"] != cstiTierEngineUndetermined {
		t.Errorf("the probe is stamped tier %q, so no row can be audited against the tier that produced it", got[0].Variant["csti_tier"])
	}
	if got[0].Variant["product"] == "" {
		t.Error("no product in the variant, so the runner cannot record what this probe expected")
	}
	if err := triage.PlannedProbesAreDeclared(cstiClassifier{}, got); err != nil {
		t.Fatalf("the reduced ladder planned something it never declared: %v", err)
	}
	t.Run("and it runs once, because there is no ladder to climb without an engine to climb it for", func(t *testing.T) {
		in2 := cstiUndeterminedInput(cstiHTMLSlot())
		in2.SentProbes = map[triage.ProbeID]bool{cstiProbeCS1: true}
		if again := cstiPlanLadder(in2); len(again) != 0 {
			t.Fatalf("planned %d more probes on round 1 of a tier with no engine to aim at", len(again))
		}
	})
	t.Run("and a proven absence still sends nothing", func(t *testing.T) {
		in3 := cstiUndeterminedInput(cstiHTMLSlot())
		in3.El = cstiAssess([]byte(cstiFixPlain), cstiCorpus(true, "var x=1;"))
		if got := cstiPlanLadder(in3); len(got) != 0 {
			t.Fatalf("planned %d probes against a COMPLETE corpus holding no engine; eligibility is still the cost model of this class", len(got))
		}
	})
}

// THE CEILING. This tier never established that an engine is present, so it may not say finding,
// may not say suspicious, and above all may not say clean or not_applicable.
func TestTheUndeterminedCSTITierIsNeverAFindingASuspicionOrAClean(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	reflected := "<html><head><script src=/static/app.js></script></head><body><div>" +
		string(m) + "{{7919*6271}}</div></body></html>"

	for _, tc := range []struct {
		name   string
		body   string
		wantIn string
	}{
		{"the delimiters came back intact, which is the pointer", reflected, "delimiters_survive_engine_unknown"},
		{"the braces were stripped and the marker was not",
			"<html><head><script src=/static/app.js></script></head><body><div>" + string(m) + "</div></body></html>",
			"delimiters_stripped_engine_unknown"},
		{"nothing came back at all",
			"<html><head><script src=/static/app.js></script></head><body><div>nothing</div></body></html>",
			"no_reflection_engine_unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := cstiUndeterminedInput(slot)
			reads := []cstiProbeRead{cstiRead(cstiProbeCS1, m, tc.body)}
			sum := cstiSummarise(reads, in.El, in.ProductInCtrl)
			v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
			if err := v.Validate(); err != nil {
				t.Errorf("verdict failed its own contract: %v", err)
			}
			if v.State != triage.StateCannotDetermine {
				t.Errorf("state %s, want cannot_determine: this tier never showed that a client template engine is present", v.State)
			}
			if v.State.CountsAsClean() {
				t.Fatal("the undetermined tier rendered as CLEAN, which is a claim about an engine nobody looked for")
			}
			if v.Grade != triage.GradeUnrated {
				t.Errorf("grade %q on an unknown, which ClassVerdict.Validate refuses", v.Grade)
			}
			if !strings.Contains(v.Reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", v.Reason, tc.wantIn)
			}
			if v.Annotations["csti_tier"] != cstiTierEngineUndetermined {
				t.Errorf("the row is stamped tier %v, want %q", v.Annotations["csti_tier"], cstiTierEngineUndetermined)
			}
			if v.Annotations["engine_presence"] != "unknown" {
				t.Error("the row does not say the engine presence is unknown, so a reader takes the silence for coverage")
			}
		})
	}
}

// The one path that is worth an hour of somebody's time has to carry the tool and the question
// that is still open, or it is just another unknown in a list of them.
func TestTheSurvivingDelimiterPointerNamesTheToolAndWhatIsStillUnknown(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	in := cstiUndeterminedInput(slot)
	body := "<html><head><script src=/static/app.js></script></head><body><div>" +
		string(m) + "{{7919*6271}}</div></body></html>"
	sum := cstiSummarise([]cstiProbeRead{cstiRead(cstiProbeCS1, m, body)}, in.El, in.ProductInCtrl)
	v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)

	found := false
	for _, tool := range v.Label.Tools {
		if tool == "domdig" {
			found = true
		}
	}
	if !found {
		t.Errorf("the pointer names tools %v and not domdig, which is the one run that settles the open question", v.Label.Tools)
	}
	if v.Label.Hints["what_is_not_established"] == "" {
		t.Error("the pointer does not say what is still unknown, so it reads as a finding at low confidence rather than as a precondition")
	}
	if v.Evidence.Phrase != "delimiters_survive_engine_unknown" {
		t.Errorf("evidence phrase %q", v.Evidence.Phrase)
	}
	// And the nine probes it withheld are named, so the coverage row is not a class that ran out
	// of ideas.
	if len(v.Untested) == 0 {
		t.Error("no probe was recorded as untested, although this tier deliberately withheld every probe but one")
	}
	for _, s := range v.Untested {
		if s.ProbeID == cstiProbeCS1 {
			t.Error("CS1 is listed as untested and it is the probe this tier sent")
		}
	}
}

// The one case an incomplete corpus cannot hide, and the two that it can.
func TestADocumentThatRunsNoScriptAtAllIsNotApplicableEvenWithACappedCorpus(t *testing.T) {
	bare := "<html><head><title>x</title></head><body><div>REFLECT</div></body></html>"
	el := cstiAssess([]byte(bare), triage.AssetCorpus{})
	gate, state, reason := cstiGate(el)
	if gate != cstiGateIneligible || state != triage.StateNotApplicable {
		t.Fatalf("gate %v state %s: an AssetCorpus holds the files this document REFERENCES, and a document "+
			"that references none has nothing for the corpus to be incomplete about", gate, state)
	}
	if !strings.Contains(reason, "no_script_in_document") {
		t.Errorf("reason %q does not name the rule", reason)
	}

	t.Run("but a TRUNCATED body can never support it", func(t *testing.T) {
		el := cstiAssess([]byte(bare), triage.AssetCorpus{})
		el.ControlTruncated = true
		if gate, state, _ := cstiGate(el); gate != cstiGateUndetermined || state != triage.StateCannotDetermine {
			t.Fatalf("gate %v state %s: the script tag could be past the cap", gate, state)
		}
	})
	t.Run("and neither can a body nobody fetched", func(t *testing.T) {
		if gate, state, _ := cstiGate(cstiAssess(nil, triage.AssetCorpus{})); gate != cstiGateUndetermined || state != triage.StateCannotDetermine {
			t.Fatalf("gate %v state %s: no control body is not the same fact as a control body with no script in it", gate, state)
		}
	})
	t.Run("and an inline event handler counts as script", func(t *testing.T) {
		withHandler := `<html><body onload="go()"><div>REFLECT</div></body></html>`
		if gate, _, _ := cstiGate(cstiAssess([]byte(withHandler), triage.AssetCorpus{})); gate != cstiGateUndetermined {
			t.Fatalf("gate %v: a page that runs an inline handler runs script, and this rule must fail closed", gate)
		}
	})
}

// A fragment has no HTTP delivery at all, so the reduced tier sends nothing to it and must say
// needs_dom_run rather than going quiet.
func TestAnUndeterminedFragmentSaysItNeedsADOMRunRatherThanGoingQuiet(t *testing.T) {
	slot := triage.Slot{
		Kind: triage.KindFragment, Key: "fragment:q", Name: "q", Value: "hello",
		ValueOrigin: triage.ValueObserved, Origin: triage.SlotObserved, ServerReachable: false,
		Constraints: triage.NewSlotConstraints(),
	}
	in := cstiUndeterminedInput(slot)
	if got := cstiPlanLadder(in); len(got) != 0 {
		t.Fatalf("planned %d HTTP probes for a fragment, which is never transmitted", len(got))
	}
	v := cstiVerdict(cstiScoreEnvOK(slot), in, cstiSummarise(nil, in.El, in.ProductInCtrl))
	if v.State.CountsAsClean() {
		t.Fatal("a fragment nobody could deliver to rendered as clean")
	}
	if !strings.Contains(v.Reason, "needs_dom_run") {
		t.Errorf("reason %q does not name needs_dom_run", v.Reason)
	}
}

func TestACappedCorpusMakesTheCSTIAlternateDelimitersGoOutUnconditionally(t *testing.T) {
	in := cstiPlanInputOK(t, cstiHTMLSlot())
	in.El.CorpusComplete = false
	ids := map[triage.ProbeID]bool{}
	for _, r := range cstiPlanLadder(in) {
		ids[r.Spec] = true
	}
	if !ids[cstiProbeCS1B] || !ids[cstiProbeCS1C] {
		t.Fatal("an incomplete corpus cannot prove the default delimiters are in use, so the alternates must be sent; reconfigured delimiters are this class's largest false negative")
	}
	if ids[cstiProbeCS1D] {
		t.Error("the ${ } probe went out although no ${ } engine was named; it is the one alternate that is never speculative")
	}
}

func TestTheCSTIDirectiveProbesWaitForTheAttributeProbeToFire(t *testing.T) {
	in := cstiPlanInputOK(t, cstiHTMLSlot())
	in.SentProbes = map[triage.ProbeID]bool{cstiProbeCS1: true, cstiProbeCS0Q: true}

	if got := cstiPlanLadder(in); len(got) != 0 {
		t.Fatalf("ruling R4 broken: %d directive probes went out before CS-0q proved the slot can create an attribute", len(got))
	}
	in.AttributeMade = true
	ids := map[triage.ProbeID]bool{}
	for _, r := range cstiPlanLadder(in) {
		ids[r.Spec] = true
	}
	if !ids[cstiProbeCS2] {
		t.Error("AngularJS was the detected engine and its directive probe was not sent")
	}
	if ids[cstiProbeCS2V] || ids[cstiProbeCS2A] || ids[cstiProbeCS3] {
		t.Error("a directive probe went out for an engine that is not on this page, which is cost with no hypothesis behind it")
	}
}

func TestACSTIFragmentIsNeverProbedOverHTTPAndIsProbedByNavigation(t *testing.T) {
	slot := cstiHTMLSlot()
	slot.Kind = triage.KindFragment
	slot.Key = "fragment:tab"
	slot.ServerReachable = false

	in := cstiPlanInputOK(t, slot)
	got := cstiPlanLadder(in)
	if len(got) == 0 {
		t.Fatal("no probe at all for a fragment, so the hash-mode AngularJS case is invisible")
	}
	for _, r := range got {
		if r.Spec != cstiProbeNav && r.Spec != cstiProbeNavNC {
			t.Errorf("%s was planned for a fragment, which no HTTP request ever carries", r.Spec)
		}
		if r.Variant["delivery"] != "browser_navigation" {
			t.Errorf("%s is not marked for browser delivery", r.Spec)
		}
	}

	// With no browser allowance there is nothing to send, and that must read as an unknown.
	in.BrowserLeft = 0
	if len(cstiPlanLadder(in)) != 0 {
		t.Fatal("a navigation was planned with no browser allowance left")
	}
	env := cstiScoreEnvOK(slot)
	v := cstiVerdict(env, in, cstiSummarise(nil, in.El, in.ProductInCtrl))
	if v.State.CountsAsClean() || !strings.Contains(v.Reason, "needs_dom_run") {
		t.Fatalf("a fragment with no navigation gave %s (%q); it must be needs_dom_run", v.State, v.Reason)
	}
}

func TestACSTIBodySlotSaysTheBrowserTierCannotDeliverItRatherThanGoingQuiet(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	slot.Kind = triage.KindBody
	slot.Key = "body:/q"
	slot.BodyMedia = triage.BodyForm
	slot.Method = "POST"

	in := cstiPlanInputOK(t, slot)
	body := `<html><body ng-app="shop"><div>` + string(m) + string(cstiBytesCS1) + `</div></body></html>`
	sum := cstiSummarise([]cstiProbeRead{cstiRead(cstiProbeCS1, m, body)}, in.El, in.ProductInCtrl)
	v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)

	if v.State != triage.StateSuspicious {
		t.Fatalf("state %s, want suspicious (%q)", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "no_browser_delivery") {
		t.Errorf("reason %q does not say that domdig navigates and cannot reissue a captured body verb", v.Reason)
	}
	if cstiNavCanDeliver(slot) {
		t.Error("a body slot claims browser delivery, which would schedule a navigation that cannot carry the payload")
	}
}

func TestCSTIClassifyAlwaysReturnsARowForTheSlotItWasAskedAbout(t *testing.T) {
	// With a zero ClassifyCtx nothing was measured, and the row must say so rather than be absent.
	// A slot with no row reads as untouched, which is indistinguishable from a class that does not
	// exist.
	slot := triage.Slot{Kind: triage.KindQuery, Key: "query:q"}
	vs := cstiClassifier{}.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: slot}})
	if len(vs) != 1 {
		t.Fatalf("Classify returned %d rows, want exactly 1", len(vs))
	}
	if vs[0].SlotKey != slot.Key || vs[0].Class != triage.ClassCSTI {
		t.Errorf("the row names slot %q class %s", vs[0].SlotKey, vs[0].Class)
	}
	if vs[0].State.CountsAsClean() {
		t.Fatal("an unmeasured slot came back clean")
	}
	if err := vs[0].Validate(); err != nil {
		t.Errorf("verdict invalid: %v", err)
	}
}

func TestCSTIPlanSendsNothingAtAllWithAZeroContext(t *testing.T) {
	if got := (cstiClassifier{}).Plan(triage.PlanCtx{Slot: triage.Slot{Key: "query:q"}}); len(got) != 0 {
		t.Fatalf("planned %d probes with no route control and no corpus; eligibility is unknown there, and unknown is not permission to send", len(got))
	}
}

// ---------------------------------------------------------------------------------------------
// WHAT THE CLASS HANDS ON
// ---------------------------------------------------------------------------------------------

func TestTheCSTILabelNamesTheEngineTheVersionAndTheEscapeForIt(t *testing.T) {
	l := cstiLabelFor(cstiEligibleFixture(t))
	if l.Engine != string(cstiEngineAngularJS) {
		t.Errorf("engine %q, want angularjs", l.Engine)
	}
	if l.Hints["angularjs_version"] != "1.5.8" {
		t.Errorf("version hint %q, want 1.5.8: the version is what selects the sandbox escape", l.Hints["angularjs_version"])
	}
	if l.Hints["sandbox"] != "present" {
		t.Errorf("sandbox hint %q, want present", l.Hints["sandbox"])
	}
	if l.Hints["escape_payload"] == "" {
		t.Error("no escape payload was selected, which is the whole reason CSTI is a separate class from SSTI")
	}
	found := false
	for _, tool := range l.Tools {
		if tool == "domdig" {
			found = true
		}
	}
	if !found {
		t.Error("the label does not point at domdig, which is the only confirmer that runs a real browser")
	}
}

func TestCSTIOracleCasesDeclareBothAPositiveAndANegative(t *testing.T) {
	pos, neg := 0, 0
	seen := map[string]bool{}
	for _, oc := range (cstiClassifier{}).OracleCases() {
		if seen[oc.Path] {
			t.Errorf("duplicate oracle path %q", oc.Path)
		}
		seen[oc.Path] = true
		switch oc.Expect {
		case cstiExpectPositive:
			pos++
			if oc.State.IsUnknown() || oc.State.CountsAsClean() {
				t.Errorf("%s is declared positive but expects %s", oc.Path, oc.State)
			}
		case cstiExpectNegative:
			neg++
			if oc.State == triage.StateFinding {
				t.Errorf("%s is declared negative but expects a finding", oc.Path)
			}
		default:
			t.Errorf("%s declares neither positive nor negative", oc.Path)
		}
		if strings.TrimSpace(oc.Note) == "" {
			t.Errorf("%s carries no note, so whoever builds it has to guess what it must do", oc.Path)
		}
	}
	if pos == 0 || neg == 0 {
		t.Fatalf("%d positive and %d negative oracle cases; a detector never shown to STAY SILENT is not a verified detector", pos, neg)
	}
}

func TestCSTIConfirmersAndEvidencersAreDistinctAndNonEmpty(t *testing.T) {
	c := cstiClassifier{}
	if len(c.Confirmers()) == 0 {
		t.Fatal("no confirmer, so a finding names no tool and the triage layer has answered nothing")
	}
	for _, e := range c.Evidencers() {
		for _, f := range c.Confirmers() {
			if e == f {
				t.Errorf("%q is listed as both evidence and confirmation, which lets weak evidence close a row", e)
			}
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE MARKER IS IN THE PAYLOAD, BECAUSE MarkerPos PLACES NOTHING
// ---------------------------------------------------------------------------------------------

// cstiRenderLogical is triageRenderPayload's step 1, the only step that touches a CSTI payload:
// the runner replaces the marker placeholder with the minted marker. It is reproduced here, on
// the DECLARED bytes, so these tests exercise what actually goes on the wire rather than a
// hand-written string that flatters the class.
func cstiRenderLogical(t *testing.T, id triage.ProbeID, m triage.Marker) string {
	t.Helper()
	for _, p := range (cstiClassifier{}).Probes() {
		if p.ID == id {
			return strings.ReplaceAll(string(p.Logical), triage.MarkerPlaceholder, string(m))
		}
	}
	t.Fatalf("no probe %s is declared", id)
	return ""
}

// TestEveryCSTIPayloadSpellsTheMarkerItselfBecauseMarkerPosPlacesNothing is the build-time half of
// the exam-2e4433b1 defect.
//
// The runner's triageRenderPayload substitutes marker TOKENS a payload spells and never reads
// ProbeSpec.MarkerPos. A class that declared its payloads bare and relied on MarkerPos therefore
// sent markerless bytes, and its own attribution rule (the marker sits in front of the run) could
// not be satisfied by any response the application could produce.
func TestEveryCSTIPayloadSpellsTheMarkerItselfBecauseMarkerPosPlacesNothing(t *testing.T) {
	for _, p := range (cstiClassifier{}).Probes() {
		if !strings.Contains(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("%s declares %q, which carries no marker placeholder. MarkerPos is dead metadata in the runner, so "+
				"this probe goes on the wire with no marker and every landing site it produces is unattributable",
				p.ID, string(p.Logical))
			continue
		}
		if !strings.HasPrefix(string(p.Logical), triage.MarkerPlaceholder) {
			t.Errorf("%s spells the placeholder at offset %d but declares MarkerPos %s; the attribution rule reads the "+
				"bytes BEFORE the run, so the position it declares and the position it ships must agree",
				p.ID, strings.Index(string(p.Logical), triage.MarkerPlaceholder), p.MarkerPos)
		}
		if p.MarkerPos != triage.MarkerPrefix {
			t.Errorf("%s spells the placeholder first and declares MarkerPos %s", p.ID, p.MarkerPos)
		}
	}
}

// TestCSTIFiresOnItsOwnPositiveControlBuiltFromItsDeclaredPayload is the round's bar, driven from
// the bytes the class actually declares against the oracle's /csti/angular document.
//
// It is built by RENDERING the declared payload the way the runner does and reflecting the result
// into the route's reflection point. That is why it catches the defect: with the marker absent
// from the declared payload the reflected text carries no marker, every landing site is
// unattributed, and the class answers cannot_determine on a page whose braces sit intact inside
// the ng-app subtree.
func TestCSTIFiresOnItsOwnPositiveControlBuiltFromItsDeclaredPayload(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()

	// The oracle's /csti/angular document, byte for byte apart from the reflection.
	page := func(reflected string) string {
		return "<!doctype html><html><head><title>canary search</title>\n" +
			"<script src=\"/csti/angular.min.js\"></script></head>\n" +
			"<body ng-app>\n<h1>Search</h1>\n" +
			"<div id=\"view\">You searched for " + reflected + "</div>\n" +
			"<span ng-non-bindable>{{ this region is never compiled }}</span>\n" +
			"</body></html>"
	}
	control := page("hello")

	el := cstiAssess([]byte(control), triage.AssetCorpus{})
	if len(el.Interpolating) == 0 {
		t.Fatal("AngularJS was not detected from the SERVED HTML alone, so eligibility depends on a corpus this build never populates")
	}
	in := cstiPlanInput{
		Slot: slot, RespMedia: "text/html", ControlOK: true, El: el,
		ProductInCtrl: map[string]bool{}, SentProbes: map[triage.ProbeID]bool{}, BrowserLeft: 0,
	}
	if gate, _, _ := cstiGate(el); gate != cstiGateEligible {
		t.Fatalf("gate is %v on the class's own positive control", gate)
	}
	if got := cstiPlanLadder(in); len(got) == 0 {
		t.Fatal("the ladder planned nothing on the class's own positive control: a toggle that sends nothing")
	}

	body := page(cstiRenderLogical(t, cstiProbeCS1, m))
	sum := cstiSummarise([]cstiProbeRead{cstiRead(cstiProbeCS1, m, body)}, el, in.ProductInCtrl)
	if !sum.markerSeen {
		t.Fatal("the marker is not in the response built from this class's own declared payload, so the class cannot attribute anything it sends")
	}
	if !sum.httpFlagged {
		t.Fatal("the delimiter run landed inside the ng-app subtree and the class did not flag it")
	}
	v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
	if v.State != triage.StateSuspicious {
		t.Fatalf("state %s (%s), want suspicious: the braces reached a region AngularJS compiles", v.State, v.Reason)
	}
	if !strings.Contains(v.Reason, "template_delimiters_reach_compiler") {
		t.Errorf("reason %q does not name the oracle that fired", v.Reason)
	}
	if v.Label.Engine == "" && len(v.Label.Tools) == 0 {
		t.Error("the row hands the operator no tool, which is the whole point of the class")
	}
}

// TestCSTIStaysSilentOnThePlainRouteWithTheSameLadder is the other half: a detector that fires
// everywhere is not a detector.
func TestCSTIStaysSilentOnThePlainRouteWithTheSameLadder(t *testing.T) {
	plain := "<!doctype html><html><head><title>canary search</title></head>\n" +
		"<body>\n<h1>Search</h1>\n" +
		"<div id=\"view\">You searched for hello</div>\n</body></html>"
	el := cstiAssess([]byte(plain), triage.AssetCorpus{})
	if len(el.Interpolating) > 0 {
		t.Fatalf("an interpolating engine was detected on a page that runs no script at all: %v", el.engineNames())
	}
	gate, state, reason := cstiGate(el)
	if gate != cstiGateIneligible {
		t.Fatalf("gate is %v on a scriptless document, so the class would spend requests on a page with nothing to compile", gate)
	}
	if state != triage.StateNotApplicable || !strings.Contains(reason, "no_script_in_document") {
		t.Fatalf("state %s reason %q", state, reason)
	}
	in := cstiPlanInput{
		Slot: cstiHTMLSlot(), RespMedia: "text/html", ControlOK: true, El: el,
		ProductInCtrl: map[string]bool{}, SentProbes: map[triage.ProbeID]bool{},
	}
	if got := cstiPlanLadder(in); len(got) != 0 {
		t.Fatalf("the ladder planned %d probes against a page with no client template engine", len(got))
	}
}

// TestAMarkerlessWireFormIsNeverReadAsASilence is the run-time half of the guard. The class's
// attribution is positional, so a probe that reached the wire with no marker in it makes every
// negative exit a measurement of the runner.
func TestAMarkerlessWireFormIsNeverReadAsASilence(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	in := cstiPlanInputOK(t, slot)
	body := "<html><body ng-app=\"shop\"><div>You searched for " + string(cstiBytesCS1) + "</div></body></html>"

	cases := []struct {
		name string
		read cstiProbeRead
		want string
	}{
		{
			name: "the wire form records the run and no marker: exactly what exam 2e4433b1 sent",
			read: cstiProbeRead{ProbeID: cstiProbeCS1, Ordinal: uint64(triage.ClassCSTI), Delivered: true,
				Survival: triage.WireSurvivalEncoded, Marker: m, Body: []byte(body),
				Logical: cstiBytesCS1, Wire: []byte("%7B%7B7919%2A6271%7D%7D")},
			want: cstiFidelityNoMarker,
		},
		{
			name: "the placeholder is still literally on the wire, so nobody substituted it",
			read: cstiProbeRead{ProbeID: cstiProbeCS1, Ordinal: uint64(triage.ClassCSTI), Delivered: true,
				Survival: triage.WireSurvivalIntact, Marker: m, Body: []byte(body),
				Logical: []byte(triage.MarkerPlaceholder + string(cstiBytesCS1)),
				Wire:    []byte(triage.MarkerPlaceholder + string(cstiBytesCS1))},
			want: cstiFidelityPlaceholder,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sum := cstiSummarise([]cstiProbeRead{tc.read}, in.El, in.ProductInCtrl)
			if sum.fidelityWhy != tc.want {
				t.Fatalf("fidelity says %q, want %q", sum.fidelityWhy, tc.want)
			}
			v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
			if v.State != triage.StateCannotDetermine {
				t.Fatalf("state %s (%s): a probe whose marker never went out cannot produce a silence", v.State, v.Reason)
			}
			if !strings.Contains(v.Reason, tc.want) {
				t.Errorf("reason %q does not name the integration failure", v.Reason)
			}
			if v.State.CountsAsClean() {
				t.Error("a fidelity failure counted as clean")
			}
		})
	}
}

// TestTheUndeterminedTierAlsoRefusesToReadAMarkerlessProbe: the reduced tier sends the same CS-1
// bytes, so the same defect reaches it and the same refusal must apply.
func TestTheUndeterminedTierAlsoRefusesToReadAMarkerlessProbe(t *testing.T) {
	m := cstiTestMarker(t)
	slot := cstiHTMLSlot()
	// A bundled SPA: script present, no engine named, corpus never populated.
	spa := "<html><head><script src=\"/static/main.9f2c.js\"></script></head><body><div id=\"app\">hello</div></body></html>"
	el := cstiAssess([]byte(spa), triage.AssetCorpus{})
	if gate, _, _ := cstiGate(el); gate != cstiGateUndetermined {
		t.Fatal("the bundled-SPA fixture did not land on the undetermined tier")
	}
	in := cstiPlanInput{
		Slot: slot, RespMedia: "text/html", ControlOK: true, El: el,
		ProductInCtrl: map[string]bool{}, SentProbes: map[triage.ProbeID]bool{},
	}
	read := cstiProbeRead{ProbeID: cstiProbeCS1, Ordinal: uint64(triage.ClassCSTI), Delivered: true,
		Survival: triage.WireSurvivalEncoded, Marker: m,
		Body:    []byte("<html><body><div>" + string(cstiBytesCS1) + "</div></body></html>"),
		Logical: cstiBytesCS1, Wire: []byte("%7B%7B7919%2A6271%7D%7D")}
	sum := cstiSummarise([]cstiProbeRead{read}, el, in.ProductInCtrl)
	v := cstiVerdict(cstiScoreEnvOK(slot), in, sum)
	if v.State != triage.StateCannotDetermine || !strings.Contains(v.Reason, cstiFidelityNoMarker) {
		t.Fatalf("state %s reason %q, want cannot_determine naming %s", v.State, v.Reason, cstiFidelityNoMarker)
	}
}

// TestTheAngularVersionIsReadFromTheServedHTMLWhenThereIsNoCorpus is the other half of "what can
// this class honestly do with HTTP alone".
//
// PlanCtx.Assets is never populated in this build, so the corpus version source is dead and the
// script URL in the served markup is the only one left. The version is not decoration: it picks
// the sandbox generation and the escape payload the row hands the operator.
func TestTheAngularVersionIsReadFromTheServedHTMLWhenThereIsNoCorpus(t *testing.T) {
	cases := []struct {
		name string
		html string
		want string
	}{
		{
			name: "the Google CDN path",
			html: `<html><head><script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.5.8/angular.min.js">` +
				`</script></head><body ng-app>hi</body></html>`,
			want: "1.5.8",
		},
		{
			name: "a versioned filename",
			html: `<html><head><script src="/static/angular-1.2.29.min.js"></script></head><body ng-app>hi</body></html>`,
			want: "1.2.29",
		},
		{
			name: "no version in the URL: none is invented",
			html: `<html><head><script src="/csti/angular.min.js"></script></head><body ng-app>hi</body></html>`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			el := cstiAssess([]byte(tc.html), triage.AssetCorpus{})
			if !el.has(cstiEngineAngularJS) {
				t.Fatal("AngularJS was not detected from the served HTML at all")
			}
			if got := el.versionOf(cstiEngineAngularJS); got != tc.want {
				t.Fatalf("version %q, want %q", got, tc.want)
			}
			if tc.want == "" {
				return
			}
			l := cstiLabelFor(el)
			if l.Hints["angularjs_version"] != tc.want {
				t.Errorf("the label does not carry the version, so the row names no sandbox and no escape")
			}
			if l.Hints["escape_payload"] == "" {
				t.Errorf("the label carries a version and no escape payload, which is the one thing the version is for")
			}
		})
	}
}

// TestTheCorpusVersionStillWinsOverTheURL: a filename is a claim and a fetched bundle is
// evidence, so the order matters and it is asserted rather than assumed.
func TestTheCorpusVersionStillWinsOverTheURL(t *testing.T) {
	html := `<html><head><script src="/static/angular-1.2.29.min.js"></script></head><body ng-app>hi</body></html>`
	el := cstiAssess([]byte(html), cstiCorpus(true, cstiAngularAsset))
	if got := el.versionOf(cstiEngineAngularJS); got != "1.5.8" {
		t.Fatalf("version %q, want the corpus's 1.5.8 rather than the URL's 1.2.29", got)
	}
}
