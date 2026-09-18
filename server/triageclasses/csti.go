package triageclasses

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLIENT SIDE TEMPLATE INJECTION (triage.ClassCSTI). CATALOGUE 1.10, research iso-client.md B.
//
// WHAT THIS CLASS ANSWERS. "Point domdig and dalfox at this slot, with these delimiters, against
// AngularJS 1.5.8 whose sandbox escape is X." It does NOT answer "is this exploitable". A CSTI
// payload proves a TEMPLATE ENGINE EVALUATED AN EXPRESSION, which is a different fact from an HTML
// parser opening a tag, and the two travel independently in both directions: an engine compiles
// {{ }} out of a fully HTML-escaped string, because no HTML encoder escapes a brace, and an app
// can allow a raw < on a page carrying no engine at all.
//
// =================================================================================================
// THE STRUCTURAL POINT, STATED BEFORE ANYTHING ELSE: CSTI NEEDS THE FRAMEWORK PRESENT.
// =================================================================================================
// Probing for Angular on a page with no Angular is pure waste, and concluding clean from it is a
// false negative with a green tick on it. So eligibility comes FIRST and it costs zero requests:
// it is read from the route control's own body and from the served-JavaScript corpus, both of
// which are unperturbed fetches and therefore controls, not any class's probe. On a page with no
// interpolating engine this class sends nothing at all and says not_applicable with the engine
// question named. That is the largest saving in the family and it comes from eligibility, never
// from borrowing another class's request.
//
// THE OTHER STRUCTURAL POINT: THE HTTP TIER CAN NEVER PRODUCE A CSTI FINDING, AND THIS FILE SAYS SO
// IN CODE RATHER THAN IN A COMMENT. The engine runs in the browser. An HTTP response can show that
// the delimiters SURVIVED into a region the detected engine compiles, which is
// suspicious (template_delimiters_reach_compiler) and is capped there by cstiHTTPCeiling. Only the
// browser navigation pair can show that the expression was EVALUATED, and that is the only path
// in this file that reaches StateFinding. A slot whose delimiters reached the compiler and whose
// navigation never ran is suspicious with the navigation named in Untested, never clean and never
// confirmed.
//
// THE THREE WAYS THIS CLASS CAN FAIL TO GET AN ANSWER, EACH WITH ITS OWN ROW:
//
//	not_applicable (no_client_template_engine)  the corpus was COMPLETE and held no engine
//	cannot_determine (framework_undetermined)   an asset did not fetch, so "no engine" is unproven
//	cannot_determine (needs_dom_run)            the delimiters arrived; nothing rendered them
//
// The first two are one grep apart and collapsing them is the mistake this layer exists to stop.
// A capped or partly-fetched corpus can never produce not_applicable here.
//
// WHY EVERY PAYLOAD IN THIS FILE IS THIS CLASS'S ALONE. The arithmetic pairs, the delimiter runs
// and the attribute probes are unique to CSTI by construction and are declared here in full, so
// CheckPayloadIsolation can see them. CSTI-CS1D shares the two bytes ${ with the XSS-R family's
// template-literal probe and nothing else: different marker stripe, different eligibility (this
// one is sent only when the corpus named a ${ } client engine), different detection rule,
// different verdict, and this class never reads another class's response. Two classes
// independently arriving at the same grammar is not sharing; one probe serving two classes is.
type cstiClassifier struct{}

func init() { triage.RegisterClassifier(cstiClassifier{}) }

func (cstiClassifier) ID() triage.ClassID { return triage.ClassCSTI }

// ---------------------------------------------------------------------------------------------
// THE ARITHMETIC, AND WHY NOT {{7*7}}
// ---------------------------------------------------------------------------------------------

// cstiPair is one multiplication and the exact decimal string a compiling engine renders for it.
//
// {{7*7}} renders 49, and 49 occurs in prices, dates, ids, CSS pixel values and base64 on very
// nearly every page, so a detector built on it fires on pages that did nothing. Four-digit primes
// give an eight-digit product, and the product is checked against the CONTROL body before the
// probe is planned (NC-B5), so a page that already prints the digits gets the next pair rather
// than a false positive.
type cstiPair struct {
	A, B    int
	Product string
}

// The pairs. The first two are the CATALOGUE's; the fourth is minted here because the HTTP tier
// and the browser tier must not share a product string.
//
// WHY THE TIERS GET DIFFERENT ARITHMETIC. The browser oracle reads the rendered outerHTML of a
// navigation. If the navigation payload carried the same digits as the HTTP probe, a cached or
// replayed HTTP body served into the browser would show the product and look like evaluation. With
// a different pair per tier, the digits in a browser capture can only have come from the browser
// probe's own expression, which is what makes CS-D3 a rank 1 deterministic-computation oracle
// rather than a correlation.
var (
	cstiPairHTTP       = cstiPair{7919, 6271, "49660049"}
	cstiPairHTTPAlt    = cstiPair{8147, 6329, "51562363"}
	cstiPairBrowser    = cstiPair{7793, 6299, "49088107"}
	cstiPairBrowserAlt = cstiPair{6113, 8017, "49007921"}
)

// Probe ids. The prefix is the class so an ordinal in a log names its owner without a lookup.
const (
	cstiProbeCS1      triage.ProbeID = "CSTI-CS1"     // default {{ }}
	cstiProbeCS1B     triage.ProbeID = "CSTI-CS1B"    // custom [[ ]]
	cstiProbeCS1C     triage.ProbeID = "CSTI-CS1C"    // custom <% %>
	cstiProbeCS1D     triage.ProbeID = "CSTI-CS1D"    // custom ${ }
	cstiProbeCS0Q     triage.ProbeID = "CSTI-CS0Q"    // ruling R4: can this slot create an attribute at all
	cstiProbeCS2      triage.ProbeID = "CSTI-CS2"     // AngularJS ng-init
	cstiProbeCS2V     triage.ProbeID = "CSTI-CS2V"    // Vue v-bind
	cstiProbeCS2A     triage.ProbeID = "CSTI-CS2A"    // Alpine x-init
	cstiProbeCS3      triage.ProbeID = "CSTI-CS3"     // Knockout data-bind
	cstiProbeNav      triage.ProbeID = "CSTI-NAV1"    // browser tier, payload navigation
	cstiProbeNavAlt   triage.ProbeID = "CSTI-NAV2"    // browser tier, fallback pair
	cstiProbeNavNC    triage.ProbeID = "CSTI-NAV1-NC" // browser tier, NC-B1 for NAV1
	cstiProbeNavNCAlt triage.ProbeID = "CSTI-NAV2-NC" // browser tier, NC-B1 for NAV2
)

// cstiMark is the runner's marker placeholder, and this class SPELLS IT rather than asking to
// have a marker glued on.
//
// THE DEFECT THIS REPLACES, MEASURED, EXAM 2e4433b1 AND REPRODUCED IN b65b3a3b. Every payload
// below used to be declared WITHOUT the marker, on the strength of ProbeSpec.MarkerPos being
// MarkerPrefix. MarkerPos is dead metadata: triageRenderPayload substitutes marker TOKENS that a
// payload spells and never reads MarkerPos at all, so what actually went on the wire for
// /csti/angular was
//
//	q=%7B%7B7919%2A6271%7D%7D
//
// with no marker anywhere in it. The delimiter run then came back in the document with no marker
// in front of it, cstiCensus counted every landing site as Unattributed, MarkerPresent was false,
// and the class reported cannot_determine (decode_depth_unknown) on its OWN positive control
// while the braces sat intact inside the ng-app subtree. A class whose attribution rule can never
// be satisfied is a class that can never fire, and the fidelity guard below now says so out loud
// instead of letting it read as a silence.
//
// NormaliseMarkers maps a real marker to this same token, so a payload written this way and a
// payload written with a literal marker are the same bytes to the isolation check. MarkerPos is
// still declared, and it now DESCRIBES where the placeholder sits (CMDI does the same) rather
// than asking the runner to do anything.
const cstiMark = triage.MarkerPlaceholder

// cstiMarked is the declared payload: this class's marker, then the run.
//
// THE CATALOGUE BRACKETS EACH PAYLOAD IN THE MARKER ON BOTH SIDES AND THIS FILE STILL DOES NOT.
// A trailing copy would be a second marker for the same probe, and the runner mints one. The
// attribution rule compensates: a delimiter run counts as this class's only when the marker
// occurs within cstiMarkerAdjacency bytes before it. That is weaker than a closing marker against
// an application that reflects the value twice adjacently, and it is recorded as a known
// divergence rather than papered over.
func cstiMarked(run []byte) []byte {
	out := make([]byte, 0, len(cstiMark)+len(run))
	out = append(out, cstiMark...)
	return append(out, run...)
}

// The exact logical bytes OF THE RUN, which is what this class searches for in a RESPONSE. The
// declared payload is cstiMarked(run); the two are kept apart because the census looks for the
// delimiters and checks the marker's adjacency separately, and searching a response for the
// marker and the run as one string would miss every application that inserts a wrapper between
// them.
var (
	cstiBytesCS1  = []byte(fmt.Sprintf("{{%d*%d}}", cstiPairHTTP.A, cstiPairHTTP.B))
	cstiBytesCS1B = []byte(fmt.Sprintf("[[%d*%d]]", cstiPairHTTP.A, cstiPairHTTP.B))
	cstiBytesCS1C = []byte(fmt.Sprintf("<%%=%d*%d%%>", cstiPairHTTP.A, cstiPairHTTP.B))
	cstiBytesCS1D = []byte(fmt.Sprintf("${%d*%d}", cstiPairHTTP.A, cstiPairHTTP.B))

	// CS-0q carries NO template syntax and NO arithmetic. Ruling R4: the four attribute payloads
	// welded a quote breakout to a template expression, so four hypotheses (quote escaped,
	// whitespace stripped, attribute-name filter, no engine) shared one observation. This probe
	// asks only "can this slot create an attribute", and the directive probes below are sent only
	// after it answered yes, so their silence is attributable to the template question alone.
	cstiBytesCS0Q = []byte(`" csti0q="1`)

	cstiBytesCS2  = []byte(fmt.Sprintf(`" ng-init="csti0q=%d*%d" q="`, cstiPairHTTP.A, cstiPairHTTP.B))
	cstiBytesCS2V = []byte(fmt.Sprintf(`" v-bind:title="%d*%d" q="`, cstiPairHTTP.A, cstiPairHTTP.B))
	cstiBytesCS2A = []byte(fmt.Sprintf(`" x-init="csti0q=%d*%d" q="`, cstiPairHTTP.A, cstiPairHTTP.B))
	cstiBytesCS3  = []byte(fmt.Sprintf(`" data-bind="text: %d*%d" q="`, cstiPairHTTP.A, cstiPairHTTP.B))

	cstiBytesNav      = []byte(fmt.Sprintf("{{%d*%d}}", cstiPairBrowser.A, cstiPairBrowser.B))
	cstiBytesNavAlt   = []byte(fmt.Sprintf("{{%d*%d}}", cstiPairBrowserAlt.A, cstiPairBrowserAlt.B))
	cstiBytesNavNC    = []byte(fmt.Sprintf("%d*%d", cstiPairBrowser.A, cstiPairBrowser.B))
	cstiBytesNavNCAlt = []byte(fmt.Sprintf("%d*%d", cstiPairBrowserAlt.A, cstiPairBrowserAlt.B))
)

// cstiMarkerAdjacency is how far before a delimiter run this class's marker may sit and still
// attribute the run to this class's probe. Sixty-four bytes covers an HTML-escaped marker, an
// inserted wrapper span and a sanitiser's whitespace, and stops short of attributing a run that
// belongs to a different reflection of a different value elsewhere in the same document.
const cstiMarkerAdjacency = 64

// The insertion points, straight from iso-client B.2.3.
var (
	// The CS-1 family goes everywhere: { } and * are raw-legal in a JSON string, inside
	// cookie-octet, and in a header field-vchar, and are percent-encoded by the runner in a query,
	// a form field and a path segment.
	cstiTextPoints = []triage.SlotKind{
		triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie, triage.KindPath,
	}
	cstiTextEncoders = []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodeMultipartValue,
		triage.EncodePathSegment, triage.EncodeHeaderValue, triage.EncodeCookie,
	}
	// The attribute family needs a RAW double quote, which a JSON string cannot deliver, and a
	// raw quote plus a SPACE, neither of which is inside cookie-octet. Body stays in Points
	// because a form or multipart body delivers both; Plan refuses the JSON sub-case and the
	// cookie case by name rather than by omission.
	cstiAttrPoints = []triage.SlotKind{
		triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie, triage.KindPath,
	}
	cstiAttrEncoders = []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeMultipartValue,
		triage.EncodePathSegment, triage.EncodeHeaderValue, triage.EncodeCookie,
	}
	// The browser tier is delivered by NAVIGATION, so it reaches the fragment (which no HTTP
	// request ever carries) and cannot reach a request body (domdig navigates, it does not reissue
	// a captured POST with a modified body).
	cstiNavPoints = []triage.SlotKind{
		triage.KindQuery, triage.KindPath, triage.KindFragment, triage.KindCookie, triage.KindHeader,
	}
	cstiNavEncoders = []triage.EncoderMode{
		triage.EncodeNone, triage.EncodeQuery, triage.EncodePathSegment,
		triage.EncodeCookie, triage.EncodeHeaderValue,
	}
)

// Probes is every payload this class will ever send.
//
// Plan's output is checked against this set by PlannedProbesAreDeclared, so a payload cannot be
// conjured at runtime and escape the build-time isolation check. Note that the fallback pairs are
// DECLARED PROBES rather than a runtime substitution into CS-1's bytes: a payload assembled at
// send time from a variant would never have been seen by CheckPayloadIsolation, and the law would
// then hold over the declared set and mean nothing about what went on the wire.
func (cstiClassifier) Probes() []triage.ProbeSpec {
	text := func(id triage.ProbeID, run []byte, tier triage.ProbeTier, notes string) triage.ProbeSpec {
		return triage.ProbeSpec{
			ID: id, Class: triage.ClassCSTI, Logical: cstiMarked(run),
			Encoders: cstiTextEncoders, Points: cstiTextPoints,
			MarkerPos: triage.MarkerPrefix, Tier: tier, Risk: triage.RiskR1, Notes: notes,
		}
	}
	attr := func(id triage.ProbeID, run []byte, notes string) triage.ProbeSpec {
		return triage.ProbeSpec{
			ID: id, Class: triage.ClassCSTI, Logical: cstiMarked(run),
			Encoders: cstiAttrEncoders, Points: cstiAttrPoints,
			MarkerPos: triage.MarkerPrefix, Tier: triage.TierFull, Risk: triage.RiskR1, Notes: notes,
		}
	}
	nav := func(id triage.ProbeID, run []byte, control bool, notes string) triage.ProbeSpec {
		return triage.ProbeSpec{
			ID: id, Class: triage.ClassCSTI, Logical: cstiMarked(run),
			Encoders: cstiNavEncoders, Points: cstiNavPoints,
			MarkerPos: triage.MarkerPrefix, Tier: triage.TierFull, Risk: triage.RiskR1,
			IsControl: control, Notes: notes,
		}
	}

	return []triage.ProbeSpec{
		text(cstiProbeCS1, cstiBytesCS1, triage.TierReduced,
			"the default {{ }} pair, which AngularJS 1.x, Vue 2, Vue 3 full build, Mustache, "+
				"Handlebars and Nunjucks all share. TierReduced because it is one request and it is "+
				"sent only when an interpolating engine was already detected for free."),
		text(cstiProbeCS1B, cstiBytesCS1B, triage.TierFull,
			"[[ ]], the most common $interpolateProvider and Vue delimiters: reconfigured "+
				"delimiters are the largest CSTI false negative there is. Sent when the corpus named "+
				"this pair, or unconditionally when the corpus is INCOMPLETE, because an incomplete "+
				"corpus cannot prove the defaults are in use."),
		text(cstiProbeCS1C, cstiBytesCS1C, triage.TierFull,
			"<% %>, Underscore, Lodash and browser-side EJS. Same sending rule as CS1B."),
		text(cstiProbeCS1D, cstiBytesCS1D, triage.TierFull,
			"${ }, sent ONLY when the corpus actually named a ${ } delimiter pair. Shares the two "+
				"bytes ${ with the XSS-R template-literal probe and nothing else: different stripe, "+
				"different eligibility, different rule, different verdict, and no shared response."),

		attr(cstiProbeCS0Q, cstiBytesCS0Q,
			"ruling R4. NO template syntax and NO arithmetic: it asks only whether this slot can "+
				"create an attribute whose name this class chose. Until it fires, silence from the "+
				"directive probes below is four hypotheses wearing one observation."),
		attr(cstiProbeCS2, cstiBytesCS2,
			"AngularJS ng-init, sent only after CS0Q created an attribute AND AngularJS was the "+
				"detected engine. Covers the common shape where braces are stripped from text and "+
				"attribute values are not filtered at all."),
		attr(cstiProbeCS2V, cstiBytesCS2V, "Vue v-bind, same rule, sent only for a detected Vue."),
		attr(cstiProbeCS2A, cstiBytesCS2A, "Alpine x-init, same rule, sent only for a detected Alpine."),
		attr(cstiProbeCS3, cstiBytesCS3,
			"Knockout binds through an attribute rather than a mustache, so it has no CS-1 form at "+
				"all and this is its only probe."),

		nav(cstiProbeNav, cstiBytesNav, false,
			"CS-D3, the class's real oracle. Its arithmetic differs from the HTTP tier's so that "+
				"digits in a rendered capture cannot have come from a replayed HTTP body."),
		nav(cstiProbeNavAlt, cstiBytesNavAlt, false,
			"the browser fallback pair, planned when the control body already prints "+
				cstiPairBrowser.Product+". NC-B5 says mint the next pair rather than send a probe "+
				"whose expected string is already on the page."),
		nav(cstiProbeNavNC, cstiBytesNavNC, true,
			"NC-B1. The same arithmetic with NO delimiters. Without it a calculator endpoint that "+
				"multiplies its own parameter is a CSTI finding. If this control's digits render, "+
				"the application computes the product itself and the whole slot is "+
				"cannot_determine (control_contaminated), never a finding."),
		nav(cstiProbeNavNCAlt, cstiBytesNavNCAlt, true, "NC-B1 for the fallback pair."),
	}
}

// Reaches. Every answer is conditional and every one carries its condition, because ReachNever
// with no reason and "nobody wired this up" are the same pixel in a report and completely
// different facts.
//
// NOTHING HERE IS ReachNever, INCLUDING THE FRAGMENT, and that is the interesting one. A fragment
// never leaves the browser, so every HTTP-level tool is structurally blind to it, and this class
// would be too if it stopped at the HTTP tier. It does not: #{{7919*6271}} against an AngularJS
// app with $location in hash mode is a classic live case, and the browser tier delivers it by
// navigation. So the fragment is conditional on the browser tier being available, and a fragment
// slot with no browser run is cannot_determine (needs_dom_run), never clean.
func (cstiClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery, triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "an interpolating client engine must be present, and the braces are not pchar " +
				"so a slot measured at decode_depth 0 receives them as literal %7B and is not_reachable (pct_literal)",
		}
	case triage.KindBody:
		if mt == "application/json" {
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "an engine must be present; the CS-1 family is raw-legal inside a JSON string, " +
					"but the attribute family needs a raw double quote and is not_reachable (json_string) here",
			}
		}
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "an engine must be present; a form or multipart body carries every payload in this " +
				"class, but the BROWSER tier cannot deliver a body at all, so a body slot is capped at the HTTP tier",
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "an engine must be present. Printing Referer or X-Forwarded-Host inside the ng-app " +
				"subtree is a real and under-tested CSTI surface, and every byte in this class is a header field-vchar",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "an engine must be present; braces, star and equals are all inside cookie-octet so the " +
				"CS-1 family goes raw, while the attribute family needs a quote and a space and is " +
				"not_reachable (cookie_octet) unless the slot was measured at decode_depth 1 or more",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "HTTP tier not_applicable (fragment): it is never transmitted. BROWSER tier fully " +
				"applicable and important, delivered by navigating to the composed URL",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "slot kind " + string(k) + " is outside the closed set this class was written against",
		}
	}
}

// ---------------------------------------------------------------------------------------------
// ELIGIBILITY. ZERO REQUESTS, AND IT DECIDES EVERYTHING ELSE.
// ---------------------------------------------------------------------------------------------

type cstiEngine string

const (
	cstiEngineAngularJS  cstiEngine = "angularjs"
	cstiEngineVue2       cstiEngine = "vue2"
	cstiEngineVue3       cstiEngine = "vue3"
	cstiEngineAlpine     cstiEngine = "alpine"
	cstiEngineKnockout   cstiEngine = "knockout"
	cstiEngineHandlebars cstiEngine = "handlebars"
	cstiEngineUnderscore cstiEngine = "underscore"
	cstiEngineNunjucks   cstiEngine = "nunjucks"
	cstiEngineAngularAOT cstiEngine = "angular_aot"
	cstiEngineEmber      cstiEngine = "ember"
	cstiEngineReactLike  cstiEngine = "react_like"
)

type cstiEngineHit struct {
	Engine  cstiEngine
	Version string
	Why     string
}

// cstiEligibility is the whole cost model of this class, and it is derived from two unperturbed
// fetches: the route control's body and the served-JS corpus.
type cstiEligibility struct {
	// Interpolating are engines that compile an in-DOM template at runtime. Only these make CSTI
	// by interpolation possible.
	Interpolating []cstiEngineHit
	// Precompiled are Angular 2+, Ember and the React family. Their equivalent bug is a trusted
	// HTML sink, which is DOM XSS and another class's finding, so they are not_applicable HERE and
	// recording clean for them would be wrong in both directions.
	Precompiled []cstiEngineHit

	VueSeen        bool
	VueFullBuild   bool
	VueBuildKnown  bool
	CorpusComplete bool
	// CustomDelims are pairs the corpus actually named, through startSymbol/endSymbol,
	// delimiters:, templateSettings or Mustache.tags.
	CustomDelims [][2]string
	DollarBrace  bool
	// BootstrapAtDocument means the corpus calls angular.bootstrap(document or applies Knockout
	// bindings with no element, so the compiled region is the whole body with low confidence.
	BootstrapAtDocument bool
	MountSelectors      []string
	AngularCSPMode      bool

	// ControlBodySeen is false when there was no unperturbed body to read at all. Without it,
	// "this document has no script" and "nobody fetched this document" are the same false, and
	// the first is a not_applicable while the second is a cannot_determine.
	ControlBodySeen bool
	// ControlTruncated is set by the caller from the control observation, because cstiAssess
	// receives a byte slice and a byte slice cannot say whether it is the whole response. A
	// truncated body can never support "there is no script on this page".
	ControlTruncated bool
	// ControlIsDocument is whether the control body is markup at all. It guards the no-script
	// rule below: "this document runs no script" is a true and completely misleading thing to say
	// about a text/plain body, whose real answer is that a client engine compiles a DOM and this
	// response is not one. Without this the plain-text routes get the wrong reason on the row.
	ControlIsDocument bool
	// DocumentHasScript is the cheapest eligibility fact in the class and the one that decides
	// whether an incomplete corpus matters at all. An AssetCorpus is built from the files this
	// document REFERENCES, so a document that references no script, carries no inline script and
	// carries no event-handler attribute has nothing for the corpus to be incomplete ABOUT: no
	// interpolating engine can be running, and the absence is proven from the control alone.
	DocumentHasScript bool
}

func (e cstiEligibility) engineNames() []string {
	out := make([]string, 0, len(e.Interpolating))
	for _, h := range e.Interpolating {
		out = append(out, string(h.Engine))
	}
	return out
}

func (e cstiEligibility) has(want cstiEngine) bool {
	for _, h := range e.Interpolating {
		if h.Engine == want {
			return true
		}
	}
	return false
}

func (e cstiEligibility) versionOf(want cstiEngine) string {
	for _, h := range e.Interpolating {
		if h.Engine == want {
			return h.Version
		}
	}
	return ""
}

// The cheap signatures. Every one of these is read from bytes the target served without any
// payload in the request, which is why the whole of eligibility costs nothing.
var (
	cstiReAngularAttr = regexp.MustCompile(`(?i)(data-|x-)?ng[-:](app|controller|repeat|bind|model|if|show|hide|class|click|init|include|view|src|href|style|options|cloak|non-bindable)\b`)
	cstiReAngularCls  = regexp.MustCompile(`(?i)\b(ng-scope|ng-binding|ng-isolate-scope|ng-pristine|ng-valid)\b`)
	cstiReAngularSrc  = regexp.MustCompile(`(?i)angular(\.min)?\.js|angular[-.]1\.|angularjs`)
	cstiReAngularCode = regexp.MustCompile(`angular\.module\(|angular\.bootstrap\(|\$compileProvider|\$interpolateProvider`)
	cstiReAngularAOT  = regexp.MustCompile(`(?i)ng-version="|_nghost-|_ngcontent-|<app-root`)
	cstiReAngularVer  = regexp.MustCompile(`full:\s*["']([0-9]+\.[0-9]+\.[0-9]+)`)
	// cstiReAngularVerURL reads the version out of the SCRIPT URL in the served HTML, which is
	// the only version source this build has without a served-JavaScript corpus.
	//
	// WHY IT IS WORTH A REGEXP. The version is not decoration: cstiAngularSandbox turns it into
	// the sandbox generation and the exact escape payload for that generation, and "AngularJS,
	// version unknown" versus "AngularJS 1.5.8, sandboxed, and here is the escape" is the whole
	// difference between a row an operator can act on and a row they have to research. The two
	// shapes below are the ones that carry a version in the markup: the Google CDN path
	// (/ajax/libs/angularjs/1.5.8/angular.min.js) and the versioned filename
	// (angular-1.5.8.min.js). A file called angular.min.js carries no version and none is
	// invented for it: the hint is simply absent, which is the honest answer.
	cstiReAngularVerURL = regexp.MustCompile(`(?i)angular(?:js)?[/-]([0-9]+\.[0-9]+\.[0-9]+)`)
	cstiReAngularCSP    = regexp.MustCompile(`(?i)\bng-csp\b`)

	cstiReVue2Code = regexp.MustCompile(`new Vue\(|Vue\.component\(|__vue__`)
	cstiReVue3Code = regexp.MustCompile(`createApp\(|__vue_app__|data-v-app`)
	cstiReVueSrc   = regexp.MustCompile(`(?i)vue(\.min|\.runtime|\.esm)?\.js|vue\.global(\.prod)?\.js|vue\.esm-browser`)
	cstiReVueAttr  = regexp.MustCompile(`(?i)\bv-(if|else|for|bind|on|model|html|text|show|cloak|pre|once)\b`)
	cstiReVueVer   = regexp.MustCompile(`(?i)(?:Vue\.js v|@vue/runtime-dom v|version\s*[:=]\s*["'])([0-9]+\.[0-9]+\.[0-9]+)`)

	cstiReAlpine     = regexp.MustCompile(`(?i)\bx-(data|text|html|init)\b|Alpine\.start\(|alpine(\.min)?\.js`)
	cstiReKnockout   = regexp.MustCompile(`data-bind=|ko\.applyBindings\(`)
	cstiReHandlebars = regexp.MustCompile(`(?i)text/x-handlebars-template|Handlebars\.compile\(|\{\{#each|\{\{\{`)
	cstiReUnderscore = regexp.MustCompile(`(?i)text/template|_\.template\(`)
	cstiReNunjucks   = regexp.MustCompile(`nunjucks\.(configure|renderString)\(`)
	cstiReEmber      = regexp.MustCompile(`(?i)ember(\.min|\.debug)?\.js|data-ember-`)
	cstiReReactLike  = regexp.MustCompile(`(?i)react(-dom)?(\.production|\.development)?(\.min)?\.js|data-reactroot|__svelte|_\$HY\b`)

	// The Vue build discriminator, which is the cheap eligibility test most scanners miss: only
	// the FULL build compiles an in-DOM template, so mustache reflected into server HTML against a
	// runtime-only build is never compiled at all.
	cstiReVueRuntimeOnly  = regexp.MustCompile(`runtime compilation is not supported|runtime-only build`)
	cstiReVueCompiler     = regexp.MustCompile(`compileToFunction|@vue/compiler-dom`)
	cstiReVueCompilerWeak = regexp.MustCompile(`compilerOptions`)

	cstiReDelimAngular = regexp.MustCompile(`(?:startSymbol|endSymbol)\s*\(\s*["']([^"']{1,8})["']`)
	cstiReDelimVue     = regexp.MustCompile(`delimiters\s*:\s*\[\s*["']([^"']{1,8})["']\s*,\s*["']([^"']{1,8})["']`)
	cstiReDelimLodash  = regexp.MustCompile(`interpolate\s*:\s*/([^/]{1,24})/`)
	cstiReDelimMustach = regexp.MustCompile(`tags\s*:\s*\[\s*["']([^"']{1,8})["']\s*,\s*["']([^"']{1,8})["']`)

	cstiReMountVue   = regexp.MustCompile(`\.mount\(\s*["']([^"']{1,64})["']|el\s*:\s*["']([^"']{1,64})["']`)
	cstiReBootstrapA = regexp.MustCompile(`angular\.bootstrap\(\s*document|ko\.applyBindings\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)`)

	// cstiReAnyScript is deliberately WIDER than any engine signature. It is used only to decide
	// that a document runs NO script at all, which is a claim that must fail closed, so it counts
	// a script element, an inline event-handler attribute, a javascript: URL, a module preload
	// and a bare import(), and anything it is unsure about reads as "there is script here".
	cstiReAnyScript = regexp.MustCompile(`(?i)<script\b|</script>|\bon[a-z]{3,15}\s*=\s*["']|javascript:|rel\s*=\s*["']?modulepreload|\bimport\s*\(`)

	// cstiReIsDocument asks only whether the control body is markup. It is wide on purpose: a
	// body it is unsure about counts as a document, which keeps the no-script rule from claiming
	// not_applicable on something it did not recognise.
	cstiReIsDocument = regexp.MustCompile(`(?i)<!doctype|<html\b|<head\b|<body\b|<div\b|<svg\b|<\?xml`)
)

// cstiAssess reads eligibility from the control body and the corpus, and from nothing else.
func cstiAssess(controlBody []byte, assets triage.AssetCorpus) cstiEligibility {
	el := cstiEligibility{
		CorpusComplete:    assets.Complete(),
		ControlBodySeen:   len(controlBody) > 0,
		ControlIsDocument: cstiReIsDocument.Match(controlBody),
		DocumentHasScript: cstiReAnyScript.Match(controlBody),
	}

	corpus := make([]byte, 0, 4096)
	for _, f := range assets.Files {
		corpus = append(corpus, f.Body...)
		corpus = append(corpus, '\n')
	}
	both := func(re *regexp.Regexp) bool { return re.Match(controlBody) || re.Match(corpus) }

	// AngularJS 1.x. The runtime-added class tokens count as positive evidence even in server
	// HTML: they mean a snapshot or an SSR of a page the framework runs on.
	if cstiReAngularAttr.Match(controlBody) || cstiReAngularCls.Match(controlBody) ||
		cstiReAngularSrc.Match(controlBody) || both(cstiReAngularCode) {
		hit := cstiEngineHit{Engine: cstiEngineAngularJS, Why: "an ng- attribute, class token, script src or angular.module call"}
		if m := cstiReAngularVer.FindSubmatch(corpus); m != nil {
			hit.Version = string(m[1])
		} else if m := cstiReAngularVerURL.FindSubmatch(controlBody); m != nil {
			// The corpus is never populated in this build, so the served HTML is the only place a
			// version can come from. It is read SECOND, so a fetched bundle that states its own
			// version always wins over a filename that may be a cache-busting lie.
			hit.Version = string(m[1])
			hit.Why += " (version read from the script URL in the served HTML, not from the file itself)"
		}
		el.Interpolating = append(el.Interpolating, hit)
	}
	if cstiReAngularCSP.Match(controlBody) {
		// ng-csp disables the Function-constructor escapes and NOT expression evaluation, so it
		// changes the payload handed to the operator and never eligibility.
		el.AngularCSPMode = true
	}
	if cstiReAngularAOT.Match(controlBody) {
		el.Precompiled = append(el.Precompiled, cstiEngineHit{
			Engine: cstiEngineAngularAOT,
			Why:    "ng-version, _nghost-, _ngcontent- or an <app-root> element: templates are compiled ahead of time",
		})
	}
	if cstiReEmber.Match(controlBody) {
		el.Precompiled = append(el.Precompiled, cstiEngineHit{
			Engine: cstiEngineEmber, Why: "Ember precompiles Handlebars, so server HTML is never interpolated",
		})
	}
	if cstiReReactLike.Match(controlBody) {
		el.Precompiled = append(el.Precompiled, cstiEngineHit{
			Engine: cstiEngineReactLike,
			Why:    "React, Preact, Svelte or Solid: no runtime interpolation of DOM text, their equivalent bug is a trusted HTML sink",
		})
	}

	// Vue, and the build question that decides whether it is eligible at all.
	vue2 := cstiReVue2Code.Match(controlBody) || cstiReVue2Code.Match(corpus)
	vue3 := cstiReVue3Code.Match(controlBody) || cstiReVue3Code.Match(corpus)
	if vue2 || vue3 || cstiReVueSrc.Match(controlBody) || cstiReVueAttr.Match(controlBody) {
		el.VueSeen = true
		// The build discriminator runs over the WHOLE corpus and not over files whose URL looks
		// like Vue, because a bundled application serves Vue inside main.<hash>.js and a
		// URL-shaped test then leaves every bundled site permanently undetermined.
		//
		// A compiler entry point WINS over the runtime-only warning string, which is the order
		// the Vue docs describe: the runtime-only build names itself, the full build ships the
		// compiler, and a bundle holding both strings is one that contains the compiler.
		switch {
		case cstiReVueCompiler.Match(corpus):
			el.VueFullBuild, el.VueBuildKnown = true, true
		case cstiReVueRuntimeOnly.Match(corpus):
			el.VueFullBuild, el.VueBuildKnown = false, true
		case cstiReVueCompilerWeak.Match(corpus):
			// compilerOptions on its own is the weakest of the three signals, so it decides only
			// when neither of the definite ones is present.
			el.VueFullBuild, el.VueBuildKnown = true, true
		}
		if el.VueFullBuild {
			engine, why := cstiEngineVue2, "Vue 2 full build, which compiles an in-DOM template"
			if vue3 {
				engine, why = cstiEngineVue3, "Vue 3 full build, which compiles an in-DOM template"
			}
			hit := cstiEngineHit{Engine: engine, Why: why}
			if m := cstiReVueVer.FindSubmatch(corpus); m != nil {
				hit.Version = string(m[1])
			}
			el.Interpolating = append(el.Interpolating, hit)
		}
	}

	if cstiReAlpine.Match(controlBody) || cstiReAlpine.Match(corpus) {
		el.Interpolating = append(el.Interpolating, cstiEngineHit{Engine: cstiEngineAlpine, Why: "x-data, x-text or Alpine.start"})
	}
	if cstiReKnockout.Match(controlBody) {
		el.Interpolating = append(el.Interpolating, cstiEngineHit{Engine: cstiEngineKnockout, Why: "data-bind or ko.applyBindings"})
	}
	if cstiReHandlebars.Match(controlBody) {
		el.Interpolating = append(el.Interpolating, cstiEngineHit{Engine: cstiEngineHandlebars, Why: "a client-side Handlebars or Mustache template block"})
	}
	if cstiReUnderscore.Match(controlBody) {
		el.Interpolating = append(el.Interpolating, cstiEngineHit{Engine: cstiEngineUnderscore, Why: "an Underscore or Lodash template block"})
	}
	if cstiReNunjucks.Match(corpus) || cstiReNunjucks.Match(controlBody) {
		el.Interpolating = append(el.Interpolating, cstiEngineHit{Engine: cstiEngineNunjucks, Why: "nunjucks in the browser"})
	}

	// Custom delimiters, the largest CSTI false negative there is.
	for _, m := range cstiReDelimAngular.FindAllSubmatch(corpus, 4) {
		el.CustomDelims = append(el.CustomDelims, [2]string{string(m[1]), ""})
	}
	for _, re := range []*regexp.Regexp{cstiReDelimVue, cstiReDelimMustach} {
		for _, m := range re.FindAllSubmatch(corpus, 4) {
			el.CustomDelims = append(el.CustomDelims, [2]string{string(m[1]), string(m[2])})
		}
	}
	if cstiReDelimLodash.Match(corpus) {
		el.CustomDelims = append(el.CustomDelims, [2]string{"<%", "%>"})
	}
	for _, d := range el.CustomDelims {
		// A ${ } engine is the only reason CS-1D is ever sent, so the test is on the OPENING
		// delimiter the corpus actually named and not on a loose dollar sign anywhere.
		if strings.Contains(d[0], "${") {
			el.DollarBrace = true
		}
	}

	el.BootstrapAtDocument = cstiReBootstrapA.Match(corpus) || cstiReBootstrapA.Match(controlBody)
	for _, m := range cstiReMountVue.FindAllSubmatch(corpus, 8) {
		for _, g := range m[1:] {
			if len(g) > 0 {
				el.MountSelectors = append(el.MountSelectors, string(g))
			}
		}
	}
	return el
}

// cstiGateResult is the gate's THREE answers, and the third one is the whole point of this type.
//
// THE DEFECT THIS REPLACES. The gate used to return a bool. Its reason string already told "no
// engine" apart from "could not tell", and the bool then folded them back together: both were
// false, both planned zero probes, and on a runner whose PlanCtx.Assets is never populated the
// SECOND one is the case on every route of every target. So an operator switched CSTI on, the
// class sent planned=0 sent=0 everywhere, and the row said cannot_determine with a reason nobody
// reads as loudly as they read an empty findings list. A toggle that does nothing is the false
// negative this layer exists to stop, and it was being delivered by the gate's return type.
//
// The three answers are now distinct at the PLAN level and not only in the prose:
//
//	cstiGateEligible      an interpolating engine is PRESENT. Full ladder, every tier, and the
//	                      browser tier can still reach a finding.
//	cstiGateUndetermined  the engine question could not be answered. ONE request goes out, it
//	                      answers the HTTP-only half of the question (do this class's delimiters
//	                      survive into the document), and NOTHING it can observe may exceed
//	                      cannot_determine. It is never clean, never suspicious, never a finding.
//	cstiGateIneligible    the absence is PROVEN from bytes in hand. Zero requests, not_applicable.
type cstiGateResult int

const (
	cstiGateEligible cstiGateResult = iota
	cstiGateUndetermined
	cstiGateIneligible
)

// cstiGate turns eligibility into a decision, and it is where "no engine", "could not tell" and
// "could not tell, so measure the half that needs no engine" stop being the same row.
func cstiGate(el cstiEligibility) (gate cstiGateResult, state triage.TriageState, reason string) {
	if len(el.Interpolating) > 0 {
		return cstiGateEligible, "", ""
	}
	if el.VueSeen && el.VueBuildKnown && !el.VueFullBuild {
		return cstiGateIneligible, triage.StateNotApplicable, "vue_runtime_only: the served Vue build names itself runtime-only " +
			"and cannot compile an in-DOM template, so a mustache reflected into this document is never compiled"
	}
	if el.VueSeen && !el.VueBuildKnown {
		return cstiGateUndetermined, triage.StateCannotDetermine, "framework_undetermined: Vue is on the page but its build was not " +
			"fetched, and full versus runtime-only is exactly the difference between eligible and inert. Not not_applicable"
	}
	if len(el.Precompiled) > 0 {
		names := make([]string, 0, len(el.Precompiled))
		for _, h := range el.Precompiled {
			names = append(names, string(h.Engine)+" ("+h.Why+")")
		}
		return cstiGateIneligible, triage.StateNotApplicable, "angular_aot: " + strings.Join(names, "; ") +
			". CSTI by interpolation cannot exist here. The equivalent bug is a trusted HTML sink, which is the DOM XSS class's finding, not this one"
	}
	if !el.CorpusComplete {
		// THE ONE CASE AN INCOMPLETE CORPUS CANNOT HIDE. An AssetCorpus holds the files this
		// document references. A document that references no script, carries no inline script and
		// carries no event-handler attribute has nothing for the corpus to be incomplete about,
		// so the absence of an engine is proven from the control body alone and this is an honest
		// not_applicable rather than a permanent unknown. It needs the WHOLE control body: a
		// truncated one could be hiding the script tag, and an unfetched one proves nothing.
		if el.ControlBodySeen && el.ControlIsDocument && !el.ControlTruncated && !el.DocumentHasScript {
			return cstiGateIneligible, triage.StateNotApplicable, "no_script_in_document: the control body is complete, " +
				"references no script, carries no inline script and carries no event-handler attribute, so nothing on this " +
				"page can run a client template engine and the capped corpus has nothing left to be incomplete about"
		}
		return cstiGateUndetermined, triage.StateCannotDetermine, "framework_undetermined: no interpolating engine was found, and the " +
			"served-JavaScript corpus was capped or partly unfetched, so the absence is unproven. A capped corpus can never produce not_applicable"
	}
	return cstiGateIneligible, triage.StateNotApplicable, "no_client_template_engine: the control body and a COMPLETE served-JavaScript " +
		"corpus hold no interpolating client engine, so there is nothing on this page to compile a template expression"
}

// ---------------------------------------------------------------------------------------------
// THE REGION SCANNER. WHERE THE DELIMITERS LANDED IS THE WHOLE HTTP-TIER RULE.
// ---------------------------------------------------------------------------------------------

type cstiSpan struct{ start, end int }

func (s cstiSpan) contains(off int) bool { return off >= s.start && off < s.end }

// cstiDocRegions is the parsed shape of one document, reduced to the five questions the detection
// rule asks. It is deliberately not a DOM: the rule needs containment, not a tree.
type cstiDocRegions struct {
	scripts    []cstiSpan
	comments   []cstiSpan
	templates  []cstiSpan
	suppressed []cstiSpan // ng-non-bindable, v-pre, x-ignore
	compiled   []cstiSpan
	// compiledResolved is false when no mount point could be resolved and the whole body was used
	// as the compiled region. A candidate found that way is low confidence, and, more importantly,
	// the ABSENCE of a candidate found that way can never support clean.
	compiledResolved bool
}

type cstiRegion struct {
	InScript   bool
	InComment  bool
	InTemplate bool
	Suppressed bool
	InCompiled bool
}

// Compiles reports whether the detected engine would compile text at this offset.
func (r cstiRegion) Compiles() bool {
	return r.InCompiled && !r.InScript && !r.InComment && !r.InTemplate && !r.Suppressed
}

func (d cstiDocRegions) at(off int) cstiRegion {
	var r cstiRegion
	for _, s := range d.scripts {
		if s.contains(off) {
			r.InScript = true
		}
	}
	for _, s := range d.comments {
		if s.contains(off) {
			r.InComment = true
		}
	}
	for _, s := range d.templates {
		if s.contains(off) {
			r.InTemplate = true
		}
	}
	for _, s := range d.suppressed {
		if s.contains(off) {
			r.Suppressed = true
		}
	}
	for _, s := range d.compiled {
		if s.contains(off) {
			r.InCompiled = true
		}
	}
	return r
}

var cstiVoidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
	"img": true, "input": true, "link": true, "meta": true, "param": true,
	"source": true, "track": true, "wbr": true,
}

var (
	cstiReAttrSuppress = regexp.MustCompile(`(?i)(^|[\s"'])((data-)?ng[-:]non-bindable|v-pre|x-ignore)([\s=/>]|$)`)
	cstiReAttrNgApp    = regexp.MustCompile(`(?i)(^|[\s"'])(data-|x-)?ng[-:]app([\s=/>]|$)`)
	cstiReAttrXData    = regexp.MustCompile(`(?i)(^|[\s"'])x-data([\s=/>]|$)`)
	cstiReAttrID       = regexp.MustCompile(`(?i)\bid\s*=\s*["']?([a-zA-Z0-9_:.-]+)`)
	cstiReAttrClass    = regexp.MustCompile(`(?i)\bclass\s*=\s*["']([^"']*)["']`)
)

func cstiIsNameByte(b byte) bool {
	return b == '-' || b == '_' || b == ':' ||
		(b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// cstiIndexFold is a case-insensitive substring search that does not copy the haystack. The
// obvious bytes.Index(bytes.ToLower(body[i:]), ...) inside the tag loop copies the tail of the
// document once per script tag, which on a 512 KiB capped body with a script-heavy page is
// quadratic for no reason.
func cstiIndexFold(hay []byte, needle string) int {
	n := len(needle)
	if n == 0 || len(hay) < n {
		return -1
	}
	low := strings.ToLower(needle)
	for i := 0; i+n <= len(hay); i++ {
		match := true
		for j := 0; j < n; j++ {
			c := hay[i+j]
			if c >= 'A' && c <= 'Z' {
				c += 'a' - 'A'
			}
			if c != low[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// cstiScanRegions walks the tags once and records the spans the detection rule asks about.
//
// WHY NOT A REAL PARSER. The allow-list gives this package bytes, regexp and strings, and the four
// questions here (script, comment, template, disabled-subtree, compiled-subtree) are containment
// questions that a tag walk answers directly. What it must NOT do is guess: an unclosed element
// extends to the end of the document, which over-reports the suppressed and compiled spans, and
// over-reporting suppressed can only LOSE a candidate, so the caller treats a document whose
// compiled root was never resolved as low confidence rather than as evidence of absence.
func cstiScanRegions(body []byte, mountSelectors []string, wholeBodyFallback bool) cstiDocRegions {
	var d cstiDocRegions
	type openElem struct {
		name       string
		start      int
		suppressed bool
		compiled   bool
	}
	var stack []openElem
	bodyElem := cstiSpan{-1, -1}

	closeOut := func(e openElem, end int) {
		sp := cstiSpan{e.start, end}
		if e.suppressed {
			d.suppressed = append(d.suppressed, sp)
		}
		if e.compiled {
			d.compiled = append(d.compiled, sp)
		}
		if e.name == "template" {
			d.templates = append(d.templates, sp)
		}
		if e.name == "body" {
			bodyElem = sp
		}
	}

	i := 0
	for i < len(body) {
		rel := bytes.IndexByte(body[i:], '<')
		if rel < 0 {
			break
		}
		p := i + rel

		if bytes.HasPrefix(body[p:], []byte("<!--")) {
			end := bytes.Index(body[p+4:], []byte("-->"))
			if end < 0 {
				d.comments = append(d.comments, cstiSpan{p, len(body)})
				break
			}
			d.comments = append(d.comments, cstiSpan{p, p + 4 + end + 3})
			i = p + 4 + end + 3
			continue
		}
		if p+1 < len(body) && (body[p+1] == '!' || body[p+1] == '?') {
			gt := bytes.IndexByte(body[p:], '>')
			if gt < 0 {
				break
			}
			i = p + gt + 1
			continue
		}

		closing := p+1 < len(body) && body[p+1] == '/'
		ns := p + 1
		if closing {
			ns++
		}
		j := ns
		for j < len(body) && cstiIsNameByte(body[j]) {
			j++
		}
		if j == ns {
			i = p + 1 // a bare '<' in text, not a tag
			continue
		}
		name := strings.ToLower(string(body[ns:j]))

		k, quote := j, byte(0)
		for k < len(body) {
			c := body[k]
			switch {
			case quote != 0:
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
			case c == '>':
				quote = 0
			}
			if quote == 0 && c == '>' {
				break
			}
			k++
		}
		if k >= len(body) {
			break
		}
		tagEnd := k + 1
		attrs := body[j:k]

		if closing {
			for n := len(stack) - 1; n >= 0; n-- {
				if stack[n].name != name {
					continue
				}
				for m := len(stack) - 1; m >= n; m-- {
					closeOut(stack[m], tagEnd)
				}
				stack = stack[:n]
				break
			}
			i = tagEnd
			continue
		}

		if name == "script" || name == "style" {
			end := len(body)
			if r := cstiIndexFold(body[tagEnd:], "</"+name); r >= 0 {
				if g := bytes.IndexByte(body[tagEnd+r:], '>'); g >= 0 {
					end = tagEnd + r + g + 1
				} else {
					end = tagEnd + r
				}
			}
			d.scripts = append(d.scripts, cstiSpan{p, end})
			i = end
			continue
		}
		if cstiVoidElements[name] || bytes.HasSuffix(bytes.TrimRight(attrs, " \t\r\n"), []byte("/")) {
			i = tagEnd
			continue
		}

		stack = append(stack, openElem{
			name:       name,
			start:      p,
			suppressed: cstiReAttrSuppress.Match(cstiAttrNamesOnly(attrs)),
			compiled:   cstiAttrsOpenACompiledRoot(attrs, mountSelectors),
		})
		i = tagEnd
	}
	for m := len(stack) - 1; m >= 0; m-- {
		closeOut(stack[m], len(body))
	}

	d.compiledResolved = len(d.compiled) > 0
	if !d.compiledResolved && wholeBodyFallback {
		if bodyElem.start >= 0 {
			d.compiled = append(d.compiled, bodyElem)
		} else {
			d.compiled = append(d.compiled, cstiSpan{0, len(body)})
		}
	}
	return d
}

// cstiAttrNamesOnly blanks out every quoted attribute VALUE, leaving the names.
//
// WHY IT EXISTS. Matching ng-non-bindable against the raw attribute text makes
// <div title="use v-pre to disable binding"> a suppressed element, and a suppressed element
// silently LOSES a candidate. Over-suppression is the false-negative direction, which is the
// expensive one, so the name tests run over names.
func cstiAttrNamesOnly(attrs []byte) []byte {
	out := make([]byte, len(attrs))
	copy(out, attrs)
	quote := byte(0)
	for i := 0; i < len(out); i++ {
		c := out[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			out[i] = ' '
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			out[i] = ' '
		}
	}
	return out
}

func cstiAttrsOpenACompiledRoot(attrs []byte, mountSelectors []string) bool {
	if names := cstiAttrNamesOnly(attrs); cstiReAttrNgApp.Match(names) || cstiReAttrXData.Match(names) {
		return true
	}
	for _, sel := range mountSelectors {
		sel = strings.TrimSpace(sel)
		if len(sel) < 2 {
			continue
		}
		switch sel[0] {
		case '#':
			if m := cstiReAttrID.FindSubmatch(attrs); m != nil && string(m[1]) == sel[1:] {
				return true
			}
		case '.':
			if m := cstiReAttrClass.FindSubmatch(attrs); m != nil {
				for _, tok := range strings.Fields(string(m[1])) {
					if tok == sel[1:] {
						return true
					}
				}
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// READING ONE RESPONSE. PURE, SO THE TESTS CAN DRIVE IT DIRECTLY.
// ---------------------------------------------------------------------------------------------

// cstiProbeRead is one of this class's own observations, reduced to what the rules read. Classify
// builds these from ctx.Own; the tests build them literally, because OwnedResponses can only be
// constructed by the runner and a detection rule that can only be exercised through the runner is
// a detection rule nobody tests.
type cstiProbeRead struct {
	ProbeID   triage.ProbeID
	Ordinal   uint64
	Delivered bool
	Survival  triage.WireSurvival
	Marker    triage.Marker
	Body      []byte
	Truncated bool
	// Logical and Wire are what the runner recorded as having been ASKED FOR and as having gone
	// out. They are read by cstiFidelity, which is the guard that stops an integration bug in the
	// send path from becoming a corpus of silences: this class's entire attribution rule is "the
	// marker sits in front of the run", so a wire form with no marker in it makes every landing
	// site unattributable and every response unreadable, and that must be said rather than scored.
	Logical []byte
	Wire    []byte
	// Browser is true when this observation is the rendered outerHTML of a navigation rather than
	// an HTTP response body. It is a distinct field and not an inference from the probe id because
	// "which tier produced these bytes" decides whether StateFinding is reachable at all.
	Browser bool
}

// cstiSiteCensus is where one probe's delimiter run landed, counted by region.
type cstiSiteCensus struct {
	MarkerPresent bool
	Total         int
	Compiled      int
	Suppressed    int
	Script        int
	Comment       int
	Template      int
	Outside       int
	Unattributed  int // the run is present but this class's marker is not near it
	PctLiteral    bool
	EntityForm    bool
}

// cstiCensus counts the delimiter run's landing sites.
//
// THE ATTRIBUTION RULE IS EXPLICIT. A run counts as this class's only when this class's marker
// occurs within cstiMarkerAdjacency bytes before it. A run with no marker near it is counted as
// Unattributed and NEVER as a candidate: on a documentation page that prints {{7919*6271}} for
// its own reasons, or on a page where a different reflection carries the same text, attributing
// it here would be a finding built on somebody else's bytes.
func cstiCensus(body []byte, marker triage.Marker, run []byte, d cstiDocRegions) cstiSiteCensus {
	var c cstiSiteCensus
	mk := []byte(strings.ToLower(string(marker)))
	lowBody := bytes.ToLower(body)
	if len(mk) > 0 {
		c.MarkerPresent = bytes.Contains(lowBody, mk)
	}

	// The percent-literal and entity forms tell "the payload never arrived" apart from "the
	// application removed it", and those two are a cannot_determine and a clean.
	pctForm := make([]byte, 0, len(run)*3)
	entForm := make([]byte, 0, len(run)*6)
	for _, b := range run {
		switch b {
		case '{', '}', '[', ']', '<', '>', '$', '%', '"', ' ':
			pctForm = append(pctForm, []byte(fmt.Sprintf("%%%02X", b))...)
		default:
			pctForm = append(pctForm, b)
		}
		switch b {
		case '<':
			entForm = append(entForm, []byte("&lt;")...)
		case '>':
			entForm = append(entForm, []byte("&gt;")...)
		case '"':
			entForm = append(entForm, []byte("&quot;")...)
		case '{':
			entForm = append(entForm, []byte("&#123;")...)
		case '}':
			entForm = append(entForm, []byte("&#125;")...)
		default:
			entForm = append(entForm, b)
		}
	}
	c.PctLiteral = bytes.Contains(lowBody, bytes.ToLower(pctForm)) && !bytes.Equal(pctForm, run)
	c.EntityForm = bytes.Contains(body, entForm) && !bytes.Equal(entForm, run)

	from := 0
	for {
		rel := bytes.Index(body[from:], run)
		if rel < 0 {
			break
		}
		off := from + rel
		from = off + 1
		c.Total++

		attributed := false
		if len(mk) > 0 {
			lo := off - cstiMarkerAdjacency
			if lo < 0 {
				lo = 0
			}
			attributed = bytes.Contains(lowBody[lo:off], mk)
		}
		if !attributed {
			c.Unattributed++
			continue
		}
		r := d.at(off)
		switch {
		case r.InScript:
			c.Script++
		case r.InComment:
			c.Comment++
		case r.InTemplate:
			c.Template++
		case r.Suppressed:
			c.Suppressed++
		case r.InCompiled:
			c.Compiled++
		default:
			c.Outside++
		}
	}
	return c
}

// ---------------------------------------------------------------------------------------------
// PLAN
// ---------------------------------------------------------------------------------------------

// cstiPlanInput is the part of PlanCtx this class reads, lifted out so the ladder is testable
// without a runner-built PlanCtx.
type cstiPlanInput struct {
	Slot           triage.Slot
	RespMedia      triage.MediaType
	ControlOK      bool
	El             cstiEligibility
	ProductInCtrl  map[string]bool
	SentProbes     map[triage.ProbeID]bool
	BudgetOut      bool
	BrowserLeft    int
	PreludeFailed  bool
	AttributeMade  bool // CS-0q created an attribute named by this class
	HTTPFlagged    bool // CS-D1 fired: the delimiters reached a compiled region
	BracesStripped bool // the marker came back and the delimiters did not
}

// Plan is the ladder. Nothing here is sent without an interpolating engine, and nothing here is
// sent twice.
func (c cstiClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	in := cstiPlanInputFrom(ctx)
	return cstiPlanLadder(in)
}

func cstiPlanInputFrom(ctx triage.PlanCtx) cstiPlanInput {
	in := cstiPlanInput{
		Slot:          ctx.Slot,
		RespMedia:     ctx.Vector.RespMedia,
		ControlOK:     ctx.Route.Resolved(),
		ProductInCtrl: map[string]bool{},
		SentProbes:    map[triage.ProbeID]bool{},
		BudgetOut:     ctx.Budget.Exhausted(),
		BrowserLeft:   ctx.Budget.RemainingBrowser,
		PreludeFailed: ctx.Prelude.Failed(),
	}
	var control []byte
	controlTruncated := false
	if in.ControlOK {
		obs := ctx.Route.Obs()
		control = obs.Body
		controlTruncated = obs.BodyTruncated
		if in.RespMedia == "" {
			in.RespMedia = obs.MediaType
		}
	}
	in.El = cstiAssess(control, ctx.Assets)
	// Truncation is a property of the OBSERVATION and not of the bytes, so it is carried in here
	// rather than guessed inside cstiAssess. A class that read a capped body as a whole one would
	// conclude "no script on this page" from a page whose script tag fell past the cap.
	in.El.ControlTruncated = controlTruncated
	for _, p := range []cstiPair{cstiPairHTTP, cstiPairHTTPAlt, cstiPairBrowser, cstiPairBrowserAlt} {
		in.ProductInCtrl[p.Product] = bytes.Contains(control, []byte(p.Product))
	}

	reads := cstiReadOwn(ctx.Own)
	for _, r := range reads {
		in.SentProbes[r.ProbeID] = true
	}
	st := cstiSummarise(reads, in.El, in.ProductInCtrl)
	in.AttributeMade = st.attributeMade
	in.HTTPFlagged = st.httpFlagged
	in.BracesStripped = st.bracesStripped
	return in
}

func cstiPlanLadder(in cstiPlanInput) []triage.ProbeRequest {
	if in.BudgetOut || in.PreludeFailed || in.Slot.Constraints.IsCredential {
		return nil
	}
	gate, _, _ := cstiGate(in.El)
	if gate == cstiGateIneligible {
		return nil
	}
	if !cstiDocumentMedia(in.RespMedia) {
		return nil
	}
	if gate == cstiGateUndetermined {
		return cstiPlanUndetermined(in)
	}

	var out []triage.ProbeRequest
	add := func(id triage.ProbeID, pair cstiPair, browser bool) {
		if in.SentProbes[id] {
			return
		}
		v := map[string]string{
			"product":    pair.Product,
			"csti_pair":  strconv.Itoa(pair.A) + "*" + strconv.Itoa(pair.B),
			"delivery":   "http_request",
			"engine_set": strings.Join(in.El.engineNames(), ","),
			"csti_tier":  cstiTierEngineDetected,
		}
		if browser {
			v["delivery"] = "browser_navigation"
		}
		out = append(out, triage.ProbeRequest{Spec: id, Slot: in.Slot.Key, Variant: v})
	}

	httpTier := in.Slot.Kind != triage.KindFragment
	bracesArrive := cstiBracesCanArrive(in.Slot)

	// Round 0. One request in the typical case.
	if httpTier && len(in.SentProbes) == 0 {
		if bracesArrive {
			add(cstiProbeCS1, cstiPairHTTP, false)
			// The alternates go out when the corpus NAMED them, and also when the corpus is
			// incomplete, because an incomplete corpus cannot prove the defaults are in use and
			// reconfigured delimiters are this class's largest false negative.
			if !in.El.CorpusComplete || len(in.El.CustomDelims) > 0 {
				add(cstiProbeCS1B, cstiPairHTTP, false)
				add(cstiProbeCS1C, cstiPairHTTP, false)
			}
			if in.El.DollarBrace {
				add(cstiProbeCS1D, cstiPairHTTP, false)
			}
		}
		if cstiAttrFamilyReaches(in.Slot) {
			add(cstiProbeCS0Q, cstiPairHTTP, false)
		}
		if len(out) > 0 {
			return out
		}
	}

	// Round 1. Ruling R4: the directive probes are sent only after CS-0q proved the slot can
	// create an attribute, and only for the engine that was actually detected.
	if in.AttributeMade {
		if in.El.has(cstiEngineAngularJS) {
			add(cstiProbeCS2, cstiPairHTTP, false)
		}
		if in.El.has(cstiEngineVue2) || in.El.has(cstiEngineVue3) {
			add(cstiProbeCS2V, cstiPairHTTP, false)
		}
		if in.El.has(cstiEngineAlpine) {
			add(cstiProbeCS2A, cstiPairHTTP, false)
		}
		if in.El.has(cstiEngineKnockout) {
			add(cstiProbeCS3, cstiPairHTTP, false)
		}
		if len(out) > 0 {
			return out
		}
	}

	// Round 2. The browser pair, which costs about a hundred times an HTTP request in wall clock
	// and is therefore scheduled only for a slot the HTTP tier flagged, or for a fragment, where
	// the HTTP tier could never run at all.
	wantBrowser := in.HTTPFlagged || in.Slot.Kind == triage.KindFragment
	if wantBrowser && cstiNavCanDeliver(in.Slot) && in.BrowserLeft >= 2 {
		payload, control, pair := cstiProbeNav, cstiProbeNavNC, cstiPairBrowser
		if in.ProductInCtrl[cstiPairBrowser.Product] {
			payload, control, pair = cstiProbeNavAlt, cstiProbeNavNCAlt, cstiPairBrowserAlt
		}
		if !in.ProductInCtrl[pair.Product] {
			add(control, pair, true)
			add(payload, pair, true)
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// The two tiers a planned probe can belong to, written into the ProbeRequest so the runner, the
// stored row and the report all name the same thing. A verdict from the second tier may never
// claim anything the second tier cannot observe, and the string is how that is audited after the
// fact rather than only asserted here.
const (
	cstiTierEngineDetected     = "engine_detected"
	cstiTierEngineUndetermined = "engine_undetermined"
)

// cstiPlanUndetermined is the reduced ladder: ONE request, and it asks the one question about
// CSTI that does not need to know whether an engine is present.
//
// WHY THIS EXISTS AT ALL. On a runner with no served-JavaScript corpus, an application that
// ships its framework inside main.<hash>.js is permanently framework_undetermined, and the old
// ladder answered that by sending nothing for the whole life of the target. The operator sees an
// enabled class with no findings. What CAN be measured without the corpus and without a browser
// is whether this class's delimiters survive the round trip into the HTML document: an engine
// compiles braces out of a fully HTML-escaped string, because no HTML encoder escapes a brace, so
// "your input comes back inside this document with {{ }} intact" is the precondition for every
// CSTI there is, and a slot where it holds is an hour of domdig well spent.
//
// WHAT IT DELIBERATELY DOES NOT DO.
//
//	It sends CS-1 ONLY. The alternate delimiter runs exist because a RECONFIGURED engine is this
//	class's largest false negative, and reconfiguration is a fact about an engine we have not
//	found. Three requests per slot to chase the delimiters of a framework nobody has evidence of
//	is the "pure waste" this class's eligibility model was written to avoid; one request to
//	establish a precondition is not.
//
//	It sends no attribute probe, no directive probe and no navigation. Every one of those is
//	aimed at a NAMED engine, and there is no named engine here.
//
//	It runs once. SentProbes non-empty means round 0 already happened, and this tier has no
//	round 1: there is no ladder to climb without an engine to climb it for.
func cstiPlanUndetermined(in cstiPlanInput) []triage.ProbeRequest {
	if !in.ControlOK || len(in.SentProbes) > 0 {
		return nil
	}
	// The fragment is the one slot the HTTP tier cannot deliver at all, and the browser tier that
	// could is not available to this tier. Sending nothing here is correct; the verdict says
	// needs_dom_run and never clean.
	if in.Slot.Kind == triage.KindFragment || !cstiBracesCanArrive(in.Slot) {
		return nil
	}
	return []triage.ProbeRequest{{
		Spec: cstiProbeCS1, Slot: in.Slot.Key,
		Variant: map[string]string{
			"product":    cstiPairHTTP.Product,
			"csti_pair":  strconv.Itoa(cstiPairHTTP.A) + "*" + strconv.Itoa(cstiPairHTTP.B),
			"delivery":   "http_request",
			"engine_set": "",
			"csti_tier":  cstiTierEngineUndetermined,
		},
	}}
}

// cstiDocumentMedia reports whether the response the engine would compile is a document at all. An
// engine compiles a DOM; a JSON API response is not one.
func cstiDocumentMedia(mt triage.MediaType) bool {
	s := strings.ToLower(string(mt))
	return strings.Contains(s, "html") || strings.Contains(s, "xhtml")
}

// cstiBracesCanArrive is the decode_depth rule. A slot MEASURED at 0 does not percent-decode, so
// the runner's %7B arrives as four literal characters and the payload never reaches the compiler.
// Depth -1 is UNKNOWN, which is a different thing: the probe goes out and the response decides,
// because refusing to send on an unmeasured slot is how a class stops testing without saying so.
func cstiBracesCanArrive(s triage.Slot) bool {
	switch s.Kind {
	case triage.KindHeader, triage.KindCookie:
		return true // braces are raw-legal in both, so no decoding is involved
	case triage.KindBody:
		if s.BodyMedia == triage.BodyJSON || s.BodyMedia == triage.BodyMultipart {
			return true
		}
	}
	return s.Constraints.DecodeDepth != 0
}

// cstiAttrFamilyReaches is the attribute family's own reachability: it needs a RAW double quote
// and a SPACE in the rendered value.
func cstiAttrFamilyReaches(s triage.Slot) bool {
	switch s.Kind {
	case triage.KindBody:
		return s.BodyMedia == triage.BodyForm || s.BodyMedia == triage.BodyMultipart
	case triage.KindCookie:
		return s.Constraints.DecodeDepth >= 1 // quote and space are outside cookie-octet
	case triage.KindFragment:
		return false
	}
	return true
}

// cstiNavCanDeliver states the browser tier's delivery limits honestly. domdig navigates: it sets
// cookies and extra headers on the context and then loads a URL. It does not reissue a captured
// POST with a modified body, so a body slot has no browser delivery at all.
func cstiNavCanDeliver(s triage.Slot) bool { return s.Kind != triage.KindBody }

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

type cstiSummary struct {
	reads          []cstiProbeRead
	ordinals       []uint64
	attributeMade  bool
	httpFlagged    bool
	httpOracle     string
	bracesStripped bool
	markerSeen     bool
	productInHTTP  bool
	// productAmbiguous is CS-D2's own abstention. The control body ALREADY printed the product,
	// so finding it in a probe response proves nothing about who evaluated what, and claiming
	// server_side_evaluation from it would misfile the slot to SSTI on a coincidence.
	productAmbiguous bool
	pctLiteral       bool
	// delimitersAttributed is the undetermined tier's whole oracle: a delimiter run came back in
	// the document with THIS class's marker within cstiMarkerAdjacency bytes in front of it. It
	// is deliberately region-blind, because the region scanner falls back to treating the whole
	// body as compiled and with no detected engine that fallback would manufacture a compiled
	// region out of nothing.
	delimitersAttributed bool
	undelivered          []cstiProbeRead
	unproven             []cstiProbeRead
	truncated            bool
	browserHit           bool
	browserProduct       string
	browserRan           bool
	controlRan           bool
	controlDirty         bool
	suppressedOnly       bool
	outsideOnly          bool
	resolvedMount        bool
	// fidelityWhy and fidelityProbe are cstiFidelity's answer. Non-empty means one of this
	// class's own probes cannot be read as a silence at all, whatever the response looked like.
	fidelityWhy   string
	fidelityProbe triage.ProbeID
}

// The fidelity refusals, each naming the integration failure it caught rather than the symptom.
const (
	cstiFidelityPlaceholder = "placeholder_not_substituted"
	cstiFidelityNoMarker    = "marker_absent_from_wire"
	cstiFidelityForeign     = "foreign_marker_stripe"
)

// cstiFidelity is the guard between an integration bug in the send path and a corpus of silences.
//
// THIS CLASS'S WHOLE ATTRIBUTION RULE IS POSITIONAL: a delimiter run is this class's only when
// this class's marker sits within cstiMarkerAdjacency bytes in front of it. So a probe that went
// out with no marker in it cannot produce an attributable landing site NO MATTER WHAT the
// application did, and every one of this class's negative exits (no_reflection,
// delimiters_stripped, delimiters_outside_compiled_region) would then be measuring the runner.
// Exam 2e4433b1 is what that looks like from the outside: four probes sent, marker nowhere on the
// wire, and cannot_determine on the class's own positive control.
//
// It runs over DELIVERED probes only. An undelivered one is already an unknown by a different
// name and its wire form is expected to be absent.
func cstiFidelity(reads []cstiProbeRead) (string, triage.ProbeID) {
	for _, r := range reads {
		if !r.Delivered {
			continue
		}
		if r.Marker != "" && r.Marker.WellFormed() && !r.Marker.BelongsTo(triage.ClassCSTI) {
			return cstiFidelityForeign, r.ProbeID
		}
		// The placeholder still literally on the wire means nobody substituted it: the probe went
		// out inert and the marker this class searches for could never have appeared.
		for _, b := range [][]byte{r.Logical, r.Wire} {
			if bytes.Contains(b, []byte(cstiMark)) {
				return cstiFidelityPlaceholder, r.ProbeID
			}
		}
		if r.Marker == "" {
			return cstiFidelityNoMarker, r.ProbeID
		}
		// Every payload this class declares spells the placeholder, so the minted marker belongs
		// in the recorded wire form. The encoders this class uses are percent, form, JSON-string,
		// multipart, path, header and cookie, and the marker is alphanumeric, so none of them
		// transforms it: absent here means absent on the wire.
		mk := []byte(r.Marker)
		if len(r.Logical) > 0 && !bytes.Contains(r.Logical, mk) {
			return cstiFidelityNoMarker, r.ProbeID
		}
		if len(r.Wire) > 0 && !bytes.Contains(bytes.ToLower(r.Wire), bytes.ToLower(mk)) {
			return cstiFidelityNoMarker, r.ProbeID
		}
	}
	return "", ""
}

// cstiFidelityDetail is the operator-facing half: what broke, and why the row is not a result.
func cstiFidelityDetail(why string, probe triage.ProbeID) string {
	switch why {
	case cstiFidelityPlaceholder:
		return "placeholder_not_substituted: probe " + string(probe) + " went out with the runner's marker placeholder " +
			"still literally in it, so the payload was inert and the marker this class attributes landing sites by could " +
			"never have appeared in the response. Nothing about this slot was measured"
	case cstiFidelityNoMarker:
		return "marker_absent_from_wire: probe " + string(probe) + " reached the wire with no minted marker in it. Every " +
			"payload this class declares spells the marker placeholder, and this class attributes a delimiter run to " +
			"itself ONLY by the marker sitting in front of it, so a markerless probe makes every landing site " +
			"unattributable and every silence the runner's rather than the application's"
	case cstiFidelityForeign:
		return "foreign_marker_stripe: probe " + string(probe) + " carries a marker whose R12 ordinal stripe belongs to " +
			"another class, so reading its response here would attribute another class's probe to this one"
	}
	return why
}

// cstiDirectiveAttrs is the attribute name each directive probe is trying to create. The probe is
// answered by the ATTRIBUTE existing, not by its text appearing, because a template expression
// welded into an attribute value is re-serialized by the application's own templating and almost
// never comes back byte-identical.
var cstiDirectiveAttrs = map[triage.ProbeID]string{
	cstiProbeCS2:  "ng-init=",
	cstiProbeCS2V: "v-bind:title=",
	cstiProbeCS2A: "x-init=",
	cstiProbeCS3:  "data-bind=",
}

// cstiSummarise applies the detection rules to this class's own observations, and to nothing else.
//
// productInControl is read from the UNPERTURBED control body, which is why CS-D2 can abstain
// rather than misfile: digits that were on the page before any probe went out are not evidence
// that anything evaluated anything.
func cstiSummarise(reads []cstiProbeRead, el cstiEligibility, productInControl map[string]bool) cstiSummary {
	s := cstiSummary{reads: reads, resolvedMount: true}
	s.fidelityWhy, s.fidelityProbe = cstiFidelity(reads)
	sawCompiled, sawSuppressed, sawOutside, sawAttributed := false, false, false, false

	for _, r := range reads {
		s.ordinals = append(s.ordinals, r.Ordinal)
		if !r.Delivered {
			s.undelivered = append(s.undelivered, r)
			continue
		}
		if !r.Survival.Proven() {
			s.unproven = append(s.unproven, r)
			continue
		}
		if r.Truncated {
			s.truncated = true
		}

		regions := cstiScanRegions(r.Body, el.MountSelectors, true)
		if !regions.compiledResolved {
			s.resolvedMount = false
		}
		product := cstiProductFor(r.ProbeID)

		switch r.ProbeID {
		case cstiProbeNav, cstiProbeNavAlt:
			s.browserRan = true
			if bytes.Contains(r.Body, []byte(product)) && !productInControl[product] {
				s.browserHit = true
				s.browserProduct = product
			}

		case cstiProbeNavNC, cstiProbeNavNCAlt:
			s.controlRan = true
			if bytes.Contains(r.Body, []byte(product)) {
				// NC-B1 fired: the digits render from arithmetic with NO delimiters, so the
				// application itself computes the product and this class's oracle is contaminated.
				s.controlDirty = true
			}

		case cstiProbeCS0Q:
			// CS-0q carries no template syntax at all, so its only question is whether this slot
			// can create an attribute. That answer, and nothing else, unlocks the directives.
			if cstiAttrInTag(r.Body, r.Marker, "csti0q=") {
				s.attributeMade = true
			}

		case cstiProbeCS2, cstiProbeCS2V, cstiProbeCS2A, cstiProbeCS3:
			if off, ok := cstiAttrOffsetInTag(r.Body, r.Marker, cstiDirectiveAttrs[r.ProbeID]); ok {
				s.markerSeen = true
				sawAttributed = true
				if regions.at(off).Compiles() {
					s.httpFlagged = true
					s.httpOracle = "directive_placement"
					sawCompiled = true
				} else {
					sawOutside = true
				}
			}
			s.productInHTTP, s.productAmbiguous = cstiProductVerdict(
				s.productInHTTP, s.productAmbiguous, r.Body, product, productInControl)

		default:
			run := cstiRunFor(r.ProbeID)
			if run == nil {
				continue
			}
			c := cstiCensus(r.Body, r.Marker, run, regions)
			if c.MarkerPresent {
				s.markerSeen = true
			}
			if c.PctLiteral {
				s.pctLiteral = true
			}
			if c.Compiled > 0 {
				s.httpFlagged = true
				if s.httpOracle == "" {
					s.httpOracle = "delimiter_placement"
				}
				sawCompiled = true
			}
			if c.Suppressed > 0 {
				sawSuppressed = true
			}
			if c.Outside > 0 || c.Script > 0 || c.Comment > 0 || c.Template > 0 {
				sawOutside = true
			}
			if c.Total > c.Unattributed {
				sawAttributed = true
				s.delimitersAttributed = true
			}
			if c.MarkerPresent && c.Total == 0 && !c.PctLiteral && !c.EntityForm {
				s.bracesStripped = true
			}
			s.productInHTTP, s.productAmbiguous = cstiProductVerdict(
				s.productInHTTP, s.productAmbiguous, r.Body, product, productInControl)
		}
	}
	s.suppressedOnly = sawSuppressed && !sawCompiled && sawAttributed
	s.outsideOnly = sawOutside && !sawCompiled && !sawSuppressed && sawAttributed
	return s
}

// cstiProductVerdict is CS-D2, and the abstention is the whole reason it is a function. The
// product in a probe response means a SERVER engine evaluated the expression, which is SSTI's
// finding, UNLESS the same digits were already on the unperturbed page, in which case nobody can
// say who put them there.
func cstiProductVerdict(server, ambiguous bool, body []byte, product string, inControl map[string]bool) (bool, bool) {
	if !bytes.Contains(body, []byte(product)) {
		return server, ambiguous
	}
	if inControl[product] {
		return server, true
	}
	return true, ambiguous
}

var cstiRunByProbe = map[triage.ProbeID][]byte{
	cstiProbeCS1:      cstiBytesCS1,
	cstiProbeCS1B:     cstiBytesCS1B,
	cstiProbeCS1C:     cstiBytesCS1C,
	cstiProbeCS1D:     cstiBytesCS1D,
	cstiProbeCS2:      cstiBytesCS2,
	cstiProbeCS2V:     cstiBytesCS2V,
	cstiProbeCS2A:     cstiBytesCS2A,
	cstiProbeCS3:      cstiBytesCS3,
	cstiProbeNav:      cstiBytesNav,
	cstiProbeNavAlt:   cstiBytesNavAlt,
	cstiProbeNavNC:    cstiBytesNavNC,
	cstiProbeNavNCAlt: cstiBytesNavNCAlt,
}

func cstiRunFor(id triage.ProbeID) []byte { return cstiRunByProbe[id] }

func cstiProductFor(id triage.ProbeID) string {
	switch id {
	case cstiProbeNav, cstiProbeNavNC:
		return cstiPairBrowser.Product
	case cstiProbeNavAlt, cstiProbeNavNCAlt:
		return cstiPairBrowserAlt.Product
	default:
		return cstiPairHTTP.Product
	}
}

// cstiAttrInTag and cstiAttrOffsetInTag ask whether this class's bytes became an ATTRIBUTE rather
// than text. CS-0q renders as <marker>" csti0q="1, so the evidence is the attribute name this
// class chose appearing with an equals sign INSIDE a start tag that also carries the marker.
//
// WHY THE MARKER MUST BE IN THE SAME TAG. Without it, any page that happens to carry a data-bind
// attribute of its own answers yes for Knockout on every slot, and the whole directive family
// would then be sent, and read, against an attribute nobody injected.
func cstiAttrInTag(body []byte, marker triage.Marker, needle string) bool {
	_, ok := cstiAttrOffsetInTag(body, marker, needle)
	return ok
}

// cstiAttrOffsetInTag returns the offset of the START TAG, not of the attribute, because the
// region rule is about which element the attribute is on.
func cstiAttrOffsetInTag(body []byte, marker triage.Marker, needle string) (int, bool) {
	if needle == "" {
		return 0, false
	}
	low := bytes.ToLower(body)
	n := []byte(strings.ToLower(needle))
	mk := []byte(strings.ToLower(string(marker)))
	from := 0
	for {
		rel := bytes.Index(low[from:], n)
		if rel < 0 {
			return 0, false
		}
		off := from + rel
		from = off + 1
		// Walk back to the nearest '<' with no '>' in between: that is "inside a start tag".
		lt := bytes.LastIndexByte(low[:off], '<')
		if lt < 0 || bytes.IndexByte(low[lt:off], '>') >= 0 {
			continue
		}
		if len(mk) > 0 && !bytes.Contains(low[lt:off], mk) {
			continue
		}
		return lt, true
	}
}

// cstiReadOwn lifts this class's own observations into the reduced form the rules read. A handle
// that fails the vault's own re-check is recorded as undelivered with the error named, never
// skipped: a response this class could not read is a measurement that did not happen.
func cstiReadOwn(own triage.OwnedResponses) []cstiProbeRead {
	out := make([]cstiProbeRead, 0, own.Len())
	for i := 0; i < own.Len(); i++ {
		p, obs, err := own.At(i)
		r := cstiProbeRead{ProbeID: p.ProbeID(), Ordinal: p.Ordinal()}
		if err != nil {
			out = append(out, r)
			continue
		}
		r.Delivered = obs.Delivered()
		r.Survival = obs.Payload.Survived
		r.Marker = obs.Marker
		r.Body = obs.Body
		r.Truncated = obs.BodyTruncated
		r.Logical = obs.Payload.Logical
		r.Wire = obs.Payload.Wire
		if len(r.Wire) == 0 {
			r.Wire = obs.Payload.Container
		}
		switch r.ProbeID {
		case cstiProbeNav, cstiProbeNavAlt, cstiProbeNavNC, cstiProbeNavNCAlt:
			r.Browser = true
		}
		out = append(out, r)
	}
	return out
}

// cstiScoreEnv is the part of ClassifyCtx the scoring rules read.
//
// IT IS A SEPARATE STRUCT SO THE RULES CAN BE TESTED. A ClassifyCtx can only be built by the
// runner: Route and PostBaseline are Replays, and NewReplay takes a capability this package
// cannot even spell. Scoring against a ctx directly would therefore mean every branch below the
// "no route control" check was unreachable from a test, and an untested branch that emits clean is
// precisely the defect this layer exists to stop.
type cstiScoreEnv struct {
	Slot                 triage.Slot
	Prelude              triage.PreludeState
	Baseline             triage.BaselineModel
	PostBaselineResolved bool
	BudgetExhausted      bool
	BrowserDeliverable   bool
}

// Classify is the verdict. It returns exactly one row per slot, because a second row for the same
// slot reads in an aggregate as a second measurement.
func (c cstiClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	in := cstiPlanInputFrom(ctx.PlanCtx)
	reads := cstiReadOwn(ctx.Own)
	sum := cstiSummarise(reads, in.El, in.ProductInCtrl)
	env := cstiScoreEnv{
		Slot:                 ctx.Slot,
		Prelude:              ctx.Prelude,
		Baseline:             ctx.Baseline,
		PostBaselineResolved: ctx.PostBaseline.Resolved(),
		BudgetExhausted:      ctx.Budget.Exhausted(),
		BrowserDeliverable:   cstiNavCanDeliver(ctx.Slot),
	}
	return []triage.ClassVerdict{cstiVerdict(env, in, sum)}
}

// cstiHTTPCeiling is the cap this class puts on itself: no HTTP-tier result may exceed suspicious,
// because the engine that would evaluate the expression runs in the browser and an HTTP response
// cannot show evaluation. It is a named function so the cap is one line that a test can assert
// against, not a habit spread over a switch.
func cstiHTTPCeiling(s triage.TriageState) triage.TriageState {
	if s == triage.StateFinding {
		return triage.StateSuspicious
	}
	return s
}

func cstiVerdict(env cstiScoreEnv, in cstiPlanInput, sum cstiSummary) triage.ClassVerdict {
	v := triage.ClassVerdict{
		Class:       triage.ClassCSTI,
		SlotKey:     env.Slot.Key,
		Ordinals:    sum.ordinals,
		Annotations: map[string]any{},
	}
	if len(in.El.Interpolating) > 0 {
		v.Annotations["csti_engines"] = strings.Join(in.El.engineNames(), ",")
	}
	if in.El.AngularCSPMode {
		// ng-csp stops the Function-constructor escapes and NOT expression evaluation, so it
		// changes the payload handed to the operator and never the eligibility decision.
		v.Annotations["angular_csp_mode"] = true
	}
	if !in.El.CorpusComplete {
		v.Annotations["corpus_capped"] = true
	}

	set := func(state triage.TriageState, oracle, reason string) triage.ClassVerdict {
		v.State, v.Oracle, v.Reason = state, oracle, reason
		if v.State.IsUnknown() {
			v.Grade = triage.GradeUnrated
		}
		return v
	}

	// 1. The structural refusals, before anything is measured.
	if env.Slot.Constraints.IsCredential {
		return set(triage.StateNotProbed, "", "credential_slot: injecting into a session or authorization slot produces a 401 whose differential looks exactly like a finding")
	}
	if env.Prelude.Failed() {
		return set(triage.StateCannotDetermine, "", "prelude_failed ("+string(env.Prelude)+"): every probe on this vector would fail validation identically, which reads as a stable endpoint with no differential, which reads as clean")
	}
	if !in.ControlOK {
		return set(triage.StateCannotDetermine, "", "no_route_control: eligibility for this class is read from the unperturbed control body and there is none, so framework presence is unknown and so is everything downstream")
	}
	gate, gateState, gateReason := cstiGate(in.El)
	if gate == cstiGateIneligible {
		v.Untested = cstiAllProbesUntested(gateReason)
		return set(gateState, "", gateReason)
	}
	if !cstiDocumentMedia(in.RespMedia) {
		return set(triage.StateNotApplicable, "", fmt.Sprintf(
			"response_not_a_document (%q): a client engine compiles a DOM, and this vector's response is not one. "+
				"A value echoed into a DIFFERENT page is a real CSTI route and is outside this class's single-response reach; it is declared, not measured",
			string(in.RespMedia)))
	}
	if gate == cstiGateUndetermined {
		return cstiUndeterminedVerdict(&v, set, env, in, sum, gateReason)
	}

	// 2. The browser tier, the only path in this file that reaches a finding.
	if sum.controlDirty {
		return set(triage.StateCannotDetermine, "computation",
			"control_contaminated: the NC-B1 navigation carried the arithmetic with NO delimiters and the product still rendered, "+
				"so this application computes the product itself and the digits cannot be attributed to a template engine")
	}
	if sum.browserHit {
		v.Label = cstiLabelFor(in.El)
		v.Evidence = triage.TriageEvidence{Phrase: "csti_product_rendered", Matched: []byte(sum.browserProduct)}
		if !sum.controlRan {
			// THE FINDING IS NOT AVAILABLE WITHOUT ITS OWN CONTROL. A rendered product with no
			// NC-B1 beside it cannot be told from a calculator endpoint that multiplies its own
			// parameter, and that shape is common enough to have its own oracle endpoint.
			v.Grade = triage.GradeMedium
			v.Untested = []triage.ProbeSkip{{ProbeID: cstiProbeNavNC, Reason: "control_navigation_missing"}}
			return set(triage.StateSuspicious, "computation",
				"product_rendered_without_control: the payload navigation rendered "+sum.browserProduct+
					" in outerHTML, but the NC-B1 control navigation never ran, so an application that computes "+
					"the product from the parameter itself has not been excluded. A finding needs its own control")
		}
		v.Grade = triage.GradeHigh
		return set(triage.StateFinding, "computation",
			"csti_confirmed: the payload navigation rendered "+sum.browserProduct+
				" in outerHTML, the NC-B1 control navigation with the same arithmetic and NO delimiters did not, "+
				"and the unperturbed control body did not carry the digits. A client template engine evaluated the expression")
	}

	// 3. The server-side exclusion, which costs nothing and prevents a whole misfile.
	if sum.productAmbiguous {
		v.Annotations["server_side_evaluation_undecidable"] = true
	}
	if sum.productInHTTP {
		v.Label = triage.TriageLabel{
			Tools: []string{"sstimap", "tinja"},
			Hints: map[string]string{"handoff": "SSTI", "product": cstiPairHTTP.Product},
		}
		return set(triage.StateCannotDetermine, "computation",
			"server_side_evaluation: the HTTP body already contains "+cstiPairHTTP.Product+
				", so a SERVER template engine evaluated the expression. That is SSTI's finding and this class must not claim it. "+
				"CSTI is NOT refuted by it, which is why this is cannot_determine and not a negative")
	}

	// 4. Nothing was sent. Say which gate stopped it rather than saying nothing.
	if len(sum.reads) == 0 {
		if env.Slot.Kind == triage.KindFragment {
			v.Untested = []triage.ProbeSkip{{ProbeID: cstiProbeNav, Reason: "browser_tier_unavailable"}}
			return set(triage.StateCannotDetermine, "", "needs_dom_run: a fragment is never transmitted, so the HTTP tier is not_applicable here and only a navigation can deliver this slot. No navigation ran")
		}
		if env.BudgetExhausted {
			v.Untested = cstiAllProbesUntested("probe_budget_exhausted")
			return set(triage.StateNotRun, "", "probe_budget_exhausted: an interpolating engine is present and this slot was never probed")
		}
		if !cstiBracesCanArrive(env.Slot) {
			v.Untested = cstiAllProbesUntested("pct_literal")
			return set(triage.StateNotReachable, "", "pct_literal: this slot was MEASURED at decode_depth 0, so the percent-encoded braces arrive as literal %7B text and no delimiter can reach the compiler")
		}
		v.Untested = cstiAllProbesUntested("no_probe_derived")
		return set(triage.StateNotPlanned, "", "no_probe_derived: an engine is present and the ladder derived no request for this slot, which is a gap in the ladder rather than a property of the application")
	}

	// 5. Delivery failures. A probe that never reached the wire proves nothing at all.
	if len(sum.undelivered) > 0 && len(sum.undelivered) == len(sum.reads) {
		return set(triage.StateCannotDetermine, "", "transport_failed: every probe this class sent on this slot failed to reach the application, so nothing about it was measured")
	}
	if len(sum.unproven) > 0 && len(sum.unproven)+len(sum.undelivered) == len(sum.reads) {
		return set(triage.StateCannotDetermine, "", "payload_wire_unproven: the encoder could not confirm this class's bytes went out intact, and a probe that may have been mangled on the way out is indistinguishable afterwards from a probe the application defended against")
	}
	if sum.truncated {
		return set(triage.StateCannotDetermine, "", "body_truncated: the response was capped before the whole document was searched, so a delimiter run past the cap would be invisible")
	}
	if sum.pctLiteral {
		return set(triage.StateCannotDetermine, "", "delimiters_not_delivered: the braces came back as literal percent-encoded text, so the payload never arrived at the compiler and the application was never asked the question")
	}
	if sum.fidelityWhy != "" {
		v.Annotations["fidelity_failure"] = sum.fidelityWhy
		return set(triage.StateCannotDetermine, "", cstiFidelityDetail(sum.fidelityWhy, sum.fidelityProbe))
	}

	// 6. The HTTP tier fired. Capped at suspicious, by this class, on purpose.
	if sum.httpFlagged {
		v.Grade = triage.GradeLow
		v.Label = cstiLabelFor(in.El)
		v.Evidence = triage.TriageEvidence{Phrase: "template_delimiters_reach_compiler"}
		reason := "template_delimiters_reach_compiler: this class's delimiter run came back inside a region the detected engine compiles. " +
			"The HTTP tier can NEVER confirm evaluation, because the engine runs in the browser, so this is capped at suspicious"
		if !sum.resolvedMount {
			v.Annotations["mount_point_unresolved"] = true
			reason += ". The mount point could not be resolved from the corpus, so the compiled region was taken as the whole body and the confidence is low"
		}
		if !sum.browserRan {
			why := "browser_tier_unavailable"
			if !env.BrowserDeliverable {
				why = "no_browser_delivery: domdig navigates and does not reissue a captured body verb, so this slot has no browser delivery at all"
			}
			v.Untested = []triage.ProbeSkip{{ProbeID: cstiProbeNav, Reason: why}}
			v.Annotations["needs_dom_run"] = true
			reason += ". " + why
		}
		oracle := sum.httpOracle
		if oracle == "" {
			oracle = "delimiter_placement"
		}
		return set(cstiHTTPCeiling(triage.StateSuspicious), oracle, reason)
	}

	// 7. The negatives. Each one names the defence or the measurement it rests on.
	if sum.suppressedOnly {
		v.Grade = triage.GradeUnrated
		return set(triage.StateNotExploitable, "delimiter_placement",
			"reflection_inside_non_bindable: every attributable landing site of this class's delimiters sits inside an element bearing "+
				"ng-non-bindable, v-pre or x-ignore, which are explicit instructions to the engine not to compile that subtree. A named defence, not a silence")
	}
	if sum.outsideOnly && sum.resolvedMount {
		return set(triage.StateClean, "delimiter_placement",
			"delimiters_outside_compiled_region: this class's delimiters arrived intact, the mount point was RESOLVED from the corpus, "+
				"and every attributable landing site is outside the compiled subtree or inside a script, a comment or a template element, none of which the engine compiles")
	}
	if sum.outsideOnly && !sum.resolvedMount {
		v.Annotations["mount_point_unresolved"] = true
		return set(triage.StateCannotDetermine, "delimiter_placement",
			"mount_point_unresolved: the delimiters arrived and landed outside the region this class GUESSED was compiled, but the mount point was never resolved, "+
				"so the guess cannot support a negative")
	}
	if sum.bracesStripped {
		if !cstiCleanPreconditions(env, in) {
			return set(triage.StateCannotDetermine, "delimiter_placement", cstiWhyNotClean(env, in))
		}
		return set(triage.StateClean, "delimiter_placement",
			"delimiters_stripped: this class's marker came back and its delimiters did not, in no entity form and no percent form, "+
				"on a slot measured to decode and against a stable baseline. The delimiters cannot reach any compiler on this response")
	}
	if !sum.markerSeen {
		if !cstiCleanPreconditions(env, in) {
			return set(triage.StateCannotDetermine, "reflection", cstiWhyNotClean(env, in))
		}
		return set(triage.StateClean, "reflection",
			"no_reflection: this class's own probes went out intact on a stable endpoint and the marker does not appear anywhere in the response, "+
				"so nothing from this slot reaches a template compiler on this document")
	}
	return set(triage.StateCannotDetermine, "reflection",
		"reflection_unresolved: this class's marker came back but its delimiters could not be placed in or out of a compiled region, which is a gap in the measurement and not a property of the application")
}

// cstiUndeterminedVerdict scores the reduced tier, and its ceiling is the whole contract.
//
// THE CEILING. This tier never established that a client template engine is present. So it may
// not say finding (nothing showed evaluation), it may not say suspicious (a "candidate" for an
// engine nobody found is a number an operator would chase for nothing), and above all it may not
// say clean or not_applicable (the engine question is open, and a silence here is a silence about
// a precondition, not about the bug). Every exit below is cannot_determine, not_run, not_probed
// or not_reachable. What changes between them is the REASON, and on the one path that matters the
// reason is a pointer with a tool attached.
//
// WHY A REASON IS WORTH A REQUEST. "framework_undetermined, zero probes" and "framework
// undetermined, and your input comes back inside this HTML document with {{ }} intact" are the
// same state and completely different instructions. The first is a row nobody actions. The second
// says: the precondition for every CSTI there is holds on this slot, and the only unanswered
// question is whether the page runs an engine, which one domdig run settles.
func cstiUndeterminedVerdict(v *triage.ClassVerdict, set func(triage.TriageState, string, string) triage.ClassVerdict,
	env cstiScoreEnv, in cstiPlanInput, sum cstiSummary, gateReason string) triage.ClassVerdict {

	v.Annotations["csti_tier"] = cstiTierEngineUndetermined
	v.Annotations["engine_presence"] = "unknown"
	v.Annotations["tier_ceiling"] = "cannot_determine"

	if len(sum.reads) == 0 {
		switch {
		case env.Slot.Kind == triage.KindFragment:
			v.Untested = cstiAllProbesUntested("needs_dom_run")
			return set(triage.StateCannotDetermine, "",
				"needs_dom_run: "+gateReason+". A fragment is never transmitted, so the one HTTP-only probe this "+
					"tier sends cannot be delivered to it either, and only a browser navigation could. Nothing measured this slot")
		case env.BudgetExhausted:
			v.Untested = cstiAllProbesUntested("probe_budget_exhausted")
			return set(triage.StateNotRun, "",
				"probe_budget_exhausted: "+gateReason+". The one delimiter-survival request this tier sends was never sent")
		case !cstiBracesCanArrive(env.Slot):
			v.Untested = cstiAllProbesUntested("pct_literal")
			return set(triage.StateNotReachable, "",
				"pct_literal: this slot was MEASURED at decode_depth 0, so the percent-encoded braces arrive as literal %7B text. "+
					"The engine question is separately unresolved ("+gateReason+")")
		default:
			v.Untested = cstiAllProbesUntested(gateReason)
			return set(triage.StateCannotDetermine, "",
				gateReason+". No probe was derived for this slot either, so not one byte was sent and nothing about it was measured")
		}
	}

	v.Untested = cstiUntestedExcept(sum, "engine_undetermined_reduced_tier: this tier sends the default delimiter run "+
		"and nothing else. Every other probe in this class is aimed at a NAMED engine, and no engine was named")

	if len(sum.undelivered) == len(sum.reads) {
		return set(triage.StateCannotDetermine, "", "transport_failed: the delimiter-survival probe never reached the application")
	}
	if len(sum.unproven)+len(sum.undelivered) == len(sum.reads) {
		return set(triage.StateCannotDetermine, "", "payload_wire_unproven: the encoder could not confirm this class's braces went out intact, "+
			"so braces missing from the response cannot be told from braces that never left")
	}
	if sum.truncated {
		return set(triage.StateCannotDetermine, "", "body_truncated: the response was capped before the whole document was searched, "+
			"so a delimiter run past the cap would be invisible. "+gateReason)
	}
	if sum.pctLiteral {
		return set(triage.StateCannotDetermine, "", "delimiters_not_delivered: the braces came back as literal percent-encoded text, "+
			"so the application was never asked the question. "+gateReason)
	}
	if sum.fidelityWhy != "" {
		v.Annotations["fidelity_failure"] = sum.fidelityWhy
		return set(triage.StateCannotDetermine, "", cstiFidelityDetail(sum.fidelityWhy, sum.fidelityProbe)+". "+gateReason)
	}
	if sum.productInHTTP {
		// This costs nothing extra and it is the one thing this tier can hand over that is worth
		// more than a pointer: the product in an HTTP body means a SERVER engine evaluated the
		// expression, which is SSTI's finding, and it does not need a client engine to exist.
		v.Label = triage.TriageLabel{
			Tools: []string{"sstimap", "tinja"},
			Hints: map[string]string{"handoff": "SSTI", "product": cstiPairHTTP.Product},
		}
		return set(triage.StateCannotDetermine, "computation",
			"server_side_evaluation: the HTTP body already contains "+cstiPairHTTP.Product+", so a SERVER template engine "+
				"evaluated the expression. That is SSTI's finding and this class must not claim it, and it says nothing either "+
				"way about a client engine, which remains unknown ("+gateReason+")")
	}

	switch {
	case sum.delimitersAttributed:
		v.Evidence = triage.TriageEvidence{Phrase: "delimiters_survive_engine_unknown", Matched: cstiBytesCS1}
		v.Label = triage.TriageLabel{
			Tools: []string{"domdig", "dalfox"},
			Hints: map[string]string{
				"what_is_established": "this slot's value comes back inside an HTML document with {{ }} intact and " +
					"this class's own marker in front of it. No HTML encoder escapes a brace, so that is the precondition " +
					"for every client-side template injection there is",
				"what_is_not_established": "whether this page runs an interpolating client template engine at all. This " +
					"build has no served-JavaScript corpus, so a framework shipped inside a bundle is invisible here",
				"next_step": "one domdig navigation against this slot answers the only open question. Check the rendered " +
					"outerHTML for the product of the expression, not for the braces",
			},
		}
		return set(triage.StateCannotDetermine, "delimiter_survival",
			"delimiters_survive_engine_unknown: this class's delimiter run came back in the document, attributable to this "+
				"class's own marker, which is the precondition for every CSTI there is. It is NOT a candidate and NOT a "+
				"finding: nothing here showed that a client template engine is present or that anything was evaluated. "+
				gateReason)
	case sum.bracesStripped:
		return set(triage.StateCannotDetermine, "delimiter_survival",
			"delimiters_stripped_engine_unknown: this class's marker came back and its braces did not, so no delimiter from "+
				"THIS reflection can reach a compiler on THIS response. That is not a clean: the engine question is unresolved "+
				"("+gateReason+"), and a client router reading this parameter out of location.search never involves the "+
				"reflection this probe measured")
	case !sum.markerSeen:
		return set(triage.StateCannotDetermine, "reflection",
			"no_reflection_engine_unknown: this slot's value does not come back in this response, so the server-reflection "+
				"route to a client template is closed on this document. It is not a clean: "+gateReason+", and a value read "+
				"client-side out of the URL reaches a template without ever appearing in a response body")
	default:
		return set(triage.StateCannotDetermine, "reflection",
			"reflection_unresolved_engine_unknown: the marker came back and the delimiter run could not be attributed to it, "+
				"which is a gap in the measurement rather than a property of the application. "+gateReason)
	}
}

// cstiUntestedExcept lists every probe this class did NOT send, so the reduced tier's coverage
// row names the nine probes it withheld instead of looking like a class that ran out of ideas.
func cstiUntestedExcept(sum cstiSummary, reason string) []triage.ProbeSkip {
	ran := make(map[triage.ProbeID]bool, len(sum.reads))
	for _, r := range sum.reads {
		ran[r.ProbeID] = true
	}
	all := cstiAllProbesUntested(reason)
	out := make([]triage.ProbeSkip, 0, len(all))
	for _, s := range all {
		if ran[s.ProbeID] {
			continue
		}
		out = append(out, s)
	}
	return out
}

// cstiCleanPreconditions is the gate in front of every clean this class can emit. Each condition
// is one of the ways this codebase has previously turned a failed measurement into a green tick.
func cstiCleanPreconditions(env cstiScoreEnv, in cstiPlanInput) bool {
	if env.Baseline.Samples == 0 || !env.Baseline.Stable || env.Baseline.Degraded {
		return false
	}
	if env.Slot.ValueOrigin == triage.ValueCanary {
		return false
	}
	if env.Slot.Constraints.DecodeDepth < 1 && cstiSlotNeedsDecoding(env.Slot) {
		return false
	}
	if !in.El.CorpusComplete {
		return false
	}
	if !env.PostBaselineResolved {
		return false
	}
	return true
}

func cstiWhyNotClean(env cstiScoreEnv, in cstiPlanInput) string {
	switch {
	case env.Baseline.Samples == 0:
		return "no_baseline_model: nothing measured this endpoint's own variation, so a response that looks unchanged proves nothing"
	case env.Baseline.Degraded:
		return "baseline_degraded: the baseline model is degraded, so a silent oracle cannot be told from an unread body"
	case !env.Baseline.Stable:
		return "endpoint_too_volatile (" + env.Baseline.GateReason + "): this endpoint varies on its own, so silence is not evidence"
	case env.Slot.ValueOrigin == triage.ValueCanary:
		return "canary_resource: the slot was probed at a fabricated identifier, and a tool pointed at a resource that does not exist is not a clean scan of the endpoint"
	case env.Slot.Constraints.DecodeDepth < 1 && cstiSlotNeedsDecoding(env.Slot):
		return "decode_depth_unknown: nobody measured whether this slot percent-decodes, so braces going missing is indistinguishable from braces never arriving"
	case !in.El.CorpusComplete:
		return "corpus_capped: the served-JavaScript corpus was capped, so neither the engine set nor the delimiter set is known to be complete"
	default:
		return "post_baseline_missing: nothing re-measured the endpoint after the probes, so drift during the run cannot be ruled out"
	}
}

func cstiSlotNeedsDecoding(s triage.Slot) bool {
	switch s.Kind {
	case triage.KindHeader, triage.KindCookie:
		return false
	case triage.KindBody:
		return s.BodyMedia == triage.BodyForm
	}
	return true
}

func cstiAllProbesUntested(reason string) []triage.ProbeSkip {
	ids := []triage.ProbeID{
		cstiProbeCS1, cstiProbeCS1B, cstiProbeCS1C, cstiProbeCS1D,
		cstiProbeCS0Q, cstiProbeCS2, cstiProbeCS2V, cstiProbeCS2A, cstiProbeCS3,
		cstiProbeNav, cstiProbeNavNC,
	}
	out := make([]triage.ProbeSkip, 0, len(ids))
	for _, id := range ids {
		out = append(out, triage.ProbeSkip{ProbeID: id, Reason: reason})
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// WHAT THE LABEL HANDS THE EXPENSIVE TOOL
// ---------------------------------------------------------------------------------------------

// cstiLabelFor is where this class earns its separate existence. "SSTI" tells an operator nothing.
// "AngularJS 1.5.8, sandboxed, and here is the escape for that exact version" tells them which
// payload to give the tool, which is the difference between a productive dalfox run and a wasted
// one. The escape payloads are REPORTED and never sent: triage's job is to aim the scanner.
func cstiLabelFor(el cstiEligibility) triage.TriageLabel {
	l := triage.TriageLabel{Tools: []string{"domdig", "dalfox"}, Hints: map[string]string{}}
	if len(el.Interpolating) > 0 {
		l.Engine = string(el.Interpolating[0].Engine)
	}
	if v := el.versionOf(cstiEngineAngularJS); v != "" {
		l.Hints["angularjs_version"] = v
		sandbox, escape := cstiAngularSandbox(v)
		l.Hints["sandbox"] = sandbox
		l.Hints["escape_payload"] = escape
	}
	if v := el.versionOf(cstiEngineVue3); v != "" {
		l.Hints["vue_version"] = v
		// The Vue 3 helper names are build dependent, so the operator is told to enumerate the
		// helpers actually present rather than to assume _openBlock exists in this bundle.
		l.Hints["escape_payload"] = "{{_openBlock.constructor('alert(1)')()}} (helper names are build dependent: enumerate the helpers in the served bundle)"
	}
	if v := el.versionOf(cstiEngineVue2); v != "" {
		l.Hints["vue_version"] = v
		l.Hints["escape_payload"] = "{{this.constructor.constructor('alert(1)')()}}"
	}
	if el.AngularCSPMode {
		l.Hints["angular_csp_mode"] = "true: the Function-constructor escapes fail under ng-csp. Expression evaluation still works, so do not waste a run on a dead payload"
	}
	if len(el.CustomDelims) > 0 {
		pairs := make([]string, 0, len(el.CustomDelims))
		for _, d := range el.CustomDelims {
			pairs = append(pairs, d[0]+" "+d[1])
		}
		l.Hints["delimiters"] = strings.Join(pairs, ", ")
	}
	return l
}

// cstiAngularSandbox maps an AngularJS version to its sandbox state and the escape that works
// against it. The sandbox was removed in 1.6.0, and PortSwigger's version table is the source.
func cstiAngularSandbox(version string) (string, string) {
	maj, min, dot := cstiSemver(version)
	switch {
	case maj != 1:
		return "unknown", "version " + version + " is not AngularJS 1.x; confirm the engine before choosing a payload"
	case min >= 6:
		return "removed", "{{constructor.constructor('alert(1)')()}}"
	case min == 1 || min == 0:
		return "none", "{{constructor.constructor('alert(1)')()}}"
	case min == 2 && dot <= 5:
		return "present", `{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}`
	case min == 2 && dot <= 18:
		return "present", `{{(_=''.sub).call.call({}[$='constructor'].getOwnPropertyDescriptor(_.__proto__,$).value,0,'alert(1)')()}}`
	case min == 2 && dot == 19:
		return "present", `{{c=toString.constructor;p=c.prototype;p.toString=p.call;["a","alert(1)"].sort(c)}}`
	case min == 2:
		return "present", `{{a="a"["constructor"].prototype;a.charAt=a.trim;$eval('a",alert(alert=1),"')}}`
	case min == 5 && dot >= 9:
		return "present", `the $event/AST escape: <input autofocus ng-focus="$event.path|orderBy:'[].constructor.from([1],alert)'">`
	default:
		return "present", `{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('a,alert(1),a')}}`
	}
}

func cstiSemver(v string) (int, int, int) {
	parts := strings.SplitN(v, ".", 4)
	get := func(i int) int {
		if i >= len(parts) {
			return 0
		}
		n, err := strconv.Atoi(strings.TrimSpace(parts[i]))
		if err != nil {
			return 0
		}
		return n
	}
	return get(0), get(1), get(2)
}

// Confirmers are the expensive tools this label points at. domdig is primary because it runs a
// real Chromium and its check set includes template evaluation; dalfox takes the version-selected
// escape payload directly.
func (cstiClassifier) Confirmers() []string { return []string{"domdig", "dalfox"} }

// Evidencers produce evidence and never confirmation. A nuclei technology template can tell you
// AngularJS is present, which is this class's PRECONDITION, not its finding.
func (cstiClassifier) Evidencers() []string { return []string{"nuclei-dast"} }

// SETTLE IS DELIBERATELY ABSENT. This class has no out-of-band evidence: the browser navigation
// resolves inside the run and there is no callback to wait for. Package triage declares no
// SettleView or Revision type yet, so a no-op here would be a method with an invented signature
// that no runner will ever call, which is worse than the honest absence. If the browser tier is
// later made asynchronous, Settle is where the late render lands, and it may only move a verdict
// UPWARD: a row already shown as suspicious must never silently become clean.

// ---------------------------------------------------------------------------------------------
// THE ORACLE ENDPOINTS THIS CLASS NEEDS BUILT
// ---------------------------------------------------------------------------------------------

type cstiExpect string

const (
	cstiExpectPositive cstiExpect = "positive"
	cstiExpectNegative cstiExpect = "negative"
)

// cstiOracleCase is one endpoint the oracle pass must build, with the verdict this class must
// reach against it. The type is class-local because package triage declares no shared one yet.
type cstiOracleCase struct {
	Path   string
	Expect cstiExpect
	State  triage.TriageState
	Note   string
}

// OracleCases. The negatives outnumber the positives on purpose: a detector never shown to STAY
// SILENT is not a verified detector, and every false positive mode named in iso-client B.6 gets
// its own endpoint here rather than a sentence in a document.
func (cstiClassifier) OracleCases() []cstiOracleCase {
	return []cstiOracleCase{
		{Path: "/csti/angular", Expect: cstiExpectPositive, State: triage.StateFinding,
			Note: "AngularJS 1.5.8 with ng-app on <body> and the q parameter reflected as text inside it. The browser pair must render the product"},
		{Path: "/csti/vue3-full", Expect: cstiExpectPositive, State: triage.StateFinding,
			Note: "Vue 3 FULL build (vue.global.js) mounted on #app, q reflected inside #app. Proves the build discriminator lets the eligible build through"},
		{Path: "/csti/angular-attr", Expect: cstiExpectPositive, State: triage.StateSuspicious,
			Note: "AngularJS, braces stripped from TEXT, attribute values unfiltered. CS-0q must create the attribute first and only then may CS-2 be sent"},
		{Path: "/csti/angular-hash", Expect: cstiExpectPositive, State: triage.StateFinding,
			Note: "AngularJS with $location in hash mode, rendering the fragment. The HTTP tier is not_applicable here, so this endpoint is the only proof the fragment path works"},

		{Path: "/csti/plain", Expect: cstiExpectNegative, State: triage.StateNotApplicable,
			Note: "no framework at all, q reflected as text. Must be not_applicable (no_client_template_engine) with ZERO requests sent"},
		{Path: "/csti/aot", Expect: cstiExpectNegative, State: triage.StateNotApplicable,
			Note: "Angular 17, ng-version and _ngcontent- attributes. Must be not_applicable (angular_aot), never clean and never suspicious"},
		{Path: "/csti/vue-runtime", Expect: cstiExpectNegative, State: triage.StateNotApplicable,
			Note: "Vue 3 RUNTIME-ONLY build serving the runtime-only warning string. Must be not_applicable (vue_runtime_only)"},
		{Path: "/csti/nonbindable", Expect: cstiExpectNegative, State: triage.StateNotExploitable,
			Note: "AngularJS with the reflection inside <span ng-non-bindable>. A named defence, so not_exploitable, and the delimiters must NOT be a candidate"},
		{Path: "/csti/inscript", Expect: cstiExpectNegative, State: triage.StateClean,
			Note: "AngularJS with ng-app resolved, reflection inside <script>. The engine does not compile script content, so the site is not a candidate"},
		{Path: "/csti/escaped", Expect: cstiExpectNegative, State: triage.StateClean,
			Note: "AngularJS, the marker returns and the braces are stripped with nothing in their place. clean (delimiters_stripped), and only with a stable baseline"},
		{Path: "/csti/jinja", Expect: cstiExpectNegative, State: triage.StateCannotDetermine,
			Note: "SERVER-rendered Jinja2 that evaluates {{ }} itself. CS-D2 must fire: cannot_determine (server_side_evaluation) with the SSTI hand-off, never a CSTI finding"},
		{Path: "/csti/calculator", Expect: cstiExpectNegative, State: triage.StateCannotDetermine,
			Note: "AngularJS present AND the app multiplies the two numbers in the parameter itself. NC-B1 must fire: cannot_determine (control_contaminated). Without this endpoint a calculator is a CSTI finding"},
		{Path: "/csti/corpus-blocked", Expect: cstiExpectNegative, State: triage.StateCannotDetermine,
			Note: "a page whose only script src 403s. Must be cannot_determine (framework_undetermined) and must NOT be not_applicable: this is the rule that keeps a failed detection from reading as clean"},
		{Path: "/csti/pct-literal", Expect: cstiExpectNegative, State: triage.StateCannotDetermine,
			Note: "AngularJS, and the app echoes the query value WITHOUT percent-decoding. The braces come back as %7B, so cannot_determine (delimiters_not_delivered), never clean"},
		{Path: "/csti/product-in-baseline", Expect: cstiExpectNegative, State: triage.StateCannotDetermine,
			Note: "AngularJS, and the unperturbed page already prints 49088107. The browser probe must switch to the fallback pair rather than report a finding on digits that were already there"},
	}
}
