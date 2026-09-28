package triageclasses

import (
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS REDIRECT (id 18). OPEN REDIRECT: a value from this slot ends up as the AUTHORITY of a
// Location the protocol acts on.
//
// WHY THIS IS A PROTOCOL-EFFECT CLASS AND NOT A REFLECTION CLASS, WHICH IS THE WHOLE DESIGN. The
// question is not "does our string come back". It is "did the parsed authority of the Location
// change to a host we named". Those two differ on exactly the case that makes every open-redirect
// scanner noisy:
//
//	Location: /login?next=%2F%2Fzqj0000000000abc.rdr.invalid
//
// Our marker is in there. Our host is in there. The browser follows it to the ORIGIN'S OWN LOGIN
// PAGE. A detector that greps the Location for the marker reports a finding on every application
// that has a "come back here afterwards" parameter, which is most of them, and the operator learns
// to ignore the class. So the marker must be in the AUTHORITY of the RESOLVED url, and
// protoeffect.go's pxHostInAuthorityPosition and pxResolveBoth are what make that a rule rather
// than an intention.
//
// WHY IT COSTS ONE REQUEST ON THE COMMON PATH. MEASURED in shipped code: the triage transport is
// built with http.ErrUseLastResponse (utils/triageEncode.go) and the runner copies the raw
// Location straight onto the observation (utils/triageRun.go). So a 3xx comes back to this class
// with its Location unfollowed and unparsed, in the same response that carried the payload. There
// is no follow-up request and no second round needed to see the effect.
//
// AND THE CONSEQUENCE OF THAT, WRITTEN DOWN BECAUSE THE FIELD NAME INVITES THE MISTAKE:
// Observation.RedirectChain is ALWAYS zero or one element. It is not a chain. No verdict in this
// class may say "the chain left the origin at hop 3", because this class cannot see hop 2.
//
// =================================================================================================
// THE TWO RESOLUTION MODELS, AND WHY A SINGLE ONE WOULD REPORT CLEAN ON THREE REAL BUGS
// =================================================================================================
// MEASURED on this machine with net/url against base http://app.example.test/a/b:
//
//	////H.rdr.invalid/    RFC 3986 -> app.example.test, path ////H.rdr.invalid/
//	\/\/H.rdr.invalid/    RFC 3986 -> app.example.test, path /a/%5C/%5C/H.rdr.invalid/
//	/\/H.rdr.invalid/     RFC 3986 -> app.example.test, path /%5C/H.rdr.invalid/
//	https:H.rdr.invalid/  RFC 3986 -> no authority at all (an opaque reference)
//
// All four are working open redirects in a browser and all four are harmless to net/url. A class
// that resolved only the strict way would send those four payloads, see four on-origin results and
// report clean on a live bug four separate times. So every Location is read TWICE, once under RFC
// 3986 and once under the three WHATWG normalisations pxBrowserForm performs, and the two models
// DISAGREEING is its own verdict: suspicious, oracle protocol_effect_parser_dependent, graded
// medium, with both readings in the annotations and the reason saying in as many words that no
// browser was in the loop. Grading that high would be asserting a browser behaviour nobody here
// measured against a browser.
//
// =================================================================================================
// WHAT THIS CLASS DOES NOT SHIP, AND WHY, SO NOBODY READS THE ABSENCE AS COVERAGE
// =================================================================================================
//
//	THE WHITELIST-PREFIX AND USERINFO BYPASSES. https://<target host>@evil/ and
//	https://<target host>.evil/ are the two most productive payloads in the whole category and
//	NEITHER IS SHIPPED, because both need the target's own host inside the payload bytes and this
//	class cannot obtain it. ProbeSpec.Logical is fixed at declaration time, which is what makes the
//	build-time isolation check possible, and the runner's ${...} substitution grammar is
//	CLASS-SCOPED to ClassTraversal, ClassLFI and ClassRFI (utils/triageRun.go,
//	triageUsesDollarTokens). A class outside that list has exactly one token: the universal
//	triage.MarkerPlaceholder. Shipping those two payloads with a made-up host would test a
//	whitelist bypass against a whitelist that does not contain the made-up host, which is a probe
//	that cannot fire dressed as one that did. The gap is named on every verdict this class writes.
//
//	THE NULL-BYTE FORM //H%00.rdr.invalid/. MEASURED: net/url refuses it outright with
//	`invalid URL escape "%00"`, under both models. The bypass works precisely because a
//	SERVER-SIDE validator stops at the NUL and a browser does not, and modelling "and a browser
//	does not" without a browser is guessing. Not shipped.
//
//	THE IDEOGRAPHIC FULL STOP AND THE IDNA FAMILY. Each fires on one normalisation bug in one
//	parser chain, costs a request on every slot, and needs a real IDNA implementation to score
//	honestly. recollapse is the framework's own tool for exactly this sweep and this class's job is
//	to tell it which slot to sweep.
//
// =================================================================================================
// WHAT THE POINTER IS FOR
// =================================================================================================
// A triage hit here is nearly the proof of concept already: an operator can paste the composed URL
// into a browser and watch it leave. What triage adds is the NEXT step for the two cases it cannot
// finish. When the slot reaches the Location and every off-origin form was refused, that is a
// filter, and recollapse (a framework container, and the framework's own scanner) is the tool that
// sweeps encoding mutations against a filter. When the slot reaches the Location and something got
// through, nuclei's DAST redirect templates are the second detector. Both pointers are only worth
// handing over on a slot that is known to reach the Location, and that is exactly what RDR-NC2
// establishes for two bytes of payload and one request.

type redirectClassifier struct{}

func init() { triage.RegisterClassifier(redirectClassifier{}) }

func (redirectClassifier) ID() triage.ClassID { return triage.ClassRedirect }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	rdrA1  triage.ProbeID = "RDR-A1"
	rdrA2  triage.ProbeID = "RDR-A2"
	rdrA3  triage.ProbeID = "RDR-A3"
	rdrA4  triage.ProbeID = "RDR-A4"
	rdrA5  triage.ProbeID = "RDR-A5"
	rdrA6  triage.ProbeID = "RDR-A6"
	rdrA7  triage.ProbeID = "RDR-A7"
	rdrNC1 triage.ProbeID = "RDR-NC1"
	rdrNC2 triage.ProbeID = "RDR-NC2"
)

// rdrHostSuffix is the only authority this class will ever call a finding.
//
// IT IS UNRESOLVABLE ON PURPOSE AND THAT IS THE FEATURE. RFC 6761 section 6.4 reserves .invalid
// and guarantees it never resolves, so no payload here names a domain anybody could register and
// then receive a redirected user on, and a target that follows the redirect itself reaches
// nothing. It is also what removes the need for a public-suffix list: "the authority is a host
// under .rdr.invalid carrying this probe's own marker" is an exact test, where "the authority is
// not a subdomain of the target's registrable domain" would need a PSL this layer does not have.
//
// The label is distinct from RFI's .rfi-inband.invalid and .nxnc.invalid so that no operator and
// no log line can confuse the two classes' traffic.
const rdrHostSuffix = ".rdr.invalid"

// rdrValuePoints and rdrValueEncoders are where this class's payloads can go.
var rdrValuePoints = []triage.SlotKind{
	triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie, triage.KindHeader,
}

var rdrValueEncoders = []triage.EncoderMode{
	triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodePathSegment,
	triage.EncodeCookie, triage.EncodeHeaderValue,
}

func (redirectClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassRedirect
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: rdrA1, Class: c, Logical: []byte("http://" + m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the base case: a fully qualified absolute URL. Both resolution models agree on it, so " +
				"it is the one payload in this class that can reach a finding with no parser-dependency " +
				"caveat at all. It is also the only probe sent in round 0 besides the reach control, " +
				"because on the overwhelming majority of slots the answer is 'this value never reaches a " +
				"Location' and the ladder must not spend nine requests discovering that",
		},
		{
			ID: rdrA2, Class: c, Logical: []byte("//" + m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "scheme-relative. MEASURED: both models resolve it to our authority, so it too can " +
				"reach a finding outright. It exists separately from A1 because the single commonest " +
				"open-redirect filter in the world is a blacklist on the string http, and a value with no " +
				"scheme in it walks past that filter while testing the same sink",
		},
		{
			ID: rdrA3, Class: c, Logical: []byte("////" + m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "four slashes. MEASURED: RFC 3986 keeps this ON ORIGIN with the whole thing as a path, " +
				"and the WHATWG special-authority-ignore-slashes state consumes the extra pair, so a " +
				"browser leaves. It can therefore only ever reach suspicious from here, and the reason " +
				"says why: a validator that used the strict reading and a browser that uses the loose one " +
				"is the bug, and confirming it needs a browser this layer does not have",
		},
		{
			ID: rdrA4, Class: c, Logical: []byte("https:" + m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "a special scheme with its slashes omitted. MEASURED: net/url makes this an OPAQUE " +
				"reference with no authority whatever, while the WHATWG special-authority-slashes state " +
				"tolerates the missing pair and reaches the authority. It is the payload for a filter " +
				"blacklisting the two slashes rather than the scheme, and it is browser-only, so " +
				"suspicious is its ceiling",
		},
		{
			ID: rdrA5, Class: c, Logical: []byte(`\/\/` + m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "backslash-slash twice. MEASURED: RFC 3986 percent-escapes the backslashes into the " +
				"path and stays on origin; WHATWG maps every backslash in a special URL to a slash, which " +
				"makes this ////host and then //host. Browser-only, suspicious ceiling",
		},
		{
			ID: rdrA6, Class: c, Logical: []byte(`/\/` + m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "slash-backslash-slash, the form that gets past a filter checking only whether the " +
				"value starts with two slashes. Same measurement and same browser-only ceiling as A5",
		},
		{
			ID: rdrA7, Class: c, Logical: []byte(m + rdrHostSuffix + "/"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "A BARE HOSTNAME, AND IT IS NOT A NEGATIVE CONTROL, WHICH IS A CORRECTION WORTH " +
				"WRITING DOWN. The obvious design makes this the control: a conforming redirector treats " +
				"a bare hostname as a relative reference, emits Location: /a/<host>/ and stays on origin, " +
				"so 'it must stay silent' looks like the perfect test that the detector parses rather " +
				"than greps. It is the wrong reading. An application that builds its Location as " +
				"\"http://\" + value turns THIS payload into an off-origin authority, and that is not a " +
				"broken detector, it is a STRONGER finding than A1: the sink supplies the scheme itself, " +
				"so every scheme blacklist on the value is beside the point. A hit here is therefore " +
				"reported, with oracle scheme_prepended_to_bare_host. The detector property the naive " +
				"design wanted is asserted where it belongs, in redirect_test.go, over a handcrafted " +
				"Location, and at run time it is RDR-NC1 that carries it",
		},
		{
			ID: rdrNC1, Class: c, Logical: []byte("/" + m + "-rdr-local"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE DETECTOR CONTROL, and the one probe in this class whose firing means the class " +
				"is wrong rather than the target is. It is an origin-absolute path, so a redirector that " +
				"honours it emits Location: /<marker>-rdr-local. The marker IS in the Location, the " +
				"Location DID change from the baseline, and the correct verdict is that nothing was " +
				"found. Every naive open-redirect detector ever written fires here: 'the marker is in the " +
				"Location', 'the Location differs from baseline', 'the response is a 302 it was not " +
				"before'. If this probe's resolved authority is ever a host under .rdr.invalid then " +
				"either the resolver is wrong or something rewrote our payload, and every verdict on " +
				"this slot becomes detector_unverified",
		},
		{
			ID: rdrNC2, Class: c, Logical: []byte("rdr-" + m + "-inert"),
			Encoders: rdrValueEncoders, Points: rdrValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE REACH CONTROL, AND IT IS WHAT MAKES A CLEAN POSSIBLE. It carries no scheme, no " +
				"slash, no colon and no dot: there is nothing in it for a URL filter to object to, so it " +
				"is the one value in this class an input validator has no reason to reject. Its job is to " +
				"answer a question no payload can answer about itself: does this slot reach the Location " +
				"at all? Without it, 'A1 produced an on-origin Location' has two readings that demand " +
				"opposite verdicts. If the slot does not feed the Location, the class has found nothing " +
				"and says clean. If the slot DOES feed it and every off-origin form was refused, that is " +
				"a filter doing its job, which is not_exploitable with a named defence and is a different " +
				"and more useful answer. One request buys the difference",
		},
	}
}

// rdrReducedLadder and rdrFullLadder are the round-1 sets. Declared as functions rather than
// package variables so a caller cannot mutate the ladder of a running class.
func rdrRound0() []triage.ProbeID { return []triage.ProbeID{rdrA1, rdrNC2} }

func rdrRound1() []triage.ProbeID {
	return []triage.ProbeID{rdrNC1, rdrA2, rdrA7, rdrA3, rdrA4, rdrA5, rdrA6}
}

func rdrAllProbeIDs() []triage.ProbeID { return append(rdrRound0(), rdrRound1()...) }

// rdrBrowserOnly names the probes whose effect exists in a browser's parser and not in RFC 3986's.
// A hit from one of these can never be graded above medium and can never be a finding.
func rdrBrowserOnly(id triage.ProbeID) bool {
	switch id {
	case rdrA3, rdrA4, rdrA5, rdrA6:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. Every value-bearing insertion point can hold a URL, so the honest answer nearly
// everywhere is that this class reaches it, with the caveat that matters recorded as the
// condition.
func (redirectClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "MEASURED: no encoder in this layer writes a raw '/' into a query VALUE, so every " +
				"payload here arrives percent-encoded as %2F%2F. That is the right thing for the common " +
				"case, because an application reading the parameter decodes it before using it as a " +
				"Location, and it means the RAW form is untested: a filter that inspects the undecoded " +
				"query string sees %2F%2F where it was looking for //. Every verdict carries " +
				"wire_form=percent_encoded and this class does not claim to have tested the raw form",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a JSON string slot or a urlencoded form field takes the URL unchanged. A JSON NUMBER " +
				"slot is string-coerced only, and a 400 there is a type rejection and never a clean. " +
				"Request media type seen: " + string(mt),
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a path segment takes the payload with its slashes percent-encoded, deliberately, so " +
				"that the probe cannot change which route runs; a response from a different route says " +
				"nothing about this slot. The consequence is the same as for a query value and is " +
				"annotated the same way",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "every byte in this class is cookie-octet, so the URL is deliverable raw, but a " +
				"redirect driven by a cookie is uncommon and these slots are probed after the value " +
				"slots rather than instead of them",
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "referer is the one header that routinely drives a redirect, and the x-forwarded and " +
				"x-original families reach routers that build one. No byte in this class is CR, LF or NUL, " +
				"so all of them are deliverable in a header value",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the fragment is never transmitted (RFC 3986 section 3.5), so the server never sees " +
				"the value and cannot put it in a Location. A browser-side redirect driven by the " +
				"fragment is real and belongs to the DOM classes, which have a browser",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "slot kind " + string(k) + " is not in the model this class was written against",
		}
	}
}

// ---------------------------------------------------------------------------------------------
// PLAN
// ---------------------------------------------------------------------------------------------

// Plan is two requests, then seven more only on a slot that showed it reaches the Location.
//
// THE GATE IS A MEASUREMENT AND NOT A GUESS. A parameter-name list (next, url, redirect_uri and
// the rest) ORDERS the work and must never suppress it: the codebase's standing rule is that a
// shape guess which suppresses a probe is a silent zero, and a parameter called "id" that turns
// out to feed a Location is exactly the bug this layer exists for. So round 0 goes out on every
// eligible slot and the round-1 ladder is gated on what round 0 OBSERVED.
func (c redirectClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType).Reach == triage.ReachNever {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() || ctx.Budget.Exhausted() {
		return nil
	}

	switch ctx.Round {
	case 0:
		return rdrPlanFor(rdrRound0(), ctx.Slot.Key)
	case 1:
		if !rdrLadderIsWorthIt(ctx) {
			return nil
		}
		return rdrPlanFor(rdrRound1(), ctx.Slot.Key)
	default:
		return nil
	}
}

func rdrPlanFor(ids []triage.ProbeID, key triage.SlotKey) []triage.ProbeRequest {
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		out = append(out, pxReq(id, key))
	}
	return out
}

// rdrLadderIsWorthIt decides whether the seven-request bypass ladder buys anything on this slot.
//
// Three ways to say yes, and each one is a different piece of evidence that the slot is connected
// to the Location:
//
//   - a round-0 probe's Location carries that probe's own marker ANYWHERE, authority or not. Even
//     in the path or the query, that proves the value reached the sink, which is the expensive
//     half of the question.
//   - the inert reach control's marker reached the Location. Same proof, from the one value a
//     filter has no reason to reject.
//   - the ROUTE CONTROL redirected and our probes did not. That is the shape of a validator that
//     rejected the payload and took another branch, and it is the case that looks most like a
//     clean and is furthest from one: something read our value and made a decision about it.
//
// Saying no costs the class nothing it could have known: with none of those three, no payload in
// the ladder can produce a Location either, and the slot is decided by round 0 alone.
func rdrLadderIsWorthIt(ctx triage.PlanCtx) bool {
	own := faOwn(ctx.Own)
	sawRedirect := false
	for _, o := range own {
		if _, ok := pxWireIsHonest(o.Obs); !ok {
			continue
		}
		loc, has := pxLocation(o.Obs)
		if !has {
			continue
		}
		sawRedirect = true
		if o.Marker != "" && strings.Contains(strings.ToLower(loc), strings.ToLower(string(o.Marker))) {
			return true
		}
	}
	if !sawRedirect && ctx.Route.Resolved() && pxIsRedirectStatus(ctx.Route.Obs().Status) {
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

// rdrHit is one probe's reading of its own Location under both models.
type rdrHit struct {
	obs      faOwnObs
	location string
	// StrictOff and BrowserOff report whether that model resolved the authority to a host under
	// .rdr.invalid carrying THIS probe's own marker.
	strictOff  bool
	browserOff bool
	strict     pxResolution
	browser    pxResolution
	// MarkerAnywhere is the weaker fact: the marker is somewhere in the Location, which proves
	// reach and proves nothing about the authority.
	markerAnywhere bool
}

func (c redirectClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassRedirect, key, state, reason, oracle, grade, ords, ann, rdrLabel(ann))
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}

	ann["wire_form"] = rdrWireForm(ctx.Slot)
	ann["host_dependent_payloads_not_shipped"] = "the whitelist-prefix and userinfo bypasses need the " +
		"target's own host inside the payload bytes, and the runner's substitution grammar is scoped to " +
		"the file-access classes, so this class cannot ask for it. Those two forms are NOT tested here"
	if h, off := pxRouteRedirectsOffOrigin(ctx); off {
		ann["route_control_already_redirects_off_origin"] = h
	}

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		return one(rdrNothingSent(ctx))
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+
					"), so the set this verdict would be drawn from is not this class's set",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	honest, skips := pxHonest(own)
	skips = append(skips, pxNotObserved(rdrAllProbeIDs(), own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload was refused, altered or left unsubstituted, so "+
				"nothing about this slot was measured and the silence is ours and not the target's",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	hits := rdrRead(honest)

	// THE DETECTOR CONTROL FIRST. Everything after it is a claim about the target, and a claim
	// about the target drawn through a detector that has just been shown to misfire is worse than
	// no claim at all.
	if h, ok := rdrFind(hits, rdrNC1); ok && (h.strictOff || h.browserOff) {
		ann["control_that_fired"] = string(rdrNC1)
		ann["control_resolutions"] = pxDescribeResolutions(h.strict, h.browser)
		v := one(triage.StateCannotDetermine,
			"detector_unverified: RDR-NC1 is an origin-absolute path and its resolved authority came back "+
				"as a host under "+rdrHostSuffix+". A conforming resolver cannot produce that from a value "+
				"beginning with a single slash, so either the resolution is wrong or something between this "+
				"process and the application rewrote the payload. No verdict on this slot is safe",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE FINDING. Both models agree that the authority left the origin for a host we named.
	//
	// THE UNIFORM-BLOCK GUARD USED TO RUN HERE AND IT HAS BEEN MOVED BELOW THE THREE POSITIVE
	// ARMS. MEASURED on the canary oracle, 2026-09-19: on /redirect/local and
	// /redirect/strictvalidator, every payload the validator refused got the same short body
	// while the baseline's differed, so faUniformBlock, which reads BODIES ONLY, called the
	// application a filter and this class answered cannot_determine (blocked) where it should
	// have answered not_exploitable on one and suspicious on the other. A redirector's body is
	// nearly always constant: the evidence in this class lives in the Location, and a guard that
	// cannot see the Location must not be allowed to overrule what is in it.
	for _, h := range hits {
		if h.obs.ProbeID == rdrNC1 || h.obs.ProbeID == rdrNC2 {
			continue
		}
		if !h.strictOff || !h.browserOff {
			continue
		}
		oracle, grade := "location_authority", triage.GradeHigh
		reason := "open_redirect: the Location this response carried resolves, under BOTH the RFC 3986 " +
			"reference resolution and the WHATWG browser reading, to an authority that is a host under " +
			rdrHostSuffix + " carrying this probe's own 16-byte marker. The application did not choose that " +
			"host; this slot did. A user following this response leaves the origin"
		if h.obs.ProbeID == rdrA7 {
			oracle = "scheme_prepended_to_bare_host"
			reason = "open_redirect_sink_supplies_the_scheme: RDR-A7 carries a BARE HOSTNAME with no scheme " +
				"and no leading slash, which a conforming redirector treats as a relative reference and keeps " +
				"on origin. It did not stay on origin, so the application built the absolute URL itself, " +
				"which means every filter that inspects the value for a scheme or for two leading slashes is " +
				"beside the point on this sink. This is a stronger shape than RDR-A1's and the tool pointer " +
				"says so"
		}
		ann["winning_probe"] = string(h.obs.ProbeID)
		ann["resolutions"] = pxDescribeResolutions(h.strict, h.browser)
		ann["location_raw"] = h.location
		v := one(triage.StateFinding, reason, oracle, grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: h.obs.Ordinal, Phrase: oracle, Matched: []byte(h.location), Length: len(h.location),
			Wire: h.obs.Obs.Payload,
		}
		return v
	}

	// THE PARSER-DEPENDENT ARM. One model leaves and the other does not.
	for _, h := range hits {
		if h.obs.ProbeID == rdrNC1 || h.obs.ProbeID == rdrNC2 {
			continue
		}
		if h.strictOff == h.browserOff {
			continue
		}
		ann["winning_probe"] = string(h.obs.ProbeID)
		ann["resolutions"] = pxDescribeResolutions(h.strict, h.browser)
		ann["location_raw"] = h.location
		ann["browser_only_payload"] = rdrBrowserOnly(h.obs.ProbeID)
		v := one(triage.StateSuspicious,
			"parser_dependent_redirect: the two readings of this Location DISAGREE. "+
				pxDescribeResolutions(h.strict, h.browser)+". That disagreement is the bug in its usual "+
				"form: a server-side validator satisfied itself with the strict reading while the browser "+
				"that actually follows the header uses the loose one. It is reported as suspicious and not "+
				"as a finding for one honest reason, which is that NO BROWSER WAS IN THE LOOP HERE. The "+
				"WHATWG reading is modelled by three named normalisations in protoeffect.go and modelled is "+
				"not measured. Open the composed URL in a browser and watch the address bar; that takes one "+
				"minute and settles it",
			"protocol_effect_parser_dependent", triage.GradeMedium, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: h.obs.Ordinal, Phrase: "parser_dependent_redirect",
			Matched: []byte(h.location), Length: len(h.location), Wire: h.obs.Obs.Payload,
		}
		return v
	}

	// THE DOCUMENT ARM, WHICH IS A WEAKER ORACLE AND SAYS SO. A Refresh header, a meta refresh or
	// a script assignment is a real redirect mechanism and it is not a protocol effect: the value
	// was placed in a document for a client to interpret, so it is rank 7 wearing rank 5's coat.
	// It is capped at suspicious and graded low, and it can never produce a finding in this class.
	for _, h := range hits {
		if h.obs.ProbeID == rdrNC1 || h.obs.ProbeID == rdrNC2 {
			continue
		}
		where, ok := rdrDocumentRedirect(h)
		if !ok {
			continue
		}
		ann["winning_probe"] = string(h.obs.ProbeID)
		ann["document_redirect_site"] = where
		v := one(triage.StateSuspicious,
			"document_redirect_reflection: this probe's own host appears in the AUTHORITY position of a URL "+
				"in "+where+", and not in a Location the protocol acts on. That is a real redirect "+
				"mechanism and a weaker oracle: a document a client may or may not interpret, rather than a "+
				"header the protocol does. It is graded low and it is never a finding in this class. What it "+
				"is good for is telling the operator that this slot reaches a URL the page builds",
			"body_redirect_reflection", triage.GradeLow, ords)
		v[0].Untested = skips
		return v
	}

	// Nothing fired. Now the three negatives, and which one is correct depends entirely on the
	// reach control, which is why it is worth its request.
	reach, reachKnown := rdrReachKnown(hits)

	// A FILTER ANSWERING IS NOT THE APPLICATION ANSWERING, asked after the positive arms and
	// AFTER THE REACH CONTROL HAS BEEN READ, because on this class the two rules describe the
	// same pixel and only the control tells them apart.
	//
	// MEASURED on /redirect/local, the route written to be this class's named-defence negative:
	// the validator refuses every off-origin form and 302s them all to "/", so six of this
	// class's distinct payloads produced one identical non-baseline response. That is the
	// letter of the uniform-block rule and it is the WRONG READING, because the application is
	// what produced it: the inert control's own value went into the Location on the same route,
	// which is proof the request reached the redirect logic and no intermediary stood in front
	// of it. A filtered redirector answering uniformly is the SIGNATURE of the defence this
	// class reports, not evidence that the class saw nothing, and asked before the control was
	// read the guard converted redirect_target_filtered into a shrug.
	//
	// So: if the reach control was measured AND reached, the block claim is refused by
	// construction. Everywhere else the guard stands, because there the uniform answer really
	// could have come from something that never let us through.
	if !(reachKnown && reach) && pxUniformBlock(ctx, honest) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical "+
				"non-baseline responses and the inert reach control did not reach the Location, so a "+
				"filter answered and the application's redirect logic was never reached",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	ann["slot_reaches_location"] = reach
	ann["reach_control_measured"] = reachKnown
	routeStatus, haveRoute := pxRouteStatus(ctx)
	anyProbeRedirected := false
	for _, h := range hits {
		if h.location != "" {
			anyProbeRedirected = true
			break
		}
	}
	ann["probe_produced_a_redirect"] = anyProbeRedirected
	if haveRoute {
		ann["route_control_status"] = routeStatus
	}

	switch {
	case !reachKnown:
		v := one(triage.StateCannotDetermine,
			"reach_control_not_measured: RDR-NC2, the inert value that answers whether this slot feeds the "+
				"Location at all, did not reach the wire on this slot. Without it, an on-origin Location has "+
				"two readings that demand opposite verdicts (the slot is not connected to the redirect, or "+
				"the slot is connected and a filter refused our value) and nothing here distinguishes them",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v

	case reach:
		// The slot DOES steer the Location and every off-origin form we sent was neutralised.
		// That is a defence, named, and it is a different and better answer than clean.
		ann["clean_preconditions"] = []string{
			"RDR-NC2's inert value reached the Location, so this slot demonstrably feeds the redirect target",
			"RDR-NC1, the origin-absolute control, resolved to the origin under both models",
			"no probe's Location resolved to an authority under " + rdrHostSuffix + " under either model",
		}
		v := one(triage.StateNotExploitable,
			"redirect_target_filtered: this slot REACHES the Location (the inert control's marker came back "+
				"in it) and every off-origin form this class sent was neutralised. A named defence is "+
				"stopping it, which is a real negative and not a silence. WHAT IT DOES NOT COVER: the two "+
				"host-dependent bypasses this class cannot ship, the raw-slash wire form, and the whole "+
				"encoding-mutation space. This is the slot to point recollapse at, and that pointer is on "+
				"the label",
			"filter_held", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v

	case !anyProbeRedirected && (!haveRoute || !pxIsRedirectStatus(routeStatus)):
		ann["clean_preconditions"] = []string{
			"neither this class's probes nor the unperturbed route control produced a 3xx with a Location",
			"the inert reach control was on the wire and its marker never appeared in a Location",
			"RDR-NC1, the origin-absolute control, stayed on origin",
		}
		v := one(triage.StateClean,
			"slot_produced_no_redirect: this endpoint emitted no Location at all, on the unperturbed control "+
				"or on any of this class's payloads, and the inert reach control proves the failure is not "+
				"our value being rejected. There is no redirect here for this slot to steer",
			"no_location_emitted", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v

	case !anyProbeRedirected && haveRoute && pxIsRedirectStatus(routeStatus):
		v := one(triage.StateCannotDetermine,
			"redirect_suppressed_by_payload: the unperturbed route control returned status "+
				strconv.Itoa(routeStatus)+" with a Location and not one of this class's probes "+
				"did. The application read our value and took a different branch, which is the outcome that "+
				"looks most like a clean and is furthest from one: something is validating this input and we "+
				"did not see what it does with a value it accepts",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v

	default:
		ann["clean_preconditions"] = []string{
			"the endpoint does emit a Location and no payload of this class ever appeared in it",
			"the inert reach control was on the wire and its marker never appeared in the Location either",
			"RDR-NC1, the origin-absolute control, stayed on origin",
		}
		v := one(triage.StateClean,
			"slot_does_not_reach_location: this endpoint redirects, and the target it redirects to is fixed. "+
				"Neither the payloads nor the inert reach control put a single byte into the Location, so this "+
				"slot is not what chooses the destination",
			"value_absent_from_location", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
}

// Settle. Nothing in this class is decided out of band, so there is nothing to wait for. It is a
// method and not an absence so that a reader can see the question was asked.
func (redirectClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

// rdrNothingSent maps "this class has no observations at all" onto the right unknown. Each of the
// four is a different fact and none of them is a clean.
func rdrNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"control to difference a Location against and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain, so every probe would " +
				"have measured the same validation failure", "", triage.GradeUnrated, nil
	}
	// THE LAST TWO ARMS LIVE IN pxNothingSentTail AND THE ORDER IS THE WHOLE POINT. See
	// pxbudgetarm.go: the budget read here is the one left at scoring time, not the one the
	// planner was shown, and putting it above the default made not_planned unreachable on every
	// capped run.
	state, reason := pxNothingSentTail(ctx, len(rdrRound0()), "a redirect probe",
		"no redirect probe was derived for this slot and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// rdrRead resolves every honest observation's Location under both models.
func rdrRead(honest []faOwnObs) []rdrHit {
	out := make([]rdrHit, 0, len(honest))
	for _, o := range honest {
		h := rdrHit{obs: o}
		loc, ok := pxLocation(o.Obs)
		if ok && pxIsRedirectStatus(o.Obs.Status) {
			h.location = loc
		} else if ok {
			// A Location on a non-3xx is recorded but never scored as a redirect: a 200 carrying
			// a Location is not a redirect and a browser does not follow it. Keeping the raw
			// value means the evidence row can still show it.
			h.location = ""
		}
		if h.location == "" {
			out = append(out, h)
			continue
		}
		base := pxBaseURL(o.Obs)
		h.strict, h.browser = pxResolveBoth(base, h.location)
		want := rdrOwnHost(o.Marker)
		h.strictOff = want != "" && h.strict.Host == want
		h.browserOff = want != "" && h.browser.Host == want
		h.markerAnywhere = o.Marker != "" &&
			strings.Contains(strings.ToLower(h.location), strings.ToLower(string(o.Marker)))
		out = append(out, h)
	}
	return out
}

// rdrOwnHost is the exact authority this probe instance named, lowercased.
//
// IT IS BUILT FROM THE PROBE'S OWN MARKER AND FROM NOTHING ELSE. That is what makes a hit
// attributable to one probe on one slot in one run: the marker is minted per probe with this
// class's R12 ordinal stripe, so a Location naming a DIFFERENT probe's host cannot be scored here,
// and a cached response carrying an earlier run's host resolves to a name this run never sent.
func rdrOwnHost(m triage.Marker) string {
	if m == "" {
		return ""
	}
	return strings.ToLower(string(m) + rdrHostSuffix)
}

func rdrFind(hits []rdrHit, id triage.ProbeID) (rdrHit, bool) {
	for _, h := range hits {
		if h.obs.ProbeID == id {
			return h, true
		}
	}
	return rdrHit{}, false
}

// rdrReachKnown reports whether the inert reach control ran, and whether it showed the slot
// feeding the Location.
func rdrReachKnown(hits []rdrHit) (reach bool, measured bool) {
	h, ok := rdrFind(hits, rdrNC2)
	if !ok {
		return false, false
	}
	return h.markerAnywhere, true
}

// rdrDocumentRedirect looks for this probe's own host in a DOCUMENT-LEVEL redirect construct: a
// Refresh header, a meta refresh, or an assignment to location.
//
// =================================================================================================
// THE BODY HALF OF THIS FUNCTION WAS WRONG AND THE ORACLE RUN CAUGHT IT. READ THIS BEFORE EDITING.
// =================================================================================================
// It used to ask only "is this probe's host in the authority position of a URL somewhere in the
// body", which is the right question for HOSTHDR and the WRONG question here, and the difference
// is what this class sends. HOSTHDR sends a bare hostname, so a body containing https://<host>/
// proves the application BUILT a URL. REDIRECT sends a URL. So an application that merely ECHOES
// the parameter puts the whole thing, slashes and all, into its own body, and the authority test
// fires on the echo.
//
// MEASURED, full-registry run against the canary oracle, 2026-09-19: this class reported
//
//	xss  REDIRECT  query:q  suspicious  document_redirect_reflection
//
// on /xss?q=, which is a pure reflection route that emits no Location, no Refresh and no meta
// refresh at all. That is the precise false positive the class's own header comment spends a
// paragraph refusing, produced by this function, on the first end-to-end run. Rank 7 wearing rank
// 5's coat, exactly as the comment warned, and the comment did not stop it.
//
// So the body half now needs the authority to sit inside a redirect CONSTRUCT, established by the
// bytes immediately in front of it, and a bare echo no longer qualifies. The window is small on
// purpose: a page that says the word "location" three paragraphs above an echoed URL is not a
// redirect, and the failure mode of a small window is a missed weak hit rather than an invented
// one.
const rdrConstructWindow = 160

func rdrDocumentRedirect(h rdrHit) (string, bool) {
	host := rdrOwnHost(h.obs.Marker)
	if host == "" {
		return "", false
	}
	// The response-header half needs no construct test: a Refresh header IS the construct, and a
	// Link or Content-Location naming our authority is the application emitting a URL rather than
	// echoing a body.
	for _, name := range []string{"Refresh", "Link", "Content-Location"} {
		for _, v := range pxRespHeader(h.obs.Obs, name) {
			if _, ok := pxHostInAuthorityPosition([]byte(v), host); ok {
				return "the " + name + " response header", true
			}
		}
	}
	body := h.obs.Obs.Body
	for _, at := range pxHostAuthorityOffsets(body, host) {
		from := at - rdrConstructWindow
		if from < 0 {
			from = 0
		}
		to := at + rdrConstructWindow/2
		if to > len(body) {
			to = len(body)
		}
		if what, ok := rdrRedirectConstruct(body[from:at], body[from:to]); ok {
			return what, true
		}
	}
	return "", false
}

// rdrRedirectConstruct reports whether the bytes immediately preceding a URL make that URL a
// redirect rather than a link, an image source or an echoed parameter.
//
// THREE CONSTRUCTS AND NOTHING ELSE, each of which navigates the browser on its own:
//
//	a meta refresh          http-equiv=refresh ... content="0;url=<URL>"
//	a location assignment   location = <URL>, location.href = <URL>, location.replace(<URL>)
//	a Refresh directive     written into the document rather than the header
//
// An href, an img src, a script src and a bare echo are all deliberately absent. Each of those is
// a real thing worth knowing about and NONE of them redirects anybody, and a class that scored
// them would fire on every page that echoes a URL-shaped parameter, which is every page this
// class sends a payload to.
// TWO WINDOWS, AND THE ASYMMETRY IS THE POINT. A location ASSIGNMENT always precedes its value,
// so the location rules read only the bytes BEFORE the URL: reading after would fire on
// <a href="http://h/">location</a>. A meta refresh's two tokens can appear in either order,
// because content= and http-equiv= are attributes, so the meta rules read a window SPANNING the
// URL. Both tokens are still required: a lone url= in a query string is the commonest URL-shaped
// thing on the web and must never qualify.
func rdrRedirectConstruct(before, spanning []byte) (string, bool) {
	b := strings.ToLower(string(before))
	sp := strings.ToLower(string(spanning))
	switch {
	case strings.Contains(sp, "http-equiv") && strings.Contains(sp, "refresh"):
		return "a meta refresh in the response body", true
	case strings.Contains(sp, "refresh") && strings.Contains(b, "url="):
		return "a refresh directive in the response body", true
	case strings.Contains(b, "location.replace") || strings.Contains(b, "location.assign") ||
		strings.Contains(b, "location.href") || strings.Contains(b, "window.location") ||
		strings.Contains(b, "location ="):
		return "an assignment to location in a script in the response body", true
	}
	return "", false
}

// rdrWireForm records what the encoder actually did to the slashes, because the class's own
// reachability note promises it on every verdict.
func rdrWireForm(s triage.Slot) string {
	switch s.Kind {
	case triage.KindQuery, triage.KindPath, triage.KindBody:
		return "percent_encoded: the slashes in every payload arrive as %2F, so the RAW form of these " +
			"payloads is untested and a filter reading the undecoded request is untested with it"
	default:
		return "raw: every byte in this class is legal unencoded in this container"
	}
}

// rdrLabel is what this class hands the expensive tooling.
//
// The two pointers are deliberately different for the two outcomes, because pointing recollapse at
// a slot that does not reach the Location is the same waste as pointing sqlmap at a static page.
func rdrLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"host_suffix": rdrHostSuffix,
		"note": "a triage hit here is close to the proof of concept already: compose the URL, open it, " +
			"watch the address bar leave the origin",
	}
	if w, ok := ann["winning_probe"].(string); ok {
		hints["winning_probe"] = w
	}
	if r, ok := ann["resolutions"].(string); ok {
		hints["resolutions"] = r
	}
	tools := []string{"nuclei"}
	hints["nuclei"] = "the DAST redirect template set is the second detector, and it is worth running " +
		"only on a slot this class showed reaching the Location"
	if reach, ok := ann["slot_reaches_location"].(bool); ok && reach {
		tools = append(tools, "recollapse")
		hints["recollapse"] = "this slot feeds the Location and a filter refused every off-origin form " +
			"this class ships. recollapse is the framework's own encoding-mutation scanner and this is " +
			"exactly the shape it exists for: a known-reachable sink behind a filter of unknown grammar"
	}
	return triage.TriageLabel{Tools: tools, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (redirectClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "both_models_agree", Probes: []triage.ProbeID{rdrA1, rdrA2, rdrA7},
			Rule: "a FINDING requires the RFC 3986 resolution and the WHATWG browser reading to name the " +
				"same off-origin authority. Where they disagree the verdict is suspicious, because the " +
				"browser half is modelled here and not measured",
		},
		{
			Name: "authority_not_path", Probes: rdrAllProbeIDs(),
			Rule: "the marker must be in the AUTHORITY of the resolved URL. Location: /login?next=%2F%2F<host> " +
				"carries the marker and redirects nobody off-origin, and it is the single most common false " +
				"positive in this class",
		},
		{
			Name: "origin_absolute_control_stays_home", Probes: []triage.ProbeID{rdrNC1},
			Rule: "RDR-NC1's resolved authority must be the request's own host. It cannot be otherwise from " +
				"a value beginning with one slash, so a hit there means the detector or the transport is " +
				"wrong and every verdict on the slot becomes detector_unverified",
		},
		{
			Name: "reach_before_defence", Probes: []triage.ProbeID{rdrNC2},
			Rule: "not_exploitable may only be claimed when the inert reach control's marker actually came " +
				"back in the Location. Without that, 'the filter held' and 'the slot was never connected' " +
				"are the same observation and the honest answer is the weaker one",
		},
		{
			Name: "fresh_marker", Probes: []triage.ProbeID{rdrA1},
			Rule: "re-send the winning payload with a FRESH marker, which is a fresh authority. A cached 302 " +
				"and a coincidence both fail that and a live redirect passes it",
		},
	}
}

func (redirectClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "location_raw", Kind: "protocol", What: "the Location header exactly as the server wrote it, unparsed and unnormalised, which is the artefact the whole filter-bypass family turns on"},
		{Name: "both_resolutions", Kind: "annotation", What: "what RFC 3986 and the browser model each made of that Location, so a parser-dependent suspicion can be judged rather than trusted"},
		{Name: "winning_form", Kind: "annotation", What: "which payload shape got through (absolute, scheme-relative, slash-run, backslash, scheme-without-slashes, bare host), which is what tells recollapse where to start"},
		{Name: "scheme_supplied_by_sink", Kind: "annotation", What: "RDR-A7 succeeding means the application builds the absolute URL itself, so every scheme and slash filter on the value is irrelevant. It changes the fix, not just the finding"},
		{Name: "reach_without_payload", Kind: "differential", What: "whether the inert control reached the Location, which is the difference between a clean, a filtered sink and an unknown"},
		{Name: "route_control_status", Kind: "differential", What: "whether the unperturbed route redirected at all, which is what makes redirect_suppressed_by_payload distinguishable from a quiet endpoint"},
	}
}

// OracleCases. /redirect already exists in the oracle container and is the naive unvalidated
// redirector, so the positive case is live today. The rest are what the container owes this class
// before its NEGATIVES can be called verified, and the negatives are the ones doing the work.
func (redirectClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "unvalidated_redirect", Route: "/redirect", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{rdrA1, rdrNC2}, WantState: triage.StateFinding,
			Why: "the shipped route copies ?next= straight into a Location and returns 302. RDR-A1 must " +
				"produce a finding with both models agreeing, and RDR-NC2's inert value must come back in " +
				"the Location, which is what proves the reach control works on a sink that is known to be " +
				"connected",
		},
		{
			Name: "next_parameter_is_not_a_redirect", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: rdrRound0(), WantState: triage.StateClean,
			Why: "a route that reflects the parameter into the BODY and emits no Location at all. Every " +
				"payload's marker is in the response and the correct verdict is clean. A detector built on " +
				"'the marker came back' fails here, which is the cheapest possible check that this class is " +
				"reading the envelope and not the body",
		},
		{
			Name: "origin_absolute_is_honoured", Route: "/redirect/local", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{rdrNC1, rdrA1}, WantState: triage.StateNotExploitable,
			Why: "a redirector that accepts a value beginning with a single slash and REFUSES anything with " +
				"a scheme or an authority, falling back to '/'. RDR-NC1 and RDR-NC2 both land in the " +
				"Location, every off-origin form does not, and the verdict must be not_exploitable with the " +
				"defence named. THIS IS THE ROUTE THAT SEPARATES A FILTER FROM AN UNCONNECTED SLOT, and " +
				"without it those two produce the same pixel",
		},
		{
			Name: "fixed_destination", Route: "/redirect/fixed", Expect: faExpectNegative, Exists: true,
			Probes: rdrRound0(), WantState: triage.StateClean,
			Why: "a route that always returns 302 to a hardcoded path and ignores every parameter. The " +
				"endpoint redirects, the baseline redirects, nothing we send appears in the Location, and " +
				"the verdict must be clean with reason slot_does_not_reach_location. A detector built on " +
				"'the response is a 302' fires on every request here",
		},
		{
			Name: "reflection_into_the_next_parameter", Route: "/redirect/loginwrap", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{rdrA1}, WantState: triage.StateNotExploitable,
			Why: "a route that 302s to /login?next=<our value urlencoded>. The marker IS in the Location, " +
				"the authority is the origin, and the browser stays home. THE SINGLE MOST IMPORTANT NEGATIVE " +
				"IN THIS CLASS: every naive open-redirect scanner reports this and the operator stops reading " +
				"the class after the third one. MEASURED, and the state this case declared was corrected by " +
				"the measurement: the answer is not_exploitable (redirect_target_filtered) and not clean, " +
				"because the inert reach control's marker comes back in the Location too, so this slot " +
				"demonstrably steers the redirect and something neutralised every off-origin form of it. " +
				"That is the more useful of the two negatives and it is the one that carries the recollapse " +
				"pointer. What the case is really asserting is unchanged and is what matters: NOT A FINDING",
		},
		{
			Name: "browser_only_slash_run", Route: "/redirect/strictvalidator", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{rdrA3, rdrA5, rdrA6}, WantState: triage.StateSuspicious,
			Why: "a route whose validator resolves the value the RFC 3986 way, decides it is on-origin, and " +
				"emits it verbatim. RDR-A3, A5 and A6 must reach SUSPICIOUS and must NOT reach a finding: " +
				"the effect is real and the confirmation needs a browser, and a class that graded it high " +
				"would be asserting a browser behaviour nothing here measured",
		},
		{
			Name: "site_wide_https_redirect", Route: "/redirect/alwaysoffsite", Expect: faExpectNegative, Exists: true,
			Probes: rdrRound0(), WantState: triage.StateClean,
			Why: "a route whose BASELINE already 302s to another host, as a site-wide HTTP-to-HTTPS or a " +
				"tenant redirect does. The class must be clean and must record " +
				"route_control_already_redirects_off_origin, because 'the Location points somewhere else' is " +
				"this endpoint's normal behaviour and scoring it would flag every such site",
		},
		{
			Name: "refresh_header_only", Route: "/redirect/meta", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{rdrA1}, WantState: triage.StateSuspicious,
			Why: "a 200 whose body carries <meta http-equiv=\"refresh\" content=\"0;url=http://<our host>/\">. " +
				"It must reach suspicious at grade low with oracle body_redirect_reflection and must never " +
				"reach a finding, because a document a client may interpret is a weaker oracle than a header " +
				"the protocol acts on",
		},
	}
}
