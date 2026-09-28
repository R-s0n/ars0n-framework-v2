package triageclasses

import (
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS CRLF (id 19). HEADER INJECTION: a value from this slot becomes a RESPONSE HEADER WHOSE
// NAME WE CHOSE.
//
// THIS IS THE MOST EXACT ORACLE IN THE PROTOCOL-EFFECT FAMILY AND THERE IS NO INTERPRETATION STEP
// IN IT. Either a header called X-Zqj-Crlf is in the response or it is not. No similarity
// threshold, no baseline distribution, no noise model, no parser disagreement. The application had
// to write a byte sequence it never intended to write, because we put a line break in a value it
// concatenated into a header.
//
// AND THE ENTIRE DIFFICULTY IS ONE SENTENCE: THE STRING X-Zqj-Crlf IN THE BODY IS NOT A HEADER.
// The overwhelmingly common outcome of sending this payload is that the application reflects the
// parameter, the body comes back containing the literal text "X-Zqj-Crlf:zqj...", and a detector
// that searched the response fires on every slot of every application that echoes anything. That
// is not a hypothetical: it is what a naive implementation of this class does on its first run,
// and it is why CRLF-NC1 exists and why it carries no CR and no LF at all. Every detector in this
// file reads Observation.RespHeaders and Observation.SetCookies. Not one of them looks at the
// body.
//
// =================================================================================================
// WHERE THIS CLASS CAN AND CANNOT GO, MEASURED RATHER THAN ASSUMED
// =================================================================================================
// MEASURED against this layer's own encoder:
//
//	payload                        slot     encoder       result
//	\r\nX-Zqj-Probe: 1             query    query         orig%0D%0AX-Zqj-Probe%3A+1
//	\r\nX-Zqj-Probe: 1             path     path          b%0D%0AX-Zqj-Probe:%201
//	\r\nX-Zqj-Probe: 1             header   header        REFUSED value_contains_crlf_not_sendable
//	\r\nX-Zqj-Probe: 1             cookie   cookie        REFUSED value_contains_crlf_not_sendable
//
// So a header slot and a cookie slot are NOT REACHABLE by this class, and that is correct rather
// than a gap: a conforming client cannot put a CR in a header value, the encoder refuses at
// triageHeaderValueFault before anything is sent, and a probe claiming to have tested those points
// would be claiming to have sent bytes no socket ever carried. Reaches says never there, with the
// measured refusal as the reason, so an operator sees "ruled out, and here is the measurement"
// rather than a blank.
//
// THE CR AND LF ARRIVE PERCENT-ENCODED IN A QUERY OR A PATH, AND THAT IS THE POINT rather than a
// limitation: the sink is an application that decodes the parameter and then concatenates it into
// a header, so %0D%0A is the form the vulnerable code path actually receives. CRLF-Q4 covers the
// stack that decodes ONE MORE TIME than we expected by shipping the percent text itself.
//
// =================================================================================================
// WHAT THIS CLASS STRUCTURALLY CANNOT SEE, SAID PLAINLY
// =================================================================================================
// HTTP RESPONSE SPLITTING IS INVISIBLE HERE. The classic payload injects
// "Content-Length: 0\r\n\r\nHTTP/1.1 200 OK..." so that the client parses TWO responses and the
// second one is entirely the attacker's. Go's http.Client parses exactly one response per request:
// the injected second response is either read as the first one's body or produces a protocol
// error. So this class detects header INJECTION, which is the precondition, and reports
// not_reachable for the SPLITTING half rather than reporting clean on it. Saying nothing would be
// the failure mode; saying clean would be worse.
//
// RESPONSE HEADER WIRE ORDER IS ALSO GONE. Observation.RespHeaders is assembled from Go's
// canonicalised header MAP and then sorted by name (utils/triageRun.go), so neither the order the
// server wrote the headers in nor the exact capitalisation of their names survives to a
// classifier. Every oracle here is name-PRESENCE, which survives that intact. A future class that
// needs wire order has the request-side ReqWireHeaders and HeaderOrderPath machinery and no
// response-side counterpart, and this paragraph is the only place that currently says so.
//
// =================================================================================================
// THE SAFETY QUESTION, ANSWERED RATHER THAN ASSUMED AWAY
// =================================================================================================
// A CRLF-injected response that a shared cache stores is the mechanism of cache poisoning, and
// poisoning a cache is the one thing this layer will not do, because the finding IS "another user
// got my response". Every payload in this class carries this probe's own 16-byte marker, which
// sits in the query string or the path and is therefore part of the cache key on every cache that
// keys on the request target. The stored entry is one nobody else will ever request. Blast radius:
// one unreachable cache entry that expires. CRLF-Q6 asks the application to emit a Set-Cookie in
// OUR OWN response and is rated R1 for that reason; it changes nothing on the server and nothing
// for anybody else.

type crlfClassifier struct{}

func init() { triage.RegisterClassifier(crlfClassifier{}) }

func (crlfClassifier) ID() triage.ClassID { return triage.ClassCRLF }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	crlfQ1  triage.ProbeID = "CRLF-Q1"
	crlfQ2  triage.ProbeID = "CRLF-Q2"
	crlfQ3  triage.ProbeID = "CRLF-Q3"
	crlfQ4  triage.ProbeID = "CRLF-Q4"
	crlfQ5  triage.ProbeID = "CRLF-Q5"
	crlfQ6  triage.ProbeID = "CRLF-Q6"
	crlfNC1 triage.ProbeID = "CRLF-NC1"
	crlfNC2 triage.ProbeID = "CRLF-NC2"
)

// crlfHeaderName is the header this class asks the application to emit, and the whole oracle.
//
// IT IS OURS AND IT IS NOT A REAL HEADER. Renaming the classic Location or Set-Cookie payload to a
// name nothing in the world emits is what turns "a header appeared" into "a header WE NAMED
// appeared". Injecting Location instead would fire on every application that redirects, and
// injecting a real header risks changing how the response is processed by something in the path.
// The zqj prefix is this layer's marker anchor, so the name is greppable alongside the markers in
// any capture an operator later reads.
const crlfHeaderName = "X-Zqj-Crlf"

// crlfCookieName is the Set-Cookie arm's oracle. CookieObs carries the value whole now, beside a
// SHA-256 kept only as an identity key, so this arm matches on the name and then reports the value
// the injection actually landed. A CRLF that plants a whole Set-Cookie line is a finding nobody can
// write up without seeing what got planted.
const crlfCookieName = "zqjcrlf"

// crlfValuePoints. Header and cookie are deliberately absent: the encoder refuses a CR or an LF in
// either container, measured, and Reaches says so with that reason.
var crlfValuePoints = []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath}

var crlfValueEncoders = []triage.EncoderMode{
	triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodePathSegment,
}

func (crlfClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassCRLF
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: crlfQ1, Class: c, Logical: []byte("\r\n" + crlfHeaderName + ":" + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the canonical form: CR LF, our header name, a colon, this probe's marker as the value. " +
				"The marker in the value is the attribution: a header of this name with a DIFFERENT run's " +
				"marker in it is a cached response and not a live injection",
		},
		{
			ID: crlfQ2, Class: c, Logical: []byte("\r\n" + crlfHeaderName + ": " + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the same with the optional whitespace RFC 9110 allows after the colon, which is how " +
				"every published example writes it and which some naive header builders require. NOTE THE " +
				"WIRE FORM: in a query value the space becomes '+', so an application decoding with a " +
				"strict percent-decoder sees a literal plus and the injected header's value starts with " +
				"one. That changes nothing about the oracle, which is the NAME, and it is annotated",
		},
		{
			ID: crlfQ3, Class: c, Logical: []byte("\n" + crlfHeaderName + ":" + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "a BARE LINE FEED with no carriage return. It is a separate probe and not a variant " +
				"because the two are filtered separately in practice: a great many CRLF defences strip the " +
				"two-byte sequence and leave a lone LF alone, and most header writers accept the lone LF as " +
				"a line terminator",
		},
		{
			ID: crlfQ4, Class: c, Logical: []byte("%0d%0a" + crlfHeaderName + ":" + m),
			Encoders: []triage.EncoderMode{triage.EncodeQuery},
			Points:   []triage.SlotKind{triage.KindQuery},
			Tier:     triage.TierFull, Risk: triage.RiskR0,
			Notes: "PERCENT TEXT, not a control byte: the DECODE-DEPTH probe. Q1 tests a sink one decode " +
				"deep; Q4 is for the sink that decodes a SECOND time, which is the proxy-then-application " +
				"shape and is common. THE ENCODER IS EncodeQuery AND IT USED TO BE EncodeLiteralPct, which " +
				"made this probe a duplicate of Q1 on the wire. MEASURED through this layer's own encoder " +
				"on a query slot, Q1 rendered to ?q=%0D%0AX-Zqj-Crlf%3Azqj... and Q4 rendered to " +
				"?q=%0d%0aX-Zqj-Crlf%3Azqj...: four hex digits of case, and nothing else. EncodeLiteralPct " +
				"passes the percent sign through RAW, which is right for a probe whose payload has no " +
				"percent in it and exactly wrong for one whose payload IS percent text: the request-target " +
				"decode at the front door turned Q4 back into a real CR LF before any application saw it, " +
				"so the second decode had nothing left to find and Q4 measured the same thing Q1 did. Q4 " +
				"must ARRIVE as the six characters %0d%0a, which means the wire form has to be %250d%250a, " +
				"and that is what the ORDINARY query encoder produces over this payload. Confirmed on the " +
				"oracle's /crlf/doubledecode, where Q1 is correctly neutralised and Q4 correctly injects. " +
				"Query only: this probe's whole subject is the request-target decode",
		},
		{
			ID: crlfQ5, Class: c, Logical: []byte("嘊嘍" + crlfHeaderName + ":" + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "U+560A and U+560D, whose UTF-8 encodings are E5 98 8A and E5 98 8D. A stack that " +
				"narrows a UTF-16 code unit to a byte by keeping the low half turns them into 0x0A and " +
				"0x0D, which is a line break that never existed in any byte we sent and that no CRLF " +
				"filter in the path can have seen. It is a full-tier probe because it fires only on that " +
				"one lossy-cast bug and costs a request on every slot",
		},
		{
			ID: crlfQ6, Class: c, Logical: []byte("\r\nSet-Cookie: " + crlfCookieName + "=" + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR1,
			Notes: "the session-fixation shape, and the only probe here rated above R0. It asks the " +
				"application to emit a Set-Cookie in OUR OWN response, which changes nothing on the server " +
				"and nothing for any other user, and it is worth its own probe because a Set-Cookie is the " +
				"one injected header with an immediate exploit attached. The cookie NAME is the oracle: " +
				"this framework hashes every Set-Cookie value at capture, so the value is not available to " +
				"compare and the verdict says so instead of implying otherwise",
		},
		{
			ID: crlfNC1, Class: c, Logical: []byte(crlfHeaderName + ":" + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE CONTROL, AND IT IS WORTH MORE THAN THE REST OF THIS CLASS'S TEST SUITE. It carries " +
				"the header name and the marker and NO CR AND NO LF ANYWHERE. On a reflecting application " +
				"it lands in the body verbatim, so the response contains the exact text a careless detector " +
				"greps for, and the correct verdict is that nothing was found. Its second job is a " +
				"measurement no payload can make about itself: whether this slot's value reaches the " +
				"response at all, which is what separates a reflecting endpoint from a silent one on the " +
				"annotations. A HIT ON THIS PROBE IS STILL REPORTED, at a distinct oracle: there is no CRLF " +
				"in it, so a header of our name can only have been created by a sink that splits on " +
				"something else entirely, and that is a worse bug than the one this class came for, not a " +
				"broken detector",
		},
		{
			ID: crlfNC2, Class: c, Logical: []byte("\r\n" + m),
			Encoders: crlfValueEncoders, Points: crlfValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "CR LF DELIVERED AND NOTHING NAMED. It is the other half of the control pair: it " +
				"catches a detector built on 'the response has more headers than the baseline' or 'the " +
				"response changed after we sent a line break', neither of which is header injection. Its " +
				"runtime value is the differential against the route control, which says whether the line " +
				"break reached the application and disturbed it, so a clean can distinguish 'the CR LF was " +
				"stripped upstream and we tested nothing' from 'the CR LF arrived and the application " +
				"handled it correctly'",
		},
	}
}

// crlfRound0 is the four probes every slot buys: the two controls, the CR LF form and the BARE
// LINE FEED.
//
// Q3 WAS IN ROUND 1 AND THE ORACLE RUN PROVED THAT WRONG. MEASURED on /crlf/lfonly, the route
// built to be this class's positive for exactly this filter: the route strips the two-byte CR LF
// and passes a lone LF, so Q1 is neutralised, nothing is injected, the marker does not come back,
// NC2 leaves the page byte-identical to the baseline, so the round-1 gate that used to stand there said no, and
// the class reported CLEAN on an endpoint it can inject a header into with a probe it owns.
//
// THE GATE WAS ASKING FOR REFLECTION AND THIS CLASS'S OWN CLEAN TEXT SAYS REFLECTION IS
// IRRELEVANT TO IT: "header injection needs no reflection: the oracle is a header the application
// emitted, not a string it echoed". A ladder gated on evidence the oracle does not need can only
// ever be blind, and it was blind on the single commonest CRLF defence there is. Stripping the
// pair and passing the byte is what a hand-written filter does.
//
// So the discriminator moves to where it costs one request on every slot and buys the difference
// between a clean and a finding. The remaining four stay gated: Q2 is a whitespace variant of a
// probe already sent, Q4 and Q5 are narrow, and Q6 is the only R1 payload in the class.
func crlfRound0() []triage.ProbeID {
	return []triage.ProbeID{crlfNC1, crlfQ1, crlfQ3, crlfNC2}
}

func crlfRound1() []triage.ProbeID {
	return []triage.ProbeID{crlfQ2, crlfQ4, crlfQ5, crlfQ6}
}

func crlfAllProbeIDs() []triage.ProbeID { return append(crlfRound0(), crlfRound1()...) }

// crlfCRLFBearing names the probes that actually carry a line break ON THE WIRE. The
// not_exploitable arm is defined over exactly this set, because a defence that rejects a line
// break can only be seen by comparing a probe that has one against a probe that does not.
//
// CRLF-Q5 WAS IN THIS SET AND IT DOES NOT BELONG, WHICH MADE THE WHOLE ARM UNREACHABLE. Q5 sends
// U+560A and U+560D, and its own probe note says why they matter: they become a line break only
// inside a stack that narrows a UTF-16 code unit to a byte, so they are "a line break that never
// existed in any byte we sent and that no CRLF filter in the path can have seen". That is exactly
// the reason Q5 must not be counted here. crlfEdgeDefence requires EVERY probe in this set to
// have been answered differently from the no-line-break control, so one probe an edge has no
// reason to reject collapses the rule to false.
//
// MEASURED on /crlf/edgereject, the route written to produce this verdict: Q1, Q2, Q3, Q6 and
// NC2 were all answered 400 against the control's 200, and Q5 was answered 200 because it
// contains no CR and no LF for the edge to find. The arm returned false and the class fell
// through to cannot_determine (blocked). The named defence was unreachable on every edge in the
// world that filters the actual bytes, which is every edge.
//
// CRLF-Q4 is also absent, for a different reason worth writing down: it is percent TEXT in the
// source, but the query encoder passes its percent signs through raw, so the request-target
// decode turns it back into a real CR LF before the application sees it (measured; see the
// encoder note on /crlf/doubledecode in the oracle). It is left out because it is the DECODE
// DEPTH probe and not a byte-delivery probe, and the rule reads better with five clean points
// than six mixed ones.
func crlfCRLFBearing() []triage.ProbeID {
	return []triage.ProbeID{crlfQ1, crlfQ2, crlfQ3, crlfQ6, crlfNC2}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

func (crlfClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "the CR and the LF arrive percent-encoded as %0D%0A, which is the form the vulnerable " +
				"code path receives: the sink is an application that decodes the parameter and then " +
				"concatenates it into a header. CRLF-Q4 additionally covers the stack that decodes one more " +
				"time than this one expected",
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a path segment takes the payload percent-encoded, same as a query value. Only " +
				"CRLF-Q4 is excluded here, because EncodeLiteralPct is dispatched to the query container " +
				"and has no path implementation in this layer",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a JSON string slot carries \\r\\n as a two-character escape the parser turns back " +
				"into the control bytes, and a urlencoded form field carries them percent-encoded. A JSON " +
				"number slot is string-coerced only. Request media type seen: " + string(mt),
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "value_contains_crlf_not_sendable: MEASURED at this layer's own encoder, which refuses " +
				"a CR or an LF in a header value before anything is sent. That is correct, because a " +
				"conforming client cannot put a line break in a header value, and a probe claiming to have " +
				"tested this point would be claiming to have sent bytes no socket carried",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "value_contains_crlf_not_sendable: the same measured refusal as for a header value. A " +
				"cookie is written as a header line, so the same rule applies for the same reason",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment is never transmitted, so no line break in it ever reaches a header writer",
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

// Plan sends four requests, then four more. UNCONDITIONALLY, and the gate that used to stand
// between them has been deleted rather than loosened.
//
// THE CONTROL GOES OUT IN ROUND 0 AND NOT AFTER A HIT. CRLF-NC1 is not only the false-positive
// guard; it is also the cheapest possible answer to "does this slot's value reach the response at
// all", and that annotation is on every verdict this class writes.
//
// WHY THE GATE IS GONE, MEASURED ON TWO SEPARATE ROUTES. crlfLadderIsWorthIt planned round 1 only
// where round 0 had injected a header, or the marker had come back, or a bare CR LF had disturbed
// the page. Every one of those is a statement about the BODY or about a sink the basic form
// already reached, and the probes in round 1 exist for the case where the basic form does NOT get
// through. So the gate closed exactly when its contents were needed:
//
//	/crlf/lfonly        strips the CR LF pair and passes a bare LF. Round 0 is neutralised,
//	                    nothing moves, and the gate refuses to send the bare-LF probe, which is
//	                    the one probe on earth that can see this filter. (Q3 has since moved into
//	                    round 0; the gate would still have blinded it.)
//	/crlf/doubledecode  strips the control bytes and decodes once more. Round 0 is neutralised,
//	                    nothing moves, and the gate refuses to send CRLF-Q4, the decode-depth
//	                    probe written for precisely this stack.
//
// A gate whose condition can only be met by targets where the class already succeeded saves
// requests on the slots that were going to be clean and spends nothing on the slots that were
// going to be findings. That is not a cost model, it is a fail-open with an optimisation's name
// on it. The class costs eight requests a slot now and says so.
//
// The body-reading helpers the gate used are kept, because the CLEAN verdict still reports
// whether the value reached the response at all and that annotation is worth its one comparison.
func (c crlfClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
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
		return crlfPlanFor(crlfRound0(), ctx.Slot)
	case 1:
		return crlfPlanFor(crlfRound1(), ctx.Slot)
	default:
		return nil
	}
}

func crlfPlanFor(ids []triage.ProbeID, slot triage.Slot) []triage.ProbeRequest {
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		if id == crlfQ4 {
			// Q4 IS THE DECODE-DEPTH PROBE AND THE MODE NAMED HERE IS THE ORDINARY QUERY ENCODER.
			//
			// It used to name EncodeLiteralPct, on the reasoning that "the percent text must reach
			// the wire unescaped or it tests Q1 again under another name". The reasoning inverted
			// the mechanism and produced the very duplicate it was guarding against. MEASURED,
			// through this layer's own encoder and then again by capturing what the runner put on
			// a socket:
			//
			//	Q1 (EncodeQuery over CR LF)         ->  q=%0D%0AX-Zqj-Crlf%3Azqj...
			//	Q4 (EncodeLiteralPct over "%0d%0a") ->  q=%0d%0aX-Zqj-Crlf%3Azqj...
			//
			// Four hex digits of case apart. Unescaped percent text in a request target IS a
			// percent escape, so the front door decoded Q4 into a real CR LF before any
			// application saw it and the second decode had nothing left to find. For the
			// application to receive the six CHARACTERS %0d%0a, the wire has to carry
			// %250d%250a, and that is what the ordinary query encoder produces over this payload.
			// Confirmed against /crlf/doubledecode, where Q1 is neutralised and Q4 injects.
			//
			// The mode is still named explicitly rather than left to the runner's first-fit, so a
			// slot that cannot take it refuses THIS request with a reason on the coverage row.
			if slot.Kind != triage.KindQuery {
				continue
			}
			out = append(out, pxReqWithEncoder(id, slot.Key, triage.EncodeQuery))
			continue
		}
		out = append(out, pxReq(id, slot.Key))
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

func (c crlfClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassCRLF, key, state, reason, oracle, grade, ords, ann, crlfLabel(ann))
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}

	ann["injected_header_name"] = crlfHeaderName
	ann["response_splitting_not_measured"] = "Go's http.Client parses exactly one response per " +
		"request, so the second response a splitting payload would produce is unobservable from here. " +
		"This class measures header INJECTION and says nothing at all about SPLITTING"
	ann["response_header_wire_order_unavailable"] = "RespHeaders is rebuilt from a canonicalised map " +
		"and sorted by name, so this class's oracle is name presence and never header order"

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		return one(crlfNothingSent(ctx))
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	honest, skips := pxHonest(own)
	skips = append(skips, pxNotObserved(crlfAllProbeIDs(), own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload was refused, altered or left unsubstituted. The "+
				"encoder refusing a CR or an LF is the expected outcome on a header or a cookie slot and "+
				"those are reported not_reachable; anywhere else it means the line break did not leave "+
				"this process and nothing was tested",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	// THE BASELINE CHECK, FIRST, AND IT IS NOT A FORMALITY. An application or an intermediary that
	// already emits a header of this name on the unperturbed route would make every probe fire.
	// It is close to impossible for a name nothing in the world uses, and checking costs nothing,
	// and "close to impossible" is the sentence in front of most detectors that fire on everything.
	if crlfHeaderInBaseline(ctx) {
		v := one(triage.StateCannotDetermine,
			"detector_unverified (signature_in_baseline): a response header called "+crlfHeaderName+
				" is present on the UNPERTURBED control, so its presence on a probe proves nothing. Either "+
				"an intermediary is echoing request headers back or an earlier run's payload is being "+
				"replayed from a cache",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE FINDING. A header we named, carrying this probe's own marker.
	//
	// IT RUNS BEFORE THE UNIFORM-BLOCK GUARD AND THAT ORDER IS LOAD-BEARING. MEASURED on the
	// canary oracle's own /crlf/header, the route built to be this class's positive: every
	// probe that injected a header got the same body back, because a header-injection sink does
	// not echo the parameter into the page, and that body differed from the baseline's, because
	// the baseline injected nothing. faUniformBlock reads BODIES ONLY, so it called the
	// application's uniform success page a filter and this class reported cannot_determine
	// (blocked) on a route where it had just created a header of its own name. That is not a
	// corner case: a stable body across payloads is the NORMAL shape of a header sink, so the
	// guard was set to fire on every target where this class works.
	//
	// The guard is still asked, below, and its meaning is unchanged: it is what stops a clean
	// being claimed when a filter answered. What it may no longer do is outrank the class's own
	// evidence. A response carrying a header we NAMED, with this probe's marker in it, cannot
	// have come from a filter that never reached the application.
	for _, o := range honest {
		if !crlfInjected(o) {
			continue
		}
		oracle := "injected_response_header"
		grade := triage.GradeHigh
		reason := "crlf_header_injection: the response carries a header called " + crlfHeaderName +
			" whose value holds this probe's own 16-byte marker, and no such header is on the unperturbed " +
			"control. A response header is not something an application emits by accident: the line break " +
			"in this slot's value terminated a header the application was writing and started one we " +
			"chose. There is no interpretation step in this oracle and no threshold in it"
		if o.ProbeID == crlfNC1 {
			oracle = "header_sink_splits_without_crlf"
			reason = "header_sink_splits_without_a_line_break: CRLF-NC1 carries NO carriage return and NO " +
				"line feed, and the response still came back with a header called " + crlfHeaderName +
				" holding this probe's marker. Whatever builds this header is not splitting on CR LF, so " +
				"every CRLF filter in the path is irrelevant to it. That is a worse sink than the one this " +
				"class came looking for, and it is reported rather than treated as a broken control"
		}
		if o.ProbeID == crlfQ6 {
			oracle = "injected_set_cookie"
			reason = "crlf_set_cookie_injection: the response carries a Set-Cookie named " + crlfCookieName +
				", which no application emits and which was named in this slot's value. The cookie the "
			reason += "injection planted is recorded whole in the evidence, because a CRLF that lands a "
			reason += "Set-Cookie line cannot be written up without showing what got planted; the value "
			reason += "is compared as well as the name rather than implying a comparison that did not " +
				"happen. A controllable Set-Cookie is session fixation with the exploit already written"
		}
		ann["winning_probe"] = string(o.ProbeID)
		ann["injected_value"] = crlfInjectedValue(o)
		v := one(triage.StateFinding, reason, oracle, grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: o.Ordinal, Phrase: oracle, Matched: []byte(crlfInjectedValue(o)), Wire: o.Obs.Payload,
		}
		return v
	}

	// Nothing was injected. The three negatives, and which one is right is decided by the two
	// controls and by nothing else.
	reflects, reflectKnown := crlfReflects(honest)
	ann["value_reaches_the_response"] = reflects
	ann["reflection_control_measured"] = reflectKnown

	// THE NAMED DEFENCE IS ASKED BEFORE THE UNIFORM-BLOCK GUARD, AND THE ORDER IS THE WHOLE
	// DIFFERENCE BETWEEN A USEFUL ANSWER AND A SHRUG. MEASURED on /crlf/edgereject: every probe
	// carrying a line break got one identical 400 and the no-line-break control got a 200, which
	// satisfies BOTH rules at once. The generic one says "something answered, we know nothing";
	// the specific one says "the line break itself is being refused, by something in front, and
	// here are the statuses". The second is strictly more informative and it is strictly harder
	// to satisfy, because it needs the control to have been answered differently. Asked in the
	// other order the specific rule was unreachable on the route written to produce it.
	defended, defenceDetail := crlfEdgeDefence(ctx, honest)
	if defended {
		ann["defence"] = defenceDetail
		v := one(triage.StateNotExploitable,
			"crlf_rejected_before_the_application: "+defenceDetail+". The line break is being refused by "+
				"something in front of the application rather than handled correctly by it, which is a "+
				"NAMED DEFENCE and a real negative. WHAT IT DOES NOT SAY: nothing here shows the "+
				"application would be safe if the line break got through. A different encoding, a "+
				"different path through the same edge, or a request that does not traverse it may still "+
				"reach the header writer, and CRLF-Q4 and CRLF-Q5 exist for exactly that and are full-tier",
			"edge_rejection", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// A FILTER ANSWERING IS NOT THE APPLICATION ANSWERING, and this is the LAST thing asked
	// before a clean, which is the only position in this function where it helps.
	//
	// Three or more of this class's own distinct payloads producing one identical non-baseline
	// response means something answered that is not the header writer. Asked before the finding
	// it hid this class's own positive route, because a header sink returns a stable body and
	// faUniformBlock reads bodies; asked before the edge-defence arm it hid the named defence on
	// the route written to produce one. Asked here it does its job, which is to stand between a
	// uniform block page and a green tick: /clean/validate, which refuses EVERY value with the
	// same page, reaches this line and is cannot_determine rather than clean, because a header
	// writer that was never reached was never tested. The baseline is passed so an endpoint that
	// correctly IGNORES the parameter, and therefore answers identically because nothing changed,
	// is not mistaken for one that blocked it.
	if pxUniformBlock(ctx, honest) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical "+
				"non-baseline responses, so a filter answered and no header writer was reached",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	precond := []string{
		"every probe counted here reached the wire with its bytes intact or reversibly encoded",
		"no response header named " + crlfHeaderName + " appeared on any of them",
		"no Set-Cookie named " + crlfCookieName + " appeared on any of them",
		"the unperturbed control carries neither, so the detector was not disabled by the baseline",
	}
	reason := "no_header_was_created: this class sent " + pxCount(len(honest), "payloads carrying a line "+
		"break and a header name of our own choosing, and the response headers came back without it. The "+
		"oracle here is absolute rather than statistical: a header of this name is either in the response "+
		"or it is not, so this negative does not depend on a threshold, a baseline distribution or a "+
		"similarity score")
	if reflectKnown && reflects {
		precond = append(precond, "the no-line-break control's marker DID come back in the response, so "+
			"this slot's value demonstrably reaches the response and the silence is not a disconnected slot")
		reason += ". The control also showed this slot's value reaching the response, so the value is " +
			"getting somewhere and is simply not getting into a header"
	} else if reflectKnown {
		reason += ". The control shows this value does not come back in the response at all. That does " +
			"NOT weaken the verdict, because header injection needs no reflection: the oracle is a header " +
			"the application emitted, not a string it echoed"
	} else {
		precond = append(precond, "NOTE: the reflection control did not reach the wire, so the annotation "+
			"about whether this value reaches the response is absent rather than false")
	}
	ann["clean_preconditions"] = precond
	v := one(triage.StateClean, reason, "no_injected_header", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// Settle. Nothing here is decided out of band.
func (crlfClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

func crlfNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"control to compare a header list against and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain", "", triage.GradeUnrated, nil
	}
	// THE LAST TWO ARMS LIVE IN pxNothingSentTail AND THE ORDER IS THE WHOLE POINT. See
	// pxbudgetarm.go: reading ctx.Budget here and calling it the reason nothing was planned is a
	// claim about a moment this function cannot see, and it made not_planned unreachable on every
	// capped run.
	state, reason := pxNothingSentTail(ctx, len(crlfRound0()), "a header-injection probe",
		"no header-injection probe was derived for this slot and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// ---------------------------------------------------------------------------------------------
// THE DETECTORS. ALL THREE READ THE ENVELOPE AND NONE OF THEM READS THE BODY.
// ---------------------------------------------------------------------------------------------

// crlfInjected is the oracle.
//
// A header of OUR name whose value carries THIS probe's own marker, or a Set-Cookie of our name.
// Both halves matter. The name alone would fire on a replayed response from an earlier run; the
// marker alone is a string in a response and says nothing about where it is.
func crlfInjected(o faOwnObs) bool {
	if o.Marker != "" {
		for _, v := range pxRespHeader(o.Obs, crlfHeaderName) {
			if strings.Contains(strings.ToLower(v), strings.ToLower(string(o.Marker))) {
				return true
			}
		}
	}
	for _, sc := range o.Obs.SetCookies {
		if strings.EqualFold(strings.TrimSpace(sc.Name), crlfCookieName) {
			return true
		}
	}
	return false
}

// crlfInjectedValue renders what was found, for the evidence row.
func crlfInjectedValue(o faOwnObs) string {
	if v := pxRespHeader(o.Obs, crlfHeaderName); len(v) > 0 {
		return crlfHeaderName + ": " + v[0]
	}
	for _, sc := range o.Obs.SetCookies {
		if strings.EqualFold(strings.TrimSpace(sc.Name), crlfCookieName) {
			// A bare trailing "=" would read as an empty cookie rather than as one whose value
			// nothing recorded, and those are different facts.
			if sc.Value == "" {
				return "Set-Cookie: " + sc.Name + " (no value recorded on this capture)"
			}
			return "Set-Cookie: " + sc.Name + "=" + sc.Value
		}
	}
	return ""
}

// crlfHeaderInBaseline reports whether the unperturbed control already carries the header this
// class is looking for, which would make the detector unusable on this endpoint.
func crlfHeaderInBaseline(ctx triage.ClassifyCtx) bool {
	for _, r := range []triage.Replay{ctx.Route, ctx.PostBaseline} {
		if !r.Resolved() {
			continue
		}
		if pxHasRespHeader(r.Obs(), crlfHeaderName) {
			return true
		}
		for _, sc := range r.Obs().SetCookies {
			if strings.EqualFold(strings.TrimSpace(sc.Name), crlfCookieName) {
				return true
			}
		}
	}
	return false
}

// crlfMarkerInResponse answers whether this probe's value reached the response in any form, and it
// is the ONLY place in this class that looks at a body.
//
// It is not an oracle and it can never produce a verdict on its own. It exists so a clean can say
// which of two very different silences it is describing, and so the round-1 decision has evidence
// behind it. The comment is here because "this function reads the body" is exactly the line a
// later reader would reuse somewhere it must not be reused.
func crlfMarkerInResponse(o triage.Observation, m triage.Marker) bool {
	if m == "" {
		return false
	}
	if _, ok := faByteForm(o.Body, []byte(m)); ok {
		return true
	}
	for _, h := range o.RespHeaders {
		if strings.Contains(strings.ToLower(h[1]), strings.ToLower(string(m))) {
			return true
		}
	}
	return false
}

// crlfReflects reads the no-line-break control's answer to "does this value reach the response".
func crlfReflects(honest []faOwnObs) (reflects bool, measured bool) {
	for _, o := range honest {
		if o.ProbeID != crlfNC1 {
			continue
		}
		return crlfMarkerInResponse(o.Obs, o.Marker), true
	}
	return false, false
}

// crlfEdgeDefence reports whether the line break was refused in front of the application.
//
// THE SHAPE IT LOOKS FOR. Every probe that carries a CR or an LF came back with a status the
// no-line-break control did NOT get, and that status is a client error. That is an edge, a WAF or
// a framework validator rejecting the byte rather than the application handling it. It is a named
// defence and therefore not_exploitable, which is a genuinely different answer from clean.
//
// THE TWO WAYS IT REFUSES TO CLAIM ONE. Without the no-line-break control there is nothing to
// compare against, so a uniform 400 could equally be an endpoint that 400s on everything. And a
// single CRLF-bearing probe is not a pattern: the rule needs at least two, so an endpoint that
// happens to dislike one particular payload is not read as a policy.
func crlfEdgeDefence(ctx triage.ClassifyCtx, honest []faOwnObs) (bool, string) {
	var control *faOwnObs
	byID := map[triage.ProbeID]faOwnObs{}
	for i := range honest {
		byID[honest[i].ProbeID] = honest[i]
		if honest[i].ProbeID == crlfNC1 {
			control = &honest[i]
		}
	}
	if control == nil || !control.Obs.Delivered() {
		return false, ""
	}
	controlStatus := control.Obs.Status
	rejected := 0
	var statuses []string
	for _, id := range crlfCRLFBearing() {
		o, ok := byID[id]
		if !ok || !o.Obs.Delivered() {
			continue
		}
		if o.Obs.Status == controlStatus {
			return false, ""
		}
		if o.Obs.Status < 400 || o.Obs.Status >= 500 {
			return false, ""
		}
		rejected++
		statuses = append(statuses, string(id)+"="+strconv.Itoa(o.Obs.Status))
	}
	if rejected < 2 {
		return false, ""
	}
	_ = ctx
	return true, "every probe carrying a line break was answered with a 4xx that the otherwise identical " +
		"no-line-break control did not get (" + strings.Join(statuses, ", ") + " against " +
		strconv.Itoa(controlStatus) + " for " + string(crlfNC1) + "), across " +
		pxCount(rejected, "distinct payloads")
}

// crlfLabel is the tool pointer.
//
// It is short and it is honest: there is no CRLF container in this framework (no crlfuzz, no
// equivalent), so nuclei's DAST templates are the second detector and the exploitation step is
// manual, because turning a header injection into an actual exploit needs a cache or a session to
// chain into and that decision belongs to an operator looking at the application.
func crlfLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"injected_header": crlfHeaderName,
		"nuclei":          "the DAST CRLF template set, as a second detector on a slot this class already implicated",
		"manual": "there is no CRLF container in this framework. Turning header injection into an exploit " +
			"needs a chain (a cache that stores the response, a session to fix, a Location to forge) and " +
			"that is a judgement about the application, not a scan",
	}
	if w, ok := ann["winning_probe"].(string); ok {
		hints["winning_probe"] = w
		hints["next"] = "reproduce with replay_request against the composed URL and read the response " +
			"headers; the injected header is visible in any client that prints them"
	}
	return triage.TriageLabel{Tools: []string{"nuclei"}, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (crlfClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "header_not_body", Probes: crlfAllProbeIDs(),
			Rule: "every detector in this class reads Observation.RespHeaders and " +
				"Observation.SetCookies. None reads the body. The literal text " + crlfHeaderName +
				" in a reflected parameter is not a header and must never score",
		},
		{
			Name: "no_line_break_no_header", Probes: []triage.ProbeID{crlfNC1},
			Rule: "CRLF-NC1 carries the header name and no CR and no LF. On a reflecting application its " +
				"bytes land in the body verbatim, and the correct verdict is that nothing was found. A hit " +
				"there is reported at a DIFFERENT oracle, because a header sink that splits without a line " +
				"break is a worse bug and not a false positive",
		},
		{
			Name: "line_break_without_a_name", Probes: []triage.ProbeID{crlfNC2},
			Rule: "CRLF-NC2 delivers the line break and names nothing. No header may be attributed to it. " +
				"It catches a detector built on 'the response gained a header' or 'the response changed'",
		},
		{
			Name: "marker_in_the_injected_value", Probes: []triage.ProbeID{crlfQ1, crlfQ2, crlfQ3, crlfQ4, crlfQ5},
			Rule: "the injected header's value must contain THIS probe's marker. The name alone would fire " +
				"on a cached response from an earlier run, and the run id inside the marker is what makes " +
				"that distinguishable",
		},
		{
			Name: "absent_from_the_baseline", Probes: crlfAllProbeIDs(),
			Rule: "the header and the cookie name must be absent from the unperturbed control and from the " +
				"post-baseline. Present on either and the detector is unusable on this endpoint, which is " +
				"cannot_determine and never a finding",
		},
	}
}

func (crlfClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "injected_header", Kind: "protocol", What: "the header name and value exactly as the response carried them, which is the whole proof"},
		{Name: "winning_form", Kind: "annotation", What: "which spelling got through: CR LF, bare LF, double-decoded percent text, or the lossy Unicode cast. That decides whether the fix is a filter or a header-writing API"},
		{Name: "set_cookie_name", Kind: "protocol", What: "a controllable Set-Cookie is session fixation. The value is hashed at capture and the verdict says so rather than implying a comparison"},
		{Name: "edge_rejection_statuses", Kind: "differential", What: "the 4xx every line-break payload got against the status the identical no-line-break control got, which is what distinguishes a defence from a quiet endpoint"},
		{Name: "value_reaches_the_response", Kind: "differential", What: "whether the no-line-break control's marker came back at all, which tells a clean which of two silences it is describing"},
		{Name: "splitting_not_measured", Kind: "annotation", What: "recorded on every verdict: this class never tested response splitting, because the client parses one response"},
	}
}

// OracleCases. The negatives are the ones doing the work here, and the first of them is the whole
// reason CRLF-NC1 exists.
func (crlfClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "header_injection", Route: "/crlf/header", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{crlfQ1, crlfNC1}, WantState: triage.StateFinding,
			Why: "a route that concatenates the parameter into a response header value without filtering " +
				"the line break. CRLF-Q1 must produce a finding and CRLF-NC1, which differs from it by " +
				"exactly two bytes, must not",
		},
		{
			Name: "reflection_is_not_injection", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: crlfRound0(), WantState: triage.StateClean,
			Why: "the shipped echo route puts the parameter in the BODY. Every probe's response then " +
				"contains the exact text " + crlfHeaderName + " and a marker, and the verdict must be " +
				"clean. THIS IS THE MOST IMPORTANT CASE IN THE CLASS: a detector that searches the " +
				"response instead of the header list passes every positive fixture and fails this one",
		},
		{
			Name: "bare_lf_only", Route: "/crlf/lfonly", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{crlfQ1, crlfQ3}, WantState: triage.StateFinding,
			Why: "a route whose filter strips the two-byte CR LF sequence and passes a lone LF. Q1 must " +
				"produce nothing and Q3 must fire. It is what proves the two are separate probes rather " +
				"than two spellings, and a class that shipped only Q1 reports clean here",
		},
		{
			Name: "double_decode", Route: "/crlf/doubledecode", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{crlfQ1, crlfQ4}, WantState: triage.StateFinding,
			Why: "a route that percent-decodes the parameter a second time before using it. Q1's CR LF is " +
				"consumed by the transport decode and the second decode finds nothing; Q4's literal %0d%0a " +
				"survives the first and becomes a line break on the second. The one route that justifies a " +
				"query-only probe with a named encoder",
		},
		{
			Name: "waf_rejects_the_line_break", Route: "/crlf/edgereject", Expect: faExpectNegative, Exists: true,
			Probes: crlfRound0(), WantState: triage.StateNotExploitable,
			Why: "a route that answers 400 to any value containing a CR or an LF and 200 to everything " +
				"else. The verdict must be not_exploitable with the defence named and the statuses " +
				"recorded, NOT clean: something is refusing the byte and nothing here shows what the " +
				"application behind it would do with one",
		},
		{
			Name: "endpoint_400s_on_everything", Route: "/clean/validate", Expect: faExpectNegative, Exists: true,
			Probes: crlfRound0(), WantState: triage.StateCannotDetermine,
			Why: "a route that rejects every value, line break or not. The no-line-break control gets the " +
				"same status as the payloads, so the EDGE-DEFENCE rule must not fire: without the control " +
				"this route is indistinguishable from /crlf/edgereject and the class would invent a defence " +
				"on every strict validator. WHAT IT MUST ANSWER INSTEAD IS cannot_determine (blocked) AND " +
				"NOT CLEAN, which is a correction the oracle run forced and which this case previously had " +
				"wrong. Every probe got one identical page that the baseline did not get, so the header " +
				"writer was never reached and nothing whatever was learned about it. A clean here would be " +
				"a green tick over a code path no request in this class ever arrived at, and not knowing " +
				"is not clean",
		},
		{
			Name: "header_of_our_name_in_the_baseline", Route: "/crlf/preset", Expect: faExpectNegative, Exists: true,
			Probes: crlfRound0(), WantState: triage.StateCannotDetermine,
			Why: "a route that emits a header called " + crlfHeaderName + " unconditionally, as an " +
				"intermediary echoing request headers would. Every probe would otherwise fire. The verdict " +
				"must be cannot_determine (signature_in_baseline), which is the rule the whole tier-4 " +
				"error-signature family lives by applied to a tier-5 oracle",
		},
		{
			Name: "set_cookie_injection", Route: "/crlf/setcookie", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{crlfQ6}, WantState: triage.StateFinding,
			Why: "a route whose injected line break produces a real Set-Cookie. The verdict must carry the " +
				"planted cookie's value, because that is the evidence the finding is written up from",
		},
	}
}
