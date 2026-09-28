package triageclasses

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS PP-SERVER (id 22). SERVER-SIDE PROTOTYPE POLLUTION, READ THROUGH A PROTOCOL EFFECT THAT
// CARRIES THIS RUN'S OWN TOKEN.
//
// THE MECHANISM, MEASURED ON NODE v24.14.1 (harvest-client.md, scratchpad/patt/pp.js):
//
//	before  app.get(json spaces) -> undefined
//	after   app.get(json spaces) -> zqj12340000000xy
//	res.json body -> "{\nzqj1234000\"ok\": true,\nzqj1234000\"id\": 7\n}"
//	ctor rung -> CTORPATH
//	restore -> "{\"ok\":true,\"id\":7}"
//	residue: own prop still on Object.prototype? -> true 0
//
// Express's res.json calls app.get('json spaces'), which reads app.settings[name] off a plain
// object literal, so a polluted Object.prototype['json spaces'] is picked up. JSON.stringify
// accepts a STRING as its space argument, so the polluted value becomes the INDENTATION of every
// JSON response. Send our own token as that value and the effect carries the token: the bytes that
// appear in the response cannot have come from anywhere but this probe's payload.
//
// That is why this class is worth building on a JSON API that reflects nothing. It is not a
// differential, not a threshold and not a reflection. It is the application emitting bytes we
// chose, in a position (between a newline and a structural character) that no echo can put them
// in.
//
// =================================================================================================
// THIS CLASS CHANGES STATE OTHER USERS SEE, AND EVERY LINE BELOW IS SHAPED BY THAT
// =================================================================================================
// Object.prototype is process-global. Between the polluting probe and the restoring probe, EVERY
// response that Express process serialises, to anybody, is indented with our token. That is
// seconds of cosmetically broken JSON on a shared target and it is the reason for all of this:
//
//	OPT-IN.          Every probe here is TierOptIn, so the runner refuses all of them unless the
//	                 operator set this class's tier to opt_in for the run. No default run of this
//	                 layer sends one byte of this class. tierAllows in triageRun.go is what
//	                 enforces it; the declaration here is what asks for it.
//	PAIRED.          A polluting probe is NEVER planned without its restoring probe in the SAME
//	                 batch. The runner sends one batch's requests consecutively, so the polluted
//	                 window is one request wide.
//	BUDGETED FIRST.  The batch is not planned at all unless the per-slot and per-run budgets can
//	                 cover the whole of it. A budget that bit between pollute and restore would
//	                 leave the target polluted, so the room is checked before the first byte.
//	VERIFIED.        The restore is checked, twice: the restoring probe's own response must be
//	                 free of the effect, and the post-baseline (an unperturbed request taken after
//	                 the last probe on this slot) must be too. A restore that cannot be VERIFIED is
//	                 recorded loudly on the verdict, not assumed.
//
// AND THE TWO THINGS THIS LAYER CANNOT ENFORCE FROM INSIDE A CLASSIFIER, SAID PLAINLY RATHER THAN
// QUIETLY ASSUMED:
//
//	ONE SLOT AT A TIME, AND LAST ON A HOST. Pollution is process-global, so probing slot B while
//	slot A's pollution is live reads as a hit on B. The harvest's own first test run demonstrated
//	exactly that: a control written third printed app.get -> 0 because the process was still
//	polluted from the probe above it. The runner walks slots and rotates classes and a Classifier
//	has no say in either, so this class CANNOT serialise itself. What it can do, and does, is keep
//	its own polluted window to one request and annotate every verdict with the fact that the
//	ordering guarantee is the runner's and is not currently made.
//
//	THE RESIDUE. Restoring with 0 produces byte-identical output, which is what "restored" means
//	here, but the own property STAYS on Object.prototype with the value 0. Nothing outside the
//	process can remove it. The behaviour is restored; the property is not. That is stated on the
//	verdict rather than papered over.
//
// =================================================================================================
// THE TOKEN THIS CLASS ASKED FOR AND DID NOT GET: <marker10>
// =================================================================================================
// JSON.stringify TRUNCATES the space string to its FIRST TEN CHARACTERS (measured, above). A
// 16-byte marker therefore arrives as anchor(3) + run id(4) + the first three ordinal digits, and
// for every ordinal below 36^3 those three digits are "000". So the indentation identifies THE
// RUN and not the probe, and in principle not even the class.
//
// The harvest asked for a runner substitution token, <marker10>, holding exactly the ten bytes
// that will survive. It does not exist: triageRenderPayloadInto substitutes triage.MarkerPlaceholder
// for every class and the ${...} and <...> families only for seven named classes, and
// triageUnsubstituted would not catch a stray <marker10> for a class outside those families, so a
// payload spelling it would go out with the literal text "<marker10>" in it and test nothing.
//
// SO THIS CLASS SHIPS WITHOUT IT AND PAYS THE PRICE IN TWO PLACES, BOTH NAMED:
//
//	(1) the effect is RUN-attributable rather than PROBE-attributable, so a hit is graded MEDIUM
//	    rather than high, and the annotation says why. It is still marker-anchored: no baseline
//	    and no other application on earth emits this run's anchor+id in an indent position.
//	(2) PPS-NC2, the control that proves the detector is not matching an echo, has to spell the
//	    FULL marker where it would rather spell the exact ten bytes the matcher looks for. It is
//	    still a valid control (the re-escaped newline is what kills the echo, not the token
//	    length) and the test that proves it is in ppserver_test.go.
//
// What is needed for grade high: <marker10> in triageRenderPayloadInto's substitution table, and
// in triageUnsubstituted so an unsubstituted one refuses the probe instead of sending it.
//
// =================================================================================================
// WHAT IS REFUSED OUTRIGHT
// =================================================================================================
// PATT lists six black-box Express gadgets. FIVE ARE NOT HERE AND WILL NOT BE, because their whole
// effect is on other people's requests and none of it is cosmetic:
//
//	{"__proto__":{"status":510}}               every response becomes 510, for everyone
//	{"__proto__":{"parameterLimit":1}}         the query parser drops parameters, for everyone
//	{"__proto__":{"exposedHeaders":["foo"]}}   a CORS header appears on every response
//	{"__proto__":{"ignoreQueryPrefix":true}}   the query parser changes shape, for everyone
//	{"__proto__":{"shell":"node", ...}}        remote code execution on the next child_process call
//
// json spaces survives the non-destructive rule because its entire effect is whitespace in a JSON
// body, it restores to byte-identical output, and the restore is verified. json escape, the
// harvest's declared secondary oracle, is NOT shipped: it also needs res.json to run, so it adds
// no reach that json spaces does not already have, and a second state mutation that buys nothing
// is a second state mutation.

type ppServerClassifier struct{ faNoSettle }

func init() { triage.RegisterClassifier(ppServerClassifier{}) }

func (ppServerClassifier) ID() triage.ClassID { return triage.ClassPPServer }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	ppsJ1  triage.ProbeID = "PPS-J1"
	ppsR1  triage.ProbeID = "PPS-R1"
	ppsJ2  triage.ProbeID = "PPS-J2"
	ppsR2  triage.ProbeID = "PPS-R2"
	ppsNC1 triage.ProbeID = "PPS-NC1"
	ppsNC2 triage.ProbeID = "PPS-NC2"
)

// ppsSetting is the one Express setting this class will touch, and the reason it is a constant is
// so that a future edit adding a second one has to come past this comment.
//
// It is chosen because its ENTIRE effect is whitespace inside a JSON body. Every other setting on
// PATT's list changes a status code, a header, a parser or a child process, and those are other
// people's requests being broken rather than made ugly.
const ppsSetting = "json spaces"

// ppsIndentLen is how many bytes of the space string JSON.stringify keeps. MEASURED on node
// v24.14.1: the eleventh character onwards is discarded, so a 16-byte marker lands as ten.
const ppsIndentLen = 10

var (
	ppsPoints   = []triage.SlotKind{triage.KindBody}
	ppsEncoders = []triage.EncoderMode{triage.EncodeJSONNodeReplace}
)

func (ppServerClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassPPServer
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: ppsJ1, Class: c,
			Logical:  []byte(`{"__proto__":{"` + ppsSetting + `":"` + m + `"}}`),
			Encoders: ppsEncoders, Points: ppsPoints,
			Tier: triage.TierOptIn, Risk: triage.RiskR2,
			Notes: "THE POLLUTING PROBE. A recursive merge that walks this object writes our value onto " +
				"Object.prototype, and Express's res.json then indents every JSON response with it. The " +
				"value is this probe's own marker, so the effect carries our token; JSON.stringify keeps " +
				"the first ten bytes of it, which is the run's anchor and id. VERIFIED on node v24.14.1. " +
				"It is NEVER planned without PPS-R1 in the same batch",
		},
		{
			ID: ppsR1, Class: c,
			Logical:  []byte(`{"__proto__":{"` + ppsSetting + `":0}}`),
			Encoders: ppsEncoders, Points: ppsPoints,
			Tier: triage.TierOptIn, Risk: triage.RiskR2,
			Notes: "THE RESTORE for PPS-J1, and the reason this class is allowed to exist. VERIFIED: a " +
				"space argument of 0 makes JSON.stringify produce output byte-identical to the " +
				"unpolluted case. It carries no marker deliberately: it is not asking the target a " +
				"question, it is putting the target back, and a marker in it would be a second token in " +
				"the indent position while we are trying to prove the indent position is empty. THE " +
				"RESIDUE IS REAL AND IS NOT HIDDEN: the own property stays on Object.prototype with the " +
				"value 0 and nothing outside the process can remove it",
		},
		{
			ID: ppsJ2, Class: c,
			Logical:  []byte(`{"constructor":{"prototype":{"` + ppsSetting + `":"` + m + `"}}}`),
			Encoders: ppsEncoders, Points: ppsPoints,
			Tier: triage.TierOptIn, Risk: triage.RiskR2,
			Notes: "THE CONSTRUCTOR RUNG, sent only when PPS-J1 did not fire and its restore verified. " +
				"PATT documents constructor.prototype as the way past a merge that blocks the literal key " +
				"__proto__, and the harvest confirmed in pp.js that it reaches the same object. Two " +
				"requests rather than four in the common case, because on a merge that takes __proto__ " +
				"this one asks nothing new",
		},
		{
			ID: ppsR2, Class: c,
			Logical:  []byte(`{"constructor":{"prototype":{"` + ppsSetting + `":0}}}`),
			Encoders: ppsEncoders, Points: ppsPoints,
			Tier: triage.TierOptIn, Risk: triage.RiskR2,
			Notes: "THE RESTORE for PPS-J2, paired with it in the same batch for the same reason PPS-R1 is " +
				"paired with PPS-J1. It restores through the rung that polluted, because a merge that " +
				"refused __proto__ on the way in would refuse it on the way out too",
		},
		{
			ID: ppsNC1, Class: c,
			Logical:  []byte(`{"ppsnc1` + m + `":{"` + ppsSetting + `":"` + m + `"}}`),
			Encoders: ppsEncoders, Points: ppsPoints,
			Tier: triage.TierOptIn, Risk: triage.RiskR1, IsControl: true,
			Notes: "THE NESTED-OBJECT CONTROL. Identical in shape to PPS-J1 and pointed at an ORDINARY KEY " +
				"instead of the prototype, so it proves the detector is not firing on 'we sent a nested " +
				"object' or on 'the endpoint changed when we sent one'. VERIFIED silent in pp.js: " +
				"non-proto key -> app.get: undefined, body compact. It is sent AFTER a restore, never " +
				"while pollution is live, because a control measured in a polluted process reads as a hit " +
				"and that is exactly the mistake the harvest made on its own first run",
		},
		{
			ID: ppsNC2, Class: c,
			Logical:  []byte(`{"ppsnc2` + m + `":"\n` + m + `\"ok\": true,\n` + m + `\"id\": 7"}`),
			Encoders: ppsEncoders, Points: ppsPoints,
			Tier: triage.TierOptIn, Risk: triage.RiskR1, IsControl: true,
			Notes: "THE ECHO CONTROL, and the one that carries the answer in its own payload. It sends a " +
				"STRING VALUE that spells the exact shape the detector looks for: a newline, the token, a " +
				"quote. If the application echoes it, JSON.stringify re-escapes the newline as the two " +
				"bytes backslash-n, so the raw 0x0A anchor fails and the detector stays silent. VERIFIED " +
				"in nc2.js: a naive matcher fires, the raw-LF matcher does not. It would rather spell the " +
				"exact ten bytes the matcher looks for, which is what <marker10> was asked for; the full " +
				"marker is the closest spelling available and the test proves it still controls the thing " +
				"it exists to control",
		},
	}
}

func ppsAllProbeIDs() []triage.ProbeID {
	return []triage.ProbeID{ppsJ1, ppsR1, ppsJ2, ppsR2, ppsNC1, ppsNC2}
}

// ppsPolluters and ppsControls name the two halves for the readers that need them.
func ppsIsPolluter(id triage.ProbeID) bool { return id == ppsJ1 || id == ppsJ2 }
func ppsIsControl(id triage.ProbeID) bool  { return id == ppsNC1 || id == ppsNC2 }

// ppsRestoreFor is the pairing, as data. A polluter with no restore is a probe this class refuses
// to plan, and this function is what a test asserts that against.
func ppsRestoreFor(id triage.ProbeID) (triage.ProbeID, bool) {
	switch id {
	case ppsJ1:
		return ppsR1, true
	case ppsJ2:
		return ppsR2, true
	}
	return "", false
}

func ppsReq(id triage.ProbeID, slot triage.SlotKey) triage.ProbeRequest {
	return triage.ProbeRequest{Spec: id, Slot: slot, Variant: map[string]string{}}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. A merge sink takes a STRUCTURED OBJECT, so the only insertion point this class has is a
// body that carries one.
func (ppServerClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "the payload is a JSON OBJECT and reaches the application through the node-replace " +
				"encoder, which edits a JSON document. The conditions are that the body is JSON (a form or " +
				"multipart body carries no node to replace) and that the application MERGES the object at " +
				"this pointer into something, which is the half no probe can know in advance. Request " +
				"media type seen: " + string(mt),
		}
	case triage.KindQuery:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the query rung of this bug is __proto__[json spaces]=<token>, which needs the " +
				"parameter NAME to be the payload AND a VALUE of our choosing alongside it. The name-slot " +
				"encoder replaces the name and KEEPS THE OBSERVED VALUE (triageEncodeNameSlot), and " +
				"ProbeRequest has no field that supplies a value for it, so the probe this layer could " +
				"send would pollute with whatever value the capture happened to hold and nothing about " +
				"the response would be attributable to us. It is refused rather than sent unattributable. " +
				"What it needs: a value alongside a name-slot payload. Note also that qs has shipped " +
				"allowPrototypes:false for years, so this rung only reaches applications that merge " +
				"req.query into a config object themselves",
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "a header value is a string and a merge sink takes a structured object. An application " +
				"that JSON-parses a header and merges the result exists and is not something any payload " +
				"in this class can deliver, because the header NAME is fixed by the capture",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "same as a header: a cookie value is a string, and a cookie that is JSON-parsed and " +
				"merged is a sink this class cannot address",
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "a path segment is a string in a position that no merge takes an object from",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the fragment is never transmitted (RFC 3986 section 3.5), so no server-side merge can " +
				"ever see it. Client-side prototype pollution through the fragment is real and belongs to " +
				"PP-CLIENT, which needs a browser",
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

// Plan is the paired ladder. Two requests in the common case, four when the constructor rung is
// worth asking, and the two controls only when there is a hit to verify.
//
// THE CONTROLS ARE GATED ON A HIT AND THAT IS A DELIBERATE INVERSION OF THE USUAL ORDER. Every
// other class in this package sends its negative controls in round 0, because a control that runs
// only when something fired cannot protect a clean. Here it can: both controls exist to refuse a
// FALSE POSITIVE (a nested object changing the response, an echo of the payload), and neither of
// them says anything about a silence. Sending them unconditionally would double the number of
// state-mutating requests this class makes against every JSON body slot on the target, for
// nothing, and this is the one class in the layer where a request has a cost beyond the wire.
func (c ppServerClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType).Reach == triage.ReachNever {
		return nil
	}
	if !ppsSlotTakesAJSONObject(ctx.Slot) {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() {
		return nil
	}
	batch := ppsBatchFor(ctx.Round, faOwn(ctx.Own))
	if len(batch) == 0 || !ppsBudgetCoversTheWholeBatch(ctx.Budget, len(batch)) {
		return nil
	}
	out := make([]triage.ProbeRequest, 0, len(batch))
	for _, id := range batch {
		out = append(out, ppsReq(id, ctx.Slot.Key))
	}
	return out
}

// ppsBatchFor is the ladder as a pure function of the round and of this class's own responses so
// far. Every batch that pollutes carries its restore.
//
// It takes the resolved own-set rather than the PlanCtx so that a test can drive it: ctx.Own is an
// OwnedResponses, which only package triage can populate, so a ladder reading it directly would be
// a ladder nothing in this package could exercise. The property this buys a test is the important
// one in this class, which is that NO round ever returns a polluting probe without its restore.
func ppsBatchFor(round int, own []faOwnObs) []triage.ProbeID {
	switch round {
	case 0:
		return []triage.ProbeID{ppsJ1, ppsR1}
	case 1:
		if ppsAnyPolluterFired(own) {
			return ppsControlsIfNotSent(own)
		}
		// Nothing fired. The constructor rung is only worth sending if the restore we already
		// performed is verifiable from here, because sending a second polluting probe into a
		// process we are not sure we cleaned is how a class turns one mutation into two.
		if ppsRestoreLooksHeld(own) {
			return []triage.ProbeID{ppsJ2, ppsR2}
		}
		return nil
	case 2:
		if ppsAnyPolluterFired(own) {
			return ppsControlsIfNotSent(own)
		}
		return nil
	}
	return nil
}

func ppsControlsIfNotSent(own []faOwnObs) []triage.ProbeID {
	var out []triage.ProbeID
	for _, id := range []triage.ProbeID{ppsNC1, ppsNC2} {
		if _, seen := faFind(own, id); !seen {
			out = append(out, id)
		}
	}
	return out
}

// ppsBudgetCoversTheWholeBatch refuses to pollute without the room to restore.
//
// THIS IS THE ONE GATE IN THE CLASS THAT IS ABOUT THE TARGET AND NOT ABOUT THE ANSWER. runSlot
// breaks out of a batch the moment spent reaches the per-slot cap or the per-run cap hits zero,
// and it does that BETWEEN requests, so a batch planned with room for one request would send the
// polluting probe, break, and leave the process polluted with no restore behind it. One margin
// request is kept in hand on top of the batch so that the same check on the next class's first
// probe cannot be the thing that bit.
func ppsBudgetCoversTheWholeBatch(b triage.TriageBudget, n int) bool {
	if b.Exhausted() {
		return false
	}
	return b.RemainingPerSlot >= n+1 && b.RemainingPerRun >= n+1
}

// ppsSlotTakesAJSONObject is the plan-time encoder question, asked the way SlotAcceptsEncoder
// asks it: a node-replace payload needs a body slot whose media is JSON, and an unset media
// resolves to JSON exactly as triageSlotBodyMedia resolves it.
//
// IT ALSO DE-DUPLICATES THE TWO SLOTS THAT SHARE ONE POINTER. The slot derivation emits two slots
// per JSON node, one declaring EncodeJSONString and one declaring EncodeJSONNodeReplace, and this
// class's payload renders identically into both: the same request would be sent twice and the
// prototype would be polluted twice for one pointer. The node twin is the one that carries this
// class, and the string twin's verdict says so rather than saying nothing.
func ppsSlotTakesAJSONObject(s triage.Slot) bool {
	if s.Kind != triage.KindBody {
		return false
	}
	switch s.BodyMedia {
	case triage.BodyJSON, triage.BodyGraphQL, triage.BodyNone, "":
	default:
		return false
	}
	return s.Encoder == triage.EncodeJSONNodeReplace
}

// ---------------------------------------------------------------------------------------------
// THE DETECTOR
// ---------------------------------------------------------------------------------------------

// ppsIndentToken is the ten bytes that survive JSON.stringify's truncation of the space string.
//
// It is the FIRST TEN of this probe's marker: anchor(3) + run id(4) + the first three ordinal
// digits. For every ordinal below 36^3 those three are "000", so this token identifies the RUN.
// That is the whole of the <marker10> gap: it is enough to exclude every baseline and every other
// application, and it is not enough to name which probe of which class put it there.
func ppsIndentToken(m triage.Marker) string {
	if !m.WellFormed() {
		return ""
	}
	return string(m)[:ppsIndentLen]
}

// ppsStructural are the bytes that may follow an indent in JSON.stringify's output. A key's
// opening quote is the common one; a nested object, array or closing bracket gives the others.
func ppsStructural(b byte) bool {
	switch b {
	case '"', '{', '}', '[', ']':
		return true
	}
	return false
}

// ppsIndentOffsets finds every place the token sits in an INDENT POSITION: immediately after a raw
// 0x0A, repeated zero or more extra times for nesting depth, and immediately before a structural
// byte.
//
// THE RAW NEWLINE IS THE WHOLE ANCHOR AND IT IS WHAT MAKES AN ECHO IMPOSSIBLE TO CONFUSE WITH A
// HIT. A reflected payload puts the token after a quote or in the middle of a string, and if the
// application re-serialises a string value that literally contains a newline then JSON.stringify
// re-escapes it as the two bytes backslash-n. Either way there is no 0x0A in front of the token.
// Measured in the harvest's nc2.js: the naive matcher fires on the echo and this one does not.
func ppsIndentOffsets(body []byte, token string) []int {
	if token == "" || len(body) == 0 {
		return nil
	}
	var out []int
	for i := 0; i < len(body); i++ {
		if body[i] != '\n' {
			continue
		}
		j := i + 1
		reps := 0
		for j+len(token) <= len(body) && string(body[j:j+len(token)]) == token {
			j += len(token)
			reps++
		}
		if reps == 0 || j >= len(body) {
			continue
		}
		if ppsStructural(body[j]) {
			out = append(out, i)
		}
	}
	return out
}

// ppsMinOccurrences is how many indent positions a hit needs.
//
// ONE IS A COINCIDENCE AND TWO IS A DOCUMENT. Indentation repeats once per key and nests, so a
// real hit on any object with two keys produces at least two. A single occurrence in a text field
// is the shape of an accident and is refused.
const ppsMinOccurrences = 2

// ppsStripIndent removes the indent tokens a hit would have inserted, so the caller can ask
// whether what is left is a JSON document.
//
// IT REMOVES A RUN OF THEM AND NOT ONE, and that is not a refinement. JSON.stringify repeats the
// indent once per nesting level, so the second level of any nested object carries the token TWICE
// in a row. The first version of this function was a bytes.ReplaceAll of "\n"+token: it removed
// the first of each pair, left the second, and what remained was not a JSON document, so the
// oracle stayed silent on every response with a nested object in it. The nested case in
// ppserver_test.go is what caught that, and it is the most ordinary JSON body there is.
func ppsStripIndent(body []byte, token string) []byte {
	if token == "" {
		return body
	}
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); {
		if body[i] != '\n' {
			out = append(out, body[i])
			i++
			continue
		}
		out = append(out, '\n')
		j := i + 1
		for j+len(token) <= len(body) && string(body[j:j+len(token)]) == token {
			j += len(token)
		}
		i = j
	}
	return out
}

// ppsEffect is one response's reading.
type ppsEffect struct {
	Obs        faOwnObs
	Token      string
	Offsets    []int
	Stripped   bool // removing the indents left a document that parses as JSON
	InBaseline bool
}

// ppsFired is the oracle. It is deliberately harder to satisfy than the harvest's rule, in one
// place, and the correction matters.
//
// THE HARVEST SAID "in a response whose body parses as JSON". A body indented with an alphanumeric
// token DOES NOT PARSE AS JSON: only space, tab, CR and LF are JSON whitespace, so the very
// response this class exists to find fails that gate. Requiring it would have made the class
// structurally silent, which is the same defect as an oracle gated on reflection and is exactly
// what this round was about.
//
// So the gate is inverted into something stronger: REMOVE the indent tokens and require what is
// left to be a JSON document. That says "this is a JSON body that has been indented with our
// token", which is the claim, rather than "this is a JSON body", which it cannot be.
func ppsFired(e ppsEffect) bool {
	return len(e.Offsets) >= ppsMinOccurrences && e.Stripped && !e.InBaseline
}

// ppsRead resolves one observation into a reading, given the unperturbed bodies this class may
// compare against.
func ppsRead(o faOwnObs, baselines [][]byte) ppsEffect {
	e := ppsEffect{Obs: o, Token: ppsIndentToken(o.Marker)}
	if e.Token == "" {
		return e
	}
	e.Offsets = ppsIndentOffsets(o.Obs.Body, e.Token)
	if len(e.Offsets) == 0 {
		return e
	}
	e.Stripped = json.Valid(ppsStripIndent(o.Obs.Body, e.Token))
	for _, b := range baselines {
		if len(ppsIndentOffsets(b, e.Token)) > 0 {
			e.InBaseline = true
			break
		}
	}
	return e
}

// ppsAnyPolluterFired is the plan-time question, and it uses the same reading the verdict does so
// the ladder and the verdict cannot disagree about whether something happened.
func ppsAnyPolluterFired(own []faOwnObs) bool {
	for _, o := range own {
		if !ppsIsPolluter(o.ProbeID) {
			continue
		}
		if ppsFired(ppsRead(o, nil)) {
			return true
		}
	}
	return false
}

// ppsRestoreLooksHeld is the plan-time half of the restore check: every restore this class has
// already sent came back with no effect in it. It is deliberately conservative, because its only
// caller is deciding whether to pollute a SECOND time.
func ppsRestoreLooksHeld(own []faOwnObs) bool {
	sent := 0
	for _, o := range own {
		if _, isRestore := ppsRestoreOf(o.ProbeID); !isRestore {
			continue
		}
		sent++
		if !o.Obs.Delivered() {
			return false
		}
		if len(ppsIndentOffsets(o.Obs.Body, ppsRunTokenFrom(own))) > 0 {
			return false
		}
	}
	return sent > 0
}

// ppsRestoreOf is ppsRestoreFor backwards: is this probe a restore, and for which polluter.
func ppsRestoreOf(id triage.ProbeID) (triage.ProbeID, bool) {
	switch id {
	case ppsR1:
		return ppsJ1, true
	case ppsR2:
		return ppsJ2, true
	}
	return "", false
}

// ppsRunTokenFrom recovers the ten-byte indent token from whichever of this class's own probes
// carried a marker.
//
// A RESTORING PROBE CARRIES NO MARKER OF ITS OWN, ON PURPOSE, so its response has to be read with
// a token borrowed from the probe whose pollution it is undoing. Every marker in a run shares its
// first ten bytes (anchor plus run id plus three zeroed ordinal digits), which is the same fact
// that costs this class its probe-level attribution and is, here, exactly what makes the borrowing
// sound: the token that would appear in a restore's response is byte-identical to the one the
// polluter installed.
func ppsRunTokenFrom(own []faOwnObs) string {
	for _, o := range own {
		if t := ppsIndentToken(o.Marker); t != "" {
			return t
		}
	}
	return ""
}

// ppsRestoreState is what the verdict says about putting the target back.
type ppsRestoreState string

const (
	// ppsRestoreVerified: a restore was sent, its own response was free of the effect, and the
	// post-baseline was too.
	ppsRestoreVerified ppsRestoreState = "verified"
	// ppsRestoreUnverified: nothing contradicts the restore and nothing confirms it either. It is
	// NOT "verified": the post-baseline is the only unperturbed sample taken after the last probe,
	// and without it this class is asserting a restore it did not measure.
	ppsRestoreUnverified ppsRestoreState = "unverified"
	// ppsRestoreFailed: the effect is still there after the restore. This is the loud one.
	ppsRestoreFailed ppsRestoreState = "failed"
	// ppsRestoreNotNeeded: nothing was ever polluted.
	ppsRestoreNotNeeded ppsRestoreState = "not_needed"
)

// ppsCheckRestore reads the restore twice: the restoring probe's own response, and the
// post-baseline, which is the unperturbed request the runner takes after the last probe on this
// slot and is the closest thing this layer has to "the target as the next user finds it".
//
// It takes the post-baseline as BYTES AND A BOOL rather than as the ClassifyCtx, for the reason
// ppsDecide does the same: a classifier cannot build a Replay, so a check that read one straight
// out of the ctx would be a check no test in this package could ever drive, and this is the check
// that decides whether the class left somebody else's target changed.
func ppsCheckRestore(own []faOwnObs, polluted bool, postBody []byte, postResolved bool) (ppsRestoreState, string) {
	if !polluted {
		return ppsRestoreNotNeeded, "no probe of this class changed anything, so there was nothing to put back"
	}
	token := ppsRunTokenFrom(own)
	if token == "" {
		return ppsRestoreUnverified, "no probe on this slot carried a marker, so the bytes a residue would " +
			"consist of are not known and the restore cannot be checked"
	}

	restoreSeen := false
	for _, o := range own {
		if _, isRestore := ppsRestoreOf(o.ProbeID); !isRestore {
			continue
		}
		restoreSeen = true
		if !o.Obs.Delivered() {
			return ppsRestoreFailed, "the restoring probe " + string(o.ProbeID) + " did not reach the " +
				"application (" + string(o.Obs.TransportErr) + "), so the pollution this class installed " +
				"was never taken back out"
		}
		if len(ppsIndentOffsets(o.Obs.Body, token)) > 0 {
			return ppsRestoreFailed, "the restoring probe " + string(o.ProbeID) + " came back STILL " +
				"CARRYING the indent this class installed, so the setting was not put back"
		}
	}
	if !restoreSeen {
		return ppsRestoreFailed, "this class polluted the prototype and NO RESTORING PROBE was observed on " +
			"this slot. The target is presumed still polluted and the operator must restart the " +
			"application process or send the restore by hand with replay_request"
	}

	if !postResolved {
		return ppsRestoreUnverified, "the restoring probe's own response was clean, and the post-baseline " +
			"(the unperturbed request taken after the last probe on this slot) did not resolve, so the " +
			"state the NEXT user finds was never measured"
	}
	if len(ppsIndentOffsets(postBody, token)) > 0 {
		return ppsRestoreFailed, "the post-baseline, an UNPERTURBED request taken after the last probe on " +
			"this slot, came back indented with this run's token. The application is still polluted"
	}
	return ppsRestoreVerified, "the restoring probe's own response and the unperturbed post-baseline both " +
		"came back free of the indent, so the behaviour is restored. THE PROPERTY IS NOT REMOVED: " +
		"Object.prototype still carries an own 'json spaces' of 0 and nothing outside the process can " +
		"delete it"
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

func (c ppServerClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassPPServer, key, state, reason, oracle, grade, ords, ann, ppsLabel(ann))
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}
	if !ppsSlotTakesAJSONObject(ctx.Slot) {
		return one(triage.StateNotRun, ppsWhyNotThisSlot(ctx.Slot), "", triage.GradeUnrated, nil)
	}
	return ppsDecide(ctx, faOwn(ctx.Own), ppsControlsFrom(ctx))
}

// ppsControls is everything this ladder needs from the SHARED unperturbed channel, as plain data.
//
// It exists because a classifier cannot construct a Replay: NewReplay takes the runner capability
// whose type lives in an internal package this one may not import. That is the right protection
// and its cost is that every arm of every class in this package that reads a control is normally
// undrivable from a test. Reducing the control to the three facts this class actually uses buys
// those arms back, and the restore check is the one that most needs them.
type ppsControls struct {
	RouteResolved   bool
	RouteSpeaksJSON bool
	PostResolved    bool
	PostBody        []byte
	Baselines       [][]byte
	// RouteObs is the unperturbed route control itself, carrying none of our bytes. RouteSpeaksJSON
	// is a DERIVED fact and it answers one question only: can this endpoint show the effect at all.
	// It cannot answer the other one, which is whether the endpoint was answering us at all, and a
	// 500 or a 401 that comes back as {"error":"..."} is valid JSON and passes it.
	RouteObs triage.Observation
}

func ppsControlsFrom(ctx triage.ClassifyCtx) ppsControls {
	c := ppsControls{
		RouteResolved:   ctx.Route.Resolved(),
		RouteSpeaksJSON: ppsRouteBodyIsJSON(ctx),
		Baselines:       faBaselineBodies(ctx),
	}
	if ctx.Route.Resolved() {
		c.RouteObs = ctx.Route.Obs()
	}
	if ctx.PostBaseline.Resolved() {
		c.PostResolved = true
		c.PostBody = ctx.PostBaseline.Obs().Body
	}
	return c
}

// ppsWhyNotThisSlot says which of the two structural reasons kept this class off a body slot. Both
// are unknowns with a reason and neither is a clean.
func ppsWhyNotThisSlot(s triage.Slot) string {
	switch s.BodyMedia {
	case triage.BodyForm, triage.BodyMultipart, triage.BodyXML:
		return "body_is_not_json: this class's payload is a JSON OBJECT and reaches the application " +
			"through the node-replace encoder, which edits a JSON document. This slot carries " +
			string(s.BodyMedia) + ", which has no node to replace, so nothing was sent and nothing is " +
			"known about whether a merge behind this endpoint is reachable another way"
	}
	return "node_twin_carries_this_class: the slot derivation emits two slots for every JSON node, one " +
		"for the string encoder and one for the node-replace encoder, and this class's payload renders " +
		"identically into both. Probing both would send the same request twice and pollute the " +
		"prototype twice for one pointer, so this class runs on the node twin of this pointer and not " +
		"on this one. The pointer IS tested; this row is not the place it is reported"
}

// ppsRouteBodyIsJSON answers "does this endpoint speak JSON at all", from the unperturbed control.
//
// It matters because the oracle is a property of a JSON response: an endpoint that never calls
// res.json cannot show this effect even when the prototype IS polluted, and a class that reported
// clean there would be reporting on an oracle it could not read.
func ppsRouteBodyIsJSON(ctx triage.ClassifyCtx) bool {
	if ctx.Route.Resolved() && json.Valid(ctx.Route.Obs().Body) {
		return true
	}
	if ctx.PostBaseline.Resolved() && json.Valid(ctx.PostBaseline.Obs().Body) {
		return true
	}
	return false
}

// ppsDecide is the verdict ladder, taking this class's own responses and the one derived fact
// about the control that a test in this package cannot otherwise construct (a classifier cannot
// build a Replay, because NewReplay takes the runner capability).
func ppsDecide(ctx triage.ClassifyCtx, own []faOwnObs, ctl ppsControls) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassPPServer, key, state, reason, oracle, grade, ords, ann, ppsLabel(ann))
	}

	ann["state_mutating_class"] = true
	ann["serialization_not_enforced_by_this_layer"] = "pollution is process-global, so a probe of this " +
		"class running while another slot's pollution is live would read as a hit. This class keeps its " +
		"own polluted window to one request and CANNOT order itself against other slots or other " +
		"classes: the runner walks slots and rotates classes and a classifier has no say in either. " +
		"What the runner would need: run this class last on a host and one slot at a time"
	ann["attribution"] = "run, not probe: JSON.stringify keeps the first ten bytes of the space string, " +
		"which are this run's anchor and id. <marker10> would make it probe-attributable and does not exist"
	ann["residue_note"] = "a verified restore means the OUTPUT is byte-identical again. The own property " +
		"stays on Object.prototype with the value 0 and cannot be removed from outside the process"

	if len(own) == 0 {
		return one(ppsNothingSent(ctx, ctl))
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
	skips = append(skips, pxNotObserved(ppsAllProbeIDs(), own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload was refused, altered or left unsubstituted. Nothing "+
				"was measured AND nothing was changed, which is the one consolation in this class",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)
	baselines := ctl.Baselines
	ann["baseline_bodies_compared"] = len(baselines)
	ann["route_speaks_json"] = ctl.RouteSpeaksJSON

	// THE CONTROLS FIRST. Everything after them is a claim about the target, and a claim drawn
	// through a detector that has just been shown to misfire is worse than no claim.
	for _, o := range honest {
		if !ppsIsControl(o.ProbeID) {
			continue
		}
		e := ppsRead(o, baselines)
		if !ppsFired(e) {
			continue
		}
		ann["control_that_fired"] = string(o.ProbeID)
		ann["control_offsets"] = len(e.Offsets)
		v := one(triage.StateCannotDetermine,
			"detector_unverified: "+string(o.ProbeID)+" is a NEGATIVE control and this class's oracle "+
				"fired on it. "+ppsWhyAControlFiring(o.ProbeID)+" Either the detector is wrong or the "+
				"process was still polluted when the control was sent, and both of those make every "+
				"reading on this slot unsafe",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE FINDING.
	var fired *ppsEffect
	for i := range honest {
		if !ppsIsPolluter(honest[i].ProbeID) {
			continue
		}
		e := ppsRead(honest[i], baselines)
		if ppsFired(e) {
			fired = &e
			break
		}
		if len(e.Offsets) > 0 && e.InBaseline {
			ann["effect_present_in_baseline"] = true
		}
	}

	state, reason := ppsCheckRestore(honest, fired != nil, ctl.PostBody, ctl.PostResolved)
	ann["restore"] = string(state)
	ann["restore_detail"] = reason

	if fired != nil {
		ann["winning_probe"] = string(fired.Obs.ProbeID)
		ann["indent_positions"] = len(fired.Offsets)
		ann["indent_token_bytes"] = ppsIndentLen
		ann["rung"] = ppsRungName(fired.Obs.ProbeID)
		controlsRan := ppsControlsRan(honest)
		ann["controls_ran"] = controlsRan
		grade := triage.GradeMedium
		if !controlsRan {
			ann["grade_capped"] = "the negative controls did not run on this slot, so the detector was not " +
				"shown silent here"
		}
		head := ""
		if state == ppsRestoreFailed || state == ppsRestoreUnverified {
			head = "RESTORE " + strings.ToUpper(string(state)) + ": " + reason + ". THAT IS THE FIRST THING " +
				"TO ACT ON, ahead of the finding itself. "
		}
		v := one(triage.StateFinding,
			head+"json_spaces_indent: an UNPERTURBED property of this response changed in a way only this "+
				"probe could have caused. The application indented its JSON with the first ten bytes of "+
				"THIS RUN'S marker, at "+strconv.Itoa(len(fired.Offsets))+" separate indent positions, and "+
				"removing those tokens leaves a valid JSON document. That is Express reading "+
				"Object.prototype['"+ppsSetting+"'] through app.get, which means the object at this body "+
				"pointer was merged into something that walks __proto__ or constructor.prototype. The "+
				"gadget reached here is cosmetic; the MERGE is the bug, and the same merge reaches "+
				"status, parameterLimit and, on a process that spawns children, shell",
			"json_spaces_indent", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: fired.Obs.Ordinal, ObsID: fired.Obs.Obs.ObsID, Phrase: "json_spaces_indent",
			Matched: []byte(fired.Token), Offset: fired.Offsets[0], Length: len(fired.Token),
			Wire: fired.Obs.Obs.Payload, MarkerForm: "raw",
		}
		return v
	}

	// A RESTORE THAT FAILED WITH NOTHING FIRING IS STILL THE LOUDEST THING ON THE ROW. It can
	// happen when a polluting probe's response was not readable but the pollution landed.
	if state == ppsRestoreFailed {
		v := one(triage.StateCannotDetermine,
			"residue_not_restored: "+reason+". No verdict about this slot is available and the target may "+
				"be left changed. Restart the application process or replay the restoring payload by hand",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE ORACLE HAS TO BE READABLE BEFORE A SILENCE MEANS ANYTHING. An endpoint that never emits
	// JSON cannot show this effect even when the prototype IS polluted.
	if !ctl.RouteSpeaksJSON {
		v := one(triage.StateCannotDetermine,
			"oracle_unreadable_no_json_response: this class reads the INDENTATION of a JSON response, and "+
				"no unperturbed response from this endpoint parsed as JSON. A merge sink behind this "+
				"pointer would be invisible here, so the silence is the oracle's and not the target's",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE DECLARED EVIDENCE SURFACE, and it is the last guard but one before this class's clean.
	//
	// THE ORACLE IS BYTES IN A BODY: ten of them, at an indent position, in a JSON document. A
	// response with no body carries none of that, and on a route whose unperturbed control is
	// already failing the documents this class searched are the failure's rather than the
	// application's answer to a polluted request. The JSON guard above cannot see either case: it
	// asks whether the endpoint EVER speaks JSON, and a 500 that comes back as {"error":"..."} is
	// valid JSON.
	//
	// IT IS THE SAME pxReadsBody DESER AND ORM-LEAK DECLARE, and the declaration is right for this
	// class rather than copied: every arm above reads ppsRead, ppsRead reads o.Obs.Body, and there
	// is no second channel.
	ann["evidence_surface"] = string(pxReadsBody)
	if why, absent := pxNoEvidenceToRead(pxReadsBody, honest, ctl.RouteObs, ctl.RouteResolved); absent {
		v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// AND THE ONE pxReadsBody CANNOT SEE, WHICH IS THIS CLASS'S ALONE. A 401 is not a 5xx and a
	// JSON 401 body is not an empty one, so both arms above pass it. What makes it fatal here is
	// particular to this oracle: the indent appears only once a merge has ACTUALLY RUN, and a
	// non-2xx is not evidence that this endpoint carried the request out at all. The operator's live estate
	// answers 401 to 88% of probes, so this is the common case there and not the corner.
	if why, unanswered := ppsNoPolluterWasAnswered(honest); unanswered {
		v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	ann["clean_preconditions"] = []string{
		"the endpoint returns JSON, so the indent oracle is readable on it",
		"THE REQUEST WAS ANSWERED: at least one polluting payload came back with a 2xx, so the " +
			"endpoint carried it out rather than turning it away before anything could merge",
		ppsControlPrecondition(ctl.RouteResolved),
		"a polluting object reached this body pointer on the wire and the response carried no indent effect",
		"the restore state is " + string(state),
		"the negative controls were not needed, because nothing fired for them to disprove",
	}
	ann["what_this_clean_does_not_cover"] = "the query rung (__proto__[json spaces] with a value of our " +
		"own), which this layer cannot deliver; every non-Express server-side gadget, since the oracle " +
		"here IS an Express setting; and a merge that happens on a different pointer of this body"
	v := one(triage.StateClean,
		"no_prototype_effect: a JSON object spelling __proto__ (and, where the ladder went that far, "+
			"constructor.prototype) was placed at this body pointer and the endpoint's JSON came back "+
			"unindented. Either nothing merges this object or the merge refuses both rungs. The effect "+
			"is a protocol one and needs no reflection, so this silence is the application's answer and "+
			"not a limitation of the oracle",
		"no_json_spaces_effect", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// ppsNoPolluterWasAnswered is the precondition that belongs to THIS oracle and to no other in
// the family.
//
// WHY A STATUS RULE IS RIGHT HERE AND WOULD BE WRONG FOR A REFLECTION CLASS. A class that reads
// its own value back out of a body learns something real from a 403 page: the value reached
// something that rendered. This class reads a GLOBAL setting of the receiving process, which only
// changes once our object has been merged into a prototype. An endpoint that refused the request
// merged nothing, so the effect had no opportunity to exist, and its absence is the refusal
// speaking rather than the application.
//
// IT COUNTS ANSWERS AND NOT REFUSALS, deliberately. "None of them was a 2xx" is a fact this
// witness measured. "They were all refused" would be a guess about what a 404 or a 400 or a 302
// means on somebody else's endpoint, and the difference between those is not measured here and is
// not needed: what stops the clean is only that nothing came back from a request this endpoint
// carried out.
// ppsControlPrecondition says only what was checked. pxBodySurfaceUnreadable skips its control
// arm entirely when no route control resolved, and a clean listing that arm anyway would be a
// precondition printed because it is usually true rather than because it was measured.
func ppsControlPrecondition(haveControl bool) string {
	if !haveControl {
		return "NO UNPERTURBED ROUTE CONTROL RESOLVED, so whether this endpoint was already failing " +
			"before it read anything we sent was NOT CHECKED on this slot"
	}
	return "THE CONTROL WAS NOT ITSELF FAILING: the unperturbed route control did not answer 5xx, so " +
		"the documents searched are the application's and not an error page's"
}

func ppsNoPolluterWasAnswered(honest []faOwnObs) (string, bool) {
	delivered, answered := 0, 0
	var statuses []string
	seen := map[int]bool{}
	for _, o := range honest {
		if !ppsIsPolluter(o.ProbeID) || !o.Obs.Delivered() {
			continue
		}
		delivered++
		if o.Obs.Status >= 200 && o.Obs.Status < 300 {
			answered++
		}
		if !seen[o.Obs.Status] {
			seen[o.Obs.Status] = true
			statuses = append(statuses, strconv.Itoa(o.Obs.Status))
		}
	}
	if answered > 0 {
		return "", false
	}
	sort.Strings(statuses)
	why := "no_polluting_probe_was_answered: " + pxCount(delivered, "of this class's polluting payloads") +
		" came back and not one of them carried a 2xx"
	if len(statuses) > 0 {
		why += " (statuses seen: " + strings.Join(statuses, ", ") + ")"
	}
	return why + ". THE EFFECT THIS CLASS READS ONLY EXISTS ONCE A MERGE HAS RUN: the indent is a " +
		"global setting of the receiving process, read back through the JSON serializer. A response " +
		"that is not a 2xx is not evidence that this endpoint carried the request out, and this " +
		"witness does not establish that it did, so the absent indent is a fact about the responses " +
		"we got and not about whether a merge sink behind this pointer would have walked __proto__. " +
		"This is not the reflection classes' reading, where a rendered error page is still something " +
		"to search", true
}

func ppsRungName(id triage.ProbeID) string {
	if id == ppsJ2 {
		return "constructor.prototype (the merge refused the literal __proto__ key and took this one)"
	}
	return "__proto__ (the literal key)"
}

func ppsControlsRan(honest []faOwnObs) bool {
	for _, id := range []triage.ProbeID{ppsNC1, ppsNC2} {
		if _, ok := faFind(honest, id); !ok {
			return false
		}
	}
	return true
}

func ppsWhyAControlFiring(id triage.ProbeID) string {
	if id == ppsNC2 {
		return "PPS-NC2 sends the answer inside an ordinary string value, so a detector that fires on it " +
			"is matching an ECHO rather than an indent: the re-serialised newline should be the two bytes " +
			"backslash-n and the raw 0x0A anchor should have failed."
	}
	return "PPS-NC1 pollutes an ORDINARY KEY rather than the prototype, so a detector that fires on it is " +
		"firing on 'we sent a nested object' rather than on the effect."
}

// ppsNothingSent maps "this class has no observations" onto the right unknown. The first case is
// the usual one and it is not a failure: this class is off unless the operator bought it.
func ppsNothingSent(ctx triage.ClassifyCtx, ctl ppsControls) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctl.RouteResolved:
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"control to read the oracle against and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain, so every probe would " +
				"have measured the same validation failure", "", triage.GradeUnrated, nil
	}

	// BOTH REMAINING ARMS ARE not_run, AND THE OLD ORDER MADE THE SECOND ONE UNREACHABLE ON EVERY
	// CAPPED RUN. The budget arm was read first, at classify time, and it claimed the cap was
	// reached "before this class could send a POLLUTE and its RESTORE together", which is a claim
	// about what the planner was shown and not about anything this function measured. Below it
	// sat opt_in_not_purchased, which is the ORDINARY reason this class sends nothing: every
	// probe it owns is declared at the opt_in tier. So on a capped run the commonest and most
	// actionable answer in the class was replaced by "raise the cap", which would not have
	// changed the row. pxbudgetarm.go has the measurement behind that.
	//
	// THE TWO ARE NOT SEPARABLE FROM HERE, so this names both rather than choosing one. The tier
	// the operator bought is not on ClassifyCtx either.
	optIn := "every probe in this class is declared at the opt_in tier and the runner refuses those " +
		"unless the operator names that tier for this class, because this is the one class in the layer " +
		"that CHANGES STATE OTHER USERS SEE (it writes to Object.prototype and restores it). Nothing was " +
		"sent, nothing is known, and nothing was changed. The other reasons a batch is skipped are a " +
		"per-slot budget too small to hold a pollute and its restore, and a body slot that carries no " +
		"JSON node"
	if ctx.Budget.Exhausted() {
		return triage.StateNotRun,
			"opt_in_not_purchased_or_probe_budget_exhausted: nothing was sent, and this row cannot tell " +
				"which of two facts stopped it, so it states both rather than picking the one that reads " +
				"like an instruction. THE ORDINARY ONE FIRST: " + optIn + ". AND THE SECOND: " +
				pxBudgetArmReason("a POLLUTE and the RESTORE that must accompany it"),
			"", triage.GradeUnrated, nil
	}
	return triage.StateNotRun, "opt_in_not_purchased: " + optIn, "", triage.GradeUnrated, nil
}

// ppsLabel is the tool pointer, and the wrong pointer here would be worse than none.
func ppsLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"tool": "none (manual) among this framework's containers. pphack, which the misc section runs, is " +
			"a CLIENT-side prototype pollution scanner (ComposePphack builds -u <url> -j against a GET " +
			"vector) and cannot see a server-side merge. Pointing an operator at it would send them to a " +
			"tool that comes back empty and reads as a refutation",
		"real_pointer": "Burp with PortSwigger's server-side-prototype-pollution extension, which the " +
			"framework can reach through populate_burp, plus the gadget list at " +
			"yuske/server-side-prototype-pollution",
		"next": "the gadget found here is cosmetic. What matters is the MERGE: the same pointer reaches " +
			"status, parameterLimit, exposedHeaders and, on a process that spawns children, shell. Those " +
			"are all refused by this layer on the non-destructive rule and they are what the report is about",
	}
	if r, ok := ann["restore"].(string); ok {
		hints["restore"] = r
	}
	return triage.TriageLabel{Engine: "express", Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// THE EXTENSION SURFACE
// ---------------------------------------------------------------------------------------------

func (ppServerClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name:   "restore_verified_byte_identical",
			Probes: []triage.ProbeID{ppsR1, ppsR2},
			Rule: "the restoring probe's own response and the unperturbed post-baseline must both come " +
				"back free of the indent. A restore that cannot be verified is reported on the verdict as " +
				"failed or unverified and is put AHEAD of the finding in the reason, because a target left " +
				"changed outranks a bug already found",
		},
		{
			Name:   "controls_after_the_restore",
			Probes: []triage.ProbeID{ppsNC1, ppsNC2},
			Rule: "both controls must be sent while the process is NOT polluted, which is why they are " +
				"planned in a later round than the pollute/restore pair rather than alongside it. A " +
				"control measured in a polluted process reads as a hit; the harvest's own first run did " +
				"exactly that",
		},
	}
}

func (ppServerClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "indent_positions", Kind: "differential",
			What: "how many separate places in the response body the indent token appeared between a raw " +
				"newline and a structural byte"},
		{Name: "rung", Kind: "annotation",
			What: "whether the merge took the literal __proto__ key or constructor.prototype, which is what " +
				"a fix has to block"},
		{Name: "restore", Kind: "annotation",
			What: "verified, unverified or failed, plus the residue note that the own property stays on " +
				"Object.prototype at 0"},
		{Name: "attribution", Kind: "annotation",
			What: "that the effect carries the RUN's ten-byte token and not the probe's, and what would " +
				"make it probe-attributable"},
	}
}

func (ppServerClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "express_merge_takes_proto", Route: "/pp/express", Expect: faExpectPositive,
			Probes: []triage.ProbeID{ppsJ1, ppsR1}, WantState: triage.StateFinding, Exists: false,
			Why: "an Express-shaped route that recursively merges the posted object into a config and then " +
				"answers with res.json. It must indent with the token, and PPS-R1 must make the next " +
				"response byte-identical to the unpolluted one. The route MUST reset its own prototype " +
				"between test runs or every later case in this list reads as a hit",
		},
		{
			Name: "merge_blocks_proto_but_not_constructor", Route: "/pp/ctoronly", Expect: faExpectPositive,
			Probes: []triage.ProbeID{ppsJ2, ppsR2}, WantState: triage.StateFinding, Exists: false,
			Why: "the same route with the literal __proto__ key filtered out. PPS-J1 must stay silent and " +
				"the ladder must then spend two more requests on the constructor rung and find it",
		},
		{
			Name: "frozen_prototype", Route: "/pp/frozen", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ppsJ1}, WantState: triage.StateClean, Exists: false,
			Why: "Object.freeze(Object.prototype) before the merge. The pollution silently fails, the JSON " +
				"comes back compact, and clean is the correct answer: the merge is there and the gadget " +
				"cannot land. It is the route that proves a silence here is the application's answer",
		},
		{
			Name: "no_json_response", Route: "/pp/htmlonly", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ppsJ1}, WantState: triage.StateCannotDetermine, Exists: false,
			Why: "a route that merges the object and answers with HTML. The oracle is unreadable there and " +
				"the class must say so rather than report clean. This is the case that separates 'the " +
				"probe did nothing' from 'the probe could not be read'",
		},
		{
			Name: "echo_of_the_payload", Route: "/clean/echo", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ppsNC2}, WantState: triage.StateClean, Exists: true,
			Why: "an endpoint that echoes the body back. PPS-NC2 carries the exact shape the detector looks " +
				"for inside a string value, and the re-escaped newline must keep the detector silent",
		},
		{
			Name: "restore_left_it_polluted", Route: "/pp/norestore", Expect: faExpectPositive,
			Probes: []triage.ProbeID{ppsJ1, ppsR1}, WantState: triage.StateFinding, Exists: false,
			Why: "a route that accepts the pollution and IGNORES the restoring value. The verdict must still " +
				"be the finding and its reason must LEAD with the unrestored state. Without this route, " +
				"'we changed the target and could not change it back' is a code path nobody has ever seen run",
		},
	}
}
