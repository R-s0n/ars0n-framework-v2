package triageclasses

import (
	"net/url"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS HPP (id 26). HTTP PARAMETER POLLUTION: the same parameter arrives twice with two
// distinguishable values, and the question is which one the application used.
//
// THE ORACLE NEEDS NO REFLECTION AND THAT IS WHY THIS CLASS IS WORTH BUILDING ON A JSON API. It is
// a PRECEDENCE differential, not an echo: send the first occurrence as A, send it again as B, and
// if the two responses differ then the application reads the FIRST occurrence. Rename the first
// occurrence away and if the response changes then the first occurrence was load-bearing. Neither
// question asks the application to print anything back.
//
// AND THE INTERESTING CASE IS A DISAGREEMENT, NOT A VALUE. A WAF that inspects the last occurrence
// in front of an application that reads the first is a filter bypass with no payload in it at all.
// This class cannot see the component in front, so it measures the half it can see, records the
// precedence, and says in the verdict that the impact needs a second component that disagrees. It
// does not claim a bypass it has not observed.
//
// =================================================================================================
// THE DELIVERY PROBLEM, MEASURED, AND IT SHAPES THE WHOLE CLASS
// =================================================================================================
// THIS RUNNER CANNOT PUT THE SAME QUERY PARAMETER ON THE WIRE TWICE ON DEMAND. That is not a
// suspicion, it is what the encoder does, read at utils/triageEncode.go:
//
//	triageEncodeQuery     -> triageReplacePair(query, name, wire, false), and the value goes
//	                         through triageEscapeQueryValue, which is url.QueryEscape, so a '&' in
//	                         a payload becomes %26 and a '=' becomes %3D. One parameter goes out.
//	triageEncodeForm      -> the same function over the body. Same escaping, same result.
//	triageEncodeNameSlot  -> QueryEscape over the NAME as well, so a name carrying a separator is
//	                         escaped too.
//	EncodeLiteralPct      -> passes '%' through raw and escapes everything else, the ampersand
//	                         included, because "an unescaped ampersand would split the parameter
//	                         and test a different string" is written into that function.
//	triageEncodeCookie    -> writes the value RAW, so a ';' DOES create a second cookie. But the
//	                         second cookie's NAME has to be spelled in the payload bytes, and a
//	                         ProbeSpec's Logical is static: the runner substitutes the marker for
//	                         every class and then only the dollar-brace and angle-bracket grammars,
//	                         and triageUsesDollarTokens and triageUsesAngleTokens both name closed
//	                         lists of five classes that do not include this one. There is no
//	                         slot-name token, so the second cookie cannot be given the slot's name.
//	triagePlaceProbe      -> implements exactly one placement, filter_root_sibling, and refuses
//	                         every other by name rather than downgrading it.
//
// So there is no path from a ProbeSpec to "?q=A&q=B" for an arbitrary q. THE FIX IS SMALL AND IT
// IS NOT IN THIS FILE: a second placement in triagePlaceProbe, "duplicate_param", that appends
// name=value beside the slot instead of replacing it, exactly as filter_root_sibling seeds a
// sibling member into a JSON document instead of replacing a node. About thirty lines in
// utils/triageRun.go and utils/triageEncode.go, and this class's arm D becomes general. It is
// reported rather than worked around, because a class that quietly tested something else and
// called it HPP would be the failure this layer exists to stop.
//
// =================================================================================================
// WHAT IS SHIPPED, AND IT IS TWO ARMS THAT DO WORK RATHER THAN ONE THAT PRETENDS TO
// =================================================================================================
//
// ARM D, TRUE DUPLICATION, ON THE SLOTS WHERE THE RUNNER CAN ALREADY DELIVER IT. Where the CAPTURE
// ITSELF already carries the parameter more than once, triageReplacePair perturbs the FIRST
// occurrence and leaves the rest untouched, and reports that it did through its duplicate flag.
// That is a real polluted request with two distinguishable values, and the precedence oracle runs
// on it unchanged. Whether it applies is decided from ctx.Vector.ComposedURL at ZERO REQUEST COST,
// so a slot it does not apply to is not_applicable with the count in the reason, never a clean.
//
// ARM S, SEPARATOR INJECTION, ON EVERY VALUE SLOT. The payload carries a raw ampersand or a raw
// semicolon between two halves. The front door sees ONE parameter whose decoded value contains a
// separator; any component that RE-PARSES that value, a downstream service handed the string, a
// framework that splits on ';' as a legacy pair separator, a URL built by concatenation, sees TWO.
// The oracle is a differential against HPP-NC1, which is the SAME PAYLOAD WITH THE TWO SEPARATOR
// BYTES REPLACED BY HYPHENS: identical length, identical alphabet, identical marker placement.
// A response that differs between them differs because of two bytes that only a parser cares
// about. That is a protocol effect, it needs no echo, and it is the one arm that reaches every
// slot in the corpus.
//
// =================================================================================================
// WHAT THIS CLASS CANNOT SEE, SAID PLAINLY
// =================================================================================================
//
// CONCATENATION IS NOT DISTINGUISHABLE FROM PRECEDENCE WITHOUT AN ECHO. ASP.NET joins duplicate
// parameters with a comma and hands the application "A,B". From outside, an application reading
// "A,B" and one reading "A" both change their answer when A changes, so arm D reports first_wins
// for both and says in the reason that a concatenating stack is inside that answer. Separating
// them needs the application to print the value, which is the one thing the target shape this
// class was built for does not do.
//
// THE COMPONENT IN FRONT IS INVISIBLE. The valuable HPP finding is a WAF or a proxy disagreeing
// with the application about which occurrence counts. This class measures the application's end
// only. It records the precedence and states the condition; it never claims the bypass.
//
// WHICH PARAMETER A RE-PARSE PICKED UP IS UNPROVEN IN BAND. Arm S shows that the separators
// changed the answer. It does not show that a parameter named hppdup arrived anywhere, because
// nothing echoes it back. The verdict is suspicious rather than a finding for exactly that reason,
// and the reason says so rather than implying an injected parameter was observed.
type hppClassifier struct{}

func init() { triage.RegisterClassifier(hppClassifier{}) }

func (hppClassifier) ID() triage.ClassID { return triage.ClassHPP }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	hppD1  triage.ProbeID = "HPP-D1"
	hppD2  triage.ProbeID = "HPP-D2"
	hppD3  triage.ProbeID = "HPP-D3"
	hppS1  triage.ProbeID = "HPP-S1"
	hppS2  triage.ProbeID = "HPP-S2"
	hppNC1 triage.ProbeID = "HPP-NC1"
)

// hppInjectedName is the parameter arm S asks a second parser to see. It is ours, it is not a
// name any application uses, and it carries no meaning to anything that does not re-parse.
const hppInjectedName = "hppdup"

var hppValuePoints = []triage.SlotKind{
	triage.KindQuery, triage.KindBody, triage.KindCookie, triage.KindHeader,
}

var hppValueEncoders = []triage.EncoderMode{
	triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
	triage.EncodeCookie, triage.EncodeHeaderValue,
}

func (hppClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassHPP
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: hppD1, Class: c, Logical: []byte("hppone" + m),
			Encoders: []triage.EncoderMode{triage.EncodeQuery, triage.EncodeForm},
			Points:   []triage.SlotKind{triage.KindQuery, triage.KindBody},
			Tier:     triage.TierReduced, Risk: triage.RiskR0,
			Notes: "ARM D, FIRST VALUE. Sent only where the CAPTURE already carries this parameter more " +
				"than once, because that is the one situation in which this runner puts the same name on " +
				"the wire twice: triageReplacePair perturbs the FIRST occurrence and leaves the rest " +
				"alone. The payload itself is inert, which is the point: this arm measures PRECEDENCE, " +
				"not what a value does, so the two halves of the pair must differ from each other and " +
				"from nothing else",
		},
		{
			ID: hppD2, Class: c, Logical: []byte("hpptwo" + m),
			Encoders: []triage.EncoderMode{triage.EncodeQuery, triage.EncodeForm},
			Points:   []triage.SlotKind{triage.KindQuery, triage.KindBody},
			Tier:     triage.TierReduced, Risk: triage.RiskR0,
			Notes: "ARM D, SECOND FIRST-VALUE, and it is not a spelling of D1. The precedence question is " +
				"'does changing the FIRST occurrence change the answer', and one probe cannot ask it: " +
				"D1 against the route control also changes whether the value is the ORIGINAL one, so a " +
				"difference there could be the application reacting to an unfamiliar value rather than to " +
				"the position. D1 against D2 holds position, arity and shape fixed and varies only the " +
				"bytes of the first occurrence. That is the differential the verdict is built on",
		},
		{
			ID: hppD3, Class: c, Logical: []byte("hppgone" + m),
			Encoders: []triage.EncoderMode{triage.EncodeNameSlot},
			Points:   []triage.SlotKind{triage.KindQuery, triage.KindBody},
			Tier:     triage.TierFull, Risk: triage.RiskR0,
			Notes: "ARM D, REMOVAL, and it perturbs the NAME rather than the value. triageEncodeNameSlot " +
				"renames the FIRST occurrence, which deletes it from the application's view of this " +
				"parameter and leaves the second occurrence as the only one. It answers the question D1 " +
				"and D2 together cannot: if changing the first value does nothing but REMOVING the first " +
				"occurrence does something, then the first occurrence is not supplying the value and is " +
				"still being counted, which is a concatenating or arity-checking stack. Full tier: it is " +
				"the third request on an arm that already has an answer from two",
		},
		{
			ID: hppS1, Class: c, Logical: []byte("hppa" + m + "&" + hppInjectedName + "=hppb" + m),
			Encoders: hppValueEncoders, Points: hppValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "ARM S, AMPERSAND. MEASURED: url.QueryEscape turns the '&' into %26 and the '=' into " +
				"%3D, so the front door parses ONE parameter and the application receives a value with a " +
				"literal ampersand in it. Any component that re-parses that string sees two parameters, " +
				"and the classic sink is an application splicing the value into a URL it then requests. " +
				"In a COOKIE or a HEADER slot the bytes go out raw, because neither encoder escapes, so " +
				"the same payload is a genuine second pair on the wire there. Its oracle is entirely a " +
				"differential against HPP-NC1 and never a search of the body",
		},
		{
			ID: hppS2, Class: c, Logical: []byte("hppa" + m + ";" + hppInjectedName + "=hppb" + m),
			Encoders: hppValueEncoders, Points: hppValuePoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "ARM S, SEMICOLON, and it is a separate probe because the two are filtered and parsed " +
				"separately. The semicolon was a legal pair separator in the original CGI specification " +
				"and a long tail of stacks still split on it, PHP's parse_str family and older Java " +
				"servlet containers among them, while every WAF rule written for parameter pollution " +
				"looks for the ampersand. IN A COOKIE SLOT IT IS NOT A SECOND-PARSE PROBE AT ALL: the " +
				"cookie encoder writes raw and a semicolon is the Cookie header's own separator, so this " +
				"payload puts a genuine second cookie on the wire. That is why the wire-honesty check in " +
				"this class accepts the encoder's RFC 6265 altered flag for this one probe on that one " +
				"container, and refuses it everywhere else",
		},
		{
			ID: hppNC1, Class: c, Logical: []byte("hppa" + m + "-" + hppInjectedName + "-hppb" + m),
			Encoders: hppValueEncoders, Points: hppValuePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE CONTROL, AND ARM S IS NOTHING WITHOUT IT. It is HPP-S1 with the ampersand and the " +
				"equals sign replaced by hyphens: the SAME LENGTH, the same alphabet, the same two marker " +
				"copies in the same two places. The only difference is two bytes that mean something to a " +
				"parser and nothing to anything else. Without it, 'the response changed when we sent a " +
				"separator' has a second reading, which is that the response changes whenever the value " +
				"changes, and that reading is true of a very large fraction of endpoints. With it, a " +
				"difference between S1 and NC1 is attributable to the separator and to nothing else. A " +
				"HIT ON THIS PROBE IS IMPOSSIBLE BY CONSTRUCTION: it has no oracle of its own, it is only " +
				"ever the right-hand side of a comparison",
		},
	}
}

func hppAllProbeIDs() []triage.ProbeID {
	return []triage.ProbeID{hppD1, hppD2, hppD3, hppS1, hppS2, hppNC1}
}

// hppSeparatorProbes is arm S's payload set, and hppDuplicateProbes is arm D's. They are functions
// rather than package variables so a caller cannot mutate the ladder of a running class.
func hppSeparatorProbes() []triage.ProbeID { return []triage.ProbeID{hppS1, hppS2, hppNC1} }

func hppDuplicateProbes() []triage.ProbeID { return []triage.ProbeID{hppD1, hppD2, hppD3} }

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

func (hppClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "ARM S ALWAYS, ARM D ONLY WHERE THE CAPTURE ALREADY DUPLICATES THE PARAMETER. MEASURED " +
				"at this layer's own encoder: triageEscapeQueryValue is url.QueryEscape, so a '&' in a " +
				"payload leaves as %26 and no probe can ask for a second copy of a name the capture did " +
				"not already carry. Where the capture DOES carry it twice, triageReplacePair perturbs the " +
				"first occurrence and leaves the rest, which is a real polluted request",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a urlencoded form field behaves exactly as a query value does and both arms apply to " +
				"it on the same conditions. A JSON body reaches ARM S ONLY: a JSON document has no " +
				"duplicate-key form this encoder can produce, because triageEncodeJSON sets the value at " +
				"a pointer and re-serializes, and a second member of the same name cannot survive a " +
				"decode and re-encode. Duplicate JSON keys are a real bug family and this class does not " +
				"reach them. Request media type seen: " + string(mt),
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "ARM S ONLY, and on this container it is not a second-parse probe but a real one: " +
				"triageEncodeCookie writes the value RAW, so the semicolon in HPP-S2 puts a genuine second " +
				"cookie on the wire. Its NAME is ours rather than this slot's, because a ProbeSpec's " +
				"payload is static and this layer offers no slot-name substitution token to a class " +
				"outside the five that own the dollar and angle grammars, so true same-name cookie " +
				"duplication is out of reach and is not claimed",
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "ARM S ONLY. triageEncodeHeader writes field-vchar raw, so both separators reach the " +
				"server unescaped, and a header whose value a framework splits into pairs, which is what " +
				"every forwarded-for and every custom routing header does, is exactly the second parser " +
				"this arm is looking for. A second header LINE of the same name is not reachable: " +
				"RequestTemplate.SetHeader replaces the first entry with this name in place and appends " +
				"only when the name is absent, so one encode can never produce two lines",
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "a path segment is not a parameter list. MEASURED: triagePathUnreserved passes '&' and " +
				"'=' through RAW, so the bytes would arrive intact, and they would still be part of one " +
				"segment rather than a second pair. A stack that turns a path segment into parameters is " +
				"doing matrix parameters or a route rewrite, which are different mechanisms with " +
				"different oracles",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment is never transmitted, so no server-side parser ever sees it",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "slot kind " + string(k) + " is not in the model this class was written against",
		}
	}
}

// ---------------------------------------------------------------------------------------------
// ARM D ELIGIBILITY, AT ZERO REQUEST COST
// ---------------------------------------------------------------------------------------------

// hppCapturedOccurrences counts how many times this slot's parameter name appears in the captured
// request target.
//
// IT IS THE WHOLE OF ARM D'S ELIGIBILITY AND IT COSTS NOTHING. ctx.Vector.ComposedURL is the
// captured URL, it is already in PlanCtx, and parsing it is the difference between planning three
// requests that measure precedence and planning three that measure nothing at all.
//
// The name comparison is on the DECODED name, because triageReplacePair decodes before comparing
// and a class whose eligibility disagreed with the encoder's matching would plan arm D on slots
// where the encoder then found one occurrence and perturbed it as an ordinary value.
func hppCapturedOccurrences(composed, name string) int {
	if name == "" {
		return 0
	}
	u, err := url.Parse(composed)
	if err != nil {
		return 0
	}
	q := u.RawQuery
	if q == "" {
		return 0
	}
	n := 0
	for _, p := range strings.Split(q, "&") {
		raw := p
		if eq := strings.Index(p, "="); eq >= 0 {
			raw = p[:eq]
		}
		dec := raw
		if d, err := url.QueryUnescape(raw); err == nil {
			dec = d
		}
		if dec == name {
			n++
		}
	}
	return n
}

// hppArmDApplies reports whether true duplication is deliverable on this slot, and why not when
// it is not.
func hppArmDApplies(slot triage.Slot, composed string) (int, string, bool) {
	if slot.Kind != triage.KindQuery && slot.Kind != triage.KindBody {
		return 0, "arm D needs a pair list this runner can perturb one occurrence of, which is a query " +
			"string or a urlencoded form body. This slot is a " + string(slot.Kind) + " slot", false
	}
	if slot.Kind == triage.KindBody && slot.BodyMedia != triage.BodyForm {
		return 0, "arm D needs a urlencoded form body. This body is " + string(slot.BodyMedia) +
			", and a JSON document has no duplicate-key form triageEncodeJSON can produce: it sets the " +
			"value at a pointer and re-serializes, so a second member of the same name cannot survive", false
	}
	n := hppCapturedOccurrences(composed, slot.Name)
	if n < 2 {
		return n, "duplication_not_deliverable: the capture carries this parameter " + pxCount(n, "time(s)") +
			", and this runner cannot add a second occurrence. MEASURED: triageEscapeQueryValue is " +
			"url.QueryEscape, so an '&' in a payload leaves as %26; triageEncodeNameSlot escapes the name " +
			"the same way; and triagePlaceProbe implements one placement, filter_root_sibling, and " +
			"refuses every other by name. A duplicate_param placement beside it would make this arm " +
			"general and is about thirty lines in files this class does not own. ARM S IS STILL SENT " +
			"HERE and this row is about arm D alone", false
	}
	return n, "", true
}

// ---------------------------------------------------------------------------------------------
// PLAN
// ---------------------------------------------------------------------------------------------

// hppRound0For is round 0, lifted out of Plan so the nothing-sent ladder can ask THE PLANNER what
// this class derives for a slot instead of asserting an answer on its behalf.
//
// Arm S's pair goes out first and unconditionally: the control is half the measurement, so
// sending it only after a hit would be sending it only where it is not needed. Arm D's two
// precedence probes ride along when the capture can carry them, because they are the stronger arm
// and waiting a round buys nothing.
func hppRound0For(slot triage.Slot, composedURL string) []triage.ProbeID {
	ids := []triage.ProbeID{hppS1, hppNC1}
	if _, _, ok := hppArmDApplies(slot, composedURL); ok {
		ids = append(ids, hppD1, hppD2)
	}
	return ids
}

func (c hppClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType).Reach == triage.ReachNever {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() || ctx.Budget.Exhausted() {
		return nil
	}

	var ids []triage.ProbeID
	switch ctx.Round {
	case 0:
		// Arm S's pair goes out first and unconditionally: the control is half the measurement,
		// so sending it only after a hit would be sending it only where it is not needed. Arm D's
		// two precedence probes ride along when the capture can carry them, because they are the
		// stronger arm and waiting a round buys nothing.
		ids = hppRound0For(ctx.Slot, ctx.Vector.ComposedURL)
	case 1:
		ids = []triage.ProbeID{hppS2}
		if _, _, ok := hppArmDApplies(ctx.Slot, ctx.Vector.ComposedURL); ok {
			ids = append(ids, hppD3)
		}
	default:
		return nil
	}

	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		if id == hppD3 {
			// THE NAME-SLOT ENCODER IS NAMED EXPLICITLY rather than left to the runner's
			// first-fit, because D3's whole question is what happens when the first occurrence's
			// NAME changes. A slot that cannot take EncodeNameSlot refuses THIS request with a
			// reason on the coverage row, which is the right outcome: a probe silently sent as an
			// ordinary value perturbation would be D1 again under another id, and the precedence
			// logic would then read two copies of the same measurement as two measurements.
			out = append(out, pxReqWithEncoder(id, ctx.Slot.Key, triage.EncodeNameSlot))
			continue
		}
		out = append(out, pxReq(id, ctx.Slot.Key))
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// WIRE HONESTY, WITH ONE NARROW EXCEPTION THAT IS WRITTEN DOWN RATHER THAN HIDDEN
// ---------------------------------------------------------------------------------------------

// hppHonest is pxHonest with one probe on one container exempted, and the exemption is the whole
// mechanism of that probe rather than a convenience.
//
// triageEncodeCookie flags any payload containing a semicolon as WireSurvivalAltered, with the
// reason "RFC 6265 cookie parsing splits the value at the semicolon, so the application reads a
// shorter value than the bytes sent". faWireIsHonest then refuses it, and correctly so for every
// other class in this package: a payload the far side truncates is a payload that tested a
// shorter string than the one planned, and no clean may be drawn from it.
//
// FOR HPP-S2 ON A COOKIE SLOT THAT SPLIT IS THE POINT. The class is asking whether a second pair
// appears, the semicolon is what makes one appear, and the encoder's note is a description of the
// probe working rather than of it failing. Refusing it would mean this class never tested the one
// container in this layer where a raw separator reaches the server unescaped, and recorded that
// silence as coverage.
//
// The exemption is as narrow as it can be made: this probe, this alteration reason, and nothing
// else. Every other altered, dropped, refused or unrecorded payload is skipped exactly as
// pxHonest skips it, and the exempted probe carries cookie_split_is_the_mechanism on the verdict
// so nobody reads the row as an ordinary intact delivery.
func hppHonest(own []faOwnObs) (honest []faOwnObs, exempted []triage.ProbeID, skips []triage.ProbeSkip) {
	for _, o := range own {
		why, ok := pxWireIsHonest(o.Obs)
		if ok {
			honest = append(honest, o)
			continue
		}
		if o.ProbeID == hppS2 &&
			o.Obs.Payload.Survived == triage.WireSurvivalAltered &&
			strings.Contains(strings.ToLower(o.Obs.Payload.AlteredBy), "rfc 6265") &&
			o.Obs.Delivered() {
			honest = append(honest, o)
			exempted = append(exempted, o.ProbeID)
			continue
		}
		skips = append(skips, triage.ProbeSkip{ProbeID: o.ProbeID, Reason: why})
	}
	return honest, exempted, skips
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

func (c hppClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHPP, key, state, reason, oracle, grade, ords, ann, hppLabel(ann))
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}

	occurrences, armDWhy, armD := hppArmDApplies(ctx.Slot, ctx.Vector.ComposedURL)
	ann["captured_occurrences"] = occurrences
	ann["arm_d_true_duplication"] = armD
	if !armD {
		ann["arm_d_not_available"] = armDWhy
	}
	ann["concatenation_not_distinguishable"] = "a stack that JOINS duplicate parameters, as ASP.NET does " +
		"with a comma, and one that takes the first both change their answer when the first value changes. " +
		"Separating them needs the application to print the value back, which is the one thing the target " +
		"shape this class was built for does not do. A first_wins verdict has a concatenating stack inside it"
	ann["component_in_front_not_measured"] = "the valuable HPP finding is a filter in front reading one " +
		"occurrence while the application reads another. This class can only see the application's end, so " +
		"it records the precedence and names the condition; it never claims a bypass it has not observed"

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		return one(hppNothingSent(ctx))
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	honest, exempted, skips := hppHonest(own)
	planned := hppSeparatorProbes()
	if armD {
		planned = append(planned, hppDuplicateProbes()...)
	}
	skips = append(skips, pxNotObserved(planned, own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(exempted) > 0 {
		ann["cookie_split_is_the_mechanism"] = "the encoder flagged " + pxJoin(exempted) + " as altered " +
			"because RFC 6265 splits a cookie value at the semicolon. For this probe that split IS the " +
			"second pair it is testing for, so the row is counted rather than skipped, and it is annotated " +
			"here so nobody reads it as an ordinary intact delivery"
	}
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload was refused, altered or left unsubstituted, so no "+
				"separator and no second occurrence ever left this process",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	// A FILTER ANSWERING IS NOT THE APPLICATION ANSWERING, AND HERE IT COMES FIRST RATHER THAN
	// LAST, WHICH IS THE OPPOSITE OF CRLF'S ORDER AND IS CORRECT FOR THIS CLASS. CRLF puts the
	// guard last because its oracle is a header the application emitted, which a filter that never
	// reached the application cannot have produced, so the class's own evidence outranks the
	// guard. EVERY ORACLE IN THIS CLASS IS A BODY DIFFERENTIAL. A filter with one error page makes
	// every arm identical, which this class would read as "the separator changed nothing" and
	// "changing the first value changed nothing", and both of those are conclusions about an
	// application no request reached.
	if pxUniformBlock(ctx, honest) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical "+
				"non-baseline responses, so a filter answered and no parameter parser was reached. It is "+
				"asked BEFORE the arms rather than after them because every oracle in this class is a body "+
				"differential, and a uniform block page makes every differential read zero, which this "+
				"class would otherwise report as a measured negative",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// ARM D, THE STRONGER ONE, FIRST.
	control, haveControl := pxRouteControl(ctx)
	if armD {
		if v, ok := hppPrecedence(control, haveControl, honest, ann, ords, skips, one, occurrences); ok {
			return v
		}
	}

	// ARM S.
	sv, fired, tally := hppSeparatorEffect(honest, ann, ords, skips, one)
	if fired {
		return sv
	}

	return hppNegative(honest, control, haveControl, tally, armD, armDWhy, occurrences, ann, ords, skips, one)
}

// hppNegative is every exit this class has left once both arms have declined to fire, and it is a
// function rather than the tail of Classify FOR ONE REASON: a ClassifyCtx cannot be built outside
// the triage package, so anything decided inside Classify can only ever be exercised by running
// the whole runner against a live target. ormDecide is split for the same reason and says so.
// Four of the five exits below are refusals that were added because they were MEASURED missing,
// and a refusal no unit test can reach is a refusal nobody will notice deleting.
func hppNegative(honest []faOwnObs, control triage.Observation, haveControl bool, tally hppArmSTally,
	armD bool, armDWhy string, occurrences int, ann map[string]any, ords []uint64,
	skips []triage.ProbeSkip,
	one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict) []triage.ClassVerdict {

	// =============================================================================================
	// WHICH ARM IS CARRYING THIS NEGATIVE, ASKED FIRST, BECAUSE THE TWO NEED DIFFERENT EVIDENCE
	// =============================================================================================
	//
	// THE SHIPPED CLEAN SAID "the application answered the separator forms exactly as it answered
	// the length-matched control". MEASURED ON THE ORACLE over 80 routes, that sentence was FALSE
	// on four of them and in two different ways:
	//
	//	/clean/empty204   204 and no body to anything. The separator forms and the control were
	//	/clean/nothing    200 and no body to anything. never compared: there was nothing to
	//	                  compare, and "no difference" was guaranteed a priori.
	//	/clean/always500  one identical 500 page for every input INCLUDING the benign control, so
	//	                  the comparison ran and could only ever have come back same.
	//	/clean/echo       a text/plain body with no tags and no JSON, so hppStructuralChange
	//	                  measured NONE of its three properties and returned faCmpDegraded twice.
	//	                  Its own doc comment ends "Not knowing is not clean, one layer down", and
	//	                  one layer up the class turned exactly that into a clean.
	//
	// THE FIX IS NOT A BLANKET ROUTE-SENSITIVITY WITNESS, AND MEASURING IT IS WHAT SHOWED THAT.
	// A first cut refused every clean where nothing this class sent moved the endpoint, which is
	// NOSQL's value_insensitive and TRAVERSAL's value_insensitive under a third name. It would
	// also have deleted /hpp/last, the one route in the corpus built to be arm D's negative: that
	// route reads the LAST occurrence, every probe this class has perturbs the FIRST, so nothing
	// it sends can move that endpoint BY CONSTRUCTION, and "nothing moved it" is arm D's ANSWER
	// rather than arm D's failure.
	//
	// So the question is which arm the negative rests on:
	//
	//	ARM D, COMPLETED     its oracle is not "does this endpoint vary" but "does the FIRST
	//	                     occurrence matter". D1 against D2 holds position and arity fixed and
	//	                     varies only the first occurrence's bytes; D3 renames that occurrence
	//	                     away and is held against the unperturbed control. When BOTH of those
	//	                     comparisons came back faCmpSame, which is a comparison that was made,
	//	                     the null is the measurement and this class may say so. faCmpSame and
	//	                     not "not different": faCmpNoBody and faCmpDegraded are comparisons
	//	                     that could not be made, and they are exactly what /clean/empty204
	//	                     would hand this arm if the capture there duplicated its parameter.
	//	ARM S ALONE          its oracle is a DIFFERENCE between two of its own responses, so it
	//	                     needs the endpoint to be capable of answering differently at all, it
	//	                     needs its own length-matched control back, and it needs at least one
	//	                     of the three structural properties to have been measurable. None of
	//	                     those three was checked before.
	armDCompleted := armD && hppArmDCompleted(honest, control, haveControl)
	ann["evidence_surface"] = string(pxReadsDifference)
	ann["arm_d_completed_with_usable_comparisons"] = armDCompleted
	sens := pxRouteSensitivity(honest, control, haveControl)
	ann["probes_that_moved_the_endpoint"] = sens.Moved
	ann["probes_matching_the_route_control"] = sens.Flat
	ann["probes_not_comparable_to_the_route_control"] = sens.Unknown
	ann["probes_that_moved_a_response_header"] = sens.HeaderMoved
	if len(sens.HeaderNames) > 0 {
		ann["response_headers_that_differed_from_the_route_control"] = sens.HeaderNames
	}

	if !armDCompleted {
		// (1) IS THERE A DIFFERENTIAL SURFACE AT ALL? On an endpoint that answers identically to
		// everything, a zero difference is arithmetic and not a measurement. This is the shared
		// precondition, and the witness already existed in the layer under another name.
		if why, absent := pxNoEvidenceToRead(pxReadsDifference, honest, control, haveControl); absent {
			v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}

		// (1b) AND IF THE WITNESS DID NOT MEASURE, DID IT SAY SO? THIS IS THE HOLE (1) LEFT AND
		// THE CLEAN WALKED STRAIGHT THROUGH IT.
		//
		// pxDifferentialSurfaceUnavailable declines only when Moved == 0 AND Flat >= 2. The floor
		// of two is correct and is argued for where it is declared: one probe matching the
		// control is the accident an application with a single error page produces all day, so
		// one flat probe is not the finding "this endpoint never varies". But declining to make
		// THAT finding is not the same as finding the opposite, and the code below read it as
		// exactly that. Moved == 0 with Flat == 1 and Unknown == 2 fell through this gate and
		// reached a clean whose own precondition line read "THIS ENDPOINT IS NOT INSENSITIVE TO
		// THIS SLOT: 0 of its 3 delivered probes came back distinguishable ... so it does answer
		// differently to something". Zero of three, therefore it does: the sentence asserted the
		// negation of the number standing next to it. 82 rows carrying it are in the test
		// database.
		//
		// SO THE CLEAN NOW NEEDS THE POSITIVE READING AND NOT MERELY THE ABSENCE OF THE NEGATIVE
		// ONE. Arm S's oracle is a difference between two of this class's own responses; it is
		// worth something only on an endpoint that has been SHOWN to answer at least one thing
		// differently. Moved >= 1 is that showing. Moved == 0 below the floor is the witness
		// saying it could not tell, and not knowing is not clean.
		//
		// THE THREE WAYS OUT OF Moved == 0 ARE NOW EXHAUSTIVE AND EACH HAS ITS OWN ROW: arm D
		// completed carries the negative on its own evidence and never reaches here at all,
		// Flat >= 2 is route_insensitive above, and everything left is this row. Nothing with
		// Moved == 0 can reach the clean, which is what makes the precondition sentence below
		// true by construction rather than by hope.
		if sens.Moved == 0 {
			why := "route_sensitivity_unmeasured: the differential witness could not establish that this " +
				"endpoint answers ANYTHING differently, and it did not establish that it answers " +
				"everything the same either. " + pxCount(sens.Delivered, "of this class's probes") +
				" were delivered: " + strconv.Itoa(sens.Moved) + " moved the status or the normalised " +
				"body away from the unperturbed route control, " + strconv.Itoa(sens.Flat) +
				" matched it and " + strconv.Itoa(sens.Unknown) + " could not be compared with it at " +
				"all. Calling an endpoint insensitive needs " + strconv.Itoa(pxDifferentialWitnessFloor) +
				" probes that matched, because one match is the coincidence any application with a " +
				"single error page produces, so this is below the floor in both directions"
			if sens.HeaderMoved > 0 {
				why += ". " + pxCount(sens.HeaderMoved, "of the delivered probes") + " did come back with " +
					"a different value in a non-volatile response header (" + pxNameList(sens.HeaderNames) +
					"), which is not this class's channel: both of its arms read the status, the " +
					"value-free element skeleton and the JSON shape, and none of them reads a header"
			}
			why += ". ARM S ALONE IS CARRYING THIS SLOT AND ITS ORACLE IS A DIFFERENCE BETWEEN TWO OF " +
				"THIS CLASS'S OWN RESPONSES, so it is worth something only where something is known to " +
				"move this endpoint. Arm D did not carry a completed reading here, so nothing else " +
				"answered. WHAT WOULD SETTLE IT: the route control came back and was held against every " +
				"probe, so what is missing is comparable probes, which on this slot means responses " +
				"this layer can project rather than truncate; failing that, a capture that duplicates " +
				"this parameter, which lets arm D answer the question without this witness at all"
			v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}

		// (2) DID THE ARM'S OWN CONTROL COME BACK? Without HPP-NC1 there is no length-matched
		// right hand side, and "the separator changed nothing" has the second reading the control
		// exists to remove. This was annotated as arm_s_not_measured and then fell through.
		if !tally.HaveControl {
			v := one(triage.StateCannotDetermine,
				"arm_s_control_absent: "+string(hppNC1)+", which is "+string(hppS1)+" with the ampersand "+
					"and the equals sign replaced by hyphens, did not come back. It is the only right-hand "+
					"side this arm has: without it a difference could be the response moving with the VALUE "+
					"rather than with the separator, and a null result is a comparison that was never made. "+
					"Arm D did not carry a completed reading either, so nothing here answered",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}

		// (3) COULD THE COMPARISON BE MADE AT ALL? hppStructuralChange deliberately refuses a body
		// that is neither HTML nor JSON, because two empty element skeletons are not evidence of
		// sameness. That refusal is worth nothing if the caller reads it as silence.
		if tally.Compared == 0 {
			v := one(triage.StateCannotDetermine,
				"arm_s_not_comparable: "+pxCount(tally.Degraded, "separator payload(s)")+" came back and "+
					"NOT ONE of them could be compared with "+string(hppNC1)+" on any of this arm's three "+
					"properties. The statuses matched, the responses carry no element skeleton on either "+
					"side because the body is neither HTML nor a tagged document, and neither side parsed "+
					"as JSON, so there was no key set, type map or cardinality to difference. Comparing two "+
					"empty skeletons is not evidence of sameness, which is why hppStructuralChange returns "+
					"degraded rather than same, and a clean here would be that refusal laundered into a "+
					"result. WHAT WOULD SETTLE IT: this arm needs a response with structure in it, so a "+
					"re-parse that changes only a scalar's text on a plain-text endpoint is outside what "+
					"this class can see",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}

		// (3b) AND IF ONLY SOME OF IT COULD BE COMPARED? THE DECISION, MADE EXPLICITLY.
		//
		// (3) refuses only when NOTHING could be compared. One separator form compared and the
		// other degraded still produced a clean, with the prose saying so: "1 further separator
		// payload(s) could not be compared on any of the three properties and this clean does
		// not rest on them". A reader who gets that far learns the truth; the STATE they are
		// counting does not carry it, and the state is what an operator filters on.
		//
		// THE TWO FORMS ARE TWO QUESTIONS AND NOT TWO SAMPLES OF ONE. HPP-S1 asks whether an
		// ampersand re-parses and HPP-S2 asks whether a semicolon does, and the probes are split
		// exactly because the two are filtered and parsed by different stacks: a Java or ASP.NET
		// front end that splits on the semicolon and not the ampersand is the case HPP-S2 was
		// added for. A clean whose oracle is no_separator_effect, resting on arm S alone, with
		// the semicolon form delivered and never compared, is the semicolon question answered by
		// omission.
		//
		// ARM D IS THE EXCEPTION AND IT IS NOT AN EXEMPTION. A completed arm D put a genuinely
		// duplicated parameter on the wire and got the same answer whether the first occurrence
		// carried one value, another, or a different name. That is the pollution question
		// answered head on, by a different arm, with its own comparisons made; a separator form
		// this class could not project is then a footnote on it and is reported as one. This
		// branch is inside `if !armDCompleted` for that reason.
		//
		// A DELIVERED FORM THAT COULD NOT BE COMPARED AND A FORM THAT NEVER LEFT THE PROCESS ARE
		// NOT THE SAME THING, and only the first is refused here. A form the tier never bought
		// or the encoder refused is work that was not done, it is on Untested and on the coverage
		// row, and the operator who bought a reduced tier can see what a reduced tier costs. A
		// form that was sent, was answered, and came back unprojectable is work that WAS done and
		// produced nothing, which is invisible everywhere except in this tally.
		if tally.Degraded > 0 {
			v := one(triage.StateCannotDetermine,
				"arm_s_partially_comparable: "+pxCount(tally.Compared, "separator form(s)")+" were "+
					"differenced against "+string(hppNC1)+" and came back the same, and "+
					pxCount(tally.Degraded, "further form(s)")+" reached the wire, were answered, and "+
					"could not be compared with it on the status, the value-free element skeleton or the "+
					"JSON shape. "+string(hppS1)+" carries an ampersand and "+string(hppS2)+" carries a "+
					"semicolon BECAUSE THE TWO ARE PARSED BY DIFFERENT STACKS, so the form that could not "+
					"be compared is a question this slot has not answered rather than a duplicate sample "+
					"of the one that was. Arm D did not carry a completed reading here, so arm S is the "+
					"whole measurement and the whole measurement is partial. WHAT WOULD SETTLE IT: this "+
					"arm needs a response it can project on both sides, so either a document with an "+
					"element skeleton or a body that parses as JSON for the form that degraded",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}

	// THE NEGATIVE. Every sentence below is conditional on the arm that produced it, because the
	// two shipped false strings in this block were both an unconditional claim about an arm that
	// had not answered.
	precond := []string{
		"every probe counted here reached the wire with its bytes intact, reversibly encoded, or split " +
			"by the container's own parser in the way this class is measuring",
	}
	reason := "no_parameter_pollution_effect: this class sent " + pxCount(len(honest), "payloads")
	oracle := "no_separator_effect"

	if armDCompleted {
		// ARM D CARRIES IT. The old code reached this sentence on armD alone, and armD alone means
		// only that the arm was ELIGIBLE, which is read off the composed URL at zero request cost.
		// hppPrecedence returns not-fired for arm_d_incomplete and for arm_d_removal_not_measured
		// as well as for a completed reading, and the clean claimed a measurement on all three.
		oracle = "first_occurrence_is_ignored"
		precond = append(precond, "ARM D COMPLETED AND IT CARRIES THIS NEGATIVE: this parameter arrives "+
			pxCount(occurrences, "times")+" on the captured request, so a genuinely POLLUTED request went "+
			"out. "+string(hppD1)+" and "+string(hppD2)+" differ only in the bytes of the FIRST occurrence "+
			"and were answered the same, and "+string(hppD3)+" renamed that occurrence away and was "+
			"answered exactly as the unperturbed control was. BOTH comparisons were usable rather than two "+
			"empty bodies, which is the line between this and /clean/empty204")
		reason += ". THE STRONGER ARM ANSWERED: the capture already duplicates this parameter, so a real " +
			"polluted request went out, and neither changing the first occurrence's value nor renaming it " +
			"away made any difference. The application reads the last occurrence, or does not read this " +
			"parameter at all. NOTHING THIS CLASS SENDS PERTURBS A LATER OCCURRENCE, so this negative is " +
			"about the first one"
	} else {
		// ARM S ALONE, AND THE SENTENCE IS NOW GUARDED BY THE GATE ABOVE RATHER THAN BY HOPE.
		// Refusal (1b) returns on Moved == 0, so sens.Moved is at least one on every path that
		// reaches here and the two lines below are reporting a measurement rather than asserting
		// its opposite. Both of them count from sens and neither of them rounds a number into a
		// word: the version that shipped read "0 of them moved this endpoint away from the
		// unperturbed control, so the endpoint does vary with this slot".
		precond = append(precond, "ARM D WAS NOT SENT AND THIS CLEAN DOES NOT COVER IT: "+armDWhy)
		precond = append(precond, "THIS ENDPOINT IS NOT INSENSITIVE TO THIS SLOT: "+
			pxCount(sens.Moved, "of its")+" "+pxCount(sens.Delivered, "delivered probes")+" came back "+
			"with a different status or a different normalised body from the unperturbed route control, "+
			"so it does answer differently to something and a null differential here is a measurement "+
			"rather than an endpoint that never varies")
		reason += ". " + pxCount(sens.Moved, "of them moved the status or the normalised body away from "+
			"the unperturbed control") + ", so this endpoint answers at least one thing this class sent " +
			"differently from a request carrying none of our bytes"
		if sens.Unknown > 0 {
			reason += " (" + pxCount(sens.Unknown, "further probe(s)") + " could not be compared with " +
				"that control at all and this clean does not rest on them)"
		}
	}

	if tally.Compared > 0 {
		precond = append(precond, "ARM S ACTUALLY COMPARED SOMETHING: "+
			pxCount(tally.Compared, "separator payload(s)")+" were differenced against "+string(hppNC1)+
			" on the status, the value-free element skeleton or the JSON key set, type map and "+
			"cardinalities, and none of those moved")
		reason += ". AND THE SEPARATOR ARM: the " + pxCount(tally.Compared, "separator form(s)") +
			" that could be compared were answered with the same status, the same value-free element " +
			"skeleton and the same JSON shape as the length-matched control with hyphens in place of the " +
			"separator and the equals sign. Two bytes that mean something to a parser and nothing to " +
			"anything else changed no branch, so nothing downstream re-parsed this value"
	} else {
		precond = append(precond, "ARM S MEASURED NOTHING AND THIS CLEAN DOES NOT COVER IT: no separator "+
			"payload could be compared with "+string(hppNC1)+" on any of this arm's three properties")
		reason += ". ARM S MEASURED NOTHING HERE and this negative does not cover it: no separator form " +
			"could be compared against the hyphen control on any of the three structural properties"
	}
	if tally.Degraded > 0 {
		// REACHABLE ONLY WITH A COMPLETED ARM D, because refusal (3b) returns on this count when
		// arm S is alone. The sentence says which arm is left holding the slot rather than
		// leaving the reader to work out that something still answered.
		reason += ". " + pxCount(tally.Degraded, "further separator payload(s)") + " could not be " +
			"compared on any of the three properties. This clean does not rest on them and does not " +
			"cover the separator form(s) they carried: what covers this slot is the completed arm D " +
			"above, which put a genuinely duplicated parameter on the wire and made both of its own " +
			"comparisons"
	}
	ann["arm_s_forms_compared"] = tally.Compared
	ann["arm_s_forms_delivered_but_not_comparable"] = tally.Degraded
	ann["clean_preconditions"] = precond
	v := one(triage.StateClean, reason, oracle, triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// hppArmDCompleted reports whether arm D actually TOOK both of its comparisons and both came back
// usable and identical, which is the one reading that makes a null result from this arm a
// measurement rather than an absence of one.
//
// faCmpSame AND NOT "anything that is not faCmpDifferent", which is the whole point of the
// function. faCmpNoBody is two empty bodies, faCmpDegraded is a truncation or a missing
// projection and faCmpUnmeasured is a response that never arrived; each of those is a comparison
// that could not be made, and hppPrecedence's switch falls through all three into the same
// last_or_unused branch as a real match. This is where they are separated, because the difference
// between /hpp/last and /clean/empty204 with a duplicated parameter is exactly the difference
// between faCmpSame and faCmpNoBody.
//
// It recomputes rather than reading hppPrecedence's annotations because a decision taken off a
// map[string]any another function happened to fill is a decision no test can pin.
func hppArmDCompleted(honest []faOwnObs, control triage.Observation, haveControl bool) bool {
	if !haveControl {
		return false
	}
	d1, ok1 := faFind(honest, hppD1)
	d2, ok2 := faFind(honest, hppD2)
	d3, ok3 := faFind(honest, hppD3)
	if !ok1 || !ok2 || !ok3 {
		return false
	}
	return faCompare(d1.Obs, d2.Obs) == faCmpSame && faCompare(d3.Obs, control) == faCmpSame
}

// Settle. Every answer arrives in the responses to the probes themselves.
func (hppClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

func hppNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"control to difference against and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain", "", triage.GradeUnrated, nil
	}
	// THE PLANNER IS ASKED FIRST AND THE BUDGET SECOND, which is what makes not_planned reachable
	// on a capped run. hppRound0For is the planner's own round 0, so this count is derived rather
	// than asserted. See pxbudgetarm.go.
	state, reason := pxNothingSentTail(ctx, len(hppRound0For(ctx.Slot, ctx.Vector.ComposedURL)),
		"a parameter-pollution probe",
		"no parameter-pollution probe was derived for this slot and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// ---------------------------------------------------------------------------------------------
// ARM D: THE PRECEDENCE ORACLE
// ---------------------------------------------------------------------------------------------

// hppPrecedence decides which occurrence the application read, from three comparisons and no echo.
//
//	D1 against D2      two different FIRST values, position and arity held fixed. Different
//	                   responses mean the first occurrence supplies the value.
//	D3 against ROUTE   the first occurrence renamed away. A different response means its presence
//	                   was load-bearing even where its value was not.
//
// THE PRECONDITION IS THAT THE PARAMETER MATTERS AT ALL, and there is no way to establish it from
// inside this arm: an application that ignores the parameter entirely answers all three the same,
// and so does one that reads the last occurrence. Those are different facts and this arm cannot
// separate them, so the "all the same" branch is a clean at the oracle first_occurrence_is_ignored
// with the ambiguity stated, rather than a claim about precedence.
// IT TAKES THE ROUTE CONTROL'S OBSERVATION RATHER THAN THE ClassifyCtx, for the reason
// pcSharedCacheRiskOf is split the same way: a Replay needs a capability from
// server/utils/internal/triagecap, Go's internal rule makes that package unimportable from this
// one BY DESIGN, and a function that could only be called with an unresolved control would have
// its whole decision table unreachable from a test. routeOK is passed separately because "there
// was no control" and "the control was an empty response" are different facts and only one of
// them permits a comparison.
func hppPrecedence(route triage.Observation, routeOK bool, honest []faOwnObs, ann map[string]any, ords []uint64,
	skips []triage.ProbeSkip, one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict,
	occurrences int) ([]triage.ClassVerdict, bool) {

	d1, ok1 := faFind(honest, hppD1)
	d2, ok2 := faFind(honest, hppD2)
	if !ok1 || !ok2 {
		ann["arm_d_incomplete"] = "arm D needs both first-value probes to have come back and it has " +
			pxCount(len(honest), "responses") + ". A precedence claim from one of them would be a " +
			"comparison against the route control, which also changes whether the value is the original " +
			"one, so it is not made"
		return nil, false
	}

	cmp := faCompare(d1.Obs, d2.Obs)
	ann["d1_vs_d2"] = string(cmp)
	switch cmp {
	case faCmpDegraded, faCmpUnmeasured:
		v := one(triage.StateCannotDetermine,
			"precedence_comparison_degraded ("+string(cmp)+"): the two first-value probes could not be "+
				"compared, either because a body was truncated or because no normalised projection was "+
				"recorded for one of them. A raw-body comparison would report a difference on every "+
				"endpoint that carries a request id in its footer, so it is not made",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v, true
	case faCmpDifferent:
		// THE APPLICATION READS THE FIRST OCCURRENCE. It is suspicious rather than a finding
		// because on its own it is a fact about the application and not a bug: the bug needs a
		// component in front that reads the other one, and this class cannot see one.
		ann["precedence"] = "first"
		stripped := faCompareStripped(d1.Obs, d2.Obs)
		ann["d1_vs_d2_after_echo_strip"] = string(stripped)
		extra := ""
		if stripped == faCmpSame {
			extra = ". NOTE: the difference disappears once each response's echo of its own payload is " +
				"stripped, so the endpoint is reflecting the value and the differential may be the echo " +
				"and nothing else. The precedence reading is weaker for it and the grade says so"
		}
		grade := triage.GradeMedium
		if stripped == faCmpSame {
			grade = triage.GradeLow
		}
		v := one(triage.StateSuspicious,
			"first_occurrence_wins: this parameter arrives "+pxCount(occurrences, "times")+" on the "+
				"captured request, so a genuinely polluted request was sent, and two probes differing ONLY "+
				"in the value of the FIRST occurrence produced different responses. The application's view "+
				"of this parameter therefore comes from the first occurrence. THAT IS NOT A BUG ON ITS "+
				"OWN, and it is reported as suspicious rather than as a finding for that reason: it "+
				"becomes one when something in front, a WAF, a CDN rule or an authorisation proxy, reads "+
				"the LAST occurrence instead, because the value it inspected is then not the value the "+
				"application acted on. This class cannot see that component, so it states the condition "+
				"rather than claiming the bypass. A CONCATENATING STACK IS INSIDE THIS ANSWER: an "+
				"application handed \"A,B\" also changes when A changes"+extra,
			"first_occurrence_wins", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: d1.Ordinal, Phrase: "first occurrence varied, response varied",
			Wire: d1.Obs.Payload,
		}
		return v, true
	}

	// D1 and D2 agree: the first occurrence's VALUE does not reach the application. D3 asks
	// whether its PRESENCE does.
	d3, ok3 := faFind(honest, hppD3)
	if !ok3 || !routeOK {
		ann["arm_d_removal_not_measured"] = "the removal probe did not come back, or there is no route " +
			"control to compare it against, so 'the first occurrence is ignored' and 'the first occurrence " +
			"is counted but not read' were not separated"
		return nil, false
	}
	rcmp := faCompare(d3.Obs, route)
	ann["d3_vs_route"] = string(rcmp)
	if rcmp == faCmpDifferent {
		ann["precedence"] = "last_but_arity_sensitive"
		v := one(triage.StateSuspicious,
			"first_occurrence_counted_but_not_read: changing the FIRST occurrence's value changed nothing, "+
				"so the application's value comes from a later occurrence, and yet RENAMING the first "+
				"occurrence away DID change the response. The first occurrence is therefore being counted "+
				"and not read. Two stacks do that: one that JOINS the occurrences and happens to produce "+
				"the same joined string for both of our first values, which is unlikely, and one that "+
				"checks the ARITY or the shape of the parameter list before using the last value, which is "+
				"common in validation middleware. Either way the parser in front of this application "+
				"treats a polluted list differently from a clean one, which is the precondition for every "+
				"pollution bypass",
			"first_occurrence_counted_but_not_read", triage.GradeLow, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{Ordinal: d3.Ordinal, Phrase: "first occurrence renamed away, response varied", Wire: d3.Obs.Payload}
		return v, true
	}

	ann["precedence"] = "last_or_unused"
	return nil, false
}

// ---------------------------------------------------------------------------------------------
// ARM S: THE SEPARATOR ORACLE
// ---------------------------------------------------------------------------------------------

// hppSeparatorEffect reports whether two bytes that mean something only to a parser changed the
// SHAPE of the answer.
//
// THE CONTROL IS HALF THE MEASUREMENT. HPP-NC1 is HPP-S1 with the ampersand and the equals sign
// replaced by hyphens: same length, same alphabet, two marker copies in the same two places. The
// only difference is two bytes that mean something to a parser and nothing to anything else.
//
// AND THE COMPARISON IS STRUCTURAL, NOT TEXTUAL, BECAUSE THE TEXTUAL ONE WAS MEASURED WRONG.
// This arm first compared the two with faCompare, falling back to faCompareStripped to excuse an
// echo. Run end to end against the canary oracle on 2026-09-19 it produced two suspicious rows:
//
//	xss   HPP  query:q    suspicious  separator_reparsed
//	ssti  HPP  query:tpl  suspicious  separator_reparsed
//
// on two routes that do nothing whatever with parameter separators. Both simply print the
// parameter back. THE ECHO GUARD DID NOT GUARD, and the reason is exact: faCompareStripped calls
// faEchoStrip(body, o.Payload.WIRE), and on a query slot the wire form is percent-encoded
// (hppa...%26hppdup%3D...) while the body carries the DECODED and HTML-escaped form. The strip
// searched for bytes that were never in the page, removed nothing, and handed back two bodies
// that differ exactly as much as the two payloads do. faCompare over the normalised body fails
// the same way for the same reason: marker FORMS are stripped from it and the rest of the payload
// is not. The unit test missed it because a hand-written fixture echoes the LOGICAL bytes, which
// is the one spelling faEchoStrip can find.
//
// So the oracle is now a property a pure echo CANNOT change: the status, the value-free element
// skeleton, or the JSON key set, type map and cardinalities. An endpoint that prints our value
// into the same page in the same place has the same skeleton and the same JSON shape whatever the
// value was. An endpoint that saw a second pair took a different BRANCH, and a different branch
// shows up in one of those three.
//
// THE COST IS A REAL FALSE NEGATIVE AND IT IS NAMED RATHER THAN HIDDEN: a re-parse that changes
// only a scalar's TEXT, and neither the status nor the shape, is invisible here. That is the right
// trade in this layer's own terms, because the alternative was firing on every reflecting endpoint
// in the corpus, and a class that fires everywhere points the expensive scanner nowhere.
//
// IT NEVER REACHES A FINDING. What it observes is that something re-parsed our value. What it does
// NOT observe is a parameter named hppdup arriving anywhere, because nothing echoes it back. The
// ceiling is suspicious and the reason says which of those two facts it has.
func hppSeparatorEffect(honest []faOwnObs, ann map[string]any, ords []uint64,
	skips []triage.ProbeSkip, one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict) ([]triage.ClassVerdict, bool, hppArmSTally) {

	var tally hppArmSTally
	nc, okNC := faFind(honest, hppNC1)
	if !okNC {
		ann["arm_s_not_measured"] = "the length-matched hyphen control did not come back, so a difference " +
			"between a separator payload and anything else could equally be the response changing with the " +
			"value. No separator claim is made without it"
		return nil, false, tally
	}
	tally.HaveControl = true

	degraded := 0
	for _, id := range []triage.ProbeID{hppS1, hppS2} {
		s, ok := faFind(honest, id)
		if !ok {
			continue
		}
		what, cmp := hppStructuralChange(nc.Obs, s.Obs)
		ann["s_vs_control_"+string(id)] = string(cmp)
		switch cmp {
		case faCmpDegraded, faCmpUnmeasured:
			degraded++
			tally.Degraded++
			continue
		case faCmpSame, faCmpNoBody:
			tally.Compared++
			continue
		}
		tally.Compared++
		sep := "an ampersand and an equals sign"
		if id == hppS2 {
			sep = "a semicolon and an equals sign"
		}
		ann["winning_probe"] = string(id)
		ann["separator"] = sep
		ann["structural_change"] = what
		v := one(triage.StateSuspicious,
			"separator_changed_the_answer: "+string(id)+" and "+string(hppNC1)+" are the same length, the "+
				"same alphabet and carry their markers in the same two places, and differ only in that one "+
				"of them contains "+sep+" where the other contains hyphens. "+what+". THAT IS A PROPERTY AN "+
				"ECHO CANNOT CHANGE: an endpoint that prints our value into the same page in the same place "+
				"has the same element skeleton and the same JSON shape whatever the value was, so the "+
				"difference is a different BRANCH and not different bytes. Two characters that mean "+
				"something only to a parser changed which branch ran, so something in this request's path "+
				"re-parsed the value into more than one pair. WHAT THIS DOES NOT SHOW, and the reason it is "+
				"suspicious rather than a finding: nothing observed a parameter named "+hppInjectedName+
				" arriving anywhere. The re-parse is measured; what the second pair then did is not, and on "+
				"an endpoint that echoes nothing it cannot be from here. The next step is to replace "+
				hppInjectedName+" with a parameter this application actually reads",
			"separator_reparsed", triage.GradeMedium, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: s.Ordinal, Phrase: "separator payload versus length-matched control: " + what,
			Wire: s.Obs.Payload,
		}
		return v, true, tally
	}
	if degraded > 0 {
		ann["arm_s_degraded"] = pxCount(degraded, "separator probe(s)") + " could not be compared " +
			"structurally: the body was truncated, or it is neither HTML nor JSON so there is no element " +
			"skeleton and no key set to difference. Arm S measured nothing on those, and where NONE of " +
			"them could be compared the caller refuses the clean outright rather than resting it on an " +
			"empty comparison"
	}
	return nil, false, tally
}

// hppArmSTally is what arm S managed to MEASURE, as opposed to what it concluded.
//
// IT EXISTS BECAUSE THE CALLER USED TO GUESS. hppSeparatorEffect returned a bare (verdict, bool)
// and a false second value meant three different things: the control never came back, the
// comparison ran and found nothing, or the comparison could not be attempted on either payload.
// Classify read all three as "arm S is silent" and emitted the same clean for each, which is how a
// text/plain endpoint with no element skeleton and no JSON came out of this class as a measured
// negative. The counts are returned so the caller can tell them apart, and the clean puts them in
// its own reason so a reader can see the denominator.
type hppArmSTally struct {
	// HaveControl is whether HPP-NC1, the length-matched hyphen payload, came back at all.
	HaveControl bool
	// Compared counts separator payloads that were differenced against it on at least one of the
	// arm's three properties: status, the value-free element skeleton, or the JSON shape.
	Compared int
	// Degraded counts separator payloads where NONE of the three could be measured on both sides.
	Degraded int
}

// hppStructuralChange is the echo-proof comparison, and it names what moved.
//
// THE THREE PROPERTIES, IN THE ORDER THEY ARE ASKED:
//
//	STATUS      the strongest, and the only one that works on any media type. A different status is
//	            a different branch, full stop.
//	SKELETON    Proj.StructTokens is the value-free tag, class and id list, hashed into
//	            StructSHA256. Printing a different string into the same element does not change it;
//	            taking a different template branch does.
//	JSON SHAPE  the key set, the pointer-to-type map and the per-array cardinalities.
//	            Proj.JSONScalars is DELIBERATELY NOT USED: it carries pointer=value, so an echoed
//	            value is inside it and this arm would be textual again under another name.
//
// It returns faCmpDegraded when NONE of the three could be measured on both sides, because a body
// that is neither HTML nor JSON has an empty skeleton on both sides and comparing two empty
// skeletons is not evidence of sameness. Not knowing is not clean, one layer down.
func hppStructuralChange(a, b triage.Observation) (string, faCmp) {
	if a.ObsID == "" || b.ObsID == "" || !a.Delivered() || !b.Delivered() {
		return "", faCmpUnmeasured
	}
	if a.BodyTruncated || b.BodyTruncated {
		return "", faCmpDegraded
	}
	if a.Status != b.Status {
		return "the two were answered with different statuses, " + pxCount(a.Status, "for the control") +
			" and " + pxCount(b.Status, "for the separator payload"), faCmpDifferent
	}

	measured := false
	var zero [32]byte
	if len(a.Proj.StructTokens) > 0 && len(b.Proj.StructTokens) > 0 &&
		a.Proj.StructSHA256 != zero && b.Proj.StructSHA256 != zero {
		measured = true
		if a.Proj.StructSHA256 != b.Proj.StructSHA256 {
			return "the value-free element skeleton of the two responses differs, so a different set of " +
					"tags, classes and ids was rendered rather than the same page with a different string in it",
				faCmpDifferent
		}
	}
	if a.Proj.JSONParsed && b.Proj.JSONParsed {
		measured = true
		for _, c := range []struct {
			what string
			x, y []string
		}{
			{"the JSON key set differs, so the response carries different fields", a.Proj.JSONKeySet, b.Proj.JSONKeySet},
			{"the JSON type map differs, so a field that was one type came back another", a.Proj.JSONTypeMap, b.Proj.JSONTypeMap},
			{"the JSON array cardinalities differ, so a collection came back a different length", a.Proj.JSONCards, b.Proj.JSONCards},
		} {
			if !hppSameLines(c.x, c.y) {
				return c.what, faCmpDifferent
			}
		}
		if a.Proj.DupJSONKeys != b.Proj.DupJSONKeys {
			return "one response carries duplicate JSON keys and the other does not", faCmpDifferent
		}
	}
	if !measured {
		return "", faCmpDegraded
	}
	return "", faCmpSame
}

// hppSameLines compares two projection lists. TriageProject emits both sorted, so order is
// meaningful and a set comparison would hide a reordering that is itself a structural change.
func hppSameLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------------------------
// THE TOOL POINTER
// ---------------------------------------------------------------------------------------------

func hppLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"manual": "there is no parameter-pollution container in this framework and the next step is a " +
			"judgement rather than a scan: swap " + hppInjectedName + " for a parameter this application " +
			"actually reads, an authorisation flag, a tenant id, a price, an ordering field, and see " +
			"which occurrence wins",
		"waf": "the finding that pays is a component in front reading a different occurrence from the " +
			"application. Run the same pair through the Target Behaviour Probe with and without the " +
			"separator: a request the edge answers and one it forwards, differing by two bytes, is the " +
			"bypass this class can only state as a condition",
	}
	if p, ok := ann["precedence"].(string); ok {
		hints["precedence"] = p
	}
	if w, ok := ann["winning_probe"].(string); ok {
		hints["winning_probe"] = w
	}
	if _, ok := ann["arm_d_not_available"]; ok {
		hints["arm_d"] = "true duplication was not deliverable on this slot and this row is arm S only. " +
			"Reproduce arm D by hand with replay_request: send the same parameter twice with two values " +
			"the application can tell apart, then send each alone"
	}
	return triage.TriageLabel{Tools: []string{}, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (hppClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "the_control_is_length_matched", Probes: []triage.ProbeID{hppNC1, hppS1},
			Rule: string(hppNC1) + " must be byte-for-byte the same length as " + string(hppS1) + " with " +
				"only '&' and '=' replaced by '-'. If a future edit changes one payload and not the other, " +
				"arm S stops being a separator measurement and becomes 'the response changed when the " +
				"value changed', which is true of most endpoints. A test asserts the lengths",
		},
		{
			Name: "echo_only_differences_do_not_score", Probes: []triage.ProbeID{hppS1, hppS2},
			Rule: "a difference between a separator payload and the control that DISAPPEARS once each " +
				"side's echo of its own payload is stripped is a reflecting endpoint and not a parser, and " +
				"must not score. faCompareStripped is asked on every arm-S hit before it is reported",
		},
		{
			Name: "precedence_needs_two_first_values", Probes: []triage.ProbeID{hppD1, hppD2},
			Rule: "the precedence claim is D1 against D2 and never D1 against the route control. Comparing " +
				"against the control also changes whether the value is the ORIGINAL one, so a difference " +
				"there could be the application reacting to an unfamiliar value rather than to position",
		},
		{
			Name: "arm_d_only_where_the_capture_duplicates", Probes: hppDuplicateProbes(),
			Rule: "arm D is planned only where hppCapturedOccurrences finds the name twice or more in the " +
				"captured request target. Anywhere else the runner would perturb the single occurrence as " +
				"an ordinary value and the class would read a plain value differential as precedence",
		},
		{
			Name: "the_block_guard_runs_first", Probes: hppAllProbeIDs(),
			Rule: "pxUniformBlock is asked BEFORE either arm, which is the opposite of CRLF's order and is " +
				"correct here: every oracle in this class is a body differential, and a filter with one " +
				"error page makes every differential read zero, which would be reported as a measured " +
				"negative about an application no request reached",
		},
		{
			Name: "no_finding_grade_from_arm_s", Probes: []triage.ProbeID{hppS1, hppS2},
			Rule: "arm S's ceiling is suspicious. It observes that a re-parse happened; it never observes " +
				"the injected parameter arriving, because nothing echoes it back. A finding grade would be " +
				"claiming the second half",
		},
	}
}

func (hppClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "precedence", Kind: "differential", What: "first, last_but_arity_sensitive, or last_or_unused. It is the fact an operator needs before choosing which occurrence to hide a payload in"},
		{Name: "captured_occurrences", Kind: "annotation", What: "how many times the capture already carried this name, which is what decided whether a genuinely polluted request could be sent at all"},
		{Name: "d1_vs_d2", Kind: "differential", What: "the comparison the precedence claim rests on, with the after-echo-strip reading beside it so a reflecting endpoint is visible rather than inferred"},
		{Name: "separator", Kind: "annotation", What: "ampersand or semicolon. Which one got through decides where the second parser is: an ampersand points at a re-parse of a decoded value, a semicolon at a legacy pair separator or at the cookie container"},
		{Name: "arm_d_not_available", Kind: "annotation", What: "on every row where true duplication could not be delivered, with the measured encoder reason. It is what stops an arm-S clean being read as covering pollution"},
		{Name: "component_in_front_not_measured", Kind: "annotation", What: "on every verdict: the bypass needs a filter that disagrees, and this class sees only the application's end"},
	}
}

// OracleCases. None of these routes exists yet, so Exists is false on every one and the oracle
// pass gets a build list rather than a wish list.
func (hppClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "first_occurrence_wins", Route: "/hpp/first", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{hppD1, hppD2}, WantState: triage.StateSuspicious,
			Why: "a route reachable as /hpp/first?q=a&q=b that renders its answer from the FIRST q and " +
				"echoes nothing. D1 and D2 must produce different responses and the verdict must be " +
				"suspicious at oracle first_occurrence_wins, NOT a finding: on its own the precedence is a " +
				"fact about the application and the bug needs a component in front that disagrees",
		},
		{
			Name: "last_occurrence_wins", Route: "/hpp/last", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{hppD1, hppD2, hppD3}, WantState: triage.StateClean,
			Why: "the same route rendering from the LAST q. D1 and D2 are identical, D3 leaves the answer " +
				"unchanged, and the verdict is clean at oracle first_occurrence_is_ignored. It is the " +
				"negative that proves the precedence oracle reads position rather than change",
		},
		{
			Name: "arity_checked", Route: "/hpp/arity", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{hppD1, hppD2, hppD3}, WantState: triage.StateSuspicious,
			Why: "a route that renders from the last q and 400s when q appears only once. D1 equals D2, " +
				"D3 differs from the control, and the verdict must be " +
				"first_occurrence_counted_but_not_read. Without D3 this route is indistinguishable from " +
				"/hpp/last and the class reports clean on a parser that treats a polluted list specially",
		},
		{
			Name: "downstream_reparse", Route: "/hpp/reparse", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{hppS1, hppNC1}, WantState: triage.StateSuspicious,
			Why: "a route that splits its own parameter's DECODED value on '&' and behaves differently " +
				"when it finds a second pair, while echoing nothing. S1 must differ from the " +
				"length-matched control and the verdict must be suspicious at oracle separator_reparsed",
		},
		{
			Name: "semicolon_reparse", Route: "/hpp/semicolon", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{hppS2, hppNC1}, WantState: triage.StateSuspicious,
			Why: "the same with ';' as the separator and '&' left alone. It is what proves S1 and S2 are " +
				"two probes rather than two spellings: every WAF rule for pollution looks for the " +
				"ampersand and a long tail of stacks still split on the semicolon",
		},
		{
			Name: "reflection_is_not_a_reparse", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{hppS1, hppNC1}, WantState: triage.StateClean,
			Why: "THE MOST IMPORTANT NEGATIVE IN THE CLASS. The shipped echo route puts the parameter in " +
				"the body, so S1's response and the control's differ in every byte of the echo and in " +
				"nothing else. faCompare over the NORMALISED body should already agree, and " +
				"faCompareStripped is the second net. The verdict must be clean: an endpoint that prints " +
				"our value back has not parsed it",
		},
		{
			Name: "endpoint_400s_on_everything", Route: "/clean/validate", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{hppS1, hppS2, hppNC1}, WantState: triage.StateCannotDetermine,
			Why: "a route that rejects every value with one identical page. Every arm reads 'no " +
				"difference', which this class would otherwise report as a measured negative about a " +
				"parser no request reached. The block guard runs BEFORE the arms so the verdict is " +
				"cannot_determine (blocked), and not knowing is not clean",
		},
		{
			Name: "single_occurrence_is_arm_s_only", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: hppSeparatorProbes(), WantState: triage.StateClean,
			Why: "a route reached with the parameter appearing ONCE. Arm D must not be planned at all, the " +
				"verdict must carry arm_d_not_available with the measured encoder reason, and the clean " +
				"preconditions must say the clean does not cover duplication. A class that planned D1 here " +
				"would perturb the single occurrence and read an ordinary value differential as precedence",
		},
	}
}
