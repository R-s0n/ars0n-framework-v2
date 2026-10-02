package triageclasses

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS HOSTHDR (id 20). HOST HEADER INJECTION: a ROUTING HEADER WE CONTROL becomes the AUTHORITY
// OF A URL THE APPLICATION BUILT.
//
// THE ORACLE IS POSITIONAL AND THAT IS THE WHOLE CLASS. An application that prints
// X-Forwarded-Host into a debug block has told the operator nothing exploitable. An application
// that builds https://<our host>/reset?token=... has handed over every password reset link on the
// site. Both responses contain the same twenty bytes. The difference is entirely where those bytes
// sit, and a detector that searched for them would report the first as the second on every
// framework with a verbose error page.
//
// So every detector here goes through pxHostInAuthorityPosition, whose rule is two anchors and a
// delimiter set: our host must be immediately preceded by "//" or by "@", and followed by end of
// input or one of pxAuthorityDelimiters. It deliberately does not parse. Its failure mode is a
// missed hit rather than an invented one, which is the correct direction for a rule that decides
// between "reflected" and "exploitable".
//
// THE SECOND ORACLE IS THE Location HEADER, read through pxResolveBoth. A 3xx whose Location
// resolves to a host we named is the same bug arriving through the protocol rather than through
// the body, and it is the stronger of the two: a browser acts on it without the user reading
// anything.
//
// =================================================================================================
// THE FOUR HEADERS, AND WHY THEY ARE NOT ONE PROBE WITH FOUR NAMES
// =================================================================================================
//
//	Host                the request's own authority. Every framework that builds an absolute URL
//	                    without a configured base reads it. Only present as a slot when the capture
//	                    recorded one, because it is not in triageInferredHeaders.
//	X-Forwarded-Host    what a reverse proxy tells the application the client asked for. Emitted by
//	                    triageInferredHeaders on every HEADER vector whether or not the crawl saw
//	                    it, which is correct: absence from a capture says nothing, because a
//	                    browser never sends it and essentially every deployment behind a proxy
//	                    honours it.
//	X-Original-URL      IIS and Symfony-style route override. It carries a PATH or an absolute URL,
//	                    not a bare authority, so it gets different payloads.
//	X-Rewrite-URL       the same mechanism under the other common spelling.
//
// The two cousins already in the inferred set, X-Original-Host and X-Host, are covered by the same
// bare-authority payloads for the same reason, and X-Forwarded-Server by the same again. They are
// listed in hhAuthorityHeaders rather than left out, because a class that probed three spellings
// of a header and not the fourth would report clean on the fourth.
//
// A PAYLOAD IS CHOSEN BY HEADER SHAPE AND NOT SENT EVERYWHERE. A bare authority in X-Original-URL
// is a relative path and tests nothing; an absolute URL in Host is not a valid authority and Go
// will put it on the wire as one anyway, which tests a malformed request rather than the sink.
// hhProbesFor is where that decision lives and it is the reason this class has two payload
// families rather than one.
//
// =================================================================================================
// THE HONEST BLIND SPOT, STATED BEFORE ANYTHING ELSE SO NOBODY READS SILENCE AS COVERAGE
// =================================================================================================
// A HOST HEADER USED ONLY IN AN OUTBOUND EMAIL IS INVISIBLE TO EVERY IN-BAND PROBE, AND THAT IS
// THE MOST VALUABLE FORM OF THIS BUG.
//
// The canonical exploit is a password reset: POST /forgot-password with X-Forwarded-Host set to an
// attacker's host, the application builds the reset link from that header, the victim receives the
// mail and clicks a link that sends their token to the attacker. Nothing about that appears in the
// response to our request. The response is a 200 and a "check your email" page, identical byte for
// byte to the one the unperturbed request produces.
//
// This class therefore CANNOT distinguish "the application does not use this header" from "the
// application uses this header only in mail it sends". Both look like a clean, and a clean here is
// annotated with exactly that sentence on every single verdict. The measurement that would close
// it is an out-of-band email sink, which this layer does not have; the OOBConfig in PlanCtx serves
// DNS and HTTP callbacks and no SMTP.
//
// SECOND BLIND SPOT: ROUTE OVERRIDE IS NOT SCORED. X-Original-URL and X-Rewrite-URL are most
// famous for making a proxy's access-control decision disagree with the application's routing, so
// that a 403 on /admin becomes a 200. That is an ACCESS CONTROL finding, its oracle is a status
// and body differential rather than a host in an authority, and scoring it here would file an
// access-control bug under a host-header heading and hide it from the class that should own it.
// This class sends those headers carrying an ABSOLUTE URL and scores only the authority.
//
// =================================================================================================
// THE SAFETY QUESTION: THIS CLASS CAN POISON A SHARED CACHE AND IS GATED ON THAT
// =================================================================================================
// X-Forwarded-Host is the single most productive unkeyed input in the web cache poisoning
// literature, for the same reason it is productive here: it changes the response and it is not in
// the cache key. A poisoned entry serves every subsequent visitor a page whose absolute URLs point
// at a host we named, and the finding IS that somebody else got our response.
//
// CRLF and REDIRECT do not need this gate because their marker rides in the request target, which
// every cache keys on, so their entry is one nobody else will ever request. THIS CLASS'S MARKER IS
// IN A HEADER and it has no cache-busting token available: the encoder touches the slot it is
// handed and nothing else. So pcSharedCacheRisk is asked of the unperturbed control before
// anything is sent, and a storable response means not_probed with the evidence named. It fails
// closed: no control, no probe.
type hostHeaderClassifier struct{}

func init() { triage.RegisterClassifier(hostHeaderClassifier{}) }

func (hostHeaderClassifier) ID() triage.ClassID { return triage.ClassHostHeader }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	hhA1  triage.ProbeID = "HH-A1"
	hhA2  triage.ProbeID = "HH-A2"
	hhU1  triage.ProbeID = "HH-U1"
	hhU2  triage.ProbeID = "HH-U2"
	hhNC1 triage.ProbeID = "HH-NC1"
)

// hhHostSuffix is the only authority this class will ever call a finding.
//
// RFC 6761 section 6.4 reserves .invalid and guarantees it never resolves, so no payload names a
// domain anybody could register and then actually receive a redirected victim on, and a target
// that tried to fetch from the host reaches nothing. Distinct from REDIRECT's .rdr.invalid, CORS's
// .cors.invalid and RFI's .rfi-inband.invalid so no operator and no log line can confuse one
// class's traffic with another's.
const hhHostSuffix = ".hh.invalid"

// hhAuthorityHeaders take a BARE AUTHORITY. Every one of them is a place a proxy or a framework
// reads the client's idea of the site's hostname from.
//
// Lowercase because triageHeaderSlots lowercases every name it emits.
func hhAuthorityHeaders() []string {
	return []string{"host", "x-forwarded-host", "x-original-host", "x-host", "x-forwarded-server"}
}

// hhURLHeaders take a PATH OR AN ABSOLUTE URL. Sending a bare authority into one of these is a
// relative path and tests nothing, which is why they are a separate list and get separate probes.
func hhURLHeaders() []string {
	return []string{"x-original-url", "x-rewrite-url"}
}

var hhPoints = []triage.SlotKind{triage.KindHeader}

var hhEncoders = []triage.EncoderMode{triage.EncodeHeaderValue}

func (hostHeaderClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassHostHeader
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: hhA1, Class: c, Logical: []byte(m + hhHostSuffix),
			Encoders: hhEncoders, Points: hhPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "THE BASE CASE: a bare authority, which is exactly what a Host or an X-Forwarded-Host " +
				"carries on the wire. The marker is the host's first DNS label, which works because a " +
				"marker is 16 bytes over [0-9a-z] with a letter first and that is precisely a legal label. " +
				"A framework that builds an absolute URL from the request's host concatenates these " +
				"bytes into the authority, and pxHostInAuthorityPosition is what tells that apart from the " +
				"same bytes printed into a debug block",
		},
		{
			ID: hhA2, Class: c, Logical: []byte(m + hhHostSuffix + ":8443"),
			Encoders: hhEncoders, Points: hhPoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "HOST WITH A PORT, and it is a separate probe rather than a spelling because the two " +
				"answers differ. A framework that splits the header on the colon and keeps only the host " +
				"drops the port; one that concatenates the raw header into a URL keeps it. Which of those " +
				"happened decides whether the injected authority can name a port at all, and an attacker " +
				"who can only name a hostname is in a very different position from one who can name a " +
				"host and a port. Full tier: it adds detail to an answer HH-A1 already gave",
		},
		{
			ID: hhU1, Class: c, Logical: []byte("https://" + m + hhHostSuffix + "/"),
			Encoders: hhEncoders, Points: hhPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "AN ABSOLUTE URL, for X-Original-URL and X-Rewrite-URL, which carry a request target " +
				"rather than an authority. It is also the right shape for any framework that treats a " +
				"routing header as a base URL rather than as a hostname. The trailing slash is deliberate: " +
				"a base that is concatenated with a path produces one slash rather than none or two, and " +
				"a missing slash is how an authority silently becomes the head of a longer hostname that " +
				"pxHostInAuthorityPosition then correctly refuses",
		},
		{
			ID: hhU2, Class: c, Logical: []byte("//" + m + hhHostSuffix + "/"),
			Encoders: hhEncoders, Points: hhPoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "SCHEME-RELATIVE. The commonest filter on a routing header of this kind is a blacklist " +
				"on the string http, and a value with no scheme in it walks straight past that while " +
				"testing the same sink. Both this layer's resolution models agree that // reaches the " +
				"authority, so a hit here needs no browser-versus-RFC caveat. Full tier",
		},
		{
			ID: hhNC1, Class: c, Logical: []byte("hh-" + m + "-inert"),
			Encoders: hhEncoders, Points: hhPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE CONTROL, AND IT IS WHAT MAKES A CLEAN MEAN ANYTHING. It carries no dot, no slash, " +
				"no colon and no scheme, so it is not a hostname and no allowlist, regular expression or " +
				"URL parse can mistake it for one, and no routing filter has a reason to reject it. " +
				"THREE JOBS, AND THE FIRST TWO WERE ONE JOB UNTIL A ROUTE SEPARATED THEM. FIRST, if a " +
				"host under " + hhHostSuffix + " carrying this probe's marker appears in authority " +
				"position, this probe never sent one, so our value was rewritten or a foreign response " +
				"is being served, and every verdict on the slot becomes detector_unverified. SECOND, if " +
				"THIS PROBE'S OWN VALUE comes back as an authority, the application puts a scheme in " +
				"front of whatever arrives in the header and never looks at it: that is a finding at its " +
				"own oracle and not a broken detector, because a sink that accepted a value which cannot " +
				"be a host will accept a host. THIRD, it answers a question no payload can answer about " +
				"itself: does this header reach the response at all? That separates 'the application " +
				"never reads this header' from 'the application reads it and builds URLs safely', which " +
				"are the same silence and completely different facts",
		},
	}
}

func hhAllProbeIDs() []triage.ProbeID {
	return []triage.ProbeID{hhA1, hhA2, hhU1, hhU2, hhNC1}
}

// hhProbesFor is the per-header payload choice, and it is the reason this class has two payload
// families. A bare authority in X-Original-URL is a relative path; an absolute URL in Host is not
// an authority. Sending either would spend a request on a question the header cannot be asked.
func hhProbesFor(name string, round int) []triage.ProbeID {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, h := range hhAuthorityHeaders() {
		if h == name {
			if round == 0 {
				return []triage.ProbeID{hhA1, hhNC1}
			}
			return []triage.ProbeID{hhA2}
		}
	}
	for _, h := range hhURLHeaders() {
		if h == name {
			if round == 0 {
				return []triage.ProbeID{hhU1, hhNC1}
			}
			return []triage.ProbeID{hhU2}
		}
	}
	return nil
}

// hhPlannedFor is every probe this class would ever send on this header, which pxNotObserved needs
// so that a probe the budget or the tier refused gets a row rather than a silence.
func hhPlannedFor(name string) []triage.ProbeID {
	return append(hhProbesFor(name, 0), hhProbesFor(name, 1)...)
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

func (hostHeaderClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "CONDITIONAL ON THE HEADER BEING A ROUTING HEADER: " +
				strings.Join(append(hhAuthorityHeaders(), hhURLHeaders()...), ", ") + ". Every one but Host " +
				"is emitted by triageInferredHeaders on every vector whose insertion_point column is " +
				"header, whether or not the crawl captured it; Host is a slot only where the capture " +
				"recorded the request line's own authority. NOTE WHAT THAT DOES NOT SAY: SlotsFor " +
				"dispatches on the vector's insertion_point, so a vector recorded as query yields query " +
				"slots and no header slot at all, and this class is silent on such a vector by " +
				"construction rather than by measurement. Any other header slot is not_applicable at " +
				"zero request cost. Request media type is irrelevant here and is recorded only for the " +
				"row: " + string(mt),
		}
	case triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "this class is about a header that tells the application or its proxy WHICH SITE THIS " +
				"IS. A " + string(k) + " slot cannot carry that, so a probe here would measure a different " +
				"mechanism and file the answer under this class's name. A URL-valued " + string(k) +
				" parameter that ends up in a Location is REDIRECT's question and REDIRECT owns that slot",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment is never transmitted, so it cannot carry a request header",
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

func (c hostHeaderClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := hhEligible(ctx.Slot); !ok {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() || ctx.Budget.Exhausted() {
		return nil
	}
	if _, risky := pcSharedCacheRisk(ctx.Route); risky {
		return nil
	}

	switch ctx.Round {
	case 0:
		return hhPlanFor(hhProbesFor(ctx.Slot.Name, 0), ctx.Slot)
	case 1:
		// ROUND 1 IS GATED ON ROUND 0, AND THE GATE HAS TWO ARMS RATHER THAN ONE.
		//
		// THE FIRST ARM IS THE ORIGINAL, AND IT IS SAFE WHERE CRLF'S WAS NOT. CRLF deleted its
		// gate because the round-1 probes were the only ones that could see the commonest
		// defence, so the gate closed exactly when its contents were needed. Here round 1 holds
		// a port variant and a scheme-relative spelling of a payload round 0 already sent in its
		// most permissive form: neither can discover a sink that HH-A1 or HH-U1 did not reach,
		// so a header that produced nothing at all in round 0 has nothing for them to add detail
		// to.
		//
		// THE SECOND ARM IS THE ONE THAT WAS MISSING, AND ITS ABSENCE IS EXACTLY THE CRLF
		// FAILURE IN THIS CLASS'S SPELLING. "Produced nothing at all in round 0" is ALSO what a
		// filter in front of the application looks like, and pxUniformBlock, the gate that names
		// a filter, needs THREE distinct payloads before it may speak. Round 0 sends two. So the
		// one arm closed the round that would have met the floor, on exactly the endpoints where
		// the floor decides between refusing and reporting a clean. hhRound1IsWorthSending is
		// where that decision now lives, with both reasons written down.
		if ok, _ := hhRound1IsWorthSending(faOwn(ctx.Own), hhBaselineBody(ctx.Route)); !ok {
			return nil
		}
		return hhPlanFor(hhProbesFor(ctx.Slot.Name, 1), ctx.Slot)
	default:
		return nil
	}
}

func hhPlanFor(ids []triage.ProbeID, slot triage.Slot) []triage.ProbeRequest {
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		out = append(out, pxReq(id, slot.Key))
	}
	return out
}

// hhSawAnyReachIn reads THIS CLASS'S OWN round-0 responses and asks whether the value we put in
// the header came back anywhere at all: in authority position, anywhere in the body, or in a
// Location.
//
// It is deliberately LOOSER than the oracle. A bare reflection is not a finding and this function
// is not deciding one; it is deciding whether spending one more request can possibly add detail.
//
// It takes a plain slice rather than a PlanCtx so that a test in this package can drive it: a
// non-empty OwnedResponses can only be built by the vault's own package. Plan asks it through
// hhRound1IsWorthSending, which is where the round-1 decision now lives.
func hhSawAnyReachIn(own []faOwnObs) bool {
	for _, o := range own {
		if o.Err != nil || o.Marker == "" || !o.Obs.Delivered() {
			continue
		}
		if _, ok := faByteForm(o.Obs.Body, []byte(o.Marker)); ok {
			return true
		}
		if loc, ok := pxLocation(o.Obs); ok && strings.Contains(strings.ToLower(loc), strings.ToLower(string(o.Marker))) {
			return true
		}
		for _, h := range o.Obs.RespHeaders {
			if strings.Contains(strings.ToLower(h[1]), strings.ToLower(string(o.Marker))) {
				return true
			}
		}
	}
	return false
}

// =================================================================================================
// THE BLOCK FLOOR, AND THE CLEAN IT USED TO MANUFACTURE
// =================================================================================================
//
// pxUniformBlock is the last thing asked before this class writes a clean, and its job is to
// separate "the application read our host and built nothing from it" from "something in front
// answered and the application never saw it". Its floor is faUniformBlockMin, which is THREE
// distinct payloads sharing one non-baseline response, and three is right: two identical answers
// are a coincidence a two-probe class would report as a filter.
//
// THIS CLASS COULD NOT REACH THREE ON THE ONE SHAPE THE GATE EXISTS FOR. hhProbesFor sends TWO
// values in round 0 on any routing header (a payload and HH-NC1) and round 1's third value was
// bought ONLY by hhSawAnyReachIn, which asks whether round 0's value came back. A filter that
// answers every routing-header value with the same page is exactly the case where nothing comes
// back, so the gate's own precondition was destroyed by the condition it was written to detect:
// two payloads, a floor of three, the gate silent, and Classify falling through to the weakest
// clean it has, whose sentence is "Nothing we put in this header came back in any form, so this
// is the weaker clean: the application may not read the header". On a filtered endpoint every
// word of that is a guess and the state is not true.
//
// THIS IS THE SAME SHAPE AS THE HH-NC1 CONTROL THAT COULD NEVER FIRE, which this class shipped
// once already: a gate whose precondition cannot be met reads exactly like a gate that was asked
// and passed. Two answers are available and both are taken below. Plan buys the third value when
// round 0 is block-shaped, so the gate can run; and Classify REFUSES where the floor is still
// unmet, so no clean rests on a gate that did not run.

// hhFloor is what pxUniformBlock could read off a set of this class's own honest observations.
type hhFloor struct {
	// OffBaseline is how many DISTINCT payload values came back with a response that is not the
	// unperturbed control's.
	OffBaseline int
	// Biggest is the largest set of distinct payload values that shared ONE such response.
	Biggest int
}

// Met reports that pxUniformBlock had enough to answer with, either way.
func (f hhFloor) Met() bool { return f.Biggest >= faUniformBlockMin }

// Unmet is the state this whole section exists for: every payload that moved the endpoint off its
// control came back with THE SAME response, and there were fewer of them than the floor. The
// endpoint answered identically whatever host we named, which is the shape of a filter in front
// rather than of a URL builder behind, and the gate that names that shape cannot speak at this
// size. It is not a block and it is not a clean. It is a measurement nobody took.
//
// Biggest == OffBaseline is the discrimination test and it is not decoration: one payload
// answered with page X and two with page Y is an endpoint telling our values apart, which is the
// opposite of a uniform block, and refusing there would convert honest cleans into unknowns the
// way faUniformBlock(own, nil) once did.
func (f hhFloor) Unmet() bool {
	return !f.Met() && f.Biggest >= 2 && f.Biggest == f.OffBaseline
}

// hhBlockFloorOf computes the floor the way faUniformBlock computes its verdict, so the two
// cannot disagree about the same observations, WITH TWO DELIBERATE DIVERGENCES NAMED HERE.
//
// faUniformBlock groups on Observation.BodySHA256 and skips any response whose body is empty.
// This function groups on the body BYTES and keeps the empty ones.
//
//   - THE DIGEST IS A RUNNER-SET FIELD. Nothing in this package can mint one, so a fixture that
//     left it at its zero value would hash every response to the same key and this predicate
//     would report a uniform block on a route that answered every probe differently. A predicate
//     whose fixtures cannot exercise it honestly is the kind of gate this section exists to stop
//     shipping.
//   - AN EMPTY BODY IS THE COMMONEST BLOCK THERE IS. A 403 with no body to every value is exactly
//     "something in front answered", and faUniformBlock skips it. That hole belongs to every
//     class that calls faUniformBlock, and fixing it there is a report item rather than a change
//     smuggled in here; what this function will not do is inherit it and then call the result a
//     floor.
func hhBlockFloorOf(own []faOwnObs, baseline []byte) hhFloor {
	groups := map[string]map[string]bool{} // response body -> set of distinct payload values
	distinct := map[string]bool{}
	for _, o := range own {
		if o.Err != nil || !o.Obs.Delivered() {
			continue
		}
		if len(baseline) > 0 && bytes.Equal(o.Obs.Body, baseline) {
			continue
		}
		k := string(o.Obs.Body)
		if groups[k] == nil {
			groups[k] = map[string]bool{}
		}
		p := string(o.Obs.Payload.Wire)
		groups[k][p] = true
		distinct[p] = true
	}
	f := hhFloor{OffBaseline: len(distinct)}
	for _, payloads := range groups {
		if len(payloads) > f.Biggest {
			f.Biggest = len(payloads)
		}
	}
	return f
}

// hhRound1IsWorthSending is the round-1 gate, and it now has TWO reasons rather than one.
//
// THE FIRST IS THE ORIGINAL AND IT IS UNCHANGED: round 1 holds a port variant and a
// scheme-relative spelling of a payload round 0 already sent in its most permissive form, so a
// header that produced nothing at all in round 0 has nothing for them to add detail to.
//
// THE SECOND IS THE FIX. Where round 0 is BLOCK-SHAPED, round 1's third distinct value is not
// detail: it is the difference between pxUniformBlock being able to answer at all and this class
// writing a clean on a gate that could not run. One request is the whole price of not reporting a
// filtered endpoint as a safe one.
func hhRound1IsWorthSending(own []faOwnObs, baseline []byte) (bool, string) {
	if hhSawAnyReachIn(own) {
		return true, "round 0's value came back somewhere, so the round-1 spellings have a sink to add detail to"
	}
	if hhBlockFloorOf(own, baseline).Unmet() {
		return true, "round 0 is block-shaped: every value that reached the wire came back with the same " +
			"non-baseline response, and pxUniformBlock needs " + strconv.Itoa(faUniformBlockMin) +
			" distinct payloads before it may say so. Round 1 supplies the third"
	}
	return false, "round 0's value came back nowhere and round 0 is not block-shaped, so neither round-1 " +
		"spelling can reach a sink round 0 missed"
}

// hhBaselineBody is the unperturbed control's body, or nil where there is no control. It is the
// argument pxUniformBlock passes and the argument passing nil throws away.
func hhBaselineBody(r triage.Replay) []byte {
	if !r.Resolved() {
		return nil
	}
	return r.Obs().Body
}

// hhFloorRefusal is the fail-closed half of the fix, and it is a function rather than a block
// inside Classify for the reason hhControlVerdict and hhCleanVerdict are: no test in this package
// can build a resolved Replay or a non-empty OwnedResponses, so an arm living inline in Classify
// can only be read by eye, and an arm that could only be read by eye is how the control that
// could never fire survived a round.
//
// IT FIRES ONLY WHERE pxUniformBlock DID NOT. Classify asks pxUniformBlock first; if the floor was
// met, that gate has already given the answer, either the block or a pass. This arm is for the
// state where the floor was NOT met and the evidence is block-shaped anyway.
func hhFloorRefusal(honest []faOwnObs, baseline []byte, header string, ann map[string]any,
	ords []uint64, skips []triage.ProbeSkip,
	one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict,
) ([]triage.ClassVerdict, bool) {
	// THE ALL-EMPTY-BODY BLOCK, which pxUniformBlock and hhBlockFloorOf both read as "floor met" and
	// then neither names: pxUniformBlock skips empty bodies so it sees nothing to group, and the
	// floor counts them so Unmet() is false and the arm below returns early. A 403 with no body to
	// every value is the commonest block there is, and it was reaching the clean untouched.
	if n, ok := pxEmptyBodyBlock(honest, baseline); ok {
		ann["empty_body_block_distinct_payloads"] = n
		ann["block_floor_required"] = faUniformBlockMin
		v := one(triage.StateCannotDetermine,
			"empty_body_block: all "+pxCount(n, "of this class's distinct values")+" for "+header+
				" that this class delivered came back with an EMPTY body and a 4xx or 5xx status, while "+
				"the unperturbed control carried a body. That is something in front answering instead of "+
				"the application, and pxUniformBlock cannot name it because it groups responses by body "+
				"and skips the empty ones. So what this application builds from "+header+" was NOT "+
				"measured, and this row is that gap. IT IS NOT A CLEAN. The Untested rows on this verdict "+
				"name every probe this class did not send on this slot",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v, true
	}
	f := hhBlockFloorOf(honest, baseline)
	if !f.Unmet() {
		return nil, false
	}
	ann["block_floor_distinct_payloads_off_the_control"] = f.OffBaseline
	ann["block_floor_largest_identical_group"] = f.Biggest
	ann["block_floor_required"] = faUniformBlockMin
	v := one(triage.StateCannotDetermine,
		"block_floor_unmet: all "+pxCount(f.OffBaseline, "of this class's distinct values")+" for "+
			header+" that moved this endpoint off its unperturbed control came back with THE SAME "+
			"response. An endpoint that answers identically whatever host we name is the shape of "+
			"something in front answering instead of the application, and pxUniformBlock is the gate "+
			"that names that shape. IT COULD NOT RUN HERE: it needs "+strconv.Itoa(faUniformBlockMin)+
			" distinct payloads sharing one non-baseline response and this slot produced "+
			strconv.Itoa(f.Biggest)+". So what this application builds from "+header+" was not "+
			"measured, and this row is that gap. IT IS NOT A CLEAN, and a clean is what this class "+
			"used to write here: the arm below it reports that nothing came back and offers that as "+
			"evidence the application may not read the header, which on a filtered endpoint is a "+
			"sentence about the filter. The Untested rows on this verdict name every probe this "+
			"class did not send on this slot and why; sending them is what closes this row",
		"", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v, true
}

// hhEligible is this class's per-slot gate and it costs no requests.
func hhEligible(s triage.Slot) (string, bool) {
	if reason, ok := faEligibleSlot(s); !ok {
		return reason, false
	}
	if s.Kind != triage.KindHeader {
		return "host_header_injection_is_a_request_header_mechanism: this slot is a " + string(s.Kind) +
			" slot, and nothing in it can tell the application which site it is serving", false
	}
	if hhProbesFor(s.Name, 0) == nil {
		return "not_a_routing_header: this class is defined on " +
			strings.Join(append(hhAuthorityHeaders(), hhURLHeaders()...), ", ") + " and this slot is " +
			s.Name + ". Perturbing an unrelated header would measure something else and record it here", false
	}
	return "", true
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

func (c hostHeaderClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassHostHeader, key, state, reason, oracle, grade, ords, ann, hhLabel(ann))
	}

	if reason, ok := hhEligible(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}

	// THE GATE IS ASKED ONLY WHERE THERE IS A CONTROL TO ASK ABOUT. With no route control the
	// honest answer is route_unresolved, which corsNothingSent and hhNothingSent give below;
	// reporting a CACHE refusal there would name the wrong reason on a row whose real problem is
	// that nothing resolved. Plan refuses that case separately, so nothing is sent either way.
	//
	// THE CONSEQUENCE FOR TESTS IS WORTH RECORDING: a test in this package cannot build a
	// resolved Replay, so the not_probed row below is unreachable from one. The decision it
	// rests on is pcSharedCacheRiskOf, which is tested directly and exhaustively.
	if why, risky := pcSharedCacheRiskOfResolved(ctx.Route); risky {
		ann["cache_safety_refusal"] = why
		return one(triage.StateNotProbed,
			"shared_cache_poisoning_risk: "+why+". X-Forwarded-Host is the most productive unkeyed input "+
				"in the cache poisoning literature for exactly the reason it is productive here: it changes "+
				"the response and it is not in the cache key. A poisoned entry serves every subsequent "+
				"visitor a page whose absolute URLs name a host we chose, and that finding happening to "+
				"somebody else is the one thing this layer will not do. THIS CLASS CANNOT BUST THE CACHE: "+
				"its marker rides in a header, not in the request target, which is why CRLF is safe on the "+
				"same endpoint and this is not",
			"", triage.GradeUnrated, nil)
	}

	ann["header"] = ctx.Slot.Name
	ann["email_side_channel_not_measured"] = "A HOST HEADER USED ONLY IN AN OUTBOUND EMAIL IS INVISIBLE " +
		"TO THIS PROBE, and that is the most valuable form of this bug. The canonical password-reset " +
		"exploit produces a response identical to the unperturbed one and puts the poisoned link in mail " +
		"nobody here can read. This class therefore cannot tell 'the application does not use this " +
		"header' from 'the application uses it only in mail it sends', and a clean below means the first " +
		"only in the sense that no IN-BAND use was found. Closing it needs an SMTP sink and PlanCtx's " +
		"OOBConfig serves DNS and HTTP callbacks and no SMTP"
	ann["route_override_not_scored"] = "X-Original-URL and X-Rewrite-URL are most famous for making a " +
		"proxy's access-control decision disagree with the application's routing, turning a 403 on /admin " +
		"into a 200. That is an ACCESS CONTROL finding with a status-and-body oracle, and scoring it here " +
		"would file it under a host-header heading and hide it from the class that should own it. This " +
		"class sends those headers carrying an absolute URL and scores only the authority"
	ann["reflection_is_not_injection"] = "every detector here goes through pxHostInAuthorityPosition. Our " +
		"host printed into a debug block is not our host in a URL, and the two are the same twenty bytes"

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		return one(hhNothingSent(ctx))
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	honest, skips := pxHonest(own)
	skips = append(skips, pxNotObserved(hhPlannedFor(ctx.Slot.Name), own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every value this class asked to put in "+ctx.Slot.Name+" was "+
				"refused, altered or left unsubstituted, so no host of ours was ever offered to the "+
				"application and nothing is known about what it would have built from one",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	if base, off := pxRouteRedirectsOffOrigin(ctx); off {
		ann["route_already_redirects_off_origin"] = base
	}

	readings := hhRead(honest)
	ann["arms"] = hhDescribeArms(readings)

	// THE DETECTOR CONTROL, ASKED BEFORE ANY POSITIVE. It is a function rather than two blocks
	// here because a test in this package cannot drive Classify: a non-empty OwnedResponses can
	// only be built by the vault's own package, by the same internal rule that stops a classifier
	// minting into another class's partition. An arm that could only be read by eye is the arm
	// that got into this state, so it is exercised directly instead. corsPositive is split for
	// the same reason and says so.
	if v, fired := hhControlVerdict(readings, ctx.Slot.Name, ann, ords, skips, one); fired {
		return v
	}

	// THE POSITIVES. Location first: a browser acts on it with nothing for the user to read.
	for _, r := range readings {
		if r.probe == hhNC1 || !r.inLocationAuthority {
			continue
		}
		ann["winning_probe"] = string(r.probe)
		ann["value_sent"] = r.sent
		ann["location"] = r.location
		ann["resolution"] = r.resolutionNote
		v := one(triage.StateFinding,
			"routing_header_reaches_the_location: the response is a "+pxCount(r.status, "redirect")+
				" whose Location resolves to a host we named in "+ctx.Slot.Name+". The authority came from "+
				"a header the client controls, which means the application is building its redirect target "+
				"from an input a browser never sends and a proxy is expected to set. A victim who follows "+
				"a link to this endpoint lands on our host, with whatever the application appended to the "+
				"URL. There is no interpretation step in this oracle: the Location was resolved under both "+
				"the RFC 3986 and the WHATWG models and the authority is ours ("+r.resolutionNote+")",
			"routing_header_in_location", triage.GradeHigh, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: r.ordinal, Phrase: "Location: " + r.location,
			Matched: []byte(r.location), Wire: triage.PayloadWire{Logical: []byte(r.sent)},
		}
		return v
	}

	// Then the body, in authority position and nowhere else.
	for _, r := range readings {
		if r.probe == hhNC1 || !r.inBodyAuthority {
			continue
		}
		ann["winning_probe"] = string(r.probe)
		ann["value_sent"] = r.sent
		ann["authority_offsets"] = r.bodyOffsets
		v := one(triage.StateFinding,
			"routing_header_becomes_a_url_authority: the response body carries a URL whose AUTHORITY is a "+
				"host we named in "+ctx.Slot.Name+", at "+pxCount(len(r.bodyOffsets), "position(s)")+
				". The test is positional and not a search: the host is immediately preceded by // or by @ "+
				"and followed by a delimiter, which is what separates an absolute URL the application built "+
				"from the same bytes printed into a debug block. Every absolute URL this endpoint emits is "+
				"therefore attacker-controlled, which is the mechanism behind poisoned password-reset "+
				"links, poisoned script and stylesheet sources, and poisoned form actions",
			"routing_header_in_url_authority", triage.GradeHigh, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: r.ordinal, Phrase: "authority=" + r.host, Offset: r.firstOffset,
			Length: len(r.host), Matched: []byte(r.host), Wire: triage.PayloadWire{Logical: []byte(r.sent)},
		}
		return v
	}

	// A filter answering is not the application answering, and this is the last thing asked before
	// a clean. The baseline goes in so an endpoint that correctly IGNORES the header, and answers
	// identically because nothing changed, is not mistaken for one that blocked it.
	if pxUniformBlock(ctx, honest) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct values for "+ctx.Slot.Name+" produced "+
				"byte-identical non-baseline responses, so something in front answered and no URL builder "+
				"was reached",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// AND THE STATE THE GATE ABOVE CANNOT SPEAK ABOUT. pxUniformBlock has a floor of three
	// distinct payloads and this class can reach the clean below with two, so "the gate did not
	// fire" was being read as "the gate was asked and passed" on exactly the endpoints the gate
	// exists for. Plan now buys the third value when round 0 is block-shaped, so this arm should
	// be rare; it is here because the round-1 probe can still be refused by the operator's tier,
	// by the risk ceiling, by the budget or by the encoder, and a clean may not depend on which.
	if v, fired := hhFloorRefusal(honest, hhBaselineBody(ctx.Route), ctx.Slot.Name, ann, ords, skips, one); fired {
		return v
	}

	// THE LAST THING ASKED BEFORE A CLEAN. No class may reach clean while one of its own declared
	// positive routes is a positive it never sent a probe at. The set is scoped to THIS header:
	// HH-U1 and HH-U2 are never planned on an authority header, so the routes that need them are
	// not this slot's question, and treating them as uncovered would turn every clean on
	// X-Forwarded-Host into an unknown.
	if unprobed := pcUnprobedDeclaredPositives(c.OracleCases(), hhPlannedFor(ctx.Slot.Name), honest); len(unprobed) > 0 {
		ann["declared_positives_not_probed"] = unprobed
		v := one(triage.StateCannotDetermine,
			"declared_positive_never_probed: this class declares routes it must fire on, and for "+
				pxCount(len(unprobed), "of them")+" not one of the probes that reaches them on "+
				ctx.Slot.Name+" was observed ("+strings.Join(unprobed, "; ")+"). Nothing was measured "+
				"about those sinks, and a clean that silently omits a whole payload family is the shape "+
				"this family already shipped once",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// The negatives. Which one is right is decided by the control and by where the value landed.
	return hhCleanVerdict(readings, ctx.Slot.Name, len(honest), ann, ords, skips, one)
}

// hhCleanVerdict is this class's negative, split out of Classify for the reason hhControlVerdict
// was: no test in this package can build a resolved Replay, so a block living inline in Classify
// can only be read by eye, and an arm that could only be read by eye is how the control that
// could never fire survived a round. sent is the number of this class's own probes that reached
// the wire, which is the denominator every sentence below quotes.
func hhCleanVerdict(readings []hhReading, header string, sent int, ann map[string]any,
	ords []uint64, skips []triage.ProbeSkip,
	one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict,
) []triage.ClassVerdict {
	reflectedSomewhere := false
	// THE THREE CHANNELS THIS CLEAN MAY NOT DENY, COLLECTED BEFORE A WORD OF IT IS WRITTEN.
	//
	// A CLEAN THAT CONTRADICTS ITS OWN PLANNER IS THE DEFECT BEING FIXED HERE. hhSawAnyReachIn
	// reads the body, the Location UNGATED BY STATUS, and every response header, and it bought
	// round 1 on /hosthdr/loc200 because it found the value in a Location on a 200. The clean
	// then said "Nothing we put in this header came back in any form". Both statements are about
	// the same three responses and only one of them can be true.
	var unfollowed, unfollowedInert string
	var unfollowedCount, unfollowedStatus int
	echoHeaders := map[string]bool{}
	for _, r := range readings {
		if r.probe == hhNC1 {
			if r.unfollowedLocationAuthority {
				unfollowedInert = r.sent
			}
			continue
		}
		if r.inBodyAnywhere {
			reflectedSomewhere = true
		}
		if r.unfollowedLocationAuthority {
			unfollowedCount++
			if unfollowed == "" {
				unfollowed, unfollowedStatus = r.unfollowedLocation, r.status
			}
		}
		for _, n := range r.otherHeaderEchoes {
			echoHeaders[n] = true
		}
	}
	echoNames := make([]string, 0, len(echoHeaders))
	for n := range echoHeaders {
		echoNames = append(echoNames, n)
	}
	sort.Strings(echoNames)
	ann["value_reaches_the_response_body"] = reflectedSomewhere
	ann["value_reaches_an_unfollowed_location"] = unfollowedCount > 0
	if unfollowed != "" {
		ann["unfollowed_location"] = unfollowed
		ann["unfollowed_location_status"] = unfollowedStatus
	}
	if len(echoNames) > 0 {
		ann["value_reaches_these_response_headers"] = echoNames
	}

	precond := []string{
		"every probe counted here put its value into " + header + " on the wire intact",
		"no response carried a host under " + hhHostSuffix + " in AUTHORITY POSITION in its body",
	}
	// THE CONTROL LINE IS ONLY PRINTED WHERE THERE WAS A CONTROL. hhControlVerdict returns before
	// this function on every control that DID produce an authority, so reaching here with a
	// control read means it produced none. Reaching here WITHOUT one means nobody checked, and a
	// precondition list is read as a list of checks that passed.
	if _, ok := hhFindReading(readings, hhNC1); ok {
		precond = append(precond, "the control "+string(hhNC1)+" produced no authority a client "+
			"would act on, so the positional test was not silently true")
	} else {
		precond = append(precond, "NOT CHECKED: "+string(hhNC1)+" was not among this class's "+
			"readings on this slot, so nothing here rules out a positional test that would have "+
			"been true of any value at all")
	}
	// THE PRECONDITION THAT WAS FALSE ON /hosthdr/loc200. It used to read "no response carried a
	// Location resolving, under either model, to a host under <suffix>", full stop. One did. The
	// line now carries the status gate that is the actual check, and where that gate is the only
	// thing that kept the Location out, it says so instead of denying the Location.
	if unfollowedCount > 0 {
		precond = append(precond, "NOT CHECKED AS WRITTEN: "+pxCount(unfollowedCount,
			"response(s)")+" DID carry a Location whose authority is a host we named, on a status "+
			"no client follows. What held here is the narrower fact: no response WITH A REDIRECT "+
			"STATUS carried one")
	} else {
		precond = append(precond, "no response with a REDIRECT STATUS (300, 301, 302, 303, 305, "+
			"307, 308) carried a Location resolving, under either model, to a host under "+hhHostSuffix)
	}

	reason := "no_url_authority_was_built: this class offered " + pxCount(sent, "distinct values") +
		" in " + header + ", every one naming a host nobody can register, and no URL in any " +
		"response took its authority from one of them"
	oracle := "no_authority_from_this_header"

	// THE STRONGEST FACT FIRST, AND THE THREE ARE NOT EXCLUSIVE, so the weaker ones are appended
	// rather than dropped.
	switch {
	case unfollowedCount > 0:
		oracle = "url_authority_only_in_an_unfollowed_location"
		reason = "authority_built_but_only_where_nothing_follows_it: this class offered " +
			pxCount(sent, "distinct values") + " in " + header + ", every one naming a host nobody " +
			"can register, and " + pxCount(unfollowedCount, "response(s)") + " came back carrying a " +
			"LOCATION WHOSE AUTHORITY IS THE HOST WE NAMED (" + unfollowed + ") on status " +
			strconv.Itoa(unfollowedStatus) + ". THE STATE IS CLEAN AND THAT IS A DECISION ABOUT THE " +
			"PROTOCOL RATHER THAN A GUESS: 300, 301, 302, 303, 305, 307 and 308 are the statuses on " +
			"which a client follows a Location, and this response is not one of them. Nothing here " +
			"redirects anybody, so there is no redirect to report and this is not the finding " +
			"/hosthdr/location produces. WHAT IT IS NOT IS SILENCE, WHICH IS WHAT THIS ROW USED TO SAY: the " +
			"application reads this header and concatenates it into an absolute URL. THE LIMIT OF " +
			"THE MEASUREMENT, STATED BECAUSE IT IS THE WHOLE DIFFERENCE BETWEEN THIS ROW AND A " +
			"FINDING: this class asked this endpoint, at this slot, with these values, and it " +
			"cannot see whether any other request to the same handler answers with a redirect " +
			"status. Next: replay_request at this endpoint on a path or with a credential that " +
			"makes it redirect, and read the Location"
		if unfollowedInert != "" {
			reason += ". AND THE SINK DID NO CHECK OF ANY KIND: the inert control " + string(hhNC1) +
				" sent " + unfollowedInert + ", which has no dot, no slash, no colon and no scheme " +
				"and cannot be a hostname, and it came back in the same position. A sink that " +
				"accepted that will accept a hostname"
		}
		precond = append(precond, "THE VALUE REACHED AUTHORITY POSITION, in a Location on a status "+
			"no client follows. It is recorded here rather than denied, and it is the one fact "+
			"this clean used to contradict")
		if reflectedSomewhere {
			reason += ". It is in the body too, and never as the authority of a URL there"
		}
	case reflectedSomewhere:
		oracle = "reflected_but_never_an_authority"
		precond = append(precond, "the value DID come back in the body, and never in authority position, "+
			"which is reflection and not injection")
		reason += ". THE VALUE DOES COME BACK: it appears in the body and never as the authority of a URL, " +
			"so the application reads this header and prints it rather than building URLs from it. That is " +
			"a stronger clean than silence, because it shows the header reaches the application"
	case len(echoNames) > 0:
		oracle = "reflected_in_a_response_header_never_an_authority"
		precond = append(precond, "the value DID come back, in a response header and never in "+
			"authority position")
		reason += ". THE VALUE DOES COME BACK, IN A RESPONSE HEADER (" + pxNameList(echoNames) +
			") AND NOWHERE ELSE, so the application reads this header. The match is on this " +
			"probe's own sixteen-byte marker, so something copied our value there and no rotating " +
			"token can have produced it. WHAT IS NOT ESTABLISHED is the thing this class scores: " +
			"no URL took its authority from our value, in a body or in a Location, so there is " +
			"nothing here a client resolves against a host we chose"
	default:
		if _, ok := hhFindReading(readings, hhNC1); ok {
			precond = append(precond, "the control reached the wire and its value did not come back either, "+
				"so nothing here shows the application reads this header at all")
			reason += ". Nothing we put in this header came back in any form, so this is the weaker clean: " +
				"the application may not read the header, or may read it only somewhere this probe cannot see"
		} else {
			precond = append(precond, "NOTE: the control did not reach the wire, so the annotation about "+
				"whether this header reaches the response is absent rather than false")
		}
	}
	// ONLY WHERE THE BRANCH ABOVE HAS NOT ALREADY SAID IT. The header case names the headers in
	// its own sentence; the body case does not, and a value that is in both is two facts.
	if unfollowedCount == 0 && reflectedSomewhere && len(echoNames) > 0 {
		reason += ". IT IS ALSO IN A RESPONSE HEADER (" + pxNameList(echoNames) + "), named here " +
			"and not read as an effect of our value"
	}
	precond = append(precond, "AND THE ONE THAT MATTERS MOST: an outbound email built from this header "+
		"is invisible to every probe here, so this clean does not cover it")
	ann["clean_preconditions"] = precond
	v := one(triage.StateClean, reason, oracle, triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// Settle. There is nothing out of band to wait for, and the one thing that would need it, an
// email, has no sink in this layer. That is annotated on every verdict rather than deferred.
func (hostHeaderClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

func hhNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is neither " +
				"a control to difference against nor evidence about this endpoint's cacheability, and " +
				"nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain", "", triage.GradeUnrated, nil
	}
	// THE LAST TWO ARMS LIVE IN pxNothingSentTail AND THE ORDER IS THE WHOLE POINT. See
	// pxbudgetarm.go: ctx.Budget here is what the run has left when the verdict is written, and
	// the sentence this arm used to carry was about what the planner was shown. Reading it first
	// also put not_planned below a condition that holds on every capped run.
	//
	// THE DERIVATION QUESTION IS ASKED OF hhProbesFor, WHICH IS THE PLANNER ITSELF. On this class
	// it is non-empty wherever hhEligible passed, so the not_planned arm stays unreachable here;
	// that is now a property of the planner rather than a side effect of arm order, and it is
	// asserted by a test.
	state, reason := pxNothingSentTail(ctx, len(hhProbesFor(ctx.Slot.Name, 0)), "a host-header probe",
		"no host-header probe was derived for this slot and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// ---------------------------------------------------------------------------------------------
// THE DETECTOR. POSITIONAL, ALWAYS.
// ---------------------------------------------------------------------------------------------

// hhReading is one probe's answer.
type hhReading struct {
	probe   triage.ProbeID
	ordinal uint64
	sent    string
	// host is the authority token THIS probe would produce, derived from what it sent. It is not
	// rebuilt from the marker: HH-NC1 sends "hh-<marker>-inert" and rebuilding gave it a needle
	// it never sends, which is what made the control gate unreachable.
	host   string
	status int
	// isControl marks HH-NC1. The control's readings are scored at a different oracle from the
	// payloads', so the two must not be told apart by a probe-id comparison spelled out at each
	// use: one of those was already missing.
	isControl bool
	// fabricatedSuffix: a host under hhHostSuffix carrying this marker appeared in authority
	// position although THIS probe never sent one. Nothing the application does can produce that,
	// so it is a rewritten value or a foreign response, and it is the one true detector failure
	// this class can observe.
	fabricatedSuffix bool

	// inBodyAnywhere is a plain substring reading. IT IS NOT AN ORACLE and nothing branches to a
	// finding on it. It exists so a clean can say which of two very different silences it is
	// describing.
	inBodyAnywhere bool
	// inBodyAuthority is the oracle: our host is the AUTHORITY of a URL in the body.
	inBodyAuthority bool
	bodyOffsets     []int
	firstOffset     int

	inLocationAuthority bool
	location            string
	resolutionNote      string

	// THE SECOND LOCATION READING, WHICH REPORTS AND NEVER SCORES. inLocationAuthority is gated
	// on pxIsRedirectStatus because no client acts on a Location carried by a 200, and that gate
	// is right. What was wrong is that the ungated fact was then thrown away, so the clean below
	// said "nothing came back in any form" about /hosthdr/loc200, whose every response carries
	// "Location: https://<our X-Forwarded-Host>/account/reset". hhSawAnyReachIn had already read
	// that same Location, ungated by status, and spent two extra requests on it.
	unfollowedLocation          string
	unfollowedLocationAuthority bool
	unfollowedResolutionNote    string

	// otherHeaderEchoes are the NON-VOLATILE response headers, Location aside, whose value
	// carries this probe's marker. Same rule: named in the clean, never scored. A clean that
	// says nothing came back while our value sits in a response header is the same false
	// sentence in a different channel.
	otherHeaderEchoes []string
}

// hhAuthorityNeedle is THE HOST THIS PROBE WOULD PUT IN AN AUTHORITY, derived from the bytes the
// probe actually sent rather than rebuilt from the marker.
//
// THE BUG IT EXISTS TO CLOSE, AND IT IS THE ONE triageStore.go:880 WARNS ABOUT BY NAME. hhRead
// used to set the needle to "<marker>.hh.invalid" for EVERY probe. That is right for HH-A1, HH-A2,
// HH-U1 and HH-U2, whose payloads all name that host. It is WRONG FOR HH-NC1, whose payload is
// "hh-<marker>-inert": the detector searched for a string the control never sends, so
// inBodyAuthority and inLocationAuthority were permanently false on the control and the gate at
// the top of Classify was STRUCTURALLY UNREACHABLE. A control that cannot fire reads exactly like
// a control that passed, and every positive on the slot was resting on it.
//
// MEASURED: /hosthdr/wrapinert answers {"site":"https://hh-<marker>-inert/"}, which is the control
// value in authority position, and the class reported finding / routing_header_in_url_authority /
// high, with the same reason text it gives on /hosthdr/absurl.
//
// THE DERIVATION IS DELIBERATELY SMALL AND DOES NOT PARSE. Strip a leading scheme or a leading
// "//", cut at the first character that ends an authority, drop any userinfo, drop any port. What
// is left is the host, which is what pxHostInAuthorityPosition is looking for. A payload family
// this class does not have yet would fall out of it unchanged rather than silently wrong.
//
// AND IT KEEPS THE ATTRIBUTION RULE. The needle must still carry THIS probe's own marker; without
// it the token names nothing this probe can be held responsible for and the empty string is
// returned, which every caller reads as "no oracle for this probe".
func hhAuthorityNeedle(sent string, m triage.Marker) string {
	v := strings.TrimSpace(sent)
	for _, p := range []string{"https://", "http://", "//"} {
		if len(v) >= len(p) && strings.EqualFold(v[:len(p)], p) {
			v = v[len(p):]
			break
		}
	}
	if i := strings.IndexAny(v, "/?#"); i >= 0 {
		v = v[:i]
	}
	if i := strings.LastIndex(v, "@"); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndex(v, ":"); i >= 0 {
		v = v[:i]
	}
	if m == "" || !strings.Contains(strings.ToLower(v), strings.ToLower(string(m))) {
		return ""
	}
	return v
}

// hhHeaderEchoes names the NON-VOLATILE response headers, Location aside, whose value carries
// this probe's marker.
//
// IT REPORTS AND IT NEVER SCORES. The match is on THIS PROBE'S OWN MARKER, sixteen bytes minted
// for this probe in this run, so unlike the difference-based pxHeaderWitness it cannot be
// satisfied by a rotating token or by any header that merely changes: something copied our value
// into that header. What it does NOT establish is the only thing this class scores, which is
// whether the application built a URL AUTHORITY out of it, and that is why the finding arms are
// positional and this is a sentence in a clean.
//
// The volatile list is consulted anyway, because a Date or a Content-Length that happened to
// contain sixteen matching bytes would be a coincidence and not a reading. Location is excluded
// here because it has two readings of its own above.
func hhHeaderEchoes(o triage.Observation, m triage.Marker) []string {
	if m == "" {
		return nil
	}
	needle := strings.ToLower(string(m))
	seen := map[string]bool{}
	var out []string
	for _, kv := range o.RespHeaders {
		n := strings.ToLower(strings.TrimSpace(kv[0]))
		if n == "" || n == "location" || pxVolatileHeader(n) || seen[n] {
			continue
		}
		if strings.Contains(strings.ToLower(kv[1]), needle) {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// hhRead reduces this class's own honest observations to readings.
func hhRead(honest []faOwnObs) []hhReading {
	out := make([]hhReading, 0, len(honest))
	for _, o := range honest {
		r := hhReading{
			probe: o.ProbeID, ordinal: o.Ordinal, sent: string(o.Obs.Payload.Logical),
			status: o.Obs.Status, isControl: o.ProbeID == hhNC1,
		}
		if o.Marker == "" {
			out = append(out, r)
			continue
		}
		r.host = hhAuthorityNeedle(r.sent, o.Marker)
		if r.host == "" {
			out = append(out, r)
			continue
		}

		// THE IMPOSSIBLE NEEDLE, KEPT AND CORRECTLY NAMED. A probe that did not send a host under
		// this class's suffix cannot cause one to appear in an authority. If it does, our value
		// was rewritten on the way through, or a response from another probe or another run is
		// being served here, and no positive on this slot can be trusted. That is the detector
		// failure the old control check was reaching for; it is not what /hosthdr/wrapinert does.
		if fabricated := string(o.Marker) + hhHostSuffix; !strings.EqualFold(r.host, fabricated) {
			if _, ok := pxHostInAuthorityPosition(o.Obs.Body, fabricated); ok {
				r.fabricatedSuffix = true
			}
			if loc, ok := pxLocation(o.Obs); ok {
				if _, ok := pxHostInAuthorityPosition([]byte(loc), fabricated); ok {
					r.fabricatedSuffix = true
				}
			}
		}

		if _, ok := faByteForm(o.Obs.Body, []byte(o.Marker)); ok {
			r.inBodyAnywhere = true
		}
		if at := pxHostAuthorityOffsets(o.Obs.Body, r.host); len(at) > 0 {
			r.inBodyAuthority = true
			r.bodyOffsets = at
			r.firstOffset = at[0]
		}

		// THE TWO READINGS THAT REPORT AND NEVER SCORE. Both exist because the clean below said
		// "Nothing we put in this header came back in any form" about /hosthdr/loc200, whose every
		// response carries "Location: https://<our X-Forwarded-Host>/account/reset".
		r.otherHeaderEchoes = hhHeaderEchoes(o.Obs, o.Marker)
		if loc, ok := pxLocation(o.Obs); ok && !pxIsRedirectStatus(o.Obs.Status) {
			if _, hit := pxHostInAuthorityPosition([]byte(loc), r.host); hit {
				r.unfollowedLocation = loc
				r.unfollowedLocationAuthority = true
			} else {
				strict, browser := pxResolveBoth(pxBaseURL(o.Obs), loc)
				if strict.Host == r.host || browser.Host == r.host {
					r.unfollowedLocation = loc
					r.unfollowedLocationAuthority = true
					r.unfollowedResolutionNote = pxDescribeResolutions(strict, browser)
				}
			}
		}

		// The Location arm. A Location on a non-redirect status is not followed by any browser, so
		// it is not SCORED: an API that echoes a Location into a 200 would otherwise be a finding
		// on every vector. It is READ just above, because a clean that denies the reflection
		// happened is a different and equally wrong answer.
		if loc, ok := pxLocation(o.Obs); ok && pxIsRedirectStatus(o.Obs.Status) {
			r.location = loc
			strict, browser := pxResolveBoth(pxBaseURL(o.Obs), loc)
			r.resolutionNote = pxDescribeResolutions(strict, browser)
			if strict.Host == r.host || browser.Host == r.host {
				r.inLocationAuthority = true
			}
			// A Location the application built by concatenating our host into a longer URL is
			// caught by the positional test over the raw header value, which the resolvers would
			// miss when the reference does not parse as one they can resolve.
			if !r.inLocationAuthority {
				if _, ok := pxHostInAuthorityPosition([]byte(loc), r.host); ok {
					r.inLocationAuthority = true
					r.resolutionNote += "; matched by the positional test over the raw Location rather " +
						"than by resolution, so the reference did not resolve to an authority under either model"
				}
			}
		}
		out = append(out, r)
	}
	return out
}

// hhControlVerdict is the control's two answers, in order. It returns false when the control
// reached the wire and produced no authority, which is the state every positive arm below it
// depends on and which used to be unreachable in the other direction.
func hhControlVerdict(readings []hhReading, header string, ann map[string]any, ords []uint64,
	skips []triage.ProbeSkip, one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict,
) ([]triage.ClassVerdict, bool) {
	// THE DETECTOR CONTROL, ASKED BEFORE ANY POSITIVE, AND IT ANSWERS TWO DIFFERENT QUESTIONS.
	//
	// ARM 0a, THE REAL DETECTOR FAILURE. A host under this class's suffix, carrying this probe's
	// marker, in authority position, in answer to a probe that never sent such a host. No
	// application can produce that from what we gave it: our value was rewritten on the way
	// through, or a response belonging to another probe or another run is being served here.
	// Every positive on this slot rests on the same authority test, so none of them is reported.
	for _, r := range readings {
		if !r.fabricatedSuffix {
			continue
		}
		ann["fabricating_probe"] = string(r.probe)
		ann["value_sent"] = r.sent
		v := one(triage.StateCannotDetermine,
			"detector_unverified (value_rewritten): "+string(r.probe)+" sent "+r.sent+", which names no "+
				"host under "+hhHostSuffix+", and the response nonetheless carries "+string(r.probe)+
				"'s own marker under "+hhHostSuffix+" IN AUTHORITY POSITION. Nothing the application does "+
				"to the value we sent can produce a host we did not send, so either something in the path "+
				"rewrote our value into one of this class's hosts or a response belonging to another probe "+
				"or another run is being served on this slot. Every positive this class could reach here "+
				"rests on the same authority test, so none of them is reported",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v, true
	}

	// ARM 0b, THE UNVALIDATED SINK, AND IT IS A FINDING RATHER THAN AN UNKNOWN. HH-NC1 carries no
	// dot, no slash, no colon and no scheme: it is not a hostname and no allowlist, regular
	// expression or parse can mistake it for one. If it comes back as the AUTHORITY of a URL, the
	// application put a scheme in front of whatever arrived in this header and did not look at it.
	//
	// WHY THIS IS NOT detector_unverified, WHICH IS WHAT THIS CLASS USED TO CLAIM. The old comment
	// said the positional test "cannot separate a URL the application built from our value from
	// one it would have built from anything". Read that again: a URL the application would build
	// from ANYTHING is a URL it builds from an attacker's host. There is nothing to separate. The
	// attacker does not need the sink to like the value; they need it to accept one, and a sink
	// that accepted a value that cannot be a hostname will accept a hostname.
	//
	// MEASURED, AND IT IS WHY THIS ARM HAD TO BE WRITTEN RATHER THAN THE OLD ONE REPAIRED.
	// /hosthdr/absurl and /hosthdr/wrapinert are THE SAME HANDLER SHAPE: both answer
	// "https://" + the routing header + a path, confirmed by hand on 2026-09-19. One is declared a
	// positive and one was declared a control-fires negative. No deterministic classifier can give
	// two answers to one behaviour, and of the two available answers the exploitable one is the
	// one that must win: reporting cannot_determine here would silence the single commonest real
	// form of this bug, the password-reset template that concatenates the header with no check.
	//
	// The unconditionality is reported ON TOP of the surface rather than instead of it, because a
	// Location a browser acts on and a link in a body still need different reports.
	if nc, ok := hhFindReading(readings, hhNC1); ok && (nc.inBodyAuthority || nc.inLocationAuthority) {
		oracle, surface := "routing_header_in_url_authority_unconditional", "a URL in the response body"
		if nc.inLocationAuthority {
			oracle, surface = "routing_header_in_location_unconditional", "the Location of a "+
				pxCount(nc.status, "response")
			ann["location"] = nc.location
			ann["resolution"] = nc.resolutionNote
		} else {
			ann["authority_offsets"] = nc.bodyOffsets
		}
		ann["control_landed_in_authority"] = true
		ann["winning_probe"] = string(hhNC1)
		ann["value_sent"] = nc.sent
		ann["payload_arms_that_also_reached_an_authority"] = hhArmsInAuthority(readings)
		v := one(triage.StateFinding,
			"routing_header_authority_is_unconditional: "+string(hhNC1)+" is the INERT CONTROL. It carries "+
				"no dot, no slash, no colon and no scheme, so it is not a hostname and no allowlist, "+
				"regular expression or URL parse can mistake it for one. It came back as the AUTHORITY of "+
				surface+". The application therefore puts a scheme in front of whatever arrives in "+
				header+" and never looks at it, which is a WEAKER check than a permissive "+
				"allowlist rather than a broken detector: an attacker does not need this sink to like "+
				"their host, only to accept one, and it accepted a value that cannot be a host at all. "+
				"WHAT THIS COSTS IS THE ATTRIBUTION, AND IT IS SAID RATHER THAN HIDDEN: on a sink this "+
				"unconditional the positional test cannot show that the URL was built from a HOST-SHAPED "+
				"payload specifically, because it would have been built from anything. The proof here is "+
				"the sink's unconditionality and not the shape of the payload. Reproduce with any value "+
				"at all in this header and read it back out of the URL",
			oracle, triage.GradeHigh, ords)
		v[0].Untested = skips
		ev := triage.TriageEvidence{
			Ordinal: nc.ordinal, Phrase: "authority=" + nc.host, Offset: nc.firstOffset,
			Length: len(nc.host), Matched: []byte(nc.host), Wire: triage.PayloadWire{Logical: []byte(nc.sent)},
		}
		if nc.inLocationAuthority {
			ev = triage.TriageEvidence{
				Ordinal: nc.ordinal, Phrase: "Location: " + nc.location,
				Matched: []byte(nc.location), Wire: triage.PayloadWire{Logical: []byte(nc.sent)},
			}
		}
		v[0].Evidence = ev
		return v, true
	}

	return nil, false
}

// hhArmsInAuthority names the PAYLOAD probes whose own value also reached an authority. It is
// recorded on the unconditional finding so that an operator can see the arm the class would have
// reported had the sink been selective, rather than losing it behind the control's answer.
func hhArmsInAuthority(rs []hhReading) []string {
	var out []string
	for _, r := range rs {
		if r.isControl || !(r.inBodyAuthority || r.inLocationAuthority) {
			continue
		}
		where := "body"
		if r.inLocationAuthority {
			where = "Location"
		}
		out = append(out, string(r.probe)+" ("+where+"): sent "+r.sent)
	}
	return out
}

func hhFindReading(rs []hhReading, id triage.ProbeID) (hhReading, bool) {
	for _, r := range rs {
		if r.probe == id {
			return r, true
		}
	}
	return hhReading{}, false
}

// hhDescribeArms renders every arm for the annotations, so an operator reading a clean can see
// what each value was actually answered with rather than trusting a summary.
func hhDescribeArms(rs []hhReading) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		line := string(r.probe) + ": sent " + r.sent + " -> "
		switch {
		case r.inLocationAuthority:
			line += "AUTHORITY OF THE LOCATION (" + r.location + ")"
		case r.inBodyAuthority:
			line += "AUTHORITY OF A URL IN THE BODY"
		case r.inBodyAnywhere:
			line += "present in the body, never in authority position"
		default:
			line += "not present in the response"
		}
		out = append(out, line)
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// THE TOOL POINTER
// ---------------------------------------------------------------------------------------------

func hhLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"nuclei": "the DAST host-header template set, as a second detector on a slot this class has " +
			"already implicated",
		"manual": "there is no host-header container in this framework. The exploit step is a judgement " +
			"about the application: which absolute URL matters. A poisoned script source is stored XSS, a " +
			"poisoned form action is a credential capture, and a poisoned reset link is account takeover, " +
			"and deciding which of those this endpoint builds is not a scan",
		"email": "THE HIGHEST-VALUE TEST IS NOT IN THIS LAYER. Find the password-reset, invite and " +
			"email-verification endpoints, send them with this header set, and read the mail. Nothing in " +
			"this class can see that, and a clean here says nothing about it",
	}
	if w, ok := ann["winning_probe"].(string); ok {
		hints["winning_probe"] = w
		hints["next"] = "reproduce with replay_request against the composed URL, setting the header " +
			"recorded in the header annotation to the value in value_sent, and look for the authority in " +
			"the Location or in the body"
	}
	if _, ok := ann["cache_safety_refusal"]; ok {
		hints["cache"] = "nothing was sent here because the response looks shared-cacheable. Point the " +
			"cache tooling at this vector instead: an unkeyed routing header on a storable response is web " +
			"cache poisoning, and confirming it is exactly the thing this class refused to do by accident"
	}
	return triage.TriageLabel{Tools: []string{"nuclei"}, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (hostHeaderClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "authority_position_not_substring", Probes: hhAllProbeIDs(),
			Rule: "a hit requires pxHostInAuthorityPosition or a Location resolving to our host. Our host " +
				"printed into a debug block, an error page, a JSON string field or a log excerpt is " +
				"REFLECTION and must never score. The two are the same bytes and the difference is the " +
				"whole class",
		},
		{
			Name: "the_inert_control_is_scored_against_what_it_sent", Probes: []triage.ProbeID{hhNC1},
			Rule: "the control's oracle must be built from the bytes " + string(hhNC1) + " ACTUALLY SENT, " +
				"which are hh-<marker>-inert. Rebuilding it from the marker as <marker>" + hhHostSuffix +
				", which is what the other four probes send and this one does not, hands the control a " +
				"needle it never puts on the wire: the gate is then structurally unreachable and a " +
				"control that CANNOT fire reads exactly like a control that passed",
		},
		{
			Name: "the_control_separates_a_rewrite_from_an_unvalidated_sink", Probes: []triage.ProbeID{hhNC1},
			Rule: "a host under " + hhHostSuffix + " in authority position on a probe that never sent one " +
				"is a rewrite or a foreign response and makes every verdict on the slot " +
				"detector_unverified. " + string(hhNC1) + "'s OWN value in authority position is a " +
				"different fact: the application wraps anything it is given, which is a FINDING at its " +
				"own oracle. Collapsing the two silences the commonest real form of this bug, the reset " +
				"template that concatenates the header with no check at all",
		},
		{
			Name: "location_only_on_a_redirect_status", Probes: hhAllProbeIDs(),
			Rule: "a Location on a 200 is followed by no browser and must not be scored. Without this rule " +
				"an API that echoes a Location into a successful response is a finding on every vector",
		},
		{
			Name: "this_probes_own_marker", Probes: hhAllProbeIDs(),
			Rule: "the authority must carry THIS probe's own 16-byte marker. A host under " + hhHostSuffix +
				" built from another marker is another probe's, another run's, or a cached response, and " +
				"the run id inside the marker is what makes the last of those distinguishable",
		},
		{
			Name: "cache_gate_before_the_first_request", Probes: hhAllProbeIDs(),
			Rule: "pcSharedCacheRisk is asked of the route control in Plan BEFORE anything is sent and " +
				"again in Classify so the refusal produces a row. A routing header is unkeyed on a shared " +
				"cache and this class has no cache-busting token, so a storable response means not_probed",
		},
		{
			Name: "the_email_blind_spot_is_on_every_verdict", Probes: hhAllProbeIDs(),
			Rule: "email_side_channel_not_measured is annotated on every state this class can reach, " +
				"including clean. A clean that did not say so would be read as covering the password-reset " +
				"exploit, which is the form of this bug that actually gets paid",
		},
	}
}

func (hostHeaderClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "authority_offsets", Kind: "content", What: "where in the body each URL taking its authority from our header sits, so an operator can see what kind of URL it is: a script source, a form action or a link"},
		{Name: "location", Kind: "protocol", What: "the raw Location exactly as the server wrote it, plus both resolutions. Raw is the point: normalising it first throws away the very forms the class is measuring"},
		{Name: "winning_header", Kind: "annotation", What: "which of the routing headers got through. Host and X-Forwarded-Host need different fixes, and X-Original-URL points at a proxy rewrite rather than at application code"},
		{Name: "winning_form", Kind: "annotation", What: "bare authority, authority with a port, absolute URL or scheme-relative. It decides whether the injected authority can name a port and whether a scheme blacklist is in the path"},
		{Name: "value_reaches_the_response_body", Kind: "differential", What: "whether the control's value came back at all, which tells a clean whether the application reads this header and prints it safely or appears not to read it"},
		{Name: "email_side_channel_not_measured", Kind: "annotation", What: "on every verdict including clean: the password-reset form of this bug produces an identical response and is invisible here"},
	}
}

// OracleCases. EVERY ROUTE BELOW EXCEPT THE LAST NOW EXISTS and Exists says so: they were
// declared as a build list, docker/oracle/round4.go built them, and each was confirmed serving
// its own X-Ars0n-Oracle header on 2026-09-19. The two negatives are the ones doing the work.
//
// AND ONE DECLARATION IN THIS LIST WAS WRONG, WHICH IS WORTH MORE THAN THE NINE THAT WERE RIGHT.
// /hosthdr/wrapinert was declared a control-fires NEGATIVE. It is byte-identical in mechanism to
// /hosthdr/absurl, which is declared a POSITIVE: both answer "https://" + the routing header + a
// path, measured by hand. No deterministic classifier can give two answers to one behaviour, so
// one of the two declarations had to go, and the exploitable reading is the one that survives.
// The case is a positive now and says why.
func (hostHeaderClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "xfh_becomes_a_link_authority", Route: "/hosthdr/absurl", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{hhA1}, WantState: triage.StateFinding,
			Why: "a route that builds an absolute URL from X-Forwarded-Host and puts it in the body, as a " +
				"password-reset page does. IT DOES NO CHECK OF ANY KIND, measured by hand: it answers " +
				"the inert control with https://hh-<marker>-inert/account/reset too. So the verdict owed " +
				"is a finding at grade high at oracle routing_header_in_url_authority_unconditional and " +
				"not at routing_header_in_url_authority: the stronger fact about this route is that the " +
				"sink accepts a value that cannot be a hostname, and a class reporting the weaker oracle " +
				"would be describing an allowlist that is not there. The specific oracle is what " +
				"/hosthdr/originalurl and /hosthdr/nohttp still produce, because those two build an " +
				"authority only from a value that already carried one",
		},
		{
			Name: "xfh_becomes_a_location", Route: "/hosthdr/location", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{hhA1}, WantState: triage.StateFinding,
			Why: "a route that 302s to an absolute URL built from X-Forwarded-Host. The Location arm must " +
				"fire and must be reported ahead of the body arm, because a browser acts on it with " +
				"nothing for the user to read. This route also wraps the inert control, so the oracle " +
				"owed is routing_header_in_location_unconditional: the SURFACE distinction survives the " +
				"unconditional reading rather than being collapsed into it, because a Location a " +
				"browser follows and a link in a body still need different reports",
		},
		{
			Name: "reflected_but_not_an_authority", Route: "/hosthdr/echo", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{hhA1, hhNC1}, WantState: triage.StateClean,
			Why: "THE MOST IMPORTANT CASE IN THE CLASS. A route that prints the X-Forwarded-Host value into " +
				"a debug block as plain text, with no scheme and no slashes in front of it. The response " +
				"contains our exact host and the verdict must be CLEAN, with the annotation recording that " +
				"the value reaches the response. A detector that searched for the bytes passes every " +
				"positive above and fails this one, and it would fire on every framework with a verbose " +
				"error page",
		},
		{
			Name: "location_on_a_200_is_not_a_redirect", Route: "/hosthdr/loc200", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{hhA1}, WantState: triage.StateClean,
			Why: "a route that answers 200 and sets a Location built from our header. No browser follows " +
				"it, so it must not score. Without this case the class fires on any API that echoes a " +
				"Location into a successful response. THE ORACLE OWED IS " +
				"url_authority_only_in_an_unfollowed_location AND NOT no_authority_from_this_header: " +
				"the value DOES come back, in authority position, in a Location the protocol says " +
				"nothing acts on. The weaker oracle means the application may not read this header, " +
				"and here it demonstrably does. This class spent two extra requests on that " +
				"reflection (hhSawAnyReachIn bought round 1 with it) and then reported that nothing " +
				"came back, which is the contradiction this case now pins",
		},
		{
			Name: "host_ignored_entirely", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{hhA1, hhNC1}, WantState: triage.StateClean,
			Why: "the shipped echo route builds no absolute URL from any header. Clean, at the weaker " +
				"oracle no_authority_from_this_header, with the clean preconditions recording that nothing " +
				"came back and therefore that the application may simply not read this header",
		},
		{
			Name: "xoriginalurl_absolute", Route: "/hosthdr/originalurl", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{hhU1}, WantState: triage.StateFinding,
			Why: "a route that treats X-Original-URL as a base and builds links from it. It is the case " +
				"that justifies a second payload family: HH-A1's bare authority in this header is a " +
				"relative path and would test nothing, and a class that sent only HH-A1 would report clean " +
				"here",
		},
		{
			Name: "port_survives_into_the_authority", Route: "/hosthdr/portconcat", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{hhA1, hhA2}, WantState: triage.StateFinding,
			Why: "a route that concatenates the RAW X-Forwarded-Host into a URL rather than parsing it, " +
				"so HH-A2's :8443 survives into the authority. It is what separates a sink that copies " +
				"the header from one that splits it on the colon and keeps the host, and an attacker who " +
				"can name a port is in a different position from one who can only name a hostname",
		},
		{
			Name: "scheme_blacklist_walked_past", Route: "/hosthdr/nohttp", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{hhU1, hhU2}, WantState: triage.StateFinding,
			Why: "a route that rejects any X-Rewrite-URL containing the string http and otherwise treats " +
				"the value as a base URL. HH-U1 is refused and HH-U2, which has no scheme in it at all, " +
				"reaches the same sink. It is the case that justifies U2 as a probe rather than a " +
				"spelling: a class shipping only U1 reports clean on the commonest filter there is",
		},
		{
			Name: "storable_response_is_refused", Route: "/hosthdr/cacheable", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{hhA1}, WantState: triage.StateNotProbed,
			Why: "a route carrying Cache-Control: public, max-age=600 with no Vary and no cookie. Nothing " +
				"may be sent: a routing header is unkeyed, so a poisoned entry would be served to the next " +
				"visitor. not_probed with the evidence named, and never clean",
		},
		{
			Name: "the_sink_wraps_anything", Route: "/hosthdr/wrapinert", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{hhNC1}, WantState: triage.StateFinding,
			Why: "a route that wraps WHATEVER it is given in https:// and prints it, so even the inert " +
				"control's value lands in authority position. IT WAS DECLARED A NEGATIVE HERE AND THAT " +
				"WAS WRONG, on two measurements. First, the class could not fire on it for the reason " +
				"the declaration imagined: hhRead built the control's needle from the marker as " +
				"<marker>" + hhHostSuffix + " while " + string(hhNC1) + " sends hh-<marker>-inert, so " +
				"the gate was structurally unreachable and the route came back finding / " +
				"routing_header_in_url_authority / high, the same answer it gives on /hosthdr/absurl. " +
				"Second, and the reason repairing the needle alone was not enough: this route and " +
				"/hosthdr/absurl are THE SAME HANDLER SHAPE, so one behaviour was declared as two " +
				"different verdicts and no classifier can honour both. A sink that wraps a value which " +
				"cannot be a hostname will wrap an attacker's hostname, which is the bug, so the verdict " +
				"owed is a finding at oracle routing_header_in_url_authority_unconditional, whose reason " +
				"states the attribution the unconditionality costs rather than hiding it",
		},
		{
			Name: "the_control_value_is_rewritten", Route: "/hosthdr/fabricatesuffix", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{hhNC1}, WantState: triage.StateCannotDetermine,
			Why: "THE ROUTE THIS CLASS STILL OWES, and the only shape that is a genuine detector failure " +
				"rather than an unvalidated sink. A route that answers ANY value in the routing header " +
				"with an absolute URL whose authority is the first token of that value plus " +
				hhHostSuffix + ", so the response carries <marker>" + hhHostSuffix + " in authority " +
				"position although " + string(hhNC1) + " sent hh-<marker>-inert and named no such host. " +
				"Nothing an application does to our value can produce a host we did not send, so the " +
				"verdict must be detector_unverified (value_rewritten) and no positive on the slot may " +
				"be reported. Without this route the rewrite arm has a fixture nowhere and is one " +
				"refactor from disappearing, which is how the control got into this state",
		},
	}
}
