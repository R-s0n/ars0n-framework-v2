package triageclasses

import (
	"net/url"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS CORS (id 28). CROSS-ORIGIN RESOURCE SHARING: we name an origin, and the response says
// whether a page at that origin may read this response and whether it may send our cookies.
//
// WHY IT GETS ID 28 RATHER THAN A RESERVED ONE. CATALOGUE 1.0 reserved twenty-seven ids and none
// of them is CORS. 28 is the next free number after CSVI(27) and it is claimed in
// utils/triage/types.go with the reasoning written beside it. The id is also the marker's ordinal
// stripe, so borrowing an existing one would make a CORS probe's marker attributable to another
// class by arithmetic.
//
// THIS IS THE CHEAPEST DETERMINISTIC TRUE POSITIVE IN THE REGISTER AND IT IS WORTH SAYING WHY.
// Every other class in this package has to reason about a differential, a threshold, a baseline
// distribution or a reflection. This one sends ONE request carrying an Origin header and reads
// TWO response headers. There is no interpretation step, no similarity score, no noise model, and
// no dependence on the application echoing anything at all. On a JSON REST API that reflects
// nothing anywhere, which is the target shape that leaves SSTI, ELI, XSS-R, CMDI, TRAVERSAL, RFI,
// NOSQL and DESER all saying cannot_determine, this class still has an answer, because the answer
// is in the envelope and not in the body.
//
// =================================================================================================
// THE ORACLE, AND THE ONE THING THAT MAKES IT EXACT
// =================================================================================================
// Access-Control-Allow-Origin came back carrying THE EXACT ORIGIN WE SENT, and that origin is a
// host under .cors.invalid built from THIS probe's own 16-byte marker.
//
// The marker is what turns "the header is present" into "the header is present because of this
// request". A preset Access-Control-Allow-Origin naming the application's own site is correct
// behaviour and appears on a large fraction of modern APIs; a preset one naming a partner is a
// business decision; a cached response from an earlier run carries an earlier run's marker. All
// three are refused by requiring the value to be byte-equal (case-insensitively, because DNS is)
// to the origin THIS probe put on the wire.
//
// THE MARKER ALPHABET IS WHAT MAKES THIS POSSIBLE AND IT IS NOT A COINCIDENCE. A marker is 16
// bytes over [0-9a-z] with a letter first, which is exactly the shape of a legal DNS label, so
// "<marker>.cors.invalid" is a syntactically valid host and "https://<marker>.cors.invalid" is a
// syntactically valid RFC 6454 origin. No other class in this package gets its attribution token
// for free in the position the oracle needs it.
//
// =================================================================================================
// FIVE DIFFERENT BUGS, FIVE DIFFERENT SEVERITIES, AND THE VERDICT SAYS WHICH
// =================================================================================================
//
//	reflected origin + Allow-Credentials: true   FINDING, high    any page reads authenticated data
//	reflected origin, no credentials             FINDING, medium  matters where auth is not a cookie
//	Allow-Origin: null (from any arm)            FINDING, high    a sandboxed iframe sends null
//	Allow-Origin: * with credentials: true       SUSPICIOUS       browsers refuse the pair; the
//	                                                              server is still wrong and a
//	                                                              non-browser client is not bound
//	origin echoed although it is NOT AN ORIGIN   FINDING, high    CORS-NC1 has no scheme, so a
//	                                                              server that echoes it is doing
//	                                                              raw string reflection with no
//	                                                              parse at all, and every allowlist
//	                                                              in front of it is decoration
//
// AND THE TWO SHAPES THAT MUST STAY SILENT, which are the cases that decide whether this class is
// a detector or a noise generator:
//
//	Allow-Origin equals the application's OWN origin, whatever we sent    CLEAN
//	no Access-Control-* header at all                                     CLEAN
//
// =================================================================================================
// WHAT THIS CLASS STRUCTURALLY CANNOT SEE, SAID PLAINLY RATHER THAN LEFT AS SILENCE
// =================================================================================================
//
// (1) PREFIX AND SUFFIX MATCHING ARE NOT MEASURED, AND THE REASON IS A SUBSTITUTION THIS LAYER
// DOES NOT OFFER. The bugs are real and common: a server checking origin.endsWith("target.com")
// lets https://eviltarget.com through, and one checking origin.startsWith("https://target.com")
// lets https://target.com.evil.com through. Testing either requires THE TARGET'S OWN HOSTNAME
// inside the payload bytes. A ProbeSpec's Logical is static and the runner substitutes exactly two
// grammars into it, the dollar-brace family and the angle-bracket family, and
// triageUsesDollarTokens and triageUsesAngleTokens both name a closed list of five classes that
// does not and should not include this one. There is no vector-host token. So the probes are NOT
// SHIPPED rather than shipped in a form that tests something else, and every verdict carries
// prefix_suffix_match_not_measured so that a clean here is never read as covering them.
//
// (2) THE NULL ORIGIN IS MEASURED SIDEWAYS, AND THE REASON IS THE ISOLATION LAW. The direct probe
// is an Origin header whose value is the four bytes "null". ClassNoSQL(5) already declares a probe
// whose logical payload is byte-equal to those four bytes, and isolation check I1b refuses a
// second class the same bytes, correctly: a block or a rejection of "null" could not then be
// attributed to either class. So the direct probe is not shipped. What IS shipped is the arm that
// catches the same bug from the other side and costs no extra request: if ANY of this class's
// arbitrary-origin probes comes back with Access-Control-Allow-Origin: null, and the unperturbed
// control does not carry it, the server maps an unrecognised origin onto null, which is precisely
// what a sandboxed iframe, a data: URL and a cross-origin redirect all send. The case this cannot
// reach is an allowlist that literally contains the string null while rejecting everything else,
// and that case is named in the annotations rather than covered by silence.
//
// (3) PREFLIGHT IS NOT MEASURED. Access-Control-Allow-Methods and Access-Control-Allow-Headers
// only appear in response to an OPTIONS request carrying Access-Control-Request-Method. The runner
// replays the captured verb (Slot.Method) and no probe may change it, so this class never sends an
// OPTIONS and never sees a preflight response. A permissive preflight on an endpoint whose simple
// response is correctly locked down is invisible here and is annotated as such.
//
// =================================================================================================
// THE SAFETY QUESTION: THIS CLASS CAN POISON A SHARED CACHE AND IS GATED ON THAT
// =================================================================================================
// An Origin header is UNKEYED on most shared caches. If the application reflects our origin into
// Access-Control-Allow-Origin and the response is stored by a CDN without Vary: Origin, the next
// user of that URL is served a response that hands read access to an attacker-named origin. That
// is the textbook CORS cache poisoning, the finding IS "another user got my response", and the
// brief's non-destructive rule forbids anything that persists for other users.
//
// CRLF does not have this problem because its marker rides in the query string, which is part of
// the cache key on every cache that keys on the request target, so its poisoned entry is one
// nobody else will ever request. THIS CLASS'S MARKER IS IN A HEADER. There is no cache-busting
// token it can add, because the encoder only touches the slot it was given.
//
// So the class asks pcSharedCacheRisk of the unperturbed control BEFORE it sends anything, and
// where the answer is yes it emits not_probed with the reason naming the header that said so. It
// fails CLOSED: no control, no probe. That is a refusal on safety grounds, which is a named
// unknown and is not a clean.
type corsClassifier struct{}

func init() { triage.RegisterClassifier(corsClassifier{}) }

func (corsClassifier) ID() triage.ClassID { return triage.ClassCORS }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	corsA1  triage.ProbeID = "CORS-A1"
	corsA2  triage.ProbeID = "CORS-A2"
	corsA3  triage.ProbeID = "CORS-A3"
	corsA4  triage.ProbeID = "CORS-A4"
	corsNC1 triage.ProbeID = "CORS-NC1"
)

// corsHostSuffix is the only authority this class will ever call a finding.
//
// RFC 6761 section 6.4 reserves .invalid and guarantees it never resolves, so no payload here
// names a domain anybody could register and then actually receive a cross-origin read on, and a
// target that tried to contact the origin reaches nothing. The label is distinct from REDIRECT's
// .rdr.invalid, RFI's .rfi-inband.invalid and HOSTHDR's .hh.invalid so that no operator and no
// log line can confuse one class's traffic with another's.
const corsHostSuffix = ".cors.invalid"

// corsHeaderSlot is the ONE slot this class is defined on. It is a lowercase header name because
// triageHeaderSlots lowercases every name it emits, and the key is "header:origin".
const corsHeaderSlot = "origin"

// The response headers this class reads. Named as constants because each one appears in a reason
// string, an annotation and a detector, and three spellings of the same header is how a detector
// quietly stops matching.
const (
	corsACAO  = "Access-Control-Allow-Origin"
	corsACAC  = "Access-Control-Allow-Credentials"
	corsACEH  = "Access-Control-Expose-Headers"
	corsACAPN = "Access-Control-Allow-Private-Network"
	corsVary  = "Vary"
)

var corsPoints = []triage.SlotKind{triage.KindHeader}

var corsEncoders = []triage.EncoderMode{triage.EncodeHeaderValue}

func (corsClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassCORS
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: corsA1, Class: c, Logical: []byte("https://" + m + corsHostSuffix),
			Encoders: corsEncoders, Points: corsPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "THE SERIOUS ONE, and the whole class in one request. A syntactically perfect RFC 6454 " +
				"origin over https, naming a host nobody can register, built from this probe's own marker. " +
				"If it comes back in Access-Control-Allow-Origin the server reflects arbitrary origins, and " +
				"if Access-Control-Allow-Credentials is also true then any page on the internet can read " +
				"this endpoint's authenticated responses with the victim's own cookies attached",
		},
		{
			ID: corsA2, Class: c, Logical: []byte("http://" + m + corsHostSuffix),
			Encoders: corsEncoders, Points: corsPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "THE SCHEME DISCRIMINATOR, and it is a separate probe rather than a spelling of A1 " +
				"because the two answers mean different things. Both reflected: the server does no scheme " +
				"check at all, so an attacker on a plaintext origin, which includes anything reachable by " +
				"a network attacker, is inside the trust boundary. A1 reflected and A2 refused: the server " +
				"HAS a scheme check, which is a named partial defence worth recording on the verdict " +
				"rather than collapsing into the same finding. A2 alone reflected is a downgrade path onto " +
				"an https site",
		},
		{
			ID: corsA3, Class: c, Logical: []byte("https://" + m + corsHostSuffix + ":31337"),
			Encoders: corsEncoders, Points: corsPoints,
			Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "A NON-DEFAULT PORT. An origin is a triple of scheme, host and port, and a comparison " +
				"that parses the URL and then compares only the hostname treats https://site:31337 as " +
				"https://site. On its own that is a same-site port confusion; here it also separates a " +
				"server that echoes the header verbatim, which returns the port, from one that " +
				"reconstructs the origin from a parse, which drops it. The port is recorded on the " +
				"verdict because the two behaviours need different fixes. Full tier: it costs a request " +
				"and it only adds detail to an answer A1 already gave",
		},
		{
			ID: corsA4, Class: c, Logical: []byte("https://" + m + corsHostSuffix + ", https://x" + m + corsHostSuffix),
			Encoders: corsEncoders, Points: corsPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "TWO ORIGINS IN ONE HEADER. The Fetch standard sends exactly one, so a server that " +
				"accepts a list is parsing something the protocol never produces, and a list parser in " +
				"front of an allowlist is how an attacker smuggles an origin past a check that only ever " +
				"examines the first entry. Both hosts carry THIS probe's marker, the second behind an 'x' " +
				"label, so the verdict can say which entry came back: the whole list, the first only, or " +
				"the second only. Each of those is a different parser bug. " +
				"REDUCED TIER, AND THAT IS A CORRECTION MEASURED ON /cors/originlist RATHER THAN A " +
				"PREFERENCE. This probe was at full tier and behind the round-1 reflection gate, which " +
				"between them meant it never went out on the one route it exists for: that route sets " +
				"Access-Control-Allow-Origin ONLY when it can split the header on a comma and parse the " +
				"second entry, so a single plain origin is answered with no CORS header at all, round 0 " +
				"sees no reflection, the gate closes and the class reports CLEAN on a list-parsing " +
				"allowlist bypass. A probe that is the ONLY WAY TO REACH A SINK is not detail, and " +
				"putting it at a tier the operator may not have bought is the same silent zero by " +
				"another route. One request",
		},
		{
			ID: corsNC1, Class: c, Logical: []byte(m + corsHostSuffix),
			Encoders: corsEncoders, Points: corsPoints,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE CONTROL, AND IT IS WORTH MORE THAN THE REST OF THE LADDER. A bare hostname is NOT " +
				"AN ORIGIN: RFC 6454 requires a scheme, and no browser ever sends this. A server that " +
				"parses the Origin header at all, or compares it against anything, cannot match it and " +
				"must not reflect it. Its first job is to catch a detector built on 'the marker is " +
				"somewhere in the response headers' rather than on 'Allow-Origin equals what we sent'. " +
				"ITS SECOND JOB IS THAT A HIT IS STILL REPORTED, at a distinct oracle: a server that " +
				"echoes a value that is not an origin is doing raw string reflection of a request header " +
				"with no parse in front of it, which is a WORSE bug than A1, not a broken control, because " +
				"it means whatever allowlist the developers believe they wrote is never consulted",
		},
	}
}

// corsRound0 is three requests: the two schemes and the control. The control goes out in round 0
// and not after a hit, because a detector whose false-positive guard only runs on the targets
// where it already fired has no guard.
func corsRound0() []triage.ProbeID { return []triage.ProbeID{corsA1, corsA2, corsNC1} }

// ROUND 1 IS GATED PER PROBE AND NOT PER ROUND, AND THE COMMENT THAT USED TO STAND HERE WAS
// WRONG. It read:
//
//	"unlike the gate CRLF deleted this one is safe, because what round 1 adds is DETAIL ABOUT A
//	 REFLECTION ROUND 0 ALREADY SAW, never the reflection itself."
//
// THE ROUTE THAT REFUTES IT IS THIS CLASS'S OWN DECLARED POSITIVE. /cors/originlist sets
// Access-Control-Allow-Origin ONLY when it can split the Origin header on a comma and parse the
// SECOND entry as an origin. A single plain origin gets nothing back at all. So round 0, which is
// three single origins, sees no Access-Control-Allow-Origin anywhere, the round gate closes, and
// CORS-A4 never leaves the process. MEASURED against the oracle on 2026-09-19:
//
//	CORS  clean  no_acao_at_all  sent=3   on /cors/originlist   (every reflecting route: sent=5)
//
// Against a real list-parsing allowlist bypass this class stated CLEAN.
//
// THE CLAIM WAS HALF TRUE AND THE HALF IS WHAT MADE IT DANGEROUS. CORS-A3 really is detail: it
// asks whether a non-default port survives a grant that round 0 already saw, and that question
// does not exist on a server that reflected nothing. CORS-A4 IS A SECOND REFLECTION MECHANISM:
// it reaches a list parser that no single-origin probe can reach, and it is the only probe in
// this class that can. A gate written per ROUND cannot tell those two apart, so it withheld both
// on exactly the evidence the second one exists to produce.

// corsRound1Ungated is the round-1 probe that goes out WHETHER OR NOT round 0 saw a reflection,
// because it reaches a sink no other probe in this class reaches.
func corsRound1Ungated() []triage.ProbeID { return []triage.ProbeID{corsA4} }

// corsRound1Gated is the round-1 probe that is genuinely detail about a reflection round 0
// already saw, and is withheld until there is one to add detail to.
func corsRound1Gated() []triage.ProbeID { return []triage.ProbeID{corsA3} }

// corsRound1For is the gate itself, as a pure function over the one fact it depends on, so a test
// in this package can exercise both answers. Plan cannot be driven from here: it refuses without
// a resolved route control and a resolved Replay needs a capability whose type lives in an
// internal package, by the same design that stops a classifier minting into another class's vault
// partition. A gate that could only be read by eye is a gate that regresses.
func corsRound1For(sawReflection bool) []triage.ProbeID {
	if sawReflection {
		return append(corsRound1Gated(), corsRound1Ungated()...)
	}
	return corsRound1Ungated()
}

// corsRound1 is every round-1 probe, which is what the declaration checks and the cost model need.
func corsRound1() []triage.ProbeID { return corsRound1For(true) }

func corsAllProbeIDs() []triage.ProbeID { return append(corsRound0(), corsRound1()...) }

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. This class lives in exactly one place and every other answer is never WITH A REASON,
// which is what keeps "ruled out" visibly different from "nobody wired this up".
//
// NOTE THE GRANULARITY MISMATCH AND THE FACT THAT IT IS HANDLED ELSEWHERE. Reaches is asked about
// a slot KIND, and this class is defined on one particular header NAME. A header slot that is not
// Origin is refused in Plan and answered not_applicable in Classify, both at zero request cost.
// Reaches cannot express that, so it answers conditional for the kind and names the condition.
func (corsClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "CONDITIONAL ON THE HEADER BEING Origin, AND ON THIS BEING A HEADER VECTOR. " +
				"header:origin is emitted by triageInferredHeaders on every vector whose insertion_point " +
				"column is header, whether or not the crawl captured an Origin, and NOT on a vector " +
				"recorded as query, body, cookie or path: SlotsFor dispatches on that column and a query " +
				"vector yields query slots only. The inferred set is what makes the class usable at all, " +
				"because a browser sends Origin only on cross-origin and non-GET requests, so a crawl " +
				"capture almost never carries one. Every other header slot is not_applicable at zero " +
				"request cost. Request media type is irrelevant to this class and is recorded only for " +
				"the row: " + string(mt),
		}
	case triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the CORS decision is made from the Origin REQUEST HEADER and from nothing else. A " +
				"value in a " + string(k) + " slot cannot become the origin the server compares against, " +
				"so a probe here would measure a different mechanism and report it under this class's name",
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

func (c corsClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := corsEligible(ctx.Slot); !ok {
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
		return corsPlanFor(corsRound0(), ctx.Slot)
	case 1:
		return corsPlanFor(corsRound1For(corsSawAnyReflection(ctx)), ctx.Slot)
	default:
		return nil
	}
}

func corsPlanFor(ids []triage.ProbeID, slot triage.Slot) []triage.ProbeRequest {
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		out = append(out, pxReq(id, slot.Key))
	}
	return out
}

// corsSawAnyReflection is the gate on the DETAIL probe, and it reads THIS CLASS'S OWN round-0
// responses only.
//
// It is deliberately loose: any Access-Control-Allow-Origin at all that is not the application's
// own origin is enough to buy CORS-A3. A tight gate here would cost nothing to get wrong in the
// other direction, because A3 cannot discover a reflection that round 0 missed. THAT SENTENCE IS
// TRUE OF A3 AND WAS FALSE OF A4, WHICH IS WHY THEY ARE NO LONGER GATED TOGETHER.
func corsSawAnyReflection(ctx triage.PlanCtx) bool {
	return corsSawReflectionIn(faOwn(ctx.Own), corsSelfOrigin(ctx.Vector.ComposedURL))
}

// corsSawReflectionIn is the same question over a resolved own-set, so Classify can ask it too:
// Classify has to know which round-1 probes were PLANNED before it can say which were skipped,
// and a second, independently written copy of this rule is how the two answers drift apart.
func corsSawReflectionIn(own []faOwnObs, self string) bool {
	for _, o := range own {
		if o.Err != nil {
			continue
		}
		for _, v := range pxRespHeader(o.Obs, corsACAO) {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}
			if self != "" && strings.EqualFold(v, self) {
				continue
			}
			return true
		}
	}
	return false
}

// corsEligible is this class's per-slot gate, and it costs no requests.
func corsEligible(s triage.Slot) (string, bool) {
	if reason, ok := faEligibleSlot(s); !ok {
		return reason, false
	}
	if s.Kind != triage.KindHeader {
		return "cors_is_a_request_header_mechanism: the browser's CORS decision is made from the Origin " +
			"request header, and this slot is a " + string(s.Kind) + " slot. Probing it would measure " +
			"something else entirely and file the answer under this class", false
	}
	if !strings.EqualFold(strings.TrimSpace(s.Name), corsHeaderSlot) {
		return "not_the_origin_header: this class is defined on the Origin request header and this slot " +
			"is " + s.Name + ". Every HEADER vector carries a header:origin slot, emitted by " +
			"triageInferredHeaders whether or not the crawl saw one, so this class is not short of a " +
			"place to run; it simply does not belong here", false
	}
	return "", true
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

func (c corsClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassCORS, key, state, reason, oracle, grade, ords, ann, corsLabel(ann))
	}

	if reason, ok := corsEligible(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}

	// THE SAFETY REFUSAL, FIRST, BECAUSE IT DECIDES WHETHER ANYTHING WAS SENT. It is asked again
	// here and not only in Plan so that the refusal produces a ROW rather than a silence: a slot
	// that was deliberately not probed and a slot nobody wired up are otherwise the same pixel.
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
			"shared_cache_poisoning_risk: "+why+". An Origin header is UNKEYED on essentially every "+
				"shared cache, so if this endpoint reflects our origin and the response is stored, the next "+
				"user of this URL is served a response granting read access to an origin we named. That is "+
				"the finding itself happening to somebody else, and this layer will not do it. THIS CLASS "+
				"CANNOT BUST THE CACHE: its marker rides in a header rather than in the request target, "+
				"which is exactly why CRLF is safe on the same endpoint and this is not. Re-run this slot "+
				"against a request whose response is not shared-cacheable, or confirm by hand",
			"", triage.GradeUnrated, nil)
	}

	corsBlindSpots(ann)

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		return one(corsNothingSent(ctx))
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	honest, skips := pxHonest(own)
	self := corsSelfOrigin(ctx.Vector.ComposedURL)
	// THE PLANNED SET IS RECONSTRUCTED, NOT ASSUMED. It used to be corsRound0() alone, which gave
	// a round-1 probe that never went out no skip row at all: the probe was simply absent and the
	// coverage read as if the ladder had run. Round 1 is planned per probe now, so the set depends
	// on the same reflection question Plan asked, and corsSawReflectionIn is the single copy of it.
	planned := append(corsRound0(), corsRound1For(corsSawReflectionIn(own, self))...)
	skips = append(skips, pxNotObserved(planned, own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every Origin header this class asked for was refused, altered or "+
				"left unsubstituted, so no origin was ever offered to the application and nothing is known "+
				"about what it would have allowed",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	ann["application_own_origin"] = self
	if self == "" {
		ann["own_origin_unknown"] = "the vector's composed URL did not yield an absolute origin, so " +
			"'the server reflected only its own origin' cannot be recognised as the correct behaviour it " +
			"is. Nothing below claims a clean on that ground"
	}

	// THE DETECTOR-DISABLED CHECK, BEFORE ANY POSITIVE. A control that already carries an
	// Allow-Origin naming one of our hosts is not possible by accident, but a control carrying a
	// WILDCARD changes what every arm below means, and a control carrying null means the null arm
	// proves nothing. Both are recorded here and consulted by the arms that care.
	baseACAO, baseHadACAO := corsBaselineACAO(ctx)
	ann["baseline_allow_origin"] = baseACAO
	ann["baseline_has_allow_origin"] = baseHadACAO
	if baseHadACAO && corsIsMarkerOrigin(baseACAO) {
		v := one(triage.StateCannotDetermine,
			"detector_unverified (signature_in_baseline): the UNPERTURBED control already carries an "+
				corsACAO+" naming a host under "+corsHostSuffix+", which no application emits on its own. "+
				"Either an intermediary is echoing request headers back onto a request that carried none, "+
				"or an earlier run's response is being replayed from a cache. Either way a hit on a probe "+
				"proves nothing here",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	readings := corsRead(honest, self)
	ann["arms"] = corsDescribeArms(readings)

	// THE POSITIVES, IN SEVERITY ORDER, AND EACH ONE NAMES A DIFFERENT BUG WITH A DIFFERENT FIX.
	if v, ok := corsPositive(readings, ctx, ann, ords, skips, one); ok {
		return v
	}

	// Nothing was reflected. Three negatives, and which one is right is decided by the control and
	// by the baseline, never by the absence of a header alone.
	if pxUniformBlock(ctx, honest) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct Origin values produced byte-identical "+
				"non-baseline responses, so something in front answered and the application's CORS logic "+
				"was never reached. An endpoint that correctly IGNORES the Origin header answers identically "+
				"because nothing changed, and that case is excluded by differencing against the control "+
				"rather than only against the other probes",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	anyACAO := false
	for _, r := range readings {
		if r.acaoPresent {
			anyACAO = true
			break
		}
	}
	ann["endpoint_emits_cors_headers"] = anyACAO

	// THE LAST THING ASKED BEFORE A CLEAN, AND IT IS THE RULE THE ROUND-1 GATE BROKE. No class may
	// reach clean while one of its own declared positive routes is a positive it never sent a
	// probe at.
	if unprobed := pcUnprobedDeclaredPositives(c.OracleCases(), corsAllProbeIDs(), honest); len(unprobed) > 0 {
		ann["declared_positives_not_probed"] = unprobed
		v := one(triage.StateCannotDetermine,
			"declared_positive_never_probed: this class declares routes it must fire on, and for "+
				pxCount(len(unprobed), "of them")+" not one of the probes that reaches them was observed "+
				"on this slot ("+strings.Join(unprobed, "; ")+"). Nothing was measured about those sinks, "+
				"and a negative that silently omits a whole mechanism is the shape this class already "+
				"shipped once: CORS-A4 was withheld by a round-level gate and /cors/originlist, a "+
				"list-parsing allowlist bypass, read as clean at oracle no_acao_at_all",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	precond := []string{
		"every probe counted here put its Origin header on the wire intact",
		"no " + corsACAO + " came back carrying any host under " + corsHostSuffix,
		"no " + corsACAO + " came back as null",
		"the unperturbed control carries no " + corsACAO + " of ours, so the detector was not disabled by the baseline",
	}
	reason := "origin_not_reflected: this class offered " + pxCount(len(honest), "distinct origins naming "+
		"hosts nobody can register") + " and " + corsACAO + " never came back carrying one of them. The " +
		"oracle is byte equality against the exact origin sent, so this negative depends on no threshold, " +
		"no baseline distribution and no similarity score"
	oracle := "no_acao_at_all"
	if anyACAO {
		oracle = "acao_is_the_applications_own_origin"
		precond = append(precond, "the endpoint DOES emit "+corsACAO+", and it named its own origin "+
			"("+self+") regardless of what we sent, which is the correct implementation rather than an absence")
		reason += ". The endpoint does speak CORS and answered with its own origin whichever origin we " +
			"offered, which is the shape of a correct allowlist and not of a missing feature"
	} else {
		precond = append(precond, "the endpoint emitted no "+corsACAO+" on any probe, so no cross-origin "+
			"page may read this response at all")
		reason += ". No " + corsACAO + " was emitted on any arm, so there is no cross-origin grant here to " +
			"misconfigure"
	}
	if nc, ok := corsFindReading(readings, corsNC1); ok {
		ann["control_reached_the_wire"] = true
		ann["control_was_echoed"] = nc.reflectedExact
	} else {
		precond = append(precond, "NOTE: the non-origin control did not reach the wire, so the claim "+
			"that this endpoint parses rather than echoes rests on the positive arms alone")
	}
	ann["clean_preconditions"] = precond
	v := one(triage.StateClean, reason, oracle, triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// Settle. Every answer this class can give arrives in the same response as the probe.
func (corsClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

func corsNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"control to read a baseline " + corsACAO + " off and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain", "", triage.GradeUnrated, nil
	}
	// THE LAST TWO ARMS LIVE IN pxNothingSentTail AND THE ORDER IS THE WHOLE POINT. They used to
	// read the budget FIRST, at classify time, and assert that the cap was reached before this
	// class sent anything, which is a claim about plan time that nothing here witnessed. That put
	// not_planned below a condition that is true on every capped run, so a planner gap was
	// reported to the operator as a pacing problem. pxbudgetarm.go has the measurement.
	state, reason := pxNothingSentTail(ctx, len(corsRound0()), "a CORS probe",
		"no CORS probe was derived for this slot and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// corsBlindSpots stamps the three sentences that stop a clean from this class being read as
// covering something it never measured.
//
// IT IS A FUNCTION RATHER THAN THREE LINES IN Classify FOR ONE REASON: a test in this package
// cannot build a resolved route control, so it cannot reach the part of Classify that would carry
// these, and a blind spot that is only documented on a code path no test can enter is a blind
// spot one refactor away from disappearing. corsBlindSpotKeys is the list a test asserts against.
func corsBlindSpots(ann map[string]any) {
	ann["prefix_suffix_match_not_measured"] = "a server matching the origin by prefix or by suffix " +
		"(origin.startsWith(\"https://target\") or origin.endsWith(\"target.com\")) is a real and common " +
		"bug and is NOT tested here. Both probes need the target's own hostname inside the payload bytes, " +
		"and this layer substitutes only the dollar-brace and angle-bracket grammars, neither of which is " +
		"offered to this class and neither of which carries a vector-host token. The probes are not " +
		"shipped rather than shipped in a form that tests something else"
	ann["preflight_not_measured"] = "Access-Control-Allow-Methods and Access-Control-Allow-Headers appear " +
		"only in response to an OPTIONS request carrying Access-Control-Request-Method. The runner replays " +
		"the captured verb and no probe may change it, so this class never sends a preflight. A permissive " +
		"preflight on an endpoint whose simple response is locked down is invisible from here"
	ann["null_origin_measured_indirectly"] = "the direct probe is an Origin header of the four bytes null, " +
		"which ClassNoSQL already declares, and isolation check I1b refuses two classes the same bytes. " +
		"What is measured instead: Allow-Origin coming back as null in answer to an arbitrary origin, " +
		"which is the same bug seen from the other side. An allowlist that literally contains null while " +
		"rejecting everything else is not reached"
}

// corsBlindSpotKeys is what corsBlindSpots must set, as data, so the test and the function cannot
// drift apart without one of them failing.
func corsBlindSpotKeys() []string {
	return []string{
		"prefix_suffix_match_not_measured",
		"preflight_not_measured",
		"null_origin_measured_indirectly",
	}
}

// ---------------------------------------------------------------------------------------------
// THE DETECTOR. IT READS TWO RESPONSE HEADERS AND NEVER THE BODY.
// ---------------------------------------------------------------------------------------------

// corsReading is one probe's answer, reduced to the facts the arms below branch on.
type corsReading struct {
	probe   triage.ProbeID
	ordinal uint64
	// sent is the exact origin string this probe put on the wire, recovered from the payload
	// record rather than re-derived, because re-deriving it would re-introduce the marker
	// substitution this class does not perform.
	sent string
	// acao is the FIRST Access-Control-Allow-Origin value, trimmed. acaoPresent is separate
	// because an empty header is not the same fact as no header.
	acao        string
	acaoPresent bool
	credentials bool
	// reflectedExact: Allow-Origin is byte-equal, case-insensitively, to what we sent.
	reflectedExact bool
	// reflectedOurHost: Allow-Origin names a host under our suffix carrying THIS probe's marker,
	// without being byte-equal to what we sent. That is the list-parse and port-drop case.
	reflectedOurHost bool
	wildcard         bool
	null             bool
	variesOnOrigin   bool
	exposeHeaders    string
	privateNetwork   bool
}

// corsRead reduces this class's own honest observations to readings.
func corsRead(honest []faOwnObs, self string) []corsReading {
	out := make([]corsReading, 0, len(honest))
	for _, o := range honest {
		r := corsReading{probe: o.ProbeID, ordinal: o.Ordinal, sent: string(o.Obs.Payload.Logical)}
		if v := pxRespHeader(o.Obs, corsACAO); len(v) > 0 {
			r.acaoPresent = true
			r.acao = strings.TrimSpace(v[0])
		}
		for _, v := range pxRespHeader(o.Obs, corsACAC) {
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				r.credentials = true
			}
		}
		for _, v := range pxRespHeader(o.Obs, corsACAPN) {
			if strings.EqualFold(strings.TrimSpace(v), "true") {
				r.privateNetwork = true
			}
		}
		if v := pxRespHeader(o.Obs, corsACEH); len(v) > 0 {
			r.exposeHeaders = strings.TrimSpace(v[0])
		}
		for _, v := range pxRespHeader(o.Obs, corsVary) {
			for _, f := range strings.Split(v, ",") {
				if strings.EqualFold(strings.TrimSpace(f), "Origin") {
					r.variesOnOrigin = true
				}
			}
		}
		if r.acaoPresent {
			r.wildcard = r.acao == "*"
			r.null = strings.EqualFold(r.acao, "null")
			r.reflectedExact = r.sent != "" && strings.EqualFold(r.acao, r.sent)
			// A host under our suffix carrying THIS probe's marker, in authority position, but
			// not byte-equal to what we sent. pxHostInAuthorityPosition is reused rather than a
			// substring search for exactly the reason it exists: the marker host appearing
			// anywhere in a header value is not the same fact as it BEING the origin.
			//
			// AND EACH PROBE IS SCORED ONLY AGAINST HOSTS IT ACTUALLY SENT. The x-prefixed host
			// exists in CORS-A4's payload and in no other, so asking every probe about it gave
			// the other four an oracle they never put on the wire, which is a hit no application
			// can produce from what we gave it and therefore evidence of a rewrite rather than a
			// grant. That is the mirror of the defect HOSTHDR's control had, in the direction
			// that invents a finding instead of losing one.
			if !r.reflectedExact && o.Marker != "" {
				host := string(o.Marker) + corsHostSuffix
				if _, ok := pxHostInAuthorityPosition([]byte(r.acao), host); ok {
					r.reflectedOurHost = true
				}
				if r.probe == corsA4 {
					if _, ok := pxHostInAuthorityPosition([]byte(r.acao), "x"+host); ok {
						r.reflectedOurHost = true
					}
				}
			}
			// The bare-hostname control has no scheme, so it is not in authority position in
			// anything. Byte equality is the only reading it can have and reflectedExact above
			// already made it.
			_ = self
		}
		out = append(out, r)
	}
	return out
}

func corsFindReading(rs []corsReading, id triage.ProbeID) (corsReading, bool) {
	for _, r := range rs {
		if r.probe == id {
			return r, true
		}
	}
	return corsReading{}, false
}

// corsPositive walks the arms in severity order and returns the first that fires.
//
// THE ORDER IS THE POINT. A response that reflects an arbitrary origin AND sets credentials is one
// finding, not two, and reporting the lower-severity reading first would file a critical
// cross-origin read under "reflected origin, no credentials".
func corsPositive(rs []corsReading, ctx triage.ClassifyCtx, ann map[string]any, ords []uint64,
	skips []triage.ProbeSkip, one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict) ([]triage.ClassVerdict, bool) {

	finish := func(v []triage.ClassVerdict, r corsReading) ([]triage.ClassVerdict, bool) {
		ann["winning_probe"] = string(r.probe)
		ann["origin_sent"] = r.sent
		ann["allow_origin_returned"] = r.acao
		ann["allow_credentials"] = r.credentials
		ann["vary_on_origin"] = r.variesOnOrigin
		if r.exposeHeaders != "" {
			ann["expose_headers"] = r.exposeHeaders
		}
		if r.privateNetwork {
			ann["allow_private_network"] = true
		}
		if !r.variesOnOrigin {
			ann["missing_vary_origin"] = "the response reflects the Origin and does NOT carry Vary: Origin, " +
				"so any shared cache in front of it may store one origin's answer and serve it to another. " +
				"That turns a per-request misconfiguration into a stored one"
		}
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: r.ordinal, Phrase: corsACAO + ": " + r.acao,
			Matched: []byte(r.acao), Wire: triage.PayloadWire{Logical: []byte(r.sent)},
		}
		return v, true
	}

	// ARM 1. An origin we named came back, AND credentials are allowed. Any page on the internet
	// reads this endpoint's authenticated responses.
	for _, r := range rs {
		if (r.reflectedExact || r.reflectedOurHost) && r.credentials {
			return finish(one(triage.StateFinding,
				"reflected_origin_with_credentials: the response granted "+r.acao+" and set "+corsACAC+
					": true. We chose that origin, it is a host under "+corsHostSuffix+" built from this "+
					"probe's own marker, and nobody can register it, so the server is not honouring an "+
					"allowlist: it is echoing whatever we ask for. Any page the victim visits can read this "+
					"endpoint's response WITH THE VICTIM'S COOKIES ATTACHED. This is the whole bug and it "+
					"needs no chain",
				"reflected_origin_with_credentials", triage.GradeHigh, ords), r)
		}
	}

	// ARM 2. Allow-Origin came back as null. A sandboxed iframe, a data: URL and a cross-origin
	// redirect all send Origin: null, and all three are trivially attacker-reachable.
	for _, r := range rs {
		if !r.null {
			continue
		}
		grade, state := triage.GradeMedium, triage.StateFinding
		extra := ". Credentials are NOT allowed, so the reach is limited to whatever this endpoint " +
			"returns without them"
		if r.credentials {
			grade = triage.GradeHigh
			extra = ". Credentials ARE allowed, so a sandboxed iframe reads this endpoint's authenticated " +
				"response"
		}
		return finish(one(state,
			"null_origin_allowed: the server answered our arbitrary origin with "+corsACAO+": null, and the "+
				"unperturbed control does not carry it. Origin: null is not an exotic value: it is what a "+
				"sandboxed iframe, a data: URL and a cross-origin redirect all send, so an attacker reaches "+
				"it from any page with one iframe tag"+extra,
			"null_origin_allowed", grade, ords), r)
	}

	// ARM 3. The control was echoed. It is not an origin at all, so there is no parse in front of
	// whatever allowlist the developers believe they wrote.
	for _, r := range rs {
		if r.probe == corsNC1 && r.reflectedExact {
			return finish(one(triage.StateFinding,
				"origin_echoed_without_parsing: "+string(corsNC1)+" carries a BARE HOSTNAME with no scheme, "+
					"which RFC 6454 says is not an origin and which no browser ever sends, and the response "+
					"came back with "+corsACAO+" set to exactly those bytes. The server is copying the "+
					"request header into the response header with no parse and no comparison, so every "+
					"allowlist and every regular expression in that code path is decoration. This is a "+
					"worse sink than a permissive allowlist and it is reported at its own oracle rather "+
					"than treated as a broken control",
				"origin_echoed_without_parsing", triage.GradeHigh, ords), r)
		}
	}

	// ARM 4. An origin we named came back without credentials.
	for _, r := range rs {
		if !r.reflectedExact && !r.reflectedOurHost {
			continue
		}
		detail := ""
		if r.probe == corsA3 && !strings.Contains(r.acao, ":31337") {
			detail = ". THE PORT WAS DROPPED: we sent a non-default port and the grant came back without " +
				"one, so the server is reconstructing the origin from a parse that compares the hostname " +
				"only. A same-site service on another port is inside this trust boundary"
		}
		if r.probe == corsA4 {
			detail = ". THIS WAS THE TWO-ORIGIN PROBE: the Fetch standard sends exactly one origin, so a " +
				"server that answered a list is running a parser the protocol never feeds, and a list " +
				"parser in front of an allowlist is how an origin gets smuggled past a check that only " +
				"reads the first entry"
		}
		return finish(one(triage.StateFinding,
			"reflected_origin_without_credentials: the response granted "+corsACAO+": "+r.acao+" for an "+
				"origin we chose, and "+corsACAC+" is not true. A cross-origin page can therefore read this "+
				"response but WITHOUT the victim's cookies, so the impact turns entirely on whether this "+
				"endpoint returns anything interesting to an unauthenticated caller, or authenticates by "+
				"something other than a cookie, such as a bearer token the attacker page already holds, or "+
				"by source IP"+detail,
			"reflected_origin_without_credentials", triage.GradeMedium, ords), r)
	}

	// ARM 5. The wildcard with credentials. Browsers refuse the pair, which is why this is
	// suspicious and not a finding, and the server is still wrong.
	for _, r := range rs {
		if r.wildcard && r.credentials {
			return finish(one(triage.StateSuspicious,
				"wildcard_with_credentials: the response carries "+corsACAO+": * together with "+corsACAC+
					": true. EVERY BROWSER REFUSES THAT PAIR, so there is no direct cross-origin read here "+
					"and this is not graded as one. It is reported because the server has declared an "+
					"intention no browser will honour, which means the code path that builds these headers "+
					"is not being exercised the way its author believes, and because a non-browser client "+
					"is bound by none of it",
				"wildcard_with_credentials", triage.GradeLow, ords), r)
		}
	}

	_ = ctx
	return nil, false
}

// corsDescribeArms renders every arm's answer for the annotations, so an operator reading a clean
// can see what each origin was actually answered with rather than trusting a summary.
func corsDescribeArms(rs []corsReading) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		acao := "<no " + corsACAO + ">"
		if r.acaoPresent {
			acao = r.acao
		}
		line := string(r.probe) + ": sent " + r.sent + " -> " + acao
		if r.credentials {
			line += " +credentials"
		}
		if r.variesOnOrigin {
			line += " +Vary:Origin"
		}
		out = append(out, line)
	}
	return out
}

// corsBaselineACAO reads the unperturbed control's Allow-Origin, which is the header this class
// would otherwise mistake for its own doing.
func corsBaselineACAO(ctx triage.ClassifyCtx) (string, bool) {
	for _, r := range []triage.Replay{ctx.Route, ctx.PostBaseline} {
		if !r.Resolved() {
			continue
		}
		if v := pxRespHeader(r.Obs(), corsACAO); len(v) > 0 {
			return strings.TrimSpace(v[0]), true
		}
	}
	return "", false
}

// corsIsMarkerOrigin reports whether a value names a host under this class's suffix. It is the
// baseline-contamination test and not an oracle: the oracle requires equality with what THIS probe
// sent, and this only has to recognise the family.
func corsIsMarkerOrigin(v string) bool {
	return strings.Contains(strings.ToLower(v), corsHostSuffix)
}

// corsSelfOrigin is the application's own origin, derived from the vector's composed URL.
//
// It is what makes "the server reflected only its own origin" recognisable as the CORRECT
// behaviour it is rather than as an unexplained header. Empty when the composed URL is not
// absolute, and every path that uses it says so rather than treating empty as a match.
func corsSelfOrigin(composed string) string {
	u, err := url.Parse(composed)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

// ---------------------------------------------------------------------------------------------
// THE DECLARED-POSITIVE GATE, USED BY THIS CLASS AND BY HOSTHDR
// ---------------------------------------------------------------------------------------------
//
// THE RULE: NO CLASS MAY REACH CLEAN WHILE ONE OF ITS OWN DECLARED POSITIVE ROUTES IS A POSITIVE
// IT NEVER SENT A PROBE AT.
//
// WHY IT IS WORTH A FUNCTION RATHER THAN CARE. A class declares, in OracleCases, the routes it
// must fire on and the probes that reach each one. That declaration is the only machine-readable
// statement of what the class believes it covers. When a gate, a tier, a budget or an encoder
// drops every probe behind one of those routes, the class has stopped covering it, and the only
// place that shows is a coverage row nobody reads beside a verdict that says clean. That is
// exactly what happened here: CORS-A4 sat behind a ROUND-level gate and above the reduced tier,
// /cors/originlist answered round 0 with no CORS header at all because its bug is only reachable
// by a comma list, and the class reported clean on a list-parsing allowlist bypass.
//
// THE TEST IS PER SLOT AND THAT MATTERS. A case whose probes are ALL unplannable on this slot is
// not this slot's question: HOSTHDR's /hosthdr/nohttp names HH-U1 and HH-U2, which are never
// planned on an authority header, and treating that as uncovered would turn every clean on
// X-Forwarded-Host into an unknown. So a case is judged only where at least one of its probes is
// in the set this slot plans, and then at least one of those must have reached the wire.
//
// WHAT THIS FUNCTION CANNOT DO, SAID PLAINLY. It compares a class against ITS OWN declaration. It
// cannot tell that the vector in front of it IS /cors/originlist, because a classifier is handed
// a slot and a composed URL and not a fixture name, and it cannot check another class's
// declaration. THE CROSS-CLASS HALF OF THE RULE BELONGS IN THE EXAM HARNESS: only the harness
// knows which route a cell was measured on, so only the harness can say "class X answered clean
// on the route X itself declares a positive". That assertion belongs beside the confusion matrix
// in utils/triageMatrix_test.go, which today logs such a disagreement rather than failing on it.
//
// IT LIVES IN cors.go FOR THE SAME REASON pcSharedCacheRisk DOES: protoeffect.go, where both
// belong, was not this agent's file to edit. Both should move next to pxUniformBlock the next
// time that file is opened.
func pcUnprobedDeclaredPositives(cases []faOracleCase, plannedHere []triage.ProbeID, honest []faOwnObs) []string {
	planned := map[triage.ProbeID]bool{}
	for _, id := range plannedHere {
		planned[id] = true
	}
	observed := map[triage.ProbeID]bool{}
	for _, o := range honest {
		observed[o.ProbeID] = true
	}

	var out []string
	for _, c := range cases {
		if c.Expect != faExpectPositive || len(c.Probes) == 0 {
			continue
		}
		var here []string
		reached := false
		for _, p := range c.Probes {
			if !planned[p] {
				continue
			}
			here = append(here, string(p))
			if observed[p] {
				reached = true
			}
		}
		if len(here) == 0 || reached {
			continue
		}
		out = append(out, c.Route+" ("+c.Name+"), reachable on this slot only by "+strings.Join(here, ", "))
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// THE SHARED-CACHE SAFETY GATE, USED BY THIS CLASS AND BY HOSTHDR
// ---------------------------------------------------------------------------------------------
//
// IT LIVES HERE RATHER THAN IN protoeffect.go, WHICH IS WHERE IT BELONGS, and that is a deliberate
// note rather than an accident: protoeffect.go was not this agent's file to edit. It is family
// MECHANISM, it carries no payload bytes and no signatures, and it should move next to
// pxUniformBlock the next time that file is opened.
//
// WHY THE GATE EXISTS AT ALL. CORS and HOSTHDR both perturb a REQUEST HEADER, and a request header
// is UNKEYED on essentially every shared cache. If the response varies on that header and the
// cache stores it, the next user of the URL is served our perturbed response. For CORS that means
// handing a stranger's browser a grant to an origin we named; for HOSTHDR it means serving a
// stranger a page whose absolute URLs point at a host we named. In both cases the finding IS that
// somebody else got our response, which is exactly what the non-destructive rule forbids.
//
// WHY CRLF AND REDIRECT DO NOT NEED IT. Their marker rides in the query string or the path, which
// is part of the cache key on every cache that keys on the request target, so the entry they
// create is one nobody else will ever request. A header-slot class has no such token available: it
// perturbs the slot it is handed and nothing else.

// pcSharedCacheRisk reports whether the unperturbed control shows POSITIVE EVIDENCE that a shared
// cache would store it, and names that evidence.
//
// IT FAILS CLOSED ON THE ONE THING IT CANNOT SEE AT ALL. No control, or a control that never came
// back, is no evidence about the endpoint, and no evidence is not safety.
//
// AND IT DOES NOT FAIL CLOSED ON EVERYTHING ELSE, WHICH IS A CORRECTION THE FULL-REGISTRY RUN
// FORCED. The first cut treated a response as storable unless it explicitly said otherwise, so
// "no Cache-Control at all" meant refuse. MEASURED, TestTheWholeRegistryRunsAndEveryClassSaysWhatItDid
// against the canary oracle on 2026-09-19:
//
//	class CORS      planned=0   sent=0
//	class HOSTHDR   planned=0   sent=0
//
// against CRLF's 24, REDIRECT's 6 and DESER's 21 on the same vectors. Both classes were enabled,
// neither sent a single probe on any slot of any vector, and the runner had nothing to name as
// missing. The test's own words: "an operator who enables it and sees nothing reads that as 'no
// bug of this class here'". A safety gate that silences the two cheapest protocol-effect classes
// on every endpoint that merely omits a header is not caution, it is a silent zero with a good
// motive, and this codebase's standing rule is that a missed bug costs far more than a request.
//
// SO THE RULE INVERTED: refuse on EVIDENCE OF CACHING rather than on ABSENCE OF A PROHIBITION.
// RFC 9111 is the authority and it points the same way.
//
//	SAFE, and each of these is sufficient on its own:
//	  the method is not GET or HEAD                       nothing else is heuristically cacheable
//	  the status is not in the heuristically cacheable set (RFC 9111 section 4.2.2)
//	  Cache-Control, CDN-Cache-Control or Surrogate-Control says no-store, private or no-cache
//	  the response sets a cookie                          every CDN default-excludes it
//	  the REQUEST carried Authorization or a Cookie, and the response does not explicitly
//	    re-permit storage with public, s-maxage or must-revalidate (RFC 9111 section 3.5)
//	  the response already declares Vary on the header this family perturbs, or Vary: *
//	    the cache keys on it, so the entry we create is our own
//
//	RISKY, and only on positive evidence:
//	  Cache-Control, CDN-Cache-Control or Surrogate-Control permits storage: public, or a
//	    non-zero s-maxage or max-age
//	  the response is demonstrably passing through a cache already: Age, X-Cache,
//	    CF-Cache-Status, X-Cache-Status or Expires
//
// Anything else is SAFE and says so: an endpoint with no cache directives, no validator evidence
// and no sign of a CDN is one where nothing in the response suggests a shared cache is involved,
// and refusing it buys nothing an operator would thank us for.
func pcSharedCacheRisk(route triage.Replay) (string, bool) {
	if !route.Resolved() {
		return "no unperturbed control resolved, so there is no evidence about whether a shared cache " +
			"would store this response. The gate fails closed on this one case: could-not-look is not safe", true
	}
	return pcSharedCacheRiskOf(route.Obs())
}

// pcSharedCacheRiskOfResolved is pcSharedCacheRisk for the CLASSIFY side, where an unresolved
// control is somebody else's row.
//
// Plan uses pcSharedCacheRisk, which refuses on an unresolved control, because Plan's question is
// "may I send". Classify's question is "what do I report", and reporting a cache refusal on a
// vector whose control never resolved would name the wrong reason: nothing about caching was
// learned there, and route_unresolved is the fact. Two callers, two questions, one decision table
// underneath.
func pcSharedCacheRiskOfResolved(route triage.Replay) (string, bool) {
	if !route.Resolved() {
		return "", false
	}
	return pcSharedCacheRiskOf(route.Obs())
}

// pcSharedCacheRiskOf is the decision itself, over the control's observation.
//
// IT IS SPLIT FROM THE Replay FOR TESTABILITY AND THAT IS A DELIBERATE FOUR LINES. A Replay can
// only be built with a capability whose type lives in server/utils/internal/triagecap, and Go's
// internal rule makes that package unimportable from here BY DESIGN: it is the same rule that
// stops a classifier minting into another class's vault partition. So a test in this package
// cannot construct a resolved route control, and a gate written only against a Replay would have
// exactly one reachable branch in its tests, the fail-closed one, while the whole table above
// went unexercised. ssti.go's sstiEnv exists for the same reason and says so.
func pcSharedCacheRiskOf(o triage.Observation) (string, bool) {
	if !o.Delivered() {
		return "the unperturbed control did not come back (" + string(o.TransportErr) + "), so nothing is " +
			"known about this endpoint at all. The gate fails closed on this one case", true
	}

	switch strings.ToUpper(strings.TrimSpace(o.ReqMethod)) {
	case "", "GET", "HEAD":
	default:
		return "", false
	}
	if !pcHeuristicallyCacheableStatus(o.Status) {
		return "", false
	}

	directives := pcCacheDirectives(o)
	for _, d := range []string{"no-store", "private", "no-cache"} {
		if directives[d] != "" || pcHasFlag(directives, d) {
			return "", false
		}
	}
	if len(o.SetCookies) > 0 {
		return "", false
	}
	for _, v := range pxRespHeader(o, corsVary) {
		for _, f := range strings.Split(v, ",") {
			switch strings.ToLower(strings.TrimSpace(f)) {
			case "origin", "host", "x-forwarded-host", "x-original-url", "x-rewrite-url", "*":
				return "", false
			}
		}
	}

	// RFC 9111 section 3.5: a shared cache MUST NOT store a response to a request carrying
	// Authorization unless the response explicitly re-permits it. A session cookie is treated the
	// same way here, which is slightly stricter than the RFC about cookies and matches what every
	// CDN actually does by default.
	explicitlyPublic := pcHasFlag(directives, "public") || pcNonZero(directives["s-maxage"]) ||
		pcHasFlag(directives, "must-revalidate")
	if !explicitlyPublic && pcRequestCarriedCredentials(o) {
		return "", false
	}

	if explicitlyPublic || pcNonZero(directives["max-age"]) {
		why := "the control explicitly permits storage by a shared cache"
		if v := pxRespHeader(o, "Cache-Control"); len(v) > 0 {
			why += " (Cache-Control: " + strings.Join(v, ", ") + ")"
		}
		for _, n := range []string{"CDN-Cache-Control", "Surrogate-Control"} {
			if v := pxRespHeader(o, n); len(v) > 0 {
				why += " (" + n + ": " + strings.Join(v, ", ") + ")"
			}
		}
		return why, true
	}

	for _, n := range []string{"Age", "X-Cache", "CF-Cache-Status", "X-Cache-Status", "Expires"} {
		if v := pxRespHeader(o, n); len(v) > 0 {
			return "the control is demonstrably passing through a cache already (" + n + ": " +
				strings.Join(v, ", ") + "), and the header this class perturbs is not in that cache's key", true
		}
	}

	return "", false
}

// pcHeuristicallyCacheableStatus is RFC 9111 section 4.2.2's list. A status outside it is not
// stored by a cache without an explicit freshness lifetime, and the explicit-lifetime case is
// caught by the directive check above rather than here.
func pcHeuristicallyCacheableStatus(code int) bool {
	switch code {
	case 200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501:
		return true
	}
	return false
}

// pcCacheDirectives flattens Cache-Control, CDN-Cache-Control and Surrogate-Control into one
// lowercased map of directive to value. A flag directive maps to the empty string, which is why
// pcHasFlag exists rather than a truthiness test on the value.
func pcCacheDirectives(o triage.Observation) map[string]string {
	out := map[string]string{}
	for _, name := range []string{"Cache-Control", "CDN-Cache-Control", "Surrogate-Control"} {
		for _, v := range pxRespHeader(o, name) {
			for _, d := range strings.Split(v, ",") {
				k, val, _ := strings.Cut(strings.TrimSpace(d), "=")
				k = strings.ToLower(strings.TrimSpace(k))
				if k == "" {
					continue
				}
				out[k] = strings.Trim(strings.TrimSpace(val), `"`)
			}
		}
	}
	return out
}

func pcHasFlag(directives map[string]string, name string) bool {
	_, ok := directives[name]
	return ok
}

// pcNonZero reads a delta-seconds directive value. An unparseable or absent value is NOT treated
// as permission: max-age=0 and max-age=banana both mean this response is not being kept.
func pcNonZero(v string) bool {
	if v == "" {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	return err == nil && n > 0
}

// pcRequestCarriedCredentials reports whether the unperturbed request carried an Authorization
// header or a Cookie, which is what brings RFC 9111 section 3.5 into play.
//
// It reads ReqHeaders, the DECLARED list, rather than ReqWireHeaders, because the declared list is
// always populated and the wire list is only recorded on the ordered path.
func pcRequestCarriedCredentials(o triage.Observation) bool {
	for _, h := range o.ReqHeaders {
		switch strings.ToLower(strings.TrimSpace(h[0])) {
		case "authorization", "cookie", "proxy-authorization":
			if strings.TrimSpace(h[1]) != "" {
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// THE TOOL POINTER
// ---------------------------------------------------------------------------------------------

func corsLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"nuclei": "the DAST cors-misconfig template set, as a second detector on a slot this class has " +
			"already implicated",
		"manual": "this class's finding IS the proof of concept: one page, one fetch with credentials " +
			"include, and the response body is in the attacker's variable. Write that page before writing " +
			"the report, because a triager who cannot read the data will downgrade it",
	}
	if w, ok := ann["winning_probe"].(string); ok {
		hints["winning_probe"] = w
		hints["next"] = "reproduce with replay_request against the composed URL, adding the Origin header " +
			"recorded in origin_sent, and read " + corsACAO + " and " + corsACAC + " off the response"
	}
	if _, ok := ann["missing_vary_origin"]; ok {
		hints["cache"] = "no Vary: Origin on a reflected grant. Point the cache tooling at this vector too: " +
			"a reflected origin that a CDN stores is web cache poisoning, and this class deliberately did " +
			"not test that because doing so would poison the entry"
	}
	return triage.TriageLabel{Tools: []string{"nuclei"}, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (corsClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "headers_not_body", Probes: corsAllProbeIDs(),
			Rule: "every detector in this class reads Observation.RespHeaders. None reads the body. The " +
				"string " + corsHostSuffix + " appearing in a reflected parameter is not a CORS grant",
		},
		{
			Name: "equality_with_what_this_probe_sent", Probes: []triage.ProbeID{corsA1, corsA2, corsA3},
			Rule: "the grant must be byte-equal, case-insensitively, to the exact origin THIS probe put on " +
				"the wire. A grant naming the application's own origin, a partner's origin, or an earlier " +
				"run's marker host is not this probe's doing, and the run id inside the marker is what " +
				"makes the last of those distinguishable",
		},
		{
			Name: "a_bare_hostname_is_not_an_origin", Probes: []triage.ProbeID{corsNC1},
			Rule: string(corsNC1) + " carries no scheme, so RFC 6454 says it is not an origin and no browser " +
				"sends it. A server that parses at all cannot match it. A hit is reported at the distinct " +
				"oracle origin_echoed_without_parsing, because raw echo is worse than a permissive " +
				"allowlist, not because the control is broken",
		},
		{
			Name: "own_origin_is_correct_behaviour", Probes: corsAllProbeIDs(),
			Rule: "a grant equal to the application's own origin, returned whatever origin we offered, is " +
				"the CORRECT implementation and must render clean. A detector that fired on the presence " +
				"of " + corsACAO + " would report a finding on every correctly configured API in the corpus",
		},
		{
			Name: "absent_from_the_baseline", Probes: corsAllProbeIDs(),
			Rule: "a grant naming a host under " + corsHostSuffix + " must be absent from the unperturbed " +
				"control and from the post-baseline. Present on either and the detector is unusable here, " +
				"which is cannot_determine and never a finding",
		},
		{
			Name: "cache_gate_before_the_first_request", Probes: corsAllProbeIDs(),
			Rule: "pcSharedCacheRisk is asked of the route control in Plan BEFORE anything is sent and " +
				"again in Classify so the refusal produces a row. An Origin header is unkeyed on a shared " +
				"cache and this class has no cache-busting token, so a storable response means not_probed",
		},
	}
}

func (corsClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "allow_origin_returned", Kind: "protocol", What: "the grant exactly as the response carried it, beside the origin we sent. The pair is the whole proof and it fits on one line"},
		{Name: "allow_credentials", Kind: "protocol", What: "true or absent. It is the single fact that separates a critical cross-origin read of authenticated data from a medium that needs the endpoint to be interesting without cookies"},
		{Name: "winning_arm", Kind: "annotation", What: "which origin got through: https, http, a non-default port, a two-origin list, or a bare hostname that is not an origin at all. Each one names a different defect in the comparison and a different fix"},
		{Name: "vary_on_origin", Kind: "annotation", What: "a reflected grant without Vary: Origin is storable by a shared cache, which turns a per-request misconfiguration into a stored one. It is recorded and deliberately not tested"},
		{Name: "application_own_origin", Kind: "differential", What: "what a correct implementation would have returned, so an operator can see at a glance that the grant is not it"},
		{Name: "blind_spots", Kind: "annotation", What: "recorded on every verdict: prefix and suffix matching are not measured, the preflight is not measured, and the null origin is measured indirectly. Each says why, so no clean is read as covering them"},
	}
}

// OracleCases. EVERY ROUTE BELOW NOW EXISTS and Exists says so: they were declared as a build
// list, docker/oracle/round4.go built them, and each one was confirmed serving its own
// X-Ars0n-Oracle header on 2026-09-19. An Exists:false left standing on a route that is up is not
// a harmless stale flag: it reads as "this class was never measured against its own fixtures",
// which is the excuse a class with a structural hole hides behind.
//
// The negatives are doing the work: the two that must stay silent are what separate a detector
// from a header-presence alarm. And one of the POSITIVES did the work this round, which is the
// whole argument for declaring them: /cors/originlist is the route that proved the round-1 gate
// withheld CORS-A4 and made this class state clean on a list-parsing allowlist bypass.
func (corsClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "reflect_with_credentials", Route: "/cors/reflect", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{corsA1}, WantState: triage.StateFinding,
			Why: "a route that copies the Origin request header into " + corsACAO + " and sets " + corsACAC +
				": true. The verdict must be finding at grade high with oracle " +
				"reflected_origin_with_credentials",
		},
		{
			Name: "reflect_without_credentials", Route: "/cors/reflectnocreds", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{corsA1}, WantState: triage.StateFinding,
			Why: "the same reflection with no " + corsACAC + ". Grade must drop to medium and the oracle " +
				"must change, because the two need different reports and a class that graded them alike " +
				"would either overstate one or bury the other",
		},
		{
			Name: "own_origin_only", Route: "/cors/allowlist", Expect: faExpectNegative, Exists: true,
			Probes: corsRound0(), WantState: triage.StateClean,
			Why: "THE MOST IMPORTANT CASE IN THE CLASS. A route that emits " + corsACAO + " naming its OWN " +
				"origin whatever Origin it is sent. Every probe gets a CORS header back and the verdict " +
				"must be clean. A detector built on 'the response carries " + corsACAO + "' passes every " +
				"positive fixture above and fails this one, and it would fire on a large fraction of " +
				"correctly configured APIs in any real corpus",
		},
		{
			Name: "no_cors_at_all", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: corsRound0(), WantState: triage.StateClean,
			Why: "the shipped echo route emits no Access-Control header of any kind. Clean, with the " +
				"annotation recording that the endpoint speaks no CORS rather than that it speaks it " +
				"correctly. It also proves the class does not read the body: the echo route puts the " +
				"Origin value we sent into the page, so the marker host IS in the response, and the " +
				"verdict must still be clean",
		},
		{
			Name: "null_origin", Route: "/cors/null", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{corsA1}, WantState: triage.StateFinding,
			Why: "a route that answers any unrecognised origin with " + corsACAO + ": null. This is the " +
				"indirect null arm and the reason it exists: the direct probe would need the four bytes " +
				"null, which ClassNoSQL already owns and isolation check I1b refuses to a second class",
		},
		{
			Name: "echo_without_parsing", Route: "/cors/rawecho", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{corsNC1}, WantState: triage.StateFinding,
			Why: "a route that copies the Origin header into " + corsACAO + " with no parse at all, so the " +
				"bare hostname control is echoed too. The verdict must fire at oracle " +
				"origin_echoed_without_parsing, which is a DIFFERENT and higher-severity answer than the " +
				"reflection arms, and must not be recorded as a broken control",
		},
		{
			Name: "wildcard_with_credentials", Route: "/cors/starcreds", Expect: faExpectPositive, Exists: true,
			Probes: corsRound0(), WantState: triage.StateSuspicious,
			Why: corsACAO + ": * together with " + corsACAC + ": true. Suspicious and NOT a finding, " +
				"because every browser refuses the pair, and the reason must say so rather than claiming " +
				"a cross-origin read that cannot happen",
		},
		{
			Name: "port_dropped_from_the_grant", Route: "/cors/portblind", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{corsA1, corsA3}, WantState: triage.StateFinding,
			Why: "a route that parses the Origin, compares the HOSTNAME only, and answers with the origin " +
				"rebuilt without its port. CORS-A3 sends :31337 and the grant comes back without it, so " +
				"the reflectedOurHost reading has to catch it where byte equality cannot. The verdict " +
				"must name the dropped port, because a comparison that ignores the port puts every " +
				"same-host service on every other port inside the trust boundary and that is a different " +
				"fix from a missing allowlist",
		},
		{
			Name: "origin_list_parsed", Route: "/cors/originlist", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{corsA4}, WantState: triage.StateFinding,
			Why: "a route that splits the Origin header on commas, checks only the FIRST entry against " +
				"its allowlist and reflects the SECOND. The Fetch standard sends exactly one origin, so " +
				"the parser is running on input the protocol never produces, and this is how an origin " +
				"gets smuggled past a check. The second entry carries the same marker behind an 'x' " +
				"label, which is what lets the verdict say which entry came back. " +
				"AND THIS ROUTE IS WHY CORS-A4 IS UNGATED AND AT THE REDUCED TIER. It answers a single " +
				"plain origin with NO Access-Control-Allow-Origin at all, because it sets one only when " +
				"it can split the header and parse the second entry. Round 0 is three single origins, so " +
				"round 0 sees nothing, and a gate on 'did round 0 see a reflection' closes on exactly the " +
				"evidence this probe exists to produce. Measured before the fix: clean, oracle " +
				"no_acao_at_all, sent=3, against sent=5 on every reflecting route in the set",
		},
		{
			Name: "preset_marker_grant", Route: "/cors/preset", Expect: faExpectNegative, Exists: true,
			Probes: corsRound0(), WantState: triage.StateCannotDetermine,
			Why: "a route that emits " + corsACAO + " naming a host under " + corsHostSuffix + " " +
				"unconditionally, as an intermediary replaying a cached response would. Every arm would " +
				"otherwise fire. The verdict must be cannot_determine (signature_in_baseline)",
		},
		{
			Name: "storable_response_is_refused", Route: "/cors/cacheable", Expect: faExpectNegative, Exists: true,
			Probes: corsRound0(), WantState: triage.StateNotProbed,
			Why: "a route whose response carries Cache-Control: public, max-age=600, sets no cookie and " +
				"declares no Vary. Nothing may be sent: an Origin header is unkeyed, so a reflected grant " +
				"stored here would be served to the next user. The verdict must be not_probed with the " +
				"cache evidence named, and must not be clean",
		},
	}
}
