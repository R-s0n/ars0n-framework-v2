package triageclasses

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// The NoSQL injection classifier, CATALOGUE 1.5, class id 5.
//
// WHAT THIS CLASS IS FOR. It does not answer "is this endpoint vulnerable". It answers "point
// sqlmap's NoSQL arm, or a manual session, at THIS slot and THIS arm". Six arms, six verdicts per
// slot, and the class never emits one scalar "NoSQL clean": N-OP (field-level operator injection),
// N-FILTER (an operator at the filter ROOT), N-JS ($where and string-concatenated JS), N-TYPE
// (type confusion with no $ character at all), N-COUCH (Mango selectors) and N-ES (Lucene and the
// Elasticsearch DSL). Each arm gets its own row because they fail for different reasons and an
// operator pointing a tool at one of them learns nothing from the other five.
//
// ==================================================================================================
// THE STRUCTURAL POINT THAT DOMINATES EVERYTHING ELSE IN THIS CLASS
// ==================================================================================================
// Operator injection needs the parameter to arrive at the driver as an OBJECT, not as a string.
// On a path segment it never can: a path segment is bytes between two slashes and no framework
// turns it into a map. On a header or a cookie it can only if the observed value is itself JSON,
// in which case the slot is re-derived as a JSON slot. On a query or form field it can only where
// the body or query parser expands bracket notation into a map, which Express/qs does and most
// other stacks do not.
//
// That decision is made at PLAN time, from the slot and the media type, at ZERO request cost, and
// where the answer is no the arms that need an object emit not_applicable with a reason. They do
// not emit clean. "I could not express my payload here" and "I expressed it and nothing happened"
// are opposite facts and this codebase has shipped them as the same pixel repeatedly.
//
// ==================================================================================================
// THE ORACLE ORDER, STRONGEST FIRST
// ==================================================================================================
//  1. N-D2 as $expr arithmetic (NSQ-F2 / NSQ-F3). {"$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}
//     is TRUE for every document and its 56862 twin is TRUE for none, so the pair is a
//     deterministic computation the server performed, not a differential we hope means something.
//     VERIFIED in the catalogue to work under --noscripting, which is what makes it tier 1: it
//     survives the hardening that kills every $where oracle.
//  2. N-D2 as a $where string computation (NSQ-J3 / NSQ-J7). The engine concatenates this probe's
//     OWN marker with 8123*7 and throws it back inside an error, so the hit is 56861 glued to a
//     marker only this class owns. It reads no data, unlike JSON.stringify(this).
//  3. N-D1, a marker inside a named engine error, baseline-subtracted and within 120 bytes of the
//     phrase.
//  4. N-D3, widening measured by ARRAY CARDINALITY from the JSON projection, never by body length.
//     A longer body is a longer body; more rows is more rows.
//
// ==================================================================================================
// THE FALSE POSITIVE THAT WOULD MAKE THIS WHOLE CLASS NOISE
// ==================================================================================================
// A 400 from a JSON schema validator rejecting an object where a string belongs looks exactly like
// a NoSQL parse error: both are "I sent {"$ne":null} and got a 4xx I did not get for the baseline".
// The research measured the actual rejection bodies rather than guessing:
//
//	Ajv  {$ne:null} -> "must be string"                          ["a","b"] -> "must be string"
//	Zod  {$ne:null} -> "expected string, received object"        ["a","b"] -> "received array"
//	Joi  {$ne:null} -> "\"username\" must be a string"           ["a","b"] -> "must be a string"
//
// A validator rejects BENIGN types too. A database does not. So this class sends NSQ-T3 (a bare
// number) and NSQ-T4 (a bare null) alongside the operator probes: neither contains a $, neither is
// an operator, and neither can trip a NoSQL parser. If the benign types are rejected the same way
// the operator was, the verdict is not_exploitable (schema_validated) and the class says so out
// loud. VERIFIED on the unprotected local login: {"username":1} and {"username":null} returned the
// ordinary 401 while {"username":{"$foo":1}} returned 500 unknown operator: $foo. That asymmetry,
// and not the status code, is the discriminator. nosqlErrorSource is where it lives and
// TestAValidatorRejectingAnObjectIsNotAnEngineError is the row that holds it up.
//
// ==================================================================================================
// EVERY WAY THIS CLASS CAN FAIL TO GET AN ANSWER, AND ITS OWN STATE FOR EACH
// ==================================================================================================
//
//	not_applicable  (fragment)                  the fragment never leaves the browser
//	not_applicable  (slot_cannot_carry_object)  a path segment, or a non-JSON header or cookie
//	not_applicable  (filter_root_not_addressable) the slot is not a top-level member of a JSON body
//	not_applicable  (object_not_parsed)         OP1 silent AND OP0 did not reproduce the baseline
//	not_exploitable (schema_validated)          the benign types were rejected identically
//	not_exploitable (odm_cast_rejected)         a Mongoose CastError names the path
//	not_exploitable (scripting_disabled)        the engine refused $where in its own words
//	cannot_determine(dollar_filtered)           a literal $ string is blocked, so nothing is testable
//	cannot_determine(no_known_good_value)       a canary or synthesized value has no baseline to widen from
//	cannot_determine(cardinality_unavailable)   the body has no array, so N-D3 has nothing to count
//	cannot_determine(probe_not_observed)        planned, and no observation came back
//	cannot_determine(payload_not_on_the_wire)   the encoder dropped or altered the bytes
//	cannot_determine(transport_failed)          the request never reached the application
//	cannot_determine(drift)                     the post-baseline disagrees with the pre-baseline
//	cannot_determine(baseline_degraded)         the comparison model cannot support a differential
//	cannot_determine(detector_unverified)       a negative control fired
//	not_probed      (credential_slot)           nobody probes a credential slot
//	not_run         (probe_budget_exhausted)    with every unsent probe named in Untested
//
// clean is reserved for: this class's own probes were planned, reached the wire, came back, the
// controls held, and this arm's own oracle stayed silent.
type nosqlClassifier struct{}

func init() { triage.RegisterClassifier(nosqlClassifier{}) }

func (nosqlClassifier) ID() triage.ClassID { return triage.ClassNoSQL }

// ------------------------------------------------------------------------------------------------
// TOKENS, CONSTANTS AND THE ONE CONVENTION THIS CLASS ASKS OF THE RUNNER
// ------------------------------------------------------------------------------------------------

const (
	// nosqlMarkerTok is triage.MarkerPlaceholder, and using it rather than a token of this
	// class's own invention is deliberate and load-bearing.
	//
	// A NoSQL payload is a JSON OBJECT. The default MarkerPrefix would splice a marker onto the
	// front of {"$eq":"alice"} and produce zqj...{"$eq":"alice"}, which is not JSON, which the
	// body parser rejects, which reads as a 400 that looks exactly like the schema-validator
	// false positive this whole class is built to separate out. So the marker has to go INSIDE
	// the payload, which is what MarkerInline is for, and something has to mark the spot.
	//
	// triage.MarkerPlaceholder is the right token for the spot because NormaliseMarkers maps a
	// real marker back onto exactly these bytes. The payload as DECLARED here and the payload as
	// SENT and then normalised are therefore byte-identical, so the build-time isolation check
	// compares the same thing the wire carried. A token of this class's own would have made the
	// declared form and the sent form two different strings and the law would have been checked
	// over a payload that never existed.
	nosqlMarkerTok = triage.MarkerPlaceholder

	// nosqlValueTok is the slot's OBSERVED value, substituted by the runner from Variant["v"].
	// The catalogue writes it as V. Several probes are defined relative to a known-good value and
	// are meaningless without one, which is why nosqlEligible refuses them on a canary slot.
	nosqlValueTok = "<v>"
	// nosqlValueIncTok is V+1 as a decimal integer, for the $mod false arm. Variant["v1"].
	nosqlValueIncTok = "<v1>"
	// nosqlFirstTok is the first character of V, for the $regex must-match arm. Variant["vfirst"].
	nosqlFirstTok = "<vfirst>"
	// nosqlWrongTok is a literal character chosen at plan time to differ from V's first
	// character, for the $regex must-NOT-match arm. Variant["w"].
	nosqlWrongTok = "<w>"
)

const (
	// The class constants. 8123*7 = 56861 and the false twin is 56862. They are this class's and
	// no other's: SSTI computes 7919*6271, CSTI 49660049, CSVI 6421*3. A shared constant would
	// mean a hit that neither class could claim.
	nosqlFactorA      = 8123
	nosqlFactorB      = 7
	nosqlTrueProduct  = "56861"
	nosqlFalseProduct = "56862"

	// nosqlProximity is how close an engine phrase and this class's marker must be before the
	// pair counts as one event. 120 bytes is the window CATALOGUE 6.1 builds /clean/echoparser to
	// exercise: an application that echoes the payload into a page which ALSO mentions
	// MongoServerError somewhere else must not read as an engine error. Measured error bodies put
	// the offending operator inside the phrase itself, well under 120.
	nosqlProximity = 120
)

// The six arms. They are strings rather than an enum because they are written into the verdict's
// Annotations and read by an operator, and because the runner must never switch on them.
const (
	nosqlArmOP     = "N-OP"
	nosqlArmFilter = "N-FILTER"
	nosqlArmJS     = "N-JS"
	nosqlArmType   = "N-TYPE"
	nosqlArmCouch  = "N-COUCH"
	nosqlArmES     = "N-ES"
)

// nosqlArms is the closed set, in report order. Every code path that returns verdicts returns one
// row per arm, so a slot can never come back with an arm missing. A missing row reads as untouched
// and is indistinguishable from an arm nobody wrote.
var nosqlArms = []string{nosqlArmOP, nosqlArmFilter, nosqlArmJS, nosqlArmType, nosqlArmCouch, nosqlArmES}

// ------------------------------------------------------------------------------------------------
// THE PROBE TABLE
// ------------------------------------------------------------------------------------------------

var (
	// nosqlObjectEncoders covers the two ways an object reaches a sink. json_node_replace puts a
	// real JSON node in the document. name_slot is the bracket form: the single-operator object
	// {"$ne":X} is rewritten as the parameter NAME u[$ne] with value X, which is the only way an
	// object exists in a query string and is exactly what qs and PHP expand back into a map.
	nosqlObjectEncoders = []triage.EncoderMode{triage.EncodeJSONNodeReplace, triage.EncodeNameSlot}
	nosqlObjectPoints   = []triage.SlotKind{triage.KindBody, triage.KindQuery, triage.KindHeader, triage.KindCookie}

	// nosqlRootEncoders is json_node_replace alone. A root-level operator is a SIBLING of the
	// slot inside the filter document and bracket notation cannot express the nesting, so these
	// probes are JSON-body only and say so rather than being sent in a form they cannot survive.
	nosqlRootEncoders = []triage.EncoderMode{triage.EncodeJSONNodeReplace}
	nosqlRootPoints   = []triage.SlotKind{triage.KindBody}

	// nosqlStringEncoders is for the arms whose payload is a STRING and therefore needs no object
	// at all: the $where concatenation arm and the Lucene arm. These are the only arms a path
	// segment, a plain header or a plain cookie can carry, and they are the reason those slots
	// are probed rather than written off.
	nosqlStringEncoders = []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
		triage.EncodeHeaderValue, triage.EncodeCookie, triage.EncodePathSegment,
		triage.EncodeMultipartValue, triage.EncodeXMLCDATA,
	}
	nosqlStringPoints = []triage.SlotKind{
		triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie, triage.KindPath,
	}

	// nosqlSpacedPoints drops the cookie. NSQ-E1 is the one payload in this class that contains a
	// SPACE, and a space is not cookie-octet, so sending it there means either an encoder
	// exception or a silently mangled probe. The catalogue's own points for E1 are Q, F and J.
	nosqlSpacedPoints = []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader}
)

// Probes is every payload this class will ever send. Thirty-five rows, one request each.
//
// THE PAYLOADS ARE THIS CLASS'S AND NO OTHER CLASS'S. Not one of them is borrowed, and where the
// catalogue's literal bytes were generic enough to collide with a sibling class they were made
// specific rather than shared:
//
//	NSQ-T3 is 8123 and not the catalogue's 123, because 123 is four bytes of nothing in
//	particular and 8123 is this class's own factor.
//	NSQ-T5 is {"<marker>":1} and not {"a":1}, which additionally makes the ODM cast error
//	marker-attributable instead of anonymous.
//	NSQ-E2 and NSQ-E3 carry the marker before the quote, because query_shard_exception reflects
//	the assembled query back, so the marker lands INSIDE the error and turns a bare parse failure
//	into an attributable one.
//	NSQ-OP1, NSQ-F1 and NSQ-C2 all mean "an operator name nothing can know" but are written
//	{"$<marker>":1}, {"$<marker>":[1]} and {"$<marker>":{}} so that three arms that fail for three
//	different reasons never share one payload.
//
// NSQ-T4 is the single exception and it is named here rather than hidden: a benign NULL control
// has to be the four bytes null, and there is no way to make those four bytes unique. If a sibling
// class ever declares a bare null the isolation check will fail the build, which is correct, and
// whoever meets it should read nosqlArmTypeVerdict to see what this one is for before moving it.
func (nosqlClassifier) Probes() []triage.ProbeSpec {
	return []triage.ProbeSpec{
		// ---- N-OP. Field-level operator injection. Needs the slot to become an object. --------
		{
			ID: "NSQ-OP0", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$eq":"` + nosqlValueTok + `"}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "THE PARSE CONTROL, and the probe that decides applicable versus not-applicable for " +
				"four of the six arms. It is semantically identical to the observed value, so if it " +
				"reproduces the baseline the object reached the query. If it does not, and OP1 raised " +
				"nothing either, the object never got there and the honest answer is not_applicable, " +
				"not clean. VERIFIED on the simple-parser app: every bracket probe returned an identical " +
				"404 and without this control a scanner would have called that clean.",
		},
		{
			ID: "NSQ-OP1", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$` + nosqlMarkerTok + `":1}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "THE ERROR CONTROL. An operator name nothing on earth can know, so a server that " +
				"complains about it by name has parsed my object. VERIFIED Mongo 7: " +
				"'unknown operator: $zqj...'. CouchDB answers 'Invalid operator'. The marker IS the " +
				"operator name, so the error is attributable to this probe and to no other.",
		},
		{
			ID: "NSQ-OP2", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$ne":"` + nosqlMarkerTok + `"}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "The widening differential, N-D3, and the single most valuable positive in the class " +
				"because a validator cannot produce it, a WAF cannot produce it and an error handler " +
				"cannot produce it. The junk argument is this probe's own marker rather than the " +
				"catalogue's six random characters: a marker cannot collide with a real value and it is " +
				"attributable if the application echoes it.",
		},
		{
			ID: "NSQ-OP3", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$gt":""}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "The second widening path. NEVER {\"$gt\":0}: BSON orders values by type before " +
				"value, so a numeric zero compared against a string field matches nothing at all and " +
				"the probe reads as a clean it never earned. The empty string is the bottom of the " +
				"string type bracket and widens.",
		},
		{
			ID: "NSQ-OP4", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$in":["` + nosqlValueTok + `","` + nosqlMarkerTok + `"]}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "The confirmation for OP2, sent only after OP2 widened. json_node_replace only: an " +
				"array inside bracket notation is a second parser question and answering two questions " +
				"with one probe is how a confirmation stops confirming anything.",
		},
		{
			ID: "NSQ-OP5", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$regex":"^` + nosqlFirstTok + `"}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "Must MATCH. Worthless on its own, which is why OP6 exists: on an endpoint that " +
				"already does prefix search, a narrowing $regex is the endpoint working as designed.",
		},
		{
			ID: "NSQ-OP6", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$regex":"^` + nosqlWrongTok + `"}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "Must NOT match, with a first character chosen at plan time to differ from V's. The " +
				"pair is what makes a regex result mean 'the metacharacter behaved as a metacharacter' " +
				"rather than 'the search box searched'.",
		},
		{
			ID: "NSQ-OP7", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$mod":[8123,` + nosqlValueTok + `]}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "N-D2 at FIELD level, for a digits-only value. VERIFIED: field-level arithmetic, one " +
				"document at age=30. It is the only computation oracle the N-OP arm has, and it is why " +
				"a numeric slot is worth probing even when the $expr root is out of reach.",
		},
		{
			ID: "NSQ-OP8", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$mod":[8123,` + nosqlValueIncTok + `]}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "The FALSE arm of OP7. VERIFIED: 0 documents. A computation oracle with only a true " +
				"arm is a detector nobody has watched stay silent.",
		},
		{
			ID: "NSQ-OP9", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$regex":8123}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "A typed-argument error: '$regex has to be a string'. It reaches a DIFFERENT code " +
				"path from OP1 (argument validation rather than operator lookup), so an endpoint that " +
				"swallows one may still leak the other. It carries no marker and therefore can only ever " +
				"reach suspicious.",
		},

		// ---- N-FILTER. An operator at the filter ROOT. JSON body only. -------------------------
		{
			ID: "NSQ-F1", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$` + nosqlMarkerTok + `":[1]}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "VERIFIED: 'unknown TOP LEVEL operator' is a different sentence from 'unknown " +
				"operator', so this probe distinguishes a filter root from a field sink and tells the " +
				"operator which of the two to point the tool at. Deliberately not byte-equal to OP1: " +
				"two arms sharing one payload cannot attribute a block to either.",
		},
		{
			ID: "NSQ-F2", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "THE STRONGEST ORACLE IN THIS CLASS AND THE ONE THE LADDER LEADS WITH. The server " +
				"computes 8123*7 and compares it with 56861, which is true for every document, so a " +
				"widened result set is a computation the server performed and not a differential we " +
				"interpreted. VERIFIED working with --noscripting, which is the hardening that kills " +
				"every $where oracle, so this arm survives where N-JS does not.",
		},
		{
			ID: "NSQ-F3", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$expr":{"$eq":[{"$multiply":[8123,7]},56862]}}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "The FALSE twin, one byte different. VERIFIED: 0 documents with and without " +
				"scripting. F2 alone proves nothing: an endpoint that returns everything for any " +
				"malformed filter would pass it. F2 wide AND F3 empty is the finding.",
		},
		{
			ID: "NSQ-F4", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$expr":{"$` + nosqlMarkerTok + `":[1,2]}}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "'Unrecognized expression'. The aggregation expression parser is a third code path " +
				"again, below the match parser, so this fires on a stack that has swallowed both OP1 " +
				"and F1. Marker-attributable.",
		},

		// ---- N-JS. $where as a node, and $where reached by string concatenation. ---------------
		{
			ID: "NSQ-J1", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$where":"0"}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "Zero documents if the JS ran. Paired with J2 it is a cardinality differential with " +
				"no marker in it, so it can only reach suspicious on its own.",
		},
		{
			ID: "NSQ-J2", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$where":"1"}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "Every document if the JS ran. The true arm of J1.",
		},
		{
			ID: "NSQ-J3", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$where":"throw new Error('` + nosqlMarkerTok + `'+(8123*7))"}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "VERIFIED. The engine concatenates this probe's own marker with the product and " +
				"throws the result, so the hit is 56861 glued directly to a marker only this class owns: " +
				"tier 1, attributable, and no timing anywhere. Deliberately NOT " +
				"throw new Error(JSON.stringify(this)), which is a better detector and reads a document " +
				"out of the database, which is a proof-of-concept step and not a triage probe.",
		},
		{
			ID: "NSQ-J4", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$where":"` + nosqlMarkerTok + `()"}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "VERIFIED: a ReferenceError naming the marker. It fires where J3 does not, because a " +
				"stack that catches a thrown Error may still leak the interpreter's own ReferenceError.",
		},
		{
			ID: "NSQ-J5", Class: triage.ClassNoSQL,
			Logical:  []byte(nosqlValueTok + `' && 8123*7==56861 && 'a'=='a`),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "The string-concatenated $where, which needs NO object and is therefore the only arm " +
				"a path segment or a plain cookie has. V MUST lead, or the quote closes a string that " +
				"was never opened around the value and the whole predicate is nonsense. TRUE arm.",
		},
		{
			ID: "NSQ-J6", Class: triage.ClassNoSQL,
			Logical:  []byte(nosqlValueTok + `' && 8123*7==56862 && 'a'=='a`),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "FALSE arm of J5. Sent in the same round, never later: a true arm whose false arm is " +
				"a round away is a detector nobody has watched stay silent.",
		},
		{
			ID: "NSQ-J7", Class: triage.ClassNoSQL,
			Logical: []byte(nosqlValueTok + `' && (function(){throw new Error('` + nosqlMarkerTok +
				`'+(8123*7))})() && 'a'=='a`),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Embeds: []triage.ProbeID{"NSQ-J3"},
			Notes: "VERIFIED. J3's computation delivered through the concatenation point, so the string " +
				"arm gets the same marker-attributed oracle the node arm has. It CONTAINS J3's thrown " +
				"expression, which is annotated in Embeds because a hit on the shorter payload inside " +
				"the longer one must be attributable rather than silently ambiguous.",
		},
		{
			ID: "NSQ-J8", Class: triage.ClassNoSQL,
			Logical:  []byte(nosqlValueTok + nosqlMarkerTok + `\'`),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "THE REPAIR CONTROL. An escaped quote must make the error go away. If it does not, " +
				"something other than my quote is erroring and every N-JS verdict on this slot becomes " +
				"cannot_determine (detector_unverified) rather than a confident finding.",
		},

		// ---- N-TYPE. Type confusion. No $ anywhere, so it survives $-stripping. ----------------
		{
			ID: "NSQ-T1", Class: triage.ClassNoSQL,
			Logical:  []byte(`["` + nosqlValueTok + `"]`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "The one-element array holding the known-good value. VERIFIED: under Mongoose it " +
				"reproduces the baseline exactly because the array is silently rewritten to $in; under " +
				"the raw driver it collapses to zero because an array is an array-equality match. That " +
				"single difference is what tells the two stacks apart with no $ character on the wire.",
		},
		{
			ID: "NSQ-T2", Class: triage.ClassNoSQL,
			Logical:  []byte(`["` + nosqlValueTok + `","` + nosqlMarkerTok + `"]`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "VERIFIED: 2 documents under Mongoose against 0 under the raw driver. A row count " +
				"above baseline with no $ anywhere in the request cannot be explained by a validator " +
				"and cannot be blocked by a $-stripping sanitiser, which is what makes this arm worth " +
				"its requests on an endpoint where every N-OP probe came back empty.",
		},
		{
			ID: "NSQ-T3", Class: triage.ClassNoSQL,
			Logical:  []byte(`8123`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "THE BENIGN-TYPE CONTROL, and the probe that kills the schema-validator false " +
				"positive. A bare number contains no $, is not an operator and cannot trip a NoSQL " +
				"parser, so if it is rejected the same way the operator probe was, the rejection came " +
				"from a validator and the finding is dead. 8123 rather than the catalogue's 123 because " +
				"8123 is this class's own factor and 123 is four bytes anyone might declare.",
		},
		{
			ID: "NSQ-T4", Class: triage.ClassNoSQL,
			Logical:  []byte(`null`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "The second benign type, and the ONE payload in this class whose bytes cannot be " +
				"made unique: a null control has to be the four bytes null. It is kept because null is " +
				"the type frameworks treat specially (a missing key, a coerced empty) where a number is " +
				"not, and a validator that lets null through while rejecting a number is a real shape.",
		},
		{
			ID: "NSQ-T5", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"` + nosqlMarkerTok + `":1}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "An object with NO $ in it. VERIFIED: Mongoose answers " +
				"'CastError: Cast to string failed for value \"{ ... }\" (type Object) at path " +
				"\"username\"'. That is N-D4, informational: it proves a schema-bearing ODM is present, " +
				"which is a NEGATIVE for exploitability and a positive for knowing what the stack is. " +
				"The key is the marker so the cast error names this probe.",
		},

		// ---- N-COUCH. Mango selectors. --------------------------------------------------------
		{
			ID: "NSQ-C2", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$` + nosqlMarkerTok + `":{}}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "CouchDB answers {\"error\":\"invalid_operator\",\"reason\":\"Invalid operator: " +
				"$...\"}. Distinct bytes from OP1 and F1 on purpose: Mango and the Mongo match parser " +
				"are different engines and a block that hits one arm must not be credited to the other.",
		},
		{
			ID: "NSQ-C4", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"$regex":"^` + nosqlMarkerTok + `["}`),
			Encoders: nosqlObjectEncoders, Points: nosqlObjectPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "VERIFIED CouchDB 3.5.2: the unbalanced class renders the argument back as an Erlang " +
				"binary literal, <<94,122,...>>, a comma-separated decimal byte list. Nothing else on " +
				"the web prints your input back that way, so it is both an engine fingerprint and a " +
				"marker transform. nosqlErlangBinary is this class's own search transform for it, " +
				"because foundations 2.5 does not have one.",
		},

		// ---- N-ES. Lucene and the Elasticsearch DSL. -------------------------------------------
		{
			ID: "NSQ-E1", Class: triage.ClassNoSQL,
			Logical:  []byte(nosqlValueTok + ` OR ` + nosqlMarkerTok + `:*`),
			Encoders: nosqlStringEncoders, Points: nosqlSpacedPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "Lucene boolean widening. The marker is used as a FIELD name that cannot exist, so " +
				"the clause matches nothing and the widening comes from OR alone; if the field name is " +
				"rejected the error names the marker. No cookie point: this is the only payload in the " +
				"class containing a space and a space is not cookie-octet.",
		},
		{
			ID: "NSQ-E2", Class: triage.ClassNoSQL,
			Logical:  []byte(nosqlValueTok + nosqlMarkerTok + `"`),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "VERIFIED ES 8.15: an unbalanced quote yields query_shard_exception with " +
				"'Failed to parse query [...]' and the assembled query REFLECTED INSIDE IT. The marker " +
				"rides in front of the quote precisely so it lands in that reflection, which turns a " +
				"bare parse failure into an attributable one.",
		},
		{
			ID: "NSQ-E3", Class: triage.ClassNoSQL,
			Logical:  []byte(nosqlValueTok + nosqlMarkerTok + `\"`),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "The repair control for E2. It must NOT error. If it does, the endpoint errors on " +
				"the marker or on the length rather than on the quote, and every N-ES verdict here is " +
				"cannot_determine (detector_unverified).",
		},
		{
			ID: "NSQ-E4", Class: triage.ClassNoSQL,
			Logical:  []byte(`{"` + nosqlMarkerTok + `":{}}`),
			Encoders: nosqlRootEncoders, Points: nosqlRootPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "An unknown DSL query clause: HTTP 400 with parsing_exception and 'unknown query " +
				"[<marker>]'. It reaches the query-clause registry rather than Lucene's grammar, which " +
				"is a different surface from E2 and can fire where E2 is caught.",
		},

		// ---- The universal control. -------------------------------------------------------------
		{
			ID: "NSQ-NC1", Class: triage.ClassNoSQL,
			Logical:  []byte(`$` + nosqlMarkerTok),
			Encoders: nosqlStringEncoders, Points: nosqlStringPoints,
			MarkerPos: triage.MarkerInline, Tier: triage.TierReduced, Risk: triage.RiskR0,
			IsControl: true,
			Notes: "A harmless STRING that happens to start with a dollar. It is not an operator, it is " +
				"not an object, and no database can do anything with it. If it is blocked, the $ " +
				"character itself is filtered and EVERY arm of this class is untestable: the verdict is " +
				"cannot_determine (dollar_filtered), never clean. VERIFIED that this is the only way to " +
				"tell a $-blocking WAF from an application that simply does not parse objects, and the " +
				"two look identical without it. It also measures junk sensitivity: an endpoint whose " +
				"response moves for any unmatched value cannot support a bare differential.",
		},
	}
}

// ------------------------------------------------------------------------------------------------
// REACHABILITY
// ------------------------------------------------------------------------------------------------

// Reaches. Every answer carries a reason, including the always, because the reason is what an
// operator reads when they ask why a slot has six rows on it.
func (nosqlClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindBody:
		switch {
		case nosqlIsJSONMedia(mt):
			return triage.Reachability{
				Reach: triage.ReachAlways,
				Reason: "a JSON body is THE primary point: json_node_replace puts a real object node " +
					"where a string was, which is the only shape operator injection can take",
			}
		case mt == "application/x-www-form-urlencoded" || strings.HasPrefix(string(mt), "multipart/"):
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "a form body carries an object only where the parser expands bracket notation, " +
					"which NSQ-OP0 and NSQ-OP1 measure rather than assume; the string arms run regardless",
			}
		case strings.Contains(string(mt), "xml"):
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "XML element text is a string, so only the $where concatenation and Lucene arms " +
					"reach it; the four object arms are not_applicable here",
			}
		default:
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "an unrecognised body media type may or may not parse into a map, so the object " +
					"arms are gated on this class's own parse control and the string arms run",
			}
		}
	case triage.KindQuery:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a query string carries an object only in bracket notation and only where the " +
				"framework expands it, which qs and PHP do and most do not; NSQ-OP0 decides",
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a header value is a string, so the object arms reach it only when the OBSERVED " +
				"value is itself a JSON object and the slot is re-derived as a JSON slot; the $where " +
				"concatenation and Lucene arms always reach it",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "as a header, and additionally never when the slot is a credential: injecting into " +
				"a session cookie returns a 401 that is indistinguishable from a differential",
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a path segment is always a string and never an object, so N-OP, N-FILTER, N-TYPE " +
				"and N-COUCH are not_applicable here by construction; only the $where concatenation " +
				"and Lucene arms run",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "RFC 3986 section 3.5 makes the fragment a client-side reference that every browser " +
				"strips before the request goes out, so no database ever sees it",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "unrecognised insertion point: this class refuses rather than guessing at an encoder",
		}
	}
}

func nosqlIsJSONMedia(mt triage.MediaType) bool {
	s := string(mt)
	return s == "application/json" || strings.HasSuffix(s, "+json") || s == "application/graphql"
}

// ------------------------------------------------------------------------------------------------
// ELIGIBILITY. Decided from the slot and the media type at ZERO request cost.
// ------------------------------------------------------------------------------------------------

// nosqlPlacement is how, if at all, an object can be put in this slot.
type nosqlPlacement string

const (
	nosqlPlaceNone     nosqlPlacement = "none"
	nosqlPlaceJSONNode nosqlPlacement = "json_node"
	nosqlPlaceBracket  nosqlPlacement = "bracket"
)

// nosqlEligibility is the whole plan-time decision, computed once and used by BOTH Plan and
// Classify. They must not re-derive it separately: a Plan that sends a probe Classify does not
// know about produces a verdict with no ordinals, and a Classify that expects a probe Plan never
// sent produces cannot_determine on a healthy run.
type nosqlEligibility struct {
	// stop is non-empty when nothing at all will be sent. state is the verdict every arm gets.
	stop  string
	state triage.TriageState

	place nosqlPlacement
	// filterRoot is true when the slot is a top-level member of a JSON body document, which is
	// the only position from which a sibling $expr key lands at the filter root.
	filterRoot bool
	// knownGood is true when the observed value is a real one the application served. N-OP and
	// N-TYPE are defined relative to a matching baseline and are meaningless without it.
	knownGood bool
	value     string
	// numeric is true when the value is digits only, which is what the $mod arithmetic needs.
	numeric   bool
	valueInc  string
	firstChar string
	wrongChar string
	// couch and es say whether those two arms have anything to send here.
	stringArms bool
}

func nosqlEligible(ctx triage.PlanCtx) nosqlEligibility {
	s := ctx.Slot
	e := nosqlEligibility{place: nosqlPlaceNone, value: s.Value}

	switch {
	case s.Kind == triage.KindFragment || !s.ServerReachable:
		e.stop, e.state = "fragment: the bytes never leave the browser, so no server-side database can see them", triage.StateNotApplicable
		return e
	case s.Constraints.IsCredential:
		e.stop, e.state = "credential_slot: injecting into an Authorization header or a session cookie returns a 401 that looks exactly like a differential, so nobody probes one", triage.StateNotProbed
		return e
	case ctx.Prelude.Failed():
		e.stop, e.state = "prelude_failed ("+string(ctx.Prelude)+"): without the token every probe fails validation identically, which reads as a stable endpoint with no differential, which reads as clean", triage.StateCannotDetermine
		return e
	case ctx.Budget.Exhausted():
		e.stop, e.state = "probe_budget_exhausted: the cap bit before this slot was reached and no NoSQL probe was sent", triage.StateNotRun
		return e
	}

	e.stringArms = true

	switch s.Kind {
	case triage.KindBody:
		switch {
		case s.BodyMedia == triage.BodyJSON || nosqlIsJSONMedia(ctx.Vector.MediaType):
			e.place = nosqlPlaceJSONNode
			e.filterRoot = nosqlIsTopLevelMember(s.FieldPath)
		case s.BodyMedia == triage.BodyForm || s.BodyMedia == triage.BodyMultipart:
			e.place = nosqlPlaceBracket
		default:
			// BodyXML, BodyGraphQL and BodyNone all put a string in the sink.
			e.place = nosqlPlaceNone
		}
	case triage.KindQuery:
		e.place = nosqlPlaceBracket
	case triage.KindHeader, triage.KindCookie:
		if nosqlValueIsJSONObject(s.Value) {
			e.place = nosqlPlaceJSONNode
		}
	case triage.KindPath:
		e.place = nosqlPlaceNone
	}

	// The known-good value gate, CATALOGUE 3.2. A canary points at a resource that does not
	// exist, so "the result set did not widen" says nothing at all.
	e.knownGood = s.Value != "" &&
		(s.ValueOrigin == triage.ValueObserved || s.ValueOrigin == triage.ValueFromEvidenceURL)

	if n, err := strconv.ParseUint(strings.TrimSpace(s.Value), 10, 32); err == nil && s.Value != "" {
		e.numeric = true
		e.valueInc = strconv.FormatUint(n+1, 10)
	}
	e.firstChar, e.wrongChar = nosqlRegexChars(s.Value)
	return e
}

// nosqlIsTopLevelMember reports whether an RFC 6901 pointer names a direct member of the document
// root. Only there is a sibling key a member of the filter root.
func nosqlIsTopLevelMember(ptr string) bool {
	if ptr == "" || ptr == "/" {
		return true
	}
	if !strings.HasPrefix(ptr, "/") {
		return false
	}
	return !strings.Contains(ptr[1:], "/")
}

// nosqlValueIsJSONObject is the header and cookie re-derivation test from CATALOGUE 3.1: a header
// whose observed value is itself a JSON object is a JSON slot wearing a header's clothes.
func nosqlValueIsJSONObject(v string) bool {
	t := strings.TrimSpace(v)
	if !strings.HasPrefix(t, "{") {
		return false
	}
	return json.Valid([]byte(t))
}

// nosqlRegexChars returns the first character of the value and a DIFFERENT one, for the $regex
// must-match and must-not-match pair. It returns empty strings when the first character is not a
// plain alphanumeric, because a regex metacharacter in the anchor position makes the probe test
// the regex engine's error handling instead of its matching, and that is a different probe.
func nosqlRegexChars(v string) (first, wrong string) {
	if v == "" {
		return "", ""
	}
	c := v[0]
	ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	if !ok {
		return "", ""
	}
	w := byte('q')
	if c == 'q' {
		w = 'w'
	}
	return string(c), string(w)
}

// ------------------------------------------------------------------------------------------------
// PLAN. The ladder.
// ------------------------------------------------------------------------------------------------

// Plan. Round 0 is the eligibility triple, round 1 leads with the strongest oracle this slot can
// carry, round 2 is everything promotion opened up.
//
// THE COST. A JSON body slot spends 3 in round 0 and 6 in round 1, so 9 on an endpoint where
// nothing fires, rising to at most 35 when every arm is promoted. A bracket-capable query or form
// slot spends 3 and then 5, so 8. A string-only slot (a path segment, a plain header, a plain
// cookie, XML text) spends 3 and then 2, so 5.
//
// The catalogue's budget line allows 12, 7 and 3 for those three shapes. This class goes over on
// the third and says so rather than trimming, because the string-only shape has exactly two arms
// left and each of them needs a PAIR: N-JS needs its true and false arms in the same round and
// N-ES needs its break and its repair control. Three requests buys one arm and a half, and the
// half that does not get sent becomes a permanent unknown on every path segment in the corpus,
// which is a silent zero with a budget line for an excuse.
func (nosqlClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	e := nosqlEligible(ctx)
	if e.stop != "" {
		return nil
	}
	key := ctx.Slot.Key

	switch ctx.Round {
	case 0:
		return nosqlRound0(e, key)
	case 1:
		return nosqlRound1(e, key, ctx)
	case 2:
		return nosqlRound2(e, key, ctx)
	default:
		return nil
	}
}

func nosqlRound0(e nosqlEligibility, key triage.SlotKey) []triage.ProbeRequest {
	// NSQ-NC1 goes first on every shape. A blocked dollar makes every other answer meaningless,
	// and it is the only probe that can tell a $-filtering WAF from an application that simply
	// does not build objects. Those two look identical from every other probe in the class.
	out := []triage.ProbeRequest{nosqlReq("NSQ-NC1", key, e)}

	if e.place == nosqlPlaceNone {
		// Nothing here can become an object. The JS concatenation pair is the whole of round 0,
		// and it is a PAIR because a true arm without its false arm is a detector nobody has
		// watched stay silent.
		if e.value != "" {
			out = append(out, nosqlReq("NSQ-J5", key, e), nosqlReq("NSQ-J6", key, e))
		}
		return out
	}
	out = append(out, nosqlReq("NSQ-OP1", key, e))
	// The parse control is only a control when there is a served value for it to be identical to.
	// {"$eq":""} against a slot whose capture carried nothing reproduces nothing and would be
	// read as object_not_parsed on an endpoint where the object parses perfectly well.
	if e.value != "" {
		out = append(out, nosqlReq("NSQ-OP0", key, e))
	}
	return out
}

func nosqlRound1(e nosqlEligibility, key triage.SlotKey, ctx triage.PlanCtx) []triage.ProbeRequest {
	if ctx.Budget.Exhausted() {
		return nil
	}
	var out []triage.ProbeRequest

	if e.place == nosqlPlaceNone {
		// The Lucene pair. E2 breaks the query and reflects the marker back inside the error,
		// E3 is the repair control that proves the break was the quote and not the length.
		if e.value != "" {
			out = append(out, nosqlReq("NSQ-E2", key, e), nosqlReq("NSQ-E3", key, e))
		}
		return out
	}

	// Lead with $expr. It is tier 1, it is deterministic computation rather than a differential,
	// and it is the one oracle that survives --noscripting.
	if e.filterRoot {
		out = append(out, nosqlReq("NSQ-F2", key, e), nosqlReq("NSQ-F3", key, e))
	}
	// The widening pair and the benign-type control, which is what makes any rejection readable.
	out = append(out, nosqlReq("NSQ-OP2", key, e), nosqlReq("NSQ-OP3", key, e), nosqlReq("NSQ-T3", key, e))
	if e.knownGood {
		out = append(out, nosqlReq("NSQ-T1", key, e), nosqlReq("NSQ-T2", key, e))
	}
	return out
}

func nosqlRound2(e nosqlEligibility, key triage.SlotKey, ctx triage.PlanCtx) []triage.ProbeRequest {
	if ctx.Budget.Exhausted() {
		return nil
	}
	var out []triage.ProbeRequest

	if e.place == nosqlPlaceNone {
		if e.value != "" {
			out = append(out, nosqlReq("NSQ-J7", key, e), nosqlReq("NSQ-J8", key, e), nosqlReq("NSQ-E1", key, e))
		}
		return out
	}

	// N-OP's remaining surface. Each of OP5/OP6, OP7/OP8 is a PAIR and is planned as one.
	out = append(out, nosqlReq("NSQ-OP9", key, e), nosqlReq("NSQ-T4", key, e), nosqlReq("NSQ-T5", key, e))
	if e.firstChar != "" && e.knownGood {
		out = append(out, nosqlReq("NSQ-OP5", key, e), nosqlReq("NSQ-OP6", key, e))
	}
	if e.numeric && e.knownGood {
		out = append(out, nosqlReq("NSQ-OP7", key, e), nosqlReq("NSQ-OP8", key, e))
	}
	// N-COUCH. Both probes reach any object-capable slot.
	out = append(out, nosqlReq("NSQ-C2", key, e), nosqlReq("NSQ-C4", key, e))

	if e.filterRoot {
		out = append(out,
			nosqlReq("NSQ-F1", key, e), nosqlReq("NSQ-F4", key, e),
			nosqlReq("NSQ-J1", key, e), nosqlReq("NSQ-J2", key, e),
			nosqlReq("NSQ-J3", key, e), nosqlReq("NSQ-J4", key, e),
			nosqlReq("NSQ-E4", key, e))
		if e.knownGood {
			out = append(out, nosqlReq("NSQ-OP4", key, e))
		}
	}
	// The string arms reach an object-capable slot too, and they test a different sink: an app
	// can build a $where string out of the same parameter it also passes as an object.
	if e.value != "" {
		out = append(out,
			nosqlReq("NSQ-J5", key, e), nosqlReq("NSQ-J6", key, e), nosqlReq("NSQ-J8", key, e),
			nosqlReq("NSQ-E2", key, e), nosqlReq("NSQ-E3", key, e))
	}
	return out
}

// nosqlReq builds one request. The Variant is where every per-instance value goes, because
// ProbeSpec.Logical is static and the isolation law is checked over the static form.
//
// THE marker_offset CONVENTION, WHICH THIS CLASS ASKS THE RUNNER FOR AND WHICH IS LISTED AS A GAP.
// Every probe here is MarkerInline, and Variant["marker_offset"] is the byte index of the
// triage.MarkerPlaceholder token inside Logical. Its ABSENCE means the payload carries no marker
// at all and none may be spliced in. That is not decoration: NSQ-OP0, NSQ-F2, NSQ-F3, NSQ-T3 and
// NSQ-T4 are controls whose whole value is being semantically identical to something benign, and a
// marker prefixed onto {"$eq":"alice"} makes it invalid JSON, which produces a 400, which is
// exactly the schema-validator shape the class exists to separate out. A control that has been
// turned into a parse error is worse than no control.
func nosqlReq(id triage.ProbeID, key triage.SlotKey, e nosqlEligibility) triage.ProbeRequest {
	v := map[string]string{
		"v":         e.value,
		"placement": string(e.place),
	}
	if e.valueInc != "" {
		v["v1"] = e.valueInc
	}
	if e.firstChar != "" {
		v["vfirst"] = e.firstChar
		v["w"] = e.wrongChar
	}
	if off := nosqlMarkerOffset(id); off >= 0 {
		v["marker_offset"] = strconv.Itoa(off)
	}
	// The four N-FILTER probes and the two $where node probes are SIBLINGS of the slot inside the
	// filter document, not replacements for it. Named so the runner cannot get it wrong silently.
	if nosqlIsRootProbe(id) {
		v["placement"] = "filter_root_sibling"
	}
	return triage.ProbeRequest{Spec: id, Slot: key, Variant: v}
}

func nosqlIsRootProbe(id triage.ProbeID) bool {
	switch id {
	case "NSQ-F1", "NSQ-F2", "NSQ-F3", "NSQ-F4", "NSQ-J1", "NSQ-J2", "NSQ-J3", "NSQ-J4", "NSQ-E4":
		return true
	}
	return false
}

// nosqlMarkerOffset is the byte index of the marker token in a declared payload, or -1 when the
// payload has none.
func nosqlMarkerOffset(id triage.ProbeID) int {
	for _, p := range (nosqlClassifier{}).Probes() {
		if p.ID == id {
			return bytes.Index(p.Logical, []byte(nosqlMarkerTok))
		}
	}
	return -1
}

// ------------------------------------------------------------------------------------------------
// THE DETECTORS. Pure functions over bytes, so every false positive below is a test row.
// ------------------------------------------------------------------------------------------------

// nosqlPhrase is one named signature. The NAME is what goes in the evidence, never a verdict.
type nosqlPhrase struct {
	Name   string
	Engine string
	Text   string
}

// nosqlEnginePhrases is the list a database produces and an application does not. Every entry is
// either VERIFIED in the research against a live engine or taken from that engine's own source.
//
// Status codes are deliberately absent. The measured vulnerable app returned 500 for the operator
// probe and 404 for a nonexistent value, and an app with a global error handler returns 400 for
// both. Grading on status alone is how this class becomes a random number generator.
var nosqlEnginePhrases = []nosqlPhrase{
	{"mongo.unknown_operator", "mongodb", "unknown operator: $"},
	{"mongo.unknown_top_level_operator", "mongodb", "unknown top level operator"},
	{"mongo.regex_type", "mongodb", "$regex has to be a string"},
	{"mongo.unrecognized_expression", "mongodb", "Unrecognized expression"},
	{"mongo.regex_invalid", "mongodb", "Regular expression is invalid:"},
	{"mongo.js_interpreter", "mongodb", "JSInterpreterFailure"},
	{"mongo.no_script_engine", "mongodb", "no globalScriptEngine"},
	{"mongo.no_server_js", "mongodb", "Cannot run server-side javascript"},
	{"mongo.server_error", "mongodb", "MongoServerError"},
	{"mongo.parse_error", "mongodb", "MongoParseError"},
	{"mongoose.cast_failed", "mongoose", "failed for value"},
	{"mongoose.cast_error", "mongoose", "CastError"},
	{"mongoose.operator_type", "mongoose", "Can't use $"},
	{"couch.invalid_operator_key", "couchdb", "invalid_operator"},
	{"couch.invalid_operator_reason", "couchdb", "Invalid operator: $"},
	{"couch.invalid_selector", "couchdb", "invalid_selector_json"},
	{"couch.bad_arg", "couchdb", "bad_arg"},
	{"es.query_shard_exception", "elasticsearch", "query_shard_exception"},
	{"es.search_phase_exception", "elasticsearch", "search_phase_execution_exception"},
	{"es.parsing_exception", "elasticsearch", "parsing_exception"},
	{"es.unknown_query", "elasticsearch", "unknown query ["},
	{"es.failed_to_parse", "elasticsearch", "Failed to parse query ["},
	{"es.script_exception", "elasticsearch", "script_exception"},
}

// nosqlValidatorPhrases is the other half of the discriminator: what Ajv, Zod, Joi, JSON Schema
// and the ordinary framework binders say when they reject an object where a string belongs. These
// were GENERATED against the real libraries rather than guessed at, which is why the list is short
// and specific instead of long and hopeful.
var nosqlValidatorPhrases = []nosqlPhrase{
	{"ajv.must_be_string", "ajv", "must be string"},
	{"ajv.must_be_number", "ajv", "must be number"},
	{"joi.must_be_a_string", "joi", "must be a string"},
	{"zod.expected_received", "zod", "expected string, received"},
	{"zod.invalid_type", "zod", "invalid_type"},
	{"jsonschema.not_of_type", "json_schema", "is not of type '"},
	{"generic.validation_error", "generic", "ValidationError"},
	{"generic.should_be_string", "generic", "should be string"},
	{"generic.must_be_of_type", "generic", "must be of type"},
}

// nosqlHit is one matched signature with enough to find it again by hand.
type nosqlHit struct {
	Phrase     nosqlPhrase
	Offset     int
	Length     int
	MarkerNear bool
	MarkerOff  int
}

// nosqlFindPhrase looks for the FIRST occurrence of any listed phrase that is not also present in
// the baseline body, and reports whether this probe's own marker sits within nosqlProximity bytes
// of it.
//
// THE BASELINE SUBTRACTION IS MANDATORY. CATALOGUE 6.1 builds /clean/dberror precisely to catch a
// detector that skips it: an endpoint whose every response, baseline included, carries a driver
// exception in a debug footer would otherwise light up on every probe this class owns.
func nosqlFindPhrase(body, baseline []byte, marker string, list []nosqlPhrase) (nosqlHit, bool) {
	for _, p := range list {
		needle := []byte(p.Text)
		at := bytes.Index(body, needle)
		if at < 0 {
			continue
		}
		if len(baseline) > 0 && bytes.Contains(baseline, needle) {
			// Present in the unperturbed response too. It is the application's prose, not my probe.
			continue
		}
		h := nosqlHit{Phrase: p, Offset: at, Length: len(needle), MarkerOff: -1}
		if marker != "" {
			if mo, near := nosqlMarkerWithin(body, marker, at, len(needle)); near {
				h.MarkerNear, h.MarkerOff = true, mo
			}
		}
		return h, true
	}
	return nosqlHit{MarkerOff: -1}, false
}

// nosqlMarkerWithin reports whether the marker occurs within nosqlProximity bytes of the phrase.
func nosqlMarkerWithin(body []byte, marker string, at, n int) (int, bool) {
	m := []byte(marker)
	from := 0
	for {
		i := bytes.Index(body[from:], m)
		if i < 0 {
			return -1, false
		}
		off := from + i
		switch {
		case off >= at && off-(at+n) <= nosqlProximity:
			return off, true
		case off < at && at-(off+len(m)) <= nosqlProximity:
			return off, true
		}
		from = off + 1
	}
}

// nosqlErrorSource is the discriminator, and it is the single most important function in the file.
type nosqlErrorSource string

const (
	// nosqlSourceNone: nothing in the response looks like a rejection at all.
	nosqlSourceNone nosqlErrorSource = "none"
	// nosqlSourceEngine: a database said something only a database says.
	nosqlSourceEngine nosqlErrorSource = "engine"
	// nosqlSourceValidator: a schema validator rejected a type. The finding is dead and the
	// verdict is not_exploitable (schema_validated), which is NOT clean: the mechanism is
	// reachable and a named defence stops it.
	nosqlSourceValidator nosqlErrorSource = "validator"
	// nosqlSourceAmbiguous: both vocabularies are present, or a rejection with neither. The
	// verdict is cannot_determine, because guessing here is how the class becomes noise.
	nosqlSourceAmbiguous nosqlErrorSource = "ambiguous"
)

// nosqlClassifyError decides where a rejection came from.
//
//	probe    the response to the operator-bearing probe
//	benign   the response to NSQ-T3, the bare number, which contains no $ and is not an operator
//	baseline the unperturbed route response
//
// THE RULE, IN ORDER:
//
//  1. An engine phrase absent from the baseline wins outright. Only a database says
//     "unknown operator: $" or "query_shard_exception".
//  2. Otherwise, if a validator phrase is present AND the benign type was rejected with the same
//     status and the same validator phrase, it is a validator. VERIFIED: Ajv, Zod and Joi all
//     reject {"$ne":null} and 123 with the same message, and a database rejects only the first.
//  3. If a validator phrase is present but the benign type was NOT rejected, the rejection came
//     from BELOW the validator, and that is the shape of a true positive even with no engine
//     phrase to name. It is ambiguous rather than engine, because a bare status difference is the
//     weakest evidence in the class and must never be graded as a hit on its own.
//  4. If the benign control is missing, the answer is ambiguous. A discriminator with one arm
//     missing has not discriminated.
func nosqlClassifyError(probe, benign, baseline []byte, probeStatus, benignStatus int, haveBenign bool, marker string) (nosqlErrorSource, nosqlHit) {
	if h, ok := nosqlFindPhrase(probe, baseline, marker, nosqlEnginePhrases); ok {
		return nosqlSourceEngine, h
	}
	vh, hasValidator := nosqlFindPhrase(probe, baseline, marker, nosqlValidatorPhrases)
	if !hasValidator {
		return nosqlSourceNone, nosqlHit{MarkerOff: -1}
	}
	if !haveBenign {
		return nosqlSourceAmbiguous, vh
	}
	if benignStatus == probeStatus && bytes.Contains(benign, []byte(vh.Phrase.Text)) {
		return nosqlSourceValidator, vh
	}
	return nosqlSourceAmbiguous, vh
}

// nosqlComputationHit is the tier-1 $where oracle: this probe's OWN marker with 56861 glued
// directly to it, which is a string the SERVER built by concatenating my marker with a product it
// computed. Nothing else produces those bytes in that order.
//
// THE FALSE POSITIVE IT REFUSES. An application that echoes the payload back shows
// '<marker>'+(8123*7), with the quote, the plus and the parenthesis between the marker and the
// digits. Requiring the digits to be IMMEDIATELY adjacent to the marker, with no byte in between,
// is what separates a computation from an echo, and TestAnEchoedPayloadIsNotAComputation is the
// row that holds it.
func nosqlComputationHit(body []byte, marker string) (int, bool) {
	if marker == "" || len(body) == 0 {
		return -1, false
	}
	needle := []byte(marker + nosqlTrueProduct)
	if i := bytes.Index(body, needle); i >= 0 {
		return i, true
	}
	return -1, false
}

// nosqlErlangBinary renders bytes the way CouchDB renders a bad Mango argument: each byte in
// decimal, comma-joined, inside <<...>>. VERIFIED CouchDB 3.5.2 prints ^a[ as <<94,97,91>>.
//
// This is THIS CLASS'S OWN marker search transform. Foundations part 2.5 has raw, upper, NCR,
// percent and base64 and does not have this one, so without it a CouchDB hit that reflects the
// marker perfectly is invisible to every marker search in the system.
func nosqlErlangBinary(b []byte) []byte {
	out := make([]byte, 0, len(b)*4)
	for i, c := range b {
		if i > 0 {
			out = append(out, ',')
		}
		out = strconv.AppendUint(out, uint64(c), 10)
	}
	return out
}

// nosqlErlangMarkerHit looks for the marker rendered as an Erlang binary inside a <<...>> literal.
// Both halves are required: the byte list alone could be any comma-separated numbers on the page.
var nosqlErlangShape = regexp.MustCompile(`<<\d+(,\d+)*>>`)

func nosqlErlangMarkerHit(body []byte, marker string) (int, bool) {
	if marker == "" {
		return -1, false
	}
	enc := nosqlErlangBinary([]byte(marker))
	i := bytes.Index(body, enc)
	if i < 0 {
		return -1, false
	}
	if !nosqlErlangShape.Match(body) {
		return -1, false
	}
	return i, true
}

// ------------------------------------------------------------------------------------------------
// CARDINALITY. N-D3 counts ROWS, never bytes.
// ------------------------------------------------------------------------------------------------

type nosqlCardVerdict string

const (
	nosqlCardsUnavailable  nosqlCardVerdict = "cardinality_unavailable"
	nosqlCardsShapeChanged nosqlCardVerdict = "cardinality_shape_changed"
	nosqlCardsSame         nosqlCardVerdict = "same"
	nosqlCardsWider        nosqlCardVerdict = "wider"
	nosqlCardsNarrower     nosqlCardVerdict = "narrower"
	nosqlCardsMixed        nosqlCardVerdict = "mixed"
)

// nosqlCards reads the array lengths out of the stored JSON projection. The projection stores
// "<pointer>.__len__=N" per array, already sorted.
//
// WHY NOT BODY LENGTH. A body that grew could have grown because a row was added, because an
// error string was added, because a timestamp got longer, or because a template rendered a
// different banner. Only the row count answers the question the widening oracle is asking, and
// CATALOGUE 1.5 says so in as many words: widening by S3 array cardinality, NEVER body length.
func nosqlCards(o triage.Observation) map[string]int {
	out := make(map[string]int, len(o.Proj.JSONCards))
	for _, c := range o.Proj.JSONCards {
		i := strings.LastIndex(c, "=")
		if i <= 0 {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(c[i+1:]))
		if err != nil {
			continue
		}
		out[strings.TrimSuffix(c[:i], ".__len__")] = n
	}
	return out
}

// nosqlCompareCards compares a probe's arrays with the baseline's, pointer by pointer.
//
// A pointer set that does not overlap at all is SHAPE CHANGED and not a widening: the response is
// a different document, most likely an error envelope, and counting its arrays against the
// baseline's compares two unrelated things.
func nosqlCompareCards(base, probe map[string]int) nosqlCardVerdict {
	if len(base) == 0 || len(probe) == 0 {
		return nosqlCardsUnavailable
	}
	up, down, shared := 0, 0, 0
	for k, b := range base {
		p, ok := probe[k]
		if !ok {
			continue
		}
		shared++
		switch {
		case p > b:
			up++
		case p < b:
			down++
		}
	}
	switch {
	case shared == 0:
		return nosqlCardsShapeChanged
	case up > 0 && down > 0:
		return nosqlCardsMixed
	case up > 0:
		return nosqlCardsWider
	case down > 0:
		return nosqlCardsNarrower
	default:
		return nosqlCardsSame
	}
}

// ------------------------------------------------------------------------------------------------
// CLASSIFY
// ------------------------------------------------------------------------------------------------

// nosqlSeen is one of this class's own observations, with the ordinal that attributes it.
type nosqlSeen struct {
	obs     triage.Observation
	ordinal uint64
	marker  string
}

// nosqlEvidenceSet is everything the six arms read. It is built once, from this class's own
// responses and the unperturbed route control, and nothing else.
type nosqlEvidenceSet struct {
	slot     triage.Slot
	el       nosqlEligibility
	seen     map[triage.ProbeID]nosqlSeen
	baseline triage.Observation
	haveBase bool
	baseCard map[string]int

	// blocked is set when NSQ-NC1, a harmless string beginning with a dollar, was refused. Every
	// arm then reports cannot_determine (dollar_filtered).
	blocked bool
	// junkSensitive is set when NSQ-NC1 moved the response without blocking it. The endpoint
	// answers differently for any unmatched value, so a bare differential cannot be graded high.
	junkSensitive bool
	// degraded and drifted each cap every arm at an unknown.
	degraded bool
	drifted  bool
}

// Classify. One row per arm per slot, always six rows, never fewer.
func (nosqlClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	el := nosqlEligible(ctx.PlanCtx)
	if el.stop != "" {
		return nosqlAllArms(key, el.state, el.stop, nil)
	}

	// The route control is checked HERE and not in nosqlEligible, deliberately. Plan runs before
	// the runner has necessarily resolved the shared route replay, and a class that refused to
	// plan on an unresolved one would silently send nothing on a run where it resolves a moment
	// later, which is a whole slot skipped with no row to say so. The place where the missing
	// baseline actually prevents a measurement is here, so this is where it is refused.
	if !ctx.Route.Resolved() {
		return nosqlAllArms(key, triage.StateCannotDetermine,
			"route_control_unresolved: there is no unperturbed response to difference against, and "+
				"every oracle in this class but the marker-in-error one is a difference. A phrase that "+
				"was already in the baseline is the application's own prose, and with no baseline there "+
				"is no way to tell the two apart", nil)
	}

	seen, err := nosqlOwn(ctx)
	if err != nil {
		return nosqlAllArms(key, triage.StateCannotDetermine,
			"own_responses_unreadable: "+err.Error()+". A class that cannot read its own responses "+
				"has measured nothing, and the fail-closed answer is an unknown", nil)
	}
	if len(seen) == 0 {
		return nosqlAllArms(key, triage.StateCannotDetermine,
			"probe_not_observed: probes were planned for this slot and not one observation came back, "+
				"so nothing about this slot was measured", nil)
	}

	ev := nosqlEvidenceSet{slot: ctx.Slot, el: el, seen: seen}
	if ctx.Route.Resolved() {
		ev.baseline, ev.haveBase = ctx.Route.Obs(), true
		ev.baseCard = nosqlCards(ev.baseline)
	}
	ev.degraded = ctx.Baseline.Degraded || (ctx.Baseline.Samples > 0 && !ctx.Baseline.Stable)
	ev.drifted = nosqlDrifted(ctx)
	ev.blocked, ev.junkSensitive = nosqlControlState(ev)

	// The two conditions that void every arm at once, checked before any arm runs.
	if ev.drifted {
		return nosqlAllArms(key, triage.StateCannotDetermine,
			"drift: the post-baseline disagrees with the unperturbed route control, so a differential "+
				"measured across this slot cannot be attributed to any probe", nosqlAllOrdinals(seen))
	}
	if ev.blocked {
		return nosqlAllArms(key, triage.StateCannotDetermine,
			"dollar_filtered: NSQ-NC1 sent a plain string beginning with a dollar, which no database "+
				"can act on, and it was refused. The dollar character itself is filtered, so every arm "+
				"of this class is untestable here. This is NOT a clean and it is NOT proof the parser "+
				"is simple: a $-stripping sanitiser and a non-parsing framework look identical from "+
				"every other probe", nosqlAllOrdinals(seen))
	}

	return []triage.ClassVerdict{
		nosqlArmOPVerdict(ev),
		nosqlArmFilterVerdict(ev),
		nosqlArmJSVerdict(ev),
		nosqlArmTypeVerdict(ev),
		nosqlArmCouchVerdict(ev),
		nosqlArmESVerdict(ev),
	}
}

// nosqlOwn collects this class's own observations for THIS slot, keyed by probe.
//
// A read error is returned rather than skipped. OwnedResponses.At fails closed on a foreign or
// unminted handle, and a class that swallows that error carries on scoring with a hole in its
// evidence and no idea there is one.
func nosqlOwn(ctx triage.ClassifyCtx) (map[triage.ProbeID]nosqlSeen, error) {
	out := make(map[triage.ProbeID]nosqlSeen, ctx.Own.Len())
	for i := 0; i < ctx.Own.Len(); i++ {
		p, obs, err := ctx.Own.At(i)
		if err != nil {
			return nil, err
		}
		if obs.SlotKey != ctx.Slot.Key {
			continue
		}
		out[p.ProbeID()] = nosqlSeen{obs: obs, ordinal: p.Ordinal(), marker: string(p.Marker())}
	}
	return out, nil
}

// nosqlDrifted compares the post-baseline with the pre-baseline route control. A slot that moved
// underneath the ladder invalidates every differential taken across it.
func nosqlDrifted(ctx triage.ClassifyCtx) bool {
	if !ctx.PostBaseline.Resolved() || !ctx.Route.Resolved() {
		return false
	}
	pre, post := ctx.Route.Obs(), ctx.PostBaseline.Obs()
	if pre.Status != post.Status {
		return true
	}
	return pre.Proj.NormBodySHA256 != [32]byte{} && pre.Proj.NormBodySHA256 != post.Proj.NormBodySHA256
}

// nosqlControlState reads NSQ-NC1, which is the only probe whose answer changes every other row.
func nosqlControlState(ev nosqlEvidenceSet) (blocked, junkSensitive bool) {
	nc, ok := ev.seen["NSQ-NC1"]
	if !ok || !ev.haveBase {
		return false, false
	}
	if !nc.obs.Delivered() {
		return false, false
	}
	base := ev.baseline
	// Blocked: the control crossed from a success into a client or server refusal. A plain string
	// cannot do that to a database, so something above the database did it.
	if base.Status < 400 && nc.obs.Status >= 400 {
		return true, false
	}
	if nc.obs.Status != base.Status {
		return false, true
	}
	if base.Proj.NormBodySHA256 != [32]byte{} && nc.obs.Proj.NormBodySHA256 != base.Proj.NormBodySHA256 {
		return false, true
	}
	return false, false
}

// nosqlUsable reports whether a probe's observation may be reasoned about at all, and says why not
// when it may not. Three separate failures, three separate reasons, none of them clean.
func (ev nosqlEvidenceSet) usable(id triage.ProbeID) (nosqlSeen, string) {
	s, ok := ev.seen[id]
	if !ok {
		return s, "probe_not_observed (" + string(id) + "): it was planned and no observation came back"
	}
	if !s.obs.Delivered() {
		return s, "transport_failed (" + string(id) + ", " + string(s.obs.TransportErr) +
			"): the request never reached the application, so its silence is the transport's and not the app's"
	}
	if !s.obs.Payload.Survived.Proven() {
		return s, "payload_not_on_the_wire (" + string(id) + ", survival " +
			string(s.obs.Payload.Survived) + "): " + s.obs.Payload.Describe() +
			". An unproven payload cannot support a clean, because a probe that was mangled on the way " +
			"out is indistinguishable afterwards from one the application defended against"
	}
	return s, ""
}

// ------------------------------------------------------------------------------------------------
// THE SIX ARMS
// ------------------------------------------------------------------------------------------------

// nosqlArmOPVerdict is field-level operator injection.
func nosqlArmOPVerdict(ev nosqlEvidenceSet) triage.ClassVerdict {
	v := nosqlBase(ev, nosqlArmOP)

	if ev.el.place == nosqlPlaceNone {
		return nosqlNA(v, "slot_cannot_carry_an_object: "+nosqlWhyNoObject(ev.slot)+
			". Operator injection needs the parameter to reach the driver as an object, so there is "+
			"nothing here for this arm to send. That is a structural fact about the slot and not a "+
			"statement about the application")
	}
	if !ev.el.knownGood {
		return nosqlCD(v, "no_known_good_value (origin "+string(ev.slot.ValueOrigin)+"): this arm is "+
			"defined relative to a response the application actually served, and a canary or "+
			"synthesized value points at a resource that does not exist, so 'the result set did not "+
			"widen' says nothing at all")
	}

	op1, why := ev.usable("NSQ-OP1")
	if why != "" {
		return nosqlCD(v, why)
	}
	op0, why0 := ev.usable("NSQ-OP0")
	if why0 != "" {
		return nosqlCD(v, why0)
	}
	v.Ordinals = []uint64{op1.ordinal, op0.ordinal}

	benign, haveBenign := ev.seen["NSQ-T3"]
	var benignBody []byte
	benignStatus := 0
	if haveBenign && benign.obs.Delivered() {
		benignBody, benignStatus = benign.obs.Body, benign.obs.Status
	} else {
		haveBenign = false
	}
	src, hit := nosqlClassifyError(op1.obs.Body, benignBody, nosqlBaseBody(ev), op1.obs.Status, benignStatus, haveBenign, op1.marker)

	switch src {
	case nosqlSourceValidator:
		if haveBenign {
			v.Ordinals = append(v.Ordinals, benign.ordinal)
		}
		v.State = triage.StateNotExploitable
		v.Oracle = "benign_type_control"
		v.Reason = "schema_validated: NSQ-T3 is a bare number with no dollar in it and cannot trip a " +
			"NoSQL parser, and it was rejected with the same status and the same phrase (" +
			hit.Phrase.Name + ") as the operator probe. A validator rejects benign types, a database " +
			"does not, so the rejection came from above the driver. The mechanism is reachable and a " +
			"named defence stops it, which is not the same as nothing being there"
		v.Evidence = nosqlEv(op1, hit)
		return v
	case nosqlSourceEngine:
		if !hit.MarkerNear {
			v.State = triage.StateSuspicious
			v.Grade = triage.GradeLow
			v.Oracle = "parser_error"
			v.Reason = "engine_error_unattributed (" + hit.Phrase.Name + ", " + hit.Phrase.Engine +
				"): a database error phrase absent from the baseline appeared, but this probe's own " +
				"marker is not within " + strconv.Itoa(nosqlProximity) + " bytes of it, so the error " +
				"cannot be attributed to this payload rather than to something else the request did"
			v.Evidence = nosqlEv(op1, hit)
			v.Label = nosqlLabel(hit.Phrase.Engine, nosqlArmOP)
			return v
		}
		v.State = triage.StateFinding
		v.Grade = triage.GradeHigh
		v.Oracle = "parser_error"
		v.Reason = "operator_name_rejected (" + hit.Phrase.Name + ", " + hit.Phrase.Engine +
			"): NSQ-OP1 named an operator that is this run's marker, so nothing but my own payload " +
			"could have produced it, and the engine answered by name within " +
			strconv.Itoa(nosqlProximity) + " bytes of the marker. The parameter reaches the query as " +
			"an object. Point the operator-injection tooling at this slot"
		v.Evidence = nosqlEv(op1, hit)
		v.Label = nosqlLabel(hit.Phrase.Engine, nosqlArmOP)
		return v
	}

	// No error of any kind from OP1. The parse control now decides between "the object reached the
	// query and the engine was quiet" and "the object never got there".
	parsed := nosqlReproducesBaseline(ev, op0.obs)
	if !parsed {
		return nosqlNA(v, "object_not_parsed: NSQ-OP1 raised nothing and NSQ-OP0, which is "+
			"semantically identical to the observed value, did not reproduce the baseline. The object "+
			"never reached the query. This arm deliberately does NOT claim to know which of a simple "+
			"query parser, a dollar-stripping sanitiser or a WAF is responsible, because from here "+
			"they are indistinguishable and naming one would be an invention")
	}

	// The object does reach the query. Now the widening oracle is meaningful.
	if w := nosqlWideningVerdict(ev, &v, "NSQ-OP2", "NSQ-OP3", "NSQ-OP4"); w != nil {
		return *w
	}

	// $mod arithmetic, this arm's only computation oracle.
	if op7, ok7 := ev.seen["NSQ-OP7"]; ok7 {
		if op8, ok8 := ev.seen["NSQ-OP8"]; ok8 && op7.obs.Delivered() && op8.obs.Delivered() {
			c7 := nosqlCompareCards(ev.baseCard, nosqlCards(op7.obs))
			c8 := nosqlCompareCards(ev.baseCard, nosqlCards(op8.obs))
			v.Ordinals = append(v.Ordinals, op7.ordinal, op8.ordinal)
			if c7 == nosqlCardsSame && c8 == nosqlCardsNarrower {
				v.State = triage.StateFinding
				v.Grade = triage.GradeHigh
				v.Oracle = "computation"
				v.Reason = "mod_arithmetic: NSQ-OP7 asked the field for a remainder that matches the " +
					"observed value and NSQ-OP8 asked for one that cannot, and the two answers " +
					"differed in the direction arithmetic predicts. The server computed something, " +
					"which a validator and a WAF cannot do"
				v.Label = nosqlLabel("mongodb", nosqlArmOP)
				return v
			}
		}
	}

	if !nosqlHaveCards(ev) {
		return nosqlCD(v, "cardinality_unavailable: the parse control proved the object reaches the "+
			"query, so this arm IS applicable, but the response carries no JSON array for the widening "+
			"oracle to count. N-D3 counts rows and never body length, so with no rows to count there "+
			"is no measurement. This is the one place where being applicable and being undecidable "+
			"meet, and it is not a clean")
	}
	return nosqlClean(ev, v, "the parse control proved the object reaches the query, the operator "+
		"probes ran and reached the wire, no named engine phrase appeared that was absent from the "+
		"baseline, and no array in the response grew")
}

// nosqlArmFilterVerdict is an operator at the filter ROOT, and it carries the strongest oracle.
func nosqlArmFilterVerdict(ev nosqlEvidenceSet) triage.ClassVerdict {
	v := nosqlBase(ev, nosqlArmFilter)

	if ev.el.place != nosqlPlaceJSONNode {
		return nosqlNA(v, "filter_root_not_addressable: a root-level operator is a SIBLING of this "+
			"slot inside the filter document, and bracket notation cannot express the nesting that "+
			"$expr needs. Only a JSON body can carry it, and this slot is "+string(ev.slot.Kind)+
			" with media "+string(ev.slot.BodyMedia))
	}
	if !ev.el.filterRoot {
		return nosqlNA(v, "filter_root_not_addressable: the slot sits at JSON pointer "+
			ev.slot.FieldPath+", which is not a direct member of the document root, so a sibling key "+
			"added beside it lands inside a sub-document and not at the filter root")
	}

	f2, why2 := ev.usable("NSQ-F2")
	if why2 != "" {
		return nosqlCD(v, why2+". NSQ-F2 is this class's tier-1 oracle and no other probe in this arm substitutes for it")
	}
	f3, why3 := ev.usable("NSQ-F3")
	if why3 != "" {
		return nosqlCD(v, why3+". NSQ-F2 without NSQ-F3 is a true arm with no false arm, and a detector nobody has watched stay silent is not a detector")
	}
	v.Ordinals = []uint64{f2.ordinal, f3.ordinal}

	c2 := nosqlCompareCards(ev.baseCard, nosqlCards(f2.obs))
	c3 := nosqlCompareCards(ev.baseCard, nosqlCards(f3.obs))

	switch {
	case c2 == nosqlCardsUnavailable || c3 == nosqlCardsUnavailable:
		// Fall through to the error-shaped oracles below; the computation cannot be read.
	case c2 == nosqlCardsWider && (c3 == nosqlCardsNarrower || c3 == nosqlCardsSame):
		v.State = triage.StateFinding
		v.Grade = triage.GradeHigh
		v.Oracle = "computation"
		v.Reason = "expr_arithmetic: the server evaluated $multiply(8123,7) and compared it with " +
			"56861, which is true of every document, and the result set widened; the 56862 twin, " +
			"which is true of none, did not. That is a computation the server performed, not a " +
			"difference we interpreted, and it is VERIFIED to work with server-side scripting " +
			"disabled. The whole request body reaches the query as a filter. Point sqlmap's NoSQL " +
			"arm, or a manual session, at this endpoint"
		v.Label = nosqlLabel("mongodb", nosqlArmFilter)
		return v
	case c2 == c3 && c2 != nosqlCardsSame:
		v.State = triage.StateSuspicious
		v.Grade = triage.GradeLow
		v.Oracle = "computation"
		v.Reason = "expr_pair_moved_together (" + string(c2) + "): both arms of the arithmetic pair " +
			"changed the result set in the same direction, which arithmetic cannot do. Something " +
			"other than the computation moved the response, most likely the extra key being rejected " +
			"or ignored, so the pair proves nothing on its own"
		return v
	}

	// The marker-bearing root probes.
	for _, id := range []triage.ProbeID{"NSQ-F1", "NSQ-F4"} {
		s, ok := ev.seen[id]
		if !ok || !s.obs.Delivered() {
			continue
		}
		v.Ordinals = append(v.Ordinals, s.ordinal)
		if h, found := nosqlFindPhrase(s.obs.Body, nosqlBaseBody(ev), s.marker, nosqlEnginePhrases); found && h.MarkerNear {
			v.State = triage.StateFinding
			v.Grade = triage.GradeHigh
			v.Oracle = "parser_error"
			v.Reason = "root_operator_rejected (" + h.Phrase.Name + ", " + h.Phrase.Engine + ", " +
				string(id) + "): the engine named an operator that is this run's marker, at the filter " +
				"root. 'unknown top level operator' is a different sentence from 'unknown operator' " +
				"and it says the whole document reaches the query, which is the more serious of the two"
			v.Evidence = nosqlEv(s, h)
			v.Label = nosqlLabel(h.Phrase.Engine, nosqlArmFilter)
			return v
		}
	}

	if c2 == nosqlCardsUnavailable || c3 == nosqlCardsUnavailable {
		return nosqlCD(v, "cardinality_unavailable: the $expr pair was sent and came back, and the "+
			"response carries no JSON array whose length the widening oracle could count. The "+
			"arithmetic may well have run; nothing in the response can tell us. N-D3 counts rows and "+
			"never body length, and a body-length oracle here would have graded a longer error string "+
			"as a widened result set")
	}
	if c2 == nosqlCardsSame && c3 == nosqlCardsSame {
		return nosqlNA(v, "object_not_parsed: both arms of the arithmetic pair returned exactly the "+
			"baseline result set, so the extra root key was dropped or ignored before the query was "+
			"built and the filter root is not reachable from this body. Not clean: the probe never "+
			"got to where it was aimed")
	}
	return nosqlClean(ev, v, "the $expr pair ran, reached the wire and came back, the true arm did "+
		"not widen while the false arm did not narrow, and no engine named a root operator")
}

// nosqlArmJSVerdict is $where, as a node and through string concatenation.
func nosqlArmJSVerdict(ev nosqlEvidenceSet) triage.ClassVerdict {
	v := nosqlBase(ev, nosqlArmJS)

	// The engine refusing scripting outright is a real answer and a named defence.
	for _, id := range []triage.ProbeID{"NSQ-J3", "NSQ-J1", "NSQ-J7", "NSQ-J5"} {
		s, ok := ev.seen[id]
		if !ok || !s.obs.Delivered() {
			continue
		}
		if h, found := nosqlFindPhrase(s.obs.Body, nosqlBaseBody(ev), s.marker, nosqlEnginePhrases); found &&
			(h.Phrase.Name == "mongo.no_script_engine" || h.Phrase.Name == "mongo.no_server_js") {
			v.Ordinals = []uint64{s.ordinal}
			v.State = triage.StateNotExploitable
			v.Oracle = "engine_refusal"
			v.Reason = "scripting_disabled (" + h.Phrase.Name + "): the engine said in its own words " +
				"that it will not run server-side JavaScript, which means the $where string DID reach " +
				"it and a named defence stopped it. That is worth more to the operator than a clean: " +
				"the sink is real, so N-FILTER's $expr arm is where the effort belongs, and it is " +
				"VERIFIED to work under exactly this configuration"
			v.Evidence = nosqlEv(s, h)
			v.Label = nosqlLabel("mongodb", nosqlArmJS)
			return v
		}
	}

	// The tier-1 computation, from either delivery shape.
	for _, id := range []triage.ProbeID{"NSQ-J3", "NSQ-J7"} {
		s, ok := ev.seen[id]
		if !ok || !s.obs.Delivered() {
			continue
		}
		v.Ordinals = append(v.Ordinals, s.ordinal)
		if off, hit := nosqlComputationHit(s.obs.Body, s.marker); hit {
			v.State = triage.StateFinding
			v.Grade = triage.GradeHigh
			v.Oracle = "computation"
			v.Reason = "where_string_computation (" + string(id) + "): the response carries this " +
				"probe's own marker with " + nosqlTrueProduct + " glued directly to it, with no byte " +
				"in between. The server concatenated my marker with a product it computed, which an " +
				"echo of the payload cannot produce, because an echo shows the quote, the plus and " +
				"the parenthesis. Server-side JavaScript evaluates this parameter"
			v.Evidence = triage.TriageEvidence{
				Ordinal: s.ordinal, ObsID: s.obs.ObsID,
				Matched: []byte(s.marker + nosqlTrueProduct), Offset: off,
				Length: len(s.marker) + len(nosqlTrueProduct),
				Phrase: "nosql.where_computation", Wire: s.obs.Payload, MarkerForm: "raw",
			}
			v.Label = nosqlLabel("mongodb", nosqlArmJS)
			return v
		}
	}

	// A ReferenceError naming the marker: the interpreter tried to resolve my identifier.
	if s, ok := ev.seen["NSQ-J4"]; ok && s.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, s.ordinal)
		if bytes.Contains(s.obs.Body, []byte("ReferenceError")) &&
			!bytes.Contains(nosqlBaseBody(ev), []byte("ReferenceError")) {
			if _, near := nosqlMarkerWithin(s.obs.Body, s.marker, bytes.Index(s.obs.Body, []byte("ReferenceError")), len("ReferenceError")); near {
				v.State = triage.StateFinding
				v.Grade = triage.GradeHigh
				v.Oracle = "parser_error"
				v.Reason = "where_reference_error: the JavaScript interpreter tried to resolve an " +
					"identifier that is this run's marker and said so, within " +
					strconv.Itoa(nosqlProximity) + " bytes of the marker itself. Nothing but my own " +
					"payload names that identifier"
				v.Label = nosqlLabel("mongodb", nosqlArmJS)
				return v
			}
		}
	}

	// The concatenation differential, which needs its repair control before it may be graded.
	j5, ok5 := ev.seen["NSQ-J5"]
	j6, ok6 := ev.seen["NSQ-J6"]
	if ok5 && ok6 && j5.obs.Delivered() && j6.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, j5.ordinal, j6.ordinal)
		c5 := nosqlCompareCards(ev.baseCard, nosqlCards(j5.obs))
		c6 := nosqlCompareCards(ev.baseCard, nosqlCards(j6.obs))
		if c5 != nosqlCardsUnavailable && c5 != c6 {
			if j8, ok8 := ev.seen["NSQ-J8"]; ok8 && j8.obs.Delivered() {
				v.Ordinals = append(v.Ordinals, j8.ordinal)
				if _, errored := nosqlFindPhrase(j8.obs.Body, nosqlBaseBody(ev), j8.marker, nosqlEnginePhrases); errored {
					return nosqlCD(v, "detector_unverified: the true and false arms of the "+
						"concatenated predicate disagreed, but NSQ-J8, which escapes the quote and "+
						"should make any syntax error go away, still produced an engine error. "+
						"Something other than my quote is breaking this endpoint, so the differential "+
						"cannot be attributed to the predicate")
				}
			}
			v.State = triage.StateSuspicious
			v.Grade = triage.GradeMedium
			v.Oracle = "differential"
			v.Reason = "where_concat_differential: the concatenated predicate's true arm and false " +
				"arm produced different result sets (" + string(c5) + " against " + string(c6) +
				"), which is what an evaluated boolean looks like. It is suspicious rather than a " +
				"finding because no marker is attributable in it: only NSQ-J7's computation can raise " +
				"this arm to a finding"
			if ev.junkSensitive {
				v.Grade = triage.GradeLow
				v.Reason += ". Graded down because NSQ-NC1 showed this endpoint answers differently " +
					"for any unmatched value, so a bare differential is weak evidence here"
			}
			v.Label = nosqlLabel("mongodb", nosqlArmJS)
			return v
		}
	}

	if len(v.Ordinals) == 0 {
		if ev.el.value == "" {
			return nosqlCD(v, "no_value_to_lead_with: every probe in this arm's string form must begin "+
				"with the observed value, because the quote has to close a string that was actually "+
				"opened, and this slot's capture carried no value")
		}
		return nosqlCD(v, "probe_not_observed: no N-JS probe produced an observation for this slot")
	}
	return nosqlClean(ev, v, "the $where probes ran, reached the wire and came back, no marker was "+
		"returned glued to this class's product, no interpreter named this run's marker, and the "+
		"concatenated true and false arms produced the same result set")
}

// nosqlArmTypeVerdict is type confusion, the arm with no dollar in it anywhere.
func nosqlArmTypeVerdict(ev nosqlEvidenceSet) triage.ClassVerdict {
	v := nosqlBase(ev, nosqlArmType)

	if ev.el.place == nosqlPlaceNone {
		return nosqlNA(v, "slot_cannot_carry_an_object: "+nosqlWhyNoObject(ev.slot)+
			". An array and a typed scalar are non-string nodes just as an operator object is")
	}
	if !ev.el.knownGood {
		return nosqlCD(v, "no_known_good_value (origin "+string(ev.slot.ValueOrigin)+"): the array "+
			"arm is defined as 'the one-element array holding the value the application served', and "+
			"a canary has no such value")
	}

	// The ODM signal comes first: a CastError is a defence AND a stack identification.
	if s, ok := ev.seen["NSQ-T5"]; ok && s.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, s.ordinal)
		if h, found := nosqlFindPhrase(s.obs.Body, nosqlBaseBody(ev), s.marker, nosqlEnginePhrases); found &&
			strings.HasPrefix(h.Phrase.Name, "mongoose.") {
			v.State = triage.StateNotExploitable
			v.Oracle = "odm_cast"
			v.Reason = "odm_cast_rejected (" + h.Phrase.Name + "): an object with no dollar in it was " +
				"refused by a schema-bearing ODM, which casts the value against the declared path " +
				"type before the query is built. That is a named defence, and it is also a positive " +
				"identification of the stack: Mongoose is present, so the operator should expect " +
				"$-stripping and sanitizeFilter as well"
			v.Evidence = nosqlEv(s, h)
			v.Annotations = map[string]any{"arm": nosqlArmType, "odm": "mongoose"}
			v.Label = nosqlLabel("mongoose", nosqlArmType)
			return v
		}
	}

	t1, why1 := ev.usable("NSQ-T1")
	if why1 != "" {
		return nosqlCD(v, why1)
	}
	t2, why2 := ev.usable("NSQ-T2")
	if why2 != "" {
		return nosqlCD(v, why2+". The two-element array without its one-element control is a result "+
			"set change with nothing to compare it to")
	}
	v.Ordinals = append(v.Ordinals, t1.ordinal, t2.ordinal)

	// The validator discriminator applies here too, and it is CHEAPER here: T1 and T2 contain no
	// dollar at all, so a rejection of them is almost certainly a type check.
	benign, haveBenign := ev.seen["NSQ-T3"]
	if haveBenign && benign.obs.Delivered() {
		src, hit := nosqlClassifyError(t2.obs.Body, benign.obs.Body, nosqlBaseBody(ev), t2.obs.Status, benign.obs.Status, true, t2.marker)
		if src == nosqlSourceValidator {
			v.Ordinals = append(v.Ordinals, benign.ordinal)
			v.State = triage.StateNotExploitable
			v.Oracle = "benign_type_control"
			v.Reason = "schema_validated (" + hit.Phrase.Name + "): the array and the bare number " +
				"were rejected identically, and neither contains a dollar or an operator. A type " +
				"validator sits in front of this parameter"
			v.Evidence = nosqlEv(t2, hit)
			return v
		}
	}

	c1 := nosqlCompareCards(ev.baseCard, nosqlCards(t1.obs))
	c2 := nosqlCompareCards(ev.baseCard, nosqlCards(t2.obs))
	switch {
	case c1 == nosqlCardsUnavailable || c2 == nosqlCardsUnavailable:
		return nosqlCD(v, "cardinality_unavailable: the array pair ran and the response carries no "+
			"JSON array to count. This arm is entirely a row-count oracle, so there is no fallback")
	case c1 == nosqlCardsSame && c2 == nosqlCardsWider:
		v.State = triage.StateFinding
		v.Grade = triage.GradeHigh
		v.Oracle = "widening"
		v.Reason = "array_rewritten_to_in: the one-element array holding the served value reproduced " +
			"the baseline exactly and the two-element array returned MORE rows. VERIFIED as the " +
			"Mongoose signature: it silently rewrites an array value into $in and casts the elements " +
			"to the schema type. There is no dollar anywhere in this request, so no validator, no WAF " +
			"and no $-stripping sanitiser can account for it"
		v.Label = nosqlLabel("mongoose", nosqlArmType)
		return v
	case c1 == nosqlCardsNarrower && c2 == nosqlCardsNarrower:
		v.State = triage.StateSuspicious
		v.Grade = triage.GradeMedium
		v.Oracle = "type_confusion"
		v.Reason = "array_reached_as_literal: both arrays collapsed the result set where the scalar " +
			"matched, which is the raw driver treating the array as an array-equality match. The " +
			"parameter reaches the query with its type intact, which is injectable, but this shape " +
			"does not widen on its own"
		v.Label = nosqlLabel("mongodb", nosqlArmType)
		return v
	}
	return nosqlClean(ev, v, "the array pair and the benign-type controls ran, reached the wire and "+
		"came back, no ODM cast error named this probe, and no array in the response grew")
}

// nosqlArmCouchVerdict is Mango.
func nosqlArmCouchVerdict(ev nosqlEvidenceSet) triage.ClassVerdict {
	v := nosqlBase(ev, nosqlArmCouch)

	if ev.el.place == nosqlPlaceNone {
		return nosqlNA(v, "slot_cannot_carry_an_object: "+nosqlWhyNoObject(ev.slot)+
			". A Mango selector is a JSON object and has no string form")
	}

	c2, why := ev.usable("NSQ-C2")
	if why != "" {
		return nosqlCD(v, why)
	}
	v.Ordinals = []uint64{c2.ordinal}

	if h, found := nosqlFindPhrase(c2.obs.Body, nosqlBaseBody(ev), c2.marker, nosqlEnginePhrases); found &&
		h.Phrase.Engine == "couchdb" && h.MarkerNear {
		v.State = triage.StateFinding
		v.Grade = triage.GradeHigh
		v.Oracle = "parser_error"
		v.Reason = "mango_operator_rejected (" + h.Phrase.Name + "): CouchDB named an operator that " +
			"is this run's marker. The parameter reaches a Mango selector"
		v.Evidence = nosqlEv(c2, h)
		v.Label = nosqlLabel("couchdb", nosqlArmCouch)
		return v
	}

	if c4, ok := ev.seen["NSQ-C4"]; ok && c4.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, c4.ordinal)
		if off, hit := nosqlErlangMarkerHit(c4.obs.Body, c4.marker); hit {
			v.State = triage.StateFinding
			v.Grade = triage.GradeHigh
			v.Oracle = "parser_error"
			v.Reason = "mango_erlang_binary: the response printed this probe's own marker back as a " +
				"comma-separated decimal byte list inside an Erlang binary literal. VERIFIED CouchDB " +
				"3.5.2 renders a bad $regex argument that way, and nothing else on the web prints " +
				"your input back in that form. This is a marker hit through this class's own " +
				"erlang_binary transform, which foundations 2.5 does not have"
			v.Evidence = triage.TriageEvidence{
				Ordinal: c4.ordinal, ObsID: c4.obs.ObsID,
				Matched: nosqlErlangBinary([]byte(c4.marker)), Offset: off,
				Length: len(nosqlErlangBinary([]byte(c4.marker))),
				Phrase: "nosql.erlang_binary", Wire: c4.obs.Payload, MarkerForm: "erlang_binary",
			}
			v.Label = nosqlLabel("couchdb", nosqlArmCouch)
			return v
		}
	}

	if op0, ok := ev.seen["NSQ-OP0"]; ok && op0.obs.Delivered() && !nosqlReproducesBaseline(ev, op0.obs) {
		return nosqlNA(v, "object_not_parsed: the parse control did not reproduce the baseline, so "+
			"no object reached any query engine here and a silent Mango arm means nothing")
	}
	return nosqlClean(ev, v, "the Mango probes ran, reached the wire and came back, no CouchDB error "+
		"named this run's marker, and the erlang_binary transform found nothing")
}

// nosqlArmESVerdict is Lucene and the Elasticsearch DSL.
func nosqlArmESVerdict(ev nosqlEvidenceSet) triage.ClassVerdict {
	v := nosqlBase(ev, nosqlArmES)

	if ev.el.value == "" {
		return nosqlCD(v, "no_value_to_lead_with: every Lucene probe appends to the observed value, "+
			"and this slot's capture carried none, so there is no assembled query to break")
	}

	e2, why := ev.usable("NSQ-E2")
	if why != "" {
		return nosqlCD(v, why)
	}
	v.Ordinals = []uint64{e2.ordinal}

	// The repair control decides whether a break may be graded at all.
	e3, ok3 := ev.seen["NSQ-E3"]
	if ok3 && e3.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, e3.ordinal)
		if _, stillErrors := nosqlFindPhrase(e3.obs.Body, nosqlBaseBody(ev), e3.marker, nosqlEnginePhrases); stillErrors {
			return nosqlCD(v, "detector_unverified: NSQ-E3 escapes the quote and must therefore be "+
				"inert, and it produced an engine error anyway. Whatever is erroring is not my quote, "+
				"so a break reported from NSQ-E2 would be attributed to the wrong cause")
		}
	}

	if h, found := nosqlFindPhrase(e2.obs.Body, nosqlBaseBody(ev), e2.marker, nosqlEnginePhrases); found &&
		h.Phrase.Engine == "elasticsearch" {
		if !h.MarkerNear {
			v.State = triage.StateSuspicious
			v.Grade = triage.GradeLow
			v.Oracle = "parser_error"
			v.Reason = "lucene_parse_error_unattributed (" + h.Phrase.Name + "): Elasticsearch failed " +
				"to parse a query, and this probe's marker is not within " + strconv.Itoa(nosqlProximity) +
				" bytes of the phrase, so the query it failed on may not be the one my value went into"
			v.Evidence = nosqlEv(e2, h)
			v.Label = nosqlLabel("elasticsearch", nosqlArmES)
			return v
		}
		v.State = triage.StateFinding
		v.Grade = triage.GradeHigh
		v.Oracle = "parser_error"
		v.Reason = "lucene_query_reflected (" + h.Phrase.Name + "): Elasticsearch failed to parse the " +
			"query and REFLECTED THE ASSEMBLED QUERY back, with this run's marker inside it. That is " +
			"both an engine identification and a picture of exactly how the application framed my " +
			"input, and NSQ-E3 proved the break was the quote and not the value"
		v.Evidence = nosqlEv(e2, h)
		v.Label = nosqlLabel("elasticsearch", nosqlArmES)
		return v
	}

	if e4, ok := ev.seen["NSQ-E4"]; ok && e4.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, e4.ordinal)
		if h, found := nosqlFindPhrase(e4.obs.Body, nosqlBaseBody(ev), e4.marker, nosqlEnginePhrases); found &&
			h.Phrase.Name == "es.unknown_query" && h.MarkerNear {
			v.State = triage.StateFinding
			v.Grade = triage.GradeHigh
			v.Oracle = "parser_error"
			v.Reason = "dsl_unknown_query: the Elasticsearch query-clause registry rejected a clause " +
				"named after this run's marker, which means the body reaches the DSL and not merely a " +
				"Lucene string"
			v.Evidence = nosqlEv(e4, h)
			v.Label = nosqlLabel("elasticsearch", nosqlArmES)
			return v
		}
	}

	if e1, ok := ev.seen["NSQ-E1"]; ok && e1.obs.Delivered() {
		v.Ordinals = append(v.Ordinals, e1.ordinal)
		if nosqlCompareCards(ev.baseCard, nosqlCards(e1.obs)) == nosqlCardsWider {
			v.State = triage.StateSuspicious
			v.Grade = triage.GradeMedium
			v.Oracle = "widening"
			v.Reason = "lucene_boolean_honoured: an OR clause naming a field that cannot exist widened " +
				"the result set. The boolean operator was honoured, which means the value is pasted " +
				"into a query string. Suspicious rather than a finding because a widening with no " +
				"marker in the response cannot be attributed by itself"
			v.Label = nosqlLabel("elasticsearch", nosqlArmES)
			return v
		}
	}

	if !ok3 {
		return nosqlCD(v, "probe_not_observed (NSQ-E3): the break probe came back and its repair "+
			"control did not, so there is nothing to show that a silent NSQ-E2 means the quote was "+
			"handled rather than that the whole value was discarded")
	}
	return nosqlClean(ev, v, "the Lucene break, its repair control and the DSL clause probe ran, "+
		"reached the wire and came back, and no Elasticsearch error phrase appeared that was absent "+
		"from the baseline")
}

// ------------------------------------------------------------------------------------------------
// VERDICT PLUMBING
// ------------------------------------------------------------------------------------------------

func nosqlBase(ev nosqlEvidenceSet, arm string) triage.ClassVerdict {
	return triage.ClassVerdict{
		Class:       triage.ClassNoSQL,
		SlotKey:     ev.slot.Key,
		Annotations: map[string]any{"arm": arm, "placement": string(ev.el.place)},
	}
}

func nosqlNA(v triage.ClassVerdict, reason string) triage.ClassVerdict {
	v.State, v.Reason, v.Grade = triage.StateNotApplicable, nosqlArmOf(v)+": "+reason, triage.GradeUnrated
	v.Ordinals = nil
	return v
}

func nosqlCD(v triage.ClassVerdict, reason string) triage.ClassVerdict {
	v.State, v.Reason, v.Grade = triage.StateCannotDetermine, nosqlArmOf(v)+": "+reason, triage.GradeUnrated
	v.Ordinals = nil
	return v
}

// nosqlClean is the ONLY way this class emits clean, and it re-checks the preconditions rather
// than trusting the caller to have done it.
//
// A clean here means: my own probes were planned, they reached the wire, they came back, the
// controls held and my own oracle stayed silent. Anything less is an unknown with a reason. Every
// precondition below has its own reason string, because "not clean" is useless to an operator who
// cannot see which of six things went wrong.
func nosqlClean(ev nosqlEvidenceSet, v triage.ClassVerdict, why string) triage.ClassVerdict {
	switch {
	case len(v.Ordinals) == 0:
		return nosqlCD(v, "no_probe_ordinals: this arm reached its clean branch with no probe to "+
			"point at, which would be a clean asserting a measurement that never happened")
	case !ev.haveBase:
		return nosqlCD(v, "route_control_unresolved: every negative in this class rests on comparing "+
			"with an unperturbed response, and there is none")
	case ev.degraded:
		return nosqlCD(v, "baseline_degraded: the comparison model is degraded or the endpoint failed "+
			"the stability gate, so a quiet oracle here cannot be distinguished from an endpoint that "+
			"is quiet about everything")
	case ev.junkSensitive:
		return nosqlCD(v, "junk_sensitive: NSQ-NC1 sent a harmless string and the response moved, so "+
			"this endpoint answers differently for any unmatched value and its silence on my probes "+
			"carries no information")
	}
	if n, moved := nosqlDifferentialSurface(ev); !moved && n >= nosqlMinDifferentialProbes {
		return nosqlCD(v, "value_insensitive: all "+strconv.Itoa(n)+" of this class's own delivered "+
			"probes came back indistinguishable from the unperturbed route control, and those probes "+
			"differ from each other by an operator object, a $where string, a Mango selector and a "+
			"Lucene break. An endpoint that answers identically to all of them is not answering about "+
			"this slot at all, so no differential was available, and every oracle in this class is a "+
			"differential. A silent oracle here means the endpoint showed me nothing, not that the "+
			"operator was rejected: an injection reaching a query whose result is never rendered "+
			"produces exactly this shape")
	}
	v.State, v.Grade, v.Oracle = triage.StateClean, triage.GradeUnrated, "silent"
	v.Reason = nosqlArmOf(v) + ": clean. " + why
	return v
}

// nosqlMinDifferentialProbes is the floor for calling an endpoint value-insensitive. Two identical
// responses to two payloads is a coincidence an application with one error page produces all day;
// three, when the three differ from each other by an operator object, a $where string and a Lucene
// break, is the endpoint saying it does not vary with this slot.
const nosqlMinDifferentialProbes = 3

// nosqlDifferentialSurface answers the question every negative in this class rests on: did ANYTHING
// this endpoint returned depend on what this slot carried.
//
// It returns how many of this class's own probes were delivered and whether any one of them was
// distinguishable from the unperturbed route control. MEASURED, exam ef8c13ab: on /clean/always500
// (500, the same 142 bytes for every input), /clean/spa (the same shell), /clean/empty204 and
// /clean/nothing (no body at all) every probe came back identical to the control and this class
// reported clean on all four. That is the worst outcome available, because a clean is what makes an
// operator point the expensive tool somewhere else. Where no probe moves the response, the honest
// answer is that nothing was measured.
//
// Its converse is already handled and must not be confused with it: junkSensitive is "everything
// moves the response", this is "nothing does", and both mean a quiet oracle carries no information.
func nosqlDifferentialSurface(ev nosqlEvidenceSet) (delivered int, moved bool) {
	if !ev.haveBase {
		return 0, false
	}
	for _, s := range ev.seen {
		if !s.obs.Delivered() {
			continue
		}
		delivered++
		if !nosqlReproducesBaseline(ev, s.obs) {
			moved = true
		}
	}
	return delivered, moved
}

func nosqlArmOf(v triage.ClassVerdict) string {
	if v.Annotations == nil {
		return "NOSQL"
	}
	if a, ok := v.Annotations["arm"].(string); ok {
		return a
	}
	return "NOSQL"
}

// nosqlAllArms emits one row per arm with the same state and reason. Used only where the whole
// class stops for one reason: every arm still gets a row, because a slot with five rows reads as
// one arm nobody wrote.
func nosqlAllArms(key triage.SlotKey, state triage.TriageState, reason string, ordinals []uint64) []triage.ClassVerdict {
	out := make([]triage.ClassVerdict, 0, len(nosqlArms))
	for _, arm := range nosqlArms {
		v := triage.ClassVerdict{
			Class:       triage.ClassNoSQL,
			SlotKey:     key,
			State:       state,
			Reason:      arm + ": " + reason,
			Annotations: map[string]any{"arm": arm},
		}
		if state.RequiresOrdinals() {
			v.Ordinals = ordinals
		}
		out = append(out, v)
	}
	return out
}

func nosqlAllOrdinals(seen map[triage.ProbeID]nosqlSeen) []uint64 {
	out := make([]uint64, 0, len(seen))
	for _, s := range seen {
		out = append(out, s.ordinal)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func nosqlBaseBody(ev nosqlEvidenceSet) []byte {
	if !ev.haveBase {
		return nil
	}
	return ev.baseline.Body
}

func nosqlHaveCards(ev nosqlEvidenceSet) bool { return len(ev.baseCard) > 0 }

// nosqlReproducesBaseline is the parse control's question: did a semantically identical payload
// produce a semantically identical response.
func nosqlReproducesBaseline(ev nosqlEvidenceSet, o triage.Observation) bool {
	if !ev.haveBase {
		return false
	}
	if o.Status != ev.baseline.Status {
		return false
	}
	if ev.baseline.Proj.NormBodySHA256 != [32]byte{} && o.Proj.NormBodySHA256 != [32]byte{} {
		return o.Proj.NormBodySHA256 == ev.baseline.Proj.NormBodySHA256
	}
	return nosqlCompareCards(ev.baseCard, nosqlCards(o)) == nosqlCardsSame
}

// nosqlWideningVerdict runs the N-D3 widening oracle over a widening probe, a second widening
// probe and a confirmation, and returns nil when nothing fired.
func nosqlWideningVerdict(ev nosqlEvidenceSet, v *triage.ClassVerdict, wide1, wide2, confirm triage.ProbeID) *triage.ClassVerdict {
	for _, id := range []triage.ProbeID{wide1, wide2} {
		s, ok := ev.seen[id]
		if !ok || !s.obs.Delivered() || !s.obs.Payload.Survived.Proven() {
			continue
		}
		v.Ordinals = append(v.Ordinals, s.ordinal)
		if nosqlCompareCards(ev.baseCard, nosqlCards(s.obs)) != nosqlCardsWider {
			continue
		}
		out := *v
		out.State = triage.StateFinding
		out.Grade = triage.GradeHigh
		out.Oracle = "widening"
		out.Reason = "operator_widened_result_set (" + string(id) + "): the operator returned MORE " +
			"rows than the unperturbed value did. This is the strongest positive shape in the class " +
			"and the reason it outranks every error string: a validator cannot produce extra rows, a " +
			"WAF cannot produce extra rows, and an error handler cannot produce extra rows"
		if c, ok := ev.seen[confirm]; ok && c.obs.Delivered() {
			out.Ordinals = append(out.Ordinals, c.ordinal)
			if nosqlCompareCards(ev.baseCard, nosqlCards(c.obs)) == nosqlCardsSame {
				out.Reason += ". Confirmed by " + string(confirm) + ", which names the served value " +
					"explicitly and reproduced the baseline, so the widening came from the operator " +
					"and not from the endpoint ignoring the parameter"
			}
		}
		if ev.junkSensitive {
			out.State = triage.StateSuspicious
			out.Grade = triage.GradeMedium
			out.Reason += ". Graded down to suspicious because NSQ-NC1 showed this endpoint answers " +
				"differently for any unmatched value"
		}
		out.Label = nosqlLabel("", nosqlArmOf(out))
		return &out
	}
	return nil
}

func nosqlWhyNoObject(s triage.Slot) string {
	switch s.Kind {
	case triage.KindPath:
		return "a path segment is the bytes between two slashes and no framework turns one into a map"
	case triage.KindHeader:
		return "this header's observed value is not itself a JSON object, so there is no node to replace"
	case triage.KindCookie:
		return "this cookie's observed value is not itself a JSON object, so there is no node to replace"
	case triage.KindBody:
		return "the body media type is " + string(s.BodyMedia) + ", which puts a string in the sink"
	default:
		return "this insertion point carries bytes and not a typed node"
	}
}

func nosqlEv(s nosqlSeen, h nosqlHit) triage.TriageEvidence {
	form := "raw"
	if !h.MarkerNear {
		form = ""
	}
	return triage.TriageEvidence{
		Ordinal: s.ordinal, ObsID: s.obs.ObsID,
		Matched: []byte(h.Phrase.Text), Offset: h.Offset, Length: h.Length,
		Phrase: h.Phrase.Name, Wire: s.obs.Payload, MarkerForm: form,
	}
}

// nosqlLabel is what the verdict hands the expensive scanner. sqlmap is named because it is the
// only tool in the framework with a NoSQL arm at all, and the hints exist so the operator does not
// start cold: the arm says which sink to aim at and the engine says which dialect to assume.
func nosqlLabel(engine, arm string) triage.TriageLabel {
	l := triage.TriageLabel{
		Tools:  []string{"sqlmap"},
		Engine: engine,
		Hints:  map[string]string{"arm": arm, "class": "nosql"},
	}
	switch engine {
	case "mongodb", "mongoose":
		l.Dialect = "mongo"
		l.Hints["operators"] = "$ne,$gt,$in,$regex,$expr,$where"
	case "couchdb":
		l.Dialect = "mango"
		l.Hints["operators"] = "$ne,$gt,$in,$regex"
	case "elasticsearch":
		l.Dialect = "lucene"
		l.Hints["operators"] = "OR,AND,*,?"
	}
	return l
}

// ------------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS AND THE ORACLE SET
// ------------------------------------------------------------------------------------------------

// Settle is the deferred out-of-band check, and this class has none: every oracle it owns is
// answered inside the response to the probe that asked. There is no callback, no stored read-back
// and no second identity, so a deferred pass would have nothing to look at. It is spelled out
// rather than omitted so that nobody later reads its absence as an oversight.
func (nosqlClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

// nosqlConfirmer is one promotion-to-confirmation rule, as data, so the ladder can be read without
// reading the ladder's code.
type nosqlConfirmer struct {
	Arm     string
	Fired   triage.ProbeID
	Confirm []triage.ProbeID
	Why     string
}

// Confirmers. CATALOGUE 2.1 for this class: OP4 for a widening, F3 then F2 again, J6 then J8,
// T3 and T4 for any N-OP hit.
func (nosqlClassifier) Confirmers() []nosqlConfirmer {
	return []nosqlConfirmer{
		{nosqlArmOP, "NSQ-OP2", []triage.ProbeID{"NSQ-OP4", "NSQ-T3", "NSQ-T4"},
			"a widening is confirmed by naming the served value explicitly in an $in and getting the " +
				"baseline back, and the benign types are what prove the rejection path is not a validator"},
		{nosqlArmOP, "NSQ-OP1", []triage.ProbeID{"NSQ-T3", "NSQ-T4"},
			"an engine error is only an engine error if the benign types were NOT rejected the same way"},
		{nosqlArmOP, "NSQ-OP5", []triage.ProbeID{"NSQ-OP6"},
			"a matching regex means nothing on an endpoint that already does prefix search; the " +
				"must-not-match twin is what makes the metacharacter reading possible"},
		{nosqlArmOP, "NSQ-OP7", []triage.ProbeID{"NSQ-OP8"},
			"the false arm of the $mod arithmetic"},
		{nosqlArmFilter, "NSQ-F2", []triage.ProbeID{"NSQ-F3", "NSQ-F2"},
			"the false twin first, then the true arm again with a FRESH marker, so the computation is " +
				"reproduced rather than observed once"},
		{nosqlArmJS, "NSQ-J5", []triage.ProbeID{"NSQ-J6", "NSQ-J8"},
			"the false arm, then the repair control that proves the break was my quote"},
		{nosqlArmJS, "NSQ-J3", []triage.ProbeID{"NSQ-J7"},
			"the same computation delivered through the other shape, which is a second independent " +
				"path to the same interpreter"},
		{nosqlArmType, "NSQ-T2", []triage.ProbeID{"NSQ-T1", "NSQ-T3"},
			"the one-element array is what separates the Mongoose rewrite from an array-equality match"},
		{nosqlArmES, "NSQ-E2", []triage.ProbeID{"NSQ-E3"},
			"the escaped quote must be inert, or the break is not the quote"},
		{nosqlArmCouch, "NSQ-C2", []triage.ProbeID{"NSQ-C4"},
			"a second CouchDB surface, reached through the argument validator rather than the " +
				"operator table, and rendered in a form only CouchDB produces"},
	}
}

// nosqlEvidencer names one extractor and what it pulls out, so a report can say what it looked at.
type nosqlEvidencer struct {
	Name string
	What string
}

// Evidencers are the four things this class extracts from a response. Nothing here is a verdict:
// every entry is a byte range or a count.
func (nosqlClassifier) Evidencers() []nosqlEvidencer {
	return []nosqlEvidencer{
		{"engine_phrase", "the first listed database error phrase that is absent from the baseline, " +
			"with its offset, its length and its signature NAME"},
		{"marker_proximity", "the offset of this probe's own marker and its distance from the phrase, " +
			"which is what turns a page that mentions a driver into an error my payload caused"},
		{"where_computation", "the offset of marker+" + nosqlTrueProduct + " with no byte in between, " +
			"which is the tier-1 $where oracle"},
		{"erlang_binary", "the offset of this probe's marker rendered as a comma-separated decimal " +
			"byte list inside <<...>>, this class's own marker transform for CouchDB"},
		{"array_cardinality", "per-pointer array lengths from the JSON projection, compared with the " +
			"unperturbed route control. Rows, never bytes"},
	}
}

// nosqlOracleCase is one route in the oracle control set, with what this class must say about it.
type nosqlOracleCase struct {
	Route  string
	Expect string // positive | negative
	Probes []triage.ProbeID
	Want   triage.TriageState
	Arm    string
	Why    string
}

// OracleCases. CATALOGUE 6.1 for this class, plus the routes the shared clean set owes it.
//
// THE NEGATIVES ARE THE HALF THAT ACTUALLY TESTS THE DETECTOR. A detector that has only ever been
// watched firing is exactly as unverified as one that has only ever been watched staying silent,
// and the three negative routes here must each produce a DIFFERENT unknown, for three different
// reasons, and none of them may be clean. If a test suite ever "fixes" a failure here by loosening
// a detector, it has misunderstood what the route is for.
//
// None of these routes exists yet. They are declared so the oracle pass can build them.
func (nosqlClassifier) OracleCases() []nosqlOracleCase {
	return []nosqlOracleCase{
		{
			Route: "/nosqli/mongo", Expect: "positive",
			Probes: []triage.ProbeID{"NSQ-OP1", "NSQ-OP0", "NSQ-OP2", "NSQ-OP4"},
			Want:   triage.StateFinding, Arm: nosqlArmOP,
			Why: "a Mongo-backed login or search that passes the parsed body straight into find(). " +
				"NSQ-OP1 must come back with 'unknown operator: $<marker>' and NSQ-OP2 must return more " +
				"rows than the baseline. It must ALSO serve a JSON array so the cardinality oracle has " +
				"something to count: an endpoint that returns one object widens invisibly",
		},
		{
			Route: "/nosqli/noscripting", Expect: "positive",
			Probes: []triage.ProbeID{"NSQ-F2", "NSQ-F3", "NSQ-J3"},
			Want:   triage.StateFinding, Arm: nosqlArmFilter,
			Why: "the same app with server-side scripting DISABLED. This is the route that matters " +
				"most: $where must be refused in the engine's own words, so N-JS returns " +
				"not_exploitable (scripting_disabled), while the $expr pair must still fire, so the " +
				"tier-1 oracle is exercised independently of the JavaScript one. Nothing else in the " +
				"control set proves that the strongest oracle survives the commonest hardening",
		},
		{
			Route: "/nosqli/mod", Expect: "positive",
			Probes: []triage.ProbeID{"NSQ-OP7", "NSQ-OP8"},
			Want:   triage.StateFinding, Arm: nosqlArmOP,
			Why: "a NUMERIC field, so the $mod field-level arithmetic has somewhere to run. Without a " +
				"numeric route the only computation oracle N-OP owns is never exercised at all",
		},
		{
			Route: "/nosqli/couch", Expect: "positive",
			Probes: []triage.ProbeID{"NSQ-C2", "NSQ-C4"},
			Want:   triage.StateFinding, Arm: nosqlArmCouch,
			Why: "a Mango _find selector built from the request. NSQ-C4 must return the erlang_binary " +
				"rendering, which is the only exercise this class's own marker transform gets anywhere",
		},
		{
			Route: "/nosqli/lucene", Expect: "positive",
			Probes: []triage.ProbeID{"NSQ-E2", "NSQ-E3", "NSQ-E1"},
			Want:   triage.StateFinding, Arm: nosqlArmES,
			Why: "an Elasticsearch query_string surface that reflects the assembled query in its parse " +
				"error. NSQ-E3 must be INERT on the same route, or the repair control is never seen " +
				"doing its job",
		},
		{
			Route: "/nosqli/strict", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-OP1", "NSQ-T3", "NSQ-T4"},
			Want:   triage.StateNotExploitable, Arm: nosqlArmOP,
			Why: "a JSON schema validator rejecting an object where a string belongs, with a 400. THE " +
				"MOST IMPORTANT NEGATIVE IN THIS CLASS. It must reject NSQ-T3 and NSQ-T4 with the same " +
				"status and the same message as NSQ-OP1, so the benign-type discriminator fires and " +
				"the verdict is not_exploitable (schema_validated). It must NOT be clean: the mechanism " +
				"is reachable and a named defence stops it. Ship it three times, once each with Ajv, " +
				"Zod and Joi wording, because the three phrasings are the three rows of the table this " +
				"class was built around",
		},
		{
			Route: "/nosqli/simpleparser", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-OP1", "NSQ-OP0"},
			Want:   triage.StateNotApplicable, Arm: nosqlArmOP,
			Why: "a query string parser that does NOT expand brackets, so every bracket probe " +
				"including the parse control returns an identical 404. Verdict must be " +
				"not_applicable (object_not_parsed). VERIFIED that without the parse control a scanner " +
				"calls this clean, which overstates what was tested",
		},
		{
			Route: "/nosqli/sanitized", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-OP1", "NSQ-OP0", "NSQ-T2"},
			Want:   triage.StateNotApplicable, Arm: nosqlArmOP,
			Why: "express-mongo-sanitize stripping the dollar. VERIFIED to be indistinguishable from " +
				"/nosqli/simpleparser from every probe in the class, so the verdict must be the same " +
				"not_applicable (object_not_parsed) and the reason must NOT claim to know which. The " +
				"N-TYPE arm must still run here and may still fire, because an array contains no dollar",
		},
		{
			Route: "/nosqli/dollarwaf", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-NC1"},
			Want:   triage.StateCannotDetermine, Arm: nosqlArmOP,
			Why: "a WAF that blocks any request containing a dollar. NSQ-NC1 sends a plain harmless " +
				"string beginning with one, and its 403 must turn EVERY arm into " +
				"cannot_determine (dollar_filtered). This route is the only thing that separates a " +
				"blocked class from a tested one, and it is not in CATALOGUE 6.1: it is asked for here",
		},
		{
			Route: "/nosqli/mongoose", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-T5", "NSQ-T1", "NSQ-T2"},
			Want:   triage.StateNotExploitable, Arm: nosqlArmType,
			Why: "a Mongoose app with a typed schema and sanitizeFilter on, which answers an object " +
				"with a CastError naming the path. Verdict not_exploitable (odm_cast_rejected). Asked " +
				"for here and not in CATALOGUE 6.1: N-D4 is the only arm with no route at all, and an " +
				"ODM cast is the commonest real answer on a Node stack",
		},
		{
			Route: "/clean/mongoprose", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-OP1", "NSQ-F1"},
			Want:   triage.StateClean, Arm: nosqlArmOP,
			Why: "a page whose BASELINE already contains 'MongoServerError' and 'unknown operator: $' " +
				"in a debug footer or in documentation prose. Every phrase must be subtracted against " +
				"the baseline and this class must stay silent. It is the direct analogue of " +
				"/clean/dberror and the only route that tests the subtraction",
		},
		{
			Route: "/clean/echomongo", Expect: "negative",
			Probes: []triage.ProbeID{"NSQ-J3", "NSQ-J7"},
			Want:   triage.StateClean, Arm: nosqlArmJS,
			Why: "an endpoint that echoes the payload back verbatim into a 400 body. The marker comes " +
				"back and so do the characters 8123*7, but with the quote, the plus and the " +
				"parenthesis between the marker and the digits, so the computation oracle must NOT " +
				"fire. This is the route that keeps the tier-1 $where oracle from being a substring " +
				"search for my own payload",
		},
	}
}
