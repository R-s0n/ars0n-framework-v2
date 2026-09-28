package triageclasses

import (
	"bytes"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS ORM LEAK (id 29). A REQUEST DICTIONARY REACHES AN ORM'S FILTER KEYWORDS, AND THE ORM
// ANSWERS AN UNKNOWN KEYWORD BY NAMING EVERY COLUMN ON THE MODEL.
//
// WHY THIS CLASS EXISTS AND WHY IT IS WORTH ONE REQUEST. Measured on Django 6.1.1 during the
// payload harvest, verbatim:
//
//	?<marker>6763=1
//	  FieldError: Cannot resolve keyword 'zqjorm000028abc' into field.
//	              Choices are: created_by, created_by_id, id, title
//
//	?title__<marker>6763=1
//	  FieldError: Unsupported lookup 'zqjorm000028abc' for CharField or join on the field not permitted.
//
// Three facts come back out of one request: that the parameter dictionary reaches filter(**...),
// the complete field list of the queried model, and, for a name the application itself prefixed,
// the Django field TYPE including whether it is a relation. The first is the bug, the second is
// the payoff, and the third is the precondition for the relational-leak chain.
//
// THE ORACLE IS MARKER-ANCHORED, SO IT NEEDS NO BASELINE AND CANNOT BE FOOLED BY A NOISY APP.
// The keyword quoted in that sentence is a marker MINTED FOR THIS PROBE IN THIS RUN. No baseline
// can contain it, no documentation page can contain it, and an application whose every response
// already carries a stack trace still cannot produce it. That is the same property that lets SQL's
// flagship oracle survive /clean/dberror, and it is why this class fires at grade high off a
// single response rather than off a differential.
//
// =================================================================================================
// THE SLOT IS THE PARAMETER NAME, NOT ITS VALUE, AND THAT DECIDES EVERYTHING BELOW
// =================================================================================================
// A filter keyword is a map KEY. Every other class in this package perturbs a VALUE; this one
// replaces the NAME and leaves the observed value exactly where it was, because
// filter(**request.GET) unpacks the keys and only the keys reach the ORM's resolver.
//
// WHAT THE ENCODER ACTUALLY SUPPORTS, CHECKED RATHER THAN ASSUMED (utils/triageEncode.go,
// triageEncodeNameSlot and SlotAcceptsEncoder):
//
//	query slot, EncodeNameSlot            WORKS. The pair's name is replaced, its value is kept
//	                                      byte for byte, and every other pair is left alone.
//	form body slot, EncodeNameSlot        WORKS, same edit against the urlencoded body.
//	JSON body slot, EncodeNameSlot        REFUSED, twice over: a JSON node slot carries no Name,
//	                                      so SlotAcceptsEncoder answers slot_has_no_name at plan
//	                                      time, and the encoder itself says "a JSON key rename is
//	                                      a different edit". ORM-D2 below reaches JSON another way.
//	header, cookie, path, fragment        no key the application unpacks. Reaches says never.
//
// AND WHAT IT DOES NOT SUPPORT, WHICH COSTS THIS CLASS THREE OF THE HARVEST'S FOUR PROBES.
// EncodeNameSlot REPLACES the name; it cannot APPEND to it, and a payload cannot spell the
// observed name because the runner's substitution grammar has no token for it. triageRenderPayload
// substitutes triage.MarkerPlaceholder for every class and the ${...} and <...> families only for
// the seven classes named in triageUsesDollarTokens and triageUsesAngleTokens, and even those
// carry the observed VALUE (<V>) and never the observed NAME. So:
//
//	ORM-D2 harvest `__<M>6763`   append, Django lookup on a known field   NOT BUILDABLE
//	ORM-D3 harvest `[<M>6763]`   append, Prisma / Rails bracket           NOT BUILDABLE
//	ORM-D4 harvest `_<M>6763`    append, Ransack predicate                NOT BUILDABLE
//
// They are NOT shipped half-built. A payload spelling a token nothing substitutes goes out with
// the token in it, tests nothing, and the class then reads the silence as the target's answer,
// which is the exact silent zero this layer exists to stop. What is needed to build them is one
// runner change and it is written down in the build report: an observed-NAME substitution token
// (`<name>`, class-scoped exactly as `<V>` is), plus an entry in triageUnsubstituted so that an
// unsubstituted one refuses the probe instead of sending it.
//
// The Django LOOKUP arm is still detected, because there is a second way to reach it that needs no
// append: an application that builds its filter as {f"title__{k}": v for k, v in params.items()}
// prefixes OUR name itself, and the response is then "Unsupported lookup '<marker>6763' for
// CharField". The signature is kept for that shape and the annotation says which one produced it.
//
// =================================================================================================
// WHAT IT MUST NOT MATCH
// =================================================================================================
//   - "Cannot resolve keyword" with SOME OTHER string quoted, which is the application's own
//     error on its own field name. Every signature in this file is anchored to the quoted token
//     being this probe's own marker plus this class's own literal.
//   - a response that merely echoes the parameter name, which every echo endpoint does. An echo
//     with no FieldError phrase is recorded (the operator wants to know the name reaches the
//     response) and fires nothing.
//   - a 500 with no marker in it. That is orm_500_differential at suspicious, and only when the
//     unperturbed route control stayed under 500.
//
// PRODUCTION DJANGO DEGRADES THIS AND THE CLASS SAYS SO. With DEBUG=False a FieldError is an
// unhandled exception and the body is the bare 500 page with no marker in it. The strong state is
// then structurally unavailable and the class has only the status differential, which is
// suspicious and never finding and never clean. It is still worth the request: CVE-2023-47117
// (Label Studio), CVE-2023-31133 (Ghost) and CVE-2023-30843 (Payload CMS) are all this bug.
//
// =================================================================================================
// EXCLUDED OUTRIGHT ON THE NON-DESTRUCTIVE RULE
// =================================================================================================
// The harvest's ORM Leak directory carries a __regex arm whose payload is a catastrophic-
// backtracking expression (^(?=^pbkdf2).*.*.*.*.*.*.*.*!!!!$). It is a resource-exhaustion payload
// aimed at the target's CPU. It is forbidden here, it is not shipped behind an opt-in, and this
// paragraph is so that nobody adds it later believing it was merely forgotten.
//
// TOOL POINTER: NONE (MANUAL), AND THAT IS THE ARGUMENT FOR THE CLASS. There is no ORM-leak tool
// among the framework's fifty containers, so triage is the only thing in the framework that will
// ever find this. The follow-up, binary-searching a password hash through __startswith, is
// replay_request in a loop, which the operator already has.

type ormLeakClassifier struct{ faNoSettle }

func init() { triage.RegisterClassifier(ormLeakClassifier{}) }

func (ormLeakClassifier) ID() triage.ClassID { return triage.ClassORMLeak }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	ormD1 triage.ProbeID = "ORM-D1"
	ormD2 triage.ProbeID = "ORM-D2"
)

// ormOwnedLiteral is this class's own four bytes, and it is not decoration.
//
// A payload that is nothing but a bare marker is the obvious shape for half a dozen future inert
// controls in other classes, and two classes shipping byte-equal payloads is the isolation law's
// first violation. Suffixing every payload with this literal means no probe here can ever collide
// with a bare-marker probe somebody writes next month, and it also means the quoted token in a
// FieldError is 20 bytes of which 16 are attributable by arithmetic: a substring match on it
// cannot be a coincidence in a hex dump.
const ormOwnedLiteral = "6763"

// ormNamePoints and ormNameEncoders are the NAME-slot arm: the parameter name is the payload.
var (
	ormNamePoints   = []triage.SlotKind{triage.KindQuery, triage.KindBody}
	ormNameEncoders = []triage.EncoderMode{triage.EncodeNameSlot}

	// ormNodePoints and ormNodeEncoders are the JSON arm. json_node_replace puts a real JSON
	// OBJECT at the slot's pointer, so the key inside that object is the filter keyword.
	ormNodePoints   = []triage.SlotKind{triage.KindBody}
	ormNodeEncoders = []triage.EncoderMode{triage.EncodeJSONNodeReplace}
)

func (ormLeakClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassORMLeak
	m := triage.MarkerPlaceholder
	return []triage.ProbeSpec{
		{
			ID: ormD1, Class: c, Logical: []byte(m + ormOwnedLiteral),
			Encoders: ormNameEncoders, Points: ormNamePoints,
			Tier: triage.TierReduced, Risk: triage.RiskR2,
			Notes: "THE WHOLE CLASS IN ONE REQUEST. The parameter NAME is replaced with a keyword " +
				"nothing on earth can resolve and the observed VALUE is kept byte for byte, so the only " +
				"thing that changed is the map key. Django answers 'Cannot resolve keyword <k> into " +
				"field. Choices are: ...' and hands over the model's columns; Prisma answers 'Unknown " +
				"argument <k>'; an application that prefixes our key into a lookup answers 'Unsupported " +
				"lookup <k> for CharField'. VERIFIED Django 6.1.1 (harvest-query.md); the Prisma and " +
				"Ransack dialects are UNVERIFIED, no Node and no Ruby were available, so a silent " +
				"response on one of those stacks is not this class claiming they were tested. " +
				"RISK R2 IS THE WORST CASE AND IT IS HONEST: on a read path this is read-only, and on " +
				"a captured write the renamed field arrives missing, so a record the endpoint would " +
				"have written from the captured request may be written short one column. Nothing new " +
				"is created and nothing is deleted",
		},
		{
			ID: ormD2, Class: c, Logical: []byte(`{"` + m + ormOwnedLiteral + `":1}`),
			Encoders: ormNodeEncoders, Points: ormNodePoints,
			Tier: triage.TierFull, Risk: triage.RiskR2,
			Notes: "THE JSON ARM, and the only way this class reaches a JSON body at all: the name-slot " +
				"encoder refuses a JSON key rename and a JSON node slot carries no Name for it to " +
				"rename. This replaces the VALUE NODE at the slot's pointer with a one-key object, so " +
				"an application doing filter(**payload['filters']) unpacks OUR key into the resolver " +
				"and the same three signatures apply. The shape is the Label Studio / Ghost CVE shape. " +
				"UNVERIFIED end to end: the harvest measured the query dictionary, not a DRF body, so " +
				"the ORACLE is the same measured one and the REACH of this arm is the unproven half. " +
				"It is full tier rather than reduced because on a JSON body the odds that the pointer " +
				"feeds a filter are lower than on a query parameter, not because it is less safe",
		},
	}
}

func ormAllProbeIDs() []triage.ProbeID { return []triage.ProbeID{ormD1, ormD2} }

// ormReq builds one ProbeRequest.
//
// It is this class's own two lines rather than the protocol-effect family's pxReq because this
// class is not in that family and does not want to inherit its future. The Variant is empty and
// the Marker is left at its zero value ON PURPOSE: the runner mints the marker from this class's
// R12 ordinal stripe, and a class that filled it in could name an ordinal belonging to another
// class and have its own probe attributed there.
func ormReq(id triage.ProbeID, slot triage.SlotKey) triage.ProbeRequest {
	return triage.ProbeRequest{Spec: id, Slot: slot, Variant: map[string]string{}}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. The rule is the harvest's: a filter keyword is a map KEY, so this class reaches exactly
// the slots that sit in a name/value map the application unpacks.
func (ormLeakClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a query parameter's NAME is a key in the dictionary a view receives, which is the " +
				"exact thing an unvalidated filter(**params) unpacks. The condition is that the pair is " +
				"in the capture: the name-slot encoder edits the observed pair and refuses when the " +
				"name is not in the captured query string",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "two different mechanisms with two different conditions. A urlencoded form field is a " +
				"key the same way a query parameter is, and ORM-D1 renames it. A JSON body has no " +
				"renameable key at all (a JSON node slot carries no Name and the name-slot encoder " +
				"refuses a key rename), so ORM-D2 reaches it by putting a one-key OBJECT at the slot's " +
				"pointer instead, which only tests anything where the application unpacks that object. " +
				"Request media type seen: " + string(mt),
		}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "a filter keyword is a map KEY and a header slot has no key the application unpacks: " +
				"the header NAME is fixed by the capture and this layer perturbs header values, not " +
				"header names. An application that folds its whole header map into a queryset is a real " +
				"shape and it is not one any probe in this class can deliver",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "same as a header: the cookie NAME is the key and nothing here renames a cookie, so " +
				"there is no keyword to inject. A cookie VALUE reaching a filter keyword would mean the " +
				"application parsed the value into a map, which is a different sink and deserves its own " +
				"row rather than a claim on this one",
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "a path segment is positional. It has no name, so it cannot be a filter keyword, and " +
				"a segment that reaches a queryset reaches it as a VALUE, which SQL and NoSQL cover",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the fragment is never transmitted (RFC 3986 section 3.5), so the server never sees " +
				"the name or the value and no ORM can be handed either",
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

// Plan is ONE request on a name-bearing slot and one on a JSON node slot, in round 0, and nothing
// after that. There is no ladder, because there is nothing a second probe of this class could ask
// that the first one did not already answer: the oracle is a single unambiguous sentence and the
// arms that would need a second request are the three the encoder cannot deliver.
//
// THERE IS NO VERB GATE AND THAT IS DELIBERATE. The harvest suggests skipping a mutating verb
// because filter(**request.data) on a write path is a different sink. It is a different sink and
// it is still this class's sink, the line in this codebase is whose data rather than which verb,
// and a probe suppressed on a shape guess is a silent zero. The verb is recorded on the verdict
// instead, so an operator can filter on it afterwards.
func (c ormLeakClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType).Reach == triage.ReachNever {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() || ctx.Budget.Exhausted() {
		return nil
	}
	if ctx.Round != 0 {
		return nil
	}
	ids := ormProbesForSlot(ctx.Slot)
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		out = append(out, ormReq(id, ctx.Slot.Key))
	}
	return out
}

// ormProbesForSlot is WHICH of this class's two probes can render into this slot, as a pure
// function of the slot.
//
// It is separate from Plan because Plan's other gates (a resolved route control, a prelude, a
// budget) are things no test in this package can construct: a classifier cannot build a Replay,
// since NewReplay takes the runner capability and this package may not import it. Splitting the
// slot question out means the interesting half is exercised directly, instead of being asserted
// in a comment because the wrapper could not be driven.
func ormProbesForSlot(s triage.Slot) []triage.ProbeID {
	if _, ok := faEligibleSlot(s); !ok {
		return nil
	}
	if (ormLeakClassifier{}).Reaches(s.Kind, "").Reach == triage.ReachNever {
		return nil
	}
	var out []triage.ProbeID
	if ormSlotHasARenameableName(s) {
		out = append(out, ormD1)
	}
	if ormSlotIsAJSONNode(s) {
		out = append(out, ormD2)
	}
	return out
}

// ormSlotHasARenameableName reports whether ORM-D1's encoder has a key to replace here.
//
// It is asked at plan time for the reason SlotAcceptsEncoder exists: on a live run 971 probes were
// planned with an encoder that could never render into the slot they named, and every one of them
// cost an ordinal, a budget slot and a fidelity row before being refused inside the process. A
// JSON node slot has no Name, so ORM-D1 would be refused there every single time.
func ormSlotHasARenameableName(s triage.Slot) bool {
	if strings.TrimSpace(s.Name) == "" {
		return false
	}
	switch s.Kind {
	case triage.KindQuery:
		return true
	case triage.KindBody:
		return s.BodyMedia == triage.BodyForm
	}
	return false
}

// ormSlotIsAJSONNode reports whether ORM-D2's node-replace encoder can render here. An unset body
// media is JSON, which is how triageSlotBodyMedia resolves it, so the same reading is used here
// rather than a second one that could disagree.
func ormSlotIsAJSONNode(s triage.Slot) bool {
	if s.Kind != triage.KindBody {
		return false
	}
	switch s.BodyMedia {
	case triage.BodyJSON, triage.BodyGraphQL, triage.BodyNone, "":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// THE DETECTOR
// ---------------------------------------------------------------------------------------------

// ormDialect names which engine answered, because the follow-up is different for each.
type ormDialect string

const (
	ormDialectDjangoField  ormDialect = "django_fielderror"
	ormDialectDjangoLookup ormDialect = "django_unsupported_lookup"
	ormDialectPrisma       ormDialect = "prisma_unknown_argument"
)

// ormSignature is one anchored phrase. The quoted token is always THIS probe's own marker plus
// this class's literal, which is what makes a hit attributable without a baseline.
type ormSignature struct {
	Dialect ormDialect
	Prefix  string
	Suffix  string
	Oracle  string
	Why     string
}

// ormSignatures is the whole table. Three phrases, each measured or cited, and nothing generic.
//
// THERE IS NO RANSACK ROW AND THAT IS A DECISION. Ransack's failure text was not measured (no Ruby
// on the harvest machine) and inventing the bytes would produce either a detector that never fires
// or one that fires on prose. A Ransack application that 500s with our marker in the body reaches
// orm_error_unclassified at suspicious, which is the honest state for "an ORM-shaped error carrying
// our keyword that this table cannot name".
var ormSignatures = []ormSignature{
	{
		Dialect: ormDialectDjangoField,
		Prefix:  "Cannot resolve keyword ",
		Suffix:  " into field.",
		Oracle:  "orm_field_enumeration",
		Why: "Django's FieldError for a keyword that is not a field on the model. The same sentence " +
			"carries 'Choices are:' followed by every column name, which is the payoff",
	},
	{
		Dialect: ormDialectDjangoLookup,
		Prefix:  "Unsupported lookup ",
		Suffix:  " for ",
		Oracle:  "orm_field_type_disclosure",
		Why: "Django's FieldError for a keyword that arrived as a LOOKUP on a real field, which happens " +
			"when the application prefixes our key itself. The token after 'for ' is the field's type, " +
			"and ForeignKey there is the precondition for the relational-leak chain",
	},
	{
		Dialect: ormDialectPrisma,
		Prefix:  "Unknown argument ",
		Suffix:  "",
		Oracle:  "orm_unknown_argument",
		Why: "Prisma's rejection of a where-argument it does not know. UNVERIFIED: no Node was available " +
			"when the payloads were measured, so this row is cited from the harvest and not from a run",
	},
}

// ormQuoteForms are the spellings the quotes around the keyword arrive in.
//
// THIS IS THE TRAP THAT WOULD HAVE MADE THE CLASS SILENT ON THE COMMONEST DEPLOYMENT. Django's
// technical 500 page renders the exception value through django.utils.html.escape, so on an HTML
// error page the apostrophes are &#x27; and a matcher looking for a raw ' finds nothing on exactly
// the deployment (DEBUG=True) where the oracle is available at all. A JSON or plain-text error
// keeps the raw apostrophe. Both are matched, and the form that matched is recorded on the verdict
// so a reader can tell which surface answered.
//
// NOT MEASURED IN THE HARVEST SESSION: the harvest captured the exception TEXT, not the rendered
// page, so the escaped spellings here are from Django's escaping rules rather than from a capture.
// They cost nothing if they never match and they are the difference between a hit and a silence if
// they do.
var ormQuoteForms = []struct{ Name, Open, Close string }{
	{"apostrophe", "'", "'"},
	{"html_numeric_hex", "&#x27;", "&#x27;"},
	{"html_numeric_dec", "&#39;", "&#39;"},
	{"html_named", "&apos;", "&apos;"},
	{"double_quote", `"`, `"`},
	{"html_double_quote", "&quot;", "&quot;"},
}

// ormHit is one signature match in one of this class's own responses.
type ormHit struct {
	Obs       faOwnObs
	Dialect   ormDialect
	Oracle    string
	QuoteForm string
	Offset    int
	Length    int
	Matched   []byte
	// Fields is the leaked column list, for the Django field arm. Empty when the sentence carried
	// no "Choices are:" clause, which is a shorter Django message and still a finding.
	Fields string
	// FieldType is the Django field class named after "for ", for the lookup arm.
	FieldType string
}

// ormToken is the exact string a signature expects to find quoted: this probe's own marker plus
// this class's literal. An observation with no marker produces an empty token and matches nothing,
// which is the fail-closed answer: a probe whose marker never reached the wire cannot have its
// keyword quoted back.
func ormToken(m triage.Marker) string {
	if !m.WellFormed() {
		return ""
	}
	return string(m) + ormOwnedLiteral
}

// ormScan runs the signature table over one response.
//
// EVERY ARM IS ANCHORED ON THE TOKEN AND NOT ON THE PHRASE. "Cannot resolve keyword" on its own is
// the application's own error about its own field name, and a detector that fired on it would fire
// on every Django application that has ever logged a bad query. The phrase is the context; the
// quoted token is the evidence.
func ormScan(o faOwnObs) (ormHit, bool) {
	tok := ormToken(o.Marker)
	if tok == "" || len(o.Obs.Body) == 0 {
		return ormHit{}, false
	}
	body := o.Obs.Body
	for _, sig := range ormSignatures {
		for _, q := range ormQuoteForms {
			needle := sig.Prefix + q.Open + tok + q.Close + sig.Suffix
			i := bytes.Index(body, []byte(needle))
			if i < 0 {
				continue
			}
			h := ormHit{
				Obs: o, Dialect: sig.Dialect, Oracle: sig.Oracle, QuoteForm: q.Name,
				Offset: i, Length: len(needle), Matched: body[i : i+len(needle)],
			}
			switch sig.Dialect {
			case ormDialectDjangoField:
				h.Fields = ormChoicesAfter(body[i+len(needle):])
			case ormDialectDjangoLookup:
				h.FieldType = ormFirstToken(body[i+len(needle):])
			}
			return h, true
		}
	}
	return ormHit{}, false
}

// ormChoicesMaxRun caps how much of the body the choices clause may claim. A model with forty
// columns is real; a body that never terminates the clause is a body we are reading wrong, and a
// cap turns that into a truncated annotation rather than a megabyte in a verdict row.
const ormChoicesMaxRun = 512

// ormChoicesAfter extracts the leaked column list from the text following a FieldError match.
//
// Django writes "... into field. Choices are: created_by, created_by_id, id, title". The clause
// ends at a newline in a plain-text or JSON error and at a tag in the rendered HTML page, so both
// terminators are honoured and the shorter wins.
func ormChoicesAfter(rest []byte) string {
	const lead = "Choices are:"
	i := bytes.Index(rest, []byte(lead))
	if i < 0 {
		return ""
	}
	tail := rest[i+len(lead):]
	if len(tail) > ormChoicesMaxRun {
		tail = tail[:ormChoicesMaxRun]
	}
	end := len(tail)
	for _, stop := range []byte{'\n', '\r', '<'} {
		if j := bytes.IndexByte(tail, stop); j >= 0 && j < end {
			end = j
		}
	}
	return strings.TrimSpace(string(tail[:end]))
}

// ormFirstToken reads the field type Django names after "for ", for example CharField or
// ForeignKey. It stops at the first space or punctuation so that "ForeignKey or join on the field
// not permitted." yields ForeignKey and not the sentence.
func ormFirstToken(rest []byte) string {
	end := 0
	for end < len(rest) {
		c := rest[end]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' {
			end++
			continue
		}
		break
	}
	return string(rest[:end])
}

// ormMarkerEchoed reports whether this probe's own keyword came back anywhere in the body at all.
//
// It is NOT an oracle and it never produces a positive. Every echo endpoint reflects a parameter
// name, so on its own this means the response contains our bytes and nothing more. It is measured
// because it is the difference between two very different cleans: "the name reached the response
// and no ORM complained" and "nothing we sent came back at all".
func ormMarkerEchoed(o faOwnObs) bool {
	tok := ormToken(o.Marker)
	if tok == "" {
		return false
	}
	return bytes.Contains(o.Obs.Body, []byte(tok)) ||
		bytes.Contains(bytes.ToLower(o.Obs.Body), []byte(strings.ToLower(tok)))
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

// Classify is the eligibility gate, the vault read, and then ormDecide.
//
// THE SPLIT IS FOR THE TESTS AND IT IS NOT COSMETIC. A classifier cannot build an
// OwnedResponses: OwnFor takes a runner capability whose type lives in an internal package this
// package may not import, which is exactly the protection that makes the vault worth having. The
// consequence is that no test in this package can drive Classify through a populated ctx.Own. So
// the whole verdict ladder lives in ormDecide, which takes the resolved own-set, and every arm
// below is exercised by ormleak_test.go against handcrafted responses. A ladder nothing can test
// is a ladder whose arms are asserted rather than checked.
func (c ormLeakClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassORMLeak, key, state, reason, oracle, grade, ords, ann, ormLabel(ann))
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}
	routeStatus, haveRoute := pxRouteStatus(ctx)
	return ormDecide(ctx, faOwn(ctx.Own), routeStatus, haveRoute)
}

// ormDecide is the verdict ladder. It is given THIS class's own responses, already resolved, and
// the unperturbed control's STATUS rather than the control itself.
//
// THE CONTROL ARRIVES AS A STATUS AND A BOOL FOR ONE REASON: no test in this package can build a
// resolved Replay, because NewReplay takes the runner capability whose type lives in an internal
// package a classifier may not import. That is the right protection and it has a cost, which is
// that every route-dependent arm of every class in this package is normally unreachable from a
// test and is therefore asserted rather than checked. Passing the one derived fact this ladder
// needs buys all four of those arms back: the junk-sensitivity gate, the refusal bucket, the
// validation bucket and the status differential are each exercised in ormleak_test.go against a
// named control status.
func ormDecide(ctx triage.ClassifyCtx, own []faOwnObs, routeStatus int, haveRoute bool) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassORMLeak, key, state, reason, oracle, grade, ords, ann, ormLabel(ann))
	}

	ann["slot_is_the_parameter_name"] = true
	ann["method"] = ctx.Slot.Method
	ann["append_arms_not_shipped"] = "the harvest's three APPEND payloads (Django __lookup, Prisma " +
		"bracket, Ransack predicate) need the observed parameter NAME inside the payload bytes, and the " +
		"runner's substitution grammar has no token for it, so they are NOT tested here and no silence " +
		"on this slot says anything about them"
	ann["django_debug_false_caveat"] = "with DEBUG=False a Django FieldError is an unhandled exception " +
		"and the body carries no keyword at all, so the strong oracle is unavailable on a production " +
		"deployment and only the status differential remains"

	if len(own) == 0 {
		return one(ormNothingSent(ctx))
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
	skips = append(skips, pxNotObserved(ormAllProbeIDs(), own)...)
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

	if haveRoute {
		ann["route_control_status"] = routeStatus
	}
	ann["baseline_bodies_compared"] = len(faBaselineBodies(ctx))

	// THE FINDING. One sentence, this probe's own keyword quoted inside it.
	for _, o := range honest {
		h, ok := ormScan(o)
		if !ok {
			continue
		}
		ann["winning_probe"] = string(h.Obs.ProbeID)
		ann["dialect"] = string(h.Dialect)
		ann["quote_form"] = h.QuoteForm
		ann["status"] = h.Obs.Obs.Status
		if h.Fields != "" {
			ann["leaked_fields"] = h.Fields
			ann["leaked_field_count"] = len(strings.Split(h.Fields, ","))
		}
		if h.FieldType != "" {
			ann["leaked_field_type"] = h.FieldType
			ann["field_is_a_relation"] = strings.Contains(h.FieldType, "ForeignKey") ||
				strings.Contains(h.FieldType, "ManyToMany") || strings.Contains(h.FieldType, "OneToOne")
		}
		v := one(triage.StateFinding, ormFindingReason(h), h.Oracle, triage.GradeHigh, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: h.Obs.Ordinal, ObsID: h.Obs.Obs.ObsID, Phrase: string(h.Dialect),
			Matched: h.Matched, Offset: h.Offset, Length: h.Length,
			Wire: h.Obs.Obs.Payload, MarkerForm: "raw",
		}
		return v
	}

	// THE JUNK-SENSITIVITY GATE. If the unperturbed route control is itself a 5xx, then a 5xx on a
	// probe is the endpoint's normal behaviour and the status differential says nothing at all.
	if haveRoute && routeStatus >= 500 {
		v := one(triage.StateCannotDetermine,
			"junk_sensitive: the unperturbed route control returned "+strconv.Itoa(routeStatus)+
				", so this endpoint errors without any help from us. No keyword came back in any probe "+
				"and the status differential, which is the only other reading available, cannot be taken "+
				"against a control that is already failing",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE MARKER IN A 5xx WITH NO PHRASE THIS TABLE KNOWS. An ORM-shaped error carrying our own
	// keyword that the signature table cannot name is exactly the Ransack case, and it is also
	// what a wrapped Django error looks like. It is suspicious and it is never clean.
	for _, o := range honest {
		if o.Obs.Status < 500 || !ormMarkerEchoed(o) {
			continue
		}
		ann["winning_probe"] = string(o.ProbeID)
		ann["status"] = o.Obs.Status
		v := one(triage.StateSuspicious,
			"orm_error_unclassified: probe "+string(o.ProbeID)+" made this endpoint return "+
				strconv.Itoa(o.Obs.Status)+" and this probe's own keyword is in the error body, but none "+
				"of the three phrases this class knows is around it. Something server-side read our map "+
				"KEY and failed on it by name, which is the mechanism; what it is not is an engine this "+
				"class can name, so it is reported at suspicious with the body offset rather than "+
				"promoted or dropped. Ransack and every framework that wraps its ORM error land here",
			"orm_error_unclassified", triage.GradeMedium, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: o.Ordinal, ObsID: o.Obs.ObsID, Phrase: "marker_in_5xx",
			Wire: o.Obs.Payload, MarkerForm: "raw",
		}
		return v
	}

	// THE STATUS DIFFERENTIAL, WHICH IS THE ONLY THING PRODUCTION DJANGO LEAVES. A 500 with no
	// keyword in it, against a control that did not 500, is the DEBUG=False shape of this very bug
	// and is also the shape of a view that needed the parameter we renamed. Both readings are
	// written into the reason rather than one of them being chosen silently.
	for _, o := range honest {
		if o.Obs.Status < 500 || (haveRoute && routeStatus >= 500) {
			continue
		}
		ann["winning_probe"] = string(o.ProbeID)
		ann["status"] = o.Obs.Status
		v := one(triage.StateSuspicious,
			"orm_500_differential: renaming this parameter to a keyword nothing can resolve turned a "+
				ormRouteStatusPhrase(routeStatus, haveRoute)+" into "+strconv.Itoa(o.Obs.Status)+
				" and no keyword came back in the body. TWO READINGS AND THIS CLASS CANNOT SEPARATE THEM "+
				"FROM HERE: a production Django (DEBUG=False) raising FieldError on our keyword looks "+
				"exactly like this, and so does a view that simply required the parameter we renamed. "+
				"The first is the bug and the second is not. The cheap separation is a second request "+
				"with a DIFFERENT unresolvable keyword and one with the original name restored, which "+
				"is replay_request twice",
			"orm_500_differential", triage.GradeLow, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: o.Ordinal, ObsID: o.Obs.ObsID, Phrase: "status_differential", Wire: o.Obs.Payload,
		}
		return v
	}

	// BEFORE ANY NEGATIVE: DID WE ACTUALLY GET THE ENDPOINT'S ANSWER?
	//
	// THE GUARD THIS CLASS CANNOT USE, AND WHY IT IS REPLACED RATHER THAN OMITTED. Every other
	// class in this package reaches for faUniformBlock, which fires when THREE distinct payloads
	// produce one identical non-baseline body. This class sends at most TWO probes per slot, so
	// that guard can never return true here: wiring it in would have been a guard that reads as
	// present and is arithmetically dead, and the fall-through it was guarding is StateClean. A
	// WAF 403 would have been recorded as "no ORM error surface", which is a false clean and the
	// exact failure this layer exists to stop.
	//
	// So the block question is asked the way a one-probe class can ask it: by STATUS CLASS against
	// the unperturbed control. Three buckets, three different facts, and only one of them is a
	// statement about the application's ORM.
	if haveRoute && routeStatus < 400 {
		for _, o := range honest {
			st := o.Obs.Status
			if st < 400 || st >= 500 {
				continue
			}
			ann["winning_probe"] = string(o.ProbeID)
			ann["status"] = st
			switch st {
			case 401, 403, 406, 429, 451:
				v := one(triage.StateCannotDetermine,
					"request_refused_before_the_view: the unperturbed control returned "+
						strconv.Itoa(routeStatus)+" and renaming one parameter turned it into "+
						strconv.Itoa(st)+". That status class is a filter, a rate limiter or an "+
						"authorisation layer answering, not a queryset, so the ORM never saw this "+
						"keyword and nothing here is known about whether it would have resolved it",
					"", triage.GradeUnrated, ords)
				v[0].Untested = skips
				return v
			case 400, 409, 415, 422:
				ann["defence"] = "the endpoint refuses a parameter name it does not recognise"
				v := one(triage.StateNotExploitable,
					"unknown_parameter_rejected: the control returned "+strconv.Itoa(routeStatus)+
						" and a parameter renamed to a keyword nothing can resolve returned "+
						strconv.Itoa(st)+". That is a NAMED DEFENCE and a better answer than clean: the "+
						"endpoint validates its parameter NAMES, so an unvalidated dictionary never "+
						"reaches a filter. WHAT IT DOES NOT COVER: a name the validator happens to "+
						"accept and pass through, and the three append arms this class cannot deliver",
					"name_validated", triage.GradeUnrated, ords)
				v[0].Untested = skips
				return v
			default:
				v := one(triage.StateCannotDetermine,
					"status_changed_unknown_cause: the control returned "+strconv.Itoa(routeStatus)+
						" and this probe returned "+strconv.Itoa(st)+". The response scored here is not "+
						"the answer this endpoint normally gives, and this class cannot tell a router "+
						"that stopped matching from a handler that refused the name",
					"", triage.GradeUnrated, ords)
				v[0].Untested = skips
				return v
			}
		}
	}

	// THE PRECONDITION, BEFORE EITHER NEGATIVE: WAS THERE A BODY TO LOOK IN?
	//
	// THIS CLASS'S ORACLE IS AN ERROR PHRASE IN A RESPONSE BODY. ormScan reads FieldError, Unknown
	// argument and Unknown column out of bytes, ormMarkerEchoed searches the same bytes for the
	// keyword, and the shipped reason said "neither the keyword nor any ORM error phrase appeared".
	// On /clean/empty204 and /clean/nothing that sentence was TRUE AND VACUOUS: it appeared in no
	// bytes because there were no bytes, and the class reported clean on both. The status arms
	// above still work on an empty response, which is why this is asked last and not first: a 500
	// with no body is a real differential and it must keep its suspicious.
	//
	// The 5xx-control half of pxReadsBody is already shipped in this class as the junk_sensitive
	// gate further up, which is why /clean/always500 was never one of the false cleans here. The
	// helper asks it again and finds it already answered, which costs one comparison.
	bodyControl, haveBodyControl := pxRouteControl(ctx)
	return ormNegative(honest, bodyControl, haveBodyControl, ann, ords, skips, one)
}

// ormNegative is everything between the last oracle and the clean, and it is a function for the
// reason ormDecide itself is one: the two guards in it are statements ABOUT THE UNPERTURBED ROUTE
// CONTROL, and no test in this package can build a resolved Replay to put one in a ClassifyCtx.
// ormDecide takes the control's STATUS as a plain value and that bought four arms back; these two
// need the control's BODY as well, so the seam moves one level down and takes the observation.
func ormNegative(honest []faOwnObs, bodyControl triage.Observation, haveBodyControl bool,
	ann map[string]any, ords []uint64, skips []triage.ProbeSkip,
	one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict,
) []triage.ClassVerdict {
	ann["evidence_surface"] = string(pxReadsBody)
	if why, absent := pxNoEvidenceToRead(pxReadsBody, honest, bodyControl, haveBodyControl); absent {
		v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// THE SAME 4xx FACT, ON THE ONE SLOT SHAPE WHERE THE SHARED RULE CANNOT SEE IT.
	if why, refused := ormControlRefusesEveryoneUnwitnessed(honest, bodyControl, haveBodyControl); refused {
		v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// The negatives. Both of them are real answers about the application and both name what they
	// did not cover.
	echoed := false
	for _, o := range honest {
		if ormMarkerEchoed(o) {
			echoed = true
			break
		}
	}
	ann["keyword_echoed_in_a_response"] = echoed
	searchedProbes, searchedBytes := pxBodyBytesRead(honest)
	ann["bodies_searched"] = searchedProbes
	ann["body_bytes_searched"] = searchedBytes
	// A PRECONDITION LIST MAY ONLY PRINT A CHECK THAT ACTUALLY RAN. Two of the five lines below
	// are statements about the unperturbed route control, and where none resolved neither of them
	// was tested: pxBodySurfaceUnreadable skips both of its control arms without one and the
	// refusal witness returns false on the spot. Printing them anyway is the stale-fact failure,
	// and an operator reads a listed precondition as a check that passed.
	controlLines := []string{
		"NO UNPERTURBED ROUTE CONTROL RESOLVED, so the two facts a control would have established " +
			"here (that it was not itself 5xx, and that it was not a 4xx this class's probes " +
			"reproduced) were NOT CHECKED on this slot",
	}
	if haveBodyControl {
		controlLines = []string{
			"the unperturbed route control resolved and did not itself return 5xx",
			"THE ENDPOINT IS NOT REFUSING EVERYONE AS FAR AS THIS CLASS COULD SEE: the control was " +
				"not a 4xx that every delivered probe of this class came back indistinguishable from",
		}
	}
	ann["clean_preconditions"] = append([]string{
		"THERE WAS A BODY TO SEARCH: " + pxCount(searchedProbes, "of this class's responses") +
			" carried one, " + pxCount(searchedBytes, "bytes") + " in total. Without this line the " +
			"sentence below is true of a 204 as well, and it was",
		"every probe counted here reached the wire with its own marker in it (pxHonest)",
	}, append(controlLines,
		"no response carried this probe's own keyword inside any of the three ORM error phrases",
		"no probe produced a 5xx that the route control did not",
	)...)
	ann["what_this_clean_does_not_cover"] = "the three APPEND arms this encoder cannot deliver; a " +
		"production Django whose FieldError is swallowed into a 200 error envelope; any ORM whose " +
		"unknown-keyword behaviour is to IGNORE the keyword silently, which is Ransack's default on " +
		"some versions and is indistinguishable from not reaching the ORM at all"

	if echoed {
		v := one(triage.StateClean,
			"keyword_echoed_no_orm_error: the parameter NAME was replaced with a keyword nothing can "+
				"resolve, the keyword came back in the response, and no ORM complained about it. The name "+
				"reaches the application and it does not reach a queryset's keyword arguments unvalidated. "+
				"An echo on its own is not a finding in any class and it is not one here",
			"no_orm_error_on_an_unresolvable_keyword", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	v := one(triage.StateClean,
		"no_orm_error_surface: this slot's parameter name was replaced with a keyword nothing can "+
			"resolve, the endpoint answered "+ormStatusList(honest)+", and neither the keyword nor "+
			"any ORM error phrase appeared in the "+pxCount(searchedBytes, "bytes of response body")+
			" this class searched across "+pxCount(searchedProbes, "responses")+". The application "+
			"is not handing this request dictionary to a filter it has not validated",
		"no_orm_error_on_an_unresolvable_keyword", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// ormControlRefusesEveryoneUnwitnessed is the 4xx arm of pxReadsBody, on the one slot shape where
// the shared rule can never reach it, and it REFUSES instead of concluding.
//
// THE ARM THAT CANNOT RUN. pxBodySurfaceUnreadable's 4xx half needs a second witness: at least
// pxDifferentialWitnessFloor (2) of this class's own delivered probes must have come back
// indistinguishable from the 4xx control before "every body I searched was the refusal's page" is
// allowed to mean anything. THIS CLASS DELIVERS EXACTLY ONE PROBE ON A NAME-BEARING SLOT. Plan
// sends ORM-D1 on a slot with a renameable name and ORM-D2 on a JSON node slot, and a query
// parameter is the first and never the second, so s.Flat on a query slot is 1 at its ceiling and
// the floor is 2. The arm is not merely silent there. It is ARITHMETICALLY DEAD, which is the same
// defect as a control that could never fire, and a clean resting on it is resting on a check that
// never ran.
//
// MEASURED, canary oracle, MATRIX A. /trav/append answers 404 with the same 30 bytes to
// ?file=hello, to ?file=zzqq99 and to ?file=../../etc/passwd. LFI and DESER both refuse there with
// control_refuses_everyone. ORM-LEAK said clean / no_orm_error_surface at sent=1, over a body that
// is the 404 page and nothing else.
//
// WHY NOT SEND A SECOND PROBE INSTEAD, WHICH IS THE OTHER WAY TO MEET THE FLOOR. It would cost one
// extra request on EVERY query slot of every vector in a run, to buy a witness that changes an
// answer only where the control is a 4xx, and it would need a second distinct payload under the
// isolation law for a class whose own Plan records that there is nothing a second probe of this
// class could ask. The refusal costs no requests and it withdraws only cleans that were never
// earned. On the operator's estate, which answers 401 to 88% of probes, it is the difference
// between a row that says "not measured" and a row that says "not vulnerable".
//
// WHAT IT DOES NOT SAY, AND THE DISTINCTION IS THE POINT: it does not say the endpoint refuses
// everyone. It says this class could not witness that to the standard the shared rule sets, and
// therefore may not read a silence here as an answer.
func ormControlRefusesEveryoneUnwitnessed(honest []faOwnObs, control triage.Observation,
	haveControl bool) (string, bool) {

	if !haveControl || control.Status < 400 || control.Status >= 500 {
		return "", false
	}
	s := pxRouteSensitivity(honest, control, haveControl)
	if s.Delivered == 0 || s.Moved > 0 || s.Flat >= pxDifferentialWitnessFloor {
		// Delivered == 0 is the caller's own no_probe_reached_the_wire exit, Moved > 0 means the
		// endpoint handed this class a real body to read, and at or above the floor the shared
		// arm in pxBodySurfaceUnreadable has already refused with a stronger sentence than this
		// one. Answering twice in two voices helps nobody.
		return "", false
	}
	why := "control_refuses_everyone_unwitnessed: the unperturbed route control carries none of our " +
		"bytes and it answered " + strconv.Itoa(control.Status) + ", and "
	if s.Flat > 0 {
		why += pxCount(s.Flat, "of this class's "+strconv.Itoa(s.Delivered)+" delivered probe(s)") +
			" came back with the same status and the same normalised body as that control, not one " +
			"of them moving it"
	} else {
		why += "not one of this class's " + pxCount(s.Delivered, "delivered probe(s)") +
			" could be compared against it at all"
	}
	if s.Unknown > 0 && s.Flat > 0 {
		why += " (" + pxCount(s.Unknown, "further probe(s)") + " could not be compared at all)"
	}
	return why + ". pxBodySurfaceUnreadable REFUSES EXACTLY THIS AND IT NEEDS " +
		strconv.Itoa(pxDifferentialWitnessFloor) + " PROBES THAT REPRODUCED THE CONTROL BEFORE IT " +
		"WILL, AND THIS CLASS CANNOT REACH THAT COUNT HERE: it plans ORM-D1 where the slot has a " +
		"renameable name and ORM-D2 where the slot is a JSON node, so a query parameter is planned " +
		"exactly one probe and the floor of " + strconv.Itoa(pxDifferentialWitnessFloor) + " is out " +
		"of reach however the arm is wired. An arm that cannot be satisfied is not a check that " +
		"passed, and the clean this row replaces was standing on it. What is left, and it is the " +
		"whole of what was measured, is that every body this class searched came back from an " +
		"endpoint whose answer to a request carrying none of our bytes is a " +
		strconv.Itoa(control.Status) + ". WHAT THIS DOES NOT CLAIM: that the endpoint refuses " +
		"everyone, or why it answered as it did. A 404 and a 401 are different facts about a " +
		"target and this row distinguishes neither. It says the witness the shared rule asks for " +
		"is out of this class's reach on this slot, so the silence of its three phrase searches " +
		"is not an answer about the application. Next: " +
		"replay_request at the same slot with a credential or a value this route accepts, which " +
		"turns a refusal page into a body worth searching", true
}

// ormStatusList names the statuses this class actually got, because the sentence it replaces said
// "the request was answered normally" and that is a judgement rather than a measurement.
//
// MEASURED, 80-route exam: /clean/echomongo answers 400 to the observed value and 400 to the
// renamed one with a different body, so this class reads a real answer there, reaches its clean,
// and shipped the words "the request was answered normally" over a Bad Request. The state is
// right and the clause was not. A status is a fact and "normally" is an opinion about somebody
// else's API, so the row prints the fact.
func ormStatusList(honest []faOwnObs) string {
	seen := map[int]bool{}
	var codes []int
	for _, o := range honest {
		if !o.Obs.Delivered() || seen[o.Obs.Status] {
			continue
		}
		seen[o.Obs.Status] = true
		codes = append(codes, o.Obs.Status)
	}
	if len(codes) == 0 {
		return "nothing this class could read a status from"
	}
	sort.Ints(codes)
	parts := make([]string, 0, len(codes))
	for _, c := range codes {
		parts = append(parts, strconv.Itoa(c))
	}
	return strings.Join(parts, " and ")
}

// ormRouteStatusPhrase renders the control's status for a reason string, and says plainly when
// there was no control rather than printing a zero that reads like one.
func ormRouteStatusPhrase(status int, have bool) string {
	if !have {
		return "response the route control never measured"
	}
	return strconv.Itoa(status)
}

// ormFindingReason writes the sentence an operator reads first. Each dialect gets its own, because
// the follow-up work is different for each and a shared sentence would bury that.
func ormFindingReason(h ormHit) string {
	switch h.Dialect {
	case ormDialectDjangoField:
		base := "orm_field_enumeration: the application handed this request's parameter NAMES to an ORM " +
			"without validating them. Django answered with a FieldError quoting THIS PROBE'S OWN 20-byte " +
			"keyword, which was minted for this probe in this run, so no baseline and no pre-existing " +
			"stack trace on this endpoint can have produced it"
		if h.Fields == "" {
			return base + ". The message carried no 'Choices are:' clause, which is the shorter Django " +
				"form; the reachability is proven and the column list is not in this body"
		}
		return base + ". The same sentence ENUMERATES THE MODEL'S COLUMNS: " + h.Fields +
			". Next: pick a column and binary-search its value through __startswith with replay_request, " +
			"which is how this becomes a password-hash disclosure rather than a schema disclosure"
	case ormDialectDjangoLookup:
		return "orm_field_type_disclosure: the application prefixed this probe's keyword onto a field of " +
			"its own and handed the result to Django, which answered 'Unsupported lookup' and named the " +
			"field's TYPE (" + h.FieldType + "). The keyword quoted is this probe's own, so the message is " +
			"attributable to this request. A relation type here is the precondition for traversing into " +
			"another model's columns with a double-underscore path"
	case ormDialectPrisma:
		return "orm_unknown_argument: Prisma rejected an argument named with THIS PROBE'S OWN keyword, " +
			"which means the request's parameter names reach a where clause unvalidated. The dialect row " +
			"is cited rather than measured (no Node was available when the payloads were verified), so " +
			"confirm the engine before writing the report; the attribution itself is not in doubt"
	}
	return "orm_leak: an ORM named this probe's own keyword back"
}

// ormNothingSent maps "this class has no observations at all" onto the right unknown. None of the
// four is a clean and each one is a different fact.
func ormNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"control to read a status differential against and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain, so every probe would " +
				"have measured the same validation failure rather than the ORM", "", triage.GradeUnrated, nil
	}
	// THE PLANNER IS ASKED FIRST AND THE BUDGET SECOND, and THIS is the class where verdicts
	// actually move: ormProbesForSlot genuinely returns nothing on some slots (a JSON node has no
	// name to rename, a name slot has no body node), and with the budget arm above the default
	// every one of those rows read probe_budget_exhausted on a capped run. See pxbudgetarm.go.
	state, reason := pxNothingSentTail(ctx, len(ormProbesForSlot(ctx.Slot)), "this class's one request",
		"no ORM-leak probe was derived for this slot: the name-slot encoder needs a parameter name to "+
			"replace and the node encoder needs a JSON body, and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// ormLabel is what the verdict hands to the expensive scanner, and for this class the honest
// answer is that there is nothing to hand it.
//
// THE POINTER IS none (manual) AND THAT IS THE ARGUMENT FOR THE CLASS RATHER THAN AGAINST IT.
// There is no ORM-leak tool among the framework's fifty containers. Naming a tool that cannot see
// this would send the operator somewhere that will come back empty and read as a refutation.
func ormLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"tool": "none (manual). No container in this framework detects an ORM keyword leak. The " +
			"follow-up is replay_request: re-send the winning request with __startswith on a leaked " +
			"column and binary-search the value one character at a time",
		"forbidden": "do NOT follow the harvest's __regex arm. Its payload is a catastrophic-backtracking " +
			"expression and this layer does not exhaust a target's CPU",
	}
	if f, ok := ann["leaked_fields"].(string); ok && f != "" {
		hints["leaked_fields"] = f
	}
	if d, ok := ann["dialect"].(string); ok && d != "" {
		hints["dialect"] = d
	}
	return triage.TriageLabel{Engine: "", Dialect: "", Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// THE EXTENSION SURFACE
// ---------------------------------------------------------------------------------------------

// Confirmers. One named second measurement, and it is the one an operator can run by hand today.
func (ormLeakClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "second_unresolvable_keyword",
			Probes: []triage.ProbeID{
				ormD1, ormD2,
			},
			Rule: "re-send the winning request with a DIFFERENT unresolvable keyword. The FieldError must " +
				"quote the NEW keyword. If it quotes the old one the body is cached, and if it quotes " +
				"neither the first hit was not ours. This is also the separation the 500-differential arm " +
				"cannot make from inside one run",
		},
		{
			Name:   "original_name_restored",
			Probes: []triage.ProbeID{ormD1},
			Rule: "re-send with the observed name and the observed value. It must return the baseline. An " +
				"endpoint that 500s on its own captured request makes every reading on this slot " +
				"junk_sensitive, and that is the check the route control performs automatically here",
		},
	}
}

// Evidencers name what this class extracts and hands on.
func (ormLeakClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "leaked_fields", Kind: "content",
			What: "the model's complete column list, taken from the 'Choices are:' clause of the FieldError"},
		{Name: "leaked_field_type", Kind: "content",
			What: "the Django field class named after 'for ' in an Unsupported lookup message, including " +
				"whether it is a relation"},
		{Name: "dialect", Kind: "annotation",
			What: "which ORM answered: django_fielderror, django_unsupported_lookup or prisma_unknown_argument"},
		{Name: "quote_form", Kind: "annotation",
			What: "whether the keyword came back inside raw apostrophes or HTML-escaped ones, which says " +
				"whether the surface was a rendered debug page or a text or JSON error"},
	}
}

// OracleCases is what the oracle container owes this class before its detector can be called
// VERIFIED. A detector only ever observed FIRING scores the same as one that always returns true,
// so the silent routes are the ones doing the verifying.
func (ormLeakClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "django_debug_fielderror", Route: "/orm/django", Expect: faExpectPositive,
			Probes: []triage.ProbeID{ormD1}, WantState: triage.StateFinding, Exists: false,
			Why: "a route that unpacks the query dictionary into a filter and renders the FieldError the " +
				"way a DEBUG=True Django does, INCLUDING the HTML-escaped apostrophes. The escaped form is " +
				"the one a real debug page emits and the one a naive matcher misses",
		},
		{
			Name: "django_production_500", Route: "/orm/djangoprod", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ormD1}, WantState: triage.StateSuspicious, Exists: false,
			Why: "the same route with DEBUG=False: a bare 500 with no keyword in the body. The class must " +
				"reach orm_500_differential at suspicious and must NOT reach finding and must NOT reach " +
				"clean. This is the case that proves the degradation is handled rather than asserted",
		},
		{
			Name: "foreign_fielderror", Route: "/orm/othererror", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ormD1}, WantState: triage.StateClean, Exists: false,
			Why: "a route that returns a REAL Django FieldError naming a different keyword entirely. The " +
				"detector must stay silent, because the phrase is the context and the quoted token is the " +
				"evidence. Without this route the class has been demonstrated and not tested",
		},
		{
			Name: "name_echo_is_not_a_leak", Route: "/clean/echoparser", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ormD1}, WantState: triage.StateClean, Exists: true,
			Why: "an endpoint that echoes the parameter name back. Every echo endpoint does this and it is " +
				"not an ORM leak; the class must record the echo and stay clean",
		},
		{
			Name: "control_refuses_everyone", Route: "/trav/append", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ormD1}, WantState: triage.StateCannotDetermine, Exists: true,
			Why: "an endpoint that answers 404 with the same 30 bytes to the unperturbed control and " +
				"to this class's only probe. The body searched for a FieldError is the page this " +
				"endpoint hands a request it is refusing, and the verdict owed is cannot_determine at " +
				"control_refuses_everyone_unwitnessed rather than clean. It is declared as its own " +
				"case because the shared 4xx arm in pxBodySurfaceUnreadable needs two probes that " +
				"reproduced the control and this class delivers one on a query slot, so the shared " +
				"rule is ARITHMETICALLY UNREACHABLE here: without this row the class reports a clean " +
				"resting on a check that never ran, which is what it did until this round",
		},
		{
			Name: "an_error_in_every_body", Route: "/clean/dberror", Expect: faExpectNegative,
			Probes: []triage.ProbeID{ormD1}, WantState: triage.StateClean, Exists: true,
			Why: "a database exception in every response including the baseline. A marker-anchored oracle " +
				"is supposed to be immune to exactly this, and this route is where that claim is checked",
		},
	}
}
