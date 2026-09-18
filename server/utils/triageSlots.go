package utils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// THE SLOT DERIVATION. Foundations part 6, and the one-function rule of 6.5.
//
// WHY THIS IS UP HERE AND THE Slot TYPE IS DOWN IN PACKAGE triage. The derivation needs
// templatedPathSegments and VectorCanary from vectorCompose.go, which is package utils, and
// package triage must not import utils or the cycle closes. So the rule is TYPES DOWN, BEHAVIOUR
// UP: triage.Slot is the type every classifier sees, and SlotsFor, which is the only thing in the
// system allowed to read attack_vectors.parameters, stays here and returns []triage.Slot.
//
// Nothing about the one-function rule changed in the move. triageVectorRow is still unexported and
// is still the only type carrying the parameters column; triage.TriageVector, which is what a
// classifier sees, still has no such field. The test-level half is
// TestOnlySlotsForReadsTheParametersColumn, which now scans this file's package.

// EncodeSlot is a TODO stub owned by the encoder agent. It must render logical bytes into the
// slot's wire form AND report what actually went out, because the two differ in exactly the cases
// that matter. See the measurements on triage.EncoderMode.
//
// IT MOVED HERE, UNCHANGED, WITH THE SLOT DERIVATION. It sat beside the Slot type before the
// package split and could not follow it down: rendering into a slot needs a RequestTemplate, and
// that is EncodeSlotInto in triageEncode.go, which is package utils. See the note at the foot of
// triageEncode.go, which is the encoder agent'"'"'s standing recommendation to delete this signature
// rather than implement it.
func EncodeSlot(s triage.Slot, mode triage.EncoderMode, logical []byte) (triage.PayloadWire, error) {
	return triage.PayloadWire{}, fmt.Errorf("EncodeSlot(%s, %s): %w", s.Key, mode, triage.ErrTriageNotImplemented)
}

// triageVectorRow is the loader's row shape and it is UNEXPORTED. It is the only type in the
// triage layer that carries the parameters column.
//
// THIS IS THE TYPE-LEVEL HALF OF THE ONE-FUNCTION RULE. The exported TriageVector below has no
// parameters field at all, so nothing downstream can read what it cannot name. A comment saying
// "only SlotsFor reads this" is worth nothing; a type that does not have the field is worth
// something. The test-level half is TestOnlySlotsForReadsTheParametersColumn.
type triageVectorRow struct {
	ID             string
	Method         string
	ComposedURL    string
	EvidenceURL    string
	InsertionPoint triage.SlotKind
	// Parameters is attack_vectors.parameters. It is EMPTY for all 51 path vectors in the measured
	// corpus, which is why SlotsFor derives path slots from the URL's segments and not from here.
	Parameters []string
	RawRequest []byte
	MediaType  triage.MediaType
}

// SlotsFor is the ONLY function that reads attack_vectors.parameters.
//
// It implements foundations 6.2 per insertion point. The contract it satisfies,
// and each clause is there because its absence has shipped a bug:
//
//   - query: parse the composed URL's query string AND union with the parameters array. Array-only
//     names get Origin inferred. Zero of both produces zero slots and a PlanNote.
//   - body: branch on the raw_request Content-Type. JSON gives one slot per leaf by RFC 6901
//     pointer PLUS one per container node with EncodeJSONNodeReplace, because replacing a scalar
//     with an object is a different sink from editing a string. Form gives indexed slots for
//     repeated names. Multipart gives THREE slots per part: value, filename, part Content-Type.
//   - header: one slot per name in the array PLUS the always-inferred set (X-Forwarded-For,
//     X-Forwarded-Host, X-Original-URL, Referer, Origin and the rest), because absence from a
//     capture says nothing about reachability.
//   - cookie: one slot per cookie name, from the captured Cookie header unioned with the array,
//     EncodeCookie.
//   - credentials on either of those two are EMITTED AND FLAGGED, not dropped. Foundations says
//     "minus credentials" and SlotConstraints.IsCredential says they are emitted anyway; the
//     second is right and this follows it. 1555 of the 1655 cookie slots in the corpus are
//     credential or analytics, so dropping them silently takes the surface from 1655 to about
//     100 with nothing in the record saying where the rest went. The flag is what keeps
//     "deliberately skipped" visibly different from "does not exist", and never probing them is
//     the runner's job, enforced on a slot that exists.
//   - path: DERIVED FROM THE SEGMENTS, NOT FROM THE ARRAY. Templated segments, identifier-shaped
//     segments, and then every remaining segment as inferred. A path vector always yields at least
//     one slot. The array is empty for all 51 path vectors, so a loop over it is a silent zero.
//
// It is implemented below, one derivation per insertion point. The invariant it keeps at every
// exit is that a vector never produces both an empty slot list and an empty note list, because
// that pair is indistinguishable from "tested, nothing to test".
func SlotsFor(row triageVectorRow, ev triage.SlotEvidence) ([]triage.Slot, []triage.PlanNote) {
	// THE ONE LEGAL READ of attack_vectors.parameters, and it happens exactly once, here. The
	// derivations below are handed a plain []string and never see the row's field, so the
	// one-function rule holds inside this file as well as across it.
	names := triageDedupeNames(row.Parameters)

	var slots []triage.Slot
	var notes []triage.PlanNote
	switch row.InsertionPoint {
	case triage.KindQuery:
		slots, notes = triageQuerySlots(row, names)
	case triage.KindBody:
		slots, notes = triageBodySlots(row, names)
	case triage.KindHeader:
		slots, notes = triageHeaderSlots(row, names)
	case triage.KindCookie:
		slots, notes = triageCookieSlots(row, names)
	case triage.KindPath:
		slots, notes = triagePathSlots(row, ev)
	case triage.KindFragment:
		slots, notes = triageFragmentSlots(row, names)
	default:
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: row.InsertionPoint,
			Reason: "insertion_point_not_in_the_closed_set"}}
	}

	// The invariant, enforced rather than trusted. A derivation that returns nothing and says
	// nothing is the silent zero itself, and this is the last place to catch one.
	if len(slots) == 0 && len(notes) == 0 {
		notes = append(notes, triage.PlanNote{VectorID: row.ID, Kind: row.InsertionPoint,
			Reason: "derivation_returned_no_slots_and_no_reason"})
	}
	return slots, notes
}

// DeriveCorpusSlots derives every vector's slots and then REFUSES the whole derivation when an
// insertion point that has vectors produced no slots.
//
// THIS IS THE CALLER AssertSlotCoverage NEVER HAD. The assertion existed, was correct, and was
// dead code, which is the same amount of protection as no assertion. The zero it exists to catch
// is only visible once the whole corpus has been derived, because one path vector legitimately
// producing no slots is a note while fifty-one of them producing none is the bug that shipped.
//
// It returns the slots and notes alongside the error on purpose: an operator looking at a refused
// run needs to see what the derivation DID produce to work out which insertion point broke.
func DeriveCorpusSlots(rows []triageVectorRow, evidence map[string]triage.SlotEvidence) ([]triage.Slot, []triage.PlanNote, error) {
	var slots []triage.Slot
	var notes []triage.PlanNote
	vectorsByKind := map[triage.SlotKind]int{}
	slotsByKind := map[triage.SlotKind]int{}

	for _, r := range rows {
		vectorsByKind[r.InsertionPoint]++
		s, n := SlotsFor(r, evidence[r.ID])
		for _, sl := range s {
			slotsByKind[sl.Kind]++
		}
		slots = append(slots, s...)
		notes = append(notes, n...)
	}

	if err := AssertSlotCoverage(vectorsByKind, slotsByKind); err != nil {
		return slots, notes, err
	}
	return slots, notes, nil
}

// ---------------------------------------------------------------------------------------------
// 6a. THE DERIVATIONS, ONE PER INSERTION POINT
// ---------------------------------------------------------------------------------------------

// triagePathSlots derives path slots FROM THE SEGMENTS and never from the parameters array.
//
// This is the derivation the whole Slot abstraction exists for. Measured: all 51 path vectors in
// the corpus have zero entries in attack_vectors.parameters, so a loop over that array probes
// nothing on 23.4% of the corpus and records every one of those vectors as tested.
//
// A templated segment is resolved to a value the application actually served, which is what
// vectorConcreteTemplatedURLFrom and templatedPathSegments already do for the scanners: the
// evidence URL's segment at the same index, and only when the two paths have the same segment
// count, because /a/{id}/b and /a/x/y/b are different routes and lining them up by index invents
// a URL nobody ever served. Reusing those two rather than writing a third copy of the walk is
// deliberate; the arity guard is the safety of the whole thing and it belongs in one place.
func triagePathSlots(row triageVectorRow, ev triage.SlotEvidence) ([]triage.Slot, []triage.PlanNote) {
	segments, ok := triagePathSegmentsOf(row.ComposedURL)
	if !ok {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindPath,
			Reason: "composed_url_has_no_parsable_path"}}
	}

	// The same arity-guarded borrow the scanners use. nil when the evidence URL describes a
	// different route shape, which falls the loop through to the canary.
	observed := templatedPathSegments(ev.EvidenceURL, len(segments))
	canary := ev.Canary
	if canary == "" {
		canary = VectorCanary
	}

	var slots []triage.Slot
	var notes []triage.PlanNote
	for i, seg := range segments {
		if seg == "" {
			continue
		}
		s := triage.Slot{
			VectorID:        row.ID,
			Kind:            triage.KindPath,
			SegmentIndex:    i,
			Method:          row.Method,
			BodyMedia:       triage.BodyNone,
			Encoder:         triage.EncodePathSegment,
			ServerReachable: true,
			Constraints:     triage.NewSlotConstraints(),
		}

		switch {
		case strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"):
			s.Key = triage.SlotKey(fmt.Sprintf("path:%d:%s", i, seg))
			s.Origin = triage.SlotObserved
			if i < len(observed) && observed[i] != "" && !strings.HasPrefix(observed[i], "{") {
				s.Value = observed[i]
				s.ValueOrigin = triage.ValueFromEvidenceURL
			} else {
				s.Value = canary
				s.ValueOrigin = triage.ValueCanary
				notes = append(notes, triage.PlanNote{VectorID: row.ID, Kind: triage.KindPath,
					Reason: fmt.Sprintf("segment_%d_resolved_to_canary_so_every_clean_here_is_cannot_determine", i)})
			}
		case triageIdentifierShaped(seg):
			s.Key = triage.SlotKey(fmt.Sprintf("path:%d:*", i))
			s.Origin = triage.SlotObserved
			s.Value = seg
			s.ValueOrigin = triage.ValueObserved
		default:
			// A literal segment such as "api" or "v1". It is still a slot: traversal, extension
			// confusion and routing bugs live on exactly these, and the crawl DID observe the
			// value. It is marked inferred because nothing in the capture says the application
			// treats it as an input.
			s.Key = triage.SlotKey(fmt.Sprintf("path:%d:*", i))
			s.Origin = triage.SlotInferred
			s.Value = seg
			s.ValueOrigin = triage.ValueObserved
		}

		s.ValueKind = triageValueKind(s.Value)
		s.Wrapper = triageWrapperOf(s.Value)
		slots = append(slots, s)
	}

	if len(slots) == 0 {
		// The route is "/" and there is nothing between the slashes. It is still a request target
		// that can be perturbed, so it yields a slot rather than a zero, and the note says why the
		// slot has no observed value.
		slots = append(slots, triage.Slot{
			VectorID: row.ID, Kind: triage.KindPath, Key: "path:0:*", SegmentIndex: 0,
			Value: "", ValueOrigin: triage.ValueSynthesized, ValueKind: triage.ValueEmpty,
			Encoder: triage.EncodePathSegment, Method: row.Method, BodyMedia: triage.BodyNone,
			Origin: triage.SlotInferred, ServerReachable: true, Constraints: triage.NewSlotConstraints(),
		})
		notes = append(notes, triage.PlanNote{VectorID: row.ID, Kind: triage.KindPath,
			Reason: "path_is_root_only_so_the_slot_carries_no_observed_value"})
	}
	return slots, notes
}

// triageQuerySlots parses the composed URL's query string and unions it with the parameters array.
func triageQuerySlots(row triageVectorRow, names []string) ([]triage.Slot, []triage.PlanNote) {
	observed := triageQueryPairs(row.ComposedURL)

	var slots []triage.Slot
	seen := map[string]bool{}
	for _, kv := range observed {
		if seen[kv[0]] {
			continue
		}
		seen[kv[0]] = true
		slots = append(slots, triageValueSlot(row, triage.KindQuery, triage.SlotKey("query:"+kv[0]), kv[0],
			kv[1], triage.ValueObserved, triage.SlotObserved, triage.EncodeQuery))
	}
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		// The corpus knows the name and the capture carried no value for it. The name is real, so
		// the slot is real; the value is not observed, so it is marked synthesized and every clean
		// drawn from it carries that caveat rather than reading as a measured clean.
		s := triageValueSlot(row, triage.KindQuery, triage.SlotKey("query:"+n), n, "", triage.ValueSynthesized,
			triage.SlotInferred, triage.EncodeQuery)
		slots = append(slots, s)
	}

	if len(slots) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindQuery,
			Reason: "no_query_and_no_parameters"}}
	}
	return slots, nil
}

// triageHeaderSlots emits the named headers plus the always-inferred set.
//
// The inferred set is not optional and is not gated on the crawl having seen those headers.
// Absence from a capture says nothing about reachability: X-Forwarded-For reaches the application
// on essentially every deployment behind a proxy and appears in essentially no capture, and a
// derivation that only emitted what it saw would never probe the header class's best slots.
func triageHeaderSlots(row triageVectorRow, names []string) ([]triage.Slot, []triage.PlanNote) {
	captured := triageHeaderValues(row.RawRequest)

	var slots []triage.Slot
	seen := map[string]bool{}
	emit := func(name string, origin triage.SlotOrigin) {
		lower := strings.ToLower(strings.TrimSpace(name))
		if lower == "" || seen[lower] {
			return
		}
		seen[lower] = true
		value, had := captured[lower]
		vo := triage.ValueSynthesized
		if had {
			vo = triage.ValueObserved
		}
		s := triageValueSlot(row, triage.KindHeader, triage.SlotKey("header:"+lower), lower, value, vo,
			origin, triage.EncodeHeaderValue)
		s.Constraints.IsCredential = triageCredentialHeader(lower)
		slots = append(slots, s)
	}

	for _, n := range names {
		emit(n, triage.SlotObserved)
	}
	for _, n := range triageInferredHeaders() {
		emit(n, triage.SlotInferred)
	}
	// Nothing below can make this zero, because the inferred set is never empty, but the check
	// stays so that emptying that list is a loud note rather than a silent zero.
	if len(slots) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindHeader,
			Reason: "no_header_names_and_the_inferred_set_is_empty"}}
	}
	return slots, nil
}

// triageCookieSlots emits one slot per cookie name, from the captured Cookie header unioned with
// the parameters array.
//
// Credential cookies are EMITTED AND FLAGGED rather than dropped. Measured: 1555 of the 1655
// cookie slots in the corpus are credential or analytics cookies, so dropping them silently would
// take the cookie surface from 1655 to about 100 with nothing in the record saying where the rest
// went. A flagged slot keeps "deliberately skipped" visibly different from "does not exist", which
// is the distinction the whole not-knowing-is-not-clean rule turns on.
func triageCookieSlots(row triageVectorRow, names []string) ([]triage.Slot, []triage.PlanNote) {
	captured := triageCookiePairs(row.RawRequest)

	var slots []triage.Slot
	seen := map[string]bool{}
	emit := func(name, value string, vo triage.ValueOrigin, origin triage.SlotOrigin) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		s := triageValueSlot(row, triage.KindCookie, triage.SlotKey("cookie:"+name), name, value, vo, origin,
			triage.EncodeCookie)
		s.Constraints.IsCredential = triageCredentialCookie(name)
		slots = append(slots, s)
	}

	for _, kv := range captured {
		emit(kv[0], kv[1], triage.ValueObserved, triage.SlotObserved)
	}
	for _, n := range names {
		emit(n, "", triage.ValueSynthesized, triage.SlotInferred)
	}

	if len(slots) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindCookie,
			Reason: "no_cookie_header_captured_and_no_parameters"}}
	}
	var notes []triage.PlanNote
	credentials := 0
	for _, s := range slots {
		if s.Constraints.IsCredential {
			credentials++
		}
	}
	if credentials == len(slots) {
		notes = append(notes, triage.PlanNote{VectorID: row.ID, Kind: triage.KindCookie,
			Reason: "all_slots_credential"})
	}
	return slots, notes
}

// triageFragmentSlots derives fragment slots, which are emitted and marked unreachable rather than
// skipped.
//
// RFC 3986 section 3.5 makes the fragment a client-side reference and every browser strips it
// before the request goes out, so every HTTP-level tool is structurally blind to it. Emitting the
// slot with ServerReachable false is what lets a server-side class say not_applicable (fragment)
// instead of clean, and lets a DOM class find the slot at all.
func triageFragmentSlots(row triageVectorRow, names []string) ([]triage.Slot, []triage.PlanNote) {
	_, frag, hasFrag := strings.Cut(row.ComposedURL, "#")

	var slots []triage.Slot
	seen := map[string]bool{}
	emit := func(name, value string, vo triage.ValueOrigin, origin triage.SlotOrigin) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		s := triageValueSlot(row, triage.KindFragment, triage.SlotKey("fragment:"+name), name, value, vo,
			origin, triage.EncodeQuery)
		s.ServerReachable = false
		slots = append(slots, s)
	}

	// A fragment such as #/connect/edit?token=abc carries its own query string; one such as
	// #access_token=x&token_type=y is a query string with no path in front of it.
	params := frag
	if _, after, ok := strings.Cut(frag, "?"); ok {
		params = after
	}
	if strings.Contains(params, "=") {
		for _, kv := range triageSplitQuery(params) {
			emit(kv[0], kv[1], triage.ValueObserved, triage.SlotObserved)
		}
	}
	for _, n := range names {
		emit(n, "", triage.ValueSynthesized, triage.SlotInferred)
	}
	if len(slots) == 0 && hasFrag && frag != "" {
		// A path-shaped fragment such as #/billing. The whole fragment is the slot.
		s := triageValueSlot(row, triage.KindFragment, "fragment:*", "", frag, triage.ValueObserved,
			triage.SlotObserved, triage.EncodeNone)
		s.ServerReachable = false
		slots = append(slots, s)
	}
	if len(slots) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindFragment,
			Reason: "no_fragment_captured_and_no_parameters"}}
	}
	return slots, nil
}

// triageBodySlots branches on the raw request's Content-Type, never on a guess.
func triageBodySlots(row triageVectorRow, names []string) ([]triage.Slot, []triage.PlanNote) {
	ctype, body := triageRequestContentTypeAndBody(row.RawRequest)
	if ctype == "" {
		ctype = string(row.MediaType)
	}
	if len(body) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody, Reason: "no_body_captured"}}
	}

	media, boundary := triageBodyMediaOf(ctype, body)
	switch media {
	case triage.BodyJSON, triage.BodyGraphQL:
		return triageJSONBodySlots(row, body, media)
	case triage.BodyForm:
		return triageFormBodySlots(row, body, names)
	case triage.BodyMultipart:
		return triageMultipartBodySlots(row, body, boundary)
	case triage.BodyXML:
		// A per-node XML derivation is the XXE and XPath classes' own work and is not attempted
		// here. The whole document is one slot so the vector is probed rather than skipped, and
		// the note says what was not derived, because an unexplained single slot on an XML body
		// reads as a complete derivation.
		s := triageValueSlot(row, triage.KindBody, "body:/", "", string(body), triage.ValueObserved,
			triage.SlotObserved, triage.EncodeXMLDocReplace)
		s.BodyMedia = triage.BodyXML
		s.FieldPath = "/"
		return []triage.Slot{s}, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody,
			Reason: "xml_body_derived_as_one_document_slot_not_per_node"}}
	default:
		s := triageValueSlot(row, triage.KindBody, "body:/", "", string(body), triage.ValueObserved,
			triage.SlotObserved, triage.EncodeNone)
		s.BodyMedia = triage.BodyNone
		s.FieldPath = "/"
		return []triage.Slot{s}, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody,
			Reason: "body_media_unrecognised_" + triageSanitiseReason(ctype)}}
	}
}

// triageJSONBodySlots walks the document and emits an RFC 6901 pointer slot per leaf plus a
// node-replace slot per node.
//
// TWO SLOTS ON A SCALAR IS NOT A DUPLICATE. Editing the string at /filters/status and replacing
// the NODE at /filters/status with an object are different sinks: the first tests the value
// parser, the second tests what the application does when the shape changes, which is where the
// NoSQL operator injections and the mass-assignment bugs live. They get different encoders and
// different keys so a verdict on one is never read as a verdict on the other.
func triageJSONBodySlots(row triageVectorRow, body []byte, media triage.BodyMedia) ([]triage.Slot, []triage.PlanNote) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		s := triageValueSlot(row, triage.KindBody, "body:/", "", string(body), triage.ValueObserved,
			triage.SlotObserved, triage.EncodeNone)
		s.BodyMedia = media
		s.FieldPath = "/"
		return []triage.Slot{s}, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody,
			Reason: "body_declared_json_but_did_not_parse"}}
	}

	var slots []triage.Slot
	var walk func(node any, pointer string)
	walk = func(node any, pointer string) {
		ptr := pointer
		if ptr == "" {
			ptr = "/"
		}
		switch n := node.(type) {
		case map[string]any:
			slots = append(slots, triageJSONNodeSlot(row, media, ptr, "", triage.EncodeJSONNodeReplace, ":node"))
			keys := make([]string, 0, len(n))
			for k := range n {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(n[k], pointer+"/"+triageJSONPointerEscape(k))
			}
		case []any:
			slots = append(slots, triageJSONNodeSlot(row, media, ptr, "", triage.EncodeJSONNodeReplace, ":node"))
			for i, v := range n {
				walk(v, pointer+"/"+strconv.Itoa(i))
			}
		default:
			slots = append(slots, triageJSONNodeSlot(row, media, ptr, triageJSONScalarText(node),
				triage.EncodeJSONString, ""))
			slots = append(slots, triageJSONNodeSlot(row, media, ptr, triageJSONScalarText(node),
				triage.EncodeJSONNodeReplace, ":node"))
		}
	}
	walk(doc, "")

	if len(slots) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody, Reason: "json_body_had_no_nodes"}}
	}
	return slots, nil
}

func triageJSONNodeSlot(row triageVectorRow, media triage.BodyMedia, pointer, value string, enc triage.EncoderMode, suffix string) triage.Slot {
	s := triageValueSlot(row, triage.KindBody, triage.SlotKey("body:"+pointer+suffix), "", value, triage.ValueObserved,
		triage.SlotObserved, enc)
	s.BodyMedia = media
	s.FieldPath = pointer
	return s
}

// triageFormBodySlots gives repeated names indexed slots, because a=1&a=2 is two sinks and an
// HTTP parameter pollution bug lives in the difference between which one the application reads.
func triageFormBodySlots(row triageVectorRow, body []byte, names []string) ([]triage.Slot, []triage.PlanNote) {
	pairs := triageSplitQuery(string(body))

	var slots []triage.Slot
	count := map[string]int{}
	seen := map[string]bool{}
	for _, kv := range pairs {
		if kv[0] == "" {
			continue
		}
		key := "body:" + kv[0]
		if n := count[kv[0]]; n > 0 {
			key = fmt.Sprintf("body:%s[%d]", kv[0], n)
		}
		count[kv[0]]++
		seen[kv[0]] = true
		s := triageValueSlot(row, triage.KindBody, triage.SlotKey(key), kv[0], kv[1], triage.ValueObserved,
			triage.SlotObserved, triage.EncodeForm)
		s.BodyMedia = triage.BodyForm
		s.FieldPath = "/" + kv[0]
		slots = append(slots, s)
	}
	for _, n := range names {
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		s := triageValueSlot(row, triage.KindBody, triage.SlotKey("body:"+n), n, "", triage.ValueSynthesized,
			triage.SlotInferred, triage.EncodeForm)
		s.BodyMedia = triage.BodyForm
		s.FieldPath = "/" + n
		slots = append(slots, s)
	}

	if len(slots) == 0 {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody,
			Reason: "form_body_had_no_fields_and_no_parameters"}}
	}
	return slots, nil
}

// triageMultipartBodySlots gives THREE slots per part: the value, the filename and the part's own
// Content-Type. All three are separate sinks, and the upload-bypass work in this codebase has
// already shown that the filename and the part Content-Type are where the interesting bugs are.
func triageMultipartBodySlots(row triageVectorRow, body []byte, boundary string) ([]triage.Slot, []triage.PlanNote) {
	if boundary == "" {
		return nil, []triage.PlanNote{{VectorID: row.ID, Kind: triage.KindBody,
			Reason: "multipart_body_with_no_boundary_in_the_content_type"}}
	}
	reader := multipart.NewReader(bytes.NewReader(body), boundary)

	var slots []triage.Slot
	var notes []triage.PlanNote
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			notes = append(notes, triage.PlanNote{VectorID: row.ID, Kind: triage.KindBody,
				Reason: "multipart_body_truncated_or_malformed_after_" + strconv.Itoa(len(slots)) + "_slots"})
			break
		}
		name := part.FormName()
		if name == "" {
			name = "part" + strconv.Itoa(len(slots))
		}
		value, _ := io.ReadAll(io.LimitReader(part, 64<<10))
		_ = part.Close()

		v := triageValueSlot(row, triage.KindBody, triage.SlotKey("body:"+name), name, string(value),
			triage.ValueObserved, triage.SlotObserved, triage.EncodeMultipartValue)
		v.BodyMedia = triage.BodyMultipart
		v.FieldPath = "/" + name
		slots = append(slots, v)

		f := triageValueSlot(row, triage.KindBody, triage.SlotKey("body:"+name+".filename"), name,
			part.FileName(), triage.ValueObserved, triage.SlotObserved, triage.EncodeMultipartName)
		f.BodyMedia = triage.BodyMultipart
		f.FieldPath = "/" + name + "/filename"
		slots = append(slots, f)

		c := triageValueSlot(row, triage.KindBody, triage.SlotKey("body:"+name+".content-type"), name,
			part.Header.Get("Content-Type"), triage.ValueObserved, triage.SlotObserved, triage.EncodeMultipartValue)
		c.BodyMedia = triage.BodyMultipart
		c.FieldPath = "/" + name + "/content-type"
		slots = append(slots, c)
	}

	if len(slots) == 0 {
		notes = append(notes, triage.PlanNote{VectorID: row.ID, Kind: triage.KindBody,
			Reason: "multipart_body_had_no_parts"})
	}
	return slots, notes
}

// ---------------------------------------------------------------------------------------------
// 6b. THE SMALL PARTS THE DERIVATIONS ARE BUILT FROM
// ---------------------------------------------------------------------------------------------

// triageValueSlot fills the fields every slot has the same way, so a derivation that forgets one
// is a compile error rather than a slot with a zero value that reads as a measurement.
func triageValueSlot(row triageVectorRow, kind triage.SlotKind, key triage.SlotKey, name, value string,
	vo triage.ValueOrigin, origin triage.SlotOrigin, enc triage.EncoderMode) triage.Slot {
	return triage.Slot{
		VectorID:        row.ID,
		Kind:            kind,
		Key:             key,
		Name:            name,
		SegmentIndex:    -1,
		Value:           value,
		ValueOrigin:     vo,
		ValueKind:       triageValueKind(value),
		Wrapper:         triageWrapperOf(value),
		Encoder:         enc,
		Method:          row.Method,
		BodyMedia:       triage.BodyNone,
		Origin:          origin,
		ServerReachable: true,
		Constraints:     triage.NewSlotConstraints(),
	}
}

func triageDedupeNames(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, n := range in {
		n = strings.TrimSpace(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

// triagePathSegmentsOf splits a composed URL's path the same way vectorConcreteTemplatedURLFrom
// does, as TEXT. Round-tripping through net/url re-encodes the path and changes the bytes on the
// wire, which is exactly what a path or traversal probe is measuring.
func triagePathSegmentsOf(raw string) ([]string, bool) {
	pathPart, _, _ := strings.Cut(raw, "?")
	pathPart, _, _ = strings.Cut(pathPart, "#")
	_, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return nil, false
	}
	_, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return nil, false
	}
	return strings.Split(path, "/"), true
}

func triageQueryPairs(raw string) [][2]string {
	_, after, ok := strings.Cut(raw, "?")
	if !ok {
		return nil
	}
	after, _, _ = strings.Cut(after, "#")
	return triageSplitQuery(after)
}

// triageSplitQuery splits an application/x-www-form-urlencoded string into decoded pairs, keeping
// duplicates and keeping order. A value that does not decode is kept RAW rather than dropped: a
// malformed percent escape is frequently the interesting thing about a captured value.
func triageSplitQuery(s string) [][2]string {
	if s == "" {
		return nil
	}
	var out [][2]string
	for _, pair := range strings.Split(s, "&") {
		if pair == "" {
			continue
		}
		rawName, rawValue, _ := strings.Cut(pair, "=")
		name := rawName
		if d, err := url.QueryUnescape(rawName); err == nil {
			name = d
		}
		value := rawValue
		if d, err := url.QueryUnescape(rawValue); err == nil {
			value = d
		}
		out = append(out, [2]string{name, value})
	}
	return out
}

// triageSplitRawRequest cuts a captured request into its header block and its body, accepting both
// CRLF and bare LF because captures come from several sources and one of them normalises.
func triageSplitRawRequest(raw []byte) (head string, body []byte) {
	if len(raw) == 0 {
		return "", nil
	}
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return string(raw[:i]), raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return string(raw[:i]), raw[i+2:]
	}
	return string(raw), nil
}

// triageHeaderValues returns the captured request's headers by lowercased name. Duplicates are
// joined with ", " rather than overwritten, because a dropped duplicate is a value that was on the
// wire and is not in the record.
func triageHeaderValues(raw []byte) map[string]string {
	head, _ := triageSplitRawRequest(raw)
	out := map[string]string{}
	lines := strings.Split(head, "\n")
	for i, line := range lines {
		if i == 0 {
			continue // the request line
		}
		line = strings.TrimRight(line, "\r")
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		if name == "" {
			continue
		}
		if prev, dup := out[name]; dup {
			out[name] = prev + ", " + value
			continue
		}
		out[name] = value
	}
	return out
}

// triageCookiePairs splits the captured Cookie header BY HAND rather than through net/http.
// http.Cookie drops the semicolon, the double quote and the backslash from a value, which are the
// SQL injection probe characters, and a slot whose observed value has been silently edited is a
// slot nobody can compare a probe against.
func triageCookiePairs(raw []byte) [][2]string {
	header := triageHeaderValues(raw)["cookie"]
	if header == "" {
		return nil
	}
	var out [][2]string
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, value, _ := strings.Cut(part, "=")
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		out = append(out, [2]string{name, strings.TrimSpace(value)})
	}
	return out
}

func triageRequestContentTypeAndBody(raw []byte) (string, []byte) {
	_, body := triageSplitRawRequest(raw)
	return triageHeaderValues(raw)["content-type"], body
}

// triageBodyMediaOf classifies a body by its declared Content-Type and, when the type is missing
// or generic, by the bytes. The boundary comes back alongside because multipart is unparsable
// without it.
func triageBodyMediaOf(ctype string, body []byte) (triage.BodyMedia, string) {
	base := ctype
	params := map[string]string{}
	if ctype != "" {
		if mt, p, err := mime.ParseMediaType(ctype); err == nil {
			base = mt
			params = p
		} else {
			base, _, _ = strings.Cut(ctype, ";")
		}
	}
	base = strings.ToLower(strings.TrimSpace(base))

	switch {
	case base == "application/json" || strings.HasSuffix(base, "+json"):
		return triage.BodyJSON, ""
	case base == "application/graphql":
		return triage.BodyGraphQL, ""
	case base == "application/x-www-form-urlencoded":
		return triage.BodyForm, ""
	case strings.HasPrefix(base, "multipart/"):
		return triage.BodyMultipart, params["boundary"]
	case base == "text/xml" || base == "application/xml" || strings.HasSuffix(base, "+xml"):
		return triage.BodyXML, ""
	}

	// No usable declaration. Sniff, because a body that is plainly JSON and was served as
	// text/plain is still a JSON sink, and refusing to derive it is a zero.
	trimmed := bytes.TrimSpace(body)
	switch {
	case len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '['):
		return triage.BodyJSON, ""
	case len(trimmed) > 0 && trimmed[0] == '<':
		return triage.BodyXML, ""
	case bytes.Contains(trimmed, []byte("=")) && !bytes.Contains(trimmed, []byte(" ")):
		return triage.BodyForm, ""
	}
	return triage.BodyNone, ""
}

// triageJSONPointerEscape is RFC 6901: ~ becomes ~0 and / becomes ~1, in that order.
func triageJSONPointerEscape(k string) string {
	return strings.ReplaceAll(strings.ReplaceAll(k, "~", "~0"), "/", "~1")
}

func triageJSONScalarText(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case string:
		return n
	case bool:
		return strconv.FormatBool(n)
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	default:
		return fmt.Sprint(n)
	}
}

// triageInferredHeaders is the always-present set: headers that reach the application on a normal
// deployment and appear in almost no capture. See triageHeaderSlots for why absence from a crawl
// is not evidence of unreachability.
func triageInferredHeaders() []string {
	return []string{
		"x-forwarded-for", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-port",
		"x-original-url", "x-rewrite-url", "x-original-host", "x-host", "x-real-ip",
		"x-http-method-override", "x-request-id", "forwarded", "true-client-ip",
		"cf-connecting-ip", "referer", "origin", "user-agent", "accept-language",
	}
}

// triageCredentialHeader names the headers a probe must never perturb. Injecting into
// Authorization produces a 401, and that 401 is a differential against baseline that looks exactly
// like a finding.
func triageCredentialHeader(lower string) bool {
	switch lower {
	case "authorization", "proxy-authorization", "cookie", "x-api-key", "api-key",
		"x-auth-token", "x-access-token", "x-session-token", "authentication",
		"x-csrf-token", "x-xsrf-token", "x-amz-security-token":
		return true
	}
	return false
}

// triageCredentialCookie flags session and CSRF cookies by name shape. It is a NAME test and never
// a value test: a value test on a cookie means reading credentials into a comparison, and the
// point of the flag is that the value is never touched.
func triageCredentialCookie(name string) bool {
	lower := strings.ToLower(name)
	for _, needle := range []string{"session", "sess", "sid", "auth", "token", "jwt", "csrf",
		"xsrf", "remember", "login", "credential", "secret", "identity", "passwd", "password"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// triageIdentifierShaped reports whether a path segment looks like a resource identifier rather
// than a route literal. It ORDERS the derivation and never gates it: a segment this returns false
// for still becomes a slot, marked inferred. A shape guess that suppresses a probe is a silent
// zero and this codebase has removed several.
func triageIdentifierShaped(seg string) bool {
	switch triageValueKind(seg) {
	case triage.ValueNumeric, triage.ValueUUID, triage.ValueBase64Like, triage.ValueDateLike:
		return true
	}
	// A mixed alphanumeric of some length, such as a slug id or a short hash.
	if len(seg) >= 8 {
		digits := strings.ContainsAny(seg, "0123456789")
		if digits {
			return true
		}
	}
	return false
}

var triageUUIDLayout = [5]int{8, 4, 4, 4, 12}

// triageValueKind classifies an observed value's shape. Like triageIdentifierShaped it orders and
// never gates.
func triageValueKind(v string) triage.ValueKind {
	if v == "" {
		return triage.ValueEmpty
	}
	if triageAllDigits(v) {
		return triage.ValueNumeric
	}
	if triageLooksUUID(v) {
		return triage.ValueUUID
	}
	if strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") ||
		strings.HasPrefix(v, "//") {
		return triage.ValueURLLike
	}
	if t := strings.TrimSpace(v); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return triage.ValueJSONLike
	}
	if triageLooksDate(v) {
		return triage.ValueDateLike
	}
	if strings.Contains(v, "/") || strings.Contains(v, "\\") {
		return triage.ValuePathLike
	}
	if len(v) >= 16 && len(v)%4 == 0 && triageBase64Charset(v) {
		return triage.ValueBase64Like
	}
	if len(v) <= 24 && !strings.ContainsAny(v, " \t") {
		return triage.ValueEnumLike
	}
	return triage.ValueFreeText
}

func triageWrapperOf(v string) triage.Wrapper {
	if v == "" {
		return triage.WrapNone
	}
	if parts := strings.Split(v, "."); len(parts) == 3 && strings.HasPrefix(v, "ey") &&
		triageBase64Charset(parts[0]) && triageBase64Charset(parts[1]) {
		return triage.WrapJWT
	}
	if strings.Contains(v, "%25") {
		return triage.WrapDoubleURL
	}
	if len(v) >= 16 && len(v)%4 == 0 && triageBase64Charset(v) {
		return triage.WrapBase64
	}
	return triage.WrapNone
}

func triageAllDigits(v string) bool {
	for _, r := range v {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func triageLooksUUID(v string) bool {
	parts := strings.Split(v, "-")
	if len(parts) != len(triageUUIDLayout) {
		return false
	}
	for i, p := range parts {
		if len(p) != triageUUIDLayout[i] {
			return false
		}
		for _, r := range p {
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

func triageLooksDate(v string) bool {
	if len(v) < 10 {
		return false
	}
	head := v[:10]
	if head[4] != '-' || head[7] != '-' {
		return false
	}
	return triageAllDigits(head[:4]) && triageAllDigits(head[5:7]) && triageAllDigits(head[8:10])
}

func triageBase64Charset(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '+' || r == '/' || r == '=' || r == '-' || r == '_'
		if !ok {
			return false
		}
	}
	return true
}

// triageSanitiseReason keeps a PlanNote reason a stable token: reasons are compared and grouped,
// and a reason carrying raw header text from a target would make every note unique.
func triageSanitiseReason(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s, _, _ = strings.Cut(s, ";")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if out == "" {
		return "none"
	}
	if len(out) > 48 {
		return out[:48]
	}
	return out
}

// AssertSlotCoverage is the runtime assertion of foundations 6.5, and it is a HARD ERROR rather
// than a warning on purpose. A warning in a log is exactly how the path insertion point shipped a
// zero slot count against 51 non-zero vectors and had every one of them recorded as tested.
//
// vectorsByKind is how many vectors exist for each insertion point; slotsByKind is how many slots
// the derivation produced. A kind with vectors and no slots aborts the run.
func AssertSlotCoverage(vectorsByKind, slotsByKind map[triage.SlotKind]int) error {
	var bad []string
	for _, k := range triage.AllSlotKinds() {
		if vectorsByKind[k] > 0 && slotsByKind[k] == 0 {
			bad = append(bad, fmt.Sprintf("%s has %d vectors and 0 slots", k, vectorsByKind[k]))
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("triage: slot derivation produced a silent zero, which would record those vectors as tested: %s",
			strings.Join(bad, "; "))
	}
	return nil
}
