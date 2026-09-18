package utils

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"ars0n-framework-v2-server/utils/triage"
)

// The triage slot encoder: logical payload bytes in, wire bytes and a modified request out.
//
// WHAT THIS FILE IS FOR. A classifier declares LOGICAL bytes, the bytes it wants the application
// to see. Between that declaration and the socket sit six containers with six different escaping
// rules, and every one of them has a way of quietly changing the payload. This file is the single
// place that rendering happens, and every rendering returns three things: the wire bytes, whether
// the payload was DELIVERED faithfully, and when it was not, a named reason. A payload that could
// not be sent as asked must never reach a classifier looking like a payload that was sent and
// shrugged off, because that is how a class gets recorded clean on a slot it never tested.
//
// THE MEASUREMENT THIS FILE EXISTS FOR. On this machine, go1.26.1:
//
//	(&http.Cookie{Name:"s", Value:`1' OR 1=1; DROP`}).String() -> `s="1' OR 1=1 DROP"`
//	(&http.Cookie{Name:"s", Value:`a"b\c`}).String()           -> `s=abc`
//
// The semicolon, the double quote and the backslash are dropped, with nothing but a line on the
// stdlib logger. Those are the SQL injection probe characters, and 75 of the 218 vectors in the
// measured corpus are cookie vectors. So cookies are rendered BY HAND into a Cookie header line
// here, exactly as shipped code already does it in scanCredentials.go:164 and redirectProbe.go:287.
// The mitigation is measured too, against an httptest server and against a raw TCP listener: the
// hand-built line arrives byte identical, and a NUL byte is refused loudly by net/http with
// "invalid header field value" rather than being sent mangled. See triageEncode_test.go, which
// asserts both halves against a real server rather than against a string.
//
// AND THE OTHER MEASURED TRAP. url.PathEscape is the wrong function for a query value:
// PathEscape("a=b") is "a=b", PathEscape("a&b") is "a&b", PathEscape("a+b") is "a+b", all raw. A
// query encoder built on it sends a payload that splits into three parameters, and then the probe
// reports on whichever fragment the application happened to read. Query and form values go through
// url.QueryEscape here and a source-scanning test forbids PathEscape in the triage files.

// TriageEncoderVersion stamps every PayloadWire this file produces. A stored observation whose
// verdict looks wrong has to be re-readable against the encoder that produced it, and the encoder
// changes more often than the schema does.
const TriageEncoderVersion = "triage-encode-1"

// ---------------------------------------------------------------------------------------------
// 1. THE REQUEST TEMPLATE
// ---------------------------------------------------------------------------------------------

// RequestTemplate is the captured request an encode is applied to. It is bytes and ordered pairs
// rather than an *http.Request on purpose: an *http.Request normalises as soon as it is built, and
// the whole point of this layer is to know what the bytes were before and after.
//
// Headers holds the Cookie line like any other header. There is no cookie jar here, because a jar
// is the mechanism that mangles cookie values.
//
// HEADER ORDER IS A CAPABILITY, NOT A PROPERTY. The Headers slice is ordered and duplicates are
// kept, and that order survives every encode in this file. It does NOT survive net/http, which
// sorts the field names on the way out: see the measurement above SerializeOrdered. A class whose
// verdict depends on the order the server sees sets RequireHeaderOrder, and then it does. Ask
// HeaderOrderIsGuaranteed rather than assuming either way.
type RequestTemplate struct {
	Method    string
	URL       string // absolute, scheme://authority/path?query. Any fragment is dropped: see below.
	Headers   [][2]string
	Body      []byte
	BodyMedia triage.BodyMedia

	// RequireHeaderOrder is the declaration a class makes when its verdict depends on the order
	// the headers reach the server in: HPP, CRLF and request smuggling all do. Setting it sends
	// this request down the ordered wire path, where the bytes are written by this package
	// instead of by net/http. Leaving it false is the normal case and means the order on the
	// socket is whatever net/http chooses, which today is alphabetical.
	RequireHeaderOrder bool
}

// Clone deep-copies the template so an encode can never mutate the caller's captured request. Two
// classes encoding against the same template is normal and they must not see each other's bytes.
func (t RequestTemplate) Clone() RequestTemplate {
	out := RequestTemplate{Method: t.Method, URL: t.URL, BodyMedia: t.BodyMedia, RequireHeaderOrder: t.RequireHeaderOrder}
	if t.Headers != nil {
		out.Headers = make([][2]string, len(t.Headers))
		copy(out.Headers, t.Headers)
	}
	if t.Body != nil {
		out.Body = append([]byte(nil), t.Body...)
	}
	return out
}

// HeaderValue returns the first value for name, matched case-insensitively as RFC 7230 requires.
func (t RequestTemplate) HeaderValue(name string) (string, bool) {
	for _, h := range t.Headers {
		if strings.EqualFold(h[0], name) {
			return h[1], true
		}
	}
	return "", false
}

// SetHeader replaces the first header with this name IN PLACE and appends only when the name is
// absent, so the position of a field in the Headers slice is the same before and after. That
// matters because header order is itself a fingerprint some WAFs read, and a probe that reorders
// headers relative to its own baseline has introduced a difference the comparator will later
// attribute to the payload.
//
// This preserves the order OF THE SLICE. Whether that order reaches the server is a separate
// question with a measured answer: on the net/http path it does not, and on the ordered wire
// path it does. See RequireHeaderOrder and HeaderOrderIsGuaranteed.
func (t *RequestTemplate) SetHeader(name, value string) {
	for i := range t.Headers {
		if strings.EqualFold(t.Headers[i][0], name) {
			t.Headers[i][1] = value
			return
		}
	}
	t.Headers = append(t.Headers, [2]string{name, value})
}

// ---------------------------------------------------------------------------------------------
// 2. THE DELIVERY REASON VOCABULARY
// ---------------------------------------------------------------------------------------------

// DeliveryReason names why a payload could not be put on the wire as asked. Every value here is a
// state the caller must turn into not_reachable or cannot_determine, never into clean. The empty
// value means delivered, and it is the ONLY value that means delivered.
type DeliveryReason string

const (
	// DeliverOK is the zero value and the only one that means the bytes went out as asked.
	DeliverOK DeliveryReason = ""

	// Structural: the insertion point cannot carry an HTTP payload at all.
	ReasonFragmentNotTransmitted DeliveryReason = "fragment_not_transmitted"

	// Transport: net/http will refuse these, loudly, at send time. They are measured refusals.
	ReasonValueCRLF    DeliveryReason = "value_contains_crlf_not_sendable"
	ReasonValueNUL     DeliveryReason = "value_contains_nul_not_sendable"
	ReasonValueControl DeliveryReason = "value_contains_control_byte_not_sendable"

	// Per-slot, from the measured reachability table on SlotConstraints.
	ReasonSlotImpossibleByte    DeliveryReason = "slot_impossible_byte"
	ReasonSlotRejectsPercentEnc DeliveryReason = "slot_rejects_percent_encoding"

	// Path.
	ReasonPathSlashUnencodable DeliveryReason = "path_segment_slash_unencodable"
	ReasonPathTemplateOpen     DeliveryReason = "path_template_unresolved"
	ReasonPathIndexOutOfRange  DeliveryReason = "path_segment_index_out_of_range"

	// The slot is not in the template. An OBSERVED slot that is missing means the template and the
	// slot disagree, which is a derivation bug, not a property of the application.
	ReasonQueryParamAbsent DeliveryReason = "query_parameter_not_in_request"
	ReasonFormFieldAbsent  DeliveryReason = "form_field_not_in_body"
	ReasonSlotHasNoName    DeliveryReason = "slot_has_no_name"

	// Body.
	ReasonBodyNotCaptured    DeliveryReason = "body_not_captured"
	ReasonBodyNotJSON        DeliveryReason = "body_is_not_valid_json"
	ReasonPointerMalformed   DeliveryReason = "json_pointer_malformed"
	ReasonPointerNotFound    DeliveryReason = "json_pointer_not_found"
	ReasonNodePayloadNotJSON DeliveryReason = "json_node_payload_is_not_valid_json"
	// encoding/json silently replaces an invalid UTF-8 byte with U+FFFD. That is the same class of
	// bug as the cookie sanitiser, so the payload is refused before it can be quietly rewritten.
	ReasonPayloadNotUTF8 DeliveryReason = "json_string_payload_is_not_utf8"

	// Declared gaps. An encoder mode with no implementation is a refusal with a name, never a
	// silent pass-through, because a pass-through would send SOMETHING and record it as the probe.
	ReasonEncoderNotImplemented DeliveryReason = "encoder_mode_not_implemented"
	ReasonEncoderWrongKind      DeliveryReason = "encoder_mode_not_valid_for_slot_kind"

	ReasonURLUnusable DeliveryReason = "request_url_not_absolute"
)

// triageDeliveryReasons is the exhaustive vocabulary, and a test asserts every constant above
// appears in it. The skeleton learned this the hard way with TriageState: a reason that exists as
// a constant but not in the table is a state nothing knows how to render.
var triageDeliveryReasons = []DeliveryReason{
	ReasonFragmentNotTransmitted,
	ReasonValueCRLF, ReasonValueNUL, ReasonValueControl,
	ReasonSlotImpossibleByte, ReasonSlotRejectsPercentEnc,
	ReasonPathSlashUnencodable, ReasonPathTemplateOpen, ReasonPathIndexOutOfRange,
	ReasonQueryParamAbsent, ReasonFormFieldAbsent, ReasonSlotHasNoName,
	ReasonBodyNotCaptured, ReasonBodyNotJSON, ReasonPointerMalformed, ReasonPointerNotFound,
	ReasonNodePayloadNotJSON, ReasonPayloadNotUTF8,
	ReasonEncoderNotImplemented, ReasonEncoderWrongKind, ReasonURLUnusable,
}

// DeliveryReasons returns the vocabulary, sorted, for a UI that has to render every state a probe
// can end in. None of these may render, sort, filter or export as clean.
func DeliveryReasons() []DeliveryReason {
	out := append([]DeliveryReason(nil), triageDeliveryReasons...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------------------------------------------------------------------------------------------
// 3. THE RESULT
// ---------------------------------------------------------------------------------------------

// Encoded is what every encode returns: the wire bytes, whether they were delivered, and when they
// were not, why. There is no fourth shape and there is no error return that a caller can ignore:
// Delivered false with a Reason is the error, and NewRequest refuses to build a request from one.
type Encoded struct {
	// Wire carries the logical bytes, the rendered bytes, the whole serialized container and the
	// survival verdict. It is the thing that goes into Observation.Payload.
	Wire triage.PayloadWire
	// Delivered is true only when the bytes went into the container as asked.
	Delivered bool
	// Reason is empty if and only if Delivered is true.
	Reason DeliveryReason
	// Detail is free text that names the specific byte, offset, field or segment. It is populated
	// on success too, for the container-level notes that are not failures but are not nothing
	// either: a duplicate parameter name, a re-serialized JSON document.
	Detail string
	// Req is the modified request. It is the zero template when Delivered is false, so a caller
	// that ignores Delivered sends nothing rather than sending the unperturbed request and
	// recording it as a probe.
	Req RequestTemplate
}

// ---------------------------------------------------------------------------------------------
// 4. THE ENTRY POINT
// ---------------------------------------------------------------------------------------------

// EncodeSlotInto renders logical into the slot of tmpl and returns the modified request.
//
// It is deliberately NOT the EncodeSlot stub in triageSlots.go: that signature has no request to
// render into, so it can produce wire bytes but not a container, and without a container there is
// nothing to check the fidelity of. See the note at the bottom of this file.
//
// mode may be EncodeNone, in which case the slot kind's default encoder is resolved and recorded
// in the chain, so "the class declared nothing" is still visible in the stored EncoderChain.
func EncodeSlotInto(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte, ov triage.SlotOverrides) Encoded {
	if mode == triage.EncodeNone || mode == "" {
		mode = DefaultEncoderFor(s)
	}

	// A fragment is not sent. RFC 3986 section 3.5 makes it a client-side reference and no
	// conforming client puts it in the request-target, so there is no such thing as a faithful
	// HTTP delivery into a fragment slot. This is the one insertion point that is impossible by
	// construction rather than by payload.
	if s.Kind == triage.KindFragment || !s.ServerReachable {
		return triageRefuse(s, mode, logical, ReasonFragmentNotTransmitted,
			"the fragment is stripped by every conforming client, so no HTTP-level probe reaches it")
	}

	// The measured per-slot impossibility table. A class whose payload needs one of these bytes
	// gets not_reachable, and the byte is named so the operator can see which one.
	for _, b := range s.Constraints.Impossible {
		if bytes.IndexByte(logical, b) >= 0 {
			return triageRefuse(s, mode, logical, ReasonSlotImpossibleByte,
				fmt.Sprintf("byte 0x%02x is on this slot's measured impossible list", b))
		}
	}

	if err := triageModeFitsKind(mode, s.Kind); err != nil {
		return triageRefuse(s, mode, logical, ReasonEncoderWrongKind, err.Error())
	}

	prefix, path, query, ok := triageSplitWireURL(tmpl.URL)
	if !ok {
		return triageRefuse(s, mode, logical, ReasonURLUnusable,
			fmt.Sprintf("%q has no scheme://authority, so there is no request-target to render into", tmpl.URL))
	}
	// An unresolved template segment poisons EVERY encode against this request, not just a path
	// encode: the request goes to a literal /orders/%7Bid%7D, which is a 404 on any app, and a
	// scanner pointed at a 404 that finds nothing has not tested the endpoint. SlotsFor resolves
	// these from the vector's own evidence URL; when it could not, the refusal belongs here.
	if i := strings.IndexAny(path, "{}"); i >= 0 {
		return triageRefuse(s, mode, logical, ReasonPathTemplateOpen,
			fmt.Sprintf("path %q still carries an unresolved template at offset %d", path, i))
	}

	switch mode {
	case triage.EncodeQuery, triage.EncodeLiteralPct, triage.EncodePctTwice:
		return triageEncodeQuery(tmpl, s, mode, logical, prefix, path, query)
	case triage.EncodeNameSlot:
		return triageEncodeNameSlot(tmpl, s, mode, logical, prefix, path, query)
	case triage.EncodePathSegment:
		return triageEncodePath(tmpl, s, mode, logical, ov, prefix, path, query)
	case triage.EncodeCookie:
		return triageEncodeCookie(tmpl, s, mode, logical, ov)
	case triage.EncodeHeaderValue:
		return triageEncodeHeader(tmpl, s, mode, logical, ov)
	case triage.EncodeForm:
		return triageEncodeForm(tmpl, s, mode, logical)
	case triage.EncodeJSONString, triage.EncodeJSONNodeReplace:
		return triageEncodeJSON(tmpl, s, mode, logical)
	case triage.EncodeXMLCDATA, triage.EncodeXMLDocReplace, triage.EncodeMultipartValue, triage.EncodeMultipartName, triage.EncodeIISUnicode:
		// Declared, not implemented. The corpus measured 218 vectors across query, body, header,
		// cookie and path with no XML and no multipart body, so these were left out rather than
		// written untested. They refuse by name so that adding an XML vector produces a visible
		// not_reachable instead of a silent clean.
		return triageRefuse(s, mode, logical, ReasonEncoderNotImplemented,
			fmt.Sprintf("encoder %q has no implementation in %s", mode, TriageEncoderVersion))
	default:
		return triageRefuse(s, mode, logical, ReasonEncoderNotImplemented,
			fmt.Sprintf("encoder %q is not a known mode", mode))
	}
}

// DefaultEncoderFor resolves the encoder a slot kind needs when the probe declared none.
func DefaultEncoderFor(s triage.Slot) triage.EncoderMode {
	switch s.Kind {
	case triage.KindQuery:
		return triage.EncodeQuery
	case triage.KindPath:
		return triage.EncodePathSegment
	case triage.KindCookie:
		return triage.EncodeCookie
	case triage.KindHeader:
		return triage.EncodeHeaderValue
	case triage.KindFragment:
		return triage.EncodeNone
	case triage.KindBody:
		switch s.BodyMedia {
		case triage.BodyForm:
			return triage.EncodeForm
		case triage.BodyMultipart:
			return triage.EncodeMultipartValue
		case triage.BodyXML:
			return triage.EncodeXMLCDATA
		default:
			// BodyJSON, BodyGraphQL and an unset media all render as a JSON string value. A
			// GraphQL POST is a JSON envelope in every capture in the corpus; when it is not, the
			// JSON encoder refuses with body_is_not_valid_json rather than guessing.
			return triage.EncodeJSONString
		}
	}
	return triage.EncodeNone
}

// triageModeFitsKind stops a probe declaring EncodeCookie on a query slot. The mismatch would
// otherwise render into the wrong container and report on a slot nobody asked about.
func triageModeFitsKind(mode triage.EncoderMode, kind triage.SlotKind) error {
	allowed := map[triage.EncoderMode][]triage.SlotKind{
		triage.EncodeQuery:           {triage.KindQuery},
		triage.EncodeLiteralPct:      {triage.KindQuery, triage.KindPath},
		triage.EncodePctTwice:        {triage.KindQuery, triage.KindPath},
		triage.EncodeNameSlot:        {triage.KindQuery, triage.KindBody},
		triage.EncodePathSegment:     {triage.KindPath},
		triage.EncodeCookie:          {triage.KindCookie},
		triage.EncodeHeaderValue:     {triage.KindHeader},
		triage.EncodeForm:            {triage.KindBody},
		triage.EncodeJSONString:      {triage.KindBody},
		triage.EncodeJSONNodeReplace: {triage.KindBody},
		triage.EncodeXMLCDATA:        {triage.KindBody},
		triage.EncodeXMLDocReplace:   {triage.KindBody},
		triage.EncodeMultipartValue:  {triage.KindBody},
		triage.EncodeMultipartName:   {triage.KindBody},
		triage.EncodeIISUnicode:      {triage.KindPath, triage.KindQuery},
	}
	ks, known := allowed[mode]
	if !known {
		return nil // the dispatch switch names it; do not fail twice with two different reasons
	}
	for _, k := range ks {
		if k == kind {
			return nil
		}
	}
	return fmt.Errorf("encoder %q renders into %v, not into a %s slot", mode, ks, kind)
}

// ---------------------------------------------------------------------------------------------
// 5. QUERY AND FORM: THE SAME CONTAINER IN TWO PLACES
// ---------------------------------------------------------------------------------------------

func triageEncodeQuery(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte, prefix, path, query string) Encoded {
	if s.Name == "" {
		return triageRefuse(s, mode, logical, ReasonSlotHasNoName, "a query slot must name its parameter")
	}
	wire, needsPct := triageEscapeQueryValue(logical, mode)
	if needsPct && (s.Constraints.PctRejected) {
		return triageRefuse(s, mode, logical, ReasonSlotRejectsPercentEnc,
			"this slot was measured to reject percent-encoding and the payload cannot be sent raw in a query")
	}

	newQuery, found, dup := triageReplacePair(query, s.Name, string(wire), false)
	if !found {
		if s.Origin != triage.SlotInferred {
			return triageRefuse(s, mode, logical, ReasonQueryParamAbsent,
				fmt.Sprintf("observed slot %q is not in the captured query %q", s.Name, query))
		}
		// An inferred slot is by definition not in the capture, so appending it IS the probe.
		newQuery = triageAppendPair(query, url.QueryEscape(s.Name), string(wire))
	}

	out := tmpl.Clone()
	out.URL = triageJoinWireURL(prefix, path, newQuery)
	return triageDelivered(s, mode, logical, wire, []byte(newQuery), "request-target query", out,
		triageDupNote(dup, s.Name))
}

func triageEncodeForm(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte) Encoded {
	if s.Name == "" {
		return triageRefuse(s, mode, logical, ReasonSlotHasNoName, "a form slot must name its field")
	}
	if len(tmpl.Body) == 0 && s.Origin != triage.SlotInferred {
		return triageRefuse(s, mode, logical, ReasonBodyNotCaptured,
			"the capture stored no body, so there is no form field to perturb")
	}
	wire, needsPct := triageEscapeQueryValue(logical, triage.EncodeQuery)
	if needsPct && s.Constraints.PctRejected {
		return triageRefuse(s, mode, logical, ReasonSlotRejectsPercentEnc,
			"this slot was measured to reject percent-encoding and a form value cannot be sent raw")
	}

	body := string(tmpl.Body)
	newBody, found, dup := triageReplacePair(body, s.Name, string(wire), false)
	if !found {
		if s.Origin != triage.SlotInferred {
			return triageRefuse(s, mode, logical, ReasonFormFieldAbsent,
				fmt.Sprintf("observed slot %q is not in the captured form body", s.Name))
		}
		newBody = triageAppendPair(body, url.QueryEscape(s.Name), string(wire))
	}

	out := tmpl.Clone()
	out.Body = []byte(newBody)
	out.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	return triageDelivered(s, mode, logical, wire, []byte(newBody), "body(form)", out,
		triageDupNote(dup, s.Name))
}

// triageEncodeNameSlot perturbs the parameter NAME rather than its value. Mass assignment and HPP
// need it, and it is a different container position, so it gets its own path rather than a flag.
func triageEncodeNameSlot(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte, prefix, path, query string) Encoded {
	if s.Name == "" {
		return triageRefuse(s, mode, logical, ReasonSlotHasNoName, "a name-slot probe must name the parameter it replaces")
	}
	wire, _ := triageEscapeQueryValue(logical, triage.EncodeQuery)

	switch s.Kind {
	case triage.KindQuery:
		newQuery, found, dup := triageReplacePair(query, s.Name, string(wire), true)
		if !found {
			return triageRefuse(s, mode, logical, ReasonQueryParamAbsent,
				fmt.Sprintf("slot %q is not in the captured query %q", s.Name, query))
		}
		out := tmpl.Clone()
		out.URL = triageJoinWireURL(prefix, path, newQuery)
		return triageDelivered(s, mode, logical, wire, []byte(newQuery), "request-target query", out,
			triageDupNote(dup, s.Name))
	case triage.KindBody:
		if s.BodyMedia != triage.BodyForm {
			return triageRefuse(s, mode, logical, ReasonEncoderNotImplemented,
				"name-slot perturbation is implemented for form bodies only; a JSON key rename is a different edit")
		}
		newBody, found, dup := triageReplacePair(string(tmpl.Body), s.Name, string(wire), true)
		if !found {
			return triageRefuse(s, mode, logical, ReasonFormFieldAbsent,
				fmt.Sprintf("slot %q is not in the captured form body", s.Name))
		}
		out := tmpl.Clone()
		out.Body = []byte(newBody)
		return triageDelivered(s, mode, logical, wire, []byte(newBody), "body(form)", out,
			triageDupNote(dup, s.Name))
	}
	return triageRefuse(s, mode, logical, ReasonEncoderWrongKind, "name-slot applies to query and form slots")
}

// triageReplacePair edits ONE pair in an &-joined pair list and leaves every other byte alone.
//
// It does not go through url.Values. Values.Encode sorts the keys and re-escapes every value, so a
// probe built with it differs from the baseline in places the payload never touched, and the
// response comparator then attributes those differences to the payload. Splitting and rejoining on
// "&" is lossless for everything we are not editing.
func triageReplacePair(pairs, name, replacement string, replaceName bool) (out string, found bool, duplicate bool) {
	if pairs == "" {
		return pairs, false, false
	}
	parts := strings.Split(pairs, "&")
	for i, p := range parts {
		rawName, rawValue := p, ""
		if eq := strings.Index(p, "="); eq >= 0 {
			rawName, rawValue = p[:eq], p[eq+1:]
		}
		if triageUnescapeName(rawName) != name {
			continue
		}
		if found {
			// A second pair with the same name. Only the first is perturbed, because perturbing
			// both sends two payloads in one request and no response can tell them apart.
			duplicate = true
			continue
		}
		found = true
		if replaceName {
			parts[i] = replacement + "=" + rawValue
		} else {
			parts[i] = rawName + "=" + replacement
		}
	}
	return strings.Join(parts, "&"), found, duplicate
}

func triageAppendPair(pairs, name, value string) string {
	if pairs == "" {
		return name + "=" + value
	}
	return pairs + "&" + name + "=" + value
}

func triageUnescapeName(n string) string {
	if d, err := url.QueryUnescape(n); err == nil {
		return d
	}
	return n
}

func triageDupNote(dup bool, name string) string {
	if !dup {
		return ""
	}
	return fmt.Sprintf("parameter %q appears more than once; only the first occurrence was perturbed", name)
}

// triageEscapeQueryValue is url.QueryEscape and never url.PathEscape. needsPct reports whether the
// escaping changed anything, which is what decides whether a percent-rejecting slot can carry it.
func triageEscapeQueryValue(logical []byte, mode triage.EncoderMode) (wire []byte, needsPct bool) {
	switch mode {
	case triage.EncodePctTwice:
		once := url.QueryEscape(string(logical))
		return []byte(url.QueryEscape(once)), true
	case triage.EncodeLiteralPct:
		// The percent sign goes through raw so the decode-depth control can measure whether the
		// application decodes once or twice. Everything else is still escaped, because an
		// unescaped ampersand would split the parameter and test a different string.
		w := triageEscapeBytes(logical, triageQueryUnreserved, '%')
		return w, !bytes.Equal(w, logical)
	default:
		w := []byte(url.QueryEscape(string(logical)))
		return w, string(w) != string(logical)
	}
}

// ---------------------------------------------------------------------------------------------
// 6. PATH SEGMENTS
// ---------------------------------------------------------------------------------------------

// triageEncodePath replaces ONE path segment. SegmentIndex is an index into the segments of the
// path after the leading slash, so /api/v1/orders/42 has index 0 "api" and index 3 "42".
//
// THE SLASH RULE. The payload is one segment. A raw slash splits it into two, which means the
// request goes to a different route and the response says nothing about the slot. So a slash is
// percent-encoded, and where the probe or the slot forbids percent-encoding it is declared
// undeliverable rather than sent split. That refusal is the correct outcome for a traversal
// payload against a slot measured to reject %2F, and it is not a clean.
func triageEncodePath(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte, ov triage.SlotOverrides, prefix, path, query string) Encoded {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if s.SegmentIndex < 0 || s.SegmentIndex >= len(segs) {
		return triageRefuse(s, mode, logical, ReasonPathIndexOutOfRange,
			fmt.Sprintf("segment index %d but %q has %d segments", s.SegmentIndex, path, len(segs)))
	}

	rawPercent := ov.RawPercent || s.Constraints.PctRejected
	if rawPercent {
		if bytes.IndexByte(logical, '/') >= 0 {
			return triageRefuse(s, mode, logical, ReasonPathSlashUnencodable,
				"the payload carries a slash and this probe requires a raw percent sign, so the payload cannot stay inside one segment")
		}
		if i := triageFirstByteNeedingEscape(logical, triagePathUnreserved(ov.PathSemicolonRaw)); i >= 0 && logical[i] != '%' {
			return triageRefuse(s, mode, logical, ReasonSlotRejectsPercentEnc,
				fmt.Sprintf("byte 0x%02x at offset %d needs percent-encoding and this slot rejects it", logical[i], i))
		}
	}

	var wire []byte
	if rawPercent {
		wire = append([]byte(nil), logical...)
	} else {
		wire = triageEscapeBytes(logical, triagePathUnreserved(ov.PathSemicolonRaw))
	}

	segs[s.SegmentIndex] = string(wire)
	newPath := "/" + strings.Join(segs, "/")

	out := tmpl.Clone()
	out.URL = triageJoinWireURL(prefix, newPath, query)
	return triageDelivered(s, mode, logical, wire, []byte(newPath), "request-target path", out, "")
}

// triagePathUnreserved is RFC 3986 pchar minus the characters that would end the segment. The
// semicolon is escaped by default because a raw one starts a matrix parameter on Tomcat and Jetty
// and the payload after it never reaches the handler; PathSemicolonRaw is the probe's opt-out.
func triagePathUnreserved(semicolonRaw bool) func(byte) bool {
	return func(c byte) bool {
		if triageIsUnreserved(c) {
			return true
		}
		switch c {
		case '!', '$', '&', '\'', '(', ')', '*', '+', ',', '=', ':', '@':
			return true
		case ';':
			return semicolonRaw
		}
		return false
	}
}

// ---------------------------------------------------------------------------------------------
// 7. COOKIES: BY HAND, ALWAYS
// ---------------------------------------------------------------------------------------------

// triageEncodeCookie rebuilds the Cookie header line by hand.
//
// It never touches http.Cookie or Request.AddCookie. Those sanitise, and what they remove is
// exactly the probe alphabet: the measurement is at the top of this file and a test asserts it
// again so the claim cannot rot. The rebuild is lossless for every cookie we are not editing,
// because splitting and rejoining on ";" preserves the original spacing byte for byte.
//
// THE SEMICOLON IS SENT BUT FLAGGED. req.Header.Set puts the bytes on the wire verbatim, which is
// what was asked for, but any RFC 6265 parser on the far side splits the value at the semicolon
// and the application sees a shorter string than the one sent. The bytes are delivered; the VALUE
// is not. That is WireSurvivalAltered, which is not Proven, which means no clean can be drawn from
// it. It is not a refusal, because the split itself is worth observing.
func triageEncodeCookie(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte, ov triage.SlotOverrides) Encoded {
	if s.Name == "" {
		return triageRefuse(s, mode, logical, ReasonSlotHasNoName, "a cookie slot must name its cookie")
	}

	wire := append([]byte(nil), logical...)
	if ov.CookieSpaceEncode {
		wire = bytes.ReplaceAll(wire, []byte(" "), []byte("%20"))
	}
	if reason, detail := triageHeaderValueFault(wire); reason != DeliverOK {
		return triageRefuse(s, mode, logical, reason, "Cookie header: "+detail)
	}

	line, _ := tmpl.HeaderValue("Cookie")
	newLine, found := triageReplaceCookie(line, s.Name, string(wire))
	if !found {
		if s.Origin != triage.SlotInferred && line != "" {
			return triageRefuse(s, mode, logical, ReasonQueryParamAbsent,
				fmt.Sprintf("observed cookie %q is not in the captured Cookie header", s.Name))
		}
		if line == "" {
			newLine = s.Name + "=" + string(wire)
		} else {
			newLine = line + "; " + s.Name + "=" + string(wire)
		}
	}

	out := tmpl.Clone()
	out.SetHeader("Cookie", newLine)

	enc := triageDelivered(s, mode, logical, wire, []byte(newLine), "Cookie", out, "")
	if bytes.IndexByte(wire, ';') >= 0 {
		enc.Wire.Survived = triage.WireSurvivalAltered
		enc.Wire.AlteredBy = "RFC 6265 cookie parsing splits the value at the semicolon, so the application reads a shorter value than the bytes sent"
		enc.Detail = enc.Wire.AlteredBy
	}
	return enc
}

// triageReplaceCookie edits one cookie in a Cookie header line. Split and join on ";" is lossless,
// so the other cookies keep their original spacing and their original encoding.
func triageReplaceCookie(line, name, value string) (string, bool) {
	if line == "" {
		return "", false
	}
	parts := strings.Split(line, ";")
	found := false
	for i, p := range parts {
		lead := p[:len(p)-len(strings.TrimLeft(p, " \t"))]
		trimmed := strings.TrimLeft(p, " \t")
		cName := trimmed
		if eq := strings.Index(trimmed, "="); eq >= 0 {
			cName = trimmed[:eq]
		}
		if cName != name || found {
			continue
		}
		found = true
		parts[i] = lead + cName + "=" + value
	}
	return strings.Join(parts, ";"), found
}

// ---------------------------------------------------------------------------------------------
// 8. HEADERS
// ---------------------------------------------------------------------------------------------

// triageEncodeHeader writes the logical bytes into a header value with NO encoding, because a
// header value has no escaping mechanism: whatever RFC 7230 field-vchar permits goes out raw and
// everything else cannot be sent at all.
//
// CR and LF are the named case. A conforming client cannot send them, Go refuses them with
// "net/http: invalid header field value", and SlotOverrides.HeaderAllowRawLF exists precisely to
// make that refusal explicit rather than to enable it, so the override is honoured as a louder
// reason and never as a bypass.
func triageEncodeHeader(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte, ov triage.SlotOverrides) Encoded {
	if s.Name == "" {
		return triageRefuse(s, mode, logical, ReasonSlotHasNoName, "a header slot must name its field")
	}
	if reason, detail := triageHeaderValueFault(logical); reason != DeliverOK {
		if reason == ReasonValueCRLF && ov.HeaderAllowRawLF {
			detail += "; the probe declared HeaderAllowRawLF, which records the refusal rather than enabling it"
		}
		return triageRefuse(s, mode, logical, reason, s.Name+" header: "+detail)
	}

	wire := append([]byte(nil), logical...)
	out := tmpl.Clone()
	out.SetHeader(s.Name, string(wire))

	enc := triageDelivered(s, mode, logical, wire, []byte(s.Name+": "+string(wire)), s.Name, out, "")
	// Leading and trailing whitespace is optional whitespace in RFC 7230 and every conforming
	// server strips it before the handler sees the value. The bytes go out; the value the
	// application reads is shorter. Same reasoning as the cookie semicolon.
	if t := strings.Trim(string(wire), " \t"); t != string(wire) {
		enc.Wire.Survived = triage.WireSurvivalAltered
		enc.Wire.AlteredBy = "RFC 7230 optional whitespace is stripped by any conforming server, so the leading or trailing space in this payload does not reach the application"
		enc.Detail = enc.Wire.AlteredBy
	}
	return enc
}

// triageHeaderValueFault reproduces net/http's field-value check so a refusal is a named state
// here rather than a transport error three layers later. Agreement with net/http is asserted by
// sending each rejected value through a real client in the tests.
func triageHeaderValueFault(v []byte) (DeliveryReason, string) {
	for i, c := range v {
		switch {
		case c == '\r' || c == '\n':
			return ReasonValueCRLF, fmt.Sprintf("byte 0x%02x at offset %d cannot be sent by a conforming client", c, i)
		case c == 0x00:
			return ReasonValueNUL, fmt.Sprintf("NUL at offset %d is rejected by net/http as an invalid header field value", i)
		case c < 0x20 && c != '\t', c == 0x7f:
			return ReasonValueControl, fmt.Sprintf("control byte 0x%02x at offset %d is not field-vchar", c, i)
		}
	}
	return DeliverOK, ""
}

// ---------------------------------------------------------------------------------------------
// 9. JSON BODIES
// ---------------------------------------------------------------------------------------------

// triageEncodeJSON sets the value at a JSON pointer and re-serializes the document.
//
// THE PAYLOAD IS A JSON STRING VALUE, so a raw double quote must become \" and a backslash \\.
// This is done by marshalling, never by string concatenation: a concatenated raw quote makes OUR
// document invalid, and the 400 that comes back is about our JSON, not about the application. A
// 400 read as a differential is a false finding, and a 400 read as a defence is a false clean.
//
// The document is decoded with UseNumber so that 1e9 does not come back out as 1000000000 and show
// up in the comparator as a difference the payload did not cause.
func triageEncodeJSON(tmpl RequestTemplate, s triage.Slot, mode triage.EncoderMode, logical []byte) Encoded {
	if len(tmpl.Body) == 0 {
		return triageRefuse(s, mode, logical, ReasonBodyNotCaptured,
			"the capture stored no body, so there is no JSON document to edit")
	}

	dec := json.NewDecoder(bytes.NewReader(tmpl.Body))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return triageRefuse(s, mode, logical, ReasonBodyNotJSON, err.Error())
	}

	tokens, err := triageJSONPointer(s.FieldPath)
	if err != nil {
		return triageRefuse(s, mode, logical, ReasonPointerMalformed, err.Error())
	}

	var value any
	var wire []byte
	switch mode {
	case triage.EncodeJSONNodeReplace:
		if !json.Valid(logical) {
			return triageRefuse(s, mode, logical, ReasonNodePayloadNotJSON,
				"a node-replace payload has to be a JSON value in its own right, and this one does not parse")
		}
		value = json.RawMessage(logical)
		wire = append([]byte(nil), logical...)
	default:
		// encoding/json replaces an invalid UTF-8 byte with U+FFFD and says nothing. That is the
		// cookie sanitiser all over again, so it is refused before it can rewrite the payload.
		if !utf8.Valid(logical) {
			return triageRefuse(s, mode, logical, ReasonPayloadNotUTF8,
				"encoding/json would silently replace the invalid byte with U+FFFD, which would test a different payload")
		}
		value = string(logical)
		w, err := triageMarshalJSON(value)
		if err != nil {
			return triageRefuse(s, mode, logical, ReasonNodePayloadNotJSON, err.Error())
		}
		wire = w
	}

	edited, err := triageSetAtPointer(doc, tokens, value)
	if err != nil {
		return triageRefuse(s, mode, logical, ReasonPointerNotFound, err.Error())
	}
	body, err := triageMarshalJSON(edited)
	if err != nil {
		return triageRefuse(s, mode, logical, ReasonBodyNotJSON, err.Error())
	}

	out := tmpl.Clone()
	out.Body = body
	out.SetHeader("Content-Type", "application/json")

	// The whole document is re-serialized, so object key order becomes encoding/json's order. That
	// is a container change the payload did not cause, and a comparator that hashes the request
	// has to know about it. It is recorded rather than hidden.
	return triageDelivered(s, mode, logical, wire, body, "body(json)", out,
		"the JSON document was re-serialized: object key order is encoding/json's, not the capture's")
}

// triageJSONPointer parses RFC 6901. The empty pointer addresses the whole document, which is a
// legitimate target for a body that is a bare string.
func triageJSONPointer(p string) ([]string, error) {
	if p == "" {
		return nil, nil
	}
	if !strings.HasPrefix(p, "/") {
		return nil, fmt.Errorf("JSON pointer %q does not start with a slash", p)
	}
	parts := strings.Split(p[1:], "/")
	for i, t := range parts {
		t = strings.ReplaceAll(t, "~1", "/")
		parts[i] = strings.ReplaceAll(t, "~0", "~")
	}
	return parts, nil
}

// triageSetAtPointer walks to the pointer and replaces the value. A pointer that does not resolve
// is an error, never a create: inventing a field would test a field the application does not read
// and record the slot as probed.
func triageSetAtPointer(node any, tokens []string, value any) (any, error) {
	if len(tokens) == 0 {
		return value, nil
	}
	head, rest := tokens[0], tokens[1:]
	switch n := node.(type) {
	case map[string]any:
		child, ok := n[head]
		if !ok {
			return nil, fmt.Errorf("no member %q in the object at this pointer", head)
		}
		sub, err := triageSetAtPointer(child, rest, value)
		if err != nil {
			return nil, err
		}
		n[head] = sub
		return n, nil
	case []any:
		i, err := strconv.Atoi(head)
		if err != nil || i < 0 || i >= len(n) {
			return nil, fmt.Errorf("index %q is not inside the %d-element array at this pointer", head, len(n))
		}
		sub, err := triageSetAtPointer(n[i], rest, value)
		if err != nil {
			return nil, err
		}
		n[i] = sub
		return n, nil
	default:
		return nil, fmt.Errorf("pointer continues at %q but the value there is a scalar", head)
	}
}

// triageMarshalJSON marshals without HTML escaping, so a payload containing <, > or & appears in
// the document as itself. The default escaping is still valid JSON and the application would decode
// the same bytes, but the wire form would no longer contain the payload, and the fidelity check
// reads the wire form.
func triageMarshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// ---------------------------------------------------------------------------------------------
// 10. THE FIDELITY CHECK
// ---------------------------------------------------------------------------------------------

// CheckFidelity re-derives WireSurvival from the bytes instead of trusting the encoder's own
// claim, and it is the value that goes on the Observation. The encoder can be wrong; the container
// cannot, because it is what the transport will write.
//
// It never returns Intact for a payload it cannot find. Unknown is a real answer here, and
// WireSurvival.Proven is false for it, so a classifier cannot reach clean through this function.
func CheckFidelity(w triage.PayloadWire) (triage.WireSurvival, string) {
	switch {
	case w.Survived == triage.WireSurvivalRefused:
		return triage.WireSurvivalRefused, w.AlteredBy
	case len(w.Logical) == 0:
		return triage.WireSurvivalUnknown, "the probe declared no logical payload, so there is nothing to check"
	case len(w.Container) == 0:
		return triage.WireSurvivalUnknown, "no serialized container was recorded, so survival cannot be checked"
	case w.Survived == triage.WireSurvivalAltered:
		// The encoder knows about alterations the bytes cannot show, for example a cookie value
		// that a parser will split. Its verdict stands.
		return triage.WireSurvivalAltered, w.AlteredBy
	case !bytes.Contains(w.Container, w.Wire):
		return triage.WireSurvivalDropped, "the rendered wire form is not present in the serialized container"
	case bytes.Equal(w.Logical, w.Wire):
		// Deliberately not "the container contains the logical bytes": another parameter in the
		// same container can hold the same byte, and that would read as intact for a payload the
		// encoder actually escaped.
		return triage.WireSurvivalIntact, ""
	default:
		return triage.WireSurvivalEncoded, fmt.Sprintf("present through the declared encoder chain %v, not verbatim", w.EncoderChain)
	}
}

// CompareDelivered is the strong form of the check: what the class asked for against what the far
// side actually parsed out of the request. It needs an echo, so it runs in the tests and against a
// loopback oracle, and it is what found the cookie bug. Byte equality or nothing.
func CompareDelivered(logical, received []byte) (triage.WireSurvival, string) {
	switch {
	case bytes.Equal(logical, received):
		return triage.WireSurvivalIntact, ""
	case len(received) == 0:
		return triage.WireSurvivalDropped, fmt.Sprintf("%d payload bytes were sent and the far side read none", len(logical))
	default:
		return triage.WireSurvivalAltered, triageFirstDifference(logical, received)
	}
}

func triageFirstDifference(want, got []byte) string {
	n := len(want)
	if len(got) < n {
		n = len(got)
	}
	for i := 0; i < n; i++ {
		if want[i] != got[i] {
			return fmt.Sprintf("first difference at offset %d: asked for 0x%02x, the far side read 0x%02x (%d bytes sent, %d read)",
				i, want[i], got[i], len(want), len(got))
		}
	}
	return fmt.Sprintf("the far side read a %d-byte prefix of the %d bytes sent", len(got), len(want))
}

// AttachEncode copies an encode onto the observation and stamps the re-derived survival verdict, so
// the fidelity result travels with the response instead of living in the runner's head.
//
// It refuses an undeliverable encode the same way NewRequest does. An Observation carrying an
// undeliverable payload would be a request that was never sent, wearing a response's shape.
//
// IT IS A FUNCTION AND NOT A METHOD because Observation now lives in package triage and Go forbids
// defining a method on another package's type. The body is unchanged. Pushing Observation's
// encoder-awareness DOWN into triage was the alternative and was rejected: it would drag
// RequestTemplate, Encoded and CheckFidelity across the boundary with it, and the whole point of
// the boundary is that it stays narrow.
// IT ALSO RECORDS WHICH SEND PATH THE HEADERS WILL TAKE, which it did not used to and which made
// Observation.ReqHeaders a lie on the common case. The old body copied e.Req.Headers into
// ReqHeaders on both paths, and Observation documented that field as ordered with duplicates
// preserved, unconditionally. On the default path net/http reorders: Host, then User-Agent, then
// the remaining names byte-sorted. So the stored order was the TEMPLATE's, the wire order was
// something else, and nothing recorded which of the two a reader was looking at. HPP, CRLF and
// smuggling are defined by order, so those three classes would have been reasoning about a list
// that no socket ever carried.
//
// The wire order is now MEASURED rather than predicted: the template goes through
// triageSerializeOnWire, which is the same function that produces the recorded container and which
// dispatches to the same two writers the send path does. Predicting net/http's ordering in a table
// here would be a second implementation of it, and the first time the standard library changed,
// the table would be wrong and silent.
func AttachEncode(o *triage.Observation, e Encoded) error {
	if !e.Delivered {
		return fmt.Errorf("triage: refusing to attach an undeliverable encode to an observation (%s: %s)", e.Reason, e.Detail)
	}
	o.ReqMethod = e.Req.Method
	o.ReqWireURL = e.Req.URL
	o.ReqHeaders = append([][2]string(nil), e.Req.Headers...)
	o.ReqWireHeaders, o.ReqHeaderOrder = triageMeasureHeaderOrder(e.Req)
	o.ReqBody = append([]byte(nil), e.Req.Body...)
	o.ReqBodyLen = len(e.Req.Body)
	o.ReqBodySHA256 = triageSHA256(e.Req.Body)
	o.Payload = e.Wire
	survived, why := CheckFidelity(e.Wire)
	o.Payload.Survived = survived
	if why != "" {
		o.Payload.AlteredBy = why
	}
	return nil
}

// triageMeasureHeaderOrder serializes the template through the writer that will actually send it
// and reads the field order back off the produced bytes.
//
// It returns the wire order and which writer produced it. When the template cannot be serialized
// at all, which for an ordered send means a URL this layer refuses, it returns nil and
// HeaderOrderUnrecorded rather than falling back to the declared order: an unmeasured order has to
// read as unmeasured. A fallback that quietly substituted the template's order would recreate the
// exact bug this function exists to end.
func triageMeasureHeaderOrder(t RequestTemplate) ([][2]string, triage.HeaderOrderPath) {
	raw, err := triageSerializeOnWire(t)
	if err != nil {
		return nil, triage.HeaderOrderUnrecorded
	}
	path := triage.HeaderOrderNetHTTPSorted
	if t.RequireHeaderOrder {
		path = triage.HeaderOrderAsDeclared
	}
	return triageHeaderLinesOf(raw), path
}

// triageHeaderLinesOf pulls the field lines out of serialized request bytes, in order, keeping
// duplicates and the exact spelling of every name.
//
// It splits each line at the FIRST colon only, because a header value may contain colons, and it
// trims exactly one leading space from the value the way RFC 7230's obs-fold-free form writes it.
// A line with no colon is not a header and is skipped rather than guessed at.
func triageHeaderLinesOf(raw []byte) [][2]string {
	head := raw
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head = raw[:i]
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) < 2 {
		return [][2]string{}
	}
	out := make([][2]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		if len(line) == 0 {
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		out = append(out, [2]string{string(name), strings.TrimPrefix(string(value), " ")})
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 11. BUILDING THE REQUEST
// ---------------------------------------------------------------------------------------------

// NewRequest turns a delivered encode into an *http.Request. Cookies go on as a header line, never
// through AddCookie, and the Host header becomes req.Host because net/http ignores it otherwise,
// which would silently neuter every Host header probe.
func (e Encoded) NewRequest(ctx context.Context) (*http.Request, error) {
	if !e.Delivered {
		return nil, fmt.Errorf("triage: refusing to build a request for an undeliverable encode (%s: %s)", e.Reason, e.Detail)
	}
	return e.Req.NewRequest(ctx)
}

// NewRequest builds the request for a template. It exists separately so the unperturbed baseline,
// which is the one thing every class shares, is built by exactly the same code path as a probe.
//
// TWO THINGS THIS PATH CANNOT GIVE YOU, both measured on a raw socket and both documented in
// full above SerializeOrdered:
//
//   - Header ORDER. net/http sorts the field names when it writes them, so the order here is
//     not the order on the wire. A class that needs order sets RequireHeaderOrder, which sends
//     the request through SerializeOrdered instead.
//   - Freedom from Accept-Encoding. The TRANSPORT, not this function, adds Accept-Encoding:
//     gzip to a request that carries none. Send goes through TriageClient, which sets
//     DisableCompression so it does not. A caller that builds a request here and sends it
//     through http.DefaultClient gets the gzip line back.
//
// Prefer Send over building a request here and choosing a client.
func (t RequestTemplate) NewRequest(ctx context.Context) (*http.Request, error) {
	var body *bytes.Reader
	if len(t.Body) > 0 {
		body = bytes.NewReader(t.Body)
	} else {
		body = bytes.NewReader(nil)
	}
	method := t.Method
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequestWithContext(ctx, method, t.URL, body)
	if err != nil {
		return nil, err
	}
	sawUserAgent := false
	for _, h := range t.Headers {
		if strings.EqualFold(h[0], "Host") {
			req.Host = h[1]
			continue
		}
		if h[0] == "" {
			return nil, fmt.Errorf("triage: refusing to build a request with an unnamed header (value %q)", h[1])
		}
		// NOT req.Header.Set, and the difference is a whole family of probes.
		//
		// Set runs the name through textproto.CanonicalMIMEHeaderKey, so x-oDD-CasE goes out as
		// X-Odd-Case, and it REPLACES rather than appends, so the second copy of a name silently
		// deletes the first. Observation.ReqHeaders records the declared list with its duplicates
		// preserved, and three classes depend on exactly that: HPP is defined by sending the same
		// name twice, a header-name casing probe measures nothing if Go rewrites the name, and a
		// CRLF probe is about the literal field the server parses. Assigning into the map writes
		// the key verbatim, because net/http serializes map keys as stored.
		req.Header[h[0]] = append(req.Header[h[0]], h[1])
		if strings.EqualFold(h[0], "User-Agent") {
			sawUserAgent = true
		}
	}

	// net/http writes its OWN User-Agent unless it finds one under the exact canonical key, and
	// it never writes that key through the header map. So a probe that spells the field
	// user-AGENT gets its line plus Go-http-client/1.1, and a class measuring the spelling of one
	// header has quietly sent two. An empty canonical entry suppresses the default and is itself
	// not written.
	//
	// Content-Length and Transfer-Encoding are deliberately NOT treated this way. A second copy
	// of either is the request smuggling probe, and that class needs to be able to send it.
	if sawUserAgent {
		if _, exact := req.Header["User-Agent"]; !exact {
			req.Header["User-Agent"] = []string{""}
		}
	}
	return req, nil
}

// triageSerializeOnWire renders the template through net/http's own serializer and returns the
// bytes it would put on the socket. It is the shared socket-level truth: the encoder's rendering
// is a claim, and this is the only thing in the process that can contradict it.
//
// It builds a THROWAWAY request, because Request.Write consumes the body reader. The request that
// is actually sent is built fresh by NewRequest from the same template.
//
// A template that declares RequireHeaderOrder is serialized by the ordered writer instead, for
// the same reason this function exists at all: the recorded container has to be the bytes that
// will actually go out, and for that template they come from a different writer.
func triageSerializeOnWire(t RequestTemplate) ([]byte, error) {
	if t.RequireHeaderOrder {
		return SerializeOrdered(t)
	}
	req, err := t.NewRequest(context.Background())
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := req.Write(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// triageContainerOnWire pulls one named container out of serialized request bytes. Header names
// are matched case-insensitively as RFC 7230 requires and EVERY copy is returned, joined by CRLF,
// so a duplicated field is one container rather than a choice between two lines.
//
// The bool is false when net/http wrote no such container at all. That is not an empty container:
// it is the whole container missing, and the caller records it as dropped.
func triageContainerOnWire(raw []byte, containerName string) ([]byte, bool) {
	head := raw
	var body []byte
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		head, body = raw[:i], raw[i+4:]
	}
	lines := bytes.Split(head, []byte("\r\n"))
	if len(lines) == 0 {
		return nil, false
	}

	switch {
	case strings.HasPrefix(containerName, "body"):
		if len(body) == 0 {
			return nil, false
		}
		return append([]byte(nil), body...), true

	case strings.HasPrefix(containerName, "request-target"):
		fields := bytes.Fields(lines[0])
		if len(fields) < 2 {
			return nil, false
		}
		target := fields[1]
		path, query, hasQuery := bytes.Cut(target, []byte("?"))
		switch {
		case strings.HasSuffix(containerName, "query"):
			if !hasQuery {
				return nil, false
			}
			return append([]byte(nil), query...), true
		case strings.HasSuffix(containerName, "path"):
			return append([]byte(nil), path...), true
		default:
			return append([]byte(nil), target...), true
		}

	default:
		var found [][]byte
		for _, line := range lines[1:] {
			name, _, ok := bytes.Cut(line, []byte(":"))
			if ok && strings.EqualFold(string(name), containerName) {
				found = append(found, line)
			}
		}
		if len(found) == 0 {
			return nil, false
		}
		return bytes.Join(found, []byte("\r\n")), true
	}
}

// ---------------------------------------------------------------------------------------------
// 11b. HEADER ORDER, AND THE HEADERS NOBODY ASKED FOR
// ---------------------------------------------------------------------------------------------

// THE TWO THINGS net/http DOES TO A REQUEST AFTER THE ENCODER HAS FINISHED WITH IT.
//
// Measured on this machine, go1.26.1, against a raw net.Listen reader. A template declaring
//
//	x-Custom-Case, Z-Last, A-First, User-Agent, M-Middle
//
// put these literal bytes on the socket:
//
//	GET /probe HTTP/1.1\r\n
//	Host: 127.0.0.1:49996\r\n
//	User-Agent: triage-test\r\n
//	A-First: three\r\n
//	M-Middle: four\r\n
//	Z-Last: two\r\n
//	x-Custom-Case: one\r\n
//	Accept-Encoding: gzip\r\n
//
// Two faults, both invisible to httptest because net/http parses the request before a handler
// can see it:
//
//  1. ORDER IS GONE. x-Custom-Case was declared first and arrived last, because
//     Header.writeSubset sorts the field names. Three classes are defined by order: HPP is
//     about which of two copies a backend takes, CRLF is about the literal sequence of fields
//     the parser walks, and request smuggling is entirely about which of Content-Length and
//     Transfer-Encoding comes first.
//  2. AN EXTRA VARIABLE. Accept-Encoding: gzip was added by the transport. Nothing asked for
//     it, and it can change the response body (gzip versus identity) independently of the
//     payload, which is exactly the kind of difference a comparator will attribute to the probe.
//
// THE DECISION. Order is made TRUE rather than documented away. A class that declares
// RequireHeaderOrder has its request bytes written to the connection by this file, in the order
// it wrote them, and net/http is used only to parse the response that comes back. The
// alternative, letting the affected classes report an honest unknown, would have made HPP, CRLF
// and smuggling report unknown on every probe forever, and a permanent unknown is a permanent
// not-tested, which is the false negative this whole layer exists to prevent.
//
// The default path is still net/http, because it is the one with the connection pool, the
// redirect policy, HTTP/2 and everything else. What changed there is that the client triage
// sends through sets DisableCompression, so the gzip line is gone on both paths.
//
// WHAT THE ORDERED PATH DOES NOT DO. It is not a general HTTP client. It speaks HTTP/1.1 only,
// it does not pool connections, it does not follow redirects, and it refuses a CRLF or a NUL in
// a header value exactly as net/http does, so it can never become an accidental request
// splitter. A class that declares RequireHeaderOrder and hits any of those limits gets an
// error, never a quietly downgraded send: see Send.

// HeaderOrderIsGuaranteed reports whether the bytes for this template will reach the socket with
// its headers in the order the template lists them.
//
// It is false by default, and that is not a bug to be papered over: on the net/http path the
// order on the wire is alphabetical, whatever the template says. A class whose verdict depends
// on order sets RequireHeaderOrder and this returns true; a class that reads false and cares
// must record cannot_determine rather than a verdict.
func HeaderOrderIsGuaranteed(t RequestTemplate) bool { return t.RequireHeaderOrder }

// triageOrderedProtocol is the only protocol the ordered writer speaks. Anything else is an
// error rather than a downgrade.
const triageOrderedProtocol = "HTTP/1.1"

// SerializeOrdered renders the template as literal HTTP/1.1 request bytes, in the order the
// template declares, adding nothing the template did not ask for except the two fields a
// request is not valid without.
//
// Host is written first only when the template does not declare one; a template that declares
// Host keeps it wherever it put it, because the position of that field is itself a probe.
//
// Content-Length is supplied only when the template declares NEITHER Content-Length NOR
// Transfer-Encoding. A second copy of either field is the request smuggling probe, so this
// function must never be the thing that adds one.
func SerializeOrdered(t RequestTemplate) ([]byte, error) {
	prefix, path, query, ok := triageSplitWireURL(t.URL)
	if !ok {
		return nil, fmt.Errorf("triage: cannot serialize an ordered request for %q: %w", t.URL, errTriageURLNotAbsolute)
	}
	scheme, authority, err := triageSchemeAuthority(prefix)
	if err != nil {
		return nil, err
	}
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("triage: the ordered wire path speaks http and https, not %q; a class that requires header order cannot probe this URL", scheme)
	}

	method := t.Method
	if method == "" {
		method = http.MethodGet
	}
	if err := triageValidToken(method); err != nil {
		return nil, fmt.Errorf("triage: refusing to write an ordered request with method %q: %w", method, err)
	}

	var buf bytes.Buffer
	buf.WriteString(method)
	buf.WriteByte(' ')
	buf.WriteString(triageJoinWireURL("", path, query))
	buf.WriteByte(' ')
	buf.WriteString(triageOrderedProtocol)
	buf.WriteString("\r\n")

	sawHost, sawLength, sawTransfer := false, false, false
	for _, h := range t.Headers {
		if strings.EqualFold(h[0], "Host") {
			sawHost = true
		}
		if strings.EqualFold(h[0], "Content-Length") {
			sawLength = true
		}
		if strings.EqualFold(h[0], "Transfer-Encoding") {
			sawTransfer = true
		}
	}
	if !sawHost {
		buf.WriteString("Host: ")
		buf.WriteString(authority)
		buf.WriteString("\r\n")
	}
	for _, h := range t.Headers {
		if err := triageValidToken(h[0]); err != nil {
			return nil, fmt.Errorf("triage: refusing to write an ordered request with header name %q: %w", h[0], err)
		}
		if reason, detail := triageHeaderValueFault([]byte(h[1])); reason != DeliverOK {
			return nil, fmt.Errorf("triage: refusing to write header %q on the ordered path (%s: %s)", h[0], reason, detail)
		}
		buf.WriteString(h[0])
		buf.WriteString(": ")
		buf.WriteString(h[1])
		buf.WriteString("\r\n")
	}
	if !sawLength && !sawTransfer && triageOrderedNeedsLength(method, len(t.Body)) {
		buf.WriteString("Content-Length: ")
		buf.WriteString(strconv.Itoa(len(t.Body)))
		buf.WriteString("\r\n")
	}
	buf.WriteString("\r\n")
	buf.Write(t.Body)
	return buf.Bytes(), nil
}

// triageOrderedNeedsLength decides whether to supply a Content-Length. A body always needs one.
// An empty body on a method that normally carries one gets Content-Length: 0, because some
// servers will otherwise sit waiting for a body that is never coming.
func triageOrderedNeedsLength(method string, bodyLen int) bool {
	if bodyLen > 0 {
		return true
	}
	switch strings.ToUpper(method) {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
		return true
	}
	return false
}

// triageSchemeAuthority splits scheme://authority and fills in the default port, so the dial
// target and the synthesized Host line are both derived from the same string.
func triageSchemeAuthority(prefix string) (scheme, authority string, err error) {
	i := strings.Index(prefix, "://")
	if i < 0 {
		return "", "", fmt.Errorf("triage: %q is not scheme://authority", prefix)
	}
	scheme = strings.ToLower(prefix[:i])
	authority = prefix[i+3:]
	if authority == "" {
		return "", "", fmt.Errorf("triage: %q has no authority", prefix)
	}
	// Credentials in the authority are not part of the Host line and are not dialed.
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		authority = authority[at+1:]
	}
	return scheme, authority, nil
}

// triageDialTarget turns an authority into a host:port for net.Dial, supplying the default port
// for the scheme when the authority does not carry one.
func triageDialTarget(scheme, authority string) (hostPort, serverName string) {
	host := authority
	port := ""
	if strings.HasPrefix(authority, "[") {
		if end := strings.Index(authority, "]"); end >= 0 {
			host = authority[:end+1]
			if rest := authority[end+1:]; strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
		}
	} else if i := strings.LastIndex(authority, ":"); i >= 0 && !strings.Contains(authority[i+1:], ":") {
		host, port = authority[:i], authority[i+1:]
	}
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	serverName = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	return net.JoinHostPort(serverName, port), serverName
}

// triageValidToken checks an RFC 7230 token, which is what a method and a header field name
// have to be. net/http rejects anything else at send time, so the ordered path does too: the
// two send paths must refuse the same requests or a class would get different answers depending
// on a flag it set for an unrelated reason.
func triageValidToken(s string) error {
	if s == "" {
		return fmt.Errorf("empty")
	}
	for i := 0; i < len(s); i++ {
		if !triageIsTokenByte(s[i]) {
			return fmt.Errorf("byte %d (0x%02x) is not an RFC 7230 token character", i, s[i])
		}
	}
	return nil
}

func triageIsTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

var errTriageURLNotAbsolute = fmt.Errorf("the URL is not scheme://authority/path")

// triageOrderedBody ties the response body to the connection: closing the body closes the
// socket, because the ordered path has no pool to hand it back to.
type triageOrderedBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b triageOrderedBody) Close() error {
	err := b.ReadCloser.Close()
	if cerr := b.conn.Close(); err == nil {
		err = cerr
	}
	return err
}

// SendOrdered writes the template's bytes to the connection itself and parses the response with
// net/http's own reader. It is the only path on which HeaderOrderIsGuaranteed is true.
//
// The caller MUST close the response body: that is what closes the socket.
func SendOrdered(ctx context.Context, t RequestTemplate) (*http.Response, error) {
	wire, err := SerializeOrdered(t)
	if err != nil {
		return nil, err
	}
	prefix, _, _, ok := triageSplitWireURL(t.URL)
	if !ok {
		return nil, fmt.Errorf("triage: cannot dial for %q: %w", t.URL, errTriageURLNotAbsolute)
	}
	scheme, authority, err := triageSchemeAuthority(prefix)
	if err != nil {
		return nil, err
	}
	hostPort, serverName := triageDialTarget(scheme, authority)

	d := net.Dialer{Timeout: triageOrderedDialTimeout}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return nil, fmt.Errorf("triage: ordered dial %s: %w", hostPort, err)
	}
	if deadline, has := ctx.Deadline(); has {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(triageOrderedIOTimeout))
	}
	if scheme == "https" {
		// Verification is off for the same reason it is off everywhere else in this codebase:
		// a self-signed or expired certificate on an internal host is a host to probe, not a
		// host to skip. Skipping it would record the class clean on a target never reached.
		tc := tls.Client(conn, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("triage: ordered TLS handshake with %s: %w", hostPort, err)
		}
		conn = tc
	}
	if _, err := conn.Write(wire); err != nil {
		conn.Close()
		return nil, fmt.Errorf("triage: ordered write to %s: %w", hostPort, err)
	}

	method := t.Method
	if method == "" {
		method = http.MethodGet
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: strings.ToUpper(method)})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("triage: ordered read from %s: %w", hostPort, err)
	}
	resp.Body = triageOrderedBody{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

const (
	triageOrderedDialTimeout = 15 * time.Second
	triageOrderedIOTimeout   = 60 * time.Second
)

// triageClientOnce guards the shared client. One client, so connections are pooled across
// probes, and one place where the transport settings that would otherwise change a comparison
// are pinned.
var (
	triageClientOnce sync.Once
	triageClient     *http.Client
)

// TriageClient is the client every triage probe that does not need header order goes through.
//
// DisableCompression is the point of it. Without it the transport adds Accept-Encoding: gzip to
// any request that does not already carry one, and then transparently decompresses the response,
// so the probe sent a header its class never wrote and the body it compared came back through a
// codec that can change independently of the payload. With it, a request carries an
// Accept-Encoding only when the template declares one, and then that exact value is sent once.
//
// Redirects are NOT followed. Following one replaces the response the probe was measuring with
// the response of a different URL, under the same observation, which is a different class of the
// same mistake: a verdict recorded against bytes the probe never addressed.
func TriageClient() *http.Client {
	triageClientOnce.Do(func() {
		triageClient = &http.Client{
			Transport: &http.Transport{
				Proxy:              http.ProxyFromEnvironment,
				DisableCompression: true,
				TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	})
	return triageClient
}

// Send puts a template on the wire down whichever path it declares and returns the response. It
// is the sanctioned way to send a triage request, and the caller must close the response body.
//
// A template that declares RequireHeaderOrder is NEVER quietly downgraded onto the net/http
// path. If the ordered writer cannot speak to that URL the call returns an error, and an error
// is an observation that did not happen, which the caller records as cannot_determine. A
// downgrade would instead produce a real response with the headers in the wrong order, and the
// class would record a verdict against a request it did not ask for.
func Send(ctx context.Context, t RequestTemplate) (*http.Response, error) {
	if t.RequireHeaderOrder {
		return SendOrdered(ctx, t)
	}
	req, err := t.NewRequest(ctx)
	if err != nil {
		return nil, err
	}
	return TriageClient().Do(req)
}

// Send sends a delivered encode. An undeliverable one is refused here as it is in NewRequest,
// because the one thing that must never happen is the unperturbed request going out and being
// recorded as a probe.
func (e Encoded) Send(ctx context.Context) (*http.Response, error) {
	if !e.Delivered {
		return nil, fmt.Errorf("triage: refusing to send an undeliverable encode (%s: %s)", e.Reason, e.Detail)
	}
	return Send(ctx, e.Req)
}

// ---------------------------------------------------------------------------------------------
// 12. SHARED HELPERS
// ---------------------------------------------------------------------------------------------

const triageHexUpper = "0123456789ABCDEF"

func triageIsUnreserved(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	case c == '-', c == '_', c == '.', c == '~':
		return true
	}
	return false
}

func triageQueryUnreserved(c byte) bool { return triageIsUnreserved(c) }

// triageEscapeBytes percent-encodes every byte the allow predicate rejects, except the bytes listed
// in raw, which are written through untouched. It walks BYTES, not runes: a multibyte character
// becomes one percent triplet per byte, which is what RFC 3986 asks for and what keeps an
// overlong-UTF-8 payload from being normalised on the way out.
func triageEscapeBytes(b []byte, allow func(byte) bool, raw ...byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if allow(c) || triageContainsByte(raw, c) {
			out = append(out, c)
			continue
		}
		out = append(out, '%', triageHexUpper[c>>4], triageHexUpper[c&0x0f])
	}
	return out
}

func triageFirstByteNeedingEscape(b []byte, allow func(byte) bool) int {
	for i, c := range b {
		if !allow(c) {
			return i
		}
	}
	return -1
}

func triageContainsByte(set []byte, c byte) bool {
	for _, s := range set {
		if s == c {
			return true
		}
	}
	return false
}

// triageSplitWireURL takes the URL apart by hand rather than through url.Parse and url.String.
// Round-tripping through net/url re-escapes the path whenever the captured bytes are not what Go
// would have written, which changes the request-target of a probe relative to its own baseline.
func triageSplitWireURL(raw string) (prefix, path, query string, ok bool) {
	i := strings.Index(raw, "://")
	if i < 0 {
		return "", "", "", false
	}
	rest := raw[i+3:]
	auth := rest
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		auth, rest = rest[:j], rest[j:]
	} else {
		rest = ""
	}
	if auth == "" {
		return "", "", "", false
	}
	prefix = raw[:i+3] + auth
	// The fragment is dropped here and not carried anywhere, because it is never transmitted. A
	// fragment kept in the template would show up in a stored wire URL that no server ever saw.
	if k := strings.Index(rest, "#"); k >= 0 {
		rest = rest[:k]
	}
	if k := strings.Index(rest, "?"); k >= 0 {
		path, query = rest[:k], rest[k+1:]
	} else {
		path = rest
	}
	if path == "" {
		path = "/"
	}
	return prefix, path, query, true
}

func triageJoinWireURL(prefix, path, query string) string {
	if query == "" {
		return prefix + path
	}
	return prefix + path + "?" + query
}

// triageDelivered records a delivered encode.
//
// Container is READ BACK OUT OF THE SERIALIZED REQUEST rather than taken from the encoder's own
// rendering, which is what makes PayloadWire.Container mean what it says it means: a byte net/http
// drops or rewrites after the encoder hands off is visible here and nowhere else. rendered is the
// encoder's claim and is kept only as the fallback for a request that cannot be serialized at all,
// where the honest answer is unknown.
func triageDelivered(s triage.Slot, mode triage.EncoderMode, logical, wire, rendered []byte, containerName string, out RequestTemplate, detail string) Encoded {
	e := Encoded{
		Wire: triage.PayloadWire{
			Logical:        append([]byte(nil), logical...),
			Wire:           append([]byte(nil), wire...),
			ContainerName:  containerName,
			EncoderChain:   []triage.EncoderMode{mode},
			EncoderVersion: TriageEncoderVersion,
		},
		Delivered: true,
		Detail:    detail,
		Req:       out,
	}

	raw, err := triageSerializeOnWire(out)
	if err != nil {
		// NOT KNOWING IS NOT CLEAN. The encoder's rendering is kept so the row is not empty, but
		// survival stays unknown because nothing has confirmed these bytes would go out.
		e.Wire.Container = append([]byte(nil), rendered...)
		e.Wire.Survived = triage.WireSurvivalUnknown
		e.Wire.AlteredBy = "the request could not be serialized, so the bytes the transport would write are unknown: " + err.Error()
		return e
	}
	onWire, ok := triageContainerOnWire(raw, containerName)
	if !ok {
		e.Wire.Survived = triage.WireSurvivalDropped
		e.Wire.AlteredBy = "net/http serialized no " + containerName + " at all, so the container the encoder rendered never reaches the socket"
		return e
	}
	e.Wire.Container = onWire

	survived, why := CheckFidelity(e.Wire)
	e.Wire.Survived = survived
	if why != "" && e.Wire.AlteredBy == "" {
		e.Wire.AlteredBy = why
	}
	_ = s
	return e
}

func triageRefuse(s triage.Slot, mode triage.EncoderMode, logical []byte, reason DeliveryReason, detail string) Encoded {
	return Encoded{
		Wire: triage.PayloadWire{
			Logical:        append([]byte(nil), logical...),
			EncoderChain:   []triage.EncoderMode{mode},
			EncoderVersion: TriageEncoderVersion,
			Survived:       triage.WireSurvivalRefused,
			AlteredBy:      string(reason) + ": " + detail,
		},
		Delivered: false,
		Reason:    reason,
		Detail:    fmt.Sprintf("slot %s (%s): %s", s.Key, s.Kind, detail),
	}
}

// triageSHA256 keeps the hashing of a request body in one place, so the Observation fields that
// are [32]byte get filled the same way everywhere.
func triageSHA256(b []byte) [32]byte { return sha256.Sum256(b) }

// NOTE FOR THE SKELETON OWNER, NOT A CHANGE I MADE.
//
// triageSlots.go still declares the stub
//
//	func EncodeSlot(s Slot, mode EncoderMode, logical []byte) (PayloadWire, error)
//
// and it cannot be implemented as written: with no request to render into there is no container,
// and without a container there is nothing for CheckFidelity to read, so the returned PayloadWire
// could only ever carry Survived unknown. EncodeSlotInto here is the same function with the
// template added. The stub should be deleted, or reduced to a call into EncodeSlotInto with an
// empty template that always returns ErrTriageNotImplemented, in the file that owns it.
