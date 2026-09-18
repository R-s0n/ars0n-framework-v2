package triageclasses

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// REFLECTED XSS (triage.ClassXSSReflected, id 9, CATALOGUE 1.9 and iso-client class A).
//
// =================================================================================================
// THE QUESTION THIS CLASS ANSWERS IS NOT "DID THE MARKER COME BACK".
// It is "did the characters that matter IN THIS CONTEXT come back usable, and can a parser prove
// it". The oracle is a PARSE-TREE STATE CHANGE: an element or an attribute NAMED by this run's
// marker. Reflection alone is not a finding, and this repository already ships a probe that
// reports reflection (server/utils/reflectionProbe.go). That probe answers a different question
// and this class reuses not one byte of it: its canary is rs0nR/rs0nE with the four characters
// <>"' appended, and every payload here is built from this class's own marker template and its
// own per-probe tail. See "PAYLOAD ISOLATION" below.
// =================================================================================================
//
// THE FIVE RULES, defined once, cited by every verdict.
//
//	RX-D1  element creation.   A start tag whose LOWERED NAME EQUALS the marker.
//	RX-D2  attribute creation. An attribute whose NAME EQUALS the marker, on any element.
//	RX-D3  JS lexer transition. An occurrence the census placed in a JS string or template text
//	                            now lexes as code or as a template substitution, inside a script
//	                            whose type is executable.
//	RX-D4  URL scheme.         A URL-bearing attribute whose value, after HTML entity decoding,
//	                            begins with the javascript scheme AND contains the marker.
//	RX-D5  character survival. SECONDARY ONLY, ceiling suspicious. The bytes the context needs
//	                            came back raw and nothing parsed. It explains a near miss and
//	                            chooses the next probe. It is never a finding on its own, because
//	                            "the < came back" is reflection, not injection.
//
// WHY A TAG NAME AND NOT alert(1). The marker's first byte is a letter by construction
// (foundations 2.3), so <marker> is a conforming start tag: the tokenizer names it, the browser
// builds an inert HTMLUnknownElement, nothing executes, nothing renders, and there is no WAF
// signature to trip. It proves the only thing that matters (the application let me open a tag)
// with zero side effect. The triage layer never sends alert(1), for any class.
//
// THE ENCODING LADDER, AND THE WAY ROUND IT GOES. Entities are decoded in exactly five tokenizer
// states: data, RCDATA, and the three attribute value states. SCRIPT DATA HAS NO CHARACTER
// REFERENCE CLAUSE AT ALL. So:
//
//	an entity-encoded quote inside a JS string in an EVENT HANDLER attribute is EXECUTABLE
//	   (the value is entity-decoded and the RESULT is handed to the JS parser: this is the
//	    PortSwigger &apos;-alert(document.domain)-&apos; lab), and
//	the same entity-encoded quote inside a JS string in a <script> block is INERT
//	   (six literal characters sitting harmlessly inside the string).
//
// Getting that backwards produces both error types at once: a false positive on every
// entity-encoded <script> reflection and a false negative on the event-handler case. RX-5b and
// RX-5d exist for the executable half; RX-NC3 asserts the inert half at run time and is the most
// important control in the family.
//
// TWO TOKENIZER FACTS THIS CLASS DEPENDS ON, both measured against the WHATWG tokenizer and both
// contradicting the usual folklore.
//
//  1. ATTR_UNQUOTED HAS TWO TERMINATORS, NOT SEVEN. In the attribute value (unquoted) state the
//     characters " ' < = and backtick raise unexpected-character-in-unquoted-attribute-value and
//     are then APPENDED to the value. Only ASCII whitespace (TAB LF FF SPACE) leaves the state and
//     only > closes the tag. A SLASH DOES NOTHING: <div a=b/> yields attribute a with value "b/".
//     A probe built on the slash reports clean on an exploitable unquoted attribute, so RX-4 is
//     built on a SPACE. The tokenizer in this file implements the two-terminator rule, not the
//     authoring-conformance rule foundations 4.2 quotes.
//  2. WITH SCRIPTING ENABLED, <noscript> IS RAWTEXT. A tokenizer configured with scripting off
//     parses <noscript><marker></noscript> into a real element and reports a finding on an
//     application that is not vulnerable. xssrTokenize treats noscript as raw text for exactly
//     this reason, and /xss/noscript is the oracle route that proves it.
//
// PAYLOAD ISOLATION, AND A DELIBERATE DIVERGENCE FROM THE CATALOGUE'S LITERAL BYTES.
//
// The isolation law compares payloads AFTER triage.NormaliseMarkers has replaced every
// marker-shaped run with a placeholder, and that is right: two probes differing only in a minted
// marker are the same payload. But it means the catalogue's own tables collide. CATALOGUE 1.9's
// RX-1 is M<M>, 1.12's SX-1text is M<M> with class 12's marker, and 1.10's CS-0q is M" M="1 with
// class 10's; normalise the markers away and those pairs are byte-equal, which is exactly what
// IsoDuplicatePayload refuses. The bare-marker census probes are worse: SSTI-S0, RX-0r, SX-0r and
// CRLF's NC1 are all one marker and nothing else, so ten classes would ship one payload.
//
// So every payload in this class carries a PER-PROBE TAIL: the probe's own id, written as -rx1,
// -rx8a, -rxnc3 and so on, in a position that is inert for the context it is aimed at. The tail
// is four to six bytes of unreserved ASCII, so it is legal raw in every insertion point including
// cookie-octet and a path segment, it changes no payload's mechanism, and it makes every one of
// these payloads byte-distinct from every other class's after marker normalisation. It also names
// the probe in the response when the marker itself came back transformed.
//
// Two payloads put the tail somewhere other than the end, and the reason is mechanical: RX-8b's
// trailing backslash must remain the LAST byte or it escapes the tail instead of the page's own
// closing quote, and RX-15's trailing /* must remain last or the tail is swallowed by the comment
// it opens.
//
// THE MARKER TEMPLATE, AND THE GUARD THAT MAKES IT SAFE. A ProbeSpec's Logical bytes are declared
// at build time and the marker is minted per probe at run time, so a payload that needs its
// marker in two places (once at offset 0 so truncation stays attributable, once as the element or
// attribute name so the oracle is a parse-tree fact) cannot write the real marker. It writes
// xssrTemplateMarker, which is marker-shaped, carries this class's ordinal stripe so
// CheckPayloadIsolation's I1d-plain accepts it, and is what triage.NormaliseMarkers finds. The
// runner substitutes the minted marker for every occurrence of it.
//
// IF THE RUNNER DOES NOT SUBSTITUTE, THIS CLASS MUST NOT REPORT CLEAN, and that is not left to
// trust: xssrTemplateSurvived re-reads the payload the runner actually recorded and, if a
// marker-shaped token that is not this probe's marker is still sitting in it, every verdict on the
// slot becomes cannot_determine (runner_bug). A template that shipped unsubstituted would put a
// marker nobody minted on the wire, find nothing, and record a green tick on an untested slot.
// That is the bug this whole layer exists to stop, so it gets a detector rather than a comment.
type xssReflectedClassifier struct{}

func init() { triage.RegisterClassifier(xssReflectedClassifier{}) }

func (xssReflectedClassifier) ID() triage.ClassID { return triage.ClassXSSReflected }

// xssrTemplateMarker is the build-time stand-in for this probe's minted marker.
//
// It is a real marker layout: anchor zqj, run id 0000, ordinal 000009, checksum 04j recomputed
// with the same CRC-32 the minter uses. Ordinal 9 mod 64 is 9, which is this class's stripe, so
// the I1d-plain check reads it as ours rather than as a foreign marker smuggled into a payload.
// The run id is all zeroes so that a template which ever reaches the wire is recognisable as one:
// a marker whose run id is not this run's is already cannot_determine (stale_marker) everywhere
// else in the layer.
const xssrTemplateMarker = "zqj000000000904j"

// xssrTemplateShortMarker is the FN-A3 narrow-field form: anchor plus the six ordinal digits, nine
// bytes, still unique within a run. A field that truncates below the marker's end reads as "the
// marker did not come back", which reads as clean, on an application that is reflecting perfectly
// well. RX-SM is the probe that stops that, and Variant["marker_form"]="short" is how it asks the
// runner for the short rendering.
const xssrTemplateShortMarker = "zqj000009"

// xssrM is the template marker, spelled short so a payload row below reads like its catalogue row.
const xssrM = xssrTemplateMarker

// The Variant keys. Variant is the declared per-instance extension point, and these are the four
// things this class must ask the runner for that ProbeSpec has no field for.
//
// THEY ARE NOT DECORATION. RX-0a is the integer-cast detector and the shape-validating-field
// detector at once: an endpoint that discards a replaced value, or 400s on a bare marker, answers
// "no reflection" to RX-0r and reflects RX-0a perfectly. Planning only the replace form records
// that endpoint as clean.
const (
	xssrVariantCompose      = "compose"
	xssrComposeReplace      = "replace"
	xssrComposeAppend       = "append_to_observed"
	xssrComposePrefix       = "prefix_observed"
	xssrVariantMarkerForm   = "marker_form"
	xssrMarkerFormShort     = "short"
	xssrVariantAcceptHeader = "accept"
	xssrAcceptHTML          = "text/html,application/xhtml+xml,*/*;q=0.8"
	xssrVariantScope        = "scope"
	xssrScopeVector         = "vector"
	xssrVariantPlacement    = "placement_context"
)

// The probe ids. They are constants because Plan names them, Classify groups by them and the skip
// list has to name the ones that were not sent; three copies of a string literal is how a renamed
// probe silently stops being planned while still being reported as untested.
const (
	xssrP0r  triage.ProbeID = "RX-0r"
	xssrP0a  triage.ProbeID = "RX-0a"
	xssrP0h  triage.ProbeID = "RX-0h"
	xssrPDec triage.ProbeID = "RX-DEC"
	xssrP1   triage.ProbeID = "RX-1"
	xssrP1c  triage.ProbeID = "RX-1c"
	xssrP1s  triage.ProbeID = "RX-1s"
	xssrP1t  triage.ProbeID = "RX-1t"
	xssrP2   triage.ProbeID = "RX-2"
	xssrP3   triage.ProbeID = "RX-3"
	xssrP4   triage.ProbeID = "RX-4"
	xssrP5a  triage.ProbeID = "RX-5a"
	xssrP5b  triage.ProbeID = "RX-5b"
	xssrP5c  triage.ProbeID = "RX-5c"
	xssrP5d  triage.ProbeID = "RX-5d"
	xssrP6a  triage.ProbeID = "RX-6a"
	xssrP6b  triage.ProbeID = "RX-6b"
	xssrP6c  triage.ProbeID = "RX-6c"
	xssrP7   triage.ProbeID = "RX-7"
	xssrP8a  triage.ProbeID = "RX-8a"
	xssrP8b  triage.ProbeID = "RX-8b"
	xssrP9a  triage.ProbeID = "RX-9a"
	xssrP10a triage.ProbeID = "RX-10a"
	xssrP10b triage.ProbeID = "RX-10b"
	xssrP11a triage.ProbeID = "RX-11a"
	xssrP11b triage.ProbeID = "RX-11b"
	xssrP12  triage.ProbeID = "RX-12"
	xssrP12t triage.ProbeID = "RX-12t"
	xssrP13  triage.ProbeID = "RX-13"
	xssrP14  triage.ProbeID = "RX-14"
	xssrP15  triage.ProbeID = "RX-15"
	xssrP16  triage.ProbeID = "RX-16"
	xssrPSM  triage.ProbeID = "RX-SM"
	xssrPNC2 triage.ProbeID = "RX-NC2"
	xssrPNC3 triage.ProbeID = "RX-NC3"
)

// Probes is the whole payload set. One row per catalogue row, same ids, same mechanisms, with the
// per-probe tail described in the header.
//
// RX-NC1 is deliberately NOT here. The catalogue charges it zero requests because it IS RX-0r: the
// bare marker must fire none of RX-D1 to RX-D4, and that is a rule applied to a response this
// class already holds, not a second request. It is enforced in xssrControlFired.
func (xssReflectedClassifier) Probes() []triage.ProbeSpec {
	all := []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie, triage.KindPath}
	// noCookie drops the one point where a raw double quote or a raw space cannot be delivered at
	// all. A JSON string body is NOT dropped here: that is a per-slot not_reachable(json_string),
	// decided in Plan from the slot's own media type, because the same KindBody carries form and
	// multipart slots where a raw quote travels perfectly well.
	noCookie := []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindPath}
	enc := []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
		triage.EncodeMultipartValue, triage.EncodeHeaderValue, triage.EncodeCookie,
		triage.EncodePathSegment,
	}
	encNoCookie := []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
		triage.EncodeMultipartValue, triage.EncodeHeaderValue, triage.EncodePathSegment,
	}

	p := func(id triage.ProbeID, logical string, points []triage.SlotKind, encoders []triage.EncoderMode, tier triage.ProbeTier, note string) triage.ProbeSpec {
		return triage.ProbeSpec{
			ID: id, Class: triage.ClassXSSReflected, Logical: []byte(logical),
			Encoders: encoders, Points: points, MarkerPos: triage.MarkerPrefix,
			Tier: tier, Risk: triage.RiskR1, Notes: note,
		}
	}

	dq := string('"')
	bt := string('`')
	bs := string('\\')

	out := []triage.ProbeSpec{
		p(xssrP0r, xssrM+"-rx0r", all, enc, triage.TierReduced,
			"the census, replace form. No metacharacter: it measures WHERE the value lands, and every "+
				"placement it returns promotes exactly its own context payload. It is also NC-A1: if any of "+
				"RX-D1 to RX-D4 fires on THIS response the detector is matching text and is broken"),
		p(xssrP0a, xssrM+"-rx0a", all, enc, triage.TierReduced,
			"the census, append form, Variant compose=append_to_observed. Catches the integer-cast "+
				"endpoint that discards a replaced value and the shape-validating field that 400s on a bare "+
				"marker. Sent ALWAYS alongside RX-0r, never as a fallback"),
		p(xssrP0h, xssrM+"-rx0h", all, enc, triage.TierFull,
			"FN-A1: the app echoes only when Accept asks for HTML and the capture asked for JSON. One per "+
				"VECTOR, not per slot; Variant scope=vector so the runner can dedupe"),
		p(xssrPDec, xssrM+"-rxdec",
			[]triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie},
			[]triage.EncoderMode{triage.EncodePctTwice}, triage.TierFull,
			"THIS CLASS'S OWN decode control, ruling R6: the shared perturbed gate is abolished because one "+
				"bad measurement suppressed probes in twelve classes at once. Sent percent-encoded one layer "+
				"deeper than the slot needs, so the marker appears in the response only if the application "+
				"decoded it. decode_depth >= 1 is precondition 2 of this class's clean"),

		p(xssrP1, xssrM+"<"+xssrM+">-rx1", all, enc, triage.TierFull,
			"HTML_TEXT, SVG_TEXT, MATHML_TEXT and UNRESOLVED. RX-D1"),
		p(xssrP1c, xssrM+"<"+xssrM+"/-rx1c", all, enc, triage.TierFull,
			"the > filtered case. It carries no > of its own: the page's next > closes the tag, the bytes "+
				"between become attribute names, and the element still forms. Confirmation for an RX-D5 near miss"),
		p(xssrP1s, xssrM+"<b>"+xssrM+"</b>-rx1s", all, enc, triage.TierFull,
			"FN-A6, the allowlist sanitizer. <b> is on every allowlist. If <b> survives as an element while "+
				"the marker element did not, the verdict is suspicious (sanitizer_allowlist) pointing at "+
				"domdig, because what is left is mutation XSS and that is browser-only. NEVER clean"),
		p(xssrP1t, xssrM+"<"+xssrM+">-rx1t", all, enc, triage.TierFull,
			"A.3 case 2: the element formed inside template, noscript, iframe or a script island. Same "+
				"mechanism as RX-1 with Variant compose=prefix_observed, which on a templated page frequently "+
				"moves the reflection out of the inert container"),

		p(xssrP2, xssrM+dq+" "+xssrM+"="+dq+"rx2", noCookie, encNoCookie, triage.TierFull,
			"ATTR_DOUBLE. RX-D2. The marker appears twice on purpose: at offset 0 so a truncation stays "+
				"attributable, and as the attribute NAME so the oracle is a parse-tree fact rather than a "+
				"substring. An attribute whose VALUE contains the marker is not a hit, and that is the whole "+
				"discrimination"),
		p(xssrP3, xssrM+"' "+xssrM+"='rx3", all, enc, triage.TierFull,
			"ATTR_SINGLE. RX-D2. The single quote is cookie-octet and needs no decoding, which makes this "+
				"the attribute probe that survives a cookie slot"),
		p(xssrP4, xssrM+" "+xssrM+"=rx4", noCookie, encNoCookie, triage.TierFull,
			"ATTR_UNQUOTED, HTML_ATTR_NAME, HTML_TAG_NAME. Built on a SPACE and not on a slash: in the "+
				"unquoted value state a slash is appended to the value and terminates nothing, so a "+
				"slash-based probe reports clean on an exploitable unquoted attribute"),

		p(xssrP5a, xssrM+"'-"+xssrM+"-'-rx5a", all, enc, triage.TierFull,
			"EVENT_HANDLER delimited by a single quote. It leaves valid JavaScript: string, minus, "+
				"identifier, minus, string. The page keeps working and only the parser sees the probe"),
		p(xssrP5b, xssrM+"&#39;-"+xssrM+"-&#39;-rx5b", all, enc, triage.TierFull,
			"FN-A12 and the highest-value single probe in this class. An event handler attribute is "+
				"entity-decoded BEFORE its value reaches the JS parser, so the &#39; becomes a real quote and "+
				"the most common 'we HTML-escape everything' configuration is exploitable here and nowhere "+
				"else in the ladder"),
		p(xssrP5c, xssrM+dq+"-"+xssrM+"-"+dq+"-rx5c", noCookie, encNoCookie, triage.TierFull,
			"EVENT_HANDLER delimited by a double quote. It needs a raw double quote, so it is "+
				"not_reachable(json_string) in a JSON string slot and cookie-illegal"),
		p(xssrP5d, xssrM+"&#34;-"+xssrM+"-&#34;-rx5d", all, enc, triage.TierFull,
			"EVENT_HANDLER, double quote, entity rung. &#34; is entity TEXT and not a raw quote, so this is "+
				"the only double-quote rung that reaches a JSON string slot"),

		p(xssrP6a, "javascript:"+xssrM+"-rx6a", all, enc, triage.TierFull,
			"URL_ATTR_SCHEME. RX-D4 needs the scheme at value offset 0; javascript: anywhere else in the "+
				"value belongs to the open redirect class and is not a hit here"),
		p(xssrP6b, "&#106;avascript:"+xssrM+"-rx6b", all, enc, triage.TierFull,
			"the entity scheme rung. The attribute value is entity-decoded and THEN handed to the URL "+
				"parser, so &#106; resolves. Percent encoding does NOT: %6a is never decoded before scheme "+
				"resolution. Two transforms behaving oppositely on the same byte in the same slot is why a "+
				"single was-it-encoded boolean loses the answer"),
		p(xssrP6c, "java&#9;script:"+xssrM+"-rx6c", all, enc, triage.TierFull,
			"the embedded control rung: after entity decoding the URL parser strips leading and embedded C0 "+
				"and whitespace, so a tab inside the scheme still resolves"),

		p(xssrP7, xssrM+"</script><"+xssrM+">-rx7", all, enc, triage.TierFull,
			"SCRIPT_DATA, any script type. </script is the ONLY exit from script data: that state has no "+
				"character reference clause, so no entity form of it can ever work"),
		p(xssrP8a, xssrM+"'-"+xssrM+"-'-rx8a", all, enc, triage.TierFull,
			"JS_STRING_SINGLE inside a <script>. The same shape as RX-5a in a different context, and a "+
				"different probe because the encoding ladder answers the two contexts OPPOSITELY: the entity "+
				"rung works in the handler and is inert here"),
		p(xssrP8b, xssrM+"-rx8b"+bs, all, enc, triage.TierFull,
			"the backslash rung, FN-A11, merged for both quote kinds by ruling R5. The backslash MUST be the "+
				"last byte: it escapes the page's own closing quote, and the sub-rule is that the string "+
				"literal is then unterminated at end of script. An app that escapes quotes and not "+
				"backslashes is a two-step breakout"),
		p(xssrP9a, xssrM+dq+"-"+xssrM+"-"+dq+"-rx9a", noCookie, encNoCookie, triage.TierFull,
			"JS_STRING_DOUBLE. A raw double quote, so not_reachable(json_string) and cookie-illegal"),
		p(xssrP10a, xssrM+"${"+xssrM+"}-rx10a", all, enc, triage.TierFull,
			"JS_TEMPLATE_TEXT. The hit is a template SUBSTITUTION, which is a lexer state change and not a "+
				"rendered value. It shares the two bytes ${ with CSTI's CS-1d and nothing else: different "+
				"marker, different stripe, different eligibility, different rule, different verdict. Two "+
				"classes independently arriving at the same grammar is not sharing"),
		p(xssrP10b, xssrM+bt+"-"+xssrM+"-"+bt+"-rx10b", all, enc, triage.TierFull,
			"the backtick rung of the template context"),

		p(xssrP11a, xssrM+"--><"+xssrM+">-rx11a", all, enc, triage.TierFull,
			"HTML_COMMENT. Comment text may not contain the exit sequence, so the exit sequence is exactly "+
				"what a filter restricts, which is why the bang variant ships beside it"),
		p(xssrP11b, xssrM+"--!><"+xssrM+">-rx11b", all, enc, triage.TierFull,
			"HTML_COMMENT for filters that block the ordinary terminator: --!> also ends a comment"),
		p(xssrP12, xssrM+"</textarea><"+xssrM+">-rx12", all, enc, triage.TierFull,
			"HTML_RCDATA in textarea. RCDATA decodes entities but only a MATCHING end tag leaves the state, "+
				"so no entity form substitutes for the literal end tag"),
		p(xssrP12t, xssrM+"</title><"+xssrM+">-rx12t", all, enc, triage.TierFull,
			"HTML_RCDATA in title, the same mechanism with the other RCDATA element"),
		p(xssrP13, xssrM+"</style><"+xssrM+">-rx13", all, enc, triage.TierFull,
			"CSS_BLOCK. style is RAWTEXT and </style is its only exit"),
		p(xssrP14, xssrM+"\n"+xssrM+"-rx14",
			[]triage.SlotKind{triage.KindBody, triage.KindQuery},
			[]triage.EncoderMode{triage.EncodeJSONString, triage.EncodeForm, triage.EncodeMultipartValue, triage.EncodeQuery},
			triage.TierFull,
			"JS_LINE_COMMENT. A line feed is the only exit from a line comment, which makes this probe "+
				"not_reachable(header_crlf) in a header and not_reachable(path_ctl) in a path segment. Those "+
				"are first-class answers and neither is a clean row"),
		p(xssrP15, xssrM+"*/"+xssrM+"-rx15/*", all, enc, triage.TierFull,
			"JS_BLOCK_COMMENT. The trailing /* must stay last: it reopens the comment the page will close, "+
				"which keeps the script parsing, and it would swallow the tail if the tail followed it"),
		p(xssrP16, xssrM+"<"+xssrM+">-rx16", all, enc, triage.TierFull,
			"FN-A10, JSON_STRING_VALUE on a sniffable type. The same shape as RX-1 and its own probe because "+
				"its HIT CARRIES A MEDIA-TYPE GATE: RX-D1 plus (text/html or empty, or sniffable with no "+
				"X-Content-Type-Options). A JSON body that renders on direct navigation is a commonly missed "+
				"real finding and it costs one request"),

		p(xssrPSM, "<"+xssrTemplateShortMarker+">", all, enc, triage.TierFull,
			"FN-A3, the narrow field. Variant marker_form=short asks for anchor plus ordinal, nine bytes, "+
				"still unique within the run. Without this rule every field with FieldLimit below 20 reads as "+
				"clean because the marker was cut in half. It carries no tail: a payload for a field that "+
				"truncates at 20 bytes cannot afford four more"),

		p(xssrPNC2, xssrM+"x"+xssrM+"y-rxnc2", all, enc, triage.TierFull,
			"NC-A2. The letters x and y sit where < and > would: the same length class with no "+
				"metacharacter. No element, no attribute and no lexer transition may be reported from this "+
				"response"),
		p(xssrPNC3, xssrM+"&lt;"+xssrM+"&gt;-rxnc3", all, enc, triage.TierFull,
			"NC-A3, THE MOST IMPORTANT CONTROL IN THE FAMILY. A character reference decodes to a CHARACTER "+
				"TOKEN and can never produce a tag, so RX-D1 must not fire on this response. It asserts at "+
				"run time the correction the whole encoding ladder rests on, and a detector that fires here "+
				"has been matching text all along"),
	}
	for i := range out {
		if out[i].ID == xssrPNC2 || out[i].ID == xssrPNC3 {
			out[i].IsControl = true
		}
		if out[i].ID == xssrP0a {
			// The append form's marker sits after the observed value, so a field limit shorter
			// than the marker's END offset truncates it. Suffix is the honest declaration and it
			// is what makes truncated distinguishable from absent (foundations 2.4).
			out[i].MarkerPos = triage.MarkerSuffix
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches is the eligibility matrix row for this class, and it consults nothing but the slot kind
// and the request media type, because that is all Reaches is given and all it should need.
//
// EVERY NON-ALWAYS ANSWER CARRIES A REASON. A ReachNever with no reason produces a slot with no
// verdict row and no explanation, and an operator cannot tell "ruled out" from "nobody wired this
// up": those are the same pixel and completely different facts.
func (xssReflectedClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindHeader:
		// Every printable ASCII including " ' < > ; = is raw-legal in a field value, so the whole
		// ladder except RX-14 reaches a header. Referer, X-Forwarded-Host and Origin landing in an
		// <a href> or a <link rel=canonical> is the common real case, and the inferred header slots
		// are what reach it.
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a form, multipart or XML body carries the whole ladder raw; a JSON STRING slot cannot carry a raw " +
				"double quote, so RX-2, RX-5c and RX-9a are not_reachable(json_string) there, which is a " +
				"first-class answer and not a clean; a JSON container node is not this class's target at all " +
				"and a number or boolean slot takes the census probe in both encodings only",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "single quote, < , > , = and / are all cookie-octet and travel raw, but a raw double quote and a " +
				"raw SPACE are not, so RX-2, RX-4, RX-5c and RX-9a depend on the application percent-decoding " +
				"its own cookie: at decode_depth 0 they are not_reachable(cookie_octet), never clean",
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "< > and the double quote must be percent-encoded and the semicolon must be %3B or a Servlet " +
				"container truncates the segment, so the whole ladder is gated on this class's own pct control; " +
				"RX-14's line feed is not_reachable(path_ctl)",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the fragment is dereferenced by the client and never transmitted (RFC 3986 section 3.5), and a " +
				"reflected-XSS verdict is a statement about what the SERVER echoed. Fragment slots belong to " +
				"XSS-DOM, which runs its own probes in a browser",
		}
	default:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: fmt.Sprintf("slot kind %q is not in this class's matrix row and this class will not guess at an "+
				"insertion point nobody measured, media type %q", k, mt),
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

// xssrEligibility is the answer to "may this class send anything to this slot at all", with the
// verdict it produces when the answer is no. It is computed by one function so that Plan's refusal
// and Classify's verdict can never disagree: two copies of a predicate is how a slot gets skipped
// by one and reported as clean by the other.
type xssrEligibility struct {
	OK     bool
	State  triage.TriageState
	Reason string
	// Promote is a reason that does NOT stop the probes but promotes any clean this class would
	// otherwise emit into a cannot_determine. A canary resource and a signed wrapper both belong
	// here: the probes run and mean something if they fire, and their silence means nothing.
	Promote string
}

func xssrEligible(ctx triage.PlanCtx) xssrEligibility {
	s := ctx.Slot
	if s.Kind == triage.KindFragment || !s.ServerReachable {
		return xssrEligibility{State: triage.StateNotApplicable,
			Reason: "fragment: the client never transmits it, so the server cannot have echoed it. XSS-DOM owns this slot"}
	}
	if s.Constraints.IsCredential {
		return xssrEligibility{State: triage.StateNotProbed,
			Reason: "credential_slot: injecting into an authorization header or a session cookie produces a 401 that " +
				"looks exactly like a differential, so no class probes one. The slot is reported rather than " +
				"dropped so that deliberately skipped stays visibly different from does not exist"}
	}
	switch ctx.Prelude {
	case triage.PreludeTokenUnobtainable, triage.PreludeViewstateBound, triage.PreludeControlContaminated:
		return xssrEligibility{State: triage.StateCannotDetermine,
			Reason: "prelude_failed (" + string(ctx.Prelude) + "): every probe would fail validation identically, " +
				"which reads as a stable endpoint with no differential, which reads as clean"}
	case triage.PreludeUnknown:
		// Unknown on a read-only verb is common and harmless; unknown on a mutating verb is the
		// case PreludeState.Failed was written for, and it stops the class rather than producing a
		// slot's worth of identically-rejected probes.
		if xssrMutatingMethod(s.Method) || xssrMutatingMethod(ctx.Vector.Method) {
			return xssrEligibility{State: triage.StateNotRun,
				Reason: "prelude_unknown_on_mutating_vector: the prelude was never measured and the verb is not " +
					"idempotent, so a silent rejection could not be told from a silent application"}
		}
	}
	if !ctx.Route.Resolved() {
		return xssrEligibility{State: triage.StateCannotDetermine,
			Reason: "route_unresolved: the vector's own route control did not resolve, so nothing can be said about " +
				"what this slot echoes"}
	}
	return xssrEligibility{OK: true, Promote: xssrPromotion(s)}
}

// xssrPromotion is the reason a CLEAN on this slot must be promoted to an unknown even though
// every probe ran and every oracle stayed silent.
//
// Both cases probe normally and both mean the silence is worthless: a tool pointed at a resource
// that does not exist finding nothing is not a clean scan of the endpoint, and a payload that
// travelled inside a signature this class cannot recompute may never have arrived in the form it
// was written. They are a separate function from the refusals so that they can be read, and
// tested, without a resolved route control.
func xssrPromotion(s triage.Slot) string {
	if s.Wrapper == triage.WrapSigned {
		return "signed_wrapper: the value travels inside a signature this class cannot re-compute, so the payload " +
			"may never have reached the application in the form it was written"
	}
	if s.ValueOrigin == triage.ValueCanary {
		return "canary_resource: the probes ran against a fabricated identifier, so a tool pointed at a 404 finding " +
			"nothing is not a clean scan of the endpoint"
	}
	return ""
}

func xssrMutatingMethod(m string) bool {
	switch strings.ToUpper(strings.TrimSpace(m)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	}
	return false
}

// Plan is the ladder of CATALOGUE 2.1: census first, then exactly the payload each placement the
// census returned calls for, then the confirmation rung for the three weak cases.
//
// IT NEVER GATES ON ANOTHER CLASS AND IT NEVER GATES ON A SHAPE GUESS. There is no "does this
// parameter look reflective" test, no ValueKind gate and no baseline media type gate, because
// every such gate is a silent zero and this repository has removed several. RX-0 is the
// discriminator; the baseline media type only ORDERS the queue.
func (c xssReflectedClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if el := xssrEligible(ctx); !el.OK {
		return nil
	}
	if ctx.Budget.Exhausted() {
		return nil
	}
	return xssrPlanRounds(ctx)
}

// xssrPlanRounds is the ladder with the gates already passed.
//
// It is split out for the same reason xssrClassifyEligible is: one of the gates is that the
// vector's route control RESOLVED, and no test in this package can build a resolved
// triage.Replay, so a ladder that could only be called through the gate could only ever be tested
// returning nil.
func xssrPlanRounds(ctx triage.PlanCtx) []triage.ProbeRequest {
	sent := xssrSentProbes(ctx.Own)
	if len(sent) >= xssrPerSlotCap {
		// This class's OWN cap, separate from the run budget. A slot whose census lands in four
		// contexts can promote fourteen payloads, and a class that spends a whole run's budget on
		// one slot has starved every other slot of its census. The thirteenth probe is refused and
		// the contexts it would have answered are reported as untested, which is an unknown.
		return nil
	}
	var reqs []triage.ProbeRequest
	add := func(id triage.ProbeID, variant map[string]string) {
		if sent[id] {
			return
		}
		if !xssrProbeReachesSlot(id, ctx.Slot).OK {
			return
		}
		reqs = append(reqs, triage.ProbeRequest{Spec: id, Slot: ctx.Slot.Key, Variant: variant})
	}

	switch {
	case ctx.Round == 0:
		add(xssrP0r, map[string]string{xssrVariantCompose: xssrComposeReplace})
		add(xssrP0a, map[string]string{xssrVariantCompose: xssrComposeAppend})
		add(xssrPDec, map[string]string{xssrVariantCompose: xssrComposeReplace})
		if !xssrRendersInABrowser(ctx.Vector.RespMedia) {
			// FN-A1. One per vector, and the runner may dedupe on the scope variant; sending it
			// per slot would be wasteful, and not sending it at all loses every endpoint that
			// echoes only for an HTML Accept.
			add(xssrP0h, map[string]string{
				xssrVariantCompose:      xssrComposeReplace,
				xssrVariantAcceptHeader: xssrAcceptHTML,
				xssrVariantScope:        xssrScopeVector,
			})
		}
		if lim := ctx.Slot.Constraints.FieldLimit; lim > 0 && lim < 20 {
			add(xssrPSM, map[string]string{
				xssrVariantCompose:    xssrComposeReplace,
				xssrVariantMarkerForm: xssrMarkerFormShort,
			})
		}
	case ctx.Round == 1:
		obs := xssrCollect(triage.ClassXSSReflected, ctx.Own)
		if obs.ReadErr != nil {
			return nil
		}
		places := obs.CensusPlacements()
		if len(places) == 0 {
			return nil
		}
		// The two controls go out whenever the slot reflects at all. They cost two requests and
		// they are the only evidence that the detector can stay silent; a detector never shown
		// staying silent is exactly as unverified as one never shown firing.
		add(xssrPNC2, map[string]string{xssrVariantCompose: xssrComposeReplace})
		add(xssrPNC3, map[string]string{xssrVariantCompose: xssrComposeReplace})
		for _, pl := range places {
			for _, id := range xssrProbesForContext(pl.Context, ctx.Vector.RespMedia) {
				add(id, map[string]string{
					xssrVariantCompose:   xssrComposeReplace,
					xssrVariantPlacement: pl.Context,
				})
			}
		}
	case ctx.Round == 2:
		obs := xssrCollect(triage.ClassXSSReflected, ctx.Own)
		if obs.ReadErr != nil {
			return nil
		}
		for _, id := range obs.ConfirmationRungs() {
			v := map[string]string{xssrVariantCompose: xssrComposeReplace}
			if id == xssrP1t {
				v[xssrVariantCompose] = xssrComposePrefix
			}
			add(id, v)
		}
	}
	return reqs
}

// xssrPerSlotCap is the per-slot ceiling from CATALOGUE 2.1: twelve, and the thirteenth is
// refused rather than sent. It is enforced here and not left to the run budget because a budget
// that is generous enough for a corpus is generous enough for one slot to eat it.
const xssrPerSlotCap = 12

// xssrRendersInABrowser is the media type gate RX-D1 carries. An element in a body the browser
// will never render is not an XSS lead, and a body served as a download is not rendered at all.
func xssrRendersInABrowser(mt triage.MediaType) bool {
	switch triage.MediaType(strings.ToLower(strings.TrimSpace(string(mt)))) {
	case "", "text/html", "application/xhtml+xml", "image/svg+xml":
		return true
	}
	return false
}

// xssrSniffable names the types a browser may still render when nothing forbids sniffing. It is
// deliberately narrow: a bare text/plain document whose whole content is the reflected value is
// the one that matters for RX-16.
//
// THE JSON AND JAVASCRIPT FAMILIES USED TO BE IN HERE AND THEY DO NOT BELONG. See
// xssrStructuredNotMarkup for what that cost.
func xssrSniffable(mt triage.MediaType) bool {
	switch triage.MediaType(strings.ToLower(strings.TrimSpace(string(mt)))) {
	case "text/plain":
		return true
	}
	return false
}

// xssrStructuredNotMarkup names the response types that carry a value into a structured document
// no browser ever parses as markup on navigation.
//
// MEASURED, exam ef8c13ab: /clean/echomongo is a CLEAN CONTROL that answers Content-Type
// application/json with {"ok":false,"error":"could not parse filter","received":"<the value>"}.
// The HTML tokenizer was run over that JSON, found a start tag whose name was the marker, and the
// class returned finding/HIGH/element_created, which is the grade an operator works first. It got
// through because the media gate treated the JSON family as sniffable and the route sets no
// nosniff.
//
// Sniffing does not do what that assumed. A DECLARED application/json is never upgraded to
// text/html: mimesniff only sniffs the unknown-type bucket, and X-Content-Type-Options is what
// closes that bucket, not what creates it. So an element found inside a JSON or JavaScript
// document is not an XSS lead on its own. It becomes one only if page JavaScript writes the value
// into a DOM sink, which is XSS-DOM's question and needs a browser, and this class already has
// the vocabulary for exactly that: needs_dom_run. THE SAME ROUTE ALREADY EMITTED IT from its
// JSON-string placement, so the class contradicted itself in two rows of the same slot.
//
// text/plain is deliberately NOT here. /cmdi, /lfi and /redirect answer text/plain with no
// nosniff, the exam confirms them as true positives, and suppressing them would trade a false
// positive for a false negative, which is the more expensive error.
func xssrStructuredNotMarkup(mt triage.MediaType) bool {
	switch triage.MediaType(strings.ToLower(strings.TrimSpace(string(mt)))) {
	case "application/json", "application/ld+json", "text/json", "application/javascript", "text/javascript":
		return true
	}
	return false
}

// xssrProbesForContext is the promotion rule: a placement promotes EXACTLY its own context's
// payloads and nothing else.
//
// A context with no payload returns nothing, which is a planned silence rather than an oversight,
// and Classify turns it into a named unknown rather than a clean.
func xssrProbesForContext(ctxName string, respMedia triage.MediaType) []triage.ProbeID {
	switch xssrNormaliseContext(ctxName) {
	case xssrCtxHTMLText, xssrCtxSVGText, xssrCtxMathMLText, xssrCtxUnresolved:
		return []triage.ProbeID{xssrP1}
	case xssrCtxAttrDouble:
		return []triage.ProbeID{xssrP2}
	case xssrCtxAttrSingle:
		return []triage.ProbeID{xssrP3}
	case xssrCtxAttrUnquoted, xssrCtxAttrName, xssrCtxTagName:
		return []triage.ProbeID{xssrP4}
	case xssrCtxEventHandler:
		// Both quote kinds and both entity rungs. The entity rungs are the reason this context is
		// worth a probe at all on an application that HTML-escapes: they are executable here and
		// nowhere else in the ladder.
		return []triage.ProbeID{xssrP5a, xssrP5b, xssrP5c, xssrP5d}
	case xssrCtxURLScheme:
		return []triage.ProbeID{xssrP6a, xssrP6b, xssrP6c}
	case xssrCtxURLPath:
		// Not the scheme position, so no scheme is reachable from here; the value is still inside
		// a URL attribute, so the attribute breakout is what is left.
		return []triage.ProbeID{xssrP2}
	case xssrCtxScriptData:
		return []triage.ProbeID{xssrP7}
	case xssrCtxJSStringSingle:
		return []triage.ProbeID{xssrP8a, xssrP8b}
	case xssrCtxJSStringDouble:
		return []triage.ProbeID{xssrP9a, xssrP8b}
	case xssrCtxJSTemplateText:
		return []triage.ProbeID{xssrP10a, xssrP10b}
	case xssrCtxJSLineComment:
		return []triage.ProbeID{xssrP14}
	case xssrCtxJSBlockComment:
		return []triage.ProbeID{xssrP15}
	case xssrCtxHTMLComment:
		return []triage.ProbeID{xssrP11a, xssrP11b}
	case xssrCtxRCDataTextarea:
		return []triage.ProbeID{xssrP12}
	case xssrCtxRCDataTitle:
		return []triage.ProbeID{xssrP12t}
	case xssrCtxCSSBlock:
		return []triage.ProbeID{xssrP13}
	case xssrCtxJSONString:
		// RX-16 answers ONE question: does this document render on direct navigation, so that a
		// JSON blob inside it becomes markup. That question is live when the response is markup
		// already (a JSON blob in an inline script) and when it is a bare text/plain body a
		// browser may reconsider. It is NOT live when the response is itself a declared JSON or
		// JavaScript document, because no browser reconsiders those: see xssrStructuredNotMarkup.
		// Sending RX-16 there would spend a probe on a question already answered, and answered no.
		if xssrStructuredNotMarkup(respMedia) {
			return nil
		}
		if xssrRendersInABrowser(respMedia) || xssrSniffable(respMedia) {
			return []triage.ProbeID{xssrP16}
		}
		return nil
	case xssrCtxJSCode:
		// The census landed in code position with no payload sent. There is no breakout to
		// perform: the value is already code. RX-8a still tests whether a quote can be opened,
		// which is what tells a template-injected identifier from a quoted string.
		return []triage.ProbeID{xssrP8a}
	}
	return nil
}

// xssrProbeReachesSlot is the per-slot half of reachability: the matrix says the class reaches
// this kind, and this says whether THIS payload's bytes can be delivered to THIS slot.
//
// Every refusal here becomes a not_reachable verdict with the reason attached. None of them is a
// clean, because a payload that could not be delivered tested nothing.
func xssrProbeReachesSlot(id triage.ProbeID, s triage.Slot) xssrEligibility {
	needsRawDoubleQuote := id == xssrP2 || id == xssrP5c || id == xssrP9a
	needsRawSpace := id == xssrP4 || id == xssrP2
	switch s.Kind {
	case triage.KindBody:
		if s.BodyMedia == triage.BodyJSON && needsRawDoubleQuote {
			return xssrEligibility{State: triage.StateNotReachable,
				Reason: "json_string: a raw double quote cannot exist inside a JSON string, and escaping it changes " +
					"the payload into one that tests something else. RX-5d's entity form is the double-quote " +
					"rung that does reach this slot"}
		}
	case triage.KindCookie:
		if needsRawDoubleQuote || needsRawSpace {
			if s.Constraints.DecodeDepth <= 0 {
				reason := "cookie_octet: a raw double quote and a raw space are outside cookie-octet, and this " +
					"class's decode probe measured decode_depth 0, so the bytes cannot arrive"
				if s.Constraints.DecodeDepth < 0 {
					reason = "cookie_octet: a raw double quote and a raw space are outside cookie-octet and the " +
						"decode depth is unmeasured, so whether the bytes arrive is unknown, which is not clean"
				}
				return xssrEligibility{State: triage.StateNotReachable, Reason: reason}
			}
		}
	case triage.KindPath:
		if id == xssrP14 {
			return xssrEligibility{State: triage.StateNotReachable,
				Reason: "path_ctl: a line feed cannot be delivered in a path segment, and it is the only exit from a " +
					"JavaScript line comment"}
		}
	case triage.KindHeader:
		if id == xssrP14 {
			return xssrEligibility{State: triage.StateNotReachable,
				Reason: "header_crlf: CR and LF are structurally impossible in a header field value, and a line feed " +
					"is the only exit from a JavaScript line comment"}
		}
		if id == xssrPDec {
			return xssrEligibility{State: triage.StateNotApplicable,
				Reason: "the decode control measures application-side percent-decoding, which a header value does not " +
					"undergo on the way in"}
		}
	}
	if s.Constraints.PctRejected && (s.Kind == triage.KindPath || id == xssrPDec) {
		return xssrEligibility{State: triage.StateCannotDetermine,
			Reason: "pct_rejected: the slot refused a percent-encoded control, so no encoded payload's fate can be read"}
	}
	for _, b := range s.Constraints.Impossible {
		if bytes.IndexByte(xssrLogicalFor(id), b) >= 0 {
			return xssrEligibility{State: triage.StateNotReachable,
				Reason: fmt.Sprintf("byte 0x%02x is measured impossible in this slot and this payload needs it", b)}
		}
	}
	return xssrEligibility{OK: true}
}

// xssrLogicalFor returns a probe's declared bytes. It reads the declaration rather than a second
// copy of the payload, so a payload edited in one place cannot be reachability-checked in another.
func xssrLogicalFor(id triage.ProbeID) []byte {
	for _, p := range (xssReflectedClassifier{}).Probes() {
		if p.ID == id {
			return p.Logical
		}
	}
	return nil
}

// xssrSentProbes is the set of this class's probes that already have a response in hand. Plan is
// called repeatedly and a probe planned twice is a request sent twice.
func xssrSentProbes(own triage.OwnedResponses) map[triage.ProbeID]bool {
	out := map[triage.ProbeID]bool{}
	for i := 0; i < own.Len(); i++ {
		p, _, err := own.At(i)
		if err != nil {
			continue
		}
		out[p.ProbeID()] = true
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// TOOL LABELS AND THE ORACLE CONTRACT
// ---------------------------------------------------------------------------------------------

// Confirmers are the expensive tools a positive label points at.
//
// dalfox is primary and reaches all five server-side insertion points. domdig is here because the
// two outcomes this class can only hand on (an allowlist sanitizer, and a JSON reflection whose
// sink is in the DOM) are browser-only questions.
func (xssReflectedClassifier) Confirmers() []string { return []string{"dalfox", "domdig"} }

// Evidencers are tools whose output is evidence and never confirmation.
//
// xssfuzz is here and not in Confirmers for a measured reason: its request path is requests.get
// only, with the body and crawl paths commented out in its source, so it reaches query slots and
// nothing else. A silent xssfuzz says nothing at all about a header, cookie, path or body slot,
// and reading its silence as confirmation would be the same silent zero this layer exists to stop.
func (xssReflectedClassifier) Evidencers() []string { return []string{"xssfuzz", "nuclei-dast"} }

// xssrOracleExpect is which side of the oracle a route exercises.
type xssrOracleExpect string

const (
	xssrExpectPositive xssrOracleExpect = "positive"
	xssrExpectNegative xssrOracleExpect = "negative"
)

// xssrOracleCase is one route this class's detectors must be run against before anybody trusts
// them. It is a local type because package triage declares no OracleCase and a classifier may not
// add one; the shape follows DESIGN.md's.
type xssrOracleCase struct {
	Route  string
	Expect xssrOracleExpect
	Probe  triage.ProbeID
	Want   triage.TriageState
	Exists bool // does docker/oracle already serve it
	Why    string
}

// OracleCases is the control set. It contains positives AND negatives, and the negatives are the
// half that actually tests anything: a detector that fires on every route scores one hundred per
// cent, and so does one that always returns true.
func (xssReflectedClassifier) OracleCases() []xssrOracleCase {
	return []xssrOracleCase{
		{Route: "/xss", Expect: xssrExpectPositive, Probe: xssrP1, Want: triage.StateFinding, Exists: true,
			Why: "reflects into HTML text, so the marker element forms and RX-D1 fires"},
		{Route: "/xss/attr", Expect: xssrExpectPositive, Probe: xssrP2, Want: triage.StateFinding,
			Why: "reflection into a double-quoted attribute value: RX-D2 must report an attribute NAMED by the marker"},
		{Route: "/xss/eventhandler", Expect: xssrExpectPositive, Probe: xssrP5b, Want: triage.StateFinding,
			Why: "reflection into an onclick with everything HTML-encoded. RX-5b must fire and RX-5a must NOT: " +
				"the attribute value is entity-decoded before the JS parser sees it, and that asymmetry is the " +
				"single highest-value thing this class knows"},
		{Route: "/xss/entity", Expect: xssrExpectNegative, Probe: xssrPNC3, Want: triage.StateClean, Exists: false,
			Why: "the reflection is echoed as &lt;M&gt;. RX-D1 MUST stay silent: a character reference decodes to a " +
				"character token and can never produce a tag. This is NC-A3 as a route and it is the most " +
				"important control in the family"},
		{Route: "/xss/encoded", Expect: xssrExpectNegative, Probe: xssrP1, Want: triage.StateClean,
			Why: "htmlspecialchars with ENT_QUOTES. All four primary rules silent, and the verdict is clean with the " +
				"encoder NAMED, which is a far more useful row than a bare clean"},
		{Route: "/xss/noscript", Expect: xssrExpectNegative, Probe: xssrP1, Want: triage.StateClean,
			Why: "every reflection wrapped in <noscript>. With scripting-enabled semantics noscript is RAWTEXT and no " +
				"element forms. A tokenizer configured with scripting OFF reports a finding here, and this route " +
				"is the only thing that catches that misconfiguration"},
		{Route: "/xss/encoded?json=1", Expect: xssrExpectNegative, Probe: xssrP16, Want: triage.StateCannotDetermine,
			Why: "the marker in a JSON response with nosniff set. RX-16's media-type gate must hold it shut and the " +
				"verdict must be cannot_determine (needs_dom_run), never clean: the value round-trips and nothing " +
				"in the response says whether a SPA writes it into the DOM"},
		{Route: "/clean/echo", Expect: xssrExpectNegative, Probe: xssrP0r, Want: triage.StateClean,
			Why: "reflects the input with no template, no parser and no sink. Reflection is not injection, and the " +
				"census probe alone must never fire a rule (NC-A1)"},
		{Route: "/clean/waf", Expect: xssrExpectNegative, Probe: xssrP1, Want: triage.StateCannotDetermine,
			Why: "an identical 403 block page for every payload. Three identical non-baseline responses from THIS " +
				"class's own payloads gives cannot_determine (blocked): no finding, and emphatically no clean"},
		{Route: "/clean/nothing", Expect: xssrExpectNegative, Probe: xssrP0r, Want: triage.StateCannotDetermine,
			Why: "200 with an empty body. No body means no oracle, so the run that yields nothing must yield an " +
				"unknown rather than a green tick"},
	}
}

// SettleNeeded records that this class has no deferred out-of-band check.
//
// There is no Settle on the Classifier interface in package triage and no SettleView type to
// implement one against, so there is no no-op to embed. This method is the declaration in its
// place: every oracle in this class reads a response that is already in hand, nothing arrives
// late, and a collaborator adds nothing here. Say so rather than leave the question open.
func (xssReflectedClassifier) SettleNeeded() bool { return false }

// ---------------------------------------------------------------------------------------------
// THE CONTEXT VOCABULARY
// ---------------------------------------------------------------------------------------------

// The contexts this class distinguishes. They are the foundations 4.1 enumeration, lowercased,
// with the ones this class can neither probe nor act on left out rather than folded into a
// neighbour: a context that is silently mapped to its nearest relative gets tested with the wrong
// payload, produces nothing, and is recorded clean.
const (
	xssrCtxHTMLText       = "html_text"
	xssrCtxSVGText        = "svg_text"
	xssrCtxMathMLText     = "mathml_text"
	xssrCtxRCDataTextarea = "html_rcdata_textarea"
	xssrCtxRCDataTitle    = "html_rcdata_title"
	xssrCtxHTMLComment    = "html_comment"
	xssrCtxTagName        = "html_tag_name"
	xssrCtxAttrName       = "html_attr_name"
	xssrCtxAttrDouble     = "attr_double"
	xssrCtxAttrSingle     = "attr_single"
	xssrCtxAttrUnquoted   = "attr_unquoted"
	xssrCtxURLScheme      = "url_attr_scheme"
	xssrCtxURLPath        = "url_attr_path"
	xssrCtxEventHandler   = "event_handler"
	xssrCtxCSSInAttr      = "css_in_attr"
	xssrCtxCSSBlock       = "css_block"
	xssrCtxScriptData     = "script_data"
	xssrCtxJSCode         = "js_code"
	xssrCtxJSStringSingle = "js_string_single"
	xssrCtxJSStringDouble = "js_string_double"
	xssrCtxJSTemplateText = "js_template_text"
	xssrCtxJSTemplateSub  = "js_template_subst"
	xssrCtxJSRegex        = "js_regex"
	xssrCtxJSLineComment  = "js_line_comment"
	xssrCtxJSBlockComment = "js_block_comment"
	xssrCtxJSONString     = "json_string_value"
	xssrCtxInertRawText   = "inert_raw_text"
	xssrCtxHeaderValue    = "header_value"
	xssrCtxUnresolved     = "unresolved"
)

// xssrNormaliseContext accepts a context name written in any of the three vocabularies in this
// tree and returns this file's.
//
// THE THREE EXIST AND DISAGREE. foundations 4.1 enumerates HTML_TEXT and friends; the Placement
// type in package triage documents a much shorter list (html_text, attr_value_quoted,
// script_string, css, url, unresolved); and this file writes its own. A classifier that assumed
// one of them would silently fail to promote a placement the moment the runner filled Placements
// with another, and a placement that promotes nothing is a context that is never probed.
//
// AN UNRECOGNISED NAME BECOMES unresolved AND NEVER html_text. Defaulting to the commonest
// context is how an attribute reflection gets tested as if it were text, produces nothing, and is
// recorded clean.
func xssrNormaliseContext(s string) string {
	n := strings.ToLower(strings.TrimSpace(s))
	switch n {
	case xssrCtxHTMLText, xssrCtxSVGText, xssrCtxMathMLText, xssrCtxRCDataTextarea, xssrCtxRCDataTitle,
		xssrCtxHTMLComment, xssrCtxTagName, xssrCtxAttrName, xssrCtxAttrDouble, xssrCtxAttrSingle,
		xssrCtxAttrUnquoted, xssrCtxURLScheme, xssrCtxURLPath, xssrCtxEventHandler, xssrCtxCSSInAttr,
		xssrCtxCSSBlock, xssrCtxScriptData, xssrCtxJSCode, xssrCtxJSStringSingle, xssrCtxJSStringDouble,
		xssrCtxJSTemplateText, xssrCtxJSTemplateSub, xssrCtxJSRegex, xssrCtxJSLineComment,
		xssrCtxJSBlockComment, xssrCtxJSONString, xssrCtxInertRawText, xssrCtxHeaderValue, xssrCtxUnresolved:
		return n
	// The foundations 4.1 spelling that this file splits in two: HTML_RCDATA does not say which
	// element, and the end tag the payload needs is the element's own, so it defaults to the
	// textarea form and the title form is reached when the tokenizer names the element itself.
	case "html_rcdata":
		return xssrCtxRCDataTextarea
	// The shorter vocabulary on triage.Placement. attr_value_quoted does not say WHICH quote, and
	// the quote is the exit character, so it cannot promote a single payload: it promotes the
	// double-quote probe and the single-quote probe both, which is what "unknown quote" honestly
	// means. It is mapped to the double form here and Plan's caller sends RX-3 as well through
	// the attr_single row when the runner reports one.
	case "attr_value_quoted":
		return xssrCtxAttrDouble
	case "script_string":
		return xssrCtxJSStringSingle
	case "css":
		return xssrCtxCSSBlock
	case "url":
		return xssrCtxURLScheme
	case "header":
		return xssrCtxHeaderValue
	}
	return xssrCtxUnresolved
}

// ---------------------------------------------------------------------------------------------
// THE TOKENIZER
// ---------------------------------------------------------------------------------------------
//
// A REGEX CANNOT DO THIS AND THAT IS NOT A PERFORMANCE CLAIM. The entire verdict is the
// distinction between "inside a text node" and "inside an attribute value", and between "a tag
// the parser named" and "a string that looks like one". A regex-based context detector is the
// single most common way a triage layer reports the wrong context, chooses the wrong follow-up
// payload, finds nothing and records a clean result.
//
// golang.org/x/net/html is the right tokenizer and this class may not import it: the classifier
// allow-list is bytes, strings and their neighbours, by design, and widening it for one class
// would widen it for every class. So the states this class's oracles actually depend on are
// implemented here, and the ones they do not are named as gaps rather than approximated:
//
//	IMPLEMENTED   data, RCDATA and RAWTEXT element content, comments, start and end tags,
//	              attribute names and the three attribute value states with the correct
//	              TWO-terminator rule for the unquoted one, the element stack, void elements,
//	              foreign content by stack membership, and the JS lexer states inside <script>.
//	NOT MODELLED  tree construction. There is no insertion-mode machine, no foster parenting and
//	              no implied end tags, so an element the tokenizer names but the tree builder
//	              would have relocated is reported where it was written. That is recorded as
//	              element_moved on the verdict rather than silently resolved, and it never turns
//	              a hit into a miss: RX-D1 asks whether the parser NAMED a tag, and the tokenizer
//	              is the part of the parser that names tags.

type xssrTokenKind uint8

const (
	xssrTokText xssrTokenKind = iota
	xssrTokStartTag
	xssrTokEndTag
	xssrTokComment
	xssrTokDoctype
	xssrTokRawText
)

// xssrAttr is one attribute with the byte ranges of its name and its value, because the whole of
// RX-D2 is "the marker is the NAME and not the value".
type xssrAttr struct {
	Name                 string
	NameStart, NameEnd   int
	Value                string
	ValueStart, ValueEnd int
	Quote                byte // 0x22, 0x27, or 0 for unquoted
}

type xssrToken struct {
	Kind               xssrTokenKind
	Start, End         int
	Name               string
	NameStart, NameEnd int
	Attrs              []xssrAttr
	SelfClose          bool
	Unclosed           bool     // the tag ran to end of input without a closing >
	Stack              []string // enclosing elements, outermost first
	Owner              string   // raw text and RCDATA only: the element whose content this is
	ScriptType         string   // script raw text only: the type attribute, lowered
}

type xssrDoc struct {
	Tokens  []xssrToken
	Errored bool // the input ended inside a tag or a comment
}

// xssrVoidElements never have content, so they are never pushed onto the stack. A stack that
// pushes <br> never pops it and every context below it is reported wrong.
var xssrVoidElements = map[string]bool{
	"area": true, "base": true, "br": true, "col": true, "embed": true, "hr": true,
	"img": true, "input": true, "link": true, "meta": true, "param": true,
	"source": true, "track": true, "wbr": true,
}

// xssrRawTextElements are the elements whose content is NOT parsed as markup. noscript is in the
// list because this tokenizer runs with SCRIPTING-ENABLED semantics, which is the correction that
// stops /xss/noscript reporting a finding. iframe, noembed, noframes and xmp are there for the
// same reason: markup written inside them does not become elements.
var xssrRawTextElements = map[string]bool{
	"script": true, "style": true, "textarea": true, "title": true,
	"noscript": true, "iframe": true, "noembed": true, "noframes": true, "xmp": true,
}

func xssrIsASCIILetter(b byte) bool { return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') }

// xssrIsHTMLSpace is the WHATWG ASCII whitespace set: TAB, LF, FF, CR and SPACE. It is the exact
// set that leaves the unquoted attribute value state, which is why it is spelled out rather than
// borrowed from unicode.IsSpace (which also matches NBSP, and an NBSP does not terminate
// anything).
func xssrIsHTMLSpace(b byte) bool {
	return b == 0x09 || b == 0x0a || b == 0x0c || b == 0x0d || b == 0x20
}

func xssrTokenize(body []byte) xssrDoc {
	var doc xssrDoc
	var stack []string
	raw := ""
	rawScriptType := ""
	i := 0
	snapshot := func() []string {
		out := make([]string, len(stack))
		copy(out, stack)
		return out
	}
	for i < len(body) {
		if raw != "" {
			end, next := xssrFindEndTag(body, i, raw)
			doc.Tokens = append(doc.Tokens, xssrToken{
				Kind: xssrTokRawText, Start: i, End: end, Stack: snapshot(),
				Owner: raw, ScriptType: rawScriptType, Unclosed: next < 0,
			})
			raw, rawScriptType = "", ""
			if next < 0 {
				doc.Errored = true
				i = len(body)
				break
			}
			i = end
			continue
		}
		if body[i] != '<' {
			j := bytes.IndexByte(body[i:], '<')
			end := len(body)
			if j >= 0 {
				end = i + j
			}
			doc.Tokens = append(doc.Tokens, xssrToken{Kind: xssrTokText, Start: i, End: end, Stack: snapshot()})
			i = end
			continue
		}
		switch {
		case bytes.HasPrefix(body[i:], []byte("<!--")):
			end := xssrFindCommentEnd(body, i+4)
			if end < 0 {
				doc.Errored = true
				doc.Tokens = append(doc.Tokens, xssrToken{Kind: xssrTokComment, Start: i, End: len(body), Stack: snapshot(), Unclosed: true})
				i = len(body)
				continue
			}
			doc.Tokens = append(doc.Tokens, xssrToken{Kind: xssrTokComment, Start: i, End: end, Stack: snapshot()})
			i = end
		case bytes.HasPrefix(body[i:], []byte("<!")):
			end := xssrScanTo(body, i, '>')
			doc.Tokens = append(doc.Tokens, xssrToken{Kind: xssrTokDoctype, Start: i, End: end, Stack: snapshot()})
			i = end
		case bytes.HasPrefix(body[i:], []byte("</")):
			tok, next := xssrParseTag(body, i, true)
			tok.Stack = snapshot()
			doc.Tokens = append(doc.Tokens, tok)
			stack = xssrPopTo(stack, tok.Name)
			i = next
		case i+1 < len(body) && xssrIsASCIILetter(body[i+1]):
			tok, next := xssrParseTag(body, i, false)
			tok.Stack = snapshot()
			doc.Tokens = append(doc.Tokens, tok)
			if tok.Unclosed {
				doc.Errored = true
			}
			if !tok.SelfClose && !xssrVoidElements[tok.Name] {
				if xssrRawTextElements[tok.Name] {
					raw = tok.Name
					if tok.Name == "script" {
						rawScriptType = xssrAttrValue(tok, "type")
					}
				}
				stack = append(stack, tok.Name)
			}
			i = next
		default:
			// A < that begins nothing is a literal character in the data state.
			doc.Tokens = append(doc.Tokens, xssrToken{Kind: xssrTokText, Start: i, End: i + 1, Stack: snapshot()})
			i++
		}
	}
	return doc
}

// xssrFindCommentEnd honours both terminators: --> and the bang form --!> .
func xssrFindCommentEnd(body []byte, from int) int {
	for i := from; i < len(body); i++ {
		if body[i] != '-' {
			continue
		}
		if bytes.HasPrefix(body[i:], []byte("-->")) {
			return i + 3
		}
		if bytes.HasPrefix(body[i:], []byte("--!>")) {
			return i + 4
		}
	}
	return -1
}

func xssrScanTo(body []byte, from int, b byte) int {
	if j := bytes.IndexByte(body[from:], b); j >= 0 {
		return from + j + 1
	}
	return len(body)
}

// xssrFindEndTag returns where the raw text content ends and where the matching end tag starts.
// A RAWTEXT element ends only at its own end tag; anything else inside it is text.
func xssrFindEndTag(body []byte, from int, name string) (contentEnd, tagStart int) {
	want := []byte("</" + name)
	for i := from; i+len(want) <= len(body); i++ {
		if body[i] != '<' {
			continue
		}
		if !xssrEqualFoldBytes(body[i:i+len(want)], want) {
			continue
		}
		after := i + len(want)
		if after < len(body) && !xssrIsHTMLSpace(body[after]) && body[after] != '>' && body[after] != '/' {
			continue
		}
		return i, i
	}
	return len(body), -1
}

func xssrEqualFoldBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

func xssrPopTo(stack []string, name string) []string {
	for i := len(stack) - 1; i >= 0; i-- {
		if stack[i] == name {
			return stack[:i]
		}
	}
	return stack
}

// xssrParseTag reads one start or end tag, with every attribute's name and value byte range.
//
// THE UNQUOTED VALUE STATE HAS TWO TERMINATORS. Only ASCII whitespace leaves the state and only >
// closes the tag; a quote, a backtick, an equals, a < and a SLASH are all appended to the value.
// That is what makes <div a=b/> yield a="b/", and it is why RX-4 is built on a space.
func xssrParseTag(body []byte, start int, end bool) (xssrToken, int) {
	tok := xssrToken{Kind: xssrTokStartTag, Start: start}
	if end {
		tok.Kind = xssrTokEndTag
	}
	i := start + 1
	if end {
		i++
	}
	tok.NameStart = i
	for i < len(body) && !xssrIsHTMLSpace(body[i]) && body[i] != '>' && body[i] != '/' {
		i++
	}
	tok.NameEnd = i
	tok.Name = strings.ToLower(string(body[tok.NameStart:tok.NameEnd]))

	for i < len(body) {
		for i < len(body) && xssrIsHTMLSpace(body[i]) {
			i++
		}
		if i >= len(body) {
			break
		}
		if body[i] == '>' {
			i++
			tok.End = i
			return tok, i
		}
		if body[i] == '/' {
			// Self-closing start tag state: only > matters here, anything else is reconsumed in
			// the before-attribute-name state, which is why a lone slash names no attribute.
			if i+1 < len(body) && body[i+1] == '>' {
				tok.SelfClose = true
				i += 2
				tok.End = i
				return tok, i
			}
			i++
			continue
		}
		var a xssrAttr
		a.NameStart = i
		for i < len(body) && !xssrIsHTMLSpace(body[i]) && body[i] != '=' && body[i] != '>' && body[i] != '/' {
			i++
		}
		a.NameEnd = i
		a.Name = strings.ToLower(string(body[a.NameStart:a.NameEnd]))
		for i < len(body) && xssrIsHTMLSpace(body[i]) {
			i++
		}
		if i < len(body) && body[i] == '=' {
			i++
			for i < len(body) && xssrIsHTMLSpace(body[i]) {
				i++
			}
			if i < len(body) && (body[i] == '"' || body[i] == '\'') {
				q := body[i]
				i++
				a.Quote = q
				a.ValueStart = i
				for i < len(body) && body[i] != q {
					i++
				}
				a.ValueEnd = i
				if i < len(body) {
					i++
				}
			} else {
				a.ValueStart = i
				for i < len(body) && !xssrIsHTMLSpace(body[i]) && body[i] != '>' {
					i++
				}
				a.ValueEnd = i
			}
			a.Value = string(body[a.ValueStart:a.ValueEnd])
		}
		if a.Name != "" {
			tok.Attrs = append(tok.Attrs, a)
		}
	}
	tok.Unclosed = true
	tok.End = len(body)
	return tok, len(body)
}

func xssrAttrValue(tok xssrToken, name string) string {
	for _, a := range tok.Attrs {
		if a.Name == name {
			return strings.ToLower(strings.TrimSpace(a.Value))
		}
	}
	return ""
}

// xssrURLAttributes is the URL-bearing attribute set. The scheme is only reachable at value offset
// zero, and collapsing URL_ATTR_SCHEME into URL_ATTR_PATH loses the whole difference between a
// reachable sink and an unreachable one.
var xssrURLAttributes = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true, "data": true,
	"poster": true, "background": true, "cite": true, "ping": true, "srcset": true,
	"longdesc": true, "manifest": true, "archive": true, "codebase": true,
	"usemap": true, "profile": true, "xlink:href": true, "xml:base": true,
}

// xssrExecutableScriptTypes is the correction most scanners get wrong. A marker inside
// <script type="application/json"> is DATA. Reporting it as script context sends the operator's
// expensive scanner at a sink that cannot execute, and an unrecognised type is data too.
func xssrExecutableScriptType(t string) bool {
	switch strings.ToLower(strings.TrimSpace(t)) {
	case "", "text/javascript", "application/javascript", "application/ecmascript",
		"text/ecmascript", "module", "text/jsx", "text/babel":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// THE MARKER SEARCH, ALL FIVE TRANSFORM FORMS
// ---------------------------------------------------------------------------------------------

// xssrMarkerForm names how a marker occurrence was written in the response. It matters because a
// hit through a re-encoded form is capped at medium (CATALOGUE 4.2) and because clean requires the
// marker to be absent in EVERY form, not merely in the raw one.
type xssrMarkerForm string

const (
	xssrFormRaw     xssrMarkerForm = "raw"
	xssrFormCase    xssrMarkerForm = "case_transformed"
	xssrFormNCR     xssrMarkerForm = "ncr"
	xssrFormPercent xssrMarkerForm = "percent"
	xssrFormBase64  xssrMarkerForm = "base64"
	xssrFormUTF16LE xssrMarkerForm = "utf16le"
)

type xssrOccurrence struct {
	Offset int
	Length int
	Form   xssrMarkerForm
}

// xssrFindMarker runs the foundations 2.5 transform set over a response body.
//
// ALL FIVE FORMS, AND NOT BECAUSE THEY ARE ALL LIKELY. Precondition 1 of this class's clean is
// that the marker is absent in every form, so every form that is not searched is a way for a
// reflecting application to be recorded as clean. Base64 is searched at all three phase
// alignments because a marker embedded in a longer base64 string encodes differently depending on
// its offset modulo three, and searching only phase zero misses two thirds of them.
func xssrFindMarker(body []byte, marker string) []xssrOccurrence {
	var out []xssrOccurrence
	if marker == "" || len(body) == 0 {
		return nil
	}
	lower := bytes.ToLower(body)
	lm := []byte(strings.ToLower(marker))
	for i := 0; ; {
		j := bytes.Index(lower[i:], lm)
		if j < 0 {
			break
		}
		at := i + j
		form := xssrFormRaw
		if !bytes.Equal(body[at:at+len(lm)], []byte(marker)) {
			form = xssrFormCase
		}
		out = append(out, xssrOccurrence{Offset: at, Length: len(lm), Form: form})
		i = at + len(lm)
	}
	for _, alt := range xssrMarkerAlternateForms(marker) {
		if alt.bytes == "" {
			continue
		}
		hay, needle := lower, []byte(strings.ToLower(alt.bytes))
		for i := 0; ; {
			j := bytes.Index(hay[i:], needle)
			if j < 0 {
				break
			}
			at := i + j
			out = append(out, xssrOccurrence{Offset: at, Length: len(needle), Form: alt.form})
			i = at + len(needle)
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Offset < out[b].Offset })
	return out
}

type xssrAltForm struct {
	form  xssrMarkerForm
	bytes string
}

func xssrMarkerAlternateForms(marker string) []xssrAltForm {
	var out []xssrAltForm
	var ncr, pct, utf16 strings.Builder
	for i := 0; i < len(marker); i++ {
		ncr.WriteString("&#")
		ncr.WriteString(strconv.Itoa(int(marker[i])))
		ncr.WriteString(";")
		pct.WriteString("%")
		pct.WriteString(strings.ToUpper(strconv.FormatInt(int64(marker[i]), 16)))
		utf16.WriteByte(marker[i])
		utf16.WriteByte(0)
	}
	out = append(out,
		xssrAltForm{xssrFormNCR, ncr.String()},
		xssrAltForm{xssrFormPercent, pct.String()},
		xssrAltForm{xssrFormUTF16LE, utf16.String()},
	)
	// Base64 at the three phase alignments. The padding characters at each end are dropped
	// because they encode the neighbouring bytes, which are the application's and not ours.
	for phase := 0; phase < 3; phase++ {
		padded := strings.Repeat("A", phase) + marker
		enc := base64.StdEncoding.EncodeToString([]byte(padded))
		enc = strings.TrimRight(enc, "=")
		start := (phase*8 + 5) / 6
		if start >= len(enc) {
			continue
		}
		core := enc[start : len(enc)-1]
		if len(core) >= 8 {
			out = append(out, xssrAltForm{xssrFormBase64, core})
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// PLACEMENTS
// ---------------------------------------------------------------------------------------------

type xssrPlacement struct {
	Offset, Length int
	Form           xssrMarkerForm
	Context        string
	Detail         string
	TagName        string
	AttrName       string
	Quote          byte
	AttrIsURL      bool
	AtValueStart   bool
	ScriptType     string
	Executable     string // yes | no | unknown
	Stack          []string
	Confidence     string // high | low
	InertContainer string // template, noscript, iframe, ... when the placement can never execute
}

// xssrClassifyPlacements is foundations part 4 over one response, with this class's own marker.
//
// It returns ONE ENTRY PER OCCURRENCE and never a "primary" placement. A response with the marker
// in html text, in an href attribute and in a JS string is three placements, and probing only the
// first is a false negative by construction: a payload that works in one is inert in the others.
func xssrClassifyPlacements(body []byte, doc xssrDoc, marker string) []xssrPlacement {
	occ := xssrFindMarker(body, marker)
	out := make([]xssrPlacement, 0, len(occ))
	for _, o := range occ {
		out = append(out, xssrPlaceOne(body, doc, o))
	}
	return out
}

func xssrPlaceOne(body []byte, doc xssrDoc, o xssrOccurrence) xssrPlacement {
	pl := xssrPlacement{Offset: o.Offset, Length: o.Length, Form: o.Form,
		Context: xssrCtxUnresolved, Confidence: "high", Executable: "unknown"}
	for _, t := range doc.Tokens {
		if o.Offset < t.Start || o.Offset >= t.End {
			continue
		}
		pl.Stack = t.Stack
		pl.InertContainer = xssrInertContainer(t.Stack)
		switch t.Kind {
		case xssrTokText:
			pl.Context = xssrCtxHTMLText
			pl.Executable = "no"
			if xssrStackHas(t.Stack, "svg") {
				pl.Context = xssrCtxSVGText
			} else if xssrStackHas(t.Stack, "math") {
				pl.Context = xssrCtxMathMLText
			}
		case xssrTokComment:
			pl.Context = xssrCtxHTMLComment
			pl.Detail = "comment_exit_restricted: comment text may not contain the terminator, which is exactly what the payload needs"
		case xssrTokDoctype:
			pl.Context = xssrCtxUnresolved
			pl.Confidence = "low"
		case xssrTokRawText:
			pl.TagName = t.Owner
			switch t.Owner {
			case "script":
				pl.ScriptType = t.ScriptType
				if !xssrExecutableScriptType(t.ScriptType) {
					pl.Context = xssrCtxScriptData
					pl.Executable = "no"
					pl.Detail = "script_type=" + t.ScriptType + ": the browser treats this island as data, so a lexer transition inside it executes nothing"
					return pl
				}
				pl.Executable = "yes"
				st := xssrLexJS(body[t.Start:t.End], o.Offset-t.Start)
				pl.Context = st.State
				pl.Confidence = st.Confidence
			case "style":
				pl.Context = xssrCtxCSSBlock
				pl.Executable = "no"
			case "textarea":
				pl.Context = xssrCtxRCDataTextarea
			case "title":
				pl.Context = xssrCtxRCDataTitle
			default:
				pl.Context = xssrCtxInertRawText
				pl.Executable = "no"
				pl.Detail = "the content of <" + t.Owner + "> is raw text with scripting enabled, so markup written here never becomes an element"
			}
		case xssrTokStartTag, xssrTokEndTag:
			pl.TagName = t.Name
			switch {
			case o.Offset >= t.NameStart && o.Offset < t.NameEnd:
				pl.Context = xssrCtxTagName
			default:
				placed := false
				for _, a := range t.Attrs {
					if o.Offset >= a.NameStart && o.Offset < a.NameEnd {
						pl.Context, pl.AttrName, placed = xssrCtxAttrName, a.Name, true
						break
					}
					if a.ValueEnd > a.ValueStart && o.Offset >= a.ValueStart && o.Offset < a.ValueEnd {
						pl.AttrName, placed = a.Name, true
						pl.Quote = a.Quote
						pl.AtValueStart = o.Offset == a.ValueStart
						switch a.Quote {
						case '"':
							pl.Context = xssrCtxAttrDouble
						case '\'':
							pl.Context = xssrCtxAttrSingle
						default:
							pl.Context = xssrCtxAttrUnquoted
						}
						switch {
						case strings.HasPrefix(a.Name, "on"):
							pl.Context = xssrCtxEventHandler
							pl.Executable = "yes"
							pl.Detail = "decode_layers=html_entity,js: the value is entity-decoded and the RESULT is parsed as JavaScript"
						case a.Name == "style":
							pl.Context = xssrCtxCSSInAttr
							pl.Executable = "no"
						case xssrURLAttributes[a.Name]:
							pl.AttrIsURL = true
							if pl.AtValueStart {
								pl.Context = xssrCtxURLScheme
							} else {
								pl.Context = xssrCtxURLPath
							}
						}
						break
					}
				}
				if !placed {
					pl.Context = xssrCtxUnresolved
					pl.Confidence = "low"
				}
			}
		}
		return pl
	}
	// Step 7. An occurrence the tokenizer could not assign is UNRESOLVED with low confidence, and
	// it is never defaulted to html_text.
	pl.Confidence = "low"
	pl.Detail = "the tokenizer assigned this occurrence to no token"
	return pl
}

func xssrStackHas(stack []string, name string) bool {
	for _, s := range stack {
		if s == name {
			return true
		}
	}
	return false
}

// xssrInertContainer names an enclosing element inside which nothing the payload creates can run.
// A hit inside one is still a hit (the breakout is proven) and is downgraded rather than dropped.
func xssrInertContainer(stack []string) string {
	for _, s := range stack {
		switch s {
		case "template", "noscript", "iframe", "noembed", "noframes", "xmp", "plaintext":
			return s
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// THE JAVASCRIPT LEXER
// ---------------------------------------------------------------------------------------------

type xssrJSResult struct {
	State        string
	Confidence   string
	Unterminated bool // the script ended inside a string or template literal
}

// xssrLexJS reports the lexical state at one offset inside a script element's content.
//
// It tracks line comments, block comments, both string kinds with backslash escapes, template
// literals with nested substitutions, and regex literals. The regex-versus-division ambiguity is
// resolved with the usual previous-significant-token heuristic, and WHERE THE HEURISTIC WAS USED
// THE RESULT IS MARKED low CONFIDENCE, which caps the verdict at suspicious. A lexer that guesses
// silently produces a confident verdict about a state it guessed.
func xssrLexJS(src []byte, off int) xssrJSResult {
	res := xssrJSResult{State: xssrCtxJSCode, Confidence: "high"}
	if off < 0 {
		return res
	}
	type frame struct{ kind byte } // '`' template literal, '{' substitution
	var stack []frame
	guessed := false
	state := xssrCtxJSCode
	var quote byte
	prevSig := byte(0)
	i := 0
	for ; i < len(src); i++ {
		c := src[i]
		if i == off {
			break
		}
		switch state {
		case xssrCtxJSCode:
			switch {
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = xssrCtxJSLineComment
				i++
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = xssrCtxJSBlockComment
				i++
			case c == '/':
				if xssrRegexCanStartAfter(prevSig) {
					state = xssrCtxJSRegex
				} else {
					guessed = true
				}
			case c == '\'':
				state, quote = xssrCtxJSStringSingle, '\''
			case c == '"':
				state, quote = xssrCtxJSStringDouble, '"'
			case c == '`':
				state = xssrCtxJSTemplateText
				stack = append(stack, frame{'`'})
			case c == '}' && len(stack) > 0 && stack[len(stack)-1].kind == '{':
				stack = stack[:len(stack)-1]
				state = xssrCtxJSTemplateText
			}
			if !xssrIsHTMLSpace(c) {
				prevSig = c
			}
		case xssrCtxJSLineComment:
			if c == '\n' {
				state = xssrCtxJSCode
			}
		case xssrCtxJSBlockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = xssrCtxJSCode
				i++
			}
		case xssrCtxJSStringSingle, xssrCtxJSStringDouble:
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				state = xssrCtxJSCode
				prevSig = c
			}
		case xssrCtxJSRegex:
			if c == '\\' {
				i++
				continue
			}
			if c == '/' {
				state = xssrCtxJSCode
				prevSig = c
			}
		case xssrCtxJSTemplateText:
			switch {
			case c == '\\':
				i++
			case c == '$' && i+1 < len(src) && src[i+1] == '{':
				state = xssrCtxJSTemplateSub
				stack = append(stack, frame{'{'})
				i++
			case c == '`':
				if len(stack) > 0 && stack[len(stack)-1].kind == '`' {
					stack = stack[:len(stack)-1]
				}
				state = xssrCtxJSCode
				prevSig = c
			}
		case xssrCtxJSTemplateSub:
			// Inside a substitution the grammar is ordinary code again; only the closing brace
			// that matches this substitution returns to template text.
			switch {
			case c == '}':
				if len(stack) > 0 && stack[len(stack)-1].kind == '{' {
					stack = stack[:len(stack)-1]
					state = xssrCtxJSTemplateText
				}
			case c == '\'':
				state, quote = xssrCtxJSStringSingle, '\''
			case c == '"':
				state, quote = xssrCtxJSStringDouble, '"'
			}
			if !xssrIsHTMLSpace(c) {
				prevSig = c
			}
		}
	}
	res.State = state
	if guessed {
		res.Confidence = "low"
	}
	// Finish the scan to answer the RX-8b sub-rule: did the literal that holds the offset survive
	// to the end of the script.
	for ; i < len(src); i++ {
		c := src[i]
		switch state {
		case xssrCtxJSStringSingle, xssrCtxJSStringDouble:
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				state = xssrCtxJSCode
			}
		case xssrCtxJSTemplateText:
			if c == '\\' {
				i++
				continue
			}
			if c == '`' {
				state = xssrCtxJSCode
			}
		case xssrCtxJSLineComment:
			if c == '\n' {
				state = xssrCtxJSCode
			}
		case xssrCtxJSBlockComment:
			if c == '*' && i+1 < len(src) && src[i+1] == '/' {
				state = xssrCtxJSCode
				i++
			}
		case xssrCtxJSCode:
			switch {
			case c == '\'':
				state, quote = xssrCtxJSStringSingle, '\''
			case c == '"':
				state, quote = xssrCtxJSStringDouble, '"'
			case c == '`':
				state = xssrCtxJSTemplateText
			case c == '/' && i+1 < len(src) && src[i+1] == '/':
				state = xssrCtxJSLineComment
				i++
			case c == '/' && i+1 < len(src) && src[i+1] == '*':
				state = xssrCtxJSBlockComment
				i++
			}
		}
	}
	switch state {
	case xssrCtxJSStringSingle, xssrCtxJSStringDouble, xssrCtxJSTemplateText:
		res.Unterminated = true
	}
	return res
}

// xssrRegexCanStartAfter is the standard heuristic: a slash begins a regex where a value cannot
// have just ended.
func xssrRegexCanStartAfter(prev byte) bool {
	switch prev {
	case 0, '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', '}', ';', '+', '-', '*', '%', '~', '^', '<', '>', '\n':
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// HTML ENTITY DECODING, FOR THE TWO CONTEXTS THAT DECODE
// ---------------------------------------------------------------------------------------------

// xssrDecodeEntities decodes numeric character references and the handful of named ones that
// matter to this class.
//
// IT IS APPLIED TO ATTRIBUTE VALUES AND NOWHERE ELSE, because attribute value states are three of
// the exactly five tokenizer states that enter the character reference state. Applying it to
// script data would be the false positive the whole encoding ladder is about: an entity inside
// <script> is six literal characters and executes nothing.
func xssrDecodeEntities(s string) string {
	if !strings.Contains(s, "&") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '&' {
			b.WriteByte(s[i])
			i++
			continue
		}
		semi := strings.IndexByte(s[i:], ';')
		if semi < 0 || semi > 10 {
			b.WriteByte(s[i])
			i++
			continue
		}
		ref := s[i+1 : i+semi]
		switch {
		case strings.HasPrefix(ref, "#x"), strings.HasPrefix(ref, "#X"):
			if n, err := strconv.ParseInt(ref[2:], 16, 32); err == nil && n > 0 && n < 0x110000 {
				b.WriteRune(rune(n))
				i += semi + 1
				continue
			}
		case strings.HasPrefix(ref, "#"):
			if n, err := strconv.ParseInt(ref[1:], 10, 32); err == nil && n > 0 && n < 0x110000 {
				b.WriteRune(rune(n))
				i += semi + 1
				continue
			}
		default:
			if r, ok := xssrNamedEntities[strings.ToLower(ref)]; ok {
				b.WriteString(r)
				i += semi + 1
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

var xssrNamedEntities = map[string]string{
	"lt": "<", "gt": ">", "amp": "&", "quot": "\"", "apos": "'",
	"tab": "\t", "newline": "\n", "nbsp": " ", "colon": ":", "sol": "/",
}

// xssrJavaScriptSchemeAtStart is RX-D4's scheme test, run on the ENTITY-DECODED value.
//
// The URL parser strips leading and embedded C0 controls and ASCII whitespace before resolving a
// scheme, which is why java&#9;script: resolves and %6a does not: percent decoding does not happen
// before scheme resolution and entity decoding does.
func xssrJavaScriptSchemeAtStart(decoded string) bool {
	want := "javascript:"
	i := 0
	for _, wc := range []byte(want) {
		for i < len(decoded) && decoded[i] <= 0x20 {
			i++
		}
		if i >= len(decoded) {
			return false
		}
		c := decoded[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c != wc {
			return false
		}
		i++
	}
	return true
}

// ---------------------------------------------------------------------------------------------
// WHAT THIS CLASS HOLDS ABOUT ITS OWN RESPONSES
// ---------------------------------------------------------------------------------------------

// xssrProbeObs is one of this class's own probes and the response it produced. It is built from
// OwnedResponses, which is the only read there is, and it is a local value: a classifier keeps
// nothing between calls, because a classifier that caches a response in a field hands every other
// class that response through the registry.
type xssrProbeObs struct {
	Probe   triage.ProbeID
	Ordinal uint64
	Marker  triage.Marker
	Obs     triage.Observation
}

type xssrRun struct {
	Items     []xssrProbeObs
	ReadErr   error
	RunnerBug string
	Ordinals  []uint64
	Notes     []string
}

// xssrCollect reads this class's own responses, and refuses to reason about anything else.
//
// A read error is kept rather than skipped. OwnedResponses.At re-checks provenance at the read
// itself and fails closed with ErrForeignObservation if the filter and the vault ever disagree;
// swallowing that would turn a provenance failure into a quiet short sweep, which is a smaller
// number of probes reported as a full one.
func xssrCollect(class triage.ClassID, own triage.OwnedResponses) xssrRun {
	var r xssrRun
	if own.Class() != class && own.Len() > 0 {
		r.ReadErr = fmt.Errorf("triage: class %s was handed a response set belonging to %s", class, own.Class())
		return r
	}
	for i := 0; i < own.Len(); i++ {
		p, obs, err := own.At(i)
		if err != nil {
			r.ReadErr = err
			return r
		}
		it := xssrProbeObs{Probe: p.ProbeID(), Ordinal: p.Ordinal(), Marker: p.Marker(), Obs: obs}
		if why := xssrTemplateSurvived(it); why != "" {
			r.RunnerBug = why
		}
		r.Items = append(r.Items, it)
		r.Ordinals = append(r.Ordinals, p.Ordinal())
	}
	sort.Slice(r.Ordinals, func(a, b int) bool { return r.Ordinals[a] < r.Ordinals[b] })
	return r
}

// xssrTemplateSurvived is the guard on the marker template, and it is the most important five
// lines in this file after the detection rules.
//
// Every payload in this class is declared with xssrTemplateMarker standing in for a marker that
// does not exist until the runner mints one. If the runner ever fails to substitute it, the wire
// carries a marker nobody minted, the response contains no occurrence of the real marker, every
// rule stays silent, and the slot is recorded CLEAN having been tested with a payload that could
// not be attributed to anything. That is precisely the failure this layer exists to stop, so it
// is detected rather than trusted: the payload the runner RECORDED is re-read, and a marker-shaped
// token in it that is not this probe's marker means the substitution did not happen.
func xssrTemplateSurvived(it xssrProbeObs) string {
	payload := it.Obs.Payload.Logical
	if len(payload) == 0 {
		payload = it.Obs.Payload.Wire
	}
	if len(payload) == 0 {
		return ""
	}
	mine := strings.ToLower(string(it.Marker))
	short := xssrShortForm(it.Marker)
	lower := strings.ToLower(string(payload))
	for i := 0; i+16 <= len(lower); i++ {
		if lower[i:i+3] != triage.DefaultMarkerAnchor {
			continue
		}
		tok := lower[i : i+16]
		if !triage.Marker(tok).WellFormed() {
			continue
		}
		if tok == mine || (short != "" && strings.HasPrefix(tok, short)) {
			continue
		}
		return fmt.Sprintf("runner_bug: probe %s went out carrying marker-shaped token %q, which is not the marker %q "+
			"minted for it. The payload template was not substituted, so nothing in the response can be attributed "+
			"to this probe and no silence from it means anything",
			it.Probe, tok, it.Marker)
	}
	return ""
}

// xssrShortForm is the nine-byte narrow-field rendering of a marker: anchor plus the six ordinal
// digits, skipping the run id. RX-SM asks the runner for it, and the template guard has to accept
// it or it would report the class's own short marker as a foreign token.
func xssrShortForm(m triage.Marker) string {
	if !m.WellFormed() {
		return ""
	}
	s := string(m)
	return s[:triage.MarkerAnchorLen] + s[triage.MarkerAnchorLen+triage.MarkerRunIDLen:triage.MarkerAnchorLen+triage.MarkerRunIDLen+triage.MarkerOrdinalLen]
}

// xssrExpectedName is what RX-D1 compares a tag name against: the full marker, or the short form
// for the narrow-field probe.
func xssrExpectedName(it xssrProbeObs) string {
	if it.Probe == xssrPSM {
		return xssrShortForm(it.Marker)
	}
	return strings.ToLower(string(it.Marker))
}

func (r xssrRun) item(id triage.ProbeID) (xssrProbeObs, bool) {
	for _, it := range r.Items {
		if it.Probe == id {
			return it, true
		}
	}
	return xssrProbeObs{}, false
}

func (r xssrRun) sent(id triage.ProbeID) bool {
	_, ok := r.item(id)
	return ok
}

// CensusPlacements is the promotion input: every context the class's own bare-marker probes
// landed in, deduplicated on the tuple that decides which payload answers it.
//
// NO AGGREGATION AND NO "PRIMARY". Three contexts produce three rows and the ladder plans for all
// three, because a payload that works in one is inert in the others.
func (r xssrRun) CensusPlacements() []xssrPlacement {
	seen := map[string]bool{}
	var out []xssrPlacement
	for _, id := range []triage.ProbeID{xssrP0r, xssrP0a, xssrP0h, xssrPSM} {
		it, ok := r.item(id)
		if !ok || !it.Obs.Delivered() {
			continue
		}
		renders, _ := xssrResponseRenders(it.Obs, it.Probe)
		jsonBody := xssrLooksLikeJSON(it.Obs)
		var placements []xssrPlacement
		if renders || !jsonBody {
			// A JSON document that does not render has no markup contexts at all, and a tokenizer
			// run over it reports the marker in "html text" on a document with no elements in it.
			// That placement would promote RX-1 and then score its silence, which is a context
			// that does not exist being tested and then recorded.
			placements = xssrClassifyPlacements(it.Obs.Body, xssrTokenize(it.Obs.Body), xssrCensusNeedle(it))
		}
		for _, pl := range placements {
			key := pl.Context + "|" + pl.TagName + "|" + pl.AttrName + "|" + pl.ScriptType + "|" + string(pl.Quote)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, pl)
		}
		// A JSON body is not markup, and the tokenizer would place the marker in html text on a
		// document that has no elements at all. The JSON placement is its own context and its own
		// honest answer, because nothing in an HTTP response says whether a SPA writes that value
		// into the DOM.
		if jsonBody && len(xssrFindMarker(it.Obs.Body, xssrCensusNeedle(it))) > 0 {
			if !seen[xssrCtxJSONString] {
				seen[xssrCtxJSONString] = true
				out = append(out, xssrPlacement{Context: xssrCtxJSONString, Executable: "unknown",
					Detail: "needs_dom_run: the value round-trips in a JSON document and no response can say whether it reaches a DOM sink"})
			}
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Context < out[b].Context })
	return out
}

func xssrCensusNeedle(it xssrProbeObs) string {
	if it.Probe == xssrPSM {
		return xssrShortForm(it.Marker)
	}
	return string(it.Marker)
}

func xssrLooksLikeJSON(obs triage.Observation) bool {
	if obs.Proj.JSONParsed {
		return true
	}
	b := bytes.TrimSpace(obs.Body)
	return len(b) > 1 && (b[0] == '{' || b[0] == '[')
}

// ConfirmationRungs is A.3: the three cases where a first result is weak, each with its own
// follow-up, all of them this class's own probes.
func (r xssrRun) ConfirmationRungs() []triage.ProbeID {
	var out []triage.ProbeID
	hits := r.Hits()
	byRule := map[string]bool{}
	inert := false
	for _, h := range hits {
		byRule[h.Rule] = true
		if h.Inert != "" {
			inert = true
		}
	}
	// Case 1: the < came back and nothing parsed. RX-1c drops the > entirely and lets the page's
	// own > close the tag.
	if !byRule["RX-D1"] && r.sent(xssrP1) && byRule["RX-D5"] {
		out = append(out, xssrP1c)
	}
	// Case 2: the element formed inside an inert container. RX-1t prefixes rather than replaces,
	// which on a templated page frequently moves the reflection out of it.
	if inert {
		out = append(out, xssrP1t)
	}
	// Case 3: the marker came back with the < GONE and no &lt; anywhere. That is the allowlist
	// sanitizer signature and RX-1s is the probe that names it.
	if !byRule["RX-D1"] && r.sent(xssrP1) {
		if it, ok := r.item(xssrP1); ok && xssrAngleBracketScrubbed(it) {
			out = append(out, xssrP1s)
		}
	}
	return out
}

// xssrAngleBracketScrubbed reports the signature that separates an ENCODER from a SCRUBBER: an
// encoder leaves &lt; behind, a scrubber leaves nothing at all. Telling them apart is what stops
// a body-rewriting WAF being recorded as a correctly escaping application.
func xssrAngleBracketScrubbed(it xssrProbeObs) bool {
	occ := xssrFindMarker(it.Obs.Body, string(it.Marker))
	if len(occ) == 0 {
		return false
	}
	w := xssrSurvivalRegion(it.Obs.Body, occ, false, xssrPayloadTail(it.Probe))
	return !bytes.Contains(w, []byte("<")) && !bytes.Contains(bytes.ToLower(w), []byte("&lt;"))
}

// THE SURVIVAL REGION, AND WHY IT IS NOT A FIXED WINDOW.
//
// The framework's existing reflection probe looks 128 bytes past its canary. That is too wide for
// a rule about THIS payload's characters: a reflection into <p>MARKER</p> has a < eleven bytes
// later that belongs to the page, so a 128-byte window reports "the angle bracket survived" on an
// application that encoded every byte we sent. The region is therefore bounded by the payload's
// OWN rendered extent: from the first occurrence of the marker to a little past the last one,
// which is where this payload's remaining bytes are and where the page's markup is not.
//
// The scheme probes are the one family whose characters come BEFORE the marker, so they look
// behind it instead, far enough for the longest scheme rung (&#106;avascript: is sixteen bytes).
const xssrSchemeLookBehind = 24

// IT IS ONE REGION PER OCCURRENCE AND IT USED TO BE ONE SPAN FROM THE FIRST TO THE LAST, which is
// the same bug the doc comment above was written to prevent, one level up. An application that
// renders the value TWICE puts its own markup between the two reflections, and a span from the
// first marker to the last swallows all of it.
//
// MEASURED, exam ef8c13ab: /xss/encoded htmlspecialchars-es every byte and renders the value in a
// div and again in an input value attribute. RX-2 carries two markers, so there were four
// occurrences, the span ran from the first to the fourth, and it contained the page's own
// <input name="q" value=". The class reported character_survival, "the bytes this context needs
// (") came back raw beside the marker", against an application that had encoded every quote it
// was sent to &#34;. The quote it found was the page's.
//
// So each occurrence gets its own region, bounded by this payload's own extent around THAT
// occurrence, and the regions are joined with a NUL. The NUL is not cosmetic: every caller asks
// "does the region contain this needle", no needle in this class contains a NUL, and joining with
// one means no match can be assembled across the gap between two reflections.
func xssrSurvivalRegion(body []byte, occ []xssrOccurrence, before bool, tail int) []byte {
	var regions [][]byte
	for _, o := range occ {
		if o.Offset < 0 || o.Offset > len(body) {
			continue
		}
		if before {
			start := o.Offset - xssrSchemeLookBehind
			if start < 0 {
				start = 0
			}
			regions = append(regions, body[start:o.Offset])
			continue
		}
		end := o.Offset + o.Length + tail
		if end > len(body) {
			end = len(body)
		}
		if end < o.Offset {
			end = o.Offset
		}
		regions = append(regions, body[o.Offset:end])
	}
	if len(regions) == 0 {
		return nil
	}
	return bytes.Join(regions, []byte{0})
}

// xssrPayloadTail is how many bytes this probe writes AFTER its last marker, read from the
// declaration rather than guessed.
//
// It is what bounds the survival region on the right. A fixed slack of even ten bytes reaches
// past the payload into the page: a reflection into <p>MARKER</p> puts the page's own < five
// bytes after the payload ends, and a survival rule that sees it reports "the angle bracket came
// back" on an application that encoded every byte we sent.
func xssrPayloadTail(id triage.ProbeID) int {
	logical := string(xssrLogicalFor(id))
	if i := strings.LastIndex(logical, xssrTemplateMarker); i >= 0 {
		return len(logical) - i - len(xssrTemplateMarker)
	}
	if i := strings.LastIndex(logical, xssrTemplateShortMarker); i >= 0 {
		return len(logical) - i - len(xssrTemplateShortMarker)
	}
	return 0
}

// ---------------------------------------------------------------------------------------------
// THE RULES
// ---------------------------------------------------------------------------------------------

type xssrHit struct {
	Rule      string
	Oracle    string
	Probe     triage.ProbeID
	Ordinal   uint64
	ObsID     string
	Offset    int
	Length    int
	Matched   []byte
	Context   string
	Detail    string
	Form      xssrMarkerForm
	Secondary bool   // RX-D5 only: ceiling suspicious, never a finding
	Downgrade string // a named reason to cap this hit at suspicious
	Inert     string // an inert container the hit landed inside
	Wire      triage.PayloadWire
}

// Hits runs the five rules over every probe response this class holds.
func (r xssrRun) Hits() []xssrHit {
	var out []xssrHit
	for _, it := range r.Items {
		if it.Probe == xssrPNC2 || it.Probe == xssrPNC3 {
			continue // the controls are scored by ControlFired, not by the ladder
		}
		out = append(out, xssrRulesFor(it)...)
	}
	return out
}

// ControlFired is NC-A1, NC-A2 and NC-A3 as a run-time assertion.
//
// If the bare census marker, the metacharacter-free control or the entity control produces an
// element, an attribute, a lexer transition or a scheme, the detector is matching text and every
// verdict this class would emit on this slot is cannot_determine (detector_unverified). A
// detector that has been shown firing on its own negative control is broken, and a broken
// detector's silence elsewhere is worthless.
func (r xssrRun) ControlFired() (bool, string) {
	for _, id := range []triage.ProbeID{xssrP0r, xssrP0a, xssrPNC2, xssrPNC3} {
		it, ok := r.item(id)
		if !ok {
			continue
		}
		for _, h := range xssrRulesFor(it) {
			if h.Secondary {
				continue
			}
			return true, fmt.Sprintf("detector_unverified: %s fired on control %s, which carries %s. %s",
				h.Rule, id, xssrControlCarries(id), xssrControlWhyItMatters(id))
		}
	}
	return false, ""
}

func xssrControlCarries(id triage.ProbeID) string {
	switch id {
	case xssrP0r, xssrP0a:
		return "the bare marker and no metacharacter at all"
	case xssrPNC2:
		return "the letters x and y where < and > would be"
	default:
		return "the marker with &lt; and &gt; as character references"
	}
}

func xssrControlWhyItMatters(id triage.ProbeID) string {
	if id == xssrPNC3 {
		return "A character reference decodes to a character token and can never produce a tag, so a rule firing " +
			"here means the detector is searching for text rather than reading a parse tree"
	}
	return "A payload with no metacharacter cannot change a parse tree, so a rule firing here means the detector " +
		"is searching for text rather than reading a parse tree"
}

// xssrRulesFor is the whole detection rule set for one probe response.
func xssrRulesFor(it xssrProbeObs) []xssrHit {
	obs := it.Obs
	if !obs.Delivered() || len(obs.Body) == 0 {
		return nil
	}
	name := xssrExpectedName(it)
	if name == "" {
		return nil
	}
	// Attribution gates, in order. Each one produces NO hit rather than a weak one, because a hit
	// nobody can attribute is a hit for nobody (ruling R12).
	if obs.RunID != "" && it.Marker.WellFormed() && it.Marker.RunID() != obs.RunID {
		return nil // stale_marker: a cached or replayed body carrying another run's token
	}
	if it.Marker.WellFormed() && !it.Marker.BelongsTo(triage.ClassXSSReflected) {
		return nil // foreign_marker_observed
	}
	downgrade := ""
	if it.Marker.Integrity() != triage.MarkerValid {
		downgrade = "marker_checksum_" + string(it.Marker.Integrity()) + ": attribution is unsafe, so the hit is capped at suspicious"
	}
	renders, mediaWhy := xssrResponseRenders(obs, it.Probe)
	doc := xssrTokenize(obs.Body)
	var out []xssrHit
	mk := func(rule, oracle string, off, length int, ctxName, detail string) xssrHit {
		h := xssrHit{Rule: rule, Oracle: oracle, Probe: it.Probe, Ordinal: it.Ordinal, ObsID: obs.ObsID,
			Offset: off, Length: length, Context: ctxName, Detail: detail, Downgrade: downgrade,
			Wire: obs.Payload, Form: xssrFormRaw}
		if off >= 0 && off+length <= len(obs.Body) {
			h.Matched = append([]byte(nil), obs.Body[off:off+length]...)
		}
		return h
	}

	// RX-D1, element creation. A start tag whose LOWERED NAME EQUALS the marker.
	for _, t := range doc.Tokens {
		if t.Kind != xssrTokStartTag {
			continue
		}
		if xssrTruncatedTail(obs, t.NameStart) {
			continue
		}
		switch {
		case t.Name == name:
			if !renders {
				continue
			}
			h := mk("RX-D1", "element_created", t.NameStart, len(name), xssrCtxTagName,
				"the tokenizer emitted a start tag whose name IS this run's marker, so the application let this "+
					"value open an element: that is a parse-tree state change and not a reflection")
			h.Inert = xssrInertContainer(t.Stack)
			if h.Inert != "" {
				h.Downgrade = "inert_container=" + h.Inert + ": the element formed but nothing inside that container runs. The breakout is still proven"
			}
			out = append(out, h)
		case strings.Contains(t.Name, name) && t.Name != name:
			h := mk("RX-D5", "tag_name_mangled", t.NameStart, len(t.Name), xssrCtxTagName,
				"a tag name CONTAINS the marker but is not equal to it, so something rewrote the name. That is a "+
					"near miss worth a look and it is not an element this value created")
			h.Secondary = true
			out = append(out, h)
		}
		// RX-D2, attribute creation. An attribute whose NAME equals the marker, anywhere.
		for _, a := range t.Attrs {
			if a.Name != name || !renders {
				continue
			}
			if xssrTruncatedTail(obs, a.NameStart) {
				continue
			}
			h := mk("RX-D2", "attribute_created", a.NameStart, len(a.Name), xssrCtxAttrName,
				"an attribute NAMED by this run's marker exists on <"+t.Name+">, so the value escaped its own "+
					"attribute and named a new one. An attribute whose VALUE contains the marker is not this, and "+
					"that is the entire discrimination")
			h.Inert = xssrInertContainer(t.Stack)
			if xssrInertHostElement(t.Name) {
				h.Detail += ". The host element " + t.Name + " is inert, which lowers the exploitability note and " +
					"changes nothing about the breakout"
			}
			out = append(out, h)
		}
		// RX-D4, URL scheme at value offset 0.
		for _, a := range t.Attrs {
			if !xssrURLAttributes[a.Name] || a.ValueEnd <= a.ValueStart {
				continue
			}
			dec := xssrDecodeEntities(a.Value)
			if !strings.Contains(strings.ToLower(dec), name) {
				continue
			}
			if xssrJavaScriptSchemeAtStart(dec) {
				if !renders {
					continue
				}
				h := mk("RX-D4", "url_scheme", a.ValueStart, a.ValueEnd-a.ValueStart, xssrCtxURLScheme,
					"a URL-bearing attribute resolves to the javascript scheme at value offset 0 after HTML entity "+
						"decoding, and the value carries this run's marker")
				if a.Name == "xlink:href" && !xssrStackHas(t.Stack, "svg") {
					h.Downgrade = "xlink_href_outside_svg: current browsers block the javascript scheme here"
				}
				out = append(out, h)
			} else if strings.HasPrefix(strings.ToLower(strings.TrimSpace(dec)), "data:") {
				h := mk("RX-D5", "data_scheme_reachable", a.ValueStart, a.ValueEnd-a.ValueStart, xssrCtxURLScheme,
					"the value controls a data: URL. Navigation to one is blocked in every current browser, so this "+
						"is not a finding here, but it is a real lead in an iframe src or an object data")
				h.Secondary = true
				out = append(out, h)
			}
		}
		// RX-D3 in an EVENT HANDLER. The attribute value is entity-decoded and the RESULT is
		// handed to the JS parser, which is why the entity rung is executable here and inert
		// inside a script element.
		for _, a := range t.Attrs {
			if !strings.HasPrefix(a.Name, "on") || a.ValueEnd <= a.ValueStart {
				continue
			}
			dec := xssrDecodeEntities(a.Value)
			if hit, conf := xssrJSEscapedInto(dec, name); hit {
				h := mk("RX-D3", "js_lexer_transition_event_handler", a.ValueStart, a.ValueEnd-a.ValueStart,
					xssrCtxEventHandler,
					"inside the "+a.Name+" handler the marker lexes as CODE after the attribute value was entity "+
						"decoded, so the value left the JavaScript string it was written into")
				if conf == "low" {
					h.Downgrade = "js_lexer_low_confidence: the regex-versus-division heuristic was used before this offset"
				}
				out = append(out, h)
			}
		}
	}

	// RX-D3 inside a <script> element.
	for _, t := range doc.Tokens {
		if t.Kind != xssrTokRawText || t.Owner != "script" {
			continue
		}
		if !xssrExecutableScriptType(t.ScriptType) {
			continue // application/json, importmap, text/template: data, not code
		}
		src := obs.Body[t.Start:t.End]
		for _, o := range xssrFindMarker(src, name) {
			st := xssrLexJS(src, o.Offset)
			switch st.State {
			case xssrCtxJSCode, xssrCtxJSTemplateSub:
				h := mk("RX-D3", "js_lexer_transition", t.Start+o.Offset, o.Length, st.State,
					"an occurrence of the marker lexes as "+st.State+" inside an executable script, so the payload "+
						"left the string literal it was written into")
				if st.Confidence == "low" {
					h.Downgrade = "js_lexer_low_confidence: the regex-versus-division heuristic was used before this offset"
				}
				out = append(out, h)
			}
		}
		// The RX-8b sub-rule: a backslash that arrived raw consumes the page's own closing quote,
		// so the literal is unterminated at the end of the script. That, on an app that escapes
		// quotes, is a two-step breakout.
		if it.Probe == xssrP8b && len(xssrFindMarker(src, name)) > 0 {
			if st := xssrLexJS(src, len(src)); st.Unterminated {
				out = append(out, mk("RX-D3", "js_string_unterminated", t.Start, len(src), xssrCtxJSStringSingle,
					"the string literal holding the marker is still open at the end of the script, which means this "+
						"payload's backslash arrived raw and escaped the page's own closing quote"))
			}
		}
	}

	// RX-D5, character survival. Secondary, ceiling suspicious, and it exists to explain a near
	// miss and choose the next probe. A triage layer that reports this as a finding is reporting
	// reflection, which is what the framework's existing probe already does.
	//
	// IT CARRIES THE SAME MEDIA GATE AS EVERY OTHER RULE IN THIS FUNCTION, AND IT DID NOT.
	// MEASURED, exam 2e4433b1: /clean/echo (text/plain with nosniff) and /clean/echomongo (a 400
	// application/json) are CLEAN CONTROLS, and this class answered suspicious on both, from this
	// arm, because the `<` came back raw beside the marker. A character that survives into a body
	// no browser parses as markup cannot open an element, cannot name an attribute and cannot
	// reach a JavaScript lexer: survival there is not a near miss, it is the media type. RX-D1,
	// RX-D2 and RX-D4 all check `renders` before they fire and this one did not, so the one rule
	// that was never allowed to be a finding was the only rule allowed to fire on a document the
	// browser never renders. The negative side now names the gate instead, in
	// xssrMediaGateClosedEverywhere, which is a stronger row than a downgraded near miss: one is
	// "this cannot execute here", the other is "here is a lead, capped".
	if len(out) == 0 && renders {
		if need, before := xssrNeededBytes(it.Probe); len(need) > 0 {
			if occ := xssrFindMarker(obs.Body, name); len(occ) > 0 {
				w := xssrSurvivalRegion(obs.Body, occ, before, xssrPayloadTail(it.Probe))
				for _, n := range need {
					if bytes.Contains(w, []byte(n)) {
						h := mk("RX-D5", "character_survival", occ[0].Offset, occ[0].Length, xssrCtxUnresolved,
							"the bytes this context needs ("+n+") came back raw beside the marker and nothing parsed. "+
								"That is a near miss, never a finding")
						h.Secondary = true
						h.Form = occ[0].Form
						out = append(out, h)
						break
					}
				}
			}
		}
	}
	if !renders && mediaWhy != "" {
		for i := range out {
			if out[i].Downgrade == "" {
				out[i].Downgrade = mediaWhy
			}
		}
	}
	return out
}

// xssrJSEscapedInto lexes a decoded event handler body and reports whether any occurrence of the
// marker sits in code position.
func xssrJSEscapedInto(decoded, marker string) (bool, string) {
	src := []byte(decoded)
	for _, o := range xssrFindMarker(src, marker) {
		st := xssrLexJS(src, o.Offset)
		if st.State == xssrCtxJSCode || st.State == xssrCtxJSTemplateSub {
			return true, st.Confidence
		}
	}
	return false, "high"
}

// xssrNeededBytes is the byte each context's payload must get through, for RX-D5, and whether it
// sits before the marker or after it.
func xssrNeededBytes(id triage.ProbeID) ([]string, bool) {
	switch id {
	case xssrP1, xssrP1c, xssrP1s, xssrP1t, xssrP16, xssrPSM:
		return []string{"<"}, false
	case xssrP2, xssrP5c, xssrP9a:
		return []string{"\""}, false
	case xssrP3, xssrP5a, xssrP8a:
		return []string{"'"}, false
	case xssrP4:
		return []string{" "}, false
	case xssrP5b, xssrP5d:
		return []string{"&#39;", "&#34;", "'", "\""}, false
	case xssrP6a, xssrP6b, xssrP6c:
		// The scheme is written BEFORE the marker, so the region is the bytes behind it.
		return []string{"javascript:", "&#106;", "&#9;"}, true
	case xssrP7, xssrP12, xssrP12t, xssrP13:
		return []string{"</"}, false
	case xssrP8b:
		return []string{"\\"}, false
	case xssrP10a:
		return []string{"${"}, false
	case xssrP10b:
		return []string{"`"}, false
	case xssrP11a:
		return []string{"-->"}, false
	case xssrP11b:
		return []string{"--!>"}, false
	case xssrP15:
		return []string{"*/"}, false
	}
	return nil, false
}

// xssrResponseRenders is RX-D1's media type gate plus the Content-Disposition check.
//
// An element in a body the browser never renders is not an XSS lead. The exception is the one
// that matters: a JSON or text body with a sniffable type and no X-Content-Type-Options renders
// on direct navigation, which is FN-A10 and a commonly missed real finding.
func xssrResponseRenders(obs triage.Observation, probe triage.ProbeID) (bool, string) {
	if cd := strings.ToLower(xssrHeader(obs, "content-disposition")); strings.Contains(cd, "attachment") {
		return false, "response_never_renders: Content-Disposition attachment, so the body is downloaded and never parsed as markup"
	}
	if xssrRendersInABrowser(obs.MediaType) {
		return true, ""
	}
	// Checked BEFORE the sniff branch, because the sniff branch is about a document whose type a
	// browser may reconsider and these are documents whose type it does not.
	if xssrStructuredNotMarkup(obs.MediaType) {
		return false, "needs_dom_run: the response is " + string(obs.MediaType) + ", a structured document " +
			"no browser parses as markup on navigation, so an element the tokenizer found in it is not an XSS " +
			"lead by itself. Whether page JavaScript writes this value into a DOM sink is XSS-DOM's question " +
			"and it needs a browser. This is NOT a clean"
	}
	if xssrSniffable(obs.MediaType) && !strings.Contains(strings.ToLower(xssrHeader(obs, "x-content-type-options")), "nosniff") {
		return true, ""
	}
	if probe == xssrP16 {
		return false, "needs_dom_run: the media type does not render and nosniff is set, so a marker in this document " +
			"can only become script if page JavaScript writes it into the DOM"
	}
	return false, "media_gate_closed: the response media type " + string(obs.MediaType) + " does not render as markup"
}

// xssrTruncatedTail refuses a hit that sits in the last 256 bytes of a body the capture cut off:
// the element may be an artefact of the cut rather than of the application.
func xssrTruncatedTail(obs triage.Observation, off int) bool {
	return obs.BodyTruncated && off > len(obs.Body)-256
}

func xssrInertHostElement(tag string) bool {
	switch tag {
	case "meta", "link", "title", "base", "style", "head", "html":
		return true
	}
	return false
}

// xssrSecondaryReason is the operator-visible text of a secondary hit, WITH its cap.
//
// It exists as a named function because the grading switch's secondary case stops before the case
// that prints Downgrade, so the cap was computed and then thrown away.
func xssrSecondaryReason(h xssrHit) string {
	if h.Downgrade == "" {
		return h.Detail
	}
	return h.Detail + ". " + h.Downgrade
}

func xssrHeader(obs triage.Observation, name string) string {
	for _, h := range obs.RespHeaders {
		if strings.EqualFold(h[0], name) {
			return h[1]
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// THE ENCODER, THE SCRUBBER, AND THE BLOCK
// ---------------------------------------------------------------------------------------------

// xssrIdentifyEncoder is A.9: for this class the "engine" is the output encoder, and naming it
// changes which payload the expensive tool should carry.
//
// It reads the window around the marker in this class's own responses and nowhere else.
func (r xssrRun) IdentifyEncoder() (string, string) {
	for _, id := range []triage.ProbeID{xssrP1, xssrP2, xssrP3, xssrP0r} {
		it, ok := r.item(id)
		if !ok || !it.Obs.Delivered() {
			continue
		}
		occ := xssrFindMarker(it.Obs.Body, string(it.Marker))
		if len(occ) == 0 {
			continue
		}
		w := string(xssrSurvivalRegion(it.Obs.Body, occ, false, xssrPayloadTail(it.Probe)))
		has := func(s string) bool { return strings.Contains(w, s) }
		switch {
		case has("&lt;") && has("&#x27;"):
			return "django.utils.html.escape", "HTML contexts are closed; the event-handler entity rung is the remaining route"
		case has("&lt;") && has("&#039;"):
			return "php.htmlspecialchars(ENT_QUOTES)", "HTML contexts are closed; the event-handler entity rung is the remaining route"
		case has("&lt;") && has("&#34;") && has("&#39;"):
			return "go.html.EscapeString or jinja2.autoescape", "both close the HTML contexts; the Server header disambiguates"
		case has("&lt;") && has("&quot;") && has("&#39;"):
			return "rails.ERB::Util.html_escape", "HTML contexts are closed; the event-handler entity rung is the remaining route"
		case has("&lt;") && has("&quot;") && strings.Contains(w, "'"):
			return "php.htmlspecialchars(no ENT_QUOTES)", "SINGLE-QUOTED attributes and single-quoted JS strings are LIVE: point dalfox at single-quote payloads"
		case has("&lt;"):
			return "an unidentified HTML escaper", "the angle brackets are encoded and the quote behaviour was not observed"
		}
	}
	return "", ""
}

// UniformBlock is foundations 5.8 reached from THIS class's own payloads only.
//
// Three identical non-baseline responses to three different payloads is a block page, and a block
// page is cannot_determine (blocked): no finding, and emphatically no clean. The cross-class
// annotation exists elsewhere and is downgrade-only; this is the per-class rule and it is the one
// a verdict may rest on.
func (r xssrRun) UniformBlock(route triage.Replay) (bool, string) {
	counts := map[string]int{}
	status := map[string]int{}
	for _, it := range r.Items {
		if !it.Obs.Delivered() || len(it.Obs.Body) == 0 {
			continue
		}
		k := xssrBodyKey(it.Obs)
		counts[k]++
		status[k] = it.Obs.Status
	}
	baseline := ""
	if route.Resolved() {
		baseline = xssrBodyKey(route.Obs())
	}
	for k, n := range counts {
		if n >= 3 && k != baseline {
			return true, fmt.Sprintf("blocked: %d of this class's own distinct payloads produced a byte-identical "+
				"status %d response that is not the route control's, so every probe was answered by the same page and "+
				"none of them reached the application", n, status[k])
		}
	}
	return false, ""
}

// MarkerSeenAnywhere is precondition 1 of the clean: the marker is absent from the body, from
// every response header, and from every redirect hop, in every transform form.
//
// A MARKER THAT DID NOT COME BACK IS ONLY CLEAN WHEN YOU CAN SHOW THE REQUEST ARRIVED AND THE
// FIELD WAS WIDE ENOUGH. That is what the other four preconditions are for.
func xssrBodyKey(o triage.Observation) string {
	// THE KEY IS THE BODY AND NOT BodySHA256, and that is not a style choice. BodySHA256 is filled
	// by the capture path; a zero value is what an unfilled field looks like, and keying on it
	// would make EVERY response identical to every other, so a healthy endpoint would read as a
	// uniform block and every slot on it would be cannot_determine. A block that is not there is
	// a cheaper error than a block that is missed, but both are wrong, and a classifier cannot
	// hash (crypto is not on the allow-list and does not need to be: these are a handful of
	// bodies, already in memory, for the length of one comparison).
	return strconv.Itoa(o.Status) + "|" + strconv.Itoa(o.BodyLen) + "|" + string(o.Body)
}

func (r xssrRun) MarkerSeenAnywhere() (bool, string) {
	for _, it := range r.Items {
		needle := xssrCensusNeedle(it)
		if needle == "" {
			continue
		}
		if len(xssrFindMarker(it.Obs.Body, needle)) > 0 {
			return true, "body"
		}
		for _, h := range it.Obs.RespHeaders {
			if len(xssrFindMarker([]byte(h[1]), needle)) > 0 {
				return true, "header:" + strings.ToLower(h[0])
			}
		}
		for _, hop := range it.Obs.RedirectChain {
			if len(xssrFindMarker([]byte(hop.Location), needle)) > 0 {
				return true, "redirect_location"
			}
		}
		for _, hit := range it.Obs.Proj.MarkerHits {
			if hit.Marker == it.Marker {
				return true, "projection:" + hit.Form
			}
		}
	}
	return false, ""
}

// ---------------------------------------------------------------------------------------------
// THE VERDICT
// ---------------------------------------------------------------------------------------------

// Classify is the answer, and the shape of this function is the shape of the rule that matters:
// EVERY WAY THIS CLASS CAN FAIL TO GET AN ANSWER HAS ITS OWN STATE, AND NONE OF THEM IS CLEAN.
//
// There are eleven of them before a rule is even run (ineligible slot, unreadable own responses,
// nothing sent, a template the runner did not substitute, a control that fired, a transport that
// refused, a uniform block, a marker in the unperturbed response, a drifted endpoint, a degraded
// comparison, an exhausted budget), and clean is reserved for "my own probes ran, faithfully
// reached the wire, and my own oracles stayed silent with all five preconditions holding".
func (c xssReflectedClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	return xssrClassify(ctx, xssrCollect(c.ID(), ctx.Own))
}

// xssrClassify is Classify with the responses already read.
//
// The split exists so the verdict logic can be tested. OwnedResponses can only be built by the
// runner, which holds the capability, so a test that could not reach this function could only
// ever exercise the paths where this class has no responses at all: the eleven unknowns would be
// covered and the two negatives and every positive would not.
func xssrClassify(ctx triage.ClassifyCtx, run xssrRun) []triage.ClassVerdict {
	el := xssrEligible(ctx.PlanCtx)
	if !el.OK {
		return []triage.ClassVerdict{xssrVerdict(ctx.Slot.Key, el.State, el.Reason)}
	}
	return xssrClassifyEligible(ctx, run, el)
}

// xssrClassifyEligible is the verdict logic for a slot this class is allowed to probe.
//
// THE SECOND SPLIT IS ALSO FOR TESTABILITY AND THE REASON IS WORTH WRITING DOWN. Eligibility
// requires the vector's route control to have RESOLVED, and a resolved triage.Replay can only be
// built by NewReplay, which takes the runner capability, whose type lives in an internal package
// this one cannot import. So no test in this package can build a ctx that passes xssrEligible.
// Without this split every test of this class would exercise one branch: route_unresolved. The
// gate itself is tested on xssrEligible, where it can be.
func xssrClassifyEligible(ctx triage.ClassifyCtx, run xssrRun, el xssrEligibility) []triage.ClassVerdict {
	slot := ctx.Slot.Key
	ann := xssrAnnotations(ctx, run)
	untested := xssrUntested(ctx.PlanCtx, run)
	finish := func(vs ...triage.ClassVerdict) []triage.ClassVerdict {
		for i := range vs {
			vs[i].Untested = untested
			if vs[i].Annotations == nil {
				vs[i].Annotations = ann
			}
		}
		return vs
	}

	if run.ReadErr != nil {
		return finish(xssrVerdict(slot, triage.StateCannotDetermine,
			"own_responses_unreadable: the vault refused to hand this class one of its own responses ("+
				run.ReadErr.Error()+"), so nothing was scored. A provenance failure is an unknown and never a short sweep"))
	}
	if len(run.Items) == 0 {
		if ctx.Budget.Exhausted() {
			return finish(xssrVerdict(slot, triage.StateNotRun,
				"probe_budget_exhausted: the budget was spent before this slot's census went out, so not one byte "+
					"was sent here and nothing at all is known about it"))
		}
		return finish(xssrVerdict(slot, triage.StateNotPlanned,
			"no probe was derived for this slot and no response is in hand, so this class measured nothing here"))
	}
	if run.RunnerBug != "" {
		return finish(xssrVerdict(slot, triage.StateCannotDetermine, run.RunnerBug))
	}
	if fired, why := run.ControlFired(); fired {
		return finish(xssrVerdict(slot, triage.StateCannotDetermine, why))
	}
	if why, ok := xssrAllUndelivered(run); ok {
		return finish(xssrVerdict(slot, triage.StateCannotDetermine, why))
	}
	if blocked, why := run.UniformBlock(ctx.Route); blocked {
		return finish(xssrVerdict(slot, triage.StateCannotDetermine, why))
	}
	if where, ok := xssrMarkerInUnperturbed(ctx, run); ok {
		return finish(xssrVerdict(slot, triage.StateCannotDetermine,
			"not_stored_or_cached_undecided: this run's marker came back in "+where+", which carried no payload of "+
				"ours. That is storage or a cache, not reflection, and it is XSS-STORED's and CACHE's question. "+
				"This class refuses to claim it and refuses to call the slot clean on the strength of it"))
	}

	hits := run.Hits()
	for _, h := range hits {
		if !h.Secondary {
			// A PRIMARY rule fired. RX-D5 alone never takes this path: character survival is the
			// state where the byte came back and nothing parsed, and reporting that as a finding
			// is reporting reflection, which is what the framework's existing probe already does.
			return finish(xssrPositiveVerdicts(ctx, run, hits, ann)...)
		}
	}
	return finish(xssrNegativeVerdicts(ctx, run, el, ann, hits)...)
}

func xssrVerdict(slot triage.SlotKey, state triage.TriageState, reason string) triage.ClassVerdict {
	return triage.ClassVerdict{Class: triage.ClassXSSReflected, SlotKey: slot, State: state, Reason: reason}
}

func xssrAllUndelivered(run xssrRun) (string, bool) {
	kinds := map[triage.TransportErrKind]int{}
	for _, it := range run.Items {
		if it.Obs.Delivered() {
			return "", false
		}
		kinds[it.Obs.TransportErr]++
	}
	var names []string
	for k, n := range kinds {
		names = append(names, fmt.Sprintf("%s x%d", k, n))
	}
	sort.Strings(names)
	return "could_not_send: every one of this class's probes was refused by the transport (" +
		strings.Join(names, ", ") + "), so the application never saw one of them. A refusal is not a quiet response", true
}

// xssrMarkerInUnperturbed asks whether this run's marker came back in a response that carried no
// payload of ours: the route control or the post-baseline.
//
// That is the reflection-versus-storage discrimination from this side of it. A marker in an
// unperturbed response means the value was stored, or a cache is serving somebody else's body,
// and either way a reflected-XSS verdict drawn from it would be wrong in both directions.
func xssrMarkerInUnperturbed(ctx triage.ClassifyCtx, run xssrRun) (string, bool) {
	check := func(name string, r triage.Replay) (string, bool) {
		if !r.Resolved() {
			return "", false
		}
		o := r.Obs()
		for _, it := range run.Items {
			if n := xssrCensusNeedle(it); n != "" && len(xssrFindMarker(o.Body, n)) > 0 {
				return name, true
			}
		}
		return "", false
	}
	if w, ok := check("the post-baseline, which is a replay at the slot's observed value", ctx.PostBaseline); ok {
		return w, true
	}
	return check("the route control, which carried no payload", ctx.Route)
}

// xssrPositiveVerdicts turns hits into rows, one per (rule, context) group.
//
// A SLOT CAN CARRY SEVERAL ROWS AND THAT IS DELIBERATE. A response with the marker in html text,
// in an href and in a JS string is three placements with three different answers, and folding
// them into one verdict loses two of them.
func xssrPositiveVerdicts(ctx triage.ClassifyCtx, run xssrRun, hits []xssrHit, ann map[string]any) []triage.ClassVerdict {
	type key struct{ rule, context string }
	groups := map[key][]xssrHit{}
	var order []key
	for _, h := range hits {
		k := key{h.Rule, h.Context}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], h)
	}
	sort.Slice(order, func(a, b int) bool {
		if order[a].rule != order[b].rule {
			return order[a].rule < order[b].rule
		}
		return order[a].context < order[b].context
	})

	encoder, encoderNote := run.IdentifyEncoder()
	csp := xssrCSPNote(run)
	var out []triage.ClassVerdict
	for _, k := range order {
		g := groups[k]
		best := g[0]
		ordinals := map[uint64]bool{}
		for _, h := range g {
			ordinals[h.Ordinal] = true
			if h.Downgrade == "" && best.Downgrade != "" {
				best = h
			}
		}
		state := triage.StateFinding
		grade := triage.GradeMedium
		reason := best.Detail
		switch {
		case best.Secondary:
			state, grade = triage.StateSuspicious, triage.GradeLow
			// A secondary hit carries its cap in the TEXT, because the switch stops here and the
			// Downgrade would otherwise never be printed. MEASURED, exam ef8c13ab: on
			// /clean/echomongo (application/json) and /clean/echo (text/plain with nosniff) the row
			// read "the bytes this context needs came back raw beside the marker" and said nothing
			// about the response being a document no browser parses as markup. A near miss is the
			// right state there, since it is what tells the operator which payload to try next, but
			// a near miss that hides the media gate reads as a lead.
			reason = xssrSecondaryReason(best)
		case best.Downgrade != "":
			state, grade = triage.StateSuspicious, triage.GradeLow
			reason = best.Detail + ". Capped at suspicious: " + best.Downgrade
		case ctx.Baseline.Degraded:
			state, grade = triage.StateSuspicious, triage.GradeLow
			reason = best.Detail + ". Capped at suspicious: the comparison for this endpoint is degraded " +
				"(an oversized, truncated or unparseable body), and a degraded comparison never produces a high grade"
		case csp != "":
			state, grade = triage.StateSuspicious, triage.GradeMedium
			reason = best.Detail + ". Capped at suspicious: " + csp +
				". CSP is a mitigation and not a refutation, so the tool is still pointed here: false negatives are the expensive error"
		case len(ordinals) > 1:
			// Reproduced with a FRESH MARKER by a second probe of this class. That is the guard
			// CATALOGUE 4.2 requires for the high grade, and it is the difference between an
			// oracle that fired and an oracle that fired twice for the same reason.
			grade = triage.GradeHigh
			reason = best.Detail + ". Reproduced by " + strconv.Itoa(len(ordinals)) + " of this class's probes, each with its own marker"
		}
		v := xssrVerdict(ctx.Slot.Key, state, reason)
		v.Grade = grade
		v.Oracle = best.Oracle
		for o := range ordinals {
			v.Ordinals = append(v.Ordinals, o)
		}
		sort.Slice(v.Ordinals, func(a, b int) bool { return v.Ordinals[a] < v.Ordinals[b] })
		v.Evidence = triage.TriageEvidence{
			Ordinal: best.Ordinal, ObsID: best.ObsID, Matched: best.Matched,
			Offset: best.Offset, Length: best.Length, Phrase: best.Rule + " " + best.Oracle,
			Wire: best.Wire, MarkerForm: string(best.Form),
		}
		v.Label = xssrLabel(ctx, best, encoder)
		v.Annotations = xssrCopyAnnotations(ann)
		v.Annotations["rule"] = best.Rule
		v.Annotations["probe"] = string(best.Probe)
		if best.Inert != "" {
			v.Annotations["inert_container"] = best.Inert
		}
		if encoderNote != "" {
			v.Annotations["encoder_note"] = encoderNote
		}
		out = append(out, v)
	}
	// Every placement the census found that no probe answered gets its own row. A placement that
	// was found and never probed is an untested context, and an untested context inside a slot
	// that also produced a finding is exactly the row that would otherwise disappear.
	out = append(out, xssrUnprobedPlacementRows(ctx, run, ann)...)
	return out
}

// xssrUnprobedPlacementRows names the contexts the census found and the ladder never answered.
func xssrUnprobedPlacementRows(ctx triage.ClassifyCtx, run xssrRun, ann map[string]any) []triage.ClassVerdict {
	var out []triage.ClassVerdict
	for _, pl := range run.CensusPlacements() {
		promoted := xssrProbesForContext(pl.Context, ctx.Vector.RespMedia)
		if pl.Context == xssrCtxCSSInAttr {
			v := xssrVerdict(ctx.Slot.Key, triage.StateNotApplicable,
				"css_attr_reflection: the value lands in a style attribute. IE's expression() is gone and no current "+
					"engine executes script from one, so this is an exfiltration and UI-redress surface and it is "+
					"reported as informational rather than as an XSS lead. Reporting it as a lead is how a triage "+
					"layer earns being ignored")
			v.Annotations = xssrCopyAnnotations(ann)
			v.Annotations["informational"] = "css_attr_reflection"
			out = append(out, v)
			continue
		}
		if pl.Context == xssrCtxJSONString {
			// FN-A9. The value round-trips in a document that is not markup, and NOTHING IN THE
			// RESPONSE can say whether page JavaScript later writes it into a DOM sink. RX-16
			// answers only the narrow case where the document renders on direct navigation; the
			// rest is XSS-DOM's, and this class does not borrow its answer or report clean in
			// its place.
			detail := "RX-16 did not run, so even the renders-on-navigation case is untested"
			if xssrStructuredNotMarkup(ctx.Vector.RespMedia) {
				detail = "RX-16 was not sent because this response is " + string(ctx.Vector.RespMedia) +
					", which no browser parses as markup on navigation, so the renders-on-navigation case is " +
					"settled without a probe and nothing else is"
			}
			if run.sent(xssrP16) {
				detail = "RX-16 ran and no element formed, which settles the renders-on-navigation case and nothing else"
			}
			v := xssrVerdict(ctx.Slot.Key, triage.StateCannotDetermine,
				"needs_dom_run: the marker round-trips inside a JSON document. "+detail+". Whether a SPA writes that "+
					"value into the DOM is XSS-DOM's question and it needs a browser")
			v.Annotations = xssrCopyAnnotations(ann)
			v.Annotations["needs_dom_run"] = true
			out = append(out, v)
			continue
		}
		if len(promoted) == 0 {
			v := xssrVerdict(ctx.Slot.Key, triage.StateNotPlanned,
				"no payload in this class answers the context "+pl.Context+", so the context was found and left "+
					"untested. Naming the gap beats leaving a hole shaped like one")
			v.Annotations = xssrCopyAnnotations(ann)
			out = append(out, v)
			continue
		}
		var missing []string
		for _, id := range promoted {
			if !run.sent(id) {
				missing = append(missing, string(id))
			}
		}
		if len(missing) == 0 {
			continue
		}
		state, why := triage.StateNotRun, "the ladder did not reach them"
		if ctx.Budget.Exhausted() {
			why = "probe_budget_exhausted: the run budget was spent"
		}
		if len(run.Items) >= xssrPerSlotCap {
			why = "probe_budget_exhausted: this class's own per-slot cap of " + strconv.Itoa(xssrPerSlotCap) +
				" probes was reached, and the thirteenth is refused rather than sent"
		}
		if r := xssrProbeReachesSlot(triage.ProbeID(missing[0]), ctx.Slot); !r.OK {
			state, why = r.State, r.Reason
		}
		v := xssrVerdict(ctx.Slot.Key, state,
			"the census placed the marker in "+pl.Context+" and "+strings.Join(missing, ", ")+
				" did not run: "+why+". The context is therefore untested, which is not the same as untouched and "+
				"is not the same as clean")
		v.Annotations = xssrCopyAnnotations(ann)
		out = append(out, v)
	}
	return out
}

// xssrNegativeVerdicts is the half of this class that has to be got right, because it is the half
// that produces a green tick.
func xssrNegativeVerdicts(ctx triage.ClassifyCtx, run xssrRun, el xssrEligibility, ann map[string]any, near []xssrHit) []triage.ClassVerdict {
	slot := ctx.Slot.Key
	rows := xssrUnprobedPlacementRows(ctx, run, ann)
	seen, where := run.MarkerSeenAnywhere()

	if !seen {
		// THE FIVE PRECONDITIONS OF clean (no_reflection). A marker that did not come back is
		// only clean when you can show the request arrived and the field was wide enough.
		if !run.sent(xssrP0r) || !run.sent(xssrP0a) {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine,
				"census_incomplete: the replace form and the append form are both required before an absence means "+
					"anything, because an integer-cast or shape-validating field discards one and reflects the other"))
		}
		if why, ok := xssrWireUnproven(run); ok {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine, why))
		}
		del := xssrDeliveryEvidence(ctx.Route.Obs(), ctx.Route.Resolved(), ctx.Slot, run)
		if !del.Delivered {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine, del.Why))
		}
		if lim := ctx.Slot.Constraints.FieldLimit; lim > 0 && lim < triage.MarkerLen {
			if !run.sent(xssrPSM) {
				return append(rows, xssrVerdict(slot, triage.StateCannotDetermine,
					fmt.Sprintf("truncated: the field truncates at %d bytes, which is shorter than the %d-byte marker, "+
						"so an absence measures the truncation and not the application. RX-SM's short marker was not sent",
						lim, triage.MarkerLen)))
			}
		}
		if ctx.Baseline.Degraded {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine,
				"degraded_comparison: the body was oversized, truncated or unparseable for this endpoint, and a "+
					"degraded comparison can never produce a clean"))
		}
		if ctx.Baseline.Samples == 0 {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine,
				"no_baseline_model: nothing measured this endpoint's normal behaviour, so an absence cannot be "+
					"distinguished from an endpoint that answers everything the same way"))
		}
		if el.Promote != "" {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine, el.Promote))
		}
		v := xssrVerdict(slot, triage.StateClean,
			"no_reflection: this class's own census probes ran in both forms, the payload is recorded as having "+
				"reached the wire, delivery to the application is shown by "+del.Evidence+", the field is wide enough "+
				"to hold the marker, the endpoint is not blocking uniformly and the comparison is not degraded. The "+
				"marker is absent from the body, from every response header and from every redirect hop, in the raw, "+
				"case-transformed, numeric-reference, percent, base64 (three phase alignments) and UTF-16LE forms")
		v.Ordinals = run.Ordinals
		v.Annotations = xssrCopyAnnotations(ann)
		v.Annotations["delivery_evidence"] = del.Evidence
		v.Annotations["decode_depth"] = del.Depth
		v.Annotations["clean_preconditions"] = "census_both_forms,wire_survival_proven,delivery_shown,field_wide_enough,not_uniform_block,comparison_not_degraded"
		v.Annotations["coverage"] = "single_identity_single_pass"
		return append(rows, v)
	}

	// THE MEDIA GATE, BEFORE ANY READING OF THE BYTES AROUND THE MARKER.
	//
	// Every rule in xssrRulesFor reads an HTML parse tree, and a body no browser parses as markup
	// has none: the tokenizer this class runs over it is producing tokens no browser will ever
	// produce. So when EVERY response this class has in hand is such a body, the right row is
	// about the media type and not about what the bytes looked like.
	//
	// The split is the one xssrResponseRenders already draws, and it is the difference between a
	// clean and an unknown. A declared application/json is never upgraded to text/html, so an
	// element "found" in it is not an XSS lead, but the value round-trips and a SPA may write it
	// into a DOM sink: that is XSS-DOM's question and it needs a browser, so it is
	// cannot_determine (needs_dom_run). Everything else the gate closes, text/plain with nosniff
	// and Content-Disposition attachment, is a document that is neither parsed as markup nor
	// obviously fetched as data, and reflected XSS cannot exist in it: that is a clean, with the
	// gate named, which is a far more useful row than a bare one.
	if closed, structured, why := xssrMediaGateClosedEverywhere(run); closed {
		if structured {
			// The JSON-string placement already emits this slot's needs_dom_run row, and two rows
			// carrying the same sentence read in an aggregate as two measurements. One is enough.
			if xssrRowsAlreadySayNeedsDOMRun(rows) {
				return rows
			}
			v := xssrVerdict(slot, triage.StateCannotDetermine,
				why+". The marker came back in "+where+" and no rule this class owns can fire on a document the "+
					"browser never parses as markup. Whether page JavaScript writes this value into a DOM sink is "+
					"XSS-DOM's question and it needs a browser, so this is NOT a clean")
			v.Ordinals = run.Ordinals
			v.Annotations = xssrCopyAnnotations(ann)
			v.Annotations["needs_dom_run"] = true
			v.Annotations["media_gate"] = "structured_not_markup"
			return append(rows, v)
		}
		v := xssrVerdict(slot, triage.StateClean,
			why+". The marker came back in "+where+" and the bytes around it were read, but no browser parses this "+
				"response as markup on navigation, so nothing reflected into it can open an element, name an "+
				"attribute or reach a JavaScript lexer. Reflection into a non-markup document is not injection. A "+
				"value this slot also reaches a DIFFERENT, rendering response with is outside a single-response "+
				"class's reach and is declared rather than measured")
		v.Ordinals = run.Ordinals
		v.Annotations = xssrCopyAnnotations(ann)
		v.Annotations["media_gate"] = "closed"
		v.Annotations["coverage"] = "single_identity_single_pass"
		return append(rows, v)
	}

	// The marker came back and not one rule fired. That is where the encoder lives, and where the
	// two failures that look identical to a careless implementation live too.
	if it, ok := run.item(xssrP1s); ok {
		if xssrBoldSurvivedWithoutMarkerElement(it) {
			v := xssrVerdict(slot, triage.StateSuspicious,
				"sanitizer_allowlist: <b> came back as a real element while the element named by this run's marker "+
					"did not, which is an allowlist sanitizer and not an output encoder. What is left is mutation "+
					"XSS, which is browser-only, so this points at domdig. It is emphatically not clean")
			v.Grade = triage.GradeLow
			v.Oracle = "allowlist_sanitizer"
			v.Ordinals = []uint64{it.Ordinal}
			v.Label = triage.TriageLabel{Tools: []string{"domdig", "dalfox"}, Hints: map[string]string{
				"why_domdig": "mutation XSS against a sanitizer cannot be established from an HTTP response",
			}}
			v.Annotations = xssrCopyAnnotations(ann)
			return append(rows, v)
		}
	}
	if why, ok := xssrScrubbingSuspected(run); ok {
		return append(rows, xssrVerdict(slot, triage.StateCannotDetermine, why))
	}
	if len(near) > 0 {
		// The bytes this context needs came back RAW and no parse tree changed. That is not an
		// encoded reflection and it may not be reported as one: it is a near miss, it chooses the
		// next probe, and its ceiling is suspicious.
		h := near[0]
		v := xssrVerdict(slot, triage.StateSuspicious, h.Detail+
			". The marker came back in "+where+" and no rule fired, so this is a filter that is present and "+
			"incomplete rather than an encoder doing its job")
		v.Grade = triage.GradeLow
		v.Oracle = h.Oracle
		v.Ordinals = []uint64{h.Ordinal}
		v.Evidence = triage.TriageEvidence{Ordinal: h.Ordinal, ObsID: h.ObsID, Matched: h.Matched,
			Offset: h.Offset, Length: h.Length, Phrase: h.Rule + " " + h.Oracle, Wire: h.Wire}
		v.Label = xssrLabel(ctx, h, "")
		v.Annotations = xssrCopyAnnotations(ann)
		return append(rows, v)
	}
	encoder, note := run.IdentifyEncoder()
	if encoder != "" {
		if missing := xssrUnansweredContexts(ctx, run); len(missing) > 0 {
			return append(rows, xssrVerdict(slot, triage.StateCannotDetermine,
				"contexts_unprobed: the output encoder looks like "+encoder+", but "+strings.Join(missing, ", ")+
					" never ran, and an encoder that closes the HTML contexts says nothing about the event-handler "+
					"entity rung, which is the one configuration this ladder exists to catch"))
		}
		v := xssrVerdict(slot, triage.StateClean,
			"encoded_all_contexts: every payload this slot's placements promoted ran, the marker came back in "+where+
				" and not one of RX-D1 to RX-D4 fired. The encoder identifies as "+encoder+". "+note)
		v.Ordinals = run.Ordinals
		v.Annotations = xssrCopyAnnotations(ann)
		v.Annotations["encoder"] = encoder
		v.Annotations["coverage"] = "single_identity_single_pass"
		v.Label = triage.TriageLabel{Engine: encoder}
		return append(rows, v)
	}
	v := xssrVerdict(slot, triage.StateCannotDetermine,
		"reflected_context_undecided: the marker came back in "+where+", no rule fired, and no output encoder could "+
			"be identified from the bytes around it. Reflection without an identified encoder and without a parse "+
			"tree change is exactly the state this class refuses to call clean")
	v.Annotations = xssrCopyAnnotations(ann)
	return append(rows, v)
}

// xssrRowsAlreadySayNeedsDOMRun reports whether a placement row on this slot already carries the
// needs_dom_run answer, so the media gate adds a row rather than repeating one.
func xssrRowsAlreadySayNeedsDOMRun(rows []triage.ClassVerdict) bool {
	for _, v := range rows {
		if v.Annotations["needs_dom_run"] == true {
			return true
		}
	}
	return false
}

// xssrMediaGateClosedEverywhere asks whether EVERY response this class actually has in hand is a
// body no browser parses as markup.
//
// EVERY, not any. One rendering response among the probes means the slot reaches a document where
// an element could form, and the gate must not close on the strength of the others. An
// undelivered probe is skipped: it has no media type, and a missing response is already an
// unknown by another name (xssrAllUndelivered runs before this). With no delivered response at
// all the answer is false, so this can never manufacture a clean out of an empty run.
//
// It returns the structured flag separately because the two closures mean different things:
// application/json and the JavaScript family are documents a SPA routinely fetches and writes
// into the DOM, and their row is needs_dom_run, not clean.
func xssrMediaGateClosedEverywhere(run xssrRun) (closed bool, structured bool, why string) {
	seen := 0
	for _, it := range run.Items {
		if !it.Obs.Delivered() {
			continue
		}
		seen++
		renders, mediaWhy := xssrResponseRenders(it.Obs, it.Probe)
		if renders {
			return false, false, ""
		}
		if xssrStructuredNotMarkup(it.Obs.MediaType) {
			structured = true
		}
		if why == "" {
			why = mediaWhy
		}
	}
	if seen == 0 {
		return false, false, ""
	}
	if why == "" {
		why = "media_gate_closed: no response this class holds for this slot is parsed as markup by any browser"
	}
	return true, structured, why
}

// xssrBoldSurvivedWithoutMarkerElement is the RX-1s reading: an allowlist sanitizer keeps <b> and
// drops the unknown element, an encoder keeps neither, and a vulnerable app keeps both.
func xssrBoldSurvivedWithoutMarkerElement(it xssrProbeObs) bool {
	doc := xssrTokenize(it.Obs.Body)
	name := xssrExpectedName(it)
	bold, marker := false, false
	for _, t := range doc.Tokens {
		if t.Kind != xssrTokStartTag {
			continue
		}
		if t.Name == "b" {
			bold = true
		}
		if t.Name == name {
			marker = true
		}
	}
	return bold && !marker
}

// xssrScrubbingSuspected is FN-A15. An encoder leaves &lt; behind; a scrubber leaves nothing. A
// body-rewriting WAF that answers 200 makes every probe look "encoded", and reading that as clean
// marks a protected application as a tested one.
func xssrScrubbingSuspected(run xssrRun) (string, bool) {
	checked, scrubbed := 0, 0
	for _, it := range run.Items {
		if it.Probe == xssrP0r || it.Probe == xssrP0a || it.Probe == xssrP0h || it.Probe == xssrPDec {
			continue
		}
		if !it.Obs.Delivered() {
			continue
		}
		need, before := xssrNeededBytes(it.Probe)
		if len(need) == 0 {
			continue
		}
		occ := xssrFindMarker(it.Obs.Body, xssrExpectedName(it))
		if len(occ) == 0 {
			continue
		}
		checked++
		w := xssrSurvivalRegion(it.Obs.Body, occ, before, xssrPayloadTail(it.Probe))
		if !bytes.Contains(w, []byte(need[0])) && !bytes.Contains(bytes.ToLower(w), []byte("&")) {
			scrubbed++
		}
	}
	if checked >= 2 && scrubbed == checked {
		return fmt.Sprintf("scrubbing_suspected: the marker survived in all %d probe responses while every "+
			"metacharacter vanished with NO entity form anywhere. An output encoder leaves &lt; behind and a "+
			"scrubber or a body-rewriting WAF leaves nothing, so this cannot be read as a correctly escaping "+
			"application", checked), true
	}
	return "", false
}

// xssrUnansweredContexts names the promoted probes that never ran, so a clean cannot be claimed
// while a context the census found sits untested.
func xssrUnansweredContexts(ctx triage.ClassifyCtx, run xssrRun) []string {
	var missing []string
	for _, pl := range run.CensusPlacements() {
		for _, id := range xssrProbesForContext(pl.Context, ctx.Vector.RespMedia) {
			if run.sent(id) {
				continue
			}
			if r := xssrProbeReachesSlot(id, ctx.Slot); !r.OK {
				continue // a payload that cannot be delivered is reported as not_reachable elsewhere
			}
			missing = append(missing, string(id))
		}
	}
	sort.Strings(missing)
	return missing
}

// xssrWireUnproven is the guard the WireSurvival type was written for. Go's http.Cookie silently
// drops the semicolon, the double quote and the backslash from a cookie value; a payload mangled
// on the way out is indistinguishable after the fact from a payload the application defended
// against, and the second reading is the one that gets written down as clean.
func xssrWireUnproven(run xssrRun) (string, bool) {
	for _, id := range []triage.ProbeID{xssrP0r, xssrP0a} {
		it, ok := run.item(id)
		if !ok {
			continue
		}
		switch it.Obs.Payload.Survived {
		case triage.WireSurvivalDropped, triage.WireSurvivalAltered:
			return "payload_mangled_on_send: " + string(id) + " was recorded as " + string(it.Obs.Payload.Survived) +
				" by " + it.Obs.Payload.AlteredBy + ", so what reached the application is not what this class wrote", true
		case triage.WireSurvivalRefused:
			return "could_not_send: the transport refused " + string(id) + " outright", true
		case triage.WireSurvivalUnknown:
			return "wire_survival_unknown: nothing recorded whether " + string(id) + "'s bytes reached the wire " +
				"intact, and an absence measured through an unrecorded send is not a clean", true
		}
	}
	return "", false
}

// xssrDelivery is the answer to the precondition that matters most on the negative side: CAN WE
// SHOW THE REQUEST ARRIVED. A marker that did not come back is only a clean when the value
// reached the application and the field was wide enough to hold the marker; otherwise it is an
// untested slot wearing a clean label.
type xssrDelivery struct {
	Delivered bool
	Decoded   bool
	Depth     int
	Evidence  string
	Why       string // set when delivery could not be shown, in the reason vocabulary
}

// xssrDeliveryEvidence reads THIS CLASS'S OWN decode probe first, ruling R6.
//
// The shared perturbed decode gate is abolished because one bad measurement used to suppress
// probes in twelve classes at once. There are four sources here and they are tried strongest
// first, because they prove different things:
//
//  1. this class's own decode probe came back carrying the marker. That proves the application
//     decoded the value AND that the value reached it. Nothing else proves both.
//  2. the route differential. The decode probe is the observed value one percent-encoding deeper,
//     so a response byte-identical to the route control means the encoded form resolved to the
//     same thing as the raw one, which is the application decoding it. If the CENSUS response is
//     also byte-identical to the route control, the parameter is being discarded entirely:
//     value_ignored, which is an unknown, and it is the negative control most scanners omit.
//  3. a decode depth measured elsewhere and recorded on the slot. Corroboration, annotated as
//     borrowed. R6 forbids a shared control GATING this class's probes; reading a measurement
//     somebody else already made, and saying where it came from, is a different thing.
//  4. nothing, which is decode_depth_unknown and is never clean.
//
// It takes the route control as an Observation and a bool rather than as a triage.Replay so that
// it can be tested: a resolved Replay can only be built by the runner.
func xssrDeliveryEvidence(route triage.Observation, routeOK bool, slot triage.Slot, run xssrRun) xssrDelivery {
	d := xssrDelivery{Depth: -1}
	dec, hasDec := run.item(xssrPDec)
	cen, hasCen := run.item(xssrP0r)

	if hasDec && dec.Obs.Delivered() && len(xssrFindMarker(dec.Obs.Body, string(dec.Marker))) > 0 {
		return xssrDelivery{Delivered: true, Decoded: true, Depth: 1, Evidence: "decode_probe_marker_returned"}
	}
	if routeOK && hasCen && cen.Obs.Delivered() {
		sameAsRoute := xssrBodyKey(cen.Obs) == xssrBodyKey(route)
		decSameAsRoute := hasDec && dec.Obs.Delivered() && xssrBodyKey(dec.Obs) == xssrBodyKey(route)
		if sameAsRoute && (!hasDec || decSameAsRoute) {
			return xssrDelivery{Why: "value_ignored: this class's census response is byte-identical to the route " +
				"control, so nothing observable depends on this slot's value. An absence measured there is a fact " +
				"about the endpoint and not about the application"}
		}
		if !sameAsRoute {
			d.Delivered, d.Depth, d.Evidence = true, 0, "value_influences_response"
			if decSameAsRoute {
				d.Decoded, d.Depth, d.Evidence = true, 1, "decode_probe_resolved_like_the_observed_value"
			}
		}
	}
	if !d.Delivered && slot.Constraints.DecodeDepth >= 1 {
		d.Delivered, d.Decoded = true, true
		d.Depth, d.Evidence = slot.Constraints.DecodeDepth, "borrowed_slot_decode_depth"
	}
	if !d.Delivered {
		d.Why = "decode_depth_unknown: this class's own decode probe did not settle whether the application reads " +
			"this slot at all, and nothing else measured it, so an absent marker cannot be told from a value that " +
			"never arrived"
		if hasDec && dec.Obs.Delivered() {
			d.Why = "decode_depth_0: this class's own decode probe came back without the marker and without " +
				"resolving like the observed value, so the application does not decode this slot and a plain " +
				"payload's absence says nothing about it"
		}
	}
	return d
}

// xssrCSPNote reads the policy off this class's own responses. CSP is a MITIGATION AND NOT A
// REFUTATION: it downgrades a finding to suspicious and the tool is still pointed at the slot,
// because false negatives are the expensive error.
func xssrCSPNote(run xssrRun) string {
	for _, it := range run.Items {
		p := xssrHeader(it.Obs, "content-security-policy")
		if p == "" {
			continue
		}
		low := strings.ToLower(p)
		if strings.Contains(low, "unsafe-inline") || strings.Contains(low, "unsafe-eval") ||
			strings.Contains(low, "nonce-") || strings.Contains(low, "*") {
			return ""
		}
		return "csp_present: script-src carries no unsafe-inline, no unsafe-eval, no wildcard host and no nonce, " +
			"so the eventual payload would be blocked by policy rather than by the application"
	}
	return ""
}

// xssrLabel is what the verdict hands the expensive scanner.
func xssrLabel(ctx triage.ClassifyCtx, h xssrHit, encoder string) triage.TriageLabel {
	tools := []string{"dalfox"}
	hints := map[string]string{
		"context": h.Context,
		"probe":   string(h.Probe),
		"rule":    h.Rule,
	}
	switch ctx.Slot.Kind {
	case triage.KindQuery:
		tools = append(tools, "xssfuzz")
	case triage.KindPath:
		hints["dalfox_path_is_unaimable"] = "a path vector is handed no -p, so dalfox scans a query parameter it " +
			"appends itself and never aims at the path segment this finding is in. Drive it by hand"
	}
	if h.Inert != "" || h.Context == xssrCtxJSONString {
		tools = append(tools, "domdig")
	}
	if encoder != "" {
		hints["encoder"] = encoder
	}
	hints["never_set_inject_marker"] = "dalfox exits clean after three requests when --inject-marker is set and the " +
		"framework never writes a marker into the request"
	return triage.TriageLabel{Tools: tools, Engine: encoder, Hints: hints}
}

// xssrAnnotations are the facts every row on this slot carries.
func xssrAnnotations(ctx triage.ClassifyCtx, run xssrRun) map[string]any {
	ann := map[string]any{
		"class":      "XSS-R",
		"slot_kind":  string(ctx.Slot.Kind),
		"coverage":   "single_identity_single_pass",
		"probes_run": len(run.Items),
	}
	if d := ctx.Slot.Constraints.DecodeDepth; d >= 0 {
		ann["decode_depth_recorded"] = d
	}
	if lim := ctx.Slot.Constraints.FieldLimit; lim > 0 {
		ann["field_limit"] = lim
		if lim < 20 {
			ann["short_marker"] = true
		}
	}
	if run.sent(xssrPSM) {
		ann["short_marker"] = true
	}
	var places []string
	for _, pl := range run.CensusPlacements() {
		places = append(places, pl.Context)
	}
	if len(places) > 0 {
		ann["placements"] = strings.Join(places, ",")
	}
	if csp := xssrCSPNote(run); csp != "" {
		ann["csp_present"] = true
	}
	// FN-A5 and FN-A13 are knowingly uncovered and are recorded rather than left silent.
	ann["not_covered"] = "overlong_utf8_and_utf7 (rejected by current browsers), second_identity, " +
		"client_side_route_change, second_order_storage (XSS-STORED's)"
	return ann
}

func xssrCopyAnnotations(in map[string]any) map[string]any {
	out := make(map[string]any, len(in)+4)
	for k, v := range in {
		out[k] = v
	}
	return out
}

// xssrUntested names every declared probe this class did not send, with the reason.
//
// A CLASS THAT QUIETLY PLANS FEWER PROBES ON ONE SLOT THAN ANOTHER IS THE SHAPE OF A SILENT ZERO.
// The list is attached to every row on the slot so that no row can be read without it.
func xssrUntested(ctx triage.PlanCtx, run xssrRun) []triage.ProbeSkip {
	promoted := map[triage.ProbeID]string{}
	for _, pl := range run.CensusPlacements() {
		for _, id := range xssrProbesForContext(pl.Context, ctx.Vector.RespMedia) {
			promoted[id] = pl.Context
		}
	}
	var out []triage.ProbeSkip
	for _, p := range (xssReflectedClassifier{}).Probes() {
		if run.sent(p.ID) {
			continue
		}
		switch {
		case !xssrProbeReachesSlot(p.ID, ctx.Slot).OK:
			out = append(out, triage.ProbeSkip{ProbeID: p.ID, Reason: xssrProbeReachesSlot(p.ID, ctx.Slot).Reason})
		case promoted[p.ID] != "":
			reason := "the census placed the marker in " + promoted[p.ID] + " and the ladder did not reach this probe"
			if len(run.Items) >= xssrPerSlotCap {
				reason = "this class's own per-slot cap of " + strconv.Itoa(xssrPerSlotCap) + " probes was reached, " +
					"so the context " + promoted[p.ID] + " is untested"
			}
			if ctx.Budget.Exhausted() {
				reason = "probe_budget_exhausted before this probe went out, and the context " + promoted[p.ID] + " is therefore untested"
			}
			out = append(out, triage.ProbeSkip{ProbeID: p.ID, Reason: reason})
		default:
			out = append(out, triage.ProbeSkip{ProbeID: p.ID,
				Reason: "no placement promoted it: this class sends a context payload only where its own census " +
					"found the marker in that context, and sending every payload everywhere would be 30 requests a slot"})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ProbeID < out[b].ProbeID })
	return out
}
