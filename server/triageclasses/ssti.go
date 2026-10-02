package triageclasses

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// SERVER SIDE TEMPLATE INJECTION. CATALOGUE 1.1, iso-eval "CLASS 1 of 3".
//
// =================================================================================================
// WHAT THIS CLASS ANSWERS: point sstimap and tinja HERE, and at THIS engine.
// WHAT IT DOES NOT ANSWER: is this exploitable. That is the scanner's job and it costs minutes.
// =================================================================================================
//
// THE ORACLE, AND WHY IT IS THE BEST ONE IN THE CATALOGUE. Send arithmetic, get the product back.
// The application had to EVALUATE to produce it, so there is no interpretation step between the
// observation and the conclusion. Three things make the false positive rate near zero and all
// three are enforced in code below rather than described:
//
//	(a) ADJACENCY. The answer must sit immediately after THIS probe's own 16-byte marker, with at
//	    most eight whitespace bytes between. An unanchored search for a seven-digit number in a
//	    40 KB page is a coin flip; an anchored one is a proof of concatenation.
//	(b) THE ANSWER IS NOT IN THE WIRE. 1721*913 is 1571273 and the string "1571273" appears
//	    nowhere in "1721*913", so an application that echoes the payload verbatim cannot produce
//	    it. iso-eval 1.2. The operand draw rejects any pair whose product is a substring of the
//	    payload, and the guard is verified by control NC2, which SENDS the answer and must still
//	    stay silent.
//	(c) THE ANSWER IS NOT IN THE BASELINE. Checked against the route control before scoring.
//
// Not 7*7. Forty-nine appears in prices, pixel counts, percentages and ids on almost every page
// ever rendered. 1721 and 913 are four-digit factors whose product is seven digits and whose
// product is not a digit repetition of either operand, which is what tells multiplication apart
// from Jinja2's `{{7*'7'}}` string repetition.
//
// THE ISOLATION LAW, APPLIED. Every payload here is this class's own. `${1721*913}` is SSTI's;
// ELI's `${1*((1).valueOf('1900000000')+1900000000)}` is ELI's; CSTI's `{{7919*6271}}` is CSTI's.
// They share delimiter CHARACTERS and no payload. That matters because a WAF rule or a validator
// can reject a merged payload for a reason belonging to either half, and the run then cannot tell
// which half was refused, so it records clean for a class it never tested. The detection polyglot
// `${{<%[%'"}}%\` is entirely within this class (it is SSTI-S1b) and using it as a first "does
// anything evaluate" probe is therefore not a cross-class merge.
//
// NOT KNOWING IS NOT CLEAN. This class has four oracles and each can be individually unavailable.
// A slot whose computation oracle could not run because the bare marker never came back is
// cannot_determine (no_reflection), not clean, because a blind template sink (an email subject, a
// PDF, a generated filename) is exactly the case a reflection-shaped clean would hide. The
// composed verdict can never be clean while any of this class's own oracles is an unknown.
//
// WHAT IS NOT COVERED, NAMED RATHER THAN HIDDEN. An engine configured with CUSTOM DELIMITERS is
// invisible to a fixed battery, so every verdict this class emits carries the annotation
// custom_delimiters_untested. An engine that renders on a LATER request is likewise out of reach;
// the markers are recorded so a subsequent crawl can find them, but this class does not crawl.
type sstiClassifier struct{}

func init() { triage.RegisterClassifier(sstiClassifier{}) }

func (sstiClassifier) ID() triage.ClassID { return triage.ClassSSTI }

// ---------------------------------------------------------------------------------------------
// 1. THE NUMBERS, AND THE GUARD THAT MAKES THEM MEAN SOMETHING
// ---------------------------------------------------------------------------------------------

const (
	// sstiA, sstiB and sstiExpected are the catalogue's worked draw. 1721*913 == 1571273.
	sstiA        = "1721"
	sstiB        = "913"
	sstiExpected = "1571273"

	// The Django `add` filter is a SUM, and a four-digit sum has five digits, which fails the
	// six-digit minimum of iso-eval 1.2. Six-digit operands are what restore the guard.
	// 481271 + 918733 == 1400004.
	sstiDjangoA        = "481271"
	sstiDjangoB        = "918733"
	sstiDjangoExpected = "1400004"

	// Go's template packages have no arithmetic operator and no add function, so the natural
	// probe is a parse error and `{{printf "%d" 1571273}}` puts the answer in the wire. Six
	// chained len calls over literals of length 7,4,9,2,6,8 produce a six-digit value that is
	// genuinely computed and that does not appear in the payload.
	sstiGoExpected = "749268"

	// The confirmation draw. FRESH OPERANDS AND A DIFFERENT OPERATOR, because re-sending the
	// first probe confirms a cache and nothing else. 9174263 - 1258147 == 7916116.
	//
	// iso-eval SSTI 3 suggests `${4643-1129}` expecting `3514` here. That is FOUR digits and
	// violates the same document's own six-digit minimum in 1.2, so a page carrying "3514"
	// anywhere adjacent to a reflected marker would confirm a finding that was never there.
	// These operands satisfy the guard: "7916116" is not a substring of "9174263-1258147".
	sstiConfA        = "9174263"
	sstiConfB        = "1258147"
	sstiConfExpected = "7916116"

	// The Go confirmation redraws the literal lengths: 3,8,5,9,2,7.
	sstiGoConfExpected = "385927"
)

// sstiMaxGap is the whitespace budget between the marker and the answer. Eight bytes, because a
// few engines emit a newline and an indent between an interpolation and the text around it. It is
// recorded on the hit: a hit with gap_bytes > 0 grades medium, never high (CATALOGUE 4.2).
const sstiMaxGap = 8

// sstiGroupSeparators is the locale digit-group separator set. FreeMarker renders a number through
// the locale's number format, so `${1721*913}` under en_US renders `1,571,273`, and an exact digit
// matcher loses one of the most common Java engines in the world while reporting it clean.
// iso-eval 1.3. APOSTROPHE is de_CH, NARROW NO-BREAK SPACE is fr_FR on modern ICU.
var sstiGroupSeparators = []string{",", ".", " ", " ", " ", "'"}

// ---------------------------------------------------------------------------------------------
// 2. THE SUBSTITUTION TOKENS, AND WHY THEY EXIST
// ---------------------------------------------------------------------------------------------

// Two of this class's probe families need bytes that only the runner can supply, because a
// ProbeSpec.Logical is a compile-time constant and a marker is minted per probe at run time.
//
// A CLASS MAY NOT MINT A MARKER. triage.MintMarkerAt takes a capability whose type lives in an
// internal package this one cannot import, which is the whole point of the package split. So the
// payload carries a TOKEN and the runner substitutes it, driven by the Variant map on the
// ProbeRequest. Detection needs no cooperation at all: a sibling marker is a deterministic
// function of this one (same anchor, same run id, ordinal plus 64 per sibling, checksum
// recomputed by the exported triage.MarkerChecksumFor), so sstiSiblingMarker reconstructs them.
//
// FAIL CLOSED. If a token is still present in the wire bytes the runner did not substitute it, the
// probe tested nothing, and Classify says cannot_determine (runner_bug) rather than reading the
// silence as clean. That is the single most repeated bug in this codebase and it gets an explicit
// check rather than a comment.
const (
	// sstiTokenM2 and sstiTokenM3 are the second and third markers of the consumption battery.
	// Tilde is RFC 3986 unreserved, inside cookie-octet, a header field-vchar, and needs no
	// escaping in JSON or XML text, so the token itself can never be the reason a probe fails.
	sstiTokenM2 = "~~m2~~"
	sstiTokenM3 = "~~m3~~"

	// sstiTokenPctMarker is this probe's own marker with every byte percent-encoded, ruling R6b.
	sstiTokenPctMarker = "~~pctm~~"

	// Variant keys the runner reads.
	sstiVariantSiblings = "sibling_markers"
	sstiVariantPctMark  = "pct_marker"
	sstiVariantExpected = "expected_answer"
)

// ---------------------------------------------------------------------------------------------
// 3. PROBE IDS
// ---------------------------------------------------------------------------------------------

const (
	// Census, decode, error polyglots, non-error polyglot.
	sstiS0  triage.ProbeID = "SSTI-S0"
	sstiDEC triage.ProbeID = "SSTI-DEC"
	sstiS1  triage.ProbeID = "SSTI-S1"
	sstiS1q triage.ProbeID = "SSTI-S1q"
	sstiS1s triage.ProbeID = "SSTI-S1s"
	sstiS1b triage.ProbeID = "SSTI-S1b"
	sstiS2  triage.ProbeID = "SSTI-S2"

	// The computation battery. ELEVEN DELIMITER FAMILIES, EACH A DIFFERENT PAYLOAD.
	sstiF1   triage.ProbeID = "SSTI-F1"
	sstiF2   triage.ProbeID = "SSTI-F2"
	sstiF3   triage.ProbeID = "SSTI-F3"
	sstiF4   triage.ProbeID = "SSTI-F4"
	sstiF5   triage.ProbeID = "SSTI-F5"
	sstiF6   triage.ProbeID = "SSTI-F6"
	sstiF6L  triage.ProbeID = "SSTI-F6L"
	sstiF7   triage.ProbeID = "SSTI-F7"
	sstiF8   triage.ProbeID = "SSTI-F8"
	sstiF9   triage.ProbeID = "SSTI-F9"
	sstiF9c  triage.ProbeID = "SSTI-F9c"
	sstiF10  triage.ProbeID = "SSTI-F10"
	sstiF10w triage.ProbeID = "SSTI-F10w"
	sstiF11  triage.ProbeID = "SSTI-F11"

	// The confirmation battery: same family, fresh marker, fresh operands, operator changed.
	sstiCF1  triage.ProbeID = "SSTI-CF1"
	sstiCF2  triage.ProbeID = "SSTI-CF2"
	sstiCF3  triage.ProbeID = "SSTI-CF3"
	sstiCF4  triage.ProbeID = "SSTI-CF4"
	sstiCF5  triage.ProbeID = "SSTI-CF5"
	sstiCF6  triage.ProbeID = "SSTI-CF6"
	sstiCF7  triage.ProbeID = "SSTI-CF7"
	sstiCF8  triage.ProbeID = "SSTI-CF8"
	sstiCF9  triage.ProbeID = "SSTI-CF9"
	sstiCF11 triage.ProbeID = "SSTI-CF11"

	// The consumption battery, for the logic-less engines that compute nothing by design.
	sstiC1  triage.ProbeID = "SSTI-C1"
	sstiC2  triage.ProbeID = "SSTI-C2"
	sstiC3  triage.ProbeID = "SSTI-C3"
	sstiC4  triage.ProbeID = "SSTI-C4"
	sstiC5  triage.ProbeID = "SSTI-C5"
	sstiCC1 triage.ProbeID = "SSTI-CC1"
	sstiCC2 triage.ProbeID = "SSTI-CC2"

	// The division triple. Ruling R1's replacement for the abolished foreign-error clause, and
	// the probe that separates "parsed my delimiters" from "evaluated my expression".
	sstiZ1 triage.ProbeID = "SSTI-Z1"
	sstiZ2 triage.ProbeID = "SSTI-Z2"
	sstiZ3 triage.ProbeID = "SSTI-Z3"

	// Distinctive content and the identification ladder.
	sstiD1 triage.ProbeID = "SSTI-D1"
	sstiD2 triage.ProbeID = "SSTI-D2"
	sstiD3 triage.ProbeID = "SSTI-D3"
	sstiI1 triage.ProbeID = "SSTI-I1"
	sstiI2 triage.ProbeID = "SSTI-I2"
	sstiI3 triage.ProbeID = "SSTI-I3"
	sstiI4 triage.ProbeID = "SSTI-I4"
	sstiI5 triage.ProbeID = "SSTI-I5"
	sstiI6 triage.ProbeID = "SSTI-I6"

	// Hackmanit's per-language error polyglots, step B of identification.
	sstiEPPython triage.ProbeID = "SSTI-EP-python"
	sstiEPRuby   triage.ProbeID = "SSTI-EP-ruby"
	sstiEPDotnet triage.ProbeID = "SSTI-EP-dotnet"
	sstiEPJava   triage.ProbeID = "SSTI-EP-java"
	sstiEPPHP    triage.ProbeID = "SSTI-EP-php"
	sstiEPJS     triage.ProbeID = "SSTI-EP-javascript"
	sstiEPGo     triage.ProbeID = "SSTI-EP-golang"

	// THE BLIND ARM: four boolean pairs and their two length-matched inert controls.
	//
	// These are the only probes in this class whose oracle does not need a single byte of the
	// payload, the marker or any computed answer to come back. One member of each pair is valid
	// expression syntax and the other is not, so an engine that PARSES the slot answers the two
	// differently while an engine-free route answers them identically. That question has an answer
	// on a JSON API that echoes nothing, which is the whole reason this arm exists.
	sstiBOK1 triage.ProbeID = "SSTI-BOK1"
	sstiBER1 triage.ProbeID = "SSTI-BER1"
	sstiBOK2 triage.ProbeID = "SSTI-BOK2"
	sstiBER2 triage.ProbeID = "SSTI-BER2"
	sstiBOK3 triage.ProbeID = "SSTI-BOK3"
	sstiBER3 triage.ProbeID = "SSTI-BER3"
	sstiBOK4 triage.ProbeID = "SSTI-BOK4"
	sstiBER4 triage.ProbeID = "SSTI-BER4"
	sstiBN1  triage.ProbeID = "SSTI-BN1"
	sstiBN2  triage.ProbeID = "SSTI-BN2"

	// The attribute-access division probes. Narrower than they look, and described honestly:
	// MEASURED in Jinja2 3.1.6, {{(1/0).zxy.zxy}} and the plain {{1721/0}} BOTH raise
	// ZeroDivisionError, so for Python this adds nothing over SSTI-Z2. Its real coverage is the
	// engines that TOLERATE division by zero  -  JavaScript yields Infinity, PHP 7 yields INF with
	// a warning  -  where only the attribute access that follows throws. Node and PHP coverage,
	// not a general upgrade.
	sstiZB1 triage.ProbeID = "SSTI-ZB1"
	sstiZB2 triage.ProbeID = "SSTI-ZB2"
	sstiZB3 triage.ProbeID = "SSTI-ZB3"
	sstiZB4 triage.ProbeID = "SSTI-ZB4"

	// The negative controls. A detector never shown STAYING SILENT is not a verified detector.
	sstiNC1  triage.ProbeID = "SSTI-NC1"
	sstiNC2  triage.ProbeID = "SSTI-NC2"
	sstiNC3a triage.ProbeID = "SSTI-NC3a"
	sstiNC3b triage.ProbeID = "SSTI-NC3b"
	sstiNC4  triage.ProbeID = "SSTI-NC4"
)

// ---------------------------------------------------------------------------------------------
// 4. PROBES
// ---------------------------------------------------------------------------------------------

// sstiValuePoints is every insertion point this class delivers a value into. The catalogue's Q, F,
// J, M# and X columns all collapse onto triage.KindBody, which is the coarser vocabulary the Slot
// abstraction uses; the per-media differences are handled by Reaches and by the encoder.
func sstiValuePoints() []triage.SlotKind {
	return []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie, triage.KindPath}
}

// sstiStdEncoders is the encoder set every value-bearing payload here declares. A CLASS NEVER
// ENCODES: it emits logical bytes and names the modes the runner may render them through.
func sstiStdEncoders() []triage.EncoderMode {
	return []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
		triage.EncodePathSegment, triage.EncodeHeaderValue, triage.EncodeCookie,
		triage.EncodeMultipartValue,
	}
}

// sstiAngleEncoders adds xml_cdata for the payloads carrying a raw `<`. In XML element text `<`
// must be `&lt;`, and an engine handed `&lt;%=` opens no scriptlet at all, so without CDATA the
// probe is not a weaker test, it is a different one. CATALOGUE 3.3.
func sstiAngleEncoders() []triage.EncoderMode {
	return append(sstiStdEncoders(), triage.EncodeXMLCDATA)
}

type sstiRow struct {
	id       triage.ProbeID
	logical  string
	points   []triage.SlotKind
	encoders []triage.EncoderMode
	tier     triage.ProbeTier
	control  bool
	variant  map[string]string
	notes    string
}

// sstiProbeTable is the whole payload set, in one place, in catalogue order.
//
// EVERY ENTRY IS A DIFFERENT PAYLOAD FOR A DIFFERENT SET OF ENGINES. `${7*7}`, `{{7*7}}` and
// `<%=7*7%>` are not three spellings of one probe: they are three grammars, and an engine that
// parses one treats the other two as literal text. Collapsing them would silently drop whole
// language ecosystems, which is the failure mode this table exists to prevent.
//
// The marker is NOT written into these bytes. MarkerPos is prefix on everything, so the runner
// prepends this probe's own minted marker and a field that truncates at sixteen bytes still leaves
// an attributable token, which is what keeps "truncated" distinguishable from "absent".
func sstiProbeTable() []sstiRow {
	std := sstiValuePoints()
	full := triage.TierFull
	return []sstiRow{
		// -- census and the per-class decode probe ------------------------------------------
		{
			id: sstiS0, logical: "-t", points: std, encoders: sstiStdEncoders(), tier: triage.TierReduced,
			notes: "bare-marker census. The two trailing bytes exist only so the payload is not the empty " +
				"string, which CheckPayloadIsolation refuses, and so that a bare 16-byte marker probe in " +
				"another class cannot be byte-equal to this one. This probe is what tells this class, with " +
				"its OWN request, whether the slot reflects at all. It never suppresses the battery: a " +
				"non-reflecting slot still gets the error oracle, and its computation verdict is " +
				"cannot_determine (no_reflection), never clean",
		},
		{
			id: sstiDEC, logical: sstiTokenPctMarker, points: []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie},
			encoders: []triage.EncoderMode{triage.EncodeLiteralPct}, tier: triage.TierReduced,
			variant: map[string]string{sstiVariantPctMark: "1"},
			notes: "this class's OWN decode probe, ruling R6. The decode control stopped being a shared " +
				"gate because it MODIFIES the value, which makes it a payload, which makes it one class's. " +
				"The marker is prepended raw and the token renders it again percent-encoded, so one request " +
				"answers the question by counting: the marker found TWICE means the slot decodes " +
				"(decode_depth >= 1), found ONCE with the literal percent text present means it does not " +
				"(decode_depth 0), found never means unknown. Ruling R6c: decode_depth may DOWNGRADE a " +
				"silent payload to cannot_determine, and may never suppress one",
		},

		// -- error polyglots -----------------------------------------------------------------
		{
			id: sstiS1, logical: `<%'${{/#{@}}%>{{`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierReduced,
			notes: "Hackmanit err1, measured to error on 52 of 52 engine configurations. TEN INDEPENDENT " +
				"MECHANISMS, and an engine only has to hit one: <% opens a scriptlet, the unclosed ' is a " +
				"hard parse error in Ruby, JavaScript and Java, ${ opens FreeMarker/Groovy/Mako/JSP EL, {{ " +
				"opens Jinja2/Twig/Go/Handlebars, / is a binary operator with no left operand so every " +
				"grammar that got that far now fails, #{ opens Ruby/Slim/Pug/SpEL, @ is Razor's transition " +
				"character, the closers are deliberately unbalanced, %> closes a scriptlet whose string is " +
				"still open, and the trailing {{ is an unterminated expression",
		},
		{
			id: sstiS1q, logical: `<#set($x<%={{={@{#{${xux}}%>)`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			notes: "the QUOTE-FREE error polyglot, 47 of 52. It exists because byte 3 of S1 is a single " +
				"quote, which is also the first byte of every SQL probe ever written: on an endpoint whose " +
				"data layer sits in the same request path, S1's error can be a database error rather than a " +
				"template one. This class refuses to read a foreign signature as its own (ruling R1), so on " +
				"such an endpoint S1q is the probe that actually produces evidence",
		},
		{
			id: sstiS1s, logical: `<%={{={@{#{${xu}}%>`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			notes: "19 bytes, 45 of 52. Sent when the measured FieldLimit cannot carry S1q. A family skipped " +
				"for truncation is recorded by name as cannot_determine (truncated), never omitted silently",
		},
		{
			id: sstiS1b, logical: `${{<%[%'"}}%\`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			notes: "13 bytes, 38 of 52, the shortest error polyglot. This is the `does anything evaluate` " +
				"polyglot the brief names, and it is ENTIRELY WITHIN THIS CLASS: it is not a merge of two " +
				"classes' payloads, it is one class's first probe, and the identification ladder below is " +
				"what turns its answer into an engine name",
		},
		{
			id: sstiS2, logical: `p ">[[${{1}}]]`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			notes: "Hackmanit's universal NON-ERROR polyglot: 35 of 52 configurations MODIFY it and only 5 " +
				"error. It is the designed answer to an application that catches template exceptions and " +
				"renders a generic page, where every error-shaped oracle is structurally blind. Detection is " +
				"a byte comparison of this class's own sent bytes against its own returned bytes",
		},

		// -- THE BLIND ARM: boolean pairs, and they carry no marker and no expected answer -----
		//
		// EVERY OTHER PAYLOAD ABOVE ASKS "did my value come back changed". These four pairs ask
		// "did the response move between a valid expression and an invalid one", and that is a
		// question a route which echoes nothing can still answer. VERIFIED in Jinja2 3.1.6:
		// BOK3 renders 6.0 and BER3 raises TemplateSyntaxError: unexpected ')'.
		//
		// TWO PAIRS PER DELIMITER FAMILY, WHICH IS NOT REDUNDANCY. A single pair fires on any
		// route that happens to answer two different strings differently. Requiring both pairs of
		// the family to move in the SAME DIRECTION is what turns a coincidence into a signal, and
		// it is PATT's own stated reason for shipping two.
		//
		// ALL FOUR PAIRS ARE LENGTH-MATCHED WITHIN THE PAIR, which was checked byte by byte and is
		// asserted by a test: 10/10, 16/16, 11/11, 17/17. An endpoint that merely ECHOES the value
		// therefore returns two bodies of the same length, so a length differential between the
		// members cannot be the echo. That property is load-bearing, because a length oracle that
		// is really measuring echo length fires on every reflecting slot in the corpus.
		{
			id: sstiBOK1, logical: "${(3*4/2)}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 1, the VALID member in the dollar-brace family. Renders 6.0 in Jinja2 3.1.6 " +
				"and a number in every engine that evaluates ${...}. It carries no marker and no expected " +
				"answer on purpose: the oracle is the difference against BER1, not anything in these bytes",
		},
		{
			id: sstiBER1, logical: "${3*)2(/4}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 1, the SYNTAX-ERROR member. Same ten bytes, same alphabet, parentheses " +
				"transposed. MEASURED: TemplateSyntaxError in Jinja2 3.1.6 through the brace-brace form of " +
				"the same construction. It is also half of control A: BER1 and BER2 are both garbage, so a " +
				"route that answers ANY unusual input differently answers these two differently too",
		},
		{
			id: sstiBOK2, logical: "${((7*8)/(2*4))}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 2, the valid member. A second, structurally different expression so the pair " +
				"is independent of pair 1 rather than a re-send of it",
		},
		{
			id: sstiBER2, logical: "${7)(*)8)(2/(*4}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 2, the syntax-error member, sixteen bytes matching BOK2 exactly",
		},
		{
			id: sstiBOK3, logical: "{{(3*4/2)}}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 3, the valid member in the brace-brace family. THIS IS THE ONE THAT WAS RUN: " +
				"Jinja2 3.1.6 renders 6.0. The brace-brace family reaches fourteen engines and is the family " +
				"the corpus is most likely to be running",
		},
		{
			id: sstiBER3, logical: "{{3*)2(/4}}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 3, the syntax-error member. VERIFIED in Jinja2 3.1.6: TemplateSyntaxError, " +
				"unexpected ')'",
		},
		{
			id: sstiBOK4, logical: "{{((7*8)/(2*4))}}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 4, the valid member, the second brace-brace expression",
		},
		{
			id: sstiBER4, logical: "{{7)(*)8)(2/(*4}}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "blind pair 4, the syntax-error member, seventeen bytes matching BOK4 exactly",
		},
		{
			id: sstiBN1, logical: "q4jv7nx2wr", points: std, encoders: sstiStdEncoders(), tier: full, control: true,
			notes: "CONTROL B, the ten-byte inert. No delimiter, no operator, no parenthesis, nothing any " +
				"grammar parses, and exactly the length of BOK1 and BER1. Paired with BN2 it is the " +
				"length-differential control the blind arm cannot run without: if these two move apart, the " +
				"arm is measuring how long the value is and not whether it parsed, and the arm is disabled " +
				"on this slot rather than reported",
		},
		{
			id: sstiBN2, logical: "q4jv7nx2wr6zc38f", points: std, encoders: sstiStdEncoders(), tier: full, control: true,
			notes: "CONTROL B, the sixteen-byte inert, the length of BOK2 and BER2. The six-byte gap between " +
				"BN1 and BN2 is the largest length gap anywhere in this arm, so a route whose response " +
				"length tracks its input length shows it here first",
		},

		// -- the attribute-access division probes, Node and PHP coverage ----------------------
		{
			id: sstiZB1, logical: "${(1/0).zxy.zxy}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "the division probe with an attribute access behind it. NOT a general upgrade over Z1: " +
				"MEASURED in Jinja2 3.1.6, {{(1/0).zxy.zxy}} and the plain division BOTH raise " +
				"ZeroDivisionError, so for Python this is a duplicate. What it adds is the engines that " +
				"TOLERATE the division  -  JavaScript returns Infinity, PHP 7 returns INF with a warning  -  " +
				"where nothing throws until the attribute access. Scored through the same arithmetic " +
				"catalogue as Z1 to Z3 and baseline-differenced like every error signature here",
		},
		{
			id: sstiZB2, logical: "{{(1/0).zxy.zxy}}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "the brace-brace form, which is where Nunjucks and Twig live",
		},
		{
			id: sstiZB3, logical: "<%=(1/0).zxy.zxy%>", points: std, encoders: sstiAngleEncoders(), tier: full,
			notes: "the scriptlet form, which is where EJS and Underscore live. Angle encoders, because in " +
				"XML element text a raw < must be CDATA or the probe opens no scriptlet at all",
		},
		{
			id: sstiZB4, logical: "#{(1/0).zxy.zxy}", points: std, encoders: sstiStdEncoders(), tier: full,
			notes: "the hash-brace form, Pug and Slim",
		},

		// -- the computation battery ---------------------------------------------------------
		{
			id: sstiF1, logical: "${" + sstiA + "*" + sstiB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierReduced,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "FreeMarker, Groovy SimpleTemplateEngine and GStringTemplateEngine, Mako, Chameleon, and " +
				"Thymeleaf where the slot lands inside a th: attribute. Best delivered as a JSON string " +
				"value: RFC 8259 requires escaping only the quote, the backslash and the C0 controls, none " +
				"of which appear here",
		},
		{
			id: sstiF2, logical: "{{" + sstiA + "*" + sstiB + "}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierReduced,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Jinja2 and its sandbox, Tornado, Twig and its sandbox, TwigJS, Nunjucks, Pebble, " +
				"Jinjava, HuBL, Blade, Scriban, Fluid, Latte in brace-brace mode. The sandboxes matter: " +
				"Hackmanit measured Jinja2 sandbox and Twig sandbox behaving identically to the " +
				"unsandboxed builds on arithmetic, so triage loses nothing by stopping here and the escape " +
				"is the tool's job",
		},
		{
			id: sstiF3, logical: "<%=" + sstiA + "*" + sstiB + "%>", points: std, encoders: sstiAngleEncoders(), tier: triage.TierReduced,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "ERB, Erubi, Erubis, EJS, Underscore, Eta, ASP/VBScript, Mojolicious, EEx, JSP scriptlet. " +
				"In XML element text this needs the xml_cdata mode, because `&lt;%=` opens no scriptlet in " +
				"any grammar and the probe would be silently testing a different thing",
		},
		{
			id: sstiF4, logical: "#{" + sstiA + "*" + sstiB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Pug, Slim, Haml, FreeMarker's legacy numeric interpolation, and any sink that drops the " +
				"value into a Ruby double-quoted string that is later evaluated",
		},
		{
			id: sstiF5, logical: "@(" + sstiA + "*" + sstiB + ")", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Razor: ASP.NET Core Razor Pages, MVC views, RazorEngine.NetCore. @( ) is in none of the " +
				"common polyglots, so a battery without this row reports every .NET application clean",
		},
		{
			id: sstiF6, logical: "{" + sstiA + "*" + sstiB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Smarty 3 and later, Latte, patTemplate. The single brace is in none of the common " +
				"polyglots either, and Smarty is still one of the most widely deployed PHP engines",
		},
		{
			id: sstiF6L, logical: "{=" + sstiA + "*" + sstiB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Latte's explicit print form. Sent when F6 was silent and the route control indicates a " +
				"PHP stack, which is an ORDERING signal and never a suppression one",
		},
		{
			id: sstiF7, logical: "[[${" + sstiA + "*" + sstiB + "}]]", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Thymeleaf INLINE TEXT. Thymeleaf evaluates ${...} only inside a th: attribute, so F1 " +
				"renders literally in body text and Thymeleaf reads as clean on the most common placement " +
				"of all. This row is the whole of Thymeleaf's body-text coverage",
		},
		{
			id: sstiF8, logical: "#set($v=" + sstiA + "*" + sstiB + ")${v}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Velocity and VelocityJS. Velocity has NO bare expression form: ${1721*913} is not a " +
				"valid reference and renders literally, so F1 misses Velocity entirely and nothing but the " +
				"#set form reaches it",
		},
		{
			id: sstiF9, logical: "{{ " + sstiA + " | times: " + sstiB + " }}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Liquid, DotLiquid, Scriban's Liquid mode. Liquid has NO infix arithmetic at all, so " +
				"{{1721*913}} renders empty and reads exactly like a non-reflecting slot. Carries SPACE, " +
				"which is not a cookie-octet: on a cookie slot it is sent only when this class's own decode " +
				"probe proved decode_depth >= 1, and F9c is the space-free fallback",
		},
		{
			id: sstiF9c, logical: "{{" + sstiA + "|times:" + sstiB + "}}", points: []triage.SlotKind{triage.KindCookie}, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "space-free Liquid, cookie slots only. UNVERIFIED (CATALOGUE 9.3 item 9): Liquid's lexer " +
				"is believed to tolerate the absent spaces around the pipe and the colon, and that was not " +
				"run against Liquid in this work. It is sent anyway because a wrong guess here costs one " +
				"request and the alternative is a cookie slot with no Liquid coverage at all",
		},
		{
			id: sstiF10, logical: "{{" + sstiDjangoA + "|add:" + sstiDjangoB + "}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiDjangoExpected},
			notes: "Django Template Language. DTL has no infix arithmetic and {{1721*913}} is a " +
				"TemplateSyntaxError rather than a computation, so F2 cannot reach it. `add` is a SUM, and " +
				"a four-digit sum fails the six-digit guard of iso-eval 1.2, which is why this row alone " +
				"carries six-digit operands",
		},
		{
			id: sstiF10w, logical: "{% widthratio " + sstiA + " 1 " + sstiB + " %}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes: "Django's only multiplication: widthratio a b c computes a/b*c. Doubles as F10's " +
				"confirmation, because it is a different tag, a different arithmetic and a different " +
				"expected answer reaching the same engine",
		},
		{
			id: sstiF11,
			logical: `{{len "aaaaaaa"}}{{len "aaaa"}}{{len "aaaaaaaaa"}}{{len "aa"}}` +
				`{{len "aaaaaa"}}{{len "aaaaaaaa"}}`,
			points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiGoExpected},
			notes: "Go text/template and html/template. Their built-in function set is and, call, html, " +
				"index, slice, js, len, not, or, print, printf, println, urlquery plus the comparisons: no " +
				"arithmetic operator and no add, so every arithmetic probe is a parse error and " +
				`{{printf "%d" 1571273}} puts the answer in the wire. Six chained len calls over literals ` +
				"of length 7,4,9,2,6,8 yield 749268, which is computed and is not in the payload. 106 " +
				"bytes: on a slot whose FieldLimit is smaller this is cannot_determine (truncated) and the " +
				"operator is told Go coverage was lost there",
		},

		// -- confirmation battery -------------------------------------------------------------
		{id: sstiCF1, logical: "${" + sstiConfA + "-" + sstiConfB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected},
			notes:   "F1 confirmation: fresh marker, fresh operands, operator changed from * to -. Re-sending the first probe confirms a cache"},
		{id: sstiCF2, logical: "{{" + sstiConfA + "-" + sstiConfB + "}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F2 confirmation"},
		{id: sstiCF3, logical: "<%=" + sstiConfA + "-" + sstiConfB + "%>", points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F3 confirmation"},
		{id: sstiCF4, logical: "#{" + sstiConfA + "-" + sstiConfB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F4 confirmation"},
		{id: sstiCF5, logical: "@(" + sstiConfA + "-" + sstiConfB + ")", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F5 confirmation"},
		{id: sstiCF6, logical: "{" + sstiConfA + "-" + sstiConfB + "}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F6 and F6L confirmation"},
		{id: sstiCF7, logical: "[(${" + sstiConfA + "-" + sstiConfB + "})]", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected},
			notes:   "F7 confirmation, and deliberately the UNESCAPED Thymeleaf inline form [( )] rather than [[ ]], so the confirmation also proves which inline mode is live"},
		{id: sstiCF8, logical: "#set($w=" + sstiConfA + "-" + sstiConfB + ")${w}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F8 confirmation, and the reference name changes too so a cached ${v} cannot answer"},
		{id: sstiCF9, logical: "{{ " + sstiConfA + " | minus: " + sstiConfB + " }}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiConfExpected}, notes: "F9 and F9c confirmation: Liquid's minus filter"},
		{id: sstiCF11,
			logical: `{{len "aaa"}}{{len "aaaaaaaa"}}{{len "aaaaa"}}{{len "aaaaaaaaa"}}` +
				`{{len "aa"}}{{len "aaaaaaa"}}`,
			points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiGoConfExpected},
			notes:   "F11 confirmation: the literal lengths are redrawn to 3,8,5,9,2,7 so the expected answer is 385927 and a cached body cannot supply it"},

		// -- consumption battery ---------------------------------------------------------------
		{
			id: sstiC1, logical: "{{" + sstiTokenM2 + "}}" + sstiTokenM3, points: std, encoders: sstiStdEncoders(), tier: triage.TierReduced,
			variant: map[string]string{sstiVariantSiblings: "2"},
			notes: "Mustache, Handlebars, Pystache, MustacheJS, HoganJS. These engines are LOGIC-LESS BY " +
				"DESIGN: no arithmetic exists in them, so an arithmetic-only triage layer records an entire " +
				"engine family as clean. What they do do is parse and CONSUME their delimiters. Three " +
				"distinct markers make that unforgeable: a hit needs M1 immediately followed by M3 with M2 " +
				"absent everywhere, which a brace-stripping sanitizer (leaving M1M2M3) cannot produce and " +
				"which no truncated prefix of the payload contains",
		},
		{id: sstiC2, logical: "${" + sstiTokenM2 + "}" + sstiTokenM3, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantSiblings: "2"}, notes: "consumption through the ${ } delimiter"},
		{id: sstiC3, logical: "<%=" + sstiTokenM2 + "%>" + sstiTokenM3, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantSiblings: "2"}, notes: "consumption through the <%= %> delimiter"},
		{id: sstiC4, logical: "{" + sstiTokenM2 + "}" + sstiTokenM3, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantSiblings: "2"}, notes: "consumption through the single brace, tier 2"},
		{id: sstiC5, logical: "#{" + sstiTokenM2 + "}" + sstiTokenM3, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantSiblings: "2"}, notes: "consumption through #{ }, tier 2"},
		{
			id: sstiCC1, logical: "{{#if " + sstiTokenM2 + "}}x{{/if}}" + sstiTokenM3, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantSiblings: "2"},
			notes: "C1 confirmation, Handlebars section form. It is what separates a PARSER from a " +
				"STRIPPER: a parser consumes the whole block including the literal x, a stripper removes " +
				"the braces and leaves the x behind, which downgrades to cannot_determine (stripper)",
		},
		{
			id: sstiCC2, logical: "{{#" + sstiTokenM2 + "}}x{{/" + sstiTokenM2 + "}}" + sstiTokenM3, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantSiblings: "2"},
			notes:   "C1 confirmation, Mustache section form, for the engines that reject Handlebars's #if",
		},

		// -- the division triple, ruling R1 -----------------------------------------------------
		{
			id: sstiZ1, logical: "${" + sstiA + "/0}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "ruling R1's replacement for the abolished foreign-error clause. A class never reads " +
				"another class's signature catalogue, not even to fail closed, so when this class's own " +
				"oracles are silent on a plainly perturbed response it sends ITS OWN disambiguator. It is " +
				"also the strongest single statement this class can make short of a computation hit: a " +
				"division-by-zero signature proves an EXPRESSION EVALUATOR ran, not merely that a parser " +
				"read the delimiters. Non-destructive: division by zero raises and destroys nothing",
		},
		{id: sstiZ2, logical: "{{" + sstiA + "/0}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull, notes: "the brace-brace arm of the division triple"},
		{id: sstiZ3, logical: "<%=" + sstiA + "/0%>", points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull, notes: "the scriptlet arm of the division triple"},

		// -- distinctive content and identification ---------------------------------------------
		{id: sstiD1, logical: "{$smarty.version}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "Smarty, and the match is its exact version. Must not fire on a version-shaped string already in the baseline"},
		{id: sstiD2, logical: "{{.}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "Go text/template or html/template, and the returned literal says what the root data value is: <no value>, map[, &{ or []"},
		{id: sstiD3, logical: "${(" + sstiA + "*" + sstiB + ")?c}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			variant: map[string]string{sstiVariantExpected: sstiExpected},
			notes:   "FreeMarker's ?c computer-format builtin. It is the answer to the locale grouping problem: an UNGROUPED 1571273 here is proof the builtin ran and therefore that the engine is FreeMarker"},
		{id: sstiI1, logical: "{{1in[1]}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "Hackmanit nonerrIdent1. One request splits the whole {{ }} candidate set: True is Jinja2/Tornado/Groovy, 1 is Twig, {1} is Latte, empty is Nunjucks/Liquid/Mustache-family/Fluid, an error is the rest"},
		{id: sstiI2, logical: `${"<%-1-%>"}`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			notes: `Hackmanit nonerrIdent2, splits the ${ } and <%= %> sets: ${""} is ERB/Erubi/Erubis/Eta, ${"1"} is EJS, <%-1-%> is Groovy/FreeMarker/Mako/Cheetah3, $<%-1-%> is Smarty`},
		{id: sstiI3, logical: `#evaluate("a")`, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "Hackmanit nonerrIdent3: Velocity returns a, VelocityJS returns empty, Thymeleaf and Haml and Pug error"},
		{id: sstiI4, logical: `{{"<b>x</b>"}}`, points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull,
			notes: "tells Go html/template (&lt;b&gt;) from text/template (<b>). Different packages, and the escaping one is a materially weaker finding, so the operator should be told which"},
		{id: sstiI5, logical: `{{'x'|upper}}`, points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "Jinja2 rather than Tornado, by the filter pipe. UNVERIFIED (CATALOGUE 9.3 item 9): Jinja2's pipe is documented and Tornado has no filter operator, so Tornado should raise a Python TypeError, but neither engine was run in this work"},
		{id: sstiI6, logical: "{$smarty.now}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull,
			notes: "Smarty confirmation: a ten-digit epoch within 300 seconds of the run's wall clock is a value the application computed and could not have echoed"},

		// -- Hackmanit language polyglots, identification step B ---------------------------------
		{id: sstiEPPython, logical: "${{/#}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull, notes: "errPython: all 9 examined Python engines error, 36 of 52 overall"},
		{id: sstiEPRuby, logical: "<%{{#{%>}", points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull, notes: "errRuby: all 6 examined Ruby engines, 38 of 52"},
		{id: sstiEPDotnet, logical: "{{@", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull, notes: "errDotnet: all 5 examined .NET engines, 26 of 52"},
		{id: sstiEPJava, logical: "<%'#{@}", points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull, notes: "errJava: all 5 examined Java engines, 19 of 52"},
		{id: sstiEPPHP, logical: "{{/}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull, notes: "errPHP: all 8 examined PHP engines, 29 of 52"},
		{id: sstiEPJS, logical: "<%${{#{%>}}", points: std, encoders: sstiAngleEncoders(), tier: triage.TierFull, notes: "errJavascript: all 13 examined JavaScript engines, 45 of 52"},
		{id: sstiEPGo, logical: "{{", points: std, encoders: sstiStdEncoders(), tier: triage.TierFull, notes: "errGolang: both examined Go engines, 23 of 52. Two bytes, and that is the whole polyglot"},

		// -- negative controls --------------------------------------------------------------------
		{
			id: sstiNC1, logical: "x7Bx7B" + sstiA + "mul" + sstiB + "x7Dx7D", points: std, encoders: sstiStdEncoders(),
			tier: triage.TierReduced, control: true,
			notes: "INERT ECHO. Every delimiter byte is replaced by a letter pair and the operator by mul, " +
				"so the payload has the same length band and the same alphabet shape as F2 and computes " +
				"nothing. If COMPUTATION fires here the matcher is finding the answer unanchored, or the " +
				"page contains it, and every verdict on this slot becomes cannot_determine " +
				"(detector_unverified)",
		},
		{
			id: sstiNC2, logical: sstiExpected, points: std, encoders: sstiStdEncoders(),
			tier: triage.TierReduced, control: true,
			notes: "THE ANSWER, SENT. The regex WILL match this. The answer_not_in_wire guard MUST suppress " +
				"it. This control verifies the GUARD rather than the regex and it is the one most likely to " +
				"be left out, because it is the only control that is supposed to produce a textual match",
		},
		{id: sstiNC3a, logical: "{{}}", points: std, encoders: sstiStdEncoders(), tier: triage.TierReduced, control: true,
			notes: "empty expression, valid delimiters. COMPUTATION must stay silent because nothing was computed, and CONSUMPTION must stay silent because there is no M2 to be absent. If the engine ERRORS here the error oracle may legitimately fire and that is not a control failure"},
		{id: sstiNC3b, logical: "${}", points: std, encoders: sstiStdEncoders(), tier: triage.TierReduced, control: true,
			notes: "the ${ } arm of the empty-expression control"},
		{
			id: sstiNC4, logical: sstiTokenM2 + sstiTokenM3, points: std, encoders: sstiStdEncoders(),
			tier: triage.TierReduced, control: true, variant: map[string]string{sstiVariantSiblings: "2"},
			notes: "three markers, NO delimiters. M1 and M3 are not adjacent and M2 is present, so " +
				"CONSUMPTION must stay silent. This catches the implementation that checks only whether M1 " +
				"and M3 are both present, which is the obvious wrong way to write the rule",
		},
	}
}

// Probes returns the declared payload set. Plan's output is checked against it, so nothing can be
// conjured at run time and escape the build-time isolation check.
func (sstiClassifier) Probes() []triage.ProbeSpec {
	rows := sstiProbeTable()
	out := make([]triage.ProbeSpec, 0, len(rows))
	for _, r := range rows {
		out = append(out, triage.ProbeSpec{
			ID:        r.id,
			Class:     triage.ClassSSTI,
			Logical:   []byte(r.logical),
			Encoders:  r.encoders,
			Points:    r.points,
			MarkerPos: triage.MarkerPrefix,
			Tier:      r.tier,
			// Every payload here is R1: it writes a value the application already accepts into a
			// slot it already reads. Nothing creates, modifies or deletes a record; the strongest
			// side effect in the whole set is a caught exception.
			Risk:      triage.RiskR1,
			IsControl: r.control,
			Notes:     r.notes,
		})
	}
	return out
}

func sstiSpecByID() map[triage.ProbeID]sstiRow {
	rows := sstiProbeTable()
	m := make(map[triage.ProbeID]sstiRow, len(rows))
	for _, r := range rows {
		m[r.id] = r
	}
	return m
}

// ---------------------------------------------------------------------------------------------
// 5. REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. CATALOGUE 3.1, the SSTI row.
//
// A TEMPLATE SINK TAKES A STRING. That single fact drives every answer here: anywhere a string can
// be delivered, this class reaches; the JSON container node and the whole-document replacement are
// not string slots and are declined by name rather than by omission.
func (sstiClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery, triage.KindPath, triage.KindHeader:
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "every payload but four is pure cookie-octet and goes raw; F9, F10w, S2 and F11 carry a " +
				"SPACE, which is not a cookie-octet, so on a cookie slot they need this class's own decode " +
				"probe to have proved decode_depth >= 1, and F9c is the space-free Liquid fallback",
		}
	case triage.KindBody:
		reason := "a JSON string, a form field, a multipart part value and XML element text are all string " +
			"slots and are reached; a JSON CONTAINER NODE is not, because a template sink takes a string " +
			"and not an object, and a number, boolean or null slot is reached only in its " +
			"json_string_coerced form, where a 400 is type_rejection and never clean"
		if strings.Contains(string(mt), "xml") {
			reason = "XML element text is reached, and F3, S1, S1q, S1s, S1b, S2, I2, I4, CF3, Z3, errRuby, " +
				"errJava and errJavascript carry a raw `<` which must be `&lt;` in element text: an engine " +
				"handed `&lt;%=` opens no scriptlet, so those rows need the xml_cdata encoder mode and the " +
				"delivery is recorded, because a CDATA-delivered value is processed differently by some " +
				"parsers and that is a variable rather than a detail"
		}
		return triage.Reachability{Reach: triage.ReachConditional, Reason: reason}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "not_applicable (fragment): RFC 3986 section 3.5 makes the fragment a client-side " +
				"reference and every browser strips it before the request goes out, so no server-side " +
				"template engine can see it under any encoding. The client-side counterpart is the CSTI " +
				"class, which reaches it by driving a headless browser rather than by sending a request",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "slot kind " + string(k) + " is not in the closed set this class was specified against",
		}
	}
}

// ---------------------------------------------------------------------------------------------
// 6. THE LADDER
// ---------------------------------------------------------------------------------------------

// sstiRefusal is a reason this class must not send on this slot, together with the state the
// verdict has to carry. Both halves travel together so a refusal can never reach Classify with the
// reason and the state out of step.
type sstiRefusal struct {
	state  triage.TriageState
	reason string
}

// sstiWhyNotSend decides whether a single byte may leave the process for this slot.
//
// IT IS THE SAME FUNCTION PLAN AND CLASSIFY BOTH CALL, which is the point: a refusal that Plan
// applies and Classify does not know about is a slot with no requests and no row, and a slot with
// no row reads as untouched.
func sstiWhyNotSend(ctx triage.PlanCtx) (sstiRefusal, bool) {
	s := ctx.Slot
	if s.Kind == triage.KindFragment || !s.ServerReachable {
		return sstiRefusal{triage.StateNotApplicable,
			"fragment: the bytes are never transmitted, so a server-side template engine cannot see them under any encoding. The client-side analogue is the CSTI class"}, true
	}
	if s.Constraints.IsCredential {
		return sstiRefusal{triage.StateNotProbed,
			"credential_slot: injecting into an Authorization header or a session cookie produces a 401, and that 401 is a differential against baseline that looks exactly like a finding"}, true
	}
	if !ctx.Route.Resolved() {
		return sstiRefusal{triage.StateCannotDetermine,
			"route_unresolved: the composed URL did not resolve at its observed value, so there is no control to difference an error signature against and no evidence that a probe would reach the same handler"}, true
	}
	if ctx.Prelude.Failed() && s.Kind == triage.KindBody {
		return sstiRefusal{triage.StateCannotDetermine,
			"prelude_failed: a body slot on this vector needs a token this run could not obtain, so every probe would fail validation identically, which reads as a stable endpoint with no differential, which reads as clean. Header, cookie, query and path slots on this vector are still probed"}, true
	}
	return sstiRefusal{}, false
}

// Plan is the ladder of iso-eval SSTI 8.1. Round 0 is the census, round 1 the batteries, round 2
// the escalation a hit earns, round 3 the identification finishers.
//
// THERE IS NO EARLY EXIT ON "NOTHING FOUND YET", and that is the single most important line in the
// function. A negative from F1 says nothing whatever about F5: they are different grammars reaching
// disjoint engine sets. The only early exits are a CONFIRMED hit (one sink runs one engine, so the
// remaining families are testing for a second engine on the same sink, which is not a thing), a
// uniform block, and a failed route or prelude.
func (sstiClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, refuse := sstiWhyNotSend(ctx); refuse {
		return nil
	}
	if ctx.Budget.Exhausted() {
		return nil
	}
	switch ctx.Round {
	case 0:
		return sstiPlanCensus(ctx)
	case 1:
		return sstiPlanBatteries(ctx)
	case 2:
		return sstiPlanEscalation(ctx)
	case 3:
		return sstiPlanFinishers(ctx)
	default:
		return nil
	}
}

// sstiPlanCensus is round 0: this class's own reflection census, its own decode probe, and the
// error polyglots, which are the only oracle available on a sink that never reflects.
func sstiPlanCensus(ctx triage.PlanCtx) []triage.ProbeRequest {
	want := []triage.ProbeID{sstiS0}
	if sstiPercentRelevant(ctx.Slot.Kind) {
		want = append(want, sstiDEC)
	}
	want = append(want, sstiS1, sstiS1q, sstiS1s, sstiS1b)
	return sstiRequests(ctx, want)
}

// sstiBlindArmOrder is the ten probes of the non-reflective arm, in send order.
//
// THE TWO INERT CONTROLS GO FIRST and that is not cosmetic. If the budget truncates the list,
// losing a delimiter pair costs the arm one family; losing BN1 or BN2 costs it the right to read
// ANY pair, because without the length control a separation cannot be told from an endpoint whose
// response length follows its input length. ELI's ladder makes the same ordering for the same
// reason and says so in eliPlanRound.
func sstiBlindArmOrder() []triage.ProbeID {
	return []triage.ProbeID{
		sstiBN1, sstiBN2,
		sstiBOK3, sstiBER3, sstiBOK4, sstiBER4,
		sstiBOK1, sstiBER1, sstiBOK2, sstiBER2,
	}
}

// sstiBlindArmEarned is the gate on the non-reflective arm, spelled out rather than folded into
// one boolean so each half can be read. It is the same gate round 2 has always applied; it is a
// function now because round 1 has to ask it too.
//
//	reflectMeasure     the census got a response, so we know what we are talking about
//	!reflects          the census marker did not come back, so the computation oracle is blind here
//	computeFamily==""  nothing computed, so the strongest oracle in the class has not answered
func sstiBlindArmEarned(sc sstiScorecard) bool {
	return sc.reflectMeasure && !sc.reflects && sc.computeFamily == ""
}

// sstiPlanBatteries is round 1: eleven computation families and five consumption families, plus
// the non-error polyglot for the application that swallows template exceptions.
//
// TWO THINGS HAPPEN HERE THAT DID NOT USED TO, AND BOTH ARE ABOUT THE ARM THAT ANSWERS WHEN
// NOTHING COMES BACK. Both were MEASURED against the canary oracle on 2026-09-19 with the whole
// registry enabled at full tier.
//
// (1) A UNIFORM BLOCK NO LONGER RETIRES THE CLASS BEFORE THE ARM IS EVER PLANNED. The runner's
// ladder is `reqs := c.Plan(planCtx); if len(reqs) == 0 { done[class] = true }`, so the FIRST
// round that plans nothing ends the class for that slot and round 2 is never called. Returning
// nil here therefore did not suppress the battery, it suppressed everything after it. Measured:
// on /ssti/blind, WHICH IS THIS CLASS'S OWN DECLARED POSITIVE ROUTE FOR THE BLIND ARM, the verdict
// was "blocked: three or more of this class's own distinct payloads produced byte-identical
// responses that differ from the route control" and not one of the arm's ten probes was sent. The
// same shape silenced it on /trav/blind. The "uniform block" there is an application raising:
// /ssti/blind answers 200 and the baseline page to every payload that PARSES and 500
// {"error":"render_failed"} to every payload that does not, which is one non-baseline body shared
// by three or more distinct payloads and is therefore indistinguishable, to that heuristic, from
// /clean/waf's identical 403.
//
// THE ARM IS SAFE ON A REAL BLOCK AND THE HEURISTIC IS NOT THE THING KEEPING IT SO. Its own two
// controls are strictly stronger. On /clean/waf, which 403s any metacharacter, BOK3 and BER3 both
// carry braces, both get the same 403, and the pair does not separate: the arm runs and is
// SILENT, which is what this class's own OracleCases already declare for that route
// ("blind_arm_on_a_uniform_block", negative). Control A refuses the arm outright on any endpoint
// whose two garbage payloads land in different status classes. So the battery stays suppressed on
// a uniform block, which is what the gate is for, and the arm is planned instead of nothing.
//
// (2) THE ARM GOES OUT BEFORE THE BATTERY WHEN THE CENSUS HAS ALREADY SAID THE SLOT DOES NOT
// REFLECT. Measured on the operator's live JSON API, and reproducible at the default per-slot cap
// of 24: rounds 0 and 1 spend all 24 (six, then eighteen) and the arm's ten requests never leave,
// so the verdict said "blind_arm_not_run (length_control_not_measured)" on every slot. That
// sentence was true and its cause was a budget, not the endpoint.
//
// THIS IS AN ORDERING CHANGE AND NEVER A SUPPRESSION. Every battery probe is still requested,
// after the arm, and whichever ones the cap cuts are named in Untested with their own reason. The
// order is right on the merits too: when the census marker did not come back, all twelve
// computation families and all five consumption families need a value back that will not come,
// while the error polyglots that do not need one already went out in round 0. The arm is the only
// oracle left that can answer, so it is the last thing that should be cut.
func sstiPlanBatteries(ctx triage.PlanCtx) []triage.ProbeRequest {
	sc := sstiScore(triage.ClassifyCtx{PlanCtx: ctx})
	fam := []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF7, sstiF8, sstiF9, sstiF10, sstiF10w, sstiF11}
	sstiOrderByStack(ctx, fam)
	return sstiRequests(ctx, sstiRound1Order(ctx.Slot.Kind, fam, sstiUniformBlock(ctx), sstiBlindArmEarned(sc)))
}

// sstiRound1Order is round 1's probe order as a pure function of the four things that decide it.
// It is split out for the reason every rule in this file is split out: a classifier cannot build
// a populated PlanCtx in a test, because ctx.Own is minted by the vault under a capability whose
// type lives in an internal package, so a rule left inline is a rule whose only reachable branch
// in a test is the one where nothing has happened yet. Both of the changes described on
// sstiPlanBatteries live here so both are exercised.
func sstiRound1Order(kind triage.SlotKind, fam []triage.ProbeID, blocked, blindEarned bool) []triage.ProbeID {
	if blocked {
		if !blindEarned {
			return nil
		}
		return sstiBlindArmOrder()
	}
	var want []triage.ProbeID
	if blindEarned {
		want = append(want, sstiBlindArmOrder()...)
	}
	want = append(want, fam...)
	if kind == triage.KindCookie {
		want = append(want, sstiF9c)
	}
	return append(want, sstiC1, sstiC2, sstiC3, sstiC4, sstiC5, sstiS2)
}

// sstiPlanEscalation is round 2. Four independent triggers, and they compose: a slot can earn a
// confirmation AND a division triple in the same round.
func sstiPlanEscalation(ctx triage.PlanCtx) []triage.ProbeRequest {
	sc := sstiScore(triage.ClassifyCtx{PlanCtx: ctx})
	if sstiUniformBlock(ctx) {
		// The same rule round 1 applies, and for the same measured reason: on a uniform block the
		// escalation probes below are all earned by a hit that a block page cannot produce, but
		// the arm is earned by the ABSENCE of an oracle and carries its own controls. sstiRequests
		// drops whatever round 1 already sent, so this is the retry for a slot whose cap bit
		// mid-arm and nothing otherwise.
		if !sstiBlindArmEarned(sc) {
			return nil
		}
		return sstiRequests(ctx, sstiBlindArmOrder())
	}
	var want []triage.ProbeID

	// (a) a computation hit earns its confirmation, the four controls, and step A of identification.
	if sc.computeFamily != "" {
		if cf, ok := sstiConfirmFor[sc.computeFamily]; ok {
			want = append(want, cf...)
		}
		want = append(want, sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4)
		want = append(want, sstiIdentStepA(sc.computeFamily)...)
	}

	// (b) a consumption hit earns the parser-versus-stripper pair, which is the only thing that
	// tells a template engine from a sanitizer that deletes braces.
	if sc.consumeFamily != "" {
		want = append(want, sstiCC1, sstiCC2, sstiNC4)
	}

	// (c) ruling R1. The response is plainly perturbed, none of this class's own rules fired, and
	// this class will NOT go looking in another class's signature catalogue to explain it. It
	// sends its own division triple instead, which also answers evaluator-versus-parser.
	if sc.perturbedUnexplained || sc.errorSignature != "" {
		want = append(want, sstiZ1, sstiZ2, sstiZ3)
		// The attribute-access forms ride with the triple rather than being earned separately,
		// because they answer the SAME question for the engines the triple cannot reach: Node and
		// PHP 7 tolerate the division and only the following attribute access throws, so Z1 to Z3
		// come back silent from a JavaScript template that ZB2 would have named.
		want = append(want, sstiZB1, sstiZB2, sstiZB3, sstiZB4)
	}

	// (f) THE BLIND ARM. Earned by the absence of the rank 1 oracle rather than by a hit, which
	// is what makes it the answer to the measurement this whole change is about. The gate is
	// sstiBlindArmEarned and its three halves are written out there.
	//
	// ROUND 1 NOW ASKS FOR IT FIRST when the census has already said the slot does not reflect,
	// because at the default per-slot cap of 24 rounds 0 and 1 spend the whole allowance and this
	// round never gets to send anything. This request stays because the cap can bite mid-arm:
	// sstiRequests drops whatever already went out, so what is left here is the remainder.
	//
	// TIER full ONLY, through sstiRequests, because it is ten requests per slot and it is the
	// weakest oracle here. A reduced-tier run does not pay for it and its rows say so by name.
	if sstiBlindArmEarned(sc) {
		want = append(want, sstiBlindArmOrder()...)
	}

	// (d) F6 silent on a PHP-indicating stack earns Latte's explicit print form.
	if sc.silent(sstiF6) && sstiStackHint(ctx) == "php" {
		want = append(want, sstiF6L)
	}

	// (g) THE FIVE NEGATIVE CONTROLS, ON THE SLOT THAT IS HEADING FOR A CLEAN.
	//
	// THE DEFECT THIS CLOSES, AND IT IS THE ONE SHAPE THIS WHOLE LAYER EXISTS TO STOP. Until now
	// NC1, NC2, NC3a, NC3b and NC4 were requested in ONE place, branch (a), which is earned by a
	// computation hit. So on a slot where nothing fired, the five probes that verify this class's
	// own matcher never left, and the clean at the bottom of the ladder rested on
	// sc.controlFired being empty, which it must be when no control was ever sent. The clean's
	// own stated precondition ("its own four controls stayed silent") was a statement about
	// requests that did not happen. MEASURED on /clean/echo, 2026-09-19: 31 ordinals, and
	// SSTI-NC1, SSTI-NC2, SSTI-NC3a, SSTI-NC3b and SSTI-NC4 all in Untested reading "only earned
	// by a first hit".
	//
	// /clean/echo IS THE ROUTE THIS CLASS NAMES FOR EXACTLY THESE FIVE. Four of its own
	// OracleCases point NC1, NC2, NC3a and NC4 at it, and the note on NC2 is explicit: it SENDS
	// the expected answer next to the marker so the answer-not-in-wire guard has something to
	// suppress. That verification was declared and never run.
	//
	// FIVE REQUESTS, AND THEY ARE THE CHEAPEST FIVE IN THE CLASS. At the default per-slot cap of
	// 24 they will often not leave, and then they are named in Untested as a BUDGET gap, which
	// blocks the clean rather than decorating it. That is the intended trade: a clean this class
	// cannot afford to verify is a clean it does not get to say.
	if sstiControlsEarned(sc) {
		want = append(want, sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4)
	}

	// (e) S2 came back DIVERGED and no family computed: the delimiters it carries are the ones to
	// confirm, so the matching confirmation goes out even with no computation hit. It is gated on
	// diverged and not on encoded, because an entity-escaped copy has every delimiter still in it
	// and there is nothing to reproduce.
	if sc.polyglot == sstiPolyglotDiverged && sc.computeFamily == "" {
		want = append(want, sstiCF1, sstiCF2, sstiCF7)
	}
	return sstiRequests(ctx, want)
}

// sstiPlanFinishers is round 3: the engine-specific probes that turn "SSTI" into "Jinja2", which
// is the difference between a tool run that works and one that has no plugin for the engine.
func sstiPlanFinishers(ctx triage.PlanCtx) []triage.ProbeRequest {
	sc := sstiScore(triage.ClassifyCtx{PlanCtx: ctx})
	if sc.computeFamily == "" && sc.consumeFamily == "" && sc.errorSignature == "" {
		return nil
	}
	var want []triage.ProbeID
	switch sc.computeFamily {
	case sstiF1:
		want = append(want, sstiD3, sstiI2, sstiEPJava, sstiEPPython)
	case sstiF2:
		want = append(want, sstiI1, sstiI5, sstiEPPython, sstiEPPHP, sstiEPJS)
	case sstiF3:
		want = append(want, sstiI2, sstiEPRuby, sstiEPJS)
	case sstiF4:
		want = append(want, sstiEPRuby, sstiEPJava)
	case sstiF5:
		want = append(want, sstiEPDotnet)
	case sstiF6, sstiF6L:
		want = append(want, sstiD1, sstiI6, sstiEPPHP)
	case sstiF8:
		want = append(want, sstiI3)
	case sstiF11:
		want = append(want, sstiD2, sstiI4)
	}
	if sc.computeFamily == "" && sc.consumeFamily != "" {
		// A logic-less engine computed nothing, so step A is unavailable. I1 is still the cheapest
		// split of the brace-brace set and D2 separates Go, which parses but also computes.
		want = append(want, sstiI1, sstiD2)
	}
	return sstiRequests(ctx, want)
}

// sstiConfirmFor maps a family that fired to the probes that must reproduce the effect with a
// FRESH MARKER AND FRESH OPERANDS before CATALOGUE 4.2 lets the verdict grade high.
var sstiConfirmFor = map[triage.ProbeID][]triage.ProbeID{
	sstiF1:   {sstiCF1},
	sstiF2:   {sstiCF2},
	sstiF3:   {sstiCF3},
	sstiF4:   {sstiCF4},
	sstiF5:   {sstiCF5},
	sstiF6:   {sstiCF6},
	sstiF6L:  {sstiCF6},
	sstiF7:   {sstiCF7},
	sstiF8:   {sstiCF8},
	sstiF9:   {sstiCF9},
	sstiF9c:  {sstiCF9},
	sstiF10:  {sstiF10w},
	sstiF10w: {sstiF10},
	sstiF11:  {sstiCF11},
	sstiD3:   {sstiCF1},
	sstiC1:   {sstiCC1, sstiCC2},
	sstiC2:   {sstiCF1},
	sstiC3:   {sstiCF3},
	sstiC4:   {sstiCF6},
	sstiC5:   {sstiCF4},
}

// sstiIdentStepA is the identification probe set a family earns immediately. Six of the eleven
// families identify the engine in one step and need nothing further.
func sstiIdentStepA(fam triage.ProbeID) []triage.ProbeID {
	switch fam {
	case sstiF2:
		return []triage.ProbeID{sstiI1}
	case sstiF1, sstiF3:
		return []triage.ProbeID{sstiI2}
	case sstiF8:
		return []triage.ProbeID{sstiI3}
	case sstiF6:
		return []triage.ProbeID{sstiD1}
	case sstiF11:
		return []triage.ProbeID{sstiD2}
	default:
		// F5 Razor, F7 Thymeleaf inline, F9 Liquid, F10 Django are each identified by the family
		// alone. Spending a request to confirm what the grammar already proved buys nothing.
		return nil
	}
}

// sstiPercentRelevant reports whether the decode probe has anything to measure. Ruling R6: zero
// cost on JSON string, header, multipart and XML slots, where no payload in this class needs
// percent-encoding at all.
func sstiPercentRelevant(k triage.SlotKind) bool {
	return k == triage.KindQuery || k == triage.KindBody || k == triage.KindPath || k == triage.KindCookie
}

// sstiRequests turns a wanted probe list into requests, dropping anything already sent, anything
// this slot cannot carry, and anything the budget no longer allows.
//
// A DROP IS NEVER SILENT: sstiUntested rebuilds exactly the same decisions at Classify time and
// writes a named row for each, because a family that was never sent and is not named reads as a
// family that came back clean.
func sstiRequests(ctx triage.PlanCtx, want []triage.ProbeID) []triage.ProbeRequest {
	specs := sstiSpecByID()
	sent := sstiSentProbes(ctx.Own)
	budget := ctx.Budget.RemainingPerSlot
	if ctx.Budget.RemainingPerRun > 0 && ctx.Budget.RemainingPerRun < budget {
		budget = ctx.Budget.RemainingPerRun
	}
	out := make([]triage.ProbeRequest, 0, len(want))
	for _, id := range want {
		if budget > 0 && len(out) >= budget {
			break
		}
		row, ok := specs[id]
		if !ok || sent[id] {
			continue
		}
		if !sstiPointsInclude(row.points, ctx.Slot.Kind) {
			continue
		}
		if !sstiFitsField(row, ctx.Slot.Constraints.FieldLimit) {
			continue
		}
		if !sstiCookieDeliverable(row, ctx.Slot) {
			continue
		}
		out = append(out, triage.ProbeRequest{
			Spec:    id,
			Slot:    ctx.Slot.Key,
			Variant: sstiVariant(row),
		})
	}
	return out
}

func sstiVariant(r sstiRow) map[string]string {
	if len(r.variant) == 0 {
		return nil
	}
	v := make(map[string]string, len(r.variant))
	for k, val := range r.variant {
		v[k] = val
	}
	return v
}

func sstiPointsInclude(points []triage.SlotKind, k triage.SlotKind) bool {
	for _, p := range points {
		if p == k {
			return true
		}
	}
	return false
}

// sstiFitsField answers whether the payload plus its markers survives a measured truncation.
// FieldLimit 0 means nobody measured it, which is not the same as "no limit", so the probe is sent
// and a silent result is downgraded rather than read as clean.
func sstiFitsField(r sstiRow, limit int) bool {
	if limit <= 0 {
		return true
	}
	return sstiWireLen(r) <= limit
}

// sstiWireLen is the logical length once the runner has done its substitutions: the marker prefix,
// the payload, and one extra marker for each sibling token.
func sstiWireLen(r sstiRow) int {
	n := triage.MarkerLen + len(r.logical)
	n += strings.Count(r.logical, sstiTokenM2) * (triage.MarkerLen - len(sstiTokenM2))
	n += strings.Count(r.logical, sstiTokenM3) * (triage.MarkerLen - len(sstiTokenM3))
	if strings.Contains(r.logical, sstiTokenPctMarker) {
		// Each of the sixteen marker bytes renders as three percent-encoded bytes.
		n += triage.MarkerLen*3 - len(sstiTokenPctMarker)
	}
	return n
}

// sstiCookieDeliverable is the SPACE question. SPACE is not a cookie-octet, so a space-bearing
// payload on a cookie slot only arrives if the application percent-decodes its cookie values, and
// that is measured by this class's own decode probe rather than assumed.
func sstiCookieDeliverable(r sstiRow, s triage.Slot) bool {
	if s.Kind != triage.KindCookie || !strings.Contains(r.logical, " ") {
		return true
	}
	return s.Constraints.DecodeDepth >= 1
}

// sstiSentProbes is the set of this class's own probes that already have a response.
func sstiSentProbes(own triage.OwnedResponses) map[triage.ProbeID]bool {
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

// sstiStackHint reads the ROUTE CONTROL, which is a Replay and therefore a legitimately shared
// observation, for a banner naming a runtime.
//
// IT REORDERS AND IT NEVER SUPPRESSES. A Java banner on a reverse proxy in front of a Python origin
// is an ordinary deployment, and a class that skipped F10 because the banner said Java would miss
// Django on exactly the deployment where the banner lies.
func sstiStackHint(ctx triage.PlanCtx) string {
	if !ctx.Route.Resolved() {
		return ""
	}
	obs := ctx.Route.Obs()
	var b strings.Builder
	for _, h := range obs.RespHeaders {
		n := strings.ToLower(h[0])
		if n == "x-powered-by" || n == "server" || n == "set-cookie" || n == "x-aspnet-version" {
			b.WriteString(strings.ToLower(h[1]))
			b.WriteByte(' ')
		}
	}
	s := b.String()
	switch {
	case strings.Contains(s, "php") || strings.Contains(s, "phpsessid") || strings.Contains(s, "laravel"):
		return "php"
	case strings.Contains(s, "asp.net") || strings.Contains(s, "kestrel") || strings.Contains(s, "iis"):
		return "dotnet"
	case strings.Contains(s, "express") || strings.Contains(s, "node") || strings.Contains(s, "connect.sid"):
		return "node"
	case strings.Contains(s, "django") || strings.Contains(s, "wsgi") || strings.Contains(s, "gunicorn") || strings.Contains(s, "sessionid"):
		return "python"
	case strings.Contains(s, "rails") || strings.Contains(s, "puma") || strings.Contains(s, "phusion") || strings.Contains(s, "_session_id"):
		return "ruby"
	case strings.Contains(s, "jsessionid") || strings.Contains(s, "tomcat") || strings.Contains(s, "jetty") || strings.Contains(s, "wildfly"):
		return "java"
	case strings.Contains(s, "golang") || strings.Contains(s, "gin") || strings.Contains(s, "echo/"):
		return "golang"
	}
	return ""
}

// sstiStackOrder is the family ordering per runtime, from iso-eval SSTI 7. Ordering only.
var sstiStackOrder = map[string][]triage.ProbeID{
	"java":   {sstiF1, sstiF2, sstiF7, sstiF8},
	"python": {sstiF1, sstiF2, sstiF10},
	"php":    {sstiF2, sstiF6},
	"ruby":   {sstiF3, sstiF4},
	"node":   {sstiF2, sstiF3, sstiF4},
	"dotnet": {sstiF5, sstiF2},
	"golang": {sstiF11},
}

// sstiOrderByStack stable-sorts the family list so the indicated runtime's families go first. It
// never removes one.
func sstiOrderByStack(ctx triage.PlanCtx, fam []triage.ProbeID) {
	pref, ok := sstiStackOrder[sstiStackHint(ctx)]
	if !ok {
		return
	}
	rank := map[triage.ProbeID]int{}
	for i, id := range pref {
		rank[id] = i
	}
	sort.SliceStable(fam, func(i, j int) bool {
		ri, oki := rank[fam[i]]
		rj, okj := rank[fam[j]]
		if oki && okj {
			return ri < rj
		}
		return oki && !okj
	})
}

// sstiUniformBlock is early exit 2 of iso-eval 8.1: three or more of THIS CLASS'S OWN distinct
// payloads produce byte-identical responses that differ from the route control.
//
// Continuing to push eighteen more payloads into a WAF buys nothing and spends the rate budget
// other slots need, and, more importantly, the silence is not this application's silence. The
// verdict is cannot_determine (blocked).
func sstiUniformBlock(ctx triage.PlanCtx) bool {
	if !ctx.Route.Resolved() {
		return false
	}
	base := ctx.Route.Obs().BodySHA256
	counts := map[[32]byte]int{}
	seenProbe := map[triage.ProbeID]bool{}
	for i := 0; i < ctx.Own.Len(); i++ {
		p, obs, err := ctx.Own.At(i)
		if err != nil || seenProbe[p.ProbeID()] || !obs.Delivered() {
			continue
		}
		seenProbe[p.ProbeID()] = true
		if obs.BodySHA256 == base {
			continue
		}
		counts[obs.BodySHA256]++
	}
	for _, n := range counts {
		if n >= 3 {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 7. THE FOUR ORACLES
// ---------------------------------------------------------------------------------------------

// sstiHit is one oracle match, with everything a grade needs.
type sstiHit struct {
	Offset     int
	Length     int
	GapBytes   int
	Matched    []byte
	MarkerForm string
	Where      string // "body" or a response header name
}

// sstiComputationHit is RULE COMPUTATION, rank 1. iso-eval SSTI 2.1.
//
//	(?<![0-9a-zA-Z]) MARKER [\s]{0,8} GROUPED(expected) (?![0-9])
//
// The left guard stops the marker being the tail of a longer token. The whitespace-only gap stops
// a template that wrapped the value in markup being read as adjacency: if the engine put the
// marker and the answer in different text nodes they are not adjacent, and the placement list is
// what resolves that, not a wider gap. The right guard is what keeps 15712730 from matching.
func sstiComputationHit(hay []byte, m triage.Marker, expected string) (sstiHit, bool) {
	for _, form := range sstiMarkerForms(m) {
		needle := []byte(form.bytes)
		from := 0
		for {
			rel := bytes.Index(hay[from:], needle)
			if rel < 0 {
				break
			}
			i := from + rel
			from = i + 1
			if i > 0 && sstiIsTokenByte(hay[i-1]) {
				continue
			}
			j := i + len(needle)
			gap := 0
			for j < len(hay) && gap < sstiMaxGap && sstiIsSpaceByte(hay[j]) {
				j++
				gap++
			}
			n, ok := sstiGroupedNumberAt(hay, j, expected)
			if !ok {
				continue
			}
			if sstiDigitsContinue(hay, j+n) {
				continue
			}
			return sstiHit{
				Offset:     i,
				Length:     j + n - i,
				GapBytes:   gap,
				Matched:    append([]byte(nil), hay[i:j+n]...),
				MarkerForm: form.name,
			}, true
		}
	}
	return sstiHit{}, false
}

// sstiDigitsContinue is the right-hand guard. A following DIGIT means the answer was part of a
// longer number (15712730), and a following decimal point or comma with a digit behind it means
// the answer was the integer part of a decimal (1571273.4).
//
// CATALOGUE 1.1 names 1571273.4 as a must-not-match and then specifies only (?![0-9]), which
// admits it. The decimal case is real: a price, a coordinate or a duration rendered next to a
// reflected marker is not an evaluated product.
func sstiDigitsContinue(hay []byte, i int) bool {
	if i >= len(hay) {
		return false
	}
	if hay[i] >= '0' && hay[i] <= '9' {
		return true
	}
	if (hay[i] == '.' || hay[i] == ',') && i+1 < len(hay) && hay[i+1] >= '0' && hay[i+1] <= '9' {
		return true
	}
	return false
}

type sstiMarkerForm struct {
	name  string
	bytes string
}

// sstiMarkerForms is the part 2.5 transform set this class searches for in-line. RAW and UPPER
// keep the answer adjacent to the marker; the NCR, percent and base64 forms do not, because a
// transform that rewrites the marker rewrites the bytes between it and the answer too. Those are
// handled by refusing to call a slot clean when the runner's own marker scan reports one, which
// is what sstiReEncodedOnly below does.
func sstiMarkerForms(m triage.Marker) []sstiMarkerForm {
	return []sstiMarkerForm{
		{"raw", string(m)},
		{"upper", strings.ToUpper(string(m))},
	}
}

func sstiIsTokenByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func sstiIsSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n' || b == '\v' || b == '\f'
}

// sstiGroupedNumberAt matches want at hay[i:], tolerating locale digit grouping, and returns the
// byte length consumed.
//
// THE RULE IS STRICTER THAN THE CATALOGUE'S REGEX, ON PURPOSE. CATALOGUE 1.1 gives
// `1(?:[,.\x20\xA0 '])?571(?:...)?273` and then says it must not match `1571.273`. It does match
// `1571.273`: the separator is optional at each boundary independently, so one separator at one
// boundary satisfies it. The fix is to require what a real number formatter actually produces:
// either NO separator anywhere, or the SAME separator at EVERY boundary of one grouping scheme.
// `1,571,273` and `15,71,273` pass, `1571.273` and `1.571273` do not, and no FreeMarker locale is
// lost because no locale groups only some of its boundaries.
func sstiGroupedNumberAt(hay []byte, i int, want string) (int, bool) {
	if i < 0 || i > len(hay) {
		return 0, false
	}
	for _, cand := range sstiGroupedForms(want) {
		if bytes.HasPrefix(hay[i:], []byte(cand)) {
			return len(cand), true
		}
	}
	return 0, false
}

// sstiGroupedForms is every rendering of want a number formatter can produce: ungrouped, western
// grouping (threes from the right) and Indic grouping (three then twos), each with each separator.
func sstiGroupedForms(want string) []string {
	out := []string{want}
	n := len(want)
	for _, bounds := range [][]int{sstiWesternBounds(n), sstiIndicBounds(n)} {
		if len(bounds) == 0 {
			continue
		}
		for _, sep := range sstiGroupSeparators {
			var b strings.Builder
			prev := 0
			for _, cut := range bounds {
				b.WriteString(want[prev:cut])
				b.WriteString(sep)
				prev = cut
			}
			b.WriteString(want[prev:])
			out = append(out, b.String())
		}
	}
	return out
}

// sstiWesternBounds is the digit indices where a group separator falls under three-digit grouping.
func sstiWesternBounds(n int) []int {
	var out []int
	for cut := n - 3; cut > 0; cut -= 3 {
		out = append(out, cut)
	}
	sort.Ints(out)
	return out
}

// sstiIndicBounds is the lakh-crore grouping: three digits, then twos. 1571273 renders 15,71,273.
func sstiIndicBounds(n int) []int {
	var out []int
	for cut := n - 3; cut > 0; cut -= 2 {
		out = append(out, cut)
	}
	sort.Ints(out)
	return out
}

// sstiConsumptionHit is RULE CONSUMPTION, rank 7. iso-eval SSTI 2.2.
//
// It is the ONLY oracle a logic-less engine has. Mustache, Handlebars, Pystache, MustacheJS and
// HoganJS compute nothing by design, so an arithmetic-only layer records an entire engine family
// as clean, which is a guaranteed false negative rather than a risk of one.
//
// Three conditions, and each kills a specific forgery:
//
//	M1 immediately followed by M3    a truncation can produce M1, M1{, M1{{ or a cut M1{{M2, and
//	                                 none of those contains M1M3
//	M2 absent in every form          a sanitizer that deletes braces produces M1M2M3, which has
//	                                 M1M2 and M2M3 adjacent and never M1M3, and requiring M2 to be
//	                                 GONE makes the difference explicit rather than incidental
//	both markers checksum            a corrupted token is attributable to nothing
func sstiConsumptionHit(hay []byte, m1, m2, m3 triage.Marker) (sstiHit, bool) {
	if m1.Integrity() != triage.MarkerValid || m3.Integrity() != triage.MarkerValid {
		return sstiHit{}, false
	}
	joined := string(m1) + string(m3)
	idx := bytes.Index(hay, []byte(joined))
	if idx < 0 {
		return sstiHit{}, false
	}
	for _, form := range sstiAllMarkerForms(m2) {
		if len(form) > 0 && bytes.Contains(bytes.ToLower(hay), bytes.ToLower([]byte(form))) {
			return sstiHit{}, false
		}
	}
	return sstiHit{
		Offset:     idx,
		Length:     len(joined),
		Matched:    append([]byte(nil), hay[idx:idx+len(joined)]...),
		MarkerForm: "raw",
	}, true
}

// sstiAllMarkerForms is the full part 2.5 transform set, used for the ABSENCE test only, where
// being generous is the safe direction: every extra form can only suppress a hit.
func sstiAllMarkerForms(m triage.Marker) []string {
	s := string(m)
	if s == "" {
		return nil
	}
	var pct strings.Builder
	for i := 0; i < len(s); i++ {
		pct.WriteString(fmt.Sprintf("%%%02x", s[i]))
	}
	var ncr strings.Builder
	for i := 0; i < len(s); i++ {
		ncr.WriteString("&#" + strconv.Itoa(int(s[i])) + ";")
	}
	return []string{
		s,
		strings.ToUpper(s),
		pct.String(),
		ncr.String(),
		base64.StdEncoding.EncodeToString([]byte(s)),
		base64.RawStdEncoding.EncodeToString([]byte(s)),
		base64.RawURLEncoding.EncodeToString([]byte(s)),
	}
}

// sstiSiblingMarker reconstructs the n-th sibling of a marker: the same anchor and run id, the
// ordinal advanced by n stripe widths so it stays in THIS class's stripe, and the checksum
// recomputed.
//
// IT IS RECONSTRUCTION, NOT MINTING. A classifier cannot mint, because triage.MintMarkerAt takes a
// capability whose type lives in an internal package this one cannot import. It can recompute a
// checksum, because that is a pure function over bytes it already holds, and that is all the
// consumption rule needs in order to recognise the markers the runner minted alongside this one.
func sstiSiblingMarker(m triage.Marker, n uint64) (triage.Marker, bool) {
	if !m.WellFormed() {
		return "", false
	}
	ord, ok := m.Ordinal()
	if !ok {
		return "", false
	}
	next := ord + n*triage.ClassStripeModulus
	if next > triage.MarkerOrdinalMax {
		return "", false
	}
	digits := strconv.FormatUint(next, 36)
	if len(digits) > triage.MarkerOrdinalLen {
		return "", false
	}
	digits = strings.Repeat("0", triage.MarkerOrdinalLen-len(digits)) + digits
	prefix := triage.DefaultMarkerAnchor + m.RunID() + digits
	sum, err := triage.MarkerChecksumFor(prefix)
	if err != nil {
		return "", false
	}
	out := triage.Marker(prefix + sum)
	if !out.WellFormed() || !out.BelongsTo(triage.ClassSSTI) {
		return "", false
	}
	return out, true
}

// sstiSignature is one row of this class's OWN error catalogue. All literals must be present.
type sstiSignature struct {
	ID       string
	Literals []string
	Engine   string
	Language string
}

// sstiErrorCatalogue is RULE ERROR SIGNATURE, rank 4, iso-eval SSTI 2.3. Names, never verdicts.
//
// IT IS THIS CLASS'S CATALOGUE AND NOBODY ELSE'S. Ruling R1 abolished the foreign-error state
// precisely because reading another class's table here made SSTI's verdict depend on ELI's: on
// Spring Boot with Thymeleaf, F1 reaches a SpEL evaluator and returns EL1008E, which is in ELI's
// table and no SSTI table, and both classes then reported "not tested" on an application where a
// template expression demonstrably reached an evaluator. A response this class cannot explain from
// its own catalogue earns its own division triple, not a look at somebody else's list.
var sstiErrorCatalogue = []sstiSignature{
	{"ftl.parse", []string{"freemarker.core.ParseException"}, "FreeMarker", "java"},
	{"ftl.template", []string{"FreeMarker template error"}, "FreeMarker", "java"},
	{"ftl.invalidref", []string{"freemarker.core.InvalidReferenceException"}, "FreeMarker", "java"},
	{"vel.parse", []string{"org.apache.velocity.exception.ParseErrorException"}, "Velocity", "java"},
	{"vel.method", []string{"org.apache.velocity.exception.MethodInvocationException"}, "Velocity", "java"},
	{"thy.proc", []string{"org.thymeleaf.exceptions.TemplateProcessingException"}, "Thymeleaf", "java"},
	{"thy.input", []string{"org.thymeleaf.exceptions.TemplateInputException"}, "Thymeleaf", "java"},
	{"peb.parse", []string{"com.mitchellbosecke.pebble.error.ParserException"}, "Pebble", "java"},
	{"peb.parse2", []string{"io.pebbletemplates.pebble.error.ParserException"}, "Pebble", "java"},
	{"groovy.mme", []string{"groovy.lang.MissingMethodException"}, "Groovy templates", "java"},
	{"groovy.compile", []string{"org.codehaus.groovy.control.MultipleCompilationErrorsException"}, "Groovy templates", "java"},
	{"jinja.syntax", []string{"jinja2.exceptions.TemplateSyntaxError"}, "Jinja2", "python"},
	{"jinja.undef", []string{"jinja2.exceptions.UndefinedError"}, "Jinja2", "python"},
	{"jinja.assert", []string{"jinja2.exceptions.TemplateAssertionError"}, "Jinja2", "python"},
	{"django.syntax", []string{"django.template.exceptions.TemplateSyntaxError"}, "Django", "python"},
	{"django.parse", []string{"Could not parse the remainder:"}, "Django", "python"},
	{"mako.rt", []string{"Mako Runtime Error"}, "Mako", "python"},
	{"mako.exc", []string{"mako.exceptions.SyntaxException"}, "Mako", "python"},
	{"tornado.tmpl", []string{"tornado.template"}, "Tornado", "python"},
	{"cheetah.parse", []string{"Cheetah.Parser.ParseError"}, "Cheetah3", "python"},
	{"chameleon.err", []string{"chameleon.exc.TemplateError"}, "Chameleon", "python"},
	{"twig.syntax", []string{`Twig\Error\SyntaxError`}, "Twig", "php"},
	{"twig.syntax2", []string{"Twig_Error_Syntax"}, "Twig", "php"},
	{"twig.runtime", []string{`Twig\Error\RuntimeError`}, "Twig", "php"},
	{"smarty.compile", []string{"SmartyCompilerException"}, "Smarty", "php"},
	{"smarty.syntax", []string{"Syntax error in template"}, "Smarty", "php"},
	{"latte.compile", []string{`Latte\CompileException`}, "Latte", "php"},
	{"blade.view", []string{`Illuminate\View\ViewException`}, "Blade", "php"},
	{"blade.facade", []string{`Facade\Ignition\Exceptions\ViewException`}, "Blade", "php"},
	{"erb.syntax", []string{"(erb):", "syntax error"}, "ERB", "ruby"},
	{"rails.template", []string{"ActionView::Template::Error"}, "Rails view layer", "ruby"},
	{"slim.parse", []string{"Slim::Parser::SyntaxError"}, "Slim", "ruby"},
	{"haml.syntax", []string{"Haml::SyntaxError"}, "Haml", "ruby"},
	{"liquid.syntax", []string{"Liquid::SyntaxError"}, "Liquid", "ruby"},
	{"liquid.err", []string{"Liquid error:"}, "Liquid", "ruby"},
	{"hbs.parse", []string{"Error: Parse error on line", "Expecting"}, "Handlebars", "javascript"},
	{"nunjucks.render", []string{"Template render error"}, "Nunjucks", "javascript"},
	{"ejs.err", []string{"ejs:", ">> "}, "EJS", "javascript"},
	{"pug.err", []string{"Pug:"}, "Pug", "javascript"},
	{"jade.err", []string{"Jade:"}, "Jade", "javascript"},
	{"dot.err", []string{"doT.js"}, "doT", "javascript"},
	{"go.tmpl.fn", []string{`function "`, `" not defined`}, "Go template", "golang"},
	{"go.tmpl.exec", []string{"template: ", `: executing "`}, "Go template", "golang"},
	{"go.tmpl.parse", []string{`unexpected "`, `" in operand`}, "Go template", "golang"},
	{"razor.compile", []string{"RazorEngine.Templating.TemplateCompilationException"}, "RazorEngine", "dotnet"},
	{"razor.aspnet", []string{"Microsoft.AspNetCore.Mvc.Razor", "CompilationFailedException"}, "ASP.NET Core Razor", "dotnet"},
	{"scriban.err", []string{"Scriban.Syntax.ScriptRuntimeException"}, "Scriban", "dotnet"},
	{"fluid.err", []string{"Fluid.ParseException"}, "Fluid", "dotnet"},
	{"eex.err", []string{"EEx.SyntaxError"}, "EEx", "elixir"},
}

// sstiArithmeticCatalogue is scored off the division triple only. A division-by-zero exception is
// proof that an EXPRESSION EVALUATOR ran, which is a materially stronger statement than "a parser
// read my delimiters", and it is the pair of statements the operator needs kept apart.
var sstiArithmeticCatalogue = []sstiSignature{
	{"arith.python", []string{"ZeroDivisionError"}, "", "python"},
	{"arith.java", []string{"java.lang.ArithmeticException"}, "", "java"},
	{"arith.php8", []string{"DivisionByZeroError"}, "", "php"},
	{"arith.php7", []string{"Division by zero"}, "", "php"},
	{"arith.ruby", []string{"divided by 0"}, "", "ruby"},
	{"arith.freemarker", []string{"Arithmetic operation failed"}, "FreeMarker", "java"},
	{"arith.node", []string{"ReferenceError", " at Object.", ".js:"}, "", "javascript"},
	{"arith.node2", []string{"TypeError", " at Object.", ".js:"}, "", "javascript"},
}

// sstiErrorSignatureIn returns the first catalogue row present in hay and ABSENT from base.
//
// THE BASELINE SUBTRACTION IS NOT OPTIONAL. An application whose every page carries a FreeMarker
// banner makes a naive matcher fire on every probe and score a hundred percent on a corpus where
// nothing at all is vulnerable.
func sstiErrorSignatureIn(cat []sstiSignature, hay, base []byte) (sstiSignature, bool) {
	for _, sig := range cat {
		if !sstiAllPresent(hay, sig.Literals) {
			continue
		}
		if sstiAllPresent(base, sig.Literals) {
			continue
		}
		return sig, true
	}
	return sstiSignature{}, false
}

func sstiAllPresent(hay []byte, lits []string) bool {
	for _, l := range lits {
		if !bytes.Contains(hay, []byte(l)) {
			return false
		}
	}
	return true
}

// sstiVersionPattern is D1's dotted version, anchored to the marker by the caller.
var sstiVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+`)

// sstiGoRootLiterals is D2's answer set: what Go's templates print for the root data value.
var sstiGoRootLiterals = []string{"<no value>", "map[", "&{", "[]"}

// sstiDistinctiveHit is RULE DISTINCTIVE CONTENT, rank 3. The application returned a value only
// this engine produces, adjacent to this probe's own marker and absent from the baseline.
func sstiDistinctiveHit(probe triage.ProbeID, hay, base []byte, m triage.Marker) (sstiHit, string, bool) {
	for _, form := range sstiMarkerForms(m) {
		idx := bytes.Index(hay, []byte(form.bytes))
		if idx < 0 {
			continue
		}
		j := idx + len(form.bytes)
		for j < len(hay) && j-idx-len(form.bytes) < sstiMaxGap && sstiIsSpaceByte(hay[j]) {
			j++
		}
		tail := hay[j:]
		switch probe {
		case sstiD1:
			if loc := sstiVersionPattern.FindIndex(tail); loc != nil {
				v := string(tail[loc[0]:loc[1]])
				if bytes.Contains(base, []byte(v)) {
					continue
				}
				return sstiHit{Offset: idx, Length: j + loc[1] - idx, Matched: append([]byte(nil), tail[loc[0]:loc[1]]...), MarkerForm: form.name}, "Smarty " + v, true
			}
		case sstiD2:
			for _, lit := range sstiGoRootLiterals {
				if bytes.HasPrefix(tail, []byte(lit)) {
					if bytes.Contains(base, []byte(lit)) {
						continue
					}
					return sstiHit{Offset: idx, Length: j + len(lit) - idx, Matched: []byte(lit), MarkerForm: form.name}, "Go template", true
				}
			}
		case sstiD3:
			// The POINT of D3 is that the answer is UNGROUPED: it is proof FreeMarker's ?c
			// computer-format builtin ran, which no other engine has.
			if bytes.HasPrefix(tail, []byte(sstiExpected)) {
				return sstiHit{Offset: idx, Length: j + len(sstiExpected) - idx, Matched: []byte(sstiExpected), MarkerForm: form.name}, "FreeMarker", true
			}
		}
	}
	return sstiHit{}, "", false
}

// ---------------------------------------------------------------------------------------------
// 8. SCORING
// ---------------------------------------------------------------------------------------------

// sstiScorecard is everything this class learned about one slot from its OWN responses.
type sstiScorecard struct {
	planned  int
	answered map[triage.ProbeID]triage.Observation
	markers  map[triage.ProbeID]triage.Marker

	computeFamily triage.ProbeID
	computeHit    sstiHit
	confirmed     bool
	consumeFamily triage.ProbeID
	consumeHit    sstiHit
	stripper      bool

	errorSignature string
	errorEngine    string
	errorLanguage  string
	evaluatorProof string
	// errorProbe and evalProbe name the probe whose response carried the signature, for the same
	// reason distinctProbe exists: a reason string that cannot say WHICH payload produced the
	// error is a reason an operator cannot reproduce.
	errorProbe triage.ProbeID
	evalProbe  triage.ProbeID

	distinctEngine string
	// distinctProbe and distinctHit are WHICH identification probe carried the engine name and
	// WHAT came back, kept so the verdict's reason can say both. distinctEngine alone named the
	// engine and nothing else, and the row shipped with an empty reason.
	distinctProbe triage.ProbeID
	distinctHit   sstiHit

	polyglot             sstiPolyglotOutcome
	perturbedUnexplained bool
	// perturbedProbe is the probe whose response moved, so the R1 sentence can name it instead
	// of describing a category.
	perturbedProbe triage.ProbeID

	reflects       bool
	reflectMeasure bool
	// censusMarkerOnWire is whether the census probe's own minted marker was in the bytes that
	// ACTUALLY WENT OUT, measured from Payload.Wire rather than assumed from MarkerPos.
	//
	// WHY THIS IS A SEPARATE FIELD AND NOT AN ASSUMPTION. Runner-placed markers are OPT-IN
	// (triageRunnerPlacesMarkersClass). THIS CLASS DOES OPT IN, at RunnerPlacesMarkers near the
	// foot of this file, and it declares PREFIX placement so the polyglot's own bytes stay
	// contiguous. This comment said the opposite for a round after the opt-in landed, which is
	// the stale-fact shape this layer keeps finding: the sentence outlived the code it described.
	//
	// The field stays, because the opt-in is a request and not a guarantee. Nothing in this
	// class spells triage.MarkerPlaceholder, so if the placement ever fails or is turned off,
	// "the marker came back ABSENT" and "no marker was ever sent" are two different facts that
	// produce the identical silence, and reporting the first when the second is true puts a
	// statement about the APPLICATION on a row that is a statement about this class's own
	// instrumentation. The verdict is cannot_determine either way; the sentence is not.
	censusMarkerOnWire bool
	decodeDepth        int
	reEncodedOnly      bool

	controlFired  triage.ProbeID
	runnerBug     string
	staleMarker   bool
	truncated     []triage.ProbeID
	notDelivered  []triage.ProbeID
	corruptMarker bool
}

func (s sstiScorecard) silent(id triage.ProbeID) bool {
	_, answered := s.answered[id]
	return answered && s.computeFamily != id
}

// sstiScore walks THIS CLASS'S OWN responses and applies the four rules. It reads ctx.Own, which
// the vault built by filtering on owner, and ctx.Route, which is a Replay and therefore a shared
// control by construction. There is no field on either context through which another class's
// perturbed response can arrive.
func sstiScore(ctx triage.ClassifyCtx) sstiScorecard {
	sc := sstiScorecard{
		answered:    map[triage.ProbeID]triage.Observation{},
		markers:     map[triage.ProbeID]triage.Marker{},
		decodeDepth: -1,
	}
	specs := sstiSpecByID()
	var base []byte
	if ctx.Route.Resolved() {
		base = ctx.Route.Obs().Body
	}

	for i := 0; i < ctx.Own.Len(); i++ {
		p, obs, err := ctx.Own.At(i)
		if err != nil {
			// A read that fails closed is recorded, never skipped into silence.
			sc.runnerBug = "own_response_unreadable: " + err.Error()
			continue
		}
		id := p.ProbeID()
		sc.planned++
		row, known := specs[id]
		if !known {
			sc.runnerBug = "undeclared_probe_in_own_set: " + string(id)
			continue
		}
		if !obs.Delivered() {
			sc.notDelivered = append(sc.notDelivered, id)
			continue
		}
		sc.answered[id] = obs
		m := obs.Marker
		sc.markers[id] = m

		// Attribution first, because a hit scored off a marker this run did not mint is not a hit.
		if m != "" {
			if m.Integrity() == triage.MarkerCorrupted {
				sc.corruptMarker = true
			}
			if !m.BelongsTo(triage.ClassSSTI) {
				// R12: a marker whose ordinal residue is not this class's is a hit for nobody.
				continue
			}
		}

		// The runner must have substituted every token. A token still on the wire means the probe
		// tested something other than what it declared.
		if sstiTokenSurvived(obs, row) {
			sc.runnerBug = "marker_substitution_unsupported: probe " + string(id) +
				" reached the wire with its substitution token intact, so the payload the runner sent is not the payload this class declared"
			continue
		}

		hay := sstiSearchSpace(obs)

		switch {
		case id == sstiS0:
			sc.reflectMeasure = true
			if m != "" && bytes.Contains(obs.Payload.Wire, []byte(m)) {
				sc.censusMarkerOnWire = true
			}
			if _, found := sstiFindMarker(hay, m); found {
				sc.reflects = true
			}
		case id == sstiDEC:
			sc.decodeDepth = sstiDecodeDepthFrom(hay, m)
		case id == sstiS2:
			if out := sstiPolyglotReturn(obs, row); out != sstiPolyglotUnread {
				sc.polyglot = out
			}
		}

		// RULE COMPUTATION.
		//
		// THE CONTROLS GO THROUGH THE SAME CODE PATH AS THE PAYLOADS, deliberately. NC1, NC2 and
		// NC3 carry no expected answer of their own, so they are scored against this class's
		// canonical one, which means the guard below is applied to them too. That is the whole
		// design of NC2: it SENDS 1571273 next to the marker, the adjacency regex does match, and
		// the answer_not_in_wire guard is what has to suppress it. A control scored by a shortcut
		// that skipped the guard would fire on NC2 every time and void every slot in the corpus.
		want := row.variant[sstiVariantExpected]
		if want == "" && row.control {
			want = sstiExpected
		}
		if want != "" && m != "" {
			switch {
			case sstiAnswerInWire(obs, want):
				// The guard of iso-eval 1.2: the answer was in the bytes that went out, so an
				// occurrence in the response proves an echo and not an evaluation.
			case len(base) > 0 && bytes.Contains(base, []byte(want)):
				// The answer is already on the page, so the draw was inadmissible for this slot.
			default:
				if hit, ok := sstiComputationHit(hay, m, want); ok {
					switch {
					case row.control:
						sc.controlFired = id
					case sstiIsConfirmation(id):
						sc.confirmed = true
					case sc.computeFamily == "":
						sc.computeFamily = id
						sc.computeHit = hit
					}
				}
			}
		}

		// RULE CONSUMPTION.
		if strings.Contains(row.logical, sstiTokenM2) && m != "" {
			m2, ok2 := sstiSiblingMarker(m, 1)
			m3, ok3 := sstiSiblingMarker(m, 2)
			if ok2 && ok3 {
				if hit, ok := sstiConsumptionHit(hay, m, m2, m3); ok {
					switch {
					case row.control:
						sc.controlFired = id
					case id == sstiCC1 || id == sstiCC2:
						if !bytes.Contains(hay, []byte(string(m)+"x"+string(m3))) {
							sc.confirmed = true
						}
					case sc.consumeFamily == "":
						sc.consumeFamily = id
						sc.consumeHit = hit
					}
				} else if (id == sstiCC1 || id == sstiCC2) && bytes.Contains(hay, []byte("x"+string(m3))) {
					// The braces went and the literal x stayed: a stripper, not a parser.
					sc.stripper = true
				}
			}
		}

		// RULE ERROR SIGNATURE, this class's catalogue only, baseline-differenced.
		if sig, ok := sstiErrorSignatureIn(sstiErrorCatalogue, hay, base); ok && sc.errorSignature == "" {
			sc.errorSignature = sig.ID
			sc.errorProbe = id
			sc.errorEngine = sig.Engine
			sc.errorLanguage = sig.Language
		}
		// The ZB forms are scored through the SAME arithmetic catalogue as the Z triple, because
		// they are the same oracle reaching further: Z1 to Z3 catch the engines that raise on the
		// division itself, ZB1 to ZB4 catch the engines that tolerate it (JavaScript Infinity,
		// PHP 7 INF) and only raise on the attribute access behind it.
		if id == sstiZ1 || id == sstiZ2 || id == sstiZ3 ||
			id == sstiZB1 || id == sstiZB2 || id == sstiZB3 || id == sstiZB4 {
			if sig, ok := sstiErrorSignatureIn(sstiArithmeticCatalogue, hay, base); ok && sc.evaluatorProof == "" {
				sc.evaluatorProof = sig.ID
				sc.evalProbe = id
				if sc.errorLanguage == "" {
					sc.errorLanguage = sig.Language
				}
				if sig.Engine != "" && sc.errorEngine == "" {
					sc.errorEngine = sig.Engine
				}
			}
		}

		// RULE DISTINCTIVE CONTENT.
		if id == sstiD1 || id == sstiD2 || id == sstiD3 {
			if hit, engine, ok := sstiDistinctiveHit(id, hay, base, m); ok {
				sc.distinctEngine = engine
				sc.distinctProbe = id
				sc.distinctHit = hit
			}
		}

		if m != "" && sstiStaleMarkerIn(hay, m) {
			sc.staleMarker = true
		}
		if lim := ctx.Slot.Constraints.FieldLimit; lim > 0 && sstiWireLen(row) > lim {
			sc.truncated = append(sc.truncated, id)
		}
		if !sc.reflects && sstiReEncodedOnly(obs, m) {
			sc.reEncodedOnly = true
		}
	}

	// Ruling R1's trigger: the response is plainly different from the control, none of this
	// class's own rules fired, and this class will not go looking in another class's table.
	if sc.computeFamily == "" && sc.consumeFamily == "" && sc.errorSignature == "" && len(base) > 0 {
		route := ctx.Route.Obs()
		ids := make([]triage.ProbeID, 0, len(sc.answered))
		for id := range sc.answered {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		for _, id := range ids {
			obs := sc.answered[id]
			if specs[id].control {
				continue
			}
			if obs.BodySHA256 == route.BodySHA256 {
				continue
			}
			if sstiEchoExplains(obs, route) {
				continue
			}
			sc.perturbedUnexplained = true
			sc.perturbedProbe = id
			break
		}
	}
	return sc
}

// sstiEchoExplains answers the question ruling R1 never asked: is the difference between this
// probe's response and the route control ACCOUNTED FOR by this class's own value coming back?
//
// WHY THIS GUARD EXISTS, MEASURED. R1's trigger was "any non-control probe whose body hash
// differs from the route control's", with the sentence "none of this class's own signatures
// explains it". On an endpoint that ECHOES, every probe differs from the control for the one
// reason the class already knows: it printed the payload. /clean/echo is that endpoint, its own
// OracleCases say the verdict there must be CLEAN with its ordinals, and it reported
// unattributed_error on the 80-route exam, as did /xss, /lfi, /redirect, /eli/echo and
// /deser/pickle. A sentence that says nothing explains the change, on a slot where this class's
// own census probe PROVED the value comes back, is a false statement about the target in the one
// field an operator reads.
//
// TWO CONDITIONS, AND THE SECOND IS THE ONE THAT KEEPS THE RUNG ALIVE. The marker must be in the
// response, so the echo is observed rather than assumed; and the probe's status class must match
// the control's, because an endpoint that echoed AND changed its status did something more than
// echo. /sqli/mssql is exactly that shape: the payload comes back entity-escaped inside a 500
// whose control is a 200, and it stays unexplained, which is what R1 is for.
func sstiEchoExplains(obs triage.Observation, route triage.Observation) bool {
	if obs.Marker == "" {
		return false
	}
	if obs.Status/100 != route.Status/100 {
		return false
	}
	_, found := sstiFindMarker(sstiSearchSpace(obs), obs.Marker)
	return found
}

// sstiSearchSpace is the body plus every response header value. A template that renders into a
// Location, a Content-Disposition filename or a custom header is a template sink, and a body-only
// search reports it clean.
func sstiSearchSpace(obs triage.Observation) []byte {
	var b bytes.Buffer
	b.Write(obs.Body)
	for _, h := range obs.RespHeaders {
		b.WriteByte('\n')
		b.WriteString(h[0])
		b.WriteString(": ")
		b.WriteString(h[1])
	}
	return b.Bytes()
}

func sstiFindMarker(hay []byte, m triage.Marker) (int, bool) {
	if m == "" {
		return 0, false
	}
	for _, f := range sstiMarkerForms(m) {
		if i := bytes.Index(hay, []byte(f.bytes)); i >= 0 {
			return i, true
		}
	}
	return 0, false
}

// sstiDecodeDepthFrom reads the decode probe's one request. Ruling R6b's three deterministic
// outcomes, counted rather than guessed: the raw marker prefix is always sent, so finding the
// marker TWICE means the percent-encoded copy came back decoded.
func sstiDecodeDepthFrom(hay []byte, m triage.Marker) int {
	if m == "" {
		return -1
	}
	// THE PERCENT-LITERAL IS READ FIRST, because it is the only UNAMBIGUOUS outcome of the three.
	// The runner places the raw marker for attribution, so an application that reflects the value in
	// two output locations (an echoed field and an error message, say, or the body and a header)
	// returns the raw marker twice with NOTHING decoded. Counting the raw marker first and reading
	// count >= 2 as a decode therefore mistook a second reflection for a decoded copy, set
	// decode_depth to 1, and skipped the decode_depth_0 cannot_determine rung; every brace payload
	// then arrived percent-encoded as literal %7B, every oracle was silent against it, and the slot
	// read CLEAN. If the literal percent form is anywhere in the response, the encoded copy did NOT
	// decode, whatever the raw count is.
	var pct strings.Builder
	for i := 0; i < len(m); i++ {
		pct.WriteString(fmt.Sprintf("%%%02x", m[i]))
	}
	if bytes.Contains(bytes.ToLower(hay), []byte(pct.String())) {
		return 0
	}
	// The literal percent form is gone and the raw marker appears more than once, so the encoded
	// copy came back decoded as a second marker alongside the attribution copy: the slot decodes.
	if bytes.Count(hay, []byte(m)) >= 2 {
		return 1
	}
	return -1
}

// sstiAnswerInWire is the guard of iso-eval 1.2, read off the recorded wire bytes rather than
// recomputed. If the wire was never captured the guard cannot be asserted, and CATALOGUE 4.2 then
// caps the hit at suspicious, which sstiGradeFor does.
func sstiAnswerInWire(obs triage.Observation, want string) bool {
	w := obs.Payload
	return bytes.Contains(w.Wire, []byte(want)) ||
		bytes.Contains(w.Logical, []byte(want)) ||
		bytes.Contains(w.Container, []byte(want))
}

// sstiTokenSurvived is the fail-closed check on the substitution contract.
func sstiTokenSurvived(obs triage.Observation, r sstiRow) bool {
	for _, tok := range []string{sstiTokenM2, sstiTokenM3, sstiTokenPctMarker} {
		if !strings.Contains(r.logical, tok) {
			continue
		}
		if bytes.Contains(obs.Payload.Wire, []byte(tok)) || bytes.Contains(obs.Payload.Container, []byte(tok)) {
			return true
		}
	}
	return false
}

// sstiPolyglotOutcome is what happened to SSTI-S2's own bytes between the request and the
// response, CLASSIFIED rather than collapsed into one boolean.
//
// WHY IT IS FOUR VALUES AND NOT A BOOLEAN, MEASURED. The boolean this replaces was "the returned
// bytes after the marker are not byte-equal to the bytes sent", and it fed a SUSPICIOUS rung
// whose sentence read "something parsed the delimiters". On the 80-route canary exam that rung
// fired on 30 routes and was clean on none of them, 29 of the 30 through this comparison, and
// every one of the 29 was read back and named:
//
//	21 routes    html.EscapeString on the way OUT: `"` came back `&#34;` and `>` came back `&gt;`.
//	             /clean/echoparser, /csti/plain, /csti/aot, /csti/vue-runtime, /xss/encoded,
//	             /xss/entity, /eli/hardened and fourteen more.
//	 2 routes    a JSON string: /clean/echomongo through strconv.Quote, /csti/inscript likewise.
//	 1 route     /csti/pct-literal, which never percent-decodes, so the braces came back as %7B.
//	 3 routes    the field CUT the value: /cmdi, /crlf/setcookie, /sqli/mssql.
//	 2 routes    a sanitizer DELETED the braces: /csti/escaped strips [{}] with a regexp,
//	             /csti/angular-attr the same for text.
//
// Not one of the 29 was a template engine, and the arm has never been observed firing on one:
// its own declared positive route, /ssti/catchall, does not exist. A payload coming back
// entity-encoded is what an HTML-escaping endpoint DOES; it is the signature of a defence
// working. So the byte comparison stays, because it is cheap and it is this class's only look at
// whether its own delimiters survived, and the CONCLUSION drawn from it changes: it can no longer
// produce a pointer, and it can still refuse a clean.
//
// WHAT WAS NOT TRADED AWAY. The shape S2 was bought for is the application that swallows every
// template exception and renders a generic page. That shape now has a better instrument in this
// same class, with a real positive control the polyglot never had: the blind boolean differential
// separates a VALID expression from an INVALID one of the same length, and it is observed firing
// on /ssti/blind. A "rewritten" polyglot and a brace-deleting sanitizer are the same bytes, which
// is why the rung below them is cannot_determine and names both readings instead of picking one.
type sstiPolyglotOutcome string

const (
	// sstiPolyglotUnread: S2 was not answered, carried no marker, or its marker is not in the
	// response. Nothing was measured and no rung reads it.
	sstiPolyglotUnread sstiPolyglotOutcome = ""
	// sstiPolyglotIntact: the bytes after the marker are the bytes that were sent.
	sstiPolyglotIntact sstiPolyglotOutcome = "intact"
	// sstiPolyglotEncoded: not byte-equal, but equal once one general-purpose encoding is undone.
	// Every delimiter is still accounted for, so the payload reached the application whole.
	sstiPolyglotEncoded sstiPolyglotOutcome = "encoded"
	// sstiPolyglotDiverged: neither. The returned copy stops short of, or differs from, the sent
	// copy under every decoding this class undoes.
	sstiPolyglotDiverged sstiPolyglotOutcome = "diverged"
)

// sstiPolyglotReturn compares the bytes this class SENT after the marker with the bytes that came
// back after it, and classifies the difference. It is a comparison of two of this class's own
// artefacts and it touches nothing else.
func sstiPolyglotReturn(obs triage.Observation, r sstiRow) sstiPolyglotOutcome {
	m := obs.Marker
	if m == "" {
		return sstiPolyglotUnread
	}
	hay := sstiSearchSpace(obs)
	i := bytes.Index(hay, []byte(m))
	if i < 0 {
		return sstiPolyglotUnread
	}
	sent := r.logical
	if sent == "" {
		return sstiPolyglotUnread
	}
	tail := hay[i+len(m):]
	if len(tail) >= len(sent) && string(tail[:len(sent)]) == sent {
		return sstiPolyglotIntact
	}
	// The window is generous because every encoding below makes the returned copy LONGER than the
	// sent copy: %7B is three bytes for one and &#34; is six.
	window := tail
	if limit := 8*len(sent) + 64; len(window) > limit {
		window = window[:limit]
	}
	for _, form := range sstiGenericDecodings(string(window)) {
		if strings.HasPrefix(form, sent) {
			return sstiPolyglotEncoded
		}
	}
	return sstiPolyglotDiverged
}

// sstiGenericDecodings undoes, one layer at a time, the three transformations that put a payload
// back on a page LOOKING different while every byte of it is still accounted for.
//
// THE LIST IS DELIBERATELY SHORT AND NAMED, and it is not net/html's entity table. What is being
// undone here is what an ESCAPER does, and the three that matter are the three measured on the
// canary exam: HTML entity escaping (Go's html.EscapeString, PHP's htmlspecialchars, every
// templating auto-escape), JSON string escaping (a value quoted into a JSON document), and the
// endpoint that never percent-decoded in the first place. A general entity table would also
// decode things no escaper produces, which is how a normaliser starts undoing the application's
// real behaviour instead of its encoding.
func sstiGenericDecodings(s string) []string {
	entity := strings.NewReplacer(
		"&amp;", "&", "&#38;", "&", "&#x26;", "&",
		"&lt;", "<", "&#60;", "<", "&#x3c;", "<", "&#x3C;", "<",
		"&gt;", ">", "&#62;", ">", "&#x3e;", ">", "&#x3E;", ">",
		"&quot;", `"`, "&#34;", `"`, "&#x22;", `"`,
		"&apos;", "'", "&#39;", "'", "&#x27;", "'",
		"&#123;", "{", "&#x7b;", "{", "&#x7B;", "{",
		"&#125;", "}", "&#x7d;", "}", "&#x7D;", "}",
		"&#36;", "$", "&#x24;", "$",
	).Replace
	jsonStr := func(in string) string {
		// A JSON string escapes the quote, the backslash and (optionally) the solidus, and
		// nothing else this payload set carries.
		return strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\/`, "/").Replace(in)
	}
	pct := func(in string) string {
		out, err := url.QueryUnescape(in)
		if err != nil {
			return in
		}
		return out
	}
	// Both orders of the two that compose in the wild: a value percent-kept and then escaped, and
	// a value escaped and then percent-kept.
	return []string{
		entity(s), jsonStr(s), pct(s),
		entity(pct(s)), pct(entity(s)), entity(jsonStr(s)), jsonStr(entity(s)),
	}
}

// sstiIsConfirmation reports whether a probe is one of the fresh-marker, fresh-operand reproductions.
func sstiIsConfirmation(id triage.ProbeID) bool {
	return strings.HasPrefix(string(id), "SSTI-CF") || id == sstiF10w
}

// sstiStaleMarkerIn reports whether the response carries a marker from a DIFFERENT run. A body
// carrying another run's token is a cached or replayed body, and any verdict drawn from it is
// cannot_determine (stale_marker) rather than a hit.
func sstiStaleMarkerIn(hay []byte, mine triage.Marker) bool {
	for _, raw := range sstiMarkerShape.FindAll(hay, 8) {
		found := triage.Marker(bytes.ToLower(raw))
		if !found.WellFormed() || found.Integrity() != triage.MarkerValid {
			continue
		}
		if !found.BelongsTo(triage.ClassSSTI) {
			continue
		}
		if found.RunID() != mine.RunID() {
			return true
		}
	}
	return false
}

var sstiMarkerShape = regexp.MustCompile(triage.MarkerShapePattern)

// sstiReEncodedOnly reports that the runner's own marker scan found this probe's marker in a
// TRANSFORMED form while this class's in-line search found nothing.
//
// It exists so a re-encoding application cannot produce a clean. If the marker came back as an NCR
// or base64 then the answer, if there was one, came back transformed too, in a shape whose byte
// offsets no longer put it adjacent to anything. That is an unmeasured slot, not a silent one.
func sstiReEncodedOnly(obs triage.Observation, m triage.Marker) bool {
	if m == "" {
		return false
	}
	for _, h := range obs.Proj.MarkerHits {
		if h.Marker != m {
			continue
		}
		if h.Form != "" && h.Form != "raw" && h.Form != "upper" {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 8b. THE BLIND ARM: THE ONE ORACLE HERE THAT NEEDS NOTHING TO COME BACK
// ---------------------------------------------------------------------------------------------
//
// WHY THIS EXISTS, AS A MEASUREMENT AND NOT AS AN OPINION. On a live JSON REST API, 30 query
// vectors, four slots: SSTI, ELI, XSS-R, CMDI, TRAVERSAL, RFI, NOSQL and DESER all returned
// cannot_determine, and CRLF and REDIRECT both ANSWERED on the same slots. The two that answered
// read the response ENVELOPE. The eight that did not were each waiting for their own value to come
// back, and on an API that echoes nothing it never does. A class gated on reflection is
// structurally silent there no matter how good its payloads are, and the fix is not a louder
// payload, it is a different question.
//
// THE DIFFERENT QUESTION. Send one expression that parses and one that does not, in the same
// delimiters, of the same length. A route with a template engine behind the slot answers them
// differently, because one renders and one raises. A route with no engine answers them
// identically, because to it they are two strings. Neither answer needs the value, the marker or a
// computed product to appear anywhere.
//
// WHAT IT MAY AND MAY NOT CONCLUDE, AND THIS IS THE WHOLE DISCIPLINE OF IT.
//
//	it may say SUSPICIOUS at grade low          something parsed this slot
//	it may NEVER say clean                      a route that answers two strings the same way has
//	                                            told you nothing about a third
//	it may NEVER say finding                    tier 6 is a differential, and a differential is
//	                                            not proof that an expression was EVALUATED
//
// A silent blind arm therefore leaves the verdict exactly where it was, at cannot_determine, and
// only changes the SENTENCE: from "the oracle was unavailable" to "the oracle ran and was quiet".
// Those are different facts and an operator spends differently on them.

// sstiBlindOutcome is what the blind arm concluded, as a value rather than as a bool, because
// "did not fire" and "could not run" are the two readings this layer keeps collapsing into one.
type sstiBlindOutcome int

const (
	sstiBlindNotRun sstiBlindOutcome = iota // a precondition failed; Why says which
	sstiBlindSilent                         // every precondition held and neither family moved
	sstiBlindDifferentiated
)

type sstiBlindResult struct {
	Outcome sstiBlindOutcome
	Family  string // "dollar_brace" or "brace_brace", set only when it fired
	Why     string // always set: the precondition that failed, or what was measured
	Detail  string
}

// sstiBlindPair is one (valid, invalid) pair.
type sstiBlindPair struct {
	OK, Err triage.ProbeID
}

// sstiBlindFamilies is the arm's shape: two families, two pairs each. Both pairs of a family must
// move, and move the SAME WAY, before the family counts. One pair alone fires on any route that
// answers two different strings differently, which is most routes.
func sstiBlindFamilies() map[string][]sstiBlindPair {
	return map[string][]sstiBlindPair{
		"dollar_brace": {{OK: sstiBOK1, Err: sstiBER1}, {OK: sstiBOK2, Err: sstiBER2}},
		"brace_brace":  {{OK: sstiBOK3, Err: sstiBER3}, {OK: sstiBOK4, Err: sstiBER4}},
	}
}

// sstiBlindArm is the whole rule, as a pure function of this class's own observations plus the
// stability facts, so every branch below is reachable from a test. A classifier cannot build a
// populated ClassifyCtx, which is why sstiEnv exists, and this follows the same rule.
func sstiBlindArm(answered map[triage.ProbeID]triage.Observation, env sstiEnv) sstiBlindResult {
	// PRECONDITION 1: the noise model. This is a rank 6 differential and it rests entirely on the
	// endpoint not differing from itself. The harvest's own words: the noise model has to exist or
	// the verdict is cannot_determine, never clean.
	if !env.stable {
		why := env.gateReason
		if why == "" {
			why = "no_model"
		}
		return sstiBlindResult{Why: "blind_arm_not_run (noise_model_absent: " + why + "): a valid-versus-invalid " +
			"differential on an endpoint that differs from itself measures the endpoint"}
	}
	if env.degraded {
		return sstiBlindResult{Why: "blind_arm_not_run (comparison_degraded): the body was oversized, truncated or " +
			"untokenisable, so a length differential over it is a differential over a truncation point"}
	}

	// PRECONDITION 2: the length control. BN1 and BN2 are inert plain text six bytes apart, which
	// is the largest length gap in this arm. If THEY move apart, this endpoint's response length
	// tracks its input length and every pair below would fire for that reason alone.
	n1, ok1 := sstiBlindLen(answered[sstiBN1])
	n2, ok2 := sstiBlindLen(answered[sstiBN2])
	if !ok1 || !ok2 {
		// THE SENTENCE NAMES WHICH ONE AND WHY, because "produced no comparable response" was one
		// phrase covering four causes that call for four different actions. MEASURED on the
		// operator's live JSON API: every slot said length_control_not_measured, and the cause on
		// every one of them was that the two probes WERE NEVER SENT, the per-slot cap having been
		// spent in rounds 0 and 1. An operator reading "no comparable response" goes looking at
		// the endpoint; the answer was a number in the settings document.
		why := "blind_arm_not_run (length_control_not_measured): SSTI-BN1 and SSTI-BN2 are the inert " +
			"pair that proves this arm is not simply measuring how long the value is, and " +
			sstiBlindWhyNoLen(answered, sstiBN1, ok1) + "; " + sstiBlindWhyNoLen(answered, sstiBN2, ok2)
		if sstiBlindAbsentFromSet(answered, sstiBN1, ok1) || sstiBlindAbsentFromSet(answered, sstiBN2, ok2) {
			why += ". " + sstiBlindAbsenceCause(env.armGate)
		}
		return sstiBlindResult{Why: why + ". The arm is disabled rather than run without it"}
	}
	s1, s2 := answered[sstiBN1].Status, answered[sstiBN2].Status
	if n1 != n2 || sstiStatusClass(s1) != sstiStatusClass(s2) {
		return sstiBlindResult{Why: "blind_arm_not_run (length_sensitive_endpoint): the two inert controls differ " +
			"by six bytes of input and came back " + strconv.Itoa(n1) + " and " + strconv.Itoa(n2) + " normalised " +
			"bytes at " + strconv.Itoa(s1) + " and " + strconv.Itoa(s2) + ", so this response tracks its input " +
			"length rather than its meaning and a pair differential here would be measuring the same thing"}
	}

	// PRECONDITION 3, WHICH IS CONTROL A. The two syntax-error payloads of a family are both
	// garbage, so an engine raises on both and answers them the same way. A route that answers ANY
	// unusual input differently answers these two differently, and that route cannot carry an arm
	// whose entire signal is "this input was unusual in a particular way".
	for _, fam := range []string{"brace_brace", "dollar_brace"} {
		pairs := sstiBlindFamilies()[fam]
		e1, okA := answered[pairs[0].Err]
		e2, okB := answered[pairs[1].Err]
		if !okA || !okB {
			continue
		}
		if sstiStatusClass(e1.Status) != sstiStatusClass(e2.Status) {
			return sstiBlindResult{Why: "blind_arm_not_run (junk_sensitive in " + fam + "): the two SYNTAX-ERROR " +
				"payloads of this family, which no engine parses and which differ only in their garbage, came " +
				"back " + strconv.Itoa(e1.Status) + " and " + strconv.Itoa(e2.Status) + ". This endpoint answers " +
				"unusual inputs differently and a valid-versus-invalid differential on it would be measuring that"}
		}
	}

	// THE RULE. Both pairs of one family must move, and move the same way.
	for _, fam := range []string{"brace_brace", "dollar_brace"} {
		pairs := sstiBlindFamilies()[fam]
		signs := make([]int, 0, 2)
		details := make([]string, 0, 2)
		incomplete := false
		missing := ""
		for _, pr := range pairs {
			sign, detail, ok := sstiBlindPairMoved(answered[pr.OK], answered[pr.Err], pr)
			if !ok {
				incomplete = true
				_, okOK := sstiBlindLen(answered[pr.OK])
				_, okErr := sstiBlindLen(answered[pr.Err])
				missing = sstiBlindWhyNoLen(answered, pr.OK, okOK) + "; " +
					sstiBlindWhyNoLen(answered, pr.Err, okErr)
				if sstiBlindAbsentFromSet(answered, pr.OK, okOK) || sstiBlindAbsentFromSet(answered, pr.Err, okErr) {
					missing += ". " + sstiBlindAbsenceCause(env.armGate)
				}
				break
			}
			if sign == 0 {
				signs = nil
				break
			}
			signs = append(signs, sign)
			details = append(details, detail)
		}
		if incomplete {
			return sstiBlindResult{Why: "blind_arm_not_run (family_incomplete: " + fam + "): a pair with one " +
				"member missing is not a pair, and " + missing}
		}
		if len(signs) == 2 && signs[0] == signs[1] {
			return sstiBlindResult{
				Outcome: sstiBlindDifferentiated, Family: fam,
				Why: "boolean_differential (" + fam + "): both of this family's valid-versus-invalid pairs moved " +
					"the response, in the same direction, on an endpoint whose stability gate passed and whose " +
					"length control stayed put. The members of each pair are the SAME LENGTH, so this is not " +
					"an echo. Something parsed this slot. It is SUSPICIOUS and not a finding: a differential " +
					"proves a parser and not an evaluation, and this class's computation oracle could not run " +
					"here to tell the two apart",
				Detail: strings.Join(details, " and "),
			}
		}
	}
	return sstiBlindResult{Outcome: sstiBlindSilent,
		Why: "blind_arm_ran_and_was_silent: both delimiter families went out as valid-versus-invalid pairs on a " +
			"stable endpoint with the length control holding, and neither family separated. That is evidence " +
			"against a template engine parsing this slot in the two delimiter shapes this arm covers, and it is " +
			"evidence about NOTHING ELSE: a tier 6 differential that stayed quiet is not a clean"}
}

// sstiBlindPairMoved compares one pair. It returns +1 when the valid member came back LARGER, -1
// when it came back smaller, 0 when nothing separated them, and measured=false when the comparison
// could not be made at all.
//
// A STATUS-CLASS DIFFERENCE OUTRANKS LENGTH, because a 500 against a 200 is a different response
// however long the bodies are, and a route that renders the valid member and raises on the invalid
// one is exactly the shape this arm is looking for.
func sstiBlindPairMoved(okObs, errObs triage.Observation, pr sstiBlindPair) (sign int, detail string, measured bool) {
	nOK, hasOK := sstiBlindLen(okObs)
	nErr, hasErr := sstiBlindLen(errObs)
	if !hasOK || !hasErr {
		return 0, "", false
	}
	cOK, cErr := sstiStatusClass(okObs.Status), sstiStatusClass(errObs.Status)
	if cOK != cErr {
		s := 1
		if cOK > cErr {
			// The sign is about the VALID member. A valid member in the higher status class is
			// the wrong way round for a rendering engine, and the same-sign rule is what makes
			// that matter: a family where one pair leans each way does not fire.
			s = -1
		}
		return s, string(pr.OK) + " answered " + strconv.Itoa(okObs.Status) + " and " + string(pr.Err) +
			" answered " + strconv.Itoa(errObs.Status), true
	}
	if nOK == nErr {
		return 0, "", true
	}
	s := 1
	if nOK < nErr {
		s = -1
	}
	return s, string(pr.OK) + " returned " + strconv.Itoa(nOK) + " normalised bytes and " + string(pr.Err) +
		" returned " + strconv.Itoa(nErr), true
}

// sstiBlindLen is the length the arm compares, and it is the NORMALISED body or nothing.
//
// Proj.NormBody has the endpoint's measured volatile regions and every marker form already cut out
// of it, which is exactly the noise band this arm would otherwise have to invent. Falling back to
// the raw body would put a request id, a timestamp and a CSRF token back into the measurement, and
// a two-byte differential over those is noise wearing a verdict. So a probe whose normalised body
// was never built is NOT COMPARABLE, and the arm says family_incomplete rather than guessing.
func sstiBlindLen(o triage.Observation) (int, bool) {
	if o.ObsID == "" || !o.Delivered() || o.BodyTruncated {
		return 0, false
	}
	if o.Proj.NormBody == nil {
		return 0, false
	}
	return len(o.Proj.NormBody), true
}

// sstiBlindAbsentFromSet reports whether a probe is missing from this class's own answered set,
// which is the one cause of an unmeasurable control that is about the LAYER rather than about the
// response. It is split out so the caller can append the cause sentence ONCE for a pair instead of
// repeating the same paragraph behind each probe.
func sstiBlindAbsentFromSet(answered map[triage.ProbeID]triage.Observation, id triage.ProbeID, ok bool) bool {
	if ok {
		return false
	}
	o, present := answered[id]
	return !present || o.ObsID == ""
}

// sstiBlindGateSentence is what the blind arm's own gate, sstiBlindArmEarned, decided on this
// slot, written as a sentence for the arm's reason strings.
//
// IT EXISTS BECAUSE THE ARM'S "NEVER SENT" ROW WAS NAMING THE WRONG COMPONENT. On every one of
// the 28 cleans of the run that prompted this, the annotation read "the round that requests it
// did not run, or the per-slot probe cap bit before it left": two claims about the runner, one
// menu, and neither of them true. On a slot that reflects, this class never asks for those ten
// probes, and sstiPlanBatteries and sstiPlanEscalation both say so in code. The decision is made
// here, in this package, and it belongs in the sentence.
//
// THE BRANCHES MIRROR sstiBlindArmEarned's THREE HALVES, BUT NOT IN THE ORDER THE GATE READS
// THEM, AND THE DIFFERENCE IS TIMING RATHER THAN TASTE.
//
// THE DEFECT THIS ORDER FIXES, reproduced on a real row. computeFamily was tested FIRST, so on a
// slot where the gate declined because the census marker came back, the sentence read
// "SSTI-F2 computed, so the strongest oracle in this class had already answered by the round in
// which the arm would have been planned", and sstiBlindAbsenceCause escalated that to
// "THIS CLASS NEVER ASKED FOR THE PROBE(S) NAMED (SSTI-F2 computed...)". Both halves are wrong
// about time. The gate is asked in round 1 and again in round 2. At the round 1 gate the
// scorecard holds ROUND 0's answers and nothing else, and NO ROUND 0 PROBE CAN SET
// computeFamily: sstiPlanCensus sends S0, DEC and the four error polyglots, and not one of those
// rows carries an expected computation or the control flag, which are the only two ways the
// RULE COMPUTATION block reaches sc.computeFamily. So a computed family is ALWAYS a fact from
// round 1 or later, and it can never be the reason the round 1 gate decided anything.
//
// THE TWO FACTS THAT ARE TIMING-SAFE ARE THE CENSUS ONES, so they go first. reflectMeasure and
// reflects are both set by S0, a round 0 probe, so whatever they read at classify time they read
// the same way at the round 1 gate and at the round 2 gate. A sentence built on them describes
// the decision that was actually taken.
//
// AND THE COMPUTED-FAMILY CASE IS NOT A "NOT REQUESTED" AT ALL. Reaching it means reflectMeasure
// was true and reflects was false, which IS the gate met, so this class asked for all ten probes
// in round 1. What the family bought is the round 2 RETRY, which sstiPlanEscalation declines.
// Saying "never asked" there points the operator away from the per-slot cap, which is the only
// cause anyone has ever measured for those ten probes going missing.
func sstiBlindGateSentence(sc sstiScorecard) string {
	switch {
	case !sc.reflectMeasure:
		return "not requested: the arm's gate needs this class's census probe " + string(sstiS0) +
			" to have answered before the slot can be called non-reflecting, and it has no response here"
	case sc.reflects:
		return "not requested: the census marker CAME BACK, so the rank 1 computation oracle was available " +
			"on this slot and this class does not spend ten requests on a tier 6 differential beside it"
	case sc.computeFamily != "":
		return "requested: the census answered and its marker did not come back, so the gate WAS met in " +
			"round 1 and this class asked for these probes then. " + string(sc.computeFamily) +
			" computed afterwards, on a round 1 or later probe, and that closed the round 2 retry only: a " +
			"family cannot be the reason the ROUND 1 gate decided, because the only answers that gate had " +
			"in hand were round 0's, and no round 0 probe can set a family"
	default:
		return "requested: the gate was met here (the census answered, its marker did not come back, and no " +
			"family computed), so this class DID ask for these probes, in round 1 and again in round 2"
	}
}

// sstiBlindAbsenceCause turns that gate decision into the half-sentence the "never sent" row
// carries, and REFUSES TO ASSERT when it was not told.
func sstiBlindAbsenceCause(gate string) string {
	switch {
	case gate == "":
		return "This class cannot see from here which of four causes applies: it never asked for the probe, " +
			"the run's tier is below this probe's, the per-slot probe cap bit before the request left, or the " +
			"run ended before the round that carries it"
	case strings.HasPrefix(gate, "not requested: "):
		return "THIS CLASS NEVER ASKED FOR THE PROBE(S) NAMED (" + strings.TrimPrefix(gate, "not requested: ") +
			"), so that absence is this class's own plan and is not evidence of a budget, a tier or anything " +
			"about the endpoint"
	default:
		return "THIS CLASS DID ASK FOR THE PROBE(S) NAMED (" + strings.TrimPrefix(gate, "requested: ") +
			") and no observation came back, and it cannot see from here which of three applies: the run's " +
			"tier is below this probe's, the per-slot probe cap bit before the request left, or the run " +
			"ended before the round that carries it"
	}
}

// sstiBlindWhyNoLen says, for one of the two inert controls, why the arm could not read a length
// off it. The four causes are four different facts:
//
//	not sent            the probe is absent from this class's own answered set. WHY it is absent
//	                    is the gate's business and not a guess, and the CALLER appends that once
//	                    through sstiBlindAbsenceCause rather than this function repeating it per
//	                    probe: sstiBlindGateSentence says whether this class asked for the arm at
//	                    all, in place of the menu of runner causes the row used to offer.
//	transport refused   it was sent and the socket said no, so the endpoint never saw it.
//	body truncated      it came back past the capture limit, so its length is the limit's.
//	no normalised body  the projection was never built, so the only length available is the raw
//	                    one, which carries the request id and the timestamp this arm must not read.
func sstiBlindWhyNoLen(answered map[triage.ProbeID]triage.Observation, id triage.ProbeID, ok bool) string {
	if ok {
		return string(id) + " was measured"
	}
	o, present := answered[id]
	switch {
	case !present || o.ObsID == "":
		return string(id) + " was NEVER SENT (absent from this class own answered set)"
	case !o.Delivered():
		return string(id) + " was sent and the transport refused it (" + string(o.TransportErr) + "), so the " +
			"application never saw it"
	case o.BodyTruncated:
		return string(id) + " came back TRUNCATED, so its length is the capture limit and not the response"
	default:
		return string(id) + " came back with no normalised body built, and the raw length carries the " +
			"volatile regions this arm must not measure"
	}
}

func sstiStatusClass(status int) int { return status / 100 }

// sstiBlindFired builds the one verdict the non-reflective arm is allowed to produce. It is a
// function because the arm is scored at TWO rungs of the ladder now: once above the uniform-block
// refusal, where a separation outranks the block, and once in its own place below every stronger
// oracle. Two copies of the grade cap would be two policies.
//
// GRADE LOW AND IT MAY NEVER BE ANYTHING ELSE. The harvest that produced these payloads says so
// in the same words: high confidence the pair behaves as described in Jinja2, low to medium that
// the differential is readable on a real route, because the verdict rests entirely on the noise
// model. There is no confirmation probe that could raise it: a second differential is a second
// coin toss, not a reproduction.
func sstiBlindFired(slot triage.SlotKey, sc sstiScorecard, blind sstiBlindResult, ords []uint64,
	untested []triage.ProbeSkip, ann map[string]any, extra string) []triage.ClassVerdict {

	ann["blind_arm_family"] = blind.Family
	ann["blind_arm_detail"] = blind.Detail
	ann["evaluation_unproven"] = true
	reason := blind.Why + ". " + blind.Detail
	if extra != "" {
		reason += ". " + extra
	}
	v := sstiOne(slot, triage.StateSuspicious, reason,
		ords, untested, ann, triage.TriageEvidence{Phrase: "boolean_differential " + blind.Family})
	v[0].Grade = triage.GradeLow
	v[0].Oracle = "boolean_differential"
	v[0].Label = sstiLabel(sc)
	return v
}

// sstiBlindSentence is what the blind arm contributes to a row it did not win. It is a sentence
// rather than a flag because the row is read by a person deciding whether to spend a tool run,
// and "the second oracle ran and was quiet" and "the second oracle could not run" send that
// person to two different places.
func sstiBlindSentence(b sstiBlindResult) string {
	switch b.Outcome {
	case sstiBlindSilent:
		return "The second, non-reflective arm DID run here: " + b.Why
	case sstiBlindDifferentiated:
		// Unreachable from the ladder, which takes the suspicious rung on this outcome. Spelled
		// out anyway, because a switch whose impossible case returns the empty string is how a
		// later reordering turns a fired oracle into a blank.
		return "The second, non-reflective arm FIRED and this row should not have been reached: " + b.Why
	default:
		return "The second, non-reflective arm did not run: " + b.Why
	}
}

// ---------------------------------------------------------------------------------------------
// 9. THE VERDICT
// ---------------------------------------------------------------------------------------------

// Classify composes ONE verdict for the slot, with each oracle's own outcome recorded in the
// annotations so nothing is hidden inside the composition.
//
// THE COMPOSITION RULE, iso-eval 1.5: the verdict is the strongest oracle result, EXCEPT that it
// can never be clean while any of this class's own oracles is an unknown. That single exception is
// the difference between a report that says "SSTI: clean" on a blind template sink and one that
// says "the computation oracle could not run here, and here is why".
func (sstiClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	slot := ctx.Slot.Key
	if r, refuse := sstiWhyNotSend(ctx.PlanCtx); refuse {
		return []triage.ClassVerdict{{
			Class: triage.ClassSSTI, SlotKey: slot, State: r.state, Reason: r.reason,
			Annotations: sstiBaseAnnotations(ctx, sstiScorecard{decodeDepth: -1}),
		}}
	}

	sc := sstiScore(ctx)
	if sc.planned == 0 {
		return []triage.ClassVerdict{{
			Class: triage.ClassSSTI, SlotKey: slot, State: triage.StateNotPlanned,
			Reason:      "no_probe_derived: this class reaches this slot and sent nothing, which is either an exhausted budget before round 0 or a ladder bug. It is reported as an untested slot, never as a clean one",
			Annotations: sstiBaseAnnotations(ctx, sc),
		}}
	}

	untested, gaps := sstiUntested(ctx, sc)
	return sstiCompose(slot, sc, sstiOrdinals(ctx), untested, gaps, sstiBaseAnnotations(ctx, sc), sstiEnvFrom(ctx))
}

// sstiEnv is the handful of facts the verdict ladder needs from the context that are not already
// in the scorecard. It exists so the ladder below is a PURE FUNCTION of a scorecard and these
// flags, and can therefore be tested.
//
// THAT IS NOT A TIDINESS REFACTOR. A classifier cannot build a populated ClassifyCtx in a test: a
// Perturbed is minted by the vault under a capability whose type lives in an internal package this
// one cannot import, which is exactly the property that stops a class reading another class's
// responses. Without this split the only reachable branches in a test would be the four refusals,
// and the whole "an unknown never becomes a clean" ladder would ship unexercised.
type sstiEnv struct {
	blocked     bool
	drifted     bool
	canaryValue bool
	unstable    bool
	gateReason  string
	// stable and degraded are the blind arm's two preconditions, and they are SEPARATE FIELDS
	// from unstable rather than its negation. unstable is deliberately lenient: it is false when
	// Samples is 0, so a slot with no baseline model at all can still reach the existing clean.
	// The blind arm cannot afford that leniency, because a rank 6 differential with no model
	// behind it is a coin toss with a verdict attached, so it asks for Stable to be POSITIVELY
	// true. Writing this as !env.unstable would have quietly enabled the arm on every endpoint
	// nobody measured.
	stable          bool
	degraded        bool
	percentRelevant bool
	// armGate is what the blind arm's OWN gate decided on this slot, as a sentence, so the arm's
	// "never sent" row can say whether this class asked for those ten probes at all.
	//
	// THE EMPTY STRING IS "NOT STATED" AND NOT "EARNED". sstiEnvFrom cannot fill it in, because
	// the gate is a function of the scorecard and not of the context, so sstiCompose sets it. A
	// caller that does not gets the honest menu of causes rather than a claim: the one thing this
	// field must never do is let a struct default become an assertion about why a probe is
	// missing. sstiBlindGateSentence is the only thing that writes it.
	armGate string
}

func sstiEnvFrom(ctx triage.ClassifyCtx) sstiEnv {
	return sstiEnv{
		blocked:         sstiUniformBlock(ctx.PlanCtx),
		drifted:         sstiDrifted(ctx),
		canaryValue:     ctx.Slot.ValueOrigin == triage.ValueCanary || ctx.Slot.ValueOrigin == triage.ValueSynthesized,
		unstable:        ctx.Baseline.Degraded || (ctx.Baseline.Samples > 0 && !ctx.Baseline.Stable),
		gateReason:      ctx.Baseline.GateReason,
		stable:          ctx.Baseline.Samples > 0 && ctx.Baseline.Stable && !ctx.Baseline.Degraded,
		degraded:        ctx.Baseline.Degraded,
		percentRelevant: sstiPercentRelevant(ctx.Slot.Kind),
	}
}

// sstiCompose is the verdict ladder. iso-eval 1.5: the verdict is the strongest oracle result,
// EXCEPT that it can never be clean while any of this class's own oracles is an unknown.
//
// THE ORDER IS THE SPECIFICATION. Everything above the positives invalidates them; everything
// between the positives and the clean is a reason a silence is not this application's silence.
func sstiCompose(slot triage.SlotKey, sc sstiScorecard, ords []uint64,
	untested []triage.ProbeSkip, gaps []triage.ProbeID, ann map[string]any, env sstiEnv) []triage.ClassVerdict {

	// ------- the hard unknowns, in the order they invalidate everything below them -----------
	if sc.runnerBug != "" {
		return sstiOne(slot, triage.StateCannotDetermine, "runner_bug: "+sc.runnerBug, ords, untested, ann, triage.TriageEvidence{})
	}
	if sc.controlFired != "" {
		return sstiOne(slot, triage.StateCannotDetermine,
			"detector_unverified: this class's own negative control "+string(sc.controlFired)+
				" produced a match, so the detector has been shown FIRING on a payload that computes nothing. Every verdict on this slot is void and the run is flagged",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if sc.staleMarker {
		return sstiOne(slot, triage.StateCannotDetermine,
			"stale_marker: a response carried an SSTI marker minted by a different run, so a cache or a replay is serving these bodies and nothing measured here is about this request",
			ords, untested, ann, triage.TriageEvidence{})
	}
	// THE BLIND ARM IS SCORED HERE, ABOVE THE UNIFORM-BLOCK RUNG, AND THIS IS THE ONE PLACE IT
	// OUTRANKS A REFUSAL RATHER THAN SITTING UNDER IT.
	//
	// MEASURED, canary oracle, 2026-09-19, whole registry at full tier: this class reported
	// "blocked" on /ssti/blind, which is the route its OWN OracleCases declare as the blind arm's
	// positive, and on /trav/blind. Both routes answer the baseline page to a payload that parses
	// and one shared error body to every payload that does not, which is three or more distinct
	// payloads on one non-baseline body: the same shape /clean/waf's identical 403 has, and
	// indistinguishable from it by that heuristic alone.
	//
	// THE ARM'S OWN CONTROLS ARE THE STRONGER TEST AND THEY ARE WHAT MAKES THIS SAFE. A filter
	// answering does not separate BOK from BER, because both carry the delimiters it is refusing:
	// on /clean/waf every one of the four pairs collapses onto the same 403 and the arm is
	// SILENT, which is exactly what this class's OracleCases declare for that route. Control A
	// refuses the arm outright when the two garbage members of a family land in different status
	// classes. So a DIFFERENTIATED arm on a uniformly-blocking-looking endpoint is a statement
	// that the endpoint discriminated between two same-length payloads that differ only in
	// whether they PARSE, which no block page does.
	//
	// EVERYTHING ELSE STILL LOSES TO THE BLOCK. A silent arm, or one that could not run, leaves
	// the rung exactly where it was and only adds its sentence, because a uniform block really
	// does mean the battery below measured a filter.
	// THE GATE'S DECISION TRAVELS WITH THE ARM. sstiEnvFrom cannot fill armGate in, because the
	// gate is a function of the scorecard; this is the one place that holds both. Without this
	// line the arm's "never sent" row offers a menu of runner causes on every slot where THIS
	// CLASS is the reason the probe is absent, which was all 28 cleans of the run that prompted it.
	env.armGate = sstiBlindGateSentence(sc)
	blind := sstiBlindArm(sc.answered, env)
	ann["blind_arm"] = blind.Why
	ann["blind_arm_gate"] = env.armGate
	if env.blocked {
		if blind.Outcome == sstiBlindDifferentiated {
			return sstiBlindFired(slot, sc, blind, ords, untested, ann,
				"This endpoint also answered three or more of this class's distinct payloads with one "+
					"byte-identical non-baseline body, which on its own reads as a uniform block. The arm "+
					"outranks that reading here: a filter refusing these delimiters refuses the VALID and the "+
					"INVALID member of a pair alike, and these separated.")
		}
		return sstiOne(slot, triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical responses that differ from the route control, which is a uniform block and not an application answer. "+
				sstiBlindSentence(blind),
			ords, untested, ann, triage.TriageEvidence{})
	}
	if env.drifted {
		return sstiOne(slot, triage.StateCannotDetermine,
			"drift: the post-baseline disagrees with the route control, so the application moved under the probes and every differential in the window is unattributable",
			ords, untested, ann, triage.TriageEvidence{})
	}

	// ------- the positives, strongest first -------------------------------------------------
	if sc.computeFamily != "" {
		grade := sstiGradeFor(sc)
		state := triage.StateFinding
		if grade != triage.GradeHigh {
			state = triage.StateSuspicious
		}
		// THE REASON IS BUILT AT EVERY GRADE AND NOT ONLY WHEN SOMETHING WENT WRONG. It used to
		// be sstiWhyNotHigh below high and the empty string at high, so the strongest row this
		// class can produce was the one row with nothing in the field every audit reads.
		reason := sstiComputeReason(sc, grade)
		ev := triage.TriageEvidence{
			Matched:    sc.computeHit.Matched,
			Offset:     sc.computeHit.Offset,
			Length:     sc.computeHit.Length,
			Phrase:     "computation " + string(sc.computeFamily),
			MarkerForm: sc.computeHit.MarkerForm,
		}
		ann["gap_bytes"] = sc.computeHit.GapBytes
		ann["evaluation_proven"] = true
		v := sstiOne(slot, state, reason, ords, untested, ann, ev)
		v[0].Grade = grade
		v[0].Oracle = "computation"
		v[0].Label = sstiLabel(sc)
		return v
	}
	if sc.consumeFamily != "" {
		state := triage.StateFinding
		grade := triage.GradeLow
		oracle := "consumption"
		if sc.confirmed {
			grade = triage.GradeMedium
		}
		reason := sstiConsumeReason(sc, grade)
		if sc.stripper {
			state = triage.StateCannotDetermine
			reason = "stripper: the delimiters were removed but the inner literal survived, which is a sanitizer deleting braces and not an engine parsing them"
			grade = triage.GradeUnrated
		}
		ann["evaluation_unproven"] = true
		ev := triage.TriageEvidence{
			Matched: sc.consumeHit.Matched, Offset: sc.consumeHit.Offset, Length: sc.consumeHit.Length,
			Phrase: "consumption " + string(sc.consumeFamily), MarkerForm: sc.consumeHit.MarkerForm,
		}
		v := sstiOne(slot, state, reason, ords, untested, ann, ev)
		v[0].Grade = grade
		v[0].Oracle = oracle
		v[0].Label = sstiLabel(sc)
		return v
	}
	if sc.distinctEngine != "" {
		ann["identified_engine"] = sc.distinctEngine
		v := sstiOne(slot, triage.StateFinding, sstiDistinctReason(sc), ords, untested, ann,
			triage.TriageEvidence{Phrase: "distinctive_content " + sc.distinctEngine})
		v[0].Grade = triage.GradeMedium
		v[0].Oracle = "distinctive_content"
		v[0].Label = sstiLabel(sc)
		return v
	}
	if sc.errorSignature != "" || sc.evaluatorProof != "" {
		phrase := sc.errorSignature
		if phrase == "" {
			phrase = sc.evaluatorProof
		}
		ann["evaluation_proven"] = sc.evaluatorProof != ""
		v := sstiOne(slot, triage.StateFinding, sstiErrorReason(sc), ords, untested, ann,
			triage.TriageEvidence{Phrase: "error_signature " + phrase})
		v[0].Grade = triage.GradeMedium
		v[0].Oracle = "error_signature"
		v[0].Label = sstiLabel(sc)
		return v
	}
	// THE BLIND ARM, and it sits HERE for two reasons worth writing down.
	//
	// BELOW EVERY OTHER POSITIVE, because it is the weakest oracle in the class. If anything above
	// fired, that oracle has already answered with better evidence and a tier 6 differential would
	// only dilute the row.
	//
	// ABOVE perturbedUnexplained, WHICH IS THE LOAD-BEARING HALF. perturbedUnexplained fires when
	// any of this class's non-control probes moved the response and none of its signatures
	// explains it, and the blind arm's own SYNTAX-ERROR members move the response on precisely the
	// endpoints the arm is designed to find. Left below it, a firing blind arm would be reported
	// as "something changed and I do not know what" while the thing that changed it was this
	// class's own pair and the class did know. The blind arm IS the explanation, so it gets the
	// row.
	if blind.Outcome == sstiBlindDifferentiated {
		return sstiBlindFired(slot, sc, blind, ords, untested, ann, "")
	}

	// ------- the unknowns that block a clean --------------------------------------------------
	// THE DIVERGED POLYGLOT, AND IT IS A REFUSAL RATHER THAN A POINTER.
	//
	// SSTI-S2's own bytes came back neither intact nor under any encoding this class undoes. Two
	// readings fit those bytes exactly and this class cannot separate them from one response: an
	// engine consumed the delimiters, or a sanitizer deleted them, or the field simply cut the
	// value short. Measured on the canary exam, the routes that reach here are /csti/escaped
	// (a regexp that strips every brace), /csti/angular-attr (the same for text), /cmdi,
	// /crlf/setcookie and /sqli/mssql (the field cut the value). None of them is a template
	// engine, and pointing an operator at any of them is the promise this class must stop making.
	//
	// IT STILL MAY NOT BE A CLEAN. If the polyglot did not survive, the delimiters the rest of
	// this battery carries did not survive either, so every silence below is a silence about
	// payloads that arrived changed. That is the whole of the argument.
	if sc.polyglot == sstiPolyglotDiverged {
		return sstiOne(slot, triage.StateCannotDetermine,
			"polyglot_diverged: this class's non-error polyglot SSTI-S2 came back neither byte-identical to what was sent nor "+
				"equal to it under percent, HTML-entity or JSON-string decoding. Its delimiters therefore did not survive this "+
				"response path, which an engine, a sanitizer that deletes braces and a field that cuts the value all produce, "+
				"and this class cannot tell those three apart from one response. Every other payload in this battery carries "+
				"the same delimiters, so no silence on this slot is the application's",
			ords, untested, ann, triage.TriageEvidence{Phrase: "polyglot_diverged"})
	}
	if sc.perturbedUnexplained {
		return sstiOne(slot, triage.StateCannotDetermine,
			"unattributed_error: "+string(sc.perturbedProbe)+" came back with a different body from the route control, its own marker "+
				"was NOT in that response or its status class had moved, and none of this class's own signatures explains the change. "+
				"Ruling R1: a class never reads another class's catalogue, not even to fail closed, so this is recorded as unexplained "+
				"rather than attributed",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if sc.reEncodedOnly {
		return sstiOne(slot, triage.StateCannotDetermine,
			"marker_form_unmatched: the marker came back only in a re-encoded form, so anything the engine computed came back transformed too and the adjacency rule had nothing to measure",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if sc.corruptMarker {
		return sstiOne(slot, triage.StateCannotDetermine,
			"marker_corrupted: a returned marker failed its checksum, so attribution to this probe is unsafe and no silence here can be read as this slot's silence",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if len(sc.notDelivered) > 0 {
		return sstiOne(slot, triage.StateCannotDetermine,
			"could_not_send: the transport refused "+sstiJoinIDs(sc.notDelivered)+", so those payloads never reached the application and their silence is the transport's, not the application's",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if !sc.reflectMeasure {
		return sstiOne(slot, triage.StateCannotDetermine,
			"census_not_run: this class's own bare-marker probe has no response, so whether the computation oracle was even available here was never measured",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if !sc.reflects && !sc.censusMarkerOnWire {
		// NOT "no_reflection". The census probe went out WITHOUT a marker in it, so the search
		// that followed looked for a value nobody sent, and its silence is this class's own and
		// not the application's. Saying no_reflection here is a false statement about the target
		// in the one field an operator reads, and it is false on every row in the corpus at once.
		//
		// See the field comment on sstiScorecard.censusMarkerOnWire for the mechanism. THE FIX
		// SHIPPED: this class opts in to runner-placed markers with PREFIX placement, which
		// leaves the polyglot's own bytes contiguous, and on the 80-route canary exam this branch
		// no longer fires anywhere. It stays as a fail-closed rung rather than being deleted,
		// because the opt-in can be turned off and this class spells no marker token of its own,
		// and the alternative to this sentence is no_reflection, which would be a false statement
		// about the target on every row at once.
		//
		// THE GUARD IS !reflects AND !onWire, not !onWire alone. If a marker came back, it was
		// plainly sent, whatever this measurement says about the wire record, and the stronger
		// fact wins. Written the other way round it preempted every branch below it including the
		// clean, which is how a truthful sentence becomes a class that can only ever say one
		// thing.
		return sstiOne(slot, triage.StateCannotDetermine,
			"census_marker_not_sent: this class's census probe SSTI-S0 reached the wire carrying no marker of "+
				"its own, so the reflection search looked for bytes that were never in the request and its "+
				"silence measures this class's instrumentation rather than the endpoint. Nothing here says "+
				"whether the slot reflects, and no silence on this slot may be read as the application's. "+
				sstiBlindSentence(blind),
			ords, untested, ann, triage.TriageEvidence{})
	}
	if !sc.reflects {
		// THE SENTENCE CHANGED AND THE STATE DID NOT, WHICH IS THE POINT OF THE WHOLE ARM.
		//
		// This row used to end at "the rank 1 oracle was structurally unavailable" and stop, which
		// is where the layer was refusing BEFORE trying. The blind arm is the trying, and its
		// outcome rides on the reason so an operator can tell three different situations apart
		// that all used to print the same word:
		//
		//	differentiated   never reaches here; it took the suspicious rung above.
		//	silent           the arm ran on a stable endpoint with its controls holding and
		//	                 neither delimiter family separated. That is real evidence against a
		//	                 template engine in these two delimiter shapes. It is STILL NOT CLEAN,
		//	                 because a tier 6 differential that stayed quiet eliminates two
		//	                 delimiter families and nothing else, and because the rank 1 oracle
		//	                 that WOULD have settled it was blind here.
		//	not run          a precondition failed and Why names it, so the operator knows whether
		//	                 to fix the endpoint model or point sstimap at the slot.
		return sstiOne(slot, triage.StateCannotDetermine,
			"no_reflection: this class's own bare marker came back ABSENT, so a computed value could not have appeared either and the rank 1 oracle was structurally unavailable rather than silent. A blind template sink (an email subject, a PDF, a generated filename, a log line) looks exactly like this, and it needs sstimap in a blind mode. "+
				sstiBlindSentence(blind),
			ords, untested, ann, triage.TriageEvidence{})
	}
	if len(sc.truncated) > 0 {
		return sstiOne(slot, triage.StateCannotDetermine,
			"truncated: the measured field limit cannot carry "+sstiJoinIDs(sc.truncated)+", so those engine families were never tested on this slot",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if sc.decodeDepth == 0 && env.percentRelevant {
		return sstiOne(slot, triage.StateCannotDetermine,
			"decode_depth_0: this class's own decode probe showed the slot does not percent-decode, so every brace and angle bracket arrived as literal percent text and no delimiter ever reached a template engine. Ruling R6c: the payloads were sent anyway and their silence is downgraded rather than read as clean",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if sc.decodeDepth < 0 && env.percentRelevant {
		return sstiOne(slot, triage.StateCannotDetermine,
			"decode_depth_unknown: this class's own decode probe was inconclusive, so whether the delimiters arrived as delimiters was never established",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if env.canaryValue {
		return sstiOne(slot, triage.StateCannotDetermine,
			"canary_resource: the slot was probed at a fabricated identifier, and a scan of a resource that does not exist is not a clean scan of the endpoint",
			ords, untested, ann, triage.TriageEvidence{})
	}
	if env.unstable {
		reason := "too_volatile: the endpoint's stability gate did not pass, so a silence here cannot be told from noise"
		if env.gateReason != "" {
			reason = env.gateReason + ": the endpoint's stability gate did not pass, so a silence here cannot be told from noise"
		}
		return sstiOne(slot, triage.StateCannotDetermine, reason, ords, untested, ann, triage.TriageEvidence{})
	}
	// BATTERY_INCOMPLETE COUNTS GAPS, NOT UNTESTED ROWS, AND THE OLD SENTENCE WAS FALSE.
	//
	// It read "N of this class's families were not sent ... so the engines they alone reach were
	// never tested here" and N was len(untested), which is every declared probe that did not go
	// out. On a slot with no hit that list is dominated by confirmations, identification
	// finishers, engine probes and the blind arm, none of which is a family and none of which
	// reaches an engine on its own. MEASURED on /clean/echo: 45 untested rows, of which 34 were
	// escalation-only, 10 were the blind arm correctly not run because the slot reflects, and one
	// was SSTI-F9c, the cookie-only sibling of a Liquid family that DID go out. Zero families
	// were missing and the row would have said 45. On /redirect/strictvalidator it shipped and
	// said 52.
	//
	// So the rung now reads the gap list, which is the subset that means an engine really was not
	// tested on this slot: a family too long for the measured field, a family carrying a space on
	// an undecoded cookie, the blind arm cut off by the budget, a negative control this slot
	// earned and did not get, and anything the ladder simply never reached.
	if len(gaps) > 0 {
		return sstiOne(slot, triage.StateCannotDetermine,
			"battery_incomplete: "+strconv.Itoa(len(gaps))+" of this class's probes were deliverable to this slot and did not go out ("+
				sstiJoinIDs(gaps)+"), each with its own reason in Untested, so what they alone reach was never tested here",
			ords, untested, ann, triage.TriageEvidence{})
	}

	// ------- and only now, a clean ------------------------------------------------------------
	//
	// EVERY PRECONDITION IS PRINTED, CATALOGUE 4.5 RULE 2: this class's own probes ran, the
	// transport delivered them, its own bare marker came back so the computation oracle was
	// available, its own decode probe proved the delimiters arrived as delimiters, every family
	// deliverable to this slot was sent, its own four controls stayed silent, and the endpoint was
	// stable. The one thing this clean does NOT cover is an engine with custom delimiters, which
	// is why the annotation rides on it.
	v := sstiOne(slot, triage.StateClean, sstiCleanReason(sc, env, blind), ords, untested, ann, triage.TriageEvidence{})
	v[0].Oracle = "computation+consumption+error_signature+distinctive_content"
	v[0].Label = sstiLabel(sc)
	return v
}

// ---------------------------------------------------------------------------------------------
// 9b. THE REASONS THE POSITIVES AND THE CLEAN USED TO SHIP WITHOUT
//
// FIVE RUNGS OF THIS LADDER CARRIED Reason: "". The computation finding, the consumption finding,
// the distinctive-content finding, the error-signature finding and the clean each put their whole
// justification into the Oracle field, the Evidence phrase and the annotations. MEASURED on the
// run that prompted these functions: length(reason) was 0 on the finding at /ssti and on all 28
// of this class's cleans.
//
// WHY THAT MATTERS MORE THAN IT LOOKS. Every audit of this layer is a grep over reason strings,
// so a class that writes nothing there is invisible to the check that has already caught three
// false causes in the other classes, and its rows are the ones nobody can contradict. CORS,
// HOSTHEADER and HPP each pin a minimum reason length on their own verdicts. SSTI did not.
//
// EVERY SENTENCE BELOW IS BUILT FROM A FIELD THE SCORECARD MEASURED. Where a guard could not be
// asserted (no recorded wire form, a control that was not deliverable here) the sentence says so
// rather than leaving the reader to assume it held.
// ---------------------------------------------------------------------------------------------

// sstiSentBytes is the logical payload this class's own table declares for a probe.
//
// IT IS WHAT WAS ASKED FOR AND NOT A CLAIM ABOUT WHAT WENT OUT. The encoder may percent-encode
// it and the runner prepends this class's minted marker, so a reason quoting this says "carried",
// and any statement about the bytes that actually left is made separately, from Payload.Survived.
func sstiSentBytes(id triage.ProbeID) string {
	return sstiSpecByID()[id].logical
}

// sstiExpectedFor mirrors sstiScore's own want derivation exactly, so a reason can name the
// number the oracle was looking for. A different rule here would print an answer the matcher
// never searched for.
func sstiExpectedFor(id triage.ProbeID) string {
	r, ok := sstiSpecByID()[id]
	if !ok {
		return ""
	}
	if w := r.variant[sstiVariantExpected]; w != "" {
		return w
	}
	if r.control {
		return sstiExpected
	}
	return ""
}

// sstiWireGuardSentence is the answer_not_in_wire guard, reported as what it actually was.
//
// THE GUARD RAN ON EVERY COMPUTATION HIT: sstiScore refuses the hit outright when the expected
// answer appears in Payload.Wire, Logical or Container. What VARIES is whether there was a wire
// record to search, and that is the difference between a hit that may reach high and one capped
// below it. Saying "the answer was not in the request" when nothing recorded the request is the
// kind of sentence this file exists to stop.
func sstiWireGuardSentence(sc sstiScorecard) string {
	want := sstiExpectedFor(sc.computeFamily)
	obs, ok := sc.answered[sc.computeFamily]
	if ok && obs.Payload.Survived.Proven() {
		return "The wire form of this request WAS recorded (survival " + string(obs.Payload.Survived) +
			") and " + want + " is not in it, so the number was produced after the request left rather than " +
			"echoed out of it"
	}
	survival := string(obs.Payload.Survived)
	if survival == "" {
		// WireSurvivalUnknown is the zero value and it prints as the empty string, which would
		// have made this read "(survival )". Unknown is the commonest case here and it is the
		// whole reason the guard could not be asserted, so it is named.
		survival = "unknown"
	}
	return "The wire form of this request was NOT recorded (survival " + survival +
		"), so the answer_not_in_wire guard could not be asserted here and this row is capped below high"
}

// sstiComputeReason is the rank 1 oracle's row, at every grade.
func sstiComputeReason(sc sstiScorecard, grade triage.TriageGrade) string {
	want := sstiExpectedFor(sc.computeFamily)
	r := "computation (" + string(sc.computeFamily) + "): this class sent " +
		strconv.Quote(sstiSentBytes(sc.computeFamily)) + " with its own minted marker prefixed, and read " +
		strconv.Quote(string(sc.computeHit.Matched)) + " back at byte offset " +
		strconv.Itoa(sc.computeHit.Offset) + " of the response: the marker in its " + sc.computeHit.MarkerForm +
		" form, " + strconv.Itoa(sc.computeHit.GapBytes) + " whitespace bytes, then " + want +
		", with no token byte before the marker and no digit continuing the number. " + want +
		" is the answer this class's table declares for that payload's operands (the families do not " +
		"all multiply: F10 adds and F11 counts), and a literal echo returns the EXPRESSION and never " +
		"its answer. " + sstiWireGuardSentence(sc)
	if sc.confirmed {
		r += ". A confirmation probe with a FRESH marker and fresh operands reproduced it, which is what " +
			"separates an evaluation from a cached body"
	}
	if grade != triage.GradeHigh {
		r += ". Graded " + string(grade) + " rather than high: " + sstiWhyNotHigh(sc)
	}
	return r
}

// sstiConsumeReason is the rank 7 oracle's row. IT CLAIMS PARSING AND NOT EVALUATION, and the
// sentence has to carry that distinction because the two earn different tool runs.
func sstiConsumeReason(sc sstiScorecard, grade triage.TriageGrade) string {
	r := "consumption (" + string(sc.consumeFamily) + "): this class sent " +
		strconv.Quote(sstiSentBytes(sc.consumeFamily)) + ", which carries three markers with the middle one " +
		"inside the delimiters, and read " + strconv.Quote(string(sc.consumeHit.Matched)) + " back at byte " +
		"offset " + strconv.Itoa(sc.consumeHit.Offset) + ": the FIRST and THIRD markers adjacent, with no " +
		"form of the middle marker anywhere in the body under any of the transforms this class searches " +
		"for. Something between the two outer markers consumed the delimiters and what they enclosed, " +
		"which an echo cannot do. IT IS NOT EVALUATION: whatever the sink computed was never shown, so " +
		"this points a tool at the slot and does not prove execution"
	if sc.confirmed {
		r += ". The parser-versus-stripper pair reproduced it and the stripper form did not survive, so " +
			"this is a parser and not a sanitizer deleting braces"
	} else {
		r += ". Graded " + string(grade) + ": the parser-versus-stripper pair has not reproduced it here, " +
			"so a sanitizer that deletes these delimiters is not yet ruled out"
	}
	return r
}

// sstiDistinctReason is the identification oracle's row. It is the one positive whose whole value
// is the ENGINE NAME, so the reason says which probe carried it.
func sstiDistinctReason(sc sstiScorecard) string {
	probe := string(sc.distinctProbe)
	if probe == "" {
		probe = "an identification probe this class did not record"
	}
	return "distinctive_content (" + probe + "): this class sent " +
		strconv.Quote(sstiSentBytes(sc.distinctProbe)) + " and read " +
		strconv.Quote(string(sc.distinctHit.Matched)) + " back at byte offset " +
		strconv.Itoa(sc.distinctHit.Offset) + ", immediately after this probe's own marker in its " +
		sc.distinctHit.MarkerForm + " form, and those bytes were NOT in the route control's body. " +
		"Rendering that value in that position is " + sc.distinctEngine + "'s documented behaviour and " +
		"no other engine in this class's table produces it, so this identifies the engine as " +
		sc.distinctEngine + " AS FAR AS THAT TABLE REACHES: it is an identification and not a census of " +
		"every engine that exists. The evaluation itself is a separate question, and the label points " +
		"the tool that has a plugin for this engine"
}

// sstiErrorReason is the error-signature and arithmetic-proof row.
//
// THE BASELINE CLAUSE SAYS WHAT WAS MEASURED AND NOT MORE. sstiErrorSignatureIn refuses a
// signature whose every literal is already in the route control's body. When that body is empty
// the check passes vacuously, so the sentence reports the comparison rather than asserting the
// signature is absent from a page this class may never have had.
func sstiErrorReason(sc sstiScorecard) string {
	phrase, probe, what := sc.errorSignature, sc.errorProbe, "a template-engine error signature"
	if phrase == "" {
		phrase, probe, what = sc.evaluatorProof, sc.evalProbe, "an ARITHMETIC error signature, which is "+
			"proof the expression was evaluated and not merely parsed"
	}
	r := "error_signature (" + phrase + "): "
	if probe != "" {
		r += "this class sent " + strconv.Quote(sstiSentBytes(probe)) + " as " + string(probe) + " and "
	} else {
		r += "one of this class's own probes came back and "
	}
	r += "every literal of " + phrase + " was present in the response while they were not all present " +
		"in the route control's body this class differenced against. That is " + what +
		", raised by the sink out of this class's own payload"
	if sc.errorEngine != "" {
		r += ". The signature names " + sc.errorEngine
		if sc.errorLanguage != "" {
			r += " (" + sc.errorLanguage + ")"
		}
	} else if sc.errorLanguage != "" {
		r += ". The signature names the " + sc.errorLanguage + " runtime"
	}
	return r + ". An error proves the sink PARSED the payload; the computation oracle is what would have " +
		"proved it evaluated one, and it did not fire on this slot"
}

// sstiControlsAnswered names the negative controls this slot actually got a response for.
//
// IT IS A MEASUREMENT AND NOT THE LIST OF FIVE. A control that does not declare this slot's
// insertion point is recorded as not_reachable and is NOT counted as a gap, so a clean can be
// reached with fewer than five of them in hand. The clean's sentence prints the ones it has.
func sstiControlsAnswered(sc sstiScorecard) []triage.ProbeID {
	var out []triage.ProbeID
	for _, id := range []triage.ProbeID{sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4} {
		if _, ok := sc.answered[id]; ok {
			out = append(out, id)
		}
	}
	return out
}

// sstiCleanReason prints EVERY PRECONDITION the ladder above it just checked, catalogue 4.5
// rule 2, and then the two things this clean does not cover.
func sstiCleanReason(sc sstiScorecard, env sstiEnv, blind sstiBlindResult) string {
	r := "clean: " + strconv.Itoa(len(sc.answered)) + " of this class's own probes came back on this slot " +
		"and none of its four oracles fired. WHAT MAKES THAT A MEASUREMENT: this class's census probe " +
		string(sstiS0) + " came back WITH its own marker in it, so a value the sink computed would have been " +
		"visible here and the rank 1 computation oracle was AVAILABLE rather than blind; the transport " +
		"delivered every probe that went out; no returned marker failed its checksum and none came back " +
		"only in a re-encoded form; every probe deliverable to this slot was sent, so nothing is listed " +
		"as a gap"
	if sc.polyglot == sstiPolyglotUnread {
		r += "; the non-error polyglot " + string(sstiS2) + "'s own bytes could not be read back, so the " +
			"delimiter-survival evidence is missing from this row"
	} else {
		r += "; the non-error polyglot " + string(sstiS2) + "'s own bytes came back " + string(sc.polyglot) +
			", so the delimiters the rest of this battery carries survived the response path"
	}
	if env.percentRelevant {
		r += "; this class's own decode probe measured a decode depth of " + strconv.Itoa(sc.decodeDepth) +
			", so the braces and angle brackets arrived as delimiters and not as literal percent text"
	} else {
		r += "; percent-decoding is not a precondition on this slot kind, so no decode depth is asserted"
	}
	if ctl := sstiControlsAnswered(sc); len(ctl) > 0 {
		r += "; this class's own negative controls " + sstiJoinIDs(ctl) + " were answered here and all of " +
			"them stayed silent, so the detector has been shown NOT firing on payloads that compute nothing"
	} else {
		r += "; NO negative control of this class was answered on this slot, so the matcher behind this " +
			"silence is unverified here"
	}
	// THE STABILITY CLAUSE SPLITS, AND THE OLD SENTENCE WOULD HAVE BEEN FALSE ON THE LENIENT HALF.
	//
	// env.unstable is false when Baseline.Samples is 0, deliberately (see the field comment on
	// sstiEnv.stable), so a slot with NO baseline model at all reaches this clean. "The
	// endpoint's stability gate passed" is a statement about a gate that did not run on that
	// slot. env.stable is the positive form and it is what the first branch rests on.
	if env.stable {
		r += "; the endpoint's stability gate PASSED, on a baseline model with samples behind it"
	} else {
		r += "; NO BASELINE MODEL WAS BUILT FOR THIS SLOT, so nothing measured this endpoint's own " +
			"variation. The stability gate did not refuse this slot, and it did not clear it either: " +
			"this clean rests on the oracles above and not on a noise model"
	}
	r += "; the value probed was the observed one rather than a " +
		"fabricated identifier. " + sstiBlindSentence(blind) +
		". WHAT THIS CLEAN DOES NOT COVER: an engine configured with custom delimiters (a rewritten " +
		"Handlebars, a Twig with only {% %}, a Mustache switched by {{=<% %>=}}) is invisible to a fixed " +
		"battery, and a value stored now and rendered on another page later is out of reach of one " +
		"request and one response"
	return r
}

func sstiOne(slot triage.SlotKey, st triage.TriageState, reason string, ords []uint64,
	untested []triage.ProbeSkip, ann map[string]any, ev triage.TriageEvidence) []triage.ClassVerdict {
	return []triage.ClassVerdict{{
		Class: triage.ClassSSTI, SlotKey: slot, State: st, Reason: reason,
		Ordinals: ords, Untested: untested, Annotations: ann, Evidence: ev,
	}}
}

// sstiGradeFor applies CATALOGUE 4.2. A rank 1 oracle reaches high ONLY with the guard asserted,
// a zero gap, a literal marker form, a valid checksum and a fresh-marker reproduction.
func sstiGradeFor(sc sstiScorecard) triage.TriageGrade {
	if sc.corruptMarker {
		return triage.GradeMedium
	}
	obs, ok := sc.answered[sc.computeFamily]
	if !ok || !obs.Payload.Survived.Proven() {
		return triage.GradeMedium
	}
	if sc.computeHit.GapBytes > 0 || sc.computeHit.MarkerForm != "raw" {
		return triage.GradeMedium
	}
	if !sc.confirmed {
		return triage.GradeMedium
	}
	return triage.GradeHigh
}

func sstiWhyNotHigh(sc sstiScorecard) string {
	switch {
	case sc.corruptMarker:
		return "the marker came back with a failed checksum, so attribution is unsafe and CATALOGUE 4.2 caps this at suspicious"
	case !sc.confirmed:
		return "the computation fired but the fresh-marker, fresh-operand confirmation has not reproduced it, so a cached body cannot yet be ruled out"
	case sc.computeHit.GapBytes > 0:
		return "whitespace separated the marker from the answer, which is allowed and downgrades the grade"
	case sc.computeHit.MarkerForm != "raw":
		return "the marker came back re-encoded, so the adjacency is between transformed bytes"
	default:
		return "the wire form of the payload was not recorded, so the answer_not_in_wire guard could not be asserted"
	}
}

// sstiDrifted compares the post-baseline with the route control. Every differential taken in a
// window where the application changed underneath is unattributable.
func sstiDrifted(ctx triage.ClassifyCtx) bool {
	if !ctx.Route.Resolved() || !ctx.PostBaseline.Resolved() {
		return false
	}
	return ctx.Route.Obs().BodySHA256 != ctx.PostBaseline.Obs().BodySHA256
}

func sstiOrdinals(ctx triage.ClassifyCtx) []uint64 {
	seen := map[uint64]bool{}
	var out []uint64
	for i := 0; i < ctx.Own.Len(); i++ {
		p, _, err := ctx.Own.At(i)
		if err != nil {
			continue
		}
		if o := p.Ordinal(); o != 0 && !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sstiUntested names every declared probe this slot did not receive, with the reason.
//
// THIS IS THE FUNCTION THAT STOPS A SHORTENED BATTERY READING AS A COMPLETE ONE. A family skipped
// for truncation, for a cookie space, for an insertion point it does not reach or for an exhausted
// budget gets a row here, because the alternative is a report where twelve engines were never
// tested and nothing on the page says so.
func sstiUntested(ctx triage.ClassifyCtx, sc sstiScorecard) ([]triage.ProbeSkip, []triage.ProbeID) {
	var out []triage.ProbeSkip
	var gaps []triage.ProbeID
	gap := func(id triage.ProbeID, reason string) {
		out = append(out, triage.ProbeSkip{ProbeID: id, Reason: reason})
		gaps = append(gaps, id)
	}
	for _, r := range sstiProbeTable() {
		if _, answered := sc.answered[r.id]; answered {
			continue
		}
		switch {
		case !sstiPointsInclude(r.points, ctx.Slot.Kind):
			// NOT A GAP. A probe that does not declare this insertion point has a sibling that
			// does: SSTI-F9c is Liquid for a cookie and SSTI-F9 is Liquid everywhere else, so on
			// a query slot F9c's absence leaves no engine untested. It is still recorded, because
			// a reader is owed the list, and it is not counted against the clean.
			out = append(out, triage.ProbeSkip{ProbeID: r.id,
				Reason: "not_reachable: this probe does not declare the " + string(ctx.Slot.Kind) + " insertion point, and the family it belongs to is carried on this slot by its sibling"})
		case !sstiFitsField(r, ctx.Slot.Constraints.FieldLimit):
			gap(r.id, "truncated: "+strconv.Itoa(sstiWireLen(r))+" bytes will not fit the measured field limit of "+
				strconv.Itoa(ctx.Slot.Constraints.FieldLimit)+", so the engines this family alone reaches were not tested here")
		case !sstiCookieDeliverable(r, ctx.Slot):
			gap(r.id, "cookie_space: this payload carries a SPACE, which is not a cookie-octet, and this class's own decode probe did not prove the slot percent-decodes")
		case sstiIsNegativeControl(r.id) && sstiControlsEarned(sc):
			// EARNED AND ABSENT IS A BUDGET GAP, AND THE OLD SENTENCE WOULD HAVE BEEN FALSE HERE.
			// These five are now requested on any reflecting slot where nothing fired, so "only
			// earned by a first hit" stops being true for them the moment the slot reflects.
			gap(r.id, "not_run (budget_before_the_controls): this class's own negative control was requested on this slot, "+
				"because a reflecting slot with no hit is the slot whose silence is about to be read as the application's, "+
				"and the per-slot probe cap bit before it left. The clean is refused rather than granted on an unverified matcher")
		case sstiIsBlindArm(r.id):
			// THE BLIND ARM IS EARNED BY THE ABSENCE OF A HIT, SO THE ESCALATION SENTENCE IS A
			// FALSE ONE FOR IT. Measured on the canary oracle: with the arm folded into the
			// escalation list, all ten of these probes came back in Untested reading "only earned
			// by a first hit, and nothing on this slot earned it", which is the exact opposite of
			// why they exist and points the operator at nothing.
			reason := sstiBlindSkipReason(sc)
			// The arm's three reasons are not one fact. Two of them say the arm was correctly not
			// run (a stronger oracle answered, or the slot reflects and the rank 1 oracle was
			// available), and those leave nothing untested. The third is a budget the operator
			// can raise, and that one is a gap.
			if sstiBlindSkipIsBudget(sc) {
				gap(r.id, reason)
			} else {
				out = append(out, triage.ProbeSkip{ProbeID: r.id, Reason: reason})
			}
		case sstiIsEscalationOnly(r.id):
			// NOT A GAP. A confirmation, an identification finisher or an engine-probe is earned
			// by a first hit. On a slot where nothing hit there is nothing for it to confirm or
			// identify, so its absence does not leave an engine untested.
			out = append(out, triage.ProbeSkip{ProbeID: r.id,
				Reason: "not_run: this probe is only earned by a first hit, and nothing on this slot earned it"})
		default:
			// THE SENTENCE NAMES THREE CAUSES AND PICKS NONE, because this class cannot see which
			// one applies. It used to name two, "the budget or the round count", and left out the
			// third: ProbeSpec.Tier is enforced by the runner and PlanCtx carries no Tier field,
			// so on a reduced-tier run every TierFull family in this table lands here and a row
			// saying the budget ran out would be inventing a cause. It is a gap either way, which
			// is what matters to the clean below.
			gap(r.id, "not_run: this probe is deliverable to this slot and no response for it came back. "+
				"This class cannot see which of the three applies: the run's tier is below this probe's, "+
				"the per-slot probe cap bit before the ladder reached it, or the run ended before its round")
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProbeID < out[j].ProbeID })
	sort.Slice(gaps, func(i, j int) bool { return gaps[i] < gaps[j] })
	return out, gaps
}

// sstiBlindSkipIsBudget decides whether the arm's absence counts against the clean.
//
// IT IS DELIBERATELY WIDER THAN sstiBlindSkipReason'S LAST BRANCH. That function now separates
// "the census never answered, so this class never asked" from "the gate was met and nothing came
// back", and only the second is something an operator can change. This predicate still counts
// BOTH as a gap, because narrowing it is the one edit here that could turn a refusal into a
// clean: the census-unanswered slot takes the census_not_run rung above battery_incomplete today,
// and a reordering of that ladder must not silently hand it a clean instead. Wider is the safe
// direction and this is the one place that says so.
func sstiBlindSkipIsBudget(sc sstiScorecard) bool {
	// THE computeFamily TERM IS GONE, and removing it widens the predicate rather than narrowing
	// it, which is the safe direction this comment already argues for. It was there to spare the
	// slot where "a stronger oracle answered" was read as a reason the arm was never requested.
	// That reading was false: reaching it means the census answered and its marker did not come
	// back, which IS the gate met, so the arm WAS requested in round 1 and its absence is the
	// same requested-and-absent gap every other met-gate slot records. It changes no verdict
	// today, because gaps are only read on the rung below the positives and a computed family
	// returns a finding long before that rung: what it changes is that the row stops
	// contradicting the sentence beside it.
	return !sc.reflects
}

// sstiControlsEarned is the second place the five negative controls are requested from, and the
// only one that does not need a hit first.
//
// THE SLOT IT SELECTS IS THE SLOT ON ITS WAY TO A CLEAN: this class's census probe came back, so
// the computation oracle was AVAILABLE here, and not one of the four oracles fired. That is
// exactly the slot whose silence is about to be reported as the application's, and it is the slot
// where a matcher that cannot fire and a matcher that had nothing to fire on look identical.
func sstiControlsEarned(sc sstiScorecard) bool {
	return sc.reflectMeasure && sc.reflects &&
		sc.computeFamily == "" && sc.consumeFamily == "" &&
		sc.errorSignature == "" && sc.evaluatorProof == "" && sc.distinctEngine == ""
}

// sstiIsNegativeControl names the five.
func sstiIsNegativeControl(id triage.ProbeID) bool {
	switch id {
	case sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4:
		return true
	}
	return false
}

// sstiIsEscalationOnly reports whether a probe is only ever sent after a first hit. It exists so
// the Untested rows say "nothing earned this" rather than "the budget ran out", which are
// different facts an operator will act on differently.
// sstiIsBlindArm names the ten probes of the non-reflective arm. They are in
// sstiIsEscalationOnly's list as well, because they are not part of the base ladder, but they
// need their own Untested sentence and this is what selects them for it.
func sstiIsBlindArm(id triage.ProbeID) bool {
	switch id {
	case sstiBOK1, sstiBER1, sstiBOK2, sstiBER2, sstiBOK3, sstiBER3, sstiBOK4, sstiBER4, sstiBN1, sstiBN2:
		return true
	}
	return false
}

// sstiBlindSkipReason says which of FOUR reasons stopped the arm, because they call for
// different actions: three are correct and cost nothing, and only the fourth is something an
// operator can change.
//
// THE OLD FOURTH BRANCH NAMED THE BUDGET AND IT WAS GUESSING TWICE OVER.
//
// It read "not_sent (budget_before_round_2)" and then restated a measurement from another run as
// though it were this slot's cause. TWO THINGS WERE WRONG WITH THAT. First, it fired whenever
// computeFamily was empty and the slot did not reflect, INCLUDING when this class's census probe
// had no response at all, and on that slot the arm was never requested: sstiBlindArmEarned needs
// reflectMeasure, so the absence is this class's own plan and there is no budget in it. Second,
// even on a slot where the gate WAS met, this class cannot see a budget from here. The same
// three causes sstiUntested's default branch spells out apply: the per-slot cap, a run tier below
// this probe's (ProbeSpec.Tier is enforced by the runner and PlanCtx carries no Tier field, and
// this arm is TierFull only), or a run that ended before the round. The cap is the only one ever
// measured and it is named as the first thing to check, which is a different sentence from
// calling it the cause.
// AND THE THIRD BRANCH WAS NAMING A LATER ROUND'S FACT AS AN EARLIER ROUND'S DECISION.
//
// computeFamily was tested first here too, and it is the one of the three that is not a round 0
// fact: no probe sstiPlanCensus sends can set it (none of those rows carries an expected
// computation or the control flag), so a computed family is always round 1 or later, while the
// gate that decides whether these ten probes are requested is asked in round 1. On a slot where
// the gate was MET, this class asked for all ten in round 1 and a family computing afterwards
// closed only the round 2 retry. "not_sent (stronger_oracle_answered)" said the opposite, and it
// said it in the row an operator reads to decide whether to raise the per-slot cap. The census
// pair goes first because both halves of it are read from S0 in round 0 and therefore say the
// same thing at the gate as they do here.
func sstiBlindSkipReason(sc sstiScorecard) string {
	switch {
	case !sc.reflectMeasure:
		return "not_sent (census_unanswered): the arm's gate needs this class's census probe " + string(sstiS0) +
			" to have answered before this slot can be called non-reflecting, and it has no response here, so " +
			"this class NEVER REQUESTED the arm. Its absence is this class's own plan and says nothing about a " +
			"budget, a tier or the endpoint"
	case sc.reflects:
		return "not_sent (slot_reflects): this arm exists for the slot whose value never comes back. Here the " +
			"census marker DID come back, so the rank 1 computation oracle was available and ten requests of " +
			"tier 6 differential would buy nothing"
	case sc.computeFamily != "":
		return "not_sent (requested_then_superseded): the census answered and its marker did not come back, so " +
			"the gate WAS met and this class requested all ten of these probes in round 1. " +
			string(sc.computeFamily) + " computed on a round 1 or later probe, which declined the round 2 " +
			"RETRY and nothing else. So the arm was asked for and no observation came back, and this class " +
			"cannot see which of three applies: the per-slot probe cap, a run tier below this probe's (the arm " +
			"is full tier only), or a run that ended before the round. CHECK THE CAP FIRST"
	default:
		return "not_sent (requested_and_absent): this arm is earned by the ABSENCE of the rank 1 oracle, not by " +
			"a hit, the gate was met on this slot, so it WAS requested in round 1 and again in round 2, and no " +
			"observation came back. THIS CLASS CANNOT SEE WHICH OF THREE APPLIES: the per-slot probe cap bit " +
			"before the requests left, the run's tier is below this probe's (the arm is full tier only and " +
			"PlanCtx carries no tier), or the run ended before the round. CHECK THE CAP FIRST: against the " +
			"canary oracle at the default per-slot cap of 24 probes, this class's census and battery spend all " +
			"24 in rounds 0 and 1 and the arm's ten requests never leave. On this slot that is a candidate and " +
			"not a finding, and the arm is the one oracle here that answers on a route that echoes nothing"
	}
}

func sstiIsEscalationOnly(id triage.ProbeID) bool {
	switch id {
	case sstiCF1, sstiCF2, sstiCF3, sstiCF4, sstiCF5, sstiCF6, sstiCF7, sstiCF8, sstiCF9, sstiCF11,
		sstiCC1, sstiCC2, sstiZ1, sstiZ2, sstiZ3, sstiZB1, sstiZB2, sstiZB3, sstiZB4,
		sstiBOK1, sstiBER1, sstiBOK2, sstiBER2, sstiBOK3, sstiBER3, sstiBOK4, sstiBER4, sstiBN1, sstiBN2,
		sstiD1, sstiD2, sstiD3, sstiI1, sstiI2, sstiI3, sstiI4, sstiI5, sstiI6,
		sstiEPPython, sstiEPRuby, sstiEPDotnet, sstiEPJava, sstiEPPHP, sstiEPJS, sstiEPGo,
		sstiNC1, sstiNC2, sstiNC3a, sstiNC3b, sstiNC4, sstiF6L:
		return true
	}
	return false
}

func sstiBaseAnnotations(ctx triage.ClassifyCtx, sc sstiScorecard) map[string]any {
	return map[string]any{
		// CARRIED ON EVERY VERDICT, INCLUDING EVERY CLEAN. An engine configured with custom
		// delimiters (Handlebars rewritten, Twig with only {% %}, a Mustache switched by
		// {{=<% %>=}}) is invisible to a fixed battery, and the gap belongs in the report rather
		// than inside a green tick.
		"custom_delimiters_untested": true,
		// Likewise: this class reads one response to one request and does not crawl, so a value
		// stored now and rendered on another page later is out of reach. The markers are recorded
		// so a later crawl can find them.
		"second_request_rendering_untested": true,
		"decode_depth":                      sc.decodeDepth,
		// WHAT HAPPENED TO SSTI-S2'S OWN BYTES, carried on every row including every clean. It
		// used to be a suspicious verdict of its own; it is evidence, and evidence belongs here.
		"polyglot_return": string(sc.polyglot),
		"slot_kind":       string(ctx.Slot.Kind),
		"reflects":        sc.reflects,
	}
}

func sstiJoinIDs(ids []triage.ProbeID) string {
	s := make([]string, 0, len(ids))
	for _, id := range ids {
		s = append(s, string(id))
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}

// ---------------------------------------------------------------------------------------------
// 10. THE LABEL. WHICH TOOL, AND WHICH PLUGIN
// ---------------------------------------------------------------------------------------------

// sstiPlugin maps an identified engine to sstimap's plugin name. An engine that is absent from
// this map has NO sstimap plugin, and the label says tinja plus manual rather than pointing the
// operator at a tool that has nothing for the engine. Telling somebody to run sstimap against a Go
// template is telling them to spend time for a guaranteed nothing.
var sstiPlugin = map[string]string{
	"Jinja2": "jinja2", "Tornado": "tornado", "Mako": "mako", "Cheetah3": "cheetah",
	"Twig": "twig", "Smarty": "smarty", "FreeMarker": "freemarker", "Velocity": "velocity",
	"ERB": "erb", "Slim": "slim", "EJS": "ejs", "Nunjucks": "nunjucks", "Pug": "pug",
	"doT": "dot", "VelocityJS": "velocity_js",
}

// sstiFamilyEngines is step A of identification: the candidate set the delimiter alone establishes.
var sstiFamilyEngines = map[triage.ProbeID][]string{
	sstiF1:   {"FreeMarker", "Groovy templates", "Mako", "Chameleon", "Thymeleaf (attribute)"},
	sstiF2:   {"Jinja2", "Tornado", "Twig", "TwigJS", "Nunjucks", "Pebble", "Jinjava", "Blade", "Scriban", "Fluid"},
	sstiF3:   {"ERB", "Erubi", "Erubis", "EJS", "Underscore", "Eta", "ASP", "Mojolicious", "EEx"},
	sstiF4:   {"Pug", "Slim", "Haml", "FreeMarker (legacy)"},
	sstiF5:   {"Razor", "RazorEngine"},
	sstiF6:   {"Smarty", "Latte", "patTemplate"},
	sstiF6L:  {"Latte"},
	sstiF7:   {"Thymeleaf (inline)"},
	sstiF8:   {"Velocity", "VelocityJS"},
	sstiF9:   {"Liquid", "DotLiquid", "Scriban (Liquid mode)"},
	sstiF9c:  {"Liquid", "DotLiquid"},
	sstiF10:  {"Django"},
	sstiF10w: {"Django"},
	sstiF11:  {"Go text/template", "Go html/template"},
	sstiC1:   {"Mustache", "Handlebars", "Pystache", "MustacheJS", "HoganJS"},
}

func sstiLabel(sc sstiScorecard) triage.TriageLabel {
	engine := sc.distinctEngine
	if engine == "" {
		engine = sc.errorEngine
	}
	candidates := sstiFamilyEngines[sc.computeFamily]
	if len(candidates) == 0 {
		candidates = sstiFamilyEngines[sc.consumeFamily]
	}
	if engine == "" && len(candidates) == 1 {
		engine = candidates[0]
	}

	hints := map[string]string{
		"family":   string(sc.computeFamily),
		"language": sc.errorLanguage,
	}
	if sc.consumeFamily != "" {
		hints["consumption_family"] = string(sc.consumeFamily)
	}
	if len(candidates) > 0 {
		hints["candidates"] = strings.Join(candidates, ", ")
	}
	if sc.evaluatorProof != "" {
		hints["evaluator_proved_by"] = sc.evaluatorProof
	}

	tools := []string{"sstimap", "tinja"}
	if p, ok := sstiPlugin[engine]; ok {
		hints["sstimap_engine"] = p
	} else if engine != "" {
		// Named honestly rather than left to be discovered by a wasted tool run.
		hints["sstimap_engine"] = ""
		hints["no_sstimap_plugin"] = engine
		tools = []string{"tinja"}
	}
	return triage.TriageLabel{Tools: tools, Engine: engine, Dialect: sc.errorLanguage, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// 11. CONFIRMERS, EVIDENCERS AND ORACLE CASES
// ---------------------------------------------------------------------------------------------

// These three are declarative descriptions of the class rather than parts of triage.Classifier,
// which today is ID, Probes, Reaches, Plan and Classify. They are typed with sstiClassifier's own
// types so they can be added to the interface later without any other class having to agree on a
// shape first, and so that this file's tests can assert over them now.
//
// There is deliberately no Settle: this class has NO out-of-band oracle. A template engine that
// reaches the network is an exploitation step and not a triage one, and the callback oracles
// belong to CMDI and SSRF. Nothing here needs a deferred check, so nothing here declares one.

// sstiConfirmation pairs a probe that can fire with the probes that must reproduce the effect
// before CATALOGUE 4.2 allows the verdict to grade high.
type sstiConfirmation struct {
	First     triage.ProbeID
	Confirm   []triage.ProbeID
	Confirms  string
	Downgrade string
}

func (sstiClassifier) Confirmers() []sstiConfirmation {
	out := make([]sstiConfirmation, 0, len(sstiConfirmFor))
	for first, conf := range sstiConfirmFor {
		c := sstiConfirmation{
			First:     first,
			Confirm:   conf,
			Confirms:  "the new expected answer adjacent to the NEW marker",
			Downgrade: "the old answer, or no answer: a cached page, which downgrades to cannot_determine (stale_marker)",
		}
		if first == sstiC1 {
			c.Confirms = "the inner block is consumed too, which is what distinguishes a parser from a brace stripper"
			c.Downgrade = "the inner literal x survives with the braces gone: a stripper, cannot_determine (stripper)"
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].First < out[j].First })
	return out
}

// sstiEvidencer is one of this class's four oracles, with the rule that recognises it and the
// grade it can reach.
type sstiEvidencer struct {
	Oracle   string
	Rank     int
	Rule     string
	MaxGrade triage.TriageGrade
	Probes   []triage.ProbeID
	Why      string
}

func (sstiClassifier) Evidencers() []sstiEvidencer {
	return []sstiEvidencer{
		{
			Oracle: "computation", Rank: 1, MaxGrade: triage.GradeHigh,
			Rule: "the marker, then at most 8 whitespace bytes, then the expected product in any single " +
				"consistent digit grouping, with answer_not_in_wire asserted and the answer absent from the " +
				"route control",
			Probes: []triage.ProbeID{sstiF1, sstiF2, sstiF3, sstiF4, sstiF5, sstiF6, sstiF6L, sstiF7, sstiF8, sstiF9, sstiF9c, sstiF10, sstiF10w, sstiF11},
			Why:    "the application had to EVALUATE to produce the answer, so there is no interpretation step between the observation and the conclusion",
		},
		{
			Oracle: "consumption", Rank: 7, MaxGrade: triage.GradeMedium,
			Rule:   "M1 immediately followed by M3, with M2 absent in every transform form and both markers passing their checksums",
			Probes: []triage.ProbeID{sstiC1, sstiC2, sstiC3, sstiC4, sstiC5},
			Why:    "the only oracle a logic-less engine has, and without it Mustache, Handlebars, Pystache, MustacheJS and HoganJS are all recorded clean by construction",
		},
		{
			Oracle: "error_signature", Rank: 4, MaxGrade: triage.GradeMedium,
			Rule:   "a signature from THIS class's catalogue, present in the probe response and absent from the route control",
			Probes: []triage.ProbeID{sstiS1, sstiS1q, sstiS1s, sstiS1b, sstiZ1, sstiZ2, sstiZ3, sstiZB1, sstiZB2, sstiZB3, sstiZB4},
			Why:    "it survives a sink that never reflects, which is the whole blind-template case, and the division triple upgrades it from parser to evaluator. The ZB forms add the engines that TOLERATE division by zero (JavaScript Infinity, PHP 7 INF) and only raise on the attribute access behind it",
		},
		{
			// THE WEAKEST ORACLE HERE AND THE ONLY ONE THAT ANSWERS ON A JSON API.
			Oracle: "boolean_differential", Rank: 6, MaxGrade: triage.GradeLow,
			Rule: "both valid-versus-invalid pairs of ONE delimiter family separate the response, in the same " +
				"direction, on an endpoint whose stability gate passed, whose two inert length controls stayed " +
				"together, and whose two syntax-error payloads came back in the same status class. The members " +
				"of each pair are byte-length-equal, so the separation cannot be an echo",
			Probes: []triage.ProbeID{sstiBOK1, sstiBER1, sstiBOK2, sstiBER2, sstiBOK3, sstiBER3, sstiBOK4, sstiBER4},
			Why: "every other oracle in this class waits for its own value to come back, and on an API that " +
				"echoes nothing it never does. This one asks whether the response MOVED between an expression " +
				"that parses and one that does not, which is a question such a route can still answer. It is " +
				"capped at low and can never produce a clean or a finding: it proves a parser, not an " +
				"evaluation, and the oracle that would tell those apart is the one that was blind here",
		},
		{
			Oracle: "distinctive_content", Rank: 3, MaxGrade: triage.GradeMedium,
			Rule:   "a value only one engine produces, adjacent to the marker and absent from the route control",
			Probes: []triage.ProbeID{sstiD1, sstiD2, sstiD3},
			Why:    "it names the engine, and the engine is what decides whether sstimap has a plugin at all",
		},
	}
}

// sstiOracleCase is one route the oracle container must serve, and what this class must do
// against it.
//
// THE SILENT ROUTES ARE THE ONES THAT ACTUALLY TEST THE DETECTOR. A detector that always says yes
// passes every verification that only counts hits. Note especially the six negative cases against
// /ssti itself: the existing route emulates FREEMARKER AND NOTHING ELSE, so F2, F3, F5, F9, F10 and
// F11 must stay silent against it. A test suite that expects the whole battery to fire there has
// misunderstood the oracle, and it will be "fixed" by loosening the detectors.
type sstiOracleCase struct {
	Name   string
	Route  string
	Probe  triage.ProbeID
	Expect string // "positive" or "negative"
	Exists bool
	Why    string
}

func (sstiClassifier) OracleCases() []sstiOracleCase {
	return []sstiOracleCase{
		{"freemarker_computation", "/ssti?tpl=", sstiF1, "positive", true,
			"the shipped route emulates FreeMarker: integers and + - * inside ${...}. F1 must fire and the verdict must be a finding"},
		{"freemarker_error", "/ssti?tpl=", sstiS1, "positive", true,
			"the same route answers anything outside its grammar with a verbose FreeMarker-style 500, so the ftl.template signature must fire"},
		{"freemarker_ungrouped", "/ssti?tpl=", sstiD3, "positive", true,
			"D3 must return an UNGROUPED 1571273, which is the identification finisher for FreeMarker and the answer to the locale grouping problem"},

		{"wrong_engine_jinja", "/ssti?tpl=", sstiF2, "negative", true,
			"the route is FreeMarker only. If the brace-brace family fires here the detector is a generic did-the-page-change test"},
		{"wrong_engine_erb", "/ssti?tpl=", sstiF3, "negative", true, "as above, for the scriptlet family"},
		{"wrong_engine_razor", "/ssti?tpl=", sstiF5, "negative", true, "as above, for Razor"},
		{"wrong_engine_liquid", "/ssti?tpl=", sstiF9, "negative", true, "as above, for Liquid"},
		{"wrong_engine_django", "/ssti?tpl=", sstiF10, "negative", true, "as above, for Django"},
		{"wrong_engine_go", "/ssti?tpl=", sstiF11, "negative", true, "as above, for Go templates"},

		{"reflection_is_not_injection", "/clean/echo", sstiF1, "negative", true,
			"the route reflects the input and has no template, no database, no shell and no parser. Every family must stay " +
				"silent and the verdict must be clean with its ordinals. MEASURED 2026-09-19 on the 80-route canary exam: " +
				"clean, 29 ordinals, with all five negative controls below ANSWERED and silent. It was cannot_determine " +
				"(unattributed_error) the round before, because the echo of this class's own payload moved the body away " +
				"from the route control and ruling R1 read that as unexplained"},
		{"answer_in_wire_guard", "/clean/echo", sstiNC2, "negative", true,
			"NC2 SENDS 1571273 adjacent to the marker, so the regex will match and the answer_not_in_wire guard must suppress it. This verifies the guard rather than the regex"},
		{"inert_echo", "/clean/echo", sstiNC1, "negative", true,
			"the delimiters are replaced by letter pairs and the operator by mul, so nothing computes. A fire here means the matcher is finding the answer unanchored"},
		{"empty_expression", "/clean/echo", sstiNC3a, "negative", true,
			"valid delimiters, no expression: neither COMPUTATION nor CONSUMPTION may fire"},
		{"three_markers_no_delimiters", "/clean/echo", sstiNC4, "negative", true,
			"M1 and M3 are not adjacent and M2 is present, so CONSUMPTION must stay silent. This catches the matcher that only checks both markers are present"},

		{"uniform_block", "/clean/waf", sstiS1, "negative", true,
			"an identical 403 to every payload: this class must reach uniform_block on its own THIRD distinct payload and record cannot_determine (blocked), not clean"},
		{"five_hundred_is_not_a_finding", "/clean/always500", sstiS1, "negative", true,
			"a 500 for every input including a benign one. The error oracle is baseline-differenced, so nothing may fire"},
		{"no_body", "/clean/empty204", sstiF1, "negative", true,
			"204 with no body on baseline and probe: the answer is cannot_determine (no_body), never identical-bodies-therefore-same"},
		{"drift", "/clean/drift", sstiF1, "negative", true,
			"the route serves version A then version B: the post-baseline must turn the error oracle into cannot_determine (drift)"},

		// -- routes that DO NOT EXIST and that this class needs built -----------------------
		{"jinja_computation", "/ssti/jinja2", sstiF2, "positive", false,
			"MISSING. A real Jinja2 render of the parameter. Today the brace-brace family, which reaches fourteen engines, has NO positive control at all: it has only ever been observed staying silent, which is exactly as unverified as only ever being observed firing"},
		{"jinja_identification", "/ssti/jinja2", sstiI1, "positive", false,
			"MISSING. {{1in[1]}} must return True against Jinja2, which is step C of identification and the probe that splits the whole brace-brace candidate set"},
		{"mustache_consumption", "/ssti/mustache", sstiC1, "positive", false,
			"MISSING, and it is the most important gap. The consumption oracle is the ONLY oracle that reaches the logic-less family, and it has never been run against a logic-less engine. Its payload also needs the three-marker substitution, so this route is what proves the runner's Variant contract works at all"},
		{"mustache_parser_not_stripper", "/ssti/mustache", sstiCC1, "positive", false,
			"MISSING. The section form must be consumed WITH its inner literal, which is what separates a parser from a stripper"},
		{"brace_stripper", "/ssti/stripper", sstiC1, "negative", false,
			"MISSING. A route that deletes { } < > from the value and echoes the rest. It produces M1M2M3, CONSUMPTION must stay silent, and the verdict must be cannot_determine (stripper) rather than a finding"},
		{"go_len_chain", "/ssti/gotemplate", sstiF11, "positive", false,
			"MISSING. Go's templates are the one engine family whose computation probe is not arithmetic at all, and the six-len construction has never been run against a real Go template"},
		{"go_html_escapes", "/ssti/gotemplate?pkg=html", sstiI4, "positive", false,
			"MISSING. html/template must return &lt;b&gt; where text/template returns <b>, and the two are materially different findings"},
		{"velocity_set", "/ssti/velocity", sstiF8, "positive", false,
			"MISSING. Velocity has no bare expression form, so F8 is the ONLY probe in this class that reaches it and it has never fired against Velocity"},
		{"liquid_times", "/ssti/liquid", sstiF9, "positive", false,
			"MISSING. Liquid has no infix arithmetic, so a silent F2 against Liquid is indistinguishable from a non-reflecting slot without this route"},
		{"django_add", "/ssti/django", sstiF10, "positive", false,
			"MISSING. Also the only route that exercises the six-digit operand rule, which exists solely because add is a sum"},
		{"smarty_version", "/ssti/smarty", sstiD1, "positive", false,
			"MISSING. The distinctive-content oracle has no positive control of any kind today"},
		{"freemarker_grouped_locale", "/ssti?tpl=&locale=en_US", sstiF1, "positive", false,
			"MISSING, and it is cheap: the same FreeMarker route rendering 1,571,273 with the locale's group separators. The grouping tolerance is the single line that decides whether the most common Java engine is found or recorded clean, and it has never been exercised end to end"},
		{"template_exception_swallowed", "/ssti/catchall", sstiS2, "positive", false,
			"MISSING, AND ITS ABSENCE IS WHY THE POLYGLOT ARM WAS RETIRED AS A POINTER. An application that catches every " +
				"template exception and renders a generic page: S2 is the designed answer to it and every error-shaped " +
				"oracle is blind there. Until this route exists, S2 has never once been observed firing on a template " +
				"engine, and on the 80-route exam its byte comparison fired on 29 routes of which 21 were an HTML escaper, " +
				"2 a JSON string, 1 an undecoded percent value, 3 a field that cut the value and 2 a brace-stripping " +
				"regexp. So S2's outcome is now evidence (polyglot_return) and a REFUSAL when it diverges, never a " +
				"suspicious row. The shape this route stands for is meanwhile covered by the blind boolean differential, " +
				"which does have a positive control at /ssti/blind. If this route is ever built, the right change is to " +
				"let a DIVERGED polyglot escalate again on evidence this route provides, not to restore the old rung"},
		{"blind_sink", "/ssti/blind", sstiS1, "positive", true,
			"A route that templates the value into something the response never shows. The computation verdict must be cannot_determine (no_reflection) and the error oracle must still fire, which is the only way the blind branch is ever tested"},
		{"custom_delimiters", "/ssti/customdelim", sstiF2, "negative", false,
			"MISSING. An engine configured with delimiters this battery does not send. The verdict may be clean, and the custom_delimiters_untested annotation must be on it, which is the only place that gap becomes visible"},
		// -- the blind arm ------------------------------------------------------------------
		{"blind_arm_stays_silent_on_a_route_with_no_engine", "/clean/echo", sstiBOK3, "negative", true,
			"the route reflects the value and evaluates nothing. Both members of every pair are the same " +
				"length, so an echo returns two identical lengths and the arm must come back " +
				"blind_arm_ran_and_was_silent. A fire here means the arm is a did-the-page-change detector"},
		{"blind_arm_is_disabled_by_its_own_length_control", "/clean/echo", sstiBN1, "negative", true,
			"BN1 and BN2 are inert plain text six bytes apart on a route that echoes. Whether the arm reports " +
				"length_sensitive_endpoint or simply stays silent, what it may NOT do is fire, and this is the " +
				"only route in the set where the control has anything to catch"},
		{"blind_arm_on_a_uniform_block", "/clean/waf", sstiBER3, "negative", true,
			"an identical 403 to everything: every pair collapses and the arm must be silent, with the verdict " +
				"coming from the blocked rung above it"},
		{"blind_arm_positive", "/ssti/blind", sstiBOK3, "positive", true,
			"THE ONE ROUTE THIS ARM NEEDS, and it now exists: the route templates the value into something the " +
				"response never shows and answers 500 to a template that raises. MEASURED 2026-09-19, and it " +
				"is why this line no longer reads MISSING in one direction and does in another: for a whole " +
				"round the route existed and the verdict here was cannot_determine (blocked), because every " +
				"syntax-error payload shares one body, faUniformBlock read that as a filter, and round 1 " +
				"returning nil retired the class before the arm was planned. The arm is now observed FIRING " +
				"here (suspicious, boolean_differential brace_brace) and staying silent on /clean/echo and " +
				"/clean/waf, which is the pair of observations that makes it verified rather than declared"},
		{"blind_arm_on_a_length_sensitive_route", "/ssti/lengthecho", sstiBN1, "negative", true,
			"A route whose response length tracks its input length and which runs NO engine. The arm must " +
				"disable itself on BN1/BN2 rather than fire on all four pairs, and that is the single " +
				"false-positive mode this arm has. MEASURED 2026-09-19: the verdict here is cannot_determine " +
				"and the arm did not fire, but the rung that produced it is the uniform-block one rather than " +
				"the length control, so the control itself is still only exercised in ssti_test.go"},

		{"server_rendered_brace_brace", "/csti/jinja", sstiF2, "positive", true,
			"THE DECLARATION WAS WRONG IN BOTH ITS FIELDS AND THE CLASS WAS RIGHT. It read exists:false and " +
				"expect:negative, on the stated ground that the route returns \"{{1721*913}} verbatim\" so a fire here " +
				"would be a fabricated client-side claim. The route exists, and the handler settles what it does: " +
				"cstiJinjaHandler runs reCSTIMustache over the parameter and REPLACES {{a*b}} with the product before " +
				"the response is written. The response therefore carries 1571273 and not the payload, which is a " +
				"SERVER-side template evaluation and is precisely this class's rank 1 oracle. MEASURED 2026-09-19 on " +
				"the 80-route canary exam: suspicious, computation SSTI-F2, grade medium, because the fresh-marker " +
				"confirmation had not reproduced it. CSTI's owed verdict on the same route is cannot_determine " +
				"(server_side_evaluation) with the hand-off to this class, and the two answers are the same reading of " +
				"the same page: the engine is on the server. Carrying it here as a NEGATIVE charged this class with a " +
				"false positive for doing the one thing it exists to do",
		},
	}
}

// RunnerPlacesMarkers opts this class in to runner-placed markers.
//
// The probe table above is written for it and says so: "The marker is NOT written into these
// bytes. MarkerPos is prefix on everything, so the runner prepends this probe's own minted
// marker." Without the opt-in the census probe SSTI-S0 reaches the wire carrying no marker, the
// reflection search looks for bytes that were never in the request, and the class reports
// census_marker_not_sent on every slot. Measured on a live run: 63 slots, no conclusion possible.
//
// WHY THE OPT-IN EXISTS AT ALL, and why this class is a legitimate member rather than a default:
// marker injection used to be unconditional and it broke three classes that need their payload
// bytes untouched. LFI-L7's oracle is that the plaintext marker is ABSENT from the request, only
// its base64 is sent. ELI-EL6 is a bare expression a 16-byte prefix turns into a parse error. So
// the runner now places a marker only for a class that asks.
//
// THIS CLASS DECLARES PREFIX, NOT INLINE, which is the distinction that makes it safe. The
// polyglot probes measure whether their own bytes come back rewritten; a marker PREPENDED leaves
// those bytes contiguous and intact, where an INLINE marker inserted among them would not. If a
// future probe here needs to go out bare, it sets Variant["marker_placement"]="omitted", which
// the runner honours ahead of MarkerPos.
func (sstiClassifier) RunnerPlacesMarkers() bool { return true }
