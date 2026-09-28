package triageclasses

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS DESER (id 24). INSECURE DESERIALIZATION: a slot's value reaches a deserializer.
//
// THIS IS THE ONLY CLASS IN THIS ROUND WHOSE PRIMARY ORACLES ARE RANK 1, DETERMINISTIC
// COMPUTATION, and every one of them was executed on this machine rather than read about. The
// output is quoted in the probe notes below, because a deserialization signature table assembled
// from memory is the exact shape of a detector that matches nothing and reports clean.
//
//	php:8.3-cli-alpine, unserialize()
//	  "zqdeser-p2a-not-serialized-probe-padpad"  ->  Error at offset 0 of 39 bytes
//	  "zqdeser-p2b-not-serialized-probe"         ->  Error at offset 0 of 32 bytes
//	  "zqdeser-plain-control-not-a-payload"      ->  Error at offset 0 of 35 bytes
//	  O:22:"zqcls_<16-byte marker>":0:{}         ->  __PHP_Incomplete_Class,
//	                                                 {"__PHP_Incomplete_Class_Name":"zqcls_<marker>"}
//	JDK 25.0.2, new ObjectInputStream(...).readObject()
//	  base64 rO0SNHQAAmhp  ->  StreamCorruptedException: invalid stream header: ACED1234
//	  base64 rO1aa3QAAmhp  ->  StreamCorruptedException: invalid stream header: ACED5A6B
//	CPython 3.13.12, pickle.loads
//	  base64 gASVGwAAAAAAAABdlCiMCHpxZGVzZXJ5lIwIMXBpY2tsM3qUZS4=  ->  ['zqdesery', '1pickl3z']
//	  base64 gASVBQAAAAAAAABacXJzLg==                              ->  invalid load key, 'Z'.
//
// =================================================================================================
// WHY EACH OF THOSE IS RANK 1 AND NOT RANK 4, WHICH IS THE WHOLE ARGUMENT
// =================================================================================================
// An ERROR SIGNATURE is rank 4 and needs baseline differencing, because a page that always carries
// the string makes a naive matcher fire on everything. Three of the four oracles here are not
// error signatures even though two of them arrive inside error text, and the distinction is that
// THE RESPONSE CONTAINS A VALUE THE APPLICATION HAD TO COMPUTE FROM OUR INPUT:
//
//	DES-P2   the number 39 is the LENGTH OF WHAT WE SENT, counted by PHP. Send two probes of
//	         different lengths and each must name its own. Two static pages cannot do that, and
//	         the pair is therefore its own discriminator in one extra request. This is
//	         7919*6271=49660049 in a different suit.
//	DES-P1   the 22 bytes __PHP_Incomplete_Class and the 27 bytes __PHP_Incomplete_Class_Name are
//	         NOT IN THE REQUEST. Only PHP's unserialize machinery emits them, and only in response
//	         to a serialized object naming a class the process does not have.
//	DES-J1   we send four raw bytes and the JVM sends back the eight ASCII characters ACED1234.
//	         That string is in neither the raw payload nor its base64 text. VERIFIED both ways.
//	DES-Y1   the request carries two eight-byte halves separated by pickle opcodes and the base64
//	         of all of it. The response carries ['zqdesery', '1pickl3z'], brackets, quotes and a
//	         comma-space, which is Python's repr and which appears in neither form of the request.
//	         VERIFIED both ways.
//
// So no reflection can produce any of them, which is what rank 1 means. They are still
// baseline-differenced, because a security-training page or a framework documentation page can
// carry any string at all, and a check that costs nothing is a check worth keeping.
//
// =================================================================================================
// THE TRAP IN THIS CLASS'S OWN CONTROL, AND IT IS WRITTEN HERE BECAUSE IT IS COUNTERINTUITIVE
// =================================================================================================
// DES-NC1 is the transformation control: an ordinary string that must produce no
// __PHP_Incomplete_Class, no invalid stream header, no pickle repr and no load-key echo. It is NOT
// and CANNOT BE the control for DES-P2, and the measurement above is why:
//
//	"zqdeser-plain-control-not-a-payload"  ->  Error at offset 0 of 35 bytes
//
// Every non-serialized string fires the length oracle on an unserialize() sink. That is the POINT
// of the length oracle, not a flaw in it, and a class that used NC1 as P2's control would silence
// its own strongest probe on every target where it works. DES-P2's control is the a/b length pair
// and nothing else, and NC1 is a THIRD point on the same line, which is why its silence is checked
// for four oracles and its number is read for the fifth.
//
// =================================================================================================
// NON-DESTRUCTIVE BY CONSTRUCTION, PER PAYLOAD
// =================================================================================================
//	DES-P2A/B/NC1  are ordinary strings. There is nothing in them to execute.
//	DES-P1         names a class the process does not have. PHP resolves nothing, constructs
//	               nothing and runs no magic method; __wakeup does not fire on an incomplete class,
//	               and 0:{} declares zero properties.
//	DES-J1/J2      fail in readStreamHeader, which runs BEFORE the first class name is read. There
//	               is no gadget surface reachable from a bad magic number.
//	DES-Y1         contains EMPTY_LIST, two SHORT_BINUNICODE, MEMOIZE, APPENDS and STOP, and no
//	               GLOBAL and no REDUCE. It builds a list of two strings. Disassembled with
//	               pickletools to confirm exactly that.
//	DES-Y2         is eleven bytes of framing and a bad opcode.
//
// NO GADGET CHAIN IS SHIPPED AND NONE EVER WILL BE FROM HERE. ysoserial, phpggc, marshalsec and
// ysoserial.net all end their chains in a command, which is exploitation and is destructive by
// definition. Triage's job is to say "an ObjectInputStream is on the other end of this slot", and
// DES-J1 does that for zero risk.
//
// =================================================================================================
// THE HONEST WEAKNESS: THERE IS NO TOOL TO POINT AT
// =================================================================================================
// None of the four gadget tools is a container in this framework. The pointer this class produces
// is a human instruction plus the recovered format name and, where DES-R0 matched, the format the
// slot already carries. That is worth having and it is worth saying plainly that it is not a next
// command. A pointer with no tool still beats a slot nobody looked at.

type deserClassifier struct{}

func init() { triage.RegisterClassifier(deserClassifier{}) }

func (deserClassifier) ID() triage.ClassID { return triage.ClassDeser }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	desP2A triage.ProbeID = "DES-P2A"
	desP2B triage.ProbeID = "DES-P2B"
	desNC1 triage.ProbeID = "DES-NC1"
	desP1  triage.ProbeID = "DES-P1"
	desJ1  triage.ProbeID = "DES-J1"
	desJ2  triage.ProbeID = "DES-J2"
	desY1  triage.ProbeID = "DES-Y1"
	desY2  triage.ProbeID = "DES-Y2"
)

// The three length-arithmetic strings, and their lengths are load-bearing rather than incidental.
//
// EVERY BYTE IS [a-z0-9-], WHICH IS DELIBERATE. No encoder in this layer escapes any of those
// characters in a query value, a form field, a JSON string, a path segment, a cookie or a header
// value, so the bytes the application decodes are byte-for-byte the bytes declared here and the
// number PHP counts is the number in this file. A payload with a space or a slash in it would be
// percent-encoded on the way out, decoded on the way in, and the two lengths would agree anyway,
// but only by an argument rather than by inspection. The verdict still compares against the
// RECORDED payload rather than against these constants, because a WAF that strips a byte changes
// the count and a class comparing to a literal would read that as a miss.
const (
	desP2AText = "zqdeser-p2a-not-serialized-probe-padpad" // 39 bytes, VERIFIED
	desP2BText = "zqdeser-p2b-not-serialized-probe"        // 32 bytes, VERIFIED
	desNC1Text = "zqdeser-plain-control-not-a-payload"     // 35 bytes, VERIFIED
)

// The Java stream headers, as base64 of AC ED <two chosen bytes> 74 00 02 68 69, and the eight
// ASCII characters the JVM is then measured to echo. Neither echo string appears in its own
// payload, in either the raw or the base64 form: VERIFIED.
const (
	desJ1Text = "rO0SNHQAAmhp"
	desJ1Echo = "ACED1234"
	desJ2Text = "rO1aa3QAAmhp"
	desJ2Echo = "ACED5A6B"
)

// The pickle payload and the repr its round trip produces. The two halves are eight bytes each and
// are separated in the raw pickle by a MEMOIZE and a SHORT_BINUNICODE opcode, so the joined form
// below exists nowhere in the request. VERIFIED both ways with pickletools.
const (
	desY1Text = "gASVGwAAAAAAAABdlCiMCHpxZGVzZXJ5lIwIMXBpY2tsM3qUZS4="
	desY1Repr = "['zqdesery', '1pickl3z']"
	desY2Text = "gASVBQAAAAAAAABacXJzLg=="
	desY2Echo = "invalid load key, 'Z'."
)

// desClassPrefix is what DES-P1's serialized object names its class.
//
// THE LENGTH IN THE PAYLOAD IS ARITHMETIC AND MUST NOT BE EDITED CASUALLY. PHP's format is
// O:<name length>:"<name>":<property count>:{}, so the 22 is the length of the rendered class
// name: six bytes of prefix plus the sixteen bytes of this run's marker. The declared payload
// spells triage.MarkerPlaceholder, which is eight characters, and the runner substitutes the real
// sixteen-byte marker before the encoder sees it, so the number is correct on the wire and wrong
// in the source. Changing the prefix without changing the 22 produces a payload PHP rejects at the
// length check, which fires DES-P2's oracle instead of DES-P1's and looks like a working probe.
const desClassPrefix = "zqcls_"

func (deserClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassDeser
	m := triage.MarkerPlaceholder
	pts := []triage.SlotKind{
		triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie, triage.KindHeader,
	}
	enc := []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodePathSegment,
		triage.EncodeCookie, triage.EncodeHeaderValue,
	}
	return []triage.ProbeSpec{
		{
			ID: desP2A, Class: c, Logical: []byte(desP2AText),
			Encoders: enc, Points: pts, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the long arm of the length pair, 39 bytes. VERIFIED on php:8.3-cli-alpine: " +
				"unserialize() answers 'Error at offset 0 of 39 bytes', which is a number PHP computed from " +
				"what we sent. IT CARRIES NO MARKER ON PURPOSE. A marker would add sixteen bytes to the " +
				"length, which is harmless, but the runner places a marker only for a class that opts in " +
				"or a payload that spells one, and this class does neither, so the length on the wire is " +
				"the length in this file. Attribution is by probe ordinal, the same exemption SQL's " +
				"arithmetic probes use for the same reason: the oracle is a computation and there is " +
				"nowhere in it a token can ride",
		},
		{
			ID: desP2B, Class: c, Logical: []byte(desP2BText),
			Encoders: enc, Points: pts, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the short arm, 32 bytes, VERIFIED to produce 'of 32 bytes'. THE PAIR IS ITS OWN " +
				"NEGATIVE CONTROL and that is the reason it is two probes rather than one. If both " +
				"responses name the same number, the string is static page text and not a computation, and " +
				"the verdict is cannot_determine rather than a finding. A detector that can only ever fire " +
				"is not a detector, and this one can be shown to discriminate for the price of one request",
		},
		{
			ID: desNC1, Class: c, Logical: []byte(desNC1Text),
			Encoders: enc, Points: pts, Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THE TRANSFORMATION CONTROL, AND READ THE FILE HEADER BEFORE ASSUMING WHAT IT CONTROLS. " +
				"It must produce no __PHP_Incomplete_Class, no invalid stream header, no pickle repr and no " +
				"load-key echo; any of those on an ordinary string means that detector is matching page " +
				"text and every verdict on the slot becomes detector_unverified. IT IS NOT DES-P2'S " +
				"CONTROL: it is 35 bytes and VERIFIED to produce 'of 35 bytes' on an unserialize sink, " +
				"because every non-serialized string does. Its number is read as a THIRD POINT on the " +
				"length line, and three independent lengths each naming themselves is as close to " +
				"certainty as this layer gets",
		},
		{
			ID: desP1, Class: c, Logical: []byte(`O:22:"` + desClassPrefix + m + `":0:{}`),
			Encoders: enc, Points: pts, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "a PHP serialized object naming a class the process does not have. VERIFIED: PHP " +
				"returns an object of type __PHP_Incomplete_Class whose __PHP_Incomplete_Class_Name " +
				"property holds our class name, and both of those strings are absent from the request, so " +
				"an echo cannot produce either. It is planned only after DES-P2 has established that an " +
				"unserialize sink is actually there, because on a slot with no such sink it is 26 bytes of " +
				"noise. Non-destructive: an unknown class resolves nothing, constructs nothing, and " +
				"__wakeup does not fire on an incomplete class",
		},
		{
			ID: desJ1, Class: c, Logical: []byte(desJ1Text),
			Encoders: enc, Points: pts, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "base64 of AC ED 12 34 74 00 02 68 69. VERIFIED on JDK 25.0.2: the JVM answers " +
				"'invalid stream header: ACED1234', hex-formatting the four bytes we chose into eight ASCII " +
				"characters that are in neither the raw payload nor its base64 text. It fails inside " +
				"readStreamHeader, before any class name is read, so there is no gadget surface at all: " +
				"this is the safest possible way to prove an ObjectInputStream is on the other end of a slot",
		},
		{
			ID: desJ2, Class: c, Logical: []byte(desJ2Text),
			Encoders: enc, Points: pts, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "the same with 5A 6B in place of 12 34, VERIFIED to echo ACED5A6B. IT IS THE JAVA ARM'S " +
				"DISCRIMINATOR, exactly as DES-P2B is the PHP arm's: two probes whose only difference is two " +
				"chosen bytes, each of which must name its OWN eight characters. A page that carries the " +
				"words 'invalid stream header' in a documentation example gives both responses the same hex " +
				"and the verdict is cannot_determine",
		},
		{
			ID: desY1, Class: c, Logical: []byte(desY1Text),
			Encoders: enc, Points: pts, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "base64 of a protocol-4 pickle of a two-element list of eight-byte strings. VERIFIED on " +
				"CPython 3.13.12: it loads to ['zqdesery', '1pickl3z'], and the JOINED repr, with its " +
				"brackets, quotes and comma-space, is in neither the raw pickle (the halves are separated " +
				"by opcodes there) nor the base64 text. So a response carrying it had to build a Python " +
				"object and render it. Disassembled with pickletools: EMPTY_LIST, two SHORT_BINUNICODE, " +
				"MEMOIZE, APPENDS, STOP. No GLOBAL and no REDUCE, so nothing is imported and nothing is " +
				"called",
		},
		{
			ID: desY2, Class: c, Logical: []byte(desY2Text),
			Encoders: enc, Points: pts, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "the pickle error arm: framing plus the byte 0x5A, which is not an opcode. VERIFIED to " +
				"produce \"invalid load key, 'Z'.\", echoing the character we chose. It is CORROBORATING " +
				"ONLY and can never carry a verdict alone, because unlike DES-Y1 it ships no second arm " +
				"with a different byte, so nothing here can show it discriminating",
		},
	}
}

func desRound0() []triage.ProbeID {
	return []triage.ProbeID{desP2A, desP2B, desNC1, desJ1, desJ2, desY1, desY2}
}

// desCleanRequires is the set of probes that must ALL have reached the wire before this class is
// allowed to say clean.
//
// IT IS THE WHOLE ARM SET AND NOT THE CHEAP ONES. Each engine has its own oracle here and they
// prove different things: DES-P2 says nothing about a JVM, DES-J1 says nothing about PHP, DES-Y1
// says nothing about either. A run at reduced tier sends only the PHP arm, so on a reduced run
// this class CANNOT reach clean and reports cannot_determine naming the engines it did not test.
// That is the correct answer and it is not a defect: the alternative is a green tick covering two
// runtimes nobody looked at.
func desCleanRequires() []triage.ProbeID {
	return []triage.ProbeID{desP2A, desP2B, desNC1, desJ1, desJ2, desY1}
}

// ---------------------------------------------------------------------------------------------
// DES-R0: THE PASSIVE FORMAT RECOGNITION TABLE. ZERO REQUESTS.
// ---------------------------------------------------------------------------------------------
//
// It reads the slot's OBSERVED value, which the crawl already captured, and says which
// serialization format that value already is. It never produces a verdict on its own: a
// ClassVerdict that asserts anything about the application requires probe ordinals
// (ClassVerdict.Validate refuses a finding, a suspicious or a clean with none), and correctly so,
// because an application round-tripping its own serialized object is not by itself a bug.
//
// What it IS for: the label, so an operator who has no tool to run at least knows which family to
// read up on, and the round-1 ladder, so a slot already carrying a Java blob is worth more probes
// than one carrying an integer.
//
// THE TWO-CHARACTER PREFIXES ARE NEVER BELIEVED ON THEIR OWN. rO, Tz, gASV and BAgK are two to
// four characters of base64 and they collide with ordinary text constantly. Every rule below
// requires the DECODE to match the binary form, or the raw value to match the grammar. And the
// exclusions matter as much as the rules: a JWT, a base64 blob whose decode is valid JSON, a
// base64 blob whose decode is ordinary UTF-8 text, and the two common image magics are all
// refused before anything else is tried.

type desFormat string

const (
	desFormatNone      desFormat = ""
	desFormatJava      desFormat = "java_serialized"
	desFormatPHP       desFormat = "php_serialized"
	desFormatPickle    desFormat = "python_pickle"
	desFormatRuby      desFormat = "ruby_marshal"
	desFormatViewState desFormat = "dotnet_viewstate"
	desFormatBinFmt    desFormat = "dotnet_binaryformatter"
	desFormatNodeSer   desFormat = "node_serialize"
)

// desPHPSerializedRe is the PHP grammar: a type letter, a colon, a count, a colon. It is anchored,
// because O:8: inside a longer string is not a serialized object.
var desPHPSerializedRe = regexp.MustCompile(`^[Oabis]:\d+:`)

// desRecognise names the serialization format of an observed value, or none.
func desRecognise(s triage.Slot) (desFormat, string) {
	v := strings.TrimSpace(s.Value)
	if v == "" {
		return desFormatNone, "the capture recorded no value for this slot, so there is nothing to recognise"
	}
	if strings.Contains(v, "_$$ND_FUNC$$_") {
		return desFormatNodeSer, "the node-serialize function marker is present in the value verbatim"
	}
	if desPHPSerializedRe.MatchString(v) {
		return desFormatPHP, "the value matches PHP's serialized grammar, a type letter and a length, anchored at offset 0"
	}
	if s.Wrapper == triage.WrapJWT || desLooksLikeJWT(v) {
		return desFormatNone, "the value is a JWT, which is three base64url segments and a signature, not a serialized object graph"
	}
	raw, ok := desDecodeBase64(v)
	if !ok || len(raw) < 4 {
		return desFormatNone, "the value is not base64 of anything long enough to carry a serialization header"
	}
	if json.Valid(raw) {
		return desFormatNone, "the value is base64 of valid JSON, which is a data envelope and not an object graph"
	}
	if utf8.Valid(raw) && desMostlyPrintable(raw) {
		return desFormatNone, "the value is base64 of ordinary printable text"
	}
	switch {
	case bytes.HasPrefix(raw, []byte{0xAC, 0xED}):
		return desFormatJava, "the base64 decode begins AC ED, the Java serialization stream magic"
	case bytes.HasPrefix(raw, []byte{0x04, 0x08}):
		return desFormatRuby, "the base64 decode begins 04 08, the Ruby Marshal version bytes"
	case raw[0] == 0x80 && raw[1] >= 0x02 && raw[1] <= 0x05:
		return desFormatPickle, "the base64 decode begins with the pickle PROTO opcode and a protocol number between 2 and 5"
	case bytes.HasPrefix(raw, []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF}):
		return desFormatBinFmt, "the base64 decode begins with the .NET BinaryFormatter serialization header record"
	case bytes.HasPrefix(raw, []byte{0xFF, 0x01}) && desViewStateName(s.Name):
		return desFormatViewState, "the base64 decode begins FF 01 and the slot is named like an ASP.NET view state field"
	case desViewStateName(s.Name):
		return desFormatViewState, "the slot is named like an ASP.NET view state field"
	}
	return desFormatNone, "the base64 decode carries none of the six serialization headers this table knows"
}

func desViewStateName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "__viewstate", "__viewstategenerator", "__eventvalidation":
		return true
	}
	return false
}

// desLooksLikeJWT is the three-segment shape, checked before anything decodes a base64 run,
// because a JWT's header decodes to JSON and its payload usually does too, and a two-character
// prefix test would otherwise class the occasional one as something else.
func desLooksLikeJWT(v string) bool {
	parts := strings.Split(v, ".")
	return len(parts) == 3 && strings.HasPrefix(parts[0], "eyJ") && len(parts[1]) > 0
}

func desDecodeBase64(v string) ([]byte, bool) {
	s := strings.TrimRight(v, "=")
	if n := len(s) % 4; n != 0 {
		s = s[:len(s)-n]
	}
	if len(s) < 8 {
		return nil, false
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return d, true
	}
	return nil, false
}

func desMostlyPrintable(b []byte) bool {
	printable := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*10 >= len(b)*9
}

// ---------------------------------------------------------------------------------------------
// THE SIGNATURE TABLE, WHICH IS THIS CLASS'S OWN AND IS SHARED WITH NOBODY
// ---------------------------------------------------------------------------------------------

var (
	// desLengthRe captures the number PHP computed. It is the only regexp here with a capture
	// group, because it is the only oracle whose answer is a value rather than a presence.
	desLengthRe = regexp.MustCompile(`(?i)unserialize\(\)\s*:\s*Error at offset\s+\d+\s+of\s+(\d+)\s+bytes`)

	desIncompleteRe  = regexp.MustCompile(`__PHP_Incomplete_Class`)
	desStreamHdrRe   = regexp.MustCompile(`(?i)invalid stream header|StreamCorruptedException`)
	desLoadKeyRe     = regexp.MustCompile(`(?i)invalid load key`)
	desUnserializeRe = regexp.MustCompile(`(?i)\bunserialize\(\)`)
)

// desCorroborating are the phrases that say "a deserializer is somewhere near here" and never say
// "it read OUR bytes". None of them may carry a verdict alone.
func desCorroborating() []faSignature {
	return []faSignature{
		{Name: "php_unserialize_named", Re: desUnserializeRe, Corroborating: true},
		{Name: "java_stream_corrupted", Re: desStreamHdrRe, Corroborating: true},
		{Name: "python_load_key", Re: desLoadKeyRe, Corroborating: true},
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

func (deserClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	base := "every payload in this class is printable ASCII (base64 text, PHP serialized text, or a " +
		"hyphenated identifier), so all of them are deliverable here with no encoder this layer has " +
		"not implemented. THE CLASS NEEDS NO NEW ENCODER AT ALL, which is why it ships while XXE, " +
		"whose oracle is stronger, does not"
	switch k {
	case triage.KindQuery, triage.KindBody, triage.KindPath:
		return triage.Reachability{Reach: triage.ReachConditional, Reason: base +
			". Request media type seen: " + string(mt)}
	case triage.KindCookie:
		return triage.Reachability{Reach: triage.ReachConditional, Reason: base +
			". A cookie is where a serialized object most often lives on a PHP or a Rails application, " +
			"so this point is worth as much as the value slots and not less"}
	case triage.KindHeader:
		return triage.Reachability{Reach: triage.ReachConditional, Reason: base +
			". A serialized blob in a header is rarer and costs the same, so these slots are probed " +
			"after the value slots rather than instead of them"}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment is never transmitted, so no server-side deserializer can ever see it",
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

// Plan sends the whole arm set in round 0, and one gated probe in round 1.
//
// WHY THERE IS NO SHAPE GATE ON ROUND 0, WHICH IS THE COSTLY DECISION IN THIS FILE. The obvious
// design gates every probe on DES-R0's recognition table, so a slot whose value carries no
// serialization header costs nothing. It is the wrong design for the one probe that matters most.
// DES-P2 fires on ANY slot whose value is passed to unserialize(), including a slot whose observed
// value is the string "en-GB", and a slot like that is invisible to any table that reads the
// value. Gating on shape would delete the class's ability to find the case nobody could have
// guessed, which is the case this whole layer exists for. The standing rule in this codebase says
// a shape guess ORDERS work and never suppresses it, and the sanctioned way to express cost is the
// TIER: the two PHP arms and the control are reduced, and the Java and Python arms are full, so a
// reduced run spends three requests a slot and a full run spends seven.
//
// ROUND 1 IS GATED ON A MEASUREMENT AND NOT A GUESS. DES-P1 goes out only once DES-P2 has shown
// that an unserialize sink is actually there. On a slot with no such sink it is 26 bytes of noise
// with nothing to answer it.
func (c deserClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType).Reach == triage.ReachNever {
		return nil
	}
	if desSignedWrapper(ctx.Slot) != "" {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() || ctx.Budget.Exhausted() {
		return nil
	}

	switch ctx.Round {
	case 0:
		ids := desRound0()
		out := make([]triage.ProbeRequest, 0, len(ids))
		for _, id := range ids {
			out = append(out, pxReq(id, ctx.Slot.Key))
		}
		return out
	case 1:
		if !desUnserializeSinkSeen(ctx) {
			return nil
		}
		return []triage.ProbeRequest{pxReq(desP1, ctx.Slot.Key)}
	default:
		return nil
	}
}

// desSignedWrapper is the zero-cost not_applicable, and it names a real exclusion rather than a
// convenience.
//
// A JWT slot is a MAC over its own contents. Replacing it with any of this class's payloads
// produces a signature failure, so every probe measures the token library's rejection path and
// none of them reaches a deserializer. The framework already models this: triage.WrapJWT exists on
// the slot, and eli.go already refuses javax.faces.ViewState as a signed wrapper for the same
// reason. ASP.NET view state is the other one and it is deliberately NOT excluded here, because
// DES-R0 recognising it is useful and because the MAC-failure message is itself a named defence;
// what this class will not do is mutate it, and it does not, since every payload REPLACES the
// value rather than corrupting one byte of it.
func desSignedWrapper(s triage.Slot) string {
	if s.Wrapper == triage.WrapJWT || desLooksLikeJWT(strings.TrimSpace(s.Value)) {
		return "signed_wrapper (jwt): this slot carries a token that is a MAC over its own contents, so " +
			"every payload this class could send would be rejected at the signature check and would " +
			"measure the token library rather than a deserializer. The JWT surface has its own tooling " +
			"(jwt_tool is a container in this framework) and its own questions"
	}
	if s.Wrapper == triage.WrapSigned {
		return "signed_wrapper: this slot is marked as carrying a signed value, so a replaced value is " +
			"rejected before anything parses it"
	}
	return ""
}

// desUnserializeSinkSeen reports whether round 0's length pair established a PHP unserialize sink.
func desUnserializeSinkSeen(ctx triage.PlanCtx) bool {
	own := faOwn(ctx.Own)
	honest, _ := pxHonest(own)
	res := desReadLengths(honest)
	return res.verdict == desLenComputed
}

// ---------------------------------------------------------------------------------------------
// THE LENGTH ORACLE
// ---------------------------------------------------------------------------------------------

type desLenVerdict string

const (
	desLenAbsent   desLenVerdict = "absent"    // no response named a length
	desLenOnePoint desLenVerdict = "one_point" // only one arm answered, so nothing can discriminate
	desLenStatic   desLenVerdict = "static"    // every arm named the SAME number: page text, not a computation
	desLenMismatch desLenVerdict = "mismatch"  // the numbers differ and do not track our payload lengths
	desLenComputed desLenVerdict = "computed"  // the differences equal our own length differences
)

type desLenReading struct {
	verdict desLenVerdict
	// points maps a probe to the length it was told and the length it actually sent.
	points map[triage.ProbeID][2]int
	// offset is the constant the application adds, which is the size of whatever it concatenates
	// around our value before calling unserialize. Zero means our value is passed straight in.
	offset int
	// exact reports offset == 0, which is the strongest form and is worth its own annotation
	// because it tells the operator the sink takes the parameter with no wrapper at all.
	exact bool
	ords  []uint64
}

// desReadLengths is the rank-1 computation oracle, and every clause in it is a refusal to
// over-read the evidence.
//
// THE RULE. Take every probe that named a length. Compute, for each, (length it was told MINUS
// length it actually sent). If every one of those differences is the SAME constant, then the
// application computed the number from our payload, because three payloads of three different
// lengths cannot produce a consistent offset by accident. The constant itself is informative: it
// is how many bytes the application wraps around our value before deserializing.
//
// IT COMPARES AGAINST THE RECORDED PAYLOAD AND NOT AGAINST THE CONSTANTS IN THIS FILE. If a WAF or
// an encoder changed the payload's length on the way out, the expected number changes with it, and
// a class comparing to the literal 39 would read a mangled probe as a miss and eventually as a
// clean. PayloadWire exists for exactly this.
func desReadLengths(honest []faOwnObs) desLenReading {
	out := desLenReading{verdict: desLenAbsent, points: map[triage.ProbeID][2]int{}}
	var offsets []int
	for _, o := range honest {
		switch o.ProbeID {
		case desP2A, desP2B, desNC1:
		default:
			continue
		}
		m := desLengthRe.FindSubmatch(o.Obs.Body)
		if m == nil {
			continue
		}
		told, err := strconv.Atoi(string(m[1]))
		if err != nil {
			continue
		}
		sent := desSentLen(o.Obs)
		if sent <= 0 {
			continue
		}
		out.points[o.ProbeID] = [2]int{told, sent}
		offsets = append(offsets, told-sent)
		out.ords = append(out.ords, o.Ordinal)
	}
	switch len(offsets) {
	case 0:
		return out
	case 1:
		out.verdict = desLenOnePoint
		out.offset = offsets[0]
		out.exact = offsets[0] == 0
		return out
	}
	allSameTold := true
	first := -1
	for _, p := range out.points {
		if first < 0 {
			first = p[0]
			continue
		}
		if p[0] != first {
			allSameTold = false
		}
	}
	if allSameTold {
		out.verdict = desLenStatic
		return out
	}
	for _, off := range offsets[1:] {
		if off != offsets[0] {
			out.verdict = desLenMismatch
			return out
		}
	}
	out.verdict = desLenComputed
	out.offset = offsets[0]
	out.exact = offsets[0] == 0
	return out
}

// desSentLen is how many bytes the application saw, which is the LOGICAL length and not the wire
// length.
//
// The wire form of a query value is percent-encoded and the application decodes it before using
// it, so the logical bytes are what unserialize() counts. Every payload in this class is
// [a-z0-9-] or base64, so in practice the two are equal; the function exists so that the reasoning
// is in the code rather than in a comment that stops being true when somebody adds a payload with
// a space in it.
func desSentLen(o triage.Observation) int {
	if n := len(o.Payload.Logical); n > 0 {
		return n
	}
	return len(o.Payload.Wire)
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

func (c deserClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return pxOneVerdict(triage.ClassDeser, key, state, reason, oracle, grade, ords, ann, desLabel(ann))
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}
	if why := desSignedWrapper(ctx.Slot); why != "" {
		return one(triage.StateNotApplicable, why, "", triage.GradeUnrated, nil)
	}

	format, formatWhy := desRecognise(ctx.Slot)
	ann["observed_format"] = string(format)
	ann["observed_format_reason"] = formatWhy
	ann["gadget_tool_pointer"] = "none: ysoserial, ysoserial.net, phpggc and marshalsec are not " +
		"containers in this framework, so the pointer this class produces is a format name and a human " +
		"instruction rather than a next command"

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		return one(desNothingSent(ctx))
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	honest, skips := pxHonest(own)
	skips = append(skips, pxNotObserved(append(desRound0(), desP1), own)...)
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload was refused, altered or left unsubstituted. Nothing "+
				"about this slot was measured, and the silence is ours",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)
	baselines := faBaselineBodies(ctx)
	ann["baseline_samples_available"] = len(baselines)

	// THE TRANSFORMATION CONTROL, FIRST, AND WITH THE LENGTH ORACLE DELIBERATELY EXCLUDED FROM IT.
	// See the file header: every non-serialized string fires the length oracle on a real sink, so
	// checking NC1 for a length would silence this class's best probe everywhere it works.
	if nc1, ok := desFind(honest, desNC1); ok {
		if fired, what := desTransformationFired(nc1, ""); fired {
			ann["control_that_fired"] = string(desNC1) + " (" + what + ")"
			v := one(triage.StateCannotDetermine,
				"detector_unverified: DES-NC1 is an ordinary hyphenated string with no serialized structure "+
					"of any kind, and the response to it carried "+what+". That string cannot be produced by "+
					"deserializing this control, so the detector is matching page text and every reading on "+
					"this slot is unsafe. NOTE that the LENGTH oracle is deliberately not part of this check: "+
					"the control is 35 bytes and a real unserialize sink correctly reports 35 for it",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}

	// THE BASELINE CHECK. A page that already carries these phrases disables the detector that
	// reads them, and disabled is not silent.
	if disabled := desDisabledByBaseline(baselines); len(disabled) > 0 {
		ann["detectors_disabled_by_baseline"] = disabled
		v := one(triage.StateCannotDetermine,
			"detector_unverified (signature_in_baseline): the unperturbed response already carries "+
				strings.Join(disabled, ", ")+", so a hit on any probe proves nothing. A documentation page, "+
				"a security-training page or a framework error catalogue does this, and it is the single "+
				"most common false positive available to a signature-reading class",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// ORACLE 1, THE STRONGEST: DES-P1's transformation, which names a type PHP invented.
	if p1, ok := desFind(honest, desP1); ok && desIncompleteRe.Match(p1.Obs.Body) {
		named := p1.Marker != "" &&
			bytes.Contains(bytes.ToLower(p1.Obs.Body), []byte(strings.ToLower(desClassPrefix+string(p1.Marker))))
		ann["winning_probe"] = string(desP1)
		ann["class_name_echoed"] = named
		grade := triage.GradeMedium
		extra := ". The class name we chose did NOT come back, so the object was created and its name " +
			"was not rendered. The transformation is still ours: nothing but PHP's unserialize emits " +
			"__PHP_Incomplete_Class"
		if named {
			grade = triage.GradeHigh
			extra = ". The response ALSO carries " + desClassPrefix + "<this probe's marker>, which is the " +
				"class name we named, so the object PHP built is the object this request asked for and the " +
				"hit is attributable to this probe instance rather than to a stale object the application " +
				"was already holding"
		}
		v := one(triage.StateFinding,
			"php_unserialize_sink: the response carries the 22 bytes __PHP_Incomplete_Class, which are "+
				"absent from the request and which nothing but PHP's unserialize machinery produces, in "+
				"answer to a serialized object naming a class this process does not have"+extra+
				". This slot is fed to unserialize()",
			"php_incomplete_class", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{Ordinal: p1.Ordinal, Phrase: "php_incomplete_class", Wire: p1.Obs.Payload}
		return v
	}

	// ORACLE 2: the length arithmetic, with its own discriminator.
	length := desReadLengths(honest)
	ann["length_oracle"] = string(length.verdict)
	if len(length.points) > 0 {
		ann["length_points"] = desRenderLengthPoints(length)
	}
	switch length.verdict {
	case desLenComputed:
		ann["winning_probe"] = string(desP2A)
		ann["wrapper_bytes"] = length.offset
		ann["exact_length"] = length.exact
		detail := ". The application adds " + strconv.Itoa(length.offset) + " bytes of its own around " +
			"this value before deserializing it, which is why the numbers are offset by a constant rather " +
			"than equal"
		if length.exact {
			detail = ". Every number equals the payload's own length exactly, so this slot's value is passed " +
				"to unserialize() with nothing wrapped around it"
		}
		v := one(triage.StateFinding,
			"php_unserialize_length_arithmetic: "+pxCount(len(length.points), "payloads of DIFFERENT lengths")+
				" each came back with a PHP unserialize error naming its OWN length. The number is not a "+
				"string in a page: it is a value the application computed from the bytes we sent, which is "+
				"the same class of oracle as sending 7919*6271 and reading 49660049 back. A static error "+
				"page gives the same number every time and is refused by this rule"+detail,
			"unserialize_length_arithmetic", triage.GradeHigh, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{Phrase: "unserialize_length_arithmetic", Ordinal: firstOrdinal(length.ords)}
		return v
	case desLenStatic:
		v := one(triage.StateCannotDetermine,
			"deser_length_not_computed: every arm of the length pair came back with the SAME number, so "+
				"the string is page text and not a computation. That is exactly what the pair exists to "+
				"catch, and it is why this class ships two payloads of different lengths rather than one",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	case desLenMismatch:
		ann["winning_probe"] = string(desP2A)
		v := one(triage.StateSuspicious,
			"php_unserialize_sink_present_length_untracked: the responses named DIFFERENT lengths, so "+
				"something is computing a number from our input, and the differences do not match our own "+
				"payload length differences, so whatever it counted is not exactly what we sent. A truncating "+
				"field, a wrapper of variable size or a WAF that rewrote one payload all produce this. An "+
				"unserialize sink is very likely here and the arithmetic did not close, so it is suspicious "+
				"and not a finding",
			"unserialize_length_untracked", triage.GradeMedium, ords)
		v[0].Untested = skips
		return v
	case desLenOnePoint:
		ann["winning_probe"] = string(desP2A)
		v := one(triage.StateSuspicious,
			"php_unserialize_sink_single_point: exactly one arm of the length pair answered, so there is a "+
				"PHP unserialize error naming a length and nothing to compare it against. One point does not "+
				"make a line: a page carrying that sentence produces the same reading. Re-run with the "+
				"second arm before believing it",
			"unserialize_length_single_point", triage.GradeLow, ords)
		v[0].Untested = skips
		return v
	}

	// ORACLE 3: the Java hex echo, with its own discriminator.
	if state, reason, oracle, grade, fired := desJavaArm(honest, ann); fired {
		v := one(state, reason, oracle, grade, ords)
		v[0].Untested = skips
		return v
	}

	// ORACLE 4: the pickle repr join.
	if y1, ok := desFind(honest, desY1); ok && bytes.Contains(y1.Obs.Body, []byte(desY1Repr)) {
		// The invariant, asserted rather than assumed: the joined repr must not be in the request.
		// It cannot be, because the two halves are separated by pickle opcodes in the raw bytes
		// and the base64 text contains neither half. Checking costs one comparison and turns an
		// argument into a fact on the row.
		if bytes.Contains(y1.Obs.Payload.Wire, []byte(desY1Repr)) || bytes.Contains(y1.Obs.Payload.Logical, []byte(desY1Repr)) {
			ann["answer_in_wire"] = true
		} else {
			ann["winning_probe"] = string(desY1)
			v := one(triage.StateFinding,
				"python_pickle_sink: the response carries the exact 24 bytes "+desY1Repr+", which is "+
					"CPython's repr of the list this pickle loads to. The brackets, the quotes and the "+
					"comma-space are Python's, not ours, and the two eight-byte halves are separated by pickle "+
					"opcodes in the raw payload and are absent from its base64 text, so this string exists in "+
					"neither form of the request. The application unpickled our bytes and rendered the result",
				"pickle_repr_join", triage.GradeHigh, ords)
			v[0].Untested = skips
			v[0].Evidence = triage.TriageEvidence{Ordinal: y1.Ordinal, Phrase: "pickle_repr_join",
				Matched: []byte(desY1Repr), Wire: y1.Obs.Payload}
			return v
		}
	}

	// ORACLE 5, CORROBORATING ONLY: the pickle load-key echo. It never carries a verdict alone and
	// it is recorded here so that an operator reading a clean can see it was present.
	if y2, ok := desFind(honest, desY2); ok && bytes.Contains(y2.Obs.Body, []byte(desY2Echo)) {
		ann["winning_probe"] = string(desY2)
		v := one(triage.StateSuspicious,
			"python_pickle_load_key_echo: the response carries \""+desY2Echo+"\", which echoes the byte this "+
				"probe chose and which CPython's unpickler produces. It is CORROBORATING ONLY and can never "+
				"be a finding in this class, because unlike the Java and PHP arms it ships no second payload "+
				"with a different byte, so nothing here has shown this detector discriminating. DES-Y1 is the "+
				"probe that settles it and it did not fire",
			"pickle_load_key_echo", triage.GradeLow, ords)
		v[0].Untested = skips
		return v
	}

	// A FILTER ANSWERING IS NOT THE APPLICATION ANSWERING, asked after every oracle and before
	// every negative, which is the only position where it helps.
	//
	// IT USED TO RUN BEFORE THE ORACLES and the sibling classes shipped the same ordering, which
	// the oracle run proved wrong on two of the three: faUniformBlock reads BODIES ONLY, so on a
	// sink whose page does not echo the payload it calls the application's own uniform response a
	// filter. Here the argument is the same one in a different suit: a response carrying a length
	// this route COMPUTED from our bytes, or a type name PHP invented, or eight hex characters a
	// JVM formatted, is not a filter's block page. What the guard is for is standing between a
	// uniform block page and a clean, and that is what it now does.
	if pxUniformBlock(ctx, honest) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical "+
				"non-baseline responses, so a filter answered and no deserializer was reached",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	control, haveControl := pxRouteControl(ctx)
	return desNegative(honest, control, haveControl, format, ann, ords, skips, one)
}

// desNegative is every exit left once all five oracles have declined to fire.
//
// IT IS A FUNCTION FOR THE REASON ormDecide IS: a ClassifyCtx cannot be built outside the triage
// package, so a decision taken inside Classify can only ever be exercised by running the whole
// runner against a live target, and the guard added below was added because it was measured
// missing. A guard no unit test can reach is a guard nobody will notice deleting. The one value
// this tail needs off the context, the unperturbed route control, is lifted out by pxRouteControl
// at the single call site and handed over as a plain Observation.
func desNegative(honest []faOwnObs, control triage.Observation, haveControl bool,
	format desFormat, ann map[string]any,
	ords []uint64, skips []triage.ProbeSkip,
	one func(triage.TriageState, string, string, triage.TriageGrade, []uint64) []triage.ClassVerdict) []triage.ClassVerdict {

	// THE PRECONDITION, AND IT IS THE LAST GUARD BEFORE EVERY NEGATIVE THIS CLASS CAN EMIT.
	//
	// EVERY ORACLE ABOVE READS THE RESPONSE BODY. __PHP_Incomplete_Class is 22 bytes in a body, the
	// length arithmetic is a number in a body, the Java arm is eight hex characters in a body and
	// the pickle arm is a 24-byte repr in a body. On /clean/empty204 and /clean/nothing there is no
	// body, and this class MEASURED CLEAN on both: six arms reported silence out of zero bytes. On
	// /clean/always500 the body exists but the benign control gets the identical error page, so the
	// pages searched were the failure's and not the application's.
	//
	// It is asked AFTER the oracles and after the uniform-block guard for the reason written on
	// that guard: an oracle that DID fire has read something real out of whatever came back, and a
	// precondition placed above it would suppress a finding to protect a clean.
	ann["evidence_surface"] = string(pxReadsBody)
	if why, absent := pxNoEvidenceToRead(pxReadsBody, honest, control, haveControl); absent {
		v := one(triage.StateCannotDetermine, why, "", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// Nothing fired. What may be said depends entirely on WHICH arms actually ran.
	missing := desArmsNotRun(honest)
	corroborated := desCorroboratedBy(honest)
	if len(corroborated) > 0 {
		ann["corroborating_phrases"] = corroborated
	}
	if len(missing) > 0 {
		ann["arms_not_run"] = missing
		v := one(triage.StateCannotDetermine,
			"only_some_engines_were_tested: every oracle that ran stayed silent, and "+
				pxCount(len(missing), "of this class's arms did not run at all")+" ("+
				strings.Join(missing, ", ")+"). Each arm answers for a DIFFERENT runtime and none of them "+
				"answers for another: the length pair says nothing about a JVM, the stream header says "+
				"nothing about PHP, and the pickle says nothing about either. On a reduced-tier run only the "+
				"PHP arm is bought, so this state is the normal and correct outcome there, and it is not a "+
				"clean because a clean would be a green tick over two runtimes nobody looked at",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	searchedProbes, searchedBytes := pxBodyBytesRead(honest)
	ann["bodies_searched"] = searchedProbes
	ann["body_bytes_searched"] = searchedBytes
	ann["clean_preconditions"] = []string{
		"THE ORACLES HAD SOMETHING TO READ: " + pxCount(searchedProbes, "of this class's responses") +
			" carried a body, " + pxCount(searchedBytes, "bytes") + " in total, and the unperturbed route " +
			"control did not itself answer 5xx. Without that line this clean would be six silences over " +
			"zero bytes, which is what it was before pxNoEvidenceToRead was added above",
		"all six arms reached the wire: the PHP length pair with its control, both Java stream headers, and the pickle",
		"no response named a length, so no unserialize sink answered",
		"no response carried __PHP_Incomplete_Class",
		"neither Java probe echoed its own four chosen bytes as hex",
		"the pickle's repr did not come back",
		"the transformation control produced none of those four",
		"none of those phrases is present in the unperturbed baseline, so no detector was disabled",
	}
	reason := "no_deserializer_answered: all six arms of this class reached the wire, " +
		pxCount(searchedBytes, "bytes of response body across") + " " +
		pxCount(searchedProbes, "responses were searched") + ", and every arm stayed silent. " +
		"Each is a rank-1 oracle over a value the runtime would have had to COMPUTE " +
		"from our bytes (a length, a type name, a hex rendering of four bytes we chose, a Python repr), " +
		"so none of them can be suppressed by escaping or by output encoding the way a reflection oracle " +
		"can. WHAT THIS DOES NOT COVER: .NET BinaryFormatter and Ruby Marshal have no active probe here " +
		"(both are recognised passively by DES-R0 and neither has a safe in-band computation oracle " +
		"shipped), and no gadget chain was attempted by design"
	if format != desFormatNone {
		reason += ". NOTE that this slot's OBSERVED value was recognised as " + string(format) +
			", so the application does round-trip a serialized object here even though none of our " +
			"payloads reached a deserializer. That is worth an operator's eye"
	}
	v := one(triage.StateClean, reason, "no_deserializer_answered", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// Settle. Nothing here is decided out of band.
func (deserClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

func desNothingSent(ctx triage.ClassifyCtx) (triage.TriageState, string, string, triage.TriageGrade, []uint64) {
	switch {
	case !ctx.Route.Resolved():
		return triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value did not resolve, so there is no " +
				"baseline to difference a signature against and nothing was sent", "", triage.GradeUnrated, nil
	case ctx.Prelude.Failed():
		return triage.StateCannotDetermine,
			"prelude_failed: this vector needs a token this run could not obtain", "", triage.GradeUnrated, nil
	}
	// THE LAST TWO ARMS LIVE IN pxNothingSentTail AND THE ORDER IS THE WHOLE POINT. The budget
	// arm used to sit above the default and assert that the cap was reached BEFORE this class
	// planned, which ctx.Budget cannot witness: it is read at Classify time and the decision it
	// claims to explain was taken in Plan. See pxbudgetarm.go.
	state, reason := pxNothingSentTail(ctx, len(desRound0()), "a deserialization probe",
		"no deserialization probe was derived for this slot and none of the named reasons above applies")
	return state, reason, "", triage.GradeUnrated, nil
}

// desJavaArm scores the stream-header pair. Same three-way shape as the length pair: both arms
// naming their OWN hex is a computation, both naming the same hex is page text, one alone is a
// single point.
func desJavaArm(honest []faOwnObs, ann map[string]any) (triage.TriageState, string, string, triage.TriageGrade, bool) {
	j1, ok1 := desFind(honest, desJ1)
	j2, ok2 := desFind(honest, desJ2)
	hit := func(o faOwnObs, want string) bool {
		return bytes.Contains(bytes.ToUpper(o.Obs.Body), []byte(want))
	}
	h1 := ok1 && hit(j1, desJ1Echo)
	h2 := ok2 && hit(j2, desJ2Echo)
	cross1 := ok1 && hit(j1, desJ2Echo)
	cross2 := ok2 && hit(j2, desJ1Echo)

	switch {
	case h1 && h2 && !cross1 && !cross2:
		ann["winning_probe"] = string(desJ1) + "+" + string(desJ2)
		return triage.StateFinding,
			"java_object_input_stream: both Java arms came back naming their OWN four chosen bytes as eight " +
				"ASCII hex characters (" + desJ1Echo + " for " + string(desJ1) + " and " + desJ2Echo + " for " +
				string(desJ2) + "), and neither echoed the other's. Those strings are in neither the raw " +
				"payload nor its base64 text, so a JVM hex-formatted our bytes: an ObjectInputStream is on " +
				"the other end of this slot. It failed in readStreamHeader, before the first class name was " +
				"read, so nothing was constructed and nothing ran",
			"java_stream_header_hex_echo", triage.GradeHigh, true
	case (h1 && cross1) || (h2 && cross2):
		ann["winning_probe"] = string(desJ1) + "+" + string(desJ2)
		return triage.StateCannotDetermine,
			"java_stream_header_not_computed: a response carried BOTH probes' hex strings, so the page is " +
				"reciting header examples rather than formatting our bytes. That is what the second arm " +
				"exists to catch", "", triage.GradeUnrated, true
	case h1 != h2:
		ann["winning_probe"] = string(desJ1)
		if h2 {
			ann["winning_probe"] = string(desJ2)
		}
		return triage.StateSuspicious,
			"java_stream_header_single_point: one Java arm echoed its own four bytes as hex and the other " +
				"did not answer at all. The echo is a computation and one point does not make a line, so this " +
				"is suspicious rather than a finding. The commonest innocent cause is the second arm not " +
				"reaching the wire; check the untested rows before spending anything on it",
			"java_stream_header_hex_echo", triage.GradeMedium, true
	}
	return "", "", "", triage.GradeUnrated, false
}

// desTransformationFired reports whether a response carries one of the four TRANSFORMATION
// signatures. The length oracle is deliberately not in here: see the file header.
func desTransformationFired(o faOwnObs, _ string) (bool, string) {
	switch {
	case desIncompleteRe.Match(o.Obs.Body):
		return true, "__PHP_Incomplete_Class"
	case bytes.Contains(bytes.ToUpper(o.Obs.Body), []byte(desJ1Echo)):
		return true, "the hex string " + desJ1Echo
	case bytes.Contains(bytes.ToUpper(o.Obs.Body), []byte(desJ2Echo)):
		return true, "the hex string " + desJ2Echo
	case bytes.Contains(o.Obs.Body, []byte(desY1Repr)):
		return true, "the pickle repr " + desY1Repr
	case bytes.Contains(o.Obs.Body, []byte(desY2Echo)):
		return true, "the pickle load-key echo"
	}
	return false, ""
}

// desDisabledByBaseline names the detectors an unperturbed response has already made unusable.
//
// THE LENGTH ORACLE IS DELIBERATELY NOT IN THIS TABLE, AND IT USED TO BE. THE ORACLE RUN CAUGHT
// IT AND IT WAS THE WORST DEFECT IN THIS FILE.
//
// A BASELINE CARRYING THE UNSERIALIZE SENTENCE IS THE SIGNATURE OF A WORKING SINK, NOT OF A
// BROKEN DETECTOR. Every non-serialized string produces that sentence on a real unserialize()
// sink; the file header above says so in as many words and measures it at 35 bytes for DES-NC1.
// The route control sends the slot's OBSERVED value, which on the case this class exists for
// ("a slot whose observed value is the string en-GB") is not serialized either. So the baseline
// carries the sentence on exactly the targets where this class works, and listing it here
// disabled the class's strongest probe on all of them.
//
// MEASURED, full-registry run against the canary oracle's /deser/php, the route built to be this
// class's positive: DESER answered cannot_determine (signature_in_baseline) while all three arms
// were correctly naming 39, 32 and 35 bytes. A tier-1 computation reported as an unusable
// signature, which is the inverse of the false positive the baseline rule exists to prevent and
// harder to notice, because cannot_determine looks cautious.
//
// NOTHING IS LOST BY REMOVING IT. The failure the baseline rule guards against here is a page
// that recites the sentence with a fixed number, and desReadLengths already refuses that by its
// own construction: every arm reads the same number, allSameTold holds, and the verdict is
// desLenStatic and cannot_determine. That rule is stronger than a baseline match, because it
// catches the static page whether or not the baseline happens to carry it. The other three
// entries stay: __PHP_Incomplete_Class, the stream-header phrase and the load-key phrase are
// strings, not numbers, and a baseline carrying one really does make the matching detector
// unusable.
func desDisabledByBaseline(baselines [][]byte) []string {
	table := []faSignature{
		{Name: "php_incomplete_class", Re: desIncompleteRe},
		{Name: "java_stream_header", Re: desStreamHdrRe},
		{Name: "python_load_key", Re: desLoadKeyRe},
	}
	_, disabled := faDisabledByBaseline(table, baselines)
	for _, b := range baselines {
		if bytes.Contains(b, []byte(desY1Repr)) {
			disabled = append(disabled, "pickle_repr_join")
			break
		}
	}
	return disabled
}

// desCorroboratedBy names the weak phrases present across this class's own responses. They never
// score; they are recorded so a clean can be read with its context.
func desCorroboratedBy(honest []faOwnObs) []string {
	seen := map[string]bool{}
	var out []string
	for _, o := range honest {
		_, corr := faMatchSignatures(desCorroborating(), o.Obs.Body)
		for _, h := range corr {
			if seen[h.Name] {
				continue
			}
			seen[h.Name] = true
			out = append(out, h.Name+" (in the response to "+string(o.ProbeID)+")")
		}
	}
	return out
}

// desArmsNotRun names the arms whose probes never reached the wire, which is what stops a
// partially-run class from reporting clean.
func desArmsNotRun(honest []faOwnObs) []string {
	present := map[triage.ProbeID]bool{}
	for _, o := range honest {
		present[o.ProbeID] = true
	}
	var missing []string
	for _, id := range desCleanRequires() {
		if !present[id] {
			missing = append(missing, string(id))
		}
	}
	return missing
}

func desFind(honest []faOwnObs, id triage.ProbeID) (faOwnObs, bool) {
	for _, o := range honest {
		if o.ProbeID == id {
			return o, true
		}
	}
	return faOwnObs{}, false
}

func firstOrdinal(ords []uint64) uint64 {
	if len(ords) == 0 {
		return 0
	}
	return ords[0]
}

func desRenderLengthPoints(r desLenReading) []string {
	var out []string
	for _, id := range []triage.ProbeID{desP2A, desP2B, desNC1} {
		p, ok := r.points[id]
		if !ok {
			continue
		}
		out = append(out, string(id)+": told "+strconv.Itoa(p[0])+", sent "+strconv.Itoa(p[1]))
	}
	return out
}

// desLabel is the pointer, and its first line is the honest one.
func desLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"no_tool": "this framework ships no deserialization gadget tool. ysoserial (Java), phpggc (PHP), " +
			"ysoserial.net and marshalsec are the four that matter and none is a container here. What this " +
			"class hands over is the RUNTIME and the SINK, which is the part that takes a scanner all day " +
			"to find",
		"never_a_gadget": "no gadget chain is shipped from triage and none should be: every chain ends in " +
			"a command, which is exploitation and is destructive by definition",
	}
	engine := ""
	if w, ok := ann["winning_probe"].(string); ok {
		hints["winning_probe"] = w
		switch {
		case strings.HasPrefix(w, "DES-P"):
			engine = "php"
			hints["next"] = "PHP unserialize(). phpggc generates a chain for whatever framework the target " +
				"runs; the gadget depends on the libraries loaded, so identify those first"
		case strings.HasPrefix(w, "DES-J"):
			engine = "java"
			hints["next"] = "java.io.ObjectInputStream. ysoserial's chain depends on the classpath; " +
				"CommonsCollections and the Spring gadgets are the usual starting points"
		case strings.HasPrefix(w, "DES-Y"):
			engine = "python"
			hints["next"] = "pickle.loads. A pickle that reaches loads is remote code execution with a " +
				"two-line payload, and that payload is deliberately not shipped from here"
		}
	}
	if f, ok := ann["observed_format"].(string); ok && f != "" {
		hints["observed_format"] = f
		if engine == "" {
			engine = f
		}
	}
	if n, ok := ann["wrapper_bytes"].(int); ok && n != 0 {
		hints["wrapper_bytes"] = strconv.Itoa(n) + " bytes are concatenated around this value before it " +
			"is deserialized, which a hand-built payload has to account for"
	}
	return triage.TriageLabel{Tools: nil, Engine: engine, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (deserClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "the_pair_is_the_control", Probes: []triage.ProbeID{desP2A, desP2B, desNC1},
			Rule: "a length finding requires at least two payloads of DIFFERENT lengths each naming its " +
				"own, with one consistent offset between told and sent. Identical numbers are page text and " +
				"the verdict is cannot_determine. DES-NC1 is a third point on that line and is NOT a control " +
				"for this oracle: every non-serialized string fires it on a real sink, measured",
		},
		{
			Name: "the_java_pair_is_the_control", Probes: []triage.ProbeID{desJ1, desJ2},
			Rule: "both arms must echo their OWN four chosen bytes and neither may echo the other's. A " +
				"response carrying both hex strings is reciting examples",
		},
		{
			Name: "answer_not_in_the_request", Probes: []triage.ProbeID{desJ1, desJ2, desY1, desP1},
			Rule: "every string these four oracles match is absent from the request in BOTH the raw and " +
				"the base64 form. VERIFIED for each. DES-Y1 additionally asserts it per response, because " +
				"one comparison turns the argument into a fact on the row",
		},
		{
			Name: "transformation_control_silent", Probes: []triage.ProbeID{desNC1},
			Rule: "an ordinary hyphenated string must produce no __PHP_Incomplete_Class, no stream-header " +
				"hex, no pickle repr and no load-key echo. Any of them means the detector is reading page " +
				"text and the whole slot is detector_unverified",
		},
		{
			Name: "every_arm_before_a_clean", Probes: desCleanRequires(),
			Rule: "clean requires all six arms on the wire. Each answers for a different runtime and none " +
				"answers for another, so a reduced-tier run that buys only the PHP arm reports " +
				"cannot_determine naming the two it did not test",
		},
	}
}

func (deserClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "length_points", Kind: "differential", What: "for each arm, the length the application named and the length actually sent. The pair of pairs is the proof; one pair is a sentence in a page"},
		{Name: "wrapper_bytes", Kind: "annotation", What: "the constant offset between told and sent, which is how many bytes the application concatenates around this value before deserializing. A hand-built payload has to account for it"},
		{Name: "class_name_echoed", Kind: "content", What: "whether __PHP_Incomplete_Class_Name came back holding the class name this probe chose, which attributes the object to this request rather than to one the application was already holding"},
		{Name: "stream_header_hex", Kind: "content", What: "the eight ASCII characters the JVM formatted from four bytes we chose. It identifies the runtime and proves it read our bytes in one string"},
		{Name: "pickle_repr", Kind: "content", What: "CPython's rendering of the object our pickle loads to, whose punctuation no reflection can produce"},
		{Name: "observed_format", Kind: "annotation", What: "what DES-R0 recognised in the slot's own captured value, at zero request cost. It is not a finding and it is the best hint available about which runtime is behind this parameter"},
		{Name: "arms_not_run", Kind: "annotation", What: "which runtimes were not tested, which is what keeps a partial pass from rendering as a clean"},
	}
}

// OracleCases. The container owes this class four positives and four negatives, and the negatives
// are the ones that decide whether any of it can be believed.
func (deserClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "php_unserialize", Route: "/deser/php", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{desP2A, desP2B, desNC1, desP1}, WantState: triage.StateFinding,
			Why: "a route that passes the parameter to PHP's unserialize and prints the warning. All three " +
				"length arms must name their own lengths with a consistent offset, and the follow-up DES-P1 " +
				"must then produce __PHP_Incomplete_Class carrying our class name. Needs a PHP runtime in " +
				"the oracle container, which today is a single Go binary",
		},
		{
			Name: "php_unserialize_with_a_wrapper", Route: "/deser/phpwrapped", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{desP2A, desP2B}, WantState: triage.StateFinding,
			Why: "the same, with the application concatenating a fixed prefix before deserializing. The " +
				"numbers must be offset by a constant and the verdict must still be a finding, with " +
				"wrapper_bytes recording the constant. IT IS THE ROUTE THAT PROVES THE RULE IS THE " +
				"DIFFERENCE AND NOT THE ABSOLUTE VALUE, and a class comparing against the literal 39 " +
				"reports clean here",
		},
		{
			Name: "static_unserialize_error_page", Route: "/deser/phpstatic", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{desP2A, desP2B}, WantState: triage.StateCannotDetermine,
			Why: "a route whose body ALWAYS contains the sentence 'unserialize(): Error at offset 0 of 39 " +
				"bytes', a documentation page or a cached error. Both arms read 39, the pair does not " +
				"discriminate, and the verdict must be cannot_determine. THIS IS THE ROUTE THAT JUSTIFIES " +
				"SHIPPING TWO PAYLOADS INSTEAD OF ONE",
		},
		{
			Name: "java_object_input_stream", Route: "/deser/java", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{desJ1, desJ2}, WantState: triage.StateFinding,
			Why: "a route that base64-decodes the parameter into an ObjectInputStream and prints the " +
				"exception. Each arm must echo its own hex and neither the other's",
		},
		{
			Name: "python_pickle", Route: "/deser/pickle", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{desY1}, WantState: triage.StateFinding,
			Why: "a route that base64-decodes and unpickles the parameter and renders the result. The exact " +
				"repr must come back and the verdict must be a finding at grade high",
		},
		{
			Name: "echo_is_not_deserialization", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: desRound0(), WantState: triage.StateCannotDetermine,
			Why: "the shipped echo route returns every payload verbatim. Not one oracle here may fire, " +
				"because every string they match is absent from the request in both forms. The verdict is " +
				"cannot_determine and not clean ONLY because the oracle container runs no PHP, JVM or " +
				"CPython, so the arms are answered by a Go handler; with a real multi-runtime fixture this " +
				"route is the class's cleanest clean",
		},
		{
			Name: "base64_noise_is_not_a_format", Route: "/clean/b64noise", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{desP2A}, WantState: triage.StateClean,
			Why: "a route whose body is full of long base64 runs. DES-R0 must recognise NOTHING from the " +
				"slot's own value and no oracle may fire on the response. It is the control for the " +
				"two-character prefix problem: rO, Tz, gASV and BAgK are short enough to appear in ordinary " +
				"base64 and are only believed when the DECODE matches",
		},
		{
			Name: "signature_in_the_baseline", Route: "/deser/preset", Expect: faExpectNegative, Exists: true,
			Probes: desRound0(), WantState: triage.StateCannotDetermine,
			Why: "a route whose unperturbed body already carries __PHP_Incomplete_Class, as a framework " +
				"documentation page does. Every probe would otherwise fire and the verdict must be " +
				"cannot_determine (signature_in_baseline)",
		},
		{
			Name: "jwt_slot_is_not_this_class", Route: "(configuration, not a route)", Expect: faExpectNegative, Exists: false,
			Probes: nil, WantState: triage.StateNotApplicable,
			Why: "a slot whose captured value is a JWT. This class must send ZERO requests and emit " +
				"not_applicable (signed_wrapper), because every payload it has would be rejected at the " +
				"signature check and would measure the token library. It is the zero-cost not-applicable " +
				"every class is required to have and this is the route that proves it costs zero",
		},
	}
}

// =================================================================================================
// THE SHARED PRECONDITION, AND IT LIVES HERE BECAUSE THIS IS THE CLASS IT IS STARKEST ABOUT
// =================================================================================================
//
// THE RULE: A CLASS MAY NOT CONVERT "MY ORACLE HAD NOTHING TO READ" INTO "I READ IT AND FOUND
// NOTHING". Those two sentences produce the same silence from a detector and opposite instructions
// to an operator. The first says point a different tool here. The second says look somewhere else,
// and it is the one that loses bugs.
//
// IT IS NOT A NEW IDEA IN THIS LAYER AND THAT IS THE POINT. utils.triageCompareBody already
// refuses it at the byte channel, in those words:
//
//	if b.NoBody && len(probe.Body) == 0 {
//	    // NOT "identical bodies, therefore same". There is nothing to compare.
//	    return ChannelResult{Channel: ChanBody, Verdict: DiffUnusable, Detail: "no_body"}
//
// faCompare says the same thing one layer up with faCmpNoBody, SQL's OracleCase for
// /clean/empty204 says "identical empty bodies are not evidence of anything", SSTI's says
// "cannot_determine (no_body), never identical-bodies-therefore-same", NOSQL refuses a clean with
// value_insensitive when nothing it sent moved the endpoint, and TRAVERSAL does the same under the
// same name. What was missing is the step that makes a rule a rule: a class had to REMEMBER to
// apply it, and three of eighteen did not.
//
// SO THE PRECONDITION IS DECLARED RATHER THAN REMEMBERED. A class names the surface its oracles
// read, and this helper answers whether that surface carried anything readable on this slot. The
// declaration is the useful half: writing pxReadsBody down next to a class's oracles is a claim
// that can be checked against the oracles, where a missing guard is invisible.
//
// WHICH SURFACE A CLASS DECLARES IS A STATEMENT ABOUT ITS ORACLES AND NOTHING ELSE, and getting it
// wrong in the safe direction still costs real coverage, so the three are drawn narrowly:
//
//	pxReadsBody        every oracle reads bytes OUT OF THE RESPONSE BODY: a signature, a number the
//	                   runtime computed, a rendered value. A 204 and a 200 with no body carry none
//	                   of that, so there is nothing to read. DESER and ORM-LEAK are this, and LFI,
//	                   RFI and PP-SERVER adopted it in the round after. Its control arm has two
//	                   halves that are NOT the same rule: a 5xx control refuses on its own, and a
//	                   4xx control refuses only with the second witness that nothing this class
//	                   sent moved it. See pxBodySurfaceUnreadable for why.
//	pxReadsDifference  every oracle is a DIFFERENCE between two of the class's own responses. A
//	                   difference needs the endpoint to be capable of answering differently at all:
//	                   where it answers identically to every input, "no difference" was guaranteed
//	                   before the first request went out. HPP is this.
//	pxReadsHeaders     the oracles read RESPONSE HEADERS, which a 204 and a 500 both carry in full.
//	                   NOTHING here refuses for this surface, deliberately: an empty-bodied route
//	                   takes nothing away from a header oracle, and a guard that fired there would
//	                   delete true negatives. CRLF and REDIRECT are this and must stay as they are.
//
// WHICH OF THE REMAINING CLASSES SHOULD ADOPT IT, from reading their oracles:
//
//	SHOULD ADOPT pxReadsBody         RFI       (faMatchSignatures and the marker echo, both in a body)
//	                                 LFI       (the same, plus the errno prose)
//	                                 PP-SERVER (its effect is a rendered field in the body)
//	                                 ORM-LEAK  (adopted in this round)
//	                                 DESER     (adopted in this round)
//	SHOULD ADOPT pxReadsDifference   HPP       (adopted in this round)
//	                                 PROTO-EFFECT (its arms are response-to-response differences)
//	ALREADY HAVE THEIR OWN           SQL, SSTI, NOSQL, TRAVERSAL, CSTI, XSS-R, ELI, CMDI, FILEACCESS
//	MUST NOT ADOPT ANY REFUSAL       CRLF, REDIRECT, CORS, HOSTHDR: header surfaces, defensibly
//	                                 clean on a 204 and on a 500
//
// Those adoptions are NOT made here. Each is another class's file and each needs its own
// measurement over the exam before and after, which is exactly the work this round did for three.
type pxEvidenceSurface string

const (
	pxReadsBody       pxEvidenceSurface = "body"
	pxReadsDifference pxEvidenceSurface = "difference"
	pxReadsHeaders    pxEvidenceSurface = "headers"
)

// pxDifferentialWitnessFloor is how many of a class's own probes must have been compared against
// the unperturbed control before "none of them moved it" is allowed to mean anything.
//
// TWO, AND NOT NOSQL'S THREE, BECAUSE THE COMPARISON HERE IS A DIFFERENT AND STRONGER ONE.
// nosqlDifferentialSurface asks whether three payloads that differ from EACH OTHER produced three
// identical answers, and three is its floor because two identical answers are a coincidence an
// application with one error page produces all day. This witness asks whether each payload
// reproduced THE UNPERTURBED CONTROL, which is a fact about the endpoint rather than about the
// payloads: a probe that came back byte-identical to a request carrying none of our bytes did not
// move this endpoint, full stop. Two of those, one of which is the arm's own length-matched
// control, is the smallest set in which "my differential was structurally zero" is a measurement
// and not an accident.
const pxDifferentialWitnessFloor = 2

// pxSensitivity is what the differential witness measured, kept as counts so a class can put the
// numbers in its own reason string rather than asserting the shape in prose.
type pxSensitivity struct {
	Delivered int // probes that reached the target and came back
	Moved     int // ... and whose response differed from the unperturbed control
	Flat      int // ... and whose response was indistinguishable from it
	Unknown   int // ... and which could not be compared at all (truncated, or no projection)

	// HeaderMoved and HeaderNames ARE REPORTED AND NEVER DECIDE ANYTHING, and the split is the
	// whole point of them.
	//
	// Moved, Flat and Unknown come from faCompare, which reads THE STATUS AND THE NORMALISED BODY
	// AND NOTHING ELSE. Every caller of this witness has body-and-status oracles, so that channel
	// is the right one to decide on: LFI searches bodies for a signature, a marker and a stack
	// error, and HPP's two arms read the status, the value-free element skeleton and the JSON
	// shape. On an endpoint that answered every probe with the control's own status and body,
	// each of those oracles was guaranteed silent before the first request went out, whatever the
	// response headers did.
	//
	// THE SENTENCE WAS STILL WRONG, WHICH IS WHY THESE TWO FIELDS EXIST. route_insensitive said
	// the probes came back "INDISTINGUISHABLE from the unperturbed route control" and that a null
	// difference "is true of every payload anyone could send". MEASURED on the canary oracle,
	// four of the thirty cells that refusal produced are endpoints whose RESPONSE HEADERS track
	// the value exactly: /redirect/local answers "Location: hppa&hppdup=hppb" to one probe and
	// "Location: hppa-hppdup-hppb" to the next behind twelve identical body bytes, and
	// /redirect/loginwrap, /redirect/strictvalidator and /crlf/setcookie do the same in Location
	// and in Set-Cookie. Those responses are distinguishable, the endpoint is demonstrably
	// reading what we sent, and the refusal's prose denied both.
	//
	// WIDENING THE DECISION WAS THE OTHER CANDIDATE AND IT WAS REFUSED, BECAUSE IT CONVERTS FOUR
	// CORRECT REFUSALS INTO CLEANS. lfiRouteInsensitive reads Moved and Flat off this same
	// struct. Counting a moving Location as movement would make it return false on exactly those
	// redirect routes, and LFI would go back to reporting clean on five endpoints whose bodies
	// are twelve constant bytes, which is the reading its own doc comment was written to stop.
	// So the channel that decides stays the channel the oracles read, and what the other channel
	// saw is carried alongside it, named, for the reason string to report.
	HeaderMoved int      // delivered probes whose non-volatile response header set differs from the control's
	HeaderNames []string // sorted, deduplicated names of the headers that differed
}

// pxRouteSensitivity answers the question every null differential rests on and almost no scanner
// asks: DOES THIS ENDPOINT ANSWER ANYTHING DIFFERENTLY AT ALL?
//
// It compares each of the class's own delivered probes against the unperturbed route control with
// faCompare, which prefers the normalised body hash and falls back to the structural projection,
// so a request id in a footer does not read as movement. faCmpNoBody counts as flat rather than as
// unknown on purpose: two empty bodies are not a failed comparison, they are an endpoint that said
// nothing either time, which is precisely the state a differential cannot work in.
func pxRouteSensitivity(honest []faOwnObs, control triage.Observation, haveControl bool) pxSensitivity {
	var s pxSensitivity
	if !haveControl {
		return s
	}
	seen := map[string]bool{}
	for _, o := range honest {
		if !o.Obs.Delivered() {
			continue
		}
		s.Delivered++
		switch faCompare(control, o.Obs) {
		case faCmpDifferent:
			s.Moved++
		case faCmpSame, faCmpNoBody:
			s.Flat++
		default:
			s.Unknown++
		}
		// THE SECOND CHANNEL, WHICH REPORTS AND DOES NOT DECIDE. See pxSensitivity.
		if names := pxHeaderWitness(control, o.Obs); len(names) > 0 {
			s.HeaderMoved++
			for _, n := range names {
				if !seen[n] {
					seen[n] = true
					s.HeaderNames = append(s.HeaderNames, n)
				}
			}
		}
	}
	sort.Strings(s.HeaderNames)
	return s
}

// pxVolatileHeaderNames is the list this witness will not read, and every entry on it is a header
// that differs between two responses for a reason that has nothing to do with what we sent.
//
// IT IS A COPY OF CATALOGUE 3.3's SEED LIST AND IT IS DELIBERATELY A COPY. utils holds the
// original as an unexported map behind the baseline learner, and a classifier cannot import it;
// duplicating twenty-six strings is better than a class reaching into the runner, and better
// than this witness reading a clock.
//
// SET-COOKIE IS ON THE ORIGINAL LIST AND IS NOT ON THIS ONE, which is the one deliberate
// divergence. The learner excludes it because a rotating session cookie moves on every request
// and would make every probe look like a finding. This witness never produces a verdict, and
// /crlf/setcookie is one of the four routes it exists to see: that route puts the slot's value
// straight into Set-Cookie, so excluding the header would blind the witness to the case it was
// written for. A rotating session cookie can therefore make HeaderMoved non-zero, which is why
// the reason strings that read it NAME THE HEADERS THAT DIFFERED rather than concluding that the
// endpoint tracks our value.
var pxVolatileHeaderNames = map[string]bool{
	"date": true, "age": true, "expires": true,
	"etag": true, "last-modified": true, "content-length": true,
	"connection": true, "keep-alive": true, "transfer-encoding": true,
	"x-request-id": true, "x-correlation-id": true, "x-trace-id": true,
	"traceparent": true, "tracestate": true, "x-amzn-requestid": true,
	"x-amz-cf-id": true, "x-amz-request-id": true, "cf-ray": true,
	"x-served-by": true, "x-cache": true, "x-cache-hits": true, "x-timer": true,
	"x-runtime": true, "server-timing": true, "via": true, "retry-after": true,
}

func pxVolatileHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if pxVolatileHeaderNames[n] {
		return true
	}
	return strings.HasPrefix(n, "ratelimit-") || strings.HasPrefix(n, "x-ratelimit-")
}

// pxHeaderFingerprint folds an observation's response headers into name -> joined values, lower
// cased, duplicates preserved in sorted order, with the volatile names dropped.
func pxHeaderFingerprint(o triage.Observation) map[string]string {
	multi := map[string][]string{}
	for _, kv := range o.RespHeaders {
		n := strings.ToLower(strings.TrimSpace(kv[0]))
		if n == "" || pxVolatileHeader(n) {
			continue
		}
		multi[n] = append(multi[n], kv[1])
	}
	out := make(map[string]string, len(multi))
	for n, v := range multi {
		sort.Strings(v)
		out[n] = strings.Join(v, "\x1f")
	}
	return out
}

// pxHeaderWitness returns the names of the non-volatile response headers on which these two
// observations differ, including a header present on one side and absent on the other.
//
// IT RETURNS NOTHING WHEN THERE IS NOTHING TO COMPARE. Two observations of which one never
// arrived carry no header difference anyone measured, and a witness that reported "they differ"
// there would be manufacturing the movement it was added to report honestly.
func pxHeaderWitness(a, b triage.Observation) []string {
	if a.ObsID == "" || b.ObsID == "" || !a.Delivered() || !b.Delivered() {
		return nil
	}
	fa, fb := pxHeaderFingerprint(a), pxHeaderFingerprint(b)
	var names []string
	for n, va := range fa {
		if vb, ok := fb[n]; !ok || vb != va {
			names = append(names, n)
		}
	}
	for n := range fb {
		if _, ok := fa[n]; !ok {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}

// pxNameList prints at most four header names and says how many more there were, so a reason
// string built from it stays a sentence and stays exact.
func pxNameList(names []string) string {
	if len(names) == 0 {
		return ""
	}
	if len(names) <= 4 {
		return strings.Join(names, ", ")
	}
	return strings.Join(names[:4], ", ") + " and " + strconv.Itoa(len(names)-4) + " more"
}

// pxNoEvidenceToRead is the precondition itself. It returns the reason a negative may NOT be
// emitted on this slot, or false when the declared surface did carry something.
//
// IT IS FAIL CLOSED ON ITS OWN ARGUMENT. A surface this function does not recognise is a class
// declaring something that was never implemented, and answering "carry on" to that would be the
// silent zero in its purest form, so it refuses and says which value it did not understand.
func pxNoEvidenceToRead(surface pxEvidenceSurface, honest []faOwnObs,
	control triage.Observation, haveControl bool) (string, bool) {

	switch surface {
	case pxReadsHeaders:
		return "", false
	case pxReadsBody:
		return pxBodySurfaceUnreadable(honest, control, haveControl)
	case pxReadsDifference:
		return pxDifferentialSurfaceUnavailable(honest, control, haveControl)
	}
	return "unknown_evidence_surface: this class declared the evidence surface " + string(surface) +
		", which pxNoEvidenceToRead does not implement. No negative may rest on a precondition that " +
		"was never checked", true
}

// pxBodySurfaceUnreadable is the pxReadsBody arm: the body carried nothing, or the application
// never answered at all.
func pxBodySurfaceUnreadable(honest []faOwnObs, control triage.Observation, haveControl bool) (string, bool) {
	delivered, empty := 0, 0
	for _, o := range honest {
		if !o.Obs.Delivered() {
			continue
		}
		delivered++
		if len(o.Obs.Body) == 0 {
			empty++
		}
	}
	if delivered == 0 {
		// Nothing came back at all. That is the caller's own no_probe_reached_the_wire exit and it
		// has a better reason than this one; saying it twice in two voices helps nobody.
		return "", false
	}

	if empty == delivered {
		why := "no_body_to_read: all " + pxCount(delivered, "of this class's own delivered probes") +
			" came back carrying ZERO body bytes"
		if haveControl {
			why += ", and the unperturbed route control answered " + strconv.Itoa(control.Status) +
				" with " + pxCount(len(control.Body), "body bytes")
		}
		return why + ". THE SILENCE THIS CLASS'S NEGATIVE RESTS ON IS READ OUT OF THE RESPONSE BODY: a " +
			"signature, a number the runtime computed from our bytes, a value it rendered, bytes a " +
			"collaborator served. None of those can be present or absent " +
			"in a response that has no body, so nothing was read here and the silence is the ABSENCE OF A " +
			"MEASUREMENT rather than the result of one. Identical empty bodies are not evidence of " +
			"anything, which is the rule utils.triageCompareBody already applies at the byte channel and " +
			"which this class now applies to its own oracles", true
	}

	if haveControl && control.Status >= 500 {
		return "control_already_failing: the unperturbed route control carries none of our bytes and it " +
			"answered " + strconv.Itoa(control.Status) + ". This endpoint is failing before it reads " +
			"anything we sent, so the bodies this class searched are that failure's page and not the " +
			"application's answer about our value. A silent oracle over an error page the benign request " +
			"gets too says nothing about whether the code behind the error would have answered. It is the " +
			"same reading ORM-LEAK already refuses to call clean", true
	}

	// THE 4xx HALF, AND IT IS A DIFFERENT FACT FROM THE 5xx HALF ABOVE.
	//
	// The arm above is unconditional because a 5xx IS the application saying it broke: it never
	// got as far as reading our bytes, so the page it served is the failure's whatever we sent.
	// A 4xx says nothing of the kind. A 404 to the observed value is an ordinary, deliberate
	// answer, and an endpoint that 404s its own value and answers differently to a payload that
	// reached the sink has handed this class a real body to read. So the 4xx arm needs a SECOND
	// WITNESS, and the one it needs is the one the operator's own target makes urgent: 88% of
	// probes against that estate come back 401, the credential-carrying case is caught by the
	// auth gate, and a vector with NO credential against an endpoint that refuses everyone fell
	// through both. What is being measured is not the status. It is that the body searched was
	// the one this endpoint hands a request it is refusing, identically, including to a request
	// carrying none of our bytes.
	if haveControl && control.Status >= 400 && control.Status < 500 {
		s := pxRouteSensitivity(honest, control, haveControl)
		if s.Delivered > 0 && s.Moved == 0 && s.Flat >= pxDifferentialWitnessFloor {
			why := "control_refuses_everyone: the unperturbed route control carries none of our bytes " +
				"and it answered " + strconv.Itoa(control.Status) + ", and " + strconv.Itoa(s.Flat) +
				" of this class's " + pxCount(s.Delivered, "delivered probes") + " came back " +
				"INDISTINGUISHABLE from it, not one of them moving it"
			if s.Unknown > 0 {
				why += " (" + pxCount(s.Unknown, "further probe(s)") + " could not be compared at all)"
			}
			return why + ". A 4xx IS NOT A CRASH AND THIS RULE NEEDS BOTH HALVES FOR THAT REASON: a " +
				"404 to the observed value is an ordinary answer and would leave a real body to read " +
				"the moment one payload moved the endpoint. Together the two say something narrower " +
				"and firmer than the 5xx arm above: every body this class searched is the page this " +
				"endpoint hands a request it is refusing, so the silence is the refusal's and not the " +
				"application's answer about our value. WHAT THIS DOES NOT SAY: why it refuses. A 404 " +
				"and a 401 are different facts, this witness distinguishes neither, and neither is " +
				"needed here, because what makes the negative unreadable is only that the refusal is " +
				"the same for us as for a request carrying nothing of ours", true
		}
	}

	return "", false
}

// pxDifferentialSurfaceUnavailable is the pxReadsDifference arm: there was no differential surface
// for a differential oracle to work on.
func pxDifferentialSurfaceUnavailable(honest []faOwnObs, control triage.Observation, haveControl bool) (string, bool) {
	if !haveControl {
		return "no_route_control: every oracle in this class is a DIFFERENCE, and a null difference only " +
			"means something once something is known to move this endpoint at all. The unperturbed route " +
			"control did not resolve, so there is no answer-with-none-of-our-bytes to hold the probes " +
			"against, and an endpoint that ignored what we sent is indistinguishable from one that " +
			"answers every input the same way", true
	}
	s := pxRouteSensitivity(honest, control, haveControl)
	if s.Delivered == 0 || s.Moved > 0 || s.Flat < pxDifferentialWitnessFloor {
		return "", false
	}
	// THE SENTENCE NOW SAYS WHICH CHANNEL IT READ, AND IT USED TO SAY "INDISTINGUISHABLE" FULL
	// STOP. faCompare reads the status and the normalised body. On /redirect/local,
	// /redirect/loginwrap, /redirect/strictvalidator and /crlf/setcookie the two responses are
	// NOT indistinguishable: the value is in Location or in Set-Cookie and it changes with every
	// probe. The refusal is still right, because every oracle in the calling class reads the
	// status and the body, but the claim was bigger than the measurement and on those four routes
	// it was simply false.
	why := "route_insensitive: " + strconv.Itoa(s.Flat) + " of this class's " +
		pxCount(s.Delivered, "delivered probes") + " came back with THE SAME STATUS AND THE SAME " +
		"NORMALISED BODY as the unperturbed route control, which answered " + strconv.Itoa(control.Status) +
		" with " + pxCount(len(control.Body), "body bytes") + ", and not one of them moved that channel"
	if s.Unknown > 0 {
		why += " (" + pxCount(s.Unknown, "further probe(s)") + " could not be compared at all)"
	}
	why += ". EVERY ORACLE IN THIS CLASS IS A DIFFERENCE BETWEEN TWO OF ITS OWN RESPONSES, READ OFF " +
		"THAT SAME CHANNEL. On an endpoint that answers every one of them with the control's own status " +
		"and body, a null difference was determined before the first request went out and says nothing " +
		"about this slot. This is NOSQL's value_insensitive and TRAVERSAL's value_insensitive reached " +
		"against the route control rather than against a junk control, and it is the reason a quiet " +
		"oracle here is an unknown and not a clean"
	// WHAT THE OTHER CHANNEL SAW. This is the difference between "this endpoint is inert" and
	// "this endpoint is inert where this class can see", and only the second was ever measured.
	if s.HeaderMoved > 0 {
		why += ". NOT INERT, THOUGH: " + pxCount(s.HeaderMoved, "of those probes") + " came back with a " +
			"different value in a non-volatile response header (" + pxNameList(s.HeaderNames) + "), so " +
			"this endpoint is reading something. This witness REPORTS that difference and does not read " +
			"it as an effect of our value: the header may equally carry an echo or a rotating token. It " +
			"is here because a slot whose value reaches a header and never reaches the body is worth a " +
			"manual look, and because the sentence above would otherwise deny that anything moved"
	}
	return why, true
}

// pxRouteControl lifts the unperturbed route control out of a ClassifyCtx into plain values.
//
// IT EXISTS SO THE PRECONDITION IS TESTABLE. triage.Replay carries its Observation behind the
// vault and only the triage package can build a resolved one, which is the whole point of the
// split and is not being argued with here. The consequence is that any decision function taking a
// ClassifyCtx can only ever be exercised through the runner, and ormDecide already shows the way
// out: take the control as plain values and let a unit test hand them over. Every caller of
// pxNoEvidenceToRead goes through this one line, so the untestable part is one line long.
func pxRouteControl(ctx triage.ClassifyCtx) (triage.Observation, bool) {
	if !ctx.Route.Resolved() {
		return triage.Observation{}, false
	}
	return ctx.Route.Obs(), true
}

// pxBodyBytesRead counts what a body-reading class actually searched, so its clean can say so.
//
// A CLEAN THAT NAMES ITS OWN DENOMINATOR IS THE CHEAPEST DEFENCE AGAINST THIS WHOLE FAMILY OF
// FAULT. "No signature appeared" and "no signature appeared in the 1,482 bytes I read" are the
// same sentence until the number is zero, and then they are opposite sentences. The count goes in
// the reason and in the annotations, so a reader who does not trust the guard can check it.
func pxBodyBytesRead(honest []faOwnObs) (probes, bytes int) {
	for _, o := range honest {
		if !o.Obs.Delivered() || len(o.Obs.Body) == 0 {
			continue
		}
		probes++
		bytes += len(o.Obs.Body)
	}
	return probes, bytes
}
