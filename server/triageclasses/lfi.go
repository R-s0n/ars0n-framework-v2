package triageclasses

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS LFI (id 14). LOCAL FILE INCLUSION AND ARBITRARY FILE OPEN: input names a file and the
// process opens it. NO PAYLOAD IN THIS CLASS CONTAINS A DOT-DOT IN ANY ENCODING.
//
// THAT SENTENCE IS THE CLASS BOUNDARY AND IT IS ENFORCED BY A TEST. Escaping a directory is
// TRAVERSAL's question and it needs TRAVERSAL's confirmation; naming a file outright is this
// class's question and it needs a different one. A merged payload that both escapes and names is
// worse than either: it can be rejected by a path validator that either half would have passed,
// or blocked by a WAF rule neither half trips, and then we cannot tell which happened, so we
// record CLEAN for a mechanism we never tested. A false positive costs the operator scanner
// time. A false negative costs the bug.
//
// WHAT THIS CLASS CAN PROVE THAT NOTHING ELSE CAN. Three oracles, in descending order:
//
//	the data:// marker rule    rank 1, near-zero false positive. The 16 plaintext marker bytes
//	                           were NEVER in the request; only their base64 was. Their appearance
//	                           in the response means the application decoded and emitted, which is
//	                           evaluation and not reflection
//	php://filter base64        a source file comes back base64 encoded, decoded here on the
//	                           PLAINTEXT signatures. It also works inside open_basedir, which is
//	                           where an absolute path does not
//	the errno oracle           the answer to BLIND LFI, and it needs no content at all. A path
//	                           that exists and cannot be read, a path that is a directory, and a
//	                           path that does not exist produce three distinguishable errors.
//	                           Nothing is read: /etc/shadow is never disclosed, only the CLASS of
//	                           error is observed, and it is not time based
//
// WHAT IS DELIBERATELY NOT SENT, EACH WITH ITS REASON. expect://id executes an OS command.
// php://input ships executable code in the body. phar:// triggers object deserialization on
// stream access. zip:// and rar:// need an uploaded archive. Log poisoning through User-Agent
// writes attacker content into a server log, which persists and affects other users. Every one of
// those is refused on safety, is recorded as not_probed, and is an UNKNOWN in the report.

type lfiClassifier struct{ faNoSettle }

func init() { triage.RegisterClassifier(lfiClassifier{}) }

func (lfiClassifier) ID() triage.ClassID { return triage.ClassLFI }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const lfiFilterPrefix = "php://filter/convert.base64-encode/resource="

// lfiNullTrunc is /etc/passwd, a real NUL byte, then the extension the application appends.
var lfiNullTrunc = func() []byte {
	out := []byte("/etc/passwd")
	out = append(out, 0x00)
	return append(out, []byte(faTokExt)...)
}()

const (
	lfiDEC  triage.ProbeID = "LFI-DEC"
	lfiL1   triage.ProbeID = "LFI-L1"
	lfiL1b  triage.ProbeID = "LFI-L1b"
	lfiL2   triage.ProbeID = "LFI-L2"
	lfiL2b  triage.ProbeID = "LFI-L2b"
	lfiL2c  triage.ProbeID = "LFI-L2c"
	lfiL4   triage.ProbeID = "LFI-L4"
	lfiL4b  triage.ProbeID = "LFI-L4b"
	lfiL5   triage.ProbeID = "LFI-L5"
	lfiL5b  triage.ProbeID = "LFI-L5b"
	lfiL6   triage.ProbeID = "LFI-L6"
	lfiL6b  triage.ProbeID = "LFI-L6b"
	lfiL7   triage.ProbeID = "LFI-L7"
	lfiL7b  triage.ProbeID = "LFI-L7b"
	lfiL8   triage.ProbeID = "LFI-L8"
	lfiL8b  triage.ProbeID = "LFI-L8b"
	lfiL10  triage.ProbeID = "LFI-L10"
	lfiL12  triage.ProbeID = "LFI-L12"
	lfiL12b triage.ProbeID = "LFI-L12b"
	lfiL13  triage.ProbeID = "LFI-L13"
	lfiL14  triage.ProbeID = "LFI-L14"
	lfiL15  triage.ProbeID = "LFI-L15"
	lfiL16  triage.ProbeID = "LFI-L16"
	lfiL14w triage.ProbeID = "LFI-L14w"
	lfiL15w triage.ProbeID = "LFI-L15w"
	lfiL16w triage.ProbeID = "LFI-L16w"
	lfiL17  triage.ProbeID = "LFI-L17"
	lfiL18  triage.ProbeID = "LFI-L18"
	lfiNC1  triage.ProbeID = "LFI-NC1"
	lfiNC3  triage.ProbeID = "LFI-NC3"
	lfiNC4  triage.ProbeID = "LFI-NC4"
	lfiNC5  triage.ProbeID = "LFI-NC5"
)

var lfiValuePoints = []triage.SlotKind{
	triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindHeader, triage.KindCookie,
}

var lfiValueEncoders = []triage.EncoderMode{
	triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodePathSegment,
	triage.EncodeHeaderValue, triage.EncodeCookie, triage.EncodeMultipartValue,
}

// Probes declares every payload this class will ever send.
//
// LFI-L16 CARRIES TWO ROLES AND IS CHARGED ONCE: it is the ENOENT arm of the errno oracle and it
// is the content-signature negative control, because "a path under /etc that does not exist" is
// the same request for both. LFI-NC2 in the catalogue is these same bytes and is not declared
// again here; declaring it would spend a request proving something already proven.
func (lfiClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassLFI
	full := triage.TierFull
	reduced := triage.TierReduced
	pathOnly := []triage.SlotKind{triage.KindPath}
	return []triage.ProbeSpec{
		{
			ID: lfiDEC, Class: c, Logical: []byte(faTokValue + "%6c%66%2d%64%65%63%2d%31%34"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, Tier: reduced, Risk: triage.RiskR0,
			Notes: "THIS CLASS'S OWN decode probe (ruling R6a). The percent text decodes to lf-dec-14, " +
				"which is this class's and nobody else's: the catalogue row percent-encodes the marker, " +
				"and a marker cannot be written into a template because it is minted per run, so two " +
				"classes doing that would ship byte-equal templates and fail the isolation check at " +
				"build time. Recorded as a deliberate divergence. The answer matters more here than " +
				"almost anywhere else, because a path slot that does not decode makes %2F unusable and " +
				"L17 and L18 exist for exactly that case",
		},
		{
			ID: lfiL1, Class: c, Logical: []byte("/etc/passwd"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0,
			Notes: "the absolute-path form, language neutral, always sent. Safe to read and reliably " +
				"present. Its signature is anchored at line start so it cannot match prose",
		},
		{
			ID: lfiL1b, Class: c, Logical: []byte("/proc/version"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the second Linux signature, so two unrelated anchored signatures are reachable. " +
				"A /proc pseudo-file reports size 0, so an empty body with Content-Length: 0 is " +
				"proc_zero_length and is NOT this detector staying silent",
		},
		{
			ID: lfiL2, Class: c, Logical: []byte("C:/Windows/win.ini"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0,
			Notes: "the Windows absolute path with forward slashes, which every Windows API accepts " +
				"and which survives a filter that only knows about backslashes",
		},
		{
			ID: lfiL2b, Class: c, Logical: []byte(`C:\Windows\win.ini`),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the backslash form. VERIFIED: a raw backslash cannot survive url.Parse in a path " +
				"segment, where it becomes %5C, so this is the query, form, JSON, header and cookie form",
		},
		{
			ID: lfiL2c, Class: c, Logical: []byte(`C:\Windows\System32\drivers\etc\hosts`),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the second Windows signature. VERIFIED exact on Windows 11 Pro 10.0.26200, and the " +
				"file opens with a UTF-8 BOM, which is why the signature is anchored at a LINE start. It " +
				"is also why lfimap's shipped base64 constant for this file cannot match a real read",
		},
		{
			ID: lfiL4, Class: c, Logical: []byte("file:///etc/passwd"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0,
			Notes: "the file: scheme, which reaches a URL-shaped sink that an absolute path does not. " +
				"On Java it is the difference between new File() and new URL(), and the error text says " +
				"which",
		},
		{
			ID: lfiL4b, Class: c, Logical: []byte("file:///C:/Windows/win.ini"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the Windows twin of L4.",
		},
		{
			ID: lfiL5, Class: c, Logical: []byte(lfiFilterPrefix + "/etc/passwd"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0,
			Notes: "the PHP filter wrapper, and it is sent UNCONDITIONALLY in tier 2 even when tier 1 " +
				"was silent. A wrapper works on endpoints where an absolute path does not, and gating it " +
				"on tier 1 would be an intra-class shared gate: the same mistake as a cross-class one, " +
				"committed inside a single class",
		},
		{
			ID: lfiL5b, Class: c, Logical: []byte(lfiFilterPrefix + "C:/Windows/win.ini"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the Windows twin of L5, for a PHP stack on Windows, which is a real deployment.",
		},
		{
			ID: lfiL6, Class: c, Logical: []byte(lfiFilterPrefix + faTokScript),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the application's OWN script, derived from the vector URL. This is the probe that " +
				"works inside open_basedir, where /etc is unreachable by construction, and it produces " +
				"SOURCE DISCLOSURE, which is a stronger finding than a passwd read on most applications",
		},
		{
			ID: lfiL6b, Class: c, Logical: []byte(lfiFilterPrefix + "index.php"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the relative fallback for L6 when the URL gives no usable script name.",
		},
		{
			ID: lfiL7, Class: c, Logical: []byte("data://text/plain;base64," + faTokMarkerB64),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0,
			Notes: "THE RANK 1 ORACLE. The 16 plaintext marker bytes are never in the request, only " +
				"their base64 is, so their appearance in the response means the application decoded and " +
				"emitted. It carries no code of any kind: text/plain and sixteen base36 characters. If " +
				"BOTH the plaintext and the literal base64 come back, that is suspicious " +
				"(data_both_present) and not a finding, because a display layer may have decoded it for " +
				"rendering",
		},
		{
			ID: lfiL7b, Class: c, Logical: []byte("data:text/plain," + faTokMarker),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the single-colon, unencoded data URI, for a stream layer that accepts the RFC 2397 " +
				"form and not the two-slash one. It cannot prove decoding (the plaintext was in the " +
				"request), so a hit here is weaker than L7 and is scored as such",
		},
		{
			ID: lfiL8, Class: c, Logical: []byte("/proc/self/environ"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0,
			Notes: "the process environment, which on a Node, Python, Ruby or Go stack is frequently " +
				"the only readable thing with a recognisable shape. Detected structurally (NUL-separated " +
				"NAME=VALUE tokens with a real PATH), never by a substring, because 'PATH=/' appears in " +
				"shell documentation and in JSON",
		},
		{
			ID: lfiL8b, Class: c, Logical: []byte("/proc/self/cmdline"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the process command line, NUL separated, same structural detection.",
		},
		{
			ID: lfiL10, Class: c, Logical: lfiNullTrunc,
			Encoders:  lfiValueEncoders,
			Points:    []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath},
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "legacy null truncation of an appended extension. A NUL is neither field-vchar nor " +
				"cookie-octet, so this is not_reachable (header_nul) and (cookie_nul) on those points, " +
				"and Go's transport refuses an invalid header value loudly rather than silently. A hit " +
				"here also brackets the PHP version at below 5.3.4",
		},
		{
			ID: lfiL12, Class: c, Logical: []byte("/WEB-INF/web.xml"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "Java. When the sink is getResourceAsStream the root is the classpath and " +
				"/etc/passwd is unreachable by construction, so the language-neutral ladder would report " +
				"a clean on a live bug. The xmlns value also distinguishes javaee from jakartaee",
		},
		{
			ID: lfiL12b, Class: c, Logical: []byte("/WEB-INF/classes/application.properties"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "Spring Boot's own configuration, same classpath reasoning as L12.",
		},
		{
			ID: lfiL13, Class: c, Logical: []byte("/web.config"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: ".NET, where the sink is usually Server.MapPath and is rooted in the application.",
		},
		{
			ID: lfiL14, Class: c, Logical: []byte("/etc/shadow"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "THE EACCES ARM of the errno oracle. NOTHING IS READ. This file is never disclosed " +
				"by a web user and this class never claims it was: only the CLASS of error is observed. " +
				"The probe is an ordinary read that fails, which is as non-destructive as a request gets",
		},
		{
			ID: lfiL15, Class: c, Logical: []byte("/etc/"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "THE EISDIR ARM: a path that exists and is a directory.",
		},
		{
			ID: lfiL16, Class: c, Logical: []byte("/etc/" + faTokMarker),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "TWO ROLES, ONE REQUEST. The ENOENT arm of the errno oracle, and the content " +
				"signature negative control: a file signature firing on a path that cannot exist means " +
				"the signature is matching an echo or a canned page, and every content verdict on the " +
				"slot becomes cannot_determine (signature_unsound). The catalogue's NC2 is these bytes " +
				"and is not declared twice",
		},
		{
			ID: lfiL14w, Class: c, Logical: []byte(`C:\Windows\System32\config\SAM`),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the Windows EACCES twin: exists, locked by the kernel, sharing violation. Nothing " +
				"is read and nothing is written",
		},
		{
			ID: lfiL15w, Class: c, Logical: []byte(`C:\Windows\`),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the Windows EISDIR twin.",
		},
		{
			ID: lfiL16w, Class: c, Logical: []byte(`C:\Windows\` + faTokMarker),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0, IsControl: true,
			Notes: "the Windows ENOENT twin, and the Windows arm's content-signature control. Both OS " +
				"families get an errno triple, because the class does not know the OS and a triple sent " +
				"at the wrong family is a silent zero dressed as a clean",
		},
		{
			ID: lfiL17, Class: c, Logical: []byte("php:"),
			Encoders: []triage.EncoderMode{triage.EncodePathSegment}, Points: pathOnly,
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "PATH SLOTS ONLY, and it needs no slash at all. When a path segment rejects %2F " +
				"(Apache AllowEncodedSlashes Off answers 404, IIS request filtering answers 400) every " +
				"other payload in this class is undeliverable, and a class with nothing deliverable that " +
				"reported clean would be reporting on the transport rather than on the application. Four " +
				"bytes that provoke a PHP wrapper error are what stops that",
		},
		{
			ID: lfiL18, Class: c, Logical: []byte(`C|/Windows/win.ini`),
			Encoders: []triage.EncoderMode{triage.EncodePathSegment}, Points: pathOnly,
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "the legacy pipe-for-colon Windows drive form, which also needs no leading slash. " +
				"Same reason as L17: a path slot must have something deliverable or its verdict is about " +
				"the transport",
		},
		{
			ID: lfiNC1, Class: c, Logical: []byte(faTokMarker),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: reduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "the bare marker: no slash, no scheme, no dot. It validates every detector at once " +
				"and it establishes the UNKNOWN-VALUE response that the errno oracle differences against. " +
				"Without it, an endpoint that 404s on anything it does not recognise makes all three " +
				"errno arms differ from the baseline and the oracle fires on a slot that never opened a " +
				"file",
		},
		{
			ID: lfiNC3, Class: c, Logical: []byte(lfiFilterPrefix + "/etc/" + faTokMarker),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0, IsControl: true,
			Notes: "validates the base64 CONTENT rule and nothing else. It MAY produce a PHP warning " +
				"and that is EXPECTED and is not a failure of this control: this control is about the " +
				"content detector, and the error detector has its own control in NC4. Conflating the two " +
				"is how a class disables a working detector because a different one behaved correctly",
		},
		{
			ID: lfiNC4, Class: c, Logical: []byte("zqjnotascheme://filter/convert.base64-encode/resource=/etc/passwd"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0, IsControl: true,
			Notes: "validates the PHP WRAPPER ERROR detector. If a scheme PHP has never heard of " +
				"produces the identical 'no suitable wrapper could be found' page as php://, then that " +
				"signature is telling us only that the value is not a filename, and it is disabled for " +
				"the endpoint with reason wrapper_error_unsound. The literal zqjnotascheme is thirteen " +
				"characters, three short of a marker, so it cannot be mistaken for one by the attribution " +
				"machinery",
		},
		{
			ID: lfiNC5, Class: c, Logical: []byte("data://text/plain;base64,enFqbm90bWFya2Vy"),
			Encoders: lfiValueEncoders, Points: lfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0, IsControl: true,
			Notes: "validates the data:// rule. The base64 decodes to zqjnotmarker, which is NOT a " +
				"marker: it shares the three-character anchor and nothing else. So a detector matching " +
				"the anchor trigram alone fires here and is caught, while a detector matching this run's " +
				"actual 16 bytes stays silent. THIS PROBE'S OWN MARKER MUST NOT APPEAR in the response",
		},
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. This class is comfortable almost everywhere, and the cookie is genuinely its best
// non-obvious point: '=' is legal raw (and php://filter/...resource= needs one), ':' and '/' are
// cookie-octet, and NO payload in this class needs a SPACE.
func (lfiClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "every payload but L10 is field-vchar, so the NUL-truncation probe is " +
				"not_reachable (header_nul) here and the rest are deliverable",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "'=' is legal raw, which the filter wrapper needs, and ':' and '/' are " +
				"cookie-octet, and no payload here needs a space; only L10's NUL is impossible " +
				"(not_reachable cookie_nul)",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a JSON string slot takes every payload in this class, including the backslash " +
				"forms, which JSON escapes losslessly; a JSON number slot is json_string_coerced only " +
				"and a 400 there is type_rejection and never clean; a multipart filename takes only the " +
				"read-side probes, never a path that could become a write target; a part Content-Type is " +
				"not_applicable (no_file_sink). Media type seen: " + string(mt),
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "conditional on THIS CLASS'S OWN decode probe. Almost every payload here needs a " +
				"'/', which inside a segment means %2F, which Apache with AllowEncodedSlashes Off answers " +
				"404 and IIS request filtering answers 400. When that happens the answer is " +
				"not_reachable (path_slash) plus L17 and L18, which need no slash, and never a clean " +
				"about a transport that could not carry the payload",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment is never transmitted, so no server-side file open is ever built from it",
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

var lfiNameOrder = regexp.MustCompile(`(?i)(file|path|dir|folder|page|doc|document|template|view|include|require|load|read|open|download|attach|name|src|target|log|report|export|image|img|url|uri|resource|stream)`)

// The tier membership is DATA and not control flow, so a test can assert the one property that
// matters about this ladder without needing a ctx nobody outside package triage can build: tier 2
// is not derived from tier 1's result, it is a list.
var (
	// lfiTier1IDs always run.
	lfiTier1IDs = []triage.ProbeID{lfiDEC, lfiNC1, lfiL1, lfiL2, lfiL16}
	// lfiTier2IDs ALSO always run, even when tier 1 was silent. A PHP wrapper works on endpoints
	// where an absolute path does not, so gating these four on tier 1 would be an intra-class
	// shared gate: the same mistake the isolation law forbids between classes, committed inside
	// one. The saving would be four requests and the cost would be every wrapper-only sink in the
	// corpus recorded as clean.
	lfiTier2IDs = []triage.ProbeID{lfiL4, lfiL5, lfiL7, lfiL8}
	// lfiPathNoSlashIDs is everything deliverable into a path segment that rejects %2F. A path
	// slot must have SOMETHING deliverable or its verdict is a statement about the transport and
	// not about the application.
	lfiPathNoSlashIDs = []triage.ProbeID{lfiDEC, lfiNC1, lfiL17, lfiL18}
)

func lfiRequests(ids []triage.ProbeID, key triage.SlotKey, sub faSubst) []triage.ProbeRequest {
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		out = append(out, faReq(id, key, sub))
	}
	return out
}

// Plan is the tiered ladder. Tier 1 and tier 2 are BOTH unconditional, which is the one thing
// about this ladder that must not be optimised away.
func (c lfiClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if !ctx.Route.Resolved() || ctx.Prelude.Failed() || ctx.Budget.Exhausted() {
		return nil
	}

	sub := faSubstFor(ctx.Slot)
	sub.Script = lfiScriptName(ctx.Vector.ComposedURL)
	key := ctx.Slot.Key
	own := faOwn(ctx.Own)

	// A path slot whose percent handling refuses %2F has exactly two deliverable payloads, and
	// sending the other twenty-eight would record twenty-eight tests of the transport.
	if ctx.Slot.Kind == triage.KindPath && ctx.Slot.Constraints.PctRejected {
		if ctx.Round != 0 {
			return nil
		}
		return lfiRequests(lfiPathNoSlashIDs, key, sub)
	}

	switch ctx.Round {
	case 0:
		return lfiRequests(lfiTier1IDs, key, sub)
	case 1:
		// TIER 2 RUNS EVEN WHEN TIER 1 WAS SILENT. A PHP wrapper works on endpoints where an
		// absolute path does not, so gating this on tier 1 would be an intra-class shared gate,
		// and the only thing it would buy is four requests.
		if lfiStopEarly(own) {
			return nil
		}
		return lfiRequests(lfiTier2IDs, key, sub)
	case 2:
		// Tier 3, on any tier 1 or tier 2 signal: content, an error signature, or a differential
		// that is not flat.
		if lfiStopEarly(own) || !lfiAnySignal(own, ctx) {
			return nil
		}
		reqs := []triage.ProbeRequest{
			faReq(lfiL1b, key, sub),
			faReq(lfiL2b, key, sub),
			faReq(lfiL2c, key, sub),
			faReq(lfiL4b, key, sub),
			faReq(lfiL7b, key, sub),
			faReq(lfiL8b, key, sub),
			faReq(lfiNC3, key, sub),
			faReq(lfiNC4, key, sub),
			faReq(lfiNC5, key, sub),
		}
		// The PHP-specific half is dropped when a non-PHP stack was identified with high
		// confidence, EXCEPT for one L5, because a PHP admin panel behind a Java front end is a
		// real deployment. What was skipped and why is recorded on the verdict.
		if eng := lfiEngine(own); eng == "" || eng == "php" {
			reqs = append(reqs, faReq(lfiL5b, key, sub), faReq(lfiL6, key, sub), faReq(lfiL6b, key, sub))
		}
		if ctx.Slot.Kind != triage.KindHeader && ctx.Slot.Kind != triage.KindCookie {
			reqs = append(reqs, faReq(lfiL10, key, sub))
		}
		return reqs
	case 3:
		// Tier 4, language targeted.
		if lfiStopEarly(own) {
			return nil
		}
		switch lfiEngine(own) {
		case "java":
			return []triage.ProbeRequest{faReq(lfiL12, key, sub), faReq(lfiL12b, key, sub)}
		case "dotnet":
			return []triage.ProbeRequest{faReq(lfiL13, key, sub)}
		default:
			return nil
		}
	case 4:
		// Tier 5, the blind branch. It runs when tiers 1 to 3 were silent and the differential
		// was not flat, and L16 is already sent so the POSIX triple costs two requests.
		if lfiStopEarly(own) || lfiContentFired(own) {
			return nil
		}
		return []triage.ProbeRequest{
			faReq(lfiL14, key, sub),
			faReq(lfiL15, key, sub),
			faReq(lfiL14w, key, sub),
			faReq(lfiL15w, key, sub),
			faReq(lfiL16w, key, sub),
		}
	default:
		return nil
	}
}

// lfiScriptName derives the application's own script from the vector URL, which is what makes L6
// work inside open_basedir. lfimap does the same thing for the same reason.
func lfiScriptName(composed string) string {
	u, err := url.Parse(composed)
	if err != nil {
		return "index.php"
	}
	base := path.Base(u.Path)
	if base == "" || base == "." || base == "/" || !strings.Contains(base, ".") {
		return "index.php"
	}
	return base
}

// lfiStopEarly is this class's own early exit. It is source disclosure, a confirmed content hit,
// or a uniform block, and it is nothing else. "Nothing found yet" is never an early exit here.
func lfiStopEarly(own []faOwnObs) bool {
	if faUniformBlock(faObsOf(own), nil) {
		return true
	}
	for _, o := range own {
		for _, d := range faDecodedRuns(o.Obs.Body, nil) {
			if bytes.HasPrefix(d, []byte("<?php")) || bytes.HasPrefix(d, []byte("<?=")) {
				return true
			}
		}
	}
	return false
}

// lfiAnySignal is the tier 3 promotion rule: content, an error signature, or a non-flat
// differential from THIS CLASS'S OWN probes.
func lfiAnySignal(own []faOwnObs, ctx triage.PlanCtx) bool {
	for _, o := range own {
		if p, _ := faMatchSignatures(lfiContent, o.Obs.Body); len(p) > 0 {
			return true
		}
		if p, _ := faMatchSignatures(lfiStreamErrors, o.Obs.Body); len(p) > 0 {
			return true
		}
		if p, _ := faMatchSignatures(lfiStackErrors, o.Obs.Body); len(p) > 0 {
			return true
		}
		if ctx.Route.Resolved() && faCompare(o.Obs, ctx.Route.Obs()) == faCmpDifferent {
			return true
		}
	}
	return false
}

// lfiContentFired reports whether a content signature fired on a non-control probe.
func lfiContentFired(own []faOwnObs) bool {
	for _, o := range own {
		if lfiIsControl(o.ProbeID) {
			continue
		}
		if p, _ := faMatchSignatures(lfiContent, o.Obs.Body); len(p) > 0 {
			return true
		}
	}
	return false
}

func lfiIsControl(id triage.ProbeID) bool {
	switch id {
	case lfiNC1, lfiNC3, lfiNC4, lfiNC5, lfiL16, lfiL16w, lfiDEC:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// THE data:// RULE, AND THE CONTROL THAT HOLDS IT DOWN
// ---------------------------------------------------------------------------------------------

// lfiDataVerdict is the data:// rule's judgement over one LFI-L7 response.
type lfiDataVerdict string

const (
	// lfiDataSilent: the sixteen marker bytes are not in the response in any form.
	lfiDataSilent lfiDataVerdict = "silent"
	// lfiDataDecoded: the PLAINTEXT marker bytes came back and the base64 text did not. Those
	// bytes were never in the request, so a stream wrapper decoded a value from this slot.
	lfiDataDecoded lfiDataVerdict = "decoded"
	// lfiDataReflected: the base64 text came back, with or without the plaintext beside it. An
	// endpoint that echoes its parameter produces this, and so does a display layer that decodes
	// for rendering. Neither is a file read.
	lfiDataReflected lfiDataVerdict = "reflected"
	// lfiDataEchoed: ONLY the base64 came back, in one of its three phases, and the plaintext did
	// not. Those are the bytes this probe itself put on the wire, so the endpoint has told us
	// nothing but that it echoes. It is kept apart from lfiDataReflected because the two used to
	// share a verdict and the shared verdict text said "the marker plaintext AND the literal
	// base64 both came back", which is FALSE in this case and was the text LFI printed on twelve
	// oracle routes, six of them clean controls. An echo is the one observation in this class that
	// carries no information, so it stops nothing: the remaining oracles still get to speak.
	lfiDataEchoed lfiDataVerdict = "echoed"
)

// lfiBlockRefutedByContent reports whether the uniform-response family that faUniformBlock counted
// is a file read rather than a filter answering.
//
// THE TWO SHAPES ARE THE SAME MEASUREMENT AND ONLY THE BODY TELLS THEM APART. Several distinct
// payloads returning one identical non-baseline body is what a WAF's canned block page looks like,
// and it is equally what /etc/passwd looks like when four encodings of the same path all resolve
// to the same file. MEASURED, exam ef8c13ab: on the oracle's own /lfi route five distinct payloads
// (../../../../etc/passwd, /etc/passwd, ....//....//etc/passwd, the percent-encoded form and the
// NUL-suffixed form) all returned the same 134 bytes of passwd, the block rule fired first, and
// the class returned cannot_determine on its own positive control while returning suspicious on
// twelve routes that had no file sink at all. A block page does not contain root:x:0:0, so when
// the uniform body matches a content signature that is LIVE on this endpoint, the block claim is
// refuted and the content oracle downstream is allowed to judge it.
//
// It takes the live table rather than computing one, so the caller cannot end up asking the block
// rule and the content oracle two different questions about which signatures this endpoint allows.
func lfiBlockRefutedByContent(honest []faOwnObs, baselines [][]byte, live []faSignature) bool {
	if len(live) == 0 {
		return false
	}
	for _, o := range honest {
		if !o.Obs.Delivered() || len(o.Obs.Body) == 0 {
			continue
		}
		if p, _ := faMatchSignatures(live, o.Obs.Body); len(p) > 0 {
			return true
		}
		for _, d := range faDecodedRuns(o.Obs.Body, baselines) {
			if p, _ := faMatchSignatures(live, d); len(p) > 0 {
				return true
			}
		}
	}
	return false
}

// lfiSentBase64 recovers the base64 text THIS probe actually carried.
//
// IT READS THE LOGICAL PAYLOAD AND NOT THE WIRE, and that is the whole bug this function exists
// to have fixed. Payload.Wire is the bytes as the encoder wrote them into the container, so on
// every query, form, cookie and path slot the comma of "base64," is written %2C and a search for
// the literal string "base64," inside the wire can NEVER match. Measured against the oracle: on
// /xss, /redirect, /cmdi and /ssti the wire contained no literal "base64,", the extracted text
// was therefore empty, the control could not fire, and LFI graded four reflecting slots
// finding/high/data_scheme_decoded while staying silent on /lfi. A control that is structurally
// incapable of firing is worse than no control: it reads, in the code and in the verdict, as a
// control that was checked and stayed quiet.
//
// Payload.Logical is what the classifier asked for before any encoder, so it carries the payload
// exactly as lfiL7 declared it with ${m64} resolved. When no logical record survives, the base64
// of the marker is what ${m64} renders to and is used instead, so the control still has something
// to compare against rather than silently degrading to "not echoed".
func lfiSentBase64(o triage.Observation, marker triage.Marker) []byte {
	const anchor = "base64,"
	if i := bytes.Index(o.Payload.Logical, []byte(anchor)); i >= 0 {
		return o.Payload.Logical[i+len(anchor):]
	}
	m := marker
	if m == "" {
		m = o.Marker
	}
	if m == "" {
		return nil
	}
	return []byte(base64.StdEncoding.EncodeToString([]byte(m)))
}

// lfiBase64Echoed reports whether the base64 text this probe sent came back in the response.
//
// It matches the full text AND the phase-trimmed middle that faByteForm's own base64 search
// matches, so the control can demote in exactly the cases the search can fire. A control that
// searched more narrowly than the detector it holds down would leave a gap the shape of the
// difference between them.
func lfiBase64Echoed(o triage.Observation, marker triage.Marker) bool {
	b64 := lfiSentBase64(o, marker)
	if len(b64) <= 8 || len(o.Body) == 0 {
		return false
	}
	if bytes.Contains(o.Body, b64) {
		return true
	}
	return bytes.Contains(o.Body, b64[4:len(b64)-4])
}

// lfiJudgeDataScheme is the data:// rule. It returns the judgement and the marker form that
// produced it.
//
// A BASE64 FORM IS NEVER THE DECODED VERDICT. faByteForm searches for the marker in eleven
// transforms and three of them are base64 phases, so an endpoint that simply echoes the payload
// hands back the marker's base64 and the search reports present. Present-as-base64 is the exact
// opposite of this rule's claim, which is that the SIXTEEN PLAINTEXT BYTES came back when only
// their base64 was sent. So the form is checked, not just the boolean.
func lfiJudgeDataScheme(o triage.Observation, marker triage.Marker) (lfiDataVerdict, string) {
	form, present := faMarkerForm(o.Body, marker)
	if !present {
		return lfiDataSilent, ""
	}
	// Present ONLY as base64 is the bytes we sent coming straight back. It is the opposite of this
	// rule's claim and it is not even a near miss, so it gets its own verdict rather than sharing
	// the both-present one.
	if strings.HasPrefix(form, "base64") {
		return lfiDataEchoed, form
	}
	if lfiBase64Echoed(o, marker) {
		return lfiDataReflected, form
	}
	return lfiDataDecoded, form
}

// lfiEngine identifies the stack from THIS CLASS'S OWN error responses.
func lfiEngine(own []faOwnObs) string {
	for _, o := range own {
		for _, s := range lfiStackErrors {
			if s.Re.Match(o.Obs.Body) {
				return strings.SplitN(s.Name, ".", 2)[0]
			}
		}
		for _, s := range lfiStreamErrors {
			if s.Re.Match(o.Obs.Body) {
				return "php"
			}
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// DETECTION
// ---------------------------------------------------------------------------------------------

// lfiContent is THIS CLASS'S OWN COPY of the content signature table. Anchored, and disjoint from
// every payload in this class, so an echo cannot produce a hit.
var lfiContent = []faSignature{
	{Name: "posix.passwd", Re: regexp.MustCompile(`(?m)^root:[^:\n]{0,64}:0:0:`)},
	{Name: "posix.passwd.corroboration", Corroborating: true,
		Re: regexp.MustCompile(`(?m)^(daemon|bin|sys|nobody|sshd|www-data):[^:\n]{0,64}:[0-9]{1,6}:[0-9]{1,6}:`)},
	{Name: "posix.proc.version", Re: regexp.MustCompile(`(?m)^Linux version [0-9]+\.[0-9]+`)},
	{Name: "win.ini", Re: regexp.MustCompile(`(?m)^; for 16-bit app support\r?$`)},
	{Name: "win.ini.mci", Corroborating: true, Re: regexp.MustCompile(`(?m)^\[mci extensions\]\r?$`)},
	{Name: "win.hosts", Re: regexp.MustCompile(`(?m)^# This is a sample HOSTS file used by Microsoft TCP/IP for Windows\.`)},
	{Name: "php.source", Re: regexp.MustCompile(`\A(<\?php|<\?=)`)},
	{Name: "java.webxml", Re: regexp.MustCompile(`<web-app[ >][\s\S]{0,1000}(<servlet-mapping|<display-name|xmlns="https?://(xmlns\.jcp\.org/xml/ns/javaee|jakarta\.ee/xml/ns/jakartaee)")`)},
	{Name: "spring.properties", Re: regexp.MustCompile(`(?m)^(spring\.[a-z]|server\.port=|management\.)`)},
	{Name: "dotnet.webconfig", Re: regexp.MustCompile(`<configuration[ >][\s\S]{0,1000}(<system\.webServer|<system\.web|<appSettings)`)},
}

// lfiStreamErrors is the PHP stream error table. Each requires baseline absence.
var lfiStreamErrors = []faSignature{
	{Name: "php.nosuchfile", Re: regexp.MustCompile(`failed to open stream: No such file or directory`)},
	{Name: "php.openbasedir", Re: regexp.MustCompile(`failed to open stream: Operation not permitted`)},
	{Name: "php.nowrapper", Re: regexp.MustCompile(`failed to open stream: no suitable wrapper could be found`)},
	{Name: "php.allowurlinclude.off", Re: regexp.MustCompile(`URL file-access is disabled in the server configuration`)},
	{Name: "php.sink", Re: regexp.MustCompile(`(?m)^Warning: (include|require|include_once|require_once|file_get_contents|readfile|fopen|file|highlight_file|show_source)\(`)},
}

// lfiStackErrors is the non-PHP stack table. Each name's first dotted component is the engine id.
var lfiStackErrors = []faSignature{
	{Name: "java.unknownprotocol", Re: regexp.MustCompile(`java\.net\.MalformedURLException: unknown protocol: php`)},
	{Name: "java.filenotfound", Re: regexp.MustCompile(`java\.io\.FileNotFoundException: `)},
	{Name: "dotnet.filenotfound", Re: regexp.MustCompile(`System\.IO\.FileNotFoundException: Could not find file '`)},
	{Name: "dotnet.uriformat", Re: regexp.MustCompile(`System\.UriFormatException`)},
	{Name: "node.enoent", Re: regexp.MustCompile(`ENOENT: no such file or directory, open '`)},
	{Name: "python.errno", Re: regexp.MustCompile(`(FileNotFoundError: \[Errno 2\]|IsADirectoryError: \[Errno 21\]|PermissionError: \[Errno 13\])`)},
	{Name: "ruby.errno", Re: regexp.MustCompile(`Errno::(ENOENT|EACCES|EISDIR)`)},
	{Name: "go.open", Re: regexp.MustCompile(`open [^\s:]+: (no such file or directory|is a directory|permission denied)`)},
}

var lfiEnvNameRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}=`)
var lfiEnvPathRe = regexp.MustCompile(`^PATH=(/[^\x00]*)(:/[^\x00]*)*$`)
var lfiCmdlineFirstRe = regexp.MustCompile(`^(/[A-Za-z0-9._+-]+)+$`)

// lfiEnvironLooksReal is the STRUCTURAL detector for /proc/self/environ.
//
// It is a function and not a regexp because the shape is the evidence: NUL-separated NAME=VALUE
// tokens with a real PATH among them. A plain "PATH=/" substring appears in shell documentation
// and in JSON, and a detector built on it fires on half the internet.
func lfiEnvironLooksReal(body []byte) bool {
	if !bytes.Contains(body, []byte{0x00}) {
		return false
	}
	toks := bytes.Split(body, []byte{0x00})
	named, hasPath := 0, false
	for _, t := range toks {
		if lfiEnvNameRe.Match(t) {
			named++
		}
		if lfiEnvPathRe.Match(t) {
			hasPath = true
		}
	}
	return named >= 3 && hasPath
}

// lfiCmdlineLooksReal is the STRUCTURAL detector for /proc/self/cmdline.
func lfiCmdlineLooksReal(body []byte) bool {
	if !bytes.Contains(body, []byte{0x00}) || bytes.Contains(body, []byte("<")) {
		return false
	}
	first := body
	if i := bytes.IndexByte(body, 0x00); i >= 0 {
		first = body[:i]
	}
	return len(first) > 0 && lfiCmdlineFirstRe.Match(first)
}

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

// Classify. One verdict, one route to clean, every other exit named.
func (c lfiClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{"base64_rule": faDecodeNote}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return []triage.ClassVerdict{{
			Class: triage.ClassLFI, SlotKey: key, State: state, Reason: reason,
			Grade: grade, Oracle: oracle, Ordinals: ords, Annotations: ann, Label: lfiLabel(ann),
		}}
	}
	ann["not_probed_on_safety"] = []string{
		"expect://id executes an OS command",
		"php://input ships executable code in the body",
		"phar:// triggers object deserialization on stream access",
		"zip:// and rar:// need an uploaded archive",
		"log poisoning via User-Agent writes attacker content into a server log, which persists and affects other users",
		"convert.iconv filter chains are long and WAF-visible and are what the confirmation tool is for",
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		switch {
		case !ctx.Route.Resolved():
			return one(triage.StateCannotDetermine,
				"route_unresolved: the composed URL at its observed value did not resolve, so every "+
					"error this class reads would be the route's and not the file sink's",
				"", triage.GradeUnrated, nil)
		case ctx.Prelude.Failed():
			return one(triage.StateCannotDetermine,
				"prelude_failed: the vector needs a token this run could not obtain",
				"", triage.GradeUnrated, nil)
		case ctx.Budget.Exhausted():
			return one(triage.StateNotRun,
				"probe_budget_exhausted: the cap was reached before this class sent anything",
				"", triage.GradeUnrated, nil)
		default:
			return one(triage.StateNotPlanned,
				"no file-open probe was derived for this slot and no reason above applies, which is "+
					"itself worth reporting rather than reading as a clean",
				"", triage.GradeUnrated, nil)
		}
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+
					"), so nothing may be scored",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	var honest []faOwnObs
	var skips []triage.ProbeSkip
	for _, o := range own {
		if why, ok := faWireIsHonest(o.Obs); !ok {
			skips = append(skips, triage.ProbeSkip{ProbeID: o.ProbeID, Reason: why})
			continue
		}
		honest = append(honest, o)
	}
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload was refused, altered or left unsubstituted",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	baselines := faBaselineBodies(ctx)
	ann["baseline_samples_available"] = len(baselines)
	if len(baselines) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_baseline_body: without an unperturbed response the baseline-absence rule cannot run, "+
				"and every content and error signature in this class depends on it",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	// The content table is resolved HERE, above the block gate, because the block gate needs it.
	// Several distinct payloads returning one identical body is a filter answering OR the same file
	// arriving through several encodings, and nothing but the body distinguishes them.
	live, disabled := faDisabledByBaseline(lfiContent, baselines)
	if faUniformBlock(faObsOf(honest), baselines[0]) && !lfiBlockRefutedByContent(honest, baselines, live) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical "+
				"non-baseline responses and none of those bodies carries a file content signature that "+
				"is live on this endpoint, so a filter answered and the file sink was never reached",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// ORACLE 1, RANK 1: the data:// marker rule.
	if l7, ok := faFind(honest, lfiL7); ok {
		judged, form := lfiJudgeDataScheme(l7.Obs, l7.Marker)
		if judged == lfiDataDecoded {
			ann["marker_form"] = form
			v := one(triage.StateFinding,
				"data_decoded: the sixteen plaintext marker bytes came back and the literal base64 text "+
					"did not. Those bytes were never in the request, so the application base64-decoded a "+
					"value it took from this slot and emitted the result, which is evaluation and not "+
					"reflection",
				"data_marker", triage.GradeHigh, ords)
			v[0].Untested = skips
			v[0].Evidence = triage.TriageEvidence{Ordinal: l7.Ordinal, MarkerForm: form, Phrase: "data_scheme_decoded"}
			return v
		}
		if judged == lfiDataEchoed {
			// The endpoint handed back the bytes this probe sent. That is a reflection, it is not
			// evidence of anything in this class, and it must not stop the ladder: the content and
			// error oracles below have not been asked yet. Recorded so the operator can see the
			// rank 1 oracle ran and why it did not answer.
			ann["data_scheme"] = "echoed_only: only the base64 this probe sent came back, so the " +
				"rank 1 oracle is structurally silent on this slot rather than negative"
		}
		if judged == lfiDataReflected {
			v := one(triage.StateSuspicious,
				"data_both_present: the marker plaintext AND the literal base64 both came back, so a "+
					"display layer may have decoded it for rendering rather than a stream wrapper having "+
					"fetched it. Worth a look, and not a finding",
				"data_marker", triage.GradeLow, ords)
			v[0].Untested = skips
			return v
		}
	}
	// Its control. A detector matching the anchor trigram alone fires on NC5 and is caught here.
	if nc5, ok := faFind(honest, lfiNC5); ok {
		if _, present := faMarkerForm(nc5.Obs.Body, nc5.Marker); present {
			ann["control_that_fired"] = "LFI-NC5"
			v := one(triage.StateCannotDetermine,
				"detector_unverified: the data:// control carried a base64 of zqjnotmarker and THIS "+
					"probe's own marker came back anyway, so the marker search is matching the anchor "+
					"trigram rather than this run's sixteen bytes",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}

	// The content-signature control. A hit on a path that cannot exist disables the content
	// detectors for this slot. The table itself was resolved above, where the block gate needed it.
	if len(disabled) > 0 {
		ann["signatures_disabled_by_baseline"] = disabled
	}
	if len(live) == 0 {
		v := one(triage.StateCannotDetermine,
			"signature_in_baseline: every content signature already matches an unperturbed response "+
				"from this endpoint, so none of them can distinguish a read from the page it always serves",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	for _, ctl := range []triage.ProbeID{lfiL16, lfiL16w, lfiNC3} {
		o, ok := faFind(honest, ctl)
		if !ok {
			continue
		}
		hit := false
		if p, _ := faMatchSignatures(live, o.Obs.Body); len(p) > 0 {
			hit = true
		}
		for _, d := range faDecodedRuns(o.Obs.Body, baselines) {
			if p, _ := faMatchSignatures(live, d); len(p) > 0 {
				hit = true
			}
		}
		if hit {
			ann["control_that_fired"] = string(ctl)
			v := one(triage.StateCannotDetermine,
				"detector_unverified (signature_unsound): a file signature fired on a path that cannot "+
					"exist, so it is matching the echo or a canned page rather than a file read",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}

	// ORACLE 2, RANK 2: content, including the base64 half.
	liveStream, _ := faDisabledByBaseline(lfiStreamErrors, baselines)
	wrapperSound := lfiWrapperErrorSound(honest, liveStream)
	if !wrapperSound {
		ann["wrapper_error_unsound"] = "a scheme PHP has never heard of produced the same page as php://, " +
			"so the wrapper-error signature says only that the value is not a filename; every " +
			"wrapper-error verdict on this slot is downgraded to suspicious"
	}
	for _, o := range honest {
		if lfiIsControl(o.ProbeID) {
			continue
		}
		body := o.Obs.Body
		if (o.ProbeID == lfiL1b || o.ProbeID == lfiL8 || o.ProbeID == lfiL8b) && len(body) == 0 {
			ann["proc_zero_length"] = true
			continue
		}
		if o.ProbeID == lfiL8 && lfiEnvironLooksReal(body) {
			v := one(triage.StateFinding,
				"environ_read: the response is NUL-separated NAME=VALUE tokens including a real PATH, "+
					"which is the structure of /proc/self/environ and is not a structure a page produces "+
					"by accident",
				"content_structural", triage.GradeHigh, ords)
			v[0].Untested = skips
			return v
		}
		if o.ProbeID == lfiL8b && lfiCmdlineLooksReal(body) {
			v := one(triage.StateFinding,
				"cmdline_read: NUL-separated tokens whose first is an absolute executable path and with "+
					"no angle bracket anywhere, which is /proc/self/cmdline and not markup",
				"content_structural", triage.GradeHigh, ords)
			v[0].Untested = skips
			return v
		}
		p, corr := faMatchSignatures(live, body)
		viaB64 := false
		for _, d := range faDecodedRuns(body, baselines) {
			dp, dc := faMatchSignatures(live, d)
			if len(dp) > 0 {
				viaB64 = true
			}
			p = append(p, dp...)
			corr = append(corr, dc...)
		}
		if len(p) == 0 {
			continue
		}
		ann["winning_probe"] = string(o.ProbeID)
		ann["via_base64_candidate_rule"] = viaB64
		if len(corr) > 0 {
			ann["corroborating"] = corr[0].Name
		}
		grade := triage.GradeMedium
		reason := "content: an anchored file signature fired on a payload that names a file and " +
			"contains no dot-dot in any encoding, and the same shape with a filename that cannot exist " +
			"stayed silent"
		if p[0].Name == "php.source" {
			grade = triage.GradeHigh
			reason = "source_disclosure: a base64 run absent from every baseline decoded to bytes " +
				"beginning <?php, which is the application's own source coming back through a stream " +
				"wrapper. This works inside open_basedir, where an absolute path does not"
		}
		v := one(triage.StateFinding, reason, "content_signature", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: o.Ordinal, Matched: p[0].Matched, Offset: p[0].Offset, Length: p[0].Length, Phrase: p[0].Name,
		}
		return v
	}

	// ORACLE 3, RANK 3: the PHP stream errors, which identify the sink without reading anything.
	for _, o := range honest {
		if lfiIsControl(o.ProbeID) {
			continue
		}
		p, _ := faMatchSignatures(liveStream, o.Obs.Body)
		if len(p) == 0 {
			continue
		}
		ann["php_sink_signature"] = p[0].Name
		if p[0].Name == "php.allowurlinclude.off" {
			// A FACT, not a suppression. It refutes remote INCLUDE and says nothing about
			// file_get_contents, fopen, copy, simplexml_load_file, DOMDocument::load or
			// getimagesize, every one of which fetches a remote URL by default. RFI is a separate
			// class with its own probes and this annotation suppresses none of them.
			ann["php_allow_url_include_off"] = true
		}
		state := triage.StateFinding
		grade := triage.GradeMedium
		if !wrapperSound {
			state = triage.StateSuspicious
			grade = triage.GradeLow
		}
		v := one(state,
			"php_stream_error: a PHP stream function received this slot's value and said so, which "+
				"identifies the sink exactly and is the strongest non-content evidence available",
			"stream_error", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{Ordinal: o.Ordinal, Matched: p[0].Matched, Offset: p[0].Offset, Length: p[0].Length, Phrase: p[0].Name}
		return v
	}

	// A Java URL sink is a SINK IDENTIFICATION, not a file read, and is reported as such.
	for _, o := range honest {
		if lfiIsControl(o.ProbeID) {
			continue
		}
		for _, s := range lfiStackErrors {
			if s.Name != "java.unknownprotocol" || !s.Re.Match(o.Obs.Body) {
				continue
			}
			inBaseline := false
			for _, b := range baselines {
				if s.Re.Match(b) {
					inBaseline = true
				}
			}
			if inBaseline {
				continue
			}
			ann["java_url_sink"] = true
			v := one(triage.StateSuspicious,
				"java_url_sink: the value reaches new URL() or URI.toURL(), which the unknown-protocol "+
					"error proves precisely. It is not a file read and this class does not claim one, but "+
					"it tells the operator exactly which sink to aim at",
				"stack_error", triage.GradeMedium, ords)
			v[0].Untested = skips
			return v
		}
	}

	// ORACLE 4: the errno oracle, this class's answer to blind LFI.
	if v := c.errno(ctx, honest, ann, ords, skips); v != nil {
		return v
	}

	// Nothing fired. Decide which kind of nothing.
	if ctx.Baseline.Degraded {
		v := one(triage.StateCannotDetermine,
			"degraded: the comparison was degraded, and a degraded comparison can never produce a clean",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if ctx.Slot.Kind == triage.KindPath && ctx.Slot.Constraints.PctRejected {
		v := one(triage.StateCannotDetermine,
			"path_slash: this path segment rejects the percent-encoded slash, so all but two payloads "+
				"in this class were undeliverable. L17 and L18 ran and were silent, which is a statement "+
				"about two payloads and not about the slot",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if ctx.Slot.Constraints.DecodeDepth == 0 && ctx.Slot.Kind == triage.KindPath {
		v := one(triage.StateCannotDetermine,
			"slot_not_decoded: the decode probe showed this slot does not percent-decode, so the "+
				"encoded forms arrived literally and were never the payload we meant to send",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if !faSentAll(honest, lfiNC1, lfiL1, lfiL2, lfiL16) {
		v := one(triage.StateNotRun,
			"incomplete_tier1: this class's tier 1 (NC1, L1, L2, L16) did not all reach the wire, and "+
				"a clean over a partial tier 1 is a clean about payloads that were never sent",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if !faSentAll(honest, lfiL4, lfiL5, lfiL7, lfiL8) {
		v := one(triage.StateNotRun,
			"tier2_not_sent: tier 2 (L4, L5, L7, L8) is unconditional by design, because a wrapper "+
				"works where an absolute path does not. Without it this class has tested absolute paths "+
				"only and must not say clean about the rest",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if lfiErrnoDifferentiated(honest) {
		v := one(triage.StateCannotDetermine,
			"append_suspected: the errno arms differentiated, so a filesystem open is happening on a "+
				"path derived from this slot, and no content came back. On a stack that appends an "+
				"extension and suppresses errors that is exactly what a live inclusion looks like. "+
				"lfimap with its truncation wordlist is the tool for it",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	ann["clean_preconditions"] = []string{
		"tier 1 and the unconditional tier 2 both reached the wire",
		"at least one unperturbed body was available for the baseline-absence rule",
		"at least one content signature was live rather than disabled by the baseline",
		"no negative control fired, including the anchor-trigram control on the marker search",
		"three distinct payloads did not collide on one response",
		"the comparison was not degraded",
		"the errno arms did not differentiate",
	}
	ann["residue_not_covered"] = []string{
		"a response that base64s a GZIPPED file read: see base64_rule, compress/zlib is off the allow-list",
		"convert.iconv filter chains, which are the confirmation tool's job by design",
		"a signed or JWT-wrapped slot, which is signed_wrapper and not this",
	}
	v := one(triage.StateClean,
		"this class's own probes ran, reached the wire, and its own oracles stayed silent with the "+
			"preconditions in the annotations all holding",
		"", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// errno is the blind oracle, and it is the only thing this class has when the file is read and
// never returned.
//
// IT NEEDS NC1 TO REPRODUCE THE BASELINE. Without that condition, an endpoint that 404s on
// anything it does not recognise makes all three arms differ and the oracle fires on a slot that
// never opened a file. And it needs the echo strip, because the three payloads have different
// lengths and an echoing endpoint would otherwise differentiate on nothing but its own echo.
func (lfiClassifier) errno(ctx triage.ClassifyCtx, honest []faOwnObs, ann map[string]any, ords []uint64, skips []triage.ProbeSkip) []triage.ClassVerdict {
	if !ctx.Baseline.Stable {
		ann["errno_oracle"] = "not_run: the stability gate was " + ctx.Baseline.GateReason
		return nil
	}
	nc1, ok := faFind(honest, lfiNC1)
	if !ok {
		ann["errno_oracle"] = "not_run: the bare-marker control was not sent, so there is no unknown-value response to difference against"
		return nil
	}
	if ctx.Route.Resolved() && faCompare(nc1.Obs, ctx.Route.Obs()) != faCmpSame {
		ann["errno_oracle"] = "not_run: the bare-marker control did not reproduce the baseline, so this " +
			"endpoint reacts to any unfamiliar value and a three-way difference would not be about the filesystem"
		return nil
	}
	for _, fam := range [][3]triage.ProbeID{
		{lfiL14, lfiL15, lfiL16},
		{lfiL14w, lfiL15w, lfiL16w},
	} {
		a, okA := faFind(honest, fam[0])
		b, okB := faFind(honest, fam[1])
		d, okC := faFind(honest, fam[2])
		if !okA || !okB || !okC {
			continue
		}
		diff, masked := 0, 0
		for _, p := range [][2]triage.Observation{{a.Obs, b.Obs}, {a.Obs, d.Obs}, {b.Obs, d.Obs}} {
			switch faCompareStripped(p[0], p[1]) {
			case faCmpDifferent:
				diff++
			case faCmpSame:
				if faCompare(p[0], p[1]) == faCmpDifferent {
					masked++
				}
			}
		}
		ann["errno_pairs_differing_after_echo_strip"] = diff
		ann["errno_pairs_explained_by_the_echo"] = masked
		if diff == 0 {
			continue
		}
		if masked > 0 {
			return []triage.ClassVerdict{{
				Class: triage.ClassLFI, SlotKey: ctx.Slot.Key, State: triage.StateMaskedOnly,
				Reason: "the three error conditions differ, but at least one pair's difference " +
					"disappears once the echoed payload is removed, so the endpoint may be reflecting " +
					"rather than opening",
				Oracle: "errno", Grade: triage.GradeLow, Ordinals: ords,
				Annotations: ann, Untested: skips, Label: lfiLabel(ann),
			}}
		}
		return []triage.ClassVerdict{{
			Class: triage.ClassLFI, SlotKey: ctx.Slot.Key, State: triage.StateFinding,
			Reason: "blind_file_open: a path that exists and cannot be read, a path that is a " +
				"directory, and a path that does not exist produced responses that differ from each " +
				"other after the echo was stripped, while the bare marker reproduced the baseline. The " +
				"application is performing a filesystem open on a path it took wholesale from this slot. " +
				"Nothing was read and it is not time based",
			Oracle: "errno", Grade: triage.GradeMedium, Ordinals: ords,
			Annotations: ann, Untested: skips, Label: lfiLabel(ann),
		}}
	}
	return nil
}

// lfiErrnoDifferentiated is the weaker question the append-suspected branch asks.
func lfiErrnoDifferentiated(honest []faOwnObs) bool {
	a, okA := faFind(honest, lfiL14)
	b, okB := faFind(honest, lfiL15)
	if !okA || !okB {
		return false
	}
	return faCompareStripped(a.Obs, b.Obs) == faCmpDifferent
}

// lfiWrapperErrorSound implements NC4: if a scheme PHP has never heard of produces the same
// wrapper error as php://, the signature means only "not a filename".
func lfiWrapperErrorSound(honest []faOwnObs, liveStream []faSignature) bool {
	nc4, ok := faFind(honest, lfiNC4)
	if !ok {
		return true // untested, and the caller records that rather than assuming either way
	}
	l5, ok := faFind(honest, lfiL5)
	if !ok {
		return true
	}
	nc4Hit := false
	for _, s := range liveStream {
		if s.Name == "php.nowrapper" && s.Re.Match(nc4.Obs.Body) {
			nc4Hit = true
		}
	}
	if !nc4Hit {
		return true
	}
	return faCompare(nc4.Obs, l5.Obs) != faCmpSame
}

// lfiLabel is what the operator and lfimap are handed.
func lfiLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"tool_caution": "lfimap's heuristics module sends an XSS polyglot, a CRLF polyglot, a " +
			"SQL-error probe and an open-redirect probe from inside the file-inclusion tool, and its " +
			"checkPayload keyword list mixes file signatures with XSS strings. That is the merged " +
			"design the isolation law forbids. Use it to confirm LFI and ignore its XSS, CRLF, SQLi " +
			"and open-redirect claims entirely",
		"run_with": "lfimap --filter, --file and --data cover exactly the payload families this " +
			"class labelled; the filter-chain module covers the convert.iconv residue this class " +
			"deliberately does not send",
		"hand_over": "the identified language, the sink function name if disclosed, the document " +
			"root, whether open_basedir is set, whether allow_url_include is off, and the single " +
			"payload that produced the hit, so the tool starts from a known-good vector",
	}
	if v, ok := ann["php_sink_signature"]; ok {
		hints["sink_signature"] = fmt.Sprint(v)
	}
	if v, ok := ann["php_allow_url_include_off"]; ok && v == true {
		hints["rfi_note"] = "allow_url_include is off, which refutes a remote INCLUDE and says nothing " +
			"about file_get_contents, fopen, copy, simplexml_load_file, DOMDocument::load or " +
			"getimagesize. RFI is its own class with its own probes and this fact suppresses none of them"
	}
	return triage.TriageLabel{Tools: []string{"lfimap", "lfihunt"}, Engine: "", Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (lfiClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "wrapper_pair", Probes: []triage.ProbeID{lfiL5, lfiNC3},
			Rule: "the base64 candidate rule yields passwd plaintext on the real resource and nothing " +
				"on the same wrapper pointed at a file that cannot exist. A PHP warning on the negative " +
				"half is EXPECTED and does not fail it: that half validates the content detector, not the " +
				"error detector",
		},
		{
			Name: "wrapper_error_soundness", Probes: []triage.ProbeID{lfiL5, lfiNC4},
			Rule: "a scheme PHP has never heard of must produce a DIFFERENT response from php://. If " +
				"the two pages are identical the wrapper-error signature is telling us only that the " +
				"value is not a filename, and every wrapper-error verdict on the slot downgrades to " +
				"suspicious",
		},
		{
			Name: "errno_triple", Probes: []triage.ProbeID{lfiL14, lfiL15, lfiL16, lfiNC1},
			Rule: "unreadable, directory and absent differ from each other after the echo strip, while " +
				"the bare marker reproduces the baseline. Nothing is read, nothing is written, and it is " +
				"not time based",
		},
		{
			Name: "data_decode", Probes: []triage.ProbeID{lfiL7, lfiNC5},
			Rule: "this run's sixteen marker bytes appear and their literal base64 does not, while the " +
				"control's zqjnotmarker payload leaves this probe's marker absent. The second half is " +
				"what catches a search matching the anchor trigram alone",
		},
	}
}

func (lfiClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "decoded_source", Kind: "content", What: "the decoded plaintext of the base64 run that matched, which for L6 is the application's own source"},
		{Name: "sink_function", Kind: "error_path", What: "the exact PHP function named in the Warning line: include, require, file_get_contents, readfile, fopen, highlight_file or show_source"},
		{Name: "open_basedir", Kind: "annotation", What: "'Operation not permitted' means it is set, which is why L6 targets the application's own script"},
		{Name: "allow_url_include", Kind: "annotation", What: "a FACT handed to RFI's operator, never a suppression of RFI's probes"},
		{Name: "php_version_bracket", Kind: "annotation", What: "L10 succeeding implies below 5.3.4; L5 succeeding while L10 fails implies a modern PHP"},
		{Name: "errno_differential", Kind: "differential", What: "which arms differed after the echo strip, so the operator can see the oracle's working"},
		{Name: "document_root", Kind: "error_path", What: "the absolute path quoted in any stack's file error"},
	}
}

// OracleCases. /lfi/errno is the only route that can verify the blind oracle at all, and
// /lfi/allowlist is the only route on which a clean from this class is legitimate.
func (lfiClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "php_wrapper_layer", Route: "/lfi/wrapper", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{lfiL5, lfiL6, lfiL7}, WantState: triage.StateFinding,
			Why: "a PHP-like stream layer honouring php://filter and data://. Without it the rank 1 " +
				"oracle in this class has never been observed firing",
		},
		{
			Name: "absolute_path_read", Route: "/lfi", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{lfiL1}, WantState: triage.StateFinding,
			Why: "already returns a canned passwd",
		},
		{
			Name: "fixed_allowlist", Route: "/lfi/allowlist", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{lfiL1, lfiL5, lfiL7, lfiNC1}, WantState: triage.StateClean,
			Why: "a fixed allow-list: nothing reaches a file open, the responses DIFFER from each " +
				"other so it is not a uniform block, and clean here is legitimate and must carry its " +
				"probe ordinals. It is the only route in this class's set where a clean is the right " +
				"answer, which is what makes it the route that proves the class can produce one honestly",
		},
		{
			Name: "blind_errno", Route: "/lfi/errno", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{lfiL14, lfiL15, lfiL16, lfiNC1}, WantState: triage.StateFinding,
			Why: "three distinguishable error classes and NO content at all, so the errno oracle fires " +
				"and the content oracle cannot. It is the only route that can verify the blind oracle",
		},
		{
			Name: "errno_but_only_echo", Route: "/lfi/errnoecho", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{lfiL14, lfiL15, lfiL16}, WantState: triage.StateMaskedOnly,
			Why: "echoes the parameter and opens nothing, so the three arms differ by length alone. " +
				"The echo strip must collapse them and the verdict must be masked_only, not a finding. " +
				"This is the one false positive the blind oracle is genuinely exposed to and it has no " +
				"fixture anywhere today",
		},
		{
			Name: "bogus_scheme_same_page", Route: "/lfi/wrapperprose", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{lfiL5, lfiNC4}, WantState: triage.StateSuspicious,
			Why: "answers 'no suitable wrapper could be found' to every unrecognised scheme including " +
				"zqjnotascheme. The wrapper-error detector must be marked unsound and every wrapper " +
				"verdict downgraded, rather than a finding being emitted",
		},
		{
			Name: "jwt_and_png_data_uri", Route: "/clean/b64noise", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{lfiL5, lfiL7}, WantState: triage.StateClean,
			Why: "a response carrying a JWT and a PNG data URI must produce ZERO base64 hits. A JWT " +
				"decodes to {\"alg\", which matches no signature, and both runs are in the baseline so " +
				"they are never decoded at all. This is the control for the rule that replaced every " +
				"base64 signature",
		},
		{
			Name: "baseline_already_shows_passwd", Route: "/clean/passwddoc", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{lfiL1}, WantState: triage.StateCannotDetermine,
			Why: "shared with TRAVERSAL: each class must reach signature_in_baseline from its own " +
				"probes, and neither may read the other's conclusion",
		},
		{
			Name: "reflection_is_not_injection", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{lfiL1, lfiL5, lfiL7, lfiNC1}, WantState: triage.StateClean,
			Why: "reflects the payload and opens nothing. The data:// rule must stay silent because " +
				"the base64 comes back and the plaintext does not, which is the exact discrimination that " +
				"rule exists to make",
		},
		{
			Name: "empty_204", Route: "/clean/empty204", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{lfiL1, lfiL14, lfiL15, lfiL16}, WantState: triage.StateCannotDetermine,
			Why: "no body on the baseline or on any probe. 'Identical bodies, therefore same' would " +
				"make the errno oracle report clean on an endpoint it could not see at all",
		},
	}
}
