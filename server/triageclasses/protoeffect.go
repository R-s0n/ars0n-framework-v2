package triageclasses

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// THE PROTOCOL-EFFECT FAMILY: shared MECHANISM, and not one shared payload byte.
//
// Three classes live here and they are three classes on purpose. REDIRECT(18) proves the
// application put an authority WE named into a Location the protocol acts on. CRLF(19) proves the
// application emitted a response header whose NAME we chose. HOSTHDR(20) proves a routing header
// we sent either changed which route ran or reached the authority of a URL the application built.
// Three different fixes, three different tools, three different severities.
//
// WHAT THEY HAVE IN COMMON, AND WHY IT IS WORTH A FILE. All three read the RESPONSE ENVELOPE
// rather than the response body. That is what puts them at oracle rank 5 (protocol effect) rather
// than rank 7 (reflection), and it is the single distinction every one of them can get wrong in
// the same way: a marker in the body is not a marker in a header, a marker in a Location's PATH is
// not a marker in its AUTHORITY, and a header NAME appearing in prose is not a header. Each of
// those three mistakes turns the class into a detector that fires on every application that echoes
// anything. So the authority test, the header-name lookup and the URL resolution live here, once,
// with the rules written down, instead of three times with three sets of bugs.
//
// WHAT THIS FILE HOLDS AND WHAT IT DOES NOT. It holds mechanism. It holds NO payload bytes, NO
// hostnames, NO header names and NO signature tables: those are per class, because the isolation
// law is about what goes on the wire and a shared helper that formats bytes cannot make a hit
// ambiguous, while a shared PAYLOAD can. fileaccess.go draws the same line for the file family and
// says so in the same words.
//
// AND IT REUSES fileaccess.go's GENERIC HALF RATHER THAN COPYING IT. faOwn, faWireIsHonest,
// faOrdinals, faFind, faBaselineBodies, faOracleCase, faConfirmer and faEvidencer carry no payload
// and no signature; they are the vault read, the fail-closed wire check and the extension-surface
// types, and every class in the package needs exactly those. A second copy of the vault read is a
// second place for the refused-read case to be dropped, and dropping a refused read is how a class
// counts one fewer probe and still reports clean. One copy, reused, with this paragraph as the
// note that it was a decision and not an accident.

// ---------------------------------------------------------------------------------------------
// 1. THE REQUEST, AND WHY THIS FAMILY MINTS ITS OWN
// ---------------------------------------------------------------------------------------------

// pxReq builds one ProbeRequest for this family.
//
// It is not faReq. faReq writes the file family's seven substitution keys (v, dir, ext, script,
// sib, oob, encoder) into every Variant, and the runner only honours the dollar grammar for
// ClassTraversal, ClassLFI and ClassRFI (triageRun.go, triageUsesDollarTokens). A class outside
// that list that shipped those keys would be declaring a contract nothing performs, and the next
// reader would reasonably assume the values arrive.
//
// SO THIS FAMILY SPELLS triage.MarkerPlaceholder AND NOTHING ELSE. That token is substituted for
// EVERY class, unconditionally, in step 1 of triageRenderPayload, and a payload that still carries
// it when the encoder is reached is REFUSED rather than sent. That is the whole token contract
// available to a class outside the file family, and every payload in these three classes is built
// to need only it.
//
// The Marker field is left at its zero value ON PURPOSE: the runner mints it from this class's
// R12 ordinal stripe, and a class that filled it in could name an ordinal belonging to another
// class and have its probe attributed there.
func pxReq(id triage.ProbeID, slot triage.SlotKey) triage.ProbeRequest {
	return triage.ProbeRequest{Spec: id, Slot: slot, Variant: map[string]string{}}
}

// pxReqWithEncoder is pxReq for a probe that needs a NAMED encoder rather than the first declared
// one the slot accepts. CRLF-Q4 is the only user: its bytes are percent TEXT and it must reach the
// wire with the percent signs unescaped, which is what EncodeLiteralPct is for. A named mode the
// slot cannot take refuses that one request and says why, rather than being silently swapped for
// a working one, which is the behaviour triageEncoderFor documents and the behaviour this family
// wants: a probe that tested a different encoding than the one it claims is worse than no probe.
func pxReqWithEncoder(id triage.ProbeID, slot triage.SlotKey, mode triage.EncoderMode) triage.ProbeRequest {
	r := pxReq(id, slot)
	r.Variant["encoder"] = string(mode)
	return r
}

// ---------------------------------------------------------------------------------------------
// 2. THE FAIL-CLOSED WIRE CHECK
// ---------------------------------------------------------------------------------------------

// pxWireIsHonest is faWireIsHonest plus the one check faWireIsHonest cannot make for this family.
//
// faWireIsHonest tests the file family's ${...} grammar. This family's only token is
// triage.MarkerPlaceholder, and the consequence of shipping it raw is exactly as bad: a payload
// reading `\r\nX-Zqj-Crlf:<marker>` on the wire has no marker in it, so the oracle looks for a
// value that was never sent, finds nothing, and the class reads that silence as the application's
// answer. The runner refuses such a probe at render time, so in a correct build this can never
// fire; it is here because "in a correct build" is the sentence in front of every silent zero this
// layer has already shipped.
func pxWireIsHonest(o triage.Observation) (string, bool) {
	if why, ok := faWireIsHonest(o); !ok {
		return why, false
	}
	for _, b := range [][]byte{o.Payload.Wire, o.Payload.Logical} {
		if bytes.Contains(b, []byte(triage.MarkerPlaceholder)) {
			return "marker_placeholder_not_substituted(" + triage.MarkerPlaceholder +
				" reached the wire, so this probe carries no marker and its oracle searches for a value nobody sent)", false
		}
	}
	return "", true
}

// pxHonest splits a resolved own-set into the probes that reached the wire intact and a skip row
// for every one that did not. Every unsent probe gets a row: a class that quietly measured fewer
// probes on one slot than another is the shape of a silent zero.
func pxHonest(own []faOwnObs) (honest []faOwnObs, skips []triage.ProbeSkip) {
	for _, o := range own {
		if why, ok := pxWireIsHonest(o.Obs); !ok {
			skips = append(skips, triage.ProbeSkip{ProbeID: o.ProbeID, Reason: why})
			continue
		}
		honest = append(honest, o)
	}
	return honest, skips
}

// pxNotObserved names every probe this class asked for that produced no observation at all.
//
// A PLANNED PROBE WITH NO RESPONSE IS NOT A PROBE THAT FOUND NOTHING. The runner drops a request
// for four separate reasons a classifier cannot see from inside Classify: the operator's tier did
// not buy it, the operator's risk ceiling refused it, the per-slot or per-run budget bit, or the
// encoder could not reach this slot with the mode the probe declared. Each of those is recorded on
// the coverage row, and none of them is visible in ctx.Own, so a class that only counted what came
// back would present a two-probe answer as if the whole ladder had run.
func pxNotObserved(planned []triage.ProbeID, own []faOwnObs) []triage.ProbeSkip {
	seen := map[triage.ProbeID]bool{}
	for _, o := range own {
		seen[o.ProbeID] = true
	}
	var out []triage.ProbeSkip
	for _, id := range planned {
		if seen[id] {
			continue
		}
		out = append(out, triage.ProbeSkip{ProbeID: id, Reason: "probe_not_observed: this class planned " +
			string(id) + " and no response was recorded for it. The refusal is on the coverage row, not here: " +
			"a tier the operator did not buy, a risk ceiling, the per-slot or per-run budget, or an encoder that " +
			"cannot reach this slot. Whichever it was, nothing about this payload was measured on this slot"})
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 3. URL RESOLUTION, THE TWO MODELS, AND THE MEASUREMENTS BEHIND THEM
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THIS MACHINE, go 1.x net/url, base http://app.example.test/a/b?next=x:
//
//	reference                          net/url ResolveReference host
//	http://H.rdr.invalid/              H.rdr.invalid
//	//H.rdr.invalid/                   H.rdr.invalid
//	////H.rdr.invalid/                 app.example.test      (path ////H.rdr.invalid/)
//	https:H.rdr.invalid/               ""                    (opaque, no authority at all)
//	\/\/H.rdr.invalid/                 app.example.test      (path /a/%5C/%5C/H.rdr.invalid/)
//	/\/H.rdr.invalid/                  app.example.test      (path /%5C/H.rdr.invalid/)
//	H.rdr.invalid/                     app.example.test      (path /a/H.rdr.invalid/)
//	/H-rdr-local                       app.example.test
//	/login?next=%2F%2FH.rdr.invalid    app.example.test
//	https://app.example.test@H.rdr...  H.rdr.invalid
//	//H%00.rdr.invalid/                PARSE ERROR: invalid URL escape "%00"
//
// FOUR THINGS FALL OUT OF THAT TABLE AND THEY SHAPE THE WHOLE REDIRECT CLASS.
//
// (a) Go's RFC 3986 resolution keeps three of the classic filter bypasses ON ORIGIN. A class that
// used only net/url would score ////evil, \/\/evil and /\/evil as harmless and report clean on
// three real open redirects, because the browser that follows the Location is not net/url.
//
// (b) So there has to be a second model, and it has to be written down rather than guessed at.
// pxBrowserForm below performs exactly three WHATWG normalisations, each named, and nothing else.
//
// (c) The two models DISAGREEING is itself the interesting signal and it is not a finding. A
// server-side validator that used the strict reading and a browser that uses the loose one is
// precisely the bug, and it is also precisely the case no HTTP-level tool can confirm. It is
// reported as suspicious with the disagreement in the annotations, and the reason says no browser
// was in the loop.
//
// (d) %00 is not parseable by net/url at all, so the null-byte bypass cannot be modelled here. It
// is not shipped. See redirect.go's NOT DOING note.

// pxBrowserForm applies the three WHATWG URL Standard behaviours that make a reference a browser
// follows differ from the reference RFC 3986 resolves.
//
// Each is a named state in the standard and nothing else is done here. This is deliberately a
// SMALL, AUDITABLE transform rather than a URL parser: a second parser would have a second set of
// bugs and no way to tell which of the two was wrong.
//
//  1. BACKSLASH IS A SLASH. In a special URL (http, https, ws, wss, ftp, file) the standard treats
//     U+005C as U+002F everywhere a slash is expected.
//  2. EXTRA LEADING SLASHES ARE IGNORED. The "special authority ignore slashes state" consumes any
//     run of slashes before the authority, so ////host is //host to a browser and a path to
//     net/url.
//  3. A SPECIAL SCHEME MAY OMIT ITS SLASHES. From the scheme state, when the reference's scheme is
//     special and differs from the base's, the parser enters the special authority slashes state,
//     which tolerates the missing "//", so https:host is https://host to a browser and an opaque
//     reference to net/url.
//
// NOT MODELLED, AND NAMED SO NOBODY READS SILENCE AS COVERAGE: percent-encoded and NUL-truncated
// authorities, IDNA and full-width character mapping, and userinfo edge cases. Each of those is a
// real bypass family and each needs a real parser to model honestly.
func pxBrowserForm(ref string) string {
	// (1) backslash is a slash.
	out := strings.ReplaceAll(ref, `\`, "/")

	// (3) a special scheme with no slashes after the colon. Checked BEFORE (2) so that the slash
	// run counted in (2) is the one that actually precedes an authority.
	for _, scheme := range []string{"http:", "https:"} {
		if len(out) > len(scheme) && strings.EqualFold(out[:len(scheme)], scheme) && out[len(scheme)] != '/' {
			out = out[:len(scheme)] + "//" + out[len(scheme):]
			break
		}
	}

	// (2) a leading run of three or more slashes collapses to two. Two is left alone: it is
	// already the scheme-relative form and both models agree on it. A run inside the reference,
	// after a scheme or after the authority, is a path and is not touched.
	if i := strings.Index(out, "://"); i >= 0 {
		head, rest := out[:i+3], out[i+3:]
		return head + strings.TrimLeft(rest, "/")
	}
	if n := len(out) - len(strings.TrimLeft(out, "/")); n >= 3 {
		return "//" + strings.TrimLeft(out, "/")
	}
	return out
}

// pxResolution is one reading of a Location header.
type pxResolution struct {
	// Model is "strict" (RFC 3986, net/url) or "browser" (pxBrowserForm then RFC 3986).
	Model string
	// Host is the resolved authority's host, lowercased, WITHOUT the port. Empty when the
	// reference resolved to no authority at all, which is what an opaque reference does.
	Host string
	// Resolved is the whole resolved URL, for the evidence row.
	Resolved string
	// Err is set when the reference could not be parsed. It is kept rather than dropped: a
	// Location this layer cannot parse is a Location whose destination is unknown, and unknown is
	// not "stayed on origin".
	Err string
}

// pxResolveBoth reads a raw Location against a base URL under both models.
//
// The base is the REQUEST url. Observation.FinalURL is set to the request template's URL by the
// runner (it does not follow redirects, so there is no final URL in the usual sense), and reading
// it as the redirect TARGET is a mistake worth naming here because the field name invites it.
func pxResolveBoth(base, loc string) (strict, browser pxResolution) {
	return pxResolveOne("strict", base, loc), pxResolveOne("browser", base, pxBrowserForm(loc))
}

func pxResolveOne(model, base, ref string) pxResolution {
	out := pxResolution{Model: model}
	b, err := url.Parse(base)
	if err != nil || b.Host == "" {
		out.Err = "base_url_unusable: the request URL recorded on the observation is not absolute, so no reference can be resolved against it"
		return out
	}
	r, err := url.Parse(ref)
	if err != nil {
		out.Err = "location_unparseable: " + err.Error()
		return out
	}
	res := b.ResolveReference(r)
	out.Host = strings.ToLower(res.Hostname())
	out.Resolved = res.String()
	return out
}

// pxHostname is the host of an absolute URL, lowercased and portless, or empty.
func pxHostname(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// ---------------------------------------------------------------------------------------------
// 4. THE AUTHORITY-POSITION TEST, WHICH IS THE WHOLE DIFFERENCE BETWEEN RANK 5 AND RANK 7
// ---------------------------------------------------------------------------------------------

// pxAuthorityDelimiters are the bytes that may legally follow a host inside a URL. Anything else
// after the host means the match is a longer name that merely starts with ours, so it is not our
// host at all.
const pxAuthorityDelimiters = "/:?#\"'<>) \t\r\n,;]}\\`&|"

// pxHostInAuthorityPosition reports whether host appears in b as the AUTHORITY of a URL, and at
// what offset.
//
// THIS IS THE FUNCTION THAT STOPS THIS FAMILY BEING A REFLECTION DETECTOR. An application that
// prints X-Forwarded-Host into a debug block has told the operator nothing exploitable; an
// application that builds https://<our host>/reset?token=... has handed over every password reset
// link on the site. Both contain the same 20 bytes. The difference is entirely positional, and a
// class that searched for the bytes would report the first as the second on every framework with a
// verbose error page.
//
// THE RULE. The host must be immediately preceded by "//" or by "@" (the userinfo separator, so
// https://user@evil/ counts), the byte before that run must not itself be a host character, and
// the host must be followed by end-of-input or one of pxAuthorityDelimiters. The comparison is
// case-insensitive because DNS is.
//
// IT DELIBERATELY DOES NOT PARSE. A parser over a response body has to decide where each candidate
// URL starts, and every heuristic for that is a second place to be wrong. Two anchors and a
// delimiter set is a rule a reader can check by eye, and its failure mode is a missed hit rather
// than an invented one.
func pxHostInAuthorityPosition(b []byte, host string) (int, bool) {
	at := pxHostAuthorityOffsets(b, host)
	if len(at) == 0 {
		return 0, false
	}
	return at[0], true
}

// pxHostAuthorityOffsets is the same rule and returns EVERY offset, which a caller needs when the
// position of the match is itself part of the question.
//
// REDIRECT needs it. Its document arm asks not only "is our host in a URL" but "is that URL in a
// REDIRECT CONSTRUCT", and the answer depends on the bytes in front of each occurrence, so a
// first-match-only helper would decide the whole question from whichever copy happened to come
// first in a page that carries several.
func pxHostAuthorityOffsets(b []byte, host string) []int {
	if len(b) == 0 || host == "" {
		return nil
	}
	hay := bytes.ToLower(b)
	needle := []byte(strings.ToLower(host))
	var out []int
	from := 0
	for {
		rel := bytes.Index(hay[from:], needle)
		if rel < 0 {
			return out
		}
		at := from + rel
		from = at + 1

		// Right edge: end of input, or a delimiter. A host character here means the match is the
		// head of a longer name.
		if end := at + len(needle); end < len(hay) && !strings.ContainsRune(pxAuthorityDelimiters, rune(hay[end])) {
			continue
		}
		// Left edge: "//" or "@" immediately before.
		if at >= 1 && hay[at-1] == '@' {
			out = append(out, at)
			continue
		}
		if at >= 2 && hay[at-1] == '/' && hay[at-2] == '/' {
			out = append(out, at)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// 5. RESPONSE HEADERS
// ---------------------------------------------------------------------------------------------

// pxRespHeader returns every value of a response header, matched case-insensitively.
//
// Observation.RespHeaders is built from Go's canonicalised header MAP and then sorted by name
// (triageRun.go), so the WIRE ORDER and the exact on-the-wire spelling of a header name are both
// lost by the time a classifier sees them. That costs this family nothing, because every oracle
// here is about a name being PRESENT, and it would cost a smuggling or an HPP class everything.
// Recorded here rather than discovered by the next author.
func pxRespHeader(o triage.Observation, name string) []string {
	var out []string
	for _, h := range o.RespHeaders {
		if strings.EqualFold(h[0], name) {
			out = append(out, h[1])
		}
	}
	return out
}

// pxHasRespHeader is the presence question on its own.
func pxHasRespHeader(o triage.Observation, name string) bool {
	return len(pxRespHeader(o, name)) > 0
}

// pxLocation returns the RAW Location as the server wrote it.
//
// RAW IS THE POINT. RedirectChain[0].Location is the unparsed header value, and a re-parse is
// exactly what the REDIRECT class is trying to measure: normalising it before the comparison
// throws away the backslash, the extra slashes and the missing slashes that the whole filter-bypass
// family turns on.
//
// AND THE CHAIN IS NOT A CHAIN. The transport is configured with http.ErrUseLastResponse
// (triageEncode.go), so the client never follows a redirect and RedirectChain is always zero or
// one element. A class that read it as a chain would read one element and believe it had seen the
// whole journey. The field name invites that and this comment is the only thing between the two.
func pxLocation(o triage.Observation) (string, bool) {
	if len(o.RedirectChain) > 0 && strings.TrimSpace(o.RedirectChain[0].Location) != "" {
		return o.RedirectChain[0].Location, true
	}
	// The fallback is not redundant. RedirectChain is only populated when a Location header was
	// present at capture time; reading the header directly means a future change to that assembly
	// does not silently blind this class.
	if v := pxRespHeader(o, "Location"); len(v) > 0 && strings.TrimSpace(v[0]) != "" {
		return v[0], true
	}
	return "", false
}

// pxIsRedirectStatus reports whether a status is one the protocol treats as a redirect.
//
// 304 is EXCLUDED and that is not an oversight: Not Modified carries no Location, the field it
// would carry is Content-Location, and counting it here would make every conditional GET on a
// cached asset look like a redirect.
func pxIsRedirectStatus(code int) bool {
	switch code {
	case 300, 301, 302, 303, 305, 307, 308:
		return true
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 6. SLOT ELIGIBILITY AND THE ROUTE CONTROL
// ---------------------------------------------------------------------------------------------

// pxRouteStatus is the unperturbed control's status, and whether there was one.
//
// Every class in this family differences against it, and every one of them must be able to say
// "there was no control" rather than assuming a 200. A missing control turns a status differential
// from evidence into a coin flip.
func pxRouteStatus(ctx triage.ClassifyCtx) (int, bool) {
	if !ctx.Route.Resolved() {
		return 0, false
	}
	o := ctx.Route.Obs()
	if !o.Delivered() {
		return 0, false
	}
	return o.Status, true
}

// pxRouteRedirectsOffOrigin reports whether the UNPERTURBED route already redirects somewhere
// other than its own host.
//
// A site-wide HTTP-to-HTTPS redirect, a tenant redirect and a marketing redirect all do this, and
// on such a vector "the response carries a Location to another host" is the baseline and not a
// finding. It is recorded as an annotation on every REDIRECT verdict so the operator reading a
// suspicious row can see that the endpoint redirects anyway.
func pxRouteRedirectsOffOrigin(ctx triage.ClassifyCtx) (string, bool) {
	if !ctx.Route.Resolved() {
		return "", false
	}
	o := ctx.Route.Obs()
	loc, ok := pxLocation(o)
	if !ok || !pxIsRedirectStatus(o.Status) {
		return "", false
	}
	strict, browser := pxResolveBoth(pxBaseURL(o), loc)
	self := pxHostname(pxBaseURL(o))
	for _, r := range []pxResolution{strict, browser} {
		if r.Host != "" && r.Host != self {
			return r.Host, true
		}
	}
	return "", false
}

// pxBaseURL is the URL a response's Location must be resolved against.
//
// FinalURL is the request template's URL, which is correct HERE only because the client does not
// follow redirects, and is the wrong field to read on any build that starts following them. The
// wire request-target is the fallback, and it can be origin-form (a path), which url.Parse accepts
// and which makes an unusable base; pxResolveOne says so rather than resolving against nothing.
func pxBaseURL(o triage.Observation) string {
	if strings.Contains(o.FinalURL, "://") {
		return o.FinalURL
	}
	if strings.Contains(o.ReqWireURL, "://") {
		return o.ReqWireURL
	}
	return o.FinalURL
}

// pxUniformBlock asks whether a filter answered instead of the application, and it passes the
// ROUTE CONTROL'S BODY, which is the argument faUniformBlock has and which passing nil throws
// away.
//
// MEASURED, full-registry run against the canary oracle, 2026-09-19. DESER called
// faUniformBlock(own, nil) and reported
//
//	static  DESER  query:q  cannot_determine  blocked: three or more of this class's own
//	                                          distinct payloads produced byte-identical
//	                                          non-baseline responses
//
// on the fixture's static index, which is the route whose whole purpose in that test is to be the
// one shape that can produce an HONEST CLEAN: it takes a parameter and ignores it, so every
// payload leaves the response byte-identical to the baseline. With no baseline passed, "identical
// to each other" and "identical to the baseline" are the same observation, and an endpoint that
// correctly ignores our input is reported as one that blocked it. That converts a clean into an
// unknown, which is the inverse of this layer's usual failure and is still a wrong answer.
//
// So the baseline goes in. A response equal to the unperturbed control is the application
// behaving normally; three DIFFERENT payloads producing one identical response that is NOT the
// control is a filter with one error page.
func pxUniformBlock(ctx triage.ClassifyCtx, honest []faOwnObs) bool {
	var baseline []byte
	if ctx.Route.Resolved() {
		baseline = ctx.Route.Obs().Body
	}
	return faUniformBlock(faObsOf(honest), baseline)
}

// pxOneVerdict is the single-row constructor every class in this family builds its exits from, so
// a row can never be emitted without its class, its slot and its annotations attached.
func pxOneVerdict(class triage.ClassID, key triage.SlotKey, state triage.TriageState, reason, oracle string,
	grade triage.TriageGrade, ords []uint64, ann map[string]any, label triage.TriageLabel) []triage.ClassVerdict {

	return []triage.ClassVerdict{{
		Class: class, SlotKey: key, State: state, Reason: reason, Grade: grade,
		Oracle: oracle, Ordinals: ords, Annotations: ann, Label: label,
	}}
}

// pxDescribeResolutions renders both readings for an annotation, so an operator reading a
// parser-dependent suspicion can see exactly what each model made of the same bytes.
func pxDescribeResolutions(strict, browser pxResolution) string {
	one := func(r pxResolution) string {
		if r.Err != "" {
			return r.Model + "=" + r.Err
		}
		if r.Host == "" {
			return r.Model + "=no_authority (" + r.Resolved + ")"
		}
		return r.Model + "=" + r.Host + " (" + r.Resolved + ")"
	}
	return one(strict) + "; " + one(browser)
}

// pxJoin is strings.Join over ProbeIDs, for a reason string that names which probes it is about.
func pxJoin(ids []triage.ProbeID) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, string(id))
	}
	return strings.Join(parts, ", ")
}

// pxCount renders a count into a reason without a format verb at the call site, so a reason string
// stays readable in source.
func pxCount(n int, what string) string { return fmt.Sprintf("%d %s", n, what) }
