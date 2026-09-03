package utils

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Turning a stored finding into something an operator can reproduce WITHOUT this framework.
//
// The results modal used to show a kind badge, the parameter, the payload and an evidence string.
// None of that lets a person check the finding themselves, and a finding nobody can check is a
// finding nobody should act on. Every one of these produces, where it honestly can:
//
//   - a clickable URL, for GET findings only, because a POST is not a link
//   - a curl command, copyable, that recreates the request
//   - the raw HTTP request, for pasting into Burp Repeater or netcat
//   - ordered manual steps, including the CONTROL request where the proof is a comparison
//
// The hard part is that every tool hands back a different shape, and several hand back almost
// nothing. Rather than invent the missing pieces, each builder says what it could not construct in
// Caveat. A reproduction that quietly guesses at the request is worse than none, because the
// operator would be testing something the scanner never sent.

// FindingReproduction is everything needed to recreate one finding by hand.
type FindingReproduction struct {
	URL        string   `json:"url,omitempty"`
	Curl       string   `json:"curl,omitempty"`
	RawRequest string   `json:"raw_request,omitempty"`
	Steps      []string `json:"steps,omitempty"`
	Caveat     string   `json:"caveat,omitempty"`
	// RequestOrigin says whether RawRequest is bytes the TOOL reported or bytes this framework
	// composed. They are different claims and this project has been bitten repeatedly by a field
	// that reads as measured when it was inferred, so the distinction is carried in the data rather
	// than left to the reader to infer from which tool it came from.
	RequestOrigin string `json:"request_origin,omitempty"`
}

// FindingForRepro is the finding plus the vector it came from. The vector matters because several
// tools record a payload and a parameter but not the request they sent, and the vector's captured
// raw request is the only place the real cookies, headers and body survive.
type FindingForRepro struct {
	Tool           string
	Kind           string
	Method         string
	InsertionPoint string
	Param          string
	Payload        string
	URL            string
	Evidence       string
	RawRequest     string

	VectorRawRequest  string
	VectorEvidenceURL string
}

// curlInEvidence matches a complete curl command embedded in an evidence string. The access bypass
// tools put their whole reproduction there rather than in a field, so it is parsed back out.
var curlInEvidence = regexp.MustCompile(`(?s)curl\s+.*?'https?://[^']+'`)

// BuildFindingReproduction is the entry point. It dispatches per tool because the tools genuinely
// differ: one stores the request bytes, one stores a curl inside a sentence, one stores the whole
// proof-of-concept URL in the payload field, and one stores neither a URL nor a request.
//
// Whatever the builder produces, the RESULT is classified before it is returned: bytes the tool
// reported and bytes this framework composed are both useful and are not the same claim, so
// RequestOrigin says which, and a composed request carries a caveat saying so in words as well.
func BuildFindingReproduction(f FindingForRepro) FindingReproduction {
	// The stored request may itself be a marked reconstruction, because the runner now fills that
	// column in rather than leaving a finding with nothing at all. The banner is stripped here so
	// the block stays paste-into-Repeater bytes, and the marking survives as RequestOrigin.
	stored, storedWasComposed := SplitReconstructedRequest(f.RawRequest)
	f.RawRequest = stored

	out := buildFindingReproductionFor(f)

	switch {
	case strings.TrimSpace(out.RawRequest) == "":
		out.RequestOrigin = RequestNone
	case !storedWasComposed && strings.TrimSpace(stored) != "" && out.RawRequest == stored:
		out.RequestOrigin = RequestCaptured
	default:
		out.RequestOrigin = RequestReconstructed
		out.Caveat = strings.TrimSpace(reconstructedCaveat + " " + out.Caveat)
	}
	return out
}

// reconstructedCaveat is the sentence a composed request always carries. Worded for someone about to
// paste the bytes into a report: the danger is not that the request is useless, it is that it gets
// quoted as "the request the scanner sent" when nothing observed it going out.
const reconstructedCaveat = "RECONSTRUCTED, not captured: these request bytes were composed by this " +
	"framework from the attack vector the scan was aimed at plus what the tool reported. Send them " +
	"and read the response before quoting this finding as evidence."

func buildFindingReproductionFor(f FindingForRepro) FindingReproduction {
	switch f.Tool {
	case "forbidden", "nomore403":
		return reproduceBypass(f)
	case "pphack":
		return reproducePphack(f)
	case "sqlmap", "ghauri", "sqlidetector":
		return reproduceSQLi(f)
	case "dalfox", "xssfuzz":
		return reproduceReflected(f)
	case "domdig":
		return reproduceDomdig(f)
	}
	return reproduceGeneric(f)
}

// reproduceBypass handles the access bypass tools, whose finding IS a header.
//
// There is no parameter and no payload: the whole finding is "this request, which differs from the
// refused one only by a header, answered 200". So the reproduction has to carry the header, and the
// steps have to carry the two CONTROL requests, because a 200 on its own proves nothing. Two of the
// three findings on ginandjuice.shop were the ordinary page returned under a header that did
// nothing, and they were only distinguishable by comparing bodies.
func reproduceBypass(f FindingForRepro) FindingReproduction {
	out := FindingReproduction{}
	target := normaliseReproURL(f.URL)

	if found := curlInEvidence.FindString(f.Evidence); found != "" {
		out.Curl = strings.Join(strings.Fields(found), " ")
		out.RawRequest = rawRequestFromCurl(out.Curl, target)
	}
	if strings.EqualFold(f.Method, "GET") || f.Method == "" {
		// Clickable, but it reproduces the request WITHOUT the header, which is the whole finding.
		// Said plainly rather than left for the operator to discover.
		out.URL = target
	}

	header := bypassHeaderFrom(out.Curl)
	// The header's value is a PATH. Resolved against the target's origin so step one is a command
	// the operator can actually run: `curl -i '/admin/'` is not a URL and fails immediately.
	protected := absoluteAgainst(target, bypassProtectedPathFrom(header))
	firstStep := "Request the protected resource directly and record the refusal, then note its " +
		"exact status and response length."
	if protected != "" {
		firstStep = fmt.Sprintf("Request the protected resource directly and record the refusal: "+
			"`curl -i %s`. Note the exact status and the response length.", quoteForShell(protected))
	}
	out.Steps = []string{
		firstStep,
		fmt.Sprintf("Request %s with NO extra header and record it: `curl -i %s`. This is the "+
			"control arm, and it is the one most people skip.", quoteForShell(target), quoteForShell(target)),
		"Now send the request below, which differs from the control only by the added header.",
		"Compare all three BODIES, not the status codes. A bypass means the third response contains " +
			"the protected content that the first one withheld.",
		"If the third response is byte-identical to the control, the header did nothing and this is " +
			"a false positive: the tool only saw that the length differed from the 403 page.",
	}
	if header != "" {
		out.Steps = append(out.Steps, fmt.Sprintf("The header under test is %q. Try it against other "+
			"paths too: on this class of bug the check is usually applied to the request path while "+
			"the application routes on the header.", header))
	}
	if out.Curl == "" {
		out.Caveat = "This tool recorded no request bytes and no curl, so the exact request could " +
			"not be rebuilt. The URL above is the one it reported."
	}
	return out
}

// reproducePphack handles client-side prototype pollution, where the PAYLOAD is a complete URL
// rather than a value. Reproduction is a browser job, not a curl job: the pollution happens in the
// page's own JavaScript, so fetching the HTML proves nothing.
func reproducePphack(f FindingForRepro) FindingReproduction {
	out := FindingReproduction{}
	poc := f.Payload
	if !strings.HasPrefix(poc, "http") {
		poc = normaliseReproURL(firstNonEmpty(f.URL, f.VectorEvidenceURL))
	}
	out.URL = poc
	out.Curl = fmt.Sprintf("curl -i -sS %s", quoteForShell(poc))
	out.RawRequest = rawRequestFor("GET", poc, nil, "")
	// The console check has to name THIS finding's key. pphack randomises it per run, so a
	// hard-coded example matches one finding and misleads on the next.
	key := pollutionKeyFrom(poc)
	out.Steps = []string{
		"Open the URL above in a browser. This one CANNOT be checked with curl: the pollution is " +
			"performed by the page's own JavaScript, so the returned HTML looks identical either way.",
		"Open the developer tools console.",
		fmt.Sprintf("In the console, read the injected property back: `Object.prototype.%s`. A "+
			"polluted prototype carries a property no ordinary object should have.", key),
		fmt.Sprintf("Confirm it is the PROTOTYPE and not just one object: `({}).%s` should return "+
			"the injected value, because an empty object inherits it.", key),
		"Load the same page WITHOUT the payload and repeat the check. The property must be absent, " +
			"or the page sets it itself and this is not pollution.",
		"pphack is NOT deterministic: measured at 3 hits in 6 identical runs against a URL it does " +
			"detect. If the console check fails, reload a few times before concluding anything.",
		"To turn the primitive into an impact, find a gadget: a place where the page reads a " +
			"property it never set. On this target searchLogger.js reads `config.transport_url` and " +
			"assigns it to a script src, so `?__proto__[transport_url]=//host/x.js` loads script.",
	}
	return out
}

// reproduceSQLi handles sqlmap, ghauri and SQLiDetector. The payload arrives as "param=value", and
// the proof for the blind techniques is a COMPARISON, so the steps carry both arms.
func reproduceSQLi(f FindingForRepro) FindingReproduction {
	out := FindingReproduction{}
	param := normaliseFindingParam(f.Param)
	value := payloadValueFor(param, f.Payload)

	base := normaliseReproURL(firstNonEmpty(f.URL, f.VectorEvidenceURL))
	target := base
	// The URL only carries the payload when the QUERY STRING is where the payload goes. sqlmap and
	// ghauri are aimed at cookies and headers too, and writing a cookie payload into the query
	// produced a link that tests an input the application never reads there.
	if placesInQuery(f.InsertionPoint, base, param) && param != "" && value != "" {
		target = withQueryParam(base, param, value)
	}

	if strings.EqualFold(firstNonEmpty(f.Method, "GET"), "GET") {
		out.URL = target
	}
	out.Curl = fmt.Sprintf("curl -i -sS %s", quoteForShell(target))
	composed, _ := ComposeFindingRequest(f)
	out.RawRequest = firstNonEmpty(f.RawRequest, composed)

	blind := strings.Contains(strings.ToLower(f.Kind), "blind")
	out.Steps = []string{
		fmt.Sprintf("Send the request below. It puts the payload in the %s parameter.",
			quoteForShell(firstNonEmpty(param, "target"))),
	}
	if blind {
		out.Steps = append(out.Steps,
			"This technique proves nothing from ONE request. It infers one bit at a time, so you "+
				"must send a TRUE arm and a FALSE arm and compare.")
		if placesInQuery(f.InsertionPoint, base, param) && param != "" {
			out.Steps = append(out.Steps,
				// Both the readable payload AND the encoded URL. The URL alone shows the operator
				// 1%3D1, which is correct on the wire and unreadable as a payload.
				fmt.Sprintf("TRUE arm, append  ' AND 1=1--  to the %s value: %s",
					param, suffixPayload(base, param, "' AND 1=1-- ")),
				fmt.Sprintf("FALSE arm, append  ' AND 1=2--  to the %s value: %s",
					param, suffixPayload(base, param, "' AND 1=2-- ")))
		} else {
			// The payload does not live in the URL here, so the arms cannot be links. Spelling them
			// out as edits to the request below is the only honest form: a URL carrying a cookie
			// payload tests an input the application does not read.
			out.Steps = append(out.Steps,
				fmt.Sprintf("TRUE arm: in the request below, append  ' AND 1=1--  to the %s %s value. "+
					"This is not a link, so it has to be sent from Repeater or curl.",
					firstNonEmpty(param, "marked"), firstNonEmpty(f.InsertionPoint, "input")),
				fmt.Sprintf("FALSE arm: the same request with  ' AND 1=2--  appended to that %s value "+
					"instead.", firstNonEmpty(f.InsertionPoint, "input")))
		}
		out.Steps = append(out.Steps,
			"Compare the two response BODIES and their lengths. A real injection makes the true arm "+
				"match the ordinary page and the false arm differ, consistently, on repeat requests.",
			"Repeat both arms at least twice. A page whose length varies on its own, for example one "+
				"carrying a nonce or a rotating banner, produces the same difference by accident.",
			"Check what the FALSE arm actually returned. On a single page application every path that "+
				"does not exist answers 200 with the same shell, so a payload that breaks the route "+
				"produces a length difference that looks exactly like a boolean oracle. If the false "+
				"arm is the application's generic shell rather than a real page, this is that.")
	} else {
		out.Steps = append(out.Steps,
			"This technique RETURNS data rather than inferring it, so the response body itself is "+
				"the evidence. Look for the injected marker or the retrieved values in the body.",
			"Send the same request with the payload removed and diff the two responses. What appears "+
				"only in the injected response is what the database returned.")
	}
	out.Steps = append(out.Steps,
		"Do not escalate beyond confirming the injection. Reading table contents is a separate "+
			"decision with its own authorisation.")
	if param == "" {
		out.Caveat = "No parameter name was recorded on this finding, so the payload could not be " +
			"placed. The URL is the one the tool reported."
	}
	return out
}

// reproduceReflected handles dalfox and xssFuzz, which record a proof-of-concept URL directly.
func reproduceReflected(f FindingForRepro) FindingReproduction {
	out := FindingReproduction{}
	target := normaliseReproURL(firstNonEmpty(f.URL, f.VectorEvidenceURL))
	if strings.EqualFold(firstNonEmpty(f.Method, "GET"), "GET") {
		out.URL = target
	}
	out.Curl = fmt.Sprintf("curl -i -sS %s", quoteForShell(target))
	composed, _ := ComposeFindingRequest(f)
	out.RawRequest = firstNonEmpty(f.RawRequest, composed)

	static := f.Tool == "dalfox" && f.Kind == "A"
	out.Steps = []string{
		"Open the URL above in a browser and watch for the payload executing, for example an alert.",
		"If nothing executes, view source and find where the payload landed. The CONTEXT decides " +
			"whether it is exploitable: inside a script string, inside an attribute, or as text.",
		"Read the RAW response, not the rendered page. A payload that comes back percent-encoded, " +
			"as %3Csvg rather than <svg, is inert: it renders as literal characters and cannot " +
			"execute. Five reported XSS on one target were exactly that, and nothing but the bytes " +
			"showed it.",
		"Send the same URL with a harmless value in place of the payload and diff the two responses. " +
			"What changed is your injection point.",
	}
	if static {
		out.Steps = append([]string{
			"NOTE this finding came from dalfox's static analysis of inline scripts, not from a " +
				"request it sent and observed. There is no stored request or response because none " +
				"was made for it. Treat it as a lead and confirm it in a browser first.",
		}, out.Steps...)
		out.Caveat = "Static AST finding: no request was sent, so no raw exchange exists. The URL is " +
			"reconstructed from the vector and the payload."
	}
	if f.Tool == "xssfuzz" {
		out.Steps = append(out.Steps,
			"xssFuzz reports that dangerous characters came back unencoded. That is REFLECTION, not "+
				"execution. Confirm the characters really are unencoded in the body, then decide "+
				"whether the context lets them do anything.")
	}
	if f.Tool == "dalfox" && f.Kind == "V" {
		out.Steps = append(out.Steps,
			"dalfox v3 has no headless browser. Its V means the payload reached an executable "+
				"position in a PARSED response, not that script ran. The browser check above is what "+
				"turns it into a proven finding.")
	}
	return out
}

// reproduceDomdig handles domdig, which stores neither a URL nor a request. Its findings DID execute
// in a real Chromium, so they are the strongest evidence in the XSS section and the least
// reproducible from what it records.
func reproduceDomdig(f FindingForRepro) FindingReproduction {
	out := FindingReproduction{}
	param := normaliseFindingParam(f.Param)
	base := firstNonEmpty(f.URL, f.VectorEvidenceURL)
	target := base
	if param != "" && f.Payload != "" {
		target = withQueryParam(base, param, f.Payload)
	}
	out.URL = target
	out.Curl = fmt.Sprintf("curl -i -sS %s", quoteForShell(target))
	out.RawRequest, _ = ComposeFindingRequest(f)
	out.Steps = []string{
		"Open the URL above in a browser with the developer tools console open.",
		"domdig drives a real Chromium and reported that this EXECUTED, so unlike the other XSS " +
			"tools its findings are execution rather than reflection. You should see the effect in " +
			"the page rather than only in the source.",
		"For a template injection payload such as {{this+{0}+this}}, look for the expression having " +
			"been EVALUATED in the rendered output rather than printed literally. Seeing the braces " +
			"echoed back verbatim means it was not evaluated.",
		"Confirm the framework is present: template injection needs a client-side template engine, " +
			"so check the page for AngularJS and for an ng-app attribute on an ancestor element.",
		"Load the same page with a harmless value in the same parameter and confirm the effect stops.",
	}
	out.Caveat = "domdig records neither a request URL nor the exchange, so this URL is rebuilt from " +
		"the vector and the payload. Check that the parameter and path match what you expect before " +
		"trusting it."
	return out
}

// reproduceGeneric is where most tools land, and it used to be the weakest part of this file: it
// handed back the vector's request with the payload never inserted, so the operator was shown the
// ordinary request and left to place the payload themselves. ComposeFindingRequest places it
// wherever it can be placed faithfully and says so when it cannot.
func reproduceGeneric(f FindingForRepro) FindingReproduction {
	out := FindingReproduction{}
	target := normaliseReproURL(firstNonEmpty(f.URL, f.VectorEvidenceURL))
	if target != "" && strings.EqualFold(firstNonEmpty(f.Method, "GET"), "GET") {
		out.URL = target
	}
	if target != "" {
		out.Curl = fmt.Sprintf("curl -i -sS %s", quoteForShell(target))
	}
	composed, note := ComposeFindingRequest(f)
	stored := strings.TrimSpace(f.RawRequest)
	switch {
	case looksLikeRawRequest(stored):
		out.RawRequest = f.RawRequest
	case strings.HasPrefix(stored, "curl"):
		// WCVS and graphql-cop put a curl COMMAND in the request column. It is what the tool
		// reported and it belongs in the curl block: pasted into Repeater, which is what the raw
		// block is labelled for, it is not a request and nothing is sent.
		out.Curl = stored
		out.RawRequest = composed
	default:
		out.RawRequest = firstNonEmpty(composed, f.RawRequest)
	}
	out.Steps = []string{
		"Send the request below and compare it against the same request with the payload removed.",
		"The difference between the two responses is the evidence. If there is no difference, the " +
			"finding does not stand up.",
		"Read the response BODY rather than the status code. On a single page application every " +
			"path that does not exist answers 200 with the same shell, so a status or length " +
			"difference is usually that shell rather than a vulnerability.",
	}
	if f.RawRequest == "" && strings.Contains(note, "NOT placed") {
		out.Caveat = "The payload could not be placed into the request below, so it is the request " +
			"the scan was aimed at rather than the one that found this. The payload is on the " +
			"finding itself and has to be inserted by hand."
	}
	return out
}

// --- captured versus composed --------------------------------------------------------------------
//
// 33 of the 42 findings in the last campaign carried no request and no response, and on that target
// the missing bytes were decisive rather than untidy. dalfox reported five XSS whose payload came
// back ONLY percent-encoded: 0 occurrences of "<svg" against 2 of inert "%3Csvg", which renders as
// text and cannot execute. ghauri reported /encryptionkeys/jwt.pub as boolean-blind because the real
// path returns a key file and the injected path returns the Angular shell that every non-existent
// path on that application returns. Neither is visible from a payload and a parameter name. Both are
// obvious from the bytes.
//
// Most of these tools report no bytes at all, so for those the framework composes the request from
// the vector it aimed and the finding's own parameter and payload. That is worth having: it is the
// request the scan was ASKED to send, it carries the vector's real cookies, and it is something an
// operator can fire and compare. It is NOT a recording, and the two must never read alike, so a
// composed request is stored behind a banner that says so in the bytes themselves. Someone who never
// learns the convention still reads the sentence.

const (
	// RequestCaptured means the bytes came from the tool: it reported the request it sent.
	RequestCaptured = "captured"
	// RequestReconstructed means this framework composed them. What the tool actually put on the
	// wire may differ in encoding, in headers it added, and in payload mutations it applied.
	RequestReconstructed = "reconstructed"
	// RequestNone means nothing was stored and nothing could honestly be composed.
	RequestNone = "none"
)

// reconstructedRequestBanner is the first line of every composed request, and it is matched on
// literally. Changing it silently reclassifies every row already stored as captured.
const reconstructedRequestBanner = "#### RECONSTRUCTED REQUEST, NOT CAPTURED BYTES ####"

// MarkReconstructedRequest wraps composed bytes so they cannot be mistaken for a capture.
//
// The marker lives INSIDE the stored text rather than only in a column, deliberately. Every consumer
// that reads raw_request, including ones written later and ones outside this repository, sees the
// disclaimer without having to know a convention. Callers that need pasteable bytes strip it with
// SplitReconstructedRequest.
func MarkReconstructedRequest(tool, note, raw string) string {
	raw = strings.TrimLeft(raw, "\r\n")
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	if _, already := SplitReconstructedRequest(raw); already {
		return raw
	}
	var b strings.Builder
	b.WriteString(reconstructedRequestBanner + "\n")
	b.WriteString("# " + firstNonEmpty(tool, "This tool") + " reported this finding without any " +
		"request bytes, so the framework composed\n")
	b.WriteString("# the request below from the attack vector the scan was aimed at and this " +
		"finding's own\n")
	b.WriteString("# parameter and payload. It is what the scan was ASKED to send, not a recording " +
		"of what\n")
	b.WriteString("# went out: any header the tool added and any encoding it applied is missing here.\n")
	if strings.TrimSpace(note) != "" {
		b.WriteString("# How it was built: " + strings.TrimSpace(note) + "\n")
	}
	b.WriteString("# Send it and read the response before quoting this finding as evidence.\n")
	b.WriteString(strings.Repeat("#", len(reconstructedRequestBanner)) + "\n")
	b.WriteString(raw)
	return b.String()
}

// SplitReconstructedRequest returns the request bytes without the banner, and whether one was there.
func SplitReconstructedRequest(raw string) (string, bool) {
	if !strings.HasPrefix(strings.TrimLeft(raw, " \t\r\n"), reconstructedRequestBanner) {
		return raw, false
	}
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for i, line := range lines {
		if i == 0 || strings.HasPrefix(line, "#") {
			continue
		}
		return strings.Join(lines[i:], "\n"), true
	}
	return "", true
}

// FindingRequestOrigin classifies what is stored in a finding's raw_request column.
func FindingRequestOrigin(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return RequestNone
	}
	if _, composed := SplitReconstructedRequest(raw); composed {
		return RequestReconstructed
	}
	return RequestCaptured
}

// FindingResponseOrigin classifies a finding's raw_response column.
//
// There are only two answers and there is deliberately no third. A response cannot be composed: it
// is the target's answer, and inventing one would be fabricating the evidence rather than the
// question. Where a tool records no response the honest report is that there is none, and the run's
// stored trace is where the operator goes instead.
func FindingResponseOrigin(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return RequestNone
	}
	return RequestCaptured
}

// ComposeFindingRequest builds the request a finding implies, and says how it was built.
//
// It starts from the vector's CAPTURED request wherever there is one, because that is where the real
// cookies, headers and body live: a request rebuilt from a URL alone reproduces a logged-out page,
// and a logged-out page injects nothing.
//
// The payload is placed only where it can be placed faithfully. A body or path finding is returned as
// the vector's own request with the payload NOT inserted, and the note says so, because guessing at
// where a value belongs in a JSON body produces a request that tests something nobody scanned.
func ComposeFindingRequest(f FindingForRepro) (string, string) {
	param := normaliseFindingParam(f.Param)
	value := payloadValueFor(param, f.Payload)
	point := strings.ToLower(strings.TrimSpace(f.InsertionPoint))
	method := strings.ToUpper(firstNonEmpty(f.Method, "GET"))
	target := normaliseReproURL(firstNonEmpty(f.URL, f.VectorEvidenceURL))

	// WHAT THE TOOL REPORTED BEATS ANYTHING COMPOSED FROM THE VECTOR. The access bypass tools put a
	// complete curl command in their evidence sentence, and that command carries the header which IS
	// the finding. Composing from the vector instead would produce the request WITHOUT the header,
	// which is the control arm: the operator would send it, see the ordinary refusal, and dismiss a
	// real bypass.
	if curl := curlInEvidence.FindString(f.Evidence); curl != "" {
		if raw := rawRequestFromCurl(strings.Join(strings.Fields(curl), " "), target); raw != "" {
			return raw, "rendered from the curl command " + firstNonEmpty(f.Tool, "the tool") +
				" reported, so the header or option under test is present."
		}
	}

	// NOT EVERY raw_request COLUMN HOLDS A REQUEST. The JWT section stores the token itself there,
	// because its "vectors" are tokens rather than endpoints. Composing on top of that would produce a
	// finding whose stored request is a bare JWT under a banner announcing it as an HTTP request,
	// which is worse than storing nothing: it looks like evidence.
	base := strings.TrimSpace(f.VectorRawRequest)
	if !looksLikeRawRequest(base) {
		base = ""
	}

	// Several tools record a whole proof-of-concept URL rather than a value: pphack puts it in the
	// payload field and SQLiDetector puts the injected URL in both payload and url. The placement is
	// already done in those, and applying a parameter on top of it would undo it.
	//
	// Only when the URL is on the SAME HOST as the finding. An open redirect or SSRF payload is also
	// an absolute URL and it is the attacker's, not the target's: pointing the reproduction at it
	// would send the operator's session to a third party and test nothing on the target at all.
	if poc := strings.TrimSpace(f.Payload); isAbsoluteURL(poc) && sameHost(poc, target) {
		target, param, value = normaliseReproURL(poc), "", ""
		if base != "" {
			return rawRequestAtURL(base, target),
				"the vector's captured request aimed at the proof-of-concept URL " +
					firstNonEmpty(f.Tool, "the tool") + " reported, which already carries the payload."
		}
	}

	placeable := param != "" && value != ""

	if base == "" {
		if target == "" {
			return "", ""
		}
		note := "composed from the finding's own URL. This vector has no captured request, so there " +
			"are no cookies here and it reproduces a logged-out session."
		if placeable && placesInQuery(point, target, param) {
			target = withQueryParam(target, param, value)
			note = "composed from the finding's URL with the payload placed in the " + param +
				" query parameter. The vector has no captured request, so there are no cookies here."
		}
		return rawRequestFor(method, target, nil, ""), note
	}

	switch {
	case placeable && placesInQuery(point, target, param):
		return rawRequestWithParam(base, param, value, target),
			"the vector's captured request with the payload placed in the " + param +
				" query parameter."
	case placeable && point == "cookie":
		return rawRequestWithCookie(base, param, value),
			"the vector's captured request with the payload placed in the " + param +
				" cookie, leaving every other cookie alone."
	case placeable && point == "header":
		return rawRequestWithHeader(base, param, value),
			"the vector's captured request with the payload placed in the " + param + " header."
	}
	return base, "the vector's captured request with the payload NOT placed: nothing here says where " +
		"a " + firstNonEmpty(point, "value") + " payload belongs in it, so this is the request the " +
		"scan was aimed at rather than the one that produced the finding. The payload is on the " +
		"finding itself."
}

// placesInQuery decides whether the query string is the honest home for this payload.
//
// An empty insertion point is the awkward case: several tools record none. It is treated as a query
// finding ONLY when the URL already carries that parameter, which is evidence rather than a guess.
func placesInQuery(point, target, param string) bool {
	switch point {
	case "query", "url":
		return true
	case "":
		if param == "" || target == "" {
			return false
		}
		parsed, err := url.Parse(target)
		if err != nil {
			return false
		}
		_, present := parsed.Query()[param]
		return present
	}
	return false
}

// rawRequestWithHeader replaces one header in a captured request, or appends it when it is absent.
func rawRequestWithHeader(raw, name, value string) string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			// The header block ends here and the header was not in it, so it is added at the end of
			// the block rather than after the body.
			out := make([]string, 0, len(lines)+1)
			out = append(out, lines[:i]...)
			out = append(out, name+": "+value)
			return strings.Join(append(out, lines[i:]...), "\n")
		}
		if headerNameIs(lines[i], name) {
			lines[i] = name + ": " + value
			return strings.Join(lines, "\n")
		}
	}
	return strings.Join(append(lines, name+": "+value), "\n")
}

// rawRequestWithCookie replaces ONE cookie's value inside the Cookie header.
//
// Not the whole header: the session almost always lives beside the cookie under test, and replacing
// the header wholesale produces a request that 401s. A 401 injects nothing, so the reproduction would
// refute a real finding.
func rawRequestWithCookie(raw, name, value string) string {
	lines := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			break
		}
		if !headerNameIs(lines[i], "Cookie") {
			continue
		}
		_, existing, _ := strings.Cut(lines[i], ":")
		lines[i] = "Cookie: " + replaceCookieValue(existing, name, value)
		return strings.Join(lines, "\n")
	}
	return rawRequestWithHeader(raw, "Cookie", name+"="+value)
}

func replaceCookieValue(header, name, value string) string {
	var out []string
	replaced := false
	for _, pair := range strings.Split(header, ";") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		if key, _, ok := strings.Cut(pair, "="); ok && strings.EqualFold(strings.TrimSpace(key), name) {
			out = append(out, name+"="+value)
			replaced = true
			continue
		}
		out = append(out, pair)
	}
	if !replaced {
		out = append(out, name+"="+value)
	}
	return strings.Join(out, "; ")
}

// rawRequestAtURL points a captured request at a different URL, keeping its headers and its body.
//
// Used where the tool reports a whole proof-of-concept URL: rebuilding from that URL alone would
// drop the cookies, and the request would reproduce a logged-out page.
func rawRequestAtURL(base, rawURL string) string {
	parsed, err := url.Parse(normaliseReproURL(rawURL))
	if err != nil || parsed.Host == "" {
		return base
	}
	requestTarget := parsed.EscapedPath()
	if requestTarget == "" {
		requestTarget = "/"
	}
	if parsed.RawQuery != "" {
		requestTarget += "?" + parsed.RawQuery
	}
	lines := strings.Split(strings.ReplaceAll(base, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return base
	}
	if parts := strings.Fields(lines[0]); len(parts) >= 2 {
		parts[1] = requestTarget
		lines[0] = strings.Join(parts, " ")
	}
	for i := 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			break
		}
		if headerNameIs(lines[i], "Host") {
			lines[i] = "Host: " + parsed.Host
		}
	}
	return strings.Join(lines, "\n")
}

// sameHost reports whether two URLs are the same origin's host. An empty second argument means there
// is nothing to compare against, which is not a match: the caller is deciding whether to REDIRECT a
// reproduction at the first URL, and doing that unchecked is how a session ends up sent to whatever
// host a payload happens to name.
func sameHost(a, b string) bool {
	first, err := url.Parse(strings.TrimSpace(a))
	if err != nil || first.Hostname() == "" {
		return false
	}
	second, err := url.Parse(strings.TrimSpace(b))
	if err != nil || second.Hostname() == "" {
		return false
	}
	return strings.EqualFold(first.Hostname(), second.Hostname())
}

func headerNameIs(line, name string) bool {
	got, _, ok := strings.Cut(line, ":")
	return ok && strings.EqualFold(strings.TrimSpace(got), name)
}

// looksLikeRawRequest reports whether a stored string actually opens with an HTTP request line.
func looksLikeRawRequest(raw string) bool {
	line, _, _ := strings.Cut(strings.TrimSpace(raw), "\n")
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return false
	}
	switch strings.ToUpper(fields[0]) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}

func isAbsoluteURL(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// --- helpers -----------------------------------------------------------------------------------

// normaliseFindingParam strips the decoration different tools add to a parameter name. ghauri
// records "category (GET)" and domdig records "GET/redirect"; neither is the parameter's name, and
// substituting on the decorated string silently matches nothing.
func normaliseFindingParam(param string) string {
	param = strings.TrimSpace(param)
	if param == "" {
		return ""
	}
	if at := strings.Index(param, " ("); at > 0 {
		param = param[:at]
	}
	if at := strings.LastIndex(param, "/"); at >= 0 && at < len(param)-1 {
		param = param[at+1:]
	}
	return strings.TrimSpace(param)
}

// payloadValueFor pulls the VALUE out of a payload recorded as "name=value". sqlmap and ghauri both
// record the whole assignment, and putting that into the query string again yields
// ?category=category=... which tests nothing.
func payloadValueFor(param, payload string) string {
	// Trailing SPACES are kept. Only line endings and tabs are trimmed, because "-- " is a MySQL
	// comment and "--" is not: trimming the space turns a payload that comments out the rest of the
	// statement into one that is a syntax error, and the operator's reproduction then refutes a real
	// finding for a reason invisible on screen.
	payload = strings.Trim(payload, "\r\n\t")
	if payload == "" {
		return ""
	}
	if param != "" && strings.HasPrefix(payload, param+"=") {
		return payload[len(param)+1:]
	}
	return payload
}

// normaliseReproURL removes the explicit default port some tools add. Forbidden reports
// https://host:443/path, which is correct but does not match anything else the operator has, and
// reads as a different host at a glance.
func normaliseReproURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if (parsed.Scheme == "https" && parsed.Port() == "443") ||
		(parsed.Scheme == "http" && parsed.Port() == "80") {
		parsed.Host = parsed.Hostname()
	}
	return parsed.String()
}

func withQueryParam(rawURL, param, value string) string {
	rawURL = normaliseReproURL(rawURL)
	if param == "" || rawURL == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(param, value)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// suffixPayload appends a payload to a parameter's EXISTING value rather than replacing it, which is
// what a boolean arm needs: the base value has to keep selecting a real row or both arms return the
// same empty page and the comparison proves nothing.
func suffixPayload(rawURL, param, suffix string) string {
	rawURL = normaliseReproURL(rawURL)
	if param == "" || rawURL == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	q.Set(param, q.Get(param)+suffix)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func rawRequestFor(method, rawURL string, headers []string, body string) string {
	parsed, err := url.Parse(normaliseReproURL(rawURL))
	if err != nil || parsed.Host == "" {
		return ""
	}
	target := parsed.EscapedPath()
	if target == "" {
		target = "/"
	}
	if parsed.RawQuery != "" {
		target += "?" + parsed.RawQuery
	}
	var b strings.Builder
	b.WriteString(strings.ToUpper(firstNonEmpty(method, "GET")) + " " + target + " HTTP/1.1\n")
	b.WriteString("Host: " + parsed.Host + "\n")
	for _, h := range headers {
		if strings.TrimSpace(h) != "" {
			b.WriteString(strings.TrimSpace(h) + "\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(body)
	return b.String()
}

// rawRequestWithParam rewrites the vector's CAPTURED request so the payload sits in the named
// parameter. Preferred over building one from scratch because the capture carries the real cookies
// and headers, and a request missing the session tests a logged out page.
func rawRequestWithParam(vectorRaw, param, value, fallbackURL string) string {
	if strings.TrimSpace(vectorRaw) == "" {
		return rawRequestFor("GET", fallbackURL, nil, "")
	}
	if param == "" || value == "" {
		return vectorRaw
	}
	lines := strings.Split(strings.ReplaceAll(vectorRaw, "\r\n", "\n"), "\n")
	if len(lines) == 0 {
		return vectorRaw
	}
	// Rewrite the request line's query string, leaving every header and the body untouched.
	parts := strings.Fields(lines[0])
	if len(parts) >= 2 {
		pathPart, queryPart, hasQuery := strings.Cut(parts[1], "?")
		q := url.Values{}
		if hasQuery {
			if parsed, err := url.ParseQuery(queryPart); err == nil {
				q = parsed
			}
		}
		q.Set(param, value)
		parts[1] = pathPart + "?" + q.Encode()
		lines[0] = strings.Join(parts, " ")
	}
	return strings.Join(lines, "\n")
}

var curlHeaderRe = regexp.MustCompile(`-H\s+'([^']+)'`)

// rawRequestFromCurl rebuilds the request bytes from a curl command, which is the only place the
// access bypass tools record what they sent.
func rawRequestFromCurl(curl, fallbackURL string) string {
	method := "GET"
	if m := regexp.MustCompile(`-X\s+'?([A-Z]+)'?`).FindStringSubmatch(curl); len(m) > 1 {
		method = m[1]
	}
	target := fallbackURL
	if m := regexp.MustCompile(`'(https?://[^']+)'`).FindStringSubmatch(curl); len(m) > 1 {
		target = m[1]
	}
	var headers []string
	for _, m := range curlHeaderRe.FindAllStringSubmatch(curl, -1) {
		headers = append(headers, m[1])
	}
	if m := regexp.MustCompile(`-A\s+'([^']+)'`).FindStringSubmatch(curl); len(m) > 1 {
		headers = append(headers, "User-Agent: "+m[1])
	}
	return rawRequestFor(method, target, headers, "")
}

// bypassHeaderFrom names the header the bypass turned on, which is the entire finding for these
// tools and is otherwise buried in a sentence.
func bypassHeaderFrom(curl string) string {
	for _, m := range curlHeaderRe.FindAllStringSubmatch(curl, -1) {
		if !strings.HasPrefix(strings.ToLower(m[1]), "user-agent:") {
			return m[1]
		}
	}
	return ""
}

// bypassProtectedPathFrom recovers the resource the operator was refused, which for a path override
// header is the header's own value.
func bypassProtectedPathFrom(header string) string {
	_, value, ok := strings.Cut(header, ":")
	if !ok {
		return ""
	}
	return strings.TrimSpace(value)
}

func quoteForShell(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// pollutionKeyFrom pulls the injected property name out of a pphack proof-of-concept URL. pphack
// randomises the key per run, so the console check has to name the key from THIS finding rather
// than a fixed example that will not match.
func pollutionKeyFrom(poc string) string {
	if m := regexp.MustCompile(`__proto__\[([A-Za-z0-9_]+)\]`).FindStringSubmatch(poc); len(m) > 1 {
		return m[1]
	}
	if m := regexp.MustCompile(`__proto__\.([A-Za-z0-9_]+)`).FindStringSubmatch(poc); len(m) > 1 {
		return m[1]
	}
	if m := regexp.MustCompile(`constructor\.prototype\.([A-Za-z0-9_]+)`).FindStringSubmatch(poc); len(m) > 1 {
		return m[1]
	}
	return "theInjectedKey"
}

// absoluteAgainst resolves a path against another URL's origin.
//
// The access bypass tools express the protected resource as a header VALUE, which is a path. A step
// that tells the operator to run `curl -i '/admin/'` wastes their time: curl rejects it, and the
// path alone does not say which host it belongs to.
func absoluteAgainst(base, path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return normaliseReproURL(path)
	}
	parsed, err := url.Parse(normaliseReproURL(base))
	if err != nil || parsed.Host == "" {
		return ""
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return parsed.Scheme + "://" + parsed.Host + path
}
