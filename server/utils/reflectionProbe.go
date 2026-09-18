package utils

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Does the payload come back? One request per input, and an answer that refuses to round itself off.
//
// A SEPARATE STEP FROM CONSOLIDATE, deliberately. Consolidate sends zero HTTP requests today
// (measured: no http client call anywhere in attackVectors.go) and stays that way, so building the
// vector list stays a database operation an operator can run against a target they have not yet
// been cleared to touch. This mirrors Consolidate -> Validate -> Investigate -> Manage, which the
// endpoint workflow already uses for exactly this reason.
//
// WHY THE ANSWER IS NOT A BOOLEAN. /api/v1/echo on the estate this was built against reflects
// <svg onload=alert(1)> completely RAW, and it is not exploitable: the response is pinned to
// application/json and could not be moved off it. Accept:, format=, callback=, jsonp= and a .html
// suffix were all tried and all refused. A flat "XSS" label on that row sends the operator to spend
// an afternoon on a non-bug. The grade therefore combines WHAT SURVIVED with WHAT THE RESPONSE IS,
// and only the pair of them earns xss_candidate_high.
//
// WHY THERE ARE FOUR NON-ANSWERS. blocked, error, needs_browser and not_probed all mean "we do not
// know", and every one of them exists because collapsing it into not_reflected produces the silent
// clean this codebase keeps meeting. A probe payload contains <, which is precisely the byte a WAF
// drops; without `blocked` a well defended target reads as "nothing reflects anywhere", which is the
// most confident possible way of being wrong.

// The status vocabulary. Every value is load bearing; see the file header for why the four
// not-an-answer states are separate rather than folded into not_reflected.
const (
	// ReflectionNotProbed is the default: this input has never been sent a canary.
	ReflectionNotProbed = "not_probed"
	// ReflectionNeedsBrowser is a fragment vector. The fragment is the one container that is never
	// put on the wire, so an HTTP probe structurally cannot answer the question for it. Recording
	// one as not_reflected would be inventing a measurement that is impossible to make.
	ReflectionNeedsBrowser = "needs_browser"
	// ReflectionIsCredential is the input that IS the credential for this host: the Authorization
	// header, the session cookie, the API key. Putting a canary there does not test the input, it
	// throws the session away, and the 401 that comes back reflects nothing.
	//
	// MEASURED, live estate 2026-09-17: all 49 header vectors on the engaged target fuzz
	// `authorization`, and the session lives in CognitoIdentityServiceProvider.* cookies, 700 of the
	// 1655 cookie parameter slots. Folding those into not_reflected would be 749 clean rows
	// describing a login wall; folding them into error would say the probe failed when it worked
	// perfectly and declined. It is a question this method cannot ask, so it gets its own word.
	ReflectionIsCredential = "is_credential"
	// ReflectionProbeRefused is THE PROBE'S OWN DECISION not to send this request.
	//
	// Distinct from blocked, which is the TARGET refusing, and from error, which is a request that
	// failed. Nothing failed here: a body vector whose verb is PUT or DELETE, a POST or PATCH body
	// without the operator's per-run opt in, a header the scan client sets itself, or a body that
	// could not be composed without inventing one. Every one of those would read as not_probed
	// otherwise, and not_probed means nobody got round to it rather than this was decided against.
	ReflectionProbeRefused = "probe_refused"
	// ReflectionBlocked is a request that was REJECTED rather than answered on its merits, so
	// reflection is UNKNOWN.
	ReflectionBlocked = "blocked"
	// ReflectionError is a request that did not produce a usable answer: timeout, DNS, TLS, a
	// missing credential, or a 5xx the payload may itself have caused.
	ReflectionError = "error"
	// ReflectionNotReflected is the only negative that means anything: the endpoint answered
	// normally and the canary was not in the body.
	ReflectionNotReflected = "not_reflected"
	// ReflectionObserved is the PASSIVE verdict: a value the crawl really sent came back whole in
	// the response the crawl really stored, so this input is echoed and NOTHING WAS SENT to learn
	// it.
	//
	// It is separate from reflected_raw because it is a weaker claim, and folding it in would be an
	// over-claim of exactly the kind this vocabulary exists to stop. The crawl sent a real value,
	// almost never one containing `<`, so "it comes back" says the input is echoed and says nothing
	// about whether markup survives, which is the half that decides whether there is an XSS. It
	// therefore grades as xss_unknown and the ACTIVE pass is what upgrades it. A passive row only
	// reaches reflected_raw when the observed value ITSELF carried one of < > " ' and it came back
	// intact, which is a measurement rather than an inference.
	ReflectionObserved = "reflected_observed"
	// ReflectionEncoded is the canary coming back with every dangerous character neutralised.
	ReflectionEncoded = "reflected_encoded"
	// ReflectionRaw is the canary coming back with at least one of < > " ' intact.
	ReflectionRaw = "reflected_raw"
)

// The grade: the "XSS label" an operator filters on, in the UI and over MCP.
//
// DERIVED, NEVER STORED. A second column would be a second thing to keep in step with status and
// content_type, and the first time a probe re-ran and updated one but not the other the label would
// start describing a measurement that no longer exists.
const (
	XSSCandidateHigh = "xss_candidate_high"
	// XSSCandidateChain is a raw reflection into a response that RENDERS, at an insertion point the
	// attacker cannot reach with a link. Everything about it is a finding except the delivery.
	//
	// TRAP 3. It is not xss_candidate_high, because a cookie or header value is set by the browser
	// the victim already has, so on its own it is self-XSS. It is not xss_candidate_low either,
	// because low means the payload has nowhere to render and this one renders perfectly: the two
	// have different next moves, and merging them would tell the operator to go looking for a
	// content type they can move when what they need is a CRLF into Set-Cookie, a cookie write from
	// a sibling subdomain, or a cache poison. The framework already ships that ranking in
	// manage_xss.rule; this is the grade that expresses it.
	XSSCandidateChain   = "xss_candidate_chain"
	XSSCandidateLow     = "xss_candidate_low"
	XSSCandidateNone    = "xss_candidate_none"
	XSSCandidateUnknown = "xss_unknown"
)

// reflectionStatusRanking is the ONE place the "which status wins" order lives.
//
// The UI sorts by it, the MCP layer filters by it and the Go summary column is computed with it. Any
// second copy is a place for the three to disagree about what a vector's headline status is, and a
// disagreement here means the operator's filter and the operator's list show different rows.
//
// Most interesting first. reflected_raw outranks reflected_encoded because it is the one that can be
// weaponised; the three unknowns outrank not_reflected because an unmeasured input is worth more of
// the operator's attention than a measured negative; needs_browser sits below them because it is an
// unknown with a known next step (drive it in a browser) rather than a failure to be retried.
//
// is_credential and probe_refused are APPENDED after needs_browser rather than inserted anywhere
// above it, which keeps every pre-existing pairwise comparison byte-identical: nothing that ranked
// above another status before ranks below it now. They sit beside needs_browser because they are the
// same kind of thing, an unknown with a known next step that is not a retry, and above not_probed
// because a decision not to send is more informative than never having looked.
// "NOT ASKED" OUTRANKS "ASKED AND GOT NOTHING", and that ordering is the whole point of this list.
//
// MEASURED on the live corpus: a cookie vector carries 22.1 inputs on average, and on this estate
// 1653 of 1655 cookie slots are the session, so they are never sent. Exactly two analytics cookies
// are sendable. With not_reflected ranked above is_credential, a vector where 21 of 22 inputs were
// never asked took its headline from the one that was, and read `not_reflected`: a clean summary of
// a vector nobody tested. That is the same false clean this codebase has been removing all day,
// arriving through the summary rather than through the classifier.
//
// So the four statuses that mean "this input was not put in front of the application" sit ABOVE
// not_reflected. A vector is only summarised as not reflecting when nothing more interesting, and
// nothing unasked, happened to any of its inputs.
//
// needs_browser stays below them because it is a definite answer about an HTTP probe rather than a
// gap: a fragment genuinely cannot be asked this way, and never will be.
var reflectionStatusRanking = []string{
	ReflectionRaw,
	// INSERTED, not appended, and inserting a NEW value cannot change any pre-existing pairwise
	// comparison: every status that outranked another before still does. It sits above
	// reflected_encoded because the two are an unknown and an answer. reflected_encoded is the
	// application saying it escapes this input; reflected_observed is "this input is echoed and
	// nobody has tested the escaping yet", which is the one that still needs work doing to it.
	ReflectionObserved,
	ReflectionEncoded,
	ReflectionBlocked,
	ReflectionError,
	ReflectionIsCredential,
	ReflectionProbeRefused,
	ReflectionNotReflected,
	ReflectionNeedsBrowser,
	ReflectionNotProbed,
}

// ReflectionStatusRank returns the sort position of a status, lower being more interesting.
//
// An unrecognised status, and the empty string a never-probed attack_vectors row carries, both rank
// with not_probed. Returning something ahead of reflected_raw for a typo would put a row the probe
// never understood at the top of the operator's list.
func ReflectionStatusRank(status string) int {
	for i, known := range reflectionStatusRanking {
		if status == known {
			return i
		}
	}
	return len(reflectionStatusRanking) - 1
}

// ReflectionStatusOrder is the ranking as data, for the UI and the MCP layer to read rather than
// re-type. Exported as a copy so a caller cannot reorder the ranking for everyone else.
func ReflectionStatusOrder() []string {
	return append([]string(nil), reflectionStatusRanking...)
}

// MostInterestingReflectionStatus reduces a vector's per-parameter statuses to the one that goes in
// attack_vectors.reflection_status.
//
// A vector with four query parameters where one reflects raw IS a raw-reflecting vector: the
// operator needs it in the list, and which parameter it was is in the probe rows underneath. Taking
// the LAST status written, or the first, would have made a vector's headline depend on parameter
// ordering.
func MostInterestingReflectionStatus(statuses ...string) string {
	if len(statuses) == 0 {
		return ReflectionNotProbed
	}
	best := ReflectionNotProbed
	for _, s := range statuses {
		if ReflectionStatusRank(s) < ReflectionStatusRank(best) {
			best = s
		}
	}
	return best
}

// XSSCandidateGrade turns one stored probe row into the label the operator filters on.
//
// The pair is the point. reflected_raw on its own is not a finding, which is what /api/v1/echo
// proved: raw < > " ' in a body pinned to application/json, no way found to move it off that type,
// and therefore nothing to render the payload. That row is xss_candidate_low, which says "real
// reflection, recorded, not worth your afternoon" rather than sending the operator after it.
func XSSCandidateGrade(status, contentType string, survived []string, insertionPoint string) string {
	switch status {
	// A PASSIVE ECHO IS A CANDIDATE, NOT AN UNKNOWN. It grades LOW rather than high: the value came
	// back whole, which is real, but the crawl almost never sent a < so nothing here says the
	// encoding is dangerous. Low is also what makes it VISIBLE, and visibility is the point.
	//
	// It graded xss_unknown until a review pointed out the consequence: after the keep rule was
	// fixed so an active not_reflected wins, the rows that survive as reflected_observed are the
	// body inputs the active pass never sends, and on the engaged target all 15 of those were
	// hand-confirmed as genuine echoes of a submitted field. Grading them unknown meant the one
	// thing the passive pass was added to find could not light the card and was reported as zero in
	// the completion toast.
	case ReflectionObserved:
		return XSSCandidateLow
	case ReflectionRaw:
		if !ReflectionContentTypeRenders(contentType) || !ReflectionSurvivedMarkup(survived) {
			return XSSCandidateLow
		}
		// TRAP 3: it renders and markup survived, so the only question left is whether an attacker
		// can put the payload there. A cookie or header value is set by the victim's own browser, so
		// this is the one that needs a named chain rather than a link.
		if !ReflectionInsertionPointDeliverable(insertionPoint) {
			return XSSCandidateChain
		}
		return XSSCandidateHigh
	case ReflectionEncoded, ReflectionNotReflected:
		return XSSCandidateNone
	}
	// reflected_observed lands below with the unknowns ON PURPOSE. It is a real observation that the
	// input is echoed, and it is not an XSS candidate: the encoding was never tested, because the
	// crawl never sent a character worth encoding. Grading it as a candidate would put a row in
	// front of the operator claiming something nobody measured.
	//
	// blocked, error, needs_browser, not_probed, and anything unrecognised. Not a claim either way.
	return XSSCandidateUnknown
}

// ReflectionContentTypeRenders reports whether a browser would parse this response as markup, which
// is the difference between a reflection that can execute and one that can only be looked at.
//
// AN EMPTY CONTENT TYPE COUNTS AS RENDERING, and that is the deliberate call rather than an
// oversight. A response with no Content-Type is MIME sniffed, and a sniffed body that starts like
// markup is rendered as markup, so grading unknown as low would bury exactly the reflections that
// are easiest to weaponise. The other direction costs the operator one look at a row.
//
// XML is NOT in the list. Browsers render an XML document as a tree rather than executing it unless
// it carries an XHTML namespace, so calling every text/xml response high would put a large number of
// API responses at the top of the list for a rendering path that usually is not there.
func ReflectionContentTypeRenders(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	// Only the type, never the parameters: "text/html; charset=utf-8" and "text/html" are one thing.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	if ct == "" {
		return true
	}
	switch ct {
	case "text/html", "application/xhtml+xml", "image/svg+xml":
		return true
	}
	return false
}

// reflectionProbeChars are the four characters whose survival decides whether a reflection can be
// turned into markup. Order is fixed because the classifier walks the response in this order.
const reflectionProbeChars = `<>"'`

// reflectionCanaryPrefix marks a string in a response as ours. rs0nR rather than the framework's
// generic canary so a probe reflection cannot be confused with a value some other tool injected.
const reflectionCanaryPrefix = "rs0nR"

// reflectionCanarySentinel closes the payload. Alphanumeric on purpose: HTML entity encoding,
// percent encoding and JavaScript escaping all leave it byte for byte identical, so its presence is
// a fact about whether the echo finished rather than about how it was encoded.
const reflectionCanarySentinel = "rs0nE"

// reflectionEvidenceCap bounds the stored snippet. Full bodies are never persisted anywhere in this
// codebase and a reflection needs its surroundings, not its document.
const reflectionEvidenceCap = 400

// reflectionTailWindow is how far past the token the classifier will walk looking for the four probe
// characters. Generous enough for the longest encoding of four characters (< and friends, 24
// bytes) with room for a separator the application inserted, short enough that unrelated markup
// further down the page can never be mistaken for a surviving character.
const reflectionTailWindow = 128

// ReflectionCanaryToken is the per-input marker, and its uniqueness is what makes attribution
// certain.
//
// ONE REQUEST PER PARAMETER, NOT TWO. A single string carries both jobs: the token proves the
// reflection belongs to THIS parameter of THIS vector when a response echoes several inputs at once,
// and the four characters after it measure the encoding. A second control request would double the
// traffic against an engagement with a 60 req/s ceiling and produce no information the one request
// does not already carry.
//
// Derived from the ids rather than randomised, so re-probing a vector produces the same token: the
// operator can grep a saved response from last week for the row they are looking at now.
func ReflectionCanaryToken(vectorID, parameter string) string {
	sum := sha256.Sum256([]byte(vectorID + "\x00" + parameter))
	return reflectionCanaryPrefix + hex.EncodeToString(sum[:])[:8]
}

// ReflectionCanaryPayload is what actually goes into the input: the token, the four probe
// characters, and a CLOSING SENTINEL.
//
// THE SENTINEL IS NOT DECORATION, it is what makes the answer trustworthy. Without it the
// classifier has to guess where our payload ends in the response, and the first version did exactly
// that: it walked the bytes after the token looking for < > " ', and on a body reading
//
//	<p>rs0nRdeadbeef</p><script>...
//
// it found the < of the very next tag and reported a raw reflection on a page that had stripped
// every probe character. That is a false positive on almost every HTML endpoint in a corpus.
//
// With a sentinel the reflected region is BOUNDED at both ends, so the bytes examined are only ever
// ours, and it answers the encoding-against-truncation question for free: the sentinel is
// alphanumeric, so no encoder changes it. Present with an empty middle means the characters were
// STRIPPED; absent means the echo was CUT SHORT. Those have different next moves, so guessing
// between them would be worse than saying which.
func ReflectionCanaryPayload(token string) string {
	return token + reflectionProbeChars + reflectionCanarySentinel
}

// ReflectionOutcome is one probe's answer, and it is the whole of what gets stored.
type ReflectionOutcome struct {
	Status      string
	Survived    []string
	ContentType string
	HTTPStatus  int
	Evidence    string
	// Detail says WHICH: which encoding was applied, which block signature fired, which error was
	// returned. Without it "reflected_encoded" cannot be told from "reflected and then truncated",
	// and those are different propositions: one is a defence, the other is a buffer limit that a
	// shorter payload walks straight through.
	Detail      string
	AuthApplied bool
	// InsertionPoint travels with the verdict because the GRADE needs it: a raw reflection into HTML
	// is weaponisable from a query parameter and is self-XSS from a cookie, and those are two
	// different pieces of news. Set by ProbeReflection from the target; empty from
	// ClassifyReflectionResponse alone, which grades as deliverable, matching the unknown-is-visible
	// rule used for content type and survived.
	InsertionPoint string
}

// Grade is the label, derived on read so it can never drift from the row it describes.
func (o ReflectionOutcome) Grade() string {
	return XSSCandidateGrade(o.Status, o.ContentType, o.Survived, o.InsertionPoint)
}

// ReflectionSurvivedMarkup reports whether the characters that came back can OPEN A TAG.
//
// WHY THE GRADE CANNOT IGNORE THIS, measured on the first real run, 2026-09-17: of 14 raw
// reflections, 13 survived ONLY the single quote and one survived "<>'".
//
// That 13 is an artefact of JSON, not a property of the application. JSON string encoding escapes
// only the double quote and the backslash, so a single quote passes through every JSON encoder
// untouched, always, on every endpoint that echoes anything. Grading on "at least one of < > " '
// survived" therefore measures the encoding rules of the response format rather than the escaping
// done by the code.
//
// It was invisible here because every one of those responses was JSON and graded low on content
// type alone. On the first HTML target it would not be invisible: a lone quote would have graded
// HIGH and glowed, which is exactly the false lead the grading exists to prevent.
//
// A quote is NOT worthless. It is how an attribute or a JavaScript string is broken out of, and the
// survived list keeps it so an operator can see it. It is just not, on its own, evidence that markup
// can be injected, so it does not carry the top grade or light the card.
//
// UNKNOWN IS TREATED AS MARKUP, deliberately, matching the empty-content-type call in
// ReflectionContentTypeRenders: a nil list means nobody recorded what survived, and hiding a real
// candidate costs more than one look at a row.
func ReflectionSurvivedMarkup(survived []string) bool {
	if survived == nil {
		return true
	}
	for _, ch := range survived {
		if strings.Contains(ch, "<") {
			return true
		}
	}
	return false
}

// ClassifyReflectionResponse turns one response into one stored row.
//
// ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE. The body is searched for the token BEFORE the status
// code is judged, so a 403 whose error page echoes the canary raw is recorded as reflected_raw
// rather than blocked. Reflection that can be SEEN is knowledge; `blocked` is the absence of
// knowledge, and there is no reason to throw away a measurement that was actually made. The
// invariant that matters is the other one: a rejected request whose body does NOT contain the token
// must never become not_reflected, and it cannot, because every no-token branch below lands on
// blocked or error unless the endpoint answered normally.
func ClassifyReflectionResponse(token string, resp ScanResponse) ReflectionOutcome {
	out := ReflectionOutcome{
		ContentType: resp.ContentType,
		HTTPStatus:  resp.Status,
		AuthApplied: resp.AuthApplied,
	}

	// A transport failure is not a negative result. A timeout on the one endpoint that reflects is
	// indistinguishable from a clean endpoint once it has been written down as not_reflected.
	if resp.Err != nil {
		out.Status = ReflectionError
		out.Detail = "request_failed: " + resp.Err.Error()
		return out
	}

	if idx := strings.Index(resp.Body, token); idx >= 0 {
		return reflectionFromBody(token, resp, out)
	}

	switch {
	// 401 is NOT filed as blocked, because blocked means a WAF dropped the payload and the fix is to
	// get past the WAF. A 401 means the probe was unauthenticated or the session died mid-run, and
	// the fix is a credential. Two different next actions, so two different rows.
	case resp.Status == 401:
		out.Status = ReflectionError
		out.Detail = "http_401: the endpoint refused the request as unauthenticated, so nothing was " +
			"put in front of the application. Re-probe with a live session."
		return out
	// The rejection statuses named in the contract, plus 451 and 418, which the endpoint workflow's
	// blockStatuses has carried since it was written for the same reason. IsBlockStatus is NOT
	// reused wholesale here: it includes 401, which the branch above has already claimed.
	case resp.Status == 403, resp.Status == 406, resp.Status == 429, resp.Status == 451, resp.Status == 418:
		out.Status = ReflectionBlocked
		out.Detail = "http_" + strconv.Itoa(resp.Status) + ": the request was rejected rather than answered, " +
			"so whether this input reflects is UNKNOWN. A payload containing < is exactly what a WAF " +
			"drops."
		return out
	// A bot manager's interstitial can arrive with a 200. The status code says nothing then, and the
	// body is the only thing that does. Reused from the endpoint workflow rather than re-listed.
	case IsChallengeBody(resp.Body):
		out.Status = ReflectionBlocked
		out.Detail = "waf_challenge_body: the response is a bot manager or WAF interstitial rather " +
			"than the application, so whether this input reflects is UNKNOWN."
		return out
	// A 5xx is a response, but it is not an answer about reflection: the payload may have broken the
	// handler before it reached the code that would have echoed it. Worth a look on its own merits,
	// and worth nothing as evidence of a clean input.
	case resp.Status >= 500:
		out.Status = ReflectionError
		out.Detail = "http_" + strconv.Itoa(resp.Status) + ": the endpoint failed on this payload, so it never " +
			"reached the code that would echo it. This is not a clean result."
		return out
	}

	// A RESPONSE WITH NO BODY TO SEARCH IS NOT A NEGATIVE RESULT. Everything below this line reached
	// the fallthrough only because the branches above did not claim it, and the fallthrough used to
	// write not_reflected for all of it. Each of these was measured producing
	// "the endpoint answered normally and the canary was absent from the body" over an empty string.
	switch {
	// THE 3xx CASE IS THE LIKELY ONE, not a corner. ScanClient never follows redirects, deliberately:
	// its own header says "a 302 to /login is the single most useful observation Validate makes, and
	// a client that follows it reports 200 and destroys the evidence". A hop carries no body, so
	// searching it finds nothing, and this estate is a cookie-session SPA where an anonymous or
	// expired probe redirects rather than 401s. Filing that as not_reflected would have turned the
	// single most common wall response into a clean verdict.
	//
	// 304 is excluded from the redirect branch below even though it is numerically 3xx. It is a
	// cache response, not a hop: nothing redirected, the client is being told to reuse what it has.
	// Calling it "redirected instead of answering" would be false, and it has no Location to name.
	// Caught by the test rather than by inspection, because 304 sits inside the numeric range.
	case resp.Status == 204, resp.Status == 304:
		out.Status = ReflectionError
		out.Detail = "http_" + strconv.Itoa(resp.Status) + ": this status carries no body by definition, so " +
			"there was nothing to search."
		return out
	case resp.Status >= 300 && resp.Status < 400:
		out.Status = ReflectionBlocked
		out.Detail = "http_" + strconv.Itoa(resp.Status) + ": the endpoint redirected instead of answering" +
			reflectionLocationSuffix(resp) + ", so there was no body to search and whether this input " +
			"reflects is UNKNOWN. A hop to a login route usually means the probe measured the wall " +
			"rather than the application."
		return out
	// The edge rejected the request, so the application never saw the payload. Different from a WAF
	// block only in who refused it, and identical in what it tells you about reflection: nothing.
	case resp.Status == 400, resp.Status == 405, resp.Status == 415:
		out.Status = ReflectionError
		out.Detail = "http_" + strconv.Itoa(resp.Status) + ": the request was rejected before the application " +
			"processed the payload, so this says nothing about whether the input reflects."
		return out
	// The body was cut at the read cap. A reflection past the cap is invisible, so the absence of the
	// canary in the part that was read proves nothing about the part that was not.
	case resp.Truncated:
		out.Status = ReflectionError
		out.Detail = "the response body was truncated at the read cap, so the canary may sit in the part " +
			"that was never read. This is not a clean result."
		return out
	// A body of zero bytes on a status that should have one. Nothing was searched.
	case strings.TrimSpace(resp.Body) == "":
		out.Status = ReflectionError
		out.Detail = "http_" + strconv.Itoa(resp.Status) + ": the response body was empty, so there was " +
			"nothing to search."
		return out
	}

	out.Status = ReflectionNotReflected
	// Deliberately NOT "answered normally". In a one request design with no control, an input filter
	// that strips the whole parameter is byte identical to an endpoint that simply does not echo, so
	// this status is "the canary was not in the body", which is weaker than "this input is safe".
	out.Detail = "http_" + strconv.Itoa(resp.Status) + ": the canary was not present in the response body. " +
		"Note that an input filter which drops the parameter entirely looks identical to an endpoint " +
		"that does not echo it."
	return out
}

// reflectionLocationSuffix names the redirect target when there is one, because "redirected to
// /login" and "redirected to /dashboard" are different pieces of news to the operator.
func reflectionLocationSuffix(resp ScanResponse) string {
	if loc := strings.TrimSpace(resp.Location); loc != "" {
		if len(loc) > 120 {
			loc = loc[:120] + "..."
		}
		return " to " + loc
	}
	return ""
}

// reflectionFromBody decides raw against encoded, and says which encoding it saw.
//
// EVERY occurrence is examined, not the first. An application routinely echoes one input twice, once
// HTML-escaped into the page text and once raw into a script block or an attribute, and taking the
// first match would report the escaped one and file a live XSS as reflected_encoded. The most
// dangerous occurrence wins and its surroundings become the evidence.
func reflectionFromBody(token string, resp ScanResponse, out ReflectionOutcome) ReflectionOutcome {
	bestSurvived := []string(nil)
	bestDetail := ""
	bestIdx := -1

	from := 0
	for {
		rel := strings.Index(resp.Body[from:], token)
		if rel < 0 {
			break
		}
		idx := from + rel
		survived, detail := reflectionMiddleVerdict(resp.Body, idx+len(token))
		if bestIdx < 0 || len(survived) > len(bestSurvived) {
			bestSurvived, bestDetail, bestIdx = survived, detail, idx
		}
		from = idx + len(token)
	}

	out.Survived = bestSurvived
	out.Evidence = reflectionSnippet(resp.Body, bestIdx)

	if len(bestSurvived) > 0 {
		out.Status = ReflectionRaw
		// Where it landed decides how much work the operator has left, and reflectionContext already
		// answers that for the endpoint workflow's signals. Reused rather than re-derived.
		where, _ := reflectionContext(resp.Body, bestIdx, len(token))
		out.Detail = "survived=" + strings.Join(bestSurvived, "") + " context=" + where
		if bestDetail != "" {
			out.Detail += " " + bestDetail
		}
		return out
	}

	out.Status = ReflectionEncoded
	out.Detail = bestDetail
	return out
}

// reflectionMiddleVerdict reads the bytes BETWEEN the token and the closing sentinel, and says which
// of < > " ' came back intact.
//
// BOUNDED AT BOTH ENDS, which is the whole reliability of this feature. Only the bytes our own
// payload produced are ever examined, so nothing the surrounding document contains can be counted as
// a surviving character. The earlier version scanned forward from the token and reported the < of
// the next tag as a survivor on any HTML page that had stripped the payload.
//
// A MISSING SENTINEL IS ITS OWN ANSWER. The sentinel is alphanumeric and survives every encoding, so
// if it is not there the echo was cut short rather than filtered, and a shorter payload may well get
// through where this one did not.
func reflectionMiddleVerdict(body string, start int) (survived []string, detail string) {
	if start > len(body) {
		return nil, "truncated: the response ended at the canary"
	}
	end := start + reflectionTailWindow
	if end > len(body) {
		end = len(body)
	}
	window := body[start:end]

	stop := strings.Index(window, reflectionCanarySentinel)
	if stop < 0 {
		return nil, "truncated: the closing marker did not come back, so the echo was cut short " +
			"rather than filtered. A shorter payload may get through."
	}
	middle := window[:stop]
	if middle == "" {
		return nil, "stripped: the canary came back with all four of < > \" ' removed"
	}

	residue, encodings, encodedCount := stripReflectionEncodings(middle)
	for i := 0; i < len(reflectionProbeChars); i++ {
		if strings.IndexByte(residue, reflectionProbeChars[i]) >= 0 {
			survived = append(survived, string(reflectionProbeChars[i]))
		}
	}

	// What is left once the raw survivors and the escaped ones are accounted for was simply
	// deleted. A count rather than a list, because a character a filter removed leaves nothing
	// behind to name it by.
	removed := len(reflectionProbeChars) - len(survived) - encodedCount
	if removed < 0 {
		removed = 0
	}
	switch {
	case len(encodings) > 0 && removed > 0:
		detail = "encoded=" + strings.Join(encodings, ",") + " stripped=" + strconv.Itoa(removed)
	case len(encodings) > 0:
		detail = "encoded=" + strings.Join(encodings, ",")
	case removed > 0:
		detail = "stripped=" + strconv.Itoa(removed)
	}
	return survived, detail
}

// reflectionEncodingForms are the escaped shapes a defence turns the four probe characters into.
//
// SORTED LONGEST FIRST, and the order is load bearing: &#x3c; must be matched before &#x3 could be,
// and < before \x3c would half-match it. All lower case, because matching is done against a
// lower-cased copy: &#X3C and &#x3c are one escape, and treating the upper-case form as unknown
// would report "stripped" on a target that is in fact encoding correctly.
var reflectionEncodingForms = sortedReflectionEncodings([]reflectionEncoding{
	{"&lt;", "html_entity"}, {"&#x3c;", "html_entity"}, {"&#60;", "html_entity"},
	{"&gt;", "html_entity"}, {"&#x3e;", "html_entity"}, {"&#62;", "html_entity"},
	{"&quot;", "html_entity"}, {"&#x22;", "html_entity"}, {"&#34;", "html_entity"},
	{"&#x27;", "html_entity"}, {"&#39;", "html_entity"}, {"&apos;", "html_entity"},
	{"%3c", "percent"}, {"%3e", "percent"}, {"%22", "percent"}, {"%27", "percent"},
	{"\\u003c", "js_unicode"}, {"\\u003e", "js_unicode"},
	{"\\u0022", "js_unicode"}, {"\\u0027", "js_unicode"},
	{"\\x3c", "js_hex"}, {"\\x3e", "js_hex"}, {"\\x22", "js_hex"}, {"\\x27", "js_hex"},
	{"\\<", "backslash"}, {"\\>", "backslash"}, {"\\\"", "backslash"}, {"\\'", "backslash"},
})

type reflectionEncoding struct{ form, name string }

func sortedReflectionEncodings(forms []reflectionEncoding) []reflectionEncoding {
	sort.SliceStable(forms, func(i, j int) bool { return len(forms[i].form) > len(forms[j].form) })
	return forms
}

// stripReflectionEncodings removes every known escaped form of the four probe characters and reports
// which schemes it saw, leaving whatever came back RAW.
//
// Removal rather than a contains() check, because the two are not the same question for a JSON body:
// \" is a quote that does NOT break out of a string, so counting the " inside it as survived would
// report a raw reflection on a correctly escaped API response. Removing the escape first leaves only
// characters that are genuinely unescaped in the document as it was served.
//
// Longest form first, so &#x3c; is never half-consumed as &#x3, and matched case insensitively
// because &#X3C and &#x3c are one escape. A case sensitive check would call the upper-case form
// "stripped", which reads as a defence on a target that is in fact encoding correctly.
func stripReflectionEncodings(middle string) (residue string, encodings []string, encodedCount int) {
	lower := strings.ToLower(middle)
	seen := map[string]bool{}
	var kept strings.Builder

	i := 0
	for i < len(middle) {
		matched := false
		for _, enc := range reflectionEncodingForms {
			if strings.HasPrefix(lower[i:], enc.form) {
				if !seen[enc.name] {
					seen[enc.name] = true
					encodings = append(encodings, enc.name)
				}
				encodedCount++
				i += len(enc.form)
				matched = true
				break
			}
		}
		if !matched {
			kept.WriteByte(middle[i])
			i++
		}
	}
	return kept.String(), encodings, encodedCount
}

// reflectionSnippet is the bounded excerpt stored as evidence, centred on the reflection.
func reflectionSnippet(body string, idx int) string {
	if idx < 0 {
		return ""
	}
	before := reflectionEvidenceCap / 3
	start := idx - before
	if start < 0 {
		start = 0
	}
	end := start + reflectionEvidenceCap
	if end > len(body) {
		end = len(body)
	}
	return body[start:end]
}

// ---------------------------------------------------------------- what to send where

// ReflectionProbeTarget is one canary, aimed. Built before any request is issued so the plan can be
// counted, shown as progress, and asserted on in a test without a network.
type ReflectionProbeTarget struct {
	VectorID       string
	InsertionPoint string
	Method         string
	// Parameter is the input being probed: the query parameter, the cookie name, the header name or
	// the body field. EMPTY for a path vector, whose segment IS the input and has no name, and for a
	// fragment vector, which is never sent.
	Parameter string
	Token     string
	// URL is the fully composed request, canary already in place for a query or path probe. Empty
	// for a fragment vector, because there is no request to compose.
	URL string
	// CookieHeader is the WHOLE Cookie header a cookie probe sends: every cookie the captured
	// request carried, with exactly one value replaced by the canary. Every other cookie has to be
	// there or the request stops being the one the operator thinks it is, and for a session cookie
	// that means a 401, and a 401 injects nothing.
	CookieHeader string
	// Body and BodyContentType are the composed request body for a body probe: the captured body
	// with the canary in ONE field and every other field at the value it was captured with.
	Body            string
	BodyContentType string
	// NeedsCredential records that this vector was captured with authentication. A probe of an
	// auth-only route without one gets a 401, reflects nothing, and would otherwise be written down
	// as not_reflected: a false negative wearing a coverage badge.
	NeedsCredential bool
	// VerbNotReplayed is the captured verb when it was something other than the verb the probe will
	// send, empty otherwise. Query, path, cookie and header probes are always GET, so this is how the
	// operator learns the verb was downgraded rather than inferring it was exercised. A BODY probe is
	// the one case where the captured verb IS sent, and there this stays empty because nothing was
	// downgraded: see planReflectionBodyTargets.
	VerbNotReplayed string
	// SkipStatus and SkipDetail are a decision, made AT PLAN TIME, not to send this request at all.
	//
	// The row still exists, still names the input, and says WHY nothing was sent. That is the whole
	// point: a body vector the probe refused to send must not read not_probed, because not_probed
	// means nobody got round to it and this one was decided against.
	SkipStatus string
	SkipDetail string
}

// reflectionProbablePoints are the insertion points this probe can answer for.
//
// ALL FIVE the consolidator can produce, plus fragment. query, path and fragment were first; cookie,
// header and body were added after the first live run measured the gap at 137 of 218 vectors on the
// engaged target, the largest single group in the table being cookie at 75. A vector with no probe
// row reads as unexamined attack surface, and 137 of them read as most of it.
//
// fragment is in the map and still sends nothing: it is the one container that never goes on the
// wire, so it gets needs_browser rather than a silence.
var reflectionProbablePoints = map[string]bool{
	"query": true, "path": true, "fragment": true,
	"cookie": true, "header": true, "body": true,
}

// ReflectionProbeApplies reports whether this probe can say anything about an insertion point.
func ReflectionProbeApplies(insertionPoint string) bool {
	return reflectionProbablePoints[insertionPoint]
}

// ReflectionProbedPoints is the same list as data, for the API and the UI to read rather than
// re-type. Sorted so the answer is stable across calls; Go's map iteration order is not.
//
// It exists because the status endpoint used to carry the literal []string{"query","path",
// "fragment"} and the unprobed-points query used to carry the same three inside a NOT IN clause.
// Three copies of a list is three places for it to disagree with the planner, and that disagreement
// shows up as a coverage number that is wrong in the confident direction.
func ReflectionProbedPoints() []string {
	out := make([]string, 0, len(reflectionProbablePoints))
	for point := range reflectionProbablePoints {
		out = append(out, point)
	}
	sort.Strings(out)
	return out
}

// ReflectionInsertionPointDeliverable reports whether an ATTACKER can put a payload in this input by
// handing a victim a link.
//
// TRAP 3, and the rule is not this file's invention: the framework already ships it, in
// docker/mcp-server/src/guidance/scanning.js under manage_xss.rule, in these words. query, path and
// fragment are attacker-delivered and reportable on their own. cookie and header are set by the
// browser the victim already has, so on their own they are self-XSS, and one becomes real only with
// a NAMED and demonstrated chain that lets an attacker set that value: CRLF injection into a
// Set-Cookie, a cookie write from a sibling subdomain the parent trusts, or a cache that stores the
// payload and serves it to other users.
//
// body is NOT deliverable either, by the rule's own test, which is whether the attacker controls the
// URL. A cross-site form POST can reach a form-encoded endpoint with no CSRF token, and that is a
// real chain and a named one, but it is a chain rather than a link.
//
// AN UNKNOWN INSERTION POINT IS TREATED AS DELIVERABLE, matching the empty-content-type call above:
// a row from an older build that carries no insertion point must not be demoted out of the
// operator's sight by a rule it predates.
func ReflectionInsertionPointDeliverable(insertionPoint string) bool {
	switch strings.ToLower(strings.TrimSpace(insertionPoint)) {
	case "cookie", "header", "body":
		return false
	}
	return true
}

// ReflectionPlanContext is what the planner needs to know BEYOND the vector itself.
//
// The two credential fields are per host and both exist to answer TRAP 2: the input being fuzzed is
// often the credential. The authoritative answer is not a name list, it is "would the framework
// itself put a value in this input on this request", and that is what these carry.
type ReflectionPlanContext struct {
	// CredentialCookies and CredentialHeaders are the cookie and header names the credential held
	// for this vector's host would set. Headers are lower cased and cookies are not, because header
	// names are case insensitive on the wire and cookie names are not.
	CredentialCookies map[string]bool
	CredentialHeaders map[string]bool
}

// reflectionCredentialHeaderNames are the headers that carry a credential whatever the target calls
// itself.
//
// MEASURED on the live estate, 2026-09-17: all 49 header vectors on the engaged target fuzz
// `authorization`, and nothing else. Putting a canary in that header sends the request with no
// credential, the API answers 401, and the body reflects nothing. Filed as not_reflected that is 49
// clean rows describing the login wall. In the dalfox campaign this same class aborted a pass after
// three consecutive session losses and had to be reported as its own class rather than folded into
// a clean total.
var reflectionCredentialHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"x-session-token":     true,
	"x-csrf-token":        true,
	"x-xsrf-token":        true,
	"authentication":      true,
}

// reflectionCredentialCookieNames are cookie names that are an AUTHENTICATION cookie by name.
//
// Deliberately exact names and one prefix rather than a substring match on "sess" or "auth". The
// live cookie list contains intercom-session-p7a9jdob, and overwriting an Intercom analytics cookie
// costs nothing: a greedy match would refuse to probe it and lose real coverage to a word.
//
// MEASURED: of 1655 cookie parameter slots on the engaged target, 700 match this list or the prefix
// and 955 do not. The 700 are the CognitoIdentityServiceProvider.* family, which is where this
// estate's session lives, so a canary in one of them logs the request out exactly as a canary in
// Authorization does.
var reflectionCredentialCookieNames = map[string]bool{
	"jsessionid": true, "phpsessid": true, "asp.net_sessionid": true, "connect.sid": true,
	"sessionid": true, "session_id": true, "session": true, "sid": true, "_session_id": true,
	"laravel_session": true, "remember_token": true,
	"auth": true, "authtoken": true, "auth_token": true,
	"access_token": true, "accesstoken": true, "id_token": true, "idtoken": true,
	"refresh_token": true, "refreshtoken": true,
	"csrftoken": true, "csrf_token": true, "xsrf-token": true, "_csrf": true,
	"__requestverificationtoken": true, "amplify-signin-with-hostedui": true,
}

// reflectionCredentialCookiePrefixes are families whose every member is a credential.
var reflectionCredentialCookiePrefixes = []string{"cognitoidentityserviceprovider."}

// reflectionReservedHeaderNames are headers the SCAN CLIENT ITSELF sets, so a canary in one of them
// measures the framework rather than the application.
//
// Each entry is a different way that measurement comes out WRONG, not merely useless:
//
//	host              Go ignores Header.Set("Host") and uses Request.Host, so the canary never
//	                  leaves and the response honestly does not contain it: a false not_reflected.
//	content-length    ScanClient.Do sets it from the bytes it is actually writing. A canary here is
//	                  either ignored or makes the request unparseable to the server.
//	accept-encoding   pinned to identity so wire sizes stay comparable AND so the body is readable.
//	                  A canary can bring back a gzipped body the classifier cannot search: another
//	                  false not_reflected, and the kind that looks like a clean result.
//	transfer-encoding, connection   hop by hop, owned by the transport.
//	x-ars0n-framework the attribution header. Overwriting it strips the marker that tells the
//	                  program these requests are authorised testing, which is a rules-of-engagement
//	                  problem before it is a measurement problem.
//
// User-Agent, Accept and Referer are deliberately NOT here. Do sets them first and the caller's
// Headers win, so the canary does go out, and a User-Agent reflection is a real and classic finding.
var reflectionReservedHeaderNames = map[string]bool{
	"host": true, "content-length": true, "accept-encoding": true,
	"transfer-encoding": true, "connection": true, "x-ars0n-framework": true,
}

// ReflectionInputIsCredential reports whether putting a canary in this input would throw the
// request's own credential away.
//
// TRAP 2. It is not a failure and it is not a negative result: it is a question this method cannot
// ask, because the method's one request has to carry the credential in order to reach the
// application at all. The honest answer is its own status, is_credential, and NO request.
//
// Three sources, most authoritative first:
//  1. the credential the framework HOLDS for this host names this cookie or header. Nothing beats
//     this: it is the framework saying it would put its own value here.
//  2. the name is an authentication name.
//  3. the captured VALUE is a JWT. Cognito names its cookies per user pool, so a target using a
//     name nobody listed is still caught by what the cookie contains.
func ReflectionInputIsCredential(insertionPoint, name, observedValue string, plan ReflectionPlanContext) bool {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)

	switch insertionPoint {
	case "header":
		if plan.CredentialHeaders[lower] {
			return true
		}
		return reflectionCredentialHeaderNames[lower]
	case "cookie":
		if plan.CredentialCookies[trimmed] {
			return true
		}
		if reflectionCredentialCookieNames[lower] {
			return true
		}
		for _, prefix := range reflectionCredentialCookiePrefixes {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
		return reflectionValueLooksLikeJWT(observedValue)
	}
	// query, path, fragment and body. A credential that rides in the URL is the same trap wearing a
	// different hat, and it is caught at send time by reflectionAuthSupplies, which reads the
	// material that is about to be applied rather than a name list.
	return false
}

// reflectionValueLooksLikeJWT recognises a compact JWS by shape: three base64url segments separated
// by dots, the first of which starts the way a JOSE header does.
//
// Shape only, never a decode. The question is "is this a credential", not "is this token valid", and
// a probe that parsed tokens would be one library away from logging one.
func reflectionValueLooksLikeJWT(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 20 || strings.Count(value, ".") != 2 {
		return false
	}
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i := 0; i < len(part); i++ {
			c := part[i]
			isB64URL := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
				(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '='
			if !isB64URL {
				return false
			}
		}
	}
	// eyJ is base64url for {" , which is how every JOSE header begins.
	return strings.HasPrefix(parts[0], "eyJ")
}

// BuildReflectionProbeTargets plans the requests for one vector with no knowledge of what
// credentials are held. Kept as the two-argument form because every existing caller and test uses
// it, and because the name-based halves of the credential and safety rules need no context.
func BuildReflectionProbeTargets(v VectorInput, needsCredential bool) []ReflectionProbeTarget {
	return BuildReflectionProbeTargetsWithPlan(v, needsCredential, ReflectionPlanContext{})
}

// BuildReflectionProbeTargetsWithPlan plans the requests for one vector: one per query parameter,
// one for a path vector, one no-request placeholder for a fragment vector, one per cookie, one per
// header and one per body field.
func BuildReflectionProbeTargetsWithPlan(v VectorInput, needsCredential bool,
	plan ReflectionPlanContext) []ReflectionProbeTarget {

	if !ReflectionProbeApplies(v.InsertionPoint) {
		return nil
	}
	// THE CAPTURED VERB IS NOT REPLAYED, for every insertion point that can be probed with a GET.
	// Reflection characterises an INPUT; it does not exercise a verb, and the same payload in the
	// same parameter reflects or does not reflect regardless of how the request that first showed it
	// was made.
	//
	// Replaying it would have been an incident on the first live run. Measured on the live corpus:
	// 9 POST, 4 PATCH, 3 PUT and 2 DELETE path vectors plus 1 PUT query vector, 19 in total, every
	// one of them authenticated. A DELETE against a paper account is not a measurement, it is a
	// deletion. scanHTTP.go's allowedScanMethods comment records that this exact defect already
	// happened once here: "a crawl that captured DELETE /api/keys/7 sent a real, authenticated
	// DELETE", and endpointInvestigationUtils.go has downgraded to GET ever since for the same
	// reason.
	//
	// GET rather than the safe-subset passthrough, because HEAD is in that subset and scanHTTP
	// discards a HEAD body (ReadBody is gated on method != HEAD). A HEAD probe would search an
	// empty string and record not_reflected against an endpoint that reflects perfectly well:
	// measured GET reflected_raw / HEAD not_reflected on one endpoint with one payload. Forcing GET
	// closes both holes in one line.
	//
	// THE ONE EXCEPTION IS body, and it is an exception because the rule cannot apply there: a GET
	// with the body stripped is not a probe of a body field, it is a different request. That is
	// TRAP 1, and planReflectionBodyTargets is where it is resolved.
	method := "GET"
	captured := strings.ToUpper(strings.TrimSpace(v.Method))
	notReplayed := ""
	if captured != "" && captured != "GET" {
		// Recorded, not discarded. An operator looking at a POST vector probed with GET has to be
		// able to see that the verb was downgraded, or they will read the result as though the
		// original request had been made. endpointInvestigationUtils.go surfaces the same fact as
		// VerbNotReplayed for the same reason.
		notReplayed = captured
	}

	// A fragment never leaves the browser, so there is nothing to compose and nothing to send. The
	// target is built anyway so the vector appears in the plan, in the progress count and in the
	// results table with needs_browser against it, rather than silently not existing.
	if v.InsertionPoint == "fragment" {
		return []ReflectionProbeTarget{{
			VectorID: v.VectorID, InsertionPoint: "fragment", Method: method,
			Token: ReflectionCanaryToken(v.VectorID, ""), NeedsCredential: needsCredential,
			VerbNotReplayed: notReplayed,
		}}
	}

	// Templated segments are made concrete FIRST. /rest/products/{id}/reviews sent literally is a
	// route the application does not have: it answers 404 or a catch-all page, and the probe then
	// measures the error page instead of the endpoint. dalfoxTargetURL has done this since the same
	// problem was found there; vectorConcreteTemplatedURL is that logic, shared.
	base := vectorConcreteTemplatedURLFrom(v.TargetURL(), v.EvidenceURL)

	if v.InsertionPoint == "path" {
		token := ReflectionCanaryToken(v.VectorID, "")
		probeURL, ok := reflectionPathProbeURL(base, ReflectionCanaryPayload(token))
		if !ok {
			return nil
		}
		return []ReflectionProbeTarget{{
			VectorID: v.VectorID, InsertionPoint: "path", Method: method,
			Token: token, URL: probeURL, NeedsCredential: needsCredential,
			VerbNotReplayed: notReplayed,
		}}
	}

	switch v.InsertionPoint {
	case "cookie":
		return planReflectionCookieTargets(v, needsCredential, plan, base, method, notReplayed)
	case "header":
		return planReflectionHeaderTargets(v, needsCredential, plan, base, method, notReplayed)
	case "body":
		return planReflectionBodyTargets(v, needsCredential, plan, base, captured)
	}

	parsed, err := url.Parse(base)
	if err != nil {
		return nil
	}
	names := v.Parameters
	if len(names) == 0 {
		return nil
	}
	out := make([]ReflectionProbeTarget, 0, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			continue
		}
		token := ReflectionCanaryToken(v.VectorID, name)
		// A copy per parameter, so each request carries the canary in ONE input and the other
		// parameters keep their observed values. Probing them all at once would make a reflection
		// impossible to attribute, which is the whole reason the token is per parameter.
		one := *parsed
		q := parsed.Query()
		q.Set(name, ReflectionCanaryPayload(token))
		one.RawQuery = q.Encode()
		out = append(out, ReflectionProbeTarget{
			VectorID: v.VectorID, InsertionPoint: "query", Method: method,
			Parameter: name, Token: token, URL: one.String(), NeedsCredential: needsCredential,
			VerbNotReplayed: notReplayed,
		})
	}
	return out
}

// planReflectionCookieTargets: one GET per cookie, with the canary in THAT cookie's value and every
// other cookie the captured request carried left exactly as it was.
//
// A cookie probe needs no verb decision. The cookie is read on the way in, so a GET asks the question
// as well as the captured verb would and cannot change anything on the way out. That is why cookie
// and header are the straightforward pair and body is not.
//
// Every other cookie is preserved because a request missing them is not the request the operator
// thinks it is. observedRequestValues has carried this rule for the scanners since a cookie vector
// lost its real token to a marker and every payload came back 401; this is the same rule, applied
// one layer earlier.
func planReflectionCookieTargets(v VectorInput, needsCredential bool, plan ReflectionPlanContext,
	base, method, notReplayed string) []ReflectionProbeTarget {

	names := v.Parameters
	if len(names) == 0 {
		return nil
	}
	out := make([]ReflectionProbeTarget, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		token := ReflectionCanaryToken(v.VectorID, name)
		target := ReflectionProbeTarget{
			VectorID: v.VectorID, InsertionPoint: "cookie", Method: method,
			Parameter: name, Token: token, URL: base, NeedsCredential: needsCredential,
			VerbNotReplayed: notReplayed,
		}
		if ReflectionInputIsCredential("cookie", name, v.ObservedValues[name], plan) {
			// TRAP 2. Overwriting this cookie logs the request out, the API answers 401, and a 401
			// reflects nothing. That is a measurement of the login wall rather than of the input, so
			// no request is sent and the row says which.
			target.SkipStatus = ReflectionIsCredential
			target.SkipDetail = "is_credential(cookie " + name + "): a canary in this cookie replaces " +
				"the session this request needs, so the target would answer 401 and the body would " +
				"reflect nothing. No request was sent. To answer it, set this cookie by hand in a " +
				"browser session you are willing to lose, or find the chain that lets an attacker " +
				"set it."
			out = append(out, target)
			continue
		}
		target.CookieHeader = reflectionCookieHeader(v.ObservedValues, name, ReflectionCanaryPayload(token))
		out = append(out, target)
	}
	return out
}

// planReflectionHeaderTargets: one GET per header, with the canary as THAT header's value.
//
// Idempotent for the same reason a cookie probe is. Two inputs are refused before any request is
// built: a header that IS the credential (TRAP 2), and a header the scan client sets itself, where
// the probe would collide with its own instrumentation and measure that instead.
func planReflectionHeaderTargets(v VectorInput, needsCredential bool, plan ReflectionPlanContext,
	base, method, notReplayed string) []ReflectionProbeTarget {

	names := v.Parameters
	if len(names) == 0 {
		return nil
	}
	out := make([]ReflectionProbeTarget, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		token := ReflectionCanaryToken(v.VectorID, name)
		target := ReflectionProbeTarget{
			VectorID: v.VectorID, InsertionPoint: "header", Method: method,
			Parameter: name, Token: token, URL: base, NeedsCredential: needsCredential,
			VerbNotReplayed: notReplayed,
		}
		switch {
		case ReflectionInputIsCredential("header", name, v.ObservedValues[name], plan):
			// TRAP 2, and on this estate it is the whole class: all 49 header vectors fuzz
			// `authorization`.
			target.SkipStatus = ReflectionIsCredential
			target.SkipDetail = "is_credential(header " + name + "): a canary in this header sends " +
				"the request with no credential, the target answers 401, and the body reflects " +
				"nothing. No request was sent. Answer it with a second identity whose session you " +
				"are willing to spend, not with this probe."
		case reflectionReservedHeaderNames[strings.ToLower(name)]:
			target.SkipStatus = ReflectionProbeRefused
			target.SkipDetail = "framework_header(" + name + "): the scan client sets this header " +
				"itself, so a probe of it measures this framework rather than the target, and in " +
				"the Host and Accept-Encoding cases the canary either never leaves or comes back " +
				"inside a compressed body the classifier cannot search. Either way the row would " +
				"read not_reflected and mean nothing. No request was sent."
		default:
			// The value goes on the wire through ScanRequest.Headers, which Do applies AFTER its own
			// instrumentation and BEFORE the credential. Nothing else needs composing.
		}
		out = append(out, target)
	}
	return out
}

// planReflectionBodyTargets resolves TRAP 1: A BODY VECTOR CANNOT BE PROBED WITH GET, AND ITS REAL
// VERB MUTATES DATA.
//
// The tension is real, and picking a side quietly would be wrong either way, so here is the rule and
// the defence of it.
//
// PUT AND DELETE ARE NEVER SENT, at any setting, and no flag unlocks them. A blind authenticated
// DELETE is not a measurement; it is the defect scanHTTP.go's allowedScanMethods comment already
// records happening once here ("a crawl that captured DELETE /api/keys/7 sent a real, authenticated
// DELETE"). PUT replaces a whole resource with whatever body we composed, so a PUT probe of one
// field of /api/v1/oauth/clients/{token} would overwrite that client's other nine fields with
// whatever values the crawl happened to capture. There is no opt in that makes either of those a
// reasonable thing to do to somebody's estate.
//
// POST AND PATCH ARE REFUSED BY DEFAULT AND UNLOCKED PER RUN. Refused, because a canary in one field
// of a POST creates a record: measured on the engaged target, the body vectors include
// POST /api/v1/accounts/{uuid}/watchlists and two POST /api/v1/paper_accounts/{uuid}/orders with 7
// and 8 fields, so one default-on run would create two watchlists and fifteen paper orders. A probe
// that creates fifteen orders is a worse outcome than an unprobed insertion point, because the
// unprobed insertion point is recoverable by asking again and the orders are not.
//
// Unlockable rather than banned, because POST and PATCH are the only way a body is read at all, and
// an operator with a disposable account is entitled to spend it. The opt in is PER RUN rather than a
// saved setting, so it cannot be left on and forgotten; it is recorded on the run row, so a run that
// mutated something says so afterwards; and it never touches PUT or DELETE.
//
// A CAPTURED GET WITH A BODY NEEDS NO OPT IN. It is idempotent by definition, and one of the 13 body
// vectors on the engaged target is one.
//
// The row for a refused input is probe_refused, NOT not_probed. not_probed means nobody got round to
// it; this one was decided against. The operator needs to tell those apart, because the first is
// answered by pressing the button again and the second by a decision only they can make.
func planReflectionBodyTargets(v VectorInput, needsCredential bool, plan ReflectionPlanContext,
	base, captured string) []ReflectionProbeTarget {

	names := v.Parameters
	if len(names) == 0 {
		return nil
	}
	verb := captured
	if verb == "" {
		// A body vector with no recorded verb is not a GET. The consolidator only ever calls an
		// insertion point body when it saw a request with a body, and assuming the safe verb here
		// would send one of the mutating ones through the safe path.
		verb = "POST"
	}

	// The verb decision is made ONCE for the vector, before any field is composed, so a refusal can
	// never depend on whether a particular field happened to parse.
	refusal := ""
	switch verb {
	case "GET", "HEAD", "OPTIONS":
		// Safe and idempotent. Sent.
	case "PUT", "DELETE", "POST", "PATCH":
		// NO SETTING UNLOCKS THIS ANY MORE. A body probe has to send the verb that carries a body,
		// and all four of these change data: a canary in one field creates or edits a real record.
		// The passive pass answers the same field out of the request and response the crawl already
		// stored, so there is nothing left to buy by writing to somebody's estate.
		refusal = "would_mutate(" + verb + "): this probe never sends a " + verb + ". The passive " +
			"pass reads this field out of the stored request and response instead. No request was sent."
	default:
		refusal = "would_mutate(" + verb + "): this verb is not one this probe knows to be safe, so " +
			"it is refused rather than guessed at. No request was sent."
	}

	out := make([]ReflectionProbeTarget, 0, len(names))
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		token := ReflectionCanaryToken(v.VectorID, name)
		target := ReflectionProbeTarget{
			VectorID: v.VectorID, InsertionPoint: "body", Method: verb,
			Parameter: name, Token: token, URL: base, NeedsCredential: needsCredential,
		}
		if refusal != "" {
			target.SkipStatus = ReflectionProbeRefused
			target.SkipDetail = refusal
			out = append(out, target)
			continue
		}
		body, contentType, ok := reflectionBodyProbe(v.ContentType, v.Body, name,
			ReflectionCanaryPayload(token))
		if !ok {
			// Refused rather than synthesised. Composing a body out of nothing, or adding a field the
			// captured request never carried, is inventing a request: on a POST that is how a probe
			// creates a record with a shape the application did not expect, and the answer it gets
			// back describes the invention rather than the input.
			target.SkipStatus = ReflectionProbeRefused
			target.SkipDetail = "uncomposable_body(" + name + "): the captured request has no body " +
				"this probe can edit (empty, unparseable, an unsupported type, or no such field in " +
				"it), and a body invented here would be a request the crawl never saw. No request " +
				"was sent."
			out = append(out, target)
			continue
		}
		target.Body, target.BodyContentType = body, contentType
		out = append(out, target)
	}
	return out
}

// reflectionBodyProbe puts the canary in ONE field of the captured body and leaves every other field
// at the value it was captured with.
//
// REPLACES, NEVER ADDS. A field that is not already in the captured body returns false, because
// adding one composes a request nobody observed: the endpoint's answer would then be about the shape
// we invented rather than about the input we meant to test.
//
// JSON re-marshals through map[string]any, so key order and number formatting are Go's rather than
// the capture's. That is a real difference from the bytes on the wire and it is accepted here: the
// stored probe_url and canary are what reproduce the row, and no application this codebase has met
// keys its behaviour on JSON member order.
func reflectionBodyProbe(contentType, captured, field, payload string) (string, string, bool) {
	captured = strings.TrimSpace(captured)
	if captured == "" || strings.TrimSpace(field) == "" {
		return "", "", false
	}
	essence := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(essence, ';'); i >= 0 {
		essence = strings.TrimSpace(essence[:i])
	}
	switch {
	case strings.Contains(essence, "json"):
		var doc map[string]any
		if err := json.Unmarshal([]byte(captured), &doc); err != nil || doc == nil {
			return "", "", false
		}
		if _, ok := doc[field]; !ok {
			return "", "", false
		}
		doc[field] = payload
		encoded, err := json.Marshal(doc)
		if err != nil {
			return "", "", false
		}
		if contentType == "" {
			contentType = "application/json"
		}
		return string(encoded), contentType, true
	case essence == "application/x-www-form-urlencoded":
		values, err := url.ParseQuery(captured)
		if err != nil {
			return "", "", false
		}
		if _, ok := values[field]; !ok {
			return "", "", false
		}
		values.Set(field, payload)
		return values.Encode(), contentType, true
	}
	// multipart, XML and everything else. Refused rather than edited with string surgery, because a
	// multipart body edited without recomputing its boundary is a request the server rejects, and a
	// 400 the probe caused is indistinguishable from a 400 the input caused.
	return "", "", false
}

// reflectionCookieHeader composes the whole Cookie header for a cookie probe: every cookie the
// capture carried, with exactly one value replaced by the canary.
//
// Sorted by name so the same capture always produces the same bytes. That is not tidiness: the
// probe_url and evidence stored beside a row are how an operator reproduces it, and a header whose
// order changed between the run and the reproduction is a header they cannot compare.
func reflectionCookieHeader(observed map[string]string, probed, payload string) string {
	pairs := make(map[string]string, len(observed)+1)
	for name, value := range observed {
		if strings.TrimSpace(name) == "" {
			continue
		}
		pairs[name] = value
	}
	pairs[probed] = payload

	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+pairs[name])
	}
	return strings.Join(parts, "; ")
}

// reflectionMergeCookieHeader overlays the credential's cookies onto the composed probe header,
// leaving the ONE probed cookie carrying its canary.
//
// The two halves come from different places at different times: the other cookies are what the crawl
// captured, possibly days ago and possibly dead, while the credential is what the operator has
// refreshed since. The live value wins for every cookie except the one being measured.
func reflectionMergeCookieHeader(base, credential, keep string) string {
	pairs := map[string]string{}
	absorb := func(raw, skip string) {
		for _, pair := range strings.Split(raw, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(pair), "=")
			name = strings.TrimSpace(name)
			if !ok || name == "" || name == skip {
				continue
			}
			pairs[name] = strings.TrimSpace(value)
		}
	}
	absorb(base, "")
	absorb(credential, keep)

	names := make([]string, 0, len(pairs))
	for name := range pairs {
		names = append(names, name)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, name := range names {
		parts = append(parts, name+"="+pairs[name])
	}
	return strings.Join(parts, "; ")
}

// reflectionAuthSupplies reports whether the credential held for this host would itself put a value
// in the input being probed.
//
// The RUNTIME half of TRAP 2, and it is not redundant with the plan-time check. The plan-time check
// reads a ReflectionPlanContext a caller may not have filled in, and a hand-built target has no plan
// at all. This one reads the material that is about to be applied, one line before it is applied, so
// a probe cannot overwrite the credential however it was composed.
func reflectionAuthSupplies(auth *ScopedAuthMaterial, insertionPoint, name string) bool {
	if auth == nil || strings.TrimSpace(name) == "" {
		return false
	}
	switch insertionPoint {
	case "header":
		if strings.EqualFold(name, "cookie") && auth.Cookies != "" {
			return true
		}
		for held := range auth.Headers {
			if strings.EqualFold(held, name) {
				return true
			}
		}
	case "cookie":
		for _, pair := range strings.Split(auth.Cookies, ";") {
			held, _, ok := strings.Cut(strings.TrimSpace(pair), "=")
			if ok && strings.TrimSpace(held) == name {
				return true
			}
		}
	case "query":
		// Apply rewrites the query string after the request is built, so a credential query
		// parameter would silently replace our canary and the probe would measure a request it did
		// not compose.
		for held := range auth.QueryParams {
			if held == name {
				return true
			}
		}
	}
	return false
}

// ReflectionCredentialNames reads a held credential's cookie and header names, for the planner.
//
// Returned as sets rather than as the material itself, so the planner cannot accidentally read a
// token value and so a test can build one without a database.
func ReflectionCredentialNames(auth *ScopedAuthMaterial) (cookies, headers map[string]bool) {
	cookies, headers = map[string]bool{}, map[string]bool{}
	if auth == nil {
		return cookies, headers
	}
	for _, pair := range strings.Split(auth.Cookies, ";") {
		name, _, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if name = strings.TrimSpace(name); ok && name != "" {
			cookies[name] = true
		}
	}
	for name := range auth.Headers {
		if name = strings.TrimSpace(name); name != "" {
			headers[strings.ToLower(name)] = true
		}
	}
	return cookies, headers
}

// reflectionPathProbeURL puts the canary in the LAST path segment, which for a path vector is the
// input: there is no -p equivalent because the segment has no name.
//
// The last NON-EMPTY segment, so a trailing slash does not put the payload in the empty string after
// it, where the application sees nothing. A path that is bare "/" gets the canary appended as a new
// segment, because a vector recorded against the root still names the root as the thing to test.
//
// Percent encoded, because < > " ' are not legal raw in a path and Go's transport would have to
// guess. An application that echoes the still-encoded form is then correctly graded as encoded: it
// did not decode our payload, so our payload is not in its output.
func reflectionPathProbeURL(base, payload string) (string, bool) {
	pathPart, queryPart, hasQuery := strings.Cut(base, "?")
	scheme, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return "", false
	}
	host, path, hasPath := strings.Cut(rest, "/")
	escaped := url.PathEscape(payload)
	if !hasPath || strings.Trim(path, "/") == "" {
		out := scheme + "://" + host + "/" + escaped
		if hasQuery {
			out += "?" + queryPart
		}
		return out, true
	}

	segments := strings.Split(path, "/")
	replaced := false
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] == "" {
			continue
		}
		segments[i] = escaped
		replaced = true
		break
	}
	if !replaced {
		return "", false
	}
	out := scheme + "://" + host + "/" + strings.Join(segments, "/")
	if hasQuery {
		out += "?" + queryPart
	}
	return out, true
}

// ReflectionRequestSender is the one method this probe needs, so a test can count requests instead
// of reading the code and hoping. *ScanClient satisfies it.
//
// Counting is not pedantry: the fragment case, the credential case and the mutating-verb case are
// all claims that NO request goes out, and the only way to hold a claim about traffic to account is
// to assert the number is zero.
type ReflectionRequestSender interface {
	Do(ctx context.Context, req ScanRequest) ScanResponse
}

// reflectionNeverSentVerbs are the verbs no reflection probe may ever put on the wire.
//
// A map rather than an if, so the list is one thing to read and one thing to test. Widening it is
// safe; narrowing it is the incident described on planReflectionBodyTargets.
// POST and PATCH JOINED PUT AND DELETE. There used to be a per-run opt in that unlocked them for
// body probes; it is gone, along with the confirm dialog in front of it. Investigate no longer has
// any setting that writes to a target, because it no longer needs one: the PASSIVE pass answers a
// body field out of the request and response the crawl already stored, so the write was buying
// nothing that could not be had for free.
var reflectionNeverSentVerbs = map[string]bool{
	"PUT": true, "DELETE": true, "POST": true, "PATCH": true,
}

// ProbeReflection sends one canary and classifies what comes back.
//
// EVERY REFUSAL IS ABOVE EVERY USE OF THE SENDER, so a target that must not produce traffic cannot
// produce it however the caller is wired.
func ProbeReflection(ctx context.Context, sender ReflectionRequestSender, target ReflectionProbeTarget,
	auth *ScopedAuthMaterial) ReflectionOutcome {

	if target.InsertionPoint == "fragment" {
		return ReflectionOutcome{
			InsertionPoint: target.InsertionPoint,
			Status:         ReflectionNeedsBrowser,
			Detail: "the fragment is never put on the wire, so no HTTP request can tell us whether " +
				"this input reflects. Drive it in a browser (domdig) to answer it.",
		}
	}

	// TRAP 1, enforced here and not only at plan time. A hand-built target, a future caller, or a
	// bug in the planner must all meet this before the sender is touched.
	if reflectionNeverSentVerbs[strings.ToUpper(strings.TrimSpace(target.Method))] {
		return ReflectionOutcome{
			InsertionPoint: target.InsertionPoint,
			Status:         ReflectionProbeRefused,
			Detail: "would_mutate(" + strings.ToUpper(strings.TrimSpace(target.Method)) + "): this " +
				"probe never sends a " + strings.ToUpper(strings.TrimSpace(target.Method)) +
				". The passive pass reads this input out of the stored request and response " +
				"instead. No request was sent.",
		}
	}

	// A decision already made and explained at plan time: the credential cases, the framework
	// headers and the mutating bodies.
	if target.SkipStatus != "" {
		return ReflectionOutcome{
			InsertionPoint: target.InsertionPoint,
			Status:         target.SkipStatus,
			Detail:         target.SkipDetail,
		}
	}

	// TRAP 2, enforced against the material that is ABOUT TO BE APPLIED rather than against a plan
	// that may have been built without one.
	if reflectionAuthSupplies(auth, target.InsertionPoint, target.Parameter) {
		return ReflectionOutcome{
			InsertionPoint: target.InsertionPoint,
			Status:         ReflectionIsCredential,
			Detail: "is_credential(" + target.InsertionPoint + " " + target.Parameter + "): the " +
				"credential held for this host sets this very input, so the canary would either be " +
				"overwritten by it or would replace it and log the request out. Either way the row " +
				"would describe the credential rather than the input. No request was sent.",
		}
	}

	// A vector captured with a credential and probed without one gets a 401, reflects nothing, and
	// would be recorded as a clean input. Refusing to send is the only honest answer: the row says
	// error and names what is missing, so it shows up as work to do rather than as coverage.
	if target.NeedsCredential && auth == nil {
		return ReflectionOutcome{
			InsertionPoint: target.InsertionPoint,
			Status:         ReflectionError,
			Detail: "credential_required: this vector was captured with authentication and no " +
				"credential is held for its host, so an unauthenticated probe would measure the login " +
				"wall rather than the endpoint. No request was sent.",
		}
	}

	req := ScanRequest{
		URL:      target.URL,
		Method:   target.Method,
		Auth:     auth,
		ReadBody: true,
	}

	switch target.InsertionPoint {
	case "cookie":
		// THE CREDENTIAL IS APPLIED LAST AND WINS. ScanClient.Do sets req.Headers first and then
		// calls Auth.Apply, which does Header.Set("Cookie", m.Cookies) and REPLACES the whole
		// header. A cookie probe that put its canary in req.Headers would have it silently deleted
		// on every host the framework holds a cookie for: the request goes out with no canary, the
		// body honestly does not contain one, and the row reads not_reflected. That is a false clean
		// produced by our own plumbing, so the canary travels inside the credential instead.
		merged := reflectionMergeCookieHeader(target.CookieHeader, authCookies(auth), target.Parameter)
		if auth != nil {
			clone := *auth
			clone.Cookies = merged
			req.Auth = &clone
		} else {
			req.Headers = map[string]string{"Cookie": merged}
		}
	case "header":
		// Applied after the client's own instrumentation and before the credential, so the canary
		// wins over User-Agent or Accept and can never win over Authorization. The headers the
		// client owns outright are refused at plan time; see reflectionReservedHeaderNames.
		req.Headers = map[string]string{target.Parameter: ReflectionCanaryPayload(target.Token)}
	case "body":
		req.Body = target.Body
		if target.BodyContentType != "" {
			// Set explicitly, never guessed: scanHTTP's own comment records that a JSON body posted
			// as form-encoded gets a 400 that looks like the endpoint rejecting the request rather
			// than the sender mislabelling it.
			req.Headers = map[string]string{"Content-Type": target.BodyContentType}
		}
	}

	resp := sender.Do(ctx, req)
	out := ClassifyReflectionResponse(target.Token, resp)
	out.InsertionPoint = target.InsertionPoint

	// A credential that was held but not applied changes what the row means, so it is recorded next
	// to the verdict rather than inferred later from whether one existed at load time.
	if target.NeedsCredential && !resp.AuthApplied && resp.Err == nil {
		out.Detail = "credential_withheld(" + resp.AuthWithheld + "): " + out.Detail
	}
	return out
}

// authCookies is the credential's cookie string, or empty when there is no credential.
func authCookies(auth *ScopedAuthMaterial) string {
	if auth == nil {
		return ""
	}
	return auth.Cookies
}
