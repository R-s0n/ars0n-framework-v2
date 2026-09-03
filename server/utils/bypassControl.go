package utils

import (
	"context"
	"hash/fnv"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// THE NEGATIVE CONTROL for the access control bypass section.
//
// A "bypass" is only a bypass if the SAME REQUEST WITHOUT THE BYPASS TECHNIQUE is refused. Neither
// nomore403 nor Forbidden checks that, and until this file existed neither did the framework: it
// compared each result against the original 4xx of the TARGET URL, while the tools were requesting
// MUTATED urls. That is a comparison against the wrong thing entirely, and it is why a run against
// OWASP Juice Shop produced 159 access-control-bypass findings of which zero were real.
//
// WHAT THE TARGET LOOKED LIKE, MEASURED. Juice Shop is an Angular SPA behind Express, so every path
// that does not exist answers 200 with the SAME 9641-byte shell. The shell also reflects the
// requested path back, which makes its length a deterministic function of the request STRING: url
// length 40 gave 11336 bytes, 41 gave 11339, 58 gave 11467. The decisive measurement is that the
// same target file, /ftp/package.json.bak, produced SEVEN different response lengths across the
// run. A real file read returns a size set by the FILE. A size set by the payload is a template.
//
// So there are two controls, and which one a candidate gets depends on where the technique lives.
// It is an EITHER, never a both, and bypassControlPlan says why in detail:
//
//   - HEADER-STRIPPED, where the technique is a header. Re-request the URL THE TOOL ACTUALLY
//     REQUESTED, same verb, with the header removed. This is the one that kills a rewriting header
//     pointed at a page that was public anyway: 28 of Forbidden's 74 results fetched the bare site
//     root or /robots.txt with an X-Original-URL style header that changed nothing at all.
//
//   - NONEXISTENT SIBLING, where the technique is in the url and there is no header to strip.
//     Request a path that certainly does not exist, built to the SAME LENGTH as the one under test
//     so a template that reflects the URL cannot answer with a different size for a trivial reason.
//     If the response under test matches what a made-up path returns, it is the catch-all page and
//     nothing was reached.
//
// Comparison is on BODY and SIZE, never on status. On this target status is nearly meaningless: a
// missing page is 200, a real bypass is 200, and the directory that needed no bypass at all is 200.
//
// Cost is two requests per surviving CANDIDATE, not per payload: the request under test re-sent so
// there is something to compare, and one control. The tools' own results are deduplicated first and
// the free checks in bypassPreScreen run before anything is sent, so on the measured run about a
// third of the candidates cost nothing at all. It goes through ScanClient and HostBudget, the same
// paced client and per-host budget the endpoint workflow uses, rather than a second client with its
// own idea of what is safe.

// Verdicts. Confirmed means a control was actually sent and the response under test survived it.
// Unverified means no control could be sent, which is NOT the same as clean and is never reported
// as a bypass.
const (
	bypassVerdictConfirmed  = "confirmed"
	bypassVerdictRejected   = "rejected"
	bypassVerdictUnverified = "unverified"
)

// Why a candidate was thrown out. Each one is recorded and counted rather than being dropped
// quietly, because replacing "159 findings" with an unexplained "3 findings" is the same failure
// wearing a smaller number.
const (
	bypassRejectNoResponse    = "no-response"
	bypassRejectEmptyBody     = "empty-body"
	bypassRejectControlSame   = "control-reproduced-it"
	bypassHoldUnsafeVerb      = "no-control-unsafe-verb"
	bypassHoldUnreproducible  = "no-control-unreproducible-technique"
	bypassHoldBadURL          = "no-control-unusable-url"
	bypassHoldControlFailed   = "no-control-request-failed"
	bypassHoldProtectedFailed = "request-under-test-failed"
	bypassHoldNoControl       = "no-control-could-be-built"
	bypassHoldBudget          = "not-screened"
)

const (
	bypassControlHeaderStripped = "header-stripped control"
	bypassControlSibling        = "nonexistent-sibling control"
)

// Screening limits. A run that spends ten minutes on controls is a run an operator cancels, and a
// cancelled run reports nothing. Ordered best-score-first so what gets screened is what the tool
// itself thought most likely.
const (
	bypassMaxScreened  = 60
	bypassScreenBudget = 4 * time.Minute
	bypassBodyKeep     = 3000
)

// bypassProbeRequest is one request the control logic wants sent.
type bypassProbeRequest struct {
	Method  string
	URL     string
	Headers []string // "Name: value", as the tools record them
}

// bypassProbeResult is what came back. Err non-empty means nothing usable arrived, which is a
// different thing from an empty body and is never treated as evidence of either access or denial.
type bypassProbeResult struct {
	Method      string
	URL         string
	Headers     []string
	Status      int
	Bytes       int
	Body        string
	ContentType string
	Err         string
}

// bypassProbeFunc is the seam. Production points it at the paced ScanClient; tests point it at a
// table of canned responses so the comparison logic is exercised without a network.
type bypassProbeFunc func(ctx context.Context, req bypassProbeRequest) bypassProbeResult

var bypassControlProbe bypassProbeFunc = liveBypassControlProbe

// bypassCandidate is one reported bypass reduced to the things that decide whether it is real.
//
// RequestedURL is the point of the whole exercise: it is the url the TOOL requested, which for
// every path, encoding and override technique is not the target url the scan was aimed at.
type bypassCandidate struct {
	Technique    string
	Method       string
	RequestedURL string
	// OriginalURL is the target the scan was AIMED at. Kept only so the accounting note can say when
	// the two differ, which on the measured run was the single most useful line an operator could
	// read: 28 of Forbidden's 74 results had requested a completely different, public url.
	OriginalURL string
	Headers     []string // every header the tool sent
	BaseHeaders []string // the subset that is not part of the technique
	Status      int
	Length      int
	Body        string // almost always empty: neither tool stores response bytes
	Curl        string
	Score       int
}

// bypassJudgement is the verdict plus the evidence for it, including the control response, which is
// stored so an operator can see both arms rather than being asked to trust the comparison.
type bypassJudgement struct {
	Verdict     string
	Slug        string
	Reason      string
	ControlKind string
	Protected   bypassProbeResult
	Control     bypassProbeResult
}

// bypassPreScreen applies the checks that need no network, and it is where the second half of this
// section's false positives died.
//
// A NON-RESPONSE IS NOT A BYPASS. 17 of nomore403's 85 results carried status 0 with a zero-byte
// body, meaning the request never completed. Six of them were scored 27 and two were scored 61 by
// the tool, so its own score kept them: a detector that reads "the connection died" as evidence of
// access is inverted, and the framework repeated it by only skipping results at 400 and above.
//
// AN EMPTY BODY WITHHOLDS NOTHING. 18 more were OPTIONS answered 204 with a zero-byte body. There
// is no protected content in an empty response, so it cannot demonstrate access to any.
//
// Only the two classes above are rejected here, and both are decided by the STATUS rather than by a
// reported length. A reported length of zero is deliberately not a rejection: a build that omits
// the field, or a parser that reads the wrong key, would then reject every candidate and file a
// noisy target as clean. That has happened once in this section already, and it is a worse failure
// than the one being fixed. A body that is really empty is caught by measurement instead, when the
// request under test is re-sent.
func bypassPreScreen(c bypassCandidate) (string, string) {
	switch {
	case c.Status == 0 && strings.TrimSpace(c.Body) == "":
		return bypassRejectNoResponse, "the request never completed: the tool recorded status 0 with " +
			"a zero-byte body, which is a dead connection rather than a response. The tool's own score " +
			"for it (" + strconv.Itoa(c.Score) + ") is not evidence, because scoring a non-response at " +
			"all is the inverted detector this check exists to stop."
	case c.Status == 204 || c.Status == 205 || c.Status == 304:
		return bypassRejectEmptyBody, "the response was " + strconv.Itoa(c.Status) + ", which carries no " +
			"body by definition. An empty response contains nothing that was being withheld, so it " +
			"cannot demonstrate access to anything."
	}
	return "", ""
}

// Techniques a Go net/http client cannot re-send faithfully. Their whole point is a request form
// the standard library refuses to build, which is exactly why Forbidden is built on PycURL and why
// nomore403 has a raw mode. A control that quietly sends a well-formed request instead would be
// comparing against something the tool never sent, so these are held as unverified and said so.
var bypassUnreproducibleTechniques = map[string]bool{
	"raw-duplicates":  true,
	"raw-authority":   true,
	"raw-desync":      true,
	"http-versions":   true,
	"http-parser":     true,
	"absolute-uri":    true,
	"proto-confusion": true,
	"host-override":   true,
	"host-overrides":  true,
	"parsers":         true,
	"protocols":       true,
}

// Headers a control arm may carry over, because they identify the CALLER rather than perform the
// bypass. Everything else is treated as part of the technique and stripped, so the two arms differ
// by the technique and by nothing else. Referer is deliberately absent: it is a bypass header on
// plenty of targets.
var bypassIdentityHeaders = map[string]bool{
	"authorization":   true,
	"cookie":          true,
	"user-agent":      true,
	"accept":          true,
	"accept-language": true,
	"content-type":    true,
}

// Headers this client cannot set through net/http, so a technique that depends on one cannot be
// reproduced and must not be judged.
var bypassUnsettableHeaders = map[string]bool{
	"host":              true,
	"content-length":    true,
	"connection":        true,
	"transfer-encoding": true,
	"upgrade":           true,
}

// screenBypassCandidates judges a whole tool run, returning one judgement per candidate in the
// order given.
func screenBypassCandidates(candidates []bypassCandidate) []bypassJudgement {
	out := make([]bypassJudgement, len(candidates))
	var live []int
	for i, c := range candidates {
		if slug, reason := bypassPreScreen(c); slug != "" {
			out[i] = bypassJudgement{Verdict: bypassVerdictRejected, Slug: slug, Reason: reason}
			continue
		}
		live = append(live, i)
	}
	if len(live) == 0 {
		return out
	}

	// Best first, so a truncated screening run spends its budget on what the tool itself rated
	// highest rather than on whatever happened to be printed first.
	sort.SliceStable(live, func(a, b int) bool {
		return candidates[live[a]].Score > candidates[live[b]].Score
	})

	ctx, cancel := context.WithTimeout(context.Background(), bypassScreenBudget)
	defer cancel()

	screened := 0
	for _, i := range live {
		if screened >= bypassMaxScreened || ctx.Err() != nil {
			out[i] = bypassJudgement{
				Verdict: bypassVerdictUnverified,
				Slug:    bypassHoldBudget,
				Reason: "the control budget for this target was spent before this candidate was " +
					"reached, so no control was sent for it. It is listed here with its own " +
					"reproduction rather than reported as a bypass, because an unscreened candidate " +
					"is exactly what this section used to file as a finding.",
			}
			continue
		}
		screened++
		out[i] = judgeBypassCandidate(ctx, candidates[i])
	}
	return out
}

// judgeBypassCandidate sends the controls for one candidate and decides.
func judgeBypassCandidate(ctx context.Context, c bypassCandidate) bypassJudgement {
	method := strings.ToUpper(firstNonEmpty(c.Method, "GET"))

	if !allowedScanMethods[method] {
		return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldUnsafeVerb,
			Reason: "the request under test is a " + method + ", and this framework will not send a " +
				method + " at a target, so its negative control could not be sent either. Without a " +
				"control there is no bypass claim to make: a " + method + " answered 2xx usually " +
				"means the application accepted a new request, not that a refused resource was " +
				"reached. Send both arms by hand if this one matters."}
	}
	if bypassUnreproducibleTechniques[strings.ToLower(strings.TrimSpace(c.Technique))] {
		return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldUnreproducible,
			Reason: "the " + c.Technique + " technique depends on a request form a Go HTTP client " +
				"cannot build, which is the whole reason the tool has its own raw sender. Re-sending " +
				"a well-formed approximation would be comparing against a request nobody made, so " +
				"this is held unverified rather than confirmed or thrown away."}
	}
	for _, h := range bypassTechniqueHeaders(c) {
		name, _, _ := strings.Cut(h, ":")
		if bypassUnsettableHeaders[strings.ToLower(strings.TrimSpace(name))] {
			return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldUnreproducible,
				Reason: "the technique sets " + strings.TrimSpace(name) + ", which this client cannot " +
					"control, so the request under test cannot be reproduced and there is nothing " +
					"honest to compare a control against."}
		}
	}
	if !bypassUsableURL(c.RequestedURL) {
		return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldBadURL,
			Reason: "the url the tool reported requesting could not be parsed, so the control could " +
				"not be aimed at it: " + truncateReason(c.RequestedURL)}
	}

	// The request UNDER TEST, re-sent. Neither tool stores response bytes, which is why every one of
	// the 159 findings carried raw_response = "". Re-sending is what makes a comparison possible at
	// all, and it is also what finally puts real captured bytes on a finding in this section.
	//
	// ALWAYS re-sent, even on the rare build where Forbidden does record a body. Both arms have to
	// be captured by the same client or the comparison acquires a second variable: PycURL and Go
	// send different default headers, and a difference caused by the client is not a bypass.
	protected := bypassControlProbe(ctx, bypassProbeRequest{
		Method: method, URL: c.RequestedURL, Headers: c.Headers,
	})
	if protected.Err != "" {
		return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldProtectedFailed,
			Protected: protected,
			Reason: "re-sending the request under test did not complete, so there was nothing to " +
				"compare a control against: " + truncateReason(protected.Err)}
	}
	if protected.Status == 0 || protected.Bytes == 0 {
		return bypassJudgement{Verdict: bypassVerdictRejected, Slug: bypassRejectEmptyBody,
			Protected: protected,
			Reason: "re-sent now, the request under test returned an empty body, so there is " +
				"nothing in it that a denial could have been withholding."}
	}

	plans := bypassControlPlan(c, method)
	if len(plans) == 0 {
		return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldNoControl,
			Protected: protected,
			Reason: "no negative control could be built for this candidate: it carries no technique " +
				"header to strip and its path has nothing that can be replaced to make a url that " +
				"certainly does not exist. Compare it by hand before believing it."}
	}

	var last bypassProbeResult
	var lastKind string
	for _, plan := range plans {
		control := bypassControlProbe(ctx, plan.Request)
		last, lastKind = control, plan.Kind
		if control.Err != "" {
			return bypassJudgement{Verdict: bypassVerdictUnverified, Slug: bypassHoldControlFailed,
				ControlKind: plan.Kind, Protected: protected, Control: control,
				Reason: "the " + plan.Kind + " did not complete, so this candidate is untested rather " +
					"than clean: " + truncateReason(control.Err)}
		}
		same, why := bypassResponsesMateriallySame(protected, control)
		if same {
			return bypassJudgement{Verdict: bypassVerdictRejected, Slug: bypassRejectControlSame,
				ControlKind: plan.Kind, Protected: protected, Control: control,
				Reason: plan.Explain + " " + why + " Nothing was bypassed: the same content comes " +
					"back without the technique."}
		}
	}

	return bypassJudgement{
		Verdict: bypassVerdictConfirmed, ControlKind: lastKind,
		Protected: protected, Control: last,
		Reason: "the " + lastKind + " did NOT reproduce this response: " +
			bypassDifferenceText(protected, last) + " That is what a bypass looks like. Read both " +
			"bodies below and name the string the control did not return before reporting it.",
	}
}

// bypassControlSpec is one control arm.
type bypassControlSpec struct {
	Kind    string
	Explain string
	Request bypassProbeRequest
}

// bypassControlPlan decides which control this candidate needs. It is an EITHER, not a both.
//
// Where the technique is a header, stripping the header is the control, and the sibling must NOT
// also run. A rewriting header is the whole point of this bug class: `GET /about` with
// `X-Original-URL: /admin` returns the admin panel, which is a real finding this framework has
// measured on ginandjuice.shop. Sent to a made-up sibling path the same header rewrites to /admin
// just the same, the sibling comes back identical to the response under test, and the control would
// throw away the one thing the section exists to find. The header-stripped arm already answers the
// question: if removing the header changes the answer, the header did something.
//
// Where the technique is in the url, there is no header to strip and the sibling is the only
// control there is.
func bypassControlPlan(c bypassCandidate, method string) []bypassControlSpec {
	if technique := bypassTechniqueHeaders(c); len(technique) > 0 {
		return []bypassControlSpec{{
			Kind: bypassControlHeaderStripped,
			Explain: "The same url and verb, sent WITHOUT " + strings.Join(bypassHeaderNames(technique), ", ") +
				", returned the same thing.",
			Request: bypassProbeRequest{Method: method, URL: c.RequestedURL, Headers: c.BaseHeaders},
		}}
	}

	if sibling := bypassSiblingURL(c.RequestedURL); sibling != "" {
		return []bypassControlSpec{{
			Kind: bypassControlSibling,
			Explain: "A url that certainly does not exist, built to the same length so a page that " +
				"reflects the request cannot differ for a trivial reason, returned the same thing.",
			Request: bypassProbeRequest{Method: method, URL: sibling, Headers: c.Headers},
		}}
	}
	return nil
}

// bypassTechniqueHeaders is every header the tool added on top of the base request.
func bypassTechniqueHeaders(c bypassCandidate) []string {
	base := map[string]bool{}
	for _, h := range c.BaseHeaders {
		base[strings.ToLower(strings.TrimSpace(h))] = true
	}
	var out []string
	for _, h := range c.Headers {
		if h = strings.TrimSpace(h); h == "" {
			continue
		}
		if !base[strings.ToLower(h)] {
			out = append(out, h)
		}
	}
	return out
}

func bypassHeaderNames(headers []string) []string {
	out := make([]string, 0, len(headers))
	for _, h := range headers {
		name, _, ok := strings.Cut(h, ":")
		if !ok {
			name = h
		}
		out = append(out, strings.TrimSpace(name))
	}
	return out
}

// bypassBaseHeaders splits a candidate's headers into the ones that identify the caller and the
// ones that are performing the bypass.
//
// nomore403 publishes its own unmodified request as the "default" row, so where that row exists the
// base set is exact rather than guessed. Forbidden has no such row, so the identity allowlist is
// used, and it errs towards KEEPING credentials on the control: an anonymous control differs from
// an authenticated response for a reason that has nothing to do with the technique, and that
// difference would keep a candidate rather than kill one.
func bypassBaseHeaders(all []string, exact []string) []string {
	if exact != nil {
		return exact
	}
	var out []string
	for _, h := range all {
		name, _, ok := strings.Cut(h, ":")
		if !ok {
			continue
		}
		if bypassIdentityHeaders[strings.ToLower(strings.TrimSpace(name))] {
			out = append(out, strings.TrimSpace(h))
		}
	}
	return out
}

// bypassSiblingURL builds a url that certainly does not exist, THE SAME LENGTH as the one given.
//
// The length is the whole trick. Measured on Juice Shop, the catch-all page's size is a function of
// the requested path string: 40 characters gave 11336 bytes and 58 gave 11467. A sibling of a
// different length would come back a different size, the comparison would call that a difference,
// and the catch-all page would be reported as a bypass all over again.
//
// Percent escapes are copied through untouched, because they are frequently the technique itself
// and because mangling one produces a malformed request rather than a control.
func bypassSiblingURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return ""
	}
	escaped := parsed.EscapedPath()
	if escaped == "" || escaped == "/" {
		return ""
	}
	segments := strings.Split(escaped, "/")
	changed := false
	for i := len(segments) - 1; i >= 0; i-- {
		if scrambled, ok := bypassScrambleSegment(segments[i]); ok {
			segments[i] = scrambled
			changed = true
			break
		}
	}
	if !changed {
		return ""
	}
	out := parsed.Scheme + "://" + parsed.Host + strings.Join(segments, "/")
	if parsed.RawQuery != "" {
		out += "?" + parsed.RawQuery
	}
	return out
}

// bypassSiblingFiller is nonsense on purpose. Anything that reads like a word risks naming a real
// path on some target.
const bypassSiblingFiller = "zq7wxj4v"

func bypassScrambleSegment(segment string) (string, bool) {
	var b strings.Builder
	replaced := 0
	for i := 0; i < len(segment); {
		ch := segment[i]
		if ch == '%' && i+2 < len(segment) && isHexDigit(segment[i+1]) && isHexDigit(segment[i+2]) {
			b.WriteString(segment[i : i+3])
			i += 3
			continue
		}
		if isAlphaNumeric(ch) {
			b.WriteByte(bypassSiblingFiller[replaced%len(bypassSiblingFiller)])
			replaced++
			i++
			continue
		}
		b.WriteByte(ch)
		i++
	}
	out := b.String()
	// Three characters is the floor. Changing one or two leaves a path that plausibly exists, and a
	// sibling that turns out to be real is a control that proves the opposite of what it claims.
	if replaced < 3 || out == segment {
		return "", false
	}
	return out, true
}

func isHexDigit(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func isAlphaNumeric(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func bypassUsableURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && parsed.Host != "" && strings.HasPrefix(parsed.Scheme, "http")
}

// bypassResponsesMateriallySame decides whether the control reproduced the response under test.
//
// ON BODY AND SIZE, NEVER ON STATUS. The whole reason this section failed is that a status change
// was read as access on a target where a nonexistent path is 200, a real bypass is 200, and a
// public directory index is 200.
//
// The reflected request path is normalised away first, in a LENGTH PRESERVING way, so a template
// that echoes the url back does not read as a difference while a genuinely different page still
// does. Redacting to a fixed-width token instead would shrink the two bodies by different amounts
// and re-introduce the size difference the normalisation is there to remove.
func bypassResponsesMateriallySame(protected, control bypassProbeResult) (bool, string) {
	if protected.Body == control.Body {
		return true, "Both responses are byte-identical at " + strconv.Itoa(len(protected.Body)) + " bytes."
	}

	np := bypassNormaliseBody(protected.Body, protected.URL)
	nc := bypassNormaliseBody(control.Body, control.URL)
	if np == nc {
		return true, "The two bodies are identical once the reflected request path is normalised " +
			"away (" + strconv.Itoa(len(protected.Body)) + " and " + strconv.Itoa(len(control.Body)) +
			" bytes on the wire, differing only where each one echoes its own url)."
	}

	gap := np
	if len(nc) > len(gap) {
		gap = nc
	}
	tolerance := 32 + len(gap)/100
	diff := len(np) - len(nc)
	if diff < 0 {
		diff = -diff
	}
	if diff <= tolerance {
		if similarity := bypassShingleSimilarity(np, nc); similarity >= 0.98 {
			return true, "The two bodies are " + strconv.Itoa(diff) + " bytes apart and share " +
				strconv.Itoa(int(similarity*100)) + "% of their content, which is the same page with " +
				"a nonce or a timestamp moved."
		}
	}
	return false, bypassDifferenceText(protected, control)
}

func bypassDifferenceText(protected, control bypassProbeResult) string {
	return "the request under test returned " + strconv.Itoa(len(protected.Body)) + " bytes" +
		bypassTypeText(protected.ContentType) + " and the control returned " +
		strconv.Itoa(len(control.Body)) + " bytes" + bypassTypeText(control.ContentType) + "."
}

func bypassTypeText(contentType string) string {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return ""
	}
	if i := strings.Index(contentType, ";"); i > 0 {
		contentType = contentType[:i]
	}
	return " of " + contentType
}

// bypassNormaliseBody blanks out every place the response echoes its own request back.
func bypassNormaliseBody(body, requestURL string) string {
	if body == "" {
		return ""
	}
	out := body
	for _, token := range bypassURLTokens(requestURL) {
		if !strings.Contains(out, token) {
			continue
		}
		out = strings.ReplaceAll(out, token, strings.Repeat("\x01", len(token)))
	}
	return bypassCollapseSpace(out)
}

// bypassURLTokens is every substring of a url a page might reflect, longest first so a long form is
// blanked before the short forms nested inside it.
func bypassURLTokens(raw string) []string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	set := map[string]bool{}
	add := func(s string) {
		// Under three characters a "token" is a fragment of ordinary prose and blanking it would
		// damage both bodies in different places.
		if s = strings.TrimSpace(s); len(s) >= 3 {
			set[s] = true
		}
	}
	add(raw)
	add(parsed.String())
	escaped := parsed.EscapedPath()
	add(escaped)
	add(parsed.Path)
	if parsed.RawQuery != "" {
		add(escaped + "?" + parsed.RawQuery)
		add(parsed.RawQuery)
	}
	for _, segment := range strings.Split(escaped, "/") {
		add(segment)
	}
	for _, segment := range strings.Split(parsed.Path, "/") {
		add(segment)
	}

	out := make([]string, 0, len(set))
	for token := range set {
		out = append(out, token)
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i]) != len(out[j]) {
			return len(out[i]) > len(out[j])
		}
		return out[i] < out[j]
	})
	return out
}

func bypassCollapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\n', '\r':
			space = true
		default:
			if space && b.Len() > 0 {
				b.WriteByte(' ')
			}
			space = false
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// bypassShingleSimilarity is a Dice coefficient over overlapping character shingles. It exists only
// to absorb a nonce or a rendered timestamp, which is why the threshold that uses it is 0.98 and is
// paired with a tight size bound: anything looser starts discarding real findings.
func bypassShingleSimilarity(a, b string) float64 {
	sa, sb := bypassShingles(a), bypassShingles(b)
	if len(sa) == 0 && len(sb) == 0 {
		return 1
	}
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	small, large := sa, sb
	if len(small) > len(large) {
		small, large = large, small
	}
	shared := 0
	for key := range small {
		if _, ok := large[key]; ok {
			shared++
		}
	}
	return 2 * float64(shared) / float64(len(sa)+len(sb))
}

func bypassShingles(s string) map[uint64]struct{} {
	const width, step, ceiling = 8, 4, 128 << 10
	out := map[uint64]struct{}{}
	if len(s) == 0 {
		return out
	}
	limit := len(s)
	if limit > ceiling {
		limit = ceiling
	}
	if limit < width {
		h := fnv.New64a()
		h.Write([]byte(s[:limit]))
		out[h.Sum64()] = struct{}{}
		return out
	}
	for i := 0; i+width <= limit; i += step {
		h := fnv.New64a()
		h.Write([]byte(s[i : i+width]))
		out[h.Sum64()] = struct{}{}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Rendering the two arms onto a finding, and the note that accounts for everything thrown away.
// ---------------------------------------------------------------------------------------------

// bypassEvidenceBlock is what goes in raw_response: BOTH arms, labelled, so the comparison can be
// checked rather than taken on trust. Until this existed every finding in this section stored an
// empty raw_response and a request marked as reconstructed.
func bypassEvidenceBlock(j bypassJudgement) string {
	var b strings.Builder
	b.WriteString("#### THE REQUEST UNDER TEST, re-sent and captured by this framework ####\n")
	b.WriteString(bypassArmText(j.Protected))
	if j.Control.URL != "" || j.Control.Err != "" {
		b.WriteString("\n\n#### NEGATIVE CONTROL: " + j.ControlKind + " ####\n")
		b.WriteString(bypassArmText(j.Control))
	}
	return b.String()
}

func bypassArmText(r bypassProbeResult) string {
	var b strings.Builder
	b.WriteString(strings.ToUpper(firstNonEmpty(r.Method, "GET")) + " " + r.URL + "\n")
	for _, h := range r.Headers {
		if strings.TrimSpace(h) != "" {
			b.WriteString(strings.TrimSpace(h) + "\n")
		}
	}
	if r.Err != "" {
		b.WriteString("-> did not complete: " + truncateReason(r.Err) + "\n")
		return b.String()
	}
	b.WriteString("-> " + strconv.Itoa(r.Status) + ", " + strconv.Itoa(r.Bytes) + " bytes")
	if r.ContentType != "" {
		b.WriteString(", " + r.ContentType)
	}
	b.WriteString("\n\n")
	body := r.Body
	if len(body) > bypassBodyKeep {
		body = body[:bypassBodyKeep] + "\n... [truncated at " + strconv.Itoa(bypassBodyKeep) + " bytes]"
	}
	b.WriteString(body)
	return b.String()
}

// bypassRawRequest renders the bytes that were actually put on the wire for the arm under test.
// Not marked as reconstructed, because this framework sent it and read the answer.
func bypassRawRequest(j bypassJudgement, fallbackURL string) string {
	target := firstNonEmpty(j.Protected.URL, fallbackURL)
	return rawRequestFor(firstNonEmpty(j.Protected.Method, "GET"), target, j.Protected.Headers, "")
}

// bypassRejectionNote is the single row that accounts for every candidate that did not survive.
//
// It exists because silently dropping 156 of 159 would replace one opaque number with another. The
// count, the reason for each class, and a line per candidate carrying its own reproduction are all
// on it, so an operator can disagree with any individual judgement and check it by hand.
func bypassRejectionNote(tool string, row vectorRow, candidates []bypassCandidate,
	judgements []bypassJudgement, kept int) *VectorFinding {

	type bucket struct {
		slug   string
		reason string
		count  int
	}
	var order []string
	buckets := map[string]*bucket{}
	var lines []string
	dropped := 0

	for i, j := range judgements {
		if j.Verdict == bypassVerdictConfirmed {
			continue
		}
		dropped++
		if _, ok := buckets[j.Slug]; !ok {
			buckets[j.Slug] = &bucket{slug: j.Slug, reason: j.Reason}
			order = append(order, j.Slug)
		}
		buckets[j.Slug].count++

		if len(lines) < 30 {
			c := candidates[i]
			line := "- " + firstNonEmpty(c.Technique, "(technique not named)") + ": " +
				strings.ToUpper(firstNonEmpty(c.Method, "GET")) + " " + c.RequestedURL + " -> " +
				strconv.Itoa(c.Status) + ", " + strconv.Itoa(c.Length) + "b."
			if c.OriginalURL != "" && c.RequestedURL != c.OriginalURL {
				line += " NOTE: that is not the url this scan was aimed at, which was " + c.OriginalURL + "."
			}
			line += " " + j.Slug + ": " + j.Reason
			if j.Control.URL != "" && j.Control.Err == "" {
				line += " The control (" + j.ControlKind + ") requested " + j.Control.URL +
					" and got " + strconv.Itoa(j.Control.Status) + ", " +
					strconv.Itoa(j.Control.Bytes) + " bytes."
			}
			if c.Curl != "" {
				line += " " + c.Curl
			}
			lines = append(lines, line)
		}
	}
	if dropped == 0 {
		return nil
	}
	if dropped > len(lines) {
		lines = append(lines, "- and "+strconv.Itoa(dropped-len(lines))+" more, same reasons.")
	}

	var summary []string
	for _, slug := range order {
		summary = append(summary, strconv.Itoa(buckets[slug].count)+" "+slug)
	}

	evidence := tool + " reported " + strconv.Itoa(len(candidates)) + " candidate bypasses of this " +
		"url. " + strconv.Itoa(kept) + " survived a negative control and " + strconv.Itoa(dropped) +
		" did not: " + strings.Join(summary, ", ") + ".\n" + strings.Join(lines, "\n")

	return &VectorFinding{
		VectorID:       row.ID,
		Tool:           tool,
		Kind:           "bypass-candidates-rejected",
		Severity:       "info",
		InsertionPoint: row.InsertionPoint,
		Method:         row.Method,
		URL:            row.EvidenceURL,
		Confidence: "not a vulnerability: this is the accounting for candidates that were NOT " +
			"reported. A bypass is only a bypass if the same request without the technique is " +
			"refused, so each candidate here was re-sent alongside a control and the control " +
			"reproduced it, or no control could be sent and the claim was withheld. Every reason " +
			"is named per candidate below so you can disagree with any of them.",
		Evidence:        evidence,
		DetectionMethod: tool + " negative control",
	}
}

// ---------------------------------------------------------------------------------------------
// The live probe: the paced client, not a second one.
// ---------------------------------------------------------------------------------------------

var (
	bypassClientOnce sync.Once
	bypassBudget     *HostBudget
	bypassClient     *ScanClient
	bypassAcquired   sync.Map
)

func bypassScanClient() *ScanClient {
	bypassClientOnce.Do(func() {
		bypassBudget = NewHostBudget()
		bypassClient = NewScanClient(bypassBudget, 15*time.Second, "", nil)
	})
	return bypassClient
}

func liveBypassControlProbe(ctx context.Context, req bypassProbeRequest) bypassProbeResult {
	out := bypassProbeResult{
		Method:  strings.ToUpper(firstNonEmpty(req.Method, "GET")),
		URL:     strings.TrimSpace(req.URL),
		Headers: req.Headers,
	}
	parsed, err := url.Parse(out.URL)
	if err != nil || parsed.Host == "" {
		out.Err = "the control url could not be parsed"
		return out
	}

	headers := map[string]string{}
	for _, h := range req.Headers {
		name, value, ok := strings.Cut(h, ":")
		name = strings.TrimSpace(name)
		if !ok || name == "" || bypassUnsettableHeaders[strings.ToLower(name)] {
			continue
		}
		headers[name] = strings.TrimSpace(value)
	}

	// bypassScanClient() FIRST. It is what initialises bypassBudget inside its sync.Once, and
	// bypassAcquireHost dereferences that budget. Called the other way round, the very first control
	// of the very first real bypass scan dereferenced a nil *HostBudget:
	//
	//	utils.(*HostBudget).Acquire(0x0, ...)   paceBudget.go:129
	//	utils.bypassAcquireHost(...)            bypassControl.go:936
	//	panic: runtime error: invalid memory address or nil pointer dereference
	//
	// runVectorScan is launched as a bare `go runVectorScan(...)`, so that panic took the entire api
	// process down rather than failing one scan. Every unit test stubs bypassControlProbe, which is
	// why a green suite never touched it: the control layer had never executed once.
	// SCOPE, CHECKED BEFORE A SINGLE REQUEST LEAVES.
	//
	// Every other ScanClient in this package is built with .WithScope(scope); this one was not, so the
	// control would send to whatever hostname the TOOL wrote into its report. That is not a
	// theoretical worry here: this section's whole failure mode was tools requesting URLs other than
	// the one they claimed, including the bare site root and /robots.txt, and Forbidden takes a
	// configurable path. A control that follows the tool wherever it went is a control that can leave
	// the engagement.
	//
	// The scope is resolved from the hostname rather than passed in, because the parser is handed a
	// vector row rather than a scope target, and it is checked here rather than on the shared client
	// because that client is a package-level singleton serving every target at once.
	host := strings.ToLower(parsed.Hostname())
	if scopeTargetID := bypassScopeTargetForHost(host); scopeTargetID != "" {
		if scope := LoadScanScope(scopeTargetID); scope != nil && !scope.Allows(host) {
			scope.Refuse(host)
			out.Err = "refused: " + host + " is outside the scope of this target (" +
				scope.Describe() + "), so no control was sent. The candidate cannot be confirmed " +
				"or rejected and is reported as unverified rather than as a bypass."
			return out
		}
	}

	client := bypassScanClient()
	bypassAcquireHost(host)
	resp := client.Do(ctx, ScanRequest{
		URL: out.URL, Method: out.Method, Headers: headers, ReadBody: true,
	})
	if resp.Err != nil {
		out.Err = resp.Err.Error()
		return out
	}
	out.Status = resp.Status
	out.Bytes = resp.BodyBytes
	out.Body = resp.Body
	out.ContentType = resp.ContentType
	return out
}

// bypassAcquireHost registers the host's rate, preferring a rate the Routing & WAF Probe MEASURED
// for whichever scope target owns this hostname, and falling back to the framework's conservative
// assumed rate when there is nothing measured to use.
//
// Only the lookup is cached. Acquire itself is called every time because it only ever LOWERS a
// host's limits, so a rate another part of the run has since measured downwards is never undone by
// this one re-registering.
func bypassAcquireHost(host string) {
	if host == "" {
		return
	}
	rate, cached := bypassAcquired.Load(host)
	if !cached {
		pc := ProbeContext{SafeRPS: 2.0, RateConfidence: "assumed", SafeConcurrency: 2}
		if id := bypassScopeTargetForHost(host); id != "" {
			pc = LoadProbeContext(id)
		}
		rps, concurrency := pc.EffectiveRate()
		rate = [2]float64{rps, float64(concurrency)}
		bypassAcquired.Store(host, rate)
	}
	measured := rate.([2]float64)
	bypassBudget.Acquire(host, measured[0], int(measured[1]), "access_bypass_control")
}

// bypassScopeTargetForHost finds which scope target a hostname belongs to, most specific first.
// The parser is handed a row, not a scope target id, so this is the only way to reach a measured
// pacing rate from here.
func bypassScopeTargetForHost(host string) string {
	if dbPool == nil {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := dbPool.Query(ctx, `SELECT id, COALESCE(scope_target,'') FROM scope_targets`)
	if err != nil {
		return ""
	}
	defer rows.Close()

	bestID, bestLen := "", -1
	for rows.Next() {
		var id, target string
		if rows.Scan(&id, &target) != nil {
			continue
		}
		candidate := strings.ToLower(strings.TrimSpace(target))
		candidate = strings.TrimPrefix(candidate, "https://")
		candidate = strings.TrimPrefix(candidate, "http://")
		candidate = strings.TrimPrefix(candidate, "*.")
		if i := strings.IndexAny(candidate, "/:"); i > 0 {
			candidate = candidate[:i]
		}
		if candidate == "" {
			continue
		}
		if host == candidate || strings.HasSuffix(host, "."+candidate) {
			if len(candidate) > bestLen {
				bestID, bestLen = id, len(candidate)
			}
		}
	}
	return bestID
}

// ---------------------------------------------------------------------------------------------
// Reading a tool's own curl back into a candidate.
// ---------------------------------------------------------------------------------------------

var (
	bypassCurlMethodRe = regexp.MustCompile(`-X\s+'?([A-Za-z]+)'?`)
	bypassCurlURLRe    = regexp.MustCompile(`'(https?://[^']+)'`)
	bypassCurlAgentRe  = regexp.MustCompile(`-A\s+'([^']+)'`)
)

// bypassHeadersFromCurl pulls every header out of a tool's reproduction command. The curl is the
// only place either tool records what it actually sent.
func bypassHeadersFromCurl(curl string) []string {
	if strings.TrimSpace(curl) == "" {
		return nil
	}
	var out []string
	for _, m := range curlHeaderRe.FindAllStringSubmatch(curl, -1) {
		if h := strings.TrimSpace(m[1]); h != "" {
			out = append(out, h)
		}
	}
	if m := bypassCurlAgentRe.FindStringSubmatch(curl); len(m) > 1 {
		out = append(out, "User-Agent: "+strings.TrimSpace(m[1]))
	}
	return out
}

func bypassURLFromCurl(curl string) string {
	if m := bypassCurlURLRe.FindStringSubmatch(curl); len(m) > 1 {
		return m[1]
	}
	return ""
}

func bypassMethodFromCurl(curl string) string {
	if m := bypassCurlMethodRe.FindStringSubmatch(curl); len(m) > 1 {
		return strings.ToUpper(m[1])
	}
	return ""
}
