package utils

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

// Reading what the two bypass tools produced.
//
// The whole job here is deciding which reported bypasses to believe. Both tools report variations
// whose response differs from a baseline, and on a real site most differences are not bypasses: a
// WAF block page, a redirect to a login form, or a denial served under status 200 all differ from a
// 403 without granting access to anything.
//
// NOTHING IN THIS FILE DECIDES ANYTHING ON ITS OWN ANY MORE. Both parsers now reduce a report to a
// list of CANDIDATES and hand them to bypassControl.go, which re-sends each one alongside a
// negative control and compares the two bodies. What survives is reported; what does not is counted
// and explained on a single note rather than dropped. That split is deliberate: the reading of a
// report and the judging of a claim were tangled together here, and the judging was wrong.
//
// The measurement that forced it: seven scanners against OWASP Juice Shop produced 165 findings, of
// which 159 came from these two tools and every one was false. They died in two ways, and neither
// is anything a report parser can see. A non-response was scored as access, and every surviving
// candidate was compared against the original target url while the tool had requested a mutated one.

// nomore403Result is one line of the --jsonl report. Captured verbatim from a real run:
//
//	{"status_code":403,"content_length":19,"technique":"default","payload":"http://host/decoy",
//	 "score":0,"likelihood":"low","score_reason":"minor variation","body_hash":"b44cf7a31cadf00b",
//	 "content_type":"text/plain","server":"nginx/1.31.3","repro_curl":"curl -i -sS -k ..."}
type nomore403Result struct {
	StatusCode    int    `json:"status_code"`
	ContentLength int    `json:"content_length"`
	Technique     string `json:"technique"`
	Payload       string `json:"payload"`
	Score         int    `json:"score"`
	Likelihood    string `json:"likelihood"`
	ScoreReason   string `json:"score_reason"`
	BodyHash      string `json:"body_hash"`
	ContentType   string `json:"content_type"`
	Server        string `json:"server"`
	ReproCurl     string `json:"repro_curl"`
}

// parseNomore403Report reads the JSON Lines report.
//
// Two things decide what becomes a finding:
//
//   - The BASELINE row. nomore403 emits its own unmodified request as technique "default", and that
//     row is the original denial. Any result sharing its body_hash is the same page again, whatever
//     status code it arrived under, and is not a bypass. This is the soft-403 defence and it works
//     because the tool publishes a body hash per result.
//   - The tool's own score and likelihood, which are kept rather than flattened. Measured, a real
//     bypass reaching different content scored 100/high; the decoy's denial pages were suppressed by
//     calibration entirely and did not appear at all.
func parseNomore403Report(stdout, report string, row vectorRow) []VectorFinding {
	var results []nomore403Result
	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var parsed nomore403Result
		if err := json.Unmarshal([]byte(line), &parsed); err != nil {
			continue
		}
		results = append(results, parsed)
	}
	if len(results) == 0 {
		return nil
	}

	// The unmodified request, which is the denial every other result is judged against, and also the
	// only place nomore403 publishes the BASE headers of the run. Knowing them exactly is what lets
	// the control strip the technique's headers and nothing else.
	baselineHash, baselineLength, baselineStatus := "", -1, 0
	var baseHeaders []string
	for _, result := range results {
		if result.Technique == "default" {
			baselineHash, baselineLength, baselineStatus = result.BodyHash, result.ContentLength, result.StatusCode
			baseHeaders = bypassHeadersFromCurl(result.ReproCurl)
			break
		}
	}

	// The target does not deny anything any more, so nothing found here is a bypass.
	//
	// The list is built from 4xx responses recorded EARLIER by other tools, and a site changes between
	// then and now: an endpoint is opened up, a login expires, a WAF rule is withdrawn. When the
	// unmodified request already succeeds, every variation of it also succeeds, and a status-only
	// comparison reports all of them as bypasses of an access control that is no longer there.
	if baselineStatus > 0 && baselineStatus < 400 {
		return []VectorFinding{{
			VectorID:       row.ID,
			Tool:           "nomore403",
			Kind:           "stale-target",
			Severity:       "info",
			Confidence:     "not a vulnerability: this URL no longer denies the request at all",
			InsertionPoint: row.InsertionPoint,
			Method:         row.Method,
			URL:            row.EvidenceURL,
			Evidence: "This target was recorded returning " + strconv.Itoa(row.BaselineStatus) +
				", but the unmodified request now answers " + strconv.Itoa(baselineStatus) +
				". There is no access control left to bypass, so the variations that also succeeded " +
				"are not findings. Re-run the consolidation to refresh the target list.",
			DetectionMethod: "nomore403 baseline",
		}}
	}

	// Deduplicated FIRST, so the control phase costs a couple of requests per distinct result rather
	// than per payload. Measured, one url with the default technique set produces dozens of records
	// that are the same response reached by a different encoding of the same path.
	var candidates []bypassCandidate
	var raw []nomore403Result
	seen := map[string]bool{}
	for _, result := range results {
		if result.Technique == "default" {
			continue
		}
		// Still the original denial, wearing a different status code.
		if baselineHash != "" && result.BodyHash == baselineHash {
			continue
		}
		// Nothing was granted: the variation was refused too. Status 0 is NOT filtered here, on
		// purpose: it used to slip through this test and be reported as a bypass, and it now has to
		// reach bypassPreScreen so it is rejected for the right reason and counted.
		if result.StatusCode >= 400 {
			continue
		}

		key := result.Technique + "|" + strconv.Itoa(result.StatusCode) + "|" + result.BodyHash
		if seen[key] {
			continue
		}
		seen[key] = true

		headers := bypassHeadersFromCurl(result.ReproCurl)
		candidates = append(candidates, bypassCandidate{
			Technique:    result.Technique,
			Method:       nomore403Method(result, row),
			RequestedURL: nomore403RequestedURL(result, row),
			OriginalURL:  row.EvidenceURL,
			Headers:      headers,
			BaseHeaders:  bypassBaseHeaders(headers, baseHeaders),
			Status:       result.StatusCode,
			Length:       result.ContentLength,
			Curl:         result.ReproCurl,
			Score:        result.Score,
		})
		raw = append(raw, result)
	}
	if len(candidates) == 0 {
		return nil
	}

	judgements := screenBypassCandidates(candidates)

	var findings []VectorFinding
	for i, judgement := range judgements {
		if judgement.Verdict != bypassVerdictConfirmed {
			continue
		}
		result := raw[i]
		// The grade is left exactly as the tool's score and the length comparison against the original
		// denial produced it. The control does not raise it: the two say different things, and a
		// response the same length as the denial page is still suspicious even when a control did not
		// reproduce it. What the control changes is whether the finding exists at all.
		severity, confidence := nomore403Grade(result, baselineLength, baselineStatus, row.BaselineStatus)
		findings = append(findings, VectorFinding{
			VectorID:       row.ID,
			Tool:           "nomore403",
			Kind:           "access-control-bypass",
			Severity:       severity,
			Confidence:     confidence + " CONTROLLED: " + judgement.Reason,
			InsertionPoint: row.InsertionPoint,
			Method:         candidates[i].Method,
			URL:            row.EvidenceURL,
			Payload:        result.Payload,
			Evidence: result.Technique + ": " + strconv.Itoa(baselineStatus) + " -> " +
				strconv.Itoa(result.StatusCode) + ", " + strconv.Itoa(baselineLength) + "b -> " +
				strconv.Itoa(result.ContentLength) + "b" + scoreText(result) + ". " + result.ReproCurl,
			DetectionMethod: "nomore403 " + result.Technique + " + " + judgement.ControlKind,
			InjectType:      result.Technique,
			RawRequest:      bypassRawRequest(judgement, candidates[i].RequestedURL),
			RawResponse:     bypassEvidenceBlock(judgement),
		})
	}
	if note := bypassRejectionNote("nomore403", row, candidates, judgements, len(findings)); note != nil {
		findings = append(findings, *note)
	}
	return findings
}

// nomore403RequestedURL recovers the url the tool ACTUALLY requested, which is the only thing a
// control can honestly be aimed at.
//
// The payload field is not it. It holds a url for the path and encoding techniques but a bare verb
// for the verb techniques, so the curl is preferred and the payload is only used when it plainly
// carries a url of its own.
func nomore403RequestedURL(result nomore403Result, row vectorRow) string {
	if fromCurl := bypassURLFromCurl(result.ReproCurl); fromCurl != "" {
		return fromCurl
	}
	if strings.HasPrefix(result.Payload, "http://") || strings.HasPrefix(result.Payload, "https://") {
		return result.Payload
	}
	return row.EvidenceURL
}

// nomore403Method recovers the verb, which for the verb-tampering techniques is the payload itself.
func nomore403Method(result nomore403Result, row vectorRow) string {
	if fromCurl := bypassMethodFromCurl(result.ReproCurl); fromCurl != "" {
		return fromCurl
	}
	if payload := strings.TrimSpace(result.Payload); payload != "" && !strings.Contains(payload, "/") &&
		payload == strings.ToUpper(payload) && len(payload) <= 10 {
		return payload
	}
	return firstNonEmpty(row.Method, "GET")
}

// nomore403Grade turns the tool's score and the comparison against the original denial into a
// severity and a sentence an operator can act on.
func nomore403Grade(result nomore403Result, baselineLength, baselineStatus, targetStatus int) (string, string) {
	sameLength := baselineLength >= 0 && result.ContentLength == baselineLength
	switch {
	case sameLength:
		return "low", "the response is a different status but exactly the same length as the original " +
			"denial, which usually means the same page. Check the body before believing it."
	case result.Score >= 90 && strings.EqualFold(result.Likelihood, "high"):
		return "high", "nomore403 scored this " + strconv.Itoa(result.Score) + " (" + result.Likelihood +
			"): the response differs from the original denial in status and in content. Confirm that " +
			"what came back is genuinely the protected resource, not a login page or a WAF notice."
	case result.Score >= 55:
		return "medium", "nomore403 scored this " + strconv.Itoa(result.Score) + " (" + result.Likelihood +
			"). Worth a look, but a status change on its own is not access: confirm the content."
	}
	return "low", "nomore403 scored this " + strconv.Itoa(result.Score) + " (" + result.Likelihood +
		"), which is below the threshold it treats as interesting."
}

func scoreText(result nomore403Result) string {
	if result.Score == 0 && result.ScoreReason == "" {
		return ""
	}
	out := ", score " + strconv.Itoa(result.Score)
	if result.ScoreReason != "" {
		out += " (" + result.ScoreReason + ")"
	}
	return out
}

// forbiddenResult is one entry of the JSON array Forbidden writes to -o.
//
// The keys are taken from a REAL report, not from the help text. That distinction cost a scan: the
// status field is called "status", and a first version of this struct read "code" because that is
// what the documentation calls it. Every record then scored zero, every record was skipped as a
// non-2xx, and a run that produced 1472 results was stored as a clean target.
//
// Both status and length arrive as STRINGS ("200", "73"), not numbers, which is why they are read
// through anyToInt rather than typed as ints.
type forbiddenResult struct {
	ID       any    `json:"id"`
	URL      string `json:"url"`
	Method   string `json:"method"`
	Command  string `json:"command"`
	Status   any    `json:"status"`
	Code     any    `json:"code"` // older builds
	Length   any    `json:"length"`
	Headers  any    `json:"headers"`
	Body     string `json:"body"`
	Response string `json:"response"`
}

// statusCode reads whichever field this build of Forbidden used.
func (r forbiddenResult) statusCode() int {
	if code := anyToInt(r.Status); code != 0 {
		return code
	}
	return anyToInt(r.Code)
}

// parseForbiddenReport reads the JSON report.
//
// Forbidden already applies the filters it was given, so what reaches the report has survived the
// ignore regex, the content length filter and the status code filter. The remaining job is to keep
// its own curl command, which is the reproduction, and to say plainly that a status code is not
// evidence of access.
func parseForbiddenReport(stdout, report string, row vectorRow) []VectorFinding {
	trimmed := strings.TrimSpace(report)
	if trimmed == "" {
		return nil
	}

	var results []forbiddenResult
	if err := json.Unmarshal([]byte(trimmed), &results); err != nil {
		// Some versions write one object per line rather than an array.
		results = nil
		for _, line := range strings.Split(trimmed, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var one forbiddenResult
			if err := json.Unmarshal([]byte(line), &one); err == nil {
				results = append(results, one)
			}
		}
		if len(results) == 0 {
			return nil
		}
	}

	var candidates []bypassCandidate
	var raw []forbiddenResult
	seen := map[string]bool{}
	for _, result := range results {
		code := result.statusCode()
		// Refusals are not candidates. Status 0 IS kept, unlike before: a record with no status is a
		// request that produced nothing, and skipping it here made it invisible. It now reaches
		// bypassPreScreen, which rejects it by name and counts it.
		if code >= 400 {
			continue
		}
		length := anyToInt(result.Length)

		// One candidate per distinct (method, status, length). Measured: a single URL with six test
		// families produced 1472 records, almost all of them the same response reached by a different
		// encoding of the same path. Screening them one by one would cost 1472 controls.
		key := result.Method + "|" + strconv.Itoa(code) + "|" + strconv.Itoa(length)
		if seen[key] {
			continue
		}
		seen[key] = true

		headers := forbiddenHeaders(result)
		candidates = append(candidates, bypassCandidate{
			Technique: forbiddenTestFamily(result),
			Method: firstNonEmpty(strings.ToUpper(strings.TrimSpace(result.Method)),
				bypassMethodFromCurl(result.Command), row.Method, "GET"),
			RequestedURL: firstNonEmpty(result.URL, bypassURLFromCurl(result.Command), row.EvidenceURL),
			OriginalURL:  row.EvidenceURL,
			Headers:      headers,
			// Forbidden publishes no unmodified-request row, so the base set is the identity
			// allowlist rather than a measured one. It errs towards KEEPING credentials, because an
			// anonymous control differs from an authenticated response for a reason that has nothing
			// to do with the technique, and that difference would keep a candidate rather than kill it.
			BaseHeaders: bypassBaseHeaders(headers, nil),
			Status:      code,
			Length:      length,
			Body:        firstNonEmpty(result.Body, result.Response),
			Curl:        result.Command,
		})
		raw = append(raw, result)
	}
	if len(candidates) == 0 {
		return nil
	}

	judgements := screenBypassCandidates(candidates)

	var findings []VectorFinding
	for i, judgement := range judgements {
		if judgement.Verdict != bypassVerdictConfirmed {
			continue
		}
		result := raw[i]
		code := result.statusCode()
		length := anyToInt(result.Length)

		severity := "medium"
		confidence := "Forbidden reached this with a request the original was refused for, and the " +
			"same request WITHOUT the technique did not reproduce it. That is the comparison this " +
			"section used to skip. It is still a candidate rather than a proven bypass: name the " +
			"string in the body that the control did not return before reporting it."
		if code >= 300 && code < 400 {
			severity = "low"
			confidence = "the response is a redirect, which is often a login flow rather than a bypass, " +
				"even though the control did not reproduce it."
		}

		evidence := result.Method + " -> " + strconv.Itoa(code) + ", " + strconv.Itoa(length) + "b"
		if result.Command != "" {
			evidence += ". " + result.Command
		}

		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "forbidden",
			Kind:            "access-control-bypass",
			Severity:        severity,
			Confidence:      confidence + " CONTROLLED: " + judgement.Reason,
			InsertionPoint:  row.InsertionPoint,
			Method:          result.Method,
			URL:             firstNonEmpty(result.URL, row.EvidenceURL),
			Evidence:        evidence,
			DetectionMethod: "forbidden + " + judgement.ControlKind,
			InjectType:      candidates[i].Technique,
			RawRequest:      bypassRawRequest(judgement, candidates[i].RequestedURL),
			RawResponse:     bypassEvidenceBlock(judgement),
		})
	}
	if note := bypassRejectionNote("forbidden", row, candidates, judgements, len(findings)); note != nil {
		findings = append(findings, *note)
	}
	return findings
}

// forbiddenTestFamily reads which test family produced a record. Forbidden encodes it in the id,
// which arrives as "1-ENCODINGS-1" or "2-METHOD-OVERRIDES-1", and the family decides whether the
// request can be reproduced at all: its parser and protocol tests exist precisely because PycURL
// sends request forms a Go client will not build.
func forbiddenTestFamily(result forbiddenResult) string {
	id := strings.TrimSpace(stringifySetting(result.ID))
	parts := strings.Split(id, "-")
	if len(parts) < 3 {
		return ""
	}
	return strings.ToLower(strings.Join(parts[1:len(parts)-1], "-"))
}

// forbiddenHeaders recovers the headers a record was produced with. The curl command is preferred
// because it is what Forbidden itself offers as the reproduction; the headers field is a fallback
// and arrives in more than one shape across builds.
func forbiddenHeaders(result forbiddenResult) []string {
	if fromCurl := bypassHeadersFromCurl(result.Command); len(fromCurl) > 0 {
		return fromCurl
	}
	switch t := result.Headers.(type) {
	case string:
		var out []string
		for _, line := range strings.Split(t, "\n") {
			if line = strings.TrimSpace(line); strings.Contains(line, ":") {
				out = append(out, line)
			}
		}
		return out
	case []any:
		var out []string
		for _, item := range t {
			if line, ok := item.(string); ok && strings.Contains(line, ":") {
				out = append(out, strings.TrimSpace(line))
			}
		}
		return out
	case map[string]any:
		var out []string
		for name, value := range t {
			out = append(out, strings.TrimSpace(name)+": "+stringifySetting(value))
		}
		sort.Strings(out)
		return out
	}
	return nil
}

// anyToInt reads a value that may have arrived as a number or as a string, because Forbidden's
// report is not consistent about which.
func anyToInt(value any) int {
	switch t := value.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		parsed, err := strconv.Atoi(strings.TrimSpace(t))
		if err != nil {
			return 0
		}
		return parsed
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
