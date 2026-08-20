package utils

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Reading what the two bypass tools produced.
//
// The whole job here is deciding which reported bypasses to believe. Both tools report variations
// whose response differs from a baseline, and on a real site most differences are not bypasses: a
// WAF block page, a redirect to a login form, or a denial served under status 200 all differ from a
// 403 without granting access to anything.

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

	// The unmodified request, which is the denial every other result is judged against.
	baselineHash, baselineLength, baselineStatus := "", -1, 0
	for _, result := range results {
		if result.Technique == "default" {
			baselineHash, baselineLength, baselineStatus = result.BodyHash, result.ContentLength, result.StatusCode
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

	var findings []VectorFinding
	seen := map[string]bool{}
	for _, result := range results {
		if result.Technique == "default" {
			continue
		}
		// Still the original denial, wearing a different status code.
		if baselineHash != "" && result.BodyHash == baselineHash {
			continue
		}
		// Nothing was granted: the variation was refused too.
		if result.StatusCode >= 400 {
			continue
		}

		key := result.Technique + "|" + strconv.Itoa(result.StatusCode) + "|" + result.BodyHash
		if seen[key] {
			continue
		}
		seen[key] = true

		severity, confidence := nomore403Grade(result, baselineLength, baselineStatus, row.BaselineStatus)
		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "nomore403",
			Kind:            "access-control-bypass",
			Severity:        severity,
			Confidence:      confidence,
			InsertionPoint:  row.InsertionPoint,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Payload:         result.Payload,
			Evidence: result.Technique + ": " + strconv.Itoa(baselineStatus) + " -> " +
				strconv.Itoa(result.StatusCode) + ", " + strconv.Itoa(baselineLength) + "b -> " +
				strconv.Itoa(result.ContentLength) + "b" + scoreText(result) + ". " + result.ReproCurl,
			DetectionMethod: "nomore403 " + result.Technique,
			InjectType:      result.Technique,
		})
	}
	return findings
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

	var findings []VectorFinding
	seen := map[string]bool{}
	for _, result := range results {
		code := result.statusCode()
		if code >= 400 || code == 0 {
			continue
		}
		length := anyToInt(result.Length)

		// One finding per distinct (method, status, length). Measured: a single URL with six test
		// families produced 1472 records, almost all of them the same response reached by a different
		// encoding of the same path. Storing them one by one would bury the handful that differ.
		key := result.Method + "|" + strconv.Itoa(code) + "|" + strconv.Itoa(length)
		if seen[key] {
			continue
		}
		seen[key] = true

		severity := "medium"
		confidence := "Forbidden reached this with a request the original was refused for. It applies " +
			"the ignore regex and length filters before reporting, so this survived them, but a " +
			"status code is not access: confirm the body is the protected resource."
		if code >= 300 && code < 400 {
			severity = "low"
			confidence = "the response is a redirect, which is often a login flow rather than a bypass."
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
			Confidence:      confidence,
			InsertionPoint:  row.InsertionPoint,
			Method:          result.Method,
			URL:             firstNonEmpty(result.URL, row.EvidenceURL),
			Evidence:        evidence,
			DetectionMethod: "forbidden",
			RawResponse:     result.Response,
		})
	}
	return findings
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
