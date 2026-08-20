package utils

import (
	"bufio"
	"encoding/json"
	"strings"
)

// Reading what the three XSS scanners produced.
//
// Each returns a different shape and means something different by a finding, and the differences are
// preserved rather than flattened. dalfox v3 dropped its headless browser, so its V means "the
// payload reached an executable position in a PARSED response", not that anything ran. domdig's
// findings really did execute, in Chromium. Calling both "vulnerable" would overstate one and
// understate the other.

// parseDalfoxJSONL reads dalfox's jsonl report.
//
// The meta line is skipped: it is a summary, not a finding, and admitting it would add a row per
// vector that says nothing. The insertion point is taken from the VECTOR rather than from dalfox's
// location field, because a cookie target is reported as location "Header" (a cookie is a header on
// the wire) and storing that would file every cookie finding under the wrong heading.
func parseDalfoxJSONL(stdout, report string, vector vectorRow) []VectorFinding {
	var findings []VectorFinding
	scanner := bufio.NewScanner(strings.NewReader(report))
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var row struct {
			Type            string `json:"type"`
			Severity        string `json:"severity"`
			Confidence      string `json:"confidence"`
			Param           string `json:"param"`
			Payload         string `json:"payload"`
			Method          string `json:"method"`
			Data            string `json:"data"`
			Evidence        string `json:"evidence"`
			DetectionMethod string `json:"detection_method"`
			InjectType      string `json:"inject_type"`
			MessageStr      string `json:"message_str"`
			Request         string `json:"request"`
			Response        string `json:"response"`
			Meta            *struct {
				FindingsCount int `json:"findings_count"`
			} `json:"meta"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.Meta != nil || row.Type == "" {
			continue
		}
		evidence := row.Evidence
		if evidence == "" {
			evidence = row.MessageStr
		}
		findings = append(findings, VectorFinding{
			VectorID:        vector.ID,
			Tool:            "dalfox",
			Kind:            row.Type,
			Severity:        strings.ToLower(row.Severity),
			Confidence:      row.Confidence,
			InsertionPoint:  vector.InsertionPoint,
			Param:           row.Param,
			Payload:         row.Payload,
			Method:          row.Method,
			URL:             row.Data,
			Evidence:        evidence,
			DetectionMethod: row.DetectionMethod,
			InjectType:      row.InjectType,
			RawRequest:      row.Request,
			RawResponse:     row.Response,
		})
	}
	return findings
}

// parseDomdigJSON reads domdig's -J report off stdout. domdig has no --output flag, so stdout is the
// only channel, which is why -q is framework owned: progress chatter mixed into it cannot be parsed.
func parseDomdigJSON(stdout, report string, vector vectorRow) []VectorFinding {
	start := strings.Index(stdout, "[")
	if start < 0 {
		return nil
	}
	var rows []struct {
		Type      string `json:"type"`
		URL       string `json:"url"`
		Payload   string `json:"payload"`
		Element   string `json:"element"`
		Message   string `json:"message"`
		Confirmed *bool  `json:"confirmed"`
	}
	if json.Unmarshal([]byte(stdout[start:]), &rows) != nil {
		return nil
	}

	var findings []VectorFinding
	for _, row := range rows {
		// domdig's own definition: confirmed means the URL contained the payload, so the route from
		// input to execution is established. Unconfirmed still means the payload EXECUTED in a real
		// browser, which is stronger evidence than dalfox's V, and it is recorded as such rather than
		// discarded.
		confidence := "confirmed"
		if row.Confirmed != nil && !*row.Confirmed {
			confidence = "executed, route not established"
		}
		findings = append(findings, VectorFinding{
			VectorID:        vector.ID,
			Tool:            "domdig",
			Kind:            row.Type,
			Severity:        "high",
			Confidence:      confidence,
			InsertionPoint:  vector.InsertionPoint,
			Param:           row.Element,
			Payload:         row.Payload,
			Method:          vector.Method,
			URL:             row.URL,
			Evidence:        row.Message,
			DetectionMethod: "browser-execution",
		})
	}
	return findings
}

// parseXSSFuzzOutput reads xssFuzz's plain text.
//
// xssFuzz has no machine readable format at all: -o writes the same lines it prints. The two that
// carry a result are the parameter verdict and the payload verdict, and they are matched on their
// literal wording because there is nothing else to match on.
func parseXSSFuzzOutput(stdout, report string, vector vectorRow) []VectorFinding {
	var findings []VectorFinding
	seen := map[string]bool{}

	for _, line := range strings.Split(stdout, "\n") {
		line = strings.TrimSpace(stripANSI(line))
		switch {
		case strings.Contains(line, "not handling dangerous characters properly"):
			param := betweenWords(line, "Parameter ", " not handling")
			key := "param:" + param
			if param == "" || seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, VectorFinding{
				VectorID: vector.ID, Tool: "xssfuzz", Kind: "R", Severity: "medium",
				// Deliberately not called a vulnerability. Without -V, xssFuzz has established that a
				// dangerous character survived, not that anything executed.
				Confidence:      "reflected, dangerous characters unfiltered",
				InsertionPoint:  vector.InsertionPoint,
				Param:           param,
				Method:          vector.Method,
				URL:             vector.EvidenceURL,
				Evidence:        line,
				DetectionMethod: "reflection",
			})
		case strings.Contains(line, "XSS Found") || strings.Contains(line, "Vulnerable URL"):
			if seen["poc:"+line] {
				continue
			}
			seen["poc:"+line] = true
			findings = append(findings, VectorFinding{
				VectorID: vector.ID, Tool: "xssfuzz", Kind: "V", Severity: "high",
				Confidence:      "validated in a browser",
				InsertionPoint:  vector.InsertionPoint,
				Method:          vector.Method,
				URL:             lastURLIn(line),
				Evidence:        line,
				DetectionMethod: "browser-execution",
			})
		}
	}
	return findings
}

// dalfoxIncomplete reads the meta line that parseDalfoxJSONL deliberately skips, and reports whether
// dalfox says it gave up.
//
// The meta line is a summary rather than a finding, which is why the finding parser ignores it. But
// it is also the ONLY place dalfox records that a run was abandoned:
//
//	{"meta":{"findings_count":0,"incomplete":true,"target_summary":[{"status":"incomplete",
//	  "error_code":"SESSION_LOST","error_message":"--session-check pattern did not match ..."}]}}
//
// Skipping the line meant skipping that, and 53 abandoned vectors were recorded as clean against an
// application that documents four separate XSS on its own /vulnerabilities page. dalfox was not
// wrong and it was not silent. Nobody was reading it.
func dalfoxIncomplete(stdout, report string) string {
	scanner := bufio.NewScanner(strings.NewReader(report))
	scanner.Buffer(make([]byte, 0, 1024*1024), 8*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var row struct {
			Meta *struct {
				Incomplete    bool `json:"incomplete"`
				TargetSummary []struct {
					Status       string `json:"status"`
					ErrorCode    string `json:"error_code"`
					ErrorMessage string `json:"error_message"`
				} `json:"target_summary"`
			} `json:"meta"`
		}
		if json.Unmarshal([]byte(line), &row) != nil || row.Meta == nil || !row.Meta.Incomplete {
			continue
		}
		// The per-target reason is the useful one. "incomplete" on its own tells an operator that
		// something went wrong but not what to change, and SESSION_LOST tells them to refresh the
		// token before believing any of it.
		for _, target := range row.Meta.TargetSummary {
			if target.ErrorCode != "" || target.ErrorMessage != "" {
				reason := target.ErrorCode
				if target.ErrorMessage != "" {
					if reason != "" {
						reason += ": "
					}
					reason += target.ErrorMessage
				}
				return reason
			}
		}
		return "dalfox reported the run incomplete without naming a reason"
	}
	return ""
}
