package utils

import (
	"encoding/json"
	"strings"
)

// Turning one attack vector plus the stored settings into one sqlmap, ghauri or SQLiDetector command.
//
// Separate from the runner so the rules can be tested without a container, because every one of them
// fails OPEN: a tool given the wrong flag does not error, it exits 0 having tested nothing, and the
// operator reads a clean result for a vector that was never touched.
//
// THE RULE, measured on both sqlmap and ghauri by changing one flag at a time against a target whose
// five insertion points all reach the same unsanitised query:
//
//	cookie, level 1, --cookie "sid=1"          NOT TESTED (exit 0, no finding)
//	cookie, level 2, --cookie "sid=1"          Parameter: sid (COOKIE)
//	cookie, level 1, --cookie "sid=1*"         Parameter: sid (COOKIE)
//	header, level 1, -H "X-Account-Id: 1"      NOT TESTED
//	header, level 3, -H "X-Account-Id: 1"      NOT TESTED  <- level 3 is User-Agent/Referer/Host only
//	header, level 1, -H "X-Account-Id: 1*"     Parameter: X-Account-Id (HEADER)
//	path,            -u ".../path/1*"          Parameter: #1* (URI)
//
// So the composer MARKS ITS TARGET and never relies on --level. Raising the level is left to the
// operator as a way to widen the search, not as the thing that makes their vector get tested.

// ComposeSqlmap builds the sqlmap argv for one vector.
func ComposeSqlmap(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("sqlmap")
	var warnings []string

	args := []string{"/opt/sqlmap/sqlmap.py", "-u", sqliTargetURL(v)}

	method := strings.ToUpper(strings.TrimSpace(v.Method))
	if method != "" && method != "GET" {
		args = append(args, "--method", method)
	}
	if v.InsertionPoint == "body" {
		args = append(args, "--data", vectorBodyFor(v))
	}

	// -p names the parameter to test, which stops sqlmap wandering into every other parameter on the
	// URL and attributing a finding to a vector that did not claim it.
	if v.InsertionPoint == "query" && len(v.Parameters) > 0 {
		args = append(args, "-p", strings.Join(v.Parameters, ","))
	}

	suppressedHeader := ""
	authCookies := stringifySetting(settings["cookie"])

	switch v.InsertionPoint {
	case "cookie":
		name := markableParam(v)
		args = append(args, "--cookie", mergeCookieHeader(authCookies, name, v.valueFor(name)))
	case "header":
		name := markableParam(v)
		suppressedHeader = strings.ToLower(name)
		args = append(args, "-H", name+": "+sqliMarkedValue(v.valueFor(name)))
		if authCookies != "" {
			args = append(args, "--cookie", authCookies)
		}
	default:
		if authCookies != "" {
			args = append(args, "--cookie", authCookies)
		}
	}

	args = append(args, composeVectorSettings(tool, settings, suppressedHeader,
		map[string]bool{"cookie": true}, &warnings)...)

	// Framework owned, appended last so a stored setting cannot displace them.
	args = append(args,
		"--batch",            // no terminal to answer prompts from
		"--disable-coloring", // escape codes corrupt stored evidence
		// ALWAYS. sqlmap stores a session per target under --output-dir and RESTORES its verdict on
		// the next run instead of sending anything. Measured against 10.0.0.18: /tmp/sqlmap-out held
		// four host directories, some days old; four traces of one run were pure cache replays, six of
		// seven findings were verdicts restored from a scan twenty hours earlier, and one stored GET
		// ?q= injection was replayed as three findings across query, cookie and header vectors that
		// never ran. The oracle canary was a replay too: it "passed" in 871ms without a test request,
		// so the one control that proves sqlmap ran would pass identically with sqlmap broken or the
		// oracle switched off. Third tool in this codebase with this defect, after commix and ghauri.
		"--flush-session",
		"--report-json", reportPath,
		"--output-dir", "/tmp/sqlmap-out",
		"-v", "0",
	)
	return args, warnings
}

// ComposeGhauri builds the ghauri argv. Same marker rules as sqlmap, verified separately on ghauri
// 1.4.3 rather than assumed from the shared heritage.
func ComposeGhauri(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("ghauri")
	var warnings []string

	args := []string{"-u", sqliTargetURL(v)}

	if v.InsertionPoint == "body" {
		args = append(args, "--data", vectorBodyFor(v))
	}
	if v.InsertionPoint == "query" && len(v.Parameters) > 0 {
		args = append(args, "-p", strings.Join(v.Parameters, ","))
	}

	suppressedHeader := ""
	authCookies := stringifySetting(settings["cookie"])

	switch v.InsertionPoint {
	case "cookie":
		name := markableParam(v)
		args = append(args, "--cookie", mergeCookieHeader(authCookies, name, v.valueFor(name)))
	case "header":
		name := markableParam(v)
		suppressedHeader = strings.ToLower(name)
		args = append(args, "-H", name+": "+sqliMarkedValue(v.valueFor(name)))
		if authCookies != "" {
			args = append(args, "--cookie", authCookies)
		}
	default:
		if authCookies != "" {
			args = append(args, "--cookie", authCookies)
		}
	}

	args = append(args, composeVectorSettings(tool, settings, suppressedHeader,
		map[string]bool{"cookie": true}, &warnings)...)

	// ghauri has no machine-readable report, so findings are read from stdout. --batch is what stops
	// it prompting "keep testing the others?" and blocking forever.
	//
	// --flush-session is not optional. ghauri's session is keyed by HOST rather than by URL and
	// parameter, so once it has recorded a verdict for ginandjuice.shop it replays that verdict for
	// every remaining vector on the host without sending a request. Measured: 53 vectors, 53 clean;
	// the same command with this flag reports
	// "category (GET) ... AND boolean-based blind - WHERE or HAVING clause".
	args = append(args, "--batch", "--flush-session")
	_ = reportPath
	return args, warnings
}

// ComposeSQLiDetector builds the SQLiDetector argv.
//
// It reads a FILE of URLs rather than taking one on the command line, so the runner writes that file
// first; the path arrives here already written. Only query vectors get this far, because eligibility
// has already ruled out everything else.
func ComposeSQLiDetector(v VectorInput, settings map[string]any, reportPath string) ([]string, []string) {
	tool, _ := VectorToolByKey("sqlidetector")
	var warnings []string

	args := []string{"/opt/SQLiDetector/sqlidetector.py", "-f", reportPath + ".urls"}
	args = append(args, composeVectorSettings(tool, settings, "", nil, &warnings)...)
	args = append(args, "-o", reportPath)
	return args, warnings
}

// sqliTargetURL builds the URL, marking a path segment when the vector is a path vector.
//
// The marker goes on the LAST non-empty segment, because that is the segment the consolidation
// templated as an identifier. Measured: with the marker, sqlmap reports Parameter: #1* (URI).
func sqliTargetURL(v VectorInput) string {
	base := v.TargetURL()
	if v.InsertionPoint != "path" {
		return base
	}

	// Edited as TEXT rather than through net/url. url.URL.String() percent-encodes the marker to
	// %2A, and sqlmap looks for a literal asterisk: it would find no custom injection point, fall
	// back to testing whatever query parameters happened to be there, and report clean for the path.
	// That is the same silent-miss this whole file exists to prevent, and the test for it is the only
	// reason it was noticed.
	pathPart, queryPart, hasQuery := strings.Cut(base, "?")
	scheme, rest, hasScheme := strings.Cut(pathPart, "://")
	if !hasScheme {
		return base
	}
	host, path, hasPath := strings.Cut(rest, "/")
	if !hasPath {
		return base
	}

	segments := strings.Split(path, "/")
	for i := len(segments) - 1; i >= 0; i-- {
		if segments[i] == "" {
			continue
		}
		// A templated segment carries no concrete value to inject into, so the canary stands in for
		// one. /users/{uuid} would otherwise be marked as /users/{uuid}* and the tool would spend the
		// scan testing the literal string {uuid}.
		if strings.HasPrefix(segments[i], "{") && strings.HasSuffix(segments[i], "}") {
			segments[i] = VectorCanary
		}
		segments[i] += "*"
		break
	}

	out := scheme + "://" + host + "/" + strings.Join(segments, "/")
	if hasQuery {
		out += "?" + queryPart
	}
	return out
}

// parseSqlmapReport reads sqlmap's --report-json.
//
// The structure is {"success":bool,"data":[{"type_name":"TECHNIQUES","value":[{place,parameter,
// data:[{technique,title,payload}]}]}]}. One finding per TECHNIQUE, because "boolean-based blind"
// and "error-based" on the same parameter are different amounts of evidence and an operator triages
// them differently.
//
// The insertion point is taken from the VECTOR, not from sqlmap's place field, which reports a
// marked cookie as "(custom) HEADER". Filing every cookie finding under header would be wrong in the
// same way dalfox's cookie labelling was.
func parseSqlmapReport(stdout, report string, row vectorRow) []VectorFinding {
	var doc struct {
		Success bool `json:"success"`
		Data    []struct {
			TypeName string          `json:"type_name"`
			Value    json.RawMessage `json:"value"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(report), &doc) != nil {
		return nil
	}

	var findings []VectorFinding
	for _, entry := range doc.Data {
		if entry.TypeName != "TECHNIQUES" {
			continue
		}
		var places []struct {
			Place     string `json:"place"`
			Parameter string `json:"parameter"`
			Data      []struct {
				Technique string `json:"technique"`
				Title     string `json:"title"`
				Payload   string `json:"payload"`
			} `json:"data"`
		}
		if json.Unmarshal(entry.Value, &places) != nil {
			continue
		}
		for _, p := range places {
			for _, d := range p.Data {
				findings = append(findings, VectorFinding{
					VectorID:       row.ID,
					Tool:           "sqlmap",
					Kind:           d.Technique,
					Severity:       sqliSeverityFor(d.Technique),
					Confidence:     "confirmed by sqlmap",
					InsertionPoint: row.InsertionPoint,
					Param:          p.Parameter,
					Payload:        d.Payload,
					Method:         row.Method,
					URL:            row.EvidenceURL,
					Evidence:       d.Title,
					// sqlmap's place is kept as the detection method rather than as the insertion
					// point, so the disagreement is visible instead of silently overwriting ours.
					DetectionMethod: "sqlmap " + strings.ToLower(p.Place),
					InjectType:      d.Technique,
				})
			}
		}
	}
	return findings
}

// parseGhauriOutput reads ghauri's stdout. It has no machine-readable report, so the block it prints
// between "Parameter:" and the closing --- is the only structured thing available.
func parseGhauriOutput(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding
	var param, technique, title string

	for _, line := range strings.Split(stripANSI(stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Parameter:"):
			param = strings.TrimSpace(strings.TrimPrefix(trimmed, "Parameter:"))
			technique, title = "", ""
		case strings.HasPrefix(trimmed, "Type:"):
			technique = strings.TrimSpace(strings.TrimPrefix(trimmed, "Type:"))
		case strings.HasPrefix(trimmed, "Title:"):
			title = strings.TrimSpace(strings.TrimPrefix(trimmed, "Title:"))
		case strings.HasPrefix(trimmed, "Payload:"):
			payload := strings.TrimSpace(strings.TrimPrefix(trimmed, "Payload:"))
			if param == "" || technique == "" {
				continue
			}
			findings = append(findings, VectorFinding{
				VectorID:        row.ID,
				Tool:            "ghauri",
				Kind:            technique,
				Severity:        sqliSeverityFor(technique),
				Confidence:      "confirmed by ghauri",
				InsertionPoint:  row.InsertionPoint,
				Param:           param,
				Payload:         payload,
				Method:          row.Method,
				URL:             row.EvidenceURL,
				Evidence:        title,
				DetectionMethod: "ghauri",
				InjectType:      technique,
			})
		}
	}
	return findings
}

// parseSQLiDetectorReport reads SQLiDetector's JSON, which is an array of [url, matched_error] pairs.
//
// Every row is reported as UNCONFIRMED. SQLiDetector has established that a database error message
// appeared in a response, which is a lead: the same error is produced by a parameter that is
// concatenated into a query and then correctly escaped later, and by an application that echoes its
// exception handler on any malformed input. That is why the tool's own description calls it a triage
// pass, and why the finding says so rather than claiming an injection.
func parseSQLiDetectorReport(stdout, report string, row vectorRow) []VectorFinding {
	var pairs [][]string
	if json.Unmarshal([]byte(report), &pairs) != nil {
		return nil
	}

	// One finding per DBMS error signature rather than per payload. Fourteen payloads against one
	// parameter routinely all match, and fourteen identical rows is a wall rather than a finding.
	seen := map[string]bool{}
	var findings []VectorFinding
	for _, pair := range pairs {
		if len(pair) < 2 {
			continue
		}
		injected, signature := pair[0], pair[1]
		if seen[signature] {
			continue
		}
		seen[signature] = true
		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "sqlidetector",
			Kind:            "error-signature",
			Severity:        "medium",
			Confidence:      "unconfirmed: a database error appeared, which is a lead rather than an injection. Confirm with sqlmap or Ghauri",
			InsertionPoint:  row.InsertionPoint,
			Param:           strings.Join(row.Parameters, ","),
			Payload:         injected,
			Method:          row.Method,
			URL:             injected,
			Evidence:        "Response matched the DBMS error pattern " + signature,
			DetectionMethod: "error-message match",
		})
	}
	return findings
}

// sqliSeverityFor grades by what the technique actually demonstrates. A stacked query means arbitrary
// statements execute; a time-based blind means one bit at a time and a slow afternoon. Both are
// findings, and treating them as the same severity makes the list useless for deciding what to do
// first.
func sqliSeverityFor(technique string) string {
	t := strings.ToLower(technique)
	switch {
	case strings.Contains(t, "stacked"):
		return "critical"
	case strings.Contains(t, "union"), strings.Contains(t, "error"):
		return "high"
	case strings.Contains(t, "boolean"), strings.Contains(t, "inline"):
		return "high"
	case strings.Contains(t, "time"):
		return "medium"
	}
	return "high"
}
