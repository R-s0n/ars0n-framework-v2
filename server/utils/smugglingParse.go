package utils

import (
	"encoding/csv"
	"encoding/json"
	"strconv"
	"strings"
)

// Reading what the two smuggling tools produced.
//
// The hard part here is not extracting the findings. It is refusing to present a timeout as a
// vulnerability, because both tools will hand one over if asked carelessly, and a desync report is
// expensive to be wrong about: it is the kind of finding a programme escalates.

// smugglexReport is the JSON smugglex writes to -o. Only the fields that are read are declared, so a
// new key upstream does not break parsing.
type smugglexReport struct {
	Version string `json:"smugglex_version"`
	Results []struct {
		Target string `json:"target"`
		Method string `json:"method"`
		Checks []struct {
			CheckType    string   `json:"check_type"`
			Vulnerable   bool     `json:"vulnerable"`
			NormalStatus string   `json:"normal_status"`
			AttackStatus string   `json:"attack_status"`
			NormalMS     *float64 `json:"normal_duration_ms"`
			AttackMS     *float64 `json:"attack_duration_ms"`
			Confidence   string   `json:"confidence"`
			Signals      []string `json:"detection_signals"`
			Diagnostics  []string `json:"diagnostics"`
			Payload      string   `json:"payload"`
		} `json:"checks"`
	} `json:"results"`
	Summary struct {
		TotalChecks      int `json:"total_checks"`
		VulnerableChecks int `json:"vulnerable_checks"`
	} `json:"summary"`
}

// parseSmugglexReport turns the JSON report into findings.
//
// Two rules, both measured:
//
//   - A check whose normal_status is CHECK_FAILED never ran. It is recorded as vulnerable:false with
//     a diagnostics entry, which means a target where every check errored produces a report that
//     counts as clean. Those become warnings carried on an informational finding, never silence.
//   - Confidence is the tool's own and is kept. Against a lab containing exactly ONE desync, five
//     separate checks reported vulnerable at low confidence, every one of them evidenced only by a
//     connection timeout. Against the CL.0 lab, one check reported high confidence evidenced by a
//     status difference. So the useful signal is not "vulnerable" but what backed it.
func parseSmugglexReport(stdout, report string, row vectorRow) []VectorFinding {
	var parsed smugglexReport
	if err := json.Unmarshal([]byte(strings.TrimSpace(report)), &parsed); err != nil {
		return nil
	}

	var findings []VectorFinding
	var failed []string

	for _, result := range parsed.Results {
		for _, check := range result.Checks {
			if strings.EqualFold(check.NormalStatus, "CHECK_FAILED") {
				failed = append(failed, check.CheckType+" ("+firstOr(check.Diagnostics, "no detail")+")")
				continue
			}
			if !check.Vulnerable {
				continue
			}

			severity, confidence := smugglexGrade(check.Confidence, check.Signals, check.NormalStatus, check.AttackStatus)
			findings = append(findings, VectorFinding{
				VectorID:        row.ID,
				Tool:            "smugglex",
				Kind:            "http-request-smuggling",
				Severity:        severity,
				Confidence:      confidence,
				InsertionPoint:  row.InsertionPoint,
				Method:          result.Method,
				URL:             result.Target,
				Payload:         check.Payload,
				Evidence:        smugglexEvidence(check.NormalStatus, check.AttackStatus, check.NormalMS, check.AttackMS, check.Signals),
				DetectionMethod: "smugglex " + check.CheckType,
				InjectType:      check.CheckType,
			})
		}
	}

	// A scan where checks errored is not a clean scan, and the difference has to survive into the
	// results table rather than living only in a log nobody opens.
	if len(failed) > 0 {
		findings = append(findings, VectorFinding{
			VectorID:       row.ID,
			Tool:           "smugglex",
			Kind:           "scan-incomplete",
			Severity:       "info",
			Confidence:     "not a vulnerability: these checks did not run, so this URL is untested for them",
			InsertionPoint: row.InsertionPoint,
			Method:         row.Method,
			URL:            row.EvidenceURL,
			Evidence: "smugglex recorded " + itoa(len(failed)) + " check(s) as CHECK_FAILED: " +
				strings.Join(failed, "; ") + ". A failed check is stored as not vulnerable, so a run " +
				"in this state would otherwise read as clean.",
			DetectionMethod: "smugglex diagnostics",
		})
	}
	return findings
}

// smugglexGrade turns the tool's own confidence and signals into a severity and a sentence.
//
// A desync backed by a status or body difference is a real finding. One backed only by the
// connection timing out is the weakest thing this tool emits, and it is also the most common: an
// endpoint that simply stops answering when handed a malformed body produces it without any parser
// disagreeing with any other parser.
func smugglexGrade(confidence string, signals []string, normalStatus, attackStatus string) (severity, sentence string) {
	joined := strings.ToLower(strings.Join(signals, ","))
	timingOnly := strings.Contains(joined, "timeout") &&
		!strings.Contains(joined, "status_") &&
		!strings.Contains(joined, "divergence")

	switch {
	// A baseline that is itself a server error means the control request failed, so every comparison
	// drawn against it is unreliable, whatever the signals say.
	//
	// Measured against a CORRECTLY IMPLEMENTED control: a front-end that properly rejects a request
	// carrying both Content-Length and Transfer-Encoding closes its upstream, the next requests get
	// 502, and smugglex scores the difference as second_request_desync and reports the target
	// vulnerable. Doing the right thing is what produced the finding.
	// smugglex has no redirect support and no flag to add it: measured against a server answering
	// 301 to everything, all seven requests went to the original path and the redirect target was
	// never fetched. So a 3xx baseline means the whole check was run against a redirect stub, which
	// has no body, no back-end and nothing to desync.
	case isRedirect(normalStatus):
		return "low", "the baseline returned " + normalStatus + ", and smugglex does not follow " +
			"redirects, so these checks were run against the redirect itself rather than against the " +
			"application. Re-run against the URL the redirect points at."

	case isServerError(normalStatus):
		return "low", "the baseline request itself returned " + normalStatus + ", so smugglex had no " +
			"working control to compare against and this comparison is unreliable. Measured: a " +
			"front-end that correctly rejects an ambiguous request drops its upstream connection, " +
			"the follow-up requests then differ, and that difference alone is reported as a desync. " +
			"Re-run against a healthy baseline before believing it."
	case strings.EqualFold(confidence, "high") && !timingOnly:
		return "high", "reported by smugglex at high confidence, backed by a difference in the " +
			"response itself rather than only in how long it took. Worth confirming by hand before reporting."
	case timingOnly:
		return "low", "reported by smugglex at " + smugglexConfidenceText(confidence) + " confidence, evidenced " +
			"ONLY by the connection timing out. An endpoint that hangs on a malformed body produces " +
			"this without any desync existing, and on a lab with a single desync five separate checks " +
			"reported it. Treat as a lead, not a finding."
	default:
		return "medium", "reported by smugglex at " + smugglexConfidenceText(confidence) + " confidence. Confirm by " +
			"hand: the check name is the probe that fired, not necessarily the class of the bug."
	}
}

func smugglexEvidence(normalStatus, attackStatus string, normalMS, attackMS *float64, signals []string) string {
	var parts []string
	if normalStatus != "" {
		parts = append(parts, "baseline "+normalStatus)
	}
	if attackStatus != "" {
		parts = append(parts, "attack "+attackStatus)
	}
	if normalMS != nil && attackMS != nil {
		parts = append(parts, "took "+msText(*normalMS)+" then "+msText(*attackMS))
	}
	if len(signals) > 0 {
		parts = append(parts, "signals: "+strings.Join(signals, ", "))
	}
	return strings.Join(parts, "; ")
}

// parseHTTP2SmuglReport reads the CSV written by --csv-log.
//
// The columns, verbatim from the header row:
//
//	target,http_method,detect_method,padding_method,smuggling_method,smuggling_variant,result
//
// result is one of three values, from the tool's own DetectResult.String(): "indistinguishable",
// "distinguishable by timing", "distinguishable not by timing". Only the last two are findings, and
// they are not equal: the source classes a pair as distinguishable BY TIMING when one of the two
// response sets contains nothing but timeouts, so an unresponsive target produces it on its own.
func parseHTTP2SmuglReport(stdout, report string, row vectorRow) []VectorFinding {
	reader := csv.NewReader(strings.NewReader(strings.TrimSpace(report)))
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil || len(records) < 2 {
		return nil
	}

	index := map[string]int{}
	for i, name := range records[0] {
		index[strings.TrimSpace(name)] = i
	}
	column := func(row []string, name string) string {
		if i, ok := index[name]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}

	// http2smugl runs a control alongside the real techniques: rows whose smuggling_method is "no
	// header smuggling" apply no mutation at all. If THOSE come back distinguishable, the target's
	// own responses vary from one request to the next, and every timing-based verdict on it is
	// measuring that variance rather than a parsing difference. Measured on a real downgrade lab,
	// where the control row was reported distinguishable by timing alongside the genuine findings.
	controlUnstable := false
	for _, record := range records[1:] {
		if strings.EqualFold(column(record, "smuggling_method"), "no header smuggling") &&
			strings.Contains(strings.ToLower(column(record, "result")), "distinguishable") &&
			!strings.Contains(strings.ToLower(column(record, "result")), "indistinguishable") {
			controlUnstable = true
			break
		}
	}

	var findings []VectorFinding
	seen := map[string]bool{}
	for _, record := range records[1:] {
		result := strings.ToLower(column(record, "result"))
		if result == "" || result == "indistinguishable" {
			continue
		}

		method := column(record, "smuggling_method")
		// The control row is not a finding about smuggling. It is reported once, below, as the reason
		// to distrust the timing-based verdicts.
		if strings.EqualFold(method, "no header smuggling") {
			continue
		}
		variant := column(record, "smuggling_variant")
		detect := column(record, "detect_method")

		// One finding per smuggling technique rather than per probe: 285 probes per target means the
		// same technique appears many times over with different padding and verbs, and a results table
		// with two hundred identical rows is a table nobody reads.
		key := method + "|" + result
		if seen[key] {
			continue
		}
		seen[key] = true

		byTimingOnly := strings.Contains(result, "by timing") && !strings.Contains(result, "not by timing")
		severity := "medium"
		confidence := "http2smugl found the valid and invalid variants distinguishable by something " +
			"other than timing, which is its stronger signal. It still means the front-end treated a " +
			"malformed HTTP/2 header as meaningful, not that a request was smuggled end to end: " +
			"confirm by hand."
		if byTimingOnly {
			severity = "low"
			confidence = "http2smugl found the variants distinguishable ONLY by timing. Its own logic " +
				"returns this when one set of responses is nothing but timeouts, so a slow or " +
				"unresponsive target produces it without any parsing difference existing."
			if controlUnstable {
				confidence += " On this target the control probe, which applies no smuggling at all, " +
					"was ALSO reported distinguishable, so the responses vary on their own and this " +
					"verdict is measuring that variance."
			}
		}

		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "http2smugl",
			Kind:            "h2-downgrade-smuggling",
			Severity:        severity,
			Confidence:      confidence,
			InsertionPoint:  row.InsertionPoint,
			Method:          column(record, "http_method"),
			URL:             column(record, "target"),
			Payload:         variant,
			Evidence:        detect + " / " + method + " / " + variant + " -> " + column(record, "result"),
			DetectionMethod: "http2smugl " + detect,
			InjectType:      method,
		})
	}

	if controlUnstable {
		findings = append(findings, VectorFinding{
			VectorID:       row.ID,
			Tool:           "http2smugl",
			Kind:           "unstable-baseline",
			Severity:       "info",
			Confidence:     "not a vulnerability: a note on how much the timing verdicts above are worth",
			InsertionPoint: row.InsertionPoint,
			Method:         row.Method,
			URL:            row.EvidenceURL,
			Evidence: "http2smugl's own control probe, which applies no header smuggling at all, came " +
				"back distinguishable for this target. Its responses therefore vary between identical " +
				"requests, and any verdict here that rests only on timing is measuring that variance " +
				"rather than a parsing difference.",
			DetectionMethod: "http2smugl control probe",
		})
	}
	return findings
}

// isServerError and isRedirect read a smugglex status string. The strings are whole status lines
// ("HTTP/1.1 502 Bad Gateway") or one of its own words ("Connection Timeout", "CHECK_FAILED"), so
// these look for the code rather than parsing.
func isServerError(status string) bool { return statusClassIs(status, '5') }
func isRedirect(status string) bool    { return statusClassIs(status, '3') }

func statusClassIs(status string, class byte) bool {
	for _, field := range strings.Fields(status) {
		if len(field) == 3 && field[0] == class &&
			field[1] >= '0' && field[1] <= '9' && field[2] >= '0' && field[2] <= '9' {
			return true
		}
	}
	return false
}

func firstOr(values []string, fallback string) string {
	if len(values) > 0 && strings.TrimSpace(values[0]) != "" {
		return values[0]
	}
	return fallback
}

func smugglexConfidenceText(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unstated"
	}
	return value
}

func msText(value float64) string {
	if value >= 1000 {
		return strconv.FormatFloat(value/1000, 'f', 1, 64) + "s"
	}
	return strconv.FormatFloat(value, 'f', 0, 64) + "ms"
}
