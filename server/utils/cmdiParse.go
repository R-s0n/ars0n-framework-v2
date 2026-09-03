package utils

import (
	"encoding/json"
	"strings"
)

// Reading what the three injection scanners produced.
//
// Only TInjA has a machine-readable report. commix and SSTImap print their results and nothing else,
// so their findings are matched on the wording they use, and the wording is quoted in each function
// so a future version that changes it can be compared against what was actually seen.

// parseCommixOutput reads commix's stdout.
//
// The line that matters reads, verbatim:
//
//	[info] GET parameter 'name' appears to be injectable via (results-based) classic command
//	injection technique.
//
// with "Cookie parameter", "POST parameter" and "HTTP Header parameter" as the other observed
// openings. A command injection is remote code execution, so anything confirmed here is critical.
func parseCommixOutput(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding
	seen := map[string]bool{}

	for _, line := range strings.Split(stripANSI(stdout), "\n") {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "appears to be injectable") {
			continue
		}

		// "GET parameter 'name' appears to be injectable via (results-based) classic ..."
		param := betweenWords(line, "'", "'")
		technique := strings.TrimSpace(betweenWords(line, "injectable via ", " technique"))
		if technique == "" {
			technique = "command injection"
		}
		if seen[param+technique] {
			continue
		}
		seen[param+technique] = true

		findings = append(findings, VectorFinding{
			VectorID: row.ID,
			Tool:     "commix",
			Kind:     technique,
			// Command injection is arbitrary code execution on the host. There is no version of this
			// that is not the most serious thing in the report.
			Severity:   "critical",
			Confidence: "confirmed by commix",
			// From the VECTOR, not from commix's own wording. It reports a marked cookie as a Cookie
			// parameter but a path injection as a GET parameter, and filing that under query would be
			// wrong in the way dalfox's cookie labelling was.
			InsertionPoint:  row.InsertionPoint,
			Param:           param,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Evidence:        line,
			DetectionMethod: "commix " + technique,
			InjectType:      "os-command",
		})
	}
	return findings
}

// parseSSTImapOutput reads SSTImap's stdout.
//
// Its result block reads:
//
//	[+] SSTImap identified the following injection point:
//	  Query parameter: name
//	  Engine: Jinja2
//	  Injection: ...
//	  Context: text
//	  OS: linux
//	  Technique: render
//	  Capabilities: ...
//
// The engine name is the useful part: "Jinja2" tells an operator which payloads and which sandbox
// escape to reach for, and it is the thing tplmap's successor exists to work out.
func parseSSTImapOutput(stdout, report string, row vectorRow) []VectorFinding {
	text := stripANSI(stdout)
	if !strings.Contains(text, "identified the following injection point") {
		return nil
	}

	engine, technique, context, capabilities, point := "", "", "", "", ""
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "Engine:"):
			engine = strings.TrimSpace(strings.TrimPrefix(trimmed, "Engine:"))
		case strings.HasPrefix(trimmed, "Technique:"):
			technique = strings.TrimSpace(strings.TrimPrefix(trimmed, "Technique:"))
		case strings.HasPrefix(trimmed, "Context:"):
			context = strings.TrimSpace(strings.TrimPrefix(trimmed, "Context:"))
		case strings.HasPrefix(trimmed, "Capabilities:"):
			capabilities = strings.TrimSpace(strings.TrimPrefix(trimmed, "Capabilities:"))
		case strings.Contains(trimmed, "parameter:"):
			point = strings.TrimSpace(betweenWords(trimmed, "parameter:", "\n"))
		}
	}
	if engine == "" {
		engine = "unknown engine"
	}
	if point == "" {
		point = strings.Join(row.Parameters, ",")
	}

	evidence := "SSTImap identified " + engine
	if context != "" {
		evidence += " in a " + context + " context"
	}
	if capabilities != "" {
		evidence += ". Capabilities: " + capabilities
	}

	return []VectorFinding{{
		VectorID: row.ID,
		Tool:     "sstimap",
		Kind:     "template-injection",
		// Server-side template injection reaches code execution on most engines, and SSTImap reports
		// which capabilities it actually confirmed, which is quoted in the evidence.
		Severity:        "critical",
		Confidence:      "confirmed by SSTImap, engine " + engine,
		InsertionPoint:  row.InsertionPoint,
		Param:           point,
		Payload:         technique,
		Method:          row.Method,
		URL:             row.EvidenceURL,
		Evidence:        evidence,
		DetectionMethod: "sstimap " + technique,
		InjectType:      engine,
	}}
}

// tinjaReport is one line of TInjA's JSONL. The first line is a run summary and carries no id or
// parameters; the rest are one per URL.
type tinjaReport struct {
	ID                  int    `json:"id"`
	URL                 string `json:"url"`
	IsWebpageVulnerable bool   `json:"isWebpageVulnerable"`
	Certainty           string `json:"certainty"`
	Default             struct {
		StatusCode int    `json:"statusCode"`
		Request    string `json:"request"`
		Response   string `json:"response"`
	} `json:"default"`
	Parameters []struct {
		Name                  string   `json:"name"`
		Type                  string   `json:"type"`
		DefaultValues         []string `json:"defaultValues"`
		IsParameterVulnerable bool     `json:"isParameterVulnerable"`
		Certainty             string   `json:"certainty"`
		IdentifiedEngine      string   `json:"identifiedEngine"`
		Reflections           []struct {
			ReflectionType string `json:"ReflectionType"`
			Preceding      string `json:"Preceding"`
			Subsequent     string `json:"Subsequent"`
		} `json:"reflections"`
	} `json:"parameters"`
}

// parseTInjAReport reads TInjA's JSONL report, one finding per vulnerable parameter.
//
// The certainty is kept as TInjA states it. It grades Very High down to Very Low, and a Very Low is
// a polyglot that produced a suspicious response rather than an engine it could name, so flattening
// them all to "vulnerable" would put a guess next to a confirmed Jinja2 sandbox.
func parseTInjAReport(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding

	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var doc tinjaReport
		if json.Unmarshal([]byte(line), &doc) != nil || len(doc.Parameters) == 0 {
			continue
		}

		for _, p := range doc.Parameters {
			if !p.IsParameterVulnerable {
				continue
			}
			engine := p.IdentifiedEngine
			if engine == "" {
				engine = "unidentified engine"
			}
			var context string
			if len(p.Reflections) > 0 {
				context = " reflected in the " + strings.ToLower(p.Reflections[0].ReflectionType)
			}
			findings = append(findings, VectorFinding{
				VectorID:       row.ID,
				Tool:           "tinja",
				Kind:           "template-injection",
				Severity:       tinjaSeverityFor(p.Certainty),
				Confidence:     p.Certainty + " certainty, engine " + engine,
				InsertionPoint: row.InsertionPoint,
				Param:          p.Name,
				Payload:        strings.Join(p.DefaultValues, ","),
				Method:         row.Method,
				URL:            doc.URL,
				Evidence: "TInjA identified " + engine + " in the " + strings.ToLower(p.Type) +
					" parameter " + p.Name + context + ".",
				DetectionMethod: "tinja polyglot",
				InjectType:      engine,
				// doc.Default is TInjA's UNPAYLOADED BASELINE PROBE, not the request that found this.
				// Storing it made every TInjA finding classify as CAPTURED, the strongest evidence
				// class, while carrying bytes that prove nothing. A real stored row: a POST-body
				// finding on parameter "email" carried
				//   raw_request  "GET /api/Users HTTP/1.1 / User-Agent: TInjA v1.2.0"
				// with no body, no payload and no credentials, and raw_response "HTTP/1.1 400 Bad
				// Request". Because RawRequest was non-empty, withFindingEvidence returned early and
				// no reconstruction was ever composed, so the finding could not be triaged at all.
				//
				// TInjA's report carries no per-finding request, so the honest answer is to store
				// NOTHING here and let the framework compose a request from the vector and mark it
				// COMPOSED. A composed request an operator can send beats a captured one that is
				// about a different request.
				RawRequest:  "",
				RawResponse: "",
			})
		}
	}
	return findings
}

// tinjaSeverityFor maps TInjA's certainty onto severity.
//
// A named engine at Very High certainty is a confirmed template injection, which on most engines is
// code execution. Below that TInjA is reporting that a polyglot disturbed the response without
// being able to say which engine did it, and that is a lead.
func tinjaSeverityFor(certainty string) string {
	switch strings.ToLower(strings.TrimSpace(certainty)) {
	case "very high":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	}
	return "low"
}
