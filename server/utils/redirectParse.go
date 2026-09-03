package utils

import (
	"encoding/json"
	"strings"
)

// Reading what the open redirect and SSRF tools produced.

// nucleiDastFinding is one line of nuclei's -jsonl output. The fuzzing fields are the useful part:
// they say which parameter, in which position, with which method, so a finding attaches to the
// vector that named it rather than to the URL in general.
type nucleiDastFinding struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string   `json:"name"`
		Severity string   `json:"severity"`
		Tags     []string `json:"tags"`
	} `json:"info"`
	Host             string   `json:"host"`
	MatchedAt        string   `json:"matched-at"`
	ExtractedResults []string `json:"extracted-results"`
	Request          string   `json:"request"`
	Response         string   `json:"response"`
	CurlCommand      string   `json:"curl-command"`
	FuzzingParameter string   `json:"fuzzing_parameter"`
	FuzzingPosition  string   `json:"fuzzing_position"`
	FuzzingMethod    string   `json:"fuzzing_method"`

	// MatcherName and MatcherStatus are only emitted when -ms is set, and MatcherStatus is FALSE for
	// a probe that matched NOTHING. A pointer rather than a bool so that "absent", which is what an
	// ordinary run produces because it reports only matches, is not read as false.
	MatcherName   string `json:"matcher-name"`
	MatcherStatus *bool  `json:"matcher-status"`
}

// parseNucleiDastReport turns nuclei's jsonl into findings.
//
// One per template-and-parameter rather than per line: nuclei reports the same open redirect twice
// when two user agents both matched, and two identical rows is a wall rather than a finding.
func parseNucleiDastReport(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding
	seen := map[string]bool{}

	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var doc nucleiDastFinding
		if json.Unmarshal([]byte(line), &doc) != nil || doc.TemplateID == "" {
			continue
		}

		// A NON-MATCH is not a finding. The Show matcher status setting (-ms) makes nuclei emit a
		// line for every probe it sends, including every one that matched nothing, and those lines
		// carry a template id like any other. Without this check each one became a high severity
		// finding: a 53 vector run produced 53 of them, all with an empty parameter, an empty URL and
		// an empty payload, because a non-match has no parameter, URL or payload to report.
		//
		// That is the mirror image of a silent clean and it is worse: a real open redirect would have
		// been one indistinguishable row among 52 fabricated ones.
		if doc.MatcherStatus != nil && !*doc.MatcherStatus {
			continue
		}

		key := doc.TemplateID + "|" + doc.FuzzingParameter
		if seen[key] {
			continue
		}
		seen[key] = true

		kind, confidence := redirectKindFor(doc.TemplateID)
		findings = append(findings, VectorFinding{
			VectorID:       row.ID,
			Tool:           "nuclei-dast",
			Kind:           kind,
			Severity:       strings.ToLower(doc.Info.Severity),
			Confidence:     confidence,
			InsertionPoint: row.InsertionPoint,
			Param:          doc.FuzzingParameter,
			Method:         doc.FuzzingMethod,
			URL:            doc.MatchedAt,
			Evidence:       doc.Info.Name + " in the " + doc.FuzzingPosition + " parameter " + doc.FuzzingParameter,
			// nuclei's own position is preserved as the detection method rather than overwriting ours,
			// so a disagreement between what we asked for and what it fuzzed stays visible.
			DetectionMethod: "nuclei " + doc.TemplateID + " (" + doc.FuzzingPosition + ")",
			InjectType:      doc.TemplateID,
			RawRequest:      doc.Request,
			RawResponse:     doc.Response,
		})
	}
	return findings
}

// redirectKindFor names what a template actually demonstrated.
//
// The distinction that matters: response-ssrf proved the server FETCHED something and handed the
// content back, which needs no callback and is a complete finding on its own. blind-ssrf proved a
// callback arrived, which is equally real but arrives through a third-party server this project does
// not control, and that server is currently returning interaction data this nuclei build cannot
// decrypt. An operator should know which of the two they are looking at.
func redirectKindFor(templateID string) (kind, confidence string) {
	switch templateID {
	case "response-ssrf":
		return "ssrf", "confirmed: the server fetched the supplied URL and the response came back, " +
			"so no callback server was involved"
	case "blind-ssrf":
		return "blind-ssrf", "confirmed by an out-of-band callback to interactsh. Re-check it: this " +
			"nuclei build has been seen failing to decrypt interaction data from the public servers"
	case "open-redirect":
		return "open-redirect", "confirmed: the Location header pointed at the supplied host"
	case "open-redirect-bypass":
		return "open-redirect", "confirmed, through a payload shaped to get past validation"
	}
	return templateID, "reported by nuclei"
}

// parseREcollapseOutput reads the mutations REcollapse printed.
//
// It produces no findings of its own, because it sends nothing: it is a list of candidate payloads.
// The runner replays them and records what actually bypassed, which is where the findings come from.
func parseREcollapseOutput(stdout, report string, row vectorRow) []VectorFinding {
	// The replay findings arrive through the report file the runner writes, in the same jsonl shape
	// the rest of this file reads. Anything on stdout is the raw mutation list.
	var findings []VectorFinding
	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var doc struct {
			Mutation string `json:"mutation"`
			Location string `json:"location"`
			Status   int    `json:"status"`
			Param    string `json:"param"`
			URL      string `json:"url"`
			Request  string `json:"request"`
			Response string `json:"response"`
		}
		if json.Unmarshal([]byte(line), &doc) != nil || doc.Mutation == "" {
			continue
		}
		findings = append(findings, VectorFinding{
			VectorID:       row.ID,
			Tool:           "recollapse",
			Kind:           "validation-bypass",
			Severity:       "medium",
			Confidence:     "confirmed: the mutated value was accepted and the redirect landed on the canary host",
			InsertionPoint: row.InsertionPoint,
			Param:          doc.Param,
			Payload:        doc.Mutation,
			Method:         row.Method,
			URL:            doc.URL,
			Evidence: "The value " + doc.Mutation + " got past validation and produced a " +
				itoa(doc.Status) + " to " + doc.Location + ".",
			DetectionMethod: "recollapse mutation replay",
			RawRequest:      doc.Request,
			RawResponse:     doc.Response,
		})
	}
	return findings
}

// parseSSRFmapOutput reads SSRFmap's stdout.
//
// SSRFmap prints per module and has no machine-readable output, so its lines are matched on their
// wording. Everything it reports is recorded as an EXPLOITATION result rather than a detection,
// because SSRFmap never checks whether the parameter was vulnerable in the first place: it was told
// so by the finding this run was based on.
func parseSSRFmapOutput(stdout, report string, row vectorRow) []VectorFinding {
	text := stripANSI(stdout)
	var findings []VectorFinding
	seen := map[string]bool{}

	// SSRFmap writes its progress and its results to the same stream, and the progress is most of it:
	// one "Checking port n°NNNN" per port per address, all on ONE line separated by tabs, which is
	// why the fields are split on tabs rather than newlines. A 438KB run against a single host
	// contained exactly one result line.
	//
	// The matcher is deliberately narrow. An earlier version matched "found", "service" and
	// "retrieved" and reported the progress chatter as findings, because those words appear in it.
	fields := strings.FieldsFunc(text, func(r rune) bool { return r == '\n' || r == '\t' })
	for _, line := range fields {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		// "IP:127.0.0.1   , Found open      port n°8000" is a result. "Checking port n°80" is not.
		interesting := strings.Contains(lower, "found open") ||
			strings.Contains(lower, "is open") ||
			strings.Contains(lower, "root:x:") ||
			strings.Contains(lower, "retrieved file") ||
			strings.Contains(lower, "credentials")
		if !interesting || trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		findings = append(findings, VectorFinding{
			VectorID: row.ID,
			Tool:     "ssrfmap",
			Kind:     "ssrf-exploitation",
			// High rather than critical: what this proves is that the SSRF reaches internal services,
			// which is the impact of a vulnerability the detector already found rather than a new one.
			Severity:        "high",
			Confidence:      "reached through the SSRF the detector already confirmed on this vector",
			InsertionPoint:  row.InsertionPoint,
			Param:           markableParam(row.toInput()),
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Evidence:        trimmed,
			DetectionMethod: "ssrfmap",
		})
	}
	return findings
}

func itoa(n int) string {
	return stringifySetting(float64(n))
}
