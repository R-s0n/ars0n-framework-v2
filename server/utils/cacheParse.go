package utils

import (
	"encoding/json"
	"strings"
)

// Reading what the two cache scanners produced.
//
// They disagree about almost everything, including what counts as a finding, so the differences are
// preserved rather than flattened. WCVS verifies that a poisoned response came back FROM THE CACHE
// on a second, clean request, and hands over the two curl commands that prove it. CacheBoom's
// poisoning mode does not: its condition is
//
//	if (cache_miss_seen and value in body) or value in body:
//
// where the second clause makes the first dead code. A match means the header was reflected, which
// is where a cache poisoning investigation STARTS. Recording that as a vulnerability would put it
// beside WCVS's proven ones.

// wcvsReport is the shape of WCVS's --generatereport JSON.
type wcvsReport struct {
	FoundVulnerabilities bool `json:"foundVulnerabilities"`
	Websites             []struct {
		URL              string   `json:"url"`
		IsVulnerable     bool     `json:"isVulnerable"`
		HasError         bool     `json:"hasError"`
		CacheIndicator   string   `json:"cacheIndicator"`
		CacheBusterFound bool     `json:"cacheBusterFound"`
		CacheBuster      string   `json:"cacheBuster"`
		ErrorMessages    []string `json:"errorMessages"`
		Results          []struct {
			Technique     string   `json:"technique"`
			IsVulnerable  bool     `json:"isVulnerable"`
			HasError      bool     `json:"hasError"`
			ErrorMessages []string `json:"errorMessages"`
			Checks        []struct {
				Identifier  string   `json:"identifier"`
				Reason      string   `json:"reason"`
				Reflections []string `json:"reflections"`
				Request     struct {
					CurlCommand string `json:"curlCommand"`
				} `json:"request"`
				SecondRequest struct {
					CurlCommand string `json:"curlCommand"`
				} `json:"secondRequest"`
			} `json:"checks"`
		} `json:"results"`
	} `json:"websites"`
}

// parseWCVSReport turns the JSON report into findings.
//
// A run where no cache was found produces one INFORMATIONAL row rather than nothing. That is the
// whole point: measured against a lab whose poisoning is real, a run that failed to find a
// cachebuster reported zero techniques and exited 0, identically to a clean scan. Without this row
// the results screen cannot tell the operator which of the two happened.
func parseWCVSReport(stdout, report string, row vectorRow) []VectorFinding {
	var doc wcvsReport
	if json.Unmarshal([]byte(report), &doc) != nil {
		return nil
	}

	var findings []VectorFinding
	for _, site := range doc.Websites {
		if !site.CacheBusterFound || site.CacheIndicator == "" {
			findings = append(findings, VectorFinding{
				VectorID:       row.ID,
				Tool:           "wcvs",
				Kind:           "no-cache-detected",
				Severity:       "info",
				Confidence:     "not tested: WCVS found no cache on this URL, so it ran no poisoning tests. This is not a clean result",
				InsertionPoint: row.InsertionPoint,
				Method:         row.Method,
				URL:            site.URL,
				Evidence: "No cache indicator or working cachebuster was found. Turn on 'Test even " +
					"without a cache' to run the tests anyway, or set a cache header if you know the " +
					"one this site uses.",
				DetectionMethod: "cache detection",
			})
			continue
		}

		for _, result := range site.Results {
			if !result.IsVulnerable {
				continue
			}
			for _, check := range result.Checks {
				// Both curl commands, because the pair IS the proof: the first plants the payload, the
				// second is an ordinary request that gets it back. One without the other is a
				// reflection.
				request := check.Request.CurlCommand
				if check.SecondRequest.CurlCommand != "" {
					request += "\n\n# then, with no poisoning header, the cache serves it back:\n" +
						check.SecondRequest.CurlCommand
				}
				findings = append(findings, VectorFinding{
					VectorID:        row.ID,
					Tool:            "wcvs",
					Kind:            result.Technique,
					Severity:        cacheSeverityFor(result.Technique),
					Confidence:      "confirmed: the poisoned response was served back from the cache",
					InsertionPoint:  row.InsertionPoint,
					Param:           check.Identifier,
					Payload:         strings.Join(check.Reflections, " "),
					Method:          row.Method,
					URL:             site.URL,
					Evidence:        check.Reason,
					DetectionMethod: "cache " + strings.ToLower(result.Technique),
					RawRequest:      request,
				})
			}
		}
	}
	return findings
}

// parseCacheBoomOutput reads CacheBoom's stdout.
//
// stdout rather than the report file, because -o is only wired up for the poisoning mode: scanner.py
// calls scan_cd without the output argument, so a deception run writes no file at all. Parsing the
// file would silently lose every deception finding.
func parseCacheBoomOutput(stdout, report string, row vectorRow) []VectorFinding {
	text := stripANSI(stdout)
	var findings []VectorFinding
	seen := map[string]bool{}

	lines := strings.Split(text, "\n")
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Poisoning: "[+] [VULNERABLE] | URL: ... | Header: X-Forwarded-Host | Payload: cacheboom.com"
		if strings.Contains(trimmed, "[VULNERABLE]") {
			header := betweenWords(trimmed, "Header: ", " |")
			if header == "" || seen["cp:"+header] {
				continue
			}
			seen["cp:"+header] = true
			findings = append(findings, VectorFinding{
				VectorID: row.ID,
				Tool:     "cacheboom",
				Kind:     "header-reflection",
				Severity: "medium",
				// Deliberately not called a poisoning. CacheBoom never checks that the response came
				// from the cache: the cache-hit half of its condition is unreachable behind an or.
				Confidence: "unconfirmed: the header was reflected, but CacheBoom does not verify that " +
					"the response was cached. Confirm with WCVS before reporting it",
				InsertionPoint:  row.InsertionPoint,
				Param:           header,
				Payload:         "cacheboom.com",
				Method:          row.Method,
				URL:             betweenWords(trimmed, "URL: ", " |"),
				Evidence:        trimmed,
				DetectionMethod: "reflection",
			})
			continue
		}

		// Deception: a multi-line block whose second request URL carries the appended extension. This
		// check DOES require a cache miss header, so it is recorded as confirmed.
		if strings.Contains(trimmed, "[+] Vulnerable:") {
			payload, second := "", ""
			for _, follow := range lines[i:min(i+8, len(lines))] {
				f := strings.TrimSpace(stripANSI(follow))
				if strings.Contains(f, "Payload: ") {
					payload = betweenWords(f, "Payload: ", "\n")
				}
				if strings.HasPrefix(f, "URL: ") && payload != "" {
					second = strings.TrimSpace(strings.TrimPrefix(f, "URL: "))
				}
			}
			// Keyed on the EXTENSION, not the payload. CacheBoom names each probe with four random
			// characters, so 8ENS.jpg and bYLx.jpg are the same finding reported twice and a URL that
			// caches four extensions produced eight rows. What an operator needs is which extensions
			// the cache stores, because a cache that only stores .css is a narrower bug than one that
			// stores anything.
			extension := payload
			if dot := strings.LastIndex(payload, "."); dot >= 0 {
				extension = payload[dot:]
			}
			// Keyed on the extension ALONE. Keying on the probe URL would not dedupe at all, because
			// the random filename is part of it and every probe is therefore unique.
			if seen["cd:"+extension] {
				continue
			}
			seen["cd:"+extension] = true
			findings = append(findings, VectorFinding{
				VectorID:       row.ID,
				Tool:           "cacheboom",
				Kind:           "web-cache-deception",
				Severity:       "high",
				Confidence:     "confirmed: the same response was returned for an appended static path and the response was cacheable",
				InsertionPoint: row.InsertionPoint,
				Param:          extension,
				Payload:        payload,
				Method:         row.Method,
				URL:            second,
				Evidence: "Appending a " + extension + " path returned the same status and content " +
					"length as the original URL (probe " + payload + "), and the response was reported " +
					"as a cache miss, meaning it was stored.",
				DetectionMethod: "path confusion",
			})
		}
	}
	return findings
}

// cacheSeverityFor grades by what the technique actually gets an attacker.
//
// Deception hands over another user's response, which is a data breach with no interaction required.
// Poisoning through an unkeyed header serves attacker content to everyone. A denial of service
// through the cache is disruptive rather than a disclosure, and request smuggling findings from a
// cache scanner are a lead for a dedicated tool rather than a conclusion.
func cacheSeverityFor(technique string) string {
	t := strings.ToLower(technique)
	switch {
	case strings.Contains(t, "deception"):
		return "critical"
	case strings.Contains(t, "header"), strings.Contains(t, "forward"), strings.Contains(t, "parameter"):
		return "high"
	case strings.Contains(t, "fat get"), strings.Contains(t, "cloaking"), strings.Contains(t, "pollution"):
		return "high"
	case strings.Contains(t, "dos"):
		return "medium"
	case strings.Contains(t, "smuggling"), strings.Contains(t, "splitting"):
		return "medium"
	}
	return "medium"
}
