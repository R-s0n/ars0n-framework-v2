package utils

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
)

// Reading what the Miscellaneous tools produced.

var (
	// Measured from the report file Upload_Bypass writes, which is the trustworthy source. Its stdout
	// echoes the configured success message back in a "User Options" block before every module, and
	// matching on the word "success" anywhere would turn that echo into a finding on every run.
	uploadReportPattern = regexp.MustCompile(
		`(?i)file uploaded successfully with the extension:\s*b?['"]?([^'"\r\n]+)['"]?`)
	// The stdout form, used only when the report is missing.
	uploadStdoutPattern = regexp.MustCompile(
		`(?i)\[\+\]\s*file uploaded successfully with:\s*(\S+)`)
	uploadModulePattern = regexp.MustCompile(`(?im)^\s*Module:\s*(.+)$`)

	// jwt_tool prints one of these per forged token IT ACTUALLY SENT. The "Response Code" part is
	// what makes it a request rather than a decode: the offline form of the same line reads
	// `jwttool_<id> - EXPLOIT: "alg":"none" - this is an exploit targeting...` and never mentions a
	// response, because nothing was sent. Keying on this is what keeps an offline run, which forges
	// tokens perfectly happily with no server involved, from reporting authentication bypass.
	jwtResponsePattern = regexp.MustCompile(
		`^jwttool_[0-9a-f]+\s+(.*?)\s+Response Code:\s*(\d{3}),\s*(\d+) bytes`)
	// The canary hit, which is the only thing that says the server TREATED the forgery as valid.
	jwtCanaryPattern = regexp.MustCompile(`(?i)^\[\+\]\s*FOUND\s+(.*?)\s+in response`)
	// Measured: "[+] secret is the CORRECT key!"
	jwtCrackPattern = regexp.MustCompile(`(?i)^\[\+\]\s*(.+?)\s+is the CORRECT key`)
)

// parseUploadBypassOutput reads what Upload_Bypass proved.
//
// A bypass is only interesting because a file the server said it would refuse is now sitting on it,
// so the filename that got through is the finding.
func parseUploadBypassOutput(stdout, report string, row vectorRow) []VectorFinding {
	source := stripANSI(report)
	pattern := uploadReportPattern
	if strings.TrimSpace(source) == "" {
		source = stripANSI(stdout)
		pattern = uploadStdoutPattern
	}

	// The report is written as a block per success: the filename line, then Content-Type, then the
	// module that produced it. Splitting on the rule between blocks keeps a filename with its module.
	var findings []VectorFinding
	seen := map[string]bool{}
	for _, block := range strings.Split(source, "----------------") {
		match := pattern.FindStringSubmatch(block)
		if match == nil {
			continue
		}
		filename := strings.TrimSpace(match[1])
		if filename == "" || seen[filename] {
			continue
		}
		seen[filename] = true

		module := ""
		if found := uploadModulePattern.FindStringSubmatch(block); found != nil {
			module = strings.TrimSpace(found[1])
		}

		evidence := "Uploaded " + filename
		if module != "" {
			evidence += " using the " + module + " technique"
		}

		findings = append(findings, VectorFinding{
			VectorID: row.ID,
			Tool:     "upload-bypass",
			Kind:     "upload-restriction-bypass",
			Severity: "high",
			Confidence: "the server accepted a file it was meant to refuse, judged by the success " +
				"indicator you configured. Fetch the uploaded file to confirm it is really stored and " +
				"really served: an upload that is accepted but never reachable is a weaker finding " +
				"than one that executes.",
			InsertionPoint:  row.InsertionPoint,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Payload:         filename,
			Evidence:        evidence,
			DetectionMethod: "upload_bypass",
			InjectType:      module,
			IsGraphQLTarget: row.IsGraphQLTarget,
		})
	}
	return findings
}

// parseJWTToolOutput reads jwt_tool's stdout.
//
// The distinction that decides everything here is between what jwt_tool OBSERVED about a token and
// what a SERVER did with one. It will happily forge a valid-looking alg:none token with no network
// access at all, and printing that is not a finding. Only a line carrying a response separates the
// two, and only a canary hit turns "the server answered 200" into "the server accepted it".
func parseJWTToolOutput(stdout, report string, row vectorRow) []VectorFinding {
	lines := strings.Split(stripANSI(stdout), "\n")

	var findings []VectorFinding
	var unconfirmed []string
	seen := map[string]bool{}
	canaryPending := ""

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		if match := jwtCrackPattern.FindStringSubmatch(line); match != nil {
			if seen[line] {
				continue
			}
			seen[line] = true
			findings = append(findings, VectorFinding{
				VectorID: row.ID,
				Tool:     "jwt-tool",
				Kind:     "jwt-weak-secret",
				Severity: "critical",
				Confidence: "the signing secret was recovered, so any token can be forged with any " +
					"claims. This is arithmetic rather than an inference: the recovered key reproduces " +
					"the token's own signature.",
				InsertionPoint:  row.InsertionPoint,
				Method:          row.Method,
				URL:             row.EvidenceURL,
				Payload:         strings.TrimSpace(match[1]),
				Evidence:        "Signing key recovered: " + strings.TrimSpace(match[1]),
				DetectionMethod: "jwt_tool",
				IsGraphQLTarget: row.IsGraphQLTarget,
			})
			continue
		}

		// The canary line comes immediately before the line naming what was sent.
		if match := jwtCanaryPattern.FindStringSubmatch(line); match != nil {
			canaryPending = strings.TrimSpace(match[1])
			continue
		}

		match := jwtResponsePattern.FindStringSubmatch(line)
		if match == nil {
			canaryPending = ""
			continue
		}
		attack, code := strings.TrimSpace(match[1]), match[2]
		status, _ := strconv.Atoi(code)

		if canaryPending != "" {
			canary := canaryPending
			canaryPending = ""
			key := "confirmed|" + attack
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, VectorFinding{
				VectorID: row.ID,
				Tool:     "jwt-tool",
				Kind:     "jwt-accepted-forgery",
				Severity: "critical",
				Confidence: "a token this tool forged was accepted by the server: the response carried " +
					canary + ", which you named as appearing only when a request is authenticated. " +
					"That is authentication bypass rather than a weakness in the token's contents.",
				InsertionPoint: row.InsertionPoint,
				Method:         row.Method,
				URL:            row.EvidenceURL,
				Payload:        attack,
				Evidence: attack + " was accepted (HTTP " + code + ", canary " + canary +
					" present in the response)",
				DetectionMethod: "jwt_tool",
				InjectType:      attack,
				IsGraphQLTarget: row.IsGraphQLTarget,
			})
			continue
		}

		// A 2xx with no canary to check it against. Collected and reported once for the whole run
		// rather than once per attack, because an endpoint that answers 2xx to everything would
		// otherwise produce a screenful of identical criticals that all mean "we do not know".
		if status >= 200 && status < 300 && !seen["unconfirmed|"+attack] {
			seen["unconfirmed|"+attack] = true
			unconfirmed = append(unconfirmed, attack+" (HTTP "+code+", "+match[3]+" bytes)")
		}
	}

	if len(unconfirmed) > 0 {
		findings = append(findings, VectorFinding{
			VectorID: row.ID,
			Tool:     "jwt-tool",
			Kind:     "jwt-forgery-not-rejected",
			Severity: "medium",
			Confidence: "NOT confirmed. These forged tokens came back 2xx, but no canary value was " +
				"set, so this cannot tell an endpoint that accepted the forgery from one that answers " +
				"2xx to everything including a request carrying no token at all. Set a canary value " +
				"that appears only in an authenticated response and run it again for a real answer.",
			InsertionPoint:  row.InsertionPoint,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Evidence:        "Forgeries not rejected: " + strings.Join(unconfirmed, "; "),
			DetectionMethod: "jwt_tool",
			IsGraphQLTarget: row.IsGraphQLTarget,
		})
	}

	// Nothing was sent, or nothing came back interesting. The token itself is still worth recording:
	// which algorithm and which issuer is what an operator needs before deciding what to try next.
	if len(findings) == 0 {
		alg, issuer := describeJWT(row.RawRequest)
		if alg == "" {
			return nil
		}
		evidence := "Token uses alg " + alg
		if issuer != "" {
			evidence += ", issued by " + issuer
		}
		return []VectorFinding{{
			VectorID: row.ID,
			Tool:     "jwt-tool",
			Kind:     "jwt-observed",
			Severity: "info",
			Confidence: "not a vulnerability: this is what the token says about itself, and nothing " +
				"was confirmed against a server",
			InsertionPoint:  row.InsertionPoint,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Evidence:        evidence + ". " + truncateSecret(row.RawRequest),
			DetectionMethod: "jwt_tool",
			InjectType:      alg,
			IsGraphQLTarget: row.IsGraphQLTarget,
		}}
	}

	_ = report
	return findings
}

// pphackResult is one line of pphack's -j output.
//
// The field names are pphack's own Go struct names rather than lower-case JSON keys, because it
// marshals its struct without tags. Measured on v0.1.4:
//
//	{"TargetURL":"http://host/?a=b","ScanURL":"http://host/?__proto__[x]=x","JSEvaluation":"1|2|3"}
//
// Guessing url/payload/gadget here would unmarshal to an empty struct, every result would fail the
// emptiness check below, and a vulnerable target would report clean.
type pphackResult struct {
	TargetURL    string `json:"TargetURL"`
	ScanURL      string `json:"ScanURL"`
	JSEvaluation string `json:"JSEvaluation"`
}

// parsePphackOutput reads the JSON pphack writes to stdout.
//
// A hit means the page's own JavaScript merged attacker input into Object.prototype, which pphack
// watched happen in a real browser rather than inferring it from a response body. That makes it a
// stronger signal than most scanners produce, but it is still a primitive rather than an impact:
// what the pollution reaches decides whether it is worth reporting.
func parsePphackOutput(stdout, report string, row vectorRow) []VectorFinding {
	source := stdout
	if strings.TrimSpace(report) != "" {
		source = report
	}

	var findings []VectorFinding
	seen := map[string]bool{}
	for _, line := range strings.Split(stripANSI(source), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var result pphackResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		if strings.TrimSpace(result.ScanURL) == "" || seen[result.ScanURL] {
			continue
		}
		seen[result.ScanURL] = true

		evidence := "Object.prototype was polluted by " + result.ScanURL
		if result.JSEvaluation != "" {
			evidence += " (the injected value " + result.JSEvaluation +
				" was readable back off the prototype)"
		}

		url := result.TargetURL
		if strings.TrimSpace(url) == "" {
			url = row.EvidenceURL
		}

		findings = append(findings, VectorFinding{
			VectorID: row.ID,
			Tool:     "pphack",
			Kind:     "client-side-prototype-pollution",
			Severity: "high",
			Confidence: "pphack loaded the page in a real browser and read the injected value back off " +
				"Object.prototype, so the pollution itself is proven rather than inferred. What it " +
				"REACHES decides the impact: find a gadget that turns the polluted property into " +
				"script execution before reporting this as XSS, because pollution with no gadget " +
				"behind it is usually low.",
			InsertionPoint:  row.InsertionPoint,
			Method:          "GET",
			URL:             url,
			Payload:         result.ScanURL,
			Evidence:        evidence,
			DetectionMethod: "pphack",
			InjectType:      result.JSEvaluation,
		})
	}
	return findings
}

// base64URLDecode decodes a JWT segment, which is base64url with the padding stripped.
func base64URLDecode(segment string) ([]byte, error) {
	if padding := len(segment) % 4; padding != 0 {
		segment += strings.Repeat("=", 4-padding)
	}
	return base64.URLEncoding.DecodeString(segment)
}
