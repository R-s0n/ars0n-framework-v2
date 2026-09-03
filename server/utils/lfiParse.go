package utils

import (
	"strconv"
	"strings"
)

// Reading what the two file-inclusion tools produced.
//
// Neither has a machine-readable report, so both are matched on wording, and the wording is quoted
// here so a future version that changes it can be compared against what was actually seen.

// parseLFImapOutput reads LFImap's stdout.
//
// The line that matters reads, verbatim, with -nc so there are no escape codes in it:
//
//	[+] LFI -> 'http://php.lab.test/index.php?file=php%3A%2F%2Ffilter%2Fresource%3D%2Fetc%2Fpasswd'
//
// and for a body vector:
//
//	[+] LFI -> 'http://host/index.php' -> HTTP POST -> 'file=php%3A%2F%2F...'
//
// A file inclusion on a PHP target reaches code execution through the wrappers, so a confirmed one
// is critical; the traversal technique proves a file read, which is high rather than critical, and
// the two are told apart by the payload that produced them.
func parseLFImapOutput(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding
	seen := map[string]bool{}

	for _, line := range strings.Split(stripANSI(stdout), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[+]") {
			continue
		}
		// "[+] Vulnerabilities found: 1" is a tally, not a finding.
		if strings.Contains(strings.ToLower(line), "vulnerabilities found") {
			continue
		}

		payload := betweenWords(line, "'", "'")
		if payload == "" {
			payload = line
		}
		technique, severity := lfiTechniqueFor(line)
		if seen[technique+payload] {
			continue
		}
		seen[technique+payload] = true

		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "lfimap",
			Kind:            technique,
			Severity:        severity,
			Confidence:      "confirmed by LFImap: the file it asked for came back",
			InsertionPoint:  row.InsertionPoint,
			Param:           strings.Join(row.Parameters, ","),
			Payload:         payload,
			Method:          row.Method,
			URL:             row.EvidenceURL,
			Evidence:        line,
			DetectionMethod: "lfimap " + technique,
		})
	}
	return findings
}

// lfimapSummaryBanner is the line LFImap prints when it reaches the end of a run. Its ABSENCE is the
// signal, so the exact wording is quoted rather than paraphrased.
const lfimapSummaryBanner = "LFImap finished with execution."

// lfimapIncomplete reports whether a run sent NO PAYLOADS, so the runner records the vector as
// UNTESTED rather than clean.
//
// THE MEASUREMENT. On scan 991aaec6, 125 of 250 LFImap traces exited 255 having sent nothing, and the
// framework recorded ZERO error rows for them: all 125 were filed as clean. The statuses that caused
// the aborts were 401 x79, 400 x27, 403 x11, 404 x5, 406 x1. Reproduced inside the tool's own
// container against a listener that answers 401:
//
//	[-] Initial request yielded 401 response. Request might not be correctly specified. To
//	    force-continue specify '--http-ok 401' to treat it as expected.
//	exit 255, 0 requests after the first, no summary printed
//
// and against a closed port, which is WORSE because it exits ZERO:
//
//	[-] Previous request caused ConnectionError. ...
//	[-] Response object is not clearly received. ...
//	LFImap finished with execution. / Parameters tested: 0 / Requests sent: 1 / Vulnerabilities found: 0
//
// Exit 0 with no findings is indistinguishable from a clean scan, which is why the EXIT CODE IS NOT
// THE SIGNAL here. The counters are: a completed run of the default technique pair prints "Parameters
// tested: 1" and "Requests sent: 32", one preflight plus 31 payloads. "Requests sent: 1" means only
// the preflight went out, and "Parameters tested: 0" means nothing was ever marked.
//
// A missing banner is treated as incomplete too, which is the safe direction: a future LFImap that
// renames it makes every run report UNTESTED, which is noisy, where the other direction would make
// every run report clean, which is the defect this exists to close.
func lfimapIncomplete(stdout, report string) string {
	text := stripANSI(stdout)

	// A run that found something plainly ran. Checked first so a partially completed scan that
	// produced a finding is never thrown away as untested.
	if lfimapCounter(text, "Vulnerabilities found:") > 0 {
		return ""
	}

	abort := lfimapAbortReason(text)

	if !strings.Contains(text, lfimapSummaryBanner) {
		if abort != "" {
			return abort
		}
		return "LFImap never reached the end of its run: nothing in its output says how many " +
			"parameters were tested or how many requests were sent, so there is no evidence any " +
			"payload was delivered. The stored trace has what it printed before it stopped."
	}

	// Present and zero, which is different from absent.
	if params := lfimapCounter(text, "Parameters tested:"); params == 0 {
		if abort != "" {
			return abort
		}
		return "LFImap finished having tested 0 parameters, so no payload was ever placed. This " +
			"vector is untested, not clean."
	}
	if sent := lfimapCounter(text, "Requests sent:"); sent >= 0 && sent <= 1 {
		if abort != "" {
			return abort
		}
		return "LFImap sent " + strconv.Itoa(sent) + " request. Its first request is the preflight " +
			"that checks the target answers at all, so no payload left the container and this " +
			"vector is untested, not clean."
	}
	return ""
}

// lfimapAbortReason turns LFImap's own refusal into something with a remedy in it.
func lfimapAbortReason(text string) string {
	if strings.Contains(text, "Initial request yielded") {
		status := lfimapInitialStatus(text)
		reason := "LFImap sent its preflight request, got " + status + ", and exited without sending " +
			"a single payload. "
		if status == "401" || status == "403" {
			return reason + "That status says the scan is not authenticated for this endpoint. Add a " +
				"session token in the Session Manager, or a Cookies or Headers value in LFImap's " +
				"settings; if the endpoint really does answer " + status + " to everyone, put " +
				status + " in 'Status codes to treat as valid' to make it test the vector anyway."
		}
		return reason + "The preflight carries the literal marker as the value, so an endpoint that " +
			"rejects an unexpected value refuses it before any payload is tried. Put " + status +
			" in 'Status codes to treat as valid' to force this vector to be tested."
	}
	if strings.Contains(text, "No arguments to test") {
		return "LFImap found nothing to mark and exited without sending a payload. The marker did " +
			"not survive into the request it built, so this vector is untested, not clean."
	}
	if strings.Contains(text, "Response object is not clearly received") ||
		strings.Contains(text, "caused ConnectionError") {
		return "LFImap could not get a response out of the target at all, so no payload was tested. " +
			"This is a reachability failure, not a clean result."
	}
	return ""
}

// lfimapInitialStatus reads the status out of the abort line, so the remedy can name it. "an
// unexpected status" rather than a guess when the wording has moved on.
func lfimapInitialStatus(text string) string {
	after := betweenWords(text, "Initial request yielded", "response")
	for _, field := range strings.Fields(after) {
		if n, err := strconv.Atoi(field); err == nil && n >= 100 && n < 600 {
			return field
		}
	}
	return "an unexpected status"
}

// lfimapCounter reads one of the summary counters, or -1 when the line is not there. -1 rather than 0
// on purpose: absent and zero mean different things and only one of them is evidence.
func lfimapCounter(text, label string) int {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, label) {
			continue
		}
		if n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, label))); err == nil {
			return n
		}
	}
	return -1
}

// lfiTechniqueFor names what the payload actually demonstrated, and grades it accordingly.
//
// The distinction is worth keeping. php://filter reads a file back and is a disclosure; php://input,
// data:// and expect:// execute what they carry, which is remote code execution on a target that
// includes them. Reporting both as "LFI" would put a config-file read next to a shell.
func lfiTechniqueFor(line string) (technique, severity string) {
	lower := strings.ToLower(line)
	switch {
	case strings.Contains(lower, "input"), strings.Contains(lower, "expect"),
		strings.Contains(lower, "data%3a"), strings.Contains(lower, "data:"):
		return "lfi-to-rce", "critical"
	case strings.Contains(lower, "filter"):
		return "lfi-file-read", "high"
	case strings.Contains(lower, "rfi"):
		return "remote-file-inclusion", "critical"
	case strings.Contains(lower, "cmd"):
		return "command-injection", "critical"
	}
	return "lfi-file-read", "high"
}

// parseLFIHuntReport reads LFIHunt's OUTPUT FILE, not its stdout.
//
// stdout is progress bars, rewritten in place with escape codes and repeated fragments; the output
// file is one clean line per finding:
//
//	Vulnerable URL: http://host/index.php?file=test | Parameter: file | Checker: PHPFilterChecker
//
// The checker name is the useful part, because it says which mechanism worked and therefore what to
// try next by hand.
func parseLFIHuntReport(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding
	seen := map[string]bool{}

	for _, line := range strings.Split(stripANSI(report), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Vulnerable URL:") {
			continue
		}

		target := strings.TrimSpace(betweenWords(line, "Vulnerable URL:", "|"))
		param := strings.TrimSpace(betweenWords(line, "Parameter:", "|"))
		checker := strings.TrimSpace(betweenWords(line, "Checker:", "\n"))
		if checker == "" {
			checker = "unknown checker"
		}
		if seen[param+checker] {
			continue
		}
		seen[param+checker] = true

		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "lfihunt",
			Kind:            lfihuntKindFor(checker),
			Severity:        lfihuntSeverityFor(checker),
			Confidence:      "confirmed by LFIHunt's " + checker,
			InsertionPoint:  row.InsertionPoint,
			Param:           param,
			Method:          row.Method,
			URL:             target,
			Evidence:        line,
			DetectionMethod: "lfihunt " + checker,
			InjectType:      checker,
		})
	}
	return findings
}

// lfihuntKindFor and lfihuntSeverityFor read the checker name, which is the only thing LFIHunt says
// about how it got in.
//
// PHPInputExploiter and PHPPearCmdChecker reach code execution; the filter checkers read a file. A
// filter CHAIN is worse than a plain filter read, because the chain technique turns a read primitive
// into arbitrary content and is the usual route to execution on a modern PHP target.
func lfihuntKindFor(checker string) string {
	switch checker {
	case "PHPInputExploiter", "PHPPearCmdChecker":
		return "lfi-to-rce"
	case "PHPFilterChainGenerator":
		return "php-filter-chain"
	case "PHPFilterChecker":
		return "lfi-file-read"
	case "EnvironChecker":
		return "environ-inclusion"
	case "DataChecker":
		return "lfi-to-rce"
	case "LFIChecker":
		return "path-traversal"
	}
	return "lfi"
}

func lfihuntSeverityFor(checker string) string {
	switch checker {
	case "PHPInputExploiter", "PHPPearCmdChecker", "DataChecker", "PHPFilterChainGenerator":
		return "critical"
	case "EnvironChecker":
		return "high"
	}
	return "high"
}
