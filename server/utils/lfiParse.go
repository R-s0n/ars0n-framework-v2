package utils

import "strings"

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
			VectorID:       row.ID,
			Tool:           "lfimap",
			Kind:           technique,
			Severity:       severity,
			Confidence:     "confirmed by LFImap: the file it asked for came back",
			InsertionPoint: row.InsertionPoint,
			Param:          strings.Join(row.Parameters, ","),
			Payload:        payload,
			Method:         row.Method,
			URL:            row.EvidenceURL,
			Evidence:       line,
			DetectionMethod: "lfimap " + technique,
		})
	}
	return findings
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
