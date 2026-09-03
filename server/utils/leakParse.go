package utils

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Reading what the sensitive data leak tools produced.
//
// snallygaster reports findings directly. The two git tools do not: their result is a directory on
// disk, so the composer writes a manifest afterwards and this reads that. In both cases the finding
// worth reporting is not "a repository was exposed" but what came out of it.

// snallygasterFinding is one entry of the JSON array. Captured verbatim from a real run:
//
//	[{"cause": "dotenv", "url": "http://leak.lab.test/app/.env", "misc": ""}]
type snallygasterFinding struct {
	Cause string `json:"cause"`
	URL   string `json:"url"`
	Misc  string `json:"misc"`
}

// parseSnallygasterOutput reads the -j JSON array.
//
// An empty array is a genuine clean result here, unlike graphql-cop: snallygaster ran its tests and
// none of them matched. It exits 1 with "Test <name> does not exist" if given a name it does not
// know, so a bad test list fails loudly rather than scanning nothing.
func parseSnallygasterOutput(stdout, report string, row vectorRow) []VectorFinding {
	source := strings.TrimSpace(stripANSI(stdout))
	start := strings.Index(source, "[")
	if start < 0 {
		return nil
	}

	var results []snallygasterFinding
	if err := json.Unmarshal([]byte(source[start:]), &results); err != nil {
		return nil
	}

	var findings []VectorFinding
	seen := map[string]bool{}
	for _, result := range results {
		key := result.Cause + "|" + result.URL
		if seen[key] {
			continue
		}
		seen[key] = true

		severity, meaning := snallygasterGrade(result.Cause)
		evidence := result.URL
		if strings.TrimSpace(result.Misc) != "" {
			evidence += " (" + result.Misc + ")"
		}

		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "snallygaster",
			Kind:            "leak-" + result.Cause,
			Severity:        severity,
			Confidence:      meaning,
			InsertionPoint:  row.InsertionPoint,
			Method:          "GET",
			URL:             result.URL,
			Evidence:        evidence,
			DetectionMethod: "snallygaster " + result.Cause,
			InjectType:      result.Cause,
			IsLeakTarget:    row.IsLeakTarget,
		})
	}
	return findings
}

// snallygasterGrade turns the test name into a severity and a sentence.
//
// These are genuinely different things and flattening them would be misleading: an exposed .git is a
// route to the whole source tree and its history, while a stray .DS_Store is a directory listing in
// disguise. The ones that hand over credentials outright are separated from the ones that only
// describe the application.
func snallygasterGrade(cause string) (severity, meaning string) {
	switch cause {
	case "git_dir", "svn_dir":
		return "high", "the version control directory is served, so the source tree and its whole " +
			"history can be reconstructed. Run the recovery tools in this section against it."
	case "dotenv", "privatekey", "sshkey", "filezilla_xml", "winscp_ini", "wsftp_ini", "sftp_config",
		"rails_database_yml", "symfony_databases_yml", "drupaldb", "magento_config", "composer":
		return "high", "this file type normally contains credentials. Fetch it and check before reporting."
	case "coredump", "sql_dump", "backup_archive", "backupfiles", "drupal_backup_migrate", "duplicator":
		return "high", "a dump or backup is downloadable, which usually means data rather than just " +
			"configuration."
	case "apache_server_status", "apache_server_info", "phpinfo", "djangodebug", "symfonydebug",
		"wpdebug", "elmah", "telescope", "postdebug", "openelasticsearch", "openmonit", "adminer":
		return "medium", "a debug or status interface is reachable, which discloses configuration and " +
			"often internal paths, tokens or live requests."
	case "ds_store", "thumbsdb", "desktopini", "idea", "deadjoe":
		return "low", "an editor or operating system artefact, which leaks file names rather than " +
			"contents. Useful for finding the next thing to look at."
	case "optionsbleed", "cgiecho", "phpunit_eval", "citrix_rce", "lfm_php", "ilias_defaultpw":
		return "critical", "this is a known exploitable condition rather than an information leak. " +
			"Confirm by hand immediately."
	}
	return "medium", "snallygaster matched one of its checks for files that should not be served."
}

// parseGitDumperOutput and parseGitToolsOutput both read the manifest the composer wrote, because
// neither tool reports anything a parser can trust: both exit 0 whether they recovered a repository
// or found nothing, and their real output is a directory.
func parseGitDumperOutput(stdout, report string, row vectorRow) []VectorFinding {
	return parseGitManifest(stdout, report, row, "git-dumper")
}

func parseGitToolsOutput(stdout, report string, row vectorRow) []VectorFinding {
	return parseGitManifest(stdout, report, row, "gittools")
}

// parseGitManifest reads the sections the composer's manifest script writes.
//
// Success is FILECOUNT above zero, not the exit code. Measured: against a URL with no .git,
// git-dumper prints "responded with status code 404", exits 0, and leaves the output directory
// created and empty.
func parseGitManifest(stdout, report string, row vectorRow, tool string) []VectorFinding {
	sections := splitManifest(report)
	fileCount := 0
	if raw := strings.TrimSpace(strings.Join(sections["FILECOUNT"], "")); raw != "" {
		fileCount, _ = strconv.Atoi(strings.Fields(raw)[0])
	}

	if fileCount == 0 {
		// Nothing was recovered. Not a finding, and not an error either: most directories have no
		// repository in them, which is the expected case.
		return nil
	}

	files := sections["FILES"]
	commits := sections["COMMITS"]
	secrets := sections["SECRETS"]

	evidence := "Recovered " + strconv.Itoa(fileCount) + " files"
	if len(commits) > 0 {
		evidence += " across " + strconv.Itoa(len(commits)) + " commits"
	}
	evidence += " from " + gitURLFor(row.EvidenceURL) + "."
	if len(files) > 0 {
		evidence += " Including: " + strings.Join(trimList(files, 8), ", ") + "."
	}

	severity := "high"
	confidence := "the repository was reconstructed, so the source tree and its history are readable. " +
		"That is the finding: what it contains decides how bad it is."

	// A credential in the history is the thing worth reporting, and it survives deletion: a secret
	// committed and then removed in a later commit is still in the object store, so the manifest
	// greps every blob rather than the checked-out tree.
	if len(secrets) > 0 {
		severity = "critical"
		confidence = "the repository was reconstructed AND lines that look like credentials are present " +
			"in its history. A secret deleted in a later commit is still recoverable, so check whether " +
			"these are live before assuming the deletion fixed anything."
		evidence += " Possible credentials: " + strings.Join(trimList(secrets, 6), " | ")
	}

	findings := []VectorFinding{{
		VectorID:        row.ID,
		Tool:            tool,
		Kind:            "exposed-git-repository",
		Severity:        severity,
		Confidence:      confidence,
		InsertionPoint:  row.InsertionPoint,
		Method:          "GET",
		URL:             gitURLFor(row.EvidenceURL),
		Evidence:        evidence,
		DetectionMethod: tool,
		RawResponse:     strings.Join(commits, "\n"),
		IsLeakTarget:    row.IsLeakTarget,
	}}
	return findings
}

// splitManifest reads the "## NAME" sections the manifest script emits.
func splitManifest(report string) map[string][]string {
	out := map[string][]string{}
	current := ""
	for _, line := range strings.Split(report, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "## ") {
			current = strings.TrimSpace(strings.TrimPrefix(trimmed, "## "))
			continue
		}
		if current == "" || trimmed == "" {
			continue
		}
		out[current] = append(out[current], trimmed)
	}
	return out
}

func trimList(values []string, limit int) []string {
	if len(values) <= limit {
		return values
	}
	out := append([]string{}, values[:limit]...)
	return append(out, "and "+strconv.Itoa(len(values)-limit)+" more")
}

// parseMantraOutput reads Mantra's stdout.
//
// There is no machine-readable format, so this matches the lines it prints. Colour codes are stripped
// first, because Mantra writes them unconditionally and they otherwise land in the middle of the
// evidence. A hit looks like:
//
//	[+] https://target/app.js [ api_key = "AIza..." ]
//
// and a failure like:
//
//	[-] Unable to make a request for https://target/app.js
func parseMantraOutput(stdout, report string, row vectorRow) []VectorFinding {
	var findings []VectorFinding
	seen := map[string]bool{}
	unreachable := false

	for _, line := range strings.Split(stripANSI(stdout), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Unable to make a request") {
			unreachable = true
			continue
		}
		if !strings.HasPrefix(line, "[+]") {
			continue
		}
		body := strings.TrimSpace(strings.TrimPrefix(line, "[+]"))
		if body == "" || seen[body] {
			continue
		}
		seen[body] = true

		findings = append(findings, VectorFinding{
			VectorID: row.ID,
			Tool:     "mantra",
			Kind:     "hardcoded-secret",
			Severity: "medium",
			Confidence: "Mantra matched a credential pattern in the content this endpoint served. That " +
				"is pattern matching, not proof: run TruffleHog against the same endpoint to find out " +
				"whether the key still works.",
			InsertionPoint:  row.InsertionPoint,
			Method:          "GET",
			URL:             row.EvidenceURL,
			Evidence:        body,
			DetectionMethod: "mantra",
			IsGraphQLTarget: row.IsGraphQLTarget,
		})
	}

	// An endpoint that could not be fetched is not an endpoint with no secrets in it.
	if len(findings) == 0 && unreachable {
		return []VectorFinding{{
			VectorID:        row.ID,
			Tool:            "mantra",
			Kind:            "not-tested",
			Severity:        "info",
			Confidence:      "not a vulnerability: the endpoint could not be fetched, so nothing was read",
			InsertionPoint:  row.InsertionPoint,
			Method:          "GET",
			URL:             row.EvidenceURL,
			Evidence:        "Mantra could not request this endpoint, so its content was never scanned.",
			DetectionMethod: "mantra",
			IsGraphQLTarget: row.IsGraphQLTarget,
		}}
	}
	return findings
}

// truffleHogResult is one line of TruffleHog's --json output. Only the fields that are read are
// declared, because the structure is large and version dependent.
type truffleHogResult struct {
	DetectorName   string `json:"DetectorName"`
	DetectorType   any    `json:"DetectorType"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	Redacted       string `json:"Redacted"`
	ExtraData      any    `json:"ExtraData"`
	SourceMetadata any    `json:"SourceMetadata"`
}

// parseTruffleHogOutput reads the JSON lines TruffleHog writes.
//
// The distinction that matters is Verified. A verified result means TruffleHog took the credential
// and used it successfully against the provider, which is a different class of finding from a string
// that merely matched a detector. Measured: its detectors also PARSE what they match, so a random
// blob between PEM markers is not reported while a real key is, which is why silence here is
// meaningful rather than a failure.
func parseTruffleHogOutput(stdout, report string, row vectorRow) []VectorFinding {
	source := report
	if strings.TrimSpace(source) == "" {
		source = stdout
	}

	var findings []VectorFinding
	seen := map[string]bool{}
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var result truffleHogResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			continue
		}
		if result.DetectorName == "" {
			continue
		}

		shown := result.Redacted
		if strings.TrimSpace(shown) == "" {
			shown = truncateSecret(result.Raw)
		}
		key := result.DetectorName + "|" + shown
		if seen[key] {
			continue
		}
		seen[key] = true

		severity, confidence := "medium", "TruffleHog's detector matched and parsed this, but could "+
			"not confirm the credential works. Worth checking by hand."
		if result.Verified {
			severity = "critical"
			confidence = "VERIFIED: TruffleHog used this credential against the provider and it worked. " +
				"This is a live secret, not a string that looks like one."
		}

		findings = append(findings, VectorFinding{
			VectorID:        row.ID,
			Tool:            "trufflehog",
			Kind:            "exposed-credential",
			Severity:        severity,
			Confidence:      confidence,
			InsertionPoint:  row.InsertionPoint,
			Method:          "GET",
			URL:             row.EvidenceURL,
			Evidence:        result.DetectorName + ": " + shown,
			DetectionMethod: "trufflehog " + result.DetectorName,
			InjectType:      result.DetectorName,
			IsGraphQLTarget: row.IsGraphQLTarget,
		})
	}
	return findings
}

// truncateSecret keeps enough of a match to recognise it without writing the whole credential into
// the database.
func truncateSecret(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= 12 {
		return raw
	}
	return raw[:6] + "..." + raw[len(raw)-4:]
}
