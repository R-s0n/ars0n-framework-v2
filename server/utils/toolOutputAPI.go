package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// The discovery half of what vector_scan_traces already gives the vector scanners.
//
// The measured failure: LinkFinder ran four times against http://10.0.0.18:3000 and every run stored
// status "error" plus the string "Usage: python linkfinder.py [Options] use -h for help", with the
// argv that produced it sitting in linkfinder_url_scans.command. None of that was reachable through
// MCP. Worse, the URL-workflow handlers in urlScanUtils.go do not even SELECT stdout or stderr, so
// for most discovery tools those two columns are written by the runner and then never read by
// anything. Working out that "-o cli" was the wrong flag took four re-runs and reasoning by
// elimination over config changes, to recover a string that was already in the database.
//
// So this file is one uniform read over every discovery scan table: the same response shape whatever
// the tool, the exact command, and stdout and stderr verbatim. It mirrors GetVectorTrace in
// vectorAPI.go deliberately, including the reason that handler exists: this is what you read when a
// scan reported something you do not believe, and it is worth exactly as much as it is verbatim.
//
// Nothing here writes and nothing here re-runs a tool. It only serves what a run already stored.

// discoveryToolOutputSource is one scan table addressed by the tool key an operator already knows.
//
// The keys match the MCP run_scan / check_scan_status vocabulary on purpose. An agent that started a
// scan as "linkfinder_url" should not have to learn that the table is called linkfinder_url_scans to
// read what it printed.
type discoveryToolOutputSource struct {
	Table string
	// Subject is the column naming what the run was pointed at: a domain, a URL, a company name, a
	// JSON list of domains. Empty where the table carries none, which is the case for the tools that
	// derive their input set from other tables rather than from an argument.
	Subject string
	Phase   string
}

// Every discovery scan table that carries the full result/error/stdout/stderr/command/execution_time
// set. A table is listed here only if it has all of them, because a partial row served through a
// uniform shape would read as "the tool printed nothing" rather than "this table never stored it".
//
// ip_port_scans is deliberately absent: it has command but no stdout, no stderr and no result, and
// its failure text lives in error_message rather than error. Serving it here would be the exact lie
// this handler exists to stop.
var discoveryToolOutputSources = map[string]discoveryToolOutputSource{
	// Wildcard subdomain discovery.
	"amass":            {Table: "amass_scans", Subject: "domain", Phase: "wildcard"},
	"subfinder":        {Table: "subfinder_scans", Subject: "domain", Phase: "wildcard"},
	"sublist3r":        {Table: "sublist3r_scans", Subject: "domain", Phase: "wildcard"},
	"assetfinder":      {Table: "assetfinder_scans", Subject: "domain", Phase: "wildcard"},
	"gau":              {Table: "gau_scans", Subject: "domain", Phase: "wildcard"},
	"ctl":              {Table: "ctl_scans", Subject: "domain", Phase: "wildcard"},
	"gospider":         {Table: "gospider_scans", Subject: "domain", Phase: "wildcard"},
	"subdomainizer":    {Table: "subdomainizer_scans", Subject: "domain", Phase: "wildcard"},
	"shuffledns":       {Table: "shuffledns_scans", Subject: "domain", Phase: "wildcard"},
	"shufflednscustom": {Table: "shufflednscustom_scans", Subject: "domain", Phase: "wildcard"},
	"cewl":             {Table: "cewl_scans", Subject: "url", Phase: "wildcard"},
	"httpx":            {Table: "httpx_scans", Subject: "domain", Phase: "wildcard"},
	"metadata":         {Table: "metadata_scans", Subject: "domain", Phase: "wildcard"},

	// Company intelligence and enumeration.
	"amass_intel":            {Table: "amass_intel_scans", Subject: "company_name", Phase: "company"},
	"metabigor_company":      {Table: "metabigor_company_scans", Subject: "company_name", Phase: "company"},
	"securitytrails_company": {Table: "securitytrails_company_scans", Subject: "company_name", Phase: "company"},
	"censys_company":         {Table: "censys_company_scans", Subject: "company_name", Phase: "company"},
	"shodan_company":         {Table: "shodan_company_scans", Subject: "company_name", Phase: "company"},
	"github_recon":           {Table: "github_recon_scans", Subject: "company_name", Phase: "company"},
	"cloud_enum":             {Table: "cloud_enum_scans", Subject: "company_name", Phase: "company"},
	"ctl_company":            {Table: "ctl_company_scans", Subject: "company_name", Phase: "company"},
	"amass_enum_company":     {Table: "amass_enum_company_scans", Subject: "domains", Phase: "company"},
	"dnsx_company":           {Table: "dnsx_company_scans", Subject: "domains", Phase: "company"},
	"katana_company":         {Table: "katana_company_scans", Subject: "domains", Phase: "company"},
	"investigate":            {Table: "investigate_scans", Phase: "company"},

	// URL workflow. These are the ones that hid the LinkFinder usage error: their own status routes
	// select neither stdout nor stderr.
	"katana_url":     {Table: "katana_url_scans", Subject: "url", Phase: "url"},
	"linkfinder_url": {Table: "linkfinder_url_scans", Subject: "url", Phase: "url"},
	"gospider_url":   {Table: "gospider_url_scans", Subject: "url", Phase: "url"},
	"waybackurls":    {Table: "waybackurls_scans", Subject: "url", Phase: "url"},
	"gau_url":        {Table: "gau_url_scans", Subject: "url", Phase: "url"},
	"ffuf_url":       {Table: "ffuf_url_scans", Subject: "url", Phase: "url"},
	"waf_probe":      {Table: "waf_probe_scans", Subject: "url", Phase: "url"},
	"ffuf":           {Table: "ffuf_scans", Phase: "url"},
	"arjun":          {Table: "arjun_scans", Phase: "url"},
	"x8":             {Table: "x8_scans", Phase: "url"},

	// Vulnerability scanning.
	"nuclei":            {Table: "nuclei_scans", Subject: "targets", Phase: "vuln"},
	"nuclei_screenshot": {Table: "nuclei_screenshots", Subject: "domain", Phase: "vuln"},
}

// DiscoveryToolOutputKeys is the sorted tool vocabulary, so an unknown key can be answered with the
// set that would have worked instead of a bare 404.
func DiscoveryToolOutputKeys() []string {
	keys := make([]string, 0, len(discoveryToolOutputSources))
	for k := range discoveryToolOutputSources {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// toolOutputSubjectExpr keeps the UNION columns type-compatible.
//
// The subject column is a domain on one table, a jsonb array of domains on another and a text[] of
// nuclei targets on a third. Casting every one of them to text at the source is what lets thirty
// seven tables answer with one row shape.
func toolOutputSubjectExpr(src discoveryToolOutputSource) string {
	if src.Subject == "" {
		return "''::text"
	}
	return fmt.Sprintf("COALESCE(%s::text, '')", src.Subject)
}

// discoveryOutputSelect builds one arm of the UNION for a single tool.
//
// The table and column names come only from discoveryToolOutputSources, which is a compile-time
// literal, so nothing a caller sends is ever interpolated. The scan id is bound as $1 and compared
// as text rather than cast to uuid, because a malformed id should be "no such run" rather than a 500
// from the driver.
func discoveryOutputSelect(key string, src discoveryToolOutputSource) string {
	return fmt.Sprintf(`SELECT '%s'::text AS tool, '%s'::text AS source_table,
		scan_id::text AS scan_id, COALESCE(status, '') AS status,
		%s AS subject, COALESCE(command, '') AS command,
		COALESCE(stdout, '') AS stdout, COALESCE(stderr, '') AS stderr,
		COALESCE(error, '') AS error, COALESCE(result, '') AS result,
		COALESCE(execution_time, '') AS execution_time, created_at,
		COALESCE(scope_target_id::text, '') AS scope_target_id
		FROM %s WHERE scan_id::text = $1`, key, src.Table, toolOutputSubjectExpr(src), src.Table)
}

// discoveryRunsSelect builds one arm of the recent-runs UNION.
//
// It reports the LENGTH of stdout, stderr and result rather than their contents. A listing is
// multiplied by its row count, and the whole point of the run read is that it is a deliberate,
// single, unsummarised fetch. command is previewed rather than returned whole for the same reason:
// the LinkFinder command on this target is a kilobyte, most of it a session JWT.
//
// scope_target_id is compared as a uuid, not cast to text, so the per-table index is usable. Thirty
// seven arms means thirty seven lookups, and turning every one of them into a sequential scan to save
// a validation the handler already does would be a poor trade.
func discoveryRunsSelect(key string, src discoveryToolOutputSource) string {
	return fmt.Sprintf(`SELECT '%s'::text AS tool, '%s'::text AS source_table,
		scan_id::text AS scan_id, COALESCE(status, '') AS status,
		%s AS subject, left(COALESCE(command, ''), 300) AS command_preview,
		length(COALESCE(command, '')) AS command_chars,
		length(COALESCE(stdout, '')) AS stdout_chars,
		length(COALESCE(stderr, '')) AS stderr_chars,
		length(COALESCE(result, '')) AS result_chars,
		COALESCE(error, '') AS error,
		COALESCE(execution_time, '') AS execution_time, created_at
		FROM %s WHERE scope_target_id = $1`, key, src.Table, toolOutputSubjectExpr(src), src.Table)
}

// toolOutputUsageMarkers are the strings a tool prints when the ARGV is wrong rather than the target.
//
// Every entry is a case the runner records as a normal finished scan, so the distinction is invisible
// in the status column. "use -h for help" is literally the LinkFinder message that cost four runs;
// the rest are the same class of failure from the other runtimes in the compose file: Python
// argparse and optparse, Go flag and cobra, and a container that does not have the binary at all.
var toolOutputUsageMarkers = []string{
	"traceback (most recent call last)",
	"unrecognized arguments",
	"no such option",
	"invalid option",
	"command not found",
	"executable file not found",
	"flag provided but not defined",
	"unknown flag:",
	"unknown shorthand flag",
	"panic: ",
	"modulenotfounderror",
}

// toolOutputAmbiguousUsageMarkers look like an argument rejection and are not reliably one.
//
// "use -h for help" WAS in the list above, and putting it there reproduced, inside the very surface
// built to prevent it, the misdiagnosis that surface exists for.
//
// LinkFinder prints `Usage: python linkfinder.py [Options] use -h for help` from a bare except that
// wraps its INPUT FETCH, not from argparse. It says the same thing whether you passed a bad flag or
// the target was unreachable. Measured on 2026-08-21: four LinkFinder runs against 10.0.0.18:3000
// printed exactly that and were read as an argument problem. The arguments were correct. The machine
// hosting the target had gone to sleep, and the same command succeeded in 7.5s with 13 endpoints
// once it woke up. Telling an operator "fix the flags, nothing was tested" would have sent them to
// change working code.
//
// Diagnosed as "unreachable_or_usage" so the row says what is actually known. The discriminator is
// not in the text: it is whether OTHER tools failed in the same window, which is why the hint says
// to look there.
var toolOutputAmbiguousUsageMarkers = []string{
	"use -h for help",
}

// looksLikeJSONDocument reports whether text is a JSON object or array rather than a message.
//
// Deliberately a real parse, not a prefix check: an error message that happens to start with "{"
// must not be excused as a misfiled result, because excusing a genuine failure is the direction that
// hides things.
func looksLikeJSONDocument(text string) bool {
	trimmed := strings.TrimSpace(text)
	if len(trimmed) < 2 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return false
	}
	return json.Valid([]byte(trimmed))
}

// toolOutputUsagePrefixes match only at the START of a line.
//
// argparse and optparse both open with "usage: prog ..." when they reject an argument, which is the
// strongest single signal there is. Matched as a line prefix rather than a substring because a
// crawler's stdout is other people's page content, and "usage:" appears in plenty of it. A false
// usage_error would send an operator to fix flags that were already right.
var toolOutputUsagePrefixes = []string{"usage:", "usage :"}

// discoveryDiagnosisFrom is the shared rule, taking whatever text the caller could afford to look at.
//
// The listing passes the command preview and a boolean, because it never pulls stdout; the single-run
// read passes the real output. Same ordering of tests either way, so the two surfaces cannot disagree
// about what a run means.
func discoveryDiagnosisFrom(status, errText, searchable string, anyOutput bool) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "running", "pending", "queued", "in_progress":
		return "running"
	}

	combined := strings.ToLower(errText + "\n" + searchable)
	for _, marker := range toolOutputUsageMarkers {
		if strings.Contains(combined, marker) {
			return "usage_error"
		}
	}

	// Checked BEFORE the usage: prefix rule, because LinkFinder's unreachable-input message opens
	// with "Usage:" and would otherwise be called a definite argument rejection by the next loop.
	for _, marker := range toolOutputAmbiguousUsageMarkers {
		if strings.Contains(combined, marker) {
			return "unreachable_or_usage"
		}
	}

	for _, line := range strings.Split(combined, "\n") {
		trimmed := strings.TrimSpace(line)
		for _, prefix := range toolOutputUsagePrefixes {
			if strings.HasPrefix(trimmed, prefix) {
				return "usage_error"
			}
		}
	}

	// A non-empty error column on a run the tool itself called successful is a MISFILED RESULT, not
	// a failure. arjunUtils.go wrote its whole JSON summary into `error` and left `result` empty, so
	// a 2m43s run that found 46 parameters was diagnosed "failed" here. That writer is fixed, and
	// this stays because the rows it already wrote are still in the database and because a status
	// the tool set itself is better evidence than the shape of a column.
	if errTrimmed := strings.TrimSpace(errText); errTrimmed != "" {
		successful := false
		switch strings.ToLower(strings.TrimSpace(status)) {
		case "success", "completed", "complete", "partial":
			successful = true
		}
		if !(successful && looksLikeJSONDocument(errTrimmed)) {
			return "failed"
		}
	}

	// A run that finished, was recorded clean, and left nothing at all behind. Not necessarily a bug,
	// but it is the shape a silently mis-pointed tool takes, so it gets its own name rather than
	// being folded into "ok".
	if !anyOutput {
		return "no_output"
	}
	return "ok"
}

// discoveryOutputDiagnosis answers the question the status column cannot: does this run's zero mean
// anything?
//
// Same intent as vectorScanVerdict in vectorAPI.go, and for the same measured reason. A LinkFinder
// run that printed a usage message and a LinkFinder run that crawled the target and genuinely found
// nothing both show up as one row with no endpoints. Only one of those is a result. "usage_error" is
// called out separately from "failed" because it changes WHAT you fix: the flags, not the target, not
// the network, not the wordlist.
func discoveryOutputDiagnosis(status, errText, stdout, stderr, result string) string {
	anyOutput := strings.TrimSpace(result) != "" ||
		strings.TrimSpace(stdout) != "" || strings.TrimSpace(stderr) != ""
	return discoveryDiagnosisFrom(status, errText, stdout+"\n"+stderr, anyOutput)
}

// discoveryOutputHint spells out what to do about a diagnosis, because the whole cost of the
// LinkFinder incident was in not knowing which knob was the wrong one.
func discoveryOutputHint(diagnosis string) string {
	switch diagnosis {
	case "usage_error":
		return "The tool rejected its own arguments: read command, fix the flags in the tool config, " +
			"and note that the run may still be recorded with a normal status. Nothing was tested."
	case "unreachable_or_usage":
		return "The tool printed a usage banner, which for this tool means EITHER bad arguments OR " +
			"an input it could not fetch. Do not change the command line on the strength of this " +
			"alone. Check whether other tools failed against the same target in the same window: " +
			"if they did, the target was down and the arguments are fine. Confirm the target is up " +
			"and re-run before touching any config."
	case "failed":
		return "The run stored an error. command is the exact argv that produced it."
	case "no_output":
		return "The run finished and stored no result, no stdout and no stderr. Check command " +
			"actually points at the intended input set before believing the zero."
	case "running":
		return "Still running. stdout and stderr are whatever has been flushed so far."
	}
	return "The run produced output. stdout and stderr are verbatim."
}

// clipToolOutput bounds one field on request and always says what it removed.
//
// fromTail exists because the two things worth reading live at opposite ends: a usage error is the
// first line a tool prints, and a crash or a truncated run is the last. A head-only clip would have
// shown the LinkFinder message, and would hide every stack trace.
func clipToolOutput(text string, maxChars int, fromTail bool) (string, bool) {
	if maxChars <= 0 || len(text) <= maxChars {
		return text, false
	}
	if fromTail {
		cut := len(text) - maxChars
		return fmt.Sprintf("[... %d chars before ...]\n%s", cut, text[cut:]), true
	}
	return fmt.Sprintf("%s\n[... %d chars after ...]", text[:maxChars], len(text)-maxChars), true
}

// toolOutputMaxChars reads the optional per-field budget.
//
// Unset means unclipped, matching GetVectorTrace: the default for a deliberate single-run read is the
// whole thing, and a caller who wants less says so. The MCP layer is where a context-window sized
// default belongs, not here.
func toolOutputMaxChars(r *http.Request) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("max_chars")))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("from")), "tail")
}

// ListDiscoveryToolOutputSources answers GET /tool-output/tools: the vocabulary, so the tool key does
// not have to be guessed from the table name.
func ListDiscoveryToolOutputSources(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tools := make([]map[string]any, 0, len(discoveryToolOutputSources))
	for _, key := range DiscoveryToolOutputKeys() {
		src := discoveryToolOutputSources[key]
		tools = append(tools, map[string]any{
			"tool": key, "table": src.Table, "phase": src.Phase, "subject_column": src.Subject,
		})
	}
	json.NewEncoder(w).Encode(map[string]any{
		"tools": tools,
		"total": len(tools),
		"note": "Every tool here stores command, stdout, stderr, error and result per run. Read one " +
			"run with /tool-output/run/{tool}/{scan_id}, or pass tool=any when you have a scan id " +
			"but not the tool that produced it.",
	})
}

// ListDiscoveryToolRuns answers GET /tool-output/runs/{scope_target_id}: which runs exist and which
// of them are worth opening.
//
// This is the step that was missing entirely. There was no way to ask "what has this target actually
// executed and what did it print", so a failing tool was only visible as an absence of results
// somewhere else in the UI.
func ListDiscoveryToolRuns(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	// Validated here so the query can bind a uuid and use the indexes. Without this a typo reaches
	// the driver as a cast failure and comes back as a 500, which reads as "the framework is broken"
	// rather than "that is not a target id".
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_target",
			scopeTargetID+" is not a scope target UUID.")
		return
	}

	keys := DiscoveryToolOutputKeys()
	if want := strings.TrimSpace(r.URL.Query().Get("tool")); want != "" && !strings.EqualFold(want, "any") {
		if _, ok := discoveryToolOutputSources[want]; !ok {
			writeJSONError(w, http.StatusNotFound, "unknown_tool",
				"No discovery tool called "+want+". Known: "+strings.Join(DiscoveryToolOutputKeys(), ", "))
			return
		}
		keys = []string{want}
	}

	limit := 50
	if n, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("limit"))); err == nil && n > 0 {
		limit = n
	}
	if limit > 500 {
		limit = 500
	}

	arms := make([]string, 0, len(keys))
	for _, key := range keys {
		arms = append(arms, discoveryRunsSelect(key, discoveryToolOutputSources[key]))
	}
	query := strings.Join(arms, "\nUNION ALL\n") +
		fmt.Sprintf("\nORDER BY created_at DESC LIMIT %d", limit)

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}
	defer rows.Close()

	runs := make([]map[string]any, 0, limit)
	problems := 0
	for rows.Next() {
		var (
			tool, table, scanID, status, subject, preview string
			errText, execTime                             string
			commandChars, stdoutChars, stderrChars        int
			resultChars                                   int
			// A pointer, not a time.Time: created_at is nullable on every one of these tables, and a
			// single NULL would otherwise fail the scan and take the whole listing with it.
			createdAt *time.Time
		)
		if err := rows.Scan(&tool, &table, &scanID, &status, &subject, &preview, &commandChars,
			&stdoutChars, &stderrChars, &resultChars, &errText, &execTime, &createdAt); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "scan_failed", err.Error())
			return
		}
		// The diagnosis is computed from the error text and the command preview only. A listing never
		// pulls stdout, so a usage message that landed past the preview shows as "failed" or
		// "no_output" here and is named exactly by the single-run read.
		diagnosis := discoveryDiagnosisFrom(status, errText, preview,
			resultChars > 0 || stdoutChars > 0 || stderrChars > 0)
		if diagnosis == "usage_error" || diagnosis == "failed" || diagnosis == "no_output" ||
			diagnosis == "unreachable_or_usage" {
			problems++
		}
		runs = append(runs, map[string]any{
			"tool": tool, "source_table": table, "scan_id": scanID, "status": status,
			"subject": subject, "command_preview": preview, "command_chars": commandChars,
			"stdout_chars": stdoutChars, "stderr_chars": stderrChars, "result_chars": resultChars,
			"error": errText, "execution_time": execTime, "created_at": createdAt,
			"diagnosis": diagnosis,
		})
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "query_failed", err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"total":           len(runs),
		"needs_attention": problems,
		"runs":            runs,
		"note": "Sizes, not contents: open one run with /tool-output/run/{tool}/{scan_id} to get " +
			"stdout and stderr verbatim. diagnosis usage_error means the tool rejected its own " +
			"flags, which the status column does not distinguish from a real scan that found nothing.",
	})
}

// GetDiscoveryToolOutput answers GET /tool-output/run/{tool}/{scan_id}: everything one discovery run
// stored, unsummarised.
//
// tool may be "any", which searches every registered table for the scan id. That case is not a
// convenience: a scan id turns up in a workflow response or a log line without the table it came
// from, and having to guess the tool before you can read the error is the same wall this file exists
// to remove.
func GetDiscoveryToolOutput(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	vars := mux.Vars(r)
	toolKey, scanID := strings.TrimSpace(vars["tool"]), vars["scan_id"]

	keys := DiscoveryToolOutputKeys()
	if toolKey != "" && !strings.EqualFold(toolKey, "any") {
		if _, ok := discoveryToolOutputSources[toolKey]; !ok {
			writeJSONError(w, http.StatusNotFound, "unknown_tool",
				"No discovery tool called "+toolKey+". Known: "+strings.Join(keys, ", ")+
					". Pass \"any\" to search every table for this scan id.")
			return
		}
		keys = []string{toolKey}
	}

	arms := make([]string, 0, len(keys))
	for _, key := range keys {
		arms = append(arms, discoveryOutputSelect(key, discoveryToolOutputSources[key]))
	}
	query := strings.Join(arms, "\nUNION ALL\n") + "\nORDER BY created_at DESC LIMIT 1"

	var (
		tool, table, id, status, subject, command string
		stdout, stderr, errText, result, execTime string
		scopeTargetID                             string
		createdAt                                 *time.Time
	)
	if err := dbPool.QueryRow(context.Background(), query, scanID).Scan(&tool, &table, &id, &status,
		&subject, &command, &stdout, &stderr, &errText, &result, &execTime, &createdAt,
		&scopeTargetID); err != nil {
		writeJSONError(w, http.StatusNotFound, "unknown_run",
			"No stored run with scan id "+scanID+" in "+strings.Join(keys, ", ")+".")
		return
	}

	maxChars, fromTail := toolOutputMaxChars(r)
	clippedStdout, stdoutClipped := clipToolOutput(stdout, maxChars, fromTail)
	clippedStderr, stderrClipped := clipToolOutput(stderr, maxChars, fromTail)
	clippedResult, resultClipped := clipToolOutput(result, maxChars, fromTail)

	diagnosis := discoveryOutputDiagnosis(status, errText, stdout, stderr, result)

	json.NewEncoder(w).Encode(map[string]any{
		"tool": tool, "source_table": table, "scan_id": id, "scope_target_id": scopeTargetID,
		"subject": subject, "status": status, "created_at": createdAt, "execution_time": execTime,
		// command first in intent if not in JSON order: it is the single most useful field here,
		// because every usage error is a statement about it.
		"command": command,
		"stdout":  clippedStdout, "stdout_chars": len(stdout), "stdout_clipped": stdoutClipped,
		"stderr": clippedStderr, "stderr_chars": len(stderr), "stderr_clipped": stderrClipped,
		"error":  errText,
		"result": clippedResult, "result_chars": len(result), "result_clipped": resultClipped,
		"diagnosis": diagnosis,
		"hint":      discoveryOutputHint(diagnosis),
	})
}
