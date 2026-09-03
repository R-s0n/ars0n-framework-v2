package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type GitHubReconScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	CompanyName       string         `json:"company_name"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result,omitempty"`
	Error             sql.NullString `json:"error,omitempty"`
	StdOut            sql.NullString `json:"stdout,omitempty"`
	StdErr            sql.NullString `json:"stderr,omitempty"`
	Command           sql.NullString `json:"command,omitempty"`
	ExecTime          sql.NullString `json:"execution_time,omitempty"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

func RunGitHubReconScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[GITHUB-RECON] [INFO] Starting GitHub Recon scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[GITHUB-RECON] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[GITHUB-RECON] [INFO] Processing GitHub Recon scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[GITHUB-RECON] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[GITHUB-RECON] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS github_recon_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`
	_, err = dbPool.Exec(context.Background(), createTableQuery)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to create github_recon_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[GITHUB-RECON] [INFO] Ensured github_recon_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO github_recon_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO github_recon_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[GITHUB-RECON] [INFO] Successfully created GitHub Recon scan record in database")

	go ExecuteGitHubReconScan(scanID, companyName)

	log.Printf("[GITHUB-RECON] [INFO] GitHub Recon scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteGitHubReconScan(scanID, companyName string) {
	log.Printf("[GITHUB-RECON] [INFO] Starting GitHub Recon scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	// Get GitHub API key from database
	var apiKeyJSON string
	err := dbPool.QueryRow(context.Background(),
		`SELECT api_key_value FROM api_keys WHERE tool_name = 'GitHub' LIMIT 1`).Scan(&apiKeyJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[GITHUB-RECON] [ERROR] No GitHub API key found in database")
			UpdateGitHubReconScanStatus(scanID, "error", "", "", "No GitHub API key configured", "", time.Since(startTime).String())
			return
		}
		log.Printf("[GITHUB-RECON] [ERROR] Failed to get GitHub API key: %v", err)
		UpdateGitHubReconScanStatus(scanID, "error", "", "", fmt.Sprintf("Failed to get GitHub API key: %v", err), "", time.Since(startTime).String())
		return
	}

	// Parse the API key JSON to extract the actual key
	var keyData map[string]interface{}
	if err := json.Unmarshal([]byte(apiKeyJSON), &keyData); err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to parse API key JSON: %v", err)
		UpdateGitHubReconScanStatus(scanID, "error", "", "", fmt.Sprintf("Failed to parse API key JSON: %v", err), "", time.Since(startTime).String())
		return
	}

	apiKey, ok := keyData["api_key"].(string)
	if !ok || apiKey == "" {
		log.Printf("[GITHUB-RECON] [ERROR] GitHub API key is empty")
		UpdateGitHubReconScanStatus(scanID, "error", "", "", "GitHub API key is empty", "", time.Since(startTime).String())
		return
	}

	log.Printf("[GITHUB-RECON] [INFO] Successfully retrieved GitHub API key")

	// The per-target Company settings, from the ONE store the Settings screen and the MCP company tool
	// both write. Absent is the normal case and produces the exact argv this runner has always built,
	// including the alphanumeric-strip seed and the 120-second context deadline.
	//
	// FOUR OF THIS TOOL'S OPTIONS CANNOT BE HONOURED HERE AT ALL - they are values inside the vendored
	// python script, not flags on it - and companyUnwireableNotes puts that on the scan row rather than
	// letting a saved setting quietly do nothing.
	ctx := context.Background()
	scopeTargetID := companyScopeTargetForScan(ctx, "github_recon_scans", scanID, "github_recon")
	tool, settings, notes := companyRunnerSettings(scopeTargetID, "github_recon")
	plan := githubReconPlanFor(companyName, companyFirstConsolidatedRootDomain(ctx, scopeTargetID), settings)
	notes = append(notes, plan.Notes...)
	notes = append(notes, companyUnwireableNotes(githubReconUnwireable, settings)...)
	if plan.Configured {
		log.Printf("[GITHUB-RECON] [INFO] Running with stored Company settings for scope target %s: %s",
			scopeTargetID, companySettingsSummary(settings))
	}
	companyLogNotes("GITHUB-RECON", notes)

	domainName := plan.Seed
	log.Printf("[GITHUB-RECON] [INFO] Transformed company name '%s' to search seed '%s' (mode %s)",
		companyName, domainName, plan.SeedMode)

	// First, check if the GitHub recon container is running
	checkCmd := exec.Command("docker", "ps", "--filter", "name=ars0n-framework-v2-github-recon-1", "--format", "{{.Status}}")
	checkOutput, err := checkCmd.Output()
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to check container status: %v", err)
		UpdateGitHubReconScanStatus(scanID, "error", "", "", fmt.Sprintf("Failed to check container status: %v", err), "", time.Since(startTime).String())
		return
	}

	containerStatus := strings.TrimSpace(string(checkOutput))
	log.Printf("[GITHUB-RECON] [DEBUG] Container status: %s", containerStatus)

	if containerStatus == "" {
		log.Printf("[GITHUB-RECON] [ERROR] GitHub recon container is not running")
		UpdateGitHubReconScanStatus(scanID, "error", "", "", "GitHub recon container is not running", "", time.Since(startTime).String())
		return
	}

	// Debug: Check what's in the container
	debugCmd := exec.Command("docker", "exec", "ars0n-framework-v2-github-recon-1", "ls", "-la", "/app/github-search")
	debugOutput, debugErr := debugCmd.Output()
	if debugErr != nil {
		log.Printf("[GITHUB-RECON] [DEBUG] Failed to list directory contents: %v", debugErr)
	} else {
		log.Printf("[GITHUB-RECON] [DEBUG] Container /app/github-search contents:\n%s", string(debugOutput))
	}

	// Debug: Check if the Python script exists
	pythonCheckCmd := exec.Command("docker", "exec", "ars0n-framework-v2-github-recon-1", "ls", "-la", plan.ScriptPath)
	pythonCheckOutput, pythonCheckErr := pythonCheckCmd.Output()
	if pythonCheckErr != nil {
		log.Printf("[GITHUB-RECON] [DEBUG] Python script check failed: %v", pythonCheckErr)
	} else {
		log.Printf("[GITHUB-RECON] [DEBUG] Python script exists: %s", string(pythonCheckOutput))
	}

	// Debug: Check the script help to see available parameters
	helpCmd := exec.Command("docker", "exec", "ars0n-framework-v2-github-recon-1", "python3", plan.ScriptPath, "-h")
	helpOutput, helpErr := helpCmd.Output()
	if helpErr != nil {
		log.Printf("[GITHUB-RECON] [DEBUG] Failed to get help output: %v", helpErr)
	} else {
		log.Printf("[GITHUB-RECON] [DEBUG] Script help output:\n%s", string(helpOutput))
	}

	// Construct the command with unbuffered Python output.
	//
	// python3 -u is LOAD BEARING and framework-owned: without it Python block-buffers stdout when it is
	// a pipe, and a scan killed by the deadline below would lose everything written so far. This
	// project has already lost data to stdout buffering once.
	argv, composeNotes := githubReconCommandArgs(plan, apiKey, tool, settings)
	notes = append(notes, composeNotes...)
	companyLogNotes("GITHUB-RECON", composeNotes)

	var stdout, stderr bytes.Buffer

	// The wall-clock deadline. 120 seconds unless a target says otherwise, and it is the ONLY deadline
	// the framework imposes on this tool. Worth knowing when raising it: killing the local `docker
	// exec` does NOT kill python inside the container, so a timed-out scan leaves the script running,
	// still fetching files and still spending the rate limit of a token the framework thinks is idle.
	scanCtx, cancel := context.WithTimeout(context.Background(), plan.ScanTimeout)
	defer cancel()
	cmd := exec.CommandContext(scanCtx, argv[0], argv[1:]...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	log.Printf("[GITHUB-RECON] [DEBUG] Executing command: %s", cmd.String())

	err = cmd.Run()
	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	log.Printf("[GITHUB-RECON] [DEBUG] Command stdout: %s", stdoutStr)
	log.Printf("[GITHUB-RECON] [DEBUG] Command stderr: %s", stderrStr)

	// WHAT GETS WRITTEN INTO THE command COLUMN, AND ONE DELIBERATE DEVIATION FROM WHAT IT USED TO BE.
	//
	// The token is passed as an argv element, so cmd.String() contains it verbatim - which means the
	// error path has been writing a GitHub Personal Access Token into the database in PLAINTEXT on
	// every failed scan. That is recorded on the registry entry as a defect and it is fixed here rather
	// than left, because this change is what invites operators to go and read that column. The command
	// LINE that is executed is unchanged, token and all; only the stored copy is redacted.
	storedCommand := githubReconRedactToken(cmd.String(), apiKey)
	if preamble := companySettingsPreamble(tool, scopeTargetID, settings, notes); preamble != "" {
		storedCommand += "\n" + preamble
	}

	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to execute GitHub Recon scan: %v", err)
		log.Printf("[GITHUB-RECON] [ERROR] Command that failed: %s", storedCommand)
		UpdateGitHubReconScanStatus(scanID, "error", "", "", stderrStr, storedCommand, time.Since(startTime).String())
		return
	}

	log.Printf("[GITHUB-RECON] [INFO] GitHub Recon scan completed successfully, processing output...")

	// Process the output to extract and validate domains.
	//
	// The extraction itself moved into githubReconExtractDomains so that the file-extension list, the
	// exclusion list and the registrable-domain reduction are configurable and, more usefully, so that
	// the whole filter is a PURE function with tests. Its default path is this runner's original code
	// unchanged, with one stated deviation: the returned list is SORTED, where the original ranged a
	// map and produced a different order on every run for the same input.
	lines := strings.Split(stdoutStr, "\n")
	log.Printf("[GITHUB-RECON] [DEBUG] Processing %d lines of output", len(lines))

	extracted, extractNotes := githubReconExtractDomains(plan, stdoutStr)
	notes = append(notes, extractNotes...)
	companyLogNotes("GITHUB-RECON", extractNotes)

	domains := make([]map[string]interface{}, 0, len(extracted))
	for _, domain := range extracted {
		domains = append(domains, map[string]interface{}{
			"domain": domain,
			"source": "github_recon",
		})
	}

	log.Printf("[GITHUB-RECON] [DEBUG] Processed %d lines, found %d unique valid domains", len(lines), len(domains))

	// THE ANTI-SILENT-NOTHING CONTROL, off by default. MEASURED: running the installed script with a
	// syntactically valid but INVALID token produced exit code 0, zero bytes on stdout AND zero bytes
	// on stderr, so the runner sees err == nil, extracts nothing and stores 'success'. A revoked,
	// expired or wrongly-scoped PAT is indistinguishable from a company with no GitHub footprint, and
	// an exhausted rate limit takes the identical path.
	if plan.FailOnZeroDomains && len(domains) == 0 {
		errorMsg := fmt.Sprintf("GitHub Recon extracted zero domains from %d bytes of stdout. "+
			"failOnZeroDomains is on, so it is recorded as an error rather than as a clean result. Note "+
			"that an INVALID or rate-limited GitHub token exits 0 with EMPTY stdout and stderr, which is "+
			"exactly this shape; a MISSING key fails loudly instead.", len(stdoutStr))
		UpdateGitHubReconScanStatus(scanID, "error", "", stdoutStr, errorMsg, storedCommand, time.Since(startTime).String())
		return
	}

	// Create result object
	result := map[string]interface{}{
		"domains": domains,
		"meta": map[string]interface{}{
			"total":         len(domains),
			"raw_lines":     len(lines),
			"domains_found": len(extracted),
		},
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to marshal result: %v", err)
		UpdateGitHubReconScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), "", "", time.Since(startTime).String())
		return
	}

	// Update scan status with success.
	//
	// The success path has always stored an EMPTY command column, so it stays empty for a target that
	// configured nothing. When settings were applied it carries the redacted command line and the
	// preamble, because otherwise nothing anywhere records that this scan searched for a different
	// seed, ran a different script, or had four of its options silently beyond the runner's reach.
	successCommand := ""
	if plan.Configured || len(notes) > 0 {
		successCommand = storedCommand
	}
	UpdateGitHubReconScanStatus(scanID, "success", string(resultJSON), string(stdoutStr), "", successCommand, time.Since(startTime).String())
	log.Printf("[GITHUB-RECON] [INFO] Successfully completed GitHub Recon scan for company %s (scan ID: %s)", companyName, scanID)
}

func UpdateGitHubReconScanStatus(scanID, status, result, stdout, stderr, command, execTime string) {
	log.Printf("[GITHUB-RECON] [INFO] Updating GitHub Recon scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE github_recon_scans SET status = $1, result = $2, stdout = $3, stderr = $4, command = $5, execution_time = $6 WHERE scan_id = $7`

	_, err := dbPool.Exec(context.Background(), query, status, result, stdout, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to update GitHub Recon scan status for scan ID %s: %v", scanID, err)
		log.Printf("[GITHUB-RECON] [ERROR] Update attempted with: status=%s, result_length=%d, stdout_length=%d, stderr_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stdout), len(stderr), len(command), execTime)
	} else {
		log.Printf("[GITHUB-RECON] [INFO] Successfully updated GitHub Recon scan status to %s for scan ID %s", status, scanID)
	}
}

func GetGitHubReconScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[GITHUB-RECON] [INFO] Retrieving GitHub Recon scan status for scan ID: %s", scanID)

	var scan GitHubReconScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM github_recon_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.CompanyName,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
		&scan.ScopeTargetID,
		&scan.AutoScanSessionID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[GITHUB-RECON] [ERROR] GitHub Recon scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[GITHUB-RECON] [ERROR] Failed to get GitHub Recon scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[GITHUB-RECON] [INFO] Successfully retrieved GitHub Recon scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[GITHUB-RECON] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
	}

	response := map[string]interface{}{
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"company_name":         scan.CompanyName,
		"status":               scan.Status,
		"result":               nullStringToString(scan.Result),
		"error":                nullStringToString(scan.Error),
		"stdout":               nullStringToString(scan.StdOut),
		"stderr":               nullStringToString(scan.StdErr),
		"command":              nullStringToString(scan.Command),
		"execution_time":       nullStringToString(scan.ExecTime),
		"created_at":           scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id":      scan.ScopeTargetID,
		"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to encode GitHub Recon scan response: %v", err)
	} else {
		log.Printf("[GITHUB-RECON] [INFO] Successfully sent GitHub Recon scan status response")
	}
}

func GetGitHubReconScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[GITHUB-RECON] [INFO] Fetching GitHub Recon scans for scope target ID: %s", scopeTargetID)

	if scopeTargetID == "" {
		log.Printf("[GITHUB-RECON] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS github_recon_scans (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL UNIQUE,
			company_name TEXT NOT NULL,
			status VARCHAR(50) NOT NULL,
			result TEXT,
			error TEXT,
			stdout TEXT,
			stderr TEXT,
			command TEXT,
			execution_time TEXT,
			created_at TIMESTAMP DEFAULT NOW(),
			scope_target_id UUID REFERENCES scope_targets(id) ON DELETE CASCADE,
			auto_scan_session_id UUID REFERENCES auto_scan_sessions(id) ON DELETE SET NULL
		);`
	_, err := dbPool.Exec(context.Background(), createTableQuery)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to create github_recon_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM github_recon_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan GitHubReconScanStatus
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.CompanyName,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
			&scan.ScopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[GITHUB-RECON] [ERROR] Error scanning GitHub Recon scan row: %v", err)
			continue
		}

		scanMap := map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"company_name":         scan.CompanyName,
			"status":               scan.Status,
			"result":               nullStringToString(scan.Result),
			"error":                nullStringToString(scan.Error),
			"stdout":               nullStringToString(scan.StdOut),
			"stderr":               nullStringToString(scan.StdErr),
			"command":              nullStringToString(scan.Command),
			"execution_time":       nullStringToString(scan.ExecTime),
			"created_at":           scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id":      scan.ScopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		}
		scans = append(scans, scanMap)
	}

	log.Printf("[GITHUB-RECON] [INFO] Successfully retrieved %d GitHub Recon scans for scope target %s", len(scans), scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scans); err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to encode scans response: %v", err)
	} else {
		log.Printf("[GITHUB-RECON] [INFO] Successfully sent GitHub Recon scans response")
	}
}
