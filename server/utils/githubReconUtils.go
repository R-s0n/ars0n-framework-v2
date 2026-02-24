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
	"regexp"
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

	// Transform company name to domain-like format (lowercase, no spaces, no special characters)
	domainName := strings.ToLower(companyName)
	domainName = strings.ReplaceAll(domainName, " ", "")
	// Remove special characters using regex - keep only alphanumeric characters
	reg := regexp.MustCompile(`[^a-zA-Z0-9]`)
	domainName = reg.ReplaceAllString(domainName, "")
	log.Printf("[GITHUB-RECON] [INFO] Transformed company name '%s' to domain format '%s'", companyName, domainName)

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
	pythonCheckCmd := exec.Command("docker", "exec", "ars0n-framework-v2-github-recon-1", "ls", "-la", "/app/github-search/github-endpoints.py")
	pythonCheckOutput, pythonCheckErr := pythonCheckCmd.Output()
	if pythonCheckErr != nil {
		log.Printf("[GITHUB-RECON] [DEBUG] Python script check failed: %v", pythonCheckErr)
	} else {
		log.Printf("[GITHUB-RECON] [DEBUG] Python script exists: %s", string(pythonCheckOutput))
	}

	// Debug: Check the script help to see available parameters
	helpCmd := exec.Command("docker", "exec", "ars0n-framework-v2-github-recon-1", "python3", "/app/github-search/github-endpoints.py", "-h")
	helpOutput, helpErr := helpCmd.Output()
	if helpErr != nil {
		log.Printf("[GITHUB-RECON] [DEBUG] Failed to get help output: %v", helpErr)
	} else {
		log.Printf("[GITHUB-RECON] [DEBUG] Script help output:\n%s", string(helpOutput))
	}

	// Construct the command with unbuffered Python output
	cmd := exec.Command("docker", "exec", "ars0n-framework-v2-github-recon-1", "python3", "-u", "/app/github-search/github-endpoints.py", "-d", domainName, "-t", apiKey)
	log.Printf("[GITHUB-RECON] [DEBUG] Executing command: %s", cmd.String())

	// Set up separate stdout and stderr pipes
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Add timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, "docker", "exec", "ars0n-framework-v2-github-recon-1", "python3", "-u", "/app/github-search/github-endpoints.py", "-d", domainName, "-t", apiKey)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	stdoutStr := stdout.String()
	stderrStr := stderr.String()

	log.Printf("[GITHUB-RECON] [DEBUG] Command stdout: %s", stdoutStr)
	log.Printf("[GITHUB-RECON] [DEBUG] Command stderr: %s", stderrStr)

	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to execute GitHub Recon scan: %v", err)
		log.Printf("[GITHUB-RECON] [ERROR] Command that failed: %s", cmd.String())
		UpdateGitHubReconScanStatus(scanID, "error", "", "", stderrStr, cmd.String(), time.Since(startTime).String())
		return
	}

	log.Printf("[GITHUB-RECON] [INFO] GitHub Recon scan completed successfully, processing output...")

	// Process the output to extract and validate domains
	domainMap := make(map[string]bool) // Use map for deduplication

	// Regex pattern for validating domain names
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

	// Additional regex to extract domains from URLs or other text
	urlDomainRegex := regexp.MustCompile(`(?:https?://)?(?:www\.)?([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,})`)

	// Common file extensions to exclude
	fileExtensions := []string{
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp", // Images
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", // Documents
		".js", ".css", ".html", ".htm", ".xml", ".json", ".yaml", ".yml", // Web files
		".zip", ".rar", ".tar", ".gz", ".7z", // Archives
		".mp4", ".avi", ".mov", ".mp3", ".wav", // Media
		".txt", ".log", ".md", ".readme", // Text files
		".php", ".asp", ".jsp", ".py", ".rb", ".go", ".java", // Code files
	}

	// Helper function to check if a string has a file extension
	isFileExtension := func(s string) bool {
		s = strings.ToLower(s)
		for _, ext := range fileExtensions {
			if strings.HasSuffix(s, ext) {
				return true
			}
		}
		return false
	}

	lines := strings.Split(stdoutStr, "\n")
	log.Printf("[GITHUB-RECON] [DEBUG] Processing %d lines of output", len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Skip if it looks like a file with extension
		if isFileExtension(line) {
			log.Printf("[GITHUB-RECON] [DEBUG] Skipping file: %s", line)
			continue
		}

		// Try to validate the line as a direct domain
		if domainRegex.MatchString(line) {
			// Convert to lowercase for consistency
			domain := strings.ToLower(line)
			domainMap[domain] = true
			log.Printf("[GITHUB-RECON] [DEBUG] Found valid domain: %s", domain)
		} else {
			// Try to extract domain from URL or other text
			matches := urlDomainRegex.FindAllStringSubmatch(line, -1)
			for _, match := range matches {
				if len(match) > 1 {
					domain := strings.ToLower(match[1])
					// Double-check the extracted domain isn't a file
					if !isFileExtension(domain) && domainRegex.MatchString(domain) {
						domainMap[domain] = true
						log.Printf("[GITHUB-RECON] [DEBUG] Extracted domain from line: %s -> %s", line, domain)
					}
				}
			}
		}
	}

	// Convert map to slice of domain objects
	domains := make([]map[string]interface{}, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, map[string]interface{}{
			"domain": domain,
			"source": "github_recon",
		})
	}

	log.Printf("[GITHUB-RECON] [DEBUG] Processed %d lines, found %d unique valid domains", len(lines), len(domains))

	// Create result object
	result := map[string]interface{}{
		"domains": domains,
		"meta": map[string]interface{}{
			"total":         len(domains),
			"raw_lines":     len(lines),
			"domains_found": len(domainMap),
		},
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("[GITHUB-RECON] [ERROR] Failed to marshal result: %v", err)
		UpdateGitHubReconScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), "", "", time.Since(startTime).String())
		return
	}

	// Update scan status with success
	UpdateGitHubReconScanStatus(scanID, "success", string(resultJSON), string(stdoutStr), "", "", time.Since(startTime).String())
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

	var scans []map[string]interface{}
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
