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
	"sort"
	"strings"
	"time"

	"net/url"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type Sublist3rScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type AssetfinderScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type CTLScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type GauScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type SubfinderScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

func RunSublist3rScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Received request to run Sublist3r scan")
	var requestData struct {
		FQDN string `json:"fqdn"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	domain := requestData.FQDN
	wildcardDomain := "*." + domain
	log.Printf("[INFO] Processing Sublist3r scan request for domain: %s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s: %v", domain, err)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[INFO] Found matching scope target ID: %s", scopeTargetID)

	scanID := uuid.New().String()
	log.Printf("[INFO] Generated new scan ID: %s", scanID)

	insertQuery := `INSERT INTO sublist3r_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create Sublist3r scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully created Sublist3r scan record in database")

	go ExecuteAndParseSublist3rScan(scanID, domain)

	log.Printf("[INFO] Initiated Sublist3r scan with ID: %s for domain: %s", scanID, domain)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseSublist3rScan(scanID, domain string) {
	log.Printf("[INFO] Starting Sublist3r scan for domain %s (scan ID: %s)", domain, scanID)
	log.Printf("[DEBUG] Initializing scan variables and preparing command")
	startTime := time.Now()

	log.Printf("[DEBUG] Constructing docker command for Sublist3r")
	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-sublist3r-1",
		"python", "/app/sublist3r.py",
		"-d", domain,
		"-v",
		"-t", "50",
		"-o", "/dev/stdout",
	)

	log.Printf("[DEBUG] Docker command constructed: %s", cmd.String())
	log.Printf("[DEBUG] Setting up stdout and stderr buffers")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[INFO] Executing Sublist3r command at %s", time.Now().Format(time.RFC3339))
	log.Printf("[DEBUG] Command working directory: %s", cmd.Dir)
	log.Printf("[DEBUG] Command environment variables: %v", cmd.Env)

	err := cmd.Run()
	execTime := time.Since(startTime).String()
	log.Printf("[INFO] Command execution completed in %s", execTime)

	if err != nil {
		log.Printf("[ERROR] Sublist3r scan failed with error: %v", err)
		log.Printf("[ERROR] Error type: %T", err)
		if exitErr, ok := err.(*exec.ExitError); ok {
			log.Printf("[ERROR] Exit code: %d", exitErr.ExitCode())
		}
		log.Printf("[ERROR] Stderr output length: %d bytes", stderr.Len())
		log.Printf("[ERROR] Stderr output content: %s", stderr.String())
		log.Printf("[ERROR] Stdout output length: %d bytes", stdout.Len())
		log.Printf("[DEBUG] Updating scan status to error state")
		UpdateSublist3rScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	log.Printf("[INFO] Sublist3r scan completed successfully in %s", execTime)
	log.Printf("[DEBUG] Processing scan output")

	// Process the output
	lines := strings.Split(stdout.String(), "\n")
	log.Printf("[INFO] Processing %d lines of output", len(lines))

	// Use a map to handle deduplication
	uniqueSubdomains := make(map[string]bool)
	for _, line := range lines {
		// Clean the line by removing ANSI color codes and other control characters
		cleanLine := regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`).ReplaceAllString(line, "")
		cleanLine = strings.TrimSpace(cleanLine)

		// Skip empty lines, banner lines, and status messages
		if cleanLine == "" ||
			strings.Contains(cleanLine, "Sublist3r") ||
			strings.Contains(cleanLine, "==") ||
			strings.Contains(cleanLine, "Total Unique Subdomains Found:") ||
			strings.HasPrefix(cleanLine, "[-]") ||
			strings.HasPrefix(cleanLine, "[!]") ||
			strings.HasPrefix(cleanLine, "[~]") ||
			strings.HasPrefix(cleanLine, "[+]") {
			continue
		}

		// Remove "SSL Certificates: " prefix if present
		cleanLine = strings.TrimPrefix(cleanLine, "SSL Certificates: ")

		// If the line is a valid subdomain of our target domain, add it to our map
		if strings.HasSuffix(cleanLine, domain) {
			uniqueSubdomains[cleanLine] = true
		}
	}

	// Convert map keys to slice
	var finalSubdomains []string
	for subdomain := range uniqueSubdomains {
		finalSubdomains = append(finalSubdomains, subdomain)
	}

	// Sort the results for consistency
	sort.Strings(finalSubdomains)

	// Join the results with newlines
	result := strings.Join(finalSubdomains, "\n")
	log.Printf("[DEBUG] Final result string length: %d bytes", len(result))

	log.Printf("[INFO] Updating scan status in database for scan ID: %s", scanID)
	UpdateSublist3rScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)

	log.Printf("[INFO] Sublist3r scan completed successfully for domain %s (scan ID: %s)", domain, scanID)
	log.Printf("[INFO] Total execution time including processing: %s", time.Since(startTime))
}

func UpdateSublist3rScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Sublist3r scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE sublist3r_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Sublist3r scan status: %v", err)
		return
	}
	log.Printf("[INFO] Successfully updated Sublist3r scan status for scan ID %s", scanID)
}

func GetSublist3rScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan Sublist3rScanStatus
	query := `SELECT * FROM sublist3r_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
		&scan.ScopeTargetID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetSublist3rScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM sublist3r_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan Sublist3rScanStatus
		var scopeTargetID string
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
			&scopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunAssetfinderScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO assetfinder_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseAssetfinderScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseAssetfinderScan(scanID, domain string) {
	log.Printf("[INFO] Starting Assetfinder scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-assetfinder-1",
		"assetfinder",
		"--subs-only",
		domain,
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Assetfinder scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateAssetfinderScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] Assetfinder scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from Assetfinder scan")
		UpdateAssetfinderScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] Assetfinder output: %s", result)
		UpdateAssetfinderScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateAssetfinderScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Assetfinder scan status for %s to %s", scanID, status)
	query := `UPDATE assetfinder_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Assetfinder scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Assetfinder scan status for %s", scanID)
	}
}

func GetAssetfinderScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan AssetfinderScanStatus
	query := `SELECT * FROM assetfinder_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
		&scan.ScopeTargetID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetAssetfinderScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM assetfinder_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan AssetfinderScanStatus
		var scopeTargetID string
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
			&scopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunGauScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	// Get the scope target ID
	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO gau_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseGauScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseGauScan(scanID, domain string) {
	log.Printf("[INFO] Starting GAU scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get rate limit and custom HTTP settings
	rateLimit := GetGauRateLimit()
	_, _ = GetCustomHTTPSettings() // GAU doesn't support custom headers or user agent
	log.Printf("[INFO] Using rate limit of %d for GAU scan", rateLimit)
	log.Printf("[DEBUG] Note: GAU does not support custom headers or user agent")

	// Build base command
	dockerCmd := []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		domain,
		"--providers", "wayback",
		"--json",
		"--verbose",
		"--subs",
		"--threads", "10",
		"--timeout", "60",
		"--retries", "2",
	}

	// Note: GAU does not support custom headers or user agent
	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)

	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] GAU scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateGauScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] GAU scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))
	if stderr.Len() > 0 {
		log.Printf("[DEBUG] stderr output: %s", stderr.String())
	}

	// Check if we have actual results
	if result == "" {
		// Try a second attempt with different flags
		dockerCmd = []string{
			"docker", "run", "--rm",
			"sxcurity/gau:latest",
			domain,
			"--providers", "wayback,otx,urlscan",
			"--subs",
			"--threads", "5",
			"--timeout", "30",
			"--retries", "3",
		}

		log.Printf("[INFO] No results from first attempt, trying second attempt with command: %s", strings.Join(dockerCmd, " "))

		stdout.Reset()
		stderr.Reset()
		cmd = exec.Command(dockerCmd[0], dockerCmd[1:]...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()

		if err == nil {
			result = stdout.String()
		}
	}

	// Process results to limit the number of URLs if necessary
	if result != "" {
		lines := strings.Split(strings.TrimSpace(result), "\n")
		lineCount := len(lines)
		log.Printf("[INFO] GAU scan found %d URLs for domain %s", lineCount, domain)

		// Check if results exceed 1000 URLs
		if lineCount > 1000 {
			log.Printf("[INFO] Results exceed 1000 URLs, setting status to 'processing' while reducing to unique subdomains")

			// Update status to "processing" to let the frontend know we're still working
			UpdateGauScanStatus(scanID, "processing", "", "Processing large result set...", strings.Join(dockerCmd, " "), execTime)

			// Map to store unique subdomains and their representative URL
			uniqueSubdomains := make(map[string]string)

			// Process each URL to extract subdomains
			for _, line := range lines {
				if line == "" {
					continue
				}

				// Extract URL - handle both raw URLs and JSON format
				var urlStr string

				// First try to parse as JSON
				var gauResult struct {
					URL string `json:"url"`
				}

				if err := json.Unmarshal([]byte(line), &gauResult); err == nil && gauResult.URL != "" {
					// Successfully parsed as JSON
					urlStr = gauResult.URL
				} else if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
					// Line appears to be a raw URL
					urlStr = line
				} else {
					log.Printf("[ERROR] Failed to parse GAU result, not valid JSON or URL: %s", line)
					continue
				}

				// Extract subdomain from URL
				parsedURL, err := url.Parse(urlStr)
				if err != nil {
					log.Printf("[ERROR] Failed to parse URL %s: %v", urlStr, err)
					continue
				}

				hostname := parsedURL.Hostname()
				if hostname == "" {
					continue
				}

				// Store the first URL for each unique subdomain
				if _, exists := uniqueSubdomains[hostname]; !exists {
					// If it was raw URL, create proper JSON for storage
					if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
						jsonData, _ := json.Marshal(map[string]string{"url": line})
						uniqueSubdomains[hostname] = string(jsonData)
					} else {
						uniqueSubdomains[hostname] = line
					}
				}
			}

			// Build a new result string with only unique subdomain URLs
			var uniqueResults []string
			for _, jsonLine := range uniqueSubdomains {
				uniqueResults = append(uniqueResults, jsonLine)
			}

			// Replace the original result with the reduced set
			result = strings.Join(uniqueResults, "\n")
			log.Printf("[INFO] Reduced %d URLs to %d unique subdomain URLs", lineCount, len(uniqueResults))

			// Now update with the final result and set status to success
			UpdateGauScanStatus(scanID, "success", result, stderr.String(), strings.Join(dockerCmd, " "), execTime)
		} else {
			// If results don't exceed 1000, just update with success directly
			UpdateGauScanStatus(scanID, "success", result, stderr.String(), strings.Join(dockerCmd, " "), execTime)
		}
	} else {
		// Empty result, update with success status
		UpdateGauScanStatus(scanID, "success", result, stderr.String(), strings.Join(dockerCmd, " "), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateGauScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating GAU scan status for %s to %s", scanID, status)
	query := `UPDATE gau_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update GAU scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated GAU scan status for %s", scanID)
	}
}

func GetGauScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanID"]

	var scan GauScanStatus
	query := `SELECT * FROM gau_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
		&scan.ScopeTargetID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetGauScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM gau_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan GauScanStatus
		var scopeTargetID string
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
			&scopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunCTLScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Starting CTL scan request handling")
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		log.Printf("[ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	log.Printf("[INFO] Processing CTL scan for domain: %s", domain)
	wildcardDomain := fmt.Sprintf("*.%s", domain)
	log.Printf("[DEBUG] Constructed wildcard domain: %s", wildcardDomain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s: %v", domain, err)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[INFO] Found scope target ID: %s for domain: %s", scopeTargetID, domain)

	scanID := uuid.New().String()
	log.Printf("[INFO] Generated new scan ID: %s", scanID)
	insertQuery := `INSERT INTO ctl_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully created CTL scan record in database")

	go ExecuteAndParseCTLScan(scanID, domain)

	log.Printf("[INFO] CTL scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseCTLScan(scanID, domain string) {
	log.Printf("[INFO] Starting CTL scan execution for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Make HTTP request to crt.sh
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		log.Printf("[ERROR] Failed to make request to crt.sh: %v", err)
		UpdateCTLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to make request to crt.sh: %v", err), "", time.Since(startTime).String())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[ERROR] crt.sh returned non-200 status code: %d", resp.StatusCode)
		UpdateCTLScanStatus(scanID, "error", "", fmt.Sprintf("crt.sh returned status code: %d", resp.StatusCode), "", time.Since(startTime).String())
		return
	}

	var results []struct {
		NameValue string `json:"name_value"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		log.Printf("[ERROR] Failed to decode crt.sh response: %v", err)
		UpdateCTLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to decode crt.sh response: %v", err), "", time.Since(startTime).String())
		return
	}

	// Process and deduplicate results
	uniqueSubdomains := make(map[string]bool)
	for _, result := range results {
		// Convert to lowercase and remove wildcard prefix
		subdomain := strings.ToLower(strings.TrimPrefix(result.NameValue, "*."))
		if strings.HasSuffix(subdomain, domain) {
			uniqueSubdomains[subdomain] = true
		}
	}

	// Convert map to sorted slice
	var subdomains []string
	for subdomain := range uniqueSubdomains {
		subdomains = append(subdomains, subdomain)
	}
	sort.Strings(subdomains)

	// Join results with newlines
	result := strings.Join(subdomains, "\n")
	log.Printf("[DEBUG] Final processed result length: %d bytes", len(result))

	UpdateCTLScanStatus(scanID, "success", result, "", fmt.Sprintf("GET %s", url), time.Since(startTime).String())
	log.Printf("[INFO] CTL scan completed and results stored successfully for domain %s", domain)
}

func UpdateCTLScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating CTL scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE ctl_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update CTL scan status for scan ID %s: %v", scanID, err)
		log.Printf("[ERROR] Update attempted with: status=%s, result_length=%d, stderr_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[INFO] Successfully updated CTL scan status to %s for scan ID %s", status, scanID)
	}
}

func GetCTLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[INFO] Retrieving CTL scan status for scan ID: %s", scanID)

	var scan CTLScanStatus
	query := `SELECT * FROM ctl_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
		&scan.ScopeTargetID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[ERROR] CTL scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get CTL scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[INFO] Successfully retrieved CTL scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
	}

	response := map[string]interface{}{
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] Failed to encode CTL scan response: %v", err)
	} else {
		log.Printf("[INFO] Successfully sent CTL scan status response")
	}
}

func GetCTLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM ctl_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan CTLScanStatus
		var scopeTargetID string
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
			&scopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunSubfinderScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO subfinder_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseSubfinderScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseSubfinderScan(scanID, domain string) {
	log.Printf("[INFO] Starting Subfinder scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subfinder-1",
		"subfinder",
		"-d", domain,
		"-silent",
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Subfinder scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateSubfinderScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] Subfinder scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from Subfinder scan")
		UpdateSubfinderScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] Subfinder output: %s", result)
		UpdateSubfinderScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateSubfinderScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Subfinder scan status for %s to %s", scanID, status)
	query := `UPDATE subfinder_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Subfinder scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Subfinder scan status for %s", scanID)
	}
}

func GetSubfinderScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan SubfinderScanStatus
	query := `SELECT * FROM subfinder_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
		&scan.ScopeTargetID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetSubfinderScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM subfinder_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan SubfinderScanStatus
		var scopeTargetID string
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
			&scopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
