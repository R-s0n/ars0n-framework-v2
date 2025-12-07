package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
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

// NucleiScreenshotStatus represents the status of a Nuclei screenshot scan
type NucleiScreenshotStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
	Status            string         `json:"status"`
	Result            sql.NullString `json:"result"`
	Error             sql.NullString `json:"error"`
	StdOut            sql.NullString `json:"stdout"`
	StdErr            sql.NullString `json:"stderr"`
	Command           sql.NullString `json:"command"`
	ExecTime          sql.NullString `json:"execution_time"`
	CreatedAt         time.Time      `json:"created_at"`
	ScopeTargetID     string         `json:"scope_target_id"`
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

// RunNucleiScreenshotScan handles the HTTP request to start a new Nuclei screenshot scan
func RunNucleiScreenshotScan(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	var payload struct {
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	log.Printf("[INFO] Starting Nuclei screenshot scan for scope target ID: %s", scopeTargetID)

	scanID := uuid.New().String()
	log.Printf("[INFO] Generated scan ID: %s", scanID)

	var domain string
	err := dbPool.QueryRow(context.Background(),
		`SELECT TRIM(LEADING '*.' FROM scope_target) FROM scope_targets WHERE id = $1`,
		scopeTargetID).Scan(&domain)
	if err != nil {
		log.Printf("[ERROR] Failed to get domain: %v", err)
		http.Error(w, "Failed to get domain", http.StatusInternalServerError)
		return
	}

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO nuclei_screenshots (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO nuclei_screenshots (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to insert scan record for scope target %s: %v", scopeTargetID, err)
		http.Error(w, fmt.Sprintf("Failed to insert scan record: %v", err), http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully inserted initial scan record for scan ID: %s", scanID)

	go ExecuteAndParseNucleiScreenshotScan(scanID, domain)

	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
	})
}

// ExecuteAndParseNucleiScreenshotScan runs the Nuclei screenshot scan and processes its results
func ExecuteAndParseNucleiScreenshotScan(scanID, domain string) {
	log.Printf("[INFO] Starting Nuclei screenshot scan execution for scan ID: %s", scanID)
	startTime := time.Now()

	// Get custom HTTP settings
	customUserAgent, customHeader := GetCustomHTTPSettings()
	log.Printf("[DEBUG] Custom User Agent: %s", customUserAgent)
	log.Printf("[DEBUG] Custom Header: %s", customHeader)

	// Get scope target ID and latest httpx results
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM nuclei_screenshots WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scope target ID: %v", err)
		UpdateNucleiScreenshotScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get scope target ID: %v", err), "", time.Since(startTime).String())
		return
	}

	// Get latest httpx results
	var httpxResults string
	err = dbPool.QueryRow(context.Background(), `
		SELECT result 
		FROM httpx_scans 
		WHERE scope_target_id = $1 
		AND status = 'success' 
		ORDER BY created_at DESC 
		LIMIT 1`, scopeTargetID).Scan(&httpxResults)
	if err != nil {
		log.Printf("[ERROR] Failed to get httpx results: %v", err)
		UpdateNucleiScreenshotScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get httpx results: %v", err), "", time.Since(startTime).String())
		return
	}

	// Process httpx results and get URLs
	var urls []string
	for _, line := range strings.Split(httpxResults, "\n") {
		if line == "" {
			continue
		}
		var result struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("[WARN] Failed to parse httpx result line for scan ID %s: %v", scanID, err)
			continue
		}
		if result.URL != "" {
			urls = append(urls, result.URL)
		}
	}

	log.Printf("[INFO] Processed %d URLs for scan ID: %s", len(urls), scanID)

	if len(urls) == 0 {
		log.Printf("[ERROR] No valid URLs found in httpx results for scan ID: %s", scanID)
		UpdateNucleiScreenshotScanStatus(scanID, "error", "", "No valid URLs found in httpx results", "", time.Since(startTime).String())
		return
	}

	// Build base command
	cmdArgs := []string{
		"docker", "exec", "ars0n-framework-v2-nuclei-1",
		"bash", "-c",
	}

	nucleiCmd := fmt.Sprintf("echo '%s' > /urls.txt && nuclei -t /root/nuclei-templates/headless/screenshot.yaml -list /urls.txt -headless -c 25 -rl 150 -timeout 10 -retries 1 -bs 25", strings.Join(urls, "\n"))

	// Add custom headers if specified
	if customHeader != "" {
		nucleiCmd += fmt.Sprintf(" -H '%s'", customHeader)
	}

	// Add custom user agent via header if specified
	if customUserAgent != "" {
		nucleiCmd += fmt.Sprintf(" -H 'User-Agent: %s'", customUserAgent)
	}

	cmdArgs = append(cmdArgs, nucleiCmd)
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	log.Printf("[INFO] Prepared Nuclei command for scan ID %s: %s", scanID, cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Execute the command
	log.Printf("[INFO] Executing Nuclei command for scan ID: %s", scanID)
	err = cmd.Run()
	if err != nil {
		log.Printf("[ERROR] Nuclei command failed for scan ID %s: %v", scanID, err)
		UpdateNucleiScreenshotScanStatus(
			scanID,
			"error",
			stdout.String(),
			fmt.Sprintf("Command failed: %v\nStderr: %s", err, stderr.String()),
			cmd.String(),
			time.Since(startTime).String(),
		)
		return
	}

	log.Printf("[INFO] Successfully completed Nuclei scan for scan ID: %s", scanID)
	log.Printf("[INFO] Scan duration for %s: %s", scanID, time.Since(startTime).String())

	// Read and process screenshot files
	var results []string
	screenshotFiles, err := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "ls", "/app/screenshots/").Output()
	if err != nil {
		log.Printf("[ERROR] Failed to list screenshot files for scan ID %s: %v", scanID, err)
		UpdateNucleiScreenshotScanStatus(
			scanID,
			"error",
			"",
			fmt.Sprintf("Failed to list screenshot files: %v", err),
			cmd.String(),
			time.Since(startTime).String(),
		)
		return
	}

	log.Printf("[DEBUG] Found screenshot files: %s", string(screenshotFiles))
	fileList := strings.Split(string(screenshotFiles), "\n")
	log.Printf("[DEBUG] Processing %d screenshot files", len(fileList))

	for _, file := range fileList {
		if file == "" || !strings.HasSuffix(file, ".png") {
			log.Printf("[DEBUG] Skipping invalid file: %s", file)
			continue
		}

		log.Printf("[DEBUG] Processing screenshot file: %s", file)

		// Read the screenshot file
		imgData, err := exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "cat", "/app/screenshots/"+file).Output()
		if err != nil {
			log.Printf("[WARN] Failed to read screenshot file %s: %v", file, err)
			continue
		}
		log.Printf("[DEBUG] Read screenshot file, size: %d bytes", len(imgData))

		// Convert the URL-safe filename back to a real URL
		url := strings.TrimSuffix(file, ".png")
		url = strings.ReplaceAll(url, "__", "://")
		url = strings.ReplaceAll(url, "_", ".")

		// Normalize the URL
		url = NormalizeURL(url)

		// Skip URLs with encoded characters that are nuclei test paths
		if strings.Contains(url, "%") {
			log.Printf("[DEBUG] Skipping nuclei test URL with encoded characters: %s", url)
			continue
		}

		log.Printf("[DEBUG] Processing screenshot for URL: %s", url)

		// Update target URL with screenshot
		screenshot := base64.StdEncoding.EncodeToString(imgData)
		log.Printf("[DEBUG] Base64 encoded screenshot size: %d bytes", len(screenshot))
		if err := UpdateTargetURLFromScreenshot(url, screenshot); err != nil {
			log.Printf("[WARN] Failed to update target URL screenshot for %s: %v", url, err)
		}

		// Create the result object for the scan results
		result := struct {
			Matched    string `json:"matched"`
			Screenshot string `json:"screenshot"`
			Timestamp  string `json:"timestamp"`
		}{
			Matched:    url,
			Screenshot: screenshot,
			Timestamp:  time.Now().Format(time.RFC3339),
		}

		// Convert to JSON and add to results
		jsonResult, err := json.Marshal(result)
		if err != nil {
			log.Printf("[WARN] Failed to marshal screenshot result for %s: %v", url, err)
			continue
		}
		results = append(results, string(jsonResult))
	}

	// Update scan status with results
	UpdateNucleiScreenshotScanStatus(
		scanID,
		"success",
		strings.Join(results, "\n"),
		stderr.String(),
		cmd.String(),
		time.Since(startTime).String(),
	)

	// Clean up screenshots in the container
	exec.Command("docker", "exec", "ars0n-framework-v2-nuclei-1", "rm", "-rf", "/app/screenshots/*").Run()
}

// UpdateNucleiScreenshotScanStatus updates the status of a Nuclei screenshot scan
func UpdateNucleiScreenshotScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Nuclei screenshot scan status for %s to %s", scanID, status)
	query := `UPDATE nuclei_screenshots SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Nuclei screenshot scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Nuclei screenshot scan status for %s", scanID)
	}
}

// GetNucleiScreenshotScanStatus retrieves the status of a Nuclei screenshot scan
func GetNucleiScreenshotScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan NucleiScreenshotStatus
	query := `SELECT * FROM nuclei_screenshots WHERE scan_id = $1`
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
		&scan.AutoScanSessionID,
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
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"domain":               scan.Domain,
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
	json.NewEncoder(w).Encode(response)
}

// GetNucleiScreenshotScansForScopeTarget retrieves all Nuclei screenshot scans for a scope target
func GetNucleiScreenshotScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `SELECT * FROM nuclei_screenshots WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan NucleiScreenshotStatus
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
			&scan.ScopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"domain":               scan.Domain,
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
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

// UpdateTargetURLFromScreenshot updates the screenshot for a target URL
func UpdateTargetURLFromScreenshot(url, screenshot string) error {
	log.Printf("[DEBUG] Updating screenshot for URL: %s", url)
	log.Printf("[DEBUG] Screenshot data length: %d", len(screenshot))

	// Normalize the URL
	url = NormalizeURL(url)
	log.Printf("[DEBUG] Normalized URL: %s", url)

	// Check if target URL exists
	var existingID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT id FROM target_urls WHERE url = $1`,
		url).Scan(&existingID)

	if err == pgx.ErrNoRows {
		log.Printf("[WARN] No target URL found for %s, cannot update screenshot", url)
		return fmt.Errorf("no target URL found for %s", url)
	} else if err != nil {
		log.Printf("[ERROR] Error checking for existing target URL: %v", err)
		return fmt.Errorf("error checking for existing target URL: %v", err)
	}

	log.Printf("[DEBUG] Found existing target URL with ID: %s", existingID)

	// Update the screenshot
	result, err := dbPool.Exec(context.Background(),
		`UPDATE target_urls SET 
			screenshot = $1,
			updated_at = NOW()
		WHERE id = $2`,
		screenshot, existingID)

	if err != nil {
		log.Printf("[ERROR] Failed to update target URL screenshot: %v", err)
		return fmt.Errorf("failed to update target URL screenshot: %v", err)
	}

	rowsAffected := result.RowsAffected()
	log.Printf("[DEBUG] Successfully updated screenshot for URL: %s (rows affected: %d)", url, rowsAffected)
	return nil
}
