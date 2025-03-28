package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type ShuffleDNSScanStatus struct {
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

type CeWLScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	URL           string         `json:"url"`
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

func RunShuffleDNSScan(w http.ResponseWriter, r *http.Request) {
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
	insertQuery := `INSERT INTO shuffledns_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseShuffleDNSScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func RunCeWLScansForUrls(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URLs []string `json:"urls" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.URLs) == 0 {
		http.Error(w, "Invalid request body. `urls` is required and must contain at least one URL.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO cewl_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, payload.URLs, "pending", nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseCeWLScansForUrls(scanID, payload.URLs)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func RunShuffleDNSWithWordlist(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Wordlist string `json:"wordlist" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Wordlist == "" {
		http.Error(w, "Invalid request body. `wordlist` is required.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO shuffledns_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, payload.Wordlist, "pending", nil)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseShuffleDNSWithWordlist(scanID, payload.Wordlist)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseShuffleDNSWithWordlist(scanID, wordlist string) {
	log.Printf("[INFO] Starting ShuffleDNS scan with wordlist (scan ID: %s)", scanID)
	startTime := time.Now()

	// Get the rate limit from settings
	rateLimit := GetShuffleDNSRateLimit()
	log.Printf("[INFO] Using ShuffleDNS rate limit: %d", rateLimit)

	// Create temporary directory for wordlist and resolvers
	tempDir := "/tmp/shuffledns-temp"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create temp directory: %v", err)
		UpdateShuffleDNSScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp directory: %v", err), "", time.Since(startTime).String())
		return
	}
	defer os.RemoveAll(tempDir)

	// Write wordlist to a temporary file
	wordlistFile := filepath.Join(tempDir, "wordlist.txt")
	if err := os.WriteFile(wordlistFile, []byte(wordlist), 0644); err != nil {
		log.Printf("[ERROR] Failed to write wordlist file: %v", err)
		UpdateShuffleDNSScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write wordlist file: %v", err), "", time.Since(startTime).String())
		return
	}

	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"shuffledns",
		"-d", wordlistFile,
		"-w", "/app/wordlists/all.txt",
		"-r", "/app/wordlists/resolvers.txt",
		"-silent",
		"-massdns", "/usr/local/bin/massdns",
		"-t", fmt.Sprintf("%d", rateLimit),
		"-mode", "bruteforce",
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] ShuffleDNS scan failed for wordlist: %v", err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateShuffleDNSScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] ShuffleDNS scan completed in %s for wordlist", execTime)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from ShuffleDNS scan")
		UpdateShuffleDNSScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] ShuffleDNS output: %s", result)
		UpdateShuffleDNSScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func ExecuteAndParseCeWLScansForUrls(scanID string, urls []string) {
	log.Printf("[INFO] Starting CeWL scans for URLs (scan ID: %s)", scanID)
	startTime := time.Now()

	for _, url := range urls {
		go ExecuteAndParseCeWLScan(scanID, url)
	}

	execTime := time.Since(startTime).String()
	log.Printf("[INFO] CeWL scans completed in %s", execTime)
}

func ExecuteAndParseShuffleDNSScan(scanID, domain string) {
	log.Printf("[INFO] Starting ShuffleDNS scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get the rate limit from settings
	rateLimit := GetShuffleDNSRateLimit()
	log.Printf("[INFO] Using ShuffleDNS rate limit: %d", rateLimit)

	// Create temporary directory for wordlist and resolvers
	tempDir := "/tmp/shuffledns-temp"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create temp directory: %v", err)
		UpdateShuffleDNSScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp directory: %v", err), "", time.Since(startTime).String())
		return
	}
	defer os.RemoveAll(tempDir)

	// Write domain to a temporary file
	domainFile := filepath.Join(tempDir, "domain.txt")
	if err := os.WriteFile(domainFile, []byte(domain), 0644); err != nil {
		log.Printf("[ERROR] Failed to write domain file: %v", err)
		UpdateShuffleDNSScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write domain file: %v", err), "", time.Since(startTime).String())
		return
	}

	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"shuffledns",
		"-d", domain,
		"-w", "/app/wordlists/all.txt",
		"-r", "/app/wordlists/resolvers.txt",
		"-silent",
		"-massdns", "/usr/local/bin/massdns",
		"-t", fmt.Sprintf("%d", rateLimit),
		"-mode", "bruteforce",
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] ShuffleDNS scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateShuffleDNSScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] ShuffleDNS scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from ShuffleDNS scan")
		UpdateShuffleDNSScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] ShuffleDNS output: %s", result)
		UpdateShuffleDNSScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateShuffleDNSScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating ShuffleDNS scan status for %s to %s", scanID, status)
	query := `UPDATE shuffledns_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update ShuffleDNS scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated ShuffleDNS scan status for %s", scanID)
	}
}

func GetShuffleDNSScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan ShuffleDNSScanStatus
	query := `SELECT * FROM shuffledns_scans WHERE scan_id = $1`
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

func GetShuffleDNSScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM shuffledns_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan ShuffleDNSScanStatus
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
			"scope_target_id": scan.ScopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunCeWLScan(w http.ResponseWriter, r *http.Request) {
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
	insertQuery := `INSERT INTO cewl_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseCeWLScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseCeWLScan(scanID, domain string) {
	log.Printf("[DEBUG] ====== Starting CeWL + ShuffleDNS Process ======")
	log.Printf("[DEBUG] ScanID: %s, Domain: %s", scanID, domain)
	startTime := time.Now()

	// Get custom HTTP settings
	customUserAgent, _ := GetCustomHTTPSettings() // CeWL only supports user agent
	log.Printf("[DEBUG] Custom User Agent: %s", customUserAgent)

	// First, get all live web servers from the latest httpx scan
	var httpxResults string
	err := dbPool.QueryRow(context.Background(), `
		SELECT result FROM httpx_scans 
		WHERE scope_target_id = (
			SELECT scope_target_id FROM cewl_scans WHERE scan_id = $1
		)
		AND status = 'success'
		ORDER BY created_at DESC 
		LIMIT 1`, scanID).Scan(&httpxResults)

	if err != nil {
		log.Printf("[ERROR] Failed to get httpx results: %v", err)
		UpdateCeWLScanStatus(scanID, "error", "", "Failed to get httpx results", "", time.Since(startTime).String())
		return
	}

	log.Printf("[DEBUG] Found httpx results length: %d bytes", len(httpxResults))

	// Process each live web server
	urls := strings.Split(httpxResults, "\n")
	log.Printf("[DEBUG] Processing %d URLs from httpx results", len(urls))

	// Create temporary directory for wordlist
	tempDir := "/tmp/cewl-temp"
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create temp directory: %v", err)
		UpdateCeWLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp directory: %v", err), "", time.Since(startTime).String())
		return
	}
	defer os.RemoveAll(tempDir)

	// Create temporary file for combined wordlist
	wordlistFile := filepath.Join(tempDir, "combined-wordlist.txt")
	wordSet := make(map[string]bool)

	// Process each URL
	for _, line := range urls {
		if line == "" {
			continue
		}

		var result struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("[WARN] Failed to parse httpx result line: %v", err)
			continue
		}

		if result.URL == "" {
			continue
		}

		// Remove www. from URL if present
		cleanURL := strings.Replace(result.URL, "www.", "", 1)

		// Build CeWL command
		cmdArgs := []string{
			"docker", "exec",
			"ars0n-framework-v2-cewl-1",
			"ruby", "/app/cewl.rb",
			cleanURL,
			"-d", "2",
			"-m", "5",
			"-c",
			"--with-numbers",
		}

		// Add custom user agent if specified
		if customUserAgent != "" {
			cmdArgs = append(cmdArgs, "--ua", customUserAgent)
		}

		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		log.Printf("[DEBUG] Running CeWL on URL: %s", cleanURL)
		err := cmd.Run()
		if err != nil {
			log.Printf("[WARN] CeWL failed for URL %s: %v", cleanURL, err)
			log.Printf("[WARN] stderr: %s", stderr.String())
			continue
		}

		output := stdout.String()

		// Process CeWL output
		words := strings.Split(output, "\n")
		wordCount := 0
		for _, line := range words {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			// Split on comma if it exists (CeWL outputs "word, count" format with -c flag)
			parts := strings.Split(line, ",")
			word := strings.TrimSpace(parts[0])

			// Basic word cleanup
			word = strings.ToLower(word)           // Convert to lowercase
			word = strings.Map(func(r rune) rune { // Remove non-alphanumeric chars
				if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
					return r
				}
				return -1
			}, word)

			// Validate word
			if word != "" && len(word) >= 3 && len(word) <= 20 && // Reasonable length
				!strings.ContainsAny(word, " \t") && // No whitespace
				!strings.Contains(word, "http") && // Skip URLs
				!strings.Contains(word, "www") { // Skip www
				wordSet[word] = true
				wordCount++
			}
		}

		log.Printf("[DEBUG] Processed %d words from URL %s", wordCount, cleanURL)
	}

	// Convert wordset to slice and sort
	var wordlist []string
	for word := range wordSet {
		wordlist = append(wordlist, word)
	}
	sort.Strings(wordlist)

	if len(wordlist) > 0 {
		previewSize := 10
		if len(wordlist) < previewSize {
			previewSize = len(wordlist)
		}
		log.Printf("[DEBUG] First %d words: %v", previewSize, wordlist[:previewSize])
	}

	if err := os.WriteFile(wordlistFile, []byte(strings.Join(wordlist, "\n")), 0644); err != nil {
		log.Printf("[ERROR] Failed to write combined wordlist: %v", err)
		UpdateCeWLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write wordlist: %v", err), "", time.Since(startTime).String())
		return
	}

	log.Printf("[DEBUG] Wordlist file written to: %s", wordlistFile)

	// Debug: Check wordlist file content
	if content, err := os.ReadFile(wordlistFile); err == nil {
		log.Printf("[DEBUG] Wordlist file size: %d bytes", len(content))
	}

	// Copy wordlist to container
	copyCmd := exec.Command(
		"docker", "cp",
		wordlistFile,
		"ars0n-framework-v2-shuffledns-1:/tmp/wordlist.txt")
	if err := copyCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to copy wordlist to container: %v", err)
		UpdateCeWLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to copy wordlist to container: %v", err), "", time.Since(startTime).String())
		return
	}

	log.Printf("[DEBUG] Wordlist copied to ShuffleDNS container")

	// Verify file in container
	checkCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"cat", "/tmp/wordlist.txt",
	)
	var checkOutput bytes.Buffer
	checkCmd.Stdout = &checkOutput
	if err := checkCmd.Run(); err == nil {
		log.Printf("[DEBUG] Wordlist in container size: %d bytes", len(checkOutput.String()))
	}

	// Store the wordlist in CeWL results
	UpdateCeWLScanStatus(scanID, "success", strings.Join(wordlist, "\n"), "", "", time.Since(startTime).String())

	// Start ShuffleDNS custom scan
	shuffleDNSScanID := uuid.New().String()
	log.Printf("[DEBUG] Starting ShuffleDNS custom scan with ID: %s", shuffleDNSScanID)

	// Get scope target ID
	var scopeTargetID string
	err = dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM cewl_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scope target ID: %v", err)
		return
	}

	log.Printf("[DEBUG] Found scope target ID: %s", scopeTargetID)

	// Insert ShuffleDNS custom scan record
	_, err = dbPool.Exec(context.Background(),
		`INSERT INTO shufflednscustom_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`,
		shuffleDNSScanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create ShuffleDNS custom scan record: %v", err)
		return
	}

	// Debug: Check resolvers file
	resolversCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"cat", "/app/wordlists/resolvers.txt",
	)
	var resolversOutput bytes.Buffer
	resolversCmd.Stdout = &resolversOutput
	if err := resolversCmd.Run(); err == nil {
		log.Printf("[DEBUG] Resolvers file size: %d bytes", len(resolversOutput.String()))
	} else {
		log.Printf("[ERROR] Failed to read resolvers file: %v", err)
	}

	// Run ShuffleDNS with the combined wordlist
	shuffleCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"shuffledns",
		"-d", domain,
		"-w", "/tmp/wordlist.txt",
		"-r", "/app/wordlists/resolvers.txt",
		"-silent",
		"-massdns", "/usr/local/bin/massdns",
		"-mode", "bruteforce",
	)

	var shuffleStdout, shuffleStderr bytes.Buffer
	shuffleCmd.Stdout = &shuffleStdout
	shuffleCmd.Stderr = &shuffleStderr

	log.Printf("[DEBUG] Running ShuffleDNS command: %s", shuffleCmd.String())
	err = shuffleCmd.Run()
	shuffleExecTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] ShuffleDNS custom scan failed: %v", err)
		log.Printf("[DEBUG] ShuffleDNS stderr: %s", shuffleStderr.String())
		log.Printf("[DEBUG] ShuffleDNS stdout: %s", shuffleStdout.String())
		UpdateShuffleDNSCustomScanStatus(shuffleDNSScanID, "error", "", shuffleStderr.String(), shuffleCmd.String(), shuffleExecTime)
		return
	}

	shuffleResult := shuffleStdout.String()
	log.Printf("[DEBUG] ShuffleDNS stdout length: %d bytes", len(shuffleResult))
	if len(shuffleResult) > 0 {
		log.Printf("[DEBUG] ShuffleDNS results: %s", shuffleResult)
	}

	if shuffleResult == "" {
		log.Printf("[WARN] No results found from ShuffleDNS scan")
		UpdateShuffleDNSCustomScanStatus(shuffleDNSScanID, "completed", "", "No results found", shuffleCmd.String(), shuffleExecTime)
	} else {
		log.Printf("[INFO] ShuffleDNS found results")
		UpdateShuffleDNSCustomScanStatus(shuffleDNSScanID, "success", shuffleResult, shuffleStderr.String(), shuffleCmd.String(), shuffleExecTime)
	}

	log.Printf("[DEBUG] ====== Completed CeWL + ShuffleDNS Process ======")
}

func UpdateCeWLScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating CeWL scan status for %s to %s", scanID, status)
	query := `UPDATE cewl_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update CeWL scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated CeWL scan status for %s", scanID)
	}
}

func GetCeWLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan CeWLScanStatus
	query := `SELECT * FROM cewl_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.URL,
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
		"url":             scan.URL,
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

func GetCeWLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM cewl_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan CeWLScanStatus
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.URL,
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
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"url":             scan.URL,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scan.ScopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func UpdateShuffleDNSCustomScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating ShuffleDNS custom scan status for %s to %s", scanID, status)
	query := `UPDATE shufflednscustom_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update ShuffleDNS custom scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated ShuffleDNS custom scan status for %s", scanID)
	}
}

func GetShuffleDNSCustomScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM shufflednscustom_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan ShuffleDNSScanStatus
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
			"scope_target_id": scan.ScopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
