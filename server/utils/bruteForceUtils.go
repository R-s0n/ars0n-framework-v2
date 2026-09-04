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
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
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

type CeWLScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	URL               string         `json:"url"`
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

func RunShuffleDNSScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN              string  `json:"fqdn" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
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
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO shuffledns_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO shuffledns_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
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
	// Per scan, not a fixed name. /tmp is a single named volume mounted into the api container
	// AND every tool container (docker-compose.yml), so a fixed path is shared storage: two runs
	// of this tool overwrite each other and each one's deferred RemoveAll deletes the other's
	// working files. The auto-scan single-flight guard does not cover this, because the manual
	// per-tool buttons reach the same code.
	tempDir := "/tmp/shuffledns-" + scanID
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
	// Per scan, not a fixed name. /tmp is a single named volume mounted into the api container
	// AND every tool container (docker-compose.yml), so a fixed path is shared storage: two runs
	// of this tool overwrite each other and each one's deferred RemoveAll deletes the other's
	// working files. The auto-scan single-flight guard does not cover this, because the manual
	// per-tool buttons reach the same code.
	tempDir := "/tmp/shuffledns-" + scanID
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

	shuffleSettings := wildcardStoredSettings(context.Background(),
		wildcardScopeTargetID(context.Background(),
			`SELECT scope_target_id::text FROM shuffledns_scans WHERE scan_id = $1`, scanID),
		"shuffledns")

	baseArgv := []string{
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
	}

	argv, configNotes := wildcardCommandWithSettings(baseArgv, "shuffledns", shuffleSettings)

	// PRECEDENCE, DECIDED AND RECORDED RATHER THAN LEFT TO IMPLEMENTATION ORDER. -t exists in two
	// places: user_settings.shuffledns_rate_limit (global, default 10000, what this runner has always
	// passed) and the per-target concurrency option. THE PER-TARGET VALUE WINS, because it is the
	// more specific of the two and because a target-level scan configuration that a global slider can
	// silently displace is a control that reports success and does nothing. The global remains the
	// default for every target with no per-target value, which is the no-settings path above.
	//
	// Worth repeating where an operator will see it: -t is NOT a rate limit. shuffledns' own help
	// calls it "Number of concurrent massdns resolves" and it maps onto massdns --hashmap-size. The
	// framework's own naming (GetShuffleDNSRateLimit, the shuffledns_rate_limit column, the Settings
	// slider) is wrong, and someone typing 10 expecting 10 queries per second gets a 1000x slowdown
	// across a 420,112-line wordlist.
	if _, ok := shuffleSettings["concurrency"]; ok {
		configNotes = append(configNotes, fmt.Sprintf(
			"concurrency (per-target Wildcard setting) took precedence over user_settings.shuffledns_rate_limit, "+
				"which is %d. Note that -t is in-flight concurrency, not queries per second.", rateLimit))
	}
	for _, note := range configNotes {
		log.Printf("[WARN] [ShuffleDNS config] %s", note)
	}

	cmd := exec.Command(argv[0], argv[1:]...)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] ShuffleDNS scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateShuffleDNSScanStatus(scanID, "error", "", wildcardAnnotatedStderr(stderr.String(), configNotes), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] ShuffleDNS scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from ShuffleDNS scan")
		UpdateShuffleDNSScanStatus(scanID, "completed", "", wildcardAnnotatedStderr("No results found", configNotes), cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] ShuffleDNS output: %s", result)
		UpdateShuffleDNSScanStatus(scanID, "success", result, wildcardAnnotatedStderr(stderr.String(), configNotes), cmd.String(), execTime)
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

	var scans = []map[string]interface{}{}
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

func RunCeWLScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN              string  `json:"fqdn" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
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
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO cewl_scans (scan_id, url, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO cewl_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
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

	// The stored Wildcard configuration for BOTH tools this function drives. The scope target is read
	// once up front rather than at the point the ShuffleDNS record is inserted, because the CeWL
	// crawl happens first and needs it too.
	scopeTargetID := wildcardScopeTargetID(context.Background(),
		`SELECT scope_target_id::text FROM cewl_scans WHERE scan_id = $1`, scanID)
	cewlSettings := wildcardStoredSettings(context.Background(), scopeTargetID, "cewl")
	shuffleSettings := wildcardStoredSettings(context.Background(), scopeTargetID, "shuffledns")

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
	// Per scan, not a fixed name. /tmp is a single named volume mounted into the api container
	// AND every tool container (docker-compose.yml), so a fixed path is shared storage: two runs
	// of this tool overwrite each other and each one's deferred RemoveAll deletes the other's
	// working files. The auto-scan single-flight guard does not cover this, because the manual
	// per-tool buttons reach the same code.
	tempDir := "/tmp/cewl-" + scanID
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create temp directory: %v", err)
		UpdateCeWLScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp directory: %v", err), "", time.Since(startTime).String())
		return
	}
	defer os.RemoveAll(tempDir)

	// Create temporary file for combined wordlist
	wordlistFile := filepath.Join(tempDir, "combined-wordlist.txt")
	wordSet := make(map[string]bool)

	// excludePaths is the one CeWL option that composes no flag, because CeWL's --exclude takes a
	// FILE of paths (cewl.rb:682-693 reads it line by line and compares each against
	// a_url_parsed.request_uri). A comma-joined value on the command line would be read as a filename
	// and match nothing at all, which is why the FLAG is runner owned while its CONTENT is the
	// operator's. Writing the file is therefore the runner's job and is done here.
	var configNotes []string
	var excludeArgs []string
	if raw, ok := cewlSettings["excludePaths"]; ok {
		if paths, valid := listSetting(raw); valid && len(paths) > 0 {
			excludeFile := filepath.Join(tempDir, "cewl-exclude.txt")
			// Same reasoning as the wordlist: the cewl container's /tmp is shared, so a fixed name
			// lets one scan's exclusion list silently govern another's crawl.
			containerExclude := "/tmp/cewl-exclude-" + scanID + ".txt"
			if err := os.WriteFile(excludeFile, []byte(strings.Join(paths, "\n")+"\n"), 0644); err != nil {
				configNotes = append(configNotes, "excludePaths was NOT applied: the exclusion file could not be "+
					"written on the host ("+err.Error()+"), so the crawl ran without it.")
			} else {
				copyExclude := exec.Command("docker", "cp", excludeFile,
					"ars0n-framework-v2-cewl-1:"+containerExclude)
				if err := copyExclude.Run(); err != nil {
					configNotes = append(configNotes, "excludePaths was NOT applied: the exclusion file could not "+
						"be copied into the CeWL container ("+err.Error()+"), so the crawl ran without it.")
				} else {
					excludeArgs = []string{"--exclude", containerExclude}
					log.Printf("[DEBUG] CeWL exclusion list written with %d paths", len(paths))
				}
			}
		}
	}

	// Every command actually executed, recorded on the scan row. UpdateCeWLScanStatus was previously
	// passed an empty string here, so a CeWL run stored no record of what it ran at all: with the
	// crawl now configurable, "what did this actually run" has to be answerable.
	var executedCommands []string

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
		baseArgs := []string{
			"docker", "exec",
			"ars0n-framework-v2-cewl-1",
			"timeout", "600",
			"ruby", "/app/cewl.rb",
			cleanURL,
			"-d", "2",
			"-m", "5",
			"-c",
			"--with-numbers",
		}

		// Add custom user agent if specified
		if customUserAgent != "" {
			baseArgs = append(baseArgs, "--ua", customUserAgent)
		}
		baseArgs = append(baseArgs, excludeArgs...)

		cmdArgs, urlNotes := wildcardCommandWithSettings(baseArgs, "cewl", cewlSettings)
		if len(executedCommands) == 0 {
			// The notes are identical for every URL in the loop, so they are logged and recorded once
			// rather than once per live host.
			for _, note := range urlNotes {
				log.Printf("[WARN] [CeWL config] %s", note)
			}
			configNotes = append(configNotes, urlNotes...)
		}
		executedCommands = append(executedCommands, strings.Join(cmdArgs, " "))

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

	// Named for the scan that will consume it. The previous fixed /tmp/wordlist.txt meant a second
	// CeWL run replaced the wordlist a first run's brute force was still reading, so shuffledns
	// silently resolved someone else's words and reported them as this target's subdomains.
	containerWordlist := "/tmp/wordlist-" + scanID + ".txt"

	// Copy wordlist to container
	copyCmd := exec.Command(
		"docker", "cp",
		wordlistFile,
		"ars0n-framework-v2-shuffledns-1:"+containerWordlist)
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
		"cat", containerWordlist,
	)
	var checkOutput bytes.Buffer
	checkCmd.Stdout = &checkOutput
	if err := checkCmd.Run(); err == nil {
		log.Printf("[DEBUG] Wordlist in container size: %d bytes", len(checkOutput.String()))
	}

	// Store the wordlist in CeWL results, WITH the commands that produced it. This column held an
	// empty string before, so a CeWL run left no record of what it ran.
	UpdateCeWLScanStatus(scanID, "success", strings.Join(wordlist, "\n"),
		wildcardAnnotatedStderr("", configNotes), strings.Join(executedCommands, "\n"),
		time.Since(startTime).String())

	// Start ShuffleDNS custom scan
	shuffleDNSScanID := uuid.New().String()
	log.Printf("[DEBUG] Starting ShuffleDNS custom scan with ID: %s", shuffleDNSScanID)

	if scopeTargetID == "" {
		log.Printf("[ERROR] Failed to get scope target ID for CeWL scan %s", scanID)
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

	// Run ShuffleDNS with the combined wordlist.
	//
	// THIS IS THE SECOND OF SHUFFLEDNS' TWO CALL SITES, and until now it honoured nothing at all: it
	// passes no -t, so it always ran at massdns' default 10000 whatever the operator chose, and any
	// config work that covered only bruteForceUtils.go:254 would leave half the runs ignoring it.
	//
	// -w IS RUNNER OWNED HERE SPECIFICALLY. /tmp/wordlist.txt is the wordlist CeWL just produced and
	// copied in, and it is the entire point of this invocation; a stored wordlist path would replace
	// it and silently turn the CeWL chain into an ordinary brute force against a different list.
	// Every other shuffledns setting applies normally.
	cewlShuffleSettings := shuffleSettings
	var shuffleNotes []string
	if _, ok := cewlShuffleSettings["wordlist"]; ok {
		trimmed := make(map[string]any, len(cewlShuffleSettings))
		for k, v := range cewlShuffleSettings {
			if k == "wordlist" {
				continue
			}
			trimmed[k] = v
		}
		cewlShuffleSettings = trimmed
		shuffleNotes = append(shuffleNotes, "The stored shuffledns wordlist was NOT applied to this run: "+
			"this invocation brute forces the wordlist CeWL just generated (/tmp/wordlist.txt), which is "+
			"what the CeWL step exists to produce. It applies to the standalone ShuffleDNS scan instead.")
	}

	baseShuffleArgv := []string{
		"docker", "exec",
		"ars0n-framework-v2-shuffledns-1",
		"shuffledns",
		"-d", domain,
		"-w", containerWordlist,
		"-r", "/app/wordlists/resolvers.txt",
		"-silent",
		"-massdns", "/usr/local/bin/massdns",
		"-mode", "bruteforce",
	}
	shuffleArgv, composedShuffleNotes := wildcardCommandWithSettings(baseShuffleArgv, "shuffledns", cewlShuffleSettings)
	shuffleNotes = append(shuffleNotes, composedShuffleNotes...)
	for _, note := range shuffleNotes {
		log.Printf("[WARN] [ShuffleDNS config] CeWL-fed run: %s", note)
	}

	shuffleCmd := exec.Command(shuffleArgv[0], shuffleArgv[1:]...)

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
		UpdateShuffleDNSCustomScanStatus(shuffleDNSScanID, "error", "", wildcardAnnotatedStderr(shuffleStderr.String(), shuffleNotes), shuffleCmd.String(), shuffleExecTime)
		return
	}

	shuffleResult := shuffleStdout.String()
	log.Printf("[DEBUG] ShuffleDNS stdout length: %d bytes", len(shuffleResult))
	if len(shuffleResult) > 0 {
		log.Printf("[DEBUG] ShuffleDNS results: %s", shuffleResult)
	}

	if shuffleResult == "" {
		log.Printf("[WARN] No results found from ShuffleDNS scan")
		UpdateShuffleDNSCustomScanStatus(shuffleDNSScanID, "completed", "", wildcardAnnotatedStderr("No results found", shuffleNotes), shuffleCmd.String(), shuffleExecTime)
	} else {
		log.Printf("[INFO] ShuffleDNS found results")
		UpdateShuffleDNSCustomScanStatus(shuffleDNSScanID, "success", shuffleResult, wildcardAnnotatedStderr(shuffleStderr.String(), shuffleNotes), shuffleCmd.String(), shuffleExecTime)
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
		"url":                  scan.URL,
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

	var scans = []map[string]interface{}{}
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
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"url":                  scan.URL,
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

	var scans = []map[string]interface{}{}
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
