package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// HttpxScanStatus represents the status of a httpx scan
type HttpxScanStatus struct {
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

// TargetURL represents a target URL in the database
type TargetURL struct {
	ID                  string         `json:"id"`
	URL                 string         `json:"url"`
	Screenshot          sql.NullString `json:"screenshot"`
	StatusCode          int            `json:"status_code"`
	Title               sql.NullString `json:"title"`
	WebServer           sql.NullString `json:"web_server"`
	Technologies        []string       `json:"technologies"`
	ContentLength       int            `json:"content_length"`
	NewlyDiscovered     bool           `json:"newly_discovered"`
	NoLongerLive        bool           `json:"no_longer_live"`
	ScopeTargetID       string         `json:"scope_target_id"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	HasDeprecatedTLS    bool           `json:"has_deprecated_tls"`
	HasExpiredSSL       bool           `json:"has_expired_ssl"`
	HasMismatchedSSL    bool           `json:"has_mismatched_ssl"`
	HasRevokedSSL       bool           `json:"has_revoked_ssl"`
	HasSelfSignedSSL    bool           `json:"has_self_signed_ssl"`
	HasUntrustedRootSSL bool           `json:"has_untrusted_root_ssl"`
	HasWildcardTLS      bool           `json:"has_wildcard_tls"`
	FindingsJSON        []byte         `json:"findings_json"`
	HTTPResponse        sql.NullString `json:"http_response"`
	HTTPResponseHeaders []byte         `json:"http_response_headers"`
	DNSARecords         []string       `json:"dns_a_records"`
	DNSAAAARecords      []string       `json:"dns_aaaa_records"`
	DNSCNAMERecords     []string       `json:"dns_cname_records"`
	DNSMXRecords        []string       `json:"dns_mx_records"`
	DNSTXTRecords       []string       `json:"dns_txt_records"`
	DNSNSRecords        []string       `json:"dns_ns_records"`
	DNSPTRRecords       []string       `json:"dns_ptr_records"`
	DNSSRVRecords       []string       `json:"dns_srv_records"`
	KatanaResults       []byte         `json:"katana_results"`
	FfufResults         []byte         `json:"ffuf_results"`
	ROIScore            int            `json:"roi_score"`
}

type TargetURLResponse struct {
	ID                  string                 `json:"id"`
	URL                 string                 `json:"url"`
	Screenshot          sql.NullString         `json:"screenshot"`
	StatusCode          int                    `json:"status_code"`
	Title               sql.NullString         `json:"title"`
	WebServer           sql.NullString         `json:"web_server"`
	Technologies        []string               `json:"technologies"`
	ContentLength       int                    `json:"content_length"`
	NewlyDiscovered     bool                   `json:"newly_discovered"`
	NoLongerLive        bool                   `json:"no_longer_live"`
	ScopeTargetID       string                 `json:"scope_target_id"`
	CreatedAt           time.Time              `json:"created_at"`
	UpdatedAt           time.Time              `json:"updated_at"`
	HasDeprecatedTLS    bool                   `json:"has_deprecated_tls"`
	HasExpiredSSL       bool                   `json:"has_expired_ssl"`
	HasMismatchedSSL    bool                   `json:"has_mismatched_ssl"`
	HasRevokedSSL       bool                   `json:"has_revoked_ssl"`
	HasSelfSignedSSL    bool                   `json:"has_self_signed_ssl"`
	HasUntrustedRootSSL bool                   `json:"has_untrusted_root_ssl"`
	HasWildcardTLS      bool                   `json:"has_wildcard_tls"`
	FindingsJSON        []interface{}          `json:"findings_json"`
	HTTPResponse        sql.NullString         `json:"http_response"`
	HTTPResponseHeaders map[string]interface{} `json:"http_response_headers"`
	DNSARecords         []string               `json:"dns_a_records"`
	DNSAAAARecords      []string               `json:"dns_aaaa_records"`
	DNSCNAMERecords     []string               `json:"dns_cname_records"`
	DNSMXRecords        []string               `json:"dns_mx_records"`
	DNSTXTRecords       []string               `json:"dns_txt_records"`
	DNSNSRecords        []string               `json:"dns_ns_records"`
	DNSPTRRecords       []string               `json:"dns_ptr_records"`
	DNSSRVRecords       []string               `json:"dns_srv_records"`
	KatanaResults       []string               `json:"katana_results"`
	FfufResults         map[string]interface{} `json:"ffuf_results"`
	ROIScore            int                    `json:"roi_score"`
}

// RunHttpxScan handles the HTTP request to start a new httpx scan
func RunHttpxScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[DEBUG] Received httpx scan request")
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		log.Printf("[ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)
	log.Printf("[DEBUG] Processing httpx scan for domain: %s (wildcard: %s)", domain, wildcardDomain)

	// Get the scope target ID
	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s: %v", domain, err)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[DEBUG] Found scope target ID: %s", scopeTargetID)

	scanID := uuid.New().String()
	log.Printf("[DEBUG] Generated new scan ID: %s", scanID)

	insertQuery := `INSERT INTO httpx_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[DEBUG] Created new scan record in database")

	go ExecuteAndParseHttpxScan(scanID, domain)
	log.Printf("[DEBUG] Started httpx scan execution in background")

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
	log.Printf("[DEBUG] Sent scan ID response to client")
}

// ExecuteAndParseHttpxScan runs the httpx scan and processes its results
func ExecuteAndParseHttpxScan(scanID, domain string) {
	log.Printf("[INFO] Starting httpx scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get the rate limit from settings
	rateLimit := GetHttpxRateLimit()
	log.Printf("[INFO] Using rate limit of %d for HTTPX scan", rateLimit)

	// Get custom HTTP settings
	customUserAgent, customHeader := GetCustomHTTPSettings()
	log.Printf("[DEBUG] Custom User Agent: %s", customUserAgent)
	log.Printf("[DEBUG] Custom Header: %s", customHeader)

	// Get scope target ID
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM httpx_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scope target ID: %v", err)
		UpdateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get scope target ID: %v", err), "", time.Since(startTime).String())
		return
	}
	log.Printf("[DEBUG] Retrieved scope target ID: %s", scopeTargetID)

	// Get consolidated subdomains
	log.Printf("[DEBUG] Fetching consolidated subdomains from database")
	rows, err := dbPool.Query(context.Background(),
		`SELECT subdomain FROM consolidated_subdomains WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get consolidated subdomains: %v", err)
		UpdateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get consolidated subdomains: %v", err), "", time.Since(startTime).String())
		return
	}
	defer rows.Close()

	var domainsToScan []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			log.Printf("[ERROR] Failed to scan subdomain row: %v", err)
			continue
		}
		domainsToScan = append(domainsToScan, subdomain)
	}
	log.Printf("[DEBUG] Found %d subdomains to scan", len(domainsToScan))

	// If no consolidated subdomains found, use the base domain
	if len(domainsToScan) == 0 {
		log.Printf("[INFO] No consolidated subdomains found, using base domain: %s", domain)
		domainsToScan = []string{domain}
	}

	// Create temporary directory for domains file
	tempDir := filepath.Join("/tmp", fmt.Sprintf("httpx-%s", scanID))
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		log.Printf("[ERROR] Failed to create temp directory: %v", err)
		UpdateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create temp directory: %v", err), "", time.Since(startTime).String())
		return
	}
	log.Printf("[DEBUG] Created temporary directory: %s", tempDir)
	defer func() {
		log.Printf("[DEBUG] Cleaning up temporary directory: %s", tempDir)
		os.RemoveAll(tempDir)
	}()

	// Write domains to file
	domainsFile := filepath.Join(tempDir, "domains.txt")
	outputFile := filepath.Join(tempDir, "httpx-output.json")
	if err := os.WriteFile(domainsFile, []byte(strings.Join(domainsToScan, "\n")), 0644); err != nil {
		log.Printf("[ERROR] Failed to write domains file: %v", err)
		UpdateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to write domains file: %v", err), "", time.Since(startTime).String())
		return
	}
	log.Printf("[DEBUG] Wrote %d domains to file: %s", len(domainsToScan), domainsFile)

	ports := []int{80, 443, 7547, 8089, 8085, 8443, 8080, 4567, 7170, 8008, 2083, 8000, 2082, 8081, 2087, 2086, 8888, 8880, 60000, 40000, 9080, 5985, 9100, 2096, 3000, 1024, 30005, 81, 21, 5000, 2095}
	portStrings := make([]string, len(ports))
	for i, port := range ports {
		portStrings[i] = fmt.Sprintf("%d", port)
	}
	portsFlag := strings.Join(portStrings, ",")

	dockerCmd := []string{
		"docker", "exec",
		"ars0n-framework-v2-httpx-1",
		"httpx",
		"-l", filepath.Join("/tmp", fmt.Sprintf("httpx-%s", scanID), "domains.txt"),
		"-ports", portsFlag,
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-server",
		"-content-length",
		"-no-color",
		"-timeout", "10",
		"-retries", "2",
		"-rate-limit", fmt.Sprintf("%d", rateLimit),
		"-mc", "100,101,200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,421,422,423,424,426,428,429,431,451,500,501,502,503,504,505,506,507,508,510,511",
	}

	// Add custom headers if specified
	// HTTPX uses -H for both headers and user agent
	if customUserAgent != "" {
		dockerCmd = append(dockerCmd, "-H", fmt.Sprintf("User-Agent: %s", customUserAgent))
	}
	if customHeader != "" {
		dockerCmd = append(dockerCmd, "-H", customHeader)
	}

	// Add output file parameter
	dockerCmd = append(dockerCmd, "-o", filepath.Join("/tmp", fmt.Sprintf("httpx-%s", scanID), "httpx-output.json"))

	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("[DEBUG] Running command: %s", strings.Join(dockerCmd, " "))
	err = cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		errMsg := stderr.String()
		log.Printf("[ERROR] httpx scan failed for %s: %v\nStderr: %s", domain, err, errMsg)
		log.Printf("[DEBUG] Command stdout: %s", stdout.String())
		UpdateHttpxScanStatus(scanID, "error", "", errMsg, strings.Join(dockerCmd, " "), execTime)
		return
	}
	log.Printf("[DEBUG] httpx scan completed successfully in %s", execTime)

	// Read the output file
	log.Printf("[DEBUG] Reading output file: %s", outputFile)
	result, err := os.ReadFile(outputFile)
	if err != nil {
		log.Printf("[ERROR] Failed to read output file: %v", err)
		UpdateHttpxScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read output file: %v", err), strings.Join(dockerCmd, " "), execTime)
		return
	}

	resultStr := string(result)
	if resultStr == "" {
		log.Printf("[INFO] No results found in output file")
		UpdateHttpxScanStatus(scanID, "completed", "", "No results found", strings.Join(dockerCmd, " "), execTime)
		return
	}
	// Process results and update target URLs
	var liveURLs []string
	lines := strings.Split(resultStr, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var httpxResult map[string]interface{}
		if err := json.Unmarshal([]byte(line), &httpxResult); err != nil {
			log.Printf("[WARN] Failed to parse result line: %v", err)
			continue
		}

		if url, ok := httpxResult["url"].(string); ok {
			liveURLs = append(liveURLs, url)
			if err := UpdateTargetURLFromHttpx(scopeTargetID, httpxResult); err != nil {
				log.Printf("[WARN] Failed to store URL %s: %v", url, err)
			}
		}
	}
	log.Printf("[INFO] HTTPX scan complete - %d live URLs found and stored", len(liveURLs))

	// Mark URLs not found in this scan as no longer live
	if err := MarkOldTargetURLsAsNoLongerLive(scopeTargetID, liveURLs); err != nil {
		log.Printf("[WARN] Failed to mark old target URLs as no longer live: %v", err)
	}

	UpdateHttpxScanStatus(scanID, "success", resultStr, stderr.String(), strings.Join(dockerCmd, " "), execTime)
	log.Printf("[INFO] HTTPX scan completed in %s", execTime)
}

// UpdateHttpxScanStatus updates the status of a httpx scan in the database
func UpdateHttpxScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating httpx scan status for %s to %s", scanID, status)
	query := `UPDATE httpx_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update httpx scan status for %s: %v", scanID, err)
	}
}

// GetHttpxScanStatus retrieves the status of a httpx scan
func GetHttpxScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanID"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	var scan HttpxScanStatus
	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id 
		FROM httpx_scans WHERE scan_id = $1`
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
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(scan)
}

// GetHttpxScansForScopeTarget retrieves all httpx scans for a scope target
func GetHttpxScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id 
		FROM httpx_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to query httpx scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan HttpxScanStatus
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
			log.Printf("[ERROR] Failed to scan httpx row: %v", err)
			continue
		}

		// Convert to map to control JSON serialization
		scanMap := map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          "", // Default empty string
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt,
			"scope_target_id": scan.ScopeTargetID,
		}

		// Only set result if it's not null and not empty
		if scan.Result.Valid && scan.Result.String != "" {
			scanMap["result"] = scan.Result.String
		}

		scans = append(scans, scanMap)
	}

	w.Header().Set("Content-Type", "application/json")
	response := map[string]interface{}{
		"scans": scans,
		"count": len(scans),
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] Failed to encode response: %v", err)
	}
}

// ConsolidateSubdomains consolidates subdomains from various sources
func ConsolidateSubdomains(scopeTargetID string) ([]string, error) {
	log.Printf("[INFO] Starting consolidation for scope target ID: %s", scopeTargetID)

	var baseDomain string
	err := dbPool.QueryRow(context.Background(), `
		SELECT TRIM(LEADING '*.' FROM scope_target) 
		FROM scope_targets 
		WHERE id = $1`, scopeTargetID).Scan(&baseDomain)
	if err != nil {
		return nil, fmt.Errorf("failed to get base domain: %v", err)
	}
	log.Printf("[INFO] Base domain for consolidation: %s", baseDomain)

	uniqueSubdomains := make(map[string]bool)
	toolResults := make(map[string]int)

	// Special handling for Amass - get from subdomains table
	amassQuery := `
		SELECT s.subdomain 
		FROM subdomains s 
		JOIN amass_scans a ON s.scan_id = a.scan_id 
		WHERE a.scope_target_id = $1 
			AND a.status = 'success'
			AND a.created_at = (
				SELECT MAX(created_at) 
				FROM amass_scans 
				WHERE scope_target_id = $1 
					AND status = 'success'
			)`

	log.Printf("[DEBUG] Processing results from amass using subdomains table")
	amassRows, err := dbPool.Query(context.Background(), amassQuery, scopeTargetID)
	if err != nil && err != pgx.ErrNoRows {
		log.Printf("[ERROR] Failed to get Amass subdomains: %v", err)
	} else {
		count := 0
		for amassRows.Next() {
			var subdomain string
			if err := amassRows.Scan(&subdomain); err != nil {
				log.Printf("[ERROR] Failed to scan Amass subdomain: %v", err)
				continue
			}
			if strings.HasSuffix(subdomain, baseDomain) {
				if !uniqueSubdomains[subdomain] {
					log.Printf("[DEBUG] Found new subdomain from amass: %s", subdomain)
					count++
				}
				uniqueSubdomains[subdomain] = true
			}
		}
		amassRows.Close()
		toolResults["amass"] = count
		log.Printf("[INFO] Found %d new unique subdomains from amass", count)
	}

	// Handle other tools
	queries := []struct {
		query string
		table string
	}{
		{
			query: `
				SELECT result 
				FROM sublist3r_scans 
				WHERE scope_target_id = $1 
					AND status = 'completed' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "sublist3r",
		},
		{
			query: `
				SELECT result 
				FROM assetfinder_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "assetfinder",
		},
		{
			query: `
				SELECT result 
				FROM ctl_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "ctl",
		},
		{
			query: `
				SELECT result 
				FROM subfinder_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "subfinder",
		},
		{
			query: `
				SELECT result 
				FROM gau_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "gau",
		},
		{
			query: `
				SELECT result 
				FROM shuffledns_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "shuffledns",
		},
		{
			query: `
				SELECT result 
				FROM shufflednscustom_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "shuffledns_custom",
		},
		{
			query: `
				SELECT result 
				FROM gospider_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "gospider",
		},
		{
			query: `
				SELECT result 
				FROM subdomainizer_scans 
				WHERE scope_target_id = $1 
					AND status = 'success' 
					AND result IS NOT NULL 
					AND result != '' 
				ORDER BY created_at DESC 
				LIMIT 1`,
			table: "subdomainizer",
		},
	}

	for _, q := range queries {
		log.Printf("[DEBUG] Processing results from %s", q.table)
		var result sql.NullString
		err := dbPool.QueryRow(context.Background(), q.query, scopeTargetID).Scan(&result)
		if err != nil {
			if err == pgx.ErrNoRows {
				log.Printf("[DEBUG] No results found for %s", q.table)
				continue
			}
			log.Printf("[ERROR] Failed to get results from %s: %v", q.table, err)
			continue
		}

		if !result.Valid || result.String == "" {
			log.Printf("[DEBUG] No valid results found for %s", q.table)
			continue
		}

		count := 0
		if q.table == "gau" {
			lines := strings.Split(result.String, "\n")
			log.Printf("[DEBUG] Processing %d lines from GAU", len(lines))
			for i, line := range lines {
				if line == "" {
					continue
				}
				var gauResult struct {
					URL string `json:"url"`
				}
				if err := json.Unmarshal([]byte(line), &gauResult); err != nil {
					log.Printf("[ERROR] Failed to parse GAU result line %d: %v", i, err)
					continue
				}
				if gauResult.URL == "" {
					continue
				}
				parsedURL, err := url.Parse(gauResult.URL)
				if err != nil {
					log.Printf("[ERROR] Failed to parse URL %s: %v", gauResult.URL, err)
					continue
				}
				hostname := parsedURL.Hostname()
				if strings.HasSuffix(hostname, baseDomain) {
					if !uniqueSubdomains[hostname] {
						log.Printf("[DEBUG] Found new subdomain from GAU: %s", hostname)
						count++
					}
					uniqueSubdomains[hostname] = true
				}
			}
		} else {
			lines := strings.Split(result.String, "\n")
			log.Printf("[DEBUG] Processing %d lines from %s", len(lines), q.table)
			for _, line := range lines {
				subdomain := strings.TrimSpace(line)
				if subdomain == "" {
					continue
				}
				if strings.HasSuffix(subdomain, baseDomain) {
					if !uniqueSubdomains[subdomain] {
						log.Printf("[DEBUG] Found new subdomain from %s: %s", q.table, subdomain)
						count++
					}
					uniqueSubdomains[subdomain] = true
				}
			}
		}
		toolResults[q.table] = count
		log.Printf("[INFO] Found %d new unique subdomains from %s", count, q.table)
	}

	var consolidatedSubdomains []string
	for subdomain := range uniqueSubdomains {
		consolidatedSubdomains = append(consolidatedSubdomains, subdomain)
	}
	sort.Strings(consolidatedSubdomains)

	log.Printf("[INFO] Tool contribution breakdown:")
	for tool, count := range toolResults {
		log.Printf("- %s: %d subdomains", tool, count)
	}
	log.Printf("[INFO] Total unique subdomains found: %d", len(consolidatedSubdomains))

	// Update database
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	_, err = tx.Exec(context.Background(), `DELETE FROM consolidated_subdomains WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old consolidated subdomains: %v", err)
	}

	for _, subdomain := range consolidatedSubdomains {
		_, err = tx.Exec(context.Background(),
			`INSERT INTO consolidated_subdomains (scope_target_id, subdomain) VALUES ($1, $2)
			ON CONFLICT (scope_target_id, subdomain) DO NOTHING`,
			scopeTargetID, subdomain)
		if err != nil {
			return nil, fmt.Errorf("failed to insert consolidated subdomain: %v", err)
		}
	}

	if err := tx.Commit(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return consolidatedSubdomains, nil
}

// HandleConsolidateSubdomains handles the HTTP request to consolidate subdomains
func HandleConsolidateSubdomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	consolidatedSubdomains, err := ConsolidateSubdomains(scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to consolidate subdomains", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":      len(consolidatedSubdomains),
		"subdomains": consolidatedSubdomains,
	})
}

// GetConsolidatedSubdomains retrieves consolidated subdomains for a scope target
func GetConsolidatedSubdomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT subdomain FROM consolidated_subdomains WHERE scope_target_id = $1 ORDER BY subdomain ASC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to get consolidated subdomains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subdomains []string
	for rows.Next() {
		var subdomain string
		if err := rows.Scan(&subdomain); err != nil {
			continue
		}
		subdomains = append(subdomains, subdomain)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":      len(subdomains),
		"subdomains": subdomains,
	})
}

// UpdateTargetURLFromHttpx updates target URL information from httpx scan results
func getIntFromInterface(val interface{}) int {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		return 0
	default:
		return 0
	}
}

func getStringFromInterface(val interface{}) string {
	if val == nil {
		return ""
	}
	if str, ok := val.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", val)
}

func UpdateTargetURLFromHttpx(scopeTargetID string, httpxData map[string]interface{}) error {
	url, ok := httpxData["url"].(string)
	if !ok || url == "" {
		return fmt.Errorf("invalid or missing URL in httpx data")
	}

	url = NormalizeURL(url)
	
	statusCode := getIntFromInterface(httpxData["status_code"])
	title := getStringFromInterface(httpxData["title"])
	webServer := getStringFromInterface(httpxData["webserver"])
	contentLength := getIntFromInterface(httpxData["content_length"])
	
	var technologies []string
	if techInterface, ok := httpxData["tech"].([]interface{}); ok {
		for _, tech := range techInterface {
			if techStr, ok := tech.(string); ok {
				technologies = append(technologies, techStr)
			}
		}
	}

	// Create findings_json array from technologies
	findingsJSON := make([]map[string]interface{}, 0)
	for _, tech := range technologies {
		finding := map[string]interface{}{
			"type":        "technology",
			"name":        tech,
			"description": fmt.Sprintf("Technology detected: %s", tech),
			"severity":    "info",
		}
		findingsJSON = append(findingsJSON, finding)
	}
	findingsJSONBytes, err := json.Marshal(findingsJSON)
	if err != nil {
		log.Printf("[WARN] Failed to marshal findings JSON: %v", err)
		findingsJSONBytes = []byte("[]")
	}

	// Check if target URL exists and update accordingly
	var existingID string
	var isNoLongerLive bool
	err = dbPool.QueryRow(context.Background(),
		`SELECT id, no_longer_live FROM target_urls WHERE url = $1`,
		url).Scan(&existingID, &isNoLongerLive)

	if err == pgx.ErrNoRows {
		// Insert new target URL
		_, err = dbPool.Exec(context.Background(),
			`INSERT INTO target_urls (
				url, status_code, title, web_server, technologies, 
				content_length, scope_target_id, newly_discovered, no_longer_live,
				findings_json, roi_score
			) VALUES ($1, $2, $3, $4, $5::text[], $6, $7, true, false, $8::jsonb, 50)`,
			url,
			statusCode,
			title,
			webServer,
			technologies,
			contentLength,
			scopeTargetID,
			findingsJSONBytes)
		
		if err == nil {
			log.Printf("[STATUS_CODE] URL: %s | Status: %d | Inserted from HTTPX", url, statusCode)
		}
	} else if err == nil {
		// Update existing target URL
		updateQuery := `UPDATE target_urls SET 
			status_code = $1,
			title = $2,
			web_server = $3,
			technologies = $4::text[],
			content_length = $5,
			no_longer_live = false,
			newly_discovered = $6,
			updated_at = NOW(),
			findings_json = $7::jsonb
		WHERE id = $8`

		_, err = dbPool.Exec(context.Background(),
			updateQuery,
			statusCode,
			title,
			webServer,
			technologies,
			contentLength,
			isNoLongerLive, // If previously marked as no longer live, mark as newly discovered
			findingsJSONBytes,
			existingID)
		
		if err == nil {
			log.Printf("[STATUS_CODE] URL: %s | Status: %d | Updated from HTTPX", url, statusCode)
		}
	} else {
		return err
	}

	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	
	return nil
}

// MarkOldTargetURLsAsNoLongerLive marks URLs not found in recent scans as no longer live
func MarkOldTargetURLsAsNoLongerLive(scopeTargetID string, liveURLs []string) error {
	_, err := dbPool.Exec(context.Background(),
		`UPDATE target_urls SET 
			no_longer_live = true,
			newly_discovered = false,
			updated_at = NOW()
		WHERE scope_target_id = $1 
		AND url NOT IN (SELECT unnest($2::text[]))`,
		scopeTargetID, liveURLs)

	return err
}

// GetTargetURLsForScopeTarget retrieves all target URLs for a scope target
func GetTargetURLsForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `
		SELECT 
			id, 
			url, 
			scope_target_id,
			status_code,
			title,
			web_server,
			technologies,
			content_length, 
			findings_json, 
			katana_results, 
			ffuf_results,
			http_response,
			http_response_headers,
			has_deprecated_tls,
			has_expired_ssl,
			has_mismatched_ssl,
			has_revoked_ssl,
			has_self_signed_ssl,
			has_untrusted_root_ssl,
			dns_a_records,
			dns_aaaa_records,
			dns_cname_records,
			dns_mx_records,
			dns_txt_records,
			dns_ns_records,
			dns_ptr_records,
			dns_srv_records,
			roi_score,
			created_at,
			screenshot
		FROM target_urls 
		WHERE scope_target_id = $1 
		ORDER BY roi_score DESC, created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get target URLs: %v", err)
		http.Error(w, "Failed to get target URLs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var targetURLs []map[string]interface{}
	for rows.Next() {
		var (
			id                  string
			url                 string
			scopeTargetID       string
			statusCode          sql.NullInt32
			title               sql.NullString
			webServer           sql.NullString
			technologies        []string
			contentLength       sql.NullInt32
			findingsJSON        sql.NullString
			katanaResults       sql.NullString
			ffufResults         sql.NullString
			httpResponse        sql.NullString
			httpResponseHeaders sql.NullString
			hasDeprecatedTLS    bool
			hasExpiredSSL       bool
			hasMismatchedSSL    bool
			hasRevokedSSL       bool
			hasSelfSignedSSL    bool
			hasUntrustedRootSSL bool
			dnsARecords         []string
			dnsAAAARecords      []string
			dnsCNAMERecords     []string
			dnsMXRecords        []string
			dnsTXTRecords       []string
			dnsNSRecords        []string
			dnsPTRRecords       []string
			dnsSRVRecords       []string
			roiScore            float64
			createdAt           time.Time
			screenshot          sql.NullString
		)

		err := rows.Scan(
			&id,
			&url,
			&scopeTargetID,
			&statusCode,
			&title,
			&webServer,
			&technologies,
			&contentLength,
			&findingsJSON,
			&katanaResults,
			&ffufResults,
			&httpResponse,
			&httpResponseHeaders,
			&hasDeprecatedTLS,
			&hasExpiredSSL,
			&hasMismatchedSSL,
			&hasRevokedSSL,
			&hasSelfSignedSSL,
			&hasUntrustedRootSSL,
			&dnsARecords,
			&dnsAAAARecords,
			&dnsCNAMERecords,
			&dnsMXRecords,
			&dnsTXTRecords,
			&dnsNSRecords,
			&dnsPTRRecords,
			&dnsSRVRecords,
			&roiScore,
			&createdAt,
			&screenshot,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		targetURL := map[string]interface{}{
			"id":                     id,
			"url":                    url,
			"scope_target_id":        scopeTargetID,
			"status_code":            nullIntToInt(statusCode),
			"title":                  nullStringToString(title),
			"web_server":             nullStringToString(webServer),
			"technologies":           technologies,
			"content_length":         nullIntToInt(contentLength),
			"findings_json":          nullStringToString(findingsJSON),
			"katana_results":         nullStringToString(katanaResults),
			"ffuf_results":           nullStringToString(ffufResults),
			"http_response":          nullStringToString(httpResponse),
			"http_response_headers":  nullStringToString(httpResponseHeaders),
			"has_deprecated_tls":     hasDeprecatedTLS,
			"has_expired_ssl":        hasExpiredSSL,
			"has_mismatched_ssl":     hasMismatchedSSL,
			"has_revoked_ssl":        hasRevokedSSL,
			"has_self_signed_ssl":    hasSelfSignedSSL,
			"has_untrusted_root_ssl": hasUntrustedRootSSL,
			"dns_a_records":          dnsARecords,
			"dns_aaaa_records":       dnsAAAARecords,
			"dns_cname_records":      dnsCNAMERecords,
			"dns_mx_records":         dnsMXRecords,
			"dns_txt_records":        dnsTXTRecords,
			"dns_ns_records":         dnsNSRecords,
			"dns_ptr_records":        dnsPTRRecords,
			"dns_srv_records":        dnsSRVRecords,
			"roi_score":              roiScore,
			"created_at":             createdAt.Format(time.RFC3339),
			"screenshot":             nullStringToString(screenshot),
		}

		targetURLs = append(targetURLs, targetURL)
	}

	w.Header().Set("Content-Type", "application/json")
	if targetURLs == nil {
		targetURLs = make([]map[string]interface{}, 0)
	}
	json.NewEncoder(w).Encode(targetURLs)
}

// UpdateTargetURLROIScore updates the ROI score for a target URL
func UpdateTargetURLROIScore(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	targetID := vars["id"]
	if targetID == "" {
		http.Error(w, "Target URL ID is required", http.StatusBadRequest)
		return
	}

	var payload struct {
		ROIScore int `json:"roi_score"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	query := `UPDATE target_urls SET roi_score = $1 WHERE id = $2`
	_, err := dbPool.Exec(context.Background(), query, payload.ROIScore, targetID)
	if err != nil {
		log.Printf("[ERROR] Failed to update ROI score: %v", err)
		http.Error(w, "Failed to update ROI score", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ConsolidateCompanyDomains consolidates company domains from various sources
func ConsolidateCompanyDomains(scopeTargetID string) ([]string, error) {
	log.Printf("[INFO] Starting company domain consolidation for scope target: %s", scopeTargetID)

	// Start a transaction
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		return nil, fmt.Errorf("failed to start transaction: %v", err)
	}
	defer tx.Rollback(context.Background())

	domainMap := make(map[string]string) // domain -> source

	// 1. Get domains from Google Dorking
	log.Printf("[INFO] Fetching Google Dorking domains...")
	googleRows, err := tx.Query(context.Background(),
		`SELECT domain FROM google_dorking_domains WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Google Dorking domains: %v", err)
	} else {
		defer googleRows.Close()
		for googleRows.Next() {
			var domain string
			if err := googleRows.Scan(&domain); err == nil {
				domainMap[domain] = "google_dorking"
			}
		}
	}

	// 2. Get domains from Reverse Whois
	log.Printf("[INFO] Fetching Reverse Whois domains...")
	whoisRows, err := tx.Query(context.Background(),
		`SELECT domain FROM reverse_whois_domains WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Reverse Whois domains: %v", err)
	} else {
		defer whoisRows.Close()
		for whoisRows.Next() {
			var domain string
			if err := whoisRows.Scan(&domain); err == nil {
				if _, exists := domainMap[domain]; !exists {
					domainMap[domain] = "reverse_whois"
				}
			}
		}
	}

	// 3. Get domains from CTL Company scans (most recent only)
	log.Printf("[INFO] Fetching CTL Company domains...")
	ctlRows, err := tx.Query(context.Background(),
		`SELECT result FROM ctl_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get CTL Company domains: %v", err)
	} else {
		defer ctlRows.Close()
		for ctlRows.Next() {
			var result string
			if err := ctlRows.Scan(&result); err == nil && result != "" {
				domains := strings.Split(result, "\n")
				for _, domain := range domains {
					domain = strings.TrimSpace(domain)
					if domain != "" {
						if _, exists := domainMap[domain]; !exists {
							domainMap[domain] = "ctl_company"
						}
					}
				}
			}
		}
	}

	// 4. Get domains from SecurityTrails Company scans (most recent only)
	log.Printf("[INFO] Fetching SecurityTrails Company domains...")
	stRows, err := tx.Query(context.Background(),
		`SELECT result FROM securitytrails_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get SecurityTrails Company domains: %v", err)
	} else {
		defer stRows.Close()
		for stRows.Next() {
			var result string
			if err := stRows.Scan(&result); err == nil && result != "" {
				var resultData map[string]interface{}
				if err := json.Unmarshal([]byte(result), &resultData); err == nil {
					if domains, ok := resultData["domains"].([]interface{}); ok {
						for _, d := range domains {
							if domain, ok := d.(string); ok {
								domain = strings.TrimSpace(domain)
								if domain != "" {
									if _, exists := domainMap[domain]; !exists {
										domainMap[domain] = "securitytrails_company"
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 5. Get domains from Censys Company scans (most recent only)
	log.Printf("[INFO] Fetching Censys Company domains...")
	censysRows, err := tx.Query(context.Background(),
		`SELECT result FROM censys_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Censys Company domains: %v", err)
	} else {
		defer censysRows.Close()
		for censysRows.Next() {
			var result string
			if err := censysRows.Scan(&result); err == nil && result != "" {
				var resultData map[string]interface{}
				if err := json.Unmarshal([]byte(result), &resultData); err == nil {
					if domains, ok := resultData["domains"].([]interface{}); ok {
						for _, d := range domains {
							if domain, ok := d.(string); ok {
								domain = strings.TrimSpace(domain)
								if domain != "" {
									if _, exists := domainMap[domain]; !exists {
										domainMap[domain] = "censys_company"
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 6. Get domains from GitHub Recon scans (most recent only)
	log.Printf("[INFO] Fetching GitHub Recon domains...")
	githubRows, err := tx.Query(context.Background(),
		`SELECT result FROM github_recon_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get GitHub Recon domains: %v", err)
	} else {
		defer githubRows.Close()
		for githubRows.Next() {
			var result string
			if err := githubRows.Scan(&result); err == nil && result != "" {
				var resultData map[string]interface{}
				if err := json.Unmarshal([]byte(result), &resultData); err == nil {
					if domains, ok := resultData["domains"].([]interface{}); ok {
						for _, d := range domains {
							if domain, ok := d.(string); ok {
								domain = strings.TrimSpace(domain)
								if domain != "" {
									if _, exists := domainMap[domain]; !exists {
										domainMap[domain] = "github_recon"
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 7. Get domains from Shodan Company scans (most recent only)
	log.Printf("[INFO] Fetching Shodan Company domains...")
	shodanRows, err := tx.Query(context.Background(),
		`SELECT result FROM shodan_company_scans 
		 WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL 
		 ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Shodan Company domains: %v", err)
	} else {
		defer shodanRows.Close()
		for shodanRows.Next() {
			var result string
			if err := shodanRows.Scan(&result); err == nil && result != "" {
				var resultData map[string]interface{}
				if err := json.Unmarshal([]byte(result), &resultData); err == nil {
					if domains, ok := resultData["domains"].([]interface{}); ok {
						for _, d := range domains {
							if domain, ok := d.(string); ok {
								domain = strings.TrimSpace(domain)
								if domain != "" {
									if _, exists := domainMap[domain]; !exists {
										domainMap[domain] = "shodan_company"
									}
								}
							}
						}
					}
				}
			}
		}
	}

	// 8. Get domains from Live Web Servers (from ASN network ranges)
	log.Printf("[INFO] Fetching Live Web Server domains from ASN scans...")
	liveRows, err := tx.Query(context.Background(),
		`SELECT DISTINCT lws.url 
		 FROM live_web_servers lws
		 JOIN ip_port_scans ips ON lws.scan_id = ips.scan_id
		 WHERE ips.scope_target_id = $1 AND ips.status = 'success' 
		 AND (lws.url IS NOT NULL AND lws.url != '')`,
		scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get Live Web Server domains: %v", err)
	} else {
		defer liveRows.Close()
		for liveRows.Next() {
			var url string
			if err := liveRows.Scan(&url); err == nil {
				// Extract domain from URL
				if url != "" {
					if domain := extractDomainFromURLInConsolidation(url); domain != "" && !isIPv4AddressInConsolidation(domain) {
						if _, exists := domainMap[domain]; !exists {
							domainMap[domain] = "live_web_servers"
						}
					}
				}
			}
		}
	}

	// Convert to sorted slice
	var consolidatedDomains []string
	for domain := range domainMap {
		consolidatedDomains = append(consolidatedDomains, domain)
	}
	sort.Strings(consolidatedDomains)

	log.Printf("[INFO] Total unique company domains found: %d", len(consolidatedDomains))

	// Clear old consolidated domains and insert new ones
	_, err = tx.Exec(context.Background(), `DELETE FROM consolidated_company_domains WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to delete old consolidated company domains: %v", err)
	}

	for _, domain := range consolidatedDomains {
		source := domainMap[domain]
		_, err = tx.Exec(context.Background(),
			`INSERT INTO consolidated_company_domains (scope_target_id, domain, source) VALUES ($1, $2, $3)
			 ON CONFLICT (scope_target_id, domain) DO NOTHING`,
			scopeTargetID, domain, source)
		if err != nil {
			return nil, fmt.Errorf("failed to insert consolidated company domain: %v", err)
		}
	}

	if err = tx.Commit(context.Background()); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %v", err)
	}

	return consolidatedDomains, nil
}

// HandleConsolidateCompanyDomains handles the HTTP request to consolidate company domains
func HandleConsolidateCompanyDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	consolidatedDomains, err := ConsolidateCompanyDomains(scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to consolidate company domains", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(consolidatedDomains),
		"domains": consolidatedDomains,
	})
}

// GetConsolidatedCompanyDomains retrieves consolidated company domains for a scope target
func GetConsolidatedCompanyDomains(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT domain FROM consolidated_company_domains WHERE scope_target_id = $1 ORDER BY domain ASC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to get consolidated company domains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			continue
		}
		domains = append(domains, domain)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"count":   len(domains),
		"domains": domains,
	})
}

// Helper functions for live web server domain extraction in consolidation
func isIPv4AddressInConsolidation(s string) bool {
	return strings.Contains(s, ".") &&
		len(strings.Split(s, ".")) == 4 &&
		!strings.Contains(s, " ")
}

func extractDomainFromURLInConsolidation(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "http://" + urlStr
	}

	// Simple domain extraction from URL
	parts := strings.Split(urlStr, "/")
	if len(parts) >= 3 {
		hostPart := parts[2]
		// Remove port if present
		if colonIndex := strings.Index(hostPart, ":"); colonIndex != -1 {
			hostPart = hostPart[:colonIndex]
		}
		return hostPart
	}
	return ""
}
