package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type CTLCompanyScanStatus struct {
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

func RunCTLCompanyScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[CTL-COMPANY] [INFO] Starting CTL Company scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[CTL-COMPANY] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[CTL-COMPANY] [INFO] Processing CTL Company scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[CTL-COMPANY] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[CTL-COMPANY] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS ctl_company_scans (
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
		log.Printf("[CTL-COMPANY] [ERROR] Failed to create ctl_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[CTL-COMPANY] [INFO] Ensured ctl_company_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO ctl_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO ctl_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[CTL-COMPANY] [INFO] Successfully created CTL Company scan record in database")

	go ExecuteAndParseCTLCompanyScan(scanID, companyName)

	log.Printf("[CTL-COMPANY] [INFO] CTL Company scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseCTLCompanyScan(scanID, companyName string) {
	log.Printf("[CTL-COMPANY] [INFO] Starting CTL Company scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	encodedCompanyName := url.QueryEscape(companyName)
	requestURL := fmt.Sprintf("https://crt.sh/?O=%s&output=json", encodedCompanyName)
	log.Printf("[CTL-COMPANY] [DEBUG] Requesting URL: %s", requestURL)

	client := &http.Client{Timeout: 60 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to create HTTP request: %v", err)
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create HTTP request: %v", err), "", time.Since(startTime).String())
		return
	}

	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to make request to crt.sh: %v", err)
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to make request to crt.sh: %v", err), "", time.Since(startTime).String())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[CTL-COMPANY] [ERROR] crt.sh returned non-200 status code: %d", resp.StatusCode)

		var errorMsg string
		switch resp.StatusCode {
		case 503:
			errorMsg = fmt.Sprintf("crt.sh is temporarily unavailable (503 Service Unavailable). This typically occurs when:\n\n• crt.sh servers are experiencing high load or maintenance\n• The query for '%s' would return too many results and was rejected\n• Database timeout occurred due to query complexity\n\nRecommendations:\n• Try again in a few minutes\n• Use a more specific company name if '%s' is too broad\n• Consider that large companies may have thousands of certificates", companyName, companyName)
		case 400:
			errorMsg = fmt.Sprintf("crt.sh rejected the request (400 Bad Request). This usually means:\n\n• Invalid characters in company name '%s'\n• Query format is not accepted by crt.sh\n• Company name contains special characters that need encoding\n\nRecommendations:\n• Try using only alphanumeric characters\n• Remove special symbols from the company name\n• Use a simplified version of the company name", companyName)
		case 429:
			errorMsg = fmt.Sprintf("crt.sh rate limit exceeded (429 Too Many Requests). This means:\n\n• Too many requests have been made to crt.sh recently\n• Your IP address is temporarily blocked\n\nRecommendations:\n• Wait 5-10 minutes before trying again\n• Avoid running multiple company scans simultaneously\n• Try again during off-peak hours")
		case 500:
			errorMsg = fmt.Sprintf("crt.sh internal server error (500 Internal Server Error). This indicates:\n\n• Technical issues on crt.sh servers\n• Database problems processing the query for '%s'\n• Unexpected error in their system\n\nRecommendations:\n• Try again in a few minutes\n• Check crt.sh status at https://crt.sh directly\n• Try a different company name to test if the issue is specific", companyName)
		case 502, 504:
			errorMsg = fmt.Sprintf("crt.sh gateway/timeout error (%d). This suggests:\n\n• Network connectivity issues to crt.sh\n• Proxy/gateway problems\n• Request timeout due to query complexity\n\nRecommendations:\n• Try again in a few minutes\n• Check your internet connection\n• Use a more specific company name to reduce query complexity", resp.StatusCode)
		default:
			errorMsg = fmt.Sprintf("crt.sh returned unexpected status code %d. This is an unusual error that may indicate:\n\n• New error condition not yet handled by our system\n• Temporary technical issues with crt.sh\n• Network connectivity problems\n\nRecommendations:\n• Try again in a few minutes\n• Check if crt.sh is accessible at https://crt.sh\n• Contact support if the issue persists", resp.StatusCode)
		}

		UpdateCTLCompanyScanStatus(scanID, "error", "", errorMsg, "", time.Since(startTime).String())
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to read response body: %v", err)
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read response body: %v", err), "", time.Since(startTime).String())
		return
	}

	bodyString := string(bodyBytes)

	if strings.Contains(bodyString, "Sorry, something went wrong") ||
		strings.Contains(bodyString, "searches that would produce many results may never succeed") ||
		strings.Contains(bodyString, "crt.sh  Certificate Search") {
		log.Printf("[CTL-COMPANY] [WARN] crt.sh returned error page indicating too many results for company: %s", companyName)
		errorMsg := fmt.Sprintf("crt.sh query for '%s' returned too many results. The search was terminated by crt.sh because it would produce an excessive number of results. Try using a more specific company name or consider that this company may have too many certificates to process efficiently.", companyName)
		UpdateCTLCompanyScanStatus(scanID, "error", "", errorMsg, "", time.Since(startTime).String())
		return
	}

	var results []struct {
		CommonName string `json:"common_name"`
	}

	if err := json.Unmarshal(bodyBytes, &results); err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to decode crt.sh response: %v", err)
		logLength := 500
		if len(bodyString) < logLength {
			logLength = len(bodyString)
		}
		log.Printf("[CTL-COMPANY] [DEBUG] Response body (first %d chars): %s", logLength, bodyString[:logLength])
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to decode crt.sh response: %v. Response may not be valid JSON.", err), "", time.Since(startTime).String())
		return
	}

	log.Printf("[CTL-COMPANY] [DEBUG] Received %d certificate entries from crt.sh", len(results))

	uniqueDomains := make(map[string]bool)
	for _, result := range results {
		domain := strings.ToLower(strings.TrimPrefix(result.CommonName, "*."))
		log.Printf("[CTL-COMPANY] [DEBUG] Processing domain: %s", domain)

		if domain == "" {
			continue
		}

		if strings.Contains(domain, " ") || strings.Contains(domain, ",") || strings.Contains(domain, "inc") {
			log.Printf("[CTL-COMPANY] [DEBUG] Skipping non-domain entry: %s", domain)
			continue
		}

		parts := strings.Split(domain, ".")
		if len(parts) >= 2 {
			lastPart := parts[len(parts)-1]
			if len(lastPart) >= 2 && len(lastPart) <= 6 {
				log.Printf("[CTL-COMPANY] [DEBUG] Keeping full domain: %s", domain)
				uniqueDomains[domain] = true
			} else {
				log.Printf("[CTL-COMPANY] [DEBUG] Skipping invalid TLD: %s", domain)
			}
		} else {
			log.Printf("[CTL-COMPANY] [DEBUG] Skipping entry without valid domain structure: %s", domain)
		}
	}

	var domains []string
	for domain := range uniqueDomains {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	result := strings.Join(domains, "\n")
	log.Printf("[CTL-COMPANY] [DEBUG] Final processed result contains %d unique domains", len(domains))
	log.Printf("[CTL-COMPANY] [DEBUG] Domains found: %v", domains)

	UpdateCTLCompanyScanStatus(scanID, "success", result, "", fmt.Sprintf("GET %s", requestURL), time.Since(startTime).String())
	log.Printf("[CTL-COMPANY] [INFO] CTL Company scan completed and results stored successfully for company %s", companyName)
}

func UpdateCTLCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[CTL-COMPANY] [INFO] Updating CTL Company scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE ctl_company_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to update CTL Company scan status for scan ID %s: %v", scanID, err)
		log.Printf("[CTL-COMPANY] [ERROR] Update attempted with: status=%s, result_length=%d, error_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[CTL-COMPANY] [INFO] Successfully updated CTL Company scan status to %s for scan ID %s", status, scanID)
	}
}

func GetCTLCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[CTL-COMPANY] [INFO] Retrieving CTL Company scan status for scan ID: %s", scanID)

	var scan CTLCompanyScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM ctl_company_scans WHERE scan_id = $1`
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
			log.Printf("[CTL-COMPANY] [ERROR] CTL Company scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[CTL-COMPANY] [ERROR] Failed to get CTL Company scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[CTL-COMPANY] [INFO] Successfully retrieved CTL Company scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[CTL-COMPANY] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
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
		log.Printf("[CTL-COMPANY] [ERROR] Failed to encode CTL Company scan response: %v", err)
	} else {
		log.Printf("[CTL-COMPANY] [INFO] Successfully sent CTL Company scan status response")
	}
}

func GetCTLCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[CTL-COMPANY] [INFO] Fetching CTL Company scans for scope target ID: %s", scopeTargetID)

	if scopeTargetID == "" {
		log.Printf("[CTL-COMPANY] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	// Ensure the table exists before trying to query it
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS ctl_company_scans (
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
		log.Printf("[CTL-COMPANY] [ERROR] Failed to create ctl_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM ctl_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan CTLCompanyScanStatus
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
			log.Printf("[CTL-COMPANY] [ERROR] Error scanning CTL Company scan row: %v", err)
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

	log.Printf("[CTL-COMPANY] [INFO] Successfully retrieved %d CTL Company scans for scope target %s", len(scans), scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scans); err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to encode scans response: %v", err)
	} else {
		log.Printf("[CTL-COMPANY] [INFO] Successfully sent CTL Company scans response")
	}
}
