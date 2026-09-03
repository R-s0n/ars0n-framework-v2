package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
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

	// The per-target Company settings, from the ONE store the Settings screen and the MCP company tool
	// both write. Absent is the normal case and produces exactly the request and exactly the filters
	// this runner has always used.
	scopeTargetID := companyScopeTargetForScan(context.Background(), "ctl_company_scans", scanID, "ctl_company")
	tool, settings, notes := companyRunnerSettings(scopeTargetID, "ctl_company")
	plan := ctlCompanyPlanFor(companyName, settings)
	if plan.Configured {
		log.Printf("[CTL-COMPANY] [INFO] Running with stored Company settings for scope target %s: %s",
			scopeTargetID, companySettingsSummary(settings))
	}
	companyLogNotes("CTL-COMPANY", notes)

	// storedCommand is what the scan row records as "what did this actually run". It has always been
	// `GET <url>`; when settings were applied the preamble is appended so the request AND the runner
	// behaviour that is not visible in the URL are both on the record.
	//
	// It reads `notes` through the closure rather than taking a copy, so a note appended after a retry
	// or after the name filter is in whichever call happens later. There is deliberately no second
	// place notes are added from.
	requestURL := plan.RequestURL
	command := func() string {
		out := fmt.Sprintf("GET %s", requestURL)
		if preamble := companySettingsPreamble(tool, scopeTargetID, settings, notes); preamble != "" {
			out += "\n" + preamble
		}
		return out
	}
	// The ERROR paths stored an EMPTY command column before this change, and they still do for a target
	// that configured nothing. Only the success path has ever recorded the request, and adding one to
	// the error rows of every existing install would be a change nobody asked for.
	errorCommand := func() string {
		if companySettingsPreamble(tool, scopeTargetID, settings, notes) == "" {
			return ""
		}
		return command()
	}

	log.Printf("[CTL-COMPANY] [DEBUG] Requesting URL: %s", requestURL)

	client := &http.Client{Timeout: plan.Timeout}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to create HTTP request: %v", err)
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create HTTP request: %v", err), errorCommand(), time.Since(startTime).String())
		return
	}

	req.Header.Set("User-Agent", plan.UserAgent)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	// MEASURED CLIENT-SIDE TRAP, which is why this one header is switchable and the rest are not. Go's
	// http.Transport only transparently decompresses a response when IT set Accept-Encoding itself;
	// setting the header by hand hands the raw gzip bytes to json.Unmarshal. ON by default because
	// that is what this runner has always sent.
	if plan.SendAcceptEncoding {
		req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	}
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// THE RETRY LOOP IS A NO-OP AT THE DEFAULT. plan.Retries is 0 unless somebody set it, so this runs
	// the request exactly once and takes exactly the paths it always took. crt.sh 5xx responses were
	// measured coming back in 0.52 to 0.67 seconds, so three retries would add under two seconds to a
	// healthy run - and ctl_company, unlike the Wildcard ctl step, has NO certspotter fallback, so a
	// single 502 is a total zero for certificate-transparency root-domain discovery.
	//
	// A transport failure is retried on the same budget as a 5xx. It is at least as transient and it
	// currently ends the scan outright.
	var resp *http.Response
	for attempt := 0; ; attempt++ {
		resp, err = client.Do(req)
		retryable := err != nil || (resp != nil && resp.StatusCode >= 500)
		if !retryable || attempt >= plan.Retries {
			break
		}
		if resp != nil {
			resp.Body.Close()
		}
		log.Printf("[CTL-COMPANY] [INFO] crt.sh attempt %d/%d failed (retryable); waiting %s before retrying.",
			attempt+1, plan.Retries+1, plan.RetryBackoff)
		notes = append(notes, fmt.Sprintf("crt.sh attempt %d of %d failed and was retried.",
			attempt+1, plan.Retries+1))
		if plan.RetryBackoff > 0 {
			time.Sleep(plan.RetryBackoff)
		}
	}
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to make request to crt.sh: %v", err)
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to make request to crt.sh: %v", err), errorCommand(), time.Since(startTime).String())
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

		UpdateCTLCompanyScanStatus(scanID, "error", "", errorMsg, errorCommand(), time.Since(startTime).String())
		return
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to read response body: %v", err)
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read response body: %v", err), errorCommand(), time.Since(startTime).String())
		return
	}

	bodyString := string(bodyBytes)

	if strings.Contains(bodyString, "Sorry, something went wrong") ||
		strings.Contains(bodyString, "searches that would produce many results may never succeed") ||
		strings.Contains(bodyString, "crt.sh  Certificate Search") {
		log.Printf("[CTL-COMPANY] [WARN] crt.sh returned error page indicating too many results for company: %s", companyName)
		errorMsg := fmt.Sprintf("crt.sh query for '%s' returned too many results. The search was terminated by crt.sh because it would produce an excessive number of results. Try using a more specific company name or consider that this company may have too many certificates to process efficiently.", companyName)
		UpdateCTLCompanyScanStatus(scanID, "error", "", errorMsg, errorCommand(), time.Since(startTime).String())
		return
	}

	// name_value carries the certificate's SAN list and is decoded unconditionally, because decoding a
	// field costs nothing. It is only READ when includeSanNames is on, so the default result set is
	// byte-identical to before: common_name and nothing else.
	var results []ctlCompanyNames

	if err := json.Unmarshal(bodyBytes, &results); err != nil {
		log.Printf("[CTL-COMPANY] [ERROR] Failed to decode crt.sh response: %v", err)
		logLength := 500
		if len(bodyString) < logLength {
			logLength = len(bodyString)
		}
		log.Printf("[CTL-COMPANY] [DEBUG] Response body (first %d chars): %s", logLength, bodyString[:logLength])
		UpdateCTLCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to decode crt.sh response: %v. Response may not be valid JSON.", err), errorCommand(), time.Since(startTime).String())
		return
	}

	log.Printf("[CTL-COMPANY] [DEBUG] Received %d certificate entries from crt.sh", len(results))

	domains, filterNotes := ctlCompanyFilterDomains(plan, results)
	notes = append(notes, filterNotes...)
	companyLogNotes("CTL-COMPANY", filterNotes)

	result := strings.Join(domains, "\n")
	log.Printf("[CTL-COMPANY] [DEBUG] Final processed result contains %d unique domains", len(domains))
	log.Printf("[CTL-COMPANY] [DEBUG] Domains found: %v", domains)

	// THE ANTI-SILENT-NOTHING CONTROL, off by default because it changes a success into an error.
	// crt.sh answers a company it has never seen with HTTP 200 and a valid empty array, and the
	// filters above can empty a non-empty response, and both land today as a 'success' row with an
	// empty result column that consolidation then reads and contributes nothing from.
	if plan.FailOnZeroDomains && len(domains) == 0 {
		errorMsg := fmt.Sprintf("crt.sh returned %d certificate entries and none survived the name filters, "+
			"so this scan found zero root domains. failOnZeroDomains is on, so it is recorded as an error "+
			"rather than as a clean result: a scan that SAW nothing and a scan that FOUND nothing are not "+
			"the same answer.", len(results))
		UpdateCTLCompanyScanStatus(scanID, "error", "", errorMsg, errorCommand(), time.Since(startTime).String())
		return
	}

	UpdateCTLCompanyScanStatus(scanID, "success", result, "", command(), time.Since(startTime).String())
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

	var scans = []map[string]interface{}{}
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
