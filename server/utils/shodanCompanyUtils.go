package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type ShodanCompanyScanStatus struct {
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

type ShodanSearchResponse struct {
	Matches []ShodanMatch `json:"matches"`
	Total   int           `json:"total"`
}

type ShodanMatch struct {
	IP        interface{} `json:"ip"`
	Hostnames []string    `json:"hostnames"`
	SSL       *ShodanSSL  `json:"ssl,omitempty"`
	HTTP      *ShodanHTTP `json:"http,omitempty"`
	Org       string      `json:"org,omitempty"`
}

type ShodanSSL struct {
	Cert *ShodanCert `json:"cert,omitempty"`
}

type ShodanCert struct {
	Subject        *ShodanSubject `json:"subject,omitempty"`
	SubjectAltName []string       `json:"names,omitempty"`
}

type ShodanSubject struct {
	CN string `json:"CN,omitempty"`
	O  string `json:"O,omitempty"`
}

type ShodanHTTP struct {
	Host string `json:"host,omitempty"`
}

func RunShodanCompanyScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[SHODAN-COMPANY] [INFO] Starting Shodan Company scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[SHODAN-COMPANY] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[SHODAN-COMPANY] [INFO] Processing Shodan Company scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[SHODAN-COMPANY] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[SHODAN-COMPANY] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS shodan_company_scans (
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
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to create shodan_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[SHODAN-COMPANY] [INFO] Ensured shodan_company_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO shodan_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO shodan_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[SHODAN-COMPANY] [INFO] Successfully created Shodan Company scan record in database")

	go ExecuteShodanCompanyScan(scanID, companyName)

	log.Printf("[SHODAN-COMPANY] [INFO] Shodan Company scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteShodanCompanyScan(scanID, companyName string) {
	log.Printf("[SHODAN-COMPANY] [INFO] Starting Shodan Company scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	UpdateShodanCompanyScanStatus(scanID, "running", "", "", "", "")

	var apiKey string
	err := dbPool.QueryRow(context.Background(), `
		SELECT 
			(api_key_value::json->>'api_key')::text as api_key_value
		FROM api_keys 
		WHERE tool_name = 'Shodan' 
		ORDER BY created_at DESC 
		LIMIT 1
	`).Scan(&apiKey)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[SHODAN-COMPANY] [ERROR] No Shodan API credentials found in database")
			UpdateShodanCompanyScanStatus(scanID, "error", "", "No Shodan API credentials found. Please configure your API credentials in the settings.", "", time.Since(startTime).String())
		} else {
			log.Printf("[SHODAN-COMPANY] [ERROR] Failed to get Shodan API credentials: %v", err)
			UpdateShodanCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get Shodan API credentials: %v", err), "", time.Since(startTime).String())
		}
		return
	}

	if apiKey == "" {
		log.Printf("[SHODAN-COMPANY] [ERROR] Shodan API key is empty")
		UpdateShodanCompanyScanStatus(scanID, "error", "", "Shodan API key is empty. Please configure your API credentials in the settings.", "", time.Since(startTime).String())
		return
	}

	log.Printf("[SHODAN-COMPANY] [INFO] Successfully retrieved Shodan API key")

	// The per-target Company settings, from the ONE store the Settings screen and the MCP company tool
	// both write. Absent is the normal case and produces exactly the four queries, one page each, one
	// second apart, with no client timeout, that this runner has always made.
	scopeTargetID := companyScopeTargetForScan(
		context.Background(), "shodan_company_scans", scanID, "shodan_company")
	tool, settings, notes := companyRunnerSettings(scopeTargetID, "shodan_company")
	plan := shodanCompanyPlanFor(companyName, settings)
	if plan.Configured {
		log.Printf("[SHODAN-COMPANY] [INFO] Running with stored Company settings for scope target %s: %s",
			scopeTargetID, companySettingsSummary(settings))
	}

	domains, searchNotes, err := searchShodanForCompany(companyName, apiKey, plan)
	notes = append(notes, searchNotes...)
	companyLogNotes("SHODAN-COMPANY", notes)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to search Shodan for company %s: %v", companyName, err)
		UpdateShodanCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to search Shodan: %v", err), shodanCompanyCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
		return
	}

	log.Printf("[SHODAN-COMPANY] [INFO] Found %d unique domains for company %s", len(domains), companyName)

	result := map[string]interface{}{
		"domains": domains,
		"meta": map[string]interface{}{
			"total": len(domains),
		},
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to marshal result: %v", err)
		UpdateShodanCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), shodanCompanyCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
		return
	}

	UpdateShodanCompanyScanStatus(scanID, "success", string(resultJSON), "", shodanCompanyCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
	log.Printf("[SHODAN-COMPANY] [INFO] Successfully completed Shodan Company scan for company %s (scan ID: %s)", companyName, scanID)
}

// shodanCompanyCommand is what the scan row records as "what did this actually run". Empty unless
// something was configured, so a default scan's row is unchanged.
func shodanCompanyCommand(tool CompanyTool, plan shodanCompanyPlan, scopeTargetID string,
	settings map[string]any, notes []string) string {
	if len(settings) == 0 && len(notes) == 0 {
		return ""
	}
	// The API key is deliberately NOT reconstructed into this string. It travels in the QUERY STRING of
	// the real request, which is its own recorded defect (Shodan accepts it as a header and the runner
	// should use that), and there is no reason to copy it into the database as well.
	return "GET https://api.shodan.io/shodan/host/search?key=REDACTED&query=<each of: " +
		strings.Join(plan.Queries, " | ") + ">\n" +
		companySettingsPreamble(tool, scopeTargetID, settings, notes)
}

// searchShodanForCompany runs the configured queries and harvests names from the configured fields.
//
// IT NOW RETURNS A REAL ERROR, WHICH IT NEVER DID BEFORE. The old signature returned an error type
// and every failure path inside the loop was a log line followed by continue or break, so the caller
// always took the success branch. That is the headline finding for this tool: because the company
// name is interpolated into the query string UNENCODED, a multi-word company produces four HTTP 400s
// with empty bodies, all four are swallowed, and the scan is stored as 'success' with zero domains.
// failWhenAllQueriesFail is the switch that makes it visible; it is OFF by default, so the default
// behaviour is unchanged.
func searchShodanForCompany(companyName, apiKey string, plan shodanCompanyPlan) ([]string, []string, error) {
	log.Printf("[SHODAN-COMPANY] [INFO] Searching Shodan for company: %s", companyName)

	domainSet := make(map[string]bool)
	var notes []string
	succeeded, failed := 0, 0

	// Timeout 0 is http.DefaultClient's behaviour: NO deadline at all. That is what this runner has
	// always had and it is why a hung connection leaves the scan row stuck at 'running' forever with
	// nothing in the framework to clean it up. requestTimeoutSeconds is how an operator fixes it.
	client := &http.Client{Timeout: plan.Timeout}

	// A 429 ABANDONS EVERY REMAINING QUERY, not just the remaining pages of the current one. That is
	// what the runner has always done - `break` out of the query loop - and it is the right behaviour:
	// Shodan credits are a monthly allowance rather than a rate, so a 429 usually means the allowance
	// is gone and the next three queries would fail identically. The labelled break is what keeps the
	// per-page loop from quietly turning one abandoned scan into four more requests.
queries:
	for _, query := range plan.Queries {
		queryFailed := false
		rateLimited := false

		for page := 1; page <= plan.MaxPages; page++ {
			log.Printf("[SHODAN-COMPANY] [INFO] Executing Shodan query: %s (page %d)", query, page)
			requestURL := shodanCompanyRequestURL(apiKey, query, page)

			var body []byte
			var attemptErr error
			// The retry loop is a no-op at the default: plan.Retries is 0 unless somebody set it.
			for attempt := 0; ; attempt++ {
				body, rateLimited, attemptErr = shodanCompanyFetch(client, requestURL)
				if attemptErr == nil || rateLimited || attempt >= plan.Retries {
					break
				}
				notes = append(notes, fmt.Sprintf("Shodan query %q page %d attempt %d of %d failed and was "+
					"retried.", query, page, attempt+1, plan.Retries+1))
			}

			if rateLimited {
				log.Printf("[SHODAN-COMPANY] [WARN] Rate limit exceeded, stopping search")
				notes = append(notes, "Shodan returned 429. The remaining queries were ABANDONED. Query credits "+
					"are a monthly allowance rather than a rate, so this is usually an exhausted allowance "+
					"rather than a speed problem.")
				if plan.TreatRateLimitAsError {
					return nil, notes, fmt.Errorf("Shodan returned 429 and treatRateLimitAsError is on: this "+
						"scan is PARTIAL, having completed %d of %d queries. Storing it as a success would make "+
						"the next scan look like the company grew", succeeded, len(plan.Queries))
				}
				break queries
			}
			if attemptErr != nil {
				log.Printf("[SHODAN-COMPANY] [WARN] Shodan query '%s' page %d failed: %v", query, page, attemptErr)
				queryFailed = true
				break
			}

			var searchResp ShodanSearchResponse
			if err := json.Unmarshal(body, &searchResp); err != nil {
				log.Printf("[SHODAN-COMPANY] [WARN] Failed to parse JSON response for query '%s': %v", query, err)
				queryFailed = true
				break
			}

			log.Printf("[SHODAN-COMPANY] [INFO] Query '%s' page %d returned %d matches of %d total",
				query, page, len(searchResp.Matches), searchResp.Total)

			for _, match := range searchResp.Matches {
				if match.SSL != nil && match.SSL.Cert != nil {
					if plan.harvests("ssl.cert.subject.CN") &&
						match.SSL.Cert.Subject != nil && match.SSL.Cert.Subject.CN != "" {
						for _, name := range shodanCompanyNames(plan, match.SSL.Cert.Subject.CN) {
							domainSet[name] = true
						}
					}
					if plan.harvests("ssl.cert.names") {
						for _, san := range match.SSL.Cert.SubjectAltName {
							for _, name := range shodanCompanyNames(plan, san) {
								domainSet[name] = true
							}
						}
					}
				}

				if plan.harvests("hostnames") {
					for _, hostname := range match.Hostnames {
						for _, name := range shodanCompanyNames(plan, hostname) {
							domainSet[name] = true
						}
					}
				}

				if plan.harvests("http.host") && match.HTTP != nil && match.HTTP.Host != "" {
					for _, name := range shodanCompanyNames(plan, match.HTTP.Host) {
						domainSet[name] = true
					}
				}
			}

			// TRUNCATION IS RECORDED. searchResp.Total was decoded and thrown away before: not stored, not
			// logged, so nothing anywhere said that a query matched 12,000 hosts and 100 were read.
			if page >= plan.MaxPages && searchResp.Total > page*len(searchResp.Matches) && len(searchResp.Matches) > 0 {
				notes = append(notes, fmt.Sprintf(
					"TRUNCATED: Shodan reports %d total matches for %q and this scan read %d page(s) of up to "+
						"100. Each further page is a separate billable query credit.",
					searchResp.Total, query, page))
			}
			// THE PAUSE HAPPENS AFTER EVERY REQUEST INCLUDING THE LAST ONE, which is what the hardcoded
			// time.Sleep(1 * time.Second) did at the end of every loop iteration. Every scan therefore
			// still pays a second it does not need, and that is deliberate: moving the sleep would change
			// the pacing of every existing target's scan, and pacing is the difference between a scan that
			// completes and one that 429s. perQueryDelaySeconds is how an operator changes it.
			lastPage := len(searchResp.Matches) == 0 || page >= plan.MaxPages
			if plan.Delay > 0 {
				time.Sleep(plan.Delay)
			}
			if lastPage {
				break
			}
		}

		if rateLimited {
			// Counted as neither a success nor a failure: the query was abandoned, not answered.
			continue
		}
		if queryFailed {
			failed++
			continue
		}
		succeeded++
	}

	if failed > 0 {
		notes = append(notes, fmt.Sprintf("%d of %d Shodan queries FAILED and were swallowed. The most likely "+
			"cause is the unencoded company name: a query containing a space produces a request line with a "+
			"raw space in it, which was MEASURED returning HTTP 400 with an empty body.",
			failed, len(plan.Queries)))
	}

	// THE SAFETY NET. Off by default, so nothing changes for anybody who has not asked for it.
	if plan.FailWhenAllQueriesFail && succeeded == 0 && len(plan.Queries) > 0 {
		return nil, notes, fmt.Errorf("every one of the %d Shodan queries failed, so this scan read NOTHING. "+
			"failWhenAllQueriesFail is on, so it is an error rather than a 'success' with zero domains. "+
			"MEASURED CAUSE: the company name is interpolated into the query string unencoded, so any "+
			"company whose name contains a space gets HTTP 400 with an empty body on every query",
			len(plan.Queries))
	}

	domains := make([]string, 0, len(domainSet))
	for domain := range domainSet {
		domains = append(domains, domain)
	}
	// SORTED, where the original ranged a map and produced a different order on every run for the same
	// input. Nothing can depend on a randomised order, and a stable one is what makes a scan-to-scan
	// diff mean anything.
	sort.Strings(domains)

	log.Printf("[SHODAN-COMPANY] [INFO] Found %d unique domains for company: %s", len(domains), companyName)
	return domains, notes, nil
}

// shodanCompanyFetch performs one request and reports (body, error, rateLimited).
//
// rateLimited is separate from error because a 429 is not a failure of THIS query, it is a statement
// about the account, and the two lead to different decisions.
func shodanCompanyFetch(client *http.Client, requestURL string) (body []byte, rateLimited bool, err error) {
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		return nil, true, fmt.Errorf("shodan returned 429")
	}
	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, false, fmt.Errorf("shodan returned status %d: %s", resp.StatusCode, string(body))
	}
	if readErr != nil {
		return nil, false, readErr
	}
	return body, false, nil
}

func extractRootDomain(hostname string) string {
	if hostname == "" || !strings.Contains(hostname, ".") {
		return ""
	}

	hostname = strings.ToLower(hostname)

	if strings.HasPrefix(hostname, "*.") {
		hostname = hostname[2:]
	}

	if isIPAddress(hostname) {
		return ""
	}

	if !isValidDomain(hostname) {
		return ""
	}

	parts := strings.Split(hostname, ".")
	if len(parts) < 2 {
		return ""
	}

	return strings.Join(parts[len(parts)-2:], ".")
}

func isIPAddress(str string) bool {
	if net.ParseIP(str) != nil {
		return true
	}

	parts := strings.Split(str, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if num, err := strconv.Atoi(part); err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}

	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}

	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}

		if part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}

		for _, char := range part {
			if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
				return false
			}
		}
	}

	lastPart := parts[len(parts)-1]
	hasLetter := false
	for _, char := range lastPart {
		if char >= 'a' && char <= 'z' {
			hasLetter = true
			break
		}
	}

	return hasLetter
}

func UpdateShodanCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[SHODAN-COMPANY] [INFO] Updating scan status for scan ID %s to: %s", scanID, status)

	query := `UPDATE shodan_company_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to update scan status for scan ID %s: %v", scanID, err)
	} else {
		log.Printf("[SHODAN-COMPANY] [INFO] Successfully updated scan status for scan ID %s", scanID)
	}
}

func GetShodanCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[SHODAN-COMPANY] [INFO] Retrieving Shodan Company scan status for scan ID: %s", scanID)

	var scan ShodanCompanyScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM shodan_company_scans WHERE scan_id = $1`
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
			log.Printf("[SHODAN-COMPANY] [ERROR] Shodan Company scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[SHODAN-COMPANY] [ERROR] Failed to get Shodan Company scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[SHODAN-COMPANY] [INFO] Successfully retrieved Shodan Company scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[SHODAN-COMPANY] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetShodanCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[SHODAN-COMPANY] [INFO] Fetching Shodan Company scans for scope target ID: %s", scopeTargetID)

	if scopeTargetID == "" {
		log.Printf("[SHODAN-COMPANY] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS shodan_company_scans (
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
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to create shodan_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM shodan_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan ShodanCompanyScanStatus
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
			log.Printf("[SHODAN-COMPANY] [ERROR] Failed to scan row: %v", err)
			continue
		}

		scanMap := map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"company_name":         scan.CompanyName,
			"status":               scan.Status,
			"created_at":           scan.CreatedAt,
			"scope_target_id":      scan.ScopeTargetID,
			"auto_scan_session_id": scan.AutoScanSessionID,
		}

		if scan.Result.Valid {
			scanMap["result"] = scan.Result.String
		}
		if scan.Error.Valid {
			scanMap["error"] = scan.Error.String
		}
		if scan.StdOut.Valid {
			scanMap["stdout"] = scan.StdOut.String
		}
		if scan.StdErr.Valid {
			scanMap["stderr"] = scan.StdErr.String
		}
		if scan.Command.Valid {
			scanMap["command"] = scan.Command.String
		}
		if scan.ExecTime.Valid {
			scanMap["execution_time"] = scan.ExecTime.String
		}

		scans = append(scans, scanMap)
	}

	log.Printf("[SHODAN-COMPANY] [INFO] Successfully retrieved %d Shodan Company scans for scope target ID: %s", len(scans), scopeTargetID)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
