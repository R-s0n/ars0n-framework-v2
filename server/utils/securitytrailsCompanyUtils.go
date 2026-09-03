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

type FlexibleString struct {
	Value string
}

func (fs *FlexibleString) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		fs.Value = s
		return nil
	}

	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		if len(arr) > 0 {
			fs.Value = arr[0]
		} else {
			fs.Value = ""
		}
		return nil
	}

	fs.Value = ""
	return nil
}

type SecurityTrailsCompanyScanStatus struct {
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

func RunSecurityTrailsCompanyScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Starting SecurityTrails Company scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Processing SecurityTrails Company scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS securitytrails_company_scans (
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
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to create securitytrails_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Ensured securitytrails_company_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO securitytrails_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO securitytrails_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully created SecurityTrails Company scan record in database")

	go ExecuteSecurityTrailsCompanyScan(scanID, companyName)

	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] SecurityTrails Company scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteSecurityTrailsCompanyScan(scanID, companyName string) {
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Starting SecurityTrails Company scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	// Get SecurityTrails API key from database
	var apiKeyJSON string
	err := dbPool.QueryRow(context.Background(), `
		SELECT api_key_value 
		FROM api_keys 
		WHERE tool_name = 'SecurityTrails' 
		ORDER BY created_at DESC 
		LIMIT 1
	`).Scan(&apiKeyJSON)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] No SecurityTrails API key found in database")
			UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", "No SecurityTrails API key found. Please configure your API key in the settings.", "", time.Since(startTime).String())
		} else {
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to get SecurityTrails API key: %v", err)
			UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get SecurityTrails API key: %v", err), "", time.Since(startTime).String())
		}
		return
	}

	// Parse the API key JSON to extract the actual key
	var keyData map[string]interface{}
	if err := json.Unmarshal([]byte(apiKeyJSON), &keyData); err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to parse API key JSON: %v", err)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to parse API key JSON: %v", err), "", time.Since(startTime).String())
		return
	}

	apiKey, ok := keyData["api_key"].(string)
	if !ok || apiKey == "" {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] SecurityTrails API key is empty or invalid")
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", "SecurityTrails API key is empty or invalid. Please configure your API key in the settings.", "", time.Since(startTime).String())
		return
	}

	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully retrieved SecurityTrails API key")

	// The per-target Company settings, from the ONE store the Settings screen and the MCP company tool
	// both write. Absent is the normal case and produces exactly one GET to
	// /v1/domains/list?whois_organization=<escaped>, a 60-second client timeout, no retries, and the
	// array-of-objects result shape this runner has always stored.
	scopeTargetID := companyScopeTargetForScan(
		context.Background(), "securitytrails_company_scans", scanID, "securitytrails_company")
	tool, settings, notes := companyRunnerSettings(scopeTargetID, "securitytrails_company")
	plan := securityTrailsCompanyPlanFor(companyName, settings)
	if plan.Configured {
		log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Running with stored Company settings for scope target %s: %s",
			scopeTargetID, companySettingsSummary(settings))
	}
	if plan.Method == "POST" {
		notes = append(notes, "requestMethod is POST. SecurityTrails documents /v1/domains/list as taking its "+
			"filter in a JSON body, and this runner now sends the documented body shape - but NEITHER FORM "+
			"WAS EVER VERIFIED: both returned 401 unauthenticated during research, so the probe proved "+
			"nothing about which one the API honours. If a filter parameter is IGNORED rather than "+
			"rejected, the response is an unfiltered slice of the internet stored as this company's root "+
			"domains: plausible, not empty, not an error, and completely wrong.")
	}
	companyLogNotes("SECURITYTRAILS-COMPANY", notes)

	// Create HTTP client with the configured timeout (60 seconds unless a target says otherwise)
	client := &http.Client{Timeout: plan.Timeout}

	var (
		allRecords   []securityTrailsRecord
		lastMeta     securityTrailsMeta
		recordCount  int
		pagesFetched int
	)

	pageLimit := securityTrailsPageLimit(plan)
	for page := 1; page <= pageLimit; page++ {
		requestURL := securityTrailsRequestURL(plan, page)
		// Rebuilt per attempt inside securityTrailsNewRequest, because a body reader cannot be read twice
		// and a retry that sent an empty body would look like a filterless query.
		requestBody := securityTrailsRequestBody(plan)

		// THE RETRY LOOP IS A NO-OP AT THE DEFAULT: plan.Retries is 0 unless somebody set it, so this
		// makes exactly one request and takes exactly the paths it always took. A 429 is retried only
		// when retries are configured, because SecurityTrails rate-limits aggressively on the entry
		// tiers and one 429 currently destroys the whole scan.
		var resp *http.Response
		for attempt := 0; ; attempt++ {
			req, reqErr := securityTrailsNewRequest(plan, requestURL, requestBody, apiKey)
			if reqErr != nil {
				log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to create HTTP request: %v", reqErr)
				UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create HTTP request: %v", reqErr), securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
				return
			}
			log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Making %s request to SecurityTrails API: %s",
				plan.Method, requestURL)
			resp, err = client.Do(req)
			retryable := err != nil || (resp != nil && (resp.StatusCode == 429 || resp.StatusCode >= 500))
			if !retryable || attempt >= plan.Retries {
				break
			}
			if resp != nil {
				resp.Body.Close()
			}
			notes = append(notes, fmt.Sprintf("SecurityTrails page %d attempt %d of %d failed and was retried.",
				page, attempt+1, plan.Retries+1))
			if plan.RetryBackoff > 0 {
				time.Sleep(plan.RetryBackoff)
			}
		}
		if err != nil {
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to make request to SecurityTrails API: %v", err)
			UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to make request to SecurityTrails API: %v", err), securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
			return
		}

		if resp.StatusCode == 429 {
			resp.Body.Close()
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] SecurityTrails API rate limit exceeded")
			UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", "SecurityTrails API rate limit exceeded. Please upgrade your plan or try again later.", securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
			return
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] SecurityTrails API returned non-200 status code: %d, body: %s", resp.StatusCode, string(body))
			UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("SecurityTrails API returned status code: %d, body: %s", resp.StatusCode, string(body)), securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
			return
		}

		// Parse response
		var response securityTrailsResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&response)
		resp.Body.Close()
		if decodeErr != nil {
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to decode SecurityTrails API response: %v", decodeErr)
			UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to decode SecurityTrails API response: %v", decodeErr), securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
			return
		}

		pagesFetched = page
		lastMeta = response.Meta
		recordCount = response.RecordCount
		allRecords = append(allRecords, response.records()...)

		if len(response.Records) == 0 {
			break
		}
		if response.Meta.TotalPages > 0 && page >= response.Meta.TotalPages {
			break
		}
	}

	// TRUNCATION IS RECORDED. The response already carries meta.total_pages and the runner already
	// stored it; what nobody could see was that the stored list was one page of it. Now the row says so.
	if lastMeta.TotalPages > pagesFetched {
		notes = append(notes, fmt.Sprintf(
			"TRUNCATED: SecurityTrails reports %d pages and this scan read %d. The stored domain list is not "+
				"the whole answer. Set fetchAllPages with a maxPages you are willing to spend query "+
				"allowance on.", lastMeta.TotalPages, pagesFetched))
	}

	if plan.RequireWhoisMatch {
		var whoisNotes []string
		allRecords, whoisNotes = securityTrailsWhoisFilter(companyName, allRecords)
		notes = append(notes, whoisNotes...)
	}

	if plan.MinResultsWarn > 0 && len(allRecords) < plan.MinResultsWarn {
		notes = append(notes, fmt.Sprintf(
			"Only %d record(s) came back, below the minResultsWarnThreshold of %d. This is a WARNING and does "+
				"not fail the scan. Post-GDPR whois_organization is redacted for most registrars, which is the "+
				"usual reason a real company returns almost nothing here.", len(allRecords), plan.MinResultsWarn))
	}

	// Process domains.
	//
	// storeDomainsAsStrings IS A DEFECT WITH A NAME, not a preference. The Consolidate Root Domains
	// step asserts d.(string) on every entry of this array, so with the default object shape the
	// assertion fails for EVERY record and not one SecurityTrails domain has ever reached the
	// consolidated list - while the scan reports success and the UI card shows a non-zero count.
	// Turning it on makes this tool contribute; it costs the whois and provider metadata the results
	// modal renders. The real fix is on one side or the other, and it is not this switch.
	var domains []interface{}
	if plan.StoreDomainsAsStrings {
		for _, record := range allRecords {
			domains = append(domains, record.Hostname)
		}
		notes = append(notes, "storeDomainsAsStrings is on, so the result carries plain hostname strings. That "+
			"is the shape Consolidate Root Domains can actually read - with the default object shape its "+
			"d.(string) assertion fails for every record and zero SecurityTrails domains reach the "+
			"consolidated list. The whois, provider and alexa_rank metadata the results modal shows is NOT "+
			"stored in this shape.")
	} else {
		for _, record := range allRecords {
			domains = append(domains, map[string]interface{}{
				"hostname":      record.Hostname,
				"host_provider": record.HostProvider,
				"mail_provider": record.MailProvider,
				"alexa_rank":    record.AlexaRank,
				"whois": map[string]interface{}{
					"created_date": time.Unix(record.CreatedDate/1000, 0).Format(time.RFC3339),
					"expires_date": time.Unix(record.ExpiresDate/1000, 0).Format(time.RFC3339),
					"registrar":    record.Registrar,
				},
			})
		}
	}
	if domains == nil {
		// json.Marshal renders a nil slice as null and an empty slice as []. The original code built the
		// slice with make(), so an empty response stored [] and it must keep doing so.
		domains = []interface{}{}
	}

	// Create result object
	result := map[string]interface{}{
		"domains": domains,
		"meta": map[string]interface{}{
			"total_pages": lastMeta.TotalPages,
			"page":        lastMeta.Page,
			"max_page":    lastMeta.MaxPage,
			"total":       recordCount,
		},
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to marshal result: %v", err)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
		return
	}

	companyLogNotes("SECURITYTRAILS-COMPANY", notes)

	// THE ANTI-SILENT-NOTHING CONTROL, off by default. A redacted WHOIS, a company name that does not
	// match the registrant string, and a filter parameter the API IGNORED all produce the same
	// zero-record 200. None of them is a clean result and all three are stored as one today.
	if plan.FailOnZeroRecords && len(allRecords) == 0 {
		errorMsg := fmt.Sprintf("SecurityTrails returned zero records (record_count %d). failOnZeroRecords is "+
			"on, so this is recorded as an error rather than as a clean result. If record_count is greater "+
			"than zero while the records array is empty, that is unambiguously a decode mismatch rather "+
			"than an empty answer.", recordCount)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", string(resultJSON), errorMsg, securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
		return
	}

	// Update scan status with success
	UpdateSecurityTrailsCompanyScanStatus(scanID, "success", string(resultJSON), "", securityTrailsCommand(tool, plan, scopeTargetID, settings, notes), time.Since(startTime).String())
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully completed SecurityTrails Company scan for company %s (scan ID: %s)", companyName, scanID)
}

// securityTrailsMeta is the pagination block SecurityTrails returns. It was always decoded and always
// stored; what did not exist was anything that READ total_pages, which is why a 37-page company was
// stored with a healthy-looking total beside one page of domains.
type securityTrailsMeta struct {
	TotalPages int `json:"total_pages"`
	Page       int `json:"page"`
	MaxPage    int `json:"max_page"`
}

// securityTrailsResponse is the decode target, unchanged in shape except for the WHOIS fields
// requireWhoisMatch needs. Extra decoded fields cannot change the default behaviour: they are only
// read when that option is on.
type securityTrailsResponse struct {
	Records []struct {
		Hostname     string         `json:"hostname"`
		HostProvider []string       `json:"host_provider"`
		MailProvider FlexibleString `json:"mail_provider"`
		AlexaRank    int            `json:"alexa_rank"`
		Whois        struct {
			CreatedDate int64  `json:"createdDate"`
			ExpiresDate int64  `json:"expiresDate"`
			Registrar   string `json:"registrar"`

			// THE THREE FIELDS requireWhoisMatch NEEDS, AND THEY ARE FlexibleString FOR A REASON. Their
			// live shapes were never observed: no SecurityTrails key is configured in this deployment, so
			// nothing past the 401 boundary could be measured. If any of them comes back as an ARRAY - which
			// is exactly what mail_provider does, and why FlexibleString exists at all - a plain `string`
			// would fail the decode and turn a scan that works today into "Failed to decode SecurityTrails
			// API response". A field added for a switch that is OFF BY DEFAULT must never be able to do
			// that, so the decoder absorbs both shapes and never errors.
			Organization FlexibleString `json:"organization"`
			Name         FlexibleString `json:"name"`
			Email        FlexibleString `json:"email"`
		} `json:"whois"`
	} `json:"records"`
	Meta        securityTrailsMeta `json:"meta"`
	RecordCount int                `json:"record_count"`
}

func (r securityTrailsResponse) records() []securityTrailsRecord {
	out := make([]securityTrailsRecord, 0, len(r.Records))
	for _, record := range r.Records {
		out = append(out, securityTrailsRecord{
			Hostname:     record.Hostname,
			HostProvider: record.HostProvider,
			MailProvider: record.MailProvider.Value,
			AlexaRank:    record.AlexaRank,
			CreatedDate:  record.Whois.CreatedDate,
			ExpiresDate:  record.Whois.ExpiresDate,
			Registrar:    record.Whois.Registrar,
			// The registrant fields, when the API returns them at all. Registrar is deliberately NOT in
			// this list: it names GoDaddy or MarkMonitor, not the company, and corroborating against it
			// would delete every real finding.
			WhoisCorroboration: []string{
				record.Whois.Organization.Value, record.Whois.Name.Value, record.Whois.Email.Value,
			},
		})
	}
	return out
}

// securityTrailsNewRequest builds one request. GET keeps the query-string form the runner has always
// used; POST sends the documented JSON body.
func securityTrailsNewRequest(plan securityTrailsCompanyPlan, requestURL, body, apiKey string) (*http.Request, error) {
	var req *http.Request
	var err error
	if body == "" {
		req, err = http.NewRequest("GET", requestURL, nil)
	} else {
		req, err = http.NewRequest("POST", requestURL, strings.NewReader(body))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if err != nil {
		return nil, err
	}
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// securityTrailsCommand is what the scan row records as "what did this actually run".
//
// The column has always been empty for this tool. It stays empty when nothing is configured, so a
// default scan's row is unchanged; when something is configured it carries the request shape and the
// settings preamble, because otherwise nothing anywhere says the scan differed from the default.
func securityTrailsCommand(tool CompanyTool, plan securityTrailsCompanyPlan, scopeTargetID string,
	settings map[string]any, notes []string) string {
	if len(settings) == 0 && len(notes) == 0 {
		return ""
	}
	command := fmt.Sprintf("%s %s", plan.Method, securityTrailsRequestURL(plan, 1))
	if body := securityTrailsRequestBody(plan); body != "" {
		command += " body=" + body
	}
	return command + "\n" + companySettingsPreamble(tool, scopeTargetID, settings, notes)
}

func UpdateSecurityTrailsCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Updating SecurityTrails Company scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE securitytrails_company_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to update SecurityTrails Company scan status for scan ID %s: %v", scanID, err)
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Update attempted with: status=%s, result_length=%d, error_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully updated SecurityTrails Company scan status to %s for scan ID %s", status, scanID)
	}
}

func GetSecurityTrailsCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Retrieving SecurityTrails Company scan status for scan ID: %s", scanID)

	var scan SecurityTrailsCompanyScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM securitytrails_company_scans WHERE scan_id = $1`
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
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] SecurityTrails Company scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to get SecurityTrails Company scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully retrieved SecurityTrails Company scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[SECURITYTRAILS-COMPANY] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
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
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to encode SecurityTrails Company scan response: %v", err)
	} else {
		log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully sent SecurityTrails Company scan status response")
	}
}

func GetSecurityTrailsCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Fetching SecurityTrails Company scans for scope target ID: %s", scopeTargetID)

	if scopeTargetID == "" {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	// Ensure the table exists before trying to query it
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS securitytrails_company_scans (
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
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to create securitytrails_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM securitytrails_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan SecurityTrailsCompanyScanStatus
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
			log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Error scanning SecurityTrails Company scan row: %v", err)
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

	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully retrieved %d SecurityTrails Company scans for scope target %s", len(scans), scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scans); err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to encode scans response: %v", err)
	} else {
		log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully sent SecurityTrails Company scans response")
	}
}
