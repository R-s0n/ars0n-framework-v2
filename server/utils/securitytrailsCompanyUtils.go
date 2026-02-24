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

	// Create HTTP client with timeout
	client := &http.Client{Timeout: 60 * time.Second}

	// Create request to SecurityTrails API
	url := fmt.Sprintf("https://api.securitytrails.com/v1/domains/list?whois_organization=%s", url.QueryEscape(companyName))
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to create HTTP request: %v", err)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create HTTP request: %v", err), "", time.Since(startTime).String())
		return
	}

	// Add API key to request
	req.Header.Set("APIKEY", apiKey)
	req.Header.Set("Accept", "application/json")
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Making request to SecurityTrails API: %s", url)

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to make request to SecurityTrails API: %v", err)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to make request to SecurityTrails API: %v", err), "", time.Since(startTime).String())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] SecurityTrails API rate limit exceeded")
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", "SecurityTrails API rate limit exceeded. Please upgrade your plan or try again later.", "", time.Since(startTime).String())
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] SecurityTrails API returned non-200 status code: %d, body: %s", resp.StatusCode, string(body))
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("SecurityTrails API returned status code: %d, body: %s", resp.StatusCode, string(body)), "", time.Since(startTime).String())
		return
	}

	// Parse response
	var response struct {
		Records []struct {
			Hostname     string         `json:"hostname"`
			HostProvider []string       `json:"host_provider"`
			MailProvider FlexibleString `json:"mail_provider"`
			AlexaRank    int            `json:"alexa_rank"`
			Whois        struct {
				CreatedDate int64  `json:"createdDate"`
				ExpiresDate int64  `json:"expiresDate"`
				Registrar   string `json:"registrar"`
			} `json:"whois"`
		} `json:"records"`
		Meta struct {
			TotalPages int `json:"total_pages"`
			Page       int `json:"page"`
			MaxPage    int `json:"max_page"`
		} `json:"meta"`
		RecordCount int `json:"record_count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to decode SecurityTrails API response: %v", err)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to decode SecurityTrails API response: %v", err), "", time.Since(startTime).String())
		return
	}

	// Process domains
	domains := make([]map[string]interface{}, len(response.Records))
	for i, record := range response.Records {
		domains[i] = map[string]interface{}{
			"hostname":      record.Hostname,
			"host_provider": record.HostProvider,
			"mail_provider": record.MailProvider.Value,
			"alexa_rank":    record.AlexaRank,
			"whois": map[string]interface{}{
				"created_date": time.Unix(record.Whois.CreatedDate/1000, 0).Format(time.RFC3339),
				"expires_date": time.Unix(record.Whois.ExpiresDate/1000, 0).Format(time.RFC3339),
				"registrar":    record.Whois.Registrar,
			},
		}
	}

	// Create result object
	result := map[string]interface{}{
		"domains": domains,
		"meta": map[string]interface{}{
			"total_pages": response.Meta.TotalPages,
			"page":        response.Meta.Page,
			"max_page":    response.Meta.MaxPage,
			"total":       response.RecordCount,
		},
	}

	// Convert result to JSON
	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("[SECURITYTRAILS-COMPANY] [ERROR] Failed to marshal result: %v", err)
		UpdateSecurityTrailsCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), "", time.Since(startTime).String())
		return
	}

	// Update scan status with success
	UpdateSecurityTrailsCompanyScanStatus(scanID, "success", string(resultJSON), "", "", time.Since(startTime).String())
	log.Printf("[SECURITYTRAILS-COMPANY] [INFO] Successfully completed SecurityTrails Company scan for company %s (scan ID: %s)", companyName, scanID)
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

	var scans []map[string]interface{}
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
