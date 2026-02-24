package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type CensysCompanyScanStatus struct {
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

func RunCensysCompanyScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[CENSYS-COMPANY] [INFO] Starting Censys Company scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[CENSYS-COMPANY] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[CENSYS-COMPANY] [INFO] Processing Censys Company scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[CENSYS-COMPANY] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[CENSYS-COMPANY] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS censys_company_scans (
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
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to create censys_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[CENSYS-COMPANY] [INFO] Ensured censys_company_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO censys_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO censys_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[CENSYS-COMPANY] [INFO] Successfully created Censys Company scan record in database")

	go ExecuteCensysCompanyScan(scanID, companyName)

	log.Printf("[CENSYS-COMPANY] [INFO] Censys Company scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteCensysCompanyScan(scanID, companyName string) {
	log.Printf("[CENSYS-COMPANY] [INFO] Starting Censys Company scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	var apiID, apiSecret string
	err := dbPool.QueryRow(context.Background(), `
		SELECT 
			(api_key_value::json->>'app_id')::text as api_key_value,
			(api_key_value::json->>'app_secret')::text as api_key_secret
		FROM api_keys 
		WHERE tool_name = 'Censys' 
		ORDER BY created_at DESC 
		LIMIT 1
	`).Scan(&apiID, &apiSecret)
	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[CENSYS-COMPANY] [ERROR] No Censys API credentials found in database")
			UpdateCensysCompanyScanStatus(scanID, "error", "", "No Censys API credentials found. Please configure your API credentials in the settings.", "", time.Since(startTime).String())
		} else {
			log.Printf("[CENSYS-COMPANY] [ERROR] Failed to get Censys API credentials: %v", err)
			UpdateCensysCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get Censys API credentials: %v", err), "", time.Since(startTime).String())
		}
		return
	}

	if apiID == "" || apiSecret == "" {
		log.Printf("[CENSYS-COMPANY] [ERROR] Censys API credentials are empty")
		UpdateCensysCompanyScanStatus(scanID, "error", "", "Censys API credentials are empty. Please configure your API credentials in the settings.", "", time.Since(startTime).String())
		return
	}

	log.Printf("[CENSYS-COMPANY] [INFO] Successfully retrieved Censys API credentials")

	client := &http.Client{Timeout: 60 * time.Second}

	url := fmt.Sprintf("https://search.censys.io/api/v2/certificates/search?q=parsed.subject.organization:%%22%s%%22&per_page=100", companyName)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to create HTTP request: %v", err)
		UpdateCensysCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create HTTP request: %v", err), "", time.Since(startTime).String())
		return
	}

	req.SetBasicAuth(apiID, apiSecret)
	req.Header.Set("Accept", "application/json")
	log.Printf("[CENSYS-COMPANY] [INFO] Making request to Censys API: %s", url)

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to make request to Censys API: %v", err)
		UpdateCensysCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to make request to Censys API: %v", err), "", time.Since(startTime).String())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 429 {
		log.Printf("[CENSYS-COMPANY] [ERROR] Censys API rate limit exceeded")
		UpdateCensysCompanyScanStatus(scanID, "error", "", "Censys API rate limit exceeded. Please upgrade your plan or try again later.", "", time.Since(startTime).String())
		return
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("[CENSYS-COMPANY] [ERROR] Censys API returned non-200 status code: %d, body: %s", resp.StatusCode, string(body))
		UpdateCensysCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Censys API returned status code: %d, body: %s", resp.StatusCode, string(body)), "", time.Since(startTime).String())
		return
	}

	var response struct {
		Result struct {
			Hits []struct {
				Parsed struct {
					Names []string `json:"names"`
				} `json:"parsed"`
			} `json:"hits"`
			Total int `json:"total"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to decode Censys API response: %v", err)
		UpdateCensysCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to decode Censys API response: %v", err), "", time.Since(startTime).String())
		return
	}

	domains := make(map[string]bool)
	for _, hit := range response.Result.Hits {
		for _, name := range hit.Parsed.Names {
			domains[name] = true
		}
	}

	uniqueDomains := make([]string, 0, len(domains))
	for domain := range domains {
		uniqueDomains = append(uniqueDomains, domain)
	}

	result := map[string]interface{}{
		"domains": uniqueDomains,
		"meta": map[string]interface{}{
			"total": response.Result.Total,
		},
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to marshal result: %v", err)
		UpdateCensysCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), "", time.Since(startTime).String())
		return
	}

	UpdateCensysCompanyScanStatus(scanID, "success", string(resultJSON), "", "", time.Since(startTime).String())
	log.Printf("[CENSYS-COMPANY] [INFO] Successfully completed Censys Company scan for company %s (scan ID: %s)", companyName, scanID)
}

func UpdateCensysCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[CENSYS-COMPANY] [INFO] Updating Censys Company scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE censys_company_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to update Censys Company scan status for scan ID %s: %v", scanID, err)
		log.Printf("[CENSYS-COMPANY] [ERROR] Update attempted with: status=%s, result_length=%d, error_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[CENSYS-COMPANY] [INFO] Successfully updated Censys Company scan status to %s for scan ID %s", status, scanID)
	}
}

func GetCensysCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[CENSYS-COMPANY] [INFO] Retrieving Censys Company scan status for scan ID: %s", scanID)

	var scan CensysCompanyScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM censys_company_scans WHERE scan_id = $1`
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
			log.Printf("[CENSYS-COMPANY] [ERROR] Censys Company scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[CENSYS-COMPANY] [ERROR] Failed to get Censys Company scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[CENSYS-COMPANY] [INFO] Successfully retrieved Censys Company scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[CENSYS-COMPANY] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
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
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to encode Censys Company scan response: %v", err)
	} else {
		log.Printf("[CENSYS-COMPANY] [INFO] Successfully sent Censys Company scan status response")
	}
}

func GetCensysCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[CENSYS-COMPANY] [INFO] Fetching Censys Company scans for scope target ID: %s", scopeTargetID)

	if scopeTargetID == "" {
		log.Printf("[CENSYS-COMPANY] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS censys_company_scans (
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
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to create censys_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM censys_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan CensysCompanyScanStatus
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
			log.Printf("[CENSYS-COMPANY] [ERROR] Error scanning Censys Company scan row: %v", err)
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

	log.Printf("[CENSYS-COMPANY] [INFO] Successfully retrieved %d Censys Company scans for scope target %s", len(scans), scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scans); err != nil {
		log.Printf("[CENSYS-COMPANY] [ERROR] Failed to encode scans response: %v", err)
	} else {
		log.Printf("[CENSYS-COMPANY] [INFO] Successfully sent Censys Company scans response")
	}
}
