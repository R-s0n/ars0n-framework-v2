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

	domains, err := searchShodanForCompany(companyName, apiKey)
	if err != nil {
		log.Printf("[SHODAN-COMPANY] [ERROR] Failed to search Shodan for company %s: %v", companyName, err)
		UpdateShodanCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to search Shodan: %v", err), "", time.Since(startTime).String())
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
		UpdateShodanCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal result: %v", err), "", time.Since(startTime).String())
		return
	}

	UpdateShodanCompanyScanStatus(scanID, "success", string(resultJSON), "", "", time.Since(startTime).String())
	log.Printf("[SHODAN-COMPANY] [INFO] Successfully completed Shodan Company scan for company %s (scan ID: %s)", companyName, scanID)
}

func searchShodanForCompany(companyName, apiKey string) ([]string, error) {
	log.Printf("[SHODAN-COMPANY] [INFO] Searching Shodan for company: %s", companyName)

	domainSet := make(map[string]bool)

	queries := []string{
		fmt.Sprintf(`ssl.cert.subject.O:"%s"`, companyName),
		fmt.Sprintf(`http.title:"%s"`, companyName),
		fmt.Sprintf(`http.html:"%s"`, companyName),
		fmt.Sprintf(`org:"%s"`, companyName),
	}

	for _, query := range queries {
		log.Printf("[SHODAN-COMPANY] [INFO] Executing Shodan query: %s", query)

		url := fmt.Sprintf("https://api.shodan.io/shodan/host/search?key=%s&query=%s", apiKey, query)

		resp, err := http.Get(url)
		if err != nil {
			log.Printf("[SHODAN-COMPANY] [WARN] HTTP request failed for query '%s': %v", query, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 429 {
			log.Printf("[SHODAN-COMPANY] [WARN] Rate limit exceeded, stopping search")
			break
		}

		if resp.StatusCode != 200 {
			body, _ := io.ReadAll(resp.Body)
			log.Printf("[SHODAN-COMPANY] [WARN] Shodan API returned status %d for query '%s': %s", resp.StatusCode, query, string(body))
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("[SHODAN-COMPANY] [WARN] Failed to read response body for query '%s': %v", query, err)
			continue
		}

		var searchResp ShodanSearchResponse
		if err := json.Unmarshal(body, &searchResp); err != nil {
			log.Printf("[SHODAN-COMPANY] [WARN] Failed to parse JSON response for query '%s': %v", query, err)
			continue
		}

		log.Printf("[SHODAN-COMPANY] [INFO] Query '%s' returned %d matches", query, len(searchResp.Matches))

		for _, match := range searchResp.Matches {
			if match.SSL != nil && match.SSL.Cert != nil {
				if match.SSL.Cert.Subject != nil && match.SSL.Cert.Subject.CN != "" {
					if domain := extractRootDomain(match.SSL.Cert.Subject.CN); domain != "" {
						domainSet[domain] = true
					}
				}

				for _, san := range match.SSL.Cert.SubjectAltName {
					if domain := extractRootDomain(san); domain != "" {
						domainSet[domain] = true
					}
				}
			}

			for _, hostname := range match.Hostnames {
				if domain := extractRootDomain(hostname); domain != "" {
					domainSet[domain] = true
				}
			}

			if match.HTTP != nil && match.HTTP.Host != "" {
				if domain := extractRootDomain(match.HTTP.Host); domain != "" {
					domainSet[domain] = true
				}
			}
		}

		time.Sleep(1 * time.Second)
	}

	var domains []string
	for domain := range domainSet {
		domains = append(domains, domain)
	}

	log.Printf("[SHODAN-COMPANY] [INFO] Found %d unique domains for company: %s", len(domains), companyName)
	return domains, nil
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

	var scans []map[string]interface{}
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
