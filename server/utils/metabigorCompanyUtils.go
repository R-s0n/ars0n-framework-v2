package utils

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type MetabigorCompanyScanStatus struct {
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

// New structured data types
type MetabigorNetworkRange struct {
	ID           string `json:"id"`
	CIDRBlock    string `json:"cidr_block"`
	ASN          string `json:"asn"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	ScanType     string `json:"scan_type"` // 'net', 'netd', 'asn'
	ScanID       string `json:"scan_id"`
}

type MetabigorASNData struct {
	ID           string `json:"id"`
	ASNNumber    string `json:"asn_number"`
	Organization string `json:"organization"`
	Country      string `json:"country"`
	ScanType     string `json:"scan_type"`
	ScanID       string `json:"scan_id"`
}

type MetabigorIPIntelligence struct {
	IPAddress    string   `json:"ip_address"`
	ASN          string   `json:"asn"`
	Organization string   `json:"organization"`
	Country      string   `json:"country"`
	City         string   `json:"city"`
	OpenPorts    []int    `json:"open_ports"`
	Services     []string `json:"services"`
	ScanID       string   `json:"scan_id"`
}

func RunMetabigorCompanyScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[METABIGOR-COMPANY] [INFO] Starting Metabigor Company scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[METABIGOR-COMPANY] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[METABIGOR-COMPANY] [INFO] Processing Metabigor Company scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[METABIGOR-COMPANY] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[METABIGOR-COMPANY] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[METABIGOR-COMPANY] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS metabigor_company_scans (
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
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to create metabigor_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[METABIGOR-COMPANY] [INFO] Ensured metabigor_company_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[METABIGOR-COMPANY] [INFO] Successfully created Metabigor Company scan record in database")

	go ExecuteMetabigorCompanyScan(scanID, companyName)

	log.Printf("[METABIGOR-COMPANY] [INFO] Metabigor Company scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteMetabigorCompanyScan(scanID, companyName string) {
	log.Printf("[METABIGOR-COMPANY] [INFO] Starting Metabigor Company scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	// Create structured data tables
	createMetabigorTables()

	// Helper function to execute the scan and count results
	executeScan := func(name string) (string, int, error) {
		command := fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i ars0n-framework-v2-metabigor-1 metabigor net --org -v", name)
		log.Printf("[METABIGOR-COMPANY] [DEBUG] Executing command: %s", command)

		output, err := exec.Command("sh", "-c", command).CombinedOutput()
		if err != nil {
			return string(output), 0, err
		}

		// Count valid result lines (lines that match the verbose pattern)
		lines := strings.Split(string(output), "\n")
		verbosePattern := regexp.MustCompile(`^(\d+)\s*-\s*([0-9a-fA-F:.\/]+)\s*-\s*(.+?)\s*-\s*([A-Z]{2})$`)
		resultCount := 0

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "[") && !strings.Contains(line, "INFO") && !strings.Contains(line, "metabigor") {
				if verbosePattern.MatchString(line) {
					resultCount++
				}
			}
		}

		return string(output), resultCount, nil
	}

	// First attempt with original company name
	log.Printf("[METABIGOR-COMPANY] [INFO] Attempting scan with original company name: '%s'", companyName)
	output, resultCount, err := executeScan(companyName)

	if err != nil {
		log.Printf("[METABIGOR-COMPANY] [ERROR] Metabigor command failed: %v", err)
		log.Printf("[METABIGOR-COMPANY] [ERROR] Command output: %s", output)
		UpdateMetabigorCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Metabigor command failed: %v\nOutput: %s", err, output), "", time.Since(startTime).String())
		return
	}

	// If no results and company name contains spaces, try without spaces
	if resultCount == 0 && strings.Contains(companyName, " ") {
		companyNameNoSpaces := strings.ReplaceAll(companyName, " ", "")
		log.Printf("[METABIGOR-COMPANY] [INFO] No results found with original name. Retrying with no spaces: '%s'", companyNameNoSpaces)

		retryOutput, retryResultCount, retryErr := executeScan(companyNameNoSpaces)

		if retryErr != nil {
			log.Printf("[METABIGOR-COMPANY] [ERROR] Retry command also failed: %v", retryErr)
			log.Printf("[METABIGOR-COMPANY] [ERROR] Retry command output: %s", retryOutput)
			UpdateMetabigorCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Both scans failed. Original: %v\nRetry: %v\nRetry Output: %s", err, retryErr, retryOutput), "", time.Since(startTime).String())
			return
		}

		if retryResultCount > 0 {
			log.Printf("[METABIGOR-COMPANY] [INFO] Retry successful! Found %d results with company name '%s'", retryResultCount, companyNameNoSpaces)
			output = retryOutput
			resultCount = retryResultCount
		} else {
			log.Printf("[METABIGOR-COMPANY] [INFO] Retry also yielded no results. Using original scan output.")
		}
	}

	log.Printf("[METABIGOR-COMPANY] [DEBUG] Final output (found %d results): %s", resultCount, output)

	// Parse and store structured results
	ParseAndStoreMetabigorResults(scanID, companyName, output, "net")

	UpdateMetabigorCompanyScanStatus(scanID, "success", "{}", "", "", time.Since(startTime).String())
	log.Printf("[METABIGOR-COMPANY] [INFO] Metabigor Company scan completed and results stored successfully for company %s (found %d network ranges)", companyName, resultCount)
}

func createMetabigorTables() {
	// Create network ranges table
	networkTableQuery := `
		CREATE TABLE IF NOT EXISTS metabigor_network_ranges (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			cidr_block VARCHAR(50),
			asn VARCHAR(20),
			organization TEXT,
			country VARCHAR(10),
			scan_type VARCHAR(20),
			created_at TIMESTAMP DEFAULT NOW()
		);`

	_, err := dbPool.Exec(context.Background(), networkTableQuery)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to create metabigor_network_ranges table: %v", err)
	}

	// Create ASN data table
	asnTableQuery := `
		CREATE TABLE IF NOT EXISTS metabigor_asn_data (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			asn_number VARCHAR(20),
			organization TEXT,
			country VARCHAR(10),
			scan_type VARCHAR(20),
			created_at TIMESTAMP DEFAULT NOW()
		);`

	_, err = dbPool.Exec(context.Background(), asnTableQuery)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to create metabigor_asn_data table: %v", err)
	}

	// Create IP intelligence table
	ipIntelTableQuery := `
		CREATE TABLE IF NOT EXISTS metabigor_ip_intelligence (
			id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
			scan_id UUID NOT NULL,
			ip_address INET,
			asn VARCHAR(20),
			organization TEXT,
			country VARCHAR(10),
			city VARCHAR(100),
			open_ports INTEGER[],
			services TEXT[],
			created_at TIMESTAMP DEFAULT NOW()
		);`

	_, err = dbPool.Exec(context.Background(), ipIntelTableQuery)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to create metabigor_ip_intelligence table: %v", err)
	}
}

func ParseAndStoreMetabigorResults(scanID, companyName, result, scanType string) {
	log.Printf("[METABIGOR] [INFO] Parsing Metabigor verbose results for scan %s", scanID)

	lines := strings.Split(result, "\n")
	var networkRanges []MetabigorNetworkRange
	var asnData []MetabigorASNData
	seenASNs := make(map[string]bool) // Track unique ASNs

	// Pattern for verbose format: ASN - CIDR - ORGANIZATION - COUNTRY
	verbosePattern := regexp.MustCompile(`^(\d+)\s*-\s*([0-9a-fA-F:.\/]+)\s*-\s*(.+?)\s*-\s*([A-Z]{2})$`)

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip log lines, empty lines, and headers
		if line == "" || strings.HasPrefix(line, "[") || strings.Contains(line, "INFO") || strings.Contains(line, "metabigor") {
			continue
		}

		log.Printf("[METABIGOR] [DEBUG] Processing line: %s", line)

		// Parse verbose format: ASN - CIDR - ORGANIZATION - COUNTRY
		if matches := verbosePattern.FindStringSubmatch(line); len(matches) == 5 {
			asnNumber := matches[1]
			cidrBlock := matches[2]
			organization := strings.TrimSpace(matches[3])
			country := matches[4]

			// Store network range
			networkRange := MetabigorNetworkRange{
				CIDRBlock:    cidrBlock,
				ASN:          "AS" + asnNumber,
				Organization: organization,
				Country:      country,
				ScanType:     scanType,
				ScanID:       scanID,
			}

			networkRanges = append(networkRanges, networkRange)
			InsertMetabigorNetworkRange(scanID, cidrBlock, "AS"+asnNumber, organization, country, scanType)

			// Store unique ASN data
			asnKey := "AS" + asnNumber
			if !seenASNs[asnKey] {
				seenASNs[asnKey] = true

				asnInfo := MetabigorASNData{
					ASNNumber:    asnKey,
					Organization: organization,
					Country:      country,
					ScanType:     scanType,
					ScanID:       scanID,
				}

				asnData = append(asnData, asnInfo)
				InsertMetabigorASNData(scanID, asnKey, organization, country, scanType)
			}
		} else {
			log.Printf("[METABIGOR] [WARNING] Could not parse line: %s", line)
		}
	}

	log.Printf("[METABIGOR] [INFO] Parsed %d network ranges and %d unique ASN records", len(networkRanges), len(asnData))
}

func extractOrganization(line string) string {
	// Remove CIDR blocks and ASN numbers to get organization name
	cidrPattern := regexp.MustCompile(`\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}`)
	asnPattern := regexp.MustCompile(`AS\d+`)

	org := line
	org = cidrPattern.ReplaceAllString(org, "")
	org = asnPattern.ReplaceAllString(org, "")
	org = strings.TrimSpace(org)
	org = strings.Trim(org, "-,")
	org = strings.TrimSpace(org)

	return org
}

func InsertMetabigorNetworkRange(scanID, cidrBlock, asn, organization, country, scanType string) {
	query := `INSERT INTO metabigor_network_ranges (scan_id, cidr_block, asn, organization, country, scan_type) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := dbPool.Exec(context.Background(), query, scanID, cidrBlock, asn, organization, country, scanType)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to insert network range: %v", err)
	}
}

func InsertMetabigorASNData(scanID, asnNumber, organization, country, scanType string) {
	query := `INSERT INTO metabigor_asn_data (scan_id, asn_number, organization, country, scan_type) VALUES ($1, $2, $3, $4, $5)`
	_, err := dbPool.Exec(context.Background(), query, scanID, asnNumber, organization, country, scanType)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to insert ASN data: %v", err)
	}
}

func UpdateMetabigorCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[METABIGOR-COMPANY] [INFO] Updating Metabigor Company scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE metabigor_company_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to update Metabigor Company scan status for scan ID %s: %v", scanID, err)
		log.Printf("[METABIGOR-COMPANY] [ERROR] Update attempted with: status=%s, result_length=%d, error_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[METABIGOR-COMPANY] [INFO] Successfully updated Metabigor Company scan status to %s for scan ID %s", status, scanID)
	}
}

func GetMetabigorCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[METABIGOR-COMPANY] [INFO] Retrieving Metabigor Company scan status for scan ID: %s", scanID)

	var scan MetabigorCompanyScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM metabigor_company_scans WHERE scan_id = $1`
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
			log.Printf("[METABIGOR-COMPANY] [ERROR] Metabigor Company scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to get Metabigor Company scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[METABIGOR-COMPANY] [INFO] Successfully retrieved Metabigor Company scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[METABIGOR-COMPANY] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
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
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to encode Metabigor Company scan response: %v", err)
	} else {
		log.Printf("[METABIGOR-COMPANY] [INFO] Successfully sent Metabigor Company scan status response")
	}
}

func GetMetabigorCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]
	log.Printf("[METABIGOR-COMPANY] [INFO] Fetching Metabigor Company scans for scope target ID: %s", scopeTargetID)

	if scopeTargetID == "" {
		log.Printf("[METABIGOR-COMPANY] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	// Ensure the table exists before trying to query it
	createTableQuery := `
		CREATE TABLE IF NOT EXISTS metabigor_company_scans (
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
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to create metabigor_company_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM metabigor_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan MetabigorCompanyScanStatus
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
			log.Printf("[METABIGOR-COMPANY] [ERROR] Error scanning Metabigor Company scan row: %v", err)
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

	log.Printf("[METABIGOR-COMPANY] [INFO] Successfully retrieved %d Metabigor Company scans for scope target %s", len(scans), scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scans); err != nil {
		log.Printf("[METABIGOR-COMPANY] [ERROR] Failed to encode scans response: %v", err)
	} else {
		log.Printf("[METABIGOR-COMPANY] [INFO] Successfully sent Metabigor Company scans response")
	}
}

// New endpoints for structured data
func GetMetabigorNetworkRanges(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[METABIGOR] [INFO] Retrieving network ranges for scan ID: %s", scanID)

	query := `SELECT id, cidr_block, asn, organization, country, scan_type FROM metabigor_network_ranges WHERE scan_id = $1 ORDER BY cidr_block`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to get network ranges: %v", err)
		http.Error(w, "Failed to get network ranges", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var networkRanges []MetabigorNetworkRange
	for rows.Next() {
		var nr MetabigorNetworkRange
		err := rows.Scan(&nr.ID, &nr.CIDRBlock, &nr.ASN, &nr.Organization, &nr.Country, &nr.ScanType)
		if err != nil {
			log.Printf("[METABIGOR] [ERROR] Error scanning network range row: %v", err)
			continue
		}
		nr.ScanID = scanID
		networkRanges = append(networkRanges, nr)
	}

	log.Printf("[METABIGOR] [INFO] Retrieved %d network ranges for scan %s", len(networkRanges), scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(networkRanges)
}

func GetMetabigorASNData(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[METABIGOR] [INFO] Retrieving ASN data for scan ID: %s", scanID)

	query := `SELECT id, asn_number, organization, country, scan_type FROM metabigor_asn_data WHERE scan_id = $1 ORDER BY asn_number`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to get ASN data: %v", err)
		http.Error(w, "Failed to get ASN data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var asnData []MetabigorASNData
	for rows.Next() {
		var asn MetabigorASNData
		err := rows.Scan(&asn.ID, &asn.ASNNumber, &asn.Organization, &asn.Country, &asn.ScanType)
		if err != nil {
			log.Printf("[METABIGOR] [ERROR] Error scanning ASN data row: %v", err)
			continue
		}
		asn.ScanID = scanID
		asnData = append(asnData, asn)
	}

	log.Printf("[METABIGOR] [INFO] Retrieved %d ASN records for scan %s", len(asnData), scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(asnData)
}

// Phase 2: Enhanced Network Discovery Functions

func RunMetabigorNetdScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[METABIGOR-NETD] [INFO] Starting Metabigor Dynamic Network scan request handling")

	var req struct {
		CompanyName       string `json:"company_name"`
		AutoScanSessionID string `json:"auto_scan_session_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[METABIGOR-NETD] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	companyName := req.CompanyName
	log.Printf("[METABIGOR-NETD] [INFO] Processing Metabigor Dynamic Network scan for company: %s", companyName)

	scanID := uuid.New().String()
	log.Printf("[METABIGOR-NETD] [INFO] Generated new scan ID: %s", scanID)

	createMetabigorTables()

	var insertQuery string
	var args []interface{}

	if req.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", "", req.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", ""}
	}

	_, err := dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[METABIGOR-NETD] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteMetabigorNetdScan(scanID, companyName)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteMetabigorNetdScan(scanID, companyName string) {
	log.Printf("[METABIGOR-NETD] [INFO] Starting dynamic network scan for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	command := fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i ars0n-framework-v2-metabigor-1 metabigor netd --org", companyName)

	log.Printf("[METABIGOR-NETD] [DEBUG] Executing command: %s", command)

	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Printf("[METABIGOR-NETD] [ERROR] Command failed: %v", err)
		UpdateMetabigorCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Command failed: %v\nOutput: %s", err, string(output)), command, time.Since(startTime).String())
		return
	}

	log.Printf("[METABIGOR-NETD] [DEBUG] Raw output: %s", string(output))
	ParseAndStoreMetabigorResults(scanID, companyName, string(output), "netd")

	UpdateMetabigorCompanyScanStatus(scanID, "success", "{}", "", command, time.Since(startTime).String())
	log.Printf("[METABIGOR-NETD] [INFO] Dynamic network scan completed for company %s", companyName)
}

func RunMetabigorASNScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[METABIGOR-ASN] [INFO] Starting Metabigor ASN scan request handling")

	var req struct {
		ASNNumber         string `json:"asn_number"`
		ScanType          string `json:"scan_type"` // "net" or "netd"
		AutoScanSessionID string `json:"auto_scan_session_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[METABIGOR-ASN] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	asnNumber := req.ASNNumber
	scanType := req.ScanType
	if scanType == "" {
		scanType = "net" // Default to static scan
	}

	log.Printf("[METABIGOR-ASN] [INFO] Processing ASN scan for %s using %s", asnNumber, scanType)

	scanID := uuid.New().String()
	createMetabigorTables()

	var insertQuery string
	var args []interface{}

	if req.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, asnNumber, "pending", "", req.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, asnNumber, "pending", ""}
	}

	_, err := dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[METABIGOR-ASN] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteMetabigorASNScan(scanID, asnNumber, scanType)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteMetabigorASNScan(scanID, asnNumber, scanType string) {
	log.Printf("[METABIGOR-ASN] [INFO] Starting ASN scan for %s using %s (scan ID: %s)", asnNumber, scanType, scanID)
	startTime := time.Now()

	var command string
	if scanType == "netd" {
		command = fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i ars0n-framework-v2-metabigor-1 metabigor netd --asn", asnNumber)
	} else {
		command = fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i ars0n-framework-v2-metabigor-1 metabigor net --asn", asnNumber)
	}

	log.Printf("[METABIGOR-ASN] [DEBUG] Executing command: %s", command)

	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Printf("[METABIGOR-ASN] [ERROR] Command failed: %v", err)
		UpdateMetabigorCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Command failed: %v\nOutput: %s", err, string(output)), command, time.Since(startTime).String())
		return
	}

	log.Printf("[METABIGOR-ASN] [DEBUG] Raw output: %s", string(output))
	ParseAndStoreMetabigorResults(scanID, asnNumber, string(output), scanType+"_asn")

	UpdateMetabigorCompanyScanStatus(scanID, "success", "{}", "", command, time.Since(startTime).String())
	log.Printf("[METABIGOR-ASN] [INFO] ASN scan completed for %s", asnNumber)
}

func RunMetabigorIPIntelligence(w http.ResponseWriter, r *http.Request) {
	log.Printf("[METABIGOR-IP] [INFO] Starting Metabigor IP Intelligence scan")

	var req struct {
		IPAddresses       []string `json:"ip_addresses"`
		ScanType          string   `json:"scan_type"` // "ipc" or "open"
		AutoScanSessionID string   `json:"auto_scan_session_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Printf("[METABIGOR-IP] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	scanType := req.ScanType
	if scanType == "" {
		scanType = "ipc" // Default to IP context scan
	}

	log.Printf("[METABIGOR-IP] [INFO] Processing IP intelligence for %d IPs using %s", len(req.IPAddresses), scanType)

	scanID := uuid.New().String()
	createMetabigorTables()

	ipList := strings.Join(req.IPAddresses, "\n")

	var insertQuery string
	var args []interface{}

	if req.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, "IP Intelligence", "pending", "", req.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO metabigor_company_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, "IP Intelligence", "pending", ""}
	}

	_, err := dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[METABIGOR-IP] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteMetabigorIPIntelligence(scanID, ipList, scanType)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteMetabigorIPIntelligence(scanID, ipList, scanType string) {
	log.Printf("[METABIGOR-IP] [INFO] Starting IP intelligence scan (scan ID: %s)", scanID)
	startTime := time.Now()

	var command string
	if scanType == "open" {
		command = fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i ars0n-framework-v2-metabigor-1 metabigor ip -open", ipList)
	} else {
		command = fmt.Sprintf("echo '%s' | /usr/bin/docker exec -i ars0n-framework-v2-metabigor-1 metabigor ipc --json", ipList)
	}

	log.Printf("[METABIGOR-IP] [DEBUG] Executing command: %s", command)

	output, err := exec.Command("sh", "-c", command).CombinedOutput()
	if err != nil {
		log.Printf("[METABIGOR-IP] [ERROR] Command failed: %v", err)
		UpdateMetabigorCompanyScanStatus(scanID, "error", "", fmt.Sprintf("Command failed: %v\nOutput: %s", err, string(output)), command, time.Since(startTime).String())
		return
	}

	log.Printf("[METABIGOR-IP] [DEBUG] Raw output: %s", string(output))

	if scanType == "ipc" {
		ParseAndStoreIPIntelligence(scanID, string(output))
	} else {
		ParseAndStoreOpenPorts(scanID, string(output))
	}

	UpdateMetabigorCompanyScanStatus(scanID, "success", "{}", "", command, time.Since(startTime).String())
	log.Printf("[METABIGOR-IP] [INFO] IP intelligence scan completed")
}

func ParseAndStoreIPIntelligence(scanID, jsonOutput string) {
	log.Printf("[METABIGOR-IP] [INFO] Parsing IP intelligence JSON for scan %s", scanID)

	lines := strings.Split(jsonOutput, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}

		var ipInfo map[string]interface{}
		if err := json.Unmarshal([]byte(line), &ipInfo); err != nil {
			log.Printf("[METABIGOR-IP] [WARNING] Failed to parse JSON line: %v", err)
			continue
		}

		// Extract IP intelligence information
		ipAddress, _ := ipInfo["ip"].(string)
		asn, _ := ipInfo["asn"].(string)
		org, _ := ipInfo["org"].(string)
		country, _ := ipInfo["country"].(string)
		city, _ := ipInfo["city"].(string)

		if ipAddress != "" {
			InsertMetabigorIPIntelligence(scanID, ipAddress, asn, org, country, city, []int{}, []string{})
		}
	}
}

func ParseAndStoreOpenPorts(scanID, output string) {
	log.Printf("[METABIGOR-IP] [INFO] Parsing open ports for scan %s", scanID)

	lines := strings.Split(output, "\n")
	ipPortPattern := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)`)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if matches := ipPortPattern.FindStringSubmatch(line); len(matches) == 3 {
			ipAddress := matches[1]
			port, _ := strconv.Atoi(matches[2])

			// For now, just store the port info as a simple record
			InsertMetabigorIPIntelligence(scanID, ipAddress, "", "", "", "", []int{port}, []string{})
		}
	}
}

func InsertMetabigorIPIntelligence(scanID, ipAddress, asn, organization, country, city string, openPorts []int, services []string) {
	query := `INSERT INTO metabigor_ip_intelligence (scan_id, ip_address, asn, organization, country, city, open_ports, services) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := dbPool.Exec(context.Background(), query, scanID, ipAddress, asn, organization, country, city, openPorts, services)
	if err != nil {
		log.Printf("[METABIGOR-IP] [ERROR] Failed to insert IP intelligence: %v", err)
	}
}

func GetMetabigorIPIntelligence(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[METABIGOR-IP] [INFO] Retrieving IP intelligence for scan ID: %s", scanID)

	query := `SELECT ip_address, asn, organization, country, city, open_ports, services FROM metabigor_ip_intelligence WHERE scan_id = $1 ORDER BY ip_address`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[METABIGOR-IP] [ERROR] Failed to get IP intelligence: %v", err)
		http.Error(w, "Failed to get IP intelligence", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ipIntel []MetabigorIPIntelligence
	for rows.Next() {
		var ip MetabigorIPIntelligence
		err := rows.Scan(&ip.IPAddress, &ip.ASN, &ip.Organization, &ip.Country, &ip.City, &ip.OpenPorts, &ip.Services)
		if err != nil {
			log.Printf("[METABIGOR-IP] [ERROR] Error scanning IP intelligence row: %v", err)
			continue
		}
		ip.ScanID = scanID
		ipIntel = append(ipIntel, ip)
	}

	log.Printf("[METABIGOR-IP] [INFO] Retrieved %d IP intelligence records for scan %s", len(ipIntel), scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(ipIntel)
}

func DeleteMetabigorNetworkRange(w http.ResponseWriter, r *http.Request) {
	networkRangeID := mux.Vars(r)["id"]
	if networkRangeID == "" {
		http.Error(w, "Network range ID is required", http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(networkRangeID); err != nil {
		http.Error(w, "Invalid network range ID format", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM metabigor_network_ranges WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, networkRangeID)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to delete network range %s: %v", networkRangeID, err)
		http.Error(w, "Failed to delete network range", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Network range not found", http.StatusNotFound)
		return
	}

	log.Printf("[METABIGOR] [INFO] Successfully deleted network range %s", networkRangeID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Network range deleted successfully"})
}

func DeleteAllMetabigorNetworkRanges(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM metabigor_network_ranges WHERE scan_id = $1`
	result, err := dbPool.Exec(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[METABIGOR] [ERROR] Failed to delete all network ranges for scan %s: %v", scanID, err)
		http.Error(w, "Failed to delete network ranges", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	log.Printf("[METABIGOR] [INFO] Successfully deleted %d network ranges for scan %s", rowsAffected, scanID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "All network ranges deleted successfully",
		"deleted_count": rowsAffected,
	})
}
