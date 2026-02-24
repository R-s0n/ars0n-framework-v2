package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type AmassIntelScanStatus struct {
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
	AutoScanSessionID sql.NullString `json:"auto_scan_session_id"`
}

type IntelNetworkRangeResponse struct {
	ID           string `json:"id"`
	CIDRBlock    string `json:"cidr_block"`
	ASN          string `json:"asn"`
	Organization string `json:"organization"`
	Description  string `json:"description"`
	Country      string `json:"country"`
	ScanID       string `json:"scan_id"`
}

type IntelASNResponse struct {
	ASNNumber    string `json:"asn_number"`
	Organization string `json:"organization"`
	Description  string `json:"description"`
	Country      string `json:"country"`
	ScanID       string `json:"scan_id"`
}

func RunAmassIntelScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var requestID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&requestID)
	if err != nil {
		log.Printf("[ERROR] No matching company scope target found for company %s", companyName)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO amass_intel_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", requestID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO amass_intel_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", requestID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create amass intel scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAmassIntelScan(scanID, companyName)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAmassIntelScan(scanID, companyName string) {
	log.Printf("[INFO] Starting Amass Intel scan for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	cmd := exec.Command(
		"docker", "run", "--rm",
		"caffix/amass",
		"intel",
		"-org", companyName,
		"-whois",
		"-active",
		"-timeout", "120",
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Amass Intel scan failed for %s: %v", companyName, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateIntelScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] Amass Intel scan completed in %s for company %s", execTime, companyName)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result != "" {
		log.Printf("[INFO] Starting to parse Intel network range results for scan %s", scanID)
		ParseAndStoreIntelNetworkResults(scanID, companyName, result)
		log.Printf("[INFO] Finished parsing Intel network range results for scan %s", scanID)
	} else {
		log.Printf("[WARN] No output from Amass Intel scan for company %s", companyName)
	}

	UpdateIntelScanStatus(scanID, "success", "{}", stderr.String(), cmd.String(), execTime)
	log.Printf("[INFO] Intel scan status updated for scan %s", scanID)
}

func ParseAndStoreIntelNetworkResults(scanID, companyName, result string) {
	log.Printf("[INFO] Starting to parse Intel network results for scan %s on company %s", scanID, companyName)

	lines := strings.Split(result, "\n")
	log.Printf("[INFO] Processing %d lines of Intel output", len(lines))

	asnPattern := regexp.MustCompile(`^ASN:\s*(\d+)\s*-\s*(.+?)\s*-\s*(.+)$`)
	cidrPattern := regexp.MustCompile(`^\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})\s*$`)

	var currentASN, currentDescription, currentOrganization string

	for lineNum, line := range lines {
		originalLine := line
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		log.Printf("[DEBUG] Processing line %d: %s", lineNum+1, line)

		if asnPattern.MatchString(line) {
			matches := asnPattern.FindStringSubmatch(line)
			if len(matches) == 4 {
				currentASN = matches[1]
				currentDescription = strings.TrimSpace(matches[2])
				currentOrganization = strings.TrimSpace(matches[3])

				InsertIntelASNData(scanID, currentASN, currentOrganization, currentDescription, "")
				log.Printf("[DEBUG] Parsed ASN: AS%s, Org: %s, Desc: %s", currentASN, currentOrganization, currentDescription)
			}
		} else if cidrPattern.MatchString(originalLine) {
			matches := cidrPattern.FindStringSubmatch(originalLine)
			if len(matches) == 2 {
				cidrBlock := matches[1]

				asn := ""
				if currentASN != "" {
					asn = "AS" + currentASN
				}

				InsertIntelNetworkRange(scanID, cidrBlock, asn, currentOrganization, currentDescription, "")
				log.Printf("[DEBUG] Parsed network range: %s, ASN: %s, Org: %s", cidrBlock, asn, currentOrganization)
			}
		}
	}
	log.Printf("[INFO] Completed parsing Intel network results for scan %s", scanID)
}

func InsertIntelNetworkRange(scanID, cidrBlock, asn, organization, description, country string) {
	log.Printf("[INFO] Inserting Intel network range: %s", cidrBlock)
	query := `INSERT INTO intel_network_ranges (scan_id, cidr_block, asn, organization, description, country) VALUES ($1, $2, $3, $4, $5, $6)`
	_, err := dbPool.Exec(context.Background(), query, scanID, cidrBlock, asn, organization, description, country)
	if err != nil {
		log.Printf("[ERROR] Failed to insert Intel network range: %v", err)
	} else {
		log.Printf("[INFO] Successfully inserted Intel network range: %s", cidrBlock)
	}
}

func InsertIntelASNData(scanID, asnNumber, organization, description, country string) {
	log.Printf("[INFO] Inserting Intel ASN data: AS%s", asnNumber)
	query := `INSERT INTO intel_asn_data (scan_id, asn_number, organization, description, country) VALUES ($1, $2, $3, $4, $5)`
	_, err := dbPool.Exec(context.Background(), query, scanID, asnNumber, organization, description, country)
	if err != nil {
		log.Printf("[ERROR] Failed to insert Intel ASN data: %v", err)
	} else {
		log.Printf("[INFO] Successfully inserted Intel ASN data: AS%s", asnNumber)
	}
}

func UpdateIntelScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Intel scan status for %s to %s", scanID, status)
	query := `UPDATE amass_intel_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Intel scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Intel scan status for %s", scanID)
	}
}

func GetAmassIntelScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scanID"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	var scan AmassIntelScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, auto_scan_session_id FROM amass_intel_scans WHERE scan_id = $1`
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
		&scan.AutoScanSessionID,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch Intel scan status: %v", err)
		http.Error(w, "Scan not found.", http.StatusNotFound)
		return
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
		"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func GetAmassIntelScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, auto_scan_session_id 
              FROM amass_intel_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch Intel scans for scope target ID %s: %v", scopeTargetID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan AmassIntelScanStatus
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
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		scans = append(scans, map[string]interface{}{
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
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(scans)
}

func GetIntelNetworkRanges(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" || scanID == "No scans available" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `SELECT id, cidr_block, asn, organization, description, country, scan_id FROM intel_network_ranges WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch Intel network ranges", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var networkRanges []IntelNetworkRangeResponse
	for rows.Next() {
		var networkRange IntelNetworkRangeResponse
		if err := rows.Scan(&networkRange.ID, &networkRange.CIDRBlock, &networkRange.ASN, &networkRange.Organization, &networkRange.Description, &networkRange.Country, &networkRange.ScanID); err != nil {
			http.Error(w, "Error scanning Intel network range", http.StatusInternalServerError)
			return
		}
		networkRanges = append(networkRanges, networkRange)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(networkRanges)
}

func GetIntelASNData(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" || scanID == "No scans available" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `SELECT asn_number, organization, description, country, scan_id FROM intel_asn_data WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch Intel ASN data", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var asnData []IntelASNResponse
	for rows.Next() {
		var asn IntelASNResponse
		if err := rows.Scan(&asn.ASNNumber, &asn.Organization, &asn.Description, &asn.Country, &asn.ScanID); err != nil {
			http.Error(w, "Error scanning Intel ASN data", http.StatusInternalServerError)
			return
		}
		asnData = append(asnData, asn)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(asnData)
}

func DeleteIntelNetworkRange(w http.ResponseWriter, r *http.Request) {
	networkRangeID := mux.Vars(r)["id"]
	if networkRangeID == "" {
		http.Error(w, "Network range ID is required", http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(networkRangeID); err != nil {
		http.Error(w, "Invalid network range ID format", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM intel_network_ranges WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, networkRangeID)
	if err != nil {
		log.Printf("[AMASS-INTEL] [ERROR] Failed to delete network range %s: %v", networkRangeID, err)
		http.Error(w, "Failed to delete network range", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Network range not found", http.StatusNotFound)
		return
	}

	log.Printf("[AMASS-INTEL] [INFO] Successfully deleted network range %s", networkRangeID)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Network range deleted successfully"})
}

func DeleteAllIntelNetworkRanges(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM intel_network_ranges WHERE scan_id = $1`
	result, err := dbPool.Exec(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[AMASS-INTEL] [ERROR] Failed to delete all network ranges for scan %s: %v", scanID, err)
		http.Error(w, "Failed to delete network ranges", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	log.Printf("[AMASS-INTEL] [INFO] Successfully deleted %d network ranges for scan %s", rowsAffected, scanID)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":       "All network ranges deleted successfully",
		"deleted_count": rowsAffected,
	})
}
