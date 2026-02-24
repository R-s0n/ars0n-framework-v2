package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type DNSxScanStatus struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	Domains       []string  `json:"domains"`
	Status        string    `json:"status"`
	Result        *string   `json:"result,omitempty"`
	Error         *string   `json:"error,omitempty"`
	StdOut        *string   `json:"stdout,omitempty"`
	StdErr        *string   `json:"stderr,omitempty"`
	Command       *string   `json:"command,omitempty"`
	ExecTime      *string   `json:"execution_time,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	ScopeTargetID string    `json:"scope_target_id"`
}

type DNSxDNSRecord struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	Record    string    `json:"record"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type DNSxRawResult struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	RawOutput string    `json:"raw_output"`
	CreatedAt time.Time `json:"created_at"`
}

func RunDNSxCompanyScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Domains []string `json:"domains" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.Domains) == 0 {
		http.Error(w, "Invalid request body. `domains` array is required.", http.StatusBadRequest)
		return
	}

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	var scopeTarget string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target FROM scope_targets WHERE id = $1 AND type = 'Company'`,
		scopeTargetID).Scan(&scopeTarget)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] No matching company scope target found for ID %s", scopeTargetID)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	domainsJSON, _ := json.Marshal(payload.Domains)

	insertQuery := `INSERT INTO dnsx_company_scans (scan_id, domains, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, string(domainsJSON), "pending", scopeTargetID)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteDNSxCompanyScan(scanID, payload.Domains, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteDNSxCompanyScan(scanID string, domains []string, scopeTargetID string) {
	log.Printf("[DNSX-COMPANY] [INFO] Starting DNSx Company scan (scan ID: %s) for %d domains", scanID, len(domains))
	startTime := time.Now()

	UpdateDNSxCompanyScanStatus(scanID, "running", "", "", "", "")

	// Delete existing results for only the domains being scanned (domain-centric approach)
	for _, domain := range domains {
		log.Printf("[DNSX-COMPANY] [INFO] Clearing existing results for domain: %s", domain)

		// Delete existing DNS records for this specific domain
		_, err := dbPool.Exec(context.Background(),
			`DELETE FROM dnsx_company_dns_records WHERE scope_target_id = $1 AND root_domain = $2`,
			scopeTargetID, domain)
		if err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] Failed to delete existing DNS records for domain %s: %v", domain, err)
		}

		// Delete existing domain result entry
		_, err = dbPool.Exec(context.Background(),
			`DELETE FROM dnsx_company_domain_results WHERE scope_target_id = $1 AND domain = $2`,
			scopeTargetID, domain)
		if err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] Failed to delete existing domain result for domain %s: %v", domain, err)
		}
	}

	var allDNSRecords []DNSxDNSRecord
	var commandsExecuted []string

	for i, domain := range domains {
		log.Printf("[DNSX-COMPANY] [INFO] Processing domain %d/%d: %s", i+1, len(domains), domain)

		cmd := exec.Command(
			"docker", "exec", "-i",
			"ars0n-framework-v2-dnsx-1",
			"dnsx",
			"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-ptr", "-srv",
			"-re", "-j",
			"-retry", "3",
		)

		commandsExecuted = append(commandsExecuted, cmd.String())
		log.Printf("[DNSX-COMPANY] [INFO] Executing command: %s with domain: %s", cmd.String(), domain)

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		cmd.Stdin = strings.NewReader(domain + "\n")

		err := cmd.Run()
		if err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] DNSx scan failed for domain %s: %v", domain, err)
			log.Printf("[DNSX-COMPANY] [ERROR] stderr output: %s", stderr.String())
			continue
		}

		result := stdout.String()
		log.Printf("[DNSX-COMPANY] [INFO] DNSx scan completed for domain %s", domain)
		log.Printf("[DNSX-COMPANY] [DEBUG] Raw output length: %d bytes", len(result))

		// Store domain result in the new domain-centric table
		InsertDNSxDomainResult(scopeTargetID, domain, scanID, result)

		// Store raw result for this domain (for legacy scan-specific history)
		InsertDNSxRawResult(scanID, domain, result)

		if result != "" {
			dnsRecords := ParseDNSxResultsDomainCentric(scopeTargetID, domain, result, scanID)
			allDNSRecords = append(allDNSRecords, dnsRecords...)
		}
	}

	log.Printf("[DNSX-COMPANY] [INFO] Found %d DNS records", len(allDNSRecords))

	// Deduplicate DNS records before counting (for scan summary)
	uniqueDNSRecords := make(map[string]DNSxDNSRecord)
	for _, dnsRecord := range allDNSRecords {
		key := fmt.Sprintf("%s-%s", dnsRecord.Record, dnsRecord.Type)
		uniqueDNSRecords[key] = dnsRecord
	}

	// Convert back to slice for counting
	deduplicatedDNSRecords := make([]DNSxDNSRecord, 0, len(uniqueDNSRecords))
	for _, dnsRecord := range uniqueDNSRecords {
		deduplicatedDNSRecords = append(deduplicatedDNSRecords, dnsRecord)
	}

	log.Printf("[DNSX-COMPANY] [INFO] Deduplicated DNS records: %d unique records from %d total discoveries", len(deduplicatedDNSRecords), len(allDNSRecords))

	result := map[string]interface{}{
		"dns_records":     deduplicatedDNSRecords,
		"domains_scanned": len(domains),
		"summary": map[string]int{
			"total_dns_records": len(deduplicatedDNSRecords),
			"a_records":         countRecordsByType(deduplicatedDNSRecords, "A"),
			"aaaa_records":      countRecordsByType(deduplicatedDNSRecords, "AAAA"),
			"cname_records":     countRecordsByType(deduplicatedDNSRecords, "CNAME"),
			"mx_records":        countRecordsByType(deduplicatedDNSRecords, "MX"),
			"ns_records":        countRecordsByType(deduplicatedDNSRecords, "NS"),
			"txt_records":       countRecordsByType(deduplicatedDNSRecords, "TXT"),
			"ptr_records":       countRecordsByType(deduplicatedDNSRecords, "PTR"),
			"srv_records":       countRecordsByType(deduplicatedDNSRecords, "SRV"),
		},
	}

	resultJSON, _ := json.Marshal(result)
	execTime := time.Since(startTime).String()
	commandsStr := strings.Join(commandsExecuted, "; ")

	UpdateDNSxCompanyScanStatus(scanID, "success", string(resultJSON), "", commandsStr, execTime)

	log.Printf("[DNSX-COMPANY] [INFO] DNSx Company scan completed (scan ID: %s) in %s", scanID, execTime)
}

func ParseDNSxResultsDomainCentric(scopeTargetID, domain, result, scanID string) []DNSxDNSRecord {
	log.Printf("[DNSX-COMPANY] [INFO] Starting to parse results for domain %s", domain)

	var dnsRecords []DNSxDNSRecord

	// Parse JSON output from DNSx
	lines := strings.Split(strings.TrimSpace(result), "\n")
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		var jsonResult map[string]interface{}
		if err := json.Unmarshal([]byte(line), &jsonResult); err != nil {
			log.Printf("[DNSX-COMPANY] [DEBUG] Failed to parse JSON line: %s, error: %v", line, err)
			continue
		}

		// Extract DNS records from the JSON response
		if host, ok := jsonResult["host"].(string); ok {
			// Process A records
			if aRecords, ok := jsonResult["a"].([]interface{}); ok {
				for _, record := range aRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "A",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "A")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "A")
					}
				}
			}

			// Process AAAA records
			if aaaaRecords, ok := jsonResult["aaaa"].([]interface{}); ok {
				for _, record := range aaaaRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "AAAA",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "AAAA")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "AAAA")
					}
				}
			}

			// Process CNAME records
			if cnameRecords, ok := jsonResult["cname"].([]interface{}); ok {
				for _, record := range cnameRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "CNAME",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "CNAME")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "CNAME")
					}
				}
			}

			// Process MX records
			if mxRecords, ok := jsonResult["mx"].([]interface{}); ok {
				for _, record := range mxRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "MX",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "MX")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "MX")
					}
				}
			}

			// Process NS records
			if nsRecords, ok := jsonResult["ns"].([]interface{}); ok {
				for _, record := range nsRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "NS",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "NS")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "NS")
					}
				}
			}

			// Process TXT records
			if txtRecords, ok := jsonResult["txt"].([]interface{}); ok {
				for _, record := range txtRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "TXT",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "TXT")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "TXT")
					}
				}
			}

			// Process PTR records
			if ptrRecords, ok := jsonResult["ptr"].([]interface{}); ok {
				for _, record := range ptrRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "PTR",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "PTR")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "PTR")
					}
				}
			}

			// Process SRV records
			if srvRecords, ok := jsonResult["srv"].([]interface{}); ok {
				for _, record := range srvRecords {
					if recordStr, ok := record.(string); ok {
						dnsRecord := DNSxDNSRecord{
							Record: recordStr,
							Type:   "SRV",
						}
						dnsRecords = append(dnsRecords, dnsRecord)
						InsertDNSxDNSRecord(scanID, domain, recordStr, "SRV")
						InsertDNSxCompanyDNSRecord(scopeTargetID, domain, recordStr, "SRV")
					}
				}
			}

			log.Printf("[DNSX-COMPANY] [DEBUG] Processed host %s", host)
		}
	}

	log.Printf("[DNSX-COMPANY] [INFO] Parsed %d DNS records for domain %s", len(dnsRecords), domain)
	return dnsRecords
}

func countRecordsByType(records []DNSxDNSRecord, recordType string) int {
	count := 0
	for _, record := range records {
		if record.Type == recordType {
			count++
		}
	}
	return count
}

func InsertDNSxDNSRecord(scanID, domain, record, recordType string) {
	query := `INSERT INTO dnsx_dns_records (scan_id, domain, record, record_type, created_at) VALUES ($1, $2, $3, $4, NOW())`
	_, err := dbPool.Exec(context.Background(), query, scanID, domain, record, recordType)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to insert DNS record: %v", err)
	}
}

func InsertDNSxRawResult(scanID, domain, rawOutput string) {
	query := `INSERT INTO dnsx_raw_results (scan_id, domain, raw_output, created_at) VALUES ($1, $2, $3, NOW())`
	_, err := dbPool.Exec(context.Background(), query, scanID, domain, rawOutput)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to insert raw result: %v", err)
	}
}

func InsertDNSxDomainResult(scopeTargetID, domain, scanID, rawOutput string) {
	query := `
		INSERT INTO dnsx_company_domain_results (scope_target_id, domain, last_scanned_at, last_scan_id, raw_output, created_at, updated_at)
		VALUES ($1, $2, NOW(), $3, $4, NOW(), NOW())
		ON CONFLICT (scope_target_id, domain)
		DO UPDATE SET 
			last_scanned_at = NOW(),
			last_scan_id = $3,
			raw_output = $4,
			updated_at = NOW()
	`
	_, err := dbPool.Exec(context.Background(), query, scopeTargetID, domain, scanID, rawOutput)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to insert/update domain result: %v", err)
	}
}

func InsertDNSxCompanyDNSRecord(scopeTargetID, rootDomain, record, recordType string) {
	query := `
		INSERT INTO dnsx_company_dns_records (scope_target_id, root_domain, record, record_type, last_scanned_at, created_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW())
		ON CONFLICT (scope_target_id, root_domain, record, record_type)
		DO UPDATE SET 
			last_scanned_at = NOW()
	`
	_, err := dbPool.Exec(context.Background(), query, scopeTargetID, rootDomain, record, recordType)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to insert/update company DNS record: %v", err)
	}
}

func UpdateDNSxCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	query := `UPDATE dnsx_company_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to update scan status: %v", err)
	}
}

func GetDNSxCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `
		SELECT id, scan_id, domains, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id
		FROM dnsx_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to fetch scans: %v", err)
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []DNSxScanStatus
	for rows.Next() {
		var scan DNSxScanStatus
		var domainsJSON string
		var result, error, stdout, stderr, command, execTime sql.NullString

		err := rows.Scan(
			&scan.ID, &scan.ScanID, &domainsJSON, &scan.Status, &result, &error,
			&stdout, &stderr, &command, &execTime, &scan.CreatedAt, &scan.ScopeTargetID,
		)
		if err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] Failed to scan row: %v", err)
			continue
		}

		// Convert sql.NullString to *string
		if result.Valid {
			scan.Result = &result.String
		}
		if error.Valid {
			scan.Error = &error.String
		}
		if stdout.Valid {
			scan.StdOut = &stdout.String
		}
		if stderr.Valid {
			scan.StdErr = &stderr.String
		}
		if command.Valid {
			scan.Command = &command.String
		}
		if execTime.Valid {
			scan.ExecTime = &execTime.String
		}

		// Parse the domains JSON
		if err := json.Unmarshal([]byte(domainsJSON), &scan.Domains); err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] Failed to parse domains JSON: %v", err)
			scan.Domains = []string{}
		}

		scans = append(scans, scan)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func GetDNSxCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `
		SELECT id, scan_id, domains, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id
		FROM dnsx_company_scans WHERE scan_id = $1`

	var scan DNSxScanStatus
	var domainsJSON string
	var result, error, stdout, stderr, command, execTime sql.NullString

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID, &scan.ScanID, &domainsJSON, &scan.Status, &result, &error,
		&stdout, &stderr, &command, &execTime, &scan.CreatedAt, &scan.ScopeTargetID,
	)

	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to fetch scan status: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	// Convert sql.NullString to *string
	if result.Valid {
		scan.Result = &result.String
	}
	if error.Valid {
		scan.Error = &error.String
	}
	if stdout.Valid {
		scan.StdOut = &stdout.String
	}
	if stderr.Valid {
		scan.StdErr = &stderr.String
	}
	if command.Valid {
		scan.Command = &command.String
	}
	if execTime.Valid {
		scan.ExecTime = &execTime.String
	}

	// Parse the domains JSON
	if err := json.Unmarshal([]byte(domainsJSON), &scan.Domains); err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to parse domains JSON: %v", err)
		scan.Domains = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetDNSxDNSRecords(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	// First verify that the scan exists and get the scope target ID
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM dnsx_company_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)

	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to find scan: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	query := `
		SELECT id, scan_id, domain, record, record_type, created_at
		FROM dnsx_dns_records 
		WHERE scan_id = $1 
		ORDER BY domain, record_type, record`

	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to fetch DNS records: %v", err)
		http.Error(w, "Failed to fetch DNS records", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var dnsRecords []DNSxDNSRecord
	for rows.Next() {
		var record DNSxDNSRecord
		err := rows.Scan(&record.ID, &record.ScanID, &record.Domain, &record.Record, &record.Type, &record.CreatedAt)
		if err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] Failed to scan DNS record row: %v", err)
			continue
		}
		dnsRecords = append(dnsRecords, record)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dnsRecords)
}

func GetDNSxRawResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	// First verify that the scan exists and get the scope target ID
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM dnsx_company_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)

	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to find scan: %v", err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	query := `
		SELECT id, scan_id, domain, raw_output, created_at
		FROM dnsx_raw_results 
		WHERE scan_id = $1 
		ORDER BY domain`

	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[DNSX-COMPANY] [ERROR] Failed to fetch raw results: %v", err)
		http.Error(w, "Failed to fetch raw results", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var rawResults []DNSxRawResult
	for rows.Next() {
		var result DNSxRawResult
		err := rows.Scan(&result.ID, &result.ScanID, &result.Domain, &result.RawOutput, &result.CreatedAt)
		if err != nil {
			log.Printf("[DNSX-COMPANY] [ERROR] Failed to scan raw result row: %v", err)
			continue
		}
		rawResults = append(rawResults, result)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rawResults)
}
