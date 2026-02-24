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
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type AmassEnumScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domains       []string       `json:"domains"`
	Status        string         `json:"status"`
	Result        sql.NullString `json:"result,omitempty"`
	Error         sql.NullString `json:"error,omitempty"`
	StdOut        sql.NullString `json:"stdout,omitempty"`
	StdErr        sql.NullString `json:"stderr,omitempty"`
	Command       sql.NullString `json:"command,omitempty"`
	ExecTime      sql.NullString `json:"execution_time,omitempty"`
	CreatedAt     time.Time      `json:"created_at"`
	ScopeTargetID string         `json:"scope_target_id"`
}

type AmassEnumCloudDomain struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type AmassEnumDNSRecord struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Record    string    `json:"record"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

type AmassEnumRawResult struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	RawOutput string    `json:"raw_output"`
	CreatedAt time.Time `json:"created_at"`
}

func RunAmassEnumCompanyScan(w http.ResponseWriter, r *http.Request) {
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
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] No matching company scope target found for ID %s", scopeTargetID)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	domainsJSON, _ := json.Marshal(payload.Domains)

	insertQuery := `INSERT INTO amass_enum_company_scans (scan_id, domains, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, string(domainsJSON), "pending", scopeTargetID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAmassEnumCompanyScan(scanID, payload.Domains, scopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAmassEnumCompanyScan(scanID string, domains []string, scopeTargetID string) {
	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Starting Amass Enum Company scan (scan ID: %s) for %d domains", scanID, len(domains))
	startTime := time.Now()

	UpdateAmassEnumCompanyScanStatus(scanID, "running", "", "", "", "")

	// Delete existing results for only the domains being scanned (domain-centric approach)
	for _, domain := range domains {
		log.Printf("[AMASS-ENUM-COMPANY] [INFO] Clearing existing results for domain: %s", domain)

		// Delete existing cloud domains for this specific domain
		_, err := dbPool.Exec(context.Background(),
			`DELETE FROM amass_enum_company_cloud_domains WHERE scope_target_id = $1 AND root_domain = $2`,
			scopeTargetID, domain)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to delete existing cloud domains for domain %s: %v", domain, err)
		}

		// Delete existing DNS records for this specific domain
		_, err = dbPool.Exec(context.Background(),
			`DELETE FROM amass_enum_company_dns_records WHERE scope_target_id = $1 AND root_domain = $2`,
			scopeTargetID, domain)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to delete existing DNS records for domain %s: %v", domain, err)
		}

		// Delete existing domain result entry
		_, err = dbPool.Exec(context.Background(),
			`DELETE FROM amass_enum_company_domain_results WHERE scope_target_id = $1 AND domain = $2`,
			scopeTargetID, domain)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to delete existing domain result for domain %s: %v", domain, err)
		}
	}

	var allCloudDomains []AmassEnumCloudDomain
	var allDNSRecords []AmassEnumDNSRecord
	var commandsExecuted []string

	for i, domain := range domains {
		log.Printf("[AMASS-ENUM-COMPANY] [INFO] Processing domain %d/%d: %s", i+1, len(domains), domain)

		rateLimit := GetAmassRateLimit()
		log.Printf("[AMASS-ENUM-COMPANY] [INFO] Using rate limit of %d for Amass scan", rateLimit)

		cmd := exec.Command(
			"docker", "run", "--rm",
			"caffix/amass",
			"enum", "-passive", "-alts", "-brute", "-nocolor",
			"-min-for-recursive", "2", "-timeout", "300",
			"-d", domain,
			// Primary public DNS resolvers
			"-r", "8.8.8.8", // Google
			"-r", "8.8.4.4", // Google Secondary
			"-r", "1.1.1.1", // Cloudflare
			"-r", "1.0.0.1", // Cloudflare Secondary
			"-r", "9.9.9.9", // Quad9
			"-r", "149.112.112.112", // Quad9 Secondary
			"-r", "64.6.64.6", // Verisign
			"-r", "64.6.65.6", // Verisign Secondary
			// Additional reliable resolvers
			"-r", "208.67.222.222", // OpenDNS
			"-r", "208.67.220.220", // OpenDNS Secondary
			"-r", "76.76.19.19", // Alternate DNS
			"-r", "76.223.100.101", // Alternate DNS Secondary
			"-r", "8.26.56.26", // Comodo Secure DNS
			"-r", "8.20.247.20", // Comodo Secure DNS Secondary
			"-r", "185.228.168.9", // CleanBrowsing
			"-r", "185.228.169.9", // CleanBrowsing Secondary
			"-r", "77.88.8.8", // Yandex DNS
			"-r", "77.88.8.1", // Yandex DNS Secondary
			"-rqps", fmt.Sprintf("%d", rateLimit),
		)

		commandsExecuted = append(commandsExecuted, cmd.String())
		log.Printf("[AMASS-ENUM-COMPANY] [INFO] Executing command: %s", cmd.String())

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Amass scan failed for domain %s: %v", domain, err)
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] stderr output: %s", stderr.String())
			continue
		}

		result := stdout.String()
		log.Printf("[AMASS-ENUM-COMPANY] [INFO] Amass scan completed for domain %s", domain)
		log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Raw output length: %d bytes", len(result))

		// Store domain result in the new domain-centric table
		InsertAmassEnumDomainResult(scopeTargetID, domain, scanID, result)

		// Store raw result for this domain (for legacy scan-specific history)
		InsertAmassEnumRawResult(scanID, domain, result)

		if result != "" {
			cloudDomains, dnsRecords := ParseAmassEnumResultsDomainCentric(scopeTargetID, domain, result)
			allCloudDomains = append(allCloudDomains, cloudDomains...)
			allDNSRecords = append(allDNSRecords, dnsRecords...)
		}
	}

	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Found %d cloud domains and %d DNS records", len(allCloudDomains), len(allDNSRecords))

	// Deduplicate cloud domains before counting (for scan summary)
	uniqueCloudDomains := make(map[string]AmassEnumCloudDomain)
	for _, cloudDomain := range allCloudDomains {
		uniqueCloudDomains[cloudDomain.Domain] = cloudDomain
	}

	// Convert back to slice for counting
	deduplicatedCloudDomains := make([]AmassEnumCloudDomain, 0, len(uniqueCloudDomains))
	for _, cloudDomain := range uniqueCloudDomains {
		deduplicatedCloudDomains = append(deduplicatedCloudDomains, cloudDomain)
	}

	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Deduplicated cloud domains: %d unique domains from %d total discoveries", len(deduplicatedCloudDomains), len(allCloudDomains))

	result := map[string]interface{}{
		"cloud_domains":   deduplicatedCloudDomains,
		"dns_records":     allDNSRecords,
		"domains_scanned": len(domains),
		"summary": map[string]int{
			"total_cloud_domains": len(deduplicatedCloudDomains),
			"aws_domains":         countDomainsByType(deduplicatedCloudDomains, "aws"),
			"gcp_domains":         countDomainsByType(deduplicatedCloudDomains, "gcp"),
			"azure_domains":       countDomainsByType(deduplicatedCloudDomains, "azure"),
			"other_domains":       countDomainsByType(deduplicatedCloudDomains, "unknown"),
		},
	}

	resultJSON, _ := json.Marshal(result)
	execTime := time.Since(startTime).String()
	commandsStr := strings.Join(commandsExecuted, "; ")

	UpdateAmassEnumCompanyScanStatus(scanID, "success", string(resultJSON), "", commandsStr, execTime)

	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Amass Enum Company scan completed (scan ID: %s) in %s", scanID, execTime)
}

func ParseAmassEnumResults(scanID, domain, result string) ([]AmassEnumCloudDomain, []AmassEnumDNSRecord) {
	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Starting to parse results for scan %s on domain %s", scanID, domain)

	var cloudDomains []AmassEnumCloudDomain
	var dnsRecords []AmassEnumDNSRecord

	patterns := map[string]*regexp.Regexp{
		"subdomain": regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
		"dns_a":     regexp.MustCompile(`a_record`),
		"dns_aaaa":  regexp.MustCompile(`aaaa_record`),
		"dns_cname": regexp.MustCompile(`cname_record`),
		"dns_mx":    regexp.MustCompile(`mx_record`),
		"dns_txt":   regexp.MustCompile(`txt_record`),
		"dns_ns":    regexp.MustCompile(`ns_record`),
	}

	lines := strings.Split(result, "\n")
	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Processing %d lines of output", len(lines))

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Processing line %d: %s", lineNum+1, line)

		if matches := patterns["subdomain"].FindAllString(line, -1); len(matches) > 0 {
			for _, subdomain := range matches {
				subdomain = strings.ToLower(subdomain)
				if IsCloudDomain(subdomain) {
					cloudType := getCloudDomainType(subdomain)
					log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Cloud domain found: %s (type: %s)", subdomain, cloudType)
					cloudDomains = append(cloudDomains, AmassEnumCloudDomain{
						ScanID: scanID,
						Domain: subdomain,
						Type:   cloudType,
					})
				}
			}
		}

		for recordType, pattern := range map[string]*regexp.Regexp{
			"A":     patterns["dns_a"],
			"AAAA":  patterns["dns_aaaa"],
			"CNAME": patterns["dns_cname"],
			"MX":    patterns["dns_mx"],
			"TXT":   patterns["dns_txt"],
			"NS":    patterns["dns_ns"],
		} {
			if pattern.MatchString(line) {
				log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Found DNS record type %s: %s", recordType, line)
				dnsRecords = append(dnsRecords, AmassEnumDNSRecord{
					ScanID: scanID,
					Record: line,
					Type:   recordType,
				})
			}
		}
	}

	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Completed parsing results for scan %s - found %d cloud domains, %d DNS records", scanID, len(cloudDomains), len(dnsRecords))
	return cloudDomains, dnsRecords
}

func getCloudDomainType(domain string) string {
	awsDomains := []string{"amazonaws.com", "awsdns", "cloudfront.net"}
	googleDomains := []string{"google.com", "gcloud.com", "appspot.com", "googleapis.com", "gcp.com", "withgoogle.com"}
	azureDomains := []string{"azure.com", "cloudapp.azure.com", "windows.net", "microsoft.com", "trafficmanager.net", "azureedge.net", "azure.net", "azurewebsites.net", "azure-api.net"}

	for _, awsDomain := range awsDomains {
		if strings.Contains(domain, awsDomain) {
			return "aws"
		}
	}

	for _, googleDomain := range googleDomains {
		if strings.Contains(domain, googleDomain) {
			return "gcp"
		}
	}

	for _, azureDomain := range azureDomains {
		if strings.Contains(domain, azureDomain) {
			return "azure"
		}
	}

	return "unknown"
}

func countDomainsByType(domains []AmassEnumCloudDomain, domainType string) int {
	count := 0
	for _, domain := range domains {
		if domain.Type == domainType {
			count++
		}
	}
	return count
}

func InsertAmassEnumCloudDomain(scanID, domain, domainType string) {
	query := `INSERT INTO amass_enum_cloud_domains (scan_id, domain, type) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, domain, domainType)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to insert cloud domain %s: %v", domain, err)
		return
	}
	log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Successfully inserted cloud domain %s with type %s", domain, domainType)
}

func InsertAmassEnumDNSRecord(scanID, record, recordType string) {
	query := `INSERT INTO amass_enum_dns_records (scan_id, record, record_type) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, record, recordType)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to insert DNS record: %v", err)
		return
	}
	log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Successfully inserted DNS record type %s", recordType)
}

func InsertAmassEnumRawResult(scanID, domain, rawOutput string) {
	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO amass_enum_raw_results (scan_id, domain, raw_output) VALUES ($1, $2, $3)`,
		scanID, domain, rawOutput)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to insert raw result: %v", err)
	}
}

// InsertAmassEnumDomainResult stores domain scan results in the domain-centric table
func InsertAmassEnumDomainResult(scopeTargetID, domain, scanID, rawOutput string) {
	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO amass_enum_company_domain_results (scope_target_id, domain, last_scan_id, raw_output, last_scanned_at, updated_at) 
		 VALUES ($1, $2, $3, $4, NOW(), NOW())
		 ON CONFLICT (scope_target_id, domain) 
		 DO UPDATE SET last_scan_id = $3, raw_output = $4, last_scanned_at = NOW(), updated_at = NOW()`,
		scopeTargetID, domain, scanID, rawOutput)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to insert/update domain result: %v", err)
	}
}

// ParseAmassEnumResultsDomainCentric parses results and stores them in domain-centric tables
func ParseAmassEnumResultsDomainCentric(scopeTargetID, domain, result string) ([]AmassEnumCloudDomain, []AmassEnumDNSRecord) {
	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Starting to parse results for domain %s", domain)

	var cloudDomains []AmassEnumCloudDomain
	var dnsRecords []AmassEnumDNSRecord

	patterns := map[string]*regexp.Regexp{
		"subdomain": regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
		"dns_a":     regexp.MustCompile(`a_record`),
		"dns_aaaa":  regexp.MustCompile(`aaaa_record`),
		"dns_cname": regexp.MustCompile(`cname_record`),
		"dns_mx":    regexp.MustCompile(`mx_record`),
		"dns_txt":   regexp.MustCompile(`txt_record`),
		"dns_ns":    regexp.MustCompile(`ns_record`),
	}

	lines := strings.Split(result, "\n")
	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Processing %d lines of output", len(lines))

	for lineNum, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Processing line %d: %s", lineNum+1, line)

		// Extract subdomains using regex
		if matches := patterns["subdomain"].FindAllString(line, -1); len(matches) > 0 {
			for _, subdomain := range matches {
				subdomain = strings.ToLower(subdomain)
				if IsCloudDomain(subdomain) {
					cloudType := getCloudDomainType(subdomain)
					log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Cloud domain found: %s (type: %s)", subdomain, cloudType)

					// Add to return array (will be deduplicated later)
					cloudDomains = append(cloudDomains, AmassEnumCloudDomain{
						Domain: subdomain,
						Type:   cloudType,
					})
				}
			}
		}

		// Parse DNS records
		for recordType, pattern := range map[string]*regexp.Regexp{
			"A":     patterns["dns_a"],
			"AAAA":  patterns["dns_aaaa"],
			"CNAME": patterns["dns_cname"],
			"MX":    patterns["dns_mx"],
			"TXT":   patterns["dns_txt"],
			"NS":    patterns["dns_ns"],
		} {
			if pattern.MatchString(line) {
				log.Printf("[AMASS-ENUM-COMPANY] [DEBUG] Found DNS record type %s: %s", recordType, line)

				// Add to return array
				dnsRecords = append(dnsRecords, AmassEnumDNSRecord{
					Record: line,
					Type:   recordType,
				})

				// Insert DNS records immediately (these are typically unique)
				_, err := dbPool.Exec(context.Background(),
					`INSERT INTO amass_enum_company_dns_records (scope_target_id, root_domain, record, record_type, last_scanned_at) 
					 VALUES ($1, $2, $3, $4, NOW())
					 ON CONFLICT (scope_target_id, root_domain, record, record_type) 
					 DO UPDATE SET last_scanned_at = NOW()`,
					scopeTargetID, domain, line, recordType)
				if err != nil {
					log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to insert DNS record: %v", err)
				}
			}
		}
	}

	// Deduplicate cloud domains before storing (like original approach)
	uniqueCloudDomains := make(map[string]AmassEnumCloudDomain)
	for _, cloudDomain := range cloudDomains {
		uniqueCloudDomains[cloudDomain.Domain] = cloudDomain
	}

	// Convert back to slice and insert deduplicated domains
	deduplicatedCloudDomains := make([]AmassEnumCloudDomain, 0, len(uniqueCloudDomains))
	for _, cloudDomain := range uniqueCloudDomains {
		// Insert into domain-centric cloud domains table
		_, err := dbPool.Exec(context.Background(),
			`INSERT INTO amass_enum_company_cloud_domains (scope_target_id, root_domain, cloud_domain, type, last_scanned_at) 
			 VALUES ($1, $2, $3, $4, NOW())
			 ON CONFLICT (scope_target_id, root_domain, cloud_domain) 
			 DO UPDATE SET type = $4, last_scanned_at = NOW()`,
			scopeTargetID, domain, cloudDomain.Domain, cloudDomain.Type)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to insert cloud domain: %v", err)
		}

		deduplicatedCloudDomains = append(deduplicatedCloudDomains, cloudDomain)
	}

	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Completed parsing results for domain %s - found %d unique cloud domains from %d total discoveries, %d DNS records",
		domain, len(deduplicatedCloudDomains), len(cloudDomains), len(dnsRecords))

	return deduplicatedCloudDomains, dnsRecords
}

func UpdateAmassEnumCompanyScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[AMASS-ENUM-COMPANY] [INFO] Updating scan status for %s to %s", scanID, status)
	query := `UPDATE amass_enum_company_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to update scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[AMASS-ENUM-COMPANY] [INFO] Successfully updated scan status for %s", scanID)
	}
}

func GetAmassEnumCompanyScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, domains, status, result, error, stdout, stderr, command, execution_time, created_at 
              FROM amass_enum_company_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to fetch scans for scope target ID %s: %v", scopeTargetID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var id, scanID, domainsJSON, status string
		var result, error, stdout, stderr, command, execTime sql.NullString
		var createdAt time.Time

		err := rows.Scan(&id, &scanID, &domainsJSON, &status, &result, &error, &stdout, &stderr, &command, &execTime, &createdAt)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to scan row: %v", err)
			continue
		}

		var domains []string
		json.Unmarshal([]byte(domainsJSON), &domains)

		scan := map[string]interface{}{
			"id":             id,
			"scan_id":        scanID,
			"domains":        domains,
			"status":         status,
			"result":         nullStringToString(result),
			"error":          nullStringToString(error),
			"stdout":         nullStringToString(stdout),
			"stderr":         nullStringToString(stderr),
			"command":        nullStringToString(command),
			"execution_time": nullStringToString(execTime),
			"created_at":     createdAt,
		}
		scans = append(scans, scan)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func GetAmassEnumCompanyScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, domains, status, result, error, stdout, stderr, command, execution_time, created_at
              FROM amass_enum_company_scans WHERE scan_id = $1`

	var id, domains, status string
	var result, error, stdout, stderr, command, execTime sql.NullString
	var createdAt time.Time

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(&id, &scanID, &domains, &status, &result, &error, &stdout, &stderr, &command, &execTime, &createdAt)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to get scan status for %s: %v", scanID, err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	var domainsArray []string
	json.Unmarshal([]byte(domains), &domainsArray)

	scan := map[string]interface{}{
		"id":             id,
		"scan_id":        scanID,
		"domains":        domainsArray,
		"status":         status,
		"result":         nullStringToString(result),
		"error":          nullStringToString(error),
		"stdout":         nullStringToString(stdout),
		"stderr":         nullStringToString(stderr),
		"command":        nullStringToString(command),
		"execution_time": nullStringToString(execTime),
		"created_at":     createdAt,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetAmassEnumCloudDomains(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	// Get scope_target_id from scan
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM amass_enum_company_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to get scope target ID for scan %s: %v", scanID, err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	// Fetch all cloud domains for this scope target (domain-centric approach)
	rows, err := dbPool.Query(context.Background(),
		`SELECT id, root_domain, cloud_domain, type, last_scanned_at 
		 FROM amass_enum_company_cloud_domains 
		 WHERE scope_target_id = $1 
		 ORDER BY last_scanned_at DESC, cloud_domain`,
		scopeTargetID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to fetch cloud domains: %v", err)
		http.Error(w, "Failed to fetch cloud domains", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var cloudDomains []map[string]interface{}
	for rows.Next() {
		var id, rootDomain, cloudDomain, domainType string
		var lastScannedAt time.Time

		err := rows.Scan(&id, &rootDomain, &cloudDomain, &domainType, &lastScannedAt)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Error scanning cloud domain row: %v", err)
			continue
		}

		cloudDomains = append(cloudDomains, map[string]interface{}{
			"id":              id,
			"root_domain":     rootDomain,
			"domain":          cloudDomain,
			"type":            domainType,
			"created_at":      lastScannedAt,
			"last_scanned_at": lastScannedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(cloudDomains)
}

func GetAmassEnumRawResults(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	// Get scope_target_id from scan
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM amass_enum_company_scans WHERE scan_id = $1`,
		scanID).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to get scope target ID for scan %s: %v", scanID, err)
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	// Fetch all domain results for this scope target (domain-centric approach)
	rows, err := dbPool.Query(context.Background(),
		`SELECT id, domain, raw_output, last_scanned_at 
		 FROM amass_enum_company_domain_results 
		 WHERE scope_target_id = $1 AND raw_output IS NOT NULL 
		 ORDER BY last_scanned_at DESC, domain`,
		scopeTargetID)
	if err != nil {
		log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Failed to fetch raw results: %v", err)
		http.Error(w, "Failed to fetch raw results", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var rawResults []map[string]interface{}
	for rows.Next() {
		var id, domain, rawOutput string
		var lastScannedAt time.Time

		err := rows.Scan(&id, &domain, &rawOutput, &lastScannedAt)
		if err != nil {
			log.Printf("[AMASS-ENUM-COMPANY] [ERROR] Error scanning raw result row: %v", err)
			continue
		}

		rawResults = append(rawResults, map[string]interface{}{
			"id":              id,
			"domain":          domain,
			"raw_output":      rawOutput,
			"created_at":      lastScannedAt,
			"last_scanned_at": lastScannedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rawResults)
}
