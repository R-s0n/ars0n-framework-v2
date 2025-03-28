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
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbPool *pgxpool.Pool

func InitDB(pool *pgxpool.Pool) {
	dbPool = pool
}

func nullStringToString(ns sql.NullString) string {
	if ns.Valid {
		return ns.String
	}
	return ""
}

type ServiceProviderResponse struct {
	Provider string `json:"provider"`
	RawData  string `json:"raw_data"`
}

type SubnetResponse struct {
	CIDR    string `json:"cidr"`
	RawData string `json:"raw_data"`
}

type ASNResponse struct {
	Number  string `json:"number"`
	RawData string `json:"raw_data"`
}

type AmassScanStatus struct {
	ID        string         `json:"id"`
	ScanID    string         `json:"scan_id"`
	Domain    string         `json:"domain"`
	Status    string         `json:"status"`
	Result    sql.NullString `json:"result,omitempty"`
	Error     sql.NullString `json:"error,omitempty"`
	StdOut    sql.NullString `json:"stdout,omitempty"`
	StdErr    sql.NullString `json:"stderr,omitempty"`
	Command   sql.NullString `json:"command,omitempty"`
	ExecTime  sql.NullString `json:"execution_time,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

type DNSRecord struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Record    string    `json:"record"`
	Type      string    `json:"type"`
	CreatedAt time.Time `json:"created_at"`
}

func ParseAndStoreResults(scanID, domain, result string) {
	log.Printf("[INFO] Starting to parse results for scan %s on domain %s", scanID, domain)

	patterns := map[string]*regexp.Regexp{
		"service_provider": regexp.MustCompile(`(\d+)\s+\(ASN\)\s+-->\s+managed_by\s+-->\s+(.+?)\s+\(RIROrganization\)`),
		"asn_announces":    regexp.MustCompile(`(\d+)\s+\(ASN\)\s+-->\s+announces\s+-->\s+([^\s]+)\s+\(Netblock\)`),
		"subnet_contains":  regexp.MustCompile(`([^\s]+)\s+\(Netblock\)\s+-->\s+contains\s+-->\s+([^\s]+)\s+\(IPAddress\)`),
		"subdomain":        regexp.MustCompile(`([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`),
		"ipv4":             regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+\(IPAddress\)`),
		"dns_a":            regexp.MustCompile(`a_record`),
		"dns_aaaa":         regexp.MustCompile(`aaaa_record`),
		"dns_cname":        regexp.MustCompile(`cname_record`),
		"dns_mx":           regexp.MustCompile(`mx_record`),
		"dns_txt":          regexp.MustCompile(`txt_record`),
		"dns_ns":           regexp.MustCompile(`ns_record`),
		"dns_srv":          regexp.MustCompile(`srv_record`),
		"dns_ptr":          regexp.MustCompile(`ptr_record`),
		"dns_spf":          regexp.MustCompile(`spf_record`),
		"dns_soa":          regexp.MustCompile(`soa_record`),
	}

	lines := strings.Split(result, "\n")
	log.Printf("[INFO] Processing %d lines of output", len(lines))

	for lineNum, line := range lines {
		log.Printf("[DEBUG] Processing line %d: %s", lineNum+1, line)

		// Parse ASN and Service Provider information
		if matches := patterns["service_provider"].FindStringSubmatch(line); len(matches) > 2 {
			asn := matches[1]
			provider := matches[2]
			log.Printf("[DEBUG] Found ASN %s with provider %s", asn, provider)
			InsertASN(scanID, asn, line)
			InsertServiceProvider(scanID, provider, line)
		}

		// Parse ASN announcements
		if matches := patterns["asn_announces"].FindStringSubmatch(line); len(matches) > 2 {
			asn := matches[1]
			subnet := matches[2]
			log.Printf("[DEBUG] Found ASN %s announcing subnet %s", asn, subnet)
			InsertASN(scanID, asn, line)
			InsertSubnet(scanID, subnet, line)
		}

		// Parse subnet contains IP
		if matches := patterns["subnet_contains"].FindStringSubmatch(line); len(matches) > 2 {
			subnet := matches[1]
			ip := matches[2]
			log.Printf("[DEBUG] Found subnet %s containing IP %s", subnet, ip)
			InsertSubnet(scanID, subnet, line)
			InsertIP(scanID, ip)
		}

		// Parse subdomains
		if matches := patterns["subdomain"].FindAllString(line, -1); len(matches) > 0 {
			log.Printf("[DEBUG] Found potential subdomain matches: %v", matches)
			for _, subdomain := range matches {
				if strings.Contains(subdomain, domain) {
					log.Printf("[DEBUG] Valid subdomain found: %s", subdomain)
					InsertSubdomain(scanID, subdomain)
				} else if IsCloudDomain(subdomain) {
					log.Printf("[DEBUG] Cloud domain found: %s", subdomain)
					InsertCloudDomain(scanID, subdomain)
				}
			}
		}

		// Parse IP addresses
		if matches := patterns["ipv4"].FindStringSubmatch(line); len(matches) > 1 {
			ip := matches[1]
			log.Printf("[DEBUG] Found IPv4 address: %s", ip)
			InsertIP(scanID, ip)
		}

		// Parse DNS records
		for recordType, pattern := range map[string]*regexp.Regexp{
			"A":     patterns["dns_a"],
			"AAAA":  patterns["dns_aaaa"],
			"CNAME": patterns["dns_cname"],
			"MX":    patterns["dns_mx"],
			"TXT":   patterns["dns_txt"],
			"NS":    patterns["dns_ns"],
			"SRV":   patterns["dns_srv"],
			"PTR":   patterns["dns_ptr"],
			"SPF":   patterns["dns_spf"],
			"SOA":   patterns["dns_soa"],
		} {
			if pattern.MatchString(line) {
				log.Printf("[DEBUG] Found DNS record type %s: %s", recordType, line)
				InsertDNSRecord(scanID, line, recordType)
			}
		}
	}
	log.Printf("[INFO] Completed parsing results for scan %s", scanID)
}

func GetAmassScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
              FROM amass_scans WHERE scope_target_id = $1`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch scans for scope target ID %s: %v", scopeTargetID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan AmassScanStatus
		err := rows.Scan(
			&scan.ID,
			&scan.ScanID,
			&scan.Domain,
			&scan.Status,
			&scan.Result,
			&scan.Error,
			&scan.StdOut,
			&scan.StdErr,
			&scan.Command,
			&scan.ExecTime,
			&scan.CreatedAt,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		scans = append(scans, map[string]interface{}{
			"id":             scan.ID,
			"scan_id":        scan.ScanID,
			"domain":         scan.Domain,
			"status":         scan.Status,
			"result":         nullStringToString(scan.Result),
			"error":          nullStringToString(scan.Error),
			"stdout":         nullStringToString(scan.StdOut),
			"stderr":         nullStringToString(scan.StdErr),
			"command":        nullStringToString(scan.Command),
			"execution_time": nullStringToString(scan.ExecTime),
			"created_at":     scan.CreatedAt.Format(time.RFC3339),
		})
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(scans)
}

func GetServiceProviders(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" || scanID == "No scans available" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `SELECT provider, raw_data FROM service_providers WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch service providers", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var providers []ServiceProviderResponse
	for rows.Next() {
		var provider ServiceProviderResponse
		if err := rows.Scan(&provider.Provider, &provider.RawData); err != nil {
			http.Error(w, "Error scanning service provider", http.StatusInternalServerError)
			return
		}
		providers = append(providers, provider)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(providers)
}

func GetCloudDomains(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	var awsDomains, gcpDomains, azureDomains []string

	cloudDomainQuery := `SELECT domain, type FROM cloud_domains WHERE scan_id = $1 ORDER BY domain ASC`
	cloudRows, err := dbPool.Query(context.Background(), cloudDomainQuery, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch cloud domains for scan %s: %v", scanID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer cloudRows.Close()

	for cloudRows.Next() {
		var domain, domainType string
		if err := cloudRows.Scan(&domain, &domainType); err != nil {
			log.Printf("[ERROR] Failed to scan cloud domain row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		switch domainType {
		case "aws":
			awsDomains = append(awsDomains, domain)
		case "gcp":
			gcpDomains = append(gcpDomains, domain)
		case "azure":
			azureDomains = append(azureDomains, domain)
		}
	}

	response := map[string][]string{
		"aws_domains":   awsDomains,
		"gcp_domains":   gcpDomains,
		"azure_domains": azureDomains,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[ERROR] Failed to encode cloud domains: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func GetASNs(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" || scanID == "No scans available" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `SELECT number, raw_data FROM asns WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch ASNs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var asns []ASNResponse
	for rows.Next() {
		var asn ASNResponse
		if err := rows.Scan(&asn.Number, &asn.RawData); err != nil {
			http.Error(w, "Error scanning ASN", http.StatusInternalServerError)
			return
		}
		asns = append(asns, asn)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(asns)
}

func GetSubnets(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" || scanID == "No scans available" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `SELECT cidr, raw_data FROM subnets WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch subnets", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var subnets []SubnetResponse
	for rows.Next() {
		var subnet SubnetResponse
		if err := rows.Scan(&subnet.CIDR, &subnet.RawData); err != nil {
			http.Error(w, "Error scanning subnet", http.StatusInternalServerError)
			return
		}
		subnets = append(subnets, subnet)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(subnets)
}

func GetSubdomains(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	// Explicitly initialize to an empty slice
	subdomains := []string{}

	subdomainQuery := `SELECT subdomain FROM subdomains WHERE scan_id = $1 ORDER BY created_at DESC`
	subRows, err := dbPool.Query(context.Background(), subdomainQuery, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch subdomains for scan %s: %v", scanID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer subRows.Close()

	for subRows.Next() {
		var subdomain string
		if err := subRows.Scan(&subdomain); err != nil {
			log.Printf("[ERROR] Failed to scan subdomain row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		subdomains = append(subdomains, subdomain)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(subdomains); err != nil {
		log.Printf("[ERROR] Failed to encode subdomains: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func GetIPs(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	query := `SELECT ip_address FROM ips WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, "Failed to fetch IPs", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ips []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			http.Error(w, "Error scanning IP", http.StatusInternalServerError)
			return
		}
		ips = append(ips, ip)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(ips)
}

func GetDNSRecords(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]
	if scanID == "" || scanID == "No scans available" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]struct{}{})
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "Invalid scan ID format", http.StatusBadRequest)
		return
	}

	query := `SELECT id, scan_id, record, record_type, created_at FROM dns_records WHERE scan_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch DNS records for scan %s: %v", scanID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var dnsRecords []DNSRecord
	for rows.Next() {
		var dnsRecord DNSRecord
		if err := rows.Scan(&dnsRecord.ID, &dnsRecord.ScanID, &dnsRecord.Record, &dnsRecord.Type, &dnsRecord.CreatedAt); err != nil {
			log.Printf("[ERROR] Failed to scan DNS record row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		dnsRecords = append(dnsRecords, dnsRecord)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[ERROR] Error iterating over rows: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(dnsRecords); err != nil {
		log.Printf("[ERROR] Failed to encode DNS records: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func GetAmassScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scanID"]
	if scanID == "" {
		http.Error(w, "Scan ID is required", http.StatusBadRequest)
		return
	}

	var scan AmassScanStatus
	query := `SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at FROM amass_scans WHERE scan_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID,
		&scan.ScanID,
		&scan.Domain,
		&scan.Status,
		&scan.Result,
		&scan.Error,
		&scan.StdOut,
		&scan.StdErr,
		&scan.Command,
		&scan.ExecTime,
		&scan.CreatedAt,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch scan status: %v", err)
		http.Error(w, "Scan not found.", http.StatusNotFound)
		return
	}

	response := map[string]interface{}{
		"id":             scan.ID,
		"scan_id":        scan.ScanID,
		"domain":         scan.Domain,
		"status":         scan.Status,
		"result":         nullStringToString(scan.Result),
		"error":          nullStringToString(scan.Error),
		"stdout":         nullStringToString(scan.StdOut),
		"stderr":         nullStringToString(scan.StdErr),
		"command":        nullStringToString(scan.Command),
		"execution_time": nullStringToString(scan.ExecTime),
		"created_at":     scan.CreatedAt.Format(time.RFC3339),
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

func RunAmassScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN string `json:"fqdn" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var requestID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&requestID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO amass_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", requestID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseAmassScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseAmassScan(scanID, domain string) {
	log.Printf("[INFO] Starting Amass scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get the rate limit from settings
	rateLimit := GetAmassRateLimit()
	log.Printf("[INFO] Using rate limit of %d for Amass scan", rateLimit)

	cmd := exec.Command(
		"docker", "run", "--rm",
		"caffix/amass",
		"enum", "-active", "-alts", "-brute", "-nocolor",
		"-min-for-recursive", "2", "-timeout", "60",
		"-d", domain,
		"-r", "8.8.8.8", "1.1.1.1", "9.9.9.9", "64.6.64.6",
		"208.67.222.222", "208.67.220.220", "8.26.56.26", "8.20.247.20",
		"185.228.168.9", "185.228.169.9", "76.76.19.19", "76.223.122.150",
		"198.101.242.72", "176.103.130.130", "176.103.130.131",
		"94.140.14.14", "94.140.15.15", "1.0.0.1", "77.88.8.8", "77.88.8.1",
		"-rf", fmt.Sprintf("%d", rateLimit),
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Amass scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] Amass scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result != "" {
		log.Printf("[INFO] Starting to parse results for scan %s", scanID)
		ParseAndStoreResults(scanID, domain, result)
		log.Printf("[INFO] Finished parsing results for scan %s", scanID)
	} else {
		log.Printf("[WARN] No output from Amass scan for domain %s", domain)
	}

	UpdateScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating scan status for %s to %s", scanID, status)
	query := `UPDATE amass_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated scan status for %s", scanID)
	}
}

func InsertServiceProvider(scanID, provider, rawData string) {
	log.Printf("[INFO] Inserting service provider: %s", provider)
	query := `INSERT INTO service_providers (scan_id, provider, raw_data) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, provider, rawData)
	if err != nil {
		log.Printf("[ERROR] Failed to insert service provider: %v", err)
	} else {
		log.Printf("[INFO] Successfully inserted service provider: %s", provider)
	}
}

func InsertASN(scanID, asn, rawData string) {
	query := `INSERT INTO asns (scan_id, number, raw_data) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, asn, rawData)
	if err != nil {
		log.Printf("Failed to insert ASN: %v (ASN: %s)", err, asn)
	} else {
		log.Printf("Successfully inserted ASN: %s", asn)
	}
}

func InsertSubnet(scanID, cidr, rawData string) {
	query := `INSERT INTO subnets (scan_id, cidr, raw_data) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, cidr, rawData)
	if err != nil {
		log.Printf("Failed to insert Subnet: %v (Subnet: %s)", err, cidr)
	} else {
		log.Printf("Successfully inserted Subnet: %s", cidr)
	}
}

func InsertIP(scanID, ip string) {
	log.Printf("[DEBUG] Inserting IP address for scan %s: %s", scanID, ip)
	query := `INSERT INTO ips (scan_id, ip_address) VALUES ($1, $2)`
	_, err := dbPool.Exec(context.Background(), query, scanID, ip)
	if err != nil {
		log.Printf("[ERROR] Failed to insert IP address %s: %v", ip, err)
	} else {
		log.Printf("[DEBUG] Successfully inserted IP address %s for scan %s", ip, scanID)
	}
}

func InsertDNSRecord(scanID, record, recordType string) {
	log.Printf("[DEBUG] Inserting DNS record type %s for scan %s: %s", recordType, scanID, record)
	query := `INSERT INTO dns_records (scan_id, record, record_type) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, record, recordType)
	if err != nil {
		log.Printf("[ERROR] Failed to insert DNS record: %v", err)
	} else {
		log.Printf("[DEBUG] Successfully inserted DNS record type %s for scan %s", recordType, scanID)
	}
}

func InsertSubdomain(scanID, subdomain string) {
	log.Printf("[DEBUG] Checking if subdomain %s for scanID %s is already stored in the database", subdomain, scanID)

	checkQuery := `SELECT COUNT(*) FROM subdomains WHERE scan_id = $1 AND subdomain = $2`
	var count int
	err := dbPool.QueryRow(context.Background(), checkQuery, scanID, subdomain).Scan(&count)
	if err != nil {
		log.Printf("[ERROR] Failed to check existence of subdomain %s for scanID %s: %v", subdomain, scanID, err)
		return
	}

	if count > 0 {
		log.Printf("[DEBUG] Subdomain %s for scanID %s already exists. Skipping insertion.", subdomain, scanID)
		return
	}
	log.Printf("[DEBUG] Attempting to insert subdomain %s for scanID: %s", subdomain, scanID)
	insertQuery := `INSERT INTO subdomains (scan_id, subdomain) VALUES ($1, $2)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, subdomain)
	if err != nil {
		log.Printf("[ERROR] Failed to insert subdomain %s for scan %s: %v", subdomain, scanID, err)
		return
	}

	log.Printf("[DEBUG] Successfully inserted subdomain %s for scanID: %s", subdomain, scanID)
}

func InsertCloudDomain(scanID, domain string) {
	var cloudType string

	awsDomains := []string{
		"amazonaws.com", "awsdns", "cloudfront.net",
	}

	googleDomains := []string{
		"google.com", "gcloud.com", "appspot.com",
		"googleapis.com", "gcp.com", "withgoogle.com",
	}

	azureDomains := []string{
		"azure.com", "cloudapp.azure.com", "windows.net",
		"microsoft.com", "trafficmanager.net", "azureedge.net", "azure.net",
		"api.applicationinsights.io", "signalr.net", "microsoftonline.com",
		"azurewebsites.net", "azure-api.net", "redis.cache.windows.net",
		"media.azure.net", "appserviceenvironment.net",
	}

	matchFound := false

	for _, awsDomain := range awsDomains {
		if strings.Contains(domain, awsDomain) {
			cloudType = "aws"
			matchFound = true
			break
		}
	}
	if !matchFound {
		for _, googleDomain := range googleDomains {
			if strings.Contains(domain, googleDomain) {
				cloudType = "gcp"
				matchFound = true
				break
			}
		}
	}
	if !matchFound {
		for _, azureDomain := range azureDomains {
			if strings.Contains(domain, azureDomain) {
				cloudType = "azure"
				matchFound = true
				break
			}
		}
	}

	if !matchFound {
		log.Printf("[DEBUG] Domain %s does not match any known cloud provider", domain)
		cloudType = "Unknown"
	}

	query := `INSERT INTO cloud_domains (scan_id, domain, type) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), query, scanID, domain, cloudType)
	if err != nil {
		log.Printf("[ERROR] Failed to insert cloud domain %s: %v", domain, err)
		return
	}

	log.Printf("[DEBUG] Successfully inserted cloud domain %s with type %s", domain, cloudType)
}

func IsCloudDomain(domain string) bool {
	awsDomains := []string{
		"amazonaws.com", "awsdns", "cloudfront.net",
	}

	googleDomains := []string{
		"google.com", "gcloud.com", "appspot.com",
		"googleapis.com", "gcp.com", "withgoogle.com",
	}

	azureDomains := []string{
		"azure.com", "cloudapp.azure.com", "windows.net",
		"microsoft.com", "trafficmanager.net", "azureedge.net", "azure.net",
		"api.applicationinsights.io", "signalr.net", "microsoftonline.com",
		"azurewebsites.net", "azure-api.net", "redis.cache.windows.net",
		"media.azure.net", "appserviceenvironment.net",
	}

	for _, awsDomain := range awsDomains {
		if strings.Contains(domain, awsDomain) {
			return true
		}
	}
	for _, googleDomain := range googleDomains {
		if strings.Contains(domain, googleDomain) {
			return true
		}
	}
	for _, azureDomain := range azureDomains {
		if strings.Contains(domain, azureDomain) {
			return true
		}
	}

	return false
}
