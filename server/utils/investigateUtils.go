package utils

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type InvestigateStatus struct {
	ID            string    `json:"id"`
	ScanID        string    `json:"scan_id"`
	ScopeTargetID string    `json:"scope_target_id"`
	Status        string    `json:"status"`
	Result        *string   `json:"result"`
	Error         *string   `json:"error"`
	StdOut        *string   `json:"stdout"`
	StdErr        *string   `json:"stderr"`
	Command       *string   `json:"command"`
	ExecTime      *string   `json:"execution_time"`
	CreatedAt     time.Time `json:"created_at"`
}

type InvestigateResult struct {
	Domain       string          `json:"domain"`
	IPAddress    string          `json:"ip_address"`
	SSL          *SSLInfo        `json:"ssl"`
	ASN          *InvestigateASN `json:"asn"`
	HTTP         *HTTPInfo       `json:"http"`
	CompanyMatch bool            `json:"company_match"`
}

type SSLInfo struct {
	Domain       string    `json:"domain"`
	Issuer       string    `json:"issuer"`
	Expiration   time.Time `json:"expiration"`
	IsExpired    bool      `json:"is_expired"`
	IsSelfSigned bool      `json:"is_self_signed"`
	IsMismatched bool      `json:"is_mismatched"`
}

type InvestigateASN struct {
	Provider string `json:"provider"`
	ASN      string `json:"asn"`
}

type HTTPInfo struct {
	StatusCode int    `json:"status_code"`
	Title      string `json:"title"`
	Server     string `json:"server"`
}

func RunInvestigateScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID string `json:"scope_target_id" binding:"required"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.ScopeTargetID == "" {
		http.Error(w, "Invalid request body. `scope_target_id` is required.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO investigate_scans (scan_id, scope_target_id, status) VALUES ($1, $2, $3)`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, payload.ScopeTargetID, "pending")
	if err != nil {
		log.Printf("[ERROR] Failed to create investigate scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteInvestigateScan(scanID, payload.ScopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteInvestigateScan(scanID, scopeTargetID string) {
	log.Printf("[INFO] Starting investigate scan for scope target %s (scan ID: %s)", scopeTargetID, scanID)
	startTime := time.Now()

	// Get consolidated company domains for this scope target
	var domains []string
	rows, err := dbPool.Query(context.Background(), `
		SELECT domain FROM consolidated_company_domains 
		WHERE scope_target_id = $1 
		ORDER BY domain`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get consolidated domains: %v", err)
		UpdateInvestigateScanStatus(scanID, "error", "", fmt.Sprintf("Failed to get domains: %v", err), "", time.Since(startTime).String())
		return
	}
	defer rows.Close()

	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			log.Printf("[ERROR] Failed to scan domain: %v", err)
			continue
		}
		domains = append(domains, domain)
	}

	if len(domains) == 0 {
		log.Printf("[INFO] No consolidated domains found for scope target %s", scopeTargetID)
		UpdateInvestigateScanStatus(scanID, "success", "[]", "", "", time.Since(startTime).String())
		return
	}

	// Get company name from scope target
	var companyName string
	err = dbPool.QueryRow(context.Background(), `
		SELECT scope_target FROM scope_targets 
		WHERE id = $1`, scopeTargetID).Scan(&companyName)
	if err != nil {
		log.Printf("[ERROR] Failed to get company name: %v", err)
		companyName = ""
	}

	var results []InvestigateResult
	for _, domain := range domains {
		log.Printf("[INFO] Investigating domain: %s", domain)
		result := InvestigateResult{Domain: domain}

		// Get IP address
		if ips, err := net.LookupIP(domain); err == nil && len(ips) > 0 {
			result.IPAddress = ips[0].String()
		} else {
			log.Printf("[WARN] Failed to resolve IP for %s: %v", domain, err)
			result.IPAddress = "N/A"
		}

		// Get SSL info
		if sslInfo := getSSLInfo(domain); sslInfo != nil {
			result.SSL = sslInfo
		}

		// Get ASN info
		if asnInfo := getASNInfo(domain); asnInfo != nil {
			result.ASN = asnInfo
		}

		// Get HTTP info and check for company match
		if httpInfo, companyMatch := getHTTPInfo(domain, companyName); httpInfo != nil {
			result.HTTP = httpInfo
			result.CompanyMatch = companyMatch
		}

		results = append(results, result)
	}

	// Convert results to JSON
	resultJSON, err := json.Marshal(results)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal results: %v", err)
		UpdateInvestigateScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal results: %v", err), "", time.Since(startTime).String())
		return
	}

	UpdateInvestigateScanStatus(scanID, "success", string(resultJSON), "", "", time.Since(startTime).String())
	log.Printf("[INFO] Investigate scan completed for scope target %s", scopeTargetID)
}

func getSSLInfo(domain string) *SSLInfo {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", domain+":443", &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("[WARN] Failed to connect to %s for SSL info: %v", domain, err)
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil
	}

	cert := certs[0]
	sslInfo := &SSLInfo{
		Domain:       domain,
		Issuer:       cert.Issuer.String(),
		Expiration:   cert.NotAfter,
		IsExpired:    time.Now().After(cert.NotAfter),
		IsSelfSigned: cert.Issuer.String() == cert.Subject.String(),
	}

	// Check for domain mismatch
	sslInfo.IsMismatched = true
	for _, name := range cert.DNSNames {
		if name == domain || (strings.HasPrefix(name, "*.") && strings.HasSuffix(domain, name[1:])) {
			sslInfo.IsMismatched = false
			break
		}
	}

	return sslInfo
}

func getASNInfo(domain string) *InvestigateASN {
	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		log.Printf("[WARN] Failed to resolve IP for %s: %v", domain, err)
		return nil
	}

	ip := ips[0].String()

	// Try multiple APIs for better reliability
	client := &http.Client{Timeout: 10 * time.Second}

	// Try ipapi.co first
	resp, err := client.Get(fmt.Sprintf("https://ipapi.co/%s/json/", ip))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var result struct {
			ASN string `json:"asn"`
			Org string `json:"org"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Org != "" {
			return &InvestigateASN{
				ASN:      result.ASN,
				Provider: result.Org,
			}
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	// Fallback to ip-api.com
	resp, err = client.Get(fmt.Sprintf("http://ip-api.com/json/%s?fields=as,org", ip))
	if err == nil && resp.StatusCode == 200 {
		defer resp.Body.Close()
		var result struct {
			AS  string `json:"as"`
			Org string `json:"org"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&result); err == nil && result.Org != "" {
			return &InvestigateASN{
				ASN:      result.AS,
				Provider: result.Org,
			}
		}
	}
	if resp != nil {
		resp.Body.Close()
	}

	log.Printf("[WARN] Failed to get ASN info for %s", ip)
	return nil
}

func getHTTPInfo(domain, companyName string) (*HTTPInfo, bool) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	url := "https://" + domain
	resp, err := client.Get(url)
	if err != nil {
		// Try HTTP if HTTPS fails
		url = "http://" + domain
		resp, err = client.Get(url)
		if err != nil {
			log.Printf("[WARN] Failed to get HTTP info for %s: %v", domain, err)
			return nil, false
		}
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[WARN] Failed to read response body for %s: %v", domain, err)
		return &HTTPInfo{StatusCode: resp.StatusCode, Server: resp.Header.Get("Server")}, false
	}

	bodyStr := string(body)

	// Extract title
	title := ""
	if start := strings.Index(bodyStr, "<title>"); start != -1 {
		start += 7
		if end := strings.Index(bodyStr[start:], "</title>"); end != -1 {
			title = strings.TrimSpace(bodyStr[start : start+end])
		}
	}

	// Check for company name match
	companyMatch := false
	if companyName != "" {
		companyLower := strings.ToLower(companyName)
		bodyLower := strings.ToLower(bodyStr)
		companyMatch = strings.Contains(bodyLower, companyLower)
	}

	return &HTTPInfo{
		StatusCode: resp.StatusCode,
		Title:      title,
		Server:     resp.Header.Get("Server"),
	}, companyMatch
}

func UpdateInvestigateScanStatus(scanID, status, result, stderr, command, execTime string) {
	query := `UPDATE investigate_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update investigate scan status: %v", err)
	}
}

func GetInvestigateScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `SELECT * FROM investigate_scans WHERE scan_id = $1`
	var scan InvestigateStatus
	var result, error, stdout, stderr, command, execTime sql.NullString

	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ID, &scan.ScanID, &scan.ScopeTargetID, &scan.Status, &result, &error,
		&stdout, &stderr, &command, &execTime, &scan.CreatedAt,
	)
	if err != nil {
		log.Printf("[ERROR] Failed to get investigate scan status: %v", err)
		http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetInvestigateScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	// Validate scope target ID
	if scopeTargetID == "" {
		log.Printf("[ERROR] Empty scope target ID provided")
		http.Error(w, "Invalid scope target ID", http.StatusBadRequest)
		return
	}

	// Validate UUID format
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		log.Printf("[ERROR] Invalid UUID format: %s, error: %v", scopeTargetID, err)
		http.Error(w, "Invalid UUID format", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM investigate_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get investigate scans for target %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []InvestigateStatus
	for rows.Next() {
		var scan InvestigateStatus
		var result, error, stdout, stderr, command, execTime sql.NullString

		err := rows.Scan(
			&scan.ID, &scan.ScanID, &scan.ScopeTargetID, &scan.Status, &result, &error,
			&stdout, &stderr, &command, &execTime, &scan.CreatedAt,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan investigate row: %v", err)
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

		scans = append(scans, scan)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
