package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"net/url"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type Sublist3rScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
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

type AssetfinderScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
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

type CTLScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
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

type GauScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
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

type SubfinderScanStatus struct {
	ID                string         `json:"id"`
	ScanID            string         `json:"scan_id"`
	Domain            string         `json:"domain"`
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

func RunSublist3rScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Received request to run Sublist3r scan")
	var requestData struct {
		FQDN              string  `json:"fqdn"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		log.Printf("[ERROR] Failed to decode request body: %v", err)
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	domain := requestData.FQDN
	wildcardDomain := "*." + domain
	log.Printf("[INFO] Processing Sublist3r scan request for domain: %s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s: %v", domain, err)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[INFO] Found matching scope target ID: %s", scopeTargetID)

	scanID := uuid.New().String()
	log.Printf("[INFO] Generated new scan ID: %s", scanID)

	var insertQuery string
	var args []interface{}
	if requestData.AutoScanSessionID != nil && *requestData.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO sublist3r_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *requestData.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO sublist3r_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create Sublist3r scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully created Sublist3r scan record in database")

	go ExecuteAndParseSublist3rScan(scanID, domain)

	log.Printf("[INFO] Initiated Sublist3r scan with ID: %s for domain: %s", scanID, domain)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// ExecuteAndParseSublist3rScan — the original Sublist3r tool is obsolete (its search-engine
// scrapers are all blocked, DNSdumpster/Virustotal are broken), so this scan no longer shells out
// to sublist3r.py. It has been repurposed into a native "Passive OSINT" aggregator that unions
// subdomains from working, key-free passive sources (RapidDNS, URLScan.io, OTX AlienVault passive
// DNS, HackerTarget hostsearch). Certificate Transparency is deliberately NOT queried here because
// the CTL scan already covers crt.sh + certspotter. Each source is best-effort: one failing (e.g. a
// rate-limit) doesn't fail the scan as long as another returns data.
func ExecuteAndParseSublist3rScan(scanID, domain string) {
	log.Printf("[PASSIVE-OSINT] Starting passive subdomain enumeration for %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	sources := []struct {
		name  string
		fetch func(string) ([]string, error)
	}{
		{"rapiddns", fetchSubdomainsFromRapidDNS},
		{"urlscan", fetchSubdomainsFromURLScan},
		{"otx", fetchSubdomainsFromOTX},
		{"hackertarget", fetchSubdomainsFromHackerTarget},
	}

	unique := make(map[string]bool)
	var usedSources []string
	var errs []string
	for _, s := range sources {
		subs, err := s.fetch(domain)
		if err != nil {
			log.Printf("[PASSIVE-OSINT] source %s failed for %s: %v", s.name, domain, err)
			errs = append(errs, fmt.Sprintf("%s: %v", s.name, err))
			continue
		}
		for _, sub := range subs {
			unique[sub] = true
		}
		usedSources = append(usedSources, fmt.Sprintf("%s(%d)", s.name, len(subs)))
	}

	command := "passive sources: rapiddns, urlscan, otx, hackertarget"
	if len(unique) == 0 {
		msg := "No subdomains found from any passive source."
		if len(errs) > 0 {
			msg += " (" + strings.Join(errs, "; ") + ")"
		}
		log.Printf("[PASSIVE-OSINT] %s", msg)
		UpdateSublist3rScanStatus(scanID, "error", "", msg, command, time.Since(startTime).String())
		return
	}

	out := make([]string, 0, len(unique))
	for s := range unique {
		out = append(out, s)
	}
	sort.Strings(out)
	result := strings.Join(out, "\n")

	log.Printf("[PASSIVE-OSINT] Found %d unique subdomains for %s via %s", len(out), domain, strings.Join(usedSources, ", "))
	UpdateSublist3rScanStatus(scanID, "success", result, strings.Join(errs, "; "), command+" -> "+strings.Join(usedSources, ", "), time.Since(startTime).String())
}

// rapidDNSSubRegex matches host labels; the domain suffix is appended (quoted) per call.
// fetchSubdomainsFromRapidDNS scrapes RapidDNS's free subdomain page (no API key). The response is
// an HTML table of "<subdomain></td><td><ip>"; we regex out every hostname ending in the target
// domain and let filterCTSubdomains validate/dedupe.
func fetchSubdomainsFromRapidDNS(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://rapiddns.io/subdomain/%s?full=1", url.QueryEscape(domain))
	log.Printf("[PASSIVE-OSINT] [DEBUG] Requesting RapidDNS: %s", requestURL)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rapiddns returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	re := regexp.MustCompile(`([A-Za-z0-9_-]+\.)+` + regexp.QuoteMeta(domain))
	names := re.FindAllString(string(bodyBytes), -1)
	filtered := filterCTSubdomains(names, domain)
	if len(filtered) == 0 {
		return nil, fmt.Errorf("rapiddns: no subdomains parsed from response")
	}
	return filtered, nil
}

// fetchSubdomainsFromURLScan queries urlscan.io's free search API (no API key for search) and pulls
// hostnames out of the indexed page/task domains for the target.
func fetchSubdomainsFromURLScan(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://urlscan.io/api/v1/search/?q=domain:%s&size=100", url.QueryEscape(domain))
	log.Printf("[PASSIVE-OSINT] [DEBUG] Requesting URLScan: %s", requestURL)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ars0n-framework-v2")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("urlscan returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to decode urlscan response: %v", err)
	}

	var names []string
	for _, r := range data.Results {
		if r.Page.Domain != "" {
			names = append(names, r.Page.Domain)
		}
		if r.Task.Domain != "" {
			names = append(names, r.Task.Domain)
		}
	}
	return filterCTSubdomains(names, domain), nil
}

// fetchSubdomainsFromHackerTarget queries HackerTarget's free hostsearch API (subdomain,ip lines).
func fetchSubdomainsFromHackerTarget(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", url.QueryEscape(domain))
	log.Printf("[PASSIVE-OSINT] [DEBUG] Requesting HackerTarget: %s", requestURL)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ars0n-framework-v2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("hackertarget returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	body := string(bodyBytes)
	// HackerTarget returns plain text: "subdomain,ip" per line, or an error/rate-limit message.
	if strings.Contains(body, "API count exceeded") || strings.Contains(body, "error check your search") {
		return nil, fmt.Errorf("hackertarget: %s", strings.TrimSpace(body))
	}

	var names []string
	for _, line := range strings.Split(body, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ",", 2)
		if len(parts) >= 1 && parts[0] != "" {
			names = append(names, parts[0])
		}
	}
	return filterCTSubdomains(names, domain), nil
}

// fetchSubdomainsFromOTX queries AlienVault OTX passive DNS (free, but aggressively rate-limited).
func fetchSubdomainsFromOTX(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/domain/%s/passive_dns", url.QueryEscape(domain))
	log.Printf("[PASSIVE-OSINT] [DEBUG] Requesting OTX: %s", requestURL)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ars0n-framework-v2")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("otx returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var data struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		return nil, fmt.Errorf("failed to decode otx response: %v", err)
	}

	var names []string
	for _, r := range data.PassiveDNS {
		names = append(names, r.Hostname)
	}
	return filterCTSubdomains(names, domain), nil
}

func UpdateSublist3rScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Sublist3r scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE sublist3r_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Sublist3r scan status: %v", err)
		return
	}
	log.Printf("[INFO] Successfully updated Sublist3r scan status for scan ID %s", scanID)
}

func GetSublist3rScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan Sublist3rScanStatus
	query := `SELECT * FROM sublist3r_scans WHERE scan_id = $1`
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
		&scan.ScopeTargetID,
		&scan.AutoScanSessionID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"domain":               scan.Domain,
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
	json.NewEncoder(w).Encode(response)
}

func GetSublist3rScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM sublist3r_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan Sublist3rScanStatus
		var scopeTargetID string
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
			&scopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"domain":               scan.Domain,
			"status":               scan.Status,
			"result":               nullStringToString(scan.Result),
			"error":                nullStringToString(scan.Error),
			"stdout":               nullStringToString(scan.StdOut),
			"stderr":               nullStringToString(scan.StdErr),
			"command":              nullStringToString(scan.Command),
			"execution_time":       nullStringToString(scan.ExecTime),
			"created_at":           scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id":      scopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunAssetfinderScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN              string  `json:"fqdn" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO assetfinder_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO assetfinder_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseAssetfinderScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseAssetfinderScan(scanID, domain string) {
	log.Printf("[INFO] Starting Assetfinder scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-assetfinder-1",
		"assetfinder",
		"--subs-only",
		domain,
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Assetfinder scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateAssetfinderScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] Assetfinder scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from Assetfinder scan")
		UpdateAssetfinderScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] Assetfinder output: %s", result)
		UpdateAssetfinderScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateAssetfinderScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Assetfinder scan status for %s to %s", scanID, status)
	query := `UPDATE assetfinder_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Assetfinder scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Assetfinder scan status for %s", scanID)
	}
}

func GetAssetfinderScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan AssetfinderScanStatus
	query := `SELECT * FROM assetfinder_scans WHERE scan_id = $1`
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
		&scan.ScopeTargetID,
		&scan.AutoScanSessionID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"domain":               scan.Domain,
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
	json.NewEncoder(w).Encode(response)
}

func GetAssetfinderScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM assetfinder_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan AssetfinderScanStatus
		var scopeTargetID string
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
			&scopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"domain":               scan.Domain,
			"status":               scan.Status,
			"result":               nullStringToString(scan.Result),
			"error":                nullStringToString(scan.Error),
			"stdout":               nullStringToString(scan.StdOut),
			"stderr":               nullStringToString(scan.StdErr),
			"command":              nullStringToString(scan.Command),
			"execution_time":       nullStringToString(scan.ExecTime),
			"created_at":           scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id":      scopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunGauScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN              string  `json:"fqdn" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	// Get the scope target ID
	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO gau_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO gau_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseGauScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseGauScan(scanID, domain string) {
	log.Printf("[INFO] Starting GAU scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get rate limit and custom HTTP settings
	rateLimit := GetGauRateLimit()
	_, _ = GetCustomHTTPSettings() // GAU doesn't support custom headers or user agent
	log.Printf("[INFO] Using rate limit of %d for GAU scan", rateLimit)
	log.Printf("[DEBUG] Note: GAU does not support custom headers or user agent")

	// Build base command
	dockerCmd := []string{
		"docker", "run", "--rm",
		"sxcurity/gau:latest",
		domain,
		"--providers", "wayback",
		"--json",
		"--verbose",
		"--subs",
		"--threads", "10",
		"--timeout", "60",
		"--retries", "2",
	}

	// Note: GAU does not support custom headers or user agent
	cmd := exec.Command(dockerCmd[0], dockerCmd[1:]...)

	log.Printf("[INFO] Executing command: %s", strings.Join(dockerCmd, " "))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] GAU scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateGauScanStatus(scanID, "error", "", stderr.String(), strings.Join(dockerCmd, " "), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] GAU scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))
	if stderr.Len() > 0 {
		log.Printf("[DEBUG] stderr output: %s", stderr.String())
	}

	// Check if we have actual results
	if result == "" {
		// Try a second attempt with different flags
		dockerCmd = []string{
			"docker", "run", "--rm",
			"sxcurity/gau:latest",
			domain,
			"--providers", "wayback,otx,urlscan",
			"--subs",
			"--threads", "5",
			"--timeout", "30",
			"--retries", "3",
		}

		log.Printf("[INFO] No results from first attempt, trying second attempt with command: %s", strings.Join(dockerCmd, " "))

		stdout.Reset()
		stderr.Reset()
		cmd = exec.Command(dockerCmd[0], dockerCmd[1:]...)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err = cmd.Run()

		if err == nil {
			result = stdout.String()
		}
	}

	// Process results to limit the number of URLs if necessary
	if result != "" {
		lines := strings.Split(strings.TrimSpace(result), "\n")
		lineCount := len(lines)
		log.Printf("[INFO] GAU scan found %d URLs for domain %s", lineCount, domain)

		// Check if results exceed 1000 URLs
		if lineCount > 1000 {
			log.Printf("[INFO] Results exceed 1000 URLs, setting status to 'processing' while reducing to unique subdomains")

			// Update status to "processing" to let the frontend know we're still working
			UpdateGauScanStatus(scanID, "processing", "", "Processing large result set...", strings.Join(dockerCmd, " "), execTime)

			// Map to store unique subdomains and their representative URL
			uniqueSubdomains := make(map[string]string)

			// Process each URL to extract subdomains
			for _, line := range lines {
				if line == "" {
					continue
				}

				// Extract URL - handle both raw URLs and JSON format
				var urlStr string

				// First try to parse as JSON
				var gauResult struct {
					URL string `json:"url"`
				}

				if err := json.Unmarshal([]byte(line), &gauResult); err == nil && gauResult.URL != "" {
					// Successfully parsed as JSON
					urlStr = gauResult.URL
				} else if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
					// Line appears to be a raw URL
					urlStr = line
				} else {
					log.Printf("[ERROR] Failed to parse GAU result, not valid JSON or URL: %s", line)
					continue
				}

				// Extract subdomain from URL
				parsedURL, err := url.Parse(urlStr)
				if err != nil {
					log.Printf("[ERROR] Failed to parse URL %s: %v", urlStr, err)
					continue
				}

				hostname := parsedURL.Hostname()
				if hostname == "" {
					continue
				}

				// Store the first URL for each unique subdomain
				if _, exists := uniqueSubdomains[hostname]; !exists {
					// If it was raw URL, create proper JSON for storage
					if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
						jsonData, _ := json.Marshal(map[string]string{"url": line})
						uniqueSubdomains[hostname] = string(jsonData)
					} else {
						uniqueSubdomains[hostname] = line
					}
				}
			}

			// Build a new result string with only unique subdomain URLs
			var uniqueResults []string
			for _, jsonLine := range uniqueSubdomains {
				uniqueResults = append(uniqueResults, jsonLine)
			}

			// Replace the original result with the reduced set
			result = strings.Join(uniqueResults, "\n")
			log.Printf("[INFO] Reduced %d URLs to %d unique subdomain URLs", lineCount, len(uniqueResults))

			// Now update with the final result and set status to success
			UpdateGauScanStatus(scanID, "success", result, stderr.String(), strings.Join(dockerCmd, " "), execTime)
		} else {
			// If results don't exceed 1000, just update with success directly
			UpdateGauScanStatus(scanID, "success", result, stderr.String(), strings.Join(dockerCmd, " "), execTime)
		}
	} else {
		// Empty result, update with success status
		UpdateGauScanStatus(scanID, "success", result, stderr.String(), strings.Join(dockerCmd, " "), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateGauScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating GAU scan status for %s to %s", scanID, status)
	query := `UPDATE gau_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update GAU scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated GAU scan status for %s", scanID)
	}
}

func GetGauScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scanID"]

	var scan GauScanStatus
	query := `SELECT * FROM gau_scans WHERE scan_id = $1`
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
		&scan.ScopeTargetID,
		&scan.AutoScanSessionID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"domain":               scan.Domain,
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
	json.NewEncoder(w).Encode(response)
}

func GetGauScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM gau_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan GauScanStatus
		var scopeTargetID string
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
			&scopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"domain":               scan.Domain,
			"status":               scan.Status,
			"result":               nullStringToString(scan.Result),
			"error":                nullStringToString(scan.Error),
			"stdout":               nullStringToString(scan.StdOut),
			"stderr":               nullStringToString(scan.StdErr),
			"command":              nullStringToString(scan.Command),
			"execution_time":       nullStringToString(scan.ExecTime),
			"created_at":           scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id":      scopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunCTLScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[INFO] Starting CTL scan request handling")
	var payload struct {
		FQDN              string  `json:"fqdn" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		log.Printf("[ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	log.Printf("[INFO] Processing CTL scan for domain: %s", domain)
	wildcardDomain := fmt.Sprintf("*.%s", domain)
	log.Printf("[DEBUG] Constructed wildcard domain: %s", wildcardDomain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s: %v", domain, err)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[INFO] Found scope target ID: %s for domain: %s", scopeTargetID, domain)

	scanID := uuid.New().String()
	log.Printf("[INFO] Generated new scan ID: %s", scanID)
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO ctl_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO ctl_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[INFO] Successfully created CTL scan record in database")

	go ExecuteAndParseCTLScan(scanID, domain)

	log.Printf("[INFO] CTL scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseCTLScan(scanID, domain string) {
	log.Printf("[INFO] Starting CTL scan execution for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	subdomains, source, err := fetchCTLSubdomains(domain)
	if err != nil {
		log.Printf("[CTL] [ERROR] All CT sources failed for %s: %v", domain, err)
		UpdateCTLScanStatus(scanID, "error", "", err.Error(), "", time.Since(startTime).String())
		return
	}

	result := strings.Join(subdomains, "\n")
	log.Printf("[CTL] [INFO] Found %d subdomains for %s via %s", len(subdomains), domain, source)
	UpdateCTLScanStatus(scanID, "success", result, "", source, time.Since(startTime).String())
	log.Printf("[INFO] CTL scan completed and results stored successfully for domain %s", domain)
}

// fetchCTLSubdomains queries Certificate Transparency logs for subdomains of domain. It prefers
// crt.sh (the most complete aggregator) but falls back to certspotter when crt.sh is unavailable —
// crt.sh is chronically overloaded and frequently returns 502/timeouts.
func fetchCTLSubdomains(domain string) (subdomains []string, source string, err error) {
	subs, crtErr := fetchCTLFromCrtSh(domain)
	if crtErr == nil {
		return subs, fmt.Sprintf("GET https://crt.sh/?q=%%.%s&output=json", domain), nil
	}
	log.Printf("[CTL] [WARN] crt.sh failed for %s (%v) — falling back to certspotter", domain, crtErr)

	subs, csErr := fetchCTLFromCertspotter(domain)
	if csErr == nil {
		return subs, fmt.Sprintf("GET https://api.certspotter.com/v1/issuances?domain=%s (crt.sh fallback)", domain), nil
	}
	return nil, "", fmt.Errorf("both Certificate Transparency sources failed. crt.sh: %v. certspotter fallback: %v", crtErr, csErr)
}

// filterCTSubdomains lowercases, strips wildcard prefixes, and keeps only names that are the domain
// itself or a subdomain of it, returning a sorted, deduplicated slice.
func filterCTSubdomains(names []string, domain string) []string {
	unique := make(map[string]bool)
	for _, name := range names {
		sub := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "*."))
		if sub != "" && (sub == domain || strings.HasSuffix(sub, "."+domain)) {
			unique[sub] = true
		}
	}
	out := make([]string, 0, len(unique))
	for s := range unique {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func fetchCTLFromCrtSh(domain string) ([]string, error) {
	// crt.sh blocks/deprioritizes Go's default User-Agent, so present as a browser. Cap at 45s so
	// we don't wait forever before falling back — crt.sh is frequently overloaded.
	requestURL := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", domain)
	log.Printf("[CTL] [DEBUG] Requesting crt.sh URL: %s", requestURL)
	client := &http.Client{Timeout: 45 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Connection", "keep-alive")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if bs := string(bodyBytes); strings.Contains(bs, "Sorry, something went wrong") ||
		strings.Contains(bs, "searches that would produce many results may never succeed") {
		return nil, fmt.Errorf("crt.sh returned an error page (too many results or overloaded)")
	}

	var results []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(bodyBytes, &results); err != nil {
		return nil, fmt.Errorf("failed to decode crt.sh response: %v", err)
	}

	// crt.sh packs multiple SAN entries into name_value separated by newlines.
	var names []string
	for _, r := range results {
		names = append(names, strings.Split(r.NameValue, "\n")...)
	}
	return filterCTSubdomains(names, domain), nil
}

func fetchCTLFromCertspotter(domain string) ([]string, error) {
	requestURL := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", domain)
	log.Printf("[CTL] [DEBUG] Requesting certspotter URL: %s", requestURL)
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ars0n-framework-v2")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("certspotter returned status %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var results []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(bodyBytes, &results); err != nil {
		return nil, fmt.Errorf("failed to decode certspotter response: %v", err)
	}

	var names []string
	for _, r := range results {
		names = append(names, r.DNSNames...)
	}
	return filterCTSubdomains(names, domain), nil
}

func UpdateCTLScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating CTL scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE ctl_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update CTL scan status for scan ID %s: %v", scanID, err)
		log.Printf("[ERROR] Update attempted with: status=%s, result_length=%d, stderr_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[INFO] Successfully updated CTL scan status to %s for scan ID %s", status, scanID)
	}
}

func GetCTLScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[INFO] Retrieving CTL scan status for scan ID: %s", scanID)

	var scan CTLScanStatus
	query := `SELECT * FROM ctl_scans WHERE scan_id = $1`
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
		&scan.ScopeTargetID,
		&scan.AutoScanSessionID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Printf("[ERROR] CTL scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get CTL scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[INFO] Successfully retrieved CTL scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
	}

	response := map[string]interface{}{
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"domain":               scan.Domain,
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
		log.Printf("[ERROR] Failed to encode CTL scan response: %v", err)
	} else {
		log.Printf("[INFO] Successfully sent CTL scan status response")
	}
}

func GetCTLScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM ctl_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan CTLScanStatus
		var scopeTargetID string
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
			&scopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"domain":               scan.Domain,
			"status":               scan.Status,
			"result":               nullStringToString(scan.Result),
			"error":                nullStringToString(scan.Error),
			"stdout":               nullStringToString(scan.StdOut),
			"stderr":               nullStringToString(scan.StdErr),
			"command":              nullStringToString(scan.Command),
			"execution_time":       nullStringToString(scan.ExecTime),
			"created_at":           scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id":      scopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunSubfinderScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		FQDN              string  `json:"fqdn" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.FQDN == "" {
		http.Error(w, "Invalid request body. `fqdn` is required.", http.StatusBadRequest)
		return
	}

	domain := payload.FQDN
	wildcardDomain := fmt.Sprintf("*.%s", domain)

	query := `SELECT id FROM scope_targets WHERE type = 'Wildcard' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO subfinder_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO subfinder_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseSubfinderScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseSubfinderScan(scanID, domain string) {
	log.Printf("[INFO] Starting Subfinder scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	cmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subfinder-1",
		"subfinder",
		"-d", domain,
		"-silent",
	)

	log.Printf("[INFO] Executing command: %s", cmd.String())

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	execTime := time.Since(startTime).String()

	if err != nil {
		log.Printf("[ERROR] Subfinder scan failed for %s: %v", domain, err)
		log.Printf("[ERROR] stderr output: %s", stderr.String())
		UpdateSubfinderScanStatus(scanID, "error", "", stderr.String(), cmd.String(), execTime)
		return
	}

	result := stdout.String()
	log.Printf("[INFO] Subfinder scan completed in %s for domain %s", execTime, domain)
	log.Printf("[DEBUG] Raw output length: %d bytes", len(result))

	if result == "" {
		log.Printf("[WARN] No output from Subfinder scan")
		UpdateSubfinderScanStatus(scanID, "completed", "", "No results found", cmd.String(), execTime)
	} else {
		log.Printf("[DEBUG] Subfinder output: %s", result)
		UpdateSubfinderScanStatus(scanID, "success", result, stderr.String(), cmd.String(), execTime)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func UpdateSubfinderScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[INFO] Updating Subfinder scan status for %s to %s", scanID, status)
	query := `UPDATE subfinder_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5 WHERE scan_id = $6`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Subfinder scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Subfinder scan status for %s", scanID)
	}
}

func GetSubfinderScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan SubfinderScanStatus
	query := `SELECT * FROM subfinder_scans WHERE scan_id = $1`
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
		&scan.ScopeTargetID,
		&scan.AutoScanSessionID,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[ERROR] Failed to get scan status: %v", err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	response := map[string]interface{}{
		"id":                   scan.ID,
		"scan_id":              scan.ScanID,
		"domain":               scan.Domain,
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
	json.NewEncoder(w).Encode(response)
}

func GetSubfinderScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM subfinder_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans = []map[string]interface{}{}
	for rows.Next() {
		var scan SubfinderScanStatus
		var scopeTargetID string
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
			&scopeTargetID,
			&scan.AutoScanSessionID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":                   scan.ID,
			"scan_id":              scan.ScanID,
			"domain":               scan.Domain,
			"status":               scan.Status,
			"result":               nullStringToString(scan.Result),
			"error":                nullStringToString(scan.Error),
			"stdout":               nullStringToString(scan.StdOut),
			"stderr":               nullStringToString(scan.StdErr),
			"command":              nullStringToString(scan.Command),
			"execution_time":       nullStringToString(scan.ExecTime),
			"created_at":           scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id":      scopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
