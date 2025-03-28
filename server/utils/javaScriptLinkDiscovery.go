package utils

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

type GoSpiderScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
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

type SubdomainizerScanStatus struct {
	ID            string         `json:"id"`
	ScanID        string         `json:"scan_id"`
	Domain        string         `json:"domain"`
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

func RunGoSpiderScan(w http.ResponseWriter, r *http.Request) {
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
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO gospider_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go executeAndParseGoSpiderScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func executeAndParseGoSpiderScan(scanID, domain string) {
	log.Printf("[INFO] Starting GoSpider scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get custom HTTP settings
	customUserAgent, customHeader := GetCustomHTTPSettings()
	log.Printf("[DEBUG] Custom User Agent: %s", customUserAgent)
	log.Printf("[DEBUG] Custom Header: %s", customHeader)

	var httpxResults string
	err := dbPool.QueryRow(context.Background(), `
		SELECT result FROM httpx_scans 
		WHERE scope_target_id = (
			SELECT scope_target_id FROM gospider_scans WHERE scan_id = $1
		)
		AND status = 'success'
		ORDER BY created_at DESC 
		LIMIT 1`, scanID).Scan(&httpxResults)

	if err != nil {
		log.Printf("[ERROR] Failed to get httpx results: %v", err)
		updateGoSpiderScanStatus(scanID, "error", "", "Failed to get httpx results", "", time.Since(startTime).String(), "")
		return
	}

	log.Printf("[DEBUG] Retrieved httpx results, length: %d bytes", len(httpxResults))

	urls := strings.Split(httpxResults, "\n")
	log.Printf("[INFO] Processing %d URLs from httpx results", len(urls))

	var allSubdomains []string
	seen := make(map[string]bool)
	var allStdout, allStderr bytes.Buffer
	var commands []string

	for _, urlLine := range urls {
		if urlLine == "" {
			continue
		}

		var httpxResult struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(urlLine), &httpxResult); err != nil {
			log.Printf("[WARN] Failed to parse httpx result line: %v", err)
			continue
		}

		if httpxResult.URL == "" {
			continue
		}

		log.Printf("[INFO] Running GoSpider against URL: %s", httpxResult.URL)
		scanStartTime := time.Now()

		cmd := exec.Command(
			"docker", "exec",
			"ars0n-framework-v2-gospider-1",
			"gospider",
			"-s", httpxResult.URL,
			"-c", "20",
			"-d", "3",
			"-t", "5",
			"-k", "1",
			"-K", "2",
			"-m", "30",
			"--blacklist", ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|svg)",
			"-a",
			"-w",
			"-r",
			"--js",
			"--sitemap",
			"--robots",
			"--debug",
			"--json",
			"-v",
		)

		// Add custom user agent if specified
		if customUserAgent != "" {
			cmd.Args = append(cmd.Args, "--user-agent", customUserAgent)
		}

		// Add custom header if specified
		if customHeader != "" {
			cmd.Args = append(cmd.Args, "--header", customHeader)
		}

		commands = append(commands, cmd.String())
		log.Printf("[DEBUG] Executing command: %s", cmd.String())

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		scanDuration := time.Since(scanStartTime)
		log.Printf("[DEBUG] GoSpider scan for %s completed in %s", httpxResult.URL, scanDuration)

		if err != nil {
			log.Printf("[WARN] GoSpider scan failed for %s: %v", httpxResult.URL, err)
			log.Printf("[WARN] stderr output: %s", stderr.String())
			continue
		}

		log.Printf("[DEBUG] Raw stdout length for %s: %d bytes", httpxResult.URL, stdout.Len())
		if stdout.Len() == 0 {
			log.Printf("[WARN] No output from GoSpider for %s", httpxResult.URL)
		}

		lines := strings.Split(stdout.String(), "\n")
		log.Printf("[DEBUG] Processing %d lines of output for %s", len(lines), httpxResult.URL)
		newSubdomains := 0

		log.Printf("[DEBUG] === Start of detailed output analysis for %s ===", httpxResult.URL)
		for i, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			log.Printf("[DEBUG] Line %d: %s", i+1, line)

			parsedURL, err := url.Parse(line)
			if err != nil {
				urlRegex := regexp.MustCompile(`https?://[^\s<>"']+|[^\s<>"']+\.[^\s<>"']+`)
				matches := urlRegex.FindAllString(line, -1)
				if len(matches) > 0 {
					log.Printf("[DEBUG] Found %d URL matches in line using regex", len(matches))
				}
				for _, match := range matches {
					log.Printf("[DEBUG] Processing URL match: %s", match)
					if !strings.HasPrefix(match, "http") {
						match = "https://" + match
						log.Printf("[DEBUG] Added https:// prefix: %s", match)
					}
					if matchURL, err := url.Parse(match); err == nil {
						hostname := matchURL.Hostname()
						log.Printf("[DEBUG] Extracted hostname: %s", hostname)
						if strings.Contains(hostname, domain) {
							if !seen[hostname] {
								log.Printf("[DEBUG] Found new subdomain from URL match: %s", hostname)
								seen[hostname] = true
								allSubdomains = append(allSubdomains, hostname)
								newSubdomains++
							} else {
								log.Printf("[DEBUG] Skipping duplicate subdomain: %s", hostname)
							}
						} else {
							log.Printf("[DEBUG] Hostname %s does not contain domain %s", hostname, domain)
						}
					} else {
						log.Printf("[DEBUG] Failed to parse URL match %s: %v", match, err)
					}
				}
				continue
			}

			hostname := parsedURL.Hostname()
			log.Printf("[DEBUG] Processing valid URL with hostname: %s", hostname)
			if strings.Contains(hostname, domain) {
				if !seen[hostname] {
					log.Printf("[DEBUG] Found new subdomain from URL: %s", hostname)
					seen[hostname] = true
					allSubdomains = append(allSubdomains, hostname)
					newSubdomains++
				} else {
					log.Printf("[DEBUG] Skipping duplicate subdomain: %s", hostname)
				}
			} else {
				log.Printf("[DEBUG] Hostname %s does not contain domain %s", hostname, domain)
			}

			pathParts := strings.Split(parsedURL.Path, "/")
			if len(pathParts) > 0 {
				log.Printf("[DEBUG] Checking %d path segments for potential subdomains", len(pathParts))
				for _, part := range pathParts {
					if strings.Contains(part, domain) && strings.Contains(part, ".") {
						cleanPart := strings.Trim(part, ".")
						log.Printf("[DEBUG] Found potential subdomain in path: %s", cleanPart)
						if !seen[cleanPart] {
							log.Printf("[DEBUG] Found new subdomain in path: %s", cleanPart)
							seen[cleanPart] = true
							allSubdomains = append(allSubdomains, cleanPart)
							newSubdomains++
						} else {
							log.Printf("[DEBUG] Skipping duplicate subdomain from path: %s", cleanPart)
						}
					}
				}
			}
		}

		log.Printf("[DEBUG] === End of detailed output analysis ===")
		log.Printf("[DEBUG] Current list of unique subdomains: %v", allSubdomains)
		log.Printf("[INFO] Found %d new unique subdomains from %s", newSubdomains, httpxResult.URL)

		allStdout.WriteString(fmt.Sprintf("\n=== Results for %s (Duration: %s) ===\n", httpxResult.URL, scanDuration))
		allStdout.Write(stdout.Bytes())
		allStderr.WriteString(fmt.Sprintf("\n=== Errors for %s ===\n", httpxResult.URL))
		allStderr.Write(stderr.Bytes())
	}

	sort.Strings(allSubdomains)
	result := strings.Join(allSubdomains, "\n")

	execTime := time.Since(startTime).String()
	log.Printf("[INFO] All GoSpider scans completed in %s", execTime)
	log.Printf("[INFO] Found %d total unique subdomains", len(allSubdomains))
	if len(allSubdomains) > 0 {
		log.Printf("[DEBUG] First 10 subdomains found: %v", allSubdomains[:min(10, len(allSubdomains))])
	}

	if result == "" {
		log.Printf("[WARN] No output from any GoSpider scan")
		updateGoSpiderScanStatus(scanID, "completed", "", "No results found", strings.Join(commands, "\n"), execTime, allStdout.String())
	} else {
		updateGoSpiderScanStatus(scanID, "success", result, allStderr.String(), strings.Join(commands, "\n"), execTime, allStdout.String())
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func updateGoSpiderScanStatus(scanID, status, result, stderr, command, execTime, stdout string) {
	log.Printf("[INFO] Updating GoSpider scan status for %s to %s", scanID, status)
	query := `UPDATE gospider_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5, stdout = $6 WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, stdout, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update GoSpider scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated GoSpider scan status for %s", scanID)
	}
}

func GetGoSpiderScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan GoSpiderScanStatus
	query := `SELECT * FROM gospider_scans WHERE scan_id = $1`
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
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetGoSpiderScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM gospider_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan GoSpiderScanStatus
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
			&scan.ScopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scan.ScopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunSubdomainizerScan(w http.ResponseWriter, r *http.Request) {
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
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, wildcardDomain).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] No matching wildcard scope target found for domain %s", domain)
		http.Error(w, "No matching wildcard scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO subdomainizer_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	_, err = dbPool.Exec(context.Background(), insertQuery, scanID, domain, "pending", scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go executeAndParseSubdomainizerScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func executeAndParseSubdomainizerScan(scanID, domain string) {
	log.Printf("[INFO] Starting Subdomainizer scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	var httpxResults string
	err := dbPool.QueryRow(context.Background(), `
		SELECT result FROM httpx_scans 
		WHERE scope_target_id = (
			SELECT scope_target_id FROM subdomainizer_scans WHERE scan_id = $1
		)
		AND status = 'success'
		ORDER BY created_at DESC 
		LIMIT 1`, scanID).Scan(&httpxResults)

	if err != nil {
		log.Printf("[ERROR] Failed to get httpx results: %v", err)
		updateSubdomainizerScanStatus(scanID, "error", "", "Failed to get httpx results", "", time.Since(startTime).String(), "")
		return
	}

	mkdirCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"mkdir", "-p", "/tmp/subdomainizer-mounts",
	)
	if err := mkdirCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to create mount directory in container: %v", err)
		updateSubdomainizerScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create mount directory: %v", err), "", time.Since(startTime).String(), "")
		return
	}

	chmodCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"chmod", "777", "/tmp/subdomainizer-mounts",
	)
	if err := chmodCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to set permissions on mount directory: %v", err)
		updateSubdomainizerScanStatus(scanID, "error", "", fmt.Sprintf("Failed to set permissions: %v", err), "", time.Since(startTime).String(), "")
		return
	}

	urls := strings.Split(httpxResults, "\n")
	log.Printf("[INFO] Processing %d URLs from httpx results", len(urls))

	var allSubdomains []string
	seen := make(map[string]bool)
	var allStdout, allStderr bytes.Buffer
	var commands []string

	for _, urlLine := range urls {
		if urlLine == "" {
			continue
		}

		var httpxResult struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(urlLine), &httpxResult); err != nil {
			log.Printf("[WARN] Failed to parse httpx result line: %v", err)
			continue
		}

		if httpxResult.URL == "" {
			continue
		}

		log.Printf("[INFO] Running Subdomainizer against URL: %s", httpxResult.URL)

		cmd := exec.Command(
			"docker", "exec",
			"ars0n-framework-v2-subdomainizer-1",
			"python3", "SubDomainizer.py",
			"-u", httpxResult.URL,
			"-k",
			"-o", "/tmp/subdomainizer-mounts/output.txt",
			"-sop", "/tmp/subdomainizer-mounts/secrets.txt",
		)

		commands = append(commands, cmd.String())
		log.Printf("[INFO] Executing command: %s", cmd.String())

		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			log.Printf("[WARN] Subdomainizer scan failed for %s: %v", httpxResult.URL, err)
			log.Printf("[WARN] stderr output: %s", stderr.String())
			continue
		}

		catCmd := exec.Command(
			"docker", "exec",
			"ars0n-framework-v2-subdomainizer-1",
			"cat", "/tmp/subdomainizer-mounts/output.txt",
		)

		var outputContent bytes.Buffer
		catCmd.Stdout = &outputContent
		if err := catCmd.Run(); err != nil {
			log.Printf("[WARN] Failed to read output file for %s: %v", httpxResult.URL, err)
			continue
		}

		lines := strings.Split(outputContent.String(), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && strings.Contains(line, domain) && !seen[line] {
				seen[line] = true
				allSubdomains = append(allSubdomains, line)
			}
		}

		allStdout.WriteString(fmt.Sprintf("\n=== Results for %s ===\n", httpxResult.URL))
		allStdout.Write(stdout.Bytes())
		allStderr.WriteString(fmt.Sprintf("\n=== Errors for %s ===\n", httpxResult.URL))
		allStderr.Write(stderr.Bytes())
	}

	sort.Strings(allSubdomains)
	result := strings.Join(allSubdomains, "\n")

	execTime := time.Since(startTime).String()
	log.Printf("[INFO] All Subdomainizer scans completed in %s", execTime)
	log.Printf("[DEBUG] Found %d unique subdomains", len(allSubdomains))

	if result == "" {
		log.Printf("[WARN] No output from any Subdomainizer scan")
		updateSubdomainizerScanStatus(scanID, "completed", "", "No results found", strings.Join(commands, "\n"), execTime, allStdout.String())
	} else {
		updateSubdomainizerScanStatus(scanID, "success", result, allStderr.String(), strings.Join(commands, "\n"), execTime, allStdout.String())
	}

	cleanupCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"rm", "-rf", "/tmp/subdomainizer-mounts",
	)
	if err := cleanupCmd.Run(); err != nil {
		log.Printf("[WARN] Failed to cleanup files in container: %v", err)
	}

	log.Printf("[INFO] Scan status updated for scan %s", scanID)
}

func updateSubdomainizerScanStatus(scanID, status, result, stderr, command, execTime, stdout string) {
	log.Printf("[INFO] Updating Subdomainizer scan status for %s to %s", scanID, status)
	query := `UPDATE subdomainizer_scans SET status = $1, result = $2, stderr = $3, command = $4, execution_time = $5, stdout = $6 WHERE scan_id = $7`
	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, stdout, scanID)
	if err != nil {
		log.Printf("[ERROR] Failed to update Subdomainizer scan status for %s: %v", scanID, err)
	} else {
		log.Printf("[INFO] Successfully updated Subdomainizer scan status for %s", scanID)
	}
}

func GetSubdomainizerScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var scan SubdomainizerScanStatus
	query := `SELECT * FROM subdomainizer_scans WHERE scan_id = $1`
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
		"id":              scan.ID,
		"scan_id":         scan.ScanID,
		"domain":          scan.Domain,
		"status":          scan.Status,
		"result":          nullStringToString(scan.Result),
		"error":           nullStringToString(scan.Error),
		"stdout":          nullStringToString(scan.StdOut),
		"stderr":          nullStringToString(scan.StdErr),
		"command":         nullStringToString(scan.Command),
		"execution_time":  nullStringToString(scan.ExecTime),
		"created_at":      scan.CreatedAt.Format(time.RFC3339),
		"scope_target_id": scan.ScopeTargetID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func GetSubdomainizerScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	query := `SELECT * FROM subdomainizer_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan SubdomainizerScanStatus
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
			&scan.ScopeTargetID,
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		scans = append(scans, map[string]interface{}{
			"id":              scan.ID,
			"scan_id":         scan.ScanID,
			"domain":          scan.Domain,
			"status":          scan.Status,
			"result":          nullStringToString(scan.Result),
			"error":           nullStringToString(scan.Error),
			"stdout":          nullStringToString(scan.StdOut),
			"stderr":          nullStringToString(scan.StdErr),
			"command":         nullStringToString(scan.Command),
			"execution_time":  nullStringToString(scan.ExecTime),
			"created_at":      scan.CreatedAt.Format(time.RFC3339),
			"scope_target_id": scan.ScopeTargetID,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
