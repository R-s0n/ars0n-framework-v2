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

type SubdomainizerScanStatus struct {
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

func RunGoSpiderScan(w http.ResponseWriter, r *http.Request) {
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
		insertQuery = `INSERT INTO gospider_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO gospider_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go executeAndParseGoSpiderScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// gospiderWildcardBaseArity is the arity of every flag THIS runner hardcodes, so the settings
// overlay can tell `-c 10` apart from a bare `-a` and never mistake a value for a flag.
var gospiderWildcardBaseArity = map[string]int{
	"-s": 1, "-c": 1, "-d": 1, "-t": 1, "-k": 1, "-K": 1, "-m": 1, "--blacklist": 1,
	"-a": 0, "-w": 0, "-r": 0, "--js": 0, "--sitemap": 0, "--robots": 0,
	"--debug": 0, "--json": 0, "-v": 0,
	"--user-agent": 1, "--header": 1,
}

// gospiderWildcardNegatable holds the two switches whose default INSIDE GoSpider is true.
//
// Omitting --js does not disable JavaScript parsing, it leaves it on, so a plain bool composer ships
// a switch that does nothing in either position while the UI shows it as off. The URL workflow was
// bitten by exactly this and fixed it the same way at urlScanUtils.go:2735-2740. Both forms were
// checked against the installed image: `gospider --js=false --robots=false --sitemap=false` parsed
// with RC 0, and an unknown flag is loud (`Error: unknown flag`), so a typo here could not pass
// silently.
var gospiderWildcardNegatable = map[string]string{
	"--js":     "--js=false",
	"--robots": "--robots=false",
}

// gospiderWildcardRegexOptions are the three settings GoSpider hands to regexp.MustCompile with no
// error handling at crawler.go:260.
//
// MEASURED: `--blacklist '['` panics the process. The runner then logs a WARN and moves to the next
// URL, so ONE BAD CHARACTER SKIPS EVERY LIVE HOST and the scan is stored as "No results found" with
// nothing naming the cause. Compiling them here is the last line of defence before that happens.
var gospiderWildcardRegexOptions = map[string]string{
	"blacklist":       "",
	"whitelist":       "",
	"whitelistDomain": "http(s)?://",
}

// buildGoSpiderWildcardCommand builds the argument vector for one live host.
//
// PURE, so the thing the tests pin is the thing the scan runs. With an empty settings map it returns
// exactly the vector this runner has always produced, which is asserted byte for byte by
// TestGoSpiderWildcardDefaultCommandIsUnchanged.
func buildGoSpiderWildcardCommand(targetURL, customUserAgent, customHeader string,
	tool WildcardTool, settings map[string]any) ([]string, []string) {

	settings, notes := sanitizeGoSpiderWildcardSettings(tool, settings)

	base := []string{
		"-s", targetURL,
		"-c", "10",
		"-d", "3",
		"-t", "3",
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
	}

	// PRECEDENCE, DECIDED AND STATED: a per-target Wildcard setting BEATS the global custom HTTP
	// setting it declares in shadowed_by. Both reach the same GoSpider flag, so one of them has to
	// win, and it has to be the specific one or the per-target field is a control that saves
	// successfully and never applies. The global is then not appended at all rather than being
	// appended and silently overridden by flag ordering, so the stored command shows one value for
	// one flag and there is nothing to reverse-engineer later.
	if customUserAgent != "" {
		if wildcardSettingIsSet(settings, "userAgent") {
			notes = append(notes, "The framework's global custom User-Agent was NOT sent: this target's "+
				"userAgent setting takes precedence over it, because a per-target field that loses to a "+
				"global one is a field that never applies.")
		} else {
			base = append(base, "--user-agent", customUserAgent)
		}
	}
	if customHeader != "" {
		if wildcardSettingIsSet(settings, "headers") {
			notes = append(notes, "The framework's global custom header was NOT sent: this target's headers "+
				"setting takes precedence over it, for the same reason as the User-Agent.")
		} else {
			base = append(base, "--header", customHeader)
		}
	}

	overlay := wildcardOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: gospiderWildcardBaseArity,
		negate:    gospiderWildcardNegatable,
	}
	args, overlayNotes := overlay.apply(base)
	notes = append(notes, overlayNotes...)

	// Honesty about a field that composes an argument and still changes nothing. GoSpider sizes its
	// worker pool from -t to drain the SITE input channel (main.go:152-158), and this runner starts
	// one process per URL with a single -s, so there is always exactly one site and therefore one
	// worker. The flag is accepted, it lands on the command line, and it cannot do anything until the
	// runner is changed to feed every live host through -S in one process.
	if wildcardSettingIsSet(settings, "threads") {
		notes = append(notes, "threads reaches the command line but cannot take effect in this runner: "+
			"GoSpider sizes that pool from the number of SITES, and this runner starts one process per URL "+
			"with a single -s. It becomes real only if the runner is changed to pass -S with every live host.")
	}

	argv := append([]string{
		"docker", "exec",
		"ars0n-framework-v2-gospider-1",
		"timeout", "300",
		"gospider",
	}, args...)
	return argv, notes
}

// sanitizeGoSpiderWildcardSettings removes the values that would kill the scan rather than configure
// it, and says which and why.
//
// A regex that does not compile is not a bad setting, it is a crash: GoSpider calls MustCompile, the
// process panics, this runner logs a WARN and moves on, and every live host is skipped while the
// scan is stored as "No results found". Dropping the pattern and running the crawl unfiltered is the
// lesser harm, and the note makes it visible instead of mysterious.
func sanitizeGoSpiderWildcardSettings(tool WildcardTool, settings map[string]any) (map[string]any, []string) {
	if len(settings) == 0 {
		return settings, nil
	}
	out := map[string]any{}
	for key, value := range settings {
		out[key] = value
	}
	var notes []string
	keys := make([]string, 0, len(gospiderWildcardRegexOptions))
	for key := range gospiderWildcardRegexOptions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		raw, ok := out[key]
		if !ok {
			continue
		}
		pattern := strings.TrimSpace(stringifySetting(raw))
		if pattern == "" {
			continue
		}
		if _, err := regexp.Compile(gospiderWildcardRegexOptions[key] + pattern); err != nil {
			delete(out, key)
			meta := tool.Options[key]
			notes = append(notes, fmt.Sprintf(
				"%s was DROPPED because %q is not a valid regular expression (%v). GoSpider compiles it with "+
					"regexp.MustCompile and no error handling, so sending it would panic the process for every "+
					"live host and store the scan as 'No results found'. The crawl ran without it. Flag: %s.",
				key, pattern, err, meta.Flag))
		}
	}
	return out, notes
}

// wildcardSettingIsSet reports whether a key carries a value that will actually compose something,
// so "present but empty" is not mistaken for "configured".
func wildcardSettingIsSet(settings map[string]any, key string) bool {
	value, ok := settings[key]
	if !ok || value == nil {
		return false
	}
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v) != ""
	case []any:
		return len(v) > 0
	case []string:
		return len(v) > 0
	case bool:
		return v
	}
	return true
}

func executeAndParseGoSpiderScan(scanID, domain string) {
	log.Printf("[INFO] Starting GoSpider scan for domain %s (scan ID: %s)", domain, scanID)
	startTime := time.Now()

	// Get custom HTTP settings
	customUserAgent, customHeader := GetCustomHTTPSettings()
	log.Printf("[DEBUG] Custom User Agent: %s", customUserAgent)
	log.Printf("[DEBUG] Custom Header: %s", customHeader)

	// The per-target Wildcard settings, from the ONE store the Settings screen and the MCP tool both
	// write. Absent is the normal case and produces the command line this runner has always built.
	var gospiderScopeTargetID string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM gospider_scans WHERE scan_id = $1`, scanID).Scan(&gospiderScopeTargetID); err != nil {
		log.Printf("[WARN] Could not resolve scope target for GoSpider scan %s, running on tool defaults: %v", scanID, err)
	}
	gospiderTool, gospiderSettings := wildcardRunnerSettings(gospiderScopeTargetID, "gospider")
	if len(gospiderSettings) > 0 {
		log.Printf("[INFO] GoSpider is running with %d stored Wildcard settings for scope target %s",
			len(gospiderSettings), gospiderScopeTargetID)
	}

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
	settingsRecorded := false

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

		argv, settingNotes := buildGoSpiderWildcardCommand(
			httpxResult.URL, customUserAgent, customHeader, gospiderTool, gospiderSettings)
		if preamble := wildcardSettingsPreamble(
			gospiderTool, gospiderScopeTargetID, gospiderSettings, settingNotes); preamble != "" && !settingsRecorded {
			allStdout.WriteString(preamble)
			for _, note := range settingNotes {
				log.Printf("[INFO] GoSpider settings: %s", note)
			}
			settingsRecorded = true
		}
		cmd := exec.Command(argv[0], argv[1:]...)

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

	var scans = []map[string]interface{}{}
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
			"scope_target_id":      scan.ScopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func RunSubdomainizerScan(w http.ResponseWriter, r *http.Request) {
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
		insertQuery = `INSERT INTO subdomainizer_scans (scan_id, domain, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO subdomainizer_scans (scan_id, domain, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, domain, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go executeAndParseSubdomainizerScan(scanID, domain)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// The container paths the runner OWNS, because it has to read each file back out with a second
// `docker exec cat` before it rm -rf's the mount directory. That is why the three "collect" options
// are switches with no flag of their own: the operator chooses whether the work is kept, the runner
// chooses where it lands.
const (
	subdomainizerWildcardMount        = "/tmp/subdomainizer-mounts"
	subdomainizerWildcardOutputPath   = subdomainizerWildcardMount + "/output.txt"
	subdomainizerWildcardSecretsPath  = subdomainizerWildcardMount + "/secrets.txt"
	subdomainizerWildcardCloudPath    = subdomainizerWildcardMount + "/cloud.txt"
	subdomainizerWildcardGithubSecret = subdomainizerWildcardMount + "/github-secrets.txt"
)

var subdomainizerWildcardBaseArity = map[string]int{
	"-u": 1, "-k": 0, "-o": 1, "-sop": 1, "-cop": 1, "-gop": 1,
}

// buildSubdomainizerWildcardCommand builds the argument vector for one live host.
//
// PURE. With an empty settings map it returns exactly the vector this runner has always produced,
// pinned by TestSubdomainizerWildcardDefaultCommandIsUnchanged.
//
// THREE THINGS HERE ARE NOT A PLAIN FLAG COMPOSITION, and each of them is a measured scan-killer
// rather than a matter of taste:
//
//   - verifyTls IS THE INVERSE OF ITS FLAG. -k is --nossl, "Use it when SSL certificate is not
//     verified". The runner passes it on every run, so verification is OFF today. A generic bool
//     composer emits the flag when the value is TRUE, which would turn "verify certificates" into
//     "do not verify certificates" - the exact opposite of what the operator asked for. It is
//     resolved here instead, and reported upward as something the vocabulary should carry a field
//     for.
//
//   - gitScan WITHOUT gitToken KILLS EVERY HOST. Reproduced: -g with no token prints "Either both
//     '-g' and '-gt' arguments are required or none required. Exiting..." and exits 1. This runner
//     treats a non-zero exit as a per-URL failure, logs a WARN and continues, so the whole scan
//     stores as "No results found" with nothing naming the cause. The flag is dropped and the reason
//     is written where the operator will see it.
//
//   - THE COLLECT SWITCHES COMPOSE NO FLAG BY DESIGN. -sop, -cop and -gop take a FILENAME the runner
//     must own. collectSecrets is already paid for on every run today and the file is deleted unread
//     at the end of the scan; turning it off is the only one of the three that changes the command
//     line as things stand.
func buildSubdomainizerWildcardCommand(targetURL string, tool WildcardTool, settings map[string]any) ([]string, []string) {
	var notes []string

	skip := map[string]bool{
		"verifyTls":            true,
		"collectSecrets":       true,
		"collectCloudAssets":   true,
		"collectGithubSecrets": true,
	}

	// -g without -gt is a verified exit 1 on every host. Refuse to send it.
	if truthySetting(settings["gitScan"]) && !wildcardSettingIsSet(settings, "gitToken") {
		skip["gitScan"] = true
		notes = append(notes, "gitScan was DROPPED because no gitToken is stored. SubDomainizer exits 1 when -g "+
			"is given without -gt, and this runner treats that as a per-URL failure and continues, so sending it "+
			"would have skipped EVERY live host and stored the scan as 'No results found' with no visible cause. "+
			"Store a GitHub token and the switch will work.")
	}

	base := []string{
		"-u", targetURL,
	}

	// verifyTls, resolved as the inverse it is. Unset and false both keep -k, which is what every
	// scan has always done; only an explicit true removes it.
	verifyTLS, explicit := settings["verifyTls"].(bool)
	if explicit && verifyTLS {
		notes = append(notes, "TLS verification was turned ON, so -k (--nossl) was NOT sent. Wildcard targets "+
			"routinely serve certificates that do not match the brute-forced hostname, and SubDomainizer treats a "+
			"certificate error as a fatal ConnectionError and exits 1, which this runner records as a skipped "+
			"host. If the scan comes back much emptier than usual, this is the first thing to turn back off.")
	} else {
		base = append(base, "-k")
	}

	base = append(base, "-o", subdomainizerWildcardOutputPath)

	// collectSecrets: on today and always has been. Only an explicit false changes the command line.
	if keepSecrets, set := settings["collectSecrets"].(bool); !set || keepSecrets {
		base = append(base, "-sop", subdomainizerWildcardSecretsPath)
	} else {
		notes = append(notes, "collectSecrets is off, so -sop was not sent. Nothing currently reads that file on a "+
			"default run anyway, so this saves the extraction work rather than losing a result.")
	}
	if truthySetting(settings["collectCloudAssets"]) {
		base = append(base, "-cop", subdomainizerWildcardCloudPath)
		notes = append(notes, "collectCloudAssets is on, so -cop was added with a runner-owned path and the file is "+
			"read back into this scan's stored output before the mount directory is deleted.")
	}
	if truthySetting(settings["collectGithubSecrets"]) && !skip["gitScan"] && truthySetting(settings["gitScan"]) {
		base = append(base, "-gop", subdomainizerWildcardGithubSecret)
		notes = append(notes, "collectGithubSecrets is on, so -gop was added with a runner-owned path.")
	}

	overlay := wildcardOverlay{
		tool:      tool,
		settings:  settings,
		baseArity: subdomainizerWildcardBaseArity,
		skip:      skip,
	}
	args, overlayNotes := overlay.apply(base)
	notes = append(notes, overlayNotes...)

	if wildcardSettingIsSet(settings, "sanMode") {
		notes = append(notes, "sanMode is on. SubDomainizer's SAN phase only PRINTS what it finds; savedata() has "+
			"already written the -o file by then, so the names never reach the file this runner reads. They are "+
			"recovered from stdout below instead, filtered to the scope target's own domain, which also contains "+
			"the 'all' mode's hop onto unrelated registrable domains.")
	}

	argv := append([]string{
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"timeout", "300",
		"python3", "SubDomainizer.py",
	}, args...)
	return argv, notes
}

// subdomainizerSANHostnames recovers the SAN phase's discoveries from stdout.
//
// It exists because the switch is otherwise a control that provably changes nothing: the block at
// SubDomainizer.py:884-925 prints its hostnames and never adds them to finalset, and finalset is
// what savedata() writes to the -o file the runner reads. Verified by reading the installed source
// in ars0n-framework-v2-subdomainizer-1.
//
// Everything is filtered through the scope target's domain, which is also the containment for
// `-san all`: that mode deliberately follows certificate SANs onto whatever else is parked on a
// shared load balancer, and none of it belongs in this target's subdomain table.
func subdomainizerSANHostnames(stdout, domain string) []string {
	marker := strings.Index(stdout, "Subject Alternative Names")
	if marker < 0 {
		return nil
	}
	hostname := regexp.MustCompile(`^[A-Za-z0-9_*][A-Za-z0-9_.\-]*\.[A-Za-z]{2,}$`)
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*m`)

	var out []string
	for _, line := range strings.Split(stdout[marker:], "\n") {
		line = strings.TrimSpace(ansi.ReplaceAllString(line, ""))
		if line == "" || strings.HasPrefix(line, "_") {
			continue
		}
		if !hostname.MatchString(line) {
			continue
		}
		if !strings.Contains(line, domain) {
			continue
		}
		out = append(out, strings.TrimPrefix(line, "*."))
	}
	return out
}

// subdomainizerWildcardCollectedFiles names the files an explicitly enabled collect switch produces,
// so the runner can read them back before the rm -rf at the end of the scan removes them.
//
// collectSecrets is the interesting one: the runner has ALWAYS passed -sop and has ALWAYS deleted
// the file unread, so the extraction work is already being paid for on every wildcard scan. Reading
// it back only happens when the operator explicitly turns the switch on, so a scan with no stored
// settings produces exactly the output it always did.
func subdomainizerWildcardCollectedFiles(settings map[string]any) []struct{ label, path string } {
	var out []struct{ label, path string }
	if keep, set := settings["collectSecrets"].(bool); set && keep {
		out = append(out, struct{ label, path string }{"Secrets found in page and JavaScript", subdomainizerWildcardSecretsPath})
	}
	if truthySetting(settings["collectCloudAssets"]) {
		out = append(out, struct{ label, path string }{"Cloud service URLs", subdomainizerWildcardCloudPath})
	}
	if truthySetting(settings["collectGithubSecrets"]) && truthySetting(settings["gitScan"]) {
		out = append(out, struct{ label, path string }{"Secrets found on GitHub", subdomainizerWildcardGithubSecret})
	}
	return out
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

	var subdomainizerScopeTargetID string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id FROM subdomainizer_scans WHERE scan_id = $1`, scanID).Scan(&subdomainizerScopeTargetID); err != nil {
		log.Printf("[WARN] Could not resolve scope target for Subdomainizer scan %s, running on tool defaults: %v", scanID, err)
	}
	subdomainizerTool, subdomainizerSettings := wildcardRunnerSettings(subdomainizerScopeTargetID, "subdomainizer")
	if len(subdomainizerSettings) > 0 {
		log.Printf("[INFO] Subdomainizer is running with %d stored Wildcard settings for scope target %s",
			len(subdomainizerSettings), subdomainizerScopeTargetID)
	}

	mkdirCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"mkdir", "-p", subdomainizerWildcardMount,
	)
	if err := mkdirCmd.Run(); err != nil {
		log.Printf("[ERROR] Failed to create mount directory in container: %v", err)
		updateSubdomainizerScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create mount directory: %v", err), "", time.Since(startTime).String(), "")
		return
	}

	chmodCmd := exec.Command(
		"docker", "exec",
		"ars0n-framework-v2-subdomainizer-1",
		"chmod", "777", subdomainizerWildcardMount,
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
	settingsRecorded := false

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

		argv, settingNotes := buildSubdomainizerWildcardCommand(httpxResult.URL, subdomainizerTool, subdomainizerSettings)
		if preamble := wildcardSettingsPreamble(
			subdomainizerTool, subdomainizerScopeTargetID, subdomainizerSettings, settingNotes); preamble != "" && !settingsRecorded {
			allStdout.WriteString(preamble)
			for _, note := range settingNotes {
				log.Printf("[INFO] Subdomainizer settings: %s", note)
			}
			settingsRecorded = true
		}
		cmd := exec.Command(argv[0], argv[1:]...)

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
			"cat", subdomainizerWildcardOutputPath,
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

		// The SAN phase never writes to the -o file, so without this the switch is a control that
		// provably changes nothing. Only runs when the operator asked for it.
		if wildcardSettingIsSet(subdomainizerSettings, "sanMode") {
			sanFound := 0
			for _, host := range subdomainizerSANHostnames(stdout.String(), domain) {
				if !seen[host] {
					seen[host] = true
					allSubdomains = append(allSubdomains, host)
					sanFound++
				}
			}
			log.Printf("[INFO] Recovered %d subdomains from the SAN phase of %s", sanFound, httpxResult.URL)
		}

		allStdout.WriteString(fmt.Sprintf("\n=== Results for %s ===\n", httpxResult.URL))
		allStdout.Write(stdout.Bytes())
		// The collect switches are only meaningful if what they collect is read back before the mount
		// directory is deleted. A MISSING file is normal, not an error: SubDomainizer writes nothing at
		// all when a result set is empty, so a failed cat here is treated as "nothing found".
		for _, extra := range subdomainizerWildcardCollectedFiles(subdomainizerSettings) {
			readCmd := exec.Command("docker", "exec", "ars0n-framework-v2-subdomainizer-1", "cat", extra.path)
			var content bytes.Buffer
			readCmd.Stdout = &content
			if err := readCmd.Run(); err != nil || strings.TrimSpace(content.String()) == "" {
				continue
			}
			allStdout.WriteString(fmt.Sprintf("\n=== %s for %s (%s) ===\n", extra.label, httpxResult.URL, extra.path))
			allStdout.Write(content.Bytes())
		}
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
		"rm", "-rf", subdomainizerWildcardMount,
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

	var scans = []map[string]interface{}{}
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
			"scope_target_id":      scan.ScopeTargetID,
			"auto_scan_session_id": nullStringToString(scan.AutoScanSessionID),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}
