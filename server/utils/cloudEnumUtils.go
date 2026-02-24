package utils

import (
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
	"github.com/jackc/pgx/v5"
)

type CloudEnumScanStatus struct {
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

type CloudEnumResult struct {
	Platform string `json:"platform"`
	Msg      string `json:"msg"`
	Target   string `json:"target"`
	Access   string `json:"access"`
}

// CloudEnumConfig represents the configuration loaded from the database
type CloudEnumConfig struct {
	Keywords            []string               `json:"keywords"`
	Threads             int                    `json:"threads"`
	EnabledPlatforms    map[string]interface{} `json:"enabled_platforms"`
	CustomDNSServer     string                 `json:"custom_dns_server"`
	DNSResolverMode     string                 `json:"dns_resolver_mode"`
	ResolverConfig      string                 `json:"resolver_config"`
	AdditionalResolvers string                 `json:"additional_resolvers"`
	MutationsFilePath   string                 `json:"mutations_file_path"`
	BruteFilePath       string                 `json:"brute_file_path"`
	ResolverFilePath    string                 `json:"resolver_file_path"`
	SelectedServices    map[string][]string    `json:"selected_services"`
	SelectedRegions     map[string][]string    `json:"selected_regions"`
}

func RunCloudEnumScan(w http.ResponseWriter, r *http.Request) {
	log.Printf("[CLOUD-ENUM] [INFO] Starting Cloud Enum scan request handling")
	var payload struct {
		CompanyName       string  `json:"company_name" binding:"required"`
		AutoScanSessionID *string `json:"auto_scan_session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.CompanyName == "" {
		log.Printf("[CLOUD-ENUM] [ERROR] Invalid request body: %v", err)
		http.Error(w, "Invalid request body. `company_name` is required.", http.StatusBadRequest)
		return
	}

	companyName := payload.CompanyName
	log.Printf("[CLOUD-ENUM] [INFO] Processing Cloud Enum scan for company: %s", companyName)

	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] No matching company scope target found for company %s: %v", companyName, err)
		http.Error(w, "No matching company scope target found.", http.StatusBadRequest)
		return
	}
	log.Printf("[CLOUD-ENUM] [INFO] Found scope target ID: %s for company: %s", scopeTargetID, companyName)

	scanID := uuid.New().String()
	log.Printf("[CLOUD-ENUM] [INFO] Generated new scan ID: %s", scanID)

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cloud_enum_scans (
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
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to create cloud_enum_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}
	log.Printf("[CLOUD-ENUM] [INFO] Ensured cloud_enum_scans table exists")

	var insertQuery string
	var args []interface{}
	if payload.AutoScanSessionID != nil && *payload.AutoScanSessionID != "" {
		insertQuery = `INSERT INTO cloud_enum_scans (scan_id, company_name, status, scope_target_id, auto_scan_session_id) VALUES ($1, $2, $3, $4, $5)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID, *payload.AutoScanSessionID}
	} else {
		insertQuery = `INSERT INTO cloud_enum_scans (scan_id, company_name, status, scope_target_id) VALUES ($1, $2, $3, $4)`
		args = []interface{}{scanID, companyName, "pending", scopeTargetID}
	}
	_, err = dbPool.Exec(context.Background(), insertQuery, args...)
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}
	log.Printf("[CLOUD-ENUM] [INFO] Successfully created Cloud Enum scan record in database")

	go ExecuteAndParseCloudEnumScan(scanID, companyName)

	log.Printf("[CLOUD-ENUM] [INFO] Cloud Enum scan initiated successfully, returning scan ID: %s", scanID)
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

func ExecuteAndParseCloudEnumScan(scanID, companyName string) {
	log.Printf("[CLOUD-ENUM] [INFO] Starting Cloud Enum scan execution for company %s (scan ID: %s)", companyName, scanID)
	startTime := time.Now()

	// Get scope target ID for config lookup
	query := `SELECT id FROM scope_targets WHERE type = 'Company' AND scope_target = $1`
	var scopeTargetID string
	err := dbPool.QueryRow(context.Background(), query, companyName).Scan(&scopeTargetID)
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to find scope target for company %s: %v", companyName, err)
		UpdateCloudEnumScanStatus(scanID, "error", "", fmt.Sprintf("Failed to find scope target: %v", err), "", time.Since(startTime).String())
		return
	}

	// Load CloudEnum configuration
	config := loadCloudEnumConfig(scopeTargetID)
	log.Printf("[CLOUD-ENUM] [INFO] Loaded config for company %s: keywords=%v, dns_mode=%s, resolver_config=%s",
		companyName, config.Keywords, config.DNSResolverMode, config.ResolverConfig)

	containerName := "ars0n-framework-v2-cloud_enum-1"
	logFile := fmt.Sprintf("/tmp/cloud_enum_%s.json", scanID)

	// Build base command
	command := []string{
		"docker", "exec", containerName,
		"python", "cloud_enum.py",
		"-l", logFile,
		"-f", "json",
	}

	// Add keywords or use company name
	if len(config.Keywords) > 0 {
		for _, keyword := range config.Keywords {
			command = append(command, "-k", keyword)
		}
	} else {
		command = append(command, "-k", companyName)
	}

	// Add DNS resolver configuration
	if config.DNSResolverMode == "multiple" {
		if config.ResolverConfig == "default" {
			// Use built-in resolver file
			command = append(command, "-nsf", "/app/resolvers.txt")
		} else if config.ResolverConfig == "custom" && config.ResolverFilePath != "" {
			// Copy custom resolver file to container
			copyResolverFile(containerName, config.ResolverFilePath, scanID)
			command = append(command, "-nsf", fmt.Sprintf("/tmp/custom_resolvers_%s.txt", scanID))
		} else if config.ResolverConfig == "hybrid" {
			// Create hybrid resolver file
			createHybridResolverFile(containerName, config.AdditionalResolvers, scanID)
			command = append(command, "-nsf", fmt.Sprintf("/tmp/hybrid_resolvers_%s.txt", scanID))
		}
	} else if config.DNSResolverMode == "single" && config.CustomDNSServer != "" {
		// Use single DNS server
		command = append(command, "-ns", config.CustomDNSServer)
	}

	// Add platform disable flags (new cloud_enum uses --disable-* instead of -p)
	if len(config.EnabledPlatforms) > 0 {
		for platform, enabled := range config.EnabledPlatforms {
			if !enabled.(bool) {
				switch platform {
				case "aws":
					command = append(command, "--disable-aws")
				case "azure":
					command = append(command, "--disable-azure")
				case "gcp":
					command = append(command, "--disable-gcp")
				}
			}
		}
	}

	// Add other configuration options
	if config.Threads > 0 && config.Threads != 5 {
		command = append(command, "-t", fmt.Sprintf("%d", config.Threads))
	}

	// Add custom mutation file if available
	if config.MutationsFilePath != "" {
		copyMutationFile(containerName, config.MutationsFilePath, scanID)
		command = append(command, "-m", fmt.Sprintf("/tmp/custom_mutations_%s.txt", scanID))
	}

	// Add custom brute force file if available
	if config.BruteFilePath != "" {
		copyBruteFile(containerName, config.BruteFilePath, scanID)
		command = append(command, "-b", fmt.Sprintf("/tmp/custom_brute_%s.txt", scanID))
	}

	// Add service selection flags
	if config.SelectedServices != nil {
		for platform, services := range config.SelectedServices {
			if len(services) > 0 {
				switch platform {
				case "aws":
					command = append(command, "--aws-services", strings.Join(services, ","))
				case "azure":
					command = append(command, "--azure-services", strings.Join(services, ","))
				case "gcp":
					command = append(command, "--gcp-services", strings.Join(services, ","))
				}
			}
		}
	}

	// Add region selection flags
	if config.SelectedRegions != nil {
		for platform, regions := range config.SelectedRegions {
			if len(regions) > 0 {
				switch platform {
				case "aws":
					command = append(command, "--aws-regions", strings.Join(regions, ","))
				case "azure":
					command = append(command, "--azure-regions", strings.Join(regions, ","))
				case "gcp":
					command = append(command, "--gcp-regions", strings.Join(regions, ","))
				}
			}
		}
	}

	log.Printf("[CLOUD-ENUM] [DEBUG] Executing command: %v", command)
	cmd := exec.Command(command[0], command[1:]...)

	stdout, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to execute cloud_enum: %v", err)
		UpdateCloudEnumScanStatus(scanID, "error", "", fmt.Sprintf("Failed to execute cloud_enum: %v", err), strings.Join(command, " "), time.Since(startTime).String())
		return
	}

	log.Printf("[CLOUD-ENUM] [DEBUG] Command stdout: %s", string(stdout))

	catCommand := []string{"docker", "exec", containerName, "cat", logFile}
	catCmd := exec.Command(catCommand[0], catCommand[1:]...)
	resultOutput, err := catCmd.Output()
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to read results file: %v", err)
		UpdateCloudEnumScanStatus(scanID, "error", "", fmt.Sprintf("Failed to read results file: %v", err), strings.Join(command, " "), time.Since(startTime).String())
		return
	}

	resultStr := string(resultOutput)
	log.Printf("[CLOUD-ENUM] [DEBUG] Raw results length: %d bytes", len(resultStr))

	var cloudEnumResults []CloudEnumResult
	lines := strings.Split(resultStr, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#### CLOUD_ENUM") {
			continue
		}

		var result CloudEnumResult
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			log.Printf("[CLOUD-ENUM] [DEBUG] Skipping invalid JSON line: %s", line)
			continue
		}
		cloudEnumResults = append(cloudEnumResults, result)
	}

	resultJSON, err := json.Marshal(cloudEnumResults)
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to marshal results: %v", err)
		UpdateCloudEnumScanStatus(scanID, "error", "", fmt.Sprintf("Failed to marshal results: %v", err), strings.Join(command, " "), time.Since(startTime).String())
		return
	}

	log.Printf("[CLOUD-ENUM] [DEBUG] Processed %d cloud resources", len(cloudEnumResults))
	UpdateCloudEnumScanStatus(scanID, "success", string(resultJSON), "", strings.Join(command, " "), time.Since(startTime).String())
	log.Printf("[CLOUD-ENUM] [INFO] Cloud Enum scan completed and results stored successfully for company %s", companyName)
}

func UpdateCloudEnumScanStatus(scanID, status, result, stderr, command, execTime string) {
	log.Printf("[CLOUD-ENUM] [INFO] Updating Cloud Enum scan status for scan ID %s to %s", scanID, status)
	query := `UPDATE cloud_enum_scans SET status = $1, result = $2, error = $3, command = $4, execution_time = $5 WHERE scan_id = $6`

	_, err := dbPool.Exec(context.Background(), query, status, result, stderr, command, execTime, scanID)
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to update Cloud Enum scan status for scan ID %s: %v", scanID, err)
		log.Printf("[CLOUD-ENUM] [ERROR] Update attempted with: status=%s, result_length=%d, error_length=%d, command_length=%d, execTime=%s",
			status, len(result), len(stderr), len(command), execTime)
	} else {
		log.Printf("[CLOUD-ENUM] [INFO] Successfully updated Cloud Enum scan status to %s for scan ID %s", status, scanID)
	}
}

func GetCloudEnumScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]
	log.Printf("[CLOUD-ENUM] [INFO] Retrieving Cloud Enum scan status for scan ID: %s", scanID)

	var scan CloudEnumScanStatus
	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM cloud_enum_scans WHERE scan_id = $1`
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
			log.Printf("[CLOUD-ENUM] [ERROR] Cloud Enum scan not found for scan ID: %s", scanID)
			http.Error(w, "Scan not found", http.StatusNotFound)
		} else {
			log.Printf("[CLOUD-ENUM] [ERROR] Failed to get Cloud Enum scan status for scan ID %s: %v", scanID, err)
			http.Error(w, "Failed to get scan status", http.StatusInternalServerError)
		}
		return
	}

	log.Printf("[CLOUD-ENUM] [INFO] Successfully retrieved Cloud Enum scan status for scan ID %s: %s", scanID, scan.Status)
	if scan.Result.Valid {
		log.Printf("[CLOUD-ENUM] [DEBUG] Scan has valid results of length: %d bytes", len(scan.Result.String))
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
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to encode Cloud Enum scan response: %v", err)
	} else {
		log.Printf("[CLOUD-ENUM] [INFO] Successfully sent Cloud Enum scan status response")
	}
}

func GetCloudEnumScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	if scopeTargetID == "" {
		log.Printf("[CLOUD-ENUM] [ERROR] No scope target ID provided")
		http.Error(w, "No scope target ID provided", http.StatusBadRequest)
		return
	}

	createTableQuery := `
		CREATE TABLE IF NOT EXISTS cloud_enum_scans (
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
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to create cloud_enum_scans table: %v", err)
		http.Error(w, "Failed to create scan table.", http.StatusInternalServerError)
		return
	}

	query := `SELECT id, scan_id, company_name, status, result, error, stdout, stderr, command, execution_time, created_at, scope_target_id, auto_scan_session_id FROM cloud_enum_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to get scans: %v", err)
		http.Error(w, "Failed to get scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scan CloudEnumScanStatus
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
			log.Printf("[CLOUD-ENUM] [ERROR] Error scanning Cloud Enum scan row: %v", err)
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

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(scans); err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to encode scans response: %v", err)
	}
}

// loadCloudEnumConfig loads the configuration for a given scope target
func loadCloudEnumConfig(scopeTargetID string) CloudEnumConfig {
	var config CloudEnumConfig

	// Set defaults
	config.Keywords = []string{}
	config.Threads = 5
	config.EnabledPlatforms = map[string]interface{}{
		"aws":   true,
		"azure": true,
		"gcp":   true,
	}
	config.CustomDNSServer = ""
	config.DNSResolverMode = "multiple"
	config.ResolverConfig = "default"
	config.AdditionalResolvers = ""
	config.MutationsFilePath = ""
	config.BruteFilePath = ""
	config.ResolverFilePath = ""
	config.SelectedServices = map[string][]string{
		"aws":   {"s3"},
		"azure": {"storage-accounts"},
		"gcp":   {"gcp-buckets"},
	}
	config.SelectedRegions = map[string][]string{
		"aws":   {"us-east-1"},
		"azure": {"eastus"},
		"gcp":   {"us-central1"},
	}

	var platformsJSON []byte
	var servicesJSON []byte
	var regionsJSON []byte
	err := dbPool.QueryRow(context.Background(), `
		SELECT keywords, threads, enabled_platforms, custom_dns_server, 
		       dns_resolver_mode, resolver_config, additional_resolvers,
		       mutations_file_path, brute_file_path, resolver_file_path,
		       selected_services, selected_regions
		FROM cloud_enum_configs 
		WHERE scope_target_id = $1 
		ORDER BY updated_at DESC 
		LIMIT 1
	`, scopeTargetID).Scan(
		&config.Keywords,
		&config.Threads,
		&platformsJSON,
		&config.CustomDNSServer,
		&config.DNSResolverMode,
		&config.ResolverConfig,
		&config.AdditionalResolvers,
		&config.MutationsFilePath,
		&config.BruteFilePath,
		&config.ResolverFilePath,
		&servicesJSON,
		&regionsJSON,
	)

	if err != nil && err != sql.ErrNoRows {
		log.Printf("[CLOUD-ENUM-CONFIG] [ERROR] Error loading config: %v", err)
		return config // Return defaults
	}

	if err != sql.ErrNoRows {
		// Parse JSON fields
		json.Unmarshal(platformsJSON, &config.EnabledPlatforms)
		json.Unmarshal(servicesJSON, &config.SelectedServices)
		json.Unmarshal(regionsJSON, &config.SelectedRegions)
	}

	return config
}

// copyResolverFile copies a custom resolver file to the container
func copyResolverFile(containerName, sourcePath, scanID string) {
	destPath := fmt.Sprintf("/tmp/custom_resolvers_%s.txt", scanID)

	// Copy file to container
	copyCmd := exec.Command("docker", "cp", sourcePath, fmt.Sprintf("%s:%s", containerName, destPath))
	if err := copyCmd.Run(); err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to copy resolver file to container: %v", err)
	} else {
		log.Printf("[CLOUD-ENUM] [INFO] Copied resolver file to container: %s", destPath)
	}
}

// createHybridResolverFile creates a hybrid resolver file combining defaults with additional resolvers
func createHybridResolverFile(containerName, additionalResolvers, scanID string) {
	destPath := fmt.Sprintf("/tmp/hybrid_resolvers_%s.txt", scanID)

	// Create command to combine default resolvers with additional ones
	createScript := fmt.Sprintf(`
		# Copy default resolvers
		cp /app/resolvers.txt %s
		
		# Add additional resolvers
		cat << 'EOF' >> %s
%s
EOF
	`, destPath, destPath, additionalResolvers)

	// Execute script in container
	cmd := exec.Command("docker", "exec", containerName, "sh", "-c", createScript)
	if err := cmd.Run(); err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to create hybrid resolver file: %v", err)
	} else {
		log.Printf("[CLOUD-ENUM] [INFO] Created hybrid resolver file: %s", destPath)
	}
}

// copyMutationFile copies a custom mutation file to the container
func copyMutationFile(containerName, sourcePath, scanID string) {
	destPath := fmt.Sprintf("/tmp/custom_mutations_%s.txt", scanID)

	copyCmd := exec.Command("docker", "cp", sourcePath, fmt.Sprintf("%s:%s", containerName, destPath))
	if err := copyCmd.Run(); err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to copy mutation file to container: %v", err)
	} else {
		log.Printf("[CLOUD-ENUM] [INFO] Copied mutation file to container: %s", destPath)
	}
}

// copyBruteFile copies a custom brute force file to the container
func copyBruteFile(containerName, sourcePath, scanID string) {
	destPath := fmt.Sprintf("/tmp/custom_brute_%s.txt", scanID)

	copyCmd := exec.Command("docker", "cp", sourcePath, fmt.Sprintf("%s:%s", containerName, destPath))
	if err := copyCmd.Run(); err != nil {
		log.Printf("[CLOUD-ENUM] [ERROR] Failed to copy brute file to container: %v", err)
	} else {
		log.Printf("[CLOUD-ENUM] [INFO] Copied brute file to container: %s", destPath)
	}
}
