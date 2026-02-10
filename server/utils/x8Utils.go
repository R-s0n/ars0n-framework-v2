package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type X8Config struct {
	Method           string              `json:"method"`
	Headers          []map[string]string `json:"headers"`
	BodyType         string              `json:"bodyType"`
	Wordlist         string              `json:"wordlist"`
	MaxDepth         int                 `json:"maxDepth"`
	Concurrency      int                 `json:"concurrency"`
	Delay            int                 `json:"delay"`
	LearnRequests    int                 `json:"learnRequests"`
	VerifyRequests   int                 `json:"verifyRequests"`
	CheckReflection  bool                `json:"checkReflection"`
	DisableColors    bool                `json:"disableColors"`
	FollowRedirects  bool                `json:"followRedirects"`
	CheckBooleans    bool                `json:"checkBooleans"`
	ValueSize        int                 `json:"valueSize"`
}

func SaveX8Config(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var config X8Config
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	configJSON, err := json.Marshal(config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	query := `
		INSERT INTO x8_configs (scope_target_id, config)
		VALUES ($1, $2)
		ON CONFLICT (scope_target_id)
		DO UPDATE SET config = $2, updated_at = NOW()
	`

	_, err = dbPool.Exec(context.Background(), query, scopeTargetID, configJSON)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func GetX8Config(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var configJSON []byte
	query := `SELECT config FROM x8_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&configJSON)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
		return
	}

	var config X8Config
	if err := json.Unmarshal(configJSON, &config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func RunX8Scan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID string `json:"scope_target_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()

	insertQuery := `
		INSERT INTO x8_scans (scan_id, scope_target_id, status, total_endpoints, processed_endpoints, parameters_found)
		VALUES ($1, $2, 'pending', 0, 0, 0)
	`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, req.ScopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go ExecuteX8Scan(scanID, req.ScopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"status":  "pending",
	})
}

func ExecuteX8Scan(scanID, scopeTargetID string) {
	startTime := time.Now()

	UpdateX8ScanStatus(scanID, "running", "", "")

	var configJSON []byte
	configQuery := `SELECT config FROM x8_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), configQuery, scopeTargetID).Scan(&configJSON)

	var config X8Config
	if err == nil {
		json.Unmarshal(configJSON, &config)
	} else {
		config = X8Config{
			Method:          "GET",
			BodyType:        "json",
			Concurrency:     10,
			LearnRequests:   9,
			VerifyRequests:  3,
			CheckReflection: true,
			ValueSize:       5,
		}
	}

	endpointsQuery := `
		SELECT DISTINCT url 
		FROM consolidated_url_endpoints 
		WHERE scope_target_id = $1 AND is_direct = true
		ORDER BY url
		LIMIT 100
	`
	rows, err := dbPool.Query(context.Background(), endpointsQuery, scopeTargetID)
	if err != nil {
		UpdateX8ScanStatus(scanID, "error", "", fmt.Sprintf("Failed to fetch endpoints: %v", err))
		return
	}
	defer rows.Close()

	var endpoints []string
	for rows.Next() {
		var url string
		if err := rows.Scan(&url); err != nil {
			continue
		}
		endpoints = append(endpoints, url)
	}

	if len(endpoints) == 0 {
		UpdateX8ScanStatus(scanID, "error", "", "No consolidated endpoints found")
		return
	}

	updateTotalQuery := `UPDATE x8_scans SET total_endpoints = $1 WHERE scan_id = $2`
	dbPool.Exec(context.Background(), updateTotalQuery, len(endpoints), scanID)

	urlsFile := fmt.Sprintf("/tmp/x8_urls_%s.txt", scanID)
	urlsContent := strings.Join(endpoints, "\n")
	if err := os.WriteFile(urlsFile, []byte(urlsContent), 0644); err != nil {
		UpdateX8ScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create URLs file: %v", err))
		return
	}
	defer os.Remove(urlsFile)

	outputFile := fmt.Sprintf("/tmp/x8_output_%s.txt", scanID)
	defer os.Remove(outputFile)

	args := []string{
		"-u", urlsFile,
		"-o", outputFile,
		"--workers", fmt.Sprintf("%d", config.Concurrency),
		"--learn-requests-count", fmt.Sprintf("%d", config.LearnRequests),
		"--verify-requests-count", fmt.Sprintf("%d", config.VerifyRequests),
		"--value-size", fmt.Sprintf("%d", config.ValueSize),
	}

	if config.Method != "" && config.Method != "GET" {
		args = append(args, "--method", config.Method)
	}

	if config.BodyType != "" {
		args = append(args, "--body-type", config.BodyType)
	}

	if config.MaxDepth > 0 {
		args = append(args, "--max-depth", fmt.Sprintf("%d", config.MaxDepth))
	}

	if config.Delay > 0 {
		args = append(args, "--delay", fmt.Sprintf("%d", config.Delay))
	}

	if config.Wordlist != "" {
		args = append(args, "--wordlist", config.Wordlist)
	}

	if config.CheckReflection {
		args = append(args, "--reflected-only")
	}

	if config.FollowRedirects {
		args = append(args, "--follow-redirects")
	}

	if config.CheckBooleans {
		args = append(args, "--check-binary")
	}

	if config.DisableColors {
		args = append(args, "--disable-colors")
	}

	if len(config.Headers) > 0 {
		for _, header := range config.Headers {
			for key, value := range header {
				args = append(args, "--headers", fmt.Sprintf("%s: %s", key, value))
			}
		}
	}

	cmdStr := fmt.Sprintf("docker exec ars0n-framework-v2-x8-1 x8 %s", strings.Join(args, " "))

	cmd := exec.Command("docker", append([]string{"exec", "ars0n-framework-v2-x8-1", "x8"}, args...)...)
	output, err := cmd.CombinedOutput()

	executionTime := time.Since(startTime).String()

	parametersFound := 0
	if _, err := os.Stat(outputFile); err == nil {
		outputData, _ := os.ReadFile(outputFile)
		if len(outputData) > 0 {
			lines := strings.Split(string(outputData), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "parameter") || strings.Contains(line, "[+]") {
					parts := strings.Fields(line)
					for i, part := range parts {
						if (strings.Contains(part, "param") || strings.Contains(part, "parameter")) && i+1 < len(parts) {
							paramName := parts[i+1]
							paramName = strings.Trim(paramName, "[]():,")
							
							if len(paramName) > 0 && paramName != "parameter" && paramName != "found" {
								var endpointURL string
								for j := i - 1; j >= 0; j-- {
									if strings.HasPrefix(parts[j], "http") {
										endpointURL = parts[j]
										break
									}
								}
								if endpointURL == "" && len(endpoints) > 0 {
									endpointURL = endpoints[0]
								}

								insertParamQuery := `
									INSERT INTO parameter_enumeration_results 
									(scan_id, scan_type, scope_target_id, endpoint_url, parameter_name, parameter_type, confidence)
									VALUES ($1, 'x8', $2, $3, $4, 'query', 'high')
								`
								dbPool.Exec(context.Background(), insertParamQuery, scanID, scopeTargetID, endpointURL, paramName)
								parametersFound++
							}
						}
					}
				}
			}
		}
	}

	if err != nil {
		UpdateX8ScanStatus(scanID, "error", string(output), fmt.Sprintf("x8 execution failed: %v", err))
		return
	}

	updateQuery := `
		UPDATE x8_scans 
		SET status = 'success', processed_endpoints = $1, parameters_found = $2, 
		    execution_time = $3, command = $4, stdout = $5
		WHERE scan_id = $6
	`
	dbPool.Exec(context.Background(), updateQuery, len(endpoints), parametersFound, executionTime, cmdStr, string(output), scanID)
}

func UpdateX8ScanStatus(scanID, status, stdout, errorMsg string) {
	query := `UPDATE x8_scans SET status = $1, stdout = $2, error = $3 WHERE scan_id = $4`
	dbPool.Exec(context.Background(), query, status, stdout, errorMsg, scanID)
}

func GetX8ScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var status, result, errorMsg, stdout, stderr, command, executionTime string
	var totalEndpoints, processedEndpoints, parametersFound int
	var createdAt time.Time

	query := `
		SELECT status, COALESCE(result, ''), COALESCE(error, ''), COALESCE(stdout, ''), 
		       COALESCE(stderr, ''), COALESCE(command, ''), COALESCE(execution_time, ''),
		       total_endpoints, processed_endpoints, parameters_found, created_at
		FROM x8_scans WHERE scan_id = $1
	`
	err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&status, &result, &errorMsg, &stdout, &stderr, &command, &executionTime,
		&totalEndpoints, &processedEndpoints, &parametersFound, &createdAt,
	)

	if err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id":              scanID,
		"status":               status,
		"result":               result,
		"error":                errorMsg,
		"stdout":               stdout,
		"stderr":               stderr,
		"command":              command,
		"execution_time":       executionTime,
		"total_endpoints":      totalEndpoints,
		"processed_endpoints":  processedEndpoints,
		"parameters_found":     parametersFound,
		"created_at":           createdAt,
	})
}

func GetX8ScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `
		SELECT scan_id, status, COALESCE(execution_time, ''), total_endpoints, 
		       processed_endpoints, parameters_found, created_at
		FROM x8_scans 
		WHERE scope_target_id = $1
		ORDER BY created_at DESC
	`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var scans []map[string]interface{}
	for rows.Next() {
		var scanID, status, executionTime string
		var totalEndpoints, processedEndpoints, parametersFound int
		var createdAt time.Time

		if err := rows.Scan(&scanID, &status, &executionTime, &totalEndpoints, &processedEndpoints, &parametersFound, &createdAt); err != nil {
			continue
		}

		scans = append(scans, map[string]interface{}{
			"scan_id":             scanID,
			"status":              status,
			"execution_time":      executionTime,
			"total_endpoints":     totalEndpoints,
			"processed_endpoints": processedEndpoints,
			"parameters_found":    parametersFound,
			"created_at":          createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func GetX8ScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `
		SELECT endpoint_url, parameter_name, parameter_type, 
		       COALESCE(example_value, ''), COALESCE(confidence, ''), created_at
		FROM parameter_enumeration_results
		WHERE scan_id = $1 AND scan_type = 'x8'
		ORDER BY endpoint_url, parameter_name
	`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var endpointURL, paramName, paramType, exampleValue, confidence string
		var createdAt time.Time

		if err := rows.Scan(&endpointURL, &paramName, &paramType, &exampleValue, &confidence, &createdAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"endpoint_url":    endpointURL,
			"parameter_name":  paramName,
			"parameter_type":  paramType,
			"example_value":   exampleValue,
			"confidence":      confidence,
			"created_at":      createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
