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

type ArjunConfig struct {
	Method          string              `json:"method"`
	Headers         []map[string]string `json:"headers"`
	Threads         int                 `json:"threads"`
	Delay           int                 `json:"delay"`
	Timeout         int                 `json:"timeout"`
	ChunkSize       int                 `json:"chunkSize"`
	Wordlist        string              `json:"wordlist"`
	PassiveMode     bool                `json:"passiveMode"`
	StableDetection bool                `json:"stableDetection"`
	JSONOutput      bool                `json:"jsonOutput"`
	IncludeParams   string              `json:"includeParams"`
	ExcludeParams   string              `json:"excludeParams"`
}

func SaveArjunConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var config ArjunConfig
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
		INSERT INTO arjun_configs (scope_target_id, config)
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

func GetArjunConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var configJSON []byte
	query := `SELECT config FROM arjun_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&configJSON)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
		return
	}

	var config ArjunConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func RunArjunScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID string `json:"scope_target_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()

	insertQuery := `
		INSERT INTO arjun_scans (scan_id, scope_target_id, status, total_endpoints, processed_endpoints, parameters_found)
		VALUES ($1, $2, 'pending', 0, 0, 0)
	`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, req.ScopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go ExecuteArjunScan(scanID, req.ScopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"status":  "pending",
	})
}

func ExecuteArjunScan(scanID, scopeTargetID string) {
	startTime := time.Now()

	UpdateArjunScanStatus(scanID, "running", "", "")

	var configJSON []byte
	configQuery := `SELECT config FROM arjun_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), configQuery, scopeTargetID).Scan(&configJSON)

	var config ArjunConfig
	if err == nil {
		json.Unmarshal(configJSON, &config)
	} else {
		config = ArjunConfig{
			Method:      "GET",
			Threads:     5,
			Timeout:     10,
			ChunkSize:   500,
			JSONOutput:  true,
		}
	}

	endpointsQuery := `
		SELECT DISTINCT url 
		FROM consolidated_url_endpoints 
		WHERE scope_target_id = $1 AND is_direct = true
		ORDER BY url
	`
	rows, err := dbPool.Query(context.Background(), endpointsQuery, scopeTargetID)
	if err != nil {
		UpdateArjunScanStatus(scanID, "error", "", fmt.Sprintf("Failed to fetch endpoints: %v", err))
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
		UpdateArjunScanStatus(scanID, "error", "", "No consolidated endpoints found")
		return
	}

	updateTotalQuery := `UPDATE arjun_scans SET total_endpoints = $1 WHERE scan_id = $2`
	dbPool.Exec(context.Background(), updateTotalQuery, len(endpoints), scanID)

	urlsFile := fmt.Sprintf("/tmp/arjun_urls_%s.txt", scanID)
	urlsContent := strings.Join(endpoints, "\n")
	if err := os.WriteFile(urlsFile, []byte(urlsContent), 0644); err != nil {
		UpdateArjunScanStatus(scanID, "error", "", fmt.Sprintf("Failed to create URLs file: %v", err))
		return
	}
	defer os.Remove(urlsFile)

	outputFile := fmt.Sprintf("/tmp/arjun_output_%s.json", scanID)
	defer os.Remove(outputFile)

	args := []string{
		"-i", urlsFile,
		"-o", outputFile,
		"-t", fmt.Sprintf("%d", config.Threads),
		"--stable",
	}

	if config.Method != "" && config.Method != "GET" {
		args = append(args, "-m", config.Method)
	}

	if config.Delay > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", config.Delay))
	}

	if config.Timeout > 0 {
		args = append(args, "--timeout", fmt.Sprintf("%d", config.Timeout))
	}

	if config.ChunkSize > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", config.ChunkSize))
	}

	if config.Wordlist != "" {
		args = append(args, "-w", config.Wordlist)
	}

	if config.PassiveMode {
		args = append(args, "--passive")
	}

	if len(config.Headers) > 0 {
		for _, header := range config.Headers {
			for key, value := range header {
				args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
			}
		}
	}

	cmdStr := fmt.Sprintf("docker exec ars0n-framework-v2-arjun-1 arjun %s", strings.Join(args, " "))

	cmd := exec.Command("docker", append([]string{"exec", "ars0n-framework-v2-arjun-1", "arjun"}, args...)...)
	output, err := cmd.CombinedOutput()

	executionTime := time.Since(startTime).String()

	if err != nil {
		UpdateArjunScanStatus(scanID, "error", string(output), fmt.Sprintf("Arjun execution failed: %v", err))
		return
	}

	parametersFound := 0
	if _, err := os.Stat(outputFile); err == nil {
		outputData, _ := os.ReadFile(outputFile)
		if len(outputData) > 0 {
			var results map[string]interface{}
			if err := json.Unmarshal(outputData, &results); err == nil {
				for url, params := range results {
					if paramList, ok := params.([]interface{}); ok {
						for _, param := range paramList {
							if paramStr, ok := param.(string); ok {
								insertParamQuery := `
									INSERT INTO parameter_enumeration_results 
									(scan_id, scan_type, scope_target_id, endpoint_url, parameter_name, parameter_type, confidence)
									VALUES ($1, 'arjun', $2, $3, $4, 'query', 'high')
								`
								dbPool.Exec(context.Background(), insertParamQuery, scanID, scopeTargetID, url, paramStr)
								parametersFound++
							}
						}
					}
				}
			}
		}
	}

	updateQuery := `
		UPDATE arjun_scans 
		SET status = 'success', processed_endpoints = $1, parameters_found = $2, 
		    execution_time = $3, command = $4, stdout = $5
		WHERE scan_id = $6
	`
	dbPool.Exec(context.Background(), updateQuery, len(endpoints), parametersFound, executionTime, cmdStr, string(output), scanID)
}

func UpdateArjunScanStatus(scanID, status, stdout, errorMsg string) {
	query := `UPDATE arjun_scans SET status = $1, stdout = $2, error = $3 WHERE scan_id = $4`
	dbPool.Exec(context.Background(), query, status, stdout, errorMsg, scanID)
}

func GetArjunScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var status, result, errorMsg, stdout, stderr, command, executionTime string
	var totalEndpoints, processedEndpoints, parametersFound int
	var createdAt time.Time

	query := `
		SELECT status, COALESCE(result, ''), COALESCE(error, ''), COALESCE(stdout, ''), 
		       COALESCE(stderr, ''), COALESCE(command, ''), COALESCE(execution_time, ''),
		       total_endpoints, processed_endpoints, parameters_found, created_at
		FROM arjun_scans WHERE scan_id = $1
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

func GetArjunScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `
		SELECT scan_id, status, COALESCE(execution_time, ''), total_endpoints, 
		       processed_endpoints, parameters_found, created_at
		FROM arjun_scans 
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

func GetArjunScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `
		SELECT endpoint_url, parameter_name, parameter_type, 
		       COALESCE(example_value, ''), COALESCE(confidence, ''), created_at
		FROM parameter_enumeration_results
		WHERE scan_id = $1 AND scan_type = 'arjun'
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
