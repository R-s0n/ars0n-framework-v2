package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type ParamethConfig struct {
	Method        string              `json:"method"`
	Headers       []map[string]string `json:"headers"`
	Threads       int                 `json:"threads"`
	Verbose       bool                `json:"verbose"`
	Diff          int                 `json:"diff"`
	Placeholder   string              `json:"placeholder"`
	Wordlist      string              `json:"wordlist"`
	IgnoreCodes   string              `json:"ignoreCodes"`
	IgnoreSizes   string              `json:"ignoreSizes"`
}

func SaveParamethConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var config ParamethConfig
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
		INSERT INTO parameth_configs (scope_target_id, config)
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

func GetParamethConfig(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var configJSON []byte
	query := `SELECT config FROM parameth_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&configJSON)

	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{})
		return
	}

	var config ParamethConfig
	if err := json.Unmarshal(configJSON, &config); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func RunParamethScan(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ScopeTargetID string `json:"scope_target_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()

	insertQuery := `
		INSERT INTO parameth_scans (scan_id, scope_target_id, status, total_endpoints, processed_endpoints, parameters_found)
		VALUES ($1, $2, 'pending', 0, 0, 0)
	`
	_, err := dbPool.Exec(context.Background(), insertQuery, scanID, req.ScopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	go ExecuteParamethScan(scanID, req.ScopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"scan_id": scanID,
		"status":  "pending",
	})
}

func ExecuteParamethScan(scanID, scopeTargetID string) {
	startTime := time.Now()

	UpdateParamethScanStatus(scanID, "running", "", "")

	var configJSON []byte
	configQuery := `SELECT config FROM parameth_configs WHERE scope_target_id = $1`
	err := dbPool.QueryRow(context.Background(), configQuery, scopeTargetID).Scan(&configJSON)

	var config ParamethConfig
	if err == nil {
		json.Unmarshal(configJSON, &config)
	} else {
		config = ParamethConfig{
			Method:      "GET",
			Threads:     5,
			Diff:        5,
			Placeholder: "test",
		}
	}

	endpointsQuery := `
		SELECT DISTINCT url 
		FROM consolidated_url_endpoints 
		WHERE scope_target_id = $1 AND is_direct = true
		ORDER BY url
		LIMIT 50
	`
	rows, err := dbPool.Query(context.Background(), endpointsQuery, scopeTargetID)
	if err != nil {
		UpdateParamethScanStatus(scanID, "error", "", fmt.Sprintf("Failed to fetch endpoints: %v", err))
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
		UpdateParamethScanStatus(scanID, "error", "", "No consolidated endpoints found")
		return
	}

	updateTotalQuery := `UPDATE parameth_scans SET total_endpoints = $1 WHERE scan_id = $2`
	dbPool.Exec(context.Background(), updateTotalQuery, len(endpoints), scanID)

	var allOutput strings.Builder
	parametersFound := 0
	processedEndpoints := 0

	for _, endpoint := range endpoints {
		args := []string{
			"-u", endpoint,
			"-t", fmt.Sprintf("%d", config.Threads),
		}

		if config.Method != "" && config.Method != "GET" {
			args = append(args, "-m", config.Method)
		}

		if config.Diff > 0 {
			args = append(args, "--diff", fmt.Sprintf("%d", config.Diff))
		}

		if config.Placeholder != "" {
			args = append(args, "--placeholder", config.Placeholder)
		}

		if config.Wordlist != "" {
			args = append(args, "-w", config.Wordlist)
		}

		if config.IgnoreCodes != "" {
			args = append(args, "--ignore-codes", config.IgnoreCodes)
		}

		if len(config.Headers) > 0 {
			for _, header := range config.Headers {
				for key, value := range header {
					args = append(args, "-H", fmt.Sprintf("%s: %s", key, value))
				}
			}
		}

		cmd := exec.Command("docker", append([]string{"exec", "ars0n-framework-v2-parameth-1", "python3", "parameth.py"}, args...)...)
		output, err := cmd.CombinedOutput()

		allOutput.WriteString(string(output))
		allOutput.WriteString("\n")

		if err == nil {
			outputLines := strings.Split(string(output), "\n")
			for _, line := range outputLines {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "Found parameter:") || strings.Contains(line, "[+]") {
					parts := strings.Fields(line)
					for _, part := range parts {
						if !strings.HasPrefix(part, "[") && !strings.HasPrefix(part, "Found") && !strings.HasPrefix(part, "parameter:") && len(part) > 0 {
							insertParamQuery := `
								INSERT INTO parameter_enumeration_results 
								(scan_id, scan_type, scope_target_id, endpoint_url, parameter_name, parameter_type, confidence)
								VALUES ($1, 'parameth', $2, $3, $4, 'query', 'medium')
							`
							dbPool.Exec(context.Background(), insertParamQuery, scanID, scopeTargetID, endpoint, part)
							parametersFound++
							break
						}
					}
				}
			}
		}

		processedEndpoints++
		updateProgressQuery := `UPDATE parameth_scans SET processed_endpoints = $1, parameters_found = $2 WHERE scan_id = $3`
		dbPool.Exec(context.Background(), updateProgressQuery, processedEndpoints, parametersFound, scanID)
	}

	executionTime := time.Since(startTime).String()

	updateQuery := `
		UPDATE parameth_scans 
		SET status = 'success', processed_endpoints = $1, parameters_found = $2, 
		    execution_time = $3, stdout = $4
		WHERE scan_id = $5
	`
	dbPool.Exec(context.Background(), updateQuery, processedEndpoints, parametersFound, executionTime, allOutput.String(), scanID)
}

func UpdateParamethScanStatus(scanID, status, stdout, errorMsg string) {
	query := `UPDATE parameth_scans SET status = $1, stdout = $2, error = $3 WHERE scan_id = $4`
	dbPool.Exec(context.Background(), query, status, stdout, errorMsg, scanID)
}

func GetParamethScanStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	var status, result, errorMsg, stdout, stderr, command, executionTime string
	var totalEndpoints, processedEndpoints, parametersFound int
	var createdAt time.Time

	query := `
		SELECT status, COALESCE(result, ''), COALESCE(error, ''), COALESCE(stdout, ''), 
		       COALESCE(stderr, ''), COALESCE(command, ''), COALESCE(execution_time, ''),
		       total_endpoints, processed_endpoints, parameters_found, created_at
		FROM parameth_scans WHERE scan_id = $1
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

func GetParamethScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["id"]

	query := `
		SELECT scan_id, status, COALESCE(execution_time, ''), total_endpoints, 
		       processed_endpoints, parameters_found, created_at
		FROM parameth_scans 
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

func GetParamethScanResults(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["scan_id"]

	query := `
		SELECT endpoint_url, parameter_name, parameter_type, 
		       COALESCE(example_value, ''), COALESCE(confidence, ''), created_at
		FROM parameter_enumeration_results
		WHERE scan_id = $1 AND scan_type = 'parameth'
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
