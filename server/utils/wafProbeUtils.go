package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// WAF Probe actively profiles a URL target (WAF presence/vendor, rate limiting, block signature)
// and produces a recommended FFUF configuration. It mirrors the FFUF URL scan flow
// (urlScanUtils.go: RunFFUFURLScan / ExecuteAndParseFFUFURLScan) and drives the shared
// `waf-probe` container via `docker exec`, same as ffuf.

const wafProbeContainer = "ars0n-framework-v2-waf-probe-1"

// RunWAFProbeScan handles POST /waf-probe/run — creates a pending scan row and kicks off the probe.
func RunWAFProbeScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL           string `json:"url"`
		ScopeTargetID string `json:"scope_target_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" || payload.ScopeTargetID == "" {
		http.Error(w, "Invalid request body. `url` and `scope_target_id` are required.", http.StatusBadRequest)
		return
	}

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1 AND id = $2`
	var foundID string
	if err := dbPool.QueryRow(context.Background(), query, payload.URL, payload.ScopeTargetID).Scan(&foundID); err != nil {
		log.Printf("[WAF-PROBE] No matching URL scope target for %s (id %s)", payload.URL, payload.ScopeTargetID)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	scanID := uuid.New().String()
	insertQuery := `INSERT INTO waf_probe_scans (scan_id, url, status, scope_target_id) VALUES ($1, $2, $3, $4)`
	if _, err := dbPool.Exec(context.Background(), insertQuery, scanID, payload.URL, "pending", payload.ScopeTargetID); err != nil {
		log.Printf("[WAF-PROBE] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseWAFProbeScan(scanID, payload.URL, payload.ScopeTargetID)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// ExecuteAndParseWAFProbeScan runs the probe in the waf-probe container and stores the JSON result.
func ExecuteAndParseWAFProbeScan(scanID, targetURL, scopeTargetID string) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[WAF-PROBE] panic in scan %s: %v", scanID, rec)
			UpdateWAFProbeScanStatus(scanID, "error", "", fmt.Sprintf("panic: %v", rec), "", "", "", "")
		}
	}()

	log.Printf("[WAF-PROBE] Starting WAF probe for %s (scan ID: %s)", targetURL, scanID)
	startTime := time.Now()
	UpdateWAFProbeScanStatus(scanID, "running", "", "", "", "", "", "")

	// Reuse the target's saved FFUF headers/cookies so authenticated targets are probed the same
	// way FFUF will fuzz them (otherwise we'd fingerprint the login/WAF wall, not the app).
	headerArgs, cookie := loadFFUFAuthForProbe(scopeTargetID)

	args := []string{"exec", wafProbeContainer, "python", "/app/waf_probe.py", targetURL,
		"--intensity", "moderate", "--json"}
	args = append(args, headerArgs...)
	if cookie != "" {
		args = append(args, "--cookie", cookie)
	}

	cmd := exec.Command("docker", args...)
	cmdStr := "docker " + strings.Join(args, " ")
	log.Printf("[WAF-PROBE] Executing: %s", cmdStr)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	execTime := time.Since(startTime).String()
	out := stdout.String()
	errOut := stderr.String()

	if err != nil {
		log.Printf("[WAF-PROBE] Probe failed for %s: %v", targetURL, err)
		UpdateWAFProbeScanStatus(scanID, "error", "", "WAF probe failed: "+errOut, out, errOut, cmdStr, execTime)
		return
	}

	// The script prints a single JSON document to stdout; validate before storing.
	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); jsonErr != nil {
		log.Printf("[WAF-PROBE] Failed to parse probe output for %s: %v", targetURL, jsonErr)
		UpdateWAFProbeScanStatus(scanID, "error", "", "Failed to parse probe output: "+jsonErr.Error(), out, errOut, cmdStr, execTime)
		return
	}

	log.Printf("[WAF-PROBE] Probe completed in %s for %s", execTime, targetURL)
	UpdateWAFProbeScanStatus(scanID, "success", strings.TrimSpace(out), "", out, errOut, cmdStr, execTime)
}

// loadFFUFAuthForProbe pulls headers/cookies out of the target's saved FFUF config (if any) and
// returns them as waf_probe.py CLI args. Best-effort: missing/invalid config yields no args.
func loadFFUFAuthForProbe(scopeTargetID string) ([]string, string) {
	var configJSON []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM ffuf_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&configJSON); err != nil {
		return nil, ""
	}
	var cfg struct {
		Headers []map[string]string `json:"headers"`
		Cookies string              `json:"cookies"`
	}
	if err := json.Unmarshal(configJSON, &cfg); err != nil {
		return nil, ""
	}
	var args []string
	for _, h := range cfg.Headers {
		name, value := h["name"], h["value"]
		if name != "" {
			args = append(args, "--header", fmt.Sprintf("%s: %s", name, value))
		}
	}
	return args, cfg.Cookies
}

// UpdateWAFProbeScanStatus updates a scan row.
func UpdateWAFProbeScanStatus(scanID, status, result, errorMsg, stdout, stderr, command, execTime string) {
	query := `UPDATE waf_probe_scans SET status = $1, result = $2, error = $3, stdout = $4, stderr = $5, command = $6, execution_time = $7 WHERE scan_id = $8`
	if _, err := dbPool.Exec(context.Background(), query, status, result, errorMsg, stdout, stderr, command, execTime, scanID); err != nil {
		log.Printf("[WAF-PROBE] Failed to update scan status: %v", err)
	}
}

// GetWAFProbeScanStatus handles GET /waf-probe/status/{scan_id}.
func GetWAFProbeScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at FROM waf_probe_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
	}
	if err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result,
		&scan.Error, &scan.Command, &scan.ExecutionTime, &scan.CreatedAt); err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

// GetWAFProbeScansForScopeTarget handles GET /scopetarget/{id}/scans/waf-probe.
func GetWAFProbeScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at
	          FROM waf_probe_scans WHERE scope_target_id = $1 ORDER BY created_at DESC`
	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to fetch scans", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	scans := make([]map[string]interface{}, 0)
	for rows.Next() {
		var (
			scanID        string
			url           string
			status        string
			result        *string
			scanErr       *string
			command       *string
			execTime      *string
			createdAt     time.Time
		)
		if err := rows.Scan(&scanID, &url, &status, &result, &scanErr, &command, &execTime, &createdAt); err != nil {
			continue
		}
		scans = append(scans, map[string]interface{}{
			"scan_id":        scanID,
			"url":            url,
			"status":         status,
			"result":         result,
			"error":          scanErr,
			"command":        command,
			"execution_time": execTime,
			"created_at":     createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

// ApplyWAFProbeRecommendations handles POST /waf-probe/apply/{scope_target_id} — merges the latest
// probe's recommended fields into the target's ffuf_configs (never clobbering unrelated fields).
func ApplyWAFProbeRecommendations(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	// Latest successful probe result.
	var resultJSON *string
	err := dbPool.QueryRow(context.Background(),
		`SELECT result FROM waf_probe_scans WHERE scope_target_id = $1 AND status = 'success' AND result IS NOT NULL ORDER BY created_at DESC LIMIT 1`,
		scopeTargetID).Scan(&resultJSON)
	if err != nil || resultJSON == nil {
		http.Error(w, "No completed WAF probe found for this target", http.StatusNotFound)
		return
	}

	var probe struct {
		Recommendations map[string]interface{} `json:"recommendations"`
	}
	if err := json.Unmarshal([]byte(*resultJSON), &probe); err != nil || len(probe.Recommendations) == 0 {
		http.Error(w, "Probe has no recommendations to apply", http.StatusBadRequest)
		return
	}

	// Existing config (or empty) as a generic map so we merge instead of overwrite.
	config := map[string]interface{}{}
	var existingJSON []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM ffuf_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&existingJSON); err == nil {
		_ = json.Unmarshal(existingJSON, &config)
	}

	mergeFFUFRecommendations(config, probe.Recommendations)

	mergedJSON, err := json.Marshal(config)
	if err != nil {
		http.Error(w, "Failed to encode merged config", http.StatusInternalServerError)
		return
	}

	upsert := `
		INSERT INTO ffuf_configs (scope_target_id, config)
		VALUES ($1, $2)
		ON CONFLICT (scope_target_id)
		DO UPDATE SET config = $2, updated_at = NOW()`
	if _, err := dbPool.Exec(context.Background(), upsert, scopeTargetID, mergedJSON); err != nil {
		http.Error(w, "Failed to save merged config", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "config": config})
}

// mergeFFUFRecommendations overlays recommended fields onto an existing config map. Scalar fields
// overwrite; `headers` is merged by header name so a recommended User-Agent adds to (not replaces)
// the user's existing headers.
func mergeFFUFRecommendations(config, rec map[string]interface{}) {
	for key, val := range rec {
		if key == "headers" {
			config["headers"] = mergeHeaderLists(config["headers"], val)
			continue
		}
		config[key] = val
	}
}

func mergeHeaderLists(existing, recommended interface{}) []interface{} {
	byName := map[string]interface{}{}
	order := []string{}
	add := func(list interface{}) {
		items, ok := list.([]interface{})
		if !ok {
			return
		}
		for _, it := range items {
			h, ok := it.(map[string]interface{})
			if !ok {
				continue
			}
			name, _ := h["name"].(string)
			if _, seen := byName[name]; !seen {
				order = append(order, name)
			}
			byName[name] = h // recommended (applied second) wins on conflict
		}
	}
	add(existing)
	add(recommended)
	merged := make([]interface{}, 0, len(order))
	for _, name := range order {
		merged = append(merged, byName[name])
	}
	return merged
}
