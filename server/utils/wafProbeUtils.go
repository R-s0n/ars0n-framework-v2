package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Target Behaviour Probe (still routed under /waf-probe for compatibility).
//
// The probe characterises how a target routes requests, handles volume, and behaves in ways that
// corrupt automated scanning. This file is the transport between the API and the probe container.
//
// Three v1 bugs are fixed here, all of which cost the operator real results:
//
//  1. The timeout was hardcoded to 5 minutes and, on expiry, wrote status=error with an EMPTY
//     result, so a long run lost everything it had learned. The timeout is now derived from the
//     config's own deadline, and on expiry the partial checkpoint is recovered and stored.
//  2. Apply used "the latest successful scan" regardless of which scan the operator was looking
//     at, so browsing an older result and clicking Apply silently applied a different one.
//  3. Apply overwrote operator-set fields unconditionally with no record and no way back.

const wafProbeContainer = "ars0n-framework-v2-waf-probe-1"

// Grace on top of the probe's own wall-clock deadline: enough for container startup, wafw00f, and
// the final JSON write. The probe refuses to start if its deadline does not fit inside this.
const probeTimeoutGraceSeconds = 90

type probeConfigEnvelope struct {
	Global struct {
		WallClockSeconds     int `json:"wall_clock_seconds"`
		GoContextTimeoutSecs int `json:"go_context_timeout_seconds"`
		RequestBudget        int `json:"request_budget"`
	} `json:"global"`
}

// RunWAFProbeScan handles POST /waf-probe/run.
func RunWAFProbeScan(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		URL           string          `json:"url"`
		ScopeTargetID string          `json:"scope_target_id"`
		Config        json.RawMessage `json:"config"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.URL == "" || payload.ScopeTargetID == "" {
		http.Error(w, "Invalid request body. `url` and `scope_target_id` are required.", http.StatusBadRequest)
		return
	}

	query := `SELECT id FROM scope_targets WHERE type = 'URL' AND scope_target = $1 AND id = $2`
	var foundID string
	if err := dbPool.QueryRow(context.Background(), query, payload.URL, payload.ScopeTargetID).Scan(&foundID); err != nil {
		log.Printf("[PROBE] No matching URL scope target for %s (id %s)", payload.URL, payload.ScopeTargetID)
		http.Error(w, "No matching URL scope target found.", http.StatusBadRequest)
		return
	}

	cfgJSON, err := resolveProbeConfig(payload.ScopeTargetID, payload.URL, payload.Config)
	if err != nil {
		http.Error(w, "Failed to resolve probe config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	scanID := uuid.New().String()
	insert := `INSERT INTO waf_probe_scans (scan_id, url, status, scope_target_id, config, schema_version)
	           VALUES ($1, $2, $3, $4, $5, 2)`
	if _, err := dbPool.Exec(context.Background(), insert, scanID, payload.URL, "pending",
		payload.ScopeTargetID, cfgJSON); err != nil {
		log.Printf("[PROBE] Failed to create scan record: %v", err)
		http.Error(w, "Failed to create scan record.", http.StatusInternalServerError)
		return
	}

	go ExecuteAndParseWAFProbeScan(scanID, payload.URL, payload.ScopeTargetID, cfgJSON)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"scan_id": scanID})
}

// resolveProbeConfig merges, in order: probe defaults, the target's saved config, an inline
// override from the request, and the target's saved FFUF auth material.
func resolveProbeConfig(scopeTargetID, url string, inline json.RawMessage) ([]byte, error) {
	cfg := map[string]interface{}{}

	var saved []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM waf_probe_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&saved); err == nil {
		_ = json.Unmarshal(saved, &cfg)
	}

	if len(inline) > 0 {
		var override map[string]interface{}
		if err := json.Unmarshal(inline, &override); err == nil {
			mergeMaps(cfg, override)
		}
	}

	target, _ := cfg["target"].(map[string]interface{})
	if target == nil {
		target = map[string]interface{}{}
		cfg["target"] = target
	}
	target["url"] = url

	attachFFUFAuth(scopeTargetID, target)

	return json.Marshal(cfg)
}

// attachFFUFAuth reuses the target's saved FFUF headers and cookies so the probe characterises the
// application the way the scanners will actually see it. The age is passed through so the probe can
// warn that an expired session means it fingerprinted the login wall rather than the app.
func attachFFUFAuth(scopeTargetID string, target map[string]interface{}) {
	auth, _ := target["auth"].(map[string]interface{})
	if auth == nil {
		auth = map[string]interface{}{"source": "ffuf_config"}
		target["auth"] = auth
	}
	if src, _ := auth["source"].(string); src != "ffuf_config" && src != "" {
		return
	}

	var configJSON []byte
	var updatedAt time.Time
	err := dbPool.QueryRow(context.Background(),
		`SELECT config, updated_at FROM ffuf_configs WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&configJSON, &updatedAt)
	if err != nil {
		return
	}

	var cfg struct {
		Headers []map[string]string `json:"headers"`
		Cookies string              `json:"cookies"`
	}
	if json.Unmarshal(configJSON, &cfg) != nil {
		return
	}

	headers := make([]map[string]string, 0, len(cfg.Headers))
	for _, h := range cfg.Headers {
		if h["name"] != "" {
			headers = append(headers, map[string]string{"name": h["name"], "value": h["value"]})
		}
	}
	auth["headers"] = headers
	auth["cookies"] = cfg.Cookies
	auth["age_days"] = int(time.Since(updatedAt).Hours() / 24)
}

func mergeMaps(dst, src map[string]interface{}) {
	for k, v := range src {
		if sub, ok := v.(map[string]interface{}); ok {
			if existing, ok := dst[k].(map[string]interface{}); ok {
				mergeMaps(existing, sub)
				continue
			}
		}
		dst[k] = v
	}
}

// ExecuteAndParseWAFProbeScan drives the probe container and stores the result.
func ExecuteAndParseWAFProbeScan(scanID, targetURL, scopeTargetID string, cfgJSON []byte) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[PROBE] panic in scan %s: %v", scanID, rec)
			UpdateWAFProbeScanStatus(scanID, "error", "", fmt.Sprintf("panic: %v", rec), "", "", "", "")
		}
	}()

	log.Printf("[PROBE] Starting probe for %s (scan %s)", targetURL, scanID)
	start := time.Now()
	UpdateWAFProbeScanStatus(scanID, "running", "", "", "", "", "", "")

	timeout := probeTimeout(cfgJSON)
	checkpoint := fmt.Sprintf("/tmp/%s.partial.json", scanID)

	args := []string{"exec", "-i", wafProbeContainer, "python", "/app/waf_probe.py",
		"--config", "-", "--scan-id", scanID, "--checkpoint", checkpoint}

	// The schema has well over a hundred knobs, so the config goes in on stdin rather than argv.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = bytes.NewReader(cfgJSON)
	cmdStr := "docker " + strings.Join(args, " ") + "  (config on stdin)"
	log.Printf("[PROBE] Executing: %s (timeout %s)", cmdStr, timeout)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	execTime := time.Since(start).String()
	out, errOut := stdout.String(), stderr.String()

	if ctx.Err() == context.DeadlineExceeded {
		// v1 wrote an empty error row here and the operator lost everything. Recover whatever the
		// probe checkpointed and store it as a partial result instead.
		log.Printf("[PROBE] Probe timed out for %s after %s", targetURL, timeout)
		if partial := recoverCheckpoint(checkpoint); partial != "" {
			storeProbeResult(scanID, scopeTargetID, "partial", partial, cmdStr, execTime, out, errOut)
			return
		}
		UpdateWAFProbeScanStatus(scanID, "error", "",
			fmt.Sprintf("Probe timed out after %s and left no recoverable checkpoint", timeout),
			out, errOut, cmdStr, execTime)
		return
	}

	if err != nil && strings.TrimSpace(out) == "" {
		log.Printf("[PROBE] Probe failed for %s: %v", targetURL, err)
		UpdateWAFProbeScanStatus(scanID, "error", "", "Probe failed: "+truncateForLog(errOut),
			out, errOut, cmdStr, execTime)
		return
	}

	var parsed map[string]interface{}
	if jsonErr := json.Unmarshal([]byte(strings.TrimSpace(out)), &parsed); jsonErr != nil {
		log.Printf("[PROBE] Failed to parse probe output for %s: %v", targetURL, jsonErr)
		UpdateWAFProbeScanStatus(scanID, "error", "",
			"Failed to parse probe output: "+jsonErr.Error(), out, errOut, cmdStr, execTime)
		return
	}

	// The probe reports its own terminal state. `partial` and `aborted` are first-class results
	// with real data, not failures, and the UI renders them fully.
	status := "success"
	if run, ok := parsed["run"].(map[string]interface{}); ok {
		switch fmt.Sprintf("%v", run["status"]) {
		case "aborted":
			status = "aborted"
		case "partial":
			status = "partial"
		case "error", "refused":
			status = "error"
		}
	}

	log.Printf("[PROBE] Probe finished in %s for %s (status %s)", execTime, targetURL, status)
	storeProbeResult(scanID, scopeTargetID, status, strings.TrimSpace(out), cmdStr, execTime, out, errOut)
}

func probeTimeout(cfgJSON []byte) time.Duration {
	var env probeConfigEnvelope
	_ = json.Unmarshal(cfgJSON, &env)

	seconds := env.Global.GoContextTimeoutSecs
	if seconds <= 0 {
		seconds = env.Global.WallClockSeconds + probeTimeoutGraceSeconds
	}
	if seconds <= 0 {
		seconds = 420
	}
	return time.Duration(seconds) * time.Second
}

func recoverCheckpoint(path string) string {
	out, err := exec.Command("docker", "exec", wafProbeContainer, "cat", path).Output()
	if err != nil {
		return ""
	}
	var probe map[string]interface{}
	if json.Unmarshal(out, &probe) != nil {
		return ""
	}
	probe["run"] = map[string]interface{}{
		"status": "partial",
		"abort_reason": map[string]interface{}{
			"rule_id": "backend_timeout",
			"detail":  "the backend timeout expired; this is what the probe had learned by then",
		},
	}
	recovered, err := json.Marshal(probe)
	if err != nil {
		return ""
	}
	return string(recovered)
}

func storeProbeResult(scanID, scopeTargetID, status, result, cmdStr, execTime, stdout, stderr string) {
	posture, requests, trips := probeSummary(result)

	query := `UPDATE waf_probe_scans
	          SET status = $1, result = $2, error = '', stdout = $3, stderr = $4, command = $5,
	              execution_time = $6, posture = $7, requests_sent = $8, trips_used = $9,
	              schema_version = 2
	          WHERE scan_id = $10`
	if _, err := dbPool.Exec(context.Background(), query, status, result, truncateForLog(stdout),
		truncateForLog(stderr), cmdStr, execTime, posture, requests, trips, scanID); err != nil {
		log.Printf("[PROBE] Failed to store result: %v", err)
	}

	if trips > 0 {
		recordEgressTrips(scanID, scopeTargetID, trips)
	}
}

func probeSummary(result string) (string, int, int) {
	var parsed struct {
		Verdict struct {
			Posture string `json:"posture"`
		} `json:"verdict"`
		Budget struct {
			RequestsSent int `json:"requests_sent"`
			TripsUsed    int `json:"trips_used"`
		} `json:"budget"`
	}
	if json.Unmarshal([]byte(result), &parsed) != nil {
		return "", 0, 0
	}
	return parsed.Verdict.Posture, parsed.Budget.RequestsSent, parsed.Budget.TripsUsed
}

// recordEgressTrips books deliberate blocks against this egress IP. The cost is cross-target and
// multi-day, so it has to be accounted for outside the run that spent it.
func recordEgressTrips(scanID, scopeTargetID string, trips int) {
	fingerprint := "local-egress"
	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO waf_probe_egress_trips (egress_fingerprint, scan_id, scope_target_id, trips)
		 VALUES ($1, $2, $3, $4)`, fingerprint, scanID, scopeTargetID, trips)
	if err != nil {
		log.Printf("[PROBE] Failed to record egress trips: %v", err)
	}
}

func truncateForLog(s string) string {
	const max = 20000
	if len(s) <= max {
		return s
	}
	return s[:max] + fmt.Sprintf("... <truncated %d bytes>", len(s)-max)
}

// ---------------------------------------------------------------------------
// Config, schema and estimation endpoints
// ---------------------------------------------------------------------------

// GetWAFProbeSchema handles GET /waf-probe/config-schema.
// The modal reads defaults, presets and the test registry from here rather than hardcoding them in
// JavaScript, so a knob is defined in exactly one place.
func GetWAFProbeSchema(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, "docker", "exec", wafProbeContainer,
		"python", "/app/waf_probe.py", "--print-defaults").Output()
	if err != nil {
		log.Printf("[PROBE] Failed to read probe schema: %v", err)
		http.Error(w, "Probe container is not reachable. Is it running?", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

func GetWAFProbeConfig(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var configJSON []byte
	err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM waf_probe_configs WHERE scope_target_id = $1`, scopeTargetID).Scan(&configJSON)

	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		// No saved config is not an error: the modal falls back to the schema defaults.
		w.Write([]byte("{}"))
		return
	}
	w.Write(configJSON)
}

func SaveWAFProbeConfig(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var cfg map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, "Invalid config JSON", http.StatusBadRequest)
		return
	}
	payload, err := json.Marshal(cfg)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO waf_probe_configs (scope_target_id, config)
		VALUES ($1, $2)
		ON CONFLICT (scope_target_id) DO UPDATE SET config = $2, updated_at = NOW()`,
		scopeTargetID, payload)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

// DryRunWAFProbe handles POST /waf-probe/dry-run/{scope_target_id}.
// Resolves the config and returns the cost estimate without sending a single request, so the
// operator can see what a run will cost before authorising it.
func DryRunWAFProbe(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		URL    string          `json:"url"`
		Config json.RawMessage `json:"config"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	cfgJSON, err := resolveProbeConfig(scopeTargetID, payload.URL, payload.Config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", wafProbeContainer,
		"python", "/app/waf_probe.py", "--config", "-", "--dry-run")
	cmd.Stdin = bytes.NewReader(cfgJSON)

	out, err := cmd.Output()
	if err != nil {
		http.Error(w, "Probe container is not reachable", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(out)
}

// AbortWAFProbeScan handles POST /waf-probe/abort/{scan_id}. The probe flushes its checkpoint on
// SIGTERM, so an aborted run still yields everything it had learned.
func AbortWAFProbeScan(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]

	_ = exec.Command("docker", "exec", wafProbeContainer,
		"pkill", "-TERM", "-f", scanID).Run()

	_, _ = dbPool.Exec(context.Background(),
		`UPDATE waf_probe_scans SET status = 'aborted' WHERE scan_id = $1 AND status IN ('pending','running')`,
		scanID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "abort_requested"})
}

// GetWAFProbeTripLedger handles GET /waf-probe/trip-ledger — deliberate blocks spent from this
// egress in the last 24 hours, shown in the consent tab so the cost is visible before it is spent.
func GetWAFProbeTripLedger(w http.ResponseWriter, r *http.Request) {
	var total int
	err := dbPool.QueryRow(context.Background(),
		`SELECT COALESCE(SUM(trips),0) FROM waf_probe_egress_trips
		 WHERE occurred_at > NOW() - INTERVAL '24 hours'`).Scan(&total)
	if err != nil {
		total = 0
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"trips_24h": total})
}

// ---------------------------------------------------------------------------
// Status reads
// ---------------------------------------------------------------------------

func GetWAFProbeScanStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at,
	                 COALESCE(posture,''), COALESCE(requests_sent,0), COALESCE(trips_used,0),
	                 COALESCE(schema_version,1)
	          FROM waf_probe_scans WHERE scan_id = $1`
	var scan struct {
		ScanID        string    `json:"scan_id"`
		URL           string    `json:"url"`
		Status        string    `json:"status"`
		Result        *string   `json:"result"`
		Error         *string   `json:"error"`
		Command       *string   `json:"command"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
		Posture       string    `json:"posture"`
		RequestsSent  int       `json:"requests_sent"`
		TripsUsed     int       `json:"trips_used"`
		SchemaVersion int       `json:"schema_version"`
	}
	if err := dbPool.QueryRow(context.Background(), query, scanID).Scan(
		&scan.ScanID, &scan.URL, &scan.Status, &scan.Result, &scan.Error, &scan.Command,
		&scan.ExecutionTime, &scan.CreatedAt, &scan.Posture, &scan.RequestsSent,
		&scan.TripsUsed, &scan.SchemaVersion); err != nil {
		http.Error(w, "Scan not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scan)
}

func GetWAFProbeScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]

	query := `SELECT scan_id, url, status, result, error, command, execution_time, created_at,
	                 COALESCE(posture,''), COALESCE(requests_sent,0), COALESCE(trips_used,0),
	                 COALESCE(schema_version,1)
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
			scanID, url, status, posture       string
			result, scanErr, command, execTime *string
			createdAt                          time.Time
			requestsSent, tripsUsed, schemaVer int
		)
		if err := rows.Scan(&scanID, &url, &status, &result, &scanErr, &command, &execTime,
			&createdAt, &posture, &requestsSent, &tripsUsed, &schemaVer); err != nil {
			continue
		}
		scans = append(scans, map[string]interface{}{
			"scan_id": scanID, "url": url, "status": status, "result": result,
			"error": scanErr, "command": command, "execution_time": execTime,
			"created_at": createdAt, "posture": posture, "requests_sent": requestsSent,
			"trips_used": tripsUsed, "schema_version": schemaVer,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scans)
}

func UpdateWAFProbeScanStatus(scanID, status, result, errorMsg, stdout, stderr, command, execTime string) {
	query := `UPDATE waf_probe_scans SET status = $1, result = $2, error = $3, stdout = $4,
	          stderr = $5, command = $6, execution_time = $7 WHERE scan_id = $8`
	if _, err := dbPool.Exec(context.Background(), query, status, result, errorMsg,
		truncateForLog(stdout), truncateForLog(stderr), command, execTime, scanID); err != nil {
		log.Printf("[PROBE] Failed to update scan status: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Apply
// ---------------------------------------------------------------------------

type applyRow struct {
	Tool       string          `json:"tool"`
	Field      string          `json:"field"`
	Value      json.RawMessage `json:"value"`
	FindingID  string          `json:"finding_id"`
	Confidence string          `json:"confidence"`
	Bundle     string          `json:"bundle"`
}

// ApplyWAFProbeRecommendations handles POST /waf-probe/apply/{scope_target_id}/{scan_id}.
//
// Takes an explicit list of rows rather than "apply everything from the newest scan". v1 did the
// latter, which meant an operator reviewing an older result and clicking Apply silently applied a
// different scan's numbers, and clobbered their own settings with no record.
func ApplyWAFProbeRecommendations(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	scanID := vars["scan_id"]

	var payload struct {
		Rows []applyRow `json:"rows"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if len(payload.Rows) == 0 {
		http.Error(w, "No rows selected to apply", http.StatusBadRequest)
		return
	}

	// The scan must belong to this target, so a scan id from another target cannot be applied here.
	if scanID != "" {
		var exists bool
		_ = dbPool.QueryRow(context.Background(),
			`SELECT EXISTS(SELECT 1 FROM waf_probe_scans WHERE scan_id = $1 AND scope_target_id = $2)`,
			scanID, scopeTargetID).Scan(&exists)
		if !exists {
			http.Error(w, "That scan does not belong to this scope target", http.StatusBadRequest)
			return
		}
	}

	byTool := map[string][]applyRow{}
	for _, row := range payload.Rows {
		byTool[row.Tool] = append(byTool[row.Tool], row)
	}

	applied := 0
	results := map[string]interface{}{}
	for tool, rows := range byTool {
		n, err := applyToolRows(scopeTargetID, scanID, tool, rows)
		if err != nil {
			results[tool] = map[string]interface{}{"error": err.Error()}
			continue
		}
		applied += n
		results[tool] = map[string]interface{}{"applied": n}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success", "applied": applied, "by_tool": results,
	})
}

func applyToolRows(scopeTargetID, scanID, tool string, rows []applyRow) (int, error) {
	if tool == "nuclei" {
		// nuclei keeps its runtime settings in nuclei_configs.advanced_config, not in a `config`
		// column, so the generic path below would fail on it.
		return applyNucleiRows(scopeTargetID, scanID, rows)
	}

	table, ok := toolConfigTable(tool)
	if !ok {
		// Tools without a config table of their own land in probe_tool_tuning, which their
		// launchers read. That keeps katana, gospider and endpoint replay tunable without
		// inventing a config table each.
		return applyGenericTuning(scopeTargetID, scanID, tool, rows)
	}

	current := map[string]interface{}{}
	var existing []byte
	if err := dbPool.QueryRow(context.Background(),
		fmt.Sprintf(`SELECT config FROM %s WHERE scope_target_id = $1`, table),
		scopeTargetID).Scan(&existing); err == nil {
		_ = json.Unmarshal(existing, &current)
	}

	applied := 0
	var untranslated []applyRow
	for _, row := range rows {
		var value interface{}
		if json.Unmarshal(row.Value, &value) != nil {
			continue
		}

		field, translated, ok := translateField(tool, current, row.Field, value)
		if !ok {
			// The tool has no knob for this. Recording it in probe_tool_tuning keeps it visible
			// and usable by the launcher instead of writing it under a name the tool ignores.
			untranslated = append(untranslated, row)
			continue
		}

		before := current[field]
		if field == "headers" {
			current[field] = mergeHeaderLists(current[field], translated)
		} else {
			current[field] = translated
		}
		journalApply(scopeTargetID, scanID, tool, storeToolConfig, applyRow{
			Tool: row.Tool, Field: field, Value: row.Value,
			FindingID: row.FindingID, Confidence: row.Confidence, Bundle: row.Bundle,
		}, before, current[field])
		applied++
	}

	merged, err := json.Marshal(current)
	if err != nil {
		return 0, err
	}
	if _, err = dbPool.Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (scope_target_id, config) VALUES ($1, $2)
		ON CONFLICT (scope_target_id) DO UPDATE SET config = $2, updated_at = NOW()`, table),
		scopeTargetID, merged); err != nil {
		return 0, err
	}

	if len(untranslated) > 0 {
		n, _ := applyGenericTuning(scopeTargetID, scanID, tool, untranslated)
		applied += n
	}
	return applied, nil
}

func applyNucleiRows(scopeTargetID, scanID string, rows []applyRow) (int, error) {
	current := map[string]interface{}{}
	var existing []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT advanced_config FROM nuclei_configs WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&existing); err == nil && len(existing) > 0 {
		_ = json.Unmarshal(existing, &current)
	}

	applied := 0
	var untranslated []applyRow
	for _, row := range rows {
		var value interface{}
		if json.Unmarshal(row.Value, &value) != nil {
			continue
		}
		field, translated, ok := translateField("nuclei", current, row.Field, value)
		if !ok {
			untranslated = append(untranslated, row)
			continue
		}
		before := current[field]
		current[field] = translated
		journalApply(scopeTargetID, scanID, "nuclei", storeToolConfig, applyRow{
			Tool: "nuclei", Field: field, Value: row.Value,
			FindingID: row.FindingID, Confidence: row.Confidence, Bundle: row.Bundle,
		}, before, translated)
		applied++
	}

	merged, err := json.Marshal(current)
	if err != nil {
		return 0, err
	}
	// A nuclei row may not exist yet, and the table has no unique constraint on scope_target_id,
	// so update-then-insert rather than an upsert.
	tag, err := dbPool.Exec(context.Background(),
		`UPDATE nuclei_configs SET advanced_config = $2 WHERE scope_target_id = $1`,
		scopeTargetID, merged)
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		if _, err := dbPool.Exec(context.Background(),
			`INSERT INTO nuclei_configs (scope_target_id, advanced_config) VALUES ($1, $2)`,
			scopeTargetID, merged); err != nil {
			return 0, err
		}
	}

	if len(untranslated) > 0 {
		n, _ := applyGenericTuning(scopeTargetID, scanID, "nuclei", untranslated)
		applied += n
	}
	return applied, nil
}

// translateField maps a probe field name onto the field the tool's own config actually uses, and
// converts the value into that field's units.
//
// This layer exists because the probe speaks one vocabulary and each tool speaks its own. Without
// it, applying `rate_limit` to ffuf writes a key ffuf's launcher never reads: the operator is told
// the setting was applied, the scan runs at the old rate, and the probe carries the blame for a
// limit it measured correctly. A silent no-op is worse than a refusal, so a field with no
// equivalent returns false and is recorded in probe_tool_tuning instead.
func translateField(tool string, current map[string]interface{}, field string,
	value interface{}) (string, interface{}, bool) {

	if strings.HasPrefix(field, "_") {
		// Pseudo-fields such as _exempt are advisory notes for the launcher, never tool settings.
		return "", nil, false
	}

	rps, isRate := toFloat(value)

	switch field {
	case "rate_limit":
		if !isRate || rps <= 0 {
			return "", nil, false
		}
		switch tool {
		case "ffuf":
			// ffuf -rate is an integer request-per-second cap. Rounding down keeps the applied
			// rate at or below what was measured, never above it.
			return "rateLimit", maxInt(1, int(rps)), true
		case "nuclei":
			return "rate_limit", maxInt(1, int(rps)), true
		case "arjun":
			// arjun has no rate flag; it has a per-request delay applied within each thread, so
			// the aggregate rate is threads/delay. Solving for delay gives threads/rps.
			return "delay", roundTo(numberOr(current["threads"], 5)/rps, 2), true
		case "x8":
			return "delay", roundTo(numberOr(current["concurrency"], 10)/rps, 2), true
		case "katana":
			// katana -rl is an integer requests-per-second cap.
			return "rateLimit", maxInt(1, int(rps)), true
		case "gospider":
			// gospider has no rate flag either, only a whole-second delay between requests per
			// matching domain, so the achievable rate is concurrency/delay. Sub-second pacing is
			// not expressible, hence the ceiling: rounding the delay down would offer more than
			// the measured rate.
			return "delay", maxInt(1, int(math.Ceil(numberOr(current["concurrent"], 10)/rps))), true
		case "linkfinder":
			// Paced by the launcher between bundles, in milliseconds.
			return "requestDelayMs", maxInt(1, int(1000.0/rps)), true
		}
		// parameth exposes neither a rate nor a delay, so there is nothing honest to write.
		return "", nil, false

	case "threads", "concurrency":
		n, ok := toFloat(value)
		if !ok || n < 1 {
			return "", nil, false
		}
		switch tool {
		case "ffuf", "arjun", "parameth":
			return "threads", int(n), true
		case "x8", "nuclei", "katana":
			return "concurrency", int(n), true
		case "gospider":
			return "concurrent", int(n), true
		}
		return "", nil, false

	case "base_url":
		// Every crawler names this the same because they all read it from the same struct field.
		switch tool {
		case "katana", "gospider", "linkfinder":
			return "baseUrl", value, true
		}
		return "", nil, false

	case "cache_bust", "reuse_session":
		switch tool {
		case "katana", "gospider":
			return field, value, true
		}
		return "", nil, false

	case "select_by_extension":
		// The probe raises this when JavaScript is served with a non-JavaScript content type, which
		// is precisely when LinkFinder must pick its inputs by extension rather than by type.
		if tool == "linkfinder" {
			return "inputSource", "discovered_js", true
		}
		return "", nil, false
	}

	// Everything else is already named the way the owning tool names it. Guarding on the tool
	// keeps an ffuf-only setting such as autoCalibrate from being written into arjun's config.
	if tool == "ffuf" {
		switch field {
		case "autoCalibrate", "filterStatusCodes", "filterSize", "filterLines", "filterWords",
			"stopOn403", "stopOnAll", "stopOnErrors", "http2", "headers", "delay", "timeout",
			"followRedirects", "matchStatusCodes":
			return field, value, true
		}
		return "", nil, false
	}
	if tool == "nuclei" {
		switch field {
		case "bulk_size", "timeout", "retries", "max_host_error", "custom_headers":
			return field, value, true
		}
		return "", nil, false
	}
	switch field {
	case "headers", "timeout", "delay", "method":
		return field, value, true
	}
	return "", nil, false
}

// Where an applied value landed. Recorded per journal entry so a revert puts it back in the same
// place, instead of inferring the store from the tool name and missing the rows that fell through
// to shared tuning because the tool had no knob of its own.
const (
	storeToolConfig = "tool_config"
	storeTuning     = "tuning"
)

// restoreToolField writes a value straight into the store the journal recorded, under the field
// name the journal recorded, with no translation. Sending it back through translateField would
// translate an already-translated name, find no match, and quietly file the restore somewhere else
// while reporting success.
//
// A previous value of null means the field did not exist before the probe wrote it, so restoring
// means removing the key rather than setting it to null: a tool reading `rateLimit: null` is not in
// the state it was in before Apply.
func restoreToolField(scopeTargetID, tool, field, store string, before interface{}) error {
	set := func(current map[string]interface{}) {
		if before == nil {
			delete(current, field)
		} else {
			current[field] = before
		}
	}

	if store == storeTuning {
		current := map[string]interface{}{}
		var existing []byte
		if err := dbPool.QueryRow(context.Background(),
			`SELECT config FROM probe_tool_tuning WHERE scope_target_id = $1 AND tool = $2`,
			scopeTargetID, tool).Scan(&existing); err == nil {
			_ = json.Unmarshal(existing, &current)
		}
		set(current)
		merged, err := json.Marshal(current)
		if err != nil {
			return err
		}
		_, err = dbPool.Exec(context.Background(), `
			INSERT INTO probe_tool_tuning (scope_target_id, tool, config) VALUES ($1, $2, $3)
			ON CONFLICT (scope_target_id, tool) DO UPDATE SET config = $3, updated_at = NOW()`,
			scopeTargetID, tool, merged)
		return err
	}

	if tool == "nuclei" {
		current := map[string]interface{}{}
		var existing []byte
		if err := dbPool.QueryRow(context.Background(),
			`SELECT advanced_config FROM nuclei_configs WHERE scope_target_id = $1`,
			scopeTargetID).Scan(&existing); err == nil && len(existing) > 0 {
			_ = json.Unmarshal(existing, &current)
		}
		set(current)
		merged, err := json.Marshal(current)
		if err != nil {
			return err
		}
		_, err = dbPool.Exec(context.Background(),
			`UPDATE nuclei_configs SET advanced_config = $2 WHERE scope_target_id = $1`,
			scopeTargetID, merged)
		return err
	}

	table, ok := toolConfigTable(tool)
	if !ok {
		return fmt.Errorf("no config table for tool %q", tool)
	}
	current := map[string]interface{}{}
	var existing []byte
	if err := dbPool.QueryRow(context.Background(),
		fmt.Sprintf(`SELECT config FROM %s WHERE scope_target_id = $1`, table),
		scopeTargetID).Scan(&existing); err == nil {
		_ = json.Unmarshal(existing, &current)
	}
	set(current)
	merged, err := json.Marshal(current)
	if err != nil {
		return err
	}
	_, err = dbPool.Exec(context.Background(), fmt.Sprintf(`
		INSERT INTO %s (scope_target_id, config) VALUES ($1, $2)
		ON CONFLICT (scope_target_id) DO UPDATE SET config = $2, updated_at = NOW()`, table),
		scopeTargetID, merged)
	return err
}

func toolConfigTable(tool string) (string, bool) {
	switch tool {
	case "ffuf":
		return "ffuf_configs", true
	case "arjun":
		return "arjun_configs", true
	case "parameth":
		return "parameth_configs", true
	case "x8":
		return "x8_configs", true
	case "katana":
		return "katana_url_configs", true
	case "gospider":
		return "gospider_url_configs", true
	case "linkfinder":
		return "linkfinder_url_configs", true
	}
	return "", false
}

func toFloat(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func numberOr(v interface{}, fallback float64) float64 {
	if f, ok := toFloat(v); ok && f > 0 {
		return f
	}
	return fallback
}

func roundTo(v float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(v*p) / p
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func applyGenericTuning(scopeTargetID, scanID, tool string, rows []applyRow) (int, error) {
	current := map[string]interface{}{}
	var existing []byte
	if err := dbPool.QueryRow(context.Background(),
		`SELECT config FROM probe_tool_tuning WHERE scope_target_id = $1 AND tool = $2`,
		scopeTargetID, tool).Scan(&existing); err == nil {
		_ = json.Unmarshal(existing, &current)
	}

	applied := 0
	for _, row := range rows {
		var value interface{}
		if json.Unmarshal(row.Value, &value) != nil {
			continue
		}
		before := current[row.Field]
		current[row.Field] = value
		journalApply(scopeTargetID, scanID, tool, storeTuning, row, before, value)
		applied++
	}

	merged, err := json.Marshal(current)
	if err != nil {
		return 0, err
	}
	_, err = dbPool.Exec(context.Background(), `
		INSERT INTO probe_tool_tuning (scope_target_id, tool, config) VALUES ($1, $2, $3)
		ON CONFLICT (scope_target_id, tool) DO UPDATE SET config = $3, updated_at = NOW()`,
		scopeTargetID, tool, merged)
	return applied, err
}

func journalApply(scopeTargetID, scanID, tool, store string, row applyRow, before, after interface{}) {
	beforeJSON, _ := json.Marshal(before)
	afterJSON, _ := json.Marshal(after)
	_, err := dbPool.Exec(context.Background(), `
		INSERT INTO waf_probe_apply_journal
		  (scope_target_id, scan_id, tool, field, store, before_value, after_value, finding_id,
		   confidence, bundle)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		scopeTargetID, scanID, tool, row.Field, store, beforeJSON, afterJSON,
		row.FindingID, row.Confidence, row.Bundle)
	if err != nil {
		log.Printf("[PROBE] Failed to journal apply for %s.%s: %v", tool, row.Field, err)
	}
}

// GetWAFProbeApplyJournal handles GET /waf-probe/apply-journal/{scope_target_id}. Downstream config
// modals read this so a field the probe set can say so, instead of looking like an operator choice.
func GetWAFProbeApplyJournal(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, scan_id, tool, field, before_value, after_value, finding_id, confidence,
		       applied_at, reverted_at
		FROM waf_probe_apply_journal
		WHERE scope_target_id = $1 AND reverted_at IS NULL
		ORDER BY applied_at DESC LIMIT 200`, scopeTargetID)
	if err != nil {
		http.Error(w, "Failed to read apply journal", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	entries := make([]map[string]interface{}, 0)
	for rows.Next() {
		var (
			id, scanID, tool, field string
			beforeVal, afterVal     []byte
			findingID, confidence   *string
			appliedAt               time.Time
			revertedAt              *time.Time
		)
		if err := rows.Scan(&id, &scanID, &tool, &field, &beforeVal, &afterVal,
			&findingID, &confidence, &appliedAt, &revertedAt); err != nil {
			continue
		}
		var before, after interface{}
		_ = json.Unmarshal(beforeVal, &before)
		_ = json.Unmarshal(afterVal, &after)
		entries = append(entries, map[string]interface{}{
			"id": id, "scan_id": scanID, "tool": tool, "field": field,
			"before": before, "after": after, "finding_id": findingID,
			"confidence": confidence, "applied_at": appliedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(entries)
}

// RevertWAFProbeApply handles POST /waf-probe/revert/{journal_id}.
func RevertWAFProbeApply(w http.ResponseWriter, r *http.Request) {
	journalID := mux.Vars(r)["journal_id"]

	var (
		scopeTargetID, tool, field, store string
		beforeVal                         []byte
	)
	err := dbPool.QueryRow(context.Background(), `
		SELECT scope_target_id, tool, field, store, before_value FROM waf_probe_apply_journal
		WHERE id = $1 AND reverted_at IS NULL`, journalID).Scan(
		&scopeTargetID, &tool, &field, &store, &beforeVal)
	if err != nil {
		http.Error(w, "Journal entry not found or already reverted", http.StatusNotFound)
		return
	}

	var before interface{}
	_ = json.Unmarshal(beforeVal, &before)

	// The journal already records the tool's own field name, so the restore writes it verbatim.
	// Sending it back through translateField would translate a translated name, find no match,
	// and quietly file the restore in probe_tool_tuning while reporting success.
	if err := restoreToolField(scopeTargetID, tool, field, store, before); err != nil {
		http.Error(w, "Failed to restore the previous value: "+err.Error(),
			http.StatusInternalServerError)
		return
	}

	_, _ = dbPool.Exec(context.Background(),
		`UPDATE waf_probe_apply_journal SET reverted_at = NOW() WHERE id = $1`, journalID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "reverted", "restored": before})
}

// mergeHeaderLists merges recommended headers into existing ones by name, so a recommended
// User-Agent adds to rather than replaces the operator's headers.
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
			byName[name] = h
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
