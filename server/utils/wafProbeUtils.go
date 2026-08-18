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

	// The grace is added to a wall clock that exists, never to a missing one.
	//
	// This read `seconds = WallClockSeconds + grace` unconditionally, so a config with no
	// wall_clock_seconds produced 0 + 90 = 90. Ninety is positive, so the 420 fallback below could
	// never fire, and every preset was cut off long before its budget: a standard run configured
	// for 660 seconds died at 90 with a backend_timeout and no verdict, having completed 30 of 44
	// tests. Any caller that saves a partial config hits this, which is easy to do.
	seconds := env.Global.GoContextTimeoutSecs
	if seconds <= 0 && env.Global.WallClockSeconds > 0 {
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
// Recommendation translation
// ---------------------------------------------------------------------------

// translateField maps a probe field name onto the field the tool's own config actually uses, and
// converts the value into that field's units.
//
// This layer exists because the probe speaks one vocabulary and each tool speaks its own: a
// measured `rate_limit` is ffuf's `rateLimit`, arjun's `-d` in whole seconds and x8's `--delay` in
// milliseconds. Getting that mapping right is the whole value of the probe's output, so it is worth
// doing carefully and worth showing the operator.
//
// It is used for display only. This used to feed an automated apply that wrote straight into the
// tool configs, and the writes failed silently: a fractional delay landed in an integer column and
// decoded to zero, so the tool ran unpaced while the UI reported the rate as applied. See
// GetWAFProbeRecommendations in wafProbeRecommend.go. A field with no equivalent returns false and
// is reported as "this tool has no setting for it" rather than being written anywhere.
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
			//
			// arjun -d is WHOLE SECONDS and ArjunConfig.Delay is an int. This used to return a
			// rounded float, and two things went wrong with it. A fractional result such as 1.67
			// cannot be unmarshalled into an int field, and ExecuteArjunScan ignores the unmarshal
			// error, so Delay silently became 0 and the `-d` flag was never emitted: applying a
			// rate limit left arjun running with no rate limit at all. Ceiling to a whole second
			// keeps the achieved rate at or under what was measured, which is the direction an
			// error has to fall.
			return "delay", maxInt(1, int(math.Ceil(numberOr(current["threads"], 5)/rps))), true
		case "x8":
			// x8 --delay is MILLISECONDS, not seconds, and --workers is the concurrency. The old
			// formula computed a delay in seconds and wrote it into a millisecond field, so a
			// measured 5 rps was applied as a 2ms pause across 10 workers, roughly 5000 rps: three
			// orders of magnitude faster than the rate the probe had just established was safe.
			// Same int truncation problem on top of it.
			return "delay", maxInt(1, int(math.Ceil(1000.0*numberOr(current["concurrency"], 10)/rps))), true
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
		return "", nil, false

	case "threads", "concurrency":
		n, ok := toFloat(value)
		if !ok || n < 1 {
			return "", nil, false
		}
		switch tool {
		case "ffuf", "arjun":
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
		// No tool here has a flag for either. This used to return true for katana and gospider, so
		// the Recommendations tab told the operator to set a switch that no command builder read.
		// Returning false makes it say plainly that the tool has no setting for it, which is the
		// truth and is actionable: it means pacing that tool has to be done another way.
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

func toolConfigTable(tool string) (string, bool) {
	switch tool {
	case "ffuf":
		return "ffuf_configs", true
	case "arjun":
		return "arjun_configs", true
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

