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
	// Method and PassiveMode are retained only so stored rows still unmarshal. The verb is now
	// decided by the scan's verb groups rather than a single config value, and --passive aborts the
	// process when combined with -i, so neither is emitted. See buildArjunArgs.
	Method          string              `json:"method"`
	PassiveMode     bool                `json:"passiveMode"`
	Headers         []map[string]string `json:"headers"`
	Threads         int                 `json:"threads"`
	Delay           int                 `json:"delay"`
	Timeout         int                 `json:"timeout"`
	ChunkSize       int                 `json:"chunkSize"`
	Wordlist        string              `json:"wordlist"`
	StableDetection bool                `json:"stableDetection"`
	JSONOutput      bool                `json:"jsonOutput"`
	IncludeParams   string              `json:"includeParams"`
	ExcludeParams   string              `json:"excludeParams"`
	// IncludeScripts brings content_class='script' endpoints into the target set. Off by default:
	// a JavaScript bundle has no server-side parameter surface, and on the reference target scripts
	// are 34 of the 80 valid rows, so including them triples the work for nothing reachable.
	IncludeScripts bool `json:"includeScripts"`

	// XMLTemplate is the body Arjun wraps candidates in for the XML pass. It must contain the
	// literal $arjun$, which is where the candidate parameters are substituted; anything without it
	// is replaced with the default rather than shipped, because Arjun crashes on a template it
	// cannot substitute into.
	XMLTemplate string `json:"xmlTemplate"`

	// Verbs holds per-verb overrides, keyed by HTTP method. A GET pass and a POST pass are not the
	// same job: a GET can run wide and fast against a cache, while a POST is writing to a body-
	// parsing route that usually wants fewer threads and a longer timeout. Everything absent here
	// falls back to the base values above, so an operator who never opens a verb tab keeps exactly
	// the behaviour they had.
	Verbs map[string]ArjunVerbOverride `json:"verbs"`
}

// ArjunVerbOverride is the per-verb half of the config.
//
// Pointers throughout, because zero is a meaningful value for most of these and "not set" has to
// stay distinguishable from "set to 0". A plain int would make every untouched field look like a
// deliberate 0 the moment any single field on the verb was edited, which is the same defect the
// base config had when its defaults lived in an else branch.
type ArjunVerbOverride struct {
	Threads         *int                `json:"threads,omitempty"`
	Delay           *int                `json:"delay,omitempty"`
	Timeout         *int                `json:"timeout,omitempty"`
	ChunkSize       *int                `json:"chunkSize,omitempty"`
	Wordlist        *string             `json:"wordlist,omitempty"`
	StableDetection *bool               `json:"stableDetection,omitempty"`
	Headers         []map[string]string `json:"headers,omitempty"`
}

// ForVerb resolves the config that a pass on this verb will actually run with.
//
// One resolver, used by the runner AND by the preview endpoint, so what the operator is shown is
// produced by the same code that builds the command. A second copy would drift, and a preview that
// drifts is worse than no preview: it is a confident description of something that did not happen.
func (c ArjunConfig) ForVerb(verb string) ArjunConfig {
	o, ok := c.Verbs[strings.ToUpper(verb)]
	if !ok {
		return c
	}
	out := c
	if o.Threads != nil {
		out.Threads = *o.Threads
	}
	if o.Delay != nil {
		out.Delay = *o.Delay
	}
	if o.Timeout != nil {
		out.Timeout = *o.Timeout
	}
	if o.ChunkSize != nil {
		out.ChunkSize = *o.ChunkSize
	}
	if o.Wordlist != nil {
		out.Wordlist = *o.Wordlist
	}
	if o.StableDetection != nil {
		out.StableDetection = *o.StableDetection
	}
	if o.Headers != nil {
		out.Headers = o.Headers
	}
	return out
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
	if err := UnmarshalConfigTolerant(configJSON, &config); err != nil {
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

// DefaultArjunConfig is the baseline every scan starts from.
//
// Applied before the stored row is unmarshalled over it, not only when the row is missing. The old
// code put defaults in the `else` branch, so a partial row like {"delay":1} unmarshalled cleanly and
// every absent key became a Go zero value: 0 threads, 0 timeout, 0 chunks. A config saved from the
// modal with one field touched silently disabled the rest.
func DefaultArjunConfig() ArjunConfig {
	return ArjunConfig{
		Threads:    5,
		Timeout:    10,
		ChunkSize:  500,
		JSONOutput: true,
	}
}

// arjunGroupTimeout bounds one verb group. Without it cmd.CombinedOutput blocks until Arjun exits
// and a wedged run against hundreds of URLs can never be stopped.
const arjunGroupTimeout = 2 * time.Hour

// defaultArjunXMLTemplate is the minimum that makes XML mode function: a single root element with
// the substitution marker inside it.
const defaultArjunXMLTemplate = "<root>$arjun$</root>"

func ExecuteArjunScan(scanID, scopeTargetID string) {
	startTime := time.Now()
	ctx := context.Background()

	UpdateArjunScanStatus(scanID, "running", "", "")

	config := DefaultArjunConfig()
	var configJSON []byte
	if err := dbPool.QueryRow(ctx,
		`SELECT config FROM arjun_configs WHERE scope_target_id = $1`,
		scopeTargetID).Scan(&configJSON); err == nil {
		_ = UnmarshalConfigTolerant(configJSON, &config)
	}

	sel, err := SelectParamEnumTargets(ctx, scopeTargetID,
		ParamTargetOptions{Tool: "arjun", IncludeScripts: config.IncludeScripts})
	if err != nil {
		UpdateArjunScanStatus(scanID, "error", "", fmt.Sprintf("Failed to select endpoints: %v", err))
		return
	}
	if sel.Total == 0 {
		UpdateArjunScanStatus(scanID, "error", "", "No valid endpoints to scan. Parameter "+
			"enumeration runs against endpoints Validate confirmed as valid, so run Consolidate "+
			"and Investigate first. Scope: "+sel.Scope)
		return
	}

	// Groups run in sequence and fold into this one scan. Total is written once, up front, across
	// every group, so progress never resets or exceeds its denominator partway through.
	groups := PlanVerbGroups("arjun", sel.Targets)
	total := TotalGroupWork(groups)
	dbPool.Exec(ctx, `UPDATE arjun_scans SET total_endpoints = $1 WHERE scan_id = $2`, total, scanID)

	var (
		allOutput strings.Builder
		cmdStrs   []string
		results   []paramEnumGroupResult
		processed int
		found     int
	)

	for _, g := range groups {
		gr, out, cmdStr, n := runArjunGroup(ctx, scanID, scopeTargetID, config, g)
		found += n
		processed += len(g.Targets)
		results = append(results, gr)
		cmdStrs = append(cmdStrs, cmdStr)
		allOutput.WriteString(fmt.Sprintf("\n===== %s (%d endpoints) =====\n", g.Label, len(g.Targets)))
		allOutput.WriteString(out)

		dbPool.Exec(ctx,
			`UPDATE arjun_scans SET processed_endpoints = $1, parameters_found = $2 WHERE scan_id = $3`,
			processed, found, scanID)
	}

	// A group that failed is reported as partial rather than error: the groups that did run
	// produced real findings, and discarding them because a later pass failed loses evidence.
	status := "success"
	var failed []string
	for _, r := range results {
		if r.Failed {
			failed = append(failed, r.Label)
		}
	}
	if len(failed) > 0 {
		status = "partial"
		if len(failed) == len(results) {
			status = "error"
		}
	}

	summary, _ := json.Marshal(map[string]interface{}{
		"groups": results, "selection": sel, "failed_groups": failed,
	})

	dbPool.Exec(ctx, `
		UPDATE arjun_scans
		SET status = $1, processed_endpoints = $2, parameters_found = $3,
		    execution_time = $4, command = $5, stdout = $6, error = $7
		WHERE scan_id = $8`,
		status, processed, found, time.Since(startTime).String(),
		strings.Join(cmdStrs, "\n"), allOutput.String(), string(summary), scanID)
}

// runArjunGroup runs one verb group and stores whatever it found.
func runArjunGroup(ctx context.Context, scanID, scopeTargetID string, config ArjunConfig,
	g VerbGroup) (paramEnumGroupResult, string, string, int) {

	res := paramEnumGroupResult{Label: g.Label, Mode: g.Mode, Endpoints: len(g.Targets)}

	// Resolve the per-verb settings for this pass. Arjun's two POST passes share a verb, so
	// both pick up the same POST overrides, which is the intent: they are one decision about
	// how hard to hit body routes, not two.
	config = config.ForVerb(g.Verb)

	safeLabel := strings.NewReplacer(" ", "_", "(", "", ")", "").Replace(g.Label)
	urlsFile := fmt.Sprintf("/tmp/arjun_urls_%s_%s.txt", scanID, safeLabel)
	outputFile := fmt.Sprintf("/tmp/arjun_output_%s_%s.json", scanID, safeLabel)
	defer os.Remove(urlsFile)
	defer os.Remove(outputFile)

	urls := make([]string, 0, len(g.Targets))
	for _, t := range g.Targets {
		urls = append(urls, t.URL)
	}
	if err := os.WriteFile(urlsFile, []byte(strings.Join(urls, "\n")+"\n"), 0644); err != nil {
		res.Failed, res.Detail = true, fmt.Sprintf("could not write URL list: %v", err)
		return res, "", "", 0
	}

	args := buildArjunArgs(config, g.Mode, urlsFile, outputFile)
	cmdStr := "docker exec ars0n-framework-v2-arjun-1 arjun " + strings.Join(args, " ")

	runCtx, cancel := context.WithTimeout(ctx, arjunGroupTimeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx,
		"docker", append([]string{"exec", "ars0n-framework-v2-arjun-1", "arjun"}, args...)...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		res.Failed = true
		res.Detail = fmt.Sprintf("arjun exited with %v", err)
		if runCtx.Err() != nil {
			res.Detail = fmt.Sprintf("timed out after %s", arjunGroupTimeout)
		}
		return res, string(output), cmdStr, 0
	}

	found := parseArjunOutput(ctx, outputFile, scanID, scopeTargetID, g)
	res.Found = found
	return res, string(output), cmdStr, found
}

func buildArjunArgs(config ArjunConfig, mode, urlsFile, outputFile string) []string {
	args := []string{"-i", urlsFile, "-o", outputFile}

	if config.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", config.Threads))
	}
	// -m defaults to GET inside Arjun, so passing it explicitly for every group keeps the stored
	// command string honest about which pass produced which findings.
	if mode != "" {
		args = append(args, "-m", mode)
	}
	// Was hardcoded. --stable makes Arjun force threads to 1 and sleep 3-9 seconds before every
	// request, which measured out at 5.7 s/request: unusable on any real corpus and not something
	// the operator had asked for.
	if config.StableDetection {
		args = append(args, "--stable")
	}
	if config.Delay > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", config.Delay))
	}
	if config.Timeout > 0 {
		args = append(args, "-T", fmt.Sprintf("%d", config.Timeout))
	}
	// Arjun overrides -c to 500 internally for any non-GET mode, so sending it there would report a
	// chunk size in the command string that Arjun did not use.
	if config.ChunkSize > 0 && mode == "GET" {
		args = append(args, "-c", fmt.Sprintf("%d", config.ChunkSize))
	}
	if config.Wordlist != "" {
		args = append(args, "-w", config.Wordlist)
	}
	// XML mode CANNOT run without --include, and the failure is silent.
	//
	// requester.py:61 does mem.var['include'].replace('$arjun$', ...) with no guard, while the GET
	// branch at line 41 checks `if mem.var['include'] and '$arjun$' in ...` first. With --include
	// unset the value is an empty dict, .replace raises AttributeError, the exception is swallowed
	// per URL, and arjun still exits 0. A whole XML pass would report success having sent nothing.
	if mode == "XML" {
		include := strings.TrimSpace(config.XMLTemplate)
		if !strings.Contains(include, "$arjun$") {
			include = defaultArjunXMLTemplate
		}
		args = append(args, "--include", include)
	} else if inc := strings.TrimSpace(config.IncludeParams); inc != "" {
		args = append(args, "--include", inc)
	}
	// --passive is deliberately not emitted. Under -i, Arjun derives the passive host from
	// urlparse(None).netloc, queries the archives for an empty host and aborts the whole process
	// with a traceback, so a single flag turns the entire scan into a no-op.
	if lines := ParamHeaderLines(config.Headers); len(lines) > 0 {
		// One --headers flag, newline separated. Not repeated -H, which Arjun does not accept.
		args = append(args, "--headers", strings.Join(lines, "\n"))
	}
	return args
}

// parseArjunOutput reads Arjun's JSON report.
//
// Arjun 2.x writes {url: {"params": [...], "method": "GET", "headers": {...}}}. The previous parser
// asserted the value was []interface{}, which is the Arjun 1.x shape, so the assertion failed on
// every row, no parameter was ever stored, and every scan reported success with zero findings.
// Confirmed against arjun/__main__.py, which builds final_result[url]['params'].
func parseArjunOutput(ctx context.Context, outputFile, scanID, scopeTargetID string,
	g VerbGroup) int {

	data, err := os.ReadFile(outputFile)
	if err != nil || len(data) == 0 {
		return 0
	}

	var results map[string]struct {
		Params  []string          `json:"params"`
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
	}
	if err := json.Unmarshal(data, &results); err != nil {
		return 0
	}

	// Arjun reports the method it actually used, so attribution comes from the tool rather than
	// from what we believe we asked for.
	found := 0
	for url, r := range results {
		method := strings.ToUpper(r.Method)
		if method == "" || g.Mode == "JSON" {
			// -m JSON reports "JSON", which is a body encoding rather than a verb.
			method = "POST"
		}
		paramType := "query"
		if method != "GET" {
			paramType = "body"
		}
		for _, name := range r.Params {
			if strings.TrimSpace(name) == "" {
				continue
			}
			// Arjun reports names only, so there is no value or reason to record for it.
			if StoreParameterFinding(ctx, scanID, "arjun", scopeTargetID, url, method,
				g.Label, name, paramType, "high", "", "") {
				found++
			}
		}
	}
	return found
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
		"scan_id":             scanID,
		"status":              status,
		"result":              result,
		"error":               errorMsg,
		"stdout":              stdout,
		"stderr":              stderr,
		"command":             command,
		"execution_time":      executionTime,
		"total_endpoints":     totalEndpoints,
		"processed_endpoints": processedEndpoints,
		"parameters_found":    parametersFound,
		"created_at":          createdAt,
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

	// Initialised, not nil: a nil slice marshals to JSON null, and every client that does
	// scans.length on the response throws before it can check.
	scans := []map[string]interface{}{}
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
		SELECT endpoint_url, COALESCE(http_method, 'GET'), COALESCE(verb_group, ''),
		       parameter_name, parameter_type,
		       COALESCE(example_value, ''), COALESCE(confidence, ''), created_at
		FROM parameter_enumeration_results
		WHERE scan_id = $1 AND scan_type = 'arjun'
		ORDER BY endpoint_url, http_method, parameter_name
	`
	rows, err := dbPool.Query(context.Background(), query, scanID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results = []map[string]interface{}{}
	for rows.Next() {
		var endpointURL, method, verbGroup, paramName, paramType, exampleValue, confidence string
		var createdAt time.Time

		if err := rows.Scan(&endpointURL, &method, &verbGroup, &paramName, &paramType,
			&exampleValue, &confidence, &createdAt); err != nil {
			continue
		}

		results = append(results, map[string]interface{}{
			"endpoint_url": endpointURL,
			// The verb is part of the finding's identity: a hidden parameter on POST /accounts is a
			// different finding from one on GET /accounts, and both used to be stored and rendered
			// as the same row.
			"http_method":    method,
			"verb_group":     verbGroup,
			"parameter_name": paramName,
			"parameter_type": paramType,
			"example_value":  exampleValue,
			"confidence":     confidence,
			"created_at":     createdAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
