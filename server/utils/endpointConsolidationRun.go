package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Consolidate: fold six discovery sources into one list of unique endpoint and verb combinations.
//
// The sources are the manual crawl plus katana, gospider, linkfinder, gau and waybackurls. FFUF is
// deliberately absent: it now runs later in the workflow, after parameter enumeration, so its hits
// are not part of the surface this step describes.
//
// Three defects in the previous implementation are fixed here, and each of them was silently wrong
// rather than loudly broken.
//
//  1. It opened with DELETE FROM consolidated_url_endpoints WHERE scope_target_id = $1. That makes
//     "manually add an endpoint" impossible: the next Consolidate destroys it. It also threw away
//     every validation verdict and every operator note. Writes are now upserts keyed on
//     endpoint_key, and the columns an operator owns are never overwritten by a run.
//  2. It LEFT JOINed endpoint_parameters, which multiplies one endpoint into one row per parameter,
//     then incremented request_count once per row. That counter was measuring how many parameters a
//     URL had and calling it traffic.
//  3. first_seen and last_seen were both time.Now(), so every endpoint appeared to have been
//     discovered at the moment of consolidation and the age of a finding was unknowable.

// The sources this step consolidates. FFUF is not here on purpose; see the file comment.
var consolidationScanTypes = []string{"katana", "gospider", "linkfinder", "gau", "waybackurls"}

type consolidatedRow struct {
	identity     EndpointIdentity
	displayURL   string
	isDirect     bool
	sources      map[string]int
	statusCodes  map[int]bool
	firstSeen    time.Time
	lastSeen     time.Time
	captureCount int
	requestCount int
	observedVerb map[string]bool
	methodKnown  bool
	graphQLOp    string
	requestBody  string
	contentType  string
	reqHeaders   map[string]interface{}
	respHeaders  map[string]interface{}
	params       map[string]*ConsolidatedParameter
}

// RunConsolidation handles POST /consolidated-endpoints/{scope_target_id}/consolidate.
//
// Asynchronous, because folding tens of thousands of archive rows inside an HTTP handler ties up a
// connection until the client times out and leaves the operator with no idea whether it worked.
func RunConsolidation(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	scanID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO endpoint_consolidation_runs (scan_id, scope_target_id, status)
		VALUES ($1, $2, 'pending')`, scanID, scopeTargetID); err != nil {
		log.Printf("[CONSOLIDATE] failed to create run: %v", err)
		http.Error(w, "Failed to create consolidation run", http.StatusInternalServerError)
		return
	}

	go executeConsolidation(scanID, scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{"scan_id": scanID, "status": "pending"})
}

func executeConsolidation(scanID, scopeTargetID string) {
	started := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[CONSOLIDATE] panic in %s: %v", scanID, rec)
			finishConsolidation(scanID, "error", 0, 0, nil, fmt.Sprintf("panic: %v", rec), started)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	_, _ = dbPool.Exec(ctx, `
		UPDATE endpoint_consolidation_runs SET status='running', updated_at=NOW()
		WHERE scan_id = $1`, scanID)

	defaultScheme, _, _ := ScopeTargetBase(scopeTargetID)
	targetDomain := extractDomainFromScopeTarget(scopeTargetID)

	rows := map[string]*consolidatedRow{}
	skipped := map[string]int{}
	read := 0

	if n, err := consolidateFromDiscovered(ctx, scopeTargetID, defaultScheme, rows, skipped); err != nil {
		finishConsolidation(scanID, "error", 0, 0, skipped, err.Error(), started)
		return
	} else {
		read += n
	}

	if n, err := consolidateFromManualCrawl(ctx, scopeTargetID, defaultScheme, targetDomain, rows, skipped); err != nil {
		log.Printf("[CONSOLIDATE] manual crawl pass failed: %v", err)
		skipped["manual_crawl_error"]++
	} else {
		read += n
	}

	if len(rows) == 0 {
		finishConsolidation(scanID, "success", 0, read, skipped, "", started)
		return
	}

	// Template group sizes, so the UI can say "one of 412 like this" instead of listing 412 rows.
	groupSize := map[string]int{}
	for _, row := range rows {
		groupSize[row.identity.TemplateKey]++
	}
	exemplarTaken := map[string]bool{}

	stored, err := storeConsolidated(ctx, scopeTargetID, scanID, rows, groupSize, exemplarTaken)
	if err != nil {
		finishConsolidation(scanID, "error", stored, read, skipped, err.Error(), started)
		return
	}

	// Rows nobody saw this run are marked, never deleted. A source going quiet is information, and
	// an operator may have deleted the tool rather than the endpoint disappearing.
	_, _ = dbPool.Exec(ctx, `
		UPDATE consolidated_url_endpoints
		SET unseen_since = COALESCE(unseen_since, NOW())
		WHERE scope_target_id = $1 AND deleted_at IS NULL AND manual_added = FALSE
		  AND (last_run_id IS DISTINCT FROM $2)`, scopeTargetID, scanID)
	_, _ = dbPool.Exec(ctx, `
		UPDATE consolidated_url_endpoints SET unseen_since = NULL
		WHERE scope_target_id = $1 AND last_run_id = $2`, scopeTargetID, scanID)

	if err := RefreshConsolidatedParameters(ctx, scopeTargetID); err != nil {
		log.Printf("[CONSOLIDATE] parameter refresh failed: %v", err)
	}

	finishConsolidation(scanID, "success", stored, read, skipped, "", started)
}

// consolidateFromDiscovered streams the crawler and archive rows.
//
// No join. The previous version joined endpoint_parameters here, which multiplied every endpoint by
// its parameter count and inflated request_count accordingly. Parameters are derived from the URL
// itself and reattached separately.
func consolidateFromDiscovered(ctx context.Context, scopeTargetID, defaultScheme string,
	out map[string]*consolidatedRow, skipped map[string]int) (int, error) {

	rows, err := dbPool.Query(ctx, `
		SELECT url, COALESCE(status_code, 0), is_direct, scan_type, created_at
		FROM discovered_endpoints
		WHERE scope_target_id = $1 AND scan_type = ANY($2)
		ORDER BY id`, scopeTargetID, consolidationScanTypes)
	if err != nil {
		return 0, fmt.Errorf("failed to read discovered endpoints: %w", err)
	}
	defer rows.Close()

	read := 0
	for rows.Next() {
		var rawURL, scanType string
		var status int
		var isDirect bool
		var createdAt time.Time
		if rows.Scan(&rawURL, &status, &isDirect, &scanType, &createdAt) != nil {
			continue
		}
		read++

		// Everything from a crawler or an archive is a GET. Only the manual crawl observes a verb.
		id, ok := CanonicalizeEndpoint(rawURL, "GET", defaultScheme)
		if !ok {
			skipped["unusable_url"]++
			continue
		}

		row := ensureRow(out, id, isDirect, createdAt)
		row.sources[scanType]++
		row.requestCount++
		if status > 0 {
			row.statusCodes[status] = true
		}
		touch(row, createdAt)
		mergeURLParams(row, id)
	}
	return read, rows.Err()
}

// consolidateFromManualCrawl folds in the captures. These are the only rows carrying a real verb,
// a real request body and a real observed response, so they take precedence on every field.
func consolidateFromManualCrawl(ctx context.Context, scopeTargetID, defaultScheme, targetDomain string,
	out map[string]*consolidatedRow, skipped map[string]int) (int, error) {

	rows, err := dbPool.Query(ctx, `
		SELECT url, COALESCE(method,'GET'), COALESCE(status_code,0), headers, response_headers,
		       COALESCE(post_data,''), COALESCE(mime_type,''), COALESCE(graphql_operation,''),
		       COALESCE(get_params,'{}'::jsonb), COALESCE(post_params,'{}'::jsonb),
		       is_direct, created_at
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY id`, scopeTargetID)
	if err != nil {
		return 0, fmt.Errorf("failed to read manual crawl captures: %w", err)
	}
	defer rows.Close()

	read := 0
	for rows.Next() {
		var rawURL, method, postData, mime, graphqlOp string
		var status int
		var reqHeaders, respHeaders, getParams, postParams []byte
		var isDirect *bool
		var createdAt time.Time
		if rows.Scan(&rawURL, &method, &status, &reqHeaders, &respHeaders, &postData, &mime,
			&graphqlOp, &getParams, &postParams, &isDirect, &createdAt) != nil {
			continue
		}
		read++

		id, ok := CanonicalizeEndpoint(rawURL, method, defaultScheme)
		if !ok {
			skipped["unusable_url"]++
			continue
		}

		direct := true
		if isDirect != nil {
			direct = *isDirect
		} else if targetDomain != "" {
			direct = strings.HasSuffix(id.Host, targetDomain)
		}

		row := ensureRow(out, id, direct, createdAt)
		row.sources["manual_crawl"]++
		row.captureCount++
		row.requestCount++
		// A verb that was actually observed, rather than assumed because a crawler found a link.
		row.methodKnown = true
		row.observedVerb[id.Method] = true
		if status > 0 {
			row.statusCodes[status] = true
		}
		if graphqlOp != "" {
			row.graphQLOp = graphqlOp
		}
		if postData != "" && row.requestBody == "" {
			row.requestBody = postData
		}
		if mime != "" && row.contentType == "" {
			row.contentType = mime
		}
		mergeHeaderMap(&row.reqHeaders, reqHeaders)
		mergeHeaderMap(&row.respHeaders, respHeaders)
		touch(row, createdAt)
		mergeURLParams(row, id)
		mergeJSONParams(row, getParams, "query")
		mergeJSONParams(row, postParams, "body")
	}
	return read, rows.Err()
}

func ensureRow(out map[string]*consolidatedRow, id EndpointIdentity, isDirect bool, at time.Time) *consolidatedRow {
	if row, ok := out[id.Key]; ok {
		// Direct wins: an endpoint seen both ways is in scope.
		if isDirect {
			row.isDirect = true
		}
		return row
	}
	row := &consolidatedRow{
		identity:     id,
		displayURL:   id.CanonicalURL,
		isDirect:     isDirect,
		sources:      map[string]int{},
		statusCodes:  map[int]bool{},
		firstSeen:    at,
		lastSeen:     at,
		observedVerb: map[string]bool{},
		reqHeaders:   map[string]interface{}{},
		respHeaders:  map[string]interface{}{},
		params:       map[string]*ConsolidatedParameter{},
	}
	out[id.Key] = row
	return row
}

// touch keeps the real observation window rather than stamping time.Now() on everything, so the
// age of a finding is answerable.
func touch(row *consolidatedRow, at time.Time) {
	if at.IsZero() {
		return
	}
	if row.firstSeen.IsZero() || at.Before(row.firstSeen) {
		row.firstSeen = at
	}
	if at.After(row.lastSeen) {
		row.lastSeen = at
	}
}

func mergeURLParams(row *consolidatedRow, id EndpointIdentity) {
	for name, value := range id.ValueParams {
		addParam(row, "query", name, value)
	}
}

func mergeJSONParams(row *consolidatedRow, raw []byte, kind string) {
	if len(raw) == 0 {
		return
	}
	var parsed map[string]interface{}
	if json.Unmarshal(raw, &parsed) != nil {
		return
	}
	for name, value := range parsed {
		addParam(row, kind, name, fmt.Sprintf("%v", value))
	}
}

func addParam(row *consolidatedRow, kind, name, value string) {
	if name == "" {
		return
	}
	key := kind + "|" + name
	p, ok := row.params[key]
	if !ok {
		p = &ConsolidatedParameter{ParamType: kind, ParamName: name}
		row.params[key] = p
	}
	p.Frequency++
	if value != "" && len(p.ExampleValues) < 5 && !contains(p.ExampleValues, value) {
		if len(value) > 256 {
			value = value[:256]
		}
		p.ExampleValues = append(p.ExampleValues, value)
	}
}

// storeConsolidated upserts on endpoint_key.
//
// The DO UPDATE list is deliberately narrow. Every column an operator or a later scan owns is
// absent from it: manual_added, pinned, notes, deleted_at, validation_*, override_*, investigated_at
// and interest_score all survive a re-run untouched. That is what makes "manually add an endpoint"
// and "override this verdict" possible at all.
func storeConsolidated(ctx context.Context, scopeTargetID, scanID string,
	rows map[string]*consolidatedRow, groupSize map[string]int, exemplarTaken map[string]bool) (int, error) {

	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	stored := 0
	skippedRows := 0
	for _, row := range rows {
		id := row.identity

		statusCodes := make([]int, 0, len(row.statusCodes))
		for code := range row.statusCodes {
			statusCodes = append(statusCodes, code)
		}
		sources := make([]string, 0, len(row.sources))
		for s := range row.sources {
			sources = append(sources, s)
		}
		verbs := make([]string, 0, len(row.observedVerb))
		for v := range row.observedVerb {
			verbs = append(verbs, v)
		}

		methodConfidence := "implied"
		if row.methodKnown {
			methodConfidence = "observed"
		}
		exemplar := false
		if !exemplarTaken[id.TemplateKey] {
			exemplar = true
			exemplarTaken[id.TemplateKey] = true
		}

		statusJSON, _ := json.Marshal(statusCodes)
		sourceCountsJSON, _ := json.Marshal(row.sources)
		flagsJSON, _ := json.Marshal(id.Flags)
		droppedJSON, _ := json.Marshal(id.DroppedParams)
		reqHeadersJSON, _ := json.Marshal(row.reqHeaders)
		respHeadersJSON, _ := json.Marshal(row.respHeaders)

		// Each endpoint is written inside its own savepoint, so one row the database refuses does
		// not take the other 1153 with it.
		//
		// Postgres aborts the whole transaction on the first failed statement: every statement after
		// it fails with "current transaction is aborted", the per-row `continue` below then skipped
		// silently through all of them, and the final Commit rolled back everything. A single URL
		// carrying a %00 in its query was enough to lose an entire consolidation while the log
		// showed one line about one row.
		sp, spErr := tx.Begin(ctx)
		if spErr != nil {
			log.Printf("[CONSOLIDATE] could not open savepoint for %s: %v", row.displayURL, spErr)
			continue
		}

		var endpointID string
		err := sp.QueryRow(ctx, `
			INSERT INTO consolidated_url_endpoints
			  (id, scope_target_id, endpoint_key, url, normalized_url, domain, path, method,
			   is_direct, status_codes, headers, response_headers, request_count, first_seen,
			   last_seen, sources, request_body, content_type,
			   scheme, schemes, port, canonical_path, identity_query, client_route,
			   templated_path, template_key, template_group_size, is_template_exemplar,
			   case_group_key, method_confidence, observed_methods, graphql_operation,
			   content_class, source_counts, capture_count, normalization_flags, dropped_params,
			   last_run_id, last_consolidated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
			        $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,NOW())
			ON CONFLICT (scope_target_id, endpoint_key) DO UPDATE SET
			  url = EXCLUDED.url,
			  domain = EXCLUDED.domain,
			  path = EXCLUDED.path,
			  is_direct = consolidated_url_endpoints.is_direct OR EXCLUDED.is_direct,
			  status_codes = EXCLUDED.status_codes,
			  headers = EXCLUDED.headers,
			  response_headers = EXCLUDED.response_headers,
			  request_count = EXCLUDED.request_count,
			  first_seen = LEAST(consolidated_url_endpoints.first_seen, EXCLUDED.first_seen),
			  last_seen = GREATEST(consolidated_url_endpoints.last_seen, EXCLUDED.last_seen),
			  sources = EXCLUDED.sources,
			  request_body = CASE WHEN EXCLUDED.request_body <> '' THEN EXCLUDED.request_body
			                      ELSE consolidated_url_endpoints.request_body END,
			  content_type = CASE WHEN EXCLUDED.content_type <> '' THEN EXCLUDED.content_type
			                      ELSE consolidated_url_endpoints.content_type END,
			  schemes = EXCLUDED.schemes,
			  templated_path = EXCLUDED.templated_path,
			  template_key = EXCLUDED.template_key,
			  template_group_size = EXCLUDED.template_group_size,
			  is_template_exemplar = EXCLUDED.is_template_exemplar,
			  case_group_key = EXCLUDED.case_group_key,
			  method_confidence = EXCLUDED.method_confidence,
			  observed_methods = EXCLUDED.observed_methods,
			  graphql_operation = EXCLUDED.graphql_operation,
			  content_class = EXCLUDED.content_class,
			  source_counts = EXCLUDED.source_counts,
			  capture_count = EXCLUDED.capture_count,
			  normalization_flags = EXCLUDED.normalization_flags,
			  dropped_params = EXCLUDED.dropped_params,
			  last_run_id = EXCLUDED.last_run_id,
			  last_consolidated_at = NOW()
			RETURNING id`,
			uuid.New().String(), scopeTargetID, id.Key, row.displayURL, id.CanonicalPath,
			id.Host, id.CanonicalPath, id.Method, row.isDirect, statusJSON,
			reqHeadersJSON, respHeadersJSON, row.requestCount, row.firstSeen, row.lastSeen,
			sources, row.requestBody, row.contentType,
			id.Scheme, []string{id.Scheme}, nullInt(id.Port), id.CanonicalPath, id.IdentityQuery,
			id.ClientRoute, id.TemplatedPath, id.TemplateKey, groupSize[id.TemplateKey], exemplar,
			id.CaseGroupKey, methodConfidence, verbs, row.graphQLOp, id.ContentClass,
			sourceCountsJSON, row.captureCount, flagsJSON, droppedJSON, scanID,
		).Scan(&endpointID)
		if err != nil {
			log.Printf("[CONSOLIDATE] failed to store %s: %v", row.displayURL, err)
			_ = sp.Rollback(ctx)
			skippedRows++
			continue
		}

		paramFailed := false
		for _, p := range row.params {
			valuesJSON, _ := json.Marshal(p.ExampleValues)
			if _, perr := sp.Exec(ctx, `
				INSERT INTO consolidated_url_parameters
				  (id, endpoint_id, param_type, param_name, example_values, frequency)
				VALUES ($1, $2, $3, $4, $5::jsonb, $6)
				ON CONFLICT (endpoint_id, param_type, param_name) DO UPDATE SET
				  example_values = EXCLUDED.example_values,
				  frequency = EXCLUDED.frequency`,
				uuid.New().String(), endpointID, p.ParamType, p.ParamName, string(valuesJSON), p.Frequency); perr != nil {
				// Previously discarded with `_, _ =`, which both hid the cause and left the whole
				// transaction aborted.
				log.Printf("[CONSOLIDATE] failed to store parameter %s on %s: %v",
					p.ParamName, row.displayURL, perr)
				paramFailed = true
				break
			}
		}
		if paramFailed {
			_ = sp.Rollback(ctx)
			skippedRows++
			continue
		}
		if cerr := sp.Commit(ctx); cerr != nil {
			log.Printf("[CONSOLIDATE] failed to release savepoint for %s: %v", row.displayURL, cerr)
			skippedRows++
			continue
		}
		stored++
	}

	if skippedRows > 0 {
		// Said out loud: a count that silently differs from the corpus size reads as "these are all
		// the endpoints there are".
		log.Printf("[CONSOLIDATE] %d row(s) could not be stored and are absent from this run's %d endpoints",
			skippedRows, stored)
	}

	if err := tx.Commit(ctx); err != nil {
		return stored, err
	}
	return stored, nil
}

// RefreshConsolidatedParameters reattaches parameters that arjun and x8 discovered.
//
// It only attaches to endpoints that already exist. The previous version also created endpoints
// from parameter rows, which invented surface that no discovery source ever saw.
func RefreshConsolidatedParameters(ctx context.Context, scopeTargetID string) error {
	rows, err := dbPool.Query(ctx, `
		SELECT endpoint_url, parameter_name, parameter_type, COALESCE(example_value,''), scan_type
		FROM parameter_enumeration_results
		WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		// The table is optional; a target that never ran parameter enumeration has none.
		return nil
	}
	defer rows.Close()

	type paramRow struct{ url, name, ptype, value, source string }
	var pending []paramRow
	for rows.Next() {
		var p paramRow
		if rows.Scan(&p.url, &p.name, &p.ptype, &p.value, &p.source) != nil {
			continue
		}
		pending = append(pending, p)
	}
	if len(pending) == 0 {
		return nil
	}

	defaultScheme, _, _ := ScopeTargetBase(scopeTargetID)
	for _, p := range pending {
		id, ok := CanonicalizeEndpoint(p.url, "GET", defaultScheme)
		if !ok {
			continue
		}
		var endpointID string
		if err := dbPool.QueryRow(ctx, `
			SELECT id FROM consolidated_url_endpoints
			WHERE scope_target_id = $1 AND endpoint_key = $2 AND deleted_at IS NULL`,
			scopeTargetID, id.Key).Scan(&endpointID); err != nil {
			continue // a parameter for an endpoint nobody discovered is not surface
		}
		values := []string{}
		if p.value != "" {
			values = append(values, p.value)
		}
		valuesJSON, _ := json.Marshal(values)
		ptype := p.ptype
		if ptype == "" {
			ptype = "query"
		}
		_, _ = dbPool.Exec(ctx, `
			INSERT INTO consolidated_url_parameters
			  (id, endpoint_id, param_type, param_name, example_values, frequency)
			VALUES ($1, $2, $3, $4, $5::jsonb, 1)
			ON CONFLICT (endpoint_id, param_type, param_name) DO UPDATE SET
			  frequency = consolidated_url_parameters.frequency + 1`,
			uuid.New().String(), endpointID, ptype, p.name, string(valuesJSON))
	}
	return nil
}

func finishConsolidation(scanID, status string, count, read int, skipped map[string]int, errMsg string, started time.Time) {
	if skipped == nil {
		skipped = map[string]int{}
	}
	skippedJSON, _ := json.Marshal(skipped)
	resultJSON, _ := json.Marshal(map[string]interface{}{
		"endpoint_count": count,
		"rows_read":      read,
		"skipped":        skipped,
		"sources":        consolidationScanTypes,
	})
	_, err := dbPool.Exec(context.Background(), `
		UPDATE endpoint_consolidation_runs
		SET status = $1, endpoint_count = $2, rows_read = $3, skipped = $4, result = $5,
		    error = $6, execution_time = $7, updated_at = NOW()
		WHERE scan_id = $8`,
		status, count, read, skippedJSON, string(resultJSON), errMsg,
		time.Since(started).String(), scanID)
	if err != nil {
		log.Printf("[CONSOLIDATE] failed to finish run %s: %v", scanID, err)
	}
	log.Printf("[CONSOLIDATE] %s finished: status=%s endpoints=%d read=%d in %s",
		scanID, status, count, read, time.Since(started))
}

// GetConsolidationStatus handles GET /consolidated-endpoints/{scope_target_id}/status/{scan_id}.
func GetConsolidationStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]

	var out struct {
		ScanID        string    `json:"scan_id"`
		Status        string    `json:"status"`
		EndpointCount int       `json:"endpoint_count"`
		RowsRead      int       `json:"rows_read"`
		Skipped       []byte    `json:"-"`
		Error         *string   `json:"error"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
	}
	err := dbPool.QueryRow(context.Background(), `
		SELECT scan_id, status, endpoint_count, rows_read, skipped, error, execution_time, created_at
		FROM endpoint_consolidation_runs WHERE scan_id = $1`, scanID).Scan(
		&out.ScanID, &out.Status, &out.EndpointCount, &out.RowsRead, &out.Skipped,
		&out.Error, &out.ExecutionTime, &out.CreatedAt)
	if err != nil {
		http.Error(w, "Consolidation run not found", http.StatusNotFound)
		return
	}

	var skipped map[string]int
	_ = json.Unmarshal(out.Skipped, &skipped)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": out.ScanID, "status": out.Status, "endpoint_count": out.EndpointCount,
		"rows_read": out.RowsRead, "skipped": skipped, "error": out.Error,
		"execution_time": out.ExecutionTime, "created_at": out.CreatedAt,
	})
}

func nullInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}
