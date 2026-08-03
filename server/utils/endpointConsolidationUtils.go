package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

type ConsolidatedEndpoint struct {
	ID              string                 `json:"id"`
	ScopeTargetID   string                 `json:"scope_target_id"`
	URL             string                 `json:"url"`
	NormalizedURL   string                 `json:"normalized_url"`
	Domain          string                 `json:"domain"`
	Path            string                 `json:"path"`
	Method          string                 `json:"method"`
	IsDirect        bool                   `json:"is_direct"`
	OriginURL       *string                `json:"origin_url,omitempty"`
	StatusCodes     []int                  `json:"status_codes"`
	Headers         map[string]interface{} `json:"headers"`
	ResponseHeaders map[string]interface{} `json:"response_headers"`
	// The recorded request body and its content type, so the raw request rebuilt downstream (IDOR
	// work, auth-flow import) is the real one rather than a request line with no payload.
	RequestBody  string                  `json:"request_body"`
	ContentType  string                  `json:"content_type"`
	RequestCount int                     `json:"request_count"`
	FirstSeen    time.Time               `json:"first_seen"`
	LastSeen     time.Time               `json:"last_seen"`
	Sources      []string                `json:"sources"`
	Parameters   []ConsolidatedParameter `json:"parameters"`
}

type ConsolidatedParameter struct {
	ID            string   `json:"id"`
	EndpointID    string   `json:"endpoint_id"`
	ParamType     string   `json:"param_type"`
	ParamName     string   `json:"param_name"`
	ExampleValues []string `json:"example_values"`
	Frequency     int      `json:"frequency"`
}

func ConsolidateURLEndpoints(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	log.Printf("[CONSOLIDATE] Starting endpoint consolidation for scope target: %s", scopeTargetID)

	_, err := dbPool.Exec(context.Background(), `DELETE FROM consolidated_url_endpoints WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to clear existing consolidated endpoints: %v", err)
		http.Error(w, "Failed to clear existing data", http.StatusInternalServerError)
		return
	}

	// Resolved once and threaded through: this used to run a database round trip for every single
	// capture row being consolidated.
	targetDomain := extractDomainFromScopeTarget(scopeTargetID)

	endpointMap := make(map[string]*ConsolidatedEndpoint)

	err = consolidateDiscoveredEndpoints(scopeTargetID, endpointMap)
	if err != nil {
		log.Printf("[ERROR] Failed to consolidate discovered endpoints: %v", err)
		http.Error(w, "Failed to consolidate discovered endpoints", http.StatusInternalServerError)
		return
	}

	err = consolidateManualCrawlEndpoints(scopeTargetID, targetDomain, endpointMap)
	if err != nil {
		log.Printf("[ERROR] Failed to consolidate manual crawl endpoints: %v", err)
		http.Error(w, "Failed to consolidate manual crawl endpoints", http.StatusInternalServerError)
		return
	}

	err = consolidateFFUFEndpoints(scopeTargetID, targetDomain, endpointMap)
	if err != nil {
		log.Printf("[ERROR] Failed to consolidate FFUF endpoints: %v", err)
	}

	// Hidden parameters found by Arjun / parameth / x8 used to be a dead end: they were written to
	// parameter_enumeration_results and read back only by their own results modals, so
	// re-consolidating discarded them and nothing downstream ever saw them.
	err = consolidateEnumeratedParameters(scopeTargetID, endpointMap)
	if err != nil {
		log.Printf("[ERROR] Failed to consolidate enumerated parameters: %v", err)
	}

	err = storeConsolidatedEndpoints(scopeTargetID, endpointMap)
	if err != nil {
		log.Printf("[ERROR] Failed to store consolidated endpoints: %v", err)
		http.Error(w, "Failed to store consolidated endpoints", http.StatusInternalServerError)
		return
	}

	log.Printf("[CONSOLIDATE] Successfully consolidated %d unique endpoints", len(endpointMap))

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":         true,
		"endpoint_count":  len(endpointMap),
		"scope_target_id": scopeTargetID,
	})
}

func normalizeURL(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	urlStr = strings.TrimSuffix(urlStr, ".")
	
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}
	
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return strings.TrimSuffix(urlStr, "/")
	}
	
	parsedURL.Host = strings.TrimSuffix(parsedURL.Host, ".")
	
	parsedURL.Path = strings.TrimSuffix(parsedURL.Path, "/")
	if parsedURL.Path == "" {
		parsedURL.Path = "/"
	}
	
	parsedURL.Fragment = ""
	parsedURL.RawQuery = ""
	
	return parsedURL.String()
}

func consolidateDiscoveredEndpoints(scopeTargetID string, endpointMap map[string]*ConsolidatedEndpoint) error {
	query := `
		SELECT de.url, de.domain, de.path, de.normalized_path, de.status_code, de.is_direct, de.scan_type,
		       ep.param_type, ep.param_name, ep.example_value
		FROM discovered_endpoints de
		LEFT JOIN endpoint_parameters ep ON ep.endpoint_id = de.id
		WHERE de.scope_target_id = $1
		ORDER BY de.url
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		return fmt.Errorf("failed to query discovered endpoints: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var urlStr, domain, path, normalizedPath, scanType string
		var statusCode *int
		var isDirect bool
		var paramType, paramName, exampleValue *string

		err := rows.Scan(&urlStr, &domain, &path, &normalizedPath, &statusCode, &isDirect, &scanType,
			&paramType, &paramName, &exampleValue)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}
		
		if path == "" {
			path = "/"
		} else if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		normalizedURL := normalizeURL(urlStr)
		key := fmt.Sprintf("%s|GET", normalizedURL)
		
		if endpoint, exists := endpointMap[key]; exists {
			if !contains(endpoint.Sources, scanType) {
				endpoint.Sources = append(endpoint.Sources, scanType)
			}
			if statusCode != nil && !containsInt(endpoint.StatusCodes, *statusCode) {
				endpoint.StatusCodes = append(endpoint.StatusCodes, *statusCode)
			}
			endpoint.RequestCount++
			endpoint.LastSeen = time.Now()
		} else {
			endpoint := &ConsolidatedEndpoint{
				ScopeTargetID: scopeTargetID,
				URL:           normalizedURL,
				NormalizedURL: normalizedPath,
				Domain:        domain,
				Path:          path,
				Method:        "GET",
				IsDirect:      isDirect,
				StatusCodes:   []int{},
				Sources:       []string{scanType},
				RequestCount:  1,
				FirstSeen:     time.Now(),
				LastSeen:      time.Now(),
				Parameters:    []ConsolidatedParameter{},
				Headers:       make(map[string]interface{}),
				ResponseHeaders: make(map[string]interface{}),
			}

			if statusCode != nil {
				endpoint.StatusCodes = append(endpoint.StatusCodes, *statusCode)
			}

			endpointMap[key] = endpoint
		}

		if paramType != nil && paramName != nil && *paramType != "path" {
			endpoint := endpointMap[key]
			found := false
			for i := range endpoint.Parameters {
				if endpoint.Parameters[i].ParamType == *paramType && endpoint.Parameters[i].ParamName == *paramName {
					if exampleValue != nil && !contains(endpoint.Parameters[i].ExampleValues, *exampleValue) {
						endpoint.Parameters[i].ExampleValues = append(endpoint.Parameters[i].ExampleValues, *exampleValue)
					}
					endpoint.Parameters[i].Frequency++
					found = true
					break
				}
			}
			if !found && paramName != nil {
				param := ConsolidatedParameter{
					ParamType:     *paramType,
					ParamName:     *paramName,
					ExampleValues: []string{},
					Frequency:     1,
				}
				if exampleValue != nil {
					param.ExampleValues = append(param.ExampleValues, *exampleValue)
				}
				endpoint.Parameters = append(endpoint.Parameters, param)
			}
		}
	}

	log.Printf("[CONSOLIDATE] Processed discovered endpoints from automated tools")
	return nil
}

func consolidateManualCrawlEndpoints(scopeTargetID, targetDomain string, endpointMap map[string]*ConsolidatedEndpoint) error {
	query := `
		SELECT url, endpoint, method, status_code, headers, response_headers, get_params, post_params,
		       mime_type, COALESCE(post_data,''), COALESCE(body_type,'')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp ASC
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		return fmt.Errorf("failed to query manual crawl captures: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var urlStr, endpoint, method, postData, bodyType string
		var statusCode *int
		var headersJSON, responseHeadersJSON, getParamsJSON, postParamsJSON []byte
		var mimeType *string

		err := rows.Scan(&urlStr, &endpoint, &method, &statusCode, &headersJSON, &responseHeadersJSON,
			&getParamsJSON, &postParamsJSON, &mimeType, &postData, &bodyType)
		if err != nil {
			log.Printf("[ERROR] Failed to scan manual crawl row: %v", err)
			continue
		}

		parsedURL, err := url.Parse(urlStr)
		if err != nil {
			continue
		}

		domain := parsedURL.Hostname()
		path := parsedURL.Path
		isDirect := (domain == targetDomain)

		normalizedURL := normalizeURL(urlStr)
		key := fmt.Sprintf("%s|%s", normalizedURL, method)

		if endpoint, exists := endpointMap[key]; exists {
			if !contains(endpoint.Sources, "manual_crawl") {
				endpoint.Sources = append(endpoint.Sources, "manual_crawl")
			}
			if statusCode != nil && !containsInt(endpoint.StatusCodes, *statusCode) {
				endpoint.StatusCodes = append(endpoint.StatusCodes, *statusCode)
			}
			// Real headers and bodies only exist on captures, so let a capture fill them in even
			// when a crawler got here first with a bare URL.
			mergeHeaderMap(&endpoint.Headers, headersJSON)
			mergeHeaderMap(&endpoint.ResponseHeaders, responseHeadersJSON)
			if endpoint.RequestBody == "" && postData != "" {
				endpoint.RequestBody = postData
				endpoint.ContentType = bodyType
			}
			endpoint.RequestCount++
			endpoint.LastSeen = time.Now()
		} else {
			endpoint := &ConsolidatedEndpoint{
				ScopeTargetID: scopeTargetID,
				URL:           normalizedURL,
				NormalizedURL: path,
				Domain:        domain,
				Path:          path,
				Method:        method,
				IsDirect:      isDirect,
				StatusCodes:   []int{},
				Sources:       []string{"manual_crawl"},
				RequestCount:  1,
				FirstSeen:     time.Now(),
				LastSeen:      time.Now(),
				Parameters:    []ConsolidatedParameter{},
				Headers:       make(map[string]interface{}),
				ResponseHeaders: make(map[string]interface{}),
			}

			if statusCode != nil {
				endpoint.StatusCodes = append(endpoint.StatusCodes, *statusCode)
			}

			if len(headersJSON) > 0 {
				json.Unmarshal(headersJSON, &endpoint.Headers)
			}
			if len(responseHeadersJSON) > 0 {
				json.Unmarshal(responseHeadersJSON, &endpoint.ResponseHeaders)
			}
			endpoint.RequestBody = postData
			endpoint.ContentType = bodyType

			endpointMap[key] = endpoint
		}

		currentEndpoint := endpointMap[key]

		if len(getParamsJSON) > 0 {
			var getParams map[string]interface{}
			if json.Unmarshal(getParamsJSON, &getParams) == nil {
				for paramName, paramValue := range getParams {
					found := false
					for i := range currentEndpoint.Parameters {
						if currentEndpoint.Parameters[i].ParamType == "query" && currentEndpoint.Parameters[i].ParamName == paramName {
							if valueStr := fmt.Sprintf("%v", paramValue); !contains(currentEndpoint.Parameters[i].ExampleValues, valueStr) {
								currentEndpoint.Parameters[i].ExampleValues = append(currentEndpoint.Parameters[i].ExampleValues, valueStr)
							}
							currentEndpoint.Parameters[i].Frequency++
							found = true
							break
						}
					}
					if !found {
						param := ConsolidatedParameter{
							ParamType:     "query",
							ParamName:     paramName,
							ExampleValues: []string{fmt.Sprintf("%v", paramValue)},
							Frequency:     1,
						}
						currentEndpoint.Parameters = append(currentEndpoint.Parameters, param)
					}
				}
			}
		}

		if len(postParamsJSON) > 0 {
			var postParams map[string]interface{}
			if json.Unmarshal(postParamsJSON, &postParams) == nil {
				for paramName, paramValue := range postParams {
					found := false
					for i := range currentEndpoint.Parameters {
						if currentEndpoint.Parameters[i].ParamType == "body" && currentEndpoint.Parameters[i].ParamName == paramName {
							if valueStr := fmt.Sprintf("%v", paramValue); !contains(currentEndpoint.Parameters[i].ExampleValues, valueStr) {
								currentEndpoint.Parameters[i].ExampleValues = append(currentEndpoint.Parameters[i].ExampleValues, valueStr)
							}
							currentEndpoint.Parameters[i].Frequency++
							found = true
							break
						}
					}
					if !found {
						param := ConsolidatedParameter{
							ParamType:     "body",
							ParamName:     paramName,
							ExampleValues: []string{fmt.Sprintf("%v", paramValue)},
							Frequency:     1,
						}
						currentEndpoint.Parameters = append(currentEndpoint.Parameters, param)
					}
				}
			}
		}
	}

	log.Printf("[CONSOLIDATE] Processed manual crawl endpoints")
	return nil
}

func consolidateFFUFEndpoints(scopeTargetID, targetDomain string, endpointMap map[string]*ConsolidatedEndpoint) error {
	query := `
		SELECT url, result
		FROM ffuf_url_scans
		WHERE scope_target_id = $1 
		  AND status = 'success'
		  AND id = (
		    SELECT id 
		    FROM ffuf_url_scans 
		    WHERE scope_target_id = $1 AND status = 'success'
		    ORDER BY created_at DESC 
		    LIMIT 1
		  )
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		return fmt.Errorf("failed to query FFUF scans: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var targetURL string
		var resultJSON *string

		if err := rows.Scan(&targetURL, &resultJSON); err != nil {
			log.Printf("[ERROR] Failed to scan FFUF row: %v", err)
			continue
		}

		if resultJSON == nil {
			continue
		}

		var ffufResult struct {
			Endpoints []struct {
				Path   string `json:"path"`
				Status int64  `json:"status"`
			} `json:"endpoints"`
		}

		if err := json.Unmarshal([]byte(*resultJSON), &ffufResult); err != nil {
			log.Printf("[ERROR] Failed to parse FFUF result: %v", err)
			continue
		}

		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			continue
		}

		for _, result := range ffufResult.Endpoints {
			path := result.Path
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
			fullURL := fmt.Sprintf("%s://%s%s", parsedURL.Scheme, parsedURL.Host, path)
			domain := parsedURL.Hostname()
			isDirect := (domain == targetDomain)

			normalizedURL := normalizeURL(fullURL)
			key := fmt.Sprintf("%s|GET", normalizedURL)

			if endpoint, exists := endpointMap[key]; exists {
				if !contains(endpoint.Sources, "ffuf") {
					endpoint.Sources = append(endpoint.Sources, "ffuf")
				}
				if !containsInt(endpoint.StatusCodes, int(result.Status)) {
					endpoint.StatusCodes = append(endpoint.StatusCodes, int(result.Status))
				}
				endpoint.RequestCount++
				endpoint.LastSeen = time.Now()
			} else {
				endpoint := &ConsolidatedEndpoint{
					ScopeTargetID: scopeTargetID,
					URL:           normalizedURL,
					NormalizedURL: path,
					Domain:        domain,
					Path:          path,
					Method:        "GET",
					IsDirect:      isDirect,
					StatusCodes:   []int{int(result.Status)},
					Sources:       []string{"ffuf"},
					RequestCount:  1,
					FirstSeen:     time.Now(),
					LastSeen:      time.Now(),
					Parameters:    []ConsolidatedParameter{},
					Headers:       make(map[string]interface{}),
					ResponseHeaders: make(map[string]interface{}),
				}
				endpointMap[key] = endpoint
			}
		}
	}

	log.Printf("[CONSOLIDATE] Processed FFUF endpoints from latest scan")
	return nil
}

func storeConsolidatedEndpoints(scopeTargetID string, endpointMap map[string]*ConsolidatedEndpoint) error {
	for _, endpoint := range endpointMap {
		endpointID := uuid.New().String()
		endpoint.ID = endpointID

		statusCodesJSON, _ := json.Marshal(endpoint.StatusCodes)
		headersJSON, _ := json.Marshal(endpoint.Headers)
		responseHeadersJSON, _ := json.Marshal(endpoint.ResponseHeaders)

		query := `
			INSERT INTO consolidated_url_endpoints 
			(id, scope_target_id, url, normalized_url, domain, path, method, is_direct, status_codes, 
			 headers, response_headers, request_count, first_seen, last_seen, sources,
			 request_body, content_type)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)
			ON CONFLICT (scope_target_id, url, method) 
			DO UPDATE SET 
				request_count = EXCLUDED.request_count,
				last_seen = EXCLUDED.last_seen,
				status_codes = EXCLUDED.status_codes,
				sources = EXCLUDED.sources,
				headers = EXCLUDED.headers,
				response_headers = EXCLUDED.response_headers,
				request_body = EXCLUDED.request_body,
				content_type = EXCLUDED.content_type
			RETURNING id
		`

		err := dbPool.QueryRow(context.Background(), query,
			endpointID, scopeTargetID, endpoint.URL, endpoint.NormalizedURL, endpoint.Domain,
			endpoint.Path, endpoint.Method, endpoint.IsDirect, statusCodesJSON,
			headersJSON, responseHeadersJSON, endpoint.RequestCount,
			endpoint.FirstSeen, endpoint.LastSeen, endpoint.Sources,
			endpoint.RequestBody, endpoint.ContentType,
		).Scan(&endpointID)

		if err != nil {
			log.Printf("[ERROR] Failed to store endpoint %s: %v", endpoint.URL, err)
			continue
		}

		for _, param := range endpoint.Parameters {
			paramID := uuid.New().String()
			exampleValuesJSON, _ := json.Marshal(param.ExampleValues)

			paramQuery := `
				INSERT INTO consolidated_url_parameters 
				(id, endpoint_id, param_type, param_name, example_values, frequency)
				VALUES ($1, $2, $3, $4, $5::jsonb, $6)
				ON CONFLICT (endpoint_id, param_type, param_name)
				DO UPDATE SET 
					example_values = EXCLUDED.example_values,
					frequency = EXCLUDED.frequency
			`

			_, err := dbPool.Exec(context.Background(), paramQuery,
				paramID, endpointID, param.ParamType, param.ParamName, string(exampleValuesJSON), param.Frequency)

			if err != nil {
				log.Printf("[ERROR] Failed to store parameter %s: %v", param.ParamName, err)
			}
		}
	}

	return nil
}

func GetConsolidatedURLEndpoints(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `
		SELECT id, scope_target_id, url, normalized_url, domain, path, method, is_direct, origin_url,
		       status_codes, headers, response_headers, request_count, first_seen, last_seen, sources,
		       COALESCE(request_body,''), COALESCE(content_type,'')
		FROM consolidated_url_endpoints
		WHERE scope_target_id = $1
		ORDER BY is_direct DESC, domain, path
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to query consolidated endpoints: %v", err)
		http.Error(w, "Failed to query endpoints", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	endpoints := []ConsolidatedEndpoint{}

	for rows.Next() {
		var endpoint ConsolidatedEndpoint
		var statusCodesJSON, headersJSON, responseHeadersJSON []byte

		err := rows.Scan(
			&endpoint.ID, &endpoint.ScopeTargetID, &endpoint.URL, &endpoint.NormalizedURL,
			&endpoint.Domain, &endpoint.Path, &endpoint.Method, &endpoint.IsDirect, &endpoint.OriginURL,
			&statusCodesJSON, &headersJSON, &responseHeadersJSON,
			&endpoint.RequestCount, &endpoint.FirstSeen, &endpoint.LastSeen, &endpoint.Sources,
			&endpoint.RequestBody, &endpoint.ContentType,
		)

		if err != nil {
			log.Printf("[ERROR] Failed to scan endpoint row: %v", err)
			continue
		}

		json.Unmarshal(statusCodesJSON, &endpoint.StatusCodes)
		json.Unmarshal(headersJSON, &endpoint.Headers)
		json.Unmarshal(responseHeadersJSON, &endpoint.ResponseHeaders)

		paramQuery := `
			SELECT id, endpoint_id, param_type, param_name, example_values, frequency
			FROM consolidated_url_parameters
			WHERE endpoint_id = $1
		`

		paramRows, err := dbPool.Query(context.Background(), paramQuery, endpoint.ID)
		if err == nil {
			for paramRows.Next() {
				var param ConsolidatedParameter
				var exampleValuesJSON []byte

				if err := paramRows.Scan(&param.ID, &param.EndpointID, &param.ParamType, &param.ParamName, &exampleValuesJSON, &param.Frequency); err == nil {
					json.Unmarshal(exampleValuesJSON, &param.ExampleValues)
					endpoint.Parameters = append(endpoint.Parameters, param)
				}
			}
			paramRows.Close()
		}

		endpoints = append(endpoints, endpoint)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(endpoints)
}

// mergeHeaderMap folds a captured header blob into an existing map without dropping what is
// already there. Crawlers create endpoints with no headers at all, so a later capture is usually
// the only chance to attach the real ones.
func mergeHeaderMap(target *map[string]interface{}, headersJSON []byte) {
	if len(headersJSON) == 0 {
		return
	}
	var incoming map[string]interface{}
	if json.Unmarshal(headersJSON, &incoming) != nil {
		return
	}
	if *target == nil {
		*target = make(map[string]interface{})
	}
	for name, value := range incoming {
		if _, exists := (*target)[name]; !exists {
			(*target)[name] = value
		}
	}
}

// consolidateEnumeratedParameters folds Arjun / parameth / x8 findings onto the endpoints they were
// discovered against. Hidden parameters are the whole point of running those tools, and until now
// they never reached the consolidated attack surface that everything downstream reads.
func consolidateEnumeratedParameters(scopeTargetID string, endpointMap map[string]*ConsolidatedEndpoint) error {
	query := `
		SELECT endpoint_url, parameter_name, parameter_type, COALESCE(example_value,''), scan_type
		FROM parameter_enumeration_results
		WHERE scope_target_id = $1
	`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		return fmt.Errorf("failed to query parameter enumeration results: %w", err)
	}
	defer rows.Close()

	attached := 0
	for rows.Next() {
		var endpointURL, paramName, paramType, exampleValue, scanType string
		if err := rows.Scan(&endpointURL, &paramName, &paramType, &exampleValue, &scanType); err != nil {
			continue
		}
		if paramName == "" {
			continue
		}

		if paramType == "" {
			paramType = "query"
		}

		normalizedURL := normalizeURL(endpointURL)

		// These tools probe a URL, not a verb, so attach the finding to every method recorded for
		// that URL rather than assuming GET.
		matched := false
		for key, endpoint := range endpointMap {
			if !strings.HasPrefix(key, normalizedURL+"|") {
				continue
			}
			matched = true
			addOrMergeParameter(endpoint, paramType, paramName, exampleValue)
			if !contains(endpoint.Sources, scanType) {
				endpoint.Sources = append(endpoint.Sources, scanType)
			}
			attached++
		}

		// The endpoint may have been discovered only by the parameter tool itself.
		if !matched {
			key := fmt.Sprintf("%s|GET", normalizedURL)
			parsed, perr := url.Parse(normalizedURL)
			if perr != nil {
				continue
			}
			endpoint := &ConsolidatedEndpoint{
				ScopeTargetID:   scopeTargetID,
				URL:             normalizedURL,
				NormalizedURL:   parsed.Path,
				Domain:          parsed.Hostname(),
				Path:            parsed.Path,
				Method:          "GET",
				IsDirect:        true,
				StatusCodes:     []int{},
				Sources:         []string{scanType},
				RequestCount:    1,
				FirstSeen:       time.Now(),
				LastSeen:        time.Now(),
				Parameters:      []ConsolidatedParameter{},
				Headers:         make(map[string]interface{}),
				ResponseHeaders: make(map[string]interface{}),
			}
			addOrMergeParameter(endpoint, paramType, paramName, exampleValue)
			endpointMap[key] = endpoint
			attached++
		}
	}

	log.Printf("[CONSOLIDATE] Attached %d enumerated parameter findings", attached)
	return nil
}

func addOrMergeParameter(endpoint *ConsolidatedEndpoint, paramType, paramName, exampleValue string) {
	for i := range endpoint.Parameters {
		if endpoint.Parameters[i].ParamType == paramType && endpoint.Parameters[i].ParamName == paramName {
			if exampleValue != "" && !contains(endpoint.Parameters[i].ExampleValues, exampleValue) {
				endpoint.Parameters[i].ExampleValues = append(endpoint.Parameters[i].ExampleValues, exampleValue)
			}
			endpoint.Parameters[i].Frequency++
			return
		}
	}

	param := ConsolidatedParameter{
		ParamType:     paramType,
		ParamName:     paramName,
		ExampleValues: []string{},
		Frequency:     1,
	}
	if exampleValue != "" {
		param.ExampleValues = append(param.ExampleValues, exampleValue)
	}
	endpoint.Parameters = append(endpoint.Parameters, param)
}

func extractDomainFromScopeTarget(scopeTargetID string) string {
	var scopeTarget string
	query := `SELECT scope_target FROM scope_targets WHERE id = $1`
	err := dbPool.QueryRow(context.Background(), query, scopeTargetID).Scan(&scopeTarget)
	if err != nil {
		return ""
	}

	if strings.HasPrefix(scopeTarget, "http://") || strings.HasPrefix(scopeTarget, "https://") {
		parsedURL, err := url.Parse(scopeTarget)
		if err == nil {
			return parsedURL.Hostname()
		}
	}

	return scopeTarget
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func containsInt(slice []int, item int) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
