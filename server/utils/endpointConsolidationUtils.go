package utils

// Read paths and shared types for consolidated endpoints.
//
// The consolidation run itself lives in endpointConsolidationRun.go. The functions that used to be
// here were removed rather than deprecated: consolidateFFUFEndpoints because FFUF now runs later in
// the workflow, and the rest because two consolidation paths would drift apart and only one of them
// would be the one being fixed.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

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

	// Validation ledger, cached onto the row so the list query does not have to join. Pointers
	// where absent is meaningful: a nil Testable means unknown, which is not the same as false and
	// still gets tested downstream.
	ValidationStatus     string  `json:"validation_status"`
	ValidationReasonCode *string `json:"validation_reason_code"`
	ValidationReason     *string `json:"validation_reason"`
	ValidationConfidence *string `json:"validation_confidence"`
	ValidationTestable   *bool   `json:"validation_testable"`

	// The operator's word, which outranks the scan's.
	OverrideStatus *string `json:"override_status"`
	OverrideNote   *string `json:"override_note"`
	ManualAdded    bool    `json:"manual_added"`
	Pinned         bool    `json:"pinned"`
	Notes          string  `json:"notes"`

	DeletedAt     *time.Time `json:"deleted_at"`
	DeletedReason *string    `json:"deleted_reason"`
	UnseenSince   *time.Time `json:"unseen_since"`

	ContentClass      string `json:"content_class"`
	TemplatedPath     string `json:"templated_path"`
	TemplateGroupSize int    `json:"template_group_size"`
	MethodConfidence  string `json:"method_confidence"`
}

type ConsolidatedParameter struct {
	ID            string   `json:"id"`
	EndpointID    string   `json:"endpoint_id"`
	ParamType     string   `json:"param_type"`
	ParamName     string   `json:"param_name"`
	ExampleValues []string `json:"example_values"`
	Frequency     int      `json:"frequency"`
}

func GetConsolidatedURLEndpoints(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	// The parameters used to be fetched with a query per endpoint, which is a thousand round trips
	// on a real target. One lateral join instead.
	query := `
		SELECT e.id, e.scope_target_id, e.url, e.normalized_url, e.domain, e.path, e.method,
		       e.is_direct, e.origin_url, e.status_codes, e.headers, e.response_headers,
		       e.request_count, e.first_seen, e.last_seen, e.sources,
		       COALESCE(e.request_body,''), COALESCE(e.content_type,''),
		       COALESCE(e.validation_status,'not_validated'), e.validation_reason_code,
		       e.validation_reason, e.validation_confidence, e.validation_testable,
		       e.override_status, e.override_note, e.manual_added, e.pinned, COALESCE(e.notes,''),
		       e.deleted_at, e.deleted_reason, COALESCE(e.content_class,'unknown'),
		       COALESCE(e.templated_path,''), COALESCE(e.template_group_size,1),
		       COALESCE(e.method_confidence,'implied'), e.unseen_since,
		       COALESCE(p.params, '[]'::json)
		FROM consolidated_url_endpoints e
		LEFT JOIN LATERAL (
		  SELECT json_agg(json_build_object(
		    'id', cp.id, 'endpoint_id', cp.endpoint_id, 'param_type', cp.param_type,
		    'param_name', cp.param_name, 'example_values', cp.example_values,
		    'frequency', cp.frequency)) AS params
		  FROM consolidated_url_parameters cp WHERE cp.endpoint_id = e.id
		) p ON TRUE
		WHERE e.scope_target_id = $1
		ORDER BY e.is_direct DESC, e.domain, e.path
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
		var statusCodesJSON, headersJSON, responseHeadersJSON, paramsJSON []byte

		err := rows.Scan(
			&endpoint.ID, &endpoint.ScopeTargetID, &endpoint.URL, &endpoint.NormalizedURL,
			&endpoint.Domain, &endpoint.Path, &endpoint.Method, &endpoint.IsDirect, &endpoint.OriginURL,
			&statusCodesJSON, &headersJSON, &responseHeadersJSON,
			&endpoint.RequestCount, &endpoint.FirstSeen, &endpoint.LastSeen, &endpoint.Sources,
			&endpoint.RequestBody, &endpoint.ContentType,
			&endpoint.ValidationStatus, &endpoint.ValidationReasonCode, &endpoint.ValidationReason,
			&endpoint.ValidationConfidence, &endpoint.ValidationTestable,
			&endpoint.OverrideStatus, &endpoint.OverrideNote, &endpoint.ManualAdded,
			&endpoint.Pinned, &endpoint.Notes, &endpoint.DeletedAt, &endpoint.DeletedReason,
			&endpoint.ContentClass, &endpoint.TemplatedPath, &endpoint.TemplateGroupSize,
			&endpoint.MethodConfidence, &endpoint.UnseenSince,
			&paramsJSON,
		)

		if err != nil {
			log.Printf("[ERROR] Failed to scan endpoint row: %v", err)
			continue
		}

		json.Unmarshal(statusCodesJSON, &endpoint.StatusCodes)
		json.Unmarshal(headersJSON, &endpoint.Headers)
		json.Unmarshal(responseHeadersJSON, &endpoint.ResponseHeaders)
		json.Unmarshal(paramsJSON, &endpoint.Parameters)

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

// consolidateEnumeratedParameters folds Arjun / x8 findings onto the endpoints they were
// discovered against. Hidden parameters are the whole point of running those tools, and until now
// they never reached the consolidated attack surface that everything downstream reads.

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
