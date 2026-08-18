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

// Manage Endpoints: the operator's control over the list.
//
// Deletion is soft. A hunter who deletes 3,000 rows because they looked like noise, and then
// realises one of them was the finding, needs them back; a hard DELETE makes that impossible and
// the next Consolidate would resurrect them anyway with their verdicts lost. Soft deletion also
// keeps the row out of every downstream tool's query without changing what discovery observed.
//
// Manual additions are the reason Consolidate no longer starts with DELETE. They are marked
// manual_added and are never touched by a run, so an endpoint learned from a report or a proxy log
// survives every re-consolidation.

// AddManualEndpoint handles POST /consolidated-endpoints/{scope_target_id}/add.
//
// Accepts either one URL or a newline-separated list, so pasting a block from a proxy or a report
// is one action rather than fifty.
func AddManualEndpoint(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		URLs   string `json:"urls"`
		URL    string `json:"url"`
		Method string `json:"method"`
		Notes  string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	raw := payload.URLs
	if raw == "" {
		raw = payload.URL
	}
	if strings.TrimSpace(raw) == "" {
		http.Error(w, "Provide at least one URL", http.StatusBadRequest)
		return
	}

	defaultScheme, _, baseURL := ScopeTargetBase(scopeTargetID)
	targetDomain := extractDomainFromScopeTarget(scopeTargetID)
	method := strings.ToUpper(strings.TrimSpace(payload.Method))
	if method == "" {
		method = "GET"
	}

	added, restored := 0, 0
	var rejected []string

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// A pasted line may carry its own verb: "POST /api/users".
		lineMethod := method
		if parts := strings.Fields(line); len(parts) == 2 && isHTTPVerb(parts[0]) {
			lineMethod = strings.ToUpper(parts[0])
			line = parts[1]
		}

		// A bare path is what an operator actually types, and what they paste out of a report or a
		// proxy log. Resolve it against the scope target rather than rejecting it.
		if strings.HasPrefix(line, "/") && !strings.HasPrefix(line, "//") {
			line = strings.TrimSuffix(baseURL, "/") + line
		}

		id, ok := CanonicalizeEndpoint(line, lineMethod, defaultScheme)
		if !ok {
			rejected = append(rejected, line)
			continue
		}

		isDirect := targetDomain == "" || strings.HasSuffix(id.Host, targetDomain)
		flagsJSON, _ := json.Marshal(id.Flags)

		// A manual add of something already present un-deletes it rather than erroring, which is
		// what an operator means when they re-add a row they deleted by mistake.
		//
		// Whether it WAS deleted has to be read before the upsert. RETURNING deleted_at after a
		// DO UPDATE that sets deleted_at = NULL returns the value it just set, so the restored
		// counter could never be anything but zero and the one flow this comment describes was the
		// one flow that never reported itself.
		var wasDeleted *time.Time
		_ = dbPool.QueryRow(context.Background(),
			`SELECT deleted_at FROM consolidated_url_endpoints
			 WHERE scope_target_id = $1 AND endpoint_key = $2`,
			scopeTargetID, id.Key).Scan(&wasDeleted)

		var ignoredDeletedAt *time.Time
		err := dbPool.QueryRow(context.Background(), `
			INSERT INTO consolidated_url_endpoints
			  (id, scope_target_id, endpoint_key, url, normalized_url, domain, path, method,
			   is_direct, status_codes, headers, response_headers, request_count, first_seen,
			   last_seen, sources, scheme, canonical_path, identity_query, client_route,
			   templated_path, template_key, case_group_key, method_confidence, observed_methods,
			   content_class, normalization_flags, manual_added, notes, validation_status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'[]'::jsonb,'{}'::jsonb,'{}'::jsonb,0,NOW(),NOW(),
			        ARRAY['manual'],$10,$11,$12,$13,$14,$15,$16,'declared',$17,$18,$19,TRUE,$20,
			        'not_validated')
			ON CONFLICT (scope_target_id, endpoint_key) DO UPDATE SET
			  manual_added = TRUE,
			  deleted_at = NULL,
			  deleted_reason = NULL,
			  notes = CASE WHEN EXCLUDED.notes <> '' THEN EXCLUDED.notes
			               ELSE consolidated_url_endpoints.notes END,
			  sources = CASE WHEN 'manual' = ANY(consolidated_url_endpoints.sources)
			                 THEN consolidated_url_endpoints.sources
			                 ELSE array_append(consolidated_url_endpoints.sources, 'manual') END
			RETURNING deleted_at`,
			uuid.New().String(), scopeTargetID, id.Key, id.CanonicalURL, id.CanonicalPath,
			id.Host, id.CanonicalPath, id.Method, isDirect, id.Scheme, id.CanonicalPath,
			id.IdentityQuery, id.ClientRoute, id.TemplatedPath, id.TemplateKey, id.CaseGroupKey,
			[]string{id.Method}, id.ContentClass, flagsJSON, payload.Notes,
		).Scan(&ignoredDeletedAt)
		if err != nil {
			log.Printf("[MANAGE] failed to add %s: %v", line, err)
			rejected = append(rejected, line)
			continue
		}
		if wasDeleted != nil {
			restored++
		} else {
			added++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"added": added, "restored": restored, "rejected": rejected,
	})
}

// DeleteEndpoints handles POST /consolidated-endpoints/{scope_target_id}/delete.
//
// Soft delete. The rows stay, excluded from every downstream query, and Restore brings them back
// with their validation verdicts intact.
func DeleteEndpoints(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		IDs    []string `json:"ids"`
		Filter string   `json:"filter"` // ruled_out | static | unseen | adjacent
		Reason string   `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	reason := payload.Reason
	if reason == "" {
		reason = "deleted by operator"
	}

	var tag int64
	switch {
	case len(payload.IDs) > 0:
		ct, err := dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints
			SET deleted_at = NOW(), deleted_reason = $1
			WHERE scope_target_id = $2 AND id = ANY($3) AND deleted_at IS NULL`,
			reason, scopeTargetID, payload.IDs)
		if err != nil {
			http.Error(w, "Failed to delete endpoints", http.StatusInternalServerError)
			return
		}
		tag = ct.RowsAffected()

	case payload.Filter != "":
		// Bulk deletion never touches a pinned row or one the operator added by hand, and never a
		// row whose verdict was only inferred. Only a measured rule-out is safe to sweep.
		var where string
		switch payload.Filter {
		case "ruled_out":
			where = `validation_status = 'ruled_out' AND validation_confidence = 'measured'
			         AND override_status IS NULL`
		case "static":
			where = `content_class = 'static'`
		case "unseen":
			where = `unseen_since IS NOT NULL`
		case "adjacent":
			where = `is_direct = FALSE`
		default:
			http.Error(w, "Unknown filter", http.StatusBadRequest)
			return
		}
		ct, err := dbPool.Exec(context.Background(), fmt.Sprintf(`
			UPDATE consolidated_url_endpoints
			SET deleted_at = NOW(), deleted_reason = $1
			WHERE scope_target_id = $2 AND deleted_at IS NULL
			  AND manual_added = FALSE AND pinned = FALSE AND (%s)`, where),
			reason, scopeTargetID)
		if err != nil {
			log.Printf("[MANAGE] bulk delete failed: %v", err)
			http.Error(w, "Failed to delete endpoints", http.StatusInternalServerError)
			return
		}
		tag = ct.RowsAffected()

	default:
		http.Error(w, "Provide ids or a filter", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": tag})
}

// RestoreEndpoints handles POST /consolidated-endpoints/{scope_target_id}/restore.
func RestoreEndpoints(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		IDs []string `json:"ids"`
		All bool     `json:"all"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	var (
		ct  interface{ RowsAffected() int64 }
		err error
	)
	if payload.All {
		ct, err = dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints SET deleted_at = NULL, deleted_reason = NULL
			WHERE scope_target_id = $1 AND deleted_at IS NOT NULL`, scopeTargetID)
	} else {
		if len(payload.IDs) == 0 {
			http.Error(w, "Provide ids or all=true", http.StatusBadRequest)
			return
		}
		ct, err = dbPool.Exec(context.Background(), `
			UPDATE consolidated_url_endpoints SET deleted_at = NULL, deleted_reason = NULL
			WHERE scope_target_id = $1 AND id = ANY($2)`, scopeTargetID, payload.IDs)
	}
	if err != nil {
		http.Error(w, "Failed to restore endpoints", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"restored": ct.RowsAffected()})
}

// OverrideEndpointVerdict handles POST /consolidated-endpoints/{scope_target_id}/override.
//
// The operator gets the last word. Validate is a measurement, not an authority, and a hunter who
// knows an endpoint is real needs to be able to say so and have every downstream tool agree.
func OverrideEndpointVerdict(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		IDs    []string `json:"ids"`
		Status string   `json:"status"` // valid | ruled_out | "" to clear
		Note   string   `json:"note"`
		Pinned *bool    `json:"pinned"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || len(payload.IDs) == 0 {
		http.Error(w, "Provide ids and a status", http.StatusBadRequest)
		return
	}
	if payload.Status != "" && payload.Status != "valid" && payload.Status != "ruled_out" {
		http.Error(w, "status must be valid, ruled_out, or empty to clear", http.StatusBadRequest)
		return
	}

	var status interface{}
	if payload.Status != "" {
		status = payload.Status
	}
	pinned := payload.Status == "valid"
	if payload.Pinned != nil {
		pinned = *payload.Pinned
	}

	ct, err := dbPool.Exec(context.Background(), `
		UPDATE consolidated_url_endpoints
		SET override_status = $1, override_note = $2, pinned = $3
		WHERE scope_target_id = $4 AND id = ANY($5)`,
		status, payload.Note, pinned, scopeTargetID, payload.IDs)
	if err != nil {
		log.Printf("[MANAGE] override failed: %v", err)
		http.Error(w, "Failed to set override", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"updated": ct.RowsAffected()})
}

// GetValidationStatus handles GET /endpoint-validation/{scope_target_id}/status/{scan_id}.
func GetValidationStatus(w http.ResponseWriter, r *http.Request) {
	writeValidationScan(w, `WHERE scan_id = $1`, mux.Vars(r)["scan_id"])
}

// GetLatestValidation handles GET /endpoint-validation/{scope_target_id}/latest.
func GetLatestValidation(w http.ResponseWriter, r *http.Request) {
	writeValidationScan(w,
		`WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 1`,
		mux.Vars(r)["scope_target_id"])
}

func writeValidationScan(w http.ResponseWriter, where, arg string) {
	var (
		scanID, status                   string
		total, processed, requests       int
		counts, assumptions, calibration []byte
		probeInputs                      []byte
		abortReason, errMsg, execTime    *string
		createdAt                        time.Time
	)
	q := `SELECT scan_id, status, total_endpoints, processed_endpoints, requests_sent,
	             counts, assumptions, calibration, probe_inputs, abort_reason, error,
	             execution_time, created_at
	      FROM endpoint_validation_scans ` + where

	if err := dbPool.QueryRow(context.Background(), q, arg).Scan(
		&scanID, &status, &total, &processed, &requests, &counts, &assumptions,
		&calibration, &probeInputs, &abortReason, &errMsg, &execTime, &createdAt); err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "not_run"})
		return
	}

	var countsMap map[string]int
	var assumptionsList []string
	var calibrationMap, probeMap map[string]interface{}
	_ = json.Unmarshal(counts, &countsMap)
	_ = json.Unmarshal(assumptions, &assumptionsList)
	_ = json.Unmarshal(calibration, &calibrationMap)
	_ = json.Unmarshal(probeInputs, &probeMap)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"scan_id": scanID, "status": status, "total_endpoints": total,
		"processed_endpoints": processed, "requests_sent": requests,
		"counts": countsMap, "assumptions": assumptionsList, "calibration": calibrationMap,
		"probe": probeMap, "abort_reason": abortReason, "error": errMsg,
		"execution_time": execTime, "created_at": createdAt,
	})
}

// RepairEndpointKeysHandler handles POST /consolidated-endpoints/{scope_target_id}/repair-keys.
func RepairEndpointKeysHandler(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	res, err := RepairEndpointKeys(scopeTargetID)
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(res)
}

func isHTTPVerb(s string) bool {
	switch strings.ToUpper(s) {
	case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT":
		return true
	}
	return false
}
