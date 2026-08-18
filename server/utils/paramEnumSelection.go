package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// The endpoint list behind each parameter tool's config modal, and which of them that tool runs.
//
// The corpus was previously invisible: it existed only inside the three runners, so an operator
// could not see what a scan would touch until after it had touched it. Being able to look at the
// list first is what makes a per-endpoint decision possible at all.
//
// Selection is stored sparsely and absence means enabled, so a newly consolidated endpoint is
// scanned by default rather than silently excluded because it did not exist when the operator last
// opened this modal.

var paramEnumTools = map[string]bool{"arjun": true, "x8": true}

type paramEnumEndpointRow struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	Host         string `json:"host"`
	Path         string `json:"path"`
	Method       string `json:"method"`
	ContentClass string `json:"content_class"`
	IsDirect     bool   `json:"is_direct"`
	Interest     int    `json:"interest_score"`
	Enabled      bool   `json:"enabled"`
	// Decided marks an explicit operator choice, so the UI can distinguish "left on" from
	// "deliberately turned on".
	Decided bool `json:"decided"`
}

type paramEnumVerbGroup struct {
	Verb      string                 `json:"verb"`
	Label     string                 `json:"label"`
	Endpoints []paramEnumEndpointRow `json:"endpoints"`
	Enabled   int                    `json:"enabled_count"`
	// Runs describes what this verb costs for this tool, because the answer is not one pass per
	// verb for every tool: Arjun scans a body-bearing endpoint twice, form then JSON.
	Runs int `json:"runs"`
}

// GetParamEnumTargets lists the valid endpoints a tool would scan, grouped by HTTP verb.
func GetParamEnumTargets(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	tool := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("tool")))
	if tool != "" && !paramEnumTools[tool] {
		writeJSONError(w, http.StatusBadRequest, "unknown_tool",
			"tool must be one of arjun or x8")
		return
	}
	includeScripts := r.URL.Query().Get("include_scripts") == "true"

	scope := LoadScanScope(scopeTargetID)
	where := ParamEnumEligibility
	if !includeScripts {
		where += paramEnumScriptExclusion
	}
	where += "\n  AND " + scope.InScopeHostSQL(InvestigationHostExpr)

	// A scalar subquery rather than a LEFT JOIN, so the eligibility predicate can be used verbatim.
	// Joining would put a second `id` and `scope_target_id` in scope and force the shared const to
	// be rewritten per call site, which is exactly how the three runners' copies drifted apart.
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, url, COALESCE(domain,''), COALESCE(canonical_path, path, '/'),
		       COALESCE(method,'GET'), COALESCE(content_class,'unknown'),
		       COALESCE(is_direct,false), COALESCE(interest_score,0),
		       (SELECT s.enabled FROM param_enum_endpoint_selection s
		         WHERE s.endpoint_id = consolidated_url_endpoints.id
		           AND s.scope_target_id = consolidated_url_endpoints.scope_target_id
		           AND s.tool = $2)
		FROM consolidated_url_endpoints
		WHERE `+where+`
		ORDER BY interest_score DESC, url`, scopeTargetID, tool)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	byVerb := map[string][]paramEnumEndpointRow{}
	total, enabled := 0, 0
	for rows.Next() {
		var e paramEnumEndpointRow
		var stored *bool
		if rows.Scan(&e.ID, &e.URL, &e.Host, &e.Path, &e.Method, &e.ContentClass,
			&e.IsDirect, &e.Interest, &stored) != nil {
			continue
		}
		e.Method = strings.ToUpper(e.Method)
		// OPTIONS and HEAD are not listed at all. Neither carries a parameter surface, and showing
		// them as unchecked rows would imply they could be turned on.
		if paramEnumSkippedVerbs[e.Method] {
			continue
		}
		e.Enabled = true
		if stored != nil {
			e.Enabled, e.Decided = *stored, true
		}
		byVerb[e.Method] = append(byVerb[e.Method], e)
		total++
		if e.Enabled {
			enabled++
		}
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	verbs := make([]string, 0, len(byVerb))
	for v := range byVerb {
		verbs = append(verbs, v)
	}
	// GET first, then the rest alphabetically: GET is almost always the bulk of the work and the
	// group an operator looks at first.
	sort.Slice(verbs, func(i, j int) bool {
		if (verbs[i] == "GET") != (verbs[j] == "GET") {
			return verbs[i] == "GET"
		}
		return verbs[i] < verbs[j]
	})

	groups := make([]paramEnumVerbGroup, 0, len(verbs))
	totalRuns := 0
	for _, v := range verbs {
		list := byVerb[v]
		g := paramEnumVerbGroup{Verb: v, Label: v, Endpoints: list}
		for _, e := range list {
			if e.Enabled {
				g.Enabled++
			}
		}
		g.Runs = g.Enabled * paramEnumPassesPerEndpoint(tool, v)
		if v != "GET" {
			g.Label = v + " (body)"
		}
		totalRuns += g.Runs
		groups = append(groups, g)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"tool":            tool,
		"groups":          groups,
		"total":           total,
		"enabled":         enabled,
		"total_runs":      totalRuns,
		"scope":           scope.Describe(),
		"include_scripts": includeScripts,
		"predicate": "Valid endpoints from Consolidate and Investigate" +
			map[bool]string{true: "", false: ", excluding JavaScript bundles"}[includeScripts],
	})
}

// paramEnumPassesPerEndpoint is how many times a tool visits one endpoint of this verb, so the modal
// can show real cost rather than implying every tool works the same way.
//
// Arjun is the odd one: -m POST sends a form-encoded body and -m JSON sends a JSON one, and an API
// route usually only answers the second, so a body endpoint is scanned twice.
func paramEnumPassesPerEndpoint(tool, verb string) int {
	if tool == "arjun" && verb != "GET" {
		return 2
	}
	return 1
}

type paramEnumSelectionRequest struct {
	Tool        string   `json:"tool"`
	EndpointIDs []string `json:"endpoint_ids"`
	Verb        string   `json:"verb"`
	All         bool     `json:"all"`
	Enabled     *bool    `json:"enabled"`
	// IncludeScripts must mirror whatever the modal was showing when the operator clicked, so a
	// bulk action covers the visible rows and only those.
	IncludeScripts bool `json:"include_scripts"`

	// Mode reassigns which of the tool's request shapes these endpoints are tested with. Empty
	// string clears the override and returns them to the auto-categorised value; sending it is what
	// distinguishes "put this back on automatic" from "leave the mode alone", which is why the field
	// is a pointer.
	Mode *string `json:"mode"`
}

// SetParamEnumSelection records which endpoints a tool runs against.
func SetParamEnumSelection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var req paramEnumSelectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	tool := strings.ToLower(strings.TrimSpace(req.Tool))
	if !paramEnumTools[tool] {
		writeJSONError(w, http.StatusBadRequest, "unknown_tool",
			"tool must be one of arjun or x8")
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	ctx := context.Background()
	var updated int64

	// A mode change is its own operation: it does not touch enabled, and enabled does not touch it.
	// Folding them together would mean re-categorising an endpoint silently re-enabled it.
	if req.Mode != nil {
		// The two tools categorise along different axes, so the accepted values differ: Arjun takes
		// a body encoding, x8 takes an injection place.
		mode := strings.TrimSpace(*req.Mode)
		if tool == "x8" {
			mode = strings.ToLower(mode)
			if mode != "" && !IsX8Place(mode) {
				writeJSONError(w, http.StatusBadRequest, "unknown_mode",
					"for x8, mode must be one of query, body, headers, cookies, or empty for automatic")
				return
			}
		} else {
			mode = strings.ToUpper(mode)
			if mode != "" && !IsArjunMode(mode) {
				writeJSONError(w, http.StatusBadRequest, "unknown_mode",
					"for arjun, mode must be one of GET, POST, JSON, XML, or empty for automatic")
				return
			}
		}
		if len(req.EndpointIDs) == 0 {
			writeJSONError(w, http.StatusBadRequest, "missing_selection", "mode needs endpoint_ids")
			return
		}
		var stored interface{}
		if mode != "" {
			stored = mode
		}
		tag, err := dbPool.Exec(ctx, `
			INSERT INTO param_enum_endpoint_selection (scope_target_id, tool, endpoint_id, enabled, mode)
			SELECT $1, $2, unnest($3::uuid[]), TRUE, $4
			ON CONFLICT (scope_target_id, tool, endpoint_id)
			DO UPDATE SET mode = EXCLUDED.mode, updated_at = NOW()`,
			scopeTargetID, tool, req.EndpointIDs, stored)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		sel, _ := SelectParamEnumTargets(ctx, scopeTargetID,
			ParamTargetOptions{Tool: tool, IncludeDisabled: true})
		byMode := map[string]int{}
		for _, t := range sel.Targets {
			byMode[t.ModeFor(tool)]++
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"updated": tag.RowsAffected(), "mode": mode, "tool": tool, "by_mode": byMode,
			"note": map[bool]string{true: "returned to automatic categorisation",
				false: "mode set explicitly"}[mode == ""],
		})
		return
	}

	switch {
	case req.All:
		// Bulk over the eligible set rather than over whatever the client happened to render, so a
		// stale modal cannot leave rows behind.
		//
		// It must match exactly what the modal SHOWS, though. Without the verb and script filters a
		// "disable all" from the GET group also switched off scripts and OPTIONS rows the operator
		// could not see: 80 rows written for a list of 25. A bulk action that reaches past the
		// visible list is the kind of thing an operator only discovers much later.
		scope := LoadScanScope(scopeTargetID)
		where := ParamEnumEligibility
		if !req.IncludeScripts {
			where += paramEnumScriptExclusion
		}
		where += "\n  AND " + scope.InScopeHostSQL(InvestigationHostExpr)
		where += "\n  AND upper(COALESCE(method,'GET')) NOT IN ('OPTIONS','HEAD')"

		args := []interface{}{scopeTargetID, tool, enabled}
		verbFilter := ""
		if v := strings.ToUpper(strings.TrimSpace(req.Verb)); v != "" {
			args = append(args, v)
			verbFilter = " AND upper(COALESCE(method,'GET')) = $4"
		}
		tag, err := dbPool.Exec(ctx, `
			INSERT INTO param_enum_endpoint_selection (scope_target_id, tool, endpoint_id, enabled)
			SELECT $1, $2, id, $3 FROM consolidated_url_endpoints
			WHERE `+where+verbFilter+`
			ON CONFLICT (scope_target_id, tool, endpoint_id)
			DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW()`, args...)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		updated = tag.RowsAffected()

	case len(req.EndpointIDs) > 0:
		tag, err := dbPool.Exec(ctx, `
			INSERT INTO param_enum_endpoint_selection (scope_target_id, tool, endpoint_id, enabled)
			SELECT $1, $2, unnest($3::uuid[]), $4
			ON CONFLICT (scope_target_id, tool, endpoint_id)
			DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = NOW()`,
			scopeTargetID, tool, req.EndpointIDs, enabled)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		updated = tag.RowsAffected()

	default:
		writeJSONError(w, http.StatusBadRequest, "missing_selection",
			"provide endpoint_ids, or all:true")
		return
	}

	sel, _ := SelectParamEnumTargets(ctx, scopeTargetID, ParamTargetOptions{Tool: tool})
	json.NewEncoder(w).Encode(map[string]interface{}{
		"updated":       updated,
		"enabled":       enabled,
		"now_selected":  sel.Total,
		"by_method":     sel.ByMethod,
		"tool":          tool,
		"scan_will_run": fmt.Sprintf("%d endpoints", sel.Total),
	})
}
