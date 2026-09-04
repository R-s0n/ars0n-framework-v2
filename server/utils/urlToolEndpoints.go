package utils

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

// Per-tool endpoint totals, counted the way consolidation counts.
//
// The tool cards used to parse a number out of the LAST scan's summary sentence. That is a
// different quantity from the one Consolidate reports, and the two could not be reconciled by
// looking at them: a Katana card read "1 Endpoint" directly after a run that found 775, because the
// run after it was a one-host probe. The card was answering "what did the most recent scan return"
// while the operator was reading it as "what has this tool found".
//
// Everything discovery finds is folded into consolidation regardless of which scan produced it, so
// the honest per-tool number is the same shape: every distinct endpoint this tool has ever found on
// this target. Now the five cards sum to something that reconciles with the consolidated total,
// give or take the overlap between tools and the manual crawl, which is the whole point of
// consolidating.

// URLDiscoveryTools are the scan_type values discovery writes into discovered_endpoints. Listed
// explicitly rather than derived from the table so a tool with no scans yet reports a real zero
// instead of being absent from the response.
var URLDiscoveryTools = []string{"waybackurls", "gau", "linkfinder", "katana", "gospider"}

type ToolEndpointCount struct {
	Total    int `json:"total"`
	Direct   int `json:"direct"`
	Adjacent int `json:"adjacent"`
}

// GetToolEndpointCounts returns every discovery tool's cumulative distinct endpoint count for a
// target, in one call, so five cards do not each make their own request.
func GetToolEndpointCounts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_target", "scope_target_id is required")
		return
	}

	out := map[string]ToolEndpointCount{}
	for _, tool := range URLDiscoveryTools {
		out[tool] = ToolEndpointCount{}
	}

	// The inner GROUP BY collapses a URL seen by several scans of the same tool into one row, which
	// is what makes this comparable with the consolidated total. bool_or rather than any single
	// row's flag: if one scan recorded a URL as direct, it is direct.
	rows, err := dbPool.Query(context.Background(), `
		SELECT scan_type,
		       count(*)                                AS total,
		       count(*) FILTER (WHERE is_direct)       AS direct,
		       count(*) FILTER (WHERE NOT is_direct)   AS adjacent
		FROM (
			SELECT scan_type, url, bool_or(COALESCE(is_direct, false)) AS is_direct
			FROM discovered_endpoints
			WHERE scope_target_id = $1
			GROUP BY scan_type, url
		) deduped
		GROUP BY scan_type`, scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	for rows.Next() {
		var tool string
		var c ToolEndpointCount
		if rows.Scan(&tool, &c.Total, &c.Direct, &c.Adjacent) != nil {
			continue
		}
		out[tool] = c
	}
	if err := rows.Err(); err != nil {
		// Reported rather than swallowed: a partial map here would silently under-count every card.
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	json.NewEncoder(w).Encode(out)
}

// GetToolEndpoints lists every distinct endpoint one tool has found on a target, across all its
// scans, for that tool's Results modal.
//
// The modals used to read /discovered-endpoints/{scan_id}, which shows one scan. That made the
// Results button disagree with the card beside it as soon as a second scan existed.
func GetToolEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	tool := mux.Vars(r)["tool"]

	known := false
	for _, t := range URLDiscoveryTools {
		if t == tool {
			known = true
			break
		}
	}
	if !known {
		writeJSONError(w, http.StatusBadRequest, "unknown_tool", "tool must be one of the URL discovery tools")
		return
	}

	// DISTINCT ON keeps the most recently seen row per URL, so a re-crawl that observed a new status
	// code wins over the first sighting. Ordering by url first is required by DISTINCT ON; the outer
	// ordering is applied afterwards.
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, url, domain, path, normalized_path, status_code, is_direct, created_at
		FROM (
			SELECT DISTINCT ON (url) id, url, domain, path, normalized_path, status_code,
			       COALESCE(is_direct, false) AS is_direct, created_at
			FROM discovered_endpoints
			WHERE scope_target_id = $1 AND scan_type = $2
			ORDER BY url, created_at DESC
		) latest
		ORDER BY is_direct DESC, url`, scopeTargetID, tool)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	defer rows.Close()

	type endpoint struct {
		ID             string    `json:"id"`
		URL            string    `json:"url"`
		Domain         string    `json:"domain"`
		Path           string    `json:"path"`
		NormalizedPath string    `json:"normalized_path"`
		StatusCode     *int      `json:"status_code"`
		IsDirect       bool      `json:"is_direct"`
		CreatedAt      time.Time `json:"created_at"`
	}

	out := []endpoint{}
	for rows.Next() {
		var e endpoint
		if rows.Scan(&e.ID, &e.URL, &e.Domain, &e.Path, &e.NormalizedPath,
			&e.StatusCode, &e.IsDirect, &e.CreatedAt) != nil {
			continue
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	json.NewEncoder(w).Encode(out)
}
