package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// The adjacent hosts a manual crawl observed, and what the operator has decided about them.
//
// An adjacent host is any host other than the scope target's own that the application contacted
// while the operator was browsing it. Those are usually where the real API lives: in one recording
// of a single-page app the target host served static assets and every meaningful call went to
// mercury-dev-api.one.app and dev-partner-auth.one.app, on a different registrable domain entirely.
//
// "Adjacent" is not the same question as "out of scope", and conflating them is what made this
// confusing. is_direct on a capture means "not the target's own host", so api.dev.countr.one is
// adjacent while already being inside the target's registrable domain and therefore always in
// scope. The two flags answer different questions and both are reported here.

type CrawlHost struct {
	Host      string `json:"host"`
	Requests  int    `json:"requests"`
	Endpoints int    `json:"endpoints"`
	IsDirect  bool   `json:"is_direct"`
	Scheme    string `json:"scheme"`

	// InScope is what the scanner will actually do. Decided distinguishes an operator's explicit
	// choice from the default, so the UI can show which hosts were deliberately set rather than
	// implying every one of them was reviewed.
	InScope bool `json:"in_scope"`
	Decided bool `json:"decided"`

	// WithinTargetDomain marks hosts that are in scope regardless of any decision here, because
	// they sit inside the scope target's own registrable domain.
	WithinTargetDomain bool `json:"within_target_domain"`

	// Set when a URL scope target already exists for this host, so the UI offers "open" rather
	// than "add" and a second click cannot create a duplicate.
	ExistingTargetID string `json:"existing_target_id,omitempty"`
}

// GetManualCrawlHosts lists every host this target's crawl observed, with its scope decision.
func GetManualCrawlHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if scopeTargetID == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_target", "scope_target_id is required")
		return
	}

	hosts, err := loadCrawlHosts(scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	adjacent := 0
	inScope := 0
	for _, h := range hosts {
		if !h.IsDirect {
			adjacent++
		}
		if h.InScope || h.WithinTargetDomain {
			inScope++
		}
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts":          hosts,
		"total":          len(hosts),
		"adjacent_count": adjacent,
		"in_scope_count": inScope,
		"scope":          LoadScanScope(scopeTargetID).Describe(),
	})
}

func loadCrawlHosts(scopeTargetID string) ([]CrawlHost, error) {
	ctx := context.Background()

	rows, err := dbPool.Query(ctx, `
		SELECT capture_host(url) AS host,
		       count(*) AS requests,
		       count(DISTINCT (endpoint, method)) AS endpoints,
		       bool_or(COALESCE(is_direct, false)) AS is_direct,
		       bool_or(url LIKE 'https://%') AS has_https
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND capture_host(url) <> ''
		GROUP BY 1
		ORDER BY 2 DESC`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to read crawl hosts: %w", err)
	}
	defer rows.Close()

	var out []CrawlHost
	for rows.Next() {
		var h CrawlHost
		var hasHTTPS bool
		if rows.Scan(&h.Host, &h.Requests, &h.Endpoints, &h.IsDirect, &hasHTTPS) != nil {
			continue
		}
		h.Scheme = "http"
		if hasHTTPS {
			h.Scheme = "https"
		}
		out = append(out, h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Explicit decisions override the default in either direction.
	decided := map[string]bool{}
	if dr, err := dbPool.Query(ctx,
		`SELECT lower(host), in_scope FROM scope_target_scope_hosts WHERE scope_target_id = $1`,
		scopeTargetID); err == nil {
		for dr.Next() {
			var host string
			var in bool
			if dr.Scan(&host, &in) == nil {
				decided[host] = in
			}
		}
		dr.Close()
	}

	// Hosts the operator named that the crawl never saw still belong in the list, otherwise the
	// modal would show a boundary narrower than the one the scanner enforces.
	seen := map[string]bool{}
	for _, h := range out {
		seen[h.Host] = true
	}
	for host, in := range decided {
		if !seen[host] {
			out = append(out, CrawlHost{Host: host, Scheme: "https", InScope: in})
		}
	}

	targets := existingURLTargets()
	primary := strings.ToLower(scopeTargetHost(scopeTargetID))
	primaryDomain := RegistrableDomain(primary)

	for i := range out {
		h := &out[i]
		if in, ok := decided[h.Host]; ok {
			h.InScope, h.Decided = in, true
		} else {
			// Observed means admitted. The extension never uploads a host that was not already in
			// its own capture scope, so a row being here is itself the operator's authorization.
			h.InScope = true
		}
		h.WithinTargetDomain = h.Host == primary ||
			(primaryDomain != "" && hostWithinDomain(h.Host, primaryDomain))
		h.ExistingTargetID = targets[h.Host]
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsDirect != out[j].IsDirect {
			return out[i].IsDirect // the target's own host first
		}
		return out[i].Requests > out[j].Requests
	})
	return out, nil
}

// existingURLTargets maps host to scope target id for every URL target already configured.
func existingURLTargets() map[string]string {
	out := map[string]string{}
	rows, err := dbPool.Query(context.Background(),
		`SELECT id, scope_target FROM scope_targets WHERE type = 'URL'`)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var id, target string
		if rows.Scan(&id, &target) != nil {
			continue
		}
		if h := hostFromScopeTarget(target); h != "" {
			out[h] = id
		}
	}
	return out
}

func hostFromScopeTarget(raw string) string {
	raw = strings.TrimSpace(strings.ToLower(raw))
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

type crawlHostScopeRequest struct {
	Hosts   []string `json:"hosts"`
	InScope *bool    `json:"in_scope"`
	Note    string   `json:"note"`
}

// SetManualCrawlHostScope records whether the framework may send requests to these hosts.
//
// Writes a row either way rather than deleting on exclude, so "the operator decided no" and "the
// operator has not looked at it" stay distinguishable. Deleting would silently re-admit the host on
// the next run, which is the failure mode that matters here.
func SetManualCrawlHostScope(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var req crawlHostScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if len(req.Hosts) == 0 {
		writeJSONError(w, http.StatusBadRequest, "missing_hosts", "`hosts` is required")
		return
	}
	inScope := true
	if req.InScope != nil {
		inScope = *req.InScope
	}

	updated := 0
	for _, raw := range req.Hosts {
		host := normalizeScopeHost(raw)
		if host == "" {
			continue
		}
		if _, err := dbPool.Exec(context.Background(), `
			INSERT INTO scope_target_scope_hosts (scope_target_id, host, in_scope, source, note)
			VALUES ($1, $2, $3, 'manual_crawl', $4)
			ON CONFLICT (scope_target_id, host)
			DO UPDATE SET in_scope = EXCLUDED.in_scope, note = EXCLUDED.note`,
			scopeTargetID, host, inScope, nullIfEmpty(req.Note)); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		updated++
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"updated":  updated,
		"in_scope": inScope,
		"scope":    LoadScanScope(scopeTargetID).Describe(),
	})
}

// PromoteManualCrawlHosts creates a URL scope target for each host so it can be worked in its own
// right, and marks it in scope for the target it was observed from.
//
// Skips hosts that already have a target instead of erroring on the batch: the "add all" button is
// the normal way to use this, and a run that refuses everything because one host was already added
// would be useless.
func PromoteManualCrawlHosts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var req struct {
		Hosts []string `json:"hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Invalid request body")
		return
	}
	if len(req.Hosts) == 0 {
		writeJSONError(w, http.StatusBadRequest, "missing_hosts", "`hosts` is required")
		return
	}

	observed := map[string]string{}
	if hosts, err := loadCrawlHosts(scopeTargetID); err == nil {
		for _, h := range hosts {
			observed[h.Host] = h.Scheme
		}
	}

	existing := existingURLTargets()
	created := []string{}
	skipped := []string{}
	failed := map[string]string{}

	for _, raw := range req.Hosts {
		host := normalizeScopeHost(raw)
		if host == "" {
			continue
		}
		if _, ok := existing[host]; ok {
			skipped = append(skipped, host)
			continue
		}

		scheme := observed[host]
		if scheme == "" {
			scheme = "https"
		}
		target := scheme + "://" + host

		var newID string
		err := dbPool.QueryRow(context.Background(), `
			INSERT INTO scope_targets (type, mode, scope_target, active)
			VALUES ('URL', 'Passive', $1, false)
			RETURNING id`, target).Scan(&newID)
		if err != nil {
			failed[host] = err.Error()
			continue
		}
		existing[host] = newID
		created = append(created, target)

		// A host worth its own target is a host worth probing from the one that found it.
		_, _ = dbPool.Exec(context.Background(), `
			INSERT INTO scope_target_scope_hosts (scope_target_id, host, in_scope, source, note)
			VALUES ($1, $2, TRUE, 'manual_crawl', 'promoted to its own URL scope target')
			ON CONFLICT (scope_target_id, host) DO UPDATE SET in_scope = TRUE`,
			scopeTargetID, host)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"created":       created,
		"created_count": len(created),
		"skipped":       skipped,
		"failed":        failed,
		"scope":         LoadScanScope(scopeTargetID).Describe(),
	})
}

// normalizeScopeHost accepts what the UI and an MCP caller each naturally send: a bare host, a full
// URL, or a "*.domain" wildcard.
func normalizeScopeHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.TrimPrefix(h, "*.")
	if h == "" {
		return ""
	}
	if strings.Contains(h, "://") {
		u, err := url.Parse(h)
		if err != nil || u.Hostname() == "" {
			return ""
		}
		return u.Hostname()
	}
	// Trim a port or a stray path if one came through.
	h = strings.TrimSuffix(h, ".")
	if i := strings.IndexAny(h, "/:"); i >= 0 {
		h = h[:i]
	}
	if h == "" || !strings.Contains(h, ".") {
		return ""
	}
	return h
}

func nullIfEmpty(s string) interface{} {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}
