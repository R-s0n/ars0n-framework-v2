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

// Building the target list for the access control bypass section.
//
// This section is the only one whose targets are not attack vectors. A 403 bypass has no parameter
// to inject into: what is being tested is whether the access control decision can be avoided at all.
// The interesting URLs are therefore the ones that already answered 401 or 403 to something this
// framework sent earlier, and those are scattered across six tables that each record an HTTP status
// for their own reasons.

// bypassStatusCodes is what qualifies, and the argument for each.
//
// 401 and 403 are the section. They are an access control decision, stated by the server, on a URL
// that exists.
//
// 404 is DELIBERATELY NOT included by default, and this is the decision most worth revisiting. A 404
// can hide a resource that exists (a proxy answering for a back-end that would serve it), which is a
// real and reported bug class. But 404 is also what every directory brute force produces by the
// thousand: on this database 404 is 60% of all 4xx rows, and most of them are ffuf misses against
// paths that never existed. Including them by default would turn a focused scan of a few dozen real
// access controls into a scan of several hundred imaginary ones. Offered as a setting instead.
//
// 405 is offered for a different reason: verb tampering is one of the bypass techniques both tools
// implement, and a 405 is the server saying the method is the thing it objects to.
//
// 400, 409, 412, 418, 426, 429 and 499 are excluded outright. They are malformed requests, conflicts,
// upgrade demands and rate limits, none of which is an access control decision.
var bypassStatusCodes = struct {
	Default  []int
	Optional map[string][]int
}{
	Default: []int{401, 403},
	Optional: map[string][]int{
		"include404": {404},
		"include405": {405},
	},
}

// bypassTargetSources is every table that records an HTTP status alongside a URL and a scope target.
//
// Written out rather than discovered, because the framework has around forty columns called "status"
// and almost all of them are SCAN status ('running', 'completed'), not HTTP status. Treating one of
// those as a status code would silently produce a target list of nothing.
var bypassTargetSources = []struct {
	Name         string
	Table        string
	StatusColumn string
}{
	{"endpoint-discovery", "discovered_endpoints", "status_code"},
	{"endpoint-validation", "endpoint_validation_results", "http_status"},
	{"manual-crawl", "manual_crawl_captures", "status_code"},
	{"fuzz", "fuzz_findings", "http_status"},
	{"attack-surface", "consolidated_attack_surface_assets", "status_code"},
	{"target-urls", "target_urls", "status_code"},
}

// ConsolidateBypassTargets rebuilds the target list for one scope target.
//
// Upserted rather than replaced, so an operator who deleted a target keeps it deleted: re-running
// consolidation after another scan must not resurrect a URL somebody has already judged not worth
// testing. Same rule the attack vector table follows.
func ConsolidateBypassTargets(ctx context.Context, scopeTargetID string, statuses []int) (int, error) {
	if len(statuses) == 0 {
		statuses = bypassStatusCodes.Default
	}

	var unions []string
	for _, source := range bypassTargetSources {
		unions = append(unions, fmt.Sprintf(
			`SELECT url, %s AS status_code, '%s' AS source FROM %s
			 WHERE scope_target_id = $1 AND %s = ANY($2) AND url IS NOT NULL AND url <> ''`,
			source.StatusColumn, source.Name, source.Table, source.StatusColumn))
	}

	// One row per URL, keeping the lowest status code seen for it and every source that reported it.
	// A URL that four tools all found 403 on is one thing to test, not four.
	query := `
		WITH found AS (` + strings.Join(unions, " UNION ALL ") + `),
		rolled AS (
		    SELECT url, MIN(status_code) AS status_code,
		           ARRAY_AGG(DISTINCT source ORDER BY source) AS sources
		    FROM found GROUP BY url
		)
		INSERT INTO access_bypass_targets (scope_target_id, url, status_code, sources, last_seen)
		SELECT $1, url, status_code, sources, NOW() FROM rolled
		ON CONFLICT (scope_target_id, url) DO UPDATE
		    SET status_code = EXCLUDED.status_code,
		        sources = EXCLUDED.sources,
		        last_seen = NOW()`

	tag, err := dbPool.Exec(ctx, query, scopeTargetID, statuses)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}

// bypassHostInScope reports whether a target URL belongs to the scope target rather than to a third
// party.
//
// This matters more here than anywhere else in the framework. A 403 is exactly what somebody else's
// infrastructure returns to a request it did not expect, so the 4xx tables fill up with hosts that
// are not the target at all: on one real scope target the commonest hosts in the 4xx set were an
// unrelated auth provider and a payment site. Pointing a bypass scan at those means sending hundreds
// of deliberately malformed requests at a company nobody has authorised us to test.
//
// The comparison is the last two labels of the hostname, which is wrong for a handful of multi-part
// suffixes like co.uk and deliberately errs towards INCLUDING rather than excluding, because a
// target wrongly dropped is a scan that silently misses something.
func bypassHostInScope(targetURL, scopeHost string) bool {
	if scopeHost == "" {
		return true
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	scopeHost = strings.ToLower(scopeHost)
	if host == "" || host == scopeHost {
		return true
	}
	return strings.HasSuffix(host, "."+registrableSuffix(scopeHost)) ||
		host == registrableSuffix(scopeHost)
}

func registrableSuffix(host string) string {
	labels := strings.Split(strings.Trim(host, "."), ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// bypassScopeHost reads the hostname a scope target names.
func bypassScopeHost(ctx context.Context, scopeTargetID string) string {
	var raw string
	if err := dbPool.QueryRow(ctx,
		`SELECT COALESCE(scope_target,'') FROM scope_targets WHERE id = $1`,
		scopeTargetID).Scan(&raw); err != nil {
		return ""
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "*.")
}

// loadBypassTargetRows is the RowSource for this section: it hands the runner the consolidated
// targets in the same shape the runner already understands.
//
// The rows carry IsBypassTarget so the runner writes them to bypass_target_id rather than to
// vector_id, whose foreign key points at attack_vectors and would reject every one of them.
//
// Out-of-scope hosts are left out of the SCAN even though they stay in the list, because sending a
// few hundred malformed requests at a third party is not something to do by accident.
func loadBypassTargetRows(ctx context.Context, scopeTargetID string) ([]vectorRow, error) {
	scopeHost := bypassScopeHost(ctx, scopeTargetID)

	rows, err := dbPool.Query(ctx, `
		SELECT id::text, url, status_code
		FROM access_bypass_targets
		WHERE scope_target_id = $1 AND deleted_at IS NULL
		ORDER BY status_code, url`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []vectorRow
	for rows.Next() {
		var id, rawURL string
		var status int
		if err := rows.Scan(&id, &rawURL, &status); err != nil {
			return nil, err
		}
		if !bypassHostInScope(rawURL, scopeHost) {
			continue
		}
		row := vectorRow{
			ID:             id,
			Method:         "GET",
			InsertionPoint: "path",
			EvidenceURL:    rawURL,
			IsBypassTarget: true,
			BaselineStatus: status,
		}
		row.Scheme, row.Domain, row.Port, row.Path = splitURLParts(rawURL)
		out = append(out, row)
	}
	return out, rows.Err()
}

// splitURLParts pulls a URL apart into the pieces vectorRow keeps them in.
func splitURLParts(rawURL string) (scheme, domain string, port int, path string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "https", "", 0, "/"
	}
	scheme = parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	domain = parsed.Hostname()
	if p := parsed.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	path = parsed.Path
	if path == "" {
		path = "/"
	}
	return scheme, domain, port, path
}

// GetBypassTargets serves the list, so the operator can see what a scan will cover before starting
// it rather than after.
func GetBypassTargets(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(r.Context(), `
		SELECT id::text, url, status_code, sources, notes, first_seen, last_seen
		FROM access_bypass_targets
		WHERE scope_target_id = $1 AND deleted_at IS NULL
		ORDER BY status_code, url`, scopeTargetID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type target struct {
		ID         string   `json:"id"`
		URL        string   `json:"url"`
		StatusCode int      `json:"status_code"`
		Sources    []string `json:"sources"`
		Notes      string   `json:"notes"`
		FirstSeen  string   `json:"first_seen"`
		LastSeen   string   `json:"last_seen"`
		// InScope is false for a host that belongs to somebody else. Those stay in the list so the
		// operator can see them, and are left out of the scan so a few hundred malformed requests do
		// not go to a third party by accident.
		InScope bool `json:"in_scope"`
	}

	scopeHost := bypassScopeHost(r.Context(), scopeTargetID)

	out := []target{}
	byStatus := map[int]int{}
	inScope, outOfScope := 0, 0
	outOfScopeHosts := map[string]int{}
	for rows.Next() {
		var t target
		var first, last interface{}
		if err := rows.Scan(&t.ID, &t.URL, &t.StatusCode, &t.Sources, &t.Notes, &first, &last); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		t.FirstSeen = fmt.Sprintf("%v", first)
		t.LastSeen = fmt.Sprintf("%v", last)
		t.InScope = bypassHostInScope(t.URL, scopeHost)
		if t.InScope {
			inScope++
			byStatus[t.StatusCode]++
		} else {
			outOfScope++
			if parsed, err := url.Parse(t.URL); err == nil {
				outOfScopeHosts[parsed.Hostname()]++
			}
		}
		out = append(out, t)
	}

	codes := make([]int, 0, len(byStatus))
	for code := range byStatus {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	summary := make([]map[string]int, 0, len(codes))
	for _, code := range codes {
		summary = append(summary, map[string]int{"status_code": code, "count": byStatus[code]})
	}

	// The out-of-scope hosts are named rather than merely counted, because a 403 is exactly what
	// somebody else's infrastructure returns to an unexpected request, and on a real target the
	// commonest hosts in the 4xx set were an unrelated auth provider and a payment site.
	type hostCount struct {
		Host  string `json:"host"`
		Count int    `json:"count"`
	}
	held := make([]hostCount, 0, len(outOfScopeHosts))
	for host, count := range outOfScopeHosts {
		held = append(held, hostCount{Host: host, Count: count})
	}
	sort.Slice(held, func(i, j int) bool { return held[i].Count > held[j].Count })

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"targets":             out,
		"count":               len(out),
		"scan_count":          inScope,
		"out_of_scope":        outOfScope,
		"out_of_scope_hosts":  held,
		"scope_host":          scopeHost,
		"by_status":           summary,
		"sources":             bypassSourceNames(),
		"scan_unit":           "URL",
	})
}

// RunBypassTargetConsolidation rebuilds the list on demand.
func RunBypassTargetConsolidation(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var body struct {
		Include404 bool `json:"include_404"`
		Include405 bool `json:"include_405"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	statuses := append([]int{}, bypassStatusCodes.Default...)
	if body.Include404 {
		statuses = append(statuses, bypassStatusCodes.Optional["include404"]...)
	}
	if body.Include405 {
		statuses = append(statuses, bypassStatusCodes.Optional["include405"]...)
	}

	count, err := ConsolidateBypassTargets(r.Context(), scopeTargetID, statuses)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"consolidated":  count,
		"status_codes":  statuses,
	})
}

// DeleteBypassTarget removes one URL from the list, and it stays removed: consolidation upserts and
// never revives a soft-deleted row.
func DeleteBypassTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := dbPool.Exec(r.Context(),
		`UPDATE access_bypass_targets SET deleted_at = NOW() WHERE id = $1`, id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

func bypassSourceNames() []string {
	names := make([]string, 0, len(bypassTargetSources))
	for _, source := range bypassTargetSources {
		names = append(names, source.Name)
	}
	return names
}

// vectorIdentityColumns decides which identity column an id belongs in.
//
// vector_id has a foreign key onto attack_vectors, so a bypass target's id written there fails the
// insert outright. The failure would be logged and the scan would carry on, recording NOTHING for a
// target it really did scan, which reads afterwards as a target that was never reached.
func vectorIdentityColumns(id string, isBypassTarget bool) (vectorID, bypassTargetID any) {
	if strings.TrimSpace(id) == "" {
		return nil, nil
	}
	if isBypassTarget {
		return nil, id
	}
	return id, nil
}

// recordScanTarget writes the per-target verdict for a scan, against whichever identity the target
// has. The two ON CONFLICT clauses differ because Postgres treats NULLs as distinct: the constraint
// that stops a vector being recorded twice does nothing for a bypass target, whose vector_id is
// always NULL, so that case needs its own partial unique index to conflict against.
func recordScanTarget(ctx context.Context, scanID, id string, isBypassTarget bool,
	status, reason string, findingCount int) error {
	vectorID, bypassID := vectorIdentityColumns(id, isBypassTarget)
	if isBypassTarget {
		_, err := dbPool.Exec(ctx, `
			INSERT INTO vector_scan_vectors (scan_id, vector_id, bypass_target_id, status, reason, finding_count)
			VALUES ($1, NULL, $2, $3, $4, $5)
			ON CONFLICT (scan_id, bypass_target_id) WHERE bypass_target_id IS NOT NULL DO NOTHING`,
			scanID, bypassID, status, reason, findingCount)
		return err
	}
	_, err := dbPool.Exec(ctx, `
		INSERT INTO vector_scan_vectors (scan_id, vector_id, status, reason, finding_count)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (scan_id, vector_id) DO NOTHING`,
		scanID, vectorID, status, reason, findingCount)
	return err
}
