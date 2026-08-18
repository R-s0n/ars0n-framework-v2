package utils

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// What each scope target has actually produced, for the Manage Scope Targets table.
//
// The three workflows produce entirely different things, so one set of columns cannot describe them.
// The table used to show Subs / Live / Nuclei / Impact for every row, which are the WILDCARD
// workflow's outputs: a Company row reported 0 subdomains while holding 867 live web servers and 20
// cloud assets, and every URL row read as four zeros while holding a thousand endpoints. Four zeros
// against a target that has been worked on for a week is not a neutral display, it is a wrong one.
//
// So the columns are per type, and the SERVER decides them. The client renders whatever
// `definitions` says, which is the same reason the fuzz options and the triage vocabulary are served
// rather than duplicated: two lists that must agree will eventually not.
//
// Everything here is counted with GROUPED queries, a fixed number of them whatever the target count.
// The modal previously issued three HTTP requests PER TARGET and parsed nuclei's whole JSON report in
// the browser, so eleven targets meant thirty three requests before the table could draw.

// scopeMetricDef is one column.
type scopeMetricDef struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Hint is the tooltip. It says where the number comes from, because "Live" meaning two different
	// things on two different rows is exactly what this endpoint exists to stop.
	Hint string `json:"hint"`
	// Emphasis marks the column that answers "is there anything here worth my time". Rendered in the
	// accent colour; everything else is plain.
	Emphasis bool `json:"emphasis,omitempty"`
}

// scopeMetricDefinitions is the contract. Adding a column here and nowhere else is enough.
var scopeMetricDefinitions = map[string][]scopeMetricDef{
	// The Company workflow maps an organisation onto infrastructure: root domains it owns, the ranges
	// it runs on, what it has in cloud, and what of that actually answers HTTP.
	"Company": {
		{Key: "root_domains", Label: "Root Domains", Hint: "Consolidated root domains owned by this company."},
		{Key: "network_ranges", Label: "Ranges", Hint: "Consolidated ASN and CIDR network ranges."},
		{Key: "cloud_assets", Label: "Cloud", Hint: "Cloud assets found in the consolidated attack surface."},
		{Key: "live_servers", Label: "Live Servers", Hint: "Live web servers in the consolidated attack surface.", Emphasis: true},
	},
	// The Wildcard workflow expands a domain into subdomains, finds which answer, and scans them.
	"Wildcard": {
		{Key: "subdomains", Label: "Subdomains", Hint: "Consolidated subdomains discovered across every scraping and brute-force round."},
		{Key: "live_servers", Label: "Live Servers", Hint: "Subdomains that answered httpx and became target URLs."},
		{Key: "findings", Label: "Findings", Hint: "Findings from the most recent successful Nuclei scan."},
		{Key: "impactful", Label: "Impactful", Hint: "Those findings rated critical, high or medium.", Emphasis: true},
	},
	// The URL workflow works one host in depth: what it exposes, what it takes, and what answered
	// differently. Session is here because whether a credential is loaded decides what the rest of
	// the workflow can even reach.
	"URL": {
		{Key: "endpoints", Label: "Endpoints", Hint: "Consolidated endpoints currently in scope, excluding deleted ones."},
		{Key: "parameters", Label: "Parameters", Hint: "Hidden parameters found by Arjun and x8."},
		{Key: "fuzz_findings", Label: "Fuzz Findings", Hint: "Stored ffuf findings, excluding dismissed ones.", Emphasis: true},
		{Key: "session", Label: "Session", Hint: "Auth flows and session tokens configured for this target."},
	},
}

// GetScopeTargetMetrics answers GET /scope-target-metrics.
func GetScopeTargetMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	ctx := r.Context()

	metrics := map[string]map[string]int{}
	// Only a target that HAS a number gets one. A missing key and a zero mean different things to the
	// table: nothing recorded yet versus counted and none.
	add := func(id, key string, n int) {
		if id == "" {
			return
		}
		if metrics[id] == nil {
			metrics[id] = map[string]int{}
		}
		metrics[id][key] += n
	}

	// countInto runs one grouped query and files the result under key.
	countInto := func(key, query string) {
		rows, err := dbPool.Query(ctx, query)
		if err != nil {
			// A table that does not exist yet is not an error worth failing the whole table over: the
			// column simply reads as nothing recorded.
			log.Printf("[WARN] scope target metrics (%s): %v", key, err)
			return
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			var n int
			if rows.Scan(&id, &n) == nil {
				add(id, key, n)
			}
		}
	}

	countInto("root_domains",
		`SELECT scope_target_id::text, count(*) FROM consolidated_company_domains GROUP BY 1`)
	countInto("network_ranges",
		`SELECT scope_target_id::text, count(*) FROM consolidated_network_ranges GROUP BY 1`)
	countInto("subdomains",
		`SELECT scope_target_id::text, count(*) FROM consolidated_subdomains GROUP BY 1`)
	// For a Wildcard target the live web servers ARE the target URLs: httpx results are promoted into
	// that table, which is also what the workflow's own Live Web Servers count reads.
	countInto("live_servers",
		`SELECT scope_target_id::text, count(*) FROM target_urls GROUP BY 1`)
	countInto("endpoints",
		`SELECT scope_target_id::text, count(*) FROM consolidated_url_endpoints
		 WHERE deleted_at IS NULL GROUP BY 1`)
	countInto("parameters",
		`SELECT scope_target_id::text, count(*) FROM parameter_enumeration_results GROUP BY 1`)
	// Dismissed findings are excluded here for the same reason the findings list hides them: the
	// operator has already said they are not worth looking at, and a count that ignores that is a
	// count of work already done.
	// Keyed apart from the Nuclei count deliberately. Both were once called "findings" and summed on
	// any target that had run both, so a URL target with 66 ffuf findings and a Nuclei scan reported
	// 138 of something that does not exist.
	countInto("fuzz_findings",
		`SELECT scope_target_id::text, count(*) FROM fuzz_findings
		 WHERE triage <> 'dismissed' GROUP BY 1`)
	countInto("session",
		`SELECT scope_target_id::text, count(*) FROM auth_flows GROUP BY 1`)
	countInto("session",
		`SELECT scope_target_id::text, count(*) FROM session_tokens GROUP BY 1`)

	// A Company target's live servers and cloud assets come from the consolidated attack surface
	// rather than from target_urls, which is why one "Live Servers" column cannot be one query.
	if rows, err := dbPool.Query(ctx, `
		SELECT scope_target_id::text, asset_type, count(*)
		FROM consolidated_attack_surface_assets GROUP BY 1, 2`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, assetType string
			var n int
			if rows.Scan(&id, &assetType, &n) != nil {
				continue
			}
			switch assetType {
			case "live_web_server":
				add(id, "live_servers", n)
			case "cloud_asset":
				add(id, "cloud_assets", n)
			}
		}
	} else {
		log.Printf("[WARN] scope target metrics (attack surface): %v", err)
	}

	// Nuclei stores its report as a JSON array in a TEXT column, so the counting happens here rather
	// than in SQL: a malformed report must cost that one target its number and nothing else.
	// DISTINCT ON takes only the most recent successful scan, which is the one the workflow displays.
	if rows, err := dbPool.Query(ctx, `
		SELECT DISTINCT ON (scope_target_id) scope_target_id::text, result
		FROM nuclei_scans
		WHERE status = 'success' AND result IS NOT NULL AND result <> ''
		ORDER BY scope_target_id, created_at DESC`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var id, result string
			if rows.Scan(&id, &result) != nil {
				continue
			}
			total, impactful := nucleiSeverityCounts(result)
			add(id, "findings", total)
			add(id, "impactful", impactful)
		}
	} else {
		log.Printf("[WARN] scope target metrics (nuclei): %v", err)
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"metrics":     metrics,
		"definitions": scopeMetricDefinitions,
	})
}

// nucleiSeverityCounts reads a nuclei report and returns how many findings it holds and how many of
// those are worth acting on. Critical, high and medium, matching the workflow's own Impactful card:
// low and info are overwhelmingly TLS and header advice, and counting them as impact makes the number
// stop meaning anything.
func nucleiSeverityCounts(result string) (total, impactful int) {
	var findings []struct {
		Info struct {
			Severity string `json:"severity"`
		} `json:"info"`
	}
	if json.Unmarshal([]byte(result), &findings) != nil {
		return 0, 0
	}
	for _, f := range findings {
		total++
		switch strings.ToLower(strings.TrimSpace(f.Info.Severity)) {
		case "critical", "high", "medium":
			impactful++
		}
	}
	return total, impactful
}
