package utils

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
)

// CSV export, overhauled.
//
// WHAT IT USED TO BE: ~2,250 lines of one hand-written function per recon tool (exportAmassData,
// exportHttpxData, ...), each with a frozen header list. Like the old .rs0n map it covered only the
// company/wildcard recon tools, so the entire URL workflow - endpoints, parameters, attack vectors,
// findings, manual crawl, replay, flows, auth, triage, fuzz - produced no CSV at all, and any column
// added to a covered tool was dropped because the header was a literal.
//
// WHAT IT IS NOW: one renderer over the SAME schema-driven engine the .rs0n bundle uses (exportBundle
// in dbBundle.go). Whatever the bundle covers, the CSV covers - every per-target table and its
// FK-reachable children - so the two exports can never drift again. Each table becomes one CSV with a
// header taken from the live schema (every column, in order) and nested JSON/array cells written as
// compact JSON so a spreadsheet still opens cleanly. Files are grouped into folders by workflow
// (auth/, urls/, findings/, recon/, config/, threat/) and a manifest.csv lists every file with its row
// count, so the zip is navigable instead of a flat wall of tables.

type CSVExportRequest struct {
	ScopeTargetIDs []string `json:"scope_target_ids"`
	// Singular alias so an MCP caller (export_scan_data target_id) and the UI (array) both work.
	ScopeTargetID string `json:"scope_target_id"`
	// Off drops the per-table folder and keeps only the curated top-level views. Default (nil) is a
	// complete export: every table.
	CuratedOnly bool `json:"curated_only"`
}

func HandleExportData(w http.ResponseWriter, r *http.Request) {
	log.Println("[INFO] Starting CSV export")

	var req CSVExportRequest
	// Tolerate the legacy body (a flat map of dataset booleans): decoding it into this struct simply
	// leaves the fields zero, which means "all targets, complete export" - a strictly better default
	// than the old partial selection.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err.Error() != "EOF" {
		log.Printf("[INFO] CSV export: non-standard body, defaulting to full export: %v", err)
	}

	ids := req.ScopeTargetIDs
	if len(ids) == 0 && strings.TrimSpace(req.ScopeTargetID) != "" {
		ids = []string{strings.TrimSpace(req.ScopeTargetID)}
	}
	if len(ids) == 0 {
		all, err := allScopeTargetIDs(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to list scope targets: %v", err), http.StatusInternalServerError)
			return
		}
		ids = all
	}
	if len(ids) == 0 {
		http.Error(w, "No scope targets to export", http.StatusBadRequest)
		return
	}

	bundle, err := exportBundle(r.Context(), ids)
	if err != nil {
		log.Printf("[ERROR] CSV export failed to gather data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to gather data: %v", err), http.StatusInternalServerError)
		return
	}
	schema, err := collectBundleSchema(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to read schema: %v", err), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)

	type manifestRow struct{ path, table string; rows int }
	var manifest []manifestRow

	writeCSV := func(path, table string, rows []json.RawMessage) {
		if len(rows) == 0 {
			return
		}
		header := schema.columns[table]
		if len(header) == 0 {
			header = unionKeys(rows)
		}
		f, err := zw.Create(path)
		if err != nil {
			log.Printf("[WARN] CSV export: create %s: %v", path, err)
			return
		}
		cw := csv.NewWriter(f)
		_ = cw.Write(header)
		for _, raw := range rows {
			m := decodeRow(raw)
			rec := make([]string, len(header))
			for i, col := range header {
				rec[i] = csvCell(m[col])
			}
			_ = cw.Write(rec)
		}
		cw.Flush()
		manifest = append(manifest, manifestRow{path: path, table: table, rows: len(rows)})
	}

	// scope_targets at the root: the spine of the export.
	writeCSV("scope_targets.csv", "scope_targets", bundle.ScopeTargets)

	// Every other table, grouped by workflow. Sorted for a stable zip.
	tables := make([]string, 0, len(bundle.TableData))
	for t := range bundle.TableData {
		tables = append(tables, t)
	}
	sort.Strings(tables)
	for _, table := range tables {
		cat := csvCategory(table)
		if req.CuratedOnly && cat == "recon" {
			// Curated-only keeps the high-signal folders and drops the long recon tail.
			continue
		}
		writeCSV(fmt.Sprintf("%s/%s.csv", cat, table), table, bundle.TableData[table])
	}

	// manifest.csv, written last so it can report everything above it.
	if mf, err := zw.Create("manifest.csv"); err == nil {
		cw := csv.NewWriter(mf)
		_ = cw.Write([]string{"file", "table", "rows"})
		sort.Slice(manifest, func(i, j int) bool { return manifest[i].path < manifest[j].path })
		for _, m := range manifest {
			_ = cw.Write([]string{m.path, m.table, fmt.Sprintf("%d", m.rows)})
		}
		// A trailing summary row so the totals are visible without a formula.
		total := 0
		for _, m := range manifest {
			total += m.rows
		}
		_ = cw.Write([]string{"TOTAL", fmt.Sprintf("%d files", len(manifest)), fmt.Sprintf("%d", total)})
		cw.Flush()
	}

	// README so the zip explains itself.
	if rf, err := zw.Create("README.txt"); err == nil {
		names := strings.Join(bundle.ExportMetadata.ScopeTargets, ", ")
		fmt.Fprintf(rf, "ars0n-framework CSV export\n"+
			"Generated: %s\nScope targets: %s\nTables: %d\nTotal rows: %d\n\n"+
			"One CSV per database table, grouped by workflow:\n"+
			"  auth/     authentication, authorization, session tokens\n"+
			"  urls/     manual crawl, endpoints, parameters, replay, flows\n"+
			"  findings/ attack vectors, vector/fuzz/triage/nuclei/WAF results\n"+
			"  threat/   threat model and notes\n"+
			"  config/   per-target tool configuration and settings\n"+
			"  recon/    subdomains, DNS, IPs, company/wildcard discovery\n\n"+
			"Cells holding JSON objects or arrays are written as compact JSON.\n"+
			"manifest.csv lists every file and its row count.\n",
			bundle.ExportMetadata.ExportedAt.Format(time.RFC3339), names,
			len(manifest), bundle.ExportMetadata.TotalRecords)
	}

	if err := zw.Close(); err != nil {
		log.Printf("[ERROR] CSV export: close zip: %v", err)
		http.Error(w, "Failed to finalize export", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("ars0n-csv-export-%s.zip", time.Now().Format("2006-01-02-15-04-05"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
	if _, err := w.Write(buf.Bytes()); err != nil {
		log.Printf("[ERROR] CSV export: write response: %v", err)
	}
	log.Printf("[INFO] CSV export completed: %d files, %d rows, %d bytes", len(manifest), bundle.ExportMetadata.TotalRecords, buf.Len())
}

func allScopeTargetIDs(ctx context.Context) ([]string, error) {
	rows, err := dbPool.Query(ctx, `SELECT id::text FROM scope_targets ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// csvCategory buckets a table into a folder by workflow, from its name prefix. Low-maintenance by
// design: a new table lands in a sensible folder without anyone editing a map, and the worst case is a
// new table under recon/ rather than a missing file.
func csvCategory(table string) string {
	switch {
	case strings.HasPrefix(table, "auth_") || strings.HasPrefix(table, "authz_") ||
		strings.HasPrefix(table, "session_token"):
		return "auth"
	case strings.HasPrefix(table, "manual_crawl") || strings.HasPrefix(table, "replay_") ||
		strings.HasPrefix(table, "request_flow") || strings.HasPrefix(table, "flow_") ||
		strings.HasPrefix(table, "detected_flow") || strings.HasPrefix(table, "consolidated_url") ||
		strings.HasPrefix(table, "discovered_endpoint") || strings.HasPrefix(table, "endpoint_") ||
		strings.HasPrefix(table, "param_enum") || strings.Contains(table, "url_scans") ||
		strings.Contains(table, "url_configs") || table == "target_urls":
		return "urls"
	case strings.HasPrefix(table, "vector_") || strings.HasPrefix(table, "fuzz_") ||
		strings.HasPrefix(table, "triage_") || strings.HasPrefix(table, "waf_probe") ||
		strings.HasPrefix(table, "nuclei") || table == "attack_vectors" ||
		strings.HasPrefix(table, "access_bypass") || strings.HasPrefix(table, "parameter_enumeration") ||
		strings.HasPrefix(table, "arjun") || strings.HasPrefix(table, "x8_") ||
		strings.HasPrefix(table, "ffuf"):
		return "findings"
	case strings.HasPrefix(table, "threat_"):
		return "threat"
	case strings.HasSuffix(table, "_config") || strings.HasSuffix(table, "_configs") ||
		strings.HasSuffix(table, "_settings") || strings.Contains(table, "engagement_config") ||
		strings.Contains(table, "tuning") || strings.HasPrefix(table, "scope_"):
		return "config"
	default:
		return "recon"
	}
}

// decodeRow parses one stored row, keeping numbers exact (json.Number) so an int64 id or a byte count
// is written as "12345", never "1.2345e+04".
func decodeRow(raw json.RawMessage) map[string]interface{} {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	m := map[string]interface{}{}
	_ = dec.Decode(&m)
	return m
}

// csvCell renders one value for a CSV cell. Scalars go verbatim; objects and arrays become compact
// JSON so the structure survives without breaking the row.
func csvCell(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprintf("%v", v)
		}
		return string(b)
	}
}

// unionKeys is the header fallback when the schema has no column list for a table (should not happen for
// a real table): the sorted union of keys seen across the rows.
func unionKeys(rows []json.RawMessage) []string {
	seen := map[string]bool{}
	for _, raw := range rows {
		for k := range decodeRow(raw) {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
