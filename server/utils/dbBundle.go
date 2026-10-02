package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Generic, schema-driven database bundle export/import (the .rs0n whole-target snapshot).
//
// WHY THIS REPLACES THE OLD MAP. The previous exporter (exportTableQueries in dbImportExport.go) was a
// hand-maintained map of 69 tables with EXPLICIT column lists. Two failure modes were baked in: a table
// nobody added to the map was silently absent from every export, and a COLUMN added to a covered table
// was silently dropped because the SELECT named the old columns. The result, by the time anyone looked,
// was that essentially the entire URL workflow - manual crawl, replay/variants, flows, auth, authz,
// endpoints, vectors, triage, fuzz, WAF probe, threat model, per-target settings - exported nothing.
//
// The engine here asks the DATABASE what to export, every time:
//   - every table with a scope_target_id column is a per-target table, filtered by the chosen targets;
//   - every table reachable from those by a foreign key is pulled in a fixpoint closure, so a child
//     three hops from the scope target (fuzz_finding_evidence -> fuzz_findings -> fuzz_runs) still
//     travels with it;
//   - content-addressed body blobs, which have no scope_target_id and no formal FK, are pulled by the
//     sha256 values the exported captures reference;
//   - every row is serialised with to_jsonb, so EVERY column and EVERY type (uuid, jsonb, arrays,
//     bytea, timestamps) crosses the wire exactly, with no per-column code to fall out of date.
//
// Import is the mirror: jsonb_populate_record turns each stored row back into the table's real rowtype,
// upserting on the table's ACTUAL primary key (not an assumed "id"). Foreign-key triggers are disabled
// for the load with SET LOCAL session_replication_role='replica', because the snapshot is internally
// consistent by construction and enforcing FKs mid-load would only force a topological sort that
// self-referential tables (replay_request_versions.parent_version_id) and cycles would break anyway.

const bundleFormatVersion = "2.0"

// safeIdent guards every identifier interpolated into SQL. Names come from information_schema, so they
// are already trusted; this is defence in depth against a future caller passing something else.
var safeIdent = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

func quoteIdent(name string) (string, error) {
	if !safeIdent.MatchString(name) {
		return "", fmt.Errorf("unsafe identifier %q", name)
	}
	return `"` + name + `"`, nil
}

// bundleFile is the on-disk shape (gzip of this JSON). Field names match the v1 format so the client's
// counters and any old reader keep working; rows are json.RawMessage so a bigint id or a deep jsonb
// body is never rounded through float64.
type bundleFile struct {
	ExportMetadata ExportMetadata               `json:"export_metadata"`
	ScopeTargets   []json.RawMessage            `json:"scope_targets"`
	TableData      map[string][]json.RawMessage `json:"table_data"`
}

type fkEdge struct {
	childCol    string
	parentTable string
	parentCol   string
}

// bundleSchema is the live picture of the database the engine plans against.
type bundleSchema struct {
	allTables   map[string]bool     // every base table in public
	perTarget   map[string]bool     // tables with a scope_target_id column
	pk          map[string][]string // table -> primary key columns (nil = no PK)
	columns     map[string][]string // table -> all column names
	childFKs    map[string][]fkEdge // child table -> its outbound FK edges
	// refCols[parentTable][parentCol] = true when some FK points at that column, so export only has to
	// remember the values of columns something can reference.
	refCols map[string]map[string]bool
}

// tablesToSkip are never exported or imported: a PK-less backup artefact, and the migration bookkeeping
// table (its rows are about THIS database's migration history, not the target's findings).
var bundleSkipTables = map[string]bool{
	"cue_backup_prekeyfix": true,
	"schema_migrations":    true,
}

func collectBundleSchema(ctx context.Context) (*bundleSchema, error) {
	s := &bundleSchema{
		allTables: map[string]bool{},
		perTarget: map[string]bool{},
		pk:        map[string][]string{},
		columns:   map[string][]string{},
		childFKs:  map[string][]fkEdge{},
		refCols:   map[string]map[string]bool{},
	}

	// All base tables, and every column in order.
	rows, err := dbPool.Query(ctx, `
		SELECT c.table_name, c.column_name
		  FROM information_schema.columns c
		  JOIN information_schema.tables t
		    ON t.table_schema = c.table_schema AND t.table_name = c.table_name
		 WHERE c.table_schema = 'public' AND t.table_type = 'BASE TABLE'
		 ORDER BY c.table_name, c.ordinal_position`)
	if err != nil {
		return nil, fmt.Errorf("read columns: %w", err)
	}
	for rows.Next() {
		var table, col string
		if err := rows.Scan(&table, &col); err != nil {
			rows.Close()
			return nil, err
		}
		if bundleSkipTables[table] {
			continue
		}
		s.allTables[table] = true
		s.columns[table] = append(s.columns[table], col)
		if col == "scope_target_id" {
			s.perTarget[table] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Primary keys.
	pkRows, err := dbPool.Query(ctx, `
		SELECT tc.table_name, kcu.column_name
		  FROM information_schema.table_constraints tc
		  JOIN information_schema.key_column_usage kcu
		    ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		 WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_schema = 'public'
		 ORDER BY tc.table_name, kcu.ordinal_position`)
	if err != nil {
		return nil, fmt.Errorf("read primary keys: %w", err)
	}
	for pkRows.Next() {
		var table, col string
		if err := pkRows.Scan(&table, &col); err != nil {
			pkRows.Close()
			return nil, err
		}
		if s.allTables[table] {
			s.pk[table] = append(s.pk[table], col)
		}
	}
	pkRows.Close()
	if err := pkRows.Err(); err != nil {
		return nil, err
	}

	// Foreign keys. Grouped by constraint so a composite FK contributes matched column pairs in order,
	// not a cartesian product of the two column lists (which the naive three-way join produces).
	fkRows, err := dbPool.Query(ctx, `
		SELECT tc.constraint_name, tc.table_name AS child, kcu.column_name AS child_col,
		       ccu.table_name AS parent, ccu.column_name AS parent_col, kcu.ordinal_position
		  FROM information_schema.table_constraints tc
		  JOIN information_schema.key_column_usage kcu
		    ON tc.constraint_name = kcu.constraint_name AND tc.table_schema = kcu.table_schema
		  JOIN information_schema.referential_constraints rc
		    ON rc.constraint_name = tc.constraint_name AND rc.constraint_schema = tc.table_schema
		  JOIN information_schema.key_column_usage ccu
		    ON ccu.constraint_name = rc.unique_constraint_name
		   AND ccu.table_schema = rc.unique_constraint_schema
		   AND ccu.ordinal_position = kcu.position_in_unique_constraint
		 WHERE tc.constraint_type = 'FOREIGN KEY' AND tc.table_schema = 'public'
		 ORDER BY tc.constraint_name, kcu.ordinal_position`)
	if err != nil {
		return nil, fmt.Errorf("read foreign keys: %w", err)
	}
	for fkRows.Next() {
		var cname, child, childCol, parent, parentCol string
		var ord int
		if err := fkRows.Scan(&cname, &child, &childCol, &parent, &parentCol, &ord); err != nil {
			fkRows.Close()
			return nil, err
		}
		if !s.allTables[child] || !s.allTables[parent] {
			continue
		}
		s.childFKs[child] = append(s.childFKs[child], fkEdge{childCol: childCol, parentTable: parent, parentCol: parentCol})
		if s.refCols[parent] == nil {
			s.refCols[parent] = map[string]bool{}
		}
		s.refCols[parent][parentCol] = true
	}
	fkRows.Close()
	if err := fkRows.Err(); err != nil {
		return nil, err
	}

	return s, nil
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

// exportBundle produces the whole-target snapshot for the given scope targets. It is the v2 engine
// behind HandleDatabaseExport.
func exportBundle(ctx context.Context, scopeTargetIDs []string) (*bundleFile, error) {
	if len(scopeTargetIDs) == 0 {
		return nil, fmt.Errorf("no scope targets specified")
	}
	schema, err := collectBundleSchema(ctx)
	if err != nil {
		return nil, err
	}

	out := &bundleFile{TableData: map[string][]json.RawMessage{}}

	// exportedVals[table][col] = set of stringified values that other rows can reference. Only columns
	// that are FK targets are tracked, which keeps this to a handful of id/scan_id columns.
	exportedVals := map[string]map[string]map[string]bool{}
	// rowKeys[table] = set of already-exported row identities, so a child pulled through two FK paths is
	// stored once.
	rowKeys := map[string]map[string]bool{}

	remember := func(table string, raws []json.RawMessage) {
		wanted := schema.refCols[table]
		pkCols := schema.pk[table]
		for _, raw := range raws {
			var m map[string]interface{}
			if err := json.Unmarshal(raw, &m); err != nil {
				continue
			}
			// Track referenceable values.
			for col := range wanted {
				if v, ok := m[col]; ok && v != nil {
					if exportedVals[table] == nil {
						exportedVals[table] = map[string]map[string]bool{}
					}
					if exportedVals[table][col] == nil {
						exportedVals[table][col] = map[string]bool{}
					}
					exportedVals[table][col][fmt.Sprintf("%v", v)] = true
				}
			}
			// Track row identity (by PK) for dedupe.
			if len(pkCols) > 0 {
				if rowKeys[table] == nil {
					rowKeys[table] = map[string]bool{}
				}
				rowKeys[table][rowIdentity(m, pkCols)] = true
			}
		}
	}

	selectWhere := func(table, where string, args ...interface{}) ([]json.RawMessage, error) {
		qt, err := quoteIdent(table)
		if err != nil {
			return nil, err
		}
		sql := fmt.Sprintf("SELECT to_jsonb(t)::text FROM %s t", qt)
		if where != "" {
			sql += " WHERE " + where
		}
		rows, err := dbPool.Query(ctx, sql, args...)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var raws []json.RawMessage
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return nil, err
			}
			cp := make([]byte, len(raw))
			copy(cp, raw)
			raws = append(raws, cp)
		}
		return raws, rows.Err()
	}

	// scope_targets themselves.
	stRows, err := selectWhere("scope_targets", "id = ANY($1)", scopeTargetIDs)
	if err != nil {
		return nil, fmt.Errorf("export scope_targets: %w", err)
	}
	out.ScopeTargets = stRows
	remember("scope_targets", stRows)

	var tablesExported []string
	total := len(stRows)

	// Round 1: every per-target table.
	for table := range schema.perTarget {
		raws, err := selectWhere(table, "scope_target_id = ANY($1)", scopeTargetIDs)
		if err != nil {
			log.Printf("[BUNDLE] export skip %s: %v", table, err)
			continue
		}
		if len(raws) > 0 {
			out.TableData[table] = raws
			remember(table, raws)
			tablesExported = append(tablesExported, table)
			total += len(raws)
		}
	}

	// Round 2: fixpoint over child tables (no scope_target_id) reachable by FK from anything exported.
	for pass := 0; pass < 20; pass++ {
		changed := false
		for table := range schema.allTables {
			if schema.perTarget[table] || table == "scope_targets" {
				continue
			}
			edges := schema.childFKs[table]
			if len(edges) == 0 {
				continue
			}
			var conds []string
			var args []interface{}
			for _, e := range edges {
				vals := exportedVals[e.parentTable][e.parentCol]
				if len(vals) == 0 {
					continue
				}
				qc, err := quoteIdent(e.childCol)
				if err != nil {
					continue
				}
				args = append(args, setToSlice(vals))
				conds = append(conds, fmt.Sprintf("%s = ANY($%d)", qc, len(args)))
			}
			if len(conds) == 0 {
				continue
			}
			raws, err := selectWhere(table, strings.Join(conds, " OR "), args...)
			if err != nil {
				log.Printf("[BUNDLE] export child skip %s: %v", table, err)
				continue
			}
			// Keep only rows not already stored (a child reachable by two paths, or re-seen next pass).
			fresh := dedupeNewRows(raws, schema.pk[table], rowKeys[table])
			if len(fresh) > 0 {
				out.TableData[table] = append(out.TableData[table], fresh...)
				remember(table, fresh)
				if !bundleContains(tablesExported, table) {
					tablesExported = append(tablesExported, table)
				}
				total += len(fresh)
				changed = true
			}
		}
		if !changed {
			break
		}
	}

	// Content-addressed body blobs: no scope_target_id, no FK, referenced by captures' sha256 values.
	if schema.allTables["manual_crawl_body_blobs"] {
		if blobRaws, err := exportBodyBlobs(ctx, out); err != nil {
			log.Printf("[BUNDLE] export body blobs: %v", err)
		} else if len(blobRaws) > 0 {
			out.TableData["manual_crawl_body_blobs"] = blobRaws
			tablesExported = append(tablesExported, "manual_crawl_body_blobs")
			total += len(blobRaws)
		}
	}

	names := make([]string, 0, len(stRows))
	for _, raw := range stRows {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) == nil {
			if n, ok := m["scope_target"].(string); ok {
				names = append(names, n)
			}
		}
	}

	out.ExportMetadata = ExportMetadata{
		ExportedAt:     time.Now(),
		Version:        bundleFormatVersion,
		ScopeTargetIDs: scopeTargetIDs,
		ScopeTargets:   names,
		TotalRecords:   total,
		TablesExported: tablesExported,
	}
	return out, nil
}

// exportBodyBlobs pulls the blob rows whose sha256 is referenced by any exported manual_crawl_captures
// row - both the response_body_sha256 column and any sha256 recorded inside the storage_originals jsonb.
func exportBodyBlobs(ctx context.Context, out *bundleFile) ([]json.RawMessage, error) {
	captures := out.TableData["manual_crawl_captures"]
	if len(captures) == 0 {
		return nil, nil
	}
	shaSet := map[string]bool{}
	for _, raw := range captures {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		if s, ok := m["response_body_sha256"].(string); ok && s != "" {
			shaSet[s] = true
		}
		// storage_originals is an object whose leaves may carry a sha256 for the request/response bodies.
		collectSha256(m["storage_originals"], shaSet)
	}
	if len(shaSet) == 0 {
		return nil, nil
	}
	rows, err := dbPool.Query(ctx,
		`SELECT to_jsonb(t)::text FROM manual_crawl_body_blobs t WHERE sha256 = ANY($1)`, setToSlice(shaSet))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var raws []json.RawMessage
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		cp := make([]byte, len(raw))
		copy(cp, raw)
		raws = append(raws, cp)
	}
	return raws, rows.Err()
}

// collectSha256 walks an arbitrary decoded-JSON value and records any string under a key that looks
// like a sha256 hash, so blobs referenced only from inside storage_originals still travel.
func collectSha256(v interface{}, out map[string]bool) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			if s, ok := val.(string); ok {
				lk := strings.ToLower(k)
				if strings.Contains(lk, "sha256") || lk == "sha" || lk == "hash" {
					if len(s) == 64 {
						out[s] = true
					}
				}
			} else {
				collectSha256(val, out)
			}
		}
	case []interface{}:
		for _, item := range t {
			collectSha256(item, out)
		}
	}
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

// importBundle loads a v2 snapshot. FK triggers are off for the load (the snapshot is consistent), so
// table order does not matter and self-referential / cyclic tables load without a topological sort.
func importBundle(ctx context.Context, bundle *bundleFile) (imported int, tables int, failed int, err error) {
	schema, err := collectBundleSchema(ctx)
	if err != nil {
		return 0, 0, 0, err
	}

	conn, err := dbPool.Acquire(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	defer conn.Release()

	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	defer tx.Rollback(ctx)

	// SET LOCAL: scoped to this transaction, so the pooled connection can never leak replica mode to a
	// later query even if we forget to reset it.
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = 'replica'"); err != nil {
		return 0, 0, 0, fmt.Errorf("disable fk triggers: %w", err)
	}

	// scope_targets first, and a failure here is FATAL. It is the parent every per-target table
	// hangs off, so committing child rows against a scope_targets that only partly loaded would
	// leave them orphaned; a root that did not fully land aborts the whole restore rather than
	// commit an inconsistent graph.
	if n, fail, terr := importBundleTable(ctx, tx, schema, "scope_targets", bundle.ScopeTargets); terr != nil {
		return 0, 0, 0, fmt.Errorf("import scope_targets: %w", terr)
	} else if fail > 0 {
		return 0, 0, 0, fmt.Errorf("import scope_targets: %d row(s) could not be loaded, so the restore was aborted to avoid orphaned child rows", fail)
	} else {
		imported += n
	}

	for table, raws := range bundle.TableData {
		if table == "scope_targets" {
			continue
		}
		n, fail, terr := importBundleTable(ctx, tx, schema, table, raws)
		imported += n
		failed += fail
		if terr != nil {
			// A transaction-level failure means the transaction can no longer commit, so continuing
			// to other tables would only pile up failures against a dead tx. Surface it instead of
			// committing a half-restore as success.
			return 0, 0, 0, fmt.Errorf("import %s: %w", table, terr)
		}
		if n > 0 {
			tables++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, 0, 0, fmt.Errorf("commit: %w", err)
	}
	return imported, tables, failed, nil
}

// importBundleTable upserts every row of one table in a single statement, keyed on the table's real
// primary key. Wrapped in a savepoint so a table that fails leaves the rest of the import intact.
func importBundleTable(ctx context.Context, tx pgx.Tx, schema *bundleSchema, table string, raws []json.RawMessage) (imported int, failed int, err error) {
	if len(raws) == 0 {
		return 0, 0, nil
	}
	if !schema.allTables[table] {
		log.Printf("[BUNDLE] import: unknown table %s, skipping %d rows", table, len(raws))
		return 0, 0, nil
	}
	qt, err := quoteIdent(table)
	if err != nil {
		return 0, 0, err
	}
	pkCols := schema.pk[table]

	var conflict string
	if len(pkCols) == 0 {
		// No PK (should not happen post-skip-list): plain insert, no upsert.
		conflict = ""
	} else {
		quotedPK := make([]string, 0, len(pkCols))
		pkSet := map[string]bool{}
		for _, c := range pkCols {
			qc, qerr := quoteIdent(c)
			if qerr != nil {
				return 0, 0, qerr
			}
			quotedPK = append(quotedPK, qc)
			pkSet[c] = true
		}
		var sets []string
		for _, c := range schema.columns[table] {
			if pkSet[c] {
				continue
			}
			qc, qerr := quoteIdent(c)
			if qerr != nil {
				return 0, 0, qerr
			}
			sets = append(sets, fmt.Sprintf("%s = EXCLUDED.%s", qc, qc))
		}
		if len(sets) == 0 {
			// Every column is part of the PK: nothing to update, just avoid duplicate-key errors.
			conflict = fmt.Sprintf("ON CONFLICT (%s) DO NOTHING", strings.Join(quotedPK, ", "))
		} else {
			conflict = fmt.Sprintf("ON CONFLICT (%s) DO UPDATE SET %s",
				strings.Join(quotedPK, ", "), strings.Join(sets, ", "))
		}
	}

	sql := fmt.Sprintf(
		"INSERT INTO %s SELECT (jsonb_populate_record(NULL::%s, elem)).* "+
			"FROM jsonb_array_elements($1::jsonb) elem %s", qt, qt, conflict)

	// BATCHED BY BOTH ROW COUNT AND SERIALISED BYTE SIZE. The whole table as one jsonb parameter
	// blows past Postgres's 256 MB jsonb field limit on a big table, and a fixed 1000-row batch does
	// the same on a bytea-heavy one (triage_bodies, manual_crawl_body_blobs, triage_verdicts) where
	// to_jsonb renders each blob as a hex string twice its byte size. Capping the batch at a few MB
	// of JSON keeps it under that limit; a batch that fails anyway (one row larger than the cap, or
	// any other exec error) is retried ROW BY ROW so a single oversized row is isolated and the rest
	// of the batch still loads. Rows that cannot be loaded even on their own are COUNTED into failed
	// and surfaced, never silently dropped: that is the difference between a restore that lost data
	// and one that reported success while losing it.
	const maxBatchRows = 1000
	const maxBatchBytes = 32 << 20 // 32 MB of serialised JSON, well under the 256 MB jsonb field limit
	total := 0
	for i := 0; i < len(raws); {
		end := i
		batchBytes := 0
		for end < len(raws) && end-i < maxBatchRows {
			rb := len(raws[end])
			if end > i && batchBytes+rb > maxBatchBytes {
				break
			}
			batchBytes += rb
			end++
		}
		imp, fail, ferr := importBundleBatch(ctx, tx, sql, table, raws[i:end])
		total += imp
		failed += fail
		if ferr != nil {
			// A transaction-level failure (a savepoint the connection would not create or roll back)
			// means the transaction can no longer commit, so there is nothing to gain by grinding on.
			return total, failed, ferr
		}
		i = end
	}
	if failed > 0 {
		log.Printf("[BUNDLE] imported %d/%d rows into %s (%d row(s) could not be loaded)", total, len(raws), table, failed)
	} else {
		log.Printf("[BUNDLE] imported %d rows into %s", total, table)
	}
	return total, failed, nil
}

// importBundleBatch loads one batch as a single statement, and on any non-fatal failure retries the
// batch ONE ROW AT A TIME so a single oversized or malformed row is isolated rather than taking the
// other rows down with it. It returns how many rows loaded, how many could not be loaded at all,
// and a fatal error only when the transaction itself became unusable.
func importBundleBatch(ctx context.Context, tx pgx.Tx, sql, table string, batch []json.RawMessage) (imported int, failed int, fatal error) {
	if len(batch) == 0 {
		return 0, 0, nil
	}
	n, ok, ferr := tryBundleExec(ctx, tx, sql, batch)
	if ferr != nil {
		return 0, 0, ferr
	}
	if ok {
		return n, 0, nil
	}
	if len(batch) == 1 {
		log.Printf("[BUNDLE] import %s: a row could not be loaded even on its own (%d bytes); counting it as failed", table, len(batch[0]))
		return 0, 1, nil
	}
	for _, raw := range batch {
		imp, fail, ferr := importBundleBatch(ctx, tx, sql, table, []json.RawMessage{raw})
		if ferr != nil {
			return imported, failed, ferr
		}
		imported += imp
		failed += fail
	}
	return imported, failed, nil
}

// tryBundleExec runs one jsonb-array insert inside its own savepoint so a failure rolls back only
// this attempt and leaves the transaction usable for the next. ok is false for a failure that is
// this batch's own (a marshal error, or a row the server rejected); fatal is set only when the
// savepoint machinery itself failed, which means the connection or transaction is gone.
func tryBundleExec(ctx context.Context, tx pgx.Tx, sql string, batch []json.RawMessage) (imported int, ok bool, fatal error) {
	arr, merr := json.Marshal(batch)
	if merr != nil {
		return 0, false, nil
	}
	const sp = "bundle_sp"
	if _, err := tx.Exec(ctx, "SAVEPOINT "+sp); err != nil {
		return 0, false, fmt.Errorf("savepoint: %w", err)
	}
	tag, execErr := tx.Exec(ctx, sql, arr)
	if execErr != nil {
		if _, rberr := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+sp); rberr != nil {
			return 0, false, fmt.Errorf("rollback to savepoint: %w", rberr)
		}
		return 0, false, nil
	}
	_, _ = tx.Exec(ctx, "RELEASE SAVEPOINT "+sp)
	return int(tag.RowsAffected()), true, nil
}

// processBundleImportJSON is the single entry point both import handlers (file upload and URL) call. It
// picks the engine by format version: v2 goes through the generic importBundle; anything older falls
// back to the legacy importDatabaseData so bundles exported before this overhaul still import.
func processBundleImportJSON(ctx context.Context, jsonData []byte) (scopeTargets, tables, records, failed int, err error) {
	var probe struct {
		ExportMetadata ExportMetadata `json:"export_metadata"`
	}
	_ = json.Unmarshal(jsonData, &probe)

	if strings.HasPrefix(probe.ExportMetadata.Version, "2") {
		var bundle bundleFile
		if err := json.Unmarshal(jsonData, &bundle); err != nil {
			return 0, 0, 0, 0, fmt.Errorf("invalid v2 bundle: %w", err)
		}
		imp, tbl, fail, err := importBundle(ctx, &bundle)
		if err != nil {
			return 0, 0, 0, 0, err
		}
		return len(bundle.ScopeTargets), tbl, imp, fail, nil
	}

	// Legacy v1 bundle (uuids stored as byte arrays, hand-maintained table set).
	var ed ExportData
	if err := json.Unmarshal(jsonData, &ed); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("invalid v1 bundle: %w", err)
	}
	if err := importDatabaseData(&ed); err != nil {
		return 0, 0, 0, 0, err
	}
	return len(ed.ScopeTargets), len(ed.TableData), ed.ExportMetadata.TotalRecords, 0, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func rowIdentity(m map[string]interface{}, pkCols []string) string {
	parts := make([]string, len(pkCols))
	for i, c := range pkCols {
		parts[i] = fmt.Sprintf("%v", m[c])
	}
	return strings.Join(parts, "\x00")
}

func dedupeNewRows(raws []json.RawMessage, pkCols []string, seen map[string]bool) []json.RawMessage {
	if len(pkCols) == 0 {
		// Cannot dedupe without a key; return as-is (only PK-less tables hit this, and those are skipped).
		return raws
	}
	var out []json.RawMessage
	for _, raw := range raws {
		var m map[string]interface{}
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		key := rowIdentity(m, pkCols)
		if seen != nil && seen[key] {
			continue
		}
		out = append(out, raw)
	}
	return out
}

func setToSlice(s map[string]bool) []string {
	out := make([]string, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

func bundleContains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
