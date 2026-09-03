package utils

import (
	"strings"
	"testing"
)

// GET /scopetarget/{id}/scans read three tables: amass_scans, httpx_scans and gau_scans. All three
// belong to the Wildcard workflow, so against the URL target http://10.0.0.18:3000, which had 17
// finished runs across katana_url, linkfinder_url, waybackurls, gau_url, gospider_url, arjun and x8,
// the endpoint returned []. Nothing in that answer says "this handler cannot see URL scans", so it
// reads as "this target has never been scanned" and an agent re-runs work that is already done.
func TestGetAllScansReachesTheURLWorkflowTables(t *testing.T) {
	// The tables that actually held rows for that target, plus the two URL tools that had none on
	// the day but are just as invisible to a three-table list.
	required := []string{
		"katana_url_scans",
		"linkfinder_url_scans",
		"waybackurls_scans",
		"gau_url_scans",
		"gospider_url_scans",
		"ffuf_url_scans",
		"arjun_scans",
		"x8_scans",
		"nuclei_scans",
	}

	present := map[string]bool{}
	for _, source := range allScanTables {
		present[source.table] = true
	}
	for _, table := range required {
		if !present[table] {
			t.Errorf("%s is not in allScanTables, so a URL target's runs in it report as no scans at all", table)
		}
	}
}

// The Company workflow has the same shape of failure: none of its tables were in the old list
// either, so a Company target that had run amass_intel and an IP/port scan also answered [].
func TestGetAllScansReachesTheCompanyWorkflowTables(t *testing.T) {
	required := []string{
		"amass_intel_scans",
		"amass_enum_company_scans",
		"dnsx_company_scans",
		"katana_company_scans",
		"metabigor_company_scans",
		"ip_port_scans",
	}

	present := map[string]bool{}
	for _, source := range allScanTables {
		present[source.table] = true
	}
	for _, table := range required {
		if !present[table] {
			t.Errorf("%s is not in allScanTables, so a Company target's runs in it report as no scans at all", table)
		}
	}
}

// Every source has to produce exactly the eleven values GetAllScansForScopeTarget scans into, in the
// same order, and has to filter by scope target. A source that selects ten columns does not fail at
// build time, it fails at request time for that one table and then gets skipped, which puts us back
// at a silent missing scan type.
func TestEveryScanSourceSelectsTheColumnsTheHandlerReads(t *testing.T) {
	for _, source := range allScanTables {
		sql := source.selectQuery()

		if !strings.Contains(sql, " FROM "+source.table+" WHERE scope_target_id = $1") {
			t.Errorf("%s: query does not read %s filtered by scope target: %s", source.table, source.table, sql)
			continue
		}
		if !strings.HasPrefix(sql, "SELECT id::text, ") {
			t.Errorf("%s: query does not start with the id the handler scans first: %s", source.table, sql)
			continue
		}

		selectList := sql[len("SELECT "):strings.Index(sql, " FROM ")]
		if got := commaDepthZeroCount(selectList); got != 11 {
			t.Errorf("%s: select list has %d expressions, the handler scans 11: %s", source.table, got, selectList)
		}
		if !strings.HasSuffix(selectList, ", created_at") {
			t.Errorf("%s: created_at must be last, it is what the list is sorted by: %s", source.table, selectList)
		}
	}
}

// A table the source list names twice would duplicate every one of its scans in the response, and a
// scan_type reused across two tables makes the response ambiguous about which tool ran.
func TestScanSourcesAreUnique(t *testing.T) {
	tables := map[string]bool{}
	types := map[string]bool{}
	for _, source := range allScanTables {
		if tables[source.table] {
			t.Errorf("%s is listed twice, so its scans appear twice in the response", source.table)
		}
		tables[source.table] = true
		if types[source.scanType] {
			t.Errorf("scan_type %q is used by more than one table, so the caller cannot tell which tool ran", source.scanType)
		}
		types[source.scanType] = true
	}
}

// The five tables that never had stdout, stderr, result or command still have to yield a row. If a
// missing column were selected by name the query would error and that whole scan type would vanish
// from the list, which is the defect this handler was fixed for.
func TestATableMissingAColumnStillYieldsARow(t *testing.T) {
	source := scanTableSource{
		table: "vector_scans", scanType: "vector_scan",
		subject: "category", status: "status", errText: "error",
	}
	sql := source.selectQuery()

	for _, absent := range []string{"stdout", "stderr", "result", "command", "execution_time", "scan_id"} {
		if strings.Contains(sql, absent) {
			t.Errorf("query names %s, a column vector_scans does not have, so the query errors and the whole table is skipped: %s", absent, sql)
		}
	}
	if got := commaDepthZeroCount(sql[len("SELECT "):strings.Index(sql, " FROM ")]); got != 11 {
		t.Errorf("a table missing six columns must still select 11 expressions, got %d: %s", got, sql)
	}
}

// commaDepthZeroCount counts top-level comma-separated expressions, ignoring commas inside the
// parentheses of COALESCE and array_to_string.
func commaDepthZeroCount(selectList string) int {
	count := 1
	depth := 0
	inString := false
	for i := 0; i < len(selectList); i++ {
		switch selectList[i] {
		case '\'':
			inString = !inString
		case '(':
			if !inString {
				depth++
			}
		case ')':
			if !inString {
				depth--
			}
		case ',':
			if !inString && depth == 0 {
				count++
			}
		}
	}
	return count
}
