package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// RequestPayload represents the request body for creating a scope target
type RequestPayload struct {
	Type        string `json:"type"`
	Mode        string `json:"mode"`
	ScopeTarget string `json:"scope_target"`
	Active      bool   `json:"active"`
}

// ResponsePayload represents the response for reading scope targets
type ResponsePayload struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	ScopeTarget string `json:"scope_target"`
	Active      bool   `json:"active"`
}

// ScanSummary represents a summary of a scan
type ScanSummary struct {
	ID        string    `json:"id"`
	ScanID    string    `json:"scan_id"`
	Domain    string    `json:"domain"`
	Status    string    `json:"status"`
	Result    string    `json:"result"`
	Error     string    `json:"error"`
	StdOut    string    `json:"stdout"`
	StdErr    string    `json:"stderr"`
	Command   string    `json:"command"`
	ExecTime  string    `json:"execution_time"`
	CreatedAt time.Time `json:"created_at"`
	ScanType  string    `json:"scan_type"`
}

// CreateScopeTarget handles the creation of a new scope target
func CreateScopeTarget(w http.ResponseWriter, r *http.Request) {
	var payload RequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// MODE IS DEFAULTED AND VALIDATED HERE rather than being passed through untouched.
	//
	// The column carries CHECK (mode IN ('Passive','Active')), and this handler used to forward
	// whatever it was given. A caller that omitted mode sent the empty string and a caller that sent
	// anything else sent that, and both violated the constraint, so every such request became a bare
	// HTTP 500 with the real reason visible only in the API container's log. The MCP tool documented
	// the values as "bb" and "pentest", which meant adding a target through the MCP server failed
	// 100 percent of the time in a way that looked like a server fault rather than a bad argument.
	mode := strings.TrimSpace(payload.Mode)
	switch strings.ToLower(mode) {
	case "":
		// Passive is the safe default: it is what the UI creates by default, and a target that
		// silently began active scanning because a field was omitted would be a worse surprise.
		mode = "Passive"
	case "passive":
		mode = "Passive"
	case "active":
		mode = "Active"
	default:
		http.Error(w, "mode must be Passive or Active, got "+payload.Mode, http.StatusBadRequest)
		return
	}

	query := `INSERT INTO scope_targets (type, mode, scope_target, active) VALUES ($1, $2, $3, $4)`
	_, err := dbPool.Exec(context.Background(), query, payload.Type, mode, payload.ScopeTarget, payload.Active)
	if err != nil {
		log.Printf("Error inserting into database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request saved successfully"})
}

// ReadScopeTarget retrieves all scope targets
func ReadScopeTarget(w http.ResponseWriter, r *http.Request) {
	rows, err := dbPool.Query(context.Background(), `SELECT id, type, scope_target, active FROM scope_targets`)
	if err != nil {
		log.Printf("Error querying database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var results = []ResponsePayload{}
	for rows.Next() {
		var res ResponsePayload
		if err := rows.Scan(&res.ID, &res.Type, &res.ScopeTarget, &res.Active); err != nil {
			log.Printf("Error scanning row: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		results = append(results, res)
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(results)
}

// DeleteScopeTarget deletes a scope target by ID
func DeleteScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "ID is required in the path", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM scope_targets WHERE id = $1`
	_, err := dbPool.Exec(context.Background(), query, id)
	if err != nil {
		log.Printf("Error deleting from database: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Request deleted successfully"})
}

// ActivateScopeTarget activates a scope target and deactivates all others
func ActivateScopeTarget(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		http.Error(w, "ID is required in the path", http.StatusBadRequest)
		return
	}

	// Start a transaction
	tx, err := dbPool.Begin(context.Background())
	if err != nil {
		log.Printf("[ERROR] Failed to begin transaction: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	// First, deactivate all scope targets
	_, err = tx.Exec(context.Background(), `UPDATE scope_targets SET active = false`)
	if err != nil {
		log.Printf("[ERROR] Failed to deactivate scope targets: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Then, activate the selected scope target
	result, err := tx.Exec(context.Background(), `UPDATE scope_targets SET active = true WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to activate scope target: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Scope target not found", http.StatusNotFound)
		return
	}

	// Commit the transaction
	if err := tx.Commit(context.Background()); err != nil {
		log.Printf("[ERROR] Failed to commit transaction: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Scope target activated successfully"})
}

// scanTableSource describes one scan table well enough for a single query and a single Scan call to
// read a ScanSummary out of it.
//
// The tables do not agree on their columns. The subdomain tools record a `domain`, the URL tools a
// `url`, the company tools a `company_name` or a `domains` array, and the parameter runners record
// no subject of their own because their targets come from a selection table rather than from a
// column on the run. A few tables predate stdout/stderr capture entirely. Naming the expression per
// table is what lets one loop read all of them.
type scanTableSource struct {
	table    string
	scanType string
	// SQL expressions, or "" where the table has no such column. Every non-empty one is coerced to
	// text and defaulted, so a NULL never aborts a row.
	subject  string
	scanID   string
	status   string
	result   string
	errText  string
	stdout   string
	stderr   string
	command  string
	execTime string
}

// standardScanTable describes a table carrying the original amass_scans column set, which is all but
// five of them.
func standardScanTable(table, scanType, subject string) scanTableSource {
	return scanTableSource{
		table:    table,
		scanType: scanType,
		subject:  subject,
		scanID:   "scan_id",
		status:   "status",
		result:   "result",
		errText:  "error",
		stdout:   "stdout",
		stderr:   "stderr",
		command:  "command",
		execTime: "execution_time",
	}
}

// selectQuery renders the one query shape every scan table is read with. A column the table does not
// have is selected as the empty string rather than dropped, because a run that recorded no stdout is
// still a run that happened and still has to appear in the list.
func (s scanTableSource) selectQuery() string {
	text := func(expr string) string {
		if expr == "" {
			return "''"
		}
		return "COALESCE((" + expr + ")::text, '')"
	}
	return "SELECT id::text, " + text(s.scanID) + ", " + text(s.subject) + ", " + text(s.status) +
		", " + text(s.result) + ", " + text(s.errText) + ", " + text(s.stdout) + ", " +
		text(s.stderr) + ", " + text(s.command) + ", " + text(s.execTime) + ", created_at FROM " +
		s.table + " WHERE scope_target_id = $1"
}

// subjectPreview keeps a multi-valued subject readable. nuclei_scans stores every target it was
// pointed at, which on a Wildcard target is a 10KB array, and this value sits inline beside every
// other scan in the list. The marker is part of the value because a silently cut string reads as the
// whole list.
func subjectPreview(expr string) string {
	cast := "(" + expr + ")::text"
	return "CASE WHEN length(" + cast + ") > 200 THEN left(" + cast + ", 200) || ' ... [truncated]' ELSE " + cast + " END"
}

// allScanTables is every table that records a scan run against a scope target.
//
// This list used to be three tables: amass, httpx and gau, all three of them Wildcard tools. Against
// the URL target http://10.0.0.18:3000, which had 17 completed runs spread across katana_url,
// linkfinder_url, waybackurls, gau_url, gospider_url, arjun and x8, /scopetarget/{id}/scans returned
// []. An empty array from an endpoint named "all scans" reads as "this target has never been
// scanned", so the one call that answers "what has already run here" said nothing had.
var allScanTables = []scanTableSource{
	// Wildcard subdomain discovery.
	standardScanTable("amass_scans", "amass", "domain"),
	standardScanTable("assetfinder_scans", "assetfinder", "domain"),
	standardScanTable("ctl_scans", "ctl", "domain"),
	standardScanTable("gau_scans", "gau", "domain"),
	standardScanTable("gospider_scans", "gospider", "domain"),
	standardScanTable("shuffledns_scans", "shuffledns", "domain"),
	standardScanTable("shufflednscustom_scans", "shuffledns_custom", "domain"),
	standardScanTable("subdomainizer_scans", "subdomainizer", "domain"),
	standardScanTable("subfinder_scans", "subfinder", "domain"),
	standardScanTable("sublist3r_scans", "sublist3r", "domain"),
	standardScanTable("cewl_scans", "cewl", "url"),

	// Wildcard live-host and enrichment passes.
	standardScanTable("httpx_scans", "httpx", "domain"),
	standardScanTable("metadata_scans", "metadata", "domain"),
	standardScanTable("nuclei_screenshots", "nuclei_screenshot", "domain"),
	standardScanTable("investigate_scans", "investigate", ""),

	// Company workflow.
	standardScanTable("amass_intel_scans", "amass_intel", "company_name"),
	standardScanTable("amass_enum_company_scans", "amass_enum_company", subjectPreview("domains")),
	standardScanTable("censys_company_scans", "censys_company", "company_name"),
	standardScanTable("cloud_enum_scans", "cloud_enum", "company_name"),
	standardScanTable("ctl_company_scans", "ctl_company", "company_name"),
	standardScanTable("dnsx_company_scans", "dnsx_company", subjectPreview("domains")),
	standardScanTable("github_recon_scans", "github_recon", "company_name"),
	standardScanTable("katana_company_scans", "katana_company", subjectPreview("domains")),
	standardScanTable("metabigor_company_scans", "metabigor_company", "company_name"),
	standardScanTable("securitytrails_company_scans", "securitytrails_company", "company_name"),
	standardScanTable("shodan_company_scans", "shodan_company", "company_name"),

	// URL workflow discovery.
	standardScanTable("katana_url_scans", "katana_url", "url"),
	standardScanTable("linkfinder_url_scans", "linkfinder_url", "url"),
	standardScanTable("waybackurls_scans", "waybackurls", "url"),
	standardScanTable("gau_url_scans", "gau_url", "url"),
	standardScanTable("gospider_url_scans", "gospider_url", "url"),
	standardScanTable("ffuf_url_scans", "ffuf_url", "url"),

	// URL workflow attack-surface passes.
	standardScanTable("arjun_scans", "arjun", ""),
	standardScanTable("x8_scans", "x8", ""),
	standardScanTable("ffuf_scans", "ffuf", ""),
	standardScanTable("nuclei_scans", "nuclei", subjectPreview("array_to_string(targets, ', ')")),
	standardScanTable("waf_probe_scans", "waf_probe", "url"),

	// The five tables that never had the full column set. They are listed here rather than left out
	// because leaving a scan table out is exactly the defect this list exists to fix.
	{
		table: "ip_port_scans", scanType: "ip_port",
		scanID: "scan_id", status: "status", errText: "error_message",
		command: "command", execTime: "execution_time",
	},
	{
		table: "company_metadata_scans", scanType: "company_metadata",
		scanID: "scan_id", status: "status", errText: "error_message",
		execTime: "execution_time",
	},
	{
		table: "endpoint_validation_scans", scanType: "endpoint_validation",
		scanID: "scan_id", status: "status", result: "result", errText: "error",
		execTime: "execution_time",
	},
	{
		table: "endpoint_investigation_scans", scanType: "endpoint_investigation",
		scanID: "scan_id", status: "status", result: "result", errText: "error",
		execTime: "execution_time",
	},
	{
		table: "vector_scans", scanType: "vector_scan",
		subject: "category || ' / ' || tool", status: "status", errText: "error",
	},
}

// GetAllScansForScopeTarget retrieves all scans for a scope target
func GetAllScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// A scope target that does not exist and a scope target that has never been scanned both used to
	// answer with an empty array. Those are different answers and a caller cannot act on either
	// without knowing which one it got, so a missing target is now a 404.
	var exists bool
	if err := dbPool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM scope_targets WHERE id = $1)`, scopeTargetID).Scan(&exists); err != nil {
		log.Printf("[ERROR] Failed to look up scope target %s: %v", scopeTargetID, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if !exists {
		http.Error(w, "Scope target not found", http.StatusNotFound)
		return
	}

	var allScans = []ScanSummary{}
	for _, source := range allScanTables {
		rows, err := dbPool.Query(context.Background(), source.selectQuery(), scopeTargetID)
		if err != nil {
			// One table an older database has not migrated yet must not blank the whole list. The
			// previous code returned 500 on the first failure, which turns a single missing table
			// into "this target has no scans at all".
			log.Printf("[ERROR] Failed to fetch %s scans: %v", source.table, err)
			continue
		}
		for rows.Next() {
			var scan ScanSummary
			if err := rows.Scan(
				&scan.ID,
				&scan.ScanID,
				&scan.Domain,
				&scan.Status,
				&scan.Result,
				&scan.Error,
				&scan.StdOut,
				&scan.StdErr,
				&scan.Command,
				&scan.ExecTime,
				&scan.CreatedAt,
			); err != nil {
				log.Printf("[ERROR] Failed to scan %s row: %v", source.table, err)
				continue
			}
			scan.ScanType = source.scanType
			allScans = append(allScans, scan)
		}
		rows.Close()
	}

	// Sort all scans by creation date, newest first
	sort.Slice(allScans, func(i, j int) bool {
		return allScans[i].CreatedAt.After(allScans[j].CreatedAt)
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allScans)
}
