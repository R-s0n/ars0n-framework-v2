package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
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

	query := `INSERT INTO scope_targets (type, mode, scope_target, active) VALUES ($1, $2, $3, $4)`
	_, err := dbPool.Exec(context.Background(), query, payload.Type, payload.Mode, payload.ScopeTarget, payload.Active)
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

	var results []ResponsePayload
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

// GetAllScansForScopeTarget retrieves all scans for a scope target
func GetAllScansForScopeTarget(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["id"]
	if scopeTargetID == "" {
		http.Error(w, "Scope target ID is required", http.StatusBadRequest)
		return
	}

	// Query for Amass scans
	amassQuery := `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
		FROM amass_scans 
		WHERE scope_target_id = $1
	`
	amassRows, err := dbPool.Query(context.Background(), amassQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch Amass scans: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer amassRows.Close()

	// Query for httpx scans
	httpxQuery := `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
		FROM httpx_scans 
		WHERE scope_target_id = $1
	`
	httpxRows, err := dbPool.Query(context.Background(), httpxQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch httpx scans: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer httpxRows.Close()

	// Query for GAU scans
	gauQuery := `
		SELECT id, scan_id, domain, status, result, error, stdout, stderr, command, execution_time, created_at 
		FROM gau_scans 
		WHERE scope_target_id = $1
	`
	gauRows, err := dbPool.Query(context.Background(), gauQuery, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to fetch GAU scans: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	defer gauRows.Close()

	var allScans []ScanSummary

	// Process Amass scans
	for amassRows.Next() {
		var scan AmassScanStatus
		err := amassRows.Scan(
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
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan Amass row: %v", err)
			continue
		}

		allScans = append(allScans, ScanSummary{
			ID:        scan.ID,
			ScanID:    scan.ScanID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			Result:    nullStringToString(scan.Result),
			Error:     nullStringToString(scan.Error),
			StdOut:    nullStringToString(scan.StdOut),
			StdErr:    nullStringToString(scan.StdErr),
			Command:   nullStringToString(scan.Command),
			ExecTime:  nullStringToString(scan.ExecTime),
			CreatedAt: scan.CreatedAt,
			ScanType:  "amass",
		})
	}

	// Process httpx scans
	for httpxRows.Next() {
		var scan HttpxScanStatus
		err := httpxRows.Scan(
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
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan httpx row: %v", err)
			continue
		}

		allScans = append(allScans, ScanSummary{
			ID:        scan.ID,
			ScanID:    scan.ScanID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			Result:    nullStringToString(scan.Result),
			Error:     nullStringToString(scan.Error),
			StdOut:    nullStringToString(scan.StdOut),
			StdErr:    nullStringToString(scan.StdErr),
			Command:   nullStringToString(scan.Command),
			ExecTime:  nullStringToString(scan.ExecTime),
			CreatedAt: scan.CreatedAt,
			ScanType:  "httpx",
		})
	}

	// Process GAU scans
	for gauRows.Next() {
		var scan GauScanStatus
		err := gauRows.Scan(
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
		)
		if err != nil {
			log.Printf("[ERROR] Failed to scan GAU row: %v", err)
			continue
		}

		allScans = append(allScans, ScanSummary{
			ID:        scan.ID,
			ScanID:    scan.ScanID,
			Domain:    scan.Domain,
			Status:    scan.Status,
			Result:    nullStringToString(scan.Result),
			Error:     nullStringToString(scan.Error),
			StdOut:    nullStringToString(scan.StdOut),
			StdErr:    nullStringToString(scan.StdErr),
			Command:   nullStringToString(scan.Command),
			ExecTime:  nullStringToString(scan.ExecTime),
			CreatedAt: scan.CreatedAt,
			ScanType:  "gau",
		})
	}

	// Sort all scans by creation date, newest first
	sort.Slice(allScans, func(i, j int) bool {
		return allScans[i].CreatedAt.After(allScans[j].CreatedAt)
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(allScans)
}
