package utils

// The per-target ROLE BOARD. A cross-agent coordination layer over hunt roles: who holds which role
// on this scope target right now, so independent agents working the same target do not both drive the
// same role. The MCP manage_agent_roles assign is session-local and in-memory; this table is the
// shared, backend-backed view.
//
// ADVISORY ONLY. A claim never blocks a tool; the only hard gate is the operator GOAL_GATE. The one
// thing the database DOES enforce is that at most one agent actively holds a given role on a given
// target, via the partial unique index idx_role_assignments_one_active. A takeover (force) releases
// the current holder and inserts the new claim in one transaction so it cannot race into two holders.
//
// This file is a deliberate near-clone of targetGoalsUtils.go, down to the pgx usage and the
// constraint-name string matching, so a reader who knows one knows the other.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// An active claim older than this reads as STALE on the board. READ-TIME flag only: nothing sweeps,
// nothing expires the row, no lease. The holder simply looks idle until it touches the claim (any
// PATCH bumps updated_at). A const so the threshold lives in one place.
const roleStaleAfter = 20 * time.Minute

// RoleAssignment is the wire shape. Timestamps are RFC3339 strings to match the rest of this API.
// Stale is computed at read time (never stored) and is only ever true for an active row.
type RoleAssignment struct {
	ID            string `json:"id"`
	ScopeTargetID string `json:"scope_target_id"`
	RoleID        string `json:"role_id"`
	AgentLabel    string `json:"agent_label"`
	Status        string `json:"status"`
	HandoffToRole string `json:"handoff_to_role"`
	Note          string `json:"note"`
	ClaimedAt     string `json:"claimed_at"`
	UpdatedAt     string `json:"updated_at"`
	Stale         bool   `json:"stale"`
}

// One column list for every query so the board, claim and update cannot drift into returning
// different field sets. The trailing stale boolean is NOT in this list; each query supplies it (the
// board as a computed expression, insert/update as FALSE) so scanRole always has exactly 10 targets.
const roleColumns = `id::text, scope_target_id::text, role_id, agent_label, status, ` +
	`handoff_to_role, note, claimed_at, updated_at`

type roleRowScanner interface {
	Scan(dest ...any) error
}

// scanRole scans the roleColumns set PLUS one trailing boolean (stale). Every SELECT/RETURNING that
// feeds it MUST append a stale expression after roleColumns.
func scanRole(row roleRowScanner) (RoleAssignment, error) {
	var ra RoleAssignment
	var claimed, updated time.Time
	if err := row.Scan(&ra.ID, &ra.ScopeTargetID, &ra.RoleID, &ra.AgentLabel, &ra.Status,
		&ra.HandoffToRole, &ra.Note, &claimed, &updated, &ra.Stale); err != nil {
		return ra, err
	}
	ra.ClaimedAt = claimed.Format(time.RFC3339)
	ra.UpdatedAt = updated.Format(time.RFC3339)
	return ra, nil
}

func writeRoleJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// roleActiveHolder reads the current active holder of (target, role) for a conflict message. Best
// effort: a missing row leaves label empty. Runs on its own pooled connection, so it is safe to call
// after an aborted claim transaction.
func roleActiveHolder(scopeTargetID, roleID string) (label string, stale bool) {
	cutoff := time.Now().Add(-roleStaleAfter)
	_ = dbPool.QueryRow(context.Background(),
		`SELECT agent_label, (updated_at < $3)
		   FROM role_assignments
		  WHERE scope_target_id = $1 AND role_id = $2 AND status = 'active'
		  LIMIT 1`, scopeTargetID, roleID, cutoff).Scan(&label, &stale)
	return label, stale
}

// GetRoleBoard handles GET /roles/{scope_target_id}. Active claims first, then most recently touched.
// Each active row is flagged stale when updated_at is older than roleStaleAfter (read-time only).
func GetRoleBoard(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "The scope target id in the URL is not a valid UUID.", http.StatusBadRequest)
		return
	}

	cutoff := time.Now().Add(-roleStaleAfter)
	rows, err := dbPool.Query(context.Background(),
		`SELECT `+roleColumns+`, (status = 'active' AND updated_at < $2) AS stale
		   FROM role_assignments
		  WHERE scope_target_id = $1
		  ORDER BY (status = 'active') DESC, updated_at DESC, claimed_at DESC`, scopeTargetID, cutoff)
	if err != nil {
		log.Printf("[ROLES] Failed to read role board for target %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to read the role board", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Non-nil on purpose: a nil slice marshals to JSON null and forces every consumer to defend.
	assignments := make([]RoleAssignment, 0)
	for rows.Next() {
		ra, scanErr := scanRole(rows)
		if scanErr != nil {
			log.Printf("[ROLES] Failed to scan a role row for target %s: %v", scopeTargetID, scanErr)
			http.Error(w, "Failed to read the role board", http.StatusInternalServerError)
			return
		}
		assignments = append(assignments, ra)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[ROLES] Role board for target %s ended early: %v", scopeTargetID, err)
		http.Error(w, "Failed to read the role board", http.StatusInternalServerError)
		return
	}

	writeRoleJSON(w, http.StatusOK, map[string]interface{}{"roles": assignments})
}

// ClaimRole handles POST /roles. Body {scope_target_id, role_id, agent_label, force}. Inserts an
// active claim. If the role is already actively held, the partial unique index rejects the insert and
// we return 409 {error:"role already held", held_by, stale} UNLESS force=true, in which case the
// existing active claim is released and the new one inserted IN ONE TRANSACTION (atomic takeover).
func ClaimRole(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID string `json:"scope_target_id"`
		RoleID        string `json:"role_id"`
		AgentLabel    string `json:"agent_label"`
		Force         bool   `json:"force"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body. Expected JSON with scope_target_id, role_id, agent_label.",
			http.StatusBadRequest)
		return
	}

	scopeTargetID := strings.TrimSpace(payload.ScopeTargetID)
	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required.", http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "scope_target_id is not a valid UUID.", http.StatusBadRequest)
		return
	}
	roleID := strings.TrimSpace(payload.RoleID)
	if roleID == "" {
		http.Error(w, "role_id is required.", http.StatusBadRequest)
		return
	}
	agentLabel := strings.TrimSpace(payload.AgentLabel)
	if agentLabel == "" {
		http.Error(w, "agent_label is required. It is the stable identity of the claiming agent.",
			http.StatusBadRequest)
		return
	}

	ctx := context.Background()
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		log.Printf("[ROLES] Failed to begin claim tx for target %s role %s: %v", scopeTargetID, roleID, err)
		http.Error(w, "Failed to claim the role", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	// Force takeover: release whoever actively holds this role on this target, in the same tx, so the
	// slot is free when we insert. A no-op when nobody holds it.
	if payload.Force {
		if _, err := tx.Exec(ctx,
			`UPDATE role_assignments SET status = 'released', updated_at = NOW()
			  WHERE scope_target_id = $1 AND role_id = $2 AND status = 'active'`,
			scopeTargetID, roleID); err != nil {
			log.Printf("[ROLES] Failed to release prior holder for target %s role %s: %v", scopeTargetID, roleID, err)
			http.Error(w, "Failed to claim the role", http.StatusInternalServerError)
			return
		}
	}

	ra, err := scanRole(tx.QueryRow(ctx,
		`INSERT INTO role_assignments (scope_target_id, role_id, agent_label)
		 VALUES ($1, $2, $3)
		 RETURNING `+roleColumns+`, FALSE AS stale`,
		scopeTargetID, roleID, agentLabel))
	if err != nil {
		if strings.Contains(err.Error(), "role_assignments_scope_target_id_fkey") {
			http.Error(w, "No scope target with that id exists.", http.StatusBadRequest)
			return
		}
		if strings.Contains(err.Error(), "idx_role_assignments_one_active") {
			// Already actively held and force was not set. Roll back the aborted tx, then read the
			// holder on a fresh connection for the conflict message.
			tx.Rollback(ctx)
			heldBy, stale := roleActiveHolder(scopeTargetID, roleID)
			writeRoleJSON(w, http.StatusConflict, map[string]interface{}{
				"error":   "role already held",
				"held_by": heldBy,
				"stale":   stale,
			})
			return
		}
		log.Printf("[ROLES] Failed to insert claim for target %s role %s: %v", scopeTargetID, roleID, err)
		http.Error(w, "Failed to claim the role", http.StatusInternalServerError)
		return
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[ROLES] Failed to commit claim for target %s role %s: %v", scopeTargetID, roleID, err)
		http.Error(w, "Failed to claim the role", http.StatusInternalServerError)
		return
	}

	writeRoleJSON(w, http.StatusCreated, ra)
}

// UpdateRoleAssignment handles PATCH /roles/{id}. Partial: status and/or handoff_to_role/note are
// COALESCE'd over the current value, and updated_at is always bumped (this is also the heartbeat
// touch that clears a stale flag). Cloned from UpdateGoal.
func UpdateRoleAssignment(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "No such role assignment", http.StatusNotFound)
		return
	}

	var payload struct {
		Status        *string `json:"status"`
		HandoffToRole *string `json:"handoff_to_role"`
		Note          *string `json:"note"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body.", http.StatusBadRequest)
		return
	}

	ra, err := scanRole(dbPool.QueryRow(context.Background(),
		`UPDATE role_assignments SET
		   status          = COALESCE($2, status),
		   handoff_to_role = COALESCE($3, handoff_to_role),
		   note            = COALESCE($4, note),
		   updated_at      = NOW()
		 WHERE id = $1
		 RETURNING `+roleColumns+`, FALSE AS stale`,
		id, payload.Status, payload.HandoffToRole, payload.Note))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "No such role assignment", http.StatusNotFound)
			return
		}
		if strings.Contains(err.Error(), "role_assignments_status_check") {
			http.Error(w, "status must be one of active, handed_off, done, released.", http.StatusBadRequest)
			return
		}
		log.Printf("[ROLES] Failed to update role assignment %s: %v", id, err)
		http.Error(w, "Failed to update the role assignment", http.StatusInternalServerError)
		return
	}

	writeRoleJSON(w, http.StatusOK, ra)
}

// ReleaseRoleAssignment handles DELETE /roles/{id}. Mirrors DeleteGoal exactly: a hard delete, 404 on
// a missing row, {"status":"deleted"} on success. Deleting the row frees the partial-unique slot so
// the role can be re-claimed. (A soft release via PATCH status='released' is also available to the
// MCP layer; the DELETE route itself is the faithful goals clone and hard-deletes.)
func ReleaseRoleAssignment(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		http.Error(w, "No such role assignment", http.StatusNotFound)
		return
	}

	tag, err := dbPool.Exec(context.Background(), `DELETE FROM role_assignments WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ROLES] Failed to delete role assignment %s: %v", id, err)
		http.Error(w, "Failed to delete the role assignment", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		http.Error(w, "No such role assignment", http.StatusNotFound)
		return
	}

	writeRoleJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
