package utils

// The engagement GOAL attached to a scope target.
//
// A goal is the one specific, PoC-backed objective the hunter is trying to reach on this target, and
// the finish line the never-give-up layer otherwise lacks. It is modelled as a red-team "flag": a
// human-readable objective plus a GIVEN/WHEN/THEN success_criteria that is binary and checkable
// against captured artifacts, not prose. The status column is a state machine the hunter may advance
// only as far as 'candidate'; 'verified' records the isolated adversarial verify turn, and 'met' is
// the operator's sign-off alone. The MCP tool, not this handler, is what enforces who may set which
// status: the server stores what it is told, so the gate against an AI self-declaring 'met' lives in
// the tool schema. is_active gates hunting (exactly one active goal per target, backed by a partial
// unique index), and ActivateGoal flips it atomically.
//
// This file is deliberately a near-clone of notesUtils.go, down to the fatal-scan and foreign-key
// handling, so a reader who knows one knows the other.

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

// TargetGoal is the wire shape. Timestamps are RFC3339 strings to match the rest of this API.
type TargetGoal struct {
	ID                string `json:"id"`
	ScopeTargetID     string `json:"scope_target_id"`
	Title             string `json:"title"`
	Description       string `json:"description"`
	VulnClass         string `json:"vuln_class"`
	AssetScope        string `json:"asset_scope"`
	SuccessCriteria   string `json:"success_criteria"`
	RequiresPoc       bool   `json:"requires_poc"`
	MinSeverity       string `json:"min_severity"`
	Status            string `json:"status"`
	IsActive          bool   `json:"is_active"`
	CandidateEvidence string `json:"candidate_evidence"`
	VerifierVerdict   string `json:"verifier_verdict"`
	VerifierNotes     string `json:"verifier_notes"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
}

// One column list for every query, so create, update, activate and list cannot drift into returning
// different field sets for the same object.
const goalColumns = `id::text, scope_target_id::text, title, description, vuln_class, asset_scope, ` +
	`success_criteria, requires_poc, min_severity, status, is_active, candidate_evidence, ` +
	`verifier_verdict, verifier_notes, created_at, updated_at`

type goalRowScanner interface {
	Scan(dest ...any) error
}

func scanGoal(row goalRowScanner) (TargetGoal, error) {
	var g TargetGoal
	var created, updated time.Time
	if err := row.Scan(&g.ID, &g.ScopeTargetID, &g.Title, &g.Description, &g.VulnClass, &g.AssetScope,
		&g.SuccessCriteria, &g.RequiresPoc, &g.MinSeverity, &g.Status, &g.IsActive, &g.CandidateEvidence,
		&g.VerifierVerdict, &g.VerifierNotes, &created, &updated); err != nil {
		return g, err
	}
	g.CreatedAt = created.Format(time.RFC3339)
	g.UpdatedAt = updated.Format(time.RFC3339)
	return g, nil
}

func writeGoalJSON(w http.ResponseWriter, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// GetGoals handles GET /goals/{scope_target_id}. Active goal first, then most recently edited.
func GetGoals(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "The scope target id in the URL is not a valid UUID.", http.StatusBadRequest)
		return
	}

	rows, err := dbPool.Query(context.Background(),
		`SELECT `+goalColumns+` FROM target_goals
		 WHERE scope_target_id = $1
		 ORDER BY is_active DESC, updated_at DESC, created_at DESC`, scopeTargetID)
	if err != nil {
		log.Printf("[GOALS] Failed to read goals for target %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to read goals", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Non-nil on purpose: a nil slice marshals to JSON null and forces every consumer to defend
	// against null before iterating.
	goals := make([]TargetGoal, 0)
	for rows.Next() {
		g, scanErr := scanGoal(rows)
		if scanErr != nil {
			// Fatal rather than skipped: a dropped goal row still returns 200 and would read as the
			// operator having deleted it, which here could mean hunting proceeds against a stale view.
			log.Printf("[GOALS] Failed to scan a goal row for target %s: %v", scopeTargetID, scanErr)
			http.Error(w, "Failed to read goals", http.StatusInternalServerError)
			return
		}
		goals = append(goals, g)
	}
	if err := rows.Err(); err != nil {
		log.Printf("[GOALS] Goal list for target %s ended early: %v", scopeTargetID, err)
		http.Error(w, "Failed to read goals", http.StatusInternalServerError)
		return
	}

	// active_goal is surfaced alongside the list so the gate and the guidance layer can read "is there
	// an active goal" without walking the array. Nil when none is active.
	var active *TargetGoal
	for i := range goals {
		if goals[i].IsActive {
			active = &goals[i]
			break
		}
	}
	writeGoalJSON(w, http.StatusOK, map[string]interface{}{"goals": goals, "active_goal": active})
}

// CreateGoal handles POST /goals. A new goal is always 'draft' and inactive; the operator activates
// it in a separate step, because activation is what flips the single-active flag.
func CreateGoal(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID   string `json:"scope_target_id"`
		Title           string `json:"title"`
		Description     string `json:"description"`
		VulnClass       string `json:"vuln_class"`
		AssetScope      string `json:"asset_scope"`
		SuccessCriteria string `json:"success_criteria"`
		RequiresPoc     *bool  `json:"requires_poc"`
		MinSeverity     string `json:"min_severity"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body. Expected JSON with at least scope_target_id and title.",
			http.StatusBadRequest)
		return
	}

	scopeTargetID := strings.TrimSpace(payload.ScopeTargetID)
	if scopeTargetID == "" {
		http.Error(w, "scope_target_id is required. A goal has to belong to a scope target.",
			http.StatusBadRequest)
		return
	}
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "scope_target_id is not a valid UUID.", http.StatusBadRequest)
		return
	}
	title := strings.TrimSpace(payload.Title)
	if title == "" {
		http.Error(w, "title is required and cannot be only whitespace.", http.StatusBadRequest)
		return
	}
	// A goal is PoC-required unless the operator explicitly says otherwise, because a goal is not met
	// by a mechanism being present, only by a demonstrated attacker gain.
	requiresPoc := true
	if payload.RequiresPoc != nil {
		requiresPoc = *payload.RequiresPoc
	}

	goal, err := scanGoal(dbPool.QueryRow(context.Background(),
		`INSERT INTO target_goals
		   (scope_target_id, title, description, vuln_class, asset_scope, success_criteria,
		    requires_poc, min_severity, status, is_active)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'draft', FALSE)
		 RETURNING `+goalColumns,
		scopeTargetID, title, payload.Description, payload.VulnClass, payload.AssetScope,
		payload.SuccessCriteria, requiresPoc, payload.MinSeverity))
	if err != nil {
		if strings.Contains(err.Error(), "target_goals_scope_target_id_fkey") {
			http.Error(w, "No scope target with that id exists.", http.StatusBadRequest)
			return
		}
		log.Printf("[GOALS] Failed to create goal for target %s: %v", scopeTargetID, err)
		http.Error(w, "Failed to create the goal", http.StatusInternalServerError)
		return
	}

	writeGoalJSON(w, http.StatusCreated, goal)
}

// UpdateGoal handles PUT /goals/{goal_id}. Partial by design: every field is COALESCE'd over the
// current value so a status-only or evidence-only write (the propose and verify transitions) cannot
// blank the columns it did not mention. updated_at is stamped on every edit, since it is a sort key.
//
// This route will store any status the DB CHECK allows, including 'met'. It does NOT itself decide who
// may set it: the MCP tool is where the hunter is barred from writing 'met'. Keeping the server
// permissive means the operator's own sign-off path and the tool's restricted path share one handler.
func UpdateGoal(w http.ResponseWriter, r *http.Request) {
	goalID := mux.Vars(r)["goal_id"]
	if _, err := uuid.Parse(goalID); err != nil {
		http.Error(w, "No such goal", http.StatusNotFound)
		return
	}

	var payload struct {
		Title             *string `json:"title"`
		Description       *string `json:"description"`
		VulnClass         *string `json:"vuln_class"`
		AssetScope        *string `json:"asset_scope"`
		SuccessCriteria   *string `json:"success_criteria"`
		RequiresPoc       *bool   `json:"requires_poc"`
		MinSeverity       *string `json:"min_severity"`
		Status            *string `json:"status"`
		CandidateEvidence *string `json:"candidate_evidence"`
		VerifierVerdict   *string `json:"verifier_verdict"`
		VerifierNotes     *string `json:"verifier_notes"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body.", http.StatusBadRequest)
		return
	}
	// A title explicitly set to whitespace would make the goal unfindable in a listing; reject it.
	// A nil title (omitted) is fine: it means "leave the title alone".
	if payload.Title != nil && strings.TrimSpace(*payload.Title) == "" {
		http.Error(w, "title cannot be set to only whitespace.", http.StatusBadRequest)
		return
	}

	goal, err := scanGoal(dbPool.QueryRow(context.Background(),
		`UPDATE target_goals SET
		   title              = COALESCE($2, title),
		   description        = COALESCE($3, description),
		   vuln_class         = COALESCE($4, vuln_class),
		   asset_scope        = COALESCE($5, asset_scope),
		   success_criteria   = COALESCE($6, success_criteria),
		   requires_poc       = COALESCE($7, requires_poc),
		   min_severity       = COALESCE($8, min_severity),
		   status             = COALESCE($9, status),
		   candidate_evidence = COALESCE($10, candidate_evidence),
		   verifier_verdict   = COALESCE($11, verifier_verdict),
		   verifier_notes     = COALESCE($12, verifier_notes),
		   updated_at         = NOW()
		 WHERE id = $1
		 RETURNING `+goalColumns,
		goalID, payload.Title, payload.Description, payload.VulnClass, payload.AssetScope,
		payload.SuccessCriteria, payload.RequiresPoc, payload.MinSeverity, payload.Status,
		payload.CandidateEvidence, payload.VerifierVerdict, payload.VerifierNotes))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "No such goal", http.StatusNotFound)
			return
		}
		// A status outside the CHECK set surfaces as a constraint violation; that is a caller mistake.
		if strings.Contains(err.Error(), "target_goals_status_check") {
			http.Error(w, "status must be one of draft, active, candidate, verified, met, rejected, "+
				"abandoned.", http.StatusBadRequest)
			return
		}
		log.Printf("[GOALS] Failed to update goal %s: %v", goalID, err)
		http.Error(w, "Failed to update the goal", http.StatusInternalServerError)
		return
	}

	writeGoalJSON(w, http.StatusOK, goal)
}

// DeleteGoal handles DELETE /goals/{goal_id}.
func DeleteGoal(w http.ResponseWriter, r *http.Request) {
	goalID := mux.Vars(r)["goal_id"]
	if _, err := uuid.Parse(goalID); err != nil {
		http.Error(w, "No such goal", http.StatusNotFound)
		return
	}

	tag, err := dbPool.Exec(context.Background(), `DELETE FROM target_goals WHERE id = $1`, goalID)
	if err != nil {
		log.Printf("[GOALS] Failed to delete goal %s: %v", goalID, err)
		http.Error(w, "Failed to delete the goal", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		http.Error(w, "No such goal", http.StatusNotFound)
		return
	}

	writeGoalJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ActivateGoal handles PATCH /goals/{goal_id}/activate. It makes this goal the single active one for
// its target in one statement, so two activations cannot race into two active goals (the partial
// unique index is the backstop). A 'draft' goal becomes 'active' on activation; any other status is
// left as it is, so re-activating a 'candidate' does not reset its progress.
func ActivateGoal(w http.ResponseWriter, r *http.Request) {
	goalID := mux.Vars(r)["goal_id"]
	if _, err := uuid.Parse(goalID); err != nil {
		http.Error(w, "No such goal", http.StatusNotFound)
		return
	}

	// The goal's target is needed to scope the flip. A missing row is a 404 here, before any write.
	var scopeTargetID string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id::text FROM target_goals WHERE id = $1`, goalID).Scan(&scopeTargetID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "No such goal", http.StatusNotFound)
			return
		}
		log.Printf("[GOALS] Failed to look up goal %s before activate: %v", goalID, err)
		http.Error(w, "Failed to activate the goal", http.StatusInternalServerError)
		return
	}

	// The SET expressions read the OLD row values in Postgres, so is_active below is the pre-update
	// flag: updated_at moves on the newly-activated goal and on whichever one was active before.
	if _, err := dbPool.Exec(context.Background(),
		`UPDATE target_goals SET
		   is_active  = (id = $1),
		   status     = CASE WHEN id = $1 AND status = 'draft' THEN 'active' ELSE status END,
		   updated_at = CASE WHEN id = $1 OR is_active THEN NOW() ELSE updated_at END
		 WHERE scope_target_id = $2`, goalID, scopeTargetID); err != nil {
		log.Printf("[GOALS] Failed to activate goal %s: %v", goalID, err)
		http.Error(w, "Failed to activate the goal", http.StatusInternalServerError)
		return
	}

	goal, err := scanGoal(dbPool.QueryRow(context.Background(),
		`SELECT `+goalColumns+` FROM target_goals WHERE id = $1`, goalID))
	if err != nil {
		log.Printf("[GOALS] Failed to read goal %s after activate: %v", goalID, err)
		http.Error(w, "Failed to activate the goal", http.StatusInternalServerError)
		return
	}

	writeGoalJSON(w, http.StatusOK, goal)
}
