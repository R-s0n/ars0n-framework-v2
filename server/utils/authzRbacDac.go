package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Role based and discretionary access control: the two authorization models an operator draws as a
// shape rather than as a list.
//
// RBAC is a grid. Roles down one axis, actions across the other, one verdict per cell. The third
// verdict is the whole reason this is worth modelling. 'cannot_do' is a role that simply was not
// given the action, and a product decision can hand it over tomorrow. 'forbidden_to_do' is a role
// that must never be able to perform it whatever else is true. Both render as the same greyed out
// button, so nothing in the application distinguishes them, and only 'forbidden_to_do' turning out
// to be reachable is a finding worth writing up. Recording which is which before testing starts is
// what turns "this worked" into "this worked and it never should have".
//
// DAC is a ladder. Access a holder can pass on, up to their own level. rank says how high a level
// sits and grant_ceiling_rank says how high a holder of it may grant. A Figma board is the
// canonical shape: the creator is an admin, an admin can invite as admin or as user, a user can
// only invite users. So admin is rank 2 ceiling 2 and user is rank 1 ceiling 1, and a user who
// manages to grant rank 2 is exactly the escalation this models.

// The three verdicts a matrix cell may hold. Checked in Go before anything is written rather than
// left to the column's CHECK constraint, so a typo comes back as a 400 naming the bad value instead
// of a 500 carrying a Postgres error string the operator has to decode.
var rbacMatrixValues = map[string]bool{
	"can_do":          true,
	"cannot_do":       true,
	"forbidden_to_do": true,
}

// What a cell means when nobody has ever touched it. See GetAuthzRBAC for why the server is the one
// that decides this.
const rbacUnsetCell = "cannot_do"

// authzRbacAxisEntry is one role or one action. The two are the same shape, so they share a loader
// and a set of handlers rather than two copies that drift apart in their ordering.
type authzRbacAxisEntry struct {
	id        string
	name      string
	desc      string
	sortOrder int
	createdAt *time.Time
}

func (e authzRbacAxisEntry) asMap(scopeTargetID string) map[string]interface{} {
	return map[string]interface{}{
		"id":              e.id,
		"scope_target_id": scopeTargetID,
		"name":            e.name,
		"description":     e.desc,
		"sort_order":      e.sortOrder,
		"created_at":      e.createdAt,
	}
}

// GetAuthzRBAC handles GET /authz/rbac/{scope_target_id}.
//
// The matrix comes back dense: every role crossed with every action, with cells nobody has ever set
// carrying rbacUnsetCell rather than being absent. A sparse matrix forces the client to invent the
// default for a missing cell, and the moment the client invents it the client and the server can
// disagree about what an untouched cell means. That disagreement is silent and it is exactly the
// kind of thing that makes an operator distrust the grid they are testing against.
//
// Ordering is row major and matches the roles and actions arrays returned alongside it, so cell
// (role i, action j) sits at index i*len(actions)+j. updated_at is null on a cell that was never
// written, which is the honest way to say "this is the default, not a decision somebody recorded".
func GetAuthzRBAC(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	roles, err := authzRbacAxis("authz_roles", scopeTargetID)
	if err != nil {
		log.Printf("[AUTHZ] Failed to load roles: %v", err)
		http.Error(w, "Failed to fetch roles", http.StatusInternalServerError)
		return
	}
	actions, err := authzRbacAxis("authz_actions", scopeTargetID)
	if err != nil {
		log.Printf("[AUTHZ] Failed to load actions: %v", err)
		http.Error(w, "Failed to fetch actions", http.StatusInternalServerError)
		return
	}

	type recordedCell struct {
		value     string
		notes     string
		updatedAt *time.Time
	}
	recorded := map[string]recordedCell{}

	// Joining through authz_roles scopes the cells without needing a second predicate: a cell's role
	// is what ties it to a scope target, and an action from a different target can never reach the
	// dense output below because it is not in the actions axis.
	rows, err := dbPool.Query(context.Background(), `
		SELECT m.role_id, m.action_id, m.value, COALESCE(m.notes, ''), m.updated_at
		FROM authz_role_action_matrix m
		JOIN authz_roles r ON r.id = m.role_id
		WHERE r.scope_target_id = $1`, scopeTargetID)
	if err != nil {
		log.Printf("[AUTHZ] Failed to load role/action matrix: %v", err)
		http.Error(w, "Failed to fetch matrix", http.StatusInternalServerError)
		return
	}
	for rows.Next() {
		var roleID, actionID, value, notes string
		var updatedAt *time.Time
		if err := rows.Scan(&roleID, &actionID, &value, &notes, &updatedAt); err != nil {
			log.Printf("[AUTHZ] Failed to scan matrix cell: %v", err)
			continue
		}
		recorded[roleID+"|"+actionID] = recordedCell{value: value, notes: notes, updatedAt: updatedAt}
	}
	rows.Close()

	roleMaps := make([]map[string]interface{}, 0, len(roles))
	for _, role := range roles {
		roleMaps = append(roleMaps, role.asMap(scopeTargetID))
	}
	actionMaps := make([]map[string]interface{}, 0, len(actions))
	for _, action := range actions {
		actionMaps = append(actionMaps, action.asMap(scopeTargetID))
	}

	matrix := make([]map[string]interface{}, 0, len(roles)*len(actions))
	for _, role := range roles {
		for _, action := range actions {
			cell := map[string]interface{}{
				"role_id":     role.id,
				"role_name":   role.name,
				"action_id":   action.id,
				"action_name": action.name,
				"value":       rbacUnsetCell,
				"notes":       "",
				"updated_at":  nil,
			}
			if c, ok := recorded[role.id+"|"+action.id]; ok {
				cell["value"] = c.value
				cell["notes"] = c.notes
				cell["updated_at"] = c.updatedAt
			}
			matrix = append(matrix, cell)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"roles":   roleMaps,
		"actions": actionMaps,
		"matrix":  matrix,
	})
}

// authzRbacAxis loads one axis of the grid. table is always one of two constants chosen at the call
// site and never anything that came out of a request, so interpolating it is safe.
func authzRbacAxis(table, scopeTargetID string) ([]authzRbacAxisEntry, error) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id, name, COALESCE(description, ''), COALESCE(sort_order, 0), created_at
		FROM `+table+`
		WHERE scope_target_id = $1
		ORDER BY sort_order ASC, name ASC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	entries := []authzRbacAxisEntry{}
	for rows.Next() {
		var e authzRbacAxisEntry
		if err := rows.Scan(&e.id, &e.name, &e.desc, &e.sortOrder, &e.createdAt); err != nil {
			log.Printf("[AUTHZ] Failed to scan %s row: %v", table, err)
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// CreateAuthzRole handles POST /authz/rbac/{scope_target_id}/roles.
func CreateAuthzRole(w http.ResponseWriter, r *http.Request) {
	authzRbacCreateAxisEntry(w, r, "authz_roles", "Role")
}

// CreateAuthzAction handles POST /authz/rbac/{scope_target_id}/actions.
func CreateAuthzAction(w http.ResponseWriter, r *http.Request) {
	authzRbacCreateAxisEntry(w, r, "authz_actions", "Action")
}

// label is capitalized because it opens the not-found message; the failure messages lower it.
func authzRbacCreateAxisEntry(w http.ResponseWriter, r *http.Request, table, label string) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   *int   `json:"sort_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	payload.Name = strings.TrimSpace(payload.Name)
	if payload.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	// An omitted sort_order puts the new entry at the end of its axis. Defaulting every row to zero
	// would silently reorder the grid by name on the next read, and the operator's ordering carries
	// meaning: roles are usually laid out least privileged first, so that the shape of the grid is
	// readable at a glance.
	id := uuid.New().String()
	var newID string
	var sortOrder int
	err := dbPool.QueryRow(context.Background(), `
		INSERT INTO `+table+` (id, scope_target_id, name, description, sort_order)
		VALUES ($1, $2, $3, $4,
		        COALESCE($5::int,
		                 (SELECT COALESCE(MAX(sort_order) + 1, 0) FROM `+table+`
		                   WHERE scope_target_id = $2)))
		RETURNING id, COALESCE(sort_order, 0)`,
		id, scopeTargetID, payload.Name, payload.Description, payload.SortOrder).Scan(&newID, &sortOrder)
	if err != nil {
		log.Printf("[AUTHZ] Failed to create %s: %v", strings.ToLower(label), err)
		http.Error(w, "Failed to create "+strings.ToLower(label), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"id": newID, "sort_order": sortOrder})
}

// UpdateAuthzRole handles PUT /authz/rbac/role/{id}.
func UpdateAuthzRole(w http.ResponseWriter, r *http.Request) {
	authzRbacUpdateAxisEntry(w, r, "authz_roles", "Role")
}

// UpdateAuthzAction handles PUT /authz/rbac/action/{id}.
func UpdateAuthzAction(w http.ResponseWriter, r *http.Request) {
	authzRbacUpdateAxisEntry(w, r, "authz_actions", "Action")
}

func authzRbacUpdateAxisEntry(w http.ResponseWriter, r *http.Request, table, label string) {
	id := mux.Vars(r)["id"]

	// Pointers, not values, so that renaming a role does not quietly reset its description to the
	// empty string just because the client sent only the field it changed.
	var payload struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if payload.Name != nil {
		trimmed := strings.TrimSpace(*payload.Name)
		if trimmed == "" {
			http.Error(w, "name cannot be empty", http.StatusBadRequest)
			return
		}
		payload.Name = &trimmed
	}

	result, err := dbPool.Exec(context.Background(), `
		UPDATE `+table+` SET
		  name = COALESCE($1, name),
		  description = COALESCE($2, description),
		  sort_order = COALESCE($3, sort_order)
		WHERE id = $4`,
		payload.Name, payload.Description, payload.SortOrder, id)
	if err != nil {
		log.Printf("[AUTHZ] Failed to update %s: %v", strings.ToLower(label), err)
		http.Error(w, "Failed to update "+strings.ToLower(label), http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, label+" not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"updated": result.RowsAffected()})
}

// DeleteAuthzRole handles DELETE /authz/rbac/role/{id}.
//
// The role's cells go with it through the FK cascade on authz_role_action_matrix. Deleting them
// here as well would be a second place that has to stay correct, and the database already knows a
// cell cannot outlive the role it belongs to.
func DeleteAuthzRole(w http.ResponseWriter, r *http.Request) {
	authzRbacDeleteAxisEntry(w, r, "authz_roles", "Role")
}

// DeleteAuthzAction handles DELETE /authz/rbac/action/{id}. Cells cascade, as with a role.
func DeleteAuthzAction(w http.ResponseWriter, r *http.Request) {
	authzRbacDeleteAxisEntry(w, r, "authz_actions", "Action")
}

func authzRbacDeleteAxisEntry(w http.ResponseWriter, r *http.Request, table, label string) {
	id := mux.Vars(r)["id"]

	result, err := dbPool.Exec(context.Background(), `DELETE FROM `+table+` WHERE id = $1`, id)
	if err != nil {
		log.Printf("[AUTHZ] Failed to delete %s: %v", strings.ToLower(label), err)
		http.Error(w, "Failed to delete "+strings.ToLower(label), http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, label+" not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": result.RowsAffected()})
}

// UpdateAuthzMatrix handles PUT /authz/rbac/{scope_target_id}/matrix.
//
// A bulk upsert on (role_id, action_id) inside one transaction. The client edits a grid and sends
// back the cells that changed, which can easily be a whole column at once, and a half applied grid
// is worse than a rejected one: the operator cannot tell by looking which half took, so they end up
// testing against a model that does not match anything they decided.
//
// Values are validated up front for the same reason. Finding the bad one on cell forty means thirty
// nine cells have already been written, and only the transaction saves them from sticking.
func UpdateAuthzMatrix(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Cells []struct {
			RoleID   string `json:"role_id"`
			ActionID string `json:"action_id"`
			Value    string `json:"value"`
			Notes    string `json:"notes"`
		} `json:"cells"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	for _, c := range payload.Cells {
		if c.RoleID == "" || c.ActionID == "" {
			http.Error(w, "each cell needs role_id and action_id", http.StatusBadRequest)
			return
		}
		if !rbacMatrixValues[c.Value] {
			http.Error(w, "value must be can_do, cannot_do or forbidden_to_do", http.StatusBadRequest)
			return
		}
	}
	if len(payload.Cells) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"updated": 0, "skipped": 0})
		return
	}

	ctx := context.Background()
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		log.Printf("[AUTHZ] Failed to begin matrix transaction: %v", err)
		http.Error(w, "Failed to save matrix", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	updated, skipped := 0, 0
	for _, c := range payload.Cells {
		// The cross join is the ownership check as much as it is the source of the ids. A cell
		// naming a role or an action that belongs to a different scope target selects no rows and
		// writes nothing, so one target's grid can never be edited through another target's URL.
		result, err := tx.Exec(ctx, `
			INSERT INTO authz_role_action_matrix (id, role_id, action_id, value, notes, updated_at)
			SELECT $1::uuid, r.id, a.id, $4::text, $5::text, NOW()
			FROM authz_roles r, authz_actions a
			WHERE r.id = $2::uuid AND a.id = $3::uuid
			  AND r.scope_target_id = $6::uuid AND a.scope_target_id = $6::uuid
			ON CONFLICT (role_id, action_id) DO UPDATE SET
			  value = EXCLUDED.value,
			  notes = EXCLUDED.notes,
			  updated_at = NOW()`,
			uuid.New().String(), c.RoleID, c.ActionID, c.Value, c.Notes, scopeTargetID)
		if err != nil {
			log.Printf("[AUTHZ] Matrix upsert failed for role %s action %s: %v", c.RoleID, c.ActionID, err)
			http.Error(w, "Failed to save matrix", http.StatusInternalServerError)
			return
		}
		if result.RowsAffected() == 0 {
			skipped++
			continue
		}
		updated++
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[AUTHZ] Failed to commit matrix transaction: %v", err)
		http.Error(w, "Failed to save matrix", http.StatusInternalServerError)
		return
	}

	// skipped is reported rather than swallowed, because a cell that wrote nothing means the client
	// is holding role or action ids that no longer belong to this target, and the operator should
	// see that instead of wondering why one square kept snapping back.
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"updated": updated, "skipped": skipped})
}

// authzDacLevel is one rung of the ladder, already resolved: ceiling holds the effective ceiling
// rather than the raw column, so nothing downstream has to reimplement the default.
type authzDacLevel struct {
	id        string
	objectID  string
	name      string
	desc      string
	rank      int
	ceiling   int
	canGrant  bool
	createdAt *time.Time
}

// GetAuthzDAC handles GET /authz/dac/{scope_target_id}.
//
// Every level carries a derived "grantable" list, the names of the levels a holder of it may hand
// out. The operator should not have to do that arithmetic in their head to see that user can create
// another user but not an admin, and that comparison is the entire point of writing the object down
// before testing it.
func GetAuthzDAC(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	rows, err := dbPool.Query(ctx, `
		SELECT id, name, COALESCE(description, ''), COALESCE(notes, ''), created_at, updated_at
		FROM authz_dac_objects
		WHERE scope_target_id = $1
		ORDER BY created_at ASC, name ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[AUTHZ] Failed to load DAC objects: %v", err)
		http.Error(w, "Failed to fetch DAC objects", http.StatusInternalServerError)
		return
	}

	type dacObject struct {
		id, name, desc, notes string
		createdAt, updatedAt  *time.Time
	}
	var objects []dacObject
	for rows.Next() {
		var o dacObject
		if err := rows.Scan(&o.id, &o.name, &o.desc, &o.notes, &o.createdAt, &o.updatedAt); err != nil {
			log.Printf("[AUTHZ] Failed to scan DAC object: %v", err)
			continue
		}
		objects = append(objects, o)
	}
	rows.Close()

	// Ordered by rank ascending, which is both the natural reading order for a ladder and the order
	// authzDacGrantable relies on to hand back a grantable list that is already sorted.
	levelRows, err := dbPool.Query(ctx, `
		SELECT l.id, l.object_id, l.name, COALESCE(l.description, ''), l.rank,
		       l.grant_ceiling_rank, COALESCE(l.can_grant, TRUE), l.created_at
		FROM authz_dac_levels l
		JOIN authz_dac_objects o ON o.id = l.object_id
		WHERE o.scope_target_id = $1
		ORDER BY l.rank ASC, l.name ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[AUTHZ] Failed to load DAC levels: %v", err)
		http.Error(w, "Failed to fetch DAC levels", http.StatusInternalServerError)
		return
	}
	levelsByObject := map[string][]authzDacLevel{}
	for levelRows.Next() {
		var l authzDacLevel
		var ceiling *int
		if err := levelRows.Scan(&l.id, &l.objectID, &l.name, &l.desc, &l.rank, &ceiling,
			&l.canGrant, &l.createdAt); err != nil {
			log.Printf("[AUTHZ] Failed to scan DAC level: %v", err)
			continue
		}
		// A level created through this API always has an explicit ceiling, so a null one only turns
		// up on a row written some other way. It resolves to the level's own rank, the same rule
		// CreateAuthzDACLevel applies, so the two paths cannot disagree about what a blank means.
		l.ceiling = l.rank
		if ceiling != nil {
			l.ceiling = *ceiling
		}
		levelsByObject[l.objectID] = append(levelsByObject[l.objectID], l)
	}
	levelRows.Close()

	out := []map[string]interface{}{}
	for _, o := range objects {
		siblings := levelsByObject[o.id]
		levels := make([]map[string]interface{}, 0, len(siblings))
		for _, l := range siblings {
			levels = append(levels, map[string]interface{}{
				"id":          l.id,
				"object_id":   l.objectID,
				"name":        l.name,
				"description": l.desc,
				"rank":        l.rank,
				// The effective ceiling, never the raw null. Handing the client a null would force it
				// to reimplement the default, which is the same trap a sparse RBAC matrix sets.
				"grant_ceiling_rank": l.ceiling,
				"can_grant":          l.canGrant,
				"created_at":         l.createdAt,
				"grantable":          authzDacGrantable(l, siblings),
			})
		}
		out = append(out, map[string]interface{}{
			"id":              o.id,
			"scope_target_id": scopeTargetID,
			"name":            o.name,
			"description":     o.desc,
			"notes":           o.notes,
			"created_at":      o.createdAt,
			"updated_at":      o.updatedAt,
			"levels":          levels,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

// authzDacGrantable is the arithmetic behind the Figma example: a level may hand out any level whose
// rank is at or below its ceiling. With the default ceiling of its own rank, admin(2,2) comes back
// with admin and user while user(1,1) comes back with user alone, and admin missing from the user
// row is the boundary the escalation test tries to cross.
//
// A ceiling deliberately set below the level's own rank drops the level from its own list, which is
// the "sits high but may only grant low" shape and is meant to read that way.
//
// siblings must already be sorted by rank ascending; the returned names inherit that order.
func authzDacGrantable(level authzDacLevel, siblings []authzDacLevel) []string {
	grantable := []string{}
	if !level.canGrant {
		return grantable
	}
	for _, s := range siblings {
		if s.rank <= level.ceiling {
			grantable = append(grantable, s.name)
		}
	}
	return grantable
}

// CreateAuthzDACObject handles POST /authz/dac/{scope_target_id}.
func CreateAuthzDACObject(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Notes       string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	payload.Name = strings.TrimSpace(payload.Name)
	if payload.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	var newID string
	err := dbPool.QueryRow(context.Background(), `
		INSERT INTO authz_dac_objects (id, scope_target_id, name, description, notes)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id`,
		uuid.New().String(), scopeTargetID, payload.Name, payload.Description, payload.Notes).Scan(&newID)
	if err != nil {
		log.Printf("[AUTHZ] Failed to create DAC object: %v", err)
		http.Error(w, "Failed to create DAC object", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{"id": newID})
}

// UpdateAuthzDACObject handles PUT /authz/dac/object/{id}.
func UpdateAuthzDACObject(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var payload struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
		Notes       *string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if payload.Name != nil {
		trimmed := strings.TrimSpace(*payload.Name)
		if trimmed == "" {
			http.Error(w, "name cannot be empty", http.StatusBadRequest)
			return
		}
		payload.Name = &trimmed
	}

	result, err := dbPool.Exec(context.Background(), `
		UPDATE authz_dac_objects SET
		  name = COALESCE($1, name),
		  description = COALESCE($2, description),
		  notes = COALESCE($3, notes),
		  updated_at = NOW()
		WHERE id = $4`,
		payload.Name, payload.Description, payload.Notes, id)
	if err != nil {
		log.Printf("[AUTHZ] Failed to update DAC object: %v", err)
		http.Error(w, "Failed to update DAC object", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "DAC object not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"updated": result.RowsAffected()})
}

// DeleteAuthzDACObject handles DELETE /authz/dac/object/{id}. Its levels cascade away with it.
func DeleteAuthzDACObject(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	result, err := dbPool.Exec(context.Background(), `DELETE FROM authz_dac_objects WHERE id = $1`, id)
	if err != nil {
		log.Printf("[AUTHZ] Failed to delete DAC object: %v", err)
		http.Error(w, "Failed to delete DAC object", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "DAC object not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": result.RowsAffected()})
}

// CreateAuthzDACLevel handles POST /authz/dac/object/{id}/levels.
//
// A level created without an explicit grant_ceiling_rank gets its own rank as the ceiling. That
// encodes the ordinary rule, which is that a holder may grant up to their own level and no higher,
// and it is the rule the Figma example describes. Storing it rather than leaving the column null
// means the ceiling is a value the operator can see and edit instead of an assumption living in
// whichever piece of code happens to read the row.
//
// Rank and ceiling are resolved in one statement so the ceiling tracks a derived rank: leaving both
// blank on a third level appends it above the other two and lets it grant all three, which is what
// an operator adding levels top down expects.
func CreateAuthzDACLevel(w http.ResponseWriter, r *http.Request) {
	objectID := mux.Vars(r)["id"]

	var payload struct {
		Name             string `json:"name"`
		Rank             *int   `json:"rank"`
		GrantCeilingRank *int   `json:"grant_ceiling_rank"`
		CanGrant         *bool  `json:"can_grant"`
		Description      string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	payload.Name = strings.TrimSpace(payload.Name)
	if payload.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	var newID string
	var rank, ceiling int
	err := dbPool.QueryRow(context.Background(), `
		INSERT INTO authz_dac_levels
		  (id, object_id, name, rank, grant_ceiling_rank, can_grant, description)
		SELECT $1::uuid, $2::uuid, $3::text, resolved.rank,
		       COALESCE($5::int, resolved.rank), COALESCE($6::bool, TRUE), $7::text
		FROM (SELECT COALESCE($4::int,
		                      (SELECT COALESCE(MAX(rank) + 1, 0) FROM authz_dac_levels
		                        WHERE object_id = $2::uuid)) AS rank) resolved
		RETURNING id, rank, grant_ceiling_rank`,
		uuid.New().String(), objectID, payload.Name, payload.Rank, payload.GrantCeilingRank,
		payload.CanGrant, payload.Description).Scan(&newID, &rank, &ceiling)
	if err != nil {
		if authzDacConflict(w, err) {
			return
		}
		log.Printf("[AUTHZ] Failed to create DAC level: %v", err)
		http.Error(w, "Failed to create level", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id": newID, "rank": rank, "grant_ceiling_rank": ceiling,
	})
}

// UpdateAuthzDACLevel handles PUT /authz/dac/level/{id}.
//
// Changing a rank deliberately leaves the stored ceiling where it is. By the time a level exists the
// ceiling is a value the operator either chose or accepted, and quietly dragging it along with the
// rank would overwrite a deliberate "this level sits high but may only grant low", which is one of
// the more interesting configurations to test.
func UpdateAuthzDACLevel(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var payload struct {
		Name             *string `json:"name"`
		Rank             *int    `json:"rank"`
		GrantCeilingRank *int    `json:"grant_ceiling_rank"`
		CanGrant         *bool   `json:"can_grant"`
		Description      *string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if payload.Name != nil {
		trimmed := strings.TrimSpace(*payload.Name)
		if trimmed == "" {
			http.Error(w, "name cannot be empty", http.StatusBadRequest)
			return
		}
		payload.Name = &trimmed
	}

	result, err := dbPool.Exec(context.Background(), `
		UPDATE authz_dac_levels SET
		  name = COALESCE($1, name),
		  rank = COALESCE($2, rank),
		  grant_ceiling_rank = COALESCE($3, grant_ceiling_rank),
		  can_grant = COALESCE($4, can_grant),
		  description = COALESCE($5, description)
		WHERE id = $6`,
		payload.Name, payload.Rank, payload.GrantCeilingRank, payload.CanGrant,
		payload.Description, id)
	if err != nil {
		if authzDacConflict(w, err) {
			return
		}
		log.Printf("[AUTHZ] Failed to update DAC level: %v", err)
		http.Error(w, "Failed to update level", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Level not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"updated": result.RowsAffected()})
}

// DeleteAuthzDACLevel handles DELETE /authz/dac/level/{id}.
func DeleteAuthzDACLevel(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	result, err := dbPool.Exec(context.Background(), `DELETE FROM authz_dac_levels WHERE id = $1`, id)
	if err != nil {
		log.Printf("[AUTHZ] Failed to delete DAC level: %v", err)
		http.Error(w, "Failed to delete level", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Level not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"deleted": result.RowsAffected()})
}

// authzDacConflict turns the two constraint failures an operator can actually cause into answers
// they can act on. A duplicate level name and a level pointed at an object that is gone are typing
// and staleness, not server faults, and a 500 tells the operator nothing about which one happened.
// Reports whether it wrote a response.
func authzDacConflict(w http.ResponseWriter, err error) bool {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "uq_authz_dac_level"):
		http.Error(w, "A level with that name already exists on this object", http.StatusConflict)
		return true
	case strings.Contains(msg, "violates foreign key constraint"):
		http.Error(w, "DAC object not found", http.StatusNotFound)
		return true
	}
	return false
}
