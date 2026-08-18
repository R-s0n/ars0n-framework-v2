package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Two of the four ways an application decides whether a caller may do a thing: Client Identity
// Patterns and Policy Based access control. The operator models what the application claims it
// does here, so that testing later has something concrete to contradict. A record on its own is
// not a finding, the finding is the application disagreeing with the record.
//
// Client Identity Patterns describe how the server works out who is asking, evidenced by one real
// request and its response. The category is the most important field because it ranks how much of
// the identity the attacker actually controls, and that ranking drives the ordering of the list.
//
// Policy Based describes an application where an administrator grants or withholds each action
// individually: an entity, every permission it has, and the specific instances of that entity with
// their specific configurations.

// validAuthzIdentityCategories mirrors the DB CHECK constraint on authz_identity_patterns.category.
var validAuthzIdentityCategories = map[string]bool{
	"user_context_object": true,
	"signed_token":        true,
	"parameter":           true,
}

// validAuthzIdentifierLocations mirrors the CHECK on identifier_location. The empty string is a
// member on purpose: the operator can record the pattern before working out where the identifier
// actually sits, and that half-finished state must be storable.
var validAuthzIdentifierLocations = map[string]bool{
	"":            true,
	"query":       true,
	"path":        true,
	"body":        true,
	"header":      true,
	"cookie":      true,
	"token_claim": true,
	"server_side": true,
}

// validAuthzPolicyValues mirrors the CHECK on authz_policy_instance_settings.value. 'unset' is not
// a synonym for 'deny': a permission that was never granted and one that was explicitly revoked can
// take different code paths in the application, and telling them apart is the point of the model.
var validAuthzPolicyValues = map[string]bool{
	"allow": true,
	"deny":  true,
	"unset": true,
}

// AuthzIdentityPattern is one demonstrated way the server identifies a caller.
type AuthzIdentityPattern struct {
	ID                 string              `json:"id"`
	ScopeTargetID      string              `json:"scope_target_id"`
	Name               string              `json:"name"`
	Category           string              `json:"category"`
	Description        string              `json:"description"`
	RawRequest         string              `json:"raw_request"`
	ResponseStatus     *int                `json:"response_status"`
	ResponseHeaders    map[string][]string `json:"response_headers"`
	ResponseBody       string              `json:"response_body"`
	ResponseTimeMs     *float64            `json:"response_time_ms"`
	IdentifierLocation string              `json:"identifier_location"`
	IdentifierName     string              `json:"identifier_name"`
	IdentifierValue    string              `json:"identifier_value"`
	Notes              string              `json:"notes"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
	// ReplayError carries a transport failure back to the operator. The table has no column for it
	// because a pattern is a record of the application, not of one replay attempt.
	ReplayError string `json:"replay_error,omitempty"`
}

// AuthzPolicyPermission is one action an entity can be configured to allow or withhold.
type AuthzPolicyPermission struct {
	ID          string    `json:"id"`
	EntityID    string    `json:"entity_id"`
	Key         string    `json:"key"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SortOrder   int       `json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuthzPolicyInstanceSetting is one permission's verdict for one instance. UpdatedAt is a pointer
// because a resolved 'unset' may have no row behind it, and a null timestamp is how the caller can
// tell a default apart from a decision the operator actually made.
type AuthzPolicyInstanceSetting struct {
	PermissionID  string     `json:"permission_id"`
	PermissionKey string     `json:"permission_key"`
	Value         string     `json:"value"`
	Notes         string     `json:"notes"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

// AuthzPolicyInstance is one real configuration of an entity, for example a specific API key.
type AuthzPolicyInstance struct {
	ID          string                       `json:"id"`
	EntityID    string                       `json:"entity_id"`
	Name        string                       `json:"name"`
	Subject     string                       `json:"subject"`
	Description string                       `json:"description"`
	Notes       string                       `json:"notes"`
	CreatedAt   time.Time                    `json:"created_at"`
	UpdatedAt   time.Time                    `json:"updated_at"`
	Settings    []AuthzPolicyInstanceSetting `json:"settings"`
}

// AuthzPolicyEntity is the thing permissions are granted on, with its permissions and instances.
type AuthzPolicyEntity struct {
	ID            string                  `json:"id"`
	ScopeTargetID string                  `json:"scope_target_id"`
	Name          string                  `json:"name"`
	Description   string                  `json:"description"`
	Notes         string                  `json:"notes"`
	CreatedAt     time.Time               `json:"created_at"`
	UpdatedAt     time.Time               `json:"updated_at"`
	Permissions   []AuthzPolicyPermission `json:"permissions"`
	Instances     []AuthzPolicyInstance   `json:"instances"`
}

// authzSettingKey addresses one cell of the instance-by-permission grid.
type authzSettingKey struct {
	instanceID   string
	permissionID string
}

func writeAuthzJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(payload)
}

// ---------------------------------------------------------------------------
// Client Identity Patterns
// ---------------------------------------------------------------------------

const authzIdentityPatternCols = `id, scope_target_id, name, category, COALESCE(description,''),
	COALESCE(raw_request,''), response_status, response_headers, COALESCE(response_body,''),
	response_time_ms, COALESCE(identifier_location,''), COALESCE(identifier_name,''),
	COALESCE(identifier_value,''), COALESCE(notes,''), created_at, updated_at`

// authzIdentityCategoryRank orders the list by how useful each category is for IDOR testing rather
// than by name. A parameter the attacker can edit outright is the best target, a signed token needs
// the signature broken first, and a server-built user context object gives the attacker nothing.
// Sorting by name would bury the only rows worth attacking under whatever the operator called them.
const authzIdentityCategoryRank = `CASE category
	WHEN 'parameter' THEN 0
	WHEN 'signed_token' THEN 1
	ELSE 2 END`

func scanAuthzIdentityPattern(row interface{ Scan(...interface{}) error }) (AuthzIdentityPattern, error) {
	var p AuthzIdentityPattern
	var headersJSON []byte
	if err := row.Scan(&p.ID, &p.ScopeTargetID, &p.Name, &p.Category, &p.Description, &p.RawRequest,
		&p.ResponseStatus, &headersJSON, &p.ResponseBody, &p.ResponseTimeMs, &p.IdentifierLocation,
		&p.IdentifierName, &p.IdentifierValue, &p.Notes, &p.CreatedAt, &p.UpdatedAt); err != nil {
		return p, err
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &p.ResponseHeaders)
	}
	return p, nil
}

func getAuthzIdentityPatternByID(id string) (AuthzIdentityPattern, error) {
	row := dbPool.QueryRow(context.Background(),
		`SELECT `+authzIdentityPatternCols+` FROM authz_identity_patterns WHERE id = $1`, id)
	return scanAuthzIdentityPattern(row)
}

func GetAuthzIdentityPatterns(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(context.Background(),
		`SELECT `+authzIdentityPatternCols+` FROM authz_identity_patterns
		 WHERE scope_target_id = $1
		 ORDER BY `+authzIdentityCategoryRank+` ASC, created_at ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get authz identity patterns: %v", err)
		http.Error(w, "Failed to fetch identity patterns", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	patterns := []AuthzIdentityPattern{}
	for rows.Next() {
		p, err := scanAuthzIdentityPattern(rows)
		if err != nil {
			log.Printf("[ERROR] Failed to scan authz identity pattern: %v", err)
			continue
		}
		patterns = append(patterns, p)
	}

	writeAuthzJSON(w, http.StatusOK, patterns)
}

func CreateAuthzIdentityPattern(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Name               string              `json:"name"`
		Category           string              `json:"category"`
		Description        string              `json:"description"`
		RawRequest         string              `json:"raw_request"`
		ResponseStatus     *int                `json:"response_status"`
		ResponseHeaders    map[string][]string `json:"response_headers"`
		ResponseBody       string              `json:"response_body"`
		ResponseTimeMs     *float64            `json:"response_time_ms"`
		IdentifierLocation string              `json:"identifier_location"`
		IdentifierName     string              `json:"identifier_name"`
		IdentifierValue    string              `json:"identifier_value"`
		Notes              string              `json:"notes"`
		// Replay sends the pasted request straight away so the record starts out with a real
		// response instead of an empty one.
		Replay bool `json:"replay"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	if !validAuthzIdentityCategories[payload.Category] {
		http.Error(w, "Invalid category (must be parameter, signed_token, or user_context_object)", http.StatusBadRequest)
		return
	}
	if !validAuthzIdentifierLocations[payload.IdentifierLocation] {
		http.Error(w, "Invalid identifier_location", http.StatusBadRequest)
		return
	}

	if payload.ResponseHeaders == nil {
		payload.ResponseHeaders = map[string][]string{}
	}
	headersJSON, _ := json.Marshal(payload.ResponseHeaders)

	id := uuid.New().String()
	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO authz_identity_patterns (id, scope_target_id, name, category, description,
		   raw_request, response_status, response_headers, response_body, response_time_ms,
		   identifier_location, identifier_name, identifier_value, notes)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
		id, scopeTargetID, payload.Name, payload.Category, payload.Description,
		sanitizeForPostgres(payload.RawRequest), payload.ResponseStatus, headersJSON,
		sanitizeForPostgres(payload.ResponseBody), payload.ResponseTimeMs,
		payload.IdentifierLocation, payload.IdentifierName, payload.IdentifierValue, payload.Notes)
	if err != nil {
		log.Printf("[ERROR] Failed to create authz identity pattern: %v", err)
		http.Error(w, "Failed to create identity pattern", http.StatusInternalServerError)
		return
	}

	if payload.Replay && strings.TrimSpace(payload.RawRequest) != "" {
		if _, rErr := replayAuthzIdentityPattern(id); rErr != nil {
			// A failed replay is not a failed create. The pattern exists and the operator can
			// fix the request and replay it again from the record.
			log.Printf("[INFO] Identity pattern %s created but initial replay failed: %v", id, rErr)
		}
	}

	writeAuthzJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

func UpdateAuthzIdentityPattern(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	// Pointers throughout so the client can send only the fields it touched. That matters most for
	// identifier_location, where the empty string is a real value and cannot mean "leave alone".
	var payload struct {
		Name               *string `json:"name"`
		Category           *string `json:"category"`
		Description        *string `json:"description"`
		RawRequest         *string `json:"raw_request"`
		IdentifierLocation *string `json:"identifier_location"`
		IdentifierName     *string `json:"identifier_name"`
		IdentifierValue    *string `json:"identifier_value"`
		Notes              *string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if payload.Category != nil && !validAuthzIdentityCategories[*payload.Category] {
		http.Error(w, "Invalid category", http.StatusBadRequest)
		return
	}
	if payload.IdentifierLocation != nil && !validAuthzIdentifierLocations[*payload.IdentifierLocation] {
		http.Error(w, "Invalid identifier_location", http.StatusBadRequest)
		return
	}
	if payload.RawRequest != nil {
		clean := sanitizeForPostgres(*payload.RawRequest)
		payload.RawRequest = &clean
	}

	result, err := dbPool.Exec(context.Background(),
		`UPDATE authz_identity_patterns SET
		   name = COALESCE($1, name),
		   category = COALESCE($2, category),
		   description = COALESCE($3, description),
		   raw_request = COALESCE($4, raw_request),
		   identifier_location = COALESCE($5, identifier_location),
		   identifier_name = COALESCE($6, identifier_name),
		   identifier_value = COALESCE($7, identifier_value),
		   notes = COALESCE($8, notes),
		   updated_at = NOW()
		 WHERE id = $9`,
		payload.Name, payload.Category, payload.Description, payload.RawRequest,
		payload.IdentifierLocation, payload.IdentifierName, payload.IdentifierValue,
		payload.Notes, id)
	if err != nil {
		log.Printf("[ERROR] Failed to update authz identity pattern: %v", err)
		http.Error(w, "Failed to update identity pattern", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Identity pattern not found", http.StatusNotFound)
		return
	}

	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"updated": true})
}

func DeleteAuthzIdentityPattern(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM authz_identity_patterns WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to delete authz identity pattern: %v", err)
		http.Error(w, "Failed to delete identity pattern", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Identity pattern not found", http.StatusNotFound)
		return
	}
	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"deleted": true})
}

// ReplayAuthzIdentityPattern re-sends the pattern's recorded request and stores what came back.
func ReplayAuthzIdentityPattern(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	replayErr, err := replayAuthzIdentityPattern(id)
	if err != nil {
		log.Printf("[ERROR] Failed to replay identity pattern %s: %v", id, err)
		http.Error(w, "Failed to replay identity pattern", http.StatusInternalServerError)
		return
	}

	pattern, err := getAuthzIdentityPatternByID(id)
	if err != nil {
		http.Error(w, "Identity pattern not found", http.StatusNotFound)
		return
	}
	pattern.ReplayError = replayErr

	writeAuthzJSON(w, http.StatusOK, pattern)
}

// replayAuthzIdentityPattern sends the stored raw request and writes the observed response back
// onto the row, so the evidence attached to the pattern is what the application does now rather
// than what it did when the operator first pasted the request in.
//
// The send itself is sendRawRequest from authFlowsUtils.go, the same engine the auth flow steps
// use. A second implementation would drift: the redirect handling, the TLS behaviour and the body
// cap are decisions that have to be identical for a replayed request to mean anything next to a
// replayed flow step.
//
// The returned string is a transport failure, which is not an error of this function: a target
// that refuses the connection is a fact about the target and the row is still updated to say the
// pattern currently produces no response. The error return is reserved for the row being missing
// or the write failing.
func replayAuthzIdentityPattern(id string) (string, error) {
	var rawRequest string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT COALESCE(raw_request,'') FROM authz_identity_patterns WHERE id = $1`, id).Scan(&rawRequest); err != nil {
		return "", err
	}
	if strings.TrimSpace(rawRequest) == "" {
		return "no raw request recorded for this pattern", nil
	}

	// A pattern has no base_url of its own, unlike an auth flow, so the target comes from the
	// pasted request's own Host header.
	baseURL := resolveBaseURL(rawRequest, "")

	// A fresh jar per replay. A pattern is a single self-contained request and must carry only the
	// cookies the operator pasted into it, otherwise a leftover session would answer the question
	// the replay is asking.
	jar, _ := cookiejar.New(nil)
	status, headers, body, ms, sendErr := sendRawRequest(rawRequest, baseURL, jar)

	replayErr := ""
	if sendErr != nil {
		replayErr = sendErr.Error()
	}

	headersJSON, _ := json.Marshal(headers)
	if headers == nil {
		headersJSON = []byte("{}")
	}
	var statusVal interface{}
	if status > 0 {
		statusVal = status
	}

	// Response bodies are arbitrary bytes: an image or a gzip stream would abort the UPDATE with
	// an invalid UTF8 sequence and lose the whole replay, so the body is scrubbed before it goes in.
	_, err := dbPool.Exec(context.Background(),
		`UPDATE authz_identity_patterns SET response_status = $1, response_headers = $2,
		   response_body = $3, response_time_ms = $4, updated_at = NOW() WHERE id = $5`,
		statusVal, headersJSON, sanitizeForPostgres(body), ms, id)
	if err != nil {
		return replayErr, err
	}
	return replayErr, nil
}

// ---------------------------------------------------------------------------
// Policy Based
// ---------------------------------------------------------------------------

// GetAuthzPolicy returns every entity for the scope target with its permissions and instances
// nested, and every instance's settings resolved against the entity's full permission list.
//
// Resolution matters: the table only holds cells the operator has touched, so a permission that has
// never been set for an instance has no row at all. Returning that as an absent key would make the
// client invent the default itself, and the two clients (UI grid and MCP) would eventually invent
// different ones. A missing row and an explicit 'unset' therefore look identical from here.
func GetAuthzPolicy(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	entityRows, err := dbPool.Query(ctx,
		`SELECT id, scope_target_id, name, COALESCE(description,''), COALESCE(notes,''),
		        created_at, updated_at
		 FROM authz_policy_entities WHERE scope_target_id = $1 ORDER BY created_at ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get authz policy entities: %v", err)
		http.Error(w, "Failed to fetch policy entities", http.StatusInternalServerError)
		return
	}

	entities := []*AuthzPolicyEntity{}
	byEntity := map[string]*AuthzPolicyEntity{}
	for entityRows.Next() {
		e := &AuthzPolicyEntity{
			Permissions: []AuthzPolicyPermission{},
			Instances:   []AuthzPolicyInstance{},
		}
		if err := entityRows.Scan(&e.ID, &e.ScopeTargetID, &e.Name, &e.Description, &e.Notes,
			&e.CreatedAt, &e.UpdatedAt); err != nil {
			log.Printf("[ERROR] Failed to scan authz policy entity: %v", err)
			continue
		}
		entities = append(entities, e)
		byEntity[e.ID] = e
	}
	entityRows.Close()

	if len(entities) == 0 {
		writeAuthzJSON(w, http.StatusOK, []*AuthzPolicyEntity{})
		return
	}

	// Permissions, in the order the operator arranged them. sort_order is the grid's column order.
	permRows, err := dbPool.Query(ctx,
		`SELECT p.id, p.entity_id, p.key, COALESCE(p.name,''), COALESCE(p.description,''),
		        COALESCE(p.sort_order,0), p.created_at
		 FROM authz_policy_permissions p
		 JOIN authz_policy_entities e ON e.id = p.entity_id
		 WHERE e.scope_target_id = $1
		 ORDER BY p.sort_order ASC, p.created_at ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get authz policy permissions: %v", err)
		http.Error(w, "Failed to fetch policy permissions", http.StatusInternalServerError)
		return
	}
	permKeys := map[string]string{}
	for permRows.Next() {
		var p AuthzPolicyPermission
		if err := permRows.Scan(&p.ID, &p.EntityID, &p.Key, &p.Name, &p.Description,
			&p.SortOrder, &p.CreatedAt); err != nil {
			log.Printf("[ERROR] Failed to scan authz policy permission: %v", err)
			continue
		}
		permKeys[p.ID] = p.Key
		if e, ok := byEntity[p.EntityID]; ok {
			e.Permissions = append(e.Permissions, p)
		}
	}
	permRows.Close()

	// Settings are read before the instances are assembled, because resolving an instance needs the
	// whole grid in hand.
	setRows, err := dbPool.Query(ctx,
		`SELECT s.instance_id, s.permission_id, s.value, COALESCE(s.notes,''), s.updated_at
		 FROM authz_policy_instance_settings s
		 JOIN authz_policy_instances i ON i.id = s.instance_id
		 JOIN authz_policy_entities e ON e.id = i.entity_id
		 WHERE e.scope_target_id = $1`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get authz policy settings: %v", err)
		http.Error(w, "Failed to fetch policy settings", http.StatusInternalServerError)
		return
	}
	stored := map[authzSettingKey]AuthzPolicyInstanceSetting{}
	for setRows.Next() {
		var instanceID string
		var s AuthzPolicyInstanceSetting
		var updatedAt time.Time
		if err := setRows.Scan(&instanceID, &s.PermissionID, &s.Value, &s.Notes, &updatedAt); err != nil {
			log.Printf("[ERROR] Failed to scan authz policy setting: %v", err)
			continue
		}
		s.UpdatedAt = &updatedAt
		stored[authzSettingKey{instanceID: instanceID, permissionID: s.PermissionID}] = s
	}
	setRows.Close()

	instRows, err := dbPool.Query(ctx,
		`SELECT i.id, i.entity_id, i.name, COALESCE(i.subject,''), COALESCE(i.description,''),
		        COALESCE(i.notes,''), i.created_at, i.updated_at
		 FROM authz_policy_instances i
		 JOIN authz_policy_entities e ON e.id = i.entity_id
		 WHERE e.scope_target_id = $1
		 ORDER BY i.created_at ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get authz policy instances: %v", err)
		http.Error(w, "Failed to fetch policy instances", http.StatusInternalServerError)
		return
	}
	for instRows.Next() {
		var inst AuthzPolicyInstance
		if err := instRows.Scan(&inst.ID, &inst.EntityID, &inst.Name, &inst.Subject,
			&inst.Description, &inst.Notes, &inst.CreatedAt, &inst.UpdatedAt); err != nil {
			log.Printf("[ERROR] Failed to scan authz policy instance: %v", err)
			continue
		}
		e, ok := byEntity[inst.EntityID]
		if !ok {
			continue
		}
		inst.Settings = make([]AuthzPolicyInstanceSetting, 0, len(e.Permissions))
		for _, perm := range e.Permissions {
			if s, found := stored[authzSettingKey{instanceID: inst.ID, permissionID: perm.ID}]; found {
				s.PermissionKey = permKeys[perm.ID]
				inst.Settings = append(inst.Settings, s)
				continue
			}
			inst.Settings = append(inst.Settings, AuthzPolicyInstanceSetting{
				PermissionID:  perm.ID,
				PermissionKey: perm.Key,
				Value:         "unset",
			})
		}
		e.Instances = append(e.Instances, inst)
	}
	instRows.Close()

	writeAuthzJSON(w, http.StatusOK, entities)
}

func CreateAuthzPolicyEntity(w http.ResponseWriter, r *http.Request) {
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
	if strings.TrimSpace(payload.Name) == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(),
		`INSERT INTO authz_policy_entities (id, scope_target_id, name, description, notes)
		 VALUES ($1,$2,$3,$4,$5)`,
		id, scopeTargetID, payload.Name, payload.Description, payload.Notes); err != nil {
		log.Printf("[ERROR] Failed to create authz policy entity: %v", err)
		http.Error(w, "Failed to create policy entity", http.StatusInternalServerError)
		return
	}

	writeAuthzJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

func UpdateAuthzPolicyEntity(w http.ResponseWriter, r *http.Request) {
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

	result, err := dbPool.Exec(context.Background(),
		`UPDATE authz_policy_entities SET
		   name = COALESCE($1, name),
		   description = COALESCE($2, description),
		   notes = COALESCE($3, notes),
		   updated_at = NOW()
		 WHERE id = $4`,
		payload.Name, payload.Description, payload.Notes, id)
	if err != nil {
		log.Printf("[ERROR] Failed to update authz policy entity: %v", err)
		http.Error(w, "Failed to update policy entity", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Policy entity not found", http.StatusNotFound)
		return
	}

	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"updated": true})
}

// DeleteAuthzPolicyEntity removes the entity and, through the ON DELETE CASCADE on
// authz_policy_permissions and authz_policy_instances, everything modelled underneath it.
func DeleteAuthzPolicyEntity(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM authz_policy_entities WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to delete authz policy entity: %v", err)
		http.Error(w, "Failed to delete policy entity", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Policy entity not found", http.StatusNotFound)
		return
	}
	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"deleted": true})
}

func CreateAuthzPolicyPermission(w http.ResponseWriter, r *http.Request) {
	entityID := mux.Vars(r)["id"]

	var payload struct {
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
		SortOrder   *int   `json:"sort_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	payload.Key = strings.TrimSpace(payload.Key)
	if payload.Key == "" {
		http.Error(w, "key is required", http.StatusBadRequest)
		return
	}

	// A new permission goes on the end of the grid unless the client placed it, so enumerating
	// permissions one after another keeps the order they were typed in.
	sortOrder := 0
	if payload.SortOrder != nil {
		sortOrder = *payload.SortOrder
	} else if err := dbPool.QueryRow(context.Background(),
		`SELECT COALESCE(MAX(sort_order),0)+1 FROM authz_policy_permissions WHERE entity_id = $1`,
		entityID).Scan(&sortOrder); err != nil {
		log.Printf("[ERROR] Failed to compute permission sort order: %v", err)
		http.Error(w, "Failed to add permission", http.StatusInternalServerError)
		return
	}

	id := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(),
		`INSERT INTO authz_policy_permissions (id, entity_id, key, name, description, sort_order)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, entityID, payload.Key, payload.Name, payload.Description, sortOrder); err != nil {
		log.Printf("[ERROR] Failed to create authz policy permission: %v", err)
		http.Error(w, "Failed to add permission (key must be unique for the entity)", http.StatusBadRequest)
		return
	}

	writeAuthzJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

func UpdateAuthzPolicyPermission(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var payload struct {
		Key         *string `json:"key"`
		Name        *string `json:"name"`
		Description *string `json:"description"`
		SortOrder   *int    `json:"sort_order"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	result, err := dbPool.Exec(context.Background(),
		`UPDATE authz_policy_permissions SET
		   key = COALESCE($1, key),
		   name = COALESCE($2, name),
		   description = COALESCE($3, description),
		   sort_order = COALESCE($4, sort_order)
		 WHERE id = $5`,
		payload.Key, payload.Name, payload.Description, payload.SortOrder, id)
	if err != nil {
		log.Printf("[ERROR] Failed to update authz policy permission: %v", err)
		http.Error(w, "Failed to update permission", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Permission not found", http.StatusNotFound)
		return
	}

	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"updated": true})
}

// DeleteAuthzPolicyPermission drops a column out of the grid. The settings that referenced it go
// with it: authz_policy_instance_settings.permission_id is declared ON DELETE CASCADE, so no
// orphaned cell survives to be resolved against a permission that no longer exists. Deleting the
// settings here by hand as well would be a second, silently divergent copy of that rule.
func DeleteAuthzPolicyPermission(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM authz_policy_permissions WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to delete authz policy permission: %v", err)
		http.Error(w, "Failed to delete permission", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Permission not found", http.StatusNotFound)
		return
	}
	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"deleted": true})
}

func CreateAuthzPolicyInstance(w http.ResponseWriter, r *http.Request) {
	entityID := mux.Vars(r)["id"]

	var payload struct {
		Name        string `json:"name"`
		Subject     string `json:"subject"`
		Description string `json:"description"`
		Notes       string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(),
		`INSERT INTO authz_policy_instances (id, entity_id, name, subject, description, notes)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		id, entityID, payload.Name, payload.Subject, payload.Description, payload.Notes); err != nil {
		log.Printf("[ERROR] Failed to create authz policy instance: %v", err)
		http.Error(w, "Failed to add instance", http.StatusInternalServerError)
		return
	}

	// No settings rows are written. Every permission resolves to 'unset' until the operator says
	// otherwise, which is exactly what a brand new instance means.
	writeAuthzJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

func UpdateAuthzPolicyInstance(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]

	var payload struct {
		Name        *string `json:"name"`
		Subject     *string `json:"subject"`
		Description *string `json:"description"`
		Notes       *string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	result, err := dbPool.Exec(context.Background(),
		`UPDATE authz_policy_instances SET
		   name = COALESCE($1, name),
		   subject = COALESCE($2, subject),
		   description = COALESCE($3, description),
		   notes = COALESCE($4, notes),
		   updated_at = NOW()
		 WHERE id = $5`,
		payload.Name, payload.Subject, payload.Description, payload.Notes, id)
	if err != nil {
		log.Printf("[ERROR] Failed to update authz policy instance: %v", err)
		http.Error(w, "Failed to update instance", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Instance not found", http.StatusNotFound)
		return
	}

	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"updated": true})
}

// DeleteAuthzPolicyInstance removes the instance, and its settings follow through the same
// ON DELETE CASCADE that protects the permission column.
func DeleteAuthzPolicyInstance(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	result, err := dbPool.Exec(context.Background(),
		`DELETE FROM authz_policy_instances WHERE id = $1`, id)
	if err != nil {
		log.Printf("[ERROR] Failed to delete authz policy instance: %v", err)
		http.Error(w, "Failed to delete instance", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Instance not found", http.StatusNotFound)
		return
	}
	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"deleted": true})
}

// SetAuthzPolicyInstanceSettings writes a batch of grid cells for one instance.
//
// Upsert on (instance_id, permission_id), because the client sends whichever cells the operator
// changed without knowing or caring whether a row already exists behind them. Setting a cell back
// to 'unset' still writes a row: that is a deliberate statement about the instance, and the notes
// explaining it have to live somewhere.
func SetAuthzPolicyInstanceSettings(w http.ResponseWriter, r *http.Request) {
	instanceID := mux.Vars(r)["id"]
	ctx := context.Background()

	var payload struct {
		Settings []struct {
			PermissionID string `json:"permission_id"`
			Value        string `json:"value"`
			Notes        string `json:"notes"`
		} `json:"settings"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	for _, s := range payload.Settings {
		if !validAuthzPolicyValues[s.Value] {
			http.Error(w, "Invalid value (must be allow, deny, or unset)", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(s.PermissionID) == "" {
			http.Error(w, "permission_id is required for every setting", http.StatusBadRequest)
			return
		}
	}

	// One transaction for the whole batch. A grid half written is a configuration the application
	// never had, and testing against it would be testing against something invented here.
	tx, err := dbPool.Begin(ctx)
	if err != nil {
		log.Printf("[ERROR] Failed to begin authz settings transaction: %v", err)
		http.Error(w, "Failed to save settings", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(ctx)

	applied := 0
	for _, s := range payload.Settings {
		// The join is the guard: it only inserts when the permission belongs to the same entity as
		// the instance. A cross-entity permission_id would otherwise create a row that GET never
		// resolves, so it would sit in the table forever, invisible and wrong.
		tag, err := tx.Exec(ctx,
			`INSERT INTO authz_policy_instance_settings (id, instance_id, permission_id, value, notes, updated_at)
			 SELECT $1, i.id, p.id, $4, $5, NOW()
			 FROM authz_policy_instances i
			 JOIN authz_policy_permissions p ON p.entity_id = i.entity_id
			 WHERE i.id = $2 AND p.id = $3
			 ON CONFLICT (instance_id, permission_id)
			 DO UPDATE SET value = EXCLUDED.value, notes = EXCLUDED.notes, updated_at = NOW()`,
			uuid.New().String(), instanceID, s.PermissionID, s.Value, s.Notes)
		if err != nil {
			log.Printf("[ERROR] Failed to upsert authz policy setting: %v", err)
			http.Error(w, "Failed to save settings", http.StatusInternalServerError)
			return
		}
		applied += int(tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		log.Printf("[ERROR] Failed to commit authz policy settings: %v", err)
		http.Error(w, "Failed to save settings", http.StatusInternalServerError)
		return
	}

	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{"updated": true, "applied": applied})
}

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

// GetAuthzSummary counts all four authorization models for the card on the Authorization view.
//
// One round trip with eight subselects rather than eight queries, because the card is rendered on
// every visit to the target and the numbers only have to agree with each other, not be assembled
// separately. forbidden_cells is called out on its own because it is the number the operator cares
// about: every one of those cells is something the application claims must never be possible, and
// each is a test that produces a finding the moment it succeeds.
func GetAuthzSummary(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var totalPatterns, catParameter, catSignedToken, catUserContext int
	var policyEntities, policyPermissions, policyInstances int
	var rbacRoles, rbacActions, rbacForbidden int
	var dacObjects, dacLevels int

	err := dbPool.QueryRow(context.Background(),
		`SELECT
		   (SELECT COUNT(*) FROM authz_identity_patterns WHERE scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_identity_patterns WHERE scope_target_id = $1 AND category = 'parameter'),
		   (SELECT COUNT(*) FROM authz_identity_patterns WHERE scope_target_id = $1 AND category = 'signed_token'),
		   (SELECT COUNT(*) FROM authz_identity_patterns WHERE scope_target_id = $1 AND category = 'user_context_object'),
		   (SELECT COUNT(*) FROM authz_policy_entities WHERE scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_policy_permissions p
		      JOIN authz_policy_entities e ON e.id = p.entity_id WHERE e.scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_policy_instances i
		      JOIN authz_policy_entities e ON e.id = i.entity_id WHERE e.scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_roles WHERE scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_actions WHERE scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_role_action_matrix m
		      JOIN authz_roles ro ON ro.id = m.role_id
		      WHERE ro.scope_target_id = $1 AND m.value = 'forbidden_to_do'),
		   (SELECT COUNT(*) FROM authz_dac_objects WHERE scope_target_id = $1),
		   (SELECT COUNT(*) FROM authz_dac_levels l
		      JOIN authz_dac_objects o ON o.id = l.object_id WHERE o.scope_target_id = $1)`,
		scopeTargetID).Scan(&totalPatterns, &catParameter, &catSignedToken, &catUserContext,
		&policyEntities, &policyPermissions, &policyInstances,
		&rbacRoles, &rbacActions, &rbacForbidden, &dacObjects, &dacLevels)
	if err != nil {
		log.Printf("[ERROR] Failed to get authz summary: %v", err)
		http.Error(w, "Failed to fetch authorization summary", http.StatusInternalServerError)
		return
	}

	writeAuthzJSON(w, http.StatusOK, map[string]interface{}{
		"identity_patterns": map[string]interface{}{
			"total":               totalPatterns,
			"parameter":           catParameter,
			"signed_token":        catSignedToken,
			"user_context_object": catUserContext,
		},
		"policy": map[string]interface{}{
			"entities":    policyEntities,
			"permissions": policyPermissions,
			"instances":   policyInstances,
		},
		"rbac": map[string]interface{}{
			"roles":           rbacRoles,
			"actions":         rbacActions,
			"forbidden_cells": rbacForbidden,
		},
		"dac": map[string]interface{}{
			"objects": dacObjects,
			"levels":  dacLevels,
		},
	})
}
