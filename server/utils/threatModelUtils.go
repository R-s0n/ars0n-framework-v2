package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// The three states a threat model entry can be in. A threat is untested until it has actually been run
// against the target; validated means the attack worked; rejected means it did not. Only these three
// values are accepted, and the same set is enforced by a CHECK constraint on the column.
const (
	ThreatTestStatusUntested  = "untested"
	ThreatTestStatusValidated = "validated"
	ThreatTestStatusRejected  = "rejected"
)

// ThreatSeverities is the closed set the UI colour-codes on. Free text here would make the header
// badge unstyleable and the list unsortable, which is the whole point of having the field.
var ThreatSeverities = []string{"critical", "high", "moderate", "low", "informational"}

func IsValidThreatSeverity(v string) bool {
	for _, s := range ThreatSeverities {
		if s == v {
			return true
		}
	}
	return false
}

func IsValidThreatTestStatus(s string) bool {
	switch s {
	case ThreatTestStatusUntested, ThreatTestStatusValidated, ThreatTestStatusRejected:
		return true
	}
	return false
}

func GetThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	query := `SELECT id, category, url, mechanism, target_object, steps, security_controls,
	          impact_customer_data, impact_attacker_scope, impact_company_reputation,
	          one_sentence, summary, severity, authenticated, attack_id, attack_custom_name,
	          test_status, created_at, updated_at
	          FROM threat_model
	          WHERE scope_target_id = $1
	          ORDER BY category, created_at`

	rows, err := dbPool.Query(context.Background(), query, scopeTargetID)
	if err != nil {
		log.Printf("[ERROR] Failed to get threat model: %v", err)
		http.Error(w, "Failed to fetch threats", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var threats = []map[string]interface{}{}
	for rows.Next() {
		var threat struct {
			ID                      string    `json:"id"`
			Category                string    `json:"category"`
			URL                     string    `json:"url"`
			Mechanism               string    `json:"mechanism"`
			TargetObject            string    `json:"target_object"`
			Steps                   string    `json:"steps"`
			SecurityControls        string    `json:"security_controls"`
			ImpactCustomerData      string    `json:"impact_customer_data"`
			ImpactAttackerScope     string    `json:"impact_attacker_scope"`
			ImpactCompanyReputation string    `json:"impact_company_reputation"`
			OneSentence             string    `json:"one_sentence"`
			Summary                 string    `json:"summary"`
			Severity                string    `json:"severity"`
			Authenticated           *bool     `json:"authenticated"`
			AttackID                string    `json:"attack_id"`
			AttackCustomName        string    `json:"attack_custom_name"`
			TestStatus              string    `json:"test_status"`
			CreatedAt               time.Time `json:"created_at"`
			UpdatedAt               time.Time `json:"updated_at"`
		}

		err := rows.Scan(&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism,
			&threat.TargetObject, &threat.Steps, &threat.SecurityControls, &threat.ImpactCustomerData,
			&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation,
			&threat.OneSentence, &threat.Summary, &threat.Severity, &threat.Authenticated, &threat.AttackID, &threat.AttackCustomName,
			&threat.TestStatus, &threat.CreatedAt, &threat.UpdatedAt)
		if err != nil {
			log.Printf("[ERROR] Failed to scan row: %v", err)
			continue
		}

		threats = append(threats, map[string]interface{}{
			"id":                        threat.ID,
			"category":                  threat.Category,
			"url":                       threat.URL,
			"mechanism":                 threat.Mechanism,
			"target_object":             threat.TargetObject,
			"steps":                     threat.Steps,
			"security_controls":         threat.SecurityControls,
			"impact_customer_data":      threat.ImpactCustomerData,
			"one_sentence":              threat.OneSentence,
			"summary":                   threat.Summary,
			"severity":                  threat.Severity,
			"authenticated":             threat.Authenticated,
			"attack_id":                 threat.AttackID,
			"attack_custom_name":        threat.AttackCustomName,
			"attack_name":               resolveAttackName(threat.AttackID, threat.AttackCustomName),
			"impact_attacker_scope":     threat.ImpactAttackerScope,
			"impact_company_reputation": threat.ImpactCompanyReputation,
			"test_status":               threat.TestStatus,
			"created_at":                threat.CreatedAt,
			"updated_at":                threat.UpdatedAt,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threats)
}

// decodeAuthenticated splits the raw authenticated field into "did the caller mention it at all"
// and "what did they say". A supplied null means undecided, which is a different statement from
// staying silent: the first resets the stored value, the second leaves it alone.
// NOTE the value type. A *json.RawMessage does not work here: encoding/json sets a pointer field
// to nil when the JSON value is null, so "authenticated": null and an absent key both arrive as nil
// and the reset case is unreachable. A plain json.RawMessage implements Unmarshaler, which the
// decoder calls even for null, so the literal bytes survive and the two stay distinguishable.

// attackCategoryError explains the refusal in terms the caller can act on: which attack, which
// category, and what would have been allowed instead.

func derefOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}

// resolveAttackName is what the UI title and every API consumer read. A catalogue citation resolves
// through the generated names so a rename propagates; an ad hoc name is its own label.
func resolveAttackName(attackID, custom string) string {
	if name, ok := AttackNames[attackID]; ok {
		return name
	}
	return custom
}

// resolveAttackChoice enforces that a threat names exactly one attack, either a catalogue entry
// appropriate to its STRIDE category or an ad hoc name. Returning the normalised pair (rather than
// validating in place) is what guarantees the two columns can never both be set: the caller writes
// what comes back here, not what arrived on the request.
func resolveAttackChoice(attackID, custom, category string) (string, string, error) {
	attackID = strings.TrimSpace(attackID)
	custom = strings.TrimSpace(custom)

	switch {
	case attackID != "" && custom != "":
		return "", "", fmt.Errorf("give either attack_id or attack_custom_name, not both")
	case attackID == "" && custom == "":
		return "", "", fmt.Errorf("every threat must name an attack: pass attack_id to cite one from the Possible Attacks list, or attack_custom_name for an ad hoc name")
	case attackID != "":
		if !IsValidAttackForCategory(attackID, category) {
			return "", "", fmt.Errorf("%s", attackCategoryError(attackID, category))
		}
		return attackID, "", nil
	default:
		if len([]rune(custom)) > 120 {
			return "", "", fmt.Errorf("attack_custom_name is too long (max 120 characters)")
		}
		return "", custom, nil
	}
}

func attackCategoryError(attackID, category string) string {
	if _, known := AttackNames[attackID]; !known {
		return fmt.Sprintf("attack_id %q is not a known attack", attackID)
	}
	allowed := make([]string, 0, len(AttackCategories))
	for id, cats := range AttackCategories {
		for _, c := range cats {
			if c == category {
				allowed = append(allowed, id)
				break
			}
		}
	}
	sort.Strings(allowed)
	return fmt.Sprintf("attack_id %q is not weaponized to achieve %s; valid choices for that category: %s",
		attackID, category, strings.Join(allowed, ", "))
}

func decodeAuthenticated(raw json.RawMessage) (supplied bool, value *bool, err error) {
	if len(raw) == 0 {
		return false, nil, nil
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, nil, fmt.Errorf("authenticated must be true, false or null")
	}
	return true, value, nil
}

func CreateThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]

	var payload struct {
		Category                string  `json:"category"`
		URL                     string  `json:"url"`
		Mechanism               *string `json:"mechanism"`
		TargetObject            *string `json:"target_object"`
		Steps                   *string `json:"steps"`
		SecurityControls        *string `json:"security_controls"`
		ImpactCustomerData      *string `json:"impact_customer_data"`
		ImpactAttackerScope     *string `json:"impact_attacker_scope"`
		ImpactCompanyReputation *string `json:"impact_company_reputation"`
		// Pointers, so the handler can tell "field not supplied" (nil, preserve what is stored)
		// from "field supplied as empty" (clear it). With plain strings the two are the same value
		// and every partial update silently blanked whatever it did not restate.
		OneSentence      *string `json:"one_sentence"`
		Summary          *string `json:"summary"`
		Severity         *string `json:"severity"`
		AttackID         *string `json:"attack_id"`
		AttackCustomName *string `json:"attack_custom_name"`
		// Raw, because a *bool cannot tell "key absent" (preserve) from "key present as null"
		// (reset to undecided) -- both decode to nil. The UI needs the second one to move a threat
		// back to undecided, so the two have to stay distinguishable this far in.
		Authenticated json.RawMessage `json:"authenticated"`
		TestStatus    string          `json:"test_status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Category == "" || payload.URL == "" {
		http.Error(w, "Category and URL are required", http.StatusBadRequest)
		return
	}

	// A threat is untested until somebody has actually run it. Callers that do not care about the
	// field simply omit it, which is the overwhelmingly common case.
	if payload.TestStatus == "" {
		payload.TestStatus = ThreatTestStatusUntested
	}
	if !IsValidThreatTestStatus(payload.TestStatus) {
		http.Error(w, "test_status must be one of untested, validated, rejected", http.StatusBadRequest)
		return
	}

	if payload.Severity != nil && !IsValidThreatSeverity(*payload.Severity) {
		http.Error(w, "severity must be one of critical, high, moderate, low, informational, or empty", http.StatusBadRequest)
		return
	}

	_, authValue, authErr := decodeAuthenticated(payload.Authenticated)
	if authErr != nil {
		http.Error(w, authErr.Error(), http.StatusBadRequest)
		return
	}

	attackID, attackCustom, attackErr := resolveAttackChoice(
		derefOr(payload.AttackID, ""), derefOr(payload.AttackCustomName, ""), payload.Category)
	if attackErr != nil {
		http.Error(w, attackErr.Error(), http.StatusBadRequest)
		return
	}

	threatID := uuid.New().String()
	query := `INSERT INTO threat_model (id, scope_target_id, category, url, mechanism,
	          target_object, steps, security_controls, impact_customer_data, impact_attacker_scope,
	          impact_company_reputation, one_sentence, summary, severity, authenticated, attack_id, attack_custom_name, test_status)
	          VALUES ($1, $2, $3, $4,
		          COALESCE($5, ''), COALESCE($6, ''), COALESCE($7, ''), COALESCE($8, ''),
		          COALESCE($9, ''), COALESCE($10, ''), COALESCE($11, ''),
		          COALESCE($12, ''), COALESCE($13, ''), COALESCE($14, ''), $15, $16, $17, $18)
	          RETURNING id, category, url, mechanism, target_object, steps, security_controls,
	          impact_customer_data, impact_attacker_scope, impact_company_reputation,
	          one_sentence, summary, severity, authenticated, attack_id, attack_custom_name,
	          test_status, created_at, updated_at`

	var threat struct {
		ID                      string `json:"id"`
		Category                string `json:"category"`
		URL                     string `json:"url"`
		Mechanism               string `json:"mechanism"`
		TargetObject            string `json:"target_object"`
		Steps                   string `json:"steps"`
		SecurityControls        string `json:"security_controls"`
		ImpactCustomerData      string `json:"impact_customer_data"`
		ImpactAttackerScope     string `json:"impact_attacker_scope"`
		ImpactCompanyReputation string `json:"impact_company_reputation"`
		OneSentence             string `json:"one_sentence"`
		Summary                 string `json:"summary"`
		Severity                string `json:"severity"`
		Authenticated           *bool  `json:"authenticated"`
		AttackID                string `json:"attack_id"`
		AttackCustomName        string `json:"attack_custom_name"`
		// Resolved from the generated catalog rather than stored, so renaming an attack in
		// attacks.js updates every threat that cites it instead of leaving stale copies behind.
		AttackName string    `json:"attack_name"`
		TestStatus string    `json:"test_status"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, threatID, scopeTargetID,
		payload.Category, payload.URL, payload.Mechanism, payload.TargetObject,
		payload.Steps, payload.SecurityControls, payload.ImpactCustomerData, payload.ImpactAttackerScope,
		payload.ImpactCompanyReputation, payload.OneSentence, payload.Summary,
		payload.Severity, authValue, attackID, attackCustom, payload.TestStatus).Scan(
		&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism,
		&threat.TargetObject, &threat.Steps, &threat.SecurityControls, &threat.ImpactCustomerData,
		&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation,
		&threat.OneSentence, &threat.Summary, &threat.Severity, &threat.Authenticated, &threat.AttackID, &threat.AttackCustomName,
		&threat.TestStatus, &threat.CreatedAt, &threat.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to create threat: %v", err)
		http.Error(w, "Failed to create threat", http.StatusInternalServerError)
		return
	}

	threat.AttackName = resolveAttackName(threat.AttackID, threat.AttackCustomName)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(threat)
}

func UpdateThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	threatID := vars["threat_id"]

	var payload struct {
		Category                string  `json:"category"`
		URL                     string  `json:"url"`
		Mechanism               *string `json:"mechanism"`
		TargetObject            *string `json:"target_object"`
		Steps                   *string `json:"steps"`
		SecurityControls        *string `json:"security_controls"`
		ImpactCustomerData      *string `json:"impact_customer_data"`
		ImpactAttackerScope     *string `json:"impact_attacker_scope"`
		ImpactCompanyReputation *string `json:"impact_company_reputation"`
		// Pointers, so the handler can tell "field not supplied" (nil, preserve what is stored)
		// from "field supplied as empty" (clear it). With plain strings the two are the same value
		// and every partial update silently blanked whatever it did not restate.
		OneSentence      *string `json:"one_sentence"`
		Summary          *string `json:"summary"`
		Severity         *string `json:"severity"`
		AttackID         *string `json:"attack_id"`
		AttackCustomName *string `json:"attack_custom_name"`
		// Raw, because a *bool cannot tell "key absent" (preserve) from "key present as null"
		// (reset to undecided) -- both decode to nil. The UI needs the second one to move a threat
		// back to undecided, so the two have to stay distinguishable this far in.
		Authenticated json.RawMessage `json:"authenticated"`
		TestStatus    string          `json:"test_status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if payload.Category == "" || payload.URL == "" {
		http.Error(w, "Category and URL are required", http.StatusBadRequest)
		return
	}

	if payload.TestStatus != "" && !IsValidThreatTestStatus(payload.TestStatus) {
		http.Error(w, "test_status must be one of untested, validated, rejected", http.StatusBadRequest)
		return
	}

	if payload.Severity != nil && !IsValidThreatSeverity(*payload.Severity) {
		http.Error(w, "severity must be one of critical, high, moderate, low, informational, or empty", http.StatusBadRequest)
		return
	}

	authSupplied, authValue, authErr := decodeAuthenticated(payload.Authenticated)
	if authErr != nil {
		http.Error(w, authErr.Error(), http.StatusBadRequest)
		return
	}

	// The pairing has to hold against the category being written, not the one that was stored, or
	// moving a threat between STRIDE sections would silently leave it citing an attack that does not
	// apply there. Whichever half the caller omits falls back to what is stored, and the merged pair
	// is what gets validated and written.
	var storedID, storedCustom string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT attack_id, attack_custom_name FROM threat_model WHERE id = $1`, threatID,
	).Scan(&storedID, &storedCustom); err != nil {
		log.Printf("[ERROR] Failed to read attack choice for threat %s: %v", threatID, err)
		http.Error(w, "Threat not found", http.StatusNotFound)
		return
	}
	attackID, attackCustom, attackErr := resolveAttackChoice(
		derefOr(payload.AttackID, storedID), derefOr(payload.AttackCustomName, storedCustom), payload.Category)
	if attackErr != nil {
		http.Error(w, attackErr.Error(), http.StatusBadRequest)
		return
	}

	// This handler replaces every other column, so an omitted test_status has to be PRESERVED rather
	// than blanked. Callers that edit a threat's prose have no reason to know its test status, and
	// silently resetting a validated threat to untested would lose the only record that it was run.
	query := `UPDATE threat_model
	          -- EVERY optional column is preserve-on-omit. This handler replaces the whole row, so a
	          -- caller that supplies only the fields it cares about must not blank the rest. Learned
	          -- the hard way: a batch that sent category, url and one flag erased mechanism,
	          -- target_object, steps, security_controls and all three impacts on 58 records.
	          SET category = $1, url = $2,
	          mechanism = COALESCE($3, mechanism),
	          target_object = COALESCE($4, target_object),
	          steps = COALESCE($5, steps),
	          security_controls = COALESCE($6, security_controls),
	          impact_customer_data = COALESCE($7, impact_customer_data),
	          impact_attacker_scope = COALESCE($8, impact_attacker_scope),
	          impact_company_reputation = COALESCE($9, impact_company_reputation),
	          -- $10 through $13 are pointers: NULL means the caller did not supply the field, so the
	          -- stored value survives. An explicitly empty string still clears, which is what lets the
	          -- UI form blank a summary. Before this guard, any partial update (an MCP call setting
	          -- only test_status, or the UI form, which never sent these) blanked the prose outright.
	          one_sentence = COALESCE($10, one_sentence),
	          summary = COALESCE($11, summary),
	          severity = COALESCE($12, severity),
	          -- COALESCE cannot express this one: setting authenticated back to undecided means
	          -- writing NULL, which COALESCE would read as "not supplied". $13 carries whether the
	          -- caller mentioned the field, $14 the value they gave.
	          authenticated = CASE WHEN $13 THEN $14 ELSE authenticated END,
	          attack_id = $15, attack_custom_name = $16,
	          test_status = COALESCE(NULLIF($17, ''), test_status), updated_at = NOW()
	          WHERE id = $18
	          RETURNING id, category, url, mechanism, target_object, steps, security_controls,
	          impact_customer_data, impact_attacker_scope, impact_company_reputation,
	          one_sentence, summary, severity, authenticated, attack_id, attack_custom_name,
	          test_status, created_at, updated_at`

	var threat struct {
		ID                      string `json:"id"`
		Category                string `json:"category"`
		URL                     string `json:"url"`
		Mechanism               string `json:"mechanism"`
		TargetObject            string `json:"target_object"`
		Steps                   string `json:"steps"`
		SecurityControls        string `json:"security_controls"`
		ImpactCustomerData      string `json:"impact_customer_data"`
		ImpactAttackerScope     string `json:"impact_attacker_scope"`
		ImpactCompanyReputation string `json:"impact_company_reputation"`
		OneSentence             string `json:"one_sentence"`
		Summary                 string `json:"summary"`
		Severity                string `json:"severity"`
		Authenticated           *bool  `json:"authenticated"`
		AttackID                string `json:"attack_id"`
		AttackCustomName        string `json:"attack_custom_name"`
		// Resolved from the generated catalog rather than stored, so renaming an attack in
		// attacks.js updates every threat that cites it instead of leaving stale copies behind.
		AttackName string    `json:"attack_name"`
		TestStatus string    `json:"test_status"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.Category, payload.URL,
		payload.Mechanism, payload.TargetObject, payload.Steps, payload.SecurityControls, payload.ImpactCustomerData,
		payload.ImpactAttackerScope, payload.ImpactCompanyReputation,
		payload.OneSentence, payload.Summary, payload.Severity, authSupplied, authValue,
		attackID, attackCustom, payload.TestStatus, threatID).Scan(
		&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism,
		&threat.TargetObject, &threat.Steps, &threat.SecurityControls, &threat.ImpactCustomerData,
		&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation,
		&threat.OneSentence, &threat.Summary, &threat.Severity, &threat.Authenticated, &threat.AttackID, &threat.AttackCustomName,
		&threat.TestStatus, &threat.CreatedAt, &threat.UpdatedAt,
	)

	if err != nil {
		log.Printf("[ERROR] Failed to update threat: %v", err)
		http.Error(w, "Failed to update threat", http.StatusInternalServerError)
		return
	}

	threat.AttackName = resolveAttackName(threat.AttackID, threat.AttackCustomName)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threat)
}

// SetThreatModelTestStatus flips a single threat between untested, validated and rejected.
//
// This exists rather than routing the Validate/Reject buttons through UpdateThreatModel because that
// handler replaces every column and demands category and url. Marking a threat as tested is a one-field
// change and the caller should not have to send the whole record back to make it, nor risk clobbering
// prose it never read.
func SetThreatModelTestStatus(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	threatID := vars["threat_id"]

	var payload struct {
		TestStatus string `json:"test_status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if !IsValidThreatTestStatus(payload.TestStatus) {
		http.Error(w, "test_status must be one of untested, validated, rejected", http.StatusBadRequest)
		return
	}

	query := `UPDATE threat_model
	          SET test_status = $1, updated_at = NOW()
	          WHERE id = $2
	          RETURNING id, category, url, mechanism, target_object, steps, security_controls,
	          impact_customer_data, impact_attacker_scope, impact_company_reputation,
	          one_sentence, summary, severity, authenticated, attack_id, attack_custom_name,
	          test_status, created_at, updated_at`

	var threat struct {
		ID                      string `json:"id"`
		Category                string `json:"category"`
		URL                     string `json:"url"`
		Mechanism               string `json:"mechanism"`
		TargetObject            string `json:"target_object"`
		Steps                   string `json:"steps"`
		SecurityControls        string `json:"security_controls"`
		ImpactCustomerData      string `json:"impact_customer_data"`
		ImpactAttackerScope     string `json:"impact_attacker_scope"`
		ImpactCompanyReputation string `json:"impact_company_reputation"`
		OneSentence             string `json:"one_sentence"`
		Summary                 string `json:"summary"`
		Severity                string `json:"severity"`
		Authenticated           *bool  `json:"authenticated"`
		AttackID                string `json:"attack_id"`
		AttackCustomName        string `json:"attack_custom_name"`
		// Resolved from the generated catalog rather than stored, so renaming an attack in
		// attacks.js updates every threat that cites it instead of leaving stale copies behind.
		AttackName string    `json:"attack_name"`
		TestStatus string    `json:"test_status"`
		CreatedAt  time.Time `json:"created_at"`
		UpdatedAt  time.Time `json:"updated_at"`
	}

	err := dbPool.QueryRow(context.Background(), query, payload.TestStatus, threatID).Scan(
		&threat.ID, &threat.Category, &threat.URL, &threat.Mechanism,
		&threat.TargetObject, &threat.Steps, &threat.SecurityControls, &threat.ImpactCustomerData,
		&threat.ImpactAttackerScope, &threat.ImpactCompanyReputation,
		&threat.OneSentence, &threat.Summary, &threat.Severity, &threat.Authenticated, &threat.AttackID, &threat.AttackCustomName,
		&threat.TestStatus, &threat.CreatedAt, &threat.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			http.Error(w, "Threat not found", http.StatusNotFound)
			return
		}
		log.Printf("[ERROR] Failed to set threat test status: %v", err)
		http.Error(w, "Failed to set test status", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(threat)
}

func DeleteThreatModel(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	threatID := vars["threat_id"]

	query := `DELETE FROM threat_model WHERE id = $1`
	result, err := dbPool.Exec(context.Background(), query, threatID)
	if err != nil {
		log.Printf("[ERROR] Failed to delete threat: %v", err)
		http.Error(w, "Failed to delete threat", http.StatusInternalServerError)
		return
	}

	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Threat not found", http.StatusNotFound)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
