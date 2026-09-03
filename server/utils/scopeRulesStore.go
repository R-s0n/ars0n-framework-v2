package utils

// Storage and HTTP surface for scope rules.
//
// The evaluator lives in scopeRules.go and knows nothing about the database. This file is the only
// thing that reads or writes scope_rules, so there is exactly one place where a stored rule becomes
// an evaluated one.

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// LoadScopeRules returns the authored rules for a target, compiled and ready to evaluate.
//
// A rule that will not compile fails the WHOLE target closed rather than being skipped, because
// dropping a broken rule is harmless for an allow and catastrophic for a deny, and nothing here can
// safely tell which one the operator meant.
func LoadScopeRules(scopeTargetID string) ([]ScopeRule, error) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, effect, kind, value, COALESCE(port,0), COALESCE(within,''),
		       is_ip, blast, enabled
		FROM scope_rules
		WHERE scope_target_id = $1
		ORDER BY created_at ASC`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("could not read scope rules: %w", err)
	}
	defer rows.Close()

	var out []ScopeRule
	for rows.Next() {
		var r ScopeRule
		var effect, kind, blast string
		if err := rows.Scan(&r.ID, &effect, &kind, &r.Value, &r.Port, &r.Within,
			&r.IsIP, &blast, &r.Enabled); err != nil {
			return nil, fmt.Errorf("could not read a scope rule: %w", err)
		}
		r.Effect = ScopeEffect(effect)
		r.Kind = ScopeKind(kind)
		r.Blast = ScopeBlast(blast)
		out = append(out, r)
	}
	return CompileScopeRules(out)
}

// HasScopeRules reports whether an operator has authored anything for this target. Callers use it to
// keep the pre-rules behaviour byte-for-byte identical when nobody has opted in.
func HasScopeRules(scopeTargetID string) bool {
	var n int
	err := dbPool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM scope_rules WHERE scope_target_id = $1 AND enabled`,
		scopeTargetID).Scan(&n)
	return err == nil && n > 0
}

/* ------------------------------------------------------------------ HTTP */

type scopeRuleDTO struct {
	ID        string `json:"id,omitempty"`
	Typed     string `json:"typed,omitempty"`
	Canonical string `json:"canonical"`
	Sentence  string `json:"sentence"`
	Effect    string `json:"effect"`
	Kind      string `json:"kind"`
	Value     string `json:"value"`
	Port      int    `json:"port,omitempty"`
	Within    string `json:"within,omitempty"`
	Blast     string `json:"blast"`
	Enabled   bool   `json:"enabled"`
	Note      string `json:"note,omitempty"`
}

func dtoFor(r ScopeRule, note string) scopeRuleDTO {
	return scopeRuleDTO{
		ID: r.ID, Canonical: CanonicalScopeText(r), Sentence: RenderScopeRule(r),
		Effect: string(r.Effect), Kind: string(r.Kind), Value: r.Value,
		Port: r.Port, Within: r.Within, Blast: string(r.Blast), Enabled: r.Enabled, Note: note,
	}
}

// GetScopeRules handles GET /scope-rules/{scope_target_id}.
func GetScopeRules(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["scope_target_id"]
	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, effect, kind, value, COALESCE(port,0), COALESCE(within,''),
		       is_ip, blast, enabled, canonical, COALESCE(note,'')
		FROM scope_rules WHERE scope_target_id = $1 ORDER BY created_at ASC`, id)
	if err != nil {
		http.Error(w, "Failed to read scope rules", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := make([]scopeRuleDTO, 0)
	for rows.Next() {
		var rule ScopeRule
		var effect, kind, blast, canonical, note string
		if rows.Scan(&rule.ID, &effect, &kind, &rule.Value, &rule.Port, &rule.Within,
			&rule.IsIP, &blast, &rule.Enabled, &canonical, &note) != nil {
			continue
		}
		rule.Effect, rule.Kind, rule.Blast = ScopeEffect(effect), ScopeKind(kind), ScopeBlast(blast)
		out = append(out, dtoFor(rule, note))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"rules": out,
		// The legacy boundary is shown alongside, because until an operator authors a rule it is
		// still the thing being enforced and a screen that hides it would be lying.
		"legacy_hosts": InScopeCrawlHosts(id),
		"rules_active": HasScopeRules(id),
	})
}

// PreviewScopeRule handles POST /scope-rules/preview. It parses without storing, so the popup and
// the React editor can render the sentence and the blast radius as the operator types.
//
// It also answers the only question that matters before saving a wide rule: of the hosts this crawl
// has already seen, which ones would this rule newly admit?
func PreviewScopeRule(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID string `json:"scope_target_id"`
		Typed         string `json:"typed"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	rule, err := ParseScopeRule(payload.Typed)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}

	resp := map[string]interface{}{
		"ok":   true,
		"rule": dtoFor(rule, ""),
	}

	// What this rule would do to hosts already recorded. This is honest about its own blind spot:
	// a wide rule exists precisely to admit hosts nobody has seen, and those cannot be previewed.
	if payload.ScopeTargetID != "" {
		existing, loadErr := LoadScopeRules(payload.ScopeTargetID)
		if loadErr == nil {
			compiled, cErr := CompileScopeRules([]ScopeRule{rule})
			if cErr == nil {
				var newlyMatched, newlyDenied []string
				for _, host := range crawlHostsForTarget(payload.ScopeTargetID) {
					auth, ok := NormalizeAuthority(host, "https")
					if !ok {
						continue
					}
					before := DecideScope(existing, auth, ok, ScopeDecisionInput{})
					after := DecideScope(append(append([]ScopeRule{}, existing...), compiled[0]),
						auth, ok, ScopeDecisionInput{})
					if !before.Allowed && after.Allowed {
						newlyMatched = append(newlyMatched, host)
					}
					if before.Allowed && !after.Allowed {
						newlyDenied = append(newlyDenied, host)
					}
				}
				resp["newly_allowed"] = newlyMatched
				resp["newly_denied"] = newlyDenied
			}
		}
		if rule.Blast == BlastWide {
			resp["warning"] = "This rule can admit hosts nobody has seen yet, so the preview above " +
				"cannot show everything it would match. Add \"within <domain>\" to bound it."
		}
	}
	json.NewEncoder(w).Encode(resp)
}

func crawlHostsForTarget(scopeTargetID string) []string {
	rows, err := dbPool.Query(context.Background(),
		`SELECT DISTINCT capture_host(url) FROM manual_crawl_captures
		 WHERE scope_target_id = $1 AND capture_host(url) <> ''`, scopeTargetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if rows.Scan(&h) == nil && h != "" {
			out = append(out, h)
		}
	}
	return out
}

// CreateScopeRule handles POST /scope-rules. A wide rule is stored disabled unless the caller
// confirms it by echoing back its exact canonical text, so widening the boundary is always a
// deliberate second act.
func CreateScopeRule(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		ScopeTargetID string `json:"scope_target_id"`
		Typed         string `json:"typed"`
		Note          string `json:"note"`
		ConfirmWide   string `json:"confirm_wide"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.ScopeTargetID == "" {
		http.Error(w, "Invalid request body. scope_target_id and typed are required.", http.StatusBadRequest)
		return
	}

	rule, err := ParseScopeRule(payload.Typed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	canonical := CanonicalScopeText(rule)
	enabled := true
	if rule.Blast == BlastWide {
		// The confirmation is the canonical text, not a boolean, so an operator cannot confirm a
		// rule other than the one they are looking at.
		if strings.TrimSpace(payload.ConfirmWide) != canonical {
			http.Error(w, fmt.Sprintf(
				"%q can admit hosts nobody has seen yet. It has not been saved. To save it anyway, "+
					"confirm by sending confirm_wide exactly as %q, or bound it with \"within <domain>\".",
				canonical, canonical), http.StatusPreconditionRequired)
			return
		}
	}

	var id string
	err = dbPool.QueryRow(context.Background(), `
		INSERT INTO scope_rules
		  (scope_target_id, effect, kind, value, port, within, is_ip, blast, enabled, canonical, note)
		VALUES ($1,$2,$3,$4,NULLIF($5,0),NULLIF($6,''),$7,$8,$9,$10,NULLIF($11,''))
		ON CONFLICT (scope_target_id, canonical) DO UPDATE
		  SET enabled = EXCLUDED.enabled, note = EXCLUDED.note
		RETURNING id::text`,
		payload.ScopeTargetID, string(rule.Effect), string(rule.Kind), rule.Value,
		rule.Port, rule.Within, rule.IsIP, string(rule.Blast), enabled, canonical, payload.Note,
	).Scan(&id)
	if err != nil {
		log.Printf("[SCOPE] Failed to store rule %q: %v", canonical, err)
		http.Error(w, "Failed to store the rule", http.StatusInternalServerError)
		return
	}

	rule.ID = id
	log.Printf("[SCOPE] target %s: stored %s (%s)", payload.ScopeTargetID, canonical, rule.Blast)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(dtoFor(rule, payload.Note))
}

// DeleteScopeRule handles DELETE /scope-rules/{rule_id}.
func DeleteScopeRule(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["rule_id"]
	tag, err := dbPool.Exec(context.Background(), `DELETE FROM scope_rules WHERE id = $1`, id)
	if err != nil {
		http.Error(w, "Failed to delete the rule", http.StatusInternalServerError)
		return
	}
	if tag.RowsAffected() == 0 {
		http.Error(w, "No such rule", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "deleted"})
}

// SetScopeRuleEnabled handles PATCH /scope-rules/{rule_id}. This is how a wide rule stored inert
// gets switched on, and how one gets switched off without losing the text.
func SetScopeRuleEnabled(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["rule_id"]
	var payload struct {
		Enabled     *bool  `json:"enabled"`
		ConfirmWide string `json:"confirm_wide"`
	}
	if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.Enabled == nil {
		http.Error(w, "Invalid request body. `enabled` is required.", http.StatusBadRequest)
		return
	}

	var canonical, blast string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT canonical, blast FROM scope_rules WHERE id = $1`, id).Scan(&canonical, &blast); err != nil {
		http.Error(w, "No such rule", http.StatusNotFound)
		return
	}

	// Enabling a wide rule needs the same confirmation creating one does, or the confirmation is
	// just a speed bump you get past by saving first and toggling second.
	if *payload.Enabled && blast == string(BlastWide) && strings.TrimSpace(payload.ConfirmWide) != canonical {
		http.Error(w, fmt.Sprintf(
			"%q can admit hosts nobody has seen yet. Confirm by sending confirm_wide exactly as %q.",
			canonical, canonical), http.StatusPreconditionRequired)
		return
	}

	if _, err := dbPool.Exec(context.Background(),
		`UPDATE scope_rules SET enabled = $2 WHERE id = $1`, id, *payload.Enabled); err != nil {
		http.Error(w, "Failed to update the rule", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "updated", "enabled": *payload.Enabled})
}
