package utils

// HTTP surface for the durable session keeper. These are thin: the loop in sessionKeeper.go does the
// real work. All writes go through the CRUD helpers so the reconcile sweep picks the change up on its
// next tick.

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// GetSessionKeepersHandler: GET /session-keepers/target/{scope_target_id}
func GetSessionKeepersHandler(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "scope_target_id must be a UUID"})
		return
	}
	keepers, err := GetSessionKeepers(context.Background(), scopeTargetID)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"keepers": keepers, "count": len(keepers)})
}

// CreateSessionKeeperHandler: POST /session-keepers/target/{scope_target_id}
// Body: { "name": "account-A", "target_url": "https://app...", "cadence_seconds": 600 }
func CreateSessionKeeperHandler(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "scope_target_id must be a UUID"})
		return
	}
	var body struct {
		Name           string `json:"name"`
		TargetURL      string `json:"target_url"`
		CadenceSeconds int    `json:"cadence_seconds"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	k, err := CreateSessionKeeper(context.Background(), scopeTargetID, body.Name, body.TargetURL, body.CadenceSeconds)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"keeper": k})
}

// UpdateSessionKeeperHandler: PUT /session-keepers/{id}
// Body: any of { "enabled": bool, "target_url": string, "cadence_seconds": int }
func UpdateSessionKeeperHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "id must be a UUID"})
		return
	}
	var body struct {
		Enabled        *bool   `json:"enabled"`
		TargetURL      *string `json:"target_url"`
		CadenceSeconds *int    `json:"cadence_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid body"})
		return
	}
	k, err := UpdateSessionKeeper(context.Background(), id, body.Enabled, body.TargetURL, body.CadenceSeconds)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"keeper": k})
}

// DeleteSessionKeeperHandler: DELETE /session-keepers/{id}
func DeleteSessionKeeperHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "id must be a UUID"})
		return
	}
	if err := DeleteSessionKeeper(context.Background(), id); err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"success": true})
}

// AdoptKeeperCookiesHandler: POST /session-keepers/{id}/adopt-cookies
// Claims the target's currently-untagged cookie tokens for this keeper's account so the keeper seeds
// exactly them. Idempotent and multi-account-safe (only touches keeper_name='' rows).
func AdoptKeeperCookiesHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "id must be a UUID"})
		return
	}
	claimed, owned, account, err := AdoptKeeperCookies(context.Background(), id)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "claimed": claimed, "owned": owned, "account": account})
}

// SetSessionKeeperEnabledHandler handles the start/stop convenience routes by toggling enabled.
func SetSessionKeeperEnabledHandler(enabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if _, err := uuid.Parse(id); err != nil {
			writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "id must be a UUID"})
			return
		}
		e := enabled
		k, err := UpdateSessionKeeper(context.Background(), id, &e, nil, nil)
		if err != nil {
			writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
			return
		}
		writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"keeper": k})
	}
}
