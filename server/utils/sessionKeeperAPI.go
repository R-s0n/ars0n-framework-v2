package utils

// HTTP surface for the durable session keeper. These are thin: the loop in sessionKeeper.go does the
// real work. All writes go through the CRUD helpers so the reconcile sweep picks the change up on its
// next tick.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

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

// SetSessionKeeperLoginConfigHandler: PUT /session-keepers/{id}/login-config
// Body (any subset): { "login_url": "...", "fill_sequence": [{selector,action,value_ref,literal}],
//   "success_probe": {kind,value}, "auto_login_enabled": bool }
// This is the NON-secret half of auto-login. Enabling is validated LOUDLY here (validate, do not warn):
// the login host must be in scope (the keeper refuses to navigate off its egress allowlist) and the
// fill sequence + stored credentials must be present. The response returns the keeper via
// sessionKeeperCols, so it never carries the password.
func SetSessionKeeperLoginConfigHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "id must be a UUID"})
		return
	}
	var body struct {
		AutoLoginEnabled *bool               `json:"auto_login_enabled"`
		LoginURL         *string             `json:"login_url"`
		FillSequence     []KeeperLoginStep   `json:"fill_sequence"`
		SuccessProbe     *KeeperSuccessProbe `json:"success_probe"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid body"})
		return
	}
	k, err := GetSessionKeeper(context.Background(), id)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}

	// A config object is passed to the store only when at least one of its parts was sent, so a bare
	// enable/disable toggle leaves the stored fill sequence alone.
	var cfgPtr *KeeperLoginConfig
	if body.FillSequence != nil || body.SuccessProbe != nil {
		cfg := KeeperLoginConfig{Steps: k.FillSequence, SuccessProbe: k.SuccessProbe}
		if body.FillSequence != nil {
			cfg.Steps = body.FillSequence
		}
		if body.SuccessProbe != nil {
			cfg.SuccessProbe = *body.SuccessProbe
		}
		cfgPtr = &cfg
	}

	// Effective values = what is being set in this call, else what is already stored.
	effURL := k.LoginURL
	if body.LoginURL != nil {
		effURL = *body.LoginURL
	}
	effSteps := k.FillSequence
	effProbe := k.SuccessProbe
	if cfgPtr != nil {
		effSteps = cfgPtr.Steps
		effProbe = cfgPtr.SuccessProbe
	}

	// Structural validation of a non-empty config, so a half-built sequence is rejected at save time.
	if effURL != "" || len(effSteps) > 0 {
		if problem := validateKeeperLoginConfig(effURL, effSteps, effProbe); problem != "" {
			writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": problem})
			return
		}
	}

	// Enabling has extra preconditions: credentials stored and the login host in scope.
	if body.AutoLoginEnabled != nil && *body.AutoLoginEnabled {
		if len(effSteps) == 0 {
			writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "auto-login needs a login fill sequence (record the login or enter the selector steps) before it can be enabled"})
			return
		}
		if !k.HasPassword {
			writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "auto-login needs stored credentials (set a username and password) before it can be enabled"})
			return
		}
		lh := hostOfURL(effURL)
		scope := LoadScanScope(k.ScopeTargetID)
		inScope, authSuffixes := scope.SuffixesByEffect()
		allow := append(append([]string{}, inScope...), authSuffixes...)
		if lh == "" || !hostAllowed(lh, allow) {
			writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "the login host is not in scope; add it to the scope (in-scope or as an auth host) so the keeper is allowed to navigate to it"})
			return
		}
	}

	updated, err := SetKeeperLoginConfig(context.Background(), id, body.AutoLoginEnabled, body.LoginURL, cfgPtr)
	if err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"keeper": updated})
}

// SetSessionKeeperCredentialsHandler: PUT /session-keepers/{id}/credentials
// Body: { "username": "...", "password": "..." }
// The SECRET half of auto-login. The password is write-only: it is stored encrypted at rest and never
// returned by any read. The response confirms storage without echoing the password.
func SetSessionKeeperCredentialsHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "id must be a UUID"})
		return
	}
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "invalid body"})
		return
	}
	if strings.TrimSpace(body.Password) == "" {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "a password is required"})
		return
	}
	if err := SetKeeperCredentials(context.Background(), id, body.Username, body.Password); err != nil {
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": err.Error()})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
		"success": true, "has_credentials": true, "username": strings.TrimSpace(body.Username)})
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
