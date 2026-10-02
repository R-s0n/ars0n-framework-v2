package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// Session tokens: the credential a scan carries, and the two questions an operator actually has
// about it.
//
// The first question is "is this thing still working", and the answer that matters is not the HTTP
// status of an authenticated request. It is the comparison against the same request sent with no
// credential at all. A target that answers 200 to both is not honouring the token, and reporting
// that as "active" because it was a 200 is how an operator spends an afternoon on a scan that ran
// completely unauthenticated and reported a login wall on every endpoint.
//
// The second question is "can I get a new one without doing the login by hand", which is why every
// token can be tied to the auth flow that issues it. Refresh replays that flow through the same
// engine the Auth Flows tab uses and pulls the new value out of the result.

const (
	tokenTypeHeader = "header"
	tokenTypeCookie = "cookie"
	tokenTypeAPIKey = "api_key"
	tokenTypeBearer = "bearer"
	tokenTypeQuery  = "query"
)

// validSessionTokenTypes mirrors the DB CHECK constraint on session_tokens.token_type.
var validSessionTokenTypes = map[string]bool{
	tokenTypeHeader: true,
	tokenTypeCookie: true,
	tokenTypeAPIKey: true,
	tokenTypeBearer: true,
	tokenTypeQuery:  true,
}

// What a stored value IS, as opposed to how it travels. See the database.go migration for the
// measurement that made this necessary.
const (
	tokenRoleCredential = "credential"
	tokenRoleCompanion  = "companion"
	// A refresh row is a stored secret SPENT to mint another credential (an OAuth refresh_token, or any
	// value the app trades for a fresh access token). It is never attached to a resource request and
	// never graded by an honoured/not-honoured comparison; it is graded only by whether it still mints.
	// Its own expires_at IS tracked, because a dead refresh token means the whole session is dead.
	tokenRoleRefresh = "refresh"
)

var validSessionTokenRoles = map[string]bool{
	tokenRoleCredential: true,
	tokenRoleCompanion:  true,
	tokenRoleRefresh:    true,
}

// normalizeTokenRole defaults an unset role to credential and refuses anything it does not know.
//
// Defaulting matters as much as validating: every token that existed before this column did has an
// empty role, and treating those as anything but a credential would stop them being graded.
func normalizeTokenRole(role string) (string, error) {
	role = strings.ToLower(strings.TrimSpace(role))
	if role == "" {
		return tokenRoleCredential, nil
	}
	if !validSessionTokenRoles[role] {
		return "", fmt.Errorf("token_role must be credential, companion, or refresh")
	}
	return role, nil
}

// Validation verdicts. These are stored in last_validation_status, so they stay short and stable:
// the client renders them as badges and a renamed value silently stops matching.
const (
	tokenStatusActive      = "active"
	tokenStatusExpired     = "expired"
	tokenStatusNotHonoured = "not_honoured"
	tokenStatusError       = "error"
	// A companion is not a credential and cannot be graded like one: sending a routing cookie on its
	// own changes nothing, so the honoured/not-honoured comparison is meaningless for it and
	// reporting not_honoured reads as "dead credential" for a value that is working perfectly.
	tokenStatusCompanion = "companion"
	// A refresh secret is graded by whether it still mints a fresh credential, not by an
	// honoured/not-honoured comparison, so like a companion it is never sent on its own for grading.
	// Deliberately absent from sessionTokenRejectedStatuses so it is never read as a dead credential.
	tokenStatusRefresh = "refresh"
)

// sessionTokenRejectedStatuses are the validation verdicts that mean the target refused the token.
// Mirrors the client's REJECTED_STATUSES (RefreshSessionModal.js) so the card, Manage Sessions and
// Refresh Session all agree on what counts as "expired". A companion's verdict is "companion", which
// is deliberately absent, so a routing cookie is never treated as a dead credential.
var sessionTokenRejectedStatuses = map[string]bool{
	"expired": true, "not_honoured": true, "invalid": true,
	"unauthorized": true, "rejected": true, "failed": true, "revoked": true,
}

// sessionTokenLooksDead reports whether a token is known to be dead: its expires_at column has passed
// or its last validation verdict was a rejection. Used to count active-but-expired credentials so a
// screen can say "active, but expired" rather than a bare "active".
func sessionTokenLooksDead(tok SessionToken, now time.Time) bool {
	if tok.ExpiresAt != nil && tok.ExpiresAt.Before(now) {
		return true
	}
	return sessionTokenRejectedStatuses[strings.ToLower(strings.TrimSpace(tok.LastValidationStatus))]
}

// SessionToken mirrors a session_tokens row, with the linked flow's name joined on for display.
type SessionToken struct {
	ID                   string     `json:"id"`
	ScopeTargetID        string     `json:"scope_target_id"`
	AuthFlowID           string     `json:"auth_flow_id"`
	AuthFlowName         string     `json:"auth_flow_name"`
	Name                 string     `json:"name"`
	TokenType            string     `json:"token_type"`
	TokenRole            string     `json:"token_role"`
	HeaderName           string     `json:"header_name"`
	CookieName           string     `json:"cookie_name"`
	ParamName            string     `json:"param_name"`
	ValuePrefix          string     `json:"value_prefix"`
	TokenValue           string     `json:"token_value"`
	ScopeDomains         []string   `json:"scope_domains"`
	CookiePath           string     `json:"cookie_path"`
	CookieDomain         string     `json:"cookie_domain"`
	CookieSecure         bool       `json:"cookie_secure"`
	CookieHTTPOnly       bool       `json:"cookie_httponly"`
	CookieSameSite       string     `json:"cookie_samesite"`
	ExpiresAt            *time.Time `json:"expires_at"`
	IsActive             bool       `json:"is_active"`
	Notes                string     `json:"notes"`
	LastValidatedAt      *time.Time `json:"last_validated_at"`
	LastValidationStatus string     `json:"last_validation_status"`
	LastValidationDetail string     `json:"last_validation_detail"`
	LastRefreshedAt      *time.Time `json:"last_refreshed_at"`
	// AutoRefresh opts this token into unattended refresh as it nears expiry, applied only when its flow
	// is fully automatable and a refresh has worked before. Off by default. See sessionAutoRefreshLoop.
	AutoRefresh bool `json:"auto_refresh"`
	// OAuth access/refresh-token model (docs/OAUTH_REFRESH_DESIGN.md). All optional; empty means unset.
	// RefreshTokenID / RefreshFlowID are stored as UUID strings ('' = NULL), like AuthFlowID.
	RefreshTokenID     string    `json:"refresh_token_id"`     // the refresh-role row that renews this one
	RefreshFlowID      string    `json:"refresh_flow_id"`      // the headless REFRESH flow (auth_flow_id stays creation)
	RefreshStrategy    string    `json:"refresh_strategy"`     // oauth_refresh_grant | replay_request | browser_recapture | none
	RefreshTransport   string    `json:"refresh_transport"`    // headless | browser_only | unknown (capability, not a gate)
	RefreshMaterialKey string    `json:"refresh_material_key"` // optional writeback JSON key override
	// CredentialKind is the measured/assigned kind of the value (oauth_access_token, oauth_refresh_token,
	// jwt, opaque_bearer, ...). It is the credential_kind column (also surfaced nested as profile.kind);
	// read-only here so the UI and MCP can badge an OAuth token without loading the full profile. Written
	// by captureOAuthTriad and the profiler, not by the generic token PUT.
	CredentialKind string    `json:"credential_kind"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`

	// Profile is what the token characterisation engine measured about this credential: its kind,
	// its lifetime and the provenance of that lifetime, and whether the session can be refreshed.
	// It is not a column; it is filled in by AttachSessionTokenProfiles on the read path and is
	// nil when nothing has been measured, which reads as unmeasured rather than as unlimited.
	Profile *SessionTokenProfile `json:"profile,omitempty"`
}

// sessionTokenPayload is the write shape for create and update. Every field is a pointer so an
// update can tell "leave this alone" apart from "set this to empty", which matters most for
// token_value: a client that omits it must not blank the credential.
type sessionTokenPayload struct {
	AuthFlowID     *string    `json:"auth_flow_id"`
	Name           *string    `json:"name"`
	TokenType      *string    `json:"token_type"`
	TokenRole      *string    `json:"token_role"`
	HeaderName     *string    `json:"header_name"`
	CookieName     *string    `json:"cookie_name"`
	ParamName      *string    `json:"param_name"`
	ValuePrefix    *string    `json:"value_prefix"`
	TokenValue     *string    `json:"token_value"`
	ScopeDomains   []string   `json:"scope_domains"`
	CookiePath     *string    `json:"cookie_path"`
	CookieDomain   *string    `json:"cookie_domain"`
	CookieSecure   *bool      `json:"cookie_secure"`
	CookieHTTPOnly *bool      `json:"cookie_httponly"`
	CookieSameSite *string    `json:"cookie_samesite"`
	ExpiresAt      *time.Time `json:"expires_at"`
	IsActive       *bool      `json:"is_active"`
	Notes          *string    `json:"notes"`
	AutoRefresh    *bool      `json:"auto_refresh"`
	// OAuth refresh model, all optional on write (nil = leave alone).
	RefreshTokenID     *string `json:"refresh_token_id"`
	RefreshFlowID      *string `json:"refresh_flow_id"`
	RefreshStrategy    *string `json:"refresh_strategy"`
	RefreshTransport   *string `json:"refresh_transport"`
	RefreshMaterialKey *string `json:"refresh_material_key"`
}

const sessionTokenCols = `t.id::text, t.scope_target_id::text, COALESCE(t.auth_flow_id::text,''),
	COALESCE(f.name,''), t.name, t.token_type, COALESCE(t.token_role,'credential'),
	COALESCE(t.header_name,''),
	COALESCE(t.cookie_name,''), COALESCE(t.param_name,''), COALESCE(t.value_prefix,''),
	COALESCE(t.token_value,''), COALESCE(t.scope_domains,'{}'), COALESCE(t.cookie_path,'/'),
	COALESCE(t.cookie_domain,''), COALESCE(t.cookie_secure,false), COALESCE(t.cookie_httponly,false),
	COALESCE(t.cookie_samesite,''), t.expires_at, COALESCE(t.is_active,false), COALESCE(t.notes,''),
	t.last_validated_at, COALESCE(t.last_validation_status,''), COALESCE(t.last_validation_detail,''),
	t.last_refreshed_at, COALESCE(t.auto_refresh,false),
	COALESCE(t.refresh_token_id::text,''), COALESCE(t.refresh_flow_id::text,''),
	COALESCE(t.refresh_strategy,''), COALESCE(t.refresh_transport,''),
	COALESCE(t.refresh_material_key,''), COALESCE(t.credential_kind,''),
	t.created_at, t.updated_at`

const sessionTokenFrom = ` FROM session_tokens t LEFT JOIN auth_flows f ON f.id = t.auth_flow_id `

// SessionTokenView is the read shape: every field of the row, the credential included, plus three
// facts about the value that a screen would otherwise have to measure for itself. The fingerprint
// says WHICH credential a row holds, so two rows carrying the same token can be spotted; the byte
// length is occasionally the only distinguishing fact about an opaque value; and has_value tells
// an empty row apart from a stored one, so a working session is not drawn as broken.
type SessionTokenView struct {
	ID                   string     `json:"id"`
	ScopeTargetID        string     `json:"scope_target_id"`
	AuthFlowID           string     `json:"auth_flow_id"`
	AuthFlowName         string     `json:"auth_flow_name"`
	Name                 string     `json:"name"`
	TokenType            string     `json:"token_type"`
	TokenRole            string     `json:"token_role"`
	HeaderName           string     `json:"header_name"`
	CookieName           string     `json:"cookie_name"`
	ParamName            string     `json:"param_name"`
	ValuePrefix          string     `json:"value_prefix"`
	ScopeDomains         []string   `json:"scope_domains"`
	CookiePath           string     `json:"cookie_path"`
	CookieDomain         string     `json:"cookie_domain"`
	CookieSecure         bool       `json:"cookie_secure"`
	CookieHTTPOnly       bool       `json:"cookie_httponly"`
	CookieSameSite       string     `json:"cookie_samesite"`
	ExpiresAt            *time.Time `json:"expires_at"`
	IsActive             bool       `json:"is_active"`
	Notes                string     `json:"notes"`
	LastValidatedAt      *time.Time `json:"last_validated_at"`
	LastValidationStatus string     `json:"last_validation_status"`
	LastValidationDetail string     `json:"last_validation_detail"`
	LastRefreshedAt      *time.Time `json:"last_refreshed_at"`
	AutoRefresh          bool       `json:"auto_refresh"`
	RefreshTokenID       string     `json:"refresh_token_id"`
	RefreshFlowID        string     `json:"refresh_flow_id"`
	RefreshStrategy      string     `json:"refresh_strategy"`
	RefreshTransport     string     `json:"refresh_transport"`
	RefreshMaterialKey   string     `json:"refresh_material_key"`
	CredentialKind       string     `json:"credential_kind"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`

	// HasValue says whether the row holds a credential at all. An empty row and a stored one are
	// different states and a screen that cannot tell them apart shows a working session as broken.
	HasValue bool `json:"has_value"`
	// ValueFingerprint is eight hex digits of the credential's SHA-256, or the word "none". Two
	// rows with the same fingerprint carry the same token, and a row whose fingerprint changed was
	// re-pasted, neither of which a screen can tell at a glance from two long opaque strings.
	ValueFingerprint string `json:"value_fingerprint"`
	// ValueLength is the byte length, so a screen does not have to count it.
	ValueLength int `json:"value_length"`

	// TokenValue is the stored credential, served to every caller. It is the operator's own
	// database read by the operator's own tool, and a captured credential is the evidence: a list
	// that hands back anything less cannot prove what was captured.
	TokenValue string `json:"token_value"`

	Profile *SessionTokenProfile `json:"profile,omitempty"`
}

// sessionTokenEventView projects one row of the validate and refresh history.
//
// The detail sentence and the evidence blob go out exactly as they were stored. The evidence is a
// recording of what the target answered, Location headers and probe URLs included, and a Location
// is precisely where a credential lands during an OAuth or SSO redirect, which is the thing an
// operator needs to see.
func sessionTokenEventView(id, kind, status, detail string, evidence map[string]interface{}, createdAt time.Time) map[string]interface{} {
	return map[string]interface{}{
		"id":     id,
		"kind":   kind,
		"status": status,
		"detail": detail,
		// A NIL MAP STAYS A NIL MAP. It marshals to null, and an empty object is not the same fact:
		// RefreshSessionModal.js renders the evidence block on `ev.evidence &&`, and {} is truthy in
		// JavaScript, so an empty object would draw an evidence panel reading "{}" for every event
		// that has no evidence behind it.
		"evidence":   evidence,
		"created_at": createdAt,
	}
}

// sessionTokenView projects one row.
func sessionTokenView(t SessionToken) SessionTokenView {
	cred := NewCredential(t.TokenValue)
	v := SessionTokenView{
		ID: t.ID, ScopeTargetID: t.ScopeTargetID, AuthFlowID: t.AuthFlowID,
		AuthFlowName: t.AuthFlowName,
		Name:         t.Name,
		TokenType:    t.TokenType,
		TokenRole:    t.TokenRole,
		HeaderName:   t.HeaderName,
		CookieName:   t.CookieName,
		ParamName:    t.ParamName,
		ValuePrefix:  t.ValuePrefix,
		ScopeDomains: t.ScopeDomains,
		CookiePath:   t.CookiePath, CookieDomain: t.CookieDomain, CookieSecure: t.CookieSecure,
		CookieHTTPOnly: t.CookieHTTPOnly, CookieSameSite: t.CookieSameSite,
		ExpiresAt: t.ExpiresAt, IsActive: t.IsActive,
		Notes:                t.Notes,
		LastValidatedAt:      t.LastValidatedAt,
		LastValidationStatus: t.LastValidationStatus,
		LastValidationDetail: t.LastValidationDetail,
		LastRefreshedAt:      t.LastRefreshedAt,
		AutoRefresh:          t.AutoRefresh,
		RefreshTokenID:       t.RefreshTokenID,
		RefreshFlowID:        t.RefreshFlowID,
		RefreshStrategy:      t.RefreshStrategy,
		RefreshTransport:     t.RefreshTransport,
		RefreshMaterialKey:   t.RefreshMaterialKey,
		CredentialKind:       t.CredentialKind,
		CreatedAt:            t.CreatedAt, UpdatedAt: t.UpdatedAt,
		HasValue:         !cred.IsZero(),
		ValueFingerprint: cred.Fingerprint(),
		ValueLength:      cred.Len(),
		TokenValue:       t.TokenValue,
		Profile:          t.Profile,
	}
	if v.ScopeDomains == nil {
		v.ScopeDomains = []string{}
	}
	return v
}

// sessionTokenViews projects a list.
func sessionTokenViews(tokens []SessionToken) []SessionTokenView {
	out := make([]SessionTokenView, 0, len(tokens))
	for i := range tokens {
		out = append(out, sessionTokenView(tokens[i]))
	}
	return out
}

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// sessionTokenListLoader is the seam the list handler reads through, so the projection above can be
// tested against the handler's real response bytes without a database.
var sessionTokenListLoader = loadSessionTokensForTarget

func loadSessionTokensForTarget(ctx context.Context, scopeTargetID string) ([]SessionToken, error) {
	if dbPool == nil {
		return nil, fmt.Errorf("no database connection")
	}
	rows, err := dbPool.Query(ctx,
		`SELECT `+sessionTokenCols+sessionTokenFrom+
			`WHERE t.scope_target_id = $1 ORDER BY t.is_active DESC, t.created_at ASC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	tokens := []SessionToken{}
	for rows.Next() {
		t, scanErr := scanSessionToken(rows)
		if scanErr != nil {
			log.Printf("[SESSION-TOKEN] Failed to scan token row: %v", scanErr)
			continue
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetSessionTokens handles GET /session-tokens/target/{scope_target_id}.
func GetSessionTokens(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	// context.Background() and not r.Context(), which is what this handler always used.
	// AttachSessionTokenProfiles WRITES the measurements it takes, and a browser that navigates
	// away mid-request would otherwise cancel that write half done. Changing it is a separate
	// decision from the projection below and is not made here.
	ctx := context.Background()
	tokens, err := sessionTokenListLoader(ctx, scopeTargetID)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to list tokens: %v", err)
		http.Error(w, "Failed to fetch session tokens", http.StatusInternalServerError)
		return
	}
	// What kind of credential each of these is, how long it lives and whether it can be renewed.
	// Attached here rather than joined in SQL because a profile is a measurement and not a column:
	// see AttachSessionTokenProfiles for why a stale one is dropped rather than shown.
	AttachSessionTokenProfiles(ctx, tokens)

	writeSessionTokenJSON(w, http.StatusOK, sessionTokenViews(tokens))
}

// GetSessionTokenEvents handles GET /session-tokens/{id}/events.
func GetSessionTokenEvents(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)

	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, kind, COALESCE(status,''), COALESCE(detail,''), evidence, created_at
		FROM session_token_events
		WHERE session_token_id = $1
		ORDER BY created_at DESC
		LIMIT 200`, tokenID)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to list events: %v", err)
		http.Error(w, "Failed to fetch token events", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	events := []map[string]interface{}{}
	for rows.Next() {
		var id, kind, status, detail string
		var evidenceJSON []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &kind, &status, &detail, &evidenceJSON, &createdAt); err != nil {
			continue
		}
		var evidence map[string]interface{}
		if len(evidenceJSON) > 0 {
			_ = json.Unmarshal(evidenceJSON, &evidence)
		}
		events = append(events, sessionTokenEventView(id, kind, status, detail, evidence, createdAt))
	}

	writeSessionTokenJSON(w, http.StatusOK, events)
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

// CreateSessionToken handles POST /session-tokens/target/{scope_target_id}.
func CreateSessionToken(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload sessionTokenPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	token := SessionToken{ScopeTargetID: scopeTargetID}
	applySessionTokenPayload(&token, payload)
	if strings.TrimSpace(token.Name) == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	if err := normalizeSessionTokenWiring(&token); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, err := insertSessionToken(token)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to create token: %v", err)
		http.Error(w, "Failed to create session token", http.StatusInternalServerError)
		return
	}
	recordSessionTokenEvent(id, "created", "manual",
		fmt.Sprintf("Added by hand as a %s token.", token.TokenType), nil)
	// Characterised as soon as it exists, so the operator is not looking at UNKNOWN for a token
	// the engine can read in the time it takes the page to re-render.
	ReprofileSessionToken(context.Background(), id)

	writeSessionTokenJSON(w, http.StatusCreated, map[string]interface{}{"id": id})
}

// UpdateSessionToken handles PUT /session-tokens/{id}.
func UpdateSessionToken(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)

	var payload sessionTokenPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	token, err := loadSessionToken(tokenID)
	if err != nil {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

	// Merged onto the stored row rather than written as a patch, so the wiring rules below judge
	// the token as it will end up, not as the request happened to describe it. Switching a token
	// from header to cookie while omitting cookie_name would otherwise pass validation.
	valueChanged := payload.TokenValue != nil && *payload.TokenValue != token.TokenValue
	applySessionTokenPayload(&token, payload)
	if strings.TrimSpace(token.Name) == "" {
		http.Error(w, "Name is required", http.StatusBadRequest)
		return
	}
	if err := normalizeSessionTokenWiring(&token); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The stored verdict described the previous value. Leaving it in place makes a freshly pasted
	// token render with the old "expired" badge, which reads as the paste having failed.
	validationStatus, validationDetail := token.LastValidationStatus, token.LastValidationDetail
	if valueChanged {
		validationStatus, validationDetail = "", ""
	}

	// A NEW VALUE CARRIES A NEW EXPIRY, and the old one must not outlive it.
	//
	// token.ExpiresAt here is the MERGED field, so when the caller sends a fresh token_value and no
	// expires_at (which is exactly what a refresh looks like) it still holds the PREVIOUS token's
	// expiry. DeriveSessionTokenExpiry returns any non-nil explicit value untouched, so the dead
	// expiry won every time and the derivation below never ran.
	//
	// MEASURED 2026-09-17: a bearer was refreshed, stored correctly (the row's token_value matched
	// the freshly minted JWT byte for byte, whose own exp was 887 seconds in the future), and
	// expires_at still read 2026-09-16, 33 hours in the past. ApplySessionTokens filters on
	// `expires_at > NOW()`, so the framework dropped the live credential it had just been given and
	// scanned anonymously. Downstream that reads as a login wall on every endpoint: 129 of 143
	// probes in one run came back 401.
	//
	// Only when the value actually changed, and only when the caller did not state an expiry
	// themselves. An operator who types an expiry means it, including for a token the framework
	// cannot parse.
	expiresAt := token.ExpiresAt
	if valueChanged && payload.ExpiresAt == nil {
		expiresAt = nil
	}

	result, err := dbPool.Exec(context.Background(), `
		UPDATE session_tokens SET
		  auth_flow_id = $1, name = $2, token_type = $3, header_name = $4, cookie_name = $5,
		  param_name = $6, value_prefix = $7, token_value = $8, scope_domains = $9,
		  cookie_path = $10, cookie_domain = $11, cookie_secure = $12, cookie_httponly = $13,
		  cookie_samesite = $14, expires_at = $15, is_active = $16, notes = $17,
		  last_validation_status = $18, last_validation_detail = $19, token_role = $21,
		  auto_refresh = $22, refresh_token_id = $23, refresh_flow_id = $24, refresh_strategy = $25,
		  refresh_transport = $26, refresh_material_key = $27,
		  updated_at = NOW()
		WHERE id = $20`,
		nullUUID(token.AuthFlowID), token.Name, token.TokenType, token.HeaderName, token.CookieName,
		token.ParamName, token.ValuePrefix, token.TokenValue, token.ScopeDomains, token.CookiePath,
		token.CookieDomain, token.CookieSecure, token.CookieHTTPOnly, token.CookieSameSite,
		DeriveSessionTokenExpiry(token.TokenValue, expiresAt),
		token.IsActive, token.Notes, validationStatus, validationDetail, tokenID, token.TokenRole,
		token.AutoRefresh, nullUUID(token.RefreshTokenID), nullUUID(token.RefreshFlowID),
		token.RefreshStrategy, token.RefreshTransport, token.RefreshMaterialKey)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to update token %s: %v", tokenID, err)
		http.Error(w, "Failed to update session token", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}
	// The value may have been replaced, and a profile of the previous credential is worse than no
	// profile at all, so it is re-measured rather than left to go stale.
	ReprofileSessionToken(context.Background(), tokenID)

	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"updated": result.RowsAffected()})
}

// DeleteSessionToken handles DELETE /session-tokens/{id}.
func DeleteSessionToken(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)

	result, err := dbPool.Exec(context.Background(), `DELETE FROM session_tokens WHERE id = $1`, tokenID)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to delete token %s: %v", tokenID, err)
		http.Error(w, "Failed to delete session token", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"deleted": result.RowsAffected()})
}

// ActivateSessionToken handles POST /session-tokens/{id}/activate.
//
// Activating a token deliberately does not deactivate any other. A working session is frequently
// more than one credential: a session cookie plus the CSRF header that has to accompany it, or a
// bearer token plus a tenant header. Treating activation as a radio button would silently switch
// off the second half of every one of those and turn a working setup into 403s.
func ActivateSessionToken(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)

	var payload struct {
		Active *bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	active := payload.Active == nil || *payload.Active

	result, err := dbPool.Exec(context.Background(),
		`UPDATE session_tokens SET is_active = $1, updated_at = NOW() WHERE id = $2`, active, tokenID)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to set active on %s: %v", tokenID, err)
		http.Error(w, "Failed to update session token", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

	state := "deactivated"
	if active {
		state = "activated"
	}
	recordSessionTokenEvent(tokenID, "activate", state,
		"Set to "+state+" by the operator. Other tokens on this target were left alone.", nil)

	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"updated": result.RowsAffected()})
}

// ---------------------------------------------------------------------------
// Raw paste parsing
// ---------------------------------------------------------------------------

// reSessionTokenHeaderLine matches a pasted header line. The name part allows only letters, digits
// and dashes, so a bare cookie pair carrying a colon in its value, redirect=https://x.com being the
// everyday case, is not mistaken for a header.
var reSessionTokenHeaderLine = regexp.MustCompile(`^([A-Za-z][A-Za-z0-9-]*):[ \t]*(.*)$`)

// reAuthScheme matches the scheme word of an Authorization value. A JWT never contains a space, so
// "first word, letters only, followed by more" is a reliable test for a scheme being present.
var reAuthScheme = regexp.MustCompile(`^[A-Za-z]+$`)

// The header names worth reading a credential out of. Anything else in a pasted request is skipped
// rather than guessed at: turning "Referer: ..." into a token would be inventing a credential.
var sessionTokenAuthHeaders = map[string]bool{
	"authorization":   true,
	"x-api-key":       true,
	"api-key":         true,
	"apikey":          true,
	"x-auth-token":    true,
	"x-access-token":  true,
	"x-session-token": true,
	"x-csrf-token":    true,
	"x-xsrf-token":    true,
}

// ParseRawSessionTokens turns a raw paste into token rows, one per cookie or credential found.
//
// The distinction people get wrong, and the reason this function exists rather than a regex at the
// call site: a Set-Cookie response header and a Cookie request header look almost identical and
// carry completely different information.
//
// Set-Cookie is the server issuing the cookie. It carries Domain, Path, Secure, HttpOnly, SameSite
// and an expiry, and those are real facts about the cookie that belong on the row. A Cookie header
// is the browser sending the value back, and that wire format has no room for any of it: it is bare
// name=value pairs and nothing else. So a token parsed from a Cookie header gets the scope target's
// own host and no flags at all. Copying Secure or a wildcard Domain onto it because the other form
// usually has them would be inventing evidence, and the operator would later read those flags back
// as something that was observed.
//
// fallbackHost is the scope target's host, used for everything that does not carry a Domain of its
// own. Deliberately the host and not its registrable domain: the only thing a Cookie header proves
// is that a browser sent this value to the host it was captured from, and widening that to every
// subdomain hands the operator's live session to hosts they never authenticated to.
func ParseRawSessionTokens(raw, fallbackHost string) []SessionToken {
	fallbackHost = strings.ToLower(strings.TrimSpace(fallbackHost))
	var out []SessionToken

	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		match := reSessionTokenHeaderLine.FindStringSubmatch(line)
		if match == nil {
			// No header prefix, so this is a bare "a=1; b=2" cookie string. It gets the Cookie
			// header treatment because that is exactly what it is, minus the label.
			out = append(out, parseCookieHeaderTokens(line, fallbackHost)...)
			continue
		}

		name, value := strings.ToLower(match[1]), strings.TrimSpace(match[2])
		switch {
		case name == "set-cookie":
			out = append(out, parseSetCookieTokens(value, fallbackHost)...)
		case name == "cookie":
			out = append(out, parseCookieHeaderTokens(value, fallbackHost)...)
		case sessionTokenAuthHeaders[name]:
			if token, ok := parseAuthHeaderToken(match[1], value, fallbackHost); ok {
				out = append(out, token)
			}
		}
	}
	return out
}

// parseSetCookieTokens reads one Set-Cookie line, flags and all.
//
// The parsing is stdlib, not hand-rolled. http.Response.Cookies covers quoted values, the two
// Expires date formats servers actually emit, Max-Age, and SameSite, and every one of those has a
// hand-rolled version somewhere that gets one of them wrong.
// reCompanionCookie matches cookie names that are ROUTING or INFRASTRUCTURE, not the session
// credential: CSRF/XSRF tokens (issued with the session, not the session itself), load-balancer and
// bot-management cookies. Classifying these as companion means refresh renews them FROM THE SAME LOGIN
// RESPONSE as the credential (refreshCompanionCookies) instead of demanding each its own auth flow,
// and they are not graded on their own by validation. The actual session credential (app_session,
// sid, JSESSIONID, a JWT cookie, ...) does not match and stays a credential.
var reCompanionCookie = regexp.MustCompile(`(?i)(csrf|xsrf|` + // anti-CSRF tokens
	`^cf_clearance$|^__cf_bm$|^__cflb$|^cf_ob_info$|^cf_use_ob$|^__cfwaitingroom$|` + // Cloudflare
	`^aws-?alb|^awsalbcors$|^awsalbtg|` + // AWS ALB
	`^bigipserver|^f5_|^lb-|` + // F5 / generic load balancer
	`^incap_ses_|^visid_incap_|^nlbi_|` + // Incapsula
	`^ak_bmsc$|^bm_sv$|^bm_mi$|^bm_sz$|^_abck$|` + // Akamai bot manager
	`^arraffinity|^gclb$|^route$|_affinity$)`) // Azure / GCP / generic affinity

// classifyCookieRole returns "companion" for a routing/infra/CSRF cookie, or "" (credential default)
// otherwise. The turnstile/challenge clearance cookies can never be minted by an app flow at all, so
// making them companions keeps them out of the per-token flow-refresh they can never satisfy.
func classifyCookieRole(name string) string {
	if reCompanionCookie.MatchString(strings.TrimSpace(name)) {
		return tokenRoleCompanion
	}
	return ""
}

func parseSetCookieTokens(value, fallbackHost string) []SessionToken {
	resp := &http.Response{Header: http.Header{"Set-Cookie": []string{value}}}

	var out []SessionToken
	for _, c := range resp.Cookies() {
		// A cookie with an empty value, or Max-Age below zero, is the server deleting the cookie.
		// Storing that as a credential gives the operator an active token that is a logout.
		if strings.TrimSpace(c.Value) == "" || c.MaxAge < 0 {
			continue
		}

		path := c.Path
		if path == "" {
			path = "/"
		}
		token := SessionToken{
			Name:           c.Name,
			TokenType:      tokenTypeCookie,
			TokenRole:      classifyCookieRole(c.Name),
			CookieName:     c.Name,
			TokenValue:     c.Value,
			CookiePath:     path,
			CookieDomain:   strings.ToLower(c.Domain),
			CookieSecure:   c.Secure,
			CookieHTTPOnly: c.HttpOnly,
			CookieSameSite: sameSiteName(c.SameSite),
			ExpiresAt:      cookieExpiry(c),
		}

		// Domain=.x.com means x.com and every subdomain, so the leading dot is dropped and the
		// consumer matches by suffix. No Domain at all means a host-only cookie, which scopes to
		// the host it was captured from and nowhere else.
		if domain := strings.TrimPrefix(token.CookieDomain, "."); domain != "" {
			token.ScopeDomains = []string{domain}
		} else if fallbackHost != "" {
			token.ScopeDomains = []string{fallbackHost}
		}

		out = append(out, token)
	}
	return out
}

// parseCookieHeaderTokens reads a "Cookie: a=1; b=2" value, or the same string with no label.
//
// No flags are set here, and that is not an omission. See ParseRawSessionTokens: the request-side
// wire format carries none, so there is nothing to read.
func parseCookieHeaderTokens(value, fallbackHost string) []SessionToken {
	req := &http.Request{Header: http.Header{"Cookie": []string{value}}}

	var out []SessionToken
	for _, c := range req.Cookies() {
		if strings.TrimSpace(c.Value) == "" {
			continue
		}
		token := SessionToken{
			Name:       c.Name,
			TokenType:  tokenTypeCookie,
			TokenRole:  classifyCookieRole(c.Name),
			CookieName: c.Name,
			TokenValue: c.Value,
			CookiePath: "/",
		}
		if fallbackHost != "" {
			token.ScopeDomains = []string{fallbackHost}
		}
		out = append(out, token)
	}
	return out
}

// parseAuthHeaderToken reads an Authorization or API key header line.
func parseAuthHeaderToken(rawName, value, fallbackHost string) (SessionToken, bool) {
	if strings.TrimSpace(value) == "" {
		return SessionToken{}, false
	}

	canonical := canonicalHeaderName(rawName)
	token := SessionToken{
		Name:       canonical,
		TokenType:  tokenTypeHeader,
		HeaderName: canonical,
		TokenValue: strings.TrimSpace(value),
	}
	if fallbackHost != "" {
		token.ScopeDomains = []string{fallbackHost}
	}

	if strings.EqualFold(canonical, "Authorization") {
		if scheme, rest, ok := strings.Cut(token.TokenValue, " "); ok &&
			strings.TrimSpace(rest) != "" && reAuthScheme.MatchString(scheme) {

			token.ValuePrefix = scheme + " "
			token.TokenValue = strings.TrimSpace(rest)
			if strings.EqualFold(scheme, "bearer") {
				// The prefix is stored normalised rather than as pasted. Most servers accept
				// "bearer " and the strict ones return 401 for it, which is a failure nobody would
				// ever trace back to the capitalisation of a word in a paste box.
				token.TokenType = tokenTypeBearer
				token.ValuePrefix = "Bearer "
			}
		}
		return token, true
	}

	lower := strings.ToLower(canonical)
	if strings.Contains(lower, "api-key") || strings.Contains(lower, "apikey") {
		token.TokenType = tokenTypeAPIKey
	}
	return token, true
}

// ParseSessionTokens handles POST /session-tokens/target/{scope_target_id}/parse.
func ParseSessionTokens(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Raw        string `json:"raw"`
		AuthFlowID string `json:"auth_flow_id"`
		Name       string `json:"name"`
		Activate   *bool  `json:"activate"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Raw) == "" {
		http.Error(w, "raw is required", http.StatusBadRequest)
		return
	}
	parsed := ParseRawSessionTokens(payload.Raw, scopeTargetHost(scopeTargetID))
	if len(parsed) == 0 {
		http.Error(w, "Nothing in that paste looked like a cookie, a Cookie header or an "+
			"Authorization header.", http.StatusBadRequest)
		return
	}

	// Pasting a credential is an act of intent: the operator wants it used. Activating by default
	// is safe here only because activation is additive, so this cannot switch anything else off.
	activate := payload.Activate == nil || *payload.Activate
	explicitName := strings.TrimSpace(payload.Name)

	tokens := []SessionToken{}
	for i := range parsed {
		token := parsed[i]
		token.ScopeTargetID = scopeTargetID
		token.AuthFlowID = strings.TrimSpace(payload.AuthFlowID)
		token.IsActive = activate

		if explicitName != "" {
			// One name cannot label six cookies, so it becomes a prefix when the paste carried
			// more than one credential.
			if len(parsed) == 1 {
				token.Name = explicitName
			} else {
				token.Name = fmt.Sprintf("%s (%s)", explicitName, token.Name)
			}
		}
		if err := normalizeSessionTokenWiring(&token); err != nil {
			log.Printf("[SESSION-TOKEN] Skipping unparseable token %q: %v", token.Name, err)
			continue
		}

		stored, err := upsertParsedSessionToken(token, explicitName != "")
		if err != nil {
			log.Printf("[SESSION-TOKEN] Failed to store parsed token %q: %v", token.Name, err)
			continue
		}
		tokens = append(tokens, stored)
	}

	if len(tokens) == 0 {
		http.Error(w, "Failed to store any of the parsed tokens", http.StatusInternalServerError)
		return
	}

	// The same projection the list uses.
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"tokens": sessionTokenViews(tokens)})
}

// cookieHeaderFromCaptureHeaders pulls the request-side Cookie header out of a stored capture's
// headers blob, case-insensitively.
func cookieHeaderFromCaptureHeaders(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]interface{}
	if json.Unmarshal(raw, &m) != nil {
		return ""
	}
	for k, v := range m {
		if strings.EqualFold(strings.TrimSpace(k), "cookie") {
			if s, ok := v.(string); ok {
				return s
			}
		}
	}
	return ""
}

// sessionHostMatches reports whether a captured request's host belongs to the token's host (exact or a
// sub/parent domain), so a recapture only reads cookies the session was actually sent to.
func sessionHostMatches(captureHost, tokenHost string) bool {
	captureHost = strings.ToLower(strings.TrimSpace(captureHost))
	tokenHost = strings.ToLower(strings.TrimSpace(tokenHost))
	if captureHost == "" || tokenHost == "" {
		return false
	}
	return captureHost == tokenHost ||
		strings.HasSuffix(captureHost, "."+tokenHost) ||
		strings.HasSuffix(tokenHost, "."+captureHost)
}

// freshestCapturedCookieHeader finds the most recent Cookie request header the crawl captured for a
// host, optionally only after `since`. This is what browser re-capture reads: the operator logs in in
// their real browser (past Cloudflare, past the OAuth/IdP interactive steps) with the extension
// recording, and the fresh session rides in the Cookie header of the requests it captured.
func freshestCapturedCookieHeader(scopeTargetID, host, since string) (string, error) {
	query := `SELECT COALESCE(url,''), headers FROM manual_crawl_captures
	          WHERE scope_target_id = $1 AND headers IS NOT NULL AND headers::text ILIKE '%cookie%'`
	args := []interface{}{scopeTargetID}
	if s := strings.TrimSpace(since); s != "" {
		// Fail CLOSED on a malformed since. The whole point of this filter is to reject a capture older
		// than the moment the operator opened the panel, so if the timestamp cannot be parsed we must
		// refuse, not silently drop the clause and hand back the newest capture of any age (which would
		// re-store a dead session and report it as a fresh recapture). The browser always sends
		// toISOString (RFC3339); a caller such as the MCP recapture action must do the same.
		ts, perr := time.Parse(time.RFC3339, s)
		if perr != nil {
			ts, perr = time.Parse(time.RFC3339Nano, s)
		}
		if perr != nil {
			return "", fmt.Errorf("since must be an RFC3339 timestamp (e.g. 2026-09-28T09:00:00Z), got %q", s)
		}
		query += ` AND timestamp > $2`
		args = append(args, ts)
	}
	query += ` ORDER BY timestamp DESC LIMIT 500`

	rows, err := dbPool.Query(context.Background(), query, args...)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var url string
		var headers []byte
		if rows.Scan(&url, &headers) != nil {
			continue
		}
		if !sessionHostMatches(flowURLHost(url), host) {
			continue
		}
		if ck := cookieHeaderFromCaptureHeaders(headers); strings.TrimSpace(ck) != "" {
			return ck, nil
		}
	}
	return "", rows.Err()
}

// RecaptureSessionToken handles POST /session-tokens/{id}/refresh-recapture. It refreshes a session
// from the live browser instead of by replaying a flow: it reads the freshest Cookie header the crawl
// captured for the token's host and upserts every value in it (the credential and its companions -
// app_session, CSRF, cf_clearance - all at once). This is the working refresh for an OAuth / federated
// / Cloudflare session, which no headless replay can renew.
func RecaptureSessionToken(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)
	token, err := loadSessionToken(tokenID)
	if err != nil {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

	var payload struct {
		Since string `json:"since"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&payload) // optional body
	}

	// Reject a malformed since here, with a clear 400, rather than letting it fall through to the read
	// (which fails closed, but as a 500). An empty since means "no lower bound" and is fine.
	if s := strings.TrimSpace(payload.Since); s != "" {
		if _, e1 := time.Parse(time.RFC3339, s); e1 != nil {
			if _, e2 := time.Parse(time.RFC3339Nano, s); e2 != nil {
				http.Error(w, "since must be an RFC3339 timestamp (e.g. 2026-09-28T09:00:00Z)", http.StatusBadRequest)
				return
			}
		}
	}

	host := ""
	if len(token.ScopeDomains) > 0 {
		host = token.ScopeDomains[0]
	}
	if host == "" {
		_, host, _ = ScopeTargetBase(token.ScopeTargetID)
	}
	if host == "" {
		http.Error(w, "Could not determine this token's host", http.StatusBadRequest)
		return
	}

	cookieHeader, err := freshestCapturedCookieHeader(token.ScopeTargetID, host, payload.Since)
	if err != nil {
		log.Printf("[SESSION-TOKEN] recapture read failed for %s: %v", tokenID, err)
		http.Error(w, "Could not read captured requests", http.StatusInternalServerError)
		return
	}
	if strings.TrimSpace(cookieHeader) == "" {
		detail := fmt.Sprintf("No captured request carrying a Cookie for %s was found%s. Log in in your "+
			"browser with the extension recording (Manual Crawling, or Record Auth Flows), then re-capture.",
			host, sinceSuffix(payload.Since))
		recordSessionTokenEvent(tokenID, "refresh", "no_capture", detail, nil)
		writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
			"status": "no_capture", "detail": detail, "new_value_set": false,
		})
		return
	}

	// A logged-in browser's Cookie header carries the whole jar: the session credential and the routing
	// / CSRF companions it needs, but also analytics, consent and ad-tracking cookies. Re-capture must
	// REFRESH THE SESSION THIS TARGET ALREADY MANAGES, not promote every incidental cookie to a managed
	// credential. So a parsed cookie is upserted only when it is already tracked for this target, or when
	// it classifies as a companion (a routing / CSRF / challenge cookie the session genuinely needs).
	// Everything else is skipped; it is still in the capture if it is ever wanted.
	tracked := map[string]bool{}
	if trows, terr := dbPool.Query(context.Background(),
		`SELECT DISTINCT lower(COALESCE(cookie_name,'')) FROM session_tokens
		 WHERE scope_target_id = $1 AND token_type = $2 AND COALESCE(cookie_name,'') <> ''`,
		token.ScopeTargetID, tokenTypeCookie); terr == nil {
		for trows.Next() {
			var n string
			if trows.Scan(&n) == nil && n != "" {
				tracked[n] = true
			}
		}
		trows.Close()
	}

	parsed := ParseRawSessionTokens("Cookie: "+cookieHeader, host)
	updated := []SessionToken{}
	skipped := 0
	for i := range parsed {
		t := parsed[i]
		if !recaptureShouldRefreshCookie(t.CookieName, tracked) {
			skipped++
			continue
		}
		t.ScopeTargetID = token.ScopeTargetID
		t.IsActive = true
		if err := normalizeSessionTokenWiring(&t); err != nil {
			continue
		}
		stored, err := upsertParsedSessionToken(t, false)
		if err != nil {
			log.Printf("[SESSION-TOKEN] recapture upsert failed for %q: %v", t.Name, err)
			continue
		}
		updated = append(updated, stored)
	}
	if len(updated) == 0 {
		http.Error(w, "The captured Cookie header held no tracked session cookie or companion to refresh. "+
			"If this is a new session, store its cookies once (paste, or Manage Sessions) so re-capture "+
			"knows which ones to refresh.", http.StatusUnprocessableEntity)
		return
	}

	skippedNote := ""
	if skipped > 0 {
		skippedNote = fmt.Sprintf(" %d other cookie(s) in the jar (analytics / consent / tracking) were "+
			"left alone.", skipped)
	}
	detail := fmt.Sprintf("Re-captured %d value(s) from the browser session on %s, credential and "+
		"companions together.%s", len(updated), host, skippedNote)
	recordSessionTokenEvent(tokenID, "refresh", "recaptured", detail, nil)
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
		"status": "recaptured", "detail": detail, "new_value_set": true,
		"updated": len(updated), "tokens": sessionTokenViews(updated),
	})
}

// recaptureShouldRefreshCookie decides whether a cookie from the browser jar is one re-capture should
// upsert: only if this target already tracks it (by lower-cased cookie name) or it classifies as a
// companion (routing / CSRF / challenge). Analytics, consent and ad-tracking cookies are neither, so
// they are left out rather than promoted to managed credentials.
func recaptureShouldRefreshCookie(cookieName string, tracked map[string]bool) bool {
	if tracked[strings.ToLower(strings.TrimSpace(cookieName))] {
		return true
	}
	return classifyCookieRole(cookieName) == tokenRoleCompanion
}

func sinceSuffix(since string) string {
	if strings.TrimSpace(since) == "" {
		return ""
	}
	return " after you started this re-capture"
}

// upsertParsedSessionToken writes one parsed token, updating the row with the same identity on this
// target rather than adding a second one.
//
// Re-pasting is the normal case, not the edge case: the operator's session expires, they log in
// again, copy the fresh Cookie header and paste it. Inserting a new row every time leaves the dead
// value still marked active alongside the new one, both get sent, and the scan behaves as though
// the paste never happened.
func upsertParsedSessionToken(token SessionToken, overwriteName bool) (SessionToken, error) {
	ctx := context.Background()

	var existingID, existingFlowID string
	err := dbPool.QueryRow(ctx, `
		SELECT id::text, COALESCE(auth_flow_id::text,'')
		FROM session_tokens
		WHERE scope_target_id = $1 AND token_type = $2
		  AND COALESCE(cookie_name,'') = $3
		  AND COALESCE(header_name,'') = $4
		  AND COALESCE(param_name,'') = $5
		ORDER BY created_at ASC
		LIMIT 1`,
		token.ScopeTargetID, token.TokenType, token.CookieName, token.HeaderName,
		token.ParamName).Scan(&existingID, &existingFlowID)

	if err != nil || existingID == "" {
		id, insertErr := insertSessionToken(token)
		if insertErr != nil {
			return SessionToken{}, insertErr
		}
		recordSessionTokenEvent(id, "parsed", "created",
			fmt.Sprintf("Parsed from a raw paste as a %s token.", token.TokenType), nil)
		ReprofileSessionToken(ctx, id)
		return loadSessionToken(id)
	}

	// A paste that did not name a flow must not unlink the one already attached: the link is what
	// makes the token refreshable, and losing it is only noticed when refresh stops working.
	flowID := token.AuthFlowID
	if flowID == "" {
		flowID = existingFlowID
	}

	nameExpr := token.Name
	if !overwriteName {
		nameExpr = ""
	}

	// The verdict on file describes the value being replaced, so it is cleared rather than left to
	// render an "expired" badge over a credential that was pasted five seconds ago.
	if _, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET
		  token_value = $1, value_prefix = $2, scope_domains = $3, cookie_path = $4,
		  cookie_domain = $5, cookie_secure = $6, cookie_httponly = $7, cookie_samesite = $8,
		  expires_at = $9, auth_flow_id = $10,
		  name = CASE WHEN $11 = '' THEN name ELSE $11 END,
		  is_active = is_active OR $12,
		  last_validation_status = '', last_validation_detail = '', updated_at = NOW()
		WHERE id = $13`,
		token.TokenValue, token.ValuePrefix, token.ScopeDomains, token.CookiePath,
		token.CookieDomain, token.CookieSecure, token.CookieHTTPOnly, token.CookieSameSite,
		// Same derivation as the insert path. Writing the raw value here set expires_at back to NULL
		// whenever a bearer JWT was re-pasted, and a NULL expiry reads as "never expires" everywhere
		// downstream, which is how a dead token kept passing every check.
		DeriveSessionTokenExpiry(token.TokenValue, token.ExpiresAt),
		nullUUID(flowID), nameExpr, token.IsActive, existingID); err != nil {
		return SessionToken{}, err
	}

	recordSessionTokenEvent(existingID, "parsed", "updated",
		"A fresh value was pasted for this token, replacing the stored one.", nil)
	// A pasted value is a DIFFERENT credential, so the stored characterisation describes something
	// that is no longer here. Re-measure before anybody reads it.
	ReprofileSessionToken(ctx, existingID)
	return loadSessionToken(existingID)
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

// ValidateSessionToken handles POST /session-tokens/{id}/validate.
func ValidateSessionToken(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)

	token, err := loadSessionToken(tokenID)
	if err != nil {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

	status, detail, evidence := runSessionTokenValidation(token)

	if _, err := dbPool.Exec(context.Background(), `
		UPDATE session_tokens
		SET last_validated_at = NOW(), last_validation_status = $1, last_validation_detail = $2,
		    updated_at = NOW()
		WHERE id = $3`, status, detail, tokenID); err != nil {
		log.Printf("[SESSION-TOKEN] Failed to persist validation for %s: %v", tokenID, err)
	}
	recordSessionTokenEvent(tokenID, "validate", status, detail, evidence)

	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
		"status": status, "detail": detail, "evidence": evidence,
	})
}

// runSessionTokenValidation sends the token at the scope target's base URL, sends the same request
// with nothing attached, and compares the two.
//
// The comparison is the whole method. An authenticated 200 proves nothing on its own: a public home
// page returns 200 to anybody. What distinguishes a working credential is that the target answered
// differently because of it. Identical answers both ways is the finding, and it is the one an
// operator most needs before they start a scan.
func runSessionTokenValidation(token SessionToken) (string, string, map[string]interface{}) {
	evidence := map[string]interface{}{"token_type": token.TokenType}

	if strings.TrimSpace(token.TokenValue) == "" {
		return tokenStatusError,
			"No value is stored for this token, so there was nothing to send.", evidence
	}

	// A companion is not a credential, so the honoured/not-honoured comparison cannot say anything
	// about it: sending a load balancer affinity cookie on its own changes no response, and grading
	// it against a control would report not_honoured forever for a value that is doing its job.
	// It is checked by being attached to every other token's validation on this target instead.
	if token.TokenRole == tokenRoleCompanion {
		evidence["role"] = tokenRoleCompanion
		return tokenStatusCompanion,
			"This is a companion value, not a credential, so it is not graded on its own. It is " +
				"sent alongside every credential validated on this target, and on the control arm " +
				"too, so the comparison isolates the credential.", evidence
	}

	// A refresh secret is spent to mint a fresh credential; it is never sent on a resource request, so
	// the honoured/not-honoured comparison says nothing about it. It is graded by whether it still
	// mints (the refresh run, RecordRefreshProof), not here.
	if token.TokenRole == tokenRoleRefresh {
		evidence["role"] = tokenRoleRefresh
		return tokenStatusRefresh,
			"This is a refresh secret, not a resource credential, so it is not graded on its own. It " +
				"is spent to mint a fresh credential; its health is whether a refresh run still " +
				"succeeds with it, not an honoured/not-honoured check.", evidence
	}

	_, host, base := ScopeTargetBase(token.ScopeTargetID)
	if host == "" || base == "" {
		return tokenStatusError,
			"Could not work out this scope target's base URL, so there was nowhere to send the " +
				"request.", evidence
	}
	// Probe the flow's own last step, not the home page.
	//
	// The base URL is the wrong place to ask "is this session alive". On a target whose root is a
	// static landing page it answers identically signed in or out, so a perfectly good token
	// measures as not_honoured; on a target whose root is a 404 it does the same thing for a
	// different reason. Both were observed on the first real run of this code.
	//
	// The auth flow already contains a better probe. Its final step is, by construction, a request
	// that only succeeds once the flow has authenticated: the page the login redirects to, or the
	// API call the token was minted for. Replaying that URL asks the question directly.
	target := base + "/"
	probeSource := "base_url"
	if flowProbe := authFlowProbeURL(token.AuthFlowID); flowProbe != "" {
		target = flowProbe
		probeSource = "auth_flow_last_step"
	} else if epProbe := authRequiredProbeURL(token.ScopeTargetID, host); epProbe != "" {
		// Better than the base URL by construction: validation already established that this exact
		// URL answers 401 or 403 without credentials, so the two arms cannot come back identical
		// for a reason unrelated to the session. The base URL fallback below is the one that
		// produced false not_honoured verdicts on every static CDN and SPA shell.
		target = epProbe
		probeSource = "validated_auth_required_endpoint"
	}
	evidence["probe_url"] = target
	evidence["probe_source"] = probeSource
	evidence["base_url"] = base + "/"

	// The clock says this expired. Recorded, not acted on: servers routinely keep honouring a value
	// past the expiry the browser would have used to drop it, and a stored date is a claim while the
	// request is a measurement. Short-circuiting here would report "expired" for a token that works.
	if token.ExpiresAt != nil && token.ExpiresAt.Before(time.Now()) {
		evidence["expired_by_clock"] = true
	}

	budget := NewHostBudget()
	rps, concurrency := LoadProbeContext(token.ScopeTargetID).EffectiveRate()
	budget.Acquire(host, rps, concurrency, "session_token_validate")

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Through ScanClient so the verb allowlist and the host rate budget apply here too, and with no
	// cookie jar, which is the part that is easy to get wrong. A shared jar would carry whatever the
	// authenticated request received into the control request, the control would stop being
	// anonymous, and every token on every target would come back looking honoured.
	//
	// SCOPED, and the comment that used to sit here was false. It said "the only URL this ever
	// requests is the scope target's own base URL, which it builds itself, so there is nothing for
	// a host boundary to protect against". It does not build it: authFlowProbeURL and
	// authRequiredProbeURL read a URL out of the CORPUS with no host filter, and the corpus holds
	// every host the crawls ever saw.
	//
	// MEASURED on the engaged target: 5 distinct auth-required hosts, and the ORDER BY url LIMIT 1
	// picks api-wallet-alpacax.staging-v2.tradetalk.us, which is explicitly OUT OF SCOPE on that
	// programme. Each validation sends two requests, the authenticated arm and the control, so
	// every session health check was two requests at a host the operator never authorised.
	//
	// It became urgent when the reflection probe started calling SessionStillHonoured every 50
	// probes: a 1911 probe run is 38 checks, so one run could put 76 unscoped requests on an
	// excluded host. The boundary belongs here rather than at the call sites, which is the same
	// lesson ScanClient.Do's own header records about this having leaked twice before.
	client := NewScanClient(budget, 20*time.Second, "", nil).
		WithScope(LoadScanScope(token.ScopeTargetID))

	// Companions go on BOTH arms, which is the whole point of separating them from credentials.
	//
	// A routing cookie is not a credential, so including it in the control keeps the two arms
	// differing by exactly one thing: the credential. Leaving it off the control would let backend
	// affinity vary between the arms and produce a difference that has nothing to do with the
	// session, which is a false "active" verdict. Leaving it off the authenticated arm is what
	// produced the false not_honoured that this whole mechanism exists to stop.
	companions, companionNames := loadCompanionMaterial(token.ScopeTargetID, host, token.ID)
	if len(companionNames) > 0 {
		evidence["companion_cookies"] = companionNames
	}

	authed := client.Do(ctx, ScanRequest{
		URL:      token.ApplyToURL(target),
		Method:   http.MethodGet,
		Auth:     withCompanions(token.AuthMaterial(host), companions, host),
		ReadBody: true,
	})
	anon := client.Do(ctx, ScanRequest{
		URL:      target,
		Method:   http.MethodGet,
		Auth:     companions,
		ReadBody: true,
	})

	if authed.Err != nil {
		return tokenStatusError,
			"The authenticated request did not complete: " + truncateReason(authed.Err.Error()),
			evidence
	}
	if anon.Err != nil {
		return tokenStatusError,
			"The unauthenticated control request did not complete, so there was nothing to compare " +
				"against: " + truncateReason(anon.Err.Error()), evidence
	}

	authedFP := BuildFingerprint(authed)
	anonFP := BuildFingerprint(anon)
	evidence["authenticated"] = map[string]interface{}{
		"status": authed.Status, "bytes": authed.BodyBytes, "location": authed.Location,
		"fingerprint": FingerprintSummary(authedFP),
	}
	evidence["anonymous"] = map[string]interface{}{
		"status": anon.Status, "bytes": anon.BodyBytes, "location": anon.Location,
		"fingerprint": FingerprintSummary(anonFP),
	}
	evidence["credential_attached"] = authed.AuthApplied || token.QueryParam() != ""

	// A challenge page means a WAF answered and the application was never reached, so nothing in
	// this measurement describes the token. This is NOT a dead session, and saying "refresh it" sends
	// the operator down a path that cannot work: on an edge like Cloudflare the challenge is bound to
	// the browser's IP and TLS fingerprint, so no captured session an automated client replays will
	// ever get past it. tokenStatusError so SessionStillHonoured proceeds rather than killing the run.
	if IsChallengeBody(authed.Body) {
		evidence["edge_blocked"] = true
		return tokenStatusError,
			"A WAF or bot manager answered instead of the application, so this says nothing about the " +
				"token. This target blocks automated clients at the edge; refreshing the session will " +
				"not help (the challenge is bound to the browser's IP and TLS fingerprint). Drive it in " +
				"a browser (domdig / the extension) instead.", evidence
	}

	// Grade by COMPARING the two arms, never by the authenticated arm's status alone. The old code
	// short-circuited to "expired" the moment the authenticated request was 401/403, without checking
	// whether the anonymous control was refused the same way. That is the IDOR-protected-object trap:
	// authRequiredProbeURL picks a route endpoint validation saw refuse an anonymous caller, but an
	// object route like /api/carts.v2/{id} or /api/notificationPreferences.v2/{id} refuses the
	// authenticated owner of a DIFFERENT account too, for ownership rather than authentication. A
	// session proven live by a 200 on the owner's own object still read "expired" from such a probe.
	authedRefused := authed.Status == 401 || authed.Status == 403 ||
		(authed.IsRedirect() && LooksLikeAuthRedirect(authed.Location))
	anonRefused := anon.Status == 401 || anon.Status == 403 ||
		(anon.IsRedirect() && LooksLikeAuthRedirect(anon.Location))

	// Both arms refused equivalently: the probe refuses everyone, so it says nothing about the
	// session. Inconclusive (tokenStatusError, which SessionStillHonoured proceeds past), credential
	// stays attached, the scan runs and reports what the target actually does.
	if authedRefused && anonRefused && ResponsesEquivalent(authedFP, anonFP) {
		return tokenStatusError, fmt.Sprintf(
			"Could not confirm the session from here: %s refused BOTH the authenticated request and the "+
				"anonymous control the same way (%s both ways). An endpoint that refuses everyone - an "+
				"object owned by another account, or a route behind a second gate - cannot tell a live "+
				"session from a dead one, so this is inconclusive rather than dead. The credential is "+
				"still attached and the scan will proceed.", target, FingerprintSummary(authedFP)), evidence
	}

	// Authed refused while the anonymous control was NOT refused the same way: the refusal is specific
	// to the credentialed arm, which is real evidence the stored value was rejected.
	if authedRefused {
		if authed.IsRedirect() {
			return tokenStatusExpired, fmt.Sprintf(
				"The authenticated request was redirected to %s, which is this target sending an "+
					"unauthenticated caller to log in (the anonymous control was not: %s).",
				authed.Location, FingerprintSummary(anonFP)), evidence
		}
		return tokenStatusExpired, fmt.Sprintf(
			"The target answered %d to the authenticated request while the anonymous control got %s, so "+
				"the refusal is specific to the credential: the stored value is expired or wrong.",
			authed.Status, FingerprintSummary(anonFP)), evidence
	}

	if ResponsesEquivalent(authedFP, anonFP) {
		// The two arms matched and neither was refused. Against the base URL that is expected even for a
		// live token (a static landing page or SPA shell answers identically signed in or out), so it is
		// inconclusive rather than dead. Against a discriminating probe a match is real evidence the
		// credential is not honoured. Return inconclusive for base_url (tokenStatusError, which
		// SessionStillHonoured proceeds past) so the credential is still attached and the scan runs.
		if probeSource == "base_url" {
			return tokenStatusError, fmt.Sprintf(
				"Could not confirm the session from here: the only probe available was the base URL, "+
					"which answered the same way with the token as without it (%s both ways). On a "+
					"static landing page or an SPA shell that is expected even for a live token, so "+
					"this is inconclusive rather than dead. The credential is still attached and the "+
					"scan will proceed; run a validation scan to record a route that refuses anonymous "+
					"callers and the next check can settle it.",
				FingerprintSummary(authedFP)), evidence
		}
		return tokenStatusNotHonoured, fmt.Sprintf(
			"%s answered the same way with the token as without it (%s both ways), and that endpoint "+
				"refuses anonymous callers, so the credential is not being honoured.",
			target, FingerprintSummary(authedFP)), evidence
	}

	return tokenStatusActive, fmt.Sprintf(
		"The target answered differently with the token (%s) than without it (%s), so it is being "+
			"honoured.", FingerprintSummary(authedFP), FingerprintSummary(anonFP)), evidence
}

// ---------------------------------------------------------------------------
// Refresh
// ---------------------------------------------------------------------------

// RefreshSessionToken handles POST /session-tokens/{id}/refresh.
func RefreshSessionToken(w http.ResponseWriter, r *http.Request) {
	tokenID := sessionTokenIDFrom(r)

	token, err := loadSessionToken(tokenID)
	if err != nil {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

	// A link to a flow is the entire refresh mechanism. The REFRESH flow (headless) is preferred, the
	// CREATION flow (auth_flow) is the fallback; with neither there is nothing to replay, and saying so
	// plainly beats a generic failure that leaves the operator poking at the button.
	if token.RefreshFlowID == "" && token.AuthFlowID == "" {
		detail := "This token is not tied to an auth flow, so there is no way to produce another " +
			"one. Link it to the login flow that issues it, then refresh. For a session with no " +
			"replayable flow (an OAuth or federated login), refresh it by pasting a fresh value."
		recordSessionTokenEvent(tokenID, "refresh", "no_flow", detail, nil)
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status": "no_flow", "detail": detail, "new_value_set": false,
		})
		return
	}

	// Refresh runs through the interactive, resumable runner (sessionRefreshInteractive.go). A flow the
	// framework can drive on its own completes in one shot and returns the classic
	// {status, detail, new_value_set}; a flow with a step that needs the operator (an MFA/OTP code)
	// pauses and returns status "needs_input" with a run_id, which is answered at
	// POST /session-refresh-runs/{run_id}/input.
	run, err := startSessionRefreshRun(token)
	if err != nil {
		http.Error(w, "Failed to start the refresh: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, refreshRunResponse(run))
}

// refreshCompanionCookies updates the active companion cookies on a target from the Set-Cookie
// headers one flow replay produced, and returns the names it actually updated.
//
// Values are matched by cookie name, so a companion whose name the flow never issued is left
// alone rather than blanked.
func refreshCompanionCookies(scopeTargetID, excludeTokenID string, setCookies []string) []string {
	if len(setCookies) == 0 {
		return nil
	}

	type companion struct{ id, name string }
	companions := []companion{}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, COALESCE(cookie_name,'')
		FROM session_tokens
		WHERE scope_target_id = $1
		  AND COALESCE(token_role,'credential') = 'companion'
		  AND COALESCE(is_active,false)
		  AND token_type = 'cookie'
		  AND id <> $2::uuid`, scopeTargetID, excludeTokenID)
	if err != nil {
		return nil
	}
	for rows.Next() {
		var c companion
		if rows.Scan(&c.id, &c.name) == nil && strings.TrimSpace(c.name) != "" {
			companions = append(companions, c)
		}
	}
	// Closed before any write, rather than updating inside the iteration: holding the read open
	// while writing on the same pool is how a deadlock gets written by accident.
	rows.Close()

	updated := []string{}
	for _, c := range companions {
		value, expires := cookieValueFromSetCookies(setCookies, c.name)
		if value == "" {
			continue
		}
		if _, err := dbPool.Exec(context.Background(), `
			UPDATE session_tokens
			SET token_value = $1, expires_at = $2, last_refreshed_at = NOW(), updated_at = NOW()
			WHERE id = $3`, value, expires, c.id); err != nil {
			log.Printf("[SESSION-TOKEN] Failed to refresh companion %s: %v", c.id, err)
			continue
		}
		updated = append(updated, c.name)
	}
	return updated
}

// replayFlowForToken runs the linked auth flow and pulls a new value out of the result.
//
// The replay is the engine in authFlowsUtils.go, called step by step exactly as ReplayAuthFlow does
// it: one shared cookie jar so a session set on step one is sent on step two, and each response
// written back onto its step so the operator can open the flow afterwards and see what happened. A
// second implementation of that loop would drift from the one the Auth Flows tab exercises, and the
// refresh path would quietly stop matching the flow the operator tested by hand.
// The Set-Cookie lines the replay produced are written to issuedCookies when it is non-nil, so the
// caller can refresh companion values out of the same login response that issued the credential.
func replayFlowForToken(token SessionToken, issuedCookies *[]string) (string, *time.Time, map[string]interface{}, error) {
	evidence := map[string]interface{}{"auth_flow_id": token.AuthFlowID}

	baseURL, err := getFlowBaseURL(token.AuthFlowID)
	if err != nil {
		return "", nil, evidence, fmt.Errorf("the linked auth flow no longer exists")
	}
	steps, err := getStepsByFlow(token.AuthFlowID)
	if err != nil {
		return "", nil, evidence, fmt.Errorf("could not read the flow's steps: %w", err)
	}
	if len(steps) == 0 {
		return "", nil, evidence, fmt.Errorf("the linked auth flow has no steps to replay")
	}

	jar, _ := cookiejar.New(nil)
	var setCookies []string
	var bodies []string
	failed := 0

	// The same variable map the interactive replay uses. Without it a token whose login carries a
	// per-request CSRF token could never be reissued: every refresh would re-send a stale token and
	// be refused, and the operator would see a flow that works by hand and not on a refresh.
	vars := map[string]string{}

	for _, step := range steps {
		request, _, refusal := prepareStepRequest(step.RawRequest, vars)
		if refusal != "" {
			failed++
			if uErr := updateStepResponse(step.ID, 0, nil, "", 0, refusal); uErr != nil {
				log.Printf("[SESSION-TOKEN] Failed to persist refusal of step %s: %v", step.ID, uErr)
			}
			// Named on the token's own event, so the reason is "step N needs a value nothing
			// captured" rather than the far less useful "every step failed to send".
			evidence["refused_step"] = step.StepOrder
			evidence["refused_reason"] = refusal
			continue
		}

		effBase := resolveBaseURL(request, baseURL)
		status, headers, body, ms, sendErr := sendRawRequest(request, effBase, jar)

		errStr := ""
		if sendErr != nil {
			errStr = sendErr.Error()
			failed++
		}
		if uErr := updateStepResponse(step.ID, status, headers, body, ms, errStr); uErr != nil {
			log.Printf("[SESSION-TOKEN] Failed to persist replay of step %s: %v", step.ID, uErr)
		}
		if sendErr != nil {
			continue
		}

		captured, _ := runAuthFlowExtractions(step.Extractions, headers, body)
		for name, value := range captured {
			vars[name] = value
		}

		// Set-Cookie is read off the raw response headers rather than out of the jar. The jar drops
		// anything whose Domain does not match the URL it was set from, which is precisely what
		// happens when a flow authenticates against an SSO host and hands the session back, and that
		// cookie is usually the one being refreshed.
		setCookies = append(setCookies, http.Header(headers).Values("Set-Cookie")...)
		if strings.TrimSpace(body) != "" {
			bodies = append(bodies, body)
		}
	}

	if issuedCookies != nil {
		*issuedCookies = setCookies
	}

	evidence["steps_replayed"] = len(steps)
	evidence["steps_failed"] = failed
	if failed == len(steps) {
		return "", nil, evidence, fmt.Errorf("every step of the flow failed to send")
	}

	value, expires, source := extractRefreshedTokenValue(token, setCookies, bodies)
	if source != "" {
		evidence["source"] = source
	}
	return value, expires, evidence, nil
}

// extractRefreshedTokenValue pulls the fresh value for a token out of the Set-Cookie headers and the
// response bodies one flow replay produced. Returns "" when nothing matched; source names where the
// value was found, for the evidence. Shared by the one-shot refresh (replayFlowForToken) and the
// resumable interactive runner (sessionRefreshInteractive.go) so the two cannot disagree.
//
// Cookies first for a cookie token and the body first for everything else, because that is where each
// one is issued. The last occurrence wins in both: a flow that logs in and then rotates the session on
// an MFA step issues the value twice, and the first is already dead by the time the flow finishes.
func extractRefreshedTokenValue(token SessionToken, setCookies, bodies []string) (string, *time.Time, string) {
	if token.TokenType == tokenTypeCookie {
		if value, expires := cookieValueFromSetCookies(setCookies, token.CookieName); value != "" {
			return value, expires, "the Set-Cookie header of the replayed flow"
		}
		if value := tokenValueFromBodies(bodies, sessionTokenBodyKeys(token)); value != "" {
			return value, nil, "a response body of the replayed flow"
		}
		return "", nil, ""
	}

	if value := tokenValueFromBodies(bodies, sessionTokenBodyKeys(token)); value != "" {
		return value, nil, "a response body of the replayed flow"
	}
	// A bearer token is occasionally handed back as a cookie the front end then reads and promotes
	// to an Authorization header, so the cookies are still worth a look.
	for _, name := range []string{token.ParamName, token.HeaderName, token.Name} {
		if name == "" {
			continue
		}
		if value, expires := cookieValueFromSetCookies(setCookies, name); value != "" {
			return value, expires, "the Set-Cookie header of the replayed flow"
		}
	}
	return "", nil, ""
}

// cookieValueFromSetCookies finds the last value issued for one cookie name across a whole replay.
func cookieValueFromSetCookies(setCookies []string, name string) (string, *time.Time) {
	if name == "" || len(setCookies) == 0 {
		return "", nil
	}
	resp := &http.Response{Header: http.Header{"Set-Cookie": setCookies}}

	var value string
	var expires *time.Time
	for _, c := range resp.Cookies() {
		if !strings.EqualFold(c.Name, name) || strings.TrimSpace(c.Value) == "" || c.MaxAge < 0 {
			continue
		}
		value = c.Value
		expires = cookieExpiry(c)
	}
	return value, expires
}

// sessionTokenBodyKeys is the search order for pulling a value out of a JSON response: whatever this
// token is called on the wire first, then the names every auth API in the world uses.
func sessionTokenBodyKeys(token SessionToken) []string {
	var keys []string
	for _, name := range []string{token.CookieName, token.ParamName, token.HeaderName, token.Name} {
		if name != "" {
			keys = append(keys, name)
		}
	}
	return append(keys, "access_token", "accessToken", "id_token", "idToken", "token", "jwt",
		"auth_token", "authToken", "session_token", "sessionToken", "session_id", "sessionId",
		"api_key", "apiKey", "csrf_token", "csrfToken")
}

// reBareJWT matches a response body that is nothing but a JWT, which a surprising number of token
// endpoints return with a text/plain content type.
var reBareJWT = regexp.MustCompile(`^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+$`)

// tokenValueFromBodies searches the replay's response bodies, newest first, for a credential.
func tokenValueFromBodies(bodies []string, keys []string) string {
	for i := len(bodies) - 1; i >= 0; i-- {
		body := strings.TrimSpace(bodies[i])
		if body == "" {
			continue
		}
		if reBareJWT.MatchString(body) {
			return body
		}

		var parsed interface{}
		if json.Unmarshal([]byte(body), &parsed) != nil {
			continue
		}
		found := map[string]string{}
		collectJSONStrings(parsed, found, 0)
		for _, key := range keys {
			if value, ok := found[normalizeTokenKey(key)]; ok {
				return value
			}
		}
	}
	return ""
}

// collectJSONStrings flattens a decoded body into normalised key to value, shallowest wins.
//
// Values shorter than eight characters and values containing whitespace are dropped: a credential
// is neither, and "ok" sitting under a key called "token" would otherwise be written back over a
// working session.
func collectJSONStrings(v interface{}, out map[string]string, depth int) {
	if depth > 8 || len(out) > 400 {
		return
	}
	switch t := v.(type) {
	case map[string]interface{}:
		for key, val := range t {
			if s, ok := val.(string); ok {
				normalized := normalizeTokenKey(key)
				if _, seen := out[normalized]; !seen && len(s) >= 8 && len(s) <= 8192 &&
					!strings.ContainsAny(s, " \t\r\n") {
					out[normalized] = s
				}
				continue
			}
			collectJSONStrings(val, out, depth+1)
		}
	case []interface{}:
		for _, item := range t {
			collectJSONStrings(item, out, depth+1)
		}
	}
}

// normalizeTokenKey folds the naming conventions apart from each other, so access_token, accessToken
// and Access-Token are one key.
func normalizeTokenKey(key string) string {
	key = strings.ToLower(key)
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	return key
}

// ---------------------------------------------------------------------------
// Wiring a token onto a request
// ---------------------------------------------------------------------------

// AuthMaterial renders the token into the shape ScanClient understands, so validation attaches it
// exactly the way a scan would. Returns nil for a token that rides in the URL, which is not a
// failure: see QueryParam and ApplyToURL.
func (t SessionToken) AuthMaterial(host string) *ScopedAuthMaterial {
	// A refresh secret is spent to mint a fresh credential, never sent on a resource request. It must
	// never be attached to a scan, so it produces no auth material regardless of its token_type.
	if t.TokenRole == tokenRoleRefresh {
		return nil
	}
	material := &ScopedAuthMaterial{
		Host:    strings.ToLower(host),
		Headers: map[string]string{},
		Source:  "session_token",
	}

	switch t.TokenType {
	case tokenTypeCookie:
		if t.CookieName == "" {
			return nil
		}
		material.Cookies = t.CookieName + "=" + t.TokenValue
	case tokenTypeQuery:
		return nil
	default:
		name := t.HeaderName
		if name == "" && t.TokenType == tokenTypeBearer {
			name = "Authorization"
		}
		if name == "" {
			// An api_key row with only a param name. It goes in the URL instead.
			return nil
		}
		material.Headers[canonicalHeaderName(name)] = t.ValuePrefix + t.TokenValue
	}
	return material
}

// QueryParam returns the query parameter this token rides in, or empty if it travels in a header or
// a cookie. An api_key with no header name is a query parameter by elimination.
func (t SessionToken) QueryParam() string {
	// A refresh secret never rides in a URL (or anywhere on a request); it is spent to mint, not sent.
	if t.TokenRole == tokenRoleRefresh {
		return ""
	}
	if t.ParamName == "" {
		return ""
	}
	if t.TokenType == tokenTypeQuery {
		return t.ParamName
	}
	if t.TokenType == tokenTypeAPIKey && t.HeaderName == "" {
		return t.ParamName
	}
	return ""
}

// ApplyToURL attaches a query-carried token to a URL, and returns the URL untouched for every other
// kind. Set rather than Add, so re-applying does not stack the parameter up.
func (t SessionToken) ApplyToURL(rawURL string) string {
	param := t.QueryParam()
	if param == "" {
		return rawURL
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	query := parsed.Query()
	query.Set(param, t.ValuePrefix+t.TokenValue)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// normalizeSessionTokenWiring fills the defaults and refuses a token that could never be sent.
//
// The DB CHECK constrains the enum and nothing else, so nothing stops a row that says token_type
// cookie with no cookie name. That row stores cleanly, shows up in the list, renders an Active
// badge, and is silently never attached to anything, which the operator reads as the scan ignoring
// their session rather than as a form they filled in wrong.
func normalizeSessionTokenWiring(t *SessionToken) error {
	t.TokenType = strings.ToLower(strings.TrimSpace(t.TokenType))
	if t.TokenType == "" {
		t.TokenType = tokenTypeHeader
	}
	if !validSessionTokenTypes[t.TokenType] {
		return fmt.Errorf("token_type must be one of header, cookie, api_key, bearer or query")
	}

	role, err := normalizeTokenRole(t.TokenRole)
	if err != nil {
		return err
	}
	t.TokenRole = role

	t.Name = strings.TrimSpace(t.Name)
	t.HeaderName = strings.TrimSpace(t.HeaderName)
	t.CookieName = strings.TrimSpace(t.CookieName)
	t.ParamName = strings.TrimSpace(t.ParamName)

	// A refresh secret is never wired to a header/cookie/query slot, so the per-type "needs a slot"
	// requirements below do not apply to it: enforcing them would reject a refresh row for lacking a
	// slot it will never use. Its token_type enum is still validated above; the slot is just optional.
	if t.TokenRole != tokenRoleRefresh {
		switch t.TokenType {
		case tokenTypeBearer:
			if t.HeaderName == "" {
				t.HeaderName = "Authorization"
			}
			if t.ValuePrefix == "" {
				t.ValuePrefix = "Bearer "
			}
		case tokenTypeHeader:
			if t.HeaderName == "" {
				return fmt.Errorf("a header token needs a header_name, or it can never be sent")
			}
		case tokenTypeCookie:
			if t.CookieName == "" {
				return fmt.Errorf("a cookie token needs a cookie_name, or it can never be sent")
			}
			if t.CookiePath == "" {
				t.CookiePath = "/"
			}
		case tokenTypeAPIKey:
			if t.HeaderName == "" && t.ParamName == "" {
				return fmt.Errorf("an api_key token needs a header_name or a param_name, or it can " +
					"never be sent")
			}
		case tokenTypeQuery:
			if t.ParamName == "" {
				return fmt.Errorf("a query token needs a param_name, or it can never be sent")
			}
		}
	}

	if t.HeaderName != "" {
		t.HeaderName = canonicalHeaderName(t.HeaderName)
	}
	if t.ScopeDomains == nil {
		t.ScopeDomains = []string{}
	}
	// An unscoped token would be attached to every host in the endpoint list, third parties
	// included. Defaulting to the scope target's own host keeps it where it was captured.
	if len(t.ScopeDomains) == 0 {
		if host := scopeTargetHost(t.ScopeTargetID); host != "" {
			t.ScopeDomains = []string{host}
		}
	}
	return nil
}

func applySessionTokenPayload(t *SessionToken, p sessionTokenPayload) {
	if p.AuthFlowID != nil {
		t.AuthFlowID = strings.TrimSpace(*p.AuthFlowID)
	}
	if p.Name != nil {
		t.Name = *p.Name
	}
	if p.TokenType != nil {
		t.TokenType = *p.TokenType
	}
	if p.TokenRole != nil {
		t.TokenRole = *p.TokenRole
	}
	if p.HeaderName != nil {
		t.HeaderName = *p.HeaderName
	}
	if p.CookieName != nil {
		t.CookieName = *p.CookieName
	}
	if p.ParamName != nil {
		t.ParamName = *p.ParamName
	}
	if p.ValuePrefix != nil {
		t.ValuePrefix = *p.ValuePrefix
	}
	if p.TokenValue != nil {
		t.TokenValue = *p.TokenValue
	}
	if p.ScopeDomains != nil {
		t.ScopeDomains = p.ScopeDomains
	}
	if p.CookiePath != nil {
		t.CookiePath = *p.CookiePath
	}
	if p.CookieDomain != nil {
		t.CookieDomain = *p.CookieDomain
	}
	if p.CookieSecure != nil {
		t.CookieSecure = *p.CookieSecure
	}
	if p.CookieHTTPOnly != nil {
		t.CookieHTTPOnly = *p.CookieHTTPOnly
	}
	if p.CookieSameSite != nil {
		t.CookieSameSite = *p.CookieSameSite
	}
	if p.ExpiresAt != nil {
		t.ExpiresAt = p.ExpiresAt
	}
	if p.IsActive != nil {
		t.IsActive = *p.IsActive
	}
	if p.Notes != nil {
		t.Notes = *p.Notes
	}
	if p.AutoRefresh != nil {
		t.AutoRefresh = *p.AutoRefresh
	}
	if p.RefreshTokenID != nil {
		t.RefreshTokenID = strings.TrimSpace(*p.RefreshTokenID)
	}
	if p.RefreshFlowID != nil {
		t.RefreshFlowID = strings.TrimSpace(*p.RefreshFlowID)
	}
	if p.RefreshStrategy != nil {
		t.RefreshStrategy = *p.RefreshStrategy
	}
	if p.RefreshTransport != nil {
		t.RefreshTransport = *p.RefreshTransport
	}
	if p.RefreshMaterialKey != nil {
		t.RefreshMaterialKey = *p.RefreshMaterialKey
	}
}

func insertSessionToken(t SessionToken) (string, error) {
	var id string
	err := dbPool.QueryRow(context.Background(), `
		INSERT INTO session_tokens
		  (scope_target_id, auth_flow_id, name, token_type, token_role, header_name, cookie_name,
		   param_name,
		   value_prefix, token_value, scope_domains, cookie_path, cookie_domain, cookie_secure,
		   cookie_httponly, cookie_samesite, expires_at, is_active, notes, auto_refresh,
		   refresh_token_id, refresh_flow_id, refresh_strategy, refresh_transport, refresh_material_key)
		VALUES ($1,$2,$3,$4,$19,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$20,
		   $21,$22,$23,$24,$25)
		RETURNING id::text`,
		t.ScopeTargetID, nullUUID(t.AuthFlowID), t.Name, t.TokenType, t.HeaderName, t.CookieName,
		t.ParamName, t.ValuePrefix, t.TokenValue, t.ScopeDomains, t.CookiePath, t.CookieDomain,
		t.CookieSecure, t.CookieHTTPOnly, t.CookieSameSite,
		// A bearer token that states its own exp should not be stored as "never expires", which is
		// how a credential dead for eleven days went on passing every expiry check in the framework.
		DeriveSessionTokenExpiry(t.TokenValue, t.ExpiresAt), t.IsActive,
		t.Notes, t.TokenRole, t.AutoRefresh,
		nullUUID(t.RefreshTokenID), nullUUID(t.RefreshFlowID), t.RefreshStrategy, t.RefreshTransport,
		t.RefreshMaterialKey).Scan(&id)
	return id, err
}

func loadSessionToken(tokenID string) (SessionToken, error) {
	row := dbPool.QueryRow(context.Background(),
		`SELECT `+sessionTokenCols+sessionTokenFrom+`WHERE t.id = $1`, tokenID)
	return scanSessionToken(row)
}

func scanSessionToken(row interface{ Scan(...interface{}) error }) (SessionToken, error) {
	var t SessionToken
	err := row.Scan(&t.ID, &t.ScopeTargetID, &t.AuthFlowID, &t.AuthFlowName, &t.Name, &t.TokenType,
		&t.TokenRole,
		&t.HeaderName, &t.CookieName, &t.ParamName, &t.ValuePrefix, &t.TokenValue, &t.ScopeDomains,
		&t.CookiePath, &t.CookieDomain, &t.CookieSecure, &t.CookieHTTPOnly, &t.CookieSameSite,
		&t.ExpiresAt, &t.IsActive, &t.Notes, &t.LastValidatedAt, &t.LastValidationStatus,
		&t.LastValidationDetail, &t.LastRefreshedAt, &t.AutoRefresh,
		&t.RefreshTokenID, &t.RefreshFlowID, &t.RefreshStrategy, &t.RefreshTransport, &t.RefreshMaterialKey,
		&t.CredentialKind,
		&t.CreatedAt, &t.UpdatedAt)
	if t.ScopeDomains == nil {
		t.ScopeDomains = []string{}
	}
	return t, err
}

// recordSessionTokenEvent appends to the token's timeline. Failures are logged and swallowed: an
// event that cannot be written must not turn a successful validation into an error the operator
// then retries against the target.
func recordSessionTokenEvent(tokenID, kind, status, detail string, evidence map[string]interface{}) {
	if tokenID == "" {
		return
	}
	if evidence == nil {
		evidence = map[string]interface{}{}
	}
	evidenceJSON, _ := json.Marshal(evidence)

	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO session_token_events (session_token_id, kind, status, detail, evidence)
		VALUES ($1, $2, $3, $4, $5)`, tokenID, kind, status, detail, evidenceJSON); err != nil {
		log.Printf("[SESSION-TOKEN] Failed to record %s event for %s: %v", kind, tokenID, err)
	}
}

// sessionTokenIdentity describes how the token goes on the wire, for operator-facing messages.
func sessionTokenIdentity(t SessionToken) string {
	switch {
	case t.CookieName != "":
		return "the " + t.CookieName + " cookie"
	case t.HeaderName != "":
		return "the " + t.HeaderName + " header"
	case t.ParamName != "":
		return "the " + t.ParamName + " query parameter"
	}
	return t.Name
}

// sessionTokenIDFrom reads the token id from the route.
//
// The alternatives are accepted because these routes are registered in main.go, and a variable
// named token_id there against an id read here fails as a 404 on an empty string, which looks like
// a missing row rather than like a routing mistake.
func sessionTokenIDFrom(r *http.Request) string {
	vars := mux.Vars(r)
	for _, key := range []string{"id", "token_id", "session_token_id"} {
		if value := vars[key]; value != "" {
			return value
		}
	}
	return ""
}

// cookieExpiry resolves a cookie's lifetime to a wall-clock time, or nil for a session cookie.
func cookieExpiry(c *http.Cookie) *time.Time {
	// Max-Age wins over Expires. That is RFC 6265's rule and also the practical one: a server that
	// sends both is normally sending Expires for the benefit of ancient clients and means Max-Age.
	if c.MaxAge > 0 {
		expiry := time.Now().Add(time.Duration(c.MaxAge) * time.Second)
		return &expiry
	}
	if !c.Expires.IsZero() {
		expiry := c.Expires
		return &expiry
	}
	// A session cookie. It lives until the browser closes, which has no wall-clock answer, and
	// writing one in would put a fake deadline on a credential that does not have one.
	return nil
}

func sameSiteName(mode http.SameSite) string {
	switch mode {
	case http.SameSiteLaxMode:
		return "Lax"
	case http.SameSiteStrictMode:
		return "Strict"
	case http.SameSiteNoneMode:
		return "None"
	}
	return ""
}

func writeSessionTokenJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[SESSION-TOKEN] Failed to write response: %v", err)
	}
}

// authFlowProbeURL returns the URL of the last step of an auth flow, which is the most
// auth-sensitive request the framework knows about for that credential.
//
// Steps are stored as raw HTTP requests, so the URL has to be reassembled from the request line and
// the Host header. A step whose request line is not parseable is skipped rather than guessed at.
// authRequiredProbeURL returns a URL that endpoint validation already proved refuses anonymous
// requests, which makes it the sharpest available test of whether a session is still live.
//
// Preferred over the scope target's base URL, which cannot answer the question at all when the root
// is a static shell, a CDN index or a 404: it returns the same bytes signed in or out, so a healthy
// token measures as not_honoured. That false negative is what made the whole check untrustworthy.
// authRequiredProbeURL finds a validated auth-gated endpoint to use as the discriminating probe.
//
// Host-filtered on purpose. The cookie being validated applies only to its own host, so probing a
// gated endpoint on a DIFFERENT in-scope host (auth.nebius.com when the token is for
// console.nebius.com) sends the cookie nowhere, both arms come back identical, and a live token
// measures as not-honoured. Only GET/HEAD, because the validator sends GET: a POST-only gateway
// answers 404/405 to a GET whether or not the caller is authenticated, so it discriminates nothing.
func authRequiredProbeURL(scopeTargetID, host string) string {
	if strings.TrimSpace(host) == "" {
		return ""
	}
	// Prefer a route the AUTHENTICATED validation arm actually passed (2xx) over one it was refused on.
	// A 2xx here means the session owns the object, so the probe discriminates: the owner gets 2xx and
	// an anonymous control gets 401/403. A route whose authed arm was itself 403 is an object owned by
	// someone else (the IDOR-protected-object trap) and refuses the owner too, so it cannot grade the
	// session. http_status is the authenticated status, because validation runs with the active token.
	var url string
	err := dbPool.QueryRow(context.Background(), `
		SELECT url FROM endpoint_validation_results
		WHERE scope_target_id = $1
		  AND status = 'valid'
		  AND reason_code = 'valid.auth_required'
		  AND COALESCE(method,'GET') IN ('GET','HEAD')
		  AND lower(split_part(url,'/',3)) = lower($2)
		ORDER BY (CASE WHEN http_status BETWEEN 200 AND 299 THEN 0 ELSE 1 END), url
		LIMIT 1`, scopeTargetID, host).Scan(&url)
	if err != nil {
		return ""
	}
	return url
}

func authFlowProbeURL(authFlowID string) string {
	if strings.TrimSpace(authFlowID) == "" {
		return ""
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT raw_request, COALESCE(response_headers, '{}'::jsonb)
		FROM auth_flow_steps
		WHERE auth_flow_id = $1 ORDER BY step_order DESC`, authFlowID)
	if err != nil {
		return ""
	}
	defer rows.Close()

	type recordedStep struct {
		raw     string
		headers []byte
	}
	steps := []recordedStep{}
	for rows.Next() {
		var s recordedStep
		if rows.Scan(&s.raw, &s.headers) != nil {
			continue
		}
		steps = append(steps, s)
	}

	// Preferred: the place the flow ended up. A password login answers 302 and sends the browser to
	// the account page, and that page is by construction something only an authenticated caller
	// sees. The placeholder guard below deliberately does NOT apply here: a recorded Location is a
	// fact from the last replay, so it is usable even though the step that produced it is not.
	for _, s := range steps {
		// rawRequestBaseURL, not rawRequestURL: the step that redirects is the login POST, and
		// rawRequestURL refuses a POST by design. Its URL is wanted only as the base to resolve the
		// Location against, and the resolved URL is then probed with GET like any other.
		if dest := recordedRedirectTarget(s.headers, rawRequestBaseURL(s.raw)); dest != "" {
			return dest
		}
	}

	for _, s := range steps {
		// A step whose request line or Host still holds a {{af:NAME}} placeholder cannot be probed:
		// the URL would contain literal braces, the request would fail for a reason that has nothing
		// to do with the session, and the token would be graded not_honoured on the strength of it.
		// Fall through to an earlier step instead.
		if len(authFlowVarNames(s.raw)) > 0 {
			continue
		}
		if u := rawRequestURL(s.raw); u != "" {
			return u
		}
	}
	return ""
}

// loadCompanionMaterial gathers the active companion cookies on a target into auth material, and
// returns their names for the evidence record.
//
// Cookies only: a companion is by definition a routing or affinity value, and every real example
// of one travels as a cookie. Returning nil rather than empty material when there are none keeps
// the control arm genuinely bare on the ordinary target that has no companions at all.
func loadCompanionMaterial(scopeTargetID, host, excludeTokenID string) (*ScopedAuthMaterial, []string) {
	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(cookie_name,''), COALESCE(token_value,'')
		FROM session_tokens
		WHERE scope_target_id = $1
		  AND COALESCE(token_role,'credential') = 'companion'
		  AND COALESCE(is_active,false)
		  AND token_type = 'cookie'
		  AND id <> $2::uuid
		ORDER BY name`, scopeTargetID, excludeTokenID)
	if err != nil {
		return nil, nil
	}
	defer rows.Close()

	pairs := []string{}
	names := []string{}
	for rows.Next() {
		var name, value string
		if rows.Scan(&name, &value) != nil {
			continue
		}
		if strings.TrimSpace(name) == "" || strings.TrimSpace(value) == "" {
			continue
		}
		pairs = append(pairs, name+"="+value)
		names = append(names, name)
	}
	if len(pairs) == 0 {
		return nil, nil
	}

	return &ScopedAuthMaterial{
		Host:    strings.ToLower(host),
		Headers: map[string]string{},
		Cookies: strings.Join(pairs, "; "),
		Source:  "session_token_companion",
	}, names
}

// withCompanions folds the companion cookies into a credential's material.
func withCompanions(material, companions *ScopedAuthMaterial, host string) *ScopedAuthMaterial {
	if companions == nil {
		return material
	}
	if material == nil {
		return companions
	}

	merged := *material
	if merged.Cookies == "" {
		merged.Cookies = companions.Cookies
	} else {
		merged.Cookies = merged.Cookies + "; " + companions.Cookies
	}
	return &merged
}

// sessionFlowProbeURL returns an auth-flow-derived probe URL for any active credential on a target.
//
// This is what lets a FIRST endpoint-scan run ask the credential question somewhere that can answer
// it. Companions are excluded: a routing cookie has a flow but proves nothing about authentication.
func sessionFlowProbeURL(scopeTargetID string) string {
	rows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT auth_flow_id::text
		FROM session_tokens
		WHERE scope_target_id = $1
		  AND auth_flow_id IS NOT NULL
		  AND COALESCE(is_active,false)
		  AND COALESCE(token_role,'credential') = 'credential'`, scopeTargetID)
	if err != nil {
		return ""
	}
	defer rows.Close()

	flowIDs := []string{}
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil && strings.TrimSpace(id) != "" {
			flowIDs = append(flowIDs, id)
		}
	}

	for _, id := range flowIDs {
		if u := authFlowProbeURL(id); u != "" {
			return u
		}
	}
	return ""
}

// recordedRedirectTarget resolves the Location a step's stored response carried, against that
// step's own URL.
//
// Same host only, on purpose. A flow that bounces through an identity provider would otherwise
// hand back a third party's URL, and validation would attach the application's session cookie to a
// request going somewhere it was never issued for.
func recordedRedirectTarget(headersJSON []byte, stepURL string) string {
	if len(headersJSON) == 0 || stepURL == "" {
		return ""
	}

	var headers map[string][]string
	if json.Unmarshal(headersJSON, &headers) != nil {
		return ""
	}

	location := ""
	for name, values := range headers {
		if strings.EqualFold(name, "Location") && len(values) > 0 {
			location = strings.TrimSpace(values[0])
			break
		}
	}
	if location == "" {
		return ""
	}

	base, err := url.Parse(stepURL)
	if err != nil {
		return ""
	}
	resolved, err := base.Parse(location)
	if err != nil || resolved.Host == "" {
		return ""
	}
	if !strings.EqualFold(resolved.Host, base.Host) {
		return ""
	}
	return resolved.String()
}

// rawRequestURL rebuilds an absolute URL from a raw HTTP request, for use as a probe target.
//
// Only safe verbs are worth probing with. A flow ending in POST /login would re-submit the login
// on every validation, which is a write and would burn rate limits and lockout counters.
func rawRequestURL(raw string) string {
	parts := strings.Fields(strings.TrimSpace(strings.SplitN(
		strings.ReplaceAll(raw, "\r\n", "\n"), "\n", 2)[0]))
	if len(parts) < 2 || strings.ToUpper(parts[0]) != http.MethodGet {
		return ""
	}
	return rawRequestBaseURL(raw)
}

// rawRequestBaseURL rebuilds the absolute URL a raw request was aimed at, whatever its verb.
//
// Split out from rawRequestURL because the two answer different questions. rawRequestURL asks
// "may I send this again", and refuses anything but GET. This asks "where was this sent", which is
// needed to resolve a relative Location out of the recorded response of a step that must never be
// replayed: the login POST is exactly that step, and its Location is the one worth probing.
// Resolving is not sending, and what finally gets probed is still fetched with GET.
func rawRequestBaseURL(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return ""
	}

	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return ""
	}
	path := parts[1]
	if strings.HasPrefix(strings.ToLower(path), "http://") ||
		strings.HasPrefix(strings.ToLower(path), "https://") {
		return path
	}

	host, scheme := "", "https"
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "host":
			host = strings.TrimSpace(value)
		case "x-forwarded-proto":
			if v := strings.TrimSpace(value); v != "" {
				scheme = v
			}
		}
	}
	if host == "" {
		return ""
	}
	// A bare host:port with a non-443 port is overwhelmingly plain HTTP in this framework's own
	// test and staging targets, and guessing https there produces a TLS error rather than a verdict.
	if strings.Contains(host, ":") && !strings.HasSuffix(host, ":443") {
		scheme = "http"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return scheme + "://" + host + path
}

// SessionStillHonoured reports whether this target's stored credential is still being accepted.
//
// This exists because a long vector scan cannot tell a clean result from a dead session. sqlmap ran
// for 2h44m and ghauri for 3h49m against ginandjuice.shop, whose session expires in well under an
// hour under load, and neither tool checks. Once the session dies every response becomes the same
// logged-out page, every vector after that point looks identically uninteresting, and 102 vectors
// were recorded clean with nothing to distinguish them from vectors that were genuinely tested.
//
// A target with NO stored credential returns true: an unauthenticated scan has no session to lose,
// and reporting "dead" there would stop every anonymous scan in the framework.
//
// Companion values are skipped for the same reason validation skips them: a load balancer affinity
// cookie is not graded on its own.
func SessionStillHonoured(ctx context.Context, scopeTargetID string) (alive bool, reason string) {
	rows, err := dbPool.Query(ctx,
		`SELECT `+sessionTokenCols+sessionTokenFrom+
			`WHERE t.scope_target_id = $1 AND COALESCE(t.is_active,false)
			   AND COALESCE(t.token_role,'credential') NOT IN ('companion','refresh')
			 ORDER BY t.created_at ASC`, scopeTargetID)
	if err != nil {
		// A database problem is not evidence that the session died, and stopping a four hour scan
		// over one failed query would be worse than the thing this guards against.
		return true, ""
	}
	defer rows.Close()

	var tokens []SessionToken
	for rows.Next() {
		token, scanErr := scanSessionToken(rows)
		if scanErr == nil {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return true, ""
	}

	for _, token := range tokens {
		status, detail, _ := runSessionTokenValidation(token)
		switch status {
		case tokenStatusActive, tokenStatusCompanion:
			return true, ""
		case tokenStatusError, tokenStatusRefresh:
			// Error: could not be graded, which is not the same as being refused. Refresh: a mint secret
			// is never a session-liveness signal (and is excluded by the query above; this is defence in
			// depth). Skip either and, if it was the only row, let the scan continue rather than killing
			// it on a probe that failed for its own reasons or on a value that was never a credential.
			continue
		default:
			// The reason aborts a scan and lands in the run record, so it names the row exactly as
			// the operator labelled it and quotes the verdict as it was measured.
			return false, fmt.Sprintf("the stored credential %q validated as %q: %s",
				token.Name, status, detail)
		}
	}
	return true, ""
}
