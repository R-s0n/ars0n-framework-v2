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

// Validation verdicts. These are stored in last_validation_status, so they stay short and stable:
// the client renders them as badges and a renamed value silently stops matching.
const (
	tokenStatusActive      = "active"
	tokenStatusExpired     = "expired"
	tokenStatusNotHonoured = "not_honoured"
	tokenStatusError       = "error"
)

// SessionToken mirrors a session_tokens row, with the linked flow's name joined on for display.
type SessionToken struct {
	ID                   string     `json:"id"`
	ScopeTargetID        string     `json:"scope_target_id"`
	AuthFlowID           string     `json:"auth_flow_id"`
	AuthFlowName         string     `json:"auth_flow_name"`
	Name                 string     `json:"name"`
	TokenType            string     `json:"token_type"`
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
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// sessionTokenPayload is the write shape for create and update. Every field is a pointer so an
// update can tell "leave this alone" apart from "set this to empty", which matters most for
// token_value: a client that omits it must not blank the credential.
type sessionTokenPayload struct {
	AuthFlowID     *string    `json:"auth_flow_id"`
	Name           *string    `json:"name"`
	TokenType      *string    `json:"token_type"`
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
}

const sessionTokenCols = `t.id::text, t.scope_target_id::text, COALESCE(t.auth_flow_id::text,''),
	COALESCE(f.name,''), t.name, t.token_type, COALESCE(t.header_name,''),
	COALESCE(t.cookie_name,''), COALESCE(t.param_name,''), COALESCE(t.value_prefix,''),
	COALESCE(t.token_value,''), COALESCE(t.scope_domains,'{}'), COALESCE(t.cookie_path,'/'),
	COALESCE(t.cookie_domain,''), COALESCE(t.cookie_secure,false), COALESCE(t.cookie_httponly,false),
	COALESCE(t.cookie_samesite,''), t.expires_at, COALESCE(t.is_active,false), COALESCE(t.notes,''),
	t.last_validated_at, COALESCE(t.last_validation_status,''), COALESCE(t.last_validation_detail,''),
	t.last_refreshed_at, t.created_at, t.updated_at`

const sessionTokenFrom = ` FROM session_tokens t LEFT JOIN auth_flows f ON f.id = t.auth_flow_id `

// ---------------------------------------------------------------------------
// Read
// ---------------------------------------------------------------------------

// GetSessionTokens handles GET /session-tokens/target/{scope_target_id}.
func GetSessionTokens(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(context.Background(),
		`SELECT `+sessionTokenCols+sessionTokenFrom+
			`WHERE t.scope_target_id = $1 ORDER BY t.is_active DESC, t.created_at ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to list tokens: %v", err)
		http.Error(w, "Failed to fetch session tokens", http.StatusInternalServerError)
		return
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

	writeSessionTokenJSON(w, http.StatusOK, tokens)
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
		events = append(events, map[string]interface{}{
			"id": id, "kind": kind, "status": status, "detail": detail,
			"evidence": evidence, "created_at": createdAt,
		})
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

	result, err := dbPool.Exec(context.Background(), `
		UPDATE session_tokens SET
		  auth_flow_id = $1, name = $2, token_type = $3, header_name = $4, cookie_name = $5,
		  param_name = $6, value_prefix = $7, token_value = $8, scope_domains = $9,
		  cookie_path = $10, cookie_domain = $11, cookie_secure = $12, cookie_httponly = $13,
		  cookie_samesite = $14, expires_at = $15, is_active = $16, notes = $17,
		  last_validation_status = $18, last_validation_detail = $19, updated_at = NOW()
		WHERE id = $20`,
		nullUUID(token.AuthFlowID), token.Name, token.TokenType, token.HeaderName, token.CookieName,
		token.ParamName, token.ValuePrefix, token.TokenValue, token.ScopeDomains, token.CookiePath,
		token.CookieDomain, token.CookieSecure, token.CookieHTTPOnly, token.CookieSameSite,
		DeriveSessionTokenExpiry(token.TokenValue, token.ExpiresAt),
		token.IsActive, token.Notes, validationStatus, validationDetail, tokenID)
	if err != nil {
		log.Printf("[SESSION-TOKEN] Failed to update token %s: %v", tokenID, err)
		http.Error(w, "Failed to update session token", http.StatusInternalServerError)
		return
	}
	if result.RowsAffected() == 0 {
		http.Error(w, "Session token not found", http.StatusNotFound)
		return
	}

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

	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{"tokens": tokens})
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
	} else if epProbe := authRequiredProbeURL(token.ScopeTargetID); epProbe != "" {
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
	// Scope is nil, deliberately. The only URL this ever requests is the scope target's own base
	// URL, which it builds itself, so there is nothing for a host boundary to protect against.
	client := NewScanClient(budget, 20*time.Second, "", nil)

	authed := client.Do(ctx, ScanRequest{
		URL:      token.ApplyToURL(target),
		Method:   http.MethodGet,
		Auth:     token.AuthMaterial(host),
		ReadBody: true,
	})
	anon := client.Do(ctx, ScanRequest{URL: target, Method: http.MethodGet, ReadBody: true})

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
	// this measurement describes the token.
	if IsChallengeBody(authed.Body) {
		return tokenStatusError,
			"A WAF or bot manager answered instead of the application, so this measurement says " +
				"nothing about the token.", evidence
	}

	// Refused outright. The target read the credential and rejected it, which is a more useful
	// answer than "the two responses matched", so it is checked first.
	if authed.Status == 401 || authed.Status == 403 {
		return tokenStatusExpired, fmt.Sprintf(
			"The target answered %d to the authenticated request. It saw the credential and refused "+
				"it, so the stored value is expired or wrong.", authed.Status), evidence
	}
	if authed.IsRedirect() && LooksLikeAuthRedirect(authed.Location) {
		return tokenStatusExpired, fmt.Sprintf(
			"The authenticated request was redirected to %s, which is this target sending an "+
				"unauthenticated caller to log in.", authed.Location), evidence
	}

	if ResponsesEquivalent(authedFP, anonFP) {
		return tokenStatusNotHonoured, fmt.Sprintf(
			"The base URL answered the same way with the token as without it (%s both ways), so it "+
				"is not being honoured. Worth checking before this is read as a dead credential: if "+
				"the base URL is a public landing page that looks identical signed in or out, a token "+
				"that works fine on the API would still measure like this.",
			FingerprintSummary(authedFP)), evidence
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

	// The link to a flow is the entire refresh mechanism. Without it there is nothing to replay, and
	// saying so plainly beats a generic failure that leaves the operator poking at the button.
	if token.AuthFlowID == "" {
		detail := "This token is not tied to an auth flow, so there is no way to produce another " +
			"one. Link it to the login flow that issues it, then refresh."
		recordSessionTokenEvent(tokenID, "refresh", "no_flow", detail, nil)
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
			"status": "no_flow", "detail": detail, "new_value_set": false,
		})
		return
	}

	value, expires, evidence, err := replayFlowForToken(token)
	if err != nil {
		detail := "The auth flow could not be replayed: " + truncateReason(err.Error())
		recordSessionTokenEvent(tokenID, "refresh", "replay_failed", detail, evidence)
		writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
			"status": "replay_failed", "detail": detail, "new_value_set": false,
		})
		return
	}

	if value == "" {
		detail := fmt.Sprintf(
			"The flow replayed, but no new value for %s turned up in the responses. Check the "+
				"flow's steps still succeed, and that the credential really is issued as a "+
				"Set-Cookie or in a response body rather than by a redirect this replay does not "+
				"follow.", sessionTokenIdentity(token))
		recordSessionTokenEvent(tokenID, "refresh", "no_token_found", detail, evidence)
		writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
			"status": "no_token_found", "detail": detail, "new_value_set": false,
		})
		return
	}

	// expires_at is replaced outright rather than merged, NULL included. Carrying the previous
	// expiry forward would describe a value that no longer exists, and a fresh session cookie with
	// no expiry genuinely has none.
	//
	// The validation verdict is cleared for the same reason it is cleared on a paste: it described
	// the old value.
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE session_tokens
		SET token_value = $1, expires_at = $2, last_refreshed_at = NOW(),
		    last_validation_status = '', last_validation_detail = '', updated_at = NOW()
		WHERE id = $3`, value, DeriveSessionTokenExpiry(value, expires), tokenID); err != nil {
		log.Printf("[SESSION-TOKEN] Failed to write refreshed value for %s: %v", tokenID, err)
		http.Error(w, "Failed to store the refreshed token", http.StatusInternalServerError)
		return
	}

	detail := fmt.Sprintf("Replayed the linked auth flow and took a new value for %s from %s.",
		sessionTokenIdentity(token), evidence["source"])
	recordSessionTokenEvent(tokenID, "refresh", "refreshed", detail, evidence)

	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
		"status": "refreshed", "detail": detail, "new_value_set": true,
	})
}

// replayFlowForToken runs the linked auth flow and pulls a new value out of the result.
//
// The replay is the engine in authFlowsUtils.go, called step by step exactly as ReplayAuthFlow does
// it: one shared cookie jar so a session set on step one is sent on step two, and each response
// written back onto its step so the operator can open the flow afterwards and see what happened. A
// second implementation of that loop would drift from the one the Auth Flows tab exercises, and the
// refresh path would quietly stop matching the flow the operator tested by hand.
func replayFlowForToken(token SessionToken) (string, *time.Time, map[string]interface{}, error) {
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

	for _, step := range steps {
		effBase := resolveBaseURL(step.RawRequest, baseURL)
		status, headers, body, ms, sendErr := sendRawRequest(step.RawRequest, effBase, jar)

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

		// Set-Cookie is read off the raw response headers rather than out of the jar. The jar drops
		// anything whose Domain does not match the URL it was set from, which is precisely what
		// happens when a flow authenticates against an SSO host and hands the session back, and that
		// cookie is usually the one being refreshed.
		setCookies = append(setCookies, http.Header(headers).Values("Set-Cookie")...)
		if strings.TrimSpace(body) != "" {
			bodies = append(bodies, body)
		}
	}

	evidence["steps_replayed"] = len(steps)
	evidence["steps_failed"] = failed
	if failed == len(steps) {
		return "", nil, evidence, fmt.Errorf("every step of the flow failed to send")
	}

	// Cookies first for a cookie token and the body first for everything else, because that is where
	// each one is issued. The last occurrence wins in both: a flow that logs in and then rotates the
	// session on an MFA step issues the value twice, and the first one is already dead by the time
	// the flow finishes.
	if token.TokenType == tokenTypeCookie {
		if value, expires := cookieValueFromSetCookies(setCookies, token.CookieName); value != "" {
			evidence["source"] = "the Set-Cookie header of the replayed flow"
			return value, expires, evidence, nil
		}
		if value := tokenValueFromBodies(bodies, sessionTokenBodyKeys(token)); value != "" {
			evidence["source"] = "a response body of the replayed flow"
			return value, nil, evidence, nil
		}
		return "", nil, evidence, nil
	}

	if value := tokenValueFromBodies(bodies, sessionTokenBodyKeys(token)); value != "" {
		evidence["source"] = "a response body of the replayed flow"
		return value, nil, evidence, nil
	}
	// A bearer token is occasionally handed back as a cookie the front end then reads and promotes
	// to an Authorization header, so the cookies are still worth a look.
	for _, name := range []string{token.ParamName, token.HeaderName, token.Name} {
		if name == "" {
			continue
		}
		if value, expires := cookieValueFromSetCookies(setCookies, name); value != "" {
			evidence["source"] = "the Set-Cookie header of the replayed flow"
			return value, expires, evidence, nil
		}
	}
	return "", nil, evidence, nil
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

	t.Name = strings.TrimSpace(t.Name)
	t.HeaderName = strings.TrimSpace(t.HeaderName)
	t.CookieName = strings.TrimSpace(t.CookieName)
	t.ParamName = strings.TrimSpace(t.ParamName)

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
}

func insertSessionToken(t SessionToken) (string, error) {
	var id string
	err := dbPool.QueryRow(context.Background(), `
		INSERT INTO session_tokens
		  (scope_target_id, auth_flow_id, name, token_type, header_name, cookie_name, param_name,
		   value_prefix, token_value, scope_domains, cookie_path, cookie_domain, cookie_secure,
		   cookie_httponly, cookie_samesite, expires_at, is_active, notes)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		RETURNING id::text`,
		t.ScopeTargetID, nullUUID(t.AuthFlowID), t.Name, t.TokenType, t.HeaderName, t.CookieName,
		t.ParamName, t.ValuePrefix, t.TokenValue, t.ScopeDomains, t.CookiePath, t.CookieDomain,
		t.CookieSecure, t.CookieHTTPOnly, t.CookieSameSite,
		// A bearer token that states its own exp should not be stored as "never expires", which is
		// how a credential dead for eleven days went on passing every expiry check in the framework.
		DeriveSessionTokenExpiry(t.TokenValue, t.ExpiresAt), t.IsActive,
		t.Notes).Scan(&id)
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
		&t.HeaderName, &t.CookieName, &t.ParamName, &t.ValuePrefix, &t.TokenValue, &t.ScopeDomains,
		&t.CookiePath, &t.CookieDomain, &t.CookieSecure, &t.CookieHTTPOnly, &t.CookieSameSite,
		&t.ExpiresAt, &t.IsActive, &t.Notes, &t.LastValidatedAt, &t.LastValidationStatus,
		&t.LastValidationDetail, &t.LastRefreshedAt, &t.CreatedAt, &t.UpdatedAt)
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
func authRequiredProbeURL(scopeTargetID string) string {
	var url string
	err := dbPool.QueryRow(context.Background(), `
		SELECT url FROM endpoint_validation_results
		WHERE scope_target_id = $1
		  AND status = 'valid'
		  AND reason_code = 'valid.auth_required'
		  AND COALESCE(method,'GET') IN ('GET','HEAD')
		ORDER BY url
		LIMIT 1`, scopeTargetID).Scan(&url)
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
		SELECT raw_request FROM auth_flow_steps
		WHERE auth_flow_id = $1 ORDER BY step_order DESC`, authFlowID)
	if err != nil {
		return ""
	}
	defer rows.Close()

	for rows.Next() {
		var raw string
		if rows.Scan(&raw) != nil {
			continue
		}
		if u := rawRequestURL(raw); u != "" {
			return u
		}
	}
	return ""
}

// rawRequestURL rebuilds an absolute URL from a raw HTTP request.
func rawRequestURL(raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(raw, "\n")
	if len(lines) == 0 {
		return ""
	}

	parts := strings.Fields(strings.TrimSpace(lines[0]))
	if len(parts) < 2 {
		return ""
	}
	// Only safe verbs are worth probing with. A flow ending in POST /login would re-submit the
	// login on every validation, which is a write and would burn rate limits and lockout counters.
	if strings.ToUpper(parts[0]) != http.MethodGet {
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
