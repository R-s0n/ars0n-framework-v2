package utils

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Bridges recorded manual-crawl traffic into the rest of the URL workflow.
//
// The capture table is the highest-fidelity data in the framework: real methods, real headers
// including cookies, real request and response bodies. Until now nothing downstream read it, so
// auth flows were typed by hand, IDOR candidates were hunted by eye, and endpoint investigation
// re-requested everything logged out. This file is what connects them.

// Headers that must never be copied verbatim into a rebuilt request: HTTP/2 pseudo-headers have no
// meaning in an HTTP/1.1 message, and the framing headers are recomputed from the body we actually
// have.
var skipRebuildHeaders = map[string]bool{
	":method":           true,
	":path":             true,
	":authority":        true,
	":scheme":           true,
	"host":              true,
	"content-length":    true,
	"transfer-encoding": true,
	"connection":        true,
	"keep-alive":        true,
	"upgrade":           true,
	"http2-settings":    true,
	"proxy-connection":  true,
	// Compression is negotiated by the replay client, and asking for a codec we then fail to decode
	// turns a readable response into binary noise.
	"accept-encoding": true,
}

// BuildRawHTTPRequest renders a capture as a raw HTTP/1.1 request, the format auth_flow_steps
// stores and http.ReadRequest parses on replay.
func BuildRawHTTPRequest(method, rawURL string, headers map[string]interface{}, body string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		parsed = &url.URL{Path: "/"}
	}

	pathQuery := parsed.RequestURI()
	if pathQuery == "" {
		pathQuery = "/"
	}

	host := parsed.Host
	if host == "" {
		host = headerString(headers, "host")
	}

	if method == "" {
		method = "GET"
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "%s %s HTTP/1.1\r\n", strings.ToUpper(method), pathQuery)
	fmt.Fprintf(&sb, "Host: %s\r\n", host)

	for name, value := range headers {
		lower := strings.ToLower(name)
		if skipRebuildHeaders[lower] || strings.HasPrefix(lower, ":") {
			continue
		}
		text := stringifyHeaderValue(value)
		if text == "" {
			continue
		}
		fmt.Fprintf(&sb, "%s: %s\r\n", canonicalHeaderName(name), text)
	}

	if body != "" {
		fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	}

	sb.WriteString("\r\n")
	sb.WriteString(body)
	return sb.String()
}

func canonicalHeaderName(name string) string {
	parts := strings.Split(name, "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + strings.ToLower(part[1:])
	}
	return strings.Join(parts, "-")
}

func stringifyHeaderValue(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, item := range v {
			if s := stringifyHeaderValue(item); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func headerString(headers map[string]interface{}, name string) string {
	if headers == nil {
		return ""
	}
	lower := strings.ToLower(name)
	for key, value := range headers {
		if strings.ToLower(key) == lower {
			return stringifyHeaderValue(value)
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Auth flow candidates
// ---------------------------------------------------------------------------

// Paths and body fields that mark a request as part of an authentication exchange. Deliberately
// broad: a false positive costs the user one unchecked checkbox, a false negative means they have
// to hand-type the request they already recorded.
// start, initiate, begin, challenge and send are how a passwordless flow opens: the request that
// asks the server to send an OTP. Missing them meant the candidate list began at step two, so an
// operator importing it got a flow that verifies a code nobody asked for. On the live corpus the
// SMS login's own first step, POST /cookieless/start, was the one request the classifier did not
// return, and it is the step without which the rest cannot run.
var authPathPattern = regexp.MustCompile(`(?i)(^|/)(login|signin|sign-in|log-in|auth|authenticate|authorize|oauth|oidc|sso|saml|token|session|register|signup|sign-up|account/create|mfa|2fa|otp|verify|challenge|reset|forgot|recover|password|passwd|passcode|credential|logout|signout|sign-out|refresh|start|initiate|begin|send-code|sendcode)`)

// phone_number and passcode carry credentials just as plainly as password does, and a phone-first
// login is the normal shape for consumer and fintech applications.
var authBodyFieldPattern = regexp.MustCompile(`(?i)"(password|passwd|pwd|passcode|pin|username|user_name|email|phone|phone_number|msisdn|otp|code|token|refresh_token|access_token|id_token|client_secret|grant_type|totp|mfa_code|verification_code|device_id)"\s*:`)

var authFormFieldPattern = regexp.MustCompile(`(?i)(^|&)(password|passwd|pwd|passcode|pin|username|user|email|phone|phone_number|otp|code|token|grant_type)=`)

// AuthFlowCandidate is a recorded request that looks like part of an auth exchange.
type AuthFlowCandidate struct {
	CaptureID    string    `json:"capture_id"`
	SessionID    string    `json:"session_id"`
	URL          string    `json:"url"`
	Endpoint     string    `json:"endpoint"`
	Method       string    `json:"method"`
	StatusCode   int       `json:"status_code"`
	Timestamp    time.Time `json:"timestamp"`
	Reason       string    `json:"reason"`
	HasBody      bool      `json:"has_body"`
	SetsCookie   bool      `json:"sets_cookie"`
	SuggestedCat string    `json:"suggested_category"`
	RawRequest   string    `json:"raw_request"`
}

// GetAuthFlowCandidates handles GET /manual-crawl/captures/target/{scope_target_id}/auth-candidates.
func GetAuthFlowCandidates(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, session_id, url, endpoint, method, status_code, headers, response_headers,
		       COALESCE(post_data,''), timestamp
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[CAPTURE-BRIDGE] Failed to query captures: %v", err)
		http.Error(w, "Failed to query captures", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	candidates := []AuthFlowCandidate{}
	for rows.Next() {
		var id, sessionID, urlStr, endpoint, method, postData string
		var statusCode *int
		var headersJSON, responseHeadersJSON []byte
		var timestamp time.Time

		if err := rows.Scan(&id, &sessionID, &urlStr, &endpoint, &method, &statusCode,
			&headersJSON, &responseHeadersJSON, &postData, &timestamp); err != nil {
			continue
		}

		reason, category := classifyAuthCapture(urlStr, method, postData)
		if reason == "" {
			continue
		}

		var headers, responseHeaders map[string]interface{}
		json.Unmarshal(headersJSON, &headers)
		json.Unmarshal(responseHeadersJSON, &responseHeaders)

		candidate := AuthFlowCandidate{
			CaptureID:    id,
			SessionID:    sessionID,
			URL:          urlStr,
			Endpoint:     endpoint,
			Method:       strings.ToUpper(method),
			Timestamp:    timestamp,
			Reason:       reason,
			HasBody:      postData != "",
			SetsCookie:   headerString(responseHeaders, "set-cookie") != "",
			SuggestedCat: category,
			RawRequest:   BuildRawHTTPRequest(method, urlStr, headers, postData),
		}
		if statusCode != nil {
			candidate.StatusCode = *statusCode
		}
		candidates = append(candidates, candidate)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(candidates)
}

// classifyAuthCapture returns why a request looks auth-related and which flow category it most
// likely belongs to. An empty reason means it is not a candidate.
func classifyAuthCapture(urlStr, method, body string) (string, string) {
	parsed, err := url.Parse(urlStr)
	path := urlStr
	if err == nil {
		path = parsed.Path
	}

	upperMethod := strings.ToUpper(method)

	// A CORS preflight is never a step in a flow. It carries no credentials, the browser sends it on
	// the caller's behalf, and replaying one authenticates nobody. They were 7 of the 17 candidates
	// on the live corpus, which is a lot of noise in a list the operator is meant to read and pick
	// from, and picking one produces a flow with a dead step in the middle.
	if upperMethod == http.MethodOptions {
		return "", ""
	}

	pathMatch := authPathPattern.MatchString(path)
	bodyMatch := body != "" && (authBodyFieldPattern.MatchString(body) || authFormFieldPattern.MatchString(body))

	if !pathMatch && !bodyMatch {
		return "", ""
	}

	// Static assets whose filename happens to contain "login" are noise, not requests.
	if isStaticAsset(urlStr) || isImageFile(urlStr) {
		return "", ""
	}

	reason := "auth-looking path"
	if bodyMatch && pathMatch {
		reason = "auth path and credential fields in body"
	} else if bodyMatch {
		reason = "credential fields in body"
	}

	lowerPath := strings.ToLower(path)
	category := "login"
	switch {
	case strings.Contains(lowerPath, "register") || strings.Contains(lowerPath, "signup") || strings.Contains(lowerPath, "sign-up"):
		category = "register"
	case strings.Contains(lowerPath, "mfa") || strings.Contains(lowerPath, "2fa") ||
		strings.Contains(lowerPath, "otp") || strings.Contains(lowerPath, "totp") ||
		strings.Contains(lowerPath, "verify") || strings.Contains(lowerPath, "challenge"):
		category = "mfa_otp"
	case strings.Contains(lowerPath, "reset") || strings.Contains(lowerPath, "forgot") ||
		strings.Contains(lowerPath, "recover"):
		category = "reset"
	}

	// A GET with no body on an auth path is usually the page, not the exchange. Still offered, but
	// the reason says so, so the user can judge.
	if upperMethod == "GET" && !bodyMatch {
		reason += " (GET, likely the page rather than the submission)"
	}

	return reason, category
}

// CreateAuthFlowFromCaptures handles POST /auth-flows/{scope_target_id}/from-captures.
//
// Steps are created with the response that was actually recorded, not by replaying. Replaying a
// login at import time would re-submit real credentials before the user has looked at them; the
// user can hit Replay explicitly once the flow is in front of them.
func CreateAuthFlowFromCaptures(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Category   string   `json:"category"`
		Name       string   `json:"name"`
		AuthType   string   `json:"auth_type"`
		CaptureIDs []string `json:"capture_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if !validAuthFlowCategories[payload.Category] {
		http.Error(w, "Invalid category (must be register, login, mfa_otp, or reset)", http.StatusBadRequest)
		return
	}
	if len(payload.CaptureIDs) == 0 {
		http.Error(w, "capture_ids is required", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		payload.Name = "Imported from manual crawl"
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, url, endpoint, method, status_code, headers, response_headers,
		       COALESCE(post_data,''), COALESCE(response_body,''), timestamp
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND id = ANY($2)
		ORDER BY timestamp ASC`, scopeTargetID, payload.CaptureIDs)
	if err != nil {
		log.Printf("[CAPTURE-BRIDGE] Failed to load captures for import: %v", err)
		http.Error(w, "Failed to load captures", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type importStep struct {
		name            string
		rawRequest      string
		statusCode      *int
		responseHeaders map[string][]string
		responseBody    string
	}

	steps := []importStep{}
	baseURL := ""

	for rows.Next() {
		var id, urlStr, endpoint, method, postData, responseBody string
		var statusCode *int
		var headersJSON, responseHeadersJSON []byte
		var timestamp time.Time

		if err := rows.Scan(&id, &urlStr, &endpoint, &method, &statusCode, &headersJSON,
			&responseHeadersJSON, &postData, &responseBody, &timestamp); err != nil {
			continue
		}

		var headers map[string]interface{}
		json.Unmarshal(headersJSON, &headers)

		var flatResponseHeaders map[string]interface{}
		json.Unmarshal(responseHeadersJSON, &flatResponseHeaders)

		if baseURL == "" {
			if parsed, perr := url.Parse(urlStr); perr == nil && parsed.Host != "" {
				baseURL = parsed.Scheme + "://" + parsed.Host
			}
		}

		steps = append(steps, importStep{
			name:            fmt.Sprintf("%s %s", strings.ToUpper(method), endpoint),
			rawRequest:      BuildRawHTTPRequest(method, urlStr, headers, postData),
			statusCode:      statusCode,
			responseHeaders: expandHeaderMap(flatResponseHeaders),
			responseBody:    responseBody,
		})
	}

	if len(steps) == 0 {
		http.Error(w, "None of the given captures exist for this target", http.StatusBadRequest)
		return
	}

	flowID := uuid.New().String()
	description := fmt.Sprintf("Imported from %d recorded request(s) on %s",
		len(steps), time.Now().Format("2006-01-02 15:04"))

	if _, err := dbPool.Exec(context.Background(),
		`INSERT INTO auth_flows (id, scope_target_id, category, name, description, auth_type, base_url)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		flowID, scopeTargetID, payload.Category, payload.Name, description, payload.AuthType, baseURL); err != nil {
		log.Printf("[CAPTURE-BRIDGE] Failed to create auth flow: %v", err)
		http.Error(w, "Failed to create auth flow", http.StatusInternalServerError)
		return
	}

	for i, step := range steps {
		headersJSON, _ := json.Marshal(step.responseHeaders)
		if _, err := dbPool.Exec(context.Background(),
			`INSERT INTO auth_flow_steps
			   (id, auth_flow_id, step_order, name, raw_request, response_status, response_headers, response_body)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			uuid.New().String(), flowID, i+1, step.name, step.rawRequest,
			step.statusCode, headersJSON, step.responseBody); err != nil {
			log.Printf("[CAPTURE-BRIDGE] Failed to insert imported step: %v", err)
		}
	}

	log.Printf("[CAPTURE-BRIDGE] Imported %d steps into auth flow %s", len(steps), flowID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"id":         flowID,
		"name":       payload.Name,
		"category":   payload.Category,
		"base_url":   baseURL,
		"step_count": len(steps),
	})
}

// expandHeaderMap converts the flat header map captures store into the multi-value shape
// auth_flow_steps.response_headers uses (which is http.Header, so replay's cookie seeding works).
func expandHeaderMap(flat map[string]interface{}) map[string][]string {
	out := map[string][]string{}
	for name, value := range flat {
		text := stringifyHeaderValue(value)
		if text == "" {
			continue
		}
		out[canonicalHeaderName(name)] = []string{text}
	}
	return out
}

// ---------------------------------------------------------------------------
// Client identifier auto-detection
// ---------------------------------------------------------------------------

var (
	uuidPattern     = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	objectIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{24}$`)
	hexHashPattern  = regexp.MustCompile(`^[0-9a-fA-F]{32,64}$`)
	jwtPattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}$`)
	digitsPattern   = regexp.MustCompile(`^\d+$`)
	base64ish       = regexp.MustCompile(`^[A-Za-z0-9+/_-]{16,}={0,2}$`)

	// Names that mark a value as something a client uses to reach one specific object. These are
	// exactly the values worth swapping for another user's in an IDOR test.
	identifierKeyPattern = regexp.MustCompile(`(?i)(^|[_.-])(id|ids|uid|guid|uuid|gid|pk|key|ref|slug|handle|num|no|code|token|sid|session|account|acct|user|userid|customer|client|member|profile|org|organi[sz]ation|team|group|tenant|workspace|project|company|order|invoice|payment|transaction|subscription|booking|ticket|document|doc|file|folder|record|entity|resource|item|node|post|message|thread|conversation|channel|report|job|task|device|asset)($|[_.-])`)
)

// looksLikeIdentifier decides whether a value is shaped like a durable object reference rather
// than free text. Being strict here matters: the point of auto-detection is a short list worth
// testing, not every string in the traffic.
func looksLikeIdentifier(value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < 3 || len(v) > 512 {
		return false
	}
	if strings.ContainsAny(v, " \t\n\r") {
		return false
	}

	switch {
	case uuidPattern.MatchString(v):
		return true
	case objectIDPattern.MatchString(v):
		return true
	case jwtPattern.MatchString(v):
		return true
	case hexHashPattern.MatchString(v):
		return true
	case digitsPattern.MatchString(v) && len(v) >= 3:
		return true
	case base64ish.MatchString(v) && hasDigitAndLetter(v):
		return true
	}
	return false
}

func hasDigitAndLetter(s string) bool {
	var digit, letter bool
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
			digit = true
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			letter = true
		}
	}
	return digit && letter
}

// Registered JWT claims that name who or what the token is for. These are matched by claim name
// because their values are often plain (a bare number, an email, a slug) and would not pass the
// shape test on their own.
var jwtIdentityClaims = map[string]bool{
	"sub": true, "uid": true, "user_id": true, "userid": true, "user": true,
	"email": true, "preferred_username": true, "upn": true, "unique_name": true,
	"oid": true, "tid": true, "tenant": true, "tenant_id": true, "org": true, "org_id": true,
	"account": true, "account_id": true, "customer_id": true, "azp": true,
	"client_id": true, "cid": true, "sid": true, "session_id": true, "jti": true,
}

// Timestamps and lifetimes are never object references.
var jwtTimeClaims = map[string]bool{
	"iat": true, "exp": true, "nbf": true, "auth_time": true, "updated_at": true,
}

type detectedIdentifier struct {
	EndpointURL string
	Method      string
	Value       string
	Label       string
}

// AutoDetectClientIdentifiers handles POST /authz/client-identifiers/{scope_target_id}/auto-detect.
//
// Walks recorded traffic (path segments, query values, request bodies, response bodies, cookies,
// and bearer tokens) and records every value shaped like an object reference. Response bodies
// matter as much as requests: that is where the other identifiers you would substitute come from.
func AutoDetectClientIdentifiers(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	rows, err := dbPool.Query(context.Background(), `
		SELECT url, method, headers, COALESCE(post_data,''), COALESCE(response_body,''),
		       COALESCE(mime_type,'')
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY timestamp ASC`, scopeTargetID)
	if err != nil {
		log.Printf("[CAPTURE-BRIDGE] Failed to query captures for auto-detect: %v", err)
		http.Error(w, "Failed to query captures", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	// Keyed on endpoint+method+value so the same id seen on every request is recorded once.
	found := map[string]detectedIdentifier{}
	capturesScanned := 0

	for rows.Next() {
		var urlStr, method, postData, responseBody, mimeType string
		var headersJSON []byte
		if err := rows.Scan(&urlStr, &method, &headersJSON, &postData, &responseBody, &mimeType); err != nil {
			continue
		}
		capturesScanned++

		var headers map[string]interface{}
		json.Unmarshal(headersJSON, &headers)

		method = strings.ToUpper(method)
		normalizedURL := normalizeURLForMatch(urlStr)

		add := func(value, label string) {
			value = strings.TrimSpace(value)
			if value == "" || len(value) > 512 {
				return
			}
			key := normalizedURL + "|" + method + "|" + value
			if _, exists := found[key]; exists {
				return
			}
			found[key] = detectedIdentifier{
				EndpointURL: normalizedURL,
				Method:      method,
				Value:       value,
				Label:       label,
			}
		}

		collectIdentifiersFromURL(urlStr, add)
		collectIdentifiersFromHeaders(headers, add)

		if postData != "" {
			collectIdentifiersFromBody(postData, "request body", add)
		}
		// Only text payloads; a description of a binary body has nothing to find.
		if responseBody != "" && isTextualResponse(mimeType) {
			collectIdentifiersFromBody(responseBody, "response body", add)
		}
	}

	inserted := 0
	for _, item := range found {
		var id string
		err := dbPool.QueryRow(context.Background(),
			`INSERT INTO authz_client_identifiers (id, scope_target_id, endpoint_url, method, value, source, label)
			 VALUES ($1, $2, $3, $4, $5, 'auto', $6)
			 ON CONFLICT (scope_target_id, endpoint_url, method, value) DO NOTHING
			 RETURNING id`,
			uuid.New().String(), scopeTargetID, item.EndpointURL, item.Method, item.Value, item.Label).Scan(&id)
		if err == nil {
			inserted++
		}
	}

	log.Printf("[CAPTURE-BRIDGE] Auto-detect scanned %d captures, found %d candidates, inserted %d new",
		capturesScanned, len(found), inserted)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"captures_scanned": capturesScanned,
		"candidates_found": len(found),
		"inserted":         inserted,
	})
}

func isTextualResponse(mimeType string) bool {
	mime := strings.ToLower(strings.TrimSpace(strings.Split(mimeType, ";")[0]))
	if mime == "" {
		return true
	}
	for _, prefix := range []string{"image/", "video/", "audio/", "font/"} {
		if strings.HasPrefix(mime, prefix) {
			return false
		}
	}
	return !strings.Contains(mime, "octet-stream") && !strings.Contains(mime, "pdf") && !strings.Contains(mime, "zip")
}

func collectIdentifiersFromURL(rawURL string, add func(value, label string)) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	for _, segment := range strings.Split(strings.Trim(parsed.Path, "/"), "/") {
		if segment != "" && looksLikeIdentifier(segment) {
			add(segment, "path segment")
		}
	}

	for key, values := range parsed.Query() {
		for _, value := range values {
			if looksLikeIdentifier(value) || (identifierKeyPattern.MatchString(key) && value != "") {
				add(value, "query param "+key)
			}
		}
	}
}

func collectIdentifiersFromHeaders(headers map[string]interface{}, add func(value, label string)) {
	if authz := headerString(headers, "authorization"); authz != "" {
		parts := strings.SplitN(authz, " ", 2)
		token := authz
		scheme := "authorization"
		if len(parts) == 2 {
			scheme = strings.ToLower(parts[0])
			token = strings.TrimSpace(parts[1])
		}
		if token != "" {
			add(token, scheme+" token")
			// A JWT's own claims are frequently the exact user or tenant id an access check keys
			// on, and they are the first thing to try changing. Standard identity claims are
			// matched by name rather than by value shape: `sub` is often a bare number and a
			// tenant is often a slug, neither of which looks like an identifier on its own.
			for claimKey, claimValue := range decodeJWTClaims(token) {
				if jwtTimeClaims[strings.ToLower(claimKey)] {
					continue
				}
				if claimValue == "" || len(claimValue) > 256 {
					continue
				}
				if jwtIdentityClaims[strings.ToLower(claimKey)] || identifierKeyPattern.MatchString(claimKey) ||
					looksLikeIdentifier(claimValue) {
					add(claimValue, "jwt claim "+claimKey)
				}
			}
		}
	}

	if cookieHeader := headerString(headers, "cookie"); cookieHeader != "" {
		for _, pair := range strings.Split(cookieHeader, ";") {
			bits := strings.SplitN(strings.TrimSpace(pair), "=", 2)
			if len(bits) != 2 {
				continue
			}
			name, value := bits[0], bits[1]
			if value != "" && (looksLikeIdentifier(value) || identifierKeyPattern.MatchString(name)) {
				add(value, "cookie "+name)
			}
		}
	}
}

// decodeJWTClaims returns the payload of a JWT as flat string values. Signature is irrelevant here;
// we are reading what the client presents, not trusting it.
func decodeJWTClaims(token string) map[string]string {
	claims := map[string]string{}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return claims
	}
	decoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims
	}
	var payload map[string]interface{}
	if json.Unmarshal(decoded, &payload) != nil {
		return claims
	}
	for key, value := range payload {
		switch v := value.(type) {
		case string:
			claims[key] = v
		case float64:
			claims[key] = strings.TrimSuffix(fmt.Sprintf("%.0f", v), ".0")
		}
	}
	return claims
}

// collectIdentifiersFromBody walks a JSON document (or a form-encoded body) and records values
// whose key names them as an object reference, or whose shape gives them away.
func collectIdentifiersFromBody(body, label string, add func(value, label string)) {
	trimmed := strings.TrimSpace(body)

	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		var parsed interface{}
		if json.Unmarshal([]byte(trimmed), &parsed) == nil {
			walkJSONForIdentifiers(parsed, "", label, 0, add)
			return
		}
	}

	// Form-encoded fallback.
	if values, err := url.ParseQuery(trimmed); err == nil {
		for key, list := range values {
			for _, value := range list {
				if identifierKeyPattern.MatchString(key) && value != "" && len(value) <= 512 {
					add(value, label+" field "+key)
				} else if looksLikeIdentifier(value) {
					add(value, label+" field "+key)
				}
			}
		}
	}
}

// walkJSONForIdentifiers recurses with a depth cap so a deeply nested or hostile document cannot
// blow the stack.
func walkJSONForIdentifiers(node interface{}, keyPath, label string, depth int, add func(value, label string)) {
	if depth > 12 {
		return
	}

	switch typed := node.(type) {
	case map[string]interface{}:
		for key, value := range typed {
			childPath := key
			if keyPath != "" {
				childPath = keyPath + "." + key
			}
			walkJSONForIdentifiers(value, childPath, label, depth+1, add)
		}
	case []interface{}:
		// Only the first few elements of a list: a hundred rows of the same shape add nothing.
		for i, value := range typed {
			if i >= 5 {
				break
			}
			walkJSONForIdentifiers(value, keyPath, label, depth+1, add)
		}
	case string:
		leaf := leafKey(keyPath)
		if identifierKeyPattern.MatchString(leaf) && typed != "" && len(typed) <= 512 {
			add(typed, label+" "+keyPath)
		} else if looksLikeIdentifier(typed) {
			add(typed, label+" "+keyPath)
		}
	case float64:
		leaf := leafKey(keyPath)
		if identifierKeyPattern.MatchString(leaf) {
			add(strings.TrimSuffix(fmt.Sprintf("%.0f", typed), ".0"), label+" "+keyPath)
		}
	}
}

func leafKey(keyPath string) string {
	if idx := strings.LastIndex(keyPath, "."); idx >= 0 {
		return keyPath[idx+1:]
	}
	return keyPath
}

// ---------------------------------------------------------------------------
// Investigation and validation both use the host-scoped ScopedAuthContext in scanCredentials.go.
// A second, target-wide credential loader used to live here: it chose one capture by recency with
// no host match, could not see the Session Manager, and stamped every result authenticated whether
// or not anything was attached. It is gone rather than deprecated, because leaving a divergent
// credential path in the tree is how the two implementations drifted apart in the first place.

// normalizeURLForMatch strips the query and trailing slash so a captured request can be matched to
// a stored endpoint. It is a display-level match, not the identity function: canonical identity
// lives in endpointIdentity.go and is what consolidation keys on.
func normalizeURLForMatch(urlStr string) string {
	urlStr = strings.TrimSpace(urlStr)
	urlStr = strings.TrimSuffix(urlStr, ".")
	// A scheme is only added when there is none.
	//
	// Testing for the http prefixes specifically meant any other scheme got one prefixed onto it:
	// a captured websocket URL wss://web.example/iojs/star became https://wss://web.example/iojs/star,
	// whose host parses as "wss". Two of those reached the live endpoint corpus and were requested
	// as though they were real HTTP endpoints. Leaving a foreign scheme intact lets
	// CanonicalizeEndpoint reject it, which is what it is there for.
	if !strings.Contains(urlStr, "://") {
		urlStr = "https://" + urlStr
	}
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return strings.TrimSuffix(urlStr, "/")
	}
	parsed.Host = strings.TrimSuffix(parsed.Host, ".")
	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	if parsed.Path == "" {
		parsed.Path = "/"
	}
	parsed.Fragment = ""
	parsed.RawQuery = ""
	return parsed.String()
}
