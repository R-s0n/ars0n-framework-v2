package utils

import (
	"context"
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

// OAuth flow detection + adoption (docs/OAUTH_REFRESH_DESIGN.md, Phase 4).
//
// Detection tells a REFRESH exchange (grant_type=refresh_token, or a silent /auth/refresh|/session/renew
// call) apart from a CREATION exchange (grant_type=authorization_code, an IdP-host hop, a single-use
// ?code=/?state=), so the operator can find the app's own silent-refresh request in the capture list.
// Adoption then builds a headless refresh flow from that request: it seeds {{token:refresh_token}} where
// the captured refresh token sat, so at replay the CURRENT stored refresh token is spent, and links the
// flow as the anchor token's refresh_flow_id.
//
// The grant_type value lives ONLY in the request body and no existing helper reads it (ParseOAuthTokenResponse
// is response-only and JSON-only; refreshEndpointPatterns is URL-only), so extractGrantType is new.

const (
	oauthRoleCreation = "creation_exchange"
	oauthRoleRefresh  = "refresh_request"
)

// reSilentRenewPath matches paths that are UNAMBIGUOUSLY a session renew (not /token or /authorize, which
// serve both creation and refresh depending on grant_type).
var reSilentRenewPath = regexp.MustCompile(`(?i)/((auth|session|tokens?)/refresh|refresh[-_]?token|silent[-_]?renew|session/renew)`)

// reAuthorizePath matches the interactive authorize endpoint, which begins a CREATION exchange.
var reAuthorizePath = regexp.MustCompile(`(?i)/(oauth2?|connect)/authorize`)

// extractGrantType reads grant_type out of a request body, whether form-urlencoded or JSON. Returns "" when
// the body carries none (a body-blind caller then falls back to path/redirect signals).
func extractGrantType(body string) string {
	b := strings.TrimSpace(body)
	if b == "" {
		return ""
	}
	// JSON first. A JSON body must NOT be form-parsed: url.ParseQuery splits on '&', so an embedded
	// "...&grant_type=..." inside a string value (e.g. a redirect_uri query) would yield a spurious
	// grant_type and hide the real one. A form body is not a valid JSON object, so json.Unmarshal fails
	// and control falls through to the form parse.
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(b), &m) == nil {
		if raw, ok := m["grant_type"]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				return strings.ToLower(strings.TrimSpace(s))
			}
		}
		return "" // a valid JSON object with no top-level grant_type; never fall through to form parsing
	}
	// form-urlencoded: grant_type=refresh_token&...
	if vals, err := url.ParseQuery(b); err == nil {
		if gt := strings.TrimSpace(vals.Get("grant_type")); gt != "" {
			return strings.ToLower(gt)
		}
	}
	return ""
}

// oauthCaptureRole classifies one captured request as an OAuth creation or refresh exchange, or "" when it
// is neither / cannot be told. grant_type (the request body) is the primary, unambiguous signal because
// the SAME /oauth2/token URL serves both a first login (authorization_code) and a refresh (refresh_token);
// path and redirect signals are the body-blind fallback.
func oauthCaptureRole(urlStr, method, body string) string {
	switch extractGrantType(body) {
	case "refresh_token":
		return oauthRoleRefresh
	case "authorization_code", "password", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code":
		return oauthRoleCreation
	}
	// No grant_type: fall back to path and single-use / IdP-host signals.
	if reSingleUse.MatchString(urlStr) || reIdPHost.MatchString(strings.ToLower(urlStr)) || reAuthorizePath.MatchString(urlStr) {
		return oauthRoleCreation
	}
	if reSilentRenewPath.MatchString(urlStr) {
		return oauthRoleRefresh
	}
	return ""
}

// reFormRefreshToken requires a delimiter (start of body, & ? or ;) before refresh_token= so it matches
// the refresh_token FIELD only, not a longer field whose name merely ends in refresh_token
// (x_refresh_token, device_refresh_token, ...). Group 1 is the delimiter, group 2 the "refresh_token=".
var reFormRefreshToken = regexp.MustCompile(`(?i)(^|[&?;])(refresh_token=)[^&\s]+`)
var reJSONRefreshToken = regexp.MustCompile(`(?i)("refresh_token"\s*:\s*")[^"]*(")`)

// seedRefreshTokenPlaceholder rewrites a request body so the captured refresh_token literal becomes the
// {{token:refresh_token}} placeholder, which the runner resolves to the CURRENT stored refresh token at
// replay. Returns the rewritten body and whether a refresh_token was found to seed. Handles form and JSON.
func seedRefreshTokenPlaceholder(body string) (string, bool) {
	if strings.Contains(body, "{{token:refresh_token}}") {
		return body, true // already templatized (idempotent re-adopt)
	}
	if reFormRefreshToken.MatchString(body) {
		return reFormRefreshToken.ReplaceAllString(body, "${1}${2}{{token:refresh_token}}"), true
	}
	if reJSONRefreshToken.MatchString(body) {
		return reJSONRefreshToken.ReplaceAllString(body, "${1}{{token:refresh_token}}${2}"), true
	}
	return body, false
}

// oauthResponseExtractions is the declarative capture set attached to a step whose response is an OAuth
// token response. The OAuth writeback (writebackRefreshResponse) is what actually mints/rotates via
// ParseOAuthTokenResponse, so these are for display and the generic single-value fallback; they are
// Optional so a step whose response is not JSON never refuses.
func oauthResponseExtractions() []AuthFlowExtraction {
	return []AuthFlowExtraction{
		{Name: "access_token", Source: "body", Pattern: `"access_token"\s*:\s*"([^"]+)"`, Decode: "none", Optional: true},
		{Name: "refresh_token", Source: "body", Pattern: `"refresh_token"\s*:\s*"([^"]+)"`, Decode: "none", Optional: true},
	}
}

// BuildRefreshFlowFromCaptures handles POST /auth-flows/{scope_target_id}/refresh-from-captures.
//
// It builds a flow_purpose='refresh' auth flow from the selected captured request(s) (the app's own
// silent-refresh call), templatizes the refresh token into {{token:refresh_token}}, attaches OAuth
// response extractions, and, when an anchor token is given, links the flow as its refresh_flow_id with
// refresh_strategy (default oauth_refresh_grant). From then on RefreshSessionToken/startSessionRefreshRun
// route to this flow automatically (refreshFlowIDFor).
func BuildRefreshFlowFromCaptures(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	w.Header().Set("Content-Type", "application/json")

	var payload struct {
		Name            string   `json:"name"`
		CaptureIDs      []string `json:"capture_ids"`
		AnchorTokenID   string   `json:"anchor_token_id"`
		RefreshStrategy string   `json:"refresh_strategy"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "Invalid request body"})
		return
	}
	if len(payload.CaptureIDs) == 0 {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "capture_ids is required"})
		return
	}
	if strings.TrimSpace(payload.Name) == "" {
		payload.Name = "OAuth refresh flow (from capture)"
	}
	strategy := strings.TrimSpace(payload.RefreshStrategy)
	if strategy == "" {
		strategy = "oauth_refresh_grant"
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT id, url, endpoint, method, status_code, headers, response_headers,
		       COALESCE(post_data,''), COALESCE(response_body,''), timestamp
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND id = ANY($2)
		ORDER BY timestamp ASC`, scopeTargetID, payload.CaptureIDs)
	if err != nil {
		log.Printf("[OAUTH-ADOPT] load captures failed: %v", err)
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Failed to load captures"})
		return
	}
	defer rows.Close()

	type step struct {
		name            string
		rawRequest      string
		statusCode      *int
		responseHeaders map[string][]string
		responseBody    string
		extractions     []AuthFlowExtraction
	}
	var steps []step
	baseURL := ""
	seededAny := false

	for rows.Next() {
		var id, urlStr, endpoint, method, postData, responseBody string
		var statusCode *int
		var headersJSON, responseHeadersJSON []byte
		var ts time.Time
		if err := rows.Scan(&id, &urlStr, &endpoint, &method, &statusCode, &headersJSON,
			&responseHeadersJSON, &postData, &responseBody, &ts); err != nil {
			continue
		}
		var headers map[string]interface{}
		json.Unmarshal(headersJSON, &headers)
		var flatResp map[string]interface{}
		json.Unmarshal(responseHeadersJSON, &flatResp)

		if baseURL == "" {
			if parsed, perr := url.Parse(urlStr); perr == nil && parsed.Host != "" {
				baseURL = parsed.Scheme + "://" + parsed.Host
			}
		}

		seededPost, didSeed := seedRefreshTokenPlaceholder(postData)
		if didSeed {
			seededAny = true
		}
		var extractions []AuthFlowExtraction
		if parsed, ok := ParseOAuthTokenResponse(responseBody); ok && parsed.HasAccessToken {
			extractions = oauthResponseExtractions()
		}
		steps = append(steps, step{
			name:            fmt.Sprintf("%s %s", strings.ToUpper(method), endpoint),
			rawRequest:      BuildRawHTTPRequest(method, urlStr, headers, seededPost),
			statusCode:      statusCode,
			responseHeaders: expandHeaderMap(flatResp),
			responseBody:    responseBody,
			extractions:     extractions,
		})
	}

	if len(steps) == 0 {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "None of the given captures exist for this target"})
		return
	}
	if !seededAny {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error": "None of the selected captures carry a refresh_token to templatize. Select the request " +
				"that spends the refresh token (grant_type=refresh_token), so it can be replayed with the stored one.",
		})
		return
	}

	// category must be one of the valid set (a DB CHECK); the creation/refresh axis is flow_purpose, set
	// to 'refresh' here (this is the first Go writer of flow_purpose).
	flowID := uuid.New().String()
	description := fmt.Sprintf("Adopted as a refresh flow from %d recorded request(s) on %s",
		len(steps), time.Now().Format("2006-01-02 15:04"))
	if _, err := dbPool.Exec(context.Background(),
		`INSERT INTO auth_flows (id, scope_target_id, category, name, description, base_url, flow_purpose)
		 VALUES ($1,$2,'login',$3,$4,$5,'refresh')`,
		flowID, scopeTargetID, payload.Name, description, baseURL); err != nil {
		log.Printf("[OAUTH-ADOPT] create flow failed: %v", err)
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Failed to create refresh flow"})
		return
	}
	for i, s := range steps {
		respHeadersJSON, _ := json.Marshal(s.responseHeaders)
		extractionsJSON, _ := json.Marshal(s.extractions)
		if len(s.extractions) == 0 {
			extractionsJSON = []byte("[]")
		}
		if _, err := dbPool.Exec(context.Background(),
			`INSERT INTO auth_flow_steps
			   (id, auth_flow_id, step_order, name, raw_request, response_status, response_headers,
			    response_body, extractions)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			uuid.New().String(), flowID, i+1, s.name, s.rawRequest, s.statusCode, respHeadersJSON,
			s.responseBody, extractionsJSON); err != nil {
			log.Printf("[OAUTH-ADOPT] insert step failed: %v", err)
		}
	}

	// Whether the container can execute this refresh headlessly, or it is browser-only (Phase 6). Derived
	// from the flow just built: a pure /oauth2/token replay is headless; anything with a challenge / IdP
	// hop / pause is browser_only and refresh must go through the operator's browser (recapture).
	transport := deriveRefreshTransport(flowID)

	// Link the flow to the anchor token, if one was named. RowsAffected is checked because pgx returns a
	// nil error for a 0-row UPDATE, so a wrong/foreign anchor id must be reported, not silently ignored.
	linked := false
	if strings.TrimSpace(payload.AnchorTokenID) != "" {
		tag, uerr := dbPool.Exec(context.Background(),
			`UPDATE session_tokens SET refresh_flow_id = $1, refresh_strategy = $2, refresh_transport = $3,
			   updated_at = NOW()
			 WHERE id = $4 AND scope_target_id = $5`,
			nullUUID(flowID), strategy, transport, payload.AnchorTokenID, scopeTargetID)
		if uerr != nil {
			log.Printf("[OAUTH-ADOPT] link anchor failed: %v", uerr)
			writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "Built the flow but could not link it to the anchor token"})
			return
		}
		if tag.RowsAffected() == 0 {
			writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error": "Built the flow, but anchor_token_id was not found on this target, so it was not linked. Link it in Manage Sessions.",
				"id":    flowID,
			})
			return
		}
		linked = true
	}

	writeSessionTokenJSON(w, http.StatusCreated, map[string]interface{}{
		"id": flowID, "name": payload.Name, "base_url": baseURL, "step_count": len(steps),
		"flow_purpose": "refresh", "linked_anchor": linked, "refresh_strategy": strategy,
		"refresh_transport": transport,
	})
}

// deriveRefreshTransport maps a flow to whether the container can run it headlessly. A pure-replay flow
// (a token endpoint call with no IdP hop, bot challenge, single-use code, or interactive pause) is
// "headless"; anything else is "browser_only", meaning the refresh has to go through the operator's
// browser (recapture). "unknown" when the flow has no readable steps. This is a CAPABILITY fact, never a
// permission gate. A container that is Cloudflare-blocked at runtime is a further reason a flow that looks
// headless still fails; that dynamic refinement is left to the run, which reports the block.
func deriveRefreshTransport(flowID string) string {
	steps, err := getStepsByFlow(flowID)
	if err != nil || len(steps) == 0 {
		return "unknown"
	}
	kind, _, _ := ClassifyFlowRefreshability(steps)
	if kind == flowRefreshReplay {
		return "headless"
	}
	return "browser_only"
}
