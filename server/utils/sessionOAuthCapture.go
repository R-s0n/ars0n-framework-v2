package utils

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// OAuth token capture (docs/OAUTH_REFRESH_DESIGN.md, Phase 2).
//
// A token endpoint response is the richest thing a login capture holds: the access_token is the
// session, the refresh_token renews it and the id_token names the principal. Today ParseOAuthTokenResponse
// reads them but only into a transient profile attribute that is never persisted, so the refresh token,
// the one value that could renew the session headlessly, is thrown away. captureOAuthTriad makes them
// durable: it stores the access token as a credential row and the refresh token as a refresh-role row
// (spent to mint, never sent), linked by refresh_token_id, so a later phase can replay the refresh.
//
// SCOPE OF PHASE 2: access + refresh. The id_token is deliberately NOT stored yet. It is not a resource
// credential and must never go on the wire, but the only roles that keep a value off the wire today are
// 'refresh' (wrong name for it) and an inactive row; its correct home (an informational, non-wired role)
// is settled in a later phase. Storing it now as a 'companion' would attach it to every scan request,
// which is wrong, so it waits.

// ttlToExpiry turns a declared expires_in into an absolute expiry (observedAt + ttl), or nil when the
// server declared none. observedAt is WHEN the response was seen, not now: a token endpoint response
// captured three hours ago issued a one-hour token that is already dead, so computing from now would
// overstate its life by three hours (and a stale opaque token would be attached to scans as if live).
// Passed to DeriveSessionTokenExpiry as the explicit value, so an opaque access token finally carries a
// real lifetime (otherwise stored as never-expires, which defeats the auto-refresh lead window). UTC, to
// match jwtExpiry / DeriveSessionTokenExpiry and the timestamp columns; a local-time value written to a
// timestamp-without-time-zone column reads back shifted by the machine's offset.
func ttlToExpiry(observedAt time.Time, ttl time.Duration, known bool) *time.Time {
	if !known || ttl <= 0 {
		return nil
	}
	t := observedAt.UTC().Add(ttl)
	return &t
}

// oauthRowName is the display name for a captured OAuth row.
func oauthRowName(kind CredentialKind) string {
	switch kind {
	case CredentialKindOAuthAccess:
		return "OAuth access token (captured)"
	case CredentialKindOAuthRefresh:
		return "OAuth refresh token (captured)"
	default:
		return "OAuth token (captured)"
	}
}

// CaptureOAuthResult reports what a single token-response promotion did.
type CaptureOAuthResult struct {
	AccessTokenID  string `json:"access_token_id,omitempty"`
	RefreshTokenID string `json:"refresh_token_id,omitempty"`
	HasRefresh     bool   `json:"has_refresh"`
	Detail         string `json:"detail"`
}

// upsertOAuthTokenRow writes one captured OAuth row, keyed so a re-capture updates the same row rather
// than adding a second. Identity is (scope_target_id, name): the name is a fixed per-kind string this
// function owns, and NOTHING else rewrites it, so the identity survives the read-path reprofiler.
//
// credential_kind must NOT be the key: it is the profiler's field, and AttachSessionTokenProfiles
// re-measures a freshly captured row (its profiled_at/fingerprint are unset) and rewrites credential_kind
// from the token's bytes (a JWT access token becomes 'jwt', an opaque one 'opaque_bearer'), which would
// make a later credential_kind-keyed upsert miss the row, insert a duplicate, and orphan the prior
// (still-sendable) access token. So credential_kind is set only as an initial hint on INSERT and is left
// to the profiler thereafter; the row is found by name regardless.
func upsertOAuthTokenRow(ctx context.Context, scopeTargetID, host string, kind CredentialKind, role, value string, expiresAt *time.Time, refreshTokenID string) (string, error) {
	if strings.TrimSpace(value) == "" {
		return "", fmt.Errorf("no value to store for %s", kind)
	}
	scope := []string{}
	if strings.TrimSpace(host) != "" {
		scope = []string{host}
	}
	// The access token is sent as an Authorization: Bearer header. The refresh token is never sent
	// (role='refresh' excludes it from every wire path), so it needs no header slot; it is stored as a
	// bearer type only to satisfy the token_type enum.
	tokenType := tokenTypeBearer
	headerName, valuePrefix := "", ""
	if role == tokenRoleCredential {
		headerName, valuePrefix = "Authorization", "Bearer "
	}
	name := oauthRowName(kind)

	var existingID string
	scanErr := dbPool.QueryRow(ctx,
		`SELECT id::text FROM session_tokens WHERE scope_target_id = $1 AND name = $2
		 ORDER BY created_at ASC LIMIT 1`, scopeTargetID, name).Scan(&existingID)

	if scanErr != nil || existingID == "" {
		var id string
		err := dbPool.QueryRow(ctx, `
			INSERT INTO session_tokens
			  (scope_target_id, name, token_type, token_role, header_name, value_prefix, token_value,
			   scope_domains, expires_at, is_active, credential_kind, refresh_token_id)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,TRUE,$10,$11)
			RETURNING id::text`,
			scopeTargetID, name, tokenType, role, headerName, valuePrefix, value,
			scope, expiresAt, string(kind), nullUUID(refreshTokenID)).Scan(&id)
		if err != nil {
			return "", err
		}
		recordSessionTokenEvent(id, "capture", "created",
			fmt.Sprintf("Captured from an OAuth token endpoint response as a %s.", kind), nil)
		return id, nil
	}

	// Update in place: a re-capture is the normal case (the session was renewed and a fresh token
	// response arrived). token_role is re-asserted (in case a profiler or edit changed it), but
	// credential_kind is left to the profiler. The stored verdict described the old value, so it is
	// cleared. refresh_token_id is preserved when no new link is supplied (COALESCE).
	_, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET
		  token_value = $1, expires_at = $2, token_role = $3, header_name = $4,
		  value_prefix = $5, token_type = $6, refresh_token_id = COALESCE($7, refresh_token_id),
		  is_active = TRUE, last_validation_status = '', last_validation_detail = '', updated_at = NOW()
		WHERE id = $8`,
		value, expiresAt, role, headerName, valuePrefix, tokenType,
		nullUUID(refreshTokenID), existingID)
	if err != nil {
		return "", err
	}
	recordSessionTokenEvent(existingID, "capture", "updated",
		fmt.Sprintf("Refreshed the stored %s from a newer OAuth token endpoint response.", kind), nil)
	return existingID, nil
}

// captureOAuthTriad promotes one token-endpoint response body into durable rows: the refresh token (so
// the access row can link to it) then the access token linked to it. Returns ok=false when the body is
// not a token response carrying an access_token, which is not an error, just nothing to promote.
func captureOAuthTriad(ctx context.Context, scopeTargetID, host, respBody string, observedAt time.Time) (CaptureOAuthResult, bool, error) {
	parsed, isToken := ParseOAuthTokenResponse(respBody)
	if !isToken || !parsed.HasAccessToken || strings.TrimSpace(parsed.AccessToken) == "" {
		return CaptureOAuthResult{}, false, nil
	}

	var res CaptureOAuthResult
	// Refresh first, so the access row can carry the link.
	if parsed.HasRefreshToken && strings.TrimSpace(parsed.RefreshToken) != "" {
		rExp := ttlToExpiry(observedAt, parsed.RefreshTTL, parsed.RefreshTTLKnown)
		rExp = DeriveSessionTokenExpiry(parsed.RefreshToken, rExp) // a JWT refresh token states its own exp
		id, err := upsertOAuthTokenRow(ctx, scopeTargetID, host, CredentialKindOAuthRefresh, tokenRoleRefresh, parsed.RefreshToken, rExp, "")
		if err != nil {
			return res, true, fmt.Errorf("store refresh token: %w", err)
		}
		res.RefreshTokenID = id
		res.HasRefresh = true
	}

	// Access token, linked to the refresh row. expires_in (observedAt + ttl) becomes the explicit expiry
	// so an opaque access token gets a real lifetime; a JWT access token's own exp is used when there is
	// none. Using observedAt, not now, means a stale capture stores an already-passed expiry rather than
	// an inflated one, so a dead token is not attached to scans.
	aExp := ttlToExpiry(observedAt, parsed.ExpiresIn, parsed.ExpiresInKnown)
	aExp = DeriveSessionTokenExpiry(parsed.AccessToken, aExp)
	id, err := upsertOAuthTokenRow(ctx, scopeTargetID, host, CredentialKindOAuthAccess, tokenRoleCredential, parsed.AccessToken, aExp, res.RefreshTokenID)
	if err != nil {
		return res, true, fmt.Errorf("store access token: %w", err)
	}
	res.AccessTokenID = id

	if res.HasRefresh {
		res.Detail = "Stored the access token as a credential and the refresh token as a linked refresh secret."
	} else {
		res.Detail = "Stored the access token as a credential. No refresh_token was in the response, so the session cannot be renewed headlessly from this capture."
	}
	return res, true, nil
}

// CaptureOAuthTriadForTarget scans the manual-crawl corpus for this target's freshest token-endpoint
// responses and promotes them. It picks the newest capture that carries an access_token and the newest
// that carries a refresh_token (which may be an earlier capture, since the refresh token usually arrives
// only at the first login while the access token rotates), so the stored pair is the current one.
func CaptureOAuthTriadForTarget(ctx context.Context, scopeTargetID string) (CaptureOAuthResult, bool, error) {
	if dbPool == nil {
		return CaptureOAuthResult{}, false, fmt.Errorf("no database connection")
	}
	// credential_kind is a profile column ensured lazily; make sure it exists before we key on it.
	if err := EnsureSessionTokenProfileSchema(ctx); err != nil {
		return CaptureOAuthResult{}, false, fmt.Errorf("ensure schema: %w", err)
	}

	rows, err := dbPool.Query(ctx, `
		SELECT COALESCE(response_body,''), timestamp
		FROM manual_crawl_captures
		WHERE scope_target_id = $1 AND response_body IS NOT NULL
		  AND response_body ~ '"(access_token|refresh_token)"'
		ORDER BY timestamp DESC
		LIMIT 500`, scopeTargetID)
	if err != nil {
		return CaptureOAuthResult{}, false, err
	}
	defer rows.Close()

	// Walk newest first; keep the first body that has an access_token and the first that has a refresh,
	// with the capture time of each so expiry is computed from when it was seen, not now.
	var accessBody, refreshBody string
	var accessAt, refreshAt time.Time
	for rows.Next() {
		var body string
		var ts *time.Time
		if rows.Scan(&body, &ts) != nil {
			continue
		}
		observed := time.Now().UTC()
		if ts != nil {
			observed = ts.UTC()
		}
		parsed, ok := ParseOAuthTokenResponse(body)
		if !ok {
			continue
		}
		if accessBody == "" && parsed.HasAccessToken && strings.TrimSpace(parsed.AccessToken) != "" {
			accessBody, accessAt = body, observed
		}
		if refreshBody == "" && parsed.HasRefreshToken && strings.TrimSpace(parsed.RefreshToken) != "" {
			refreshBody, refreshAt = body, observed
		}
		if accessBody != "" && refreshBody != "" {
			break
		}
	}
	if accessBody == "" {
		return CaptureOAuthResult{}, false, nil // nothing token-shaped in the corpus (e.g. a BFF target)
	}

	host := scopeTargetHost(scopeTargetID)

	// If the newest access-bearing body has no refresh but an earlier body does, splice the refresh in
	// by promoting the refresh row from the refresh body first, then the access from the access body.
	res := CaptureOAuthResult{}
	if refreshBody != "" && refreshBody != accessBody {
		if rParsed, ok := ParseOAuthTokenResponse(refreshBody); ok && rParsed.HasRefreshToken {
			rExp := ttlToExpiry(refreshAt, rParsed.RefreshTTL, rParsed.RefreshTTLKnown)
			rExp = DeriveSessionTokenExpiry(rParsed.RefreshToken, rExp)
			if id, err := upsertOAuthTokenRow(ctx, scopeTargetID, host, CredentialKindOAuthRefresh, tokenRoleRefresh, rParsed.RefreshToken, rExp, ""); err == nil {
				res.RefreshTokenID = id
				res.HasRefresh = true
			} else {
				return res, true, fmt.Errorf("store refresh token: %w", err)
			}
		}
	}

	// Promote the access body (and its own refresh, if it carried one). captureOAuthTriad links the
	// access row to whatever refresh row it creates; when we already made one above, link to that.
	triad, promoted, err := captureOAuthTriad(ctx, scopeTargetID, host, accessBody, accessAt)
	if err != nil {
		return res, true, err
	}
	if !promoted {
		return res, false, nil
	}
	if res.RefreshTokenID != "" && triad.RefreshTokenID == "" {
		// The access body had no refresh of its own; relink the access row to the earlier refresh row.
		if _, err := dbPool.Exec(ctx,
			`UPDATE session_tokens SET refresh_token_id = $1, updated_at = NOW() WHERE id = $2`,
			nullUUID(res.RefreshTokenID), triad.AccessTokenID); err != nil {
			log.Printf("[OAUTH-CAPTURE] could not link access %s to refresh %s: %v", triad.AccessTokenID, res.RefreshTokenID, err)
		}
	} else {
		res.RefreshTokenID = triad.RefreshTokenID
		res.HasRefresh = triad.HasRefresh
	}
	res.AccessTokenID = triad.AccessTokenID
	if res.HasRefresh {
		res.Detail = "Stored the access token as a credential and the refresh token as a linked refresh secret."
	} else {
		res.Detail = "Stored the access token as a credential. No refresh_token was found in the corpus, so the session cannot be renewed headlessly."
	}
	return res, true, nil
}

// CaptureOAuthTokens handles POST /session-tokens/target/{scope_target_id}/capture-oauth. It promotes
// the freshest OAuth token-endpoint response in the corpus into durable access + refresh rows.
func CaptureOAuthTokens(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeSessionTokenJSON(w, http.StatusBadRequest, map[string]interface{}{"error": "scope_target_id must be a UUID"})
		return
	}
	res, promoted, err := CaptureOAuthTriadForTarget(context.Background(), scopeTargetID)
	if err != nil {
		log.Printf("[OAUTH-CAPTURE] target %s: %v", scopeTargetID, err)
		writeSessionTokenJSON(w, http.StatusInternalServerError, map[string]interface{}{"error": "could not capture OAuth tokens: " + err.Error()})
		return
	}
	if !promoted {
		writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
			"status": "no_token_response",
			"detail": "No OAuth token endpoint response with an access_token was found in this target's captures. A confidential-client / BFF app (tokens never reach the browser) has nothing to capture here; refresh it by re-capturing the session cookie instead.",
		})
		return
	}
	writeSessionTokenJSON(w, http.StatusOK, map[string]interface{}{
		"status":           "captured",
		"detail":           res.Detail,
		"access_token_id":  res.AccessTokenID,
		"refresh_token_id": res.RefreshTokenID,
		"has_refresh":      res.HasRefresh,
	})
}
