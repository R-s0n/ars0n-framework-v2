package utils

// Durable headless session keeper (docs/OAUTH_REFRESH_DESIGN.md, keeper phase).
//
// The problem it solves: a short-lived bearer (the authx example is ~15 min) forces the operator to
// hit browser refresh or paste a token every few minutes, which is not a workflow. The keeper is a
// framework-run HEADLESS browser that holds the IdP session, loads the UNMODIFIED SPA, lets the app
// re-mint its own bearer, harvests the fresh value from its own network, and upserts it into
// session_tokens on a loop - so refresh is hands-free and needs no browser open and no pasting.
//
// THIS FILE is the Go control side. It owns policy (which keepers exist, their scope-derived egress
// allowlist, the cookie seed) and the store writeback. The browser itself lives in a separate
// long-running Puppeteer container (docker/session-keeper). The two talk over the shared temp_data
// volume by a file RECONCILIATION contract, not a network port, matching every other tool:
//
//	/tmp/session-keeper/desired/<id>.json   Go writes the wanted state; deleting it stops the keeper.
//	/tmp/session-keeper/harvest/<id>-<ts>.json  keeper writes a harvested credential; Go stores + deletes.
//	/tmp/session-keeper/status/<id>.json    keeper writes health; Go reads it into the row.
//
// SCOPE SAFETY: the keeper only ever runs the unmodified SPA's own requests (using the IdP, not
// testing it). Its egress allowlist is derived here from the SAME scope the scanners use -
// SuffixesByEffect over LoadScanScope - so it is exactly {in-scope hosts} UNION {classified auth
// hosts}, fail-closed. The keeper aborts everything else and never crafts or fuzzes a request. The
// attribution header is attached only on in-scope app requests, never to an auth host.
//
// SECURITY NOTE (operator-visible, deliberate v1 choice): the cookie seed can include a long-lived
// IdP refresh cookie, which is an account-takeover-grade credential for the operator's OWN test
// account. It is stored and served like all other captured material (the standing "capture is the
// point" rule), NOT encrypted at rest and NOT redacted from exports. The egress allowlist bounds
// where it can ever be sent (only the in-scope app + classified auth hosts the SPA itself calls).
// Encrypt-at-rest / redact-on-export for refresh-role material is a deliberate follow-up the operator
// decides, because it is a carve-out from a hard standing rule.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	keeperIPCRoot      = "/tmp/session-keeper"
	keeperDefaultCad   = 600 // seconds; a 10-min reload comfortably re-mints a 15-min bearer
	keeperMinCadence   = 120
	keeperDeadFailures = 5 // consecutive keeper-reported failures before the row is parked as error
)

// SessionKeeper is one durable keeper row: a (scope target, account) whose session is kept warm.
type SessionKeeper struct {
	ID                  string     `json:"id"`
	ScopeTargetID       string     `json:"scope_target_id"`
	Name                string     `json:"name"`
	TargetURL           string     `json:"target_url"`
	Enabled             bool       `json:"enabled"`
	Status              string     `json:"status"`
	CadenceSeconds      int        `json:"cadence_seconds"`
	LastReloadAt        *time.Time `json:"last_reload_at,omitempty"`
	LastHarvestAt       *time.Time `json:"last_harvest_at,omitempty"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastError           string     `json:"last_error"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// keeperCookie is one seeded cookie, shaped for Puppeteer/CDP setCookie on the keeper side.
type keeperCookie struct {
	Name     string `json:"name"`
	Value    string `json:"value"`
	Domain   string `json:"domain"`
	Path     string `json:"path"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"httpOnly"`
	SameSite string `json:"sameSite"`
}

// keeperDesired is the desired-state file the Go side writes and the keeper container reconciles.
type keeperDesired struct {
	KeeperID       string            `json:"keeper_id"`
	Name           string            `json:"name"`
	TargetURL      string            `json:"target_url"`
	Allowlist      []string          `json:"allowlist"`       // egress: in-scope UNION auth hosts
	InScopeHosts   []string          `json:"in_scope_hosts"`  // may carry the attribution header
	AuthHosts      []string          `json:"auth_hosts"`      // auth-only side; the header is NEVER attached here
	Cookies        []keeperCookie    `json:"cookies"`         // seed for first fill / re-seed
	CadenceSeconds int               `json:"cadence_seconds"` // reload interval
	ProgramHeaders map[string]string `json:"program_headers"` // attribution, in-scope requests only
	MaxRPS         float64           `json:"max_rps"`
	Generation     string            `json:"generation"` // bumped when the cookie seed changes -> re-seed
}

// keeperHarvest is what the keeper writes when it captures a fresh credential from its own network.
type keeperHarvest struct {
	KeeperID   string `json:"keeper_id"`
	Name       string `json:"name"`
	Host       string `json:"host"`
	ObservedAt string `json:"observed_at"` // RFC3339
	Kind       string `json:"kind"`        // oauth_token_response | bearer_header | cookie
	Body       string `json:"body"`        // raw token-endpoint JSON (oauth_token_response)
	Value      string `json:"value"`       // "Bearer x" / cookie string (bearer_header | cookie)
}

// keeperStatusFile is the health the keeper reports each tick.
type keeperStatusFile struct {
	KeeperID            string   `json:"keeper_id"`
	Status              string   `json:"status"` // seeding | live | needs_recapture | error
	Detail              string   `json:"detail"`
	LastReloadAt        string   `json:"last_reload_at"`
	LastHarvestAt       string   `json:"last_harvest_at"`
	ConsecutiveFailures int      `json:"consecutive_failures"`
	AbortedSample       []string `json:"aborted_sample"`
}

func keeperSubdir(sub string) string { return filepath.Join(keeperIPCRoot, sub) }

// ensureKeeperDirs makes the IPC tree. Best-effort: a keeper with no container yet still has its row.
func ensureKeeperDirs() error {
	for _, sub := range []string{"desired", "harvest", "status"} {
		if err := os.MkdirAll(keeperSubdir(sub), 0o755); err != nil {
			return err
		}
	}
	return nil
}

/* ------------------------------------------------------------------ CRUD */

func scanSessionKeeper(row interface{ Scan(...interface{}) error }) (SessionKeeper, error) {
	var k SessionKeeper
	err := row.Scan(&k.ID, &k.ScopeTargetID, &k.Name, &k.TargetURL, &k.Enabled, &k.Status,
		&k.CadenceSeconds, &k.LastReloadAt, &k.LastHarvestAt, &k.ConsecutiveFailures, &k.LastError,
		&k.CreatedAt, &k.UpdatedAt)
	return k, err
}

const sessionKeeperCols = `SELECT id::text, scope_target_id::text, name, target_url, enabled, status,
	cadence_seconds, last_reload_at, last_harvest_at, consecutive_failures, last_error,
	created_at, updated_at FROM session_keepers `

// GetSessionKeepers lists the keepers for a scope target, newest first.
func GetSessionKeepers(ctx context.Context, scopeTargetID string) ([]SessionKeeper, error) {
	if dbPool == nil {
		return nil, fmt.Errorf("no database connection")
	}
	rows, err := dbPool.Query(ctx, sessionKeeperCols+`WHERE scope_target_id = $1 ORDER BY created_at DESC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SessionKeeper{}
	for rows.Next() {
		k, err := scanSessionKeeper(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// GetSessionKeeper reads one keeper by id.
func GetSessionKeeper(ctx context.Context, id string) (SessionKeeper, error) {
	var zero SessionKeeper
	if dbPool == nil {
		return zero, fmt.Errorf("no database connection")
	}
	return scanSessionKeeper(dbPool.QueryRow(ctx, sessionKeeperCols+`WHERE id = $1`, id))
}

// CreateSessionKeeper inserts a keeper. name defaults to "default" so a single-account target needs no
// label; target_url defaults to the scope target's own https origin when the caller does not supply one.
func CreateSessionKeeper(ctx context.Context, scopeTargetID, name, targetURL string, cadenceSeconds int) (SessionKeeper, error) {
	var zero SessionKeeper
	if dbPool == nil {
		return zero, fmt.Errorf("no database connection")
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = "default"
	}
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		if h := scopeTargetHost(scopeTargetID); h != "" {
			targetURL = "https://" + h
		}
	}
	if cadenceSeconds < keeperMinCadence {
		cadenceSeconds = keeperDefaultCad
	}
	var id string
	err := dbPool.QueryRow(ctx, `
		INSERT INTO session_keepers (scope_target_id, name, target_url, cadence_seconds, status, enabled)
		VALUES ($1, $2, $3, $4, 'pending', TRUE)
		ON CONFLICT (scope_target_id, name) DO UPDATE SET
		  target_url = EXCLUDED.target_url, cadence_seconds = EXCLUDED.cadence_seconds,
		  enabled = TRUE, updated_at = NOW()
		RETURNING id::text`,
		scopeTargetID, name, targetURL, cadenceSeconds).Scan(&id)
	if err != nil {
		return zero, err
	}
	return GetSessionKeeper(ctx, id)
}

// UpdateSessionKeeper applies the partial fields the operator can change (enabled / target_url /
// cadence), leaving the keeper-reported lifecycle columns alone. Pointers so an omitted field is kept.
func UpdateSessionKeeper(ctx context.Context, id string, enabled *bool, targetURL *string, cadenceSeconds *int) (SessionKeeper, error) {
	var zero SessionKeeper
	if dbPool == nil {
		return zero, fmt.Errorf("no database connection")
	}
	var cad *int
	if cadenceSeconds != nil {
		c := *cadenceSeconds
		if c < keeperMinCadence {
			c = keeperMinCadence
		}
		cad = &c
	}
	// Re-enabling clears a parked error so the next reconcile starts it fresh.
	_, err := dbPool.Exec(ctx, `
		UPDATE session_keepers SET
		  enabled = COALESCE($2, enabled),
		  target_url = COALESCE($3, target_url),
		  cadence_seconds = COALESCE($4, cadence_seconds),
		  status = CASE WHEN COALESCE($2, enabled) = FALSE THEN 'stopped'
		                WHEN $2 IS TRUE THEN 'pending' ELSE status END,
		  consecutive_failures = CASE WHEN $2 IS TRUE THEN 0 ELSE consecutive_failures END,
		  last_error = CASE WHEN $2 IS TRUE THEN '' ELSE last_error END,
		  updated_at = NOW()
		WHERE id = $1`, id, enabled, targetURL, cad)
	if err != nil {
		return zero, err
	}
	return GetSessionKeeper(ctx, id)
}

// DeleteSessionKeeper removes the row and its desired file, so the keeper container tears the browser
// context down on its next reconcile.
func DeleteSessionKeeper(ctx context.Context, id string) error {
	if dbPool == nil {
		return fmt.Errorf("no database connection")
	}
	_, err := dbPool.Exec(ctx, `DELETE FROM session_keepers WHERE id = $1`, id)
	// Removing the desired file makes the keeper container close the browser and reap its own profile
	// dir on its next reconcile (the owner-cleans-up path, no cross-container race). We also best-effort
	// remove the persistent profile here so a container that is DOWN at delete time does not leave the
	// IdP refresh cookie sitting on the volume; if Chromium still holds it, this partially fails and the
	// container finishes the job. Keyed on true deletion, never on a mere disable.
	_ = os.Remove(filepath.Join(keeperSubdir("desired"), id+".json"))
	_ = os.Remove(filepath.Join(keeperSubdir("status"), id+".json"))
	_ = os.RemoveAll(filepath.Join(keeperSubdir("profiles"), id))
	return err
}

/* ------------------------------------------------------------------ desired-state derivation */

// keeperCookieSeed reads the cookie-type session tokens the operator has already captured for the
// target and shapes them for the keeper's cookie jar. This reuses the existing capture->parse
// pipeline (the Session Manager's recapture populates these rows); the keeper needs no new corpus
// parsing, and a fresh recapture is picked up automatically because this reads the live rows.
// keeperCookieSeed returns the cookies ONE keeper seeds into its headless profile. It is scoped to the
// keeper's own account (session_tokens.keeper_name = keeperName) so that two keepers for one target (A
// and B for a cross-account IDOR) never seed each other's Cognito/session cookies into the same profile,
// which would collide on LastAuthUser and mint the wrong identity. A keeper with NO cookies of its own
// falls back to the target's UNTAGGED cookies (keeper_name = ''), which keeps the single-account case
// working without any tagging ceremony; once an account's cookies are tagged (via "adopt" or a tagged
// capture) that keeper stops touching the untagged pool. The one ambiguous case the operator must avoid
// is leaving TWO accounts' cookies untagged at once; the adopt flow is the one-click fix.
func keeperCookieSeed(ctx context.Context, scopeTargetID, keeperName string) ([]keeperCookie, error) {
	fallback := scopeTargetHost(scopeTargetID)
	rows, err := dbPool.Query(ctx, `
		SELECT cookie_name, token_value, COALESCE(cookie_domain,''), COALESCE(NULLIF(cookie_path,''),'/'),
		       COALESCE(cookie_secure,false), COALESCE(cookie_httponly,false), COALESCE(cookie_samesite,'')
		FROM session_tokens
		WHERE scope_target_id = $1 AND is_active = TRUE AND token_type = 'cookie'
		  AND COALESCE(cookie_name,'') <> '' AND COALESCE(token_value,'') <> ''
		  AND (
		    keeper_name = $2
		    OR (keeper_name = '' AND NOT EXISTS (
		      SELECT 1 FROM session_tokens st2
		      WHERE st2.scope_target_id = $1 AND st2.is_active = TRUE AND st2.token_type = 'cookie'
		        AND COALESCE(st2.cookie_name,'') <> '' AND COALESCE(st2.token_value,'') <> ''
		        AND st2.keeper_name = $2
		    ))
		  )`, scopeTargetID, keeperName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []keeperCookie
	for rows.Next() {
		var c keeperCookie
		if err := rows.Scan(&c.Name, &c.Value, &c.Domain, &c.Path, &c.Secure, &c.HttpOnly, &c.SameSite); err != nil {
			return nil, err
		}
		if strings.TrimSpace(c.Domain) == "" {
			c.Domain = fallback
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AdoptKeeperCookies claims the target's currently-UNTAGGED active-or-not cookie tokens for this keeper's
// account (sets keeper_name = the keeper's name). It is the one-click way to say "the session I just
// captured belongs to this account", and it is multi-account-safe because it only ever moves keeper_name=''
// rows: it can never steal cookies already tagged for another account. The recommended multi-account flow
// is: capture account A's session, create keeper A, adopt; then capture B, create keeper B, adopt. Returns
// how many rows it just claimed and how many cookies the account owns in total.
func AdoptKeeperCookies(ctx context.Context, keeperID string) (claimed int, owned int, account string, err error) {
	if dbPool == nil {
		return 0, 0, "", fmt.Errorf("no database connection")
	}
	k, err := GetSessionKeeper(ctx, keeperID)
	if err != nil {
		return 0, 0, "", err
	}
	tag, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET keeper_name = $1, updated_at = NOW()
		WHERE scope_target_id = $2 AND token_type = 'cookie' AND keeper_name = ''`,
		k.Name, k.ScopeTargetID)
	if err != nil {
		return 0, 0, k.Name, err
	}
	claimed = int(tag.RowsAffected())
	_ = dbPool.QueryRow(ctx,
		`SELECT count(*) FROM session_tokens WHERE scope_target_id = $1 AND token_type = 'cookie' AND keeper_name = $2`,
		k.ScopeTargetID, k.Name).Scan(&owned)
	return claimed, owned, k.Name, nil
}

// keeperDesiredFor builds the desired-state file for one keeper from the live scope + token store.
func keeperDesiredFor(ctx context.Context, k SessionKeeper) (keeperDesired, error) {
	scope := LoadScanScope(k.ScopeTargetID)
	inScope, authSuffixes := scope.SuffixesByEffect()

	allowSet := map[string]bool{}
	for _, h := range inScope {
		allowSet[h] = true
	}
	for _, h := range authSuffixes {
		allowSet[h] = true
	}
	allow := make([]string, 0, len(allowSet))
	for h := range allowSet {
		allow = append(allow, h)
	}
	sort.Strings(allow)

	cookies, err := keeperCookieSeed(ctx, k.ScopeTargetID, k.Name)
	if err != nil {
		return keeperDesired{}, err
	}

	headers := map[string]string{}
	maxRPS := float64(engagementMaxRPSCeiling)
	if cfg, err := ResolveEngagementConfig(k.ScopeTargetID); err == nil {
		for hn, hv := range cfg.HeaderMap() {
			headers[hn] = hv
		}
		if cfg.MaxRPS > 0 && cfg.MaxRPS <= engagementMaxRPSCeiling {
			maxRPS = cfg.MaxRPS
		}
	}

	cad := k.CadenceSeconds
	if cad < keeperMinCadence {
		cad = keeperDefaultCad
	}

	d := keeperDesired{
		KeeperID:       k.ID,
		Name:           k.Name,
		TargetURL:      k.TargetURL,
		Allowlist:      allow,
		InScopeHosts:   inScope,
		AuthHosts:      authSuffixes,
		Cookies:        cookies,
		CadenceSeconds: cad,
		ProgramHeaders: headers,
		MaxRPS:         maxRPS,
	}
	d.Generation = keeperGeneration(d)
	return d, nil
}

// keeperGeneration is a short digest of ONLY the seed-affecting fields (target URL + cookies), so a
// changed generation means "re-seed the browser profile". The allowlist and cadence are deliberately
// NOT in it: those are applied live by the keeper without a restart, so folding them in would force a
// pointless profile re-seed (and, worse, overwrite a rotated IdP cookie with the stale captured seed)
// every time the operator tweaks the scope or the reload interval.
func keeperGeneration(d keeperDesired) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|", d.TargetURL)
	for _, c := range d.Cookies {
		fmt.Fprintf(h, "%s=%s;%s;", c.Name, c.Value, c.Domain)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

/* ------------------------------------------------------------------ the loop */

// StartSessionKeeperLoop runs the reconcile + harvest + status sweep on a ticker, mirroring
// StartSessionAutoRefreshLoop. It is a convenience loop: every error is logged, never fatal.
func StartSessionKeeperLoop(interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	if err := ensureKeeperDirs(); err != nil {
		log.Printf("[SESSION-KEEPER] could not create IPC dirs: %v", err)
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			sweepSessionKeepers()
		}
	}()
}

func sweepSessionKeepers() {
	if dbPool == nil {
		return
	}
	// Harvests first, so a token just dropped is stored before a status sweep might flip the row.
	pollKeeperHarvests()
	pollKeeperStatus()
	reconcileKeepers()
}

// reconcileKeepers makes the desired/ directory reflect exactly the enabled keeper rows: write a
// current desired file for each, and remove any file whose keeper is gone or disabled (which the
// container reads as "stop this session").
func reconcileKeepers() {
	ctx := context.Background()
	rows, err := dbPool.Query(ctx, sessionKeeperCols+`WHERE enabled = TRUE`)
	if err != nil {
		log.Printf("[SESSION-KEEPER] list enabled keepers: %v", err)
		return
	}
	var enabled []SessionKeeper
	for rows.Next() {
		if k, err := scanSessionKeeper(rows); err == nil {
			enabled = append(enabled, k)
		}
	}
	rows.Close()

	want := map[string]bool{}
	for _, k := range enabled {
		want[k.ID] = true
		d, err := keeperDesiredFor(ctx, k)
		if err != nil {
			log.Printf("[SESSION-KEEPER] desired for %s: %v", k.ID, err)
			continue
		}
		if err := writeJSONFileAtomic(filepath.Join(keeperSubdir("desired"), k.ID+".json"), d); err != nil {
			log.Printf("[SESSION-KEEPER] write desired %s: %v", k.ID, err)
		}
	}

	// Remove desired files for keepers that are no longer enabled/present.
	entries, _ := os.ReadDir(keeperSubdir("desired"))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !want[id] {
			_ = os.Remove(filepath.Join(keeperSubdir("desired"), e.Name()))
		}
	}
}

// pollKeeperHarvests reads every harvested-credential file, stores it, and deletes the file. A file
// that cannot be parsed or stored is moved aside rather than left to be retried forever.
func pollKeeperHarvests() {
	ctx := context.Background()
	dir := keeperSubdir("harvest")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var h keeperHarvest
		if err := json.Unmarshal(raw, &h); err != nil {
			log.Printf("[SESSION-KEEPER] bad harvest file %s: %v", e.Name(), err)
			_ = os.Remove(path)
			continue
		}
		k, err := GetSessionKeeper(ctx, h.KeeperID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				_ = os.Remove(path) // the keeper row is genuinely gone; drop the orphan
			} else {
				// A transient DB error is not a gone row: keep the harvest and retry next tick rather
				// than losing a freshly minted bearer.
				log.Printf("[SESSION-KEEPER] transient error loading keeper %s, keeping harvest: %v", h.KeeperID, err)
			}
			continue
		}
		if permanent, serr := storeKeeperHarvest(ctx, k, h); serr != nil {
			if permanent {
				log.Printf("[SESSION-KEEPER] dropping unstorable harvest for %s: %v", k.ID, serr)
				_ = os.Remove(path)
			} else {
				log.Printf("[SESSION-KEEPER] transient store error for %s, keeping harvest: %v", k.ID, serr)
			}
			continue
		}
		_, _ = dbPool.Exec(ctx, `
			UPDATE session_keepers SET last_harvest_at = NOW(), status = 'live',
			  consecutive_failures = 0, last_error = '', updated_at = NOW() WHERE id = $1`, k.ID)
		_ = os.Remove(path)
		log.Printf("[SESSION-KEEPER] keeper %s (%s) harvested a fresh %s and stored it", k.ID, k.Name, h.Kind)
	}
}

// pollKeeperStatus folds the keeper container's self-reported health into the row.
func pollKeeperStatus() {
	ctx := context.Background()
	dir := keeperSubdir("status")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var st keeperStatusFile
		if err := json.Unmarshal(raw, &st); err != nil {
			continue
		}
		status := st.Status
		if status == "" {
			status = "live"
		}
		// A run of keeper-reported failures parks the row as error so the UI stops claiming it is live.
		if st.ConsecutiveFailures >= keeperDeadFailures && status != "needs_recapture" {
			status = "error"
		}
		if !keeperStatusValid(status) {
			status = "error"
		}
		// last_reload_at is reported every tick; persist it (COALESCE so an empty report before the
		// first reload never clobbers a prior value). last_harvest_at is written by pollKeeperHarvests
		// on an actual store, so it is not overwritten here.
		var lastReload *time.Time
		if t, perr := time.Parse(time.RFC3339, st.LastReloadAt); perr == nil {
			tu := t.UTC()
			lastReload = &tu
		}
		_, _ = dbPool.Exec(ctx, `
			UPDATE session_keepers SET status = $2, consecutive_failures = $3,
			  last_error = $4, last_reload_at = COALESCE($5, last_reload_at), updated_at = NOW()
			WHERE id = $1 AND enabled = TRUE`,
			st.KeeperID, status, st.ConsecutiveFailures, truncateKeeperErr(st.Detail), lastReload)
	}
}

func keeperStatusValid(s string) bool {
	switch s {
	case "pending", "seeding", "live", "needs_recapture", "stopped", "error":
		return true
	}
	return false
}

func truncateKeeperErr(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 500 {
		return s[:500]
	}
	return s
}

/* ------------------------------------------------------------------ store writeback */

// keeperTokenName is the per-keeper session_tokens identity, so two accounts for one target keep
// distinct live tokens instead of upserting over each other.
func keeperTokenName(k SessionKeeper) string {
	return "Session keeper: " + k.Name
}

// storeKeeperHarvest upserts the freshly harvested credential into session_tokens under the keeper's
// own name, derives a real expiry, marks it active, records an event, and re-profiles it. validate,
// scans and triage re-read session_tokens on their own clocks, so there is nothing else to wire: the
// keeper's one job is to keep this row fresh with a correct expires_at.
// storeKeeperHarvest returns permanent=true when the failure is in the harvest itself (a body that is
// not a token response, an empty bearer, an unknown kind) so the poller drops the file; a DB-write
// failure returns permanent=false so the poller keeps the file and retries rather than losing a fresh
// bearer to a momentary pool hiccup.
func storeKeeperHarvest(ctx context.Context, k SessionKeeper, h keeperHarvest) (permanent bool, err error) {
	// The host the credential is USED against is the app host (the scope target's own host / the SPA
	// origin), NOT the issuer/token-endpoint host the oauth response was observed on. An IdP-direct SPA
	// mints its bearer at an AUTH host, but the bearer is a credential for the app API, so scoping it to
	// the issuer would attach it to nothing the scanners run against.
	appHost := scopeTargetHost(k.ScopeTargetID)
	if appHost == "" {
		appHost = hostOfURL(k.TargetURL)
	}

	observed := time.Now().UTC()
	if t, perr := time.Parse(time.RFC3339, h.ObservedAt); perr == nil {
		observed = t.UTC()
	}

	switch h.Kind {
	case "oauth_token_response":
		parsed, ok := ParseOAuthTokenResponse(h.Body)
		if !ok || !parsed.HasAccessToken || strings.TrimSpace(parsed.AccessToken) == "" {
			return true, fmt.Errorf("harvest body is not a token response with an access_token")
		}
		exp := ttlToExpiry(observed, parsed.ExpiresIn, parsed.ExpiresInKnown)
		exp = DeriveSessionTokenExpiry(parsed.AccessToken, exp)
		if werr := upsertKeeperBearer(ctx, k, appHost, parsed.AccessToken, exp); werr != nil {
			return false, werr
		}
		return false, nil

	case "bearer_header":
		val := strings.TrimSpace(h.Value)
		val = strings.TrimPrefix(val, "Bearer ")
		val = strings.TrimPrefix(val, "bearer ")
		if val == "" {
			return true, fmt.Errorf("empty bearer header harvested")
		}
		// A bearer_header is observed on an in-scope app request, so its host is already the app host;
		// fall back to appHost when the harvest did not carry one.
		useHost := strings.TrimSpace(h.Host)
		if useHost == "" {
			useHost = appHost
		}
		exp := DeriveSessionTokenExpiry(val, nil) // a JWT carries its own exp; opaque stays nil
		if werr := upsertKeeperBearer(ctx, k, useHost, val, exp); werr != nil {
			return false, werr
		}
		return false, nil

	case "cookie":
		host := strings.TrimSpace(h.Host)
		if host == "" {
			host = appHost
		}
		tokens := ParseRawSessionTokens(h.Value, host)
		if len(tokens) == 0 {
			return true, fmt.Errorf("no cookies parsed from harvest")
		}
		for i := range tokens {
			if werr := upsertKeeperCookie(ctx, k, tokens[i]); werr != nil {
				return false, werr
			}
		}
		return false, nil

	default:
		return true, fmt.Errorf("unknown harvest kind %q", h.Kind)
	}
}

// hostOfURL returns the lowercase hostname of a URL, or "" if it does not parse.
func hostOfURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// upsertKeeperCookie writes/refreshes one cookie-kind credential under a per-keeper, per-cookie name,
// keyed by (scope_target_id, name) so two accounts' cookies never upsert over each other (the
// shared upsertParsedSessionToken keys on cookie_name and would collide). The keeper does not emit
// cookie harvests in v1, but the path is kept correct for the BFF/opaque-session case.
func upsertKeeperCookie(ctx context.Context, k SessionKeeper, t SessionToken) error {
	cookieName := strings.TrimSpace(t.CookieName)
	if cookieName == "" || strings.TrimSpace(t.TokenValue) == "" {
		return nil // nothing to store for this parsed row
	}
	name := keeperTokenName(k) + " / " + cookieName
	path := t.CookiePath
	if path == "" {
		path = "/"
	}
	var existingID string
	_ = dbPool.QueryRow(ctx,
		`SELECT id::text FROM session_tokens WHERE scope_target_id = $1 AND name = $2
		 ORDER BY created_at ASC LIMIT 1`, k.ScopeTargetID, name).Scan(&existingID)
	if existingID == "" {
		var id string
		err := dbPool.QueryRow(ctx, `
			INSERT INTO session_tokens
			  (scope_target_id, name, keeper_name, token_type, token_role, cookie_name, token_value,
			   cookie_path, cookie_domain, cookie_secure, cookie_httponly, cookie_samesite, is_active,
			   last_refreshed_at, notes)
			VALUES ($1,$2,$3,'cookie','credential',$4,$5,$6,$7,$8,$9,$10,TRUE,NOW(),$11)
			RETURNING id::text`,
			k.ScopeTargetID, name, k.Name, cookieName, t.TokenValue, path, t.CookieDomain, t.CookieSecure,
			t.CookieHTTPOnly, t.CookieSameSite, "Kept fresh by the headless session keeper.").Scan(&id)
		if err != nil {
			return err
		}
		recordSessionTokenEvent(id, "capture", "created", "Harvested (cookie) by the headless session keeper.", nil)
		ReprofileSessionToken(ctx, id)
		return nil
	}
	_, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET token_value = $1, cookie_path = $2, cookie_domain = $3,
		  cookie_secure = $4, cookie_httponly = $5, cookie_samesite = $6, is_active = TRUE,
		  last_validation_status = '', last_validation_detail = '', last_refreshed_at = NOW(),
		  updated_at = NOW()
		WHERE id = $7`,
		t.TokenValue, path, t.CookieDomain, t.CookieSecure, t.CookieHTTPOnly, t.CookieSameSite, existingID)
	if err != nil {
		return err
	}
	recordSessionTokenEvent(existingID, "refresh", "success", "Refreshed (cookie) by the headless session keeper.", nil)
	ReprofileSessionToken(ctx, existingID)
	return nil
}

// upsertKeeperBearer writes/refreshes the keeper's bearer credential row, keyed by (scope_target, name).
func upsertKeeperBearer(ctx context.Context, k SessionKeeper, host, value string, expiresAt *time.Time) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("no bearer value to store")
	}
	name := keeperTokenName(k)
	scope := []string{}
	if host != "" {
		scope = []string{host}
	}

	var existingID string
	_ = dbPool.QueryRow(ctx,
		`SELECT id::text FROM session_tokens WHERE scope_target_id = $1 AND name = $2
		 ORDER BY created_at ASC LIMIT 1`, k.ScopeTargetID, name).Scan(&existingID)

	if existingID == "" {
		var id string
		err := dbPool.QueryRow(ctx, `
			INSERT INTO session_tokens
			  (scope_target_id, name, keeper_name, token_type, token_role, header_name, value_prefix,
			   token_value, scope_domains, expires_at, is_active, credential_kind, last_refreshed_at, notes)
			VALUES ($1,$2,$3,'bearer','credential','Authorization','Bearer ',$4,$5,$6,TRUE,$7,NOW(),$8)
			RETURNING id::text`,
			k.ScopeTargetID, name, k.Name, value, scope, expiresAt, string(CredentialKindOAuthAccess),
			"Kept fresh by the headless session keeper.").Scan(&id)
		if err != nil {
			return err
		}
		recordSessionTokenEvent(id, "capture", "created", "Harvested by the headless session keeper.", nil)
		ReprofileSessionToken(ctx, id)
		return nil
	}

	_, err := dbPool.Exec(ctx, `
		UPDATE session_tokens SET
		  token_value = $1, expires_at = $2, scope_domains = $3, is_active = TRUE,
		  token_type = 'bearer', token_role = 'credential', header_name = 'Authorization',
		  value_prefix = 'Bearer ', last_validation_status = '', last_validation_detail = '',
		  last_refreshed_at = NOW(), updated_at = NOW()
		WHERE id = $4`, value, expiresAt, scope, existingID)
	if err != nil {
		return err
	}
	recordSessionTokenEvent(existingID, "refresh", "success", "Refreshed by the headless session keeper.", nil)
	ReprofileSessionToken(ctx, existingID)
	return nil
}

/* ------------------------------------------------------------------ helpers */

// writeJSONFileAtomic writes via a temp file + rename so the keeper never reads a half-written file.
func writeJSONFileAtomic(path string, v interface{}) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
