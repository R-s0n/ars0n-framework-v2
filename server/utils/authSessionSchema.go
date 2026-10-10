package utils

import (
	"context"
	"fmt"
)

// AuthSessionSchema is the SINGLE authoritative list of every column, constraint and index added to the
// auth-flow and session-token tables after their base CREATE TABLE (which lives in database.go). It is
// applied by BOTH createTables (package main, the real database, via `queries = append(queries,
// utils.AuthSessionSchema...)`) AND the test harness (triageTestDB -> EnsureAuthSessionSchema).
//
// WHY THIS EXISTS: the migration in database.go runs in package main, which the utils test suite cannot
// import, so the throwaway test database was provisioned only by TriageSchema + SessionTokenProfileSchema.
// Any column added to createTables alone therefore read as "column does not exist" in every DB-backed
// test, and the failure was silent because a passing package hides it. That bit auto_refresh and
// auth_flow_steps.interaction. Putting every additive change to these tables here, and applying it from
// both places, makes it impossible for the two databases to drift: a column added here reaches both.
//
// Every statement is idempotent (ADD COLUMN IF NOT EXISTS, CREATE INDEX IF NOT EXISTS, DROP+ADD for a
// CHECK) and safe to run repeatedly and in either database. The base tables must already exist; the real
// DB creates them inline just before this list runs, and the test DB has them from its seed. Ordering
// matters only where noted (token_role before its CHECK).
var AuthSessionSchema = []string{
	// --- auth_flow_steps ---
	// extractions: what a step captures from its own response for a later step ({{af:NAME}}). interaction:
	// what the operator must supply on refresh (MFA/OTP), {} means fully automatable. See
	// authFlowsVariables.go and sessionRefreshInteractive.go.
	`ALTER TABLE auth_flow_steps ADD COLUMN IF NOT EXISTS extractions JSONB NOT NULL DEFAULT '[]'::jsonb;`,
	`ALTER TABLE auth_flow_steps ADD COLUMN IF NOT EXISTS interaction JSONB NOT NULL DEFAULT '{}'::jsonb;`,
	`CREATE INDEX IF NOT EXISTS idx_auth_flows_scope_target ON auth_flows(scope_target_id);`,
	`CREATE INDEX IF NOT EXISTS idx_auth_flow_steps_flow ON auth_flow_steps(auth_flow_id);`,
	// Replay order is a fact, not a tie-break. Built only if existing rows do not already violate it.
	`DO $$
	 BEGIN
	   IF NOT EXISTS (
	     SELECT 1 FROM auth_flow_steps a
	     JOIN auth_flow_steps b ON a.auth_flow_id = b.auth_flow_id
	       AND a.step_order = b.step_order AND a.id <> b.id
	   ) THEN
	     CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_flow_steps_order
	       ON auth_flow_steps(auth_flow_id, step_order);
	   END IF;
	 END $$;`,

	// --- auth_flows ---
	// magic_link joins the category list. A CHECK cannot be widened in place, so drop and recreate.
	`ALTER TABLE auth_flows DROP CONSTRAINT IF EXISTS auth_flows_category_check;`,
	`ALTER TABLE auth_flows ADD CONSTRAINT auth_flows_category_check
	   CHECK (category IN ('register','login','mfa_otp','magic_link','reset'));`,
	// How the flow was produced (recorded via the extension vs manual), and the creation/refresh axis
	// (orthogonal to category): a flow the detector builds from a silent-refresh capture is 'refresh',
	// everything else stays 'creation'. See docs/OAUTH_REFRESH_DESIGN.md.
	`ALTER TABLE auth_flows
	   ADD COLUMN IF NOT EXISTS source VARCHAR(16) NOT NULL DEFAULT 'manual',
	   ADD COLUMN IF NOT EXISTS recording_id UUID;`,
	`ALTER TABLE auth_flows ADD COLUMN IF NOT EXISTS flow_purpose VARCHAR(16) NOT NULL DEFAULT 'creation';`,

	// --- session_tokens ---
	// token_role: what the value IS (credential | companion | refresh), as opposed to how it travels.
	// Added before the CHECK that constrains it. See sessionTokens.go.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS token_role VARCHAR(16)
	   NOT NULL DEFAULT 'credential';`,
	// Opt-in unattended refresh; off by default. See sessionAutoRefreshLoop.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS auto_refresh BOOLEAN NOT NULL DEFAULT FALSE;`,
	// The session-keeper account a token belongs to, matching session_keepers.name. A keeper seeds
	// ONLY the cookies tagged with its own name, so two accounts for one target (A and B for a
	// cross-account IDOR) never seed each other's Cognito cookies into the same headless profile.
	// '' means unassigned; the keeper's "adopt" tags a target's untagged cookies to one account.
	`ALTER TABLE session_tokens ADD COLUMN IF NOT EXISTS keeper_name VARCHAR(128) NOT NULL DEFAULT ''`,
	// token_role gains 'refresh'. Drop-and-recreate widens an existing two-value constraint to three.
	`ALTER TABLE session_tokens DROP CONSTRAINT IF EXISTS session_tokens_token_role_check;`,
	`ALTER TABLE session_tokens ADD CONSTRAINT session_tokens_token_role_check
	   CHECK (token_role IN ('credential','companion','refresh'));`,
	// OAuth access/refresh-token model (docs/OAUTH_REFRESH_DESIGN.md). All nullable and additive.
	// refresh_token_id is the first token->token link; refresh_flow_id is the headless refresh flow;
	// refresh_strategy/transport/material_key describe how (and whether) the session renews.
	`ALTER TABLE session_tokens
	   ADD COLUMN IF NOT EXISTS refresh_token_id UUID REFERENCES session_tokens(id) ON DELETE SET NULL,
	   ADD COLUMN IF NOT EXISTS refresh_flow_id UUID REFERENCES auth_flows(id) ON DELETE SET NULL,
	   ADD COLUMN IF NOT EXISTS refresh_strategy VARCHAR(24) NOT NULL DEFAULT '',
	   ADD COLUMN IF NOT EXISTS refresh_transport VARCHAR(16) NOT NULL DEFAULT '',
	   ADD COLUMN IF NOT EXISTS refresh_material_key VARCHAR(64) NOT NULL DEFAULT '';`,
	`CREATE INDEX IF NOT EXISTS idx_session_tokens_refresh_token
	   ON session_tokens(refresh_token_id) WHERE refresh_token_id IS NOT NULL;`,
	`CREATE INDEX IF NOT EXISTS idx_session_tokens_target
	   ON session_tokens(scope_target_id, is_active);`,

	// --- session_token_events ---
	`CREATE INDEX IF NOT EXISTS idx_session_token_events
	   ON session_token_events(session_token_id, created_at DESC);`,

	// --- session_keepers ---
	// One durable headless-browser session keeper per (scope_target, account). It holds the IdP
	// session in a headless browser, lets the UNMODIFIED SPA re-mint its short-lived bearer, harvests
	// the fresh value from its own network, and upserts it into session_tokens under a per-keeper
	// name (so two accounts for one target do not upsert over each other). name is the account label
	// and the row-identity disambiguator. target_url is the SPA origin the keeper loads. cadence is
	// how often the keeper reloads to force a re-mint; status is the keeper's own lifecycle, separate
	// from the token's validation state. The keeper is driven by a Go scheduler over the shared
	// temp_data volume; nothing here stores the cookie seed (it is derived from the live token store
	// at reconcile time, so a fresh recapture is picked up automatically).
	`CREATE TABLE IF NOT EXISTS session_keepers (
	    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	    scope_target_id UUID NOT NULL REFERENCES scope_targets(id) ON DELETE CASCADE,
	    name TEXT NOT NULL,
	    target_url TEXT NOT NULL DEFAULT '',
	    enabled BOOLEAN NOT NULL DEFAULT TRUE,
	    status VARCHAR(24) NOT NULL DEFAULT 'pending'
	      CHECK (status IN ('pending','seeding','live','logging_in','needs_recapture','stopped','error')),
	    cadence_seconds INTEGER NOT NULL DEFAULT 600,
	    last_reload_at TIMESTAMP,
	    last_harvest_at TIMESTAMP,
	    consecutive_failures INTEGER NOT NULL DEFAULT 0,
	    last_error TEXT NOT NULL DEFAULT '',
	    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
	    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
	    UNIQUE (scope_target_id, name)
	);`,
	`CREATE INDEX IF NOT EXISTS idx_session_keepers_target ON session_keepers(scope_target_id);`,

	// --- framework_secrets ---
	// Install-local secret material. The only row today is the AES-256 key that encrypts a stored keeper
	// login PASSWORD at rest (session_keepers.login_password_enc). This table deliberately has NO
	// scope_target_id and NO foreign key to anything the export walks, so the generic v2 bundle engine
	// (dbBundle.go) never pulls it: an exported .rs0n/CSV/MCP bundle therefore carries only ciphertext,
	// and the key never leaves this install. A bundle restored onto a DIFFERENT install cannot decrypt
	// the password (different key), which is the right property: the operator re-enters it, and the
	// keeper treats an undecryptable credential as no credential (it parks, never loops).
	`CREATE TABLE IF NOT EXISTS framework_secrets (
	    key_name TEXT PRIMARY KEY,
	    key_material BYTEA NOT NULL,
	    created_at TIMESTAMP NOT NULL DEFAULT NOW()
	);`,

	// --- session_keepers: auto-login (operator-configured headless re-login) ---
	// When the IdP REFRESH token itself expires (its hard TTL), the keeper can log in again on its own
	// with operator-stored credentials instead of parking needs_recapture - the standard authenticated-
	// scan login-sequence behaviour (Burp/ZAP/Caido). All additive and backward-safe: auto_login_enabled
	// defaults FALSE, so an existing keeper behaves exactly as before (re-mint from the refresh token,
	// park needs_recapture on expiry).
	//
	// login_config holds the GENERIC form fill sequence + success probe, no app/IdP specifics in the
	// schema: {"steps":[{"selector","action","value_ref","literal"}],"success_probe":{"kind","value"}}.
	// login_username is the account username (low value, stored plain). login_password_enc is the account
	// PASSWORD, a REUSABLE credential of higher blast radius than a bounded session token, so it is stored
	// AES-256-GCM encrypted (nonce||ciphertext; NULL = none) with the install-local framework_secrets key
	// and is NEVER selected into a list/read response, log, status file, or export in the clear. See
	// keeperLoginConfig.go. consecutive_login_failures + last_login_attempt_at drive the lockout-safe
	// attempt cap: the keeper is DISARMED after a small number of consecutive failed logins so a bad
	// credential, a changed form, or a CAPTCHA/MFA prompt can never hammer the real account into lockout.
	`ALTER TABLE session_keepers
	   ADD COLUMN IF NOT EXISTS auto_login_enabled BOOLEAN NOT NULL DEFAULT FALSE,
	   ADD COLUMN IF NOT EXISTS login_url TEXT NOT NULL DEFAULT '',
	   ADD COLUMN IF NOT EXISTS login_config JSONB NOT NULL DEFAULT '{}'::jsonb,
	   ADD COLUMN IF NOT EXISTS login_username TEXT NOT NULL DEFAULT '',
	   ADD COLUMN IF NOT EXISTS login_password_enc BYTEA,
	   ADD COLUMN IF NOT EXISTS consecutive_login_failures INTEGER NOT NULL DEFAULT 0,
	   ADD COLUMN IF NOT EXISTS last_login_attempt_at TIMESTAMP;`,
	// 'logging_in' joins the status set. Drop-and-recreate widens the inline CHECK on existing DBs; the
	// CREATE TABLE above already lists it for fresh DBs. Same drop-and-recreate pattern as the
	// session_tokens_token_role_check widen earlier in this file.
	`ALTER TABLE session_keepers DROP CONSTRAINT IF EXISTS session_keepers_status_check;`,
	`ALTER TABLE session_keepers ADD CONSTRAINT session_keepers_status_check
	   CHECK (status IN ('pending','seeding','live','logging_in','needs_recapture','stopped','error'));`,
}

// EnsureAuthSessionSchema applies AuthSessionSchema. It is idempotent. The test harness calls it so a
// DB-backed test runs against the same auth/session schema production uses, closing the drift that hid
// auto_refresh and auth_flow_steps.interaction.
func EnsureAuthSessionSchema(ctx context.Context) error {
	if dbPool == nil {
		return fmt.Errorf("no database connection")
	}
	for _, stmt := range AuthSessionSchema {
		if _, err := dbPool.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("auth/session schema statement failed: %w", err)
		}
	}
	return nil
}
