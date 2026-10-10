package utils

// Credential store and login-config types for the session keeper's AUTHENTICATED-SCAN auto-login (the
// standard DAST login-sequence feature: Burp/ZAP/Caido all have it). When a keeper's IdP refresh token
// has itself expired (its hard TTL), the keeper can no longer re-mint the bearer and today it parks
// needs_recapture and waits for a human. With a login config saved and auto_login_enabled, the keeper
// instead drives the operator-configured login FORM in its headless browser and keeps the session
// alive hands-free. This file owns the login value types, the save-time validation, and the
// install-local credential crypto. The schema-backed store lives on session_keepers (sessionKeeper.go),
// the headless login step lives in keeper.mjs, and the reconcile trigger lives in sessionKeeper.go.
// Everything here is GENERIC: a CSS-selector fill sequence plus a success probe, with no host,
// selector, or client id hardcoded, so it drives any app's login form, not one IdP's.
//
// SECURITY: the stored PASSWORD is a reusable account credential (higher blast radius than a bounded
// session token), so it is encrypted at rest with an install-local AES-256-GCM key and is NEVER
// returned in the clear by any read/list and NEVER logged. The username is low-value and plain.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// KeeperLoginStep is one browser action in the generic login fill sequence. It is CSS-selector driven
// so it works against ANY login form. value_ref (for action "type") says where the typed text comes
// from: "username"/"password" resolve from the stored credentials at keeper runtime, "literal" uses
// Literal verbatim (a fixed dropdown value, a tenant slug). The password value NEVER appears in this
// struct; it is resolved from the decrypted credential only inside the keeper's page.type call.
type KeeperLoginStep struct {
	Selector string `json:"selector,omitempty"`
	Action   string `json:"action"`              // type | click | waitFor | submit
	ValueRef string `json:"value_ref,omitempty"` // username | password | literal (for action=type)
	Literal  string `json:"literal,omitempty"`   // used only when value_ref=literal
}

// KeeperSuccessProbe tells the keeper how it knows the login succeeded. Exactly one signal is used.
// kind in {bearer,url,selector,cookie}; value is the URL substring / CSS selector / cookie name (empty
// for bearer, which means "any fresh bearer was harvested this cycle"). This single {kind,value} shape
// is what keeper.mjs loginSucceeded consumes, so it is conveyed to the keeper verbatim.
type KeeperSuccessProbe struct {
	Kind  string `json:"kind"`            // bearer | url | selector | cookie
	Value string `json:"value,omitempty"` // substring / selector / cookie name (omit for bearer)
}

// KeeperLoginConfig is the non-secret login config: the ordered fill sequence plus the success probe.
// It carries no credentials, so it is safe to store as JSONB and return in any list/read response.
type KeeperLoginConfig struct {
	Steps        []KeeperLoginStep  `json:"steps"`
	SuccessProbe KeeperSuccessProbe `json:"success_probe"`
}

/* ------------------------------------------------------------------ credential crypto */

const frameworkCredKeyName = "keeper_credential_aes_key_v1"

var (
	credKeyOnce sync.Once
	credKey     []byte
	credKeyErr  error
)

// frameworkCredKey loads, or on first use generates and stores, the install-local 32-byte AES key used
// to encrypt stored keeper passwords. The key lives in framework_secrets, which has no scope_target_id
// and no FK, so the generic export engine never carries it off this install. Cached for the process
// lifetime. The INSERT ... ON CONFLICT DO NOTHING + re-select is safe under a concurrent creator
// (e.g. a test harness) without ever overwriting a key already in use.
func frameworkCredKey(ctx context.Context) ([]byte, error) {
	credKeyOnce.Do(func() {
		if dbPool == nil {
			credKeyErr = fmt.Errorf("no database connection")
			return
		}
		var k []byte
		if err := dbPool.QueryRow(ctx,
			`SELECT key_material FROM framework_secrets WHERE key_name = $1`, frameworkCredKeyName).Scan(&k); err == nil && len(k) == 32 {
			credKey = k
			return
		}
		nk := make([]byte, 32)
		if _, rerr := rand.Read(nk); rerr != nil {
			credKeyErr = rerr
			return
		}
		if _, rerr := dbPool.Exec(ctx,
			`INSERT INTO framework_secrets (key_name, key_material) VALUES ($1, $2)
			 ON CONFLICT (key_name) DO NOTHING`, frameworkCredKeyName, nk); rerr != nil {
			credKeyErr = rerr
			return
		}
		if rerr := dbPool.QueryRow(ctx,
			`SELECT key_material FROM framework_secrets WHERE key_name = $1`, frameworkCredKeyName).Scan(&k); rerr != nil {
			credKeyErr = rerr
			return
		}
		if len(k) != 32 {
			credKeyErr = fmt.Errorf("stored credential key has the wrong length")
			return
		}
		credKey = k
	})
	return credKey, credKeyErr
}

// sealWithKey / openWithKey are the pure AES-256-GCM core (no DB), so the round-trip is unit-testable
// with a fixed key. The output is nonce||ciphertext. Error strings deliberately carry NO plaintext.
func sealWithKey(key []byte, plaintext string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, []byte(plaintext), nil), nil
}

func openWithKey(key, blob []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(blob) < gcm.NonceSize() {
		return "", fmt.Errorf("stored credential is corrupt")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		// Wrong install key (e.g. a bundle restored onto another install) or tampering. No plaintext.
		return "", fmt.Errorf("stored credential could not be decrypted (wrong install key or tampering)")
	}
	return string(pt), nil
}

func encryptCredential(ctx context.Context, plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	key, err := frameworkCredKey(ctx)
	if err != nil {
		return nil, err
	}
	return sealWithKey(key, plaintext)
}

func decryptCredential(ctx context.Context, blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", nil
	}
	key, err := frameworkCredKey(ctx)
	if err != nil {
		return "", err
	}
	return openWithKey(key, blob)
}

/* ------------------------------------------------------------------ validation */

var keeperLoginActions = map[string]bool{"type": true, "click": true, "waitFor": true, "submit": true}
var keeperValueRefs = map[string]bool{"username": true, "password": true, "literal": true}

// validateKeeperLoginConfig rejects a config that cannot work, at save time, so the operator is told
// why instead of the keeper failing silently later. Pure (no DB), so it is unit-testable. All messages
// avoid em-dashes per the standing rule. Returns "" when the config is usable.
func validateKeeperLoginConfig(loginURL string, steps []KeeperLoginStep, probe KeeperSuccessProbe) string {
	u, err := url.Parse(strings.TrimSpace(loginURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "login_url must be an absolute http or https URL"
	}
	if len(steps) == 0 {
		return "the login fill sequence needs at least one step"
	}
	sawType := false
	for i, s := range steps {
		act := strings.TrimSpace(s.Action)
		if !keeperLoginActions[act] {
			return fmt.Sprintf("step %d: %q is not a login action; use type, click, waitFor or submit", i+1, s.Action)
		}
		if act == "type" {
			sawType = true
			ref := strings.TrimSpace(s.ValueRef)
			if !keeperValueRefs[ref] {
				return fmt.Sprintf("step %d: a type step needs value_ref username, password or literal", i+1)
			}
			if ref == "literal" && s.Literal == "" {
				return fmt.Sprintf("step %d: a literal type step needs a literal value", i+1)
			}
		}
		if (act == "type" || act == "click" || act == "waitFor") && strings.TrimSpace(s.Selector) == "" {
			return fmt.Sprintf("step %d: a %s step needs a selector", i+1, act)
		}
	}
	if !sawType {
		return "the fill sequence needs at least one type step (the username or password field)"
	}
	switch strings.TrimSpace(probe.Kind) {
	case "bearer":
	case "url", "selector", "cookie":
		if strings.TrimSpace(probe.Value) == "" {
			return fmt.Sprintf("a %s success probe needs a value", probe.Kind)
		}
	default:
		return "success_probe kind must be bearer, url, selector or cookie"
	}
	return ""
}
