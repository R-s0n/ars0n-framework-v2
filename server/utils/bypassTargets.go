package utils

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"strings"
)

// Scope judgement and target identity, shared across the sections whose targets are not attack
// vectors.
//
// The access control bypass section used to derive its own target list here. It no longer does: like
// GraphQL, the sensitive leak sections and the exposed git section, an operator now picks the
// endpoints per tool on a Targets tab. What survives is the part that is genuinely shared: deciding
// whether a host belongs to the scope target, and deciding which column a scan row or finding is
// keyed by.

// bypassHostInScope reports whether a target URL belongs to the scope target rather than to a third
// party.
//
// This matters more here than anywhere else in the framework. A 403 is exactly what somebody else's
// infrastructure returns to a request it did not expect, so the 4xx tables fill up with hosts that
// are not the target at all: on one real scope target the commonest hosts in the 4xx set were an
// unrelated auth provider and a payment site. Pointing a bypass scan at those means sending hundreds
// of deliberately malformed requests at a company nobody has authorised us to test.
//
// The comparison is the last two labels of the hostname, which is wrong for a handful of multi-part
// suffixes like co.uk and deliberately errs towards INCLUDING rather than excluding, because a
// target wrongly dropped is a scan that silently misses something.
func bypassHostInScope(targetURL, scopeHost string) bool {
	if scopeHost == "" {
		return true
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return true
	}
	host := strings.ToLower(parsed.Hostname())
	scopeHost = strings.ToLower(scopeHost)
	if host == "" || host == scopeHost {
		return true
	}
	return strings.HasSuffix(host, "."+registrableSuffix(scopeHost)) ||
		host == registrableSuffix(scopeHost)
}

func registrableSuffix(host string) string {
	labels := strings.Split(strings.Trim(host, "."), ".")
	if len(labels) <= 2 {
		return host
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

// bypassScopeHost reads the hostname a scope target names.
func bypassScopeHost(ctx context.Context, scopeTargetID string) string {
	var raw string
	if err := dbPool.QueryRow(ctx,
		`SELECT COALESCE(scope_target,'') FROM scope_targets WHERE id = $1`,
		scopeTargetID).Scan(&raw); err != nil {
		return ""
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "*.")
}

// splitURLParts pulls a URL apart into the pieces vectorRow keeps them in.
func splitURLParts(rawURL string) (scheme, domain string, port int, path string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "https", "", 0, "/"
	}
	scheme = parsed.Scheme
	if scheme == "" {
		scheme = "https"
	}
	domain = parsed.Hostname()
	if p := parsed.Port(); p != "" {
		fmt.Sscanf(p, "%d", &port)
	}
	path = parsed.Path
	if path == "" {
		path = "/"
	}
	return scheme, domain, port, path
}

// targetIdentity is which column a scan row or finding is keyed by.
//
// FOUR cases now, and each was added because the previous design silently lost data. Attack vectors
// live in attack_vectors, access bypass targets in access_bypass_targets, sensitive leak directories
// in leak_targets, and GraphQL endpoints in NO table at all because the operator keeps that list in
// each tool's settings.
//
// Getting it wrong is invisible: the foreign key rejects the insert, the error is logged, the scan
// carries on, and the per-target row reports findings that the findings table does not contain.
// Measured exactly that way, twice, before this existed.
type targetIdentity struct {
	VectorID  any
	BypassID  any
	LeakID    any
	TargetURL any
}

func identityFor(id string, isBypass, isGraphQL, isLeak bool, targetURL string) targetIdentity {
	out := targetIdentity{}
	if strings.TrimSpace(targetURL) != "" && (isGraphQL || isLeak) {
		out.TargetURL = targetURL
	}
	if strings.TrimSpace(id) == "" {
		return out
	}
	switch {
	case isGraphQL:
		// No table, so no foreign key. The URL is the identity.
	case isLeak:
		out.LeakID = id
	case isBypass:
		out.BypassID = id
	default:
		out.VectorID = id
	}
	return out
}

// RecordDeniedEndpoint remembers a URL that refused the framework, so the bypass section has
// something to work on.
//
// WHY THIS EXISTS, and what it does NOT fix. The access bypass section was empty on the reference
// target, and the obvious diagnosis was that observed 4xx were not being plumbed through to it. That
// diagnosis was wrong: DeniedEndpoints already unions six tables, it works, and it correctly offered
// 57 x 404 and 70 x 405. There were ZERO 401 or 403 anywhere in the database, because nothing in the
// framework had ever requested a path that returns one. /admin was not in discovered_endpoints, not
// in endpoint_validation_results, not in fuzz_findings and not in consolidated_url_endpoints. The
// only 403 that was ever seen came from a request typed by hand.
//
// So this closes a real gap, and the gap it closes is NOT the one that hid /admin. A 401 or 403 the
// framework happens to observe now becomes a bypass target instead of being discarded as just another
// status code. What still has to happen for /admin specifically is DISCOVERY: a path nothing ever
// requests cannot refuse anything, and no amount of plumbing downstream changes that.
//
// Writes are additive and never resurrect a deletion, the same invariant the attack vector and
// endpoint tables hold: an operator who removes a target must not have it reappear on the next scan.
func RecordDeniedEndpoint(ctx context.Context, scopeTargetID, rawURL string, statusCode int, source string) {
	// Only the codes that mean "this exists and you may not have it". A 404 is what a directory brute
	// force emits by the thousand and a 405 is a verb mismatch; neither is a denial worth a bypass
	// attempt, and folding them in would bury the handful that are.
	if statusCode != 401 && statusCode != 403 {
		return
	}
	if strings.TrimSpace(rawURL) == "" || strings.TrimSpace(scopeTargetID) == "" {
		return
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO access_bypass_targets (scope_target_id, url, status_code, sources)
		VALUES ($1, $2, $3, ARRAY[$4]::TEXT[])
		ON CONFLICT (scope_target_id, url) DO UPDATE
		SET last_seen = NOW(),
		    status_code = EXCLUDED.status_code,
		    sources = (
		        SELECT array_agg(DISTINCT s ORDER BY s)
		        FROM unnest(access_bypass_targets.sources || EXCLUDED.sources) AS s
		    )
		WHERE access_bypass_targets.deleted_at IS NULL`,
		scopeTargetID, rawURL, statusCode, source); err != nil {
		log.Printf("[BYPASS] recording denied endpoint %s: %v", rawURL, err)
	}
}

// vectorIdentityColumns decides which identity column an id belongs in.
//
// vector_id has a foreign key onto attack_vectors, so a bypass target's id written there fails the
// insert outright. The failure would be logged and the scan would carry on, recording NOTHING for a
// target it really did scan, which reads afterwards as a target that was never reached.
func vectorIdentityColumns(id string, isBypassTarget bool) (vectorID, bypassTargetID any) {
	if strings.TrimSpace(id) == "" {
		return nil, nil
	}
	if isBypassTarget {
		return nil, id
	}
	return id, nil
}

// recordScanTarget writes the per-target verdict for a scan, against whichever identity the target
// has. The two ON CONFLICT clauses differ because Postgres treats NULLs as distinct: the constraint
// that stops a vector being recorded twice does nothing for a bypass target, whose vector_id is
// always NULL, so that case needs its own partial unique index to conflict against.
func recordScanTarget(ctx context.Context, scanID, id string, isBypassTarget bool,
	status, reason string, findingCount int) error {
	return recordScanTargetFor(ctx, scanID, id, isBypassTarget, false, "", status, reason, findingCount)
}

// recordScanTargetFor writes the per-target verdict against whichever identity the target has.
//
// One statement for every case, with the unused columns NULL. The ON CONFLICT clause has to match
// the identity in use, because Postgres treats NULLs as distinct: the constraint that stops an
// attack vector being recorded twice does nothing for a target whose vector_id is always NULL, so
// each identity has its own partial unique index to conflict against.
func recordScanTargetFor(ctx context.Context, scanID, id string, isBypassTarget, isURLTarget bool,
	targetURL, status, reason string, findingCount int) error {
	return recordScanTargetIdentity(ctx, scanID,
		identityFor(id, isBypassTarget, isURLTarget, false, targetURL), status, reason, findingCount)
}

func recordScanTargetIdentity(ctx context.Context, scanID string, identity targetIdentity,
	status, reason string, findingCount int) error {

	conflict := "(scan_id, vector_id) DO NOTHING"
	switch {
	case identity.BypassID != nil:
		conflict = "(scan_id, bypass_target_id) WHERE bypass_target_id IS NOT NULL DO NOTHING"
	case identity.LeakID != nil:
		conflict = "(scan_id, leak_target_id) WHERE leak_target_id IS NOT NULL DO NOTHING"
	case identity.TargetURL != nil:
		conflict = "(scan_id, target_url) WHERE target_url IS NOT NULL DO NOTHING"
	}

	_, err := dbPool.Exec(ctx, `
		INSERT INTO vector_scan_vectors (scan_id, vector_id, bypass_target_id, leak_target_id,
		                                 target_url, status, reason, finding_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT `+conflict,
		scanID, identity.VectorID, identity.BypassID, identity.LeakID, identity.TargetURL,
		status, reason, findingCount)
	return err
}

// vectorFindingIdentity decides which identity columns a finding belongs in. Same four cases as
// recordScanTargetIdentity, and the same silent failure when it is wrong.
func vectorFindingIdentity(f VectorFinding) (vectorID, bypassTargetID any) {
	identity := identityFor(f.VectorID, f.IsBypassTarget, f.IsGraphQLTarget, f.IsLeakTarget, "")
	return identity.VectorID, identity.BypassID
}

// vectorFindingLeakID is the leak column, kept separate so the existing insert signature is unchanged.
func vectorFindingLeakID(f VectorFinding) any {
	return identityFor(f.VectorID, f.IsBypassTarget, f.IsGraphQLTarget, f.IsLeakTarget, "").LeakID
}
