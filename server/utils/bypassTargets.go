package utils

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"sort"
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

// bypassScopeJudge decides whether a candidate URL belongs to the scope target, using the
// framework's OWN boundary rather than a second opinion kept in this file.
//
// This matters more here than anywhere else in the framework. A 403 is exactly what somebody else's
// infrastructure returns to a request it did not expect, so the 4xx tables fill up with hosts that
// are not the target at all: on one real scope target the commonest hosts in the 4xx set were an
// unrelated auth provider and a payment site. Pointing a bypass scan at those means sending hundreds
// of deliberately malformed requests at a company nobody has authorised us to test. nomore403 alone
// spends roughly a thousand requests per URL.
//
// WHAT THIS REPLACED, AND WHY. The judgement used to be a comparison of the LAST TWO LABELS of the
// hostname, with a comment saying it "deliberately errs towards INCLUDING rather than excluding". On
// a real engagement whose scope target is app.staging-v2.tradetalk.us, that admitted every
// *.tradetalk.us host: authx, data, wallet-api, paper-api, api-wallet-alpacax and stream.data were
// all handed to the operator badged in_scope=true, and none of them is in the programme's scope.
// Three operator overrides already said so and all three were invisible to that comparison:
//
//	scope_rules              - one enabled rule, "=app.staging-v2.tradetalk.us", exact host, and
//	                           because rules REPLACE the legacy boundary every other host is
//	                           default_deny. The framework's own answer was already exact.
//	scope_target_scope_hosts - authx, data and cognito-idp all stored at in_scope=false.
//	in_scope_override        - a column on access_bypass_targets with no reader and no writer.
//
// The fix is not a narrower heuristic. It is to stop holding a second opinion: ask the same
// ScanScope that gates the crawler, the fuzzer and the flow runner, in the same order the flow
// runner asks it - the operator's explicit deny FIRST, then the boundary - so a host can only be
// offered here if the scanner would have been allowed to send to it anyway.
//
// THE DIRECTION IS NOW FAIL-CLOSED, and that is the deliberate reversal. An unparseable URL, a
// scope target that names no host, or an exclusion list that will not read, all judge OUT of scope.
// The old code returned true for every one of those. A candidate wrongly dropped is a badge the
// operator can see and override by marking the endpoint anyway; a candidate wrongly admitted is
// unauthorised traffic, which cannot be taken back.
//
// Wildcard programmes are unaffected. A Wildcard scope target's boundary really is its registrable
// domain, so ScanScope keeps admitting its subdomains; what disappears is this file inventing that
// same width for a URL target that never asked for it.
type bypassScopeJudge struct {
	scope  *ScanScope
	denied map[string]bool
	// loaded distinguishes "boundary established" from the zero value. A zero judge admits nothing.
	loaded bool
}

// loadBypassScopeJudge reads the boundary for a scope target. Any failure yields a judge that
// admits nothing.
// No context parameter: neither ExcludedScopeHosts nor LoadScanScope takes one, and accepting a
// ctx this cannot honour would claim a cancellation that never happens.
func loadBypassScopeJudge(scopeTargetID string) bypassScopeJudge {
	if strings.TrimSpace(scopeTargetID) == "" {
		return bypassScopeJudge{}
	}
	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		log.Printf("[BYPASS] target %s: exclusion list unreadable, no candidate is marked in scope: %v",
			scopeTargetID, err)
		return bypassScopeJudge{}
	}
	return bypassScopeJudgeFor(LoadScanScope(scopeTargetID), denied)
}

// bypassScopeJudgeFor pairs a boundary with the operator's exclusions. The one place loaded is set,
// so "a judge with no boundary admits nothing" cannot be undone by a caller building the struct by
// hand, and the one entry point a test can reach without a database.
func bypassScopeJudgeFor(scope *ScanScope, denied map[string]bool) bypassScopeJudge {
	if scope == nil {
		return bypassScopeJudge{}
	}
	return bypassScopeJudge{scope: scope, denied: denied, loaded: true}
}

// InScope reports whether a candidate URL may be offered as a target of this scope target.
func (j bypassScopeJudge) InScope(rawURL string) bool {
	if !j.loaded {
		return false
	}
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return false
	}
	host := strings.ToLower(strings.Trim(parsed.Hostname(), "."))
	if host == "" {
		return false
	}
	return bypassHostAllowed(j.scope, j.denied, host)
}

// Describe renders the boundary the badges were judged against, so "why is this marked out of
// scope" has an answer on screen rather than in a log line.
func (j bypassScopeJudge) Describe() string {
	if !j.loaded || j.scope == nil {
		return "nothing (this target's scope boundary could not be read, so no candidate is in scope)"
	}
	out := j.scope.Describe()
	if len(j.denied) > 0 {
		hosts := make([]string, 0, len(j.denied))
		for h := range j.denied {
			hosts = append(hosts, h)
		}
		sort.Strings(hosts)
		out += "; excluded by the operator: " + strings.Join(hosts, ", ")
	}
	return out
}

// bypassHostAllowed is the decision, deny before allow, the same order detectedFlowRun.go uses.
//
// The deny check is NOT redundant with the boundary. A host the operator marked in_scope=false that
// also sits inside the target's registrable domain is still admitted by ScanScope.Allows, because
// the legacy half of that boundary is a domain rule. See ExcludedScopeHosts.
//
// A nil ScanScope means no boundary was established. ScanScope.Allows answers true for a nil
// receiver, which is right for a caller that opted out of scoping and wrong for every caller here,
// so it is refused explicitly rather than by omission.
func bypassHostAllowed(scope *ScanScope, denied map[string]bool, host string) bool {
	if host == "" || scope == nil {
		return false
	}
	if IsDeniedFlowHost(denied, host) {
		return false
	}
	// AllowsNarrow, not Allows: this decides whether to OFFER a host to nomore403 and Forbidden,
	// which send on the order of a thousand malformed requests per URL, so a host the operator named
	// must not carry its whole registrable domain in with it. See AllowsNarrow for why Allows itself
	// cannot be narrowed instead.
	return scope.AllowsNarrow(host)
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
