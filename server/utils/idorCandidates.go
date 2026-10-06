package utils

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// The deterministic IDOR candidate join.
//
// This is the object-level sibling of the pointer layer: it turns stored evidence into a ranked list
// of "this endpoint takes an id, is auth-gated, and hands back an owned-looking object, so swap the
// id across two identities". It is the half of consolidation an operator cannot run by hand on 32
// id-bearing endpoints, and the half an AI must NOT run, because automated consolidation cannot call
// a model. So everything here is deterministic: it reads only three stored sources (attack_vectors,
// manual_crawl_captures, and the authz_* model), applies a fixed gate and a fixed score, and sends
// NO request at the target. The id-swap proof-of-concept is the operator's to perform; this file
// only surfaces and ranks.
//
// FOUR HONESTY GUARDS ARE BAKED IN, because the fastest way to make this list worthless is to
// overclaim:
//   (a) auth is only ever "client-sent", never "server-enforced". The corpus shows a request carried
//       an Authorization header; it does not show the server checked it. idorAuthCaveat is the only
//       phrasing used, and the word "enforced" appears nowhere.
//   (b) a PII/financial SCHEMA match is a surface signal and never adds to the score. On an unfunded
//       account the PII fields are null, and a null given_name is not a leak. HasPII admits a
//       candidate through the gate; it does not rank it.
//   (c) cookie and tracking parameter names (AMP_*, __stripe_*, _rdt_*, _gcl_*,
//       CognitoIdentityServiceProvider.*, intercom-*, onfido-*, gdpr_*) are blacklisted from the
//       id-like-param signal. Measured: the accounts cookie vectors carry a uuid signal made
//       entirely of these, and admitting them would invent hundreds of "id" candidates.
//   (d) ownership is never asserted. A returned owner_id is "a concrete id to swap", not "another
//       user's object". Whose object it is belongs to the operator and the authz model, not here.

// IDORCandidate is one id-bearing, auth-gated endpoint worth an id-swap test. The shape is the
// shared contract: the pointer layer wraps it, so these names do not move.
type IDORCandidate struct {
	VectorID       string
	Method         string
	URL            string
	Path           string
	InsertionPoint string
	Param          string
	// IDLocation is where the swappable id sits: "path" (the id is a path segment, the classic IDOR
	// primitive) or "query"/"body"/"header" (an id-like parameter). Never "cookie": a cookie id rides
	// every request and is not an object reference the caller chooses per request.
	IDLocation string
	// GuessTier is the id kind, from analyzeIdentifiers (reused, not reinvented): "sequential" or
	// "uuid_v1" are enumerable, "object_id" is timestamp-ordered, "uuid_v4" is random and needs a
	// leaked id, "unknown" when the value matches no known shape.
	GuessTier     string
	HasOwnerField bool
	HasPII        bool
	// AuthClientSent means the corpus request carried an Authorization/bearer. It is CLIENT-SENT, not
	// proven server-enforced: see guard (a).
	AuthClientSent    bool
	IDLeaked          bool
	KnownIDValue      string
	IDLeakSource      string
	Score             int
	Reasons           []string
	IdentityPatternID string
}

// The id-guess tiers, named after the analyzeIdentifiers signal they come from so the mapping is
// one-to-one and auditable.
const (
	idGuessSequential = "sequential"
	idGuessUUIDv1     = "uuid_v1"
	idGuessObjectID   = "object_id"
	idGuessUUIDv4     = "uuid_v4"
	idGuessUnknown    = "unknown"
)

// idorAuthCaveat is the ONLY way auth is described on a candidate. Guard (a): the corpus proves the
// client sent a credential, never that the server enforced one.
const idorAuthCaveat = "client-sent auth (not proven server-enforced)"

// ---------------------------------------------------------------------------------------------
// Pure functions: the gate, the blacklist, the id-like-param test, the guess tier, the scorer.
// Factored out of the DB call on purpose, so each is unit-tested without a database.
// ---------------------------------------------------------------------------------------------

// idorCandidateGate is THE gate, as data: (id-bearing path OR id-like non-cookie param) AND
// (an owner reference OR a PII schema) AND client-sent auth AND at least one observed 200. Every
// argument is a fact the collector measured from the corpus, so the whole admission decision is one
// readable boolean a test can drive directly.
func idorCandidateGate(idBearing, hasOwner, hasPII, authSent, observed200 bool) bool {
	return idBearing && (hasOwner || hasPII) && authSent && observed200
}

// idorCookieTrackingBlacklist reports whether a parameter name is a cookie or third-party tracking
// token rather than an application object reference. Guard (c). Matched by lowercase prefix because
// these families all carry their own random suffix (AMP_MKTG_d6814239bf, __stripe_sid, _rdt_uuid).
func idorCookieTrackingBlacklist(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, p := range []string{
		"amp_", "__stripe_", "_rdt_", "_gcl_",
		"cognitoidentityserviceprovider.", "intercom-", "onfido-", "gdpr_",
	} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// idorIDishName reports whether a parameter name reads like an object reference. Used only to admit
// a NUMERIC or high-entropy param as id-like: a bare number is an id under /orders/{id} and a form
// field under annual_income_max, and only the name tells them apart.
func idorIDishName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	if strings.HasSuffix(n, "_id") || strings.HasSuffix(n, "uuid") || strings.HasSuffix(n, "guid") || n == "id" {
		return true
	}
	for _, tok := range []string{"account", "owner", "user", "client", "customer", "order", "party", "holder", "subject"} {
		if strings.Contains(n, tok) {
			return true
		}
	}
	return false
}

// idorIsIDLikeParam reports whether one parameter is an id-like non-cookie object reference. A uuid
// or a jwt value is an object reference whatever it is called; a numeric or high-entropy value is
// one only when the NAME says so. A blacklisted name is never one, whatever the value looks like.
func idorIsIDLikeParam(name, value string) bool {
	if idorCookieTrackingBlacklist(name) {
		return false
	}
	switch classifyInputValue(value) {
	case SignalUUID, SignalJWT:
		return true
	case SignalNumericID, SignalHighEntropy:
		return idorIDishName(name)
	}
	return false
}

// idGuessProbe wraps a bare numeric id so analyzeIdentifiers' reSeqID (which anchors on an id: or
// ID= prefix) recognises it. A uuid, mongo id or hex value is left alone: its own rule fires on the
// raw value.
func idGuessProbe(v string) string {
	v = strings.TrimSpace(v)
	if v != "" && isAllDigits(v) {
		return `"id":` + v
	}
	return v
}

// idGuessTier classifies the swappable id by REUSING analyzeIdentifiers, so the uuid_v1-vs-uuid_v4
// distinction (which the attack_vectors signals column cannot make) comes from the one place in the
// codebase that makes it. The most-guessable kind present wins, because that is the kind that sets
// how reachable neighbouring objects are.
func idGuessTier(idValue string) string {
	if strings.TrimSpace(idValue) == "" {
		return idGuessUnknown
	}
	kinds := map[string]bool{}
	for _, s := range analyzeIdentifiers(SignalInput{Body: idGuessProbe(idValue)}) {
		kinds[s.Kind] = true
	}
	switch {
	case kinds["identifier_sequential"]:
		return idGuessSequential
	case kinds["identifier_uuid_v1"]:
		return idGuessUUIDv1
	case kinds["identifier_object_id"]:
		return idGuessObjectID
	case kinds["identifier_uuid_v4"]:
		return idGuessUUIDv4
	}
	return idGuessUnknown
}

// scoreIDORCandidate is the agreed heuristic, as a pure function of the candidate's measured fields
// so a test can assert each term. It never asserts ownership (guard d), never scores a PII schema
// (guard b), and never calls auth enforced (guard a). A missing term simply does not add; nothing
// here subtracts, because every surviving candidate already cleared the gate.
func scoreIDORCandidate(c IDORCandidate) (int, []string) {
	score := 0
	var reasons []string

	// A concrete owner/account reference came back, so there is a real id to swap. This is the
	// strongest single signal and the thing that separates an IDOR candidate from a bare id in a URL.
	// It says an owner reference EXISTS, not who owns it.
	if c.HasOwnerField {
		score += 3
		reasons = append(reasons, "the response carries an owner/account reference, so there is a concrete id to swap (whose object it is is for the operator to settle, not asserted here)")
	}

	// Guessability of the swappable id.
	switch c.GuessTier {
	case idGuessSequential, idGuessUUIDv1:
		score += 3
		reasons = append(reasons, "the id is enumerable ("+c.GuessTier+"), so neighbouring objects can be reached by counting or derivation")
	case idGuessObjectID:
		score += 1
		reasons = append(reasons, "the id is a timestamp-ordered object id, so nearby values are partly predictable")
	case idGuessUUIDv4:
		if !c.IDLeaked {
			reasons = append(reasons, "the id is a random uuid_v4: not guessable, so this needs a leaked id before it is testable")
		}
	}

	// An id-acquisition primitive turns a needs-a-leak uuid_v4 into something reachable: the swap
	// target can be obtained from a sibling collection response.
	if c.IDLeaked {
		score += 2
		reasons = append(reasons, "a sibling collection response exposes this id ("+firstNonEmpty(c.IDLeakSource, "a collection endpoint")+"), an id-acquisition primitive")
	}

	// A concrete id value is recorded, so the two-identity PoC has a value on hand rather than a
	// template.
	if strings.TrimSpace(c.KnownIDValue) != "" {
		score += 1
		reasons = append(reasons, "a concrete id value is recorded for the id-swap PoC")
	}

	// A modelled identity pattern is PRIOR evidence the endpoint returns a body for one identity,
	// with a request already formed to replay under a second. It is NOT a two-identity diff, so it is
	// worth prior-finding weight and no more: the collector ranks a no-replay candidate low on
	// purpose, and only a real two-identity replay would earn higher.
	if strings.TrimSpace(c.IdentityPatternID) != "" {
		score += 2
		reasons = append(reasons, "an authorization identity pattern (category=parameter) is modelled for this endpoint, with a pre-formed request to replay under a second identity")
	}

	// Auth is client-sent, stated in the one allowed phrasing (guard a).
	if c.AuthClientSent {
		reasons = append(reasons, "the corpus request carried "+idorAuthCaveat)
	}

	// A PII/financial schema is a surface signal only and never scores (guard b): the fields may be
	// schema-level or null on an unfunded account.
	if c.HasPII {
		reasons = append(reasons, "the response matches a PII/financial schema (surface signal only, not scored: fields may be schema-level or null)")
	}

	return score, reasons
}

// ---------------------------------------------------------------------------------------------
// The join. Deterministic, read-only, no active request, no model call.
// ---------------------------------------------------------------------------------------------

// idorDriverRow is one attack_vectors row as the driver query returns it.
type idorDriverRow struct {
	ID             string
	Method         string
	Scheme         string
	Domain         string
	Path           string
	InsertionPoint string
	Parameters     []string
	Signals        []string
}

// idorFamily groups driver rows by one endpoint (method + domain + templated path) and keeps the
// best representative: the path row wins, because the path id is the object reference an attacker
// chooses per request, and a body/query id is only used when the endpoint has no path id.
type idorFamily struct {
	rep      idorDriverRow
	idLoc    string
	param    string
	repScore int
}

// idorEvidenceQuery answers the corpus half for ONE endpoint family with four short-circuiting
// EXISTS checks and a sample URL. The owner/PII/auth checks are bounded to the 300 most recent
// matching captures so a 19k-capture endpoint (e.g. trade_account/margin on the Alpaca estate)
// cannot turn a modal open into a full-table scan: an API endpoint returns the same schema every
// call, so the recent window is representative. $1 scope target, $2 method, $3 templated path.
const idorEvidenceQuery = `
SELECT
  EXISTS(SELECT 1 FROM manual_crawl_captures
         WHERE scope_target_id=$1 AND method=$2
           AND (endpoint=$3 OR endpoint LIKE $3 || '?%')
           AND status_code=200) AS has_200,
  EXISTS(SELECT 1 FROM (
           SELECT response_body FROM manual_crawl_captures
           WHERE scope_target_id=$1 AND method=$2
             AND (endpoint=$3 OR endpoint LIKE $3 || '?%')
             AND status_code=200
           ORDER BY timestamp DESC LIMIT 300) s
         WHERE s.response_body ~ '"(owner_id|account_id|user_id|owner|holder_id)"') AS has_owner,
  EXISTS(SELECT 1 FROM (
           SELECT response_body FROM manual_crawl_captures
           WHERE scope_target_id=$1 AND method=$2
             AND (endpoint=$3 OR endpoint LIKE $3 || '?%')
             AND status_code=200
           ORDER BY timestamp DESC LIMIT 300) s
         WHERE s.response_body ~* '"(given_name|family_name|date_of_birth|tax_id|ssn|email_address|phone_number|street_address|postal_code|annual_income|liquid_net_worth|total_net_worth|net_worth|funding_source|buying_power|portfolio_value|last_equity|cash_withdrawable|account_number)"') AS has_pii,
  EXISTS(SELECT 1 FROM (
           SELECT headers FROM manual_crawl_captures
           WHERE scope_target_id=$1 AND method=$2
             AND (endpoint=$3 OR endpoint LIKE $3 || '?%')
           ORDER BY timestamp DESC LIMIT 300) s
         WHERE s.headers::text ILIKE '%authorization%' OR s.headers::text ILIKE '%bearer %') AS auth_sent,
  COALESCE((SELECT url FROM manual_crawl_captures
            WHERE scope_target_id=$1 AND method=$2
              AND (endpoint=$3 OR endpoint LIKE $3 || '?%')
              AND status_code=200
            ORDER BY timestamp DESC LIMIT 1), '') AS sample_url`

// idorLeakQuery answers the id-acquisition half: does the swappable id value appear in a response on
// a sibling COLLECTION endpoint. position() avoids LIKE wildcard surprises in the id value, and the
// endpoint equality keeps the scan on the indexed collection path. $1 scope target, $2 collection
// path, $3 id value.
const idorLeakQuery = `
SELECT EXISTS(SELECT 1 FROM manual_crawl_captures
   WHERE scope_target_id=$1 AND (endpoint=$2 OR endpoint LIKE $2 || '?%')
     AND status_code=200 AND position($3 in response_body) > 0)`

// CollectIDORCandidates reads the three stored sources and returns ranked IDOR candidates. It sends
// no request and calls no model. With no id-bearing vector, or no auth-gated owner/PII evidence, it
// returns an empty slice and no error, so the pointer layer that wraps it is unchanged on a target
// that has no IDOR data.
func CollectIDORCandidates(ctx context.Context, scopeTargetID string) ([]IDORCandidate, error) {
	families, err := idorDriverFamilies(ctx, scopeTargetID)
	if err != nil {
		return nil, err
	}
	if len(families) == 0 {
		return []IDORCandidate{}, nil
	}

	clientIDs, err := idorLoadClientIdentifiers(ctx, scopeTargetID)
	if err != nil {
		return nil, err
	}
	patterns, err := idorLoadIdentityPatterns(ctx, scopeTargetID)
	if err != nil {
		return nil, err
	}

	out := []IDORCandidate{}
	for _, fam := range families {
		rep := fam.rep
		method := strings.ToUpper(firstNonEmpty(rep.Method, "GET"))

		var has200, hasOwner, hasPII, authSent bool
		var sampleURL string
		if err := dbPool.QueryRow(ctx, idorEvidenceQuery, scopeTargetID, method, rep.Path).
			Scan(&has200, &hasOwner, &hasPII, &authSent, &sampleURL); err != nil {
			return nil, fmt.Errorf("idor candidates: evidence for %s %s: %w", method, rep.Path, err)
		}

		idBearing := fam.idLoc != "" && fam.idLoc != "cookie"
		if !idorCandidateGate(idBearing, hasOwner, hasPII, authSent, has200) {
			continue
		}

		// The swappable id value: the authz model's path-segment value first (an operator-curated
		// swap target), else extracted from a sample captured URL by lining it up against the
		// template. Never fabricated. The authz tables carry no domain, so they are looked up by
		// method+templated-path (idorFamilyPathKey) rather than the domain-bearing family key.
		authzKey := idorFamilyPathKey(method, rep.Domain, rep.Path)
		knownID, knownLoc := "", fam.idLoc
		if ci, ok := clientIDs[authzKey]; ok && ci.value != "" {
			knownID, knownLoc = ci.value, firstNonEmpty(ci.location, fam.idLoc)
		}
		if knownID == "" {
			knownID = idorExtractIDFromSample(sampleURL, rep.Path)
		}

		leaked, leakSource := false, ""
		if knownID != "" {
			if coll := idorCollectionPath(rep.Path); coll != "" {
				if err := dbPool.QueryRow(ctx, idorLeakQuery, scopeTargetID, coll, knownID).Scan(&leaked); err != nil {
					leaked = false // id-leak is a scoring signal, not a gate: fail closed to not-leaked
				}
				if leaked {
					leakSource = coll
				}
			}
		}

		patternID := ""
		if p, ok := patterns[authzKey]; ok {
			patternID = p
		}

		c := IDORCandidate{
			VectorID:          rep.ID,
			Method:            method,
			URL:               idorComposeURL(rep.Scheme, rep.Domain, rep.Path),
			Path:              rep.Path,
			InsertionPoint:    rep.InsertionPoint,
			Param:             fam.param,
			IDLocation:        knownLoc,
			GuessTier:         idGuessTier(knownID),
			HasOwnerField:     hasOwner,
			HasPII:            hasPII,
			AuthClientSent:    authSent,
			IDLeaked:          leaked,
			KnownIDValue:      knownID,
			IDLeakSource:      leakSource,
			IdentityPatternID: patternID,
		}
		c.Score, c.Reasons = scoreIDORCandidate(c)
		out = append(out, c)
	}

	// Most worth an hour first. The tie-breakers make the order total so two identical corpora rank
	// identically: a ranking that wobbles is a ranking nobody can cite.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].Method != out[j].Method {
			return out[i].Method < out[j].Method
		}
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].VectorID < out[j].VectorID
	})
	return out, nil
}

// idorDriverFamilies loads every non-deleted vector and keeps one representative per endpoint: a
// path-id row where there is one, otherwise an id-like non-cookie parameter row. attack_vectors.path
// is already templated by consolidation, so it is used as-is.
func idorDriverFamilies(ctx context.Context, scopeTargetID string) (map[string]*idorFamily, error) {
	rows, err := dbPool.Query(ctx, `
		SELECT id::text, COALESCE(method,'GET'), COALESCE(scheme,'https'), COALESCE(domain,''),
		       COALESCE(path,'/'), COALESCE(insertion_point,''),
		       COALESCE(parameters, ARRAY[]::text[]), COALESCE(signals, ARRAY[]::text[])
		FROM attack_vectors
		WHERE scope_target_id = $1 AND deleted_at IS NULL
		ORDER BY domain, path, method, insertion_point`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("idor candidates: driver rows: %w", err)
	}
	defer rows.Close()

	families := map[string]*idorFamily{}
	for rows.Next() {
		var r idorDriverRow
		if err := rows.Scan(&r.ID, &r.Method, &r.Scheme, &r.Domain, &r.Path, &r.InsertionPoint,
			&r.Parameters, &r.Signals); err != nil {
			return nil, fmt.Errorf("idor candidates: scan driver row: %w", err)
		}
		loc, param, rank := idorDriverRole(r)
		if loc == "" {
			continue
		}
		key := idorFamilyKey(strings.ToUpper(r.Method), r.Domain, r.Path)
		if f, ok := families[key]; !ok || rank > f.repScore {
			families[key] = &idorFamily{rep: r, idLoc: loc, param: param, repScore: rank}
		}
	}
	return families, rows.Err()
}

// idorDriverRole decides whether a vector row is an id-bearing driver and, if so, where its id sits
// and how strong a representative it is (path beats body beats query, header is never a driver here:
// a header id is the credential, handled as AuthClientSent).
func idorDriverRole(r idorDriverRow) (loc, param string, rank int) {
	switch strings.ToLower(r.InsertionPoint) {
	case "path":
		if idorPathHasIDMarker(r.Path) || idorSignalsAny(r.Signals, SignalUUID, SignalNumericID, SignalJWT, SignalHighEntropy) {
			return "path", "", 3
		}
	case "body", "query":
		if !idorSignalsAny(r.Signals, SignalUUID, SignalJWT, SignalNumericID, SignalHighEntropy) {
			return "", "", 0
		}
		for _, name := range r.Parameters {
			if idorCookieTrackingBlacklist(name) {
				continue
			}
			if idorIDishName(name) {
				if strings.ToLower(r.InsertionPoint) == "body" {
					return "body", name, 2
				}
				return "query", name, 1
			}
		}
	}
	return "", "", 0
}

// idorPathHasIDMarker reports whether a templated path carries an id segment.
func idorPathHasIDMarker(path string) bool {
	for _, m := range []string{"{uuid}", "{id}", "{token}", "{jwt}"} {
		if strings.Contains(path, m) {
			return true
		}
	}
	return false
}

func idorSignalsAny(signals []string, want ...string) bool {
	for _, s := range signals {
		for _, w := range want {
			if s == w {
				return true
			}
		}
	}
	return false
}

// idorCollectionPath is the path up to the first id segment, i.e. the sibling collection that lists
// the ids this endpoint takes. /api/v1/accounts/{uuid}/details -> /api/v1/accounts. Empty when the
// very first segment is an id, since there is no collection above it.
func idorCollectionPath(path string) string {
	segs := strings.Split(path, "/")
	var kept []string
	for _, s := range segs {
		if s == "{uuid}" || s == "{id}" || s == "{token}" || s == "{jwt}" {
			break
		}
		kept = append(kept, s)
	}
	coll := strings.Join(kept, "/")
	if coll == "" || coll == path {
		return ""
	}
	return coll
}

// idorExtractIDFromSample lines a concrete captured URL up against the templated path and returns the
// first segment that the template marked as an id. Deterministic and read-only: it reads a value the
// crawl already stored, it does not fetch anything.
func idorExtractIDFromSample(sampleURL, templatedPath string) string {
	if strings.TrimSpace(sampleURL) == "" {
		return ""
	}
	u, err := url.Parse(sampleURL)
	if err != nil {
		return ""
	}
	concrete := strings.Split(u.Path, "/")
	template := strings.Split(templatedPath, "/")
	if len(concrete) != len(template) {
		return ""
	}
	for i := range template {
		switch template[i] {
		case "{uuid}", "{id}", "{token}", "{jwt}":
			if concrete[i] != "" {
				return concrete[i]
			}
		}
	}
	return ""
}

func idorComposeURL(scheme, domain, path string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	scheme = firstNonEmpty(strings.TrimSpace(scheme), "https")
	if strings.TrimSpace(path) == "" {
		path = "/"
	}
	return scheme + "://" + domain + path
}

func idorFamilyKey(method, domain, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + "\x00" + strings.ToLower(strings.TrimSpace(domain)) + "\x00" + path
}

// idorPatternKey keys the authz model's rows, which carry no domain of their own, by method and
// templated path alone. The driver families are also looked up by method and templated path (the
// domain in idorFamilyKey is dropped for this lookup by idorFamilyPathKey), which is correct for a
// single-host engagement and the common case; a cross-host name collision is a known, documented
// edge.
func idorPatternKey(method, templatedPath string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + "\x00" + templatedPath
}

// idorClientIdent is the swap target the authz model recorded for an endpoint.
type idorClientIdent struct {
	value    string
	location string
}

// idorLoadClientIdentifiers templates each client identifier's endpoint URL and keeps the
// path-segment value (the id to swap) per endpoint, preferring a row the operator labelled as the
// path segment.
func idorLoadClientIdentifiers(ctx context.Context, scopeTargetID string) (map[string]idorClientIdent, error) {
	rows, err := dbPool.Query(ctx, `
		SELECT endpoint_url, COALESCE(method,'GET'), value, COALESCE(label,'')
		FROM authz_client_identifiers WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("idor candidates: client identifiers: %w", err)
	}
	defer rows.Close()

	out := map[string]idorClientIdent{}
	pathLabelled := map[string]bool{}
	for rows.Next() {
		var endpointURL, method, value, label string
		if err := rows.Scan(&endpointURL, &method, &value, &label); err != nil {
			return nil, fmt.Errorf("idor candidates: scan client identifier: %w", err)
		}
		key := idorPatternKey(method, idorTemplatedPath(endpointURL))
		isPath := strings.Contains(strings.ToLower(label), "path")
		if _, ok := out[key]; ok && !isPath {
			continue // a path-labelled value already won this endpoint
		}
		if pathLabelled[key] && !isPath {
			continue
		}
		loc := "path"
		if !isPath {
			loc = ""
		}
		out[key] = idorClientIdent{value: value, location: loc}
		if isPath {
			pathLabelled[key] = true
		}
	}
	return out, rows.Err()
}

// idorLoadIdentityPatterns keys each category=parameter identity pattern by the method and templated
// path parsed out of its stored raw request, so a candidate can carry the pattern's id (and through
// it the pre-formed replay the pointer layer surfaces).
func idorLoadIdentityPatterns(ctx context.Context, scopeTargetID string) (map[string]string, error) {
	rows, err := dbPool.Query(ctx, `
		SELECT id::text, COALESCE(raw_request,'')
		FROM authz_identity_patterns
		WHERE scope_target_id = $1 AND category = 'parameter'`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("idor candidates: identity patterns: %w", err)
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var id, raw string
		if err := rows.Scan(&id, &raw); err != nil {
			return nil, fmt.Errorf("idor candidates: scan identity pattern: %w", err)
		}
		method, path := idorMethodPathFromRaw(raw)
		if method == "" || path == "" {
			continue
		}
		key := idorPatternKey(method, path)
		if _, ok := out[key]; !ok {
			out[key] = id
		}
	}
	return out, rows.Err()
}

// idorTemplatedPath extracts a path from a URL or bare path and templates it with the SAME function
// consolidation used, so an authz endpoint URL keys the same way as attack_vectors.path.
func idorTemplatedPath(rawPathOrURL string) string {
	s := strings.TrimSpace(rawPathOrURL)
	if s == "" {
		return ""
	}
	if u, err := url.Parse(s); err == nil && u.Path != "" {
		s = u.Path
	} else if i := strings.IndexAny(s, "?#"); i >= 0 {
		s = s[:i]
	}
	tp, _ := templateVectorPath(s)
	return tp
}

// idorMethodPathFromRaw reads the method and templated path off a stored raw request's request line.
func idorMethodPathFromRaw(raw string) (string, string) {
	line := raw
	if i := strings.IndexAny(raw, "\r\n"); i >= 0 {
		line = raw[:i]
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) < 2 {
		return "", ""
	}
	return strings.ToUpper(parts[0]), idorTemplatedPath(parts[1])
}

// idorFamilyPathKey re-derives the pattern-key (method + templated path, no domain) from a family
// key so the authz lookups line up with the driver families.
func idorFamilyPathKey(method, domain, path string) string {
	return idorPatternKey(method, path)
}
