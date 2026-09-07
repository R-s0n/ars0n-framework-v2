package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// The list of endpoints active flow detection must never send a request to.
//
// This file exists before the scanner does, and that ordering is the point. Active detection sends
// real requests to a live target under a bug bounty programme, and on one target already in this
// operator's notes SIX endpoints dispatch a one-time code to a REAL CUSTOMER when they are hit with
// an identifier that resolves. A scanner without a way to say "not that one" is a button that emails
// and texts strangers, so the mechanism is built first and the scanner is written on top of it.
//
// Nothing is pre-seeded. A seeded list would be a guess about somebody else's application, and a
// wrong guess in either direction is bad: a missing entry gives false confidence, and an invented one
// silently removes coverage. The operator adds entries, the dry run shows them what a run would hit
// so they know what to add, and every excluded endpoint is reported back rather than quietly dropped.
//
// `reason` is NOT NULL and not blank. An exclusion with no explanation is an exclusion the next
// operator deletes, or worse, keeps for the wrong reason. "verification code, emails the account
// owner" survives a handover; an empty string does not.

// ---------------------------------------------------------------------------
// The matcher
// ---------------------------------------------------------------------------

// FlowExclusion is one operator-authored rule.
type FlowExclusion struct {
	ID        string    `json:"id"`
	Pattern   string    `json:"pattern"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"created_at"`
}

// Matches reports whether this rule covers the given host and path.
//
// PATTERN GRAMMAR, deliberately small, because a matcher an operator cannot predict is a matcher
// they will not trust with the endpoint that texts their customers:
//
//	/account/verify          a path on ANY host
//	api.example.com/verify   a path on ONE host
//	api.example.com          an entire host
//	*.example.com/verify     a path on that domain and every subdomain of it
//	/account/*/resend        `*` matches any run of characters, including `/`
//
// TWO RULES DECIDE EVERYTHING ELSE.
//
// FIRST, a pattern with no `*` in its path is a SUBTREE match at a path-segment boundary, not a
// substring one. `/home` covers `/home`, `/home/` and `/home/settings`, and does NOT cover
// `/homepage`. Substring matching here would be a silent over-match: the operator excludes `/home`,
// the scanner also skips `/homepage`, and they never find out they lost it. Requiring an exact match
// instead would be the opposite failure, where excluding `/account/close` still lets
// `/account/close/confirm` through.
//
// SECOND, where the two directions genuinely conflict, this over-matches. Host comparison and path
// comparison are both case-insensitive even though paths are case-sensitive on the wire, and `*`
// crosses `/`. Over-matching costs coverage the operator can SEE, because the dry run lists every
// excluded endpoint with the rule and the reason that excluded it. Under-matching sends a request
// nobody wanted sent, and there is no undo for that.
//
// The query string is compared only when the pattern itself contains a `?`. Active detection strips
// query strings before it sends anything (see flowDetectionActive.go), so in the normal case there is
// no query to compare; an operator who has turned that off can still exclude `/reset?token=*`.
func (e FlowExclusion) Matches(host, path, rawQuery string) bool {
	return flowExclusionMatches(e.Pattern, host, path, rawQuery)
}

func flowExclusionMatches(pattern, host, path, rawQuery string) bool {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		// An empty pattern matching everything would turn a typo into a scanner that does nothing and
		// reports every endpoint as deliberately excluded.
		return false
	}
	pattern = strings.ToLower(pattern)

	// A pattern pasted straight out of the browser keeps its scheme. Strip it rather than refuse it:
	// the operator's intent is unambiguous and rejecting it teaches nothing.
	if i := strings.Index(pattern, "://"); i >= 0 {
		pattern = pattern[i+3:]
	}
	pattern = strings.TrimSuffix(pattern, "#")
	if i := strings.Index(pattern, "#"); i >= 0 {
		pattern = pattern[:i]
	}

	hostPart, pathPart := splitFlowExclusionPattern(pattern)

	if !flowExclusionHostMatches(hostPart, strings.ToLower(strings.Trim(host, "."))) {
		return false
	}
	if pathPart == "" {
		// Host-only pattern: the whole host is off limits.
		return true
	}

	candidate := path
	if candidate == "" {
		candidate = "/"
	}
	if !strings.HasPrefix(candidate, "/") {
		candidate = "/" + candidate
	}
	if strings.Contains(pathPart, "?") && rawQuery != "" {
		candidate += "?" + rawQuery
	}
	candidate = strings.ToLower(candidate)

	if strings.Contains(pathPart, "*") {
		return flowGlobMatch(pathPart, candidate)
	}

	// The segment-boundary subtree rule. Trailing slashes are normalised away first so `/home` and
	// `/home/` are the same rule, which is what an operator typing either of them means.
	base := strings.TrimSuffix(pathPart, "/")
	if base == "" {
		// The pattern was "/" — the whole host, which is a thing an operator is allowed to say.
		return true
	}
	trimmedCandidate := strings.TrimSuffix(candidate, "/")
	if trimmedCandidate == base {
		return true
	}
	return strings.HasPrefix(candidate, base+"/")
}

// splitFlowExclusionPattern separates the host half from the path half. A pattern that starts with
// `/` has no host half and therefore applies to every host, which is the right default: an operator
// naming a dangerous path usually means the path, wherever it is served from.
func splitFlowExclusionPattern(pattern string) (hostPart, pathPart string) {
	if strings.HasPrefix(pattern, "/") {
		return "", pattern
	}
	if i := strings.Index(pattern, "/"); i >= 0 {
		return pattern[:i], pattern[i:]
	}
	return pattern, ""
}

func flowExclusionHostMatches(hostPart, host string) bool {
	if hostPart == "" || hostPart == "*" {
		return true
	}
	if host == "" {
		return false
	}
	// A port in the pattern or the candidate is not part of the identity of a host here. Excluding
	// api.example.com must cover api.example.com:8443, because the endpoint that texts a customer
	// does not become safe on another port.
	hostPart = stripFlowHostPort(hostPart)
	host = stripFlowHostPort(host)

	if strings.HasPrefix(hostPart, "*.") {
		base := hostPart[2:]
		// The domain itself is included. An operator writing *.example.com to keep a scanner off that
		// programme means the programme, and reading it as "every subdomain except the apex" would be
		// a boundary that fails on the one host most likely to matter.
		return host == base || strings.HasSuffix(host, "."+base)
	}
	if strings.Contains(hostPart, "*") {
		return flowGlobMatch(hostPart, host)
	}
	return host == hostPart
}

func stripFlowHostPort(h string) string {
	// Only a trailing :digits is a port. An IPv6 literal is full of colons and must survive intact.
	i := strings.LastIndex(h, ":")
	if i < 0 || strings.Contains(h[i+1:], "]") || strings.Contains(h[i+1:], ".") {
		return h
	}
	for _, c := range h[i+1:] {
		if c < '0' || c > '9' {
			return h
		}
	}
	if i+1 >= len(h) {
		return h
	}
	return h[:i]
}

// flowGlobMatch is an anchored wildcard match where `*` is the only metacharacter and it crosses `/`.
//
// `?` is deliberately NOT a wildcard: it is the query separator in every URL an operator will paste,
// and a matcher where a pasted URL silently means something other than itself is a matcher that will
// eventually skip the wrong endpoint.
//
// Iterative with backtracking rather than recursive, so a pattern of a hundred stars against a long
// URL cannot blow the stack of the HTTP handler that called it.
func flowGlobMatch(pattern, s string) bool {
	pi, si := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		switch {
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			pi++
			mark = si
		case pi < len(pattern) && pattern[pi] == s[si]:
			pi++
			si++
		case star >= 0:
			pi = star + 1
			mark++
			si = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// FlowExclusionDecision is why one endpoint was kept out of a run. The rule and the reason travel
// with it, because "31 endpoints were excluded" is not something an operator can act on.
type FlowExclusionDecision struct {
	Excluded bool   `json:"excluded"`
	Pattern  string `json:"pattern,omitempty"`
	Reason   string `json:"reason,omitempty"`
	ID       string `json:"exclusion_id,omitempty"`
}

// FirstFlowExclusionMatch returns the first rule covering this URL, in creation order, so the same
// URL always reports the same rule rather than whichever one the map iterated to first.
func FirstFlowExclusionMatch(rules []FlowExclusion, rawURL string) FlowExclusionDecision {
	parsed, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		// An unparseable URL is not something to guess about. The caller refuses it separately; here
		// the honest answer is that no rule was found to cover it.
		return FlowExclusionDecision{}
	}
	host := parsed.Hostname()
	path := parsed.Path
	for _, rule := range rules {
		if rule.Matches(host, path, parsed.RawQuery) {
			return FlowExclusionDecision{Excluded: true, Pattern: rule.Pattern, Reason: rule.Reason, ID: rule.ID}
		}
	}
	return FlowExclusionDecision{}
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// LoadFlowExclusions reads a target's rules in creation order.
//
// An error is returned rather than swallowed and an empty list is NOT substituted for one. A failed
// read of the exclusion list must fail the run: the alternative is a scanner that loses the operator's
// "do not touch this, it texts customers" rule to a transient database error and sends the request
// anyway.
func LoadFlowExclusions(scopeTargetID string) ([]FlowExclusion, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT id, pattern, COALESCE(reason,''), created_at
		   FROM flow_detection_exclusions
		  WHERE scope_target_id = $1
		  ORDER BY created_at ASC, id ASC`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []FlowExclusion{}
	for rows.Next() {
		var e FlowExclusion
		if err := rows.Scan(&e.ID, &e.Pattern, &e.Reason, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// GET /flow-detection/{scope_target_id}/exclusions
// ---------------------------------------------------------------------------

func GetFlowDetectionExclusions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	rules, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		log.Printf("[FLOW-DETECT] Failed to load exclusions for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The exclusion list could not be read: "+err.Error())
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"exclusions": rules,
		"count":      len(rules),
	})
}

// ---------------------------------------------------------------------------
// POST /flow-detection/{scope_target_id}/exclusions
// ---------------------------------------------------------------------------

type flowExclusionRequest struct {
	Pattern string `json:"pattern"`
	Reason  string `json:"reason"`
}

func CreateFlowDetectionExclusion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var req flowExclusionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
		return
	}

	pattern := strings.TrimSpace(req.Pattern)
	reason := strings.TrimSpace(req.Reason)
	if pattern == "" {
		writeJSONError(w, http.StatusBadRequest, "pattern_required",
			"A pattern is required. Use a path (/account/verify), a host (api.example.com), or both "+
				"(api.example.com/account/verify). * matches any run of characters.")
		return
	}
	if reason == "" {
		// Refused, not defaulted. An exclusion whose reason is "added by the UI" is an exclusion the
		// next operator deletes because nothing on screen tells them what it was protecting.
		writeJSONError(w, http.StatusBadRequest, "reason_required",
			"A reason is required. Write what this endpoint does, for example \"sends a verification "+
				"code to the account owner\". An exclusion with no reason gets deleted by whoever "+
				"reads this list next.")
		return
	}

	// A pattern that cannot match anything is a rule the operator believes is protecting them and is
	// not. Checked here rather than at run time, when it is too late to matter.
	if hostPart, pathPart := splitFlowExclusionPattern(strings.ToLower(pattern)); hostPart == "" && pathPart == "" {
		writeJSONError(w, http.StatusBadRequest, "pattern_matches_nothing",
			"That pattern cannot match any endpoint.")
		return
	}

	id := uuid.New().String()
	_, err := dbPool.Exec(context.Background(),
		`INSERT INTO flow_detection_exclusions (id, scope_target_id, pattern, reason)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (scope_target_id, pattern) DO UPDATE SET reason = EXCLUDED.reason`,
		id, scopeTargetID, pattern, reason)
	if err != nil {
		log.Printf("[FLOW-DETECT] Failed to add exclusion %q for %s: %v", pattern, scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The exclusion could not be saved: "+err.Error())
		return
	}

	log.Printf("[FLOW-DETECT] Exclusion added for %s: %q (%s)", scopeTargetID, pattern, reason)

	rules, _ := LoadFlowExclusions(scopeTargetID)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":    true,
		"exclusions": rules,
	})
}

// ---------------------------------------------------------------------------
// DELETE /flow-detection/exclusions/{id}
// ---------------------------------------------------------------------------

func DeleteFlowDetectionExclusion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	id := mux.Vars(r)["id"]
	if _, err := uuid.Parse(id); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_id", "id must be a UUID")
		return
	}

	tag, err := dbPool.Exec(context.Background(),
		`DELETE FROM flow_detection_exclusions WHERE id = $1`, id)
	if err != nil {
		log.Printf("[FLOW-DETECT] Failed to delete exclusion %s: %v", id, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The exclusion could not be deleted: "+err.Error())
		return
	}
	if tag.RowsAffected() == 0 {
		writeJSONError(w, http.StatusNotFound, "not_found", "No exclusion with that id")
		return
	}

	log.Printf("[FLOW-DETECT] Exclusion %s deleted", id)
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// ---------------------------------------------------------------------------
// The hard host deny, which is not an exclusion rule and must not be confused with one
// ---------------------------------------------------------------------------

// ExcludedScopeHosts returns the hosts this target has explicitly marked in_scope=false.
//
// THIS IS SEPARATE FROM ScanScope ON PURPOSE, and it is not redundant with it.
//
// LoadScanScope drops an in_scope=false host from its `extra` list, which is enough only when that
// host was in the boundary BECAUSE the crawl saw it. It is not enough when the host also sits inside
// the target's own registrable domain: analytics.example.com marked in_scope=false on a target whose
// domain is example.com is still admitted by ScanScope.Allows, because the *.example.com rule covers
// it independently of the crawl list. The operator ticked a box that says "never send here" and the
// boundary they were shown says otherwise.
//
// Active detection is the wrong feature to discover that in. So the deny is applied as a separate,
// unconditional filter that runs BEFORE the scope check, and a host on this list is never selected,
// never followed as a redirect destination, and reported as excluded so the operator sees why.
func ExcludedScopeHosts(scopeTargetID string) (map[string]bool, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT lower(host) FROM scope_target_scope_hosts
		  WHERE scope_target_id = $1 AND in_scope = FALSE`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		if host = strings.Trim(strings.TrimSpace(host), "."); host != "" {
			out[host] = true
		}
	}
	return out, rows.Err()
}

// IsDeniedFlowHost reports whether a host, or any parent domain of it, was marked in_scope=false.
//
// The parent walk matters: excluding example.com and then requesting tracking.example.com would
// honour the letter of the operator's decision and break its meaning. Checking parents over-matches
// in the safe direction, which is the same trade the pattern matcher makes.
func IsDeniedFlowHost(denied map[string]bool, host string) bool {
	host = strings.ToLower(strings.Trim(strings.TrimSpace(host), "."))
	if host == "" || len(denied) == 0 {
		return false
	}
	host = stripFlowHostPort(host)
	if denied[host] {
		return true
	}
	labels := strings.Split(host, ".")
	for i := 1; i < len(labels); i++ {
		if denied[strings.Join(labels[i:], ".")] {
			return true
		}
	}
	return false
}

// SortedFlowExclusionPatterns is used by the dry run's summary so the operator sees the whole list
// they are running under, not only the rules that happened to fire.
func SortedFlowExclusionPatterns(rules []FlowExclusion) []string {
	out := make([]string, 0, len(rules))
	for _, r := range rules {
		out = append(out, r.Pattern)
	}
	sort.Strings(out)
	return out
}
