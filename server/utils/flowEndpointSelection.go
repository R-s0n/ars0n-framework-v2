package utils

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Which endpoints active flow detection may touch.
//
// ============================================================================
// EVERYTHING IS SELECTED BY DEFAULT, AND THIS STORES THE DESELECTIONS
// ============================================================================
//
// That is the load-bearing decision in this file and it is worth being explicit about, because the
// obvious alternative looks identical on screen and is wrong.
//
// Suppose the table stored SELECTIONS instead. The operator opens Configure on a corpus of 400
// endpoints, unticks the twelve they do not want, saves, and detection scans 388. Two days later
// they crawl again and the corpus is 900. Those 500 new endpoints have no row in a selections table,
// so they are not selected, so detection never touches them - and there is nothing on the screen to
// say so. The operator configured once, discovered more surface, and quietly stopped scanning all of
// it, while the run still says "completed". That is a scanner reporting a clean result for traffic it
// never sent, which is the failure this whole feature exists to avoid.
//
// Storing the NEGATIVE keeps the default correct as the corpus grows. A newly discovered endpoint
// has no row, so it is selected, so it is scanned. The only endpoints skipped are the ones somebody
// explicitly took out, which is the only claim this table should ever be able to make.
//
// The cost of this choice is that "deselect all" is a statement about the endpoints that existed
// when you pressed it, not a standing rule - anything discovered afterwards comes back selected. The
// API says so in its response rather than leaving it to be discovered later.
//
// ============================================================================
// SELECTION IS NOT AN EXCLUSION, AND MUST NOT BECOME ONE
// ============================================================================
//
// flow_detection_exclusions is a permanent "never send here" rule with a mandatory reason, written
// because six endpoints on one of this operator's targets dispatch a one-time code to a real
// customer. A deselection is "not this run's problem" and needs no reason. They are separate tables,
// they are reported separately in the dry run, and re-selecting an endpoint does NOT overturn an
// exclusion. If the two were one flag, the cheap control would be able to silently delete the
// expensive one.

// ---------------------------------------------------------------------------
// The key
// ---------------------------------------------------------------------------

// FlowEndpointKey is the stable identity of one thing active detection can send.
//
// SHAPE:  METHOD|host[:port]|/canonical/path      e.g. GET|api.example.com|/account/verify
//
// Readable rather than hashed, deliberately. This is an operator-facing config table: a key you can
// read in a log line, paste into a SQL query, and recognise on a screen is worth more here than the
// four bytes a hash would save, and every other identity in this codebase that had to be debugged
// was debugged by first un-hashing it.
//
// IT IS DERIVED THROUGH CanonicalizeEndpoint, which is what makes it survive a re-crawl: the same
// dot-segment removal, percent-encoding normalisation, duplicate-slash collapse, trailing-slash trim
// and case preservation the endpoint list itself uses. A key computed by hand here would drift from
// the list within one release and the operator's deselections would silently stop matching anything.
//
// THREE THINGS ARE DELIBERATELY ABSENT, and each omission is a decision:
//
//	THE QUERY STRING.  Detection strips query strings before sending, so /search?q=a and /search?q=b
//	                   are ONE request to /search. This is why the key is deliberately COARSER than
//	                   consolidated_url_endpoints.endpoint_key, which includes the identity query:
//	                   keying on the finer identity would give the operator a deselect control that
//	                   removes one of fifty identical requests and changes nothing on the wire. The
//	                   coarse key also errs in the safe direction - a deselection covers MORE than the
//	                   row that was clicked, never less.
//	THE SCHEME.        http://host/a and https://host/a are one endpoint over two transports, which is
//	                   the same rule CanonicalizeEndpoint applies and for the same reason.
//	THE CLIENT ROUTE.  A #!/route is not sent to the server at all.
func FlowEndpointKey(rawURL, method string) (string, bool) {
	id, ok := CanonicalizeEndpoint(rawURL, method, "https")
	if !ok {
		return "", false
	}
	hostPort := id.Host
	if id.Port != 0 {
		hostPort = id.Host + ":" + strconv.Itoa(id.Port)
	}
	return id.Method + "|" + hostPort + "|" + id.CanonicalPath, true
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

// LoadFlowEndpointDeselections reads the keys this target has taken out.
//
// An error is RETURNED and an empty set is never substituted for one. The substitution would be safe
// in the traffic sense - everything stays selected, nothing gets skipped - but it is dishonest in the
// direction that matters: the operator unticked an endpoint, the read failed, and the scanner sent it
// anyway while reporting a normal run. The exclusion list fails closed for the same reason.
func LoadFlowEndpointDeselections(scopeTargetID string) (map[string]bool, error) {
	rows, err := dbPool.Query(context.Background(),
		`SELECT endpoint_key FROM flow_endpoint_deselections WHERE scope_target_id = $1`,
		scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]bool{}
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		if k = strings.TrimSpace(k); k != "" {
			out[k] = true
		}
	}
	return out, rows.Err()
}

// flowSelectionMaxKeys caps one bulk call. Above this the client is enumerating a corpus rather than
// making a choice, and `all` is the call it wanted.
const flowSelectionMaxKeys = 50000

// SetFlowEndpointSelection is the bulk set. selected=true DELETES the deselection rows (returning
// those endpoints to the default), selected=false INSERTS them.
//
// One statement either way, so select-all and select-none are one round trip rather than a thousand.
func SetFlowEndpointSelection(scopeTargetID string, keys []string, selected bool) (int64, error) {
	clean := normalizeFlowSelectionKeys(keys)
	if len(clean) == 0 {
		return 0, nil
	}

	if selected {
		tag, err := dbPool.Exec(context.Background(),
			`DELETE FROM flow_endpoint_deselections
			  WHERE scope_target_id = $1 AND endpoint_key = ANY($2::text[])`,
			scopeTargetID, clean)
		if err != nil {
			return 0, err
		}
		return tag.RowsAffected(), nil
	}

	tag, err := dbPool.Exec(context.Background(),
		`INSERT INTO flow_endpoint_deselections (scope_target_id, endpoint_key)
		 SELECT $1, k FROM unnest($2::text[]) AS k
		 ON CONFLICT (scope_target_id, endpoint_key) DO NOTHING`,
		scopeTargetID, clean)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// normalizeFlowSelectionKeys trims, drops blanks and deduplicates, preserving the order the client
// sent so a log line reads the way the operator's screen did.
//
// The dedupe is not tidiness. The DELETE branch uses = ANY($2), where a repeated key is harmless, but
// the INSERT branch feeds unnest() into an ON CONFLICT DO NOTHING, and Postgres refuses a command
// that tries to affect the same row twice in one statement: a list containing the same key twice
// would fail the whole bulk call with "cannot affect row a second time" rather than deselecting
// anything. A UI that sends a key twice is not misbehaving, it just has two rows on screen that
// collapsed to one endpoint - which, given the query-stripping key, is the normal case.
func normalizeFlowSelectionKeys(keys []string) []string {
	clean := make([]string, 0, len(keys))
	seen := map[string]bool{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		clean = append(clean, k)
	}
	return clean
}

// ClearFlowEndpointDeselections returns every endpoint on this target to the default.
func ClearFlowEndpointDeselections(scopeTargetID string) (int64, error) {
	tag, err := dbPool.Exec(context.Background(),
		`DELETE FROM flow_endpoint_deselections WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// loadFlowEndpointStatuses maps each flow endpoint key to the status codes the crawl observed.
//
// Kept SEPARATE from loadFlowDetectionCandidates rather than merged into it. The candidate loader is
// the single answer to "what exists on this target", shared by the planner and by this list, and two
// loaders is how a config screen ends up offering an endpoint the planner does not know about. This
// is a side lookup that decorates that one list and can return nothing without changing what is in it.
//
// THERE IS NO "LAST STATUS" AND THIS DOES NOT INVENT ONE. consolidation stores status_codes as a SET
// (a map[int]bool, written whole on every run), so the array carries no order and the last element is
// not the most recent observation. Reporting one as "last status" would be a number that looks like a
// fact and is not, which is the same class of defect as a count that counts something else.
//
// BOTH SOURCES ARE READ, and the crawl one is not optional decoration. loadFlowDetectionCandidates
// sources endpoints from the crawl as well as from consolidation, so reading statuses from
// consolidation alone left every crawl-discovered row with an empty status list. Empty is documented
// on FlowEndpointRow as "nobody has requested it yet", which would have been a plain untruth about an
// endpoint the operator's own browser had just hit two hundred times and recorded the answer to.
func loadFlowEndpointStatuses(scopeTargetID string) (map[string][]int, error) {
	merged := map[string]map[int]bool{}
	observe := func(key string, codes ...int) {
		if merged[key] == nil {
			merged[key] = map[int]bool{}
		}
		for _, c := range codes {
			if c > 0 {
				merged[key][c] = true
			}
		}
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(url,''), COALESCE(NULLIF(method,''),'GET'), COALESCE(status_codes,'[]'::jsonb)
		  FROM consolidated_url_endpoints
		 WHERE scope_target_id = $1 AND deleted_at IS NULL AND COALESCE(url,'') <> ''`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var rawURL, method string
		var raw []byte
		if err := rows.Scan(&rawURL, &method, &raw); err != nil {
			continue
		}
		key, ok := FlowEndpointKey(rawURL, method)
		if !ok {
			continue
		}
		var codes []int
		if len(raw) > 0 {
			_ = json.Unmarshal(raw, &codes)
		}
		observe(key, codes...)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// status_code 0 is the crawl's marker for "no response was observed", which happens when the
	// request failed or was only seen by the network observer. It is filtered out rather than reported,
	// because a 0 on a status list reads as a status.
	crows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT COALESCE(url,''), COALESCE(NULLIF(method,''),'GET'), status_code
		  FROM manual_crawl_captures
		 WHERE scope_target_id = $1 AND COALESCE(url,'') <> '' AND url LIKE 'http%'
		   AND COALESCE(status_code,0) > 0`, scopeTargetID)
	if err != nil {
		return nil, err
	}
	defer crows.Close()
	for crows.Next() {
		var rawURL, method string
		var code int
		if err := crows.Scan(&rawURL, &method, &code); err != nil {
			continue
		}
		key, ok := FlowEndpointKey(rawURL, method)
		if !ok {
			continue
		}
		observe(key, code)
	}
	if err := crows.Err(); err != nil {
		return nil, err
	}

	out := make(map[string][]int, len(merged))
	for k, set := range merged {
		list := make([]int, 0, len(set))
		for c := range set {
			list = append(list, c)
		}
		sort.Ints(list)
		out[k] = list
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

// FlowEndpointRow is one endpoint as the Configure screen sees it.
//
// Selected and Sendable are SEPARATE fields and the difference is the point. Selected is the
// operator's own choice and nothing else touches it. Sendable is whether the STANDING rules would
// let a run reach this endpoint: the deselection, the denied-host list, the scope boundary and the
// exclusion rules. A row that is selected and not sendable is a real and common state - the operator
// ticked it, and an exclusion still refuses it - and collapsing the two into one tick box would
// either hide the exclusion or make it look like the operator's decision.
//
// SENDABLE IS NOT "THIS RUN WILL REQUEST IT", and the difference is worth stating because it is the
// kind of near-synonym that turns into a wrong number on a screen. A run also applies its OWN
// config, which this screen deliberately knows nothing about: an endpoint recorded as POST is not
// sent by a GET-only run, and an endpoint past max_requests is reported over_budget. Both are facts
// about the run, not about the endpoint, so neither belongs in a per-target configuration list that
// is read before any run is configured.
//
// The two arithmetics that DO hold, and they are checked separately:
//
//	total - deselected - excluded - out_of_scope        = sendable        (this list)
//	sendable - method-filtered - over_budget - unusable = request_count   (the plan)
type FlowEndpointRow struct {
	EndpointKey string `json:"endpoint_key"`
	Method      string `json:"method"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	// URL is the exact string detection would put on the wire for this row, query string stripped.
	URL string `json:"url"`
	// Sources is every table this endpoint was found in, sorted: manual_crawl, consolidated,
	// attack_vector, or any combination. Worth reading rather than ignoring: an endpoint carrying only
	// manual_crawl is one the operator's browser reached that consolidation has not caught up with yet,
	// which is the normal state immediately after a recording and before a consolidate run.
	Sources []string `json:"sources"`
	// ObservedStatusCodes is every status the crawl recorded for this endpoint, sorted and
	// deduplicated. Empty means nobody has requested it yet, which is not the same as 0.
	ObservedStatusCodes []int `json:"observed_status_codes"`

	Selected bool `json:"selected"`
	Sendable bool `json:"sendable"`
	// NotSentReason is why a run would skip this row, using the same reason codes as the dry run's
	// skipped list: deselected | exclusion | host_excluded | out_of_scope. Empty when sendable.
	NotSentReason string `json:"not_sent_reason,omitempty"`
	// Pattern and Detail carry the exclusion rule and its reason, so the screen can show WHY without
	// a second lookup. An exclusion nobody can see the reason for is one the next operator deletes.
	Pattern string `json:"pattern,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// FlowEndpointSummary partitions the corpus. Every endpoint is counted in exactly one of Deselected,
// Excluded, OutOfScope and Sendable, so the four add up to Total and the arithmetic on screen holds.
//
// Selected is deliberately NOT one of those four: it is Total minus Deselected, and it overlaps the
// other three, because an endpoint can be selected and still refused by a rail.
type FlowEndpointSummary struct {
	Total      int `json:"total"`
	Selected   int `json:"selected"`
	Deselected int `json:"deselected"`
	Excluded   int `json:"excluded"`
	OutOfScope int `json:"out_of_scope"`
	Sendable   int `json:"sendable"`
	// Matched is how many rows the current filter returned. Named so it cannot be mistaken for a
	// corpus total, which is exactly the confusion four other fields in this codebase already caused.
	Matched int `json:"matched"`
	// Returned is how many rows are in this page of the response.
	Returned int `json:"returned"`
}

// FlowEndpointFilter is the (simple) filtering this endpoint supports.
//
// NOT the capture query language. BuildCaptureFilter compiles to SQL against manual_crawl_captures'
// own columns (url, status_code, post_data, mime_type); this list is assembled in Go by merging two
// different tables and deduplicating on the flow key, so there is no single table for that predicate
// to run against. Rather than build a second, in-memory evaluator that would drift from the SQL one
// and answer the same query differently in two places, this is a plain case-insensitive substring
// match over method, host, path and URL, plus three explicit state filters.
type FlowEndpointFilter struct {
	Query string // substring over method, host, path and URL
	// State is one of: "", selected, deselected, excluded, out_of_scope, sendable.
	State  string
	Source string // "", manual_crawl, consolidated, attack_vector
	Limit  int
	Offset int
}

// BuildFlowEndpointList is the whole list, as a pure function over what was read from the database.
//
// Pure on purpose, same as buildFlowDetectionPlan: what this returns decides which endpoints a
// scanner will send traffic to, and a decision that can only be exercised against a live 6,000-row
// corpus is a decision nobody will ever check.
//
// PRECEDENCE, and it matches PartitionFlowCandidatesBySelection so the screen and the run agree:
// deselected first (the operator's own choice explains it best), then the in_scope=false deny, then
// the scope boundary, then the exclusion rules.
func BuildFlowEndpointList(
	candidates []flowDetectionCandidate, statuses map[string][]int, deselected map[string]bool,
	rules []FlowExclusion, denied map[string]bool, scope *ScanScope, filter FlowEndpointFilter,
) ([]FlowEndpointRow, FlowEndpointSummary) {

	byKey := map[string]*FlowEndpointRow{}
	order := []string{}

	for _, c := range candidates {
		key, ok := FlowEndpointKey(c.URL, c.Method)
		if !ok {
			// Unparseable rows are not listed. They cannot be selected or deselected because they
			// have no stable identity, and the planner already reports them as unusable_url where an
			// operator can act on them.
			continue
		}
		// The displayed URL is what the planner would send, so the two screens cannot disagree about
		// what a row means. IncludeQuery is deliberately false here: the config screen is about which
		// ENDPOINTS may be touched, and the query string is a per-run decision.
		sendable, parsed, err := flowDetectionSendableURL(c.URL, false)
		if err != nil {
			continue
		}

		row, exists := byKey[key]
		if !exists {
			row = &FlowEndpointRow{
				EndpointKey:         key,
				Method:              strings.ToUpper(strings.TrimSpace(c.Method)),
				Host:                parsed.Host,
				Path:                parsed.Path,
				URL:                 sendable,
				Sources:             []string{},
				ObservedStatusCodes: statuses[key],
			}
			if row.Method == "" {
				row.Method = http.MethodGet
			}
			if row.ObservedStatusCodes == nil {
				row.ObservedStatusCodes = []int{}
			}
			byKey[key] = row
			order = append(order, key)
		}
		if c.Source != "" && !flowListContains(row.Sources, c.Source) {
			row.Sources = append(row.Sources, c.Source)
			sort.Strings(row.Sources)
		}
	}

	summary := FlowEndpointSummary{Total: len(order)}
	rows := make([]FlowEndpointRow, 0, len(order))

	for _, key := range order {
		row := byKey[key]
		row.Selected = !deselected[key]

		// The bare hostname, without the port: that is what the deny list and the scope boundary are
		// both keyed on. row.Host keeps the port because the operator needs to see it.
		host := hostFromFlowURL(row.URL)

		switch {
		case !row.Selected:
			row.NotSentReason = "deselected"
			row.Detail = "you took this endpoint out of the selection for this target"
			summary.Deselected++
		case IsDeniedFlowHost(denied, host):
			row.NotSentReason = "host_excluded"
			row.Detail = host + " is marked out of scope for this target"
			summary.OutOfScope++
		case scope != nil && !scope.Allows(host):
			row.NotSentReason = "out_of_scope"
			row.Detail = host + " is outside this target's boundary"
			summary.OutOfScope++
		default:
			if d := FirstFlowExclusionMatch(rules, row.URL); d.Excluded {
				row.NotSentReason = "exclusion"
				row.Pattern = d.Pattern
				row.Detail = d.Reason
				summary.Excluded++
			} else {
				row.Sendable = true
				summary.Sendable++
			}
		}
		rows = append(rows, *row)
	}
	summary.Selected = summary.Total - summary.Deselected

	// Stable order, host then path then method, so two loads of the same corpus read the same and an
	// operator can find the row they were looking at a minute ago.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Host != rows[j].Host {
			return rows[i].Host < rows[j].Host
		}
		if rows[i].Path != rows[j].Path {
			return rows[i].Path < rows[j].Path
		}
		return rows[i].Method < rows[j].Method
	})

	matched := make([]FlowEndpointRow, 0, len(rows))
	for _, row := range rows {
		if flowEndpointRowMatches(row, filter) {
			matched = append(matched, row)
		}
	}
	summary.Matched = len(matched)

	if filter.Offset > 0 {
		if filter.Offset >= len(matched) {
			matched = matched[:0]
		} else {
			matched = matched[filter.Offset:]
		}
	}
	if filter.Limit > 0 && len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
	}
	summary.Returned = len(matched)

	return matched, summary
}

func flowEndpointRowMatches(row FlowEndpointRow, f FlowEndpointFilter) bool {
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" {
		hay := strings.ToLower(row.Method + " " + row.Host + " " + row.Path + " " + row.URL)
		if !strings.Contains(hay, q) {
			return false
		}
	}
	if src := strings.ToLower(strings.TrimSpace(f.Source)); src != "" {
		if !flowListContains(row.Sources, src) {
			return false
		}
	}
	switch strings.ToLower(strings.TrimSpace(f.State)) {
	case "", "all":
		return true
	case "selected":
		return row.Selected
	case "deselected":
		return !row.Selected
	case "excluded":
		return row.NotSentReason == "exclusion"
	case "out_of_scope":
		return row.NotSentReason == "out_of_scope" || row.NotSentReason == "host_excluded"
	case "sendable":
		return row.Sendable
	case "not_sendable":
		return !row.Sendable
	}
	return true
}

// hostFromFlowURL pulls the hostname back out of a URL this file produced. The URL came from
// flowDetectionSendableURL, so it is already lowercased and parseable; a failure here means a bug
// upstream and the safest answer is the empty host, which no scope admits.
func hostFromFlowURL(raw string) string {
	_, parsed, err := flowDetectionSendableURL(raw, false)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

func flowListContains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Feeding the planner
// ---------------------------------------------------------------------------

// PartitionFlowCandidatesBySelection removes the deselected endpoints from a candidate list and
// returns one skip row for each, so the dry run's arithmetic holds:
//
//	total - deselected - excluded - out_of_scope - method - unusable = sent
//
// IT RUNS BEFORE buildFlowDetectionPlan, NOT AFTER, and that ordering is not cosmetic. The planner
// truncates its target list at the run's max_requests and reports the remainder as over_budget. If
// deselection were applied afterwards, a budget of 250 could be filled with endpoints the operator
// had already taken out, the real ones would be cut as over_budget, and the run would send 250
// requests of which some number were explicitly unwanted while the endpoints that were wanted went
// untouched.
//
// The skips are deduplicated on the flow key for the same reason the planner deduplicates its
// targets: fifty rows of /search?q=<fifty things> are one request and must be one line on the screen.
func PartitionFlowCandidatesBySelection(
	candidates []flowDetectionCandidate, deselected map[string]bool, includeQuery bool,
) (kept []flowDetectionCandidate, skipped []FlowDetectionSkip) {

	kept = make([]flowDetectionCandidate, 0, len(candidates))
	skipped = []FlowDetectionSkip{}
	if len(deselected) == 0 {
		return append(kept, candidates...), skipped
	}

	reported := map[string]bool{}
	for _, c := range candidates {
		key, ok := FlowEndpointKey(c.URL, c.Method)
		if !ok || !deselected[key] {
			// A row whose key cannot be derived is KEPT, not dropped. It has no identity to be
			// deselected by, and the planner reports it as unusable_url where the operator can see
			// it - which is better than this function silently swallowing it.
			kept = append(kept, c)
			continue
		}
		if reported[key] {
			continue
		}
		reported[key] = true

		display := strings.TrimSpace(c.URL)
		if s, _, err := flowDetectionSendableURL(c.URL, includeQuery); err == nil {
			display = s
		}
		method := strings.ToUpper(strings.TrimSpace(c.Method))
		if method == "" {
			method = http.MethodGet
		}
		skipped = append(skipped, FlowDetectionSkip{
			URL: display, Method: method, Reason: "deselected",
			Detail: "you took this endpoint out of the selection for this target",
		})
	}
	return kept, skipped
}

// ---------------------------------------------------------------------------
// GET /flow-config/{scope_target_id}/endpoints
// ---------------------------------------------------------------------------

// loadFlowEndpointView reads everything the list and the summary need. Every read is fatal on error
// for the same reason the planner's are: a config screen assembled from a partial read shows an
// endpoint as sendable when a rule that could not be read says otherwise.
func loadFlowEndpointView(scopeTargetID string) (
	[]flowDetectionCandidate, map[string][]int, map[string]bool,
	[]FlowExclusion, map[string]bool, *ScanScope, error,
) {
	candidates, err := loadFlowDetectionCandidates(scopeTargetID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	statuses, err := loadFlowEndpointStatuses(scopeTargetID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	deselected, err := LoadFlowEndpointDeselections(scopeTargetID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	rules, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	return candidates, statuses, deselected, rules, denied, LoadScanScope(scopeTargetID), nil
}

func GetFlowEndpoints(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	candidates, statuses, deselected, rules, denied, scope, err := loadFlowEndpointView(scopeTargetID)
	if err != nil {
		log.Printf("[FLOW-CONFIG] Failed to build the endpoint list for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The endpoint list could not be read: "+err.Error())
		return
	}

	q := r.URL.Query()
	filter := FlowEndpointFilter{
		Query:  q.Get("q"),
		State:  q.Get("state"),
		Source: q.Get("source"),
	}
	if n, err := strconv.Atoi(q.Get("limit")); err == nil && n > 0 {
		filter.Limit = n
	}
	if n, err := strconv.Atoi(q.Get("offset")); err == nil && n > 0 {
		filter.Offset = n
	}

	rows, summary := BuildFlowEndpointList(candidates, statuses, deselected, rules, denied, scope, filter)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"endpoints":          rows,
		"summary":            summary,
		"scope_boundary":     scope.Describe(),
		"exclusion_patterns": SortedFlowExclusionPatterns(rules),
		"denied_hosts":       sortedFlowHostSet(denied),
		// Said on every response rather than in documentation nobody reads. It is the one thing about
		// this model that surprises people.
		"selection_model": "Every endpoint is selected unless you take it out. Anything discovered by " +
			"a later crawl arrives selected, so growing the corpus never silently shrinks what gets " +
			"scanned.",
	})
}

// ---------------------------------------------------------------------------
// POST /flow-config/{scope_target_id}/endpoints/selection
// ---------------------------------------------------------------------------

type flowEndpointSelectionRequest struct {
	EndpointKeys []string `json:"endpoint_keys"`
	Selected     *bool    `json:"selected"`
	// All applies the change to every endpoint currently on this target, so select-all and
	// select-none do not require the client to enumerate several thousand keys.
	All bool `json:"all"`
}

func SetFlowEndpointSelectionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var req flowEndpointSelectionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
		return
	}
	// A POINTER, so that an omitted `selected` is refused rather than silently read as false. A bulk
	// call that means "select these" and is decoded as "deselect these" would turn a screen full of
	// ticks into a screen full of skips with nothing to say why.
	if req.Selected == nil {
		writeJSONError(w, http.StatusBadRequest, "selected_required",
			"selected must be true or false. It is not defaulted, because a bulk call whose meaning "+
				"was guessed would deselect a whole corpus by omission.")
		return
	}
	if !req.All && len(req.EndpointKeys) == 0 {
		writeJSONError(w, http.StatusBadRequest, "no_endpoints",
			"Send endpoint_keys, or all:true to apply this to every endpoint on the target.")
		return
	}
	if len(req.EndpointKeys) > flowSelectionMaxKeys {
		writeJSONError(w, http.StatusBadRequest, "too_many_keys",
			"That is more than "+strconv.Itoa(flowSelectionMaxKeys)+" keys in one call. Use all:true.")
		return
	}

	note := ""
	var affected int64
	var err error

	switch {
	case req.All && *req.Selected:
		// Select-all is a DELETE of every row, not an insert of every key, which is what keeps the
		// default correct for endpoints discovered later.
		affected, err = ClearFlowEndpointDeselections(scopeTargetID)
	case req.All:
		// Deselect-all enumerates what exists NOW. It cannot be a standing rule, because this table
		// stores the negative on purpose, so anything discovered afterwards comes back selected.
		// Said in the response rather than left to be discovered against a live target.
		candidates, cErr := loadFlowDetectionCandidates(scopeTargetID)
		if cErr != nil {
			log.Printf("[FLOW-CONFIG] Failed to read endpoints for %s: %v", scopeTargetID, cErr)
			writeJSONError(w, http.StatusInternalServerError, "internal_error",
				"The endpoint list could not be read: "+cErr.Error())
			return
		}
		keys := map[string]bool{}
		for _, c := range candidates {
			if k, ok := FlowEndpointKey(c.URL, c.Method); ok {
				keys[k] = true
			}
		}
		list := make([]string, 0, len(keys))
		for k := range keys {
			list = append(list, k)
		}
		affected, err = SetFlowEndpointSelection(scopeTargetID, list, false)
		note = "Deselected the " + strconv.Itoa(len(list)) + " endpoints that exist right now. " +
			"Endpoints discovered by a later crawl will arrive selected, because this list stores " +
			"what you took out rather than what you left in."
	default:
		affected, err = SetFlowEndpointSelection(scopeTargetID, req.EndpointKeys, *req.Selected)
	}

	if err != nil {
		log.Printf("[FLOW-CONFIG] Failed to set selection for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The selection could not be saved: "+err.Error())
		return
	}

	summary, sErr := FlowEndpointSummaryFor(scopeTargetID)
	if sErr != nil {
		log.Printf("[FLOW-CONFIG] Selection saved for %s but the summary failed: %v", scopeTargetID, sErr)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The selection was saved but the new counts could not be read: "+sErr.Error())
		return
	}

	log.Printf("[FLOW-CONFIG] Selection updated for %s: selected=%v, %d row(s) changed, %d/%d now sendable",
		scopeTargetID, *req.Selected, affected, summary.Sendable, summary.Total)

	out := map[string]interface{}{
		"success": true,
		"changed": affected,
		"summary": summary,
	}
	if note != "" {
		out["note"] = note
	}
	json.NewEncoder(w).Encode(out)
}

// ---------------------------------------------------------------------------
// GET /flow-config/{scope_target_id}/endpoints/summary
// ---------------------------------------------------------------------------

// FlowEndpointSummaryFor is the counts alone, for a screen that wants "1,204 of 1,340 selected"
// without carrying the rows.
func FlowEndpointSummaryFor(scopeTargetID string) (FlowEndpointSummary, error) {
	candidates, statuses, deselected, rules, denied, scope, err := loadFlowEndpointView(scopeTargetID)
	if err != nil {
		return FlowEndpointSummary{}, err
	}
	// An EMPTY filter, deliberately. The summary must count the whole corpus, not the current page:
	// "1,204 of 1,340 selected" is a claim about the target, and computing it from a filtered or
	// paginated slice is precisely how a number that looks like a corpus total ends up reporting a
	// page size. The rows are discarded here; only the counts are wanted.
	_, summary := BuildFlowEndpointList(
		candidates, statuses, deselected, rules, denied, scope, FlowEndpointFilter{})
	return summary, nil
}

func GetFlowEndpointSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	summary, err := FlowEndpointSummaryFor(scopeTargetID)
	if err != nil {
		log.Printf("[FLOW-CONFIG] Failed to summarise endpoints for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"The endpoint counts could not be read: "+err.Error())
		return
	}
	json.NewEncoder(w).Encode(summary)
}
