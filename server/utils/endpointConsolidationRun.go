package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Consolidate: fold six discovery sources into one list of unique endpoint and verb combinations.
//
// The sources are the manual crawl plus katana, gospider, linkfinder, gau and waybackurls. FFUF is
// deliberately absent: it now runs later in the workflow, after parameter enumeration, so its hits
// are not part of the surface this step describes.
//
// Three defects in the previous implementation are fixed here, and each of them was silently wrong
// rather than loudly broken.
//
//  1. It opened with DELETE FROM consolidated_url_endpoints WHERE scope_target_id = $1. That makes
//     "manually add an endpoint" impossible: the next Consolidate destroys it. It also threw away
//     every validation verdict and every operator note. Writes are now upserts keyed on
//     endpoint_key, and the columns an operator owns are never overwritten by a run.
//  2. It LEFT JOINed endpoint_parameters, which multiplies one endpoint into one row per parameter,
//     then incremented request_count once per row. That counter was measuring how many parameters a
//     URL had and calling it traffic.
//  3. first_seen and last_seen were both time.Now(), so every endpoint appeared to have been
//     discovered at the moment of consolidation and the age of a finding was unknowable.

// The sources this step consolidates. FFUF is not here on purpose; see the file comment.
var consolidationScanTypes = []string{"katana", "gospider", "linkfinder", "gau", "waybackurls"}

// Scope is enforced here, at import, rather than later at request time.
//
// Measured on a target scoped to http://10.0.0.18:3000. gau returned nine URLs on
// http://10.0.0.18:80 (login.cfm, Content/Default.asp, Animal_Mineral_Vegetable/exercise1_config.jsp)
// which is a different service on the same machine, and one host that cannot exist at all,
// "http://.10.18/robots.txt". All ten became consolidated_url_endpoints rows and were only turned
// away much later, by the request layer, as skipped.out_of_scope. By then they had already been
// counted as attack surface, shown to the operator, and queued for validation. The same corpus also
// holds w3.org, fonts.googleapis.com, youtube.com and opensea.io, which the crawlers read off the
// page and which scanScope.go already calls "evidence of nothing".
//
// Two separate defects produced that, which is why the check is one object rather than a condition
// bolted onto each pass.
//
//  1. Consolidation applied no host boundary whatsoever. Every row a source emitted became surface.
//  2. The boundary that does exist mis-parses an IP literal. RegistrableDomain("10.0.0.18") returns
//     "0.18", because it takes the last two labels of anything that is not a known two-label public
//     suffix, so the boundary renders as "*.0.18, 10.0.0.18" and would admit any host ending in
//     ".0.18". An IP literal has no registrable domain: for one, the boundary is the exact host and
//     the domain widening is skipped entirely. RegistrableDomain itself lives in scanCredentials.go
//     and is deliberately not touched from here.
//
// A port-bearing scope target is a single service, not a machine. When the target names a non-default
// port every row must carry that same port, which is what separates the Juice Shop on :3000 from
// whatever answers on :80.
const (
	exclusionInvalidHost = "invalid_host"
	exclusionOutOfHost   = "out_of_scope_host"
	exclusionOutOfPort   = "out_of_scope_port"
)

// consolidationScope is the admission decision, kept free of database access so both passes share
// one implementation and so it is testable without a live target.
type consolidationScope struct {
	host     string // the scope target's own host, lowercased
	port     int    // the non-default port the target names; 0 when it names none
	hostIsIP bool

	// allowed is used only for an IP-literal target: the target host plus whatever the operator
	// explicitly authorised. Nothing is inferred from the labels of an address.
	allowed map[string]bool

	// scope is the normal registrable-domain boundary, used only for a named host.
	scope *ScanScope

	// unbounded means no host could be determined for this scope target. Consolidation records
	// rather than requests, so refusing everything here would empty an operator's corpus over a
	// database read that failed; the run says so instead.
	unbounded bool
}

func newConsolidationScope(scopeTargetID, scheme, base string) *consolidationScope {
	c := parseConsolidationScopeBase(scheme, base)
	if c.unbounded {
		return c
	}
	if c.hostIsIP {
		c.allowed[c.host] = true
		// An operator's explicit decision still counts, even for an address. InScopeCrawlHosts is
		// the same list the scanner and the scope modal read, called rather than reimplemented so
		// the three cannot disagree about what is in scope.
		for _, h := range InScopeCrawlHosts(scopeTargetID) {
			if h != "" {
				c.allowed[strings.ToLower(h)] = true
			}
		}
		return c
	}
	c.scope = LoadScanScope(scopeTargetID)
	return c
}

// parseConsolidationScopeBase derives the host, the port and whether the host is an address.
//
// Separate from the database reads so the branch that matters, "is this target an IP literal and
// therefore not eligible for registrable-domain widening", can be checked without a live target.
func parseConsolidationScopeBase(scheme, base string) *consolidationScope {
	c := &consolidationScope{allowed: map[string]bool{}}

	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		c.unbounded = true
		return c
	}
	c.host = strings.ToLower(strings.Trim(u.Hostname(), "."))
	if c.host == "" {
		c.unbounded = true
		return c
	}
	// ScopeTargetBase has already dropped a port that is the scheme default, so anything left is a
	// port the operator meant.
	if p := u.Port(); p != "" {
		if n, convErr := strconv.Atoi(p); convErr == nil && !isDefaultPort(scheme, n) {
			c.port = n
		}
	}
	c.hostIsIP = net.ParseIP(c.host) != nil
	return c
}

// admit reports whether this identity belongs to this target, and why not when it does not.
func (c *consolidationScope) admit(id EndpointIdentity) (bool, string) {
	// Checked before the boundary, and for every target: a host that cannot exist is not an endpoint
	// no matter whose scope is being considered.
	if !hostIsSyntacticallyValid(id.Host) {
		return false, exclusionInvalidHost
	}
	if c == nil || c.unbounded {
		return true, ""
	}

	// Host before port, because the reason is the whole point of recording the refusal. Checking the
	// port first reported www.w3.org and fonts.googleapis.com as "out_of_scope_port" on this target,
	// which is true and useless: they are not this application at all. With this order the only rows
	// that read as a port problem are the ones that really are, the nine http://10.0.0.18:80 rows.
	inScope := false
	if c.hostIsIP {
		// An address has no subdomains, so nothing is inferred from its labels.
		inScope = c.allowed[id.Host]
	} else {
		inScope = c.scope.Allows(id.Host)
	}
	if !inScope {
		return false, exclusionOutOfHost
	}

	if c.port != 0 && id.Port != c.port {
		return false, exclusionOutOfPort
	}
	return true, ""
}

// hostIsSyntacticallyValid rejects strings that no resolver could ever answer for.
//
// "http://.10.18/robots.txt" survived a whole consolidation and was stored as an endpoint. Its host
// has an empty first label, which is impossible, and no amount of scope configuration would ever
// make it real. gau produces these by mangling an address it read out of an archive index.
func hostIsSyntacticallyValid(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	// url.Hostname() strips the brackets off an IPv6 literal, so a colon here means an address.
	if strings.Contains(host, ":") {
		return net.ParseIP(host) != nil
	}
	if net.ParseIP(host) != nil {
		return true
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			ch := label[i]
			switch {
			case ch >= 'a' && ch <= 'z',
				ch >= 'A' && ch <= 'Z',
				ch >= '0' && ch <= '9',
				ch == '-', ch == '_':
			default:
				return false
			}
		}
	}
	// A top-level label cannot be all digits. net.ParseIP above already admitted the real addresses,
	// so anything reaching here that ends in a number is a mangled one: "10.0.18", "10.18", "3000".
	last := labels[len(labels)-1]
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			return true
		}
	}
	return false
}

// How many refused URLs are kept verbatim. Bounded because the counts are stored as one JSON blob on
// the run, and an archive source can emit tens of thousands of out-of-scope rows.
const maxExclusionSamples = 500

// consolidationExclusion is one row consolidation refused.
//
// Kept whole, with the URL that caused it, because "excluded=1 with no way to see which row" was
// itself reported as a defect: a count an operator cannot act on is barely better than silence.
type consolidationExclusion struct {
	URL    string `json:"url"`
	Host   string `json:"host"`
	Port   int    `json:"port,omitempty"`
	Source string `json:"source"`
	Reason string `json:"reason"`
}

type exclusionLog struct {
	Total     int                      `json:"total"`
	ByReason  map[string]int           `json:"by_reason"`
	ByHost    map[string]int           `json:"by_host"`
	Samples   []consolidationExclusion `json:"samples"`
	Truncated bool                     `json:"samples_truncated"`
}

func newExclusionLog() *exclusionLog {
	return &exclusionLog{ByReason: map[string]int{}, ByHost: map[string]int{}}
}

func (e *exclusionLog) record(rawURL string, id EndpointIdentity, source, reason string) {
	if e == nil {
		return
	}
	e.Total++
	e.ByReason[reason]++

	// Grouped by host and port together, because "nine rows on 10.0.0.18:80" is the sentence that
	// makes the problem obvious and "nine rows on 10.0.0.18" is the one that hides it.
	hostKey := id.Host
	if hostKey == "" {
		hostKey = "(unparsed)"
	}
	if id.Port != 0 {
		hostKey += ":" + strconv.Itoa(id.Port)
	}
	e.ByHost[hostKey]++

	if len(e.Samples) >= maxExclusionSamples {
		e.Truncated = true
		return
	}
	if len(rawURL) > 512 {
		rawURL = rawURL[:512]
	}
	e.Samples = append(e.Samples, consolidationExclusion{
		URL: rawURL, Host: id.Host, Port: id.Port, Source: source, Reason: reason,
	})
}

type consolidatedRow struct {
	identity     EndpointIdentity
	displayURL   string
	isDirect     bool
	sources      map[string]int
	statusCodes  map[int]bool
	firstSeen    time.Time
	lastSeen     time.Time
	captureCount int
	requestCount int
	observedVerb map[string]bool
	methodKnown  bool
	graphQLOp    string
	requestBody  string
	contentType  string
	reqHeaders   map[string]interface{}
	respHeaders  map[string]interface{}
	params       map[string]*ConsolidatedParameter
}

// RunConsolidation handles POST /consolidated-endpoints/{scope_target_id}/consolidate.
//
// Asynchronous, because folding tens of thousands of archive rows inside an HTTP handler ties up a
// connection until the client times out and leaves the operator with no idea whether it worked.
func RunConsolidation(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	scanID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO endpoint_consolidation_runs (scan_id, scope_target_id, status)
		VALUES ($1, $2, 'pending')`, scanID, scopeTargetID); err != nil {
		log.Printf("[CONSOLIDATE] failed to create run: %v", err)
		http.Error(w, "Failed to create consolidation run", http.StatusInternalServerError)
		return
	}

	go executeConsolidation(scanID, scopeTargetID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{"scan_id": scanID, "status": "pending"})
}

func executeConsolidation(scanID, scopeTargetID string) {
	started := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[CONSOLIDATE] panic in %s: %v", scanID, rec)
			finishConsolidation(scanID, "error", 0, 0, nil, nil, fmt.Sprintf("panic: %v", rec), started)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	_, _ = dbPool.Exec(ctx, `
		UPDATE endpoint_consolidation_runs SET status='running', updated_at=NOW()
		WHERE scan_id = $1`, scanID)

	defaultScheme, _, base := ScopeTargetBase(scopeTargetID)
	targetDomain := extractDomainFromScopeTarget(scopeTargetID)
	scope := newConsolidationScope(scopeTargetID, defaultScheme, base)

	rows := map[string]*consolidatedRow{}
	skipped := map[string]int{}
	excluded := newExclusionLog()
	read := 0

	if scope.unbounded {
		// Said out loud rather than silently importing everything: a run with no boundary looks
		// identical on screen to a run whose boundary held.
		log.Printf("[CONSOLIDATE] %s: no host could be determined for scope target %s, importing without a host boundary",
			scanID, scopeTargetID)
		skipped["scope_boundary_unknown"]++
	}

	if n, err := consolidateFromDiscovered(ctx, scopeTargetID, defaultScheme, scope, rows, skipped, excluded); err != nil {
		finishConsolidation(scanID, "error", 0, 0, skipped, excluded, err.Error(), started)
		return
	} else {
		read += n
	}

	if n, err := consolidateFromManualCrawl(ctx, scopeTargetID, defaultScheme, targetDomain, scope, rows, skipped, excluded); err != nil {
		log.Printf("[CONSOLIDATE] manual crawl pass failed: %v", err)
		skipped["manual_crawl_error"]++
	} else {
		read += n
	}

	if excluded.Total > 0 {
		log.Printf("[CONSOLIDATE] %s: %d row(s) refused as out of scope: by reason %v, by host %v",
			scanID, excluded.Total, excluded.ByReason, excluded.ByHost)
	}

	if len(rows) == 0 {
		finishConsolidation(scanID, "success", 0, read, skipped, excluded, "", started)
		return
	}

	// Template group sizes, so the UI can say "one of 412 like this" instead of listing 412 rows.
	groupSize := map[string]int{}
	for _, row := range rows {
		groupSize[row.identity.TemplateKey]++
	}
	exemplarTaken := map[string]bool{}

	stored, err := storeConsolidated(ctx, scopeTargetID, scanID, rows, groupSize, exemplarTaken)
	if err != nil {
		finishConsolidation(scanID, "error", stored, read, skipped, excluded, err.Error(), started)
		return
	}

	// Rows nobody saw this run are marked, never deleted. A source going quiet is information, and
	// an operator may have deleted the tool rather than the endpoint disappearing.
	_, _ = dbPool.Exec(ctx, `
		UPDATE consolidated_url_endpoints
		SET unseen_since = COALESCE(unseen_since, NOW())
		WHERE scope_target_id = $1 AND deleted_at IS NULL AND manual_added = FALSE
		  AND (last_run_id IS DISTINCT FROM $2)`, scopeTargetID, scanID)
	_, _ = dbPool.Exec(ctx, `
		UPDATE consolidated_url_endpoints SET unseen_since = NULL
		WHERE scope_target_id = $1 AND last_run_id = $2`, scopeTargetID, scanID)

	if err := RefreshConsolidatedParameters(ctx, scopeTargetID); err != nil {
		log.Printf("[CONSOLIDATE] parameter refresh failed: %v", err)
	}

	finishConsolidation(scanID, "success", stored, read, skipped, excluded, "", started)
}

// consolidateFromDiscovered streams the crawler and archive rows.
//
// No join. The previous version joined endpoint_parameters here, which multiplied every endpoint by
// its parameter count and inflated request_count accordingly. Parameters are derived from the URL
// itself and reattached separately.
func consolidateFromDiscovered(ctx context.Context, scopeTargetID, defaultScheme string,
	scope *consolidationScope, out map[string]*consolidatedRow, skipped map[string]int,
	excluded *exclusionLog) (int, error) {

	rows, err := dbPool.Query(ctx, `
		SELECT url, COALESCE(status_code, 0), is_direct, scan_type, created_at
		FROM discovered_endpoints
		WHERE scope_target_id = $1 AND scan_type = ANY($2)
		ORDER BY id`, scopeTargetID, consolidationScanTypes)
	if err != nil {
		return 0, fmt.Errorf("failed to read discovered endpoints: %w", err)
	}
	defer rows.Close()

	read := 0
	for rows.Next() {
		var rawURL, scanType string
		var status int
		var isDirect bool
		var createdAt time.Time
		if rows.Scan(&rawURL, &status, &isDirect, &scanType, &createdAt) != nil {
			continue
		}
		read++

		// Everything from a crawler or an archive is a GET. Only the manual crawl observes a verb.
		id, ok := CanonicalizeEndpoint(rawURL, "GET", defaultScheme)
		if !ok {
			skipped["unusable_url"]++
			continue
		}

		// Refused here rather than stored and flagged at request time. This is where gau's nine
		// http://10.0.0.18:80 rows and its "http://.10.18/robots.txt" stop being attack surface.
		if admitted, reason := scope.admit(id); !admitted {
			excluded.record(rawURL, id, scanType, reason)
			skipped[reason]++
			continue
		}

		row := ensureRow(out, id, isDirect, createdAt)
		row.sources[scanType]++
		row.requestCount++
		if status > 0 {
			row.statusCodes[status] = true
		}
		touch(row, createdAt)
		mergeURLParams(row, id)
	}
	return read, rows.Err()
}

// consolidateFromManualCrawl folds in the captures. These are the only rows carrying a real verb,
// a real request body and a real observed response, so they take precedence on every field.
func consolidateFromManualCrawl(ctx context.Context, scopeTargetID, defaultScheme, targetDomain string,
	scope *consolidationScope, out map[string]*consolidatedRow, skipped map[string]int,
	excluded *exclusionLog) (int, error) {

	rows, err := dbPool.Query(ctx, `
		SELECT url, COALESCE(method,'GET'), COALESCE(status_code,0), headers, response_headers,
		       COALESCE(post_data,''), COALESCE(mime_type,''), COALESCE(graphql_operation,''),
		       COALESCE(get_params,'{}'::jsonb), COALESCE(post_params,'{}'::jsonb),
		       is_direct, created_at
		FROM manual_crawl_captures
		WHERE scope_target_id = $1
		ORDER BY id`, scopeTargetID)
	if err != nil {
		return 0, fmt.Errorf("failed to read manual crawl captures: %w", err)
	}
	defer rows.Close()

	read := 0
	for rows.Next() {
		var rawURL, method, postData, mime, graphqlOp string
		var status int
		var reqHeaders, respHeaders, getParams, postParams []byte
		var isDirect *bool
		var createdAt time.Time
		if rows.Scan(&rawURL, &method, &status, &reqHeaders, &respHeaders, &postData, &mime,
			&graphqlOp, &getParams, &postParams, &isDirect, &createdAt) != nil {
			continue
		}
		read++

		id, ok := CanonicalizeEndpoint(rawURL, method, defaultScheme)
		if !ok {
			skipped["unusable_url"]++
			continue
		}

		// A capture is the operator's own browsing, and InScopeCrawlHosts already admits every host
		// they recorded unless they excluded it by hand, so this pass loses nothing an operator
		// vouched for. What it does catch is a capture on a port the target does not name, which is
		// a different service on the same machine and not the thing under test.
		if admitted, reason := scope.admit(id); !admitted {
			excluded.record(rawURL, id, "manual_crawl", reason)
			skipped[reason]++
			continue
		}

		direct := true
		if isDirect != nil {
			direct = *isDirect
		} else if targetDomain != "" {
			direct = strings.HasSuffix(id.Host, targetDomain)
		}

		row := ensureRow(out, id, direct, createdAt)
		row.sources["manual_crawl"]++
		row.captureCount++
		row.requestCount++
		// A verb that was actually observed, rather than assumed because a crawler found a link.
		row.methodKnown = true
		row.observedVerb[id.Method] = true
		if status > 0 {
			row.statusCodes[status] = true
		}
		if graphqlOp != "" {
			row.graphQLOp = graphqlOp
		}
		if postData != "" && row.requestBody == "" {
			row.requestBody = postData
		}
		if mime != "" && row.contentType == "" {
			row.contentType = mime
		}
		mergeHeaderMap(&row.reqHeaders, reqHeaders)
		mergeHeaderMap(&row.respHeaders, respHeaders)
		touch(row, createdAt)
		mergeURLParams(row, id)
		mergeJSONParams(row, getParams, "query")
		mergeJSONParams(row, postParams, "body")
	}
	return read, rows.Err()
}

func ensureRow(out map[string]*consolidatedRow, id EndpointIdentity, isDirect bool, at time.Time) *consolidatedRow {
	if row, ok := out[id.Key]; ok {
		// Direct wins: an endpoint seen both ways is in scope.
		if isDirect {
			row.isDirect = true
		}
		return row
	}
	row := &consolidatedRow{
		identity:     id,
		displayURL:   id.CanonicalURL,
		isDirect:     isDirect,
		sources:      map[string]int{},
		statusCodes:  map[int]bool{},
		firstSeen:    at,
		lastSeen:     at,
		observedVerb: map[string]bool{},
		reqHeaders:   map[string]interface{}{},
		respHeaders:  map[string]interface{}{},
		params:       map[string]*ConsolidatedParameter{},
	}
	out[id.Key] = row
	return row
}

// touch keeps the real observation window rather than stamping time.Now() on everything, so the
// age of a finding is answerable.
func touch(row *consolidatedRow, at time.Time) {
	if at.IsZero() {
		return
	}
	if row.firstSeen.IsZero() || at.Before(row.firstSeen) {
		row.firstSeen = at
	}
	if at.After(row.lastSeen) {
		row.lastSeen = at
	}
}

func mergeURLParams(row *consolidatedRow, id EndpointIdentity) {
	for name, value := range id.ValueParams {
		addParam(row, "query", name, value)
	}
}

func mergeJSONParams(row *consolidatedRow, raw []byte, kind string) {
	if len(raw) == 0 {
		return
	}
	var parsed map[string]interface{}
	if json.Unmarshal(raw, &parsed) != nil {
		return
	}
	for name, value := range parsed {
		addParam(row, kind, name, fmt.Sprintf("%v", value))
	}
}

func addParam(row *consolidatedRow, kind, name, value string) {
	if name == "" {
		return
	}
	key := kind + "|" + name
	p, ok := row.params[key]
	if !ok {
		p = &ConsolidatedParameter{ParamType: kind, ParamName: name}
		row.params[key] = p
	}
	p.Frequency++
	if value != "" && len(p.ExampleValues) < 5 && !contains(p.ExampleValues, value) {
		if len(value) > 256 {
			value = value[:256]
		}
		p.ExampleValues = append(p.ExampleValues, value)
	}
}

// storeConsolidated upserts on endpoint_key.
//
// The DO UPDATE list is deliberately narrow. Every column an operator or a later scan owns is
// absent from it: manual_added, pinned, notes, deleted_at, validation_*, override_*, investigated_at
// and interest_score all survive a re-run untouched. That is what makes "manually add an endpoint"
// and "override this verdict" possible at all.
func storeConsolidated(ctx context.Context, scopeTargetID, scanID string,
	rows map[string]*consolidatedRow, groupSize map[string]int, exemplarTaken map[string]bool) (int, error) {

	tx, err := dbPool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	stored := 0
	skippedRows := 0
	for _, row := range rows {
		id := row.identity

		statusCodes := make([]int, 0, len(row.statusCodes))
		for code := range row.statusCodes {
			statusCodes = append(statusCodes, code)
		}
		sources := make([]string, 0, len(row.sources))
		for s := range row.sources {
			sources = append(sources, s)
		}
		verbs := make([]string, 0, len(row.observedVerb))
		for v := range row.observedVerb {
			verbs = append(verbs, v)
		}

		methodConfidence := "implied"
		if row.methodKnown {
			methodConfidence = "observed"
		}
		exemplar := false
		if !exemplarTaken[id.TemplateKey] {
			exemplar = true
			exemplarTaken[id.TemplateKey] = true
		}

		statusJSON, _ := json.Marshal(statusCodes)
		sourceCountsJSON, _ := json.Marshal(row.sources)
		flagsJSON, _ := json.Marshal(id.Flags)
		droppedJSON, _ := json.Marshal(id.DroppedParams)
		reqHeadersJSON, _ := json.Marshal(row.reqHeaders)
		respHeadersJSON, _ := json.Marshal(row.respHeaders)

		// Each endpoint is written inside its own savepoint, so one row the database refuses does
		// not take the other 1153 with it.
		//
		// Postgres aborts the whole transaction on the first failed statement: every statement after
		// it fails with "current transaction is aborted", the per-row `continue` below then skipped
		// silently through all of them, and the final Commit rolled back everything. A single URL
		// carrying a %00 in its query was enough to lose an entire consolidation while the log
		// showed one line about one row.
		sp, spErr := tx.Begin(ctx)
		if spErr != nil {
			log.Printf("[CONSOLIDATE] could not open savepoint for %s: %v", row.displayURL, spErr)
			continue
		}

		var endpointID string
		err := sp.QueryRow(ctx, `
			INSERT INTO consolidated_url_endpoints
			  (id, scope_target_id, endpoint_key, url, normalized_url, domain, path, method,
			   is_direct, status_codes, headers, response_headers, request_count, first_seen,
			   last_seen, sources, request_body, content_type,
			   scheme, schemes, port, canonical_path, identity_query, client_route,
			   templated_path, template_key, template_group_size, is_template_exemplar,
			   case_group_key, method_confidence, observed_methods, graphql_operation,
			   content_class, source_counts, capture_count, normalization_flags, dropped_params,
			   last_run_id, last_consolidated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
			        $19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38,NOW())
			ON CONFLICT (scope_target_id, endpoint_key) DO UPDATE SET
			  url = EXCLUDED.url,
			  domain = EXCLUDED.domain,
			  path = EXCLUDED.path,
			  is_direct = consolidated_url_endpoints.is_direct OR EXCLUDED.is_direct,
			  status_codes = EXCLUDED.status_codes,
			  headers = EXCLUDED.headers,
			  response_headers = EXCLUDED.response_headers,
			  request_count = EXCLUDED.request_count,
			  first_seen = LEAST(consolidated_url_endpoints.first_seen, EXCLUDED.first_seen),
			  last_seen = GREATEST(consolidated_url_endpoints.last_seen, EXCLUDED.last_seen),
			  sources = EXCLUDED.sources,
			  request_body = CASE WHEN EXCLUDED.request_body <> '' THEN EXCLUDED.request_body
			                      ELSE consolidated_url_endpoints.request_body END,
			  content_type = CASE WHEN EXCLUDED.content_type <> '' THEN EXCLUDED.content_type
			                      ELSE consolidated_url_endpoints.content_type END,
			  schemes = EXCLUDED.schemes,
			  templated_path = EXCLUDED.templated_path,
			  template_key = EXCLUDED.template_key,
			  template_group_size = EXCLUDED.template_group_size,
			  is_template_exemplar = EXCLUDED.is_template_exemplar,
			  case_group_key = EXCLUDED.case_group_key,
			  method_confidence = EXCLUDED.method_confidence,
			  observed_methods = EXCLUDED.observed_methods,
			  graphql_operation = EXCLUDED.graphql_operation,
			  content_class = EXCLUDED.content_class,
			  source_counts = EXCLUDED.source_counts,
			  capture_count = EXCLUDED.capture_count,
			  normalization_flags = EXCLUDED.normalization_flags,
			  dropped_params = EXCLUDED.dropped_params,
			  last_run_id = EXCLUDED.last_run_id,
			  last_consolidated_at = NOW()
			RETURNING id`,
			uuid.New().String(), scopeTargetID, id.Key, row.displayURL, id.CanonicalPath,
			id.Host, id.CanonicalPath, id.Method, row.isDirect, statusJSON,
			reqHeadersJSON, respHeadersJSON, row.requestCount, row.firstSeen, row.lastSeen,
			sources, row.requestBody, row.contentType,
			id.Scheme, []string{id.Scheme}, nullInt(id.Port), id.CanonicalPath, id.IdentityQuery,
			id.ClientRoute, id.TemplatedPath, id.TemplateKey, groupSize[id.TemplateKey], exemplar,
			id.CaseGroupKey, methodConfidence, verbs, row.graphQLOp, id.ContentClass,
			sourceCountsJSON, row.captureCount, flagsJSON, droppedJSON, scanID,
		).Scan(&endpointID)
		if err != nil {
			log.Printf("[CONSOLIDATE] failed to store %s: %v", row.displayURL, err)
			_ = sp.Rollback(ctx)
			skippedRows++
			continue
		}

		paramFailed := false
		for _, p := range row.params {
			valuesJSON, _ := json.Marshal(p.ExampleValues)
			if _, perr := sp.Exec(ctx, `
				INSERT INTO consolidated_url_parameters
				  (id, endpoint_id, param_type, param_name, example_values, frequency)
				VALUES ($1, $2, $3, $4, $5::jsonb, $6)
				ON CONFLICT (endpoint_id, param_type, param_name) DO UPDATE SET
				  example_values = EXCLUDED.example_values,
				  frequency = EXCLUDED.frequency`,
				uuid.New().String(), endpointID, p.ParamType, p.ParamName, string(valuesJSON), p.Frequency); perr != nil {
				// Previously discarded with `_, _ =`, which both hid the cause and left the whole
				// transaction aborted.
				log.Printf("[CONSOLIDATE] failed to store parameter %s on %s: %v",
					p.ParamName, row.displayURL, perr)
				paramFailed = true
				break
			}
		}
		if paramFailed {
			_ = sp.Rollback(ctx)
			skippedRows++
			continue
		}
		if cerr := sp.Commit(ctx); cerr != nil {
			log.Printf("[CONSOLIDATE] failed to release savepoint for %s: %v", row.displayURL, cerr)
			skippedRows++
			continue
		}
		stored++
	}

	if skippedRows > 0 {
		// Said out loud: a count that silently differs from the corpus size reads as "these are all
		// the endpoints there are".
		log.Printf("[CONSOLIDATE] %d row(s) could not be stored and are absent from this run's %d endpoints",
			skippedRows, stored)
	}

	if err := tx.Commit(ctx); err != nil {
		return stored, err
	}
	return stored, nil
}

// RefreshConsolidatedParameters reattaches parameters that arjun and x8 discovered.
//
// It only attaches to endpoints that already exist. The previous version also created endpoints
// from parameter rows, which invented surface that no discovery source ever saw.
func RefreshConsolidatedParameters(ctx context.Context, scopeTargetID string) error {
	rows, err := dbPool.Query(ctx, `
		SELECT endpoint_url, parameter_name, parameter_type, COALESCE(example_value,''), scan_type
		FROM parameter_enumeration_results
		WHERE scope_target_id = $1`, scopeTargetID)
	if err != nil {
		// The table is optional; a target that never ran parameter enumeration has none.
		return nil
	}
	defer rows.Close()

	type paramRow struct{ url, name, ptype, value, source string }
	var pending []paramRow
	for rows.Next() {
		var p paramRow
		if rows.Scan(&p.url, &p.name, &p.ptype, &p.value, &p.source) != nil {
			continue
		}
		pending = append(pending, p)
	}
	if len(pending) == 0 {
		return nil
	}

	defaultScheme, _, _ := ScopeTargetBase(scopeTargetID)
	for _, p := range pending {
		id, ok := CanonicalizeEndpoint(p.url, "GET", defaultScheme)
		if !ok {
			continue
		}
		var endpointID string
		if err := dbPool.QueryRow(ctx, `
			SELECT id FROM consolidated_url_endpoints
			WHERE scope_target_id = $1 AND endpoint_key = $2 AND deleted_at IS NULL`,
			scopeTargetID, id.Key).Scan(&endpointID); err != nil {
			continue // a parameter for an endpoint nobody discovered is not surface
		}
		values := []string{}
		if p.value != "" {
			values = append(values, p.value)
		}
		valuesJSON, _ := json.Marshal(values)
		ptype := p.ptype
		if ptype == "" {
			ptype = "query"
		}
		_, _ = dbPool.Exec(ctx, `
			INSERT INTO consolidated_url_parameters
			  (id, endpoint_id, param_type, param_name, example_values, frequency)
			VALUES ($1, $2, $3, $4, $5::jsonb, 1)
			ON CONFLICT (endpoint_id, param_type, param_name) DO UPDATE SET
			  frequency = consolidated_url_parameters.frequency + 1`,
			uuid.New().String(), endpointID, ptype, p.name, string(valuesJSON))
	}
	return nil
}

// consolidationScopeTargetFor reads back the target a run belongs to, so finishConsolidation can
// count the corpus without every caller having to thread the id through.
func consolidationScopeTargetFor(scanID string) string {
	var id string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target_id::text FROM endpoint_consolidation_runs WHERE scan_id = $1`,
		scanID).Scan(&id); err != nil {
		return ""
	}
	return id
}

func finishConsolidation(scanID, status string, count, read int, skipped map[string]int,
	excluded *exclusionLog, errMsg string, started time.Time) {
	if skipped == nil {
		skipped = map[string]int{}
	}
	if excluded == nil {
		excluded = newExclusionLog()
	}
	skippedJSON, _ := json.Marshal(skipped)
	// The refused rows travel in `result` rather than in a new column, so the reason is retrievable
	// without a schema change. GetConsolidationStatus unpacks it back out.
	// corpus_total is COUNTED, and it is not the same number as endpoint_count.
	//
	// endpoint_count is what THIS RUN stored. It excludes every endpoint the operator added by hand,
	// because those come from no source and so are never re-seen by a consolidation pass. Measured on
	// the Juice Shop target: a run reported endpoint_count 201 while the live corpus held 218, the
	// difference being 17 hand-added rows. The UI and the MCP tool both present that number as "the
	// endpoint count", so the operator's own additions read as having vanished.
	//
	// Reported alongside rather than replacing it: "how many did this run account for" is a real
	// question, and so is "how many are there". A single field cannot answer both, and this file has
	// already been bitten once by a count that meant something narrower than its name.
	corpusTotal := -1
	if scopeTargetID := consolidationScopeTargetFor(scanID); scopeTargetID != "" {
		var n int
		if err := dbPool.QueryRow(context.Background(), `
			SELECT COUNT(*) FROM consolidated_url_endpoints
			WHERE scope_target_id = $1 AND deleted_at IS NULL`, scopeTargetID).Scan(&n); err == nil {
			corpusTotal = n
		}
	}
	result := map[string]interface{}{
		"endpoint_count": count,
		"rows_read":      read,
		"skipped":        skipped,
		"excluded":       excluded,
		"sources":        consolidationScanTypes,
	}
	// Omitted rather than reported as 0 when it could not be read. A zero here would say the corpus
	// is empty, which is the one thing it definitely is not if a run just stored rows into it.
	if corpusTotal >= 0 {
		result["corpus_total"] = corpusTotal
		result["counts_note"] = "endpoint_count is what this run stored. corpus_total is every live " +
			"endpoint on the target including the ones added by hand, which no consolidation pass " +
			"re-sees because they come from no source."
	}
	resultJSON, _ := json.Marshal(result)
	_, err := dbPool.Exec(context.Background(), `
		UPDATE endpoint_consolidation_runs
		SET status = $1, endpoint_count = $2, rows_read = $3, skipped = $4, result = $5,
		    error = $6, execution_time = $7, updated_at = NOW()
		WHERE scan_id = $8`,
		status, count, read, skippedJSON, string(resultJSON), errMsg,
		time.Since(started).String(), scanID)
	if err != nil {
		log.Printf("[CONSOLIDATE] failed to finish run %s: %v", scanID, err)
	}
	log.Printf("[CONSOLIDATE] %s finished: status=%s endpoints=%d read=%d excluded=%d in %s",
		scanID, status, count, read, excluded.Total, time.Since(started))
}

// GetConsolidationStatus handles GET /consolidated-endpoints/{scope_target_id}/status/{scan_id}.
//
// Returns the refused rows, not only how many. A caller that is told "excluded: 9" and cannot ask
// which nine has to go read the container log to find out whether the run threw away noise or threw
// away the engagement, which is how the previous excluded-count defect was reported.
func GetConsolidationStatus(w http.ResponseWriter, r *http.Request) {
	scanID := mux.Vars(r)["scan_id"]

	var out struct {
		ScanID        string    `json:"scan_id"`
		Status        string    `json:"status"`
		EndpointCount int       `json:"endpoint_count"`
		RowsRead      int       `json:"rows_read"`
		Skipped       []byte    `json:"-"`
		Result        *string   `json:"-"`
		Error         *string   `json:"error"`
		ExecutionTime *string   `json:"execution_time"`
		CreatedAt     time.Time `json:"created_at"`
	}
	err := dbPool.QueryRow(context.Background(), `
		SELECT scan_id, status, endpoint_count, rows_read, skipped, result, error, execution_time, created_at
		FROM endpoint_consolidation_runs WHERE scan_id = $1`, scanID).Scan(
		&out.ScanID, &out.Status, &out.EndpointCount, &out.RowsRead, &out.Skipped, &out.Result,
		&out.Error, &out.ExecutionTime, &out.CreatedAt)
	if err != nil {
		http.Error(w, "Consolidation run not found", http.StatusNotFound)
		return
	}

	var skipped map[string]int
	_ = json.Unmarshal(out.Skipped, &skipped)

	excluded := consolidationExclusionsFromResult(out.Result)

	payload := map[string]interface{}{
		"scan_id": out.ScanID, "status": out.Status, "endpoint_count": out.EndpointCount,
		"rows_read": out.RowsRead, "skipped": skipped, "excluded": excluded, "error": out.Error,
		"execution_time": out.ExecutionTime, "created_at": out.CreatedAt,
	}
	// Pass through the corpus total when the run recorded one. Runs written before it existed
	// simply do not carry the key, which is the honest representation of "not measured".
	if out.Result != nil {
		var stored struct {
			CorpusTotal *int    `json:"corpus_total"`
			CountsNote  *string `json:"counts_note"`
		}
		if json.Unmarshal([]byte(*out.Result), &stored) == nil && stored.CorpusTotal != nil {
			payload["corpus_total"] = *stored.CorpusTotal
			if stored.CountsNote != nil {
				payload["counts_note"] = *stored.CountsNote
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(payload)
}

// consolidationExclusionsFromResult unpacks the refused rows a run stored.
//
// Runs written before scope enforcement existed have no "excluded" key, and a run that refused
// nothing should read as zero rather than as null: "excluded: null" is the same unanswerable state
// the count-only report already was.
func consolidationExclusionsFromResult(result *string) *exclusionLog {
	empty := newExclusionLog()
	if result == nil || strings.TrimSpace(*result) == "" {
		return empty
	}
	var parsed struct {
		Excluded *exclusionLog `json:"excluded"`
	}
	if json.Unmarshal([]byte(*result), &parsed) != nil || parsed.Excluded == nil {
		return empty
	}
	if parsed.Excluded.ByReason == nil {
		parsed.Excluded.ByReason = map[string]int{}
	}
	if parsed.Excluded.ByHost == nil {
		parsed.Excluded.ByHost = map[string]int{}
	}
	return parsed.Excluded
}

func nullInt(n int) interface{} {
	if n == 0 {
		return nil
	}
	return n
}
