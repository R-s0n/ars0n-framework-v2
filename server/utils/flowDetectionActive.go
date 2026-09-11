package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Active flow detection: sending requests to find routing the operator never clicked.
//
// The passive detector (replayRequestFlows.go) reconstructs flows from traffic the operator's own
// browser produced. It is honest and it is blind in one specific way: it can only ever show a path
// somebody walked. The login redirect chain on a page nobody visited, the 302 that a stale endpoint
// still answers with, the route that only exists for an unauthenticated caller - none of that is in
// the corpus, because nobody generated it.
//
// So this issues ONE request per selected endpoint, follows the redirects it gets back, and writes
// every hop into manual_crawl_captures with capture_source='active'. Storing them as captures is the
// whole design: the sitemap, the repeater, the query language and the flow segmenter already read
// that table, so a second table would mean changing all four. The rows go in under their own
// session_id, which is what makes them segment into their own flows instead of being spliced into a
// recording the operator made last week.
//
// ============================================================================
// THE RAILS
// ============================================================================
//
// The verb is the operator's choice: any syntactically valid HTTP method token is sendable, from GET
// to PROPFIND to something the application invented for itself, and a recorded request body is sent
// with it. The rails below are the programme's rules and this scanner's correctness, which is a
// different thing:
//
//	SCOPE.           ScanClient.WithScope refuses out-of-boundary hosts at the door, and a host marked
//	                 in_scope=false is denied separately and unconditionally first. See
//	                 ExcludedScopeHosts for why the second check is not redundant. This is the bug
//	                 bounty programme's boundary, not a preference.
//	EXCLUSIONS.      flow_detection_exclusions, checked on every selected endpoint AND again on every
//	                 redirect destination before it is followed. The operator's own list.
//	PACING.          HostBudget, the same ladder Validate and Investigate use: an rps ceiling, a total
//	                 request budget, and an abort when the target starts returning 429/503 or slows
//	                 down under the traffic. Plus jitter, which HostBudget does not do. Programmes
//	                 mandate rates, and the per-target gate exists because four concurrent runs were
//	                 measured delivering 9 rps against a 2 rps limit.
//	REDIRECT LIMIT.  A chain longer than max_redirects is a loop or a login wall. Runaway protection.
//	NO CREDENTIALS.  No cookie jar, no ScopedAuthMaterial, no Authorization header. Not a restriction
//	                 on the operator: this scanner has no session to send, and a request that quietly
//	                 acted as somebody would make every result unattributable. Replay Requests and the
//	                 Request Flow Builder are where a request carries the recorded session.
//	QUERY STRINGS.   Stripped unless include_query, because a stored query holds the identifiers the
//	                 operator's browser really sent. Their switch, off by default, shown in the dry run.
//	DRY RUN.         A separate endpoint that sends nothing and reports every excluded endpoint WITH
//	                 the rule that excluded it. Available, not a gate.
//
// Anything added here that sends a request must go through runFlowDetectionChain. That is the one
// door, for the same reason ScanClient is the one door underneath it: a rule every call site has to
// remember is a rule that leaks.

const (
	// One request per second is the default because this is discovery, not fuzzing. There are at most
	// a few thousand endpoints and no reason to be fast about them.
	flowDetectDefaultRPS = 1.0
	flowDetectMaxRPS     = 10.0

	// A ceiling on what a single run can cost the target, independent of what the operator typed.
	flowDetectDefaultMaxRequests = 250
	flowDetectHardMaxRequests    = 5000

	// Redirects are the point of this scanner, so they are followed, but a chain longer than this is
	// a loop or a login wall and neither gets more interesting on the sixth hop.
	flowDetectDefaultMaxRedirects = 5
	flowDetectHardMaxRedirects    = 10

	flowDetectDefaultTimeoutS = 15
	flowDetectMaxTimeoutS     = 60

	// Jitter as a fraction of the pacing interval. HostBudget paces on a fixed interval, which is a
	// machine-shaped traffic pattern; a little noise on top costs nothing and stops the run looking
	// like exactly what it is to anything watching.
	flowDetectJitterFraction = 0.35

	// How often the runner re-reads its own status row, so a cancel issued by another process (or
	// after this one restarted) still stops it. The in-memory latch is the fast path; this is the one
	// that works when the fast path is not there.
	flowDetectCancelPollEvery = 10
)

// FlowDetectionConfig is what a run is allowed to be asked for.
type FlowDetectionConfig struct {
	Methods     []string `json:"methods"`
	RPS         float64  `json:"rps"`
	MaxRequests int      `json:"max_requests"`

	// A POINTER so that "omitted" and "false" are different things. Redirects are the whole reason
	// this scanner exists, so the default is TRUE, and a plain bool would mean every client that left
	// the field out silently got a run that cannot see a redirect chain. That is the field-translation
	// failure where a control reports success and does nothing, and it is worth one pointer to avoid.
	FollowRedirects *bool `json:"follow_redirects"`

	MaxRedirects int `json:"max_redirects"`
	TimeoutS     int `json:"timeout_s"`

	// Off by default. On, the recorded query string is sent as it was recorded, which means any
	// identifier in it is sent too. The dry run renders the full URL either way so the operator can
	// see what turning this on actually means for their corpus.
	IncludeQuery bool `json:"include_query"`

	// On by default. The body recorded for an endpoint is sent with it when the verb takes one.
	// A POINTER, so "omitted" and "false" are different: a body-taking verb sent with an empty body
	// gets a 400 from most endpoints, which would be recorded as if the endpoint had been tested.
	// Off means every request goes out with an empty body; the plan says which it was.
	SendRecordedBodies *bool `json:"send_recorded_bodies"`
}

// BodiesEnabled reports whether recorded bodies are sent, resolving the pointer's default.
func (c FlowDetectionConfig) BodiesEnabled() bool {
	return c.SendRecordedBodies == nil || *c.SendRecordedBodies
}

// FlowDetectionTarget is one request the run intends to make.
type FlowDetectionTarget struct {
	URL    string `json:"url"`
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Source string `json:"source"` // consolidated | attack_vector

	// The recorded body this request will carry, and its Content-Type. Empty means the request goes
	// out with no body. BodyBytes is reported separately so a dry run can show the size without the
	// plan carrying every body twice.
	Body        string `json:"body,omitempty"`
	ContentType string `json:"content_type,omitempty"`
	BodyBytes   int    `json:"body_bytes,omitempty"`
}

// FlowDetectionSkip is one endpoint that will NOT be requested, and why.
//
// Reason codes, so a client can group them and an operator can act on each:
//
//	exclusion         an operator rule matched. Pattern and Detail carry the rule and its reason.
//	host_excluded     the host is marked in_scope=false on this target.
//	out_of_scope      the host is outside the target's boundary.
//	method            the endpoint's method is not one this run is sending.
//	unusable_url      the row does not parse into an http(s) URL.
//	over_budget       the run's max_requests was reached before this endpoint's turn.
type FlowDetectionSkip struct {
	URL     string `json:"url"`
	Method  string `json:"method"`
	Reason  string `json:"reason"`
	Pattern string `json:"pattern,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// FlowDetectionPlan is what a dry run returns and what a real run executes.
type FlowDetectionPlan struct {
	Targets []FlowDetectionTarget `json:"targets"`
	Skipped []FlowDetectionSkip   `json:"skipped"`

	RequestCount int     `json:"request_count"`
	SkippedCount int     `json:"skipped_count"`
	RPS          float64 `json:"rps"`

	// Two numbers, not one. The first is what the run costs if nothing redirects; the second is the
	// worst case if everything does. Reporting only the first is how a "200 request" run turns into
	// 1,200 requests against somebody's production.
	EstimatedSeconds          int `json:"estimated_seconds"`
	MaxRequestsWorstCase      int `json:"max_requests_worst_case"`
	EstimatedSecondsWorstCase int `json:"estimated_seconds_worst_case"`

	// How many of Skipped were the operator's own deselections, so the screen can show
	// total - deselected - excluded = sent without having to count reason codes itself.
	DeselectedCount int `json:"deselected_count"`

	// THE BODY REPORT. Three numbers, because "detection sent your POSTs" and "detection sent your
	// POSTs with an empty body" are different runs and only one of them tested anything.
	//
	// BodyTakingCount is how many planned requests use a verb that takes a body; BodiesAttached is
	// how many of those found a recorded body; BodiesEmpty is the remainder, which will go out with
	// no body and most likely come back 400.
	BodyTakingCount int  `json:"body_taking_count"`
	BodiesAttached  int  `json:"bodies_attached"`
	BodiesEmpty     int  `json:"bodies_empty"`
	BodiesEnabled   bool `json:"bodies_enabled"`
	// One sentence saying which of the above happened, for a client that shows a line rather than
	// four numbers. Empty when the run sends no body-taking verbs.
	BodyNote string `json:"body_note,omitempty"`

	// Every rule in force, not only the ones that fired. An operator reviewing a dry run needs to see
	// the list they are running under.
	ExclusionPatterns []string `json:"exclusion_patterns"`
	ScopeBoundary     string   `json:"scope_boundary"`
	DeniedHosts       []string `json:"denied_hosts"`

	// Config is the run's config AFTER the target's engagement rules have been folded in, so what the
	// dry run shows for rps, budget and timeout is what the run will actually use. Showing the
	// requested values instead would tell an operator on a 45-requests-per-minute programme that they
	// were about to send at 10 rps.
	Config FlowDetectionConfig `json:"config"`

	// Engagement is the programme's rules for this target and where each field came from, so the dry
	// run can say "sending X-HackerOne-DailyPay-Research, set for this target" rather than leaving
	// the operator to trust that it happened.
	Engagement *ResolvedEngagementConfig `json:"engagement,omitempty"`

	// Set when the plan is legal but pointless, so the UI can say why instead of showing an empty
	// table. A run with nothing to send is refused rather than started.
	Warning string `json:"warning,omitempty"`
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

// ValidateFlowDetectionConfig normalises a requested config.
//
// Every verb is legal here. There is no list: a method is checked for SHAPE, not membership, so
// PROPFIND, LOCK, REPORT and an application's own invented verb all validate. What is refused is a
// string that is not an HTTP method token at all, which is a typo check and not a policy: "GET /x"
// with a space in it is a mangled config, not a verb anybody meant.
//
// The default is GET, because a sensible default is not a block. An operator opening the modal for
// the first time should not immediately send POSTs to everything; nothing stops them selecting POST.
func ValidateFlowDetectionConfig(cfg FlowDetectionConfig) (FlowDetectionConfig, error) {
	out := cfg

	seen := map[string]bool{}
	methods := []string{}
	for _, m := range cfg.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		methods = append(methods, m)
	}
	if len(methods) == 0 {
		methods = defaultFlowDetectionMethods()
	}
	sort.Strings(methods)
	out.Methods = methods

	for _, m := range methods {
		if !IsHTTPMethodToken(m) {
			return out, fmt.Errorf(
				"%q is not a valid HTTP method token. A method is one or more of the characters "+
					"A-Z, a-z, 0-9 and !#$%%&'*+-.^_`|~, with no spaces", m)
		}
	}

	if out.RPS <= 0 {
		out.RPS = flowDetectDefaultRPS
	}
	if out.RPS > flowDetectMaxRPS {
		out.RPS = flowDetectMaxRPS
	}

	if out.MaxRequests <= 0 {
		out.MaxRequests = flowDetectDefaultMaxRequests
	}
	if out.MaxRequests > flowDetectHardMaxRequests {
		out.MaxRequests = flowDetectHardMaxRequests
	}

	if out.MaxRedirects <= 0 {
		out.MaxRedirects = flowDetectDefaultMaxRedirects
	}
	if out.MaxRedirects > flowDetectHardMaxRedirects {
		out.MaxRedirects = flowDetectHardMaxRedirects
	}
	if out.FollowRedirects == nil {
		follow := true
		out.FollowRedirects = &follow
	}
	if !*out.FollowRedirects {
		out.MaxRedirects = 0
	}

	if out.TimeoutS <= 0 {
		out.TimeoutS = flowDetectDefaultTimeoutS
	}
	if out.TimeoutS > flowDetectMaxTimeoutS {
		out.TimeoutS = flowDetectMaxTimeoutS
	}

	return out, nil
}

// defaultFlowDetectionMethods is what an unspecified verb list means: all of them, not just GET.
//
// The verb is also the SELECTION filter, since a run only touches endpoints already observed
// answering that verb. A GET-only default therefore did not merely send fewer requests, it silently
// removed every write endpoint from the corpus, and a run that never asked reads as a run that found
// nothing. The operator narrows this when they want to; the framework does not narrow it for them.
func defaultFlowDetectionMethods() []string {
	return []string{
		http.MethodGet, http.MethodHead, http.MethodOptions,
		http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete,
	}
}

// DefaultFlowDetectionConfig is what the UI should open with: every quick-pick verb, one request per
// second, redirects followed, no query strings, recorded bodies sent.
func DefaultFlowDetectionConfig() FlowDetectionConfig {
	cfg, _ := ValidateFlowDetectionConfig(FlowDetectionConfig{})
	return cfg
}

// ---------------------------------------------------------------------------
// Planning: which endpoints, and which are refused and why
// ---------------------------------------------------------------------------

// flowDetectionCandidate is a row read out of the corpus before any filter has been applied.
type flowDetectionCandidate struct {
	URL    string
	Method string
	Source string
	// Body as it was recorded for this endpoint, empty when the corpus has none. See
	// loadFlowDetectionBodies for where it comes from and why most rows have none.
	Body        string
	ContentType string
}

// flowDetectVerbTakesBody reports whether sending a body with this verb is meaningful.
//
// A DENY LIST OF THREE, not an allow list of four. GET, HEAD and OPTIONS are excluded even when the
// corpus recorded a body against them: a bodied GET is accepted by almost nothing and rejected
// inconsistently by proxies, so attaching one would change the response for reasons that have
// nothing to do with the endpoint. HEAD is defined to have no body at all.
//
// Everything else carries its recorded body, and it has to be this way round now that any method
// token is sendable. An allow list of POST/PUT/PATCH/DELETE would send an empty PROPFIND or an empty
// REPORT, both of which are defined by the XML body they carry, and the run would record a 400 as
// though the endpoint had been tested.
func flowDetectVerbTakesBody(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// loadFlowDetectionBodies indexes the request bodies this target has actually recorded.
//
// TWO SOURCES, and the second one was missed. manual_crawl_captures.post_data is the operator's own
// crawl, which is the richer of the two. consolidated_url_endpoints ALSO carries request_body and
// content_type, which an earlier version of this comment asserted did not exist; on the live
// database 23 consolidated rows hold a real body, and every one of them was being ignored, so a
// POST detection run sent them empty and the plan reported them as "no recorded body". An empty
// POST answers 400 and lands in the capture table looking exactly like an endpoint that was tested.
//
// The CRAWL WINS on a conflict. Both describe the same request, but the crawl row is the one whose
// body was observed on the wire with its headers beside it, while a consolidated row may have been
// assembled from an archive. So consolidated is loaded first and the crawl overwrites it.
//
// Keyed on NormalizeFlowTuple - method, host, path - so it matches the way the planner dedupes after
// the query strip. Keying on the full URL would miss every row whose query string differed.
//
// The MOST RECENT body wins within each source, and empties never overwrite a real one: an endpoint
// captured twice, once with a body and once without, should send the body it was seen carrying.
func loadFlowDetectionBodies(scopeTargetID string) (map[string]string, map[string]string, error) {
	bodies := map[string]string{}
	types := map[string]string{}

	// The consolidated corpus first, so a crawl row for the same tuple replaces it below.
	crows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(NULLIF(method,''),'GET'), COALESCE(url,''),
		       COALESCE(request_body,''), COALESCE(content_type,'')
		  FROM consolidated_url_endpoints
		 WHERE scope_target_id = $1 AND deleted_at IS NULL
		   AND COALESCE(request_body,'') <> ''
		 ORDER BY last_seen ASC`, scopeTargetID)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read consolidated request bodies: %w", err)
	}
	for crows.Next() {
		var method, rawURL, body, contentType string
		if err := crows.Scan(&method, &rawURL, &body, &contentType); err != nil {
			continue
		}
		if strings.TrimSpace(body) == "" {
			continue
		}
		key := NormalizeFlowTuple(method, rawURL)
		bodies[key] = body
		types[key] = contentType
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return nil, nil, fmt.Errorf("could not read consolidated request bodies: %w", err)
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(method,''), COALESCE(url,''), COALESCE(post_data,''), COALESCE(body_type,'')
		  FROM manual_crawl_captures
		 WHERE scope_target_id = $1 AND COALESCE(post_data,'') <> ''
		 ORDER BY timestamp ASC`, scopeTargetID)
	if err != nil {
		return nil, nil, fmt.Errorf("could not read recorded request bodies: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var method, rawURL, body, bodyType string
		if err := rows.Scan(&method, &rawURL, &body, &bodyType); err != nil {
			continue
		}
		if strings.TrimSpace(body) == "" {
			continue
		}
		key := NormalizeFlowTuple(method, rawURL)
		bodies[key] = body
		types[key] = bodyType
	}
	return bodies, types, rows.Err()
}

// flowDetectionContentType maps a recorded body_type to a Content-Type header.
//
// An empty result means the header is not set, and that is deliberate: guessing wrong is worse than
// not guessing. A JSON body labelled as a form gets a 400 that reads like the endpoint rejecting the
// request rather than the sender mislabelling it.
func flowDetectionContentType(bodyType, body string) string {
	switch strings.ToLower(strings.TrimSpace(bodyType)) {
	case "json", "application/json":
		return "application/json"
	case "form", "form-data", "urlencoded", "application/x-www-form-urlencoded":
		return "application/x-www-form-urlencoded"
	case "multipart", "multipart/form-data":
		// The boundary is part of the recorded bytes and cannot be reconstructed from body_type
		// alone, so this is left unset rather than sent with a boundary that does not match.
		return ""
	case "xml", "text/xml", "application/xml":
		return "application/xml"
	}
	// Nothing recorded: infer only from an unambiguous shape.
	trimmed := strings.TrimSpace(body)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "application/json"
	}
	return ""
}

// loadFlowDetectionCandidates sources endpoints from the three tables that describe this target's
// surface. All three are read, not one:
//
//	manual_crawl_captures      what the operator's browser actually did, available the moment a
//	                           recording stops
//	consolidated_url_endpoints the crawl and archive corpus, available only after consolidation runs
//	attack_vectors             the operator-curated list, which routinely contains hand-added rows
//	                           that never appeared in any crawl
//
// THE CRAWL WAS THE MISSING SOURCE and its absence was invisible in the worst way. This one function
// feeds the Configure screen, the card's endpoint metric, the detection planner and deselect-all, so
// on a target that had been crawled but never consolidated, 3,548 recorded requests produced an
// endpoint list of zero rows and a card reading "0 of 0 discovered". Nothing errored and nothing
// looked broken: the corpus simply was never asked for. A screen that reports an empty corpus and a
// screen that reports a corpus it did not read are indistinguishable to the operator, which is the
// same class of defect as a count that counts something else.
//
// THE CRAWL IS READ FIRST, and that ordering carries a decision. BuildFlowEndpointList merges rows on
// the flow key and the FIRST occurrence supplies the displayed URL, so reading the crawl first means
// the URL on screen is one that was genuinely observed on the wire rather than one a consolidation
// pass may have assembled from an archive. Same precedence, and the same reasoning, as
// loadFlowDetectionBodies, where the crawl also wins.
//
// DISTINCT IS DONE IN SQL for the crawl, because a browsing session hits the same request hundreds of
// times: on a live corpus here it collapses 3,548 rows to 386 before any of them leave Postgres. The
// duplicates that remain are the same endpoint under different query strings, and those are collapsed
// by BuildFlowEndpointList on the flow key, which strips the query and is where that decision belongs.
// Expect the resulting endpoint count to differ slightly from the number the manual-crawl summary
// reports: that summary groups on a TEMPLATISED path (/accounts/{uuid}/details), while a candidate
// must keep the literal path because the literal path is what gets sent.
//
// NO RESOURCE-TYPE FILTER. Stylesheets, images and fonts recorded by the crawl become candidates like
// everything else. Dropping them here would be this file quietly deciding what the operator may scan,
// and the header comment on flowEndpointSelection.go explains at length why silently narrowing a
// corpus is the one thing this feature must not do. They arrive selected, they are visible on the
// Configure screen, and taking them out is one filtered deselect.
func loadFlowDetectionCandidates(scopeTargetID string) ([]flowDetectionCandidate, error) {
	out := []flowDetectionCandidate{}

	mrows, err := dbPool.Query(context.Background(), `
		SELECT DISTINCT COALESCE(url,''), COALESCE(NULLIF(method,''),'GET')
		  FROM manual_crawl_captures
		 WHERE scope_target_id = $1 AND COALESCE(url,'') <> '' AND url LIKE 'http%'`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("could not read crawled endpoints: %w", err)
	}
	for mrows.Next() {
		var c flowDetectionCandidate
		if err := mrows.Scan(&c.URL, &c.Method); err != nil {
			continue
		}
		c.Source = "manual_crawl"
		out = append(out, c)
	}
	mrows.Close()
	if err := mrows.Err(); err != nil {
		return nil, fmt.Errorf("could not read crawled endpoints: %w", err)
	}

	rows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(url,''), COALESCE(NULLIF(method,''),'GET')
		  FROM consolidated_url_endpoints
		 WHERE scope_target_id = $1 AND deleted_at IS NULL AND COALESCE(url,'') <> ''`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("could not read consolidated endpoints: %w", err)
	}
	for rows.Next() {
		var c flowDetectionCandidate
		if err := rows.Scan(&c.URL, &c.Method); err != nil {
			continue
		}
		c.Source = "consolidated"
		out = append(out, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("could not read consolidated endpoints: %w", err)
	}

	vrows, err := dbPool.Query(context.Background(), `
		SELECT COALESCE(NULLIF(scheme,''),'https'), COALESCE(domain,''), port,
		       COALESCE(NULLIF(path,''),'/'), COALESCE(NULLIF(method,''),'GET')
		  FROM attack_vectors
		 WHERE scope_target_id = $1 AND deleted_at IS NULL AND COALESCE(domain,'') <> ''`, scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("could not read attack vectors: %w", err)
	}
	defer vrows.Close()
	for vrows.Next() {
		var scheme, domain, path, method string
		var port *int
		if err := vrows.Scan(&scheme, &domain, &port, &path, &method); err != nil {
			continue
		}
		authority := domain
		if port != nil && *port > 0 && !flowDetectDefaultPort(scheme, *port) {
			authority = fmt.Sprintf("%s:%d", domain, *port)
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		out = append(out, flowDetectionCandidate{
			URL:    scheme + "://" + authority + path,
			Method: method,
			Source: "attack_vector",
		})
	}
	return out, vrows.Err()
}

func flowDetectDefaultPort(scheme string, port int) bool {
	return (strings.EqualFold(scheme, "https") && port == 443) ||
		(strings.EqualFold(scheme, "http") && port == 80)
}

// flowDetectionSendableURL turns a stored URL into the exact string this scanner will put on the
// wire, or returns an error explaining why it will not put anything on the wire for that row.
//
// THE QUERY STRING IS DROPPED unless includeQuery. This is the "send the endpoint, not the payload"
// rule and it is not a nicety: a consolidated row is a URL somebody's browser really requested, so
// its query holds real tokens, real order numbers and real email addresses. GET /reset?token=abc
// against a live target burns that token. GET /reset does not.
//
// The fragment and any userinfo go too. A fragment is never sent anyway, and userinfo in a stored URL
// is a credential that must not be replayed.
func flowDetectionSendableURL(raw string, includeQuery bool) (string, *url.URL, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", nil, fmt.Errorf("unparseable URL")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", nil, fmt.Errorf("scheme %q is not http or https", parsed.Scheme)
	}
	if parsed.Hostname() == "" {
		return "", nil, fmt.Errorf("no host")
	}

	clean := *parsed
	clean.Scheme = scheme
	clean.Host = strings.ToLower(parsed.Host)
	clean.User = nil
	clean.Fragment = ""
	clean.RawFragment = ""
	if !includeQuery {
		clean.RawQuery = ""
		clean.ForceQuery = false
	}
	if clean.Path == "" {
		clean.Path = "/"
	}
	return clean.String(), &clean, nil
}

// PlanFlowDetection decides what a run would send and what it would refuse to send.
//
// This is the whole safety story in one function, and the dry run and the real run BOTH call it, so
// what the operator was shown is what the runner executes. Two code paths here would be two chances
// for the preview to disagree with reality, which is exactly the failure that makes a dry run
// worthless.
//
// Order matters. The denied-host check runs FIRST, before scope, because it is the operator's own
// explicit "never send here" and it must not be able to be overridden by a boundary that happens to
// admit the host for a different reason.
func PlanFlowDetection(scopeTargetID string, cfg FlowDetectionConfig) (*FlowDetectionPlan, error) {
	// THE ENGAGEMENT CONFIG IS RESOLVED FIRST, BEFORE ValidateFlowDetectionConfig.
	//
	// Order, not preference. Validate fills every zero field with a framework default, after which
	// "the client did not ask for an rps" is indistinguishable from "the client asked for 1.0" - and
	// a per-target rate cap that can never be applied because a default got there first is a control
	// that shows a number on screen and changes nothing on the wire.
	//
	// FAIL CLOSED. If the programme's rules cannot be read we do not send. A run that proceeds
	// without them is a run that sends traffic to DailyPay without the header their brief calls
	// mandatory, at a rate Assurant caps, and reports success. Same rule as the exclusion list below,
	// for the same reason.
	engagement, err := ResolveEngagementConfig(scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf(
			"this target's engagement config could not be read, so no run may start: %w", err)
	}
	cfg = ApplyEngagementToDetection(cfg, engagement)

	cfg, err = ValidateFlowDetectionConfig(cfg)
	if err != nil {
		return nil, err
	}

	// Loaded, and a failure is fatal to the plan. An exclusion list that could not be read must never
	// degrade into an empty one: that is a scanner losing "this endpoint texts customers" to a
	// transient database error and sending the request anyway.
	rules, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("the exclusion list could not be read, so no run may start: %w", err)
	}
	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("the excluded-host list could not be read, so no run may start: %w", err)
	}
	scope := LoadScanScope(scopeTargetID)

	candidates, err := loadFlowDetectionCandidates(scopeTargetID)
	if err != nil {
		return nil, err
	}

	// The recorded bodies, when the run is sending them. A failure here is NOT fatal to the plan:
	// unlike the exclusion list, a missing body index cannot cause a request to reach something it
	// should not - it can only make body-taking requests go out empty. That is reported in the plan's
	// body counts rather than stopping the run, so the operator sees it instead of guessing.
	if cfg.BodiesEnabled() {
		bodies, types, berr := loadFlowDetectionBodies(scopeTargetID)
		if berr != nil {
			log.Printf("[FLOW-DETECT] Could not read recorded bodies for %s: %v", scopeTargetID, berr)
		} else {
			for i := range candidates {
				if !flowDetectVerbTakesBody(candidates[i].Method) {
					continue
				}
				key := NormalizeFlowTuple(candidates[i].Method, candidates[i].URL)
				if body, ok := bodies[key]; ok {
					candidates[i].Body = body
					candidates[i].ContentType = flowDetectionContentType(types[key], body)
				}
			}
		}
	}

	// The operator's selection, applied BEFORE the plan is built rather than to the plan afterwards.
	// See PartitionFlowCandidatesBySelection: the planner truncates at max_requests, so filtering
	// later would let deselected endpoints consume the budget and push the wanted ones into
	// over_budget. A failure to read the selection is fatal for the same reason the exclusion list is.
	deselected, err := LoadFlowEndpointDeselections(scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf(
			"the endpoint selection could not be read, so no run may start: %w", err)
	}
	candidates, deselectedSkips := PartitionFlowCandidatesBySelection(candidates, deselected, cfg.IncludeQuery)

	plan := buildFlowDetectionPlan(candidates, cfg, rules, denied, scope)
	plan.Skipped = append(plan.Skipped, deselectedSkips...)
	plan.SkippedCount = len(plan.Skipped)
	plan.DeselectedCount = len(deselectedSkips)
	plan.Engagement = &engagement

	// buildFlowDetectionPlan's warning blames the method, scope and exclusion rules, because it never
	// sees a deselection. When a deselection is what emptied the plan, say so: sending an operator to
	// re-read their exclusion list for something they did on the Configure screen is how a correct
	// message becomes a wrong one.
	if plan.RequestCount == 0 && plan.DeselectedCount > 0 {
		plan.Warning = fmt.Sprintf(
			"Nothing would be sent. %d endpoint(s) are deselected for this target; the rest were "+
				"filtered out by the method, scope or exclusion rules listed above. Open Configure "+
				"to select the endpoints you want detection to reach.", plan.DeselectedCount)
	}

	return plan, nil
}

// buildFlowDetectionPlan is every selection and refusal decision, as a pure function.
//
// The database reads are all in PlanFlowDetection above and NOTHING is decided there. The split is
// the point: the rules that stop this scanner requesting the endpoint that texts a customer are
// judgement calls, and a judgement call that can only be exercised against a live 6,000-row corpus
// is a judgement call nobody will ever check. Every one of them is tested in
// flowDetectionActive_test.go against a handful of structs.
func buildFlowDetectionPlan(
	candidates []flowDetectionCandidate, cfg FlowDetectionConfig,
	rules []FlowExclusion, denied map[string]bool, scope *ScanScope,
) *FlowDetectionPlan {

	wanted := map[string]bool{}
	for _, m := range cfg.Methods {
		wanted[m] = true
	}

	plan := &FlowDetectionPlan{
		Targets:           []FlowDetectionTarget{},
		Skipped:           []FlowDetectionSkip{},
		RPS:               cfg.RPS,
		Config:            cfg,
		ExclusionPatterns: SortedFlowExclusionPatterns(rules),
		ScopeBoundary:     scope.Describe(),
		DeniedHosts:       sortedFlowHostSet(denied),
	}

	seen := map[string]bool{}
	for _, c := range candidates {
		method := strings.ToUpper(strings.TrimSpace(c.Method))
		if method == "" {
			method = http.MethodGet
		}

		// The method filter is on the endpoint's RECORDED verb, not a verb we impose. Selecting POST
		// sends POST to the routes already observed answering a POST; it does not turn every GET into
		// a POST. Sending a verb to a route never seen answering it would be inventing a request, and
		// "GET /logout" is why that is not a safe thing to invent.
		if !wanted[method] {
			plan.Skipped = append(plan.Skipped, FlowDetectionSkip{
				URL: c.URL, Method: method, Reason: "method",
				Detail: fmt.Sprintf("this run sends %s only", strings.Join(cfg.Methods, ", ")),
			})
			continue
		}

		sendable, parsed, err := flowDetectionSendableURL(c.URL, cfg.IncludeQuery)
		if err != nil {
			plan.Skipped = append(plan.Skipped, FlowDetectionSkip{
				URL: c.URL, Method: method, Reason: "unusable_url", Detail: err.Error(),
			})
			continue
		}

		key := method + " " + sendable
		if seen[key] {
			// Dedupe AFTER the query strip, which is where most of it happens: fifty rows of
			// /search?q=<fifty different things> collapse into one request to /search.
			continue
		}
		seen[key] = true

		host := parsed.Hostname()

		if IsDeniedFlowHost(denied, host) {
			plan.Skipped = append(plan.Skipped, FlowDetectionSkip{
				URL: sendable, Method: method, Reason: "host_excluded",
				Detail: fmt.Sprintf("%s is marked out of scope for this target", host),
			})
			continue
		}
		if !scope.Allows(host) {
			plan.Skipped = append(plan.Skipped, FlowDetectionSkip{
				URL: sendable, Method: method, Reason: "out_of_scope",
				Detail: fmt.Sprintf("%s is outside this target's boundary (%s)", host, plan.ScopeBoundary),
			})
			continue
		}
		if d := FirstFlowExclusionMatch(rules, sendable); d.Excluded {
			plan.Skipped = append(plan.Skipped, FlowDetectionSkip{
				URL: sendable, Method: method, Reason: "exclusion",
				Pattern: d.Pattern, Detail: d.Reason,
			})
			continue
		}

		target := FlowDetectionTarget{
			URL: sendable, Method: method, Host: host, Path: parsed.Path, Source: c.Source,
		}
		if cfg.BodiesEnabled() && flowDetectVerbTakesBody(method) {
			target.Body = c.Body
			target.ContentType = c.ContentType
			target.BodyBytes = len(c.Body)
		}
		plan.Targets = append(plan.Targets, target)
	}

	// Stable order so two dry runs of the same corpus read the same, and so the operator reviewing a
	// list can find the entry they were looking at a minute ago.
	sort.SliceStable(plan.Targets, func(i, j int) bool {
		if plan.Targets[i].Host != plan.Targets[j].Host {
			return plan.Targets[i].Host < plan.Targets[j].Host
		}
		if plan.Targets[i].Path != plan.Targets[j].Path {
			return plan.Targets[i].Path < plan.Targets[j].Path
		}
		return plan.Targets[i].Method < plan.Targets[j].Method
	})

	// The budget cut is reported, never silent. "You asked for everything and we sent the first 250"
	// is information the operator needs in order to decide whether to raise the budget or narrow the
	// corpus, and hiding it makes the run look complete when it was truncated.
	if len(plan.Targets) > cfg.MaxRequests {
		for _, t := range plan.Targets[cfg.MaxRequests:] {
			plan.Skipped = append(plan.Skipped, FlowDetectionSkip{
				URL: t.URL, Method: t.Method, Reason: "over_budget",
				Detail: fmt.Sprintf("the run's budget of %d requests was reached first", cfg.MaxRequests),
			})
		}
		plan.Targets = plan.Targets[:cfg.MaxRequests]
	}

	plan.RequestCount = len(plan.Targets)
	plan.SkippedCount = len(plan.Skipped)

	// Counted AFTER the budget cut, so these describe the requests that will actually be sent rather
	// than the ones that were considered. A count that silently includes truncated entries is the
	// "counts that are not counts" failure.
	plan.BodiesEnabled = cfg.BodiesEnabled()
	for _, t := range plan.Targets {
		if !flowDetectVerbTakesBody(t.Method) {
			continue
		}
		plan.BodyTakingCount++
		if t.Body != "" {
			plan.BodiesAttached++
		} else {
			plan.BodiesEmpty++
		}
	}

	plan.BodyNote = flowDetectionBodyNote(plan)

	plan.MaxRequestsWorstCase = plan.RequestCount * (1 + cfg.MaxRedirects)
	if plan.RPS > 0 {
		plan.EstimatedSeconds = int(math.Ceil(float64(plan.RequestCount) / plan.RPS))
		plan.EstimatedSecondsWorstCase = int(math.Ceil(float64(plan.MaxRequestsWorstCase) / plan.RPS))
	}

	if plan.RequestCount == 0 {
		plan.Warning = "Nothing would be sent. Every endpoint on this target was filtered out by the " +
			"method, scope or exclusion rules listed above, or there are no endpoints yet - " +
			"consolidate the URL workflow first."
	}
	return plan
}

// flowDetectionBodyNote states what the run will do about request bodies, in one sentence.
//
// An empty-bodied POST is the case worth naming. It reaches the endpoint, gets a 400 or a 415, and
// is recorded as a request that was sent - which reads exactly like a tested endpoint unless
// somebody says otherwise. This says otherwise.
func flowDetectionBodyNote(plan *FlowDetectionPlan) string {
	if plan.BodyTakingCount == 0 {
		return ""
	}
	if !plan.BodiesEnabled {
		return fmt.Sprintf("%d request(s) use a verb that takes a body, and send_recorded_bodies is "+
			"off, so all of them go out with an empty body.", plan.BodyTakingCount)
	}
	switch {
	case plan.BodiesEmpty == 0:
		return fmt.Sprintf("%d request(s) use a verb that takes a body and all of them carry the body "+
			"recorded for that endpoint.", plan.BodyTakingCount)
	case plan.BodiesAttached == 0:
		return fmt.Sprintf("%d request(s) use a verb that takes a body and NONE of them have one: this "+
			"target has no recorded bodies for those endpoints. They will be sent empty, which most "+
			"endpoints answer 400 or 415 regardless of what they do with a real body.",
			plan.BodyTakingCount)
	default:
		return fmt.Sprintf("%d of %d body-taking request(s) carry a recorded body; the other %d are sent "+
			"empty and will mostly answer 400 or 415 whatever the endpoint does with a real body.",
			plan.BodiesAttached, plan.BodyTakingCount, plan.BodiesEmpty)
	}
}

func sortedFlowHostSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// Run state
// ---------------------------------------------------------------------------

// FlowDetectionStatus is what the status endpoint returns.
type FlowDetectionStatus struct {
	RunID       string          `json:"run_id"`
	SessionID   string          `json:"session_id"`
	Status      string          `json:"status"`
	Planned     int             `json:"planned"`
	Sent        int             `json:"sent"`
	Errors      int             `json:"errors"`
	Excluded    int             `json:"excluded"`
	Redirects   int             `json:"redirects"`
	Aborted     bool            `json:"aborted"`
	AbortReason string          `json:"abort_reason,omitempty"`
	LastError   string          `json:"last_error,omitempty"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
	Config      json.RawMessage `json:"config,omitempty"`
}

const (
	flowRunPending   = "pending"
	flowRunRunning   = "running"
	flowRunCancelled = "cancelled"
	flowRunCompleted = "completed"
	flowRunAborted   = "aborted"
	flowRunError     = "error"
)

// The in-memory cancel latch. It is the fast path, not the only path: the runner also re-reads its
// own status row, so a cancel that arrives after this process restarted still stops the run rather
// than leaving a request-issuing goroutine nobody can reach.
var (
	flowRunCancelsMu sync.Mutex
	flowRunCancels   = map[string]context.CancelFunc{}
)

func registerFlowRunCancel(runID string, cancel context.CancelFunc) {
	flowRunCancelsMu.Lock()
	defer flowRunCancelsMu.Unlock()
	flowRunCancels[runID] = cancel
}

func releaseFlowRunCancel(runID string) {
	flowRunCancelsMu.Lock()
	defer flowRunCancelsMu.Unlock()
	delete(flowRunCancels, runID)
}

func cancelFlowRunInMemory(runID string) bool {
	flowRunCancelsMu.Lock()
	cancel, ok := flowRunCancels[runID]
	flowRunCancelsMu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
	return ok
}

// ---------------------------------------------------------------------------
// POST /flow-detection/{scope_target_id}/dry-run
// ---------------------------------------------------------------------------

// DryRunFlowDetection handles POST /flow-detection/{scope_target_id}/dry-run. It sends nothing.
//
// A preview, available whenever it is wanted, not a gate the run has to pass through. It returns the
// exact plan the run would execute, including which requests carry a body.
func DryRunFlowDetection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	cfg := DefaultFlowDetectionConfig()
	if r.Body != nil {
		// An empty body is a dry run of the defaults, which is the most common thing to want.
		var requested FlowDetectionConfig
		if err := json.NewDecoder(r.Body).Decode(&requested); err == nil {
			cfg = requested
		}
	}

	plan, err := PlanFlowDetection(scopeTargetID, cfg)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "plan_refused", err.Error())
		return
	}
	json.NewEncoder(w).Encode(plan)
}

// ---------------------------------------------------------------------------
// POST /flow-detection/{scope_target_id}/run
// ---------------------------------------------------------------------------

func StartFlowDetection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var requested FlowDetectionConfig
	if err := json.NewDecoder(r.Body).Decode(&requested); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_body", "Body must be JSON: "+err.Error())
		return
	}

	cfg, err := ValidateFlowDetectionConfig(requested)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_config", err.Error())
		return
	}

	// One request-issuing scan at a time per target. The rate budget only governs this process's own
	// requests, so running beside ffuf or nuclei means the measured rate is a fiction.
	if running := RequestIssuingScansRunning(scopeTargetID); len(running) > 0 {
		writeJSONError(w, http.StatusConflict, "scans_running",
			"These scans are already sending traffic at this target: "+strings.Join(running, ", ")+
				". Active flow detection paces itself against a per-host budget that those tools do "+
				"not share, so running alongside them would send more than either of you measured.")
		return
	}

	var existing int
	_ = dbPool.QueryRow(context.Background(),
		`SELECT count(*) FROM flow_detection_runs
		  WHERE scope_target_id = $1 AND status IN ('pending','running','cancelling')`,
		scopeTargetID).Scan(&existing)
	if existing > 0 {
		writeJSONError(w, http.StatusConflict, "already_running",
			"An active flow detection run is already in progress for this target.")
		return
	}

	plan, err := PlanFlowDetection(scopeTargetID, cfg)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "plan_refused", err.Error())
		return
	}
	if plan.RequestCount == 0 {
		writeJSONError(w, http.StatusBadRequest, "nothing_to_send", plan.Warning)
		return
	}

	_, _, base := ScopeTargetBase(scopeTargetID)
	if base == "" {
		base = "active-flow-detection"
	}

	// The captures this run writes need a session to hang off, and giving the run its own session is
	// what makes its rows segment into their own flows instead of being spliced into whatever the
	// operator recorded last. It is a real session row: this really is traffic against this target.
	sessionID := uuid.New().String()
	now := time.Now().UTC()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO manual_crawl_sessions (id, scope_target_id, target_url, status, started_at, last_heartbeat_at)
		VALUES ($1, $2, $3, 'active', $4, $4)`, sessionID, scopeTargetID, base, now); err != nil {
		log.Printf("[FLOW-DETECT] Failed to create session for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"Could not create the capture session for this run: "+err.Error())
		return
	}

	cfgJSON, _ := json.Marshal(cfg)
	runID := uuid.New().String()
	if _, err := dbPool.Exec(context.Background(), `
		INSERT INTO flow_detection_runs
		  (id, scope_target_id, session_id, status, config, planned_count, excluded_count, started_at)
		VALUES ($1, $2, $3, 'running', $4, $5, $6, NOW())`,
		runID, scopeTargetID, sessionID, cfgJSON, plan.RequestCount, plan.SkippedCount); err != nil {
		log.Printf("[FLOW-DETECT] Failed to create run for %s: %v", scopeTargetID, err)
		writeJSONError(w, http.StatusInternalServerError, "internal_error",
			"Could not start the run: "+err.Error())
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	registerFlowRunCancel(runID, cancel)
	go func() {
		defer releaseFlowRunCancel(runID)
		defer cancel()
		executeFlowDetectionRun(ctx, runID, scopeTargetID, sessionID, plan)
	}()

	log.Printf("[FLOW-DETECT] Run %s started for %s: %d requests at %.2f rps (%d excluded)",
		runID, scopeTargetID, plan.RequestCount, plan.RPS, plan.SkippedCount)

	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id":        runID,
		"session_id":    sessionID,
		"status":        flowRunRunning,
		"planned":       plan.RequestCount,
		"excluded":      plan.SkippedCount,
		"rps":           plan.RPS,
		"estimated_sec": plan.EstimatedSeconds,
	})
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

// executeFlowDetectionRun sends the plan.
//
// CANCELLATION IS NOT A DISCARD. A cancelled run keeps every capture it already wrote and records
// what it reached, because the operator who pressed cancel usually did so having seen something they
// wanted to look at, and throwing the run away would throw that away with it.
func executeFlowDetectionRun(ctx context.Context, runID, scopeTargetID, sessionID string, plan *FlowDetectionPlan) {
	budget := NewHostBudget()
	scope := LoadScanScope(scopeTargetID)

	hosts := map[string]bool{}
	for _, t := range plan.Targets {
		if !hosts[t.Host] {
			hosts[t.Host] = true
			budget.Acquire(t.Host, plan.RPS, 1, "active flow detection")
		}
	}

	// THE ENGAGEMENT CONFIG, RE-READ HERE.
	//
	// Re-read rather than taken from the plan, the same way the exclusion list below is, so a header
	// the operator added between pressing dry-run and pressing run is on every request. And fatal on
	// failure: sending a programme's traffic without the identifying header their brief calls
	// mandatory is how a research run gets read by a SOC as an attack.
	engagement, err := ResolveEngagementConfig(scopeTargetID)
	if err != nil {
		finishFlowDetectionRun(runID, sessionID, flowRunError, "",
			"this target's engagement config could not be re-read, so nothing was sent: "+err.Error(),
			0, 0, 0)
		return
	}
	// The programme's header, vetted by HeaderMap: it refuses the credential-bearing names even if
	// the stored row carries one, because ScanRequest.Headers is applied last and would otherwise
	// walk straight through the no-credentials rail this scanner is built on.
	engagementHeaders := engagement.HeaderMap()

	// send_cookies is NOT consulted, deliberately, and this comment is the reason it stays that way.
	// The jar is nil and the config has no path to change that: an unauthenticated request cannot act
	// as anybody, and a per-target flag must not be able to re-enable a rail the transport does not
	// have. See ResolvedEngagementConfig.SendCookies.
	client := NewScanClient(budget, time.Duration(plan.Config.TimeoutS)*time.Second,
		engagement.EffectiveUserAgent,
		nil /* NO COOKIE JAR: an unauthenticated request cannot act as anybody */).
		WithScope(scope)

	// Re-read rather than reuse the plan's, so a rule the operator added between pressing dry-run and
	// pressing run is honoured. A failure here stops the run before a single request: the alternative
	// is running with a list we could not read.
	rules, err := LoadFlowExclusions(scopeTargetID)
	if err != nil {
		finishFlowDetectionRun(runID, sessionID, flowRunError, "", "the exclusion list could not be re-read: "+err.Error(), 0, 0, 0)
		return
	}
	denied, err := ExcludedScopeHosts(scopeTargetID)
	if err != nil {
		finishFlowDetectionRun(runID, sessionID, flowRunError, "", "the excluded-host list could not be re-read: "+err.Error(), 0, 0, 0)
		return
	}

	// Read once, not once per capture. is_direct is the same comparison for every row this run writes,
	// and doing it inside the write would be one extra query per request sent.
	targetHost := scopeTargetHost(scopeTargetID)

	sent, errors, redirects := 0, 0, 0
	lastError := ""
	cancelled := false
	interval := time.Duration(float64(time.Second) / plan.RPS)

	// THE SUB-0.5-RPS GAP, AND WHY IT IS PAID FOR HERE.
	//
	// HostBudget.Acquire clamps any rps below pacingMinRPS (0.5) UP to 0.5, so a programme that caps
	// at 20 requests per minute - 0.33 rps, which several briefs do - would be paced at 0.5 rps by the
	// budget and the run would exceed the cap while every number on screen said otherwise. The clamp
	// is right for the budget's own purposes and wrong as the last word on a rate the operator was
	// told is a hard limit.
	//
	// So the deficit between what the config asked for and the fastest the budget will go is slept
	// off here, before the budget is even consulted. Zero for every rps at or above 0.5, which is
	// every default.
	pacingFloor := time.Duration(float64(time.Second) / math.Max(plan.RPS, pacingMinRPS))
	pacingDeficit := interval - pacingFloor
	if pacingDeficit < 0 {
		pacingDeficit = 0
	}

	for i, target := range plan.Targets {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		if i%flowDetectCancelPollEvery == 0 && flowDetectionRunCancelRequested(runID) {
			cancelled = true
			break
		}
		if reason := budget.Aborted(); reason != "" {
			finishFlowDetectionRun(runID, sessionID, flowRunAborted, reason,
				lastError, sent, errors, redirects)
			log.Printf("[FLOW-DETECT] Run %s aborted after %d requests: %s", runID, sent, reason)
			return
		}
		if sent >= plan.Config.MaxRequests {
			break
		}

		hopsUsed, hopErrors, hopLast := runFlowDetectionChain(
			ctx, client, budget, rules, denied, scope,
			scopeTargetID, sessionID, targetHost, target, plan.Config, engagementHeaders,
			plan.Config.MaxRequests-sent, interval, pacingDeficit)
		sent += hopsUsed
		errors += hopErrors
		if hopsUsed > 1 {
			redirects += hopsUsed - 1
		}
		if hopLast != "" {
			lastError = hopLast
		}

		updateFlowDetectionProgress(runID, sent, errors, redirects, lastError)
	}

	status := flowRunCompleted
	abortReason := ""
	if cancelled {
		status = flowRunCancelled
	}
	if reason := budget.Aborted(); reason != "" {
		status = flowRunAborted
		abortReason = reason
	}
	finishFlowDetectionRun(runID, sessionID, status, abortReason, lastError, sent, errors, redirects)
	log.Printf("[FLOW-DETECT] Run %s %s: %d requests sent, %d errors, %d redirect hops",
		runID, status, sent, errors, redirects)
}

// runFlowDetectionChain sends one endpoint and follows its redirects, recording every hop.
//
// The redirect destination is re-checked against the denied-host list, the scope boundary AND the
// exclusion rules before it is followed. That is the check most likely to be forgotten and the one
// most likely to matter: a 302 is exactly how an application would hand this scanner the URL of the
// endpoint the operator excluded.
//
// Returns how many requests it actually sent, how many failed, and the last error string.
func runFlowDetectionChain(
	ctx context.Context, client *ScanClient, budget *HostBudget,
	rules []FlowExclusion, denied map[string]bool, scope *ScanScope,
	scopeTargetID, sessionID, targetHost string, target FlowDetectionTarget,
	cfg FlowDetectionConfig, engagementHeaders map[string]string,
	remaining int, interval, pacingDeficit time.Duration,
) (sent int, failed int, lastError string) {

	current := target.URL
	// The verb and body for THIS hop. They change across a redirect, which is the whole reason they
	// are not read off `target` inside the loop - see the 303 handling below.
	method := target.Method
	body := target.Body
	contentType := target.ContentType

	for hop := 0; hop <= cfg.MaxRedirects; hop++ {
		if ctx.Err() != nil || sent >= remaining {
			return sent, failed, lastError
		}

		// Jitter on top of HostBudget's fixed interval, plus whatever the budget's own floor cannot
		// slow down to. HostBudget gives the rate ceiling; this stops the run being a metronome and
		// makes a sub-0.5-rps programme cap real. Redirect hops are paced too: a chain of five is five
		// requests at the target and the cap counts requests, not endpoints.
		flowDetectionJitter(ctx, interval, pacingDeficit)

		// The programme's identifying header, and nothing else beyond the body's Content-Type.
		// HeaderMap has already refused the credential-bearing names, so there is no path from this
		// map to a request that acts as a logged-in user. Copied rather than mutated: engagementHeaders
		// is shared across every request in the run, and writing a per-request Content-Type into it
		// would leak that header onto every subsequent endpoint.
		headers := engagementHeaders
		if body != "" && contentType != "" {
			headers = make(map[string]string, len(engagementHeaders)+1)
			for k, v := range engagementHeaders {
				headers[k] = v
			}
			headers["Content-Type"] = contentType
		}

		started := time.Now().UTC()
		resp := client.Do(ctx, ScanRequest{
			URL:      current,
			Method:   method,
			Body:     body,
			Headers:  headers,
			ReadBody: false, // routing and redirects are the observation; bodies are not needed
		})
		sent++

		errText := ""
		if resp.Err != nil {
			errText = resp.Err.Error()
			lastError = errText
			failed++
		}

		next := ""
		chain := []FlowRedirectHop{}
		if resp.IsRedirect() && cfg.MaxRedirects > 0 && hop < cfg.MaxRedirects {
			if resolved := resolveFlowRedirect(current, resp.Location); resolved != "" {
				if reason := flowRedirectRefusal(rules, denied, scope, resolved); reason != "" {
					// Recorded, not silently dropped. "This 302 points at something you excluded" is a
					// finding in itself and the operator should see it on the capture.
					errText = strings.TrimSpace(errText + " redirect not followed: " + reason)
					lastError = errText
				} else {
					next = resolved
					// The hop is written onto the capture that PRODUCED it, in the shape the passive
					// segmenter already reads (from/location/statusCode). That is what makes the
					// destination continue this flow instead of rooting a new one, and what makes
					// deriveFlowLinks draw a redirect edge between the two rows.
					chain = append(chain, FlowRedirectHop{
						From: current, Location: resolved, StatusCode: resp.Status,
					})
					// RFC 9110's redirect rules, which only start mattering now that a body is real.
					//
					// 301, 302 and 303 turn the next hop into a GET with no body. Every browser and
					// curl does this, and a scanner that instead re-POSTed the recorded body to the
					// destination would submit it TWICE - once at the endpoint and once at whatever it
					// redirected to. 307 and 308 exist precisely to preserve the method and body, so
					// they keep both.
					switch resp.Status {
					case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther:
						method, body, contentType = http.MethodGet, "", ""
					}
				}
			}
		}

		// `method` and `body`, not target's: after a 303 this hop was a GET with no body, and
		// recording it as the POST that started the chain would put a body in the capture table that
		// never went on the wire.
		writeFlowDetectionCapture(scopeTargetID, sessionID, targetHost, current, method, body,
			contentType, resp, chain, errText, started, hop == 0)

		if next == "" {
			return sent, failed, lastError
		}
		current = next
	}
	return sent, failed, lastError
}

// flowRedirectRefusal returns why a redirect destination must not be followed, or "".
func flowRedirectRefusal(rules []FlowExclusion, denied map[string]bool, scope *ScanScope, dest string) string {
	parsed, err := url.Parse(dest)
	if err != nil || parsed.Hostname() == "" {
		return "the destination is not a usable URL"
	}
	host := parsed.Hostname()
	if IsDeniedFlowHost(denied, host) {
		return host + " is marked out of scope for this target"
	}
	if !scope.Allows(host) {
		return host + " is outside this target's scope boundary"
	}
	if d := FirstFlowExclusionMatch(rules, dest); d.Excluded {
		return "matched the exclusion " + d.Pattern + " (" + d.Reason + ")"
	}
	return ""
}

// resolveFlowRedirect turns a Location header into an absolute http(s) URL, or "" if it cannot be
// one. Relative locations are the common case and resolving them against the request URL is the
// only correct reading of RFC 9110.
func resolveFlowRedirect(from, location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	base, err := url.Parse(from)
	if err != nil {
		return ""
	}
	ref, err := url.Parse(location)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(ref)
	if abs == nil {
		return ""
	}
	scheme := strings.ToLower(abs.Scheme)
	if scheme != "http" && scheme != "https" || abs.Hostname() == "" {
		return ""
	}
	abs.Scheme = scheme
	abs.User = nil
	abs.Fragment = ""
	abs.RawFragment = ""
	return abs.String()
}

// flowDetectionJitter waits out two things before a request.
//
// deficit is the part of the configured pacing interval that HostBudget will not honour, because it
// clamps any rps below pacingMinRPS up to that floor. It is zero at every default and non-zero only
// when a programme's cap is slower than one request every two seconds - which several bug bounty
// briefs are. Paid first and in full: it is a rate limit somebody promised a company.
//
// The jitter on top is up to flowDetectJitterFraction of the interval. HostBudget paces on a fixed
// interval, which is a machine-shaped traffic pattern; the noise costs nothing and stops the run
// looking like exactly what it is to anything watching.
func flowDetectionJitter(ctx context.Context, interval, deficit time.Duration) {
	wait := time.Duration(0)
	if deficit > 0 {
		wait = deficit
	}
	if interval > 0 {
		if span := time.Duration(float64(interval) * flowDetectJitterFraction); span > 0 {
			wait += time.Duration(rand.Int63n(int64(span) + 1))
		}
	}
	if wait <= 0 {
		return
	}
	select {
	case <-time.After(wait):
	case <-ctx.Done():
	}
}

// ---------------------------------------------------------------------------
// Writing the results as captures
// ---------------------------------------------------------------------------

// writeFlowDetectionCapture stores one active request as a manual_crawl_captures row.
//
// resource_type is 'document' so the existing segmenter treats each endpoint as a navigation and
// roots a flow on it, and so redirect destinations continue that flow through the rule
// segmentCaptureFlows already has for exactly this shape.
//
// post_data is the body that was ACTUALLY SENT. Storing an empty string while sending a body would
// make the repeater rebuild a different request from this row than the one that produced the
// response sitting next to it.
func writeFlowDetectionCapture(
	scopeTargetID, sessionID, targetHost, requestURL, method, body, contentType string,
	resp ScanResponse, chain []FlowRedirectHop, errText string,
	at time.Time, isRoot bool,
) {
	responseHeaders := map[string]string{}
	for k := range resp.Header {
		responseHeaders[k] = resp.Header.Get(k)
	}
	responseHeadersJSON, _ := json.Marshal(responseHeaders)

	// The request headers as they were actually sent, so the repeater can reproduce this exact
	// request. There are no credentials in here by construction.
	sentHeaders := map[string]string{
		"User-Agent":        "ars0n-framework/2.0 (+authorized-testing)",
		"Accept-Encoding":   "identity",
		"X-Ars0n-Framework": "endpoint-workflow",
	}
	if body != "" && contentType != "" {
		sentHeaders["Content-Type"] = contentType
	}
	requestHeadersJSON, _ := json.Marshal(sentHeaders)

	chainJSON, _ := json.Marshal(chain)
	if len(chain) == 0 {
		chainJSON = []byte("[]")
	}

	host := ""
	if parsed, err := url.Parse(requestURL); err == nil {
		host = strings.ToLower(parsed.Hostname())
	}
	isDirect := targetHost != "" && strings.EqualFold(host, targetHost)

	resourceType := "document"
	initiator := "active_detection"
	if !isRoot {
		initiator = "redirect"
	}

	_, err := dbPool.Exec(context.Background(), `
		INSERT INTO manual_crawl_captures
		  (id, session_id, scope_target_id, url, endpoint, method, status_code, headers,
		   response_headers, post_data, response_body, get_params, post_params, body_type,
		   tab_id, timestamp, mime_type, sources, graphql_operation, resource_type, initiator,
		   redirect_chain, error, duration_ms, request_body_truncated, response_body_truncated,
		   is_direct, capture_source)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'', '{}'::jsonb,'{}'::jsonb,$11,
		        NULL,$12,$13,$14,'',$15,$16,$17,$18,$19,FALSE,FALSE,$20,'active')`,
		uuid.New().String(), sessionID, scopeTargetID,
		sanitizeForPostgres(requestURL), sanitizeForPostgres(requestURL),
		strings.ToUpper(method), resp.Status, requestHeadersJSON, responseHeadersJSON,
		// post_data and body_type: the request body actually sent, and how it was labelled.
		sanitizeForPostgres(body), sanitizeForPostgres(contentType),
		// mime_type is the RESPONSE content type. Not the same field as body_type above.
		at, sanitizeForPostgres(resp.ContentType), []string{"active_detection"},
		resourceType, initiator, chainJSON, sanitizeForPostgres(errText),
		int(resp.ElapsedMS), isDirect)
	if err != nil {
		log.Printf("[FLOW-DETECT] Failed to store capture for %s: %v", requestURL, err)
	}
}

// ---------------------------------------------------------------------------
// Run bookkeeping
// ---------------------------------------------------------------------------

func updateFlowDetectionProgress(runID string, sent, errors, redirects int, lastError string) {
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE flow_detection_runs
		   SET sent_count = $2, error_count = $3, redirect_count = $4, last_error = $5, updated_at = NOW()
		 WHERE id = $1`, runID, sent, errors, redirects, lastError); err != nil {
		log.Printf("[FLOW-DETECT] Failed to update progress for %s: %v", runID, err)
	}
}

func finishFlowDetectionRun(runID, sessionID, status, abortReason, lastError string, sent, errors, redirects int) {
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE flow_detection_runs
		   SET status = $2, abort_reason = NULLIF($3,''), last_error = $4,
		       sent_count = $5, error_count = $6, redirect_count = $7,
		       completed_at = NOW(), updated_at = NOW()
		 WHERE id = $1`, runID, status, abortReason, lastError, sent, errors, redirects); err != nil {
		log.Printf("[FLOW-DETECT] Failed to finish run %s: %v", runID, err)
	}
	// The session is closed whatever the outcome, including a cancel, so the captures it wrote are a
	// finished recording rather than one that looks like it is still going.
	if _, err := dbPool.Exec(context.Background(), `
		UPDATE manual_crawl_sessions
		   SET status = 'completed', ended_at = NOW(),
		       request_count = (SELECT count(*) FROM manual_crawl_captures WHERE session_id = $1),
		       endpoint_count = (SELECT count(DISTINCT url) FROM manual_crawl_captures WHERE session_id = $1)
		 WHERE id = $1`, sessionID); err != nil {
		log.Printf("[FLOW-DETECT] Failed to close session %s: %v", sessionID, err)
	}
}

// flowDetectionRunCancelRequested re-reads the run's own row. This is the path that works when the
// cancel arrived at a different process, or after a restart put the in-memory latch out of reach.
func flowDetectionRunCancelRequested(runID string) bool {
	var status string
	if err := dbPool.QueryRow(context.Background(),
		`SELECT status FROM flow_detection_runs WHERE id = $1`, runID).Scan(&status); err != nil {
		return false
	}
	return status == "cancelling" || status == flowRunCancelled
}

// ---------------------------------------------------------------------------
// GET /flow-detection/{scope_target_id}/status
// ---------------------------------------------------------------------------

func GetFlowDetectionStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var s FlowDetectionStatus
	var abortReason, lastError *string
	var cfgJSON []byte
	err := dbPool.QueryRow(context.Background(), `
		SELECT id, session_id, status, planned_count, sent_count, error_count,
		       excluded_count, redirect_count, abort_reason, last_error, started_at, completed_at, config
		  FROM flow_detection_runs
		 WHERE scope_target_id = $1
		 ORDER BY created_at DESC
		 LIMIT 1`, scopeTargetID).Scan(&s.RunID, &s.SessionID, &s.Status, &s.Planned, &s.Sent,
		&s.Errors, &s.Excluded, &s.Redirects, &abortReason, &lastError, &s.StartedAt, &s.CompletedAt, &cfgJSON)
	if err != nil {
		// No run yet is a normal state, not an error. The UI opens on this.
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "idle"})
		return
	}
	if abortReason != nil {
		s.AbortReason = *abortReason
	}
	if lastError != nil {
		s.LastError = *lastError
	}
	s.Aborted = s.Status == flowRunAborted
	if len(cfgJSON) > 0 {
		s.Config = json.RawMessage(cfgJSON)
	}

	json.NewEncoder(w).Encode(s)
}

// ---------------------------------------------------------------------------
// POST /flow-detection/{scope_target_id}/cancel
// ---------------------------------------------------------------------------

func CancelFlowDetection(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		writeJSONError(w, http.StatusBadRequest, "scope_target_required", "scope_target_id must be a UUID")
		return
	}

	var runID string
	if err := dbPool.QueryRow(context.Background(), `
		SELECT id FROM flow_detection_runs
		 WHERE scope_target_id = $1 AND status IN ('pending','running','cancelling')
		 ORDER BY created_at DESC LIMIT 1`, scopeTargetID).Scan(&runID); err != nil {
		writeJSONError(w, http.StatusNotFound, "not_running", "No active flow detection run to cancel")
		return
	}

	// The DB flag goes first. If this process dies between the two, the runner's poll still sees the
	// cancel; doing it the other way round would leave a stopped run marked running forever.
	if _, err := dbPool.Exec(context.Background(),
		`UPDATE flow_detection_runs SET status = 'cancelling', updated_at = NOW() WHERE id = $1`,
		runID); err != nil {
		log.Printf("[FLOW-DETECT] Failed to flag run %s as cancelling: %v", runID, err)
	}
	inMemory := cancelFlowRunInMemory(runID)

	log.Printf("[FLOW-DETECT] Cancel requested for run %s (in-memory latch found: %v)", runID, inMemory)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id": runID,
		"status": "cancelling",
		"note": "The run stops after the request in flight. Everything it already reached is kept, " +
			"so the flows it found are still there.",
	})
}

// ---------------------------------------------------------------------------
// passive / active / both
// ---------------------------------------------------------------------------

const (
	FlowSourcePassive = "passive"
	FlowSourceActive  = "active"
	FlowSourceBoth    = "both"
)

// FlowDetectionInput describes one flow for the purposes of labelling it. Kept separate from
// FlowSummary so the derivation is a pure function over data, testable without a database and
// without the segmenter.
type FlowDetectionInput struct {
	ID string
	// One entry per capture: 'passive' or 'active'. Anything else is read as passive, because a row
	// written before capture_source existed is a row the operator's browser produced.
	CaptureSources []string
	// One entry per capture: the normalised (method, host, path) tuple.
	Tuples []string
}

// FlowCaptureSourceKind classifies a flow from its captures alone.
func FlowCaptureSourceKind(sources []string) string {
	hasActive, hasPassive := false, false
	for _, s := range sources {
		if strings.EqualFold(strings.TrimSpace(s), FlowSourceActive) {
			hasActive = true
		} else {
			hasPassive = true
		}
	}
	switch {
	case hasActive && hasPassive:
		return FlowSourceBoth
	case hasActive:
		return FlowSourceActive
	default:
		// No captures at all reads as passive. A flow with nothing in it cannot have been produced by
		// this scanner, which never writes an empty one.
		return FlowSourcePassive
	}
}

// NormalizeFlowTuple is the identity a flow is compared on: method, host, path. Query strings and
// timing are deliberately excluded. The scanner strips query strings before it sends anything, so
// including them would guarantee that an active flow NEVER matches the passive flow it reproduces,
// which is the exact case this comparison exists to catch.
func NormalizeFlowTuple(method, rawURL string) string {
	m := strings.ToUpper(strings.TrimSpace(method))
	if m == "" {
		m = http.MethodGet
	}
	host, path := "", "/"
	if parsed, err := url.Parse(strings.TrimSpace(rawURL)); err == nil {
		host = strings.ToLower(parsed.Hostname())
		if parsed.Path != "" {
			path = parsed.Path
		}
	}
	// A trailing slash is the same endpoint. /account and /account/ arriving as two different flows
	// would report both as single-source when they are one route.
	if len(path) > 1 {
		path = strings.TrimSuffix(path, "/")
	}
	return m + " " + host + " " + path
}

// flowTupleSignature is the set of tuples a flow contains, order-independent and duplicate-free.
// A SET, because a passive flow records the same XHR three times and the active reproduction records
// it once; comparing lists would call those different flows.
func flowTupleSignature(tuples []string) string {
	seen := map[string]bool{}
	unique := make([]string, 0, len(tuples))
	for _, t := range tuples {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		unique = append(unique, t)
	}
	sort.Strings(unique)
	return strings.Join(unique, "\n")
}

// DeriveFlowDetectionSources labels every flow passive, active or both.
//
// TWO WAYS TO BE 'both', and the second is the one the operator asked for:
//
//  1. The flow itself contains a mix of passive and active captures. That happens when the scanner
//     ran during a recording session, or when a redirect destination was already in the corpus.
//  2. The flow's (method, host, path) SET is identical to some other flow's, and between them the two
//     flows have both sources. A route found by the crawl AND rediscovered by the scanner is a route
//     found by both, and labelling either of them single-source would hide that agreement - which is
//     the most useful signal here, because agreement is what tells the operator the active run
//     reproduced something real rather than inventing a path.
//
// The promotion is SYMMETRIC. Both flows say 'both', because both of them were found by both.
func DeriveFlowDetectionSources(flows []FlowDetectionInput) map[string]string {
	kinds := make(map[string]string, len(flows))
	signatures := make(map[string]string, len(flows))
	sigHasPassive := map[string]bool{}
	sigHasActive := map[string]bool{}

	for _, f := range flows {
		kind := FlowCaptureSourceKind(f.CaptureSources)
		sig := flowTupleSignature(f.Tuples)
		kinds[f.ID] = kind
		signatures[f.ID] = sig
		if sig == "" {
			continue
		}
		switch kind {
		case FlowSourceActive:
			sigHasActive[sig] = true
		case FlowSourcePassive:
			sigHasPassive[sig] = true
		case FlowSourceBoth:
			sigHasActive[sig] = true
			sigHasPassive[sig] = true
		}
	}

	out := make(map[string]string, len(flows))
	for _, f := range flows {
		kind := kinds[f.ID]
		if kind != FlowSourceBoth {
			sig := signatures[f.ID]
			if sig != "" && sigHasActive[sig] && sigHasPassive[sig] {
				kind = FlowSourceBoth
			}
		}
		out[f.ID] = kind
	}
	return out
}

// FlowDetectionSources returns detection_source keyed by flow id for every flow of one scope target.
//
// This is the function replayRequestFlows.go calls. It lives here rather than there because that file
// is owned by the passive detector and adding a source concept to it would mean the passive detector
// knowing about the active one. It re-uses segmentCaptureFlows so the ids it returns are byte-for-byte
// the ids /flows returns; deriving the segmentation twice with two implementations would be two
// segmentations that eventually disagree.
func FlowDetectionSources(scopeTargetID string) map[string]string {
	captures, err := queryFlowCaptures(`
		SELECT id, session_id, tab_id, COALESCE(method,''), COALESCE(url,''),
		       COALESCE(status_code,0), COALESCE(resource_type,''), COALESCE(initiator,''),
		       COALESCE(mime_type,''), timestamp, COALESCE(duration_ms,0),
		       COALESCE(octet_length(response_body),0),
		       (COALESCE(post_data,'') <> '') AS has_body,
		       COALESCE(redirect_chain,'[]'::jsonb),
		       TRUE AS matched
		  FROM manual_crawl_captures
		 WHERE scope_target_id = $1
		 ORDER BY timestamp ASC
		 LIMIT 50000`, []interface{}{scopeTargetID})
	if err != nil {
		log.Printf("[FLOW-DETECT] Could not read captures for detection source: %v", err)
		return map[string]string{}
	}

	// capture_source is fetched separately rather than added to the projection above, because that
	// projection belongs to replayRequestFlows.go and its FlowCapture struct has no field for it.
	sources := map[string]string{}
	rows, err := dbPool.Query(context.Background(),
		`SELECT id, COALESCE(capture_source,'passive') FROM manual_crawl_captures WHERE scope_target_id = $1`,
		scopeTargetID)
	if err == nil {
		for rows.Next() {
			var id, src string
			if rows.Scan(&id, &src) == nil {
				sources[id] = src
			}
		}
		rows.Close()
	}

	inputs := []FlowDetectionInput{}
	for _, flow := range segmentCaptureFlows(captures) {
		if len(flow.Captures) == 0 {
			continue
		}
		root := flow.Captures[0]
		in := FlowDetectionInput{ID: EncodeFlowID(root.SessionID, root.TabID, root.ID)}
		for _, c := range flow.Captures {
			src := sources[c.ID]
			if src == "" {
				src = FlowSourcePassive
			}
			in.CaptureSources = append(in.CaptureSources, src)
			in.Tuples = append(in.Tuples, NormalizeFlowTuple(c.Method, c.URL))
		}
		inputs = append(inputs, in)
	}
	return DeriveFlowDetectionSources(inputs)
}
