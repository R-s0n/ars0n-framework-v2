package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// Validate: does each consolidated endpoint address a distinct resource that exists right now, or
// is the response this target's catch-all for things that do not?
//
// It labels. It never merges rows and never deletes them. Deduplication belongs to Consolidate,
// where it is deterministic and inspectable; a scan that quietly removes rows because two pages
// looked alike is how a real admin panel disappears because it shares a template with a dashboard.
//
// The asymmetry that governs every rule below: ruling something IN is cheap to get wrong, ruling
// something OUT is expensive. A false positive costs the hunter five minutes. A false negative
// costs them the finding, silently, and they never learn it happened. So a rule-out requires a
// measured comparison against a control taken from the same directory in the same epoch, and
// everything short of that is "unverified", which is reported and kept.
//
// 401 and 403 are therefore valid, not ruled out. Being behind authentication or a WAF is positive
// evidence the endpoint exists, and those are the endpoints most worth testing.

const (
	validationStatusValid      = "valid"
	validationStatusRuledOut   = "ruled_out"
	validationStatusUnverified = "unverified"
	validationStatusSkipped    = "skipped"
)

// Whole path segments that make a GET destructive despite GET being nominally safe. `GET /logout`
// is doubly damaging: it destroys the session and turns every subsequent verdict into a login wall.
var destructiveSegment = regexp.MustCompile(`(?i)^(logout|signout|sign-out|signoff|revoke|delete|destroy|remove|reset|purge|truncate|deactivate|cancel|disable|drop|wipe|terminate|unsubscribe|approve|publish|send|invalidate|expire)$`)

type ValidationVerdict struct {
	EndpointID   string
	EndpointKey  string
	URL          string
	Method       string
	Status       string
	ReasonCode   string
	Reason       string
	Confidence   string
	Testable     *bool
	RuleFired    string
	Falsifier    string
	HTTPStatus   int
	ResponseSize int
	ResponseMS   int64
	ContentType  string
	Location     string
	Title        string
	StructHash   string
	Simhash      string
	ControlURL   string
	Flags        []string
	Evidence     map[string]interface{}
}

type validationRun struct {
	scanID        string
	scopeTargetID string
	ctx           context.Context

	probe  ProbeContext
	client *ScanClient
	budget *HostBudget
	auth   *ScopedAuthContext
	scope  *ScanScope

	baseScheme string
	baseHost   string
	baseURL    string

	// References measured in phase 0 under Validate's own recipe, never inherited as bytes from
	// the probe. Comparing a cache-busted response against the probe's non-busted median is how
	// everything ends up looking real.
	notFound   ResponseFingerprint
	notFoundOK bool
	login      ResponseFingerprint
	loginOK    bool
	baseline   ResponseFingerprint
	isSPAShell bool
	baselineMS int64
	// Tri-state on purpose. nil means the question could not be answered, which is a different
	// thing from answering no, and reporting it as no told operators their session was dead on
	// every target whose root is a static shell.
	credsHonoured *bool
	credsProbeURL string

	// One not-found control per directory, because a catch-all is usually route-scoped: /api/*
	// returns a JSON 404 while /* returns the SPA shell, and one global control describes neither.
	controls    map[string]ResponseFingerprint
	controlURLs map[string]string
	controlBad  map[string]bool

	requests int
	// Endpoints that wanted a directory control after the family cap was reached. They fall back to
	// the global not-found reference, which is weaker, and the operator has to be told.
	controlCapHit int
	assumptions   []string
	counts        map[string]int
	// Endpoints this run actually measured, which is not the same as the number of rows it wrote.
	// An aborted run still writes a verdict for everything it never reached, so summing counts
	// always equals the total and reports "2282/2282 processed" on a run that judged 44.
	judged int
}

const (
	// The per-directory not-found oracle is the primary rule-out mechanism, so running out of it
	// quietly degrades every verdict after the cap. A live run hit exactly 300 and said nothing:
	// every directory past that fell back to the global reference, which on a client-routed app is
	// the shell, so those endpoints could only ever come back ambiguous.
	//
	// Raised, and hitting it is now reported as an assumption rather than absorbed.
	maxControlFamilies = 1500
	validationTokenPfx = "ars0nprobe"
)

// EndpointScanPreflight is every refusal that has to happen before a single request is sent.
//
// It lives here rather than inside the handler because the combined Investigate run has to make the
// identical decisions, and a second copy of them would drift. A run that starts when it should have
// refused cannot be undone by anything downstream: the traffic has already gone out.
type EndpointScanPreflight struct {
	Probe ProbeContext
	Total int

	// Set when the run must not start. HTTPStatus is what the caller should return, Reason is what
	// the operator should read, and Acknowledgeable marks the refusals a deliberate second click can
	// override.
	HTTPStatus      int
	Reason          string
	Acknowledgeable bool
}

func (p EndpointScanPreflight) Refused() bool { return p.HTTPStatus != 0 }

// Write emits the refusal. Acknowledgeable refusals go out as JSON so the client can offer to
// proceed anyway; the rest are plain text, because there is nothing to decide.
func (p EndpointScanPreflight) Write(w http.ResponseWriter) {
	if p.Acknowledgeable {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(p.HTTPStatus)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"refused": true, "reason": p.Reason, "acknowledgeable": true,
		})
		return
	}
	http.Error(w, p.Reason, p.HTTPStatus)
}

// RunEndpointScanPreflight decides whether an endpoint scan may start against this target.
func RunEndpointScanPreflight(scopeTargetID string, acknowledge bool) EndpointScanPreflight {
	out := EndpointScanPreflight{}

	// Refuse rather than compete. The rate budget only governs requests this process makes; ffuf,
	// katana and gospider run in their own containers and ignore it entirely, so the only honest
	// way to respect a measured rate is not to run at the same time as them.
	if running := RequestIssuingScansRunning(scopeTargetID); len(running) > 0 {
		out.HTTPStatus = http.StatusConflict
		out.Reason = "Cannot run while these scans are sending traffic at the target: " +
			strings.Join(running, ", ") + ". Wait for them to finish, or stop them."
		return out
	}

	out.Probe = LoadProbeContext(scopeTargetID)
	if out.Probe.Refuse != "" && !acknowledge {
		out.HTTPStatus = http.StatusConflict
		out.Reason = out.Probe.Refuse
		out.Acknowledgeable = true
		return out
	}

	_ = dbPool.QueryRow(context.Background(), `
		SELECT count(*) FROM consolidated_url_endpoints
		WHERE scope_target_id = $1 AND deleted_at IS NULL`, scopeTargetID).Scan(&out.Total)
	if out.Total == 0 {
		out.HTTPStatus = http.StatusBadRequest
		out.Reason = "No consolidated endpoints to work with. Run Consolidate first."
		return out
	}
	return out
}

// StartValidationScan inserts the scan row Validate's executor expects to find.
func StartValidationScan(scanID, scopeTargetID string, probe ProbeContext, total int) error {
	probeJSON, _ := json.Marshal(probe)
	_, err := dbPool.Exec(context.Background(), `
		INSERT INTO endpoint_validation_scans (scan_id, scope_target_id, status, total_endpoints, probe_inputs)
		VALUES ($1, $2, 'pending', $3, $4)`, scanID, scopeTargetID, total, probeJSON)
	return err
}

// RunEndpointValidation handles POST /endpoint-validation/{scope_target_id}.
//
// Validate on its own is kept as an API route, but the client drives the combined run in
// endpointScanRun.go instead, so an operator cannot investigate a target before validating it.
func RunEndpointValidation(w http.ResponseWriter, r *http.Request) {
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	var payload struct {
		Acknowledge bool `json:"acknowledge"`
	}
	_ = json.NewDecoder(r.Body).Decode(&payload)

	pre := RunEndpointScanPreflight(scopeTargetID, payload.Acknowledge)
	if pre.Refused() {
		pre.Write(w)
		return
	}

	scanID := uuid.New().String()
	if err := StartValidationScan(scanID, scopeTargetID, pre.Probe, pre.Total); err != nil {
		log.Printf("[VALIDATE] Failed to create scan row: %v", err)
		http.Error(w, "Failed to create validation scan", http.StatusInternalServerError)
		return
	}

	go ExecuteEndpointValidation(scanID, scopeTargetID, pre.Probe)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{"scan_id": scanID, "total_endpoints": pre.Total})
}

func ExecuteEndpointValidation(scanID, scopeTargetID string, probe ProbeContext) {
	started := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[VALIDATE] panic in %s: %v", scanID, rec)
			finishValidation(scanID, "error", fmt.Sprintf("panic: %v", rec), started, nil)
		}
	}()

	// Two hours is the ceiling. A run that needs longer than that is being asked to validate more
	// than an operator can act on, and the dry run says so before any traffic is sent.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()

	updateValidationStatus(scanID, "running", 0, 0)

	scheme, host, base := ScopeTargetBase(scopeTargetID)
	if host == "" {
		finishValidation(scanID, "error", "Could not determine the scope target's host", started, nil)
		return
	}

	run := &validationRun{
		scanID:        scanID,
		scopeTargetID: scopeTargetID,
		ctx:           ctx,
		probe:         probe,
		budget:        NewHostBudget(),
		auth:          LoadScopedAuthContext(scopeTargetID),
		scope:         LoadScanScope(scopeTargetID),
		baseScheme:    scheme,
		baseHost:      host,
		baseURL:       base,
		controls:      map[string]ResponseFingerprint{},
		controlURLs:   map[string]string{},
		controlBad:    map[string]bool{},
		assumptions:   append([]string{}, probe.Assumptions...),
		counts:        map[string]int{},
	}

	// The probe may have found the configured URL is not where the application actually lives.
	// Validating the pre-redirect host measures a site the operator is not testing.
	if probe.CanonicalBaseURL != "" && !probe.ConfiguredCanonical {
		if u, err := url.Parse(probe.CanonicalBaseURL); err == nil && u.Hostname() != "" {
			run.assumptions = append(run.assumptions, fmt.Sprintf(
				"The probe found %s is not canonical; requests were rewritten to %s.",
				run.baseHost, u.Hostname()))
			run.baseHost = strings.ToLower(u.Hostname())
			run.baseScheme = u.Scheme
			run.baseURL = strings.TrimSuffix(probe.CanonicalBaseURL, "/")
		}
	}

	rps, concurrency := probe.EffectiveRate()
	run.budget.Acquire(run.baseHost, rps, concurrency, "waf_probe")

	var jar http.CookieJar
	if probe.ReuseSession {
		jar, _ = newSimpleCookieJar()
	}
	run.client = NewScanClient(run.budget, 20*time.Second, "", jar).WithScope(run.scope)
	run.assumptions = append(run.assumptions, fmt.Sprintf(
		"Requests were confined to %s. Endpoints on any other host are kept in the list and "+
			"reported as out of scope rather than requested: an engagement for one target does not "+
			"authorise sending traffic to a third party.", run.scope.Describe()))

	if !run.calibrate() {
		finishValidation(scanID, "error",
			"The target did not answer the calibration requests, so nothing measured after that "+
				"would mean anything.", started, run)
		return
	}

	queue, err := run.buildQueue()
	if err != nil {
		finishValidation(scanID, "error", err.Error(), started, run)
		return
	}
	updateValidationStatus(scanID, "running", len(queue), 0)

	status := "success"
	processed := 0
	batch := make([]ValidationVerdict, 0, 50)

	for i := range queue {
		if ctx.Err() != nil {
			status = "partial"
			break
		}
		if reason := run.budget.Aborted(); reason != "" {
			status = "aborted"
			break
		}

		verdict := run.evaluate(queue[i])
		batch = append(batch, verdict)
		run.counts[verdict.Status]++
		processed++

		if len(batch) >= 50 {
			run.commit(batch)
			batch = batch[:0]
		}
		// Progress used to be published only when a batch of 50 flushed, so a run of fewer than 50
		// endpoints sat at 0/12 from start to finish and the button that reports it looked hung.
		// Every ten is frequent enough to move and rare enough not to be a write per endpoint.
		if processed%10 == 0 {
			updateValidationStatus(scanID, "running", len(queue), processed)
		}
	}
	if len(batch) > 0 {
		run.commit(batch)
	}
	run.judged = processed

	// Anything the run never reached is recorded explicitly rather than left looking validated.
	if processed < len(queue) {
		remainder := make([]ValidationVerdict, 0, len(queue)-processed)
		for _, cand := range queue[processed:] {
			remainder = append(remainder, ValidationVerdict{
				EndpointID: cand.id, EndpointKey: cand.key, URL: cand.url, Method: cand.method,
				Status: validationStatusUnverified, ReasonCode: "unverified.budget_exhausted",
				Reason:     "The run stopped before reaching this endpoint.",
				Confidence: "assumed", RuleFired: "not_reached",
				Falsifier: "Re-running validation would measure it.",
			})
			run.counts[validationStatusUnverified]++
		}
		run.commit(remainder)
	}

	if run.controlCapHit > 0 {
		run.assumptions = append(run.assumptions, fmt.Sprintf(
			"The per-directory not-found oracle was capped at %d directories and %d endpoint(s) "+
				"arrived after that. Those were compared against the target's global not-found "+
				"response instead, which is a weaker comparison, so their verdicts are more likely "+
				"to be reported as indistinguishable than to be ruled out.",
			maxControlFamilies, run.controlCapHit))
	}

	if reason := run.budget.Aborted(); reason != "" && status != "partial" {
		status = "aborted"
	}
	finishValidation(scanID, status, "", started, run)
}

// ---------------------------------------------------------------- phase 0

// calibrate measures, under Validate's own recipe, what this target does with the base URL, with
// paths that cannot exist, and with credentials. Roughly a dozen requests.
//
// Validate never inherits the probe's byte measurements directly. The probe measured without cache
// busting and possibly with a different Accept-Encoding; comparing this run's numbers against those
// is the mistake that makes every endpoint look real.
func (r *validationRun) calibrate() bool {
	var latencies []int64
	var baseResp ScanResponse

	for i := 0; i < 3; i++ {
		resp := r.get(r.baseURL+"/", true)
		if resp.Err == nil && resp.Status > 0 {
			baseResp = resp
			latencies = append(latencies, resp.ElapsedMS)
		}
		time.Sleep(400 * time.Millisecond)
	}
	if len(latencies) == 0 {
		return false
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	r.baselineMS = latencies[len(latencies)/2]
	r.budget.SetBaseline(r.baseHost, r.baselineMS)
	r.baseline = BuildFingerprint(baseResp)

	// Four shapes, because a not-found response is frequently route-scoped and extension-scoped.
	var nfFingerprints []ResponseFingerprint
	for _, shape := range []string{"/%s", "/%s/", "/%s.json", "/api/%s"} {
		path := fmt.Sprintf(shape, validationTokenPfx+"-"+randomToken(12))
		resp := r.get(r.baseURL+path, true)
		if resp.Err == nil && resp.Status > 0 {
			nfFingerprints = append(nfFingerprints, BuildFingerprint(resp))
		}
	}
	if len(nfFingerprints) > 0 {
		r.notFound = nfFingerprints[0]
		r.notFoundOK = true
		// The catch-all itself may be the login page. That is the case an operator describes as
		// "it serves the login page for everything and returns 200", and it has to be recognised
		// whether or not this run has credentials: with none, the login body is all there is.
		if looksLikeLoginBody(baseResp.Body) {
			r.login = r.baseline
			r.loginOK = true
		}
		// The SPA shell case: a path that cannot exist returns the same thing as the home page.
		if MatchesReference(nfFingerprints[0], r.baseline) && r.baseline.CTFamily == "html" {
			r.isSPAShell = true
			r.assumptions = append(r.assumptions,
				"Paths that cannot exist return the same HTML shell as the home page, so this "+
					"target routes on the client. Server-side path enumeration cannot distinguish "+
					"anything here: HTML responses are reported as indistinguishable and kept, and "+
					"the JSON and script surface is where the real routes are.")
		}
	}

	// Does a credentialed request differ from an anonymous one? Without this, an empty page is
	// ambiguous: it could be an empty page or an unauthenticated one.
	//
	// Which URL this asks matters more than the comparison does. The base URL cannot answer it on
	// any target whose root is a static shell, a CDN index or a soft 404: it returns the same bytes
	// signed in or out, so a perfectly live session measured as not honoured and the operator was
	// told to go and fix a credential that was never broken. Prefer a URL a previous run already
	// proved refuses anonymous callers, and when only the base URL is available and it is known not
	// to discriminate, say the question is open rather than answering it wrongly.
	probeURL := r.baseURL + "/"
	discriminating := false
	if better := authRequiredProbeURL(r.scopeTargetID); better != "" {
		probeURL = better
		discriminating = true
	} else if better := sessionFlowProbeURL(r.scopeTargetID); better != "" {
		// authRequiredProbeURL reads PRIOR validation results, so on a first run it has nothing to
		// offer and the base URL was all that was left. The session manager already knows a better
		// one: the page the login flow redirects to, which by construction only an authenticated
		// caller sees. Measured on ginandjuice.shop 2026-08-19, where the root differs by 87 bytes
		// signed in versus out: the run reported credentials_honoured=false for a session that had
		// just validated as active, and every authenticated endpoint fell to unverified.login_wall.
		probeURL = better
		discriminating = true
	}
	r.credsProbeURL = probeURL

	if material, _ := r.auth.For(hostOf(probeURL)); material != nil {
		clean := r.getRaw(probeURL, true, nil)
		authed := r.getRaw(probeURL, true, material)
		if clean.Err == nil && authed.Err == nil {
			cleanFP := BuildFingerprint(clean)
			authedFP := BuildFingerprint(authed)
			differs := !MatchesReference(authedFP, cleanFP)

			switch {
			case differs:
				honoured := true
				r.credsHonoured = &honoured
			case discriminating || !r.isSPAShell:
				// Either the probe was known to refuse anonymous callers, or the base URL does vary
				// by path and so is capable of varying by credential. A match here is real evidence.
				notHonoured := false
				r.credsHonoured = &notHonoured
				r.assumptions = append(r.assumptions,
					"Credentialed and anonymous requests to "+probeURL+" returned the same page, "+
						"so the saved session is probably not being honoured. Endpoints behind "+
						"authentication are reported as unverified rather than ruled out.")
			default:
				// Base URL on a target that returns the same shell for everything. The two arms
				// were always going to match, so this measured nothing.
				r.credsHonoured = nil
				r.assumptions = append(r.assumptions,
					"Whether the saved session is honoured could not be established. The only "+
						"available probe was the base URL, which returns the same shell for every "+
						"path on this target and so cannot differ by credential either. Run the "+
						"scan once to record a route that refuses anonymous callers, and the next "+
						"run can test it properly. Credentials were still attached to every request.")
			}

			// An anonymous response that looks like a login page is the login fingerprint.
			if looksLikeLoginBody(clean.Body) {
				r.login = cleanFP
				r.loginOK = true
			}
		}
	} else {
		r.assumptions = append(r.assumptions,
			"No credentials were available for this host, so anything behind authentication is "+
				"reported as unverified rather than ruled out.")
	}

	if !r.loginOK && r.probe.AuthWallVerdict == "login_page" {
		r.assumptions = append(r.assumptions,
			"The probe reported the control path is a login page; login-wall detection falls back "+
				"to body markers.")
	}
	return true
}

// ---------------------------------------------------------------- queue

type validationCandidate struct {
	id           string
	key          string
	url          string
	method       string
	host         string
	path         string
	contentClass string
	sources      []string
	score        int

	// What the manual crawl recorded for this endpoint, carried so a verdict can cite it. The
	// browser issuing a request and receiving a response is direct evidence the route exists, and it
	// is evidence no re-probe can reproduce on a CDN-hosted SPA that answers 200 with the same shell
	// for every path.
	captureCount  int
	crawlStatuses []int
}

// observedInCrawl reports whether the crawl saw a real response for this endpoint, and returns the
// status that carries the evidence.
//
// The negative cases are the point. Each of the following appeared in a single real recording, which
// is why none of them are assumed away:
//   - a recorded 404 or 410, where the application asked for something that genuinely is not there
//   - status 0 or no status, where the request was cancelled or failed in transport, so nothing was
//     observed at all
//   - OPTIONS, where a 204 is the CORS preflight answering and says nothing about the path: servers
//     routinely answer preflight for routes that do not exist
func (c validationCandidate) observedInCrawl() (int, bool) {
	if c.captureCount <= 0 || len(c.crawlStatuses) == 0 {
		return 0, false
	}
	if c.method == http.MethodOptions {
		return 0, false
	}
	best := 0
	for _, s := range c.crawlStatuses {
		if s <= 0 || s == http.StatusNotFound || s == http.StatusGone {
			continue
		}
		// Prefer the most informative observation: a 2xx over a 401, a 401 over a 500.
		if best == 0 || (s < best && s >= 200) {
			best = s
		}
	}
	return best, best > 0
}

// buildQueue snapshots the work at run start and freezes it. A Consolidate midway through would
// otherwise insert rows before a live cursor and leave a silent gap the operator never sees.
func (r *validationRun) buildQueue() ([]validationCandidate, error) {
	rows, err := dbPool.Query(r.ctx, `
		SELECT id, COALESCE(endpoint_key,''), url, COALESCE(method,'GET'), COALESCE(domain,''),
		       COALESCE(canonical_path, path, '/'), COALESCE(content_class,'unknown'),
		       COALESCE(sources, '{}'), COALESCE(capture_count, 0),
		       COALESCE(status_codes, '[]'::jsonb)
		FROM consolidated_url_endpoints
		WHERE scope_target_id = $1 AND deleted_at IS NULL
		ORDER BY is_direct DESC, id`, r.scopeTargetID)
	if err != nil {
		return nil, fmt.Errorf("failed to read consolidated endpoints: %w", err)
	}
	defer rows.Close()

	var out []validationCandidate
	for rows.Next() {
		var c validationCandidate
		var statuses []byte
		if rows.Scan(&c.id, &c.key, &c.url, &c.method, &c.host, &c.path, &c.contentClass,
			&c.sources, &c.captureCount, &statuses) != nil {
			continue
		}
		if len(statuses) > 0 {
			_ = json.Unmarshal(statuses, &c.crawlStatuses)
		}
		if c.key == "" {
			c.key = c.id
		}
		c.score = candidateScore(c)
		out = append(out, c)
	}

	// Value order, not alphabetical. A truncated run should have spent its requests on the
	// endpoints worth measuring, and /api sorted after /assets is how that goes wrong.
	sort.SliceStable(out, func(i, j int) bool { return out[i].score > out[j].score })

	// Freeze it so resume and reporting agree on what the run was asked to do.
	for i, c := range out {
		_, _ = dbPool.Exec(r.ctx, `
			INSERT INTO endpoint_validation_queue (scan_id, endpoint_id, endpoint_key, ordinal, state)
			VALUES ($1, $2, $3, $4, 'queued')
			ON CONFLICT (scan_id, endpoint_key) DO NOTHING`, r.scanID, c.id, c.key, i)
	}
	return out, nil
}

var juicyTokens = []string{"admin", "internal", "debug", "test", "staging", "old", "backup",
	"legacy", "config", "export", "impersonate", "sudo", "root", "token", "secret",
	"graphql", "swagger", "openapi", "actuator", "health", "metrics", "env", "git",
	"api", "v1", "v2", "auth", "login", "upload", "download", "user", "account"}

func candidateScore(c validationCandidate) int {
	score := 0
	lower := strings.ToLower(c.path)
	for _, tok := range juicyTokens {
		if strings.Contains(lower, tok) {
			score += 8
		}
	}
	switch c.contentClass {
	case "api":
		score += 40
	case "page":
		score += 15
	case "script":
		score += 5
	case "static":
		score -= 30
	}
	for _, s := range c.sources {
		switch s {
		case "manual_crawl":
			// Someone navigated to it in a browser. That is the strongest possible evidence.
			score += 50
		case "linkfinder":
			score += 20
		case "katana", "gospider":
			score += 10
		}
	}
	if c.method != "GET" {
		score += 25
	}
	return score
}

// ---------------------------------------------------------------- evaluation

// evaluate probes the endpoint, then lets what the manual crawl already observed settle the cases
// the probe could not.
//
// Only unverified.* is promoted, and that restriction is the whole design. A skip was a deliberate
// decision not to measure, and a ruled_out is hard live evidence of absence that outranks a stale
// observation: an endpoint that answered 200 during the crawl and hard-404s now has been removed,
// and saying so is the correct answer rather than a stale valid.
//
// This exists because the probe cannot win on a CDN-hosted SPA. Every unknown path returns the same
// 200 index.html shell, so content comparison against a control is meaningless, and one real run
// produced 758 unverified.spa_shell_ambiguous out of 1137. The crawl watched the application itself
// issue those requests, which is evidence the re-probe has no way to recover.
func (r *validationRun) evaluate(c validationCandidate) ValidationVerdict {
	v := r.probeEndpoint(c)
	if v.Status != validationStatusUnverified {
		return v
	}
	status, ok := c.observedInCrawl()
	if !ok {
		return v
	}

	prior := v.ReasonCode
	v.Status = validationStatusValid
	v.ReasonCode = "valid.observed_in_crawl"
	v.Reason = fmt.Sprintf(
		"The manual crawl recorded the application itself issuing %s to this endpoint %s, answered "+
			"%d. Probing could not confirm it independently (%s), but a request the application made "+
			"and a response it received is direct evidence the route exists.",
		c.method, pluralRequests(c.captureCount), status, prior)
	v.RuleFired = "observed_in_crawl"
	v.Confidence = "observed"
	v.Falsifier = "A recorded 404 or 410, no recorded response, or an OPTIONS preflight would not " +
		"establish the route; a live hard 404 under the recorded verb would show it has since been removed."
	if v.Testable == nil {
		v.Testable = boolPtr(true)
	}
	if v.Evidence == nil {
		v.Evidence = map[string]interface{}{}
	}
	v.Evidence["crawl_status_codes"] = c.crawlStatuses
	v.Evidence["crawl_capture_count"] = c.captureCount
	v.Evidence["probe_verdict"] = prior
	return v
}

func pluralRequests(n int) string {
	if n == 1 {
		return "once"
	}
	return fmt.Sprintf("%d times", n)
}

func (r *validationRun) probeEndpoint(c validationCandidate) ValidationVerdict {
	v := ValidationVerdict{
		EndpointID: c.id, EndpointKey: c.key, URL: c.url, Method: c.method,
		Confidence: "measured", Evidence: map[string]interface{}{},
	}

	// Scope first. Whether this framework is allowed to send a request at all outranks every
	// question about what the response would mean.
	//
	// The row is kept. An endpoint the application loads from a third party is real attack surface
	// and worth recording; what is not acceptable is probing somebody else's host under an
	// engagement that named this one.
	if !r.scope.AllowsURL(c.url) {
		r.scope.Refuse(hostOf(c.url))
		return skipVerdict(v, "skipped.out_of_scope", fmt.Sprintf(
			"%s is outside this scope target (%s), so no request was sent. The endpoint is kept "+
				"because third-party surface is worth knowing about; add the host to the scan's "+
				"scope if it is in your program.", hostOf(c.url), r.scope.Describe()))
	}

	// Static assets are stored but not measured: validating ten thousand images buys nothing and
	// spends the whole rate budget doing it.
	if c.contentClass == "static" {
		return skipVerdict(v, "skipped.static_asset",
			"Static asset. Not measured; it is kept in the list and excluded from testing.")
	}

	// A GET that logs you out is still destructive. This is the one place a safe verb is not safe.
	if seg := destructiveSegmentIn(c.path); seg != "" {
		return skipVerdict(v, "skipped.destructive_heuristic", fmt.Sprintf(
			"The path segment %q suggests requesting this would change state on the target, so it "+
				"was not requested. GET /logout would destroy the session and turn every later "+
				"verdict into a login wall.", seg))
	}

	if c.method != http.MethodGet && c.method != http.MethodHead && c.method != http.MethodOptions {
		return r.evaluateUnsafeMethod(v, c)
	}

	// HEAD and OPTIONS are safe, so send the verb that was actually recorded rather than
	// substituting GET. Probing an OPTIONS row with GET and then ruling it out on the GET's 404
	// recorded a confident ruled_out.hard_404 against a route that exists and answers OPTIONS
	// perfectly well, which is a false negative stated with measured confidence: the worst kind.
	if c.method == http.MethodHead || c.method == http.MethodOptions {
		resp := r.request(c.url, c.method, c.method != http.MethodHead)
		v = r.judge(v, c, resp)
		// Absence under HEAD or OPTIONS is weaker evidence than absence under GET. A server that
		// routes only GET on a path answers 404 to OPTIONS while the path plainly exists, which is
		// the same reasoning evaluateUnsafeMethod already applies to the write verbs.
		if v.Status == validationStatusRuledOut &&
			(v.ReasonCode == "ruled_out.hard_404" || v.ReasonCode == "ruled_out.gone") {
			v.Status = validationStatusUnverified
			v.ReasonCode = "unverified.verb_not_routed"
			v.Reason = fmt.Sprintf("Answered %d to %s. That does not establish the path is absent: "+
				"a server routing only GET here answers the same way while the path exists.",
				resp.Status, c.method)
			v.RuleFired = "verb_not_routed"
			v.Confidence = "measured"
			v.Falsifier = "A 2xx for this exact URL under GET would show the path exists."
		}
		return v
	}

	resp := r.get(c.url, true)
	return r.judge(v, c, resp)
}

// evaluateUnsafeMethod characterises a POST/PUT/PATCH/DELETE row without ever sending that verb.
//
// A 404 under GET is not evidence the POST route is absent: Express app.post()-only routes and
// Rails production routing both answer 404 for the wrong verb, and those are the two most common
// stacks in scope. So absence under GET never rules the row out.
func (r *validationRun) evaluateUnsafeMethod(v ValidationVerdict, c validationCandidate) ValidationVerdict {
	opts := r.request(c.url, http.MethodOptions, true)
	if opts.Err == nil && opts.Status > 0 {
		allow := opts.Header.Get("Allow") + "," + opts.Header.Get("Access-Control-Allow-Methods")
		if strings.Contains(strings.ToUpper(allow), c.method) {
			v.Status = validationStatusValid
			v.ReasonCode = "valid.method_confirmed"
			v.Reason = fmt.Sprintf("OPTIONS advertises %s on this path (Allow: %s).",
				c.method, strings.Trim(allow, ","))
			v.RuleFired = "options_allow"
			v.HTTPStatus = opts.Status
			v.Testable = boolPtr(true)
			v.Falsifier = "A request with " + c.method + " returning 405 would disprove it."
			return v
		}
	}

	probe := r.get(c.url, true)
	v.HTTPStatus = probe.Status
	v.ResponseMS = probe.ElapsedMS
	v.ResponseSize = probe.BodyBytes

	switch {
	case probe.Status == 405 || probe.Status == 501:
		v.Status = validationStatusValid
		v.ReasonCode = "valid.method_confirmed"
		v.Reason = fmt.Sprintf("GET returned %d, so the route exists and rejects the verb. The "+
			"recorded %s was never sent.", probe.Status, c.method)
		v.RuleFired = "get_405"
		v.Testable = boolPtr(true)
	case probe.Status >= 200 && probe.Status < 300:
		v.Status = validationStatusValid
		v.ReasonCode = "valid.distinct"
		v.Reason = fmt.Sprintf("GET on this path answered %d, so the path exists. The recorded %s "+
			"was never sent, so the write surface is unconfirmed.", probe.Status, c.method)
		v.RuleFired = "get_2xx"
		v.Testable = boolPtr(true)
	default:
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.unsafe_method"
		v.Reason = fmt.Sprintf("This row records %s, which is never sent. GET returned %d, and "+
			"that is not evidence the %s route is absent: Express and Rails both answer 404 for a "+
			"wrong verb.", c.method, probe.Status, c.method)
		v.RuleFired = "unsafe_method_unresolved"
		v.Confidence = "inferred"
	}
	v.Flags = append(v.Flags, "verb_not_replayed")
	v.Falsifier = "Sending " + c.method + " by hand would settle it."
	return v
}

// judge is the verdict ladder. First match wins and the rule is recorded, so every verdict can be
// traced to the observation that produced it.
func (r *validationRun) judge(v ValidationVerdict, c validationCandidate, resp ScanResponse) ValidationVerdict {
	v.HTTPStatus = resp.Status
	v.ResponseSize = resp.BodyBytes
	v.ResponseMS = resp.ElapsedMS
	v.ContentType = resp.ContentType
	v.Location = resp.Location

	if resp.Err != nil {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.unreachable"
		v.Reason = "The request did not complete: " + truncateReason(resp.Err.Error())
		v.RuleFired = "transport_error"
		v.Confidence = "measured"
		v.Falsifier = "A completed request would settle it."
		return v
	}

	fp := BuildFingerprint(resp)
	v.Title = fp.Title
	v.StructHash = fp.StructureHash
	v.Simhash = fp.SimhashHex
	v.Evidence["fingerprint"] = FingerprintSummary(fp)

	// 429 and 503: the run outpaced the target. This says nothing about the endpoint.
	if resp.Status == 429 || (resp.Status == 503 && resp.Header.Get("Retry-After") != "") {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.rate_limited"
		v.Reason = fmt.Sprintf("Answered %d, which is the target throttling this run rather than "+
			"anything about the endpoint.", resp.Status)
		v.RuleFired = "rate_limited"
		v.Falsifier = "Re-running at a lower rate would measure it."
		return v
	}

	// 401 and 403 are evidence of existence, not absence. A central authorisation middleware
	// returning a uniform 403 across /api/admin, /api/billing and /api/users is exactly the surface
	// a hunter wants, and ruling those out would delete the most interesting rows on the target.
	if resp.Status == 401 || resp.Status == 403 {
		if r.looksBlocked(resp, fp) {
			v.Status = validationStatusUnverified
			v.ReasonCode = "unverified.blocked"
			v.Reason = "Refused by a WAF or bot manager rather than the application, so the " +
				"endpoint itself was never reached."
			v.RuleFired = "waf_block"
			v.Flags = append(v.Flags, "waf")
			v.Falsifier = "A request that reaches the application would settle it."
			return v
		}
		v.Status = validationStatusValid
		v.ReasonCode = "valid.auth_required"
		v.Reason = fmt.Sprintf("Answered %d. The route exists and is refusing this identity, "+
			"which is positive evidence it is real.", resp.Status)
		v.RuleFired = "auth_status"
		v.Testable = boolPtr(true)
		v.Falsifier = "A not-found response with valid credentials would disprove it."
		return v
	}

	if IsBlockStatus(resp.Status) || IsChallengeBody(resp.Body) {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.blocked"
		v.Reason = fmt.Sprintf("Answered %d with a challenge or block page, so the application "+
			"was never reached.", resp.Status)
		v.RuleFired = "block_or_challenge"
		v.Flags = append(v.Flags, "waf")
		v.Falsifier = "A request that reaches the application would settle it."
		return v
	}

	// A hard 404 is the one cheap, unambiguous rule-out.
	//
	// Confidence comes from whether THIS run established a not-found reference, not from whether
	// the probe happened to run its own test. Calibration always measures one, and the status code
	// is observed directly, so a missing probe does not make this an assumption.
	if resp.Status == 404 || resp.Status == 410 {
		conf := r.ruleOutConfidence()
		v.Status = validationStatusRuledOut
		v.ReasonCode = "ruled_out.hard_404"
		if resp.Status == 410 {
			v.ReasonCode = "ruled_out.gone"
		}
		v.Reason = fmt.Sprintf("Answered %d. This target uses real not-found statuses, so this "+
			"path does not exist as requested.", resp.Status)
		v.RuleFired = "hard_404"
		v.Confidence = conf
		v.Testable = testableFor(validationStatusRuledOut, conf, true)
		v.Falsifier = "A 2xx for this exact URL, verb and Accept header would disprove it."
		if hasSource(c.sources, "gau") || hasSource(c.sources, "waybackurls") {
			v.Flags = append(v.Flags, "historical_only")
			v.Reason += " It came from an archive, so it may have existed once."
		}
		// A juicy name that 404s today is still worth a manual look, so it is never marked untestable.
		if containsJuicyToken(c.path) {
			v.Flags = append(v.Flags, "historical_lead")
			v.Testable = nil
		}
		return v
	}

	if resp.IsRedirect() {
		return r.judgeRedirect(v, c, resp)
	}

	// Body matches the login page. With no credentials this is not evidence about the endpoint.
	if r.loginOK && MatchesReference(fp, r.login) {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.login_wall"
		if !r.auth.HasAny() {
			v.ReasonCode = "unverified.pending_auth"
		}
		v.Reason = "The body is the login page. That means this run is not authenticated here, " +
			"not that the endpoint is absent."
		v.RuleFired = "login_body"
		v.Flags = append(v.Flags, "login_wall")
		v.Falsifier = "An authenticated request returning different content would settle it."
		return v
	}

	// The per-directory control: the primary oracle. Compared only against a control taken from
	// the same directory, because /api/* and /* frequently have different catch-alls.
	//
	// Order matters here and getting it wrong is destructive. An earlier version applied the
	// SPA-shell rule to every HTML response BEFORE this comparison, which swept a genuinely
	// distinct dashboard page into the ambiguous bucket alongside the catch-all. The shell rule
	// is a modifier on a response that MATCHES the shell, never a filter on the content type.
	// Keyed on the endpoint's own origin, scheme and port included, not on the bare hostname. Two
	// services on one host that differ only by port have different not-found behaviour, and sharing
	// a control between them means one service's catch-all rules out the other's real endpoints.
	dir := EndpointDirectory(c.path)
	family := originOf(c.url) + "|" + dir + "|" + ExtensionClass(c.path)
	if control, ok := r.controlFor(family, c); ok {
		if MatchesReference(fp, control) {
			return r.catchAllVerdict(v, fp, fmt.Sprintf(
				"Byte-for-byte the same answer this target gives a path that cannot exist in %s, "+
					"so nothing distinct is served here.", dir),
				"ruled_out.catch_all", "directory_control_match",
				r.controlURLs[family], !r.controlBad[family])
		}
	} else if r.controlBad[family] {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.local_oracle_unstable"
		v.Reason = fmt.Sprintf("The not-found control for %s disagreed with itself, so there is "+
			"no reliable answer to compare against in this directory.", dir)
		v.RuleFired = "oracle_unstable"
		v.Confidence = "inferred"
		v.Falsifier = "A stable control response would allow a verdict."
		return v
	}

	// Global not-found echo.
	if r.notFoundOK && MatchesReference(fp, r.notFound) {
		return r.catchAllVerdict(v, fp,
			"Returns 200 but the body is this target's not-found page. A soft 404.",
			"ruled_out.soft_404_echo", "global_notfound_match", "", true)
	}

	if fp.Opaque {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.opaque_body"
		v.Reason = "A binary response, which is never fingerprinted from its contents."
		v.RuleFired = "opaque"
		v.Testable = boolPtr(true)
		v.Falsifier = "n/a"
		return v
	}

	v.Status = validationStatusValid
	v.ReasonCode = "valid.distinct"
	v.Reason = fmt.Sprintf("Answered %d with content that differs from this target's not-found "+
		"response and from its login page.", resp.Status)
	v.RuleFired = "distinct_content"
	v.Testable = boolPtr(true)
	v.Falsifier = "Matching the directory's not-found control would disprove it."
	return v
}

// catchAllVerdict turns "this response is the target's catch-all" into a verdict, applying the two
// conditions that stop it becoming a rule-out.
//
// On a client-routed app, and on a target whose not-found page the probe could not tell apart from
// real content, matching the catch-all is not evidence the route is absent: the server hands the
// same shell to every path and the routing happens in the browser. Those cases stay unverified and
// testable-unknown, so downstream tools still look at them.
// ruleOutConfidence reports how much this run's own measurements support ruling something out.
//
// Measured when calibration established a not-found reference under this run's exact recipe.
// Inferred when it could not, or when the probe result being leaned on is stale. Never assumed on
// the strength of a directly observed status code.
func (r *validationRun) ruleOutConfidence() string {
	if !r.notFoundOK {
		return "inferred"
	}
	if r.probe.Available && r.probe.Stale {
		return "inferred"
	}
	return "measured"
}

func (r *validationRun) catchAllVerdict(v ValidationVerdict, fp ResponseFingerprint,
	reason, code, rule, controlURL string, oracleHealthy bool) ValidationVerdict {

	v.ControlURL = controlURL

	if r.isSPAShell {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.spa_shell_ambiguous"
		v.Reason = "The response is this target's catch-all shell, which it serves for every path. " +
			"Routing happens in the browser, so a server-side request cannot tell whether this " +
			"route exists. Its real surface is the JSON and script traffic."
		v.RuleFired = "spa_shell_" + rule
		v.Flags = append(v.Flags, "spa_shell")
		v.Falsifier = "A JSON or non-shell response for this path would settle it."
		return v
	}
	if r.loginOK && MatchesReference(fp, r.login) {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.login_wall"
		if !r.auth.HasAny() {
			v.ReasonCode = "unverified.pending_auth"
		}
		v.Reason = "The catch-all this target serves is its login page, so this cannot be told " +
			"apart from an endpoint that exists but is behind authentication."
		v.RuleFired = "login_wall_" + rule
		v.Flags = append(v.Flags, "login_wall")
		v.Falsifier = "An authenticated request returning different content would settle it."
		return v
	}
	if r.probe.NotFoundVerdict == "soft_404_indistinguishable" {
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.indistinguishable"
		v.Reason = "The probe found this target's not-found page indistinguishable from real " +
			"content, so a body match is not evidence of absence."
		v.RuleFired = "indistinguishable_" + rule
		v.Confidence = "inferred"
		v.Falsifier = "A distinguishable not-found response would allow a verdict."
		return v
	}

	conf := r.ruleOutConfidence()
	v.Status = validationStatusRuledOut
	v.ReasonCode = code
	v.Reason = reason
	v.RuleFired = rule
	v.Confidence = conf
	v.Testable = testableFor(validationStatusRuledOut, conf, oracleHealthy)
	v.Falsifier = "A response differing from the measured catch-all would disprove it."
	if controlURL != "" {
		v.Falsifier = "A response differing from " + controlURL + " would disprove it."
	}
	return v
}

// judgeRedirect handles 3xx. The Location is compared whole, query included.
//
// A per-row Location like /login?next=%2Fadmin%2Fusers proves the router parsed and recognised the
// requested path, so the endpoint exists and is behind auth. Normalising the query away before
// comparing turns that proof into "everything redirects to /login", which is precisely the false
// positive this whole feature exists to eliminate.
func (r *validationRun) judgeRedirect(v ValidationVerdict, c validationCandidate, resp ScanResponse) ValidationVerdict {
	loc := resp.Location

	if LooksLikeAuthRedirect(loc) {
		if redirectCarriesReturnPath(loc, c.path) {
			v.Status = validationStatusValid
			v.ReasonCode = "valid.auth_required"
			v.Reason = fmt.Sprintf("Redirects to %s, and the target carries this path back in its "+
				"query, so the router recognised the request. The endpoint exists behind auth.", loc)
			v.RuleFired = "auth_redirect_with_return"
			v.Testable = boolPtr(true)
			v.Falsifier = "The same Location for a path that cannot exist would disprove it."
			return v
		}
		v.Status = validationStatusUnverified
		v.ReasonCode = "unverified.login_wall"
		if !r.auth.HasAny() {
			v.ReasonCode = "unverified.pending_auth"
		}
		v.Reason = fmt.Sprintf("Redirects to %s with no reference to the requested path, so this "+
			"cannot be told apart from the target sending everything to its login page.", loc)
		v.RuleFired = "auth_redirect_uniform"
		v.Flags = append(v.Flags, "login_wall")
		v.Falsifier = "An authenticated request would settle it."
		return v
	}

	// A redirect that only swaps in the canonical host is the target normalising, not a resource.
	if r.probe.CanonicalBaseURL != "" && redirectOnlyChangesHost(c.url, loc) {
		v.Status = validationStatusRuledOut
		v.ReasonCode = "ruled_out.canonical_redirect"
		v.Reason = fmt.Sprintf("Redirects to the same path on the canonical host (%s). The "+
			"canonical row is the real endpoint.", loc)
		v.RuleFired = "canonical_redirect"
		v.Confidence = "measured"
		v.Testable = boolPtr(false)
		v.Falsifier = "A redirect to a different path would disprove it."
		return v
	}

	v.Status = validationStatusValid
	v.ReasonCode = "valid.distinct"
	v.Reason = fmt.Sprintf("Answered %d redirecting to %s, which is a routing decision specific "+
		"to this path.", resp.Status, loc)
	v.RuleFired = "redirect_distinct"
	v.Testable = boolPtr(true)
	v.Falsifier = "The same Location for a nonexistent path would disprove it."
	return v
}

// controlFor issues, and caches, one not-found control per directory family.
//
// Bounded at 300 families. A CMS with 5,000 directories would otherwise cost 5,000 extra requests
// purely on controls, and the remainder falls back to the global reference rather than going
// unmeasured.
func (r *validationRun) controlFor(family string, c validationCandidate) (ResponseFingerprint, bool) {
	if fp, ok := r.controls[family]; ok {
		return fp, !r.controlBad[family]
	}
	if r.controlBad[family] {
		return ResponseFingerprint{}, false
	}
	if len(r.controls) >= maxControlFamilies {
		r.controlCapHit++
		return ResponseFingerprint{}, false
	}

	dir := EndpointDirectory(c.path)
	ext := ""
	if e := ExtensionClass(c.path); e == "data" {
		ext = ".json"
	}

	// The control must be issued against the endpoint's own origin, port included.
	//
	// This was built from the bare `domain` column and the base scheme, which silently drops the
	// port. Against a target on any port other than the scheme default, every control request went
	// to a different server, and whatever answered there became that directory's idea of "not
	// found". The failure is quiet in both directions: sometimes the wrong server's 404 is unstable
	// and the whole directory reports local_oracle_unstable, and sometimes it is stable, in which
	// case real endpoints get compared against an unrelated application.
	origin := originOf(c.url)
	if origin == "" {
		origin = r.baseURL
	}
	controlOf := func() string {
		return fmt.Sprintf("%s%s/%s-%s%s",
			origin, strings.TrimSuffix(dir, "/"), validationTokenPfx, randomToken(12), ext)
	}

	controlURL := controlOf()
	resp := r.get(controlURL, true)
	if resp.Err != nil || resp.Status == 0 {
		r.controlBad[family] = true
		return ResponseFingerprint{}, false
	}
	fp := BuildFingerprint(resp)

	// A directory whose own control disagrees with the global reference is exactly the directory
	// the global reference does not describe, so it gets a second control rather than a fallback.
	if r.notFoundOK && !MatchesReference(fp, r.notFound) {
		second := r.get(controlOf(), true)
		if second.Err != nil {
			r.controlBad[family] = true
			return ResponseFingerprint{}, false
		}
		// ResponsesEquivalent, not MatchesReference, and the difference decides whether this target
		// gets an oracle at all.
		//
		// MatchesReference refuses to match a JSON body under 512 bytes, because being wrong there
		// deletes a real endpoint. The question here is the opposite one: did two requests for two
		// paths that cannot exist come back the same? A 21-byte {"error":"not_found"} is the single
		// most common API 404 there is, and judging it by the rule-out floor declares two identical
		// responses to be in disagreement, marks the directory unstable, and disables the primary
		// oracle for exactly the endpoints most worth ruling on.
		if !ResponsesEquivalent(BuildFingerprint(second), fp) {
			// Two controls, two different answers. There is no oracle here.
			r.controlBad[family] = true
			return ResponseFingerprint{}, false
		}
	}

	r.controls[family] = fp
	r.controlURLs[family] = controlURL
	return fp, true
}

func (r *validationRun) looksBlocked(resp ScanResponse, fp ResponseFingerprint) bool {
	if IsChallengeBody(resp.Body) {
		return true
	}
	// Without a measured block signature from the probe, a 403 is never called a WAF block. A
	// uniform application-level 403 is real surface and must not be discarded as noise.
	if !r.probe.BlockUsable {
		return false
	}
	if r.probe.BlockStatus != 0 && resp.Status == r.probe.BlockStatus {
		tolerance := r.probe.SizeTolerance
		if tolerance < 64 {
			tolerance = 64
		}
		if absInt(fp.DecodedSize-r.probe.BlockSize) <= tolerance {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- requests

func (r *validationRun) get(rawURL string, readBody bool) ScanResponse {
	host := hostOf(rawURL)
	material, _ := r.auth.For(host)
	return r.getRaw(rawURL, readBody, material)
}

func (r *validationRun) getRaw(rawURL string, readBody bool, material *ScopedAuthMaterial) ScanResponse {
	return r.request2(rawURL, http.MethodGet, readBody, material)
}

func (r *validationRun) request(rawURL, method string, readBody bool) ScanResponse {
	host := hostOf(rawURL)
	material, _ := r.auth.For(host)
	return r.request2(rawURL, method, readBody, material)
}

func (r *validationRun) request2(rawURL, method string, readBody bool, material *ScopedAuthMaterial) ScanResponse {
	headers := map[string]string{}
	if r.probe.ForceCacheBust {
		headers["Cache-Control"] = "no-cache"
		headers["Pragma"] = "no-cache"
	}
	r.requests++
	return r.client.Do(r.ctx, ScanRequest{
		URL: rawURL, Method: method, Headers: headers, Auth: material, ReadBody: readBody,
	})
}

// ---------------------------------------------------------------- persistence

func (r *validationRun) commit(batch []ValidationVerdict) {
	if len(batch) == 0 {
		return
	}
	tx, err := dbPool.Begin(r.ctx)
	if err != nil {
		log.Printf("[VALIDATE] begin failed: %v", err)
		return
	}
	defer tx.Rollback(r.ctx)

	for _, v := range batch {
		evidenceJSON, _ := json.Marshal(v.Evidence)
		if _, err := tx.Exec(r.ctx, `
			INSERT INTO endpoint_validation_results
			  (scan_id, scope_target_id, endpoint_id, endpoint_key, url, method, status,
			   reason_code, reason, confidence, testable, rule_fired, falsifier, http_status,
			   response_size, response_ms, content_type, location, title, structure_hash, simhash,
			   control_url, flags, evidence)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
			ON CONFLICT (scan_id, endpoint_key) DO UPDATE SET
			  status = EXCLUDED.status, reason_code = EXCLUDED.reason_code,
			  reason = EXCLUDED.reason, confidence = EXCLUDED.confidence,
			  testable = EXCLUDED.testable`,
			r.scanID, r.scopeTargetID, nullUUID(v.EndpointID), v.EndpointKey, v.URL, v.Method,
			v.Status, v.ReasonCode, v.Reason, v.Confidence, v.Testable, v.RuleFired, v.Falsifier,
			v.HTTPStatus, v.ResponseSize, v.ResponseMS, v.ContentType, v.Location, v.Title,
			v.StructHash, v.Simhash, v.ControlURL, v.Flags, evidenceJSON); err != nil {
			log.Printf("[VALIDATE] result insert failed for %s: %v", v.URL, err)
			continue
		}

		// Cached onto the endpoint row so the list query does not have to join.
		if _, err := tx.Exec(r.ctx, `
			UPDATE consolidated_url_endpoints
			SET validation_status = $1, validation_reason_code = $2, validation_reason = $3,
			    validation_confidence = $4, validation_testable = $5, validation_scan_id = $6,
			    validated_at = NOW()
			WHERE id = $7`,
			v.Status, v.ReasonCode, v.Reason, v.Confidence, v.Testable, r.scanID,
			nullUUID(v.EndpointID)); err != nil {
			log.Printf("[VALIDATE] projection failed for %s: %v", v.URL, err)
		}
	}

	if err := tx.Commit(r.ctx); err != nil {
		log.Printf("[VALIDATE] commit failed: %v", err)
	}
}

func updateValidationStatus(scanID, status string, total, processed int) {
	_, _ = dbPool.Exec(context.Background(), `
		UPDATE endpoint_validation_scans
		SET status = $1, total_endpoints = GREATEST(total_endpoints, $2),
		    processed_endpoints = $3, updated_at = NOW()
		WHERE scan_id = $4`, status, total, processed, scanID)
}

func finishValidation(scanID, status, errMsg string, started time.Time, run *validationRun) {
	execTime := time.Since(started).String()

	var (
		countsJSON      = []byte("{}")
		assumptionsJSON = []byte("[]")
		calibrationJSON = []byte("{}")
		resultJSON      []byte
		requests        int
		abortReason     string
	)
	// What the run measured, not how many rows it wrote. See validationRun.judged.
	judged := 0
	if run != nil {
		judged = run.judged
	}

	if run != nil {
		countsJSON, _ = json.Marshal(run.counts)
		assumptionsJSON, _ = json.Marshal(run.assumptions)
		calibrationJSON, _ = json.Marshal(map[string]interface{}{
			"baseline_ms": run.baselineMS,
			// The number the degradation ladder actually compares against, which is not baseline_ms.
			// Reporting only the base-URL probe is how an abort came to name a value no rule used.
			"working_baseline_ms": run.budget.WorkingBaseline(run.baseHost),
			"not_found_measured":  run.notFoundOK,
			"not_found_status":    run.notFound.Status,
			"not_found_size":      run.notFound.DecodedSize,
			"login_fingerprinted": run.loginOK,
			"spa_shell":           run.isSPAShell,
			// Null when it could not be established, which the UI renders as no claim at all
			// rather than as a failed session.
			"credentials_honoured":  run.credsHonoured,
			"credentials_probe_url": run.credsProbeURL,
			"control_families":      len(run.controls),
			"control_cap_hit":       run.controlCapHit,
			"unstable_families":     len(run.controlBad),
			"scope":                 run.scope.Describe(),
			"out_of_scope_hosts":    len(run.scope.Refused()),
		})
		requests = run.requests
		abortReason = run.budget.Aborted()
		resultJSON, _ = json.Marshal(map[string]interface{}{
			"counts":        run.counts,
			"assumptions":   run.assumptions,
			"pacing_events": run.budget.Events(),
			"probe":         run.probe,
		})
	}

	_, err := dbPool.Exec(context.Background(), `
		UPDATE endpoint_validation_scans
		SET status = $1, error = $2, execution_time = $3, requests_sent = $4,
		    counts = $5, assumptions = $6, calibration = $7, abort_reason = $8,
		    result = $9, processed_endpoints = GREATEST(processed_endpoints, $10),
		    updated_at = NOW()
		WHERE scan_id = $11`,
		status, errMsg, execTime, requests, countsJSON, assumptionsJSON, calibrationJSON,
		abortReason, string(resultJSON), judged, scanID)
	if err != nil {
		log.Printf("[VALIDATE] failed to finish scan %s: %v", scanID, err)
	}
	log.Printf("[VALIDATE] %s finished: status=%s requests=%d in %s", scanID, status, requests, execTime)
}

// ---------------------------------------------------------------- helpers

// testableFor implements the one rule that keeps a false negative from being destructive:
// testable=false requires a measured verdict from a healthy oracle. Anything less is unknown, and
// unknown still gets tested downstream.
func testableFor(status, confidence string, oracleHealthy bool) *bool {
	if status == validationStatusRuledOut && confidence == "measured" && oracleHealthy {
		return boolPtr(false)
	}
	return nil
}

func skipVerdict(v ValidationVerdict, code, reason string) ValidationVerdict {
	v.Status = validationStatusSkipped
	v.ReasonCode = code
	v.Reason = reason
	v.RuleFired = code
	v.Confidence = "measured"
	v.Falsifier = "n/a"
	return v
}

func destructiveSegmentIn(path string) string {
	for _, seg := range strings.Split(path, "/") {
		if seg != "" && destructiveSegment.MatchString(seg) {
			return seg
		}
	}
	return ""
}

func containsJuicyToken(path string) bool {
	lower := strings.ToLower(path)
	for _, tok := range []string{"admin", "internal", "debug", "config", "backup", "export",
		"secret", "token", "actuator", "swagger", "graphql", ".git", ".env"} {
		if strings.Contains(lower, tok) {
			return true
		}
	}
	return false
}

// redirectCarriesReturnPath reports whether a login redirect echoes the requested path back, which
// proves the router recognised it rather than blanket-redirecting.
func redirectCarriesReturnPath(location, requestPath string) bool {
	if requestPath == "" || requestPath == "/" {
		return false
	}
	decoded, err := url.QueryUnescape(location)
	if err != nil {
		decoded = location
	}
	return strings.Contains(decoded, requestPath)
}

func redirectOnlyChangesHost(requestURL, location string) bool {
	req, err1 := url.Parse(requestURL)
	loc, err2 := url.Parse(location)
	if err1 != nil || err2 != nil || loc.Host == "" {
		return false
	}
	return req.EscapedPath() == loc.EscapedPath() && req.RawQuery == loc.RawQuery &&
		!strings.EqualFold(req.Host, loc.Host)
}

func looksLikeLoginBody(body string) bool {
	l := strings.ToLower(body)
	if len(l) > 40000 {
		l = l[:40000]
	}
	hasPassword := strings.Contains(l, `type="password"`) || strings.Contains(l, "type='password'")
	hasSignIn := strings.Contains(l, "sign in") || strings.Contains(l, "log in") ||
		strings.Contains(l, "login") || strings.Contains(l, "sign-in")
	return hasPassword && hasSignIn
}

func hasSource(sources []string, want string) bool {
	for _, s := range sources {
		if s == want {
			return true
		}
	}
	return false
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// originOf returns scheme://host[:port]. Unlike hostOf, which answers "whose credentials apply
// here" and so deliberately ignores the port, this answers "which server am I talking to", where
// the port is part of the answer.
func originOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.Scheme == "" {
		return ""
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func boolPtr(b bool) *bool { return &b }

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func truncateReason(s string) string {
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

func nullUUID(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// newSimpleCookieJar returns a jar for targets where the probe recommended session reuse, so the
// run does not mint a new session on every request.
func newSimpleCookieJar() (http.CookieJar, error) {
	return &memoryJar{cookies: map[string][]*http.Cookie{}}, nil
}

type memoryJar struct {
	cookies map[string][]*http.Cookie
}

func (j *memoryJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.cookies[u.Host] = cookies
}

func (j *memoryJar) Cookies(u *url.URL) []*http.Cookie {
	return j.cookies[u.Host]
}
