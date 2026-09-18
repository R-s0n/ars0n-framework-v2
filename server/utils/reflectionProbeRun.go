package utils

import (
	"context"
	"fmt"
	"log"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Running the reflection probe over every insertion point a target's vectors carry.
//
// The step that turns the attack vector list into an XSS work queue: the operator presses it after
// Consolidate, it sends one canary per input, and every row it writes says either what it measured
// or why it could not measure anything. See reflectionProbe.go for the vocabulary and the grade.

// reflectionProbeTimeout bounds one request.
//
// Shorter than the 20s ScanClient default, because a probe is a single GET against an endpoint the
// crawl has already reached, and a run over two hundred inputs paced at the WAF probe's measured
// rate should not be able to spend an hour inside four hung sockets. A timeout is recorded as
// `error`, never as not_reflected, so nothing is lost by being impatient.
const reflectionProbeTimeout = 12 * time.Second

// reflectionSessionCheckEvery is how many probes run between session liveness checks.
//
// SAME MECHANISM AS THE VECTOR SCAN, deliberately: SessionStillHonoured, called from the loop, with
// everything after a dead session recorded UNTESTED rather than clean. See vectorSessionCheckEvery
// in vectorScan.go for why one check at the start is the thing that misses it.
//
// A different NUMBER, because the unit is a different size. A vector costs minutes, so every eight
// of them is a check every half hour. A probe costs about a third of a second (measured: 145 probes
// in roughly 45 seconds), so every eight probes would be a check every three seconds and the two
// requests the check costs would dominate the run. Every fifty is a check every fifteen seconds
// against a bearer that lives about nine hundred, which loses at most fifty probes.
const reflectionSessionCheckEvery = 50

// StartReflectionProbe kicks off a run and returns its id immediately.
//
// A goroutine for the same reason every other long runner in this package uses one: a probe of two
// hundred inputs paced to a target's measured rate takes minutes, and an HTTP request that waits for
// it is killed by the proxy long before it finishes.
func StartReflectionProbe(ctx context.Context, scopeTargetID string) (string, error) {
	if strings.TrimSpace(scopeTargetID) == "" {
		return "", fmt.Errorf("no scope target given")
	}

	// A second run against the same target would probe the same inputs concurrently, double the
	// traffic against an engagement with a rate ceiling, and race two writers onto the same
	// (vector_id, parameter) rows. Refused rather than queued: the operator pressed the button
	// twice, and telling them the first one is still going is the useful answer.
	var running string
	if err := dbPool.QueryRow(ctx, `
		SELECT id::text FROM vector_reflection_runs
		WHERE scope_target_id = $1 AND status = 'running'
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).Scan(&running); err == nil && running != "" {
		return "", fmt.Errorf("a reflection probe is already running for this target")
	}

	vectors, err := loadVectorRows(ctx, scopeTargetID)
	if err != nil {
		return "", err
	}
	if len(vectors) == 0 {
		return "", fmt.Errorf("no attack vectors to investigate. Run Consolidate first")
	}

	// The credential set is loaded ONCE and read per host, because the planner has to know which
	// cookie and header names the framework itself would set: those are the inputs a canary would
	// overwrite, and overwriting one measures the login wall. See TRAP 2 on ReflectionInputIsCredential.
	plan, skipped := planReflectionProbe(vectors, LoadScopedAuthContext(scopeTargetID))

	// AN EMPTY ACTIVE PLAN IS NOT A REASON TO REFUSE ANY MORE. The passive pass reads stored
	// exchanges and needs no plan at all, so a target whose every vector is a body vector still has
	// an answer waiting in the database. Refusing here would have thrown it away.

	runID := uuid.New().String()
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_reflection_runs (id, scope_target_id, status, phase, total_probes,
		                                    completed_probes, skipped_points, created_at)
		VALUES ($1, $2, 'running', 'passive', $3, 0, $4, NOW())`,
		runID, scopeTargetID, len(plan), mustJSON(skipped)); err != nil {
		return "", err
	}

	go runReflectionProbe(runID, scopeTargetID, vectors, plan)
	return runID, nil
}

// reflectionPlanItem is one planned probe plus the vector context the writer needs.
type reflectionPlanItem struct {
	Target ReflectionProbeTarget
	Host   string
}

// planReflectionProbe turns the vector table into the list of requests that will be made, and counts
// what it left out.
//
// Every insertion point the consolidator produces is planned now, so the skip counts only ever hold
// vectors that could not be AIMED (a query vector naming no parameter, a path whose URL will not
// parse). They are still reported, for the reason they were added: measured on the live vector table
// on 2026-09-17 the probe covered 138 of 317 vectors, and without a number saying how many were left
// out the results table read as the whole attack surface when it was less than half of it. A list
// that is silently partial is worse than one that is visibly empty.
//
// A vector the probe DECLINES to send is not a skip and is not counted here. It gets a row, with
// is_credential or probe_refused on it and a detail saying why, because that is a measurement of the
// method rather than a gap in the plan.
func planReflectionProbe(vectors []vectorRow,
	auth *ScopedAuthContext) ([]reflectionPlanItem, map[string]int) {

	skipped := map[string]int{}
	var plan []reflectionPlanItem

	for _, v := range vectors {
		if !ReflectionProbeApplies(v.InsertionPoint) {
			skipped[v.InsertionPoint]++
			continue
		}
		in := v.toInput()
		planCtx := ReflectionPlanContext{}
		if auth != nil {
			// Per host, not per target: a credential held for app.example.test says nothing about
			// what cdn.example.test would send, and ScopedAuthContext already scopes it that way.
			if material, _ := auth.For(strings.ToLower(v.Domain)); material != nil {
				planCtx.CredentialCookies, planCtx.CredentialHeaders = ReflectionCredentialNames(material)
			}
		}
		targets := BuildReflectionProbeTargetsWithPlan(in, reflectionVectorNeedsCredential(v.RawRequest),
			planCtx)
		if len(targets) == 0 {
			// A query vector with no named parameter has no input to put a canary in, and a path
			// vector whose URL would not parse cannot be aimed. Counted under its own key so the
			// number is visible rather than being quietly absent from the plan.
			skipped["unaimable_"+v.InsertionPoint]++
			continue
		}
		for _, t := range targets {
			plan = append(plan, reflectionPlanItem{Target: t, Host: strings.ToLower(v.Domain)})
		}
	}
	return plan, skipped
}

// reflectionVectorNeedsCredential reports whether this vector was captured WITH authentication.
//
// Measured on the live vector table on 2026-09-17, over the 138 vectors this probe covers: 64 carry
// an Authorization, Cookie or X-API-Key header in their recorded request (51 of the 68 path vectors,
// 13 of the 70 query ones). Probing one of those anonymously gets a 401, reflects nothing, and would
// be filed not_reflected, which is a false negative wearing a coverage badge. Knowing the vector
// needed a credential is what lets the run record `error` and say so instead.
//
// The other direction is NOT symmetrical and is deliberately left alone: 56 of the 70 query vectors
// have no recorded request at all, so this returns false for them. That is the honest answer to
// "was this captured with a credential" when nothing was captured, and those probes still send
// whatever credential is held for the host.
//
// Read from the recorded request bytes rather than from whether a credential happens to be held now,
// because those are different questions: the first is a fact about the capture, the second changes
// every time the operator refreshes a token.
func reflectionVectorNeedsCredential(rawRequest string) bool {
	if rawRequest == "" {
		return false
	}
	text := strings.ReplaceAll(rawRequest, "\r\n", "\n")
	head, _, _ := strings.Cut(text, "\n\n")
	for _, line := range strings.Split(head, "\n") {
		name, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "authorization", "cookie", "x-api-key", "x-auth-token", "x-csrf-token":
			return true
		}
	}
	return false
}

// runReflectionProbe is the goroutine body, and it is TWO PASSES over the same vector list.
//
// PASSIVE FIRST, over everything, sending nothing: the crawl already stored thousands of matched
// request/response pairs, so for a large share of the corpus the answer is already in the database
// and can be had at no cost to the target. ACTIVE SECOND, which is the only pass that learns what
// the application does with a dangerous character, because the crawl never sent one.
//
// Active still runs on an input passive already proved echoes. Passive says "this comes back";
// active says "and < survives", and only the second one is an XSS candidate.
func runReflectionProbe(runID, scopeTargetID string, vectors []vectorRow, plan []reflectionPlanItem) {
	// A probe must never be able to kill the API. Same guard and the same reason as runVectorScan:
	// this runs as a bare `go`, Go takes the whole process down when a goroutine panics, and a panic
	// here would kill every other scan in flight. The run is marked failed rather than left on
	// 'running', because a run row stuck at running with no process behind it poisons every
	// "is something running" check that follows, including the duplicate guard in StartReflectionProbe.
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[REFLECT] PANIC in run %s: %v\n%s", runID, rec, debug.Stack())
			_, _ = dbPool.Exec(context.Background(), `
				UPDATE vector_reflection_runs SET status = 'error', completed_at = NOW(), error = $2
				WHERE id = $1 AND status = 'running'`,
				runID, "The probe crashed part way through. Inputs it never reached are not_probed.")
		}
	}()

	ctx := context.Background()
	authCtx := LoadScopedAuthContext(scopeTargetID)

	// Statuses accumulate per vector so the summary column is computed with the SAME ranking
	// function the UI and the MCP layer call, rather than with a SQL ORDER BY that would be a second
	// copy of the order and free to disagree with it.
	perVector := map[string][]string{}

	// ------------------------------------------------------------------ phase 1: passive
	passive := map[string]PassiveReflectionResult{}
	index := BuildPassiveIndex(vectors, authCtx)
	captures, err := loadPassiveCaptures(ctx, scopeTargetID, index)
	if err != nil {
		log.Printf("[REFLECT] passive pass for %s: %v", runID, err)
	} else {
		passive = PassiveScanCaptures(index, captures)
		for _, res := range passive {
			if err := storePassiveReflection(ctx, scopeTargetID, res); err != nil {
				log.Printf("[REFLECT] storing passive row for vector %s param %q: %v",
					res.VectorID, res.Parameter, err)
			}
			perVector[res.VectorID] = append(perVector[res.VectorID], res.Outcome.Status)
		}
		for vectorID, statuses := range perVector {
			updateReflectionSummary(ctx, vectorID, statuses)
		}
	}
	if _, err := dbPool.Exec(ctx, `
		UPDATE vector_reflection_runs SET phase = 'active', passive_reflections = $2 WHERE id = $1`,
		runID, len(passive)); err != nil {
		log.Printf("[REFLECT] phase update: %v", err)
	}

	if reflectionRunCancelled(ctx, runID) {
		finishReflectionRun(ctx, runID, "cancelled", 0, "Cancelled before the active pass ran.", nil)
		return
	}

	// ------------------------------------------------------------------ phase 2: active
	//
	// PREFLIGHT: ONE request that proves the credential still works, before spending the rest.
	// Measured on the first live run: 129 of 143 probes came back 401 from a captured Authorization
	// header that had expired. The guard behaved correctly and recorded `error` rather than
	// not_reflected, so no false clean was written. It simply should never have started.
	//
	// It runs HERE, after the passive pass, rather than before the run: a dead credential is no
	// reason to throw away results that needed no credential at all.
	if why := preflightReflectionCredential(ctx, scopeTargetID, plan); why != "" {
		finishReflectionRun(ctx, runID, "error", 0, why, nil)
		return
	}

	// The host boundary, enforced inside Do before the request is built. WithScope rather than a
	// check at this call site, because the comment on it records that this boundary leaked twice
	// exactly when a call site was left to remember it.
	scope := LoadScanScope(scopeTargetID)
	budget := NewHostBudget()
	rps, concurrency := LoadProbeContext(scopeTargetID).EffectiveRate()
	for _, item := range plan {
		if item.Host != "" {
			budget.Acquire(item.Host, rps, concurrency, "waf_probe")
		}
	}
	// No cookie jar. A Set-Cookie from one probe must not travel to the next one: a target that
	// hands out an anonymous session would otherwise make every later probe carry it, and the row
	// would stop describing the request the operator thinks it describes.
	client := NewScanClient(budget, reflectionProbeTimeout, "", nil).WithScope(scope)

	completed := 0
	cancelled := false
	sessionLost := ""
	var untested []reflectionPlanItem

	for i, item := range plan {
		// BEFORE EVERY PROBE, not between vectors. A query vector with twelve parameters is twelve
		// requests, and a cancel that only landed between vectors would keep sending for all twelve.
		// One extra query per request, against a loop that is already making a network round trip
		// per request, is free.
		if reflectionRunCancelled(ctx, runID) {
			cancelled = true
			break
		}

		// THE SESSION CHECK. The credential is proved ONCE, in preflightReflectionCredential, and a
		// bearer on the engaged estate lives about nine hundred seconds. A run that outlives it 401s
		// for its whole tail, and a 401 body reflects nothing, so every remaining input would be
		// filed on a response that was never about the input. Same call and same rule as the vector
		// scan: what was not reached is UNTESTED, never clean.
		if reflectionShouldCheckSession(completed) {
			if alive, why := SessionStillHonoured(ctx, scopeTargetID); !alive {
				log.Printf("[REFLECT] %s: session lost after %d probes: %s", runID, completed, why)
				sessionLost = why
				untested = plan[i:]
				break
			}
		}

		var material *ScopedAuthMaterial
		if item.Host != "" {
			material, _ = authCtx.For(item.Host)
		}

		// Which verdict is stored, and from which pass. See reflectionKeepPassive.
		res, havePassive := passive[passiveProbeKey(item.Target.VectorID, item.Target.Parameter)]
		outcome, source := reflectionKeepPassive(
			ProbeReflection(ctx, client, item.Target, material), res.Outcome, havePassive)
		if err := storeReflectionProbe(ctx, scopeTargetID, item.Target, outcome, source); err != nil {
			log.Printf("[REFLECT] storing probe for vector %s param %q: %v",
				item.Target.VectorID, item.Target.Parameter, err)
		}
		perVector[item.Target.VectorID] = append(perVector[item.Target.VectorID], outcome.Status)
		updateReflectionSummary(ctx, item.Target.VectorID, perVector[item.Target.VectorID])

		completed++
		if _, err := dbPool.Exec(ctx, `
			UPDATE vector_reflection_runs SET completed_probes = $2 WHERE id = $1`,
			runID, completed); err != nil {
			log.Printf("[REFLECT] progress update: %v", err)
		}
	}

	// Everything the dead session stopped us reaching gets a row saying so. A passive row is left
	// alone: it was measured from a stored exchange, the session had no part in it, and overwriting
	// a real measurement with an error would be the loss this guard exists to prevent.
	for _, item := range reflectionUntestedTail(untested, passive) {
		out := reflectionUntestedOutcome(item.Target.InsertionPoint)
		if err := storeReflectionProbe(ctx, scopeTargetID, item.Target, out, "active"); err != nil {
			log.Printf("[REFLECT] recording untested probe for vector %s param %q: %v",
				item.Target.VectorID, item.Target.Parameter, err)
		}
		perVector[item.Target.VectorID] = append(perVector[item.Target.VectorID], out.Status)
		updateReflectionSummary(ctx, item.Target.VectorID, perVector[item.Target.VectorID])
	}

	status, runErr := "completed", ""
	if sessionLost != "" {
		status = "error"
		runErr = "The session stopped being honoured; the rest was not sent. Refresh it and re-run."
	}
	if cancelled {
		// Cancelled is its own terminal state, and the remaining rows stay not_probed. Marking the
		// run completed would make a probe that stopped at 8 of 200 inputs indistinguishable from one
		// that finished, and the 192 rows nobody sent would read as coverage.
		status = "cancelled"
		runErr = fmt.Sprintf("Cancelled after %d of %d inputs; the rest were not sent.",
			completed, len(plan))
	}
	finishReflectionRun(ctx, runID, status, completed, runErr, scope.Refused())
}

// finishReflectionRun writes the terminal row.
//
// ONE SHORT SENTENCE in error, never a paragraph. The reason a single input could not be measured
// belongs in that input's own row, where the operator is looking at the thing it describes; the run
// error is the headline, and a headline that runs to ninety words stops being read.
func finishReflectionRun(ctx context.Context, runID, status string, completed int, runErr string,
	refused map[string]int) {

	if len(refused) > 0 {
		hosts := make([]string, 0, len(refused))
		for host := range refused {
			hosts = append(hosts, host)
		}
		sort.Strings(hosts)
		runErr = strings.TrimSpace(runErr + " Out of scope, not probed: " + strings.Join(hosts, ", ") + ".")
	}
	if _, err := dbPool.Exec(ctx, `
		UPDATE vector_reflection_runs
		SET status = $2, phase = '', completed_probes = $3, error = NULLIF($4,''), completed_at = NOW()
		WHERE id = $1`, runID, status, completed, runErr); err != nil {
		log.Printf("[REFLECT] finalising run %s: %v", runID, err)
	}
}

// reflectionRunCancelled reads the cooperative cancel flag.
//
// Cooperative rather than a process kill, the same shape vector_scans uses: the probes already
// written keep their verdicts and the inputs that were never reached stay not_probed, which is the
// truth about them.
func reflectionRunCancelled(ctx context.Context, runID string) bool {
	var requested bool
	if err := dbPool.QueryRow(ctx,
		`SELECT cancel_requested FROM vector_reflection_runs WHERE id = $1`, runID).
		Scan(&requested); err != nil {
		return false
	}
	return requested
}

// storePassiveReflection writes one passive verdict.
//
// probe_url is the CAPTURE's url and canary is empty, because no canary was sent. A row that
// borrowed the active columns without saying so would read as a request that was made.
func storePassiveReflection(ctx context.Context, scopeTargetID string,
	res PassiveReflectionResult) error {

	target := ReflectionProbeTarget{
		VectorID:       res.VectorID,
		Parameter:      res.Parameter,
		InsertionPoint: res.Outcome.InsertionPoint,
		URL:            res.CaptureURL,
	}
	return storeReflectionProbe(ctx, scopeTargetID, target, res.Outcome, "passive")
}

// storeReflectionProbe writes one input's verdict, replacing whatever the last run said about it.
//
// UPSERT on (vector_id, parameter) because the row is the CURRENT answer for that input, not a log
// entry. An operator who fixes a credential and re-probes wants the row to say what it says now; the
// history of what it used to say is what the run rows are for.
func storeReflectionProbe(ctx context.Context, scopeTargetID string, target ReflectionProbeTarget,
	outcome ReflectionOutcome, source string) error {

	evidence := outcome.Evidence
	if len(evidence) > reflectionEvidenceCap {
		evidence = evidence[:reflectionEvidenceCap]
	}
	// A nil slice is written as NULL by pgx, and survived is NOT NULL. Every status but
	// reflected_raw leaves this nil, so without the empty slice the insert would fail for six of the
	// seven statuses and the run would log an error per probe while storing nothing.
	survived := outcome.Survived
	if survived == nil {
		survived = []string{}
	}
	_, err := dbPool.Exec(ctx, `
		INSERT INTO vector_reflection_probes (scope_target_id, vector_id, parameter, insertion_point,
		    status, survived, content_type, http_status, evidence, detail, probe_url, canary,
		    auth_applied, evidence_source, probed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
		ON CONFLICT (vector_id, parameter) DO UPDATE SET
		    scope_target_id = EXCLUDED.scope_target_id,
		    insertion_point = EXCLUDED.insertion_point,
		    status = EXCLUDED.status,
		    survived = EXCLUDED.survived,
		    content_type = EXCLUDED.content_type,
		    http_status = EXCLUDED.http_status,
		    evidence = EXCLUDED.evidence,
		    detail = EXCLUDED.detail,
		    probe_url = EXCLUDED.probe_url,
		    canary = EXCLUDED.canary,
		    auth_applied = EXCLUDED.auth_applied,
		    evidence_source = EXCLUDED.evidence_source,
		    probed_at = NOW()`,
		scopeTargetID, target.VectorID, target.Parameter, target.InsertionPoint,
		outcome.Status, survived, outcome.ContentType, outcome.HTTPStatus,
		evidence, outcome.Detail, target.URL, target.Token, outcome.AuthApplied, source)
	return err
}

// updateReflectionSummary keeps attack_vectors.reflection_status in step with the probe rows.
//
// Denormalised on purpose: the UI filters a list of two hundred vectors on it and the MCP layer
// answers "every vector with the XSS label" from it, and both would otherwise need a join and an
// ordering per row. The value is computed by MostInterestingReflectionStatus so there is exactly one
// definition of which status wins.
func updateReflectionSummary(ctx context.Context, vectorID string, statuses []string) {
	if _, err := dbPool.Exec(ctx,
		`UPDATE attack_vectors SET reflection_status = $2 WHERE id = $1`,
		vectorID, MostInterestingReflectionStatus(statuses...)); err != nil {
		log.Printf("[REFLECT] summary for vector %s: %v", vectorID, err)
	}
}

// preflightReflectionCredential sends ONE probe through the REAL path and refuses the run when the
// target answers 401 or 403.
//
// It has to be the real path, not a hand-rolled request: a preflight that builds its own client or
// its own credential can pass while the run fails, which is worse than no preflight because it
// certifies the thing it did not test. So it uses the same ScanClient, the same ScopedAuthContext,
// the same ProbeReflection, and the first item of the same plan.
//
// 401 and 403 only. A 404, a 500 or a timeout on ONE endpoint says nothing about the credential and
// must not block a run over the other 142: the point is to catch a dead session, not to demand a
// perfect target.
//
// Returns the SHORT sentence the card shows, or empty for "carry on".
func preflightReflectionCredential(ctx context.Context, scopeTargetID string, plan []reflectionPlanItem) string {
	first := reflectionPlanItem{}
	for _, item := range plan {
		// A target the probe has already decided not to send cannot preflight anything: it would
		// return its refusal without touching the network and the run would start on the strength of
		// a request that was never made.
		if item.Host != "" && item.Target.URL != "" && item.Target.SkipStatus == "" {
			first = item
			break
		}
	}
	if first.Host == "" {
		return "" // nothing sendable to preflight with; the run's own guards cover it
	}

	scope := LoadScanScope(scopeTargetID)
	budget := NewHostBudget()
	rps, concurrency := LoadProbeContext(scopeTargetID).EffectiveRate()
	budget.Acquire(first.Host, rps, concurrency, "waf_probe")
	client := NewScanClient(budget, reflectionProbeTimeout, "", nil).WithScope(scope)

	material, _ := LoadScopedAuthContext(scopeTargetID).For(first.Host)
	outcome := ProbeReflection(ctx, client, first.Target, material)

	switch outcome.HTTPStatus {
	case 401:
		return "Session token expired or rejected. Refresh it and try again."
	case 403:
		return "The target answered 403. Get past it or refresh the session token, then try again."
	}
	return ""
}

// reflectionShouldCheckSession is the cadence: after every reflectionSessionCheckEvery completed
// probes, never before the first one.
func reflectionShouldCheckSession(completed int) bool {
	return completed > 0 && completed%reflectionSessionCheckEvery == 0
}

// reflectionUntestedTail is which of the probes a dead session stopped us reaching need a row.
//
// A passive row is LEFT ALONE. It was measured from an exchange the crawl had already stored, the
// session had no part in producing it, and overwriting a real measurement with an error would be
// exactly the data loss this guard exists to prevent.
func reflectionUntestedTail(tail []reflectionPlanItem,
	passive map[string]PassiveReflectionResult) []reflectionPlanItem {

	var out []reflectionPlanItem
	for _, item := range tail {
		if _, ok := passive[passiveProbeKey(item.Target.VectorID, item.Target.Parameter)]; ok {
			continue
		}
		out = append(out, item)
	}
	return out
}

// reflectionUntestedOutcome is the row an input gets when the session died before it was sent.
//
// ReflectionError, never ReflectionNotReflected: nothing was measured about this input, and a
// negative that was never asked for is the silent clean the whole status vocabulary exists to stop.
func reflectionUntestedOutcome(insertionPoint string) ReflectionOutcome {
	return ReflectionOutcome{
		Status:         ReflectionError,
		InsertionPoint: insertionPoint,
		Detail:         "Untested: the session died before this input was sent.",
	}
}

// reflectionKeepPassive decides which of the two verdicts for one input is stored, and says which
// pass it came from.
//
// THE PASSIVE ROW SURVIVES AN ACTIVE NON-ANSWER, BUT NOT AN ACTIVE ANSWER.
//
// Passive says "the value this request sent came back in the response". That is a weaker claim than
// it sounds, because a lookup satisfies it: GET /paper_accounts/<uuid>/margin returns {"id":"<uuid>"}
// not because the application echoed the string, but because it fetched the row whose primary key IS
// that string. A census of all 34 passive findings on the engaged target found 18 of that shape, a
// 53% false positive rate, and no gate built out of length, entropy or attribution can separate
// them: a lookup passes every one.
//
// The ACTIVE probe is exactly the instrument that separates them. It sends a canary no row has ever
// been keyed by, so an echo comes back and a lookup returns nothing. Its not_reflected is therefore
// a REAL measurement of this input and must win. It used to lose: not_reflected was absent from the
// answered list, so the weaker passive claim overwrote the stronger active one.
//
// What still survives is the passive row for an input the active pass NEVER SENT: a body field,
// where the active status is probe_refused. Nothing was measured there, so there is nothing to
// prefer, and passive is the only evidence that exists.
//
// THE KEPT DETAIL IS RETURNED UNCHANGED. It used to have the active probe's own detail concatenated
// onto it, which made it the longest string the reflection table can render, 472 characters of
// italic body text on every body row, and it said nothing the row does not already carry in a
// column: evidence_source says passive and status says what was measured.
func reflectionKeepPassive(active, kept ReflectionOutcome, havePassive bool) (ReflectionOutcome, string) {
	answered := active.Status == ReflectionRaw ||
		active.Status == ReflectionEncoded ||
		active.Status == ReflectionNotReflected
	if havePassive && !answered {
		return kept, "passive"
	}
	return active, "active"
}
