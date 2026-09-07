package utils

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// Everything here runs against the pure core and against the runner with its four dependencies
// injected: no dbPool, no sockets, no real clock. That is deliberate. The parts worth arguing about
// are which condition matches, what a missing header does, and whether a flow that loops can be made
// to stop - and a cap that can only be exercised by pointing a runner at a live target is a cap
// nobody will ever check.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func condResponse(status int, body string, headers map[string][]string) FlowResponse {
	return FlowResponse{Ran: true, Status: status, Body: body, Headers: headers, TimeMs: 120.5}
}

func condCtx(resp FlowResponse) FlowEvalContext {
	return FlowEvalContext{Response: resp, Steps: map[string]FlowStepRef{}}
}

// matchesCond is the one-liner the operator-facing question reduces to: does this expression fire
// against this response?
func matchesCond(t *testing.T, when string, ctx FlowEvalContext) (bool, FlowConditionMatch) {
	t.Helper()
	match := EvaluateFlowConditions([]FlowCondition{{When: when, Then: FlowActionStop}}, ctx)
	return match.Index == 0, match
}

// condRails is the boundary the conditional runner is given in tests: the legacy scope plus an
// empty deny list and an empty exclusion list, which is what a target with neither configured has.
func condRails() flowSendRails {
	return flowSendRails{Scope: condScope(), Denied: map[string]bool{}, Exclusions: nil}
}

func condScope() *ScanScope {
	s := &ScanScope{
		domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{},
		primary: "app.example.com",
	}
	s.Allow("example.com")
	return s
}

func condStep(id, name, path string, order int, enabled bool, conds ...FlowCondition) RequestFlowStep {
	return RequestFlowStep{
		ID:         id,
		StepOrder:  order,
		Name:       name,
		RawRequest: "GET " + path + " HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
		Enabled:    enabled,
		Conditions: conds,
	}
}

// condRunner drives runRequestFlowConditional with a scripted sender and a fake clock, and records
// everything the run did to the outside world.
type condRunner struct {
	statuses  []int // per send, cycled: the last one repeats
	bodies    []string
	headers   map[string][]string
	sendErr   error
	sent      []string // the raw bytes of every request, in order
	persisted []string
	slept     time.Duration
	sleeps    []time.Duration
	clock     time.Time
	jars      []http.CookieJar
}

func (c *condRunner) deps() flowRunDeps {
	if c.clock.IsZero() {
		c.clock = time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	}
	return flowRunDeps{
		send: func(raw, baseURL string, jar http.CookieJar, timeout time.Duration) (int, map[string][]string, string, float64, error) {
			c.sent = append(c.sent, raw)
			c.jars = append(c.jars, jar)
			// A send costs time, so a wall-clock cap can actually be reached in a test.
			c.clock = c.clock.Add(10 * time.Millisecond)
			idx := len(c.sent) - 1
			status := 200
			if len(c.statuses) > 0 {
				if idx >= len(c.statuses) {
					idx = len(c.statuses) - 1
				}
				status = c.statuses[idx]
			}
			body := ""
			if len(c.bodies) > 0 {
				bi := len(c.sent) - 1
				if bi >= len(c.bodies) {
					bi = len(c.bodies) - 1
				}
				body = c.bodies[bi]
			}
			return status, c.headers, body, 12.0, c.sendErr
		},
		persist: func(stepID string, status int, headers map[string][]string, body string, ms float64, errStr string) error {
			c.persisted = append(c.persisted, stepID)
			return nil
		},
		sleep: func(d time.Duration) {
			c.slept += d
			c.sleeps = append(c.sleeps, d)
			c.clock = c.clock.Add(d)
		},
		now: func() time.Time { return c.clock },
	}
}

func (c *condRunner) run(steps []RequestFlowStep, caps FlowRunCaps) *FlowRunResult {
	flow := RequestFlow{ID: "flow-1", ScopeTargetID: "target-1", BaseURL: "https://app.example.com"}
	return runRequestFlowConditional(flow, steps, condRails(),
		ResolveEngagementFrom(nil, EngagementGlobals{}), caps, nil, c.deps())
}

func condCaps() FlowRunCaps {
	return ResolveFlowRunCaps(FlowRunCapRequest{}, ResolveEngagementFrom(nil, EngagementGlobals{}))
}

// ---------------------------------------------------------------------------
// Operators
// ---------------------------------------------------------------------------

// Every numeric operator against the field the operator will use ninety percent of the time. A
// branching flow whose == is right and whose >= is off by one is worse than no branching at all.
func TestFlowConditionNumericOperators(t *testing.T) {
	ctx := condCtx(condResponse(302, "", nil))

	for _, tc := range []struct {
		when string
		want bool
	}{
		{"status == 302", true},
		{"status == 200", false},
		{"status != 200", true},
		{"status != 302", false},
		{"status > 300", true},
		{"status > 302", false},
		{"status < 400", true},
		{"status < 302", false},
		{"status >= 302", true},
		{"status >= 303", false},
		{"status <= 302", true},
		{"status <= 301", false},
	} {
		got, match := matchesCond(t, tc.when, ctx)
		if got != tc.want {
			t.Errorf("%q against status 302: got %v want %v (problems %v)", tc.when, got, tc.want, match.Problems)
		}
	}
}

// size and time_ms are the two fields that make "the response changed shape" expressible, which is
// how a blind injection or an access-control difference is actually detected.
func TestFlowConditionSizeAndTimeFields(t *testing.T) {
	resp := condResponse(200, "0123456789", nil) // 10 bytes
	resp.TimeMs = 4200
	ctx := condCtx(resp)

	for _, tc := range []struct {
		when string
		want bool
	}{
		{"size == 10", true},
		{"size > 9", true},
		{"size > 10", false},
		{"time_ms > 4000", true},
		{"time_ms < 4000", false},
		{"body ~ 456", true},
	} {
		if got, match := matchesCond(t, tc.when, ctx); got != tc.want {
			t.Errorf("%q: got %v want %v (%v)", tc.when, got, tc.want, match.Problems)
		}
	}
}

// The text operators, including the one that is a regular expression and the two that are negations.
func TestFlowConditionTextOperators(t *testing.T) {
	ctx := condCtx(condResponse(200, `{"error":"Invalid CSRF token"}`, map[string][]string{
		"Content-Type": {"application/json; charset=utf-8"},
	}))

	for _, tc := range []struct {
		when string
		want bool
	}{
		{`body ~ "invalid csrf"`, true}, // ~ is case-insensitive on purpose
		{`body ~ "INVALID CSRF"`, true},
		{`body !~ "welcome back"`, true},
		{`body !~ "Invalid"`, false},
		{`body =~ "Invalid [A-Z]+ token"`, true},
		{`body =~ "^nope"`, false},
		{`header.Content-Type ~ json`, true},
		{`header.Content-Type == "application/json; charset=utf-8"`, true},
		{`header.Content-Type == "application/json"`, false}, // == is exact, not a prefix
	} {
		if got, match := matchesCond(t, tc.when, ctx); got != tc.want {
			t.Errorf("%q: got %v want %v (%v)", tc.when, got, tc.want, match.Problems)
		}
	}
}

// HTTP header names are case-insensitive, and the operator will type whichever case they saw in the
// response pane. A condition that works on Location and not location is a condition that fails at
// random.
func TestFlowConditionHeaderNameIsCaseInsensitive(t *testing.T) {
	ctx := condCtx(condResponse(302, "", map[string][]string{
		"Location": {"/dashboard"},
	}))
	for _, when := range []string{
		"header.Location ~ dashboard",
		"header.location ~ dashboard",
		"header.LOCATION ~ dashboard",
	} {
		if got, match := matchesCond(t, when, ctx); !got {
			t.Errorf("%q did not match a Location header (%v)", when, match.Problems)
		}
	}
}

// THE ONE THAT MATTERS MOST. An absent header is ABSENT, not "". If it compared equal to the empty
// string then `header.X != "y"` would be true on a response that never carried X at all, and the
// flow would branch on a header the server did not send.
func TestFlowConditionMissingHeaderNeverMatches(t *testing.T) {
	ctx := condCtx(condResponse(200, "hello", map[string][]string{
		"Content-Type": {"text/html"},
	}))

	for _, when := range []string{
		`header.Location == ""`,
		`header.Location == "/dashboard"`,
		`header.Location != "/dashboard"`,
		`header.Location ~ dashboard`,
		`header.Location !~ dashboard`,
		`header.Location =~ .*`,
	} {
		if got, _ := matchesCond(t, when, ctx); got {
			t.Errorf("%q matched even though the response has no Location header", when)
		}
	}

	// And it is still a NON-match rather than an error, so the next condition gets its turn.
	match := EvaluateFlowConditions([]FlowCondition{
		{When: `header.Location ~ dashboard`, Then: FlowActionStop},
		{When: `status == 200`, Then: FlowActionFail},
	}, ctx)
	if match.Index != 1 || match.Action != FlowActionFail {
		t.Errorf("the condition after a missing-header miss did not get its turn: %+v", match)
	}
}

// A header with several values: a positive operator matches on ANY, a negation must hold for ALL.
// "no value of Set-Cookie contains admin" is what the operator means when there are three of them.
func TestFlowConditionMultiValuedHeader(t *testing.T) {
	ctx := condCtx(condResponse(200, "", map[string][]string{
		"Set-Cookie": {"session=abc; HttpOnly", "theme=dark"},
	}))
	if got, _ := matchesCond(t, "header.Set-Cookie ~ theme", ctx); !got {
		t.Error("~ must match when any value contains the needle")
	}
	if got, _ := matchesCond(t, "header.Set-Cookie !~ theme", ctx); got {
		t.Error("!~ must be false when any value contains the needle")
	}
	if got, _ := matchesCond(t, "header.Set-Cookie !~ admin", ctx); !got {
		t.Error("!~ must be true when no value contains the needle")
	}
}

// ---------------------------------------------------------------------------
// The failure modes that must not be silent
// ---------------------------------------------------------------------------

// A regex that will not compile is caught at save time. If one reaches the evaluator anyway - an old
// row, a hand-edited JSONB - it must produce a stated problem, not a panic and not a silent false.
func TestFlowConditionBadRegexIsExplainedNotPanicked(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("an uncompilable regex panicked the evaluator: %v", r)
		}
	}()

	ctx := condCtx(condResponse(200, "anything", nil))
	match := EvaluateFlowConditions([]FlowCondition{
		{When: `body =~ "([unclosed"`, Then: FlowActionStop},
	}, ctx)

	if match.Index != -1 {
		t.Errorf("a broken regex matched something: %+v", match)
	}
	if len(match.Problems) == 0 || !strings.Contains(strings.ToLower(match.Problems[0]), "compile") {
		t.Errorf("the operator is not told the regex is broken: %v", match.Problems)
	}
	// And it is refused at save time, which is where it should actually be caught.
	if problem := ValidateFlowConditions([]FlowCondition{
		{When: `body =~ "([unclosed"`, Then: FlowActionStop}}, nil); problem == "" {
		t.Error("an uncompilable regex was accepted at save time")
	}
}

// A numeric comparison against a field that is not a number is an operator error, and saying so is
// the difference between "my condition never fires" and "I compared text with >".
func TestFlowConditionNumericOperatorOnTextIsAProblem(t *testing.T) {
	ctx := condCtx(condResponse(200, "not a number at all", map[string][]string{
		"Content-Type": {"text/html"},
	}))

	match := EvaluateFlowConditions([]FlowCondition{
		{When: "body > 5", Then: FlowActionStop},
	}, ctx)
	if match.Index != -1 {
		t.Fatalf("a numeric comparison against text matched: %+v", match)
	}
	if len(match.Problems) == 0 || !strings.Contains(match.Problems[0], "not a number") {
		t.Errorf("the operator is not told why: %v", match.Problems)
	}

	// The value side is caught earlier still, at parse time, because there is no response involved.
	if _, err := parseFlowConditionExpr("status > abc"); err == nil {
		t.Error("`status > abc` parsed, and would have been a condition that never fires")
	}

	// A numeric header IS comparable, which is the case this must not break.
	numeric := condCtx(condResponse(200, "", map[string][]string{"Content-Length": {"4096"}}))
	if got, m := matchesCond(t, "header.Content-Length > 1000", numeric); !got {
		t.Errorf("a numeric header could not be compared numerically: %v", m.Problems)
	}
}

// A catch-all in the middle makes every condition after it dead, and dead conditions are invisible:
// the operator sees them in the list and believes they can fire.
func TestFlowConditionCatchAllMustBeLast(t *testing.T) {
	bad := []FlowCondition{
		{When: "status == 200", Then: FlowActionContinue},
		{When: "*", Then: FlowActionFail},
		{When: "status == 500", Then: FlowActionStop},
	}
	problem := ValidateFlowConditions(bad, nil)
	if problem == "" {
		t.Fatal("a catch-all in the middle was accepted, making the condition after it dead")
	}
	if !strings.Contains(problem, "catch-all") || !strings.Contains(problem, "end") {
		t.Errorf("the refusal does not explain itself: %s", problem)
	}

	good := []FlowCondition{
		{When: "status == 200", Then: FlowActionContinue},
		{When: "else", Then: FlowActionFail},
	}
	if problem := ValidateFlowConditions(good, nil); problem != "" {
		t.Errorf("a catch-all in last position was refused: %s", problem)
	}

	// Both spellings, and both actually match.
	for _, when := range []string{"*", "else", "ELSE"} {
		if got, _ := matchesCond(t, when, condCtx(condResponse(418, "", nil))); !got {
			t.Errorf("the catch-all %q did not match", when)
		}
	}
}

// First match wins, and nothing after the winner is consulted.
func TestFlowConditionFirstMatchWins(t *testing.T) {
	ctx := condCtx(condResponse(302, "", map[string][]string{"Location": {"/login"}}))
	match := EvaluateFlowConditions([]FlowCondition{
		{When: "status == 200", Then: FlowActionContinue},
		{When: "status == 302", Then: FlowActionGoto, Target: "Follow", Message: "redirected"},
		{When: "*", Then: FlowActionFail},
	}, ctx)

	if match.Index != 1 || match.Action != FlowActionGoto || match.Target != "Follow" {
		t.Fatalf("the second condition should have won: %+v", match)
	}
	if match.Message != "redirected" {
		t.Errorf("the message did not survive: %q", match.Message)
	}
}

// No condition matching is not an error and not a stop: it is "next step in order", which is what a
// flow with no conditions at all does. Branching must not change what an existing flow does.
func TestFlowConditionNoMatchMeansContinue(t *testing.T) {
	match := EvaluateFlowConditions([]FlowCondition{
		{When: "status == 500", Then: FlowActionFail},
	}, condCtx(condResponse(200, "", nil)))
	if match.Index != -1 || match.Action != FlowActionContinue {
		t.Errorf("an unmatched list must continue, got %+v", match)
	}
	if match := EvaluateFlowConditions(nil, condCtx(condResponse(200, "", nil))); match.Action != FlowActionContinue {
		t.Errorf("a step with no conditions must continue, got %+v", match)
	}
}

// An action nobody recognises must never become a jump. A typo in "goto" that silently became one
// would send a request the operator did not ask for.
func TestFlowConditionUnknownActionIsNotAJump(t *testing.T) {
	match := EvaluateFlowConditions([]FlowCondition{
		{When: "*", Then: "jmp", Target: "somewhere"},
	}, condCtx(condResponse(200, "", nil)))
	if match.Action != FlowActionContinue {
		t.Errorf("%q became %q", "jmp", match.Action)
	}
	if problem := ValidateFlowConditions([]FlowCondition{{When: "*", Then: "jmp"}}, nil); problem == "" {
		t.Error("an unknown action was accepted at save time")
	}
}

// ---------------------------------------------------------------------------
// Referring to an earlier step
// ---------------------------------------------------------------------------

// "Did the login step succeed" is the obvious real use, and it has to work by name and by id.
func TestFlowConditionReferencesAnEarlierStep(t *testing.T) {
	login := condResponse(200, `{"token":"abc"}`, map[string][]string{"Set-Cookie": {"session=1"}})
	ctx := FlowEvalContext{
		Response: condResponse(403, "denied", nil),
		Steps: map[string]FlowStepRef{
			"login":       {Name: "Login", Response: &login},
			"step-uuid-1": {Name: "Login", Response: &login},
		},
	}

	for _, when := range []string{
		"step.Login.status == 200",
		"step.login.status == 200",
		"step.step-uuid-1.status == 200",
		`step.Login.body ~ token`,
		"step.Login.header.Set-Cookie ~ session",
		"step.Login.size > 0",
	} {
		if got, match := matchesCond(t, when, ctx); !got {
			t.Errorf("%q did not match (%v)", when, match.Problems)
		}
	}

	// And the current response is still the default subject.
	if got, _ := matchesCond(t, "status == 403", ctx); !got {
		t.Error("a bare field must still mean the step that just ran")
	}
}

// A step name with spaces is normal (GET /login), so a reference to one has to be quotable.
func TestFlowConditionQuotedStepReference(t *testing.T) {
	prior := condResponse(201, "", nil)
	ctx := FlowEvalContext{
		Response: condResponse(200, "", nil),
		Steps:    map[string]FlowStepRef{"post /v1/tickets": {Name: "POST /v1/tickets", Response: &prior}},
	}
	if got, match := matchesCond(t, `step."POST /v1/tickets".status == 201`, ctx); !got {
		t.Errorf("a quoted step reference did not resolve: %v", match.Problems)
	}
	// A step name containing dots must not be cut at the wrong one.
	js := condResponse(200, "", map[string][]string{"Content-Type": {"application/javascript"}})
	dotted := FlowEvalContext{
		Response: condResponse(200, "", nil),
		Steps:    map[string]FlowStepRef{"get /static/app.js": {Name: "GET /static/app.js", Response: &js}},
	}
	if got, match := matchesCond(t, `step."GET /static/app.js".header.Content-Type ~ javascript`, dotted); !got {
		t.Errorf("a dotted step name broke the field split: %v", match.Problems)
	}
}

// THE DISARM RULE. A skipped step must not silently make a condition false: the operator has to be
// told the condition could not be judged and why, or they will conclude the target changed.
func TestFlowConditionSaysWhenAReferencedStepWasSkipped(t *testing.T) {
	ctx := FlowEvalContext{
		Response: condResponse(200, "", nil),
		Steps: map[string]FlowStepRef{
			"login": {Name: "Login",
				Missing: "it is turned off, so the run skipped it rather than sending it"},
		},
	}

	match := EvaluateFlowConditions([]FlowCondition{
		{When: "step.Login.status == 200", Then: FlowActionStop},
	}, ctx)
	if match.Index != -1 {
		t.Fatal("a condition on a step that never ran matched")
	}
	if len(match.Problems) != 1 {
		t.Fatalf("the skip was not reported: %v", match.Problems)
	}
	if !strings.Contains(match.Problems[0], "turned off") ||
		!strings.Contains(match.Problems[0], "Login") {
		t.Errorf("the problem does not say which step or why: %s", match.Problems[0])
	}
}

// Naming a step that does not exist is a different mistake from naming one that has not run, and the
// message has to tell them apart: one is a typo, the other is the flow's order.
func TestFlowConditionUnknownStepIsSaidDifferently(t *testing.T) {
	match := EvaluateFlowConditions([]FlowCondition{
		{When: "step.Nonexistent.status == 200", Then: FlowActionStop},
	}, condCtx(condResponse(200, "", nil)))

	if len(match.Problems) != 1 || !strings.Contains(match.Problems[0], "no step called") {
		t.Errorf("an unknown step was not reported as one: %v", match.Problems)
	}
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

func TestFlowConditionParserRejectsNonsense(t *testing.T) {
	for _, expr := range []string{
		"",
		"status",              // no operator
		"status ==",           // no value
		"== 200",              // no field
		"latency == 5",        // not a field
		"step.Login == 200",   // a step with no field
		"step..status == 200", // an empty step reference
		`body =~ "(["`,        // a regex that does not compile
	} {
		if _, err := parseFlowConditionExpr(expr); err == nil {
			t.Errorf("%q parsed and should not have", expr)
		}
	}

	// A value containing spaces or an operator character survives quoting.
	expr, err := parseFlowConditionExpr(`body ~ "user id = 42"`)
	if err != nil {
		t.Fatalf("a quoted value did not parse: %v", err)
	}
	if expr.Value != "user id = 42" {
		t.Errorf("the quoted value was mangled to %q", expr.Value)
	}
}

// ---------------------------------------------------------------------------
// Goto targets and cycles
// ---------------------------------------------------------------------------

func TestFlowConditionGotoTargetsAreResolvedAtSaveTime(t *testing.T) {
	steps := []FlowGraphStep{
		{ID: "id-1", Name: "Login"},
		{ID: "id-2", Name: "Dashboard"},
	}

	if problem := ValidateFlowConditions([]FlowCondition{
		{When: "status == 302", Then: FlowActionGoto, Target: "Dashboard"}}, steps); problem != "" {
		t.Errorf("a goto to a real step was refused: %s", problem)
	}
	if problem := ValidateFlowConditions([]FlowCondition{
		{When: "status == 302", Then: FlowActionGoto, Target: "id-2"}}, steps); problem != "" {
		t.Errorf("a goto by step id was refused: %s", problem)
	}
	if problem := ValidateFlowConditions([]FlowCondition{
		{When: "status == 302", Then: FlowActionGoto, Target: "Nowhere"}}, steps); problem == "" {
		t.Error("a goto to a step that does not exist was accepted")
	}
	if problem := ValidateFlowConditions([]FlowCondition{
		{When: "status == 302", Then: FlowActionGoto}}, steps); problem == "" {
		t.Error("a goto with no target was accepted")
	}
	// An ambiguous name has no single destination and must not be resolved to whichever row came
	// back first: that makes the flow's behaviour depend on the planner.
	dupes := []FlowGraphStep{{ID: "a", Name: "Login"}, {ID: "b", Name: "Login"}}
	if problem := ValidateFlowConditions([]FlowCondition{
		{When: "*", Then: FlowActionGoto, Target: "Login"}}, dupes); problem == "" {
		t.Error("an ambiguous goto target was accepted")
	}
	// A target on an action that cannot jump is a mistake worth catching: the operator meant goto.
	if problem := ValidateFlowConditions([]FlowCondition{
		{When: "*", Then: FlowActionStop, Target: "Dashboard"}}, steps); problem == "" {
		t.Error("a stop carrying a target was accepted")
	}
}

// Cycles are warned about at AUTHORING time, not refused: a bounded retry loop is legitimate. What
// is not acceptable is the operator finding out when it fires at a live target.
func TestFlowConditionCycleDetection(t *testing.T) {
	backwards := []FlowGraphStep{
		{ID: "1", Name: "Login"},
		{ID: "2", Name: "Check", Conditions: []FlowCondition{
			{When: "status == 401", Then: FlowActionGoto, Target: "Login"},
		}},
	}
	warnings := DetectFlowConditionCycles(backwards)
	if len(warnings) == 0 {
		t.Fatal("a backwards goto was not reported as a loop")
	}
	if !strings.Contains(warnings[0], "Login") || !strings.Contains(warnings[0], "Check") {
		t.Errorf("the warning does not name the steps in the loop: %s", warnings[0])
	}

	selfLoop := []FlowGraphStep{
		{ID: "1", Name: "Poll", Conditions: []FlowCondition{
			{When: "status == 202", Then: FlowActionRetry},
		}},
	}
	if len(DetectFlowConditionCycles(selfLoop)) == 0 {
		t.Error("a retry was not reported as a step that can run again")
	}

	// And a forward-only flow must NOT be warned about, or the warning stops meaning anything.
	forward := []FlowGraphStep{
		{ID: "1", Name: "A", Conditions: []FlowCondition{
			{When: "status == 200", Then: FlowActionGoto, Target: "C"}}},
		{ID: "2", Name: "B"},
		{ID: "3", Name: "C", Conditions: []FlowCondition{{When: "*", Then: FlowActionStop}}},
	}
	if warnings := DetectFlowConditionCycles(forward); len(warnings) != 0 {
		t.Errorf("a flow that cannot loop was warned about: %v", warnings)
	}
}

// ---------------------------------------------------------------------------
// The caps
// ---------------------------------------------------------------------------

// The defaults, and the fact that nothing the operator sends can turn a cap off.
func TestFlowConditionCapsCannotBeDisabled(t *testing.T) {
	eng := ResolveEngagementFrom(nil, EngagementGlobals{})

	base := ResolveFlowRunCaps(FlowRunCapRequest{}, eng)
	if base.MaxExecutions != flowRunDefaultMaxExecutions ||
		base.PerStepMaxExecutions != flowRunDefaultPerStepExecutions ||
		base.RetryCap != flowRunDefaultRetryCap ||
		base.RetryDelayMs != flowRunDefaultRetryDelayMs ||
		base.WallClockS != flowRunDefaultWallClockS {
		t.Errorf("the defaults are not what is documented: %+v", base)
	}

	zero := 0
	huge := 10000000
	negative := -1

	off := ResolveFlowRunCaps(FlowRunCapRequest{
		MaxExecutions: &zero, PerStepMaxExecutions: &zero, WallClockS: &zero,
		RetryDelayMs: &zero,
	}, eng)
	if off.MaxExecutions < 1 || off.PerStepMaxExecutions < 1 || off.WallClockS < 1 {
		t.Errorf("zero turned a cap off: %+v", off)
	}
	if off.RetryDelayMs < flowRunMinRetryDelayMs {
		t.Errorf("a retry with no delay is a tight loop that happens to be counted: %+v", off)
	}

	raised := ResolveFlowRunCaps(FlowRunCapRequest{
		MaxExecutions: &huge, PerStepMaxExecutions: &huge, RetryCap: &huge,
		RetryDelayMs: &huge, WallClockS: &huge,
	}, eng)
	if raised.MaxExecutions != flowRunMaxExecutionsCeiling ||
		raised.PerStepMaxExecutions != flowRunPerStepExecutionsCeiling ||
		raised.RetryCap != flowRunRetryCapCeiling ||
		raised.RetryDelayMs != flowRunMaxRetryDelayMs ||
		raised.WallClockS != flowRunWallClockCeilingS {
		t.Errorf("a cap was raised past its ceiling: %+v", raised)
	}
	if len(raised.Notes) == 0 {
		t.Error("clamping was silent, so the operator's numbers and the run's disagree in secret")
	}

	negativeCaps := ResolveFlowRunCaps(FlowRunCapRequest{MaxExecutions: &negative}, eng)
	if negativeCaps.MaxExecutions < 1 {
		t.Errorf("a negative budget is not a budget: %+v", negativeCaps)
	}
}

// ---------------------------------------------------------------------------
// The runner
// ---------------------------------------------------------------------------

// A flow with no conditions still walks 1..n, which is what every flow saved before branching
// existed does. If this ever changes, an existing flow silently starts behaving differently.
func TestFlowConditionRunnerWalksALinearFlow(t *testing.T) {
	runner := &condRunner{}
	result := runner.run([]RequestFlowStep{
		condStep("a", "One", "/one", 1, true),
		condStep("b", "Two", "/two", 2, true),
		condStep("c", "Three", "/three", 3, true),
	}, condCaps())

	if result.Outcome != flowOutcomeCompleted || result.StopReason != FlowStopCompleted {
		t.Fatalf("a straight-line flow did not complete: %s / %s", result.Outcome, result.StopDetail)
	}
	if len(runner.sent) != 3 || result.Executions != 3 || result.RequestsSent != 3 {
		t.Errorf("expected 3 sends, got %d (executions %d)", len(runner.sent), result.Executions)
	}
	if len(result.Trace) != 3 {
		t.Fatalf("the trace has %d entries for 3 steps", len(result.Trace))
	}
	for i, entry := range result.Trace {
		if entry.Sequence != i+1 || entry.Attempt != 1 || entry.MatchedCondition != -1 ||
			entry.Action != FlowActionContinue {
			t.Errorf("trace %d is wrong: %+v", i, entry)
		}
	}
}

// The trace is the run's explanation, and a branching run has no other one.
func TestFlowConditionRunnerTraceExplainsTheBranch(t *testing.T) {
	runner := &condRunner{statuses: []int{302, 200}}
	result := runner.run([]RequestFlowStep{
		condStep("a", "Login", "/login", 1, true,
			FlowCondition{When: "status == 302", Then: FlowActionGoto, Target: "Dashboard",
				Message: "logged in, following the redirect"}),
		condStep("b", "Error page", "/error", 2, true),
		condStep("c", "Dashboard", "/dashboard", 3, true),
	}, condCaps())

	if len(result.Trace) != 2 {
		t.Fatalf("expected two executions (Login, Dashboard), got %d", len(result.Trace))
	}
	first := result.Trace[0]
	if first.StepName != "Login" || first.Status != 302 || first.MatchedCondition != 0 ||
		first.Action != FlowActionGoto || first.ActionTargetName != "Dashboard" ||
		first.MatchedWhen != "status == 302" ||
		first.Message != "logged in, following the redirect" {
		t.Errorf("the branch is not explained: %+v", first)
	}
	if result.Trace[1].StepName != "Dashboard" {
		t.Errorf("the goto did not land on Dashboard: %+v", result.Trace[1])
	}
	// The step that was jumped over never ran, and never claims to have.
	for _, entry := range result.Trace {
		if entry.StepName == "Error page" {
			t.Error("a step that was branched around appears in the trace as having run")
		}
	}
}

// A goto must not lose the session or the captured variables: a step reached by a jump has to see
// everything the steps that actually ran produced, or every real flow breaks at the first branch.
func TestFlowConditionRunnerCarriesCookiesAndVariablesAcrossAJump(t *testing.T) {
	jar := &recordingJar{}
	steps := []RequestFlowStep{
		condStep("a", "Login", "/login", 1, true,
			FlowCondition{When: "status == 200", Then: FlowActionGoto, Target: "Use token"}),
		condStep("b", "Skipped middle", "/middle", 2, true),
		{
			ID: "c", StepOrder: 3, Name: "Use token", Enabled: true,
			RawRequest: "GET /me HTTP/1.1\r\nHost: app.example.com\r\nX-Token: {{af:tok}}\r\n\r\n",
		},
	}
	steps[0].Extractions = []AuthFlowExtraction{
		{Name: "tok", Source: "body", Pattern: `"token":"([^"]+)"`},
	}

	runner := &condRunner{bodies: []string{`{"token":"abc123"}`, ""}}
	flow := RequestFlow{ID: "flow-1", ScopeTargetID: "target-1", BaseURL: "https://app.example.com"}
	result := runRequestFlowConditional(flow, steps, condRails(),
		ResolveEngagementFrom(nil, EngagementGlobals{}), condCaps(), jar, runner.deps())

	if len(runner.sent) != 2 {
		t.Fatalf("expected two sends, got %d", len(runner.sent))
	}
	if !strings.Contains(runner.sent[1], "X-Token: abc123") {
		t.Errorf("the value captured before the jump did not reach the step after it:\n%s", runner.sent[1])
	}
	if strings.Contains(runner.sent[1], "{{af:tok}}") {
		t.Error("an unsubstituted placeholder was sent to the target")
	}
	for i, used := range runner.jars {
		if used != http.CookieJar(jar) {
			t.Errorf("send %d used a different cookie jar, so the session does not carry", i)
		}
	}
	if result.Outcome != flowOutcomeCompleted {
		t.Errorf("the run did not complete: %s", result.StopDetail)
	}
}

// THE CAP THAT MATTERS MOST. A flow that jumps backwards forever is a denial of service, and the
// budget counts EXECUTIONS: six steps is six definitions and unbounded executions. Six of them so
// the RUN budget is what runs out first, rather than the per-step cap, which has its own test.
func TestFlowConditionRunnerStopsAnInfiniteLoop(t *testing.T) {
	runner := &condRunner{}
	caps := condCaps()
	loop := []RequestFlowStep{
		condStep("a", "One", "/one", 1, true),
		condStep("b", "Two", "/two", 2, true),
		condStep("c", "Three", "/three", 3, true),
		condStep("d", "Four", "/four", 4, true),
		condStep("e", "Five", "/five", 5, true),
		condStep("f", "Six", "/six", 6, true,
			FlowCondition{When: "*", Then: FlowActionGoto, Target: "One"}),
	}
	result := runner.run(loop, caps)

	if result.Outcome != flowOutcomeCapped || result.StopReason != FlowStopMaxExecutions {
		t.Fatalf("an infinite loop was not capped: %s / %s / %s",
			result.Outcome, result.StopReason, result.StopDetail)
	}
	if !strings.Contains(result.StopDetail, "MAX EXECUTED STEPS") {
		t.Errorf("the run does not say which cap stopped it, in those words: %s", result.StopDetail)
	}
	if result.Executions > caps.MaxExecutions {
		t.Errorf("the budget was exceeded: %d executions against a cap of %d",
			result.Executions, caps.MaxExecutions)
	}
	if len(runner.sent) > caps.MaxExecutions {
		t.Errorf("%d requests were sent to the target under a budget of %d",
			len(runner.sent), caps.MaxExecutions)
	}
}

// The per-step cap exists because a budget with room left is not a licence to hammer one endpoint.
func TestFlowConditionRunnerStopsOnThePerStepCap(t *testing.T) {
	runner := &condRunner{}
	caps := condCaps()
	caps.PerStepMaxExecutions = 3
	caps.MaxExecutions = 100

	result := runner.run([]RequestFlowStep{
		condStep("a", "Spin", "/spin", 1, true,
			FlowCondition{When: "*", Then: FlowActionGoto, Target: "Spin"}),
	}, caps)

	if result.StopReason != FlowStopPerStepCap {
		t.Fatalf("the per-step cap did not fire: %s / %s", result.StopReason, result.StopDetail)
	}
	if !strings.Contains(result.StopDetail, "PER-STEP EXECUTION CAP") ||
		!strings.Contains(result.StopDetail, "Spin") {
		t.Errorf("the reason names neither the cap nor the step: %s", result.StopDetail)
	}
	if len(runner.sent) != 3 {
		t.Errorf("a step capped at 3 executions was sent %d times", len(runner.sent))
	}
	// The run's own numbers have to agree with each other: a trace with fewer entries than the
	// execution count is a run that cannot be read.
	if result.Executions != len(result.Trace) {
		t.Errorf("executions (%d) and trace entries (%d) disagree", result.Executions, len(result.Trace))
	}
}

// A retry is small, separate, and delayed. Without the delay it is a tight loop that happens to be
// counted; without the cap it is the same loop with extra steps.
func TestFlowConditionRunnerRetryCapAndDelay(t *testing.T) {
	runner := &condRunner{statuses: []int{503}}
	caps := condCaps()
	caps.RetryCap = 2
	caps.RetryDelayMs = 500

	result := runner.run([]RequestFlowStep{
		condStep("a", "Flaky", "/flaky", 1, true,
			FlowCondition{When: "status >= 500", Then: FlowActionRetry}),
	}, caps)

	if result.StopReason != FlowStopRetryCap {
		t.Fatalf("the retry cap did not fire: %s / %s", result.StopReason, result.StopDetail)
	}
	if !strings.Contains(result.StopDetail, "RETRY CAP") {
		t.Errorf("the reason does not name the retry cap: %s", result.StopDetail)
	}
	// One first attempt plus two retries.
	if len(runner.sent) != 3 {
		t.Errorf("a retry cap of 2 produced %d sends", len(runner.sent))
	}
	// The attempt number is in the trace, which is what makes a retried step legible at all.
	if len(result.Trace) < 3 || result.Trace[0].Attempt != 1 || result.Trace[1].Attempt != 2 ||
		result.Trace[2].Attempt != 3 {
		t.Errorf("attempt numbers are not recorded: %+v", result.Trace)
	}
	if runner.slept < 2*500*time.Millisecond {
		t.Errorf("the retries were not delayed: slept %s", runner.slept)
	}
}

// A run cannot outlive the operator watching it, however slowly it is paced.
func TestFlowConditionRunnerStopsOnTheWallClock(t *testing.T) {
	runner := &condRunner{}
	caps := condCaps()
	caps.WallClockS = 1
	caps.MaxExecutions = flowRunMaxExecutionsCeiling
	caps.RPS = 2 // half a second between requests, so the second runs out first

	result := runner.run([]RequestFlowStep{
		condStep("a", "Spin", "/spin", 1, true,
			FlowCondition{When: "*", Then: FlowActionGoto, Target: "Spin"}),
	}, caps)

	if result.StopReason != FlowStopWallClock {
		t.Fatalf("the wall clock did not stop the run: %s / %s", result.StopReason, result.StopDetail)
	}
	if !strings.Contains(result.StopDetail, "WALL CLOCK") {
		t.Errorf("the reason does not name the cap: %s", result.StopDetail)
	}
}

// The engagement's own request budget is the programme's number, not ours, and a loop must not be
// able to spend past it.
func TestFlowConditionRunnerHonoursTheEngagementRequestBudget(t *testing.T) {
	runner := &condRunner{}
	caps := condCaps()
	caps.MaxRequests = 4
	caps.MaxExecutions = flowRunMaxExecutionsCeiling
	caps.PerStepMaxExecutions = flowRunPerStepExecutionsCeiling

	result := runner.run([]RequestFlowStep{
		condStep("a", "Spin", "/spin", 1, true,
			FlowCondition{When: "*", Then: FlowActionGoto, Target: "Spin"}),
	}, caps)

	if result.StopReason != FlowStopRequestBudget {
		t.Fatalf("the engagement budget did not stop the run: %s / %s",
			result.StopReason, result.StopDetail)
	}
	if len(runner.sent) != 4 {
		t.Errorf("a budget of 4 sent %d requests", len(runner.sent))
	}
	if !strings.Contains(result.StopDetail, "ENGAGEMENT REQUEST BUDGET") {
		t.Errorf("the reason does not name the budget: %s", result.StopDetail)
	}
}

// Every request the runner sends is paced to the engagement's rate limit, loop or not.
func TestFlowConditionRunnerPacesEveryRequest(t *testing.T) {
	runner := &condRunner{}
	caps := condCaps()
	caps.RPS = 1 // one second between sends

	runner.run([]RequestFlowStep{
		condStep("a", "One", "/one", 1, true),
		condStep("b", "Two", "/two", 2, true),
		condStep("c", "Three", "/three", 3, true),
	}, caps)

	// Three sends, two gaps, and the sender itself only consumes 10ms of each.
	if runner.slept < 1900*time.Millisecond {
		t.Errorf("three requests at 1 rps slept only %s", runner.slept)
	}
}

// THE DISARM MACHINERY. A disabled step is not sent, and skipping it must not silently break a
// condition that referenced it.
func TestFlowConditionRunnerSkipsDisarmedStepsAndSaysSo(t *testing.T) {
	runner := &condRunner{}
	result := runner.run([]RequestFlowStep{
		condStep("a", "Create ticket", "/tickets", 1, false), // disarmed
		condStep("b", "Check", "/check", 2, true,
			FlowCondition{When: `step."Create ticket".status == 201`, Then: FlowActionStop}),
	}, condCaps())

	if len(runner.sent) != 1 {
		t.Fatalf("a disarmed step was sent: %d requests went out", len(runner.sent))
	}
	for _, raw := range runner.sent {
		if strings.Contains(raw, "/tickets") {
			t.Error("the disarmed step's bytes reached the target")
		}
	}

	skipped := result.Trace[0]
	if !skipped.Skipped || skipped.Sent || !strings.Contains(skipped.SkipReason, "turned off") {
		t.Errorf("the skip is not recorded: %+v", skipped)
	}

	checked := result.Trace[1]
	if len(checked.ConditionProblems) == 0 ||
		!strings.Contains(checked.ConditionProblems[0], "turned off") {
		t.Errorf("a condition on a disarmed step failed silently: %+v", checked.ConditionProblems)
	}
	if len(result.Warnings) == 0 {
		t.Error("the run does not warn that a condition referenced a step that was skipped")
	}
	// A skipped visit still costs the budget, so two disarmed steps pointing at each other cannot
	// spin forever without sending anything.
	if result.Executions != 2 {
		t.Errorf("a skipped step did not count as an execution: %d", result.Executions)
	}
}

// stop and fail are different outcomes and the difference is the whole point: one is the flow
// reaching its answer, the other is the flow saying the answer is wrong.
func TestFlowConditionRunnerStopAndFailAreDifferent(t *testing.T) {
	stopped := (&condRunner{statuses: []int{200}}).run([]RequestFlowStep{
		condStep("a", "One", "/one", 1, true,
			FlowCondition{When: "status == 200", Then: FlowActionStop, Message: "got in"}),
		condStep("b", "Two", "/two", 2, true),
	}, condCaps())
	if stopped.Outcome != flowOutcomeStopped || stopped.StopReason != FlowStopByCondition ||
		stopped.StopDetail != "got in" {
		t.Errorf("stop did not report success with the message: %+v", stopped)
	}

	failed := (&condRunner{statuses: []int{403}}).run([]RequestFlowStep{
		condStep("a", "One", "/one", 1, true,
			FlowCondition{When: "status == 403", Then: FlowActionFail, Message: "not authorised"}),
	}, condCaps())
	if failed.Outcome != flowOutcomeFailed || failed.StopReason != FlowStopFailed ||
		failed.StopDetail != "not authorised" {
		t.Errorf("fail did not report failure with the message: %+v", failed)
	}
}

// A goto whose target was deleted after the flow was authored stops the run and says so, rather than
// falling through to whatever step happens to be next.
func TestFlowConditionRunnerStopsWhenAGotoTargetIsGone(t *testing.T) {
	result := (&condRunner{}).run([]RequestFlowStep{
		condStep("a", "One", "/one", 1, true,
			FlowCondition{When: "*", Then: FlowActionGoto, Target: "Deleted step"}),
		condStep("b", "Two", "/two", 2, true),
	}, condCaps())

	if result.StopReason != FlowStopGotoMissing {
		t.Fatalf("a dangling goto did not stop the run: %s / %s", result.StopReason, result.StopDetail)
	}
	if !strings.Contains(result.StopDetail, "Deleted step") {
		t.Errorf("the reason does not name the missing target: %s", result.StopDetail)
	}
}

// A step refused by the scope boundary does not abort the run and does not get its conditions
// evaluated: it produced no response, so there is nothing to branch on.
func TestFlowConditionRunnerRefusalDoesNotBranch(t *testing.T) {
	steps := []RequestFlowStep{
		{ID: "a", StepOrder: 1, Name: "Third party", Enabled: true,
			RawRequest: "GET /collect HTTP/1.1\r\nHost: analytics.thirdparty.io\r\n\r\n",
			Conditions: []FlowCondition{{When: "*", Then: FlowActionFail, Message: "should not fire"}}},
		condStep("b", "Two", "/two", 2, true),
	}

	runner := &condRunner{}
	result := runner.run(steps, condCaps())

	if len(runner.sent) != 1 {
		t.Fatalf("an out-of-scope step was sent: %d requests went out", len(runner.sent))
	}
	if result.Outcome != flowOutcomeCompleted {
		t.Errorf("a refusal aborted the run instead of landing on its step: %+v", result)
	}
	if result.Trace[0].Refusal == "" ||
		!strings.Contains(result.Trace[0].Refusal, "analytics.thirdparty.io") {
		t.Errorf("the refusal is not recorded on the step: %+v", result.Trace[0])
	}
	if result.Trace[0].MatchedCondition != -1 {
		t.Error("a condition was evaluated against a step that was never sent")
	}
}

// ---------------------------------------------------------------------------
// The engagement config, on the wire
// ---------------------------------------------------------------------------

// A sender that does not carry the programme's mandatory header sends traffic a SOC reads as an
// attack. The raw bytes are edited rather than a header map being passed, so this is the test that
// the splice actually works and leaves the body alone.
func TestFlowConditionEngagementHeaderReachesTheWire(t *testing.T) {
	name := "X-HackerOne-Research"
	value := "rs0n"
	eng := ResolveEngagementFrom(&EngagementOverrides{
		CustomHeaderName: &name, CustomHeaderValue: &value,
	}, EngagementGlobals{})

	raw := "POST /v1/tickets HTTP/1.1\r\nHost: app.example.com\r\n" +
		"Content-Type: multipart/form-data; boundary=xyz\r\nContent-Length: 40\r\n\r\n" +
		"--xyz\r\nContent-Disposition: form-data\r\n\r\n"

	out, notes := applyEngagementToRawRequest(raw, eng)
	if !strings.Contains(out, name+": "+value) {
		t.Fatalf("the programme's header did not reach the request:\n%s", out)
	}
	if len(notes) == 0 {
		t.Error("the run does not record that it added the header")
	}
	// The body is untouched, byte for byte: a multipart boundary rewritten is a request that is no
	// longer the one the operator is testing.
	_, _, body := splitRawRequestHeadBody(out)
	if body != "--xyz\r\nContent-Disposition: form-data\r\n\r\n" {
		t.Errorf("the body was rewritten: %q", body)
	}
	if !strings.Contains(out, "Content-Length: 40") {
		t.Error("an unrelated header was dropped")
	}

	// Replacing rather than duplicating, when the step already carries the same header with a
	// different value: two X-HackerOne-Research headers is not what the programme asked for.
	withOwn := "GET / HTTP/1.1\r\nHost: app.example.com\r\n" + name + ": stale\r\n\r\n"
	replaced, _ := applyEngagementToRawRequest(withOwn, eng)
	if strings.Count(replaced, name+":") != 1 {
		t.Errorf("the header was duplicated rather than replaced:\n%s", replaced)
	}
	if !strings.Contains(replaced, name+": "+value) {
		t.Errorf("the stale value survived:\n%s", replaced)
	}
}

// A User-Agent nobody configured must NOT overwrite the one on a recorded step: a built-in default
// is not an instruction, and rewriting it changes the request the operator is testing. One that WAS
// configured must win, because that is somebody's deliberate engagement choice.
func TestFlowConditionEngagementUserAgentRules(t *testing.T) {
	recorded := "GET / HTTP/1.1\r\nHost: app.example.com\r\nUser-Agent: Mozilla/5.0 (real browser)\r\n\r\n"

	untouched, _ := applyEngagementToRawRequest(recorded, ResolveEngagementFrom(nil, EngagementGlobals{}))
	if !strings.Contains(untouched, "User-Agent: Mozilla/5.0 (real browser)") {
		t.Errorf("the default User-Agent overwrote a recorded one:\n%s", untouched)
	}

	ua := "dailypay-research/1.0"
	configured := ResolveEngagementFrom(&EngagementOverrides{CustomUserAgent: &ua}, EngagementGlobals{})
	replaced, notes := applyEngagementToRawRequest(recorded, configured)
	if !strings.Contains(replaced, "User-Agent: "+ua) {
		t.Errorf("a configured User-Agent did not reach the wire:\n%s", replaced)
	}
	if strings.Contains(replaced, "Mozilla/5.0") {
		t.Error("both User-Agents are on the request")
	}
	if len(notes) == 0 {
		t.Error("replacing the User-Agent was not recorded")
	}

	// A step with no User-Agent at all still gets one, rather than going out with Go's default.
	bare := "GET / HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	filled, _ := applyEngagementToRawRequest(bare, ResolveEngagementFrom(nil, EngagementGlobals{}))
	if !strings.Contains(filled, "User-Agent: "+engagementDefaultUserAgent) {
		t.Errorf("a step with no User-Agent did not get the framework's:\n%s", filled)
	}
}

// The replay endpoint is a SENDER, so it must resolve this target's engagement config and it must
// stop when it cannot. Asserted against the source because the only other way to see it is to point
// the runner at a live programme and read their WAF logs afterwards.
func TestFlowConditionReplayResolvesTheEngagementConfig(t *testing.T) {
	raw, err := os.ReadFile("requestFlowBuilder.go")
	if err != nil {
		t.Fatalf("could not read the builder: %v", err)
	}
	var code strings.Builder
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		code.WriteString(line)
		code.WriteString("\n")
	}
	body := code.String()

	if !strings.Contains(body, "ResolveEngagementConfig(flow.ScopeTargetID)") {
		t.Error("the replay must resolve the engagement config rather than assuming defaults")
	}
	if !strings.Contains(body, "engagement_unreadable") {
		t.Error("a config that cannot be read must stop the run, not fall back to defaults")
	}
	if !strings.Contains(body, "ResolveFlowRunCaps(") {
		t.Error("the replay must run under resolved caps")
	}

	// And the runner has to actually put the header and the user agent on the bytes.
	runnerSrc, err := os.ReadFile("flowConditions.go")
	if err != nil {
		t.Fatalf("could not read the runner: %v", err)
	}
	for _, needed := range []string{"eng.HeaderMap()", "eng.EffectiveUserAgent", "eng.RequestTimeoutS"} {
		if !strings.Contains(string(runnerSrc), needed) {
			t.Errorf("the runner never uses %s, so a programme's traffic goes out without it", needed)
		}
	}
}

// recordingJar is a cookie jar that records nothing but its own identity: the test only needs to
// know that every step in a run was handed THE SAME jar.
type recordingJar struct {
	cookies []*http.Cookie
}

func (j *recordingJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.cookies = append(j.cookies, cookies...)
}
func (j *recordingJar) Cookies(u *url.URL) []*http.Cookie { return j.cookies }
