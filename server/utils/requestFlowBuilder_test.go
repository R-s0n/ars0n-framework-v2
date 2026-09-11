package utils

import (
	"bufio"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Everything here runs against the pure core: no dbPool, no network. That is deliberate, and it is
// the same reason segmentCaptureFlows is a pure function over structs. The judgement calls worth
// arguing about are which captures become steps, in what order, whether the bytes survive, and
// whether a seeded POST arrives armed. A judgement call that can only be exercised against a live
// 6,000-row table is a judgement call nobody will ever check.

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

func requestFlowTestCapture(id, method, rawURL, resourceType string, status int,
	hasBody bool, at time.Time) FlowCapture {
	tab := 7
	return FlowCapture{
		ID:           id,
		SessionID:    "11111111-1111-1111-1111-111111111111",
		TabID:        &tab,
		Method:       method,
		URL:          rawURL,
		StatusCode:   status,
		ResourceType: resourceType,
		Timestamp:    at,
		HasBody:      hasBody,
		Matched:      true,
	}
}

// A flow shaped like the ones the live corpus actually produces: a navigation, the subresources it
// pulls, an XHR, and the form POST that is the reason anybody opened the flow view.
func requestFlowTestFlow() (captureFlow, map[string]requestFlowSeedCapture) {
	t0 := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

	captures := []FlowCapture{
		requestFlowTestCapture("aaaaaaaa-0000-4000-8000-000000000001",
			"GET", "https://app.example.com/dashboard/tickets", "document", 200, false, t0),
		requestFlowTestCapture("aaaaaaaa-0000-4000-8000-000000000002",
			"GET", "https://cdn.example.com/static/app.js", "script", 200, false, t0.Add(90*time.Millisecond)),
		requestFlowTestCapture("aaaaaaaa-0000-4000-8000-000000000003",
			"GET", "https://api.example.com/v1/tickets?page=1", "xhr", 200, false, t0.Add(300*time.Millisecond)),
		requestFlowTestCapture("aaaaaaaa-0000-4000-8000-000000000004",
			"POST", "https://api.example.com/v1/tickets/new", "fetch", 302, true, t0.Add(900*time.Millisecond)),
		requestFlowTestCapture("aaaaaaaa-0000-4000-8000-000000000005",
			"GET", "https://cdn.example.com/static/logo.png", "image", 200, false, t0.Add(1200*time.Millisecond)),
	}

	detail := map[string]requestFlowSeedCapture{
		captures[0].ID: {
			ID: captures[0].ID, Method: "GET", URL: captures[0].URL,
			Headers: map[string]interface{}{"Accept": "text/html", "Cookie": "session=abc123"},
		},
		captures[1].ID: {
			ID: captures[1].ID, Method: "GET", URL: captures[1].URL,
			Headers: map[string]interface{}{"Accept": "*/*"},
		},
		captures[2].ID: {
			ID: captures[2].ID, Method: "GET", URL: captures[2].URL,
			Headers: map[string]interface{}{"Accept": "application/json", "Authorization": "Bearer tok"},
		},
		captures[3].ID: {
			ID: captures[3].ID, Method: "POST", URL: captures[3].URL,
			Headers: map[string]interface{}{"Content-Type": "application/json"},
			Body:    `{"subject":"broken","account_id":"9182734"}`,
		},
		captures[4].ID: {
			ID: captures[4].ID, Method: "GET", URL: captures[4].URL,
			Headers: map[string]interface{}{"Accept": "image/*"},
		},
	}

	return captureFlow{Captures: captures, RootKind: flowRootNavigation}, detail
}

// requestFlowWriteVerbFlow is a flow made of the verbs a builder used to disarm: one read and four
// writes, every one of them carrying the body that was recorded.
func requestFlowWriteVerbFlow() (captureFlow, map[string]requestFlowSeedCapture) {
	t0 := time.Date(2026, 3, 4, 10, 0, 0, 0, time.UTC)

	specs := []struct {
		id, method, url, body string
	}{
		{"bbbbbbbb-0000-4000-8000-000000000001", "GET", "https://app.example.com/basket", ""},
		{"bbbbbbbb-0000-4000-8000-000000000002", "POST", "https://api.example.com/v1/basket/items", `{"sku":"A1"}`},
		{"bbbbbbbb-0000-4000-8000-000000000003", "PUT", "https://api.example.com/v1/basket/items/1", `{"qty":2}`},
		{"bbbbbbbb-0000-4000-8000-000000000004", "PATCH", "https://api.example.com/v1/basket", `{"note":"x"}`},
		{"bbbbbbbb-0000-4000-8000-000000000005", "DELETE", "https://api.example.com/v1/basket/items/1", ""},
	}

	captures := make([]FlowCapture, 0, len(specs))
	detail := map[string]requestFlowSeedCapture{}
	for i, s := range specs {
		kind := "fetch"
		if i == 0 {
			kind = "document"
		}
		captures = append(captures, requestFlowTestCapture(s.id, s.method, s.url, kind, 200,
			s.body != "", t0.Add(time.Duration(i*100)*time.Millisecond)))
		detail[s.id] = requestFlowSeedCapture{
			ID: s.id, Method: s.method, URL: s.url,
			Headers: map[string]interface{}{"Content-Type": "application/json"},
			Body:    s.body,
		}
	}

	return captureFlow{Captures: captures, RootKind: flowRootNavigation}, detail
}

func mustParseRequestFlowStep(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("seeded step does not parse as an HTTP request: %v\n---\n%s\n---", err, raw)
	}
	return req
}

// ---------------------------------------------------------------------------
// Seeding from a detected flow
// ---------------------------------------------------------------------------

// The headline case. The operator detected a flow and pressed "build from this flow". What comes
// back has to BE that flow: the same requests, in the same order, as sendable bytes.
func TestRequestFlowBuilderSeedsDetectedFlowInOrder(t *testing.T) {
	flow, detail := requestFlowTestFlow()

	steps := seedStepsFromFlow(flow, detail, false, nil)

	// The default selection mirrors the diagram: root, xhr, the POST. The script and the image are
	// the 90% of the corpus the flow view hides, and seeding them would hand back a flow that does
	// not resemble the one the operator picked.
	wantCaptures := []string{
		"aaaaaaaa-0000-4000-8000-000000000001",
		"aaaaaaaa-0000-4000-8000-000000000003",
		"aaaaaaaa-0000-4000-8000-000000000004",
	}
	if len(steps) != len(wantCaptures) {
		var got []string
		for _, s := range steps {
			got = append(got, s.Name)
		}
		t.Fatalf("seeded %d steps (%v), want %d", len(steps), got, len(wantCaptures))
	}
	for i, want := range wantCaptures {
		if steps[i].SourceCaptureID != want {
			t.Errorf("step %d came from capture %s, want %s (order does not match the flow)",
				i+1, steps[i].SourceCaptureID, want)
		}
	}

	wantNames := []string{
		"GET /dashboard/tickets",
		"GET /v1/tickets",
		"POST /v1/tickets/new",
	}
	for i, want := range wantNames {
		if steps[i].Name != want {
			t.Errorf("step %d is named %q, want %q", i+1, steps[i].Name, want)
		}
	}

	// Every seeded step has to be sendable. A step that will not parse is a step the operator finds
	// out about when the whole replay stops on it.
	for i, s := range steps {
		req := mustParseRequestFlowStep(t, s.RawRequest)
		if req.Host == "" {
			t.Errorf("step %d has no Host header, so there is nowhere to send it", i+1)
		}
	}

	// The request line has to survive intact, query string included: an XHR whose ?page=1 was
	// dropped is a different request from the one that was recorded.
	xhr := mustParseRequestFlowStep(t, steps[1].RawRequest)
	if xhr.URL.RequestURI() != "/v1/tickets?page=1" {
		t.Errorf("xhr step targets %q, want /v1/tickets?page=1", xhr.URL.RequestURI())
	}
	if xhr.Host != "api.example.com" {
		t.Errorf("xhr step Host is %q, want api.example.com", xhr.Host)
	}
	if xhr.Header.Get("Authorization") != "Bearer tok" {
		t.Errorf("xhr step lost its Authorization header")
	}
}

// include_all is the same escape hatch show_all is on the diagram: the operator asked for the
// subresources, so they get them, still in flow order.
func TestRequestFlowBuilderIncludeAllSeedsEveryRequest(t *testing.T) {
	flow, detail := requestFlowTestFlow()

	steps := seedStepsFromFlow(flow, detail, true, nil)
	if len(steps) != 5 {
		t.Fatalf("include_all seeded %d steps, want all 5", len(steps))
	}
	for i, s := range steps {
		if s.SourceCaptureID != flow.Captures[i].ID {
			t.Errorf("step %d came from %s, want %s", i+1, s.SourceCaptureID, flow.Captures[i].ID)
		}
	}
}

// An explicit selection beats the noise filter. The operator ticked a stylesheet on purpose; second
// guessing that would drop a request they deliberately chose.
//
// The order is still the FLOW's order, not the order the ids happened to arrive in.
func TestRequestFlowBuilderExplicitSelectionKeepsFlowOrder(t *testing.T) {
	flow, detail := requestFlowTestFlow()

	only := map[string]bool{
		"aaaaaaaa-0000-4000-8000-000000000004": true, // the POST, last in the flow
		"aaaaaaaa-0000-4000-8000-000000000002": true, // the script, second in the flow
	}
	steps := seedStepsFromFlow(flow, detail, false, only)

	if len(steps) != 2 {
		t.Fatalf("selected 2 captures, got %d steps", len(steps))
	}
	if steps[0].SourceCaptureID != "aaaaaaaa-0000-4000-8000-000000000002" {
		t.Errorf("first step is %s, want the script (it is earlier in the flow)", steps[0].SourceCaptureID)
	}
	if steps[1].SourceCaptureID != "aaaaaaaa-0000-4000-8000-000000000004" {
		t.Errorf("second step is %s, want the POST", steps[1].SourceCaptureID)
	}
}

// A capture the detector listed but whose bytes could not be loaded is skipped, not emitted as an
// empty step. An empty step in the middle of a flow breaks the ordering the operator relies on and
// stops the replay on a request that never existed.
func TestRequestFlowBuilderSkipsCapturesWithNoBytes(t *testing.T) {
	flow, detail := requestFlowTestFlow()
	delete(detail, "aaaaaaaa-0000-4000-8000-000000000003")

	steps := seedStepsFromFlow(flow, detail, false, nil)
	if len(steps) != 2 {
		t.Fatalf("got %d steps, want 2 (the xhr's bytes are gone)", len(steps))
	}
	for _, s := range steps {
		if strings.TrimSpace(s.RawRequest) == "" {
			t.Errorf("a step was seeded with no request in it")
		}
		if s.SourceCaptureID == "aaaaaaaa-0000-4000-8000-000000000003" {
			t.Errorf("the capture with no bytes was still turned into a step")
		}
	}
}

// ---------------------------------------------------------------------------
// A capture round-trips through http.ReadRequest
// ---------------------------------------------------------------------------

// The bytes are the product. A step seeded from a capture is what the operator edits and what the
// transport sends, and http.ReadRequest is the exact parser sendRawRequest uses, so if it will not
// read it back the step cannot be sent at all.
func TestRequestFlowBuilderSeededStepRoundTripsThroughReadRequest(t *testing.T) {
	body := `{"subject":"broken","account_id":"9182734"}`
	seed := requestFlowSeedCapture{
		ID:     "aaaaaaaa-0000-4000-8000-000000000004",
		Method: "POST",
		URL:    "https://api.example.com/v1/tickets/new?draft=1",
		Headers: map[string]interface{}{
			"Content-Type":  "application/json",
			"Authorization": "Bearer tok",
			"Cookie":        "session=abc123",
		},
		Body: body,
	}

	step := requestFlowSeedStep(seed)
	req := mustParseRequestFlowStep(t, step.RawRequest)

	if req.Method != "POST" {
		t.Errorf("method came back as %q, want POST", req.Method)
	}
	if req.Host != "api.example.com" {
		t.Errorf("Host came back as %q, want api.example.com", req.Host)
	}
	if req.URL.RequestURI() != "/v1/tickets/new?draft=1" {
		t.Errorf("target came back as %q, want /v1/tickets/new?draft=1", req.URL.RequestURI())
	}

	// The body is the part that goes wrong silently. http.ReadRequest will not read one without a
	// Content-Length, so a step with the header missing is stored, sent empty, answered 400 by the
	// target, and the target gets the blame.
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("reading the body back failed: %v", err)
	}
	if string(got) != body {
		t.Errorf("body came back as %q, want %q", string(got), body)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length is %d, want %d", req.ContentLength, len(body))
	}
	if req.Header.Get("Authorization") != "Bearer tok" {
		t.Errorf("Authorization header did not survive")
	}
}

// BuildRawHTTPRequest's output must NOT be run through normalizeRawRequest on the way in.
//
// The normalizer replaces every \r\n in the WHOLE string, body included, and then recomputes the
// length from the shortened bytes: self-consistent and corrupt. On a multipart body that rewrites
// every boundary, and the step stops being the request that was captured.
func TestRequestFlowBuilderKeepsMultipartBodyByteForByte(t *testing.T) {
	body := "------b\r\nContent-Disposition: form-data; name=\"f\"; filename=\"a.txt\"\r\n\r\nhi\r\n------b--\r\n"
	seed := requestFlowSeedCapture{
		ID:      "aaaaaaaa-0000-4000-8000-000000000009",
		Method:  "POST",
		URL:     "https://api.example.com/upload",
		Headers: map[string]interface{}{"Content-Type": "multipart/form-data; boundary=----b"},
		Body:    body,
	}

	step := requestFlowSeedStep(seed)
	req := mustParseRequestFlowStep(t, step.RawRequest)

	got, _ := io.ReadAll(req.Body)
	if string(got) != body {
		t.Errorf("multipart body was rewritten.\n got %q\nwant %q", string(got), body)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length is %d, want %d; a length that disagrees with the body truncates it",
			req.ContentLength, len(body))
	}
}

// ---------------------------------------------------------------------------
// Seeding arms every step, whatever its verb
// ---------------------------------------------------------------------------

// THE GUARANTEE THIS TEST EXISTS TO PIN. A step seeded from a capture arrives ENABLED, and the verb
// has nothing to do with it.
//
// This used to be the other way round: a seeded POST arrived turned off, so an operator who imported
// a flow and pressed Replay got a run in which the login submitted nothing, the basket never filled
// and every step after it answered as an anonymous user, while reporting green. A flow whose writes
// arrive disabled proves nothing when it passes. If a future edit reintroduces a verb branch in
// seeding, this fails.
func TestRequestFlowBuilderSeedsEveryVerbEnabled(t *testing.T) {
	flow, detail := requestFlowWriteVerbFlow()

	steps := seedStepsFromFlow(flow, detail, true, nil)
	if len(steps) != 5 {
		t.Fatalf("expected all 5 captures to seed, got %d", len(steps))
	}

	seen := map[string]bool{}
	for _, s := range steps {
		method := requestFlowMethodOf(s.RawRequest)
		seen[method] = true
		if !s.Enabled {
			t.Errorf("%s (%s) arrived turned OFF. Seeding must arm every step it creates; the verb "+
				"is the operator's business and the scope rails are the control.", s.Name, method)
		}
	}
	for _, want := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
		if !seen[want] {
			t.Errorf("the fixture must exercise %s", want)
		}
	}
}

// A hand-added step is armed too, and an explicit enabled:false is still honoured. That switch is
// the operator's and it is the only thing that turns a step off.
func TestRequestFlowBuilderSeededStepIsArmed(t *testing.T) {
	seed := requestFlowSeedCapture{
		ID:      "aaaaaaaa-0000-4000-8000-00000000000a",
		Method:  "DELETE",
		URL:     "https://api.example.com/v1/accounts/9182734",
		Headers: map[string]interface{}{"Authorization": "Bearer tok"},
	}
	if step := requestFlowSeedStep(seed); !step.Enabled {
		t.Error("a seeded DELETE must arrive armed")
	}
}

func TestRequestFlowBuilderReadsTheVerbOffUnparseableBytes(t *testing.T) {
	// Mid-edit bytes that http.ReadRequest would refuse. The verb still has to be readable, because
	// it is what labels the step and what the preview shows.
	cases := map[string]string{
		"DELETE /v1/accounts/9182734 HTTP/1.1\r\nHost: api.example.com": "DELETE",
		"post /v1/otp/send HTTP/1.1\nHost: api.example.com\nContent-Le": "POST",
		"PATCH /v1/profile": "PATCH",
		"GET /v1/tickets?page=1 HTTP/1.1\r\nHost: api.example.com\r\n\r\n": "GET",
		"PROPFIND /dav/ HTTP/1.1\r\nHost: api.example.com":                 "PROPFIND",
		"HEAD /":  "HEAD",
		"OPTIONS": "OPTIONS",
	}
	for raw, want := range cases {
		if got := requestFlowMethodOf(raw); got != want {
			t.Errorf("requestFlowMethodOf(%q) = %q, want %q", raw, got, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Reorder
// ---------------------------------------------------------------------------

func requestFlowTestIDs() []string {
	return []string{"s1", "s2", "s3", "s4", "s5"}
}

// Stability means three things, and all three are the difference between a reorder and a data loss.
func TestRequestFlowBuilderReorderIsStable(t *testing.T) {
	current := requestFlowTestIDs()

	// 1. A no-op reorder is a no-op.
	same, err := resolveStepOrder(current, []string{"s1", "s2", "s3", "s4", "s5"})
	if err != nil {
		t.Fatalf("reordering to the current order failed: %v", err)
	}
	if strings.Join(same, ",") != "s1,s2,s3,s4,s5" {
		t.Errorf("a no-op reorder produced %v", same)
	}

	// 2. Moving one step leaves every other step's relative order alone.
	moved, err := resolveStepOrder(current, []string{"s1", "s4", "s2", "s3", "s5"})
	if err != nil {
		t.Fatalf("reorder failed: %v", err)
	}
	if strings.Join(moved, ",") != "s1,s4,s2,s3,s5" {
		t.Errorf("reorder produced %v, want [s1 s4 s2 s3 s5]", moved)
	}

	// 3. Applying the same desired order twice gives the same answer. A reorder that is not
	// idempotent drifts every time a client re-sends what it is already showing.
	again, err := resolveStepOrder(moved, []string{"s1", "s4", "s2", "s3", "s5"})
	if err != nil {
		t.Fatalf("re-applying the same order failed: %v", err)
	}
	if strings.Join(again, ",") != strings.Join(moved, ",") {
		t.Errorf("re-applying the same order changed it: %v then %v", moved, again)
	}
}

// A partial list is refused rather than quietly appending the rest.
//
// "The ids you named go first, the rest keep their relative order behind them" is the tempting
// alternative and it silently moves steps the operator never touched: send four of eleven and seven
// steps jump to the end of a flow whose whole meaning is its order.
func TestRequestFlowBuilderReorderRefusesAPartialList(t *testing.T) {
	_, err := resolveStepOrder(requestFlowTestIDs(), []string{"s3", "s1"})
	if err == nil {
		t.Fatal("a partial order was accepted; the three unnamed steps would have moved silently")
	}
	// The message has to name what was left out. "you sent 2 of 5" leaves the operator to work out
	// which three.
	for _, want := range []string{"s2", "s4", "s5"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name the missing step %s: %v", want, err)
		}
	}
}

func TestRequestFlowBuilderReorderRefusesDuplicatesAndStrangers(t *testing.T) {
	if _, err := resolveStepOrder(requestFlowTestIDs(),
		[]string{"s1", "s2", "s2", "s3", "s4", "s5"}); err == nil {
		t.Error("a duplicated step id was accepted, so one step had two positions")
	}
	if _, err := resolveStepOrder(requestFlowTestIDs(),
		[]string{"s1", "s2", "s3", "s4", "s5", "s9"}); err == nil {
		t.Error("a step from another flow was accepted into this one's order")
	}
	if _, err := resolveStepOrder(requestFlowTestIDs(),
		[]string{"s1", "", "s2", "s3", "s4", "s5"}); err == nil {
		t.Error("an empty step id was accepted")
	}
}

// The move form is the same permutation, expressed as a gesture.
func TestRequestFlowBuilderMoveStepIsAPermutation(t *testing.T) {
	cases := []struct {
		name string
		id   string
		to   int
		want string
	}{
		{"to the front", "s4", 1, "s4,s1,s2,s3,s5"},
		{"to the end", "s2", 5, "s1,s3,s4,s5,s2"},
		{"one up", "s3", 2, "s1,s3,s2,s4,s5"},
		{"onto itself", "s3", 3, "s1,s2,s3,s4,s5"},
		// Dragged past the end is a gesture, not an error; clamping is what the operator meant.
		{"past the end", "s1", 99, "s2,s3,s4,s5,s1"},
		{"before the start", "s5", -3, "s5,s1,s2,s3,s4"},
	}

	for _, tc := range cases {
		got, err := moveStepOrder(requestFlowTestIDs(), tc.id, tc.to)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if strings.Join(got, ",") != tc.want {
			t.Errorf("%s: got %v, want %s", tc.name, got, tc.want)
		}
		if len(got) != len(requestFlowTestIDs()) {
			t.Errorf("%s: a move changed the number of steps from %d to %d",
				tc.name, len(requestFlowTestIDs()), len(got))
		}
	}

	if _, err := moveStepOrder(requestFlowTestIDs(), "s9", 1); err == nil {
		t.Error("moving a step that is not in the flow was accepted")
	}
}

// ---------------------------------------------------------------------------
// Scope
// ---------------------------------------------------------------------------

// scope_target_scope_hosts carries in_scope=false rows the operator put there on purpose, and a
// step resolving to one of them must never be sent. The refusal has to name the host and the
// boundary, because "not sent" with no reason is how an operator concludes the feature is broken.
func TestRequestFlowBuilderRefusesAnOutOfScopeStep(t *testing.T) {
	scope := &ScanScope{
		domains: map[string]bool{},
		extra:   map[string]bool{},
		refused: map[string]int{},
		primary: "app.example.com",
	}
	scope.Allow("example.com")

	inScope := "GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	if host, refusal := requestFlowScopeRefusal(inScope, "", flowSendRails{Scope: scope}); refusal != "" {
		t.Errorf("an in-scope step was refused (host %q): %s", host, refusal)
	}

	outOfScope := "GET /collect HTTP/1.1\r\nHost: analytics.thirdparty.io\r\n\r\n"
	host, refusal := requestFlowScopeRefusal(outOfScope, "", flowSendRails{Scope: scope})
	if refusal == "" {
		t.Fatal("a step aimed at a third-party host was allowed through")
	}
	if host != "analytics.thirdparty.io" {
		t.Errorf("the refusal blames host %q, want analytics.thirdparty.io", host)
	}
	if !strings.Contains(refusal, "analytics.thirdparty.io") || !strings.Contains(refusal, "example.com") {
		t.Errorf("the refusal names neither the host nor the boundary: %s", refusal)
	}
}

// Removing the verb gate must not have opened the scope gate. A DELETE, a POST and a PUT aimed at a
// host outside the boundary or on the operator's deny list are refused exactly as a GET is, and the
// preview says so before anything is sent.
func TestRequestFlowBuilderStillRefusesWriteStepsOutsideTheBoundary(t *testing.T) {
	scope := &ScanScope{
		domains: map[string]bool{},
		extra:   map[string]bool{},
		refused: map[string]int{},
		primary: "app.example.com",
	}
	scope.Allow("example.com")
	rails := flowSendRails{Scope: scope, Denied: map[string]bool{"analytics.example.com": true}}

	steps := []RequestFlowStep{
		{ID: "s1", StepOrder: 1, Name: "in scope write", Enabled: true,
			RawRequest: "POST /v1/basket HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 3\r\n\r\na=1"},
		{ID: "s2", StepOrder: 2, Name: "offsite write", Enabled: true,
			RawRequest: "DELETE /v1/accounts/1 HTTP/1.1\r\nHost: api.thirdparty.io\r\n\r\n"},
		{ID: "s3", StepOrder: 3, Name: "denied host write", Enabled: true,
			RawRequest: "PUT /v1/e HTTP/1.1\r\nHost: analytics.example.com\r\nContent-Length: 3\r\n\r\na=1"},
	}

	rows := requestFlowPreview(steps, "", rails)

	if rows[0].Refusal != "" || !rows[0].InScope {
		t.Fatalf("an in-scope POST must be sendable: %+v", rows[0])
	}
	for _, i := range []int{1, 2} {
		if rows[i].Refusal == "" || rows[i].InScope {
			t.Fatalf("%s (%s) was going to be SENT. The scope rails are the control and they must "+
				"still refuse a write: %+v", rows[i].Name, rows[i].Method, rows[i])
		}
	}
}

// A step with no Host header and no flow base URL has nowhere to go. Sending it somewhere guessed at
// is the one outcome that is worse than refusing it.
func TestRequestFlowBuilderRefusesAStepWithNoDestination(t *testing.T) {
	scope := &ScanScope{
		domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{},
		primary: "app.example.com",
	}
	if _, refusal := requestFlowScopeRefusal("GET /dashboard HTTP/1.1\r\n\r\n", "",
		flowSendRails{Scope: scope}); refusal == "" {
		t.Error("a step with no Host header and no base URL was allowed through")
	}
	// The flow's base URL is the documented fallback for exactly this, so it has to work.
	if _, refusal := requestFlowScopeRefusal("GET /dashboard HTTP/1.1\r\n\r\n",
		"https://app.example.com", flowSendRails{Scope: scope}); refusal != "" {
		t.Errorf("base_url did not stand in for the missing Host header: %s", refusal)
	}
}

// The preview is the dry run, and it must agree with the send about every step, because a preview
// that says one thing and a replay that does another is worse than no preview.
func TestRequestFlowBuilderPreviewMatchesWhatWouldBeSent(t *testing.T) {
	scope := &ScanScope{
		domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{},
		primary: "app.example.com",
	}
	scope.Allow("example.com")

	steps := []RequestFlowStep{
		{ID: "s1", StepOrder: 1, Name: "login",
			RawRequest: "GET /login HTTP/1.1\r\nHost: app.example.com\r\n\r\n", Enabled: true},
		{ID: "s2", StepOrder: 2, Name: "send code",
			RawRequest: "POST /otp/send HTTP/1.1\r\nHost: app.example.com\r\nContent-Length: 9\r\n\r\n{\"a\":\"1\"}",
			Enabled:    false},
		{ID: "s3", StepOrder: 3, Name: "third party",
			RawRequest: "GET /collect HTTP/1.1\r\nHost: analytics.thirdparty.io\r\n\r\n", Enabled: true},
		{ID: "s4", StepOrder: 4, Name: "uses a capture",
			RawRequest: "GET /me HTTP/1.1\r\nHost: app.example.com\r\nX-Csrf: {{af:csrf}}\r\n\r\n",
			Enabled:    true},
	}

	rows := requestFlowPreview(steps, "", flowSendRails{Scope: scope})
	if len(rows) != 4 {
		t.Fatalf("preview returned %d rows for 4 steps", len(rows))
	}

	if rows[0].Refusal != "" || !rows[0].InScope {
		t.Errorf("step 1 should go out as a plain in-scope GET, got %+v", rows[0])
	}
	if rows[1].Method != "POST" {
		t.Errorf("the preview must report the verb it read off the bytes, got %q", rows[1].Method)
	}
	if rows[1].Refusal == "" {
		t.Errorf("step 2 is turned off and the preview did not say it would be skipped")
	}
	if !rows[1].InScope {
		t.Errorf("step 2 is turned off, not out of scope; the two must not be confused: %+v", rows[1])
	}
	if rows[2].InScope || rows[2].Refusal == "" {
		t.Errorf("step 3 is out of scope and the preview did not refuse it: %+v", rows[2])
	}
	// The placeholders a step depends on belong in the dry run: they are the usual reason a flow
	// stops halfway, and the operator can see the wiring before spending a request finding out.
	if len(rows[3].Placeholders) != 1 || rows[3].Placeholders[0] != "csrf" {
		t.Errorf("step 4's {{af:csrf}} placeholder was not reported: %v", rows[3].Placeholders)
	}

	// "hosts" on a dry run reads as "the machines about to be contacted", so the third-party host
	// this run is going to refuse must not appear in it.
	hosts := sortedRequestFlowHosts(rows)
	if strings.Join(hosts, ",") != "app.example.com" {
		t.Errorf("preview hosts are %v, want only app.example.com; a refused or disabled step's "+
			"host in this list claims traffic that will not be sent", hosts)
	}
}

// ---------------------------------------------------------------------------
// The variable machinery is shared, not reimplemented
// ---------------------------------------------------------------------------

// A builder step goes through exactly the same prepareStepRequest the auth flow replay uses, so
// substitution, body-aware encoding and the Content-Length repair are not a second implementation
// that can drift. This asserts the seam rather than the internals.
func TestRequestFlowBuilderStepUsesTheSharedSubstitution(t *testing.T) {
	raw := "POST /login HTTP/1.1\r\nHost: app.example.com\r\n" +
		"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\n\r\n" +
		"csrf={{af:csrf}}"

	out, used, refusal := prepareStepRequest(raw, map[string]string{"csrf": "a b&c=d"})
	if refusal != "" {
		t.Fatalf("a resolvable placeholder was refused: %s", refusal)
	}
	if len(used) != 1 || used[0] != "csrf" {
		t.Errorf("substitution reported %v, want [csrf]", used)
	}

	req := mustParseRequestFlowStep(t, out)
	body, _ := io.ReadAll(req.Body)
	// Form encoded, because the placeholder sits in a form body: dropped in raw, the & and = would
	// have broken the body and the target would answer with an application error.
	if string(body) != "csrf=a+b%26c%3Dd" {
		t.Errorf("body is %q, want the value form-encoded", string(body))
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length is %d but the substituted body is %d bytes; a stale length truncates it",
			req.ContentLength, len(body))
	}

	// An unresolved placeholder is refused rather than sent as a literal {{af:csrf}}.
	if _, _, refusal := prepareStepRequest(raw, map[string]string{}); refusal == "" {
		t.Error("a step with no captured value for its placeholder was allowed to send")
	}
}

// ---------------------------------------------------------------------------
// The two rails the builder was measured walking straight through
// ---------------------------------------------------------------------------

// A host marked in_scope=false is NOT covered by ScanScope.Allows when it also sits inside the
// target's registrable domain: the *.example.com rule admits it independently of the crawl list. So
// the deny list has to be a separate check, and this is the one that proves it.
//
// Measured before the fix, against a listener on the compose network: a built step for
// denied.flowlab.test, marked in_scope=false on a target scoped to app.flowlab.test, was dialled.
func TestRequestFlowBuilderRefusesADeniedHostInsideTheBoundary(t *testing.T) {
	scope := &ScanScope{
		domains: map[string]bool{"example.com": true},
		extra:   map[string]bool{}, refused: map[string]int{},
		primary: "app.example.com",
	}
	denied := "GET /anything HTTP/1.1\r\nHost: analytics.example.com\r\n\r\n"

	// The precondition, stated out loud: the boundary alone lets this through.
	if !scope.Allows("analytics.example.com") {
		t.Fatal("precondition failed: the boundary was expected to admit the denied host")
	}

	rails := flowSendRails{Scope: scope, Denied: map[string]bool{"analytics.example.com": true}}
	host, refusal := requestFlowScopeRefusal(denied, "", rails)
	if refusal == "" {
		t.Fatal("a host marked in_scope=false was allowed through by the builder")
	}
	if host != "analytics.example.com" || !strings.Contains(refusal, "marked out of scope") {
		t.Errorf("the refusal does not say the host was denied: host=%q %s", host, refusal)
	}

	// And the parent walk, so excluding example.com covers tracking.example.com.
	parentRails := flowSendRails{Scope: scope, Denied: map[string]bool{"example.com": true}}
	if _, r := requestFlowScopeRefusal(denied, "", parentRails); r == "" {
		t.Error("a denied parent domain did not cover its subdomain")
	}
}

// The exclusion list is the operator's own tool. Active detection refuses a match and so does the
// detected-flow runner; the builder used not to read the list at all, and a replay of /admin/danger
// under an exclusion of /admin/* was wire-confirmed reaching the listener.
func TestRequestFlowBuilderRefusesAnExcludedURL(t *testing.T) {
	scope := &ScanScope{
		domains: map[string]bool{}, extra: map[string]bool{}, refused: map[string]int{},
		primary: "app.example.com",
	}
	rules := []FlowExclusion{{Pattern: "/admin/*", Reason: "never touch admin"}}
	rails := flowSendRails{Scope: scope, Denied: map[string]bool{}, Exclusions: rules}

	excluded := "GET /admin/danger HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	_, refusal := requestFlowScopeRefusal(excluded, "", rails)
	if refusal == "" {
		t.Fatal("an excluded URL was allowed through by the builder")
	}
	if !strings.Contains(refusal, "/admin/*") || !strings.Contains(refusal, "never touch admin") {
		t.Errorf("the refusal names neither the rule nor the operator's reason: %s", refusal)
	}

	// The rule is judged on the PATH, so a step on the same host outside it still sends.
	allowed := "GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
	if _, r := requestFlowScopeRefusal(allowed, "", rails); r != "" {
		t.Errorf("a URL no rule covers was refused: %s", r)
	}
}

// The exclusion match needs the whole URL, not the host, or every path rule matches nothing.
func TestRequestFlowStepURLCarriesThePath(t *testing.T) {
	got := requestFlowStepURL("GET /admin/danger?x=1 HTTP/1.1\r\nHost: app.example.com\r\n\r\n", "")
	if got != "https://app.example.com/admin/danger?x=1" {
		t.Errorf("step URL is %q, want the scheme, host, path and query", got)
	}
	// base_url is the fallback for a step with no Host header, and it must keep its scheme and port.
	got = requestFlowStepURL("GET /admin/danger HTTP/1.1\r\n\r\n", "http://app.example.com:8080")
	if got != "http://app.example.com:8080/admin/danger" {
		t.Errorf("step URL is %q, want base_url's scheme and port preserved", got)
	}
}

// A rails load that failed must refuse everything rather than render a preview of green ticks. An
// empty exclusion list substituted for an unreadable one is how the operator's "this endpoint texts
// a real customer" rule is lost to a transient database error.
// EVERYTHING means every verb. Now that nothing narrows a run by verb, a write is not held back by
// some second rail of its own: this one has to catch it, so a DELETE is checked alongside the read.
func TestRequestFlowUnreadableRailsRefuseEverything(t *testing.T) {
	rails := flowSendRails{Unreadable: "the exclusion list could not be read"}

	for _, raw := range []string{
		"GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
		"DELETE /api/orders/7 HTTP/1.1\r\nHost: app.example.com\r\n\r\n",
	} {
		verb := strings.SplitN(raw, " ", 2)[0]
		_, refusal := requestFlowScopeRefusal(raw, "", rails)
		if refusal == "" {
			t.Fatalf("a %s step was allowed through while the rails were unreadable", verb)
		}
		if !strings.Contains(refusal, "could not be read") {
			t.Errorf("the %s refusal does not say why: %s", verb, refusal)
		}
	}

	// And the same through the preview the operator actually reads, where a refused step must not
	// also be reporting itself in scope.
	steps := []RequestFlowStep{
		{ID: "w1", StepOrder: 1, Name: "delete", Enabled: true,
			RawRequest: "DELETE /api/orders/7 HTTP/1.1\r\nHost: app.example.com\r\n\r\n"},
	}
	for _, row := range requestFlowPreview(steps, "https://app.example.com", rails) {
		if row.Refusal == "" {
			t.Fatalf("%s was previewed as sendable while the rails were unreadable", row.Method)
		}
		if row.InScope {
			t.Errorf("%s reports in_scope=true while the rails could not be read", row.Method)
		}
	}
}
