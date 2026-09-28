package utils

// THE CONFUSION MATRIX. Every route the oracle serves for the newest five classes and the newest
// four arms, crossed with EVERY REGISTERED CLASS, in one run per insertion point.
//
// WHY THIS FILE EXISTS SEPARATELY FROM triageRun_test.go. That test runs the whole registry
// against THREE vectors, all of them insertion_point='query', on /ssti, /xss and the static
// index. It answers "does every class say what it did". It cannot answer the two questions this
// round was set to answer:
//
//  1. Does a class that fires on its own positive route stay SILENT on the route built to keep it
//     silent? A positive fixture only shows a detector can fire. It is the negative that says the
//     detector measures what it claims to. Nine of the routes below exist only to be negatives.
//
//  2. On a JSON REST API THAT ECHOES NOTHING, how many classes can reach a conclusion at all?
//     That is the shape of the operator's real target and, before the non-reflective arms landed,
//     the answer was two of fourteen. /api/items is that shape and it is in every run below.
//
// AND THE THIRD QUESTION, WHICH IS THE ONE THAT BITES. A shipped class that regressed because a
// new class landed beside it is the worst outcome available in this round, and it is invisible to
// any test that only exercises the new classes. So every class is enabled on every route, and the
// matrix is printed whole rather than filtered to the interesting cells.
//
// THIS TEST IS A MEASUREMENT AND ONLY ASSERTS WHAT CANNOT BE A JUDGEMENT CALL. It fails on a
// finding against /api/items, which is a benign endpoint that reads its parameters and shows
// nothing, and on a vector that produced no verdict at all. Everything else is logged, because a
// cell that disagrees with a class's own OracleCases is a result to read rather than a red test
// to satisfy: the declaration is a class author's prediction and this file is the measurement.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"ars0n-framework-v2-server/utils/triage"
)

// r4Route is one row of the corpus this test builds. Kind is the insertion point, which decides
// which classes can reach it at all: SlotsFor dispatches on that column, so a query vector yields
// query slots and NOTHING ELSE, and the first header-only classes in the register (CORS and
// HOSTHDR) are unreachable from a query vector however they are configured.
type r4Route struct {
	Path  string
	Param string
	Kind  triage.SlotKind
	// Query is the evidence URL's query string when it must be something other than Param=hello.
	// HPP arm D is the reason: its eligibility is read off the composed URL and it needs the
	// parameter to appear TWICE, which is a property of the capture and not of a payload.
	Query string
	// Body and CType make a request with a JSON document in it, which is the only way to reach
	// PP-SERVER: all six of its probes are json_node_replace on a body node.
	Body  string
	CType string
	Note  string
}

// r4QueryRoutes is the query-slot corpus: every new route that reads a query parameter, plus the
// three routes the previous matrix used, so a regression in a shipped class is a direct
// comparison and not a recollection.
func r4QueryRoutes() []r4Route {
	return []r4Route{
		{Path: "/api/items", Param: "q", Note: "THE OPERATOR'S SHAPE: JSON, echoes nothing, benign"},
		{Path: "/ssti", Param: "tpl", Note: "carried over from the previous matrix"},
		{Path: "/xss", Param: "q", Note: "carried over from the previous matrix"},
		{Path: "/", Param: "q", Note: "carried over from the previous matrix (static index)"},

		{Path: "/ssti/blind", Param: "q", Note: "SSTI blind arm, positive"},
		{Path: "/ssti/lengthecho", Param: "q", Note: "SSTI blind arm, THE false-positive mode"},
		{Path: "/eli/blind", Param: "q", Note: "ELI parse differential, positive"},

		{Path: "/trav/blind", Param: "file", Note: "TRAVERSAL blind three-way, positive"},
		{Path: "/trav/append", Param: "file", Note: "TRAVERSAL extension append"},
		{Path: "/trav/ignored", Param: "file", Note: "TRAVERSAL value-ignored control"},

		{Path: "/hpp/first", Param: "q", Query: "q=alpha&q=beta", Note: "HPP arm D, first wins"},
		{Path: "/hpp/last", Param: "q", Query: "q=alpha&q=beta", Note: "HPP arm D, THE negative"},
		{Path: "/hpp/arity", Param: "q", Query: "q=alpha&q=beta", Note: "HPP arm D, arity checked"},
		{Path: "/hpp/reparse", Param: "q", Note: "HPP arm S, ampersand"},
		{Path: "/hpp/semicolon", Param: "q", Note: "HPP arm S, semicolon"},

		{Path: "/orm/django", Param: "q", Note: "ORM LEAK, DEBUG=True positive"},
		{Path: "/orm/djangoprod", Param: "q", Note: "ORM LEAK, DEBUG=False degradation"},
		{Path: "/orm/othererror", Param: "q", Note: "ORM LEAK, THE negative: a real error naming someone else"},
	}
}

// r4HeaderRoutes is the header-slot corpus. Every one of these is unreachable from a query vector
// and every one of them was declared with Exists:false until this round.
func r4HeaderRoutes() []r4Route {
	k := triage.KindHeader
	return []r4Route{
		{Path: "/api/items", Param: "x-forwarded-host", Kind: k, Note: "THE OPERATOR'S SHAPE, on headers"},
		{Path: "/cors/reflect", Param: "origin", Kind: k, Note: "CORS positive, credentials"},
		{Path: "/cors/reflectnocreds", Param: "origin", Kind: k, Note: "CORS positive, no credentials"},
		{Path: "/cors/allowlist", Param: "origin", Kind: k, Note: "CORS THE negative: a correct API"},
		{Path: "/cors/null", Param: "origin", Kind: k, Note: "CORS null grant"},
		{Path: "/cors/rawecho", Param: "origin", Kind: k, Note: "CORS raw echo, no parse"},
		{Path: "/cors/starcreds", Param: "origin", Kind: k, Note: "CORS wildcard with credentials"},
		{Path: "/cors/portblind", Param: "origin", Kind: k, Note: "CORS hostname-only comparison"},
		{Path: "/cors/originlist", Param: "origin", Kind: k, Note: "CORS comma list, second entry"},
		{Path: "/cors/preset", Param: "origin", Kind: k, Note: "CORS signature in the baseline"},
		{Path: "/cors/cacheable", Param: "origin", Kind: k, Note: "CORS storable, nothing may be sent"},
		{Path: "/hosthdr/absurl", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR body authority"},
		{Path: "/hosthdr/location", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR 302 Location"},
		{Path: "/hosthdr/loc200", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR negative: Location on a 200"},
		{Path: "/hosthdr/echo", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR THE negative: reflected, not an authority"},
		{Path: "/hosthdr/originalurl", Param: "x-original-url", Kind: k, Note: "HOSTHDR URL-header family"},
		{Path: "/hosthdr/portconcat", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR raw concatenation"},
		{Path: "/hosthdr/nohttp", Param: "x-rewrite-url", Kind: k, Note: "HOSTHDR scheme blacklist"},
		{Path: "/hosthdr/wrapinert", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR control fires: detector_unverified"},
		{Path: "/hosthdr/cacheable", Param: "x-forwarded-host", Kind: k, Note: "HOSTHDR storable"},
	}
}

// r4BodyRoutes is the JSON-body corpus. PP-SERVER is the only class that needs it and the shape
// of the document matters: the probes replace a NODE, so there has to be an object node under a
// name for them to replace.
func r4BodyRoutes() []r4Route {
	const doc = `{"filters":{"category":"gin"},"page":2}`
	k := triage.KindBody
	return []r4Route{
		{Path: "/api/items", Kind: k, Body: doc, CType: "application/json", Note: "THE OPERATOR'S SHAPE, on a body"},
		{Path: "/pp/express", Kind: k, Body: doc, CType: "application/json", Note: "PP positive, __proto__"},
		{Path: "/pp/ctoronly", Kind: k, Body: doc, CType: "application/json", Note: "PP positive, constructor only"},
		{Path: "/pp/frozen", Kind: k, Body: doc, CType: "application/json", Note: "PP THE negative: the gadget cannot land"},
		{Path: "/pp/htmlonly", Kind: k, Body: doc, CType: "application/json", Note: "PP oracle unreadable"},
		{Path: "/pp/norestore", Kind: k, Body: doc, CType: "application/json", Note: "PP restore ignored"},
	}
}

// r4Target inserts one scope target and one attack vector per route, and removes all of it
// afterwards. It is a near-copy of triageOracleTarget on purpose: that helper hardcodes three
// query vectors and this test needs forty across three insertion points, and editing a helper
// another agent is actively working in would be the wrong kind of shared change.
func r4Target(t *testing.T, ctx context.Context, base string, routes []r4Route) (string, map[string]r4Route) {
	t.Helper()
	id := uuid.New().String()
	if _, err := dbPool.Exec(ctx,
		`INSERT INTO scope_targets (id, type, mode, scope_target, active) VALUES ($1, 'URL', 'Passive', $2, FALSE)`,
		id, base); err != nil {
		t.Fatalf("create scope target: %v", err)
	}
	t.Cleanup(func() {
		if os.Getenv("TRIAGE_TEST_KEEP") != "" {
			t.Logf("TRIAGE_TEST_KEEP is set, so scope target %s is left in the database", id)
			return
		}
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM scope_targets WHERE id = $1`, id); err != nil {
			t.Errorf("could not clean up scope target %s: %v", id, err)
		}
	})

	host, port, scheme := triageSplitBase(t, base)
	byID := map[string]r4Route{}
	for _, rt := range routes {
		kind := rt.Kind
		if kind == "" {
			kind = triage.KindQuery
		}
		query := rt.Query
		if query == "" && rt.Param != "" && kind == triage.KindQuery {
			query = rt.Param + "=hello"
		}
		if query == "" {
			query = "page=2"
		}
		evidence := base + rt.Path + "?" + query
		params := []string{}
		if rt.Param != "" {
			params = append(params, rt.Param)
		}
		method := "GET"
		raw := ""
		if rt.Body != "" {
			method = "POST"
			raw = fmt.Sprintf("POST %s?%s HTTP/1.1\r\nHost: %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n%s",
				rt.Path, query, host, rt.CType, len(rt.Body), rt.Body)
		}
		vectorID := uuid.New().String()
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO attack_vectors (id, scope_target_id, vector_key, method, scheme, domain, port,
			                            path, insertion_point, parameters, evidence_url, raw_request)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			vectorID, id, string(kind)+":"+rt.Path, method, scheme, host, port, rt.Path,
			string(kind), params, evidence, raw); err != nil {
			t.Fatalf("insert vector %s %s: %v", kind, rt.Path, err)
		}
		byID[vectorID] = rt
	}
	return id, byID
}

// r4Settings enables every class at its widest tier and gives the run enough budget to reach the
// arms that need it.
//
// PerSlotProbes IS RAISED TO 48 AND THAT IS NOT A CONVENIENCE. At the default of 24, SSTI's
// rounds 0 and 1 spend the whole allowance and its ten-request blind arm is never sent, so the
// arm this round exists to measure would have been measured at zero. The Untested row says so
// honestly at the default, which is the right behaviour on a real target and the wrong setting
// for the experiment.
func r4Settings(tier triage.ProbeTier) TriageInvestigateSettings {
	s := TriageSettingsDefaults()
	for key := range s.Classes {
		cs := s.Classes[key]
		cs.Enabled = true
		cs.Tier = string(tier)
		s.Classes[key] = cs
	}
	s.Tier = string(tier)
	// MEASURED, AND LOWERED AFTER THE FIRST RUN. At 120 requests per second with concurrency 8
	// the header corpus produced baseline_transport_proto on four of twenty routes and
	// transport_refused on several classes elsewhere: the run was outpacing the socat proxy in
	// front of the oracle and the layer correctly recorded "I could not measure this" rather than
	// a clean. Those cells are an artefact of the harness and not a result, which is exactly the
	// kind of thing that gets written into a report as a class defect if nobody re-runs it.
	s.Pacing.RequestsPerSecond = 35
	s.Pacing.Concurrency = 3
	s.Pacing.PerSlotProbes = 48
	s.Pacing.PerRunProbes = 200000
	s.Pacing.RespectTargetBudget = false
	return s
}

// r4Cell is one cell of the matrix: what one class concluded about one route.
type r4Cell struct {
	State  triage.TriageState
	Oracle string
	Grade  triage.TriageGrade
	Reason string
	Sent   int
}

// r4Run runs the whole registry over one corpus and returns route -> class -> cell.
func r4Run(t *testing.T, ctx context.Context, base string, routes []r4Route, tier triage.ProbeTier, label string) map[string]map[string]r4Cell {
	t.Helper()
	scopeTargetID, byID := r4Target(t, ctx, base, routes)
	triageSaveSettings(t, ctx, scopeTargetID, r4Settings(tier))

	started := time.Now()
	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("%s: start the run: %v", label, err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 45*time.Minute); status != "completed" {
		var runErr *string
		_ = dbPool.QueryRow(ctx, `SELECT error FROM triage_runs WHERE id = $1`, runUUID).Scan(&runErr)
		msg := ""
		if runErr != nil {
			msg = *runErr
		}
		t.Fatalf("%s: the run finished %q: %s", label, status, msg)
	}
	t.Logf("=== %s: %d routes, run %s, %s", label, len(routes), runUUID, time.Since(started).Round(time.Second))

	sentPair := map[string]int{}
	for _, c := range triageRunCoverageRows(t, ctx, runUUID) {
		sentPair[c.Class+"|"+c.VectorID] += c.Sent
	}
	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("%s: read verdicts: %v", label, err)
	}
	if len(verdicts) == 0 {
		t.Fatalf("%s: the run produced no verdict at all, which is the silent-zero shape this whole layer exists to stop", label)
	}

	out := map[string]map[string]r4Cell{}
	seen := map[string]bool{}
	for _, r := range verdicts {
		rt, ok := byID[r.VectorID]
		if !ok {
			continue
		}
		seen[rt.Path] = true
		v := r.Verdict
		cls := v.Class.String()
		if out[rt.Path] == nil {
			out[rt.Path] = map[string]r4Cell{}
		}
		// A class produces one verdict per SLOT, and a header vector has nineteen slots. The cell
		// keeps the LOUDEST one: a class that fired on origin and was silent on user-agent has
		// fired, and a matrix that recorded the last slot alphabetically would hide it.
		cur, had := out[rt.Path][cls]
		cell := r4Cell{State: v.State, Oracle: v.Oracle, Grade: v.Grade,
			Reason: triageFirstLine(v.Reason), Sent: sentPair[cls+"|"+r.VectorID]}
		if !had || r4Louder(cell.State, cur.State) {
			out[rt.Path][cls] = cell
		}
	}
	for _, rt := range routes {
		if !seen[rt.Path] {
			t.Errorf("%s: route %s produced no verdict from any class", label, rt.Path)
		}
	}
	return out
}

// r4Louder orders the states by how much they claim, so a per-route cell built from many slots
// keeps the strongest claim rather than an arbitrary one.
func r4Louder(a, b triage.TriageState) bool { return r4Rank(a) > r4Rank(b) }

func r4Rank(s triage.TriageState) int {
	switch s {
	case triage.StateFinding:
		return 6
	case triage.StateSuspicious:
		return 5
	case triage.StateNotExploitable:
		return 4
	case triage.StateClean:
		return 3
	case triage.StateNotProbed:
		return 2
	case triage.StateCannotDetermine:
		return 1
	default:
		return 0
	}
}

// r4Concluded is the question this round exists to answer, as a predicate. A conclusion is a
// verdict that TELLS THE OPERATOR SOMETHING: this endpoint has the bug, or it does not, or it has
// it and it cannot be reached. cannot_determine, not_probed and not_run are all the layer saying
// it did not find out, and NOT KNOWING IS NOT CLEAN is the rule that makes the distinction worth
// counting.
func r4Concluded(s triage.TriageState) bool {
	switch s {
	case triage.StateFinding, triage.StateSuspicious, triage.StateClean, triage.StateNotExploitable:
		return true
	}
	return false
}

func r4Print(t *testing.T, title string, m map[string]map[string]r4Cell, routes []r4Route) {
	t.Helper()
	notes := map[string]string{}
	for _, rt := range routes {
		notes[rt.Path] = rt.Note
	}
	paths := make([]string, 0, len(m))
	for p := range m {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	t.Logf("")
	t.Logf("################ %s ################", title)
	for _, p := range paths {
		classes := make([]string, 0, len(m[p]))
		for c := range m[p] {
			classes = append(classes, c)
		}
		sort.Strings(classes)
		concluded := 0
		for _, c := range classes {
			if r4Concluded(m[p][c].State) {
				concluded++
			}
		}
		t.Logf("")
		t.Logf("---- %s   (%s)   %d/%d classes concluded", p, notes[p], concluded, len(classes))
		for _, c := range classes {
			cell := m[p][c]
			t.Logf("     %-10s %-17s %-28s %-8s sent=%-4d %s",
				c, cell.State, cell.Oracle, cell.Grade, cell.Sent, r4Trim(cell.Reason, 110))
		}
	}
}

func r4Trim(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\n", " "))
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

// THE TAIL OF THE HEADER CORPUS PRODUCED NOTHING, TWICE, AND THIS IS THE EXPERIMENT THAT SAYS WHY.
//
// In the full header run the last four routes in path order (/hosthdr/nohttp, /originalurl,
// /portconcat, /wrapinert) came back baseline_transport_proto for EVERY class, sent=0. The same
// four both times, at 120 requests per second and again at 35, which rules pacing out and rules a
// route defect in: except that all four answer 200 to curl.
//
// The third possibility is the one that is true, and it is a property of the RUN rather than of
// any route: HostBudget aborts the whole run when the target degrades, rate-limits or collapses,
// and after that every vector not yet sampled records a transport error and its classes correctly
// say cannot_determine instead of clean. Vectors are processed in path order, so the abort always
// lands on the same tail.
//
// This test runs those four routes AS THEIR OWN CORPUS. If they conclude here, the cells in the
// big matrix are the safety brake and not a defect in the routes or the classes, and the number to
// read off the matrix is the one from this run.
func TestRound4HeaderTailIsARunLevelAbortAndNotARouteDefect(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)

	var tail []r4Route
	for _, rt := range r4HeaderRoutes() {
		switch rt.Path {
		case "/hosthdr/nohttp", "/hosthdr/originalurl", "/hosthdr/portconcat", "/hosthdr/wrapinert":
			tail = append(tail, rt)
		}
	}
	m := r4Run(t, ctx, base, tail, triage.TierFull, "HEADER TAIL, ALONE")
	r4Print(t, "MATRIX B2: THE HEADER TAIL RUN ON ITS OWN", m, tail)

	for _, rt := range tail {
		cell, ok := m[rt.Path][triage.ClassHostHeader.String()]
		if !ok {
			t.Errorf("%s produced no HOSTHDR cell even alone", rt.Path)
			continue
		}
		if cell.Sent == 0 {
			t.Errorf("%s: HOSTHDR still sent nothing with the route alone (%s), so the big matrix's zero is NOT a run-level abort and the route or the class is at fault: %s",
				rt.Path, cell.State, cell.Reason)
		}
	}
}

// TestRound4ConfusionMatrix is the whole measurement. Three runs, one per insertion point,
// because SlotsFor dispatches on the insertion_point column and a single corpus cannot reach a
// header-only class and a query-only class at once.
func TestRound4ConfusionMatrix(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)

	query := r4Run(t, ctx, base, r4QueryRoutes(), triage.TierFull, "QUERY SLOTS")
	r4Print(t, "MATRIX A: QUERY SLOTS", query, r4QueryRoutes())

	header := r4Run(t, ctx, base, r4HeaderRoutes(), triage.TierFull, "HEADER SLOTS")
	r4Print(t, "MATRIX B: HEADER SLOTS", header, r4HeaderRoutes())

	// PP-SERVER declares every probe at the OPT-IN tier, so a run at full tier sends none of them
	// and the five /pp routes would be measured at zero while reading as covered.
	body := r4Run(t, ctx, base, r4BodyRoutes(), triage.TierOptIn, "BODY SLOTS (opt-in tier)")
	r4Print(t, "MATRIX C: JSON BODY SLOTS", body, r4BodyRoutes())

	// THE NUMBER THIS ROUND EXISTS TO PRODUCE.
	for _, m := range []struct {
		label string
		cells map[string]map[string]r4Cell
	}{{"query", query}, {"header", header}, {"body", body}} {
		cells := m.cells["/api/items"]
		if cells == nil {
			t.Errorf("/api/items produced no cells on %s slots", m.label)
			continue
		}
		var concluded, silent []string
		for c, cell := range cells {
			if r4Concluded(cell.State) {
				concluded = append(concluded, c+"("+string(cell.State)+")")
			} else {
				silent = append(silent, c+"("+string(cell.State)+")")
			}
		}
		sort.Strings(concluded)
		sort.Strings(silent)
		t.Logf("")
		t.Logf("ECHO-FREE JSON API (/api/items, %s slots): %d of %d classes CONCLUDED", m.label, len(concluded), len(cells))
		t.Logf("   concluded: %s", strings.Join(concluded, " "))
		t.Logf("   silent:    %s", strings.Join(silent, " "))

		// THE ONE ASSERTION. /api/items reads its parameters and shows nothing, acts on nothing
		// and is not vulnerable to anything. A finding here is a false positive with no defence
		// available, and it is the single result that would make every other number in this
		// matrix unreadable.
		for c, cell := range cells {
			if cell.State == triage.StateFinding {
				t.Errorf("FALSE POSITIVE: %s reported a FINDING on the benign echo-free JSON API (%s slots): %s / %s",
					c, m.label, cell.Oracle, cell.Reason)
			}
		}
	}
}
