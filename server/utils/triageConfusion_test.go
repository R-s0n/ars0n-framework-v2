package utils

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"ars0n-framework-v2-server/utils/triage"

	"github.com/google/uuid"
)

// THE FULL CONFUSION MATRIX: EVERY REGISTERED CLASS AGAINST EVERY ORACLE ROUTE.
//
// WHY THIS EXISTS AND WHY THE PER-CLASS ORACLE TESTS DO NOT COVER IT. Each class declares its own
// OracleCases and each class's own test suite checks that it fires on its route and stays silent
// on the two or three routes it thought to name. Nothing anywhere checked the OTHER seventy-odd
// cells. The isolation law in triage/registry.go stops two classes shipping byte-equal payloads;
// it says nothing whatever about two classes firing on the SAME EVIDENCE, and a new class landing
// a false positive on an older class's positive route is invisible to every test in this
// repository except this one.
//
// IT IS A MEASUREMENT AND NOT AN ASSERTION, deliberately. Adjudicating 14 classes times 79 routes
// requires knowing what each route does to each class's payloads, which is exactly the judgement
// that must not be encoded as a table nobody rereads. So this test PRINTS the matrix, asserts the
// three properties that are true by construction rather than by opinion, and leaves the cells to
// be read. The three:
//
//	(a) no class may produce zero verdicts, which is the silent-zero shape;
//	(b) every route must answer, so a cell reading "no verdict" is a missing measurement and not
//	    a clean;
//	(c) the shipped positives must still fire, so a regression from a new class is loud.
//
// IT IS GATED ON THE ORACLE AND ON NOTHING ELSE, and it used to be gated on an environment
// variable nobody sets.
//
// The old gate was a BARE t.Skip behind TRIAGE_CONFUSION, justified by wall clock: it opens
// roughly twenty thousand sockets and takes about six minutes. What that bought was a test which
// never ran. In a full suite run it printed SKIP, the package reported ok, and property (c) up
// there, "the shipped positives must still fire, so a regression from a new class is loud", was
// asserted by nothing at all. In the run that found this, the oracle was PRESENT and driving four
// other tests in the same package while this one skipped.
//
// That is the not-measured ledger's own thesis committed against the ledger. triageNotMeasured
// exists because a facility gate that leaves by t.Skip is invisible, and the whole argument is
// that OPT-IN HONESTY IS NOT HONESTY: a test whose facility is there and which still does not run
// is a measurement nobody took, recorded as a pass. So the gate is now the facility and only the
// facility. triageOracleBase ledgers an unreachable oracle and fails the package at the end of
// the run unless TRIAGE_ALLOW_UNMEASURED is set, and a REACHABLE oracle means this runs.
//
// WHAT THAT COSTS, SAID OUT LOUD: about 367s on a package that already takes roughly 1465s, so
// the utils suite goes to something near 1830s and -timeout 90m still covers it comfortably.
// There is no new opt-out, deliberately, because an opt-out is the thing that was wrong here. An
// agent iterating on one test narrows with -run, which skips nothing it claims to have measured;
// a full suite run pays the six minutes and gets the regression detector it thought it had.
func TestTheFullConfusionMatrixOverEveryOracleRouteAndEveryClass(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)

	targetID := uuid.New().String()
	if _, err := dbPool.Exec(ctx,
		`INSERT INTO scope_targets (id, type, mode, scope_target, active) VALUES ($1, 'URL', 'Passive', $2, FALSE)`,
		targetID, base); err != nil {
		t.Fatalf("create scope target: %v", err)
	}
	t.Cleanup(func() {
		if os.Getenv("TRIAGE_TEST_KEEP") != "" {
			t.Logf("TRIAGE_TEST_KEEP is set, so scope target %s is left in the database", targetID)
			return
		}
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM scope_targets WHERE id = $1`, targetID); err != nil {
			t.Errorf("clean up scope target %s: %v", targetID, err)
		}
	})

	host, port, scheme := triageSplitBase(t, base)
	routes := triageOracleRoutes()
	byVector := map[string]string{}
	for _, rt := range routes {
		vectorID := uuid.New().String()
		evidence := fmt.Sprintf("%s%s?%s=%s", base, rt.path, rt.param, rt.value)
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO attack_vectors (id, scope_target_id, vector_key, method, scheme, domain, port,
			                            path, insertion_point, parameters, evidence_url)
			VALUES ($1,$2,$3,'GET',$4,$5,$6,$7,'query',$8,$9)`,
			vectorID, targetID, "oracle:"+rt.path, scheme, host, port, rt.path,
			[]string{rt.param}, evidence); err != nil {
			t.Fatalf("insert vector for %s: %v", rt.path, err)
		}
		byVector[vectorID] = rt.path
	}

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = true
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	// The pacing is the whole run's shape. The oracle is a local Go binary with no database
	// behind it, so the only thing these numbers buy is wall clock. The per-slot cap is raised
	// above every class's full ladder on purpose: a cap that bites turns a verdict into
	// probe_budget_exhausted, which is neither a fire nor a silence and would make the matrix
	// unreadable.
	settings.Pacing.RequestsPerSecond = 100
	settings.Pacing.Concurrency = 10
	settings.Pacing.PerSlotProbes = 80
	settings.Pacing.PerRunProbes = 400000
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, targetID, settings)

	started := time.Now()
	runUUID, err := StartTriageRun(ctx, targetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 60*time.Minute); status != "completed" {
		var runErr *string
		_ = dbPool.QueryRow(ctx, `SELECT error FROM triage_runs WHERE id = $1`, runUUID).Scan(&runErr)
		msg := ""
		if runErr != nil {
			msg = *runErr
		}
		t.Fatalf("the run finished %q: %s", status, msg)
	}
	t.Logf("run %s finished in %s over %d routes", runUUID, time.Since(started).Round(time.Second), len(routes))

	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	if len(verdicts) == 0 {
		t.Fatal("the run produced no verdict at all, which is the silent-zero shape this layer exists to stop")
	}

	type cell struct {
		state  triage.TriageState
		oracle string
		reason string
	}
	grid := map[string]map[string]cell{} // route -> class -> cell
	classes := map[string]bool{}
	perClass := map[string]int{}
	for _, r := range verdicts {
		route := byVector[r.VectorID]
		cls := r.Verdict.Class.String()
		classes[cls] = true
		perClass[cls]++
		if grid[route] == nil {
			grid[route] = map[string]cell{}
		}
		// A vector has exactly one query slot here, so one row per class per route. If a class
		// ever returns two, the louder state wins the cell and the detail is in the dump below.
		prev, seen := grid[route][cls]
		if !seen || triageConfusionLoudness(r.Verdict.State) > triageConfusionLoudness(prev.state) {
			grid[route][cls] = cell{
				state:  r.Verdict.State,
				oracle: r.Verdict.Oracle,
				reason: triageFirstLine(r.Verdict.Reason),
			}
		}
	}

	classNames := make([]string, 0, len(classes))
	for c := range classes {
		classNames = append(classNames, c)
	}
	sort.Strings(classNames)

	// THE EXCLUSION IS PRINTED BEFORE THE MATRIX, so it is read by whoever reads the matrix. It
	// is checked against the corpus first: an exclusion naming a route that is no longer in the
	// run is an exclusion nobody is applying, and it would go on suppressing a column that had
	// quietly moved somewhere else.
	t.Log("---- routes excluded from cell-to-cell comparison between rounds ----")
	inCorpus := map[string]bool{}
	for _, rt := range routes {
		inCorpus[rt.path] = true
	}
	for _, route := range triageConfusionExcludedRoutes() {
		if !inCorpus[route] {
			t.Errorf("EXCLUSION %s names a route this corpus no longer contains, so it excludes nothing and the reason it records is stale", route)
			continue
		}
		t.Logf("EXCLUDED %-28s %s", route, triageConfusionNondeterministic[route])
	}
	t.Logf("---- %d route(s) excluded; their cells print as -- in the matrix below and their states are listed separately ----",
		len(triageConfusionNondeterministic))

	// THE MATRIX. One line per route, one column per class, each cell the first letter pair of
	// the state: FI finding, SU suspicious, CL clean, NE not_exploitable, CD cannot_determine,
	// NA not_applicable, NR not_reachable, NP not_planned, XX no verdict row at all. An excluded
	// route prints -- in every column: its verdict is still required to exist, and its VALUE is
	// not comparable between rounds.
	var header strings.Builder
	header.WriteString(fmt.Sprintf("%-28s", "route"))
	for _, c := range classNames {
		header.WriteString(fmt.Sprintf(" %-9s", c))
	}
	t.Log(header.String())
	routePaths := make([]string, 0, len(grid))
	for _, rt := range routes {
		routePaths = append(routePaths, rt.path)
	}
	missing := 0
	for _, route := range routePaths {
		excluded := triageConfusionNondeterministic[route] != ""
		label := route
		if excluded {
			label = route + " (excl)"
		}
		var line strings.Builder
		line.WriteString(fmt.Sprintf("%-28s", label))
		for _, c := range classNames {
			cl, ok := grid[route][c]
			if !ok {
				// A MISSING VERDICT IS STILL A DEFECT ON AN EXCLUDED ROUTE. What is excluded is
				// the STATE the cell settled on, not the requirement that it settle on one: a
				// pair that was planned and produced nothing reads as untouched either way.
				line.WriteString(fmt.Sprintf(" %-9s", "XX"))
				missing++
				continue
			}
			if excluded {
				line.WriteString(fmt.Sprintf(" %-9s", "--"))
				continue
			}
			line.WriteString(fmt.Sprintf(" %-9s", triageConfusionCode(cl.state)))
		}
		t.Log(line.String())
	}

	// EVERY CELL THAT FIRED, in full, because a fire is the only cell that can be a false
	// positive and the reason is what decides it.
	t.Log("---- every cell that fired (finding or suspicious) ----")
	fired := 0
	for _, route := range routePaths {
		if triageConfusionNondeterministic[route] != "" {
			continue
		}
		for _, c := range classNames {
			cl, ok := grid[route][c]
			if !ok || (cl.state != triage.StateFinding && cl.state != triage.StateSuspicious) {
				continue
			}
			fired++
			t.Logf("FIRE %-28s %-9s %-11s %-34s %s", route, c, cl.state, cl.oracle, cl.reason)
		}
	}
	t.Logf("---- %d cells fired on comparable routes, %d cells have no verdict row ----", fired, missing)

	// EVERY CELL IN FULL. A state code alone cannot be adjudicated: cannot_determine covers a
	// disabled detector, a blocked request and a control that did not run, and those are three
	// different facts about the run.
	t.Log("---- every cell, with its reason ----")
	for _, route := range routePaths {
		if triageConfusionNondeterministic[route] != "" {
			continue
		}
		for _, c := range classNames {
			cl, ok := grid[route][c]
			if !ok {
				continue
			}
			t.Logf("CELL %-28s %-9s %-16s %s", route, c, cl.state, cl.reason)
		}
	}

	// THE EXCLUDED CELLS, IN THEIR OWN BLOCK AND UNDER THEIR OWN WORD. They are measurements and
	// they are worth reading; what they are not is comparable with the same cell last round. A
	// verifier diffing this log between rounds diffs the CELL lines above and reads these.
	if len(triageConfusionNondeterministic) > 0 {
		t.Log("---- cells on excluded routes: MEASURED BUT NOT COMPARABLE BETWEEN ROUNDS ----")
		for _, route := range triageConfusionExcludedRoutes() {
			for _, c := range classNames {
				cl, ok := grid[route][c]
				if !ok {
					continue
				}
				t.Logf("NOTCOMPARABLE %-28s %-9s %-16s %s", route, c, cl.state, cl.reason)
			}
		}
	}

	for _, c := range classNames {
		t.Logf("class %-9s produced %d verdicts across %d routes", c, perClass[c], len(routes))
	}

	// (a) and (b): no class may be absent and no route may be unanswered.
	for _, c := range classNames {
		if perClass[c] == 0 {
			t.Errorf("class %s produced no verdict anywhere in the matrix", c)
		}
	}
	if missing > 0 {
		t.Errorf("%d class/route cells produced no verdict row at all. A pair that was planned and "+
			"then produced nothing reads as untouched in the UI when it was in fact tested and "+
			"inconclusive, which is the silent zero in its per-cell form", missing)
	}

	// (c) THE SHIPPED POSITIVES MUST STILL FIRE. This is the regression half: a new class cannot
	// be allowed to change what an old one says on the route that old class was built against.
	for _, want := range []struct{ route, class string }{
		{"/ssti", "SSTI"},
		{"/sqli", "SQL"},
		{"/xss", "XSS-R"},
		{"/cmdi", "CMDI"},
		{"/eli", "ELI"},
		// NOSQL's declared positive route is deliberately NOT asserted here, and the reason is
		// this harness and not the class. Its OracleCases name /nosqli/mongo with NSQ-OP1,
		// NSQ-OP0, NSQ-OP2 and NSQ-OP4, which are OPERATOR OBJECTS: they need a JSON body slot
		// to render into, because {"q":{"$ne":null}} is not a thing a query string can carry.
		// Every vector in this matrix is a GET query slot, so on this route the class is
		// answering about a slot its strongest arm cannot reach. Measured here: NOSQL returns
		// cannot_determine (junk_sensitive), because /nosqli/mongo is a search endpoint and its
		// result set legitimately moves when the harmless control changes the search term.
		// Asserting a finding from this shape would be asserting something the run did not test.
		{"/nosqli/lucene", "NOSQL"},
		{"/csti/angular", "CSTI"},
		{"/lfi", "LFI"},
		{"/redirect", "REDIRECT"},
		{"/crlf/header", "CRLF"},
		{"/deser/php", "DESER"},
	} {
		cl, ok := grid[want.route][want.class]
		if !ok {
			t.Errorf("%s produced no verdict on %s, its own declared positive route", want.class, want.route)
			continue
		}
		if cl.state != triage.StateFinding && cl.state != triage.StateSuspicious {
			t.Errorf("%s reported %s on %s, which is its own declared positive route: %s",
				want.class, cl.state, want.route, cl.reason)
		}
	}
}

// triageConfusionNondeterministic names every route in this corpus whose CELL VALUE can change
// between two runs of this test on an unchanged tree, with the reason, keyed by route.
//
// WHY THIS IS A NAMED TABLE AND NOT A THING EACH VERIFIER REMEMBERS. Every round after this one
// asks the same question of this matrix: did any cell move. A corpus that moves by itself makes
// that question unanswerable in both directions. It is a permanent source of false alarms, and,
// far worse, it is a standing excuse: a real regression gets dismissed as drift by whoever
// remembers that one of these routes is flaky. Writing the exclusion down, checking it against
// the corpus, and PRINTING IT IN THE OUTPUT means the next round reads the exclusion off the log
// it is diffing rather than off somebody's recollection.
//
// /clean/drift, MEASURED. The oracle rotates the route's body every driftPeriod (8) requests off
// driftCounter, a process-global atomic in the oracle binary that every test in this package
// shares. So which generation a probe ladder straddles depends on how many requests reached that
// route earlier in the same oracle process, which depends on what else ran. PROVED: three runs of
// this test against an unchanged tree returned clean, cannot_determine, clean. Round 14 recorded
// "no drift exclusion needed" off a single run and that was luck; round 15 watched 4 of 1440
// cells move for this reason alone.
//
// THE OTHER FIX IS BETTER AND IT IS NOT THIS FILE'S TO MAKE. Keying the generation off something
// per-run, a header or a query value, instead of a global counter would make the route
// deterministic and let the exclusion go. docker/oracle/main.go is not in this round's file list,
// so that patch is written up rather than applied, and this table is what makes the question
// answerable until it lands.
//
// EXCLUDING A ROUTE EXCLUDES ITS CELL VALUE AND NOTHING ELSE. Its verdicts must still exist
// (property (b) counts them into `missing` exactly as before), its classes still count toward
// property (a), and if it were a declared positive route for some class property (c) would still
// assert it. What is dropped is only the comparison of this round's letters with last round's.
var triageConfusionNondeterministic = map[string]string{
	"/clean/drift": "the oracle rotates this route's body every 8 requests off driftCounter, a process-global atomic shared by every test in the package, so which generation a ladder straddles depends on how many requests reached the route earlier in the same oracle process",
}

// triageConfusionExcludedRoutes is the exclusion list in a stable order, so two rounds print it
// the same way and a diff of the log shows a change to the list as a change to the list.
func triageConfusionExcludedRoutes() []string {
	out := make([]string, 0, len(triageConfusionNondeterministic))
	for route := range triageConfusionNondeterministic {
		out = append(out, route)
	}
	sort.Strings(out)
	return out
}

func triageConfusionCode(s triage.TriageState) string {
	switch s {
	case triage.StateFinding:
		return "FI"
	case triage.StateSuspicious:
		return "SU"
	case triage.StateClean:
		return "CL"
	case triage.StateNotExploitable:
		return "NE"
	case triage.StateCannotDetermine:
		return "CD"
	case triage.StateNotApplicable:
		return "NA"
	case triage.StateNotReachable:
		return "NRch"
	case triage.StateNotPlanned:
		return "NP"
	case triage.StateNotRun:
		return "NRun"
	default:
		return string(s)
	}
}

// triageConfusionLoudness ranks states so the noisiest one wins a cell. A false positive that
// hides behind a second quieter verdict on the same pair is the one thing this matrix must not
// let through.
func triageConfusionLoudness(s triage.TriageState) int {
	switch s {
	case triage.StateFinding:
		return 6
	case triage.StateSuspicious:
		return 5
	case triage.StateNotExploitable:
		return 4
	case triage.StateCannotDetermine:
		return 3
	case triage.StateClean:
		return 2
	default:
		return 1
	}
}

type triageOracleRoute struct {
	path  string
	param string
	value string
}

// triageOracleRoutes is every surface the canary oracle serves, with the parameter name that
// surface reads.
//
// THE TWO SCRIPT FILES ARE ABSENT ON PURPOSE. /csti/angular.min.js and /csti/blocked.js are
// assets the CSTI pages load, not places a payload goes, and a vector pointed at either would
// measure a static file. Everything else the mux registers is here, including the routes whose
// natural method is POST: a GET against those is still a request the classes must not invent a
// finding from.
func triageOracleRoutes() []triageOracleRoute {
	q := func(path string) triageOracleRoute { return triageOracleRoute{path, "q", "hello"} }
	named := func(path, param, value string) triageOracleRoute {
		return triageOracleRoute{path, param, value}
	}
	return []triageOracleRoute{
		named("/", "q", "hello"),
		q("/xss"),
		named("/sqli", "id", "1"),
		named("/redirect", "next", "/home"),
		named("/lfi", "file", "readme"),
		named("/cmdi", "cmd", "localhost"),
		named("/ssti", "tpl", "hello"),

		q("/clean/noisy"),
		named("/clean/dberror", "id", "1"),
		named("/clean/intcast", "id", "1"),
		named("/clean/validate", "id", "1"),
		named("/clean/waf", "id", "1"),
		q("/clean/always500"),
		q("/clean/echo"),
		q("/clean/spa"),
		q("/clean/nonidem"),
		q("/clean/empty204"),
		q("/clean/nothing"),
		q("/clean/drift"),
		named("/clean/echoparser", "id", "1"),
		named("/clean/junk", "id", "1"),
		named("/clean/inert", "id", "1"),
		q("/clean/passwddoc"),
		q("/clean/b64noise"),
		q("/clean/mongoprose"),
		q("/clean/echomongo"),
		q("/clean/versionprose"),

		named("/sqli/mssql", "sort", "name"),
		named("/sqli/mysql", "sort", "name"),
		named("/sqli/json", "id", "1"),
		named("/sqli/blind", "id", "hello"),
		named("/sqli/status200", "id", "1"),
		named("/rfi/inband-include", "file", "readme.txt"),
		named("/rfi/inband-reject", "file", "readme.txt"),

		q("/xss/encoded"),
		q("/xss/entity"),

		q("/eli"),
		q("/eli/spel"),
		q("/eli/ognl"),
		q("/eli/longmath"),
		q("/eli/hardened"),
		q("/eli/echo"),
		q("/eli/devmode"),

		q("/nosqli/mongo"),
		q("/nosqli/noscripting"),
		q("/nosqli/where"),
		q("/nosqli/lucene"),
		q("/nosqli/strict"),

		q("/csti/angular"),
		q("/csti/plain"),
		q("/csti/jinja"),
		q("/csti/escaped"),
		q("/csti/nonbindable"),
		q("/csti/inscript"),
		q("/csti/pct-literal"),
		q("/csti/product-in-baseline"),
		q("/csti/calculator"),
		q("/csti/aot"),
		q("/csti/vue-runtime"),
		q("/csti/corpus-blocked"),
		q("/csti/angular-attr"),
		q("/csti/angular-hash"),

		q("/crlf/header"),
		q("/crlf/lfonly"),
		q("/crlf/doubledecode"),
		q("/crlf/edgereject"),
		q("/crlf/preset"),
		q("/crlf/setcookie"),

		q("/deser/php"),
		q("/deser/phpwrapped"),
		q("/deser/phpstatic"),
		q("/deser/java"),
		q("/deser/pickle"),
		q("/deser/preset"),

		named("/redirect/local", "next", "/home"),
		named("/redirect/fixed", "next", "/home"),
		named("/redirect/loginwrap", "next", "/home"),
		named("/redirect/strictvalidator", "next", "/home"),
		named("/redirect/alwaysoffsite", "next", "/home"),
		named("/redirect/meta", "next", "/home"),
	}
}
