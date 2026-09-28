package utils

import (
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// A SKIP IS NOT A PASS.
//
// This file is the answer to a defect found in our own suite on 2026-09-19. The two end-to-end
// tests that are the only executable proof the triage layer works against a real target,
// TestTriageVerdictsBecomePointersOnTheOracle and TestTheWholeRegistryRunsAndEveryClassSaysWhatItDid,
// call t.Skipf when the canary oracle is unreachable. Both FAIL on unmodified code when it IS
// reachable. So the sentence "go test ./... is green on all four packages" was quoted for a week
// about a suite in which the two tests that could have contradicted it had never once executed.
//
// That is the same bug the whole triage layer exists to stop, committed against ourselves: an
// ABSENCE OF MEASUREMENT READ AS A POSITIVE FACT. A pair that was never probed is not clean; a
// test that never ran is not green. There is no version of that rule that applies to the target
// and not to us.
//
// ---------------------------------------------------------------------------------------------
// WHY THIS SHAPE AND NOT ANOTHER
// ---------------------------------------------------------------------------------------------
//
// Three options were on the table. The deciding measurement is that GO TEST THROWS AWAY THE
// OUTPUT OF A PACKAGE THAT PASSES. Verified directly:
//
//	$ go test ./...        # TestMain writes "LOUD SUMMARY LINE" to stderr, package passes
//	ok  	tm	0.256s     # ... and the line is nowhere on the terminal
//
// So option (b), "print a loud summary line", is not available on its own. There is no way to
// report anything to the reader of a plain `go test ./...` except by failing. A summary nobody
// can see is the same silence under a friendlier name.
//
// Option (a), "fail rather than skip when an env var says the oracle should be there", makes the
// honest reading OPT IN. Whoever forgets the variable gets the green they already had, which is
// the exact failure mode being fixed. Opt-in honesty is not honesty.
//
// So: FAIL BY DEFAULT, WITH A NAMED OPT-OUT. A skipped facility-dependent test now makes the
// package fail, the failure carries the full list of what did not run and the commands that would
// make it run, and TRIAGE_ALLOW_UNMEASURED=1 turns it back into an ordinary skip for whoever
// genuinely wants to run the unit tests on a laptop with nothing up.
//
// BE HONEST ABOUT WHAT THE OPT-OUT COSTS. With it set the package passes, and go test then throws
// the listing away with the rest of the output, so the reader sees nothing unless they pass -v.
// That is not an oversight to be worked around: the variable means "I accept a run that measured
// less than it claims", and there is no way to both accept that and keep being told. What the
// change buys is that accepting it is now an act, in one named place, instead of the default.
//
// The check lives in TestMain, AFTER m.Run, and not in a guard test. A guard test runs in source
// order and could not see a skip recorded by a test that runs after it; TestMain sees all of them
// whatever -run, -shuffle or parallelism did.
//
// ---------------------------------------------------------------------------------------------
// WHAT IS AND IS NOT ROUTED THROUGH HERE
// ---------------------------------------------------------------------------------------------
//
// Only FACILITY gates: a skip that means "the thing under test was never exercised because a
// database, an oracle or a tool was not there". Those are the ones that masquerade as passes.
//
// Skips that mean "this build has nothing of the kind to exercise" (no class is unavailable, no
// tool is registered) are a different statement and are left alone; they are about the build, not
// about the environment, and failing on them would make the suite unusable while telling nobody
// anything new. The package still contains about twenty of those and they are listed in the
// report that accompanied this change.

// The facility names. They are constants so a typo cannot open a fourth, unlisted bucket.
const (
	triageFacilityOracle   = "oracle"
	triageFacilityDatabase = "database"
)

// triageAllowUnmeasuredEnv is the one opt-out. It is deliberately not per-facility: the decision
// it records is "I accept a run that measured less than it claims", and that is one decision.
const triageAllowUnmeasuredEnv = "TRIAGE_ALLOW_UNMEASURED"

// triageHowToMeasure is printed with the failure. A message that says a facility is missing and
// not how to supply it makes the reader go and find this file, and most of them will instead set
// the opt-out, which is the outcome this whole change is trying to avoid.
var triageHowToMeasure = map[string]string{
	triageFacilityOracle: "the oracle has no host port, so reach it from inside the compose network or publish it:\n" +
		"      docker run -d --rm --name triage-oracle-proxy --network ars0n-framework-v2_ars0n-network \\\n" +
		"        -p 18000:18000 alpine/socat tcp-listen:18000,fork,reuseaddr tcp:oracle:8000\n" +
		"      then run with TRIAGE_ORACLE_URL=http://localhost:18000",
	triageFacilityDatabase: "point the suite at the THROWAWAY database, never at ars0n:\n" +
		"      TRIAGE_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:55433/triage_test",
}

type triageUnmeasuredRecord struct {
	Facility string
	Test     string
	Reason   string
}

var (
	triageUnmeasuredMu  sync.Mutex
	triageUnmeasuredLog []triageUnmeasuredRecord
)

// triageNotMeasured is THE ONLY DOOR a facility gate may leave by. It records what was not
// measured, then skips. Calling t.Skip directly for a missing facility puts the test back in the
// blind spot, which is why the report that accompanied this change lists every remaining t.Skip
// in the package by hand.
func triageNotMeasured(t *testing.T, facility, format string, args ...any) {
	t.Helper()
	reason := fmt.Sprintf(format, args...)
	triageUnmeasuredMu.Lock()
	triageUnmeasuredLog = append(triageUnmeasuredLog, triageUnmeasuredRecord{
		Facility: facility,
		Test:     t.Name(),
		Reason:   reason,
	})
	triageUnmeasuredMu.Unlock()
	t.Skipf("NOT MEASURED (%s): %s. A skip is not a pass; see the summary at the end of the run.", facility, reason)
}

// triageUnmeasuredSummary renders the ledger, or "" when everything ran.
func triageUnmeasuredSummary() string {
	triageUnmeasuredMu.Lock()
	recs := append([]triageUnmeasuredRecord(nil), triageUnmeasuredLog...)
	triageUnmeasuredMu.Unlock()
	if len(recs) == 0 {
		return ""
	}

	byFacility := map[string][]triageUnmeasuredRecord{}
	for _, r := range recs {
		byFacility[r.Facility] = append(byFacility[r.Facility], r)
	}
	facilities := make([]string, 0, len(byFacility))
	for f := range byFacility {
		facilities = append(facilities, f)
	}
	sort.Strings(facilities)

	const bar = "================================================================================"
	var b strings.Builder
	fmt.Fprintf(&b, "\n%s\nNOT MEASURED: %d test(s) did not run because a facility was not there.\n", bar, len(recs))
	b.WriteString("A SKIP IS NOT A PASS. Nothing these tests assert is known either way for this run.\n")
	for _, f := range facilities {
		rs := byFacility[f]
		fmt.Fprintf(&b, "\n  %s  (%d test(s))\n      %s\n", strings.ToUpper(f), len(rs), rs[0].Reason)
		names := make([]string, 0, len(rs))
		seen := map[string]bool{}
		for _, r := range rs {
			if !seen[r.Test] {
				seen[r.Test] = true
				names = append(names, r.Test)
			}
		}
		sort.Strings(names)
		shown := names
		if len(shown) > 20 {
			shown = shown[:20]
		}
		for _, n := range shown {
			fmt.Fprintf(&b, "        %s\n", n)
		}
		if len(names) > len(shown) {
			fmt.Fprintf(&b, "        ... and %d more\n", len(names)-len(shown))
		}
		if how := triageHowToMeasure[f]; how != "" {
			fmt.Fprintf(&b, "    TO MEASURE: %s\n", how)
		}
	}
	fmt.Fprintf(&b, "\n%s\n", bar)
	return b.String()
}

// TestMain is the only one in package utils. It exists for the summary above and does nothing
// else: m.Run is called exactly once and its exit code is honoured, so no other test in this
// package changes behaviour because of this file.
func TestMain(m *testing.M) {
	code := m.Run()
	summary := triageUnmeasuredSummary()
	if summary == "" {
		os.Exit(code)
	}
	fmt.Fprint(os.Stderr, summary)
	if os.Getenv(triageAllowUnmeasuredEnv) != "" {
		fmt.Fprintf(os.Stderr, "%s is set, so the gap above is accepted and the suite's own result stands.\n\n",
			triageAllowUnmeasuredEnv)
		os.Exit(code)
	}
	fmt.Fprintf(os.Stderr,
		"FAILING THE PACKAGE. Every test that ran may well have passed; the point is that the ones\n"+
			"listed above did not run, and a run that reports success for tests it never executed is the\n"+
			"same defect this layer exists to stop, pointed at ourselves.\n"+
			"Supply the facilities above, or set %s=1 to accept the gap for this run.\n\n",
		triageAllowUnmeasuredEnv)
	os.Exit(1)
}

// The opt-out and the facility variables have to be read by a test that ALWAYS runs, or the go
// build cache will hand back a stale pass. Measured directly: an os.Getenv inside TestMain, before
// or after m.Run, is not part of the cache key, so a run with TRIAGE_ALLOW_UNMEASURED=1 poisoned
// every later run without it:
//
//	$ ALLOW=1 go test ./...   ->  ok
//	$ go test ./...           ->  PASS / LOUD SUMMARY / FAIL      (correct, cache missed)
//	$ ALLOW=1 go test ./...   ->  ok   (cached)
//	... but with the read only in TestMain, that last line came back "ok (cached)" for the run
//	    WITHOUT the variable too, which is the stale green all over again.
//
// Reading them here puts all four into the cache key, so changing any of them re-runs the suite.
func TestTheMeasurementPolicyIsPartOfTheBuildCacheKey(t *testing.T) {
	t.Logf("%s=%q TRIAGE_ORACLE_URL=%q TRIAGE_TEST_DATABASE_URL=%q DATABASE_URL set=%v",
		triageAllowUnmeasuredEnv, os.Getenv(triageAllowUnmeasuredEnv),
		os.Getenv("TRIAGE_ORACLE_URL"), os.Getenv("TRIAGE_TEST_DATABASE_URL"),
		os.Getenv("DATABASE_URL") != "")
}

// THE TWO GATES STAY ROUTED, asserted by name. If either goes back to a bare t.Skip the blind
// spot returns, and it returns silently: the tests would still be listed as skipped by `go test
// -v`, which nobody reads, and the package would go back to exiting 0.
//
// triageOracleBase in triageRun_test.go is the gate for BOTH oracle tests named at the top of
// this file; triageTestDB in triageStore_test.go is the gate for every test that needs a
// database, the two oracle tests included.
func TestTheTwoFacilityGatesStillRouteThroughTheLedger(t *testing.T) {
	for _, want := range []struct{ file, needle string }{
		{"triageRun_test.go", "triageNotMeasured(t, triageFacilityOracle"},
		{"triageStore_test.go", "triageNotMeasured(t, triageFacilityDatabase"},
	} {
		src, err := os.ReadFile(want.file)
		if err != nil {
			t.Fatalf("read %s: %v", want.file, err)
		}
		if !strings.Contains(string(src), want.needle) {
			t.Errorf("%s no longer routes its facility gate through the ledger (looked for %q). "+
				"A facility skip that does not reach triageNotMeasured is invisible to the end-of-run "+
				"summary, and the suite goes back to reporting a pass for tests that never ran",
				want.file, want.needle)
		}
	}
}

// THE REST OF THE PACKAGE'S SKIPS, LISTED RATHER THAN JUDGED.
//
// Routing the two facility gates fixes the two tests that mattered. It does not make every other
// t.Skip in this package honest, and pretending otherwise would be the same overclaim in a new
// place. So this test prints them, with their file and line, on every -v run, and pins the COUNT:
// adding a skip is then a visible decision in a diff, and whoever adds one has to say in the
// commit whether it is a facility gate (which belongs in the ledger) or a statement about the
// build (which does not).
//
// =================================================================================================
// THE PIN'S OWN RECIPE, BECAUSE FOUR AGENTS PRODUCED FOUR NUMBERS AND NONE COULD REPRODUCE ANOTHER
// =================================================================================================
//
// THE HISTORY, SO THE NEXT READER DOES NOT REPEAT IT. The pin said 28. Round 13 re-counted 28 and
// renamed the test to say it counts STATIC CALL SITES rather than the four SKIP lines a run
// prints. Round 15 measured 33 and called the pin stale. Round 16 measured 33 as well, and
// recorded that the round moved it by zero. One of them noted the real defect underneath all
// four disagreements: THE COUNTING COMMAND WAS RECORDED NOWHERE, so each reader invented their
// own and compared it against a number produced by a different one. A guard whose measurement
// nobody can reproduce is not a guard.
//
// SO THE COMMAND IS RECORDED HERE, IT IS PRINTED WITH THE NUMBER, AND THIS TEST RUNS IT. Where a
// POSIX shell is on PATH the recipe below is executed and its answer is compared against the
// answer the Go code computed; the two disagreeing is itself a failure. Where there is no shell
// the run says so as UNKNOWN and checks the recipe for drift statically instead, because a
// recipe that cannot be run here is still a recipe the reader can run.
//
// THE RIGHT NUMBER IS 28, AND HERE IS WHERE THE OTHER THREE CAME FROM, each reproduced:
//
//	28   this package's *_test.go files, excluding this one. What the test below counts, what
//	     the recipe below prints, and what the pin asserts.
//	30   28 plus the two lines in THIS file. One is the t.Skipf inside triageNotMeasured, which
//	     is the ledger's own door and not a gated test; the other is the line
//	     `if !strings.Contains(trimmed, "t.Skip(")` in the counter below, which is the DETECTOR
//	     MATCHING ITSELF and is not a call site at all. That is why this file is excluded by
//	     name, and the exclusion is now printed rather than buried in the loop.
//	33   30 plus 3 in package utils/triageclasses (rfi_test.go and two in sql_test.go), which is
//	     a DIFFERENT PACKAGE that this test never reads. Counting across both packages and
//	     comparing the total against a pin scoped to one is the whole of the round-15 and
//	     round-16 disagreement.
//	 4   not a count of call sites at all: the SKIP lines a full-facility run prints. Recorded
//	     below and deliberately not asserted.
//
// THE GAP BETWEEN 28 AND 4 IS NOT SLACK AND IT IS NOT A DEFECT. A call site becomes a SKIP line
// only when its guard fires. Twenty-four of these guard a BUILD FACT that is currently satisfied
// (the shape being guarded exists, something of that kind is registered, the corpus is not
// empty), so they are call sites that correctly never fire. The rest are opt-in corpus
// instruments and one unavailable-class subtest, and those are the SKIP lines a run prints.
//
// MEASURED, NOT INFERRED, on a full-facility run (oracle at localhost:18000 and the throwaway DSN
// both supplied), reported identically by three agents:
//
//	SKIP TestPassiveAgainstStoredCorpus                            reflectionPassiveCorpus_test.go
//	SKIP TestMeasureThePlanningWaste                               triageRun_test.go
//	SKIP TestThrottleRuleOverTheStoredTraceCorpus                  vectorThrottleCorpus_test.go
//	SKIP TestTheWholeRegistryRunsAndEveryClassSaysWhatItDid/
//	         an_unavailable_class_still_says_so_on_every_slot      triageRun_test.go
//
// THAT FOUR IS RECORDED HERE AND DELIBERATELY NOT ASSERTED. A test cannot count another test's
// runtime skips without re-running the package inside itself, so asserting it here would be a
// number this file could not measure, which is the exact failure mode the ledger exists to stop.
// What IS asserted at the bottom is that the files those four live in still exist and still carry
// a skip, so the list cannot rot into naming tests that are gone.

// triageSkipPinScope is what the pin is a count OF, in one sentence, so a reader who widens the
// scope can see that they have.
const triageSkipPinScope = "static t.Skip/t.Skipf CALL SITES in the *_test.go files of package " +
	"utils ONLY, excluding triageNotMeasured_test.go (the ledger's own file, whose two hits are " +
	"the ledger door and the detector matching its own needle) and excluding every other " +
	"package, utils/triageclasses included"

// triageSkipPinCommand is the recipe, run from server/utils. It is the whole answer to four
// agents getting four numbers: the next disagreement is settled by running this one line.
//
// IT MUST STAY EQUIVALENT TO THE LOOP BELOW, and the test below runs it and compares rather than
// trusting this comment. The three parts correspond one for one: the glob is the os.ReadDir
// filter, the first grep -v is the self-exclusion, the second is the whole-line-comment skip.
const triageSkipPinCommand = `grep -n 't\.Skip(\|t\.Skipf(' *_test.go | ` +
	`grep -v '^triageNotMeasured_test.go:' | ` +
	`grep -v '^[^:]*:[0-9]*:[[:space:]]*//' | wc -l`

func TestTheStaticSkipCallSitesInThisPackageAreCountedAndListed(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	var found, counted, excluded []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name == triageSkipPinSelf {
			excluded = append(excluded, name)
			continue
		}
		counted = append(counted, name)
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if !strings.Contains(trimmed, "t.Skip(") && !strings.Contains(trimmed, "t.Skipf(") {
				continue
			}
			found = append(found, fmt.Sprintf("%s:%d", name, i+1))
		}
	}
	sort.Strings(found)
	sort.Strings(counted)
	sort.Strings(excluded)

	// THE RECIPE AND THE FILE LIST ARE PRINTED WITH THE NUMBER, ALWAYS. A number whose reader
	// cannot tell what was counted is how this test came to have four different answers.
	t.Logf("SKIP PIN: %d call site(s). SCOPE: %s.", len(found), triageSkipPinScope)
	t.Logf("SKIP PIN RECIPE, run from server/utils:\n  %s", triageSkipPinCommand)
	// THE FILES THAT CONTRIBUTED, WITH THEIR SHARE, so the total can be checked against its parts
	// by eye rather than by re-running anything.
	perFile := map[string]int{}
	for _, f := range found {
		perFile[strings.SplitN(f, ":", 2)[0]]++
	}
	contributing := make([]string, 0, len(perFile))
	for f := range perFile {
		contributing = append(contributing, f)
	}
	sort.Strings(contributing)
	parts := make([]string, 0, len(contributing))
	for _, f := range contributing {
		parts = append(parts, fmt.Sprintf("%s x%d", f, perFile[f]))
	}
	t.Logf("SKIP PIN CONTRIBUTING FILES (%d of %d scanned): %s", len(contributing), len(counted), strings.Join(parts, ", "))
	t.Logf("SKIP PIN EXCLUDED %d file(s) BY NAME: %s", len(excluded), strings.Join(excluded, " "))
	// AND THE WHOLE SCANNED SET, because every disagreement so far was a disagreement about
	// SCOPE rather than about counting, and a scope is only checkable when it is listed.
	for i := 0; i < len(counted); i += 8 {
		end := i + 8
		if end > len(counted) {
			end = len(counted)
		}
		t.Logf("SKIP PIN SCANNED [%3d-%3d]: %s", i+1, end, strings.Join(counted[i:end], " "))
	}
	for _, f := range found {
		t.Logf("static t.Skip call site: %s", f)
	}

	// Measured on 2026-09-19, after the two facility gates were routed into the ledger,
	// re-counted on 2026-09-20, and settled on 2026-09-21 by recording the recipe above. Every
	// one of these was read and is a statement about the BUILD (nothing of that kind is
	// registered, the shape being guarded no longer exists, the test is about the empty case) or
	// an opt-in corpus instrument that asserts nothing when it is off.
	//
	// 28 since the full class-by-route confusion matrix stopped being opt-in. It used to be 29:
	// triageConfusion_test.go carried a bare t.Skip on TRIAGE_CONFUSION, classified here as "an
	// opt-in corpus instrument that asserts nothing when it is off", and that classification was
	// the defect. Its stated purpose is that the shipped positives must still fire so a
	// regression from a new class is loud, and in a full suite run with the oracle PRESENT and
	// driving four other tests in this package, it printed SKIP and the package reported ok. The
	// env gate is gone; it now gates on triageOracleBase alone, so an absent oracle is ledgered
	// and a reachable one means it RUNS, at a measured 364s.
	const want = 28
	if len(found) != want {
		t.Errorf("this package now has %d t.Skip CALL SITE(S) IN ITS SOURCE, and %d were counted and "+
			"classified on 2026-09-19, re-counted on 2026-09-20 and settled on 2026-09-21:\n  %s\n"+
			"SCOPE: %s.\n"+
			"REPRODUCE THIS NUMBER, from server/utils:\n  %s\n"+
			"IF YOU MEASURED A DIFFERENT NUMBER, CHECK THE SCOPE BEFORE THE PIN: 30 is this count plus "+
			"the two hits in triageNotMeasured_test.go (the ledger door, and the detector matching its "+
			"own needle, which is not a call site); 33 is 30 plus the three in package "+
			"utils/triageclasses, which this test never reads; 4 is the number of SKIP lines a "+
			"full-facility RUN prints, which is a different quantity again.\n"+
			"A NEW SKIP IS NOT A FREE ONE. If it means a facility was missing, route it through "+
			"triageNotMeasured so the end-of-run summary sees it. If it means this build has nothing of "+
			"that kind to exercise, say so in the skip message and update this count.",
			len(found), want, strings.Join(found, "\n  "), triageSkipPinScope, triageSkipPinCommand)
	}

	// THE RECIPE IS RUN, NOT ASSERTED. A recorded command that nobody ever executes is the same
	// thing as a number nobody can reproduce, one level up.
	triageCheckSkipPinRecipe(t, len(found))

	// AND THE FOUR THAT ACTUALLY FIRE STAY NAMEABLE. The runtime figure cannot be asserted from in
	// here, so what is asserted is that the files it names have not been deleted or emptied of
	// skips underneath the comment. A list of runtime skips pointing at tests that no longer exist
	// is worse than no list: the next reader measures four, finds the names stale, and concludes
	// the pin is broken all over again, which is how this round started.
	for _, file := range []string{
		"reflectionPassiveCorpus_test.go",
		"triageRun_test.go",
		"vectorThrottleCorpus_test.go",
	} {
		carries := false
		for _, f := range found {
			if strings.HasPrefix(f, file+":") {
				carries = true
				break
			}
		}
		if !carries {
			t.Errorf("%s no longer carries a t.Skip, but this test's comment still names it as the home "+
				"of one of the four SKIP lines a full-facility run prints. Re-measure the runtime skips "+
				"and rewrite that list: a stale list is what makes the next reader call the pin broken",
				file)
		}
	}
}

// triageSkipPinSelf is this file, excluded from its own count. It is a constant because the
// exclusion is the single commonest way to get 30 instead of 28, so it is named once and printed
// in the output rather than being a string buried in a loop condition.
const triageSkipPinSelf = "triageNotMeasured_test.go"

// triageCheckSkipPinRecipe runs the recorded recipe and compares its answer with the one the Go
// code above computed.
//
// WHY IT EXECUTES RATHER THAN INSPECTS. The defect this closes is that four readers each invented
// a command and compared it against a number produced by a different one. Recording a command
// fixes nothing unless the recorded command really does produce the pinned number, and the only
// way to know that is to run it.
//
// NO SHELL IS UNKNOWN, NOT A PASS AND NOT A FAILURE. On a machine without sh the recipe cannot be
// checked here, so the run SAYS so and falls back to checking the recipe for drift against the
// loop it mirrors. It does NOT route through triageNotMeasured: that ledger is for a facility the
// thing under test needed, and what is under test here is a count that was computed in full.
func triageCheckSkipPinRecipe(t *testing.T, want int) {
	t.Helper()

	// THE STATIC CHECK RUNS EITHER WAY, because it is the one that catches the recipe drifting
	// away from the loop rather than the loop drifting away from the pin.
	for _, part := range []string{`t\.Skip(`, `t\.Skipf(`, triageSkipPinSelf, "*_test.go"} {
		if !strings.Contains(triageSkipPinCommand, part) {
			t.Errorf("the recorded recipe no longer mentions %q, so it has drifted away from the loop it "+
				"is supposed to mirror and will hand the next reader a different number:\n  %s",
				part, triageSkipPinCommand)
		}
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Logf("SKIP PIN RECIPE NOT EXECUTED HERE: no POSIX shell on PATH (%v), so whether the recorded "+
			"command reproduces %d is UNKNOWN in this run rather than confirmed. It was checked for "+
			"drift statically. Run it yourself from server/utils:\n  %s", err, want, triageSkipPinCommand)
		return
	}
	out, err := exec.Command(sh, "-c", triageSkipPinCommand).Output()
	if err != nil {
		t.Errorf("the recorded recipe did not run (%v). A recipe nobody can execute is how this pin came "+
			"to have four different answers:\n  %s", err, triageSkipPinCommand)
		return
	}
	got, convErr := strconv.Atoi(strings.TrimSpace(string(out)))
	if convErr != nil {
		t.Errorf("the recorded recipe printed %q, which is not a number:\n  %s", strings.TrimSpace(string(out)), triageSkipPinCommand)
		return
	}
	t.Logf("SKIP PIN RECIPE EXECUTED: it printed %d, and the enumeration above counted %d.", got, want)
	if got != want {
		t.Errorf("THE RECORDED RECIPE AND THIS TEST DISAGREE: the command printed %d and the enumeration "+
			"counted %d. Whichever is wrong, the pin is now unreproducible again, which is the exact "+
			"state this recipe was written to end. Fix the command or the loop so the two measure the "+
			"same thing, and say in the commit which one was wrong:\n  %s",
			got, want, triageSkipPinCommand)
	}
}
