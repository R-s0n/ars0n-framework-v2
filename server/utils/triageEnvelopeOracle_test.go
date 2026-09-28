package utils

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"ars0n-framework-v2-server/utils/triage"

	"github.com/google/uuid"
)

// THE REGRESSION TEST FOR THE THREE ENVELOPE CLASSES, END TO END, AGAINST THE LIVE ORACLE.
//
// WHY IT HAS TO BE HERE AND NOT IN triageclasses. Every defect it guards against is an ORDERING
// defect inside Classify, and Classify takes a vault handle a classifier cannot forge: that is
// the whole point of the package split, and leak_test.go asserts the forgery does not compile. So
// the class's own package can unit-test its helpers and cannot drive its own Classify with real
// observations. This package can, because the runner lives here.
//
// WHAT IT CAUGHT, ALL THREE ON THE FIRST FULL RUN, 2026-09-19, and none of them visible to any
// unit test in the repository:
//
//	CRLF     answered cannot_determine (blocked) on /crlf/header, where it had just created a
//	         response header of its own name. faUniformBlock reads BODIES, a header sink returns
//	         a stable body, and the guard ran before the finding.
//	REDIRECT answered cannot_determine (blocked) on /redirect/local and /redirect/strictvalidator
//	         for the same reason: a redirector's body is constant and its evidence is in the
//	         Location.
//	DESER    answered cannot_determine (signature_in_baseline) on /deser/php while all three of
//	         its length arms were correctly naming 39, 32 and 35 bytes, because the baseline of a
//	         working unserialize sink carries the same sentence that the sink produces.
//
// Each is a class refusing to report the thing it was built to report, on the route built to make
// it report, and each looked cautious rather than broken. A detector that cannot fire is worth
// less than no detector, because the operator reads its silence as coverage.
func TestTheEnvelopeClassesFireOnTheirOwnOracleRoutesAndStaySilentBesideThem(t *testing.T) {
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
			return
		}
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM scope_targets WHERE id = $1`, targetID); err != nil {
			t.Errorf("clean up scope target %s: %v", targetID, err)
		}
	})

	// Each row is one route and what each of the three classes must say about it. An empty want
	// means the row is not asserted for that class, which is only used where the correct answer
	// depends on machinery outside these three classes.
	type expect struct {
		route string
		param string
		value string
		class string
		// fire is whether this class must reach finding or suspicious here. The silent rows are
		// the ones doing the work: a detector watched only firing is not verified.
		fire bool
		// state, when set, is the exact verdict required.
		state triage.TriageState
	}
	rows := []expect{
		{route: "/crlf/header", param: "q", value: "hello", class: "CRLF", fire: true, state: triage.StateFinding},
		{route: "/crlf/setcookie", param: "q", value: "hello", class: "CRLF", fire: true, state: triage.StateFinding},
		{route: "/crlf/lfonly", param: "q", value: "hello", class: "CRLF", fire: true, state: triage.StateFinding},
		// THE DECODE-DEPTH ROUTE. It strips the control bytes out of the once-decoded value and
		// then percent-decodes again, so CRLF-Q1 must be neutralised and CRLF-Q4 must get through.
		// It is the row that pins the encoder fix: while Q4 used EncodeLiteralPct the two probes
		// were the same four-hex-digit request in different case and this route silenced both.
		{route: "/crlf/doubledecode", param: "q", value: "hello", class: "CRLF", fire: true, state: triage.StateFinding},
		{route: "/crlf/edgereject", param: "q", value: "hello", class: "CRLF", state: triage.StateNotExploitable},
		{route: "/crlf/preset", param: "q", value: "hello", class: "CRLF", state: triage.StateCannotDetermine},
		{route: "/clean/echo", param: "q", value: "hello", class: "CRLF", state: triage.StateClean},
		// NOT CLEAN, AND THE ORACLE RUN IS WHY. /clean/validate refuses every value, line break or
		// not, with one identical page the baseline does not get. The edge-defence rule correctly
		// does NOT fire, because the no-line-break control was refused too, and the honest answer
		// to what is left is that the header writer was never reached and nothing about it was
		// measured. The class's own declared case said clean; not knowing is not clean.
		{route: "/clean/validate", param: "id", value: "1", class: "CRLF", state: triage.StateCannotDetermine},

		{route: "/deser/php", param: "q", value: "hello", class: "DESER", fire: true, state: triage.StateFinding},
		{route: "/deser/phpwrapped", param: "q", value: "hello", class: "DESER", fire: true, state: triage.StateFinding},
		{route: "/deser/java", param: "q", value: "hello", class: "DESER", fire: true, state: triage.StateFinding},
		{route: "/deser/pickle", param: "q", value: "hello", class: "DESER", fire: true, state: triage.StateFinding},
		{route: "/deser/phpstatic", param: "q", value: "hello", class: "DESER", state: triage.StateCannotDetermine},
		{route: "/deser/preset", param: "q", value: "hello", class: "DESER", state: triage.StateCannotDetermine},
		{route: "/clean/b64noise", param: "q", value: "hello", class: "DESER", state: triage.StateClean},

		{route: "/redirect", param: "next", value: "/home", class: "REDIRECT", fire: true, state: triage.StateFinding},
		{route: "/redirect/strictvalidator", param: "next", value: "/home", class: "REDIRECT", fire: true, state: triage.StateSuspicious},
		{route: "/redirect/meta", param: "next", value: "/home", class: "REDIRECT", fire: true, state: triage.StateSuspicious},
		{route: "/redirect/local", param: "next", value: "/home", class: "REDIRECT", state: triage.StateNotExploitable},
		{route: "/redirect/fixed", param: "next", value: "/home", class: "REDIRECT", state: triage.StateClean},
		{route: "/redirect/alwaysoffsite", param: "next", value: "/home", class: "REDIRECT", state: triage.StateClean},
		{route: "/clean/echo", param: "q", value: "hello", class: "REDIRECT", state: triage.StateClean},
	}

	host, port, scheme := triageSplitBase(t, base)
	vectorOf := map[string]string{}
	routeOf := map[string]string{}
	for _, r := range rows {
		key := r.route + "?" + r.param
		if _, seen := vectorOf[key]; seen {
			continue
		}
		vectorID := uuid.New().String()
		evidence := fmt.Sprintf("%s%s?%s=%s", base, r.route, r.param, r.value)
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO attack_vectors (id, scope_target_id, vector_key, method, scheme, domain, port,
			                            path, insertion_point, parameters, evidence_url)
			VALUES ($1,$2,$3,'GET',$4,$5,$6,$7,'query',$8,$9)`,
			vectorID, targetID, "envelope:"+key, scheme, host, port, r.route,
			[]string{r.param}, evidence); err != nil {
			t.Fatalf("insert vector %s: %v", key, err)
		}
		vectorOf[key] = vectorID
		routeOf[vectorID] = key
	}

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = key == "crlf" || key == "deser" || key == "redirect"
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	settings.Pacing.RequestsPerSecond = 60
	settings.Pacing.Concurrency = 6
	settings.Pacing.PerSlotProbes = 40
	settings.Pacing.PerRunProbes = 20000
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, targetID, settings)

	runUUID, err := StartTriageRun(ctx, targetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 15*time.Minute); status != "completed" {
		var runErr *string
		_ = dbPool.QueryRow(ctx, `SELECT error FROM triage_runs WHERE id = $1`, runUUID).Scan(&runErr)
		msg := ""
		if runErr != nil {
			msg = *runErr
		}
		t.Fatalf("the run finished %q: %s", status, msg)
	}

	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	got := map[string]triage.ClassVerdict{}
	for _, r := range verdicts {
		key := routeOf[r.VectorID] + "|" + r.Verdict.Class.String()
		got[key] = r.Verdict
		t.Logf("%-28s %-9s %-16s %s", routeOf[r.VectorID], r.Verdict.Class, r.Verdict.State,
			triageFirstLine(r.Verdict.Reason))
	}

	// ONE CLASS MUST BE SEEN ON BOTH SIDES OF ITS OWN LINE. A class that only ever fires and a
	// class that only ever stays silent are equally unverified, so the count of each is asserted
	// per class rather than left to the rows happening to cover both.
	fires := map[string]int{}
	silences := map[string]int{}

	for _, r := range rows {
		key := r.route + "?" + r.param + "|" + r.class
		v, ok := got[key]
		if !ok {
			t.Errorf("%s produced no verdict on %s, so the pair reads as untouched when it was tested",
				r.class, r.route)
			continue
		}
		fired := v.State == triage.StateFinding || v.State == triage.StateSuspicious
		if fired {
			fires[r.class]++
		} else {
			silences[r.class]++
		}
		if fired != r.fire {
			verb := "stayed silent on"
			if fired {
				verb = "fired on"
			}
			t.Errorf("%s %s %s (%s). want fire=%v. reason: %s",
				r.class, verb, r.route, v.State, r.fire, triageFirstLine(v.Reason))
			continue
		}
		if r.state != "" && v.State != r.state {
			t.Errorf("%s reported %s on %s, want %s. reason: %s",
				r.class, v.State, r.route, r.state, triageFirstLine(v.Reason))
		}
	}

	for _, c := range []string{"CRLF", "DESER", "REDIRECT"} {
		if fires[c] == 0 {
			t.Errorf("%s never fired anywhere in this run, so its detectors were only watched staying silent", c)
		}
		if silences[c] == 0 {
			t.Errorf("%s fired on every route in this run, which is what a detector that fires on everything looks like", c)
		}
	}
}
