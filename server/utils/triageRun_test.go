package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"ars0n-framework-v2-server/utils/triage"

	"github.com/google/uuid"
)

// Tests for the triage runner.
//
// THE ONE THAT MATTERS IS TestTheRunnerFiresOnTheOracleAndStaysSilentBesideIt. A detector that has
// only ever been watched firing is not verified: a classifier that always returned "finding" would
// pass every positive test in this file. So the end-to-end test asserts BOTH directions from the
// SAME class against the SAME run: SSTI fires on /ssti, where an emulated FreeMarker really does
// evaluate its arithmetic, and stays silent on /xss, where the same bytes are reflected back
// verbatim and evaluated by nothing.
//
// Everything above that is a unit test of the parts of the runner that decide what goes on the
// wire, because those are where a false negative is manufactured: a token the runner did not
// substitute, a tier that silently allowed nothing, a deselected vector that produced no row.

// ---------------------------------------------------------------------------------------------
// Payload rendering, and the fail-closed guard
// ---------------------------------------------------------------------------------------------

func triageTestMarker(t *testing.T, class triage.ClassID, ordinal uint64) triage.Marker {
	t.Helper()
	m, err := triage.MintMarkerAt(triageRunnerCapability(), "rn01", class, ordinal)
	if err != nil {
		t.Fatalf("mint marker for %s: %v", class, err)
	}
	return m
}

// A marker-shaped literal in a declared payload is substituted for the minted marker. The classes
// cannot mint, so if this does not happen the probe carries a marker belonging to no run, every
// attribution check refuses it, and the class reports cannot_determine forever.
func TestTheRunnerSubstitutesTheMintedMarkerForAClassLiteral(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	spec := triage.ProbeSpec{ID: "SQL-Q1", Class: triage.ClassSQL, Logical: []byte("'zqjsql0000004ju8'")}
	req := triage.ProbeRequest{Spec: "SQL-Q1", Variant: map[string]string{
		triageVarSQLMarkerInPayload: "yes", triageVarSQLValuePosition: "lead"}}
	slot := triage.Slot{Value: "1", Kind: triage.KindQuery}

	got, why := triageRenderPayload(spec, req, slot, marker)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	want := "1'" + string(marker) + "'"
	if string(got) != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

// sql_value_position is the directive that puts the observed value back. The catalogue writes
// SQL-Q1 as V'M' and the Go class dropped the leading V into this variant, so a runner that
// ignored it would send 'M' into a slot the application reads as a different value entirely.
func TestTheRunnerHonoursTheValuePositionDirective(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	spec := triage.ProbeSpec{ID: "SQL-MP", Class: triage.ClassSQL, Logical: []byte("zqjsql0000004ju8 ")}
	req := triage.ProbeRequest{Spec: "SQL-MP", Variant: map[string]string{
		triageVarSQLMarkerInPayload: "yes", triageVarSQLValuePosition: "trail"}}
	got, why := triageRenderPayload(spec, req, triage.Slot{Value: "abc"}, marker)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if want := string(marker) + " abc"; string(got) != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

// sql_marker_in_payload "no" means the marker must NOT be written into the value. Those probes are
// complete SQL fragments whose trailing quote repair breaks if a marker is appended, and a runner
// that appended one anyway would make the true arm a syntax error and the boolean detector could
// never fire.
func TestTheRunnerLeavesTheMarkerOutWhenTheClassSaysSo(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	spec := triage.ProbeSpec{ID: "SQL-A1", Class: triage.ClassSQL, Logical: []byte("' AND (4093*7)=28651 AND 'a'='a")}
	req := triage.ProbeRequest{Spec: "SQL-A1", Variant: map[string]string{
		triageVarSQLMarkerInPayload: "no", triageVarSQLValuePosition: "lead"}}
	got, _ := triageRenderPayload(spec, req, triage.Slot{Value: "1"}, marker)
	if strings.Contains(string(got), string(marker)) {
		t.Errorf("rendered %q, which carries the marker the class asked to be left out", got)
	}
}

// The file-access family declares a ${...} token grammar and every one of its classifiers says, in
// its own words, that an unsubstituted token must never reach a clean. Only the runner can
// enforce that, because a class sees a response and not the wire.
func TestTheRunnerSubstitutesTheFileFamilyTokens(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassLFI, uint64(triage.ClassLFI))
	spec := triage.ProbeSpec{ID: "LFI-L10", Class: triage.ClassLFI, Logical: []byte("${dir}../../etc/passwd${ext}")}
	req := triage.ProbeRequest{Spec: "LFI-L10", Variant: map[string]string{"dir": "up/", "ext": ".png"}}
	got, why := triageRenderPayload(spec, req, triage.Slot{Value: "up/x.png"}, marker)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if want := "up/../../etc/passwd.png"; string(got) != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

// AND THE OTHER HALF, WHICH IS THE ONE THAT PREVENTS A FALSE CLEAN. A token the runner did not
// substitute refuses the probe. Sending it would put literal bytes on the wire that no application
// can answer, the class would see a null result, and a null result is what a clean is made of.
func TestAnUnsubstitutedTokenRefusesTheProbeRatherThanSendingIt(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassLFI, uint64(triage.ClassLFI))
	spec := triage.ProbeSpec{ID: "LFI-L10", Class: triage.ClassLFI, Logical: []byte("${dir}../../etc/passwd")}
	req := triage.ProbeRequest{Spec: "LFI-L10", Variant: map[string]string{}}
	_, why := triageRenderPayload(spec, req, triage.Slot{Value: "x"}, marker)
	if why == "" {
		t.Fatal("an unsubstituted ${dir} was accepted, so the probe would have gone out testing nothing and the class would have read the silence as clean")
	}
	if !strings.Contains(why, "${dir}") {
		t.Errorf("the refusal is %q, which does not name the token that was left behind", why)
	}
}

// THE GUARD MUST BE CLASS-SCOPED. SSTI-F1's payload IS ${1721*913} and CMDI-B11's carries ${IFS}:
// those are payload bytes, not tokens. A runner that refused them would turn the class with the
// cheapest true positive in the catalogue into a class that never sends anything, and every slot
// in the corpus would come back untested while looking configured.
func TestTheDollarGuardDoesNotRefuseAPayloadThatIsMadeOfDollarBraces(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSSTI, uint64(triage.ClassSSTI))
	spec := triage.ProbeSpec{ID: "SSTI-F1", Class: triage.ClassSSTI, Logical: []byte("${1721*913}")}
	got, why := triageRenderPayload(spec, triage.ProbeRequest{Spec: "SSTI-F1"}, triage.Slot{Value: "hello"}, marker)
	if why != "" {
		t.Fatalf("SSTI-F1 was refused as an unsubstituted token: %s", why)
	}
	if string(got) != "${1721*913}" {
		t.Errorf("rendered %q, want the payload unchanged", got)
	}
}

// The percent-encoded marker form is what the decode probes are, and getting it wrong makes
// decode_depth permanently unknown, which downstream is a caveat on every verdict on the slot.
func TestTheDecodeProbeGoesOutAsPercentEscapes(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	spec := triage.ProbeSpec{ID: "SQL-DEC", Class: triage.ClassSQL, Logical: []byte("%7a%71%6a")}
	req := triage.ProbeRequest{Spec: "SQL-DEC", Variant: map[string]string{
		triageVarSQLMarkerForm: "percent_bytes", triageVarSQLValuePosition: "lead"}}
	got, why := triageRenderPayload(spec, req, triage.Slot{Value: "1"}, marker)
	if why != "" {
		t.Fatalf("render refused: %s", why)
	}
	if want := "1" + triagePercentEncodeAll(string(marker)); string(got) != want {
		t.Errorf("rendered %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------------------------
// The settings, honoured
// ---------------------------------------------------------------------------------------------

// A class the operator switched off is not planned at all, and a class with no entry in a stored
// document is ON. The second half is the important one: NormaliseTriageSettings fills the document
// from the defaults, and a class silently missing from a stored document must not become a whole
// attack class recorded as never attempted.
func TestADisabledClassIsNotPlannedAndAnAbsentOneIs(t *testing.T) {
	all := RegisteredTriageClassIDs()
	if len(all) == 0 {
		t.Skip("NOT MEASURED: no classifier is registered in this build, so nothing about class selection was exercised.")
	}
	settings := TriageSettingsDefaults()
	off := all[0]
	settings.Classes[TriageClassKey(off)] = TriageClassSetting{Enabled: false, Tier: "reduced", MaxRisk: "R2"}
	if len(all) > 1 {
		delete(settings.Classes, TriageClassKey(all[1]))
	}

	got := triageEnabledClasses(settings)
	for _, id := range got {
		if id == off {
			t.Errorf("class %s was switched off and is still in the plan", off)
		}
	}
	if len(all) > 1 {
		found := false
		for _, id := range got {
			if id == all[1] {
				found = true
			}
		}
		if !found {
			t.Errorf("class %s has no entry in the stored document and was dropped, which is a whole attack class recorded as never attempted", all[1])
		}
	}
}

// The tier the operator bought is the tier that is sent. opt_in is never included by a broader
// tier: the registry's rule is that it is chosen per run with the cost named.
func TestTheTierCeilingIsApplied(t *testing.T) {
	class := triage.ClassSQL
	cases := []struct {
		tier  string
		probe triage.ProbeTier
		want  bool
	}{
		{"reduced", triage.TierReduced, true},
		{"reduced", triage.TierFull, false},
		{"reduced", triage.TierOptIn, false},
		{"full", triage.TierReduced, true},
		{"full", triage.TierFull, true},
		{"full", triage.TierOptIn, false},
		{"opt_in", triage.TierOptIn, true},
	}
	for _, c := range cases {
		rr := &triageRunner{settings: TriageInvestigateSettings{
			Classes: map[string]TriageClassSetting{TriageClassKey(class): {Enabled: true, Tier: c.tier}},
		}}
		if got := rr.tierAllows(class, triage.ProbeSpec{Tier: c.probe}); got != c.want {
			t.Errorf("tier %q against probe tier %q = %v, want %v", c.tier, c.probe, got, c.want)
		}
	}
}

// The per-class risk ceiling. A probe above the ceiling is refused on safety grounds, which is
// not_probed with a reason and is never a clean.
func TestTheRiskCeilingIsApplied(t *testing.T) {
	class := triage.ClassSQL
	rr := &triageRunner{settings: TriageInvestigateSettings{
		Classes: map[string]TriageClassSetting{TriageClassKey(class): {Enabled: true, MaxRisk: "R1"}},
	}}
	if !rr.riskAllows(class, triage.ProbeSpec{Risk: triage.RiskR1}) {
		t.Error("an R1 probe was refused under an R1 ceiling")
	}
	if rr.riskAllows(class, triage.ProbeSpec{Risk: triage.RiskR2}) {
		t.Error("an R2 probe was allowed under an R1 ceiling, so the operator's safety setting bought nothing")
	}
}

// ---------------------------------------------------------------------------------------------
// The unknown states
// ---------------------------------------------------------------------------------------------

// Every unknown row the runner writes must pass ClassVerdict.Validate, which refuses one with no
// reason. An unknown with no reason is how a check that never ran becomes a clean on the next
// refactor, so it is checked here for every state the runner can emit.
func TestEveryUnknownTheRunnerWritesCarriesAReasonAndNoGrade(t *testing.T) {
	states := []triage.TriageState{
		triage.StateNotRun, triage.StateNotApplicable, triage.StateNotProbed,
		triage.StateCannotDetermine, triage.StateNotReachable, triage.StateNotPlanned,
	}
	for _, s := range states {
		v := triageUnknownVerdict(triage.ClassSQL, "query:id", s, "")
		if err := v.Validate(); err != nil {
			t.Errorf("the runner's %s row does not validate: %v", s, err)
		}
		if !v.State.IsUnknown() {
			t.Errorf("%s is not unknown, so the runner is using it for something it does not mean", s)
		}
		if v.State.CountsAsClean() {
			t.Errorf("%s counts as clean, which is the whole bug this layer exists to stop", s)
		}
	}
}

// A run that is cancelled writes not_run for everything it never reached. Absent rows would read
// as coverage nobody has.
func TestCancellationProducesNotRunAndNeverClean(t *testing.T) {
	v := triageUnknownVerdict(triage.ClassSSTI, "query:q", triage.StateNotRun,
		"cancelled: the operator cancelled the run before this pair was measured")
	if v.State.CountsAsClean() {
		t.Fatal("a cancelled pair reads as clean")
	}
	cov := triage.SummariseVerdicts([]triage.ClassVerdict{v})
	if cov.RendersAsClean() {
		t.Fatal("a coverage set holding one cancelled pair renders as clean")
	}
	if cov.Unknown != 1 {
		t.Errorf("the cancelled pair is counted as %d unknowns, want 1", cov.Unknown)
	}
}

// ---------------------------------------------------------------------------------------------
// The encoder choice
// ---------------------------------------------------------------------------------------------

// ProbeSpec.Encoders is a LIST and ProbeRequest carries no encoder, so the runner chooses. It must
// choose one that FITS the slot: taking the first in the list would send a query encoder into a
// cookie, EncodeSlotInto would refuse it by name, and the slot would read as unreachable when it
// was the runner choosing wrongly.
func TestTheRunnerPicksAnEncoderThatFitsTheSlotKind(t *testing.T) {
	spec := triage.ProbeSpec{Encoders: []triage.EncoderMode{triage.EncodeQuery, triage.EncodeCookie}}
	got := triageEncoderFor(spec, triage.ProbeRequest{}, triage.Slot{Kind: triage.KindCookie})
	if got != triage.EncodeCookie {
		t.Errorf("chose %q for a cookie slot, want %q", got, triage.EncodeCookie)
	}
	got = triageEncoderFor(spec, triage.ProbeRequest{}, triage.Slot{Kind: triage.KindQuery})
	if got != triage.EncodeQuery {
		t.Errorf("chose %q for a query slot, want %q", got, triage.EncodeQuery)
	}
}

// ---------------------------------------------------------------------------------------------
// End to end, against the local oracle
// ---------------------------------------------------------------------------------------------

// triageOracleBase is the only target these tests may reach. It is read from the environment so
// the suite cannot be pointed at anything else by editing a constant.
func triageOracleBase(t *testing.T) string {
	t.Helper()
	base := strings.TrimRight(os.Getenv("TRIAGE_ORACLE_URL"), "/")
	if base == "" {
		base = "http://oracle:8000"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(base + "/ssti?tpl=hello")
	if err != nil {
		t.Skipf("NOT MEASURED: the canary oracle at %s is not reachable (%v), so the runner was never shown producing a verdict from a real classifier against a real response. This is a gap in coverage, not a pass.", base, err)
	}
	resp.Body.Close()
	return base
}

// triageOracleTarget creates a scope target whose host is the oracle's, plus the two vectors the
// end-to-end test needs, and removes all of it afterwards.
func triageOracleTarget(t *testing.T, ctx context.Context, base string) (string, map[string]string) {
	t.Helper()
	id := uuid.New().String()
	if _, err := dbPool.Exec(ctx,
		`INSERT INTO scope_targets (id, type, mode, scope_target, active) VALUES ($1, 'URL', 'Passive', $2, FALSE)`,
		id, base); err != nil {
		t.Fatalf("create scope target: %v", err)
	}
	t.Cleanup(func() {
		// TRIAGE_TEST_KEEP leaves the target and everything hanging off it in place, so the rows
		// this run wrote can be read back out of the database by hand. It is off by default: a
		// suite that leaves rows behind is a suite that pollutes the next run's counts.
		if os.Getenv("TRIAGE_TEST_KEEP") != "" {
			t.Logf("TRIAGE_TEST_KEEP is set, so scope target %s and its triage rows are left in the database", id)
			return
		}
		if _, err := dbPool.Exec(context.Background(), `DELETE FROM scope_targets WHERE id = $1`, id); err != nil {
			t.Errorf("could not clean up scope target %s: %v", id, err)
		}
	})

	host, port, scheme := triageSplitBase(t, base)
	vectors := map[string]string{}
	for _, v := range []struct{ key, path, param string }{
		{"ssti", "/ssti", "tpl"},
		{"xss", "/xss", "q"},
		// The static index. It takes a query parameter and IGNORES it, so every probe in the
		// catalogue leaves the response byte-identical to the baseline. That is the only shape
		// that can produce an honest CLEAN, and a clean is the verdict a detector has to be
		// watched reaching before it is worth anything.
		{"static", "/", "q"},
	} {
		vectorID := uuid.New().String()
		evidence := fmt.Sprintf("%s%s?%s=hello", base, v.path, v.param)
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO attack_vectors (id, scope_target_id, vector_key, method, scheme, domain, port,
			                            path, insertion_point, parameters, evidence_url)
			VALUES ($1,$2,$3,'GET',$4,$5,$6,$7,'query',$8,$9)`,
			vectorID, id, v.key+":"+v.path, scheme, host, port, v.path, []string{v.param}, evidence); err != nil {
			t.Fatalf("insert vector %s: %v", v.key, err)
		}
		vectors[v.key] = vectorID
	}
	return id, vectors
}

func triageSplitBase(t *testing.T, base string) (host string, port int, scheme string) {
	t.Helper()
	scheme = "http"
	rest := base
	if i := strings.Index(base, "://"); i >= 0 {
		scheme = base[:i]
		rest = base[i+3:]
	}
	host = rest
	port = 80
	if scheme == "https" {
		port = 443
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		host = rest[:i]
		fmt.Sscanf(rest[i+1:], "%d", &port)
	}
	return host, port, scheme
}

// triageSaveSettings writes the settings document the run will read, so the test exercises the
// same path the Configure modal writes through.
func triageSaveSettings(t *testing.T, ctx context.Context, scopeTargetID string, s TriageInvestigateSettings) {
	t.Helper()
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("encode settings: %v", err)
	}
	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_tool_settings (scope_target_id, tool, settings, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (scope_target_id, tool)
		DO UPDATE SET settings = EXCLUDED.settings, updated_at = NOW()`,
		scopeTargetID, TriageSettingsTool, encoded); err != nil {
		t.Fatalf("save settings: %v", err)
	}
}

func triageWaitForRun(t *testing.T, ctx context.Context, runUUID string, limit time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		var status string
		if err := dbPool.QueryRow(ctx, `SELECT status FROM triage_runs WHERE id = $1`, runUUID).Scan(&status); err != nil {
			t.Fatalf("read run status: %v", err)
		}
		if status != "running" {
			return status
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("the run did not finish within %v", limit)
	return ""
}

// THE END-TO-END TEST. One run, three vectors, two classes, both directions.
//
// SSTI must FIRE on /ssti, where the oracle's emulated FreeMarker really evaluates what it is
// handed, and no class may fire on the static index, which takes a query parameter and ignores it
// so that every probe in the catalogue leaves the page byte-identical to its own baseline. At
// least one class must reach an outright CLEAN there.
//
// THE CLEAN IS THE HALF THAT TESTS THE RUNNER. A classifier that always answered "finding" would
// pass the firing assertion on its own, and so would a runner that mixed one slot's responses into
// another's: the first version of this file did exactly that, and SSTI reported a FreeMarker
// ParseException on /xss, whose response contains no error text at all.
func TestTheRunnerFiresOnTheOracleAndStaysSilentBesideIt(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, vectors := triageOracleTarget(t, ctx, base)

	// SSTI and SQL, at full tier. Two classes rather than ten so the run is small enough to read
	// by eye, and these two because between them they cover both directions: SSTI has a real
	// positive on this oracle and SQL has a real clean on a page nothing it sends can move.
	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = key == TriageClassKey(triage.ClassSSTI) || key == TriageClassKey(triage.ClassSQL)
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	settings.Pacing.RequestsPerSecond = 20
	settings.Pacing.RespectTargetBudget = false

	// TWO OF THE OPERATOR'S OWN PAYLOADS, because they are the one verdict path the runner judges
	// itself, and they are therefore the one place a CLEAN can be demonstrated end to end against
	// this oracle. See the note on the assertions below for why no registered classifier reaches
	// one here.
	settings.CustomPayloads = []TriageCustomPayload{
		{
			ID: "quiet", Class: TriageClassKey(triage.ClassSQL), Label: "never matches",
			Payload: "ars0nquiet" + triage.MarkerPlaceholder, Encoding: "utf8",
			Points: []string{"query"}, Enabled: true,
			Detection: TriageDetection{Mode: TriageDetectBodyContains,
				Pattern: "ars0n-triage-string-no-page-can-contain"},
		},
		{
			ID: "echo", Class: TriageClassKey(triage.ClassSQL), Label: "marker comes back",
			Payload: "ars0necho" + triage.MarkerPlaceholder, Encoding: "utf8",
			Points: []string{"query"}, Enabled: true,
			Detection: TriageDetection{Mode: TriageDetectReflect},
		},
	}
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 10*time.Minute); status != "completed" {
		var runErr *string
		_ = dbPool.QueryRow(ctx, `SELECT error FROM triage_runs WHERE id = $1`, runUUID).Scan(&runErr)
		msg := ""
		if runErr != nil {
			msg = *runErr
		}
		t.Fatalf("the run finished %q: %s", status, msg)
	}

	rows, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("the run produced no verdict at all, which is the silent-zero shape this whole layer exists to stop")
	}

	name := map[string]string{}
	for k, id := range vectors {
		name[id] = k
	}
	var sstiFired, cleanOnStatic, echoFiredOnXSS bool
	for _, r := range rows {
		v := r.Verdict
		arm := r.Arm
		if arm == "" {
			arm = "-"
		}
		t.Logf("%-7s %-5s %-10s %-9s %-16s grade=%-6s oracle=%-16s unproven=%d reason=%s",
			name[r.VectorID], v.Class, v.SlotKey, arm, v.State, v.Grade, v.Oracle, r.UnprovenProbes,
			triageFirstLine(v.Reason))

		custom := strings.HasPrefix(r.Arm, "custom:")
		switch name[r.VectorID] {
		case "ssti":
			if !custom && v.Class == triage.ClassSSTI && v.State.Kind() == triage.StateKindPositive {
				sstiFired = true
			}
		case "xss":
			if !custom && v.State.Kind() == triage.StateKindPositive {
				t.Errorf("%s fired on /xss, where the payload is reflected and evaluated by nothing. A detector that fires on reflection fires on everything", v.Class)
			}
			if r.Arm == "custom:echo" && v.State.Kind() == triage.StateKindPositive {
				echoFiredOnXSS = true
			}
		case "static":
			if v.State.Kind() == triage.StateKindPositive {
				t.Errorf("%s (arm %q) fired on the static index, which ignores its query string entirely, so nothing sent there could have changed that page", v.Class, r.Arm)
			}
			if v.State.CountsAsClean() {
				cleanOnStatic = true
			}
		}
	}

	if !sstiFired {
		t.Error("SSTI produced no positive on /ssti, where the oracle's emulated FreeMarker really does evaluate what it is handed. A runner never shown producing a true positive has not been shown to run the classifiers at all")
	}
	if !echoFiredOnXSS {
		t.Error("the reflect-detection payload did not fire on /xss, which reflects everything it is given, so the runner's own oracle path was never shown answering yes")
	}

	// THE TRUE NEGATIVE, AND WHY IT COMES FROM THIS PATH.
	//
	// No REGISTERED CLASSIFIER reaches an outright clean against this oracle, and their reasons
	// are printed above and are correct: SSTI says no_reflection on the static index because a
	// blind template sink looks exactly like a page that ignores its input, and SQL says
	// decode_depth_unknown there because a page that echoes nothing cannot answer its decode
	// probe. Those are honest unknowns, not a runner defect. The oracle ships no clean control at
	// all, which its own notes call the headline gap: every route it serves is deliberately
	// vulnerable, so a detector cannot be watched staying silent on one.
	//
	// The operator's own payloads ARE judged by the runner, so this is the negative the runner can
	// be held to end to end: a payload that went out proven, against a page that answered, whose
	// declared oracle stayed silent, recorded as clean rather than as an absence.
	if !cleanOnStatic {
		t.Error("nothing reached a CLEAN on the static index. A runner never shown producing a true negative is not verified: a detector that always says yes would pass the positive assertion on its own")
	}

	// THE COVERAGE HALF. Verdicts alone do not say what was never measured, and the split between
	// the two tables is the thing the operator is paying for.
	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	t.Logf("coverage: %+v", cov)
	if cov.EligiblePairs == 0 {
		t.Error("the run recorded no coverage pairs, so nothing says which (slot, class) cells were eligible and the verdicts have no denominator")
	}
	if cov.RanPairs == 0 {
		t.Error("the run measured no pair at all, so every verdict above came from somewhere other than a request")
	}
}

func triageFirstLine(s string) string {
	if i := strings.IndexAny(s, ".\n"); i > 0 {
		return s[:i]
	}
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

// A deselected vector is not scanned, and its coverage row says deselected rather than clean. The
// two are the same pixel on a report and completely different facts.
func TestADeselectedVectorIsRecordedAsNotRunAndNeverClean(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, vectors := triageOracleTarget(t, ctx, base)

	if _, err := dbPool.Exec(ctx, `
		INSERT INTO vector_scan_selection (scope_target_id, tool, vector_id, enabled)
		VALUES ($1, $2, $3, FALSE)
		ON CONFLICT (scope_target_id, tool, vector_id) DO UPDATE SET enabled = FALSE`,
		scopeTargetID, TriageRunTool, vectors["xss"]); err != nil {
		t.Skipf("NOT MEASURED: could not write a selection row (%v), so deselection was not exercised.", err)
	}

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = key == TriageClassKey(triage.ClassSSTI)
		settings.Classes[key] = cs
	}
	settings.Pacing.RequestsPerSecond = 20
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 5*time.Minute); status != "completed" {
		t.Fatalf("the run finished %q", status)
	}

	rows, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	sawDeselected := false
	for _, r := range rows {
		if r.VectorID != vectors["xss"] {
			continue
		}
		if r.Verdict.State.CountsAsClean() {
			t.Errorf("the deselected vector produced a clean verdict on %s, so switching a vector off bought coverage nobody measured", r.Verdict.SlotKey)
		}
		if strings.Contains(r.Verdict.Reason, "deselected") {
			sawDeselected = true
		}
	}
	if !sawDeselected {
		t.Error("the deselected vector produced no row saying so, so an operator reading the report cannot tell it from a vector that was tested")
	}
}

// ---------------------------------------------------------------------------------------------
// The three runner defects, end to end against the oracle
// ---------------------------------------------------------------------------------------------

// triageCovRow is one row of triage_coverage. There is no loader for the individual rows in the
// store because nothing but the report ever needed them; the assertions below need them because
// the question they ask is "did this pair send anything", and only the coverage table answers it.
type triageCovRow struct {
	VectorID string
	SlotKey  string
	Class    string
	Planned  int
	Sent     int
	Ran      bool
}

func triageRunCoverageRows(t *testing.T, ctx context.Context, runUUID string) []triageCovRow {
	t.Helper()
	rows, err := dbPool.Query(ctx, `
		SELECT vector_id, slot_key, class_name, planned_probes, sent_probes, ran
		FROM triage_coverage WHERE run_id = $1 ORDER BY class_name, vector_id, slot_key`, runUUID)
	if err != nil {
		t.Fatalf("read coverage rows: %v", err)
	}
	defer rows.Close()
	var out []triageCovRow
	for rows.Next() {
		var r triageCovRow
		if err := rows.Scan(&r.VectorID, &r.SlotKey, &r.Class, &r.Planned, &r.Sent, &r.Ran); err != nil {
			t.Fatalf("scan coverage row: %v", err)
		}
		out = append(out, r)
	}
	return out
}

// THE WHOLE-REGISTRY RUN. Every class the settings layer offers, enabled, at full tier, against
// the oracle, once. The four subtests are four readings of the same run rather than four runs,
// because the run costs minutes and they are all asking about the same set of rows.
//
// WHAT EACH SUBTEST IS FOR is in the comment above it. Between them they are the executable form
// of one rule: a pair that was not measured must say so, and a pair that WAS measured must not
// claim it was not.
func TestTheWholeRegistryRunsAndEveryClassSaysWhatItDid(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, vectors := triageOracleTarget(t, ctx, base)

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = true
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	settings.Pacing.RequestsPerSecond = 40
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 20*time.Minute); status != "completed" {
		var runErr *string
		_ = dbPool.QueryRow(ctx, `SELECT error FROM triage_runs WHERE id = $1`, runUUID).Scan(&runErr)
		msg := ""
		if runErr != nil {
			msg = *runErr
		}
		t.Fatalf("the run finished %q: %s", status, msg)
	}

	name := map[string]string{}
	for k, id := range vectors {
		name[id] = k
	}
	sentPair := map[string]int{}
	sentClass := map[string]int{}
	plannedClass := map[string]int{}
	for _, c := range triageRunCoverageRows(t, ctx, runUUID) {
		sentPair[c.Class+"|"+c.VectorID+"|"+c.SlotKey] += c.Sent
		sentClass[c.Class] += c.Sent
		plannedClass[c.Class] += c.Planned
	}
	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	if len(verdicts) == 0 {
		t.Fatal("the run produced no verdict at all, which is the silent-zero shape this whole layer exists to stop")
	}
	for _, r := range verdicts {
		v := r.Verdict
		t.Logf("%-7s %-9s %-14s %-18s sent=%-3d %s", name[r.VectorID], v.Class, v.SlotKey, v.State,
			sentPair[v.Class.String()+"|"+r.VectorID+"|"+string(v.SlotKey)], triageFirstLine(v.Reason))
	}
	for cls := range plannedClass {
		t.Logf("class %-9s planned=%-4d sent=%d", cls, plannedClass[cls], sentClass[cls])
	}

	// DEFECT 1. The classify-time budget must reflect what was actually spent.
	//
	// The runner passed a literal 0 as remainingPerSlot when it built the ClassifyCtx, so
	// TriageBudget.Exhausted() was true for every class on every slot of every run. ELI and NOSQL
	// both ask that question INSIDE Classify, so both returned not_run (probe_budget_exhausted,
	// "nothing was sent") on slots where they had just sent fourteen and twenty probes. Two of
	// ten classes could never conclude and about a quarter of the run's requests bought a verdict
	// that said nothing had been sent.
	//
	// THE ASSERTION IS THE CONTRADICTION ITSELF and not a number: no pair may say the cap bit
	// before it sent anything while its own coverage row says it sent something.
	//
	// THE CAP BITING MID-LADDER IS NOT THAT CONTRADICTION, and reading it as one was this test's
	// own defect. A class that sent its whole per-slot allowance of 24 and then found the budget
	// gone has to SAY the budget stopped it: "the silence covers only the probes that were sent"
	// is the operator's warning that the ladder is incomplete, and it is the opposite of the
	// zero-probe claim this subtest hunts. Matching the key probe_budget_exhausted alone flagged
	// both, so on 2026-09-18 SQL hitting its honest per-slot cap on /xss and /ssti failed a test
	// whose stated defect it does not have.
	//
	// So the rule is on the CLAIM and it defaults to strict: a budget row whose coverage row says
	// probes went out must ACKNOWLEDGE them in words. A reason that does not is treated as
	// claiming zero, which also catches the bare, reasonless form that says nothing at all.
	acknowledgesSends := func(reason string) bool {
		for _, phrase := range []string{
			"the probes that were sent",
			"the probes it did send",
		} {
			if strings.Contains(reason, phrase) {
				return true
			}
		}
		return false
	}
	t.Run("the classify-time budget reflects what was actually spent", func(t *testing.T) {
		bad := 0
		for _, r := range verdicts {
			v := r.Verdict
			if !strings.Contains(v.Reason, "probe_budget_exhausted") {
				continue
			}
			n := sentPair[v.Class.String()+"|"+r.VectorID+"|"+string(v.SlotKey)]
			if n <= 0 {
				continue
			}
			if acknowledgesSends(v.Reason) {
				continue
			}
			bad++
			if bad <= 12 {
				t.Errorf("%s %s/%s says %q, which claims the cap bit before anything went out, and its own coverage row says it sent %d probes there. The budget the classifier was shown is not the budget the run spent. A class whose ladder was genuinely cut short mid-slot must say so, naming the probes that were sent",
					name[r.VectorID], v.Class, v.SlotKey, triageFirstLine(v.Reason), n)
			}
		}
		if bad > 12 {
			t.Errorf("... and %d more pairs with the same contradiction", bad-12)
		}
	})

	// DEFECT 2. CMDI's post-baseline.
	//
	// ClassifyCtx.PostBaseline is documented as "taken after the last probe on the slot", and the
	// runner never took it: it built every ClassifyCtx with the zero Replay, so
	// PostBaseline.Resolved() was false everywhere and CMDI returned post_baseline_unresolved on
	// every slot it probed. That is the runner withholding a measurement the class asked for, not
	// a property of the target.
	t.Run("the post-baseline is taken so a class that needs one can conclude", func(t *testing.T) {
		for _, r := range verdicts {
			v := r.Verdict
			if !strings.Contains(v.Reason, "post_baseline_unresolved") {
				continue
			}
			if n := sentPair[v.Class.String()+"|"+r.VectorID+"|"+string(v.SlotKey)]; n > 0 {
				t.Errorf("%s %s/%s sent %d probes and then could not be scored, because the runner never took the post-baseline it is required to take",
					name[r.VectorID], v.Class, v.SlotKey, n)
			}
		}
	})

	// DEFECT 2, THE OTHER HALF. A class offered as an ordinary toggle that then plans nothing on
	// every slot of every run is a false negative with a checkbox in front of it: the operator
	// enables it, sees no finding, and reads that as "no bug of this kind here".
	//
	// So every class the settings layer OFFERS must, on a run where it is enabled, either send at
	// least one probe somewhere, or be declared UNAVAILABLE by the runner with a reason the
	// operator can read. Availability is the runner's answer about its own capabilities, so it is
	// asserted against the runner's own declaration and never guessed from the class list.
	t.Run("every offered class either sends something or is declared unavailable", func(t *testing.T) {
		avail := TriageClassAvailabilityFor(settings)
		for _, info := range TriageClassVocabulary() {
			id := triage.ClassID(info.ID)
			// A class with NO entry is fully available with nothing missing. Reading the zero
			// value as "unavailable" would declare every healthy class broken.
			a, declared := avail[id]
			if declared && !a.Available {
				if strings.TrimSpace(a.Reason) == "" {
					t.Errorf("%s is declared unavailable with no reason, which is the same silence under another name", info.Name)
				}
				if sentClass[info.Name] > 0 {
					t.Errorf("%s is declared unavailable and still sent %d probes", info.Name, sentClass[info.Name])
				}
				continue
			}
			if sentClass[info.Name] > 0 {
				continue
			}
			// It sent nothing and the runner says it CAN run. That is only acceptable if the
			// runner has named the facility it could not give the class; otherwise this is the
			// enabled checkbox that quietly measures nothing.
			if len(a.Missing) == 0 || strings.TrimSpace(a.Reason) == "" {
				t.Errorf("%s is offered to the operator as an ordinary toggle, was enabled for this run, sent not one probe on any slot of any vector, and the runner names nothing that it failed to give it. An operator who enables it and sees nothing reads that as 'no bug of this class here'",
					info.Name)
			}
		}
	})

	// An unavailable class must still produce a row on every slot it would have been eligible
	// for, and that row must carry the unavailability reason. A class simply absent from the
	// report cannot be told from one that was never eligible, which is the same absence again.
	t.Run("an unavailable class still says so on every slot", func(t *testing.T) {
		unavailable := TriageUnavailableClasses(settings)
		if len(unavailable) == 0 {
			t.Skip("NOT MEASURED: this build declares no class unavailable, so the unavailable row was not exercised. That is a gap in coverage, not a pass.")
		}
		seen := map[triage.ClassID]bool{}
		for _, r := range verdicts {
			v := r.Verdict
			if _, off := unavailable[v.Class]; !off {
				continue
			}
			seen[v.Class] = true
			if v.State.CountsAsClean() {
				t.Errorf("%s is unavailable in this build and produced a CLEAN on %s", v.Class, v.SlotKey)
			}
			if !strings.Contains(v.Reason, triageClassUnavailableReason) {
				t.Errorf("%s is unavailable and its row on %s reads %q, which does not say so", v.Class, v.SlotKey, triageFirstLine(v.Reason))
			}
		}
		for id := range unavailable {
			if !seen[id] {
				t.Errorf("%s is unavailable in this build and produced no row at all, so the report cannot tell it from a class that was never eligible", id)
			}
		}
	})

	// The reserved placeholder must not appear in a run at all. It is the third defect's visible
	// consequence: 1705 not_planned rows on the real corpus, for a class with no switch.
	t.Run("the reserved placeholder produced no row", func(t *testing.T) {
		for _, r := range verdicts {
			if TriageClassIsReserved(r.Verdict.Class) {
				t.Errorf("%s is reserved, is deliberately absent from the settings vocabulary, and still produced a %s row on %s",
					r.Verdict.Class, r.Verdict.State, r.Verdict.SlotKey)
				break
			}
		}
	})
}

// DEFECT 3, AS A UNIT. A class the settings layer refuses to expose must not be force-enabled by
// its own absence from the settings document.
//
// triageEnabledClasses treated "no entry" as "enabled", which is right for a real class whose
// entry a stored document happens to be missing, and wrong for the reserved placeholder, whose
// key TriageClassIsReserved deliberately removes from the vocabulary so that it can never be
// written. Absent-because-unwritable then meant enabled. The pattern force-enables any future
// hidden class, so the assertion is over the reserved predicate and not over the one id.
func TestAClassTheSettingsLayerWillNotExposeIsNotEnabledByItsOwnAbsence(t *testing.T) {
	settings := TriageSettingsDefaults()
	for _, id := range triageEnabledClasses(settings) {
		if TriageClassIsReserved(id) {
			t.Errorf("%s is reserved, has no key in the vocabulary, can therefore never be written into the settings document, and is enabled by that very absence. There is no setting that can switch it off", id)
		}
	}
	// And again with a document that does not mention it at all, which is the shape every stored
	// document has.
	delete(settings.Classes, TriageClassKey(triage.ClassExample))
	for _, id := range triageEnabledClasses(settings) {
		if TriageClassIsReserved(id) {
			t.Errorf("%s is enabled by a stored document that cannot mention it", id)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// The one-recorder rule, and the coin flip it exists to stop
// ---------------------------------------------------------------------------------------------

// THE BUG THIS GUARDS, MEASURED ON THIS MACHINE.
//
// The reconciliation in triageStore.go decides whether a pair has lost evidence by comparing two
// numbers: triage_coverage.sent_probes, and how many triage_fidelity rows the pair holds. That is
// a check only while the two count the SAME POPULATION. They did not. There were FIVE places that
// appended a fidelity row, and between them they maintained rr.sent, TriageCoverageRow.SentProbes
// and rr.fidelity inconsistently, so an operator's custom payload added a record and no count.
// Measured against the canary oracle, one run, SQL and SSTI:
//
//	class slot       sent held extra
//	SQL   query:q      23   25     2
//	SQL   query:q      23   25     2
//	SQL   query:tpl    23   25     2
//	SSTI  query:q      24   24     0
//
// Every SQL pair could lose two genuine probe records with sent_probes - held still negative,
// clamped to zero by GREATEST, and nothing to show for it. The pairs with no custom payload were
// exact. A comparison between two counters that count different populations is not a check, it is
// a coin flip that usually lands on clean.
//
// A SIXTH GUARD WOULD NOT HAVE FIXED IT, which is why this is a source scan and not an assertion:
// two counters maintained by hand at different call sites will diverge again. The rule is that
// there is one recorder and the counters do not exist outside it.
//
// It is written in the style of TestOnlySlotsForReadsTheParametersColumn, which enforces the same
// shape of rule one layer up, and it scans the same two halves of the layer so a guard cannot stay
// green by the code moving to the other package.
func TestEveryProbeRecordGoesThroughOneRecorder(t *testing.T) {
	const recorder = "recordProbeAttempt"

	dir := packageDir(t)
	var files []string
	for _, pat := range []string{
		filepath.Join(dir, "triage*.go"),
		filepath.Join(dir, "triage", "*.go"),
		filepath.Join(dir, "..", "triageclasses", "*.go"),
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatalf("glob %s: %v", pat, err)
		}
		if len(m) == 0 {
			t.Fatalf("%s matched no files, so this guard is covering less of the layer than it claims", pat)
		}
		for _, f := range m {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			files = append(files, f)
		}
	}
	if len(files) < 2 {
		t.Fatalf("found %d non-test files in the triage layer, so this test is checking nothing", len(files))
	}

	// The three mutations that describe ONE population: the record, the pair's count of records,
	// and the run's count of records. Whoever does one must do all three, in one place.
	const (
		mutAppend  = "appends a probe record to the fidelity buffer"
		mutPair    = "moves the pair's SentProbes counter"
		mutPlanned = "moves the pair's PlannedProbes counter"
		mutRun     = "moves the run's sent counter"
	)
	counterFields := map[string]string{
		"SentProbes":    mutPair,
		"PlannedProbes": mutPlanned,
		"sent":          mutRun,
	}

	// what maps a function name to the mutations its body performs.
	what := map[string]map[string]bool{}
	where := map[string]string{}
	for _, f := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f, nil, 0) // mode 0 drops comments, so the prose that
		if err != nil {                                  // DESCRIBES this rule is not scanned for it
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			add := func(m string) {
				if what[fn.Name.Name] == nil {
					what[fn.Name.Name] = map[string]bool{}
				}
				what[fn.Name.Name][m] = true
				where[fn.Name.Name] = filepath.Base(f)
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch s := n.(type) {
				case *ast.IncDecStmt:
					if sel, ok := s.X.(*ast.SelectorExpr); ok {
						if m, ok := counterFields[sel.Sel.Name]; ok {
							add(m)
						}
					}
				case *ast.AssignStmt:
					for i, lhs := range s.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						// A counter moved by "x.N += 1" or by "x.N = x.N + 1". A plain
						// "x.N = 0" is a reset and is not a second bookkeeper.
						if m, ok := counterFields[sel.Sel.Name]; ok {
							if s.Tok == token.ADD_ASSIGN || (i < len(s.Rhs) && mentionsField(s.Rhs[i], sel.Sel.Name)) {
								add(m)
							}
						}
						if sel.Sel.Name != "fidelity" {
							continue
						}
						for _, rhs := range s.Rhs {
							call, ok := rhs.(*ast.CallExpr)
							if !ok {
								continue
							}
							if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "append" {
								add(mutAppend)
							}
						}
					}
				}
				return true
			})
		}
	}

	if len(what[recorder]) == 0 {
		t.Fatalf("no function named %s appends a probe record, so the one recorder does not exist and every call site is free to keep its own counts again", recorder)
	}
	for _, m := range []string{mutAppend, mutPair, mutPlanned, mutRun} {
		if !what[recorder][m] {
			t.Errorf("%s does not %s. The point of one recorder is that the record and every count of it move TOGETHER; a recorder that moves only some of them is the same divergence with fewer call sites", recorder, m)
		}
	}

	var offenders []string
	for fn, ms := range what {
		if fn == recorder {
			continue
		}
		for m := range ms {
			offenders = append(offenders, fmt.Sprintf("%s (%s) %s", fn, where[fn], m))
		}
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf(`these functions record a probe attempt outside %s: %v.

%s is the only place allowed to, because sent_probes and the number of probe records held are compared against each other to decide whether a pair has lost evidence, and a second call site that moves one without the other makes that comparison absorb real losses. Measured before this rule existed: every pair an operator payload reached held sent_probes + 2 records, so two destroyed records on that pair read as clean.`,
			recorder, offenders, recorder)
	}
}

// mentionsField reports whether an expression reads a field of this name, which is how
// "x.N = x.N + 1" is told apart from "x.N = 0".
func mentionsField(e ast.Expr, name string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// ---------------------------------------------------------------------------------------------
// F2: the rows the store refused, and the caller that dropped them anyway
// ---------------------------------------------------------------------------------------------

// RecordTriageFidelity refuses a WHOLE BATCH, before it opens its transaction, when any row
// carries http_status 0 or is marked delivered while also carrying a transport error. Its comment
// says "the caller still holds the rows". The caller did not:
//
//	if _, err := RecordTriageFidelity(ctx, rr.runUUID, rr.fidelity); err != nil {
//	    log.Printf(...)
//	}
//	rr.fidelity = nil      // UNCONDITIONAL
//
// Measured before the fix: stored 0 of 3, all three destroyed, one log line. The run ended UNKNOWN
// only because triage_coverage.sent_probes still said three had gone out, and sent_probes is
// exactly the witness the uncounted-extra-row bug defeats. Two defeated witnesses is a clean on a
// unit nobody tested.
//
// So: nothing the store refuses is discarded. A row that cannot be stored as measured is stored as
// a record OF the refusal, which is unproven by construction and cannot render clean.
func TestFlushKeepsTheProbeRecordsTheStoreRefused(t *testing.T) {
	ctx := triageTestDB(t)
	runUUID := triageTestRun(t, ctx)

	// SQL is class 4, so every ordinal here is 4 modulo the stripe modulus, which the schema
	// CHECKs. The middle row is the caller bug: http_status 0, which the store refuses for the
	// whole batch before it writes anything.
	mk := func(ordinal uint64, status int) TriageFidelityRow {
		r := NewTriageFidelityRow(triage.ClassSQL, ordinal)
		r.ProbeID = "SQL-B1"
		r.VectorID = "v-f2"
		r.SlotKey = "query:sort"
		r.ObsKind = triage.ObsProbe
		r.HTTPStatus = status
		r.Delivered = status > 0
		r.Wire = triage.PayloadWire{
			Logical:  []byte("1 OR 1=1"),
			Wire:     []byte("1%20OR%201=1"),
			Survived: triage.WireSurvivalEncoded,
		}
		return r
	}
	rows := []TriageFidelityRow{mk(4, 200), mk(68, 0), mk(132, 200)}

	rr := &triageRunner{runUUID: runUUID, fidelity: rows}
	rr.flush(ctx)

	var held int
	if err := dbPool.QueryRow(ctx,
		`SELECT count(*) FROM triage_fidelity WHERE run_id = $1`, runUUID).Scan(&held); err != nil {
		t.Fatalf("count probe records: %v", err)
	}
	if held != len(rows) {
		t.Errorf("the run holds %d of %d probe records after the flush. A row the store refuses must be RETAINED or RECORDED AS REFUSED, never dropped: a probe record is the only evidence that a probe was ever sent, and this whole layer exists because a destroyed record then reads as proof the probe was fine",
			held, len(rows))
	}
	if len(rr.fidelity) != 0 {
		t.Errorf("the buffer still holds %d rows after a flush that accounted for them, which would write them a second time and a duplicate is an error here", len(rr.fidelity))
	}

	// The refused row is there and says so. survived is outside ('intact','encoded'), which is
	// what makes every reader count it as unproven.
	var survived, msg string
	if err := dbPool.QueryRow(ctx,
		`SELECT survived, transport_msg FROM triage_fidelity WHERE run_id = $1 AND ordinal = 68`,
		runUUID).Scan(&survived, &msg); err != nil {
		t.Fatalf("the refused probe record (ordinal 68) is not in the table at all: %v", err)
	}
	if survived == string(triage.WireSurvivalIntact) || survived == string(triage.WireSurvivalEncoded) {
		t.Errorf("the refused probe record reads survived=%q, which every reader counts as PROVEN. A record the store would not take must never read as a probe that reached the wire", survived)
	}
	if !strings.Contains(msg, "http_status") {
		t.Errorf("the refused probe record does not say why it could not be stored (transport_msg = %q), and a refusal with no reason is an absence with extra steps", msg)
	}

	t.Logf("held=%d of %d, ordinal 68 survived=%q msg=%s", held, len(rows), survived, triageFirstLine(msg))
}

// ---------------------------------------------------------------------------------------------
// S2b end to end: the uncounted record, and the real one it absorbs
// ---------------------------------------------------------------------------------------------

// THE REVIEWER'S SCENARIO, DRIVEN BY THE RUNNER RATHER THAN BY HAND, because the claim is about
// what the runner produces and hand-written numbers would pass whatever the runner does.
//
// One run against the canary oracle with two of the operator's own payloads attached to SQL. Then:
//
//  1. Every pair must hold exactly as many probe records as its coverage row says it sent.
//     Measured before the fix: SQL pairs said sent=23 and held 25, SSTI pairs said 24 and held 24.
//     The two extra are the custom payloads, which incremented the run counter and never the
//     pair's.
//  2. A pair that a delivered probe reached must record ran = true. The schema's
//     CHECK (ran = FALSE OR sent_probes > 0) is satisfied by ran=false, so it says nothing about
//     a pair that only an operator payload reached, and that pair used to record ran=false with
//     its probes on the wire.
//  3. Destroy ONE genuine probe record and the pair's own shortfall witness must see it. That
//     witness is sent_probes minus records held, the one the reconciliation clamps at zero.
//     Before the fix it read 23 - 24 = -1 on a SQL pair, clamped to zero, and the loss was gone.
//
// WHY (3) IS ASSERTED ON THAT WITNESS AND NOT ONLY ON THE RUN ROLL-UP. There are two witnesses and
// the roll-up believes the larger. The other one is the set of ordinals the verdicts cite, and on
// THIS oracle the SQL classifier happens to cite every ordinal it sent, so it catches the deletion
// on its own and the roll-up stays honest by luck. A check that works only while a classifier is
// generous with its citations is not a check: the store's own comment says the second witness
// exists for rows lost from a pair whose verdict never landed, and for those there is no luck.
func TestALostProbeRecordIsNotAbsorbedByAnUncountedOne(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, _ := triageOracleTarget(t, ctx, base)

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = key == TriageClassKey(triage.ClassSSTI) || key == TriageClassKey(triage.ClassSQL) || key == TriageClassKey(triage.ClassCSTI)
		cs.Tier = string(triage.TierFull)
		if key == TriageClassKey(triage.ClassCSTI) {
			cs.Tier = string(triage.TierReduced)
		}
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	settings.Pacing.RequestsPerSecond = 20
	settings.Pacing.RespectTargetBudget = false
	settings.CustomPayloads = []TriageCustomPayload{
		{
			ID: "csti-only", Class: TriageClassKey(triage.ClassCSTI), Label: "the only thing this class sends",
			Payload: "ars0ncsti" + triage.MarkerPlaceholder, Encoding: "utf8",
			Points: []string{"query"}, Enabled: true,
			Detection: TriageDetection{Mode: TriageDetectReflect},
		},
		{
			ID: "quiet", Class: TriageClassKey(triage.ClassSQL), Label: "never matches",
			Payload: "ars0nquiet" + triage.MarkerPlaceholder, Encoding: "utf8",
			Points: []string{"query"}, Enabled: true,
			Detection: TriageDetection{Mode: TriageDetectBodyContains,
				Pattern: "ars0n-triage-string-no-page-can-contain"},
		},
		{
			ID: "echo", Class: TriageClassKey(triage.ClassSQL), Label: "marker comes back",
			Payload: "ars0necho" + triage.MarkerPlaceholder, Encoding: "utf8",
			Points: []string{"query"}, Enabled: true,
			Detection: TriageDetection{Mode: TriageDetectReflect},
		},
	}
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 10*time.Minute); status != "completed" {
		t.Fatalf("the run finished %q", status)
	}

	type triagePair struct {
		vectorID  string
		slot      string
		classID   int
		className string
		planned   int
		sent      int
		held      int
		delivered int
		ran       bool
	}
	rows, err := dbPool.Query(ctx, `
		SELECT c.vector_id, c.slot_key, c.class_id, c.class_name, c.planned_probes, c.sent_probes, c.ran,
		       (SELECT count(*) FROM triage_fidelity f
		         WHERE f.run_id = c.run_id AND f.vector_id = c.vector_id
		           AND f.slot_key = c.slot_key AND f.class_id = c.class_id),
		       (SELECT count(*) FROM triage_fidelity f
		         WHERE f.run_id = c.run_id AND f.vector_id = c.vector_id
		           AND f.slot_key = c.slot_key AND f.class_id = c.class_id AND f.delivered)
		FROM triage_coverage c WHERE c.run_id = $1
		ORDER BY c.class_name, c.slot_key, c.vector_id`, runUUID)
	if err != nil {
		t.Fatalf("read pairs: %v", err)
	}
	var pairs []triagePair
	for rows.Next() {
		var p triagePair
		if err := rows.Scan(&p.vectorID, &p.slot, &p.classID, &p.className, &p.planned, &p.sent, &p.ran, &p.held, &p.delivered); err != nil {
			rows.Close()
			t.Fatalf("scan pair: %v", err)
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	if len(pairs) == 0 {
		t.Fatal("the run recorded no coverage pair at all, so there is nothing to reconcile and the silent zero is the whole result")
	}

	for _, p := range pairs {
		t.Logf("%-5s %-10s %s planned=%d sent=%d held=%d delivered=%d ran=%v",
			p.className, p.slot, p.vectorID[:8], p.planned, p.sent, p.held, p.delivered, p.ran)
	}
	for _, p := range pairs {
		if p.sent != p.held {
			t.Errorf("%s on %s holds %d probe records and its coverage row says it sent %d. sent_probes and the number of records held are the two witnesses the reconciliation compares, and a pair where they describe different populations absorbs %d destroyed records without a word",
				p.className, p.slot, p.held, p.sent, p.held-p.sent)
		}
		// planned_probes IS THE UNREPAIRED READOUT OF WHAT THE RUNNER ITSELF COUNTED.
		// triageRaiseSentProbesFloor lifts sent_probes to the number of records a pair holds on the
		// way into the database, so sent_probes above can agree with held while the runner's own
		// bookkeeping is still short; planned_probes is written by the same hand and is not lifted.
		// Measured before the one recorder existed: SQL pairs wrote planned=23 and sent=23 while
		// holding 25 records, the two extra being the operator's own payloads.
		if p.planned != p.held {
			t.Errorf("%s on %s holds %d probe records and its coverage row says it planned %d. That is the runner's own count of what it recorded, unrepaired by anything downstream, and it is short by %d",
				p.className, p.slot, p.held, p.planned, p.held-p.planned)
		}
		if p.delivered > 0 && !p.ran {
			t.Errorf("%s on %s delivered %d probes and records ran = false. The schema CHECK (ran = FALSE OR sent_probes > 0) is satisfied by that shape, so nothing catches it, and a pair reached only by an operator's own payload looks exactly like a pair nothing was ever sent to",
				p.className, p.slot, p.delivered)
		}
	}

	// THE CUSTOM-PAYLOAD-ONLY PAIR, NAMED SO IT CANNOT QUIETLY STOP EXISTING. CSTI is enabled at
	// the reduced tier and declares only full-tier probes, so it plans and sends none of its own
	// here; the single probe that reaches that pair is the operator's payload. Before the one
	// recorder, sendCustomPayloads touched no coverage row at all, so this pair recorded
	// sent_probes = 0, planned_probes = 0 and ran = false with its probe on the wire and its
	// response judged, and the schema's CHECK (ran = FALSE OR sent_probes > 0) is satisfied by
	// exactly that shape, so nothing anywhere said a word.
	var customOnly bool
	for _, p := range pairs {
		if p.className != triage.ClassCSTI.String() || p.held == 0 {
			continue
		}
		customOnly = true
		if p.sent == 0 || !p.ran {
			t.Errorf("the pair only the operator's own payload reached (%s on %s) holds %d probe records, %d of them delivered, and records sent_probes = %d ran = %v",
				p.className, p.slot, p.held, p.delivered, p.sent, p.ran)
		}
	}
	if !customOnly {
		t.Error("no pair was reached only by an operator's custom payload, so the half of this test that covers that shape measured nothing. CSTI at the reduced tier declares no probes it may send, and its custom payload is what should have reached it")
	}

	// Destroy one genuine probe record on the fattest pair and ask that pair's own shortfall
	// witness whether it can see the loss.
	victim := pairs[0]
	for _, p := range pairs {
		if p.held-p.sent > victim.held-victim.sent || (p.held-p.sent == victim.held-victim.sent && p.held > victim.held) {
			victim = p
		}
	}
	if victim.held < 2 {
		t.Fatalf("the fattest pair holds %d probe records, which is too few to destroy one and still have a run to reconcile", victim.held)
	}
	var lostOrdinal int64
	if err := dbPool.QueryRow(ctx, `
		SELECT ordinal FROM triage_fidelity
		WHERE run_id = $1 AND vector_id = $2 AND slot_key = $3 AND class_id = $4
		ORDER BY ordinal DESC LIMIT 1`,
		runUUID, victim.vectorID, victim.slot, victim.classID).Scan(&lostOrdinal); err != nil {
		t.Fatalf("pick a probe record to destroy: %v", err)
	}
	if _, err := dbPool.Exec(ctx,
		`DELETE FROM triage_fidelity WHERE run_id = $1 AND ordinal = $2`, runUUID, lostOrdinal); err != nil {
		t.Fatalf("destroy probe record %d: %v", lostOrdinal, err)
	}

	var sentNow, heldNow int
	if err := dbPool.QueryRow(ctx, `
		SELECT c.sent_probes,
		       (SELECT count(*) FROM triage_fidelity f
		         WHERE f.run_id = c.run_id AND f.vector_id = c.vector_id
		           AND f.slot_key = c.slot_key AND f.class_id = c.class_id)
		FROM triage_coverage c
		WHERE c.run_id = $1 AND c.vector_id = $2 AND c.slot_key = $3 AND c.class_id = $4`,
		runUUID, victim.vectorID, victim.slot, victim.classID).Scan(&sentNow, &heldNow); err != nil {
		t.Fatalf("re-read the victim pair: %v", err)
	}
	t.Logf("victim %s %s: destroyed ordinal %d, sent=%d held=%d, shortfall witness = %d",
		victim.className, victim.slot, lostOrdinal, sentNow, heldNow, sentNow-heldNow)
	if sentNow-heldNow < 1 {
		t.Errorf("a genuine probe record was destroyed on %s / %s and the pair's own shortfall witness reads %d. sent_probes minus held is the witness that catches a record lost from a pair whose verdict never landed, and it is the only one that does. It reads zero or less here because the pair held records nothing counted, so the subtraction started negative and GREATEST clamped the loss away",
			victim.className, victim.slot, sentNow-heldNow)
	}

	cov, err := LoadTriageRunCoverage(ctx, runUUID)
	if err != nil {
		t.Fatalf("read coverage: %v", err)
	}
	t.Logf("after the deletion: %+v", cov)
	if cov.MissingFidelityRows < 1 {
		t.Errorf("the run roll-up reports %d missing probe records after one was destroyed: %+v", cov.MissingFidelityRows, cov)
	}
	if cov.RendersAsClean() {
		t.Fatal("HOLE: the run renders as CLEAN with a destroyed probe record in it")
	}
}

// ---------------------------------------------------------------------------------------------
// The counters, in process, where nothing downstream can repair them
// ---------------------------------------------------------------------------------------------

// A REFUSED PROBE IS STILL A PROBE ATTEMPT, AND IT MUST BE COUNTED WHERE IT IS RECORDED.
//
// This is the defect at its smallest and it needs no database and no network, which is the point:
// triageStore.go now lifts sent_probes to the number of records a pair holds whenever the records
// prove a larger number, so the symptom is repaired on the way into the database and cannot be
// seen from the far side of it. A repair downstream is a good floor and it is not the same thing
// as the counters agreeing, so this asks the runner directly.
//
// The probe here names a query parameter the request does not have, so EncodeSlotInto refuses it
// before anything reaches a socket. That path writes a fidelity row, because a payload that never
// went out with no record of it is the silent zero this layer exists to stop. Before the one
// recorder existed it wrote the row and moved NEITHER counter, so the pair held one more record
// than it admitted sending, which is one destroyed record it could absorb without a word.
func TestARefusedProbeIsCountedOnThePairThatRecordedIt(t *testing.T) {
	minter, err := NewMarkerMinter("rn01")
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	c, ok := triage.ClassifierFor(triage.ClassSQL)
	if !ok {
		t.Fatal("the SQL classifier is not registered, so this test cannot drive the runner at all")
	}
	const probe = triage.ProbeID("SQL-B1")
	if _, ok := triageSpecFor(c, probe); !ok {
		t.Fatalf("%s no longer declares %s, so this test is driving a path that does not exist", c.ID(), probe)
	}

	settings := TriageSettingsDefaults()
	cs := settings.Classes[TriageClassKey(triage.ClassSQL)]
	cs.Enabled, cs.Tier, cs.MaxRisk = true, string(triage.TierOptIn), string(triage.RiskR3)
	settings.Classes[TriageClassKey(triage.ClassSQL)] = cs
	settings.Tier = string(triage.TierOptIn)

	rr := &triageRunner{
		runUUID:   "unit-test",
		settings:  settings,
		minter:    minter,
		coverage:  map[string]*TriageCoverageRow{},
		covDirty:  map[string]bool{},
		perturbed: map[string][]triage.Perturbed{},
	}
	u := &triageUnitPlan{
		VectorID: "v-counters",
		Template: RequestTemplate{Method: "GET", URL: "http://127.0.0.1:1/x?present=1"},
	}
	// absent is not in the query string, so the encoder refuses to deliver into it.
	slot := triage.Slot{VectorID: u.VectorID, Kind: triage.KindQuery, Key: "query:absent",
		Name: "absent", Value: "1", SegmentIndex: -1, ServerReachable: true}

	if sent := rr.sendProbe(context.Background(), u, slot, c, triage.ProbeRequest{Spec: probe}, TriageBaseline{}); sent {
		t.Fatalf("the runner reported a request went out for a parameter the request does not carry, so this test is no longer exercising the refused path")
	}

	if len(rr.fidelity) != 1 {
		t.Fatalf("the refused probe left %d probe records. A payload that never went out, with no record that it never went out, is the silent zero: the class sees no response and the absence reads as clean", len(rr.fidelity))
	}
	row := rr.cov(u.VectorID, slot.Key, triage.ClassSQL)
	if row.SentProbes != len(rr.fidelity) {
		t.Errorf(`the pair holds %d probe records and its SentProbes counter says %d.

These two are compared against each other, in SQL, to decide whether a pair has lost evidence: gap = GREATEST(cited_gone, sent_probes - records held, 0). A pair holding more records than it counted starts that subtraction negative, GREATEST clamps it to zero, and %d genuinely destroyed records then read as clean. Both must move in the one recorder, together, or they are two hand-maintained numbers over the same population and they will diverge again.`,
			len(rr.fidelity), row.SentProbes, len(rr.fidelity)-row.SentProbes)
	}
	if row.PlannedProbes != len(rr.fidelity) {
		t.Errorf("the pair holds %d probe records and its PlannedProbes counter says %d: a probe that was attempted was planned", len(rr.fidelity), row.PlannedProbes)
	}
	if rr.sent != len(rr.fidelity) {
		t.Errorf("the run counter says %d probes and the run holds %d probe records; probes_sent on the card is then a different number from the evidence behind it", rr.sent, len(rr.fidelity))
	}
	if row.Ran {
		t.Error("the pair records ran = true having delivered nothing: Ran is the measurement fact, and a refused encode measured nothing")
	}

	// THE OTHER DIRECTION, so this is not satisfied by a runner that counts everything twice, is
	// asserted end to end in TestALostProbeRecordIsNotAbsorbedByAnUncountedOne: there every pair
	// holds exactly as many probe records as it counted, on real delivered probes, and a pair that
	// delivered anything records ran = true.

	t.Logf("records=%d SentProbes=%d PlannedProbes=%d run.sent=%d ran=%v",
		len(rr.fidelity), row.SentProbes, row.PlannedProbes, rr.sent, row.Ran)
}

// =================================================================================================
// RFI IS DEGRADED AND NOT UNAVAILABLE
//
// MEASURED, run ef8c13ab, 2026-09-18: RFI was not_run on all 32 routes of the full oracle matrix,
// every row reading "class_unavailable: remote file inclusion has NO in-band oracle". That
// sentence was true when it was written and is not true now. The class was rebuilt with a real
// in-band tier: three requests (RFI-H0, RFI-H1, RFI-H2) at a host under .invalid, which RFC 6761
// section 6.4 guarantees never resolves, so the tier needs NO collaborator, sends no packet to
// any third party, and reads the error a fetching stack prints when it is handed a name that
// cannot be resolved.
//
// TriageClassAvailabilityFor still answered Available: false, pairIsLive refuses an unavailable
// class, and so the tier that needs nothing was never planned. A class that cannot send a probe
// and a class whose runner refuses to let it are the same silence to the operator, and this table
// is the one place that is supposed to tell them apart.
//
// WHAT MUST NOT FOLLOW FROM THE FIX. Available does NOT mean whole. The out-of-band half is still
// missing and it is the half that owns this class's finding and its only clean, so the entry must
// keep naming both facilities and every row the class writes must keep carrying oob_half_missing.
// An in-band-only RFI result that read as a complete RFI test would be the false negative this
// layer exists to stop, wearing a green tick.
func TestRFIIsDegradedRatherThanUnavailableSoItsInBandTierRuns(t *testing.T) {
	settings := TriageSettingsDefaults()

	for _, tc := range []struct {
		name string
		oob  TriageOOB
	}{
		{"no collaborator at all", TriageOOB{Mode: string(triage.OOBNone), GraceSeconds: 60}},
		{"a collaborator that cannot serve content", TriageOOB{
			Mode: string(triage.OOBHTTPPath), Base: "oob.example.invalid", GraceSeconds: 60, ServesContent: false}},
		{"a collaborator configured to serve, on a build that ingests no callback", TriageOOB{
			Mode: string(triage.OOBHTTPPath), Base: "oob.example.invalid", GraceSeconds: 60, ServesContent: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings.OOB = tc.oob
			avail := TriageClassAvailabilityFor(settings)
			entry, declared := avail[triage.ClassRFI]
			if !declared {
				t.Fatal("RFI has no entry at all, so the run record names nothing missing and an " +
					"in-band-only result reads as a complete remote-file-inclusion test")
			}
			if !entry.Available {
				t.Errorf("RFI is still declared unavailable, so pairIsLive refuses every pair and "+
					"the in-band tier, which needs no collaborator and no infrastructure of any "+
					"kind, is never planned. Reason on the row: %s", entry.Reason)
			}
			missing := map[string]bool{}
			for _, m := range entry.Missing {
				missing[m] = true
			}
			for _, want := range []string{triageCapOOBCollaborator, triageCapOOBContent} {
				if !missing[want] {
					t.Errorf("RFI does not name %s as missing. Both halves of its real oracle are "+
						"still absent and the run record is where the report learns that a silence "+
						"from this class does not cover the inclusion question", want)
				}
			}
			if strings.TrimSpace(entry.Reason) == "" {
				t.Error("a degraded class with no reason is the same silence under another name")
			}
			if strings.Contains(entry.Reason, triageClassUnavailableReason) {
				t.Errorf("the reason still begins with %q, which is the phrase the report and the "+
					"settings screen grep for to mark a class as not runnable",
					triageClassUnavailableReason)
			}
			if !strings.Contains(entry.Reason, "oob_half_missing") {
				t.Error("the reason does not name oob_half_missing, which is the annotation every " +
					"row this class writes has to carry for an aggregate to know the in-band tier " +
					"cannot answer the inclusion question")
			}
		})
	}

	// And the two subsets the rest of the runner reads must agree with it.
	settings.OOB = TriageOOB{Mode: string(triage.OOBNone), GraceSeconds: 60}
	if reason, unavailable := TriageUnavailableClasses(settings)[triage.ClassRFI]; unavailable {
		t.Errorf("TriageUnavailableClasses still lists RFI, and that map is what pairIsLive and the "+
			"settings screen both consult: %s", reason)
	}
	degraded := triageDegradedClasses(settings)
	if len(degraded[triage.ClassRFI.String()]) == 0 {
		t.Error("RFI is absent from the degraded map, so the run record claims a run in which " +
			"nothing was missing from this class")
	}
}

// THE ROWS THE RUNNER WRITES ON A CLASS'S BEHALF ARE ROWS TOO.
//
// baseline_unstable, not_reached, deselected_vector and budget_exhausted are synthesised by the
// runner before the class is called, so the class cannot annotate them. Measured on run
// 8c9d745c: RFI carried oob_half_missing on 33 of 35 answered rows and the two without it were
// the runner's own baseline_unstable rows. "Every row names the missing half" is only a rule if
// it holds for every row.
func TestTheRunnerStampsItsOwnShortfallOnRowsTheClassNeverSaw(t *testing.T) {
	settings := TriageSettingsDefaults()
	settings.OOB = TriageOOB{Mode: string(triage.OOBNone), GraceSeconds: 60}
	rr := &triageRunner{settings: settings}
	rr.plan.Degraded = triageDegradedByClass(settings)

	rr.addVerdict(triageUnknownVerdict(triage.ClassRFI, "query:q", triage.StateCannotDetermine,
		"baseline_unstable (masked_fraction 0.53 above 0.35): no payload of this class was sent here"), "v1")
	if len(rr.verdicts) != 1 {
		t.Fatalf("expected one buffered verdict, got %d", len(rr.verdicts))
	}
	ann := rr.verdicts[0].Verdict.Annotations
	if ann["oob_half_missing"] != true {
		t.Errorf("a runner-synthesised RFI row does not carry oob_half_missing, so an aggregate "+
			"counting RFI rows cannot tell that this class's finding was out of reach for the whole "+
			"run. Annotations: %v", ann)
	}
	if ann["missing_half"] != "no_collaborator" {
		t.Errorf("the row does not name WHICH half is missing, and no_collaborator, "+
			"no_content_collaborator and no_callback_ingest are three different things to go and "+
			"build. Got %v", ann["missing_half"])
	}
	if ann["runner_degraded"] == nil {
		t.Error("the row does not name the runner facilities that were missing")
	}

	// A class that annotated the row itself knows more than the runner does, and the stamp must
	// not overwrite it.
	own := triage.ClassVerdict{Class: triage.ClassRFI, SlotKey: "query:q", State: triage.StateSuspicious,
		Reason: "remote_fetch_attempted", Annotations: map[string]any{"missing_half": "no_content_collaborator"}}
	rr.addVerdict(own, "v1")
	if got := rr.verdicts[1].Verdict.Annotations["missing_half"]; got != "no_content_collaborator" {
		t.Errorf("the runner overwrote the class's own annotation with %v", got)
	}

	// A class with nothing missing must be left entirely alone: an empty annotation map on a
	// healthy class is noise in every row of the report.
	rr.addVerdict(triageUnknownVerdict(triage.ClassSQL, "query:id", triage.StateCannotDetermine,
		"baseline_unstable"), "v1")
	if a := rr.verdicts[2].Verdict.Annotations; len(a) != 0 {
		t.Errorf("a class the runner has nothing missing for was annotated anyway: %v", a)
	}
}

// THE PLACEHOLDER MUST NOT SURVIVE THE MEASUREMENT, END TO END AGAINST THE ORACLE.
//
// The store-level rule is pinned in triageStore_test.go. This is the other half: that the runner
// actually files its placeholders under the reserved arm, so the rule has something to fire on.
// Before the fix the last full exam recorded 328 measured pairs still carrying a not_reached row,
// the roll-up counted every one of them as unknown, and the Clean filter on the operator surface
// was a dead control.
func TestAMeasuredPairKeepsNoNotReachedRowAfterALiveRun(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, _ := triageOracleTarget(t, ctx, base)

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = key == TriageClassKey(triage.ClassSSTI)
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Pacing.RequestsPerSecond = 20
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 10*time.Minute); status != "completed" {
		t.Fatalf("the run finished %q", status)
	}

	ran := map[string]bool{}
	for _, c := range triageRunCoverageRows(t, ctx, runUUID) {
		if c.Ran {
			ran[c.VectorID+"|"+c.SlotKey+"|"+c.Class] = true
		}
	}
	if len(ran) == 0 {
		t.Skip("NOT MEASURED: the run measured no pair at all, so nothing here could have superseded a placeholder. This is a gap in coverage, not a pass.")
	}

	rows, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	armsByPair := map[string][]string{}
	for _, r := range rows {
		key := r.VectorID + "|" + string(r.Verdict.SlotKey) + "|" + r.Verdict.Class.String()
		armsByPair[key] = append(armsByPair[key], r.Arm)
		if r.Arm == TriagePlanArm && ran[key] {
			t.Errorf("pair %s was measured and still carries the plan placeholder (%s). The roll-up counts it as unknown and the operator is told the run never got to a pair it probed",
				key, r.Verdict.State)
		}
		if strings.HasPrefix(r.Verdict.Reason, "not_reached") && ran[key] {
			t.Errorf("pair %s was measured and a row on it still says %q", key, r.Verdict.Reason)
		}
	}
	for key, arms := range armsByPair {
		if len(arms) < 2 {
			continue
		}
		for _, a := range arms {
			if a == TriagePlanArm {
				t.Errorf("pair %s holds the plan placeholder beside %d real arms (%v), and the two may never both stand",
					key, len(arms)-1, arms)
				break
			}
		}
	}
}
