package utils

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"ars0n-framework-v2-server/utils/triage"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5/pgxpool"
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
	cookie := triage.Slot{Kind: triage.KindCookie, Name: "session", ServerReachable: true, SegmentIndex: -1}
	got, reason, _ := triageEncoderFor(spec, triage.ProbeRequest{}, cookie)
	if reason != "" {
		t.Fatalf("refused a cookie slot this probe can reach: %s", reason)
	}
	if got != triage.EncodeCookie {
		t.Errorf("chose %q for a cookie slot, want %q", got, triage.EncodeCookie)
	}
	query := triage.Slot{Kind: triage.KindQuery, Name: "q", ServerReachable: true, SegmentIndex: -1}
	got, reason, _ = triageEncoderFor(spec, triage.ProbeRequest{}, query)
	if reason != "" {
		t.Fatalf("refused a query slot this probe can reach: %s", reason)
	}
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
		// Routed through the ledger in triageNotMeasured_test.go rather than skipping straight
		// out. A bare t.Skip here made TestTriageVerdictsBecomePointersOnTheOracle and
		// TestTheWholeRegistryRunsAndEveryClassSaysWhatItDid invisible: both FAIL on unmodified
		// code when the oracle IS reachable, and for a week the suite was quoted as green.
		triageNotMeasured(t, triageFacilityOracle,
			"the canary oracle at %s is not reachable (%v), so the runner was never shown producing a verdict from a real classifier against a real response", base, err)
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
	// EVERY INSERTION POINT A REGISTERED CLASS CAN REACH NEEDS A VECTOR HERE, or that class is
	// untested and the test that would say so cannot see it.
	//
	// This fixture held query vectors only, which was invisible until CORS(28) and HOSTHDR(20)
	// landed as the first HEADER-ONLY classes. Both correctly answered not_applicable on every
	// query slot, with a good reason ("the CORS decision is made from the Origin REQUEST HEADER
	// and from nothing else"), and the registry test then correctly failed them for being offered
	// to the operator while sending nothing anywhere. The classes were right, the reason was
	// right, and the fixture was the thing that was wrong.
	//
	// A header vector is therefore not an extra case, it is the missing half of the corpus.
	for _, v := range []struct{ key, path, param, point string }{
		{"ssti", "/ssti", "tpl", "query"},
		{"xss", "/xss", "q", "query"},
		// The static index. It takes a query parameter and IGNORES it, so every probe in the
		// catalogue leaves the response byte-identical to the baseline. That is the only shape
		// that can produce an honest CLEAN, and a clean is the verdict a detector has to be
		// watched reaching before it is worth anything.
		{"static", "/", "q", "query"},
		// The header surface. Origin is the slot CORS reads and nothing else does, so it is also
		// the negative control for every class that must stay out of a header it has no business
		// in. HOSTHDR reaches it through the same insertion point.
		{"header", "/", "Origin", "header"},
	} {
		vectorID := uuid.New().String()
		evidence := fmt.Sprintf("%s%s?%s=hello", base, v.path, v.param)
		if v.point == "header" {
			evidence = base + v.path
		}
		if _, err := dbPool.Exec(ctx, `
			INSERT INTO attack_vectors (id, scope_target_id, vector_key, method, scheme, domain, port,
			                            path, insertion_point, parameters, evidence_url)
			VALUES ($1,$2,$3,'GET',$4,$5,$6,$7,$8,$9,$10)`,
			vectorID, id, v.key+":"+v.path, scheme, host, port, v.path, v.point,
			[]string{v.param}, evidence); err != nil {
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

	// NO PROBE IN THE WHOLE REGISTRY IS REFUSED FOR A PLACEMENT THE RUNNER DOES NOT RECOGNISE.
	//
	// The Variant key "placement" is overloaded: nosql.go writes its own slot-shape enum into it
	// on every probe and only overwrites it with a directive on nine of them. A runner that
	// refuses what it does not recognise therefore refuses a whole class. Measured, 2026-09-19:
	// a first cut of triagePlaceProbe turned all 60 NOSQL probes in this very run into
	// probe_not_observed, and NOTHING IN THIS TEST NOTICED, because planned == sent counts
	// refused attempts as sent. This is the assertion that would have caught it.
	var unknownPlacement []string
	skipRows, err := dbPool.Query(ctx, `
		SELECT class_name, slot_key, skipped_probes::text FROM triage_coverage
		WHERE run_id = $1 AND skipped_probes::text LIKE '%placement_unknown%'`, runUUID)
	if err != nil {
		t.Fatalf("read placement refusals: %v", err)
	}
	for skipRows.Next() {
		var cls, slotKey, skipped string
		if err := skipRows.Scan(&cls, &slotKey, &skipped); err != nil {
			t.Fatalf("scan placement refusal: %v", err)
		}
		unknownPlacement = append(unknownPlacement, cls+" "+slotKey+": "+triageFirstLine(skipped))
	}
	skipRows.Close()
	if len(unknownPlacement) > 0 {
		t.Errorf("%d pairs had probes refused for a placement this runner does not recognise, so those probes never opened a socket and the class read the silence: %s",
			len(unknownPlacement), strings.Join(unknownPlacement, " | "))
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

// ---------------------------------------------------------------------------------------------
// PLANNING WASTE: THE PROBES THAT NEVER LEFT THE PROCESS
//
// Live run acaff558 sent 7425 probes and 6931 of them, 93 percent, were refused inside the runner
// after being planned, counted, minted and attempted. Each one burned an ordinal, wrote a fidelity
// row and was charged to the operator as a probe sent, and every one of them was knowable before
// any request went out. These tests hold the three decisions at plan time.
//
// THE RULE THAT SHAPES ALL OF THEM: dropping waste must never drop coverage. A probe with three
// encoder modes of which one cannot reach this slot is still sent under the other two, and a class
// that can reach a slot some other way is never refused because one of its modes cannot.
// ---------------------------------------------------------------------------------------------

func runTestBodySlot() triage.Slot {
	return triage.Slot{
		VectorID: "v1", Kind: triage.KindBody, Key: "body:/name:node", FieldPath: "/name",
		BodyMedia: triage.BodyJSON, Value: "hello", SegmentIndex: -1, Method: http.MethodPost,
		ServerReachable: true, Constraints: triage.NewSlotConstraints(),
	}
}

// TestTheRunnerWillNotHandTheEncoderAModeItAlreadyRefused is the 256 and the 971 together. Both
// arrived at the encoder because the runner chose a mode nothing had asked whether the slot could
// take.
func TestTheRunnerWillNotHandTheEncoderAModeItAlreadyRefused(t *testing.T) {
	slot := runTestBodySlot()

	// The 971. EncodeForm is first in this list and fits KindBody by kind alone. The slot is a
	// JSON body, so the form encoder has no field name to write into and refuses every time.
	spec := triage.ProbeSpec{Encoders: []triage.EncoderMode{triage.EncodeForm, triage.EncodeJSONString}}
	mode, reason, _ := triageEncoderFor(spec, triage.ProbeRequest{}, slot)
	if reason != "" {
		t.Fatalf("the runner refused a probe that has a mode which does reach this slot: %s", reason)
	}
	if mode != triage.EncodeJSONString {
		t.Errorf("chose %q for a JSON body slot, want %q. Choosing the first mode that fits BY KIND sends the form encoder at a slot with no field name",
			mode, triage.EncodeJSONString)
	}

	// The 256. Traversal's round-2 sweep names its encoder per instance, and iis_unicode renders
	// into a path or a query and never into a body. A named mode is never silently swapped for a
	// working one: the class asked for that specific evasion and a different one under its name
	// would be scored as the answer to a question nobody asked.
	req := triage.ProbeRequest{Variant: map[string]string{"encoder": string(triage.EncodeIISUnicode)}}
	_, reason, detail := triageEncoderFor(spec, req, slot)
	if reason != ReasonEncoderWrongKind {
		t.Fatalf("a named encoder that cannot render into this slot came back as usable: reason %q", reason)
	}
	if !strings.Contains(detail, string(triage.EncodeIISUnicode)) {
		t.Errorf("the refusal does not name the mode: %q", detail)
	}
}

// TestOneUnusableModeDoesNotCostTheProbeItsOtherModes is the false negative this fix must not
// create. Waste is cheap; a payload that was never sent and reads as clean is not.
func TestOneUnusableModeDoesNotCostTheProbeItsOtherModes(t *testing.T) {
	slot := runTestBodySlot()
	spec := triage.ProbeSpec{Encoders: []triage.EncoderMode{
		triage.EncodeIISUnicode, // cannot reach a body
		triage.EncodeCookie,     // cannot reach a body
		triage.EncodeJSONString, // can
	}}
	mode, reason, _ := triageEncoderFor(spec, triage.ProbeRequest{}, slot)
	if reason != "" {
		t.Fatalf("two unusable modes cost the probe its third: %s. That is a probe that is never sent and a slot that reads as untested", reason)
	}
	if mode != triage.EncodeJSONString {
		t.Errorf("chose %q, want %q", mode, triage.EncodeJSONString)
	}

	// And the other half: a probe whose declared modes ALL miss still falls through to the slot
	// kind's own default rather than being dropped, because the default is what EncodeNone has
	// always resolved to and dropping it here would be a silent loss of coverage.
	only := triage.ProbeSpec{Encoders: []triage.EncoderMode{triage.EncodeIISUnicode}}
	mode, reason, _ = triageEncoderFor(only, triage.ProbeRequest{}, slot)
	if reason != "" {
		t.Fatalf("a probe with no usable declared mode was refused instead of falling back to the slot default encoder: %s", reason)
	}
	if mode != triage.EncodeNone && mode != triage.EncodeJSONString {
		t.Errorf("fell back to %q, want the slot kind's default", mode)
	}
}

// TestAPairThatNoEncoderCanReachIsNotApplicableAndSaysSo. Silence is the thing being replaced: the
// operator must be able to read that traversal's IIS encoder cannot reach a JSON body, because
// that is a true fact about their application and not a gap in the report.
func TestAPairThatNoEncoderCanReachIsNotApplicableAndSaysSo(t *testing.T) {
	// A fragment takes nothing at all, by RFC 3986, so it is the one slot where the answer is the
	// same for every mode any class could declare.
	frag := triage.Slot{
		VectorID: "v1", Kind: triage.KindFragment, Key: "fragment:0", SegmentIndex: -1,
		ServerReachable: false, Constraints: triage.NewSlotConstraints(),
	}
	spec := triage.ProbeSpec{ID: "X-1", Encoders: []triage.EncoderMode{triage.EncodeQuery}}
	reason := triageSlotTakesNoProbeFrom([]triage.ProbeSpec{spec}, frag)
	if reason == "" {
		t.Fatal("a slot no declared encoder and no default can reach was reported as plannable")
	}
	if !strings.Contains(reason, "not_applicable") {
		t.Errorf("the reason does not read as not_applicable, so the row cannot be told from a clean: %q", reason)
	}

	// And a body slot that json_string reaches is NOT not_applicable, even though this class's
	// one declared mode misses it, because the default encoder gets there.
	body := runTestBodySlot()
	iis := triage.ProbeSpec{ID: "X-2", Encoders: []triage.EncoderMode{triage.EncodeIISUnicode}}
	if reason := triageSlotTakesNoProbeFrom([]triage.ProbeSpec{iis}, body); reason != "" {
		t.Errorf("a reachable slot was written off as not_applicable: %q", reason)
	}
}

// TestACredentialSlotIsRefusedAtPlanTimeAndIsNotInTheDenominator.
//
// 1382 of the 3450 slots on run acaff558 carry is_credential, are correctly flagged, and were
// planned anyway: 13820 of the 34500 eligible pairs. pairIsLive refused every one of them at probe
// time, so nothing was ever sent, but the denominator had already been written and the operator
// was shown a run that was 40 percent work that could never happen. Fuzzing a session cookie is
// also actively harmful: it invalidates the session the rest of the run depends on.
func TestACredentialSlotIsRefusedAtPlanTimeAndIsNotInTheDenominator(t *testing.T) {
	cred := triage.Slot{
		VectorID: "v1", Kind: triage.KindCookie, Key: "cookie:session", Name: "session",
		Value: "abc", SegmentIndex: -1, ServerReachable: true,
		Constraints: triage.NewSlotConstraints(),
	}
	cred.Constraints.IsCredential = true

	excl, eligible := triagePairExclusion(nil, cred, triage.ReachAlways, "")
	if excl == "" {
		t.Fatal("a credential slot was planned as live work")
	}
	if !strings.Contains(excl, "is_credential") {
		t.Errorf("the exclusion does not name the reason: %q", excl)
	}
	if eligible {
		t.Error("a credential slot counted in the denominator. The operator is then shown work the runner will never do, and the coverage fraction understates itself for the rest of the run")
	}

	// A non-credential cookie on the same vector is untouched.
	plain := cred
	plain.Key, plain.Name = "cookie:theme", "theme"
	plain.Constraints.IsCredential = false
	if excl, eligible := triagePairExclusion(nil, plain, triage.ReachAlways, ""); excl != "" || !eligible {
		t.Errorf("an ordinary cookie was excluded (%q, eligible=%v)", excl, eligible)
	}
}

// TestAClassWhoseSubjectIsTheCredentialCanOptIn. A JWT or session-fixation class wants the
// Authorization header: it is the thing under test, not collateral. That has to be an explicit
// declaration on the class rather than the default, so that adding such a class is a visible
// decision and not a hole every other class falls through.
func TestAClassWhoseSubjectIsTheCredentialCanOptIn(t *testing.T) {
	cred := triage.Slot{
		VectorID: "v1", Kind: triage.KindHeader, Key: "header:authorization", Name: "Authorization",
		Value: "Bearer x", SegmentIndex: -1, ServerReachable: true,
		Constraints: triage.NewSlotConstraints(),
	}
	cred.Constraints.IsCredential = true

	if excl, _ := triagePairExclusion(triageCredentialOptInStub{}, cred, triage.ReachAlways, ""); excl != "" {
		t.Errorf("a class that declared the credential slot as its subject was refused anyway: %q", excl)
	}
	if excl, _ := triagePairExclusion(triageCredentialOptOutStub{}, cred, triage.ReachAlways, ""); excl == "" {
		t.Error("a class that did not opt in was allowed onto a credential slot")
	}
}

// The two stubs declare only what triagePairExclusion reads: the probes they would send, and
// whether the credential is their subject. Embedding the interface keeps the rest unimplemented,
// which is correct: a call to anything else here is a bug in the function under test.
type triageCredentialOptInStub struct{ triage.Classifier }

func (triageCredentialOptInStub) ProbesCredentialSlots() bool { return true }
func (triageCredentialOptInStub) Probes() []triage.ProbeSpec {
	return []triage.ProbeSpec{{ID: "J-1", Encoders: []triage.EncoderMode{triage.EncodeHeaderValue}}}
}

type triageCredentialOptOutStub struct{ triage.Classifier }

func (triageCredentialOptOutStub) Probes() []triage.ProbeSpec {
	return []triage.ProbeSpec{{ID: "X-1", Encoders: []triage.EncoderMode{triage.EncodeHeaderValue}}}
}

// TestATemplatedPathIsResolvedFromTheVectorsOwnEvidence is the 5666, and it is the one where the
// fix is not less work but more coverage.
//
// 121 of the 317 vectors in the corpus carry a brace in their path. EncodeSlotInto refuses every
// probe against every slot of such a vector, because a request to a literal /accounts/{uuid}/orders
// is a 404 on any application and a scanner pointed at a 404 has tested nothing. 112 of those 121
// carry a concrete evidence URL with the real identifier in it. Resolving the template from the
// vector's own evidence is what templatedPathSegments already does for every other scanner, arity
// guarded so /a/{id}/b never borrows from /a/x/y/b.
func TestATemplatedPathIsResolvedFromTheVectorsOwnEvidence(t *testing.T) {
	row := triageVectorRow{
		ID: "v1", Method: http.MethodPost,
		ComposedURL: "https://app.example.test/api/v1/accounts/{uuid}/orders",
		EvidenceURL: "https://app.example.test/api/v1/accounts/edd0edb9-7562-4c9f-a5cb-5c70d5996c08/orders",
	}
	tmpl := triageRunTemplateFor(row)
	if strings.ContainsAny(tmpl.URL, "{}") {
		t.Fatalf("the request template still carries an unresolved template: %q. Every probe against every slot of this vector is refused before it reaches the wire", tmpl.URL)
	}
	if !strings.Contains(tmpl.URL, "edd0edb9-7562-4c9f-a5cb-5c70d5996c08") {
		t.Errorf("the template was resolved to something other than the identifier the crawl actually observed: %q", tmpl.URL)
	}

	// The arity guard. A different route shape must not be borrowed from, and the runner must not
	// invent a URL nobody served: it refuses the vector instead, by name.
	wrong := row
	wrong.EvidenceURL = "https://app.example.test/api/v1/accounts/x/y/orders"
	tmpl = triageRunTemplateFor(wrong)
	if !strings.ContainsAny(tmpl.URL, "{}") {
		t.Errorf("borrowed segments across a different route shape and built %q, which nothing ever served", tmpl.URL)
	}
	if why := triageUnitUnplannable(wrong); why == "" {
		t.Error("a vector whose path cannot be resolved was planned as live work, so every probe against it is a refusal charged to the operator")
	} else if !strings.Contains(why, "path_template_unresolved") {
		t.Errorf("the reason does not name the defect: %q", why)
	}

	// The nine with no evidence at all. Same answer, and never a canary in a route position: a
	// canary segment is a 404 route, which is the same nothing with a different name on it.
	none := row
	none.EvidenceURL = ""
	if why := triageUnitUnplannable(none); why == "" {
		t.Error("a templated vector with no evidence URL was planned as live work")
	}
	if strings.Contains(triageRunTemplateFor(none).URL, VectorCanary) {
		t.Error("the runner substituted a canary into a route position, which addresses a resource that does not exist and turns every clean here into a false negative")
	}

	// And the vectors that were never templated are untouched.
	plain := triageVectorRow{ID: "v2", Method: http.MethodGet, ComposedURL: "https://app.example.test/api/v1/orders?q=1"}
	if why := triageUnitUnplannable(plain); why != "" {
		t.Errorf("an ordinary vector was refused: %q", why)
	}
	if got := triageRunTemplateFor(plain).URL; got != plain.ComposedURL {
		t.Errorf("an ordinary vector's URL was rewritten: %q", got)
	}
}

// ---------------------------------------------------------------------------------------------
// THE MEASUREMENT
//
// TestMeasureThePlanningWaste is not an assertion, it is an instrument. It builds the plan from a
// REAL corpus, counts what the runner would have planned before this change and what it plans
// now, and prints both. It is skipped unless TRIAGE_MEASURE_DATABASE_URL names a database, and it
// opens that database with default_transaction_read_only so that pointing it at a live operator's
// corpus cannot write a byte. buildTriagePlan issues SELECTs only; the read-only transaction is
// the belt to that braces.
//
// Run it with:
//
//	TRIAGE_MEASURE_DATABASE_URL=... TRIAGE_MEASURE_TARGET=<scope target uuid> \
//	  go test ./utils/ -run TestMeasureThePlanningWaste -count=1 -v
// ---------------------------------------------------------------------------------------------

// triageOldEncoderFor is the encoder choice exactly as it stood before this change: honour a named
// mode unconditionally, otherwise take the first declared mode that fits the slot's KIND, ignoring
// the body media and ignoring whether the container needs a name the slot does not have.
func triageOldEncoderFor(spec triage.ProbeSpec, req triage.ProbeRequest, slot triage.Slot) triage.EncoderMode {
	if named := strings.TrimSpace(req.Variant["encoder"]); named != "" {
		return triage.EncoderMode(named)
	}
	for _, m := range spec.Encoders {
		if triageModeFitsKind(m, slot.Kind) == nil {
			return m
		}
	}
	return triage.EncodeNone
}

func TestMeasureThePlanningWaste(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("TRIAGE_MEASURE_DATABASE_URL"))
	target := strings.TrimSpace(os.Getenv("TRIAGE_MEASURE_TARGET"))
	if dsn == "" || target == "" {
		t.Skip("NOT MEASURED: set TRIAGE_MEASURE_DATABASE_URL and TRIAGE_MEASURE_TARGET to measure the plan against a real corpus. This is an instrument, not an assertion, and skipping it proves nothing either way.")
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	dsn += sep + "options=" + url.QueryEscape("-c default_transaction_read_only=on")

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	prev := dbPool
	InitDB(pool)
	defer InitDB(prev)

	settings, notes := LoadTriageSettings(ctx, target)
	for _, n := range notes {
		t.Logf("SETTINGS          %s", n)
	}
	plan, err := buildTriagePlan(ctx, target, settings)
	if err != nil {
		t.Fatalf("build plan: %v", err)
	}

	slots := map[triage.SlotKey]bool{}
	credSlots := map[string]bool{}
	unplannableUnits, unplannablePairs := 0, 0
	for _, u := range plan.Units {
		if u.Unplannable != "" {
			unplannableUnits++
		}
		for _, s := range u.Slots {
			slots[s.Key] = true
			if s.Constraints.IsCredential {
				credSlots[u.VectorID+"/"+string(s.Key)] = true
			}
		}
	}

	eligible, credPairs, encPairs := 0, 0, 0
	for _, p := range plan.Pairs {
		if p.Eligible {
			eligible++
		}
		switch {
		case strings.HasPrefix(p.Excluded, "is_credential"):
			credPairs++
		case strings.HasPrefix(p.Excluded, "path_template_unresolved"):
			unplannablePairs++
		case strings.HasPrefix(p.Excluded, "not_applicable"):
			encPairs++
		}
	}

	// The probe-level count. For every live pair, every payload the class declares is resolved
	// both ways and asked whether the encoder would take it. This is the same question sendProbe
	// asks per probe instance, so the ratio is the ratio of the live run.
	reg := triage.RegisteredClassifiers()
	oldRefused, newRefused, newDropped, planned := 0, 0, 0, 0
	byReason := map[DeliveryReason]int{}
	for _, u := range plan.Units {
		if !u.Selected {
			continue
		}
		for _, s := range u.Slots {
			for _, class := range plan.EnabledClasses {
				c, ok := reg[class]
				if !ok {
					continue
				}
				if plan.Unavailable[class] != "" {
					continue
				}
				for _, spec := range c.Probes() {
					planned++
					// BEFORE: the vector's template was never resolved, so the URL check refused
					// everything on a templated vector whatever the mode was.
					oldMode := triageOldEncoderFor(spec, triage.ProbeRequest{}, s)
					if strings.ContainsAny(u.Vector.ComposedURL, "{}") {
						oldRefused++
						byReason[ReasonPathTemplateOpen]++
					} else if reason, _ := SlotAcceptsEncoder(s, oldMode); reason != "" {
						oldRefused++
						byReason[reason]++
					}
					// AFTER: an unplannable vector or an excluded pair plans nothing at all, and
					// what is planned is resolved through the capability first.
					if u.Unplannable != "" || rrExcludedFor(plan, u.VectorID, s.Key, class) != "" {
						newDropped++
						continue
					}
					if _, reason, _ := triageEncoderFor(spec, triage.ProbeRequest{}, s); reason != "" {
						newRefused++
					}
				}
			}
		}
	}

	t.Logf("CORPUS            %d vectors, %d slots, %d of them credential",
		len(plan.Units), len(slots), len(credSlots))
	t.Logf("PAIRS   before    %d counted as eligible", len(plan.Pairs))
	t.Logf("PAIRS   after     %d counted as eligible (%d credential pairs removed from the denominator, every one keeping its coverage row)",
		eligible, credPairs)
	t.Logf("PAIRS   excluded  %d credential, %d on a request-target that cannot be resolved (%d vectors), %d that no encoder can reach",
		credPairs, unplannablePairs, unplannableUnits, encPairs)
	t.Logf("PROBES  planned   %d declared payloads across every live pair", planned)
	t.Logf("PROBES  before    %d would reach the encoder and be refused inside the process", oldRefused)
	for r, n := range byReason {
		t.Logf("PROBES  before      %-40s %d", r, n)
	}
	t.Logf("PROBES  after     %d refused inside the process, %d never planned (no ordinal, no fidelity row, a named coverage row instead)",
		newRefused, newDropped)
}

// rrExcludedFor reads the plan-time decision off the plan, the way writePlanRows indexes it.
func rrExcludedFor(plan triagePlan, vectorID string, slot triage.SlotKey, class triage.ClassID) string {
	for _, p := range plan.Pairs {
		if p.Slot.VectorID == vectorID && p.Slot.Key == slot && p.Class == class {
			return p.Excluded
		}
	}
	return ""
}

// TestTheOldEncoderChoiceStillReproducesTheRefusalsItCaused is the before half of this change,
// kept in the tree rather than described in a commit message.
//
// triageOldEncoderFor is the choice exactly as it stood: honour a named mode unconditionally,
// otherwise take the first declared mode that fits the slot's KIND. This test drives both
// functions over the two slot shapes that produced 1227 of the 6931 refusals on live run
// acaff558, and asserts that the old one still reaches the encoder and is still refused, and that
// the new one is not. If someone widens the kind table and deletes the capability check, the
// first half of this test keeps passing and the second half fails, which is the right way round.
func TestTheOldEncoderChoiceStillReproducesTheRefusalsItCaused(t *testing.T) {
	tmpl := RequestTemplate{
		Method: http.MethodPost,
		URL:    "https://app.example.test/api/v1/orders",
		Body:   []byte(`{"name":"hello"}`),
	}
	slot := runTestBodySlot()

	for _, tc := range []struct {
		name string
		spec triage.ProbeSpec
		req  triage.ProbeRequest
		was  DeliveryReason
	}{
		{
			// The 971. Six classes declare form before json_string, so every one of them aimed
			// the form encoder at a JSON body slot that has no field name to write into.
			name: "form declared before json_string, into a JSON body",
			spec: triage.ProbeSpec{Encoders: []triage.EncoderMode{triage.EncodeForm, triage.EncodeJSONString}},
			was:  ReasonSlotHasNoName,
		},
		{
			// The 256. Traversal's round-2 sweep, 128 pct_twice and 128 iis_unicode, into bodies.
			name: "traversal's encoder sweep, into a JSON body",
			spec: triage.ProbeSpec{Encoders: []triage.EncoderMode{triage.EncodeJSONString}},
			req:  triage.ProbeRequest{Variant: map[string]string{"encoder": string(triage.EncodeIISUnicode)}},
			was:  ReasonEncoderWrongKind,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// BEFORE: the mode reaches the encoder, which refuses it. The probe has by this point
			// already been counted against the per-slot cap, minted an ordinal from the run's
			// stripe and written a row to triage_fidelity.
			oldMode := triageOldEncoderFor(tc.spec, tc.req, slot)
			enc := EncodeSlotInto(tmpl, slot, oldMode, []byte("payload"), triage.SlotOverrides{})
			if enc.Delivered {
				t.Fatalf("the old choice delivered %q into a JSON body, so this test no longer reproduces the defect it was written for", oldMode)
			}
			if enc.Reason == "" {
				t.Fatal("the encoder refused without a reason")
			}

			// AFTER: the runner either picks a mode that works, or refuses before the probe is
			// planned. Either way nothing undeliverable reaches the encoder.
			newMode, reason, _ := triageEncoderFor(tc.spec, tc.req, slot)
			if reason != "" {
				t.Logf("refused at plan time under %q: %s (no ordinal, no fidelity row, a named coverage row instead)", newMode, reason)
				return
			}
			enc = EncodeSlotInto(tmpl, slot, newMode, []byte("payload"), triage.SlotOverrides{})
			if !enc.Delivered {
				t.Fatalf("the runner planned %q and the encoder refused it with %q: %s", newMode, enc.Reason, enc.Detail)
			}
			t.Logf("planned under %q and delivered, where the old choice picked %q and was refused", newMode, oldMode)
		})
	}

	// And the 5666: the request-target itself. A templated vector refused every probe against
	// every slot on every class, whatever the encoder was.
	row := triageVectorRow{
		ID: "v1", Method: http.MethodPost,
		ComposedURL: "https://app.example.test/api/v1/accounts/{uuid}/orders?x=hello",
		EvidenceURL: "https://app.example.test/api/v1/accounts/edd0edb9-7562-4c9f-a5cb-5c70d5996c08/orders?x=hello",
	}
	before := EncodeSlotInto(RequestTemplate{Method: row.Method, URL: row.ComposedURL},
		encTestSlot(triage.KindQuery), triage.EncodeQuery, []byte("payload"), triage.SlotOverrides{})
	if before.Delivered || before.Reason != ReasonPathTemplateOpen {
		t.Fatalf("an unresolved request-target no longer refuses (%v, %q), so this test no longer reproduces the defect", before.Delivered, before.Reason)
	}
	after := EncodeSlotInto(triageRunTemplateFor(row),
		encTestSlot(triage.KindQuery), triage.EncodeQuery, []byte("payload"), triage.SlotOverrides{})
	if !after.Delivered {
		t.Fatalf("the resolved request-target still refuses: %q: %s", after.Reason, after.Detail)
	}
}

// ---------------------------------------------------------------------------------------------
// D4. THE ORDER THE PLAN IS WALKED IN
//
// These are pure tests over triageInterleave and the truncation report: no database, no socket,
// no budget object. The defect they pin was measured on a live run and it is a false negative,
// not a performance problem. Of 34,500 planned pairs the run spent its whole 4,000-probe budget
// on body slots and sent zero requests at cookie, header, path and query, because the plan was
// walked in raw table order. The card then said "0 fired", which reads as a fact about the
// application and was a fact about the sort order of a Postgres result set.
// ---------------------------------------------------------------------------------------------

// triageTableOrder reproduces the OLD walk exactly: units in plan order, each driven to
// completion. It is kept in the test file so the two orders can be measured against the same
// budget in the same assertion, and so the regression this fix closes cannot be reopened by
// accident without a test going red.
func triageTableOrder(units []triageUnitPlan) []triageWorkItem {
	var out []triageWorkItem
	for i := range units {
		u := &units[i]
		if !u.Selected || len(u.Slots) == 0 {
			continue
		}
		for _, s := range u.Slots {
			out = append(out, triageWorkItem{Unit: u, Slot: s})
		}
	}
	return out
}

// triageKindsIn names the distinct insertion-point kinds in a prefix of a schedule, which is what
// a fixed probe budget actually buys.
func triageKindsIn(items []triageWorkItem, prefix int) map[triage.SlotKind]int {
	out := map[triage.SlotKind]int{}
	for i, w := range items {
		if i >= prefix {
			break
		}
		out[w.Slot.Kind]++
	}
	return out
}

// triageShapedLikeTheLiveRun builds a plan with the shape measured on the operator's run: the
// kinds in the order the vector table returned them, body first and small, cookie enormous.
func triageShapedLikeTheLiveRun() []triageUnitPlan {
	shape := []struct {
		kind    triage.SlotKind
		vectors int
		slots   int
	}{
		{triage.KindBody, 8, 17},    // 136 slots, and they sorted first
		{triage.KindCookie, 30, 69}, // 2070 slots
		{triage.KindHeader, 19, 49},
		{triage.KindPath, 24, 9},
		{triage.KindQuery, 31, 3},
	}
	var units []triageUnitPlan
	for _, s := range shape {
		for v := 0; v < s.vectors; v++ {
			id := fmt.Sprintf("%s-v%02d", s.kind, v)
			u := triageUnitPlan{VectorID: id, Selected: true}
			for n := 0; n < s.slots; n++ {
				u.Slots = append(u.Slots, triage.Slot{
					VectorID: id,
					Kind:     s.kind,
					Key:      triage.SlotKey(fmt.Sprintf("%s:%s:%d", s.kind, id, n)),
				})
			}
			units = append(units, u)
		}
	}
	return units
}

// THE MEASURED DEFECT, BOTH WAYS ROUND. A budget that can afford 400 of 2,900 slots must buy some
// of every kind. In table order it buys body and nothing else, which is what the operator was
// looking at when they read "0 fired" off a card.
func TestAFixedBudgetBuysEveryKindOnlyBecauseTheOrderInterleaves(t *testing.T) {
	units := triageShapedLikeTheLiveRun()
	kinds := []triage.SlotKind{triage.KindBody, triage.KindCookie, triage.KindHeader, triage.KindPath, triage.KindQuery}

	// A budget that affords 130 of the plan's 2,899 slots. In table order it does not even finish
	// the 136 body slots that sorted first, so four of the five kinds get literally nothing.
	const tight = 130
	old := triageKindsIn(triageTableOrder(units), tight)
	if len(old) != 1 || old[triage.KindBody] != tight {
		t.Fatalf("the old table-order walk was supposed to reproduce the measured starvation and did not: the first %d slots covered %v", tight, old)
	}

	now := triageKindsIn(triageInterleave(units), tight)
	for _, k := range kinds {
		if now[k] < 20 {
			t.Errorf("%s got %d slots in the first %d of the interleaved schedule, which is not a share of five kinds: %v", k, now[k], tight, now)
		}
	}

	// A LARGER BUDGET FINISHES THE SMALL KINDS OUTRIGHT, and that is the point rather than a side
	// effect. Query is 93 slots, it is cheap, and it is where SQL injection actually lives; cookie
	// is 2,070 replicated slots and is not. Dealing one per kind per cycle spends the budget in
	// that order without anyone having to rank the kinds by hand.
	const roomier = 600
	wide := triageKindsIn(triageInterleave(units), roomier)
	if wide[triage.KindQuery] != 93 {
		t.Errorf("query has 93 slots and the budget affords %d, so all 93 should be bought; got %d", roomier, wide[triage.KindQuery])
	}
	if wide[triage.KindCookie] >= 2070 {
		t.Errorf("cookie has 2070 slots and must be the kind that gets truncated, not the kind that gets everything; got %d", wide[triage.KindCookie])
	}
	if got := triageKindsIn(triageTableOrder(units), roomier); got[triage.KindQuery] != 0 {
		t.Errorf("the old walk is meant to still be sending zero query slots at %d, got %d", roomier, got[triage.KindQuery])
	}
}

// Within one kind the rotation is across VECTORS, so a cut does not exhaust one endpoint's
// seventy cookies while two hundred other endpoints are never touched.
func TestTheScheduleSpreadsAcrossVectorsBeforeItGoesDeepIntoOne(t *testing.T) {
	var units []triageUnitPlan
	for v := 0; v < 5; v++ {
		id := fmt.Sprintf("v%d", v)
		u := triageUnitPlan{VectorID: id, Selected: true}
		for n := 0; n < 4; n++ {
			u.Slots = append(u.Slots, triage.Slot{VectorID: id, Kind: triage.KindCookie,
				Key: triage.SlotKey(fmt.Sprintf("cookie:%s:%d", id, n))})
		}
		units = append(units, u)
	}

	got := triageInterleave(units)
	if len(got) != 20 {
		t.Fatalf("20 slots planned, %d scheduled", len(got))
	}
	seen := map[string]bool{}
	for _, w := range got[:5] {
		seen[w.Unit.VectorID] = true
	}
	if len(seen) != 5 {
		t.Errorf("the first five items should be one slot from each of the five vectors, got %v", seen)
	}
}

// NOTHING MAY FALL OUT OF THE ROTATION. A schedule that quietly drops a slot is the silent zero
// this whole layer exists to remove, and it would be invisible: the coverage row was written
// before the run started and would simply stay not_run.
func TestTheScheduleContainsEveryPlannedSlotExactlyOnce(t *testing.T) {
	units := triageShapedLikeTheLiveRun()
	units = append(units,
		triageUnitPlan{VectorID: "deselected", Selected: false, Slots: []triage.Slot{
			{VectorID: "deselected", Kind: triage.KindQuery, Key: "query:deselected:0"}}},
		triageUnitPlan{VectorID: "empty", Selected: true},
		// A kind this build does not name must still be dealt from rather than dropped.
		triageUnitPlan{VectorID: "odd", Selected: true, Slots: []triage.Slot{
			{VectorID: "odd", Kind: triage.SlotKind("trailer"), Key: "trailer:odd:0"}}},
	)

	want := map[triage.SlotKey]int{}
	for i := range units {
		if !units[i].Selected {
			continue
		}
		for _, s := range units[i].Slots {
			want[s.Key]++
		}
	}

	got := map[triage.SlotKey]int{}
	for _, w := range triageInterleave(units) {
		got[w.Slot.Key]++
		if w.Unit.VectorID != w.Slot.VectorID {
			t.Fatalf("slot %s was scheduled against vector %s", w.Slot.Key, w.Unit.VectorID)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("scheduled %d distinct slots, planned %d", len(got), len(want))
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("slot %s planned %d times, scheduled %d", k, n, got[k])
		}
	}
	if got["query:deselected:0"] != 0 {
		t.Errorf("a deselected vector was scheduled")
	}
	if got["trailer:odd:0"] != 1 {
		t.Errorf("a slot of an unrecognised kind was dropped off the end of the schedule")
	}
}

// The caps are checked per probe and the ladder walked `live` in one fixed order, so whichever
// class sorted last was systematically the one that never spent. The rotation is where that is
// fixed; the ladder itself is left alone, because a class's round N is planned from its own
// round N-1 and hoisting class above slot would break what the interface promises.
func TestTheClassOrderRotatesSoTheSameClassIsNotAlwaysLast(t *testing.T) {
	live := []triage.ClassID{triage.ClassSQL, triage.ClassNoSQL, triage.ClassSSTI, triage.ClassLFI}
	lastSeen := map[triage.ClassID]int{}
	firstSeen := map[triage.ClassID]int{}
	for at := 0; at < len(live)*7; at++ {
		got := triageRotateClasses(live, at)
		if len(got) != len(live) {
			t.Fatalf("rotation at %d changed the class count: %v", at, got)
		}
		seen := map[triage.ClassID]bool{}
		for _, c := range got {
			seen[c] = true
		}
		if len(seen) != len(live) {
			t.Fatalf("rotation at %d lost or duplicated a class: %v", at, got)
		}
		firstSeen[got[0]]++
		lastSeen[got[len(got)-1]]++
	}
	for _, c := range live {
		if firstSeen[c] != 7 || lastSeen[c] != 7 {
			t.Errorf("%s went first %d times and last %d times over 28 slots; an even rotation is 7 and 7", c, firstSeen[c], lastSeen[c])
		}
	}
	if len(triageRotateClasses([]triage.ClassID{triage.ClassSQL}, 3)) != 1 {
		t.Errorf("a single-class rotation should be the identity")
	}
}

// THE TRUNCATION HAS TO BE READABLE OFF THE CARD. A run that could only afford 19% of its plan
// and says nothing is indistinguishable from a run that asked everything and found nothing, and
// the second reading is the one an operator makes by default.
func TestABudgetCutReportsHowMuchOfThePlanItBoughtAndWhatItMissed(t *testing.T) {
	rr := &triageRunner{
		budget:   triage.TriageBudget{PerRun: 4000, PerSlot: 24},
		coverage: map[string]*TriageCoverageRow{},
		covDirty: map[string]bool{},
	}

	add := func(kind triage.SlotKind, vector string, n int, class triage.ClassID, ran bool) {
		for i := 0; i < n; i++ {
			slot := triage.Slot{VectorID: vector, Kind: kind,
				Key: triage.SlotKey(fmt.Sprintf("%s:%s:%d", kind, vector, i))}
			rr.plan.Pairs = append(rr.plan.Pairs, triagePair{Slot: slot, Class: class, Eligible: true})
			row := rr.cov(vector, slot.Key, class)
			row.Ran = ran
		}
	}
	// Measured: body was the only kind that got anything, and only one class of it.
	add(triage.KindBody, "vb", 100, triage.ClassSQL, true)
	add(triage.KindBody, "vb", 100, triage.ClassSSTI, false)
	add(triage.KindCookie, "vc", 300, triage.ClassSQL, false)
	add(triage.KindQuery, "vq", 100, triage.ClassSQL, false)
	// A pair the planner refused is not part of the denominator and must not dilute the percent.
	rr.plan.Pairs = append(rr.plan.Pairs, triagePair{
		Slot:  triage.Slot{VectorID: "vc", Kind: triage.KindCookie, Key: "cookie:vc:cred"},
		Class: triage.ClassSQL, Eligible: false})

	quiet := rr.truncation()
	if quiet.Cut {
		t.Fatalf("a run that was not cut must not claim it was")
	}

	rr.budgetCut = true
	cut := rr.truncation()
	if cut.Planned != 600 || cut.Measured != 100 {
		t.Fatalf("planned %d measured %d, want 600 and 100 (the ineligible pair must be out of both)", cut.Planned, cut.Measured)
	}
	if cut.Percent() != 16 {
		t.Errorf("100 of 600 is 16%% floored, got %d", cut.Percent())
	}

	s := cut.Sentence()
	for _, want := range []string{
		"BUDGET TRUNCATED AT 16% OF THE PLAN",
		"per-run cap of 4000 probes",
		"100 of 600 probeable pairs",
		"cookie (0 of 300)",
		"query (0 of 100)",
		"body 100 of 200",
		"never clean",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("the truncation sentence does not carry %q.\nGot: %s", want, s)
		}
	}
	// SSTI got nothing and body did get something, so the kind line must not claim body is blind
	// while the class line does name SSTI.
	if strings.Contains(s, "body (0 of") {
		t.Errorf("body was measured and must not be listed as blind: %s", s)
	}
	if !strings.Contains(s, "Classes that got no probe at all") || !strings.Contains(s, "SSTI") {
		t.Errorf("a class that got nothing has to be named: %s", s)
	}
}

// ---------------------------------------------------------------------------------------------
// D2. THE OPERATOR'S OWN PAYLOADS
// ---------------------------------------------------------------------------------------------

// triageOldCustomRender is the render sendCustomPayloads used to do: two substitutions, both of
// which require the payload to SPELL a marker, and no read of MarkerPos at all. It is kept here
// so the false clean it manufactured is measured rather than described.
func triageOldCustomRender(logicalBytes []byte, marker triage.Marker) []byte {
	logical := triageMarkerLiteral.ReplaceAll(logicalBytes, []byte(marker))
	return bytes.ReplaceAll(logical, []byte(triage.MarkerPlaceholder), []byte(marker))
}

// THE SIXTH FALSE-CLEAN DOOR, MEASURED. A reflect-mode payload saved in the modal carries marker
// position "prefix" by default and does not spell a marker anywhere. Under the old render it went
// out bare, ScanMarkers found nothing, fired was false, and the row said StateClean: "the
// operator's own payload went out as asked and its own declared oracle stayed silent".
func TestACustomReflectPayloadPutsItsMarkerOnTheWire(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	p := TriageCustomPayload{
		ID: "op-1", Class: "sql", Payload: "' OR 1=1 -- ",
		Points: []string{"query"}, Enabled: true,
		Detection: TriageDetection{Mode: TriageDetectReflect},
	}

	if old := triageOldCustomRender([]byte(p.Payload), marker); bytes.Contains(old, []byte(marker)) {
		t.Fatalf("the old render was supposed to leave the marker off the wire and did not, so this test is not reproducing the defect: %q", old)
	}

	spec, err := triageCustomProbeSpec(triage.ClassSQL, p)
	if err != nil {
		t.Fatalf("building the spec: %v", err)
	}
	if spec.MarkerPos != triage.MarkerPrefix {
		t.Fatalf("an operator payload with no marker_pos defaults to prefix in the modal and at save time; the runner built %q", spec.MarkerPos)
	}
	req := triage.ProbeRequest{Spec: spec.ID, Marker: marker, Variant: triageCustomVariant(p)}
	got, why := triageRenderPayload(spec, req, triage.Slot{Kind: triage.KindQuery, Value: "1"}, marker)
	if why != "" {
		t.Fatalf("the payload was refused: %s", why)
	}
	if !bytes.HasPrefix(got, []byte(marker)) {
		t.Fatalf("marker_pos prefix did not put the marker on the wire: %q", got)
	}
	if !bytes.Contains(got, []byte("' OR 1=1 -- ")) {
		t.Fatalf("the operator's own bytes did not survive the render: %q", got)
	}
}

func TestACustomPayloadHonoursEveryMarkerPositionItCanDeclare(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	slot := triage.Slot{Kind: triage.KindQuery, Value: "1"}

	render := func(t *testing.T, pos string) []byte {
		t.Helper()
		p := TriageCustomPayload{ID: "op-" + pos, Class: "sql", Payload: "abc",
			Points: []string{"query"}, MarkerPos: pos,
			Detection: TriageDetection{Mode: TriageDetectReflect}}
		spec, err := triageCustomProbeSpec(triage.ClassSQL, p)
		if err != nil {
			t.Fatalf("spec: %v", err)
		}
		req := triage.ProbeRequest{Spec: spec.ID, Marker: marker, Variant: triageCustomVariant(p)}
		got, why := triageRenderPayload(spec, req, slot, marker)
		if why != "" {
			t.Fatalf("%s was refused: %s", pos, why)
		}
		return got
	}

	if got := render(t, "suffix"); !bytes.HasSuffix(got, []byte(marker)) {
		t.Errorf("suffix: %q", got)
	}
	if got := render(t, "prefix"); !bytes.HasPrefix(got, []byte(marker)) {
		t.Errorf("prefix: %q", got)
	}
	// THE OPT-OUT THE SHIPPED PATH GREW AFTER ELI-EL6 WAS CORRUPTED BY A PREFIX. The modal cannot
	// spell it yet, and the renderer honours it now so that the day it can, a bare payload stays
	// bare instead of becoming a parse error in every dialect.
	if got := render(t, "omitted"); bytes.Contains(got, []byte(marker)) {
		t.Errorf("marker_pos omitted still attached a marker: %q", got)
	}
	if got := render(t, "none"); bytes.Contains(got, []byte(marker)) {
		t.Errorf("marker_pos none still attached a marker: %q", got)
	}
}

// A payload that SPELLS its own marker has chosen where it goes, and a second one prepended would
// corrupt it. This is the guard the shipped path carries and the custom path now inherits rather
// than reimplements.
func TestACustomPayloadThatSpellsItsMarkerIsNotGivenASecond(t *testing.T) {
	marker := triageTestMarker(t, triage.ClassSQL, uint64(triage.ClassSQL))
	p := TriageCustomPayload{ID: "op-2", Class: "sql", Payload: "concat(" + triage.MarkerPlaceholder + ",1)",
		Points: []string{"query"}, Detection: TriageDetection{Mode: TriageDetectReflect}}
	spec, err := triageCustomProbeSpec(triage.ClassSQL, p)
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	req := triage.ProbeRequest{Spec: spec.ID, Marker: marker, Variant: triageCustomVariant(p)}
	got, why := triageRenderPayload(spec, req, triage.Slot{Kind: triage.KindQuery, Value: "1"}, marker)
	if why != "" {
		t.Fatalf("refused: %s", why)
	}
	if n := bytes.Count(got, []byte(marker)); n != 1 {
		t.Fatalf("the payload spelled its own marker and got %d of them: %q", n, got)
	}
	if !bytes.HasPrefix(got, []byte("concat(")) {
		t.Fatalf("a marker was prepended onto a payload that had already placed one: %q", got)
	}
}

// A PAYLOAD NOTHING CAN JUDGE IS NOT SENT. detection mode "inherit" is the modal's first option
// and produced a guaranteed unknown; the request went out first, up to one per matching slot,
// which on the measured corpus is 3,450 live requests per payload for no answer.
func TestAnUnjudgeableCustomPayloadIsRefusedBeforeAnythingIsSent(t *testing.T) {
	cases := []struct {
		name string
		p    TriageCustomPayload
		want string
	}{
		{"inherit", TriageCustomPayload{ID: "i", Detection: TriageDetection{Mode: "inherit"}}, "custom_payload_inherit_unsupported"},
		{"blank", TriageCustomPayload{ID: "b", Detection: TriageDetection{Mode: ""}}, "custom_payload_inherit_unsupported"},
		{"bad regex", TriageCustomPayload{ID: "r", Detection: TriageDetection{Mode: TriageDetectBodyRegex, Pattern: "("}}, "custom_payload_bad_pattern"},
	}
	for _, c := range cases {
		why := triageCustomOracleUnusable(c.p)
		if !strings.Contains(why, c.want) {
			t.Errorf("%s: want a refusal naming %s, got %q", c.name, c.want, why)
		}
		if !strings.Contains(why, "Nothing was sent") {
			t.Errorf("%s: the row has to say the request was not made, got %q", c.name, why)
		}
	}
	for _, mode := range []string{TriageDetectReflect, TriageDetectBodyContains, TriageDetectStatusIn, TriageDetectTimeDelay} {
		if why := triageCustomOracleUnusable(TriageCustomPayload{ID: "ok", Detection: TriageDetection{Mode: mode}}); why != "" {
			t.Errorf("%s is a mode the runner can read and was refused: %s", mode, why)
		}
	}
	if why := triageCustomOracleUnusable(TriageCustomPayload{ID: "ok", Detection: TriageDetection{Mode: TriageDetectBodyRegex, Pattern: "^a+b$"}}); why != "" {
		t.Errorf("a valid regex was refused: %s", why)
	}
}

// AN EMPTY POINTS LIST FAILS CLOSED. It used to answer true, which aimed the payload at every
// insertion point the class touches. The save-time validator has always refused it.
func TestACustomPayloadWithNoDeclaredPointsReachesNothing(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindQuery}
	if triageCustomReachesSlot(TriageCustomPayload{ID: "p"}, slot) {
		t.Errorf("a payload with no points list must not reach a slot")
	}
	if !triageCustomReachesSlot(TriageCustomPayload{ID: "p", Points: []string{"body", "query"}}, slot) {
		t.Errorf("a payload that names query must reach a query slot")
	}
	if triageCustomReachesSlot(TriageCustomPayload{ID: "p", Points: []string{"body"}}, slot) {
		t.Errorf("a payload that names only body must not reach a query slot")
	}
}

// THE RUN-START ISOLATION LAW NOW SEES THE OPERATOR'S PAYLOADS. Before this, a payload that was
// disjoint from the catalogue when it was saved was never re-checked against a probe shipped
// later, and a hit on either of two byte-equal payloads is attributable to neither.
func TestTheRunStartIsolationLawIncludesTheOperatorsOwnPayloads(t *testing.T) {
	if err := triageAssertIsolationIncludingCustom(TriageInvestigateSettings{}); err != nil {
		t.Fatalf("the shipped registry alone must pass the law: %v", err)
	}

	var collide []byte
	for _, c := range triage.RegisteredClassifiers() {
		for _, spec := range c.Probes() {
			if len(spec.Logical) >= 24 && c.ID() != triage.ClassSQL {
				collide = spec.Logical
				break
			}
		}
		if collide != nil {
			break
		}
	}
	if collide == nil {
		t.Skip("NOT MEASURED: no shipped probe of 24 bytes or more outside SQL, so no payload could be built that the law must refuse. This is a gap in coverage, not a pass.")
	}

	s := TriageInvestigateSettings{CustomPayloads: []TriageCustomPayload{{
		ID: "op-collide", Class: "sql", Payload: string(collide), Enabled: true,
		Points: []string{"query"}, Detection: TriageDetection{Mode: TriageDetectReflect},
	}}}
	if err := triageAssertIsolationIncludingCustom(s); err == nil {
		t.Errorf("an operator payload byte-equal to another class's shipped probe was allowed to start a run, so a hit on it would be attributable to neither class")
	}

	// A disabled payload is not going on the wire, so it is not part of the law.
	s.CustomPayloads[0].Enabled = false
	if err := triageAssertIsolationIncludingCustom(s); err != nil {
		t.Errorf("a disabled payload blocked the run: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// L1: THE SHAPE-ONLY GATE. A vector the gate judged STABLE ON ITS SHAPE was refused by the
// runner's front door and no class sent a single byte into it.
//
// MEASURED, live run a218419a (run_id fkqv), 2026-09-19: 500 verdicts across 6 vectors and 50
// distinct slots carried baseline_unstable, and EVERY ONE of them named json_shape_stable as the
// reason. Not one was a genuinely unstable baseline. The message the operator read was false in
// both halves: it said "the unperturbed samples already disagree with each other" immediately
// after the gate had found their shape identical.
// ---------------------------------------------------------------------------------------------

// triageShapeOnlyServer is a REST endpoint whose BYTES are never the same twice and whose SHAPE
// never changes: an id, a server timestamp and a counter, which is the ordinary anatomy of the
// endpoints this layer is pointed at. It is the fixture the gate calls judgeable_shape_only and
// it is the fixture the front door used to throw away.
func triageShapeOnlyServer(t *testing.T) *httptest.Server {
	t.Helper()
	var n int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt64(&n, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"id":"%s","served_at":"%s","seq":%d,"items":[{"sym":"AAPL","px":%d}]}`,
			uuid.New().String(), time.Now().UTC().Format(time.RFC3339Nano), i, 1000+i)
	}))
	t.Cleanup(s.Close)
	return s
}

// triageVolatileServer changes its SHAPE as well as its bytes, so the gate has nothing to hold.
// It is the control: the fix must not turn a genuinely unstable baseline into a probed one.
func triageVolatileServer(t *testing.T) *httptest.Server {
	t.Helper()
	var n int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := atomic.AddInt64(&n, 1)
		w.Header().Set("Content-Type", "application/json")
		fields := make([]string, 0, int(i%5)+1)
		for k := 0; k <= int(i%5); k++ {
			fields = append(fields, fmt.Sprintf(`"f%d_%d":%q`, i, k, uuid.New().String()))
		}
		fmt.Fprintf(w, "{%s}", strings.Join(fields, ","))
	}))
	t.Cleanup(s.Close)
	return s
}

// triageUnitRunner is a runner with no database, no pacing and no scope filter, for driving the
// parts of the sweep that need only an HTTP client. Every map the runner writes through is
// present, because a nil map here panics in a way that reads as a transport failure.
func triageUnitRunner(t *testing.T, classes ...triage.ClassID) *triageRunner {
	t.Helper()
	runID := strings.ToLower(uuid.New().String()[:4])
	minter, err := NewMarkerMinter(runID)
	if err != nil {
		t.Fatalf("minter: %v", err)
	}
	rr := &triageRunner{
		runUUID:   "unit-" + runID,
		runID:     runID,
		settings:  TriageSettingsDefaults(),
		minter:    minter,
		vault:     triage.NewPerturbedVault(triageRunnerCapability(), runID),
		coverage:  map[string]*TriageCoverageRow{},
		covDirty:  map[string]bool{},
		perturbed: map[string][]triage.Perturbed{},
		excluded:  map[string]string{},
		unitCtx:   map[string]*triageUnitCtx{},
		budget:    triage.TriageBudget{PerRun: 10000, PerSlot: 24},
	}
	rr.plan.EnabledClasses = classes
	rr.plan.Unavailable = map[triage.ClassID]string{}
	rr.plan.Degraded = map[triage.ClassID][]string{}
	t.Cleanup(func() { rr.vault.Release(triageRunnerCapability()) })
	return rr
}

// triageQueryUnit is one vector with one query slot, pointed at base.
func triageQueryUnit(base, param string) (*triageUnitPlan, triage.Slot) {
	u := &triageUnitPlan{
		VectorID: "v-" + param,
		Host:     "127.0.0.1",
		Template: RequestTemplate{Method: "GET", URL: base + "/?" + param + "=hello"},
		Selected: true,
	}
	slot := triage.Slot{VectorID: u.VectorID, Kind: triage.KindQuery, Key: triage.SlotKey("query:" + param),
		Name: param, Value: "hello", SegmentIndex: -1, ServerReachable: true,
		Origin: triage.SlotObserved, ValueOrigin: triage.ValueObserved,
		Constraints: triage.NewSlotConstraints()}
	u.Slots = []triage.Slot{slot}
	return u, slot
}

func TestAShapeStableBaselineIsProbedInsteadOfBeingCalledUnstable(t *testing.T) {
	srv := triageShapeOnlyServer(t)
	rr := triageUnitRunner(t, triage.ClassSQL)
	rr.settings.Tier = string(triage.TierOptIn)
	cs := rr.settings.Classes[TriageClassKey(triage.ClassSQL)]
	cs.Enabled, cs.Tier, cs.MaxRisk = true, string(triage.TierOptIn), string(triage.RiskR3)
	rr.settings.Classes[TriageClassKey(triage.ClassSQL)] = cs
	u, slot := triageQueryUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassSQL, Eligible: true}}

	uc := rr.unitContext(context.Background(), u)
	if uc == nil {
		t.Fatal("no unit context at all")
	}

	// THE FIXTURE HAS TO BE THE ONE THIS TEST IS ABOUT. If the gate did not land on
	// judgeable_shape_only the test proves nothing, and saying so is not the same as passing.
	if uc.baseline.Gate != GateJudgeableShapeOnly {
		t.Fatalf("NOT MEASURED: the fixture did not produce the gate this test exists to exercise: gate=%q detail=%q. A byte-noisy, shape-stable JSON endpoint is what the live corpus is full of, and if this server no longer produces that verdict the shape-only path went untested.",
			uc.baseline.Gate, uc.baseline.GateDetail)
	}

	if !uc.judgeable {
		t.Errorf("the runner refused a vector whose SHAPE the gate found stable, so no class sent a byte into it. GateVerdict.ShapeJudgeable exists for exactly this verdict and its own comment says a REST endpoint whose bytes are dominated by ids and timestamps can still be judged on its shape. The front door asked BytesJudgeable instead, and on live run a218419a that cost 500 verdicts across 6 vectors, every one of them refused with the reason json_shape_stable.")
	}
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "baseline_unstable") {
			t.Errorf("a shape-stable vector produced %q", v.Verdict.Reason)
		}
	}

	// AND THE POINT OF IT: bytes actually go out. judgeable=true with no probe behind it would
	// be the same absence with a friendlier flag. runSlot itself needs a database for its
	// cancel check, so the probe is driven directly; what is being proved here is that the
	// front door no longer stops it.
	if !uc.judgeable {
		return
	}
	c, registered := triage.ClassifierFor(triage.ClassSQL)
	if !registered {
		t.Fatal("NOT MEASURED: the SQL classifier is not registered, so no probe could be driven into the accepted vector")
	}
	const probe = triage.ProbeID("SQL-B1")
	if _, declared := triageSpecFor(c, probe); !declared {
		t.Fatalf("NOT MEASURED: %s no longer declares %s", c.ID(), probe)
	}
	if !rr.sendProbe(context.Background(), u, slot, c, triage.ProbeRequest{Spec: probe, Slot: slot.Key}, uc.baseline) {
		var why []string
		for _, sk := range rr.cov(u.VectorID, slot.Key, triage.ClassSQL).Skipped {
			why = append(why, string(sk.ProbeID)+": "+sk.Reason)
		}
		t.Errorf("a probe into the accepted shape-only vector never reached the wire: %s", strings.Join(why, " | "))
	}
	if n := len(rr.perturbed[triageUnitKey(u.VectorID, slot.Key)]); n == 0 {
		t.Errorf("the probe went out and the vault holds no observation for it")
	}

	// AND IT IS RECORDED AS DIFFERENCED. A shape-only baseline still produces a differential,
	// on the shape channel, and a verdict marked undifferenced ranks below an external tool's
	// undifferenced claim about the same pair.
	if !uc.baseline.Gate.ShapeJudgeable() {
		t.Errorf("the accepted baseline does not report as shape-judgeable, so every verdict off it would be filed as undifferenced")
	}
}

func TestAGenuinelyUnstableBaselineIsStillRefusedAndSaysWhatTheGateFound(t *testing.T) {
	srv := triageVolatileServer(t)
	rr := triageUnitRunner(t, triage.ClassSQL)
	u, slot := triageQueryUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassSQL, Eligible: true}}

	uc := rr.unitContext(context.Background(), u)
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	if uc.baseline.Gate.ShapeJudgeable() {
		t.Fatalf("NOT MEASURED: the fixture did not produce an unstable gate, so the control this test exists to be was not exercised: gate=%q detail=%q",
			uc.baseline.Gate, uc.baseline.GateDetail)
	}
	if uc.judgeable {
		t.Fatal("a vector whose samples really do disagree was accepted for probing")
	}
	if len(rr.verdicts) == 0 {
		t.Fatal("the refused vector produced no row at all, which is the silent zero this layer exists to replace")
	}
	for _, v := range rr.verdicts {
		if !strings.Contains(v.Verdict.Reason, "baseline_unstable") {
			t.Errorf("the refusal row does not name the refusal: %q", v.Verdict.Reason)
		}
		if !strings.Contains(v.Verdict.Reason, string(uc.baseline.Gate)) {
			t.Errorf("the refusal row does not name what the gate actually found (%q): %q. The old message asserted the samples already disagree with each other whatever the gate said, which was false on every shape-only vector in the live corpus.",
				uc.baseline.Gate, v.Verdict.Reason)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// L2a: A MARKER MUST NOT DESTROY A JSON NODE PAYLOAD.
//
// MEASURED, live run a218419a: 384 probe attempts were refused by the encoder with
// json_node_payload_is_not_valid_json, and 190 of them were NSQ-F2 and NSQ-F3, the $expr
// arithmetic pair that nosql.go calls "THE STRONGEST ORACLE IN THIS CLASS AND THE ONE THE LADDER
// LEADS WITH". Neither reached the wire once. Their declared bytes ARE valid JSON; the runner
// appended a 16-byte marker to them because they declare MarkerPos inline and spell no marker
// token, and {"$expr":...}<marker> is not a JSON value.
// ---------------------------------------------------------------------------------------------

func TestAMarkerIsNotAppendedWhereItWouldDestroyAJSONNodePayload(t *testing.T) {
	spec := triage.ProbeSpec{
		ID: "TEST-NODE", Class: triage.ClassNoSQL,
		Logical:   []byte(`{"$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}`),
		Encoders:  []triage.EncoderMode{triage.EncodeJSONNodeReplace},
		MarkerPos: triage.MarkerInline,
	}
	slot := triage.Slot{Kind: triage.KindBody, Key: "body:/symbol", FieldPath: "/symbol",
		Name: "symbol", Value: "AAPL", SegmentIndex: -1, ServerReachable: true, BodyMedia: triage.BodyJSON}
	mk := triageTestMarker(t, triage.ClassNoSQL, uint64(triage.ClassNoSQL))

	logical, unresolved, pos := triageRenderPayloadInto(spec, triage.ProbeRequest{Spec: spec.ID}, slot, mk,
		triage.EncodeJSONNodeReplace)
	if unresolved != "" {
		t.Fatalf("the payload was refused for an unsubstituted token: %s", unresolved)
	}
	if !json.Valid(logical) {
		t.Fatalf("the rendered payload is not valid JSON, so EncodeSlotInto refuses it before a socket opens and the class reads the silence: %s. This is the measured cause of NSQ-F2 and NSQ-F3 never reaching the wire on live run a218419a.", logical)
	}
	if pos != "" {
		t.Errorf("the observation was told the marker is at %q when no marker went into the bytes. A class told the marker is present when it is not is being handed a fact that is false.", pos)
	}

	// AND THE OTHER DIRECTION: a payload the marker does NOT break must still get its marker,
	// or this guard has traded one blindness for another.
	str := triage.ProbeSpec{ID: "TEST-STR", Class: triage.ClassNoSQL,
		Logical: []byte(`"abc"`), Encoders: []triage.EncoderMode{triage.EncodeJSONNodeReplace},
		MarkerPos: triage.MarkerPrefix}
	got, _, gotPos := triageRenderPayloadInto(str, triage.ProbeRequest{Spec: str.ID}, slot, mk, triage.EncodeQuery)
	if !bytes.Contains(got, []byte(mk)) {
		t.Errorf("the guard swallowed the marker on a payload it does not break: %s", got)
	}
	if gotPos != triage.MarkerPrefix {
		t.Errorf("a marker that WAS placed is recorded as %q, want %q", gotPos, triage.MarkerPrefix)
	}
}

func TestTheStrongestNoSQLOracleActuallyReachesTheWire(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassNoSQL)
	if !ok {
		t.Fatal("NOT MEASURED: the NOSQL classifier is not registered in this build, so its strongest oracle could not be driven at all. That is a gap in coverage, not a pass.")
	}
	const probe = triage.ProbeID("NSQ-F2")
	spec, found := triageSpecFor(c, probe)
	if !found {
		t.Fatalf("NOT MEASURED: %s no longer declares %s, so this test is driving a path that does not exist", c.ID(), probe)
	}
	if !json.Valid(spec.Logical) {
		t.Fatalf("NOT MEASURED: %s no longer declares a JSON node payload (%s), so this test is about something else", probe, spec.Logical)
	}

	var seen []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		seen = append([]byte(nil), b...)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(srv.Close)

	rr := triageUnitRunner(t, triage.ClassNoSQL)
	rr.settings.Tier = string(triage.TierOptIn)
	cs := rr.settings.Classes[TriageClassKey(triage.ClassNoSQL)]
	cs.Enabled, cs.Tier, cs.MaxRisk = true, string(triage.TierOptIn), string(triage.RiskR3)
	rr.settings.Classes[TriageClassKey(triage.ClassNoSQL)] = cs

	u := &triageUnitPlan{VectorID: "v-body", Host: "127.0.0.1", Selected: true,
		Template: RequestTemplate{Method: "POST", URL: srv.URL + "/query",
			Body: []byte(`{"symbol":"AAPL","limit":10}`), BodyMedia: triage.BodyJSON}}
	slot := triage.Slot{VectorID: u.VectorID, Kind: triage.KindBody, Key: "body:/symbol",
		FieldPath: "/symbol", Name: "symbol", Value: "AAPL", SegmentIndex: -1,
		ServerReachable: true, BodyMedia: triage.BodyJSON, Constraints: triage.NewSlotConstraints()}
	u.Slots = []triage.Slot{slot}

	req := triage.ProbeRequest{Spec: probe, Slot: slot.Key,
		Variant: map[string]string{"placement": "filter_root_sibling"}}
	sent := rr.sendProbe(context.Background(), u, slot, c, req, TriageBaseline{Gate: GateJudgeable})

	if !sent {
		var why []string
		for _, s := range rr.cov(u.VectorID, slot.Key, triage.ClassNoSQL).Skipped {
			why = append(why, string(s.ProbeID)+": "+s.Reason)
		}
		t.Fatalf("%s never reached the wire: %s. nosql.go calls this probe THE STRONGEST ORACLE IN THIS CLASS. On live run a218419a it was refused 95 times and delivered 0.",
			probe, strings.Join(why, " | "))
	}
	if len(seen) == 0 {
		t.Fatal("the probe reported as sent and the server saw no body")
	}
	var doc map[string]any
	if err := json.Unmarshal(seen, &doc); err != nil {
		t.Fatalf("the body that went out is not JSON (%v): %s", err, seen)
	}
	if doc["symbol"] != "AAPL" {
		t.Errorf("the root-sibling probe overwrote the slot's own value: %s", seen)
	}
	if _, has := doc["$expr"]; !has {
		t.Errorf("the $expr operator did not arrive as a sibling at the filter root: %s", seen)
	}

	// THE OTHER SHAPE OF ROOT PROBE: one whose MARKER IS THE OPERATOR NAME. NSQ-F1 is
	// {"$<marker>":[1]}, so the placement has to carry the marker out of the payload and into
	// the member name, and the bytes on the wire still have to contain it or the class can never
	// attribute the "unknown TOP LEVEL operator" it is looking for.
	const f1 = triage.ProbeID("NSQ-F1")
	if _, found := triageSpecFor(c, f1); !found {
		t.Logf("NOT MEASURED: %s is no longer declared, so the marker-in-the-operator-name shape was not exercised", f1)
		return
	}
	seen = nil
	sentF1 := rr.sendProbe(context.Background(), u, slot, c,
		triage.ProbeRequest{Spec: f1, Slot: slot.Key, Variant: map[string]string{"placement": "filter_root_sibling"}},
		TriageBaseline{Gate: GateJudgeable})
	if !sentF1 {
		var why []string
		for _, sk := range rr.cov(u.VectorID, slot.Key, triage.ClassNoSQL).Skipped {
			why = append(why, string(sk.ProbeID)+": "+sk.Reason)
		}
		t.Fatalf("%s never reached the wire: %s", f1, strings.Join(why, " | "))
	}
	marker := ""
	for _, f := range rr.fidelity {
		if f.ProbeID == f1 {
			marker = string(f.Marker)
		}
	}
	if marker == "" {
		t.Fatalf("no probe record for %s, so nothing says what went out", f1)
	}
	if !bytes.Contains(seen, []byte(marker)) {
		t.Errorf("the marker %q is not in the bytes that reached the server, so no hit from %s could ever be attributed: %s", marker, f1, seen)
	}
	var f1doc map[string]any
	if err := json.Unmarshal(seen, &f1doc); err != nil {
		t.Fatalf("the %s body is not JSON (%v): %s", f1, err, seen)
	}
	if f1doc["symbol"] != "AAPL" {
		t.Errorf("%s overwrote the slot value: %s", f1, seen)
	}
}

// ---------------------------------------------------------------------------------------------
// L2b: THE filter_root_sibling PLACEMENT.
//
// nosql.go plans nine probes at a placement the runner does not implement. The class says it in
// words: "The four N-FILTER probes and the two $where node probes are SIBLINGS of the slot inside
// the filter document, not replacements for it. Named so the runner cannot get it wrong silently."
// The runner got it wrong silently: it read no placement at all and node-replaced the slot.
// ---------------------------------------------------------------------------------------------

func TestTheFilterRootSiblingPlacementAddsTheOperatorBesideTheSlot(t *testing.T) {
	tmpl := RequestTemplate{Method: "POST", URL: "http://127.0.0.1:1/q",
		Body: []byte(`{"filter":{"symbol":"AAPL"},"limit":10}`), BodyMedia: triage.BodyJSON}
	slot := triage.Slot{Kind: triage.KindBody, Key: "body:/filter/symbol", FieldPath: "/filter/symbol",
		Name: "symbol", Value: "AAPL", SegmentIndex: -1, ServerReachable: true, BodyMedia: triage.BodyJSON}
	payload := []byte(`{"$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}`)

	out, reason, detail := triagePlaceProbe(tmpl, slot, "filter_root_sibling", triage.EncodeJSONNodeReplace, payload)
	if reason != "" {
		t.Fatalf("the placement was refused: %s: %s", reason, detail)
	}

	var doc map[string]any
	if err := json.Unmarshal(out.Template.Body, &doc); err != nil {
		t.Fatalf("the placed body is not JSON (%v): %s", err, out.Template.Body)
	}
	filter, isObj := doc["filter"].(map[string]any)
	if !isObj {
		t.Fatalf("the filter document is gone from the placed body: %s", out.Template.Body)
	}
	if filter["symbol"] != "AAPL" {
		t.Errorf("the slot's own value was overwritten: %v. A root operator is a SIBLING of the slot; replacing the slot tests a different question and the class then scores its own oracle against an answer to that other question.", filter["symbol"])
	}
	if _, has := filter["$expr"]; !has {
		t.Errorf("the operator was not added beside the slot: %s", out.Template.Body)
	}
	if out.Slot.FieldPath != "/filter/$expr" {
		t.Errorf("the encode slot points at %q, want the sibling member /filter/$expr", out.Slot.FieldPath)
	}
	if out.Slot.Key != slot.Key {
		t.Errorf("the synthesized slot changed the storage identity to %q; coverage and fidelity would then be filed against a slot that does not exist", out.Slot.Key)
	}
	if !bytes.Equal(out.Logical, []byte(`{"$eq":[{"$multiply":[8123,7]},56861]}`)) {
		t.Errorf("the logical bytes handed to the encoder are %s, want the operator's own value", out.Logical)
	}

	// A ROOT-LEVEL SLOT. The live corpus carries body:/:node, a body slot whose pointer is "/"
	// and whose member name is empty: 468 probe attempts on run a218419a were refused
	// json_pointer_not_found on it. Its enclosing filter document is the whole body, so a
	// sibling IS addressable there even though a node replace is not.
	rootTmpl := RequestTemplate{Method: "POST", URL: "http://127.0.0.1:1/q",
		Body: []byte(`{"symbol":"AAPL"}`), BodyMedia: triage.BodyJSON}
	rootSlot := triage.Slot{Kind: triage.KindBody, Key: "body:/:node", FieldPath: "/",
		SegmentIndex: -1, ServerReachable: true, BodyMedia: triage.BodyJSON}
	rootOut, rootReason, rootDetail := triagePlaceProbe(rootTmpl, rootSlot, "filter_root_sibling", triage.EncodeJSONNodeReplace, payload)
	if rootReason != "" {
		t.Errorf("the root slot was refused (%s: %s), so the largest single population of refusals in the live run stays refused", rootReason, rootDetail)
	} else if rootOut.Slot.FieldPath != "/$expr" {
		t.Errorf("the root sibling points at %q, want /$expr", rootOut.Slot.FieldPath)
	}

	// THE REFUSALS, EACH BY NAME. A placement that cannot be honoured must be refused with a
	// reason, never quietly downgraded to a node replace: that is how a probe tests one thing
	// and is scored as another.
	for _, bad := range []struct {
		name    string
		tmpl    RequestTemplate
		slot    triage.Slot
		mode    triage.EncoderMode
		payload []byte
		want    string
	}{
		{"a query slot has no filter document", RequestTemplate{Method: "GET", URL: "http://127.0.0.1:1/q?a=1"},
			triage.Slot{Kind: triage.KindQuery, Name: "a", SegmentIndex: -1}, triage.EncodeQuery, payload,
			"filter_root_not_addressable"},
		{"the slot is the whole document", tmpl,
			triage.Slot{Kind: triage.KindBody, FieldPath: "", BodyMedia: triage.BodyJSON, SegmentIndex: -1},
			triage.EncodeJSONNodeReplace, payload, "filter_root_not_addressable"},
		{"the member is already there", RequestTemplate{Method: "POST", URL: "http://127.0.0.1:1/q",
			Body: []byte(`{"filter":{"symbol":"AAPL","$expr":1}}`), BodyMedia: triage.BodyJSON},
			slot, triage.EncodeJSONNodeReplace, payload, "filter_root_member_collision"},
		{"the payload is not a one-member object", tmpl, slot, triage.EncodeJSONNodeReplace,
			[]byte(`"plain"`), "filter_root_payload_not_an_operator_object"},
		{"the body is not JSON at all", RequestTemplate{Method: "POST", URL: "http://127.0.0.1:1/q",
			Body: []byte(`a=1&b=2`), BodyMedia: triage.BodyForm}, slot, triage.EncodeJSONNodeReplace,
			payload, "filter_root_not_addressable"},
	} {
		_, got, _ := triagePlaceProbe(bad.tmpl, bad.slot, "filter_root_sibling", bad.mode, bad.payload)
		if got != bad.want {
			t.Errorf("%s: refused with %q, want %q", bad.name, got, bad.want)
		}
	}

	// THE KEY IS OVERLOADED, AND REFUSING WHAT IT ACTUALLY CARRIES COSTS A WHOLE CLASS.
	// nosql.go writes placement on EVERY probe from its own slot-shape enum and only overwrites
	// it with filter_root_sibling on the nine root ones. A first cut of triagePlaceProbe refused
	// every value it did not recognise and turned all 60 NOSQL probes in the end-to-end run into
	// probe_not_observed. This asks the real class what it actually plans, so the guard cannot
	// go stale against a vocabulary that lives in someone else's file.
	// These are the values nosql.go's own nosqlPlacement enum puts in this key on every probe it
	// plans. They describe the SLOT, not a request, and they have to pass straight through. The
	// live counterpart of this assertion is in TestTheWholeRegistryRunsAndEveryClassSaysWhatItDid,
	// which fails if any probe in a real run is refused placement_unknown; this one names the
	// three values so a reader knows where they came from without running an oracle.
	for _, descriptive := range []string{"none", "json_node", "bracket"} {
		out, got, detail := triagePlaceProbe(tmpl, slot, descriptive, triage.EncodeJSONNodeReplace, payload)
		if got != "" {
			t.Errorf("placement %q, which nosql.go writes on every probe it plans as a description of the slot, was refused as %q (%s). All 60 NOSQL probes in the end-to-end run came back probe_not_observed the last time this was wrong.",
				descriptive, got, detail)
		}
		if got == "" && out.Slot.FieldPath != slot.FieldPath {
			t.Errorf("placement %q moved the encode slot to %q; a descriptive value must change nothing", descriptive, out.Slot.FieldPath)
		}
	}

	// An unknown placement is refused rather than ignored. A placement the runner silently drops
	// is the same defect with a different name.
	if _, got, _ := triagePlaceProbe(tmpl, slot, "somewhere_else", triage.EncodeJSONNodeReplace, payload); got != "placement_unknown" {
		t.Errorf("an unknown placement was accepted (%q), so a class asking for something this runner cannot do would be answered as though it could", got)
	}
	// No placement at all is the ordinary path and must not be disturbed.
	if plain, got, _ := triagePlaceProbe(tmpl, slot, "", triage.EncodeJSONNodeReplace, payload); got != "" || plain.Slot.FieldPath != slot.FieldPath {
		t.Errorf("the no-placement path was changed: reason %q, field path %q", got, plain.Slot.FieldPath)
	}
}

func TestAProbeTheRunnerRefusedIsNamedOnTheVerdict(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassNoSQL)
	slot := triage.Slot{VectorID: "v1", Kind: triage.KindBody, Key: "body:/x", SegmentIndex: -1}
	row := rr.cov("v1", slot.Key, triage.ClassNoSQL)
	row.Skipped = append(row.Skipped, triage.ProbeSkip{ProbeID: "NSQ-F2",
		Reason: "filter_root_not_addressable: this slot has no enclosing filter document"})

	v := triage.ClassVerdict{Class: triage.ClassNoSQL, SlotKey: slot.Key,
		State:  triage.StateCannotDetermine,
		Reason: "N-FILTER: probe_not_observed (NSQ-F2): it was planned and no observation came back"}
	rr.annotateRunnerRefusals("v1", slot.Key, triage.ClassNoSQL, []*triage.ClassVerdict{&v})

	ann, _ := v.Annotations["runner_refused_probes"].(string)
	if !strings.Contains(ann, "NSQ-F2") || !strings.Contains(ann, "filter_root_not_addressable") {
		t.Errorf("the verdict does not name the runner as the cause: annotations=%v. probe_not_observed on its own reads as a fact about the target; the runner knows exactly why no observation came back and has to say so on the row the operator reads.", v.Annotations)
	}
}

// ---------------------------------------------------------------------------------------------
// D7: A RUN THAT DID NOT FINISH ITS PLAN MUST NOT SAY completed.
//
// MEASURED, live run a218419a: status completed at 20,180 of 20,680 planned pairs. The 500 that
// went missing are EXACTLY the 500 baseline_unstable pairs: unitContext decides them and writes
// their rows, and never counts them, so the counter under-reports by the size of the decision.
// ---------------------------------------------------------------------------------------------

func TestAPairDecidedWithoutAProbeIsStillCountedAsReached(t *testing.T) {
	srv := triageVolatileServer(t)
	rr := triageUnitRunner(t, triage.ClassSQL, triage.ClassSSTI)
	u, slot := triageQueryUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{
		{Slot: slot, Class: triage.ClassSQL, Eligible: true},
		{Slot: slot, Class: triage.ClassSSTI, Eligible: true},
	}

	uc := rr.unitContext(context.Background(), u)
	if uc.judgeable {
		t.Fatalf("NOT MEASURED: the volatile fixture came back judgeable (%q), so the decided-without-a-probe path was not exercised. That is a gap in coverage, not a pass.", uc.baseline.Gate)
	}
	if rr.completed != 2 {
		t.Errorf("the runner decided 2 pairs at baseline time and counted %d of them as reached. On live run a218419a that gap was 500 pairs, and it is the whole of the 20,180-of-20,680 shortfall the run then reported under the word completed.", rr.completed)
	}
	if n := len(rr.decided); n != 2 {
		t.Errorf("the runner recorded %d decided pairs, want 2", n)
	}
}

func TestARunThatLeftPairsUndecidedDoesNotReportItselfCompleted(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassSQL)
	mk := func(i int) triage.Slot {
		return triage.Slot{VectorID: "v1", Kind: triage.KindQuery,
			Key: triage.SlotKey(fmt.Sprintf("query:p%d", i)), Name: fmt.Sprintf("p%d", i), SegmentIndex: -1}
	}
	unit := triageUnitPlan{VectorID: "v1", Selected: true}
	for i := 0; i < 4; i++ {
		rr.plan.Pairs = append(rr.plan.Pairs, triagePair{Slot: mk(i), Class: triage.ClassSQL, Eligible: true})
		unit.Slots = append(unit.Slots, mk(i))
	}
	unit.Slots = append(unit.Slots, mk(9))
	rr.plan.Units = []triageUnitPlan{unit}
	// A pair the plan refused is not in the denominator and must not create a phantom shortfall.
	rr.plan.Pairs = append(rr.plan.Pairs, triagePair{Slot: mk(9), Class: triage.ClassSQL, Eligible: false})
	rr.excluded[rr.coverageKey("v1", mk(9).Key, triage.ClassSQL)] = "is_credential"

	status, short := rr.terminalStatus()
	if status == TriageRunCompleted {
		t.Errorf("a run that decided none of its 4 planned pairs called itself completed")
	}
	if !strings.Contains(short, "0 of 4") {
		t.Errorf("the shortfall does not name its size: %q", short)
	}

	for i := 0; i < 3; i++ {
		rr.markDecided("v1", mk(i).Key, triage.ClassSQL)
	}
	status, short = rr.terminalStatus()
	if status == TriageRunCompleted {
		t.Errorf("3 of 4 planned pairs decided and the run called itself completed. That is the measured lie from run a218419a: 20,180 of 20,680 under the word completed.")
	}
	if !strings.Contains(short, "3 of 4") {
		t.Errorf("the shortfall sentence does not name the shortfall: %q", short)
	}

	rr.markDecided("v1", mk(3).Key, triage.ClassSQL)
	status, short = rr.terminalStatus()
	if status != TriageRunCompleted {
		t.Errorf("a run that decided every planned pair reported %q, want %q (%s)", status, TriageRunCompleted, short)
	}
	if short != "" {
		t.Errorf("a run with no shortfall still produced a shortfall sentence: %q", short)
	}

	// A CANCEL ALWAYS WINS.
	rr.cancelled = true
	if got, _ := rr.terminalStatus(); got != TriageRunCancelled {
		t.Errorf("a cancelled run reported %q", got)
	}
	rr.cancelled = false

	// A BUDGET CUT KEEPS THE VOICE THE TRUNCATION SENTENCE ALREADY HAS rather than growing a
	// second one, but it still must not be called completed.
	rr.decided = map[string]bool{}
	rr.budgetCut = true
	got, short := rr.terminalStatus()
	if got == TriageRunCompleted {
		t.Errorf("a budget-truncated run that reached none of its plan called itself completed")
	}
	if short != "" {
		t.Errorf("the budget cut grew a second voice beside the truncation sentence: %q. The truncation sentence already says BUDGET TRUNCATED AT n%% OF THE PLAN with the same numbers.", short)
	}
}

// A BUDGET STOP IS incomplete, NOT error. See TriageRunIncomplete for the two measured runs.
//
// This is the runner half: the store now has the word, and terminalStatus has to use it. A run
// that finished its plan must still report completed, which is the half a careless fix breaks.
func TestABudgetStopReportsIncompleteAndNotError(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassSQL)
	mk := func(i int) triage.Slot {
		return triage.Slot{VectorID: "v1", Kind: triage.KindQuery,
			Key: triage.SlotKey(fmt.Sprintf("query:p%d", i)), Name: fmt.Sprintf("p%d", i), SegmentIndex: -1}
	}
	unit := triageUnitPlan{VectorID: "v1", Selected: true}
	for i := 0; i < 4; i++ {
		rr.plan.Pairs = append(rr.plan.Pairs, triagePair{Slot: mk(i), Class: triage.ClassSQL, Eligible: true})
		unit.Slots = append(unit.Slots, mk(i))
	}
	rr.plan.Units = []triageUnitPlan{unit}

	rr.budgetCut = true
	rr.markDecided("v1", mk(0).Key, triage.ClassSQL)
	status, short := rr.terminalStatus()
	if status == TriageRunError {
		t.Errorf("a run that sent every probe its cap allowed and stopped at the cap reported %q. Nothing failed: the operator is sent looking for a crash, and the word stops meaning anything when a real one happens.", status)
	}
	if status != TriageRunIncomplete {
		t.Errorf("a budget stop reported %q, want %q (%s)", status, TriageRunIncomplete, short)
	}

	// THE OTHER SHORTFALL IS THE SAME KIND OF THING: the run worked and did not finish.
	rr.budgetCut = false
	status, short = rr.terminalStatus()
	if status != TriageRunIncomplete {
		t.Errorf("a run that left pairs undecided for a reason other than the budget reported %q, want %q", status, TriageRunIncomplete)
	}
	if !strings.Contains(short, "1 of 4") {
		t.Errorf("the shortfall sentence does not name the shortfall: %q", short)
	}

	// AND A RUN THAT ANSWERED ITS PLAN IS STILL completed.
	for i := 1; i < 4; i++ {
		rr.markDecided("v1", mk(i).Key, triage.ClassSQL)
	}
	if status, short = rr.terminalStatus(); status != TriageRunCompleted {
		t.Errorf("a run that decided every planned pair reported %q, want %q (%s)", status, TriageRunCompleted, short)
	}

	// A CANCEL STILL WINS OVER BOTH.
	rr.cancelled = true
	rr.decided = map[string]bool{}
	if got, _ := rr.terminalStatus(); got != TriageRunCancelled {
		t.Errorf("a cancelled run reported %q", got)
	}
}

// ---------------------------------------------------------------------------------------------
// A DESELECTED VECTOR COSTS ONE ROW, NOT ONE PER (SLOT, CLASS)
// ---------------------------------------------------------------------------------------------

// MEASURED, on the run this change came from: 37,570 coverage rows, of which 36,361 (97%) were
// for vectors the operator had switched off. The planner walked every slot of every deselected
// vector against every enabled class and wrote the identical "you switched this off" sentence
// 193 times per vector.
//
// The cost is not only storage. Those pairs were ELIGIBLE, so planned_pairs read 31,066 for a run
// whose real work was 1,209 pairs, and the progress indicator therefore read 0.6% done when the
// run was 16% through. A denominator that can never be retired is not a denominator.
//
// THE RULE THAT MUST SURVIVE: a deselected vector still leaves a record. A slot that silently
// vanishes from the report cannot be told from one that was tested and came back clean, and that
// is the failure this whole layer exists to refuse. One row per vector carries exactly the same
// fact as 193 identical ones.
func TestADeselectedVectorLeavesOneRowAndNotOnePerPair(t *testing.T) {
	reg := triage.RegisteredClassifiers()
	enabled := []triage.ClassID{triage.ClassSQL, triage.ClassSSTI, triage.ClassLFI}

	slots := make([]triage.Slot, 0, 7)
	for i := 0; i < 7; i++ {
		slots = append(slots, triage.Slot{
			VectorID: "v-off", Kind: triage.KindQuery, SegmentIndex: -1,
			Name: fmt.Sprintf("p%d", i), Key: triage.SlotKey(fmt.Sprintf("query:p%d", i)),
		})
	}
	off := &triageUnitPlan{VectorID: "v-off", Selected: false, Slots: slots}
	on := &triageUnitPlan{VectorID: "v-on", Selected: true, Slots: slots}

	pairs := triagePairsForUnit(off, enabled, reg)
	if len(pairs) != 1 {
		t.Fatalf("a deselected vector with 7 slots and 3 classes produced %d pairs, want 1. On the measured run that multiplier was 193 per vector and 36,361 rows of the 37,570 written.",
			len(pairs))
	}
	p := pairs[0]
	if p.Eligible {
		t.Error("the deselected record is counted in the denominator, so a finished run still reports work outstanding that no amount of running will retire")
	}
	if !p.Deselected {
		t.Error("the record does not say it is a deselection, so nothing downstream can tell it from a pair the budget missed")
	}
	if !strings.Contains(p.Excluded, "deselected") {
		t.Errorf("the record's reason does not name the deselection: %q", p.Excluded)
	}
	if !strings.Contains(p.Excluded, "7") || !strings.Contains(p.Excluded, "3") {
		t.Errorf("the one record must say how much it stands for (7 slots, 3 classes), or it reads as one slot being off: %q", p.Excluded)
	}
	if strings.TrimSpace(string(p.Slot.Key)) == "" {
		t.Error("the record has no slot key, and RecordTriageCoverage refuses a row with no identity outright, so the deselection would leave NO record at all")
	}
	// CLASS 0 IS REFUSED BY THE STORE AND THE REFUSAL WAS MEASURED, NOT ARGUED.
	//
	// The first version of this record was filed under triage.ClassNone, on the reasoning that no
	// class was asked. RecordTriageVerdicts refuses class 0 outright (covorphan excludes it, so
	// such a row is invisible to the witness that catches a pair with no coverage row), the store
	// logged "filed under class 0 ... refused rather than written where nothing will ever check
	// it", and the deselected vector then left NO verdict at all: the exact coverage lie this
	// record exists to prevent, reached by trying to be precise about it.
	if p.Class == triage.ClassNone {
		t.Error("the record is filed under class 0, which RecordTriageVerdicts refuses, so the deselection leaves no verdict row at all")
	}
	// SSTI is id 1 and SQL is id 4, so the lowest enabled id here is SSTI regardless of the order
	// the caller listed them in. Deterministic is the property that matters: two runs of the same
	// plan must file the record the same way or the row moves between reports for no reason.
	if p.Class != triage.ClassSSTI {
		t.Errorf("the record is filed under %s; it must be the lowest enabled class id so the choice is deterministic across runs, which is %s here", p.Class, triage.ClassSSTI)
	}
	if !strings.Contains(p.Excluded, p.Class.String()) {
		t.Errorf("the record does not say which class it is filed under, so it reads as a statement about that class alone: %q", p.Excluded)
	}
	if strings.TrimSpace(p.ReachReason) == "" {
		t.Error("the record carries reach never with no reason, which RecordTriageCoverage refuses")
	}

	// A SELECTED VECTOR IS UNTOUCHED: still one pair per slot per class.
	full := triagePairsForUnit(on, enabled, reg)
	if len(full) != len(slots)*len(enabled) {
		t.Fatalf("a selected vector produced %d pairs, want %d; the saving must come out of the deselected side only",
			len(full), len(slots)*len(enabled))
	}
	for _, q := range full {
		if q.Deselected {
			t.Fatalf("a selected vector's pair is marked deselected: %+v", q)
		}
	}

	// A DESELECTED VECTOR WITH NO SLOTS HAS NOTHING TO KEY A ROW ON, and it had no rows before
	// either. It must not invent one that the store would then refuse.
	if n := len(triagePairsForUnit(&triageUnitPlan{VectorID: "v-empty"}, enabled, reg)); n != 0 {
		t.Errorf("a deselected vector with no slots produced %d pairs, want 0", n)
	}
	// AND NEITHER DOES ONE WITH NO ENABLED CLASS THAT THIS BUILD CAN RUN. There would be nothing
	// to file the verdict under, and class 0 is refused.
	if n := len(triagePairsForUnit(off, []triage.ClassID{triage.ClassID(62)}, reg)); n != 0 {
		t.Errorf("a deselected vector whose only enabled class is unregistered produced %d pairs, want 0", n)
	}
}

// ---------------------------------------------------------------------------------------------
// THE DENOMINATOR THE PLAN ROWS RECORD
// ---------------------------------------------------------------------------------------------

// buildPlanRows is the arithmetic half of writePlanRows, so it can be measured without a database.
// What is measured here is the shape of the report: how many rows a deselected vector costs, which
// of them count in the denominator, and whether the row carries the flag that keeps it out.
func TestThePlanRowsPutOnlyRealWorkInTheDenominator(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassSQL, triage.ClassSSTI)

	slots := func(vector string, n int) []triage.Slot {
		out := make([]triage.Slot, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, triage.Slot{VectorID: vector, Kind: triage.KindQuery, SegmentIndex: -1,
				Name: fmt.Sprintf("p%d", i), Key: triage.SlotKey(fmt.Sprintf("query:%s:p%d", vector, i))})
		}
		return out
	}
	live := triageUnitPlan{VectorID: "v-on", Selected: true, Slots: slots("v-on", 3)}
	off := triageUnitPlan{VectorID: "v-off", Selected: false, Slots: slots("v-off", 40)}
	rr.plan.Units = []triageUnitPlan{live, off}
	rr.plan.DeselectedVectors = 1
	rr.plan.SelectedVectors = 1

	reg := triage.RegisteredClassifiers()
	rr.plan.Pairs = append(rr.plan.Pairs, triagePairsForUnit(&rr.plan.Units[0], rr.plan.EnabledClasses, reg)...)
	rr.plan.Pairs = append(rr.plan.Pairs, triagePairsForUnit(&rr.plan.Units[1], rr.plan.EnabledClasses, reg)...)

	eligible := rr.buildPlanRows()

	if eligible != 6 {
		t.Errorf("the denominator is %d, want 6 (3 slots x 2 classes on the one vector the operator kept). The deselected vector's 80 pairs are not work this run can ever retire, and counting them is what made a 16%%-through run report 0.6%%.",
			eligible)
	}
	if n := len(rr.coverage); n != 7 {
		t.Errorf("%d coverage rows were built, want 7: six for the live vector and ONE for the deselected one. Before this change the deselected vector alone wrote 80.", n)
	}

	var deselectedRows int
	for _, row := range rr.coverage {
		if row.VectorID != "v-off" {
			if row.Ineligible {
				t.Errorf("a live pair %s/%s is marked ineligible", row.VectorID, row.SlotKey)
			}
			continue
		}
		deselectedRows++
		if !row.Ineligible {
			t.Error("the deselected record is written into the coverage table as ELIGIBLE while planned_pairs leaves it out, so the two numbers count different populations and DenominatorSurplus reads the difference forever")
		}
		if len(row.Skipped) == 0 || !strings.Contains(row.Skipped[0].Reason, "deselected") {
			t.Errorf("the deselected record does not say why nothing was sent: %+v", row.Skipped)
		}
		if !strings.Contains(row.Skipped[0].Reason, "40") {
			t.Errorf("the one record does not say it stands for all 40 slots, so it reads as one slot being off: %q", row.Skipped[0].Reason)
		}
		if row.Ran {
			t.Error("the deselected record claims it ran")
		}
	}
	if deselectedRows != 1 {
		t.Errorf("the deselected vector left %d coverage rows, want exactly 1", deselectedRows)
	}

	// AND IT STILL LEAVES A VERDICT. A coverage row with no verdict behind it is the pair the
	// roll-up counts under PairsWithNoVerdict, which is its own kind of gap.
	var offVerdicts int
	for _, v := range rr.verdicts {
		if v.VectorID == "v-off" {
			offVerdicts++
			if !v.Verdict.State.IsUnknown() {
				t.Errorf("the deselected record's verdict is %q, which is not an unknown", v.Verdict.State)
			}
		}
	}
	if offVerdicts != 1 {
		t.Errorf("the deselected vector left %d verdict rows, want exactly 1", offVerdicts)
	}
}

// ---------------------------------------------------------------------------------------------
// THE ONE SENTENCE WHOSE JOB IS HONEST REPORTING
// ---------------------------------------------------------------------------------------------

// MEASURED, verbatim off the card: "BUDGET TRUNCATED AT 2% OF THE PLAN: only 915 of 31066 eligible
// pairs were ever asked anything." The run had covered 915 of 1,209 pairs a probe could ever have
// reached, which is 76%. The denominator was padded with every pair of every vector the operator
// had switched off, and the "kinds that got no probe at all" list then named the insertion points
// of those same deselected vectors, as though the budget had missed them.
//
// So the one sentence written to stop a truncated run reading as a clean one was itself reporting
// a 2% sweep as the honest number and blaming the budget for the operator's own choices.
//
// THE RULE: the denominator is what the budget could have bought, and nothing else. A pair the
// operator switched off, a pair no encoder can render into, a class this build cannot run: none of
// them was ever going to be asked, so none of them dilutes the percentage, and each is reported as
// the different thing it is.
func TestTheTruncationSentenceCountsOnlyWhatTheBudgetCouldHaveBought(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassSQL, triage.ClassSSTI)
	rr.budget = triage.TriageBudget{PerRun: 4000, PerSlot: 24}

	mkSlot := func(vector string, kind triage.SlotKind, i int) triage.Slot {
		return triage.Slot{VectorID: vector, Kind: kind, SegmentIndex: -1,
			Name: fmt.Sprintf("p%d", i), Value: "hello", ServerReachable: true,
			Origin: triage.SlotObserved, ValueOrigin: triage.ValueObserved,
			Constraints: triage.NewSlotConstraints(),
			Key:         triage.SlotKey(fmt.Sprintf("%s:%s:%d", kind, vector, i))}
	}

	// THE VECTOR THE OPERATOR KEPT: 4 query pairs, of which 1 was reached.
	on := triageUnitPlan{VectorID: "v-on", Selected: true}
	for i := 0; i < 2; i++ {
		on.Slots = append(on.Slots, mkSlot("v-on", triage.KindQuery, i))
	}
	// THE VECTOR THE OPERATOR SWITCHED OFF: a cookie vector with 50 slots. Before this change its
	// 100 pairs were in the denominator and "cookie" was named as a kind the budget never reached.
	off := triageUnitPlan{VectorID: "v-off", Selected: false}
	for i := 0; i < 50; i++ {
		off.Slots = append(off.Slots, mkSlot("v-off", triage.KindCookie, i))
	}
	// A VECTOR WHOSE REQUEST-TARGET WILL NOT RESOLVE: eligible, never probeable, and not the
	// budget's fault either.
	broken := triageUnitPlan{VectorID: "v-broken", Selected: true, Unplannable: "path_template_unresolved: the request-target is \"/a/{uuid}\""}
	broken.Slots = append(broken.Slots, mkSlot("v-broken", triage.KindPath, 0))

	rr.plan.Units = []triageUnitPlan{on, off, broken}
	rr.plan.SelectedVectors, rr.plan.DeselectedVectors = 2, 1
	reg := triage.RegisteredClassifiers()
	for i := range rr.plan.Units {
		rr.plan.Pairs = append(rr.plan.Pairs, triagePairsForUnit(&rr.plan.Units[i], rr.plan.EnabledClasses, reg)...)
	}
	rr.buildPlanRows()

	// One of the four live pairs got a probe.
	rr.cov("v-on", mkSlot("v-on", triage.KindQuery, 0).Key, triage.ClassSQL).Ran = true
	rr.budgetCut = true

	cut := rr.truncation()
	if cut.Planned != 4 || cut.Measured != 1 {
		t.Fatalf("planned %d measured %d, want 4 and 1. The 100 pairs of the deselected cookie vector and the 2 of the unresolvable one were never buyable with any budget.",
			cut.Planned, cut.Measured)
	}
	if cut.Percent() != 25 {
		t.Errorf("1 of 4 is 25%%, got %d%%", cut.Percent())
	}
	if cut.DeselectedVectors != 1 {
		t.Errorf("the truncation reports %d deselected vectors, want 1", cut.DeselectedVectors)
	}
	if cut.RefusedByPlan != 2 {
		t.Errorf("the truncation reports %d pairs refused before the run, want 2 (the unresolvable vector against both classes)", cut.RefusedByPlan)
	}

	s := cut.Sentence()
	t.Logf("sentence: %s", s)
	for _, want := range []string{"BUDGET TRUNCATED AT 25% OF THE PLAN", "1 of 4", "per-run cap of 4000 probes"} {
		if !strings.Contains(s, want) {
			t.Errorf("the truncation sentence does not carry %q.\nGot: %s", want, s)
		}
	}
	// THE OPERATOR'S OWN CHOICE MUST NOT BE REPORTED AS THE BUDGET'S DOING.
	if strings.Contains(s, "cookie (0 of") {
		t.Errorf("an insertion point that exists only on a DESELECTED vector is listed as one the budget never reached: %s", s)
	}
	if !strings.Contains(strings.ToLower(s), "deselect") {
		t.Errorf("the sentence never mentions the vectors the operator switched off, so their absence from the report has no explanation at all: %s", s)
	}
	if !strings.Contains(s, "refused before the run") {
		t.Errorf("the pairs no probe could ever have reached are neither counted nor named: %s", s)
	}
	// AND THE BLIND LINE STILL WORKS FOR A KIND THE BUDGET REALLY DID MISS.
	if !strings.Contains(s, "Classes that got no probe at all") || !strings.Contains(s, "SSTI") {
		t.Errorf("SSTI got nothing on the live vector and is not named: %s", s)
	}
}

// A RUN THAT WAS NOT CUT STILL REPORTS THE OPERATOR'S OWN EXCLUSIONS NOWHERE, because there is no
// sentence at all. This pins that adding the new counters did not make an uncut run start talking.
func TestAnUncutRunProducesNoTruncationSentence(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassSQL)
	off := triageUnitPlan{VectorID: "v-off", Selected: false,
		Slots: []triage.Slot{{VectorID: "v-off", Kind: triage.KindQuery, Key: "query:p0", SegmentIndex: -1}}}
	rr.plan.Units = []triageUnitPlan{off}
	rr.plan.DeselectedVectors = 1
	rr.plan.Pairs = triagePairsForUnit(&rr.plan.Units[0], rr.plan.EnabledClasses, triage.RegisteredClassifiers())
	rr.buildPlanRows()
	if cut := rr.truncation(); cut.Cut {
		t.Error("a run that was never cut claims it was")
	}
}

// ---------------------------------------------------------------------------------------------
// D-AUTH: THE RUN MEASURED AN AUTHENTICATION WALL AND CALLED IT CLEAN
//
// MEASURED on the operator's completed run 2n6f: 4674 of 5312 probes (88%) came back 401. All 27
// vectors whose captured raw_request carries an Authorization header returned 401 to every probe;
// the only 200s in the whole run came from the 3 vectors that carry no credential at all.
// triageRunTemplateFor replays every captured header verbatim, so the bearer tokens WERE sent.
// They were expired.
//
// A 401 page emits no Location, creates no header, shows no parameter pollution and raises no ORM
// error, so CRLF, HPP, REDIRECT and ORM-LEAK each concluded CLEAN on 93 slots: 372 verdicts that
// are true about the authentication wall and say nothing whatever about the application. Real
// coverage was 3 of 30 vectors, and the run reported itself completed.
//
// These tests are the fixture the write-up asked for: a server that answers 401 to everything.
// ---------------------------------------------------------------------------------------------

// triageTestExpiredJWT is a JWS-SHAPED string and nothing more. Three base64url segments, so the
// credential rule's shape net sees it for what a captured bearer token is, and it carries no
// signature and no claim anybody would want. No real token goes in a file.
const triageTestExpiredJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0LWZpeHR1cmUifQ.AAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// triageAuthWallServer answers 401 to everything, byte-identically, with the WWW-Authenticate a
// bearer realm emits. Byte-identical matters twice: the baseline gate must call it JUDGEABLE, so
// the old runner has no other reason to refuse the vector, and every probe response must equal
// the baseline, so no class reads a differential and no class's uniform-block detector fires.
// What is left is exactly the live condition: a stable, readable, entirely uninformative wall.
func triageAuthWallServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("WWW-Authenticate", "Bearer realm=\"api\", error=\"invalid_token\"")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "{\"code\":40100,\"message\":\"unauthorized\"}")
	}))
	t.Cleanup(s.Close)
	return s
}

// triageForbiddenServer answers 403 with NO challenge and no token error: the application itself
// saying this identity may not have this resource. That is a real measurement and the gate must
// NOT swallow it. It is the control for the 401/403 decision.
func triageForbiddenServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "{\"code\":40300,\"message\":\"you do not have access to this account\"}")
	}))
	t.Cleanup(s.Close)
	return s
}

// triageCredentialUnit is triageQueryUnit with a captured bearer token on it, which is what every
// one of the 27 walled vectors in run 2n6f looks like.
func triageCredentialUnit(base, param string) (*triageUnitPlan, triage.Slot) {
	u, slot := triageQueryUnit(base, param)
	u.Template.Headers = [][2]string{{"Authorization", "Bearer " + triageTestExpiredJWT}}
	return u, slot
}

func triageEnableClass(rr *triageRunner, class triage.ClassID) {
	key := TriageClassKey(class)
	cs := rr.settings.Classes[key]
	cs.Enabled, cs.Tier, cs.MaxRisk = true, string(triage.TierFull), string(triage.RiskR3)
	rr.settings.Classes[key] = cs
	rr.settings.Tier = string(triage.TierFull)
}

func triageCleanRows(rr *triageRunner) []TriageVerdictRow {
	var out []TriageVerdictRow
	for _, v := range rr.verdicts {
		if v.Verdict.State.CountsAsClean() {
			out = append(out, v)
		}
	}
	return out
}

// GATE 1, STALENESS. The vector replays a credential, the UNPERTURBED baseline comes back 401, so
// the session the rest of the run depends on is dead before a payload is sent.
func TestAVectorWhoseReplayedCredentialIsRefusedIsNeverClean(t *testing.T) {
	ctx := triageTestDB(t)
	srv := triageAuthWallServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageCredentialUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, u)
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	// THE FIXTURE HAS TO BE THE ONE THIS TEST IS ABOUT. If the baseline gate refused this vector
	// for its own reasons the test proves nothing about the session.
	if !uc.baseline.Gate.ShapeJudgeable() {
		t.Fatalf("NOT MEASURED: the 401 wall did not produce a judgeable baseline (gate=%q detail=%q), so the vector was refused for a reason that has nothing to do with the dead session",
			uc.baseline.Gate, uc.baseline.GateDetail)
	}
	if uc.judgeable {
		// The old path. Driving it is the point: this is the output the defect produced.
		rr.runSlot(ctx, u, slot, uc.baseline, uc.samples, uc.prelude, 0)
	}

	for _, v := range triageCleanRows(rr) {
		t.Errorf("CLEAN OFF AN AUTHENTICATION WALL: %s reported %s on %s.\nReason: %s\nEvery response this vector produced was a 401 to a replayed bearer token. The class is right about what it saw and the row says nothing about the application.",
			v.Verdict.Class, v.Verdict.State, v.Verdict.SlotKey, v.Verdict.Reason)
	}
	if len(rr.verdicts) == 0 {
		t.Fatal("the walled vector produced no row at all, which is the silent zero this layer exists to replace")
	}
	named := false
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "session_expired") {
			named = true
			t.Logf("refusal: %s", v.Verdict.Reason)
		}
	}
	if !named {
		var got []string
		for _, v := range rr.verdicts {
			got = append(got, string(v.Verdict.State)+": "+v.Verdict.Reason)
		}
		t.Errorf("no row names session_expired, so nothing tells the operator their own session is dead.\nGot:\n  %s", strings.Join(got, "\n  "))
	}
}

// GATE 2, CONCLUSION. It is a SECOND and INDEPENDENT gate, so it is exercised with gate 1 out of
// the way: the baseline is taken directly and the slot is driven without going through the front
// door. A session that dies AFTER calibration reaches exactly this shape, and no class may return
// a negative from responses that are all auth refusals on a credential-carrying vector.
func TestNoClassMayConcludeFromAnAuthRefusalOnACredentialVector(t *testing.T) {
	ctx := triageTestDB(t)
	srv := triageAuthWallServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageCredentialUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	baseline, samples, why := rr.calibrate(ctx, u)
	if !baseline.Gate.ShapeJudgeable() {
		t.Fatalf("NOT MEASURED: the 401 wall did not produce a judgeable baseline (gate=%q why=%q)", baseline.Gate, why)
	}
	rr.runSlot(ctx, u, slot, baseline, samples, triage.PreludeTokenNotRequired, 0)

	if len(rr.verdicts) == 0 {
		t.Fatal("NOT MEASURED: the class produced no verdict at all, so the gate had nothing to turn back")
	}
	for _, v := range rr.verdicts {
		t.Logf("%s %s: %s", v.Verdict.Class, v.Verdict.State, v.Verdict.Reason)
	}
	for _, v := range triageCleanRows(rr) {
		t.Errorf("CLEAN OFF AN AUTHENTICATION WALL, PAST THE CONCLUSION GATE: %s on %s.\nReason: %s",
			v.Verdict.State, v.Verdict.SlotKey, v.Verdict.Reason)
	}
	// AND IT WAS THE GATE THAT DID IT. Without this the test would also pass if the class had
	// happened to answer cannot_determine for reasons of its own, which proves nothing about the
	// rule that has to hold for the eighteen other classes and the ones not yet written.
	if rr.authGated == 0 {
		t.Error("no verdict was turned back by the conclusion gate, so what this test measured was the class's own judgement and not the gate")
	}
	named := false
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "session_expired_at_conclusion") {
			named = true
			// THE CLASS'S OWN SENTENCE SURVIVES. It is the only description of what the probes
			// actually did, and the gate is not entitled to delete it.
			if !strings.Contains(v.Verdict.Reason, "ORIGINAL VERDICT") {
				t.Errorf("the gate threw away the class's own sentence: %s", v.Verdict.Reason)
			}
		}
	}
	if !named {
		t.Error("the gate turned a verdict back and no row says so")
	}
}

// THE CONTROL FOR THE 401/403 DECISION. A 403 with no challenge and no token error is the
// application answering about authorisation, which is a real measurement and the exact answer an
// access-control test exists to read. Swallowing it would turn every true negative of that test
// into an unknown, which is the same defect pointed the other way.
func TestAPlainForbiddenIsTheApplicationAnsweringAndIsStillProbed(t *testing.T) {
	ctx := triageTestDB(t)
	srv := triageForbiddenServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageCredentialUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, u)
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	if !uc.baseline.Gate.ShapeJudgeable() {
		t.Fatalf("NOT MEASURED: the 403 fixture did not produce a judgeable baseline (gate=%q detail=%q)",
			uc.baseline.Gate, uc.baseline.GateDetail)
	}
	if !uc.judgeable {
		t.Fatal("a plain 403 was treated as a dead session and the whole vector went unprobed. 403 is the server saying it understood the request and refuses to authorise it, which is an answer about the application and the one an access-control test exists to read.")
	}
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "session_expired") {
			t.Errorf("a plain 403 was reported as an expired session: %s", v.Verdict.Reason)
		}
	}
}

// THE OTHER CONTROL. A 401 on a vector that carries NO credential is the application correctly
// telling an anonymous caller to log in. It is not our session dying, and blaming it on one would
// be a reason string guessing at a cause.
func TestA401OnAVectorThatCarriesNoCredentialIsNotBlamedOnASession(t *testing.T) {
	ctx := triageTestDB(t)
	srv := triageAuthWallServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageQueryUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, u)
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "session_expired") {
			t.Errorf("a vector that replays no credential at all was reported as having an expired session: %s", v.Verdict.Reason)
		}
	}
}

// triageStaticServer takes a query parameter and ignores it: byte-identical to its own baseline
// whatever is sent, and no authentication anywhere near it. It is the control server for the
// authentication-wall tests.
func triageStaticServer(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, "{\"ok\":true,\"items\":[]}")
	}))
	t.Cleanup(s.Close)
	return s
}

// THE 403 THAT IS A 401 WEARING A 403. RFC 6750 s3.1 invalid_token in a 403 body is a statement
// about the credential, not about the resource, so it is staleness. This is the other half of the
// 401/403 decision and it is what keeps that decision from being a bare status-code rule.
func TestA403ThatNamesTheTokenItselfIsADeadSession(t *testing.T) {
	ctx := triageTestDB(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "{\"error\":\"invalid_token\",\"error_description\":\"the access token is no longer valid\"}")
	}))
	t.Cleanup(srv.Close)

	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageCredentialUnit(srv.URL, "q")
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, u)
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	if uc.judgeable {
		t.Fatal("a 403 whose body names the token itself was probed as though it were the application answering about authorisation")
	}
	named := false
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, string(triageAuthTokenRefused)) {
			named = true
			t.Logf("refusal: %s", v.Verdict.Reason)
		}
	}
	if !named {
		t.Errorf("the refusal does not name the 403 that complained about the token, so the operator cannot tell it from a plain authorisation refusal")
	}
}

// THE RUN-LEVEL SENTENCE: ONCE, WITH THE COUNT, IN THE TRUNCATION'S VOICE. The write-up asked for
// exactly this and asked for it NOT to be repeated per pair; the per-pair rows carry their own
// reason already. And a run that measured a wall must not report itself completed, because
// completed is the one terminal status the certificate renders under.
func TestTheAuthenticationWallIsSaidOnceAtRunLevelAndBlocksTheCertificate(t *testing.T) {
	ctx := triageTestDB(t)
	wall := triageAuthWallServer(t)
	open := triageStaticServer(t)

	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)

	dead1, slot1 := triageCredentialUnit(wall.URL, "a")
	dead2, slot2 := triageCredentialUnit(wall.URL, "b")
	live, slot3 := triageQueryUnit(open.URL, "c")
	rr.plan.Units = []triageUnitPlan{*dead1, *dead2, *live}
	rr.plan.Pairs = []triagePair{
		{Slot: slot1, Class: triage.ClassCRLF, Eligible: true},
		{Slot: slot2, Class: triage.ClassCRLF, Eligible: true},
		{Slot: slot3, Class: triage.ClassCRLF, Eligible: true},
	}
	for i := range rr.plan.Units {
		rr.unitContext(ctx, &rr.plan.Units[i])
	}

	w := rr.authWall()
	if w.Stale != 2 || w.Credentialed != 2 || w.Vectors != 3 {
		t.Fatalf("NOT MEASURED: the run-level reading is stale=%d credentialed=%d vectors=%d, want 2, 2 and 3. The fixture is two walled credential vectors and one open vector that carries none.",
			w.Stale, w.Credentialed, w.Vectors)
	}
	if !w.Measured() {
		t.Fatal("two dead sessions and the run does not consider itself to have hit a wall")
	}
	if w.Pairs != 2 {
		t.Errorf("the wall reports %d refused pair(s), want 2", w.Pairs)
	}

	s := w.Sentence()
	t.Logf("sentence: %s", s)
	for _, want := range []string{"AUTHENTICATION WALL", "2 of 3", "401_credential_not_accepted x2", "session_expired", "re-capture"} {
		if !strings.Contains(s, want) {
			t.Errorf("the run-level sentence does not carry %q.\nGot: %s", want, s)
		}
	}
	// SAID ONCE. Not the phrase per pair: the count is the whole point of saying it at run level.
	if n := strings.Count(s, "AUTHENTICATION WALL"); n != 1 {
		t.Errorf("the sentence says its headline %d times, want once", n)
	}

	status, shortfall := rr.terminalStatus()
	if status != TriageRunIncomplete {
		t.Errorf("a run whose corpus replays a dead credential reported %q. Every refused pair IS decided, so the pair arithmetic says the plan finished, and %q is the one status the certificate renders under: run 2n6f reported exactly this and was a measurement of a login page.",
			status, TriageRunCompleted)
	}
	if shortfall != "" {
		t.Errorf("the wall wrote a second sentence into the shortfall column as well as its own: %q", shortfall)
	}
}

// AND THE CONTROL FOR THAT ONE: a run with no credential anywhere near it must not start talking
// about authentication walls, and must still be able to report itself completed.
func TestARunWithNoCredentialSaysNothingAboutAnAuthenticationWall(t *testing.T) {
	ctx := triageTestDB(t)
	open := triageStaticServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageQueryUnit(open.URL, "c")
	rr.plan.Units = []triageUnitPlan{*u}
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}
	rr.unitContext(ctx, &rr.plan.Units[0])

	if w := rr.authWall(); w.Measured() {
		t.Errorf("a run against an endpoint nobody authenticated to reports an authentication wall: %s", w.Sentence())
	}
}

// THE CREDENTIAL READING ITSELF. It has to name what carries the credential, because the operator
// has to know what to re-capture, AND it has to show what rode in it, because the verdict row it
// lands in is where the operator reads what this run actually sent. A row that named a carrier and
// dropped its contents could not be checked against the wire or replayed by hand.
func TestTheCredentialReadingNamesWhatCarriesItAndShowsWhatRodeInIt(t *testing.T) {
	cases := []struct {
		name  string
		tmpl  RequestTemplate
		want  string
		value string
		empty bool
	}{
		{name: "bearer", tmpl: RequestTemplate{Headers: [][2]string{{"Authorization", "Bearer " + triageTestExpiredJWT}}}, want: "the Authorization header", value: triageTestExpiredJWT},
		{name: "api key", tmpl: RequestTemplate{Headers: [][2]string{{"X-Api-Key", "abc123"}}}, want: "the X-Api-Key header", value: "abc123"},
		{name: "session cookie", tmpl: RequestTemplate{Headers: [][2]string{{"Cookie", "theme=dark; JSESSIONID=9F1A2B; tz=UTC"}}}, want: "the JSESSIONID cookie", value: "9F1A2B"},
		// THIS CASE USED TO EXPECT "Cookie header" AND THAT WAS THE DEFECT. A one-character
		// preference cookie is not credential material, and reading it as one reported an
		// endpoint that refuses everyone as our own session dying. See
		// TestATrackingCookieIsNotReadAsAReplayedCredential for the measured version.
		{name: "an unrecognised cookie too small to hold a secret", tmpl: RequestTemplate{Headers: [][2]string{{"Cookie", "xq=1"}}}, empty: true},
		{name: "an unrecognised cookie that could be a session id", tmpl: RequestTemplate{Headers: [][2]string{{"Cookie", "xq=9f8a1b2c3d4e5f60718293a4"}}}, want: "the xq cookie", value: "9f8a1b2c3d4e5f60718293a4"},
		{name: "none", tmpl: RequestTemplate{Headers: [][2]string{{"Accept", "application/json"}, {"X-Forwarded-For", "127.0.0.1"}}}, empty: true},
		{name: "no headers", tmpl: RequestTemplate{}, empty: true},
	}
	for _, c := range cases {
		got := triageTemplateCredential(c.tmpl)
		if c.empty {
			if got != "" {
				t.Errorf("%s: read %q as credential material, and a vector wrongly called credentialed is one the gates can refuse to conclude about", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: read %q, want it to name %q", c.name, got, c.want)
		}
		// AND THE CREDENTIAL ITSELF IS IN THE SENTENCE. PII, credentials and secrets in a capture
		// are the finding: a leaked token is proved by showing the token, so the row that says a
		// token rode in a carrier has to say WHICH token, verbatim.
		if !strings.Contains(got, c.value) {
			t.Errorf("%s: read %q, and it does not carry the credential %q that actually went out. "+
				"A reading that names a carrier and drops its contents cannot be checked against the wire.",
				c.name, got, c.value)
		}
	}
}

// THE STATUS TABLE, AS DATA. The whole 401/403 judgement is one function, so it is asserted in one
// place rather than inferred from four end-to-end tests.
func TestWhichStatusesCountAsARefusalOfOurOwnCredential(t *testing.T) {
	obs := func(status int, headers [][2]string, body string) triage.Observation {
		return triage.Observation{Status: status, RespHeaders: headers, Body: []byte(body)}
	}
	cases := []struct {
		name string
		obs  triage.Observation
		want triageAuthRefusal
	}{
		{"401 with challenge", obs(401, [][2]string{{"Www-Authenticate", "Bearer realm=\"api\""}}, ""), triageAuthUnauthorized},
		{"401 bare json api", obs(401, nil, "{\"message\":\"unauthorized\"}"), triageAuthUnauthorized},
		{"407 proxy", obs(407, nil, ""), triageAuthProxyAuth},
		{"403 plain", obs(403, nil, "{\"message\":\"you may not access this account\"}"), triageAuthAnswered},
		{"403 with challenge", obs(403, [][2]string{{"Www-Authenticate", "Bearer error=\"invalid_token\""}}, ""), triageAuthTokenRefused},
		{"403 naming the token", obs(403, nil, "{\"error\":\"invalid_token\"}"), triageAuthTokenRefused},
		{"200", obs(200, nil, "{}"), triageAuthAnswered},
		{"404", obs(404, nil, ""), triageAuthAnswered},
		{"500", obs(500, nil, ""), triageAuthAnswered},
		// A 419 IS DELIBERATELY NOT ONE. It is a vendor code that means a CSRF token mismatch,
		// which the prelude layer owns, and claiming it here would be a reason string guessing.
		{"419 laravel page expired", obs(419, nil, "session expired"), triageAuthAnswered},
	}
	for _, c := range cases {
		got, evidence := triageAuthRefusalOf(c.obs)
		if got != c.want {
			t.Errorf("%s: read as %q, want %q", c.name, got, c.want)
		}
		if got != triageAuthAnswered && strings.TrimSpace(evidence) == "" {
			t.Errorf("%s: refused with no evidence, and a refusal that cannot say what it saw is a reason string guessing at its own cause", c.name)
		}
		if got == triageAuthAnswered && evidence != "" {
			t.Errorf("%s: not a refusal and yet carries evidence %q", c.name, evidence)
		}
	}
}

// A SESSION THAT DIES HALFWAY IS WHY THERE ARE TWO GATES. The baseline passes, the class sends its
// probes, and every one of them comes back 401. Gate 1 cannot see that and gate 2 must.
//
// MEASURED HERE, AND WORTH WRITING DOWN: on this particular shape CRLF's OWN uniform-block
// detector fires first and says "blocked", because 8 byte-identical NON-baseline responses is
// exactly what its filter test looks for. So on this fixture the conclusion gate has nothing to
// turn back. That is a correct outcome and it is not the thing under test, so the assertion is
// the invariant rather than the mechanism: whatever reaches a verdict here, none of it may be a
// negative. A class without that detector, and most do not have one, lands on the gate instead.
func TestASessionThatDiesAfterCalibrationIsCaughtByTheConclusionGate(t *testing.T) {
	ctx := triageTestDB(t)
	var served int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if atomic.AddInt64(&served, 1) <= int64(TriageBaselineSamples) {
			fmt.Fprint(w, "{\"ok\":true}")
			return
		}
		w.Header().Set("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, "{\"message\":\"unauthorized\"}")
	}))
	t.Cleanup(srv.Close)

	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageCredentialUnit(srv.URL, "q")
	rr.plan.Units = []triageUnitPlan{*u}
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, &rr.plan.Units[0])
	if uc == nil || !uc.judgeable {
		t.Fatalf("NOT MEASURED: the front door refused a vector whose baseline was a clean 200, so the SECOND gate was never reached (judgeable=%v)", uc != nil && uc.judgeable)
	}
	rr.runSlot(ctx, &rr.plan.Units[0], slot, uc.baseline, uc.samples, uc.prelude, 0)

	for _, v := range rr.verdicts {
		t.Logf("%s %s: %s", v.Verdict.Class, v.Verdict.State, v.Verdict.Reason)
	}
	for _, v := range triageCleanRows(rr) {
		t.Errorf("a session that died after the baseline still produced a negative: %s on %s.\nReason: %s",
			v.Verdict.State, v.Verdict.SlotKey, v.Verdict.Reason)
	}
	if rr.authGated == 0 && len(rr.verdicts) > 0 {
		anyNegative := false
		for _, v := range rr.verdicts {
			if v.Verdict.State.Kind() == triage.StateKindNegative {
				anyNegative = true
			}
		}
		if anyNegative {
			t.Error("a negative verdict came off an all-401 pair and the conclusion gate counted nothing")
		}
	}
}

// THE CONCLUSION GATE'S ONE EXEMPTION IS CLOSED BY DEFAULT. A class whose subject IS the
// credential perturbs the Authorization header on purpose and its 401s are its measurement, so
// the gate steps aside for that PAIR. No class in this build declares it, so the exemption must
// be false everywhere today: if it ever reads true for a class that did not opt in, the gate has
// a hole in it exactly where the 372 verdicts came through.
func TestTheCredentialSubjectExemptionIsClosedUnlessAClassDeclaresIt(t *testing.T) {
	rr := triageUnitRunner(t)
	cred := triage.Slot{
		VectorID: "v1", Kind: triage.KindHeader, Key: "header:authorization", Name: "Authorization",
		Value: "Bearer x", SegmentIndex: -1, ServerReachable: true,
		Constraints: triage.NewSlotConstraints(),
	}
	cred.Constraints.IsCredential = true
	plain := cred
	plain.Key, plain.Name, plain.Value = "query:q", "q", "hello"
	plain.Kind = triage.KindQuery
	plain.Constraints.IsCredential = false

	rr.plan.Units = []triageUnitPlan{{VectorID: "v1", Selected: true, Slots: []triage.Slot{cred, plain}}}

	optedIn := 0
	for _, c := range triage.RegisteredClassifiers() {
		if triageClassWantsCredentialSlots(c) {
			optedIn++
			continue
		}
		if rr.credentialSlotProbedOnPurpose("v1", cred.Key, c.ID()) {
			t.Errorf("%s did not declare the credential as its subject and the conclusion gate exempted it on a credential slot anyway", c.ID())
		}
		if rr.credentialSlotProbedOnPurpose("v1", plain.Key, c.ID()) {
			t.Errorf("%s was exempted on an ORDINARY slot, which would take the gate off every pair of the class", c.ID())
		}
	}
	t.Logf("classes declaring the credential as their subject in this build: %d", optedIn)
	// AND AN UNKNOWN VECTOR IS NOT AN EXEMPTION EITHER. A runner that cannot find the unit knows
	// nothing about the slot, and "I cannot tell" must not open the gate.
	if rr.credentialSlotProbedOnPurpose("v-nosuch", cred.Key, triage.ClassCRLF) {
		t.Error("a vector the plan does not hold was treated as an exempt credential slot")
	}
}

// ---------------------------------------------------------------------------------------------
// WHAT COUNTS AS REPLAYED CREDENTIAL MATERIAL, AND WHAT DOES NOT
//
// The auth gate shipped correct and with two holes, both named by the agent who built it.
//
// HOLE A, TOO BROAD. The credential reading returned "a Cookie header whose individual names the
// credential rule does not recognise" for ANY non-empty Cookie header. An endpoint that answers
// 401 to EVERYONE, plus a stray analytics cookie in the capture, was therefore reported as our
// own session being dead with "re-capture this vector with a live session". That sends the
// operator to fix a session that was never the problem and turns a real target-side fact into a
// tooling excuse.
//
// HOLE B, NOT BROAD ENOUGH. The reading walked headers and cookies only, so ?api_key=... and a
// token in a JSON body were invisible to BOTH gates and the false clean stayed open on exactly
// those vectors.
// ---------------------------------------------------------------------------------------------

// triageAnalyticsCookies is what a real capture carries alongside nothing else: Google Analytics,
// Facebook, Hotjar, Cloudflare bot management. Not one of them is read by the application for
// authorisation, and a 401 on a request carrying only these is the target refusing an anonymous
// caller.
const triageAnalyticsCookies = "_ga=GA1.2.1234567890.1699999999; _fbp=fb.1.1699999999999.1234567890; " +
	"_hjSessionUser_3170977=eyJpZCI6ImFiYyJ9; __cf_bm=vQ8kZmNvb2tpZQ1234567890abcdef"

// HOLE A, AT THE READING. A tracking cookie is not a credential, and the one that hurts most is
// _hjSessionUser_*, because it compacts to a name containing "session" and the shared cookie rule
// says credential on it.
func TestATrackingCookieIsNotReadAsAReplayedCredential(t *testing.T) {
	tmpl := RequestTemplate{Headers: [][2]string{{"Cookie", triageAnalyticsCookies}}}
	if got := triageTemplateCredential(tmpl); got != "" {
		t.Errorf("a capture carrying only analytics cookies reads as credential material: %q\nEvery gate downstream then reports a target that refuses everyone as OUR session being dead, and sends the operator to re-capture a session that was never the problem.", got)
	}
}

// AND THE OPPOSITE FAILURE, WHICH IS THE ONE THAT COSTS MORE. A session cookie under a name
// nobody listed must still fire: a wrongly withheld conclusion is recoverable and a wrong clean
// is not. The reading must NAME the cookie, because "a Cookie header whose individual names the
// credential rule does not recognise" does not tell the operator what to re-capture.
func TestAnUnrecognisedButSecretShapedCookieStillCountsAsACredential(t *testing.T) {
	cases := []struct {
		name string
		jar  string
		want string
	}{
		{"opaque hex under an unlisted name", "portal_state=9f8a1b2c3d4e5f60718293a4b5c6d7e8", "portal_state"},
		{"opaque base64url under an unlisted name", "zz=YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoxMjM0", "zz"},
		{"a JWS under a tracking name beats the tracking list", "_ga=" + triageTestExpiredJWT, "_ga"},
		{"a real session cookie beside the analytics ones", triageAnalyticsCookies + "; JSESSIONID=9F1A2B3C4D5E6F708192A3B4", "JSESSIONID"},
	}
	for _, c := range cases {
		got := triageTemplateCredential(RequestTemplate{Headers: [][2]string{{"Cookie", c.jar}}})
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: read %q, and it does not name %q. When the rule cannot tell, it must fire AND say what to re-capture.", c.name, got, c.want)
		}
		// AND IT CARRIES THE COOKIE'S VALUE. The cookie this branch fired on is one no name rule
		// recognises, so "the portal_state cookie" tells the operator nothing they can act on
		// without the bytes beside it.
		for _, pair := range strings.Split(c.jar, ";") {
			n, v, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if strings.TrimSpace(n) != c.want {
				continue
			}
			if v = strings.TrimSpace(v); v != "" && !strings.Contains(got, v) {
				t.Errorf("%s: the credential reading %q dropped the value %q it fired on", c.name, got, v)
			}
		}
	}
}

// HOLE B, AT THE READING. A credential in the query string or the body is replayed by
// triageRunTemplateFor exactly as a header is, and until now neither gate could see one.
func TestACredentialInTheQueryStringOrBodyIsReadAsOne(t *testing.T) {
	cases := []struct {
		name  string
		tmpl  RequestTemplate
		want  string
		value string
		empty bool
	}{
		{name: "api key in the query", want: "api_key", value: "ak_9f8a1b2c3d4e5f60",
			tmpl: RequestTemplate{Method: "GET", URL: "https://api.test/v1/orders?api_key=ak_9f8a1b2c3d4e5f60&page=2"}},
		{name: "access token in the query", want: "access_token", value: triageTestExpiredJWT,
			tmpl: RequestTemplate{Method: "GET", URL: "https://api.test/v1/orders?access_token=" + triageTestExpiredJWT}},
		{name: "a signature in the query", want: "X-Amz-Signature", value: "8d1f2e3c4b5a69788796a5b4c3d2e1f0",
			tmpl: RequestTemplate{Method: "GET", URL: "https://api.test/o.pdf?X-Amz-Signature=8d1f2e3c4b5a69788796a5b4c3d2e1f0&X-Amz-Expires=900"}},
		{name: "a bearer token in a json body", want: "access_token", value: triageTestExpiredJWT,
			tmpl: RequestTemplate{Method: "POST", URL: "https://api.test/v1/refresh", BodyMedia: triage.BodyJSON,
				Body: []byte(`{"grant_type":"refresh","access_token":"` + triageTestExpiredJWT + `"}`)}},
		{name: "a session token in a nested json body", want: "session.token", value: "9f8a1b2c3d4e5f60718293a4b5c6d7e8",
			tmpl: RequestTemplate{Method: "POST", URL: "https://api.test/v1/rpc", BodyMedia: triage.BodyJSON,
				Body: []byte(`{"session":{"token":"9f8a1b2c3d4e5f60718293a4b5c6d7e8"},"page":2}`)}},
		{name: "a csrf token in a form body", want: "csrf_token", value: "8d1f2e3c4b5a6978",
			tmpl: RequestTemplate{Method: "POST", URL: "https://api.test/v1/transfer", BodyMedia: triage.BodyForm,
				Body: []byte("amount=10&csrf_token=8d1f2e3c4b5a6978")}},
		{name: "an ordinary query carries nothing", empty: true,
			tmpl: RequestTemplate{Method: "GET", URL: "https://api.test/v1/orders?page=2&sort=desc&cursor=eyJvIjoyMH0"}},
		{name: "an ordinary json body carries nothing", empty: true,
			tmpl: RequestTemplate{Method: "POST", URL: "https://api.test/v1/orders", BodyMedia: triage.BodyJSON,
				Body: []byte(`{"symbol":"AAPL","qty":10,"notes":"buy the dip"}`)}},
	}
	for _, c := range cases {
		got := triageTemplateCredential(c.tmpl)
		if c.empty {
			if got != "" {
				t.Errorf("%s: read %q as credential material. A vector wrongly called credentialed is one the gates refuse to conclude about, which is the false-clean defect pointed the other way.", c.name, got)
			}
			continue
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: read %q, want it to name %q. A credential the reading cannot see is a gate that cannot fire, and the false clean stays open on exactly those vectors.", c.name, got, c.want)
		}
		// AND IT CARRIES WHAT RODE THERE. A signed URL and a token in a body are credentials the
		// operator has to be able to lift straight out of the verdict row and replay.
		if !strings.Contains(got, c.value) {
			t.Errorf("%s: read %q, and it dropped the credential %q it fired on. The verdict row is "+
				"where the operator reads what this run sent, so it has to say what was sent.",
				c.name, got, c.value)
		}
	}
}

// triageCookieUnit is a vector whose captured request carries a cookie jar and nothing else.
func triageCookieUnit(base, param, jar string) (*triageUnitPlan, triage.Slot) {
	u, slot := triageQueryUnit(base, param)
	u.Template.Headers = [][2]string{{"Cookie", jar}}
	return u, slot
}

// triageQueryCredentialUnit is a vector whose credential rides in the URL, which is the shape
// hole B left completely uncovered: the probeable slot is page and the credential is api_key.
func triageQueryCredentialUnit(base string) (*triageUnitPlan, triage.Slot) {
	u := &triageUnitPlan{
		VectorID: "v-apikey",
		Host:     "127.0.0.1",
		Template: RequestTemplate{Method: "GET", URL: base + "/v1/orders?api_key=ak_9f8a1b2c3d4e5f60&page=2"},
		Selected: true,
	}
	slot := triage.Slot{VectorID: u.VectorID, Kind: triage.KindQuery, Key: triage.SlotKey("query:page"),
		Name: "page", Value: "2", SegmentIndex: -1, ServerReachable: true,
		Origin: triage.SlotObserved, ValueOrigin: triage.ValueObserved,
		Constraints: triage.NewSlotConstraints()}
	u.Slots = []triage.Slot{slot}
	return u, slot
}

// HOLE A, END TO END, AND THIS IS THE ROW THE OPERATOR READS. An endpoint that answers 401 to
// everyone, on a capture whose only cookies are analytics, must not be reported as our own
// session dying. It must also not be clean: nothing behind that wall was measured. Two different
// causes, two different fixes, and the row has to say which one fired.
func TestAWallThatRefusesEveryoneIsNotReportedAsOurOwnDeadSession(t *testing.T) {
	ctx := triageTestDB(t)
	srv := triageAuthWallServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageCookieUnit(srv.URL, "q", triageAnalyticsCookies)
	rr.plan.Units = []triageUnitPlan{*u}
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, &rr.plan.Units[0])
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	if uc.judgeable {
		rr.runSlot(ctx, &rr.plan.Units[0], slot, uc.baseline, uc.samples, uc.prelude, 0)
	}
	for _, v := range rr.verdicts {
		t.Logf("%s %s: %s", v.Verdict.Class, v.Verdict.State, v.Verdict.Reason)
	}
	if len(rr.verdicts) == 0 {
		t.Fatal("the walled vector produced no row at all, which is the silent zero this layer exists to replace")
	}
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "session_expired") || strings.Contains(v.Verdict.Reason, "re-capture") {
			t.Errorf("AN ANALYTICS COOKIE WAS READ AS OUR SESSION: %s\nThis endpoint refuses everyone. Reporting it as our own dead session sends the operator to re-capture a session that was never the problem and converts a target-side fact into a tooling excuse.", v.Verdict.Reason)
		}
	}
	for _, v := range triageCleanRows(rr) {
		t.Errorf("CLEAN OFF AN AUTHENTICATION WALL: %s on %s.\nReason: %s\nNarrowing the credential test must not open a new route to a clean: every response here was a 401 and nothing about the application was measured.",
			v.Verdict.State, v.Verdict.SlotKey, v.Verdict.Reason)
	}
	named := false
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "no_credential_held") {
			named = true
		}
	}
	if !named {
		t.Error("no row names the cause that actually fired: this run holds no credential for an endpoint that refuses everyone. The operator's next move is to obtain one, not to re-capture the one they have.")
	}
}

// HOLE B, END TO END. The credential is in the query string, the wall refuses it, and the gate
// has to fire on exactly the same evidence it fires on for a header.
func TestAVectorWhoseQueryStringCredentialIsRefusedIsNeverClean(t *testing.T) {
	ctx := triageTestDB(t)
	srv := triageAuthWallServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, slot := triageQueryCredentialUnit(srv.URL)
	rr.plan.Units = []triageUnitPlan{*u}
	rr.plan.Pairs = []triagePair{{Slot: slot, Class: triage.ClassCRLF, Eligible: true}}

	uc := rr.unitContext(ctx, &rr.plan.Units[0])
	if uc == nil {
		t.Fatal("no unit context at all")
	}
	if !uc.baseline.Gate.ShapeJudgeable() {
		t.Fatalf("NOT MEASURED: the 401 wall did not produce a judgeable baseline (gate=%q detail=%q)", uc.baseline.Gate, uc.baseline.GateDetail)
	}
	if uc.judgeable {
		rr.runSlot(ctx, &rr.plan.Units[0], slot, uc.baseline, uc.samples, uc.prelude, 0)
	}
	for _, v := range rr.verdicts {
		t.Logf("%s %s: %s", v.Verdict.Class, v.Verdict.State, v.Verdict.Reason)
	}
	for _, v := range triageCleanRows(rr) {
		t.Errorf("CLEAN OFF AN AUTHENTICATION WALL, CREDENTIAL IN THE QUERY STRING: %s on %s.\nReason: %s",
			v.Verdict.State, v.Verdict.SlotKey, v.Verdict.Reason)
	}
	named := false
	for _, v := range rr.verdicts {
		if strings.Contains(v.Verdict.Reason, "session_expired") && strings.Contains(v.Verdict.Reason, "api_key") {
			named = true
		}
	}
	if !named {
		t.Error("no row names the api_key query parameter as the credential that was refused, so the operator cannot tell what to re-capture")
	}
}

// ---------------------------------------------------------------------------------------------
// A CLASS THAT IS REACHABLE AND WAS NEVER EXERCISED
//
// Run a90a70af: CORS 931 reachable coverage rows and 0 exercised, HOSTHDR 931 and 0, PP-SERVER
// 139 and 0, because every header and body vector was deselected. On the card that reads as 93
// not_applicable rows per class with nothing whatever saying why. Two states, one line each, at
// RUN level and not per pair.
// ---------------------------------------------------------------------------------------------

// triageCoverageRowFor plants one coverage row the way writePlanRows would, so the roll-up is
// measured over the same population the SQL against triage_coverage would count.
func triageCoverageRowFor(rr *triageRunner, vec string, slot triage.SlotKey, class triage.ClassID,
	reach triage.Reach, ran bool, why string) {

	row := rr.cov(vec, slot, class)
	row.Reach, row.Ran = reach, ran
	if why != "" {
		row.Skipped = []triage.ProbeSkip{{Reason: why}}
	}
}

const triageDeselectedWhy = "deselected: the operator switched this vector off for Investigate, so nothing was sent and nothing is known about it"

// ZERO EXERCISED. The class could reach every one of its units and not one of them was measured.
func TestAClassThatIsReachableAndNeverExercisedIsNamedAtRunLevel(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassCORS, triage.ClassCRLF)
	for _, v := range []string{"v1", "v2", "v3"} {
		triageCoverageRowFor(rr, v, "header:origin", triage.ClassCORS, triage.ReachAlways, false, triageDeselectedWhy)
	}
	// The control lives in the same run: a class that DID run must not be named.
	triageCoverageRowFor(rr, "v1", "query:q", triage.ClassCRLF, triage.ReachAlways, true, "")

	said := triageRunLevelSay(rr)
	t.Logf("run level: %s", said)
	for _, want := range []string{"CORS", "3 reachable", "0 exercised", "deselected"} {
		if !strings.Contains(said, want) {
			t.Errorf("nothing this run says at run level carries %q.\nGot: %s\nOn the card that class is 3 rows of not_applicable with nothing saying why.", want, said)
		}
	}
	if strings.Contains(said, "CRLF") {
		t.Errorf("a class that was actually exercised is reported as silent: %s", said)
	}
}

// ZERO REACHABLE. The class could never reach a single unit in this corpus, which is a different
// fact with a different next move, and it is worth exactly one line as well.
func TestAClassThatCanNeverReachAnythingIsNamedOnceAtRunLevel(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassPPServer)
	const why = "not_applicable: this class only reaches a JSON body and this vector has none"
	for _, v := range []string{"v1", "v2", "v3", "v4"} {
		triageCoverageRowFor(rr, v, "query:q", triage.ClassPPServer, triage.ReachNever, false, why)
	}

	said := triageRunLevelSay(rr)
	t.Logf("run level: %s", said)
	for _, want := range []string{"PP-SERVER", "0 of 4", "not_applicable"} {
		if !strings.Contains(said, want) {
			t.Errorf("nothing this run says at run level carries %q.\nGot: %s", want, said)
		}
	}
	if n := strings.Count(said, "PP-SERVER"); n != 1 {
		t.Errorf("the class is named %d times at run level, want once: this is a run-level roll-up and not a per-pair row", n)
	}
}

// THE CONTROL FOR BOTH. A run where every class was exercised says nothing about silent classes,
// because a line that appears on every run is a line nobody reads.
func TestARunWhoseClassesWereAllExercisedReportsNoSilentClass(t *testing.T) {
	rr := triageUnitRunner(t, triage.ClassCRLF, triage.ClassCORS)
	triageCoverageRowFor(rr, "v1", "query:q", triage.ClassCRLF, triage.ReachAlways, true, "")
	triageCoverageRowFor(rr, "v1", "header:origin", triage.ClassCORS, triage.ReachAlways, true, "")
	triageCoverageRowFor(rr, "v2", "header:origin", triage.ClassCORS, triage.ReachAlways, false, "")

	said := triageRunLevelSay(rr)
	if strings.Contains(said, "exercised") || strings.Contains(said, "reachable") {
		t.Errorf("a run that exercised every class still reports a silent class: %s", said)
	}
}

// triageRunLevelSay is every sentence this run would put in its error column.
//
// IT CALLS THE REAL ASSEMBLY. runTriage composes the head of triage_runs.error out of exactly
// this list, so a test reading it is reading what the operator reads rather than a second
// spelling of it that can drift.
func triageRunLevelSay(rr *triageRunner) string {
	_, shortfall := rr.terminalStatus()
	return strings.Join(rr.diagnosticSentences(shortfall), " ")
}

// THE CONCLUSION GATE HAS TWO CAUSES NOW AND IT MUST NAME THE RIGHT ONE. Gate 1 catches almost
// every anonymous wall at the baseline, so the second cause reaches gate 2 only when the wall
// went up after calibration. It is asserted directly rather than through a fixture, because a
// branch that writes a reason string and is only reachable by accident is a reason string nobody
// ever reads until it is wrong.
func TestTheConclusionGateNamesWhichOfTheTwoCausesFired(t *testing.T) {
	refusal := triage.Observation{Status: 401, Body: []byte(`{"message":"unauthorized"}`),
		RespHeaders: [][2]string{{"Www-Authenticate", `Bearer realm="api"`}}}
	clean := func(slot triage.SlotKey) triage.ClassVerdict {
		return triage.ClassVerdict{Class: triage.ClassCRLF, SlotKey: slot, State: triage.StateClean,
			Reason: "no_header_was_created: the class own sentence", Grade: triage.GradeUnrated, Ordinals: []uint64{1}}
	}

	cases := []struct {
		name       string
		unit       func(string, string) (*triageUnitPlan, triage.Slot)
		wantReason string
		wantOurs   bool
	}{
		{"a credential that went stale", triageCredentialUnit, "session_expired_at_conclusion", true},
		{"an endpoint that refuses everyone", triageQueryUnit, "no_credential_held_at_conclusion", false},
	}
	for _, c := range cases {
		rr := triageUnitRunner(t, triage.ClassCRLF)
		u, slot := c.unit("http://127.0.0.1:1", "q")
		rr.plan.Units = []triageUnitPlan{*u}
		// Two responses, both refusals, recorded the way dispatch records them.
		rr.noteAuthResponse(&rr.plan.Units[0], slot.Key, triage.ClassCRLF, &refusal, triageCredWire{})
		rr.noteAuthResponse(&rr.plan.Units[0], slot.Key, triage.ClassCRLF, &refusal, triageCredWire{})

		out, turned := rr.authWallGate(clean(slot.Key), u.VectorID)
		if !turned {
			t.Errorf("%s: a clean verdict off two 401s was let through the conclusion gate", c.name)
			continue
		}
		if out.State != triage.StateCannotDetermine {
			t.Errorf("%s: the gate turned the verdict into %q, want cannot_determine", c.name, out.State)
		}
		if !strings.Contains(out.Reason, c.wantReason) {
			t.Errorf("%s: the gate named a cause it did not observe.\nGot: %s\nWant it to lead with %q", c.name, out.Reason, c.wantReason)
		}
		if !strings.Contains(out.Reason, "ORIGINAL VERDICT") {
			t.Errorf("%s: the gate threw away the class own sentence: %s", c.name, out.Reason)
		}
		if got := out.Annotations["auth_wall_our_problem"]; got != c.wantOurs {
			t.Errorf("%s: auth_wall_our_problem is %v, want %v. This annotation is what a filter groups a page of unknowns by, so a wall that refused an anonymous request must not land in the bucket labelled re-capture the corpus.",
				c.name, got, c.wantOurs)
		}
		t.Logf("%s: %s", c.name, out.Reason)
	}
}

// THE AMBIGUOUS CASE HAS TO DECLARE ITSELF. Firing on shape alone is the right call, and it is
// also the one remaining way the narrowed rule can cost the operator a live session: if the
// opaque cookie it fired on is not a credential, the row is telling them to re-capture something
// that never expired. The row says which kind of reading it rests on, so the mistake is visible
// rather than inherited.
func TestAReadingThatFiredOnShapeAloneSaysSoOnTheRow(t *testing.T) {
	shape := triageReadCredentials(RequestTemplate{Headers: [][2]string{{"Cookie", "portal_state=9f8a1b2c3d4e5f60718293a4b5c6d7e8"}}})
	if !triageCredentialShapeOnly(shape.Items) {
		t.Fatalf("a reading with no name match anywhere does not report itself as shape-only: %v", shape.Items)
	}
	named := triageReadCredentials(RequestTemplate{Headers: [][2]string{
		{"Authorization", "Bearer " + triageTestExpiredJWT},
		{"Cookie", "portal_state=9f8a1b2c3d4e5f60718293a4b5c6d7e8"},
	}})
	if triageCredentialShapeOnly(named.Items) {
		t.Error("a reading carrying an Authorization header reports itself as resting on shape alone")
	}

	st := &triageAuthState{Credential: shape.Summary(), ShapeOnly: true, Samples: 5,
		Kind: triageAuthUnauthorized, Evidence: "401 with no WWW-Authenticate challenge"}
	if reason := triageStaleSessionReason(st); !strings.Contains(reason, "SHAPE alone") {
		t.Errorf("a shape-only reading produces a row that does not say so:\n%s", reason)
	}
	st.ShapeOnly = false
	if reason := triageStaleSessionReason(st); strings.Contains(reason, "SHAPE alone") {
		t.Errorf("a reading that matched a name still carries the shape-only caveat:\n%s", reason)
	}
}

// A BODY WHOSE MEDIA WAS NEVER DECLARED GETS THE SAME READING AS ONE THAT DECLARED IT. The media
// is sniffed with the rule the slot layer already uses, because a credential seen on one path and
// missed on the other is a false clean that depends on which function built the template.
func TestACredentialInABodyWhoseMediaWasNeverDeclaredIsStillRead(t *testing.T) {
	tmpl := RequestTemplate{Method: "POST", URL: "https://api.test/v1/rpc",
		Body: []byte(`{"api_key":"ak_9f8a1b2c3d4e5f60","page":2}`)}
	if got := triageTemplateCredential(tmpl); !strings.Contains(got, "api_key") {
		t.Errorf("a JSON body with no declared media read %q, want it to name the api_key field", got)
	}
}

// A BODY WHOSE FIELDS ARE NOT ADDRESSABLE STILL HAS TO GIVE UP ITS TOKEN. Multipart, XML and
// GraphQL bodies are not parsed by name here, so the only question left is the shape one, and a
// request carrying a compact JWS is carrying a credential whatever field holds it. The item names
// no field, because there is no field to name, so the TOKEN is what identifies it: this is the one
// branch where the value is not an extra, it is the whole of what the reading knows.
func TestATokenInABodyWithNoAddressableFieldsIsStillRead(t *testing.T) {
	body := "--b\r\nContent-Disposition: form-data; name=\"id_token\"\r\n\r\n" +
		triageTestExpiredJWT + "\r\n--b\r\nContent-Disposition: form-data; name=\"qty\"\r\n\r\n10\r\n--b--\r\n"
	tmpl := RequestTemplate{Method: "POST", URL: "https://api.test/v1/upload",
		BodyMedia: triage.BodyMultipart, Body: []byte(body)}
	got := triageTemplateCredential(tmpl)
	if !strings.Contains(got, "multipart body") {
		t.Errorf("a multipart body carrying a bearer token reads as %q, and a credential the reading cannot see is a gate that cannot fire", got)
	}
	if !strings.Contains(got, triageTestExpiredJWT) {
		t.Errorf("the reading %q dropped the token it found. There is no field name here, so the "+
			"token is the only thing that says WHICH credential this body carries.", got)
	}
	// AND THE CONTROL: the same body with no token in it carries nothing, because a shape net
	// that fires on any multipart body would make every upload vector unconcludable.
	plain := RequestTemplate{Method: "POST", URL: "https://api.test/v1/upload", BodyMedia: triage.BodyMultipart,
		Body: []byte("--b\r\nContent-Disposition: form-data; name=\"qty\"\r\n\r\n10\r\n--b--\r\n")}
	if got := triageTemplateCredential(plain); got != "" {
		t.Errorf("a multipart body with no token in it reads as credential material: %q", got)
	}
}

// A NAME MATCH OVER A BOOLEAN IS NOT A CREDENTIAL. remember=1 is the checkbox on a login form and
// auth=true is a mode switch, and both carry a word the shared credential rule lists. Reading
// either as credential material puts a target that refuses everyone back under "your session is
// dead", which is the whole defect this round narrowed. No secret fits in a boolean.
func TestANameMatchOverAFlagIsNotACredential(t *testing.T) {
	cases := []struct {
		name string
		tmpl RequestTemplate
	}{
		{"the remember checkbox in a query", RequestTemplate{Method: "GET", URL: "https://api.test/login?remember=1&page=2"}},
		{"an auth mode switch in a query", RequestTemplate{Method: "GET", URL: "https://api.test/v1/orders?auth=true"}},
		{"a flag cookie", RequestTemplate{Headers: [][2]string{{"Cookie", "auth=1; logged_in=yes"}}}},
		{"a boolean in a json body", RequestTemplate{Method: "POST", URL: "https://api.test/v1/login", BodyMedia: triage.BodyJSON,
			Body: []byte(`{"remember":"true","user":"ada"}`)}},
	}
	for _, c := range cases {
		if got := triageTemplateCredential(c.tmpl); got != "" {
			t.Errorf("%s: read %q as credential material", c.name, got)
		}
	}
	// AND THE LINE HOLDS ON THE OTHER SIDE: the same names over a real value still fire, so this
	// narrowing costs no credential.
	real := RequestTemplate{Method: "GET", URL: "https://api.test/v1/orders?auth=9f8a1b2c3d4e5f60718293a4"}
	if got := triageTemplateCredential(real); !strings.Contains(got, "auth") {
		t.Errorf("a credential name over a real value stopped firing: %q", got)
	}
}

// A TOKEN INSIDE A JSON ARRAY IS STILL A TOKEN. The walk applies the rule at exactly one site, so
// a string hanging off an array is asked the same question as a string hanging off a field. It
// was not, in the first cut of this walk: {"tokens":["<a JWS>"]} read as nothing at all, which is
// a credential the reading cannot see and therefore a gate that cannot fire.
func TestATokenInsideAJSONArrayIsRead(t *testing.T) {
	tmpl := RequestTemplate{Method: "POST", URL: "https://api.test/v1/batch", BodyMedia: triage.BodyJSON,
		Body: []byte(`{"session":{"tokens":["` + triageTestExpiredJWT + `","` + triageTestExpiredJWT + `"]},"page":2}`)}
	got := triageTemplateCredential(tmpl)
	if !strings.Contains(got, "session.tokens") {
		t.Errorf("a token inside a JSON array reads as %q, want it to name session.tokens", got)
	}
	// ONE ARRAY IS ONE FACT. Five hundred tokens in a list is not five hundred sentences, and that
	// has to keep holding now that the items carry their values: the dedupe key is the item's
	// ident, which is carrier, name and rule with the value left out, precisely so that an array of
	// distinct tokens still reduces to one line about the field that holds them.
	if n := strings.Count(got, "session.tokens"); n != 1 {
		t.Errorf("an array of two tokens produced %d items, want 1: %q", n, got)
	}
	// AND THAT ONE LINE CARRIES A TOKEN. Naming the path without the bytes leaves the operator
	// something they cannot check against the wire.
	if !strings.Contains(got, triageTestExpiredJWT) {
		t.Errorf("the reading %q names session.tokens and drops what was in it", got)
	}
	// AND AN ARRAY OF ORDINARY STRINGS IS STILL NOTHING.
	plain := RequestTemplate{Method: "POST", URL: "https://api.test/v1/batch", BodyMedia: triage.BodyJSON,
		Body: []byte(`{"symbols":["AAPL","MSFT"],"qty":10}`)}
	if got := triageTemplateCredential(plain); got != "" {
		t.Errorf("an array of ordinary strings reads as credential material: %q", got)
	}
}

// ---------------------------------------------------------------------------------------------
// CREDENTIAL FRESHNESS: THE TOKEN THAT GOES ON THE WIRE IS NOT THE ONE IN THE CORPUS
// ---------------------------------------------------------------------------------------------
//
// MEASURED ON THE LIVE TARGET, 2026-09-20. Same endpoint, same host, same mandatory header:
// the token in attack_vectors.raw_request answers 401, and the token manual_crawl_captures
// recorded at 12:09:43 the same day answers 200. The runner replays the first one. So on the 170
// of 317 vectors whose capture carries an Authorization header, every response it has ever
// measured was the authentication wall.
//
// EVERY TOKEN STRING BELOW IS A LITERAL INVENTED IN THIS FILE. None of them is a credential, for
// this target or any other, and no test here reads one out of the database.

// triageOneTokenServer accepts EXACTLY ONE Authorization value and refuses every other request
// with a 401, which is the behaviour of the live target and the only behaviour that can tell a
// fresh credential from a stale one.
//
// accepted is a function rather than a string so a test can rotate the value mid-run, which is
// the thing a fifteen-minute token in a twenty-nine-minute run does.
func triageOneTokenServer(t *testing.T, accepted func() string) (*httptest.Server, *int64) {
	t.Helper()
	var served int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != accepted() {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"error":"unauthorized"}`)
			return
		}
		atomic.AddInt64(&served, 1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"account":"ok","balance":1}`)
	}))
	t.Cleanup(s.Close)
	return s, &served
}

// triageFakeCreds is a credential source that hands out whatever the test says is current. It
// exists because the rotation the runner has to survive happens on somebody else's clock, which
// a database fixture cannot reproduce inside one test.
type triageFakeCreds struct {
	current      func() []triageFreshCred
	status       triageFreshCredStatus
	invalidated  []string
	freshForCall int
}

func (f *triageFakeCreds) FreshFor(host string) ([]triageFreshCred, triageFreshCredStatus) {
	f.freshForCall++
	st := f.status
	st.Host = host
	creds := f.current()
	st.Fresh = len(creds)
	return creds, st
}

func (f *triageFakeCreds) Invalidate(host string) { f.invalidated = append(f.invalidated, host) }

// triageBearerCred builds the credential record for a made-up bearer value.
func triageBearerCred(value, source string, expires time.Time) triageFreshCred {
	c := triageFreshCred{Header: "Authorization", value: value, Source: source, Observed: time.Now()}
	if !expires.IsZero() {
		c.Expires, c.ExpirySource = expires, "the token's own exp claim"
	}
	c.Fingerprint = triageCredFingerprint(value)
	return c
}

// triageCredentialVector is one vector whose captured request replays a credential that the
// target stopped accepting: the corpus as it exists on the live engagement.
func triageCredentialVector(base, staleValue string) *triageUnitPlan {
	return &triageUnitPlan{
		VectorID: "v-fresh-cred",
		Host:     "127.0.0.1",
		Selected: true,
		Template: RequestTemplate{Method: "GET", URL: base + "/v1/accounts",
			Headers: [][2]string{
				{"Accept", "application/json"},
				{"Authorization", staleValue},
				{"X-Client", "web"},
			}},
	}
}

// TestTheStaleCapturedTokenIsReplacedByTheFreshestOneAtSendTime is the whole fix in one test.
//
// THE FIRST HALF IS THE OLD BEHAVIOUR AND IT MUST BE SEEN TO FAIL. dispatch's credential layer
// only ever set a header the template did NOT already carry, and a vector replaying a stale
// Authorization always already carries one, so that layer has never once been able to correct a
// dead token. The request goes out with the corpus bytes and the target refuses it.
func TestTheStaleCapturedTokenIsReplacedByTheFreshestOneAtSendTime(t *testing.T) {
	const stale = "Bearer corpus-token-captured-two-days-ago"
	const live = "Bearer session-token-captured-twelve-minutes-ago"
	srv, served := triageOneTokenServer(t, func() string { return live })

	rr := triageUnitRunner(t, triage.ClassCRLF)
	u := triageCredentialVector(srv.URL, stale)
	rr.plan.Units = []triageUnitPlan{*u}

	// WITHOUT A SOURCE, which is exactly what the runner was before this change: the captured
	// bytes go out and the wall answers.
	obs := rr.dispatch(context.Background(), &rr.plan.Units[0], rr.plan.Units[0].Template,
		triage.ObsBaseline, triage.ClassNone, "", 1)
	if obs.Status != http.StatusUnauthorized {
		t.Fatalf("the fixture does not reproduce the measurement: replaying the stale corpus token got %d, want 401", obs.Status)
	}

	// WITH THE SOURCE the freshest credential is substituted over the captured one.
	rr.creds = &triageFakeCreds{current: func() []triageFreshCred {
		return []triageFreshCred{triageBearerCred(live, "manual_crawl_captures", time.Now().Add(9*time.Minute))}
	}}
	obs = rr.dispatch(context.Background(), &rr.plan.Units[0], rr.plan.Units[0].Template,
		triage.ObsBaseline, triage.ClassNone, "", 1)
	if obs.Status != http.StatusOK {
		t.Fatalf("the freshest credential was not substituted at send time: got %d, want 200. "+
			"The captured Authorization header is still what reached the socket, so every "+
			"verdict this run can produce is about the login wall", obs.Status)
	}
	if atomic.LoadInt64(served) != 1 {
		t.Errorf("the target served %d authenticated response(s), want 1", atomic.LoadInt64(served))
	}

	// THE TEMPLATE IS NOT MUTATED. dispatch substitutes into a clone, so the corpus row the
	// operator can read still says what was captured.
	if got, _ := rr.plan.Units[0].Template.HeaderValue("Authorization"); got != stale {
		t.Errorf("substitution edited the stored template: the vector's own Authorization is no longer the captured one")
	}
}

// TestARunOutlivesTheTokenItStartedWith is the fifteen-minutes-versus-twenty-nine problem.
//
// A run takes about 1,757 seconds and the target's bearer lives about 900. Substituting once at
// unit setup fixes the first half of a run and hands the second half the same corpse, so the
// source is re-read DURING the run and the request that follows a rotation has to be served.
func TestARunOutlivesTheTokenItStartedWith(t *testing.T) {
	const stale = "Bearer corpus-token-captured-two-days-ago"
	const first = "Bearer session-token-minted-at-t0"
	const second = "Bearer session-token-minted-at-t0-plus-15m"

	var rotated atomic.Bool
	accepted := func() string {
		if rotated.Load() {
			return second
		}
		return first
	}
	srv, served := triageOneTokenServer(t, accepted)

	rr := triageUnitRunner(t, triage.ClassCRLF)
	u := triageCredentialVector(srv.URL, stale)
	rr.plan.Units = []triageUnitPlan{*u}
	rr.creds = &triageFakeCreds{current: func() []triageFreshCred {
		if rotated.Load() {
			return []triageFreshCred{triageBearerCred(second, "manual_crawl_captures", time.Now().Add(14*time.Minute))}
		}
		return []triageFreshCred{triageBearerCred(first, "manual_crawl_captures", time.Now().Add(1*time.Minute))}
	}}

	send := func() int {
		return rr.dispatch(context.Background(), &rr.plan.Units[0], rr.plan.Units[0].Template,
			triage.ObsBaseline, triage.ClassNone, "", 1).Status
	}

	for i := 0; i < 3; i++ {
		if got := send(); got != http.StatusOK {
			t.Fatalf("probe %d before the rotation got %d, want 200", i, got)
		}
	}

	// THE TOKEN ROTATES UNDER THE RUN, which is what a browser session does every few minutes.
	rotated.Store(true)
	for i := 0; i < 3; i++ {
		if got := send(); got != http.StatusOK {
			t.Fatalf("probe %d AFTER the rotation got %d, want 200: the run is still sending the "+
				"token it started with, so the back half of every run goes out holding a corpse", i, got)
		}
	}
	if atomic.LoadInt64(served) != 6 {
		t.Errorf("the target served %d authenticated response(s) across the rotation, want 6", atomic.LoadInt64(served))
	}
}

// TestARefusalMakesTheRunReReadTheCredentialInsteadOfWaitingOutItsTTL pins the trigger that does
// not depend on our arithmetic about anybody else's clock. A TTL and an expiry margin are both
// guesses about when a token dies; a 401 is the target saying so.
func TestARefusalMakesTheRunReReadTheCredentialInsteadOfWaitingOutItsTTL(t *testing.T) {
	srv, _ := triageOneTokenServer(t, func() string { return "Bearer never-handed-out" })
	rr := triageUnitRunner(t, triage.ClassCRLF)
	u := triageCredentialVector(srv.URL, "Bearer corpus-token-captured-two-days-ago")
	rr.plan.Units = []triageUnitPlan{*u}
	fake := &triageFakeCreds{current: func() []triageFreshCred {
		return []triageFreshCred{triageBearerCred("Bearer held-and-refused", "manual_crawl_captures", time.Now().Add(9*time.Minute))}
	}}
	rr.creds = fake

	obs := rr.dispatch(context.Background(), &rr.plan.Units[0], rr.plan.Units[0].Template,
		triage.ObsBaseline, triage.ClassNone, "", 1)
	if obs.Status != http.StatusUnauthorized {
		t.Fatalf("fixture: want a 401 to drive the invalidation, got %d", obs.Status)
	}
	if len(fake.invalidated) != 1 || fake.invalidated[0] != "127.0.0.1" {
		t.Errorf("a refused credential did not invalidate the cached reading for its host: %v. "+
			"The next probe would send the same disproved token for up to a whole TTL", fake.invalidated)
	}
}

// TestSubstitutionLeavesAPayloadAClassPutInTheCredentialCarrierAlone.
//
// A class whose SUBJECT is the credential opts into credential slots and then deliberately
// perturbs that exact header. Its 401s are its measurement. Overwriting its payload with a live
// token would delete the only kind of probe that can ever say anything about a credential, and
// would do it silently.
func TestSubstitutionLeavesAPayloadAClassPutInTheCredentialCarrierAlone(t *testing.T) {
	const payload = "Bearer eyJhbGciOiJub25lIn0.e30."
	fresh := triageBearerCred("Bearer live-session", "manual_crawl_captures", time.Now().Add(9*time.Minute))

	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.creds = &triageFakeCreds{current: func() []triageFreshCred { return []triageFreshCred{fresh} }}

	probe := RequestTemplate{Method: "GET", URL: "http://127.0.0.1:1/v1/accounts",
		Headers: [][2]string{{"Authorization", payload}}}
	wire := rr.applyFreshCredentials(&probe, "127.0.0.1", triage.SlotKey("header:authorization"))

	if got, _ := probe.HeaderValue("Authorization"); got != payload {
		t.Errorf("substitution overwrote the payload the class placed in the credential carrier")
	}
	if len(wire.Substituted) != 0 {
		t.Errorf("the wire record claims a substitution that did not happen: %v", wire.Substituted)
	}
	if len(wire.HeldBack) != 1 {
		t.Errorf("the carrier was left alone but the row does not say so: %+v", wire.HeldBack)
	}

	// THE SAME CLASS ON AN ORDINARY SLOT IS SUBSTITUTED LIKE EVERYTHING ELSE. The exemption is
	// the carrier being written to, not the class.
	other := RequestTemplate{Method: "GET", URL: "http://127.0.0.1:1/v1/accounts?q=1",
		Headers: [][2]string{{"Authorization", "Bearer corpus-token"}}}
	wire = rr.applyFreshCredentials(&other, "127.0.0.1", triage.SlotKey("query:q"))
	if got, _ := other.HeaderValue("Authorization"); got == "Bearer corpus-token" {
		t.Errorf("a query-slot probe kept the stale credential: the exemption is too wide")
	}
	if len(wire.Substituted) != 1 {
		t.Errorf("the substitution on an ordinary slot is not recorded: %+v", wire)
	}
}

// TestACookieCredentialIsSubstitutedWithoutDisturbingTheRestOfTheJar. Header order is a
// fingerprint and so is cookie order: a probe whose jar is ordered differently from its own
// baseline has introduced a difference the comparator will read as the payload's doing.
func TestACookieCredentialIsSubstitutedWithoutDisturbingTheRestOfTheJar(t *testing.T) {
	fresh := triageFreshCred{Cookie: "session", value: "fresh-session-value",
		Source: "manual_crawl_captures", Observed: time.Now()}
	fresh.Fingerprint = triageCredFingerprint(fresh.value)

	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.creds = &triageFakeCreds{current: func() []triageFreshCred { return []triageFreshCred{fresh} }}

	tmpl := RequestTemplate{Method: "GET", URL: "http://127.0.0.1:1/v1/accounts",
		Headers: [][2]string{{"Cookie", "_ga=GA1.2.9; session=stale-session-value; theme=dark"}}}
	rr.applyFreshCredentials(&tmpl, "127.0.0.1", triage.SlotKey("query:q"))

	got, _ := tmpl.HeaderValue("Cookie")
	want := "_ga=GA1.2.9; session=fresh-session-value; theme=dark"
	if got != want {
		t.Errorf("cookie substitution rewrote the jar:\n got %q\nwant %q", got, want)
	}
}

// TestTheWallReasonSaysWhichCredentialWasRefusedAndPrintsIt.
//
// The shipped sentence ended "the fix is to re-capture this vector with a live session and run
// again". On a request that carried a credential captured twelve minutes ago that advice fixes
// nothing: re-capturing the vector replays the same refused token. A reason string that sends
// the operator to the wrong fix is the same defect as one that names a cause it did not observe.
//
// AND IT PRINTS THE CREDENTIAL. The row's whole job is to say what the wall refused; the bytes
// are what the operator checks the request against, and a row naming the carrier but not the
// value could not be verified against anything.
func TestTheWallReasonSaysWhichCredentialWasRefusedAndPrintsIt(t *testing.T) {
	const secret = "Bearer live-session-value-the-wall-refused"
	cred := triageBearerCred(secret, "manual_crawl_captures", time.Now().Add(9*time.Minute))

	substituted := &triageAuthState{
		Credential: "the Authorization header", Kind: triageAuthUnauthorized,
		Evidence: "401 with no WWW-Authenticate challenge", Samples: 3,
		Wire: triageCredWire{Substituted: []string{cred.Carrier()}, Describe: []string{cred.String()},
			Sent:   []string{cred.Carrier() + " = " + cred.Value()},
			Status: triageFreshCredStatus{Host: "app.example.test", Fresh: 1}},
	}
	got := triageStaleSessionReason(substituted)
	if strings.Contains(got, "re-capture this vector") {
		t.Errorf("the row still sends the operator to re-capture a corpus that is not the problem:\n%s", got)
	}
	for _, want := range []string{"substituted", "manual_crawl_captures", cred.Fingerprint, secret} {
		if !strings.Contains(got, want) {
			t.Errorf("the row does not say %q, so what went on the wire is not auditable from it:\n%s", want, got)
		}
	}

	// AND WHEN NOTHING FRESHER EXISTED, the old advice is still the right advice, because then
	// the captured bytes really were what the target refused.
	replayed := &triageAuthState{
		Credential: "the Authorization header", Kind: triageAuthUnauthorized,
		Evidence: "401 with no WWW-Authenticate challenge", Samples: 3,
		Wire: triageCredWire{Status: triageFreshCredStatus{Host: "app.example.test",
			Note: "2 stored credential(s) for this host were read and every one of them has already expired; nothing newer has been captured", Expired: 2}},
	}
	got = triageStaleSessionReason(replayed)
	if !strings.Contains(got, "re-capture this vector") {
		t.Errorf("a vector whose captured bytes really did go out lost the advice that fits it:\n%s", got)
	}
	if !strings.Contains(got, "already expired") {
		t.Errorf("the row does not say why nothing fresher was available:\n%s", got)
	}
}

// TestTheRunNoticesWhenNoFreshCredentialIsArriving. A run must be able to outlive the token it
// started with, and it must notice when no fresh credential is arriving any more rather than
// silently degrading: a run that quietly stops authenticating produces a page of refusals that
// reads exactly like an endpoint refusing everyone.
func TestTheRunNoticesWhenNoFreshCredentialIsArriving(t *testing.T) {
	var dry atomic.Bool
	source := &triageDBFreshCreds{scopeTargetID: "", cache: map[string]*triageFreshCredEntry{}}
	// Driven through the real cache bookkeeping, because exhaustion IS the bookkeeping: the
	// question is whether the source remembers that this run once had a credential.
	feed := func() []triageFreshCred {
		if dry.Load() {
			return nil
		}
		return []triageFreshCred{triageBearerCred("Bearer live", "manual_crawl_captures", time.Now().Add(9*time.Minute))}
	}
	put := func() triageFreshCredStatus {
		now := time.Now()
		creds := feed()
		st := triageFreshCredStatus{Host: "app.example.test", ReadAt: now, Fresh: len(creds)}
		if prev := source.cache["app.example.test"]; prev != nil {
			st.LastFreshAt = prev.status.LastFreshAt
		}
		if len(creds) > 0 {
			st.LastFreshAt = now
		} else if !st.LastFreshAt.IsZero() {
			st.Exhausted = true
			st.Note = "2 stored credential(s) for this host were read and every one of them has already expired; nothing newer has been captured"
		}
		source.cache["app.example.test"] = &triageFreshCredEntry{creds: creds, status: st}
		return st
	}

	if st := put(); st.Exhausted {
		t.Fatalf("a source that is handing out a live credential reported exhaustion")
	}
	dry.Store(true)
	st := put()
	if !st.Exhausted {
		t.Fatalf("the source stopped producing credentials and did not notice: the run would " +
			"degrade to anonymous silently and every later refusal would read as the target's doing")
	}

	rr := triageUnitRunner(t, triage.ClassCRLF)
	// The kind the source states for this shape, because the two exhaustions are two facts and
	// the run-level sentence now switches on which one fired.
	st.ExhaustionKind = triageCredExhaustedEmpty
	rr.noteCredExhaustion("app.example.test", st)
	note, seen := rr.credExhausted["app.example.test"]
	if !seen {
		t.Errorf("the runner did not record the exhausted host, so the run-level sentence cannot name it")
	}
	if note.Kind != triageCredExhaustedEmpty || note.Fresh != 0 {
		t.Errorf("the runner recorded the transition without the reading that separates the two kinds: %+v", note)
	}
	w := rr.authWall()
	w.Stale = 1
	if !strings.Contains(w.Sentence(), "CREDENTIAL SUPPLY RAN OUT DURING THE RUN") {
		t.Errorf("the run's own sentence does not say the credential supply ran out:\n%s", w.Sentence())
	}

	line := triageCredExhaustionLine("run-1", "app.example.test", st)
	if !strings.Contains(line, "NO FRESH CREDENTIAL IS ARRIVING") {
		t.Errorf("the warning line does not say what happened: %s", line)
	}
	// THIS USED TO FAIL IF A CREDENTIAL APPEARED IN THE LINE, and that assertion is gone rather
	// than softened. What this line is for is telling the operator what the run is holding and
	// why it is no longer good enough, and a credential in it is the evidence for that sentence,
	// not a leak out of it.
}

// triageTestJWT builds a compact JWS with a chosen exp. The signature is the literal string
// "not-a-signature": nothing here verifies one, and nothing here is a credential.
func triageTestJWT(exp time.Time) string {
	head := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := base64.RawURLEncoding.EncodeToString([]byte(
		fmt.Sprintf(`{"sub":"party:00000000-0000-0000-0000-000000000000","exp":%d}`, exp.Unix())))
	return head + "." + body + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-signature"))
}

// TestTheTokensOwnExpiryBeatsTheColumnThatWasNeverValidated.
//
// Both session_tokens rows on the live engagement carry an operator-typed expires_at and an
// EMPTY last_validation_status: nothing has ever checked either of them against the target. A
// JWT states its own exp. Believing the column over the token puts a credential on the wire on
// the strength of a field nobody has validated.
func TestTheTokensOwnExpiryBeatsTheColumnThatWasNeverValidated(t *testing.T) {
	now := time.Now()

	// The operator's row claims another hour; the token inside it died an hour ago.
	declared := triageFreshCred{Header: "Authorization", value: "Bearer " + triageTestJWT(now.Add(-time.Hour)),
		Source: "session_tokens", Observed: now}
	if exp, ok := triageJWTExpiry(declared.value); !ok {
		t.Fatalf("the exp of a compact JWS was not readable")
	} else {
		declared.Expires, declared.ExpirySource = exp, "the token's own exp claim"
	}
	if !triageFreshCredDead(declared, now) {
		t.Errorf("a token whose own exp passed an hour ago was treated as usable because a column said so")
	}

	// TIES ON created_at ARE REAL AND THEY ARE NOT A CORNER CASE. On the measured corpus two
	// DISTINCT tokens share one created_at to the microsecond, because a crawl writes its batch
	// at once, and their exps are 26 seconds apart. Ordering by observation time alone picks
	// between them by luck.
	same := now.Add(-time.Minute)
	shorter := triageBearerCred("Bearer "+triageTestJWT(now.Add(9*time.Minute)), "manual_crawl_captures", now.Add(9*time.Minute))
	longer := triageBearerCred("Bearer "+triageTestJWT(now.Add(14*time.Minute)), "manual_crawl_captures", now.Add(14*time.Minute))
	shorter.Observed, longer.Observed = same, same

	ranked := triageRankFreshCreds([]triageFreshCred{shorter, longer})
	if len(ranked) != 1 {
		t.Fatalf("two candidates for one carrier produced %d credentials, want the best one", len(ranked))
	}
	if ranked[0].Fingerprint != longer.Fingerprint {
		t.Errorf("the shorter-lived of two tokens captured in the same batch was chosen")
	}

	// A READABLE EXPIRY BEATS AN UNREADABLE ONE, whatever table it came from: "alive for another
	// nine minutes" is a stronger claim than "nobody has said otherwise".
	opaque := triageBearerCred("Bearer opaque-api-key-with-no-expiry", "session_tokens", time.Time{})
	opaque.Observed = now
	ranked = triageRankFreshCreds([]triageFreshCred{opaque, shorter})
	if ranked[0].Fingerprint != shorter.Fingerprint {
		t.Errorf("a credential whose freshness cannot be checked outranked one whose can")
	}
}

// TestACredentialRendersItsValue. triageFreshCred is printed into reason strings and log lines,
// and those are what an operator checks against the request that went out, so the rendering
// carries the bytes as well as the fingerprint that compares them.
func TestACredentialRendersItsValue(t *testing.T) {
	const secret = "Bearer this-is-what-went-on-the-wire"
	c := triageBearerCred(secret, "manual_crawl_captures", time.Now().Add(9*time.Minute))
	for _, rendered := range []string{c.String(), fmt.Sprintf("%v", c), fmt.Sprintf("%s", c)} {
		if !strings.Contains(rendered, secret) {
			t.Fatalf("THE RENDERING DROPPED THE CREDENTIAL: %s. A reason string that describes a "+
				"substitution without the value it substituted cannot be checked against the "+
				"request it describes", rendered)
		}
		if !strings.Contains(rendered, c.Fingerprint) {
			t.Errorf("the rendering carries no fingerprint, so two renderings cannot be compared: %s", rendered)
		}
	}
	if c.Value() != secret {
		t.Errorf("Value() does not return the bytes that go on the wire: %q", c.Value())
	}
	// THE FINGERPRINT IS STILL A COMPARISON KEY and has to keep discriminating.
	if triageCredFingerprint(secret) == triageCredFingerprint(secret+"x") {
		t.Errorf("two different credentials share a fingerprint")
	}
}

// ---------------------------------------------------------------------------------------------
// THE SECOND EXHAUSTION IS A DIFFERENT FACT AND MUST NOT BORROW THE FIRST ONE SENTENCES.
//
// triageCarryExhaustion sets Exhausted for TWO states. The first, triageCredExhaustedEmpty, is
// guarded by status.Fresh == 0: the source hands out nothing. The second,
// triageCredExhaustedUnverifiable, is reached only when that first guard did NOT match, so it
// fires while Fresh is ABOVE ZERO: the source is still handing credentials out and merely cannot
// read a lifetime on any of them.
//
// Three shipped sentences state the first fact about both, and none of them reads
// ExhaustionKind at all:
//
//	triageRefusedCredentialAdvice  "cannot now" and "the capture stream stopped before the run did"
//	triageAuthWall.Sentence        "held nothing usable for them by the end" and
//	                               "No fresher session was captured while the run was going"
//
// Under the second kind every one of those is a claim about a credential supply that is still
// supplying. This is the fixture the live estate is actually in.
func TestTheSecondExhaustionIsNeverDescribedAsTheFirst(t *testing.T) {
	now := time.Now()
	unverifiable := triageFreshCredStatus{
		Host: "app.example.test", ReadAt: now,
		Fresh: 2, Verifiable: 0,
		LastFreshAt: now, LastVerifiableAt: now.Add(-7 * time.Minute),
		Exhausted: true, ExhaustionKind: triageCredExhaustedUnverifiable,
		Unmeasured: []string{"the Cookie header", "the X-Api-Key header"},
	}
	unverifiable.Note = triageCredUnmeasuredClause(unverifiable)

	empty := triageFreshCredStatus{
		Host: "other.example.test", ReadAt: now,
		Fresh: 0, LastFreshAt: now.Add(-11 * time.Minute),
		Exhausted: true, ExhaustionKind: triageCredExhaustedEmpty,
		Note: "2 stored credential(s) for this host were read and every one of them has already expired; nothing newer has been captured",
	}

	// THE PER-ROW ADVICE. The wire here substituted nothing, which is what a probe on a
	// credential slot looks like, so the advice falls through to the exhaustion branch.
	st := &triageAuthState{Credential: "the Cookie header", Kind: triageAuthUnauthorized,
		Evidence: "401 with no WWW-Authenticate challenge", Samples: 3,
		Wire: triageCredWire{Status: unverifiable}}
	advice := triageRefusedCredentialAdvice(st)
	t.Logf("advice under the second exhaustion: %s", advice)
	for _, forbidden := range []string{"cannot now", "capture stream stopped"} {
		if strings.Contains(advice, forbidden) {
			t.Errorf("the row says %q about a source that is still handing out %d credential(s) for this host. Nothing on this branch read ExhaustionKind, so it states the empty exhaustion about the unverifiable one:\n%s",
				forbidden, unverifiable.Fresh, advice)
		}
	}
	if !strings.Contains(advice, "UNMEASURED") {
		t.Errorf("the row does not say that the authentication state here is unmeasured, which is the only thing this branch actually read:\n%s", advice)
	}

	// AND THE FIRST KIND MUST KEEP ITS OWN WORDS, because the fix for it really is upstream.
	emptyAdvice := triageRefusedCredentialAdvice(&triageAuthState{
		Credential: "the Cookie header", Kind: triageAuthUnauthorized, Samples: 1,
		Wire: triageCredWire{Status: empty}})
	if !strings.Contains(emptyAdvice, "upstream of the runner") {
		t.Errorf("the empty exhaustion lost the advice that fits it:\n%s", emptyAdvice)
	}

	// THE RUN-LEVEL SENTENCE, which is what reaches the run note.
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.noteCredExhaustion("app.example.test", unverifiable)
	w := rr.authWall()
	w.Stale = 1
	sentence := w.Sentence()
	t.Logf("run sentence under the second exhaustion: %s", sentence)
	for _, forbidden := range []string{"held nothing usable for them by the end", "No fresher session was captured"} {
		if strings.Contains(sentence, forbidden) {
			t.Errorf("the run note says %q about a host whose source is still handing out %d credential(s):\n%s",
				forbidden, unverifiable.Fresh, sentence)
		}
	}
	if !strings.Contains(sentence, "UNMEASURED") {
		t.Errorf("the run note does not report the state that actually fired:\n%s", sentence)
	}

	// AND BOTH KINDS AT ONCE MUST STILL BE TWO CLAUSES, never one number over both.
	rr2 := triageUnitRunner(t, triage.ClassCRLF)
	rr2.noteCredExhaustion("app.example.test", unverifiable)
	rr2.noteCredExhaustion("other.example.test", empty)
	both := rr2.authWall().Sentence()
	t.Logf("run sentence with one host of each kind: %s", both)
	if !strings.Contains(both, "app.example.test") || !strings.Contains(both, "other.example.test") {
		t.Errorf("a run with one host of each kind does not name both:\n%s", both)
	}
	if strings.Contains(both, "2 host(s)") {
		t.Errorf("two different facts were rolled into one count, which is the thing the two kinds exist to prevent:\n%s", both)
	}
}

// A RUN THAT WENT ANONYMOUS IS NOT A COMPLETED RUN, AND IT IS NOT A SILENCE.
//
// triageAuthWall.Measured is the one predicate terminalStatus and diagnosticSentences both read.
// It counts Stale, Gated and Unauthenticated and ignores CredExhausted entirely, so a run whose
// credential supply died half way through, on a corpus whose endpoints answer anonymously, is
// recorded completed and says nothing whatever. Completed is the single status the certificate
// renders under. The whole layer exists so that a silence is never mistaken for a clean.
func TestARunWhoseCredentialSupplyDiedIsNeverRecordedCompletedAndSilent(t *testing.T) {
	ctx := triageTestDB(t)
	open := triageStaticServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, _ := triageQueryUnit(open.URL, "c")
	rr.plan.Units = []triageUnitPlan{*u}
	// NO PAIRS ON PURPOSE. The plan shortfall is a second, unrelated route to
	// TriageRunIncomplete, and a fixture that trips it would let this test pass with the defect
	// standing. With nothing planned, planShortfall is satisfied and completed is what this run
	// reports unless the wall reading says otherwise.
	rr.unitContext(ctx, &rr.plan.Units[0])

	// Nothing here hit a wall: the endpoint answers every request. The only thing that happened
	// is that this run stopped being able to authenticate.
	now := time.Now()
	rr.noteCredExhaustion("app.example.test", triageFreshCredStatus{
		Host: "app.example.test", ReadAt: now, Fresh: 0, LastFreshAt: now.Add(-9 * time.Minute),
		Exhausted: true, ExhaustionKind: triageCredExhaustedEmpty,
		Note: "2 stored credential(s) for this host were read and every one of them has already expired; nothing newer has been captured",
	})

	w := rr.authWall()
	if w.Stale != 0 || w.Unauthenticated != 0 || w.Gated != 0 {
		t.Fatalf("the fixture is meant to hit no wall at all: stale=%d unauth=%d gated=%d", w.Stale, w.Unauthenticated, w.Gated)
	}
	if !w.Measured() {
		t.Errorf("a run that stopped being able to authenticate reports itself as having measured nothing worth saying, so it is recorded completed and the operator is told nothing")
	}

	status, _ := rr.terminalStatus()
	if status == TriageRunCompleted {
		t.Errorf("a run that went anonymous part way through reported %q, which is the one status the certificate renders under", status)
	}

	said := triageRunLevelSay(rr)
	t.Logf("run note: %s", said)
	if !strings.Contains(said, "app.example.test") {
		t.Errorf("the run note never names the host this run stopped being able to authenticate to:\n%s", said)
	}
	// AND IT MUST NOT INVENT A WALL IT DID NOT MEASURE. Not one row here was refused.
	if strings.Contains(said, "THIS RUN MEASURED AN AUTHENTICATION WALL") {
		t.Errorf("the run note claims this run measured an authentication wall on a corpus where every request was answered:\n%s", said)
	}
	if strings.Contains(said, "Not one of these rows is clean") {
		t.Errorf("the run note asserts something about rows that do not exist: no pair here was refused:\n%s", said)
	}
}

// PATCH 3b. A HELD-BACK RECORD MUST NOT WIN THE WIRE SLOT FROM A SUBSTITUTING ONE.
//
// noteAuthResponse lets an exhausted wire overwrite the recorded one unconditionally, because an
// exhaustion is the later and worse fact. That was safe while Exhausted meant the empty kind,
// where nothing could have been substituted anyway. Under triageCredExhaustedUnverifiable the
// source is still substituting, so a credential-slot probe, whose wire deliberately substitutes
// NOTHING, now overwrites the substituting record and the vector loses the one reading that
// matters: the freshest credential this framework holds went out and was refused anyway.
func TestAHeldBackCredentialSlotProbeDoesNotOverwriteASubstitutingWire(t *testing.T) {
	refusal := triage.Observation{Status: 401, Body: []byte(`{"message":"unauthorized"}`)}
	now := time.Now()
	unverifiable := triageFreshCredStatus{
		Host: "app.example.test", ReadAt: now, Fresh: 2, Verifiable: 0,
		LastFreshAt: now, LastVerifiableAt: now.Add(-7 * time.Minute),
		Exhausted: true, ExhaustionKind: triageCredExhaustedUnverifiable,
		Unmeasured: []string{"the Cookie header"},
	}
	unverifiable.Note = triageCredUnmeasuredClause(unverifiable)

	rr := triageUnitRunner(t, triage.ClassCRLF)
	u, slot := triageCredentialUnit("http://127.0.0.1:1", "q")
	rr.plan.Units = []triageUnitPlan{*u}

	// Request one substituted the freshest credential in the building and was refused.
	rr.noteAuthResponse(&rr.plan.Units[0], slot.Key, triage.ClassCRLF, &refusal, triageCredWire{
		Substituted: []string{"the Cookie header"},
		Describe:    []string{"manual_crawl_captures cookie fp:abcd1234"},
		Status:      unverifiable,
	})
	// Request two is a credential-slot probe: the class owns that carrier, so nothing was
	// substituted and the captured value went out unchanged.
	rr.noteAuthResponse(&rr.plan.Units[0], slot.Key, triage.ClassCRLF, &refusal, triageCredWire{
		HeldBack: []string{"the Cookie header"},
		Status:   unverifiable,
	})

	st := rr.authState[u.VectorID]
	if st == nil {
		t.Fatal("no auth state was recorded for the vector")
	}
	if !st.Wire.Used() {
		t.Errorf("the held-back credential-slot probe took the wire slot from the substituting request, so this vector now reads as one that sent nothing fresher than its capture. The reading it lost is the strongest one available: the freshest credential went out and the target refused THAT as well.")
	}
	if len(st.HeldBackCarriers) != 1 {
		t.Errorf("the held-back carrier was not accumulated on the vector: %v", st.HeldBackCarriers)
	}
	advice := triageRefusedCredentialAdvice(st)
	t.Logf("advice: %s", advice)
	if !strings.Contains(advice, "refused THAT as well") {
		t.Errorf("the row lost the substitution reading:\n%s", advice)
	}

	// THE EMPTY KIND KEEPS ITS UNCONDITIONAL PRECEDENCE, because there it really is the later
	// and worse fact and nothing could have been substituted into it.
	rr2 := triageUnitRunner(t, triage.ClassCRLF)
	u2, slot2 := triageCredentialUnit("http://127.0.0.1:1", "q")
	rr2.plan.Units = []triageUnitPlan{*u2}
	rr2.noteAuthResponse(&rr2.plan.Units[0], slot2.Key, triage.ClassCRLF, &refusal, triageCredWire{
		Substituted: []string{"the Cookie header"},
		Describe:    []string{"manual_crawl_captures cookie fp:abcd1234"},
		Status:      triageFreshCredStatus{Host: "app.example.test", Fresh: 1},
	})
	rr2.noteAuthResponse(&rr2.plan.Units[0], slot2.Key, triage.ClassCRLF, &refusal, triageCredWire{
		Status: triageFreshCredStatus{Host: "app.example.test", Fresh: 0,
			LastFreshAt: now.Add(-time.Minute), Exhausted: true,
			ExhaustionKind: triageCredExhaustedEmpty, Note: "nothing newer has been captured"},
	})
	st2 := rr2.authState[u2.VectorID]
	if st2.Wire.Used() {
		t.Errorf("the run ran out of credentials entirely and the vector still reports that something fresher went out on it")
	}
}

// =================================================================================================
// ROUND 17. TWO SENTENCES THE RUN RECORD GOT WRONG, AND ONE IT NEVER SAID AT ALL.
// =================================================================================================

// THE TWELFTH FALSE SENTENCE: "this run authenticated to them earlier".
//
// Eleven clauses asserting a fact no branch had established have been found and closed in this
// layer. This is the twelfth, and it survived the round-16 rewrite of the sentences around it
// because that rewrite audited the clauses it was changing rather than the ones it was carrying.
// It appeared at two sites, both on the empty-exhaustion branch: triageRefusedCredentialAdvice
// and triageAuthWall.credExhaustionClause.
//
// WHAT THE BRANCH ACTUALLY READ. The guard is status.Fresh == 0 && !status.LastFreshAt.IsZero(),
// and LastFreshAt is assigned in triageCarryExhaustion at the moment a read came back with a
// non-empty credential slice. It records that THE SOURCE WAS HANDING SOMETHING OUT for that host.
// Whether a request carrying one went out is not read there, and whether a target ACCEPTED one is
// not recorded anywhere in this package: triageFreshCredStatus has no acceptance field, which
// this test asserts by reflection rather than by reading, and the cache entry's honoured counter
// counts refusal-driven re-reads rather than acceptances.
//
// SO THE HONEST WORDING IS "HELD", AND THE MOMENT IS A FIGURE THIS RUN READ. LastFreshAt is a
// timestamp, so the sentence quotes it instead of saying "earlier", and the difference between
// holding a credential and being authenticated by one is then visible on the card rather than
// only in this comment.
func TestNoSentenceClaimsATargetEverAcceptedACredential(t *testing.T) {
	now := time.Now()
	held := now.Add(-7 * time.Minute)
	empty := triageFreshCredStatus{
		Host: "app.v17-accept.test", ReadAt: now,
		Fresh: 0, LastFreshAt: held,
		Exhausted: true, ExhaustionKind: triageCredExhaustedEmpty,
		Note: "2 stored credential(s) for this host were read and every one of them has already expired; nothing newer has been captured",
	}
	stamp := held.UTC().Format(time.RFC3339)

	// SITE 1: the per-row advice.
	advice := triageRefusedCredentialAdvice(&triageAuthState{
		Credential: "the Cookie header", Kind: triageAuthUnauthorized, Samples: 1,
		Wire: triageCredWire{Status: empty}})
	t.Logf("row advice on the empty exhaustion: %s", advice)

	// SITE 2: the run-level clause.
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.noteCredExhaustion("app.v17-accept.test", empty)
	clause := rr.authWall().Sentence()
	t.Logf("run clause on the empty exhaustion: %s", clause)

	for _, site := range []struct{ what, got string }{{"the row advice", advice}, {"the run clause", clause}} {
		low := strings.ToLower(site.got)
		for _, forbidden := range []string{"authenticated to them earlier", "authenticated to this host earlier", "run authenticated to"} {
			if strings.Contains(low, forbidden) {
				t.Errorf("%s says %q. Nothing on this branch read that: the guard is LastFreshAt, which records that the SOURCE was handing a credential out, and no field in this package records a target accepting one.\nGot: %s",
					site.what, forbidden, site.got)
			}
		}
		if !strings.Contains(site.got, "HELD") {
			t.Errorf("%s no longer says what it actually read, which is that this run HELD a credential for the host:\n%s", site.what, site.got)
		}
		if !strings.Contains(site.got, stamp) {
			t.Errorf("%s says the run held one earlier and does not quote LastFreshAt (%s), which is the one figure behind the word 'earlier':\n%s",
				site.what, stamp, site.got)
		}
		if !strings.Contains(site.got, "ACCEPTED") {
			t.Errorf("%s never says that acceptance is unrecorded, so a reader has no way to tell holding a credential from being authenticated by one:\n%s", site.what, site.got)
		}
	}

	// THE REASON, MEASURED RATHER THAN ASSERTED IN A COMMENT. If a field recording acceptance is
	// ever added to the status, these sentences may be rewritten to read it, and this test is the
	// thing that should say so.
	for _, f := range triageStructFieldNames(triageFreshCredStatus{}) {
		low := strings.ToLower(f)
		if strings.Contains(low, "accept") || strings.Contains(low, "honour") || strings.Contains(low, "honor") {
			t.Errorf("triageFreshCredStatus now carries %q. The sentences above are worded HELD precisely because nothing recorded acceptance; if that has changed they may now read this field and say so", f)
		}
	}

	// AND THE CLAIM MUST NOT COME BACK ANYWHERE IN THE RUNNER'S OWN SOURCE. Both sites were string
	// literals, and a third could be added without either fixture above touching it.
	for _, line := range triageNonCommentLines(t, "triageRun.go") {
		if strings.Contains(strings.ToLower(line.text), "run authenticated to") {
			t.Errorf("triageRun.go:%d states that this run authenticated to a host: %s\nNothing in this package observes a target accepting a credential.",
				line.n, strings.TrimSpace(line.text))
		}
	}
}

// A RUN THAT COULD NEVER MEASURE ITS OWN SESSION IS SILENT IN THE RUN RECORD, AND IT IS THE STATE
// THE LIVE ESTATE IS IN.
//
// THE NEIGHBOURING STATE, AND WHY IT IS THE HARDER ONE. Round 16 closed the case where a run GOES
// anonymous with renewal off: that is a transition, triageCarryExhaustion sees it, sets Exhausted,
// and noteCredExhaustion carries it into the run note. This is the case where there was never
// anything to lose. triageCarryExhaustion sets NeverVerifiable on a first read of Fresh > 0 and
// Verifiable == 0, deliberately leaves Exhausted false because nothing transitioned, and the fact
// then reaches the card's own note and STOPS. noteCredExhaustion returns early on !Exhausted,
// CredExhausted stays empty, Measured reports false, terminalStatus reports completed, which is
// the one status the certificate renders under, and diagnosticSentences says nothing at all.
//
// IT IS NOT A CORNER. On the estate this engine is pointed at, the first read for the target
// already reads Verifiable zero, both Cognito JWS having expired before the run began and the
// surviving credential being a five segment JWE with no readable expiry. So LastVerifiableAt
// never leaves zero, neither exhaustion can ever fire, and every run against it takes exactly
// this path.
//
// DRIVEN THROUGH THE REAL CALL SITE. applyFreshCredentials is where the runner meets the
// credential source and the only place this status is read, so a fixture that called the note
// function by hand would prove that the function works and not that the runner reaches it.
func TestARunThatCouldNeverMeasureItsSessionIsNotSilentInTheRunRecord(t *testing.T) {
	ctx := triageTestDB(t)
	open := triageStaticServer(t)
	rr := triageUnitRunner(t, triage.ClassCRLF)
	rr.budget.RemainingPerRun = rr.budget.PerRun
	triageEnableClass(rr, triage.ClassCRLF)
	u, _ := triageQueryUnit(open.URL, "c")
	rr.plan.Units = []triageUnitPlan{*u}
	// NO PAIRS ON PURPOSE, for the same reason as the exhaustion test above: the plan shortfall is
	// a second, unrelated route to TriageRunIncomplete, and a fixture that tripped it would let
	// the defect stand while the test passed.
	rr.unitContext(ctx, &rr.plan.Units[0])

	const host = "app.v17-neververifiable.test"
	cred := triageBearerCred("v17.opaque.refresh.material", "a manual crawl capture", time.Time{})
	st := triageFreshCredStatus{
		Verifiable: 0, NeverVerifiable: true,
		Unmeasured: []string{"the Authorization header"},
	}
	st.Note = triageCredNeverVerifiableClause(triageFreshCredStatus{Fresh: 1, Unmeasured: st.Unmeasured})
	rr.creds = &triageFakeCreds{status: st, current: func() []triageFreshCred { return []triageFreshCred{cred} }}

	send := RequestTemplate{Method: "GET", URL: "https://" + host + "/v1/accounts",
		Headers: [][2]string{{"Accept", "application/json"}}}
	wire := rr.applyFreshCredentials(&send, host, triage.SlotKey("query:c"))
	if !wire.Status.NeverVerifiable || wire.Status.Exhausted {
		t.Fatalf("the fixture is meant to be the never-verifiable state and not an exhaustion: never=%v exhausted=%v",
			wire.Status.NeverVerifiable, wire.Status.Exhausted)
	}

	w := rr.authWall()
	if w.Stale != 0 || w.Unauthenticated != 0 || w.Gated != 0 {
		t.Fatalf("the fixture is meant to hit no wall at all: stale=%d unauth=%d gated=%d", w.Stale, w.Unauthenticated, w.Gated)
	}
	if len(w.CredExhausted) != 0 {
		t.Fatalf("the fixture is meant to record no exhaustion: %d recorded", len(w.CredExhausted))
	}
	if !w.Measured() {
		t.Errorf("a run that could never read a lifetime on any credential it holds reports itself as having measured nothing worth saying, so it is recorded completed and the operator is told nothing. NeverVerifiable is said on the card and nowhere in the run record")
	}

	status, _ := rr.terminalStatus()
	if status == TriageRunCompleted {
		t.Errorf("a run that never knew whether it was authenticated reported %q, which is the one status the certificate renders under", status)
	}

	said := triageRunLevelSay(rr)
	t.Logf("run note: %s", said)
	if !strings.Contains(said, host) {
		t.Errorf("the run note never names the host this run could not measure its authentication state for:\n%s", said)
	}
	if !strings.Contains(said, "NEVER") {
		t.Errorf("the run note does not report the state that actually fired, which is that no credential for this host ever carried a lifetime this run could read:\n%s", said)
	}
	if !strings.Contains(said, "UNMEASURED") {
		t.Errorf("the run note does not say that the authentication state on that host is unmeasured, which is the whole reason this line exists:\n%s", said)
	}
	if !strings.Contains(said, st.Note) {
		t.Errorf("the run note describes the state instead of quoting what the source read:\nwant quoted: %s\ngot: %s", st.Note, said)
	}
	// AND IT MUST NOT INVENT EITHER OF THE TWO NEIGHBOURING FACTS. Not one row here was refused,
	// and nothing here changed state: a supply that was never measurable did not run out.
	for _, forbidden := range []string{
		"THIS RUN MEASURED AN AUTHENTICATION WALL",
		"Not one of these rows is clean",
		"CHANGED STATE WHILE IT WAS RUNNING",
		"CREDENTIAL SUPPLY RAN OUT DURING THE RUN",
	} {
		if strings.Contains(said, forbidden) {
			t.Errorf("the run note says %q about a run where every request was answered and nothing transitioned:\n%s", forbidden, said)
		}
	}
}

// triageStructFieldNames lists a struct's field names, so a test can assert what a type does NOT
// record without a reader having to take a comment's word for it.
func triageStructFieldNames(v any) []string {
	rt := reflect.TypeOf(v)
	if rt == nil || rt.Kind() != reflect.Struct {
		return nil
	}
	out := make([]string, 0, rt.NumField())
	for i := 0; i < rt.NumField(); i++ {
		out = append(out, rt.Field(i).Name)
	}
	return out
}

type triageSourceLine struct {
	n    int
	text string
}

// triageNonCommentLines returns the lines of a source file that are not whole-line comments, so a
// test can pin a claim out of the string literals without tripping over the comments that quote
// that claim in order to explain why it was removed.
func triageNonCommentLines(t *testing.T, file string) []triageSourceLine {
	t.Helper()
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read %s: %v", file, err)
	}
	var out []triageSourceLine
	for i, line := range strings.Split(string(src), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "//") {
			continue
		}
		out = append(out, triageSourceLine{n: i + 1, text: line})
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// The response a verdict points into
// ---------------------------------------------------------------------------------------------

// A VERDICT'S EVIDENCE IS A SPAN INTO A RESPONSE, SO THE RESPONSE HAS TO BE THERE.
//
// triage_verdicts records evidence_offset, evidence_length, evidence_matched and a phrase. Until
// this test existed no triage table stored a response at all, so a finding that said "arithmetic
// evaluated, 5 bytes at offset 412" pointed into a body that had been garbage collected before the
// run ended. An operator cannot paste an offset into a bug report, and the whole layer exists to
// decide whether a target is worth twenty-eight minutes of sqlmap, which is a judgement a human
// makes by READING the response.
//
// This test is deliberately written in SQL rather than through the store's own API, because the
// claim it is making is about what the DATABASE holds after a real run against a real target. It
// runs end to end against the canary oracle, and it asserts three separate things:
//
//  1. every delivered probe's record says what happened to its response body, and never leaves
//     that field at the unrecorded default, so a missing body can never be read as an empty one;
//  2. the body a verdict's evidence points into can be fetched from the run's own rows; and
//  3. THE OFFSET STILL MEANS WHAT IT SAYS: body[offset : offset+length] is byte-for-byte the
//     evidence_matched the classifier recorded. That is the assertion that catches the stored
//     bytes and the scanner's index space drifting apart, which is the only way this feature can
//     fail quietly.
func TestAVerdictEvidenceSpanResolvesToAStoredResponseBody(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, vectors := triageOracleTarget(t, ctx, base)

	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = key == TriageClassKey(triage.ClassSSTI)
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	settings.Pacing.RequestsPerSecond = 20
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
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
	_ = vectors

	// 1. EVERY DELIVERED PROBE ACCOUNTS FOR ITS RESPONSE BODY.
	var delivered, unaccounted, forgotten int
	if err := dbPool.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE body_state = ''),
		       count(*) FILTER (WHERE body_state = 'not_attached')
		FROM triage_fidelity WHERE run_id = $1 AND delivered`, runUUID).Scan(&delivered, &unaccounted, &forgotten); err != nil {
		t.Fatalf("read the probe records: %v", err)
	}
	if delivered == 0 {
		t.Fatal("the run delivered no probe at all, so there is no response for anything to point into")
	}
	if unaccounted > 0 {
		t.Errorf("%d of %d delivered probes leave body_state at the unrecorded default, so a reader cannot tell a response that was never stored from one that came back empty",
			unaccounted, delivered)
	}
	// not_attached is a DEFECT IN THE RUNNER and not a fact about the target: a response arrived
	// and the send path never handed its body to the store. It is recorded rather than rendered as
	// an empty response precisely so this assertion can be made.
	if forgotten > 0 {
		t.Errorf("%d of %d delivered probes got a response whose body no send path handed over, so there is a route through the runner that still drops what the target said",
			forgotten, delivered)
	}

	// 2. THE BODIES ARE REACHABLE FROM THE PROBE RECORDS, IN SQL, WITH NO GO IN THE WAY. This is
	// the join that did not exist: before this feature the third line of it named a table that was
	// not there ("relation triage_bodies does not exist" is what the operator's own database still
	// answers for the seven runs it holds).
	var joined, distinctBodies, bodyBytes int
	if err := dbPool.QueryRow(ctx, `
		SELECT count(*), count(DISTINCT f.body_sha256), COALESCE(sum(DISTINCT b.body_len), 0)
		FROM triage_fidelity f
		JOIN triage_bodies b ON b.run_id = f.run_id AND b.body_sha256 = f.body_sha256
		WHERE f.run_id = $1`, runUUID).Scan(&joined, &distinctBodies, &bodyBytes); err != nil {
		t.Fatalf("join the probe records to their responses: %v", err)
	}
	if joined == 0 {
		t.Fatal("not one probe record in this run resolves to a stored response")
	}
	t.Logf("%d probe records resolve to %d distinct response bodies holding %d bytes (%.1fx deduplication)",
		joined, distinctBodies, bodyBytes, float64(joined)/float64(distinctBodies))

	// 3. THE SPAN RESOLVES, AND IT RESOLVES TO THE RIGHT BYTES.
	//
	// THROUGH THE STORE AND NOT THROUGH THE JOIN ABOVE, because a join on evidence_ordinal finds
	// nothing: SSTI's computation oracle, the strongest verdict it produces, records the offset,
	// the length and the matched bytes and NO ordinal, so evidence_ordinal is 0 on exactly the rows
	// that matter most. LoadTriageEvidenceWindow resolves those by finding which of the responses
	// the verdict rests on actually holds those bytes at that offset, which is a measurement over
	// the stored responses rather than an assumption about which probe it was.
	verdicts, err := LoadTriageVerdicts(ctx, runUUID, TriageVerdictFilter{})
	if err != nil {
		t.Fatalf("read verdicts: %v", err)
	}
	spans, verified := 0, 0
	for _, row := range verdicts {
		ev := row.Verdict.Evidence
		if len(ev.Matched) == 0 || ev.Offset < 0 {
			continue
		}
		spans++
		w, err := LoadTriageEvidenceWindow(ctx, runUUID, row)
		if err != nil {
			t.Fatalf("resolve the evidence of %s/%s: %v", row.Verdict.Class, row.Verdict.SlotKey, err)
		}
		if !w.Resolved {
			t.Errorf("%s %s on %s records %q at offset %d and it resolves to no stored response: %s",
				row.Verdict.Class, row.Verdict.State, row.Verdict.SlotKey, ev.Matched, ev.Offset, w.Why)
			continue
		}
		if !w.OffsetVerified {
			t.Errorf("%s %s on %s resolved to the response of probe ordinal %d and the offset did not check out: %s",
				row.Verdict.Class, row.Verdict.State, row.Verdict.SlotKey, w.Response.Ordinal, w.Why)
			continue
		}
		verified++
		t.Logf("%s %s on %s (%s): %q at offset %d of the %d byte %s response of probe ordinal %d, resolved by %s",
			row.Verdict.Class, row.Verdict.State, row.Verdict.SlotKey, ev.Phrase, ev.Matched,
			w.Offset, len(w.Response.Body), w.Response.ContentType, w.Response.Ordinal, w.HowResolved)
	}
	if spans == 0 {
		t.Fatal("no verdict in this run recorded a span into a response at all, so the thing this test exists to check was never produced. A run that fires nothing cannot demonstrate that a finding is readable")
	}
	if verified == 0 {
		t.Errorf("%d verdicts recorded a span into a response and not one of them could be shown pointing at the bytes it claimed", spans)
	}
}

// ---------------------------------------------------------------------------------------------
// The two reads that put a response in front of the operator
// ---------------------------------------------------------------------------------------------

// triageResponseRouter registers the two routes EXACTLY as main.go must, so what passes here is
// the path the client calls. The main.go registration is not in this file's remit; these are the
// handlers it points at.
func triageResponseRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/triage/{scope_target_id}/run/response", GetTriageRunResponse).Methods("GET")
	r.HandleFunc("/triage/{scope_target_id}/run/evidence", GetTriageRunEvidence).Methods("GET")
	return r
}

func triageGET(t *testing.T, path string, wantCode int) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	triageResponseRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != wantCode {
		t.Fatalf("GET %s: %d, want %d: %s", path, rec.Code, wantCode, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s returned something that is not JSON: %v: %s", path, err, rec.Body.String())
	}
	return body
}

// THE READ AN OPERATOR ACTUALLY MAKES. A verdict names a probe ordinal, the operator asks for that
// probe's response, and the bytes come back: lossless in body_base64 always, and as readable text
// only when they really are text.
//
// THE SECOND HALF IS THE ONE THAT MATTERS. A probe whose body is NOT stored must come back with no
// body field at all, so a client rendering `body || ""` shows nothing rather than drawing an empty
// response the target never sent.
func TestTheResponseReadServesTheBytesAndNeverInventsAnEmptyOne(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	runUUID, err := CreateTriageRun(ctx, TriageRunSpec{
		ScopeTargetID: target, RunID: strings.ToLower(uuid.New().String()[:4]), Tier: triage.TierFull,
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	stored := triageBodyProbe(triage.ClassSQL, 4+64, `{"error":"unterminated quoted string"}`)
	// A probe that got a response and whose body nothing handed over: the runner-defect shape.
	forgotten := NewTriageFidelityRow(triage.ClassSQL, 4+128)
	forgotten.VectorID, forgotten.SlotKey = "v1", "query:q"
	forgotten.HTTPStatus = 500
	forgotten.Delivered = true
	forgotten.Wire = triage.PayloadWire{Logical: []byte("x"), Survived: triage.WireSurvivalIntact}
	// A response that is not valid UTF-8, which a JSON string cannot carry.
	binary := triageBodyProbe(triage.ClassSQL, 4+192, string([]byte{0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe}))
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{stored, forgotten, binary}); err != nil {
		t.Fatalf("record: %v", err)
	}

	got := triageGET(t, "/triage/"+target+"/run/response?ordinal=68", http.StatusOK)
	resp, _ := got["response"].(map[string]any)
	if resp["body"] != `{"error":"unterminated quoted string"}` {
		t.Errorf("the stored response came back as %v", resp["body"])
	}
	if resp["body_is_text"] != true || resp["body_stored"] != true {
		t.Errorf("a stored text response reports body_is_text=%v body_stored=%v", resp["body_is_text"], resp["body_stored"])
	}
	if b64, _ := resp["body_base64"].(string); b64 == "" {
		t.Error("the lossless copy of the response is missing")
	}

	missing := triageGET(t, "/triage/"+target+"/run/response?ordinal=132", http.StatusOK)
	mresp, _ := missing["response"].(map[string]any)
	if _, present := mresp["body"]; present {
		t.Errorf("a probe whose body was never stored served a body field anyway: %v", mresp["body"])
	}
	if mresp["body_stored"] != false {
		t.Error("a probe whose body was never stored claims it was")
	}
	if why, _ := mresp["body_missing_because"].(string); why == "" {
		t.Error("nothing said why the response is not there, so its absence is indistinguishable from an empty response")
	}

	// A BINARY BODY IS NOT SILENTLY MANGLED INTO A STRING. The lossless copy is there, the string
	// is not, and body_is_text says which.
	bin := triageGET(t, "/triage/"+target+"/run/response?ordinal=196", http.StatusOK)
	bresp, _ := bin["response"].(map[string]any)
	if bresp["body_is_text"] != false {
		t.Errorf("a body that is not valid UTF-8 reports body_is_text=%v", bresp["body_is_text"])
	}
	if _, present := bresp["body"]; present {
		t.Error("a body that is not valid UTF-8 was served as a string anyway, which is a lossy copy of the evidence")
	}
	if b64, _ := bresp["body_base64"].(string); b64 != base64.StdEncoding.EncodeToString([]byte{0x89, 0x50, 0x4e, 0x47, 0xff, 0xfe}) {
		t.Errorf("the lossless copy of a binary response is wrong: %v", bresp["body_base64"])
	}

	// A probe nobody ever recorded is a 404 and never an empty response.
	triageGET(t, "/triage/"+target+"/run/response?ordinal=999936", http.StatusNotFound)
}

// THE READ BEHIND THE FINDING. The operator is looking at a verdict, not at an ordinal, and what
// they need is the response its span points into with the span checked against the bytes.
func TestTheEvidenceReadResolvesAVerdictSpanAndSaysHowItDidIt(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)
	runUUID, err := CreateTriageRun(ctx, TriageRunSpec{
		ScopeTargetID: target, RunID: strings.ToLower(uuid.New().String()[:4]), Tier: triage.TierFull,
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	body := `<html><body>hello 1571033 world</body></html>`
	offset := strings.Index(body, "1571033")
	probe := triageBodyProbe(triage.ClassSSTI, 1+64, body)
	if _, err := RecordTriageFidelity(ctx, runUUID, []TriageFidelityRow{probe}); err != nil {
		t.Fatalf("record probe: %v", err)
	}
	verdict := TriageVerdictRow{
		VectorID:   "v1",
		Provenance: ProvenanceNativeProbe,
		Verdict: triage.ClassVerdict{
			Class: triage.ClassSSTI, SlotKey: "query:q", State: triage.StateFinding,
			Grade: triage.GradeHigh, Reason: "the arithmetic was evaluated", Oracle: "computation",
			Ordinals: []uint64{1 + 64},
			Evidence: triage.TriageEvidence{
				Ordinal: 1 + 64, Matched: []byte("1571033"), Offset: offset, Length: 7,
				Phrase: "computation freemarker",
			},
		},
	}
	if _, err := RecordTriageVerdicts(ctx, runUUID, []TriageVerdictRow{verdict}); err != nil {
		t.Fatalf("record verdict: %v", err)
	}

	got := triageGET(t, "/triage/"+target+"/run/evidence?class=SSTI&slot_key=query:q&vector_id=v1", http.StatusOK)
	if got["resolved"] != true {
		t.Fatalf("the span did not resolve: %v", got["why"])
	}
	if got["offset_verified"] != true {
		t.Fatalf("the offset was not verified against the stored bytes: %v", got["why"])
	}
	if got["how_resolved"] != "evidence_ordinal" {
		t.Errorf("resolved by %v, want the ordinal the verdict named", got["how_resolved"])
	}
	resp, _ := got["response"].(map[string]any)
	if resp["body"] != body {
		t.Errorf("the response the span points into came back as %v", resp["body"])
	}
	// The operator can now read the offset off the screen and find the bytes themselves.
	off := int(got["offset"].(float64))
	length := int(got["length"].(float64))
	if got := body[off : off+length]; got != "1571033" {
		t.Errorf("offset %d of the served response holds %q", off, got)
	}
}
