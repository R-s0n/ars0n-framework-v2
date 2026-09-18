package triageclasses

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// ---------------------------------------------------------------------------------------------
// FIXTURES
// ---------------------------------------------------------------------------------------------

const (
	// sqlTestRunID is the run id inside sqlMarkerTemplate, so a fixture observation stamped with
	// it looks like a response to a probe from THIS run.
	sqlTestRunID = "sql0"
	// sqlTestForeignMarker is a well-formed marker whose ordinal is 5, so its R12 stripe is
	// ClassNoSQL. It exists to prove that a foreign marker inside a DBMS error is a hit for
	// nobody rather than a hit for whoever looked first.
	sqlTestForeignMarker = "zqjsql0000005v3a"
	// sqlTestCorruptMarker is sqlMarkerTemplate with the last checksum byte changed, which is
	// what a sink that rewrote the middle of our token looks like.
	sqlTestCorruptMarker = "zqjsql0000004ju9"
)

// sqlTestObs builds an observation that looks like a delivered response carrying our marker.
func sqlTestObs(body string) triage.Observation {
	o := triage.Observation{
		ObsID:      "obs-" + fmt.Sprint(len(body)),
		RunID:      sqlTestRunID,
		Status:     200,
		Body:       []byte(body),
		BodyLen:    len(body),
		Marker:     triage.Marker(sqlMarkerTemplate),
		Kind:       triage.ObsProbe,
		Class:      triage.ClassSQL,
		ReqWireURL: "/x",
	}
	o.BodySHA256 = sha256.Sum256(o.Body)
	o.Payload = triage.PayloadWire{Logical: []byte("x"), Wire: []byte("x"), Survived: triage.WireSurvivalIntact}
	return o
}

// sqlTestEvidence builds an evidence set directly, because a triage.Perturbed cannot be minted
// outside package triage and a test that had to go through Plan or Classify could never reach any
// rule past the first three refusals.
type sqlTestProbe struct {
	id      triage.ProbeID
	obs     triage.Observation
	ordinal uint64
	marker  string
}

func sqlTestEvidence(control triage.Observation, probes ...sqlTestProbe) *sqlEvidence {
	ev := &sqlEvidence{byProbe: map[triage.ProbeID][]sqlSeen{}, decodeDepth: 1}
	ev.control = control
	ev.haveCtl = true
	for i, p := range probes {
		ord := p.ordinal
		if ord == 0 {
			ord = uint64(4 + 64*i) // every ordinal in this class's R12 stripe
		}
		mk := p.marker
		if mk == "" {
			mk = sqlMarkerTemplate
		}
		s := sqlSeen{probe: p.id, ordinal: ord, marker: triage.Marker(mk), obs: p.obs}
		s.d1 = sqlEvalD1(p.obs)
		s.cmp = sqlCompare(p.obs, control)
		ev.byProbe[p.id] = append(ev.byProbe[p.id], s)
		ev.all = append(ev.all, s)
		if len(sqlMarkerHits(p.obs)) > 0 {
			ev.echoedAny = true
		}
		if e := sqlIdentifyEngine(p.obs.Body); e != "" && ev.engine == "" {
			ev.engine = e
		}
		if w, ok := sqlWeakSignature(p.obs.Body); ok && ev.weakSeen == "" {
			ev.weakSeen = w
		}
		if p.id == sqlNC1 && s.d1.Fired {
			ev.junkSensitive = true
		}
	}
	ev.uniformBlock, ev.uniformInert = sqlUniformBlock(ev)
	return ev
}

func sqlTestCtx() triage.ClassifyCtx {
	return triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Slot: triage.Slot{
			VectorID: "v1", Kind: triage.KindQuery, Key: "query:id", Name: "id", Value: "alice",
			ValueOrigin: triage.ValueObserved, ValueKind: triage.ValueFreeText,
			Method: "GET", ServerReachable: true, SegmentIndex: -1,
			Constraints: triage.NewSlotConstraints(),
		},
		Vector:   triage.TriageVector{ID: "v1", Method: "GET", MediaType: ""},
		Baseline: triage.BaselineModel{Samples: 5, Stable: true},
		Prelude:  triage.PreludeTokenNotRequired,
		Budget:   triage.TriageBudget{PerSlot: 22, PerRun: 5000, RemainingPerSlot: 10, RemainingPerRun: 500},
	}}
}

func sqlAnyClean(vs []triage.ClassVerdict) bool {
	for _, v := range vs {
		if v.State.CountsAsClean() {
			return true
		}
	}
	return false
}

// A real PostgreSQL 18 reply to SQL-Q1, with our marker inside the phrase.
func sqlPGError() string {
	return `{"error":"ERROR:  syntax error at or near \"` + sqlMarkerTemplate + `\"\nLINE 1: select * from t where name = 'alice'` + sqlMarkerTemplate + `''"}`
}

// ---------------------------------------------------------------------------------------------
// REGISTRATION AND THE ISOLATION LAW
// ---------------------------------------------------------------------------------------------

// The class registers itself and satisfies the contract that can be checked without sending
// anything. ValidateClassifier already runs at registration, but a panic out of an init() names an
// id and not a file, and this turns it into a named failure next to the class it is about.
func TestTheSQLClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassSQL)
	if !ok {
		t.Fatal("the SQL classifier did not register itself, so the whole class would be missing from every report with no error anywhere")
	}
	if c.ID() != triage.ClassSQL {
		t.Fatalf("registered under SQL but reports %s", c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	ctx := sqlTestCtx()
	if err := triage.PlannedProbesAreDeclared(c, c.Plan(ctx.PlanCtx)); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassSQL {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
		if len(p.Points) == 0 {
			t.Errorf("probe %s names no insertion point, so it can never be planned", p.ID)
		}
		if len(p.Logical) == 0 && !p.IsControl {
			t.Errorf("probe %s is a non-control with no bytes, which would send nothing and record clean", p.ID)
		}
	}
}

// The marker literal written into the payload bytes belongs to THIS class's R12 stripe.
//
// This is the test for a bug the catalogue itself would have introduced. CATALOGUE 1.4 heads the
// SQL section "Marker zqj4f3q000a1kx9m", whose ordinal digits read 13016 in base36 and
// 13016 mod 64 is 24, which is ClassDeser. Shipping that literal would fail I1d-plain at build
// time as a foreign marker in a SQL payload, and if the check had not existed it would have meant
// a deserialization probe's response handing this class a hit.
func TestTheMarkerLiteralInEverySQLPayloadBelongsToThisClassesStripe(t *testing.T) {
	m := triage.Marker(sqlMarkerTemplate)
	if !m.WellFormed() {
		t.Fatalf("%q is not a well-formed marker", m)
	}
	if got := m.Integrity(); got != triage.MarkerValid {
		t.Errorf("checksum of %q is %s, want valid: a payload carrying a bad checksum would be read back as corrupted and cap every hit at suspicious", m, got)
	}
	if !m.BelongsTo(triage.ClassSQL) {
		id, _ := m.ClassID()
		t.Errorf("%q is in class %s's ordinal stripe, not SQL's", m, id)
	}
	if bad := triage.Marker("zqj4f3q000a1kx9m"); bad.BelongsTo(triage.ClassSQL) {
		t.Error("the catalogue's illustrative literal now parses as SQL's, so the correction in sqlMarkerTemplate is no longer needed and this test should say so")
	}

	c := sqlClassifier{}
	for _, p := range c.Probes() {
		if len(p.Logical) == 0 {
			continue
		}
		norm := triage.NormaliseMarkers(p.Logical)
		if bytes.Contains(p.Logical, []byte(triage.DefaultMarkerAnchor)) && bytes.Equal(norm, p.Logical) {
			t.Errorf("probe %s carries the marker anchor but nothing marker-shaped, so the isolation check cannot normalise it and two classes could collide unnoticed: %q", p.ID, p.Logical)
		}
	}
}

// The registry satisfies the isolation law with this class in it. A byte-equal payload across two
// classes means a block or a rejection cannot be attributed to either, so one of them records
// clean for a mechanism it never tested.
func TestNoSQLPayloadIsByteEqualToAnotherClassesPayload(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		if v.ClassA == triage.ClassSQL || v.ClassB == triage.ClassSQL {
			t.Errorf("ISOLATION: %s", v)
		}
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
	if rep.ClassesChecked < 2 {
		t.Log("only one class is registered, so the cross-class half of the law cannot fire here")
	}
}

// Not one of SQLiDetector's fourteen payloads is duplicated here.
//
// Duplicating them would fail the isolation test, and it would also waste a request per payload
// per slot without reducing a single false negative: the tool already sends them on every query
// slot. What this class adds is the baseline, the marker, the junk calibration, the balanced
// repair and reach beyond the query string, none of which the tool has.
func TestNoSQLPayloadRepeatsASQLiDetectorByteString(t *testing.T) {
	theirs := []string{
		"'123", "''123", "`123", `")123`, `"))123`, "`)123", "`))123", "'))123",
		`')123"123`, "[]123", `""123`, `'"123`, `"'123`, `\123`,
	}
	for _, p := range (sqlClassifier{}).Probes() {
		got := string(p.Logical)
		for _, t14 := range theirs {
			if got == t14 {
				t.Errorf("probe %s ships SQLiDetector's payload %q verbatim", p.ID, t14)
			}
		}
	}
}

// The decode probe's bytes are the percent form of this class's own marker, computed rather than
// typed. One wrong nibble in a hand-written %7a%71%6a... is a decode probe that measures nothing
// and reports decode_depth unknown forever.
func TestTheDecodeProbeCarriesThePercentFormOfThisClassesMarker(t *testing.T) {
	want := "%7a%71%6a%73%71%6c%30%30%30%30%30%30%34%6a%75%38"
	if got := string(sqlPercentEncodeBytes(sqlMarkerTemplate)); got != want {
		t.Fatalf("percent form is %q, want %q", got, want)
	}
	for _, p := range (sqlClassifier{}).Probes() {
		if p.ID != sqlDEC {
			continue
		}
		if string(p.Logical) != want {
			t.Errorf("SQL-DEC logical bytes are %q, want the percent form of the marker", p.Logical)
		}
		if len(p.Encoders) != 1 || p.Encoders[0] != triage.EncodeLiteralPct {
			t.Errorf("SQL-DEC must go out with literal_pct or the runner re-encodes the percents and the probe asks a different question: %v", p.Encoders)
		}
		return
	}
	t.Fatal("SQL-DEC is not declared")
}

// ---------------------------------------------------------------------------------------------
// THE PRIMARY ORACLE, AND EVERY NAMED FALSE POSITIVE IT MUST STAY SILENT ON
// ---------------------------------------------------------------------------------------------

func TestTheParserErrorOracleFiresOnTheTrueShapeAndStaysSilentOnEveryNamedFalsePositive(t *testing.T) {
	farAway := "ERROR:  syntax error at or near \"x\"" + strings.Repeat(" ", 200) + sqlMarkerTemplate
	nextLine := "ERROR:  syntax error at or near \"x\"\n" + sqlMarkerTemplate

	cases := []struct {
		name  string
		obs   triage.Observation
		fire  bool
		why   string
		route string
	}{
		{
			name: "a PostgreSQL parse error naming this run's marker is the true shape",
			obs:  sqlTestObs(sqlPGError()), fire: true,
			why: "the engine quoted our own token back, and the baseline cannot contain a token minted for this probe",
		},
		{
			name: "the same error rendered raw by a server-side page",
			obs:  sqlTestObs(`<pre>ERROR:  syntax error at or near "` + sqlMarkerTemplate + `"</pre>`),
			fire: true,
			why:  "the catalogue's phrase set is written against raw text and must still work there",
		},
		{
			name: "a MariaDB 1064 naming the marker inside a JSON body",
			obs:  sqlTestObs(`{"detail":"You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '` + sqlMarkerTemplate + `''' at line 1"}`),
			fire: true,
			why:  "the MySQL family phrase, JSON-encoded, which is the shape the measured corpus actually returns",
		},
		{
			name: "a SQLite unknown-column message naming the marker",
			obs:  sqlTestObs(`{"error":"no such column: ` + sqlMarkerTemplate + `"}`),
			fire: true,
			why:  "SQLite's wording appears in neither sqlmap's errors.xml nor SQLiDetector's 153 signatures",
		},
		{
			name: "an application whose every response carries a PSQLException but not our marker",
			obs:  sqlTestObs(`<div class="debug">org.postgresql.util.PSQLException: ERROR:  syntax error at or near "select"</div>`),
			fire: false, route: "/clean/dberror",
			why: "this is the whole reason the oracle requires the marker: subtraction cannot separate a DBMS error caused by the payload from one the endpoint always emits",
		},
		{
			name: "the payload echoed onto a page that mentions SQL more than 120 bytes away",
			obs:  sqlTestObs(farAway), fire: false, route: "/clean/echoparser",
			why: "reflection next to unrelated prose is not the parser complaining about our token",
		},
		{
			name: "the marker on a different logical line from the phrase",
			obs:  sqlTestObs(nextLine), fire: false,
			why: "a stack trace and a template can put two unrelated things thirty bytes apart on different lines",
		},
		{
			name: "a weak driver-name signature with our marker right beside it",
			obs:  sqlTestObs("Microsoft OLE DB Provider for SQL Server Driver " + sqlMarkerTemplate),
			fire: false,
			why:  "a driver name in a stack trace is not a parser error; the weak catalogue may only raise a hit this class already made",
		},
		{
			name: "a page discussing SQL syntax with our marker in the search box",
			obs:  sqlTestObs("<h1>SQL syntax tutorial</h1><input value=\"" + sqlMarkerTemplate + "\">"),
			fire: false,
			why:  "SQL (warning|error|syntax) is in the weak catalogue precisely because ordinary pages carry it",
		},
		{
			name: "an empty body",
			obs:  sqlTestObs(""), fire: false,
			why: "no body is not a silent oracle, it is no measurement",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sqlEvalD1(tc.obs)
			if got.Fired != tc.fire {
				t.Fatalf("fired=%v want %v (%s). route %s, refusal reason %q", got.Fired, tc.fire, tc.why, tc.route, got.Why)
			}
			if !tc.fire && got.Phrase != "" && got.Why == "" {
				t.Errorf("a phrase matched and the hit was refused with no reason recorded, so the refusal is invisible to the operator")
			}
		})
	}
}

// A marker from another class's ordinal stripe inside a DBMS error is a hit for NOBODY.
//
// Ruling R12 exists because four of one class's binary constants decoded to another class's
// marker, so a deserialization probe's response handed a different class a finding. The arithmetic
// is what makes that structurally detectable instead of a matter of inspection.
func TestAForeignStripeMarkerInsideADatabaseErrorIsAHitForNobody(t *testing.T) {
	body := `ERROR:  syntax error at or near "` + sqlTestForeignMarker + `"`
	o := sqlTestObs(body)
	o.Marker = triage.Marker(sqlTestForeignMarker)
	o.Proj.MarkerHits = []triage.MarkerHit{{
		Form: "raw", Offset: strings.Index(body, sqlTestForeignMarker),
		Length: len(sqlTestForeignMarker), Marker: triage.Marker(sqlTestForeignMarker),
	}}
	got := sqlEvalD1(o)
	if got.Fired {
		t.Fatal("the oracle fired on another class's marker, so a probe from any other class can manufacture a SQL finding")
	}
	if !strings.Contains(got.Why, "foreign_marker_observed") {
		t.Errorf("refusal reason %q does not name foreign_marker_observed", got.Why)
	}
}

// A marker minted by an earlier run is a cached body, not a hit.
func TestAMarkerFromAnotherRunIsStaleRatherThanAHit(t *testing.T) {
	o := sqlTestObs(sqlPGError())
	o.RunID = "zzzz"
	got := sqlEvalD1(o)
	if got.Fired {
		t.Fatal("the oracle fired on a marker from a different run, so a cached response becomes a finding")
	}
	if !strings.Contains(got.Why, "stale_marker") {
		t.Errorf("refusal reason %q does not name stale_marker", got.Why)
	}
}

// A corrupted marker still fires, and it is capped at suspicious, because attribution is unsafe.
func TestACorruptedMarkerCapsTheHitAtSuspicious(t *testing.T) {
	body := `ERROR:  syntax error at or near "` + sqlTestCorruptMarker + `"`
	o := sqlTestObs(body)
	o.Marker = triage.Marker(sqlTestCorruptMarker)
	o.Proj.MarkerHits = []triage.MarkerHit{{
		Form: "raw", Offset: strings.Index(body, sqlTestCorruptMarker),
		Length: len(sqlTestCorruptMarker), Marker: triage.Marker(sqlTestCorruptMarker),
	}}
	ev := sqlTestEvidence(sqlTestObs("ok"), sqlTestProbe{id: sqlQ1, obs: o, marker: sqlTestCorruptMarker})
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if len(vs) != 1 {
		t.Fatalf("want one verdict, got %d", len(vs))
	}
	if vs[0].State != triage.StateSuspicious {
		t.Errorf("state %s, want suspicious: a marker whose checksum failed cannot be attributed safely", vs[0].State)
	}
	if vs[0].Grade == triage.GradeHigh {
		t.Error("a corrupted marker graded high")
	}
}

// ---------------------------------------------------------------------------------------------
// THE CONTROLS, WHICH ARE WHAT MAKE THE ORACLE A DETECTOR RATHER THAN A SUBSTRING SEARCH
// ---------------------------------------------------------------------------------------------

// If a purely alphanumeric suffix already errors, every marker-in-error verdict on the slot is
// void. It is not clean, and it is not a finding: it is undecidable, and the reason names why.
func TestTheJunkControlVoidsTheErrorOracleRatherThanProducingAClean(t *testing.T) {
	ev := sqlTestEvidence(sqlTestObs("ok"),
		sqlTestProbe{id: sqlNC1, obs: sqlTestObs(sqlPGError())},
		sqlTestProbe{id: sqlQ1, obs: sqlTestObs(sqlPGError())},
	)
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if len(vs) != 1 || vs[0].State != triage.StateCannotDetermine {
		t.Fatalf("want a single cannot_determine, got %#v", vs)
	}
	if !strings.Contains(vs[0].Reason, "junk_sensitive") {
		t.Errorf("reason %q does not name junk_sensitive", vs[0].Reason)
	}
	if sqlAnyClean(vs) {
		t.Error("a junk-sensitive slot produced a clean")
	}
	if reqs := sqlNextRequests(sqlTestCtx().PlanCtx, ev); len(reqs) != 0 {
		t.Errorf("the ladder kept going after the junk control fired: %v", reqs)
	}
}

// A break and its balanced control producing the SAME parse error means the delimiter never
// reached SQL. Reading that as a break is a confident false positive with a marker in it.
func TestABalancedControlReproducingTheSameParseErrorIsNotAFinding(t *testing.T) {
	ev := sqlTestEvidence(sqlTestObs("ok"),
		sqlTestProbe{id: sqlQ1, obs: sqlTestObs(sqlPGError())},
		sqlTestProbe{id: sqlQ2, obs: sqlTestObs(sqlPGError())},
	)
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if vs[0].State != triage.StateCannotDetermine {
		t.Fatalf("state %s, want cannot_determine: both the break and its doubled-quote control errored identically", vs[0].State)
	}
	if !strings.Contains(vs[0].Reason, "metachar_not_delivered") {
		t.Errorf("reason %q does not name metachar_not_delivered", vs[0].Reason)
	}
}

// An unknown-column error from the doubled control is the IDENTIFIER CONTEXT SIGNAL and must not
// be mistaken for the break failing to deliver. Getting this wrong would throw away every finding
// against a PostgreSQL ORDER BY "col" sink, which is the context the class was extended to reach.
func TestAnUnknownColumnErrorFromTheDoubledControlIsAContextSignalNotAFailure(t *testing.T) {
	ident := `ERROR:  column "name"` + sqlMarkerTemplate + `" does not exist`
	ev := sqlTestEvidence(sqlTestObs("ok"),
		sqlTestProbe{id: sqlD1P, obs: sqlTestObs(sqlPGError())},
		sqlTestProbe{id: sqlD2P, obs: sqlTestObs(ident)},
	)
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if vs[0].State != triage.StateFinding && vs[0].State != triage.StateSuspicious {
		t.Fatalf("state %s, want a positive: the doubled double quote produced an unknown-column error, which proves an identifier context", vs[0].State)
	}
	if vs[0].Oracle != "parser_error" {
		t.Errorf("oracle %q, want parser_error", vs[0].Oracle)
	}
}

// A hit that was reproduced with a fresh marker AND has its control grades high; one without
// either does not. A hit nobody reproduced is a suspicion.
func TestAHitGradesHighOnlyWhenItWasReproducedWithAFreshMarkerAndItsControlWasSent(t *testing.T) {
	hit := sqlTestObs(sqlPGError())
	silent := sqlTestObs("ok")

	lone := sqlTestEvidence(silent, sqlTestProbe{id: sqlQ1, obs: hit})
	if v := sqlDecide(sqlTestCtx(), lone, false)[0]; v.Grade == triage.GradeHigh {
		t.Error("a single unreproduced hit with no control graded high")
	}

	// The repeat carries a SECOND ordinal from this class's stripe, and its body quotes THAT
	// marker back, which is what "reproduced with a fresh marker" means.
	const second = "zqjsql000001why3"
	secondHit := sqlTestObs(strings.ReplaceAll(sqlPGError(), sqlMarkerTemplate, string(second)))
	secondHit.Marker = triage.Marker(second)
	full := sqlTestEvidence(silent,
		sqlTestProbe{id: sqlQ1, obs: hit},
		sqlTestProbe{id: sqlQ2, obs: silent},
		sqlTestProbe{id: sqlQ1, obs: secondHit, ordinal: 68, marker: second},
	)
	v := sqlDecide(sqlTestCtx(), full, false)[0]
	if v.State != triage.StateFinding {
		t.Fatalf("state %s, want finding", v.State)
	}
	if v.Grade != triage.GradeHigh {
		t.Errorf("grade %s, want high: the hit was reproduced with a fresh marker and its balanced control stayed silent", v.Grade)
	}
	if len(v.Ordinals) == 0 {
		t.Error("a positive with no probe ordinals points the operator at nothing")
	}
}

// ---------------------------------------------------------------------------------------------
// THE INT CAST, WHICH IS THE HIGHEST-VALUE NEGATIVE IN THE CLASS
// ---------------------------------------------------------------------------------------------

func TestAnIntCastIsNotCleanItIsCastedAndAnInertParameterIsNeither(t *testing.T) {
	base := sqlTestObs("rows: 1")
	moved := sqlTestObs("rows: 0")

	cases := []struct {
		name  string
		c5    triage.Observation
		c6    triage.Observation
		state triage.TriageState
		says  string
		why   string
	}{
		{
			name: "the application parses an int and discards the tail",
			c5:   base, c6: moved,
			state: triage.StateNotExploitable, says: "casted",
			why: "1' and 1 are the same request, which every scanner on earth records as clean",
		},
		{
			name: "the parameter does not move the response at all",
			c5:   base, c6: base,
			state: triage.StateCannotDetermine, says: "parameter_inert",
			why: "without the influence control, an inert parameter is indistinguishable from a cast one and both read as clean",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := sqlTestEvidence(base,
				sqlTestProbe{id: sqlC5, obs: tc.c5},
				sqlTestProbe{id: sqlC6, obs: tc.c6},
			)
			vs := sqlDecide(sqlTestCtx(), ev, false)
			if vs[0].State != tc.state {
				t.Fatalf("state %s, want %s (%s)", vs[0].State, tc.state, tc.why)
			}
			if !strings.Contains(vs[0].Reason, tc.says) {
				t.Errorf("reason %q does not say %s", vs[0].Reason, tc.says)
			}
			if sqlAnyClean(vs) {
				t.Error("a cast or inert parameter produced a clean")
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE BOOLEAN AND LIKE ARMS, WHERE ONE HALF PROVES NOTHING
// ---------------------------------------------------------------------------------------------

func TestTheBooleanArmNeedsEveryHalfAndStaysSilentWhenAnyIsMissing(t *testing.T) {
	same := sqlTestObs("rows: 1")
	diff := sqlTestObs("rows: 0")

	cases := []struct {
		name  string
		a1    []triage.Observation
		a2    triage.Observation
		a3    *triage.Observation
		found bool
		why   string
	}{
		{
			name: "true arm matches, false arm differs, control does not look true, true arm reproduced",
			a1:   []triage.Observation{same, same}, a2: diff, a3: &diff, found: true,
			why: "all four halves",
		},
		{
			name: "the true arm was never repeated",
			a1:   []triage.Observation{same}, a2: diff, a3: &diff, found: false,
			why: "a page that simply differs on every second request produces exactly this shape",
		},
		{
			name: "the invalid-syntax control also looks true",
			a1:   []triage.Observation{same, same}, a2: diff, a3: &same, found: false,
			why: "two integers separated by a space are not an expression, so a control that looks TRUE means the detector is not measuring the boolean at all",
		},
		{
			name: "the false arm did not move",
			a1:   []triage.Observation{same, same}, a2: same, a3: &diff, found: false,
			why: "half a differential is not a differential",
		},
		{
			name: "the control was never sent",
			a1:   []triage.Observation{same, same}, a2: diff, a3: nil, found: false,
			why: "a detector never shown staying silent is not verified",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probes := []sqlTestProbe{}
			for _, o := range tc.a1 {
				probes = append(probes, sqlTestProbe{id: sqlA1, obs: o})
			}
			probes = append(probes, sqlTestProbe{id: sqlA2, obs: tc.a2})
			if tc.a3 != nil {
				probes = append(probes, sqlTestProbe{id: sqlA3, obs: *tc.a3})
			}
			ev := sqlTestEvidence(same, probes...)
			_, got := ev.d2Confirmed()
			if got != tc.found {
				t.Fatalf("d2Confirmed=%v want %v (%s)", got, tc.found, tc.why)
			}
			if !tc.found {
				vs := sqlDecide(sqlTestCtx(), ev, false)
				for _, v := range vs {
					if v.State.Kind() == triage.StateKindPositive {
						t.Errorf("an incomplete boolean differential produced %s", v.State)
					}
				}
			}
		})
	}
}

func TestTheLikeArmNeedsBothHalvesAndIsNeverAFindingOnItsOwn(t *testing.T) {
	base := sqlTestObs("3 results")
	wider := sqlTestObs("47 results")

	t.Run("both halves present gives a suspicion and not a finding", func(t *testing.T) {
		ev := sqlTestEvidence(base,
			sqlTestProbe{id: sqlL1, obs: wider},
			sqlTestProbe{id: sqlL2, obs: base},
		)
		vs := sqlDecide(sqlTestCtx(), ev, false)
		if vs[0].State != triage.StateSuspicious {
			t.Fatalf("state %s, want suspicious: a percent that widens proves the value reaches a pattern, not that it reaches the parser", vs[0].State)
		}
	})

	// The escaped control moved the response too, so the LIKE pair says nothing. It is the LIKE
	// ARM that is undecided, not the class: see
	// TestAnEscapedPercentThatAlsoMovedTheResponseDisqualifiesOnlyTheLikeArm for the false
	// negative the class-wide reading used to cause.
	t.Run("the escaped control also widened, so the LIKE arm alone is undecided", func(t *testing.T) {
		ev := sqlTestEvidence(base,
			sqlTestProbe{id: sqlL1, obs: wider},
			sqlTestProbe{id: sqlL2, obs: wider},
		)
		vs := sqlDecide(sqlTestCtx(), ev, false)
		if sqlAnyClean(vs) {
			t.Fatalf("a LIKE pair that could not be read produced a clean: %s", sqlReasons(vs))
		}
		var like *triage.ClassVerdict
		for i := range vs {
			if vs[i].Oracle == "like_widening" {
				like = &vs[i]
			}
		}
		if like == nil || like.State != triage.StateCannotDetermine {
			t.Fatalf("want a cannot_determine row for the LIKE arm, got %s", sqlReasons(vs))
		}
		if !strings.Contains(like.Reason, "like_arm_unreadable") {
			t.Errorf("reason %q does not name like_arm_unreadable", like.Reason)
		}
	})
}

// ---------------------------------------------------------------------------------------------
// NOT KNOWING IS NOT CLEAN
// ---------------------------------------------------------------------------------------------

// Every way this class can fail to get an answer has its own state and its own reason, and none
// of them renders as clean. This codebase has shipped the opposite bug repeatedly.
func TestEveryUndecidablePathYieldsAnUnknownRatherThanAClean(t *testing.T) {
	silent := sqlTestObs("ok")
	quiet := []sqlTestProbe{
		{id: sqlQ1, obs: silent}, {id: sqlQ2, obs: silent},
		{id: sqlA1, obs: silent}, {id: sqlA2, obs: silent}, {id: sqlA3, obs: silent},
	}

	cases := []struct {
		name   string
		mutate func(ctx *triage.ClassifyCtx, ev *sqlEvidence)
		says   string
		why    string
	}{
		{
			name: "the stability gate did not pass",
			mutate: func(ctx *triage.ClassifyCtx, _ *sqlEvidence) {
				ctx.Baseline.Stable = false
				ctx.Baseline.GateReason = "status_flap"
			},
			says: "status_flap",
			why:  "the boolean arm is the only detector that can see an endpoint suppressing errors, and a flapping status takes it away",
		},
		{
			name:   "the comparison was degraded",
			mutate: func(ctx *triage.ClassifyCtx, _ *sqlEvidence) { ctx.Baseline.Degraded = true },
			says:   "too_volatile",
			why:    "a degraded comparison can never produce clean",
		},
		{
			name:   "the value was a fabricated canary",
			mutate: func(ctx *triage.ClassifyCtx, _ *sqlEvidence) { ctx.Slot.ValueOrigin = triage.ValueCanary },
			says:   "canary_resource",
			why:    "a scan of a 404 that came back with nothing found is not a clean scan of the endpoint",
		},
		{
			name: "not one probe reached the application",
			mutate: func(_ *triage.ClassifyCtx, ev *sqlEvidence) {
				for i := range ev.all {
					ev.all[i].obs.TransportErr = triage.TransportConnect
				}
			},
			says: "blocked (transport)",
			why:  "a transport refusal is could-not-send, never a quiet response",
		},
		{
			name:   "the slot does not percent-decode",
			mutate: func(_ *triage.ClassifyCtx, ev *sqlEvidence) { ev.decodeDepth = 0 },
			says:   "decode_depth_0",
			why:    "a percent-encoded quote that was never decoded never reached the parser",
		},
		{
			name:   "the decode probe was never sent",
			mutate: func(_ *triage.ClassifyCtx, ev *sqlEvidence) { ev.decodeDepth = -1 },
			says:   "decode_depth_not_measured",
			why:    "a probe that was never sent has no outcome to report, and reporting one is the same bug one level up",
		},
		{
			name: "the decode probe ran and the endpoint reflects nothing",
			mutate: func(_ *triage.ClassifyCtx, ev *sqlEvidence) {
				ev.decodeDepth = -1
				s := sqlSeen{probe: sqlDEC, ordinal: 900, obs: sqlTestObs("ok")}
				ev.byProbe[sqlDEC] = append(ev.byProbe[sqlDEC], s)
				ev.all = append(ev.all, s)
			},
			says: "no_reflection",
			why:  "an oracle that was structurally unavailable is a different fact from one that was ambiguous, and the operator's next move differs",
		},
		{
			name: "the decode probe ran on an echoing endpoint and was inconclusive",
			mutate: func(_ *triage.ClassifyCtx, ev *sqlEvidence) {
				ev.decodeDepth = -1
				ev.echoedAny = true
				s := sqlSeen{probe: sqlDEC, ordinal: 901, obs: sqlTestObs("ok")}
				ev.byProbe[sqlDEC] = append(ev.byProbe[sqlDEC], s)
				ev.all = append(ev.all, s)
			},
			says: "decode_depth_unknown",
			why:  "unknown is not zero and neither is clean",
		},
		{
			name: "the field truncates before the marker and the marker-first probe was not sent",
			mutate: func(ctx *triage.ClassifyCtx, _ *sqlEvidence) {
				ctx.Slot.Constraints.FieldLimit = 8
			},
			says: "truncated",
			why:  "every payload in this class leads with the observed value, so a short field blinds the primary oracle entirely",
		},
		{
			name: "no probe recorded its payload surviving to the wire",
			mutate: func(_ *triage.ClassifyCtx, ev *sqlEvidence) {
				for i := range ev.all {
					ev.all[i].obs.Payload.Survived = triage.WireSurvivalUnknown
				}
			},
			says: "metachar_stripped",
			why:  "net/http's cookie writer silently drops the semicolon, the double quote and the backslash, which are this class's probe characters",
		},
		{
			name:   "the budget cut the ladder short",
			mutate: func(ctx *triage.ClassifyCtx, _ *sqlEvidence) { ctx.Budget.RemainingPerSlot = 0 },
			says:   "probe_budget_exhausted",
			why:    "a cap that bites produces a named unknown, never a shortened clean",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := sqlTestCtx()
			ev := sqlTestEvidence(silent, quiet...)
			tc.mutate(&ctx, ev)
			vs := sqlDecide(ctx, ev, false)
			if len(vs) == 0 {
				t.Fatal("no verdict at all, so the slot reads as untouched")
			}
			// The property is at the AGGREGATE, because CATALOGUE 4.5 rule 1 forbids folding an
			// unknown into a clean at ANY layer. Some of these cases legitimately emit a clean
			// row for the arm that did run alongside an unknown row for the arm that could not,
			// and what must never happen is the report rendering the slot as a green tick.
			if cov := triage.SummariseVerdicts(vs); cov.RendersAsClean() {
				t.Errorf("the slot rendered as clean: %s (%s)", tc.name, tc.why)
			}
			found := false
			for _, v := range vs {
				if err := v.Validate(); err != nil {
					t.Errorf("verdict failed its own contract: %v", err)
				}
				if strings.Contains(v.Reason, tc.says) {
					found = true
				}
			}
			if !found {
				t.Errorf("no verdict named %q; got %s", tc.says, sqlReasons(vs))
			}
		})
	}
}

func sqlReasons(vs []triage.ClassVerdict) string {
	var b strings.Builder
	for _, v := range vs {
		fmt.Fprintf(&b, "[%s %s: %.90s] ", v.State, v.Oracle, v.Reason)
	}
	return b.String()
}

// Drift and a uniform block each end the slot with a statement rather than a pass.
func TestDriftAndAUniformBlockEndTheSlotWithAStatement(t *testing.T) {
	silent := sqlTestObs("ok")
	ev := sqlTestEvidence(silent, sqlTestProbe{id: sqlQ1, obs: silent}, sqlTestProbe{id: sqlQ2, obs: silent})
	vs := sqlDecide(sqlTestCtx(), ev, true)
	if vs[0].State != triage.StateCannotDetermine || !strings.Contains(vs[0].Reason, "drift") {
		t.Errorf("drift produced %s %q", vs[0].State, vs[0].Reason)
	}

	block := sqlTestObs("<h1>403 Forbidden</h1>")
	bev := sqlTestEvidence(silent,
		sqlTestProbe{id: sqlQ1, obs: block},
		sqlTestProbe{id: sqlD1P, obs: block},
		sqlTestProbe{id: sqlB1, obs: block},
	)
	if !bev.uniformBlock {
		t.Fatal("three distinct payloads returning the same non-control body was not recognised as a uniform block")
	}
	bvs := sqlDecide(sqlTestCtx(), bev, false)
	if bvs[0].State != triage.StateCannotDetermine || !strings.Contains(bvs[0].Reason, "blocked") {
		t.Errorf("uniform block produced %s %q", bvs[0].State, bvs[0].Reason)
	}
	if reqs := sqlNextRequests(sqlTestCtx().PlanCtx, bev); len(reqs) != 0 {
		t.Errorf("the ladder kept spending requests into a block: %v", reqs)
	}
}

// A slot that cannot be reached or must not be touched gets a named non-test, not a pass.
func TestTheFragmentAndTheCredentialSlotAreNamedNonTestsAndNeverCleans(t *testing.T) {
	c := sqlClassifier{}

	frag := sqlTestCtx()
	frag.Slot.Kind = triage.KindFragment
	frag.Slot.ServerReachable = false
	vs := c.Classify(frag)
	if vs[0].State != triage.StateNotApplicable || sqlAnyClean(vs) {
		t.Errorf("fragment produced %s", vs[0].State)
	}
	if !strings.Contains(vs[0].Reason, "fragment") {
		t.Errorf("reason %q does not name the fragment", vs[0].Reason)
	}

	cred := sqlTestCtx()
	cred.Slot.Constraints.IsCredential = true
	cvs := c.Classify(cred)
	if cvs[0].State != triage.StateNotProbed || sqlAnyClean(cvs) {
		t.Errorf("credential slot produced %s", cvs[0].State)
	}
	if reqs := c.Plan(cred.PlanCtx); len(reqs) != 0 {
		t.Errorf("a credential slot was planned against: %v", reqs)
	}

	pre := sqlTestCtx()
	pre.Prelude = triage.PreludeTokenUnobtainable
	pvs := c.Classify(pre)
	if pvs[0].State != triage.StateCannotDetermine || !strings.Contains(pvs[0].Reason, "prelude_failed") {
		t.Errorf("an unobtainable prelude produced %s %q", pvs[0].State, pvs[0].Reason)
	}

	// The route control is a Replay, which cannot be constructed outside package triage, so the
	// default ctx carries an unresolved one. That is the fail-closed path and it is worth
	// asserting: no route control means no control to difference against.
	unresolved := sqlTestCtx()
	uvs := c.Classify(unresolved)
	if uvs[0].State != triage.StateCannotDetermine || !strings.Contains(uvs[0].Reason, "route_unresolved") {
		t.Errorf("an unresolved route produced %s %q", uvs[0].State, uvs[0].Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// THE CLEAN, AND WHAT IT CARRIES
// ---------------------------------------------------------------------------------------------

// The one path that may say clean emits a row per detector arm, each with its own ordinals, and
// the annotation that says what the clean does NOT cover.
func TestACleanCarriesItsOwnOrdinalsPreconditionsAndOneRowPerArm(t *testing.T) {
	silent := sqlTestObs("ok")
	ev := sqlTestEvidence(silent,
		sqlTestProbe{id: sqlQ1, obs: silent}, sqlTestProbe{id: sqlQ2, obs: silent},
		sqlTestProbe{id: sqlD1P, obs: silent}, sqlTestProbe{id: sqlD2P, obs: silent},
		sqlTestProbe{id: sqlA1, obs: silent}, sqlTestProbe{id: sqlA2, obs: silent},
		sqlTestProbe{id: sqlA3, obs: sqlTestObs("500")},
	)
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if len(vs) != 2 {
		t.Fatalf("want one row per arm, got %d: %s", len(vs), sqlReasons(vs))
	}
	arms := map[string]triage.ClassVerdict{}
	for _, v := range vs {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
		arms[v.Oracle] = v
	}
	for _, oracle := range []string{"parser_error", "boolean_differential"} {
		v, ok := arms[oracle]
		if !ok {
			t.Fatalf("no row for the %s arm, so its silence hides inside the other arm's clean", oracle)
		}
		if v.State != triage.StateClean {
			t.Errorf("%s arm is %s, want clean", oracle, v.State)
		}
		if len(v.Ordinals) == 0 {
			t.Errorf("%s arm reported clean with zero probe ordinals, which asserts a measurement that never happened", oracle)
		}
	}
	if arms["parser_error"].Annotations["quote_survival_unproven"] != true {
		t.Error("no probe echoed anything anywhere, so the clean must carry quote_survival_unproven: we cannot separate correctly parameterised from the quote being stripped before the query")
	}
	if _, ok := arms["parser_error"].Annotations["stacked_query"]; !ok {
		t.Error("the stacked-statement gap is a standing limitation of every clean in this class and must be printed with it")
	}
}

// A silent error arm plus an unrunnable boolean arm is two rows, and the aggregate is not clean.
// Folding them into one clean is the bug this whole layer exists to stop.
func TestASilentErrorArmDoesNotCoverABooleanArmThatCouldNotRun(t *testing.T) {
	silent := sqlTestObs("ok")
	ctx := sqlTestCtx()
	ctx.Baseline.Stable = false
	ctx.Baseline.GateReason = "too_volatile"
	ev := sqlTestEvidence(silent,
		sqlTestProbe{id: sqlQ1, obs: silent}, sqlTestProbe{id: sqlQ2, obs: silent},
		sqlTestProbe{id: sqlA1, obs: silent}, sqlTestProbe{id: sqlA2, obs: silent}, sqlTestProbe{id: sqlA3, obs: silent},
	)
	vs := sqlDecide(ctx, ev, false)
	cov := triage.SummariseVerdicts(vs)
	if cov.RendersAsClean() {
		t.Fatal("the aggregate rendered as clean while the only detector that can see an error-suppressing endpoint never ran")
	}
	if cov.Unknown == 0 {
		t.Error("no unknown row, so nothing in the report names the half that was not tested")
	}
	if len(cov.Malformed) != 0 {
		t.Errorf("malformed verdicts: %v", cov.Malformed)
	}
}

// Every declared probe that was not sent appears in Untested with a reason. A class that quietly
// plans fewer probes on one slot than another is the shape of a silent zero.
func TestEveryProbeThisClassDidNotSendIsNamedWithAReason(t *testing.T) {
	silent := sqlTestObs("ok")
	ev := sqlTestEvidence(silent, sqlTestProbe{id: sqlQ1, obs: silent}, sqlTestProbe{id: sqlQ2, obs: silent})
	vs := sqlDecide(sqlTestCtx(), ev, false)
	declared := map[triage.ProbeID]bool{}
	for _, p := range (sqlClassifier{}).Probes() {
		declared[p.ID] = true
	}
	named := map[triage.ProbeID]bool{sqlQ1: true, sqlQ2: true}
	for _, s := range vs[0].Untested {
		if strings.TrimSpace(s.Reason) == "" {
			t.Errorf("probe %s is listed as untested with no reason", s.ProbeID)
		}
		named[s.ProbeID] = true
	}
	for id := range declared {
		if !named[id] {
			t.Errorf("probe %s was neither sent nor named as untested, so it vanished silently", id)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

// The observed value's shape ORDERS the ladder and never suppresses it. A shape guess that
// suppresses a probe is a silent zero, and this codebase has removed several.
func TestTheValueShapeOrdersTheLadderAndNeverSuppressesIt(t *testing.T) {
	cases := []struct {
		name  string
		slot  triage.Slot
		first triage.ProbeID
		why   string
	}{
		{
			name:  "a digits-only value leads with the cast pair",
			slot:  triage.Slot{Value: "1", ValueKind: triage.ValueNumeric},
			first: sqlC5,
			why:   "on a real corpus the int cast is the most common answer on a numeric slot and proving it costs two requests",
		},
		{
			name:  "a slot named sort leads with the comma and the ordinal",
			slot:  triage.Slot{Name: "sort", Value: "name", ValueKind: triage.ValueEnumLike},
			first: sqlC1,
			why:   "an identifier or ordinal context is where no quote is syntactically available and where every other tool is blind",
		},
		{
			name:  "free text leads with the single-quote break",
			slot:  triage.Slot{Name: "q", Value: "alice", ValueKind: triage.ValueFreeText},
			first: sqlQ1,
			why:   "the single quote is the highest-yield first probe on a string sink",
		},
		{
			name:  "a UUID is probed like free text and is not skipped",
			slot:  triage.Slot{Name: "id", Value: "3f2504e0-4f89-11d3-9a0c-0305e82c3301", ValueKind: triage.ValueUUID},
			first: sqlQ1,
			why:   "a UUID-shaped value still reaches a string-built statement, and suppressing it would be a silent zero",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rungs := sqlLadderFor(tc.slot)
			if len(rungs) < 2 {
				t.Fatalf("ladder has %d rungs", len(rungs))
			}
			if rungs[0][0] != sqlNC1 {
				t.Errorf("the junk control is not first; it is what says whether the marker oracle is usable here at all")
			}
			// The unrepaired break is in rung 0 on EVERY shape. It is one request, it needs no
			// baseline and it is the only payload in the class that can provoke an
			// unterminated-literal error, so a shape that reaches it five rungs later reports an
			// absence whenever the budget runs out in between.
			inRung0 := false
			for _, id := range rungs[0] {
				if id == sqlU1 {
					inRung0 = true
				}
			}
			if !inRung0 {
				t.Errorf("the %s ladder does not send the unrepaired break in rung 0, so the class's strongest oracle waits behind the shape guess", tc.name)
			}
			if rungs[1][0] != tc.first {
				t.Errorf("first detection probe is %s, want %s (%s)", rungs[1][0], tc.first, tc.why)
			}
			// Every shape eventually reaches every context, in some order.
			seen := map[triage.ProbeID]bool{}
			for _, r := range rungs {
				for _, id := range r {
					seen[id] = true
				}
			}
			for _, must := range []triage.ProbeID{sqlQ1, sqlC1, sqlB1, sqlK1, sqlP1, sqlP3} {
				if !seen[must] {
					t.Errorf("the %s ladder never reaches %s, so that context is a silent zero on this shape", tc.name, must)
				}
			}
		})
	}
}

// A cookie that does not percent-decode gets the whitespace-free forms, and the probes it cannot
// carry are recorded as unreachable rather than quietly dropped.
func TestACookieThatDoesNotDecodeGetsTheCommentFormAndSaysWhichProbesItCannotCarry(t *testing.T) {
	ctx := sqlTestCtx()
	ctx.Slot.Kind = triage.KindCookie
	ctx.Slot.Key = "cookie:theme"
	ctx.Slot.Name = "theme"
	ctx.Slot.Constraints.DecodeDepth = 0

	if r := sqlSkipReason(sqlC3, ctx.PlanCtx); !strings.Contains(r, "decode_depth_0") {
		t.Errorf("SQL-C3 on a non-decoding cookie is skipped with %q, want a decode_depth_0 reason: the space cannot be delivered", r)
	}
	if r := sqlSkipReason(sqlA1, ctx.PlanCtx); !strings.Contains(r, "decode_depth_0") {
		t.Errorf("SQL-A1 on a non-decoding cookie is skipped with %q", r)
	}
	if r := sqlSkipReason(sqlA1w, ctx.PlanCtx); r != "" {
		t.Errorf("the comment form was skipped on the one slot it exists for: %q", r)
	}
	if r := sqlSkipReason(sqlA1w, sqlTestCtx().PlanCtx); r == "" {
		t.Error("the comment form was planned on a slot that can carry a space, which spends a request to test a substitution nothing needs")
	}
}

// The flow probe is never planned unless the operator budgeted a mutating request, and never on a
// verb that deletes. It writes a value that persists, and that is the one thing the safety rule
// refuses outright.
func TestTheSecondOrderFlowProbeIsDeclinedUnlessTheOperatorBudgetedAWrite(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		mutting int
		allowed bool
	}{
		{"a GET is never a write", "GET", 4, false},
		{"a DELETE is refused even with budget", "DELETE", 4, false},
		{"a POST with no mutating allowance is refused", "POST", 0, false},
		{"a POST the operator budgeted is allowed", "POST", 4, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := sqlTestCtx()
			ctx.Slot.Method = tc.method
			ctx.Budget.RemainingMutating = tc.mutting
			if got := sqlFlowProbeAllowed(ctx.PlanCtx); got != tc.allowed {
				t.Fatalf("allowed=%v want %v", got, tc.allowed)
			}
			if !tc.allowed {
				if r := sqlSkipReason(sqlS1, ctx.PlanCtx); !strings.Contains(r, "second_order_write_declined") {
					t.Errorf("skip reason %q does not name second_order_write_declined", r)
				}
			}
		})
	}
}

// A hit ends the ladder, but not before the control and a repeat with a fresh marker are sent.
func TestAHitEndsTheLadderOnlyAfterItsControlAndItsRepeat(t *testing.T) {
	hit := sqlTestObs(sqlPGError())
	silent := sqlTestObs("ok")
	ctx := sqlTestCtx()

	ev := sqlTestEvidence(silent, sqlTestProbe{id: sqlQ1, obs: hit})
	reqs := sqlNextRequests(ctx.PlanCtx, ev)
	got := map[triage.ProbeID]int{}
	for _, r := range reqs {
		got[r.Spec]++
	}
	if got[sqlQ2] != 1 || got[sqlQ1] != 1 {
		t.Fatalf("after a hit the ladder planned %v, want the balanced control and a repeat of the break", got)
	}

	done := sqlTestEvidence(silent,
		sqlTestProbe{id: sqlQ1, obs: hit},
		sqlTestProbe{id: sqlQ1, obs: hit, ordinal: 68},
		sqlTestProbe{id: sqlQ2, obs: silent},
	)
	if rest := sqlNextRequests(ctx.PlanCtx, done); len(rest) != 0 {
		t.Errorf("the ladder kept going after a confirmed hit: %v", rest)
	}
}

// A proven cast stops the ladder, because nothing after it can add anything.
func TestAProvenCastStopsTheLadder(t *testing.T) {
	base := sqlTestObs("rows: 1")
	ev := sqlTestEvidence(base,
		sqlTestProbe{id: sqlC5, obs: base},
		sqlTestProbe{id: sqlC6, obs: sqlTestObs("rows: 0")},
	)
	if reqs := sqlNextRequests(sqlTestCtx().PlanCtx, ev); len(reqs) != 0 {
		t.Errorf("the ladder kept spending requests on a slot whose value is cast to an integer: %v", reqs)
	}
}

// ---------------------------------------------------------------------------------------------
// REACH, COMPARISON, AND THE DECLARED ORACLE SET
// ---------------------------------------------------------------------------------------------

func TestReachesNamesAReasonEverywhereOneIsRequired(t *testing.T) {
	c := sqlClassifier{}
	for _, k := range triage.AllSlotKinds() {
		for _, mt := range []triage.MediaType{"", "application/json", "application/x-www-form-urlencoded", "multipart/form-data", "application/xml", "application/graphql", "text/html"} {
			r := c.Reaches(k, mt)
			if r.Reach != triage.ReachAlways && strings.TrimSpace(r.Reason) == "" {
				t.Errorf("Reaches(%s, %q) is %s with no reason, so an operator cannot tell ruled out from never wired up", k, mt, r.Reach)
			}
		}
	}
	if r := c.Reaches(triage.KindFragment, ""); r.Reach != triage.ReachNever {
		t.Error("the fragment is reachable, but RFC 3986 section 3.5 says it is never transmitted")
	}
	if r := c.Reaches(triage.KindBody, "application/json"); !strings.Contains(r.Reason, "NOSQL") {
		t.Error("the JSON container answer does not say the object encoder belongs to NOSQL, which is where the reader has to be sent")
	}
}

// An unmeasured comparison must never read as "same", because "same" is the true half of the
// boolean differential and a default of same manufactures it out of nothing.
func TestAnUnmeasuredComparisonIsNeverSame(t *testing.T) {
	ok := sqlTestObs("body")
	cases := []struct {
		name  string
		probe triage.Observation
		ctl   triage.Observation
		want  sqlCmp
	}{
		{"a transport refusal", func() triage.Observation { o := sqlTestObs("x"); o.TransportErr = triage.TransportTimeout; return o }(), ok, sqlCmpUnusable},
		{"two empty bodies", sqlTestObs(""), sqlTestObs(""), sqlCmpUnusable},
		{"a truncated body", func() triage.Observation { o := sqlTestObs("x"); o.BodyTruncated = true; return o }(), ok, sqlCmpUnusable},
		{"a different status", func() triage.Observation { o := sqlTestObs("body"); o.Status = 500; return o }(), ok, sqlCmpDifferent},
		{"identical bodies", ok, ok, sqlCmpSame},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sqlCompare(tc.probe, tc.ctl); got != tc.want {
				t.Errorf("cmp=%q want %q", got, tc.want)
			}
		})
	}
	if sqlCmpUnusable != "" {
		t.Error("the unusable comparison is not the zero value, so a forgotten field reads as a measurement")
	}
}

// The oracle set declares both a route this class MUST fire on and a route it MUST stay silent
// on. Verification that only counts hits is how a detector that always says yes passes.
func TestTheOracleSetDeclaresBothAFireRouteAndASilentRoute(t *testing.T) {
	cases := (sqlClassifier{}).OracleCases()
	var pos, neg int
	seen := map[string]bool{}
	declared := map[triage.ProbeID]bool{}
	for _, p := range (sqlClassifier{}).Probes() {
		declared[p.ID] = true
	}
	for _, c := range cases {
		if seen[c.Route] {
			t.Errorf("route %s is declared twice", c.Route)
		}
		seen[c.Route] = true
		switch c.Expect {
		case sqlExpectPositive:
			pos++
		case sqlExpectNegative:
			neg++
		default:
			t.Errorf("route %s expects %q, which is neither positive nor negative", c.Route, c.Expect)
		}
		if strings.TrimSpace(c.Why) == "" {
			t.Errorf("route %s carries no reason, so nobody building it knows what it is for", c.Route)
		}
		for _, id := range c.Probes {
			if !declared[id] {
				t.Errorf("route %s names probe %s, which this class does not declare", c.Route, id)
			}
		}
	}
	if pos == 0 || neg == 0 {
		t.Fatalf("the oracle set has %d fire routes and %d silent routes; a detector never shown staying silent is not verified", pos, neg)
	}
	for _, want := range []string{"/clean/dberror", "/clean/echoparser", "/clean/intcast"} {
		if !seen[want] {
			t.Errorf("%s is not in the oracle set, and it is one of the three routes this class cannot be trusted without", want)
		}
	}
}

// Every break has a confirmation and every confirmation names what it proves.
func TestEveryBreakHasAConfirmationThatSaysWhatItProves(t *testing.T) {
	c := sqlClassifier{}
	have := map[triage.ProbeID]bool{}
	for _, cf := range c.Confirmers() {
		if len(cf.Confirm) == 0 || strings.TrimSpace(cf.Proves) == "" {
			t.Errorf("confirmer for %s is empty", cf.Hit)
		}
		have[cf.Hit] = true
	}
	for hit := range sqlBreakControls {
		if !have[hit] {
			t.Errorf("break %s has a control in the code but no confirmer row explaining what the control proves", hit)
		}
	}
	for _, e := range c.Evidencers() {
		if strings.TrimSpace(e.Records) == "" {
			t.Errorf("oracle %s records nothing", e.Oracle)
		}
	}
	if vs := c.Settle(sqlTestCtx()); vs != nil {
		t.Error("Settle returned a verdict, but this class has no deferred out-of-band check and inventing one would be a verdict about nothing")
	}
}

// ---------------------------------------------------------------------------------------------
// THE UNIFORM BLOCK AND THE LOOKUP PARAMETER, MEASURED AGAINST THE ORACLE
// ---------------------------------------------------------------------------------------------

// The oracle's /sqli route at its observed value id=1, byte for byte. It is the single commonest
// shape on the web: a lookup parameter whose value selects a record, where the control returns
// the record and ANY other value returns one byte-identical empty page.
const (
	sqlOracleRowPage = "<!doctype html><title>canary</title><!-- ARS0N_CANARY_OK -->\n" +
		"<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>\n<p>1 product matched.</p>"
	sqlOracleEmptyPage = "<!doctype html><title>canary</title><!-- ARS0N_CANARY_OK -->\n" +
		"<p>0 products matched.</p>"
)

// sqlOracleLookupEvidence is what this class sees on http://oracle:8000/sqli?id=1: the control
// returns the row, and the four probes of the first two rungs all return the same empty page.
//
// SQL-NC1 is in that set and it is the whole point. NC1 is the marker followed by four digits,
// purely alphanumeric, no metacharacter of any kind, and SQL-C6 is the observed value with every
// digit replaced by a 9. A filter refusing metacharacters cannot be what produced those two
// responses, so a bucket holding one of them is the application's own "no such record" page.
func sqlOracleLookupEvidence(extra ...sqlTestProbe) *sqlEvidence {
	empty := sqlTestObs(sqlOracleEmptyPage)
	probes := []sqlTestProbe{
		{id: sqlNC1, obs: empty},
		{id: sqlDEC, obs: empty},
		{id: sqlC5, obs: empty},
		{id: sqlC6, obs: empty},
	}
	return sqlTestEvidence(sqlTestObs(sqlOracleRowPage), append(probes, extra...)...)
}

// THE FALSE NEGATIVE THIS TEST EXISTS FOR. The uniform-block early exit used to fire on a lookup
// parameter, because every perturbation of a value that selects a record returns the same empty
// page and none of them equals the control. The class stopped after four requests, never sent the
// delimiter ladder and never sent the boolean arm, and called the endpoint filtered.
//
// The boolean arm is the ONLY detector in this class that can see an endpoint which suppresses
// errors, and a lookup parameter is exactly where a blind boolean injection lives, so the early
// exit removed the one detector that shape needs. sqlmap was never pointed at it.
func TestAUniformEmptyPageIsNotAFilterWhenThisClasssOwnMetacharacterFreeProbeIsInIt(t *testing.T) {
	ev := sqlOracleLookupEvidence()

	if ev.uniformBlock {
		t.Error("the four empty pages read as a uniform block, so the ladder stops after four requests " +
			"and the boolean arm is never sent. SQL-NC1 carries no metacharacter and produced the same " +
			"page, which rules a metacharacter filter out rather than in")
	}
	if got := sqlNextRequests(sqlTestCtx().PlanCtx, ev); len(got) == 0 {
		t.Error("the ladder returned no further probes, so it stopped on the empty pages")
	}
	for _, v := range sqlDecide(sqlTestCtx(), ev, false) {
		if strings.Contains(v.Reason, "blocked:") {
			t.Errorf("verdict %q claims a filter answered. Nothing was filtered: a lookup parameter "+
				"returns one empty page for every value that is not the one on record", v.Reason)
		}
	}
}

// And the cost of the early exit, stated as the thing it actually threw away: a CONFIRMED boolean
// injection, reported as a block.
func TestAConfirmedBooleanDifferentialIsNotReportedAsABlockedEndpoint(t *testing.T) {
	row := sqlTestObs(sqlOracleRowPage)
	empty := sqlTestObs(sqlOracleEmptyPage)
	// The true arm reproduces the row twice, the false arm and the invalid-syntax control do not.
	// That is d2Confirmed in full, and it is the shape a blind boolean injection makes.
	ev := sqlOracleLookupEvidence(
		sqlTestProbe{id: sqlA1, obs: row}, sqlTestProbe{id: sqlA1, obs: row},
		sqlTestProbe{id: sqlA2, obs: empty}, sqlTestProbe{id: sqlA3, obs: empty},
	)
	if _, ok := ev.d2Confirmed(); !ok {
		t.Fatal("the fixture no longer confirms the boolean differential, so this test proves nothing")
	}
	vs := sqlDecide(sqlTestCtx(), ev, false)
	for _, v := range vs {
		if strings.Contains(v.Reason, "blocked:") {
			t.Fatalf("a confirmed boolean differential was reported as %q. The uniform-block rule runs "+
				"before the positives, so the strongest evidence this class can produce was discarded "+
				"in favour of a claim about a filter", v.Reason)
		}
	}
	if len(vs) != 1 || vs[0].State != triage.StateFinding {
		t.Errorf("verdicts %+v, want one finding from the boolean differential", vs)
	}
}

// The rule still has to fire where it belongs: three metacharacter-carrying payloads collapsing
// onto one non-control response, with no inert probe of ours in that bucket, is a filter.
func TestThreeMetacharacterPayloadsCollapsingOnOneResponseIsStillABlock(t *testing.T) {
	blocked := sqlTestObs("<html><body>Request blocked by security policy.</body></html>")
	ev := sqlTestEvidence(sqlTestObs(sqlOracleRowPage),
		sqlTestProbe{id: sqlNC1, obs: sqlTestObs(sqlOracleEmptyPage)},
		sqlTestProbe{id: sqlQ1, obs: blocked},
		sqlTestProbe{id: sqlD1P, obs: blocked},
		sqlTestProbe{id: sqlB1, obs: blocked},
	)
	if !ev.uniformBlock {
		t.Fatal("three quote payloads answered by one identical page that the metacharacter-free " +
			"control did NOT produce is a filter, and the rule has to keep saying so")
	}
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if len(vs) != 1 || !strings.Contains(vs[0].Reason, "blocked:") {
		t.Errorf("verdicts %+v, want the blocked verdict", vs)
	}
}

// decode_depth ends up unknown in three different ways and they are three different facts. The
// reason used to describe an OUTCOME of the decode probe in all three, including on a slot where
// the decode probe was never sent, which reports a result where there is no result.
func TestTheThreeWaysDecodeDepthIsUnknownAreToldApart(t *testing.T) {
	empty := sqlTestObs(sqlOracleEmptyPage)
	echoing := sqlTestObs("you searched for " + sqlMarkerTemplate + " and found nothing")

	t.Run("the decode probe was never sent", func(t *testing.T) {
		ev := sqlTestEvidence(sqlTestObs(sqlOracleRowPage), sqlTestProbe{id: sqlQ1, obs: empty})
		ev.decodeDepth = -1
		if got := sqlDecodeUnknownReason(ev); !strings.Contains(got, "decode_depth_not_measured") {
			t.Errorf("reason %q claims the probe returned something. It was never sent", got)
		}
	})
	t.Run("the endpoint reflects nothing at all", func(t *testing.T) {
		ev := sqlTestEvidence(sqlTestObs(sqlOracleRowPage),
			sqlTestProbe{id: sqlDEC, obs: empty}, sqlTestProbe{id: sqlQ1, obs: empty})
		ev.decodeDepth = -1
		got := sqlDecodeUnknownReason(ev)
		if !strings.Contains(got, "no_reflection") {
			t.Errorf("reason %q frames an unavailable oracle as an ambiguous slot", got)
		}
	})
	t.Run("the endpoint echoes but the decode probe was ambiguous", func(t *testing.T) {
		ev := sqlTestEvidence(sqlTestObs(sqlOracleRowPage),
			sqlTestProbe{id: sqlDEC, obs: empty}, sqlTestProbe{id: sqlQ1, obs: echoing})
		ev.decodeDepth = -1
		got := sqlDecodeUnknownReason(ev)
		if strings.Contains(got, "no_reflection") || strings.Contains(got, "not_measured") {
			t.Errorf("reason %q, want the plain ambiguous reading: the probe ran and the endpoint echoes", got)
		}
	})
	t.Run("none of the three renders as clean", func(t *testing.T) {
		for _, ev := range []*sqlEvidence{
			sqlTestEvidence(sqlTestObs(sqlOracleRowPage), sqlTestProbe{id: sqlQ1, obs: empty}),
			sqlTestEvidence(sqlTestObs(sqlOracleRowPage), sqlTestProbe{id: sqlDEC, obs: empty}),
		} {
			ev.decodeDepth = -1
			if sqlAnyClean(sqlDecide(sqlTestCtx(), ev, false)) {
				t.Error("an unknown decode depth produced a clean")
			}
		}
	})
}

// ---------------------------------------------------------------------------------------------
// THE UNREPAIRED BREAK, MEASURED AGAINST THE ORACLE AT http://oracle:8000/sqli?id=1
// ---------------------------------------------------------------------------------------------

// sqlOracleUnterminatedError is the oracle's reply to the observed value followed by ONE single
// quote and this class's marker, captured off the wire byte for byte:
//
//	GET /sqli?id=1%27zqjsql0000004ju8   ->   HTTP 500, 267 bytes
//
// It is the commonest error-based shape there is: a driver exception whose first line names the
// complaint and whose LATER line quotes the submitted statement back verbatim, carrying our
// marker. Every JDBC, psycopg, PDO and Hibernate error page in the world is laid out this way.
const sqlOracleUnterminatedError = "<!doctype html><title>error</title><!-- ARS0N_CANARY_OK -->\n" +
	"<h1>Database error</h1>\n" +
	"<pre>org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near \"'\"\n" +
	"  Position: 42\n" +
	"  Query: SELECT name, price FROM products WHERE id = '1'" + sqlMarkerTemplate + "'</pre>"

// The other oracle routes, also captured off the wire with the SAME payload. Every one of them
// reflects the marker verbatim and none of them is SQL injectable, so they are the half of the
// bar that actually tests the detector: a class that fires everywhere is as useless as one that
// fires nowhere.
var sqlOracleReflectingRoutes = map[string]string{
	"/xss": "<!doctype html><title>canary</title><!-- ARS0N_CANARY_OK -->\n" +
		"<div id=\"out\">hello'" + sqlMarkerTemplate + "</div>\n" +
		"<script>var searchText = 'hello'" + sqlMarkerTemplate + "';</script>",
	"/lfi": "no such document: hello'" + sqlMarkerTemplate + "\n",
	"/ssti": "<!doctype html><title>canary</title><!-- ARS0N_CANARY_OK -->\n" +
		"<h1>Hello, hello'" + sqlMarkerTemplate + "!</h1>\n" +
		"<p>Rendered by the canary oracle's emulated template engine.</p>",
	"/cmdi":     "PING hello'" + sqlMarkerTemplate + ": 56 data bytes\n1 packets transmitted, 1 received\nARS0N_CANARY_OK\n",
	"/redirect": "redirecting to hello'" + sqlMarkerTemplate,
}

// sqlUnrepairedBreakProbe finds the declared probe that leaves the string literal OPEN: an odd
// number of single quotes and no comment to swallow the tail.
//
// THE BUG THIS EXISTS TO NAME. Every delimiter payload in this class closes and reopens, which is
// right for the boolean arm and leaves the statement lexically complete. The consequence nobody
// wrote down is that no payload in the class can ever produce an unterminated-literal error, and
// two phrases in the class's OWN strong catalogue, pg.unterminated_quoted and
// mssql.unclosed_quotation, are therefore unreachable by anything this class sends. They are
// detectors watching for an error the class has no way to cause.
func sqlUnrepairedBreakProbe(t *testing.T) triage.ProbeID {
	t.Helper()
	var found []triage.ProbeID
	for _, p := range (sqlClassifier{}).Probes() {
		if bytes.Contains(p.Logical, []byte("--")) || bytes.Contains(p.Logical, []byte("/*")) {
			continue
		}
		if bytes.Count(p.Logical, []byte("'"))%2 == 1 {
			found = append(found, p.ID)
		}
	}
	if len(found) != 1 {
		t.Fatalf("declared probes leaving an unbalanced single quote: %v, want exactly one. "+
			"With none, the class cannot produce an unterminated-literal error at all and "+
			"pg.unterminated_quoted and mssql.unclosed_quotation can never fire; with more than "+
			"one, two payloads test the same thing and no verdict can name which broke it", found)
	}
	return found[0]
}

// The marker inside the echoed statement of a driver error block is a hit even though the phrase
// is on an earlier line. That is the layout of every driver error page there is, and requiring
// the same line meant this oracle could only ever see a single-line MySQL 1064.
func TestTheMarkerInsideAnEchoedStatementOfTheSameErrorBlockIsAHit(t *testing.T) {
	got := sqlEvalD1(sqlTestObs(sqlOracleUnterminatedError))
	if !got.Fired {
		t.Fatalf("the oracle's own 500 did not fire the primary oracle. refusal %q. "+
			"The engine quoted OUR marker back inside the statement it could not parse, which is "+
			"the one oracle in this class that needs no baseline", got.Why)
	}
	if got.Phrase != "pg.unterminated_quoted" {
		t.Errorf("phrase %q, want pg.unterminated_quoted", got.Phrase)
	}
	if e := sqlIdentifyEngine([]byte(sqlOracleUnterminatedError)); e != "postgresql" {
		t.Errorf("engine %q, want postgresql: --dbms is what makes the operator's sqlmap run cheaper than a cold start", e)
	}
}

// And the negatives the block rule must not swallow. A marker sitting alone on the next line is
// still not associated, because a stack trace and a template put unrelated things there.
func TestTheBlockRuleStillRefusesEveryNamedFalsePositive(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"the marker alone on the following line", "ERROR:  syntax error at or near \"x\"\n" + sqlMarkerTemplate},
		{"the marker beyond the window on a labelled line", "ERROR:  syntax error at or near \"x\"\n  Query: " + strings.Repeat("x", 200) + sqlMarkerTemplate},
		{"a blank line between the phrase and the echoed statement", "ERROR:  syntax error at or near \"x\"\n\n  Query: select " + sqlMarkerTemplate},
		{"the search box on a page about databases", "<h1>SQL syntax tutorial</h1>\n<input value=\"" + sqlMarkerTemplate + "\">"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sqlEvalD1(sqlTestObs(tc.body)); got.Fired {
				t.Errorf("fired on %q", tc.name)
			}
		})
	}
}

// THE BAR, BOTH HALVES. The class fires on the deliberately vulnerable route with a named oracle
// and an ordinal, and stays silent on every oracle route that is not SQL injectable.
func TestTheClassFiresOnTheVulnerableOracleRouteAndStaysSilentOnTheOthers(t *testing.T) {
	u1 := sqlUnrepairedBreakProbe(t)
	empty := sqlTestObs(sqlOracleEmptyPage)
	row := sqlTestObs(sqlOracleRowPage)

	broke := sqlTestObs(sqlOracleUnterminatedError)
	broke.Status = 500

	t.Run("it fires on /sqli", func(t *testing.T) {
		ev := sqlTestEvidence(row,
			sqlTestProbe{id: sqlNC1, obs: empty},
			sqlTestProbe{id: sqlDEC, obs: empty},
			sqlTestProbe{id: u1, obs: broke},
			sqlTestProbe{id: sqlQ2, obs: empty},
		)
		vs := sqlDecide(sqlTestCtx(), ev, false)
		if len(vs) != 1 || vs[0].State != triage.StateFinding {
			t.Fatalf("verdicts %s, want one finding. This is the single most visible defect in the "+
				"whole layer: sqlmap is the tool everyone knows and triage never points it anywhere", sqlReasons(vs))
		}
		if vs[0].Oracle != "parser_error" {
			t.Errorf("oracle %q, want parser_error", vs[0].Oracle)
		}
		if len(vs[0].Ordinals) == 0 {
			t.Error("the finding carries no ordinal, so nobody can trace it back to a probe")
		}
		if vs[0].Label.Engine != "postgresql" {
			t.Errorf("label engine %q, want postgresql", vs[0].Label.Engine)
		}
		if err := vs[0].Validate(); err != nil {
			t.Errorf("verdict failed its own contract: %v", err)
		}
	})

	t.Run("it stays silent on every reflecting route", func(t *testing.T) {
		for route, body := range sqlOracleReflectingRoutes {
			refl := sqlTestObs(body)
			if got := sqlEvalD1(refl); got.Fired {
				t.Errorf("%s: the primary oracle fired on a route with no database behind it at all. "+
					"Reflection is not injection", route)
			}
			ev := sqlTestEvidence(sqlTestObs("baseline "+route),
				sqlTestProbe{id: sqlNC1, obs: refl},
				sqlTestProbe{id: u1, obs: refl},
				sqlTestProbe{id: sqlQ2, obs: refl},
			)
			for _, v := range sqlDecide(sqlTestCtx(), ev, false) {
				if v.State == triage.StateFinding || v.State == triage.StateSuspicious {
					t.Errorf("%s: %s (%s). A class that fires everywhere is as useless as one that fires nowhere",
						route, v.State, v.Reason)
				}
			}
		}
	})
}

// The escaped percent moving the response too disqualifies THE LIKE ARM and nothing else.
//
// THE FALSE NEGATIVE THIS TEST EXISTS FOR. The old rule read "both halves of the LIKE pair differ
// from the control" as this class's negative control FIRING, and returned one class-wide
// cannot_determine (detector_unverified) before the positives were looked at at all. Both halves
// differ from the control on every endpoint whose value selects a record, which is most of the
// web, so a slot carrying a live parser break reported detector_unverified and sqlmap was never
// pointed at it. Measured against the oracle: /xss, /lfi and /ssti all landed there.
//
// The A3 half of the same function was already scoped this way, with a comment explaining that
// the unscoped version turned every inert slot into detector_unverified. The LIKE half never got
// the same treatment, and it cannot: the LIKE detector claims something only when the escaped
// percent DID stay put, so the two conditions are mutually exclusive and the branch can never
// describe a detector that fired on its own control.
func TestAnEscapedPercentThatAlsoMovedTheResponseDisqualifiesOnlyTheLikeArm(t *testing.T) {
	base := sqlTestObs("3 results")
	wider := sqlTestObs("47 results")
	broke := sqlTestObs(sqlOracleUnterminatedError)

	// The probe lookup is inside the subtest that needs it, so the second subtest still runs on a
	// build that has no unrepaired break and can report what that build does with the LIKE pair.
	t.Run("it does not withdraw a live parser break", func(t *testing.T) {
		u1 := sqlUnrepairedBreakProbe(t)
		ev := sqlTestEvidence(base,
			sqlTestProbe{id: u1, obs: broke},
			sqlTestProbe{id: sqlQ2, obs: base},
			sqlTestProbe{id: sqlL1, obs: wider},
			sqlTestProbe{id: sqlL2, obs: wider},
		)
		vs := sqlDecide(sqlTestCtx(), ev, false)
		if vs[0].State != triage.StateFinding {
			t.Fatalf("verdicts %s, want the parser break to stand", sqlReasons(vs))
		}
	})

	t.Run("the LIKE arm says it could not be read, and says it in its own row", func(t *testing.T) {
		ev := sqlTestEvidence(base,
			sqlTestProbe{id: sqlQ1, obs: base}, sqlTestProbe{id: sqlQ2, obs: base},
			sqlTestProbe{id: sqlA1, obs: base}, sqlTestProbe{id: sqlA2, obs: sqlTestObs("none")},
			sqlTestProbe{id: sqlA3, obs: sqlTestObs("none")},
			sqlTestProbe{id: sqlL1, obs: wider}, sqlTestProbe{id: sqlL2, obs: wider},
		)
		vs := sqlDecide(sqlTestCtx(), ev, false)
		var like *triage.ClassVerdict
		for i := range vs {
			if vs[i].Oracle == "like_widening" {
				like = &vs[i]
			}
		}
		if like == nil {
			t.Fatalf("no row for the LIKE arm, so the fact that it could not be read vanished: %s", sqlReasons(vs))
		}
		if like.State != triage.StateCannotDetermine {
			t.Errorf("LIKE arm is %s, want cannot_determine", like.State)
		}
		if !strings.Contains(like.Reason, "like_arm_unreadable") {
			t.Errorf("reason %q does not name like_arm_unreadable", like.Reason)
		}
		for _, v := range vs {
			if strings.Contains(v.Reason, "detector_unverified") {
				t.Error("the LIKE ambiguity is still withdrawing the whole class")
			}
		}
	})
}

// ---------------------------------------------------------------------------------------------
// THE TWO IDENTIFIER CONTEXTS, MEASURED AGAINST THE ORACLE AT
// http://oracle:8000/sqli/mssql?sort=name AND http://oracle:8000/sqli/mysql?sort=name
//
// These are the two contexts SQL-K1 and SQL-B1 exist for and the two a quote ladder cannot reach.
// The full confusion matrix of run ef8c13ab declared SQL -> CLEAN on both of them. Both are live
// injections. A clean on a live injection is the worst answer this system can produce: the
// operator does not point sqlmap there and the bug is never found.
//
// The payload was right and the probe was sent. What failed was the READING: the oracle renders
// the driver message as HTML, so every quote in it arrives as &#39;, and nine of the eighteen
// strong phrases anchor on a literal quote.
// ---------------------------------------------------------------------------------------------

// Captured off the wire, byte for byte, with this class's own marker in the payload.
//
//	GET /sqli/mssql?sort=name%5Dzqjsql0000004ju8%5B   ->   HTTP 500
const sqlOracleMSSQLBracketBreak = "<!doctype html><title>error</title><!-- ARS0N_CANARY_OK -->\n" +
	"<h1>Server Error</h1>\n" +
	"<pre>System.Data.SqlClient.SqlException (0x80131904): Msg 102, Level 15, State 1, Line 1\n" +
	"Incorrect syntax near &#39;" + sqlMarkerTemplate + "[&#39;.\n" +
	"   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)\n" +
	"   Statement: SELECT name, price FROM products ORDER BY [name]" + sqlMarkerTemplate + "[]</pre>"

// GET /sqli/mssql?sort=name%5D%5Dzqjsql0000004ju8   ->   HTTP 500
const sqlOracleMSSQLDoubledControl = "<!doctype html><title>error</title><!-- ARS0N_CANARY_OK -->\n" +
	"<h1>Server Error</h1>\n" +
	"<pre>System.Data.SqlClient.SqlException (0x80131904): Msg 102, Level 15, State 1, Line 1\n" +
	"Incorrect syntax near &#39;]" + sqlMarkerTemplate + "&#39;.\n" +
	"   at System.Data.SqlClient.SqlConnection.OnError(SqlException exception)\n" +
	"   Statement: SELECT name, price FROM products ORDER BY [name]]" + sqlMarkerTemplate + "]</pre>"

// GET /sqli/mysql?sort=name%60zqjsql0000004ju8%60   ->   HTTP 500
const sqlOracleMySQLBacktickBreak = "<!doctype html><title>error</title><!-- ARS0N_CANARY_OK -->\n" +
	"<h1>Database error</h1>\n" +
	"<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server\n" +
	"version for the right syntax to use near &#39;name`" + sqlMarkerTemplate + "`&#39; at line 1\n" +
	"Statement: SELECT name, price FROM products ORDER BY `name`" + sqlMarkerTemplate + "``</pre>"

// GET /sqli/mysql?sort=name%60%60zqjsql0000004ju8   ->   HTTP 500
const sqlOracleMySQLDoubledControl = "<!doctype html><title>error</title><!-- ARS0N_CANARY_OK -->\n" +
	"<h1>Database error</h1>\n" +
	"<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server\n" +
	"version for the right syntax to use near &#39;name``" + sqlMarkerTemplate + "&#39; at line 1\n" +
	"Statement: SELECT name, price FROM products ORDER BY `name``" + sqlMarkerTemplate + "`</pre>"

// The same route at a value carrying no metacharacter: HTTP 200 and a row. This is what makes
// the 500 above mean something, and it is what SQL-NC1 measures.
//
//	GET /sqli/mssql?sort=namezqjsql0000004ju81234   ->   HTTP 200
const sqlOracleMSSQLInert = "<!doctype html><title>canary</title><!-- ARS0N_CANARY_OK -->\n" +
	"<table><tr><td>Rosewood Gin</td><td>42.00</td></tr></table>\n" +
	"<p>sorted by [name" + sqlMarkerTemplate + "1234]</p>\n"

// sqlTestObsAt is sqlTestObs with a status other than 200, because a break that BROKE something
// is the whole subject here and a fixture that is always 200 cannot express it.
func sqlTestObsAt(body string, status int) triage.Observation {
	o := sqlTestObs(body)
	o.Status = status
	return o
}

// THE DEFECT ITSELF. A server-rendered error page escapes the driver's quote, and a catalogue
// anchored on a literal quote reads nothing on it.
func TestTheDriverQuoteArrivesAsAnEntityOnEveryServerRenderedErrorPage(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		phrase string
		engine string
	}{
		{"the MSSQL bracket identifier, SQL-K1", sqlOracleMSSQLBracketBreak, "mssql.incorrect_syntax_near", "mssql"},
		{"the MySQL backtick identifier, SQL-B1", sqlOracleMySQLBacktickBreak, "mysql.right_syntax_near", "mysql"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sqlEvalD1(sqlTestObsAt(tc.body, 500))
			if !got.Fired {
				t.Fatalf("the primary oracle read nothing on a LIVE injection. refusal %q.\n"+
					"The engine quoted OUR marker back inside the message it could not parse. The only "+
					"thing between that and a finding is that the page is HTML and the driver's quote "+
					"arrived as an entity. This slot was reported CLEAN, and a clean on a live injection "+
					"is the worst answer this class can give", got.Why)
			}
			if got.Phrase != tc.phrase {
				t.Errorf("phrase %q, want %q", got.Phrase, tc.phrase)
			}
			if e := sqlIdentifyEngine([]byte(tc.body)); e != tc.engine {
				t.Errorf("engine %q, want %q: the engine is printed in the first line of the reply, and without it the operator gets a finding with no --dbms", e, tc.engine)
			}
		})
	}
}

// The structural half, so the next phrase somebody adds cannot reintroduce this. No strong
// phrase may anchor on a bare quote character: every quote in the catalogue goes through the
// forms constant, which carries the raw, the JSON-escaped and the HTML-entity spellings.
func TestNoStrongPhraseAnchorsOnABareQuoteCharacter(t *testing.T) {
	strip := func(src string) string {
		src = strings.ReplaceAll(src, sqlQuoteForms, "")
		return strings.ReplaceAll(src, sqlDQuoteForms, "")
	}
	for _, p := range sqlEnginePhrases {
		if src := strip(p.re.String()); strings.ContainsAny(src, "'\"") {
			t.Errorf("phrase %s still anchors on a bare quote outside the quote-forms constant: %s\n"+
				"A driver message rendered into HTML carries the entity form and into JSON the backslash "+
				"form, and a pattern with a literal quote in it matches neither. That is how two live "+
				"injections came back clean", p.name, src)
		}
	}
	for _, f := range sqlEngineFingerprints {
		if src := strip(f.re.String()); strings.ContainsAny(src, "'\"") {
			t.Errorf("engine fingerprint %s anchors on a bare quote outside the quote-forms constant: %s", f.engine, src)
		}
	}
}

// Every escaper anybody actually uses, on the same message. A catalogue that reads Go's output
// and not PHP's is a catalogue that works on one stack.
func TestTheQuoteFormsCoverWhatRealEscapersEmit(t *testing.T) {
	find := func(name string) *regexp.Regexp {
		for _, p := range sqlEnginePhrases {
			if p.name == name {
				return p.re
			}
		}
		t.Fatalf("no phrase named %s", name)
		return nil
	}
	mssql := find("mssql.incorrect_syntax_near")
	for _, form := range []string{"'", "\\'", "&#39;", "&#039;", "&apos;", "&#x27;", "&#X27;"} {
		if body := "Incorrect syntax near " + form + sqlMarkerTemplate + form + "."; !mssql.MatchString(body) {
			t.Errorf("mssql.incorrect_syntax_near does not read the single quote spelled %q", form)
		}
	}
	pg := find("pg.syntax_error_at_or_near")
	for _, form := range []string{"\"", "\\\"", "&#34;", "&#034;", "&quot;", "&#x22;"} {
		if body := "ERROR:  syntax error at or near " + form + sqlMarkerTemplate + form; !pg.MatchString(body) {
			t.Errorf("pg.syntax_error_at_or_near does not read the double quote spelled %q", form)
		}
	}
}

// AND THE NEGATIVE THE FIX MUST NOT COST. /clean/echoparser carries the SAME entity-escaped
// MySQL 1064 in a debug footer and echoes the payload at the top of the page, far outside the
// window. Until now that route passed because the phrase never matched at all, which is passing
// for the wrong reason; now the phrase matches and the window rule has to do its job.
func TestTheWindowStillRefusesTheEchoparserPageNowThatItsPhraseIsReadable(t *testing.T) {
	body := "<!doctype html><title>search</title>\n<h1>No results</h1>\n" +
		"<p>Nothing matched hello&#39;" + sqlMarkerTemplate + ".</p>\n" +
		"<p>Try a shorter search term, or browse the catalogue by category. Popular\n" +
		"categories this week are gin, rye and vermouth. Saved searches are kept for thirty days and can be\n" +
		"exported from your account settings at any time.</p>\n" +
		"<div class=\"debug-footer\">\n<p>Last logged application error, retained for support:</p>\n" +
		"<pre>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server\n" +
		"version for the right syntax to use near &#39;LIMIT 0, 25&#39; at line 3</pre>\n</div>\n"

	var readable bool
	for _, p := range sqlEnginePhrases {
		if p.name == "mysql.right_syntax_near" {
			readable = p.re.MatchString(body)
		}
	}
	if !readable {
		t.Fatal("the phrase is not readable on this page, so this test is not exercising the window rule")
	}
	got := sqlEvalD1(sqlTestObs(body))
	if got.Fired {
		t.Fatalf("the oracle fired on a page that merely echoes the payload and separately mentions a "+
			"database error about LIMIT 0, 25. Reflection next to a stale error is not injection. matched %q", got.Matched)
	}
	if !strings.Contains(got.Why, "phrase_and_marker_not_the_same_error") {
		t.Errorf("refusal %q, want phrase_and_marker_not_the_same_error: the reason this page is clean must be the window rule and not an unreadable phrase", got.Why)
	}
}

// THE VERDICT ON THE TWO LIVE ROUTES. Before: parser_error CLEAN. It must never be clean again.
//
// It is NOT a finding either, and that is the oracle's debt rather than this class's. Both routes
// error on the mere PRESENCE of the delimiter, so the doubled control gets the identical message,
// and a break whose balanced control reproduces the same parse error is by this class's own rule
// a delimiter that never reached the parser. On a real engine ]] and a doubled backtick are
// ESCAPES and the control answers Invalid column name or Unknown column instead, which this class
// already whitelists as the identifier-context signal, and the pair then resolves to a finding.
func TestTheTwoIdentifierContextsAreNeverCleanAgain(t *testing.T) {
	cases := []struct {
		name               string
		breakID, ctlID     triage.ProbeID
		breakBody, ctlBody string
	}{
		{"/sqli/mssql, the bracket identifier", sqlK1, sqlK2, sqlOracleMSSQLBracketBreak, sqlOracleMSSQLDoubledControl},
		{"/sqli/mysql, the backtick identifier", sqlB1, sqlB2, sqlOracleMySQLBacktickBreak, sqlOracleMySQLDoubledControl},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := sqlTestEvidence(sqlTestObs(sqlOracleMSSQLInert),
				sqlTestProbe{id: sqlNC1, obs: sqlTestObs(sqlOracleMSSQLInert)},
				sqlTestProbe{id: tc.breakID, obs: sqlTestObsAt(tc.breakBody, 500)},
				sqlTestProbe{id: tc.ctlID, obs: sqlTestObsAt(tc.ctlBody, 500)},
			)
			vs := sqlDecide(sqlTestCtx(), ev, false)
			if sqlAnyClean(vs) {
				t.Fatalf("this live injection is still reported clean: %s", sqlReasons(vs))
			}
			if vs[0].State != triage.StateCannotDetermine {
				t.Fatalf("state %s, want cannot_determine: %s", vs[0].State, sqlReasons(vs))
			}
			if !strings.Contains(vs[0].Reason, "metachar_not_delivered") {
				t.Errorf("reason %q does not name metachar_not_delivered. The break and its doubled control "+
					"produced the identical parse error, which is the honest reading of what this oracle "+
					"sends back today", vs[0].Reason)
			}
		})
	}
}

// ---------------------------------------------------------------------------------------------
// THE SAFETY NET: A BREAK THAT BROKE THE SERVER AND LEFT NOTHING TO READ
// ---------------------------------------------------------------------------------------------

// The catalogue fix makes the oracle's two routes readable. This is the rule for the next one
// that is not: an unread measurement is not an absence of the vulnerability.
func TestABreakThatBrokeTheServerWithNothingReadableIsNotAClean(t *testing.T) {
	// A 500 from an application that caught the driver exception and rendered its own page. No
	// phrase, no marker, nothing at all for the error oracle to read.
	opaque := "<!doctype html><title>Error</title><h1>Something went wrong</h1><p>Reference 4471.</p>"
	ok := sqlTestObs(sqlOracleMSSQLInert)

	ev := sqlTestEvidence(ok,
		sqlTestProbe{id: sqlNC1, obs: ok},
		sqlTestProbe{id: sqlQ1, obs: sqlTestObsAt(opaque, 500)},
		sqlTestProbe{id: sqlQ2, obs: ok},
	)
	vs := sqlDecide(sqlTestCtx(), ev, false)
	if sqlAnyClean(vs) {
		t.Fatalf("a payload made the endpoint answer 500 where this class's own metacharacter-free "+
			"control got a 200, and the verdict is clean: %s", sqlReasons(vs))
	}
	if !strings.Contains(vs[0].Reason, "break_error_unreadable") {
		t.Fatalf("reason %q does not name break_error_unreadable", vs[0].Reason)
	}
	if !strings.Contains(vs[0].Reason, string(sqlQ1)) || !strings.Contains(vs[0].Reason, string(sqlNC1)) {
		t.Errorf("reason %q names neither the probe that broke it nor the metacharacter-free witness "+
			"that makes the comparison mean anything", vs[0].Reason)
	}
}

// And the four shapes it must stay out of, because a gate that fires often is a gate the operator
// learns to skip. Each of these already has a NAMED owner in this class and the new rule must
// neither steal it nor duplicate it.
func TestTheUnreadableBreakGateStaysOutOfTheShapesThatAlreadyHaveAnOwner(t *testing.T) {
	five := func(b string) triage.Observation { return sqlTestObsAt(b, 500) }
	four := func(b string) triage.Observation { return sqlTestObsAt(b, 400) }
	ok := sqlTestObs(sqlOracleMSSQLInert)

	t.Run("/clean/always500: every response is 5xx including the route control", func(t *testing.T) {
		ev := sqlTestEvidence(five("<h1>Service unavailable</h1>"),
			sqlTestProbe{id: sqlNC1, obs: five("<h1>Service unavailable</h1>")},
			sqlTestProbe{id: sqlQ1, obs: five("<h1>Service unavailable</h1>")},
		)
		if _, _, _, fired := ev.unreadableBreak(); fired {
			t.Error("fired on an endpoint that answers 500 to everything, which is not a break")
		}
	})

	t.Run("/clean/junk: the metacharacter-free control got the 5xx too", func(t *testing.T) {
		ev := sqlTestEvidence(ok,
			sqlTestProbe{id: sqlNC1, obs: five("<h1>Bad value</h1>")},
			sqlTestProbe{id: sqlQ1, obs: five("<h1>Bad value</h1>")},
		)
		if _, _, _, fired := ev.unreadableBreak(); fired {
			t.Error("fired where a purely alphanumeric suffix also produced the 500. That endpoint errors " +
				"on any modified value and junk_sensitive already owns it")
		}
	})

	t.Run("/clean/validate: a 4xx is a rejection, not a break", func(t *testing.T) {
		ev := sqlTestEvidence(ok,
			sqlTestProbe{id: sqlNC1, obs: ok},
			sqlTestProbe{id: sqlQ1, obs: four("<h1>That value could not be accepted</h1>")},
			sqlTestProbe{id: sqlQ2, obs: four("<h1>That value could not be accepted</h1>")},
		)
		if _, _, _, fired := ev.unreadableBreak(); fired {
			t.Error("fired on a 400. Input validation refusing a quote is a defence with its own name, " +
				"and calling it a broken server would put an unknown on every validated field on the web")
		}
	})

	t.Run("nothing metacharacter-free was measured at all", func(t *testing.T) {
		ev := &sqlEvidence{byProbe: map[triage.ProbeID][]sqlSeen{}, decodeDepth: 1}
		ev.all = append(ev.all, sqlSeen{probe: sqlQ1, obs: five("<h1>oops</h1>")})
		if _, _, _, fired := ev.unreadableBreak(); fired {
			t.Error("fired with neither the route control nor an inert probe to compare against, which " +
				"invents the comparison the whole gate is made of")
		}
	})
}
