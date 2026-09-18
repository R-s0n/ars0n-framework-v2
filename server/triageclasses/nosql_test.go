package triageclasses

import (
	"crypto/sha256"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// WHAT THESE TESTS ARE FOR, AND WHAT THEY DELIBERATELY DO NOT DO.
//
// A classifier cannot mint a triage.Perturbed: the vault takes a runner capability whose type
// lives in server/utils/internal/triagecap, and this package sits outside server/utils precisely
// so it cannot import that. So no test in this package can hand Classify a populated Own set, and
// an end-to-end "response in, verdict out" test is structurally impossible here.
//
// That is why every detection rule in nosql.go is a PURE FUNCTION over bytes and counts, and why
// Classify is a thin adapter over them. The rules are tested exhaustively below, with each named
// false positive as a first-class table row, and Classify itself is tested for the one property
// the adapter can break on its own: with nothing to read, it must produce unknowns and never a
// clean.

// ------------------------------------------------------------------------------------------------
// REGISTRATION AND THE ISOLATION LAW
// ------------------------------------------------------------------------------------------------

// The class links itself in through its own init and nothing else. A class that fails to register
// produces no rows at all, and no row looks exactly like no bug.
func TestTheNoSQLClassifierRegistersItselfAndSatisfiesTheContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassNoSQL)
	if !ok {
		t.Fatal("the NoSQL classifier did not register itself, so the whole class would be silently absent from every report")
	}
	if c.ID() != triage.ClassNoSQL {
		t.Fatalf("registered under NOSQL but reports %s", c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	for _, p := range c.Probes() {
		if p.Class != triage.ClassNoSQL {
			t.Errorf("probe %s declares class %s", p.ID, p.Class)
		}
		if len(p.Logical) == 0 && !p.IsControl {
			t.Errorf("probe %s has no bytes and is not a control, so it would send nothing and record clean", p.ID)
		}
		if p.Notes == "" {
			t.Errorf("probe %s carries no note, so nobody can tell why it exists or what it must not fire on", p.ID)
		}
	}
}

// Every probe this class plans was declared, or the isolation law was checked over a payload that
// never went on the wire.
func TestEveryNoSQLProbeThePlannerEmitsWasDeclaredUpFront(t *testing.T) {
	c := nosqlClassifier{}
	for _, tc := range nosqlPlanFixtures() {
		for round := 0; round < 4; round++ {
			ctx := tc.ctx
			ctx.Round = round
			if err := triage.PlannedProbesAreDeclared(c, c.Plan(ctx)); err != nil {
				t.Errorf("%s round %d: %v", tc.name, round, err)
			}
		}
	}
}

// No two probes in this class share bytes. The registry check only fires across classes, so an
// intra-class collision would pass it while making an error unattributable between two arms, which
// is the same harm the law is written against.
func TestNoTwoNoSQLPayloadsAreByteEqualToEachOther(t *testing.T) {
	seen := map[string]triage.ProbeID{}
	for _, p := range (nosqlClassifier{}).Probes() {
		k := string(triage.NormaliseMarkers(p.Logical))
		if prev, dup := seen[k]; dup {
			t.Errorf("probes %s and %s ship byte-equal payloads, so a block or a rejection cannot be attributed to either arm", prev, p.ID)
		}
		seen[k] = p.ID
	}
}

// The registry-wide law, run from here so that a collision with a sibling class shows up next to
// this class rather than in somebody else's file.
func TestTheRegistryStillPassesTheIsolationLawWithNoSQLRegistered(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		t.Errorf("ISOLATION: %s", v)
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
}

// ------------------------------------------------------------------------------------------------
// THE STRUCTURAL POINT: A SLOT THAT CANNOT CARRY AN OBJECT IS NOT_APPLICABLE, NEVER CLEAN
// ------------------------------------------------------------------------------------------------

func TestASlotThatCannotCarryAnObjectIsNotApplicableAndNeverClean(t *testing.T) {
	cases := []struct {
		name      string
		slot      triage.Slot
		media     triage.MediaType
		wantPlace nosqlPlacement
	}{
		{
			"a path segment is bytes between two slashes and no framework makes it a map",
			triage.Slot{Kind: triage.KindPath, Key: "path:4:{id}", SegmentIndex: 4, Value: "42", ValueOrigin: triage.ValueObserved, ServerReachable: true},
			"", nosqlPlaceNone,
		},
		{
			"a plain header value is a string",
			triage.Slot{Kind: triage.KindHeader, Key: "header:x-tenant", Name: "x-tenant", Value: "acme", ValueOrigin: triage.ValueObserved, ServerReachable: true},
			"", nosqlPlaceNone,
		},
		{
			"a header whose observed value IS a JSON object is re-derived as a JSON slot",
			triage.Slot{Kind: triage.KindHeader, Key: "header:x-ctx", Name: "x-ctx", Value: `{"tenant":"acme"}`, ValueOrigin: triage.ValueObserved, ServerReachable: true},
			"", nosqlPlaceJSONNode,
		},
		{
			"XML element text is a string too",
			triage.Slot{Kind: triage.KindBody, Key: "body:/user", BodyMedia: triage.BodyXML, Value: "alice", ValueOrigin: triage.ValueObserved, ServerReachable: true},
			"application/xml", nosqlPlaceNone,
		},
		{
			"a JSON body is the primary point",
			triage.Slot{Kind: triage.KindBody, Key: "body:/username", FieldPath: "/username", BodyMedia: triage.BodyJSON, Value: "alice", ValueOrigin: triage.ValueObserved, ServerReachable: true},
			"application/json", nosqlPlaceJSONNode,
		},
		{
			"a query string may carry an object in bracket notation, which the parse control measures",
			triage.Slot{Kind: triage.KindQuery, Key: "query:user", Name: "user", Value: "alice", ValueOrigin: triage.ValueObserved, ServerReachable: true},
			"", nosqlPlaceBracket,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := nosqlCtx(tc.slot, tc.media)
			if got := nosqlEligible(ctx).place; got != tc.wantPlace {
				t.Fatalf("placement = %q, want %q", got, tc.wantPlace)
			}
			if tc.wantPlace != nosqlPlaceNone {
				return
			}
			// The four object arms must say not_applicable with a reason, and must not be clean.
			ev := nosqlEvidenceSet{slot: tc.slot, el: nosqlEligible(ctx)}
			for _, v := range []triage.ClassVerdict{
				nosqlArmOPVerdict(ev), nosqlArmTypeVerdict(ev), nosqlArmCouchVerdict(ev),
			} {
				if v.State.CountsAsClean() {
					t.Errorf("%s reported clean on a slot that cannot carry an object", nosqlArmOf(v))
				}
				if !v.State.IsUnknown() {
					t.Errorf("%s reported %q, which an aggregate would count as a measurement", nosqlArmOf(v), v.State)
				}
				if !strings.Contains(v.Reason, "cannot_carry_an_object") && !strings.Contains(v.Reason, "not_addressable") {
					t.Errorf("%s reason %q does not name the structural cause", nosqlArmOf(v), v.Reason)
				}
			}
		})
	}
}

// N-FILTER needs a top-level member of a JSON document, because a sibling key added anywhere
// deeper lands inside a sub-document and not at the filter root.
func TestTheFilterRootArmRefusesASlotThatIsNotATopLevelMember(t *testing.T) {
	cases := []struct {
		ptr  string
		want bool
	}{
		{"", true},
		{"/", true},
		{"/username", true},
		{"/filters/status", false},
		{"/a/b/c", false},
		{"username", false},
	}
	for _, tc := range cases {
		if got := nosqlIsTopLevelMember(tc.ptr); got != tc.want {
			t.Errorf("nosqlIsTopLevelMember(%q) = %v, want %v", tc.ptr, got, tc.want)
		}
	}

	deep := triage.Slot{
		Kind: triage.KindBody, Key: "body:/filters/status", FieldPath: "/filters/status",
		BodyMedia: triage.BodyJSON, Value: "open", ValueOrigin: triage.ValueObserved, ServerReachable: true,
	}
	ev := nosqlEvidenceSet{slot: deep, el: nosqlEligible(nosqlCtx(deep, "application/json"))}
	v := nosqlArmFilterVerdict(ev)
	if v.State != triage.StateNotApplicable {
		t.Errorf("N-FILTER on a nested pointer reported %q, want not_applicable", v.State)
	}
	if !strings.Contains(v.Reason, "filter_root_not_addressable") {
		t.Errorf("reason %q does not name the cause", v.Reason)
	}
}

// ------------------------------------------------------------------------------------------------
// THE NAMED FALSE POSITIVE: A SCHEMA VALIDATOR IS NOT AN ENGINE
// ------------------------------------------------------------------------------------------------

// THE ROW THAT MATTERS MOST IN THIS FILE.
//
// A 400 from a JSON schema validator rejecting an object where a string belongs looks exactly like
// a NoSQL parse error. The discriminator is the benign-type control: a validator rejects a bare
// number too, a database does not. Every wording here was GENERATED against the real library.
func TestAValidatorRejectingAnObjectIsNotAnEngineError(t *testing.T) {
	const marker = "zqj1a2b3c4d5e6f"

	cases := []struct {
		name         string
		probeBody    string
		benignBody   string
		baseline     string
		probeStatus  int
		benignStatus int
		haveBenign   bool
		want         nosqlErrorSource
	}{
		{
			name:        "Ajv rejects the operator object and the bare number identically, so it is a validator",
			probeBody:   `{"errors":[{"instancePath":"/username","message":"must be string"}]}`,
			benignBody:  `{"errors":[{"instancePath":"/username","message":"must be string"}]}`,
			probeStatus: 400, benignStatus: 400, haveBenign: true,
			want: nosqlSourceValidator,
		},
		{
			name:        "Zod says received object for the operator and received number for the control, same phrase, still a validator",
			probeBody:   `{"error":"Invalid input: expected string, received object"}`,
			benignBody:  `{"error":"Invalid input: expected string, received number"}`,
			probeStatus: 422, benignStatus: 422, haveBenign: true,
			want: nosqlSourceValidator,
		},
		{
			name:        "Joi rejects both with must be a string",
			probeBody:   `{"message":"\"username\" must be a string"}`,
			benignBody:  `{"message":"\"username\" must be a string"}`,
			probeStatus: 400, benignStatus: 400, haveBenign: true,
			want: nosqlSourceValidator,
		},
		{
			name:        "the engine phrase wins outright even when a validator is also on the page",
			probeBody:   `{"message":"must be string"} <!-- unknown operator: $` + marker + ` -->`,
			benignBody:  `{"message":"must be string"}`,
			probeStatus: 500, benignStatus: 400, haveBenign: true,
			want: nosqlSourceEngine,
		},
		{
			name:        "VERIFIED shape of a true positive: the operator 500s and the bare number gets the ordinary 401",
			probeBody:   `{"error":"unknown operator: $` + marker + `"}`,
			benignBody:  `{"error":"invalid credentials"}`,
			probeStatus: 500, benignStatus: 401, haveBenign: true,
			want: nosqlSourceEngine,
		},
		{
			name:        "a validator phrase with the benign control NOT rejected is ambiguous, never an engine hit",
			probeBody:   `{"message":"must be string"}`,
			benignBody:  `{"ok":true}`,
			probeStatus: 400, benignStatus: 200, haveBenign: true,
			want: nosqlSourceAmbiguous,
		},
		{
			name:        "a validator phrase with NO benign control at all is ambiguous: a discriminator with one arm missing has not discriminated",
			probeBody:   `{"message":"must be string"}`,
			probeStatus: 400, haveBenign: false,
			want: nosqlSourceAmbiguous,
		},
		{
			name:        "an engine phrase that is ALSO in the baseline is the application's own prose and is subtracted",
			probeBody:   `<footer>powered by MongoServerError debug build</footer>`,
			baseline:    `<footer>powered by MongoServerError debug build</footer>`,
			benignBody:  `<footer>powered by MongoServerError debug build</footer>`,
			probeStatus: 200, benignStatus: 200, haveBenign: true,
			want: nosqlSourceNone,
		},
		{
			name:        "an ordinary successful response is not a rejection of any kind",
			probeBody:   `{"results":[{"username":"alice"}]}`,
			benignBody:  `{"results":[]}`,
			probeStatus: 200, benignStatus: 200, haveBenign: true,
			want: nosqlSourceNone,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := nosqlClassifyError(
				[]byte(tc.probeBody), []byte(tc.benignBody), []byte(tc.baseline),
				tc.probeStatus, tc.benignStatus, tc.haveBenign, marker)
			if got != tc.want {
				t.Errorf("nosqlClassifyError = %q, want %q", got, tc.want)
			}
		})
	}
}

// A validator verdict is not_exploitable, which is a NEGATIVE, and it must never be clean: the
// mechanism is reachable and a named defence stops it, and an operator who reads "clean" will
// never come back when the validator is relaxed in a later release.
func TestASchemaValidatorProducesNotExploitableAndNotClean(t *testing.T) {
	if triage.StateNotExploitable.CountsAsClean() {
		t.Fatal("not_exploitable counts as clean in the vocabulary, which would make the validator verdict a green tick")
	}
	if triage.StateNotExploitable.IsUnknown() {
		t.Error("not_exploitable reads as unknown, which loses the fact that a defence was NAMED")
	}
}

// ------------------------------------------------------------------------------------------------
// THE PROXIMITY WINDOW AND THE ECHO FALSE POSITIVE
// ------------------------------------------------------------------------------------------------

// An engine phrase more than 120 bytes from this probe's own marker is not attributable to this
// probe. CATALOGUE 6.1 builds /clean/echoparser to exercise exactly this window.
func TestAnEnginePhraseFarFromTheMarkerIsNotAttributedToThisProbe(t *testing.T) {
	const marker = "zqj1a2b3c4d5e6f"
	near := []byte(`{"error":"unknown operator: $` + marker + `"}`)
	far := []byte(`<p>` + marker + `</p>` + strings.Repeat("x", 400) + `<p>unknown operator: $foo</p>`)

	h, ok := nosqlFindPhrase(near, nil, marker, nosqlEnginePhrases)
	if !ok || !h.MarkerNear {
		t.Errorf("the marker inside the error phrase itself was not read as near: ok=%v near=%v", ok, h.MarkerNear)
	}
	h, ok = nosqlFindPhrase(far, nil, marker, nosqlEnginePhrases)
	if !ok {
		t.Fatal("the phrase was not found at all")
	}
	if h.MarkerNear {
		t.Error("a marker 400 bytes from the phrase was read as near, so an echoing page that also mentions a driver would be graded as an engine error")
	}
}

// THE ECHO. The tier-1 $where oracle is marker+56861 with nothing in between. An application that
// echoes the payload shows '<marker>'+(8123*7), and the characters are all there.
func TestAnEchoedPayloadIsNotAComputation(t *testing.T) {
	const marker = "zqj1a2b3c4d5e6f"
	cases := []struct {
		name string
		body string
		want bool
	}{
		{
			"the server concatenated my marker with the product it computed",
			`{"error":"` + marker + `56861"}`,
			true,
		},
		{
			"the server echoed my payload back verbatim, so the digits are there but not glued to the marker",
			`{"error":"bad filter: {\"$where\":\"throw new Error('` + marker + `'+(8123*7))\"}"}`,
			false,
		},
		{
			"the marker came back on its own, which is a reflection and not a computation",
			`<p>no user named ` + marker + `</p>`,
			false,
		},
		{
			"the product came back on its own, which could be any number on the page",
			`<p>order 56861 not found</p>`,
			false,
		},
		{
			"the FALSE product glued to the marker is not this oracle firing",
			`{"error":"` + marker + `56862"}`,
			false,
		},
		{
			"an empty body decides nothing",
			``,
			false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := nosqlComputationHit([]byte(tc.body), marker); got != tc.want {
				t.Errorf("nosqlComputationHit = %v, want %v", got, tc.want)
			}
		})
	}
}

// The erlang_binary transform is this class's own, because foundations 2.5 does not have one, and
// without it a perfect CouchDB marker reflection is invisible to every marker search in the layer.
func TestTheErlangBinaryTransformFindsACouchMarkerAndStaysSilentOnPlainNumbers(t *testing.T) {
	if got := string(nosqlErlangBinary([]byte("^a["))); got != "94,97,91" {
		t.Errorf("nosqlErlangBinary(%q) = %q, want the VERIFIED CouchDB rendering 94,97,91", "^a[", got)
	}

	const marker = "zqj1a2b3c4d5e6f"
	enc := string(nosqlErlangBinary([]byte(marker)))
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"a real CouchDB bad_arg reply", `{"error":"bad_arg","reason":"Bad argument for operator $regex: <<94,` + enc + `,91>>"}`, true},
		{"the byte list with no Erlang literal around it is any old comma-separated numbers", `csv export: ` + enc, false},
		{"an Erlang literal that does not contain my marker belongs to somebody else's request", `{"reason":"<<97,108,105,99,101>>"}`, false},
		{"an empty body", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, got := nosqlErlangMarkerHit([]byte(tc.body), marker); got != tc.want {
				t.Errorf("nosqlErlangMarkerHit = %v, want %v", got, tc.want)
			}
		})
	}
}

// ------------------------------------------------------------------------------------------------
// WIDENING IS COUNTED IN ROWS, NEVER IN BYTES
// ------------------------------------------------------------------------------------------------

func TestWideningIsMeasuredInRowsAndAnAbsentArrayIsUndecidableRatherThanClean(t *testing.T) {
	cases := []struct {
		name  string
		base  map[string]int
		probe map[string]int
		want  nosqlCardVerdict
	}{
		{"the operator returned more rows, which is the strongest positive in the class",
			map[string]int{"/results": 1}, map[string]int{"/results": 12}, nosqlCardsWider},
		{"the operator returned fewer rows",
			map[string]int{"/results": 12}, map[string]int{"/results": 0}, nosqlCardsNarrower},
		{"the same rows came back",
			map[string]int{"/results": 3}, map[string]int{"/results": 3}, nosqlCardsSame},
		{"the baseline carries no array at all, so there is nothing to count and no verdict to give",
			map[string]int{}, map[string]int{"/results": 9}, nosqlCardsUnavailable},
		{"the probe carries no array, which is usually an error envelope",
			map[string]int{"/results": 9}, map[string]int{}, nosqlCardsUnavailable},
		{"a completely different document shape is not a widening, it is a different document",
			map[string]int{"/results": 3}, map[string]int{"/errors": 40}, nosqlCardsShapeChanged},
		{"one array grew and another shrank, which arithmetic cannot explain",
			map[string]int{"/a": 1, "/b": 9}, map[string]int{"/a": 5, "/b": 2}, nosqlCardsMixed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nosqlCompareCards(tc.base, tc.probe); got != tc.want {
				t.Errorf("nosqlCompareCards = %q, want %q", got, tc.want)
			}
		})
	}
}

// The projection strings are parsed, not guessed at, and a malformed entry is dropped rather than
// counted as zero. A zero here would read as "the array emptied", which is a narrowing that never
// happened.
func TestArrayCardinalitiesComeFromTheProjectionAndMalformedEntriesAreDroppedNotZeroed(t *testing.T) {
	o := triage.Observation{Proj: triage.Projections{JSONCards: []string{
		"/results.__len__=7",
		"/results/0/tags.__len__=2",
		"garbage-with-no-equals",
		"/broken.__len__=notanumber",
	}}}
	got := nosqlCards(o)
	if got["/results"] != 7 || got["/results/0/tags"] != 2 {
		t.Errorf("cards = %v, want /results 7 and /results/0/tags 2", got)
	}
	if _, present := got["/broken"]; present {
		t.Error("a card whose count did not parse was recorded anyway, and it would read as an array that emptied")
	}
	if len(got) != 2 {
		t.Errorf("cards = %v, want exactly the two parseable entries", got)
	}
}

// ------------------------------------------------------------------------------------------------
// EVERY UNDECIDABLE PATH YIELDS AN UNKNOWN, AND NEVER A CLEAN
// ------------------------------------------------------------------------------------------------

func TestEveryWayThisClassCanFailToGetAnAnswerYieldsAnUnknownWithAReason(t *testing.T) {
	jsonSlot := triage.Slot{
		Kind: triage.KindBody, Key: "body:/username", FieldPath: "/username",
		BodyMedia: triage.BodyJSON, Value: "alice", ValueOrigin: triage.ValueObserved,
		ServerReachable: true, Constraints: triage.NewSlotConstraints(),
	}

	cases := []struct {
		name      string
		mutate    func(*triage.ClassifyCtx)
		wantState triage.TriageState
		wantIn    string
	}{
		{
			"a fragment never leaves the browser",
			func(c *triage.ClassifyCtx) { c.Slot.Kind = triage.KindFragment; c.Slot.ServerReachable = false },
			triage.StateNotApplicable, "fragment",
		},
		{
			"a credential slot answers 401 to everything, which looks exactly like a differential",
			func(c *triage.ClassifyCtx) { c.Slot.Constraints.IsCredential = true },
			triage.StateNotProbed, "credential_slot",
		},
		{
			"a failed prelude makes every probe fail validation identically, which reads as a stable endpoint",
			func(c *triage.ClassifyCtx) { c.Prelude = triage.PreludeTokenUnobtainable },
			triage.StateCannotDetermine, "prelude_failed",
		},
		{
			"an unmeasured prelude is a failed one: its zero value is not token_not_required",
			func(c *triage.ClassifyCtx) { c.Prelude = triage.PreludeUnknown },
			triage.StateCannotDetermine, "prelude_failed",
		},
		{
			"the budget bit before this slot was reached",
			func(c *triage.ClassifyCtx) { c.Budget.RemainingPerSlot = 0 },
			triage.StateNotRun, "probe_budget_exhausted",
		},
		{
			// This is also the default shape of every ctx a test in this package can build: a
			// classifier cannot construct a resolved Replay, because NewReplay takes the runner
			// capability and this package cannot import triagecap. So the honest thing a test can
			// assert here is that the missing baseline is refused by name.
			"no unperturbed route control means nothing to difference against",
			func(c *triage.ClassifyCtx) {},
			triage.StateCannotDetermine, "route_control_unresolved",
		},
	}

	c := nosqlClassifier{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := triage.ClassifyCtx{PlanCtx: nosqlCtx(jsonSlot, "application/json")}
			tc.mutate(&ctx)

			vs := c.Classify(ctx)
			if len(vs) != len(nosqlArms) {
				t.Fatalf("got %d verdicts, want one per arm (%d). A slot with an arm missing reads as an arm nobody wrote", len(vs), len(nosqlArms))
			}
			for _, v := range vs {
				if err := v.Validate(); err != nil {
					t.Errorf("verdict failed its own contract: %v", err)
				}
				if v.State.CountsAsClean() {
					t.Fatalf("%s reported CLEAN on %q", nosqlArmOf(v), tc.name)
				}
				if !v.State.IsUnknown() {
					t.Errorf("%s reported %q, which an aggregate counts as a measurement", nosqlArmOf(v), v.State)
				}
				if v.State != tc.wantState {
					t.Errorf("%s state = %q, want %q", nosqlArmOf(v), v.State, tc.wantState)
				}
				if !strings.Contains(v.Reason, tc.wantIn) {
					t.Errorf("%s reason %q does not name %q", nosqlArmOf(v), v.Reason, tc.wantIn)
				}
			}
			if cov := triage.SummariseVerdicts(vs); cov.RendersAsClean() {
				t.Error("the aggregate over these verdicts renders as clean")
			}
		})
	}
}

// The clean branch re-checks its own preconditions rather than trusting whoever called it, because
// a clean is the only verdict in this class that asserts something about the application.
func TestTheCleanBranchRefusesEveryPreconditionItCannotShow(t *testing.T) {
	slot := triage.Slot{Kind: triage.KindBody, Key: "body:/u", FieldPath: "/u", BodyMedia: triage.BodyJSON,
		Value: "alice", ValueOrigin: triage.ValueObserved, ServerReachable: true}

	cases := []struct {
		name   string
		ev     nosqlEvidenceSet
		ords   []uint64
		wantIn string
	}{
		{"a clean with no probe ordinals asserts a measurement that never happened",
			nosqlEvidenceSet{slot: slot, haveBase: true}, nil, "no_probe_ordinals"},
		{"a clean with no unperturbed response has nothing to be quiet relative to",
			nosqlEvidenceSet{slot: slot, haveBase: false}, []uint64{69}, "route_control_unresolved"},
		{"a degraded baseline cannot tell a quiet oracle from an endpoint that is quiet about everything",
			nosqlEvidenceSet{slot: slot, haveBase: true, degraded: true}, []uint64{69}, "baseline_degraded"},
		{"an endpoint that moves for any junk value carries no information in its silence",
			nosqlEvidenceSet{slot: slot, haveBase: true, junkSensitive: true}, []uint64{69}, "junk_sensitive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := nosqlBase(tc.ev, nosqlArmOP)
			v.Ordinals = tc.ords
			got := nosqlClean(tc.ev, v, "the probes ran and the oracle stayed silent")
			if got.State.CountsAsClean() {
				t.Fatalf("clean was allowed through: %q", got.Reason)
			}
			if !strings.Contains(got.Reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", got.Reason, tc.wantIn)
			}
		})
	}

	// And the positive control: with every precondition met, clean IS reachable. A clean branch
	// that can never be taken is a class that can never report a negative, which is its own bug.
	ok := nosqlEvidenceSet{slot: slot, haveBase: true}
	v := nosqlBase(ok, nosqlArmOP)
	v.Ordinals = []uint64{69}
	if got := nosqlClean(ok, v, "the probes ran and the oracle stayed silent"); !got.State.CountsAsClean() {
		t.Errorf("clean is unreachable even with every precondition met: %q / %q", got.State, got.Reason)
	}
}

// A probe that never reached the wire cannot support any verdict, and each of the three ways it
// can fail gets its own reason. This is the bug this codebase has shipped repeatedly: a tool that
// never ran, recorded as a pass.
func TestAProbeThatNeverReachedTheWireCannotSupportAVerdict(t *testing.T) {
	cases := []struct {
		name   string
		seen   map[triage.ProbeID]nosqlSeen
		wantIn string
	}{
		{
			"the probe was planned and no observation came back",
			map[triage.ProbeID]nosqlSeen{},
			"probe_not_observed",
		},
		{
			"the request never reached the application",
			map[triage.ProbeID]nosqlSeen{"NSQ-OP1": {obs: triage.Observation{TransportErr: triage.TransportTimeout}}},
			"transport_failed",
		},
		{
			"the encoder dropped the bytes, so the application never saw the payload",
			map[triage.ProbeID]nosqlSeen{"NSQ-OP1": {obs: triage.Observation{
				Payload: triage.PayloadWire{Survived: triage.WireSurvivalDropped, AlteredBy: "net/http.Cookie sanitizer"},
			}}},
			"payload_not_on_the_wire",
		},
		{
			"survival was never measured, and unknown is not survived",
			map[triage.ProbeID]nosqlSeen{"NSQ-OP1": {obs: triage.Observation{}}},
			"payload_not_on_the_wire",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := nosqlEvidenceSet{seen: tc.seen}
			_, why := ev.usable("NSQ-OP1")
			if why == "" {
				t.Fatal("the probe was accepted as usable")
			}
			if !strings.Contains(why, tc.wantIn) {
				t.Errorf("reason %q does not name %q", why, tc.wantIn)
			}
		})
	}
}

// ------------------------------------------------------------------------------------------------
// THE LADDER
// ------------------------------------------------------------------------------------------------

type nosqlPlanFixture struct {
	name string
	ctx  triage.PlanCtx
}

func nosqlPlanFixtures() []nosqlPlanFixture {
	return []nosqlPlanFixture{
		{"json body top-level member", nosqlCtx(triage.Slot{
			Kind: triage.KindBody, Key: "body:/username", FieldPath: "/username", BodyMedia: triage.BodyJSON,
			Value: "alice", ValueOrigin: triage.ValueObserved, ServerReachable: true,
		}, "application/json")},
		{"json body nested member", nosqlCtx(triage.Slot{
			Kind: triage.KindBody, Key: "body:/f/status", FieldPath: "/f/status", BodyMedia: triage.BodyJSON,
			Value: "open", ValueOrigin: triage.ValueObserved, ServerReachable: true,
		}, "application/json")},
		{"query slot with a numeric value", nosqlCtx(triage.Slot{
			Kind: triage.KindQuery, Key: "query:age", Name: "age",
			Value: "30", ValueOrigin: triage.ValueObserved, ServerReachable: true,
		}, "")},
		{"path segment", nosqlCtx(triage.Slot{
			Kind: triage.KindPath, Key: "path:3:{id}", SegmentIndex: 3,
			Value: "42", ValueOrigin: triage.ValueObserved, ServerReachable: true,
		}, "")},
		{"canary-valued json slot", nosqlCtx(triage.Slot{
			Kind: triage.KindBody, Key: "body:/id", FieldPath: "/id", BodyMedia: triage.BodyJSON,
			Value: "00000000-0000-0000-0000-000000000000", ValueOrigin: triage.ValueCanary, ServerReachable: true,
		}, "application/json")},
		{"slot with no captured value", nosqlCtx(triage.Slot{
			Kind: triage.KindQuery, Key: "query:q", Name: "q",
			Value: "", ValueOrigin: triage.ValueObserved, ServerReachable: true,
		}, "")},
	}
}

// Round 0 sends the dollar control first on every shape, because a blocked dollar makes every
// other answer in the class meaningless and nothing else can detect it.
func TestRoundZeroAlwaysSendsTheDollarControlAndTheRightPairForTheShape(t *testing.T) {
	c := nosqlClassifier{}
	cases := []struct {
		fixture string
		want    []triage.ProbeID
	}{
		{"json body top-level member", []triage.ProbeID{"NSQ-NC1", "NSQ-OP1", "NSQ-OP0"}},
		{"query slot with a numeric value", []triage.ProbeID{"NSQ-NC1", "NSQ-OP1", "NSQ-OP0"}},
		{"path segment", []triage.ProbeID{"NSQ-NC1", "NSQ-J5", "NSQ-J6"}},
	}
	for _, tc := range cases {
		t.Run(tc.fixture, func(t *testing.T) {
			ctx := nosqlFixture(t, tc.fixture)
			got := nosqlIDs(c.Plan(ctx))
			if strings.Join(nosqlStrings(got), ",") != strings.Join(nosqlStrings(tc.want), ",") {
				t.Errorf("round 0 = %v, want %v", got, tc.want)
			}
		})
	}
}

// The strongest oracle is led with, not saved for later. $expr is tier 1, it is deterministic
// computation rather than a differential, and it is the one oracle that survives --noscripting.
func TestTheLadderLeadsWithTheExprArithmeticWhereverItCanReachTheFilterRoot(t *testing.T) {
	c := nosqlClassifier{}
	ctx := nosqlFixture(t, "json body top-level member")
	ctx.Round = 1
	got := nosqlIDs(c.Plan(ctx))
	if len(got) < 2 || got[0] != "NSQ-F2" || got[1] != "NSQ-F3" {
		t.Errorf("round 1 = %v, want the $expr pair first", got)
	}

	// And where it cannot reach the root, it is not sent at all rather than sent somewhere it
	// cannot work: a probe aimed where it cannot land is a false negative with a request attached.
	nested := nosqlFixture(t, "json body nested member")
	nested.Round = 1
	for _, id := range nosqlIDs(c.Plan(nested)) {
		if id == "NSQ-F2" || id == "NSQ-F3" {
			t.Errorf("the $expr pair was aimed at a nested pointer where a sibling key cannot reach the filter root")
		}
	}
}

// A differential arm never sends a true arm without its false arm in the same round. A detector
// nobody has watched stay silent is not a detector.
func TestNoDifferentialArmEverSendsATrueArmWithoutItsFalseArmInTheSameRound(t *testing.T) {
	pairs := [][2]triage.ProbeID{
		{"NSQ-F2", "NSQ-F3"},
		{"NSQ-J5", "NSQ-J6"},
		{"NSQ-OP5", "NSQ-OP6"},
		{"NSQ-OP7", "NSQ-OP8"},
		{"NSQ-E2", "NSQ-E3"},
		{"NSQ-T1", "NSQ-T2"},
	}
	c := nosqlClassifier{}
	for _, f := range nosqlPlanFixtures() {
		for round := 0; round < 4; round++ {
			ctx := f.ctx
			ctx.Round = round
			in := map[triage.ProbeID]bool{}
			for _, id := range nosqlIDs(c.Plan(ctx)) {
				in[id] = true
			}
			for _, p := range pairs {
				if in[p[0]] != in[p[1]] {
					t.Errorf("%s round %d sent %s=%v and %s=%v: a differential arm split across rounds",
						f.name, round, p[0], in[p[0]], p[1], in[p[1]])
				}
			}
		}
	}
}

// A canary or synthesized value has no baseline to widen from, so the two arms defined relative to
// it decline with a reason while the arms that need no known-good value still run.
func TestACanaryValuedSlotDeclinesTheArmsThatNeedAKnownGoodValueAndRunsTheRest(t *testing.T) {
	ctx := nosqlFixture(t, "canary-valued json slot")
	el := nosqlEligible(ctx)
	if el.knownGood {
		t.Fatal("a canary value was accepted as known-good, so a widening oracle would be measured against a resource that does not exist")
	}

	ev := nosqlEvidenceSet{slot: ctx.Slot, el: el}
	for _, v := range []triage.ClassVerdict{nosqlArmOPVerdict(ev), nosqlArmTypeVerdict(ev)} {
		if v.State != triage.StateCannotDetermine {
			t.Errorf("%s = %q, want cannot_determine", nosqlArmOf(v), v.State)
		}
		if !strings.Contains(v.Reason, "no_known_good_value") {
			t.Errorf("%s reason %q does not name the cause", nosqlArmOf(v), v.Reason)
		}
	}

	// N-FILTER needs no known-good value: the $expr arithmetic is true of every document.
	c := nosqlClassifier{}
	ctx.Round = 1
	saw := false
	for _, id := range nosqlIDs(c.Plan(ctx)) {
		if id == "NSQ-F2" {
			saw = true
		}
	}
	if !saw {
		t.Error("the $expr arm was suppressed on a canary slot, but it needs no known-good value and is this class's strongest oracle")
	}
}

// The regex pair is skipped rather than sent broken when the value's first character is not a
// plain alphanumeric, because a metacharacter in the anchor position tests the regex engine's
// error handling and not its matching.
func TestTheRegexPairIsSkippedWhenTheValueCannotAnchorIt(t *testing.T) {
	cases := []struct {
		value      string
		wantFirst  string
		wantDiffer bool
	}{
		{"alice", "a", true},
		{"queen", "q", true},
		{"30", "3", true},
		{"*wild", "", false},
		{"", "", false},
		{"[bracket", "", false},
	}
	for _, tc := range cases {
		first, wrong := nosqlRegexChars(tc.value)
		if first != tc.wantFirst {
			t.Errorf("nosqlRegexChars(%q) first = %q, want %q", tc.value, first, tc.wantFirst)
		}
		if tc.wantDiffer && first == wrong {
			t.Errorf("nosqlRegexChars(%q) produced the same character twice, so the must-match and must-not-match probes are identical", tc.value)
		}
	}
}

// Every probe declares a marker offset or declares that it carries no marker, and the controls
// whose value is being benign carry none. A marker prefixed onto {"$eq":"alice"} makes it invalid
// JSON, which produces the very 400 this class exists to tell apart from an engine error.
func TestTheBenignControlsCarryNoMarkerAndEveryMarkerBearingProbeNamesItsOffset(t *testing.T) {
	mustNotCarry := []triage.ProbeID{"NSQ-OP0", "NSQ-F2", "NSQ-F3", "NSQ-T3", "NSQ-T4", "NSQ-J1", "NSQ-J2", "NSQ-OP3", "NSQ-OP9"}
	for _, id := range mustNotCarry {
		if off := nosqlMarkerOffset(id); off >= 0 {
			t.Errorf("%s carries a marker at %d, and it is a control whose whole value is being semantically benign", id, off)
		}
	}
	for _, p := range (nosqlClassifier{}).Probes() {
		if p.MarkerPos != triage.MarkerInline {
			t.Errorf("probe %s uses MarkerPos %q; this class is inline-only because a prefixed marker makes a JSON payload invalid", p.ID, p.MarkerPos)
		}
		off := nosqlMarkerOffset(p.ID)
		req := nosqlReq(p.ID, "body:/u", nosqlEligibility{value: "alice", place: nosqlPlaceJSONNode})
		got, present := req.Variant["marker_offset"]
		if off >= 0 && (!present || got == "") {
			t.Errorf("probe %s embeds a marker and its request names no offset", p.ID)
		}
		if off < 0 && present {
			t.Errorf("probe %s carries no marker and its request names an offset anyway, so the runner would splice one in", p.ID)
		}
	}
}

// ------------------------------------------------------------------------------------------------
// THE ORACLE SET
// ------------------------------------------------------------------------------------------------

// A detector never shown to STAY SILENT is not verified. The oracle set must carry both halves,
// and the negatives must each produce a DIFFERENT unknown or negative, for different reasons.
func TestTheOracleSetDeclaresBothAPositiveAndANegativeAndNoNegativeIsASilentClean(t *testing.T) {
	cases := (nosqlClassifier{}).OracleCases()
	pos, neg := 0, 0
	seenRoute := map[string]bool{}
	for _, c := range cases {
		if seenRoute[c.Route] {
			t.Errorf("route %s is declared twice", c.Route)
		}
		seenRoute[c.Route] = true
		if c.Why == "" {
			t.Errorf("route %s says nothing about what it is for, so whoever builds it will build the wrong thing", c.Route)
		}
		if len(c.Probes) == 0 {
			t.Errorf("route %s names no probe", c.Route)
		}
		switch c.Expect {
		case "positive":
			pos++
			if c.Want != triage.StateFinding {
				t.Errorf("route %s is a FIRE route and expects %q", c.Route, c.Want)
			}
		case "negative":
			neg++
			if c.Want == triage.StateFinding || c.Want == triage.StateSuspicious {
				t.Errorf("route %s is a SILENT route and expects a positive state %q", c.Route, c.Want)
			}
		default:
			t.Errorf("route %s declares Expect %q, which is neither positive nor negative", c.Route, c.Expect)
		}
	}
	if pos == 0 {
		t.Error("no positive oracle route: the detectors have only ever been watched staying silent")
	}
	if neg == 0 {
		t.Error("no negative oracle route: the detectors have only ever been watched firing, which is exactly as unverified")
	}

	// The three CATALOGUE 6.1 negatives must reach three DIFFERENT answers, or one of them is
	// standing in for the others and the distinction the class was built around is untested.
	want := map[string]triage.TriageState{
		"/nosqli/strict":       triage.StateNotExploitable,
		"/nosqli/simpleparser": triage.StateNotApplicable,
		"/nosqli/sanitized":    triage.StateNotApplicable,
	}
	for _, c := range cases {
		if w, named := want[c.Route]; named && c.Want != w {
			t.Errorf("route %s expects %q, want %q", c.Route, c.Want, w)
		}
		if named := want[c.Route]; named != "" && c.Want.CountsAsClean() {
			t.Errorf("route %s expects clean, and CATALOGUE 6.1 says these three must never be clean", c.Route)
		}
	}
}

// Every arm has at least one route, positive or negative. An arm with no route at all is an arm
// whose detector has never been run against anything.
func TestEveryArmHasAtLeastOneOracleRoute(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range (nosqlClassifier{}).OracleCases() {
		covered[c.Arm] = true
	}
	for _, arm := range nosqlArms {
		if !covered[arm] {
			t.Errorf("arm %s has no oracle route, so nothing anywhere exercises its detector", arm)
		}
	}
}

// Confirmers and Evidencers are declared so the ladder and the extraction can be read as data.
func TestTheConfirmersAndEvidencersAreDeclaredAndPointAtRealProbes(t *testing.T) {
	declared := map[triage.ProbeID]bool{}
	for _, p := range (nosqlClassifier{}).Probes() {
		declared[p.ID] = true
	}
	cs := (nosqlClassifier{}).Confirmers()
	if len(cs) == 0 {
		t.Fatal("no confirmers declared, so every hit in this class stands on a single observation")
	}
	for _, c := range cs {
		if !declared[c.Fired] {
			t.Errorf("confirmer names undeclared probe %s", c.Fired)
		}
		for _, id := range c.Confirm {
			if !declared[id] {
				t.Errorf("confirmer for %s names undeclared probe %s", c.Fired, id)
			}
		}
		if c.Why == "" {
			t.Errorf("confirmer for %s says nothing about why the confirmation is needed", c.Fired)
		}
	}
	if len((nosqlClassifier{}).Evidencers()) == 0 {
		t.Error("no evidencers declared, so a verdict could point at nothing")
	}
}

// Settle is a deliberate no-op: every oracle this class owns is answered inside the response to
// the probe that asked, so a deferred pass would have nothing to look at.
func TestSettleIsADeliberateNoOpBecauseThisClassHasNoOutOfBandOracle(t *testing.T) {
	if vs := (nosqlClassifier{}).Settle(triage.ClassifyCtx{}); len(vs) != 0 {
		t.Errorf("Settle returned %d verdicts; this class has no deferred check", len(vs))
	}
}

// ------------------------------------------------------------------------------------------------
// helpers
// ------------------------------------------------------------------------------------------------

func nosqlCtx(s triage.Slot, mt triage.MediaType) triage.PlanCtx {
	if s.Constraints.DecodeDepth == 0 && !s.Constraints.IsCredential {
		s.Constraints = triage.NewSlotConstraints()
	}
	return triage.PlanCtx{
		Slot:    s,
		Vector:  triage.TriageVector{ID: "v1", Method: "POST", MediaType: mt},
		Prelude: triage.PreludeTokenNotRequired,
		Budget:  triage.TriageBudget{PerSlot: 40, PerRun: 4000, RemainingPerSlot: 40, RemainingPerRun: 4000},
	}
}

func nosqlFixture(t *testing.T, name string) triage.PlanCtx {
	t.Helper()
	for _, f := range nosqlPlanFixtures() {
		if f.name == name {
			return f.ctx
		}
	}
	t.Fatalf("no plan fixture named %q", name)
	return triage.PlanCtx{}
}

func nosqlIDs(reqs []triage.ProbeRequest) []triage.ProbeID {
	out := make([]triage.ProbeID, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Spec)
	}
	return out
}

func nosqlStrings(ids []triage.ProbeID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, string(id))
	}
	return out
}

// ------------------------------------------------------------------------------------------------
// EXAM ef8c13ab, DEFECT 1: A CLEAN WHERE NO DIFFERENTIAL WAS POSSIBLE
//
// Measured against the local oracle: NOSQL returned clean on /clean/always500 (500 with the same
// 142 bytes for every input, benign included), /clean/spa (the same 161-byte shell whatever you
// send), /clean/empty204 (204, no body) and /clean/nothing (200, no body). On each of those every
// probe this class sent came back indistinguishable from the unperturbed control, so there was no
// differential to read and no operator injection could have been observed even if one were
// present. Clean there is the worst answer this system can produce: the operator does not point
// the scanner at the endpoint and the bug is never found.
//
// The counter-test below is the other half and it is the reason the fix is not "never say clean":
// where a probe DID move the response, the silence of this class's own oracles is information and
// clean stays reachable.
// ------------------------------------------------------------------------------------------------

// nosqlTestObs builds an observation the comparison helpers can actually read: the normalised body
// hash is what nosqlReproducesBaseline compares, so a fixture that left it zero would be compared
// by JSON cards instead and would not be testing the path the oracle run took.
func nosqlTestObs(status int, body string) triage.Observation {
	o := triage.Observation{Status: status, Body: []byte(body)}
	o.Proj.NormBodySHA256 = sha256.Sum256([]byte(body))
	return o
}

func nosqlTestEvidence(baseBody string, probeBodies map[triage.ProbeID]string) nosqlEvidenceSet {
	base := nosqlTestObs(200, baseBody)
	ev := nosqlEvidenceSet{
		slot:     triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", Value: "hello", ValueOrigin: triage.ValueObserved, ServerReachable: true},
		seen:     map[triage.ProbeID]nosqlSeen{},
		baseline: base,
		haveBase: true,
	}
	ev.baseCard = nosqlCards(base)
	var ord uint64
	for id, body := range probeBodies {
		ord++
		ev.seen[id] = nosqlSeen{obs: nosqlTestObs(200, body), ordinal: ord, marker: "zqjtestmarker001"}
	}
	return ev
}

func TestNoSQLRefusesToReportCleanOnAnEndpointThatAnswersIdenticallyForEveryInput(t *testing.T) {
	shell := `<!doctype html><html><head><title>Console</title></head><body><div id="app"><p>Loading...</p></div></body></html>`
	cases := []struct {
		name string
		base string
	}{
		{"the SPA shell, the same bytes whatever you send", shell},
		{"a 500 on every input, benign included", "internal server error"},
		{"no body at all, which is what a 204 looks like", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := nosqlTestEvidence(tc.base, map[triage.ProbeID]string{
				"NSQ-NC1": tc.base, "NSQ-J1": tc.base, "NSQ-C1": tc.base, "NSQ-E1": tc.base,
			})
			v := nosqlBase(ev, nosqlArmJS)
			v.Ordinals = []uint64{1, 2, 3, 4}
			got := nosqlClean(ev, v, "the $where probes ran, reached the wire and came back")
			if got.State == triage.StateClean {
				t.Fatalf("NOSQL reported CLEAN on an endpoint whose every response to this class was "+
					"byte-identical to the control. No differential was available, so no injection "+
					"could have been observed even if present, and a clean here sends the operator "+
					"away from a live endpoint. reason=%q", got.Reason)
			}
			if got.State != triage.StateCannotDetermine {
				t.Fatalf("state = %s, want cannot_determine. reason=%q", got.State, got.Reason)
			}
			if !strings.Contains(got.Reason, "value_insensitive") {
				t.Errorf("the reason must name the measurement that stopped the clean, got %q", got.Reason)
			}
		})
	}
}

func TestNoSQLStillReportsCleanWhenItsOwnProbesDidMoveTheResponse(t *testing.T) {
	ev := nosqlTestEvidence("<h1>Rosewood Gin</h1><p>product id 1</p>", map[triage.ProbeID]string{
		"NSQ-NC1": "<h1>Rosewood Gin</h1><p>product id 1</p>",
		"NSQ-J1":  "<h1>Juniper Dry</h1><p>product id 0</p>",
		"NSQ-C1":  "<h1>Rosewood Gin</h1><p>product id 1</p>",
	})
	v := nosqlBase(ev, nosqlArmJS)
	v.Ordinals = []uint64{1, 2, 3}
	got := nosqlClean(ev, v, "the $where probes ran and no interpreter named this run's marker")
	if got.State != triage.StateClean {
		t.Fatalf("state = %s, want clean: one of this class's own probes moved the response, so the "+
			"endpoint demonstrably shows what it does with this slot and the silence of the $where "+
			"oracles is information. reason=%q", got.State, got.Reason)
	}
}
