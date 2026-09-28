package triageclasses

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"strconv"
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

	named := []nosqlCleanClaim{{Kind: nosqlOracleNamed, Ready: true, Claim: "no named phrase appeared"}}
	counted := []nosqlCleanClaim{{Kind: nosqlOracleCount, Ready: true, Claim: "no array grew"}}

	cases := []struct {
		name   string
		ev     nosqlEvidenceSet
		claims []nosqlCleanClaim
		ords   []uint64
		wantIn string
	}{
		{"a clean with no probe ordinals asserts a measurement that never happened",
			nosqlEvidenceSet{slot: slot, haveBase: true}, named, nil, "no_probe_ordinals"},
		{"a clean with no unperturbed response has nothing to be quiet relative to",
			nosqlEvidenceSet{slot: slot, haveBase: false}, named, []uint64{69}, "route_control_unresolved"},
		{"a degraded baseline cannot tell a quiet oracle from an endpoint that is quiet about everything",
			nosqlEvidenceSet{slot: slot, haveBase: true, degraded: true}, named, []uint64{69}, "baseline_degraded"},
		// The junk case is now about the ROW COUNTERS and about nothing else, which is the whole
		// correction: an endpoint that moves for any junk value cannot support a bare differential,
		// and it can perfectly well support a search for a named engine phrase.
		{"an endpoint that moves for any junk value cannot support a bare row-count differential",
			nosqlEvidenceSet{slot: slot, haveBase: true, junkSensitive: true,
				baseCard: map[string]int{"/results": 3}}, counted, []uint64{69}, "junk_sensitive"},
		{"a response with no array in it leaves a row counter nothing to count",
			nosqlEvidenceSet{slot: slot, haveBase: true}, counted, []uint64{69}, "cardinality_unavailable"},
		{"an arm that declares no oracle at all has nothing to have watched staying silent",
			nosqlEvidenceSet{slot: slot, haveBase: true}, nil, []uint64{69}, "no_oracle_declared"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := nosqlBase(tc.ev, nosqlArmOP)
			v.Ordinals = tc.ords
			got := nosqlCleanOn(tc.ev, v, tc.claims, "the probes ran and the oracle stayed silent")
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
	if got := nosqlCleanOn(ok, v, named, "the probes ran and the oracle stayed silent"); !got.State.CountsAsClean() {
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
			got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
				{Kind: nosqlOracleNamed, Ready: true, Claim: "no marker came back glued to this class's product"},
				{Kind: nosqlOracleCount, Ready: true, Claim: "the true and false arms produced the same result set"},
			}, "the $where probes ran, reached the wire and came back")
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
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no interpreter named this run's marker"},
	}, "the $where probes ran")
	if got.State != triage.StateClean {
		t.Fatalf("state = %s, want clean: one of this class's own probes moved the response, so the "+
			"endpoint demonstrably shows what it does with this slot and the silence of the $where "+
			"oracles is information. reason=%q", got.State, got.Reason)
	}
}

// ------------------------------------------------------------------------------------------------
// RUN a218419a, THE LARGEST SINGLE DELIVERY FAILURE IN THE WHOLE RUN
//
// 384 of this class's 965 fidelity rows came back json_node_payload_is_not_valid_json. Four
// probes, and every attempt at each of them was refused:
//
//	NSQ-T3   107  logical 8123zqjfkqv000091umk
//	NSQ-F2    95  logical {"$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}zqjfkqv00003p9hc
//	NSQ-F3    95  logical {"$expr":{"$eq":[{"$multiply":[8123,7]},56862]}}zqjfkqv00005hdxs
//	NSQ-OP0   87  logical {"$eq":"0"}zqjfkqv0001dxm52
//
// Two of them are the arms of this class's tier-1 arithmetic oracle and one is the parse control
// that decides applicable from not-applicable for four of the six arms. Not one of them was ever
// sent, and the four arms above them reported cannot_determine (probe_not_observed) on every slot
// in the corpus.
//
// THE CAUSE IS IN THIS FILE. nosqlReq said "the ABSENCE of marker_offset means the payload carries
// no marker at all and none may be spliced in", and the runner does not read absence that way:
// MarkerInline with no offset clamps to the end of the payload and appends 16 bytes there. The
// runner HAS an opt-out, Variant["marker_placement"]="omitted", which ELI grew after exactly this
// happened to ELI-EL6, and this class never declared it. An absent key is not an instruction.
// ------------------------------------------------------------------------------------------------

// nosqlBareProbes is every probe in this class whose declared payload spells no marker token. The
// list is derived, never written out, so a probe added later cannot quietly miss the opt-out.
func nosqlBareProbes() []triage.ProbeSpec {
	var out []triage.ProbeSpec
	for _, p := range (nosqlClassifier{}).Probes() {
		if !bytes.Contains(p.Logical, []byte(nosqlMarkerTok)) {
			out = append(out, p)
		}
	}
	return out
}

func TestABareProbeDeclaresTheMarkerOptOutAndDoesNotRelyOnAnAbsentOffset(t *testing.T) {
	bare := nosqlBareProbes()
	if len(bare) == 0 {
		t.Fatal("no probe in this class is bare, so this test measures nothing")
	}
	for _, p := range bare {
		req := nosqlReq(p.ID, "body:/name", nosqlEligibility{value: "alice", place: nosqlPlaceJSONNode})
		if got := req.Variant["marker_placement"]; got != "omitted" {
			t.Errorf("%s carries no marker token and its request says marker_placement=%q. The "+
				"runner reads MarkerInline with no offset as 'append at the end' and glues 16 bytes "+
				"onto the payload; on run a218419a that refused every attempt at this probe with "+
				"json_node_payload_is_not_valid_json", p.ID, got)
		}
	}
}

func TestAMarkerBearingProbeDoesNotDeclareTheOptOutBecauseItNeedsItsMarker(t *testing.T) {
	for _, p := range (nosqlClassifier{}).Probes() {
		if !bytes.Contains(p.Logical, []byte(nosqlMarkerTok)) {
			continue
		}
		req := nosqlReq(p.ID, "body:/name", nosqlEligibility{value: "alice", place: nosqlPlaceJSONNode})
		if got, present := req.Variant["marker_placement"]; present {
			t.Errorf("%s spells a marker token and its request also says marker_placement=%q, which "+
				"would be a probe with no attributable token in it", p.ID, got)
		}
	}
}

// THE OPT-OUT IS NOT DECORATION, and this is the arithmetic that proves it. Every bare probe in
// this class whose payload is a JSON value stops being one the moment 16 alphanumeric bytes are
// glued to either end of it, and json_node_replace is the only encoder that can put an operator
// object into a filter document.
func TestAMarkerOnEitherEndOfABareProbeDestroysTheJSONItHasToBe(t *testing.T) {
	marker := []byte("zqjfkqv0001dxm52") // a real marker off run a218419a: 16 bytes of [0-9a-z]
	if len(marker) != 16 {
		t.Fatalf("the sample marker is %d bytes, not 16", len(marker))
	}
	checked := 0
	for _, p := range nosqlBareProbes() {
		rendered := bytes.ReplaceAll(p.Logical, []byte(nosqlValueTok), []byte("0"))
		if !json.Valid(rendered) {
			continue // a string-arm payload; it is not delivered as a JSON node
		}
		checked++
		for _, wire := range [][]byte{
			append(append([]byte{}, marker...), rendered...),
			append(append([]byte{}, rendered...), marker...),
		} {
			if json.Valid(wire) {
				t.Errorf("%s survives a marker at one end (%s), so this test is not measuring the "+
					"failure it was written for", p.ID, wire)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no bare probe renders to a JSON value, so the node-replace failure is not modelled here")
	}
}

// ------------------------------------------------------------------------------------------------
// RUN a218419a, THE WRONG CLEAN IN N-FILTER
//
// The four N-FILTER probes are SIBLINGS of the slot inside the filter document, which nosqlReq
// says in as many words and marks with placement=filter_root_sibling. Sibling keys at a filter
// root are ANDed. So on an endpoint that really does evaluate $expr:
//
//	baseline                                  N rows
//	NSQ-F2, the always-true arm, ANDed        N rows   -> same
//	NSQ-F3, the always-false arm, ANDed        0 rows   -> narrower
//
// MEASURED, on the oracle's own declared positive route for this arm, through the socat proxy:
//
//	POST /nosqli/noscripting {"name":"hello"}                                  count 1
//	POST /nosqli/noscripting {"name":"hello","$expr":...56861]}}  (true)       count 1
//	POST /nosqli/noscripting {"name":"hello","$expr":...56862]}}  (false)      count 0
//
// nosqlArmFilterVerdict required the TRUE arm to WIDEN before it would call anything a finding.
// An AND can never widen. So the finding branch was structurally unreachable for the only
// placement this arm has, every other branch fell through, and the function ended at
// nosqlClean with the sentence "the true arm did not widen while the false arm did not narrow" on
// a run where the false arm had just narrowed to zero. A confirmed NoSQL injection, reported as
// clean, in a reason that contradicts the evidence it was drawn from.
// ------------------------------------------------------------------------------------------------

// nosqlCardObs is an observation carrying a row count the widening oracle can read.
func nosqlCardObs(rows int) triage.Observation {
	o := triage.Observation{Status: 200, TransportErr: triage.TransportOK}
	o.Payload.Survived = triage.WireSurvivalIntact
	o.Proj.JSONCards = []string{"/rows.__len__=" + strconv.Itoa(rows)}
	o.Body = []byte(`{"count":` + strconv.Itoa(rows) + `}`)
	o.Proj.NormBodySHA256 = sha256.Sum256(o.Body)
	return o
}

// nosqlFilterRootEvidence is a JSON body slot at a top-level pointer, which is the only shape
// N-FILTER runs on, with the arithmetic pair's row counts set by the caller.
func nosqlFilterRootEvidence(baseRows, f2Rows, f3Rows int) nosqlEvidenceSet {
	slot := triage.Slot{
		Kind: triage.KindBody, Key: "body:/name", FieldPath: "/name", Value: "hello",
		BodyMedia: triage.BodyJSON, ValueOrigin: triage.ValueObserved, ServerReachable: true,
	}
	base := nosqlCardObs(baseRows)
	return nosqlEvidenceSet{
		slot:     slot,
		el:       nosqlEligibility{place: nosqlPlaceJSONNode, filterRoot: true, knownGood: true, value: "hello"},
		baseline: base,
		haveBase: true,
		baseCard: nosqlCards(base),
		seen: map[triage.ProbeID]nosqlSeen{
			"NSQ-F2": {obs: nosqlCardObs(f2Rows), ordinal: 2, marker: "zqjfkqv00003p9hc"},
			"NSQ-F3": {obs: nosqlCardObs(f3Rows), ordinal: 3, marker: "zqjfkqv00005hdxs"},
		},
	}
}

func TestTheExprPairFiringAsAnANDIsAFindingAndNeverAClean(t *testing.T) {
	// The measured oracle shape: 1, 1, 0.
	got := nosqlArmFilterVerdict(nosqlFilterRootEvidence(1, 1, 0))

	if got.State == triage.StateClean {
		t.Fatalf("N-FILTER reported CLEAN on the shape the oracle's own positive route produces: "+
			"the always-true arm returned the baseline row count and the always-false arm returned "+
			"none. A sibling key at a filter root is ANDed, so that is what a working $expr looks "+
			"like and it is the only thing it can look like. reason=%q", got.Reason)
	}
	if got.State != triage.StateFinding {
		t.Fatalf("state = %s, want finding. reason=%q", got.State, got.Reason)
	}
	if got.Oracle != "computation" {
		t.Errorf("oracle = %q, want computation: the server performed 8123*7, it was not inferred", got.Oracle)
	}
	if !strings.Contains(got.Reason, "expr_arithmetic") {
		t.Errorf("the reason does not name the oracle: %q", got.Reason)
	}
}

// The other half. A pair that moved together, or did not move at all, is NOT the computation, and
// the extra key being dropped has to stay separable from the extra key being evaluated.
func TestTheExprPairThatDidNotSeparateIsNotAFinding(t *testing.T) {
	cases := []struct {
		name         string
		base, f2, f3 int
		wantState    triage.TriageState
		wantIn       string
	}{
		{"the key was dropped: both arms are the baseline", 3, 3, 3, triage.StateNotApplicable, "object_not_parsed"},
		{"both arms moved the same way, which arithmetic cannot do", 3, 1, 1, triage.StateSuspicious, "expr_pair_moved_together"},
		{"the false arm emptied and the true arm did too", 3, 0, 0, triage.StateSuspicious, "expr_pair_moved_together"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nosqlArmFilterVerdict(nosqlFilterRootEvidence(tc.base, tc.f2, tc.f3))
			if got.State == triage.StateClean {
				t.Fatalf("clean: %q", got.Reason)
			}
			if got.State != tc.wantState {
				t.Fatalf("state = %s, want %s. reason=%q", got.State, tc.wantState, got.Reason)
			}
			if !strings.Contains(got.Reason, tc.wantIn) {
				t.Errorf("reason %q does not name %q", got.Reason, tc.wantIn)
			}
		})
	}
}

// A widening true arm is still a finding: a sink that replaces the whole filter rather than
// ANDing a sibling into it widens instead of holding steady, and both are the computation.
func TestAWideningTrueArmIsStillTheComputation(t *testing.T) {
	got := nosqlArmFilterVerdict(nosqlFilterRootEvidence(1, 4, 0))
	if got.State != triage.StateFinding {
		t.Fatalf("state = %s, want finding. reason=%q", got.State, got.Reason)
	}
}

// NO CLEAN MAY REST ON A PROBE THE RUNNER NEVER SENT. The reason a class cannot see its own probe
// is almost always in the tool, not in the target, and on run a218419a it was: 384 refusals in
// the encoder. The verdict must say so rather than reading as a measurement of the endpoint.
func TestAnUnobservedProbeNamesTheToolAndNotTheTarget(t *testing.T) {
	ev := nosqlFilterRootEvidence(1, 1, 0)
	delete(ev.seen, "NSQ-F2")

	got := nosqlArmFilterVerdict(ev)
	if got.State != triage.StateCannotDetermine {
		t.Fatalf("state = %s, want cannot_determine. reason=%q", got.State, got.Reason)
	}
	low := strings.ToLower(got.Reason)
	for _, want := range []string{"probe_not_observed", "runner", "not a measurement"} {
		if !strings.Contains(low, want) {
			t.Errorf("the reason does not name %q, so it reads as a fact about the target: %q", want, got.Reason)
		}
	}
}

// A PROBE AIMED AT THE FILTER ROOT THAT DID NOT LAND THERE IS THE TOOL'S FAULT AND MUST SAY SO.
// The four N-FILTER probes are marked placement=filter_root_sibling. A runner that node-replaces
// instead sends {"name":{"$expr":{...}}}, a field-level $expr, which every engine rejects the
// same way for both arms. That reads as object_not_parsed, which is a sentence about the target.
func TestAFilterRootProbeThatLandedSomewhereElseNamesTheRunner(t *testing.T) {
	ev := nosqlFilterRootEvidence(3, 3, 3) // the shape a rejected pair produces
	misplaced := ev.seen["NSQ-F2"]
	misplaced.obs.ReqBody = []byte(`{"name":{"$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}}`)
	ev.seen["NSQ-F2"] = misplaced

	got := nosqlArmFilterVerdict(ev)
	if got.State != triage.StateCannotDetermine {
		t.Fatalf("state = %s, want cannot_determine. reason=%q", got.State, got.Reason)
	}
	for _, want := range []string{"filter_root_placement_not_made", "RUNNER"} {
		if !strings.Contains(got.Reason, want) {
			t.Errorf("the reason does not name %q: %q", want, got.Reason)
		}
	}
}

func TestAFilterRootProbeThatDidLandThereIsNotAccused(t *testing.T) {
	ev := nosqlFilterRootEvidence(1, 1, 0)
	placed := ev.seen["NSQ-F2"]
	placed.obs.ReqBody = []byte(`{"name":"hello","$expr":{"$eq":[{"$multiply":[8123,7]},56861]}}`)
	ev.seen["NSQ-F2"] = placed

	if got := nosqlArmFilterVerdict(ev); got.State != triage.StateFinding {
		t.Fatalf("state = %s, want finding. reason=%q", got.State, got.Reason)
	}
}

// AN UNRECORDED REQUEST IS NOT EVIDENCE OF A MISPLACEMENT. Accusing the runner on an absence is
// the same mistake as reading an absence as a clean, in the other direction.
func TestAnUnreadableRequestBodyDoesNotAccuseTheRunner(t *testing.T) {
	for _, body := range [][]byte{nil, []byte(""), []byte("name=hello"), []byte(`["not","an","object"]`)} {
		if placed, known := nosqlRootSiblingPlaced(triage.Observation{ReqBody: body}, "$expr"); known || placed {
			t.Errorf("ReqBody %q answered placed=%v known=%v, want both false", body, placed, known)
		}
	}
	placed, known := nosqlRootSiblingPlaced(triage.Observation{
		ReqBody: []byte(`{"name":"hello","$expr":{}}`)}, "$expr")
	if !placed || !known {
		t.Errorf("a root $expr answered placed=%v known=%v, want both true", placed, known)
	}
}

// RFC 6901 SAYS "/" IS THE MEMBER NAMED "", AND THAT IS WHAT THIS CLASS HAS TO KEEP BELIEVING.
// Run a218419a produced eleven slots keyed body:/:node with field_path "/" and an empty name, and
// every class that wrote to one was refused with json_pointer_not_found. The pointer is the
// slot's, handed identically to all nine classes, so the derivation is where it is wrong. If
// someone later "fixes" it here the class stops reaching a filter root whose field really is
// named "", which is a coverage loss traded for a symptom.
func TestTheRootMemberPointerIsReadTheWayRFC6901DefinesIt(t *testing.T) {
	cases := map[string]bool{
		"":              true, // the whole document
		"/":             true, // the member whose key is the empty string
		"/name":         true,
		"/a/b":          false,
		"/categories/0": false,
		"name":          false,
	}
	for ptr, want := range cases {
		if got := nosqlIsTopLevelMember(ptr); got != want {
			t.Errorf("nosqlIsTopLevelMember(%q) = %v, want %v", ptr, got, want)
		}
	}
}

// ------------------------------------------------------------------------------------------------
// THE SAME ROOT CAUSE, IN N-JS, AND IT IS A SECOND WRONG CLEAN
//
// MEASURED on the oracle's own $where positive route, GET /nosqli/where?q=, through the socat
// proxy, with the value hello and a real 16-byte marker off run a218419a:
//
//	baseline                                        count 1
//	NSQ-J5 bare   hello' && 8123*7==56861 && 'a'=='a         count 1
//	NSQ-J6 bare   hello' && 8123*7==56862 && 'a'=='a         count 0   <- the differential
//	NSQ-J5 + marker appended  ...'a'=='azqjfkqv0001dxm52     count 0
//	NSQ-J6 + marker appended  ...'a'=='azqjfkqv0001dxm52     count 0   <- no differential
//
// The appended marker lands inside the final string comparison, so 'a'=='a becomes
// 'a'=='azqjfkqv0001dxm52, which is false, and the TRUE arm of the boolean can never be true.
// Both arms then return zero rows, c5 == c6, the differential does not fire, and the arm falls
// through to nosqlClean. Both arms DID move away from the baseline, so the value-insensitive
// guard passes them, and the clean is returned on a route that is a declared positive.
//
// The fix is the marker opt-out, not a change here: bare, this arm reads the differential
// correctly. The test is what stops the opt-out being removed later.
// ------------------------------------------------------------------------------------------------

func nosqlJSEvidence(baseRows, j5Rows, j6Rows int) nosqlEvidenceSet {
	base := nosqlCardObs(baseRows)
	return nosqlEvidenceSet{
		slot:     triage.Slot{Kind: triage.KindQuery, Key: "query:q", Name: "q", Value: "hello", ValueOrigin: triage.ValueObserved, ServerReachable: true},
		el:       nosqlEligibility{place: nosqlPlaceNone, knownGood: true, value: "hello"},
		baseline: base,
		haveBase: true,
		baseCard: nosqlCards(base),
		seen: map[triage.ProbeID]nosqlSeen{
			"NSQ-J5": {obs: nosqlCardObs(j5Rows), ordinal: 5, marker: "zqjfkqv00000a1b2"},
			"NSQ-J6": {obs: nosqlCardObs(j6Rows), ordinal: 6, marker: "zqjfkqv00000c3d4"},
		},
	}
}

func TestTheWhereConcatenationDifferentialFiresOnTheShapeTheOracleProducesBare(t *testing.T) {
	got := nosqlArmJSVerdict(nosqlJSEvidence(1, 1, 0))
	if got.State != triage.StateSuspicious {
		t.Fatalf("state = %s, want suspicious. reason=%q", got.State, got.Reason)
	}
	if !strings.Contains(got.Reason, "where_concat_differential") {
		t.Errorf("the reason does not name the differential: %q", got.Reason)
	}
}

// ------------------------------------------------------------------------------------------------
// WHY THIS CLASS COULD NEVER SAY CLEAN, AND THE THREE SENTENCES THAT EXPLAINED IT WRONGLY
// ------------------------------------------------------------------------------------------------

// nosqlCleanFixture is an endpoint shape plus the evidence set this class would build from it.
// The named-string oracles in this class read BODIES; the row-count oracles read ARRAYS. The two
// preconditions are different and the fixtures below separate them deliberately.
func nosqlCleanFixture(base string, probes map[triage.ProbeID]string, junk bool) nosqlEvidenceSet {
	ev := nosqlTestEvidence(base, probes)
	ev.junkSensitive = junk
	return ev
}

// A JUNK-SENSITIVE ENDPOINT BLINDS THE ROW COUNTERS AND BLINDS NOTHING ELSE.
//
// The shipped gate killed EVERY arm on junk sensitivity with "its silence on my probes carries no
// information". That is true of a bare differential and FALSE of every named-string oracle in this
// class: N-COUCH looks for a CouchDB phrase naming this run's marker, N-ES for an Elasticsearch
// parse error absent from the baseline, N-JS for this run's marker glued to a product the server
// computed. A harmless value moving the response cannot put any of those strings into it, and an
// endpoint that moves for junk is an endpoint that DEMONSTRABLY CAN show what it did with the
// slot, which is the precondition a marker oracle actually needs.
//
// MEASURED, canary oracle, the 80-route exam, per arm out of 80 query slots: N-ES 38 junk_sensitive,
// N-JS 38, N-COUCH 5. Eighty-one arm rows reporting an unknown because a control moved, on arms
// whose own oracle is a string search.
func TestAJunkSensitiveEndpointDoesNotBlindTheNamedStringOracles(t *testing.T) {
	page := `{"results":[{"id":1}],"echo":"hello"}`
	ev := nosqlCleanFixture(page, map[triage.ProbeID]string{
		"NSQ-C2": `{"results":[{"id":1}],"echo":"probe-a"}`,
		"NSQ-C4": `{"results":[{"id":1}],"echo":"probe-b"}`,
	}, true)
	v := nosqlBase(ev, nosqlArmCouch)
	v.Ordinals = []uint64{1, 2}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no CouchDB error named this run's marker"},
	}, "the Mango probes ran, reached the wire and came back")
	if !got.State.CountsAsClean() {
		t.Fatalf("N-COUCH, whose clean rests entirely on a string search for a CouchDB phrase and "+
			"for this class's own erlang_binary marker transform, refused to conclude because a "+
			"HARMLESS CONTROL MOVED THE RESPONSE. A moving response is what a marker oracle needs, "+
			"not what defeats it:\n  %s / %s", got.State, got.Reason)
	}
}

// AND AN ARM WITH BOTH KINDS STILL CONCLUDES, over the half that was judged, saying which half was
// not. /clean/echomongo is the route this class's own OracleCases declare must produce a CLEAN from
// N-JS, and it is an endpoint that echoes the payload into a 400: junk-sensitive by construction.
func TestAnArmWithBothOracleKindsCleansOverTheHalfItCouldJudge(t *testing.T) {
	page := `{"error":"bad request","echo":"hello"}`
	ev := nosqlCleanFixture(page, map[triage.ProbeID]string{
		"NSQ-J3": `{"error":"bad request","echo":"ZZmarker'+(8123*7)+'"}`,
		"NSQ-J7": `{"error":"bad request","echo":"other"}`,
	}, true)
	v := nosqlBase(ev, nosqlArmJS)
	v.Ordinals = []uint64{1, 2}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no marker came back glued to this class's product"},
		{Kind: nosqlOracleCount, Ready: true, Claim: "the concatenated true and false arms produced the same result set"},
	}, "the $where probes ran, reached the wire and came back")
	if !got.State.CountsAsClean() {
		t.Fatalf("N-JS refused to conclude on the shape its own OracleCases declare must be clean "+
			"(/clean/echomongo, an endpoint that echoes the payload into a 400):\n  %s / %s",
			got.State, got.Reason)
	}
	if !strings.Contains(got.Reason, "no marker came back glued to this class's product") {
		t.Errorf("the clean does not say which oracle was watched staying silent:\n  %s", got.Reason)
	}
	if !strings.Contains(got.Reason, "row_count") || !strings.Contains(got.Reason, "could not be judged") {
		t.Errorf("the clean does not say which oracle could NOT be judged, so it reads as a wider "+
			"clean than it is:\n  %s", got.Reason)
	}
	if _, ok := got.Annotations["oracles_not_judged"]; !ok {
		t.Errorf("the verdict carries no oracles_not_judged annotation, so the narrowing is in prose "+
			"only and nothing downstream can read it: %v", got.Annotations)
	}
}

// A RESPONSE WITH NO ARRAY IN IT BLINDS THE ROW COUNTERS AND BLINDS NOTHING ELSE, which is the
// same category error one precondition over and the LARGEST one by count.
//
// MEASURED, same exam: N-OP returned cannot_determine (cardinality_unavailable) on 35 of 80 query
// slots and N-TYPE on 69. N-TYPE deserves it and says so: it is entirely a row-count oracle. N-OP
// is not. Its first and strongest oracle is nosqlClassifyError, a search for a named engine phrase
// with this run's marker beside it, and that oracle ran and stayed silent on every one of those 35.
func TestNoArrayToCountDoesNotBlindTheNamedStringHalfOfAnArm(t *testing.T) {
	page := `<html><body>Welcome, hello</body></html>`
	ev := nosqlCleanFixture(page, map[triage.ProbeID]string{
		"NSQ-OP1": `<html><body>Welcome, probe</body></html>`,
		"NSQ-OP0": `<html><body>Welcome, hello</body></html>`,
	}, false)
	if nosqlHaveCards(ev) {
		t.Fatal("the fixture was supposed to carry no JSON array at all")
	}
	v := nosqlBase(ev, nosqlArmOP)
	v.Ordinals = []uint64{1, 2}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no named engine phrase appeared that was absent from the baseline"},
		{Kind: nosqlOracleCount, Ready: true, Claim: "no array in the response grew"},
	}, "the parse control proved the object reaches the query and the operator probes ran")
	if !got.State.CountsAsClean() {
		t.Fatalf("N-OP refused to conclude anything on an HTML endpoint because there was no JSON "+
			"array to count, discarding the answer its named-phrase oracle actually gave:\n  %s / %s",
			got.State, got.Reason)
	}
	if strings.Contains(got.Reason, "no array in the response grew") {
		t.Errorf("the clean claims the row-count oracle stayed silent when there were no rows to "+
			"count, which is the overstatement this whole gate exists to stop:\n  %s", got.Reason)
	}
}

// AND AN ARM THAT IS ROW COUNTS AND NOTHING ELSE STILL REFUSES, and says the precondition is a
// property of the arm rather than a transient. N-TYPE's own words are "This arm is entirely a
// row-count oracle, so there is no fallback", and that is the honest answer, not a bug to loosen.
func TestARowCountOnlyArmStillRefusesWhenThereAreNoRows(t *testing.T) {
	page := `<html><body>Welcome, hello</body></html>`
	ev := nosqlCleanFixture(page, map[triage.ProbeID]string{
		"NSQ-T1": `<html><body>Welcome, a</body></html>`,
		"NSQ-T2": `<html><body>Welcome, b</body></html>`,
	}, false)
	v := nosqlBase(ev, nosqlArmType)
	v.Ordinals = []uint64{1, 2}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleCount, Ready: true, Claim: "no array in the response grew"},
	}, "the array pair ran, reached the wire and came back")
	if got.State.CountsAsClean() {
		t.Fatalf("a row-count-only arm reported clean on a response with no rows in it: %s", got.Reason)
	}
	if !strings.Contains(got.Reason, "cardinality_unavailable") {
		t.Errorf("the refusal does not name cardinality_unavailable, which is the reason an operator "+
			"greps for:\n  %s", got.Reason)
	}
}

// AN ENDPOINT THAT ANSWERS IDENTICALLY TO EVERYTHING STILL BLINDS BOTH KINDS. The named oracles
// are not exempt from this one and must not become exempt: a named string appearing in a probe
// response that is absent from the baseline would BY DEFINITION make that probe distinguishable
// from the control, so where nothing is distinguishable no named string could have appeared and
// the silence is vacuous.
func TestAnEndpointThatNeverVariesBlindsTheNamedStringOraclesToo(t *testing.T) {
	shell := `<!doctype html><html><body><div id="app">Loading...</div></body></html>`
	ev := nosqlCleanFixture(shell, map[triage.ProbeID]string{
		"NSQ-NC1": shell, "NSQ-C2": shell, "NSQ-C4": shell, "NSQ-E2": shell,
	}, false)
	v := nosqlBase(ev, nosqlArmCouch)
	v.Ordinals = []uint64{1, 2, 3, 4}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no CouchDB error named this run's marker"},
	}, "the Mango probes ran")
	if got.State.CountsAsClean() {
		t.Fatalf("clean on an endpoint whose every response to this class was byte-identical to the "+
			"unperturbed control: %s", got.Reason)
	}
	if !strings.Contains(got.Reason, "value_insensitive") {
		t.Errorf("the refusal does not name value_insensitive:\n  %s", got.Reason)
	}
}

// THE value_insensitive SENTENCE MAY NOT CLAIM SOMETHING THIS CLASS CAN BE READ TO REFUTE.
//
// It shipped saying "every oracle in this class is a differential". Three of the six arms clean on
// a string search and nothing else: N-COUCH on a CouchDB phrase and the erlang_binary transform,
// N-ES on an Elasticsearch parse error, and N-JS's tier-1 oracle on this run's marker glued to a
// product. The sentence was the justification for a gate that then blocked all three.
func TestTheValueInsensitiveReasonDoesNotClaimEveryOracleIsADifferential(t *testing.T) {
	shell := `<!doctype html><html><body><div id="app">Loading...</div></body></html>`
	ev := nosqlCleanFixture(shell, map[triage.ProbeID]string{
		"NSQ-NC1": shell, "NSQ-C2": shell, "NSQ-C4": shell,
	}, false)
	v := nosqlBase(ev, nosqlArmCouch)
	v.Ordinals = []uint64{1, 2, 3}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no CouchDB error named this run's marker"},
	}, "the Mango probes ran")
	if strings.Contains(got.Reason, "every oracle in this class is a differential") {
		t.Errorf("the value_insensitive reason still asserts that every oracle in this class is a "+
			"differential. nosqlArmCouchVerdict, nosqlArmESVerdict and the tier-1 half of "+
			"nosqlArmJSVerdict each clean on a string search:\n  %s", got.Reason)
	}
}

// THE probe_not_observed SENTENCE MAY NOT NAME A CAUSE THE RUN REFUTES.
//
// It shipped saying "The commonest cause is the encoder refusing the probe before it was sent,
// which the run records against this ordinal in triage_fidelity with survived=refused". The
// operator's run 2n6f holds ZERO refused rows: survived is only encoded (3830) and intact (1482),
// totalling exactly probes_sent. Those probes left NO fidelity row at all, which is a different
// failure with a different fix, and the sentence sent the operator to look up a row that does not
// exist.
func TestTheProbeNotObservedReasonDoesNotNameACauseTheRunRefutes(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   nosqlEvidenceSet
	}{
		{"not one of this class's probes came back", nosqlEvidenceSet{seen: map[triage.ProbeID]nosqlSeen{}}},
		{"some came back and this one did not", nosqlEvidenceSet{seen: map[triage.ProbeID]nosqlSeen{
			"NSQ-OP0": {obs: nosqlTestObs(200, "ok"), ordinal: 7},
		}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, why := tc.ev.usable("NSQ-OP1")
			if why == "" {
				t.Fatal("the probe was accepted as usable")
			}
			if strings.Contains(why, "The commonest cause is") {
				t.Errorf("the reason still guesses at a cause it cannot see:\n  %s", why)
			}
			low := strings.ToLower(why)
			if strings.Contains(low, "survived=refused") && !strings.Contains(low, "no fidelity row") {
				t.Errorf("the reason still sends the operator to a survived=refused row without "+
					"saying that on the run which found this there were none, and that the absence "+
					"of a row is itself the distinguishing fact:\n  %s", why)
			}
			if !strings.Contains(low, "cannot see why") && !strings.Contains(low, "do not know") {
				t.Errorf("the reason does not say plainly that this class cannot see the cause from "+
					"here:\n  %s", why)
			}
			if !strings.Contains(why, "fidelity") {
				t.Errorf("the reason does not name what would distinguish the candidates:\n  %s", why)
			}
		})
	}

	// AND IT MUST REPORT WHAT IT CAN ACTUALLY SEE, which is how many of this class's own probes
	// did come back on this slot. One missing probe out of eleven and eleven missing out of eleven
	// are different failures and the operator can act on the difference.
	none := nosqlEvidenceSet{seen: map[triage.ProbeID]nosqlSeen{}}
	_, whyNone := none.usable("NSQ-OP1")
	some := nosqlEvidenceSet{seen: map[triage.ProbeID]nosqlSeen{"NSQ-OP0": {obs: nosqlTestObs(200, "ok")}}}
	_, whySome := some.usable("NSQ-OP1")
	if whyNone == whySome {
		t.Errorf("the reason is identical whether NONE of this class's probes came back or all but "+
			"this one did, so it reports nothing this class actually measured:\n  %s", whyNone)
	}
}

// A CLEAN MAY NOT CLAIM AN ORACLE STAYED SILENT WHEN THE PROBES THAT ORACLE READS NEVER CAME BACK.
//
// This is the same false clean one level in from the endpoint. N-JS's row-count claim reads
// NSQ-J5 against NSQ-J6 and the branch that compares them is entered only when both are in hand,
// so a clean carrying "the concatenated true and false arms produced the same result set" on a
// slot where neither arm came back is a measurement asserted out of two missing responses. The
// endpoint's own preconditions cannot catch it: the endpoint may be perfectly well behaved and
// the probes still absent.
func TestACleanDoesNotClaimAnOracleWhoseProbesNeverCameBack(t *testing.T) {
	page := `{"results":[{"id":1}],"echo":"hello"}`
	ev := nosqlCleanFixture(page, map[triage.ProbeID]string{
		"NSQ-J3": `{"results":[{"id":1}],"echo":"a"}`,
	}, false)
	v := nosqlBase(ev, nosqlArmJS)
	v.Ordinals = []uint64{1}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: nosqlAnyDelivered(ev, "NSQ-J3", "NSQ-J7", "NSQ-J4"),
			Claim: "no marker came back glued to this class's product"},
		{Kind: nosqlOracleCount, Ready: nosqlAllDelivered(ev, "NSQ-J5", "NSQ-J6"),
			Claim: "the concatenated true and false arms produced the same result set"},
	}, "the $where probes ran")
	if !got.State.CountsAsClean() {
		t.Fatalf("the named-string half was answerable and the arm refused anyway: %s / %s",
			got.State, got.Reason)
	}
	if strings.Contains(got.Reason, "the concatenated true and false arms produced the same result set") {
		t.Errorf("the clean asserts a result-set comparison over two probes that never came back:\n  %s",
			got.Reason)
	}
	if !strings.Contains(got.Reason, "probes_not_delivered") {
		t.Errorf("the clean does not say the row-count oracle was never in a position to answer:\n  %s",
			got.Reason)
	}

	// AND A PAIR IS A PAIR. One arm of the concatenation differential without the other is not a
	// differential, so Ready must be all-or-nothing and not any-of.
	half := nosqlCleanFixture(page, map[triage.ProbeID]string{
		"NSQ-J5": `{"results":[{"id":1}],"echo":"a"}`,
	}, false)
	if nosqlAllDelivered(half, "NSQ-J5", "NSQ-J6") {
		t.Error("one arm of the true/false pair was accepted as a delivered differential")
	}
	if !nosqlAnyDelivered(half, "NSQ-J5", "NSQ-J6") {
		t.Error("nosqlAnyDelivered missed a probe that is present and delivered")
	}
	if nosqlAllDelivered(half) {
		t.Error("nosqlAllDelivered over an empty id list reported ready, which would make every " +
			"unwired claim believed by default")
	}
}

// AN ORACLE WHOSE PROBE IS NEVER PLANNED IS AN ORACLE THAT DOES NOT EXIST ON THAT SLOT.
//
// MEASURED, canary oracle, the 80-route exam, triage_fidelity for the whole run: across 79 slots
// NSQ-J5, NSQ-J6 and NSQ-J8 each have 79 rows and NSQ-J7 has ZERO. NSQ-J8 is NSQ-J7's repair
// control. Seventy-nine requests went out carrying the control for a probe that was never sent,
// and N-JS's tier-1 computation oracle - this run's marker glued to a product the server computed,
// the one oracle in the arm that is attributable rather than a bare differential - was blind on
// every query slot in the corpus. The same asymmetry sends NSQ-E2 and NSQ-E3 to an object-capable
// slot while NSQ-E1, the boolean-widening probe, is planned only where the slot CANNOT carry an
// object.
//
// The ladder's own comment says why the string arms belong on an object-capable slot: "an app can
// build a $where string out of the same parameter it also passes as an object." That argument
// covers J7 exactly as it covers J5, J6 and J8.
func TestEveryStringArmProbeIsPlannedWhereItsOwnControlIsPlanned(t *testing.T) {
	slot := triage.Slot{
		Kind: triage.KindQuery, Key: "query:q", Name: "q", Value: "hello",
		ValueOrigin: triage.ValueObserved, ServerReachable: true,
	}
	ctx := nosqlCtx(slot, "")
	e := nosqlEligible(ctx)
	if e.place == nosqlPlaceNone {
		t.Fatalf("the fixture was meant to be an object-capable slot, and nosqlEligible calls it %q", e.place)
	}

	planned := map[triage.ProbeID]bool{}
	for round := 0; round < 4; round++ {
		c := ctx
		c.Round = round
		for _, r := range (nosqlClassifier{}).Plan(c) {
			planned[r.Spec] = true
		}
	}

	for _, pair := range []struct{ probe, control triage.ProbeID }{
		{"NSQ-J7", "NSQ-J8"},
		{"NSQ-E1", "NSQ-E2"},
	} {
		if planned[pair.control] && !planned[pair.probe] {
			t.Errorf("%s is planned on an object-capable %s slot and %s is not. %s exists to make "+
				"%s readable, so every one of those requests is a control for a measurement that "+
				"was never taken, and the oracle %s carries is blind on every slot of this shape",
				pair.control, slot.Kind, pair.probe, pair.control, pair.probe, pair.probe)
		}
	}
}
