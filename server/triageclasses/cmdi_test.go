package triageclasses

import (
	"bytes"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// Tests for the OS command injection classifier.
//
// WHAT THESE TESTS ARE FOR. Not that the detector fires: a detector that always says yes fires
// too. The false-positive rows are the first-class citizens here, and so is every path that must
// yield an unknown rather than a clean. A class that has only ever been observed firing is
// exactly as unverified as one that has only ever been observed staying silent.

// Markers in THIS class's R12 ordinal stripe: ordinal mod 64 must equal 3. Hand-built rather than
// minted because MintMarkerAt takes a capability this package deliberately cannot import, which
// is the same reason cmdiEnv exists.
const (
	cmdiMarkOne   triage.Marker = "zqjtest000003xyz" // ordinal 3
	cmdiMarkTwo   triage.Marker = "zqjtest00001vxyz" // ordinal 67, 67 mod 64 == 3
	cmdiMarkOther triage.Marker = "zqjtest000004xyz" // ordinal 4, which is class SQL, not this one
)

func TestTheHandBuiltTestMarkersAreInThisClassesOwnStripe(t *testing.T) {
	for _, m := range []triage.Marker{cmdiMarkOne, cmdiMarkTwo} {
		if !m.WellFormed() {
			t.Fatalf("marker %q is not well formed, so every test below is testing nothing", m)
		}
		if !m.BelongsTo(triage.ClassCMDI) {
			owner, _ := m.ClassID()
			t.Fatalf("marker %q is in class %s's stripe, not CMDI's", m, owner)
		}
	}
	if cmdiMarkOther.BelongsTo(triage.ClassCMDI) {
		t.Fatal("the foreign marker is in this class's stripe, so the foreign-marker test proves nothing")
	}
}

// cmdiRender is what the runner is expected to put on the wire for a declared probe: the payload
// with the marker placeholder and the observed-value placeholder substituted.
func cmdiRender(t *testing.T, id triage.ProbeID, m triage.Marker, value string) string {
	t.Helper()
	spec, ok := cmdiSpecIndex()[id]
	if !ok {
		t.Fatalf("probe %s is not declared", id)
	}
	s := string(spec.Logical)
	s = strings.ReplaceAll(s, cmdiMark, string(m))
	s = strings.ReplaceAll(s, cmdiObservedValue, value)
	s = strings.ReplaceAll(s, cmdiOOBBase, "oob.example")
	return s
}

// cmdiShotOf builds one delivered, wire-proven observation of a probe.
func cmdiShotOf(t *testing.T, id triage.ProbeID, m triage.Marker, body string) cmdiShot {
	t.Helper()
	wire := cmdiRender(t, id, m, "widget")
	return cmdiShot{
		probe:   id,
		ordinal: 3,
		marker:  m,
		obs: triage.Observation{
			ObsID:  "obs-" + string(id),
			Status: 200,
			Body:   []byte(body),
			Payload: triage.PayloadWire{
				Logical:   []byte(wire),
				Wire:      []byte(wire),
				Container: []byte(wire),
				Survived:  triage.WireSurvivalIntact,
			},
		},
	}
}

// cmdiFullSweep is every probe a clean at this slot depends on, each answered with the same
// body. It exists because a clean is only reachable after the whole deliverable set has gone
// out, which is CATALOGUE 4.5 rule 2 for this class.
func cmdiFullSweep(t *testing.T, env cmdiEnv, m triage.Marker, body func(triage.ProbeID) string) []cmdiShot {
	t.Helper()
	var out []cmdiShot
	for _, id := range cmdiRequiredFamilies(env) {
		out = append(out, cmdiShotOf(t, id, m, body(id)))
	}
	if len(out) < 10 {
		t.Fatalf("the deliverable set for this slot is only %d probes, which is too few for the sweep to mean anything", len(out))
	}
	return out
}

func cmdiQuerySlot() triage.Slot {
	return triage.Slot{
		VectorID: "v1", Kind: triage.KindQuery, Key: "query:sort", Name: "sort",
		Value: "widget", ValueOrigin: triage.ValueObserved, Method: "GET",
		ServerReachable: true,
		Constraints:     triage.SlotConstraints{DecodeDepth: 1},
	}
}

func cmdiHealthyEnv() cmdiEnv {
	return cmdiEnv{
		slot:     cmdiQuerySlot(),
		route:    cmdiSnapshot{status: 200, sha: [32]byte{9, 9, 9}, body: []byte("<html>widget</html>")},
		postBase: true,
		baseline: triage.BaselineModel{Samples: 5, Stable: true},
	}
}

// ---------------------------------------------------------------------------------------------
// REGISTRATION AND THE CONTRACT
// ---------------------------------------------------------------------------------------------

func TestTheCMDIClassifierRegistersItselfAndSatisfiesTheClassifierContract(t *testing.T) {
	c, ok := triage.ClassifierFor(triage.ClassCMDI)
	if !ok {
		t.Fatal("the CMDI classifier did not register itself, so the whole class would be missing from every report with no error anywhere")
	}
	if c.ID() != triage.ClassCMDI {
		t.Fatalf("registered under CMDI but reports %s", c.ID())
	}
	if err := triage.ValidateClassifier(c); err != nil {
		t.Errorf("ValidateClassifier: %v", err)
	}
	if err := triage.PlannedProbesAreDeclared(c, c.Plan(triage.PlanCtx{Slot: cmdiQuerySlot()})); err != nil {
		t.Errorf("PlannedProbesAreDeclared: %v", err)
	}
}

func TestEveryCMDIPayloadIsThisClassesOwnAndSharedWithNoOtherRegisteredClass(t *testing.T) {
	rep := triage.CheckPayloadIsolation(triage.RegisteredClassifiers())
	for _, v := range rep.Violations {
		if v.ClassA == triage.ClassCMDI || v.ClassB == triage.ClassCMDI {
			t.Errorf("ISOLATION: %s", v)
		}
	}
	t.Logf("isolation ran over %d classes and %d probes", rep.ClassesChecked, rep.ProbesChecked)
}

func TestNoTwoCMDIProbesShipTheSameBytes(t *testing.T) {
	seen := map[string]triage.ProbeID{}
	for _, p := range (cmdiClassifier{}).Probes() {
		k := string(triage.NormaliseMarkers(p.Logical))
		if prev, dup := seen[k]; dup {
			t.Errorf("%s and %s ship byte-equal payloads, so a block or a rejection cannot be attributed to either family", p.ID, prev)
		}
		seen[k] = p.ID
		if len(p.Logical) == 0 {
			t.Errorf("%s has no bytes, so it tests nothing and would record clean", p.ID)
		}
	}
}

func TestTheCensusProbeIsNotABareMarkerBecauseTwoOtherClassesShipOne(t *testing.T) {
	spec := cmdiSpecIndex()[cmdiC0]
	norm := string(triage.NormaliseMarkers(spec.Logical))
	if norm == triage.MarkerPlaceholder {
		t.Error("the census probe is a bare marker. SSTI-S0 and ELI-E0 are bare markers too, so all three normalise to the same bytes and the isolation law fails the build")
	}
	if !bytes.Contains(spec.Logical, []byte(cmdiMark+cmdiArithTag)) {
		t.Error("the census probe does not carry the marker plus the arithmetic tag, so a silent census would not prove the answer prefix cannot come back")
	}
}

func TestNoCMDIPayloadIsDestructive(t *testing.T) {
	// The payloads are read-only by construction and this is the test that keeps them that way.
	// Every token here either destroys data, kills a process, writes to disk, or hammers a third
	// party, and none of them has any business in a triage probe.
	forbidden := []string{
		"rm ", "rm -", "del ", "format ", "mkfs", "shutdown", "reboot", "halt", "poweroff",
		"kill ", "killall", "pkill", "dd ", ":(){", "fork", "chmod", "chown", "mv ", "cp ",
		"> /", ">>", "truncate", "shred", "wipefs", "useradd", "passwd", "iptables",
		"DROP", "DELETE", "TRUNCATE", "Remove-Item", "Stop-Computer", "Restart-Computer",
	}
	for _, p := range (cmdiClassifier{}).Probes() {
		low := strings.ToLower(string(p.Logical))
		for _, bad := range forbidden {
			if strings.Contains(low, strings.ToLower(bad)) {
				t.Errorf("%s contains %q, and this class ships to every user against every app", p.ID, bad)
			}
		}
	}
}

func TestTheOutOfBandPayloadsOnlyEverReachTheConfiguredCollaborator(t *testing.T) {
	for _, p := range (cmdiClassifier{}).Probes() {
		s := string(p.Logical)
		if !strings.Contains(s, "http") && !strings.Contains(s, "nslookup") {
			continue
		}
		if !strings.Contains(s, cmdiOOBBase) {
			t.Errorf("%s reaches the network at a host that is not the configured collaborator: %q", p.ID, s)
		}
	}
}

func TestTheFragmentIsNotApplicableAndCarriesAReason(t *testing.T) {
	r := (cmdiClassifier{}).Reaches(triage.KindFragment, "text/html")
	if r.Reach != triage.ReachNever {
		t.Error("the fragment is reachable, but RFC 3986 strips it before the request leaves the browser, so no server-side shell can ever see it")
	}
	if r.Reason == "" {
		t.Error("a never with no reason is a silent zero wearing a different hat")
	}
	v := (cmdiClassifier{}).Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{
		Slot: triage.Slot{Kind: triage.KindFragment, Key: "fragment:tab"},
	}})
	cmdiAssertNoneClean(t, v)
}

// ---------------------------------------------------------------------------------------------
// THE COMPUTATION RULE, AND EVERY NAMED FALSE POSITIVE
// ---------------------------------------------------------------------------------------------

func TestTheComputationRuleFiresOnTheTrueShapeAndStaysSilentOnEveryNamedFalsePositive(t *testing.T) {
	m := cmdiMarkOne
	live := string(m) + "a140004" + string(m) + "s"
	reflected := cmdiRender(t, cmdiB1, m, "widget")

	cases := []struct {
		name string
		shot cmdiShot
		want bool
		why  string
	}{
		{
			name: "a live shell writes the arithmetic and the substitution as one contiguous run",
			shot: cmdiShotOf(t, cmdiB1, m, "<p>result: "+live+"</p>"),
			want: true,
			why:  "this is the whole class: the answer is in the response and was never in the request",
		},
		{
			name: "a live shell that only expanded the arithmetic",
			shot: cmdiShotOf(t, cmdiB13, m, "hit "+string(m)+"a140004 end"),
			want: true,
			why:  "the cmd.exe and brace families carry no substitution, so the arithmetic half alone is a hit",
		},
		{
			name: "a live shell that only ran the command substitution",
			shot: cmdiShotOf(t, cmdiCF3, m, "hit "+string(m)+"a"+string(m)+"s end"),
			want: true,
			why:  "the two tagged markers become adjacent only when $( ) actually ran",
		},
		{
			name: "FALSE POSITIVE: the endpoint reflects the payload verbatim and runs nothing",
			shot: cmdiShotOf(t, cmdiB1, m, "you searched for "+reflected),
			want: false,
			why:  "reflection is not injection. The answer string never appears because nothing computed it",
		},
		{
			name: "FALSE POSITIVE: the answer was in the REQUEST and came straight back",
			shot: func() cmdiShot {
				s := cmdiShotOf(t, cmdiNC2, m, "echo of "+live)
				s.probe = cmdiB1 // score it as a real probe: the not-in-the-request clause must still bite
				w := []byte(live)
				s.obs.Payload.Logical, s.obs.Payload.Wire, s.obs.Payload.Container = w, w, w
				return s
			}(),
			want: false,
			why:  "CMDI-NC2's shape. Without the not-in-the-request clause every echoing endpoint is a finding",
		},
		{
			name: "FALSE POSITIVE: the number 140004 appears in the page for its own reasons",
			shot: cmdiShotOf(t, cmdiB1, m, "<td>140004</td><td>"+string(m)+"a</td>"),
			want: false,
			why:  "the rule is a contiguous run anchored on this probe's own marker, not a substring search for the sum",
		},
		{
			name: "FALSE POSITIVE: the marker and the sum are present but not adjacent",
			shot: cmdiShotOf(t, cmdiB1, m, string(m)+"a is your token and 140004 is your order id"),
			want: false,
			why:  "a shell concatenates; an application that prints both separately has computed nothing",
		},
		{
			name: "FALSE POSITIVE: the answer carries another class's marker",
			shot: func() cmdiShot {
				s := cmdiShotOf(t, cmdiB1, cmdiMarkOther, "x "+string(cmdiMarkOther)+"a140004"+string(cmdiMarkOther)+"s y")
				s.marker = cmdiMarkOther
				return s
			}(),
			want: false,
			why:  "R12: a marker outside this class's ordinal stripe is a hit for nobody, never a hit for whoever looked first",
		},
		{
			name: "FALSE POSITIVE: the answer carries a different marker of our own",
			shot: cmdiShotOf(t, cmdiB1, m, "x "+string(cmdiMarkTwo)+"a140004"+string(cmdiMarkTwo)+"s y"),
			want: false,
			why:  "each probe's answer is anchored on its OWN minted marker, or a late body from another probe confirms this one",
		},
		{
			name: "FALSE POSITIVE: the transport refused and there is no response at all",
			shot: func() cmdiShot {
				s := cmdiShotOf(t, cmdiB1, m, live)
				s.obs.TransportErr = triage.TransportInvalidHeader
				return s
			}(),
			want: false,
			why:  "an undelivered probe's body cannot be read as anything, in either direction",
		},
		{
			name: "FALSE POSITIVE: no marker was minted for a payload that spells the placeholder",
			shot: func() cmdiShot {
				s := cmdiShotOf(t, cmdiB1, m, live)
				s.marker = ""
				return s
			}(),
			want: false,
			why:  "with no marker there is nothing to anchor on, and anchoring on the sum alone is a substring search",
		},
		{
			name: "FALSE POSITIVE: a negative control's response, which is never scored as a hit",
			shot: cmdiShotOf(t, cmdiNC1, m, live),
			want: false,
			why:  "controls are scored by cmdiControlFired, and scoring one as a finding would make the control set self-confirming",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := cmdiComputeHit(tc.shot)
			if got != tc.want {
				t.Errorf("computation rule fired=%v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

func TestAReflectedNegativeControlDoesNotCountAsTheDetectorFiring(t *testing.T) {
	m := cmdiMarkOne
	// CMDI-NC2 and CMDI-NC3 carry the answer bytes ON PURPOSE. A reflecting endpoint hands them
	// straight back, and the not-in-the-request clause must suppress them. If this test fails,
	// every echoing endpoint in the corpus becomes detector_unverified and the class is useless.
	shots := []cmdiShot{
		cmdiShotOf(t, cmdiNC2, m, "you said "+cmdiRender(t, cmdiNC2, m, "widget")),
		cmdiShotOf(t, cmdiNC3, m, "you said "+cmdiRender(t, cmdiNC3, m, "widget")),
	}
	if fired, which := cmdiControlFired(shots); fired {
		t.Errorf("control %s counted as fired on a plain reflection of its own bytes, which would void every verdict on every echoing endpoint", which)
	}
}

func TestANegativeControlThatReallyFiresVoidsEveryVerdictOnTheSlot(t *testing.T) {
	m := cmdiMarkOne
	// CMDI-NC1 is inert: every metacharacter is spelled as a word, so its response cannot contain
	// the answer unless the detector is matching something that is not a shell.
	bad := cmdiShotOf(t, cmdiNC1, m, "surprise "+string(m)+"a140004"+string(m)+"s")
	if fired, _ := cmdiControlFired([]cmdiShot{bad}); !fired {
		t.Fatal("the inert control did not register as fired, so a broken detector would go unnoticed")
	}
	v := cmdiVerdict(cmdiHealthyEnv(), []cmdiShot{
		bad,
		cmdiShotOf(t, cmdiB1, m, "hit "+string(m)+"a140004"+string(m)+"s"),
	})
	cmdiAssertNoneClean(t, v)
	if v[0].State != triage.StateCannotDetermine || !strings.Contains(v[0].Reason, cmdiReasonDetectorBad) {
		t.Errorf("state %q reason %q, want cannot_determine (detector_unverified): a detector shown firing on its own control is broken and its hits are worthless too", v[0].State, v[0].Reason)
	}
	for _, row := range v {
		if row.State.Kind() == triage.StateKindPositive {
			t.Error("a finding was reported by a detector that had just failed its own control")
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE BLIND CASE, AND EVERY OTHER WAY OF NOT KNOWING
// ---------------------------------------------------------------------------------------------

func TestASlotThatEchoesNothingWithNoCollaboratorIsNeverCleanAndSaysNeedsCommix(t *testing.T) {
	m := cmdiMarkOne
	// Everything went out perfectly and came back with a body that is simply the application's
	// own page. There is no reflection, so the computation oracle was never available, and there
	// is no collaborator, so the out-of-band oracle was never available either. The class has NO
	// non-timing oracle here and it must say so.
	// A blind sink answers exactly what the unperturbed value answered: the command runs, the
	// output goes nowhere, and the page is unchanged. That is what makes it blind.
	const page = "<html>nothing here</html>"
	env := cmdiHealthyEnv()
	env.route.body, env.route.sha = []byte(page), [32]byte{}
	shots := cmdiFullSweep(t, env, m, func(triage.ProbeID) string { return page })
	v := cmdiVerdict(env, shots)
	cmdiAssertNoneClean(t, v)
	if !strings.Contains(v[0].Reason, cmdiReasonBlindNoOracle) {
		t.Errorf("reason %q does not name no_oob_endpoint, so the report cannot tell an untestable blind sink from a tested quiet one", v[0].Reason)
	}
	if !strings.Contains(strings.ToLower(v[0].Reason), "commix") {
		t.Error("the reason does not tell the operator to point commix here, which is the only actionable thing left to say")
	}
	if got := v[0].Annotations["cmdi_echo_available"]; got != false {
		t.Errorf("cmdi_echo_available=%v, want false recorded explicitly rather than absent", got)
	}
}

func TestEveryUnreachableOrUndecidablePathYieldsAnUnknownRatherThanAClean(t *testing.T) {
	m := cmdiMarkOne
	quiet := "<html>nothing</html>"
	echoing := func(id triage.ProbeID) cmdiShot {
		return cmdiShotOf(t, id, m, "you said "+cmdiRender(t, id, m, "widget"))
	}

	cases := []struct {
		name  string
		env   func() cmdiEnv
		shots []cmdiShot
		want  string
		why   string
	}{
		{
			name:  "a probe that never reached the wire",
			env:   cmdiHealthyEnv,
			shots: []cmdiShot{echoing(cmdiC0), func() cmdiShot { s := echoing(cmdiB1); s.obs.TransportErr = triage.TransportTimeout; return s }()},
			want:  cmdiReasonNotDelivered,
			why:   "a transport refusal is the transport's silence, not the application's",
		},
		{
			name:  "a probe whose wire survival was never recorded",
			env:   cmdiHealthyEnv,
			shots: []cmdiShot{echoing(cmdiC0), func() cmdiShot { s := echoing(cmdiB1); s.obs.Payload.Survived = triage.WireSurvivalUnknown; return s }()},
			want:  cmdiReasonWireUnproven,
			why:   "Go's own cookie writer silently drops the semicolon, the quote and the backslash, which are this class's probe characters",
		},
		{
			name: "the runner never substituted the marker placeholder",
			env:  cmdiHealthyEnv,
			shots: []cmdiShot{echoing(cmdiC0), func() cmdiShot {
				s := echoing(cmdiB1)
				raw := cmdiSpecIndex()[cmdiB1].Logical
				s.obs.Payload.Wire, s.obs.Payload.Container = raw, raw
				return s
			}()},
			want: cmdiReasonPlaceholder,
			why:  "an unsubstituted placeholder makes every payload inert while the responses look perfectly normal, which would turn the whole corpus green",
		},
		{
			name: "the runner never substituted the observed value placeholder",
			env:  cmdiHealthyEnv,
			shots: []cmdiShot{echoing(cmdiC0), func() cmdiShot {
				s := echoing(cmdiA1)
				raw := cmdiSpecIndex()[cmdiA1].Logical
				s.obs.Payload.Wire, s.obs.Payload.Container = raw, raw
				return s
			}()},
			want: cmdiReasonPlaceholder,
			why:  "the argument-injection family needs the real value beside the flag, and a literal <V> is not it",
		},
		{
			name: "a response carrying a marker from another class's stripe",
			env:  cmdiHealthyEnv,
			shots: []cmdiShot{echoing(cmdiC0), func() cmdiShot {
				s := echoing(cmdiB1)
				s.marker = cmdiMarkOther
				return s
			}()},
			want: cmdiReasonForeignMarker,
			why:  "Own is meant to be filtered by stripe, so a foreign marker here is a runner bug and must be loud",
		},
		{
			name:  "the post-baseline did not resolve",
			env:   func() cmdiEnv { e := cmdiHealthyEnv(); e.postBase = false; return e },
			shots: []cmdiShot{echoing(cmdiC0), echoing(cmdiB1)},
			want:  cmdiReasonNoPostBase,
			why:   "a silence measured across an undetected drift is not a silence",
		},
		{
			name: "the endpoint failed its own stability gate",
			env: func() cmdiEnv {
				e := cmdiHealthyEnv()
				e.baseline = triage.BaselineModel{Samples: 5, Stable: false, GateReason: "too_volatile"}
				return e
			},
			shots: []cmdiShot{echoing(cmdiC0), echoing(cmdiB1)},
			want:  cmdiReasonDrift,
			why:   "an endpoint that varies more than any signal this class could see has not been measured by it",
		},
		{
			name: "the slot's value was fabricated rather than observed",
			env: func() cmdiEnv {
				e := cmdiHealthyEnv()
				e.slot.ValueOrigin = triage.ValueCanary
				return e
			},
			shots: []cmdiShot{echoing(cmdiC0), echoing(cmdiB1)},
			want:  cmdiReasonCanary,
			why:   "a scan aimed at a resource the application does not have is a scan of a 404",
		},
		{
			name:  "this class sent nothing at all at this slot",
			env:   cmdiHealthyEnv,
			shots: nil,
			want:  cmdiReasonNothing,
			why:   "a slot with no row reads as untouched, and a slot with a row saying nothing ran reads as what it is",
		},
		{
			name: "no probe echoed and no collaborator was configured",
			env:  cmdiHealthyEnv,
			shots: []cmdiShot{
				cmdiShotOf(t, cmdiC0, m, quiet), cmdiShotOf(t, cmdiB1, m, quiet),
			},
			want: cmdiReasonBlindNoOracle,
			why:  "no echo and no callback host means no oracle existed, so nothing was measured",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := cmdiVerdict(tc.env(), tc.shots)
			cmdiAssertNoneClean(t, v)
			if !strings.Contains(v[0].Reason, tc.want) {
				t.Errorf("reason %q does not name %q. %s", v[0].Reason, tc.want, tc.why)
			}
		})
	}
}

func TestAHealthySilentRunIsTheOnlyThingThatProducesAClean(t *testing.T) {
	m := cmdiMarkOne
	// Everything the clean preconditions ask for: delivered, wire-proven, substituted, the
	// endpoint stable, the post-baseline resolved, the slot's value observed, the census echoing
	// so the computation oracle was genuinely available, and not one rule firing.
	env := cmdiHealthyEnv()
	shots := cmdiFullSweep(t, env, m, func(id triage.ProbeID) string {
		return "you searched for " + cmdiRender(t, id, m, "widget")
	})
	v := cmdiVerdict(env, shots)
	if len(v) != 1 || v[0].State != triage.StateClean {
		t.Fatalf("state %q reason %q, want clean. A class that can never say clean is as useless as one that always does", v[0].State, v[0].Reason)
	}
	if err := v[0].Validate(); err != nil {
		t.Errorf("the clean verdict fails its own contract: %v", err)
	}
	if len(v[0].Ordinals) == 0 {
		t.Error("a clean with no probe ordinals asserts a measurement that never happened, and ClassVerdict.Validate is supposed to catch it")
	}
	if len(v[0].Untested) == 0 {
		t.Error("the clean names no unsent probe, but the timing family is always unsent and the operator has to be able to see it")
	}
	if v[0].Annotations["cmdi_blind_sink_note"] == nil {
		t.Error("the clean does not carry its own preconditions, which CATALOGUE 4.5 rule 2 requires of every class")
	}
}

func TestAPartialSweepIsNeverACleanEvenWhenEveryProbeThatRanWasSilent(t *testing.T) {
	m := cmdiMarkOne
	// The census reflected, so the computation oracle was genuinely available and every probe
	// that went out was quiet. Only three of them went out.
	shots := []cmdiShot{
		cmdiShotOf(t, cmdiC0, m, "you said "+cmdiRender(t, cmdiC0, m, "widget")),
		cmdiShotOf(t, cmdiB1, m, "you said "+cmdiRender(t, cmdiB1, m, "widget")),
		cmdiShotOf(t, cmdiNC1, m, "you said "+cmdiRender(t, cmdiNC1, m, "widget")),
	}
	v := cmdiVerdict(cmdiHealthyEnv(), shots)
	cmdiAssertNoneClean(t, v)
	if !strings.Contains(v[0].Reason, cmdiReasonFamilies) {
		t.Errorf("reason %q does not name families_not_sent. A silence from four of twenty families is a statement about four families", v[0].Reason)
	}
	for _, want := range []triage.ProbeID{cmdiB7, cmdiA1, cmdiW1} {
		if !strings.Contains(v[0].Reason, string(want)) {
			t.Errorf("the reason does not name %s among the families that were not sent, so an operator cannot see what is missing", want)
		}
	}
}

func TestACollaboratorThatWasConfiguredAndNeverProbedIsNotAClean(t *testing.T) {
	m := cmdiMarkOne
	env := cmdiHealthyEnv()
	env.oobMode = triage.OOBWildcardDNS
	const page = "<html>nothing</html>"
	env.route.body = []byte(page)
	// No reflection, so the only oracle available was the callback, and not one callback probe
	// was sent. There is nothing here that could have been measured.
	v := cmdiVerdict(env, []cmdiShot{cmdiShotOf(t, cmdiC0, m, page), cmdiShotOf(t, cmdiB1, m, page)})
	cmdiAssertNoneClean(t, v)
}

// ---------------------------------------------------------------------------------------------
// THE UNIFORM BLOCK AND ITS DELIBERATELY PARTIAL EARLY EXIT
// ---------------------------------------------------------------------------------------------

func TestAUniformBlockSplitsTheSlotAndNeverCollapsesIntoOneRow(t *testing.T) {
	m := cmdiMarkOne
	blocked := func(id triage.ProbeID) cmdiShot {
		s := cmdiShotOf(t, id, m, "<h1>403 Forbidden</h1>")
		s.obs.Status = 403
		s.obs.Proj.NormBodySHA256 = [32]byte{1, 2, 3}
		return s
	}
	env := cmdiHealthyEnv()
	shots := []cmdiShot{blocked(cmdiB1), blocked(cmdiB2), blocked(cmdiB3), blocked(cmdiA1)}
	_ = env.route.body
	if !cmdiUniformBlock(env, shots) {
		t.Fatal("three distinct payloads producing one byte-identical response that differs from the route control is a uniform block, and it was not detected")
	}
	v := cmdiVerdict(env, shots)
	cmdiAssertNoneClean(t, v)
	if len(v) != 2 {
		t.Fatalf("got %d rows, want 2: the metacharacter route and the argument-injection route are different mechanisms and a block on one says nothing about the other", len(v))
	}
	routes := map[string]triage.TriageState{}
	for _, row := range v {
		routes[row.Annotations[cmdiRouteKey].(string)] = row.State
	}
	if routes[cmdiRouteMetachar] != triage.StateCannotDetermine {
		t.Errorf("the metacharacter route is %q, want cannot_determine: a block is not a defence measurement", routes[cmdiRouteMetachar])
	}
	if _, ok := routes[cmdiRouteArgv]; !ok {
		t.Error("there is no argument-injection row, so the one deliberately partial early exit in this class has collapsed into a single blocked verdict")
	}
}

func TestAnEndpointThatSimplyMatchesTheRouteControlIsNotABlock(t *testing.T) {
	m := cmdiMarkOne
	env := cmdiHealthyEnv()
	same := func(id triage.ProbeID) cmdiShot {
		s := cmdiShotOf(t, id, m, "<html>widget</html>")
		s.obs.Proj.NormBodySHA256 = env.route.sha
		return s
	}
	if cmdiUniformBlock(env, []cmdiShot{same(cmdiB1), same(cmdiB2), same(cmdiB3)}) {
		t.Error("responses identical to the route control were read as a block, but identical-to-the-control is the opposite of a block and this would turn every well-behaved endpoint into cannot_determine")
	}
}

// ---------------------------------------------------------------------------------------------
// ARGUMENT INJECTION AND THE WINDOWS BATTERY
// ---------------------------------------------------------------------------------------------

func TestTheArgumentInjectionBannerRuleSubtractsTheRouteControl(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		route string
		want  bool
		why   string
	}{
		{
			name: "a tool banner the control does not carry",
			body: "Version: ImageMagick 7.1.1-21 Q16-HDRI x86_64",
			want: true,
			why:  "the value reached an argv array and the tool printed its own banner, which no separator probe would ever have found",
		},
		{
			name:  "FALSE POSITIVE: the application names its own toolchain on every page",
			body:  "<footer>Powered by ImageMagick 7.1.1</footer>",
			route: "<footer>Powered by ImageMagick 7.1.1</footer>",
			want:  false,
			why:   "the control carries the same phrase, so it is the application's prose and not our flag",
		},
		{
			name: "FALSE POSITIVE: a bare usage label from a web form",
			body: "Usage: type a product name and press enter",
			want: false,
			why:  "a bare Usage: is a form label as often as a tool's help block, so the rule wants a flag beside it",
		},
		{
			name: "a real usage block",
			body: "Usage: convert [options] input output\n  --help  show this",
			want: true,
			why:  "the flag beside the usage label is what makes it a tool's output",
		},
		{
			name: "FALSE POSITIVE: an ordinary page with the word version in it",
			body: "<h1>Release version 3 is out</h1>",
			want: false,
			why:  "a curated list of tool banners is the point; matching the word version would fire on half the web",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, got := cmdiToolBanner([]byte(tc.body), []byte(tc.route))
			if got != tc.want {
				t.Errorf("banner rule fired=%v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

func TestAnArgumentInjectionBannerIsCappedAtSuspiciousAndPointsAtCommix(t *testing.T) {
	m := cmdiMarkOne
	shots := []cmdiShot{
		cmdiShotOf(t, cmdiC0, m, "you said "+cmdiRender(t, cmdiC0, m, "widget")),
		cmdiShotOf(t, cmdiA1, m, "ImageMagick 7.1.1-21 Q16-HDRI"),
	}
	v := cmdiVerdict(cmdiHealthyEnv(), shots)
	if v[0].State != triage.StateSuspicious {
		t.Errorf("state %q, want suspicious: a curated banner is weaker evidence than a computation and must not be graded as a finding", v[0].State)
	}
	if len(v[0].Label.Tools) != 1 || v[0].Label.Tools[0] != "commix" {
		t.Errorf("label tools %v, want exactly commix: this class has one confirmer in the framework and must not default to a nearest-named tool", v[0].Label.Tools)
	}
}

func TestTheWindowsExpansionRuleFiresOnPathextAndStaysSilentOnProse(t *testing.T) {
	m := cmdiMarkOne
	cases := []struct {
		name string
		id   triage.ProbeID
		body string
		want bool
		why  string
	}{
		{"PATHEXT expanded right after our own marker", cmdiW3,
			"out: " + string(m) + "a.COM;.EXE;.BAT;.CMD", true,
			"only an interpreting cmd.exe emits that value, and the request never contained it"},
		{"a drive-lettered working directory right after our own marker", cmdiW5,
			"out: " + string(m) + "aC:\\inetpub\\wwwroot", true,
			"%CD% expands to a drive-lettered path, which nothing else in an HTTP response looks like"},
		{"FALSE POSITIVE: the page mentions .COM;.EXE somewhere else entirely", cmdiW3,
			"help text: PATHEXT is usually .COM;.EXE;.BAT. Your token is " + string(m) + "a", false,
			"the rule is anchored immediately after this probe's own marker, not anywhere in the body"},
		{"FALSE POSITIVE: the probe was merely reflected", cmdiW3,
			"you said " + cmdiRender(t, cmdiW3, m, "widget"), false,
			"a reflected %PATHEXT% is a literal percent sign and a word, not an expansion"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, got := cmdiWindowsExpansion(cmdiShotOf(t, tc.id, m, tc.body))
			if got != tc.want {
				t.Errorf("windows rule fired=%v, want %v. %s", got, tc.want, tc.why)
			}
		})
	}
}

func TestTheCaretProbeIsShippedSeparatelyFromTheOtherCmdExeForm(t *testing.T) {
	specs := cmdiSpecIndex()
	caret, ok := specs[cmdiW6]
	if !ok {
		t.Fatal("there is no cmd.exe caret probe, and no separator probe finds a keyword filter that a caret walks through")
	}
	if !bytes.Contains(caret.Logical, []byte("^")) {
		t.Error("the caret probe contains no caret")
	}
	if bytes.Equal(triage.NormaliseMarkers(caret.Logical), triage.NormaliseMarkers(specs[cmdiW1].Logical)) {
		t.Error("the caret probe is byte-equal to CMDI-W1, so a block on one could not be attributed to either")
	}
}

// ---------------------------------------------------------------------------------------------
// OUT OF BAND
// ---------------------------------------------------------------------------------------------

func TestADNSCallbackIsAFindingUnlessTheEgressControlResolvedToo(t *testing.T) {
	m, n := cmdiMarkOne, cmdiMarkTwo
	quiet := "<html>nothing</html>"
	o1 := cmdiShotOf(t, cmdiO1, m, quiet)
	nc5 := cmdiShotOf(t, cmdiNC5, n, quiet)

	env := cmdiHealthyEnv()
	env.oobMode = triage.OOBWildcardDNS
	env.callbacks = []triage.CallbackRec{{Marker: m, Protocol: "dns"}}
	v := cmdiVerdict(env, []cmdiShot{o1, nc5})
	if v[0].State != triage.StateFinding || v[0].Oracle != "oob" {
		t.Errorf("state %q oracle %q, want a finding from the oob oracle: a callback carrying our own marker is the only oracle a blind slot has", v[0].State, v[0].Oracle)
	}

	// Now the bare-label control resolves too. The target resolves every hostname it is handed,
	// so the callback is evidence about a link unfurler and not about a shell.
	env.callbacks = append(env.callbacks, triage.CallbackRec{Marker: n, Protocol: "dns"})
	v = cmdiVerdict(env, []cmdiShot{o1, nc5})
	cmdiAssertNoneClean(t, v)
	if !strings.Contains(v[0].Reason, cmdiReasonEgress) {
		t.Errorf("reason %q does not name egress_resolver, so an operator would file a report they have to withdraw", v[0].Reason)
	}
}

func TestACallbackThisClassCannotTieToItsOwnProbeIsAHitForNobody(t *testing.T) {
	env := cmdiHealthyEnv()
	env.oobMode = triage.OOBWildcardDNS
	env.callbacks = []triage.CallbackRec{{Marker: cmdiMarkTwo, Protocol: "dns"}}
	// The only probe sent carries a different marker, so nothing ties the callback to this class's
	// own traffic. It must not become a finding.
	env.route.body = []byte("<html>nothing</html>")
	v := cmdiVerdict(env, []cmdiShot{cmdiShotOf(t, cmdiC0, cmdiMarkOne, "<html>nothing</html>")})
	for _, row := range v {
		if row.State.Kind() == triage.StateKindPositive {
			t.Errorf("an unattributable callback produced %q, and a hit nobody can tie to a probe is a hit for nobody", row.State)
		}
	}
	cmdiAssertNoneClean(t, v)
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

func TestTheLadderSendsTheCensusAndTheWholeControlSetBeforeAnythingElse(t *testing.T) {
	env := cmdiHealthyEnv()
	got := map[triage.ProbeID]bool{}
	for _, r := range cmdiPlan(env, nil) {
		got[r.Spec] = true
	}
	for _, want := range []triage.ProbeID{cmdiC0, cmdiNC1, cmdiNC2, cmdiNC3, cmdiNC4, cmdiB1} {
		if !got[want] {
			t.Errorf("round 0 does not send %s. The control set goes out with the first probe or the detector is unverified for the whole slot", want)
		}
	}
	if got[cmdiW1] || got[cmdiO1] {
		t.Error("round 0 sent a Windows or an out-of-band probe, so the ladder is not a ladder")
	}
}

func TestTheLadderStopsTheSeparatorBatteryOnAHitButKeepsTheConfirmationRound(t *testing.T) {
	m := cmdiMarkOne
	hit := cmdiShotOf(t, cmdiB1, m, "hit "+string(m)+"a140004"+string(m)+"s")
	env := cmdiHealthyEnv()

	env.round = 1
	if reqs := cmdiPlan(env, []cmdiShot{hit}); len(reqs) != 0 {
		t.Errorf("the separator battery kept going after a confirmed computation hit, sending %d more requests for nothing", len(reqs))
	}
	env.round = 5
	got := map[triage.ProbeID]bool{}
	for _, r := range cmdiPlan(env, []cmdiShot{hit}) {
		got[r.Spec] = true
	}
	for _, want := range []triage.ProbeID{cmdiCF1, cmdiCF2, cmdiCF3} {
		if !got[want] {
			t.Errorf("the confirmation round did not send %s, so the hit can never be graded high", want)
		}
	}
}

func TestAUniformBlockStopsTheMetacharacterRoundsAndNotTheArgumentInjectionOne(t *testing.T) {
	m := cmdiMarkOne
	env := cmdiHealthyEnv()
	blocked := func(id triage.ProbeID) cmdiShot {
		s := cmdiShotOf(t, id, m, "403")
		s.obs.Status = 403
		s.obs.Proj.NormBodySHA256 = [32]byte{7}
		return s
	}
	shots := []cmdiShot{blocked(cmdiB1), blocked(cmdiB2), blocked(cmdiB3)}

	env.round = 1
	if reqs := cmdiPlan(env, shots); len(reqs) != 0 {
		t.Error("the separator battery kept going under a uniform block, which spends requests learning nothing")
	}
	env.round = 3
	if reqs := cmdiPlan(env, shots); len(reqs) == 0 {
		t.Error("the argument-injection family was cancelled by a uniform block, but it carries no metacharacter at all and the validator that rejected the others has not been shown to reject it")
	}
}

func TestTheTimingProbesAreDeclaredAndAreNeverPlanned(t *testing.T) {
	specs := cmdiSpecIndex()
	for _, id := range []triage.ProbeID{cmdiT0, cmdiT2, cmdiT5} {
		if _, ok := specs[id]; !ok {
			t.Errorf("%s is not declared, so the gap it represents is invisible in the cost model and in every Untested list", id)
		}
	}
	env := cmdiHealthyEnv()
	env.oobMode = triage.OOBWildcardDNS
	for round := 0; round < 8; round++ {
		env.round = round
		for _, r := range cmdiPlan(env, nil) {
			if r.Spec == cmdiT0 || r.Spec == cmdiT2 || r.Spec == cmdiT5 {
				t.Fatalf("round %d planned %s. Timing needs a run-wide one-slot-at-a-time token that PlanCtx does not expose, and N concurrent sleeps against N workers is a denial of service", round, r.Spec)
			}
		}
	}
	skips := cmdiUntestedFor(cmdiQuerySlot(), []cmdiShot{cmdiShotOf(t, cmdiC0, cmdiMarkOne, "x")})
	found := false
	for _, s := range skips {
		if s.ProbeID == cmdiT5 && strings.Contains(s.Reason, "timing") {
			found = true
		}
	}
	if !found {
		t.Error("the timing family is not named in the Untested list, so an operator cannot see that the blind oracle was never offered")
	}
}

func TestTheRawNewlineSeparatorIsOnlyEverAimedAtABodySlot(t *testing.T) {
	spec := cmdiSpecIndex()[cmdiB6]
	for _, k := range spec.Points {
		if k != triage.KindBody {
			t.Errorf("CMDI-B6 declares %s, but net/http refuses a CR or LF in a header value at send and a cookie cannot carry one", k)
		}
	}
	hdr := triage.Slot{Kind: triage.KindHeader, Key: "header:x-forwarded-for", Value: "1.2.3.4", ServerReachable: true}
	if why := cmdiUndeliverable(hdr, spec); why != "point_not_declared" && why != "header_crlf" {
		t.Errorf("the raw LF probe is considered deliverable to a header slot, reason %q", why)
	}
}

func TestADecodeDepthZeroCookieLosesTheSeparatorFamiliesByNameAndNotSilently(t *testing.T) {
	cookie := triage.Slot{
		Kind: triage.KindCookie, Key: "cookie:theme", Name: "theme", Value: "dark",
		ValueOrigin: triage.ValueObserved, ServerReachable: true,
		Constraints: triage.SlotConstraints{DecodeDepth: 0},
	}
	specs := cmdiSpecIndex()
	if why := cmdiUndeliverable(cookie, specs[cmdiB1]); why != "decode_depth_0" {
		t.Errorf("the semicolon family on a non-decoding cookie is %q, want decode_depth_0: a semicolon is not cookie-octet and pretending otherwise records clean on bytes that never arrived", why)
	}
	if why := cmdiUndeliverable(cookie, specs[cmdiB7]); why != "decode_depth_0" {
		t.Errorf("CMDI-B7 on a non-decoding cookie is %q, want decode_depth_0: it carries a space and a space is not cookie-octet", why)
	}
	for _, id := range []triage.ProbeID{cmdiB17, cmdiB18} {
		if why := cmdiUndeliverable(cookie, specs[id]); why != "" {
			t.Errorf("%s on a non-decoding cookie is %q, want deliverable: every byte of the whitespace-free substitution family is cookie-octet, and without it this whole surface would go untested", id, why)
		}
	}
	skips := cmdiUntestedFor(cookie, nil)
	named := map[triage.ProbeID]string{}
	for _, s := range skips {
		named[s.ProbeID] = s.Reason
	}
	if named[cmdiB1] == "" {
		t.Error("the semicolon family is missing from the Untested list, so its absence reads as a family that was sent and found nothing")
	}
}

// ---------------------------------------------------------------------------------------------
// THE DECLARATIONS
// ---------------------------------------------------------------------------------------------

func TestTheOracleCasesDeclareAtLeastOneFireRouteAndAtLeastOneSilentRoute(t *testing.T) {
	cases := (cmdiClassifier{}).OracleCases()
	pos, neg := 0, 0
	for _, c := range cases {
		switch c.Expect {
		case cmdiExpectPositive:
			pos++
		case cmdiExpectNegative:
			neg++
		default:
			t.Errorf("oracle case %q has expectation %q, which is neither positive nor negative", c.Name, c.Expect)
		}
		if c.Want == "" || len(c.Probes) == 0 {
			t.Errorf("oracle case %q does not say what it is for or which probes it exercises", c.Name)
		}
	}
	if pos == 0 {
		t.Error("no fire route: a detector never observed firing has not been shown to work")
	}
	if neg == 0 {
		t.Error("no silent route: a detector never observed staying silent scores the same as one that always says yes")
	}
	t.Logf("%d fire routes and %d silent routes declared, of which %d already exist", pos, neg, cmdiExistingRoutes(cases))
}

func cmdiExistingRoutes(cases []cmdiOracleCase) int {
	n := 0
	for _, c := range cases {
		if c.Exists {
			n++
		}
	}
	return n
}

func TestEveryConfirmerAndEveryEvidencerNamesADeclaredProbeOrARealOracle(t *testing.T) {
	specs := cmdiSpecIndex()
	for _, cf := range (cmdiClassifier{}).Confirmers() {
		if _, ok := specs[cf.Probe]; !ok {
			t.Errorf("confirmer names %s, which is not a declared probe and therefore can never be planned", cf.Probe)
		}
		if cf.Why == "" {
			t.Errorf("confirmer %s says nothing about why it reproduces anything", cf.Probe)
		}
	}
	oracles := map[string]bool{"computation": true, "oob": true, "banner": true, "none": true}
	for _, ev := range (cmdiClassifier{}).Evidencers() {
		if !oracles[ev.Oracle] {
			t.Errorf("evidencer names oracle %q, which this class does not have", ev.Oracle)
		}
		if ev.Extracts == "" {
			t.Errorf("evidencer for %s does not say what it stores, so the evidence is improvised at the call site", ev.Rule)
		}
	}
}

func TestSettleIsClassifyWithTheGraceWindowStampedOnIt(t *testing.T) {
	v := (cmdiClassifier{}).Settle(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: cmdiQuerySlot()}})
	if len(v) == 0 {
		t.Fatal("Settle returned no row, so a callback arriving after the grace window would have nowhere to land")
	}
	if v[0].Annotations["cmdi_settled_after_grace_window"] != true {
		t.Error("a settled verdict is indistinguishable from a first-pass one, so nobody can tell whether the out-of-band window was waited out")
	}
	cmdiAssertNoneClean(t, v)
}

func TestNoCMDISourceLineCarriesAnEmdash(t *testing.T) {
	// The repo forbids them and a payload carrying one would also be a byte nobody intended to
	// send. Checked over the declared payloads and the reasons this class emits.
	for _, p := range (cmdiClassifier{}).Probes() {
		if bytes.ContainsRune(p.Logical, '\u2014') || bytes.ContainsRune(p.Logical, '\u2013') {
			t.Errorf("%s carries a dash character that is not ASCII", p.ID)
		}
	}
}

// cmdiAssertNoneClean is the assertion this whole file is built around.
func cmdiAssertNoneClean(t *testing.T, vs []triage.ClassVerdict) {
	t.Helper()
	if len(vs) == 0 {
		t.Fatal("no verdict at all, so the slot reads as untouched and nothing in the report says this class did not run")
	}
	for _, v := range vs {
		if err := v.Validate(); err != nil {
			t.Errorf("verdict fails its own contract: %v", err)
		}
		if v.State.CountsAsClean() {
			t.Errorf("state clean with reason %q, but this path did not measure the slot and not knowing is never clean", v.Reason)
		}
	}
}
