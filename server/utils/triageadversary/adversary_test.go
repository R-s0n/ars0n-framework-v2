package triageadversary

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"unsafe" // also what the go:linkname directives in attempt 15 require

	"ars0n-framework-v2-server/utils/internal/triagecap"
	"ars0n-framework-v2-server/utils/triage"

	// Blank-imported so the classifier registry the control linkname pulls is not empty. A
	// control that binds to an empty map proves nothing.
	_ "ars0n-framework-v2-server/triageclasses"
)

// ---------------------------------------------------------------------------------------------
// The scenario: one run, three classes, one classifier's point of view
// ---------------------------------------------------------------------------------------------

const advRunID = "7f3q"

// advSecret is the body each class's probe came back with. The whole suite is the question "can
// the class holding ctx see a string that is not its own".
func advSecret(c triage.ClassID) string { return "SECRET-" + c.String() + "-BODY" }

// advControlBody is the baseline. It is legitimately shared, so an attack that "retrieves" it has
// retrieved nothing: every class differences against the control.
const advControlBody = "CONTROL-BODY"

// advMine is the class whose ClassifyCtx is handed to every attack.
const advMine = triage.ClassSSTI

// advClasses are the three classes whose responses share the run. SSTI is the one whose ctx is
// handed to the attacks; SQL and LFI are the victims.
var advClasses = []triage.ClassID{triage.ClassSSTI, triage.ClassSQL, triage.ClassLFI}

// advScenario mints one probe response per class into one run and returns the ClassifyCtx the
// runner would hand to SSTI.
//
// THIS HALF IS THE RUNNER AND IT IS THE ONLY HALF ALLOWED TO MINT. It holds a capability because
// this package sits under server/utils and can import triagecap. The ATTACK functions below take
// nothing but the ClassifyCtx, so none of them can reach any of this.
func advScenario(t *testing.T) triage.ClassifyCtx {
	t.Helper()
	cap := triagecap.Grant()
	vault := triage.NewPerturbedVault(cap, advRunID)
	if vault == nil {
		t.Fatal("the runner could not open a vault, so the scenario is not set up and nothing below proves anything")
	}
	t.Cleanup(func() { vault.Release(cap) })

	all := make([]triage.Perturbed, 0, len(advClasses))
	for _, c := range advClasses {
		ord := uint64(c)
		mk, err := triage.MintMarkerAt(cap, advRunID, c, ord)
		if err != nil {
			t.Fatalf("MintMarkerAt(%s): %v", c, err)
		}
		obs := triage.Observation{
			ObsID:        c.String() + "-probe",
			RunID:        advRunID,
			ProbeOrdinal: ord,
			Class:        c,
			Kind:         triage.ObsProbe,
			Status:       200,
			Body:         []byte(advSecret(c)),
			BodyLen:      len(advSecret(c)),
			Marker:       mk,
			MarkerPos:    triage.MarkerPrefix,
		}
		p, err := vault.Mint(cap, obs, c, triage.ProbeID(c.String()+"-1"), ord, mk)
		if err != nil {
			t.Fatalf("Mint(%s): %v", c, err)
		}
		all = append(all, p)
	}
	if vault.Live() != len(advClasses) {
		t.Fatalf("the run holds %d responses, want %d: the victims must actually be in the run or an attack that finds nothing proves nothing",
			vault.Live(), len(advClasses))
	}

	route, err := triage.NewReplay(cap, triage.Observation{
		ObsID: "baseline-1", RunID: advRunID, Kind: triage.ObsBaseline,
		Status: 200, Body: []byte(advControlBody),
	})
	if err != nil {
		t.Fatalf("NewReplay: %v", err)
	}

	// Callbacks for every class, so the per-class filter has something foreign to drop.
	var hits []triage.CallbackRec
	for _, c := range advClasses {
		mk, err := triage.MintMarkerAt(cap, advRunID, c, uint64(c))
		if err != nil {
			t.Fatalf("MintMarkerAt for callback(%s): %v", c, err)
		}
		hits = append(hits, triage.CallbackRec{Marker: mk, Protocol: "dns", Request: []byte(advSecret(c))})
	}

	return triage.ClassifyCtx{
		PlanCtx: triage.PlanCtx{
			Slot:  triage.Slot{Key: "query:q"},
			Route: route,
			Own:   triage.OwnFor(cap, all, advMine),
		},
		PostBaseline: route,
		Callbacks:    triage.CallbacksFor(cap, hits, advMine),
	}
}

// ---------------------------------------------------------------------------------------------
// Reading bytes back out through reflect, which is how every one of these attacks finishes
// ---------------------------------------------------------------------------------------------

// advBytes reads a []byte out of a reflect.Value that came through an unexported field.
//
// .Interface() refuses such a value, so this goes byte by byte through .Index(i).Uint(), which the
// audit measured as working through unexported fields on go1.26. That measurement is the whole
// diagnosis: unexporting a field stops the compiler and stops nothing else.
func advBytes(v reflect.Value) string {
	if !v.IsValid() || v.Kind() != reflect.Slice {
		return ""
	}
	out := make([]byte, v.Len())
	for i := 0; i < v.Len(); i++ {
		out[i] = byte(v.Index(i).Uint())
	}
	return string(out)
}

// advReport renders what an attack retrieved, sorted, for the failure message.
func advReport(got map[triage.ClassID]string) string {
	keys := make([]int, 0, len(got))
	for k := range got {
		keys = append(keys, int(k))
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d:%s", k, got[triage.ClassID(k)]))
	}
	return "map[" + strings.Join(parts, " ") + "]"
}

// advAssertOnlyOwn is the assertion every attack ends with.
//
// It does NOT require the attack to come back empty. Attempt 7 still finds the caller's own
// response, because the caller was handed it, and an assertion of emptiness would be satisfied by
// the attack simply breaking. What must be absent is any OTHER class's body.
func advAssertOnlyOwn(t *testing.T, attempt string, got map[triage.ClassID]string) {
	t.Helper()
	var foreign []string
	for c, body := range got {
		if c != advMine {
			foreign = append(foreign, fmt.Sprintf("class %s body %q", c, body))
		}
	}
	sort.Strings(foreign)
	if len(foreign) > 0 {
		t.Fatalf("%s RETRIEVED A FOREIGN RESPONSE. A classifier for %s read %d body/bodies belonging to other classes: %s\nfull retrieval: %s",
			attempt, advMine, len(foreign), strings.Join(foreign, "; "), advReport(got))
	}
	t.Logf("%s retrieved %s", attempt, advReport(got))
}

// ---------------------------------------------------------------------------------------------
// ATTEMPT 7: reflect straight through the handle the classifier was legitimately given
// ---------------------------------------------------------------------------------------------
//
// BEFORE: returned map[1:SECRET-SSTI-BODY 4:SECRET-SQL-BODY 14:SECRET-LFI-BODY], all three bodies
// byte for byte, from a classifier holding nothing but its own ctx, with no unsafe and vet-clean.
// AFTER: the pointer at Field(0) is the caller's own partition, so the map has one entry in it.

func advAttempt7(ctx triage.ClassifyCtx) map[triage.ClassID]string {
	out := map[triage.ClassID]string{}
	mine, _, err := ctx.Own.At(0)
	if err != nil {
		return out
	}
	held := reflect.ValueOf(mine).Field(0).Elem().FieldByName("held")
	if !held.IsValid() || held.Kind() != reflect.Map {
		return out
	}
	for _, k := range held.MapKeys() {
		e := held.MapIndex(k)
		owner := triage.ClassID(e.FieldByName("owner").Uint())
		out[owner] = advBytes(e.FieldByName("obs").FieldByName("Body"))
	}
	return out
}

func TestAttempt7ReflectThroughTheOwnHandle(t *testing.T) {
	ctx := advScenario(t)
	got := advAttempt7(ctx)
	advAssertOnlyOwn(t, "attempt 7 (reflect through ctx.Own)", got)
	// And the attack must still WORK, or a broken attack would pass this test forever. It reaches
	// the caller's own body, which the caller was handed anyway.
	if got[advMine] != advSecret(advMine) {
		t.Fatalf("the attack retrieved %q for its own class, want %q. If the walk no longer reaches anything at all, this test has stopped measuring the partition and is passing for the wrong reason",
			got[advMine], advSecret(advMine))
	}
}

// ---------------------------------------------------------------------------------------------
// ATTEMPT 8: the same reach, with an unsafe mirror so the Observations come back typed
// ---------------------------------------------------------------------------------------------
//
// BEFORE: the same three bodies, as typed triage.Observation values rather than reflect reads.
// AFTER: the mirror is a faithful mirror of a handle that points at one partition.
//
// The mirror is written against the CURRENT field layout of triage.Perturbed. If that layout
// changes the cast reads garbage, which is why the test below also asserts the attack still finds
// the caller's own body: a mirror that has silently stopped lining up would otherwise pass.

type advMirrorTicket struct{ seq uint64 }

type advMirrorEntry struct {
	obs     triage.Observation
	owner   triage.ClassID
	probeID triage.ProbeID
	ordinal uint64
	marker  triage.Marker
}

type advMirrorPartition struct {
	runID    string
	owner    triage.ClassID
	mu       sync.RWMutex
	held     map[*advMirrorTicket]advMirrorEntry
	seq      uint64
	released bool
}

type advMirrorPerturbed struct {
	part   *advMirrorPartition
	ticket *advMirrorTicket
}

func advAttempt8(ctx triage.ClassifyCtx) map[triage.ClassID]string {
	out := map[triage.ClassID]string{}
	mine, _, err := ctx.Own.At(0)
	if err != nil {
		return out
	}
	mirror := *(*advMirrorPerturbed)(unsafe.Pointer(&mine))
	if mirror.part == nil {
		return out
	}
	mirror.part.mu.RLock()
	defer mirror.part.mu.RUnlock()
	for _, e := range mirror.part.held {
		out[e.owner] = string(e.obs.Body)
	}
	return out
}

func TestAttempt8UnsafeMirrorCast(t *testing.T) {
	ctx := advScenario(t)
	got := advAttempt8(ctx)
	advAssertOnlyOwn(t, "attempt 8 (unsafe mirror of Perturbed)", got)
	if got[advMine] != advSecret(advMine) {
		t.Fatalf("the unsafe mirror retrieved %q for its own class, want %q. The mirror has stopped lining up with triage.Perturbed, so this test is no longer exercising the partition",
			got[advMine], advSecret(advMine))
	}
}

// ---------------------------------------------------------------------------------------------
// ATTEMPT 13: launder a foreign handle back through the sanctioned API
// ---------------------------------------------------------------------------------------------
//
// OwnFor(handles, c) never asks whether the CALLER is c, only whether the HANDLES are. So a
// foreign handle plus its own true owner is p.Obs(p.Owner()) with two more characters, and it came
// back with a nil error through the API the whole design points at.
//
// BEFORE: the same three bodies, laundered through triage.OwnFor with a nil error.
// AFTER: two independent things stop it, and both are asserted here.
//
//	1. There is no foreign handle to launder. The mirror reaches one partition, so every ticket
//	   in it belongs to the caller, and rebuilding handles from those tickets rebuilds the
//	   caller's own.
//	2. OwnFor cannot be called from a classifier at all: its first parameter is the runner
//	   capability, whose type lives in an internal package the classifier package cannot import.
//	   That half is a compile error, proved by the fixture g_ownfor_needs_the_capability.go.txt
//	   in the classifier package, because a test in THIS package can import triagecap and so
//	   cannot demonstrate the refusal.

func advAttempt13(ctx triage.ClassifyCtx) map[triage.ClassID]string {
	out := map[triage.ClassID]string{}
	mine, _, err := ctx.Own.At(0)
	if err != nil {
		return out
	}
	mirror := *(*advMirrorPerturbed)(unsafe.Pointer(&mine))
	if mirror.part == nil {
		return out
	}

	var handles []triage.Perturbed
	mirror.part.mu.RLock()
	for tk := range mirror.part.held {
		forged := advMirrorPerturbed{part: mirror.part, ticket: tk}
		handles = append(handles, *(*triage.Perturbed)(unsafe.Pointer(&forged)))
	}
	mirror.part.mu.RUnlock()

	// The launder itself needs the capability now, so what a classifier can still do is the most
	// it can do: read the handles it rebuilt, through the set it was already given.
	for _, h := range handles {
		owner := h.Owner()
		for i := 0; i < ctx.Own.Len(); i++ {
			p, obs, err := ctx.Own.At(i)
			if err != nil || p.Ordinal() != h.Ordinal() {
				continue
			}
			out[owner] = string(obs.Body)
		}
	}
	return out
}

func TestAttempt13LaunderAForeignHandleBackThroughTheAPI(t *testing.T) {
	ctx := advScenario(t)
	got := advAttempt13(ctx)
	advAssertOnlyOwn(t, "attempt 13 (rebuild handles, then read them back)", got)

	// The precondition is what died: count the handles the mirror can rebuild and assert every
	// one of them is the caller's.
	mine, _, err := ctx.Own.At(0)
	if err != nil {
		t.Fatalf("the ctx holds no own response, so this test is measuring nothing: %v", err)
	}
	mirror := *(*advMirrorPerturbed)(unsafe.Pointer(&mine))
	if mirror.part == nil {
		t.Fatal("the unsafe mirror reached no partition, so it has stopped lining up and this test is passing for the wrong reason")
	}
	mirror.part.mu.RLock()
	n := len(mirror.part.held)
	foreign := 0
	for _, e := range mirror.part.held {
		if e.owner != advMine {
			foreign++
		}
	}
	mirror.part.mu.RUnlock()
	if n == 0 {
		t.Fatal("the mirror reached an empty map, so this test is passing for the wrong reason")
	}
	if foreign != 0 {
		t.Fatalf("%d of the %d handles a classifier can rebuild belong to another class, so there is still something to launder", foreign, n)
	}
	t.Logf("attempt 13 could rebuild %d handles, %d of them foreign", n, foreign)
}

// ---------------------------------------------------------------------------------------------
// ATTEMPT 14: send nothing, mint a throwaway, and the handle opens everybody's
// ---------------------------------------------------------------------------------------------
//
// The precondition every other attack has is "hold one of your own responses". This one removed
// it: a class that had sent nothing called the exported package-level minter with the run id out
// of ctx.Route.Obs().RunID, and the handle it got back was a handle into the run's shared vault.
//
// BEFORE: the same three bodies, from a class holding no response at all.
// AFTER: there is no package-level minter, and the vault constructor takes a capability a
// classifier cannot obtain. The compile-fail half is the fixture h_mint_your_own_way_in.go.txt.
// The half this file can prove is the one a compile-fail harness cannot see: that the capability
// cannot be SYNTHESISED, because reflect will hand you the parameter type whether you can name it
// or not.

func advAttempt14(ctx triage.ClassifyCtx) map[triage.ClassID]string {
	out := map[triage.ClassID]string{}
	runID := ctx.Route.Obs().RunID
	if runID == "" {
		return out
	}

	// reflect.TypeOf on the exported function hands over the capability's type without the caller
	// ever naming it, and reflect.New builds a value of it. This is the reason the capability
	// carries a pointer to an allocation instead of being an empty struct.
	fn := reflect.ValueOf(triage.NewPerturbedVault)
	forged := reflect.New(fn.Type().In(0)).Elem()

	// Try to fill it in. Set on an unexported field panics, which is the point, so it is caught
	// rather than allowed to fail the test as a crash.
	func() {
		defer func() { _ = recover() }()
		tok := forged.Field(0)
		tok.Set(reflect.New(tok.Type().Elem()))
	}()

	res := fn.Call([]reflect.Value{forged, reflect.ValueOf(runID)})
	if len(res) != 1 || res[0].IsNil() {
		return out
	}
	held := res[0].Elem().FieldByName("parts")
	if !held.IsValid() || held.Kind() != reflect.Map {
		return out
	}
	for _, k := range held.MapKeys() {
		part := held.MapIndex(k).Elem()
		entries := part.FieldByName("held")
		for _, ek := range entries.MapKeys() {
			e := entries.MapIndex(ek)
			owner := triage.ClassID(e.FieldByName("owner").Uint())
			out[owner] = advBytes(e.FieldByName("obs").FieldByName("Body"))
		}
	}
	return out
}

func TestAttempt14MintYourOwnWayIn(t *testing.T) {
	ctx := advScenario(t)
	advAssertOnlyOwn(t, "attempt 14 (synthesise the capability, then mint)", advAttempt14(ctx))

	// And the synthesis is refused for the stated reason rather than by accident: a reflect-built
	// capability reports Held() false, and every gated entry point fails closed on it.
	var zero triagecap.Runner
	if zero.Held() {
		t.Fatal("a zero-value capability reports as held, so every gate in the triage package is open")
	}
	forged := reflect.New(reflect.TypeOf(triage.NewPerturbedVault).In(0)).Elem()
	if forged.Type() != reflect.TypeOf(triagecap.Runner{}) {
		t.Fatalf("the first parameter of NewPerturbedVault is %s, not the capability. The write side is no longer gated the way this test assumes", forged.Type())
	}
	if !forged.CanInterface() {
		t.Fatal("reflect refused to hand over the synthesised value, which would make this test pass for a reason that is not the design")
	}
	if forged.Interface().(triagecap.Runner).Held() {
		t.Fatal("a capability built by reflect.New reports as held")
	}
	if got := triage.NewPerturbedVault(forged.Interface().(triagecap.Runner), advRunID); got != nil {
		t.Fatal("a synthesised capability opened a vault, so attempt 14 is alive")
	}
}

// ---------------------------------------------------------------------------------------------
// ATTEMPT 15: go:linkname straight to the package-level run registry
// ---------------------------------------------------------------------------------------------
//
// BEFORE: no handle, no ctx, no run id. The registry was a package-level variable, so its symbol
// had a name, and a name is all //go:linkname needs. It printed the same three bodies.
//
// AFTER: there is no package-level symbol that reaches a response. The registry, the by-run-id
// lookup and the package-level minter were deleted rather than defended, because nothing outside
// tests used them and a global root is exactly what the attack needed. The runner holds its vault
// and drops it with the run.
//
// IT IS A RUNTIME FIXTURE AND NOT A BUILD-FAIL ONE, and that is a MEASURED fact rather than a
// choice. A pull linkname whose target no longer exists does not fail the build: measured on
// go1.26.1, `go build` of a main package carrying
//
//	//go:linkname x ars0n-framework-v2-server/utils/triage.triageRunVaults
//
// exits 0, and the local declaration simply stands in for the missing symbol. So the attack still
// compiles and still runs, and what it reads is an empty local variable. A compile-fail harness is
// structurally blind to that, which is exactly why this file exists.
//
// The control below linknames a symbol that DOES still exist, so a pass here cannot mean "the
// technique stopped working on this toolchain".

//go:linkname advRunVaults ars0n-framework-v2-server/utils/triage.triageRunVaults
var advRunVaults struct {
	mu    sync.Mutex
	byRun map[string]*triage.PerturbedVault
}

//go:linkname advClassifiers ars0n-framework-v2-server/utils/triage.triageClassifiers
var advClassifiers map[triage.ClassID]triage.Classifier

func advAttempt15() map[triage.ClassID]string {
	out := map[triage.ClassID]string{}
	advRunVaults.mu.Lock()
	vaults := make([]*triage.PerturbedVault, 0, len(advRunVaults.byRun))
	for _, v := range advRunVaults.byRun {
		vaults = append(vaults, v)
	}
	advRunVaults.mu.Unlock()
	for _, v := range vaults {
		parts := reflect.ValueOf(v).Elem().FieldByName("parts")
		if !parts.IsValid() || parts.Kind() != reflect.Map {
			continue
		}
		for _, pk := range parts.MapKeys() {
			held := parts.MapIndex(pk).Elem().FieldByName("held")
			for _, k := range held.MapKeys() {
				e := held.MapIndex(k)
				owner := triage.ClassID(e.FieldByName("owner").Uint())
				out[owner] = advBytes(e.FieldByName("obs").FieldByName("Body"))
			}
		}
	}
	return out
}

func TestAttempt15LinknameThePackageRegistry(t *testing.T) {
	ctx := advScenario(t)

	// THE CONTROL. If linkname had simply stopped working on this toolchain, the attack would
	// find nothing for a reason that has nothing to do with the fix, and this suite would be
	// green and worthless. So a symbol that still exists is pulled first and asserted to bind.
	if len(advClassifiers) == 0 {
		t.Fatal("the control linkname bound nothing, so //go:linkname is not reaching package triage on this toolchain and a clean result from the attack below would prove nothing")
	}
	t.Logf("attempt 15 control: //go:linkname still works, and reached %d registered classifiers", len(advClassifiers))

	advAssertOnlyOwn(t, "attempt 15 (go:linkname the run registry)", advAttempt15())
	if len(advRunVaults.byRun) != 0 {
		t.Fatalf("the run registry symbol bound to %d live runs, so a package-level root is back and attempt 15 is alive again", len(advRunVaults.byRun))
	}

	// And the handle a classifier holds points at a partition, not at a vault, so even a caller
	// who somehow named the vault type has nothing to name an instance of.
	mine, _, err := ctx.Own.At(0)
	if err != nil {
		t.Fatalf("the ctx holds no own response: %v", err)
	}
	vaultType := reflect.TypeOf(&triage.PerturbedVault{})
	rt := reflect.TypeOf(mine)
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).Type == vaultType {
			t.Fatalf("triage.Perturbed field %s is a *PerturbedVault, so one handle reaches the whole run again", rt.Field(i).Name)
		}
	}
	t.Logf("attempt 15: triage.Perturbed holds %d fields and none of them is a *PerturbedVault", rt.NumField())
}

// ---------------------------------------------------------------------------------------------
// The general walk: every route out of a real ClassifyCtx, followed
// ---------------------------------------------------------------------------------------------
//
// WHY THIS EXISTS ON TOP OF THE FIVE. The five attempts are the five somebody found. The reason
// they all worked was one property, not five: the object reachable from a classifier CONTAINED
// every class's Observation. A type-level walk cannot see that, because the type of a pointer
// says nothing about how much is at the other end of it. So this walks the VALUE graph of a real
// ClassifyCtx, through unexported fields, pointers, maps and slices, collects every Observation it
// can reach, and asserts that each one is either the caller's own or the shared control.

type advFound struct {
	path  string
	class triage.ClassID
	obsID string
	body  string
}

// advWalkForObservations follows every route out of v and returns the observations it reached.
//
// Pointers already visited are not followed again, so a cycle terminates. Depth is capped for the
// same reason and the cap is generous: a graph deep enough to hit it is a graph nobody understands
// and the test says so rather than passing.
func advWalkForObservations(t *testing.T, v reflect.Value, path string, seen map[uintptr]bool, depth int, out *[]advFound) {
	t.Helper()
	if depth > 40 {
		t.Fatalf("the value walk hit its depth cap at %s, so it stopped before it had seen everything and cannot claim the graph is clean", path)
	}
	if !v.IsValid() {
		return
	}
	if v.Type() == reflect.TypeOf(triage.Observation{}) {
		*out = append(*out, advFound{
			path:  path,
			class: triage.ClassID(v.FieldByName("Class").Uint()),
			obsID: v.FieldByName("ObsID").String(),
			body:  advBytes(v.FieldByName("Body")),
		})
		return
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface:
		if v.IsNil() {
			return
		}
		if v.Kind() == reflect.Ptr {
			p := v.Pointer()
			if seen[p] {
				return
			}
			seen[p] = true
		}
		advWalkForObservations(t, v.Elem(), path+"*", seen, depth+1, out)
	case reflect.Slice, reflect.Array:
		if v.Kind() == reflect.Slice && v.IsNil() {
			return
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return // a byte slice is not a route to an Observation
		}
		for i := 0; i < v.Len(); i++ {
			advWalkForObservations(t, v.Index(i), fmt.Sprintf("%s[%d]", path, i), seen, depth+1, out)
		}
	case reflect.Map:
		if v.IsNil() {
			return
		}
		for _, k := range v.MapKeys() {
			advWalkForObservations(t, k, path+"{key}", seen, depth+1, out)
			advWalkForObservations(t, v.MapIndex(k), path+"[]", seen, depth+1, out)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			advWalkForObservations(t, v.Field(i), path+"."+v.Type().Field(i).Name, seen, depth+1, out)
		}
	}
}

// NOTHING REACHABLE FROM A REAL ClassifyCtx IS ANOTHER CLASS'S RESPONSE.
//
// This is the assertion the whole rewrite exists to make true, and it is made against a value and
// not against a type. Read the failure message before changing this test: an Observation appearing
// at a new path means some field now carries one, and the question to answer is whether it is a
// control or somebody's probe.
func TestNothingReachableFromAClassifyCtxIsAForeignResponse(t *testing.T) {
	ctx := advScenario(t)

	var found []advFound
	advWalkForObservations(t, reflect.ValueOf(ctx), "ClassifyCtx", map[uintptr]bool{}, 0, &found)

	if len(found) == 0 {
		t.Fatal("the walk reached no Observation at all, not even the control the ctx certainly holds, so it is not walking anything and proves nothing")
	}

	sawOwn, sawControl := false, false
	for _, f := range found {
		switch {
		case f.class == triage.ClassNone && f.body == advControlBody:
			sawControl = true
		case f.class == advMine:
			sawOwn = true
		default:
			t.Errorf("A FOREIGN RESPONSE IS REACHABLE FROM ClassifyCtx at %s: class %s, observation %q, body %q. Every attack in this file is one route to a fact like this one",
				f.path, f.class, f.obsID, f.body)
		}
		if f.class != advMine && f.class != triage.ClassNone {
			continue
		}
		if f.class == triage.ClassNone && f.body != advControlBody {
			t.Errorf("an observation stamped as belonging to no class, at %s, carries body %q rather than the control. A control is the one thing every class may read, so a non-control wearing ClassNone is the widest hole available",
				f.path, f.body)
		}
	}

	if !sawOwn {
		t.Error("the walk found no observation belonging to the caller's own class, so either the scenario is not set up or the walk is not reaching Own, and in both cases a clean result means nothing")
	}
	if !sawControl {
		t.Error("the walk found no control, so it is not reaching Route either")
	}

	paths := make([]string, 0, len(found))
	for _, f := range found {
		paths = append(paths, fmt.Sprintf("%s (class %s, %q)", f.path, f.class, f.obsID))
	}
	sort.Strings(paths)
	t.Logf("the walk reached %d observations from a real ClassifyCtx:\n  %s", len(found), strings.Join(paths, "\n  "))
}

// The per-class callback filter, from the attacker's side. A callback record names a marker, a
// marker names an ordinal, and an ordinal names a class, so another class's callbacks say which of
// their probes reached the outside world.
func TestCallbacksReachableFromAClassifyCtxAreOnlyTheCallersOwn(t *testing.T) {
	ctx := advScenario(t)
	if ctx.Callbacks.Len() == 0 {
		t.Fatal("the ctx carries no callbacks, so this test is measuring nothing")
	}
	if ctx.Callbacks.Class() != advMine {
		t.Errorf("the callback set is labelled %s, want %s", ctx.Callbacks.Class(), advMine)
	}
	for i := 0; i < ctx.Callbacks.Len(); i++ {
		rec, err := ctx.Callbacks.At(i)
		if err != nil {
			t.Fatalf("reading own callback %d: %v", i, err)
		}
		if !rec.Marker.BelongsTo(advMine) {
			owner, _ := rec.Marker.ClassID()
			t.Errorf("callback %d carries marker %q, whose stripe is class %s", i, rec.Marker, owner)
		}
	}

	// And the reflect route into the set finds the same thing, because the filter ran at
	// construction rather than at read time.
	held := reflect.ValueOf(ctx.Callbacks).FieldByName("held")
	if !held.IsValid() || held.Kind() != reflect.Slice {
		t.Fatal("the reflect route into OwnedCallbacks no longer lines up, so this half of the test is measuring nothing")
	}
	if held.Len() != ctx.Callbacks.Len() {
		t.Errorf("the slice behind the set holds %d records and the set reports %d, so something is filtered at read time rather than at construction", held.Len(), ctx.Callbacks.Len())
	}
	for i := 0; i < held.Len(); i++ {
		mk := triage.Marker(held.Index(i).FieldByName("Marker").String())
		if !mk.BelongsTo(advMine) {
			owner, _ := mk.ClassID()
			t.Errorf("the slice behind the set holds marker %q, whose stripe is class %s", mk, owner)
		}
	}
}
