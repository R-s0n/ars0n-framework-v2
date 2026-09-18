package triage

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"ars0n-framework-v2-server/utils/internal/triagecap"
)

// testCap is the runner capability the tests mint with.
//
// THE TESTS LIVE IN PACKAGE triage, WHICH IS UNDER server/utils, SO THEY CAN HAVE ONE. That is the
// whole shape of the defence and it is worth saying out loud here: the capability's type lives in
// server/utils/internal/triagecap, Go's internal rule makes it importable by everything rooted at
// server/utils and by nothing else, and the classifiers were moved to server/triageclasses so
// that they fall outside. A test that can mint is not a hole; a classifier that can mint is.
var testCap = triagecap.Grant()

// ---------------------------------------------------------------------------------------------
// The vault: the isolation law as a shape rather than as a check
// ---------------------------------------------------------------------------------------------

// Leak (a), the direct field read, is closed at COMPILE TIME, and this is its runtime witness.
//
// The previous Perturbed held the Observation in an unexported field, so
// func leak(p Perturbed) Observation { return p.obs } compiled and returned another class's whole
// response with no check of any kind in the way. It does not compile now, because there is no
// field to read: Perturbed is a vault pointer and a ticket. A test cannot assert that something
// fails to compile, so it asserts the property that makes it fail: no field of Perturbed is, or
// contains, an Observation.
func TestPerturbedHoldsNoObservation(t *testing.T) {
	rt := reflect.TypeOf(Perturbed{})
	if rt.NumField() != 2 {
		t.Errorf("Perturbed has %d fields, want 2 (a vault and a ticket). Every extra field is a candidate for the direct read that leak (a) used", rt.NumField())
	}
	obs := reflect.TypeOf(Observation{})
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if f.Type == obs || f.Type == reflect.PointerTo(obs) {
			t.Errorf("Perturbed field %s is an Observation, so p.%s returns another class's whole response with no ownership check", f.Name, f.Name)
		}
	}

	// And the walker agrees: nothing reachable from a Perturbed VALUE is an observation without
	// going through the vault, which is a pointer the walker stops at because Perturbed is a
	// sanctioned holder. Walking the vault type itself is the honest check.
	if n := reflect.TypeOf(PerturbedVault{}).NumField(); n == 0 {
		t.Fatal("PerturbedVault has no fields, so it is not holding anything and the vault is not real")
	}
}

// Leak (b), the forged literal, fails closed at RUNTIME in the one form that still compiles.
//
// The literal the reviewer wrote, Perturbed{obs: other.obs, owner: ClassSQL, ordinal: 4, ok:
// true}, no longer compiles: there are no such fields. What a forger inside this package can
// still write is a literal carrying a ticket, either invented or stolen from another class's
// value, and both of those have to fail.
func TestAForgedPerturbedLiteralFailsClosed(t *testing.T) {
	v := NewPerturbedVault(testCap, "run-forge")
	defer v.Release(testCap)

	victim, err := v.Mint(testCap, Observation{ObsID: "ssti-secret", Kind: ObsProbe, Class: ClassSSTI},
		ClassSSTI, "SSTI-1", 1+ClassStripeModulus, "")
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// A ticket the partition never minted. It is a different allocation, therefore a different map
	// key, therefore not in the map.
	invented := Perturbed{part: v.parts[ClassSSTI], ticket: &perturbedTicket{seq: 1}}
	if _, err := v.ObsOf(testCap, invented); !errors.Is(err, ErrUnmintedPerturbed) {
		t.Errorf("a Perturbed carrying an invented ticket returned err = %v, want ErrUnmintedPerturbed", err)
	}
	if invented.Minted() {
		t.Error("an invented ticket reported as minted")
	}

	// A ticket stolen from another class's value, with the forger naming itself the owner. This
	// is the exact shape of leak (b), rewritten for the new struct. The owner is read from the
	// VAULT ENTRY, so the forgery changes nothing.
	stolen := Perturbed{part: victim.part, ticket: victim.ticket}
	_, got, err := (OwnedResponses{class: ClassSQL, held: []Perturbed{stolen}}).At(0)
	if !errors.Is(err, ErrForeignObservation) {
		t.Errorf("class SQL read class SSTI's response through a forged literal, err = %v", err)
	}
	if got.ObsID != "" {
		t.Errorf("the forged read returned observation %q alongside the error", got.ObsID)
	}
	if stolen.Owner() != ClassSSTI {
		t.Errorf("the forged value reports owner %s; the owner must come from the vault entry, which says SSTI", stolen.Owner())
	}

	// And it never reaches SQL's Own set in the first place, because OwnFor reads the same
	// authoritative owner. A value that lands in the wrong slice is a value somebody counts.
	if own := OwnFor(testCap, []Perturbed{stolen, invented}, ClassSQL); own.Len() != 0 {
		t.Errorf("OwnFor handed class SQL %d forged responses", own.Len())
	}
	if own := OwnFor(testCap, []Perturbed{stolen}, ClassSSTI); own.Len() != 1 {
		t.Errorf("OwnFor did not hand the real owner its own response back, got %d", own.Len())
	}

	// ClassNone is nobody's class, so it collects nothing. Otherwise every unminted value, which
	// reports ClassNone, would be handed to whoever asked for it.
	if own := OwnFor(testCap, []Perturbed{stolen, invented, {}}, ClassNone); own.Len() != 0 {
		t.Errorf("OwnFor(ClassNone) collected %d values, including the unminted ones", own.Len())
	}

	// The zero value is not a measured response.
	if _, err := v.ObsOf(testCap, Perturbed{}); !errors.Is(err, ErrUnmintedPerturbed) {
		t.Errorf("a zero-value Perturbed returned err = %v, want ErrUnmintedPerturbed", err)
	}

	// Nor is the runner's own read a way around ownership. ObsOf resolves the ticket in THIS
	// vault's map, so a handle another vault minted is not there, and holding one vault is never
	// holding another run's responses.
	other := NewPerturbedVault(testCap, "run-forge-other")
	defer other.Release(testCap)
	if _, err := other.ObsOf(testCap, victim); !errors.Is(err, ErrUnmintedPerturbed) {
		t.Errorf("a vault handed back a response another vault minted, err = %v", err)
	}
}

// Leak (c), laundering, is refused by NewReplay whatever the stamps say.
//
// The launder takes a real probe response, sets Kind to ObsBaseline, Class to ClassNone and
// ProbeOrdinal to 0, and hands it to NewReplay. The old check read exactly those three fields and
// nothing else, so the re-stamp was the whole attack: a response produced by one class's SQL
// payload became the shared control every class differences against.
func TestNewReplayRefusesALaunderedProbe(t *testing.T) {
	probe := Observation{
		ObsID: "sql-probe-68", Kind: ObsProbe, Class: ClassSQL, ProbeOrdinal: 68,
		Status: 500, Body: []byte("org.postgresql.util.PSQLException"),
		Payload: PayloadWire{
			Logical: []byte("1' OR 1=1--"), Wire: []byte("1%27%20OR%201%3D1--"),
			ContainerName: "query", Survived: WireSurvivalEncoded,
		},
		Marker: testMarker(t, "7f3q", 68), MarkerPos: MarkerPrefix,
	}

	// The launder, verbatim.
	laundered := probe
	laundered.Kind = ObsBaseline
	laundered.Class = ClassNone
	laundered.ProbeOrdinal = 0

	if _, err := NewReplay(testCap, laundered); err == nil {
		t.Fatal("a re-stamped SQL probe became a shared control, which hands one class's payload response to every class")
	} else if !strings.Contains(err.Error(), "payload") {
		t.Errorf("the refusal %q does not name the payload, so nobody reading it will know why the stamps were not believed", err)
	}

	// The marker alone is enough, with no payload record at all. Only a probe carries a marker,
	// so a marker on something stamped as a baseline means one of the two is a lie.
	markerOnly := Observation{ObsID: "b", Kind: ObsBaseline, Marker: testMarker(t, "7f3q", 68)}
	if _, err := NewReplay(testCap, markerOnly); err == nil {
		t.Error("an observation stamped as a baseline but carrying a probe marker became a shared control")
	}
	posOnly := Observation{ObsID: "b", Kind: ObsBaseline, MarkerPos: MarkerSuffix}
	if _, err := NewReplay(testCap, posOnly); err == nil {
		t.Error("an observation stamped as a baseline but carrying a marker position became a shared control")
	}

	// Every individual field of the payload record is enough on its own. A DROPPED payload is the
	// dangerous one: its bytes are not on the wire, so a check that only looked at Wire would
	// wave it through, and the response is still a response to somebody's probe.
	for name, p := range map[string]PayloadWire{
		"logical only":   {Logical: []byte("x")},
		"wire only":      {Wire: []byte("x")},
		"container only": {Container: []byte("Cookie: a=x")},
		"name only":      {ContainerName: "Cookie"},
		"chain only":     {EncoderChain: []EncoderMode{EncodeCookie}},
		"version only":   {EncoderVersion: "v3"},
		"dropped":        {Survived: WireSurvivalDropped},
		"altered by":     {AlteredBy: "net/http.Cookie sanitizer"},
	} {
		if _, err := NewReplay(testCap, Observation{Kind: ObsBaseline, Payload: p}); err == nil {
			t.Errorf("%s: an observation carrying a payload record became a shared control", name)
		}
		if !p.Present() {
			t.Errorf("%s: PayloadWire.Present() said no payload was recorded", name)
		}
	}
	if (PayloadWire{}).Present() {
		t.Error("an empty payload record read as present, which would refuse every genuine control")
	}

	// A genuine baseline still works, or there are no controls at all.
	r, err := NewReplay(testCap, Observation{ObsID: "b1", Kind: ObsBaseline, Status: 200, Body: []byte("hi")})
	if err != nil {
		t.Fatalf("NewReplay rejected a genuine baseline: %v", err)
	}
	if !r.Resolved() || r.Obs().ObsID != "b1" {
		t.Error("a genuine baseline did not come back resolved")
	}

	// A marker found IN THE RESPONSE is not a refusal reason. On a stored-payload application a
	// genuine baseline echoes back markers from earlier runs, and refusing those would make the
	// control unobtainable exactly where controls matter most.
	echoed := Observation{ObsID: "b2", Kind: ObsBaseline,
		Proj: Projections{MarkerHits: []MarkerHit{{Marker: testMarker(t, "7f3q", 68), Form: "raw"}}}}
	if _, err := NewReplay(testCap, echoed); err != nil {
		t.Errorf("a baseline that echoed an earlier run's marker was refused: %v", err)
	}
}

// The vault has a lifetime, because a package-level map of Observations is a leak with a tidy
// name. A run holds a few hundred kilobytes of response body per probe.
func TestReleasingARunFreesItsResponsesAndFailsClosed(t *testing.T) {
	v := NewPerturbedVault(testCap, "run-lifecycle")
	var held []Perturbed
	for i := 0; i < 8; i++ {
		ord := uint64(i)*ClassStripeModulus + uint64(ClassSQL)
		p, err := v.Mint(testCap, Observation{ObsID: "o" + strconv.Itoa(i), Kind: ObsProbe, Class: ClassSQL},
			ClassSQL, ProbeID("SQL-"+strconv.Itoa(i)), ord, testMarker(t, "7f3q", ord))
		if err != nil {
			t.Fatalf("Mint %d: %v", i, err)
		}
		held = append(held, p)
	}
	if v.Live() != 8 {
		t.Fatalf("vault holds %d responses, want 8", v.Live())
	}

	if n := v.Release(testCap); n != 8 {
		t.Errorf("Release dropped %d responses, want 8", n)
	}
	if v.Live() != 0 {
		t.Errorf("the vault still holds %d responses after release, so a run's bodies outlive the run", v.Live())
	}
	if n := v.Release(testCap); n != 0 {
		t.Errorf("a second Release dropped %d, want 0: release must be idempotent", n)
	}

	// A handle that outlived its run fails closed. It does NOT come back as an empty observation,
	// because an empty observation is a response a classifier can score, and scoring one that was
	// never measured is the whole failure this layer exists to stop.
	for _, p := range held {
		if _, err := ownRead(p, ClassSQL); !errors.Is(err, ErrRunReleased) {
			t.Fatalf("a handle into a released run returned err = %v, want ErrRunReleased", err)
		}
		if p.Minted() {
			t.Fatal("a handle into a released run reported as minted")
		}
	}
	// Minting into a released vault is refused rather than silently reopening it.
	if _, err := v.Mint(testCap, Observation{Kind: ObsProbe}, ClassSQL, "SQL-X", ClassStripeModulus+uint64(ClassSQL), ""); !errors.Is(err, ErrRunReleased) {
		t.Errorf("minting into a released vault returned err = %v, want ErrRunReleased", err)
	}
}

// THERE IS NO PACKAGE-LEVEL ROOT, AND THAT IS WHAT ENDED ATTEMPT 15.
//
// This test used to be TestTheRunRegistryIsScopedAndReleasable and it asserted that the registry
// behind the package-level NewPerturbed opened a vault per run and dropped it on release. All of
// that was true. It was also the whole attack surface for //go:linkname, which needs one thing and
// one thing only: a package-level symbol. The audit wrote
//
//	//go:linkname x ars0n-framework-v2-server/utils/triage.triageRunVaults
//
// into a file that imported nothing but triage and unsafe, and printed every class's response body
// with no handle, no ctx and no run id. Nothing outside tests called NewPerturbed, so the registry
// was deleted rather than defended: the runner holds its vault from NewPerturbedVault and ends it
// with Release, and a run's responses are reachable only from a value somebody is holding.
//
// So the assertion is inverted. This walks the package's own declarations and fails if any
// package-level variable can reach a vault, a partition or an Observation, because the day one
// comes back is the day the linkname attack comes back with it.
func TestNoPackageLevelVariableHoldsResponses(t *testing.T) {
	dir := packageDir(t)
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) < 2 {
		t.Fatalf("found %d source files, so this test is checking nothing", len(paths))
	}

	fset := token.NewFileSet()
	checked := 0
	found := 0
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", p, err)
		}
		checked++
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range vs.Names {
					found++
					typeText := varTypeText(t, fset, vs)
					for _, needle := range packageLevelResponseNeedles() {
						if strings.Contains(typeText, needle) {
							t.Errorf("%s declares package-level var %s, whose type is %q and mentions %q. A package-level symbol is all //go:linkname needs, and a package-level symbol that can reach a response is how the audit read every class's body with no handle, no ctx and no run id",
								filepath.Base(p), name.Name, typeText, needle)
						}
					}
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("parsed zero non-test files, so this test is checking nothing")
	}
	t.Logf("walked %d package-level var declarations across %d files of package triage", found, checked)

	// THE GUARD IS TESTED BEFORE IT IS TRUSTED, against the declaration that used to be here and
	// against three other shapes of the same mistake. A guard whose pattern has never matched
	// anything is a guard nobody has checked, and this one has to fire on the real registry, on
	// the obvious rewrites of it, and on nothing legitimate.
	for _, src := range []string{
		"package triage\nvar triageRunVaults = struct {\n\tmu    sync.Mutex\n\tbyRun map[string]*PerturbedVault\n}{byRun: make(map[string]*PerturbedVault, 4)}",
		"package triage\nvar cache map[string]Observation",
		"package triage\nvar lastRun = NewPerturbedVault(cap, \"7f3q\")",
		"package triage\nvar seen = map[*classPartition]bool{}",
	} {
		if !declaresAResponseHolder(t, src) {
			t.Errorf("the needles do not fire on:\n%s\nso the guard would not notice this coming back", src)
		}
	}
	// And it fires on nothing legitimate, or the next person deletes it. Every one of these is a
	// real declaration in this package today.
	for _, src := range []string{
		"package triage\nvar ErrForeignObservation = errors.New(\"triage: refused to hand class B a response produced by class A's payload\")",
		"package triage\nvar markerPattern = regexp.MustCompile(MarkerShapePattern)",
		"package triage\nvar triageClassifiers = map[ClassID]Classifier{}",
	} {
		if declaresAResponseHolder(t, src) {
			t.Errorf("the guard fired on legitimate code:\n%s\nA guard that fires on correct code is a guard the next person deletes", src)
		}
	}
}

// declaresAResponseHolder is the guard's predicate, run over one file's source.
func declaresAResponseHolder(t *testing.T, src string) bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	for _, decl := range file.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			text := varTypeText(t, fset, vs)
			for _, needle := range packageLevelResponseNeedles() {
				if strings.Contains(text, needle) {
					return true
				}
			}
		}
	}
	return false
}

// varTypeText renders what a var declaration says about its TYPE, and nothing else.
//
// WHY NOT THE WHOLE DECLARATION. The first version of this guard matched the rendered spec and
// fired on ErrForeignObservation, whose NAME contains the word Observation and whose type is an
// error. A guard that fires on an error variable is a guard somebody deletes, and then the
// registry comes back unnoticed. So the match is against the declared type when there is one, the
// composite literal's type when the value is a literal, and the called function's name when the
// value is a constructor call, which is enough to catch NewPerturbedVault without catching
// errors.New.
func varTypeText(t *testing.T, fset *token.FileSet, vs *ast.ValueSpec) string {
	t.Helper()
	parts := make([]string, 0, 2)
	if vs.Type != nil {
		parts = append(parts, renderNode(t, fset, vs.Type))
	}
	for _, v := range vs.Values {
		switch e := v.(type) {
		case *ast.CompositeLit:
			if e.Type != nil {
				parts = append(parts, renderNode(t, fset, e.Type))
			}
		case *ast.CallExpr:
			parts = append(parts, renderNode(t, fset, e.Fun))
		case *ast.UnaryExpr:
			if cl, ok := e.X.(*ast.CompositeLit); ok && cl.Type != nil {
				parts = append(parts, renderNode(t, fset, cl.Type))
			}
		}
	}
	return strings.Join(parts, " ")
}

// packageLevelResponseNeedles names the types a package-level variable must not be able to reach.
// They are assembled at run time so that this scanner's own source does not contain them.
func packageLevelResponseNeedles() []string {
	return []string{
		"Perturbed" + "Vault",
		"class" + "Partition",
		"perturbed" + "Entry",
		"Obser" + "vation",
		"triageRun" + "Vaults",
	}
}

func renderNode(t *testing.T, fset *token.FileSet, n ast.Node) string {
	t.Helper()
	var buf strings.Builder
	if err := printer.Fprint(&buf, fset, n); err != nil {
		t.Fatalf("print node: %v", err)
	}
	return buf.String()
}

// A run restarted under the same id gets a FRESH vault, because the runner opens a new one, and an
// old handle can never resolve against a new response.
func TestAHandleNeverResolvesAgainstARestartedRun(t *testing.T) {
	const runID = "7f3q"
	ord := ClassStripeModulus + uint64(ClassSQL)

	first := NewPerturbedVault(testCap, runID)
	p, err := first.Mint(testCap, Observation{ObsID: "r1", RunID: runID, Kind: ObsProbe, Class: ClassSQL},
		ClassSQL, "SQL-1", ord, testMarker(t, runID, ord))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if got, err := ownRead(p, ClassSQL); err != nil || got.ObsID != "r1" {
		t.Fatalf("the owner could not read its own response: %q, %v", got.ObsID, err)
	}
	if n := first.Release(testCap); n != 1 {
		t.Errorf("Release dropped %d responses, want 1", n)
	}
	if _, err := ownRead(p, ClassSQL); !errors.Is(err, ErrRunReleased) {
		t.Errorf("a handle survived its run's release, err = %v", err)
	}

	second := NewPerturbedVault(testCap, runID)
	defer second.Release(testCap)
	q, err := second.Mint(testCap, Observation{ObsID: "r2", RunID: runID, Kind: ObsProbe, Class: ClassSQL},
		ClassSQL, "SQL-2", ord, testMarker(t, runID, ord))
	if err != nil {
		t.Fatalf("Mint after restart: %v", err)
	}
	if got, err := ownRead(q, ClassSQL); err != nil || got.ObsID != "r2" {
		t.Fatalf("the restarted run could not read its own response: %q, %v", got.ObsID, err)
	}
	if _, err := ownRead(p, ClassSQL); err == nil {
		t.Error("a handle from the released run resolved against the restarted run's vault")
	}
	// The second vault does not answer for the first vault's handle either, so holding one run is
	// never holding another.
	if _, err := second.ObsOf(testCap, p); err == nil {
		t.Error("the restarted run's vault answered for a handle the released run minted")
	}
}

// ---------------------------------------------------------------------------------------------
// The partition: the primary fix, asserted as a shape
// ---------------------------------------------------------------------------------------------

// A Perturbed points at ONE CLASS'S partition, and the partition holds one class's entries.
//
// This is the property that kills the whole reflect family of attacks, so it is asserted directly
// rather than left as a consequence of the code reading correctly. An attack that walks from a
// handle, by reflect or by an unsafe cast or by any other route, arrives here, and what is here is
// what the caller was already handed.
func TestAHandleReachesOnlyItsOwnClassesPartition(t *testing.T) {
	v := NewPerturbedVault(testCap, "7f3q")
	defer v.Release(testCap)

	perClass := map[ClassID]Perturbed{}
	for _, id := range []ClassID{ClassSSTI, ClassSQL, ClassLFI} {
		ord := uint64(id)
		p, err := v.Mint(testCap, Observation{ObsID: id.String(), Kind: ObsProbe, Class: id, ProbeOrdinal: ord,
			Body: []byte("SECRET-" + id.String() + "-BODY")}, id, ProbeID(id.String()+"-1"), ord, testMarker(t, "7f3q", ord))
		if err != nil {
			t.Fatalf("Mint %s: %v", id, err)
		}
		perClass[id] = p
	}

	if v.Live() != 3 {
		t.Fatalf("the vault holds %d responses across every partition, want 3", v.Live())
	}
	for id, p := range perClass {
		if p.part == nil {
			t.Fatalf("class %s's handle points at no partition", id)
		}
		if p.part.owner != id {
			t.Errorf("class %s's handle points at class %s's partition", id, p.part.owner)
		}
		if got := v.LiveFor(id); got != 1 {
			t.Errorf("class %s's partition holds %d responses, want 1", id, got)
		}
		p.part.mu.RLock()
		n := len(p.part.held)
		owners := map[ClassID]bool{}
		for _, e := range p.part.held {
			owners[e.owner] = true
		}
		p.part.mu.RUnlock()
		if n != 1 {
			t.Errorf("the map reachable from class %s's handle holds %d entries, want exactly its own 1. Every reflect attack in the adversary package ends at this map", id, n)
		}
		for owner := range owners {
			if owner != id {
				t.Errorf("the map reachable from class %s's handle holds class %s's entry", id, owner)
			}
		}
	}

	// Two classes' handles never point at the same object, or the partition is not a partition.
	if perClass[ClassSQL].part == perClass[ClassLFI].part {
		t.Error("two classes' handles point at the same partition, so the vault is not partitioned at all")
	}
}

// No exported signature hands a vault, a partition or a raw Observation to a caller who did not
// already hold one.
//
// WHY BY REFLECTION OVER THE EXPORTED SURFACE. The audit's attempt 14 needed no handle at all: it
// called an exported package-level function, got a value back, and reflected through it. The
// defence is that no exported function RETURNS anything that reaches another class's response
// unless the caller passed in the capability or the vault. This walks the package's exported
// functions and checks exactly that.
func TestNoExportedFunctionHandsOutTheWholeRun(t *testing.T) {
	capType := reflect.TypeOf(triagecap.Runner{})
	vaultType := reflect.TypeOf(&PerturbedVault{})

	type surface struct {
		name string
		fn   any
	}
	// The complete exported minting, releasing and filtering surface. Adding one means adding it
	// here, which is the point: the list is the audit.
	for _, s := range []surface{
		{"NewPerturbedVault", NewPerturbedVault},
		{"OwnFor", OwnFor},
		{"CallbacksFor", CallbacksFor},
		{"NewReplay", NewReplay},
		{"NewRunID", NewRunID},
		{"MintMarkerAt", MintMarkerAt},
		{"(*PerturbedVault).Mint", (*PerturbedVault).Mint},
		{"(*PerturbedVault).ObsOf", (*PerturbedVault).ObsOf},
		{"(*PerturbedVault).Release", (*PerturbedVault).Release},
	} {
		ft := reflect.TypeOf(s.fn)
		gated := false
		for i := 0; i < ft.NumIn(); i++ {
			if ft.In(i) == capType || ft.In(i) == vaultType {
				gated = true
			}
		}
		if !gated {
			t.Errorf("%s takes neither a triagecap.Runner nor a *PerturbedVault, so a classifier can call it. Every one of these mints, releases or filters responses, and attempt 14 was a class calling exactly this kind of entry point with a run id it already had", s.name)
		}
	}
}

// The runner is parallel, so the vault is hammered from many goroutines. Run with -race to make
// this mean what it says.
func TestTheVaultIsSafeUnderConcurrentMinting(t *testing.T) {
	v := NewPerturbedVault(testCap, "run-parallel")
	defer v.Release(testCap)

	classes := AllClassIDs()
	const perClass = 20
	var wg sync.WaitGroup
	mints := make([][]Perturbed, len(classes))
	for ci, id := range classes {
		wg.Add(1)
		go func(ci int, id ClassID) {
			defer wg.Done()
			for i := 0; i < perClass; i++ {
				ord := uint64(i+1)*ClassStripeModulus + uint64(id)
				p, err := v.Mint(testCap, Observation{ObsID: id.String() + "-" + strconv.Itoa(i), Kind: ObsProbe, Class: id},
					id, ProbeID(id.String()), ord, "")
				if err != nil {
					t.Errorf("Mint for %s: %v", id, err)
					return
				}
				mints[ci] = append(mints[ci], p)
			}
		}(ci, id)
	}
	wg.Wait()

	if want := len(classes) * perClass; v.Live() != want {
		t.Fatalf("vault holds %d responses after concurrent minting, want %d", v.Live(), want)
	}

	// Read them back concurrently too, and check each one lands with exactly its owner.
	var all []Perturbed
	for _, m := range mints {
		all = append(all, m...)
	}
	wg = sync.WaitGroup{}
	for _, id := range classes {
		wg.Add(1)
		go func(id ClassID) {
			defer wg.Done()
			own := OwnFor(testCap, all, id)
			if own.Len() != perClass {
				t.Errorf("class %s was handed %d of %d responses, want %d", id, own.Len(), len(all), perClass)
				return
			}
			for i := 0; i < own.Len(); i++ {
				p, _, err := own.At(i)
				if err != nil {
					t.Errorf("class %s could not read a response it owns: %v", id, err)
				}
				for _, other := range classes {
					if other == id {
						continue
					}
					// No accessor takes an owner, so the only way to try is to build a set
					// labelled with somebody else's class, which a classifier cannot do at all.
					// The read still fails closed against the vault entry.
					if _, _, err := (OwnedResponses{class: other, held: []Perturbed{p}}).At(0); !errors.Is(err, ErrForeignObservation) {
						t.Errorf("class %s read class %s's response, err = %v", other, id, err)
					}
					if OwnFor(testCap, []Perturbed{p}, other).Len() != 0 {
						t.Errorf("class %s was handed one of class %s's responses by OwnFor", other, id)
					}
				}
			}
		}(id)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------------------------
// The source guard: nothing outside vault.go may touch the vault
// ---------------------------------------------------------------------------------------------
//
// WHAT THIS GUARD IS NOW FOR, AND WHAT IT IS NO LONGER FOR. It used to be the whole defence: the
// triage layer lived in package utils beside 300 other files, unexported meant nothing, and a
// test scanning source was the only thing standing between a classifier and another class's
// response. It was not enough. A reviewer wrote the identical leak in a file named
// sqliClassifier.go, which the glob "triage*.go" did not match, and the full suite stayed green.
// Widening the glob would not have been enough either, because the guard's own clean fixture
// sanctioned p.Obs(p.Owner()), which returned a foreign response with a nil error.
//
// The real boundary is now the PACKAGE, and it is enforced by the compiler in
// classes/leak_test.go, which builds each of the four leaks and asserts the build fails. What is
// left for this guard is the much smaller job it is actually good at: keeping the OTHER FILES OF
// THIS PACKAGE off the vault's internals, so that the number of places able to reach around the
// owner check stays at one. It scans this package's own source, not a filename pattern, so a new
// file called anything at all is covered the moment it is added.

// triageVaultNeedle is one forbidden construct and the reason it is forbidden.
//
// The pattern is a regexp and not a substring because the field needles have to end at a word
// boundary. Measured while writing this: a plain substring search for the raw observation field
// matched "EXCLUDED.observed_value" in the store's upsert SQL, and a guard that fires on correct
// code is a guard the next person deletes.
type triageVaultNeedle struct {
	pattern string
	why     string
}

// triageVaultNeedles builds the needles AT RUN TIME so that the scanner's own source does not
// contain the strings it is looking for. The same trick the parameters-column guard uses, for the
// same reason: a scanner that matches itself is a scanner somebody disables.
func triageVaultNeedles() []triageVaultNeedle {
	p := "Perturbed"
	low := "perturbed"
	return []triageVaultNeedle{
		{p + `\{`, "constructs a " + p + " composite literal, which goes around Mint and therefore around the stripe check, the marker check and the partition"},
		{`\.` + "obs" + `\b`, "reads a raw observation field, which is leak (a): the whole response with no ownership check in front of it"},
		{`\.` + "ticket" + `\b`, "reads the vault handle off a value, which is the first half of forging one"},
		{`\.` + "vault" + `\b`, "reaches the vault through a value somebody is holding"},
		{`\.` + "part" + `\b`, "reaches a class's partition through a handle somebody is holding, which is where every reflect attack lands"},
		{`\.` + "parts" + `\b`, "reaches the map of every class's partition, which is the whole run"},
		{`\.` + "held" + `\b`, "reaches into a partition's map directly"},
		{low + "Ticket", "names the vault's handle type"},
		{low + "Entry", "names the vault's entry type"},
		{"class" + "Partition", "names the partition type, which only vault.go may construct or dereference"},
		// The last two name things that NO LONGER EXIST, and the needles stay for exactly that
		// reason. The package-level run registry and the by-run-id lookup were how //go:linkname
		// and a bare run id reached every class's responses. Deleting them fixed it; these two
		// rows are what notices the day somebody reintroduces one for convenience.
		{"triageRun" + "Vaults", "names the run registry, which was deleted because a package-level symbol is all //go:linkname needs"},
		{low + "VaultFor", "reaches a vault by run id, which needs no handle at all and was leak (d)"},
	}
}

// triageScanForVaultLeaks reports, per file, which forbidden constructs it contains.
func triageScanForVaultLeaks(files map[string]string) map[string][]string {
	out := map[string][]string{}
	for name, text := range files {
		for _, n := range triageVaultNeedles() {
			if regexp.MustCompile(n.pattern).MatchString(text) {
				out[name] = append(out[name], n.pattern+": "+n.why)
			}
		}
		sort.Strings(out[name])
	}
	return out
}

// The guard is tested before it is trusted. Each fixture is one of the four leaks written into a
// file of this package that is not vault.go. The filenames are deliberately NOT triage-prefixed:
// the leak that got through the old guard was in a file called sqliClassifier.go.
func TestTheVaultSourceGuardFires(t *testing.T) {
	p := "Perturbed"
	leaky := map[string]string{
		"sqliClassifier.go": "func leak(x " + p + ") Observation { return x." + "obs }",
		"ssti.go":           "v := " + p + "{part: other." + "part}",
		"anything.go":       "for k := range partition." + "held { _ = k }",
		"z.go":              "var t *" + "perturbedTicket",
		"byRunID.go":        "v := " + "perturbedVaultFor" + "(runID)",
		"wholeRun.go":       "for _, pt := range v." + "parts { _ = pt }",
		"partType.go":       "var q *" + "classPartition",
	}
	found := triageScanForVaultLeaks(leaky)
	for name := range leaky {
		if len(found[name]) == 0 {
			t.Errorf("the source guard did not fire on %s, so that leak could be written into this package today", name)
		}
	}

	// And it does not fire on the legitimate API, or nobody can write a runner.
	//
	// NOTE WHAT IS NO LONGER IN THIS FIXTURE. The old one contained p.Obs(class), and that was the
	// hole: the clean fixture SANCTIONED the call shape that let p.Obs(p.Owner()) hand over a
	// foreign response. There is no such accessor now, so there is nothing to sanction.
	clean := map[string]string{
		"triageRunner.go": "v := NewPerturbedVault(cap, runID)\n" +
			"defer v.Release(cap)\n" +
			"p, err := v.Mint(cap, obs, owner, probeID, ordinal, marker)\n" +
			"own := OwnFor(cap, all, class)\n" +
			"cb := CallbacksFor(cap, hits, class)\n" +
			"h, o, err := own.At(i)\n" +
			"o2, err := v.ObsOf(cap, p)\n" +
			"_ = p.Owner()\n" +
			"_ = v.Live()\n" +
			"_ = v.LiveFor(class)\n",
	}
	if got := triageScanForVaultLeaks(clean); len(got) != 0 {
		t.Errorf("the source guard fired on the legitimate API: %v. A guard that fires on correct code is a guard the next person deletes", got)
	}
}

// No file of this package outside vault.go touches the vault, constructs a Perturbed literal, or
// reads a raw response field.
//
// SCOPE, AND WHY IT IS EVERY FILE AND NOT A FILENAME PATTERN. The predecessor globbed
// "triage*.go", and a reviewer got the identical leak past it by calling the file
// sqliClassifier.go. There is no pattern here: EVERY non-test .go file in the package directory
// is scanned, so the next file is covered whatever it is called. The set is also now small and
// bounded, because everything that does not need the vault lives one package up.
//
// WHY IT IS NOT "MENTIONS THE VAULT AT ALL". The runner has to open a vault, mint into it, read
// out of it and end it, so NewPerturbedVault, Mint, ObsOf and Release are exported and are not
// needles. What is forbidden is everything that goes AROUND those: the handle type, the entry
// type, the partition type, the partition map, the run registry that no longer exists, the
// by-run-id lookup that no longer exists, and the field reads that were leaks (a) and (b).
func TestNoTriageFileOutsideTypesTouchesTheVault(t *testing.T) {
	dir := packageDir(t)
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) < 2 {
		t.Fatalf("found %d source files, so this test is checking nothing", len(paths))
	}

	// The scanner must not match its own source, and its own path comes from the call stack
	// rather than from a hardcoded name so that renaming this file cannot silently disable it.
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed, so the scanner cannot exclude itself and would match its own needles")
	}

	owner := "vault" + ".go"
	files := map[string]string{}
	sawOwner := false
	for _, p := range paths {
		if sameFile(p, self) || strings.HasSuffix(p, "_test.go") {
			continue
		}
		if filepath.Base(p) == owner {
			sawOwner = true
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		files[filepath.Base(p)] = string(src)
	}
	if !sawOwner {
		t.Fatalf("%s is not among this package's files, so the guard is excluding a file that does not exist and is checking the wrong set", owner)
	}
	if len(files) == 0 {
		t.Fatal("the guard scanned zero files, so it is checking nothing")
	}
	t.Logf("scanned %d files of package triage besides %s: %v", len(files), owner, sortedNames(files))

	for name, offences := range triageScanForVaultLeaks(files) {
		for _, o := range offences {
			t.Errorf("%s %s. Only %s may, because that is the file the vault lives in and the isolation law is only as strong as the number of places that can reach around it", name, o, owner)
		}
	}
}

func sortedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ownRead is the read a classifier actually has: filter to its own set, then read by index.
//
// When OwnFor comes back empty the handle did not resolve to a live entry owned by `as`, and the
// test wants the AUTHORITATIVE reason rather than a silent zero, so the read goes through a set
// labelled with the same class. That is a construction only this package can perform, which is
// the point: outside it, an empty set is all there is, and an empty set scores nothing.
func ownRead(p Perturbed, as ClassID) (Observation, error) {
	own := OwnFor(testCap, []Perturbed{p}, as)
	if own.Len() == 0 {
		own = OwnedResponses{class: as, held: []Perturbed{p}}
	}
	_, obs, err := own.At(0)
	return obs, err
}
