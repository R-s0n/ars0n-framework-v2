package triageclasses

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// THE BOUNDARY, TESTED BY THE COMPILER.
//
// Every previous attempt to keep one attack class out of another's responses was a check inside
// package utils, and each one sprang a leak, because a check is code and the next file can be
// written around it. The last round closed three leaks with a vault and a source-scanning test,
// and an adversarial reviewer then found a fourth, wrote it into a file called sqliClassifier.go
// which the guard's "triage*.go" glob did not match, and left the full suite green. Widening the
// glob would not have helped either: the same reviewer showed p.Obs(p.Owner()) handed over a
// foreign response with a nil error and was sanctioned by the guard's own clean fixture.
//
// So the boundary is the package, and this file is how it stays one. Each fixture under
// testdata/leaks is one leak, written the way an attacker would write it, in a package that
// imports triage exactly as a classifier does. The test hands each to `go build` and asserts the
// build FAILS. A fixture that starts compiling is a hole that has reopened, and the test says so
// with the file name and the leak's description rather than with a diff.
//
// WHY testdata. Go tooling ignores a directory called testdata, so these files are never part of
// `go build ./...`, never part of `go vet ./...`, and never part of this package. They are copied
// out to a temporary .go path inside testdata and built by explicit path, so nothing that walks
// the module ever sees a broken package.

// leakFixture is one leak: the fixture file, and what it would let a classifier do.
type leakFixture struct {
	file string
	leak string
	// wantErr is a distinctive fragment of the compiler's refusal. It is asserted so that the
	// test fails loudly if the fixture stops compiling for some UNRELATED reason, such as a typo
	// or a renamed exported symbol. A fixture that fails to build for the wrong reason proves
	// nothing about the boundary and would sit there green forever.
	wantErr string
}

func leakFixtures() []leakFixture {
	return []leakFixture{
		{
			file:    "a_field_read.go.txt",
			leak:    "leak (a): read the observation field straight off a Perturbed, going around every check",
			wantErr: "p.obs undefined",
		},
		{
			file:    "b_forged_literal.go.txt",
			leak:    "leak (b): forge a Perturbed composite literal around NewPerturbed, carrying another class's ticket",
			wantErr: "cannot refer to unexported field",
		},
		{
			file:    "c_launder_replay.go.txt",
			leak:    "leak (c): read a foreign response with p.Obs(p.Owner()) and launder it through NewReplay into the one channel every class reads",
			wantErr: "foreign.Obs undefined",
		},
		{
			file:    "d_range_the_vault.go.txt",
			leak:    "leak (d): range over the vault's held map from one handle and take every class's response",
			wantErr: "p.vault undefined",
		},
		{
			file:    "d2_vault_by_run_id.go.txt",
			leak:    "leak (d), second half: reach the run's whole vault with nothing but the run id every classifier already has",
			wantErr: "undefined: triage.PerturbedVaultFor",
		},
		{
			file:    "e_forged_owned_set.go.txt",
			leak:    "leak (b) against the type that replaced the owner argument: build an OwnedResponses labelled with your own class over somebody else's handles",
			wantErr: "cannot refer to unexported field",
		},
		// The five below are the write side, closed after an adversarial audit ran fifteen
		// attempts against the package split and five succeeded. Read the header of
		// utils/internal/triagecap for the mechanism. Note what is NOT here: attempts 7, 8 and 15
		// COMPILE, so no fixture in this file can see them. They live as runtime tests in
		// utils/triageadversary and as refusals in importguard_test.go, and that split is the
		// whole reason this harness is not the only defence any more.
		{
			file:    "g_ownfor_needs_the_capability.go.txt",
			leak:    "attempt 13: launder a foreign handle through OwnFor, which asks whether the HANDLES belong to c and never whether the CALLER does",
			wantErr: "not enough arguments in call to triage.OwnFor",
		},
		{
			file:    "h_mint_your_own_way_in.go.txt",
			leak:    "attempt 14: a class that has sent nothing mints one throwaway response with the run id out of ctx.Route.Obs().RunID, and the handle it gets back opens everybody's",
			wantErr: "undefined: triage.NewPerturbed",
		},
		{
			file:    "i_open_a_vault_by_hand.go.txt",
			leak:    "attempt 14, second form: open a vault directly, then mint into any class's partition",
			wantErr: "not enough arguments in call to triage.NewPerturbedVault",
		},
		{
			file:    "j_reach_the_capability.go.txt",
			leak:    "walk through the gate rather than around it: import the capability package and grant yourself one",
			wantErr: "use of internal package",
		},
		{
			file:    "k_mint_your_own_marker.go.txt",
			leak:    "reach the marker minter, which this package's doc comment claimed was impossible while triage.MintMarkerAt sat exported beside it",
			wantErr: "not enough arguments in call to triage.MintMarkerAt",
		},
	}
}

// TestTheKnownLeaksDoNotCompile is the point of the package split, and of the capability that came
// after it.
//
// WHAT IT CANNOT SEE, SAID OUT LOUD SO NOBODY READS A GREEN RUN AS COVERAGE. Five of the audit's
// fifteen attempts COMPILED. Three of them still do: attempt 7 is reflect alone, attempt 8 adds an
// unsafe cast, attempt 15 is a go:linkname, and a harness that asserts a build FAILS is
// structurally blind to all three. Those live as runtime tests in utils/triageadversary, which
// runs them and asserts they come back with nothing, and as refusals in importguard_test.go.
func TestTheKnownLeaksDoNotCompile(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Fatalf("no go toolchain on PATH, so this test cannot prove anything and must not pass silently: %v", err)
	}
	dir := packageDirOf(t)
	fixtures := leakFixtures()
	if len(fixtures) < 11 {
		t.Fatalf("%d fixtures, want at least the eleven known compile-time leaks", len(fixtures))
	}

	for _, f := range fixtures {
		f := f
		t.Run(strings.TrimSuffix(f.file, ".go.txt"), func(t *testing.T) {
			src := filepath.Join(dir, "testdata", "leaks", f.file)
			body, err := os.ReadFile(src)
			if err != nil {
				t.Fatalf("read fixture %s: %v", src, err)
			}
			out, buildErr := buildFixture(t, dir, f.file, body)
			if buildErr == nil {
				t.Fatalf("THE BOUNDARY HAS REOPENED. %s built cleanly, so a classifier can once again %s.\nfixture:\n%s",
					f.file, f.leak, body)
			}
			if !strings.Contains(out, f.wantErr) {
				t.Fatalf("%s failed to build, but not for the reason it exists to prove.\nwant the refusal to mention %q\ngot:\n%s",
					f.file, f.wantErr, out)
			}
			t.Logf("%s\n  compiler: %s", f.leak, strings.TrimSpace(out))
		})
	}
}

// buildFixture copies one fixture to a temporary .go path inside testdata and builds it by
// explicit path, returning the compiler's combined output.
//
// The temporary file lives under testdata rather than in os.TempDir because `go build` resolves
// the import of ars0n-framework-v2-server/utils/triage against the module containing the named
// files. Outside the module there is no such module, the build would fail with a MODULE error
// rather than with the type error the fixture is about, and the test would pass for the wrong
// reason, which is the failure mode the wantErr assertion exists to catch.
func buildFixture(t *testing.T, dir, name string, body []byte) (string, error) {
	t.Helper()
	tmp := filepath.Join(dir, "testdata", "leaks", "zz_building_"+strings.TrimSuffix(name, ".txt"))
	if err := os.WriteFile(tmp, body, 0o600); err != nil {
		t.Fatalf("write %s: %v", tmp, err)
	}
	defer os.Remove(tmp)

	cmd := exec.Command("go", "build", "-o", os.DevNull, tmp)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// TestEveryLeakFixtureIsListed stops a fixture being added to the directory and never run, and
// stops one being deleted while its row stays in the table.
//
// A fixture nobody builds is a leak nobody is testing for, and the whole failure mode this file
// exists for is a guard that is quietly checking a smaller set than it looks like it is.
func TestEveryLeakFixtureIsListed(t *testing.T) {
	dir := packageDirOf(t)
	onDisk, err := filepath.Glob(filepath.Join(dir, "testdata", "leaks", "*.go.txt"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	got := make([]string, 0, len(onDisk))
	for _, p := range onDisk {
		got = append(got, filepath.Base(p))
	}
	want := make([]string, 0, len(leakFixtures()))
	for _, f := range leakFixtures() {
		want = append(want, f.file)
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("fixtures on disk %v, fixtures in the table %v. A fixture that is not in the table is never built, and a leak nobody builds is a leak nobody is testing for", got, want)
	}
}

func packageDirOf(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed, so the test cannot find its own fixtures")
	}
	return filepath.Dir(self)
}
