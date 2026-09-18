package triageclasses

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// THE IMPORT GUARD, AND THE HONEST ACCOUNT OF WHY IT IS A TEST.
//
// Everything else that keeps one attack class out of another's responses is structural. The vault
// is partitioned by (run, class), so a reflect walk from a classifier's handle reaches its own
// entries and there is nothing else there to find. Minting takes a capability whose type lives in
// server/utils/internal/triagecap, and this package sits outside server/utils, so the compiler
// refuses the import. Those need no test to be true; the tests only record that they are.
//
// //go:linkname has no structural defence in Go. It reaches a package-level symbol by NAME,
// through the linker, with no import and no type. The best available answers are to leave nothing
// worth reaching, which is why package triage now has no package-level variable that can reach a
// response, and to refuse the directive here. This guard is the second of those.
//
// WHY THIS GUARD IS NOT THE GUARD THAT FAILED THREE TIMES. Every previous guard in this layer
// matched a FILENAME PATTERN, and the leak walked past it by choosing a different filename: the
// last one globbed "triage*.go" and the reviewer wrote the identical leak into sqliClassifier.go,
// and the full suite stayed green. This one enumerates a CLOSED DIRECTORY. Every .go file in
// server/triageclasses is scanned, whatever it is called, and a classifier that is not in this
// directory is not linked into the runner at all, because the runner reaches the classifiers
// through one blank import of exactly this package.
//
// The second difference is that it checks a property that CANNOT BE SPELLED ANOTHER WAY. An
// import path is an exact string in the file's import block; there is no aliasing, no
// concatenation and no indirection that produces an import of unsafe without the literal path
// being there. A linkname is a compiler directive with one spelling. Compare that with the old
// needle list, which chased expressions: `p.obs`, `p.vault.held`, `Perturbed{...}`. Expressions
// have infinitely many spellings, which is why chasing them lost every time.
//
// WHAT IS FORBIDDEN AND WHY EACH ONE.
//
//	unsafe   an unsafe.Pointer cast reads and writes through any type, so it defeats the
//	         capability's unexported field and would let a class forge one. Attempt 8 used a
//	         mirror cast to read foreign Observations as typed values.
//	reflect  reflect reads THROUGH unexported fields: .String, .Int, .Uint, .Index, .Len and
//	         .MapKeys all work on a value obtained from one, and only .Interface and .Set refuse.
//	         Attempt 7, the headline, was reflect alone with no unsafe and it was vet-clean.
//	linkname the linker will bind a local name to any package-level symbol in the build.
//
// AND WHY THAT IS NOT OVERREACH. A classifier decides what to send and reads what came back. It
// takes a ProbeSpec, a PlanCtx and a ClassifyCtx and returns ProbeRequests and ClassVerdicts. None
// of that is reflective and none of it is unsafe. If a class ever genuinely needs one of the
// three, the answer is a helper in package triage with a shape somebody reviewed, not a hole in
// this list.

// guardedImport is one forbidden import path and the reason it is forbidden.
type guardedImport struct {
	path string
	why  string
}

// classifierGuardNeedles builds the forbidden set AT RUN TIME so that this file's own source does
// not contain the strings it looks for. Import paths are matched exactly, so a scanner that
// matched its own imports would be a scanner somebody disables.
func classifierGuardNeedles() []guardedImport {
	return []guardedImport{
		{"un" + "safe", "an unsafe pointer cast reads and writes through any type, which defeats every unexported field in the layer: attempt 8 mirrored triage.Perturbed and read foreign Observations as typed values"},
		{"ref" + "lect", "reflect reads through unexported fields, which is the whole diagnosis: attempt 7 walked from one legitimately-held handle to every class's response body with no unsafe at all and passed go vet"},
	}
}

// classifierLinknameDirective is the directive, assembled so this file does not contain it.
func classifierLinknameDirective() string { return "//go:" + "linkname" }

// classifierAllowedModuleImports is the module-internal import allow-list.
//
// A classifier imports the type layer and nothing else from this codebase. utils holds the runner,
// the store and the marker allocator; importing it would be a cycle AND would hand a class the
// allocator. The capability package is refused by the compiler already, and it is listed nowhere
// here so that a reader of this file can see the allow-list is one entry long.
var classifierAllowedModuleImports = map[string]bool{
	"ars0n-framework-v2-server/utils/triage": true,
}

const classifierModulePrefix = "ars0n-framework-v2-server/"

// classifierAllowedStdlib is the STDLIB ALLOW-LIST, and it is the reason this guard is different
// in kind from the four that preceded it.
//
// WHY AN ALLOW-LIST. Every earlier defence in this layer enumerated what was forbidden, and each
// one was walked past by something nobody had thought of yet. The score: an accessor check was
// beaten by a direct field read; a filename glob was beaten by naming the file sqliClassifier.go;
// a needle list was beaten by reflect; and the reflect and unsafe needles were then beaten by
//
//	runtime.GC(); debug.WriteHeapDump(f.Fd())
//
// which read SQL's and LFI's response bodies out of a 1,008,664 byte heap dump using nothing but
// os and runtime/debug. Measured, go vet clean, and the guard stayed green because neither import
// was on the list. Four rounds, four enumerations, four escapes. Enumeration is the wrong shape:
// the forbidden set is every package that can read memory or touch the process, and that set is
// open. The permitted set is small, closed, and obvious.
//
// WHAT A CLASSIFIER ACTUALLY DOES: it builds payload bytes and it matches response bytes. It
// takes a ProbeSpec, a PlanCtx and a ClassifyCtx; it returns ProbeRequests and ClassVerdicts. It
// does not open files, start goroutines, read the environment, resolve a host or send a request,
// because the runner does all of that on its behalf. So the list below is not a restriction on
// what a classifier needs, it is a description of it.
//
// ADDING TO THIS LIST IS A DESIGN DECISION, NOT A CONVENIENCE. If a class needs something absent
// here, the answer is usually a helper in package triage with a shape somebody reviewed. A
// package that can read process memory, touch the filesystem, or reach the network never belongs
// here whatever the justification, because a classifier with any of those does not need the vault
// to see another class's data.
var classifierAllowedStdlib = map[string]bool{
	// Payload construction and response matching, which is the whole job.
	"bytes": true, "fmt": true, "regexp": true, "sort": true, "strconv": true,
	"strings": true, "unicode": true, "unicode/utf8": true, "errors": true,
	"math": true, "slices": true, "maps": true,
	// Body encodings. A JSON body payload must be marshalled rather than concatenated, which is
	// the single most common way a probe becomes a 400 about its own document instead of a test.
	"encoding/json": true, "encoding/base64": true, "encoding/hex": true,
	"encoding/xml": true, "encoding/csv": true,
	// URL and path shapes, for the classes whose payloads are URLs or path segments.
	"net/url": true, "path": true, "mime": true,
	// Durations appear in probe specifications even though no class uses timing as a primary
	// oracle. time.Now is not needed and its absence is not enforced here; the runner stamps time.
	"time": true,
}

// classifierStdlibAllowListApplies reports whether the allow-list binds this file.
//
// It binds the files that SHIP. Test files in this package are excluded for one practical reason:
// the guard's own source needs go/parser, os and runtime to do the scanning, and a rule that
// forbids the scanner from scanning is a rule somebody deletes. The deny-needles below still
// apply to every file including tests, so the three named attacks cannot hide in a _test.go
// either. A test file is not linked into the runner, so a leak there cannot reach a live run.
func classifierStdlibAllowListApplies(name string) bool {
	return !strings.HasSuffix(name, "_test.go")
}

// classifierGuardFinding is one refusal, with enough detail to act on.
type classifierGuardFinding struct {
	file string
	line int
	what string
}

func (f classifierGuardFinding) String() string {
	return f.file + ":" + strconv.Itoa(f.line) + ": " + f.what
}

// scanClassifierSource is the guard's predicate over one file's source. It is a function taking
// text so that the test below can run it over fixtures and prove it fires.
func scanClassifierSource(t *testing.T, name, src string) []classifierGuardFinding {
	t.Helper()
	var out []classifierGuardFinding

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatalf("%s: unquote import %s: %v", name, imp.Path.Value, err)
		}
		line := fset.Position(imp.Pos()).Line
		for _, n := range classifierGuardNeedles() {
			if path == n.path {
				out = append(out, classifierGuardFinding{name, line, "imports " + path + ": " + n.why})
			}
		}
		if strings.HasPrefix(path, classifierModulePrefix) && !classifierAllowedModuleImports[path] {
			out = append(out, classifierGuardFinding{name, line,
				"imports " + path + ", which is not the type layer. A classifier imports ars0n-framework-v2-server/utils/triage and nothing else from this codebase: everything else in the layer handles every class's responses at once"})
			continue
		}

		// THE ALLOW-LIST. Anything that is neither the type layer nor an allowed stdlib package
		// is refused by default, so a package nobody anticipated is refused without anybody
		// having to anticipate it. This is what closes runtime/debug.WriteHeapDump, and it closed
		// it before that attack was known rather than after.
		if classifierStdlibAllowListApplies(name) &&
			!strings.HasPrefix(path, classifierModulePrefix) &&
			!classifierAllowedStdlib[path] {
			out = append(out, classifierGuardFinding{name, line,
				"imports " + path + ", which is not on the classifier allow-list. A classifier builds payload bytes and matches response bytes; it does not read memory, touch the filesystem, or reach the network, because the runner does all of that for it. If this class genuinely needs it, add a reviewed helper to package triage rather than widening this list"})
		}
	}

	// The directive is scanned as text rather than through the AST, because a compiler directive
	// is a comment and its only property that matters is that it is written down at all.
	directive := classifierLinknameDirective()
	for i, l := range strings.Split(src, "\n") {
		if strings.Contains(l, directive) {
			out = append(out, classifierGuardFinding{name, i + 1,
				"carries a " + directive + " directive, which binds a local name to any package-level symbol in the build, with no import and no type in the way. It is the one attack in this layer with no structural defence"})
		}
	}
	return out
}

// TestTheClassifierPackageImportsNeitherUnsafeNorReflect enumerates the directory.
//
// NOTE WHAT WAS HERE BEFORE: nothing. There was no import guard on the classifier package at all,
// and the audit's fifteen attempts were all written as files in it.
func TestTheClassifierPackageImportsNeitherUnsafeNorReflect(t *testing.T) {
	dir := packageDirOf(t)
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(paths) < 2 {
		t.Fatalf("found %d source files in %s, so this guard is checking nothing", len(paths), dir)
	}

	// The guard must not match its own source, and its own path comes from the call stack rather
	// than from a hardcoded name so that renaming this file cannot silently disable it.
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed, so the scanner cannot exclude itself")
	}

	scanned := make([]string, 0, len(paths))
	for _, p := range paths {
		if sameClassifierFile(p, self) {
			continue
		}
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read %s: %v", p, err)
		}
		base := filepath.Base(p)
		scanned = append(scanned, base)
		for _, f := range scanClassifierSource(t, base, string(src)) {
			t.Errorf("%s. A classifier decides what to send and reads what came back; none of that is reflective, unsafe or linked by name", f)
		}
	}
	if len(scanned) == 0 {
		t.Fatal("the guard scanned zero files, so it is checking nothing")
	}
	sort.Strings(scanned)
	t.Logf("scanned %d files of %s: %v", len(scanned), filepath.Base(dir), scanned)
}

// TestTheClassifierImportGuardFiresOnAllThree is the guard tested before it is trusted.
//
// Each fixture is one of the three attacks that survived the audit and still compiles. A guard
// whose pattern has never matched anything is a guard nobody has checked, and this layer has now
// shipped three of those.
func TestTheClassifierImportGuardFiresOnAllThree(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		wantHit string
	}{
		{
			name: "attempt7_reflect.go",
			src: "package triageclasses\n\nimport (\n\t\"" + "ref" + "lect\"\n\n\t\"ars0n-framework-v2-server/utils/triage\"\n)\n\n" +
				"func attempt7(ctx triage.ClassifyCtx) {\n\tmine, _, _ := ctx.Own.At(0)\n\t_ = reflect.ValueOf(mine).Field(0).Elem().FieldByName(\"held\")\n}\n",
			wantHit: "ref" + "lect",
		},
		{
			name: "attempt8_unsafe.go",
			src: "package triageclasses\n\nimport (\n\t\"" + "un" + "safe\"\n\n\t\"ars0n-framework-v2-server/utils/triage\"\n)\n\n" +
				"type mirror struct{ part, ticket " + "un" + "safe.Pointer }\n\n" +
				"func attempt8(p triage.Perturbed) mirror { return *(*mirror)(" + "un" + "safe.Pointer(&p)) }\n",
			wantHit: "un" + "safe",
		},
		{
			name: "attempt15_linkname.go",
			src: "package triageclasses\n\nimport (\n\t\"sync\"\n\n\t\"ars0n-framework-v2-server/utils/triage\"\n)\n\n" +
				classifierLinknameDirective() + " runVaults ars0n-framework-v2-server/utils/triage.triageRunVaults\n" +
				"var runVaults struct {\n\tmu    sync.Mutex\n\tbyRun map[string]*triage.PerturbedVault\n}\n",
			wantHit: classifierLinknameDirective(),
		},
		{
			name:    "reach_the_runner.go",
			src:     "package triageclasses\n\nimport \"ars0n-framework-v2-server/utils\"\n\nvar _ = utils.AssertTriageRegistryIsolation\n",
			wantHit: "ars0n-framework-v2-server/utils",
		},
	}
	for _, c := range cases {
		got := scanClassifierSource(t, c.name, c.src)
		if len(got) == 0 {
			t.Errorf("THE GUARD DID NOT FIRE on %s, so this could be written into the classifier package today:\n%s", c.name, c.src)
			continue
		}
		hit := false
		for _, f := range got {
			if strings.Contains(f.what, c.wantHit) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("%s: the guard fired, but not for %q. It said: %v", c.name, c.wantHit, got)
		}
		t.Logf("%s: %v", c.name, got)
	}

	// And it does not fire on a real classifier, or it gets deleted by the next person who adds
	// one. This is the shape of every file in this directory.
	clean := "package triageclasses\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n\n\t\"ars0n-framework-v2-server/utils/triage\"\n)\n\n" +
		"type sqli struct{}\n\nfunc init() { triage.RegisterClassifier(sqli{}) }\n\n" +
		"func (sqli) ID() triage.ClassID { return triage.ClassSQL }\n"
	if got := scanClassifierSource(t, "sqli.go", clean); len(got) != 0 {
		t.Errorf("the guard fired on an ordinary classifier: %v. A guard that fires on correct code is a guard the next person deletes", got)
	}
}

// sameClassifierFile compares two paths by their cleaned absolute form, because the glob and the
// call stack can spell the same file differently.
func sameClassifierFile(a, b string) bool {
	aa, err := filepath.Abs(a)
	if err != nil {
		return false
	}
	bb, err := filepath.Abs(b)
	if err != nil {
		return false
	}
	return filepath.Clean(aa) == filepath.Clean(bb)
}
