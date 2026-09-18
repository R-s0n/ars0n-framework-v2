package triageclasses

import (
	"strings"
	"testing"
)

// THE ALLOW-LIST FIXTURES.
//
// Four rounds of enumerating what is forbidden were each walked past by something nobody had
// thought of: a direct field read beat an accessor check, a filename beat a glob, reflect beat a
// needle list, and then a heap dump beat the reflect and unsafe needles. This file proves the
// fifth attempt is a different shape, by showing it refuses the attack that beat its predecessor
// WITHOUT that attack being named in the rule.
//
// The point is not that these specific imports are refused. It is that they are refused BY
// DEFAULT, so the next one nobody thought of is refused too.

// TestTheAllowListRefusesTheHeapDumpAttack is the attack that beat the deny-list, kept as a test.
//
// Measured by the audit: this exact shape, written into the classifier package, read SQL's and
// LFI's response bodies out of a 1,008,664 byte heap dump. It imports os and runtime/debug,
// neither of which was on the needle list, so the guard stayed green and go vet was clean. The
// vault partitioning was irrelevant because nothing walked the object graph.
func TestTheAllowListRefusesTheHeapDumpAttack(t *testing.T) {
	src := "package triageclasses\n\nimport (\n" +
		"\t\"os\"\n\t\"runtime\"\n\t\"runtime/debug\"\n\t\"strings\"\n\n" +
		"\t\"ars0n-framework-v2-server/utils/triage\"\n)\n\n" +
		"func harvest(ctx triage.ClassifyCtx, wanted string) bool {\n" +
		"\tf, _ := os.CreateTemp(\"\", \"t\")\n\truntime.GC()\n\tdebug.WriteHeapDump(f.Fd())\n" +
		"\tb, _ := os.ReadFile(f.Name())\n\treturn strings.Contains(string(b), wanted)\n}\n"

	refused := refusedPaths(t, scanClassifierSource(t, "zz_heapdump.go", src))

	for _, want := range []string{"os", "runtime", "runtime/debug"} {
		if !refused[want] {
			t.Errorf("the allow-list did not refuse %q, so the heap dump attack still passes the guard", want)
		}
	}
	// strings is on the list and must NOT be refused, or this is a blanket ban rather than a rule.
	if refused["strings"] {
		t.Error("the allow-list refused strings, which a classifier legitimately needs to match a response body")
	}
}

// TestTheAllowListRefusesPackagesNobodyEnumerated is the property the deny-lists never had.
//
// None of these is named anywhere in the rule. Each one either reads process memory, touches the
// filesystem, reaches the network, or starts something that outlives the call, and any of those
// makes the vault beside the point. They are refused because they are absent, which is the only
// defence that survives an attack nobody predicted.
func TestTheAllowListRefusesPackagesNobodyEnumerated(t *testing.T) {
	for _, path := range []string{
		"os", "os/exec", "runtime", "runtime/debug", "runtime/pprof", "runtime/metrics",
		"syscall", "net", "net/http", "io", "io/ioutil", "bufio", "log",
		"sync", "context", "plugin", "debug/elf", "embed", "testing",
	} {
		src := "package triageclasses\n\nimport \"" + path + "\"\n"
		if !refusedPaths(t, scanClassifierSource(t, "zz_probe.go", src))[path] {
			t.Errorf("a shipping classifier file may import %q, which the allow-list should refuse by default", path)
		}
	}
}

// TestTheAllowListPermitsWhatAClassifierActuallyNeeds is the other half.
//
// A guard that refuses everything is as useless as one that refuses nothing, because the first
// person to hit it deletes it. These are the packages the job genuinely requires: building
// payload bytes and matching response bytes.
func TestTheAllowListPermitsWhatAClassifierActuallyNeeds(t *testing.T) {
	for _, path := range []string{
		"bytes", "fmt", "regexp", "sort", "strconv", "strings", "errors",
		"encoding/json", "encoding/base64", "encoding/hex", "encoding/xml",
		"net/url", "path", "unicode/utf8", "math", "time",
		"ars0n-framework-v2-server/utils/triage",
	} {
		src := "package triageclasses\n\nimport \"" + path + "\"\n"
		if got := scanClassifierSource(t, "zz_probe.go", src); len(got) != 0 {
			t.Errorf("the allow-list refused %q, which a classifier needs: %v", path, got)
		}
	}
}

// TestTheAllowListDoesNotBindTestFiles records a deliberate limit rather than hiding it.
//
// The guard's own scanner needs go/parser, os and runtime, so a rule that bound every file would
// forbid the scanning. Test files are therefore exempt from the allow-list, and the reason that
// is acceptable is that a _test.go file is not linked into the runner, so a leak there cannot
// reach a live run. The three named attacks are still refused in test files by the needles.
func TestTheAllowListDoesNotBindTestFiles(t *testing.T) {
	src := "package triageclasses\n\nimport \"os\"\n"

	if got := scanClassifierSource(t, "guard_test.go", src); len(got) != 0 {
		t.Errorf("a _test.go file was bound by the allow-list, which would forbid the guard from scanning: %v", got)
	}
	if got := scanClassifierSource(t, "shipping.go", src); len(got) == 0 {
		t.Error("a shipping file was NOT bound by the allow-list, so the exemption leaks into production code")
	}
	// The needles still bind a test file, so the known attacks cannot hide in one.
	reflectSrc := "package triageclasses\n\nimport \"" + "ref" + "lect\"\n"
	if got := scanClassifierSource(t, "sneaky_test.go", reflectSrc); len(got) == 0 {
		t.Error("the reflect needle did not fire in a _test.go file, so an attack can hide there")
	}
}

// refusedPaths turns findings back into the set of import paths that were refused.
func refusedPaths(t *testing.T, found []classifierGuardFinding) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, f := range found {
		rest := strings.TrimPrefix(f.what, "imports ")
		if rest == f.what {
			continue
		}
		if i := strings.IndexAny(rest, ",:"); i >= 0 {
			out[rest[:i]] = true
		}
	}
	return out
}
