package utils

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// Tests for the triage layer's shared vocabulary and core types.
//
// Four of these are not really unit tests. They are the isolation law and the not-knowing-is-not-
// clean rule written down in a form the build enforces, and each of them exists because the
// corresponding bug has already shipped in this codebase:
//
//   - TestOnlySlotsForReadsTheParametersColumn: the path insertion point probed nothing on 51
//     vectors and recorded them tested, because a loop read attack_vectors.parameters and that
//     column is empty for every path vector.
//   - TestNoUnknownStateCanBeReportedClean and TestStateVocabularyIsExhaustive: a check that never
//     ran, re-classified as clean on the next refactor.
//   - TestPlanCtxExposesPerturbedResponsesOnlyThroughOwn: a class reaching a verdict from another
//     class's response.
//   - TestPayloadWireDefaultsToUnprovenSurvival: Go's http.Cookie silently drops the exact
//     characters a SQL injection probe is made of.

// ---------------------------------------------------------------------------------------------
// The one-function rule, and the silent zero it exists to stop
// ---------------------------------------------------------------------------------------------

// attack_vectors.parameters is read by SlotsFor and by nothing else in the triage layer.
//
// THE BUG THIS GUARDS. Measured in Postgres: 218 vectors and 1860 parameter slots, of which the 51
// path vectors contribute ZERO. Any loop over that array probes nothing on 23.4% of the corpus and
// records those vectors as tested. That has already shipped here once.
//
// SCOPE, AND IT IS NARROWER THAN foundations 6.5 ASKS FOR. Foundations proposes a CI grep over all
// of server/. That cannot run here: package utils already reads the parameters column legitimately
// in the storage and consolidation paths (attackVectors.go writes it, vectorAPI.go serves it, and
// seventeen other files touch attack_vectors). The rule this test enforces is therefore the triage
// layer's own: within triage*.go, SlotsFor is the only reader.
//
// THE PACKAGE SPLIT DID NOT WIDEN THIS, AND COULD NOT HAVE. triageVectorRow, the only type
// carrying the parameters column, stayed up here with SlotsFor, because the derivation needs
// templatedPathSegments from vectorCompose.go and package triage must not import utils. What DID
// change is that triage.TriageVector, the type a classifier sees, is now in another package
// entirely, so the type-level half of the one-function rule is enforced by the compiler for every
// classifier rather than by the field simply being absent.
func TestOnlySlotsForReadsTheParametersColumn(t *testing.T) {
	// BOTH HALVES OF THE LAYER, not just this package's. After the split the types live in
	// utils/triage and the classifiers in server/triageclasses, and a guard still globbing only
	// "triage*.go" would be covering the half that did not move. That is precisely how a source
	// guard stayed green while the leak it existed for was written into sqliClassifier.go.
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
		files = append(files, m...)
	}
	if len(files) < 2 {
		t.Fatalf("found %d triage files, so this test is checking nothing", len(files))
	}

	// The scanner must not match its own source. Its own path comes from the call stack rather
	// than from a hardcoded name, so renaming this file cannot silently disable the check.
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed, so the scanner cannot exclude itself and would match its own needles")
	}

	// Built at run time rather than written as one literal, so the needle for the column name
	// does not appear in any file this scanner reads.
	column := "attack_vectors" + "." + "parameters"
	field := "Parameters"

	var owner string
	var offenders []string
	for _, f := range files {
		if sameFile(f, self) {
			continue
		}
		text := triageSourceWithoutComments(t, f)
		declaresSlotsFor := strings.Contains(text, "func SlotsFor(")
		if declaresSlotsFor {
			if owner != "" {
				t.Errorf("SlotsFor is declared in both %s and %s", filepath.Base(owner), filepath.Base(f))
			}
			owner = f
			continue
		}
		if strings.Contains(text, column) || strings.Contains(text, "."+field) || strings.Contains(text, field+" []") {
			offenders = append(offenders, filepath.Base(f))
		}
	}
	if owner == "" {
		t.Fatal("no triage file declares SlotsFor, so the one legal reader of the parameters column does not exist")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Errorf("these triage files read the parameters column: %v. SlotsFor is the only function allowed to, because that array is empty for every path vector and a second reader is how 51 vectors get probed with nothing and recorded as tested", offenders)
	}

	// The type-level half of the rule, and the half that cannot be worked around: the exported
	// vector type has no parameters field at all, so nothing downstream can read what it cannot
	// name.
	rt := reflect.TypeOf(triage.TriageVector{})
	for i := 0; i < rt.NumField(); i++ {
		if strings.Contains(strings.ToLower(rt.Field(i).Name), "param") {
			t.Errorf("TriageVector has field %s: the exported vector type must not carry the parameters column, or the one-function rule is only a comment again", rt.Field(i).Name)
		}
	}
}

// A slot derivation that returns nothing and says nothing is the silent zero itself. Every vector
// produces at least one slot or at least one note, and this holds for the stub as well as for the
// implementation, which is why it can be written now.
func TestSlotDerivationNeverReturnsBothEmpty(t *testing.T) {
	rows := []triageVectorRow{
		{ID: "v-query", InsertionPoint: triage.KindQuery, Parameters: []string{"sort"}},
		{ID: "v-path-no-params", InsertionPoint: triage.KindPath, Parameters: nil},
		{ID: "v-body", InsertionPoint: triage.KindBody, Parameters: []string{}},
	}
	for _, r := range rows {
		slots, notes := SlotsFor(r, triage.SlotEvidence{})
		if len(slots) == 0 && len(notes) == 0 {
			t.Errorf("vector %s produced no slots and no notes, which reads as tested and is the exact shape of the path-vector bug", r.ID)
		}
	}
}

// A zero slot count for an insertion point that has vectors aborts the run. It is not a warning.
// A warning in a log is how the path insertion point shipped a zero against 51 vectors.
func TestZeroSlotsForAnInsertionPointWithVectorsIsAHardError(t *testing.T) {
	// The measured corpus, as it stood when this layer was specified.
	vectors := map[triage.SlotKind]int{triage.KindCookie: 75, triage.KindQuery: 30, triage.KindBody: 13, triage.KindHeader: 49, triage.KindPath: 51}

	shipped := map[triage.SlotKind]int{triage.KindCookie: 1655, triage.KindQuery: 92, triage.KindBody: 64, triage.KindHeader: 49, triage.KindPath: 0}
	err := AssertSlotCoverage(vectors, shipped)
	if err == nil {
		t.Fatal("51 path vectors with 0 path slots was accepted, which is the bug this assertion exists for")
	}
	if !strings.Contains(err.Error(), "path has 51 vectors and 0 slots") {
		t.Errorf("error %q does not name the insertion point and the counts", err)
	}

	fixed := map[triage.SlotKind]int{triage.KindCookie: 1655, triage.KindQuery: 92, triage.KindBody: 64, triage.KindHeader: 49, triage.KindPath: 51}
	if err := AssertSlotCoverage(vectors, fixed); err != nil {
		t.Errorf("a corpus with slots on every insertion point was rejected: %v", err)
	}
	// An insertion point with no vectors and no slots is correct, not a failure.
	if err := AssertSlotCoverage(map[triage.SlotKind]int{triage.KindFragment: 0}, map[triage.SlotKind]int{triage.KindFragment: 0}); err != nil {
		t.Errorf("an insertion point with no vectors was reported as a silent zero: %v", err)
	}
}

// ---------------------------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------------------------

// testMarker builds a well-formed marker for a given ordinal. The checksum is a placeholder
// because no verifier exists yet; Marker.Integrity reports Unchecked and the test above asserts
// that stays true until someone writes one.
func testMarker(t *testing.T, runID string, ordinal uint64) triage.Marker {
	t.Helper()
	if len(runID) != triage.MarkerRunIDLen {
		t.Fatalf("run id %q is %d chars, want %d", runID, len(runID), triage.MarkerRunIDLen)
	}
	ord := strconv.FormatUint(ordinal, 36)
	if len(ord) > triage.MarkerOrdinalLen {
		t.Fatalf("ordinal %d does not fit in %d base36 chars", ordinal, triage.MarkerOrdinalLen)
	}
	ord = strings.Repeat("0", triage.MarkerOrdinalLen-len(ord)) + ord
	// The checksum is COMPUTED, not a fixed literal. A fixture with a made-up checksum was
	// harmless only while Marker.Integrity() was a stub; now that the verifier is wired, every
	// marker this helper builds would read corrupted and no test could tell a real corruption
	// from the fixture.
	prefix := triage.DefaultMarkerAnchor + runID + ord
	sum, err := triage.MarkerChecksumFor(prefix)
	if err != nil {
		t.Fatalf("checksum for %q: %v", prefix, err)
	}
	m := triage.Marker(prefix + sum)
	if !m.WellFormed() {
		t.Fatalf("built a malformed marker %q", m)
	}
	if got := m.Integrity(); got != triage.MarkerValid {
		t.Fatalf("built marker %q reads %q", m, got)
	}
	return m
}

// packageDir returns the directory holding this package's source.
func packageDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Dir(self)
}

func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	if err != nil {
		return false
	}
	return os.SameFile(ai, bi)
}

// constantsOfType parses the package's non-test source and returns every constant declared with
// the named type, as name to string value.
//
// Reading the source rather than a hand-kept list is the only way this can be exhaustive: a list
// is exactly the thing that goes stale when someone adds a constant.
func constantsOfType(t *testing.T, typeName string) map[string]string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, packageDir(t), func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	out := map[string]string{}
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, s := range gd.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok {
						continue
					}
					id, ok := vs.Type.(*ast.Ident)
					if !ok || id.Name != typeName {
						continue
					}
					for i, n := range vs.Names {
						if i >= len(vs.Values) {
							continue
						}
						lit, ok := vs.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						v, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("unquote %s: %v", lit.Value, err)
						}
						out[n.Name] = v
					}
				}
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// Slot derivation against the measured corpus
// ---------------------------------------------------------------------------------------------

// triageCorpusRows builds a corpus with the MEASURED shape: 218 vectors split cookie 75, query 30,
// body 13, header 49, path 51. The path rows carry NO entries in the parameters array, because
// that is what the real ones carry, and it is the whole reason the Slot abstraction exists.
func triageCorpusRows() ([]triageVectorRow, map[string]triage.SlotEvidence) {
	var rows []triageVectorRow
	evidence := map[string]triage.SlotEvidence{}

	for i := 0; i < 75; i++ {
		id := "cookie-" + strconv.Itoa(i)
		rows = append(rows, triageVectorRow{
			ID: id, Method: "GET", InsertionPoint: triage.KindCookie,
			ComposedURL: "https://app.example.com/dashboard",
			RawRequest: []byte("GET /dashboard HTTP/1.1\r\nHost: app.example.com\r\n" +
				"Cookie: session_theme=dark; sid=abc123; _ga=GA1.2.9\r\n\r\n"),
			Parameters: []string{"session_theme", "sid", "_ga"},
		})
		_ = id
	}
	for i := 0; i < 30; i++ {
		id := "query-" + strconv.Itoa(i)
		rows = append(rows, triageVectorRow{
			ID: id, Method: "GET", InsertionPoint: triage.KindQuery,
			ComposedURL: "https://api.example.com/v2/orders?sort=asc&page=2",
			Parameters:  []string{"sort", "page", "filter"},
		})
	}
	for i := 0; i < 13; i++ {
		id := "body-" + strconv.Itoa(i)
		rows = append(rows, triageVectorRow{
			ID: id, Method: "POST", InsertionPoint: triage.KindBody, MediaType: "application/json",
			ComposedURL: "https://api.example.com/v2/orders",
			RawRequest: []byte("POST /v2/orders HTTP/1.1\r\nHost: api.example.com\r\n" +
				"Content-Type: application/json\r\n\r\n" +
				`{"symbol":"AAPL","qty":3,"filters":{"status":"open"}}`),
			Parameters: []string{"symbol", "qty"},
		})
	}
	for i := 0; i < 49; i++ {
		id := "header-" + strconv.Itoa(i)
		rows = append(rows, triageVectorRow{
			ID: id, Method: "GET", InsertionPoint: triage.KindHeader,
			ComposedURL: "https://api.example.com/v2/account",
			RawRequest: []byte("GET /v2/account HTTP/1.1\r\nHost: api.example.com\r\n" +
				"X-Tenant: acme\r\nAuthorization: Bearer secret\r\n\r\n"),
			Parameters: []string{"X-Tenant", "Authorization"},
		})
	}
	// The 51 path vectors. Empty parameters array, templated segment, evidence URL carrying the
	// identifier the crawl actually saw.
	for i := 0; i < 51; i++ {
		id := "path-" + strconv.Itoa(i)
		rows = append(rows, triageVectorRow{
			ID: id, Method: "GET", InsertionPoint: triage.KindPath,
			ComposedURL: "https://api.example.com/api/v1/paper_accounts/{uuid}/trade_account/margin",
			EvidenceURL: "https://api.example.com/api/v1/paper_accounts/9f8c1d22-1111-2222-3333-444455556666/trade_account/margin",
			Parameters:  nil,
		})
		evidence[id] = triage.SlotEvidence{
			EvidenceURL: "https://api.example.com/api/v1/paper_accounts/9f8c1d22-1111-2222-3333-444455556666/trade_account/margin",
		}
	}
	return rows, evidence
}

// The derivation runs against the measured corpus shape and produces slots on every insertion
// point, with the path insertion point the one that matters.
//
// THE BUG THIS IS THE END OF. 51 of 218 vectors are path vectors, all 51 have zero entries in
// attack_vectors.parameters, and the shipped derivation looped over that array. 23.4% of the
// corpus was probed with nothing and recorded as tested. SlotsFor was then a stub that returned
// zero slots for everything, and AssertSlotCoverage, which exists to catch exactly that, had no
// caller, so the whole Slot abstraction was inert.
func TestSlotsForCoversEveryInsertionPointOnTheMeasuredCorpus(t *testing.T) {
	rows, evidence := triageCorpusRows()
	if len(rows) != 218 {
		t.Fatalf("the fixture has %d vectors, want the measured 218", len(rows))
	}

	slots, notes, err := DeriveCorpusSlots(rows, evidence)
	if err != nil {
		t.Fatalf("the derivation refused the measured corpus: %v", err)
	}

	byKind := map[triage.SlotKind]int{}
	for _, s := range slots {
		byKind[s.Kind]++
	}
	for _, k := range []triage.SlotKind{triage.KindCookie, triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindPath} {
		if byKind[k] == 0 {
			t.Errorf("insertion point %s produced ZERO slots against a corpus that has vectors for it, which is the silent zero itself", k)
		}
	}

	// The load-bearing number. 51 path vectors, and every one of them must produce at least one
	// slot, from its SEGMENTS, with an empty parameters array.
	if byKind[triage.KindPath] < 51 {
		t.Errorf("51 path vectors produced %d path slots, want at least 51: a path vector that yields no slot is probed with nothing and recorded as tested", byKind[triage.KindPath])
	}

	// Every vector produced something. A vector with no slots and no notes is indistinguishable
	// from a vector that was tested and had nothing to test.
	covered := map[string]bool{}
	for _, s := range slots {
		covered[s.VectorID] = true
	}
	for _, n := range notes {
		covered[n.VectorID] = true
	}
	for _, r := range rows {
		if !covered[r.ID] {
			t.Errorf("vector %s (%s) produced no slots and no notes", r.ID, r.InsertionPoint)
		}
	}
}

// Path slots come from the SEGMENTS and the templated one resolves to a value the application
// actually served.
func TestPathSlotsComeFromSegmentsAndResolveTheTemplate(t *testing.T) {
	row := triageVectorRow{
		ID: "p1", Method: "GET", InsertionPoint: triage.KindPath,
		ComposedURL: "https://api.example.com/api/v1/paper_accounts/{uuid}/trade_account/margin",
		Parameters:  nil, // as all 51 real path vectors are
	}
	ev := triage.SlotEvidence{EvidenceURL: "https://api.example.com/api/v1/paper_accounts/9f8c1d22-1111-2222-3333-444455556666/trade_account/margin"}

	slots, _ := SlotsFor(row, ev)
	if len(slots) < 6 {
		t.Fatalf("a six-segment path produced %d slots, want one per non-empty segment", len(slots))
	}

	var templated *triage.Slot
	for i := range slots {
		if slots[i].SegmentIndex == 3 {
			templated = &slots[i]
		}
		if slots[i].Kind != triage.KindPath {
			t.Errorf("slot %s has kind %s on a path vector", slots[i].Key, slots[i].Kind)
		}
		if slots[i].Encoder != triage.EncodePathSegment {
			t.Errorf("slot %s uses encoder %s, want the path segment encoder", slots[i].Key, slots[i].Encoder)
		}
	}
	if templated == nil {
		t.Fatal("the templated segment produced no slot")
	}
	if templated.Key != "path:3:{uuid}" {
		t.Errorf("templated slot key = %q, want path:3:{uuid} with the index first so it sorts numerically", templated.Key)
	}
	if templated.Value != "9f8c1d22-1111-2222-3333-444455556666" {
		t.Errorf("templated slot value = %q, want the identifier from the evidence URL. Substituting the canary unconditionally is what aimed half the corpus at resources that do not exist", templated.Value)
	}
	if templated.ValueOrigin != triage.ValueFromEvidenceURL {
		t.Errorf("templated slot origin = %q, want %q", templated.ValueOrigin, triage.ValueFromEvidenceURL)
	}
	if templated.ValueKind != triage.ValueUUID {
		t.Errorf("templated slot value kind = %q, want uuid", templated.ValueKind)
	}

	// THE ARITY GUARD. An evidence URL describing a different route shape must not be borrowed
	// from, because lining up /a/{id}/b against /a/x/y/b by index invents a URL nobody served.
	slots, notes := SlotsFor(row, triage.SlotEvidence{EvidenceURL: "https://api.example.com/api/v1/other"})
	var canaried bool
	for _, s := range slots {
		if s.SegmentIndex == 3 {
			if s.ValueOrigin != triage.ValueCanary {
				t.Errorf("a mismatched evidence URL was borrowed from anyway: origin %q value %q", s.ValueOrigin, s.Value)
			}
			if s.Value != VectorCanary {
				t.Errorf("the canary fallback produced %q, want %q", s.Value, VectorCanary)
			}
			canaried = true
		}
	}
	if !canaried {
		t.Fatal("the templated segment produced no slot on the mismatched-evidence path")
	}
	// And it says so, because every clean drawn from a canary-valued slot is cannot_determine.
	var said bool
	for _, n := range notes {
		if strings.Contains(n.Reason, "canary") {
			said = true
		}
	}
	if !said {
		t.Errorf("resolving a segment to the canary produced no note; notes were %v", notes)
	}

	// A root-only path still yields a slot rather than a zero.
	rootSlots, rootNotes := SlotsFor(triageVectorRow{ID: "p2", InsertionPoint: triage.KindPath,
		ComposedURL: "https://api.example.com/"}, triage.SlotEvidence{})
	if len(rootSlots) != 1 || len(rootNotes) == 0 {
		t.Errorf("a root-only path produced %d slots and %d notes, want 1 slot and a note saying why it has no observed value", len(rootSlots), len(rootNotes))
	}
}

// The other insertion points derive what they are supposed to derive.
func TestSlotsForDerivesEachInsertionPoint(t *testing.T) {
	keys := func(slots []triage.Slot) map[triage.SlotKey]triage.Slot {
		out := map[triage.SlotKey]triage.Slot{}
		for _, s := range slots {
			out[s.Key] = s
		}
		return out
	}

	t.Run("query unions the URL with the parameters array", func(t *testing.T) {
		slots, notes := SlotsFor(triageVectorRow{ID: "q", Method: "GET", InsertionPoint: triage.KindQuery,
			ComposedURL: "https://h.example.com/s?sort=asc&page=2",
			Parameters:  []string{"sort", "hidden"}}, triage.SlotEvidence{})
		k := keys(slots)
		for _, want := range []triage.SlotKey{"query:sort", "query:page", "query:hidden"} {
			if _, ok := k[want]; !ok {
				t.Errorf("no slot %q; got %v", want, slots)
			}
		}
		if k["query:sort"].ValueOrigin != triage.ValueObserved || k["query:sort"].Value != "asc" {
			t.Errorf("query:sort = %q (%s), want asc observed", k["query:sort"].Value, k["query:sort"].ValueOrigin)
		}
		if k["query:hidden"].Origin != triage.SlotInferred {
			t.Error("a name that came only from the parameters array was not marked inferred")
		}
		if k["query:page"].Encoder != triage.EncodeQuery {
			t.Errorf("query encoder = %s, want query. PathEscape leaves = & and + raw, which splits one payload into three parameters", k["query:page"].Encoder)
		}
		if len(notes) != 0 {
			t.Errorf("unexpected notes %v", notes)
		}

		// Zero query and zero parameters is a note, never a silent zero.
		_, notes = SlotsFor(triageVectorRow{ID: "q0", InsertionPoint: triage.KindQuery,
			ComposedURL: "https://h.example.com/s"}, triage.SlotEvidence{})
		if len(notes) != 1 || notes[0].Reason != "no_query_and_no_parameters" {
			t.Errorf("notes = %v, want exactly no_query_and_no_parameters", notes)
		}
	})

	t.Run("json body gives a pointer per leaf and a node slot per node", func(t *testing.T) {
		slots, _ := SlotsFor(triageVectorRow{ID: "b", Method: "POST", InsertionPoint: triage.KindBody,
			RawRequest: []byte("POST /o HTTP/1.1\r\nContent-Type: application/json\r\n\r\n" +
				`{"symbol":"AAPL","filters":{"status":"open"},"tags":["a"]}`)}, triage.SlotEvidence{})
		k := keys(slots)
		for _, want := range []triage.SlotKey{
			"body:/symbol", "body:/symbol:node",
			"body:/filters:node", "body:/filters/status", "body:/filters/status:node",
			"body:/tags:node", "body:/tags/0", "body:/:node",
		} {
			if _, ok := k[want]; !ok {
				t.Errorf("no slot %q; got %v", want, triageSortedSlotKeys(slots))
			}
		}
		if k["body:/symbol"].Encoder != triage.EncodeJSONString {
			t.Errorf("leaf encoder = %s, want json_string", k["body:/symbol"].Encoder)
		}
		if k["body:/symbol:node"].Encoder != triage.EncodeJSONNodeReplace {
			t.Errorf("node encoder = %s, want json_node_replace: replacing a scalar with an object is a different sink from editing a string", k["body:/symbol:node"].Encoder)
		}
		if k["body:/filters/status"].FieldPath != "/filters/status" {
			t.Errorf("field path = %q, want the RFC 6901 pointer", k["body:/filters/status"].FieldPath)
		}
	})

	t.Run("form body indexes repeated names", func(t *testing.T) {
		slots, _ := SlotsFor(triageVectorRow{ID: "f", Method: "POST", InsertionPoint: triage.KindBody,
			RawRequest: []byte("POST /o HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" +
				"a=1&a=2&b=3")}, triage.SlotEvidence{})
		k := keys(slots)
		for _, want := range []triage.SlotKey{"body:a", "body:a[1]", "body:b"} {
			if _, ok := k[want]; !ok {
				t.Errorf("no slot %q; got %v. a=1&a=2 is two sinks and which one the application reads is the whole HPP bug", want, triageSortedSlotKeys(slots))
			}
		}
	})

	t.Run("multipart gives three slots per part", func(t *testing.T) {
		body := "--X\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\n" +
			"Content-Type: image/png\r\n\r\nPNGDATA\r\n--X--\r\n"
		slots, _ := SlotsFor(triageVectorRow{ID: "m", Method: "POST", InsertionPoint: triage.KindBody,
			RawRequest: []byte("POST /u HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=X\r\n\r\n" + body)},
			triage.SlotEvidence{})
		k := keys(slots)
		for _, want := range []triage.SlotKey{"body:file", "body:file.filename", "body:file.content-type"} {
			if _, ok := k[want]; !ok {
				t.Errorf("no slot %q; got %v. The filename and the part Content-Type are where the upload bypasses live", want, triageSortedSlotKeys(slots))
			}
		}
		if k["body:file.filename"].Value != "a.png" {
			t.Errorf("filename slot value = %q, want a.png", k["body:file.filename"].Value)
		}
		if k["body:file.filename"].Encoder != triage.EncodeMultipartName {
			t.Errorf("filename encoder = %s, want multipart_filename", k["body:file.filename"].Encoder)
		}
	})

	t.Run("header adds the always-inferred set and flags credentials", func(t *testing.T) {
		slots, _ := SlotsFor(triageVectorRow{ID: "h", Method: "GET", InsertionPoint: triage.KindHeader,
			RawRequest: []byte("GET / HTTP/1.1\r\nX-Tenant: acme\r\nAuthorization: Bearer s\r\n\r\n"),
			Parameters: []string{"X-Tenant", "Authorization"}}, triage.SlotEvidence{})
		k := keys(slots)
		if got, ok := k["header:x-tenant"]; !ok || got.Value != "acme" {
			t.Errorf("header:x-tenant = %q (present %v), want acme. Header names are case-insensitive, so the key is lowercased", got.Value, ok)
		}
		if !k["header:authorization"].Constraints.IsCredential {
			t.Error("Authorization was not flagged as a credential. Injecting into it produces a 401, and that 401 is a differential that looks exactly like a finding")
		}
		for _, want := range []triage.SlotKey{"header:x-forwarded-for", "header:x-original-url", "header:referer", "header:origin"} {
			if _, ok := k[want]; !ok {
				t.Errorf("no slot %q. Absence from a crawl says nothing about reachability, and these reach the application on essentially every deployment", want)
			}
		}
		if k["header:x-forwarded-for"].Origin != triage.SlotInferred {
			t.Error("an always-inferred header was not marked inferred, so an operator cannot filter it out")
		}
	})

	t.Run("cookie emits credentials rather than dropping them", func(t *testing.T) {
		slots, _ := SlotsFor(triageVectorRow{ID: "c", Method: "GET", InsertionPoint: triage.KindCookie,
			RawRequest: []byte("GET / HTTP/1.1\r\nCookie: session_theme=dark; sid=abc; _ga=GA1.2\r\n\r\n"),
			Parameters: []string{"session_theme", "sid", "_ga"}}, triage.SlotEvidence{})
		k := keys(slots)
		if len(k) != 3 {
			t.Fatalf("got %d cookie slots, want 3: %v", len(k), triageSortedSlotKeys(slots))
		}
		if !k["cookie:sid"].Constraints.IsCredential {
			t.Error("sid was not flagged as a credential")
		}
		if k["cookie:_ga"].Constraints.IsCredential {
			t.Error("an analytics cookie was flagged as a credential, which would stop it being probed for no reason")
		}
		if k["cookie:_ga"].Encoder != triage.EncodeCookie {
			t.Errorf("cookie encoder = %s, want the hand-built one. http.Cookie drops the semicolon, the double quote and the backslash, which are the SQL injection probe characters", k["cookie:_ga"].Encoder)
		}
		if k["cookie:session_theme"].Value != "dark" {
			t.Errorf("cookie:session_theme value = %q, want dark", k["cookie:session_theme"].Value)
		}
	})

	t.Run("fragment slots are emitted and marked unreachable", func(t *testing.T) {
		slots, _ := SlotsFor(triageVectorRow{ID: "fr", Method: "GET", InsertionPoint: triage.KindFragment,
			ComposedURL: "https://h.example.com/s#access_token=x&token_type=bearer"}, triage.SlotEvidence{})
		k := keys(slots)
		if _, ok := k["fragment:access_token"]; !ok {
			t.Fatalf("no fragment:access_token slot; got %v", triageSortedSlotKeys(slots))
		}
		for _, s := range slots {
			if s.ServerReachable {
				t.Errorf("fragment slot %s reported server-reachable. Every browser strips the fragment before the request goes out, so an HTTP-level class must say not_applicable and never clean", s.Key)
			}
		}
		// A path-shaped fragment is still one slot rather than none.
		slots, _ = SlotsFor(triageVectorRow{ID: "fr2", InsertionPoint: triage.KindFragment,
			ComposedURL: "https://h.example.com/s#/billing"}, triage.SlotEvidence{})
		if len(slots) != 1 || slots[0].Key != "fragment:*" {
			t.Errorf("a path-shaped fragment produced %v, want one fragment:* slot", triageSortedSlotKeys(slots))
		}
	})

	t.Run("a body with nothing captured is a note and never a zero", func(t *testing.T) {
		_, notes := SlotsFor(triageVectorRow{ID: "b0", InsertionPoint: triage.KindBody}, triage.SlotEvidence{})
		if len(notes) != 1 || notes[0].Reason != "no_body_captured" {
			t.Errorf("notes = %v, want exactly no_body_captured", notes)
		}
	})
}

// DeriveCorpusSlots is the caller AssertSlotCoverage never had, and it refuses the run rather than
// logging a warning.
//
// A warning in a log is exactly how the path insertion point shipped a zero against 51 vectors and
// had every one of them recorded as tested.
func TestDeriveCorpusSlotsRefusesASilentZero(t *testing.T) {
	// 51 path vectors whose composed URL has no parsable path at all: the derivation produces
	// notes and no slots, which per-vector is correct and corpus-wide is the bug.
	var rows []triageVectorRow
	for i := 0; i < 51; i++ {
		rows = append(rows, triageVectorRow{ID: "p" + strconv.Itoa(i), InsertionPoint: triage.KindPath,
			ComposedURL: "not-a-url"})
	}
	rows = append(rows, triageVectorRow{ID: "q0", InsertionPoint: triage.KindQuery,
		ComposedURL: "https://h.example.com/s?a=1"})

	slots, notes, err := DeriveCorpusSlots(rows, nil)
	if err == nil {
		t.Fatal("51 path vectors producing 0 path slots was accepted, which records all 51 as tested")
	}
	if !strings.Contains(err.Error(), "path has 51 vectors and 0 slots") {
		t.Errorf("error %q does not name the insertion point and the counts", err)
	}
	// The slots and notes come back with the error, because an operator looking at a refused run
	// needs to see what the derivation did produce.
	if len(notes) == 0 {
		t.Error("the refusal came back with no notes, so there is nothing to diagnose it from")
	}
	if len(slots) == 0 {
		t.Error("the refusal came back with no slots at all, including the query vector's, so the partial result is not usable for diagnosis")
	}

	// And a corpus with slots everywhere is accepted.
	good, evidence := triageCorpusRows()
	if _, _, err := DeriveCorpusSlots(good, evidence); err != nil {
		t.Errorf("the measured corpus was refused: %v", err)
	}
}

func triageSortedSlotKeys(slots []triage.Slot) []string {
	out := make([]string, 0, len(slots))
	for _, s := range slots {
		out = append(out, string(s.Key))
	}
	sort.Strings(out)
	return out
}

// triageSourceWithoutComments returns a file's source with every comment removed.
//
// THE SCAN HAS TO IGNORE COMMENTS, and the reason is the same one the encoder's mangling guard
// gives: the files that explain a trap name it, so a raw grep fires on the warning instead of on
// the mistake. triage/types.go DESCRIBES why the parameters column may not be read a second time,
// which under a raw grep made it an offender. Parsing and reprinting without comments is the only
// way to scan for the mistake and not for the documentation of the mistake.
func triageSourceWithoutComments(t *testing.T, path string) string {
	t.Helper()
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, path, nil, 0) // mode 0 drops comments, which is the point
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, parsed); err != nil {
		t.Fatalf("print %s: %v", path, err)
	}
	return buf.String()
}
