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

// ---------------------------------------------------------------------------------------------
// The templated-name dedupe, and the three dedupes the derivation refuses
//
// MEASURED ON THE OPERATOR'S LIVE RUN a218419a, 3,450 slots over 216 vectors, read out of Postgres:
//
//	kind   | slots | distinct names | vectors | distinct (host, method, path)
//	cookie |  2068 |             31 |      75 |                            73
//	header |   931 |             19 |      49 |                            49
//
// 560 of the 2,068 cookie slots carry an unresolved {uuid} in the NAME and all 560 have their
// concrete twin on the same vector, carrying an observed value. Those are the ones deduped. The
// rest is 31 names against 73 distinct endpoints and 19 names against 49 distinct endpoints,
// which is not replication, and the tests below hold that line so a later optimisation cannot
// quietly cross it.
// ---------------------------------------------------------------------------------------------

// triageCognitoRawRequest is the live cookie capture's shape: concrete Cognito cookies on the
// wire, with the pool and subject replaced by neutral text.
func triageCognitoRawRequest() []byte {
	return []byte("GET /api/v1/accounts HTTP/1.1\r\nHost: h.example.com\r\n" +
		"Cookie: CognitoIdentityServiceProvider.poolabc123.d4887448-50b1-7015-03be-6b285cf9fb5e.accessToken=eyJraWQ; " +
		"CognitoIdentityServiceProvider.poolabc123.d4887448-50b1-7015-03be-6b285cf9fb5e.userData=%7B%22a%22%3A1%7D; " +
		"CognitoIdentityServiceProvider.poolabc123.LastAuthUser=d4887448-50b1-7015-03be-6b285cf9fb5e; " +
		"AMP_d6814239bf=JTdCJTIy\r\n\r\n")
}

func TestTemplatedCookieNameIsCoveredByItsConcreteTwinOnTheSameVector(t *testing.T) {
	row := triageVectorRow{ID: "v1", Method: "GET", InsertionPoint: triage.KindCookie,
		ComposedURL: "https://h.example.com/api/v1/accounts",
		RawRequest:  triageCognitoRawRequest(),
		Parameters: []string{
			"CognitoIdentityServiceProvider.poolabc123.{uuid}.accessToken",
			"CognitoIdentityServiceProvider.poolabc123.{uuid}.userData",
			"CognitoIdentityServiceProvider.poolabc123.LastAuthUser",
			"AMP_d6814239bf",
		}}
	slots, notes := SlotsFor(row, triage.SlotEvidence{})

	for _, s := range slots {
		if strings.Contains(string(s.Key), "{") {
			t.Errorf("slot %q survived: no client ever sent a cookie whose NAME contains a %q placeholder, "+
				"so the probe goes out under a name that does not exist and its answer is already being "+
				"asked by the concrete twin one slot over on the same request", s.Key, "{uuid}")
		}
	}

	// The concrete cookies are all still there. The dedupe must never cost a real name.
	k := map[triage.SlotKey]bool{}
	for _, s := range slots {
		k[s.Key] = true
	}
	for _, want := range []triage.SlotKey{
		"cookie:CognitoIdentityServiceProvider.poolabc123.d4887448-50b1-7015-03be-6b285cf9fb5e.accessToken",
		"cookie:CognitoIdentityServiceProvider.poolabc123.d4887448-50b1-7015-03be-6b285cf9fb5e.userData",
		"cookie:CognitoIdentityServiceProvider.poolabc123.LastAuthUser",
		"cookie:AMP_d6814239bf",
	} {
		if !k[want] {
			t.Errorf("no slot %q; got %v", want, triageSortedSlotKeys(slots))
		}
	}
	if len(slots) != 4 {
		t.Errorf("slots = %d, want 4. Live shape: 28 cookies per vector of which 8 are templated", len(slots))
	}

	// EVERY DROPPED SLOT NAMES ITS COVER. A slot that disappears without a record is a coverage
	// lie, which is the exact failure this layer exists to prevent, and it is worse than the
	// request it saved.
	covered := 0
	for _, n := range notes {
		if !strings.HasPrefix(n.Reason, "name_is_the_unresolved_template_of_") {
			continue
		}
		covered++
		if n.VectorID != "v1" || n.Kind != triage.KindCookie {
			t.Errorf("note %+v does not point at the vector that lost the slot", n)
		}
		if !strings.Contains(n.Reason, "d4887448-50b1-7015-03be-6b285cf9fb5e") {
			t.Errorf("note %q does not name the slot that carries the probe instead", n.Reason)
		}
	}
	if covered != 2 {
		t.Errorf("cover notes = %d, want 2, one per dropped slot; notes = %v", covered, notes)
	}
}

func TestATemplatedNameWithNoConcreteTwinIsKeptAndSaidToBeUnresolved(t *testing.T) {
	// FAIL OPEN. An unmatched template is a name the corpus believes in, and dropping it is the
	// silent zero. Measured on the live corpus: zero such cases today, which is exactly when the
	// guard is cheap to add and impossible to notice missing.
	row := triageVectorRow{ID: "v2", Method: "GET", InsertionPoint: triage.KindCookie,
		ComposedURL: "https://h.example.com/x",
		RawRequest:  []byte("GET /x HTTP/1.1\r\nCookie: other=1\r\n\r\n"),
		Parameters:  []string{"prefix.{uuid}.suffix"}}
	slots, notes := SlotsFor(row, triage.SlotEvidence{})

	var found bool
	for _, s := range slots {
		if s.Key == "cookie:prefix.{uuid}.suffix" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the templated slot was dropped with nothing on this vector covering it; got %v",
			triageSortedSlotKeys(slots))
	}
	var noted bool
	for _, n := range notes {
		if strings.Contains(n.Reason, "unresolved_template_and_no_concrete_form") {
			noted = true
		}
	}
	if !noted {
		t.Errorf("kept the slot without saying the name is unresolved, so a clean here would read as a "+
			"measured clean; notes = %v", notes)
	}
}

func TestABareTemplatePlaceholderDoesNotAbsorbEveryCookieOnTheRequest(t *testing.T) {
	// A bare placeholder reduces to "match anything". Absorbing a slot into the wrong cover is the
	// same false negative as dropping it, so a pattern with no literal text of its own is refused
	// and keeps its slot.
	row := triageVectorRow{ID: "v3", Method: "GET", InsertionPoint: triage.KindCookie,
		ComposedURL: "https://h.example.com/x",
		RawRequest:  []byte("GET /x HTTP/1.1\r\nCookie: sid=abc; other=1\r\n\r\n"),
		Parameters:  []string{"{uuid}"}}
	slots, _ := SlotsFor(row, triage.SlotEvidence{})
	var found bool
	for _, s := range slots {
		if s.Key == "cookie:{uuid}" {
			found = true
		}
	}
	if !found {
		t.Errorf("a bare placeholder was absorbed by an unrelated cookie; got %v", triageSortedSlotKeys(slots))
	}
}

func TestTemplatedHeaderNameIsCoveredByItsConcreteTwin(t *testing.T) {
	row := triageVectorRow{ID: "v4", Method: "GET", InsertionPoint: triage.KindHeader,
		ComposedURL: "https://h.example.com/x",
		RawRequest:  []byte("GET /x HTTP/1.1\r\nX-Tenant-abc123-Key: v\r\n\r\n"),
		Parameters:  []string{"X-Tenant-abc123-Key", "X-Tenant-{token}-Key"}}
	slots, notes := SlotsFor(row, triage.SlotEvidence{})
	for _, s := range slots {
		if strings.Contains(string(s.Key), "{") {
			t.Errorf("templated header slot %q survived beside its concrete twin", s.Key)
		}
	}
	var covered bool
	for _, n := range notes {
		if strings.Contains(n.Reason, "header:x-tenant-abc123-key") {
			covered = true
		}
	}
	if !covered {
		t.Errorf("no note names the header slot that carries the probe instead; notes = %v", notes)
	}
}

func TestTheSameCookieNameOnDifferentVectorsIsNotDeduped(t *testing.T) {
	// THE DEDUPE THIS DERIVATION REFUSES, AND WHY.
	//
	// It looks like 85% replication: 31 cookie names over 2,068 slots. It is not. The 75 cookie
	// vectors on the live corpus are 75 different endpoints, 73 distinct (host, method, path):
	// /api/v1/accounts/{uuid}/details, /api/v1/oauth/clients/{token}/secret, /internal/clock,
	// /verify. Probing AMP_d6814239bf on 69 of them does not test one thing 69 times, it asks 69
	// different handlers whether they read that cookie, and a cookie read by one endpoint and
	// ignored by another is the normal case. Probing one and recording the other 72 as covered is
	// a coverage lie with a false negative under it.
	raw := []byte("GET /x HTTP/1.1\r\nCookie: _gcl_au=1.1.2\r\n\r\n")
	rows := []triageVectorRow{
		{ID: "e1", Method: "GET", InsertionPoint: triage.KindCookie,
			ComposedURL: "https://h.example.com/api/v1/accounts", RawRequest: raw},
		{ID: "e2", Method: "GET", InsertionPoint: triage.KindCookie,
			ComposedURL: "https://h.example.com/internal/clock", RawRequest: raw},
	}
	slots, notes, err := DeriveCorpusSlots(rows, map[string]triage.SlotEvidence{})
	if err != nil {
		t.Fatalf("DeriveCorpusSlots: %v", err)
	}
	if len(slots) != 2 {
		t.Fatalf("corpus slots = %d, want 2. _gcl_au on /api/v1/accounts and _gcl_au on /internal/clock "+
			"are two different handlers being asked the same question, not one question asked twice: "+
			"%v (notes %v)", len(slots), triageSortedSlotKeys(slots), notes)
	}
	byVector := map[string]int{}
	for _, s := range slots {
		byVector[s.VectorID]++
	}
	if byVector["e1"] != 1 || byVector["e2"] != 1 {
		t.Errorf("one endpoint lost its coverage row to the other: %v", byVector)
	}
}

func TestTheInferredHeaderSetIsNotDedupedAcrossVectors(t *testing.T) {
	// Measured: all 49 header vectors on the live corpus are 49 distinct endpoints, so the
	// replication factor on that axis is exactly 1. X-Forwarded-For against /account/login and
	// against /api/v1/paper_accounts/{uuid}/orders are different ACL decisions by different code.
	rows := []triageVectorRow{
		{ID: "h1", Method: "GET", InsertionPoint: triage.KindHeader, ComposedURL: "https://h.example.com/account/login"},
		{ID: "h2", Method: "GET", InsertionPoint: triage.KindHeader, ComposedURL: "https://h.example.com/api/v1/orders"},
	}
	slots, _, err := DeriveCorpusSlots(rows, map[string]triage.SlotEvidence{})
	if err != nil {
		t.Fatalf("DeriveCorpusSlots: %v", err)
	}
	xff := 0
	for _, s := range slots {
		if s.Key == "header:x-forwarded-for" {
			xff++
		}
	}
	if xff != len(rows) {
		t.Errorf("x-forwarded-for slots = %d over %d endpoints, want one each: an endpoint that lost its "+
			"slot to another endpoint's probe was never tested and is recorded as covered", xff, len(rows))
	}
}

func TestTemplateLiteralMatchingIsAnchoredAndNotARegexp(t *testing.T) {
	// The literals come from a target's own cookie names. Compiling those as a pattern is how a
	// name carrying a "." or a "+" silently matches something else.
	cases := []struct {
		pattern, candidate string
		want               bool
		why                string
	}{
		{"a.{uuid}.accessToken", "a.d4887448.accessToken", true, "the measured case"},
		{"a.{uuid}.accessToken", "a.d4887448.refreshToken", false, "a different tail is a different cookie"},
		{"a.{uuid}.deviceKey", "a.d4887448.deviceGroupKey", false, "deviceGroupKey is not deviceKey"},
		{"a.{uuid}.k", "a..k", false, "the placeholder has to swallow at least one character"},
		{"a.{x}.b.{y}.c", "a.1.b.2.c", true, "two placeholders in order"},
		{"a.{x}.b.{y}.c", "a.1.c", false, "a middle literal that is not there"},
		{"x+y{z}", "xAy1", false, "+ is a literal, not a quantifier"},
		{"pre{z}", "prefix", true, "a trailing placeholder with an empty tail"},
		{"pre{z}", "pre", false, "an empty match is not a match"},
	}
	for _, c := range cases {
		literals, ok := triageTemplateLiterals(c.pattern)
		got := ok && triageTemplateLiteralsMatch(literals, c.candidate)
		if got != c.want {
			t.Errorf("%q vs %q = %v, want %v (%s)", c.pattern, c.candidate, got, c.want, c.why)
		}
	}
	if _, ok := triageTemplateLiterals("{uuid}"); ok {
		t.Error("a pattern with no literal text of its own was accepted; it matches anything")
	}
	if triageNameCarriesTemplate("plain.name") {
		t.Error("a name with no placeholder was read as templated")
	}
}

// ---------------------------------------------------------------------------------------------
// R5. THE CREDENTIAL RULE, AND THE SLOTS IT WAS REFUSING BY ACCIDENT
// ---------------------------------------------------------------------------------------------

// The credential rule must not match a credential word INSIDE another word.
//
// MEASURED, live run a218419a on the engaged estate. The rule was fifteen strings.Contains calls,
// and one of them was "identity". Every cookie in the CognitoIdentityServiceProvider family
// therefore matched on the product's NAME rather than on anything it holds, so four leaves that
// carry no secret at all were refused as credentials and never probed:
//
//	.clockDrift       a clock offset in seconds
//	.deviceKey        a device identifier
//	.deviceGroupKey   a device group identifier
//	.userData         a JSON blob of username and attributes
//
// 4 names on 70 vectors each, 280 slots, never sent a byte and recorded with is_credential rather
// than with a verdict. A credential slot correctly refused is good. A real slot wrongly refused is
// a missed bug, and this is the false-negative door the whole layer exists to close.
//
// The other over-broad matches in the same rule, each of which refuses a probeable slot on a name
// a real application uses, are in the table below. They are reachable on any target, not only
// this one, which is why the fix is the matching rule and not a patch to one needle.
func TestTheCredentialRuleDoesNotMatchAWordInsideAnotherWord(t *testing.T) {
	const cognito = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.d4887448-50b1-7015-03be-6b285cf9fb5e."

	cases := []struct {
		name string
		want bool
		why  string
	}{
		// The measured false negatives, in the exact live spelling.
		{cognito + "clockDrift", false, "a clock offset is not a credential; it matched on identity inside the product name"},
		{cognito + "deviceKey", false, "a device identifier is not a credential; same accidental match"},
		{cognito + "deviceGroupKey", false, "a device group identifier is not a credential; same accidental match"},
		{cognito + "userData", false, "a username blob is not a secret; same accidental match"},
		// The same family's leaves that DO hold the secret must stay refused.
		{cognito + "accessToken", true, "the access token is the session"},
		{cognito + "idToken", true, "the id token is the session"},
		{cognito + "refreshToken", true, "the refresh token mints sessions"},
		{cognito + "randomPasswordKey", true, "the device password"},
		{"CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.LastAuthUser", true, "auth is a whole word here"},

		// Over-broad matches reachable on any target. Each of these was refused by the old rule.
		{"author_id", false, "auth inside author: an author id is an IDOR slot, not a credential"},
		{"authority", false, "auth inside authority"},
		{"resident_id", false, "sid inside resident"},
		{"subsidiary_id", false, "sid inside subsidiary"},
		{"consider_flag", false, "sid inside consider"},
		{"inside_track", false, "sid inside inside"},
		{"sidebar_state", false, "sid inside sidebar"},
		{"assessment_id", false, "sess inside assessment"},
		{"assessor", false, "sess inside assessor"},
		{"identity_provider", false, "an identity names a subject, not a secret, and this is a probeable slot"},
		{"login_redirect", false, "a login redirect is an open-redirect slot; login names a subject, not a secret"},
		{"login_hint", false, "same"},
		{"passwordless_enabled", false, "password inside passwordless: a feature flag"},
		{"remembered_filters", false, "remember inside remembered"},

		// True positives that must survive the tightening. These are the reason the rule exists.
		{"PHPSESSID", true, "the canonical run-together session cookie"},
		{"JSESSIONID", true, "same, Java"},
		{"ASP.NET_SessionId", true, "same, .NET"},
		{"TAsessionID", true, "a run-together name from the corpus"},
		{"connect.sid", true, "express-session"},
		{"laravel_session", true, "framework session"},
		{"_csrf", true, "csrf token"},
		{"csrf_token", true, "csrf token"},
		{"XSRF-TOKEN", true, "angular csrf token"},
		{"__RequestVerificationToken", true, "asp.net anti-forgery token"},
		{"access_token", true, "bearer material"},
		{"refresh_token", true, "bearer material"},
		{"id_token", true, "bearer material"},
		{"auth", true, "a whole word"},
		{"sid", true, "a whole word"},
		{"sess", true, "a whole word"},
		{"__stripe_sid", true, "a session id, whole word"},
		{"intercom-session-p7a9jdob", true, "a session, whole word"},
		{"ai_session", true, "a session, whole word"},
		{"remember_me", true, "a whole word"},
		{"api_key", true, "api key"},
		{"apiKey", true, "api key, camel"},
		{"client_secret", true, "a secret"},
		{"oauth_state", true, "oauth is a whole word and the old rule caught it through auth"},
		{"jwt", true, "a whole word"},
		{"user_password", true, "a whole word"},
		{"passwd", true, "a whole word"},
		{"Bearer", true, "a whole word"},
		{"MFAdeviceToken", true, "token is a whole word"},

		// Names on the live corpus that must stay probeable.
		{"AMP_d6814239bf", false, "analytics, and not a credential by name"},
		{"_gcl_au", false, "au is not auth"},
		{"_rdt_uuid", false, "not a credential by name"},
		{"__stripe_mid", false, "mid is not sid"},
		{"intercom-device-id-p7a9jdob", false, "a device id is not a session"},
		{"amplify-signin-with-hostedUI", false, "a boolean flag read by the browser"},
		{"cf_clearance", false, "not a credential by name"},
		{"notice_gdpr_prefs", false, "a preference"},
	}

	for _, c := range cases {
		if got := triageCredentialCookie(c.name, ""); got != c.want {
			t.Errorf("triageCredentialCookie(%q) = %v, want %v: %s", c.name, got, c.want, c.why)
		}
	}
}

// A cookie or header whose VALUE is a compact JWS is a credential whatever it is called.
//
// This is the half that makes tightening the name rule safe. Cognito names its cookies per user
// pool and a target using a name nobody listed would otherwise be probed with its own session
// thrown away, which produces a 401 that is a perfect differential against baseline and looks
// exactly like a finding. The same net already guards the reflection probe
// (reflectionValueLooksLikeJWT, which this reuses rather than copying), and it is a SHAPE test:
// three base64url segments and a JOSE header prefix, never a decode and never a comparison
// against held material.
func TestAJWTValuedSlotIsACredentialWhateverItIsCalled(t *testing.T) {
	const jws = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	if !triageCredentialCookie("prefs_blob", jws) {
		t.Error("a cookie holding a JWS was not refused; a probe here throws the session away")
	}
	if !triageCredentialHeader("x-company-context", jws) {
		t.Error("a header holding a JWS was not refused")
	}
	if triageCredentialCookie("prefs_blob", "eyJhbGciOiJIUzI1NiJ9") {
		t.Error("a single base64 segment is not a JWS and must stay probeable")
	}
	if triageCredentialCookie("prefs_blob", "a.b.c") {
		t.Error("three short segments are not a JWS")
	}
	if triageCredentialHeader("referer", "https://example.test/a.b.c") {
		t.Error("a URL is not a JWS")
	}
}

// The header credential rule stays an EXACT name list and does not inherit the substring match.
//
// Its failure mode is the opposite one: a header wrongly refused loses coverage on exactly the
// slots that pay (x-forwarded-for, x-original-url), so it is deliberately narrow. This pins that
// the tightening of the cookie rule did not leak into it.
func TestTheHeaderCredentialRuleRefusesOnlyTheCredentialHeaders(t *testing.T) {
	for _, n := range []string{"authorization", "proxy-authorization", "cookie", "x-api-key",
		"api-key", "x-auth-token", "x-access-token", "x-session-token", "authentication",
		"x-csrf-token", "x-xsrf-token", "x-amz-security-token"} {
		if !triageCredentialHeader(n, "") {
			t.Errorf("header %q is a credential and was not refused", n)
		}
	}
	for _, n := range []string{"x-forwarded-for", "x-forwarded-host", "x-original-url",
		"x-rewrite-url", "referer", "origin", "user-agent", "accept-language", "true-client-ip",
		"cf-connecting-ip", "x-http-method-override", "x-request-id", "x-real-ip", "forwarded",
		"x-author", "x-session-affinity"} {
		if triageCredentialHeader(n, "") {
			t.Errorf("header %q is probeable and was refused as a credential", n)
		}
	}
}

// The tokeniser cuts a name the way a human reads it, including run-together and camel forms.
func TestCredentialNameTokenising(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"CognitoIdentityServiceProvider.7cd3.d4887448.clockDrift",
			[]string{"cognito", "identity", "service", "provider", "7", "cd", "3", "d", "4887448", "clock", "drift"}},
		{"__RequestVerificationToken", []string{"request", "verification", "token"}},
		{"ASP.NET_SessionId", []string{"asp", "net", "session", "id"}},
		{"_gcl_au", []string{"gcl", "au"}},
		{"XSRF-TOKEN", []string{"xsrf", "token"}},
		{"remember_me", []string{"remember", "me"}},
		{"", nil},
	}
	for _, c := range cases {
		got := triageNameTokens(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("triageNameTokens(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// The live corpus, end to end: the four Cognito leaves that hold no secret become probeable slots
// and every leaf that holds one stays refused.
//
// It is the derivation and not the predicate, because the predicate being right is worth nothing
// if triageCookieSlots stops calling it.
func TestTheFourHarmlessCognitoLeavesBecomeProbeableSlots(t *testing.T) {
	const pool = "CognitoIdentityServiceProvider.7cd3keuknr18mv2boiaesbgce3.d4887448-50b1-7015-03be-6b285cf9fb5e"
	names := []string{"clockDrift", "deviceKey", "deviceGroupKey", "userData",
		"accessToken", "idToken", "refreshToken", "randomPasswordKey"}
	var jar []string
	for _, n := range names {
		jar = append(jar, pool+"."+n+"=x")
	}
	raw := "GET /api/v1/account HTTP/1.1\r\nHost: app.staging-v2.tradetalk.us\r\n" +
		"Cookie: " + strings.Join(jar, "; ") + "\r\n\r\n"

	slots, _ := SlotsFor(triageVectorRow{
		ID: "v1", Method: "GET", ComposedURL: "https://app.staging-v2.tradetalk.us/api/v1/account",
		InsertionPoint: triage.KindCookie, RawRequest: []byte(raw),
	}, triage.SlotEvidence{})

	cred := map[string]bool{}
	for _, s := range slots {
		cred[strings.TrimPrefix(s.Name, pool+".")] = s.Constraints.IsCredential
	}
	if len(cred) != len(names) {
		t.Fatalf("derived %d cookie slots, want %d: %v", len(cred), len(names), cred)
	}
	for _, n := range []string{"clockDrift", "deviceKey", "deviceGroupKey", "userData"} {
		if cred[n] {
			t.Errorf("%s is refused as a credential and never probed; it holds no secret", n)
		}
	}
	for _, n := range []string{"accessToken", "idToken", "refreshToken", "randomPasswordKey"} {
		if !cred[n] {
			t.Errorf("%s is the session and must stay refused", n)
		}
	}
}
