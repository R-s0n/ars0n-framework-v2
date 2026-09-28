package utils

import (
	"ars0n-framework-v2-server/utils/triage"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"unicode"
	"unicode/utf8"
)

// Tests for the marker mechanism.
//
// The isolation law is the thing under test here, not a property of it. A marker that one class
// emitted must be a hit for NOBODY else, and the test that proves it walks all 27 class ordinals
// in both directions rather than sampling two of them. The transform tests are the other half:
// every transform in the requirement set is exercised with a real minted marker and a real
// checksum, because a search routine that has only ever been run against the raw form has not
// been shown to survive anything.

const markerTestRunID = "1f3q"

// ---------------------------------------------------------------------------------------------
// MINTING AND THE STRIPE
// ---------------------------------------------------------------------------------------------

func TestAMintedMarkerIsWellFormedAndAttributesToItsOwner(t *testing.T) {
	for _, c := range triage.AllClassIDs() {
		m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, c, uint64(c))
		if err != nil {
			t.Fatalf("minting for %s: %v", c, err)
		}
		if !m.WellFormed() {
			t.Errorf("%s minted %q, which is not well formed", c, m)
		}
		if len(m) != triage.MarkerLen {
			t.Errorf("%s minted %q of length %d, want %d", c, m, len(m), triage.MarkerLen)
		}
		if got := m.RunID(); got != markerTestRunID {
			t.Errorf("%s minted %q whose run id reads %q, want %q", c, m, got, markerTestRunID)
		}
		if !m.BelongsTo(c) {
			owner, _ := m.ClassID()
			t.Errorf("%s minted %q which attributes to %s instead", c, m, owner)
		}
		if got := triage.VerifyMarkerIntegrity(m); got != triage.MarkerValid {
			t.Errorf("%s minted %q whose checksum reads %q, want valid", c, m, got)
		}
	}
}

// The isolation law, executable. Every class mints a marker; every other class is asked about it;
// the answer is never yes.
func TestAForeignMarkerIsAHitForNobodyAcrossEveryClassStripe(t *testing.T) {
	classes := triage.AllClassIDs()
	// 29 real classes plus ClassExample, the id reserved for the placeholder classifier so that it
	// does not squat on a real one. The count is asserted because this test's coverage claim is
	// "every declared stripe", and a class quietly added or removed would shrink that claim
	// without shrinking the passing result.
	//
	// It was 28 while the register held the original 27. CORS took id 28 and ORM-LEAK took 29,
	// both after CATALOGUE 1.0 was written and both with their reasoning in the const block in
	// triage/types.go. Updating this number is the deliberate act the assertion is asking for.
	if len(classes) != 30 {
		t.Fatalf("expected the 29 declared classes plus the reserved example id, got %d; this test's coverage claim depends on that count", len(classes))
	}

	minted := map[triage.ClassID]triage.Marker{}
	for _, c := range classes {
		m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, c, uint64(c)+3*triage.ClassStripeModulus)
		if err != nil {
			t.Fatalf("minting for %s: %v", c, err)
		}
		minted[c] = m
	}

	for _, owner := range classes {
		body := []byte("<p>echo " + string(minted[owner]) + "</p>")
		sightings := ScanMarkers(body)
		if len(sightings) != 1 {
			t.Fatalf("%s: expected one sighting in its own body, got %d", owner, len(sightings))
		}

		for _, asker := range classes {
			a := AttributeMarkers(sightings, asker, markerTestRunID)
			if asker == owner {
				if !a.Verdict.IsHit() {
					t.Errorf("%s asked about its own marker and got %q", asker, a.Verdict)
				}
				continue
			}
			if a.Verdict.IsHit() {
				t.Errorf("%s claimed %s's marker %q as a hit", asker, owner, minted[owner])
			}
			if a.Verdict != MarkerVerdictForeign {
				t.Errorf("%s asked about %s's marker and got %q, want foreign", asker, owner, a.Verdict)
			}
			if len(a.Mine) != 0 {
				t.Errorf("%s put %s's marker in its own bucket", asker, owner)
			}
			if minted[owner].BelongsTo(asker) {
				t.Errorf("BelongsTo says %s's marker belongs to %s", owner, asker)
			}
		}
	}
}

func TestMintingRefusesAnOrdinalOutsideTheOwnersStripe(t *testing.T) {
	// Ordinal 24 is DESER's stripe. CATALOGUE 1.1's illustrative SSTI literal has exactly this
	// defect: its ordinal field decodes to 13016, and 13016 mod 64 is 24. Transcribing those
	// literals would attribute every SSTI marker to DESER, so the minter refuses.
	if _, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSSTI, 24); err == nil {
		t.Fatal("minted an SSTI marker on DESER's stripe without complaint")
	} else if !strings.Contains(err.Error(), "DESER") {
		t.Errorf("the refusal should name the class the ordinal actually belongs to, got %q", err)
	}

	if _, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassNone, 0); err == nil {
		t.Error("minted a marker for the unknown class id 0")
	}
	if _, err := triage.MintMarkerAt(triageRunnerCapability(), "nope!", triage.ClassSQL, 4); err == nil {
		t.Error("minted a marker with a malformed run id")
	}
	if _, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSQL, triage.MarkerOrdinalMax+triage.ClassStripeModulus); err == nil {
		t.Error("minted an ordinal too large for six base36 digits instead of refusing")
	}
}

func TestTheMinterNeverIssuesTheSameOrdinalTwiceUnderConcurrency(t *testing.T) {
	minter, err := NewMarkerMinter(markerTestRunID)
	if err != nil {
		t.Fatalf("NewMarkerMinter: %v", err)
	}

	const perClass = 20
	classes := triage.AllClassIDs()

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := map[triage.Marker]MintedMarker{}

	for _, c := range classes {
		for i := 0; i < perClass; i++ {
			wg.Add(1)
			go func(c triage.ClassID) {
				defer wg.Done()
				rec, err := minter.Mint(c, triage.ProbeID("p"), triage.SlotKey("s"))
				if err != nil {
					t.Errorf("Mint(%s): %v", c, err)
					return
				}
				mu.Lock()
				defer mu.Unlock()
				if prev, dup := got[rec.Marker]; dup {
					t.Errorf("marker %q issued twice, to ordinals %d and %d", rec.Marker, prev.Ordinal, rec.Ordinal)
				}
				got[rec.Marker] = rec
			}(c)
		}
	}
	wg.Wait()

	if len(got) != len(classes)*perClass {
		t.Fatalf("issued %d distinct markers, want %d", len(got), len(classes)*perClass)
	}
	for m, rec := range got {
		if !m.BelongsTo(rec.Class) {
			t.Errorf("marker %q was issued to %s but attributes elsewhere", m, rec.Class)
		}
	}
	if minter.Issued() != len(got) {
		t.Errorf("Issued reports %d, %d markers are in hand", minter.Issued(), len(got))
	}
}

func TestAMintedMarkerResolvesBackToTheProbeThatEmittedIt(t *testing.T) {
	minter, err := NewMarkerMinter(markerTestRunID)
	if err != nil {
		t.Fatalf("NewMarkerMinter: %v", err)
	}
	rec, err := minter.Mint(triage.ClassSQL, triage.ProbeID("sql-bool-01"), triage.SlotKey("v1#cookie:sid"))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}

	// The late-response case: a body arrives carrying the token and nothing else identifies it.
	back, ok := minter.Lookup(rec.Marker)
	if !ok {
		t.Fatalf("marker %q does not resolve back to its issue record", rec.Marker)
	}
	if back.ProbeID != "sql-bool-01" || back.SlotKey != "v1#cookie:sid" || back.Class != triage.ClassSQL {
		t.Errorf("resolved to probe %q slot %q class %s, want sql-bool-01 / v1#cookie:sid / SQL",
			back.ProbeID, back.SlotKey, back.Class)
	}

	unissued, _ := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSQL, 4+900*triage.ClassStripeModulus)
	if _, ok := minter.Lookup(unissued); ok {
		t.Errorf("a marker this minter never issued resolved to a probe record")
	}
}

func TestTheChecksumCatchesASingleFlippedCharacter(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassCMDI, uint64(triage.ClassCMDI))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	if triage.VerifyMarkerIntegrity(m) != triage.MarkerValid {
		t.Fatalf("a freshly minted marker %q did not verify", m)
	}

	// Flip one ordinal digit. The result is still sixteen well-formed bytes and still reads an
	// ordinal, which is exactly the case the checksum exists for: without it, this string would
	// be attributed to whatever class its new residue lands in.
	flipped := []byte(m)
	if flipped[12] == 'a' {
		flipped[12] = 'b'
	} else {
		flipped[12] = 'a'
	}
	bad := triage.Marker(flipped)
	if !bad.WellFormed() {
		t.Fatalf("expected %q to stay well formed so the checksum is what catches it", bad)
	}
	if got := triage.VerifyMarkerIntegrity(bad); got != triage.MarkerCorrupted {
		t.Errorf("a flipped marker %q verified as %q, want corrupted", bad, got)
	}

	if got := triage.VerifyMarkerIntegrity(triage.Marker("not a marker")); got != triage.MarkerCorrupted {
		t.Errorf("a non-marker verified as %q, want corrupted; unchecked would let it grade higher", got)
	}
}

func TestACorruptedMarkerInOurStripeIsAnUnknownAndNotAHit(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassXXE, uint64(triage.ClassXXE))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	broken := []byte(m)
	broken[15] = 'z' // checksum digit, so the ordinal and therefore the stripe are untouched
	if triage.Marker(broken) == m {
		broken[15] = 'y'
	}

	a := AttributeMarkers(ScanMarkers([]byte("x"+string(broken)+"x")), triage.ClassXXE, markerTestRunID)
	if a.Verdict.IsHit() {
		t.Errorf("a corrupted marker read as a hit")
	}
	if !a.Verdict.IsUnknown() {
		t.Errorf("a corrupted marker read as %q, which is not an unknown; it would be allowed to render as clean", a.Verdict)
	}
}

// ---------------------------------------------------------------------------------------------
// THE TRANSFORM SET
// ---------------------------------------------------------------------------------------------

func TestAMarkerSurvivesCaseFoldingEntitiesPercentEncodingAndAlphanumericFilters(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassXSSReflected, uint64(triage.ClassXSSReflected))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	raw := string(m)

	entities := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "&#%d;", s[i])
		}
		return b.String()
	}
	hexEntities := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "&#x%x;", s[i])
		}
		return b.String()
	}
	percent := func(s string) string {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			fmt.Fprintf(&b, "%%%02x", s[i])
		}
		return b.String()
	}

	cases := []struct {
		name string
		body string
		form string
		fold string
	}{
		{"raw in html text", "<p>hello " + raw + " world</p>", MarkerFormRaw, "none"},
		{"upper cased by the application", "<p>" + strings.ToUpper(raw) + "</p>", MarkerFormRaw, "upper"},
		{"title cased", "<p>" + strings.ToUpper(raw[:1]) + raw[1:] + "</p>", MarkerFormRaw, "title"},
		{"decimal character references", "<p>" + entities(raw) + "</p>", MarkerFormNCR, "none"},
		{"hex character references", "<p>" + hexEntities(raw) + "</p>", MarkerFormNCR, "none"},
		{"percent encoded", "location=/next?q=" + percent(raw), MarkerFormPercent, "none"},
		{"glued to surrounding alphanumerics by a filter", "prefix" + raw + "suffix", MarkerFormRaw, "none"},
		{"broken up with delimiters", "id=" + raw[:4] + "-" + raw[4:10] + "-" + raw[10:], MarkerFormSqueezed, "none"},
		{"inside a json string value", `{"echo":"` + raw + `"}`, MarkerFormRaw, "none"},
		{"inside an attribute value", `<input value="` + raw + `">`, MarkerFormRaw, "none"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sightings := ScanMarkers([]byte(tc.body))
			var found *MarkerSighting
			for i := range sightings {
				if sightings[i].Hit.Marker == m {
					found = &sightings[i]
					break
				}
			}
			if found == nil {
				t.Fatalf("marker %q not recovered from %q; sightings=%+v", m, tc.body, sightings)
			}
			if found.Completeness != MarkerComplete {
				t.Errorf("recovered as %q, want complete", found.Completeness)
			}
			if found.Integrity != triage.MarkerValid {
				t.Errorf("recovered with integrity %q, want valid", found.Integrity)
			}
			if found.Hit.Form != tc.form {
				t.Errorf("recorded form %q, want %q", found.Hit.Form, tc.form)
			}
			if found.Hit.CaseTransform != tc.fold {
				t.Errorf("recorded case transform %q, want %q", found.Hit.CaseTransform, tc.fold)
			}
			if found.Hit.Offset < 0 || found.Hit.Offset >= len(tc.body) {
				t.Errorf("offset %d is not inside the original body of %d bytes", found.Hit.Offset, len(tc.body))
			}
			a := AttributeMarkers(sightings, triage.ClassXSSReflected, markerTestRunID)
			if !a.Verdict.IsHit() {
				t.Errorf("the owner asked and got %q", a.Verdict)
			}
			if b := AttributeMarkers(sightings, triage.ClassSQL, markerTestRunID); b.Verdict.IsHit() {
				t.Errorf("SQL claimed an XSS-R marker recovered from the %s form", tc.form)
			}
		})
	}
}

func TestAMarkerSurvivesTruncationAtSixteenAndThirtyTwoCharacters(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSSTI, uint64(triage.ClassSSTI))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	// Prefix placement is the default for exactly this reason: a field that keeps the first 16 or
	// the first 32 bytes keeps a whole, attributable token.
	payload := string(m) + "{{7*7}}and-a-long-tail-that-will-be-cut"

	for _, limit := range []int{triage.MarkerLen, 32} {
		body := payload[:limit]
		a := AttributeMarkers(ScanMarkers([]byte(body)), triage.ClassSSTI, markerTestRunID)
		if !a.Verdict.IsHit() {
			t.Errorf("truncated at %d, the owner got %q instead of a hit", limit, a.Verdict)
		}
		if len(a.Mine) != 1 || a.Mine[0].Completeness != MarkerComplete {
			t.Errorf("truncated at %d, the sighting is %+v", limit, a.Mine)
		}
	}
}

// The requirement stated as its own test, because absent and truncated are the two answers this
// codebase has historically collapsed into one.
func TestATruncatedMarkerIsDistinguishableFromAnAbsentOne(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSSTI, uint64(triage.ClassSSTI))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}

	absent := AttributeMarkers(ScanMarkers([]byte("<p>nothing of ours here at all</p>")), triage.ClassSSTI, markerTestRunID)
	if absent.Verdict != MarkerVerdictAbsent {
		t.Fatalf("a body with no marker read %q, want absent", absent.Verdict)
	}
	if absent.Verdict.IsUnknown() {
		t.Error("absent is a measurement and must not read as an unknown, or every silent oracle becomes untested")
	}

	// Ten bytes: the anchor and the run id survived, three ordinal digits did, the rest did not.
	cut := string(m)[:10]
	partial := AttributeMarkers(ScanMarkers([]byte("<p>"+cut+"</p>")), triage.ClassSSTI, markerTestRunID)
	if partial.Verdict == MarkerVerdictAbsent {
		t.Fatal("a truncated marker read as absent, which is the false-clean this mechanism exists to prevent")
	}
	if partial.Verdict != MarkerVerdictTruncated {
		t.Errorf("a truncated marker read %q, want truncated_unattributable", partial.Verdict)
	}
	if !partial.Verdict.IsUnknown() {
		t.Error("truncated must be an unknown: the field ate part of the payload and nothing can be concluded")
	}
	if len(partial.Truncated) != 1 {
		t.Fatalf("expected one truncated sighting, got %d", len(partial.Truncated))
	}
	if got := partial.Truncated[0].Text; got != cut {
		t.Errorf("the truncated sighting kept %q, want %q; len(Text) is how the field limit gets measured", got, cut)
	}
	if partial.Truncated[0].ClassKnown {
		t.Error("ten bytes is not enough to read the six ordinal digits, so the class must be unknown rather than guessed")
	}

	// Three bytes of anchor on their own are noise, not a sighting.
	noise := AttributeMarkers(ScanMarkers([]byte("the band zqj played")), triage.ClassSSTI, markerTestRunID)
	if noise.Verdict != MarkerVerdictAbsent {
		t.Errorf("a bare anchor read %q; every page containing the anchor would become an unknown", noise.Verdict)
	}
}

func TestATruncatedMarkerFromAnotherRunIsNotThisRunsUnknown(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), "aaaa", triage.ClassSSTI, uint64(triage.ClassSSTI))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	a := AttributeMarkers(ScanMarkers([]byte(string(m)[:10])), triage.ClassSSTI, markerTestRunID)
	if a.Verdict != MarkerVerdictForeign {
		t.Errorf("a remnant carrying run id aaaa read %q during run %s, want foreign", a.Verdict, markerTestRunID)
	}
}

func TestAStaleRunIDReadsAsUnknownRatherThanAsAHit(t *testing.T) {
	old, err := triage.MintMarkerAt(triageRunnerCapability(), "aaaa", triage.ClassSQL, uint64(triage.ClassSQL))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	a := AttributeMarkers(ScanMarkers([]byte("cached page "+string(old))), triage.ClassSQL, "bbbb")
	if a.Verdict.IsHit() {
		t.Error("a body carrying a previous run's marker read as a hit for this run")
	}
	if a.Verdict != MarkerVerdictStaleRun {
		t.Errorf("got %q, want stale_run", a.Verdict)
	}
	if !a.Verdict.IsUnknown() {
		t.Error("stale_run must be an unknown: the body is cached or late and says nothing about this probe")
	}
}

func TestForeignSightingsAreReportedWithTheClassThatOwnsThem(t *testing.T) {
	sql, _ := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSQL, uint64(triage.ClassSQL))
	lfi, _ := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassLFI, uint64(triage.ClassLFI))

	a := AttributeMarkers(ScanMarkers([]byte(string(sql)+" and "+string(lfi))), triage.ClassCMDI, markerTestRunID)
	if a.Verdict != MarkerVerdictForeign {
		t.Fatalf("CMDI got %q from a body holding SQL's and LFI's markers", a.Verdict)
	}
	want := []triage.ClassID{triage.ClassSQL, triage.ClassLFI}
	if len(a.ForeignClasses) != 2 {
		t.Fatalf("expected the two owning classes to be named, got %v", a.ForeignClasses)
	}
	for _, w := range want {
		found := false
		for _, g := range a.ForeignClasses {
			if g == w {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is not in the reported foreign classes %v", w, a.ForeignClasses)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE VOCABULARY GUARD AND THE DECLARED GAPS
// ---------------------------------------------------------------------------------------------

// markerVerdictKinds is the classification every MarkerVerdict must carry. The source scan below
// fails the build if a constant is added without one, which is the only way this package has
// found to stop a new state quietly rendering as clean.
var markerVerdictKinds = map[MarkerVerdict]bool{
	MarkerVerdictAbsent:    false,
	MarkerVerdictMine:      false,
	MarkerVerdictForeign:   false,
	MarkerVerdictStaleRun:  true,
	MarkerVerdictTruncated: true,
	MarkerVerdictCorrupted: true,
}

func TestEveryMarkerVerdictIsClassifiedAsAMeasurementOrAnUnknown(t *testing.T) {
	// Every triage source file is scanned, not just this mechanism's own, so a constant added in
	// a sibling file by another agent is caught too. Both halves of the layer are scanned since the
	// package split: this package's triage*.go and every file of package triage below it. A guard
	// that kept globbing only one directory after a move is a guard silently checking less than it
	// looks like it is.
	files, err := triageLayerSources(t)
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	decl := regexp.MustCompile(`(?m)^\s*(?:const\s+)?(\w+)\s+MarkerVerdict\s*=\s*"([^"]+)"`)
	var matches [][]string
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("reading %s: %v", f, err)
		}
		matches = append(matches, decl.FindAllStringSubmatch(string(src), -1)...)
	}
	if len(matches) == 0 {
		t.Fatal("found no MarkerVerdict constants to scan; the guard would pass vacuously")
	}
	for _, m := range matches {
		v := MarkerVerdict(m[2])
		wantUnknown, ok := markerVerdictKinds[v]
		if !ok {
			t.Errorf("constant %s = %q is declared but has no row in markerVerdictKinds: decide whether it is a measurement or an unknown before using it", m[1], m[2])
			continue
		}
		if got := v.IsUnknown(); got != wantUnknown {
			t.Errorf("%s reports IsUnknown()=%v, the table says %v", m[1], got, wantUnknown)
		}
	}
	if len(matches) != len(markerVerdictKinds) {
		t.Errorf("scanned %d constants but the table has %d rows", len(matches), len(markerVerdictKinds))
	}
}

func TestAnUnrecognisedMarkerVerdictFailsClosed(t *testing.T) {
	if !MarkerVerdict("something_new").IsUnknown() {
		t.Error("an unrecognised verdict read as known; a value from a database row could then render as clean")
	}
	if MarkerVerdict("").IsUnknown() != true {
		t.Error("the zero value must be an unknown")
	}
	if MarkerVerdict("").IsHit() {
		t.Error("the zero value must not be a hit")
	}
}

func TestTheMarkerSearchDeclaresItsGapsRatherThanHidingThem(t *testing.T) {
	gaps := MarkerSearchGaps()
	if len(gaps) == 0 {
		t.Fatal("no declared gaps; either the search is complete, which it is not, or the list was emptied without a decision")
	}
	want := []string{"base64", "wide encodings", "unicode escapes"}
	for _, w := range want {
		found := false
		for _, g := range gaps {
			if strings.Contains(g, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("the %s gap is no longer declared; if it was closed, the test that closes it belongs here", w)
		}
	}
	// A base64-wrapped marker really is invisible today. Pinning it keeps the gap honest.
	m, _ := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSQL, uint64(triage.ClassSQL))
	encoded := "elFKMWYzcQ" // any base64-ish blob; the point is only that the raw token is absent
	if strings.Contains(encoded, string(m)) {
		t.Fatal("test fixture accidentally contains the raw marker")
	}
	if a := AttributeMarkers(ScanMarkers([]byte(encoded)), triage.ClassSQL, markerTestRunID); a.Verdict != MarkerVerdictAbsent {
		t.Errorf("the base64 gap now reports %q; update MarkerSearchGaps in the same diff", a.Verdict)
	}
}

func TestARunIDIsFourBytesOfTheMarkerAlphabet(t *testing.T) {
	id, err := triage.NewRunID(triageRunnerCapability())
	if err != nil {
		t.Fatalf("NewRunID: %v", err)
	}
	if !triage.WellFormedRunID(id) {
		t.Errorf("NewRunID produced %q, which it then rejects", id)
	}
	for _, bad := range []string{"", "abc", "abcde", "ABCD", "ab-d", "ab d"} {
		if triage.WellFormedRunID(bad) {
			t.Errorf("%q was accepted as a run id", bad)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// ONE BODY PER QUESTION
// ---------------------------------------------------------------------------------------------

// Marker.Integrity is the method a classifier reaches for, and VerifyMarkerIntegrity is the
// verifier that was actually written. While the method was a stub returning Unchecked, every hit
// in the system was capped at suspicious by a verifier that had been written and never called.
// Fail-closed is not the same as correct.
func TestTheIntegrityMethodIsTheRealVerifierAndNotASecondBody(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSQL, uint64(triage.ClassSQL))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	if got := m.Integrity(); got != triage.MarkerValid {
		t.Errorf("a freshly minted marker reads %q from the method, want %q", got, triage.MarkerValid)
	}

	flipped := []byte(m)
	if flipped[12] == 'a' {
		flipped[12] = 'b'
	} else {
		flipped[12] = 'a'
	}
	for _, bad := range []triage.Marker{triage.Marker(flipped), triage.Marker("not a marker"), triage.Marker("")} {
		if got := bad.Integrity(); got != triage.MarkerCorrupted {
			t.Errorf("%q reads %q from the method, want %q", bad, got, triage.MarkerCorrupted)
		}
	}

	// The two must not be able to disagree, whatever the input.
	for _, m := range []triage.Marker{m, triage.Marker(flipped), "not a marker", "", "zqj1f3q0000004xx"} {
		if a, b := m.Integrity(), triage.VerifyMarkerIntegrity(m); a != b {
			t.Errorf("%q: the method says %q and the function says %q; that is two sources of truth", m, a, b)
		}
	}
}

// MintMarker was a free function returning ErrTriageNotImplemented next to a working
// MarkerMinter.Mint. A free function cannot allocate: with no counter it cannot issue a distinct
// ordinal per call, and a package-level counter would make two concurrent runs share a sequence
// and hand out the same ordinal twice. It has to be gone, not merely unused, or it comes back.
func TestThereIsNoFreeMintMarkerFunctionBesideTheMinter(t *testing.T) {
	files, err := triageLayerSources(t)
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(files) == 0 {
		t.Fatalf("the glob found no triage files, so this guard is checking nothing")
	}
	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		checked++
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		for _, d := range parsed.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil {
				continue
			}
			if fn.Name.Name == "MintMarker" {
				t.Errorf("%s declares a free MintMarker; the runner holds one *MarkerMinter per run and calls Mint", fset.Position(fn.Pos()))
			}
		}
	}
	if checked == 0 {
		t.Fatalf("every triage file was skipped, so this guard is checking nothing")
	}
}

// triageLayerSources is every source file of the triage layer, both directories.
//
// The layer is package utils' triage*.go files plus the whole of utils/triage and the whole of
// server/triageclasses, which sits outside server/utils on purpose so that Go's internal rule
// keeps the minting capability away from it. Any source guard in this package that scans only one
// of those is covering
// half the layer, which is how a leak got past a "triage*.go" guard in a file called
// sqliClassifier.go. It fails rather than returning a short list, because a guard that quietly
// scans nothing is the failure this whole layer exists to stop.
func triageLayerSources(t *testing.T) ([]string, error) {
	t.Helper()
	var out []string
	for _, pat := range []string{
		filepath.Join(".", "triage*.go"),
		filepath.Join(".", "triage", "*.go"),
		filepath.Join("..", "triageclasses", "*.go"),
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			return nil, err
		}
		if len(m) == 0 {
			t.Fatalf("%s matched no files, so this guard is covering less of the layer than it claims", pat)
		}
		out = append(out, m...)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// THE TWO BUFFERS: a byte offset measured in one string and used to index another
// ---------------------------------------------------------------------------------------------
//
// triageScanOnePass used to build lower := strings.ToLower(string(p.text)) and then run one loop
// that bounded itself on len(lower), sliced lower, and indexed p.text. Unicode case mapping is not
// length preserving, so the two buffers are not the same length on every input, and every index in
// that loop was therefore valid in at most one of them.
//
// THE TWO FAILURES THAT CAME OUT OF IT ARE OPPOSITE AND BOTH FATAL.
//
//  1. A rune that GROWS under lowering makes lower longer than text, so the loop walks off the end
//     of p.text and panics. runTriage recovers the panic and marks the WHOLE RUN status=error, so
//     one such byte anywhere in any response kills every pair the run had not reached yet.
//
//  2. A rune that SHRINKS under lowering makes lower shorter than text, so the anchor is found at a
//     lower index than the position it actually occupies in p.text, and the run is then read from
//     the wrong bytes. There is no panic and no error row: the marker is simply not seen. For a
//     truncated marker, which the squeeze pass is not allowed to report, the whole scan then comes
//     back empty and the attribution is ABSENT, which IS a measurement and reads as clean.
//
// The fix is not a clamp. A clamp would keep the second failure, which is the expensive one. The
// fold is length preserving by construction now, and there is only one buffer left to index.

// The premise, checked rather than asserted. If Go's Unicode tables ever add a third growing rune,
// this test says so on the next run instead of on the next panic.
func TestExactlyTwoRunesGrowUnderLoweringAndNeitherKillsAScan(t *testing.T) {
	var grow []rune
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if utf8.RuneLen(r) < 0 {
			continue
		}
		if len(string(unicode.ToLower(r))) > len(string(r)) {
			grow = append(grow, r)
		}
	}
	if len(grow) != 2 || grow[0] != 0x023A || grow[1] != 0x023E {
		t.Fatalf("the growing set is %U; this test was written for exactly U+023A and U+023E", grow)
	}
	for _, r := range grow {
		t.Run(fmt.Sprintf("%U", r), func(t *testing.T) {
			// The anchor and the run sit at the very END of the body, which is where the old
			// loop's extra byte of slack turned into an index past the end of p.text.
			body := []byte(string(r) + triage.DefaultMarkerAnchor + markerTestRunID)
			if len(body) >= len(strings.ToLower(string(body))) {
				t.Fatalf("this body does not grow under lowering, so it cannot exercise the defect: text=%d lower=%d",
					len(body), len(strings.ToLower(string(body))))
			}
			got := ScanMarkers(body)
			// Surviving is the assertion here. What it reports is the next test's business.
			for _, s := range got {
				if s.Hit.Offset < 0 || s.Hit.Offset+s.Hit.Length > len(body) {
					t.Errorf("sighting reports %d+%d into a %d byte body", s.Hit.Offset, s.Hit.Length, len(body))
				}
			}
		})
	}
}

// A REALISTIC BODY with both growing runes in it, and a real marker that still has to come back. A
// scan that survives by finding nothing has not been fixed, it has been disabled.
func TestAMarkerIsStillFoundInABodyCarryingTheGrowingRunes(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassXSSReflected, uint64(triage.ClassXSSReflected))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	body := []byte(`{"ok":true,"display_name":"Ⱥsh Ⱦorvald","note":"Ⱥ Ⱦ Ⱥ Ⱦ","echo":"` +
		string(m) + `","trailing":"Ⱦ"}`)
	if len(body) >= len(strings.ToLower(string(body))) {
		t.Fatalf("this body does not grow under lowering, so it does not exercise the defect")
	}

	sightings := ScanMarkers(body)
	var found *MarkerSighting
	for i := range sightings {
		if sightings[i].Hit.Marker == m {
			found = &sightings[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("marker %q not recovered from a body containing U+023A and U+023E; sightings=%+v", m, sightings)
	}
	if found.Completeness != MarkerComplete {
		t.Errorf("recovered as %q, want complete", found.Completeness)
	}
	if found.Integrity != triage.MarkerValid {
		t.Errorf("recovered with integrity %q, want valid", found.Integrity)
	}
	if got := string(body[found.Hit.Offset : found.Hit.Offset+found.Hit.Length]); got != string(m) {
		t.Errorf("the reported offset/length %d+%d cuts %q out of the body, not the marker %q",
			found.Hit.Offset, found.Hit.Length, got, m)
	}
	if a := AttributeMarkers(sightings, triage.ClassXSSReflected, markerTestRunID); a.Verdict != MarkerVerdictMine {
		t.Errorf("attribution says %q for the class that minted it", a.Verdict)
	}
}

// THE SHRINKING HALF, which is the false clean. No panic, no error row, just a marker the scan
// walks straight past because the anchor's index in the lowered copy is not its index in the body.
//
// The case chosen is a TRUNCATED marker, because that is where the miss is unrecoverable: the
// squeeze pass reports complete tokens only, so it cannot cover for the raw pass, and an empty scan
// attributes as MarkerVerdictAbsent, whose IsUnknown() is false. A field that ate four bytes of the
// payload would be recorded as a clean measurement that the payload did not reflect.
func TestAShrinkingRuneBeforeAMarkerDoesNotTurnATruncationIntoAnAbsence(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassXSSReflected, uint64(triage.ClassXSSReflected))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	// U+212B ANGSTROM SIGN is three bytes and lowers to U+00E5, which is two.
	const shrink = "Å"
	if len(strings.ToLower(shrink)) >= len(shrink) {
		t.Fatalf("%q no longer shrinks under lowering, so this test needs another rune", shrink)
	}
	cut := 12
	body := []byte(`{"temperature":"300 ` + shrink + `","echo":"` + string(m)[:cut] + `"}`)

	sightings := ScanMarkers(body)
	a := AttributeMarkers(sightings, triage.ClassXSSReflected, markerTestRunID)
	if a.Verdict == MarkerVerdictAbsent {
		t.Fatalf("a body carrying %d of the 16 bytes of our own marker attributed as %q, whose IsUnknown() is %v. A truncation read as an absence is a measurement made out of a miss; sightings=%+v",
			cut, a.Verdict, a.Verdict.IsUnknown(), sightings)
	}
	if a.Verdict != MarkerVerdictTruncated {
		t.Errorf("attribution says %q, want %q", a.Verdict, MarkerVerdictTruncated)
	}
	if len(a.Truncated) != 1 {
		t.Fatalf("want exactly one truncated sighting, got %d: %+v", len(a.Truncated), a.Truncated)
	}
	s := a.Truncated[0]
	if s.Text != string(m)[:cut] {
		t.Errorf("the truncated run reads %q, want %q, so len(Text) cannot be used to measure where the field cut", s.Text, string(m)[:cut])
	}
	if got := string(body[s.Hit.Offset : s.Hit.Offset+s.Hit.Length]); got != string(m)[:cut] {
		t.Errorf("the reported offset/length %d+%d cuts %q out of the body, not the remnant %q",
			s.Hit.Offset, s.Hit.Length, got, string(m)[:cut])
	}
}

// The structural half of the fix, asserted directly: every pass hands the scanner one text and one
// offset table of the SAME length, and the fold the scanner applies to that text does not change
// its length. Those two facts together are what make an index valid in every buffer the scanner
// touches, so they are pinned rather than left as a property of the current code.
func TestEveryPassKeepsTextOffsetsAndFoldTheSameLength(t *testing.T) {
	bodies := [][]byte{
		nil,
		[]byte(""),
		[]byte("zqj"),
		[]byte("Ⱥ Ⱦ Å İ ẞ K"),
		[]byte("&#122;&#113;&#106;&#x31;&#x66; %7a%71%6a %zz % "),
		[]byte(`{"a":"` + strings.Repeat("Ⱦ", 40) + `","b":"ZQJ1F3Q000041ABC"}`),
	}
	for _, body := range bodies {
		for _, p := range []triageDecodedPass{triagePassRaw(body), triagePassNCR(body), triagePassPercent(body), triagePassSqueeze(body)} {
			if len(p.text) != len(p.orig) {
				t.Errorf("pass %q on %q produced %d bytes of text and %d offsets", p.form, body, len(p.text), len(p.orig))
			}
			if got := triageFoldASCII(p.text); len(got) != len(p.text) {
				t.Errorf("pass %q on %q: the fold turned %d bytes into %d, so an index into one is not an index into the other",
					p.form, body, len(p.text), len(got))
			}
			for i, o := range p.orig {
				if o < 0 || o >= len(body) {
					t.Errorf("pass %q on %q maps its byte %d to original offset %d, outside a %d byte body", p.form, body, i, o, len(body))
				}
			}
		}
	}
}

// The fold still has to be a fold: it must recover an upper-cased marker, which is the whole reason
// the scanner folds case at all.
func TestTheASCIIFoldStillRecoversAnUpperCasedMarker(t *testing.T) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassSQL, uint64(triage.ClassSQL))
	if err != nil {
		t.Fatalf("MintMarkerAt: %v", err)
	}
	for _, tc := range []struct{ name, body string }{
		{"upper", "<p>" + strings.ToUpper(string(m)) + "</p>"},
		{"upper after a growing rune", "<p>Ⱥ " + strings.ToUpper(string(m)) + "</p>"},
		{"upper after a shrinking rune", "<p>Å " + strings.ToUpper(string(m)) + "</p>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := AttributeMarkers(ScanMarkers([]byte(tc.body)), triage.ClassSQL, markerTestRunID)
			if a.Verdict != MarkerVerdictMine {
				t.Fatalf("an upper-cased copy of our own marker attributed as %q", a.Verdict)
			}
			if a.Mine[0].Hit.CaseTransform != "upper" {
				t.Errorf("case transform recorded as %q, want upper", a.Mine[0].Hit.CaseTransform)
			}
		})
	}
}

// NO OTHER FUNCTION IN THE LAYER MAY MEASURE ONE STRING AND INDEX ANOTHER.
//
// The defect above is a SHAPE, not an incident, and the shape has a precise definition: one
// function binds a case-folded COPY of some value to a name, and then uses byte indexes or slices
// on BOTH the copy and the value it was folded from. Case mapping is not length preserving, so the
// two are not the same length on every input, and an index computed against one of them is only
// coincidentally valid in the other.
//
// A folded copy that is the ONLY thing indexed is fine, and there are several of those in the
// layer (xssrTemplateSurvived reads its whole scan off the lowered payload and never touches the
// original). The guard is therefore written against the AST and not a grep: a grep for
// strings.ToLower reports about thirty header and parameter names in this layer, which would make
// it noise nobody reads. This finds the pair.
func TestNoTriageFunctionIndexesBothACaseFoldedCopyAndItsSource(t *testing.T) {
	files, err := triageLayerSources(t)
	if err != nil {
		t.Fatalf("list the layer: %v", err)
	}

	// rootIdents collects the plain identifiers an expression reads, so string(p.text) yields
	// {string, p} and payload yields {payload}. The conversion names are harmless: nothing is ever
	// indexed through them.
	rootIdents := func(e ast.Expr) map[string]bool {
		out := map[string]bool{}
		ast.Inspect(e, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				out[id.Name] = true
			}
			return true
		})
		return out
	}
	// rootOf names the variable an index or slice expression walks through: lower[i] and p.text[i]
	// give lower and p.
	var rootOf func(e ast.Expr) string
	rootOf = func(e ast.Expr) string {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			return rootOf(v.X)
		case *ast.IndexExpr:
			return rootOf(v.X)
		case *ast.SliceExpr:
			return rootOf(v.X)
		case *ast.ParenExpr:
			return rootOf(v.X)
		}
		return ""
	}

	fset := token.NewFileSet()
	var offenders []string
	for _, f := range files {
		file, err := parser.ParseFile(fset, f, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			var body *ast.BlockStmt
			switch v := n.(type) {
			case *ast.FuncDecl:
				body = v.Body
			case *ast.FuncLit:
				body = v.Body
			default:
				return true
			}
			if body == nil {
				return true
			}
			type fold struct {
				dst   string
				srcs  map[string]bool
				where token.Position
				fn    string
			}
			var folds []fold
			indexed := map[string]bool{}
			ast.Inspect(body, func(m ast.Node) bool {
				switch v := m.(type) {
				case *ast.IndexExpr:
					if r := rootOf(v.X); r != "" {
						indexed[r] = true
					}
				case *ast.SliceExpr:
					if r := rootOf(v.X); r != "" {
						indexed[r] = true
					}
				case *ast.AssignStmt:
					for i, rhs := range v.Rhs {
						call, ok := rhs.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							continue
						}
						sel, ok := call.Fun.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						pkg, ok := sel.X.(*ast.Ident)
						if !ok || pkg.Name != "strings" {
							continue
						}
						if sel.Sel.Name != "ToLower" && sel.Sel.Name != "ToUpper" {
							continue
						}
						if i >= len(v.Lhs) {
							continue
						}
						dst, ok := v.Lhs[i].(*ast.Ident)
						if !ok {
							continue
						}
						folds = append(folds, fold{
							dst:   dst.Name,
							srcs:  rootIdents(call.Args[0]),
							where: fset.Position(v.Pos()),
							fn:    sel.Sel.Name,
						})
					}
				}
				return true
			})
			for _, fl := range folds {
				if !indexed[fl.dst] {
					continue
				}
				for src := range fl.srcs {
					if src == fl.dst || !indexed[src] {
						continue
					}
					offenders = append(offenders, fmt.Sprintf(
						"%s:%d: %s := strings.%s(... %s ...) and the same function indexes both %s and %s",
						filepath.Base(fl.where.Filename), fl.where.Line, fl.dst, fl.fn, src, fl.dst, src))
				}
			}
			return true
		})
	}
	if len(offenders) != 0 {
		t.Errorf("%d function(s) index both a case-folded copy and the value it was folded from:\n  %s\n"+
			"This is the shape that panicked triageScanOnePass on U+023A and silently lost markers after U+212B. "+
			"Index the folded copy throughout, or fold with a length-preserving byte fold like triageFoldASCII.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// A FUZZ TARGET, because the defect above was a class of input and not an input. Under a plain
// `go test` this runs the seed corpus only, which costs nothing; `go test -fuzz` on this name
// will hunt for the next byte sequence that walks the scanner out of its own buffer.
//
// The properties are the two the fix is supposed to guarantee, and nothing about what the scanner
// FINDS: it must not panic, and every offset and length it reports must name real bytes of the
// body the caller handed it, because a sighting that points outside the body is evidence of the
// two-buffer defect even when it does not crash.
func FuzzScanMarkersStaysInsideTheBodyItWasGiven(f *testing.F) {
	m, err := triage.MintMarkerAt(triageRunnerCapability(), markerTestRunID, triage.ClassXSSReflected, uint64(triage.ClassXSSReflected))
	if err != nil {
		f.Fatalf("MintMarkerAt: %v", err)
	}
	for _, s := range []string{
		"",
		"zqj",
		string(m),
		"Ⱥ" + triage.DefaultMarkerAnchor + markerTestRunID,
		"Ⱦ" + triage.DefaultMarkerAnchor + markerTestRunID,
		"Å" + string(m)[:12],
		`{"echo":"` + string(m) + `","n":"ȺȾKİ"}`,
		"&#122;&#113;&#106;" + string(m)[3:],
		"%7a%71%6a" + string(m)[3:],
		strings.ToUpper(string(m)),
		strings.Repeat("Ⱥ", 64) + "zqj",
		"\xff\xfe\x00zqj1f3q\x00\xff",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		for _, s := range ScanMarkers(body) {
			if s.Hit.Offset < 0 || s.Hit.Length < 0 || s.Hit.Offset+s.Hit.Length > len(body) {
				t.Fatalf("sighting reports %d+%d in a %d byte body: %+v", s.Hit.Offset, s.Hit.Length, len(body), s)
			}
			if s.Completeness != MarkerComplete && s.Completeness != MarkerTruncated {
				t.Fatalf("sighting reports completeness %q, which is neither of the two answers", s.Completeness)
			}
		}
	})
}
