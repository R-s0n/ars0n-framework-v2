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
	// 27 real classes plus ClassExample, the id reserved for the placeholder classifier so that it
	// does not squat on a real one. The count is asserted because this test's coverage claim is
	// "every declared stripe", and a class quietly added or removed would shrink that claim
	// without shrinking the passing result.
	if len(classes) != 28 {
		t.Fatalf("expected the 27 declared classes plus the reserved example id, got %d; this test's coverage claim depends on that count", len(classes))
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
