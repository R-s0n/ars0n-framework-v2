package utils

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"ars0n-framework-v2-server/utils/triage"
)

// A pointer says "spend an hour here rather than on the other 217 vectors", so the ordering is the
// feature. These tests are about the two things that make an ordering usable: it has to put the
// stronger evidence first, and it has to be able to say why.

// THE RANKING RULE, stated as a test: a delta-checked native hit outranks a bare signature match,
// whatever severity word the signature carried.
//
// This is the one that would be got wrong by sorting on severity, which is the obvious thing to do
// and is wrong: severity is a claim about impact IF TRUE, and strength is how likely it is to be
// true at all.
func TestDeltaCheckedOutranksACriticalSignature(t *testing.T) {
	delta := Pointer{
		ID: "triage:a", AttackClass: triage.ClassSQL.String(), Deliverable: true,
		StrengthRank: EvidenceRank(ProvenanceNativeProbe, true), severity: "low",
	}
	signature := Pointer{
		ID: "vector_finding:b", AttackClass: triage.ClassSQL.String(), Deliverable: true,
		StrengthRank: EvidenceRank(ProvenancePriorFinding, false), severity: "critical",
	}
	pointers := []Pointer{signature, delta}
	rankPointers(pointers)
	if pointers[0].ID != "triage:a" {
		t.Fatalf("a critical signature outranked a delta-checked hit: got %s first", pointers[0].ID)
	}
	if pointers[0].Rank != 1 || pointers[1].Rank != 2 {
		t.Fatalf("ranks not stamped 1,2: got %d,%d", pointers[0].Rank, pointers[1].Rank)
	}
}

// Severity breaks ties INSIDE a strength band, and only there.
func TestSeverityOnlyBreaksTiesInsideAStrengthBand(t *testing.T) {
	low := Pointer{ID: "vector_finding:a", Deliverable: true, StrengthRank: 2, severity: "low"}
	crit := Pointer{ID: "vector_finding:b", Deliverable: true, StrengthRank: 2, severity: "critical"}
	pointers := []Pointer{low, crit}
	rankPointers(pointers)
	if pointers[0].ID != "vector_finding:b" {
		t.Fatalf("inside one band the critical should come first, got %s", pointers[0].ID)
	}
}

// A pointer an attacker can trigger with a link beats an equally strong one that needs a chain
// demonstrated first. Same rule the XSS grade already uses, applied to every class.
func TestDeliverableBeatsSelfInflictedAtEqualStrength(t *testing.T) {
	cookie := Pointer{ID: "reflection_probe:a", StrengthRank: 1, severity: "medium", Deliverable: false}
	query := Pointer{ID: "reflection_probe:b", StrengthRank: 1, severity: "medium", Deliverable: true}
	pointers := []Pointer{cookie, query}
	rankPointers(pointers)
	if pointers[0].ID != "reflection_probe:b" {
		t.Fatalf("the deliverable pointer should outrank the self-inflicted one, got %s", pointers[0].ID)
	}
}

// A ranking nobody can explain is a ranking nobody trusts, so every pointer has to carry the why.
func TestEveryRankedPointerSaysWhyItRanksThere(t *testing.T) {
	pointers := []Pointer{
		{ID: "a", StrengthRank: 5, Deliverable: true},
		{ID: "b", StrengthRank: 1, Deliverable: false, severity: "medium"},
		{ID: "c", StrengthRank: 0, Deliverable: true},
	}
	rankPointers(pointers)
	for _, p := range pointers {
		if strings.TrimSpace(p.WhyRanked) == "" {
			t.Errorf("pointer %s ranks %d and says nothing about why", p.ID, p.Rank)
		}
		if !strings.Contains(p.WhyRanked, "of 3") {
			t.Errorf("pointer %s does not say where it sits in the list: %q", p.ID, p.WhyRanked)
		}
	}
	for _, p := range pointers {
		if !p.Deliverable && !strings.Contains(p.WhyRanked, "link") {
			t.Errorf("pointer %s was ranked down for not being deliverable and does not say so: %q",
				p.ID, p.WhyRanked)
		}
	}
}

// The strength labels and the sort have to come from the same place, or the list is ordered one way
// and labelled another. Both read EvidenceRank.
func TestStrengthLabelsFollowEvidenceRank(t *testing.T) {
	cases := []struct {
		provenance TriageProvenance
		delta      bool
		want       string
	}{
		{ProvenanceNativeProbe, true, PointerStrengthDeltaChecked},
		{ProvenanceExternalTool, false, PointerStrengthToolReported},
		{ProvenanceNativeProbe, false, PointerStrengthProbeObserved},
		{ProvenancePriorFinding, false, PointerStrengthPriorFinding},
		{ProvenancePassiveCorpus, false, PointerStrengthPassiveEcho},
		{ProvenanceUnknown, false, PointerStrengthUnattributed},
	}
	for _, c := range cases {
		got := pointerStrengthFor(EvidenceRank(c.provenance, c.delta))
		if got != c.want {
			t.Errorf("provenance %q delta %v: want %s, got %s", c.provenance, c.delta, c.want, got)
		}
	}
	// The vocabulary the client reads has to contain every label the server can emit, or a filter
	// built from it silently drops rows.
	order := map[string]bool{}
	for _, s := range PointerStrengthOrder() {
		order[s] = true
	}
	for _, c := range cases {
		if !order[c.want] {
			t.Errorf("%s is emitted but is not in PointerStrengthOrder", c.want)
		}
	}
}

// AN UNMAPPED TOOL MUST STILL PRODUCE A POINTER. A dropped pointer is the false negative this whole
// layer exists to prevent, so a tool nobody has classified lands under UNCLASSIFIED rather than
// vanishing.
func TestAnUnmappedToolStillGetsAClass(t *testing.T) {
	got := pointerClassForFinding("some-tool-nobody-mapped", "whatever")
	if got != pointerClassUnclassified {
		t.Fatalf("an unmapped tool should be UNCLASSIFIED, got %q", got)
	}
	if pointerClassLabel(got) == got {
		t.Error("UNCLASSIFIED has no label, so the operator sees a bare token")
	}
	// And it still names a next step, even if that step is a hand review.
	_, reason := pointerNextTool(got)
	if strings.TrimSpace(reason) == "" {
		t.Error("an unclassified pointer names no next move at all")
	}
}

// dalfox A is a static source-to-sink path in JavaScript, which is DOM XSS and not reflection.
// Sending it to the reflected bucket would point the operator back at dalfox instead of a browser.
func TestDalfoxIsSplitByKind(t *testing.T) {
	if got := pointerClassForFinding("dalfox", "A"); got != triage.ClassXSSDOM.String() {
		t.Errorf("dalfox A should be DOM XSS, got %q", got)
	}
	if got := pointerClassForFinding("dalfox", "V"); got != triage.ClassXSSReflected.String() {
		t.Errorf("dalfox V should be reflected XSS, got %q", got)
	}
	if tool, _ := pointerNextTool(triage.ClassXSSDOM.String()); tool != "domdig" {
		t.Errorf("a DOM pointer should point at the browser tool, got %q", tool)
	}
}

// Every class this file can emit needs a label and a next step, or a pointer arrives on the screen
// saying nothing about what to do with it.
func TestEveryMappedClassHasALabelAndANextStep(t *testing.T) {
	classes := map[string]bool{pointerClassUnclassified: true}
	for _, class := range pointerToolClass {
		classes[class] = true
	}
	for class := range classes {
		if strings.TrimSpace(pointerClassLabels[class]) == "" {
			t.Errorf("class %s has no label", class)
		}
		tool, reason := pointerNextTool(class)
		if strings.TrimSpace(reason) == "" {
			t.Errorf("class %s names no next step", class)
		}
		if tool == "" && !strings.Contains(strings.ToLower(reason), "hand review") &&
			!strings.Contains(strings.ToLower(reason), "reading it") {
			t.Errorf("class %s has no tool and does not explain why", class)
		}
	}
}

// THE DELIVERY GATE IS NOT RE-IMPLEMENTED HERE. The path reads
// ReflectionInsertionPointDeliverable and FindingDeliveryNote, so a cookie XSS pointer is marked
// self-inflicted and carries the named chain, and a query one carries neither.
func TestTheAttackPathReusesTheDeliveryGate(t *testing.T) {
	cookie := Pointer{
		AttackClass: triage.ClassXSSReflected.String(), InsertionPoint: "cookie",
		Parameter: "theme", Method: "GET", URL: "https://example.test/a", NextTool: "dalfox",
		Rule: "reflected",
	}
	path := pointerAttackPath(cookie)
	if path.Deliverable {
		t.Error("a cookie XSS is not attacker-deliverable")
	}
	if !strings.Contains(strings.ToLower(path.DeliveryNote), "self-xss") {
		t.Errorf("the cookie path should carry the self-XSS gate, got %q", path.DeliveryNote)
	}
	if !strings.Contains(strings.ToLower(path.DeliveryNote), "set-cookie") {
		t.Error("the gate should NAME the chain rather than gesture at one")
	}

	query := cookie
	query.InsertionPoint = "query"
	qpath := pointerAttackPath(query)
	if !qpath.Deliverable {
		t.Error("a query XSS is attacker-deliverable with a link")
	}
	if qpath.DeliveryNote != "" {
		t.Errorf("a deliverable point should carry no gate, got %q", qpath.DeliveryNote)
	}
	if qpath.Next.Tool != "dalfox" || qpath.Next.InsertionPoint != "query" || qpath.Next.Parameter != "theme" {
		t.Error("the next step must carry the vector already selected for the tool")
	}
	if len(qpath.PossibleAttacks) == 0 || strings.TrimSpace(qpath.Entry) == "" {
		t.Error("the path has to say where the attacker enters and what they could do next")
	}
}

// THE DELIVERY GATE IS AN XSS RULE AND MUST NOT BE APPLIED TO EVERY CLASS.
//
// This shipped wrong once in this file: an exposed credential in env.js came back deliverable
// false and was ranked below an equally strong pointer "an attacker can trigger with a link",
// which is a category error. vectorExplain.go already says why: everything outside the XSS family
// is exploited by the attacker sending their own request.
func TestTheDeliveryGateAppliesOnlyToVictimDeliveredClasses(t *testing.T) {
	if !pointerDeliverable(pointerClassSecret, "body") {
		t.Error("an exposed secret in a body is read by fetching the file, so delivery does not gate it")
	}
	if !pointerDeliverable(triage.ClassSQL.String(), "cookie") {
		t.Error("a SQL injection in a cookie is sent by the attacker's own request, so delivery does not gate it")
	}
	if pointerDeliverable(triage.ClassXSSReflected.String(), "cookie") {
		t.Error("a cookie XSS IS gated: the victim's own browser sets that value")
	}
	if note := pointerDeliveryNote(pointerClassSecret, "dalfox", "cookie"); note != "" {
		t.Errorf("a secret pointer must not carry an XSS self-XSS note, got %q", note)
	}
	if note := pointerDeliveryNote(triage.ClassXSSReflected.String(), "dalfox", "cookie"); note == "" {
		t.Error("a cookie XSS pointer must carry the named chain")
	}
	// And the ranking must not then demote a class the gate does not apply to.
	pointers := []Pointer{
		{ID: "b", AttackClass: pointerClassSecret, StrengthRank: 2, severity: "medium",
			Deliverable: pointerDeliverable(pointerClassSecret, "body")},
		{ID: "a", AttackClass: triage.ClassSQL.String(), StrengthRank: 2, severity: "medium",
			Deliverable: pointerDeliverable(triage.ClassSQL.String(), "cookie")},
	}
	rankPointers(pointers)
	for _, p := range pointers {
		if strings.Contains(p.WhyRanked, "link") {
			t.Errorf("pointer %s is not a victim-delivered class and was ranked on delivery: %q", p.ID, p.WhyRanked)
		}
	}
}

// A POINTER WITH NO URL IS NOT ACTIONABLE. One real row on the measured corpus is an xssfuzz
// finding stored with an empty url on a vector whose evidence_url was also null.
func TestAPointerWithNoStoredURLGetsOneFromTheVector(t *testing.T) {
	if got := pointerVectorURL("https", "app.example.test", "/api/v1/echo"); got != "https://app.example.test/api/v1/echo" {
		t.Errorf("composed the wrong URL: %q", got)
	}
	if got := pointerVectorURL("", "app.example.test", ""); got != "https://app.example.test/" {
		t.Errorf("a missing scheme and path should default, got %q", got)
	}
	if got := pointerVectorURL("https", "", "/a"); got != "" {
		t.Errorf("with no host there is nothing honest to compose, got %q", got)
	}
}

// A COMPOSED URL MUST NOT CLAIM TO BE A CAPTURED ONE. xssfuzz row 71bbdd5e is stored with an empty
// url on a vector whose evidence_url is null, so the pointer's URL is assembled here. An operator
// who reproduces an inferred URL believing it is the request the tool sent loses an hour, so the
// origin travels with the URL and the note says so in words.
func TestAComposedURLSaysItWasComposed(t *testing.T) {
	url, origin, note := pointerURLWithOrigin("", PointerURLFromTool, "", "https", "app.example.test", "/api/v1/echo")
	if url != "https://app.example.test/api/v1/echo" {
		t.Fatalf("composed the wrong URL: %q", url)
	}
	if origin != PointerURLComposed {
		t.Errorf("a composed URL must be marked composed, got %q", origin)
	}
	if !strings.Contains(strings.ToLower(note), "composed") {
		t.Errorf("a composed URL must carry the warning, got %q", note)
	}

	// A URL the tool actually stored is captured, and carries no warning.
	url, origin, note = pointerURLWithOrigin("https://app.example.test/x?q=1", PointerURLFromTool,
		"https://app.example.test/other", "https", "app.example.test", "/x")
	if url != "https://app.example.test/x?q=1" || origin != PointerURLFromTool || note != "" {
		t.Errorf("a captured URL was relabelled: %q %q %q", url, origin, note)
	}

	// The vector's own recorded URL is the second-best captured answer, ahead of composing.
	url, origin, _ = pointerURLWithOrigin("", PointerURLFromTool, "https://app.example.test/other",
		"https", "app.example.test", "/x")
	if url != "https://app.example.test/other" || origin != PointerURLFromVector {
		t.Errorf("the vector's evidence URL should be preferred to composing: %q %q", url, origin)
	}

	// Nothing to compose from. Not a blank field on the screen: a stated absence.
	url, origin, note = pointerURLWithOrigin("", PointerURLFromTool, "", "", "", "")
	if url != "" || origin != PointerURLNone || strings.TrimSpace(note) == "" {
		t.Errorf("a pointer with no URL must say so: %q %q %q", url, origin, note)
	}
}

// The attack path is the sentence the operator reads, so a composed URL has to be marked THERE too
// rather than only in a field beside it.
func TestTheAttackPathMarksAComposedURL(t *testing.T) {
	composed := pointerAttackPath(Pointer{
		AttackClass: triage.ClassXSSReflected.String(), InsertionPoint: "query", Parameter: "q",
		Method: "GET", URL: "https://app.example.test/api/v1/echo", URLOrigin: PointerURLComposed,
	})
	if !strings.Contains(strings.ToLower(composed.Entry), "composed") {
		t.Errorf("a composed URL is presented as a captured request: %q", composed.Entry)
	}
	captured := pointerAttackPath(Pointer{
		AttackClass: triage.ClassXSSReflected.String(), InsertionPoint: "query", Parameter: "q",
		Method: "GET", URL: "https://app.example.test/api/v1/echo", URLOrigin: PointerURLFromTool,
	})
	if strings.Contains(strings.ToLower(captured.Entry), "composed") {
		t.Errorf("a captured URL was labelled composed: %q", captured.Entry)
	}
}

// DEFECT 3, LOCKED. vector_reflection_probes is keyed (vector_id, parameter), so the passive pass
// overwrites the status and evidence on a row whose probe_url and canary still hold an earlier
// ACTIVE attempt's values. Seen live: a passive pointer whose probe_url contained
// rs0nR4f657925<>"'rs0nE. Nothing derived from a passive row may carry that value.
func TestAPassiveRowNeverShowsTheStaleActiveProbeURL(t *testing.T) {
	stale := "https://app.staging.example/api/v1/accounts/rs0n/trade_account/rs0nR4f657925%3C%3E%22%27rs0nE"
	url, origin, _ := pointerReflectionURL("passive", stale, "https://app.staging.example/api/v1/accounts/rs0n/trade_account",
		"https", "app.staging.example", "/api/v1/accounts/rs0n/trade_account")
	if strings.Contains(url, "rs0nR") {
		t.Fatalf("a passive pointer carried the earlier active attempt's canary URL: %q", url)
	}
	if origin != PointerURLFromVector {
		t.Errorf("a passive pointer's URL is the vector's own, got origin %q", origin)
	}
	// With no vector URL either, it composes rather than falling back to the stale probe URL.
	url, origin, _ = pointerReflectionURL("passive", stale, "", "https", "app.staging.example", "/a")
	if strings.Contains(url, "rs0nR") || origin != PointerURLComposed {
		t.Fatalf("a passive pointer fell back to the stale probe URL: %q %q", url, origin)
	}
	// The active pass owns that column, so it keeps it.
	url, origin, _ = pointerReflectionURL("active", stale, "", "https", "app.staging.example", "/a")
	if url != stale || origin != PointerURLFromProbe {
		t.Errorf("the active pass should carry its own probe URL: %q %q", url, origin)
	}
}

// DEFECT 4. The canary exclusion is 390 of 415 rows on the measured corpus, so it decides most of
// this screen. It has to hold for EVERY tool, which means it has to be applied to the URL the
// pointer will carry: a finding stored with an empty url column was invisible to a check that only
// read that column, and would have listed the framework's own test fixture as a target.
func TestTheCanaryExclusionReadsTheURLThePointerWillCarry(t *testing.T) {
	t.Setenv("ARS0N_CANARY_HOST", "oracle:8000")

	// The shape that used to slip through: no url on the finding, no evidence_url on the vector,
	// and the vector sitting on the oracle.
	url, _, _ := pointerURLWithOrigin("", PointerURLFromTool, "", "http", "oracle:8000", "/xss/reflect")
	if !findingIsCanary(url) {
		t.Errorf("a control hit with an empty url column was not recognised: %q", url)
	}
	// And the real row it must NOT swallow: the same empty url on a vector at the target.
	url, _, _ = pointerURLWithOrigin("", PointerURLFromTool, "", "https", "app.staging.example", "/api/v1/echo")
	if findingIsCanary(url) {
		t.Errorf("a real finding was excluded as the control: %q", url)
	}
	// No URL anywhere: not a canary, because nothing says it is, and the caller counts it as
	// uncheckable rather than dropping it.
	url, origin, _ := pointerURLWithOrigin("", PointerURLFromTool, "", "", "", "")
	if findingIsCanary(url) || origin != PointerURLNone {
		t.Errorf("an unknown URL was treated as the control: %q %q", url, origin)
	}
}

// The exclusion is large enough that "trust me" is not an account of it. The note carries the
// arithmetic per tool, and every tool with rows appears whether or not any of them were control
// hits, so a tool that is entirely about the target is visible as such.
func TestTheCanaryNoteProvesTheExclusionPerTool(t *testing.T) {
	note := pointerCanaryNote(PointerFindingCoverage{
		Rows: 415, Pointers: 9, ExcludedCanary: 390, ExcludedDismiss: 16, CanaryHost: "oracle:8000",
		RowsByTool:   map[string]int{"dalfox": 223, "sqlmap": 126, "mantra": 17, "xssfuzz": 9},
		CanaryByTool: map[string]int{"dalfox": 223, "sqlmap": 126, "xssfuzz": 8},
	})
	for _, want := range []string{"390 of 415", "oracle:8000", "dalfox 223 of 223", "sqlmap 126 of 126",
		"mantra 0 of 17", "xssfuzz 8 of 9"} {
		if !strings.Contains(note, want) {
			t.Errorf("the canary note drops %q: %q", want, note)
		}
	}
	// A finding with no URL cannot be checked either way, and that has to be said rather than
	// folded into the excluded count or into the kept count without comment.
	unchecked := pointerCanaryNote(PointerFindingCoverage{
		Rows: 3, ExcludedCanary: 1, CanaryHost: "oracle:8000", CanaryUncheckable: 2,
		RowsByTool: map[string]int{"mantra": 3}, CanaryByTool: map[string]int{"mantra": 1},
	})
	if !strings.Contains(unchecked, "no URL from any source") {
		t.Errorf("the uncheckable rows are not reported: %q", unchecked)
	}
	// With no canary host configured nothing can be excluded, and a silent zero there would read
	// as "the control never fired" rather than "the filter was never armed".
	unarmed := pointerCanaryNote(PointerFindingCoverage{
		Rows: 5, RowsByTool: map[string]int{"dalfox": 5}, CanaryByTool: map[string]int{},
	})
	if !strings.Contains(unarmed, "ARS0N_CANARY_HOST is unset") {
		t.Errorf("an unarmed control filter must say so: %q", unarmed)
	}
}

// A pointer with no attack class still gets a path rather than an empty object, because an empty
// object on the screen reads as "nothing here" and the row is right there in the list.
func TestAnUnclassifiedPointerStillGetsAPath(t *testing.T) {
	p := Pointer{AttackClass: pointerClassUnclassified, InsertionPoint: "", Method: "", URL: ""}
	path := pointerAttackPath(p)
	if strings.TrimSpace(path.Entry) == "" || len(path.PossibleAttacks) == 0 {
		t.Fatal("an unclassified pointer produced an empty attack path")
	}
	if !strings.Contains(strings.ToLower(path.Entry), "unrecorded") {
		t.Errorf("a missing insertion point should be named as missing, got %q", path.Entry)
	}
}

// THE COUNTS ARE THE CORPUS, NEVER THE FILTERED VIEW. "0 blocked while filtered to XSS High is not
// a fact about the target" was caught in review on the reflection panel once already, so the count
// helper is tested on the whole list and the handler is the only thing that filters.
func TestCountsCoverEverySourceEvenAtZero(t *testing.T) {
	counts := countPointers([]Pointer{
		{Source: PointerSourceReflection, AttackClass: "XSS-R", Grade: XSSCandidateLow, InsertionPoint: "path", Strength: PointerStrengthPassiveEcho},
		{Source: PointerSourceReflection, AttackClass: "XSS-R", Grade: XSSCandidateLow, InsertionPoint: "body", Strength: PointerStrengthPassiveEcho},
		{Source: PointerSourceFinding, AttackClass: "SSTI", Grade: "critical", InsertionPoint: "query", Strength: PointerStrengthPriorFinding},
	})
	if counts.BySource[PointerSourceReflection] != 2 || counts.BySource[PointerSourceFinding] != 1 {
		t.Fatalf("source counts wrong: %v", counts.BySource)
	}
	if _, ok := counts.BySource[PointerSourceTriage]; !ok {
		t.Error("a source with nothing in it must read 0 rather than be absent: an absent key reads as 'not a thing'")
	}
	if counts.ByInsertionPoint["path"] != 1 || counts.ByInsertionPoint["body"] != 1 {
		t.Errorf("insertion point counts wrong: %v", counts.ByInsertionPoint)
	}
	if counts.ByGrade["critical"] != 1 || counts.ByGrade[XSSCandidateLow] != 2 {
		t.Errorf("grade counts wrong: %v", counts.ByGrade)
	}
}

// A pointer with no recorded insertion point is counted under a name rather than under "", which
// renders as a blank row nobody can read or filter on.
func TestAnUnrecordedInsertionPointIsNamed(t *testing.T) {
	counts := countPointers([]Pointer{{Source: PointerSourceFinding, InsertionPoint: ""}})
	if counts.ByInsertionPoint["unrecorded"] != 1 {
		t.Errorf("an empty insertion point should count as unrecorded: %v", counts.ByInsertionPoint)
	}
}

// The slot key grammar is only parsed when the prefix is a real insertion point. Four triage
// classes address a host, a vector, a container or a body document, and parsing one of those with
// the slot grammar would invent an insertion point that does not exist.
func TestOnlyARealSlotKeyYieldsAnInsertionPoint(t *testing.T) {
	if got := triageSlotInsertionPoint("query:sort"); got != "query" {
		t.Errorf("query:sort should yield query, got %q", got)
	}
	if got := triageSlotName("query:sort"); got != "sort" {
		t.Errorf("query:sort should name sort, got %q", got)
	}
	if got := triageSlotInsertionPoint("app.staging.example:443"); got != "" {
		t.Errorf("a host key is not an insertion point, got %q", got)
	}
	if got := triageSlotName("app.staging.example:443"); got != "" {
		t.Errorf("a host key names no parameter, got %q", got)
	}
}

// The headline is the one sentence that has to sit beside the count, and it has to carry the
// denominator. A list of 34 pointers with no denominator reads as "the other vectors are fine".
//
// THE NUMBERS ARE THE MEASURED CORPUS as it stands after the union fix: 43 pointers, 28 of 218
// vectors, 7 pointers on no vector at all, 184 unknown rather than 186.
func TestTheHeadlineCarriesTheDenominator(t *testing.T) {
	cov := PointerCoverage{
		Vectors: PointerVectorCoverage{
			Total: 218, WithPointer: 28, Concluded: 34, Unknown: 184,
			PointersWithoutVector: 7,
			ConcludedBySource: map[string]int{
				PointerSourceReflection: 32, PointerSourceFinding: 2, PointerSourceTriage: 0,
			},
		},
		Reflection: PointerReflectionCoverage{ProbeRows: 1764, Unknown: 1714},
	}
	headline := pointerCoverageHeadline(43, cov)
	for _, want := range []string{"43", "218", "1714", "1764", "184", "28"} {
		if !strings.Contains(headline, want) {
			t.Errorf("the headline drops %s: %q", want, headline)
		}
	}
	if !strings.Contains(headline, "unknown rather than clean") {
		t.Errorf("the headline must say unknown is not clean: %q", headline)
	}
	// WHICH SOURCE CONCLUDED WHAT. "184 have no conclusion" is only checkable if the sentence says
	// what the conclusions were, and "triage 0" is the one that says the runner has never run.
	for _, want := range []string{"reflection probe 32", "prior finding 2", "triage 0"} {
		if !strings.Contains(headline, want) {
			t.Errorf("the headline does not say which source concluded what, missing %q: %q", want, headline)
		}
	}
	// The pointers that sit in no vector denominator, so 43 across 28 of 218 can be reconciled.
	if !strings.Contains(headline, "plus 7 on no vector") {
		t.Errorf("the headline hides the pointers that belong to no vector: %q", headline)
	}
}

// THE DEFECT THIS TEST EXISTS FOR: the headline said "186 vectors have no conclusion from any
// source" while two of those 186 carried a tool's finding. Concluded and Unknown came from the
// reflection grade alone, so a vector whose probe errored was called unknown even after a scanner
// reported on it. A vector with a pointer is concluded by SOME source, by definition.
func TestAVectorWithAPointerIsNeverCountedAsUnknown(t *testing.T) {
	corpus := map[string]string{
		"v-errored":     ReflectionError,
		"v-credential":  ReflectionIsCredential,
		"v-observed":    ReflectionObserved,
		"v-notreflect":  ReflectionNotReflected,
		"v-untouched-1": ReflectionError,
		"v-untouched-2": ReflectionIsCredential,
	}
	cov := pointerVectorCoverageFrom(corpus, []Pointer{
		// A tool reported on a vector the probe could not answer for. This is the row that was
		// counted as "no conclusion from any source" while a finding sat on it.
		{Source: PointerSourceFinding, VectorID: "v-errored"},
		// The probe's own pointer, on a vector the probe already concluded about.
		{Source: PointerSourceReflection, VectorID: "v-observed"},
		// A finding with no vector at all, which belongs in no vector denominator.
		{Source: PointerSourceFinding, VectorID: ""},
		// A finding on a vector that is not in this corpus, which is what a deleted vector with a
		// surviving finding looks like.
		{Source: PointerSourceFinding, VectorID: "v-deleted"},
	})

	if cov.Total != 6 {
		t.Fatalf("total should be the corpus size, got %d", cov.Total)
	}
	// Concluded: observed and not_reflected by the probe, plus the errored vector a finding
	// reached. Unknown: the credential one and the two nothing touched.
	if cov.Concluded != 3 || cov.Unknown != 3 {
		t.Fatalf("concluded/unknown wrong: %d concluded, %d unknown", cov.Concluded, cov.Unknown)
	}
	if cov.ConcludedBySource[PointerSourceReflection] != 2 {
		t.Errorf("the probe concluded on observed and not_reflected, got %d",
			cov.ConcludedBySource[PointerSourceReflection])
	}
	if cov.ConcludedBySource[PointerSourceFinding] != 1 {
		t.Errorf("one finding landed on a corpus vector, got %d", cov.ConcludedBySource[PointerSourceFinding])
	}
	if _, ok := cov.ConcludedBySource[PointerSourceTriage]; !ok {
		t.Error("a source that concluded nothing must read 0 rather than be absent")
	}
	if cov.WithPointer != 2 {
		t.Errorf("two corpus vectors carry a pointer, got %d", cov.WithPointer)
	}
	if cov.PointersWithoutVector != 1 || cov.PointersOffCorpus != 1 {
		t.Errorf("the pointers outside the denominator are not reported: %d without a vector, %d off corpus",
			cov.PointersWithoutVector, cov.PointersOffCorpus)
	}
	// The arithmetic the operator will do: WithPointer + off-denominator pointers accounts for
	// every pointer in the list, and Concluded + Unknown accounts for every vector.
	if cov.Concluded+cov.Unknown != cov.Total {
		t.Errorf("the vector arithmetic does not close: %d + %d != %d", cov.Concluded, cov.Unknown, cov.Total)
	}
}

// A MEASURED NEGATIVE IS A CONCLUSION AND A REFUSAL IS NOT. The three statuses that mean the probe
// declined or failed have to stay unknown, or the coverage card starts calling a credential it
// refused to burn a vector it cleared.
func TestOnlyAMeasuredStatusCounts(t *testing.T) {
	concluded := []string{ReflectionObserved, ReflectionRaw, ReflectionEncoded, ReflectionNotReflected}
	unknown := []string{ReflectionIsCredential, ReflectionError, ReflectionProbeRefused, ReflectionNotProbed, "", "something-new"}
	for _, s := range concluded {
		if !pointerStatusConcluded(s) {
			t.Errorf("%s is a claim about the vector and was counted as unknown", s)
		}
	}
	for _, s := range unknown {
		if pointerStatusConcluded(s) {
			t.Errorf("%s is a record of NOT having measured and was counted as a conclusion", s)
		}
	}
}

// pointerStatusConcluded asks XSSCandidateGrade with an empty content type and no survived set. It
// is allowed to do that ONLY because neither input can turn a concluding status into unknown. This
// locks the invariant: if the grade rule ever gains a content-type path to xss_unknown, this fails
// here rather than by quietly calling an unknown a conclusion on the operator's screen.
func TestConcludedIsStatusAloneWhateverTheContentType(t *testing.T) {
	types := []string{"", "text/html", "application/json", "text/plain; charset=utf-8", "image/png"}
	survivals := [][]string{nil, {}, {"<", ">", "\"", "'"}, {"<"}}
	points := []string{"", "query", "cookie", "header", "body", "path"}
	statuses := []string{
		ReflectionObserved, ReflectionRaw, ReflectionEncoded, ReflectionNotReflected,
		ReflectionIsCredential, ReflectionError, ReflectionProbeRefused, ReflectionNotProbed, "unrecognised",
	}
	for _, status := range statuses {
		want := pointerStatusConcluded(status)
		for _, ct := range types {
			for _, survived := range survivals {
				for _, point := range points {
					got := XSSCandidateGrade(status, ct, survived, point) != XSSCandidateUnknown
					if got != want {
						t.Fatalf("status %q: conclusion changed with content type %q, survived %v, point %q: %v then %v",
							status, ct, survived, point, want, got)
					}
				}
			}
		}
	}
}

// Nothing in this file may contain an emdash, and the delivery and ranking sentences are the ones
// most likely to grow one.
func TestNoEmdashesInTheOperatorFacingText(t *testing.T) {
	var text []string
	for _, label := range pointerClassLabels {
		text = append(text, label)
	}
	for rank := 0; rank <= 5; rank++ {
		text = append(text, pointerStrengthWhy(rank))
	}
	for class := range pointerClassLabels {
		_, reason := pointerNextTool(class)
		text = append(text, reason)
		text = append(text, pointerPossibleAttacks(class, false)...)
		text = append(text, pointerPossibleAttacks(class, true)...)
	}
	text = append(text, pointerComposedURLNote, pointerNoURLNote)
	text = append(text, pointerCanaryNote(PointerFindingCoverage{
		Rows: 415, ExcludedCanary: 390, CanaryHost: "oracle:8000", CanaryUncheckable: 1,
		RowsByTool: map[string]int{"dalfox": 223}, CanaryByTool: map[string]int{"dalfox": 223},
	}))
	text = append(text, pointerCoverageHeadline(43, PointerCoverage{
		Vectors: PointerVectorCoverage{
			Total: 218, WithPointer: 28, Concluded: 34, Unknown: 184, PointersWithoutVector: 7,
			ConcludedBySource: map[string]int{PointerSourceReflection: 32, PointerSourceFinding: 2},
		},
		Reflection: PointerReflectionCoverage{ProbeRows: 1764, Unknown: 1714},
	}))
	text = append(text, pointerAttackPath(Pointer{
		AttackClass: triage.ClassXSSReflected.String(), InsertionPoint: "query", Parameter: "q",
		Method: "GET", URL: "https://app.example.test/a", URLOrigin: PointerURLComposed,
	}).Entry)
	for _, s := range text {
		if strings.ContainsAny(s, "—–") {
			t.Errorf("emdash or endash in operator-facing text: %q", s)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// The triage source says what the ROWS say, and nothing else
// ---------------------------------------------------------------------------------------------

// These are the tests that stop this file telling an operator their triage results do not exist.
//
// THE DEFECT THEY WERE WRITTEN AGAINST: the coverage block for the triage source carried the
// literal sentence "The triage runner is built and not yet wired, so no pointer in this list comes
// from it". The runner is wired and probing. Every target that had not been triaged yet therefore
// read as a feature that does not exist, an operator who believes it never presses Investigate,
// and every verdict the run would have produced is a finding nobody goes looking for. A stale
// sentence is a false negative when the sentence is the one the operator reads before deciding.

// pointersRouter registers the list route EXACTLY as main.go does, so what passes here is the path
// the client actually calls.
func pointersRouter() *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc("/attack-vectors/{scope_target_id}/pointers", GetAttackVectorPointers).Methods("GET")
	return r
}

func pointersGET(t *testing.T, target string) map[string]any {
	t.Helper()
	rec := httptest.NewRecorder()
	pointersRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/attack-vectors/"+target+"/pointers", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET pointers: %d %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET pointers returned something that is not JSON: %v: %s", err, rec.Body.String())
	}
	return body
}

func pointersTriageCoverage(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	cov, ok := body["coverage"].(map[string]any)
	if !ok {
		t.Fatalf("no coverage block on the response: %v", body)
	}
	tri, ok := cov["triage"].(map[string]any)
	if !ok {
		t.Fatalf("no triage coverage block on the response: %v", cov)
	}
	return tri
}

// THE REGRESSION TEST FOR THE STALE SENTENCE, over the wire, on the shape that produced it: a
// target with no triage run of its own.
//
// It asserts the two things the sentence has to do. It must not describe the runner as absent,
// unbuilt or unwired, because that is a claim about the code and the code changes underneath it.
// And it must name the button that would close the gap, because "no data" without "here is how to
// get some" is how an operator concludes there is nothing to get.
func TestATargetWithNoTriageRunIsToldToRunItRatherThanThatTheRunnerDoesNotExist(t *testing.T) {
	ctx := triageTestDB(t)
	target := triageTestTarget(t, ctx)

	tri := pointersTriageCoverage(t, pointersGET(t, target))
	note, _ := tri["note"].(string)
	if note == "" {
		t.Fatal("the triage coverage block carries no note at all, so a zero arrives with no reason beside it")
	}
	for _, claim := range []string{"not yet wired", "not wired", "is built and not", "empty today"} {
		if strings.Contains(strings.ToLower(note), claim) {
			t.Errorf("the note makes a claim about the state of the runner (%q), which goes stale the moment the runner changes and then reads to an operator as 'your triage results do not exist': %q", claim, note)
		}
	}
	if !strings.Contains(note, "Investigate") {
		t.Errorf("the note does not name the button that would produce triage data, so the gap reads as permanent: %q", note)
	}
	if !strings.Contains(strings.ToLower(note), "not a clean result") {
		t.Errorf("the note does not say the zero is a gap rather than a clean: %q", note)
	}
	if got, _ := tri["status"].(string); got != PointerTriageNoRun {
		t.Errorf("status %q, want %q: the status is what the client switches on", got, PointerTriageNoRun)
	}
}

// THE SAME SENTENCE, DERIVED. Six different situations produce "0 triage pointers" and only one of
// them is anything like a clean. This is the table of all six, and the point of it is that every
// row is selected by data: there is no branch here that any human has to remember to edit.
func TestTheTriageNoteIsDerivedFromTheRowsRatherThanAsserted(t *testing.T) {
	cases := []struct {
		name       string
		cov        PointerTriageCoverage
		wantStatus string
		wantIn     []string
	}{
		{
			name: "no run at all", cov: PointerTriageCoverage{},
			wantStatus: PointerTriageNoRun,
			wantIn:     []string{"No triage run has been started", "Investigate", "not a clean result"},
		},
		{
			name:       "tables unreadable",
			cov:        PointerTriageCoverage{ReadError: "relation \"triage_runs\" does not exist"},
			wantStatus: PointerTriageUnreadable,
			wantIn:     []string{"could not be read in full", "does not exist", "not a zero"},
		},
		{
			name: "still going",
			cov: PointerTriageCoverage{RunID: "r1", RunStatus: "running", RunPhase: "probing",
				PlannedPairs: 77, CompletedPairs: 9, ProbesSent: 112, Verdicts: 14},
			wantStatus: PointerTriageRunning,
			wantIn:     []string{"still going", "probing", "9 of 77 planned pairs", "unmeasured rather than clean"},
		},
		{
			name: "cancelled part way",
			cov: PointerTriageCoverage{RunID: "r2", RunStatus: "cancelled",
				PlannedPairs: 77, CompletedPairs: 3, Verdicts: 5},
			wantStatus: PointerTriageCancelled,
			wantIn:     []string{"cancelled before it finished", "unmeasured rather than clean"},
		},
		{
			name: "errored part way",
			cov: PointerTriageCoverage{RunID: "r3", RunStatus: "error",
				PlannedPairs: 77, CompletedPairs: 40, Verdicts: 61},
			wantStatus: PointerTriageRunFailed,
			wantIn:     []string{"ended in an error", "unmeasured rather than clean"},
		},
		{
			name: "finished with verdicts and positives",
			cov: PointerTriageCoverage{RunID: "r4", RunStatus: "completed", Slots: 231, Pairs: 77,
				Verdicts: 77, Positive: 4, Unknown: 12, PayloadUnproven: 3, ProbesSent: 955,
				PlannedPairs: 77, CompletedPairs: 77},
			wantStatus: PointerTriageRead,
			wantIn: []string{"77 verdicts", "4 positive became pointers", "12 are unknown",
				"3 rest on a payload", "955 probes sent across 77 of 77 planned pairs"},
		},
		{
			name:       "finished having recorded nothing",
			cov:        PointerTriageCoverage{RunID: "r5", RunStatus: "completed", PlannedPairs: 77},
			wantStatus: PointerTriageRead,
			wantIn:     []string{"recorded no verdict at all", "not a clean result"},
		},
		{
			name: "finished with verdicts and no positive",
			cov: PointerTriageCoverage{RunID: "r6", RunStatus: "completed", Verdicts: 77,
				Unknown: 30, PlannedPairs: 77, CompletedPairs: 77},
			wantStatus: PointerTriageRead,
			wantIn:     []string{"no positive state", "rather than as a clean bill"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := triageCoverageFinish(tc.cov)
			if got.Status != tc.wantStatus {
				t.Errorf("status %q, want %q", got.Status, tc.wantStatus)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(got.Note, want) {
					t.Errorf("note does not contain %q: %s", want, got.Note)
				}
			}
			if strings.ContainsAny(got.Note, "—–") {
				t.Errorf("emdash or endash in the note: %q", got.Note)
			}
		})
	}
}

// NOT KNOWING IS NOT CLEAN, at the level of the struct the client switches on. A read that failed
// outranks every count in the block, because a count nobody could read is not a zero, and Measured
// is the one predicate the rest of the screen is allowed to ask before treating this source's
// silence as meaningful.
func TestAnUnreadableTriageTableIsNeverMeasured(t *testing.T) {
	unreadable := PointerTriageCoverage{RunID: "r1", RunStatus: "completed", Verdicts: 77,
		ReadError: "connection refused"}
	if triageCoverageStatus(unreadable) != PointerTriageUnreadable {
		t.Errorf("a failed read reported as %q: a broken database and an untriaged target must not look alike", triageCoverageStatus(unreadable))
	}
	if unreadable.Measured() {
		t.Error("a coverage block whose read failed reports itself as measured")
	}
	for _, notMeasured := range []PointerTriageCoverage{
		{},
		{RunID: "r", RunStatus: "running", Verdicts: 3},
		{RunID: "r", RunStatus: "cancelled", Verdicts: 3},
		{RunID: "r", RunStatus: "error", Verdicts: 3},
		{RunID: "r", RunStatus: "completed"},
	} {
		if notMeasured.Measured() {
			t.Errorf("%+v reports itself as measured, so its zero would render as a clean", notMeasured)
		}
	}
	measured := PointerTriageCoverage{RunID: "r", RunStatus: "completed", Verdicts: 77}
	if !measured.Measured() {
		t.Error("a completed run with verdicts, read without error, does not report itself as measured")
	}
	if !measured.HasRun() || !measured.HasVerdicts() {
		t.Error("HasRun and HasVerdicts are the derivations the screen asks instead of reading a sentence")
	}
}

// THE BRANCH ITSELF, END TO END, against the only target these tests may reach.
//
// collectTriagePointers was written against an empty table and had never been shown turning a real
// verdict into a real pointer. This runs the classifiers at the local oracle, then calls the
// endpoint the client calls and requires triage-sourced pointers to come back out of it, carrying
// the fields the card renders. A source that has never once produced a row is a source nobody can
// say works.
func TestTriageVerdictsBecomePointersOnTheOracle(t *testing.T) {
	base := triageOracleBase(t)
	ctx := triageTestDB(t)
	scopeTargetID, vectors := triageOracleTarget(t, ctx, base)

	// EVERY REGISTERED CLASS, at full tier. The narrow two-class run is triageRun_test's, where
	// the question is whether a classifier fires and stays silent in the right places. The
	// question here is whether the pointer layer can carry whatever the ten classifiers produce,
	// so the run is the one the Investigate button actually starts.
	settings := TriageSettingsDefaults()
	for key := range settings.Classes {
		cs := settings.Classes[key]
		cs.Enabled = true
		cs.Tier = string(triage.TierFull)
		settings.Classes[key] = cs
	}
	settings.Tier = string(triage.TierFull)
	settings.Pacing.RequestsPerSecond = 20
	settings.Pacing.RespectTargetBudget = false
	triageSaveSettings(t, ctx, scopeTargetID, settings)

	runUUID, err := StartTriageRun(ctx, scopeTargetID)
	if err != nil {
		t.Fatalf("start the run: %v", err)
	}
	if status := triageWaitForRun(t, ctx, runUUID, 10*time.Minute); status != "completed" {
		t.Fatalf("the run finished %q rather than completed", status)
	}

	body := pointersGET(t, scopeTargetID)
	tri := pointersTriageCoverage(t, body)
	t.Logf("triage coverage: %v", tri)
	if got, _ := tri["status"].(string); got != PointerTriageRead {
		t.Fatalf("triage coverage status %q after a completed run, want %q", got, PointerTriageRead)
	}
	if got, _ := tri["run_id"].(string); got != runUUID {
		t.Errorf("coverage names run %q, the run that just finished is %q", got, runUUID)
	}

	name := map[string]string{}
	for k, id := range vectors {
		name[id] = k
	}
	triagePointers := 0
	for _, raw := range body["pointers"].([]any) {
		p := raw.(map[string]any)
		if p["source"] != PointerSourceTriage {
			continue
		}
		triagePointers++
		t.Logf("triage pointer: vector=%s class=%s grade=%v strength=%v point=%v url=%v rule=%v next=%v",
			name[p["vector_id"].(string)], p["attack_class"], p["grade"], p["strength"],
			p["insertion_point"], p["url"], p["rule"], p["next_tool"])
		for _, field := range []string{"attack_class", "rule", "next_tool", "strength"} {
			if s, _ := p[field].(string); strings.TrimSpace(s) == "" {
				t.Errorf("a triage pointer carries no %s, so the card has nothing to render: %v", field, p)
			}
		}
	}
	if triagePointers == 0 {
		t.Fatalf("the run produced %v verdicts of which %v positive, and not one of them reached the pointer list. The triage branch is broken, which is a larger defect than the sentence that described it",
			tri["verdicts"], tri["positive"])
	}
	if counts, ok := body["counts"].(map[string]any); ok {
		t.Logf("pointers by source: %v", counts["by_source"])
	}
	t.Logf("headline: %v", body["coverage"].(map[string]any)["headline"])
}
