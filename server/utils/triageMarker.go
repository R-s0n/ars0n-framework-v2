package utils

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ars0n-framework-v2-server/utils/internal/triagecap"
	"ars0n-framework-v2-server/utils/triage"
)

// Marker minting, marker search and marker attribution: the half of the triage layer that decides
// whether a byte sequence in a response is THIS class's reflection, another class's reflection, a
// mangled remnant, or nothing at all.
//
// The skeleton (triage/types.go, one package down) owns the Marker type, its layout constants and the pure readers
// WellFormed / RunID / Ordinal / ClassID / BelongsTo. This file owns everything that has to
// compute: the checksum, the striped allocator, the encoded-form search, and the per-class
// attribution verdict.
//
// THE ISOLATION LAW IN ARITHMETIC. Ordinals are striped, ordinal mod ClassStripeModulus == the
// owning class id, so every marker names its owner without a lookup table. A class asks exactly
// one question of a token it found, BelongsTo, and a token from another stripe answers no. There
// is no path by which class B reaches a verdict from a marker class A emitted: not "B ignored it",
// but "B cannot match it". TestAForeignMarkerIsAHitForNobodyAcrossEveryClassStripe proves that
// over all 27 class ordinals rather than asserting it.
//
// WHY THE SEARCH IS NOT A strings.Contains. Requirement set from foundations part 2.5: a marker
// has to survive case folding, HTML numeric character references, percent encoding,
// alphanumeric-only filtering and field truncation, and a TRUNCATED marker has to come back
// distinguishable from an ABSENT one. Absent is a measurement and a reflection oracle may read it
// as negative. Truncated is not a measurement: the field ate part of the token, so nothing can be
// concluded, and it gets its own verdict that never renders as clean.

// ---------------------------------------------------------------------------------------------
// 1. MINTING
// ---------------------------------------------------------------------------------------------

// markerPrefixLen is anchor + run id + ordinal, the bytes the checksum is computed over. It is
// re-derived here from the exported layout constants rather than exported from package triage,
// because the scanner below needs the length and nothing outside this file needs the name.
const markerPrefixLen = triage.MarkerAnchorLen + triage.MarkerRunIDLen + triage.MarkerOrdinalLen

// MintedMarker is the issue record. The marker carries WHICH PROBE emitted it because the ordinal
// IS the probe record's key, and this is the table that resolves it back.
//
// WHY THIS EXISTS RATHER THAN A BARE MARKER. A response can arrive after its probe, out of a
// cache, or out of order behind a proxy. Without the issue record, a late body proves only that
// some request once carried that token. With it, the class, the probe id, the slot and the mint
// time are all recoverable, so a late body is either attributable or explicitly stale, never
// quietly folded into whatever probe happened to be in flight when it landed.
type MintedMarker struct {
	Marker   triage.Marker
	Ordinal  uint64
	Class    triage.ClassID
	ProbeID  triage.ProbeID
	SlotKey  triage.SlotKey
	RunID    string
	MintedAt time.Time
}

// MarkerMinter allocates striped ordinals for one run. A class NEVER mints its own marker: the
// runner mints and hands the marker over in a ProbeRequest, which is what makes the stripe an
// invariant of the system instead of a convention each of the 27 classes has to remember.
type MarkerMinter struct {
	mu sync.Mutex
	// cap is the runner capability, held by the allocator rather than read from a package-level
	// variable, so there is no process-lifetime symbol for anything to reach for.
	cap    triagecap.Runner
	runID  string
	next   map[triage.ClassID]uint64
	issued map[triage.Marker]MintedMarker
	now    func() time.Time
}

// NewMarkerMinter starts an allocator for runID.
func NewMarkerMinter(runID string) (*MarkerMinter, error) {
	if !triage.WellFormedRunID(runID) {
		return nil, fmt.Errorf("triage: run id %q is not %d bytes of [0-9a-z]", runID, triage.MarkerRunIDLen)
	}
	return &MarkerMinter{
		cap:    triagecap.Grant(),
		runID:  runID,
		next:   map[triage.ClassID]uint64{},
		issued: map[triage.Marker]MintedMarker{},
		now:    time.Now,
	}, nil
}

// RunID is the run this minter stamps into every marker.
func (m *MarkerMinter) RunID() string { return m.runID }

// Mint allocates the next ordinal in owner's stripe. Safe for concurrent use: the runner sends
// probes from a worker pool, and two goroutines racing on the counter would issue one ordinal
// twice, which would make two probes indistinguishable in exactly the responses they reflect into.
func (m *MarkerMinter) Mint(owner triage.ClassID, probe triage.ProbeID, slot triage.SlotKey) (MintedMarker, error) {
	if !owner.Known() {
		return MintedMarker{}, fmt.Errorf("triage: refusing to mint a marker for unknown class id %d", uint8(owner))
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	ord, seen := m.next[owner]
	if !seen {
		// The first ordinal in a stripe is the class id itself, so the stripe arithmetic holds
		// from the very first probe rather than from the second.
		ord = uint64(owner)
	}
	if ord > triage.MarkerOrdinalMax {
		return MintedMarker{}, fmt.Errorf("triage: class %s has exhausted its ordinal stripe at %d; wrapping would re-issue a live marker",
			owner, uint64(triage.MarkerOrdinalMax))
	}
	mk, err := triage.MintMarkerAt(m.cap, m.runID, owner, ord)
	if err != nil {
		return MintedMarker{}, err
	}
	rec := MintedMarker{
		Marker:   mk,
		Ordinal:  ord,
		Class:    owner,
		ProbeID:  probe,
		SlotKey:  slot,
		RunID:    m.runID,
		MintedAt: m.now(),
	}
	m.next[owner] = ord + triage.ClassStripeModulus
	m.issued[mk] = rec
	return rec, nil
}

// Lookup resolves a marker seen in a response back to the probe that emitted it.
func (m *MarkerMinter) Lookup(mk triage.Marker) (MintedMarker, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.issued[mk]
	return rec, ok
}

// Issued is the number of markers handed out, for the run report.
func (m *MarkerMinter) Issued() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.issued)
}

// ---------------------------------------------------------------------------------------------
// 2. THE SEARCH, OVER THE TRANSFORM SET
// ---------------------------------------------------------------------------------------------

// The Form values recorded on a MarkerHit. They name the TRANSPORT transform that had to be undone
// to see the token; case is recorded separately in CaseTransform, because an application can fold
// case and percent-encode in the same pipeline and one field could only report one of them.
const (
	MarkerFormRaw      = "raw"
	MarkerFormNCR      = "ncr"      // HTML numeric character references, &#122; and &#x7a;
	MarkerFormPercent  = "percent"  // %7a%71%6a...
	MarkerFormSqueezed = "squeezed" // every non-alphanumeric byte dropped, per the filter case
)

// markerSearchNotImplemented names the transforms this search does NOT undo. It is a declared list
// and a test pins it, so closing a gap is a visible decision in a diff rather than a silent change
// of coverage. Most of the reflection-reading classes read reflections through this function; a
// gap nobody can see is a false clean for all of them at once.
var markerSearchNotImplemented = []string{
	"base64: a marker re-emitted inside a base64 blob is not extracted",
	"wide encodings: a marker interleaved with NUL bytes by a utf-16 response is not extracted",
	"unicode escapes: backslash-u escapes of the alphabet in JS or JSON are not decoded",
}

// MarkerSearchGaps is the declared coverage gap of ScanMarkers.
func MarkerSearchGaps() []string {
	out := make([]string, len(markerSearchNotImplemented))
	copy(out, markerSearchNotImplemented)
	return out
}

// MarkerCompleteness separates the two things a partial token can mean.
type MarkerCompleteness string

const (
	// MarkerComplete is all sixteen bytes present and in the alphabet.
	MarkerComplete MarkerCompleteness = "complete"

	// MarkerTruncated is the anchor and at least the run id present, then the run of
	// alphanumerics ending early. NOT KNOWING IS NOT CLEAN: a field that ate four bytes of the
	// token did something to the payload, and no reflection verdict can be drawn either way.
	MarkerTruncated MarkerCompleteness = "truncated"
)

// markerMinSightingLen is the anchor plus the run id. Below that, a "zqj" in a response is three
// letters, and reporting it would turn every page that contains the anchor into an unknown.
const markerMinSightingLen = triage.MarkerAnchorLen + triage.MarkerRunIDLen

// MarkerSighting is one occurrence of something marker-shaped, carrying everything that could be
// read off it and nothing that could not.
type MarkerSighting struct {
	Hit          triage.MarkerHit
	Completeness MarkerCompleteness

	// Text is the alphanumeric run as read, lowercased, at most MarkerLen bytes. For a truncated
	// sighting it is the only evidence there is, and it is kept so a field limit can be measured
	// from it: len(Text) is where the field cut.
	Text string

	RunID        string
	Ordinal      uint64
	OrdinalKnown bool
	Class        triage.ClassID
	ClassKnown   bool
	Integrity    triage.MarkerIntegrity
}

// triageIsMarkerAlnum matches the marker alphabet before case folding.
func triageIsMarkerAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// triageDecodedPass is one search pass: bytes to scan, plus the offset in the ORIGINAL body each byte
// came from. Offsets are reported against the original body, because an offset into a decoded
// buffer nobody kept is not evidence.
type triageDecodedPass struct {
	form string
	text []byte
	orig []int
}

// triagePassRaw is the identity pass.
func triagePassRaw(body []byte) triageDecodedPass {
	orig := make([]int, len(body))
	for i := range body {
		orig[i] = i
	}
	return triageDecodedPass{form: MarkerFormRaw, text: body, orig: orig}
}

// triagePassNCR undoes HTML numeric character references only. Named entities are deliberately not
// decoded: the marker alphabet is [0-9a-z] and no named entity encodes an alphanumeric, so a
// named-entity decoder would add no coverage while folding &amp; into & and shifting every offset
// after it.
func triagePassNCR(body []byte) triageDecodedPass {
	out := make([]byte, 0, len(body))
	orig := make([]int, 0, len(body))
	for i := 0; i < len(body); {
		if body[i] == '&' && i+2 < len(body) && body[i+1] == '#' {
			j := i + 2
			base := 10
			if j < len(body) && (body[j] == 'x' || body[j] == 'X') {
				base = 16
				j++
			}
			start := j
			for j < len(body) && j-start < 8 && triageIsDigitInBase(body[j], base) {
				j++
			}
			if j > start && j < len(body) && body[j] == ';' {
				if v, err := strconv.ParseUint(string(body[start:j]), base, 32); err == nil && v < 128 {
					out = append(out, byte(v))
					orig = append(orig, i)
					i = j + 1
					continue
				}
			}
		}
		out = append(out, body[i])
		orig = append(orig, i)
		i++
	}
	return triageDecodedPass{form: MarkerFormNCR, text: out, orig: orig}
}

func triageIsDigitInBase(b byte, base int) bool {
	if b >= '0' && b <= '9' {
		return true
	}
	if base == 16 {
		return (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
	}
	return false
}

// triagePassPercent undoes %XX. It does NOT use url.QueryUnescape: that returns an error on a stray
// percent and abandons the whole string, and a response containing one malformed escape is exactly
// the kind of body a marker ends up in.
func triagePassPercent(body []byte) triageDecodedPass {
	out := make([]byte, 0, len(body))
	orig := make([]int, 0, len(body))
	for i := 0; i < len(body); {
		if body[i] == '%' && i+2 < len(body) {
			if v, err := strconv.ParseUint(string(body[i+1:i+3]), 16, 8); err == nil {
				out = append(out, byte(v))
				orig = append(orig, i)
				i += 3
				continue
			}
		}
		out = append(out, body[i])
		orig = append(orig, i)
		i++
	}
	return triageDecodedPass{form: MarkerFormPercent, text: out, orig: orig}
}

// triagePassSqueeze drops every non-alphanumeric byte. This is the alphanumeric-only filter case from
// the requirement set, and it also recovers a marker an application broke up with delimiters, for
// example a token re-rendered as zqj-1f3q-000041-xyz or with a zero-width space injected by a
// templating layer. The checksum is what stops the squeeze from manufacturing sightings out of
// unrelated alphanumerics that happen to sit next to an anchor.
func triagePassSqueeze(body []byte) triageDecodedPass {
	out := make([]byte, 0, len(body))
	orig := make([]int, 0, len(body))
	for i := 0; i < len(body); i++ {
		if triageIsMarkerAlnum(body[i]) {
			out = append(out, body[i])
			orig = append(orig, i)
		}
	}
	return triageDecodedPass{form: MarkerFormSqueezed, text: out, orig: orig}
}

// triageCaseTransformOf names what happened to the case of the run, in the MarkerHit vocabulary
// none | upper | title | mixed.
func triageCaseTransformOf(raw string) string {
	hasUpper, hasLower := false, false
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 'A' && raw[i] <= 'Z' {
			hasUpper = true
		}
		if raw[i] >= 'a' && raw[i] <= 'z' {
			hasLower = true
		}
	}
	switch {
	case !hasUpper:
		return "none"
	case !hasLower:
		return "upper"
	case raw[0] >= 'A' && raw[0] <= 'Z':
		return "title"
	default:
		return "mixed"
	}
}

// ScanMarkers finds every marker-shaped run in body, across the transform set, and reports what
// could be read off each one.
//
// It attributes nothing. Attribution is AttributeMarkers, and it is a separate function taking the
// asking class, so "what is in this body" and "is any of it mine" can never be the same question
// answered once and shared between classes.
func ScanMarkers(body []byte) []MarkerSighting {
	passes := []triageDecodedPass{triagePassRaw(body), triagePassNCR(body), triagePassPercent(body), triagePassSqueeze(body)}

	// One sighting per position in the ORIGINAL body. The least-transformed pass that found
	// something there wins, with one upgrade: a later pass that recovers a COMPLETE token where
	// an earlier pass could only see a truncated run replaces it.
	//
	// The upgrade is not cosmetic. The squeeze pass glues a run across whatever delimiter follows
	// it, so on a body like "<p>zqj1f3q000<\p>" the raw pass sees ten bytes and the squeeze pass
	// sees twelve; both are truncated, and reporting both would double-count one remnant. On a
	// body where an application injected a delimiter INTO the token, the squeeze pass is the only
	// one that recovers all sixteen bytes, and that sighting has to win.
	at := map[int]int{}
	var out []MarkerSighting

	for _, p := range passes {
		// The squeeze pass reports COMPLETE tokens only. It is the one pass that deletes bytes
		// rather than decoding them, so it glues a run across whatever delimiter follows, and a
		// partial run it produces cannot be told apart from the neighbouring text: "the band zqj
		// played" squeezes to "thebandzqjplayed" and offers "zqjplayed" as a nine-byte remnant.
		// Sixteen bytes with a recomputing checksum is credible; anything shorter from this pass
		// is noise, and noise that reads as an unknown is how a real page becomes untestable.
		completeOnly := p.form == MarkerFormSqueezed
		for _, s := range triageScanOnePass(p) {
			if completeOnly && s.Completeness != MarkerComplete {
				continue
			}
			idx, seen := at[s.Hit.Offset]
			if !seen {
				at[s.Hit.Offset] = len(out)
				out = append(out, s)
				continue
			}
			if out[idx].Completeness != MarkerComplete && s.Completeness == MarkerComplete {
				out[idx] = s
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Hit.Offset < out[j].Hit.Offset })
	return out
}

func triageScanOnePass(p triageDecodedPass) []MarkerSighting {
	var out []MarkerSighting
	lower := strings.ToLower(string(p.text))
	for i := 0; i+triage.MarkerAnchorLen <= len(lower); i++ {
		if lower[i:i+triage.MarkerAnchorLen] != triage.DefaultMarkerAnchor {
			continue
		}
		// Read the alphanumeric run from the anchor, capped at the marker length. Capping rather
		// than demanding a delimiter is the alphanumeric-filter case: a token glued to the text
		// after it is still a token, and the checksum is what rejects a bad slice.
		end := i
		for end < len(lower) && end-i < triage.MarkerLen && triageIsMarkerAlnum(p.text[end]) {
			end++
		}
		run := lower[i:end]
		if len(run) < markerMinSightingLen {
			continue
		}
		s := MarkerSighting{
			Hit: triage.MarkerHit{
				Form:          p.form,
				Offset:        p.orig[i],
				Length:        p.orig[end-1] - p.orig[i] + 1,
				CaseTransform: triageCaseTransformOf(string(p.text[i:end])),
			},
			Text:  run,
			RunID: run[triage.MarkerAnchorLen:markerMinSightingLen],
		}

		if len(run) >= markerPrefixLen {
			if n, err := strconv.ParseUint(run[markerMinSightingLen:markerPrefixLen], 36, 64); err == nil {
				s.Ordinal = n
				s.OrdinalKnown = true
				s.Class = triage.ClassID(n % triage.ClassStripeModulus)
				s.ClassKnown = true
			}
		}
		if len(run) == triage.MarkerLen {
			if mk := triage.Marker(run); mk.WellFormed() {
				s.Completeness = MarkerComplete
				s.Hit.Marker = mk
				s.Integrity = triage.VerifyMarkerIntegrity(mk)
			}
		}
		if s.Completeness == "" {
			// Anything short of sixteen well-formed bytes is truncated, NOT absent. The two are
			// different answers and every caller is required to be able to tell them apart.
			s.Completeness = MarkerTruncated
			s.Integrity = triage.MarkerUnchecked
		}
		out = append(out, s)
		i = end - 1
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 3. ATTRIBUTION: THE ONE QUESTION A CLASS IS ALLOWED TO ASK
// ---------------------------------------------------------------------------------------------

// MarkerVerdict is what a body says about ONE class's markers. Every value is either a measurement
// or an explicit unknown, and IsUnknown is the predicate that keeps the unknowns out of clean.
type MarkerVerdict string

const (
	// MarkerVerdictAbsent is a real measurement: nothing marker-shaped belonging to this class is
	// in this body. A reflection oracle may read it as negative.
	MarkerVerdictAbsent MarkerVerdict = "absent"

	// MarkerVerdictMine is this class's own marker, this run, checksum valid.
	MarkerVerdictMine MarkerVerdict = "mine"

	// MarkerVerdictForeign is another class's stripe, and nothing of ours. Also a measurement: our
	// payload did not reflect. Recorded rather than dropped, because another class's marker
	// appearing in a response we did not send it in is how a stored-reflection surface announces
	// itself.
	MarkerVerdictForeign MarkerVerdict = "foreign"

	// MarkerVerdictStaleRun is our stripe, another run's id: a cached or replayed body. UNKNOWN.
	MarkerVerdictStaleRun MarkerVerdict = "stale_run"

	// MarkerVerdictTruncated is a partial token that could be ours. UNKNOWN.
	MarkerVerdictTruncated MarkerVerdict = "truncated_unattributable"

	// MarkerVerdictCorrupted is sixteen well-formed bytes in our stripe whose checksum does not
	// recompute. UNKNOWN: either the application rewrote a character, or the slice was never a
	// marker and the stripe arithmetic is reading noise.
	MarkerVerdictCorrupted MarkerVerdict = "corrupted"
)

// IsHit is true for exactly one verdict. A reflection is attributable or it is not.
func (v MarkerVerdict) IsHit() bool { return v == MarkerVerdictMine }

// IsUnknown fails closed: anything this function does not recognise is unknown. NOT KNOWING IS NOT
// CLEAN, and the way that rule gets broken is a new constant added without a case here.
func (v MarkerVerdict) IsUnknown() bool {
	switch v {
	case MarkerVerdictAbsent, MarkerVerdictMine, MarkerVerdictForeign:
		return false
	default:
		return true
	}
}

// MarkerAttribution is the full answer for one class, with the evidence kept in buckets so a run
// report can say WHY the class got the verdict it got.
type MarkerAttribution struct {
	Owner   triage.ClassID
	RunID   string
	Verdict MarkerVerdict

	Mine           []MarkerSighting
	Foreign        []MarkerSighting
	Stale          []MarkerSighting
	Truncated      []MarkerSighting
	Corrupted      []MarkerSighting
	ForeignClasses []triage.ClassID
}

// AttributeMarkers answers "is any of this mine" for exactly one class.
//
// THE ISOLATION LAW LIVES HERE. Two classes handed the same sightings get two different answers,
// and neither can reach the other's. A marker from another stripe lands in Foreign for every class
// that asks, which means it is a hit for nobody: not ignored by the honest classes and then
// claimed by the first one to look, but unclaimable by construction.
//
// Precedence among our own sightings is deliberately unknown-first. A stale or truncated token of
// ours outranks a clean one, because it says the transport did something we did not model and the
// clean sighting may not be the whole story. Only Mine with nothing of ours unexplained is a hit.
func AttributeMarkers(sightings []MarkerSighting, owner triage.ClassID, runID string) MarkerAttribution {
	a := MarkerAttribution{Owner: owner, RunID: runID}
	foreignSeen := map[triage.ClassID]bool{}

	for _, s := range sightings {
		switch {
		case s.Completeness == MarkerTruncated:
			// A truncated token names a class only if the six ordinal digits survived. If they
			// did and they are not ours, it is somebody else's remnant and not our unknown.
			if s.ClassKnown && s.Class != owner {
				a.Foreign = append(a.Foreign, s)
				foreignSeen[s.Class] = true
				continue
			}
			// A run id that is not ours could not have been minted by this run at all, so the
			// remnant is somebody else's regardless of how much of the ordinal survived.
			if s.RunID != runID {
				a.Foreign = append(a.Foreign, s)
				continue
			}
			// What is left is a remnant from THIS run whose owner cannot be read. It is an
			// unknown for every class that asks, this one included, and that is deliberate: a
			// response nobody can attribute is a response nobody may call clean on reflection
			// grounds. Fail-closed costs scanner time; the other direction costs a finding.
			a.Truncated = append(a.Truncated, s)
		case !s.ClassKnown || s.Class != owner:
			a.Foreign = append(a.Foreign, s)
			if s.ClassKnown {
				foreignSeen[s.Class] = true
			}
		case s.Integrity != triage.MarkerValid:
			a.Corrupted = append(a.Corrupted, s)
		case s.RunID != runID:
			a.Stale = append(a.Stale, s)
		default:
			a.Mine = append(a.Mine, s)
		}
	}

	for c := range foreignSeen {
		a.ForeignClasses = append(a.ForeignClasses, c)
	}
	sort.Slice(a.ForeignClasses, func(i, j int) bool { return a.ForeignClasses[i] < a.ForeignClasses[j] })

	switch {
	case len(a.Truncated) > 0:
		a.Verdict = MarkerVerdictTruncated
	case len(a.Corrupted) > 0:
		a.Verdict = MarkerVerdictCorrupted
	case len(a.Stale) > 0:
		a.Verdict = MarkerVerdictStaleRun
	case len(a.Mine) > 0:
		a.Verdict = MarkerVerdictMine
	case len(a.Foreign) > 0:
		a.Verdict = MarkerVerdictForeign
	default:
		a.Verdict = MarkerVerdictAbsent
	}
	return a
}

// AttributeObservation is what the classifiers will actually call: scan the body, then answer for
// one class. It takes the class explicitly for the reason the vault's accessors no longer do: it
// is called by the RUNNER, which legitimately handles every class at once, and not by a
// classifier. A classifier never names a class; see triage.OwnedResponses. In package
// utils there is no unexported boundary, so the owner is named at every call site.
func AttributeObservation(obs triage.Observation, owner triage.ClassID, runID string) MarkerAttribution {
	return AttributeMarkers(ScanMarkers(obs.Body), owner, runID)
}

// WIRING NOTE, NOW DONE. The skeleton declared two bodies that belonged here and both have been
// resolved in place: Marker.Integrity() delegates to VerifyMarkerIntegrity above instead of
// returning MarkerUnchecked forever, and the free MintMarker stub has been deleted rather than
// given a package-level counter, which would make two concurrent runs share a sequence and issue
// the same ordinal twice. The runner holds one *MarkerMinter per run and calls Mint.
