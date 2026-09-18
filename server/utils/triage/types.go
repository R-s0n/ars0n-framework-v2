// Package triage is the isolation-critical core of the Investigate triage layer.
//
// WHY IT IS ITS OWN PACKAGE. The layer's one law is that every attack class gets its own payloads
// and reaches a verdict only from ITS OWN probes' responses. That law was previously defended
// inside package utils by a vault plus a source-scanning test, and it kept springing leaks,
// because in one package every field is reachable and the test that guards it is itself code that
// a new file can step around. An adversarial review found a fourth leak that left the whole suite
// green: a file named sqliClassifier.go ranging over the vault's held map, and reaching that vault
// with nothing but a run id.
//
// IN GO THE ONLY REAL BOUNDARY IS THE PACKAGE. So the core types and the vault live here, the
// fields behind them are unexported, and a classifier in server/triageclasses physically cannot
// name them. Those leaks are compile errors rather than test failures. See
// triageclasses/leak_test.go, which builds each one and asserts the compiler refuses it.
//
// AND THEN THE PACKAGE BOUNDARY TURNED OUT NOT TO BE ENOUGH EITHER. An adversarial audit ran
// fifteen attempts against the split and five succeeded, three of them with no unsafe and all of
// them vet-clean, because UNEXPORTING A FIELD STOPS THE COMPILER AND STOPS NOTHING ELSE: reflect
// reads straight through one. The object a classifier could reach CONTAINED every class's
// Observation, so every reflective path found them all. Three things changed:
//
//   - The vault is PARTITIONED BY (run, class). A Perturbed points at its owner's partition, so a
//     reflect walk from a handle enumerates what the caller was already handed. See section 8a of
//     vault.go.
//   - Minting, releasing and filtering take a capability whose type lives in
//     server/utils/internal/triagecap. Go's internal rule makes it importable by everything under
//     server/utils and nothing else, which is why the classifiers moved OUT of server/utils to
//     server/triageclasses. Partitioning the read side alone is undone by a class that can mint
//     into another class's partition.
//   - The package-level run registry is gone. It was the root //go:linkname needed.
//
// The runtime half of the regression suite lives in utils/triageadversary, because a compile-fail
// harness is structurally blind to an attack that compiles.
//
// WHAT IS HERE AND WHAT IS NOT. Here: the vocabulary (ClassID, TriageState, Slot, SlotKind,
// Observation, PayloadWire, Marker), the two observation wrappers (Replay and Perturbed) with the
// vault behind them, what a classifier receives (PlanCtx, ClassifyCtx) and what it returns
// (ClassVerdict), the probe declaration (ProbeSpec), the Classifier interface and the registry.
// Not here, and in package utils above: the runner, the store, the schema, the response
// comparator, the encoder, the marker MINTER and the prelude. Those need a database handle and the
// vector-composition helpers, and dragging them down here would either create an import cycle or
// force a wide exported surface, which is the worse boundary.
//
// THE SPLIT RULE WHEREVER A CYCLE THREATENS: TYPES DOWN, BEHAVIOUR UP. Slot is here; SlotsFor, the
// derivation that needs utils.templatedPathSegments, stays in utils and returns []triage.Slot.
package triage

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// The Investigate triage layer: the shared vocabulary and the core types.
//
// WHAT THIS LAYER IS. Between "the crawl captured 218 attack vectors" and "point sqlmap at this
// one" there is a cheap triage pass: for every insertion point on every vector, decide per attack
// class whether the expensive scanner is worth a run. The layer is specified in
// scratchpad/sqli-probe/CATALOGUE.md (sections 4 and 5) and iso-00-foundations.md (parts 2, 3, 6).
// This file is the skeleton those two documents describe. The classifiers, the encoders, the
// response comparators and the marker minter are other files and other people.
//
// THE ISOLATION LAW, WHICH IS WHY THE TYPES LOOK LIKE THIS. Every attack class gets its own
// payloads. No payload serves two classes, no class reaches a verdict from another class's
// response, and there is no shared gate probe. The reason is not tidiness. A merged payload can be
// rejected by a validator that either half alone would have passed, or blocked by a WAF rule that
// neither half alone would have tripped, and afterwards you cannot tell which happened. You then
// record clean for a class you never tested, and the operator never points the expensive scanner
// at the one place it would have found something. A false negative is the expensive error here; a
// false positive only costs scanner time.
//
// The law is enforced by types rather than by comment:
//
//   - Replay is a response to an UNPERTURBED request. It carries no payload, so it is the control,
//     so sharing it is correct. NewReplay refuses an observation that carries a class, an ordinal,
//     A PAYLOAD RECORD OR A MARKER, which closes the "re-stamp a probe and pass it off as a
//     control" route. The stamps are not believed on their own: a mis-stamped probe would
//     otherwise launder itself into the one channel every class reads.
//   - Perturbed is a response to a request that carried a payload, so it belongs to exactly one
//     class. IT HOLDS NO OBSERVATION. The response lives in a per-run vault and Perturbed is a
//     handle to it, so there is no field to read, an invented handle resolves to nothing, and a
//     stolen handle resolves to its true owner. See section 8a. The vault's fields are unexported
//     and this is now its own package, so from a classifier those are compile errors and not
//     runtime refusals; when all of this lived in package utils beside 300 other files,
//     unexported meant nothing and an accessor check meant little, because a direct field read
//     and a forged composite literal both go around the accessor rather than through it.
//   - Marker ordinals are striped, ordinal mod 64 == class id, so a marker emitted by one class
//     cannot be attributed to another by arithmetic (ruling R12).
//
// NOT KNOWING IS NOT CLEAN. Every failure to measure has its own state, none of them renders as
// clean, and the zero value of every "did it work" field means unknown rather than fine. This
// codebase has shipped the other version of that bug more than once, most recently as a path

// insertion point that probed nothing on 51 vectors and recorded them tested.

// ErrTriageNotImplemented marks a stub that another agent owns. It is returned rather than
// panicked so a partial build still runs its tests, and it is an error rather than a zero value so
// nobody mistakes "not built yet" for "measured and fine".
var ErrTriageNotImplemented = errors.New("triage: not implemented yet")

// ErrForeignObservation is returned when a classifier asks to read a response that another class's
// payload produced. See OwnedResponses.At, which is the only read there is.
var ErrForeignObservation = errors.New("triage: refused to hand class B a response produced by class A's payload")

// ---------------------------------------------------------------------------------------------
// 1. CLASS IDENTITY AND THE ORDINAL STRIPE
// ---------------------------------------------------------------------------------------------

// ClassID is an attack class, permanent once assigned. A retired class keeps its id, because the
// id is also the marker's ordinal stripe and reusing one would make historical markers ambiguous.
type ClassID uint8

// ClassStripeModulus is the R12 striping constant: a probe ordinal is allocated so that
// ordinal % ClassStripeModulus == the owning class id. That is what makes a marker attributable by
// arithmetic instead of by a lookup table, and it is what makes a foreign marker detectable at
// match time rather than by inspection.
//
// It also caps the class register: a class id must be strictly less than the modulus or two
// classes share a stripe. TestClassIDsFitTheOrdinalStripe asserts that.
const ClassStripeModulus = 64

// The class register, CATALOGUE section 1.0. Ids are permanent.
const (
	ClassNone         ClassID = 0 // a baseline or a shared control belongs to no class
	ClassSSTI         ClassID = 1
	ClassELI          ClassID = 2
	ClassCMDI         ClassID = 3
	ClassSQL          ClassID = 4
	ClassNoSQL        ClassID = 5
	ClassLDAP         ClassID = 6
	ClassXPath        ClassID = 7
	ClassGraphQL      ClassID = 8
	ClassXSSReflected ClassID = 9
	ClassCSTI         ClassID = 10
	ClassXSSDOM       ClassID = 11
	ClassXSSStored    ClassID = 12
	ClassTraversal    ClassID = 13
	ClassLFI          ClassID = 14
	ClassRFI          ClassID = 15
	ClassXXE          ClassID = 16
	ClassSSRF         ClassID = 17
	ClassRedirect     ClassID = 18
	ClassCRLF         ClassID = 19
	ClassHostHeader   ClassID = 20
	ClassCache        ClassID = 21
	ClassPPServer     ClassID = 22
	ClassPPClient     ClassID = 23
	ClassDeser        ClassID = 24
	ClassMassAssign   ClassID = 25
	ClassHPP          ClassID = 26
	ClassCSVI         ClassID = 27

	// ClassExample is RESERVED FOR THE PLACEHOLDER CLASSIFIER and is deliberately outside the
	// twenty-seven real ids.
	//
	// It exists because the placeholder used to occupy ClassCSVI. RegisterClassifier panics on a
	// duplicate id, correctly and loudly, so the author of the real CSVI class would have hit that
	// panic from an init() in a package they had not touched, with a message naming an id rather
	// than a file. Reserving an id costs one line and means every one of the twenty-seven is free
	// on the day somebody writes it.
	//
	// 63 is the largest id ClassStripeModulus allows, so the register can grow from 27 upwards for
	// a long time before it meets this one, and if it ever does the collision is a build-time
	// duplicate in this const block rather than a runtime panic.
	ClassExample ClassID = 63
)

// triageClassNames is the register as data, so a test can walk it and so String never invents a
// name for an id nobody assigned.
var triageClassNames = map[ClassID]string{
	ClassSSTI:         "SSTI",
	ClassELI:          "ELI",
	ClassCMDI:         "CMDI",
	ClassSQL:          "SQL",
	ClassNoSQL:        "NOSQL",
	ClassLDAP:         "LDAP",
	ClassXPath:        "XPATH",
	ClassGraphQL:      "GRAPHQL",
	ClassXSSReflected: "XSS-R",
	ClassCSTI:         "CSTI",
	ClassXSSDOM:       "XSS-DOM",
	ClassXSSStored:    "XSS-STORED",
	ClassTraversal:    "TRAVERSAL",
	ClassLFI:          "LFI",
	ClassRFI:          "RFI",
	ClassXXE:          "XXE",
	ClassSSRF:         "SSRF",
	ClassRedirect:     "REDIRECT",
	ClassCRLF:         "CRLF",
	ClassHostHeader:   "HOSTHDR",
	ClassCache:        "CACHE",
	ClassPPServer:     "PP-SERVER",
	ClassPPClient:     "PP-CLIENT",
	ClassDeser:        "DESER",
	ClassMassAssign:   "MASSASSIGN",
	ClassHPP:          "HPP",
	ClassCSVI:         "CSVI",
	ClassExample:      "EXAMPLE",
}

// Known reports whether the id is in the register. An unknown id is never silently treated as a
// class: it is how a stripe arithmetic bug would otherwise present as a plausible attribution.
func (c ClassID) Known() bool {
	_, ok := triageClassNames[c]
	return ok
}

func (c ClassID) String() string {
	if n, ok := triageClassNames[c]; ok {
		return n
	}
	if c == ClassNone {
		return "none"
	}
	return "class(" + strconv.Itoa(int(c)) + ")"
}

// AllClassIDs returns the register in ascending id order.
func AllClassIDs() []ClassID {
	out := make([]ClassID, 0, len(triageClassNames))
	for id := range triageClassNames {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------------------------------------------------------------------------------------------
// 2. MARKERS, AND THE ARITHMETIC THAT MAKES A FOREIGN ONE MATCH NOBODY
// ---------------------------------------------------------------------------------------------

// Marker is the 16-byte per-probe token of foundations part 2.2, laid out as
//
//	[anchor 3][run id 4][probe ordinal 6][checksum 3]
//
// over the alphabet [0-9a-z] with a letter first. The alphabet is the whole point: every byte is
// RFC 3986 unreserved, inside cookie-octet, a header field-vchar, untouched by HTML escaping and
// untouched by JSON escaping, so the marker is byte-identical in all seven insertion points and
// one search routine works everywhere.
type Marker string

const (
	MarkerLen         = 16
	MarkerAnchorLen   = 3
	MarkerRunIDLen    = 4
	MarkerOrdinalLen  = 6
	MarkerChecksumLen = 3

	// DefaultMarkerAnchor is searched for first, as a single substring scan, before any of the 16
	// byte comparisons happen.
	DefaultMarkerAnchor = "zqj"
)

// MarkerIntegrity is the checksum verdict, and its zero value is Unchecked rather than Valid.
//
// WHY THE ZERO VALUE MATTERS HERE. CATALOGUE 4.2 caps a hit whose marker came back CORRUPTED at
// suspicious, because attribution is unsafe. A field that defaults to Valid would quietly promote
// every unchecked marker to a high-grade finding the first time somebody forgot to call the
// verifier. Unchecked is not Valid and never grades above suspicious.
type MarkerIntegrity string

const (
	MarkerUnchecked MarkerIntegrity = ""          // no verifier has run. Caps the hit at suspicious.
	MarkerValid     MarkerIntegrity = "valid"     // checksum recomputed and matched
	MarkerCorrupted MarkerIntegrity = "corrupted" // checksum recomputed and did not match
)

// WellFormed reports whether the marker has the right length, anchor and alphabet. It says nothing
// about the checksum: that is Integrity, and it is deliberately a separate question.
func (m Marker) WellFormed() bool {
	if len(m) != MarkerLen || !strings.HasPrefix(string(m), DefaultMarkerAnchor) {
		return false
	}
	for i := 0; i < len(m); i++ {
		b := m[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'z') {
			return false
		}
	}
	// First byte is a letter so the marker is never a valid integer and is never read as
	// scientific notation by a JSON or YAML parser on the way back.
	return m[0] >= 'a' && m[0] <= 'z'
}

// RunID is bytes 3 to 6. A response arriving during run B carrying run A's id is a cached or
// replayed body, and any verdict drawn from it is cannot_determine (stale_marker).
func (m Marker) RunID() string {
	if !m.WellFormed() {
		return ""
	}
	return string(m[MarkerAnchorLen : MarkerAnchorLen+MarkerRunIDLen])
}

// Ordinal is bytes 7 to 12 read as base36. The ordinal is the primary key of the probe record, so
// the marker is not a random token you look up in a table of random tokens: it is the index.
func (m Marker) Ordinal() (uint64, bool) {
	if !m.WellFormed() {
		return 0, false
	}
	start := MarkerAnchorLen + MarkerRunIDLen
	n, err := strconv.ParseUint(string(m[start:start+MarkerOrdinalLen]), 36, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ClassID is the R12 stripe: ordinal mod 64. This is the arithmetic that makes cross-class marker
// contamination structurally detectable. A malformed marker attributes to nobody.
func (m Marker) ClassID() (ClassID, bool) {
	n, ok := m.Ordinal()
	if !ok {
		return ClassNone, false
	}
	return ClassID(n % ClassStripeModulus), true
}

// BelongsTo is the single question a class asks of a marker it found in a response. A marker whose
// ordinal residue is not this class's is foreign_marker_observed: a hit for nobody, not a hit for
// whoever happened to look first.
func (m Marker) BelongsTo(c ClassID) bool {
	owner, ok := m.ClassID()
	return ok && owner == c
}

// Integrity recomputes CRC-32 over bytes 0 to 12 modulo 36^3 and compares it with bytes 13 to 15.
// It is one line because the verifier lives in triageMarker.go and there must be exactly one of
// it: while this was a stub returning Unchecked, every hit in the system was capped at suspicious
// by a verifier that had been written and never called.
//
// FAILS CLOSED. Anything that is not marker-shaped reads corrupted, never unchecked.
func (m Marker) Integrity() MarkerIntegrity { return VerifyMarkerIntegrity(m) }

// A free MintMarker(runID, owner) used to sit here returning ErrTriageNotImplemented, and it has
// been DELETED rather than implemented. The signature cannot allocate: with no counter it cannot
// issue a distinct ordinal per call and it cannot record which probe a marker belongs to, and a
// package-level counter would make two concurrent runs share a sequence and hand the same ordinal
// to two classes, which is the one thing the stripe exists to prevent.
//
// The runner holds one *MarkerMinter per run and calls Mint. A class never mints its own marker:
// it is handed one in a ProbeRequest, which is what makes the stripe an invariant of the system
// rather than a convention each class has to remember. MintMarkerAt is the deterministic half,
// for the allocator and for tests.

// ---------------------------------------------------------------------------------------------
// 3. THE STATE VOCABULARY. ONE SHAPE FOR EVERY CLASS, CLASS AS A COLUMN NOT A TYPE
// ---------------------------------------------------------------------------------------------

// TriageState is the verdict state. It is a string and not an int so an unrecognised value from a
// database row or a JSON payload stays unrecognised instead of colliding with a valid iota.
//
// CATALOGUE 4.1 defines ten statuses. Foundations part 8 adds three comparison outcomes that are
// verdict-bearing (borderline, masked_only, reordered) and that CATALOGUE 4.1 does not repeat.
// Both documents agree that none of the three may read as clean, so all thirteen live here, in one
// vocabulary, with kind as data. The state means the same thing in every class; the class is a
// column on ClassVerdict, never a distinct type.
type TriageState string

const (
	// The five positives. Something was observed. None of them is clean and none is a silence.
	StateFinding    TriageState = "finding"     // this class's own oracle fired and confirmed
	StateSuspicious TriageState = "suspicious"  // fired at reduced confidence, or a degraded oracle
	StateBorderline TriageState = "borderline"  // differential between the measured threshold and the floor
	StateMaskedOnly TriageState = "masked_only" // changed, but only where the endpoint varies anyway
	StateReordered  TriageState = "reordered"   // same bytes, different order

	// The two negatives. These are the only states that assert anything about the application.
	StateClean          TriageState = "clean"           // this class's own probes ran and its own oracle stayed silent
	StateNotExploitable TriageState = "not_exploitable" // reachable, and a NAMED defence stops it

	// The one structural state. The class was correctly not run because the mechanism cannot exist
	// here. It is unknown in effect, and every aggregate treats it as unknown, but it is not an
	// admission of a measurement failure, so it keeps its own kind.
	StateNotApplicable TriageState = "not_applicable"

	// The five unknowns proper. Something prevented measurement and the reason names what.
	StateCannotDetermine TriageState = "cannot_determine" // measurement was attempted or prevented
	StateNotReachable    TriageState = "not_reachable"    // the bytes cannot be delivered to this slot at all
	StateNotPlanned      TriageState = "not_planned"      // no probe was derived, and the reason is named
	StateNotRun          TriageState = "not_run"          // the probe exists and was deliberately not sent
	StateNotProbed       TriageState = "not_probed"       // the probe is specified and refused on safety grounds
)

// StateKind partitions the vocabulary. It exists so a renderer, a sorter, an exporter and a filter
// all make the same distinction from the same data instead of each re-deriving it from a switch
// that someone will later add a case to and get wrong.
type StateKind string

const (
	StateKindPositive   StateKind = "positive"
	StateKindNegative   StateKind = "negative"
	StateKindStructural StateKind = "structural"
	StateKindUnknown    StateKind = "unknown"
)

// StateRule is one row of the vocabulary, as data.
type StateRule struct {
	State TriageState
	Kind  StateKind
	// Unknown is the authority for IsUnknown. It is a separate field from Kind because
	// not_applicable is structurally its own kind and yet is unknown to every aggregate, and
	// encoding that as "Kind == StateKindUnknown" would lose it.
	Unknown bool
	// RequiresReason: the row is meaningless without one. "Unknown" with no reason is how a check
	// that never ran gets quietly re-classified as clean on the next refactor.
	RequiresReason bool
	// RequiresOrdinals: the row asserts something about the application, so it must name the
	// probes that produced it. A clean with zero ordinals is a hard error, not a warning. A
	// warning in a log is how this shipped the first time.
	RequiresOrdinals bool
	Meaning          string
}

// triageStateRules is the whole vocabulary. TestStateVocabularyIsExhaustive parses this file's
// TriageState constants out of the source and asserts the two sets match in both directions, so a
// new state cannot be added without a decision recorded here.
var triageStateRules = []StateRule{
	{StateFinding, StateKindPositive, false, false, true, "this class's own oracle fired and confirmed; point the tool here"},
	{StateSuspicious, StateKindPositive, false, false, true, "fired at reduced confidence, or a degraded or secondary oracle fired; worth a look, never a clean"},
	{StateBorderline, StateKindPositive, false, true, true, "the differential fell between the measured threshold and the floor"},
	{StateMaskedOnly, StateKindPositive, false, true, true, "the response changed, but only where this endpoint varies anyway"},
	{StateReordered, StateKindPositive, false, true, true, "same bytes, different order"},

	{StateClean, StateKindNegative, false, false, true, "this class's own probes ran, its own oracle stayed silent, and its clean-preconditions held"},
	{StateNotExploitable, StateKindNegative, false, true, true, "tested, the mechanism is reachable, and a named defence stops it"},

	{StateNotApplicable, StateKindStructural, true, true, false, "the mechanism cannot exist here; correctly not run, and unknown to every aggregate"},

	{StateCannotDetermine, StateKindUnknown, true, true, false, "something prevented measurement and the reason names what"},
	{StateNotReachable, StateKindUnknown, true, true, false, "the bytes cannot be delivered to this slot at all"},
	{StateNotPlanned, StateKindUnknown, true, true, false, "no probe was derived, and the reason is named"},
	{StateNotRun, StateKindUnknown, true, true, false, "the probe exists and was deliberately not sent: an early exit, an opt-in switch, a budget cap"},
	{StateNotProbed, StateKindUnknown, true, true, false, "the probe is specified and is refused on safety grounds"},
}

var triageStateByName = func() map[TriageState]StateRule {
	m := make(map[TriageState]StateRule, len(triageStateRules))
	for _, r := range triageStateRules {
		m[r.State] = r
	}
	return m
}()

// StateRules returns the vocabulary, for a renderer or an exporter that needs to enumerate it.
func StateRules() []StateRule {
	out := make([]StateRule, len(triageStateRules))
	copy(out, triageStateRules)
	return out
}

// IsUnknown is THE predicate. Every caller that is about to render, sort, export, filter or
// aggregate a state asks this and nothing else.
//
// IT FAILS CLOSED. A state that is not in the vocabulary is unknown, and so is the zero value. The
// alternative, treating an unrecognised string as "not unknown", means a typo in a migration or a
// state added by a future agent without a rule row silently becomes eligible to render as clean.
func (s TriageState) IsUnknown() bool {
	r, ok := triageStateByName[s]
	if !ok {
		return true
	}
	return r.Unknown
}

// CountsAsClean is the only sanctioned way to ask "may this be shown as clean". It is derived from
// the same data as IsUnknown so the two can never disagree.
func (s TriageState) CountsAsClean() bool {
	return !s.IsUnknown() && s == StateClean
}

// Kind returns the partition. An unrecognised state is StateKindUnknown, for the same fail-closed
// reason as IsUnknown.
func (s TriageState) Kind() StateKind {
	if r, ok := triageStateByName[s]; ok {
		return r.Kind
	}
	return StateKindUnknown
}

// Known reports whether the state has a rule row.
func (s TriageState) Known() bool {
	_, ok := triageStateByName[s]
	return ok
}

// RequiresReason and RequiresOrdinals expose the rule row's obligations so ClassVerdict.Validate
// and any future writer enforce the same thing from the same source.
func (s TriageState) RequiresReason() bool {
	r, ok := triageStateByName[s]
	return !ok || r.RequiresReason
}

func (s TriageState) RequiresOrdinals() bool {
	r, ok := triageStateByName[s]
	return ok && r.RequiresOrdinals
}

// TriageGrade is a property of the ORACLE that fired, not of the class. CATALOGUE 4.2.
type TriageGrade string

const (
	GradeUnrated TriageGrade = ""       // every non-finding, non-suspicious state
	GradeHigh    TriageGrade = "high"   // rank 1 or 2 with its guard asserted AND reproduced with a fresh marker
	GradeMedium  TriageGrade = "medium" // rank 3 or 4 baseline-differenced, or rank 1 with a caveat
	GradeLow     TriageGrade = "low"    // rank 5 or 7, or a degraded comparison
)

// ---------------------------------------------------------------------------------------------
// 4. THE VERDICT RECORD, AND THE TWO INVARIANTS THIS CODEBASE HAS ALREADY BROKEN ONCE
// ---------------------------------------------------------------------------------------------

// ProbeID names a probe in the catalogue, for example "CSVI-W1".
type ProbeID string

// ProbeSkip records a probe this class did not send, and why. Every unsent probe gets a row: a
// class that quietly plans fewer probes on one slot than another is the shape of a silent zero.
type ProbeSkip struct {
	ProbeID ProbeID
	Reason  string
}

// TriageEvidence is what a verdict points at. It carries the wire bytes as well as the logical
// ones for the reason set out on PayloadWire.
type TriageEvidence struct {
	Ordinal    uint64 // the probe whose observation this evidence came from
	ObsID      string
	Matched    []byte // the bytes the oracle matched
	Offset     int    // where in the body, so an operator can find it
	Length     int
	Phrase     string      // the human-readable signature name, for example "pg.PSQLException"
	Wire       PayloadWire // what we asked for versus what actually went out
	Callback   *CallbackRec
	MarkerForm string // raw | upper | ncr | percent | base64, from the part 2.5 search transform set
}

// TriageLabel is what the verdict hands to the expensive scanner: which tools to run, and the
// tool-specific hints that make the run cheaper than a cold start.
type TriageLabel struct {
	Tools   []string // "sqlmap", "ghauri", "dalfox", ...
	Engine  string   // the identified backend, when one was identified
	Dialect string
	Hints   map[string]string
}

// ClassVerdict is one class's answer about one unit of work. CATALOGUE 4.3.
type ClassVerdict struct {
	Class   ClassID
	SlotKey SlotKey // or a vector, container or host key for the per-unit classes
	State   TriageState
	Reason  string // required for every state whose rule row says so
	Grade   TriageGrade
	Oracle  string // which of THIS class's rules fired: "computation", "oob", "parser_error", ...

	// Ordinals are the probes that produced this verdict. Empty plus clean is a hard error.
	Ordinals []uint64
	// Untested is every probe this class did not send, each with its reason.
	Untested    []ProbeSkip
	Evidence    TriageEvidence
	Annotations map[string]any // decode_depth, quote_survival_unproven, header_list_size, ...
	Label       TriageLabel
}

// Validate enforces the two invariants of CATALOGUE 4.3, both of which this codebase has already
// violated once in other features.
//
// The first is the load-bearing one: a clean with no probe record is a class claiming it tested
// something when nothing was sent. It fails the run. It is not a log line.
func (v ClassVerdict) Validate() error {
	if !v.State.Known() {
		return fmt.Errorf("triage: verdict for class %s carries unrecognised state %q", v.Class, v.State)
	}
	if v.State.RequiresOrdinals() && len(v.Ordinals) == 0 {
		return fmt.Errorf("triage: class %s emitted %s on %q with zero probe ordinals, which asserts a measurement that never happened",
			v.Class, v.State, v.SlotKey)
	}
	if v.State.RequiresReason() && strings.TrimSpace(v.Reason) == "" {
		return fmt.Errorf("triage: class %s emitted %s on %q with no reason, and an unknown with no reason is how a check that never ran becomes a clean",
			v.Class, v.State, v.SlotKey)
	}
	if v.State.IsUnknown() && v.Grade != GradeUnrated {
		return fmt.Errorf("triage: class %s emitted unknown state %s on %q graded %q, but only a fired oracle carries a grade",
			v.Class, v.State, v.SlotKey, v.Grade)
	}
	return nil
}

// Coverage is what an aggregate over many verdicts is allowed to say. It is a set of counts and
// not a single state, because CATALOGUE 4.5 rule 1 forbids folding an unknown into a clean at any
// layer: a vector whose slots are half clean and half cannot_determine is reported as partially
// tested with the untested half named, never as a green tick.
type Coverage struct {
	Total     int
	Positive  int
	Negative  int
	Unknown   int
	Clean     int
	Untested  []string // "<class>:<slotkey>:<reason>" for every unknown row, so the report can name them
	Malformed []string // verdicts that failed Validate. Never silently dropped.
}

// SummariseVerdicts is the only sanctioned aggregation. There is deliberately no function that
// returns a single TriageState for a set of verdicts, because no such value can be honest.
func SummariseVerdicts(vs []ClassVerdict) Coverage {
	var c Coverage
	for _, v := range vs {
		c.Total++
		if err := v.Validate(); err != nil {
			c.Malformed = append(c.Malformed, err.Error())
		}
		switch {
		case v.State.IsUnknown():
			c.Unknown++
			c.Untested = append(c.Untested, fmt.Sprintf("%s:%s:%s", v.Class, v.SlotKey, v.Reason))
		case v.State.Kind() == StateKindPositive:
			c.Positive++
		case v.State.Kind() == StateKindNegative:
			c.Negative++
			if v.State.CountsAsClean() {
				c.Clean++
			}
		}
	}
	return c
}

// RendersAsClean is the aggregate-level counterpart of TriageState.CountsAsClean. An empty set is
// not clean, a set with one unknown row is not clean, and a set with a malformed row is not clean.
func (c Coverage) RendersAsClean() bool {
	return c.Total > 0 && c.Unknown == 0 && c.Positive == 0 && len(c.Malformed) == 0 && c.Clean == c.Total
}

// ---------------------------------------------------------------------------------------------
// 5. THE SLOT ABSTRACTION. FOUNDATIONS PART 6
// ---------------------------------------------------------------------------------------------

// SlotKind is an insertion point. Measured in Postgres on the live corpus before any of this was
// written: 218 vectors and 1860 parameter slots, split cookie 75 vectors / 1655 slots,
// query 30 / 92, body 13 / 64, header 49 / 49, and path 51 vectors / ZERO slots.
//
// That zero is the reason the Slot abstraction exists. attack_vectors.parameters has no entries at
// all for the 51 path vectors, so any loop over that array probes nothing on 23.4% of the corpus
// and records those vectors as tested. That bug has already shipped here once.
type SlotKind string

const (
	KindQuery    SlotKind = "query"
	KindBody     SlotKind = "body"
	KindHeader   SlotKind = "header"
	KindCookie   SlotKind = "cookie"
	KindPath     SlotKind = "path"
	KindFragment SlotKind = "fragment"
)

// AllSlotKinds is the closed set. A kind not in here reaches no class's Reaches.
func AllSlotKinds() []SlotKind {
	return []SlotKind{KindQuery, KindBody, KindHeader, KindCookie, KindPath, KindFragment}
}

// SlotKey is the storage identity, stable across runs so a re-run updates rather than duplicates,
// and namespaced by kind so a vector can carry a query parameter and a path segment both called
// order_id. Foundations 6.3 gives the grammar:
//
//	query:sort
//	body:/filters/status
//	body:file.filename            (multipart: part name, then the sub-sink)
//	cookie:session_theme
//	header:x-tenant               (lowercased: header names are case-insensitive)
//	path:4:{order_id}             (index FIRST so it sorts numerically)
//	path:2:*                      (identifier-shaped segment with no template name)
//	fragment:tab
type SlotKey string

// ValueKind and Wrapper are the converged shape enumerations, and they keep the property they were
// converged on: THEY ORDER PERTURBATIONS AND NEVER GATE THEM. A UUID slot is probed. A slot whose
// value looks like an enum is probed. A shape guess that suppresses a probe is a silent zero and
// this codebase has removed several.
type ValueKind string

const (
	ValueUnknown    ValueKind = ""
	ValueNumeric    ValueKind = "numeric"
	ValueUUID       ValueKind = "uuid"
	ValueEnumLike   ValueKind = "enum_like"
	ValueFreeText   ValueKind = "free_text"
	ValuePathLike   ValueKind = "path_like"
	ValueURLLike    ValueKind = "url_like"
	ValueJSONLike   ValueKind = "json_like"
	ValueDateLike   ValueKind = "date_like"
	ValueBase64Like ValueKind = "base64_like"
	ValueEmpty      ValueKind = "empty"
)

type Wrapper string

const (
	WrapNone      Wrapper = ""
	WrapBase64    Wrapper = "base64"
	WrapDoubleURL Wrapper = "double_url"
	WrapJWT       Wrapper = "jwt"
	WrapSigned    Wrapper = "signed"
)

// SlotConstraints is what the slot will and will not carry. Everything in here is MEASURED by a
// control probe or read from the part 1.4 reachability table; nothing in here is a guess, and the
// unknown values are distinguishable from the measured ones.
type SlotConstraints struct {
	// Impossible is bytes that cannot be delivered here raw or encoded. A class whose payload
	// needs one of them emits not_reachable, never clean.
	Impossible []byte
	// DecodeDepth is -1 when the decode control has not run or was inconclusive, which is a
	// different thing from 0 (the slot does not percent-decode). Both are reasons on a verdict:
	// decode_depth_unknown and decode_depth_0.
	DecodeDepth int
	PctRejected bool
	// FieldLimit is 0 when unknown, otherwise the observed truncation length from a marker probe.
	FieldLimit int
	// IsCredential slots are never probed. Injecting into Authorization or a session cookie
	// produces a 401, and that 401 is a differential against baseline that looks exactly like a
	// finding. In the measured corpus 1555 of the 1655 cookie slots are credential or analytics,
	// which is why the effective cookie surface is around 100 and not 1655. They are emitted
	// anyway, so "deliberately skipped" stays visibly different from "does not exist".
	IsCredential bool
}

// NewSlotConstraints returns constraints whose unknowns read as unknown. Use it rather than the
// zero value, because the zero DecodeDepth is 0, and 0 means "measured, and this slot does not
// decode", which is a claim.
func NewSlotConstraints() SlotConstraints {
	return SlotConstraints{DecodeDepth: -1}
}

// Slot is a named query parameter, a body field by JSON pointer, a cookie, a header, or a PATH
// SEGMENT BY INDEX. Foundations 6.1.
type Slot struct {
	VectorID     string
	Kind         SlotKind
	Key          SlotKey // the storage identity, stable across runs, see SlotKey
	Name         string  // parameter, field, cookie or header name. EMPTY for a path segment.
	FieldPath    string  // body only: RFC 6901 JSON pointer, for example "/filters/symbol"
	SegmentIndex int     // path only: index into the path's segments. -1 otherwise.
	Value        string  // the OBSERVED value. Empty when the capture carried none.
	ValueOrigin  ValueOrigin
	ValueKind    ValueKind
	Wrapper      Wrapper
	Encoder      EncoderMode // which foundations part 1 encoder renders into this slot
	Method       string      // the captured verb, replayed as captured
	BodyMedia    BodyMedia
	Origin       SlotOrigin
	// ServerReachable is false for a fragment. RFC 3986 section 3.5 makes the fragment a
	// client-side reference and every browser strips it before the request goes out, so every
	// HTTP-level tool is structurally blind to it. A server-side class on a fragment slot emits
	// not_applicable (fragment), never clean.
	ServerReachable bool
	Constraints     SlotConstraints
}

type ValueOrigin string

const (
	// ValueObserved: the crawl saw this value. The only origin a clean may come from unqualified.
	ValueObserved ValueOrigin = "observed"
	// ValueFromEvidenceURL: borrowed from the vector's own evidence_url, in step with the
	// templated path and only when the segment counts match.
	ValueFromEvidenceURL ValueOrigin = "evidence_url"
	// ValueCanary: a fabricated identifier. EVERY clean verdict from a canary-valued slot is
	// promoted to cannot_determine (canary_resource). Measured: 112 of 218 vectors carry a
	// templated segment and 97 of those have a concrete id in their own evidence URL; the
	// remaining 15 are probed at a resource that does not exist, and a tool pointed at a 404 that
	// comes back with nothing found is not a clean scan of the endpoint.
	ValueCanary ValueOrigin = "canary"
	// ValueSynthesized: neither observed nor borrowed, invented to have something to perturb.
	ValueSynthesized ValueOrigin = "synthesized"
)

type SlotOrigin string

const (
	// SlotObserved: the crawl saw this slot.
	SlotObserved SlotOrigin = "observed"
	// SlotInferred: reachable on any app but not in the capture, for example X-Forwarded-For, or a
	// path segment derived from shape rather than from a template. Present by default, because
	// absence from a crawl says nothing about reachability, and flagged so an operator can filter.
	SlotInferred SlotOrigin = "inferred"
)

type BodyMedia string

const (
	BodyNone      BodyMedia = "none"
	BodyJSON      BodyMedia = "json"
	BodyForm      BodyMedia = "form"
	BodyMultipart BodyMedia = "multipart"
	BodyXML       BodyMedia = "xml"
	BodyGraphQL   BodyMedia = "graphql"
)

// EncoderMode names a foundations part 1 encoder. A class NEVER percent-encodes, never
// JSON-escapes and never renders a cookie value: it emits logical bytes and declares a mode.
//
// THE MEASUREMENT BEHIND EncodeCookie, AND WHY IT IS NOT http.Cookie. On this machine:
//
//	(&http.Cookie{Name:"s", Value:`1' OR 1=1; DROP`}).String() -> `s="1' OR 1=1 DROP"`
//	(&http.Cookie{Name:"s", Value:`a"b\c`}).String()           -> `s=abc`
//
// The semicolon, the double quote and the backslash are DROPPED, with nothing but a line on the
// stdlib logger. Those are exactly the SQL injection probe characters, and 75 of the 218 vectors in
// the measured corpus are cookie vectors. A cookie probe built with http.Cookie or AddCookie tests
// something other than what was asked and then records clean.
//
// The mitigation is measured too, against an httptest server: req.Header.Set("Cookie", ...) with
// the same values arrives byte-identical, and a NUL byte is rejected with
// "net/http: invalid header field value", which is a loud error the probe records as could-not-send
// rather than as clean. Shipped code already does it that way in scanCredentials.go:164 and
// redirectProbe.go:287, so the encoder follows those.
//
// AND THE OTHER MEASURED ENCODER TRAP: url.PathEscape is the wrong function for a query value.
// PathEscape("a=b") is "a=b", PathEscape("a&b") is "a&b", PathEscape("a+b") is "a+b", all raw.
// QueryEscape gives a%3Db, a%26b and a%2Bb. A query encoder built on PathEscape sends a payload
// that splits into three parameters and then reports on whichever one the app read.
type EncoderMode string

const (
	EncodeNone            EncoderMode = "none"
	EncodeQuery           EncoderMode = "query"  // url.QueryEscape, NOT url.PathEscape
	EncodeForm            EncoderMode = "form"   // application/x-www-form-urlencoded field
	EncodePathSegment     EncoderMode = "path"   // RFC 3986 pchar, with the semicolon override
	EncodeCookie          EncoderMode = "cookie" // hand-built Cookie header line, never http.Cookie
	EncodeHeaderValue     EncoderMode = "header" // field-vchar, CR and LF rejected at send
	EncodeJSONString      EncoderMode = "json_string"
	EncodeJSONNodeReplace EncoderMode = "json_node_replace" // replace the value NODE, not the value text
	EncodeXMLCDATA        EncoderMode = "xml_cdata"
	EncodeXMLDocReplace   EncoderMode = "xml_document_replace"
	EncodeLiteralPct      EncoderMode = "literal_pct" // the runner writes % through unencoded
	EncodePctTwice        EncoderMode = "pct_twice"
	EncodeIISUnicode      EncoderMode = "iis_unicode"
	EncodeNameSlot        EncoderMode = "name_slot" // perturb the parameter NAME, not its value
	EncodeMultipartValue  EncoderMode = "multipart_value"
	EncodeMultipartName   EncoderMode = "multipart_filename"
)

// PlanNote is a derivation that produced no slot, with the reason named. Foundations 6.2: an empty
// query and an empty parameter array produce zero slots AND a note. Never silence.
type PlanNote struct {
	VectorID string
	Kind     SlotKind
	Reason   string // no_body_captured, no_query_and_no_parameters, all_slots_credential, ...
}

// TriageVector is what every other file in the triage layer sees. Note what is absent.
type TriageVector struct {
	ID          string
	Method      string
	ComposedURL string
	MediaType   MediaType // the REQUEST media type, parsed and lowercased
	RespMedia   MediaType // the media type the capture's response carried
	Host        string
}

// MediaType is a parsed, lowercased media type, for example "application/json".
type MediaType string

// SlotEvidence is the crawl's own record of this vector, used to resolve a templated path segment
// to a value the application actually served.
type SlotEvidence struct {
	EvidenceURL string
	RawRequest  []byte
	Canary      string // the fallback when the evidence URL cannot supply a segment
}

// ---------------------------------------------------------------------------------------------
// 7. THE OBSERVATION RECORD. FOUNDATIONS PART 3
// ---------------------------------------------------------------------------------------------

// WireSurvival answers "did the payload survive to the wire", and its zero value is Unknown.
//
// THIS FIELD EXISTS BECAUSE OF A MEASUREMENT. Go's http.Cookie silently drops the semicolon, the
// double quote and the backslash from a cookie value (see EncoderMode). Those are the SQL
// injection probe characters. Without a recorded wire form, a probe that was mangled on the way out
// is indistinguishable after the fact from a probe the application defended against, and the second
// reading is the one that gets written down as clean.
type WireSurvival string

const (
	// WireSurvivalUnknown is the zero value. It is not "survived". A verdict drawn from an
	// unknown-survival probe carries the caveat, and a clean drawn from one is not a clean.
	WireSurvivalUnknown WireSurvival = ""
	WireSurvivalIntact  WireSurvival = "intact"  // the logical bytes appear verbatim in the wire form
	WireSurvivalEncoded WireSurvival = "encoded" // present, transformed by a DECLARED encoder, reversible
	WireSurvivalAltered WireSurvival = "altered" // present and changed by something we did not ask for
	WireSurvivalDropped WireSurvival = "dropped" // bytes we asked for are not on the wire at all
	WireSurvivalRefused WireSurvival = "refused" // the transport refused to send it, loudly
)

// Proven reports whether the payload is known to have reached the wire in a usable form. Unknown
// is not proven. This is the predicate a classifier uses before it is allowed to say clean.
func (w WireSurvival) Proven() bool {
	return w == WireSurvivalIntact || w == WireSurvivalEncoded
}

// PayloadWire stores the payload TWICE: what the class asked for, and what actually went out.
type PayloadWire struct {
	// Logical is what the classifier asked for, before any encoder. It is []byte and not string so
	// an overlong-UTF-8 payload cannot be written as a Go string literal and silently normalised.
	Logical []byte
	// Wire is the bytes the payload occupies in the serialized request.
	Wire []byte
	// Container is the whole serialized container the slot sits in: the Cookie header line, the
	// query string, the JSON body. A DROPPED byte is only visible here, because Wire is what the
	// encoder believes it produced and Container is what the transport actually wrote.
	Container []byte
	// ContainerName is which container, for example "Cookie" or "request-target".
	ContainerName  string
	EncoderChain   []EncoderMode
	EncoderVersion string
	Survived       WireSurvival
	// AlteredBy names what changed it when Survived is Altered or Dropped, for example
	// "net/http.Cookie sanitizer".
	AlteredBy string
}

// Present reports whether this record describes a payload at all.
//
// IT IS THE LAUNDERING CHECK. NewReplay used to trust Kind, Class and ProbeOrdinal, which are
// stamps, and a mis-stamped or deliberately re-stamped probe therefore became a shared control.
// This record is not a stamp: it is written by the encoder from what actually went out. Any
// non-zero field in it means a payload was rendered, so the observation is not a control.
//
// EVERY field counts, including the ones that look like metadata. An encoder chain with no bytes
// still means an encoder ran, and Survived set to anything at all, dropped included, means the
// runner measured a payload's fate. A dropped payload is the single most dangerous one to launder:
// the bytes are not on the wire, so a check that only looked at Wire would wave it through, and
// the response it produced is still a response to a class's probe.
func (p PayloadWire) Present() bool {
	return len(p.Logical) > 0 || len(p.Wire) > 0 || len(p.Container) > 0 ||
		p.ContainerName != "" || len(p.EncoderChain) > 0 || p.EncoderVersion != "" ||
		p.Survived != WireSurvivalUnknown || p.AlteredBy != ""
}

// Describe names which parts of the record are populated, so a refusal says what it saw rather
// than printing a payload into a log.
func (p PayloadWire) Describe() string {
	var parts []string
	if n := len(p.Logical); n > 0 {
		parts = append(parts, fmt.Sprintf("logical %d bytes", n))
	}
	if n := len(p.Wire); n > 0 {
		parts = append(parts, fmt.Sprintf("wire %d bytes", n))
	}
	if n := len(p.Container); n > 0 {
		parts = append(parts, fmt.Sprintf("container %d bytes", n))
	}
	if p.ContainerName != "" {
		parts = append(parts, "container "+p.ContainerName)
	}
	if len(p.EncoderChain) > 0 {
		modes := make([]string, 0, len(p.EncoderChain))
		for _, m := range p.EncoderChain {
			modes = append(modes, string(m))
		}
		parts = append(parts, "encoders "+strings.Join(modes, "+"))
	}
	if p.EncoderVersion != "" {
		parts = append(parts, "encoder version "+p.EncoderVersion)
	}
	if p.Survived != WireSurvivalUnknown {
		parts = append(parts, "survival "+string(p.Survived))
	}
	if p.AlteredBy != "" {
		parts = append(parts, "altered by "+p.AlteredBy)
	}
	if len(parts) == 0 {
		return "no payload recorded"
	}
	return strings.Join(parts, ", ")
}

// TransportErrKind is a typed send failure. It is typed so a refusal is never mistaken for a
// response: a NUL byte in a header value produces "net/http: invalid header field value" at send
// time, and that probe must record could-not-send, never clean.
type TransportErrKind string

const (
	TransportOK            TransportErrKind = ""
	TransportDNS           TransportErrKind = "dns"
	TransportConnect       TransportErrKind = "connect"
	TransportTLS           TransportErrKind = "tls"
	TransportTimeout       TransportErrKind = "timeout"
	TransportReset         TransportErrKind = "reset"
	TransportProto         TransportErrKind = "proto"
	TransportInvalidHeader TransportErrKind = "invalid_header_value" // the loud NUL-byte case
)

// ObsKind says what a request was for. Only ObsProbe carries a class.
type ObsKind string

const (
	ObsBaseline       ObsKind = "baseline"
	ObsRouteControl   ObsKind = "route_control"
	ObsPreludeControl ObsKind = "prelude_control"
	ObsDecodeControl  ObsKind = "decode_control" // a PERTURBED control, owned by one class (R6a)
	ObsPctControl     ObsKind = "pct_control"    // likewise
	ObsProbe          ObsKind = "probe"
)

// CarriesPayload reports whether this kind of observation came from a modified request. The decode
// and pct controls do modify the value, which is ruling R6a expressed as a predicate and the whole
// reason those two stopped being shared gates.
func (k ObsKind) CarriesPayload() bool {
	return k == ObsProbe || k == ObsDecodeControl || k == ObsPctControl
}

// CookieObs records a Set-Cookie without storing its value. The name and the attributes are the
// signal; the value is a credential and is hashed.
type CookieObs struct {
	Name       string
	ValueSHA   [32]byte
	Attributes []string
}

// Hop is one redirect step. Location is stored RAW, because a re-parse is exactly what the
// REDIRECT class is trying to measure.
type Hop struct {
	Status   int
	Location string
	FinalURL string
}

// MarkerHit is one occurrence of a marker in a response.
type MarkerHit struct {
	Form          string // raw | upper | ncr | percent | base64, part 2.5
	Offset        int
	Length        int
	CaseTransform string // none | upper | title | mixed
	Marker        Marker
}

// Placement is the part 4 reflection context classifier's output for one hit.
type Placement struct {
	Context    string // html_text | attr_value_quoted | script_string | css | url | unresolved
	Detail     string
	Confidence string // high | low. Low is set by the JS lexer's regex-versus-division ambiguity.
}

// Projections are the derived forms, stored rather than recomputed, with the deriver's version
// alongside. A re-run with a changed projection must be distinguishable from a real change, and it
// is only distinguishable if the version that produced the stored form is stored with it.
type Projections struct {
	NormBody       []byte // volatile regions and marker forms removed. Nil until the post-baseline lands.
	NormBodySHA256 [32]byte
	Title          string
	StructTokens   []string // sorted value-free tag, class and id skeleton
	StructSHA256   [32]byte
	JSONParsed     bool     // did it parse, regardless of Content-Type
	JSONKeySet     []string // sorted pointers, array indices collapsed to []
	JSONTypeMap    []string // sorted "pointer=type"
	JSONCards      []string // sorted "pointer.__len__=N"
	JSONScalars    []string // sorted "pointer=value", volatile pointers excluded
	DupJSONKeys    bool
	// ErrorSigs holds signature NAMES, for example "pg.PSQLException", and never a verdict. The
	// moment you store is_sqli:true you have frozen a verdict into the evidence.
	ErrorSigs  []string
	MarkerHits []MarkerHit
	Placements []Placement
}

// Observation is everything captured about one request and its response, and it is the unit that
// lets a classifier be re-run after a code change without re-issuing a single request.
//
// AN OBSERVATION NEVER CONTAINS A VERDICT. A verdict is a function of an observation plus a
// baseline plus a model; storing one inside the observation is how a stale verdict outlives the
// evidence that produced it.
type Observation struct {
	// identity
	ObsID        string
	RunID        string
	ProbeOrdinal uint64  // the marker's ordinal. 0 for a baseline sample.
	Class        ClassID // ClassNone for a baseline and for a shared control
	VectorID     string
	SlotKey      SlotKey // empty for a vector-level baseline
	Kind         ObsKind
	Attempt      int // 1-based. A retry is a separate observation, never an overwrite.

	// request, exactly as it went out
	ReqMethod string
	// ReqWireURL is the request-target AS WRITTEN ON THE WIRE, not a re-parse. A re-parse
	// normalises away the thing a path or CRLF probe was testing.
	ReqWireURL string
	// ReqHeaders is the header list AS THE TEMPLATE DECLARED IT: the order the encoder wrote,
	// duplicates preserved, names spelled exactly as the class spelled them.
	//
	// IT IS NOT NECESSARILY THE ORDER ON THE WIRE, AND THE DOC COMMENT USED TO SAY IT WAS. It read
	// "ordered, duplicates preserved" with no condition attached, while AttachEncode filled it from
	// the template on both send paths and the DEFAULT path reorders: net/http writes Host first,
	// then User-Agent, then the remaining field names byte-sorted. So a classifier read an order
	// that had never existed on any socket, recorded it confidently, and nothing anywhere said
	// which path the request had taken. HPP is about which of two copies a backend takes, CRLF is
	// about the literal sequence of fields the parser walks, and smuggling is entirely about
	// whether Content-Length or Transfer-Encoding comes first: all three would have been reasoning
	// about fiction, and a class reasoning about fiction reaches a verdict, which is worse than
	// reaching none.
	//
	// So there are now three fields instead of one overloaded one. This is what was ASKED FOR,
	// ReqWireHeaders is what WENT OUT, and ReqHeaderOrder says which writer produced the second
	// and therefore whether the two agree.
	ReqHeaders [][2]string
	// ReqWireHeaders is the header list in the order it was serialized onto the connection,
	// measured by running the template through the same writer the send path uses rather than by
	// predicting what that writer would do. It is nil when nobody measured it, which is what
	// ReqHeaderOrder reports as unrecorded.
	ReqWireHeaders [][2]string
	// ReqHeaderOrder names the writer. Its zero value is unrecorded, so a classifier that forgets
	// to check gets "nobody measured this" rather than a confident lie.
	ReqHeaderOrder HeaderOrderPath
	ReqBody        []byte // capped at 256 KiB; the SHA and the length are always of the full body
	ReqBodySHA256  [32]byte
	ReqBodyLen     int
	// Payload is the logical bytes, the wire bytes and the survival verdict. See PayloadWire.
	Payload   PayloadWire
	Marker    Marker
	MarkerPos MarkerPos

	// response, exactly as it came back
	Status        int
	StatusText    string
	Proto         string
	RespHeaders   [][2]string // ALL of them, ordered, duplicates preserved. Filtering at capture is irreversible.
	Body          []byte      // capped at 512 KiB
	BodyTruncated bool
	BodySHA256    [32]byte // of the FULL body, not the cap
	BodyLen       int
	ContentType   string // the raw header value
	MediaType     MediaType
	Charset       string
	SetCookies    []CookieObs
	RedirectChain []Hop
	FinalURL      string
	TransportErr  TransportErrKind
	TransportMsg  string
	TLSVersion    string
	TLSCipher     uint16

	// timing, monotonic clock, nanoseconds. Stored because it cannot be recomputed and because the
	// stability gate needs the baseline distribution. Never a primary oracle.
	TDNS, TConnect, TTLS, TTFB, TTotal int64
	SentAt                             time.Time // wall clock, for correlating with the target's own logs

	// derived at capture, versioned
	Proj        Projections
	ProjVersion string
}

// Delivered reports whether the request reached the application at all. A transport refusal is not
// a silent oracle: it is could-not-send, and a classifier must not read it as a quiet response.
func (o Observation) Delivered() bool {
	return o.TransportErr == TransportOK
}

// HeaderOrderPath names which writer put this request's headers on the connection, because the two
// writers in this layer disagree about order and the disagreement is a whole family of classes.
type HeaderOrderPath string

const (
	// HeaderOrderUnrecorded is the zero value and means NOBODY MEASURED IT. It is not "the order
	// was fine". A class whose verdict depends on order and sees this emits cannot_determine.
	HeaderOrderUnrecorded HeaderOrderPath = ""
	// HeaderOrderAsDeclared means the ordered wire writer sent the bytes, so ReqHeaders and
	// ReqWireHeaders are the same list and the declared order is the order the server parsed.
	HeaderOrderAsDeclared HeaderOrderPath = "as_declared"
	// HeaderOrderNetHTTPSorted means the default net/http path sent the bytes, so the field names
	// were reordered on the way out: Host first, then User-Agent, then the rest byte-sorted.
	// ReqHeaders is what was asked for and ReqWireHeaders is what went out.
	HeaderOrderNetHTTPSorted HeaderOrderPath = "nethttp_sorted"
)

// Recorded reports whether anybody measured the wire order at all.
func (p HeaderOrderPath) Recorded() bool {
	return p == HeaderOrderAsDeclared || p == HeaderOrderNetHTTPSorted
}

// DeclaredOrderHeld reports whether the headers reached the server in the order the class wrote
// them. Its answer for the unrecorded zero value is false, which is the fail-closed one.
func (p HeaderOrderPath) DeclaredOrderHeld() bool { return p == HeaderOrderAsDeclared }

// WireHeaders returns the headers in the order they went out, and a bool that is false when that
// order was never measured.
//
// EVERY ORDER-SENSITIVE CLASS READS THIS AND NOT ReqHeaders. The bool is the whole point: an
// unmeasured order has to be distinguishable from a measured one, or the first refactor that
// forgets to record the path turns every HPP and smuggling verdict into a confident reading of a
// list nothing ever sent.
func (o Observation) WireHeaders() ([][2]string, bool) {
	if !o.ReqHeaderOrder.Recorded() || o.ReqWireHeaders == nil {
		return nil, false
	}
	return o.ReqWireHeaders, true
}

// MarkerPos says where in the payload the marker sits. Prefix is the default so that a field that
// truncates at 16 bytes still leaves an attributable marker.
type MarkerPos string

const (
	MarkerPrefix MarkerPos = "prefix"
	MarkerSuffix MarkerPos = "suffix"
	MarkerInline MarkerPos = "inline" // with the offset in ProbeRequest.Variant["marker_offset"]
)
