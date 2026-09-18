package triage

import (
	"bytes"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
)

// The classifier contract and the registry. CATALOGUE section 5.
//
// The runner knows one interface and N implementations of it. Adding a class means adding a file
// and an init(); it means touching no runner code, no switch statement and no enum of oracles.
// CATALOGUE 5.6 proves that by adding CSVI end to end without changing anything outside its own
// file, and that property is the reason the interface is shaped the way it is rather than as a
// pile of per-class hooks.
//
// This file also holds the isolation law in executable form. CheckPayloadIsolation runs over the
// union of every registered class's Probes() and is the thing that stops two classes shipping the
// same payload bytes. It is a plain function rather than only a test so the runner can also refuse
// to start on a registry that violates it.

// ---------------------------------------------------------------------------------------------
// 1. THE PROBE
// ---------------------------------------------------------------------------------------------

// ProbeTier is how much of the ladder a run is buying.
type ProbeTier string

const (
	TierReduced ProbeTier = "reduced" // the cheap pass every run gets
	TierFull    ProbeTier = "full"
	TierOptIn   ProbeTier = "opt_in" // the operator chose it, per run, with the cost named
)

// RiskTier is how much the probe can disturb the target. R3 is off unless the operator opted in,
// per run. A probe that is refused for risk emits not_probed with a reason, never clean.
type RiskTier string

const (
	RiskR0 RiskTier = "R0" // read-only, no state change possible
	RiskR1 RiskTier = "R1" // writes a value the app already accepts
	RiskR2 RiskTier = "R2" // may create or modify a record
	RiskR3 RiskTier = "R3" // may be destructive or noisy. Opt-in, per run.
)

// SlotOverrides are the per-slot encoder exceptions a probe needs, for example a path probe that
// requires a raw semicolon, or a cookie probe that requires the space percent-encoded. They are
// declared on the probe rather than decided by the encoder, so the encoder stays one function and
// the exception stays visible in the catalogue row it belongs to.
type SlotOverrides struct {
	PathSemicolonRaw  bool
	CookieSpaceEncode bool
	HeaderAllowRawLF  bool // never honoured on the wire; it makes a not_reachable explicit
	RawPercent        bool
}

// ProbeSpec is one payload a class may send. Every probe a class will ever send is declared here,
// and Plan's output is checked against this set, so a payload cannot be conjured at runtime and
// escape the build-time isolation check.
type ProbeSpec struct {
	ID    ProbeID
	Class ClassID // asserted == the owning Classifier.ID() at registration
	// Logical is the LOGICAL bytes. It is []byte and not string so that an overlong-UTF-8 payload
	// cannot be written as a Go string literal and silently sent re-encoded as its shortest form,
	// which would test something other than what was asked.
	Logical  []byte
	Encoders []EncoderMode
	Points   []SlotKind
	// MarkerPos defaults to prefix so that a field truncating at 16 bytes still leaves the marker
	// attributable, which is what keeps "truncated" distinguishable from "absent".
	MarkerPos MarkerPos
	Tier      ProbeTier
	Risk      RiskTier
	Overrides SlotOverrides
	// IsControl marks a NEGATIVE control. A class whose control fires has not proven its detector
	// silent, so all of that class's verdicts on that slot become
	// cannot_determine (detector_unverified) and the run is flagged.
	IsControl bool
	// Embeds is the explicit annotation required by isolation check I1c when this probe's payload
	// contains another class's payload as a substring of 24 bytes or more. Containment across
	// classes is not forbidden, it is forbidden SILENTLY: an unannotated containment means a hit
	// on the shorter payload cannot be attributed, and the build refuses it.
	Embeds []ProbeID
	// Notes is free text for the catalogue row's reasoning. Never read by the runner.
	Notes string
}

// ProbeRequest is one instance of a ProbeSpec, aimed at one slot, with a marker the RUNNER minted.
// A class never mints its own marker: that is what makes the R12 ordinal stripe an invariant of
// the system rather than a convention every class has to remember.
type ProbeRequest struct {
	Spec   ProbeID
	Slot   SlotKey
	Marker Marker
	// Variant carries the per-instance values: arithmetic operands, the served OOB filename, the
	// injected header name, the marker offset for MarkerInline.
	Variant map[string]string
}

// ---------------------------------------------------------------------------------------------
// 2. REACHABILITY
// ---------------------------------------------------------------------------------------------

type Reach int

const (
	// ReachNever always carries a reason. A never with no reason is a silent zero wearing a
	// different hat: the operator sees a class absent from a slot and cannot tell whether it was
	// ruled out or forgotten.
	ReachNever Reach = iota
	ReachConditional
	ReachAlways
)

func (r Reach) String() string {
	switch r {
	case ReachAlways:
		return "always"
	case ReachConditional:
		return "conditional"
	default:
		return "never"
	}
}

// Reachability is what Reaches returns.
//
// CATALOGUE 5.3 declares the return type as a bare Reach with the reason in a separate
// ReachReason. Returning them together is the same information and makes the reason impossible to
// omit, which is the only property that matters here. Noted as a deliberate divergence.
type Reachability struct {
	Reach Reach
	// Reason is required for ReachNever and for ReachConditional. For never it becomes the
	// verdict's not_applicable reason; for conditional it names the condition the ladder checks.
	Reason string
}

// ---------------------------------------------------------------------------------------------
// 3. THE CLASSIFIER
// ---------------------------------------------------------------------------------------------

// Classifier is the whole contract. Twenty-seven implementations, one runner, no switch statement.
type Classifier interface {
	// ID is the identity AND the marker ordinal stripe, so a marker is attributable by arithmetic
	// rather than by a lookup table that someone has to keep in sync.
	ID() ClassID

	// Probes is every probe this class will ever send. The build-time isolation check runs over
	// the union of Probes() across the registry.
	Probes() []ProbeSpec

	// Reaches says which insertion points this class reaches and on what condition. Pure, cheap,
	// no I/O. The eligibility matrix is the union of every class's Reaches, not a separate table
	// that can drift from the classes.
	Reaches(SlotKind, MediaType) Reachability

	// Plan is the ladder. Called repeatedly until it returns nil. Round 0 is the first probe.
	Plan(PlanCtx) []ProbeRequest

	// Classify is the verdict, called once after Plan returns nil or the budget is exhausted. It
	// MUST return at least one ClassVerdict for every slot it planned against, because a slot that
	// was planned and then produced no row is a slot that reads as untouched when it was in fact
	// tested and inconclusive.
	Classify(ClassifyCtx) []ClassVerdict
}

// ---------------------------------------------------------------------------------------------
// 4. THE REGISTRY
// ---------------------------------------------------------------------------------------------

// triageClassifiers is the registry. The runner iterates it and knows nothing else about any class.
var triageClassifiers = map[ClassID]Classifier{}

// RegisterClassifier adds a class. It panics rather than returning an error because it runs from
// init(), where an error has nowhere to go and a partially-registered registry would silently run
// with a class missing, which is a whole attack class recorded as never attempted.
func RegisterClassifier(c Classifier) {
	id := c.ID()
	if !id.Known() {
		panic(fmt.Sprintf("triage: class id %d is not in the register in triage/types.go", id))
	}
	if uint64(id) >= ClassStripeModulus {
		panic(fmt.Sprintf("triage: class id %d is not less than the ordinal stripe modulus %d, so it would share a stripe with class %d",
			id, ClassStripeModulus, uint64(id)%ClassStripeModulus))
	}
	if _, dup := triageClassifiers[id]; dup {
		panic(fmt.Sprintf("triage: duplicate class id %d (%s)", id, id))
	}
	for _, p := range c.Probes() {
		if p.Class != id {
			panic(fmt.Sprintf("triage: probe %s declares class %d, registered under %d", p.ID, p.Class, id))
		}
	}
	if err := ValidateClassifier(c); err != nil {
		panic("triage: " + err.Error())
	}
	if where, bad := classifierCarriesAResponse(reflect.TypeOf(c), c.ID().String(), map[reflect.Type]bool{}); bad {
		panic(fmt.Sprintf("triage: classifier %s has a field that can hold a response, at %s. %s", id, where, whyAClassifierHoldsNoState))
	}
	triageClassifiers[id] = c
}

// reachProbeMediaTypes is the representative set ValidateClassifier calls Reaches with. Reaches is
// specified as pure and cheap with no I/O, so calling it at registration costs nothing and turns
// "a never with no reason" from a code review question into a build failure.
var reachProbeMediaTypes = []MediaType{
	"",
	"application/json",
	"application/x-www-form-urlencoded",
	"multipart/form-data",
	"application/xml",
	"application/graphql",
	"text/html",
}

// ValidateClassifier checks the parts of the contract that can be checked without sending
// anything: every Reaches answer carries a reason where one is required, and every declared probe
// names at least one insertion point the class actually reaches.
//
// THE REASON REQUIREMENT IS THE POINT. A class that returns ReachNever with no reason produces a
// slot with no verdict row and no explanation, and an operator reading the report cannot tell
// "ruled out because the mechanism cannot exist in a cookie" from "nobody wired this up". Those
// are the same pixel and completely different facts.
func ValidateClassifier(c Classifier) error {
	var problems []string
	reached := map[SlotKind]bool{}
	for _, k := range AllSlotKinds() {
		for _, mt := range reachProbeMediaTypes {
			r := c.Reaches(k, mt)
			switch r.Reach {
			case ReachAlways, ReachConditional:
				reached[k] = true
			}
			if r.Reach != ReachAlways && r.Reason == "" {
				problems = append(problems, fmt.Sprintf("Reaches(%s, %q) returned %s with no reason", k, mt, r.Reach))
			}
		}
	}
	for _, p := range c.Probes() {
		if len(p.Points) == 0 {
			problems = append(problems, fmt.Sprintf("probe %s names no insertion point, so it can never be planned", p.ID))
			continue
		}
		any := false
		for _, k := range p.Points {
			if reached[k] {
				any = true
				break
			}
		}
		if !any {
			problems = append(problems, fmt.Sprintf("probe %s targets %v, none of which this class reaches, so it is dead weight in the cost model", p.ID, p.Points))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("class %s failed the classifier contract: %s", c.ID(), strings.Join(problems, "; "))
	}
	return nil
}

// RegisteredClassifiers returns a copy of the registry, so a caller cannot mutate it.
func RegisteredClassifiers() map[ClassID]Classifier {
	out := make(map[ClassID]Classifier, len(triageClassifiers))
	for k, v := range triageClassifiers {
		out[k] = v
	}
	return out
}

// ClassifierFor looks one up.
func ClassifierFor(id ClassID) (Classifier, bool) {
	c, ok := triageClassifiers[id]
	return c, ok
}

// ---------------------------------------------------------------------------------------------
// 5. THE ISOLATION LAW, EXECUTABLE
// ---------------------------------------------------------------------------------------------

// MarkerPlaceholder is what a marker is replaced with before payloads are compared. Two probes
// that differ only in their marker are the SAME payload for the purpose of this check, because the
// marker is minted per probe and would otherwise make every payload trivially unique.
const MarkerPlaceholder = "<marker>"

// MarkerShapePattern is the regexp SOURCE for a marker in any case. Case-insensitive on purpose:
// DESER's payloads carry Mu, the marker with byte 0 uppercased, and a case-sensitive normaliser
// would treat Mu and M as different payloads and let a real collision through.
//
// It is exported as a source string rather than as a compiled *regexp.Regexp because the body
// comparator in package utils strips marker forms on every comparison and needs its own compiled
// copy. Handing out the compiled value would hand out shared mutable state: Regexp.Longest()
// changes how every other caller matches. The SHAPE is the thing that must have one definition,
// and this constant is it.
const MarkerShapePattern = `(?i)` + DefaultMarkerAnchor + `[0-9a-zA-Z]{13}`

var markerPattern = regexp.MustCompile(MarkerShapePattern)

// NormaliseMarkers replaces every marker-shaped run with MarkerPlaceholder.
//
// It is implemented here rather than left as a stub because without it the isolation check cannot
// exist, and the isolation check is the law. It deliberately knows only the marker SHAPE from
// foundations 2.2; minting, checksums and ordinal allocation belong to the marker agent.
func NormaliseMarkers(payload []byte) []byte {
	return markerPattern.ReplaceAll(payload, []byte(MarkerPlaceholder))
}

// IsolationViolationKind names which rule was broken, so a failure message says what to do rather
// than printing a diff.
type IsolationViolationKind string

const (
	// IsoDuplicateProbeID: two probes share an ID, so an ordinal cannot be traced to one payload.
	IsoDuplicateProbeID IsolationViolationKind = "duplicate_probe_id"
	// IsoProbeClassMismatch: a probe declares a class other than the one that registered it.
	IsoProbeClassMismatch IsolationViolationKind = "probe_class_mismatch"
	// IsoDuplicatePayload is check I1b, the law itself: two classes declare byte-equal payloads.
	IsoDuplicatePayload IsolationViolationKind = "duplicate_payload_across_classes"
	// IsoUndeclaredContainment is check I1c: one class's payload contains another's, 24 bytes or
	// more, without an Embeds annotation saying so.
	IsoUndeclaredContainment IsolationViolationKind = "undeclared_containment"
	// IsoForeignMarker is check I1d (CATALOGUE T-ISO-3): a payload embeds a marker whose ordinal
	// stripe belongs to another class, so that class's marker search would get a hit from this
	// class's probe.
	IsoForeignMarker IsolationViolationKind = "foreign_marker_in_payload"
	// IsoEmptyPayload: a non-control probe with no bytes tests nothing and would record clean.
	IsoEmptyPayload IsolationViolationKind = "empty_payload"
)

// IsolationViolation is one broken rule.
type IsolationViolation struct {
	Kind   IsolationViolationKind
	ProbeA ProbeID
	ClassA ClassID
	ProbeB ProbeID
	ClassB ClassID
	Detail string
}

func (v IsolationViolation) String() string {
	if v.ProbeB == "" {
		return fmt.Sprintf("%s: %s (class %s): %s", v.Kind, v.ProbeA, v.ClassA, v.Detail)
	}
	return fmt.Sprintf("%s: %s (class %s) versus %s (class %s): %s",
		v.Kind, v.ProbeA, v.ClassA, v.ProbeB, v.ClassB, v.Detail)
}

// IsolationReport is the result. It reports what it CHECKED as well as what it found, because a
// check that has not been written is not a check that passed, and the only way to keep those two
// apart is to name the gaps in the output the test reads.
type IsolationReport struct {
	Violations           []IsolationViolation
	ChecksRun            []string
	ChecksNotImplemented []string
	ClassesChecked       int
	ProbesChecked        int
}

// OK reports whether the registry satisfies every check that ran. It says nothing about the checks
// that did not run, which is why ChecksNotImplemented is asserted separately by the test.
func (r IsolationReport) OK() bool { return len(r.Violations) == 0 }

// isolationChecksNotImplemented is the honest gap list.
//
// CATALOGUE T-ISO-3 requires decoding every binary constant a probe emits (base64, hex,
// length-prefixed) and asserting the embedded marker belongs to the owning class. The plain-text
// half of that is implemented below. The encoded half is not, because the encoders that would
// produce those constants are another agent's file and there is nothing yet to decode. The gap is
// listed rather than left silent so that nobody reads a green isolation test as covering it.
var isolationChecksNotImplemented = []string{
	"I1d-encoded: markers embedded as base64, hex or length-prefixed binary are not extracted yet",
	"I1a: the dot-dot and XML-ness family rules of ruling R7 are not encoded yet",
}

// CheckPayloadIsolation runs the law over a registry.
//
// It takes the registry as an argument rather than reading the package variable so that the test
// can also run it against a fixture with a planted collision and prove the check actually fires. A
// law that has only ever been run against a registry that satisfies it has not been tested.
func CheckPayloadIsolation(reg map[ClassID]Classifier) IsolationReport {
	rep := IsolationReport{
		ChecksRun: []string{
			"I0-ids: probe ids are globally unique and each declares its registering class",
			"I1b: payloads are pairwise byte-disjoint across classes after marker normalisation",
			"I1c: cross-class containment of 24 bytes or more carries an Embeds annotation",
			"I1d-plain: a plain-text marker in a payload belongs to the owning class's stripe",
		},
		ChecksNotImplemented: append([]string(nil), isolationChecksNotImplemented...),
		ClassesChecked:       len(reg),
	}

	type entry struct {
		spec  ProbeSpec
		owner ClassID
		norm  []byte
	}
	var all []entry
	for _, id := range sortedClassIDs(reg) {
		for _, p := range reg[id].Probes() {
			all = append(all, entry{spec: p, owner: id, norm: NormaliseMarkers(p.Logical)})
		}
	}
	rep.ProbesChecked = len(all)

	// I0: ids unique, class stamped correctly, payload non-empty.
	byID := map[ProbeID]entry{}
	for _, e := range all {
		if prev, dup := byID[e.spec.ID]; dup {
			rep.Violations = append(rep.Violations, IsolationViolation{
				Kind: IsoDuplicateProbeID, ProbeA: e.spec.ID, ClassA: e.owner,
				ProbeB: prev.spec.ID, ClassB: prev.owner,
				Detail: "an ordinal cannot be traced back to one payload if two probes share an id",
			})
			continue
		}
		byID[e.spec.ID] = e
		if e.spec.Class != e.owner {
			rep.Violations = append(rep.Violations, IsolationViolation{
				Kind: IsoProbeClassMismatch, ProbeA: e.spec.ID, ClassA: e.owner,
				Detail: fmt.Sprintf("declares class %s", e.spec.Class),
			})
		}
		if len(e.spec.Logical) == 0 && !e.spec.IsControl {
			rep.Violations = append(rep.Violations, IsolationViolation{
				Kind: IsoEmptyPayload, ProbeA: e.spec.ID, ClassA: e.owner,
				Detail: "a non-control probe with no bytes sends nothing and would record clean",
			})
		}
	}

	// I1b: pairwise byte-equality across classes, after marker normalisation.
	seen := map[string]entry{}
	for _, e := range all {
		k := string(e.norm)
		prev, dup := seen[k]
		if !dup {
			seen[k] = e
			continue
		}
		if prev.owner != e.owner {
			rep.Violations = append(rep.Violations, IsolationViolation{
				Kind: IsoDuplicatePayload, ProbeA: e.spec.ID, ClassA: e.owner,
				ProbeB: prev.spec.ID, ClassB: prev.owner,
				Detail: "byte-equal payloads: a block or a rejection of this payload cannot be attributed to either class",
			})
		}
	}

	// I1c: containment of 24 bytes or more across classes needs an Embeds annotation. Containment
	// is not forbidden. Silent containment is, because a hit on the shorter payload inside the
	// longer one's response is attributable to neither class unless someone wrote down that it can
	// happen.
	const containmentFloor = 24
	for i := range all {
		for j := range all {
			if i == j || all[i].owner == all[j].owner {
				continue
			}
			short, long := all[i], all[j]
			if len(short.norm) < containmentFloor || len(short.norm) >= len(long.norm) {
				continue
			}
			if !bytes.Contains(long.norm, short.norm) || declaresEmbed(long.spec, short.spec.ID) {
				continue
			}
			rep.Violations = append(rep.Violations, IsolationViolation{
				Kind: IsoUndeclaredContainment, ProbeA: long.spec.ID, ClassA: long.owner,
				ProbeB: short.spec.ID, ClassB: short.owner,
				Detail: fmt.Sprintf("contains %d bytes of it with no Embeds annotation", len(short.norm)),
			})
		}
	}

	// I1d-plain: a marker written into a payload must be the owning class's.
	for _, e := range all {
		for _, m := range markerPattern.FindAll(e.spec.Logical, -1) {
			mk := Marker(bytes.ToLower(m))
			owner, ok := mk.ClassID()
			if !ok {
				continue // a marker-shaped run that does not parse is not an attribution risk
			}
			if owner != e.owner {
				rep.Violations = append(rep.Violations, IsolationViolation{
					Kind: IsoForeignMarker, ProbeA: e.spec.ID, ClassA: e.owner,
					Detail: fmt.Sprintf("embeds marker %q, whose ordinal stripe is class %s", m, owner),
				})
			}
		}
	}

	sort.Slice(rep.Violations, func(i, j int) bool {
		if rep.Violations[i].Kind != rep.Violations[j].Kind {
			return rep.Violations[i].Kind < rep.Violations[j].Kind
		}
		if rep.Violations[i].ProbeA != rep.Violations[j].ProbeA {
			return rep.Violations[i].ProbeA < rep.Violations[j].ProbeA
		}
		return rep.Violations[i].ProbeB < rep.Violations[j].ProbeB
	})
	return rep
}

func declaresEmbed(p ProbeSpec, id ProbeID) bool {
	for _, e := range p.Embeds {
		if e == id {
			return true
		}
	}
	return false
}

func sortedClassIDs(reg map[ClassID]Classifier) []ClassID {
	out := make([]ClassID, 0, len(reg))
	for id := range reg {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// PlannedProbesAreDeclared checks Plan's output against Probes(). A payload conjured at runtime
// would never have been seen by CheckPayloadIsolation, so the isolation law would hold over the
// declared set and mean nothing about what actually went on the wire.
func PlannedProbesAreDeclared(c Classifier, reqs []ProbeRequest) error {
	declared := map[ProbeID]bool{}
	for _, p := range c.Probes() {
		declared[p.ID] = true
	}
	var undeclared []string
	for _, r := range reqs {
		if !declared[r.Spec] {
			undeclared = append(undeclared, string(r.Spec))
		}
	}
	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		return fmt.Errorf("triage: class %s planned probes it never declared, so they were never isolation-checked: %v",
			c.ID(), undeclared)
	}
	return nil
}
