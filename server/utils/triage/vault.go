package triage

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"ars0n-framework-v2-server/utils/internal/triagecap"
)

// ---------------------------------------------------------------------------------------------
// 8. THE TWO KINDS OF OBSERVATION. CATALOGUE 5.1, AND THIS IS THE ISOLATION LAW AS A TYPE
// ---------------------------------------------------------------------------------------------

// Replay is the response to a request that was a REPLAY of something the crawl observed: the
// unperturbed baseline, the route control at the slot's observed value, the prelude control
// carrying the captured body verbatim.
//
// A replay carries no payload from any class, so it is the control, so sharing it is correct. It is
// the ONLY kind of observation the runner hands to more than one classifier.
type Replay struct {
	obs Observation
	ok  bool // set only by NewReplay, so a zero-value Replay cannot pose as a measured control
}

// NewReplay refuses an observation that carries a payload.
//
// WHY THIS CHECK EXISTS AND IS NOT A COMMENT. Replay is the one shared channel. If a perturbed
// response could be wrapped in a Replay, the isolation law would have exactly one hole and it would
// be the widest one: every class reads the controls. The check closes it at construction.
//
// AND WHY IT NO LONGER TRUSTS THE STAMPS. The first version checked Kind, Class and ProbeOrdinal
// and nothing else, which made it launderable: take a perturbed observation, set Kind to
// ObsBaseline, Class to ClassNone and ProbeOrdinal to 0, and a response that carried a SQL payload
// becomes a control every class reads. Those three fields are stamped by the same code that could
// be wrong, so they cannot be the only evidence. The payload and the marker are the RECORD OF WHAT
// WENT OUT, written by the encoder and by the marker minter, so they are checked too and they win:
// an observation carrying either is refused whatever its stamps say. Fail closed. If the stamps
// and the wire record disagree, something is wrong, and the one shared channel is the last place
// to guess which of the two is right.
//
// Proj.MarkerHits is deliberately NOT a refusal reason. A marker in the RESPONSE is something the
// application echoed back, and on a stored-payload application a genuine baseline can carry one
// from an earlier run. Refusing on that would make the control unobtainable on exactly the
// applications where the controls matter most. obs.Marker is what THIS request carried, which is a
// different claim, and that is the one that is checked.
//
// IT TAKES THE RUNNER CAPABILITY because minting a control is a runner act. A class that could
// build its own Replay could hand a fabricated control to any shared helper that takes one and
// score a differential against a response nobody measured.
func NewReplay(cap triagecap.Runner, obs Observation) (Replay, error) {
	if !cap.Held() {
		return Replay{}, ErrNotTheRunner
	}
	if obs.Kind.CarriesPayload() {
		return Replay{}, fmt.Errorf("triage: refused to make a shared control out of a %s observation, which carried a payload", obs.Kind)
	}
	if obs.Class != ClassNone || obs.ProbeOrdinal != 0 {
		return Replay{}, fmt.Errorf("triage: refused to make a shared control out of an observation stamped class %s ordinal %d",
			obs.Class, obs.ProbeOrdinal)
	}
	if obs.Payload.Present() {
		return Replay{}, fmt.Errorf("triage: refused to make a shared control out of observation %q: it is stamped kind %s class %s ordinal %d, but it carries a payload (%s), and the payload record is what actually went out on the wire",
			obs.ObsID, obs.Kind, obs.Class, obs.ProbeOrdinal, obs.Payload.Describe())
	}
	if obs.Marker != "" || obs.MarkerPos != "" {
		return Replay{}, fmt.Errorf("triage: refused to make a shared control out of observation %q: it is stamped kind %s class %s ordinal %d, but it carries marker %q at position %q, and only a probe carries a marker",
			obs.ObsID, obs.Kind, obs.Class, obs.ProbeOrdinal, obs.Marker, obs.MarkerPos)
	}
	return Replay{obs: obs, ok: true}, nil
}

// Obs returns the control. It takes no class argument because a control belongs to everyone.
func (r Replay) Obs() Observation { return r.obs }

// Resolved reports whether this replay actually happened. A zero-value Replay is not a resolved
// route: a classifier that reads ctx.Route without checking would otherwise plan against a route
// control that was never sent.
func (r Replay) Resolved() bool { return r.ok }

// ---------------------------------------------------------------------------------------------
// 8a. THE VAULT, WHY Perturbed HOLDS NO OBSERVATION, AND WHY IT HOLDS NO WHOLE VAULT EITHER
// ---------------------------------------------------------------------------------------------
//
// THE FOUR LEAKS THE FIRST VAULT CLOSED. All four compiled against the version before it, which
// kept the Observation in an unexported field and guarded it with an accessor check:
//
//	(a) direct field read:  func leak(p Perturbed) Observation { return p.obs }
//	(b) forged literal:     Perturbed{obs: other.obs, owner: ClassSQL, ordinal: 4, ok: true}
//	(c) laundering:         re-stamp a probe as a baseline and feed it to NewReplay
//	(d) range the map:      for _, e := range p.vault.held { out = append(out, e.obs) }
//	                        or PerturbedVaultFor(runID), which needs no handle at all
//
// (a) and (b) died when the observation left the struct and the handle became a ticket used by
// pointer identity. (c) died in NewReplay. (d) died when the classifiers became their own package
// and every one of those field names became unexported to them.
//
// AND THEN THE FIFTH FAMILY, WHICH IS WHY THE VAULT IS NOW PARTITIONED.
//
// An adversarial audit ran fifteen attempts against the package-split version and five succeeded,
// all of them vet-clean, three of them without unsafe. The diagnosis is one sentence:
//
//	UNEXPORTING A FIELD STOPS THE COMPILER AND STOPS NOTHING ELSE.
//
// reflect reads through unexported fields perfectly well. .String, .Int, .Uint, .Index, .Len and
// .MapKeys all work on a value obtained from an unexported field; only .Interface and .Set refuse.
// So from the one handle a classifier is legitimately given:
//
//	mine, _, _ := ctx.Own.At(0)
//	held := reflect.ValueOf(mine).Field(0).Elem().FieldByName("held")
//	for _, k := range held.MapKeys() { ... }
//
// printed every class's response body byte for byte. The unsafe variant did the same and handed
// back typed Observations. A third attempt took those foreign handles straight back through
// OwnFor, which asks whether the HANDLES belong to c and never whether the CALLER does, and so
// returned a foreign response with a nil error through the sanctioned API. A fourth removed the
// precondition entirely: a class that had sent nothing minted one throwaway response of its own
// with the run id out of ctx.Route.Obs().RunID, and the handle it got back opened everybody's.
//
// EVERY ONE OF THOSE IS THE SAME BUG. The object a classifier can reach CONTAINED every class's
// Observation. No guard fixes that, because there is nothing wrong with any individual step; the
// wrong thing is what is sitting at the end of the pointer. Three rounds of guards each sprang a
// new hole, and the compile-fail fixtures are structurally blind to all four of these because
// they compile.
//
// SO THE OBJECT AT THE END OF THE POINTER IS NOW A DIFFERENT OBJECT. The vault is keyed by
// (run, class). A Perturbed points at its owner's PARTITION and not at the run's vault, so the
// map a reflect walk finds holds one class's entries and the walk enumerates exactly what the
// caller was already handed. There is nothing to find, so there is no test in the way, so there is
// nothing for the next clever reader to write around.
//
//	attempt 7  reflect from the handle          -> the partition, which is your own
//	attempt 8  unsafe mirror of the handle      -> the same partition
//	attempt 13 OwnFor over foreign handles      -> there are no foreign handles to pass
//	attempt 14 mint a throwaway and reflect it  -> minting needs the runner capability
//	attempt 15 go:linkname the run registry     -> there is no package-level registry any more
//
// THE WRITE SIDE HAD TO GO WITH IT. Partitioning the read side alone is undone by minting: name
// class SQL as the owner and the handle you get back is a handle into SQL's partition. So every
// minting entry point now takes a triagecap.Runner, which lives in an internal package that the
// classifiers, being outside server/utils, cannot import. See that package's doc comment.
//
// AND THE PACKAGE-LEVEL REGISTRY IS GONE. It existed so that NewPerturbed(obs, ...) could find the
// run's vault from obs.RunID. It was also a package-level symbol, which is all //go:linkname needs:
// the audit reached every class's body with no handle, no ctx and no run id. Nothing in this
// codebase called NewPerturbed outside tests, so the registry was deleted rather than defended.
// The runner holds its own vault from NewPerturbedVault and ends it with Release. A run's
// responses are now reachable only from a value somebody is holding, which is the property that
// made the linkname attack work and the property that ends it.

// ErrUnmintedPerturbed is returned when a Perturbed resolves to no vault entry: a zero value, a
// forged composite literal, or a handle into a partition that never minted it. In every case there
// is no measured response behind the value, so it fails closed.
var ErrUnmintedPerturbed = errors.New("triage: this Perturbed was never minted by a vault, so there is no measured response behind it")

// ErrRunReleased is returned when the run that owned a response has been released. It is a
// distinct error from ErrUnmintedPerturbed because "the run is over" and "this value is a forgery"
// are different bugs with different fixes.
var ErrRunReleased = errors.New("triage: the run that owned this response has been released")

// ErrNotTheRunner is returned by every entry point that mints, releases or partitions responses
// when the caller did not present the runner capability.
//
// It is fail-closed on purpose and it is an ERROR rather than a panic: a runner bug should be a
// loud refusal at the call site, and a classifier that somehow reached one of these should get
// nothing rather than a crash that a recover could turn into a retry loop.
var ErrNotTheRunner = errors.New("triage: this is a runner-only entry point and the caller presented no runner capability, so nothing was minted, released or filtered")

// perturbedTicket is the unforgeable handle, used by pointer identity.
//
// It carries a field rather than being an empty struct because Go is allowed to give two
// zero-size allocations the same address, and two tickets that compare equal would make one
// response readable through another's handle.
type perturbedTicket struct {
	seq uint64
}

// perturbedEntry is everything known about one perturbed response. It lives in the partition and
// never on a value a caller holds, so none of it can be forged by writing a struct literal.
type perturbedEntry struct {
	obs     Observation
	owner   ClassID
	probeID ProbeID
	ordinal uint64
	marker  Marker
}

// classPartition is ONE CLASS'S responses within one run, and it is the only vault object a
// Perturbed points at.
//
// THIS TYPE IS THE PRIMARY FIX. Everything reachable from a classifier's handle, by any route
// including reflect and unsafe, is inside one of these, and one of these holds one class's
// entries. The owner is a field of the partition rather than only of each entry so that a
// partition can answer "whose am I" without reading anything it holds.
type classPartition struct {
	runID    string
	owner    ClassID
	mu       sync.RWMutex
	held     map[*perturbedTicket]perturbedEntry
	seq      uint64
	released bool
}

func (c *classPartition) lookup(t *perturbedTicket) (perturbedEntry, error) {
	if c == nil || t == nil {
		return perturbedEntry{}, ErrUnmintedPerturbed
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.released {
		return perturbedEntry{}, fmt.Errorf("%w: run %q, class %s", ErrRunReleased, c.runID, c.owner)
	}
	e, ok := c.held[t]
	if !ok {
		return perturbedEntry{}, ErrUnmintedPerturbed
	}
	return e, nil
}

// PerturbedVault holds one run's perturbed responses, one partition per class.
//
// ONLY THE RUNNER EVER HOLDS ONE. No value a classifier can reach points at a vault: a Perturbed
// points at a partition, PlanCtx carries no vault, and there is no package-level registry to look
// one up in. Holding a vault is holding the whole run, which is exactly what the runner does and
// exactly what a class must never do.
//
// LIFECYCLE, because a map of Observations that outlives its run is a memory leak with a tidy
// name. The vault is created per run and dropped with it: Release empties every partition, and
// once the runner drops its reference the whole run's responses are collectable even if a stale
// Perturbed is still held somewhere. Reading through a released handle is an error, never an empty
// observation that a classifier could score as a silent response.
//
// CONCURRENCY. The runner sends probes in parallel. The vault's own lock covers the partition map
// and each partition has its own lock, so two classes minting at once do not serialise on each
// other. Reads return the Observation BY VALUE, which is a copy, so a reader can neither mutate
// the stored response nor race a later write to the same entry.
type PerturbedVault struct {
	runID    string
	mu       sync.RWMutex
	parts    map[ClassID]*classPartition
	released bool
}

// NewPerturbedVault opens a vault for one run.
//
// It takes the runner capability: opening a vault is the act that creates partitions, and a class
// that could open one could mint into any partition of it.
func NewPerturbedVault(cap triagecap.Runner, runID string) *PerturbedVault {
	if !cap.Held() {
		return nil
	}
	return &PerturbedVault{runID: runID, parts: make(map[ClassID]*classPartition, 8)}
}

// partitionFor returns the run's partition for one class, opening it on first use.
func (v *PerturbedVault) partitionFor(owner ClassID) (*classPartition, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.released {
		return nil, fmt.Errorf("%w: run %q", ErrRunReleased, v.runID)
	}
	p, ok := v.parts[owner]
	if !ok {
		p = &classPartition{runID: v.runID, owner: owner, held: make(map[*perturbedTicket]perturbedEntry, 16)}
		v.parts[owner] = p
	}
	return p, nil
}

// Release drops every response this run captured and makes every outstanding handle fail closed.
// It is idempotent, and it returns how many entries it dropped so a runner can log the number
// rather than guess at it.
func (v *PerturbedVault) Release(cap triagecap.Runner) int {
	if v == nil || !cap.Held() {
		return 0
	}
	v.mu.Lock()
	parts := make([]*classPartition, 0, len(v.parts))
	for _, p := range v.parts {
		parts = append(parts, p)
	}
	v.parts = nil
	v.released = true
	v.mu.Unlock()

	n := 0
	for _, p := range parts {
		p.mu.Lock()
		n += len(p.held)
		p.held = nil
		p.released = true
		p.mu.Unlock()
	}
	return n
}

// Live reports how many responses the vault is holding across every partition, so the lifecycle
// can be measured rather than asserted.
//
// It needs no capability because it needs a vault, and a vault is the capability: nothing a
// classifier can reach is one.
func (v *PerturbedVault) Live() int {
	if v == nil {
		return 0
	}
	v.mu.RLock()
	parts := make([]*classPartition, 0, len(v.parts))
	for _, p := range v.parts {
		parts = append(parts, p)
	}
	v.mu.RUnlock()
	n := 0
	for _, p := range parts {
		p.mu.RLock()
		n += len(p.held)
		p.mu.RUnlock()
	}
	return n
}

// LiveFor reports how many responses one class's partition is holding. A per-class number is what
// tells "this class sent nothing" apart from "this run sent nothing", and those two produce
// different verdicts.
func (v *PerturbedVault) LiveFor(owner ClassID) int {
	if v == nil {
		return 0
	}
	v.mu.RLock()
	p := v.parts[owner]
	v.mu.RUnlock()
	if p == nil {
		return 0
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.held)
}

// RunID reports which run this vault belongs to.
func (v *PerturbedVault) RunID() string {
	if v == nil {
		return ""
	}
	return v.runID
}

// Perturbed is the response to a request that carried a payload. The request was MODIFIED,
// therefore it is a payload, therefore it belongs to exactly one class.
//
// IT HOLDS NO OBSERVATION AND NO VAULT. Its two fields are the OWNER'S PARTITION and a ticket.
// Neither of them is a response, and neither of them reaches another class's. See section 8a.
type Perturbed struct {
	part   *classPartition
	ticket *perturbedTicket
}

// Mint stamps ownership at send time, asserts the R12 stripe, and puts the response in the
// OWNER'S partition of this run.
//
// The runner is the only caller and the capability is what makes that true rather than hoped for.
// The assertions are here so that a runner bug is loud instead of producing a response nobody can
// attribute.
func (v *PerturbedVault) Mint(cap triagecap.Runner, obs Observation, owner ClassID, probeID ProbeID, ordinal uint64, marker Marker) (Perturbed, error) {
	if !cap.Held() {
		return Perturbed{}, ErrNotTheRunner
	}
	if v == nil {
		return Perturbed{}, errors.New("triage: Mint called with no vault, so there is nowhere to put the response that another class cannot reach")
	}
	if !owner.Known() {
		return Perturbed{}, fmt.Errorf("triage: perturbed response stamped with unregistered class %d", owner)
	}
	if ordinal%ClassStripeModulus != uint64(owner) {
		return Perturbed{}, fmt.Errorf("triage: ordinal %d is in stripe %d but was stamped for class %s (stripe %d)",
			ordinal, ordinal%ClassStripeModulus, owner, uint64(owner))
	}
	if marker != "" && !marker.BelongsTo(owner) {
		return Perturbed{}, fmt.Errorf("triage: marker %q does not belong to class %s, so its response would be attributable to the wrong class",
			marker, owner)
	}

	part, err := v.partitionFor(owner)
	if err != nil {
		return Perturbed{}, fmt.Errorf("%w, probe %s", err, probeID)
	}
	part.mu.Lock()
	defer part.mu.Unlock()
	if part.released {
		return Perturbed{}, fmt.Errorf("%w: run %q, probe %s", ErrRunReleased, part.runID, probeID)
	}
	part.seq++
	t := &perturbedTicket{seq: part.seq}
	part.held[t] = perturbedEntry{obs: obs, owner: owner, probeID: probeID, ordinal: ordinal, marker: marker}
	return Perturbed{part: part, ticket: t}, nil
}

// entry resolves the handle. Everything a caller can learn about a Perturbed goes through here, so
// a value that was not minted learns nothing.
func (p Perturbed) entry() (perturbedEntry, error) {
	if p.part == nil || p.ticket == nil {
		return perturbedEntry{}, ErrUnmintedPerturbed
	}
	return p.part.lookup(p.ticket)
}

// Minted reports whether this value resolves to a response the runner actually captured. A forged
// literal, a zero value and a released handle all report false.
func (p Perturbed) Minted() bool {
	_, err := p.entry()
	return err == nil
}

// THERE IS NO Perturbed.Obs, AND ITS ABSENCE IS THE ANSWER TO A SPECIFIC HOLE.
//
// The accessor before it was Obs(as ClassID): the caller named the class it was asking as, and the
// call succeeded when that name matched the vault entry's owner. It was sound against a forged
// owner field, because the answer came from the entry. It was not sound against the caller simply
// asking for the truth: p.Obs(p.Owner()) returned a FOREIGN response with a nil error, because
// Owner() reads the same authoritative entry that Obs then compares against, so the two always
// agree.
//
// Any accessor that lets the caller NAME an owner has this shape. So no accessor does. A
// classifier does not ask for a class's response; it is handed the responses that are ALREADY its
// own, as an OwnedResponses whose class it cannot set, and reads them by index.
//
// ObsOf is the runner's read, and it is a method on the VAULT rather than on the handle, because
// holding the vault is holding every response in the run: the runner legitimately does and no
// classifier can. A handle into a partition this vault does not own resolves to nothing.
func (v *PerturbedVault) ObsOf(cap triagecap.Runner, p Perturbed) (Observation, error) {
	if !cap.Held() {
		return Observation{}, ErrNotTheRunner
	}
	if v == nil || p.part == nil || p.ticket == nil {
		return Observation{}, ErrUnmintedPerturbed
	}
	v.mu.RLock()
	mine := v.parts[p.part.owner] == p.part
	released := v.released
	v.mu.RUnlock()
	if released {
		return Observation{}, fmt.Errorf("%w: run %q", ErrRunReleased, v.runID)
	}
	if !mine {
		return Observation{}, ErrUnmintedPerturbed
	}
	e, err := p.part.lookup(p.ticket)
	if err != nil {
		return Observation{}, err
	}
	return e.obs, nil
}

// Owner is the authoritative owner, read from the vault entry. An unminted value owns nothing and
// reports ClassNone, which is no classifier's id, so it reaches nobody's Own.
func (p Perturbed) Owner() ClassID {
	e, err := p.entry()
	if err != nil {
		return ClassNone
	}
	return e.owner
}

func (p Perturbed) ProbeID() ProbeID {
	e, err := p.entry()
	if err != nil {
		return ""
	}
	return e.probeID
}

func (p Perturbed) Ordinal() uint64 {
	e, err := p.entry()
	if err != nil {
		return 0
	}
	return e.ordinal
}

func (p Perturbed) Marker() Marker {
	e, err := p.entry()
	if err != nil {
		return ""
	}
	return e.marker
}

// OwnedResponses is one class's own perturbed responses WITH the class they belong to, bound into
// a single value that only this package can construct with a class in it.
//
// WHY THE CLASS LIVES HERE AND NOT IN THE CALL. A classifier never names an owner, so it can never
// name the wrong one, and it can never name the right one for the wrong handle either. The class
// comes from OwnFor, which is a FILTER: it can only narrow a set of handles to those the vault
// says belong to c. A zero-value OwnedResponses, which is all a foreign package can build, carries
// class ClassNone, and ClassNone is not a registered owner, so it reads nothing at all.
type OwnedResponses struct {
	class ClassID
	held  []Perturbed
}

// OwnFor is the filter that builds PlanCtx.Own, and it is the load-bearing line of the whole
// system. Everything else about isolation is a consequence of this loop being right.
//
// It reads Owner(), which resolves through the partition, so a forged literal claiming to be class
// SQL's never enters SQL's set in the first place. ClassNone is refused outright: it is the
// baseline's class, no classifier runs as it, and letting it through would hand every unminted
// value to whoever asked.
//
// IT TAKES THE RUNNER CAPABILITY, and that closes a hole the filter itself could never close.
// OwnFor asks whether the HANDLES belong to c. It has never asked, and cannot ask, whether the
// CALLER is c. So OwnFor([]Perturbed{h}, h.Owner()) is p.Obs(p.Owner()) with two more characters:
// hand it a foreign handle together with that handle's true owner and it returns the foreign
// response through the sanctioned API with a nil error. Partitioning means a classifier holds no
// foreign handle to pass; the capability means a classifier cannot make the call at all. Both,
// because the audit's lesson was that one line of defence is the number that keeps failing.
//
// A caller with no capability gets a set labelled ClassNone, which reads nothing. That is a
// deliberate empty rather than an error return, because the signature is part of the classifier
// contract's shape and the only caller that can get here without a capability is a bug.
func OwnFor(cap triagecap.Runner, all []Perturbed, c ClassID) OwnedResponses {
	if !cap.Held() {
		return OwnedResponses{class: ClassNone}
	}
	out := OwnedResponses{class: c, held: make([]Perturbed, 0, 16)}
	if c == ClassNone {
		return out
	}
	for _, p := range all {
		if p.Owner() == c {
			out.held = append(out.held, p)
		}
	}
	return out
}

// Class is whose responses these are. It is read from the set, never set by a caller.
func (o OwnedResponses) Class() ClassID { return o.class }

// Len is how many of this class's own responses are in hand.
func (o OwnedResponses) Len() int { return len(o.held) }

// At returns the i-th handle and the response behind it.
//
// The owner check is made AGAIN here, against the vault entry, even though OwnFor already filtered
// on it. That is deliberate: OwnFor's filter is a loop somebody can edit, and this is the read
// itself. If the two ever disagree the read fails closed with ErrForeignObservation rather than
// handing over a response whose provenance two pieces of code no longer agree on.
func (o OwnedResponses) At(i int) (Perturbed, Observation, error) {
	if i < 0 || i >= len(o.held) {
		return Perturbed{}, Observation{}, fmt.Errorf("triage: class %s asked for own response %d of %d", o.class, i, len(o.held))
	}
	p := o.held[i]
	e, err := p.entry()
	if err != nil {
		return p, Observation{}, err
	}
	if e.owner != o.class {
		return p, Observation{}, fmt.Errorf("%w: a set built for class %s holds class %s's probe %s",
			ErrForeignObservation, o.class, e.owner, e.probeID)
	}
	return p, e.obs, nil
}

// whyAClassifierHoldsNoState is the explanation the panic carries, because a panic out of an
// init() with no reason attached is a panic somebody works around.
const whyAClassifierHoldsNoState = "A classifier is a pure function of the ctx it is handed: it takes a PlanCtx or a ClassifyCtx and returns requests or verdicts, and it keeps nothing between calls. " +
	"THE REASON IS NOT TIDINESS. RegisteredClassifiers and ClassifierFor are exported and a classifier can call them, so every registered value is reachable from every other class. " +
	"That is harmless exactly as long as no classifier HOLDS a response: the moment one caches its own observations in a field, a reflect walk from the registry hands them to everybody, " +
	"and the vault's partitioning is bypassed without anybody touching the vault. Keep per-run state in the ctx, or ask for a field on PlanCtx that the runner fills and OwnFor filters."

// classifierCarriesAResponse walks a classifier's own type for anything that could hold a
// response, and it fails closed on an interface because a walker cannot see what one will hold.
//
// It is deliberately narrow: the response-bearing types of this package, plus interfaces. A
// classifier with an int, a string, a duration or a compiled regexp is fine and is not the shape
// this exists to catch.
func classifierCarriesAResponse(rt reflect.Type, path string, seen map[reflect.Type]bool) (string, bool) {
	if rt == nil {
		return "", false
	}
	switch rt {
	case reflect.TypeOf(Observation{}), reflect.TypeOf(Perturbed{}), reflect.TypeOf(Replay{}),
		reflect.TypeOf(OwnedResponses{}), reflect.TypeOf(OwnedCallbacks{}), reflect.TypeOf(&PerturbedVault{}):
		return path + " (" + rt.String() + ")", true
	}
	switch rt.Kind() {
	case reflect.Interface:
		return path + " (interface " + rt.String() + ", which a walker cannot see into)", true
	case reflect.Ptr, reflect.Slice, reflect.Array, reflect.Chan:
		return classifierCarriesAResponse(rt.Elem(), path+"*", seen)
	case reflect.Map:
		if p, bad := classifierCarriesAResponse(rt.Key(), path+"{key}", seen); bad {
			return p, true
		}
		return classifierCarriesAResponse(rt.Elem(), path+"[]", seen)
	case reflect.Struct:
		if seen[rt] {
			return "", false
		}
		seen[rt] = true
		for i := 0; i < rt.NumField(); i++ {
			if p, bad := classifierCarriesAResponse(rt.Field(i).Type, path+"."+rt.Field(i).Name, seen); bad {
				return p, true
			}
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------------------------
// 9. WHAT A CLASSIFIER RECEIVES. CATALOGUE 5.2
// ---------------------------------------------------------------------------------------------

// BaselineModel is derived from the five unperturbed samples ALONE. TODO(noise agent): fill in.
// The fields are named here because classifiers reference them and the shape must be stable.
//
// IT CARRIES NO OBSERVATION, AND THAT IS CHECKED RATHER THAN INTENDED. The baseline is legitimately
// shared, because it is the control and every class differences against it. What makes that safe
// is that nothing in this struct is a RESPONSE: every field is a derived statistic, a byte range,
// a header name or a flag. The type walker in types_test.go asserts it, so a future agent adding a
// convenient Samples []Observation field fails the build rather than turning the one shared
// channel into the widest hole in the layer.
type BaselineModel struct {
	Samples int // how many unperturbed samples backed this model. 0 means no model.
	// Stable is the part 5.7 stability gate verdict. Its zero value is false, so an endpoint with
	// no model is never treated as stable.
	Stable          bool
	GateReason      string // too_volatile, status_flap, or empty when Stable
	VolatileRegions []VolatileRegion
	VolatileHeaders []string
	VolatileJSONPtr []string
	// SeedSuppressed names headers the seed list excluded but the learner found constant, with
	// their baseline values, so nothing vanishes silently from the comparison.
	SeedSuppressed map[string]string
	ClockTick      bool    // did a one-second-granularity field tick during the baseline window
	RFloor         float64 // the measured per-endpoint similarity floor
	RMAD           float64
	TimingNanos    []int64 // the baseline TTFB distribution, for the stability gate
	Degraded       bool    // body over 10 MiB, truncated, or the tokenizer errored. Can never produce clean.
}

// VolatileRegion is a byte range that differs across the baseline samples for this endpoint. It is
// MEASURED, never a hardcoded regex list: a hardcoded list suppresses the one signal that mattered
// on the one endpoint nobody tested it against.
type VolatileRegion struct {
	Offset int
	Length int
	Source string // learned | seed
}

// PreludeState is foundations 7.7. Its zero value is PreludeUnknown, not "no token needed".
type PreludeState string

const (
	PreludeUnknown             PreludeState = ""
	PreludeTokenNotRequired    PreludeState = "token_not_required"
	PreludeTokenObtained       PreludeState = "token_obtained"
	PreludeTokenUnobtainable   PreludeState = "token_required_unobtainable"
	PreludeViewstateBound      PreludeState = "viewstate_bound"
	PreludeControlContaminated PreludeState = "prelude_control_contaminated"
)

// Failed reports whether the prelude blocks sending. Unknown counts as failed: an unmeasured
// prelude on a mutating vector means every probe silently fails validation identically, which
// reads as a stable endpoint with no differential, which reads as clean.
func (p PreludeState) Failed() bool {
	return p != PreludeTokenNotRequired && p != PreludeTokenObtained
}

// AssetCorpus is the served-JS corpus. TODO(assets agent): fill in.
//
// ScannedN and AvailableM are BOTH required and are separate fields on purpose. This codebase has
// shipped four separate fields named like a corpus total that actually reported a page size or a
// per-run artefact, and the LinkFinder section silently capped at 50 files while reporting a count
// that read as complete. A capped corpus must be able to say it was capped.
//
// IT IS SHARED ACROSS CLASSES AND THAT IS CORRECT. An AssetFile is a file the target SERVES, fetched
// unperturbed by a GET that carried no class's payload. It is a control in the same sense the
// baseline is. What would break the law is an AssetFile whose Body came back from a perturbed
// request, so the corpus is built once, before any class plans anything, and never appended to
// during a run.
type AssetCorpus struct {
	Files    []AssetFile
	ScannedN int
	// AvailableM is meaningless unless Counted is true. Zero available can mean "this host serves
	// no JS" or "nobody counted", and those two produce opposite verdicts, so they get two fields
	// rather than one overloaded zero.
	AvailableM int
	Counted    bool
}

// Complete reports whether the corpus covers everything that was available. A class whose oracle
// needs the full corpus and gets an incomplete one emits cannot_determine (corpus_capped).
func (a AssetCorpus) Complete() bool { return a.Counted && a.ScannedN >= a.AvailableM }

type AssetFile struct {
	URL       string
	MediaType MediaType
	Body      []byte
	SHA256    [32]byte
}

// OOBConfig describes the out-of-band collaborator, and its zero value is OOBNone, so a class that
// needs a callback and was not given one emits no_collaborator rather than a silent clean.
type OOBConfig struct {
	Mode OOBMode
	// Base is the collaborator base host. The framework ships no default: a third party's default
	// collaborator would send this operator's target data to that third party.
	Base string
	// GraceWindow is how long after the last probe a callback still counts.
	GraceWindow time.Duration
	// ServesContent distinguishes a collaborator that can answer with a body (which RFI needs)
	// from one that only records the hit.
	ServesContent bool
}

type OOBMode string

const (
	OOBNone        OOBMode = ""
	OOBWildcardDNS OOBMode = "wildcard_dns"
	// OOBHTTPPath cannot see a DNS-only callback, which is the majority of SSRF. A class using it
	// says so with oob_no_dns rather than reporting clean.
	OOBHTTPPath OOBMode = "http_path"
)

// CallbackRec is one out-of-band hit.
type CallbackRec struct {
	Marker     Marker
	Protocol   string // dns | http
	SourceIP   string
	SourceASN  string
	ReceivedAt time.Time
	Request    []byte
}

// OwnedCallbacks is one class's own out-of-band hits, bound to the class they belong to.
//
// WHY THIS IS A TYPE AND NOT A COMMENT ON A SLICE. The field used to be []CallbackRec with a
// comment saying "only records whose marker ordinal is in THIS class's stripe ever reach a
// classifier". A comment is not a filter. Nothing checked it, nothing could check it, and the
// runner that would have had to honour it has not been written yet, so the first version of it
// would have been written against a field that looks like it carries every callback because it
// does. A callback record names the marker, which names the ordinal, which names the class, and a
// class reading another class's callbacks learns which of their probes reached the outside world.
//
// So it is the same shape as OwnedResponses: only this package can build one with a class in it,
// the filter is arithmetic on the marker's R12 stripe, and a zero value is labelled ClassNone and
// holds nothing.
type OwnedCallbacks struct {
	class ClassID
	held  []CallbackRec
}

// CallbacksFor filters out-of-band hits to the ones whose marker ordinal is in c's stripe.
//
// A record whose marker does not parse belongs to NOBODY and is dropped by every class rather than
// handed to the first one that asks. An unattributable callback is exactly the record that would
// otherwise be counted twice, once by the class that fired it and once by whoever else was looking.
func CallbacksFor(cap triagecap.Runner, all []CallbackRec, c ClassID) OwnedCallbacks {
	if !cap.Held() {
		return OwnedCallbacks{class: ClassNone}
	}
	out := OwnedCallbacks{class: c, held: make([]CallbackRec, 0, 4)}
	if c == ClassNone {
		return out
	}
	for _, r := range all {
		if r.Marker.BelongsTo(c) {
			out.held = append(out.held, r)
		}
	}
	return out
}

// Class is whose callbacks these are.
func (o OwnedCallbacks) Class() ClassID { return o.class }

// Len is how many of this class's own callbacks are in hand.
func (o OwnedCallbacks) Len() int { return len(o.held) }

// At returns the i-th callback, re-checking the marker's stripe against the set's class for the
// same reason OwnedResponses.At re-checks the owner: the filter is a loop somebody can edit and
// this is the read itself.
func (o OwnedCallbacks) At(i int) (CallbackRec, error) {
	if i < 0 || i >= len(o.held) {
		return CallbackRec{}, fmt.Errorf("triage: class %s asked for own callback %d of %d", o.class, i, len(o.held))
	}
	r := o.held[i]
	if !r.Marker.BelongsTo(o.class) {
		owner, _ := r.Marker.ClassID()
		return CallbackRec{}, fmt.Errorf("%w: a callback set built for class %s holds marker %q, whose stripe is class %s",
			ErrForeignObservation, o.class, r.Marker, owner)
	}
	return r, nil
}

// TriageBudget caps the work. Every cap that bites produces a named unknown, never a shortened
// clean: probe_budget_exhausted or slot_budget.
type TriageBudget struct {
	PerSlot           int
	PerRun            int
	MutatingAllowance int // how many non-idempotent requests this run may send
	BrowserAllowance  int // how many real-browser runs the DOM classes may have
	RemainingPerSlot  int
	RemainingPerRun   int
	RemainingMutating int
	RemainingBrowser  int
}

// Exhausted reports whether anything is left. A class that stops here must say which probes it did
// not send, in ClassVerdict.Untested.
func (b TriageBudget) Exhausted() bool {
	return b.RemainingPerSlot <= 0 || b.RemainingPerRun <= 0
}

// PlanCtx is everything a classifier may see when deciding what to send next.
//
// NOTE WHAT IS ABSENT. There is no field through which another class's perturbed response can
// arrive. Own is filtered by OwnFor and, since the partitioning, the handles in it do not even
// point at an object that holds anybody else's. Route and Prelude are Replays, which NewReplay
// refuses to build from a perturbed observation. Vector has no Parameters field. There is no vault
// and no run registry.
//
// That absence is asserted two ways. TestPlanCtxExposesPerturbedResponsesOnlyThroughOwn walks the
// TYPE graph, so a future agent adding a convenient "AllResponses" field fails the build. The
// adversary package walks the VALUE graph of a real ClassifyCtx at run time, through unexported
// fields, because a type walk cannot see what is at the end of a pointer and the whole family of
// leaks that forced the partitioning was about exactly that.
type PlanCtx struct {
	Slot     Slot
	Vector   TriageVector
	Baseline BaselineModel
	Route    Replay // the composed URL at its observed value
	Prelude  PreludeState
	Assets   AssetCorpus
	// Own is THIS class's own responses so far, and nothing else.
	Own    OwnedResponses
	Budget TriageBudget
	OOB    OOBConfig
	Round  int // 0 for the first batch
}

// ClassifyCtx is PlanCtx at scoring time, plus the post-baseline.
type ClassifyCtx struct {
	PlanCtx
	// PostBaseline is taken after the last probe on the slot. If it disagrees with the
	// pre-baseline the slot drifted and every verdict on it is cannot_determine (drift).
	PostBaseline Replay
	// Callbacks holds only the records whose marker ordinal is in THIS class's stripe, and the
	// type is what makes that true rather than the sentence.
	Callbacks OwnedCallbacks
}
