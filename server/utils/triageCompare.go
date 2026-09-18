package utils

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"ars0n-framework-v2-server/utils/triage"
)

// The comparator and the noise model. foundations part 5, CATALOGUE section 3.
//
// Every class differential in the triage layer rests on this file, so it decides whether the
// feature works on an application nobody has seen. Three properties are load-bearing and each one
// exists because its absence has already produced a shipped bug somewhere in this tree:
//
//  1. THE VOLATILE MAP IS MEASURED, NEVER LISTED. A hardcoded regex list of "things that look like
//     a timestamp" covers the apps its author had seen, is version-locked to the target's current
//     id format, and, worst, a pattern written to eat an epoch also eats a row count. "count": 12
//     going to "count": 0 is the cleanest boolean oracle a JSON API ever offers and a blindfold
//     that suppresses it reports clean with no indication anything was suppressed. So the app tells
//     us what varies, by varying: we difference the baseline samples against each other.
//
//  2. AGGRESSIVE MASKING IS ONLY SAFE BECAUSE NOTHING IS DISCARDED. The union of the markings over
//     all sample pairings masks more, not less. That trades false positives for false negatives
//     unless a probe whose only difference lies inside a masked region can reach a state of its
//     own. DiffMaskedOnly is that state, it carries the byte ranges and the before/after content,
//     and CountsAsClean is false for it. Implement the union without it and this layer prevents
//     exactly the errors it was built to prevent, in the wrong direction.
//
//  3. NOT KNOWING IS NOT CLEAN. GateVerdict, DiffVerdict and CompareResult all have a zero value
//     that means unmeasured, all of them answer false to CountsAsClean, and every path that cannot
//     measure returns a named reason rather than a quiet same.
//
// THE ONE THING SHARED ACROSS CLASSES is the unperturbed baseline, because it is the control and
// not a payload. Nothing in this file reads a perturbed response except through triage.OwnedResponses,
// which refuses a caller that is not the owning class.

// ---------------------------------------------------------------------------------------------
// 1. CONSTANTS, AND WHERE EACH NUMBER CAME FROM
// ---------------------------------------------------------------------------------------------

const (
	// triageDynamicityBoundary is sqlmap's DYNAMICITY_BOUNDARY_LENGTH (lib/core/settings.py:357).
	// A marking is anchored by this many bytes of context on each side, and a matching block
	// shorter than two boundaries cannot anchor one, so it is dropped.
	triageDynamicityBoundary = 20

	// triageGramLen is the anchor width for the matching-block search. Every block we keep is
	// longer than 2*boundary, so every block we keep contains at least one gram of this width,
	// so indexing grams of this width finds every block we would have kept. See
	// triageMatchingBlocks for why this replaces difflib's algorithm rather than porting it.
	triageGramLen = 2*triageDynamicityBoundary + 1

	// triageShingleLen is the shingle width for the Jaccard metric of foundations 5.4 item 7.
	triageShingleLen = 8

	// triageEchoMinRun is the shortest run of bytes shared between the sent wire payload and the
	// response body that counts as an echo and is removed from both sides before comparing.
	// Without echo removal any reflecting parameter makes every probe differ from baseline and the
	// whole differential collapses into noise.
	triageEchoMinRun = 8

	// TriageBaselineSamples is foundations 5.1. Five is not "five feels safe": sample 2 buys the
	// first differential, 3 buys alternation (A,B,A from a two-server pool), 4 buys bounded versus
	// unbounded variation, 5 buys a timing distribution and the fifth Date value.
	TriageBaselineSamples = 5

	// TriageNonIdempotentSamples is foundations 5.10 rule 1. Taking five samples of a POST that
	// creates a row creates five rows. The weaker noise model is the correct trade.
	TriageNonIdempotentSamples = 2

	// triageGateRFloorMin is G2.
	triageGateRFloorMin = 0.90

	// triageGateMaskedMax is G3: the fraction of the body inside learned markings.
	triageGateMaskedMax = 0.35

	// triageSingleMarkingMax is the foundations 5.3 escalation for one marking on its own.
	triageSingleMarkingMax = 0.30

	// triageRatioLowerBound and triageRatioUpperBound are sqlmap's LOWER_RATIO_BOUND and
	// UPPER_RATIO_BOUND (settings.py:106,107), kept only as the clamp on the measured threshold
	// and as the at-or-below-0.02 backstop. See triageDecideByRatio for the one place we refuse to
	// honour the upper bound as an override and why.
	triageRatioLowerBound = 0.02
	triageRatioUpperBound = 0.98

	// triageDegradeBytes is sqlmap's MAX_DIFFLIB_SEQUENCE_LENGTH (settings.py:1618). Above it the
	// comparison falls back to a length ratio and is marked degraded, and a degraded comparison
	// can never produce clean.
	triageDegradeBytes = 10 << 20

	// triageGramOccurrenceCap and triageMatchBudgetFactor bound the matching-block search. A body
	// of repeated boilerplate can otherwise make the extension step quadratic. Exhausting the
	// budget sets MatchIncomplete, which degrades the comparison; it never silently truncates the
	// marking set, because a short marking set reads as a stable endpoint.
	triageGramOccurrenceCap = 32
	triageMatchBudgetFactor = 64

	// triageMaskLengthRatio is THE LENGTH CEILING ON A LEARNED MASK, and it exists because the
	// novelty test next to it is alphabet-only.
	//
	// A marking attests an ALPHABET by measurement: these are the bytes this region was seen to
	// hold. It attests nothing about CAPACITY. A six-byte hexadecimal trace id attests all
	// sixteen hexadecimal digits, and without a ceiling the region then absorbs any quantity of
	// hexadecimal in silence. What fits in that silence is a boolean oracle whose rendered
	// output happens to be in-alphabet, a row count or a concatenated column dump inside the
	// masked span, and it disappears at any size. That is a false negative in the single most
	// important SQLi signal, and it does not get smaller as the payload gets bigger.
	//
	// So the probe's content for a region must lie within this factor of the length range the
	// region was OBSERVED to take, in both directions. Outside it the content is unattested and
	// the comparison is masked_only, which is reportable and is not clean.
	//
	// THE NUMBER. The widest legitimate re-render in the fixture corpus is T2c, where a 6-byte
	// fixed-width hex trace id is replaced by a 15-byte opaque id of the same alphabet: a ratio
	// of 2.5, and a case the foundations document sanctions as same. 3 is the smallest whole
	// multiple above it. The motivating false negative sits at 6 -> 24 bytes, a ratio of 4, so
	// the corpus brackets the ceiling from both sides rather than leaving it to taste. It is a
	// ratio and not an absolute byte count because the thing being bounded is how much more
	// channel the probe opened than the endpoint ever showed us, and that is relative.
	//
	// The shrink direction falls out of the same rule and is how DISAPPEARANCE is caught: a
	// region that held 6 bytes in every sample and holds 0 in the probe is below 6/3, so it is
	// unattested. A region observed empty at least once has emptiness attested and stays same.
	triageMaskLengthRatio = 3.0
)

// TriageBaselineMinSpan and TriageBaselineMinGap are THE BASELINE SPACING RULE, foundations 5.1,
// and they are specification rather than an implementation detail.
//
// Measured by the designer: five back-to-back requests complete in under 300 ms, so a body
// carrying a second-granularity timestamp shows the same value in all five, the learner concludes
// it is invariant, and then EVERY probe differs from baseline on the clock. Every class reports a
// differential on every payload, the operator chases hundreds of false positives, and the real one
// is invisible. The window must be wide enough for a one-second clock to tick inside it.
const (
	TriageBaselineMinSpan = 2200 * time.Millisecond
	TriageBaselineMinGap  = 1100 * time.Millisecond
)

// ---------------------------------------------------------------------------------------------
// 2. THE VERDICT VOCABULARIES
// ---------------------------------------------------------------------------------------------

// GateVerdict is the foundations 5.7 stability gate output. Its zero value is GateUnmeasured, so a
// caller that forgot to build a baseline gets an honest unknown rather than a judgeable endpoint.
//
// THE GATE GATES THE DIFFERENTIAL, NOT THE ENDPOINT. An endpoint that is too volatile still gets
// probed by every class whose oracle is deterministic computation, an out-of-band callback,
// distinctive content or an error signature, because none of those needs a baseline comparison.
// Only the differential oracles go to cannot_determine. Disabling the endpoint would throw away
// four working oracles because a fifth is unusable.
type GateVerdict string

const (
	GateUnmeasured         GateVerdict = ""
	GateJudgeable          GateVerdict = "judgeable"
	GateJudgeableShapeOnly GateVerdict = "judgeable_shape_only"
	GateTooVolatile        GateVerdict = "too_volatile"
	GateStatusFlap         GateVerdict = "status_flap"
	GateDrifted            GateVerdict = "drifted"
)

// BytesJudgeable reports whether a byte-level differential taken against this baseline means
// anything at all.
func (g GateVerdict) BytesJudgeable() bool { return g == GateJudgeable }

// ShapeJudgeable reports whether a JSON-shape or HTML-structure differential is usable. It is true
// for judgeable_shape_only, which is the whole point of that verdict: a REST endpoint whose bytes
// are dominated by ids and timestamps can still be judged on its shape.
func (g GateVerdict) ShapeJudgeable() bool {
	return g == GateJudgeable || g == GateJudgeableShapeOnly
}

// Reason is the cannot_determine reason a class records when the gate closed its oracle.
func (g GateVerdict) Reason() string {
	switch g {
	case GateJudgeable, GateJudgeableShapeOnly:
		return ""
	case GateTooVolatile:
		return "too_volatile"
	case GateStatusFlap:
		return "status_flap"
	case GateDrifted:
		return "drift"
	default:
		return "no_baseline"
	}
}

// DiffVerdict is one comparison outcome. The zero value is DiffUnmeasured and it is unknown.
type DiffVerdict string

const (
	DiffUnmeasured DiffVerdict = ""
	DiffSame       DiffVerdict = "same"
	DiffDifferent  DiffVerdict = "different"
	DiffBorderline DiffVerdict = "borderline"
	DiffMaskedOnly DiffVerdict = "masked_only"
	DiffReordered  DiffVerdict = "reordered"
	// DiffUnusable is a channel or a comparison that could not be measured: no body, a closed
	// gate, a transport refusal. It is not "no difference found".
	DiffUnusable DiffVerdict = "unusable"
)

// IsUnknown is the predicate. It fails closed: a verdict nobody recognises is unknown.
func (d DiffVerdict) IsUnknown() bool {
	switch d {
	case DiffSame, DiffDifferent, DiffBorderline, DiffMaskedOnly, DiffReordered:
		return false
	default:
		return true
	}
}

// CountsAsSame is the only route to "this probe changed nothing", and it is deliberately the only
// one, so a renderer and an exporter cannot drift apart the way two hand-written switches do.
func (d DiffVerdict) CountsAsSame() bool { return d == DiffSame }

// TriageState maps a comparison outcome onto the shared state vocabulary.
//
// DiffDifferent maps to StateSuspicious and NOT to StateFinding on purpose. A differential is
// evidence that the payload changed the response; it is not evidence that the class's mechanism
// fired. The owning class upgrades to a finding from its OWN oracle. It may never downgrade an
// unknown to clean.
func (d DiffVerdict) TriageState() triage.TriageState {
	switch d {
	case DiffSame:
		return triage.StateClean
	case DiffDifferent:
		return triage.StateSuspicious
	case DiffBorderline:
		return triage.StateBorderline
	case DiffMaskedOnly:
		return triage.StateMaskedOnly
	case DiffReordered:
		return triage.StateReordered
	default:
		return triage.StateCannotDetermine
	}
}

// diffRank orders the outcomes when several channels disagree. Different outranks everything
// because a change anywhere is a change; unusable outranks same because "one channel could not be
// read" must not be presentable as "nothing changed".
func diffRank(d DiffVerdict) int {
	switch d {
	case DiffDifferent:
		return 6
	case DiffReordered:
		return 5
	case DiffMaskedOnly:
		return 4
	case DiffBorderline:
		return 3
	case DiffUnusable:
		return 2
	case DiffSame:
		return 1
	default:
		return 0
	}
}

// ChannelID names one comparison channel. foundations 5.7 and CATALOGUE 3.3 between them require
// all of these, and they are separate channels rather than one blended score because "the status
// changed" and "a value changed in a 40 KB body" are different facts and a single ratio conflates
// them.
type ChannelID string

const (
	ChanStatus      ChannelID = "status"
	ChanHeaders     ChannelID = "headers"
	ChanBody        ChannelID = "body"
	ChanContentType ChannelID = "content_type"
	ChanLength      ChannelID = "length"
	ChanRedirect    ChannelID = "redirect_target"
	ChanCookies     ChannelID = "cookies_set"
	ChanJSONShape   ChannelID = "json_shape"
	ChanHTMLStruct  ChannelID = "html_structure"
)

// AllChannels is the full set, in report order.
func AllChannels() []ChannelID {
	return []ChannelID{
		ChanStatus, ChanHeaders, ChanBody, ChanContentType,
		ChanLength, ChanRedirect, ChanCookies, ChanJSONShape, ChanHTMLStruct,
	}
}

// ChannelResult is one channel's answer plus what it had to exclude to give it. Excluded is
// populated rather than dropped so a suppressed signal is auditable: the operator who sees a clean
// result and one interesting suppressed header can see it.
type ChannelResult struct {
	Channel  ChannelID
	Verdict  DiffVerdict
	Detail   string
	Excluded []string
}

// ---------------------------------------------------------------------------------------------
// 3. BYTE PRIMITIVES
// ---------------------------------------------------------------------------------------------

type triageBlock struct{ ai, bi, n int }

// triageGramIndex maps a rolling hash of triageGramLen bytes to the positions it occurs at.
type triageGramIndex struct {
	k   int
	pos map[uint64][]int32
}

const triageHashBase = uint64(1000003)

func triageBuildGramIndex(b []byte, k int) triageGramIndex {
	idx := triageGramIndex{k: k, pos: make(map[uint64][]int32)}
	if len(b) < k {
		return idx
	}
	pow := uint64(1)
	for i := 0; i < k-1; i++ {
		pow *= triageHashBase
	}
	var h uint64
	for i := 0; i < k; i++ {
		h = h*triageHashBase + uint64(b[i])
	}
	for i := 0; ; i++ {
		if cur := idx.pos[h]; len(cur) < triageGramOccurrenceCap {
			idx.pos[h] = append(cur, int32(i))
		}
		if i+k >= len(b) {
			break
		}
		h = (h-uint64(b[i])*pow)*triageHashBase + uint64(b[i+k])
	}
	return idx
}

// triageMatchingBlocks is the equivalent of difflib's get_matching_blocks, and it is a replacement
// rather than a port for two measured reasons.
//
// First, difflib is quadratic in the number of occurrences of each element. On a body whose
// alphabet is small, hexadecimal for instance, every byte occurs about n/16 times and the search
// degenerates. Second, Python's SequenceMatcher defaults to autojunk=True, which treats any
// element occurring in more than 1% of the sequence as junk once the sequence passes 200 elements.
// Over BYTES that discards the space character and most letters on any page above 20 KB, so a long
// common run is cut at every common byte. sqlmap inherits both behaviours.
//
// We only ever keep blocks longer than 2*triageDynamicityBoundary, and every such block contains
// at least one gram of triageGramLen bytes, so indexing grams of that width finds every block we
// would keep, in linear time, with no junk heuristic. The second return value is false when the
// extension budget ran out, which degrades the comparison rather than silently shortening the
// marking set.
func triageMatchingBlocks(a, b []byte) ([]triageBlock, bool) {
	if len(a) < triageGramLen || len(b) < triageGramLen {
		return nil, true
	}
	idx := triageBuildGramIndex(b, triageGramLen)
	budget := triageMatchBudgetFactor * (len(a) + len(b))
	complete := true

	type rng struct{ alo, ahi, blo, bhi int }
	var out []triageBlock
	stack := []rng{{0, len(a), 0, len(b)}}
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if r.ahi-r.alo < triageGramLen || r.bhi-r.blo < triageGramLen {
			continue
		}
		ai, bi, n, spent := triageLongestMatch(a, b, idx, r.alo, r.ahi, r.blo, r.bhi, budget)
		budget -= spent
		if budget <= 0 {
			complete = false
			budget = 0
		}
		if n == 0 {
			continue
		}
		out = append(out, triageBlock{ai, bi, n})
		if ai > r.alo && bi > r.blo {
			stack = append(stack, rng{r.alo, ai, r.blo, bi})
		}
		if ai+n < r.ahi && bi+n < r.bhi {
			stack = append(stack, rng{ai + n, r.ahi, bi + n, r.bhi})
		}
		if !complete {
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ai < out[j].ai })
	return out, complete
}

func triageLongestMatch(a, b []byte, idx triageGramIndex, alo, ahi, blo, bhi, budget int) (int, int, int, int) {
	k := idx.k
	bestA, bestB, bestN, spent := 0, 0, 0, 0
	if ahi-alo < k || bhi-blo < k {
		return 0, 0, 0, 0
	}
	pow := uint64(1)
	for i := 0; i < k-1; i++ {
		pow *= triageHashBase
	}
	var h uint64
	for i := alo; i < alo+k; i++ {
		h = h*triageHashBase + uint64(a[i])
	}
	for i := alo; i+k <= ahi; i++ {
		for _, p32 := range idx.pos[h] {
			p := int(p32)
			if p < blo || p+k > bhi {
				continue
			}
			// Extend the anchor both ways, staying inside the range.
			s, e := i, i+k
			q, f := p, p+k
			for s > alo && q > blo && a[s-1] == b[q-1] {
				s--
				q--
				spent++
			}
			for e < ahi && f < bhi && a[e] == b[f] {
				e++
				f++
				spent++
			}
			if e-s > bestN {
				bestA, bestB, bestN = s, q, e-s
			}
			if spent > budget {
				return bestA, bestB, bestN, spent
			}
		}
		if i+k >= ahi {
			break
		}
		h = (h-uint64(a[i])*pow)*triageHashBase + uint64(a[i+k])
	}
	return bestA, bestB, bestN, spent
}

// triageBagRatio is the quick_ratio equivalent: a multiset comparison, O(n). It ignores order
// entirely, which is why it never stands alone here.
func triageBagRatio(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range a {
		counts[c]++
	}
	matches := 0
	for _, c := range b {
		if counts[c] > 0 {
			counts[c]--
			matches++
		}
	}
	return 2.0 * float64(matches) / float64(len(a)+len(b))
}

func triageShingleSet(b []byte) map[uint64]struct{} {
	set := make(map[uint64]struct{})
	if len(b) == 0 {
		return set
	}
	if len(b) <= triageShingleLen {
		set[triageHash64(b)] = struct{}{}
		return set
	}
	for i := 0; i+triageShingleLen <= len(b); i++ {
		set[triageHash64(b[i:i+triageShingleLen])] = struct{}{}
	}
	return set
}

func triageHash64(b []byte) uint64 {
	h := uint64(14695981039346656037)
	for _, c := range b {
		h ^= uint64(c)
		h *= 1099511628211
	}
	return h
}

// triageShingleRatio is Jaccard similarity over 8-byte shingles. It is the order-sensitive half of
// the pair: two bodies that are anagrams score 1.0 on the bag ratio, so a result set whose order
// reverses with the same contents reads as identical under quick_ratio alone. That is a real
// differential signal and it is why this metric exists.
func triageShingleRatio(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1
	}
	sa, sb := triageShingleSet(a), triageShingleSet(b)
	if len(sa) == 0 || len(sb) == 0 {
		return 0
	}
	inter := 0
	small, large := sa, sb
	if len(sb) < len(sa) {
		small, large = sb, sa
	}
	for h := range small {
		if _, ok := large[h]; ok {
			inter++
		}
	}
	union := len(sa) + len(sb) - inter
	if union == 0 {
		return 1
	}
	return float64(inter) / float64(union)
}

// triageLongestCommonRun returns the longest run of at least minLen bytes present in both inputs,
// or nil. Used for echo removal.
func triageLongestCommonRun(a, b []byte, minLen int) []byte {
	if minLen <= 0 || len(a) < minLen || len(b) < minLen {
		return nil
	}
	idx := triageBuildGramIndex(b, minLen)
	best := 0
	bestAt := -1
	pow := uint64(1)
	for i := 0; i < minLen-1; i++ {
		pow *= triageHashBase
	}
	var h uint64
	for i := 0; i < minLen; i++ {
		h = h*triageHashBase + uint64(a[i])
	}
	for i := 0; i+minLen <= len(a); i++ {
		for _, p32 := range idx.pos[h] {
			p := int(p32)
			e, f := i+minLen, p+minLen
			for e < len(a) && f < len(b) && a[e] == b[f] {
				e++
				f++
			}
			if e-i > best {
				best, bestAt = e-i, i
			}
		}
		if i+minLen >= len(a) {
			break
		}
		h = (h-uint64(a[i])*pow)*triageHashBase + uint64(a[i+minLen])
	}
	if bestAt < 0 {
		return nil
	}
	return a[bestAt : bestAt+best]
}

// ---------------------------------------------------------------------------------------------
// 4. MARKINGS: LEARNING WHAT THIS ENDPOINT VARIES, BY WATCHING IT VARY
// ---------------------------------------------------------------------------------------------

// TriageMarking is one learned volatile region, represented the way sqlmap represents it: by the
// bytes on each side of the hole rather than by an offset. That representation is what makes T2c
// work, where the volatile value changes LENGTH between responses and an offset-based region would
// slide off it.
type TriageMarking struct {
	Prefix []byte
	Suffix []byte
}

// TriageLearnMarkings is foundations 5.3, adapted from sqlmap's findDynamicContent
// (lib/core/common.py:3395) with merge=True.
//
// The union across all pairings, not the intersection: a region that varies in ANY pair is
// volatile. Three samples from a two-server pool look identical when you happen to hit the same
// server twice, so intersecting would learn nothing on exactly the endpoint that needs the model
// most.
func TriageLearnMarkings(samples [][]byte) ([]TriageMarking, bool) {
	if len(samples) < 2 {
		return nil, true
	}
	first := samples[0]
	var out []TriageMarking
	seen := make(map[string]bool)
	complete := true
	for j := 1; j < len(samples); j++ {
		blocks, ok := triageMatchingBlocks(first, samples[j])
		if !ok {
			complete = false
		}
		kept := blocks[:0]
		for _, blk := range blocks {
			if blk.n > 2*triageDynamicityBoundary {
				kept = append(kept, blk)
			}
		}
		if len(kept) == 0 {
			// No block survived the boundary filter, so there is nothing to anchor a marking to
			// and this pairing learns nothing. Masking the whole document instead would be worse
			// than useless: every normalised body becomes empty, every ratio becomes 1.0, and the
			// gate then fails on masked_fraction rather than on the similarity floor, which hides
			// WHY the endpoint is unjudgeable. The floor already says it, at G2, correctly.
			continue
		}
		for i := -1; i < len(kept); i++ {
			var prefix, suffix []byte
			if i >= 0 {
				blk := kept[i]
				prefix = first[blk.ai : blk.ai+blk.n]
			}
			if i+1 < len(kept) {
				blk := kept[i+1]
				suffix = first[blk.ai : blk.ai+blk.n]
			}
			if prefix == nil && suffix != nil && kept[i+1].ai == 0 {
				continue
			}
			if suffix == nil && prefix != nil {
				blk := kept[i]
				if blk.ai+blk.n >= len(first) {
					continue
				}
			}
			if prefix == nil && suffix == nil {
				continue
			}
			if len(prefix) > triageDynamicityBoundary {
				prefix = prefix[len(prefix)-triageDynamicityBoundary:]
			}
			if len(suffix) > triageDynamicityBoundary {
				suffix = suffix[:triageDynamicityBoundary]
			}
			key := string(prefix) + "\x00" + string(suffix)
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, TriageMarking{Prefix: prefix, Suffix: suffix})
		}
	}
	return out, complete
}

// TriageApplyMarkings removes the content of every marking, returning the normalised body, the
// holes in ORIGINAL coordinates, and the hole contents in marking order (empty string when the
// marking did not match this body).
//
// The three cases are sqlmap's removeDynamicContent (common.py:3471): prefix-only trims the tail,
// suffix-only trims the head, both removes the span between.
func TriageApplyMarkings(body []byte, ms []TriageMarking) ([]byte, []triage.VolatileRegion, []string) {
	cur := append([]byte(nil), body...)
	var holes []triage.VolatileRegion
	contents := make([]string, len(ms))
	if len(ms) == 0 {
		return cur, nil, contents
	}
	for mi, m := range ms {
		if m.Prefix == nil && m.Suffix == nil {
			// The whole document varied. Mask all of it.
			if len(cur) > 0 {
				contents[mi] = string(cur)
				holes = triageAddHole(holes, 0, len(cur), body, cur)
				cur = cur[:0]
			}
			continue
		}
		switch {
		case m.Prefix == nil:
			i := bytes.LastIndex(cur, m.Suffix)
			if i > 0 {
				contents[mi] = string(cur[:i])
				holes = triageAddHole(holes, 0, i, body, cur)
				cur = cur[i:]
			}
		case m.Suffix == nil:
			i := bytes.Index(cur, m.Prefix)
			if i >= 0 && i+len(m.Prefix) < len(cur) {
				start := i + len(m.Prefix)
				contents[mi] = string(cur[start:])
				holes = triageAddHole(holes, start, len(cur)-start, body, cur)
				cur = cur[:start]
			}
		default:
			i := bytes.Index(cur, m.Prefix)
			if i < 0 {
				continue
			}
			start := i + len(m.Prefix)
			j := bytes.Index(cur[start:], m.Suffix)
			if j < 0 {
				continue
			}
			if j == 0 {
				continue
			}
			contents[mi] = string(cur[start : start+j])
			holes = triageAddHole(holes, start, j, body, cur)
			cur = append(cur[:start:start], cur[start+j:]...)
		}
	}
	sort.Slice(holes, func(i, j int) bool { return holes[i].Offset < holes[j].Offset })
	return cur, holes, contents
}

// triageAddHole records a hole found at curOffset in the partially-normalised body, translating it
// back to a coordinate in the original. Reported offsets are approximate once several markings
// overlap; they exist so the operator can find the region, not so anything is computed from them.
func triageAddHole(holes []triage.VolatileRegion, curOffset, length int, orig, cur []byte) []triage.VolatileRegion {
	off := curOffset
	if len(cur) < len(orig) {
		off += len(orig) - len(cur)
	}
	if off > len(orig) {
		off = len(orig)
	}
	return append(holes, triage.VolatileRegion{Offset: off, Length: length, Source: "learned"})
}

// ---------------------------------------------------------------------------------------------
// 5. PROJECTIONS: HTML STRUCTURE AND JSON SHAPE
// ---------------------------------------------------------------------------------------------

var triageTagRe = regexp.MustCompile(`(?is)<\s*([a-z][a-z0-9-]*)((?:\s+[^<>]*)?)>`)
var triageScriptRe = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script\s*>|<style\b[^>]*>.*?</style\s*>|<!--.*?-->`)
var triageAttrRe = regexp.MustCompile(`(?is)\b(class|id)\s*=\s*("([^"]*)"|'([^']*)'|([^\s"'<>]+))`)
var triageTitleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title\s*>`)

// TriageStructTokens is foundations 5.6, adapted from extractStructuralTokens (common.py:3295):
// strip script, style and comments, then collect the value-free tag, class and id skeleton. It is
// how a byte-unstable but structurally stable HTML page stays judgeable, and a results table
// appearing or disappearing still moves it.
func TriageStructTokens(body []byte) []string {
	if len(body) == 0 {
		return nil
	}
	clean := triageScriptRe.ReplaceAll(body, []byte(" "))
	set := make(map[string]bool)
	for _, m := range triageTagRe.FindAllSubmatch(clean, -1) {
		tag := strings.ToLower(string(m[1]))
		set["tag:"+tag] = true
		for _, a := range triageAttrRe.FindAllSubmatch(m[2], -1) {
			name := strings.ToLower(string(a[1]))
			val := string(a[3]) + string(a[4]) + string(a[5])
			for _, v := range strings.Fields(val) {
				switch name {
				case "class":
					set["cls:"+tag+"."+v] = true
				case "id":
					set["id:"+tag+"#"+v] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func triageTitle(body []byte) string {
	m := triageTitleRe.FindSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// triageJSONProj is the foundations 5.5 four-projection JSON model.
type triageJSONProj struct {
	Parsed  bool
	Keys    []string          // S1, sorted RFC 6901 pointers, array indices collapsed to []
	Types   []string          // S2, sorted "pointer=type"
	Cards   []string          // S3, sorted "pointer.__len__=N"
	Scalars map[string]string // S4, collapsed pointer to the LEXICAL token
	DupKeys bool
	Records int
	GQL     triageGraphQLFacts

	// The accumulators the walker fills. They live on the projection rather than in a parallel
	// structure so a partially walked document cannot be mistaken for a complete one.
	keySet  map[string]bool
	typeSet map[string]map[string]bool
	cardSet map[string]*triageCardAcc
}

// triageGraphQLFacts is the CATALOGUE 3.3 GraphQL rule made concrete. A GraphQL endpoint answers
// 200 for a syntax error and 200 for success, so status is useless and a byte ratio is dominated
// by the payload; the signal lives entirely in the shape.
type triageGraphQLFacts struct {
	Present       bool
	ErrorCount    int
	ExtensionCode []string
	MessageShape  []string
	DataNull      bool
}

func triageProjectJSON(body []byte) triageJSONProj {
	p := triageJSONProj{Scalars: map[string]string{}}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return p
	}
	if ok := triageWalkJSONDoc(trimmed, "", &p); ok {
		p.Parsed = true
		p.finish(body)
		return p
	}
	// NDJSON, JSON Lines and application/json-seq: parse per record; the shape is the union of the
	// per-record projections plus a record count.
	lines := bytes.Split(trimmed, []byte("\n"))
	if len(lines) < 2 {
		return p
	}
	n := 0
	for _, ln := range lines {
		ln = bytes.TrimSpace(bytes.TrimPrefix(ln, []byte{0x1e}))
		if len(ln) == 0 {
			continue
		}
		if !triageWalkJSONDoc(ln, "", &p) {
			return triageJSONProj{Scalars: map[string]string{}}
		}
		n++
	}
	if n == 0 {
		return triageJSONProj{Scalars: map[string]string{}}
	}
	p.Parsed = true
	p.Records = n
	p.finish(body)
	return p
}

func triageWalkJSONDoc(doc []byte, root string, p *triageJSONProj) bool {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	if err := triageWalkJSON(dec, root, p); err != nil {
		return false
	}
	// Reject trailing content, so a body that is "1 <html>" does not read as the number 1.
	if _, err := dec.Token(); err != io.EOF {
		return false
	}
	return true
}

type triageCardAcc struct {
	total int
	n     int
}

var triageCardsKey = "\x00cards"

func triageWalkJSON(dec *json.Decoder, ptr string, p *triageJSONProj) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	return triageWalkJSONValue(dec, ptr, tok, p)
}

func triageWalkJSONValue(dec *json.Decoder, ptr string, tok json.Token, p *triageJSONProj) error {
	p.addKey(ptr)
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			p.addType(ptr, "object")
			seen := map[string]bool{}
			for {
				kt, err := dec.Token()
				if err != nil {
					return err
				}
				if d, ok := kt.(json.Delim); ok && d == '}' {
					return nil
				}
				key, ok := kt.(string)
				if !ok {
					return fmt.Errorf("triage: object key was not a string")
				}
				if seen[key] {
					p.DupKeys = true
				}
				seen[key] = true
				vt, err := dec.Token()
				if err != nil {
					return err
				}
				if err := triageWalkJSONValue(dec, ptr+"/"+triagePointerEscape(key), vt, p); err != nil {
					return err
				}
			}
		case '[':
			p.addType(ptr, "array")
			n := 0
			for {
				vt, err := dec.Token()
				if err != nil {
					return err
				}
				if d, ok := vt.(json.Delim); ok && d == ']' {
					p.addCard(ptr, n)
					return nil
				}
				if err := triageWalkJSONValue(dec, ptr+"[]", vt, p); err != nil {
					return err
				}
				n++
			}
		}
		return fmt.Errorf("triage: unexpected delimiter %v", t)
	case string:
		p.addType(ptr, "string")
		p.addScalar(ptr, t)
	case json.Number:
		// THE LEXICAL TOKEN, not the parsed value. sqlmap's jsonMinimize stringifies the parsed
		// scalar, so 1e2, 100 and 100.0 all render as 100.0 and a precision change is invisible,
		// and a large integer round-tripped through a float64 loses its low digits outright. This
		// is a live defect there and we must not inherit it.
		p.addType(ptr, "number")
		p.addScalar(ptr, t.String())
	case bool:
		p.addType(ptr, "boolean")
		p.addScalar(ptr, strconv.FormatBool(t))
	case nil:
		p.addType(ptr, "null")
		p.addScalar(ptr, "null")
	}
	return nil
}

func (p *triageJSONProj) addKey(ptr string) {
	if p.keySet == nil {
		p.keySet = map[string]bool{}
	}
	p.keySet[ptr] = true
}

func (p *triageJSONProj) addType(ptr, typ string) {
	if p.typeSet == nil {
		p.typeSet = map[string]map[string]bool{}
	}
	if p.typeSet[ptr] == nil {
		p.typeSet[ptr] = map[string]bool{}
	}
	p.typeSet[ptr][typ] = true
}

func (p *triageJSONProj) addCard(ptr string, n int) {
	if p.cardSet == nil {
		p.cardSet = map[string]*triageCardAcc{}
	}
	acc := p.cardSet[ptr]
	if acc == nil {
		acc = &triageCardAcc{}
		p.cardSet[ptr] = acc
	}
	acc.total += n
	acc.n++
}

func (p *triageJSONProj) addScalar(ptr, val string) {
	if p.Scalars == nil {
		p.Scalars = map[string]string{}
	}
	if old, ok := p.Scalars[ptr]; ok {
		p.Scalars[ptr] = old + "\x1f" + val
		return
	}
	p.Scalars[ptr] = val
}

func (p *triageJSONProj) finish(raw []byte) {
	p.Keys = triageSortedKeys(p.keySet)
	for _, ptr := range triageSortedTypeKeys(p.typeSet) {
		types := triageSortedKeys(p.typeSet[ptr])
		p.Types = append(p.Types, ptr+"="+strings.Join(types, "|"))
	}
	for _, ptr := range triageSortedCardKeys(p.cardSet) {
		acc := p.cardSet[ptr]
		if acc.n == 1 {
			p.Cards = append(p.Cards, ptr+".__len__="+strconv.Itoa(acc.total))
			continue
		}
		// A collapsed pointer that occurred several times keeps both numbers, because a change in
		// how many arrays there are and a change in how long they are are different facts.
		p.Cards = append(p.Cards, ptr+".__len__sum="+strconv.Itoa(acc.total))
		p.Cards = append(p.Cards, ptr+".__len__n="+strconv.Itoa(acc.n))
	}
	if p.Records > 0 {
		p.Cards = append(p.Cards, "/__records__.__len__="+strconv.Itoa(p.Records))
	}
	sort.Strings(p.Cards)
	// Duplicate keys within one object mean the shape has lost information: RFC 8259 permits them
	// and parsers keep the last. Any value-level verdict on such a document is low confidence.
	p.GQL = triageGraphQLFactsFrom(p)
}

func triageGraphQLFactsFrom(p *triageJSONProj) triageGraphQLFacts {
	var f triageGraphQLFacts
	if !p.keySet["/data"] && !p.keySet["/errors"] {
		return f
	}
	f.Present = true
	if acc := p.cardSet["/errors"]; acc != nil {
		f.ErrorCount = acc.total
	}
	if v, ok := p.Scalars["/errors[]/extensions/code"]; ok {
		f.ExtensionCode = strings.Split(v, "\x1f")
		sort.Strings(f.ExtensionCode)
	}
	if v, ok := p.Scalars["/errors[]/message"]; ok {
		for _, m := range strings.Split(v, "\x1f") {
			f.MessageShape = append(f.MessageShape, triageClassifyMessage(m))
		}
		sort.Strings(f.MessageShape)
	}
	if t := p.typeSet["/data"]; t != nil && t["null"] {
		f.DataNull = true
	}
	return f
}

// triageClassifyMessage reduces an error message to a shape. GraphQL messages routinely embed the
// offending position and the offending token, so comparing them raw makes two instances of the
// same error look like two different errors.
func triageClassifyMessage(s string) string {
	var b strings.Builder
	prevDigit := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			if !prevDigit {
				b.WriteByte('#')
			}
			prevDigit = true
			continue
		}
		prevDigit = false
		b.WriteRune(r)
	}
	return b.String()
}

func triagePointerEscape(k string) string {
	k = strings.ReplaceAll(k, "~", "~0")
	return strings.ReplaceAll(k, "/", "~1")
}

func triageSortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func triageSortedTypeKeys(m map[string]map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func triageSortedCardKeys(m map[string]*triageCardAcc) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ShapeDiff is foundations 5.5's structured diff. It is a diff and not a ratio because "the shape
// changed" and "a value changed" are different facts.
type ShapeDiff struct {
	KeysAdded    []string
	KeysRemoved  []string
	TypesChanged []string
	LensChanged  []string
	ValsChanged  []string
	// VolatileHit lists pointers that changed but are volatile. It is the JSON analogue of
	// masked_only and exists for the same reason: nothing is silently dropped.
	VolatileHit []string
	DupJSONKeys bool
	GQLChanged  []string
}

// Empty reports whether the two shapes agreed on everything that is not volatile.
func (s ShapeDiff) Empty() bool {
	return len(s.KeysAdded) == 0 && len(s.KeysRemoved) == 0 && len(s.TypesChanged) == 0 &&
		len(s.LensChanged) == 0 && len(s.ValsChanged) == 0 && len(s.GQLChanged) == 0
}

func triageShapeDiff(base, probe triageJSONProj, volatile map[string]bool) ShapeDiff {
	var d ShapeDiff
	d.DupJSONKeys = base.DupKeys || probe.DupKeys
	bk := triageStringSet(base.Keys)
	pk := triageStringSet(probe.Keys)
	for _, k := range probe.Keys {
		if !bk[k] {
			d.KeysAdded = append(d.KeysAdded, k)
		}
	}
	for _, k := range base.Keys {
		if !pk[k] {
			d.KeysRemoved = append(d.KeysRemoved, k)
		}
	}
	d.TypesChanged = triageLineDiff(base.Types, probe.Types)
	d.LensChanged = triageLineDiff(base.Cards, probe.Cards)
	for ptr, bv := range base.Scalars {
		pv, ok := probe.Scalars[ptr]
		if !ok || pv == bv {
			continue
		}
		if volatile[ptr] {
			d.VolatileHit = append(d.VolatileHit, ptr)
			continue
		}
		d.ValsChanged = append(d.ValsChanged, ptr)
	}
	sort.Strings(d.ValsChanged)
	sort.Strings(d.VolatileHit)
	if base.GQL.Present || probe.GQL.Present {
		if base.GQL.ErrorCount != probe.GQL.ErrorCount {
			d.GQLChanged = append(d.GQLChanged, fmt.Sprintf("errors.__len__ %d -> %d", base.GQL.ErrorCount, probe.GQL.ErrorCount))
		}
		if strings.Join(base.GQL.ExtensionCode, ",") != strings.Join(probe.GQL.ExtensionCode, ",") {
			d.GQLChanged = append(d.GQLChanged, "errors[].extensions.code changed")
		}
		if strings.Join(base.GQL.MessageShape, ",") != strings.Join(probe.GQL.MessageShape, ",") {
			d.GQLChanged = append(d.GQLChanged, "errors[].message shape changed")
		}
		if base.GQL.DataNull != probe.GQL.DataNull {
			d.GQLChanged = append(d.GQLChanged, "data null flipped")
		}
	}
	return d
}

func triageStringSet(in []string) map[string]bool {
	m := make(map[string]bool, len(in))
	for _, s := range in {
		m[s] = true
	}
	return m
}

func triageLineDiff(a, b []string) []string {
	as, bs := triageStringSet(a), triageStringSet(b)
	var out []string
	for _, s := range b {
		if !as[s] {
			out = append(out, "+"+s)
		}
	}
	for _, s := range a {
		if !bs[s] {
			out = append(out, "-"+s)
		}
	}
	sort.Strings(out)
	return out
}

// TriageProject fills the derived projections on an observation. It deliberately does NOT touch
// ErrorSigs, MarkerHits or Placements: the signature catalogue and the reflection classifier are
// owned elsewhere, and overwriting them here would make this file the silent owner of a verdict.
//
// NormBody is computed against the markings, which are learned from the baseline, so a probe
// captured before the model was complete has the wrong NormBody. Pass the markings once the
// post-baseline has landed and call this again; ProjVersion carries a hash of the marking set so a
// projection computed against a stale map is detectable.
func TriageProject(o *triage.Observation, markings []TriageMarking) {
	norm, _, _ := TriageApplyMarkings(o.Body, markings)
	o.Proj.NormBody = norm
	o.Proj.NormBodySHA256 = sha256.Sum256(norm)
	o.Proj.Title = triageTitle(o.Body)
	o.Proj.StructTokens = TriageStructTokens(o.Body)
	o.Proj.StructSHA256 = sha256.Sum256([]byte(strings.Join(o.Proj.StructTokens, "\n")))
	jp := triageProjectJSON(o.Body)
	o.Proj.JSONParsed = jp.Parsed
	o.Proj.JSONKeySet = jp.Keys
	o.Proj.JSONTypeMap = jp.Types
	o.Proj.JSONCards = jp.Cards
	o.Proj.DupJSONKeys = jp.DupKeys
	o.Proj.JSONScalars = triageScalarLines(jp.Scalars, nil)
	o.ProjVersion = "triageCompare/1+" + triageMarkingsHash(markings)
}

func triageScalarLines(m map[string]string, volatile map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k, v := range m {
		if volatile[k] {
			continue
		}
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out
}

func triageMarkingsHash(ms []TriageMarking) string {
	h := sha256.New()
	for _, m := range ms {
		h.Write(m.Prefix)
		h.Write([]byte{0})
		h.Write(m.Suffix)
		h.Write([]byte{0})
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:6])
}

// ---------------------------------------------------------------------------------------------
// 6. HEADERS
// ---------------------------------------------------------------------------------------------

// triageSeedVolatileHeaders is CATALOGUE 3.3's seed list: headers known to vary that may happen to
// be constant across a short baseline window, so the learner would miss them. It is SECONDARY to
// the learned set and every entry is justified in the table there. Everything not listed here is
// compared, including every unknown X- header, because a new header appearing is one of the
// cleanest protocol-level signals available.
var triageSeedVolatileHeaders = map[string]bool{
	"date": true, "age": true, "expires": true, "set-cookie": true,
	"etag": true, "last-modified": true, "content-length": true,
	"connection": true, "keep-alive": true, "transfer-encoding": true,
	"x-request-id": true, "x-correlation-id": true, "x-trace-id": true,
	"traceparent": true, "tracestate": true, "x-amzn-requestid": true,
	"x-amz-cf-id": true, "x-amz-request-id": true, "cf-ray": true,
	"x-served-by": true, "x-cache": true, "x-cache-hits": true, "x-timer": true,
	"x-runtime": true, "server-timing": true, "via": true, "retry-after": true,
}

func triageSeedVolatile(name string) bool {
	n := strings.ToLower(name)
	if triageSeedVolatileHeaders[n] {
		return true
	}
	return strings.HasPrefix(n, "ratelimit-") || strings.HasPrefix(n, "x-ratelimit-")
}

func triageHeaderMap(h [][2]string) map[string]string {
	m := map[string][]string{}
	for _, kv := range h {
		n := strings.ToLower(strings.TrimSpace(kv[0]))
		m[n] = append(m[n], kv[1])
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		sort.Strings(v)
		out[k] = strings.Join(v, "\x1f")
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// 7. THE BASELINE
// ---------------------------------------------------------------------------------------------

// NonIdempotentReport is foundations 5.10. Its zero value claims nothing.
type NonIdempotentReport struct {
	Detected   bool
	CreatesRow bool
	Reasons    []string
	// SamplesAllowed is 2 for a non-idempotent vector and 5 otherwise. Taking five samples of a
	// POST that creates a row creates five rows, and the non-destructive rule is not negotiable.
	SamplesAllowed int
	// RequiresABA says a differential on this vector counts only when bracketed by two baselines
	// that agree with each other after masking.
	RequiresABA bool
	// NeverReplay is set for DELETE, which is never replayed at all.
	NeverReplay bool
}

// TriageBaseline is the measured noise model for one slot. It is derived ONLY from unperturbed
// samples, which is why it is the one thing every class may share.
type TriageBaseline struct {
	Model triage.BaselineModel

	Gate       GateVerdict
	GateDetail string

	Markings           []TriageMarking
	MaskedFraction     float64
	DistinctNormalised int
	StatusCounts       map[int]int
	Threshold          float64

	// ClockUnproven is foundations 5.1: the spacing was honoured and still no byte of the body
	// changed, so we never saw a one-second clock tick. On such an endpoint a probe whose only
	// difference is confined to digit-bearing runs is masked_only, not different.
	ClockUnproven bool
	NoBody        bool

	SpanMillis      int64
	MaxGapMillis    int64
	SpacingHonoured bool

	BodyLenMin int
	BodyLenMax int

	Template     triage.Observation
	TemplateNorm []byte
	TemplateJSON triageJSONProj
	StructTokens []string

	VolatilePointers map[string]bool
	HeaderVolatile   map[string]bool
	SeedSuppressed   map[string]string

	NonIdempotent NonIdempotentReport

	// MatchIncomplete means the matching-block search ran out of budget, so the marking set may be
	// short. It degrades every comparison against this baseline rather than being ignored: a short
	// marking set reads as a stable endpoint, which is the wrong direction to fail.
	MatchIncomplete bool

	// Remeasured holds the first, failed measurement when the gate was retried. foundations 5.7
	// allows exactly one re-measurement and requires both sets to be recorded.
	Remeasured *TriageBaseline

	holeAlphabet []map[byte]bool
	// holeLenMin and holeLenMax are the length range each marking's content took across the
	// WHOLE baseline, parallel to holeAlphabet and learned the same way. The alphabet says what
	// bytes the region may hold; these say how many, and triageMaskLengthRatio explains why the
	// second question has to be asked separately.
	holeLenMin []int
	holeLenMax []int
	// pointerAlphabet is the set of bytes each JSON scalar pointer took across the WHOLE
	// baseline, not just the template. Learning it from one sample would call a fresh
	// hexadecimal request id novel whenever the template's own id happened to miss a digit,
	// which turns a clean endpoint into a page of masked_only results at random.
	pointerAlphabet map[string]map[byte]bool
	sampleCount     int
}

// Judgeable is the single predicate a class asks before running a differential oracle.
func (b TriageBaseline) Judgeable() bool { return b.Gate.BytesJudgeable() }

// BaselineSchedule is the sampling plan. It exists as a value so the runner cannot quietly send
// five back-to-back requests: Validate refuses a plan that a one-second clock could sleep through.
type BaselineSchedule struct {
	Samples int
	Gaps    []time.Duration
}

// BaselineScheduleFor returns the plan for a vector. The spacing carries one gap above
// TriageBaselineMinGap so a one-second clock ticks at least once inside the window.
func BaselineScheduleFor(nonIdempotent bool) BaselineSchedule {
	if nonIdempotent {
		// Two samples, and the gap alone must span the clock, because there is no third sample to
		// spread the window over.
		return BaselineSchedule{Samples: TriageNonIdempotentSamples, Gaps: []time.Duration{TriageBaselineMinSpan + 100*time.Millisecond}}
	}
	return BaselineSchedule{
		Samples: TriageBaselineSamples,
		Gaps: []time.Duration{
			300 * time.Millisecond,
			TriageBaselineMinGap + 100*time.Millisecond,
			400 * time.Millisecond,
			500 * time.Millisecond,
		},
	}
}

// Validate refuses a schedule that cannot observe a slow clock.
func (s BaselineSchedule) Validate() error {
	if s.Samples < 2 {
		return fmt.Errorf("triage: a baseline of %d samples buys no differential, and sample 2 is the whole of the noise model", s.Samples)
	}
	if len(s.Gaps) != s.Samples-1 {
		return fmt.Errorf("triage: %d samples need %d gaps, got %d", s.Samples, s.Samples-1, len(s.Gaps))
	}
	var span time.Duration
	var maxGap time.Duration
	for _, g := range s.Gaps {
		span += g
		if g > maxGap {
			maxGap = g
		}
	}
	if span < TriageBaselineMinSpan {
		return fmt.Errorf("triage: baseline span %v is under %v, so a one-second clock can sleep through the whole window and the learner records it as invariant", span, TriageBaselineMinSpan)
	}
	if maxGap < TriageBaselineMinGap {
		return fmt.Errorf("triage: largest inter-sample gap %v is under %v, so no single gap is wide enough to guarantee a tick", maxGap, TriageBaselineMinGap)
	}
	return nil
}

// DetectNonIdempotent is foundations 5.10's detection, from the capture and the samples alone.
func DetectNonIdempotent(method string, samples []triage.Observation) NonIdempotentReport {
	r := NonIdempotentReport{SamplesAllowed: TriageBaselineSamples}
	m := strings.ToUpper(strings.TrimSpace(method))
	switch m {
	case "GET", "HEAD", "OPTIONS":
	case "":
		r.Detected = true
		r.Reasons = append(r.Reasons, "verb_unknown")
	default:
		r.Detected = true
		r.Reasons = append(r.Reasons, "verb_"+strings.ToLower(m))
	}
	if m == "DELETE" {
		r.NeverReplay = true
	}
	for _, o := range samples {
		if o.Status == 201 {
			r.Detected = true
			r.CreatesRow = true
			r.Reasons = append(r.Reasons, "status_201")
			break
		}
	}
	for _, o := range samples {
		if o.Status >= 300 && o.Status < 400 {
			continue
		}
		for _, kv := range o.RespHeaders {
			if strings.EqualFold(kv[0], "location") {
				r.Detected = true
				r.CreatesRow = true
				r.Reasons = append(r.Reasons, "location_on_non_redirect")
				break
			}
		}
	}
	if triageMonotone(samples) {
		r.Detected = true
		r.CreatesRow = true
		r.Reasons = append(r.Reasons, "monotone_counter_in_response")
	}
	if r.Detected {
		r.SamplesAllowed = TriageNonIdempotentSamples
	}
	if r.CreatesRow {
		r.RequiresABA = true
	}
	sort.Strings(r.Reasons)
	return r
}

// triageMonotone looks for an array length or a numeric scalar that strictly increases across the
// samples. A growing counter is LEARNED, not masked away: it is what tells us the endpoint writes.
func triageMonotone(samples []triage.Observation) bool {
	if len(samples) < 3 {
		return false
	}
	projs := make([]triageJSONProj, len(samples))
	for i, o := range samples {
		projs[i] = triageProjectJSON(o.Body)
		if !projs[i].Parsed {
			return false
		}
	}
	for ptr, first := range projs[0].Scalars {
		prev, err := strconv.ParseFloat(first, 64)
		if err != nil {
			continue
		}
		rising := true
		for _, p := range projs[1:] {
			v, ok := p.Scalars[ptr]
			if !ok {
				rising = false
				break
			}
			cur, err := strconv.ParseFloat(v, 64)
			if err != nil || cur <= prev {
				rising = false
				break
			}
			prev = cur
		}
		if rising {
			return true
		}
	}
	return false
}

// BuildTriageBaseline learns the noise model and runs the stability gate. post may be nil, in
// which case drift is UNMEASURED and the gate says so: a missing post-baseline is not a passing
// one.
func BuildTriageBaseline(samples []triage.Observation, post *triage.Observation) TriageBaseline {
	b := TriageBaseline{
		StatusCounts:     map[int]int{},
		VolatilePointers: map[string]bool{},
		HeaderVolatile:   map[string]bool{},
		SeedSuppressed:   map[string]string{},
		sampleCount:      len(samples),
	}
	b.Model.Samples = len(samples)
	if len(samples) == 0 {
		b.Gate = GateUnmeasured
		b.GateDetail = "no_baseline_samples"
		b.Model.GateReason = b.GateDetail
		return b
	}
	b.Template = samples[0]
	method := samples[0].ReqMethod
	b.NonIdempotent = DetectNonIdempotent(method, samples)

	for _, o := range samples {
		b.StatusCounts[o.Status]++
		b.Model.TimingNanos = append(b.Model.TimingNanos, o.TTFB)
	}

	b.SpanMillis, b.MaxGapMillis, b.SpacingHonoured = TriageObservedSpacing(samples)

	// Transport refusals are could-not-send, never a quiet response.
	for _, o := range samples {
		if !o.Delivered() {
			b.Gate = GateUnmeasured
			b.GateDetail = "baseline_transport_" + string(o.TransportErr)
			b.Model.GateReason = b.GateDetail
			return b
		}
	}

	bodies := make([][]byte, len(samples))
	allEmpty := true
	b.BodyLenMin, b.BodyLenMax = samples[0].BodyLen, samples[0].BodyLen
	for i, o := range samples {
		bodies[i] = o.Body
		if o.BodyLen < b.BodyLenMin {
			b.BodyLenMin = o.BodyLen
		}
		if o.BodyLen > b.BodyLenMax {
			b.BodyLenMax = o.BodyLen
		}
		if len(o.Body) > 0 {
			allEmpty = false
		}
		if o.BodyTruncated || o.BodyLen > triageDegradeBytes {
			b.Model.Degraded = true
		}
	}
	b.NoBody = allEmpty

	if len(samples) >= 2 && !allEmpty {
		var complete bool
		b.Markings, complete = TriageLearnMarkings(bodies)
		b.MatchIncomplete = !complete
	}
	b.Model.VolatileRegions = nil

	// Normalise every sample and measure what the masking cost.
	norms := make([][]byte, len(samples))
	holeContents := make([][]string, len(samples))
	var maskedSum float64
	for i, o := range samples {
		n, holes, contents := TriageApplyMarkings(o.Body, b.Markings)
		norms[i] = n
		holeContents[i] = contents
		if i == 0 {
			b.Model.VolatileRegions = holes
		}
		if len(o.Body) > 0 {
			var removed int
			for _, h := range holes {
				removed += h.Length
			}
			maskedSum += float64(removed) / float64(len(o.Body))
		}
	}
	if len(samples) > 0 {
		b.MaskedFraction = maskedSum / float64(len(samples))
	}
	b.TemplateNorm = norms[0]

	// The alphabet each hole took across the baseline. It is what lets a changed masked region be
	// told apart from a masked region carrying something this endpoint has never produced.
	b.holeAlphabet = make([]map[byte]bool, len(b.Markings))
	b.holeLenMin = make([]int, len(b.Markings))
	b.holeLenMax = make([]int, len(b.Markings))
	for mi := range b.Markings {
		alpha := map[byte]bool{}
		lo, hi := -1, 0
		for si := range samples {
			if mi >= len(holeContents[si]) {
				continue
			}
			c := holeContents[si][mi]
			for i := 0; i < len(c); i++ {
				alpha[c[i]] = true
			}
			// A sample the marking did not match contributes a length of 0, which is the honest
			// reading: this endpoint was observed with nothing in that region, so nothing in
			// that region is attested and a probe that empties it is not news.
			if lo < 0 || len(c) < lo {
				lo = len(c)
			}
			if len(c) > hi {
				hi = len(c)
			}
		}
		if lo < 0 {
			lo = 0
		}
		b.holeAlphabet[mi] = alpha
		b.holeLenMin[mi] = lo
		b.holeLenMax[mi] = hi
	}

	distinct := map[string]bool{}
	for _, n := range norms {
		distinct[string(n)] = true
	}
	b.DistinctNormalised = len(distinct)

	// The clock. If, despite the spacing, no byte of the body changed across the whole window, we
	// never observed a slow clock tick and must say so.
	rawDistinct := map[string]bool{}
	for _, o := range samples {
		rawDistinct[string(o.Body)] = true
	}
	b.Model.ClockTick = len(rawDistinct) > 1
	b.ClockUnproven = !b.Model.ClockTick

	// Headers: learned first, seed second, and a seed exclusion that the learner found constant is
	// reported rather than dropped.
	b.HeaderVolatile, b.SeedSuppressed = triageLearnHeaders(samples)
	for h := range b.HeaderVolatile {
		b.Model.VolatileHeaders = append(b.Model.VolatileHeaders, h)
	}
	sort.Strings(b.Model.VolatileHeaders)
	b.Model.SeedSuppressed = b.SeedSuppressed

	// JSON shape, and the volatile pointers, which are excluded from S4 ONLY. A key that appears
	// and disappears across samples is not noise to be masked; it is an endpoint whose shape is
	// unstable, which is a gate condition and not an exclusion.
	projs := make([]triageJSONProj, len(samples))
	for i, o := range samples {
		projs[i] = triageProjectJSON(o.Body)
	}
	b.TemplateJSON = projs[0]
	b.pointerAlphabet = map[string]map[byte]bool{}
	for _, p := range projs {
		for ptr, v := range p.Scalars {
			alpha := b.pointerAlphabet[ptr]
			if alpha == nil {
				alpha = map[byte]bool{}
				b.pointerAlphabet[ptr] = alpha
			}
			for i := 0; i < len(v); i++ {
				alpha[v[i]] = true
			}
		}
	}
	if projs[0].Parsed {
		for ptr, v := range projs[0].Scalars {
			for _, p := range projs[1:] {
				if pv, ok := p.Scalars[ptr]; !ok || pv != v {
					b.VolatilePointers[ptr] = true
					break
				}
			}
		}
	}
	for p := range b.VolatilePointers {
		b.Model.VolatileJSONPtr = append(b.Model.VolatileJSONPtr, p)
	}
	sort.Strings(b.Model.VolatileJSONPtr)
	b.StructTokens = TriageStructTokens(samples[0].Body)

	// The measured threshold. sqlmap latches kb.matchRatio from whichever response arrived first,
	// so the same probe set in a different order can give a different verdict. This is
	// order-independent and comes from data we already have.
	b.Model.RFloor, b.Model.RMAD = triagePairwiseFloor(norms)
	b.Threshold = triageClamp(b.Model.RFloor-3*b.Model.RMAD, triageRatioLowerBound, triageRatioUpperBound)

	b.Gate, b.GateDetail = triageStabilityGate(&b, samples, projs, post)
	b.Model.Stable = b.Gate == GateJudgeable
	b.Model.GateReason = b.GateDetail
	return b
}

// TriageObservedSpacing measures the window the samples actually covered. It reads SentAt, the
// wall clock, because the question is whether a one-second clock on the TARGET could have ticked.
func TriageObservedSpacing(samples []triage.Observation) (spanMillis, maxGapMillis int64, honoured bool) {
	if len(samples) < 2 {
		return 0, 0, false
	}
	times := make([]time.Time, 0, len(samples))
	for _, o := range samples {
		if o.SentAt.IsZero() {
			return 0, 0, false
		}
		times = append(times, o.SentAt)
	}
	sort.Slice(times, func(i, j int) bool { return times[i].Before(times[j]) })
	span := times[len(times)-1].Sub(times[0])
	var maxGap time.Duration
	for i := 1; i < len(times); i++ {
		if g := times[i].Sub(times[i-1]); g > maxGap {
			maxGap = g
		}
	}
	return span.Milliseconds(), maxGap.Milliseconds(),
		span >= TriageBaselineMinSpan && maxGap >= TriageBaselineMinGap
}

func triageLearnHeaders(samples []triage.Observation) (map[string]bool, map[string]string) {
	volatile := map[string]bool{}
	suppressed := map[string]string{}
	first := triageHeaderMap(samples[0].RespHeaders)
	names := map[string]bool{}
	maps := make([]map[string]string, len(samples))
	for i, o := range samples {
		maps[i] = triageHeaderMap(o.RespHeaders)
		for n := range maps[i] {
			names[n] = true
		}
	}
	for n := range names {
		constant := true
		for _, m := range maps {
			if m[n] != first[n] {
				constant = false
				break
			}
		}
		if !constant {
			volatile[n] = true
			continue
		}
		if triageSeedVolatile(n) {
			// Excluded by the seed list but measured constant. Report it with its value, so a
			// clean result with one interesting suppressed header is still visible.
			suppressed[n] = first[n]
		}
	}
	return volatile, suppressed
}

// triagePairwiseFloor computes the floor and the median absolute deviation over all C(n,2) pairs
// of normalised bodies.
func triagePairwiseFloor(norms [][]byte) (float64, float64) {
	if len(norms) < 2 {
		return 0, 0
	}
	var mins []float64
	for i := 0; i < len(norms); i++ {
		for j := i + 1; j < len(norms); j++ {
			rb := triageBagRatio(norms[i], norms[j])
			rs := triageShingleRatio(norms[i], norms[j])
			mins = append(mins, math.Min(rb, rs))
		}
	}
	floor := mins[0]
	for _, v := range mins {
		if v < floor {
			floor = v
		}
	}
	return floor, triageMAD(mins)
}

func triageMAD(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	med := triageMedian(vals)
	devs := make([]float64, len(vals))
	for i, v := range vals {
		devs[i] = math.Abs(v - med)
	}
	return triageMedian(devs)
}

func triageMedian(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	s := append([]float64(nil), vals...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

func triageClamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// triageStabilityGate is foundations 5.7, exactly.
//
//	G1  every baseline sample has the SAME status                 else -> status_flap
//	G2  r_floor on normalised bodies >= 0.90                      else -> G2'
//	G2' JSON on every sample and S1, S2, S3 byte-identical, or
//	    HTML and StructTokens identical                           -> judgeable_shape_only
//	G3  masked_fraction <= 0.35                                   else -> too_volatile
//	G4  MediaType identical across all samples                    else -> too_volatile
//	G5  the post-baseline satisfies G1-G4 against the pre         else -> drifted
func triageStabilityGate(b *TriageBaseline, samples []triage.Observation, projs []triageJSONProj, post *triage.Observation) (GateVerdict, string) {
	if len(samples) < 2 {
		return GateUnmeasured, "insufficient_baseline_samples"
	}
	// G1
	if len(b.StatusCounts) > 1 {
		return GateStatusFlap, "status_flap " + triageStatusMultiset(b.StatusCounts)
	}
	// G2 / G2'
	if b.Model.RFloor < triageGateRFloorMin {
		if shape, why := triageShapeStable(samples, projs); shape {
			// Still subject to G4: a media type that flaps makes even the shape meaningless.
			if !triageMediaStable(samples) {
				return GateTooVolatile, "media_type_flap"
			}
			if post != nil {
				if v, d := triageDriftCheck(b, *post); v != "" {
					return v, d
				}
			}
			return GateJudgeableShapeOnly, why
		}
		return GateTooVolatile, fmt.Sprintf("r_floor %.4f below %.2f and no stable shape", b.Model.RFloor, triageGateRFloorMin)
	}
	// G3
	if b.MaskedFraction > triageGateMaskedMax {
		return GateTooVolatile, fmt.Sprintf("masked_fraction %.3f above %.2f", b.MaskedFraction, triageGateMaskedMax)
	}
	// G4
	if !triageMediaStable(samples) {
		return GateTooVolatile, "media_type_flap"
	}
	// G5
	if post != nil {
		if v, d := triageDriftCheck(b, *post); v != "" {
			return v, d
		}
	}
	return GateJudgeable, ""
}

func triageStatusMultiset(counts map[int]int) string {
	keys := make([]int, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d:%d", k, counts[k]))
	}
	return "{" + strings.Join(parts, ", ") + "}"
}

func triageShapeStable(samples []triage.Observation, projs []triageJSONProj) (bool, string) {
	allJSON := true
	for _, p := range projs {
		if !p.Parsed {
			allJSON = false
			break
		}
	}
	if allJSON {
		k := strings.Join(projs[0].Keys, "\n")
		t := strings.Join(projs[0].Types, "\n")
		c := strings.Join(projs[0].Cards, "\n")
		for _, p := range projs[1:] {
			if strings.Join(p.Keys, "\n") != k || strings.Join(p.Types, "\n") != t || strings.Join(p.Cards, "\n") != c {
				return false, ""
			}
		}
		return true, "json_shape_stable"
	}
	first := TriageStructTokens(samples[0].Body)
	if len(first) == 0 {
		return false, ""
	}
	joined := strings.Join(first, "\n")
	for _, o := range samples[1:] {
		if strings.Join(TriageStructTokens(o.Body), "\n") != joined {
			return false, ""
		}
	}
	return true, "html_structure_stable"
}

func triageMediaStable(samples []triage.Observation) bool {
	mt := samples[0].MediaType
	for _, o := range samples[1:] {
		if o.MediaType != mt {
			return false
		}
	}
	return true
}

// triageDriftCheck is G5 and foundations 5.9. A closing baseline that no longer matches the
// opening one means the endpoint changed under us, and every differential taken in that window is
// cannot_determine (drift). Not clean, not unstable. Without it the run produces a page of
// confident false positives and, on the next run, a page of confident clean results.
func triageDriftCheck(b *TriageBaseline, post triage.Observation) (GateVerdict, string) {
	if !post.Delivered() {
		return GateDrifted, "post_baseline_transport_" + string(post.TransportErr)
	}
	if b.StatusCounts[post.Status] == 0 {
		return GateDrifted, fmt.Sprintf("post_baseline_status %d not in %s", post.Status, triageStatusMultiset(b.StatusCounts))
	}
	if post.MediaType != b.Template.MediaType {
		return GateDrifted, "post_baseline_media_type"
	}
	norm, _, _ := TriageApplyMarkings(post.Body, b.Markings)
	r := math.Min(triageBagRatio(b.TemplateNorm, norm), triageShingleRatio(b.TemplateNorm, norm))
	if r < b.Model.RFloor {
		return GateDrifted, fmt.Sprintf("post_baseline_similarity %.4f below measured floor %.4f", r, b.Model.RFloor)
	}
	return "", ""
}

// GateNeedsRemeasurement reports whether foundations 5.7's single retry applies. Transient load
// produces spurious flaps, so a failed gate is re-measured once with five fresh samples after a
// five second pause. The second failure is final.
func GateNeedsRemeasurement(b TriageBaseline) bool {
	if b.Remeasured != nil {
		return false
	}
	switch b.Gate {
	case GateJudgeable, GateJudgeableShapeOnly:
		return false
	default:
		return true
	}
}

// CombineRemeasurement keeps both measurement sets, as the retry rule requires. The second
// measurement stands, and the first hangs off it so the report can show what changed.
func CombineRemeasurement(first, second TriageBaseline) TriageBaseline {
	out := second
	f := first
	out.Remeasured = &f
	return out
}

// ---------------------------------------------------------------------------------------------
// 8. THE COMPARISON
// ---------------------------------------------------------------------------------------------

// ByteRange is a span of the normalised body.
type ByteRange struct {
	Offset int
	Length int
}

// MaskedHit is one masked region whose content changed for this probe. It carries the before and
// after so the operator can see what the mask swallowed: "this endpoint varies here anyway, but it
// varied differently for this probe".
type MaskedHit struct {
	Marking  int
	Range    ByteRange
	Baseline string
	Probe    string
	// NovelBytes is true when the probe's content for this region contains bytes the region never
	// held across the whole baseline. That is the trigger for masked_only rather than same, and it
	// is a measured property rather than a threshold someone picked.
	NovelBytes bool
	// LenUnattested is true when the probe's content for this region is outside the LENGTH range
	// the region was observed to take across the baseline, by more than triageMaskLengthRatio.
	LenUnattested bool
	LenDetail     string
}

// CompareResult is the full comparison. Every ratio, diff and verdict in it is COMPUTED and never
// stored on an observation, because all of them are functions of two observations and a model, and
// all of them must change when the model does.
type CompareResult struct {
	Verdict  DiffVerdict
	Reason   string
	Channels []ChannelResult

	RBag      float64
	RShingle  float64
	RFloor    float64
	Threshold float64

	Degraded    bool
	DegradedWhy string
	// MaxState caps what the owning class may claim from this comparison. A degraded comparison
	// caps at suspicious and can never produce clean.
	MaxState triage.TriageState

	// PayloadUnproven is set when the probe cannot show that the bytes its class asked for were
	// still in the request when it left. See the block in CompareToBaseline.
	PayloadUnproven    bool
	PayloadUnprovenWhy string

	Shape       ShapeDiff
	ShapeUsable bool

	MaskedHits     []MaskedHit
	ChangedRegions []ByteRange

	RemovedMarkerBytes int
	RemovedEchoBytes   int

	Gate GateVerdict
}

// IsUnknown fails closed.
func (c CompareResult) IsUnknown() bool { return c.Verdict.IsUnknown() }

// CountsAsClean is the ONLY route to clean. A degraded comparison, a closed gate and every unknown
// verdict all answer false here, so a renderer, a sorter, an exporter and a filter cannot disagree
// about what clean means.
func (c CompareResult) CountsAsClean() bool {
	if c.Degraded || c.PayloadUnproven || !c.Verdict.CountsAsSame() {
		return false
	}
	return c.Gate.BytesJudgeable() || c.Gate.ShapeJudgeable()
}

// State is the state the owning class starts from. It never returns StateFinding: only the class's
// own oracle can do that.
func (c CompareResult) State() triage.TriageState {
	s := c.Verdict.TriageState()
	if c.Degraded && s == triage.StateClean {
		return triage.StateCannotDetermine
	}
	if c.Degraded && s == triage.StateFinding {
		return triage.StateSuspicious
	}
	return s
}

// CompareToBaseline is the comparator. It never sends a request and never reads a perturbed
// response belonging to another class: probe is the caller's own observation.
func CompareToBaseline(b TriageBaseline, probe triage.Observation) CompareResult {
	res := CompareResult{
		Gate:      b.Gate,
		RFloor:    b.Model.RFloor,
		Threshold: b.Threshold,
		MaxState:  triage.StateFinding,
	}

	// ---- THE FIDELITY FLAG IS COMPUTED BEFORE ANY EARLY RETURN
	//
	// PayloadUnproven is a property of the PROBE, not of the route this function took. It used to
	// be set in the fidelity block far below, which meant the two branches that return ahead of
	// that block produced a CompareResult whose flag was false about a probe that plainly had not
	// proven anything.
	//
	// The measured one: a payload REFUSED by the transport is refused at send time. "net/http:
	// invalid header field value" on a NUL byte sets both WireSurvivalRefused and
	// TransportInvalidHeader on the same probe, so !Delivered() returned first and left the flag
	// false. A classifier keying on res.PayloadUnproven alone therefore missed refused, while the
	// store's one definition of unproven (triageUnprovenFidelity: survived NOT IN
	// ('intact','encoded')) counted it. Two layers, one probe, two answers.
	//
	// The zero value is UNKNOWN, not intact. A probe that never measured its own survival is
	// indistinguishable after the fact from one that was mangled, so it is flagged too.
	if !probe.Payload.Survived.Proven() {
		res.PayloadUnproven = true
		res.PayloadUnprovenWhy = triagePayloadUnprovenReason(probe.Payload)
	}

	if !probe.Delivered() {
		// A transport refusal is could-not-send. It is never a quiet response, and in particular
		// "net/http: invalid header field value" on a NUL byte is a loud error the probe records
		// rather than a defended application.
		//
		// The transport names the more specific failure, so its reason is what the operator
		// reads. The flag set above is ADDITIVE and rides along with it.
		res.Verdict = DiffUnusable
		res.Reason = "transport_" + string(probe.TransportErr)
		res.MaxState = triage.StateCannotDetermine
		return res
	}
	switch b.Gate {
	case GateJudgeable, GateJudgeableShapeOnly:
	default:
		res.Verdict = DiffUnusable
		res.Reason = b.Gate.Reason()
		res.MaxState = triage.StateCannotDetermine
		return res
	}

	if b.Model.Degraded || probe.BodyTruncated || probe.BodyLen > triageDegradeBytes || b.MatchIncomplete {
		res.Degraded = true
		switch {
		case b.MatchIncomplete:
			res.DegradedWhy = "matching_block_budget_exhausted"
		case probe.BodyTruncated || b.Model.Degraded:
			res.DegradedWhy = "body_truncated_or_oversized"
		default:
			res.DegradedWhy = "body_over_diff_limit"
		}
		res.MaxState = triage.StateSuspicious
	}

	// ---- THE PAYLOAD MUST BE PROVEN TO HAVE REACHED THE WIRE
	//
	// Delivered() above is a TRANSPORT fact: the request went out and a response came back. It
	// says nothing about whether the bytes this class asked for were still inside that request
	// when it left, and those are different questions with different failure modes.
	//
	// The measured one: Go's net/http Cookie writer silently drops the semicolon, the double
	// quote and the backslash from a cookie value, and those are the SQL injection probe
	// characters. Such a probe is delivered perfectly, arrives carrying no payload, comes back
	// byte-identical to the baseline because nothing was ever tested, and this comparator finds
	// no difference. Reading that as clean is exactly the false negative WireSurvival was added
	// for: the class tested nothing, records clean, and the operator never comes back here.
	//
	// The FLAG is set at the top of this function so that the early returns carry it too. This
	// is where it CAPS, and it is deliberately after the degraded block: degraded sets MaxState
	// to suspicious, and an unproven payload is the stricter of the two, so it must have the
	// last word or a mangled probe on a truncated body would come back claiming suspicious.
	if res.PayloadUnproven {
		res.MaxState = triage.StateCannotDetermine
	}

	// ---- status
	statusVerdict := DiffSame
	statusDetail := ""
	if probe.Status != b.Template.Status {
		statusVerdict = DiffDifferent
		statusDetail = fmt.Sprintf("%d -> %d", b.Template.Status, probe.Status)
	}
	res.Channels = append(res.Channels, ChannelResult{Channel: ChanStatus, Verdict: statusVerdict, Detail: statusDetail})

	// ---- content type
	ctVerdict := DiffSame
	ctDetail := ""
	if probe.MediaType != b.Template.MediaType {
		ctVerdict = DiffDifferent
		ctDetail = string(b.Template.MediaType) + " -> " + string(probe.MediaType)
	}
	res.Channels = append(res.Channels, ChannelResult{Channel: ChanContentType, Verdict: ctVerdict, Detail: ctDetail})

	// ---- headers
	res.Channels = append(res.Channels, triageCompareHeaders(b, probe))

	// ---- cookies set
	res.Channels = append(res.Channels, triageCompareCookies(b, probe))

	// ---- redirect target
	res.Channels = append(res.Channels, triageCompareRedirect(b, probe))

	// ---- body, and the two ratios
	bodyCh, hits, changed, removedMarker, removedEcho, rbag, rshingle := triageCompareBody(b, probe)
	res.Channels = append(res.Channels, bodyCh)
	res.MaskedHits = hits
	res.ChangedRegions = changed
	res.RemovedMarkerBytes = removedMarker
	res.RemovedEchoBytes = removedEcho
	res.RBag = rbag
	res.RShingle = rshingle

	// ---- length, judged against the range the baseline itself covered
	//
	// A length outside that range is only a signal on an endpoint with no learned marking. Where
	// a marking exists the length moves with the volatile region by construction, so treating a
	// length change as a differential would report a trace id that got one byte longer as a
	// finding on every probe that followed it.
	lenVerdict := DiffSame
	lenDetail := fmt.Sprintf("%d..%d -> %d", b.BodyLenMin, b.BodyLenMax, probe.BodyLen)
	if probe.BodyLen < b.BodyLenMin || probe.BodyLen > b.BodyLenMax {
		if len(b.Markings) > 0 {
			lenVerdict = DiffUnusable
			lenDetail += " (length moves with the masked regions)"
		} else {
			lenVerdict = DiffDifferent
		}
	}
	res.Channels = append(res.Channels, ChannelResult{Channel: ChanLength, Verdict: lenVerdict, Detail: lenDetail})

	// ---- shape channels
	probeJSON := triageProjectJSON(probe.Body)
	res.Shape = triageShapeDiff(b.TemplateJSON, probeJSON, b.VolatilePointers)
	shape := res.Shape
	if b.TemplateJSON.Parsed && probeJSON.Parsed {
		res.ShapeUsable = true
		sv := DiffSame
		if !shape.Empty() {
			sv = DiffDifferent
		} else if len(shape.VolatileHit) > 0 && triageAnyNovelPointer(b, probeJSON, shape.VolatileHit) {
			sv = DiffMaskedOnly
		}
		detail := ""
		if shape.DupJSONKeys {
			detail = "duplicate_json_keys: value-level verdicts on this document are low confidence"
		}
		res.Channels = append(res.Channels, ChannelResult{Channel: ChanJSONShape, Verdict: sv, Detail: detail})
	} else if b.TemplateJSON.Parsed != probeJSON.Parsed {
		res.Channels = append(res.Channels, ChannelResult{
			Channel: ChanJSONShape,
			Verdict: DiffDifferent,
			Detail:  fmt.Sprintf("json parseability changed: %v -> %v", b.TemplateJSON.Parsed, probeJSON.Parsed),
		})
		res.ShapeUsable = true
	} else {
		res.Channels = append(res.Channels, ChannelResult{Channel: ChanJSONShape, Verdict: DiffUnusable, Detail: "not_json"})
	}

	if len(b.StructTokens) > 0 {
		pt := TriageStructTokens(probe.Body)
		sv := DiffSame
		var detail string
		if d := triageLineDiff(b.StructTokens, pt); len(d) > 0 {
			sv = DiffDifferent
			detail = strings.Join(d, " ")
		}
		res.Channels = append(res.Channels, ChannelResult{Channel: ChanHTMLStruct, Verdict: sv, Detail: detail})
	} else {
		res.Channels = append(res.Channels, ChannelResult{Channel: ChanHTMLStruct, Verdict: DiffUnusable, Detail: "no_html_structure"})
	}

	// ---- combine
	res.Verdict, res.Reason = triageCombine(b, res)
	if res.PayloadUnproven && (res.Verdict == DiffSame || res.Verdict.IsUnknown()) {
		// A difference is still a difference, and a masked_only or a reordered stands: something
		// changed and the operator should see it. What an unproven payload cannot produce is the
		// NEGATIVE. "Nothing changed" from a probe that may never have carried anything is not a
		// measurement of the application, so it becomes unusable with a reason that names why.
		res.Verdict = DiffUnusable
		res.Reason = res.PayloadUnprovenWhy
	}
	if res.Degraded && res.MaxState == triage.StateSuspicious && res.Verdict == DiffSame {
		// A degraded comparison that found nothing has not proven sameness. It stays same for the
		// report but CountsAsClean is false, so no aggregate can render it clean.
		res.Reason = "degraded:" + res.DegradedWhy
	}
	return res
}

// triagePayloadUnprovenReason names what happened to the payload, because a cannot_determine with
// no reason is the thing property 3 at the top of this file forbids.
func triagePayloadUnprovenReason(w triage.PayloadWire) string {
	by := ""
	if w.AlteredBy != "" {
		by = " (" + w.AlteredBy + ")"
	}
	switch w.Survived {
	case triage.WireSurvivalDropped:
		return "payload_unproven_dropped: the bytes this class asked for are not in the serialized request" + by +
			", so an identical response means nothing was tested"
	case triage.WireSurvivalRefused:
		return "payload_unproven_refused: the transport refused to send this payload" + by
	case triage.WireSurvivalAltered:
		return "payload_unproven_altered: something we did not ask for changed the payload on the way out" + by +
			", so what the application answered is not what this class asked"
	default:
		return "payload_unproven_unknown: this probe never recorded whether its payload reached the wire, and unknown is not intact"
	}
}

func triageCompareHeaders(b TriageBaseline, probe triage.Observation) ChannelResult {
	base := triageHeaderMap(b.Template.RespHeaders)
	cur := triageHeaderMap(probe.RespHeaders)
	names := map[string]bool{}
	for n := range base {
		names[n] = true
	}
	for n := range cur {
		names[n] = true
	}
	sorted := triageSortedKeys(names)
	var changed, excluded []string
	for _, n := range sorted {
		if b.HeaderVolatile[n] {
			excluded = append(excluded, "learned_volatile:"+n)
			continue
		}
		if triageSeedVolatile(n) {
			excluded = append(excluded, "seed_suppressed:"+n)
			continue
		}
		if base[n] != cur[n] {
			switch {
			case base[n] == "":
				changed = append(changed, "+"+n)
			case cur[n] == "":
				changed = append(changed, "-"+n)
			default:
				changed = append(changed, "~"+n)
			}
		}
	}
	v := DiffSame
	if len(changed) > 0 {
		v = DiffDifferent
	}
	return ChannelResult{Channel: ChanHeaders, Verdict: v, Detail: strings.Join(changed, " "), Excluded: excluded}
}

func triageCompareCookies(b TriageBaseline, probe triage.Observation) ChannelResult {
	// Names and attributes, never values: a session cookie rotating is the normal case and
	// Set-Cookie is on the seed-volatile list for exactly that reason. A NEW cookie, or a changed
	// attribute set, is a protocol-level signal.
	fold := func(cs []triage.CookieObs) []string {
		out := make([]string, 0, len(cs))
		for _, c := range cs {
			attrs := append([]string(nil), c.Attributes...)
			sort.Strings(attrs)
			out = append(out, c.Name+"["+strings.Join(attrs, ",")+"]")
		}
		sort.Strings(out)
		return out
	}
	d := triageLineDiff(fold(b.Template.SetCookies), fold(probe.SetCookies))
	v := DiffSame
	if len(d) > 0 {
		v = DiffDifferent
	}
	return ChannelResult{Channel: ChanCookies, Verdict: v, Detail: strings.Join(d, " ")}
}

func triageCompareRedirect(b TriageBaseline, probe triage.Observation) ChannelResult {
	loc := func(o triage.Observation) string {
		for _, kv := range o.RespHeaders {
			if strings.EqualFold(kv[0], "location") {
				return kv[1]
			}
		}
		return ""
	}
	chain := func(o triage.Observation) string {
		parts := make([]string, 0, len(o.RedirectChain))
		for _, h := range o.RedirectChain {
			parts = append(parts, fmt.Sprintf("%d>%s", h.Status, h.Location))
		}
		return strings.Join(parts, "|")
	}
	bl, pl := loc(b.Template), loc(probe)
	bc, pc := chain(b.Template), chain(probe)
	bf, pf := b.Template.FinalURL, probe.FinalURL
	if bl == pl && bc == pc && bf == pf {
		if bl == "" && bc == "" && bf == "" {
			return ChannelResult{Channel: ChanRedirect, Verdict: DiffUnusable, Detail: "no_redirect_observed"}
		}
		return ChannelResult{Channel: ChanRedirect, Verdict: DiffSame}
	}
	return ChannelResult{Channel: ChanRedirect, Verdict: DiffDifferent, Detail: fmt.Sprintf("location %q -> %q, final %q -> %q", bl, pl, bf, pf)}
}

// triageCompareBody is the byte channel. Marker forms and the echoed payload come off BOTH sides
// first, then the learned markings, then the two ratios.
func triageCompareBody(b TriageBaseline, probe triage.Observation) (ChannelResult, []MaskedHit, []ByteRange, int, int, float64, float64) {
	if b.NoBody && len(probe.Body) == 0 {
		// NOT "identical bodies, therefore same". There is nothing to compare.
		return ChannelResult{Channel: ChanBody, Verdict: DiffUnusable, Detail: "no_body"}, nil, nil, 0, 0, 0, 0
	}

	baseStripped, baseMarkerN := triageStripMarkerForms(b.Template.Body)
	probeStripped, probeMarkerN := triageStripMarkerForms(probe.Body)
	echoN := 0
	if len(probe.Payload.Wire) > 0 {
		if run := triageLongestCommonRun(probe.Payload.Wire, probeStripped, triageEchoMinRun); len(run) > 0 {
			var n1, n2 int
			probeStripped, n1 = triageRemoveAll(probeStripped, run)
			baseStripped, n2 = triageRemoveAll(baseStripped, run)
			echoN = n1 + n2
		}
	}

	baseNorm, _, baseHoles := TriageApplyMarkings(baseStripped, b.Markings)
	probeNorm, probeHoleRanges, probeHoles := TriageApplyMarkings(probeStripped, b.Markings)

	var hits []MaskedHit
	for mi := range b.Markings {
		if mi >= len(baseHoles) || mi >= len(probeHoles) {
			break
		}
		if baseHoles[mi] == probeHoles[mi] {
			continue
		}
		novel := false
		if mi < len(b.holeAlphabet) {
			for i := 0; i < len(probeHoles[mi]); i++ {
				if !b.holeAlphabet[mi][probeHoles[mi][i]] {
					novel = true
					break
				}
			}
		}
		// The length question, which the alphabet test above cannot ask. See
		// triageMaskLengthRatio: a region attests the bytes it was seen to hold, never how many
		// of them, and capacity is what a boolean oracle hides in.
		lenBad, lenWhy := false, ""
		if mi < len(b.holeLenMax) && mi < len(b.holeLenMin) {
			n := float64(len(probeHoles[mi]))
			lo, hi := float64(b.holeLenMin[mi]), float64(b.holeLenMax[mi])
			switch {
			case n > hi*triageMaskLengthRatio:
				lenBad = true
				lenWhy = fmt.Sprintf("%d bytes, and this region held at most %d across the baseline",
					len(probeHoles[mi]), b.holeLenMax[mi])
			case n*triageMaskLengthRatio < lo:
				lenBad = true
				if len(probeHoles[mi]) == 0 {
					lenWhy = fmt.Sprintf("the region is empty, and it held at least %d bytes in every baseline sample",
						b.holeLenMin[mi])
				} else {
					lenWhy = fmt.Sprintf("%d bytes, and this region held at least %d across the baseline",
						len(probeHoles[mi]), b.holeLenMin[mi])
				}
			}
		}
		rng := ByteRange{}
		if mi < len(probeHoleRanges) {
			rng = ByteRange{Offset: probeHoleRanges[mi].Offset, Length: probeHoleRanges[mi].Length}
		}
		hits = append(hits, MaskedHit{
			Marking: mi, Range: rng, Baseline: baseHoles[mi], Probe: probeHoles[mi],
			NovelBytes: novel, LenUnattested: lenBad, LenDetail: lenWhy,
		})
	}

	rbag := triageBagRatio(baseNorm, probeNorm)
	rshingle := triageShingleRatio(baseNorm, probeNorm)

	changed := triageChangedRegions(baseNorm, probeNorm)

	v, detail := triageDecideBody(b, baseNorm, probeNorm, rbag, rshingle, hits, changed)
	return ChannelResult{Channel: ChanBody, Verdict: v, Detail: detail}, hits, changed, baseMarkerN + probeMarkerN, echoN, rbag, rshingle
}

// triageDecideBody turns the two ratios and the masked hits into one body verdict.
func triageDecideBody(b TriageBaseline, baseNorm, probeNorm []byte, rbag, rshingle float64, hits []MaskedHit, changed []ByteRange) (DiffVerdict, string) {
	identical := bytes.Equal(baseNorm, probeNorm)

	if identical {
		// The normalised bodies agree. The only remaining question is whether the mask swallowed
		// something worth reporting.
		for _, h := range hits {
			if h.NovelBytes {
				return DiffMaskedOnly, fmt.Sprintf("marking %d carried bytes this region never held across the baseline: %q", h.Marking, h.Probe)
			}
		}
		// The alphabet may be fully attested and the region still be carrying something new,
		// because the alphabet says nothing about how much of it fits. See
		// triageMaskLengthRatio. Disappearance is the same test from the other side: absence has
		// no bytes to be novel, so the loop above passes it trivially.
		for _, h := range hits {
			if h.LenUnattested {
				return DiffMaskedOnly, fmt.Sprintf("marking %d is outside the length range this region was observed to take: %s", h.Marking, h.LenDetail)
			}
		}
		if b.MaskedFraction >= triageSingleMarkingMax {
			return DiffMaskedOnly, fmt.Sprintf("normalised bodies agree but %.0f%% of the body is masked, which is too much to call this clean", b.MaskedFraction*100)
		}
		return DiffSame, ""
	}

	// Reordering is tested BEFORE the clock rule. A bag ratio of exactly 1.0 with a shingle ratio
	// below it is a specific, strong statement: the same bytes came back in a different order.
	// The clock rule is a fallback for an endpoint that never proved its clock ticks, and letting
	// it swallow a reordering would lose the one signal quick_ratio alone already loses.
	if rbag >= 1.0 && rshingle < 1.0 {
		return DiffReordered, fmt.Sprintf("r_bag %.4f r_shingle %.4f", rbag, rshingle)
	}

	// THE CLOCK RULE, foundations 5.1. When nothing changed across the whole baseline window we
	// never saw a one-second clock tick, so a probe that differs only in digit-bearing runs
	// cannot be told apart from the clock finally ticking. It is masked_only, which is reportable
	// and is not clean. It costs nothing when the clock did tick, and its cost when it did not is
	// that a digit-only differential on a genuinely static page reports at reduced confidence
	// instead of as a finding.
	if b.ClockUnproven && triageAllChangesDigitBearing(baseNorm, probeNorm, changed) {
		return DiffMaskedOnly, "clock_unproven: every changed run is digit-bearing and this endpoint never proved its clock ticks"
	}

	return triageDecideByRatio(b, rbag, rshingle)
}

// triageDecideByRatio is foundations 5.4 item 8, with ONE DELIBERATE DIVERGENCE, flagged here
// because it changes an answer.
//
// The spec keeps sqlmap's absolute guards as backstops: at or above 0.98 with r_mad == 0 is same,
// at or below 0.02 is different. The lower guard is kept unconditionally: it can only ever produce
// a differential, so it cannot cost a finding.
//
// The upper guard is NOT applied as an override, and is used only when no threshold could be
// measured. On a perfectly stable endpoint r_floor is 1.0, so the measured threshold clamps to
// 0.98, and a probe at 0.985 is borderline by measurement. Honouring the upper guard there would
// call it same, which on the one kind of endpoint where a 1.5% change is certainly real is a false
// negative. Borderline is reportable and is not clean, so the cost of the divergence is operator
// attention and the cost of the other direction is a missed bug.
func triageDecideByRatio(b TriageBaseline, rbag, rshingle float64) (DiffVerdict, string) {
	r := math.Min(rbag, rshingle)
	detail := fmt.Sprintf("r %.4f, threshold %.4f, floor %.4f", r, b.Threshold, b.Model.RFloor)

	if r <= triageRatioLowerBound {
		return DiffDifferent, detail + " (at or below the absolute lower bound)"
	}
	if b.sampleCount < 2 {
		if r >= triageRatioUpperBound {
			return DiffSame, detail + " (no measured threshold; absolute upper bound)"
		}
		return DiffDifferent, detail + " (no measured threshold; absolute bounds only)"
	}
	switch {
	case r < b.Threshold:
		return DiffDifferent, detail
	case r >= b.Model.RFloor:
		return DiffSame, detail
	default:
		return DiffBorderline, detail
	}
}

// triageChangedRegions returns the spans of probeNorm that have no counterpart in baseNorm. They
// are reported so a differential says WHERE, and because T2b requires the changed bytes to be
// shown outside the masked region.
func triageChangedRegions(baseNorm, probeNorm []byte) []ByteRange {
	if bytes.Equal(baseNorm, probeNorm) {
		return nil
	}
	blocks, _ := triageMatchingBlocks(probeNorm, baseNorm)
	if len(blocks) == 0 {
		return []ByteRange{{Offset: 0, Length: len(probeNorm)}}
	}
	var out []ByteRange
	pos := 0
	for _, blk := range blocks {
		if blk.ai > pos {
			out = append(out, ByteRange{Offset: pos, Length: blk.ai - pos})
		}
		if blk.ai+blk.n > pos {
			pos = blk.ai + blk.n
		}
	}
	if pos < len(probeNorm) {
		out = append(out, ByteRange{Offset: pos, Length: len(probeNorm) - pos})
	}
	return out
}

// triageAllChangesDigitBearing reports whether every changed run sits inside a token that carries a
// digit on one side or the other.
func triageAllChangesDigitBearing(baseNorm, probeNorm []byte, changed []ByteRange) bool {
	if len(changed) == 0 {
		return false
	}
	for _, r := range changed {
		if !triageTokenHasDigit(probeNorm, r) {
			return false
		}
	}
	// The baseline side must also be digit-bearing, otherwise a probe that replaced a word with a
	// number would read as the clock.
	rev := triageChangedRegions(probeNorm, baseNorm)
	for _, r := range rev {
		if !triageTokenHasDigit(baseNorm, r) {
			return false
		}
	}
	return true
}

func triageTokenHasDigit(body []byte, r ByteRange) bool {
	start, end := r.Offset, r.Offset+r.Length
	if start < 0 || end > len(body) || start >= end {
		return false
	}
	for start > 0 && !triageIsTokenBreak(body[start-1]) {
		start--
	}
	for end < len(body) && !triageIsTokenBreak(body[end]) {
		end++
	}
	for i := start; i < end; i++ {
		if body[i] >= '0' && body[i] <= '9' {
			return true
		}
	}
	return false
}

func triageIsTokenBreak(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '<' || c == '>' ||
		c == '"' || c == '\'' || c == ',' || c == ';' || c == '{' || c == '}'
}

func triageAnyNovelPointer(b TriageBaseline, probe triageJSONProj, ptrs []string) bool {
	for _, p := range ptrs {
		alpha, ok := b.pointerAlphabet[p]
		if !ok {
			return true
		}
		cur := probe.Scalars[p]
		for i := 0; i < len(cur); i++ {
			if !alpha[cur[i]] {
				return true
			}
		}
	}
	return false
}

// triageStripMarkerForms removes every marker-shaped token from a body. The marker alphabet is
// base36 (foundations 2.2), so no percent-encoding or entity transform changes its bytes; only
// case can, and markerPattern is case-insensitive.
// triageMarkerShape is this file's own compiled copy of the marker shape. The SOURCE is
// triage.MarkerShapePattern, so there is still exactly one definition of what a marker looks like;
// what is local is the compiled object, because a shared one is shared mutable state.
var triageMarkerShape = regexp.MustCompile(triage.MarkerShapePattern)

func triageStripMarkerForms(body []byte) ([]byte, int) {
	if len(body) == 0 {
		return body, 0
	}
	n := 0
	out := triageMarkerShape.ReplaceAllFunc(body, func(m []byte) []byte {
		n += len(m)
		return nil
	})
	return out, n
}

func triageRemoveAll(body, needle []byte) ([]byte, int) {
	if len(needle) == 0 {
		return body, 0
	}
	count := bytes.Count(body, needle)
	if count == 0 {
		return body, 0
	}
	return bytes.ReplaceAll(body, needle, nil), count * len(needle)
}

// triageCombine folds the channels into one verdict. Unusable outranks same, because "that channel
// could not be read" must never present as "nothing changed".
func triageCombine(b TriageBaseline, res CompareResult) (DiffVerdict, string) {
	best := DiffUnmeasured
	var reason string
	shapeOnly := b.Gate == GateJudgeableShapeOnly

	// On a shape-only endpoint the byte channels are unusable by construction, and the shape
	// channel is the measurement. Dropping the byte channels is only honest while the shape
	// channel actually answered: if it did not, the unusable body channel is the whole story and
	// the comparison must say so rather than reporting the remaining channels as agreement.
	shapeAnswered := false
	if shapeOnly {
		for _, ch := range res.Channels {
			switch ch.Channel {
			case ChanJSONShape, ChanHTMLStruct:
				if !ch.Verdict.IsUnknown() {
					shapeAnswered = true
				}
			}
		}
	}

	for _, ch := range res.Channels {
		v := ch.Verdict
		if shapeOnly {
			switch ch.Channel {
			case ChanBody, ChanLength:
				if shapeAnswered {
					continue
				}
				v = DiffUnusable
			}
		}
		if v == DiffUnusable && ch.Channel != ChanBody {
			// A channel that does not apply to this response (no redirect, not JSON, no HTML) is
			// silent rather than unknown. Only the body channel's unusability is load-bearing,
			// because it is the channel every class leans on.
			continue
		}
		if diffRank(v) > diffRank(best) {
			best = v
			if v == DiffUnusable && ch.Channel == ChanBody && ch.Detail != "" {
				// The body channel's own reason IS the comparison's reason. Prefixing it with the
				// channel name would make a caller matching on no_body miss it.
				reason = ch.Detail
				continue
			}
			reason = string(ch.Channel)
			if ch.Detail != "" {
				reason += ": " + ch.Detail
			}
		}
	}
	if best == DiffUnmeasured {
		return DiffUnusable, "no_channel_produced_a_measurement"
	}
	if best == DiffSame {
		reason = ""
	}
	return best, reason
}

// ---------------------------------------------------------------------------------------------
// 9. INTERFERENCE: UNIFORM BLOCKING
// ---------------------------------------------------------------------------------------------

// Interference is foundations 5.8's per-class rule. A WAF or a validation layer that answers
// identically to every payload is not a finding and is not noise: it is an ABSENCE OF MEASUREMENT.
type Interference struct {
	UniformBlock bool
	// Fingerprint is the SHA-256 prefix of the identical non-baseline response, after marker and
	// echo removal. It is what the cross-class annotation compares, and it is a hash rather than a
	// body so no class can read another class's response content out of it.
	Fingerprint string
	Payloads    int
	Reason      string
}

// DetectUniformBlock looks ONLY at the calling class's own probes.
//
// IT TAKES NO CLASS ARGUMENT. It takes a triage.OwnedResponses, which is the class's own set with
// the owner bound into it by triage.OwnFor, so there is no id to pass and therefore no id to pass
// wrongly. The previous signature took own plus an `as ClassID` and read each response with
// p.Obs(as), which was sound only while the caller passed the truth; p.Obs(p.Owner()) handed over
// a foreign response with a nil error. There is now no accessor that takes an owner at all.
//
// Three or more of a class's OWN distinct payloads producing byte-identical responses that differ
// from the baseline means this slot answered the class rather than the application did.
func DetectUniformBlock(b TriageBaseline, own triage.OwnedResponses) (Interference, error) {
	groups := map[string]map[string]bool{}
	for i := 0; i < own.Len(); i++ {
		p, obs, err := own.At(i)
		if err != nil {
			return Interference{}, err
		}
		if !obs.Delivered() {
			continue
		}
		stripped, _ := triageStripMarkerForms(obs.Body)
		if len(obs.Payload.Wire) > 0 {
			if run := triageLongestCommonRun(obs.Payload.Wire, stripped, triageEchoMinRun); len(run) > 0 {
				stripped, _ = triageRemoveAll(stripped, run)
			}
		}
		norm, _, _ := TriageApplyMarkings(stripped, b.Markings)
		if bytes.Equal(norm, b.TemplateNorm) && obs.Status == b.Template.Status {
			continue
		}
		fp := fmt.Sprintf("%d:%x", obs.Status, sha256.Sum256(norm))
		if groups[fp] == nil {
			groups[fp] = map[string]bool{}
		}
		groups[fp][strconv.FormatUint(p.Ordinal(), 10)+"/"+string(p.ProbeID())] = true
	}
	for fp, payloads := range groups {
		if len(payloads) >= 3 {
			return Interference{
				UniformBlock: true,
				Fingerprint:  fp,
				Payloads:     len(payloads),
				Reason:       "blocked",
			}, nil
		}
	}
	return Interference{}, nil
}

// CrossClassUniformBlock is THE SINGLE DECLARED EXCEPTION to the isolation law, and it is an
// ANNOTATION rather than an input to any verdict.
//
// It may only ever downgrade to cannot_determine. It may never produce a clean result, may never
// produce a finding, and no class's verdict is computed from it. Its only purpose is to tell the
// operator that a WAF sat in front of this slot, which is itself worth knowing. It takes
// fingerprints, not responses, so there is no route by which one class's body reaches another.
func CrossClassUniformBlock(perClass map[triage.ClassID]Interference) (bool, []triage.ClassID) {
	byFP := map[string][]triage.ClassID{}
	for c, i := range perClass {
		if !i.UniformBlock {
			continue
		}
		byFP[i.Fingerprint] = append(byFP[i.Fingerprint], c)
	}
	for _, cs := range byFP {
		if len(cs) >= 2 {
			sort.Slice(cs, func(i, j int) bool { return cs[i] < cs[j] })
			return true, cs
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------------------------
// 10. ERROR SIGNATURES, BASELINE-DIFFERENCED
// ---------------------------------------------------------------------------------------------

// NovelErrorSigs returns the signatures present in the probe that the BASELINE did not already
// carry. It is the whole of this file's involvement with error signatures: the catalogue that
// produces Proj.ErrorSigs is owned elsewhere, and this function owns only the differencing.
//
// Without it, an endpoint whose unperturbed response always contains
// "org.postgresql.util.PSQLException: connection pool warning" makes every probe look like a
// finding, and the scanner scores 100% on a corpus where every route is vulnerable. With it, that
// signature is disabled for the endpoint and a DIFFERENT signature appearing is still a signal.
func NovelErrorSigs(baselineSigs, probeSigs []string) []string {
	base := triageStringSet(baselineSigs)
	var out []string
	for _, s := range probeSigs {
		if !base[s] {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------------------------
// 11. A/B/A ON A MUTATING VECTOR
// ---------------------------------------------------------------------------------------------

// CheckBracketingBaselines is foundations 5.10 rule 5. A differential on a creates_row vector
// counts only if the two bracketing baselines agree with each other after masking. It triples the
// cost on the mutating vectors and it is the only way a differential on a mutating endpoint means
// anything.
func CheckBracketingBaselines(b TriageBaseline, before, after triage.Observation) (bool, string) {
	if !before.Delivered() || !after.Delivered() {
		return false, "bracketing_baseline_transport_error"
	}
	if before.Status != after.Status {
		return false, fmt.Sprintf("bracketing baselines disagree on status: %d then %d", before.Status, after.Status)
	}
	nb, _, _ := TriageApplyMarkings(before.Body, b.Markings)
	na, _, _ := TriageApplyMarkings(after.Body, b.Markings)
	if bytes.Equal(nb, na) {
		return true, ""
	}
	r := math.Min(triageBagRatio(nb, na), triageShingleRatio(nb, na))
	if b.sampleCount >= 2 && r >= b.Model.RFloor {
		return true, ""
	}
	return false, fmt.Sprintf("bracketing baselines differ after masking, r %.4f below floor %.4f", r, b.Model.RFloor)
}

// ---------------------------------------------------------------------------------------------
// 12. SMALL HELPERS
// ---------------------------------------------------------------------------------------------
