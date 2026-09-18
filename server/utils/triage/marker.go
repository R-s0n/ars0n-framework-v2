package triage

import (
	"crypto/rand"
	"fmt"
	"hash/crc32"
	"math/big"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/internal/triagecap"
)

// Marker arithmetic: the checksum, the run id and the deterministic mint.
//
// WHY THIS HALF IS DOWN HERE AND THE MINTER IS NOT. Marker.Integrity() has to be able to recompute
// the checksum, and Marker lives in this package, so the checksum body has to live here too or the
// method becomes a call up into utils and the import cycle closes. What stays in
// utils/triageMarker.go is everything STATEFUL or SEARCH-shaped: the per-run MarkerMinter that
// allocates ordinals, the encoded-form scanner and the per-class attribution verdict. A class
// never mints its own marker; it is handed one in a ProbeRequest, and keeping the allocator in
// utils means the classes package cannot reach it at all.
//
// MintMarkerAt is exported from here because the allocator in utils needs it, and it takes the
// runner capability.
//
// AN EARLIER VERSION OF THIS COMMENT WAS A LIVE COUNTEREXAMPLE TO THE ONE IN classes.go. It said
// MintMarkerAt was safe to hand to a classifier, on the grounds that it refuses an ordinal outside
// the owner's stripe, so the worst a class could do was mint a marker it already owns. Meanwhile
// classes.go claimed a class could not reach the minter at all. Both could not be true, and an
// adversarial audit called triage.MintMarkerAt from the classifier package on every one of fifteen
// attempts. The capability makes the classes.go claim the true one: the parameter type lives in
// server/utils/internal/triagecap, and a classifier, being outside server/utils, cannot import
// that package and therefore cannot spell the call.

const (
	// MarkerOrdinalMax is 36^6 - 1, the largest ordinal that fits the six base36 digits of the
	// layout. Running out is an error and never a wrap: a wrapped ordinal would re-issue a marker
	// that a cached response from earlier in the same run could still be carrying, and the late
	// body would then be attributed to the wrong probe.
	MarkerOrdinalMax = 2176782335

	// markerChecksumModulus is 36^3, so the checksum renders in exactly MarkerChecksumLen digits.
	markerChecksumModulus = 46656

	// markerPrefixLen is anchor + run id + ordinal, the bytes the checksum is computed over.
	markerPrefixLen = MarkerAnchorLen + MarkerRunIDLen + MarkerOrdinalLen

	triageMarkerAlphabet = "0123456789abcdefghijklmnopqrstuvwxyz"
)

// triageRenderBase36 renders v zero-padded to width digits, refusing rather than truncating when it does
// not fit. A silently truncated ordinal is a marker attributed to a different class.
func triageRenderBase36(v uint64, width int) (string, error) {
	s := strconv.FormatUint(v, 36)
	if len(s) > width {
		return "", fmt.Errorf("triage: %d does not fit in %d base36 digits", v, width)
	}
	return strings.Repeat("0", width-len(s)) + s, nil
}

// MarkerChecksumFor is CRC-32 (IEEE) over the first thirteen bytes, reduced mod 36^3 and rendered
// base36. It is not a security property; it is what tells a real marker apart from thirteen bytes
// of somebody else's base36 that happen to start with the anchor, and what makes a single flipped
// character in a reflected token detectable instead of silently attributing to another ordinal.
func MarkerChecksumFor(prefix string) (string, error) {
	if len(prefix) != markerPrefixLen {
		return "", fmt.Errorf("triage: marker checksum wants exactly %d bytes of prefix, got %d", markerPrefixLen, len(prefix))
	}
	return triageRenderBase36(uint64(crc32.ChecksumIEEE([]byte(prefix)))%markerChecksumModulus, MarkerChecksumLen)
}

// VerifyMarkerIntegrity recomputes the checksum. It is the ONE body for the question, and
// Marker.Integrity() is a one-line delegation to it, so a classifier reaching for the method and a
// caller reaching for the function can never be told different things.
//
// FAILS CLOSED. Anything that is not marker-shaped reads corrupted, not unchecked. Both cap a hit
// at suspicious, but corrupted is the one that says a decision was actually made.
func VerifyMarkerIntegrity(m Marker) MarkerIntegrity {
	if !m.WellFormed() {
		return MarkerCorrupted
	}
	want, err := MarkerChecksumFor(string(m[:markerPrefixLen]))
	if err != nil || want != string(m[markerPrefixLen:]) {
		return MarkerCorrupted
	}
	return MarkerValid
}

// WellFormedRunID reports whether s is a usable run id: exactly MarkerRunIDLen bytes of the marker
// alphabet. The run id is how a response that arrived during run B carrying run A's token is
// recognised as cached or late rather than as a hit.
func WellFormedRunID(s string) bool {
	if len(s) != MarkerRunIDLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		if (b < '0' || b > '9') && (b < 'a' || b > 'z') {
			return false
		}
	}
	return true
}

// NewRunID draws a fresh run id from crypto/rand. Not math/rand: two runs started in the same
// millisecond by a supervisor loop would otherwise share a run id, and separating them is the
// entire job of the run id.
func NewRunID(cap triagecap.Runner) (string, error) {
	if !cap.Held() {
		return "", ErrNotTheRunner
	}
	out := make([]byte, MarkerRunIDLen)
	for i := range out {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(triageMarkerAlphabet))))
		if err != nil {
			return "", fmt.Errorf("triage: could not draw a run id: %w", err)
		}
		out[i] = triageMarkerAlphabet[n.Int64()]
	}
	return string(out), nil
}

// MintMarkerAt builds the marker for one exact ordinal. It is the deterministic half, used by the
// allocator below and by tests; the runner wants MarkerMinter.Mint.
//
// It REFUSES an ordinal outside owner's stripe. That refusal is the isolation law at the only
// point in the system where a marker can be given the wrong owner.
func MintMarkerAt(cap triagecap.Runner, runID string, owner ClassID, ordinal uint64) (Marker, error) {
	if !cap.Held() {
		return "", ErrNotTheRunner
	}
	if !owner.Known() {
		return "", fmt.Errorf("triage: refusing to mint a marker for unknown class id %d", uint8(owner))
	}
	if !WellFormedRunID(runID) {
		return "", fmt.Errorf("triage: run id %q is not %d bytes of [0-9a-z]", runID, MarkerRunIDLen)
	}
	if ordinal > MarkerOrdinalMax {
		return "", fmt.Errorf("triage: ordinal %d exceeds the %d that six base36 digits hold", ordinal, uint64(MarkerOrdinalMax))
	}
	if ordinal%ClassStripeModulus != uint64(owner) {
		return "", fmt.Errorf("triage: ordinal %d has stripe %d, which is class %s, not %s: minting it would attribute this probe to another class",
			ordinal, ordinal%ClassStripeModulus, ClassID(ordinal%ClassStripeModulus), owner)
	}
	digits, err := triageRenderBase36(ordinal, MarkerOrdinalLen)
	if err != nil {
		return "", err
	}
	prefix := DefaultMarkerAnchor + runID + digits
	sum, err := MarkerChecksumFor(prefix)
	if err != nil {
		return "", err
	}
	m := Marker(prefix + sum)
	if !m.WellFormed() {
		return "", fmt.Errorf("triage: minted %q, which is not well formed; the anchor or the alphabet changed under this function", m)
	}
	return m, nil
}
