package utils

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =================================================================================================
// INVALIDATE-ON-REFUSAL DEFEATED THE CACHE EXACTLY WHERE THE CACHE MATTERED
// =================================================================================================
//
// The third freshness trigger is right, and unbounded it is also the live shape: 170 vectors
// behind a wall means every probe answers 401, every 401 calls Invalidate, and every following
// probe pays a full credential re-read. The TTL sized for about 60 reads over a 29 minute run
// becomes one read per probe, and the run is slowest precisely where it is learning nothing.
//
// WHAT THE FLOOR MUST NOT DO is suppress new information. These tests assert both halves: the
// wall is floored, and a rotation is not.

func readPackageFile(t *testing.T, name string) (string, error) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(packageDir(t), name))
	return string(b), err
}

// credFor builds a fixture credential. NOTHING HERE IS A REAL TOKEN and nothing is a value: the
// fingerprint is the only thing this type ever prints and it is what the floor compares on.
func credFor(header, fingerprint string) triageFreshCred {
	return triageFreshCred{Header: header, Source: "fixture", Fingerprint: fingerprint}
}

func seedCredEntry(s *triageDBFreshCreds, host string, creds []triageFreshCred) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cache[host] = &triageFreshCredEntry{
		creds:  creds,
		status: triageFreshCredStatus{Host: host, Fresh: len(creds), ReadAt: time.Now()},
	}
}

func credReadAt(s *triageDBFreshCreds, host string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cache[host].status.ReadAt
}

// TestAWallOfRefusalsCostsOneReReadAndNotOnePerProbe is the cost half.
func TestAWallOfRefusalsCostsOneReReadAndNotOnePerProbe(t *testing.T) {
	const host = "app.example.test"
	s := newTriageFreshCredentials("scope-fixture")
	seedCredEntry(s, host, []triageFreshCred{credFor("Authorization", "aaaaaaaa")})

	// The live shape: 170 vectors behind a wall, every one refused, back to back.
	for i := 0; i < 170; i++ {
		s.Invalidate(host)
	}
	honoured, floored := s.invalidationCounts(host)
	if honoured != 1 {
		t.Errorf("170 refusals of the SAME credential honoured %d re-read(s), want 1. Every honoured "+
			"invalidation is a full credential refresh in front of the next probe", honoured)
	}
	if floored != 169 {
		t.Errorf("floored %d of 170 refusals, want 169", floored)
	}
	if !credReadAt(s, host).IsZero() {
		t.Error("the first refusal did not revoke the cached reading, so the trigger that matters " +
			"is not firing at all")
	}
}

// TestARotationIsNotFlooredEvenInsideTheWindow is the correctness half, and it is the one that
// would make a floor dangerous if it were wrong: a target that refuses a token, a browser that
// captures a new one, and a refusal of THAT one must re-read at once.
func TestARotationIsNotFlooredEvenInsideTheWindow(t *testing.T) {
	const host = "app.example.test"
	s := newTriageFreshCredentials("scope-fixture")
	seedCredEntry(s, host, []triageFreshCred{credFor("Authorization", "aaaaaaaa")})

	s.Invalidate(host)
	s.Invalidate(host)
	if honoured, floored := s.invalidationCounts(host); honoured != 1 || floored != 1 {
		t.Fatalf("honoured=%d floored=%d before the rotation, want 1 and 1", honoured, floored)
	}

	// The run re-read and got a DIFFERENT credential, which the target has now also refused.
	// Same host, same instant, and this refusal carries information the last one did not.
	seedCredEntry(s, host, []triageFreshCred{credFor("Authorization", "bbbbbbbb")})
	s.Invalidate(host)
	honoured, _ := s.invalidationCounts(host)
	if honoured != 1 {
		t.Errorf("a refusal of a DIFFERENT credential inside the floor window was suppressed "+
			"(honoured=%d after the rotation, counted on the fresh entry). The floor is a bound on "+
			"repeating a disproved answer, never on learning a new one", honoured)
	}
	if !credReadAt(s, host).IsZero() {
		t.Error("the rotated credential's refusal did not revoke the cached reading")
	}
}

// AND THE WINDOW ACTUALLY ELAPSES. A floor that never lifts is a cache that never refreshes,
// which is the failure this whole file exists to prevent pointing the other way.
func TestTheRefusalFloorLiftsWhenTheWindowHasPassed(t *testing.T) {
	const host = "app.example.test"
	s := newTriageFreshCredentials("scope-fixture")
	seedCredEntry(s, host, []triageFreshCred{credFor("Authorization", "aaaaaaaa")})

	s.Invalidate(host)
	s.Invalidate(host)

	s.mu.Lock()
	s.cache[host].refusedAt = time.Now().Add(-triageFreshCredRefusalFloor - time.Second)
	s.cache[host].status.ReadAt = time.Now()
	s.mu.Unlock()

	s.Invalidate(host)
	if honoured, _ := s.invalidationCounts(host); honoured != 2 {
		t.Errorf("honoured=%d after the window elapsed, want 2: a floor that never lifts is a cache "+
			"that never refreshes", honoured)
	}
	if !credReadAt(s, host).IsZero() {
		t.Error("the refusal after the window elapsed did not revoke the cached reading")
	}
}

// AN EMPTY CREDENTIAL SET IS A STATE AND NOT AN ABSENCE OF ONE. "this host has no credential"
// and "this entry has never been invalidated" would both print as the empty string, and the
// first refusal after the cache went dry would then be floored against a comparison that never
// happened.
func TestAnEmptyCredentialSetHasItsOwnName(t *testing.T) {
	const host = "app.example.test"
	s := newTriageFreshCredentials("scope-fixture")
	seedCredEntry(s, host, nil)

	s.Invalidate(host)
	if honoured, _ := s.invalidationCounts(host); honoured != 1 {
		t.Errorf("the first refusal on a host with no cached credential honoured %d re-read(s), want 1",
			honoured)
	}
	if triageCredSetPrint(nil) == "" {
		t.Error("an empty credential set prints as the empty string, which is also the zero value of " +
			"the field it is compared against")
	}
	if triageCredSetPrint(nil) == triageCredSetPrint([]triageFreshCred{credFor("Authorization", "aaaaaaaa")}) {
		t.Error("an empty set and a one-credential set print the same, so the floor cannot tell a " +
			"host that went dry from one that rotated")
	}
}

// AND A HOST WITH NOTHING CACHED IS NOT COUNTED EITHER WAY. There is nothing to revoke and the
// next FreshFor reads regardless, so calling that a floored re-read would overstate the saving.
func TestAnUncachedHostIsNotCountedAsAFlooredReRead(t *testing.T) {
	s := newTriageFreshCredentials("scope-fixture")
	s.Invalidate("never.seen.test")
	if honoured, floored := s.invalidationCounts("never.seen.test"); honoured != 0 || floored != 0 {
		t.Errorf("honoured=%d floored=%d for a host that was never cached, want 0 and 0", honoured, floored)
	}
}

// AND THE PRINT CARRIES NO VALUE. It is built from the carrier name and the fingerprint, which
// are the only things this type is allowed to render, and it is compared in memory rather than
// logged; this test is what keeps it that way if somebody widens it.
func TestTheCredentialSetPrintCarriesNoValue(t *testing.T) {
	c := triageFreshCred{Header: "Authorization", Source: "session_tokens", Fingerprint: "deadbeef"}
	// The value field is unexported and set only by the reader, so a fixture cannot put a token
	// in one from here, which is itself the point. What is asserted is the shape of the output.
	got := triageCredSetPrint([]triageFreshCred{c})
	if got != "Authorization header=deadbeef" {
		t.Errorf("print = %q, want the carrier and the fingerprint and nothing else", got)
	}
}

// THE SCOPE TARGET IS READ ONCE. It is immutable for the run, and re-deriving it inside
// sessionTokenCandidates made every credential refresh three SELECTs rather than two.
//
// It is asserted over the source because the call it counts is a database read: driving it would
// need a scope_targets row, and these tests may not write to the scan database.
func TestTheScopeTargetIsReadOnceAtConstruction(t *testing.T) {
	src, err := readPackageFile(t, "triageFreshCredential.go")
	if err != nil {
		t.Fatalf("read triageFreshCredential.go: %v", err)
	}
	if n := strings.Count(src, "ScopeTargetBase("); n != 1 {
		t.Errorf("ScopeTargetBase is called %d time(s) in this file, want exactly 1 (the constructor). "+
			"Every other call site is a third SELECT per refresh on a value that cannot change "+
			"between the first probe and the last", n)
	}
	if !strings.Contains(src, "defaultDomain: RegistrableDomain(strings.ToLower(targetHost))") {
		t.Error("the constructor does not derive defaultDomain, so the per-refresh read is still there")
	}
	if !strings.Contains(src, "defaultDomain := s.defaultDomain") {
		t.Error("sessionTokenCandidates does not read the constructed defaultDomain")
	}
}
