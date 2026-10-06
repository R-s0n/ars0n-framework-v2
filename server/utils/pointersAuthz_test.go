package utils

import (
	"strings"
	"testing"
)

// collectAuthzPointers hits the database (CollectIDORCandidates), so the mapping it delegates to is
// exercised here through its pure core, assembleAuthzPointers. No container and no DB are touched.
// The seed is the Alpaca shape: GET /accounts/{uuid}/details returns an owner field plus PII, the
// path id is a UUIDv4 (needs a leak), and a sibling list leaks it.
func TestAssembleAuthzPointersYieldsAnIDORPointerFromACandidateAndNoneWhenEmpty(t *testing.T) {
	c := IDORCandidate{
		VectorID:       "11111111-1111-1111-1111-111111111111",
		Method:         "GET",
		URL:            "https://api.example.test/api/v1/accounts/abc/details",
		Path:           "/api/v1/accounts/{uuid}/details",
		InsertionPoint: "path",
		Param:          "account_id",
		IDLocation:     "path parameter {uuid}",
		GuessTier:      "uuid_v4",
		HasOwnerField:  true,
		HasPII:         true,
		AuthClientSent: true,
		IDLeaked:       true,
		KnownIDValue:   "abc",
		IDLeakSource:   "GET /api/v1/accounts",
		Score:          7,
		Reasons:        []string{"owner field present", "client-sent auth"},
	}

	got := assembleAuthzPointers([]IDORCandidate{c})
	if len(got) != 1 {
		t.Fatalf("one candidate should yield one pointer, got %d", len(got))
	}
	p := got[0]
	if p.AttackClass != pointerClassIDOR {
		t.Errorf("attack class = %q, want %q", p.AttackClass, pointerClassIDOR)
	}
	if p.Source != PointerSourceAuthz {
		t.Errorf("source = %q, want %q", p.Source, PointerSourceAuthz)
	}
	if p.StrengthRank != EvidenceRank(ProvenancePriorFinding, false) {
		t.Errorf("an IDOR candidate must rank in the prior_finding band, got rank %d", p.StrengthRank)
	}
	if !p.Deliverable {
		t.Error("IDOR is sent by the attacker's own request, so it is deliverable and delivery does not gate it")
	}
	if p.Grade != "" || p.severity != "" {
		t.Error("IDOR must carry no grade or severity: schema-level PII is a surface signal, not impact")
	}
	if !strings.Contains(strings.ToLower(p.Rule), "swap") {
		t.Errorf("the rule must name the id swap, got %q", p.Rule)
	}
	if p.NextTool != "" || !strings.Contains(strings.ToLower(p.NextToolReason), "hand review") {
		t.Errorf("the next step must be a hand review with a second identity, got tool %q reason %q", p.NextTool, p.NextToolReason)
	}
	if p.authzCandidate == nil || p.authzCandidate.KnownIDValue != "abc" {
		t.Error("the candidate must be stashed on the pointer for the detail endpoint")
	}

	if none := assembleAuthzPointers(nil); len(none) != 0 {
		t.Errorf("no candidates must yield no pointer, got %d", len(none))
	}
}
