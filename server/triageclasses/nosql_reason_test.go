package triageclasses

import (
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// =================================================================================================
// A BLIND ORACLE MAY NOT NAME A COMPONENT IT DID NOT MEASURE
//
// nosqlCleanOn's not-ready row read: "the probes this oracle reads did not all come back on this
// slot, so it was never in a position to answer and its silence is the runner's and not the
// endpoint's".
//
// Ready goes false for THREE different reasons and only one of them is the runner's:
//
//	no observation at all   nothing came back for the probe. This class cannot see whether it was
//	                        never issued, cut by a cap, or lost.
//	the TRANSPORT refused   the request went out and the socket said no. That is the network or
//	                        the target, and telling an operator to go and look at the tool when
//	                        the target reset the connection is a guessed cause.
//	survival unproven       the widening oracle's Ready also asks that the payload be PROVEN on
//	                        the wire, which is the encoder's record and not the runner's delivery.
//
// The verdict is an unknown either way. The sentence is not.
// =================================================================================================

func TestABlindNoSQLOracleDoesNotBlameTheRunnerForATransportRefusal(t *testing.T) {
	page := `{"results":[{"id":1}],"echo":"hello"}`
	ev := nosqlTestEvidence(page, map[triage.ProbeID]string{
		"NSQ-J3": `{"results":[{"id":1}],"echo":"a"}`,
		"NSQ-J5": `{"results":[{"id":1}],"echo":"b"}`,
	})
	// NSQ-J6 went out and the socket refused it. Nothing about that is the tool's.
	ev.seen["NSQ-J6"] = nosqlSeen{obs: triage.Observation{
		ObsID: "o-j6", TransportErr: triage.TransportConnect,
	}}

	v := nosqlBase(ev, nosqlArmJS)
	v.Ordinals = []uint64{1, 2}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: nosqlAnyDelivered(ev, "NSQ-J3", "NSQ-J7", "NSQ-J4"),
			Reads: []triage.ProbeID{"NSQ-J3", "NSQ-J7", "NSQ-J4"},
			Claim: "no marker came back glued to this class's product"},
		{Kind: nosqlOracleCount, Ready: nosqlAllDelivered(ev, "NSQ-J5", "NSQ-J6"),
			Reads: []triage.ProbeID{"NSQ-J5", "NSQ-J6"},
			Claim: "the concatenated true and false arms produced the same result set"},
	}, "the $where probes ran")

	if strings.Contains(got.Reason, "the runner's and not the endpoint's") {
		t.Errorf("the row-count oracle is blind because the TRANSPORT refused NSQ-J6, and the reason blames "+
			"the runner:\n  %s", got.Reason)
	}
	if !strings.Contains(got.Reason, "NSQ-J6") {
		t.Errorf("the reason does not name the probe that was not in hand, so the operator cannot check "+
			"it:\n  %s", got.Reason)
	}
	if !strings.Contains(got.Reason, string(triage.TransportConnect)) {
		t.Errorf("the reason does not carry the transport error that is the whole difference between a tool "+
			"problem and a target problem:\n  %s", got.Reason)
	}
	// The token the rest of the suite greps for stays, because it is the thing being reported.
	if !strings.Contains(got.Reason, "probes_not_delivered") {
		t.Errorf("the not-ready row lost its own token:\n  %s", got.Reason)
	}
}

// A PROBE WITH NO OBSERVATION AT ALL IS A DIFFERENT FACT FROM ONE THE TRANSPORT REFUSED, and the
// row has to keep them apart or the two get the same investigation.
func TestABlindNoSQLOracleSeparatesAMissingObservationFromARefusedOne(t *testing.T) {
	page := `{"results":[{"id":1}],"echo":"hello"}`
	ev := nosqlTestEvidence(page, map[triage.ProbeID]string{
		"NSQ-J5": `{"results":[{"id":1}],"echo":"b"}`,
	})

	v := nosqlBase(ev, nosqlArmJS)
	v.Ordinals = []uint64{1}
	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no marker came back glued to this class's product"},
		{Kind: nosqlOracleCount, Ready: nosqlAllDelivered(ev, "NSQ-J5", "NSQ-J6"),
			Reads: []triage.ProbeID{"NSQ-J5", "NSQ-J6"},
			Claim: "the concatenated true and false arms produced the same result set"},
	}, "the $where probes ran")

	if !strings.Contains(got.Reason, "no observation") {
		t.Errorf("NSQ-J6 has no observation at all and the reason does not say so:\n  %s", got.Reason)
	}
	if strings.Contains(got.Reason, "the runner's and not the endpoint's") {
		t.Errorf("the reason still asserts which component is responsible for a missing observation:\n  %s", got.Reason)
	}
	// NSQ-J5 DID come back. An all-of pair that reports both halves missing sends the operator
	// after a probe that is sitting in the evidence set.
	if !strings.Contains(got.Reason, "NSQ-J5") || !strings.Contains(got.Reason, "NSQ-J6") {
		t.Errorf("the reason does not distinguish the half that came back from the half that did not:\n  %s", got.Reason)
	}
}

// AND A CLAIM THAT NAMES NO PROBE STILL REPORTS ITSELF. Reads is optional, because three of the
// declared claims are Ready:true by construction and read probes the arm already proved usable.
// A claim that is not ready AND names nothing must say that, not fall through to silence.
func TestANotReadyClaimWithNoDeclaredProbesSaysSoRatherThanGuessing(t *testing.T) {
	page := `{"results":[{"id":1}]}`
	ev := nosqlTestEvidence(page, map[triage.ProbeID]string{"NSQ-C2": `{"results":[{"id":1}],"echo":"a"}`})
	v := nosqlBase(ev, nosqlArmCouch)
	v.Ordinals = []uint64{1}

	got := nosqlCleanOn(ev, v, []nosqlCleanClaim{
		{Kind: nosqlOracleNamed, Ready: true, Claim: "no CouchDB error named this run's marker"},
		{Kind: nosqlOracleCount, Ready: false, Claim: "no array in the response grew"},
	}, "the Mango probes ran")

	if !strings.Contains(got.Reason, "probes_not_delivered") {
		t.Fatalf("a not-ready claim was dropped from the row entirely:\n  %s", got.Reason)
	}
	if strings.Contains(got.Reason, "the runner's and not the endpoint's") {
		t.Errorf("a claim that names no probe still asserts which component is responsible:\n  %s", got.Reason)
	}
}
