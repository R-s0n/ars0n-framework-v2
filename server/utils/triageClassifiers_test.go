package utils

import (
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// The link from the runner to the classifiers, end to end.
//
// This package imports server/triageclasses for its side effects only. If that import is ever
// dropped, or a classifier's init() stops running, the registry is empty, the runner iterates
// nothing, and every attack class is silently absent from every report. There is no error
// anywhere on that path, which is why it gets a test rather than a comment.
func TestTheClassifiersAreLinkedInByTheBlankImport(t *testing.T) {
	ids := RegisteredTriageClassIDs()
	if len(ids) == 0 {
		t.Fatal("no classifier reached the registry from package utils. The blank import of server/triageclasses is the only thing that links them in, and with it gone the runner iterates an empty registry and reports nothing for every class")
	}
	for _, id := range ids {
		if !id.Known() {
			t.Errorf("class id %d is registered but is not in the register in triage/types.go", id)
		}
		c, ok := triage.ClassifierFor(id)
		if !ok || c.ID() != id {
			t.Errorf("ClassifierFor(%s) did not round-trip", id)
		}
	}
	t.Logf("registered classes visible from package utils: %v", ids)
}

// The isolation law is checkable from where the runner will call it, not only from a test inside
// the triage package.
func TestTheRegistryIsolationGateIsCallableFromTheRunner(t *testing.T) {
	if err := AssertTriageRegistryIsolation(); err != nil {
		t.Errorf("AssertTriageRegistryIsolation: %v", err)
	}
}
