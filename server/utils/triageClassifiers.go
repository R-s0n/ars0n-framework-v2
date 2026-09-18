package utils

import (
	"fmt"
	"sort"
	"strings"

	"ars0n-framework-v2-server/utils/triage"

	// The classifiers register themselves from init(). This blank import is the ONLY thing that
	// links them in, and it is deliberately the only coupling in that direction: package
	// triageclasses imports triage and nothing else, so nothing a classifier can name reaches the
	// runner, the store or the marker minter.
	//
	// WHY A BLANK IMPORT AND NOT A LIST. A list of classes is a second place to change when a
	// class is added, and a class silently missing from it is a whole attack class recorded as
	// never attempted, which is the most expensive shape of bug this layer has. Adding a class is
	// adding a file to server/triageclasses; nothing here changes.
	//
	// AND WHY THAT DIRECTORY IS NOT UNDER server/utils. The minting capability lives in
	// server/utils/internal/triagecap, and Go's internal rule makes a/b/internal/c importable by
	// everything under a/b. While the classifiers lived at server/utils/triage/classes they were
	// under server/utils, so the rule would have let them import the capability and mint into any
	// class's partition. Moving them to server/triageclasses is what makes the refusal a build
	// error. The import path below is load-bearing; do not "tidy" it back under utils.
	_ "ars0n-framework-v2-server/triageclasses"
)

// The link between the runner in this package and the classifiers one package down.

// AssertTriageRegistryIsolation runs the isolation law over whatever registered itself, and it is
// meant to be called before a run starts rather than only from a test.
//
// A law that is only checked in CI is a law that holds on the developer's machine. Two classes
// shipping byte-equal payloads makes a block or a rejection of that payload attributable to
// neither of them, and the operator then reads one of the two as clean. The run refuses to start
// instead.
func AssertTriageRegistryIsolation() error {
	reg := triage.RegisteredClassifiers()
	rep := triage.CheckPayloadIsolation(reg)
	if rep.OK() {
		return nil
	}
	lines := make([]string, 0, len(rep.Violations))
	for _, v := range rep.Violations {
		lines = append(lines, v.String())
	}
	sort.Strings(lines)
	return fmt.Errorf("triage: the registry breaks the isolation law over %d classes and %d probes, so no verdict from this run could be attributed: %s",
		rep.ClassesChecked, rep.ProbesChecked, strings.Join(lines, "; "))
}

// RegisteredTriageClassIDs is the register as the runner sees it, in ascending id order.
func RegisteredTriageClassIDs() []triage.ClassID {
	reg := triage.RegisteredClassifiers()
	out := make([]triage.ClassID, 0, len(reg))
	for id := range reg {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
