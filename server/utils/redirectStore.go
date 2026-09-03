package utils

import (
	"context"
	"strings"
)

// Keeping REcollapse's output where the scanner can reach it.
//
// REcollapse prints mutations and stops; it has no network code and never sends one. So its "scan"
// does not produce findings, it produces AMMUNITION, and the honest way to report that is a count of
// what it built rather than a list of vulnerabilities it did not find.
//
// The list goes on the shared volume because the two tools live in different containers: REcollapse
// prints in its own, the API writes the file, and nuclei reads it from its own.

// storeREcollapseMutations writes the payload list and reports what was built.
func storeREcollapseMutations(ctx context.Context, tool VectorTool, v VectorInput,
	stdout string) ([]VectorFinding, []string) {

	var warnings []string
	var lines []string
	for _, line := range strings.Split(stripANSI(stdout), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return nil, []string{"REcollapse produced no mutations, so there is nothing for the scan to " +
			"send. Check the webhook URL."}
	}

	// The framework's own structural forms are counted here too, because they are part of what the
	// scanner will send and an operator reading "2083 payloads" should be reading the real number.
	webhook := strings.TrimRight(strings.TrimSpace(stringifySetting(v.Section["listeningWebhookURL"])), "/")
	extra := FrameworkSSRFPayloads(webhook+"/"+vectorTokenPlaceholder, v.Domain)

	body := strings.Join(lines, "\n") + "\n"
	if err := writeContainerFile(ctx, tool.Container, redirectMutationsPath(v.ScopeTargetID), body); err != nil {
		return nil, []string{"Could not store the payload list: " + err.Error()}
	}

	// Written into the SCANNER's container as well. Both mount the shared volume, but writing it
	// through the container that will read it is what makes a mount misconfiguration surface here
	// rather than as an empty scan later.
	if scanner, ok := VectorToolByKey("nuclei-dast"); ok && scanner.Container != tool.Container {
		if err := writeContainerFile(ctx, scanner.Container,
			redirectMutationsPath(v.ScopeTargetID), body); err != nil {
			warnings = append(warnings, "Stored the payload list, but could not write it into the "+
				"scanner's container: "+err.Error())
		}
	}

	return []VectorFinding{{
		VectorID: v.VectorID,
		Tool:     "recollapse",
		Kind:     "payload-list",
		Severity: "info",
		Confidence: "not a vulnerability: this is the payload list the scan will send. REcollapse " +
			"generates mutations and sends nothing itself",
		InsertionPoint: v.InsertionPoint,
		Param:          markableParam(v),
		Method:         v.Method,
		URL:            v.TargetURL(),
		Evidence: itoa(len(lines)) + " mutations of the webhook URL, plus " + itoa(len(extra)) +
			" structural bypass forms from the framework. Each one carries a marker unique to the " +
			"vector it is sent at, so a callback names the parameter that produced it.",
		DetectionMethod: "payload generation",
	}}, warnings
}
