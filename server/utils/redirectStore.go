package utils

import (
	"context"
	"fmt"
	"strings"
)

// Turning REcollapse's output into a scan.
//
// REcollapse prints mutations and stops; it has no network code and never sends one. Until this
// section was reshaped its "scan" therefore produced no findings at all, only AMMUNITION: the list
// went onto a shared volume and nuclei fired it from a template this project maintained.
//
// Now the framework sends the list itself, in redirectProbe.go, so this function is the seam between
// the two: read what REcollapse printed, hand it to the prober, return what came back. The shared
// volume, the cross-container write and the per-target payload file are all gone with it, and so is
// the failure they carried, where a scan that ran before REcollapse had ever run sent only the
// framework's own forms and said so in a warning nobody reads.

// runREcollapseProbe parses the mutation list and sends it at one vector.
//
// The findings returned are the IN-BAND ones only: a redirect to the webhook host, or a response
// carrying a local file, a cloud metadata document or an internal service banner. The out-of-band
// half is collected once at the end of the scan by collectWebhookFindings, because a callback can
// arrive seconds after the response that triggered it.
func runREcollapseProbe(ctx context.Context, v VectorInput, settings map[string]any,
	stdout string) ([]VectorFinding, []string, error) {

	var mutations []string
	seen := map[string]bool{}
	for _, line := range strings.Split(stripANSI(stdout), "\n") {
		line = strings.TrimSpace(line)
		// REcollapse prints one mutation per line and nothing else, but a line that lost its token is
		// a payload that cannot be attributed to anything, and sending it would produce a callback
		// nobody can match to a parameter.
		if line == "" || seen[line] || !strings.Contains(line, vectorTokenPlaceholder) {
			continue
		}
		seen[line] = true
		mutations = append(mutations, line)
	}

	// AN ERROR, not a warning. REcollapse printing nothing usable means the payload generator did not
	// run, and a vector whose generator did not run has not been tested. The previous version returned
	// a warning here and the runner filed the vector clean, which is exactly the fail-open this
	// framework keeps rediscovering: the operator reads "no SSRF" from a scan that sent nothing.
	//
	// The framework's own structural forms are NOT a consolation prize. They are built from the
	// webhook inside ProbeSSRFVector, which is never reached from here.
	if len(mutations) == 0 {
		return nil, nil, fmt.Errorf("UNTESTED: REcollapse produced no mutations carrying the token " +
			"placeholder, so nothing was sent and this vector's result is unknown rather than clean. " +
			"Check the Listening Webhook URL on the Webhook tab, and check the REcollapse trace for a " +
			"rejected argument")
	}

	result := ProbeSSRFVector(ctx, v, mutations, settings)
	warnings := result.Warnings

	if result.Untested != "" {
		// Findings already proved are kept: they happened, whatever stopped the run afterwards.
		return result.Findings, warnings, fmt.Errorf("UNTESTED: %s", result.Untested)
	}

	// Reported even when nothing was found, because "0 findings" and "0 findings from 3,411 requests"
	// are different claims and only the second one is evidence.
	if result.Sent > 0 && len(result.Findings) == 0 {
		summary := "Sent " + itoa(result.Sent) + " payloads and nothing answered in band."
		if result.Failed > 0 {
			summary += " " + itoa(result.Failed) + " of them failed at the transport layer, which is " +
				"ordinary for payloads aimed at unroutable addresses but is worth reading if the number " +
				"is most of them."
		}
		summary += " Any blind callback is decided at the end of the scan, when the results URL is read."
		warnings = append(warnings, summary)
	}
	return result.Findings, warnings, nil
}
