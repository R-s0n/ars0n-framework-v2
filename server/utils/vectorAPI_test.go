package utils

import (
	"strings"
	"testing"
)

// What the results endpoint says about a finding's evidence, which is the first thing an operator
// needs and the thing the last campaign could not answer. 33 of its 42 findings had neither request
// nor response, and the two real ones were indistinguishable from the forty false ones until
// somebody read bytes that were never stored.
func TestTheEvidenceNoteSaysWhatIsActuallyStored(t *testing.T) {
	cases := []struct {
		name, tool, request, response string
		mustSay                       []string
		mustNotSay                    []string
	}{
		{
			name: "both halves captured", tool: "dalfox",
			request: RequestCaptured, response: RequestCaptured,
			mustSay: []string{"dalfox", "response"},
		},
		{
			name: "request captured, no response", tool: "nuclei-dast",
			request: RequestCaptured, response: RequestNone,
			mustSay:    []string{"no response"},
			mustNotSay: []string{"COMPOSED"},
		},
		{
			name: "response captured, request composed", tool: "commix",
			request: RequestReconstructed, response: RequestCaptured,
			mustSay: []string{"composed"},
		},
		{
			name: "nothing but a composed request", tool: "ghauri",
			request: RequestReconstructed, response: RequestNone,
			// The important half: an operator must not read a composed request as a measurement.
			mustSay: []string{"COMPOSED", "Nothing here is measured"},
		},
		{
			name: "nothing at all", tool: "domdig",
			request: RequestNone, response: RequestNone,
			mustSay: []string{"cannot be triaged"},
		},
	}
	for _, c := range cases {
		note := findingEvidenceNote(c.tool, c.request, c.response)
		for _, want := range c.mustSay {
			if !strings.Contains(note, want) {
				t.Errorf("%s: the note never says %q, so the operator cannot tell what they are "+
					"holding: %s", c.name, want, note)
			}
		}
		for _, unwanted := range c.mustNotSay {
			if strings.Contains(note, unwanted) {
				t.Errorf("%s: the note says %q about evidence that was captured: %s",
					c.name, unwanted, note)
			}
		}
	}
}

// The claim has to change with the finding rather than with the tool. dalfox reports an exchange for
// a reflected finding and nothing at all for a static one, so a per-tool sentence would be wrong for
// half of its own rows.
func TestTheEvidenceNoteIsPerFindingRatherThanPerTool(t *testing.T) {
	reflected := findingEvidenceNote("dalfox", RequestCaptured, RequestCaptured)
	static := findingEvidenceNote("dalfox", RequestNone, RequestNone)
	if reflected == static {
		t.Error("two findings from the same tool with completely different evidence got the same note")
	}
	if !strings.Contains(static, "cannot be triaged") {
		t.Errorf("a finding with no bytes at all must say so plainly, got %q", static)
	}
}
