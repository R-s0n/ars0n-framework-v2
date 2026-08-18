package utils

import (
	"strings"
	"testing"
)

// A sniper request fills one marked position and leaves the rest at their resting values. Rendering
// every marker as injected shows the operator a request that was never sent, and for a finding whose
// whole meaning is "this slot did something different" that is the one detail that has to be right.
func TestSniperDetailMarksOnlyTheCarryingPosition(t *testing.T) {
	step := FuzzStep{
		FFUFMode:   "sniper",
		RawRequest: "POST /body HTTP/1.1\nHost: t.test\n\n{\"a\":\"{{p01}}\",\"b\":\"{{p02}}\"}",
		Positions: []FuzzPosition{
			{Token: "{{p01}}", RestingValue: "restA", Role: "body_value"},
			{Token: "{{p02}}", RestingValue: "restB", Role: "body_value"},
		},
	}
	values := map[string]string{
		keywordForToken("{{p01}}"): "restA",
		keywordForToken("{{p02}}"): "is_admin",
	}
	parts, rendered := renderFuzzFindingRequest(step, values,
		map[string]string{"{{p01}}": "body_value", "{{p02}}": "body_value"},
		map[string]bool{"{{p02}}": true})

	if want := "{\"a\":\"restA\",\"b\":\"is_admin\"}"; !strings.Contains(rendered, want) {
		t.Errorf("rendered request should be the bytes sent, %q missing from:\n%s", want, rendered)
	}
	var carried, injected int
	for _, p := range parts {
		if p.Injected {
			injected++
		}
		if p.Carried {
			carried++
			if p.Token != "{{p02}}" {
				t.Errorf("wrong position marked as carrying: %s", p.Token)
			}
		}
	}
	if injected != 2 || carried != 1 {
		t.Errorf("both positions are spans but only one carried: injected=%d carried=%d", injected, carried)
	}

	// A finding stored before attribution worked carries ffuf's keyword, which names no position. It
	// must not be silently matched to one.
	if fuzzStepHasToken(step, "FUZZ") || fuzzStepHasToken(step, "") {
		t.Error("a keyword that is not a position token must not resolve to one")
	}
	if !fuzzStepHasToken(step, "{{p01}}") {
		t.Error("a real position token should resolve")
	}
}
