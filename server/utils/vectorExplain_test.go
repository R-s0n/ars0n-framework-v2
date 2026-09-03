package utils

import (
	"strings"
	"testing"
)

// The reason this file exists: every entry has to state the LIMIT of the evidence, not just the
// claim. A results modal that only says "SQL injection found" is how an operator comes to believe a
// reflection is an execution, or a status code is access.
func TestEveryExplanationSaysWhatItDidNotProve(t *testing.T) {
	for key, entry := range findingExplanations {
		if strings.TrimSpace(entry.Title) == "" {
			t.Errorf("%s has no title", key)
		}
		if strings.TrimSpace(entry.WhatItProved) == "" {
			t.Errorf("%s does not say what the tool proved", key)
		}
		if strings.TrimSpace(entry.WhatItDidNotProve) == "" {
			t.Errorf("%s does not say what the tool did NOT prove, which is the field that stops a "+
				"lead being read as a finding", key)
		}
	}
}

// Every tool that can produce a finding needs a default, or a kind we have not enumerated yet
// arrives in the modal with no explanation at all.
func TestEveryToolHasADefaultExplanation(t *testing.T) {
	for _, tool := range []string{"dalfox", "domdig", "xssfuzz", "sqlmap", "ghauri",
		"sqlidetector", "pphack", "forbidden", "nomore403"} {
		if _, ok := findingExplanations[tool+"|*"]; !ok {
			t.Errorf("%s has no default entry, so an unenumerated kind explains nothing", tool)
		}
	}
}

// The fallback chain: exact kind, then the tool default, then empty rather than wrong.
func TestExplainFallsBackFromKindToToolToNothing(t *testing.T) {
	if got := ExplainFinding("dalfox", "V"); !strings.Contains(got.WhatItDidNotProve, "headless") {
		t.Error("the exact dalfox V entry should win")
	}
	fallback := ExplainFinding("dalfox", "some-new-kind")
	exact := ExplainFinding("dalfox", "V")
	if fallback.Title == "" || fallback.Title == exact.Title {
		t.Errorf("an unknown kind should fall back to the tool default and get its own text, got %q",
			fallback.Title)
	}
	if got := ExplainFinding("a-tool-we-do-not-have", "x"); got.Title != "" {
		t.Errorf("an unknown tool should explain nothing rather than something wrong, got %q", got.Title)
	}
}

// The specific overclaims this project actually made. Each of these was believed at some point
// during the ginandjuice.shop engagement and each cost real time.
func TestTheKnownOverclaimsAreExplicitlyContradicted(t *testing.T) {
	cases := []struct {
		tool, kind, mustMention string
		why                     string
	}{
		{"dalfox", "V", "headless",
			"dalfox ships no headless browser of its own, so a parsed-position V is not execution"},
		{"dalfox", "A", "static analysis",
			"an A finding is static analysis; no payload was sent, so there is no exchange to show"},
		{"xssfuzz", "R", "substring",
			"xssFuzz does a plain substring test and knows nothing about context"},
		{"sqlidetector", "*", "exception",
			"an error signature is matched by any app that surfaces its exception handler"},
		{"pphack", "client-side-prototype-pollution", "gadget",
			"pollution without a gadget is a weakness, not an impact"},
		{"forbidden", "access-control-bypass", "denial",
			"the tool's only content baseline is the denial page, never the ordinary page"},
	}
	for _, c := range cases {
		got := ExplainFinding(c.tool, c.kind)
		blob := strings.ToLower(got.WhatItProved + " " + got.WhatItDidNotProve + " " +
			got.FalsePositive + " " + got.SeverityNote)
		if !strings.Contains(blob, strings.ToLower(c.mustMention)) {
			t.Errorf("%s/%s never mentions %q: %s", c.tool, c.kind, c.mustMention, c.why)
		}
	}
}

// A blind technique and a data-returning one are different findings with different impact, and the
// text has to draw that line or an operator cannot triage between them.
func TestBlindAndDataReturningSQLiAreDescribedDifferently(t *testing.T) {
	blind := ExplainFinding("ghauri", "boolean-based blind")
	union := ExplainFinding("sqlmap", "UNION query")

	if !strings.Contains(strings.ToLower(blind.WhatItDidNotProve), "data") {
		t.Error("a blind finding must say it retrieved no data")
	}
	unionBlob := strings.ToLower(union.WhatItProved + " " + union.WhyItMatters + " " + union.Title)
	if !strings.Contains(unionBlob, "data") {
		t.Error("a UNION finding must say data actually crossed into the response")
	}
	if blind.FalsePositive == union.FalsePositive {
		t.Error("these two fail in different ways and must not share false positive guidance")
	}
}
