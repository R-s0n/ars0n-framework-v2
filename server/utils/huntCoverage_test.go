package utils

import (
	"strings"
	"testing"
)

// The ssrf seed the contract requires, and the '*' baseline keys. If a future edit drops one of
// these the test fails loudly, because the gate's strength is exactly this list being complete.
var wantSSRFAxisKeys = []string{
	"content_discovery_ffuf_per_host", "param_enum_arjun", "param_enum_x8",
	"vector_scan_recollapse_full", "nuclei_dast_ssrf", "per_url_param_ssrf_canary_fuzz",
	"crawl_depth", "header_ssrf",
}

var wantBaselineAxisKeys = []string{
	"content_discovery", "param_enum", "vector_scan", "nuclei", "deeper_crawl",
}

func TestHuntAxisCatalogInvariants(t *testing.T) {
	cat := huntAxisCatalog()
	if len(cat) == 0 {
		t.Fatal("catalog is empty")
	}
	seen := map[string]bool{}
	for _, ax := range cat {
		if ax.Key == "" {
			t.Errorf("axis with empty Key: %+v", ax)
		}
		if seen[ax.Key] {
			t.Errorf("duplicate axis key %q", ax.Key)
		}
		seen[ax.Key] = true
		if ax.Label == "" || ax.LaunchHint == "" || ax.CompletionProbe == "" || ax.VulnClass == "" {
			t.Errorf("axis %q missing a required field (label/launch_hint/completion_probe/vuln_class)", ax.Key)
		}
		if ax.probe.completedSQL == "" {
			t.Errorf("axis %q has no completed probe SQL", ax.Key)
		}
		if ax.probe.key != ax.Key {
			t.Errorf("axis %q probe.key is %q, want it to match Key", ax.Key, ax.probe.key)
		}
		// No em dashes in anything the operator or the agent reads (standing rule).
		for _, s := range []string{ax.Label, ax.LaunchHint, ax.CompletionProbe} {
			if strings.ContainsRune(s, '—') {
				t.Errorf("axis %q has an em dash in an operator-facing string: %q", ax.Key, s)
			}
		}
	}
}

func TestRequiredAxesSSRFHasBaselineAndSeed(t *testing.T) {
	got := map[string]bool{}
	for _, ax := range RequiredAxes("ssrf") {
		got[ax.Key] = true
	}
	for _, k := range append(append([]string{}, wantBaselineAxisKeys...), wantSSRFAxisKeys...) {
		if !got[k] {
			t.Errorf("RequiredAxes(ssrf) missing %q", k)
		}
	}
}

func TestRequiredAxesUnknownClassIsBaselineOnly(t *testing.T) {
	axes := RequiredAxes("totally-made-up-class")
	if len(axes) != len(wantBaselineAxisKeys) {
		t.Fatalf("unknown class should yield only the %d baseline axes, got %d", len(wantBaselineAxisKeys), len(axes))
	}
	for _, ax := range axes {
		if ax.VulnClass != "*" {
			t.Errorf("unknown class produced a non-baseline axis %q (class %q)", ax.Key, ax.VulnClass)
		}
	}
}

func TestNormalizeVulnClassAliases(t *testing.T) {
	cases := map[string]string{
		"SSRF":                        "ssrf",
		" redirect-ssrf ":             "ssrf",
		"Server Side Request Forgery": "ssrf",
		"open_redirect":               "ssrf",
		"Cross-Site Scripting":        "xss",
		"auth-bypass":                 "access-bypass",
		"sql injection":               "sqli",
		"BOLA":                        "idor",
		"weird-new-class":             "weird-new-class",
	}
	for in, want := range cases {
		if got := normalizeVulnClass(in); got != want {
			t.Errorf("normalizeVulnClass(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAxisStatusPrecedence(t *testing.T) {
	cases := []struct {
		name string
		in   probeOutcome
		want HuntAxisStatus
	}{
		{"not-ran is unknown (fail closed)", probeOutcome{ran: false, completed: 9, hits: 9, inFlight: 9}, AxisUnknown},
		{"completed with hits", probeOutcome{ran: true, completed: 2, hits: 1}, AxisCompletedHits},
		{"completed empty", probeOutcome{ran: true, completed: 2, hits: 0}, AxisCompletedEmpty},
		{"running only", probeOutcome{ran: true, completed: 0, inFlight: 1}, AxisRunning},
		{"nothing", probeOutcome{ran: true}, AxisNotStarted},
	}
	for _, c := range cases {
		if got := axisStatus(c.in); got != c.want {
			t.Errorf("%s: axisStatus = %q, want %q", c.name, got, c.want)
		}
	}
}

// seeded probe outcomes stand in for seeded rows: assembleHuntCoverage is pure.
func TestAssembleCoverageFailClosedOnMissingProbe(t *testing.T) {
	axes := RequiredAxes("ssrf")
	// Seed every axis complete EXCEPT leave two out of the map entirely (simulating unreadable tables).
	outcomes := map[string]probeOutcome{}
	for i, ax := range axes {
		if i < 2 {
			continue // missing -> unknown -> fail closed
		}
		outcomes[ax.Key] = probeOutcome{ran: true, completed: 1}
	}
	cov := assembleHuntCoverage(axes, "ssrf", outcomes)
	if cov.Exhaustible {
		t.Error("coverage must NOT be exhaustible while any axis is unknown")
	}
	if len(cov.UnknownAxes) != 2 {
		t.Errorf("want 2 unknown axes, got %d (%v)", len(cov.UnknownAxes), cov.UnknownAxes)
	}
	// Every unknown axis must appear in not_started with a launch hint so the gate can print it.
	hints := 0
	for _, a := range cov.NotStarted {
		if a.LaunchHint != "" {
			hints++
		}
	}
	if hints != len(cov.NotStarted) || len(cov.NotStarted) < 2 {
		t.Errorf("every not_started axis needs a launch hint; got %d hints over %d not_started", hints, len(cov.NotStarted))
	}
}

func TestAssembleCoverageEarnedWhenAllComplete(t *testing.T) {
	axes := RequiredAxes("ssrf")
	outcomes := map[string]probeOutcome{}
	for i, ax := range axes {
		if i%2 == 0 {
			outcomes[ax.Key] = probeOutcome{ran: true, completed: 1, hits: 1} // completed_hits
		} else {
			outcomes[ax.Key] = probeOutcome{ran: true, completed: 1} // completed_empty
		}
	}
	cov := assembleHuntCoverage(axes, "ssrf", outcomes)
	if !cov.Exhaustible {
		t.Error("coverage should be EARNED/exhaustible when every required axis has a completed run")
	}
	if cov.Completed != cov.Total {
		t.Errorf("completed %d != total %d", cov.Completed, cov.Total)
	}
	if len(cov.NotStarted) != 0 {
		t.Errorf("not_started must be empty when exhaustible, got %d", len(cov.NotStarted))
	}
	if strings.ContainsRune(cov.Message, '—') {
		t.Error("coverage message contains an em dash")
	}
}

func TestAssembleCoveragePartialExcludesRunningFromNotStarted(t *testing.T) {
	axes := RequiredAxes("ssrf")
	if len(axes) < 3 {
		t.Fatalf("expected several ssrf axes, got %d", len(axes))
	}
	outcomes := map[string]probeOutcome{}
	outcomes[axes[0].Key] = probeOutcome{ran: true, completed: 1} // completed_empty
	outcomes[axes[1].Key] = probeOutcome{ran: true, inFlight: 1}  // running (already launched)
	for _, ax := range axes[2:] {
		outcomes[ax.Key] = probeOutcome{ran: true} // not_started
	}
	cov := assembleHuntCoverage(axes, "ssrf", outcomes)
	if cov.Exhaustible {
		t.Error("partial coverage must not be exhaustible")
	}
	for _, a := range cov.NotStarted {
		if a.Key == axes[1].Key {
			t.Errorf("running axis %q must NOT be in not_started (it is already launched)", a.Key)
		}
		if a.Status != AxisNotStarted {
			t.Errorf("not_started axis %q has status %q", a.Key, a.Status)
		}
	}
	if cov.Completed != 1 {
		t.Errorf("want 1 completed, got %d", cov.Completed)
	}
}
