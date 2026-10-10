package utils

// HUNT COVERAGE: has the automated work that EARNS an "exhausted" verdict actually completed?
//
// THE PROBLEM THIS EXISTS FOR. The agent declares a goal "exhausted / blocked / no path / done" after
// a short burst of manual probing (a dozen one-off curl calls) instead of launching the long-running
// automated runs (ffuf content discovery, arjun/x8 param enumeration, the full vector scans,
// nuclei, per-param SSRF-canary fuzzing) and letting them run for hours or days. The root cause is
// that it judges completeness by ELAPSED TIME and EFFORT SPENT, a frame it cannot actually perceive.
//
// THE FIX THIS FILE PROVIDES. A data-driven catalog of the automated hunting AXES that must each
// reach a COMPLETED run before a goal of a given vuln_class can be called exhausted, and a
// deterministic computation of how many of those axes have actually completed for a target, read
// straight from the run tables. "Exhausted" is then a state the agent EARNS by completed runs, never
// one it asserts from the clock. The MCP gate (keep_hunting / whats_next / manage_goals) reads the
// endpoint this file serves and refuses a soft-done verdict while required axes are incomplete.
//
// FAIL CLOSED. A probe that cannot be read is 'unknown', which is treated as NOT complete, so an
// unreadable or absent run signal keeps the goal un-exhaustible and the agent errs toward MORE
// hunting, never less. This mirrors the methodology advisor's rule that a failed query is never a
// zero (methodologyAdvisor.go). No AI is in this path: the catalog and the coverage are computed
// from tables alone, so the gate built on top of it is deterministic.
//
// No em dashes anywhere in the operator-facing strings in this file (standing rule; huntCoverage_test
// asserts it, alongside the mcp-server guidance test that enforces the same on the JS side).

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"
)

// HuntAxisStatus is the per-axis verdict. Only completed_hits and completed_empty count as COMPLETE
// for exhaustibility; running, not_started and unknown all keep the goal un-exhaustible.
type HuntAxisStatus string

const (
	AxisNotStarted     HuntAxisStatus = "not_started"
	AxisRunning        HuntAxisStatus = "running"
	AxisCompletedHits  HuntAxisStatus = "completed_hits"
	AxisCompletedEmpty HuntAxisStatus = "completed_empty"
	// AxisUnknown is the FAIL-CLOSED state: the probe could not be read. Never treated as complete.
	AxisUnknown HuntAxisStatus = "unknown"
)

// axisProbe is the deterministic DB signal for one axis. completedSQL MUST return exactly two ints
// for $1 = scope_target_id: (number of terminal-COMPLETED runs, number of those that found hits).
// runningSQL returns one int, the number of in-flight (pending/running) runs, and may be empty when
// an axis has no meaningful in-flight notion. $1 may appear several times; pgx binds it once.
type axisProbe struct {
	key          string
	completedSQL string
	runningSQL   string
}

// HuntAxis is one required automated hunting axis: what to run, how to know it completed, and the
// exact command that launches it. vulnClass "*" is the baseline that applies to every class.
type HuntAxis struct {
	Key             string `json:"key"`
	Label           string `json:"label"`
	VulnClass       string `json:"vuln_class"`
	LaunchHint      string `json:"launch_hint"`
	CompletionProbe string `json:"completion_probe"`
	// probe is unexported so it never serializes; the human-readable CompletionProbe above is what the
	// MCP and UI see.
	probe axisProbe
}

// probeOutcome is what one axis's probe produced. ran=false means the completed-probe query failed,
// which is the fail-closed path to AxisUnknown.
type probeOutcome struct {
	ran       bool
	completed int
	hits      int
	inFlight  int
}

// CoverageAxisResult is one axis in the coverage report.
type CoverageAxisResult struct {
	Key             string         `json:"key"`
	Label           string         `json:"label"`
	VulnClass       string         `json:"vuln_class"`
	Status          HuntAxisStatus `json:"status"`
	CompletionProbe string         `json:"completion_probe"`
	CompletedRuns   int            `json:"completed_runs"`
	Hits            int            `json:"hits"`
	InFlight        int            `json:"in_flight"`
	// LaunchHint is attached only when the axis is NOT complete, so the gate can print the exact
	// command to fire next.
	LaunchHint string `json:"launch_hint,omitempty"`
}

// HuntCoverage is the whole report for one target and one vuln_class.
type HuntCoverage struct {
	VulnClass string               `json:"vuln_class"`
	Axes      []CoverageAxisResult `json:"axes"`
	Completed int                  `json:"completed"`
	Total     int                  `json:"total"`
	// Exhaustible is true ONLY when every required axis has a completed run AND none is unknown. It is
	// the one signal the MCP gate reads to decide whether an "exhausted" verdict is EARNED.
	Exhaustible bool `json:"exhaustible"`
	// NotStarted lists the axes the agent still has to LAUNCH (status not_started or unknown), each
	// carrying its exact launch command. Running axes are omitted here: they are already launched.
	NotStarted []CoverageAxisResult `json:"not_started"`
	// UnknownAxes names the fail-closed axes, so a caller can tell "not run" from "could not read".
	UnknownAxes []string `json:"unknown_axes,omitempty"`
	Message     string   `json:"message"`
}

// huntAxisCatalog is the single source of truth. Seeded richly for ssrf and with a baseline '*' set
// that applies to every class. Trivially extensible: add a block of axes with a new VulnClass value
// (e.g. "xss", "sqli", "idor") and they are picked up by RequiredAxes automatically. Every axis maps
// to a confirmed run table and its confirmed terminal-success literal:
//   vector_scans.status='completed'  arjun_scans/x8_scans.status='success'  fuzz_runs.status='success'
//   nuclei_scans.status='success'    endpoint_scan_runs.status='success'
func huntAxisCatalog() []HuntAxis {
	axes := []HuntAxis{
		// ---- the '*' BASELINE: applies to every class ------------------------------------------------
		{
			Key: "content_discovery", VulnClass: "*",
			Label:      "Content discovery at the web root (FUZZ in the path)",
			LaunchHint: `manage_fuzz action:"run" on a flow with purpose content-discovery and FUZZ in the PATH at the web root`,
			CompletionProbe: "A fuzz_runs row with status='success' on a fuzz_flows row whose purpose='content-discovery' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE r.status = 'success'),
    count(*) FILTER (WHERE r.status = 'success' AND COALESCE(r.findings_new,0) > 0)
  FROM fuzz_runs r JOIN fuzz_flows f ON f.id = r.flow_id
  WHERE r.scope_target_id = $1 AND f.purpose = 'content-discovery'`,
				runningSQL: `SELECT count(*) FROM fuzz_runs r JOIN fuzz_flows f ON f.id = r.flow_id
  WHERE r.scope_target_id = $1 AND f.purpose = 'content-discovery' AND r.status IN ('pending','running')`,
			},
		},
		{
			Key: "param_enum", VulnClass: "*",
			Label:      "Hidden parameter enumeration (arjun or x8)",
			LaunchHint: `run_scan tool:"arjun" (and/or run_scan tool:"x8")`,
			CompletionProbe: "An arjun_scans OR x8_scans row with status='success' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    (SELECT count(*) FROM arjun_scans WHERE scope_target_id = $1 AND status = 'success')
  + (SELECT count(*) FROM x8_scans   WHERE scope_target_id = $1 AND status = 'success'),
    (SELECT count(*) FROM arjun_scans WHERE scope_target_id = $1 AND status = 'success' AND COALESCE(parameters_found,0) > 0)
  + (SELECT count(*) FROM x8_scans   WHERE scope_target_id = $1 AND status = 'success' AND COALESCE(parameters_found,0) > 0)`,
				runningSQL: `SELECT
    (SELECT count(*) FROM arjun_scans WHERE scope_target_id = $1 AND status IN ('pending','running'))
  + (SELECT count(*) FROM x8_scans   WHERE scope_target_id = $1 AND status IN ('pending','running'))`,
			},
		},
		{
			Key: "vector_scan", VulnClass: "*",
			Label:      "At least one vector scan completed for the goal's class",
			LaunchHint: `manage_<class> action:"run" for the goal's class (e.g. manage_redirect, manage_sqli, manage_xss)`,
			CompletionProbe: "A vector_scans row with status='completed' for this target (any category/tool).",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'completed'),
    count(*) FILTER (WHERE status = 'completed' AND COALESCE(finding_count,0) > 0)
  FROM vector_scans WHERE scope_target_id = $1`,
				runningSQL: `SELECT count(*) FROM vector_scans WHERE scope_target_id = $1 AND status NOT IN ('completed','error')`,
			},
		},
		{
			Key: "nuclei", VulnClass: "*",
			Label:      "Nuclei run (surface templates or DAST)",
			LaunchHint: `run_scan tool:"nuclei" (surface), or manage_redirect action:"run" which runs nuclei-dast`,
			CompletionProbe: "A nuclei_scans row with status='success', OR a vector_scans row with tool='nuclei-dast' and status='completed', for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    (SELECT count(*) FROM nuclei_scans  WHERE scope_target_id = $1 AND status = 'success')
  + (SELECT count(*) FROM vector_scans  WHERE scope_target_id = $1 AND tool = 'nuclei-dast' AND status = 'completed'),
    (SELECT count(*) FROM nuclei_scans  WHERE scope_target_id = $1 AND status = 'success' AND COALESCE(result,'') NOT IN ('','[]'))
  + (SELECT count(*) FROM vector_scans  WHERE scope_target_id = $1 AND tool = 'nuclei-dast' AND status = 'completed' AND COALESCE(finding_count,0) > 0)`,
				runningSQL: `SELECT
    (SELECT count(*) FROM nuclei_scans WHERE scope_target_id = $1 AND status IN ('pending','running'))
  + (SELECT count(*) FROM vector_scans WHERE scope_target_id = $1 AND tool = 'nuclei-dast' AND status NOT IN ('completed','error'))`,
			},
		},
		{
			Key: "deeper_crawl", VulnClass: "*",
			Label:      "Deeper endpoint scan / crawl completed",
			LaunchHint: `run_endpoint_scan to consolidate and scan endpoints, then re-run manage_fuzz content discovery recursively at deeper path depth`,
			CompletionProbe: "An endpoint_scan_runs row with status='success' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'success'),
    count(*) FILTER (WHERE status = 'success' AND COALESCE(total_endpoints,0) > 0)
  FROM endpoint_scan_runs WHERE scope_target_id = $1`,
				runningSQL: `SELECT count(*) FROM endpoint_scan_runs WHERE scope_target_id = $1 AND status IN ('pending','running')`,
			},
		},

		// ---- ssrf: the richly seeded class ----------------------------------------------------------
		{
			Key: "content_discovery_ffuf_per_host", VulnClass: "ssrf",
			Label:      "ffuf content discovery per host (SSRF reaches unlinked internal routes)",
			LaunchHint: `manage_fuzz action:"run" on a content-discovery flow (FUZZ in path) against every in-scope host`,
			CompletionProbe: "Same signal as the baseline content_discovery axis: a fuzz_runs success on a content-discovery flow. One content discovery run satisfies both.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE r.status = 'success'),
    count(*) FILTER (WHERE r.status = 'success' AND COALESCE(r.findings_new,0) > 0)
  FROM fuzz_runs r JOIN fuzz_flows f ON f.id = r.flow_id
  WHERE r.scope_target_id = $1 AND f.purpose = 'content-discovery'`,
				runningSQL: `SELECT count(*) FROM fuzz_runs r JOIN fuzz_flows f ON f.id = r.flow_id
  WHERE r.scope_target_id = $1 AND f.purpose = 'content-discovery' AND r.status IN ('pending','running')`,
			},
		},
		{
			Key: "param_enum_arjun", VulnClass: "ssrf",
			Label:      "Arjun hidden-parameter enumeration (SSRF hides in unlisted params)",
			LaunchHint: `run_scan tool:"arjun"`,
			CompletionProbe: "An arjun_scans row with status='success' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'success'),
    count(*) FILTER (WHERE status = 'success' AND COALESCE(parameters_found,0) > 0)
  FROM arjun_scans WHERE scope_target_id = $1`,
				runningSQL: `SELECT count(*) FROM arjun_scans WHERE scope_target_id = $1 AND status IN ('pending','running')`,
			},
		},
		{
			Key: "param_enum_x8", VulnClass: "ssrf",
			Label:      "x8 hidden-parameter enumeration across query/body/headers/cookies",
			LaunchHint: `run_scan tool:"x8"`,
			CompletionProbe: "An x8_scans row with status='success' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'success'),
    count(*) FILTER (WHERE status = 'success' AND COALESCE(parameters_found,0) > 0)
  FROM x8_scans WHERE scope_target_id = $1`,
				runningSQL: `SELECT count(*) FROM x8_scans WHERE scope_target_id = $1 AND status IN ('pending','running')`,
			},
		},
		{
			Key: "vector_scan_recollapse_full", VulnClass: "ssrf",
			Label:      "REcollapse canary scan over the redirect-ssrf vectors",
			LaunchHint: `manage_redirect action:"run" (the redirect-ssrf vector scan runs REcollapse with the canary prefix)`,
			CompletionProbe: "A vector_scans row with category='redirect-ssrf', tool='recollapse', status='completed' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'completed'),
    count(*) FILTER (WHERE status = 'completed' AND COALESCE(finding_count,0) > 0)
  FROM vector_scans WHERE scope_target_id = $1 AND category = 'redirect-ssrf' AND tool = 'recollapse'`,
				runningSQL: `SELECT count(*) FROM vector_scans WHERE scope_target_id = $1 AND category = 'redirect-ssrf' AND tool = 'recollapse' AND status NOT IN ('completed','error')`,
			},
		},
		{
			Key: "nuclei_dast_ssrf", VulnClass: "ssrf",
			Label:      "Nuclei DAST over the redirect-ssrf vectors (the detector)",
			LaunchHint: `manage_redirect action:"run" (the redirect-ssrf vector scan runs nuclei-dast)`,
			CompletionProbe: "A vector_scans row with category='redirect-ssrf', tool='nuclei-dast', status='completed' for this target.",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'completed'),
    count(*) FILTER (WHERE status = 'completed' AND COALESCE(finding_count,0) > 0)
  FROM vector_scans WHERE scope_target_id = $1 AND category = 'redirect-ssrf' AND tool = 'nuclei-dast'`,
				runningSQL: `SELECT count(*) FROM vector_scans WHERE scope_target_id = $1 AND category = 'redirect-ssrf' AND tool = 'nuclei-dast' AND status NOT IN ('completed','error')`,
			},
		},
		{
			Key: "per_url_param_ssrf_canary_fuzz", VulnClass: "ssrf",
			Label:      "Per-URL parameter value fuzzing with an out-of-band SSRF canary",
			LaunchHint: `manage_fuzz action:"run" on a value/param fuzz flow (purpose other than content-discovery); put an out-of-band SSRF canary in every fuzzed value`,
			CompletionProbe: "A fuzz_runs row with status='success' on a fuzz_flows row whose purpose is NOT 'content-discovery' for this target (a value/parameter fuzzing pass).",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE r.status = 'success'),
    count(*) FILTER (WHERE r.status = 'success' AND COALESCE(r.findings_new,0) > 0)
  FROM fuzz_runs r JOIN fuzz_flows f ON f.id = r.flow_id
  WHERE r.scope_target_id = $1 AND f.purpose <> 'content-discovery'`,
				runningSQL: `SELECT count(*) FROM fuzz_runs r JOIN fuzz_flows f ON f.id = r.flow_id
  WHERE r.scope_target_id = $1 AND f.purpose <> 'content-discovery' AND r.status IN ('pending','running')`,
			},
		},
		{
			Key: "crawl_depth", VulnClass: "ssrf",
			Label:      "Deeper endpoint scan / crawl completed (SSRF surface widens with depth)",
			LaunchHint: `run_endpoint_scan, then re-run content discovery recursively at deeper path depth`,
			CompletionProbe: "An endpoint_scan_runs row with status='success' for this target (same signal as baseline deeper_crawl).",
			probe: axisProbe{
				completedSQL: `SELECT
    count(*) FILTER (WHERE status = 'success'),
    count(*) FILTER (WHERE status = 'success' AND COALESCE(total_endpoints,0) > 0)
  FROM endpoint_scan_runs WHERE scope_target_id = $1`,
				runningSQL: `SELECT count(*) FROM endpoint_scan_runs WHERE scope_target_id = $1 AND status IN ('pending','running')`,
			},
		},
		{
			Key: "header_ssrf", VulnClass: "ssrf",
			Label:      "Header-based SSRF exercised (X-Forwarded-For/-Host, Host, etc.)",
			LaunchHint: `consolidate header insertion-point vectors then manage_redirect action:"run"; or manage_fuzz with X-Forwarded-For / X-Forwarded-Host / Host carrying an out-of-band canary`,
			CompletionProbe: "A completed redirect-ssrf vector_scans row AND at least one attack_vectors row with insertion_point='header' for this target (a header vector was actually scanned). hits is not tracked separately for this axis, so it reports completed_empty once both hold.",
			probe: axisProbe{
				completedSQL: `SELECT
    CASE WHEN EXISTS(SELECT 1 FROM vector_scans WHERE scope_target_id = $1 AND category = 'redirect-ssrf' AND status = 'completed')
          AND EXISTS(SELECT 1 FROM attack_vectors WHERE scope_target_id = $1 AND deleted_at IS NULL AND insertion_point = 'header')
         THEN 1 ELSE 0 END,
    0`,
				runningSQL: "",
			},
		},
	}
	// Keep probe.key in lockstep with Key so the DB layer logs the right axis on a failure without the
	// catalog having to repeat the key.
	for i := range axes {
		axes[i].probe.key = axes[i].Key
	}
	return axes
}

// vulnClassAliases folds the free-text goal.vuln_class onto the canonical catalog keys. An unknown
// class is left as its cleaned self and simply matches no class block, so only the '*' baseline
// applies: a real floor, never an empty requirement.
var vulnClassAliases = map[string]string{
	"ssrf":                         "ssrf",
	"redirect-ssrf":                "ssrf",
	"open-redirect":                "ssrf",
	"redirect":                     "ssrf",
	"server-side-request-forgery":  "ssrf",
	"xss":                          "xss",
	"cross-site-scripting":         "xss",
	"sqli":                         "sqli",
	"sql-injection":                "sqli",
	"idor":                         "idor",
	"bola":                         "idor",
	"auth-bypass":                  "access-bypass",
	"access-bypass":                "access-bypass",
	"authz":                        "access-bypass",
	"access-control":               "access-bypass",
}

// normalizeVulnClass lowercases, trims and unifies separators, then applies the alias map.
func normalizeVulnClass(s string) string {
	c := strings.ToLower(strings.TrimSpace(s))
	c = strings.ReplaceAll(c, " ", "-")
	c = strings.ReplaceAll(c, "_", "-")
	for strings.Contains(c, "--") {
		c = strings.ReplaceAll(c, "--", "-")
	}
	if canon, ok := vulnClassAliases[c]; ok {
		return canon
	}
	return c
}

// RequiredAxes is the set of axes that must each complete before a goal of this class is exhaustible:
// the '*' baseline plus the axes tagged with the normalized class. Deduplicated by key (first wins),
// baseline first so its ordering is stable.
func RequiredAxes(vulnClass string) []HuntAxis {
	class := normalizeVulnClass(vulnClass)
	seen := map[string]bool{}
	out := make([]HuntAxis, 0, 16)
	for _, ax := range huntAxisCatalog() {
		if ax.VulnClass != "*" && ax.VulnClass != class {
			continue
		}
		if seen[ax.Key] {
			continue
		}
		seen[ax.Key] = true
		out = append(out, ax)
	}
	return out
}

// axisStatus is the pure state machine from a probe outcome. Precedence, highest first:
// unknown (fail-closed) > completed_hits > completed_empty > running > not_started.
func axisStatus(o probeOutcome) HuntAxisStatus {
	if !o.ran {
		return AxisUnknown
	}
	if o.completed > 0 && o.hits > 0 {
		return AxisCompletedHits
	}
	if o.completed > 0 {
		return AxisCompletedEmpty
	}
	if o.inFlight > 0 {
		return AxisRunning
	}
	return AxisNotStarted
}

// axisIsComplete: only a completed run (with or without hits) counts toward exhaustibility.
func axisIsComplete(s HuntAxisStatus) bool {
	return s == AxisCompletedHits || s == AxisCompletedEmpty
}

// assembleHuntCoverage is the whole judgement, kept pure so it is testable without a database
// (mirrors adviseOnState in methodologyAdvisor.go). outcomes is keyed by axis Key; a missing entry
// is treated as a failed probe, i.e. AxisUnknown, which is the fail-closed default.
func assembleHuntCoverage(axes []HuntAxis, vulnClass string, outcomes map[string]probeOutcome) HuntCoverage {
	c := HuntCoverage{
		VulnClass:  normalizeVulnClass(vulnClass),
		Axes:       make([]CoverageAxisResult, 0, len(axes)),
		NotStarted: make([]CoverageAxisResult, 0),
	}
	anyUnknown := false
	for _, ax := range axes {
		o, ok := outcomes[ax.Key]
		if !ok {
			o = probeOutcome{ran: false} // fail closed: an absent probe is unknown, never complete
		}
		st := axisStatus(o)
		res := CoverageAxisResult{
			Key: ax.Key, Label: ax.Label, VulnClass: ax.VulnClass, Status: st,
			CompletionProbe: ax.CompletionProbe,
			CompletedRuns:   o.completed, Hits: o.hits, InFlight: o.inFlight,
		}
		c.Total++
		if axisIsComplete(st) {
			c.Completed++
		} else {
			res.LaunchHint = ax.LaunchHint
			// NotStarted is what the gate tells the agent to LAUNCH. Running axes are already launched,
			// so they stay out of this list but still read as not-complete for exhaustibility.
			if st == AxisNotStarted || st == AxisUnknown {
				c.NotStarted = append(c.NotStarted, res)
			}
		}
		if st == AxisUnknown {
			anyUnknown = true
			c.UnknownAxes = append(c.UnknownAxes, ax.Key)
		}
		c.Axes = append(c.Axes, res)
	}
	// EARNED, not asserted: every required axis has a completed run and none is unknown. Fail-closed:
	// a single unknown axis holds exhaustible false even when the completed count equals the total.
	c.Exhaustible = c.Total > 0 && c.Completed == c.Total && !anyUnknown
	c.Message = coverageMessage(c)
	return c
}

// coverageMessage is the operator-facing summary. No em dashes. It carries the exact framing the gate
// reuses: exhausted is earned by completed runs, not elapsed time.
func coverageMessage(c HuntCoverage) string {
	if c.Total == 0 {
		return "No required hunting axes are defined for this class yet. The baseline axes always apply; " +
			"set a goal vuln_class to add class-specific axes."
	}
	if c.Exhaustible {
		return fmt.Sprintf("All %d required axes have completed runs (coverage %d of %d). Exhausted is now "+
			"EARNED: an honest \"ran everything, coverage %d of %d, no PoC\" report is permitted for this "+
			"goal. A confirmed finding still reopens the hunt.", c.Total, c.Completed, c.Total, c.Completed, c.Total)
	}
	return fmt.Sprintf("Coverage %d of %d required axes completed. Exhausted is earned by completed runs, "+
		"not elapsed time. Launch the not_started axes below and let them run for hours or days; you are "+
		"notified on completion.", c.Completed, c.Total)
}

// runAxisProbe executes one axis's probe against the live pool. FAIL CLOSED: if the completed query
// errors, the outcome is ran=false, which assembleHuntCoverage renders as AxisUnknown and never
// counts as complete. A failure of the advisory running query does NOT taint completeness.
func runAxisProbe(ctx context.Context, scopeTargetID string, p axisProbe) probeOutcome {
	var completed, hits int
	if err := dbPool.QueryRow(ctx, p.completedSQL, scopeTargetID).Scan(&completed, &hits); err != nil {
		log.Printf("[HUNT-COVERAGE] axis %q completed-probe failed (fail-closed to unknown): %v", p.key, err)
		return probeOutcome{ran: false}
	}
	o := probeOutcome{ran: true, completed: completed, hits: hits}
	if p.runningSQL != "" {
		var inFlight int
		if err := dbPool.QueryRow(ctx, p.runningSQL, scopeTargetID).Scan(&inFlight); err != nil {
			log.Printf("[HUNT-COVERAGE] axis %q running-probe failed (completeness already read): %v", p.key, err)
		} else {
			o.inFlight = inFlight
		}
	}
	return o
}

// ComputeHuntCoverage reads every required axis for the target and class and returns the report.
func ComputeHuntCoverage(ctx context.Context, scopeTargetID, vulnClass string) HuntCoverage {
	axes := RequiredAxes(vulnClass)
	outcomes := make(map[string]probeOutcome, len(axes))
	for _, ax := range axes {
		outcomes[ax.Key] = runAxisProbe(ctx, scopeTargetID, ax.probe)
	}
	return assembleHuntCoverage(axes, vulnClass, outcomes)
}

// goalSummary is the slice of the active goal the coverage response surfaces.
type goalSummary struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Status    string `json:"status"`
	VulnClass string `json:"vuln_class"`
}

// GetHuntCoverage answers GET /goals/{scope_target_id}/coverage and the alias
// GET /hunt-coverage/{scope_target_id}. It resolves the active goal (its vuln_class drives the
// class-specific axes), then computes coverage. An explicit ?vuln_class= overrides the goal's class,
// which the UI and tests use to preview a class before a goal exists.
//
// FAIL CLOSED on the goal read too: if the active goal cannot be read, coverage is still computed
// against the baseline (class empty), and because the baseline axes are rarely all complete the
// report stays non-exhaustible, so the gate never opens on a glitch.
func GetHuntCoverage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	if _, err := uuid.Parse(scopeTargetID); err != nil {
		http.Error(w, "The scope target id in the URL is not a valid UUID.", http.StatusBadRequest)
		return
	}
	ctx := context.Background()

	var active *goalSummary
	var g goalSummary
	err := dbPool.QueryRow(ctx,
		`SELECT id::text, title, status, COALESCE(vuln_class,'')
		   FROM target_goals WHERE scope_target_id = $1 AND is_active = TRUE LIMIT 1`,
		scopeTargetID).Scan(&g.ID, &g.Title, &g.Status, &g.VulnClass)
	switch {
	case err == nil:
		active = &g
	case errors.Is(err, pgx.ErrNoRows):
		// No active goal. The gate (spec #3) only constrains the agent when a goal IS active, so this
		// is a normal state: still report baseline coverage so the UI can show it.
	default:
		log.Printf("[HUNT-COVERAGE] could not read active goal for target %s (fail-closed): %v", scopeTargetID, err)
	}

	vulnClass := ""
	if active != nil {
		vulnClass = active.VulnClass
	}
	if q := strings.TrimSpace(r.URL.Query().Get("vuln_class")); q != "" {
		vulnClass = q
	}

	coverage := ComputeHuntCoverage(ctx, scopeTargetID, vulnClass)

	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"active_goal":     active,
		"coverage":        coverage,
	})
}
