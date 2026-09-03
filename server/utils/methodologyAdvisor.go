package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"

	"github.com/gorilla/mux"
)

// WHAT TO DO NEXT ON THIS TARGET, decided from the target's actual data.
//
// The other methodology endpoints answer "how does this step work". This one answers the question an
// operator actually has, which is "what should I do right now", and it answers it by looking at what
// has and has not happened on this specific target rather than by reciting the workflow.
//
// WHY IT EXISTS. Static guidance did not prevent the failure it was written for. On the reference
// engagement a fuzzing flow of ten steps was built, every step fuzzed parameters, headers or cookies
// on endpoints that were already known, and content discovery at the web root never ran. Nothing in
// the framework said so. Every card reported success, every scan completed, and the access-bypass
// section had zero targets as a downstream consequence that surfaced days later.
//
// A checklist nobody reads cannot fix that. A check that looks at the database and says "you have 24
// query vectors and 0 path vectors, and no content discovery has ever run on this target" can.
//
// THE VOCABULARY IS rs0n's, deliberately. This framework is an implementation of the methodology from
// the DEFCON 32 Bug Bounty Village workshop, and its central data structure is that methodology's
// definition made literal: an Injection Attack Vector is the unique combination of HTTP verb,
// domain:port, endpoint and injection point, which is exactly the identity attack_vectors keys on.
// Using different words for the same idea would make the framework harder to learn, not easier.

// AdvisorFinding is one thing worth doing, or one thing worth knowing, about this target now.
type AdvisorFinding struct {
	// Severity of the ADVICE, not of a vulnerability: blocker, gap, or note.
	//
	// blocker means a later step cannot work until this is done. gap means work that is quietly
	// missing. note is context worth having.
	Severity string `json:"severity"`
	Step     string `json:"step"`
	Title    string `json:"title"`
	// Detail states the measured fact first and the consequence second, because the fact is what makes
	// the advice credible.
	Detail string `json:"detail"`
	Action string `json:"action"`
	// Pillar is which of the four the work belongs to: recon, injection, logic, cloud.
	Pillar string `json:"pillar"`
}

// GetTargetAdvice answers GET /methodology/{scope_target_id}/advice.
func GetTargetAdvice(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	ctx := context.Background()

	state := readTargetState(ctx, scopeTargetID)
	findings := adviseOnState(state)

	// Blockers first, then gaps, then notes. An operator reads the top of a list.
	rank := map[string]int{"blocker": 0, "gap": 1, "note": 2}
	sort.SliceStable(findings, func(i, j int) bool {
		return rank[findings[i].Severity] < rank[findings[j].Severity]
	})

	json.NewEncoder(w).Encode(map[string]any{
		"state":   state,
		"advice":  findings,
		"blocked": countSeverity(findings, "blocker"),
		"gaps":    countSeverity(findings, "gap"),
		"principle": "Ebb and flow. Work down the recon methodology until you have three to five " +
			"attack vectors worth testing, test them, and when you get stuck put a pin in them and go " +
			"back to an earlier part of recon to expand the attack surface. Then pick three to five " +
			"new vectors and try again.",
		"source": "Methodology vocabulary follows rs0n's DEFCON 32 Bug Bounty Village workshop, which " +
			"this framework implements. An Injection Attack Vector is the unique combination of HTTP " +
			"verb, domain:port, endpoint and injection point. A Logic Attack Vector is an overly " +
			"complex mechanism, a database query using an id from the request, granular access " +
			"controls, or a hacky implementation.",
	})
}

// TargetState is what has measurably happened on this target.
type TargetState struct {
	CrawlCaptures     int            `json:"manual_crawl_captures"`
	Endpoints         int            `json:"discovered_endpoints"`
	Vectors           int            `json:"attack_vectors"`
	VectorsByPoint    map[string]int `json:"attack_vectors_by_insertion_point"`
	FuzzFlows         int            `json:"fuzz_flows"`
	ContentDiscovery  int            `json:"content_discovery_flows"`
	FuzzRuns          int            `json:"fuzz_runs"`
	DeniedEndpoints   int            `json:"denied_endpoints_401_403"`
	VectorScans       int            `json:"vector_scans"`
	UnverifiedScans   int            `json:"unverified_scans"`
	Findings          int            `json:"vector_findings"`
	Threats           int            `json:"threat_model_entries"`
	Mechanisms        int            `json:"documented_mechanisms"`
	ActiveCredentials int            `json:"active_session_tokens"`
	// Unreadable names the checks that could not be run at all. A count of -1 means unknown, and the
	// advisor must never turn an unknown into advice: telling an operator to do work they have already
	// done is how an advisory gets ignored, and being ignored is the only way this feature can fail.
	Unreadable []string `json:"unreadable_checks,omitempty"`
}

func readTargetState(ctx context.Context, id string) TargetState {
	s := TargetState{VectorsByPoint: map[string]int{}}

	// A FAILED QUERY IS NOT A ZERO, and this helper used to say it was.
	//
	// The first version returned 0 on any error, which meant a typo in a table name produced "this
	// target has no mechanisms documented" rather than "I could not tell". It was caught immediately
	// because it advised a target with 17 documented mechanisms to go and document some, but a subtler
	// version of the same mistake would have produced confident advice built on nothing. That is the
	// exact fail-open pattern this whole advisor exists to detect in other people's tools, reproduced
	// here in a helper, which is a fair reminder of how easy it is.
	//
	// Unreadable counts are collected and reported, so the caller can tell the difference between a
	// step that has not happened and a check that did not work.
	one := func(label, q string) int {
		var n int
		if err := dbPool.QueryRow(ctx, q, id).Scan(&n); err != nil {
			log.Printf("[ADVISOR] could not read %s: %v", label, err)
			s.Unreadable = append(s.Unreadable, label)
			return -1
		}
		return n
	}
	s.CrawlCaptures = one("manual_crawl_captures", `SELECT count(*) FROM manual_crawl_captures WHERE scope_target_id = $1`)
	s.Endpoints = one("consolidated_url_endpoints", `SELECT count(*) FROM consolidated_url_endpoints WHERE scope_target_id = $1`)
	s.Vectors = one("attack_vectors", `SELECT count(*) FROM attack_vectors WHERE scope_target_id = $1 AND deleted_at IS NULL`)
	s.FuzzFlows = one("fuzz_flows", `SELECT count(*) FROM fuzz_flows WHERE scope_target_id = $1`)
	s.ContentDiscovery = one("content_discovery_flows", `SELECT count(*) FROM fuzz_flows WHERE scope_target_id = $1
	                          AND purpose = 'content-discovery'`)
	s.FuzzRuns = one("fuzz_runs", `SELECT count(*) FROM fuzz_runs WHERE scope_target_id = $1`)
	// COUNTED FROM THE SAME PLACE THE BYPASS SECTION OFFERS THEM, not from the curated table.
	//
	// The first version counted access_bypass_targets, which is written only by RecordDeniedEndpoint
	// during endpoint discovery. On a target whose 401s and 403s were observed by endpoint VALIDATION
	// instead, that table is empty while manage_access_bypass happily offers four denied endpoints, so
	// the advisor told an operator to go and do work whose input already existed. Two tools disagreeing
	// about the same target is how an advisory loses its credibility, and it was caught within a day.
	//
	// This union mirrors DeniedEndpoints. It is deliberately duplicated as a count rather than
	// refactored to share code, because DeniedEndpoints returns rows with scope judgement and dedupe
	// applied and this only needs to know whether the section has anything to work on.
	s.DeniedEndpoints = one("denied_endpoints", `
		WITH found AS (
			SELECT url, status_code FROM discovered_endpoints
			 WHERE scope_target_id = $1 AND url <> '' AND status_code IN (401,403)
			UNION ALL
			SELECT url, http_status FROM endpoint_validation_results
			 WHERE scope_target_id = $1 AND url <> '' AND http_status IN (401,403)
			UNION ALL
			SELECT url, status_code FROM manual_crawl_captures
			 WHERE scope_target_id = $1 AND url <> '' AND status_code IN (401,403)
			UNION ALL
			SELECT url, status_code FROM access_bypass_targets
			 WHERE scope_target_id = $1 AND deleted_at IS NULL AND status_code IN (401,403)
		)
		SELECT count(DISTINCT url) FROM found`)
	s.VectorScans = one("vector_scans", `SELECT count(*) FROM vector_scans WHERE scope_target_id = $1`)
	s.UnverifiedScans = one("unverified_scans", `SELECT count(*) FROM vector_scans
	                         WHERE scope_target_id = $1 AND COALESCE(error,'') <> ''`)
	s.Findings = one("vector_findings", `SELECT count(*) FROM vector_findings f
	                  JOIN vector_scans v ON v.id = f.scan_id WHERE v.scope_target_id = $1`)
	s.Threats = one("threat_model", `SELECT count(*) FROM threat_model WHERE scope_target_id = $1`)
	// mechanisms_examples, plural. The singular spelling silently reported zero.
	s.Mechanisms = one("mechanisms_examples", `SELECT count(DISTINCT mechanism) FROM mechanisms_examples WHERE scope_target_id = $1`)
	// is_active, not a status string. The status column does not exist on this table.
	s.ActiveCredentials = one("active_session_tokens", `SELECT count(*) FROM session_tokens
	                           WHERE scope_target_id = $1 AND COALESCE(is_active, FALSE)
	                             AND COALESCE(token_role,'credential') = 'credential'`)

	for _, point := range VectorInsertionPoints {
		s.VectorsByPoint[point] = 0
	}
	rows, err := dbPool.Query(ctx, `
		SELECT insertion_point, count(*) FROM attack_vectors
		WHERE scope_target_id = $1 AND deleted_at IS NULL GROUP BY insertion_point`, id)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var p string
			var n int
			if rows.Scan(&p, &n) == nil {
				s.VectorsByPoint[p] = n
			}
		}
	}
	return s
}

// adviseOnState is the whole judgement, kept pure so it is testable without a database.
func adviseOnState(s TargetState) []AdvisorFinding {
	var out []AdvisorFinding
	add := func(sev, step, title, detail, action, pillar string) {
		out = append(out, AdvisorFinding{sev, step, title, detail, action, pillar})
	}

	// THE CHECK THIS FILE EXISTS FOR.
	if s.ContentDiscovery == 0 && s.FuzzRuns == 0 {
		add("blocker", "content-discovery", "No content discovery has ever run on this target",
			"No fuzz flow on this target has purpose content-discovery, and no fuzz run has ever "+
				"executed. Nothing has asked this target whether an unlinked path exists.",
			"Create a fuzz flow with purpose content-discovery and a step that puts FUZZ in the PATH "+
				"at the web root, then run it. This is the first command of an engagement, and every "+
				"later step is bounded by the endpoint list it produces.",
			"recon")
	} else if s.ContentDiscovery == 0 && s.FuzzRuns > 0 {
		add("gap", "content-discovery", "Fuzzing has run, but never against the path",
			fmt.Sprintf("%d fuzz run(s) exist and no flow has purpose content-discovery. That is the "+
				"exact shape of the reference failure: ten steps fuzzing parameters, headers and "+
				"cookies on endpoints that were already known, and nothing ever fuzzing the path.",
				s.FuzzRuns),
			"Add a content-discovery flow. Fuzzing parameters finds hidden inputs on endpoints you "+
				"already have; it cannot discover an endpoint.",
			"recon")
	}

	if s.CrawlCaptures == 0 {
		add("blocker", "manual-crawl", "Nothing has been captured from the application",
			"There are no manual crawl captures. Every attack vector with a real body, a real header "+
				"set or a real cookie jar comes from this step, so the vector list will be thin and "+
				"skewed towards query parameters until it happens.",
			"Browse the application through the capture extension, logged in, and SUBMIT every form "+
				"rather than only visiting the pages that hold them.",
			"recon")
	}

	if s.Vectors == 0 && (s.CrawlCaptures > 0 || s.Endpoints > 0) {
		add("blocker", "consolidate-vectors", "Data exists but no attack vectors have been built",
			fmt.Sprintf("%d capture(s) and %d endpoint(s) are stored, and there are 0 attack vectors. "+
				"Every scanner runs against the vector list, so every section will report clean.",
				s.CrawlCaptures, s.Endpoints),
			"Run Consolidate Attack Vectors.", "injection")
	}

	// Insertion point coverage. An empty point is a guaranteed clean report from every tool.
	if s.Vectors > 0 {
		var empty []string
		for _, p := range VectorInsertionPoints {
			if s.VectorsByPoint[p] == 0 {
				empty = append(empty, p)
			}
		}
		if len(empty) > 0 {
			add("gap", "consolidate-vectors", "Insertion points with no coverage at all",
				fmt.Sprintf("These insertion points have zero vectors: %v. Every tool in every section "+
					"will report nothing wrong with them, because nothing was ever sent there. That is "+
					"a gap in coverage, not a clean result.", empty),
				"Add vectors by hand at the empty points on endpoints where they make sense, or accept "+
					"and record that those points are untested on this target.",
				"injection")
		}
	}

	if s.Vectors > 0 && s.VectorScans == 0 {
		add("gap", "vector-scanning", "Vectors are built but nothing has been scanned",
			fmt.Sprintf("%d attack vector(s) exist and no vector scan has run.", s.Vectors),
			"Pick three to five vectors worth testing and run the relevant sections against them. Do "+
				"not try to run everything at once; work a handful, then go back to recon.",
			"injection")
	}

	if s.UnverifiedScans > 0 {
		add("blocker", "vector-scanning", "Some scans did not finish and their results do not count",
			fmt.Sprintf("%d of %d scan(s) recorded an error, which means the run stopped or its "+
				"positive control failed. Those results are UNVERIFIED, not clean.",
				s.UnverifiedScans, s.VectorScans),
			"Read the scan verdict and the What Ran tab on each, fix the cause, and re-run before "+
				"treating any of their output as coverage.",
			"injection")
	}

	if s.DeniedEndpoints == 0 {
		sev, detail := "gap", "No endpoint on this target has been recorded returning 401 or 403."
		if s.ContentDiscovery == 0 {
			sev = "blocker"
			detail += " That is expected, because content discovery has not run: a path nothing " +
				"requests cannot refuse anything."
		}
		add(sev, "access-bypass", "The access bypass section has no targets",
			detail,
			"Run content discovery first. The 401 and 403 responses it produces are the input to this "+
				"section, and they are findings in their own right: the resource exists and is being "+
				"withheld.",
			"logic")
	}

	if s.CrawlCaptures > 0 && s.ActiveCredentials == 0 {
		add("gap", "authentication", "No active session token",
			"The application has been crawled but no session token is active. Any scan run now tests "+
				"the application as an anonymous visitor, and on an authenticated application that "+
				"means testing the login wall.",
			"Record an auth flow and confirm a token is active before scanning. Watch the Active "+
				"count, not the total.",
			"logic")
	}

	// Logic testing. rs0n's four logic attack vector types all need the application to be understood
	// first, and mechanisms are how this framework records that understanding.
	if s.Mechanisms == 0 && s.CrawlCaptures > 0 {
		add("gap", "threat-model", "No mechanisms documented, so logic testing has nothing to work from",
			"A Logic Attack Vector is an overly complex mechanism, a database query using an id from "+
				"the request, granular access controls, or a hacky implementation. None of those can "+
				"be found by a scanner, and none can be recorded until the application's mechanisms "+
				"are written down.",
			"Document the mechanisms, notable objects and security controls, then write threats "+
				"against them. Work spoofing and elevation of privilege first: those are the "+
				"categories no tool can help with.",
			"logic")
	} else if s.Threats == 0 && s.Mechanisms > 0 {
		add("gap", "threat-model", "Mechanisms are documented but no threats have been written",
			fmt.Sprintf("%d mechanism(s) are recorded and the threat model is empty.", s.Mechanisms),
			"Write one threat per mechanism that names an endpoint and a single concrete test.",
			"logic")
	}

	if len(s.Unreadable) > 0 {
		add("note", "", "Some checks could not be run",
			fmt.Sprintf("These state checks failed to read and were skipped rather than being reported "+
				"as zero: %v. Advice below is based on what could be read.", s.Unreadable),
			"This is a defect in the advisor rather than in the target. The counts it could not read "+
				"say nothing about whether that work has been done.",
			"")
	}

	if len(out) == 0 {
		add("note", "", "No blockers or gaps detected",
			"Every step this advisor checks has produced something. That is not the same as being "+
				"finished: it means nothing is obviously missing.",
			"Go back to recon and expand the attack surface, then pick three to five new attack "+
				"vectors. Ebb and flow.",
			"recon")
	}
	return out
}

func countSeverity(findings []AdvisorFinding, severity string) int {
	n := 0
	for _, f := range findings {
		if f.Severity == severity {
			n++
		}
	}
	return n
}
