package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Reading the Routing & WAF Probe so Validate does not have to rediscover what it already measured.
//
// Availability is evaluated per field, not per scan. A probe row with status='success' proves the
// run finished, not that every test in it ran: the passive preset omits response_stability and all
// the waf_* tests, and safe omits every load_* test. Treating a successful run as proof a field
// exists produces a confident verdict built on a value that was never measured.
//
// Everything that is missing is named in the result, and any verdict that depended on it is marked
// assumed rather than measured. An operator can then see exactly which conclusions rest on a
// measurement and which rest on a default.

type ProbeContext struct {
	Available bool   `json:"available"`
	ScanID    string `json:"scan_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Preset    string `json:"preset,omitempty"`
	AgeHours  int    `json:"age_hours"`
	Stale     bool   `json:"stale"`
	Posture   string `json:"posture,omitempty"`

	// Pacing
	SafeRPS         float64 `json:"safe_rps"`
	RateConfidence  string  `json:"safe_rps_confidence,omitempty"`
	RateVerified    bool    `json:"safe_rps_verified"`
	SafeConcurrency int     `json:"safe_concurrency"`
	RateWithheld    string  `json:"rate_withheld_reason,omitempty"`

	// Not-found behaviour: the single most useful thing Validate inherits.
	NotFoundVerdict  string `json:"notfound_verdict,omitempty"`
	NotFoundStatus   int    `json:"notfound_status"`
	NotFoundSize     int    `json:"notfound_median_size"`
	NotFoundSpread   int    `json:"notfound_size_spread"`
	NotFoundFilter   bool   `json:"notfound_filterable"`
	Distinguishable  bool   `json:"notfound_distinguishable"`

	// Stability governs how much size drift means nothing.
	SizeTolerance   int  `json:"size_tolerance"`
	UnstableBodies  bool `json:"unstable_bodies"`

	// Routing and session behaviour
	CanonicalBaseURL   string `json:"canonical_base_url,omitempty"`
	ConfiguredCanonical bool  `json:"configured_is_canonical"`
	ForceCacheBust     bool   `json:"force_cache_bust"`
	ReuseSession       bool   `json:"reuse_session_recommended"`

	// Auth and blocking
	AuthWallVerdict  string `json:"auth_wall_verdict,omitempty"`
	BlockStatus      int    `json:"block_signature_status"`
	BlockSize        int    `json:"block_signature_size"`
	BlockUsable      bool   `json:"block_signature_usable"`
	StealthSwap      bool   `json:"stealth_swap"`
	StickyBlocking   bool   `json:"sticky_blocking"`

	// What was actually present in the result, and what was not.
	PresentTests []string `json:"present_tests"`
	MissingTests []string `json:"missing_tests"`
	Assumptions  []string `json:"assumptions"`

	// Refuse carries a reason the run should not start at all.
	Refuse string `json:"refuse,omitempty"`
}

// Tests Validate cares about. Anything here that the probe did not run is named on the result.
var validateRelevantTests = []string{
	"notfound_fingerprint", "response_stability", "auth_wall", "redirect_topology",
	"caching_behaviour", "session_issuance", "waf_block_signature", "waf_response_mode",
	"waf_stickiness", "load_ramp",
}

const probeStaleAfterHours = 24 * 14

// LoadProbeContext reads the newest usable probe result for a target.
//
// 'error' rows are ignored: they carry no measurements. 'partial' and 'aborted' are accepted
// because the probe checkpoints after every phase, so what they did measure is real.
func LoadProbeContext(scopeTargetID string) ProbeContext {
	pc := ProbeContext{
		SafeRPS:         2.0,
		RateConfidence:  "assumed",
		SafeConcurrency: 2,
		SizeTolerance:   256,
	}

	var (
		scanID, status string
		resultJSON     *string
		createdAt      time.Time
	)
	err := dbPool.QueryRow(context.Background(), `
		SELECT scan_id, status, result, created_at
		FROM waf_probe_scans
		WHERE scope_target_id = $1
		  AND status IN ('success','partial','aborted')
		  AND result IS NOT NULL
		ORDER BY created_at DESC
		LIMIT 1`, scopeTargetID).Scan(&scanID, &status, &resultJSON, &createdAt)
	if err != nil || resultJSON == nil {
		pc.Assumptions = append(pc.Assumptions,
			"No Routing & WAF Probe result for this target. Validate measured its own baseline and "+
				"is pacing at a conservative assumed rate. Run the probe first for a measured rate "+
				"and a measured not-found fingerprint.")
		pc.MissingTests = append([]string{}, validateRelevantTests...)
		return pc
	}

	var doc struct {
		Verdict struct {
			Posture         string   `json:"posture"`
			SafeRPS         *float64 `json:"safe_rps"`
			RateConfidence  string   `json:"safe_rps_confidence"`
			RateVerified    bool     `json:"safe_rps_verified"`
			SafeConcurrency *int     `json:"safe_concurrency"`
		} `json:"verdict"`
		Recommendations struct {
			Suppressed []struct {
				Field  string `json:"field"`
				Reason string `json:"reason"`
			} `json:"suppressed"`
		} `json:"recommendations"`
		Results    map[string]json.RawMessage `json:"results"`
		ConfigUsed struct {
			Preset string `json:"preset"`
		} `json:"config_used"`
	}
	if json.Unmarshal([]byte(*resultJSON), &doc) != nil || doc.Results == nil {
		pc.Assumptions = append(pc.Assumptions,
			"The stored probe result could not be parsed, so none of its measurements were used.")
		pc.MissingTests = append([]string{}, validateRelevantTests...)
		return pc
	}

	pc.Available = true
	pc.ScanID = scanID
	pc.Status = status
	pc.Preset = doc.ConfigUsed.Preset
	pc.Posture = doc.Verdict.Posture
	pc.AgeHours = int(time.Since(createdAt).Hours())
	pc.Stale = pc.AgeHours > probeStaleAfterHours

	for _, name := range validateRelevantTests {
		if _, ok := doc.Results[name]; ok {
			pc.PresentTests = append(pc.PresentTests, name)
		} else {
			pc.MissingTests = append(pc.MissingTests, name)
		}
	}

	// ---- pacing -------------------------------------------------------------------------
	if doc.Verdict.SafeRPS != nil && *doc.Verdict.SafeRPS > 0 {
		pc.SafeRPS = *doc.Verdict.SafeRPS
		pc.RateConfidence = doc.Verdict.RateConfidence
		pc.RateVerified = doc.Verdict.RateVerified
	} else {
		for _, s := range doc.Recommendations.Suppressed {
			if s.Field == "rate_limit" {
				pc.RateWithheld = s.Reason
			}
		}
		pc.Assumptions = append(pc.Assumptions,
			"The probe withheld a safe rate"+reasonSuffix(pc.RateWithheld)+
				" so Validate is pacing at a conservative assumed floor.")
	}
	if doc.Verdict.SafeConcurrency != nil && *doc.Verdict.SafeConcurrency > 0 {
		pc.SafeConcurrency = *doc.Verdict.SafeConcurrency
	}

	// ---- not-found ----------------------------------------------------------------------
	var nf struct {
		Verdict         string `json:"verdict"`
		MedianSize      int    `json:"median_size"`
		SizeSpread      int    `json:"size_spread"`
		Filterable      bool   `json:"filterable"`
		Distinguishable bool   `json:"distinguishable_from_content"`
		Fingerprint     struct {
			Status int `json:"status"`
		} `json:"fingerprint"`
	}
	if raw, ok := doc.Results["notfound_fingerprint"]; ok && json.Unmarshal(raw, &nf) == nil {
		pc.NotFoundVerdict = nf.Verdict
		pc.NotFoundStatus = nf.Fingerprint.Status
		pc.NotFoundSize = nf.MedianSize
		pc.NotFoundSpread = nf.SizeSpread
		pc.NotFoundFilter = nf.Filterable
		pc.Distinguishable = nf.Distinguishable
		if nf.Verdict == "soft_404_indistinguishable" {
			pc.Assumptions = append(pc.Assumptions,
				"The probe found this target's not-found response indistinguishable from real "+
					"content, so no endpoint is ruled out on body similarity alone. Every 200 is "+
					"reported as indistinguishable and kept.")
		}
	} else {
		pc.Assumptions = append(pc.Assumptions,
			"The probe did not run its not-found fingerprint, so Validate measured its own.")
	}

	// ---- stability ----------------------------------------------------------------------
	var rs struct {
		Verdict        string `json:"verdict"`
		SizeTolerance  int    `json:"recommended_size_tolerance"`
		AutoCalibrate  bool   `json:"auto_calibrate_recommended"`
	}
	if raw, ok := doc.Results["response_stability"]; ok && json.Unmarshal(raw, &rs) == nil {
		if rs.SizeTolerance > 0 {
			pc.SizeTolerance = rs.SizeTolerance
		}
		pc.UnstableBodies = rs.AutoCalibrate
	} else {
		pc.Assumptions = append(pc.Assumptions,
			"Response stability was not measured, so a default size tolerance is in use and size "+
				"agreement is treated as supporting evidence rather than proof.")
	}

	// ---- routing ------------------------------------------------------------------------
	var rt struct {
		CanonicalBaseURL    string `json:"canonical_base_url"`
		ConfiguredCanonical bool   `json:"configured_is_canonical"`
	}
	if raw, ok := doc.Results["redirect_topology"]; ok && json.Unmarshal(raw, &rt) == nil {
		pc.CanonicalBaseURL = rt.CanonicalBaseURL
		pc.ConfiguredCanonical = rt.ConfiguredCanonical
	} else {
		pc.ConfiguredCanonical = true
	}

	var cb struct {
		ForceCacheBust bool `json:"force_cache_bust"`
	}
	if raw, ok := doc.Results["caching_behaviour"]; ok && json.Unmarshal(raw, &cb) == nil {
		pc.ForceCacheBust = cb.ForceCacheBust
	}

	var si struct {
		ReuseSession bool `json:"reuse_session_recommended"`
	}
	if raw, ok := doc.Results["session_issuance"]; ok && json.Unmarshal(raw, &si) == nil {
		pc.ReuseSession = si.ReuseSession
	}

	// ---- auth and blocking ---------------------------------------------------------------
	var aw struct {
		Verdict string `json:"verdict"`
	}
	if raw, ok := doc.Results["auth_wall"]; ok && json.Unmarshal(raw, &aw) == nil {
		pc.AuthWallVerdict = aw.Verdict
		if aw.Verdict == "credentials_not_honoured" {
			// Running now would fingerprint the login wall and call it the application. Every
			// verdict would be wrong in the same direction, which is worse than no verdicts.
			pc.Refuse = "The probe found this target's saved credentials are not being accepted. " +
				"Validate would measure the login wall rather than the application. Refresh the " +
				"session in the FFUF configuration, or recapture with the manual crawl, then retry."
		}
	}

	var bs struct {
		Verdict  string `json:"verdict"`
		Status   int    `json:"status"`
		WireSize int    `json:"wire_size"`
	}
	if raw, ok := doc.Results["waf_block_signature"]; ok && json.Unmarshal(raw, &bs) == nil {
		pc.BlockUsable = bs.Verdict == "usable"
		pc.BlockStatus = bs.Status
		pc.BlockSize = bs.WireSize
	}

	var wrm struct {
		Verdict string `json:"verdict"`
	}
	if raw, ok := doc.Results["waf_response_mode"]; ok && json.Unmarshal(raw, &wrm) == nil {
		pc.StealthSwap = wrm.Verdict == "stealth_swap"
	}

	var ws struct {
		Verdict string `json:"verdict"`
	}
	if raw, ok := doc.Results["waf_stickiness"]; ok && json.Unmarshal(raw, &ws) == nil {
		pc.StickyBlocking = strings.Contains(strings.ToLower(ws.Verdict), "sticky")
	}

	// ---- posture-driven refusals and brakes ----------------------------------------------
	switch pc.Posture {
	case "INCONCLUSIVE":
		pc.Refuse = "The probe's control arm was blocked, meaning this target refuses benign " +
			"traffic. Nothing Validate measured would describe the application. Investigate why " +
			"the probe's control requests were blocked before running this."
	case "DEFENDED":
		pc.SafeRPS = pc.SafeRPS / 2
		pc.Assumptions = append(pc.Assumptions,
			"The probe rated this target DEFENDED, so the rate is halved and the abort thresholds "+
				"are tightened.")
	}

	if pc.Stale {
		pc.Assumptions = append(pc.Assumptions, fmt.Sprintf(
			"The probe result is %d days old. Both the target and this egress address may have "+
				"changed since it was measured.", pc.AgeHours/24))
	}
	if len(pc.MissingTests) > 0 {
		pc.Assumptions = append(pc.Assumptions, fmt.Sprintf(
			"The %s preset did not run: %s. Verdicts depending on those are marked assumed.",
			orUnknown(pc.Preset), strings.Join(pc.MissingTests, ", ")))
	}

	return pc
}

// EffectiveRate returns the paced rate and concurrency Validate should use, after the confidence
// factor and the hard cap on unmeasured rates.
func (pc ProbeContext) EffectiveRate() (float64, int) {
	rps := EffectiveRPS(pc.SafeRPS, pc.RateConfidence)
	conc := pc.SafeConcurrency
	if conc < 1 {
		conc = 1
	}
	if conc > 8 {
		conc = 8
	}
	if pc.RateConfidence != "measured" && conc > 2 {
		conc = 2
	}
	return rps, conc
}

// ConfidenceFor downgrades a verdict's confidence when the probe test it relied on was absent.
func (pc ProbeContext) ConfidenceFor(dependsOn string, measured string) string {
	for _, missing := range pc.MissingTests {
		if missing == dependsOn {
			return "assumed"
		}
	}
	if pc.Stale {
		if measured == "measured" {
			return "inferred"
		}
	}
	return measured
}

func reasonSuffix(reason string) string {
	if reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

func orUnknown(s string) string {
	if s == "" {
		return "probe"
	}
	return s
}
