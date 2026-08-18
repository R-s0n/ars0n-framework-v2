package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

// What the probe measured, expressed as the exact setting each tool needs.
//
// This replaces the automated apply. Writing the numbers into the tool configs looked convenient
// and was not: the write went through a field translation that could get the name, the unit or the
// type wrong, and every one of those failures was silent. A rounded float landed in an integer
// column and decoded to zero, so the journal said the rate had been applied, the modal showed it
// applied, and the tool ran with no pacing at all. A delay computed in seconds went into a
// millisecond field and ran three orders of magnitude too fast.
//
// The translation itself is still the useful part, so it is kept and pointed at the screen instead
// of at the database. Telling an operator "set ffuf rateLimit to 5" is worth doing; doing it behind
// their back is not, because when it goes wrong nothing tells them.
//
// Units are carried explicitly for the same reason. "delay 2" is not actionable when arjun counts
// seconds and x8 counts milliseconds, and that ambiguity is what produced the 1000x error.

type recommendedSetting struct {
	Setting    string      `json:"setting"`
	Value      interface{} `json:"value"`
	Unit       string      `json:"unit,omitempty"`
	Why        string      `json:"why,omitempty"`
	Confidence string      `json:"confidence,omitempty"`
	FindingID  string      `json:"finding_id,omitempty"`
	// Restrictive marks a setting that slows the tool down. The operator should know which
	// recommendations cost them throughput and which are free.
	Restrictive bool `json:"restrictive"`
	// ProbeField is the generic name the probe used, kept so a recommendation can be traced back
	// to the measurement that produced it.
	ProbeField string `json:"probe_field"`
}

type recommendedTool struct {
	Tool     string               `json:"tool"`
	Where    string               `json:"where"`
	Settings []recommendedSetting `json:"settings"`
	// Notes covers anything the probe suggested for this tool that the tool has no knob for.
	Notes []string `json:"notes,omitempty"`
}

// settingUnit names the unit a tool-native field is counted in.
//
// Without this the operator is reading a bare number. arjun -d is whole seconds, x8 --delay is
// milliseconds, and gospider -k is whole seconds; presenting all three as "delay" is how a
// thousandfold error goes unnoticed.
func settingUnit(tool, field string) string {
	switch field {
	case "rateLimit", "rate_limit":
		return "requests per second"
	case "requestDelayMs":
		return "milliseconds between requests"
	case "delay":
		switch tool {
		case "x8":
			return "milliseconds between requests"
		case "arjun", "gospider":
			return "whole seconds between requests"
		}
		return "delay"
	case "threads", "concurrency", "concurrent":
		return "parallel workers"
	case "filterSize", "filterSizes":
		return "bytes, responses of this size are discarded"
	}
	return ""
}

// noKnobNote explains what it means that a tool cannot honour a measurement, rather than just
// stating that it cannot.
//
// This was the case the removed apply handled worst: a tool with no rate flag had its recommended
// rate written to a side table nothing reads, and the operator was told the rate had been applied
// while the tool ran flat out. Saying so plainly is the whole point of the change.
func noKnobNote(tool, field string, value interface{}) string {
	switch tool {
	case "framework":
		return fmt.Sprintf(
			"%s = %v is advisory. There is no framework-wide rate limiter, so this is only "+
				"achieved by setting the per-tool values above and not running those tools "+
				"against this target at the same time.", field, value)
	case "endpoint_replay":
		return fmt.Sprintf(
			"%s = %v is not settable here. Endpoint replay paces itself from its own measurements "+
				"during the scan.", field, value)
	}
	return fmt.Sprintf(
		"The probe measured %s = %v, but %s has no setting for it and will ignore it.",
		field, value, tool)
}

// toolLocation tells the operator where to type the value.
func toolLocation(tool string) string {
	switch tool {
	case "ffuf":
		return "FFUF Configure modal"
	case "arjun", "x8":
		return "Hidden Attack Vector Fuzzing, " + tool + " Configure modal"
	case "katana", "gospider", "linkfinder":
		return "Live Target Crawling, " + tool + " Configure modal"
	case "nuclei":
		return "Nuclei Configure modal, advanced settings"
	case "framework":
		return "Applies to the whole workflow, not one tool"
	}
	return ""
}

// GetWAFProbeRecommendations handles
// GET /waf-probe/recommendations/{scope_target_id} and .../{scope_target_id}/{scan_id}.
func GetWAFProbeRecommendations(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scopeTargetID := vars["scope_target_id"]
	scanID := vars["scan_id"]

	var resultJSON *string
	var storedScanID string
	var err error
	if scanID != "" {
		err = dbPool.QueryRow(context.Background(),
			`SELECT scan_id, result FROM waf_probe_scans
			 WHERE scan_id = $1 AND scope_target_id = $2`,
			scanID, scopeTargetID).Scan(&storedScanID, &resultJSON)
	} else {
		err = dbPool.QueryRow(context.Background(),
			`SELECT scan_id, result FROM waf_probe_scans
			 WHERE scope_target_id = $1 AND status IN ('success','partial','aborted')
			   AND result IS NOT NULL
			 ORDER BY created_at DESC LIMIT 1`, scopeTargetID).Scan(&storedScanID, &resultJSON)
	}

	w.Header().Set("Content-Type", "application/json")
	if err != nil || resultJSON == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "not_run",
			"note":   "No Routing & WAF Probe result for this target yet.",
		})
		return
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
			ByTool map[string][]struct {
				Field       string          `json:"field"`
				Value       json.RawMessage `json:"value"`
				Why         string          `json:"why"`
				Confidence  string          `json:"confidence"`
				Restrictive bool            `json:"restrictive"`
				FindingID   string          `json:"finding_id"`
			} `json:"by_tool"`
			Suppressed []struct {
				Field  string `json:"field"`
				Reason string `json:"reason"`
			} `json:"suppressed"`
		} `json:"recommendations"`
	}
	if json.Unmarshal([]byte(*resultJSON), &doc) != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "error",
			"note":   "The stored probe result could not be parsed.",
		})
		return
	}

	tools := []recommendedTool{}
	for tool, rows := range doc.Recommendations.ByTool {
		entry := recommendedTool{Tool: tool, Where: toolLocation(tool), Settings: []recommendedSetting{}}

		// The current config is read only to resolve settings that depend on it, such as a delay
		// derived from the thread count. Nothing here writes.
		current := currentToolConfig(tool, scopeTargetID)

		for _, row := range rows {
			var value interface{}
			if json.Unmarshal(row.Value, &value) != nil {
				continue
			}

			// A leading underscore marks an advisory field rather than a setting. `_exempt` on gau
			// and waybackurls says those tools query public archives instead of the target, so the
			// measured rate does not apply to them at all. Reporting that as "no setting for it"
			// would read as a gap when it is the opposite: a deliberate exemption.
			if strings.HasPrefix(row.Field, "_") {
				note := row.Why
				if note == "" {
					note = fmt.Sprintf("%s: %s = %v", tool, row.Field, value)
				}
				entry.Notes = append(entry.Notes, note)
				continue
			}

			field, translated, ok := translateField(tool, current, row.Field, value)
			if !ok {
				// The tool has no knob for this. Said plainly, because the alternative is what the
				// old apply did: write it somewhere nothing reads and report success.
				entry.Notes = append(entry.Notes, noKnobNote(tool, row.Field, value))
				continue
			}

			entry.Settings = append(entry.Settings, recommendedSetting{
				Setting:     field,
				Value:       translated,
				Unit:        settingUnit(tool, field),
				Why:         row.Why,
				Confidence:  row.Confidence,
				FindingID:   row.FindingID,
				Restrictive: row.Restrictive,
				ProbeField:  row.Field,
			})
		}

		if len(entry.Settings) > 0 || len(entry.Notes) > 0 {
			tools = append(tools, entry)
		}
	}

	// Restrictive tools first: those are the ones that change what a scan does.
	sort.SliceStable(tools, func(i, j int) bool {
		ri, rj := 0, 0
		for _, s := range tools[i].Settings {
			if s.Restrictive {
				ri++
			}
		}
		for _, s := range tools[j].Settings {
			if s.Restrictive {
				rj++
			}
		}
		if ri != rj {
			return ri > rj
		}
		return tools[i].Tool < tools[j].Tool
	})

	measured := map[string]interface{}{
		"posture":    doc.Verdict.Posture,
		"confidence": doc.Verdict.RateConfidence,
		"verified":   doc.Verdict.RateVerified,
	}
	if doc.Verdict.SafeRPS != nil {
		measured["safe_rps"] = *doc.Verdict.SafeRPS
	}
	if doc.Verdict.SafeConcurrency != nil {
		measured["safe_concurrency"] = *doc.Verdict.SafeConcurrency
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":     "ok",
		"scan_id":    storedScanID,
		"measured":   measured,
		"tools":      tools,
		"suppressed": doc.Recommendations.Suppressed,
		"note": "These are recommendations only. Nothing here has been written to any tool " +
			"configuration; set them yourself in the modal named against each tool.",
	})
}

// currentToolConfig reads a tool's saved config so a derived recommendation can be resolved against
// it. Read only, and a missing config is not an error: the translation falls back to its own
// defaults.
func currentToolConfig(tool, scopeTargetID string) map[string]interface{} {
	current := map[string]interface{}{}

	if tool == "nuclei" {
		var raw []byte
		if err := dbPool.QueryRow(context.Background(),
			`SELECT advanced_config FROM nuclei_configs WHERE scope_target_id = $1`,
			scopeTargetID).Scan(&raw); err == nil && len(raw) > 0 {
			_ = json.Unmarshal(raw, &current)
		}
		return current
	}

	table, ok := toolConfigTable(tool)
	if !ok {
		return current
	}
	var raw []byte
	if err := dbPool.QueryRow(context.Background(),
		fmt.Sprintf(`SELECT config FROM %s WHERE scope_target_id = $1`, table),
		scopeTargetID).Scan(&raw); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &current)
	}
	return current
}
