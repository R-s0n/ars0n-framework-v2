package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/gorilla/mux"

	"ars0n-framework-v2-server/utils"
)

// Wiring that has to live in package main because the handlers it reaches do.
//
// utils cannot import main, so the auto-scan orchestrator calls back through function variables
// registered here at startup. Only the nuclei step needs this: every other step's handler is
// already in utils.

// nucleiDefaultTemplates and nucleiDefaultSeverities mirror client/src/utils/nucleiDefaults.js.
// The browser applied these when the stored config named no templates, so a server-driven run has
// to apply the same ones or an auto scan quietly runs a narrower nuclei than it used to.
var (
	nucleiDefaultTemplates  = []string{"cves", "vulnerabilities", "exposures", "misconfiguration", "takeovers"}
	nucleiDefaultSeverities = []string{"critical", "high", "medium", "low"}
)

// registerAutoScanHooks is called once from main().
func registerAutoScanHooks() {
	utils.AutoScanNucleiStep = autoScanRunNuclei
}

// autoScanRunNuclei reproduces the browser's nuclei step: read the stored config, fill in the
// defaults it used, force target_mode to httpx, save it back, then start the scan.
//
// The save is not optional. startNucleiScan RE-READS nuclei_configs rather than using anything the
// caller passes (main.go:4148), so skipping the write would run nuclei in whatever mode was last
// stored -- usually attack_surface, which targets something else entirely.
func autoScanRunNuclei(targetID, sessionID string) (string, error) {
	// The live web servers this target has, which is what the browser fetched to decide whether
	// there was anything to scan at all.
	code, body := callMainHandler(getWildcardNucleiTargets, "GET",
		"/scopetarget/"+targetID+"/wildcard-nuclei-targets", map[string]string{"id": targetID}, nil)
	if code < 200 || code > 299 {
		return "", fmt.Errorf("could not read nuclei targets (%d)", code)
	}
	targets := extractNucleiTargets(body)
	if len(targets) == 0 {
		return "", nil // caller treats an empty scan id as "nothing to do"
	}

	// Merge with what is stored, exactly as autoScanSteps.js:1444 does.
	var storedTemplates, storedSeverities, storedTemplateIDs, storedExcludeIDs, storedExcludeTags []string
	var uploaded, advanced []byte
	_ = dbPool.QueryRow(context.Background(), `
		SELECT COALESCE(templates,'{}'), COALESCE(severities,'{}'), COALESCE(template_ids,'{}'),
		       COALESCE(exclude_ids,'{}'), COALESCE(exclude_tags,'{}'),
		       COALESCE(uploaded_templates,'[]'), COALESCE(advanced_config,'{}')
		FROM nuclei_configs WHERE scope_target_id = $1::uuid ORDER BY created_at DESC LIMIT 1`,
		targetID).Scan(&storedTemplates, &storedSeverities, &storedTemplateIDs,
		&storedExcludeIDs, &storedExcludeTags, &uploaded, &advanced)

	hasTemplates := len(storedTemplates) > 0 || len(storedTemplateIDs) > 0
	finalTemplates := storedTemplates
	finalTemplateIDs := storedTemplateIDs
	if !hasTemplates {
		finalTemplates = nucleiDefaultTemplates
		finalTemplateIDs = []string{}
	}
	finalSeverities := storedSeverities
	if len(finalSeverities) == 0 {
		finalSeverities = nucleiDefaultSeverities
	}

	cfg := map[string]interface{}{
		"targets":      targets,
		"templates":    finalTemplates,
		"severities":   finalSeverities,
		"target_mode":  "httpx",
		"template_ids": finalTemplateIDs,
		"exclude_ids":  orEmpty(storedExcludeIDs),
		"exclude_tags": orEmpty(storedExcludeTags),
	}
	cfg["advanced_config"] = rawOrEmptyObject(advanced)
	cfg["uploaded_templates"] = rawOrEmptyArray(uploaded)

	if code, resp := callMainHandler(saveNucleiConfig, "POST", "/nuclei-config/"+targetID,
		map[string]string{"scope_target_id": targetID, "id": targetID}, cfg); code < 200 || code > 299 {
		return "", fmt.Errorf("could not save nuclei config (%d): %s", code, string(resp))
	}

	code, resp := callMainHandler(startNucleiScan, "POST",
		"/scopetarget/"+targetID+"/scans/nuclei/start", map[string]string{"id": targetID}, nil)
	if code < 200 || code > 299 {
		return "", fmt.Errorf("nuclei refused to start (%d): %s", code, string(resp))
	}
	var out map[string]interface{}
	if json.Unmarshal(resp, &out) == nil {
		for _, k := range []string{"scan_id", "scanID", "id"} {
			if v, ok := out[k].(string); ok && v != "" {
				return v, nil
			}
		}
	}
	return "", fmt.Errorf("nuclei started but returned no scan id")
}

func callMainHandler(h func(http.ResponseWriter, *http.Request), method, path string,
	vars map[string]string, body interface{}) (int, []byte) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if len(vars) > 0 {
		req = mux.SetURLVars(req, vars)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec.Code, rec.Body.Bytes()
}

func extractNucleiTargets(body []byte) []string {
	var wrapped struct {
		Targets []struct {
			URL             string `json:"url"`
			AssetIdentifier string `json:"asset_identifier"`
		} `json:"targets"`
	}
	var out []string
	if json.Unmarshal(body, &wrapped) == nil && len(wrapped.Targets) > 0 {
		for _, t := range wrapped.Targets {
			if t.URL != "" {
				out = append(out, t.URL)
			} else if t.AssetIdentifier != "" {
				out = append(out, t.AssetIdentifier)
			}
		}
		return out
	}
	// The endpoint may also answer with a bare array, which is what the client's second branch
	// handles (autoScanSteps.js:1417).
	var bare []struct {
		URL             string `json:"url"`
		AssetIdentifier string `json:"asset_identifier"`
	}
	if json.Unmarshal(body, &bare) == nil {
		for _, t := range bare {
			if t.URL != "" {
				out = append(out, t.URL)
			} else if t.AssetIdentifier != "" {
				out = append(out, t.AssetIdentifier)
			}
		}
	}
	return out
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func rawOrEmptyObject(raw []byte) interface{} {
	var v map[string]interface{}
	if len(raw) > 0 && json.Unmarshal(raw, &v) == nil {
		return v
	}
	return map[string]interface{}{}
}

func rawOrEmptyArray(raw []byte) interface{} {
	var v []interface{}
	if len(raw) > 0 && json.Unmarshal(raw, &v) == nil {
		return v
	}
	return []interface{}{}
}
