package utils

import (
	"context"
	"encoding/json"
	"log"
)

// State the orchestrator reads and writes. Kept beside the sequencer so the columns it depends on
// are visible in one place.

// autoScanScopeTarget returns the scope_target string, e.g. "*.example.com".
func autoScanScopeTarget(targetID string) (string, error) {
	var scopeTarget string
	err := dbPool.QueryRow(context.Background(),
		`SELECT scope_target FROM scope_targets WHERE id = $1`, targetID).Scan(&scopeTarget)
	return scopeTarget, err
}

func autoScanCount(query, targetID string) (int, error) {
	var n int
	err := dbPool.QueryRow(context.Background(), query, targetID).Scan(&n)
	return n, err
}

// loadAutoScanConfigValues reads the singleton config row.
//
// It is a GLOBAL singleton with no scope_target_id (database.go:101), so two targets share one set
// of caps. That is pre-existing and deliberately not changed here: making it per target would alter
// what the caps mean on every existing installation. The single-flight guard means only one run
// reads it at a time, which is the case that mattered.
func loadAutoScanConfigValues() (autoScanConfigValues, error) {
	var cfg autoScanConfigValues
	var raw []byte
	err := dbPool.QueryRow(context.Background(), `
		SELECT row_to_json(c) FROM (
			SELECT amass, sublist3r, assetfinder, gau, ctl, subfinder,
			       consolidate_httpx_round1, shuffledns, cewl, consolidate_httpx_round2,
			       gospider, subdomainizer, consolidate_httpx_round3,
			       nuclei_screenshot, metadata, nuclei,
			       max_consolidated_subdomains AS "maxConsolidatedSubdomains",
			       max_live_web_servers AS "maxLiveWebServers"
			FROM auto_scan_config LIMIT 1
		) c`).Scan(&raw)
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// setAutoScanState writes all three columns together.
//
// Writing current_step alone would be the single most damaging shortcut available here. The blanket
// false,false is the ONLY thing in the repository that ever clears is_cancelled: the browser helper
// defaults both flags to false on every step transition, and Resume clears is_paused alone. Drop it
// and a cancelled target keeps the flag forever, so every later run stops at its first check with
// nothing in the UI to explain why.
func setAutoScanState(targetID, step string, paused, cancelled bool) {
	_, err := dbPool.Exec(context.Background(), `
		INSERT INTO auto_scan_state (scope_target_id, current_step, is_paused, is_cancelled, updated_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (scope_target_id) DO UPDATE
		SET current_step = EXCLUDED.current_step,
		    is_paused = EXCLUDED.is_paused,
		    is_cancelled = EXCLUDED.is_cancelled,
		    updated_at = NOW()`, targetID, step, paused, cancelled)
	if err != nil {
		log.Printf("[AUTO-SCAN] could not write state for %s: %v", targetID, err)
	}
}

// recordAutoScanStep appends to steps_run.
//
// This column has been read in four places and written in none, so every historical row is NULL.
// It is the only record of what actually COMPLETED: current_step says where the sequence got to,
// which is a different question and is unvalidated TEXT.
func recordAutoScanStep(sessionID string, stepsRun []string) {
	payload, err := json.Marshal(stepsRun)
	if err != nil {
		return
	}
	if _, err := dbPool.Exec(context.Background(),
		`UPDATE auto_scan_sessions SET steps_run = $1 WHERE id = $2`, string(payload), sessionID); err != nil {
		log.Printf("[AUTO-SCAN] could not record steps_run for %s: %v", sessionID, err)
	}
}

// finishAutoScanSession closes the session out and records the final counts the history modal shows.
//
// Guarded on the current status so a late writer cannot flip a terminal row: updateAutoScanSessionFinalStats
// hard-sets 'completed' with no such check today, which is why no session has ever been recorded as
// cancelled even though both callers of /cancel pass through it.
func finishAutoScanSession(sessionID, targetID, status, errMsg string) {
	consolidated, _ := autoScanCount(`SELECT count(*) FROM consolidated_subdomains WHERE scope_target_id = $1`, targetID)
	live, _ := autoScanCount(`SELECT count(*) FROM target_urls WHERE scope_target_id = $1`, targetID)

	var errValue interface{}
	if errMsg != "" {
		errValue = errMsg
	}
	_, err := dbPool.Exec(context.Background(), `
		UPDATE auto_scan_sessions
		SET status = $1,
		    ended_at = NOW(),
		    error_message = COALESCE($2, error_message),
		    final_consolidated_subdomains = $3,
		    final_live_web_servers = $4
		WHERE id = $5 AND status IN ('pending','running')`,
		status, errValue, consolidated, live, sessionID)
	if err != nil {
		log.Printf("[AUTO-SCAN] could not finish session %s: %v", sessionID, err)
	}
}
