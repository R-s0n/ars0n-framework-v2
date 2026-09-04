package utils

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// The individual steps, and the plumbing that starts a handler in process and waits for its row.

// scanPollInterval matches the browser's 5s poll. Not tuned down: several of these tools take
// minutes and the interval only decides how quickly the run notices, not how fast the tool goes.
const scanPollInterval = 5 * time.Second

// callHandler runs one of the existing HTTP handlers in process and returns its status and body.
//
// This is how the orchestrator avoids owning a second copy of thirteen handlers' row-insert logic.
// mux.SetURLVars is required because several handlers read path variables.
func callHandler(h http.HandlerFunc, method, path string, vars map[string]string, body interface{}) (int, []byte) {
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

// scanIDFrom pulls the scan id out of a handler response. The handlers are not consistent about
// the key, so both spellings are accepted rather than silently returning "".
func scanIDFrom(body []byte) string {
	var out map[string]interface{}
	if json.Unmarshal(body, &out) != nil {
		return ""
	}
	for _, key := range []string{"scan_id", "scanID", "id"} {
		if v, ok := out[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// waitForScanRow blocks until a scan row reaches a terminal status.
//
// Keyed on scan_id, unlike the browser, which took the NEWEST row of that type by created_at
// (wildcardAutoScan.js:118). That was wrong in a way that only showed up on a second run: httpx
// rounds 2 and 3 could resolve against round 1's already-completed row and return immediately.
//
// The terminal set is deliberately wide. Different tools end differently -- nuclei writes 'failed'
// rather than 'error', metadata writes an interim 'running', gau writes an interim 'processing' --
// and treating an unknown status as terminal would end a step early.
func (r *autoScanRun) waitForScanRow(table, scanID string) error {
	if scanID == "" {
		return fmt.Errorf("no scan id returned")
	}
	query := fmt.Sprintf(`SELECT status FROM %s WHERE scan_id = $1`, table)
	for {
		select {
		case <-r.ctx.Done():
			return errAutoScanStopped
		case <-time.After(scanPollInterval):
		}

		// Cancel is checked while waiting as well as between steps. The browser could not do this:
		// its waiter never looked at the flag, so a cancel was not noticed until the running tool
		// finished. Honouring it here stops the SEQUENCE promptly; the tool already running is
		// still left to finish and store its results, which is what cancel has always meant.
		if r.cancelled() {
			return errAutoScanStopped
		}

		var status string
		if err := dbPool.QueryRow(r.ctx, query, scanID).Scan(&status); err != nil {
			if r.ctx.Err() != nil {
				return errAutoScanStopped
			}
			// A row that is not there yet is normal immediately after the insert.
			continue
		}
		switch status {
		case "success", "completed", "failed", "error", "cancelled":
			return nil
		}
	}
}

// runTool is the shape thirteen of the nineteen steps share: call the handler, wait for the row.
func (r *autoScanRun) runTool(tool, table string) error {
	h, body, path, vars := autoScanToolRequest(tool, r)
	if h == nil {
		return fmt.Errorf("no handler wired for %s", tool)
	}
	code, resp := callHandler(h, "POST", path, vars, body)
	if code < 200 || code > 299 {
		return fmt.Errorf("%s refused to start (%d): %s", tool, code, autoScanTruncate(string(resp)))
	}
	return r.waitForScanRow(table, scanIDFrom(resp))
}

// autoScanToolRequest maps a step to the handler and body the browser sent it.
func autoScanToolRequest(tool string, r *autoScanRun) (http.HandlerFunc, interface{}, string, map[string]string) {
	session := r.sessionID
	fqdnBody := map[string]interface{}{"fqdn": r.domain, "auto_scan_session_id": session}

	switch tool {
	case "amass":
		return RunAmassScan, fqdnBody, "/amass/run", nil
	case "sublist3r":
		return RunSublist3rScan, fqdnBody, "/sublist3r/run", nil
	case "assetfinder":
		return RunAssetfinderScan, fqdnBody, "/assetfinder/run", nil
	case "gau":
		return RunGauScan, fqdnBody, "/gau/run", nil
	case "ctl":
		return RunCTLScan, fqdnBody, "/ctl/run", nil
	case "subfinder":
		return RunSubfinderScan, fqdnBody, "/subfinder/run", nil
	case "shuffledns":
		return RunShuffleDNSScan, fqdnBody, "/shuffledns/run", nil
	case "gospider":
		return RunGoSpiderScan, fqdnBody, "/gospider/run", nil
	case "subdomainizer":
		return RunSubdomainizerScan, fqdnBody, "/subdomainizer/run", nil
	case "metadata":
		return RunMetaDataScan, fqdnBody, "/metadata/run", nil
	}
	return nil, nil, "", nil
}

// ---------------------------------------------------------------- the special steps

// consolidate folds the sources into consolidated_subdomains, then applies the subdomain cap.
func (r *autoScanRun) consolidate(stepName string) error {
	// The 3s pause before consolidating is not padding. Consolidation reads rows the previous tool
	// is still committing, and without it a consolidation can run short and read as "the tools
	// found nothing". autoScanSteps.js:531, :849, :1121.
	if !r.sleep(3 * time.Second) {
		return errAutoScanStopped
	}

	code, resp := callHandler(HandleConsolidateSubdomains, "GET",
		"/consolidate-subdomains/"+r.targetID, map[string]string{"id": r.targetID}, nil)
	if code < 200 || code > 299 {
		return fmt.Errorf("consolidation failed (%d): %s", code, autoScanTruncate(string(resp)))
	}

	count, err := autoScanCount(`SELECT count(*) FROM consolidated_subdomains WHERE scope_target_id = $1`, r.targetID)
	if err != nil {
		return err
	}
	// `cap > 0 &&` reproduces the client's falsy check (autoScanSteps.js:560). A bare count > cap
	// would arm a brake that is currently OFF whenever the cap is 0, which is a behaviour change
	// disguised as a bug fix.
	if r.config.MaxConsolidatedSubdomains > 0 && count > r.config.MaxConsolidatedSubdomains {
		log.Printf("[AUTO-SCAN] %s pausing at %s: %d consolidated subdomains exceeds the cap of %d",
			r.sessionID, stepName, count, r.config.MaxConsolidatedSubdomains)
		setAutoScanState(r.targetID, stepName, true, false)
		return errAutoScanStopped
	}
	return nil
}

// httpx probes the consolidated set, then applies the live-server cap.
func (r *autoScanRun) httpx(stepName string) error {
	// The stored per-target httpx config, which is where the browser's httpxScanConfig came from
	// (App.js:3945 reads GET /httpx-config/{id}). Reading it here is what stops a server-driven
	// httpx from silently running with defaults.
	var cfg *HttpxScanConfig
	var raw []byte
	if err := dbPool.QueryRow(r.ctx,
		`SELECT config FROM httpx_configs WHERE scope_target_id = $1`, r.targetID).Scan(&raw); err == nil && len(raw) > 0 {
		var parsed HttpxScanConfig
		if json.Unmarshal(raw, &parsed) == nil {
			cfg = &parsed
		}
	}

	body := map[string]interface{}{"fqdn": r.domain, "auto_scan_session_id": r.sessionID}
	if cfg != nil {
		body["config"] = cfg
	}
	code, resp := callHandler(RunHttpxScan, "POST", "/httpx/run", nil, body)
	if code < 200 || code > 299 {
		return fmt.Errorf("httpx refused to start (%d): %s", code, autoScanTruncate(string(resp)))
	}
	if err := r.waitForScanRow("httpx_scans", scanIDFrom(resp)); err != nil {
		return err
	}

	// 1s settle before counting, matching autoScanSteps.js:630, :944, :1216.
	if !r.sleep(time.Second) {
		return errAutoScanStopped
	}

	count, err := autoScanCount(`SELECT count(*) FROM target_urls WHERE scope_target_id = $1`, r.targetID)
	if err != nil {
		return err
	}
	if r.config.MaxLiveWebServers > 0 && count > r.config.MaxLiveWebServers {
		log.Printf("[AUTO-SCAN] %s pausing at %s: %d live web servers exceeds the cap of %d",
			r.sessionID, stepName, count, r.config.MaxLiveWebServers)
		setAutoScanState(r.targetID, stepName, true, false)
		return errAutoScanStopped
	}
	return nil
}

// cewl runs CeWL and then waits for the shufflednscustom scan the server chains off it.
//
// This step needs its own waiter and must NOT be folded into runTool. UpdateCeWLScanStatus marks
// the CeWL row 'success' at bruteForceUtils.go:735 -- BEFORE the shufflednscustom row is inserted
// and before the brute force runs at all. A generic wait-for-terminal-status therefore returns
// while shuffledns is still resolving, and the next consolidation deletes and re-inserts
// consolidated_subdomains against a half-written result set.
func (r *autoScanRun) cewl() error {
	code, resp := callHandler(RunCeWLScan, "POST", "/cewl/run",
		nil, map[string]interface{}{"fqdn": r.domain, "auto_scan_session_id": r.sessionID})
	if code < 200 || code > 299 {
		return fmt.Errorf("cewl refused to start (%d): %s", code, autoScanTruncate(string(resp)))
	}
	if err := r.waitForScanRow("cewl_scans", scanIDFrom(resp)); err != nil {
		return err
	}

	// Now wait for the chained custom-wordlist brute force, keyed on the target because the CeWL
	// response cannot name a scan that did not exist when it answered.
	deadline := time.Now().Add(2 * time.Hour)
	for time.Now().Before(deadline) {
		if !r.sleep(scanPollInterval) {
			return errAutoScanStopped
		}
		var status string
		err := dbPool.QueryRow(r.ctx, `
			SELECT status FROM shufflednscustom_scans
			WHERE scope_target_id = $1 ORDER BY created_at DESC LIMIT 1`, r.targetID).Scan(&status)
		if err != nil {
			if r.ctx.Err() != nil {
				return errAutoScanStopped
			}
			continue
		}
		switch status {
		case "success", "completed", "failed", "error", "cancelled":
			// 5s trailing buffer, autoScanSteps.js:828.
			if !r.sleep(5 * time.Second) {
				return errAutoScanStopped
			}
			return nil
		}
	}
	return fmt.Errorf("shufflednscustom did not finish within 2h")
}

func (r *autoScanRun) nucleiScreenshot() error {
	code, resp := callHandler(RunNucleiScreenshotScan, "POST",
		"/scopetarget/"+r.targetID+"/nuclei-screenshot/run",
		map[string]string{"id": r.targetID},
		map[string]interface{}{"fqdn": r.domain, "auto_scan_session_id": r.sessionID})
	if code < 200 || code > 299 {
		return fmt.Errorf("nuclei-screenshot refused to start (%d): %s", code, autoScanTruncate(string(resp)))
	}
	return r.waitForScanRow("nuclei_screenshots", scanIDFrom(resp))
}

// AutoScanNucleiStep is set by package main at startup. It prepares the nuclei config exactly as
// the browser did and starts the scan, returning the scan id to wait on.
var AutoScanNucleiStep func(targetID, sessionID string) (string, error)

// nuclei is last and has its own shape: it skips entirely when there is nothing to scan.
func (r *autoScanRun) nuclei() error {
	targets, err := autoScanCount(`SELECT count(*) FROM target_urls WHERE scope_target_id = $1`, r.targetID)
	if err != nil {
		return err
	}
	if targets == 0 {
		// The client returns early here rather than starting a scan with no targets
		// (autoScanSteps.js:1420). Starting one would record a scan that could not have found
		// anything, which reads later as "nuclei found nothing".
		log.Printf("[AUTO-SCAN] %s: no nuclei targets, skipping", r.sessionID)
		return nil
	}
	// startNucleiScan and the nuclei-config handlers live in package main, which imports utils, so
	// utils cannot call them. main registers the step here at startup instead. The hook also does
	// the config write the browser did (merge the stored config with the default templates and
	// severities, force target_mode "httpx", save it back) -- startNucleiScan re-reads that row
	// rather than using the caller's values, so skipping the write would silently run nuclei
	// against whatever mode was last stored.
	if AutoScanNucleiStep == nil {
		return fmt.Errorf("nuclei step is not registered")
	}
	scanID, err := AutoScanNucleiStep(r.targetID, r.sessionID)
	if err != nil {
		return err
	}
	return r.waitForScanRow("nuclei_scans", scanID)
}

// ---------------------------------------------------------------- run helpers

// sleep waits, but returns false the moment the run is stopping, so a cancel does not have to wait
// out a five second pause.
func (r *autoScanRun) sleep(d time.Duration) bool {
	select {
	case <-r.ctx.Done():
		return false
	case <-time.After(d):
		return !r.cancelled()
	}
}

func (r *autoScanRun) cancelled() bool {
	var cancelled bool
	err := dbPool.QueryRow(context.Background(),
		`SELECT COALESCE(is_cancelled, false) FROM auto_scan_state WHERE scope_target_id = $1`,
		r.targetID).Scan(&cancelled)
	return err == nil && cancelled
}

func (r *autoScanRun) paused() bool {
	var paused bool
	err := dbPool.QueryRow(context.Background(),
		`SELECT COALESCE(is_paused, false) FROM auto_scan_state WHERE scope_target_id = $1`,
		r.targetID).Scan(&paused)
	return err == nil && paused
}

func (r *autoScanRun) shouldStop() (bool, string) {
	if r.ctx.Err() != nil {
		return true, "run cancelled"
	}
	if r.cancelled() {
		return true, "cancelled by operator"
	}
	return false, ""
}

// waitWhilePaused holds the sequence while is_paused is set, returning false if the run should end
// instead of resuming. The browser polled every 2s for the same purpose.
func (r *autoScanRun) waitWhilePaused(stepName string) bool {
	log.Printf("[AUTO-SCAN] %s paused before %s", r.sessionID, stepName)
	for {
		if !r.sleep(2 * time.Second) {
			return false
		}
		if r.cancelled() {
			return false
		}
		if !r.paused() {
			log.Printf("[AUTO-SCAN] %s resumed at %s", r.sessionID, stepName)
			return true
		}
	}
}

func autoScanTruncate(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
