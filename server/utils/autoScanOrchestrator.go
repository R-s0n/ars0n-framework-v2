package utils

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
)

// The wildcard auto-scan sequencer, moved out of the browser.
//
// It used to be a for-loop in client/src/utils/wildcardAutoScan.js, so closing or refreshing the tab
// ended the scan: the tool that happened to be running finished (it is a detached goroutine) and
// nothing ever advanced past it. The nineteen steps and their order come from
// client/src/utils/autoScanSteps.js, which is the real specification -- the loop passes ~62
// arguments to getAutoScanSteps and BOTH call sites wrap it in a zero-argument closure
// (App.js:1796, :2466), so every one of those arguments is discarded. Reading the loop as the
// contract gets the wrong contract.
//
// Two decisions shape everything here.
//
// FIRST, steps are started by calling the EXISTING HTTP handlers in process rather than by
// reimplementing what they do. Each handler resolves the scope target, inserts the scan row with
// the right auto_scan_session_id and spawns the tool. Thirteen hand-copied versions of that would
// drift from the originals the first time one of them was fixed, and the drift would be invisible
// because both paths would still "work". Calling the handler means the orchestrator and the manual
// per-tool button run identical code by construction.
//
// SECOND, completion is decided by polling the scan row rather than by waiting on the goroutine.
// The tools spawn their own goroutines internally (ExecuteAndParseCeWLScansForUrls spawns one per
// URL), so a synchronous call would return before the work finished for some tools and not others.
// Polling the row is what the browser did and it is uniform.

// autoScanStep is one entry in the sequence. ConfigKey is the auto_scan_config field that switches
// it off; an absent key means the step always runs.
type autoScanStep struct {
	Name      string
	ConfigKey string
	Run       func(*autoScanRun) error
}

type autoScanRun struct {
	ctx       context.Context
	sessionID string
	targetID  string
	domain    string // bare domain: scope_target with the leading "*." removed
	config    autoScanConfigValues
	stepsRun  []string
}

// autoScanConfigValues mirrors the JSON getAutoScanConfig returns.
type autoScanConfigValues struct {
	Amass                     bool `json:"amass"`
	Sublist3r                 bool `json:"sublist3r"`
	Assetfinder               bool `json:"assetfinder"`
	Gau                       bool `json:"gau"`
	Ctl                       bool `json:"ctl"`
	Subfinder                 bool `json:"subfinder"`
	ConsolidateHttpxRound1    bool `json:"consolidate_httpx_round1"`
	Shuffledns                bool `json:"shuffledns"`
	Cewl                      bool `json:"cewl"`
	ConsolidateHttpxRound2    bool `json:"consolidate_httpx_round2"`
	Gospider                  bool `json:"gospider"`
	Subdomainizer             bool `json:"subdomainizer"`
	ConsolidateHttpxRound3    bool `json:"consolidate_httpx_round3"`
	NucleiScreenshot          bool `json:"nuclei_screenshot"`
	Metadata                  bool `json:"metadata"`
	Nuclei                    bool `json:"nuclei"`
	MaxConsolidatedSubdomains int  `json:"maxConsolidatedSubdomains"`
	MaxLiveWebServers         int  `json:"maxLiveWebServers"`
}

// enabled answers the gate for a step. Absent key means "always".
func (c autoScanConfigValues) enabled(key string) bool {
	switch key {
	case "":
		return true
	case "amass":
		return c.Amass
	case "sublist3r":
		return c.Sublist3r
	case "assetfinder":
		return c.Assetfinder
	case "gau":
		return c.Gau
	case "ctl":
		return c.Ctl
	case "subfinder":
		return c.Subfinder
	case "consolidate_httpx_round1":
		return c.ConsolidateHttpxRound1
	case "shuffledns":
		return c.Shuffledns
	case "cewl":
		return c.Cewl
	case "consolidate_httpx_round2":
		return c.ConsolidateHttpxRound2
	case "gospider":
		return c.Gospider
	case "subdomainizer":
		return c.Subdomainizer
	case "consolidate_httpx_round3":
		return c.ConsolidateHttpxRound3
	case "nuclei_screenshot":
		return c.NucleiScreenshot
	case "metadata":
		return c.Metadata
	case "nuclei":
		return c.Nuclei
	}
	return true
}

// errAutoScanStopped ends the run without recording a failure: the operator asked for it.
var errAutoScanStopped = fmt.Errorf("auto scan stopped")

// autoScanRunning tracks live orchestrators so a cancel can reach the goroutine rather than only
// setting a flag the loop reads between steps.
var (
	autoScanRunningMu sync.Mutex
	autoScanRunning   = map[string]context.CancelFunc{}
)

// ---------------------------------------------------------------- the sequence

// autoScanSteps is the nineteen steps, in the order autoScanSteps.js runs them.
func autoScanSequence() []autoScanStep {
	return []autoScanStep{
		{"amass", "amass", func(r *autoScanRun) error { return r.runTool("amass", "amass_scans") }},
		{"sublist3r", "sublist3r", func(r *autoScanRun) error { return r.runTool("sublist3r", "sublist3r_scans") }},
		{"assetfinder", "assetfinder", func(r *autoScanRun) error { return r.runTool("assetfinder", "assetfinder_scans") }},
		{"gau", "gau", func(r *autoScanRun) error { return r.runTool("gau", "gau_scans") }},
		{"ctl", "ctl", func(r *autoScanRun) error { return r.runTool("ctl", "ctl_scans") }},
		{"subfinder", "subfinder", func(r *autoScanRun) error { return r.runTool("subfinder", "subfinder_scans") }},

		{"consolidate", "consolidate_httpx_round1", func(r *autoScanRun) error { return r.consolidate("consolidate") }},
		{"httpx", "consolidate_httpx_round1", func(r *autoScanRun) error { return r.httpx("httpx") }},

		{"shuffledns", "shuffledns", func(r *autoScanRun) error { return r.runTool("shuffledns", "shuffledns_scans") }},
		{"shuffledns_cewl", "cewl", func(r *autoScanRun) error { return r.cewl() }},

		{"consolidate_round2", "consolidate_httpx_round2", func(r *autoScanRun) error { return r.consolidate("consolidate_round2") }},
		{"httpx_round2", "consolidate_httpx_round2", func(r *autoScanRun) error { return r.httpx("httpx_round2") }},

		{"gospider", "gospider", func(r *autoScanRun) error { return r.runTool("gospider", "gospider_scans") }},
		{"subdomainizer", "subdomainizer", func(r *autoScanRun) error { return r.runTool("subdomainizer", "subdomainizer_scans") }},

		{"consolidate_round3", "consolidate_httpx_round3", func(r *autoScanRun) error { return r.consolidate("consolidate_round3") }},
		{"httpx_round3", "consolidate_httpx_round3", func(r *autoScanRun) error { return r.httpx("httpx_round3") }},

		{"nuclei-screenshot", "nuclei_screenshot", func(r *autoScanRun) error { return r.nucleiScreenshot() }},
		{"metadata", "metadata", func(r *autoScanRun) error { return r.runTool("metadata", "metadata_scans") }},
		{"nuclei", "nuclei", func(r *autoScanRun) error { return r.nuclei() }},
	}
}

// ---------------------------------------------------------------- entry point

// StartAutoScanOrchestrator launches the sequencer for a session. The caller has already inserted
// the session row and taken the single-flight guard.
func StartAutoScanOrchestrator(sessionID, targetID string) {
	startAutoScanOrchestrator(sessionID, targetID, nil)
}

// ResumeAutoScanOrchestrator picks a session back up after a restart, skipping the steps that had
// already finished.
func ResumeAutoScanOrchestrator(sessionID, targetID string, completed []string) {
	startAutoScanOrchestrator(sessionID, targetID, completed)
}

func startAutoScanOrchestrator(sessionID, targetID string, completed []string) {
	ctx, cancel := context.WithCancel(context.Background())

	autoScanRunningMu.Lock()
	autoScanRunning[sessionID] = cancel
	autoScanRunningMu.Unlock()

	go func() {
		defer func() {
			autoScanRunningMu.Lock()
			delete(autoScanRunning, sessionID)
			autoScanRunningMu.Unlock()
			cancel()
			// A panic in one step must not take the API down and must not leave the session
			// wedged in 'running', where the unique index would block every future start.
			if rec := recover(); rec != nil {
				log.Printf("[AUTO-SCAN] PANIC in session %s: %v", sessionID, rec)
				finishAutoScanSession(sessionID, targetID, "error", fmt.Sprintf("internal error: %v", rec))
			}
		}()
		runAutoScan(ctx, sessionID, targetID, completed)
	}()
}

// CancelAutoScanOrchestrator stops a live run. The flag is still what the loop reads between steps;
// cancelling the context additionally unblocks a wait that is mid-poll so the run stops promptly
// instead of after the current tool's next poll interval.
func CancelAutoScanOrchestrator(sessionID string) bool {
	autoScanRunningMu.Lock()
	cancel, ok := autoScanRunning[sessionID]
	autoScanRunningMu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

func runAutoScan(ctx context.Context, sessionID, targetID string, completed []string) {
	scopeTarget, err := autoScanScopeTarget(targetID)
	if err != nil {
		log.Printf("[AUTO-SCAN] %s: cannot read scope target: %v", sessionID, err)
		finishAutoScanSession(sessionID, targetID, "error", "Could not read the scope target for this session.")
		return
	}
	// The client does exactly this: activeTarget.scope_target.replace('*.', '')
	domain := strings.Replace(scopeTarget, "*.", "", 1)

	// Steps already recorded as finished are not re-run. A step that was mid-flight when the process
	// died is NOT in this list -- steps_run records completions, not attempts -- so it runs again,
	// which is what you want: its tool goroutine died with the process and its scan row was either
	// left dangling or deleted by the pending-scan sweep.
	done := map[string]bool{}
	for _, name := range completed {
		done[name] = true
	}

	run := &autoScanRun{ctx: ctx, sessionID: sessionID, targetID: targetID, domain: domain, stepsRun: completed}
	if len(completed) > 0 {
		log.Printf("[AUTO-SCAN] session %s RESUMING for %s, %d step(s) already done", sessionID, domain, len(completed))
	} else {
		log.Printf("[AUTO-SCAN] session %s starting for %s", sessionID, domain)
	}

	for _, step := range autoScanSequence() {
		// Config is re-read before every step ON PURPOSE. The browser loop read it once per run,
		// but each step's gate was evaluated against the config object the step closure captured at
		// build time, and the steps were rebuilt per iteration -- so editing the config mid-scan
		// did affect the remaining steps. Re-reading preserves that.
		cfg, err := loadAutoScanConfigValues()
		if err != nil {
			log.Printf("[AUTO-SCAN] %s: cannot read config: %v", sessionID, err)
			finishAutoScanSession(sessionID, targetID, "error", "Could not read the auto scan configuration.")
			return
		}
		run.config = cfg

		stop, reason := run.shouldStop()
		if stop {
			log.Printf("[AUTO-SCAN] %s stopping before %s: %s", sessionID, step.Name, reason)
			setAutoScanState(targetID, "completed", false, false)
			finishAutoScanSession(sessionID, targetID, "completed", "")
			return
		}
		if run.paused() {
			// Paused means "hold here", not "give up". The browser polled every 2s waiting for the
			// operator to resume, and so does this.
			if !run.waitWhilePaused(step.Name) {
				setAutoScanState(targetID, "completed", false, false)
				finishAutoScanSession(sessionID, targetID, "completed", "")
				return
			}
		}

		if !cfg.enabled(step.ConfigKey) {
			continue
		}
		if done[step.Name] {
			continue
		}

		// All three columns are written together, exactly as the browser helper did with its
		// false,false defaults. That blanket write is the ONLY thing in the repository that clears
		// is_cancelled -- Resume clears is_paused alone -- so writing current_step by itself would
		// latch a cancel forever and make the target permanently unstartable.
		setAutoScanState(targetID, step.Name, false, false)
		log.Printf("[AUTO-SCAN] %s step %s", sessionID, step.Name)

		if err := step.Run(run); err != nil {
			if err == errAutoScanStopped || ctx.Err() != nil {
				setAutoScanState(targetID, "completed", false, false)
				finishAutoScanSession(sessionID, targetID, "completed", "")
				return
			}
			// A failing tool does not end the run. The browser's waiter treated 'failed' and
			// 'error' exactly like success and moved on, and several steps depend on later ones
			// running regardless.
			log.Printf("[AUTO-SCAN] %s step %s reported: %v (continuing)", sessionID, step.Name, err)
		}
		run.stepsRun = append(run.stepsRun, step.Name)
		recordAutoScanStep(sessionID, run.stepsRun)
	}

	setAutoScanState(targetID, "completed", false, false)
	finishAutoScanSession(sessionID, targetID, "completed", "")
	log.Printf("[AUTO-SCAN] session %s finished", sessionID)
}
