package utils

import (
	"context"
	"encoding/json"
	"log"
)

// Picking auto-scan sessions back up after the API restarts.
//
// A browser refresh no longer stops a scan because the sequencer is server-side. A restart of the
// API still would: the goroutine dies with the process. Marking those sessions interrupted was the
// honest minimum, but the run can actually be continued -- steps_run records which steps finished,
// and every step is independently restartable because each one starts a fresh scan row.
//
// This runs AFTER createTables, so the pending-scan sweep has already cleared the rows belonging to
// whichever step was mid-flight. That is exactly right: the interrupted step is not in steps_run,
// so it re-runs from the beginning against a clean row rather than waiting on a corpse.

// ResumeInterruptedAutoScans restarts every session left running by a restart.
func ResumeInterruptedAutoScans() {
	rows, err := dbPool.Query(context.Background(), `
		SELECT id::text, scope_target_id::text, COALESCE(steps_run::text, '[]')
		FROM auto_scan_sessions
		WHERE status IN ('pending', 'running')`)
	if err != nil {
		log.Printf("[AUTO-SCAN] Could not look for interrupted sessions: %v", err)
		return
	}

	type pending struct{ sessionID, targetID, steps string }
	var found []pending
	for rows.Next() {
		var p pending
		if rows.Scan(&p.sessionID, &p.targetID, &p.steps) == nil {
			found = append(found, p)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		log.Printf("[AUTO-SCAN] Could not read interrupted sessions: %v", err)
		return
	}

	for _, p := range found {
		var completed []string
		if json.Unmarshal([]byte(p.steps), &completed) != nil {
			// Every session created before steps_run was written has NULL here. Treat that as
			// "nothing is known to have finished" and start from the top, never as "nothing ran":
			// re-running a step is wasteful, skipping one silently leaves a gap in the scan.
			completed = nil
		}

		// A session whose target has been deleted can never run. Close it rather than leaving it
		// holding the one-live-session index against a target that no longer exists.
		var exists bool
		if err := dbPool.QueryRow(context.Background(),
			`SELECT EXISTS(SELECT 1 FROM scope_targets WHERE id = $1)`, p.targetID).Scan(&exists); err != nil || !exists {
			log.Printf("[AUTO-SCAN] Session %s cannot resume: its scope target is gone", p.sessionID)
			markAutoScanInterrupted(p.sessionID,
				"The scope target this scan belonged to no longer exists, so it could not be resumed.")
			continue
		}

		// A session that was PAUSED stays paused. The orchestrator's own pause wait handles it, so
		// resuming here does not silently restart a run the operator had deliberately held.
		log.Printf("[AUTO-SCAN] Resuming session %s (%d step(s) already done)", p.sessionID, len(completed))
		ResumeAutoScanOrchestrator(p.sessionID, p.targetID, completed)
	}

	if len(found) > 0 {
		log.Printf("[AUTO-SCAN] Resumed %d session(s) interrupted by a restart", len(found))
	}
}

func markAutoScanInterrupted(sessionID, reason string) {
	_, err := dbPool.Exec(context.Background(), `
		UPDATE auto_scan_sessions
		SET status = 'interrupted', ended_at = COALESCE(ended_at, NOW()),
		    error_message = COALESCE(error_message, $2)
		WHERE id = $1 AND status IN ('pending','running')`, sessionID, reason)
	if err != nil {
		log.Printf("[AUTO-SCAN] Could not mark session %s interrupted: %v", sessionID, err)
	}
}
