package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"time"

	"github.com/gorilla/mux"
)

// Stopping a run, and making sure the tool stops with it.
//
// Two facts make this less obvious than it looks. The steps run sequentially inside a goroutine that
// nothing holds a handle to, so cancellation has to be cooperative: a flag the goroutine reads
// between steps. And killing the context around `docker exec` kills the docker CLI client, NOT ffuf
// inside the container, so a cancelled or timed-out step leaves ffuf running and still sending
// requests to a target the framework believes it has stopped hitting. x8 hit exactly this and
// killX8InContainer is the precedent; the ffuf image is golang:1.24-alpine and does have pkill, so
// this one can be direct rather than walking /proc.

// CancelFuzzRun handles POST /fuzz/runs/{run_id}/cancel.
func CancelFuzzRun(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	runID := mux.Vars(r)["run_id"]
	ctx := context.Background()

	var status string
	if err := dbPool.QueryRow(ctx,
		`SELECT status FROM fuzz_runs WHERE id = $1`, runID).Scan(&status); err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "run not found")
		return
	}
	if status != "running" && status != "pending" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"run_id": runID, "status": status,
			"message": "This run already finished, so there is nothing to cancel.",
		})
		return
	}

	// The flag first, so the goroutine stops at the next step boundary even if the kill below fails.
	if _, err := dbPool.Exec(ctx,
		`UPDATE fuzz_runs SET cancel_requested = TRUE WHERE id = $1`, runID); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	// The step currently in flight will not stop on its own: it is a foreign process in another
	// container that only exits when its wordlist runs out.
	killed := killFfufForRun(runID)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"run_id": runID, "cancel_requested": true, "killed_processes": killed,
		"message": "Cancellation requested. The step in flight was signalled and no further steps " +
			"will start. Findings already stored are kept.",
	})
}

// killFfufForRun stops any ffuf process working for this run.
//
// Matched on the run's own /tmp/fuzz/<runID>/ directory, which appears in every invocation's
// -request and -o paths, so a concurrent run for another target is untouched. Returns whether the
// kill command reported success, which is best-effort by nature: the process may have exited between
// the check and the signal.
// Retried, because a single attempt can arrive in the gap before ffuf exists. The runner spends about
// a second rendering a step (one docker exec per wordlist to count it) between deciding to run and
// spawning ffuf, so one pkill can match nothing and be reported as "already stopped" while the step
// then starts and sends its whole wordlist. Retrying covers the spawn; the runner also re-reads the
// cancel flag immediately before spawning, which covers the rest.
func killFfufForRun(runID string) bool {
	killed := false
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(500 * time.Millisecond)
		}
		killCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		// pkill -f matches the full command line. The exit status is 1 when nothing matched, which is a
		// normal outcome rather than an error.
		err := exec.CommandContext(killCtx, "docker", "exec", ffufContainer,
			"pkill", "-f", fmt.Sprintf("/tmp/fuzz/%s/", runID)).Run()
		cancel()
		if err == nil {
			killed = true
		}
	}
	return killed
}

// fuzzRunCancelled reports whether the operator has asked this run to stop. Read between steps.
func fuzzRunCancelled(ctx context.Context, runID string) bool {
	var cancelled bool
	if err := dbPool.QueryRow(ctx,
		`SELECT cancel_requested FROM fuzz_runs WHERE id = $1`, runID).Scan(&cancelled); err != nil {
		return false
	}
	return cancelled
}
