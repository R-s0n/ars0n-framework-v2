package utils

import "strings"

// Which stored run outputs keep their bytes, and why a missing one is not a missing run.
//
// TWO DEFECTS, measured on 2026-09-17, and they compound.
//
// FIRST, absence was unexplainable. The old policy DELETED the whole trace row, so a pruned run and
// a run that never happened looked identical: no row either way. A vector with zero traces was
// investigated as a fail-open for a real chunk of an afternoon before the retention policy was
// found. The retention itself was never the bug; the silence was.
//
// SECOND, the policy assumed a scan is a large batch. It kept three SCANS. This operator drives ONE
// VECTOR PER SCAN, so "keep 3 scans" kept 3 VECTORS out of 140. Measured directly: every dalfox scan
// before 21:14 had 0 traces and every one after had 2.
//
// So pruning now blanks the OUTPUT and keeps the ROW, which is what the original comment always
// claimed it did, and retention counts VECTOR RUNS rather than scans. A blanked row still carries
// the command, the exit, the duration and the original byte count, which is a few hundred bytes
// against the 64 KB (vectorTraceStdoutLimit) an output can occupy, and it answers the only question
// that matters: this run happened, and its output aged out.

const (
	// The most recent runs of one tool on one target that keep their output no matter what they are.
	//
	// Fifty, not three, because the unit is now a vector run: the campaign that exposed this drove
	// 140 vectors through 140 single-vector scans in an evening, and three of them was not a
	// diagnostic window, it was a rounding error. Fifty covers a day of that pattern and still bounds
	// the table: 50 runs times 64 KB is about 3 MB per tool per target.
	vectorTraceRecentKept = 50

	// The most recent INTERESTING runs that keep their output on top of the recent ones.
	//
	// A timeout or a non-zero exit is worth far more than a clean run, and the boring ones are what
	// should be dropped first. Six vectors timed out in that campaign and their output is the only
	// place the reason could have been read; under a flat recency rule the next fifty clean runs
	// would have pushed all six out.
	vectorTraceInterestingKept = 50

	// A ceiling on how many rows one prune pass will consider, so this stays a bounded query on a
	// table nothing else deletes from. Rows beyond it are already blanked by earlier passes, because
	// pruning only ever moves forward in time.
	vectorTraceScanRows = 5000
)

// vectorTracePrunedNote replaces the stored output. It is written into the stdout column so that
// every reader, including one going at the table with psql, sees the explanation rather than an
// empty string that reads like a run which printed nothing.
const vectorTracePrunedNote = "[output aged out] This run happened and its command, exit status, " +
	"duration and output size are still recorded above. Only the captured output was dropped, to " +
	"bound the size of the trace table. Re-run the vector to get output for it again."

// traceRetention is the one row the planner needs, with no database types in it so the policy can be
// tested without a database.
type traceRetention struct {
	ID string
	// TimedOut and ExitDetail come straight from the stored columns.
	TimedOut   bool
	ExitDetail string
	// Pruned is whether the output has already been dropped. An already blank row is never returned
	// again, so a prune pass that changes nothing issues no writes.
	Pruned bool
}

// traceExitWasClean reports whether this trace's exit_detail describes a successful exit.
//
// Coupled to exitDescription, which writes "0 (success, ...)" for a nil error and the error string
// otherwise, and a test pins the two together so a change to one cannot silently reclassify every
// stored trace as interesting (or, worse, every failure as boring).
func traceExitWasClean(detail string) bool {
	return strings.HasPrefix(strings.TrimSpace(detail), "0 (success")
}

func (t traceRetention) interesting() bool {
	return t.TimedOut || !traceExitWasClean(t.ExitDetail)
}

// planTraceBlanking takes the rows for one tool on one target, NEWEST FIRST, and returns the ids
// whose output should be dropped.
//
// Two independent keep sets, unioned:
//
//	the newest vectorTraceRecentKept rows, whatever they are, so "what did the last runs do" is
//	always answerable;
//	the newest vectorTraceInterestingKept rows that timed out or exited non-zero, so a rare failure
//	is not pushed out by a run of ordinary successes.
//
// Everything else that still holds output is returned. Nothing is deleted anywhere: the caller
// blanks, and the row survives so that a reader can tell a pruned run from a run that never
// happened, which is the whole reason this file exists.
func planTraceBlanking(newestFirst []traceRetention) []string {
	var blank []string
	// Counted over EVERY interesting row seen, including the ones inside the recent window. Counting
	// only the ones outside it would let a burst of failures at the top spend nothing, and the two
	// tiers would then stack: fifty recent plus fifty more failures underneath them, indefinitely.
	interestingSeen := 0

	for index, row := range newestFirst {
		keep := index < vectorTraceRecentKept
		if row.interesting() {
			interestingSeen++
			if interestingSeen <= vectorTraceInterestingKept {
				keep = true
			}
		}
		if keep || row.Pruned {
			continue
		}
		blank = append(blank, row.ID)
	}
	return blank
}
