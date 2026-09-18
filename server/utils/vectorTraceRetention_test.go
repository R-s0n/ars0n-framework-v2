package utils

import (
	"fmt"
	"strings"
	"testing"
)

// cleanRun is what a trace row looks like for a run that exited 0, which is the overwhelming
// majority of them and the reason a flat recency rule loses the rare interesting ones.
func cleanRun(id int) traceRetention {
	return traceRetention{ID: fmt.Sprintf("t%03d", id), ExitDetail: exitDescription(nil)}
}

func TestPlanTraceBlanking(t *testing.T) {
	// THE MEASURED PATTERN. This operator drives ONE VECTOR PER SCAN: 140 vectors in an evening is
	// 140 scans with one trace each (two, counting the tool's second run label). The old policy kept
	// 3 SCANS, so it kept 3 vectors out of 140, and every dalfox scan before 21:14 had 0 traces while
	// every one after had 2.
	oneVectorPerScan := func() []traceRetention {
		var rows []traceRetention
		for i := 0; i < 140; i++ {
			rows = append(rows, cleanRun(i))
		}
		return rows
	}

	// Six vectors timed out during that campaign, and their output is the only place the reason could
	// have been read. Here they sit well below the recency window.
	withTimeouts := func() []traceRetention {
		rows := oneVectorPerScan()
		for _, i := range []int{80, 95, 96, 110, 130, 139} {
			rows[i].TimedOut = true
		}
		return rows
	}

	cases := []struct {
		name string
		rows []traceRetention
		// wantKept are ids that must NOT be blanked; wantBlanked must be.
		wantKept    []string
		wantBlanked []string
		wantCount   int
	}{{
		name: "one vector per scan keeps a real diagnostic window, not three vectors",
		rows: oneVectorPerScan(),
		// Newest 50 survive; the 90 older ones lose their output.
		wantKept:    []string{"t000", "t049"},
		wantBlanked: []string{"t050", "t139"},
		wantCount:   90,
	}, {
		// A timeout is worth far more than a clean run, so if something has to go it should be the
		// boring ones. All six timeouts survive even though five of them are older than the 50th run.
		name:        "timeouts survive a flood of ordinary successes",
		rows:        withTimeouts(),
		wantKept:    []string{"t080", "t095", "t096", "t110", "t130", "t139"},
		wantBlanked: []string{"t050", "t081", "t138"},
		wantCount:   84,
	}, {
		// Nothing to do on a small history, which is the common case and must issue no writes.
		name:      "a short history is left alone",
		rows:      []traceRetention{cleanRun(0), cleanRun(1), cleanRun(2)},
		wantKept:  []string{"t000", "t001", "t002"},
		wantCount: 0,
	}, {
		// Idempotent: a row whose output is already gone is never handed back, so a second prune pass
		// over the same history writes nothing.
		name: "already pruned rows are not returned again",
		rows: func() []traceRetention {
			rows := oneVectorPerScan()
			for i := 50; i < 140; i++ {
				rows[i].Pruned = true
			}
			return rows
		}(),
		wantCount: 0,
	}, {
		// The interesting tier is bounded too. A tool that fails on everything cannot pin the whole
		// table open.
		name: "an all-failing history is still bounded",
		rows: func() []traceRetention {
			var rows []traceRetention
			for i := 0; i < 200; i++ {
				row := cleanRun(i)
				row.ExitDetail = "exit status 2"
				rows = append(rows, row)
			}
			return rows
		}(),
		wantKept:    []string{"t000", "t049"},
		wantBlanked: []string{"t050", "t199"},
		wantCount:   150,
	}}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			blanked := map[string]bool{}
			for _, id := range planTraceBlanking(c.rows) {
				blanked[id] = true
			}
			if len(blanked) != c.wantCount {
				t.Errorf("blanked %d rows, want %d", len(blanked), c.wantCount)
			}
			for _, id := range c.wantKept {
				if blanked[id] {
					t.Errorf("%s must keep its output", id)
				}
			}
			for _, id := range c.wantBlanked {
				if !blanked[id] {
					t.Errorf("%s must have its output dropped", id)
				}
			}
		})
	}
}

// traceExitWasClean reads a column written by exitDescription, and the two live in different files.
// This pins them together: a change to either one silently reclassifies every stored trace, in one
// direction or the other, and both directions are bad.
func TestTraceExitClassificationMatchesExitDescription(t *testing.T) {
	if !traceExitWasClean(exitDescription(nil)) {
		t.Errorf("a successful exit must not be classified as interesting: %q", exitDescription(nil))
	}
	if traceExitWasClean(exitDescription(fmt.Errorf("exit status 2"))) {
		t.Error("a failed exit must be classified as interesting")
	}
	if traceExitWasClean("") {
		t.Error("an unrecorded exit is not evidence of success")
	}
}

// The note is what a reader sees in place of the output, so it has to say that the run HAPPENED.
// An empty stdout column reads as a tool that printed nothing, which is the confusion this replaces.
func TestPrunedNoteExplainsAbsence(t *testing.T) {
	for _, want := range []string{"aged out", "happened"} {
		if !strings.Contains(vectorTracePrunedNote, want) {
			t.Errorf("the pruned note must mention %q: %s", want, vectorTracePrunedNote)
		}
	}
}
