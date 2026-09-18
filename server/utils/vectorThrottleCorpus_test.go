package utils

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// Running the rule over every stdout this framework has ever stored.
//
// A rule that fires on a clean run is worse than no rule, and the only way to know is to run it
// over real output rather than over output written to make it pass. The corpus is dumped straight
// out of the live database:
//
//	docker exec ars0n-framework-v2-db-1 psql -U postgres -d ars0n -t -A -c \
//	  "SELECT json_agg(row_to_json(x))::text FROM (SELECT id, split_part(command,' ',3) AS
//	   container, stdout FROM vector_scan_traces) x;" > trace-corpus.json
//	VECTOR_TRACE_CORPUS=/path/to/trace-corpus.json go test ./utils/ -run Corpus -v
//
// Skipped when the file is absent, so it does not turn a checkout into a database dependency, and
// the numbers it printed on the day are recorded below.
//
// MEASURED 2026-09-18 over 574 traces across 21 tools:
//
//	naive strings.Contains(stdout, "429")   4 traces:  1 real, 3 false (smugglex ns timestamps)
//	this rule                               1 trace:   1 real, 0 false
//
// The one is Forbidden trace aac20032, "| 429 | 479 |" out of 3412 requests, which was filed at the
// time as a completed scan with no findings. It is the only run in the whole corpus the target
// demonstrably refused, and it was invisible.
func TestThrottleRuleOverTheStoredTraceCorpus(t *testing.T) {
	path := os.Getenv("VECTOR_TRACE_CORPUS")
	if path == "" {
		t.Skip("set VECTOR_TRACE_CORPUS to a trace dump to re-validate against real output")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading corpus: %v", err)
	}
	var traces []struct {
		ID        string `json:"id"`
		Container string `json:"container"`
		Stdout    string `json:"stdout"`
	}
	if err := json.Unmarshal(raw, &traces); err != nil {
		t.Fatalf("parsing corpus: %v", err)
	}
	if len(traces) == 0 {
		t.Fatal("corpus is empty")
	}

	naive := map[string]int{}
	fired := map[string]int{}
	total := map[string]int{}
	for _, tr := range traces {
		total[tr.Container]++
		if strings.Contains(tr.Stdout, "429") {
			naive[tr.Container]++
		}
		if why := throttledByTarget(tr.Stdout); why != "" {
			fired[tr.Container]++
			t.Logf("FIRED %s %s: %s", tr.Container, tr.ID, why)
		}
	}

	keys := make([]string, 0, len(total))
	for k := range total {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	naiveAll, firedAll := 0, 0
	for _, k := range keys {
		naiveAll += naive[k]
		firedAll += fired[k]
		t.Logf("%-36s traces=%-4d naive429=%-3d rule=%d", k, total[k], naive[k], fired[k])
	}
	t.Logf("TOTAL traces=%d naive429=%d rule=%d", len(traces), naiveAll, firedAll)
}
