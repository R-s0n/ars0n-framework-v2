package utils

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

// THE PASS RUN OVER THE REAL STORED CORPUS, read only, no network.
//
// A false-positive rule that is right in a table-driven test and wrong over thousands of real
// response bodies is the failure that matters here, and the only way to see it is to run the rule
// over the real bodies. This test does that against a dump of a target's manual_crawl_captures and
// attack_vectors, taken with psql, so nothing here touches a live database or a live host.
//
// SKIPPED unless both dumps are pointed at, because the corpus is a target's crawl and does not
// belong in the repository:
//
//	REFLECTION_CORPUS_CAPTURES=<dir>/captures.b64 \
//	REFLECTION_CORPUS_VECTORS=<dir>/vectors.b64 \
//	go test ./utils/ -run TestPassiveAgainstStoredCorpus -v
//
// Each file is one base64-encoded JSON object per line, which is how a COPY gets a response body
// containing newlines and backslashes out of Postgres without either side having to agree on an
// escaping scheme. The SQL that produces them is in the report beside this change.
func TestPassiveAgainstStoredCorpus(t *testing.T) {
	capturePath := os.Getenv("REFLECTION_CORPUS_CAPTURES")
	vectorPath := os.Getenv("REFLECTION_CORPUS_VECTORS")
	if capturePath == "" || vectorPath == "" {
		t.Skip("set REFLECTION_CORPUS_CAPTURES and REFLECTION_CORPUS_VECTORS to run the pass " +
			"over a real crawl")
	}

	var vectors []vectorRow
	readCorpus(t, vectorPath, func(raw []byte) {
		var row struct {
			ID             string   `json:"id"`
			Method         string   `json:"method"`
			Domain         string   `json:"domain"`
			Path           string   `json:"path"`
			InsertionPoint string   `json:"insertion_point"`
			Parameters     []string `json:"parameters"`
		}
		if json.Unmarshal(raw, &row) != nil {
			return
		}
		vectors = append(vectors, vectorRow{
			ID: row.ID, Method: row.Method, Domain: row.Domain, Path: row.Path,
			InsertionPoint: row.InsertionPoint, Parameters: row.Parameters,
		})
	})

	var captures []PassiveCapture
	matched := 0
	index := BuildPassiveIndex(vectors, nil)
	readCorpus(t, capturePath, func(raw []byte) {
		var row struct {
			ID              string         `json:"id"`
			Method          string         `json:"method"`
			URL             string         `json:"url"`
			Endpoint        string         `json:"endpoint"`
			Headers         map[string]any `json:"headers"`
			PostData        string         `json:"post_data"`
			ResponseBody    string         `json:"response_body"`
			ResponseHeaders map[string]any `json:"response_headers"`
			MimeType        string         `json:"mime_type"`
			StatusCode      int            `json:"status_code"`
		}
		if json.Unmarshal(raw, &row) != nil {
			return
		}
		c := PassiveCapture{
			ID: row.ID, Method: row.Method, URL: row.URL, Endpoint: row.Endpoint,
			RequestHeaders: passiveHeaderMap(row.Headers), RequestBody: row.PostData,
			ResponseBody: row.ResponseBody, StatusCode: row.StatusCode,
			ContentType: passiveResponseContentType(passiveHeaderMap(row.ResponseHeaders), row.MimeType),
		}
		// The same filter loadPassiveCaptures applies in SQL: only exchanges a vector points at are
		// read at all, which is what keeps the pass from walking 52MB of JavaScript.
		if len(index[PassiveMatchKey(c.Host(), c.Path())]) == 0 {
			return
		}
		matched++
		captures = append(captures, c)
	})

	found := PassiveScanCaptures(index, captures)

	byStatus := map[string]int{}
	byPoint := map[string]int{}
	vectorsHit := map[string]bool{}
	for _, res := range found {
		byStatus[res.Outcome.Status]++
		byPoint[res.Outcome.InsertionPoint]++
		vectorsHit[res.VectorID] = true
	}

	t.Logf("corpus: %d vectors, %d captures with a body, %d of them paired with a vector",
		len(vectors), len(captures)+0, matched)
	t.Logf("passive reflections: %d inputs across %d vectors", len(found), len(vectorsHit))
	t.Logf("by status: %s", sortedCounts(byStatus))
	t.Logf("by insertion point: %s", sortedCounts(byPoint))

	keys := make([]string, 0, len(found))
	for key := range found {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if i >= 25 {
			t.Logf("... and %d more", len(keys)-25)
			break
		}
		res := found[key]
		t.Logf("  %s %-24s %-18s %s | %s", res.Outcome.Status, res.Parameter,
			res.Outcome.InsertionPoint, trimForLog(res.CaptureURL, 70),
			trimForLog(strings.ReplaceAll(res.Outcome.Evidence, "\n", " "), 90))
	}

	// THE ASSERTION THAT MATTERS on a real corpus is not "it found something", it is that the rule
	// did not degenerate into matching everything. A pass that reported a reflection on most of the
	// inputs it looked at would be reporting coincidence.
	considered := 0
	for _, c := range captures {
		for _, ref := range index[PassiveMatchKey(c.Host(), c.Path())] {
			considered += len(passiveVectorParameters(ref))
		}
	}
	t.Logf("input/capture pairs considered: %d, reported: %d", considered, len(found))
	if considered > 0 && len(found)*2 > considered {
		t.Fatalf("passive reported %d reflections from %d considered pairs: the rule is matching "+
			"coincidence, not echoes", len(found), considered)
	}
}

func readCorpus(t *testing.T, path string, each func([]byte)) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			t.Fatalf("decoding a line of %s: %v", path, err)
		}
		each(raw)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
}

func sortedCounts(counts map[string]int) string {
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}

func trimForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
