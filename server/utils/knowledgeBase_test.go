package utils

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// The knowledge base is embedded by main.go and handed to the handlers at boot, so these tests
// install a synthetic corpus instead. It carries the two shapes that actually matter: small
// instructional prose under methodology/, and a long numbered index under reports/accepted/ standing
// in for the 607 KB hackerone-top-reports.md that motivated the cap.
func installTestKnowledgeBase(t *testing.T) {
	t.Helper()

	var corpus strings.Builder
	corpus.WriteString("# Top HackerOne Disclosed Reports\n\n## Top 100 Reports by Bounty Amount\n")
	for i := 1; i <= 400; i++ {
		corpus.WriteString("- [IDOR in the reporting API](https://hackerone.com/reports/1000" +
			strconv.Itoa(i) + ") to SomeProgram - $2500, 120 upvotes\n")
	}

	fsys := fstest.MapFS{
		"methodology/web-app-methodology.md": &fstest.MapFile{Data: []byte(
			"# Web Application Bug Bounty Methodology\n\n## Phase 4: Access Control\n" +
				"Test every object id with another account's session. IDOR is the highest yield class here.\n")},
		"checklists/web-app-checklist.md": &fstest.MapFile{Data: []byte(
			"# Web App Checklist\n\n## Authorization\n- [ ] Swap ids between accounts to find IDOR\n")},
		"reports/accepted/hackerone-top-reports.md": &fstest.MapFile{Data: []byte(corpus.String())},
		"reports/rejected/false-positives.md": &fstest.MapFile{Data: []byte(
			"# False Positives\n\n## Self IDOR\nReading your own object is not an IDOR.\n")},
		// Not markdown, so it must never appear in the tree or be readable through the file route.
		"reports/accepted/SOURCES.txt": &fstest.MapFile{Data: []byte("not a document")},
	}

	previousIndex, previousByPath, previousFS := knowledgeSnapshot()
	t.Cleanup(func() {
		knowledgeMu.Lock()
		defer knowledgeMu.Unlock()
		knowledgeFS, knowledgeIndex, knowledgeByPath = previousFS, previousIndex, previousByPath
	})
	if n := SetKnowledgeBaseFS(fsys); n != 4 {
		t.Fatalf("indexed %d documents, want 4 markdown files with the .txt excluded", n)
	}
}

func getKnowledge(t *testing.T, handler http.HandlerFunc, target string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("GET %s returned non JSON (%d): %s", target, rec.Code, rec.Body.String())
	}
	return rec, body
}

// The embedded FS is read only and rooted, so escaping it is not the threat. Serving something that
// was never indexed is, and a traversal attempt must be refused loudly rather than answered with an
// empty 200 that reads like a file with no content.
func TestKnowledgeFileRejectsTraversalAndUnknownPaths(t *testing.T) {
	installTestKnowledgeBase(t)

	for _, tc := range []struct {
		path string
		code int
		err  string
	}{
		{"../../server/main.go", http.StatusBadRequest, "invalid_path"},
		{"methodology/../../etc/passwd", http.StatusBadRequest, "invalid_path"},
		{"/etc/passwd", http.StatusBadRequest, "invalid_path"},
		{"./methodology/web-app-methodology.md", http.StatusBadRequest, "invalid_path"},
		{"methodology\\web-app-methodology.md", http.StatusBadRequest, "invalid_path"},
		{"", http.StatusBadRequest, "missing_path"},
		{"methodology/", http.StatusBadRequest, "invalid_path"},
		// Real file, present in the synthetic FS, but not markdown so it was never indexed.
		{"reports/accepted/SOURCES.txt", http.StatusNotFound, "unknown_file"},
		{"reports/accepted/does-not-exist.md", http.StatusNotFound, "unknown_file"},
	} {
		rec, body := getKnowledge(t, GetKnowledgeFile, "/knowledge-base/file?path="+tc.path)
		if rec.Code != tc.code {
			t.Errorf("path %q: status %d, want %d", tc.path, rec.Code, tc.code)
		}
		if body["error"] != tc.err {
			t.Errorf("path %q: error %v, want %q", tc.path, body["error"], tc.err)
		}
		if _, ok := body["content"]; ok {
			t.Errorf("path %q: refusal still carried content", tc.path)
		}
	}
}

// The cap is the guard that keeps an unguarded MCP read of a 607 KB index from costing an agent its
// whole context window. It must hold by default, be escapable only on purpose, and never hand back
// half a line.
func TestKnowledgeFileCapsUntilFullIsPassed(t *testing.T) {
	installTestKnowledgeBase(t)
	const corpusPath = "reports/accepted/hackerone-top-reports.md"

	rec, body := getKnowledge(t, GetKnowledgeFile, "/knowledge-base/file?path="+corpusPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	content, _ := body["content"].(string)
	if len(content) == 0 {
		t.Fatal("capped read returned no content at all")
	}
	if len(content) > knowledgeCharCap {
		t.Errorf("returned %d characters, want at most %d", len(content), knowledgeCharCap)
	}
	if body["truncated"] != true {
		t.Error("truncated flag was not set on a capped read")
	}
	total, _ := body["size_bytes"].(float64)
	if int(total) <= knowledgeCharCap {
		t.Fatalf("test corpus is %d bytes, too small to exercise the cap", int(total))
	}
	// Whole lines only: every line the caller received must be a complete line of the document.
	for _, line := range strings.Split(content, "\n") {
		if line != "" && !strings.HasSuffix(line, "upvotes") && !strings.HasPrefix(line, "#") {
			t.Fatalf("capped read cut a line in half: %q", line)
		}
	}
	if _, ok := body["next_offset"]; !ok {
		t.Error("a capped read must report next_offset so a caller can page on")
	}

	recFull, bodyFull := getKnowledge(t, GetKnowledgeFile, "/knowledge-base/file?path="+corpusPath+"&full=true")
	if recFull.Code != http.StatusOK {
		t.Fatalf("full read status %d, want 200", recFull.Code)
	}
	fullContent, _ := bodyFull["content"].(string)
	if len(fullContent) <= knowledgeCharCap {
		t.Errorf("full=true returned %d characters, expected the whole %d byte file", len(fullContent), int(total))
	}
	if bodyFull["truncated"] != false {
		t.Error("full=true must not report truncated")
	}
	if _, ok := bodyFull["next_offset"]; ok {
		t.Error("full=true left a next_offset, which would loop a paging caller forever")
	}

	// Paging in lines is what lets a search hit be opened at the right place without the whole file.
	_, paged := getKnowledge(t, GetKnowledgeFile,
		"/knowledge-base/file?path="+corpusPath+"&offset=3&limit=2")
	pagedContent, _ := paged["content"].(string)
	if got := len(strings.Split(pagedContent, "\n")); got != 2 {
		t.Errorf("offset/limit returned %d lines, want 2", got)
	}
	if paged["offset"] != float64(3) {
		t.Errorf("offset echoed as %v, want 3", paged["offset"])
	}
}

// offset and line_number have to be the SAME numbering or the two routes do not compose.
//
// The search route's own note tells a caller to open a hit with offset=<line_number>, and
// line_number is 1 based. offset was a slice index, so every hit opened one line late. On a 4702
// line index of near identical entries that is invisible: the reader is on the wrong line and has no
// way to tell, which is the same failure as not anchoring at all.
func TestKnowledgeFileOffsetIsTheLineNumberSearchReports(t *testing.T) {
	installTestKnowledgeBase(t)
	const corpusPath = "reports/accepted/hackerone-top-reports.md"

	_, hitsBody := getKnowledge(t, SearchKnowledgeBase,
		"/knowledge-base/search?q=IDOR&max=40&path="+corpusPath)
	hits, _ := hitsBody["hits"].([]any)
	if len(hits) == 0 {
		t.Fatal("the corpus file returned no hits to open")
	}

	for _, h := range hits {
		hit, _ := h.(map[string]any)
		lineNo, _ := hit["line_number"].(float64)
		wanted, _ := hit["line"].(string)

		_, opened := getKnowledge(t, GetKnowledgeFile,
			"/knowledge-base/file?limit=1&path="+corpusPath+"&offset="+strconv.Itoa(int(lineNo)))
		got, _ := opened["content"].(string)
		if got != wanted {
			t.Fatalf("hit at line %d opened on %q, want %q", int(lineNo), got, wanted)
		}
		if opened["offset"] != lineNo {
			t.Errorf("offset echoed as %v for a read at line %d", opened["offset"], int(lineNo))
		}
	}

	// An absent offset is the top of the file, and so is 0. A reader that has not asked for a line
	// must not silently skip one.
	for _, target := range []string{
		"/knowledge-base/file?limit=1&path=" + corpusPath,
		"/knowledge-base/file?limit=1&offset=0&path=" + corpusPath,
		"/knowledge-base/file?limit=1&offset=1&path=" + corpusPath,
	} {
		_, body := getKnowledge(t, GetKnowledgeFile, target)
		if got, _ := body["content"].(string); got != "# Top HackerOne Disclosed Reports" {
			t.Errorf("%s started on %q, want the first line of the file", target, got)
		}
		if body["offset"] != float64(1) {
			t.Errorf("%s echoed offset %v, want 1", target, body["offset"])
		}
	}

	// next_offset is fed straight back in, so it has to be a line number too: the line AFTER the last
	// one returned, never the last one again.
	_, page := getKnowledge(t, GetKnowledgeFile,
		"/knowledge-base/file?limit=5&offset=10&path="+corpusPath)
	if page["next_offset"] != float64(15) {
		t.Errorf("a 5 line read from line 10 offered next_offset %v, want 15", page["next_offset"])
	}
	_, nextPage := getKnowledge(t, GetKnowledgeFile,
		"/knowledge-base/file?limit=5&offset=15&path="+corpusPath)
	firstOfNext, _ := nextPage["content"].(string)
	lastOfPrev, _ := page["content"].(string)
	prevLines := strings.Split(lastOfPrev, "\n")
	if strings.Split(firstOfNext, "\n")[0] == prevLines[len(prevLines)-1] {
		t.Error("next_offset re-served the line the previous page ended on")
	}
}

// Paging has to terminate. Deriving returned_lines by re-splitting the content loses a trailing
// blank line, which sends next_offset back to where the caller already was: an agent walking a
// document one page at a time then reads the same blank line forever.
func TestKnowledgeFilePagingAlwaysAdvances(t *testing.T) {
	installTestKnowledgeBase(t)

	offset, pages := 0, 0
	for {
		_, body := getKnowledge(t, GetKnowledgeFile,
			"/knowledge-base/file?path=methodology/web-app-methodology.md&limit=1&offset="+strconv.Itoa(offset))
		next, ok := body["next_offset"].(float64)
		if !ok {
			break
		}
		if int(next) <= offset {
			t.Fatalf("next_offset %d did not advance past offset %d", int(next), offset)
		}
		offset = int(next)
		pages++
		if pages > 20 {
			t.Fatal("paging a four line document did not terminate")
		}
	}
	if pages == 0 {
		t.Fatal("paging stopped before it started")
	}
}

// A search for a class name must return the METHOD before the examples, and every hit has to carry
// the nearest preceding heading or a line out of a 4702 line index cannot be placed.
func TestKnowledgeSearchRanksInstructionFirst(t *testing.T) {
	installTestKnowledgeBase(t)

	rec, body := getKnowledge(t, SearchKnowledgeBase, "/knowledge-base/search?q=IDOR")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200: %s", rec.Code, rec.Body.String())
	}
	hitsRaw, _ := body["hits"].([]any)
	if len(hitsRaw) == 0 {
		t.Fatal("search for IDOR returned nothing")
	}
	first, _ := hitsRaw[0].(map[string]any)
	if cat, _ := first["category"].(string); cat != "methodology" {
		t.Errorf("top hit came from %q, want methodology ahead of the report corpora", cat)
	}
	if heading, _ := first["heading"].(string); heading == "" {
		t.Error("hit carried no heading, so the caller cannot place the line")
	}
	if ln, _ := first["line_number"].(float64); ln <= 0 {
		t.Error("hit carried no line number, so the caller cannot open the file at it")
	}
	// Default max is 40 and the synthetic corpus holds 400 matches, so the per file quota has to
	// leave room for the other documents rather than letting the index own every slot.
	if len(hitsRaw) > knowledgeSearchDefaultMax {
		t.Errorf("returned %d hits, want at most the default max of %d", len(hitsRaw), knowledgeSearchDefaultMax)
	}
	seen := map[string]bool{}
	for _, h := range hitsRaw {
		hit, _ := h.(map[string]any)
		p, _ := hit["path"].(string)
		seen[p] = true
	}
	if len(seen) < 3 {
		t.Errorf("every hit came from %d document(s); the per file quota did not spread the results", len(seen))
	}
	if total, _ := body["total_matches"].(float64); int(total) < 400 {
		t.Errorf("total_matches reported %d, want the true corpus count of at least 400", int(total))
	}
}

// max is caller supplied and the caller is usually an agent paying for every line.
func TestKnowledgeSearchHonoursHardMax(t *testing.T) {
	installTestKnowledgeBase(t)

	_, body := getKnowledge(t, SearchKnowledgeBase, "/knowledge-base/search?q=IDOR&max=5000")
	if got, _ := body["max"].(float64); int(got) != knowledgeSearchHardMax {
		t.Errorf("max clamped to %d, want the hard cap of %d", int(got), knowledgeSearchHardMax)
	}
	hits, _ := body["hits"].([]any)
	if len(hits) > knowledgeSearchHardMax {
		t.Errorf("returned %d hits, want at most %d", len(hits), knowledgeSearchHardMax)
	}

	rec, errBody := getKnowledge(t, SearchKnowledgeBase, "/knowledge-base/search?q=")
	if rec.Code != http.StatusBadRequest || errBody["error"] != "missing_query" {
		t.Errorf("empty query answered %d %v, want 400 missing_query", rec.Code, errBody["error"])
	}
}

// A category filter that narrows to nothing because the NAME is wrong must not look like a corpus
// that is silent on the subject. Measured against the real corpus: category=accepted answered 200
// with zero hits for a query the accepted reports discuss at length, because the indexed name is
// reports/accepted. Zero hits is the most expensive wrong answer this route can give.
func TestKnowledgeSearchRefusesUnknownCategory(t *testing.T) {
	installTestKnowledgeBase(t)

	// The two shapes the matcher accepts still work, and still find the hits they should.
	for _, wanted := range []string{"methodology", "reports", "reports/accepted", "reports/rejected"} {
		rec, body := getKnowledge(t, SearchKnowledgeBase,
			"/knowledge-base/search?q=IDOR&category="+url.QueryEscape(wanted))
		if rec.Code != http.StatusOK {
			t.Fatalf("category %q answered %d, want 200: %s", wanted, rec.Code, rec.Body.String())
		}
		hits, _ := body["hits"].([]any)
		if len(hits) == 0 {
			t.Errorf("category %q returned no hits, but the synthetic corpus has IDOR in every file", wanted)
		}
		for _, h := range hits {
			hit, _ := h.(map[string]any)
			if cat, _ := hit["category"].(string); !strings.HasPrefix(cat, wanted) {
				t.Errorf("category %q returned a hit from %q", wanted, cat)
			}
		}
	}

	// The short forms are the ones an operator or an MCP enum would reach for, and they index nothing.
	for _, wrong := range []string{"accepted", "rejected", "Reports/Accepted/", "nonsense"} {
		rec, body := getKnowledge(t, SearchKnowledgeBase,
			"/knowledge-base/search?q=IDOR&category="+url.QueryEscape(wrong))
		if wrong == "Reports/Accepted/" {
			// Case and a trailing slash are normalised by the matcher, so this one is a real category.
			if rec.Code != http.StatusOK {
				t.Errorf("category %q answered %d, want 200: the matcher lowercases and trims slashes",
					wrong, rec.Code)
			}
			continue
		}
		if rec.Code != http.StatusNotFound || body["error"] != "unknown_category" {
			t.Errorf("category %q answered %d %v with %v hits, want 404 unknown_category rather than "+
				"an empty result that reads as a silent corpus",
				wrong, rec.Code, body["error"], body["total_matches"])
		}
	}
}

// The tree is the client reader's whole left hand side and the MCP's only listing, so it must be
// metadata only and must group into the four categories the reader draws.
func TestKnowledgeTreeListsMarkdownOnly(t *testing.T) {
	installTestKnowledgeBase(t)

	rec, body := getKnowledge(t, GetKnowledgeBaseTree, "/knowledge-base")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rec.Code)
	}
	files, _ := body["files"].([]any)
	if len(files) != 4 {
		t.Fatalf("tree listed %d files, want 4", len(files))
	}
	firstFile, _ := files[0].(map[string]any)
	if cat, _ := firstFile["category"].(string); cat != "methodology" {
		t.Errorf("tree opened with %q, want methodology first", cat)
	}
	if _, ok := firstFile["content"]; ok {
		t.Error("the tree carried file content; it is metadata only")
	}
	if title, _ := firstFile["title"].(string); title != "Web Application Bug Bounty Methodology" {
		t.Errorf("title %q, want the document H1", title)
	}

	_, filtered := getKnowledge(t, GetKnowledgeBaseTree, "/knowledge-base?category=reports")
	filteredFiles, _ := filtered["files"].([]any)
	if len(filteredFiles) != 2 {
		t.Errorf("category=reports listed %d files, want both accepted and rejected", len(filteredFiles))
	}

	recUnknown, unknown := getKnowledge(t, GetKnowledgeBaseTree, "/knowledge-base?category=nope")
	if recUnknown.Code != http.StatusNotFound || unknown["error"] != "unknown_category" {
		t.Errorf("unknown category answered %d %v, want 404 unknown_category", recUnknown.Code, unknown["error"])
	}
}

// An unloaded corpus must never look like an empty one. This estate has a documented history of a
// scan that ran over nothing reading exactly like a clean scan.
func TestKnowledgeRoutesRefuseWhenNotLoaded(t *testing.T) {
	previousIndex, previousByPath, previousFS := knowledgeSnapshot()
	t.Cleanup(func() {
		knowledgeMu.Lock()
		defer knowledgeMu.Unlock()
		knowledgeFS, knowledgeIndex, knowledgeByPath = previousFS, previousIndex, previousByPath
	})
	knowledgeMu.Lock()
	knowledgeFS, knowledgeIndex, knowledgeByPath = nil, nil, map[string]KnowledgeFile{}
	knowledgeMu.Unlock()

	for name, handler := range map[string]http.HandlerFunc{
		"/knowledge-base":                                  GetKnowledgeBaseTree,
		"/knowledge-base/search?q=IDOR":                    SearchKnowledgeBase,
		"/knowledge-base/file?path=methodology/web-app.md": GetKnowledgeFile,
	} {
		rec, body := getKnowledge(t, handler, name)
		if rec.Code != http.StatusServiceUnavailable || body["error"] != "knowledge_base_unavailable" {
			t.Errorf("%s answered %d %v, want 503 knowledge_base_unavailable", name, rec.Code, body["error"])
		}
	}
}

// Guards the index build itself against a corpus that changes shape under it.
func TestKnowledgeIndexSkipsDirectoriesAndNonMarkdown(t *testing.T) {
	fsys := fstest.MapFS{
		"methodology/a.md":        &fstest.MapFile{Data: []byte("no heading here\nsecond line\n")},
		"methodology/nested/b.md": &fstest.MapFile{Data: []byte("# B\n")},
		"README":                  &fstest.MapFile{Data: []byte("skip me")},
	}
	files, byPath := buildKnowledgeIndex(fsys)
	if len(files) != 2 {
		t.Fatalf("indexed %d files, want 2", len(files))
	}
	if _, ok := byPath["README"]; ok {
		t.Error("a non markdown file was indexed")
	}
	var a KnowledgeFile
	for _, f := range files {
		if f.Path == "methodology/a.md" {
			a = f
		}
	}
	if a.Title != "A" {
		t.Errorf("title for a headingless file was %q, want the prettified file name", a.Title)
	}
	if a.Lines != 2 {
		t.Errorf("line count %d, want 2 with the trailing newline not counted as a line", a.Lines)
	}
	if _, err := fs.Stat(fsys, "methodology/a.md"); err != nil {
		t.Fatalf("synthetic corpus is broken: %v", err)
	}
}
