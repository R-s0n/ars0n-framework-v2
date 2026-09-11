package utils

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// THE BUG BOUNTY KNOWLEDGE BASE, SERVED OUT OF THE BINARY.
//
// WHY THIS FILE EXISTS. The methodology in methodology.go is the framework's own opinion about the
// order of the workflow. This is the other half: 27 vendored markdown documents, 1.4 MB of hunting
// methodology, a checklist, and two corpora of real disclosed reports (accepted and rejected). The
// operator was running that corpus from a separate MCP server, so an agent driving this framework
// could reach the tools or the reading material but never both in the same session. Absorbed here,
// one API serves both the client's reader modal and the MCP browse/read/search tools, and nothing
// can drift between them.
//
// SIZE DRIVES EVERY DECISION BELOW. reports/accepted/hackerone-top-reports.md alone is 607 KB and
// 4702 lines, and it is not prose: it is one report per line, each with a title, a hackerone.com
// link, the program and the bounty. So:
//
//   - Reading a file is capped at 20000 characters unless the caller passes full=true. An unguarded
//     MCP read of that one file would otherwise blow roughly 150k tokens of an agent's context on a
//     numbered index it cannot use.
//   - Search is LINE LEVEL, not file level. A query for "IDOR" against the corpus should come back
//     as individual report lines carrying their links and their bounty amounts, which is tiny and is
//     the actually useful answer.
//   - Hits from methodology/ and checklists/ outrank hits from the report corpora, always, whatever
//     the text score says. Someone searching "SSRF" wants the method before the examples.
//
// THE FILES ARE EMBEDDED, NOT MOUNTED. The api container gets no volume for them, so the corpus has
// to travel inside the binary. The //go:embed directive itself cannot live in this file: embed
// patterns may not contain "..", so a package in server/utils can only embed things underneath
// server/utils, and the knowledge base is vendored at server/knowledge-base. main.go therefore holds
// the directive and hands the rooted FS to SetKnowledgeBaseFS at boot. Moving the vendored directory
// to satisfy the compiler was the alternative and was rejected: anyone re-vendoring the corpus will
// put it back where it is documented to live, and would then have silently un-embedded it.

const (
	// knowledgeCharCap is the default ceiling on a single read. Whole lines only, see readKnowledge.
	knowledgeCharCap = 20000
	// Search result limits. The hard cap exists because the caller supplying it is usually an agent
	// that will pay for every line in context.
	knowledgeSearchDefaultMax = 40
	knowledgeSearchHardMax    = 200
	// knowledgeSearchScanCap bounds how many raw hits are collected before ranking. A one-letter
	// query against the 4702 line index would otherwise build a slice of the whole corpus.
	knowledgeSearchScanCap = 5000
	// knowledgeLineCap keeps one absurdly long markdown line from dominating a result set. Longer
	// lines come back as a window around the match.
	knowledgeLineCap = 400
)

// KnowledgeFile is one document in the corpus, as the tree lists it.
type KnowledgeFile struct {
	// Path is relative to the knowledge base root, always forward slashed, for example
	// "reports/accepted/idor-reports.md". It is the only identifier the read and search routes accept.
	Path string `json:"path"`
	// Title is the document's first H1, falling back to a prettified file name.
	Title string `json:"title"`
	// Category is the containing directory, for example "reports/accepted". CategoryLabel is the same
	// thing spelled for a human, because the client reader groups the tree by it.
	Category      string `json:"category"`
	CategoryLabel string `json:"category_label"`
	SizeBytes     int    `json:"size_bytes"`
	Lines         int    `json:"lines"`
	// Corpus marks the report collections: documents meant to be SEARCHED rather than read end to
	// end. The client modal may still load one whole, because a human scrolling a document is not an
	// agent's context budget, but an MCP caller should be reaching for search instead.
	Corpus bool `json:"corpus"`
}

// KnowledgeHit is one matching line. Heading is the nearest preceding markdown heading, which is
// what turns a bare line from a 4702 line index into something a caller can place.
type KnowledgeHit struct {
	Path       string `json:"path"`
	LineNumber int    `json:"line_number"`
	Line       string `json:"line"`
	Heading    string `json:"heading"`
	Category   string `json:"category"`
	Title      string `json:"title"`
	// Score is exposed so a caller can see WHY one hit outranked another rather than guessing.
	Score int `json:"score"`
}

// Category ordering. This is the ranking the contract cares about: instruction before examples.
var knowledgeCategoryRank = map[string]int{
	"methodology":      0,
	"checklists":       1,
	"reports/accepted": 2,
	"reports/rejected": 3,
}

var knowledgeCategoryLabels = map[string]string{
	"methodology":      "Methodology",
	"checklists":       "Checklists",
	"reports/accepted": "Accepted Reports",
	"reports/rejected": "Rejected Reports",
}

var (
	knowledgeMu     sync.RWMutex
	knowledgeFS     fs.FS
	knowledgeIndex  []KnowledgeFile
	knowledgeByPath map[string]KnowledgeFile
)

// SetKnowledgeBaseFS installs the embedded corpus and builds the index once, at boot. fsys must
// already be rooted AT the knowledge base, so its top level is methodology/, checklists/ and
// reports/. Returns the number of markdown files indexed so the caller can log it: a zero there
// means the embed pattern stopped matching and every knowledge route is about to answer 503, which
// is worth one line in the log rather than a mystery in the UI.
//
// Also called by the tests with a synthetic FS, which is why the index is rebuilt on every call
// rather than guarded by a sync.Once.
func SetKnowledgeBaseFS(fsys fs.FS) int {
	files, byPath := buildKnowledgeIndex(fsys)

	knowledgeMu.Lock()
	defer knowledgeMu.Unlock()
	knowledgeFS = fsys
	knowledgeIndex = files
	knowledgeByPath = byPath
	return len(files)
}

// buildKnowledgeIndex walks the corpus once and keeps only the metadata. The content is NOT cached:
// it already lives in the embedded FS, and a second copy on the heap buys nothing when a full search
// over 1.4 MB costs milliseconds.
func buildKnowledgeIndex(fsys fs.FS) ([]KnowledgeFile, map[string]KnowledgeFile) {
	files := []KnowledgeFile{}
	byPath := map[string]KnowledgeFile{}
	if fsys == nil {
		return files, byPath
	}

	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		// Only markdown. The directory can legitimately hold other things (a LICENSE, a source note),
		// and listing them as readable documents would just produce broken entries in the reader.
		if !strings.EqualFold(path.Ext(p), ".md") {
			return nil
		}
		data, readErr := fs.ReadFile(fsys, p)
		if readErr != nil {
			return nil
		}
		category := path.Dir(p)
		if category == "." {
			category = "root"
		}
		entry := KnowledgeFile{
			Path:          p,
			Title:         knowledgeTitle(string(data), p),
			Category:      category,
			CategoryLabel: knowledgeCategoryLabel(category),
			SizeBytes:     len(data),
			Lines:         len(splitKnowledgeLines(string(data))),
			Corpus:        strings.HasPrefix(category, "reports"),
		}
		files = append(files, entry)
		byPath[p] = entry
		return nil
	})

	sort.Slice(files, func(i, j int) bool {
		ri, rj := knowledgeRank(files[i].Category), knowledgeRank(files[j].Category)
		if ri != rj {
			return ri < rj
		}
		return files[i].Path < files[j].Path
	})
	return files, byPath
}

func knowledgeRank(category string) int {
	if r, ok := knowledgeCategoryRank[category]; ok {
		return r
	}
	// Anything vendored later that nobody has ranked sorts after the known categories rather than
	// jumping the queue ahead of the methodology.
	return len(knowledgeCategoryRank) + 1
}

func knowledgeCategoryLabel(category string) string {
	if label, ok := knowledgeCategoryLabels[category]; ok {
		return label
	}
	return category
}

// knowledgeTitle prefers the document's own H1. Without one the file name is still a better label
// than the path, so "idor-reports.md" becomes "Idor Reports".
func knowledgeTitle(content, p string) string {
	for _, line := range splitKnowledgeLines(content) {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "# ") {
			return strings.TrimSpace(strings.Trim(trimmed, "# "))
		}
		// Give up on the scan quickly: a title that is not in the opening lines is not a title.
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			break
		}
	}
	name := strings.TrimSuffix(path.Base(p), path.Ext(p))
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

// splitKnowledgeLines splits on newline and drops the empty element a trailing newline produces, so
// a 4702 line file reports 4702 lines rather than 4703.
func splitKnowledgeLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if content == "" {
		return []string{}
	}
	lines := strings.Split(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

func knowledgeSnapshot() ([]KnowledgeFile, map[string]KnowledgeFile, fs.FS) {
	knowledgeMu.RLock()
	defer knowledgeMu.RUnlock()
	return knowledgeIndex, knowledgeByPath, knowledgeFS
}

// knowledgeUnavailable answers when the embed never arrived. Deliberately NOT an empty success:
// "no files" and "the corpus failed to load" look identical to a caller otherwise, and this estate
// has a long history of an empty result reading as a clean one.
func knowledgeUnavailable(w http.ResponseWriter) {
	writeJSONError(w, http.StatusServiceUnavailable, "knowledge_base_unavailable",
		"The knowledge base is not loaded in this process. The api binary embeds server/knowledge-base at build time.")
}

// resolveKnowledgePath is the traversal guard. The embedded FS is read only and rooted, so escaping
// it is not the threat here; serving something that was never meant to be a document is. Membership
// in the index is the real check and everything above it is belt and braces, kept because the guard
// has to stay obvious to the next reader.
func resolveKnowledgePath(raw string) (KnowledgeFile, string, bool) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return KnowledgeFile{}, "missing_path", false
	}
	// Backslashes are rejected rather than normalised: an embedded FS path never contains one, so a
	// caller sending "reports\accepted\x.md" is either on the wrong platform or probing.
	if strings.ContainsAny(p, "\\\x00") {
		return KnowledgeFile{}, "invalid_path", false
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "./") {
		return KnowledgeFile{}, "invalid_path", false
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return KnowledgeFile{}, "invalid_path", false
		}
	}
	_, byPath, _ := knowledgeSnapshot()
	entry, ok := byPath[p]
	if !ok {
		return KnowledgeFile{}, "unknown_file", false
	}
	return entry, "", true
}

// GetKnowledgeBaseTree answers GET /knowledge-base. Metadata only: no content ever leaves here, so
// the client reader can draw its whole tree in one small response and then lazy load what is opened.
func GetKnowledgeBaseTree(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	files, _, fsys := knowledgeSnapshot()
	if fsys == nil {
		knowledgeUnavailable(w)
		return
	}

	wanted := strings.TrimSpace(r.URL.Query().Get("category"))
	out := []KnowledgeFile{}
	totalBytes := 0
	for _, f := range files {
		if wanted != "" && !knowledgeCategoryMatches(f.Category, wanted) {
			continue
		}
		out = append(out, f)
		totalBytes += f.SizeBytes
	}
	if wanted != "" && len(out) == 0 {
		writeJSONError(w, http.StatusNotFound, "unknown_category",
			"No knowledge base category "+wanted+". Call /knowledge-base with no filter for the list.")
		return
	}

	// The per category summary is what the reader modal draws its left hand groups from, in the order
	// the methodology would have someone read them.
	type categorySummary struct {
		Category string `json:"category"`
		Label    string `json:"label"`
		Files    int    `json:"files"`
		Bytes    int    `json:"size_bytes"`
	}
	summaries := []categorySummary{}
	seen := map[string]int{}
	for _, f := range out {
		if idx, ok := seen[f.Category]; ok {
			summaries[idx].Files++
			summaries[idx].Bytes += f.SizeBytes
			continue
		}
		seen[f.Category] = len(summaries)
		summaries = append(summaries, categorySummary{
			Category: f.Category, Label: f.CategoryLabel, Files: 1, Bytes: f.SizeBytes,
		})
	}

	json.NewEncoder(w).Encode(map[string]any{
		"files":       out,
		"categories":  summaries,
		"total_files": len(out),
		"total_bytes": totalBytes,
		"note": "Files marked corpus are report collections meant to be searched, not read whole. " +
			"Use /knowledge-base/search?q= for those and read a file only once a hit points at it.",
	})
}

// knowledgeCategoryExists reports whether any indexed file answers to this category name. Derived
// from the index rather than from a literal list so it cannot drift when a directory is added.
func knowledgeCategoryExists(files []KnowledgeFile, wanted string) bool {
	for _, f := range files {
		if knowledgeCategoryMatches(f.Category, wanted) {
			return true
		}
	}
	return false
}

// knowledgeCategoryMatches accepts either the full category ("reports/accepted") or its top level
// ("reports"), so a caller can ask for every report without knowing the split.
func knowledgeCategoryMatches(category, wanted string) bool {
	category = strings.ToLower(category)
	wanted = strings.ToLower(strings.Trim(wanted, "/"))
	return category == wanted || strings.HasPrefix(category, wanted+"/")
}

// GetKnowledgeFile answers GET /knowledge-base/file?path=<p>.
//
// The cap is the whole point of this handler. Without full=true the response stops at 20000
// characters on a line boundary and says so, because the largest document here is 607 KB and the
// caller is frequently an agent that cannot afford it. offset and limit are in LINES, so a caller
// that does want the whole thing can page it without ever holding it all at once, and search hits
// (which carry a line number) can be opened at the right place.
func GetKnowledgeFile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	_, _, fsys := knowledgeSnapshot()
	if fsys == nil {
		knowledgeUnavailable(w)
		return
	}

	q := r.URL.Query()
	entry, failure, ok := resolveKnowledgePath(q.Get("path"))
	if !ok {
		switch failure {
		case "missing_path":
			writeJSONError(w, http.StatusBadRequest, "missing_path",
				"Pass path=<file> as listed by /knowledge-base.")
		case "unknown_file":
			writeJSONError(w, http.StatusNotFound, "unknown_file",
				"No knowledge base file at that path. Call /knowledge-base for the list.")
		default:
			writeJSONError(w, http.StatusBadRequest, "invalid_path",
				"Path must be a plain relative path as listed by /knowledge-base, with no .. segments.")
		}
		return
	}

	data, err := fs.ReadFile(fsys, entry.Path)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "read_failed",
			"The knowledge base file is indexed but could not be read: "+err.Error())
		return
	}

	full := knowledgeBoolParam(q.Get("full"))
	offset := knowledgeIntParam(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}
	limit := knowledgeIntParam(q.Get("limit"), 0)
	if limit < 0 {
		limit = 0
	}

	lines := splitKnowledgeLines(string(data))
	totalLines := len(lines)

	// OFFSET IS A LINE NUMBER, 1 BASED, and it has to be: the search route tells callers to open a hit
	// with offset=<line_number>, and line_number is the 1 based number this same handler reports. It
	// was a slice index, so offset=151 served line 152 and every search hit opened one line late. On a
	// 4702 line index of near identical entries a reader cannot see that it is on the wrong line, which
	// makes it the same class of bug as the anchoring it was there to provide. 0 and absent both mean
	// the top of the file, so an unset parameter still reads from line 1.
	start := offset - 1
	if start < 0 {
		start = 0
	}
	if start > totalLines {
		start = totalLines
	}
	end := totalLines
	if limit > 0 && start+limit < end {
		end = start + limit
	}
	// The cap is applied to the LINE SLICE, not to the joined string, and returned_lines is then the
	// length of that slice. Deriving it by re-splitting the content instead looks equivalent and is
	// not: a selection ending on a blank line loses that line to the split, so next_offset lands back
	// where it started and an agent paging a document loops on one blank line forever.
	selected := lines[start:end]
	truncated := false
	if !full {
		kept, used := 0, 0
		for _, line := range selected {
			cost := len(line)
			if kept > 0 {
				cost++ // the newline the join will add
			}
			if used+cost > knowledgeCharCap {
				break
			}
			used += cost
			kept++
		}
		switch {
		case kept == 0 && len(selected) > 0:
			// One line longer than the entire budget. Cut it rather than return nothing, and still
			// count it as consumed so a paging caller advances instead of stalling on it.
			selected = []string{knowledgeCutRunes(selected[0], knowledgeCharCap)}
			truncated = true
		case kept < len(selected):
			selected = selected[:kept]
			truncated = true
		}
	}
	content := strings.Join(selected, "\n")
	returnedLines := len(selected)
	// Callers page by feeding next_offset straight back in. Absent when there is nothing left, so an
	// agent has an unambiguous stop condition rather than a loop that re-reads the tail forever.
	resp := map[string]any{
		"path":           entry.Path,
		"title":          entry.Title,
		"category":       entry.Category,
		"category_label": entry.CategoryLabel,
		"corpus":         entry.Corpus,
		"size_bytes":     entry.SizeBytes,
		"total_lines":    totalLines,
		// Echoed in the same 1 based numbering the caller passes and search reports, so a response can
		// be checked against the line it was meant to open without a mental conversion.
		"offset":         start + 1,
		"returned_lines": returnedLines,
		"returned_bytes": len(content),
		"truncated":      truncated,
		"content":        content,
	}
	if next := start + returnedLines; next < totalLines {
		resp["next_offset"] = next + 1
	}
	if truncated {
		note := "Stopped at " + strconv.Itoa(knowledgeCharCap) + " characters on a line boundary. " +
			"Page on with offset and limit, both in lines, or pass full=true for the whole file."
		if entry.Corpus {
			note += " This file is a report corpus: /knowledge-base/search?q= is almost always the " +
				"better call than reading it."
		}
		resp["note"] = note
	}
	json.NewEncoder(w).Encode(resp)
}

// knowledgeCutRunes trims to at most n bytes without splitting a UTF-8 sequence. The corpus carries
// Russian report titles, so cutting mid rune is a live case and would put a replacement character in
// the JSON rather than the text.
func knowledgeCutRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8StartsRune(s[n]) {
		n--
	}
	return s[:n]
}

func knowledgeBoolParam(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y":
		return true
	}
	return false
}

func knowledgeIntParam(v string, def int) int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}

// SearchKnowledgeBase answers GET /knowledge-base/search?q=<q>&max=<n>.
//
// Line level, and case insensitive substring by default, because the corpus is one report per line:
// a query for "IDOR" should come back as report lines with their links and bounty amounts rather
// than as "idor-reports.md matched". Ranking is described on knowledgeScore.
func SearchKnowledgeBase(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	files, _, fsys := knowledgeSnapshot()
	if fsys == nil {
		knowledgeUnavailable(w)
		return
	}

	q := r.URL.Query()
	query := strings.TrimSpace(q.Get("q"))
	if query == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_query",
			"Pass q=<text>. Search is a case insensitive substring match over every line of the corpus.")
		return
	}

	max := knowledgeIntParam(q.Get("max"), knowledgeSearchDefaultMax)
	if max <= 0 {
		max = knowledgeSearchDefaultMax
	}
	if max > knowledgeSearchHardMax {
		max = knowledgeSearchHardMax
	}

	// category= narrows the search, and a category nobody indexed is refused rather than filtered.
	//
	// MEASURED before this guard existed: category=accepted returned 200 with zero hits, because the
	// indexed name is reports/accepted and the matcher only accepts that or its top level "reports".
	// A caller reads that zero as "the accepted corpus never mentions account takeover", which is the
	// same lie as a scan reporting clean having sent nothing. The tree route already 404s on an
	// unknown category; the two routes take the same parameter and must answer it the same way.
	category := strings.TrimSpace(q.Get("category"))
	if category != "" && !knowledgeCategoryExists(files, category) {
		writeJSONError(w, http.StatusNotFound, "unknown_category",
			"No knowledge base category "+category+". Call /knowledge-base for the list; the report "+
				"categories are spelled reports/accepted and reports/rejected, and reports matches both.")
		return
	}

	// path= scopes the search to one document. Same guard as the read route: an unknown path is a
	// 404 rather than a silent search of everything, which would look like a clean result.
	var only string
	if raw := strings.TrimSpace(q.Get("path")); raw != "" {
		entry, _, ok := resolveKnowledgePath(raw)
		if !ok {
			writeJSONError(w, http.StatusBadRequest, "invalid_path",
				"path must be a file listed by /knowledge-base.")
			return
		}
		only = entry.Path
	}

	// whole_word drops matches inside a longer word. Off by default because the corpus is full of
	// compound tokens ("SSRFmap", "IDORs") that a substring query should still find, on for the
	// caller who has just watched "rce" return every line containing the word "source".
	wholeWord := knowledgeBoolParam(q.Get("whole_word"))

	needle := strings.ToLower(query)
	hits := []KnowledgeHit{}
	total := 0
	capped := false

	for _, f := range files {
		if only != "" && f.Path != only {
			continue
		}
		if category != "" && !knowledgeCategoryMatches(f.Category, category) {
			continue
		}
		data, err := fs.ReadFile(fsys, f.Path)
		if err != nil {
			continue
		}
		heading := ""
		for i, line := range splitKnowledgeLines(string(data)) {
			if isKnowledgeHeading(line) {
				heading = knowledgeHeadingText(line)
			}
			idx := knowledgeMatchIndex(strings.ToLower(line), needle, wholeWord)
			if idx < 0 {
				continue
			}
			total++
			if len(hits) >= knowledgeSearchScanCap {
				capped = true
				continue
			}
			hits = append(hits, KnowledgeHit{
				Path:       f.Path,
				LineNumber: i + 1,
				Line:       knowledgeWindow(line, idx, len(needle)),
				Heading:    heading,
				Category:   f.Category,
				Title:      f.Title,
				Score:      knowledgeScore(line, heading, needle, idx),
			})
		}
	}

	sort.SliceStable(hits, func(i, j int) bool {
		ri, rj := knowledgeRank(hits[i].Category), knowledgeRank(hits[j].Category)
		if ri != rj {
			return ri < rj
		}
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		if hits[i].Path != hits[j].Path {
			return hits[i].Path < hits[j].Path
		}
		return hits[i].LineNumber < hits[j].LineNumber
	})

	selected := knowledgeSelect(hits, max)

	json.NewEncoder(w).Encode(map[string]any{
		"query":         query,
		"hits":          selected,
		"returned":      len(selected),
		"total_matches": total,
		"max":           max,
		"scan_capped":   capped,
		"whole_word":    wholeWord,
		"note": "Ordered methodology and checklists first, then accepted reports, then rejected. " +
			"Open a hit with /knowledge-base/file?path=<path>&offset=<line_number>. Short queries " +
			"match inside longer words, so pass whole_word=true if a term like rce is pulling in source " +
			"and resource.",
	})
}

// knowledgeSelect takes the top max hits but will not let one document own the whole page. The 607
// KB index would otherwise fill every slot for any common term and hide the other eleven report
// files entirely. Quota first, then the leftovers refill whatever the quota left unused, so a query
// that genuinely only appears in one file still comes back full.
func knowledgeSelect(hits []KnowledgeHit, max int) []KnowledgeHit {
	if len(hits) <= max {
		return hits
	}
	quota := max / 3
	if quota < 3 {
		quota = 3
	}
	selected := make([]KnowledgeHit, 0, max)
	perFile := map[string]int{}
	deferred := []KnowledgeHit{}
	for _, h := range hits {
		if len(selected) >= max {
			break
		}
		if perFile[h.Path] >= quota {
			deferred = append(deferred, h)
			continue
		}
		perFile[h.Path]++
		selected = append(selected, h)
	}
	for _, h := range deferred {
		if len(selected) >= max {
			break
		}
		selected = append(selected, h)
	}
	return selected
}

// knowledgeScore ranks within a category. Category order itself is NOT negotiable and is applied
// before this, so a strong corpus hit can never outrank the methodology.
//
// THE WORD BOUNDARY BONUS IS THE BIG ONE, and it is weighted above the heading bonus on purpose.
// Substring matching means a query of "rce" hits "source", "force" and "resource" on most pages, and
// with heading weighted higher the top results for "rce" came back as "Resource Exhaustion" and
// "Batch query for brute-force" while the actual RCE guidance sat below them. Matches inside a
// longer word are demoted rather than dropped, so a deliberate substring query still works, and
// whole_word=true is there for a caller that wants them gone entirely.
func knowledgeScore(line, heading, needle string, idx int) int {
	score := 0
	lower := strings.ToLower(line)
	if knowledgeWordBoundary(lower, idx, len(needle)) {
		score += 60
	}
	if isKnowledgeHeading(line) {
		score += 25
	}
	if heading != "" && strings.Contains(strings.ToLower(heading), needle) {
		score += 10
	}
	return score
}

// knowledgeMatchIndex returns the offset of the match to report, or -1. Under wholeWord it keeps
// looking past a match that sits inside a longer word, so "rce" still finds "RCE:" on a line whose
// first occurrence was in "source".
func knowledgeMatchIndex(lower, needle string, wholeWord bool) int {
	idx := strings.Index(lower, needle)
	if !wholeWord {
		return idx
	}
	for idx >= 0 {
		if knowledgeWordBoundary(lower, idx, len(needle)) {
			return idx
		}
		next := strings.Index(lower[idx+1:], needle)
		if next < 0 {
			return -1
		}
		idx += 1 + next
	}
	return -1
}

func knowledgeWordBoundary(lower string, idx, n int) bool {
	before := true
	if idx > 0 {
		before = !isKnowledgeWordRune(rune(lower[idx-1]))
	}
	after := true
	if end := idx + n; end < len(lower) {
		after = !isKnowledgeWordRune(rune(lower[end]))
	}
	return before && after
}

func isKnowledgeWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_'
}

func isKnowledgeHeading(line string) bool {
	trimmed := strings.TrimLeft(line, " \t")
	if !strings.HasPrefix(trimmed, "#") {
		return false
	}
	rest := strings.TrimLeft(trimmed, "#")
	return rest == "" || strings.HasPrefix(rest, " ")
}

func knowledgeHeadingText(line string) string {
	trimmed := strings.TrimSpace(line)
	trimmed = strings.TrimLeft(trimmed, "#")
	return strings.TrimSpace(strings.TrimRight(trimmed, "# "))
}

// knowledgeWindow keeps a long line from dominating a result set, returning the match in context
// with ellipses rather than the whole paragraph.
func knowledgeWindow(line string, idx, n int) string {
	if len(line) <= knowledgeLineCap {
		return line
	}
	start := idx - knowledgeLineCap/3
	if start < 0 {
		start = 0
	}
	end := start + knowledgeLineCap
	if end > len(line) {
		end = len(line)
		start = end - knowledgeLineCap
		if start < 0 {
			start = 0
		}
	}
	// Do not cut a multi byte rune in half, or the JSON carries a replacement character where the
	// match was. The Russian titles in the corpus make this a live case, not a hypothetical.
	for start > 0 && start < len(line) && !utf8StartsRune(line[start]) {
		start--
	}
	for end < len(line) && !utf8StartsRune(line[end]) {
		end++
	}
	out := line[start:end]
	if start > 0 {
		out = "... " + out
	}
	if end < len(line) {
		out += " ..."
	}
	return out
}

// utf8StartsRune reports whether b is the first byte of a UTF-8 sequence. Continuation bytes are
// 10xxxxxx.
func utf8StartsRune(b byte) bool { return b&0xC0 != 0x80 }
