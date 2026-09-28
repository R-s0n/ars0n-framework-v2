package utils

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// =================================================================================================
// A REDIRECT HOP IS NOT A PAGE
// =================================================================================================
//
// DoFollowing recovers the hop that broke a redirect chain so a caller gets SOMETHING rather than
// nothing. That is the right trade for the transport and the wrong one for the record: what comes
// back is a 3xx with an empty body, and every page-derived field computed from it is a
// measurement of nothing. investigateEndpoint computed Title, Forms, InputFields, APIs, Secrets,
// Comments, Signals, Frameworks AND Misconfigs off that empty body, so the row read
// "investigated, found nothing" for a page nobody fetched, and it carried two MISCONFIGURATIONS
// derived from a redirect hop: a 302 has no page to frame and no charset to declare.
//
// THE CHAIN HERE IS THREE HOPS ON PURPOSE. A one-hop chain cannot tell a recovery that returns
// the breaking hop from one that returns the caller's first response, which is how the defect
// shipped.
func redirectChainTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/c", http.StatusFound)
	})
	// The hop that breaks it. A trailing percent is not a valid escape, so no URL parser accepts
	// this Location and net/http abandons the whole walk.
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://evil.example/tok%")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/page", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Frame-Options", "DENY")
		_, _ = w.Write([]byte("<html><head><title>Admin Console</title></head><body>" +
			"<form action=\"/login\" method=\"post\"><input name=\"u\"></form></body></html>"))
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

// TestABrokenRedirectChainIsNotAnEmptyPage is the row-level defect.
func TestABrokenRedirectChainIsNotAnEmptyPage(t *testing.T) {
	s := redirectChainTestServer(t)

	broke := investigateEndpoint("ep-broke", s.URL+"/a", s.URL+"/a", http.MethodGet, nil, nil, nil)
	page := investigateEndpoint("ep-page", s.URL+"/page", s.URL+"/page", http.MethodGet, nil, nil, nil)

	// The control half: a page that really was fetched must still be analysed in full, or the fix
	// would be "stop investigating", which is the same defect pointing the other way.
	if page.Title != "Admin Console" {
		t.Fatalf("the control page was not analysed (title %q), so this test is asserting nothing", page.Title)
	}
	if len(page.Forms) == 0 {
		t.Fatalf("the control page reported no forms, so this test is asserting nothing (status=%d size=%d)",
			page.StatusCode, page.ResponseSize)
	}
	if page.RedirectChainBroke {
		t.Errorf("a page that was fetched reports a broken chain: %s", page.RedirectChainNote)
	}

	t.Logf("CHAIN BROKE : status=%d size=%d title=%q forms=%d apis=%d secrets=%d misconfigs=%d broke=%v",
		broke.StatusCode, broke.ResponseSize, broke.Title, len(broke.Forms), len(broke.APIs),
		len(broke.Secrets), len(broke.Misconfigs), broke.RedirectChainBroke)

	if broke.StatusCode < 300 || broke.StatusCode > 399 {
		t.Fatalf("the broken-chain fixture returned status %d, so the recovery did not fire and this "+
			"test is asserting nothing", broke.StatusCode)
	}
	if !broke.RedirectChainBroke {
		t.Error("the row carries no field saying the chain broke, so nothing downstream can tell it " +
			"from a real empty page: status 302, size 0, no title, no forms is exactly what a page " +
			"that answers 302 with an empty body looks like")
	}
	if strings.TrimSpace(broke.RedirectChainNote) == "" {
		t.Error("the row says the chain broke and does not say how, so an operator cannot tell an " +
			"unparseable Location from a hop limit from a 3xx with no Location at all")
	}
	// THE WORST PART. Both of these are true OF A REDIRECT HOP and neither is a property of the
	// endpoint: a 302 has no page to frame and no charset to declare.
	if len(broke.Misconfigs) != 0 {
		t.Errorf("%d misconfiguration(s) were derived from a redirect hop: %v. A 302 has no page to "+
			"frame and no charset to declare, so neither of these is a fact about the endpoint",
			len(broke.Misconfigs), broke.Misconfigs)
	}
	if len(broke.SecurityHeaders.Missing) != 0 {
		t.Errorf("%d security header(s) were reported MISSING from a page that was never fetched: %v. "+
			"An absence claim about a document nobody read is a fabrication in the other direction",
			len(broke.SecurityHeaders.Missing), broke.SecurityHeaders.Missing)
	}
	for name, n := range map[string]int{
		"forms": len(broke.Forms), "input fields": len(broke.InputFields), "apis": len(broke.APIs),
		"secrets": len(broke.Secrets), "comments": len(broke.Comments), "signals": len(broke.Signals),
		"frameworks": len(broke.Frameworks), "technologies": len(broke.Technologies),
	} {
		if n != 0 {
			t.Errorf("%d %s were computed from a redirect hop's empty body", n, name)
		}
	}
	if broke.Title != "" {
		t.Errorf("a title was extracted from a redirect hop: %q", broke.Title)
	}
	// AND THE NOTE MUST NOT CARRY THE Location. It is attacker-influenced, it can carry userinfo,
	// and this string is written to a log line and into the scan result.
	for _, needle := range []string{"evil.example", "tok%"} {
		if strings.Contains(broke.RedirectChainNote, needle) {
			t.Errorf("the note pastes the Location header (%q), which is attacker-controlled text on "+
				"its way into a log and a stored row: %s", needle, broke.RedirectChainNote)
		}
	}
}

// TestRedirectChainBreakNamesWhichOfTheThreeShapesItSaw. All three mean "this is a hop, not a
// page" to a reader of the row, and an operator chasing one needs to know which: an unparseable
// Location is a finding about the target, a hop limit is a finding about the chain, and a 3xx
// with no Location is a finding about the handler.
func TestRedirectChainBreakNamesWhichOfTheThreeShapesItSaw(t *testing.T) {
	mk := func(status int, loc string, setLoc bool) *http.Response {
		r := &http.Response{StatusCode: status, Header: http.Header{}}
		if setLoc {
			r.Header.Set("Location", loc)
		}
		return r
	}
	for _, tc := range []struct {
		name   string
		resp   *http.Response
		wantIn string // "" means: this is a page, say nothing
	}{
		{"a page", mk(200, "", false), ""},
		{"a 404 is still a page", mk(404, "", false), ""},
		{"a nil response is not a hop", nil, ""},
		{"302 with no Location at all", mk(302, "", false), "no Location header"},
		{"302 whose Location no parser accepts", mk(302, "https://evil.example/tok%", true),
			"no URL parser accepts"},
		{"302 with a perfectly good Location, handed back by a FOLLOWING client",
			mk(302, "https://elsewhere.example/next", true), "was not walked to the end"},
		{"308 is a followed status too", mk(308, "", false), "no Location header"},
		{"303 as well", mk(303, "", false), "no Location header"},
		{"299 is not", mk(299, "", false), ""},
		{"400 is not", mk(400, "", false), ""},
		// THE 3xx STATUSES net/http DOES NOT FOLLOW ARE NOT HOPS. redirectBehavior walks exactly
		// 301, 302, 303, 307 and 308 and hands the rest back because it never intended to walk
		// them. A 300 can carry a real body listing the alternatives, and calling it a hop would
		// throw that page away and report a broken chain, which is this defect inverted.
		{"300 Multiple Choices can be a real page", mk(300, "", false), ""},
		{"304 Not Modified is the target answering, not a hop", mk(304, "", false), ""},
		{"305 is not followed either", mk(305, "https://proxy.example/", true), ""},
		{"306 is unused and is not a hop", mk(306, "", false), ""},
	} {
		got := redirectChainBreak(tc.resp)
		if tc.wantIn == "" {
			if got != "" {
				t.Errorf("%s: reported a broken chain: %s", tc.name, got)
			}
			continue
		}
		if !strings.Contains(got, tc.wantIn) {
			t.Errorf("%s: note %q does not name %q, so the three shapes are not distinguishable",
				tc.name, got, tc.wantIn)
		}
		// Never the Location value, in any shape.
		for _, needle := range []string{"evil.example", "elsewhere.example", "tok%"} {
			if strings.Contains(got, needle) {
				t.Errorf("%s: the note pastes the Location (%q): %s", tc.name, needle, got)
			}
		}
	}
}

// TestTheMetadataRowDoesNotClaimAnEmptyPageForAPageNeverFetched.
//
// The same defect, in the other place round 10 put it. ExecuteAndParseNucleiTechScan cannot be
// driven from a test: it needs the ars0n pool, which these tests may not write to, and a docker
// exec. So what is asserted is the SQL, read out of the source. Before this change the broken
// chain reached the one UPSERT below and stored status_code=302, an empty title, content_length
// of 0 and an empty http_response, for a URL whose page was never fetched. There is no column on
// target_urls for
// "the chain broke", so the narrower column list IS the field: title, content_length and
// http_response are left unwritten, which is NULL on an insert and unchanged on a conflict, and
// every reader in this tree already models NULL for all three (sql.NullString, nullIntToInt,
// *int). An empty string and a 0 say a page was read and was empty; NULL says nobody read one.
func TestTheMetadataRowDoesNotClaimAnEmptyPageForAPageNeverFetched(t *testing.T) {
	src, err := os.ReadFile(filepath.Join(packageDir(t), "metaDataUtils.go"))
	if err != nil {
		t.Fatalf("read metaDataUtils.go: %v", err)
	}
	text := string(src)

	if !strings.Contains(text, "chainBreak := redirectChainBreak(resp)") {
		t.Fatal("the fetch loop does not ask whether the chain broke, so every recovered hop is still " +
			"stored as a page")
	}
	idx := strings.Index(text, `if chainBreak != "" {`)
	if idx < 0 {
		t.Fatal("there is no broken-chain branch, so the recovered hop takes the page UPSERT")
	}
	end := strings.Index(text[idx:], "\n\t\t\tcontinue\n\t\t}\n")
	if end < 0 {
		t.Fatal("could not find the end of the broken-chain branch")
	}
	branch := text[idx : idx+end]
	for _, col := range []string{"title", "content_length", "http_response,", "extractTitle", "sanitizedBody"} {
		if strings.Contains(branch, col) {
			t.Errorf("the broken-chain branch still writes %q. A stored row saying the page was empty, "+
				"untitled and zero bytes long, for a page nobody fetched, is strictly worse than the "+
				"absent row this replaced: an absent row is honest about its absence", col)
		}
	}
	for _, col := range []string{"status_code", "http_response_headers"} {
		if !strings.Contains(branch, col) {
			t.Errorf("the broken-chain branch does not store %q, which WAS measured. Dropping it "+
				"throws away the one thing the round-10 conversion was for, which is that the URL "+
				"answered at all", col)
		}
	}
	if !strings.Contains(text, "chainBrokeRequests") {
		t.Error("a URL whose chain could not be walked is being counted as a success or as a failure. " +
			"It is neither: the target answered and no page was fetched, and folding it into either " +
			"column is how the row became unreadable in the first place")
	}
}

// THE BREAKING HOP IS RECORDED VERBATIM.
//
// This hop's Location was never stored before: net/http discarded the whole response, so nothing
// downstream ever saw it, and recording it is most of what the recovery is worth, because an
// unparseable Location IS the finding. It is stored exactly as the server sent it, credentials
// included: a Location carrying userinfo is the thing the operator needs to see, and a rewritten
// one is not evidence of anything.
func TestTheBreakingHopIsRecordedVerbatim(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/b", http.StatusFound)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		// Userinfo AND a trailing percent, so it cannot parse and it carries a password.
		w.Header().Set("Location", "https://svc-account:hunter2@evil.example/tok%")
		w.WriteHeader(http.StatusFound)
	})
	s := httptest.NewServer(mux)
	t.Cleanup(s.Close)

	res := investigateEndpoint("ep", s.URL+"/a", s.URL+"/a", http.MethodGet, nil, nil, nil)
	if !res.RedirectChainBroke {
		t.Fatalf("the chain did not break, so this test asserts nothing (status %d)", res.StatusCode)
	}
	found := false
	for _, r := range res.Redirects {
		if r.Location == "https://svc-account:hunter2@evil.example/tok%" {
			found = true
		}
	}
	if !found {
		t.Errorf("the hop that broke the chain was not recorded as the server sent it: %+v. The "+
			"Location goes into the row byte for byte, because an unparseable Location carrying "+
			"credentials is itself the finding", res.Redirects)
	}
}
