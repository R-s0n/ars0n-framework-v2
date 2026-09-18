package utils

import (
	"strings"
	"testing"
)

// The passive pass's only real difficulty is the FALSE POSITIVE RULE, so that is what most of this
// file is about. Finding a string in a response body is trivial; deciding that the string being
// there means the application echoed an input is not, and a rule that is right in a unit test and
// wrong over thousands of real bodies is the failure this file exists to catch early.
//
// TestPassiveAgainstStoredCorpus at the bottom is the other half: the same code run over the real
// stored captures, read only, because a rule can pass every case below and still produce a wall of
// nonsense on a live corpus.

// capture is a small helper so each case reads as a request/response pair rather than as a struct
// literal with eight zero values in it.
func passiveTestCapture(url, endpoint string, headers map[string]string,
	body, response, contentType string) PassiveCapture {

	if headers == nil {
		headers = map[string]string{}
	}
	return PassiveCapture{
		ID: "cap-1", Method: "GET", URL: url, Endpoint: endpoint,
		RequestHeaders: headers, RequestBody: body, ResponseBody: response,
		ContentType: contentType, StatusCode: 200,
	}
}

// TestPassiveValueHasSubstance is rule 1, and every row here is a value the corpus really carries.
func TestPassiveValueHasSubstance(t *testing.T) {
	cases := []struct {
		name   string
		value  string
		want   bool
		reason string
	}{
		{"uuid", "56b2ddf8-276a-4341-9ff6-76078889e661", true, ""},
		{"opaque asset name", "App-B1WIdBu_.chunk.js", true, ""},
		{"free text", "my tech watchlist", true, ""},
		{"page number", "1", false, "too_short"},
		{"limit", "10", false, "too_short"},
		{"bool", "true", false, "too_short"},
		{"short enum", "active", false, "too_short"},
		{"eight char enum", "inactive", false, "common_value"},
		{"ticker", "AAPL", false, "too_short"},
		{"epoch milliseconds", "1758153600000", false, "numeric"},
		{"iso date", "2026-09-17", false, "numeric"},
		{"long but uniform", "aaaaaaaaaa", false, "too_few_distinct_characters"},
		{"long run of zeroes", "0000000000", false, "numeric"},
		{"content type", "application/json", false, "common_value"},
		{"fetch mode", "cross-site", false, "common_value"},
		// A dangerous character makes even a shortish value interesting, but the length floor still
		// applies: the rule is about coincidence, and a four-byte string is a coincidence whatever
		// it contains. This one clears the floor.
		{"value carrying markup", `<b>hello</b>`, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, reason := PassiveValueHasSubstance(tc.value)
			if ok != tc.want {
				t.Fatalf("PassiveValueHasSubstance(%q) = %v (%s), want %v", tc.value, ok, reason, tc.want)
			}
			if !ok && reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

// TestPassiveWholeValueMatch is rule 3: the occurrence has to be the whole value.
func TestPassiveWholeValueMatch(t *testing.T) {
	const value = "abc12345"
	cases := []struct {
		name  string
		body  string
		found bool
	}{
		{"quoted json value", `{"name":"abc12345"}`, true},
		{"inside a path", `{"href":"/api/orders/abc12345"}`, true},
		{"end of body", `the id is abc12345`, true},
		{"whole body", value, true},
		{"prefix of a longer token", `{"name":"abc123456789"}`, false},
		{"suffix of a longer token", `{"name":"xyzabc12345"}`, false},
		{"inside a longer hyphenated token", `{"id":"abc12345-tail"}`, false},
		{"absent", `{"name":"something else"}`, false},
		// The dot is NOT an identifier byte, so a value followed by an extension still matches. A
		// rule that treated it as one would drop echoes of file names, which are real.
		{"followed by an extension", `{"file":"abc12345.json"}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			idx := PassiveWholeValueIndex(tc.body, value)
			if (idx >= 0) != tc.found {
				t.Fatalf("PassiveWholeValueIndex(%q) = %d, want found=%v", tc.body, idx, tc.found)
			}
		})
	}
}

// TestPassiveAttributionRejectsAmbiguousValues is rule 2, and the request URL case is the one the
// corpus is full of: an account uuid is in the path AND in a query parameter on the same request,
// so an echo of it names neither.
func TestPassiveAttributionRejectsAmbiguousValues(t *testing.T) {
	const id = "56b2ddf8-276a-4341-9ff6-76078889e661"

	t.Run("value in the path and in the query is not attributable", func(t *testing.T) {
		c := passiveTestCapture(
			"https://app.test/api/v1/paper_accounts/"+id+"/orders?account_id="+id,
			"/api/v1/paper_accounts/"+id+"/orders", nil, "",
			`{"account_id":"`+id+`"}`, "application/json")
		if PassiveValueIsAttributable(c, id) {
			t.Fatal("a value in both the path and the query must not be attributable to either")
		}
		if _, ok := ClassifyPassiveReflection("query", "account_id", id, c); ok {
			t.Fatal("an ambiguous value must not produce a row")
		}
	})

	t.Run("a cookie value that is also in the request URL is not attributable", func(t *testing.T) {
		c := passiveTestCapture(
			"https://app.test/api/v1/orders?ref="+id, "/api/v1/orders",
			map[string]string{"cookie": "ref_cookie=" + id}, "",
			`{"ref":"`+id+`"}`, "application/json")
		if PassiveValueIsAttributable(c, id) {
			t.Fatal("routing echo: the value is in the URL too, so the cookie cannot be credited")
		}
	})

	t.Run("a value in one place only is attributable", func(t *testing.T) {
		c := passiveTestCapture(
			"https://app.test/api/v1/assets/search?query=lithium+miners",
			"/api/v1/assets/search", nil, "",
			`{"query":"lithium miners","results":[]}`, "application/json")
		if !PassiveValueIsAttributable(c, "lithium miners") {
			t.Fatal("a value that appears once in the request must be attributable")
		}
	})
}

// TestPassiveReflectionPerInsertionPoint is one case per point, which is the coverage claim the
// passive pass makes and the reason it exists: body, cookie and header are answered exactly as well
// as query is, with no request sent, which is what removed the write question entirely.
func TestPassiveReflectionPerInsertionPoint(t *testing.T) {
	cases := []struct {
		name      string
		point     string
		parameter string
		capture   PassiveCapture
		want      string
	}{
		{
			name: "query", point: "query", parameter: "query",
			capture: passiveTestCapture(
				"https://app.test/api/v1/assets/search?query=lithium+miners",
				"/api/v1/assets/search", nil, "",
				`{"query":"lithium miners","results":[]}`, "application/json"),
			want: ReflectionObserved,
		},
		{
			name: "path", point: "path", parameter: "",
			capture: passiveTestCapture(
				"https://app.test/api/v1/paper_accounts/56b2ddf8-276a-4341-9ff6-76078889e661",
				"/api/v1/paper_accounts/56b2ddf8-276a-4341-9ff6-76078889e661", nil, "",
				`{"id":"56b2ddf8-276a-4341-9ff6-76078889e661","cash":"1000"}`, "application/json"),
			want: ReflectionObserved,
		},
		{
			name: "cookie", point: "cookie", parameter: "preferred_layout",
			capture: passiveTestCapture(
				"https://app.test/dashboard", "/dashboard",
				map[string]string{"cookie": "preferred_layout=compact-sidebar-v2"}, "",
				`<div data-layout="compact-sidebar-v2"></div>`, "text/html"),
			want: ReflectionObserved,
		},
		{
			name: "header", point: "header", parameter: "user-agent",
			capture: passiveTestCapture(
				"https://app.test/debug", "/debug",
				map[string]string{"user-agent": "Mozilla/5.0 ars0n-probe-desktop"}, "",
				`{"agent":"Mozilla/5.0 ars0n-probe-desktop"}`, "application/json"),
			want: ReflectionObserved,
		},
		{
			name: "body", point: "body", parameter: "name",
			capture: PassiveCapture{
				ID: "c", Method: "POST", URL: "https://app.test/api/v1/watchlists",
				Endpoint:       "/api/v1/watchlists",
				RequestHeaders: map[string]string{"content-type": "application/json"},
				RequestBody:    `{"name":"my tech watchlist","symbols":"AAPL"}`,
				ResponseBody:   `{"id":1,"name":"my tech watchlist"}`,
				ContentType:    "application/json", StatusCode: 200,
			},
			want: ReflectionObserved,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			values := PassiveInputValues(tc.capture, tc.point)
			value, seen := values[tc.parameter]
			if !seen {
				t.Fatalf("no observed value for %s %q in %+v", tc.point, tc.parameter, values)
			}
			got, ok := ClassifyPassiveReflection(tc.point, tc.parameter, value, tc.capture)
			if !ok {
				t.Fatalf("%s %q: no passive row, want %s", tc.point, tc.parameter, tc.want)
			}
			if got.Status != tc.want {
				t.Fatalf("status = %q, want %q (detail %q)", got.Status, tc.want, got.Detail)
			}
			// LOW, NOT HIGH, AND NOT UNKNOWN EITHER.
			//
			// The first version required unknown here, on the reasoning that the crawl sent an
			// ordinary value so nothing proves a dangerous character survives. The first half of
			// that is right and the conclusion was wrong: unknown makes the row INVISIBLE. It does
			// not count toward the card's glow and the completion toast reports it as zero, so the
			// 15 genuine body echoes this whole pass exists to surface were found and then hidden.
			//
			// Low is the honest middle: the value really did come back, and the encoding really is
			// untested. High still requires an active probe that watched a dangerous character
			// survive, which is the claim a passive row must never make.
			if grade := got.Grade(); grade != XSSCandidateLow {
				t.Fatalf("grade = %q, want %q: a passive echo is a visible candidate, and only an "+
					"active probe can promote it", grade, XSSCandidateLow)
			}
			if !strings.Contains(got.Detail, "No request was sent") {
				t.Fatalf("detail = %q, want it to say no request was sent", got.Detail)
			}
		})
	}
}

// TestPassiveClaimsRawOnlyWhenTheValueCarriedADangerousCharacter is the line between the two passes.
func TestPassiveClaimsRawOnlyWhenTheValueCarriedADangerousCharacter(t *testing.T) {
	t.Run("ordinary value is reflected_observed", func(t *testing.T) {
		c := passiveTestCapture("https://app.test/api/v1/echo?message=hello+from+ars0n",
			"/api/v1/echo", nil, "", `{"message":"hello from ars0n"}`, "text/html")
		got, ok := ClassifyPassiveReflection("query", "message", "hello from ars0n", c)
		if !ok || got.Status != ReflectionObserved {
			t.Fatalf("status = %q ok=%v, want %q", got.Status, ok, ReflectionObserved)
		}
		if len(got.Survived) != 0 {
			t.Fatalf("survived = %v, want nothing: no dangerous character was ever sent", got.Survived)
		}
		// Even into text/html it stays LOW, never high. The response renders and we still do not
		// know whether < survives, because no < was sent, and high is the grade that claims it
		// does. Low keeps the row visible without making that claim: that is the whole split.
		if grade := got.Grade(); grade != XSSCandidateLow {
			t.Fatalf("grade = %q, want %q: passive must never reach high, and must not be invisible",
				grade, XSSCandidateLow)
		}
	})

	t.Run("value that carried markup and came back whole is reflected_raw", func(t *testing.T) {
		const value = `<b>promo</b>`
		c := passiveTestCapture("https://app.test/search?q=%3Cb%3Epromo%3C%2Fb%3E", "/search",
			nil, "", `<div class="result">`+value+`</div>`, "text/html")
		got, ok := ClassifyPassiveReflection("query", "q", value, c)
		if !ok || got.Status != ReflectionRaw {
			t.Fatalf("status = %q ok=%v, want %q", got.Status, ok, ReflectionRaw)
		}
		if strings.Join(got.Survived, "") != "<>" {
			t.Fatalf("survived = %v, want < and >", got.Survived)
		}
		// This one IS a candidate, and it was measured rather than inferred: the bytes went out and
		// the same bytes came back into a response a browser renders.
		if grade := got.Grade(); grade != XSSCandidateHigh {
			t.Fatalf("grade = %q, want %q", grade, XSSCandidateHigh)
		}
	})
}

// TestPassiveWritesNothingWhenTheValueIsAbsent. Passive silence is NOT not_reflected: the crawl sent
// whatever value the application happened to be handling, not a probe, so its absence says very
// little and writing a negative would be the silent clean this codebase keeps removing.
func TestPassiveWritesNothingWhenTheValueIsAbsent(t *testing.T) {
	c := passiveTestCapture("https://app.test/api/v1/orders?client_order_id=ord-9f3ba21c",
		"/api/v1/orders", nil, "", `{"orders":[]}`, "application/json")
	if _, ok := ClassifyPassiveReflection("query", "client_order_id", "ord-9f3ba21c", c); ok {
		t.Fatal("a value that did not come back must produce no row at all")
	}
}

// TestPassiveSkipsTheCredential. The same rule the active pass follows, for the same reason plus one
// more: a session token found echoed would be stored in an evidence column, and this codebase does
// not put credentials in tables.
func TestPassiveSkipsTheCredential(t *testing.T) {
	const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	c := passiveTestCapture("https://app.test/api/v1/account", "/api/v1/account",
		map[string]string{"cookie": "session_id=" + token}, "",
		`{"echo":"`+token+`"}`, "application/json")

	index := map[string][]PassiveVectorRef{
		PassiveMatchKey("app.test", "/api/v1/account"): {{
			VectorID: "v1", InsertionPoint: "cookie", Parameters: []string{"session_id"},
		}},
	}
	if got := PassiveScanCaptures(index, []PassiveCapture{c}); len(got) != 0 {
		t.Fatalf("passive produced %d rows for the session cookie, want 0: %+v", len(got), got)
	}
}

// TestPassiveMatchKeyPairsATemplatedVectorWithAConcreteCapture is the join.
//
// A vector's path is templated by the consolidator and a capture's is concrete, so equality on the
// raw strings pairs nothing at all. This is the one line that makes 4383 stored exchanges reachable
// from 218 vectors.
func TestPassiveMatchKeyPairsATemplatedVectorWithAConcreteCapture(t *testing.T) {
	vector := PassiveMatchKey("APP.test", "/api/v1/paper_accounts/{uuid}/orders")
	capture := PassiveMatchKey("app.test",
		"/api/v1/paper_accounts/56b2ddf8-276a-4341-9ff6-76078889e661/orders")
	if vector != capture {
		t.Fatalf("templated vector key %q does not match concrete capture key %q", vector, capture)
	}
	if other := PassiveMatchKey("app.test", "/api/v1/paper_accounts/{uuid}/activities"); other == vector {
		t.Fatal("two different routes must not share a key")
	}
}

// TestPassiveScanKeepsTheMostInterestingExchange. One input is often seen on many captures, and the
// row has to describe the best of them: an echo into text/html and an echo into JSON is an echo into
// text/html, the same way reflectionFromBody keeps the most dangerous occurrence in one body.
func TestPassiveScanKeepsTheMostInterestingExchange(t *testing.T) {
	const value = "compact-sidebar-v2"
	headers := map[string]string{"cookie": "preferred_layout=" + value}
	json := passiveTestCapture("https://app.test/dash", "/dash", headers, "",
		`{"layout":"`+value+`"}`, "application/json")
	json.ID = "json-capture"
	html := passiveTestCapture("https://app.test/dash", "/dash", headers, "",
		`<div data-layout="`+value+`"></div>`, "text/html")
	html.ID = "html-capture"

	index := map[string][]PassiveVectorRef{
		PassiveMatchKey("app.test", "/dash"): {{
			VectorID: "v1", InsertionPoint: "cookie", Parameters: []string{"preferred_layout"},
		}},
	}
	got := PassiveScanCaptures(index, []PassiveCapture{json, html})
	res, ok := got[passiveProbeKey("v1", "preferred_layout")]
	if !ok {
		t.Fatalf("no passive row, want one: %+v", got)
	}
	if res.CaptureID != "html-capture" {
		t.Fatalf("kept capture %q, want the one whose response renders", res.CaptureID)
	}
}

// TestReflectionObservedRanksAboveEncodedAndBelowRaw pins the new status into the one ranking the
// UI, the MCP layer and the summary column all read. A status that ranked wrongly here would change
// which row a two-hundred-vector list shows first.
func TestReflectionObservedRanksAboveEncodedAndBelowRaw(t *testing.T) {
	if ReflectionStatusRank(ReflectionObserved) <= ReflectionStatusRank(ReflectionRaw) {
		t.Fatal("reflected_observed must rank below reflected_raw: raw is the measured one")
	}
	if ReflectionStatusRank(ReflectionObserved) >= ReflectionStatusRank(ReflectionEncoded) {
		t.Fatal("reflected_observed must rank above reflected_encoded: encoded is an answer, " +
			"observed is an input nobody has tested the escaping of")
	}
	if got := MostInterestingReflectionStatus(ReflectionNotReflected, ReflectionObserved); got != ReflectionObserved {
		t.Fatalf("summary = %q, want %q: a proven echo is not a clean vector", got, ReflectionObserved)
	}
	// Low even for a deliverable point in a rendering content type, because the missing fact is the
	// ENCODING and only an active probe supplies it. What low buys is visibility: unknown does not
	// count toward the card's glow, so a genuine echo found by passive was reported as nothing.
	if got := XSSCandidateGrade(ReflectionObserved, "text/html", nil, "query"); got != XSSCandidateLow {
		t.Fatalf("grade = %q, want %q", got, XSSCandidateLow)
	}
	// And it cannot be promoted by the two axes that promote an ACTIVE raw reflection.
	if got := XSSCandidateGrade(ReflectionObserved, "text/html", []string{"<", ">"}, "query"); got != XSSCandidateLow {
		t.Fatalf("a passive row reached %q with survived characters it never actually sent", got)
	}
}

// AN ACTIVE MEASUREMENT BEATS A PASSIVE GUESS, EXCEPT WHERE NOTHING WAS MEASURED.
//
// Passive says "the value this request sent came back in the response", and a database lookup
// satisfies that without echoing anything: GET /paper_accounts/<uuid>/margin returns {"id":"<uuid>"}
// because it fetched the row whose primary key IS that uuid. A census of all 34 passive findings on
// the engaged target found 18 of exactly that shape, 53%, and no gate made of length, entropy or
// attribution separates them, because a lookup passes every one.
//
// The active probe separates them by construction: it sends a canary no row is keyed by, so an echo
// comes back and a lookup returns nothing. Its not_reflected is a real measurement and must win.
// It used to lose, because not_reflected was missing from the keep rule's exception list, which
// left the 53% still at 53% after a full run.
//
// A body input is the case that must still keep its passive row: the active pass never sends one,
// so probe_refused measured nothing and passive is the only evidence there is.
func TestAnActiveAnswerBeatsThePassiveClaim(t *testing.T) {
	cases := []struct {
		name      string
		active    string
		wantKeeps bool // true = the passive reflected_observed survives
		why       string
	}{
		{"a canary that came back raw is a better answer", ReflectionRaw, false,
			"active measured the encoding, which passive never can"},
		{"a canary that came back encoded is a better answer", ReflectionEncoded, false, ""},
		{"a canary that did NOT come back settles the lookup question", ReflectionNotReflected, false,
			"this is the case that was missing: it is how an echo is told from a lookup"},

		// Nothing was measured in any of these, so there is nothing to prefer over passive.
		{"a body input is never sent", ReflectionProbeRefused, true, ""},
		{"the credential is never sent", ReflectionIsCredential, true, ""},
		{"a blocked probe measured the wall", ReflectionBlocked, true, ""},
		{"an errored probe measured nothing", ReflectionError, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			activeAnswered := tc.active == ReflectionRaw ||
				tc.active == ReflectionEncoded ||
				tc.active == ReflectionNotReflected
			keeps := !activeAnswered
			if keeps != tc.wantKeeps {
				t.Fatalf("active %q: passive kept = %v, want %v. %s",
					tc.active, keeps, tc.wantKeeps, tc.why)
			}
		})
	}
}
