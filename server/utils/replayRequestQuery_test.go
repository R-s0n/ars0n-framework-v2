package utils

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// The compiled expressions for the plain columns, spelled out once so the expectations below read
// as "this operator produces this comparison" rather than as a wall of COALESCE.
const (
	sqlMethod = `COALESCE(method,'')`
	sqlURL    = `COALESCE(url,'')`
	sqlStatus = `COALESCE(status_code,0)`
	sqlMime   = `COALESCE(mime_type,'')`
	sqlBody   = `COALESCE(post_data,'')`
	// Deliberately NOT COALESCEd, and NULLIF'd rather than left bare: the recorder writes '' for a
	// body it did not keep, so an unrecorded body is unknown, not empty, and a comparison against
	// it must be UNKNOWN and drop the row rather than answer for it.
	sqlResp = `NULLIF(response_body,'')`
	// octet_length because the documented unit is bytes.
	sqlSize   = `octet_length(NULLIF(response_body,''))`
	sqlTime   = `COALESCE(duration_ms,0)`
	sqlClass  = `(COALESCE(status_code,0)/100)`
	sqlDirect = `COALESCE(is_direct,false)`
	sqlGraph  = `COALESCE(graphql_operation,'')`
	sqlRType  = `COALESCE(resource_type,'')`
	sqlInit   = `COALESCE(initiator,'')`
)

func TestReplayRequestQueryOperators(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		wantSQL  string
		wantArgs []interface{}
	}{
		{
			name:     "equals is case-insensitive",
			query:    "method = POST",
			wantSQL:  `(lower(` + sqlMethod + `) = lower($1))`,
			wantArgs: []interface{}{"POST"},
		},
		{
			name:     "not equals",
			query:    "method != GET",
			wantSQL:  `(lower(` + sqlMethod + `) <> lower($1))`,
			wantArgs: []interface{}{"GET"},
		},
		{
			name:     "contains",
			query:    "host ~ assurant",
			wantSQL:  `(strpos(lower(` + captureSQLHost + `), lower($1)) > 0)`,
			wantArgs: []interface{}{"assurant"},
		},
		{
			name:     "does not contain",
			query:    "url !~ static",
			wantSQL:  `(strpos(lower(` + sqlURL + `), lower($1)) = 0)`,
			wantArgs: []interface{}{"static"},
		},
		{
			name:     "starts with",
			query:    "path ^= /api",
			wantSQL:  `(left(lower(` + captureSQLPath + `), length(lower($1))) = lower($1))`,
			wantArgs: []interface{}{"/api"},
		},
		{
			name:     "ends with",
			query:    "path $= .json",
			wantSQL:  `(right(lower(` + captureSQLPath + `), length(lower($1))) = lower($1))`,
			wantArgs: []interface{}{".json"},
		},
		{
			name:     "regex compiles to case-insensitive posix match",
			query:    `url =~ /api/v[0-9]+/`,
			wantSQL:  `(` + sqlURL + ` ~* $1)`,
			wantArgs: []interface{}{"/api/v[0-9]+/"},
		},
		{
			name:     "greater than or equal is numeric",
			query:    "status >= 400",
			wantSQL:  `(` + sqlStatus + ` >= $1)`,
			wantArgs: []interface{}{int64(400)},
		},
		{
			name:     "greater than",
			query:    "size > 10000",
			wantSQL:  `(` + sqlSize + ` > $1)`,
			wantArgs: []interface{}{int64(10000)},
		},
		{
			name:     "less than",
			query:    "time < 250",
			wantSQL:  `(` + sqlTime + ` < $1)`,
			wantArgs: []interface{}{int64(250)},
		},
		{
			name:     "less than or equal",
			query:    "status <= 299",
			wantSQL:  `(` + sqlStatus + ` <= $1)`,
			wantArgs: []interface{}{int64(299)},
		},
		{
			name:     "equals on a numeric field compares numbers",
			query:    "status = 200",
			wantSQL:  `(` + sqlStatus + ` = $1)`,
			wantArgs: []interface{}{int64(200)},
		},
		{
			name:     "not equals on a numeric field",
			query:    "status != 200",
			wantSQL:  `(` + sqlStatus + ` <> $1)`,
			wantArgs: []interface{}{int64(200)},
		},
		{
			name:     "a text operator on a numeric field falls back to the digits",
			query:    "status ~ 40",
			wantSQL:  `(strpos(lower(COALESCE(status_code::text,'')), lower($1)) > 0)`,
			wantArgs: []interface{}{"40"},
		},
		{
			name:     "no spaces around the operator",
			query:    "status>=500",
			wantSQL:  `(` + sqlStatus + ` >= $1)`,
			wantArgs: []interface{}{int64(500)},
		},
		{
			name:     "a fractional bound is accepted",
			query:    "time > 1.5",
			wantSQL:  `(` + sqlTime + ` > $1)`,
			wantArgs: []interface{}{1.5},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := BuildCaptureFilter(tc.query, 1)
			if err != nil {
				t.Fatalf("BuildCaptureFilter(%q) returned error: %v", tc.query, err)
			}
			if sql != tc.wantSQL {
				t.Errorf("SQL mismatch\n got: %s\nwant: %s", sql, tc.wantSQL)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Errorf("args mismatch\n got: %#v\nwant: %#v", args, tc.wantArgs)
			}
		})
	}
}

func TestReplayRequestQueryFields(t *testing.T) {
	cases := []struct {
		name     string
		query    string
		wantSQL  string
		wantArgs []interface{}
	}{
		{"method", "method = GET", `(lower(` + sqlMethod + `) = lower($1))`, []interface{}{"GET"}},
		{"status", "status = 404", `(` + sqlStatus + ` = $1)`, []interface{}{int64(404)}},
		{"host", "host = api.example.com", `(lower(` + captureSQLHost + `) = lower($1))`, []interface{}{"api.example.com"}},
		{"domain is an alias for host", "domain = api.example.com", `(lower(` + captureSQLHost + `) = lower($1))`, []interface{}{"api.example.com"}},
		{"path", "path = /login", `(lower(` + captureSQLPath + `) = lower($1))`, []interface{}{"/login"}},
		{"url", "url ~ graphql", `(strpos(lower(` + sqlURL + `), lower($1)) > 0)`, []interface{}{"graphql"}},
		{"query", "query ~ redirect", `(strpos(lower(` + captureSQLQuery + `), lower($1)) > 0)`, []interface{}{"redirect"}},
		{"mime", "mime ~ json", `(strpos(lower(` + sqlMime + `), lower($1)) > 0)`, []interface{}{"json"}},
		{"ext", "ext = js", `(lower(` + captureSQLExt + `) = lower($1))`, []interface{}{"js"}},
		{"body", "body ~ password", `(strpos(lower(` + sqlBody + `), lower($1)) > 0)`, []interface{}{"password"}},
		{"resp.body", "resp.body ~ stack", `(strpos(lower(` + sqlResp + `), lower($1)) > 0)`, []interface{}{"stack"}},
		{"size", "size >= 1", `(` + sqlSize + ` >= $1)`, []interface{}{int64(1)}},
		{"time", "time >= 0", `(` + sqlTime + ` >= $1)`, []interface{}{int64(0)}},
		{"status_class", "status_class = 4", `(` + sqlClass + ` = $1)`, []interface{}{int64(4)}},
		{"resource_type", "resource_type = xmlhttprequest", `(lower(` + sqlRType + `) = lower($1))`, []interface{}{"xmlhttprequest"}},
		{"initiator", "initiator ~ example", `(strpos(lower(` + sqlInit + `), lower($1)) > 0)`, []interface{}{"example"}},
		{"is_direct true", "is_direct = true", `(` + sqlDirect + ` = $1)`, []interface{}{true}},
		{"is_direct false", "is_direct = false", `(` + sqlDirect + ` = $1)`, []interface{}{false}},
		{"is_direct not equals", "is_direct != true", `(` + sqlDirect + ` <> $1)`, []interface{}{true}},
		{"graphql", "graphql = GetUser", `(lower(` + sqlGraph + `) = lower($1))`, []interface{}{"GetUser"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := BuildCaptureFilter(tc.query, 1)
			if err != nil {
				t.Fatalf("BuildCaptureFilter(%q) returned error: %v", tc.query, err)
			}
			if sql != tc.wantSQL {
				t.Errorf("SQL mismatch\n got: %s\nwant: %s", sql, tc.wantSQL)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Errorf("args mismatch\n got: %#v\nwant: %#v", args, tc.wantArgs)
			}
		})
	}
}

// The JSONB families bind two values: the key first, then the compared value. Both must be
// parameters, because both come from the operator.
func TestReplayRequestQueryJSONBFields(t *testing.T) {
	cases := []struct {
		name         string
		query        string
		wantArgs     []interface{}
		wantContains []string
		wantAbsent   []string
	}{
		{
			name:     "request header lookup lower-cases the name",
			query:    "header.Cookie ~ session",
			wantArgs: []interface{}{"cookie", "session"},
			wantContains: []string{
				`headers->>$1`,
				`lower(h.key) = $1`,
				`lower($2)`,
			},
			wantAbsent: []string{"response_headers"},
		},
		{
			name:     "response header lookup reads the response column",
			query:    "resp.header.Server ~ nginx",
			wantArgs: []interface{}{"server", "nginx"},
			wantContains: []string{
				`response_headers->>$1`,
				`lower(h.key) = $1`,
			},
		},
		{
			name:     "parameter lookup checks GET and POST and keeps the name's case",
			query:    "param.userId = 5",
			wantArgs: []interface{}{"userId", "5"},
			wantContains: []string{
				`get_params->>$1`,
				`post_params->>$1`,
				`lower($2)`,
			},
		},
		{
			name:     "has:header is a presence test with no value",
			query:    "has:header.Authorization",
			wantArgs: []interface{}{"authorization"},
			wantContains: []string{
				`EXISTS (SELECT 1 FROM jsonb_each_text(`,
				`lower(h.key) = $1`,
			},
		},
		{
			name:     "has:param checks both parameter columns",
			query:    "has:param.redirect_uri",
			wantArgs: []interface{}{"redirect_uri"},
			wantContains: []string{
				`get_params`,
				`post_params`,
				`g.key = $1`,
				`p.key = $1`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := BuildCaptureFilter(tc.query, 1)
			if err != nil {
				t.Fatalf("BuildCaptureFilter(%q) returned error: %v", tc.query, err)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Errorf("args mismatch\n got: %#v\nwant: %#v", args, tc.wantArgs)
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(sql, want) {
					t.Errorf("SQL is missing %q\ngot: %s", want, sql)
				}
			}
			for _, absent := range tc.wantAbsent {
				if strings.Contains(sql, absent) {
					t.Errorf("SQL should not mention %q\ngot: %s", absent, sql)
				}
			}
			if strings.Contains(sql, captureHeaderParamMarker) {
				t.Errorf("the JSONB key placeholder marker survived into the SQL: %s", sql)
			}
		})
	}
}

func TestReplayRequestQueryBooleansAndGrouping(t *testing.T) {
	methodEq := `(lower(` + sqlMethod + `) = lower($%d))`
	cases := []struct {
		name     string
		query    string
		wantSQL  string
		wantArgs []interface{}
	}{
		{
			name:     "explicit AND",
			query:    "method = POST AND status >= 400",
			wantSQL:  `(` + fmtSQL(methodEq, 1) + ` AND (` + sqlStatus + ` >= $2))`,
			wantArgs: []interface{}{"POST", int64(400)},
		},
		{
			name:     "adjacent terms imply AND",
			query:    "method = POST status >= 400",
			wantSQL:  `(` + fmtSQL(methodEq, 1) + ` AND (` + sqlStatus + ` >= $2))`,
			wantArgs: []interface{}{"POST", int64(400)},
		},
		{
			name:  "AND binds tighter than OR",
			query: "method = GET OR method = POST AND status = 200",
			wantSQL: `(` + fmtSQL(methodEq, 1) + ` OR (` + fmtSQL(methodEq, 2) +
				` AND (` + sqlStatus + ` = $3)))`,
			wantArgs: []interface{}{"GET", "POST", int64(200)},
		},
		{
			name:  "parentheses override precedence",
			query: "(method = GET OR method = POST) AND status = 200",
			wantSQL: `((` + fmtSQL(methodEq, 1) + ` OR ` + fmtSQL(methodEq, 2) +
				`) AND (` + sqlStatus + ` = $3))`,
			wantArgs: []interface{}{"GET", "POST", int64(200)},
		},
		{
			name:     "NOT binds tighter than AND",
			query:    "NOT method = GET AND status = 200",
			wantSQL:  `((NOT ` + fmtSQL(methodEq, 1) + `) AND (` + sqlStatus + ` = $2))`,
			wantArgs: []interface{}{"GET", int64(200)},
		},
		{
			name:     "NOT applies to a group",
			query:    "NOT (method = GET OR method = POST)",
			wantSQL:  `(NOT (` + fmtSQL(methodEq, 1) + ` OR ` + fmtSQL(methodEq, 2) + `))`,
			wantArgs: []interface{}{"GET", "POST"},
		},
		{
			name:     "keywords are case-insensitive",
			query:    "method = GET or method = POST",
			wantSQL:  `(` + fmtSQL(methodEq, 1) + ` OR ` + fmtSQL(methodEq, 2) + `)`,
			wantArgs: []interface{}{"GET", "POST"},
		},
		{
			name:     "nested groups",
			query:    "method = GET AND (status = 200 OR (status = 302))",
			wantSQL:  `(` + fmtSQL(methodEq, 1) + ` AND ((` + sqlStatus + ` = $2) OR (` + sqlStatus + ` = $3)))`,
			wantArgs: []interface{}{"GET", int64(200), int64(302)},
		},
		{
			name:  "the spec's presence-and-negation example",
			query: "has:header.authorization AND NOT path ^= /static",
			wantSQL: `(` + captureHeaderPresenceSQL("headers", "$1") +
				` AND (NOT (left(lower(` + captureSQLPath + `), length(lower($2))) = lower($2))))`,
			wantArgs: []interface{}{"authorization", "/static"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := BuildCaptureFilter(tc.query, 1)
			if err != nil {
				t.Fatalf("BuildCaptureFilter(%q) returned error: %v", tc.query, err)
			}
			if sql != tc.wantSQL {
				t.Errorf("SQL mismatch\n got: %s\nwant: %s", sql, tc.wantSQL)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Errorf("args mismatch\n got: %#v\nwant: %#v", args, tc.wantArgs)
			}
		})
	}
}

func fmtSQL(template string, n int) string {
	return strings.Replace(template, "$%d", "$"+strconv.Itoa(n), 1)
}

func TestReplayRequestQueryBareTerms(t *testing.T) {
	bare := func(p string) string {
		return `(strpos(lower(` + sqlURL + `), lower(` + p + `)) > 0 ` +
			`OR strpos(lower(` + sqlMethod + `), lower(` + p + `)) > 0 ` +
			`OR strpos(COALESCE(status_code::text,''), ` + p + `) > 0)`
	}

	cases := []struct {
		name     string
		query    string
		wantSQL  string
		wantArgs []interface{}
	}{
		{
			name:     "a lone word searches url, method and status",
			query:    "login",
			wantSQL:  bare("$1"),
			wantArgs: []interface{}{"login"},
		},
		{
			name:     "two bare words are ANDed",
			query:    "login admin",
			wantSQL:  `(` + bare("$1") + ` AND ` + bare("$2") + `)`,
			wantArgs: []interface{}{"login", "admin"},
		},
		{
			name:     "a bare word combines with a field term",
			query:    "login AND method = POST",
			wantSQL:  `(` + bare("$1") + ` AND (lower(` + sqlMethod + `) = lower($2)))`,
			wantArgs: []interface{}{"login", "POST"},
		},
		{
			name:     "a field name alone is a bare word, not a broken term",
			query:    "graphql",
			wantSQL:  bare("$1"),
			wantArgs: []interface{}{"graphql"},
		},
		{
			name:     "quoting is the escape hatch for a word that names a field",
			query:    `"path"`,
			wantSQL:  bare("$1"),
			wantArgs: []interface{}{"path"},
		},
		{
			name:     "a quoted value may contain spaces",
			query:    `path = "/a b/c"`,
			wantSQL:  `(lower(` + captureSQLPath + `) = lower($1))`,
			wantArgs: []interface{}{"/a b/c"},
		},
		{
			name:     "an escaped quote survives inside a quoted value",
			query:    `resp.body ~ "say \"hi\""`,
			wantSQL:  `(strpos(lower(` + sqlResp + `), lower($1)) > 0)`,
			wantArgs: []interface{}{`say "hi"`},
		},
		{
			name:     "an empty query matches everything",
			query:    "   ",
			wantSQL:  "TRUE",
			wantArgs: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sql, args, err := BuildCaptureFilter(tc.query, 1)
			if err != nil {
				t.Fatalf("BuildCaptureFilter(%q) returned error: %v", tc.query, err)
			}
			if sql != tc.wantSQL {
				t.Errorf("SQL mismatch\n got: %s\nwant: %s", sql, tc.wantSQL)
			}
			if !reflect.DeepEqual(args, tc.wantArgs) {
				t.Errorf("args mismatch\n got: %#v\nwant: %#v", args, tc.wantArgs)
			}
		})
	}
}

// The caller binds $1 to the scope target, so the filter has to be able to start anywhere.
func TestReplayRequestQueryPlaceholderOffset(t *testing.T) {
	sql, args, err := BuildCaptureFilter("method = POST AND status = 200", 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := `((lower(` + sqlMethod + `) = lower($2)) AND (` + sqlStatus + ` = $3))`
	if sql != want {
		t.Errorf("SQL mismatch\n got: %s\nwant: %s", sql, want)
	}
	if !reflect.DeepEqual(args, []interface{}{"POST", int64(200)}) {
		t.Errorf("args mismatch: %#v", args)
	}
}

// The single most important property in this file. The search box takes attacker-shaped text by
// design, and none of it may ever reach the SQL as text.
func TestReplayRequestQueryNeverInterpolatesValues(t *testing.T) {
	hostile := []string{
		`url ~ "' OR 1=1 --"`,
		`path = "'; DROP TABLE manual_crawl_captures; --"`,
		`header.x-evil ~ "UNION SELECT null"`,
		`"'; SELECT pg_sleep(10); --"`,
		`param."a';--" = 1`,
	}

	for _, query := range hostile {
		sql, args, err := BuildCaptureFilter(query, 1)
		if err != nil {
			// Refusing to parse is an acceptable answer; silently interpolating is not.
			continue
		}
		for _, arg := range args {
			text, ok := arg.(string)
			if !ok || text == "" {
				continue
			}
			if strings.Contains(sql, text) {
				t.Errorf("value %q was interpolated into the SQL for query %q:\n%s", text, query, sql)
			}
		}
		for _, marker := range []string{"DROP TABLE", "pg_sleep", "OR 1=1"} {
			if strings.Contains(sql, marker) {
				t.Errorf("query %q leaked %q into the SQL:\n%s", query, marker, sql)
			}
		}
	}
}

func TestReplayRequestQueryErrors(t *testing.T) {
	cases := []struct {
		name        string
		query       string
		wantMessage string
		wantPos     int
	}{
		{
			name:        "operator with no value",
			query:       "method =",
			wantMessage: `expected a value after "=" but the query ended`,
			wantPos:     8,
		},
		{
			name:        "unknown field",
			query:       "foo = bar",
			wantMessage: `unknown field "foo"`,
			wantPos:     1,
		},
		// A second operator standing where the value belongs used to parse cleanly as "the literal
		// string =" plus a bare term, so the whole query silently matched nothing. A broken query
		// that returns an empty result is indistinguishable from a working query with no matches,
		// which is the worst thing a search box can do.
		{
			name:        "operator used as a value",
			query:       "method = = POST",
			wantMessage: `expected a value after "=" but found the operator "="`,
			wantPos:     10,
		},
		{
			name:        "two-character operator used as a value",
			query:       "status > >= 5",
			wantMessage: `expected a value after ">" but found the operator ">="`,
			wantPos:     10,
		},
		{
			name:        "unclosed group",
			query:       "(method = POST",
			wantMessage: `expected ")" (the group opened at position 1 is still open)`,
			wantPos:     15,
		},
		{
			name:        "stray closing paren",
			query:       "method = POST)",
			wantMessage: `unexpected ")"; expected AND, OR or the end of the query`,
			wantPos:     14,
		},
		{
			name:        "bad regular expression",
			query:       "path =~ [unclosed",
			wantMessage: `invalid regular expression "[unclosed"`,
			wantPos:     1,
		},
		{
			name:        "non-numeric value on a numeric field",
			query:       "status > abc",
			wantMessage: `field "status" is numeric; expected a number, got "abc"`,
			wantPos:     1,
		},
		{
			name:        "numeric operator on a text field",
			query:       "path > 5",
			wantMessage: `operator ">" needs a numeric field; "path" is text`,
			wantPos:     1,
		},
		{
			name:        "doubled operator",
			query:       "method ~~ POST",
			wantMessage: `"~~" is not an operator`,
			wantPos:     8,
		},
		{
			name:        "header with no name",
			query:       "header. ~ x",
			wantMessage: `expected a header name after "header."`,
			wantPos:     1,
		},
		{
			name:        "unterminated quote",
			query:       `path = "unterminated`,
			wantMessage: `unterminated quoted value; expected a closing double quote`,
			wantPos:     8,
		},
		{
			name:        "non-boolean value on a boolean field",
			query:       "is_direct = maybe",
			wantMessage: `field "is_direct" is a boolean; expected true or false, got "maybe"`,
			wantPos:     1,
		},
		{
			name:        "field followed by a word instead of an operator",
			query:       "path login",
			wantMessage: `expected an operator after field "path"`,
			wantPos:     6,
		},
		{
			name:        "has: with neither header nor param",
			query:       "has:cookie",
			wantMessage: `has: tests for a header or a parameter`,
			wantPos:     1,
		},
		{
			name:        "dangling AND",
			query:       "method = POST AND",
			wantMessage: `expected a term after "AND" but the query ended`,
			wantPos:     15,
		},
		{
			name:        "dangling OR",
			query:       "method = POST OR",
			wantMessage: `expected a term after "OR" but the query ended`,
			wantPos:     15,
		},
		{
			name:        "dangling NOT",
			query:       "NOT",
			wantMessage: `expected a term after "NOT" but the query ended`,
			wantPos:     1,
		},
		{
			name:        "a keyword where a term belongs",
			query:       "method = POST AND AND status = 200",
			wantMessage: `expected a term but found "AND"`,
			wantPos:     19,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := BuildCaptureFilter(tc.query, 1)
			if err == nil {
				t.Fatalf("BuildCaptureFilter(%q) should have failed", tc.query)
			}
			parseErr, ok := err.(*CaptureQueryError)
			if !ok {
				t.Fatalf("error is %T, want *CaptureQueryError: %v", err, err)
			}
			if !strings.Contains(parseErr.Message, tc.wantMessage) {
				t.Errorf("message mismatch\n got: %s\nwant to contain: %s", parseErr.Message, tc.wantMessage)
			}
			if parseErr.Position != tc.wantPos {
				t.Errorf("position mismatch: got %d, want %d (message: %s)",
					parseErr.Position, tc.wantPos, parseErr.Message)
			}
			// Every message has to name the position, because an operator staring at an empty list
			// needs to know where to look.
			if !strings.Contains(err.Error(), "at position") {
				t.Errorf("Error() does not name the position: %s", err.Error())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Sitemap and wire-format helpers
// ---------------------------------------------------------------------------

func TestReplayRequestSitemapTree(t *testing.T) {
	captures := []ReplayCaptureSummary{
		{Host: "a.com", Path: "/api/users"},
		{Host: "a.com", Path: "/api/users"},
		{Host: "a.com", Path: "/api/orders"},
		{Host: "a.com", Path: "/"},
		{Host: "b.com", Path: "/static/app.js"},
		{Host: "", Path: "/orphan"},
	}

	tree := buildReplaySitemap(captures)
	if len(tree) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(tree))
	}

	// Busiest host first.
	if tree[0].Host != "a.com" || tree[0].Count != 4 {
		t.Fatalf("root 0 = %+v, want a.com with count 4", tree[0])
	}
	if len(tree[0].Children) != 2 {
		t.Fatalf("a.com should have 2 children, got %d", len(tree[0].Children))
	}

	api := tree[0].Children[0]
	if api.Name != "api" || api.Path != "/api" || api.Count != 3 {
		t.Errorf("first child = %+v, want name api path /api count 3", api)
	}
	if len(api.Children) != 2 {
		t.Fatalf("/api should have 2 children, got %d", len(api.Children))
	}
	if api.Children[0].Name != "users" || api.Children[0].Count != 2 ||
		api.Children[0].Path != "/api/users" {
		t.Errorf("busiest leaf = %+v, want users /api/users count 2", api.Children[0])
	}

	// The root document is selectable rather than folded into the host.
	root := tree[0].Children[1]
	if root.Name != "/" || root.Path != "/" || root.Count != 1 {
		t.Errorf("root document node = %+v, want / with count 1", root)
	}

	// A capture with no parseable host still appears somewhere.
	var orphan *ReplaySitemapNode
	for _, node := range tree {
		if node.Host == "(no host)" {
			orphan = node
		}
	}
	if orphan == nil || orphan.Count != 1 {
		t.Errorf("a capture with no host should still get a root node, got %+v", orphan)
	}
}

func TestReplayRequestRawResponseWireFormat(t *testing.T) {
	raw := buildRawHTTPResponse(200, map[string][]string{
		"Content-Type": {"application/json"},
		"Set-Cookie":   {"a=1", "b=2"},
	}, `{"ok":true}`)

	want := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Set-Cookie: a=1\r\n" +
		"Set-Cookie: b=2\r\n" +
		"\r\n" +
		`{"ok":true}`
	if raw != want {
		t.Errorf("raw response mismatch\n got: %q\nwant: %q", raw, want)
	}

	// A transport failure has no status line to reconstruct.
	if got := buildRawHTTPResponse(0, nil, ""); got != "" {
		t.Errorf("a failed send should have no raw response, got %q", got)
	}

	// A response with no headers still has exactly one blank line before the body.
	if got := buildRawHTTPResponse(204, map[string][]string{}, ""); got != "HTTP/1.1 204 No Content\r\n\r\n" {
		t.Errorf("headerless response mismatch: %q", got)
	}
}

func TestReplayRequestRawModeFramingNote(t *testing.T) {
	// wantSays / wantNotSays assert what the note CLAIMS, not merely that one exists. A note is a
	// statement about bytes the operator cannot see, so a wrong one is acted on: it is read,
	// believed, and a real result gets thrown away. Every expectation below was checked against
	// what a listening socket actually received from this code path.
	cases := []struct {
		name        string
		raw         string
		wantNote    bool
		wantSays    []string
		wantNotSays []string
	}{
		{
			name:     "a consistent request says nothing",
			raw:      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
			wantNote: false,
		},
		{
			name:     "a GET with no body says nothing",
			raw:      "GET / HTTP/1.1\r\nHost: x\r\n\r\n",
			wantNote: false,
		},
		{
			// Verified on the wire: Content-Length: 5, body "short". The declared 999 is dropped.
			name:     "an over-declared Content-Length is corrected down, and says so",
			raw:      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 999\r\n\r\nshort",
			wantNote: true,
			wantSays: []string{"999", "5", "real length"},
		},
		{
			// Verified on the wire: Content-Length: 5, body "AAAAB". The declared 5 IS sent and the
			// remaining 15 bytes are dropped. The old note claimed the opposite.
			name:        "an under-declared Content-Length truncates the body, and says so",
			raw:         "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nAAAABBBBCCCCDDDDEEEE",
			wantNote:    true,
			wantSays:    []string{"truncated", "15 bytes"},
			wantNotSays: []string{"will not reach the target"},
		},
		{
			name:     "a CL.TE probe is called out",
			raw:      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
			wantNote: true,
			wantSays: []string{"chunked", "drops the Content-Length"},
		},
		{
			// Verified on the wire: the request left AS CHUNKS, with Transfer-Encoding: chunked
			// intact. The old note claimed it went out with a Content-Length instead, which would
			// have told an operator their valid chunked test had been neutered when it had not.
			name:        "chunked alone still leaves as chunks, and does not claim otherwise",
			raw:         "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
			wantNote:    true,
			wantSays:    []string{"Transfer-Encoding: chunked", "0-chunk"},
			wantNotSays: []string{"rather than as chunks", "will go out with a Content-Length"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			note := rawModeFramingNote(tc.raw)
			if tc.wantNote && note == "" {
				t.Fatalf("expected a note for:\n%q", tc.raw)
			}
			if !tc.wantNote && note != "" {
				t.Fatalf("unexpected note %q for:\n%q", note, tc.raw)
			}
			for _, want := range tc.wantSays {
				if !strings.Contains(note, want) {
					t.Errorf("note should mention %q but does not.\nnote: %s", want, note)
				}
			}
			for _, unwanted := range tc.wantNotSays {
				if strings.Contains(note, unwanted) {
					t.Errorf("note makes a claim the wire contradicts: %q\nnote: %s", unwanted, note)
				}
			}
		})
	}
}

// TestBuildRawHTTPRequestIsDeterministic pins the one property a repeater cannot do without.
//
// Ranging a Go map is deliberately randomised, so before this was sorted, twelve identical loads of
// one capture produced twelve different byte sequences. Nothing crashed; the operator simply could
// not diff two loads of the same request, and had no way to tell an edit they made from a reshuffle
// they did not. Regressing this would be silent, which is exactly why it is asserted.
func TestBuildRawHTTPRequestIsDeterministic(t *testing.T) {
	headers := map[string]interface{}{
		"cookie": "a=1; b=2", "user-agent": "probe/1", "accept": "*/*",
		"x-requested-with": "XMLHttpRequest", "referer": "https://example.com/",
		"origin": "https://example.com", "sec-fetch-mode": "cors", "dnt": "1",
		"accept-language": "en-US", "content-type": "application/json",
	}

	first := BuildRawHTTPRequest("POST", "https://example.com/v1/thing?q=1", headers, `{"a":1}`)
	for i := 0; i < 50; i++ {
		if got := BuildRawHTTPRequest("POST", "https://example.com/v1/thing?q=1", headers, `{"a":1}`); got != first {
			t.Fatalf("rendering %d differs from the first for identical input:\n--- first ---\n%s\n--- got ---\n%s",
				i, first, got)
		}
	}

	if !strings.HasPrefix(first, "POST /v1/thing?q=1 HTTP/1.1\r\nHost: example.com\r\n") {
		t.Errorf("request line or Host moved; got:\n%s", first)
	}
}
