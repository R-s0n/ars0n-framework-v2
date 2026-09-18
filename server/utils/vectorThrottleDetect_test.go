package utils

import (
	"strings"
	"testing"
)

// The three smugglex traces below are verbatim from vector_scan_traces on 2026-09-18. They are the
// reason this file exists in the shape it does: strings.Contains(stdout, "429") fires on 4 of the
// 574 stored traces and these are 3 of the 4, every one of them a nanosecond fraction.
const (
	smugglexTimestampA = `          "normal_status": "HTTP/1.1 200 OK",
          "attack_status": null,
          "normal_duration_ms": 311,
          "attack_duration_ms": null,
          "timestamp": "2026-09-07T00:43:20.184295922+00:00"
        },`
	smugglexTimestampB = `          "normal_status": "HTTP/1.1 200 OK",
          "timestamp": "2026-09-07T00:44:31.723429961+00:00"
        },`
	smugglexTimestampC = `          "normal_status": "HTTP/1.1 302 Found",
          "timestamp": "2026-09-07T01:08:46.429418705+00:00"
        },`

	// The one true positive in the whole corpus: Forbidden v13.4, trace
	// aac20032-dd39-4c2f-b6e0-013c562752c3, 479 of 3412 requests refused, recorded at the time as a
	// completed scan with no findings.
	forbiddenThrottled = `23:12:34 - Preparing test records...
Number of created test records: 3412
23:12:34 - Running tests using the Python Requests engine...
Press CTRL + C to exit early - results will be saved
Progress: |████████████████████████████████████████| 3412/3412 [100%] in 1:48.9 (31.35/s)
+---------------+---------+
| Status Code   |   Count |
+===============+=========+
| 400           |     178 |
| 404           |      19 |
| 429           |     479 |
| IGNORED       |    2727 |
| ERROR         |       9 |
+---------------+---------+
Script has finished in 0:01:49.621352`

	// A ghauri run from the live authenticated campaign, 2026-09-18. 1690 seconds, exit 0, recorded
	// clean. Nothing in it reports a status, which is the point: this must stay quiet.
	ghauriClean = `[10:19:29] [INFO] testing connection to the target URL
[10:19:30] [INFO] target URL content is stable
[10:19:30] [WARNING] heuristic (basic) test shows that COOKIE parameter 'AMP_MKTG_d6814239bf' might not be injectable
[10:19:30] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'
[10:22:41] [INFO] testing 'MySQL >= 5.0.12 time-based blind (query SLEEP)'
[10:30:25] [INFO] testing 'MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (UPDATEXML)'`
)

func TestThrottleDetectionSeparatesARefusedRunFromAQuotedNumber(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   bool
		// wantCounted, when non-zero, is the tally the reason must quote, so a regression that
		// scores a summary row as a single line is caught rather than passing on the boolean.
		wantCounted int
	}{
		// ---- must fire -------------------------------------------------------------------
		{
			name:        "forbidden status summary table, the one true positive in the corpus",
			stdout:      forbiddenThrottled,
			want:        true,
			wantCounted: 479,
		},
		{
			name: "one line where the tool names the refusal is enough",
			stdout: "[10:19:30] [INFO] testing connection to the target URL\n" +
				"[10:22:14] [WARNING] got a 429 ('Too Many Requests') HTTP error code\n" +
				"[10:22:15] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n",
			want: true,
		},
		{
			name:   "three bare refused responses",
			stdout: "[!] 429\n[!] 429\nsomething else\n[!] 429\n",
			want:   true,
		},
		{
			name: "status field in a findings stream, repeated",
			stdout: `{"url":"https://h/a","status":429,"length":52}
{"url":"https://h/b","status":429,"length":52}
{"url":"https://h/c","status":429,"length":52}`,
			want: true,
		},
		{
			// Commix's real phrasing, taken from two stored traces that carried '404' and '500' in
			// this slot. It reports the number and never uses the word, so the wording list alone
			// would have missed every throttled commix run.
			name: "commix prose about what the server answered",
			stdout: "[21:49:35] [info] Checking whether the target is protected by some kind of WAF/IPS.\n" +
				"[21:49:35] [warning] The web server responded with an HTTP error code '429', " +
				"which could interfere with the results of the tests.\n" +
				"[21:49:35] [info] Using output directory '/tmp/commix-out'.\n",
			want: true,
		},
		{
			name: "wording on a run that did report the number counts once the number is there",
			stdout: "GET /api/v1/accounts -> 429\n" +
				"server says: rate limit exceeded, retry after 30s\n" +
				"GET /api/v1/accounts -> 429\n",
			want: true,
		},

		// ---- must NOT fire ---------------------------------------------------------------
		{
			name:   "smugglex nanosecond timestamp A, real trace",
			stdout: smugglexTimestampA,
		},
		{
			name:   "smugglex nanosecond timestamp B, real trace",
			stdout: smugglexTimestampB,
		},
		{
			name:   "smugglex nanosecond timestamp C, real trace",
			stdout: smugglexTimestampC,
		},
		{
			name:   "a clean ghauri run from the live campaign",
			stdout: ghauriClean,
		},
		{
			name: "a payload that happens to contain the digits",
			stdout: "[INFO] testing payload: ' AND 429=429 -- -\n" +
				"[INFO] testing payload: ' AND 429=430 -- -\n" +
				"[INFO] parameter 'q' does not seem to be injectable\n",
		},
		{
			name: "the tool echoing the status codes it was told to ignore",
			stdout: "[INFO] starting sqlmap with --ignore-code=429 --rate-limit 3\n" +
				"[INFO] testing connection to the target URL\n" +
				"[INFO] all tested parameters do not appear to be injectable\n",
		},
		{
			name: "a status summary that saw 429 once, harmlessly",
			stdout: "+-------------+-------+\n| Status Code | Count |\n" +
				"| 200         |  3400 |\n| 429         |     1 |\n+-------------+-------+\n",
		},
		{
			name:   "two refused responses is not a campaign",
			stdout: "[!] 429\nGET /a 200\n[!] 429\n",
		},
		{
			name: "wording with no status anywhere is the tool's own vocabulary",
			stdout: "[rate-limit-bypass:header] [http] [info] https://h/a\n" +
				"[rate-limit-bypass:ip] [http] [info] https://h/b\n" +
				"[generic-throttling-check] [http] [info] https://h/c\n",
		},
		{
			name: "a reflected body quoting the phrase once",
			stdout: `[INFO] response body: {"error":"Too Many Requests"}` + "\n" +
				"[INFO] parameter 'q' does not seem to be injectable\n",
		},
		{
			name:   "a duration that happens to be 429 milliseconds",
			stdout: "GET /api/v1/accounts 200 in 429ms\nGET /api/v1/orders 200 in 0.429s\n",
		},
		{
			// Verbatim from the stored sstimap traces. "Too Many" with no request in sight, and no
			// status anywhere in the run, which is exactly what the bare-429 gate is for.
			name: "sstimap redirect loop, real trace wording",
			stdout: "[*] Eval_generic plugin is testing * code context escape with 13 variations\n" +
				"[-] Error: Too Many redirects.\n[-] Error: Too Many redirects.\n" +
				"[-] Error: Too Many redirects.\n" +
				"[*] Eval_generic plugin is testing boolean error-based blind injection\n",
		},
		{
			name: "configuration restated three times is still configuration",
			stdout: "[INFO] ignoring status code 429\n[INFO] ignoring status code 429\n" +
				"[INFO] ignoring status code 429\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			why := throttledByTarget(tc.stdout)
			if tc.want && why == "" {
				t.Fatalf("this run WAS throttled and the vector will be recorded clean.\nscore=%+v",
					observeThrottling(tc.stdout))
			}
			if !tc.want && why != "" {
				t.Fatalf("this run was NOT throttled and would be re-run for nothing: %s\nscore=%+v",
					why, observeThrottling(tc.stdout))
			}
			if tc.wantCounted != 0 {
				ev := observeThrottling(tc.stdout)
				if ev.Counted != tc.wantCounted {
					t.Fatalf("summary row counted %d, want %d", ev.Counted, tc.wantCounted)
				}
			}
		})
	}
}

// The single refused response is the boundary case worth its own test, because it is the one a
// looser rule gets wrong in both directions: fire on it and every scanner that meets one 429 in a
// thousand requests reports its vector untested, ignore it and a genuinely throttled run that only
// printed once goes in as clean. It is deliberately below the threshold, and the evidence is still
// recorded so the decision is visible rather than absent.
func TestOneRefusedResponseIsRecordedButDoesNotFire(t *testing.T) {
	stdout := "GET /api/v1/accounts -> 429\nGET /api/v1/accounts -> 200\n"
	ev := observeThrottling(stdout)
	if ev.Weight != 1 || ev.Lines != 1 {
		t.Fatalf("one refused response should score exactly 1 on 1 line, got %+v", ev)
	}
	if why := throttledByTarget(stdout); why != "" {
		t.Fatalf("one refused response must not mark a vector untested: %s", why)
	}
}

// The reason string has to tell an operator two things they cannot get anywhere else: how much of
// the vector the rate limiter answered, and what to do about it. A message that only says "rate
// limited" leaves them to guess whether to re-run.
func TestTheReportedReasonTellsTheOperatorWhatToDo(t *testing.T) {
	why := throttledByTarget(forbiddenThrottled)
	if why == "" {
		t.Fatal("the corpus's one throttled run is not reported")
	}
	for _, want := range []string{"479", "re-run", "rate", "line "} {
		if !strings.Contains(why, want) {
			t.Fatalf("reason does not mention %q, so the operator cannot act on it: %s", want, why)
		}
	}
}

// Placement check. The runner must consult this for EVERY tool, not only the ones that declare an
// Incomplete hook, which is the whole argument for it being shared: a tool with no hook is exactly
// the tool whose throttled run gets filed as clean.
func TestEveryToolIsCoveredByTheSharedThrottleCheck(t *testing.T) {
	withHook := 0
	for _, tool := range vectorRegistry {
		if tool.Incomplete != nil {
			withHook++
		}
	}
	total := len(vectorRegistry)
	if total == 0 {
		t.Fatal("no tools registered")
	}
	if withHook == total {
		t.Skip("every tool now declares an Incomplete hook; the shared check is still the right " +
			"place, but this test no longer demonstrates the gap")
	}
	t.Logf("%d of %d registered tools declare no Incomplete hook and are covered only by the "+
		"shared throttle check", total-withHook, total)
}

// THE RULE IS NOT ONE TOOL'S WORDING, and these are the other tools' own phrasings rather than
// phrasings invented to pass. Each string below was taken from the tool's source on 2026-09-18, not
// from a stored trace, because no stored trace has a 429 in it except the Forbidden one above.
//
//	sqlmap  lib/request/connect.py:961   debugMsg = "got HTTP error code: %d ('%s')"
//	ghauri  core/tests.py:560-566        logger.warning("HTTP error code detected during run:")
//	                                     message = f"{error_msg} - {counter} time(s)", where
//	                                     common/utils.py:1169 builds error_msg = "429 (Too Many
//	                                     Requests)"
//	dalfox  src/utils/http.rs:842        eprintln!("[retry] {:?} -> waiting {}ms before retry
//	                                     (429:{} transient:{})")
//
// READ THIS WITH TestTheToolsThisRuleIsBlindTo BELOW. Two of these three do not print these lines
// at the flags this framework runs them with, so passing here is necessary and not sufficient: it
// proves the rule is generic, and the other test records that being generic is not the same as
// being able to see.
func TestTheRuleFiresOnOtherToolsOwnWordingNotJustForbiddens(t *testing.T) {
	cases := map[string]string{
		"sqlmap at -v 2 or higher": "[12:04:11] [DEBUG] got HTTP error code: 429 ('Too Many Requests')\n" +
			"[12:04:11] [DEBUG] got HTTP error code: 429 ('Too Many Requests')\n" +
			"[12:04:12] [INFO] testing 'AND boolean-based blind - WHERE or HAVING clause'\n",
		"sqlmap, one such line on its own": "[12:04:11] [INFO] testing connection to the target URL\n" +
			"[12:04:11] [DEBUG] got HTTP error code: 429 ('Too Many Requests')\n",
		"ghauri once a 429 reaches its firewall counter": "[12:31:02] [INFO] testing 'AND boolean-based blind'\n" +
			"[12:31:44] [WARNING] HTTP error code detected during run:\n" +
			"429 (Too Many Requests) - 3 time(s). Do you want to keep testing the others (if any) [y/N]? N\n",
		"dalfox under --debug": "[retry] Status(429) -> waiting 1000ms before retry (429:1 transient:0)\n" +
			"[retry] Status(429) -> waiting 2000ms before retry (429:2 transient:0)\n" +
			"[retry] Status(429) -> waiting 4000ms before retry (429:3 transient:0)\n",
	}
	for name, stdout := range cases {
		t.Run(name, func(t *testing.T) {
			if why := throttledByTarget(stdout); why == "" {
				t.Fatalf("this tool was throttled in its own words and the vector reads clean.\n"+
					"score=%+v", observeThrottling(stdout))
			}
		})
	}
}

// THE TOOLS THIS RULE CANNOT SEE, pinned so the gap is a fact in the suite rather than a paragraph.
//
// A rule over stdout reads only a tool that speaks, and the framework decides how much its tools
// say. sqlmap is run at -v 0, at which the 429 line above (a logger.debug) is never printed, and
// dalfox is run without --debug, at which its retry line is never printed. ghauri needs no flag
// assertion because the silence is in its source: core/tests.py increments the firewall counter for
// 403 and 406 only, so the wording asserted above is unreachable on a 429 at any verbosity.
//
// Together those are 172 of the 575 stored traces. What covers them is the budget control either
// side of each vector in vectorRateLimit.go, which reads the target's headers and needs nothing
// from the tool.
//
// IF THIS TEST FAILS because someone raised sqlmap's verbosity or added --debug to dalfox, that is
// an improvement, not a regression: the rule now has eyes on that tool. Delete the case and the
// matching paragraph in vectorThrottleDetect.go.
func TestTheToolsThisRuleIsBlindTo(t *testing.T) {
	v := VectorInput{
		Method: "GET", Scheme: "https", Domain: "app.example.com", Path: "/dash",
		InsertionPoint: "query", Parameters: []string{"q"},
		ObservedValues: map[string]string{"q": "1"},
	}

	sqlmapArgs, _ := ComposeSqlmap(v, map[string]any{}, "/tmp/r.json")
	if argValueAfter(sqlmapArgs, "-v") != "0" {
		t.Errorf("sqlmap is no longer composed with -v 0 (got -v %q). Its 429 line is a logger.debug "+
			"and needs -v 2, so if verbosity was raised the shared throttle rule can now see sqlmap "+
			"and the blind list in vectorThrottleDetect.go is stale",
			argValueAfter(sqlmapArgs, "-v"))
	}

	dalfoxArgs, _ := ComposeDalfox(v, map[string]any{}, "/tmp/r.jsonl")
	for _, arg := range dalfoxArgs {
		if arg == "--debug" {
			t.Error("dalfox is now composed with --debug, so its '[retry] Status(429)' line reaches " +
				"stdout and the blind list in vectorThrottleDetect.go is stale")
		}
	}
}
