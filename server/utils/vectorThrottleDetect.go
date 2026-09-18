package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Reading, out of a CONTAINERISED TOOL'S OWN OUTPUT, that the target refused it.
//
// vectorRateLimit.go watches the budget for the requests the FRAMEWORK makes, through ScanClient,
// and that covers everything routed through Go. It covers none of the work that matters: sqlmap,
// ghauri, dalfox, domdig, commix, lfimap and the rest run as `docker exec` into their own
// containers and open their own sockets. The framework never sees those requests, so when the
// target starts answering 429 partway through a vector the tool simply keeps going. A 429 body
// injects nothing and reflects nothing, so the tool finds nothing, exits 0, and the runner records
// the vector CLEAN. That is the fail-open this codebase keeps closing, arriving from the target
// instead of from a setting.
//
// MEASURED on a live estate, 2026-09-18: the authenticated API enforces a token bucket of roughly
// 200 burst refilling near 3.33/s, PER ENDPOINT, and one ghauri cookie vector spends about 1690
// requests. Any tool averaging above the refill drains the bucket mid-vector, and the remainder of
// that vector is answered by the rate limiter rather than by the application.
//
// WHY THIS IS SHARED RATHER THAN FIFTEEN COPIES OF A REGEX IN THE REGISTRY.
//
// tool.Incomplete is per tool because giving up is per tool: "Content type is not text/html" is a
// sentence only domdig says, and {"meta":{"incomplete":true}} is a shape only dalfox writes. Each
// one needs its own reader because each tool invented its own vocabulary for the same idea.
//
// A 429 is the opposite. It is a property of the TARGET, not of the tool, and it has exactly one
// vocabulary, HTTP's. Every tool here that speaks HTTP can be throttled, including the next one
// added, and a per-tool hook is fifteen chances to forget plus a sixteenth that starts blind.
// So the runner applies this to every tool's stdout, in addition to tool.Incomplete rather than
// instead of it: a tool that both stopped AND was throttled has its own reason reported with the
// throttle evidence appended, because "dalfox reported incomplete" and "lower the rate and re-run"
// are different instructions and the operator needs the second one.
//
// STDOUT ONLY, NOT THE REPORT FILE. The report is the tool's findings, and a 429 inside a finding
// is a fact ABOUT a request the tool chose to record, not a report that the run was throttled.
// Reading it would pull in every stored response body, which is where the quoted-status false
// positives live.
//
// THE FALSE POSITIVE PROBLEM RUNS THE OTHER WAY HERE, and it is the whole difficulty. Tool output
// quotes the target: a scanner that printed a payload containing 429, or a response body that
// reflected one, or a one line summary of the status codes it was told to ignore, has not been
// throttled. A rule that fires on a clean run is worse than no rule, because the operator learns to
// re-run vectors that were fine and then stops believing the label. Two things keep this honest.
//
//  1. DIGIT BOUNDARIES. Naive strings.Contains(out, "429") fires on 4 of the 574 stored traces and
//     3 of those 4 are wrong, all smugglex, all the same shape: "429" inside the nanosecond
//     fraction of an RFC3339 timestamp, "2026-09-07T00:44:31.723429961+00:00". Requiring the 429
//     not to be adjacent to another digit, and not to follow a decimal point, removes all three and
//     keeps the one true positive.
//  2. A THRESHOLD, because one mention is a mention. Being throttled is not a thing that happens
//     once to a tool spending hundreds of requests: it either prints a line per refused request, or
//     it prints one summary row with a count in it. Both of those clear the threshold and a lone
//     quoted number does not.
//
// VALIDATED against every stdout this framework has ever stored, 574 traces across 21 tools, on
// 2026-09-18. The rule below fires on ONE of them: a Forbidden run whose own status table reads
// "| 429 | 479 |" against 3412 requests, which is a genuinely throttled run that was recorded as a
// completed scan at the time. Zero other traces fire, including the three smugglex timestamps.
//
// WHAT THIS CANNOT SEE, AND IT IS MORE THAN THE PARAGRAPHS ABOVE IMPLY.
//
// A 429 has one vocabulary, but a rule over stdout can only read a tool that SPEAKS. Three of the
// tools this framework leans on hardest print nothing at all about a 429 at the flags this
// framework itself chooses, so for them the check below is dead code and their throttled runs are
// still recorded clean. Verified against the tools' own sources on 2026-09-18, not inferred:
//
//   sqlmap  (100 of 575 stored traces). lib/request/connect.py logs "got HTTP error code: 429
//           ('Too Many Requests')" through logger.debug, which needs -v 2 or higher. ComposeSqlmap
//           in sqliCompose.go appends "-v", "0" as a framework-owned argument, at which sqlmap
//           prints critical messages only. No 429 ever reaches stdout.
//   ghauri  (28 traces). Its "HTTP error code detected during run:" warning is behind
//           http_firewall_code_counter, and core/tests.py increments that ONLY for status 403 and
//           406. A 429 is parsed into Response.error and never printed at any verbosity.
//   dalfox  (44 traces). utils/http.rs retries every 429 and honours Retry-After, but the
//           "[retry] Status(429) -> waiting Nms" line is behind the DEBUG flag, and
//           ComposeDalfox does not pass --debug.
//
// So the claim this file may be read as making, that a shared check covers every tool because 429
// has one vocabulary, is WRONG AS STATED and is corrected here rather than in a commit message.
// Coverage is not a property of the rule, it is a property of what each tool was told to print.
// What actually carries those three is the control request either side of every vector in
// vectorRateLimit.go, which reads the target's own headers and needs no cooperation from the tool.
// This rule is the SECOND instrument, and it earns its place on the tools that do speak: Forbidden
// counts its status codes in a summary table, commix narrates the code it got, and every future
// tool added to the registry is covered without anyone remembering to write a hook.

// rateLimitEvidenceThreshold is how much evidence means "this run was throttled" rather than "this
// run mentioned a number". Three, and the weights below are chosen against it: one refused request
// is noise, one line where the tool NAMES the refusal is enough on its own, and a summary row
// carries however many the tool counted.
const rateLimitEvidenceThreshold = 3

// throttleEvidence is what was actually seen, kept as numbers so the reported reason can tell an
// operator how far through the run the target turned on them rather than just that it did.
type throttleEvidence struct {
	Weight int
	// Lines is how many output lines carried an observation, and Counted the largest number a
	// summary row attributed to 429. They are reported separately because they answer different
	// questions: Lines is how often the tool said it, Counted is how many requests it lost.
	Lines     int
	Counted   int
	FirstLine int
	TotalLine int
	Sample    string
}

// throttleCountRow matches a status summary row that is nothing but 429 and a count, which is how
// a tool reports a tally rather than an event. Forbidden v13.4 prints exactly this:
//
//	| 429           |     479 |
//
// The leading [^0-9]* is load bearing twice over: it anchors the row at the start of the line AND
// it guarantees the 429 has no digit before it, which Go's regexp cannot say with a lookbehind.
// Requiring a separator immediately after the 429 does the same job on the right. Deliberately
// strict about what may follow the count, so that a findings row like {"status":429,"length":1234}
// does NOT match and get scored 1234; that row is one refused request and falls through to the per
// line path below, worth 1.
var throttleCountRow = regexp.MustCompile(`^[^0-9]*429[ \t|:=]+([0-9]+)[ \t|]*$`)

// throttleFlagToken strips command line flags out of a line before it is searched for wording.
// `--rate-limit 5`, `-rl`, and `--ignore-code=429` are a tool describing its own configuration, not
// a target refusing it, and a usage block that echoes them must not read as an incident.
var throttleFlagToken = regexp.MustCompile(`(^|[\s"'(\[])--?[A-Za-z][A-Za-z0-9_-]*(=\S+)?`)

// throttleWords are the phrasings that mean a caller was refused for going too fast. Only consulted
// on output that ALSO carries a bare 429 somewhere, which is the gate that keeps a nuclei template
// named "rate-limit-bypass" or a wordlist entry from scoring: every HTTP client prints the status
// number, so wording with no number anywhere is the tool's own vocabulary rather than an
// observation.
var throttleWords = []string{
	"too many requests",
	"rate limit",
	"rate-limit",
	"ratelimit",
	"rate_limit",
	"retry-after",
	"retry after",
	"throttl",
	"slow down",
	"quota exceeded",
}

// throttleStatusPhrases are a tool's own PROSE about what the server answered. Next to a bare 429
// they are as good as the wording above, and they are needed because several tools report the
// number without ever using the word. Commix says exactly this, twice in the stored corpus with
// other codes in it:
//
//	[21:49:35] [warning] The web server responded with an HTTP error code '404', which could
//	interfere with the results of the tests.
//
// With '429' in that slot the run is throttled and nothing in the wording list would have caught
// it. Prose is the discriminator: a findings row like {"status":429} carries the number without a
// sentence around it and stays worth 1, which is what stops one refused response out of a thousand
// from marking a vector untested.
var throttleStatusPhrases = []string{
	"http error code",
	"error code",
	"status code",
	"response code",
	"responded with",
	"returned status",
	"got a",
}

// throttleConfigWords mark a line as the tool describing its own configuration. "ignoring status
// code 429" and a matcher list are the tool being told about a number, not the server sending one,
// and a configuration line scores nothing at all rather than 1: repeated it would otherwise reach
// the threshold on its own.
var throttleConfigWords = []string{"ignor", "filter", "matcher", "exclude", "usage:", "expect"}

// hasStatus429 reports whether a line carries 429 as a number in its own right.
//
// A digit on either side means it is part of a longer number, and a decimal point in front means it
// is the tail of a fraction; between them those two rejections are the difference between one hit
// and four across the stored corpus. A '.' AFTER is allowed, because "responded 429." is a
// sentence, not a float.
func hasStatus429(line string) bool {
	for i := 0; i+3 <= len(line); i++ {
		if line[i:i+3] != "429" {
			continue
		}
		if i > 0 && (isASCIIDigit(line[i-1]) || line[i-1] == '.') {
			continue
		}
		if i+3 < len(line) && isASCIIDigit(line[i+3]) {
			continue
		}
		return true
	}
	return false
}

func isASCIIDigit(b byte) bool { return b >= '0' && b <= '9' }

// namesTheRefusal reports whether a line says in words that the caller was refused, with the flags
// taken out first so a tool's own `--rate-limit` option cannot be read as an incident.
func namesTheRefusal(line string) bool {
	return containsAnyFold(throttleFlagToken.ReplaceAllString(line, " "), throttleWords)
}

// describesAStatus reports whether a line is prose about what the server answered, so that a bare
// 429 sitting in it can be read as an observation rather than as a number.
func describesAStatus(line string) bool {
	return containsAnyFold(throttleFlagToken.ReplaceAllString(line, " "), throttleStatusPhrases)
}

// describesConfiguration reports whether a line is the tool restating what it was told, which is
// never evidence of anything the target did.
func describesConfiguration(line string) bool {
	return containsAnyFold(line, throttleConfigWords)
}

func containsAnyFold(line string, words []string) bool {
	lower := strings.ToLower(line)
	for _, word := range words {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}

// observeThrottling scores the output. Exported behaviour lives in throttledByTarget; this is split
// out so the tests can assert on the numbers rather than on the wording of a sentence.
func observeThrottling(stdout string) throttleEvidence {
	ev := throttleEvidence{}
	if !strings.Contains(stdout, "429") {
		return ev
	}
	lines := strings.Split(stdout, "\n")
	ev.TotalLine = len(lines)

	// THE GATE. Wording alone never scores. A run where no line carries a bare 429 anywhere is a run
	// where nothing reported a status, and everything left is vocabulary: template names, wordlist
	// entries, help text, a header name in a request the tool echoed.
	sawStatus := false
	for _, line := range lines {
		if hasStatus429(line) {
			sawStatus = true
			break
		}
	}
	if !sawStatus {
		return ev
	}

	for i, line := range lines {
		weight := 0
		configuration := describesConfiguration(line)
		switch {
		case configuration && !throttleCountRow.MatchString(line):
			// The tool restating its own settings. Worth nothing, deliberately, rather than 1.
			weight = 0
		case throttleCountRow.MatchString(line):
			// A tally. The number IS the count of refused requests, so it is the weight: one row
			// saying 479 is 479 requests the application never saw.
			n, err := strconv.Atoi(throttleCountRow.FindStringSubmatch(line)[1])
			if err == nil && n > 0 {
				weight = n
				if n > ev.Counted {
					ev.Counted = n
				}
			}
		case hasStatus429(line) && (namesTheRefusal(line) || describesAStatus(line)):
			// The tool NAMED it: "got a 429 ('Too Many Requests') HTTP error code", or "responded
			// with an HTTP error code '429'". A payload echo or a findings row does not come with
			// the tool's own diagnosis wrapped around it, so one of these is enough on its own.
			weight = rateLimitEvidenceThreshold
		case hasStatus429(line):
			// One refused request, or one quoted number. Worth 1: it takes three to mean anything.
			weight = 1
		case namesTheRefusal(line):
			// Wording on a run that did report a 429 somewhere. Also worth 1, for the same reason.
			weight = 1
		}
		if weight == 0 {
			continue
		}
		ev.Weight += weight
		ev.Lines++
		if ev.FirstLine == 0 {
			ev.FirstLine = i + 1
			ev.Sample = strings.TrimSpace(line)
		}
	}
	return ev
}

// throttledByTarget reports, from a tool's stdout, that the TARGET was rate limiting it, and why
// that makes the vector untested. An empty return means no.
//
// NO FINDINGS ESCAPE HATCH, and that is the difference from domdigIncomplete, which stays quiet
// whenever a run produced findings. domdig's refusals are about ONE sub-resource and a crawl that
// still found a bug plainly worked. A 429 is about the requests that came after it, and finding a
// bug in the first third of a vector says nothing about the two thirds the rate limiter answered.
// Both results survive: the runner parses and keeps the findings, and stamps the vector untested.
func throttledByTarget(stdout string) string {
	ev := observeThrottling(stdout)
	if ev.Weight < rateLimitEvidenceThreshold {
		return ""
	}
	return fmt.Sprintf("the target rate limited this run (%s, first at line %d of %d: %q), so the "+
		"rest of this vector was answered by the rate limiter and not by the application; lower "+
		"this tool's request rate and re-run the vector.",
		throttleScale(ev), ev.FirstLine, ev.TotalLine, tailOf(ev.Sample))
}

// throttleScale says how much was seen in the terms the tool used, because "479 refused requests"
// and "6 refused responses" lead to the same action but very different confidence in it.
func throttleScale(ev throttleEvidence) string {
	if ev.Counted > 0 {
		return strconv.Itoa(ev.Counted) + " responses counted as 429 by the tool's own summary"
	}
	return strconv.Itoa(ev.Lines) + " output line(s) reporting a 429"
}
