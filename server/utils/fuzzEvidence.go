package utils

import (
	"context"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The bytes ffuf actually sent and received, read back off disk and attached to the finding they
// belong to.
//
// ffuf's -od writes one file per MATCHED result into a directory. Verified against 2.2.1 in this
// composer's own mode: the file holds the request ffuf really sent, including the User-Agent and
// Accept-Encoding it adds itself and the header-name casing it normalises, then a separator line,
// then the complete response with its status line, headers and body.
//
// That capture is worth more than the reconstruction fuzzFindingDetail.go does from the step
// template, for two reasons beyond the response body. It is what ffuf sent rather than what the
// framework believes ffuf sent. And for a sniper step it is the ONLY way to know which position was
// fuzzed, because ffuf's JSON reports every sniper hit under the single keyword FUZZ with the same
// URL, so two genuinely different requests are otherwise indistinguishable.

const (
	// Caps, because a matched response can be megabytes and findings accumulate forever. The head is
	// where the status line, the headers and the beginning of the body live, which is what triage
	// needs; the full length is recorded alongside so a truncation is never silent.
	fuzzEvidenceRequestCap  = 16 * 1024
	fuzzEvidenceResponseCap = 64 * 1024
)

// fuzzEvidenceSeparator matches the line ffuf writes between the request and the response. Matched
// loosely rather than on the exact "---- ↑ Request ---- Response ↓ ----" string, because that line
// carries U+2191 and U+2193 and pinning the arrows makes the parser fail on an encoding change
// rather than on a format change.
var fuzzEvidenceSeparator = regexp.MustCompile(`(?m)^-{3,}.*Request.*Response.*-{3,}\r?$`)

// capturedExchange is one -od file, parsed.
type capturedExchange struct {
	Request  string
	Response string
}

// resultFileName is ffuf's own name for the evidence file: the md5 of the file's contents, which it
// reports back in the JSON report as `resultfile`. Validated before it is joined to a path because
// the report arrives from a /tmp volume shared with every tool container.
var resultFileName = regexp.MustCompile(`^[0-9a-f]{32}$`)

// readExchangeFile returns the bytes ffuf recorded for one result.
//
// The mapping needs no guesswork: ffuf sets resp.ResultFile to the file it just wrote and carries it
// into the json output as `resultfile` (pkg/output/stdout.go Result, pkg/ffuf/interfaces.go). Matching
// on url and payload instead would be a heuristic, and it would be ambiguous for exactly the steps
// that need evidence most, where every request goes to the same url and only a header, a cookie or a
// body value differs.
//
// Errors are swallowed: evidence is an attachment to a finding, and a missing or malformed capture
// must never cost the finding itself.
func readExchangeFile(dir, resultFile string) *capturedExchange {
	if dir == "" || !resultFileName.MatchString(resultFile) {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(dir, resultFile))
	if err != nil || len(data) == 0 {
		return nil
	}
	text := string(data)
	loc := fuzzEvidenceSeparator.FindStringIndex(text)
	if loc == nil {
		return nil
	}
	return &capturedExchange{
		Request:  strings.TrimRight(text[:loc[0]], "\r\n"),
		Response: strings.TrimLeft(text[loc[1]:], "\r\n"),
	}
}

// storeFuzzEvidence records one exchange against a finding, replacing whatever an earlier run left.
//
// Both halves are sanitised before they are stored. These are RAW WIRE BYTES, so a matched response
// is routinely something Postgres will not accept in a text column: a favicon, a zip, a PDF, an
// undecoded compressed body. Postgres rejects a NUL outright ("invalid byte sequence for encoding
// UTF8: 0x00") and rejects an invalid sequence the same way, and the whole INSERT dies with it. The
// error used to be discarded as well, so the row simply never appeared and the detail view then told
// the operator the bytes had never been captured, which is a different and untrue statement.
func storeFuzzEvidence(ctx context.Context, findingID, runID string, ex *capturedExchange) {
	if ex == nil || findingID == "" {
		return
	}
	req, reqTruncated := clipEvidence(ex.Request, fuzzEvidenceRequestCap)
	resp, respTruncated := clipEvidence(ex.Response, fuzzEvidenceResponseCap)
	_, err := dbPool.Exec(ctx, `
		INSERT INTO fuzz_finding_evidence
		    (finding_id, run_id, request_bytes, response_bytes, response_total_bytes, truncated,
		     request_total_bytes, request_truncated, captured_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
		ON CONFLICT (finding_id) DO UPDATE
		SET run_id = EXCLUDED.run_id,
		    request_bytes = EXCLUDED.request_bytes,
		    response_bytes = EXCLUDED.response_bytes,
		    response_total_bytes = EXCLUDED.response_total_bytes,
		    truncated = EXCLUDED.truncated,
		    request_total_bytes = EXCLUDED.request_total_bytes,
		    request_truncated = EXCLUDED.request_truncated,
		    captured_at = NOW()`,
		findingID, nullIfEmpty(runID),
		sanitizeForTextColumn(req), sanitizeForTextColumn(resp),
		len(ex.Response), respTruncated, len(ex.Request), reqTruncated)
	if err != nil {
		// Loud, because the visible symptom is a finding that claims nothing was ever captured.
		log.Printf("[WARN] fuzz evidence not stored for finding %s: %v", findingID, err)
	}
}

// clipEvidence shortens to a cap without splitting a character.
//
// Slicing on a raw byte offset is what makes truncation destroy the record instead of shortening it:
// a cut landing inside a multi-byte sequence leaves an invalid string, Postgres refuses the whole
// row, and the finding ends up with no evidence at all rather than with its first 64KB.
func clipEvidence(s string, limit int) (string, bool) {
	if len(s) <= limit {
		return s, false
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// attributeSniperPosition works out WHICH marked position a sniper hit came from, by looking at the
// bytes that were actually sent.
//
// This cannot be answered from ffuf's report. Measured against 2.2.1 with two positions and a two
// word list: all four results carry url unchanged and input {"FUZZ": <word>}, and the `position`
// field is the index of the word in the wordlist, not the index of the section mark. Two different
// requests, {"a":"restA","b":"is_admin"} and {"a":"is_admin","b":"restB"}, therefore report
// identically and collapse into one finding.
//
// The captured request distinguishes them, so this reconstructs what each candidate would have
// looked like on the wire and asks which one was actually sent. The unit of comparison is the single
// LINE the token sits on: ffuf rewrites the headers around it (adding User-Agent, Content-Length and
// Accept-Encoding, and canonicalising header names) but never edits the line itself, so a whole
// request cannot be compared byte for byte while one line can.
//
// Line endings are normalised on both sides first. The template is stored with \n and ffuf sends
// \r\n, and an earlier revision compared a fixed window of preceding bytes that happened to span the
// blank line before the body: neither position matched, and all four results collapsed back into
// two. That is why the comparison is anchored to a line rather than a byte window.
//
// Returns "" when it cannot be decided, and the caller must then not pretend to know.
func attributeSniperPosition(step FuzzStep, request, payload string) string {
	if payload == "" || request == "" || len(step.Positions) == 0 {
		return ""
	}
	// One marked position is not a puzzle: there is nowhere else the payload could have gone. Without
	// this the finding keeps ffuf's own keyword as its position and the detail view renders the raw
	// {{p01}} marker instead of the value.
	if len(step.Positions) == 1 {
		return step.Positions[0].Token
	}

	sentLines := strings.Split(strings.ReplaceAll(request, "\r\n", "\n"), "\n")

	// Each candidate is the line its position sits on, split at the payload site. Matching on the
	// surrounding text rather than on the whole rendered line is what makes this survive ffuf
	// re-encoding the payload: a path payload containing a space is sent as %20, so the line never
	// compares equal while the text either side of it still does.
	type candidate struct{ token, before, after string }
	var candidates []candidate
	for _, p := range step.Positions {
		idx := strings.Index(step.RawRequest, p.Token)
		if idx < 0 {
			continue
		}
		rest := func(text string) string {
			for _, other := range step.Positions {
				text = strings.ReplaceAll(text, other.Token, other.RestingValue)
			}
			return strings.ReplaceAll(text, "\r\n", "\n")
		}
		head := rest(step.RawRequest[:idx])
		tail := rest(step.RawRequest[idx+len(p.Token):])
		before := head
		if at := strings.LastIndex(head, "\n"); at >= 0 {
			before = head[at+1:]
		}
		after := tail
		if at := strings.Index(tail, "\n"); at >= 0 {
			after = tail[:at]
		}
		// A position occupying its whole line has nothing to anchor against and would match anything.
		if before == "" && after == "" {
			continue
		}
		candidates = append(candidates, candidate{token: p.Token, before: before, after: after})
	}

	// Both comparisons run over every candidate together. Consulting the exact pass alone first was a
	// bias, not a preference: a raw request pasted from a browser has lowercase header names and ffuf
	// canonicalises them, so a header position ALWAYS needs folding while a body or path position
	// never does, and the body candidate won every time regardless of which slot was really filled.
	fits := func(line, before, after string, fold bool) bool {
		line = strings.TrimSuffix(line, "\r")
		if len(line) < len(before)+len(after) {
			return false
		}
		head, tail := line[:len(before)], line[len(line)-len(after):]
		if fold {
			head, tail = strings.ToLower(head), strings.ToLower(tail)
			if head != strings.ToLower(before) || tail != strings.ToLower(after) {
				return false
			}
		} else if head != before || tail != after {
			return false
		}
		// The surrounding text alone does not identify the position. When the payload sits at the end
		// of a line the trailing anchor is empty, so every position whose leading text appears would
		// match and two candidates would look equally good. What settles it is the value at the site:
		// the position that carried the payload holds the payload, the others hold resting values.
		middle := line[len(before) : len(line)-len(after)]
		if middle == payload {
			return true
		}
		// ffuf re-encodes a payload that lands in the URL: a wordlist entry with a trailing space is
		// sent as %20, so the bytes never compare equal to the word that produced them.
		if v, err := url.PathUnescape(middle); err == nil && v == payload {
			return true
		}
		v, err := url.QueryUnescape(middle)
		return err == nil && v == payload
	}

	var found string
	for _, c := range candidates {
		matched := false
		for _, line := range sentLines {
			if fits(line, c.before, c.after, false) || fits(line, c.before, c.after, true) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if found != "" && found != c.token {
			return "" // two positions are indistinguishable in these bytes, so neither can be claimed
		}
		found = c.token
	}
	return found
}
