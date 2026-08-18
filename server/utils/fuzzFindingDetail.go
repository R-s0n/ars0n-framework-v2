package utils

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
)

// One finding, expanded into the request that produced it and the place the payload landed.
//
// A row of url, status and size cannot be acted on. The operator's next move is always to replay the
// request by hand, and to do that they need the bytes: the method, every header the step carried, the
// body if there was one, and WHERE in all of that the payload was substituted. That last part is the
// one a table can never show, because "position {{p01}}" means nothing without the text around it.
//
// The request is RECONSTRUCTED from the step's stored template plus the payload recorded on the
// finding, not read back from the wire. ffuf writes request and response bytes only when -od or
// -audit-log is set, which this framework does not set, so reconstruction is the honest best
// available and the response side is limited to the metrics ffuf reports. Both facts are stated in
// the payload rather than left for the operator to discover.

// fuzzRequestPart is one span of the reconstructed request. Splitting rather than marking up means the
// client decides how to render an injected span, and a payload containing HTML cannot break the view.
type fuzzRequestPart struct {
	Text     string `json:"text"`
	Injected bool   `json:"injected,omitempty"`
	Token    string `json:"token,omitempty"`
	Role     string `json:"role,omitempty"`
	// Carried marks the position that actually held this finding's payload. Every position carries one
	// in clusterbomb and pitchfork, but sniper fills exactly one per request and leaves the rest at
	// their resting values, and highlighting all of them identically says the request was something it
	// was not.
	Carried bool `json:"carried,omitempty"`
}

// GetFuzzFindingDetail answers GET /fuzz/findings/{finding_id}.
func GetFuzzFindingDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	findingID := mux.Vars(r)["finding_id"]
	ctx := context.Background()

	var (
		stepID, runID           *string
		url, method, payload    string
		positionToken, ctype    string
		redirect, triage, notes string
		status, words, lines    int
		size                    int64
		timesSeen               int
	)
	err := dbPool.QueryRow(ctx, `
		SELECT step_id, first_seen_run_id, url, COALESCE(method,''), COALESCE(payload,''),
		       COALESCE(position_token,''), COALESCE(content_type,''),
		       COALESCE(redirect_location,''), triage, COALESCE(notes,''),
		       COALESCE(http_status,0), COALESCE(response_words,0), COALESCE(response_lines,0),
		       COALESCE(response_size,0), times_seen
		FROM fuzz_findings WHERE id = $1`, findingID).
		Scan(&stepID, &runID, &url, &method, &payload, &positionToken, &ctype, &redirect,
			&triage, &notes, &status, &words, &lines, &size, &timesSeen)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "not_found", "finding not found")
		return
	}

	out := map[string]interface{}{
		"id": findingID, "url": url, "method": method, "payload": payload,
		"position_token": positionToken, "triage": triage, "times_seen": timesSeen,
		"response": map[string]interface{}{
			"http_status": status, "size": size, "words": words, "lines": lines,
			"content_type": ctype, "redirect_location": redirect,
		},
	}
	if notes != "" {
		out["notes"] = notes
	}

	// The bytes ffuf actually sent and received, when the run captured them. This is better evidence
	// than the reconstruction below in every respect: it is what went on the wire rather than what the
	// framework believes went on the wire, and it is the only thing that carries a response body.
	var evReq, evResp string
	var evTotal, evReqTotal int64
	var evTruncated, evReqTruncated, evStale bool
	var evAt *string
	if dbPool.QueryRow(ctx, `
		SELECT e.request_bytes, e.response_bytes, e.response_total_bytes, e.truncated,
		       COALESCE(e.request_total_bytes,0), COALESCE(e.request_truncated,false),
		       e.captured_at::text,
		       (f.last_seen_run_id IS NOT NULL AND e.run_id IS DISTINCT FROM f.last_seen_run_id)
		FROM fuzz_finding_evidence e
		JOIN fuzz_findings f ON f.id = e.finding_id
		WHERE e.finding_id = $1`, findingID).
		Scan(&evReq, &evResp, &evTotal, &evTruncated, &evReqTotal, &evReqTruncated, &evAt,
			&evStale) == nil && (evReq != "" || evResp != "") {
		ev := map[string]interface{}{
			"request":             evReq,
			"response":            evResp,
			"truncated":           evTruncated,
			"total_bytes":         evTotal,
			"request_truncated":   evReqTruncated,
			"request_total_bytes": evReqTotal,
			"stale":               evStale,
		}
		if evAt != nil {
			ev["captured_at"] = *evAt
		}
		notes := []string{}
		if evTruncated {
			notes = append(notes, fmt.Sprintf(
				"The response was %d bytes and the first %d are stored. Replay the request to see all of it.",
				evTotal, len(evResp)))
		}
		if evReqTruncated {
			notes = append(notes, fmt.Sprintf(
				"The request was %d bytes and the first %d are stored, so its tail is missing.",
				evReqTotal, len(evReq)))
		}
		// Numbers on the row come from the most recent run; these bytes may not. That happens when a
		// later run re-observed the finding without capturing (capture switched off, or the capture
		// could not be stored), and showing an old body under a new status silently misattributes it.
		if evStale {
			notes = append(notes, "These bytes were captured by an EARLIER run than the one that last "+
				"saw this finding, so they may not match the status and size shown above. Re-run the "+
				"step with capture on to refresh them.")
		}
		if len(notes) > 0 {
			ev["note"] = strings.Join(notes, " ")
		}
		out["evidence"] = ev
	} else {
		// Said plainly, because an operator looking for a response body needs to know it was never
		// captured rather than assume the finding is incomplete.
		out["response_note"] = "No bytes were captured for this finding, so the request below is " +
			"reconstructed from the step and there is no response body to show. Capture is on by " +
			"default for new runs; findings stored before it existed have none. Re-run the step to " +
			"record the real exchange."
	}

	// The control this finding is read against: the same request carrying a value that cannot exist.
	// Returned whole, bytes included, because the comparison an operator actually makes is between two
	// responses rather than between two numbers.
	var bStatus, bWords, bLines int
	var bSize, bTotal int64
	var bReq, bResp, bType, bPosition string
	var bTruncated bool
	var bAt *string
	if dbPool.QueryRow(ctx, `
		SELECT COALESCE(b.http_status,0), COALESCE(b.response_size,0), COALESCE(b.response_words,0),
		       COALESCE(b.response_lines,0), COALESCE(b.content_type,''), COALESCE(b.position_token,''),
		       b.request_bytes, b.response_bytes, COALESCE(b.response_total_bytes,0), b.truncated,
		       b.captured_at::text
		FROM fuzz_baselines b
		JOIN fuzz_findings f ON f.baseline_id = b.id
		WHERE f.id = $1`, findingID).
		Scan(&bStatus, &bSize, &bWords, &bLines, &bType, &bPosition, &bReq, &bResp, &bTotal,
			&bTruncated, &bAt) == nil {
		baseline := map[string]interface{}{
			"canary":         FuzzCanaryValue,
			"http_status":    bStatus,
			"response_size":  bSize,
			"response_words": bWords,
			"response_lines": bLines,
			"content_type":   bType,
			"request":        bReq,
			"response":       bResp,
			"truncated":      bTruncated,
			"total_bytes":    bTotal,
			"position_token": bPosition,
		}
		if bAt != nil {
			baseline["captured_at"] = *bAt
		}
		// The judgement, stated rather than left as an exercise. Two numbers side by side still need
		// reading; this says what they amount to.
		//
		// SIZE ALONE IS NOT ENOUGH, and reading it alone gets this exactly backwards on the most
		// common wall there is. A 404 whose body echoes the path it was asked for returns a different
		// LENGTH for every payload while its word and line counts never move: measured on a live host,
		// 61 findings, 61 different sizes, one word count, all of them the same catch-all. Comparing
		// sizes called 56 of those 61 real. Comparing shape calls all 61 what they are.
		// The verdict itself comes from the one shared rule; what follows only chooses how to say it.
		verdict := baselineVerdict(status, size, words, lines, bStatus, bSize, bWords, bLines)
		sameShape := bStatus == status && bWords == words && bLines == lines
		// Better still when it can be proved: if the length differs by exactly the length the payload
		// itself differs by, the body is echoing the payload and nothing else changed.
		delta := size - bSize
		payloadDelta := int64(len(fuzzPayloadWord(payload)) - len(FuzzCanaryValue))

		switch {
		case bStatus == status && bSize == size:
			baseline["verdict"] = verdict
			baseline["note"] = fmt.Sprintf(
				"A value that cannot exist (%s) gets the SAME answer: %d, %d bytes. This endpoint is "+
					"not distinguishing the payload, so this row is the target's catch-all rather than "+
					"a discovery.", FuzzCanaryValue, bStatus, bSize)
		case sameShape && delta == payloadDelta:
			baseline["verdict"] = verdict
			baseline["note"] = fmt.Sprintf(
				"The canary (%s) gets the same %d with the same %d words and %d lines, and the %d byte "+
					"difference is exactly the difference in payload length: this response is echoing "+
					"what was asked for. Same answer, not a discovery.",
				FuzzCanaryValue, bStatus, bWords, bLines, delta)
		case sameShape:
			baseline["verdict"] = verdict
			baseline["note"] = fmt.Sprintf(
				"The canary (%s) gets the same %d with the same %d words and %d lines, so this is one "+
					"response whose length moves with the payload rather than a different response. "+
					"Byte length alone would have called this a discovery.",
				FuzzCanaryValue, bStatus, bWords, bLines)
		case bStatus != status:
			baseline["verdict"] = verdict
			baseline["note"] = fmt.Sprintf(
				"The canary (%s) answers %d where this payload answers %d, so the endpoint is treating "+
					"them differently.", FuzzCanaryValue, bStatus, status)
		default:
			baseline["verdict"] = verdict
			baseline["note"] = fmt.Sprintf(
				"Same status, but the canary (%s) comes back with %d words and %d lines against this "+
					"payload's %d and %d, so the response itself is different rather than just longer.",
				FuzzCanaryValue, bWords, bLines, words, lines)
		}
		out["baseline"] = baseline
	} else {
		out["baseline_note"] = "No baseline has been taken for this finding yet. Re-run the flow: the " +
			"last phase of a run sends the same request with " + FuzzCanaryValue + " in place of the " +
			"payload, so a finding can be compared against a value that cannot exist."
	}

	// The step is what holds the request template and the position roles.
	if stepID == nil {
		out["request_note"] = "The step that produced this finding has been deleted, so the request " +
			"cannot be reconstructed. The URL above is what ffuf reported."
		json.NewEncoder(w).Encode(out)
		return
	}
	step, err := loadFuzzStep(ctx, *stepID)
	if err != nil {
		out["request_note"] = "The step that produced this finding could not be loaded."
		json.NewEncoder(w).Encode(out)
		return
	}

	values := parseFuzzPayload(payload, step.Positions)

	// Sniper fills ONE marked position per request and leaves the others at their resting values, and
	// ffuf reports every one of them under the same keyword, so the payload map cannot say which slot
	// was live. The slot recorded on the finding can, and without applying it here both positions
	// render as injected and the request on screen is not the request that was sent.
	carried := map[string]bool{}
	sniper := strings.EqualFold(step.FFUFMode, "sniper")
	switch {
	case !sniper:
		for _, p := range step.Positions {
			carried[p.Token] = true
		}
	case fuzzStepHasToken(step, positionToken):
		live := payload
		if _, after, ok := strings.Cut(payload, "="); ok {
			live = after
		}
		for _, p := range step.Positions {
			kw := keywordForToken(p.Token)
			if p.Token == positionToken {
				values[kw], carried[p.Token] = live, true
			} else {
				values[kw] = p.RestingValue
			}
		}
	default:
		out["position_note"] = "Which position carried the payload was not established for this " +
			"finding, so every marked position is shown holding its marker. ffuf reports one keyword " +
			"for all sniper slots, and the answer only survives in the bytes that were sent."
	}

	roleFor := map[string]string{}
	positions := []map[string]interface{}{}
	for _, p := range step.Positions {
		kw := keywordForToken(p.Token)
		roleFor[p.Token] = p.Role
		where := describeFuzzRole(p.Role)
		if sniper && len(carried) > 0 && !carried[p.Token] {
			where = "held at its resting value for this request, not fuzzed"
		}
		positions = append(positions, map[string]interface{}{
			"token": p.Token, "keyword": kw, "role": p.Role,
			"value": values[kw], "wordlist": p.Wordlist,
			"resting_value": p.RestingValue, "encoder": p.Encoder,
			"where": where, "carried": carried[p.Token],
		})
	}

	parts, rendered := renderFuzzFindingRequest(step, values, roleFor, carried)
	out["step"] = map[string]interface{}{
		"id": step.ID, "ordinal": step.Ordinal, "name": step.Name, "host": step.TargetHost,
		"scheme": step.Scheme, "ffuf_mode": step.FFUFMode, "enabled": step.Enabled,
		"options": step.Options,
	}
	out["positions"] = positions
	out["request_parts"] = parts
	out["request"] = rendered
	out["curl"] = curlForFuzzRequest(step.Scheme, rendered)

	// The command that produced this row, for reproduction and for checking which filters were in
	// force at the time, which the step's current options do not tell you.
	if runID != nil {
		var command, detail string
		if dbPool.QueryRow(ctx, `
			SELECT COALESCE(command,''), COALESCE(detail,'') FROM fuzz_step_runs
			WHERE run_id = $1 AND step_id = $2 LIMIT 1`, *runID, *stepID).
			Scan(&command, &detail) == nil {
			if command != "" {
				out["command"] = command
			}
			if detail != "" {
				out["run_detail"] = detail
			}
		}
	}

	json.NewEncoder(w).Encode(out)
}

// parseFuzzPayload turns "FUZZP01=admin&FUZZP02=1" back into keyword to value.
//
// Split on the keyword markers rather than on "&", because a payload from a wordlist can contain both
// "&" and "=" and naive splitting would truncate it. builtin-large ships 114 entries containing "?"
// and 41 containing "&".
func parseFuzzPayload(payload string, positions []FuzzPosition) map[string]string {
	out := map[string]string{}
	if payload == "" {
		return out
	}

	type marker struct {
		keyword string
		at      int
	}
	var markers []marker
	for _, p := range positions {
		kw := keywordForToken(p.Token)
		if at := strings.Index(payload, kw+"="); at == 0 || (at > 0 && payload[at-1] == '&') {
			markers = append(markers, marker{kw, at})
		}
	}
	// Document order, so each value runs to the start of the next marker.
	for i := 0; i < len(markers); i++ {
		for j := i + 1; j < len(markers); j++ {
			if markers[j].at < markers[i].at {
				markers[i], markers[j] = markers[j], markers[i]
			}
		}
	}
	for i, m := range markers {
		start := m.at + len(m.keyword) + 1
		end := len(payload)
		if i+1 < len(markers) {
			end = markers[i+1].at
			if end > 0 && payload[end-1] == '&' {
				end--
			}
		}
		if start <= end && end <= len(payload) {
			out[m.keyword] = payload[start:end]
		}
	}
	// A single unnamed position, or a payload ffuf reported under a keyword this step no longer has.
	if len(out) == 0 {
		if k, v, ok := strings.Cut(payload, "="); ok {
			out[k] = v
		}
	}
	return out
}

// fuzzStepHasToken reports whether a recorded position token still names a position on the step. It
// is false for findings stored before attribution worked, which carry ffuf's keyword instead.
func fuzzStepHasToken(step FuzzStep, token string) bool {
	if token == "" {
		return false
	}
	for _, p := range step.Positions {
		if p.Token == token {
			return true
		}
	}
	return false
}

// renderFuzzFindingRequest substitutes the recorded payloads into the step's template and returns the
// result split into injected and untouched spans.
func renderFuzzFindingRequest(step FuzzStep, values map[string]string,
	roleFor map[string]string, carried map[string]bool) ([]fuzzRequestPart, string) {

	raw := step.RawRequest
	parts := []fuzzRequestPart{}
	var rendered strings.Builder

	idx := 0
	for _, loc := range fuzzTokenRe.FindAllStringIndex(raw, -1) {
		if loc[0] > idx {
			text := raw[idx:loc[0]]
			parts = append(parts, fuzzRequestPart{Text: text})
			rendered.WriteString(text)
		}
		token := raw[loc[0]:loc[1]]
		value, ok := values[keywordForToken(token)]
		if !ok {
			// No payload recorded for this position: show the marker rather than inventing a value.
			value = token
		}
		parts = append(parts, fuzzRequestPart{
			Text: value, Injected: true, Token: token, Role: roleFor[token],
			Carried: carried[token],
		})
		rendered.WriteString(value)
		idx = loc[1]
	}
	if idx < len(raw) {
		parts = append(parts, fuzzRequestPart{Text: raw[idx:]})
		rendered.WriteString(raw[idx:])
	}
	return parts, rendered.String()
}

// describeFuzzRole says in words where a position sits, because "query_value" is jargon and the
// operator's question is "what did this actually change".
func describeFuzzRole(role string) string {
	switch role {
	case "path":
		return "in the URL path, so each payload is a different path being requested"
	case "query_value":
		return "as the value of a query string parameter"
	case "header_name":
		return "as a header NAME, so each payload is a different header being sent"
	case "header_value":
		return "as a header value"
	case "cookie_value":
		return "inside the Cookie header"
	case "body_value":
		return "in the request body"
	case "method":
		return "as the HTTP method itself"
	case "missing":
		return "nowhere: this position is no longer present in the request text"
	}
	return role
}

// curlForFuzzRequest renders the reconstructed request as a curl command, so it can be replayed
// without retyping it.
//
// The Host header is dropped because the URL carries it, and -i is included because the status and
// the headers are the whole point of a replay.
func curlForFuzzRequest(scheme, raw string) string {
	head, body, _ := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	lines := strings.Split(head, "\n")
	if len(lines) == 0 {
		return ""
	}
	fields := strings.Fields(lines[0])
	if len(fields) < 2 {
		return ""
	}
	method, target := fields[0], fields[1]

	host := ""
	var headers []string
	for _, l := range lines[1:] {
		name, value, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if strings.EqualFold(name, "host") {
			host = value
			continue
		}
		if strings.EqualFold(name, "content-length") {
			continue // curl computes it
		}
		headers = append(headers, fmt.Sprintf("-H %s", shellSingleQuote(name+": "+value)))
	}
	if scheme == "" {
		scheme = "https"
	}

	cmd := []string{"curl", "-i", "-s", "-X", method,
		shellSingleQuote(scheme + "://" + host + target)}
	cmd = append(cmd, headers...)
	if strings.TrimSpace(body) != "" {
		cmd = append(cmd, "--data-raw "+shellSingleQuote(body))
	}
	return strings.Join(cmd, " ")
}

// shellSingleQuote quotes a value for sh, including values that themselves contain a single quote.
func shellSingleQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}
