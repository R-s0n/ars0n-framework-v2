package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Whether the credential a step is about to replay is already dead.
//
// This is the check that would have prevented the worst result this framework has produced. A step
// seeded from a captured request carried "authorization: Bearer <JWT>" whose exp was thirty minutes
// after capture. Twelve days later it was still being replayed, all 5000 requests came back with the
// same 401, and 4997 of them were recorded as findings. Nothing anywhere looked at the token.
//
// Reading exp without verifying the signature is exactly right here. The question is not "is this
// token genuine", which only the issuer can answer, it is "has this token already expired", which the
// token states in plain text and which decides whether spending 5000 requests can teach anything.

// jwtLike matches the shape of a JWT anywhere in a header value: three base64url segments. Matching
// the shape rather than the header name means a token pasted into a cookie or a custom header is
// caught too.
// Padding is included in the character class because some issuers emit padded segments, and stopping
// the match at the '=' handed jwtExpiry a truncated payload that would never decode.
var jwtLike = regexp.MustCompile(`eyJ[A-Za-z0-9_=-]{5,}\.[A-Za-z0-9_=-]{5,}\.[A-Za-z0-9_=-]*`)

// fuzzCredentialProblems reports on every credential-looking value in a rendered request.
//
// Errors block the step. An expired token cannot produce a finding, so spending a wordlist proving
// it is dead is worse than refusing: it costs the target the traffic and the operator the time, and
// it produces a result set that looks like data.
func fuzzCredentialProblems(raw string, now time.Time) (errs []string, warnings []string) {
	head, _, _ := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")

	seen := map[string]bool{}
	for i, line := range strings.Split(head, "\n") {
		// Every line is searched, not only the ones that parse as a header. The request line has no
		// colon, so requiring one exempted the entire URL from this check, and a token in a query
		// string is a common way to carry one.
		where, value := "request line", line
		if i > 0 {
			if name, rest, ok := strings.Cut(line, ":"); ok {
				where, value = strings.TrimSpace(name)+" header", rest
			} else {
				where = "request"
			}
		}
		for _, token := range jwtLike.FindAllString(value, -1) {
			if seen[token] {
				continue
			}
			seen[token] = true

			exp, ok := jwtExpiry(token)
			if !ok {
				continue // not a JWT, or one with no exp: nothing to say
			}
			switch {
			case exp.Before(now):
				errs = append(errs, fmt.Sprintf(
					"The %s carries a token that expired %s ago (exp %s). Every request in this "+
						"step would come back with the same auth error, which is not a finding: it is one "+
						"response repeated a few thousand times. Refresh the credential, or remove the "+
						"header to scan this endpoint logged out on purpose.",
					where, humaniseDuration(now.Sub(exp)), exp.UTC().Format(time.RFC3339)))
			case exp.Sub(now) < 10*time.Minute:
				warnings = append(warnings, fmt.Sprintf(
					"The %s carries a token that expires in %s (exp %s). A step long enough to "+
						"outlive it will start returning auth errors partway through, and those look "+
						"exactly like findings.",
					where, humaniseDuration(exp.Sub(now)), exp.UTC().Format(time.RFC3339)))
			}
		}
	}
	return errs, warnings
}

// jwtExpiry reads exp out of a JWT payload without verifying anything.
func jwtExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return time.Time{}, false
	}
	// base64url, and JWT segments are unpadded.
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Some issuers pad anyway.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return time.Time{}, false
		}
	}
	// json.RawMessage rather than *float64, because exp is not always a JSON number. Issuers emit it as
	// a quoted string too, and a typed field makes json.Unmarshal fail on the WHOLE payload, which this
	// function then reports as "no exp" - so a dead token sails through the check that exists to catch
	// exactly it.
	var claims struct {
		Exp json.RawMessage `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || len(claims.Exp) == 0 {
		return time.Time{}, false
	}
	raw := strings.Trim(strings.TrimSpace(string(claims.Exp)), `"`)
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil || seconds <= 0 {
		return time.Time{}, false
	}
	// Milliseconds, which some issuers use. Read as seconds, exp 1754408107000 becomes the year 57573
	// and a token twelve days dead is treated as valid for the next fifty thousand. The threshold is
	// far above any real seconds value: 1e11 seconds is the year 5138.
	if seconds > 1e11 {
		seconds /= 1000
	}
	return time.Unix(int64(seconds), 0), true
}

// humaniseDuration is for a sentence an operator reads, not for arithmetic.
func humaniseDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d seconds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// applySessionTokens rewrites the credential headers of a rendered request with the target's CURRENT
// session tokens.
//
// Opt in per step, deliberately. A fuzz step is raw text the operator wrote and can read, and
// silently rewriting it would break the one property that makes this composer trustworthy: what you
// see in the preview is what goes on the wire. With the option on, the preview shows the substituted
// request too, because both go through RenderFuzzStep.
//
// Only headers the operator ALREADY has in the request are replaced. Adding a credential to a request
// that did not carry one changes what the step is testing, and a step deliberately probing an
// endpoint logged out is a legitimate thing to want.
func applySessionTokens(raw, scopeTargetID string) (string, []string) {
	host := HostFromRawRequest(raw)
	if host == "" || scopeTargetID == "" {
		return raw, nil
	}
	material, _ := LoadScopedAuthContext(scopeTargetID).For(host)
	if material == nil || len(material.Headers) == 0 {
		return raw, nil
	}

	head, body, hadBody := strings.Cut(strings.ReplaceAll(raw, "\r\n", "\n"), "\n\n")
	var notes []string
	lines := strings.Split(head, "\n")
	for i, line := range lines {
		name, oldValue, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		canonical := canonicalHeaderName(strings.TrimSpace(name))
		fresh, found := material.Headers[canonical]
		if !found || fresh == strings.TrimSpace(oldValue) {
			continue
		}
		// A header being FUZZED is not a header to overwrite. Replacing the line wholesale would take
		// the position mark with it, and the step would then run with one fewer position while the
		// preview, the position list and every finding still claimed it was there.
		if strings.Contains(line, "§") || fuzzTokenRe.MatchString(line) {
			notes = append(notes, fmt.Sprintf(
				"%s was NOT refreshed from the Session Manager because it carries a fuzz position. "+
					"Replacing it would delete the marker and silently drop that position from the step.",
				strings.TrimSpace(name)))
			continue
		}
		lines[i] = strings.TrimSpace(name) + ": " + fresh
		notes = append(notes, fmt.Sprintf(
			"%s was replaced with the current value from the Session Manager, so this step is not "+
				"replaying the credential frozen into it when it was seeded.", strings.TrimSpace(name)))
	}
	out := strings.Join(lines, "\n")
	if hadBody {
		out += "\n\n" + body
	}
	return out, notes
}

// DeriveSessionTokenExpiry fills in expires_at from a JWT that already states it.
//
// The live target's stored token had expires_at NULL while its own payload carried
// exp 2026-08-05T16:45:16Z, so every expiry check in the framework passed a credential that had been
// dead for eleven days. Cookies get an expiry from Set-Cookie attributes; a bearer token pasted by
// the operator got nothing, even when the token says so itself.
//
// An explicit value always wins: the operator or the Set-Cookie header knows something the token
// body may not.
func DeriveSessionTokenExpiry(value string, explicit *time.Time) *time.Time {
	if explicit != nil {
		return explicit
	}
	token := jwtLike.FindString(value)
	if token == "" {
		return nil
	}
	exp, ok := jwtExpiry(token)
	if !ok {
		return nil
	}
	return &exp
}
