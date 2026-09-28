package utils

import (
	"encoding/json"
	"testing"
)

// The set_cookies column is what session-token extraction and the replay cookie jar read. When the
// extension does not split Set-Cookie out for itself, the fallback derives the list from the stored
// response headers, and a response that sets several cookies stores them as a jsonb array.
//
// The fallback used to comma-join that array into a single string. http.Response.Cookies parses one
// cookie per value, so the joined form parses as one cookie and every cookie after the first is
// lost. The session is rarely the first cookie a login sets, so the recording that was supposed to
// capture a login captured everything except the login.
func TestAuthRecordedRequestKeepsEverySetCookie(t *testing.T) {
	args := buildAuthRecordedRequestArgs("rec-1", 1, AuthRecordedRequestInput{
		Method: "POST",
		URL:    "https://app.example.com/login",
		ResponseHeaders: map[string]interface{}{
			"set-cookie": []interface{}{
				"csrf=aaa; Path=/",
				"session=deadbeef; Path=/; HttpOnly",
				"locale=en; Path=/",
			},
		},
	})

	// set_cookies is the 13th column; see the INSERT in insertAuthRecordedRequests.
	raw, ok := args[12].([]byte)
	if !ok {
		t.Fatalf("expected set_cookies as marshalled JSON, got %T", args[12])
	}

	var cookies []string
	if err := json.Unmarshal(raw, &cookies); err != nil {
		t.Fatalf("set_cookies is not a JSON array: %v", err)
	}
	if len(cookies) != 3 {
		t.Fatalf("expected 3 cookies, got %d: %v", len(cookies), cookies)
	}

	var found bool
	for _, c := range cookies {
		if c == "session=deadbeef; Path=/; HttpOnly" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the session cookie did not survive: %v", cookies)
	}
}

// A single Set-Cookie is still stored as a one-element list, unchanged.
func TestAuthRecordedRequestSingleSetCookie(t *testing.T) {
	args := buildAuthRecordedRequestArgs("rec-1", 1, AuthRecordedRequestInput{
		Method:          "POST",
		URL:             "https://app.example.com/login",
		ResponseHeaders: map[string]interface{}{"Set-Cookie": "session=abc; Path=/"},
	})

	raw, _ := args[12].([]byte)
	var cookies []string
	if err := json.Unmarshal(raw, &cookies); err != nil {
		t.Fatalf("set_cookies is not a JSON array: %v", err)
	}
	if len(cookies) != 1 || cookies[0] != "session=abc; Path=/" {
		t.Fatalf("unexpected set_cookies: %v", cookies)
	}
}
