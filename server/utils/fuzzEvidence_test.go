package utils

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Evidence is RAW WIRE BYTES, so a matched response is routinely something Postgres refuses in a text
// column. Both failures below produced the same visible symptom: no evidence row at all, and a detail
// view telling the operator the bytes were never captured.
func TestEvidenceIsStorableAfterClipping(t *testing.T) {
	// A cut landing inside a multi-byte character must shorten the string, not corrupt it. Postgres
	// rejects the whole INSERT on "invalid byte sequence for encoding UTF8", so a truncation that
	// splits a rune destroys the record it was supposed to preserve.
	body := strings.Repeat("a", 9) + "↑↓"
	for limit := 1; limit <= len(body); limit++ {
		got, truncated := clipEvidence(body, limit)
		if !utf8.ValidString(got) {
			t.Fatalf("limit %d produced an invalid string: %q", limit, got)
		}
		if truncated != (len(body) > limit) {
			t.Errorf("limit %d reported truncated=%v", limit, truncated)
		}
		if len(got) > limit {
			t.Errorf("limit %d returned %d bytes", limit, len(got))
		}
	}

	// A binary body is stored with the offending bytes replaced rather than dropped on the floor. That
	// a binary response came back is itself worth seeing.
	binary := "HTTP/1.1 200 OK\r\n\r\n\x00\x01\xff\xfePK\x03\x04"
	clean := sanitizeForTextColumn(binary)
	if !utf8.ValidString(clean) || strings.ContainsRune(clean, 0) {
		t.Fatalf("sanitised evidence is still unstorable: %q", clean)
	}
	if !strings.Contains(clean, "HTTP/1.1 200 OK") {
		t.Errorf("sanitising must keep the readable part: %q", clean)
	}
}
