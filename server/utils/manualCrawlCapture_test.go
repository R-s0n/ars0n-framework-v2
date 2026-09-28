package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// sanitizeForPostgres is necessary and stays: a NUL byte cannot live in a Postgres text column.
// What was missing is the record of what it did. An operator reading a body with a replacement
// character in it could not tell whether the target sent that character or whether we put it
// there, and on a binary payload behind a texty content-type that is the difference between a
// finding and a rendering artefact.
func TestSanitizeForPostgresCheckedCountsAlteredBytes(t *testing.T) {
	nul := string(rune(0))

	cases := []struct {
		name        string
		in          string
		wantOut     string
		wantAltered int
	}{
		{"clean text reports nothing", `{"a":1}`, `{"a":1}`, 0},
		{"empty reports nothing", "", "", 0},
		{"one nul is one altered byte", "ab" + nul + "cd", "abcd", 1},
		{"three nuls are three altered bytes", nul + "a" + nul + nul, "a", 3},
		{"unicode survives and reports nothing", "héllo → 世界", "héllo → 世界", 0},
		{"a replacement character the target really sent is not an alteration",
			"a�b", "a�b", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, altered := sanitizeForPostgresChecked(tc.in)
			if got != tc.wantOut {
				t.Errorf("got %q, want %q", got, tc.wantOut)
			}
			if altered != tc.wantAltered {
				t.Errorf("altered byte count = %d, want %d", altered, tc.wantAltered)
			}
		})
	}
}

// A lone continuation byte is not valid UTF-8. It is replaced, and the replacement must be
// reported, because the stored body is now byte-for-byte different from the wire.
func TestSanitizeForPostgresCheckedReportsInvalidUTF8(t *testing.T) {
	invalid := string([]byte{0x61, 0xff, 0xfe, 0x62})
	got, altered := sanitizeForPostgresChecked(invalid)
	if altered != 2 {
		t.Errorf("altered byte count = %d, want 2", altered)
	}
	if !strings.Contains(got, "a") || !strings.Contains(got, "b") {
		t.Errorf("valid characters were lost: %q", got)
	}
}

// sanitizeForPostgres itself must be unchanged for every existing caller: same output, byte for
// byte, as before this change.
func TestSanitizeForPostgresUnchangedByTheCheckedVariant(t *testing.T) {
	for _, in := range []string{
		"", "clean", "ab" + string(rune(0)) + "cd", string([]byte{0x61, 0xff, 0x62}), "héllo → 世界",
	} {
		checked, _ := sanitizeForPostgresChecked(in)
		if got := sanitizeForPostgres(in); got != checked {
			t.Errorf("sanitizeForPostgres(%q) = %q, checked variant = %q", in, got, checked)
		}
	}
}

// The row must say which fields were altered and by how much, so a reader knows what they are
// holding. A capture whose response body was sanitised and whose URL was not must name only the
// response body.
func TestCaptureAlterationsNameTheAlteredFields(t *testing.T) {
	nul := string(rune(0))
	var alt captureAlterations

	url := alt.text("url", "https://example.test/a")
	body := alt.text("response_body", "PNG"+nul+"DATA")
	post := alt.text("post_data", "clean=1")

	if url != "https://example.test/a" || post != "clean=1" {
		t.Fatalf("clean fields were changed: url=%q post=%q", url, post)
	}
	if body != "PNGDATA" {
		t.Fatalf("response body = %q, want %q", body, "PNGDATA")
	}
	if len(alt.fields) != 1 || alt.fields[0] != "response_body" {
		t.Fatalf("altered fields = %v, want [response_body]", alt.fields)
	}
	if alt.bytes != 1 {
		t.Fatalf("altered bytes = %d, want 1", alt.bytes)
	}
}

// The case where the operator most needs the wire truth is the case where we changed something,
// and it is rare enough to be cheap: the pre-sanitiser bytes are kept, content addressed, and the
// row points at them.
func TestCaptureAlterationsKeepTheOriginalBytes(t *testing.T) {
	original := "PNG" + string(rune(0)) + "DATA"
	var alt captureAlterations
	alt.text("response_body", original)

	sum := sha256.Sum256([]byte(original))
	want := hex.EncodeToString(sum[:])

	if alt.originals["response_body"] != want {
		t.Fatalf("originals[response_body] = %q, want %q", alt.originals["response_body"], want)
	}
	blob, ok := alt.blobs[want]
	if !ok {
		t.Fatalf("no blob stored for the original bytes; blobs = %v", alt.blobs)
	}
	if string(blob.Content) != original {
		t.Fatalf("stored original = %q, want %q", blob.Content, original)
	}
	if blob.Capped {
		t.Error("an original kept for an altered row must never be capped")
	}
}

// A header map stored as jsonb is altered by the same sanitiser. encoding/json has no lossless
// byte form for the original map, so the fact and the count are recorded and no original is
// claimed. Claiming one we cannot produce would be worse than recording none.
func TestCaptureAlterationsOnAJSONMapRecordTheFactWithoutClaimingBytes(t *testing.T) {
	var alt captureAlterations
	raw := alt.jsonMap("response_headers", map[string]interface{}{
		"x-trace": "ab" + string(rune(0)) + "cd",
	})

	var decoded map[string]interface{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("stored jsonb does not parse: %v", err)
	}
	if decoded["x-trace"] != "abcd" {
		t.Fatalf("header value = %v, want abcd", decoded["x-trace"])
	}
	if len(alt.fields) != 1 || alt.fields[0] != "response_headers" {
		t.Fatalf("altered fields = %v, want [response_headers]", alt.fields)
	}
	if alt.bytes != 1 {
		t.Fatalf("altered bytes = %d, want 1", alt.bytes)
	}
	if _, claimed := alt.originals["response_headers"]; claimed {
		t.Error("an original was claimed for a jsonb field, which cannot be reproduced losslessly")
	}
}

// Media bodies are the point of the blob path: an IDOR that returns another user's photo has to
// be provable from the capture table. The bytes arrive base64 encoded and must round trip.
func TestDecodeCaptureBlobRoundTripsTheBytes(t *testing.T) {
	png := []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0xff, 0xfe}
	sum := sha256.Sum256(png)
	digest := hex.EncodeToString(sum[:])

	blob, err := decodeCaptureBlob(&CaptureBodyBlob{
		SHA256:   digest,
		Bytes:    int64(len(png)),
		MimeType: "image/png",
		Base64:   "iVBORw0KGgoA//4=",
	})
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if string(blob.Content) != string(png) {
		t.Fatalf("bytes did not round trip: got % x, want % x", blob.Content, png)
	}
	if blob.SHA256 != digest {
		t.Errorf("digest = %q, want %q", blob.SHA256, digest)
	}
	if blob.StoredBytes != int64(len(png)) || blob.ByteSize != int64(len(png)) {
		t.Errorf("sizes wrong: stored=%d wire=%d want %d", blob.StoredBytes, blob.ByteSize, len(png))
	}
	if blob.Capped {
		t.Error("an uncapped body was marked capped")
	}
}

// The digest is recomputed from the bytes that actually arrived, never taken on trust. A declared
// digest that disagrees means the payload was corrupted in transit, and storing those bytes under
// that name would make every later identity comparison a lie.
func TestDecodeCaptureBlobRefusesAMismatchedHash(t *testing.T) {
	_, err := decodeCaptureBlob(&CaptureBodyBlob{
		SHA256: strings.Repeat("0", 64),
		Bytes:  3,
		Base64: "YWJj",
	})
	if err == nil {
		t.Fatal("a blob whose bytes do not hash to its declared digest was accepted")
	}
}

// A capped blob holds a prefix of a larger object. The digest names the bytes we hold, so it is
// still recomputable and still proves two stored prefixes identical, but the row has to say the
// body is a prefix or a capped body reads as a complete one.
func TestDecodeCaptureBlobRecordsBothSizesForACappedBody(t *testing.T) {
	stored := []byte("abc")
	sum := sha256.Sum256(stored)

	blob, err := decodeCaptureBlob(&CaptureBodyBlob{
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  1048576,
		Capped: true,
		Base64: "YWJj",
	})
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !blob.Capped {
		t.Error("capped flag was lost")
	}
	if blob.ByteSize != 1048576 || blob.StoredBytes != 3 {
		t.Errorf("a capped blob must record both sizes: wire=%d stored=%d", blob.ByteSize, blob.StoredBytes)
	}
}

// A capture can carry a digest with no bytes: the extension already shipped those bytes earlier in
// the session and the framework holds them under that digest. The row still has to resolve to the
// bytes, so the digest alone is accepted and the row records it.
func TestCaptureBlobMayArriveWithoutBytes(t *testing.T) {
	blob, err := decodeCaptureBlob(&CaptureBodyBlob{
		SHA256: strings.Repeat("a", 64),
		Bytes:  4096,
	})
	if err != nil {
		t.Fatalf("a digest-only reference was refused: %v", err)
	}
	if blob.Content != nil {
		t.Error("a digest-only reference must not invent content")
	}
	if blob.SHA256 != strings.Repeat("a", 64) {
		t.Errorf("digest lost: %q", blob.SHA256)
	}
}
