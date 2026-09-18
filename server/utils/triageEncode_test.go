package utils

import (
	"ars0n-framework-v2-server/utils/triage"
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Tests for the slot encoder.
//
// THESE TESTS SEND REAL REQUESTS. Almost every one of them stands up an httptest server, sends the
// encoded request through a real net/http client and asserts on what the SERVER received. That is
// deliberate and it is the whole point: the cookie mangling this file exists to prevent is
// invisible to a string comparison, because the encoder's own output string is correct and the
// sanitiser runs afterwards, inside the transport. One test goes further and reads the literal
// bytes off a TCP socket.

// ---------------------------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------------------------

// capturedRequest is what the far side actually received.
type capturedRequest struct {
	Method     string
	RequestURI string
	Header     http.Header
	Host       string
	Body       []byte
	Seen       bool
}

func triageEchoServer(t *testing.T) (*httptest.Server, func() capturedRequest) {
	t.Helper()
	var last capturedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		last = capturedRequest{
			Method:     r.Method,
			RequestURI: r.RequestURI,
			Header:     r.Header.Clone(),
			Host:       r.Host,
			Body:       body,
			Seen:       true,
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, func() capturedRequest { return last }
}

func triageSend(t *testing.T, e Encoded) error {
	t.Helper()
	req, err := e.NewRequest(context.Background())
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return nil
}

// triageTemplateFor builds a captured request that carries one probeable slot of each kind, so a
// single fixture covers every insertion point and the slots stay comparable across them.
func triageTemplateFor(base string, kind triage.SlotKind) (RequestTemplate, triage.Slot) {
	s := triage.Slot{
		VectorID:        "v-test",
		Kind:            kind,
		Key:             triage.SlotKey(string(kind) + ":target"),
		SegmentIndex:    -1,
		ValueOrigin:     triage.ValueObserved,
		Origin:          triage.SlotObserved,
		ServerReachable: kind != triage.KindFragment,
		Constraints:     triage.NewSlotConstraints(),
		Method:          http.MethodGet,
	}
	tmpl := RequestTemplate{
		Method:  http.MethodGet,
		URL:     base + "/api/v1/orders/42?keep=one&target=original&tail=two",
		Headers: [][2]string{{"User-Agent", "triage-test"}, {"Cookie", "sid=abc; target=original; tz=utc"}},
	}

	switch kind {
	case triage.KindQuery:
		s.Name = "target"
	case triage.KindHeader:
		s.Name = "X-Target"
		tmpl.Headers = append(tmpl.Headers, [2]string{"X-Target", "original"})
	case triage.KindCookie:
		s.Name = "target"
	case triage.KindPath:
		s.SegmentIndex = 3 // /api/v1/orders/42 -> api, v1, orders, 42
	case triage.KindBody:
		s.Name = "target"
		s.FieldPath = "/target"
		s.BodyMedia = triage.BodyJSON
		s.Method = http.MethodPost
		tmpl.Method = http.MethodPost
		tmpl.BodyMedia = triage.BodyJSON
		tmpl.Body = []byte(`{"keep":"one","target":"original","n":1e9}`)
		tmpl.Headers = append(tmpl.Headers, [2]string{"Content-Type", "application/json"})
	case triage.KindFragment:
		s.Name = "tab"
	}
	return tmpl, s
}

// triageReadSlot pulls the value the SERVER read out of the request for this slot kind.
//
// The cookie case parses the Cookie line by hand rather than through r.Cookies(). Go's own server
// side cookie parser drops any cookie whose value contains a quote, a backslash or a space, so
// using it here would report a payload as missing when the bytes are sitting in the header. What
// is being measured is what arrived, not what Go is willing to parse.
func triageReadSlot(t *testing.T, cap capturedRequest, s triage.Slot) []byte {
	t.Helper()
	if !cap.Seen {
		t.Fatalf("the server received no request at all")
	}
	switch s.Kind {
	case triage.KindQuery:
		u, err := url.ParseRequestURI(cap.RequestURI)
		if err != nil {
			t.Fatalf("server received an unparseable request-target %q: %v", cap.RequestURI, err)
		}
		return []byte(u.Query().Get(s.Name))
	case triage.KindHeader:
		return []byte(cap.Header.Get(s.Name))
	case triage.KindCookie:
		for _, part := range strings.Split(cap.Header.Get("Cookie"), ";") {
			part = strings.TrimLeft(part, " \t")
			if name, value, ok := strings.Cut(part, "="); ok && name == s.Name {
				return []byte(value)
			}
		}
		return nil
	case triage.KindPath:
		target := cap.RequestURI
		if i := strings.Index(target, "?"); i >= 0 {
			target = target[:i]
		}
		segs := strings.Split(strings.TrimPrefix(target, "/"), "/")
		if s.SegmentIndex >= len(segs) {
			t.Fatalf("server saw %d path segments in %q, wanted index %d", len(segs), target, s.SegmentIndex)
		}
		decoded, err := url.PathUnescape(segs[s.SegmentIndex])
		if err != nil {
			t.Fatalf("segment %q did not decode: %v", segs[s.SegmentIndex], err)
		}
		return []byte(decoded)
	case triage.KindBody:
		if s.BodyMedia == triage.BodyForm {
			v, err := url.ParseQuery(string(cap.Body))
			if err != nil {
				t.Fatalf("server received an unparseable form body %q: %v", cap.Body, err)
			}
			return []byte(v.Get(s.Name))
		}
		var doc map[string]any
		if err := json.Unmarshal(cap.Body, &doc); err != nil {
			t.Fatalf("server received a body that is not valid JSON, which means we sent a broken document: %v (%s)", err, cap.Body)
		}
		str, _ := doc[s.Name].(string)
		return []byte(str)
	}
	t.Fatalf("no reader for slot kind %s", s.Kind)
	return nil
}

// ---------------------------------------------------------------------------------------------
// the measurement this file exists for
// ---------------------------------------------------------------------------------------------

// The claim in the comments is re-measured here so it cannot rot into folklore, and the encoder is
// measured against it in the same test. If a future Go stops mangling, this test says so rather
// than quietly passing.
func TestHttpCookieStillMangesTheProbeAlphabetAndTheHandBuiltHeaderDoesNot(t *testing.T) {
	cases := []struct {
		value     string
		stdlibGot string
	}{
		{`1' OR 1=1; DROP`, `s="1' OR 1=1 DROP"`},
		{`a"b\c`, `s=abc`},
	}
	for _, c := range cases {
		if got := (&http.Cookie{Name: "s", Value: c.value}).String(); got != c.stdlibGot {
			t.Errorf("http.Cookie(%q).String() = %q, the measurement this encoder is built on said %q; re-check the encoder's assumptions",
				c.value, got, c.stdlibGot)
		}
	}

	srv, last := triageEchoServer(t)
	for _, c := range cases {
		tmpl, slot := triageTemplateFor(srv.URL, triage.KindCookie)
		enc := EncodeSlotInto(tmpl, slot, triage.EncodeCookie, []byte(c.value), triage.SlotOverrides{})
		if !enc.Delivered {
			t.Fatalf("cookie %q was refused: %s (%s)", c.value, enc.Reason, enc.Detail)
		}
		if err := triageSend(t, enc); err != nil {
			t.Fatalf("send: %v", err)
		}
		line := last().Header.Get("Cookie")
		if want := "sid=abc; target=" + c.value + "; tz=utc"; line != want {
			t.Errorf("the server received Cookie %q, wanted %q: the quote, the backslash or the semicolon was lost", line, want)
		}
	}
}

// The strongest form of that assertion: the literal bytes on the socket, read before any parser
// touches them.
func TestTheCookieLineReachesTheSocketByteIdentical(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	raw := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			raw <- "accept failed: " + err.Error()
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		var buf bytes.Buffer
		br := bufio.NewReader(conn)
		for {
			line, err := br.ReadString('\n')
			buf.WriteString(line)
			if err != nil || line == "\r\n" {
				break
			}
		}
		io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
		raw <- buf.String()
	}()

	payload := `1' OR 1=1; DROP`
	tmpl, slot := triageTemplateFor("http://"+ln.Addr().String(), triage.KindCookie)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeCookie, []byte(payload), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}

	got := <-raw
	want := "Cookie: sid=abc; target=" + payload + "; tz=utc\r\n"
	if !strings.Contains(got, want) {
		t.Errorf("the bytes on the socket do not contain %q.\nwhole request:\n%s", want, got)
	}
}

// ---------------------------------------------------------------------------------------------
// every insertion point crossed with every metacharacter that matters
// ---------------------------------------------------------------------------------------------

// triageMetachars is the alphabet the injection classes are built from, plus the two bytes that
// cannot be sent in a header and a multibyte character to catch a per-rune encoder.
var triageMetachars = []struct {
	name string
	char string
}{
	{"single quote", `'`},
	{"double quote", `"`},
	{"backslash", `\`},
	{"semicolon", `;`},
	{"ampersand", `&`},
	{"equals", `=`},
	{"plus", `+`},
	{"less than", `<`},
	{"greater than", `>`},
	{"open brace", `{`},
	{"close brace", `}`},
	{"dollar", `$`},
	{"backtick", "`"},
	{"pipe", `|`},
	{"percent", `%`},
	{"newline", "\n"},
	{"nul", "\x00"},
	{"utf8 e acute", "é"},
	{"utf8 cjk", "世"},
}

// The core round trip. Every deliverable combination has to arrive byte identical, and every
// undeliverable one has to come back with a named reason and no request. There is no third
// outcome, and in particular there is no outcome where the bytes change and nobody is told.
func TestEveryInsertionPointEitherDeliversTheMetacharacterOrNamesWhyItCannot(t *testing.T) {
	srv, last := triageEchoServer(t)
	kinds := []triage.SlotKind{triage.KindQuery, triage.KindPath, triage.KindCookie, triage.KindHeader, triage.KindBody}

	for _, kind := range kinds {
		for _, mc := range triageMetachars {
			t.Run(string(kind)+"/"+mc.name, func(t *testing.T) {
				logical := []byte("aa" + mc.char + "bb")
				tmpl, slot := triageTemplateFor(srv.URL, kind)
				enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, logical, triage.SlotOverrides{})

				wantReason := triageExpectedRefusal(kind, mc.char)
				if wantReason != DeliverOK {
					if enc.Delivered {
						t.Fatalf("%s carrying %s was delivered, but it cannot be sent by a conforming client", kind, mc.name)
					}
					if enc.Reason != wantReason {
						t.Fatalf("refused with %q, wanted %q (%s)", enc.Reason, wantReason, enc.Detail)
					}
					if enc.Detail == "" {
						t.Fatalf("a refusal with no detail is a silent zero in different clothing")
					}
					if _, err := enc.NewRequest(context.Background()); err == nil {
						t.Fatalf("an undeliverable encode built a request anyway, which is how it reaches a classifier as sent")
					}
					return
				}

				if !enc.Delivered {
					t.Fatalf("%s carrying %s was refused with %q: %s", kind, mc.name, enc.Reason, enc.Detail)
				}
				if err := triageSend(t, enc); err != nil {
					t.Fatalf("send: %v", err)
				}
				got := triageReadSlot(t, last(), slot)

				// The cookie semicolon is the one delivered-but-altered case: the bytes are on the
				// wire and the parser on the far side splits the value at them.
				if kind == triage.KindCookie && mc.char == ";" {
					if enc.Wire.Survived != triage.WireSurvivalAltered {
						t.Fatalf("a cookie value carrying a semicolon must be flagged altered, got %q", enc.Wire.Survived)
					}
					if enc.Wire.Survived.Proven() {
						t.Fatalf("an altered payload must not count as proven, or a clean can be drawn from it")
					}
					if string(got) != "aa" {
						t.Fatalf("expected the far side to read the value truncated at the semicolon, got %q", got)
					}
					return
				}

				if survived, why := CompareDelivered(logical, got); survived != triage.WireSurvivalIntact {
					t.Fatalf("%s carrying %s arrived as %q: %s (%s)", kind, mc.name, got, survived, why)
				}
			})
		}
	}
}

// triageExpectedRefusal is the expectation table: which crossings cannot be delivered at all.
// Header and cookie values are the only containers with no escaping mechanism, so they are the
// only ones where a byte is simply unsendable.
func triageExpectedRefusal(kind triage.SlotKind, char string) DeliveryReason {
	if kind != triage.KindHeader && kind != triage.KindCookie {
		return DeliverOK
	}
	switch char {
	case "\n":
		return ReasonValueCRLF
	case "\x00":
		return ReasonValueNUL
	}
	return DeliverOK
}

// net/http has to agree with triageHeaderValueFault, or the encoder is refusing the wrong set and
// something it passes will blow up in the transport instead of being recorded as a refusal.
func TestNetHttpRefusesExactlyTheHeaderValuesTheEncoderRefuses(t *testing.T) {
	srv, _ := triageEchoServer(t)
	for _, mc := range triageMetachars {
		value := "aa" + mc.char + "bb"
		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Target", value)
		_, sendErr := http.DefaultClient.Do(req)

		reason, _ := triageHeaderValueFault([]byte(value))
		switch {
		case reason == DeliverOK && sendErr != nil:
			t.Errorf("the encoder would have sent %q but net/http refused it: %v", mc.name, sendErr)
		case reason != DeliverOK && sendErr == nil:
			t.Errorf("the encoder refuses %q as %s but net/http sent it happily; the refusal set is wrong", mc.name, reason)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// per insertion point
// ---------------------------------------------------------------------------------------------

// The PathEscape trap, measured rather than asserted from memory, and then the encoder shown not
// to fall into it: a payload full of query metacharacters has to stay ONE parameter.
func TestAQueryPayloadStaysOneParameterBecauseQueryEscapeIsUsedNotPathEscape(t *testing.T) {
	for _, s := range []string{"a=b", "a&b", "a+b"} {
		if url.PathEscape(s) != s {
			t.Fatalf("url.PathEscape(%q) = %q; the measurement this encoder is built on said it passes these through raw", s, url.PathEscape(s))
		}
	}

	srv, last := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindQuery)
	logical := []byte("a=b&c=d+e#f")
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, logical, triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}

	u, err := url.ParseRequestURI(last().RequestURI)
	if err != nil {
		t.Fatalf("request-target %q did not parse: %v", last().RequestURI, err)
	}
	if got := len(u.Query()); got != 3 {
		t.Errorf("the server saw %d query parameters, wanted the original 3: the payload split the query", got)
	}
	if got := u.Query().Get("target"); got != string(logical) {
		t.Errorf("target = %q, wanted %q", got, logical)
	}
	if got := u.Query().Get("tail"); got != "two" {
		t.Errorf("the parameter after the payload arrived as %q, wanted \"two\"", got)
	}
}

// A traversal payload is one segment or it is nothing. A raw slash would change the route, and
// then the response says nothing at all about the slot that was probed.
func TestAPathPayloadStaysInsideOneSegment(t *testing.T) {
	srv, last := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindPath)
	logical := []byte("../../etc/passwd")
	enc := EncodeSlotInto(tmpl, slot, triage.EncodePathSegment, logical, triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}

	target := last().RequestURI
	if i := strings.Index(target, "?"); i >= 0 {
		target = target[:i]
	}
	if segs := strings.Split(strings.TrimPrefix(target, "/"), "/"); len(segs) != 4 {
		t.Fatalf("the server saw %d path segments in %q, wanted 4: the payload escaped its segment", len(segs), target)
	}
	if !strings.Contains(target, "%2F") {
		t.Errorf("request-target %q does not carry an encoded slash", target)
	}
	if got := triageReadSlot(t, last(), slot); string(got) != string(logical) {
		t.Errorf("the segment decoded to %q, wanted %q", got, logical)
	}
	if enc.Wire.Survived != triage.WireSurvivalEncoded {
		t.Errorf("survival = %q, wanted encoded: the payload is present through a declared encoder, not verbatim", enc.Wire.Survived)
	}
}

// The path is the one insertion point where a payload can be undeliverable for a reason that is
// neither the transport's nor the application's: the probe itself forbids the only escaping that
// would keep the payload in one segment.
func TestAPathPayloadWithASlashIsUndeliverableWhenTheProbeDemandsARawPercent(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1/x", triage.KindPath)
	tmpl.URL = "http://127.0.0.1:1/api/v1/orders/42"
	enc := EncodeSlotInto(tmpl, slot, triage.EncodePathSegment, []byte("../../etc/passwd"), triage.SlotOverrides{RawPercent: true})
	if enc.Delivered {
		t.Fatalf("a slash was delivered into a single path segment with percent-encoding forbidden")
	}
	if enc.Reason != ReasonPathSlashUnencodable {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonPathSlashUnencodable)
	}
	if enc.Wire.Survived.Proven() {
		t.Fatalf("a refused payload must never read as proven")
	}
}

// A JSON payload has to be escaped INTO the document, so the document stays valid and the 400 that
// comes back, if one comes back, is about the application and not about our own broken JSON.
func TestAJsonBodyPayloadGoesInAsAStringValueAndTheDocumentStaysValid(t *testing.T) {
	srv, last := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindBody)
	logical := []byte(`a"b\c'd` + "\n" + `<e>{{7*7}}`)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeJSONString, logical, triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if !json.Valid(enc.Req.Body) {
		t.Fatalf("the encoder produced an invalid JSON document: %s", enc.Req.Body)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(last().Body, &doc); err != nil {
		t.Fatalf("the server received invalid JSON: %v", err)
	}
	if got, _ := doc["target"].(string); got != string(logical) {
		t.Errorf("target = %q, wanted %q", got, logical)
	}
	if got, _ := doc["keep"].(string); got != "one" {
		t.Errorf("the sibling field changed to %q", got)
	}
	// 1e9 must not come back as 1000000000. A comparator diffing the request would otherwise see a
	// change the payload did not cause.
	if !bytes.Contains(enc.Req.Body, []byte("1e9")) {
		t.Errorf("the number was reformatted by the round trip: %s", enc.Req.Body)
	}
}

// The reason the JSON encoder refuses invalid UTF-8 rather than marshalling it: measured here so
// the refusal is justified by the behaviour and not by a hunch.
func TestEncodingJsonSilentlyRewritesInvalidUtf8WhichIsWhyThePayloadIsRefusedFirst(t *testing.T) {
	bad := []byte{'a', 0xff, 'b'}
	marshalled, err := json.Marshal(string(bad))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !bytes.Contains(marshalled, []byte{'\\', 'u', 'f', 'f', 'f', 'd'}) {
		t.Fatalf("encoding/json produced %s; the refusal in the encoder is justified by it rewriting the byte as an escaped U+FFFD", marshalled)
	}

	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindBody)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeJSONString, bad, triage.SlotOverrides{})
	if enc.Delivered {
		t.Fatalf("an invalid-UTF-8 payload was delivered, so a different payload was tested than the one asked for")
	}
	if enc.Reason != ReasonPayloadNotUTF8 {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonPayloadNotUTF8)
	}
}

func TestANodeReplacePayloadThatIsNotJsonIsRefusedRatherThanCorruptingTheDocument(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindBody)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeJSONNodeReplace, []byte(`{"a":`), triage.SlotOverrides{})
	if enc.Delivered {
		t.Fatalf("a malformed JSON fragment was spliced into the document")
	}
	if enc.Reason != ReasonNodePayloadNotJSON {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonNodePayloadNotJSON)
	}

	ok := EncodeSlotInto(tmpl, slot, triage.EncodeJSONNodeReplace, []byte(`{"$gt":""}`), triage.SlotOverrides{})
	if !ok.Delivered {
		t.Fatalf("a valid JSON object was refused: %s", ok.Detail)
	}
	if !bytes.Contains(ok.Req.Body, []byte(`{"$gt":""}`)) {
		t.Errorf("the node was not replaced: %s", ok.Req.Body)
	}
}

func TestAFormFieldIsEncodedAndTheOtherFieldsAreLeftAlone(t *testing.T) {
	srv, last := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindBody)
	tmpl.Method = http.MethodPost
	tmpl.BodyMedia = triage.BodyForm
	tmpl.Body = []byte("keep=one&target=original&tail=two")
	tmpl.SetHeader("Content-Type", "application/x-www-form-urlencoded")
	slot.BodyMedia = triage.BodyForm
	slot.FieldPath = ""

	logical := []byte("a=b&c=d+e")
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeForm, logical, triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}

	values, err := url.ParseQuery(string(last().Body))
	if err != nil {
		t.Fatalf("the server received an unparseable form body: %v", err)
	}
	if len(values) != 3 {
		t.Errorf("the server saw %d fields, wanted 3: the payload split the body", len(values))
	}
	if got := values.Get("target"); got != string(logical) {
		t.Errorf("target = %q, wanted %q", got, logical)
	}
	if got := values.Get("tail"); got != "two" {
		t.Errorf("the field after the payload arrived as %q", got)
	}
}

// The fragment is the one insertion point where faithful delivery is impossible by construction
// rather than by payload. It is never a clean and it is never silence.
func TestAFragmentSlotIsUndeliverableBecauseNoClientEverSendsOne(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindFragment)
	for _, mode := range []triage.EncoderMode{triage.EncodeNone, triage.EncodeQuery, triage.EncodeHeaderValue} {
		enc := EncodeSlotInto(tmpl, slot, mode, []byte("anything"), triage.SlotOverrides{})
		if enc.Delivered {
			t.Fatalf("mode %s delivered a payload into a fragment", mode)
		}
		if enc.Reason != ReasonFragmentNotTransmitted {
			t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonFragmentNotTransmitted)
		}
	}
}

// HeaderAllowRawLF exists to make the refusal explicit, not to enable it. If it ever starts
// enabling it, this test fails and somebody has to argue for request splitting on purpose.
func TestTheRawLinefeedOverrideRecordsTheRefusalRatherThanEnablingIt(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindHeader)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeHeaderValue, []byte("a\r\nX-Injected: 1"), triage.SlotOverrides{HeaderAllowRawLF: true})
	if enc.Delivered {
		t.Fatalf("a CRLF payload was delivered into a header value")
	}
	if enc.Reason != ReasonValueCRLF {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonValueCRLF)
	}
	if !strings.Contains(enc.Detail, "HeaderAllowRawLF") {
		t.Errorf("the detail does not mention the override the probe declared: %q", enc.Detail)
	}
}

// Leading and trailing whitespace goes out on the wire and is then stripped by the server before
// the handler sees it. The bytes are delivered; the value is not. Same shape as the cookie
// semicolon, and the same consequence: not proven, so no clean.
func TestAHeaderPayloadWrappedInWhitespaceIsFlaggedAlteredBecauseServersStripIt(t *testing.T) {
	srv, last := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindHeader)
	logical := []byte("  {{7*7}}  ")
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeHeaderValue, logical, triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if enc.Wire.Survived != triage.WireSurvivalAltered {
		t.Fatalf("survival = %q, wanted altered", enc.Wire.Survived)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := last().Header.Get("X-Target"); got == string(logical) {
		t.Skip("this server did not strip the optional whitespace, so the flag is conservative here")
	}
}

// A Host header slot has to become req.Host, or net/http drops it and every Host header probe is
// silently a no-op that reports clean.
func TestAHostHeaderSlotReachesTheServerAsTheHostAndNotAsADroppedHeader(t *testing.T) {
	srv, last := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindHeader)
	slot.Name = "Host"
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeHeaderValue, []byte("evil.example"), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}
	if got := last().Host; got != "evil.example" {
		t.Errorf("the server saw Host %q, wanted evil.example", got)
	}
}

// ---------------------------------------------------------------------------------------------
// refusals that are about the slot or the template, not about the transport
// ---------------------------------------------------------------------------------------------

func TestAByteOnTheSlotsMeasuredImpossibleListIsRefusedRatherThanEncodedAround(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindQuery)
	slot.Constraints.Impossible = []byte{'\''}
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("aa'bb"), triage.SlotOverrides{})
	if enc.Delivered {
		t.Fatalf("a byte measured impossible for this slot was delivered")
	}
	if enc.Reason != ReasonSlotImpossibleByte {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonSlotImpossibleByte)
	}
	if !strings.Contains(enc.Detail, "0x27") {
		t.Errorf("the detail does not name the byte: %q", enc.Detail)
	}
}

func TestASlotThatRejectsPercentEncodingRefusesAPayloadThatNeedsIt(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindQuery)
	slot.Constraints.PctRejected = true
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("a&b"), triage.SlotOverrides{})
	if enc.Delivered {
		t.Fatalf("a payload needing percent-encoding was delivered into a slot measured to reject it")
	}
	if enc.Reason != ReasonSlotRejectsPercentEnc {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonSlotRejectsPercentEnc)
	}

	// A payload that needs no encoding is unaffected: the constraint gates the encoding, not the slot.
	ok := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("plain"), triage.SlotOverrides{})
	if !ok.Delivered {
		t.Fatalf("a payload needing no encoding was refused: %s", ok.Detail)
	}
}

// An unresolved template poisons every encode against the request, not just a path encode: the
// request goes to a literal brace URL, which 404s on any application, and a class that finds
// nothing at a 404 has not tested the endpoint.
func TestAnUnresolvedPathTemplateIsRefusedForEveryInsertionPointOnThatRequest(t *testing.T) {
	for _, kind := range []triage.SlotKind{triage.KindQuery, triage.KindCookie, triage.KindHeader, triage.KindPath} {
		tmpl, slot := triageTemplateFor("http://127.0.0.1:1", kind)
		tmpl.URL = "http://127.0.0.1:1/api/v1/orders/{order_id}?keep=one&target=original&tail=two"
		if kind == triage.KindHeader {
			tmpl.Headers = append(tmpl.Headers, [2]string{"X-Target", "original"})
		}
		enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("payload"), triage.SlotOverrides{})
		if enc.Delivered {
			t.Errorf("%s: a request carrying an unresolved {order_id} was sent anyway", kind)
		}
		if enc.Reason != ReasonPathTemplateOpen {
			t.Errorf("%s: reason = %q, wanted %q", kind, enc.Reason, ReasonPathTemplateOpen)
		}
	}
}

func TestAnObservedSlotMissingFromTheTemplateIsADerivationBugAndSaysSo(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindQuery)
	slot.Name = "absent"
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("payload"), triage.SlotOverrides{})
	if enc.Delivered {
		t.Fatalf("a parameter that is not in the captured request was quietly appended and recorded as probed")
	}
	if enc.Reason != ReasonQueryParamAbsent {
		t.Fatalf("reason = %q, wanted %q", enc.Reason, ReasonQueryParamAbsent)
	}

	// An INFERRED slot is by definition absent from the capture, so appending it is the probe.
	slot.Origin = triage.SlotInferred
	inferred := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("payload"), triage.SlotOverrides{})
	if !inferred.Delivered {
		t.Fatalf("an inferred slot could not be appended: %s", inferred.Detail)
	}
	if !strings.Contains(inferred.Req.URL, "absent=payload") {
		t.Errorf("the inferred parameter is not in the URL: %s", inferred.Req.URL)
	}
}

func TestAnEncoderWithNoImplementationRefusesByNameRatherThanPassingTheBytesThrough(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindBody)
	for _, mode := range []triage.EncoderMode{triage.EncodeXMLCDATA, triage.EncodeXMLDocReplace, triage.EncodeMultipartValue, triage.EncodeMultipartName} {
		enc := EncodeSlotInto(tmpl, slot, mode, []byte("payload"), triage.SlotOverrides{})
		if enc.Delivered {
			t.Errorf("%s has no implementation but delivered something", mode)
		}
		if enc.Reason != ReasonEncoderNotImplemented {
			t.Errorf("%s: reason = %q, wanted %q", mode, enc.Reason, ReasonEncoderNotImplemented)
		}
	}
}

func TestAnEncoderPointedAtTheWrongContainerIsRefused(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1", triage.KindQuery)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeCookie, []byte("payload"), triage.SlotOverrides{})
	if enc.Delivered || enc.Reason != ReasonEncoderWrongKind {
		t.Fatalf("a cookie encoder rendered into a query slot: delivered=%v reason=%q", enc.Delivered, enc.Reason)
	}
}

// ---------------------------------------------------------------------------------------------
// the fidelity check
// ---------------------------------------------------------------------------------------------

func TestTheFidelityCheckNeverReportsIntactForBytesItCannotFind(t *testing.T) {
	cases := []struct {
		name string
		in   triage.PayloadWire
		want triage.WireSurvival
	}{
		{"refused stays refused", triage.PayloadWire{Logical: []byte("x"), Survived: triage.WireSurvivalRefused}, triage.WireSurvivalRefused},
		{"no logical payload is unknown", triage.PayloadWire{Container: []byte("abc")}, triage.WireSurvivalUnknown},
		{"no container is unknown, not intact", triage.PayloadWire{Logical: []byte("x"), Wire: []byte("x")}, triage.WireSurvivalUnknown},
		{"wire absent from the container is dropped", triage.PayloadWire{Logical: []byte("a;b"), Wire: []byte("a;b"), Container: []byte("s=ab")}, triage.WireSurvivalDropped},
		{"verbatim is intact", triage.PayloadWire{Logical: []byte("ab"), Wire: []byte("ab"), Container: []byte("s=ab")}, triage.WireSurvivalIntact},
		{"escaped is encoded", triage.PayloadWire{Logical: []byte("a b"), Wire: []byte("a+b"), Container: []byte("s=a+b")}, triage.WireSurvivalEncoded},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, why := CheckFidelity(c.in)
			if got != c.want {
				t.Fatalf("got %q, wanted %q (%s)", got, c.want, why)
			}
			if got == triage.WireSurvivalUnknown && why == "" {
				t.Errorf("an unknown with no reason is exactly the silent zero this layer exists to stop")
			}
		})
	}
}

// This is the check that found the cookie bug: what was asked for against what the far side read.
func TestCompareDeliveredCallsAMangledPayloadAlteredAndNamesTheOffset(t *testing.T) {
	got, why := CompareDelivered([]byte(`a"b\c`), []byte("abc"))
	if got != triage.WireSurvivalAltered {
		t.Fatalf("got %q, wanted altered", got)
	}
	if !strings.Contains(why, "offset 1") {
		t.Errorf("the explanation does not locate the difference: %q", why)
	}
	if dropped, _ := CompareDelivered([]byte("x"), nil); dropped != triage.WireSurvivalDropped {
		t.Errorf("an empty read is %q, wanted dropped", dropped)
	}
}

func TestAnObservationCarriesTheFidelityResultAndRefusesAnUndeliverableEncode(t *testing.T) {
	srv, _ := triageEchoServer(t)
	tmpl, slot := triageTemplateFor(srv.URL, triage.KindQuery)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("a b"), triage.SlotOverrides{})

	var obs triage.Observation
	if err := AttachEncode(&obs, enc); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if obs.Payload.Survived != triage.WireSurvivalEncoded {
		t.Errorf("the observation carries survival %q, wanted encoded", obs.Payload.Survived)
	}
	if obs.ReqWireURL != enc.Req.URL {
		t.Errorf("the observation did not record the wire URL")
	}
	if obs.Payload.EncoderVersion != TriageEncoderVersion {
		t.Errorf("the observation did not record which encoder produced it")
	}

	refused := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("x"), triage.SlotOverrides{})
	refused.Delivered = false
	refused.Reason = ReasonValueNUL
	var bad triage.Observation
	if err := AttachEncode(&bad, refused); err == nil {
		t.Fatalf("an undeliverable encode was attached to an observation, which is how a request nobody sent gets a verdict")
	}
}

func TestEverySuccessfulEncodeRecordsBothTheLogicalAndTheWireBytes(t *testing.T) {
	srv, _ := triageEchoServer(t)
	for _, kind := range []triage.SlotKind{triage.KindQuery, triage.KindPath, triage.KindCookie, triage.KindHeader, triage.KindBody} {
		tmpl, slot := triageTemplateFor(srv.URL, kind)
		enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("aa'bb"), triage.SlotOverrides{})
		if !enc.Delivered {
			t.Fatalf("%s: refused: %s", kind, enc.Detail)
		}
		switch {
		case len(enc.Wire.Logical) == 0:
			t.Errorf("%s: no logical bytes recorded", kind)
		case len(enc.Wire.Wire) == 0:
			t.Errorf("%s: no wire bytes recorded", kind)
		case len(enc.Wire.Container) == 0:
			t.Errorf("%s: no container recorded, so a dropped byte would be invisible", kind)
		case enc.Wire.ContainerName == "":
			t.Errorf("%s: the container is not named", kind)
		case enc.Wire.Survived == triage.WireSurvivalUnknown:
			t.Errorf("%s: survival was left unknown on a delivered payload", kind)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// the guards
// ---------------------------------------------------------------------------------------------

// The strongest guard in this file. Comments saying "never use http.Cookie" are worth nothing; a
// test that reads the AST and fails the build is worth something.
//
// It parses rather than greps, because triage/types.go and triageEncode.go both DESCRIBE the trap
// in their comments, and a grep would fire on the warning instead of on the mistake. Test files
// are excluded: this file calls http.Cookie deliberately, to measure the mangling.
func TestTheTriageFilesNeverUseTheManglingApis(t *testing.T) {
	banned := []struct {
		pkg, sel, why string
	}{
		{"http", "Cookie", "http.Cookie drops the semicolon, the double quote and the backslash from a value; build the Cookie header by hand"},
		{"", "AddCookie", "Request.AddCookie goes through the same sanitiser as http.Cookie"},
		{"url", "PathEscape", "url.PathEscape leaves =, & and + raw, so a query value built with it splits into several parameters"},
	}

	// The triage layer is now two directories: this package's triage*.go files, and every file of
	// the triage package below it. Both are scanned. A guard that kept globbing only "triage*.go"
	// after the split would have quietly stopped covering the half that moved, which is the exact
	// shape of the bug that let a leak through a "triage*.go" source guard in a file called
	// sqliClassifier.go.
	files, err := filepath.Glob(filepath.Join(".", "triage*.go"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	below, err := filepath.Glob(filepath.Join(".", "triage", "*.go"))
	if err != nil {
		t.Fatalf("glob triage package: %v", err)
	}
	classes, err := filepath.Glob(filepath.Join(".", "triage", "classes", "*.go"))
	if err != nil {
		t.Fatalf("glob classes package: %v", err)
	}
	files = append(append(files, below...), classes...)
	if len(files) == 0 {
		t.Fatalf("the glob found no triage files, so this guard is checking nothing")
	}
	if len(below) == 0 {
		t.Fatalf("the glob found no files in package triage, so the half of the layer that moved is not covered")
	}

	checked := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		checked++
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f, src, 0) // 0: comments are dropped, which is the point
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			ident, _ := sel.X.(*ast.Ident)
			for _, b := range banned {
				if sel.Sel.Name != b.sel {
					continue
				}
				if b.pkg != "" && (ident == nil || ident.Name != b.pkg) {
					continue
				}
				t.Errorf("%s uses %s: %s", fset.Position(sel.Pos()), b.sel, b.why)
			}
			return true
		})
	}
	if checked == 0 {
		t.Fatalf("every triage file was skipped, so this guard is checking nothing")
	}
}

// Every DeliveryReason constant has to be in the vocabulary slice, or a UI renders a state it has
// never heard of and the safest-looking default wins. The skeleton learned this with TriageState.
func TestTheDeliveryReasonVocabularyIsExhaustive(t *testing.T) {
	known := map[DeliveryReason]bool{}
	for _, r := range triageDeliveryReasons {
		if r == DeliverOK {
			t.Errorf("DeliverOK means delivered and must not be in the refusal vocabulary")
		}
		if known[r] {
			t.Errorf("reason %q is listed twice", r)
		}
		known[r] = true
	}

	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "triageEncode.go", nil, 0)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	declared := 0
	ast.Inspect(parsed, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		typ, _ := spec.Type.(*ast.Ident)
		if typ == nil || typ.Name != "DeliveryReason" {
			return true
		}
		for i, name := range spec.Names {
			if name.Name == "DeliverOK" {
				continue
			}
			declared++
			lit, _ := spec.Values[i].(*ast.BasicLit)
			if lit == nil {
				continue
			}
			value := DeliveryReason(strings.Trim(lit.Value, `"`))
			if !known[value] {
				t.Errorf("constant %s = %q is declared but is not in triageDeliveryReasons: nothing can render or filter it",
					name.Name, value)
			}
		}
		return true
	})
	if declared != len(triageDeliveryReasons) {
		t.Errorf("%d DeliveryReason constants are declared but the vocabulary lists %d", declared, len(triageDeliveryReasons))
	}
	if declared == 0 {
		t.Fatalf("the scan found no constants, so this guard is checking nothing")
	}
}

// Not knowing is not clean. No refusal may ever come back proven, and no refusal may come back
// without a reason, whatever the slot or the mode.
func TestNoRefusalEverReadsAsProvenAndNoRefusalIsEverSilent(t *testing.T) {
	srv, _ := triageEchoServer(t)
	modes := []triage.EncoderMode{triage.EncodeNone, triage.EncodeQuery, triage.EncodeForm, triage.EncodePathSegment, triage.EncodeCookie,
		triage.EncodeHeaderValue, triage.EncodeJSONString, triage.EncodeJSONNodeReplace, triage.EncodeXMLCDATA, triage.EncodeMultipartValue,
		triage.EncodeNameSlot, triage.EncodeLiteralPct, triage.EncodePctTwice, triage.EncodeIISUnicode, triage.EncoderMode("invented")}

	refusals := 0
	for _, kind := range triage.AllSlotKinds() {
		for _, mode := range modes {
			for _, payload := range [][]byte{[]byte("plain"), []byte("a\x00b"), []byte("a\r\nb"), {'a', 0xff}} {
				tmpl, slot := triageTemplateFor(srv.URL, kind)
				enc := EncodeSlotInto(tmpl, slot, mode, payload, triage.SlotOverrides{})
				if enc.Delivered {
					if enc.Reason != DeliverOK {
						t.Errorf("%s/%s: delivered with reason %q set", kind, mode, enc.Reason)
					}
					continue
				}
				refusals++
				if enc.Reason == DeliverOK {
					t.Errorf("%s/%s: refused with no reason", kind, mode)
				}
				if enc.Detail == "" {
					t.Errorf("%s/%s: refused with no detail", kind, mode)
				}
				if enc.Wire.Survived.Proven() {
					t.Errorf("%s/%s: a refusal read as proven", kind, mode)
				}
				if enc.Req.URL != "" || len(enc.Req.Headers) != 0 || len(enc.Req.Body) != 0 {
					t.Errorf("%s/%s: a refusal carries a request, which a careless caller will send", kind, mode)
				}
			}
		}
	}
	if refusals == 0 {
		t.Fatalf("no combination was refused, so this test proves nothing")
	}
}

// The encoder must never mutate the template it was handed. Two classes encode against the same
// captured request, and if one of them could edit it the second would be probing the first one's
// payload and attributing the response to itself.
func TestEncodingDoesNotMutateTheTemplateTheClassWasHanded(t *testing.T) {
	srv, _ := triageEchoServer(t)
	for _, kind := range []triage.SlotKind{triage.KindQuery, triage.KindPath, triage.KindCookie, triage.KindHeader, triage.KindBody} {
		tmpl, slot := triageTemplateFor(srv.URL, kind)
		before := fmt.Sprintf("%s|%v|%s", tmpl.URL, tmpl.Headers, tmpl.Body)
		EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("payload-one"), triage.SlotOverrides{})
		EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("payload-two"), triage.SlotOverrides{})
		if after := fmt.Sprintf("%s|%v|%s", tmpl.URL, tmpl.Headers, tmpl.Body); after != before {
			t.Errorf("%s: the template changed under the encoder\n before %s\n after  %s", kind, before, after)
		}
	}
}

// ---------------------------------------------------------------------------------------------
// the socket is the only witness: exact header names, duplicates, and the recorded container
// ---------------------------------------------------------------------------------------------

// triageSocketMirror is the shared socket-level oracle. It accepts one connection, reads the whole
// request including the body, answers 204 and hands back the literal bytes.
//
// httptest is not enough for any of the assertions below, because net/http parses the request
// before a handler can see it: textproto canonicalises every field name on the way in, so a probe
// whose whole point is the spelling of a header reads as identical to one that was rewritten.
func triageSocketMirror(t *testing.T) (addr string, raw func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	out := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			out <- "accept failed: " + err.Error()
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		var buf bytes.Buffer
		br := bufio.NewReader(conn)
		length := 0
		for {
			line, err := br.ReadString('\n')
			buf.WriteString(line)
			if n, ok := triageContentLengthOf(line); ok {
				length = n
			}
			if err != nil || line == "\r\n" {
				break
			}
		}
		if length > 0 {
			body := make([]byte, length)
			if _, err := io.ReadFull(br, body); err == nil {
				buf.Write(body)
			}
		}
		io.WriteString(conn, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
		out <- buf.String()
	}()

	return ln.Addr().String(), func() string { return <-out }
}

func triageContentLengthOf(line string) (int, bool) {
	name, value, ok := strings.Cut(line, ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// A header field name is data. The CRLF, host header and HPP classes all probe the spelling of a
// name or the presence of a second copy of one, and req.Header.Set destroys both: textproto
// canonicalises the name and Set replaces rather than appends.
func TestAHeaderReachesTheSocketWithItsExactNameAndItsDuplicates(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{
		Method: http.MethodGet,
		URL:    "http://" + addr + "/probe",
		Headers: [][2]string{
			{"User-Agent", "triage-test"},
			{"x-oDD-CasE", "casing-probe"},
			{"X-Dup", "first"},
			{"X-Dup", "second"},
		},
	}
	req, err := tmpl.NewRequest(context.Background())
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	got := raw()
	if !strings.Contains(got, "x-oDD-CasE: casing-probe\r\n") {
		t.Errorf("the exact field name did not reach the socket; a casing probe measured nothing.\nwhole request:\n%s", got)
	}
	if n := strings.Count(got, "X-Dup: "); n != 2 {
		t.Errorf("%d copies of X-Dup reached the socket, want 2; HPP is defined by sending the same name twice.\nwhole request:\n%s", n, got)
	}
	for _, want := range []string{"X-Dup: first\r\n", "X-Dup: second\r\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the socket bytes are missing %q.\nwhole request:\n%s", want, got)
		}
	}
}

// PayloadWire.Container claims to be what the transport actually wrote, and that claim is what
// makes a dropped byte detectable. It has to hold against the socket, not against the string the
// encoder built a moment before net/http touched it.
func TestTheRecordedContainerIsTheBytesTheTransportActuallyWrote(t *testing.T) {
	for _, kind := range []triage.SlotKind{triage.KindQuery, triage.KindPath, triage.KindCookie, triage.KindHeader, triage.KindBody} {
		t.Run(string(kind), func(t *testing.T) {
			addr, raw := triageSocketMirror(t)
			tmpl, slot := triageTemplateFor("http://"+addr, kind)
			enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("aa'bb"), triage.SlotOverrides{})
			if !enc.Delivered {
				t.Fatalf("refused: %s", enc.Detail)
			}
			if err := triageSend(t, enc); err != nil {
				t.Fatalf("send: %v", err)
			}
			got := raw()
			if len(enc.Wire.Container) == 0 {
				t.Fatalf("no container recorded, so a dropped byte would be invisible")
			}
			if !strings.Contains(got, string(enc.Wire.Container)) {
				t.Errorf("the recorded container %q is not in the bytes the transport wrote.\nwhole request:\n%s", enc.Wire.Container, got)
			}
		})
	}
}

// The case that proves the point. The slot names its header in lower case while the captured
// request spells it X-Target, so the encoder's own rendering and the bytes on the wire disagree
// about the field name, and only one of the two was ever sent.
func TestTheContainerFollowsTheWireWhenTheSlotAndTheTemplateSpellTheHeaderDifferently(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl, slot := triageTemplateFor("http://"+addr, triage.KindHeader)
	slot.Name = "x-target"

	enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("aa'bb"), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if err := triageSend(t, enc); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := raw()
	if !strings.Contains(got, string(enc.Wire.Container)) {
		t.Errorf("the recorded container %q was never on the wire.\nwhole request:\n%s", enc.Wire.Container, got)
	}
	if enc.Wire.Survived == triage.WireSurvivalUnknown {
		t.Errorf("survival was left unknown on a delivered payload")
	}
}

// A container net/http never wrote must not read as an intact payload. This is the fail-closed
// half: if the field cannot be found in the serialized request, the probe is dropped, not clean.
func TestAContainerTheTransportDidNotWriteIsNotIntact(t *testing.T) {
	tmpl, slot := triageTemplateFor("http://127.0.0.1:1/x", triage.KindHeader)
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("aa'bb"), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	wire := enc.Wire
	wire.Container = []byte("X-Target: something-else-entirely")
	if got, _ := CheckFidelity(wire); got == triage.WireSurvivalIntact {
		t.Errorf("a payload absent from its container read as intact")
	}
}

// net/http writes its own User-Agent unless it finds one under the EXACT canonical key, so a
// probe that spells the field user-AGENT gets its line plus Go's default, and the class that was
// measuring the spelling of one header has silently sent two.
func TestACasedUserAgentDoesNotArriveAlongsideGosDefault(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{
		Method:  http.MethodGet,
		URL:     "http://" + addr + "/probe",
		Headers: [][2]string{{"user-AGENT", "probe-ua"}},
	}
	req, err := tmpl.NewRequest(context.Background())
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	got := raw()
	if !strings.Contains(got, "user-AGENT: probe-ua\r\n") {
		t.Errorf("the cased User-Agent did not reach the socket.\nwhole request:\n%s", got)
	}
	if strings.Contains(got, "Go-http-client") {
		t.Errorf("net/http added its own User-Agent beside the probe's, so the request carries two.\nwhole request:\n%s", got)
	}
}

// ---------------------------------------------------------------------------------------------
// residual 1: header ORDER, and residual 2: the Accept-Encoding nobody asked for
// ---------------------------------------------------------------------------------------------

// triageOrderedHeaderLines returns the field names of a raw request, in the order they appear on
// the socket, skipping the request line. It is deliberately dumb: it splits on CRLF and takes the
// text before the first colon, because that is what a server's parser sees.
func triageOrderedHeaderLines(raw string) []string {
	head, _, _ := strings.Cut(raw, "\r\n\r\n")
	lines := strings.Split(head, "\r\n")
	var out []string
	for _, line := range lines[1:] {
		name, _, ok := strings.Cut(line, ":")
		if ok {
			out = append(out, name)
		}
	}
	return out
}

// triageSendVia sends a template down whichever path it declares and drains the response.
func triageSendVia(t *testing.T, tmpl RequestTemplate) error {
	t.Helper()
	resp, err := Send(context.Background(), tmpl)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// THE MEASUREMENT. On this machine, go1.26.1, a template declaring
//
//	x-Custom-Case, Z-Last, A-First, User-Agent, M-Middle
//
// arrives as Host, User-Agent, A-First, M-Middle, Z-Last, x-Custom-Case: net/http's
// Header.writeSubset sorts. Three classes are defined by order. HPP is which duplicate a backend
// takes, CRLF is about the literal field sequence the parser walks, and request smuggling is
// entirely about which of Content-Length and Transfer-Encoding comes first.
func TestNetHttpSortsHeadersWhichIsWhyTheOrderedPathExists(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{
		Method: http.MethodGet,
		URL:    "http://" + addr + "/probe",
		Headers: [][2]string{
			{"x-Custom-Case", "one"},
			{"Z-Last", "two"},
			{"A-First", "three"},
			{"User-Agent", "triage-test"},
			{"M-Middle", "four"},
		},
	}
	if err := triageSendVia(t, tmpl); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := triageOrderedHeaderLines(raw())
	if len(got) == 0 || got[len(got)-1] != "x-Custom-Case" {
		t.Skipf("net/http no longer sorts this way; got %v. The ordered path is still the guarantee.", got)
	}
	if HeaderOrderIsGuaranteed(tmpl) {
		t.Errorf("the template claims header order is guaranteed on the net/http path, and the socket says it is not: %v", got)
	}
}

// The fix. A class that declares RequireHeaderOrder gets the bytes it wrote, in the order it
// wrote them, because they are written to the connection by this package and not by net/http.
func TestADeclaredOrderReachesTheSocketInThatExactOrder(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{
		Method: http.MethodGet,
		URL:    "http://" + addr + "/probe",
		Headers: [][2]string{
			{"x-Custom-Case", "one"},
			{"Z-Last", "two"},
			{"A-First", "three"},
			{"User-Agent", "triage-test"},
			{"M-Middle", "four"},
		},
		RequireHeaderOrder: true,
	}
	if !HeaderOrderIsGuaranteed(tmpl) {
		t.Fatalf("a template that requires header order does not report the guarantee")
	}
	if err := triageSendVia(t, tmpl); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := triageOrderedHeaderLines(raw())
	want := []string{"Host", "x-Custom-Case", "Z-Last", "A-First", "User-Agent", "M-Middle"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("header order on the socket\n got  %v\n want %v", got, want)
	}
}

// Order is not the only thing the ordered path has to keep: it must not lose the exact spelling
// of a name, a second copy of one, or the body.
func TestTheOrderedPathKeepsCasingDuplicatesAndTheBody(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{
		Method: http.MethodPost,
		URL:    "http://" + addr + "/probe?a=1",
		Headers: [][2]string{
			{"x-oDD-CasE", "casing-probe"},
			{"X-Dup", "first"},
			{"X-Dup", "second"},
			{"Content-Type", "text/plain"},
		},
		Body:               []byte("payload'body"),
		RequireHeaderOrder: true,
	}
	if err := triageSendVia(t, tmpl); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := raw()
	for _, want := range []string{
		"POST /probe?a=1 HTTP/1.1\r\n",
		"x-oDD-CasE: casing-probe\r\n",
		"X-Dup: first\r\n",
		"X-Dup: second\r\n",
		"Content-Length: 12\r\n",
		"payload'body",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the ordered path lost %q.\nwhole request:\n%s", want, got)
		}
	}
	if n := strings.Count(got, "X-Dup: "); n != 2 {
		t.Errorf("%d copies of X-Dup on the socket, want 2.\nwhole request:\n%s", n, got)
	}
}

// A class that declares a Content-Length or a Transfer-Encoding owns it. The ordered path
// supplies a Content-Length only when the template declared neither, because a second copy of
// either field IS the request smuggling probe.
func TestTheOrderedPathDoesNotOverrideAFramingHeaderTheClassDeclared(t *testing.T) {
	tmpl := RequestTemplate{
		Method: http.MethodPost,
		URL:    "http://127.0.0.1:1/probe",
		Headers: [][2]string{
			{"Content-Length", "12"},
			{"Transfer-Encoding", "chunked"},
		},
		Body:               []byte("payload'body"),
		RequireHeaderOrder: true,
	}
	wire, err := SerializeOrdered(tmpl)
	if err != nil {
		t.Fatalf("SerializeOrdered: %v", err)
	}
	if n := bytes.Count(wire, []byte("Content-Length:")); n != 1 {
		t.Errorf("%d Content-Length fields, want the one the class declared.\n%s", n, wire)
	}
	if n := bytes.Count(wire, []byte("Transfer-Encoding:")); n != 1 {
		t.Errorf("%d Transfer-Encoding fields, want the one the class declared.\n%s", n, wire)
	}
	if i, j := bytes.Index(wire, []byte("Content-Length:")), bytes.Index(wire, []byte("Transfer-Encoding:")); i > j {
		t.Errorf("the two framing fields were reordered, which is the whole probe.\n%s", wire)
	}
}

// Residual 2. net/http's transport adds Accept-Encoding: gzip to any request that does not
// already carry one. That is an extra variable in every comparison, and it can change the
// response body independently of the payload.
func TestTheDefaultClientAddsAnAcceptEncodingTheClassNeverAsked(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{Method: http.MethodGet, URL: "http://" + addr + "/probe"}
	req, err := tmpl.NewRequest(context.Background())
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if !strings.Contains(raw(), "Accept-Encoding: gzip") {
		t.Skip("net/http no longer adds Accept-Encoding; the hazard this guards is gone")
	}
}

// The fix, on BOTH paths. Neither the triage client nor the ordered writer may add a header the
// class did not declare.
func TestNoPathAddsAnAcceptEncodingTheClassNeverAsked(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		name := "nethttp"
		if ordered {
			name = "ordered"
		}
		t.Run(name, func(t *testing.T) {
			addr, raw := triageSocketMirror(t)
			tmpl := RequestTemplate{
				Method:             http.MethodGet,
				URL:                "http://" + addr + "/probe",
				RequireHeaderOrder: ordered,
			}
			if err := triageSendVia(t, tmpl); err != nil {
				t.Fatalf("send: %v", err)
			}
			got := raw()
			if strings.Contains(strings.ToLower(got), "accept-encoding") {
				t.Errorf("an Accept-Encoding the class never asked for reached the socket.\nwhole request:\n%s", got)
			}
		})
	}
}

// A class that DOES want an encoding still gets exactly the one it asked for, once.
func TestAnAcceptEncodingTheClassDidAskForIsSentOnceAndUnchanged(t *testing.T) {
	for _, ordered := range []bool{false, true} {
		name := "nethttp"
		if ordered {
			name = "ordered"
		}
		t.Run(name, func(t *testing.T) {
			addr, raw := triageSocketMirror(t)
			tmpl := RequestTemplate{
				Method:             http.MethodGet,
				URL:                "http://" + addr + "/probe",
				Headers:            [][2]string{{"Accept-Encoding", "br"}},
				RequireHeaderOrder: ordered,
			}
			if err := triageSendVia(t, tmpl); err != nil {
				t.Fatalf("send: %v", err)
			}
			got := raw()
			if n := strings.Count(strings.ToLower(got), "accept-encoding:"); n != 1 {
				t.Errorf("%d Accept-Encoding fields, want 1.\nwhole request:\n%s", n, got)
			}
			if !strings.Contains(got, "Accept-Encoding: br\r\n") {
				t.Errorf("the declared Accept-Encoding was rewritten.\nwhole request:\n%s", got)
			}
		})
	}
}

// The ordered path is still a real HTTP client: it has to come back with a parsed response, and
// it has to work over TLS, or the classes that need order could only probe plaintext.
func TestTheOrderedPathReadsARealResponseIncludingOverTLS(t *testing.T) {
	for _, tlsOn := range []bool{false, true} {
		name := "http"
		if tlsOn {
			name = "https"
		}
		t.Run(name, func(t *testing.T) {
			h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Echo", r.Header.Get("X-Probe"))
				w.WriteHeader(http.StatusTeapot)
				io.WriteString(w, "body-back")
			})
			var srv *httptest.Server
			if tlsOn {
				srv = httptest.NewTLSServer(h)
			} else {
				srv = httptest.NewServer(h)
			}
			defer srv.Close()
			tmpl := RequestTemplate{
				Method:             http.MethodGet,
				URL:                srv.URL + "/probe",
				Headers:            [][2]string{{"X-Probe", "hello"}},
				RequireHeaderOrder: true,
			}
			resp, err := SendOrdered(context.Background(), tmpl)
			if err != nil {
				t.Fatalf("SendOrdered: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusTeapot {
				t.Errorf("status %d, want 418", resp.StatusCode)
			}
			if got := resp.Header.Get("X-Echo"); got != "hello" {
				t.Errorf("X-Echo %q, want hello", got)
			}
			if string(body) != "body-back" {
				t.Errorf("body %q, want body-back", body)
			}
		})
	}
}

// Fail closed. A class that declared it needs ordered headers must never be silently downgraded
// onto the sorting path: a scheme the ordered writer cannot speak is an error the caller turns
// into an honest unknown, not a response.
func TestARequiredOrderIsNeverSilentlyDowngraded(t *testing.T) {
	tmpl := RequestTemplate{
		Method:             http.MethodGet,
		URL:                "ftp://127.0.0.1:1/probe",
		RequireHeaderOrder: true,
	}
	if _, err := Send(context.Background(), tmpl); err == nil {
		t.Fatalf("a scheme the ordered writer cannot speak returned a response instead of an error")
	}
}

// The capability flag survives a Clone, or a class that declared it would lose the declaration
// the moment the encoder copied the template.
func TestCloneCarriesTheHeaderOrderDeclaration(t *testing.T) {
	tmpl := RequestTemplate{Method: http.MethodGet, URL: "http://127.0.0.1:1/x", RequireHeaderOrder: true}
	if !tmpl.Clone().RequireHeaderOrder {
		t.Errorf("Clone dropped RequireHeaderOrder, so an encoded probe would silently take the sorting path")
	}
	enc := EncodeSlotInto(tmpl, triage.Slot{}, triage.EncodeNone, []byte("x"), triage.SlotOverrides{})
	_ = enc
}

// The ordered path writes the bytes itself, which is exactly how it could become an accidental
// request splitter. It must refuse the same header values net/http refuses, or a class would
// get a different answer depending on a flag it set for an unrelated reason, and a CRLF the
// encoder already declared undeliverable would go out anyway.
func TestTheOrderedPathRefusesTheSameHeaderValuesNetHttpRefuses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"crlf", "a\r\nX-Injected: yes"},
		{"lf", "a\nX-Injected: yes"},
		{"nul", "a\x00b"},
		{"control", "a\x07b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl := RequestTemplate{
				Method:             http.MethodGet,
				URL:                "http://127.0.0.1:1/probe",
				Headers:            [][2]string{{"X-Probe", tc.value}},
				RequireHeaderOrder: true,
			}
			wire, err := SerializeOrdered(tmpl)
			if err == nil {
				t.Fatalf("the ordered writer emitted a request carrying %q:\n%s", tc.value, wire)
			}
			if strings.Contains(err.Error(), "X-Injected") {
				t.Errorf("the refusal message quotes the injected field, which is fine, but check it names a reason: %v", err)
			}
		})
	}
}

// A header name that is not an RFC 7230 token is refused too. net/http errors on one at send
// time, so the ordered path does not get to be the lenient one.
func TestTheOrderedPathRefusesAHeaderNameThatIsNotAToken(t *testing.T) {
	for _, name := range []string{"X Probe", "X:Probe", "X\rProbe", ""} {
		tmpl := RequestTemplate{
			Method:             http.MethodGet,
			URL:                "http://127.0.0.1:1/probe",
			Headers:            [][2]string{{name, "v"}},
			RequireHeaderOrder: true,
		}
		if wire, err := SerializeOrdered(tmpl); err == nil {
			t.Errorf("header name %q was written to the wire:\n%s", name, wire)
		}
	}
}

// A template that declares its own Host keeps it where it put it, because the position of that
// field is itself a probe on some front ends.
func TestADeclaredHostKeepsItsPositionAndIsNotDuplicated(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl := RequestTemplate{
		Method: http.MethodGet,
		URL:    "http://" + addr + "/probe",
		Headers: [][2]string{
			{"X-Before", "1"},
			{"Host", "spoofed.example"},
			{"X-After", "2"},
		},
		RequireHeaderOrder: true,
	}
	if err := triageSendVia(t, tmpl); err != nil {
		t.Fatalf("send: %v", err)
	}
	got := raw()
	if n := strings.Count(got, "Host: "); n != 1 {
		t.Errorf("%d Host fields, want the one the class declared.\nwhole request:\n%s", n, got)
	}
	if !strings.Contains(got, "Host: spoofed.example\r\n") {
		t.Errorf("the declared Host was replaced by the dial target.\nwhole request:\n%s", got)
	}
	want := []string{"X-Before", "Host", "X-After"}
	if names := triageOrderedHeaderLines(got); strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("the Host field moved\n got  %v\n want %v", names, want)
	}
}

// The recorded container has to come from the writer that will actually send the request. If it
// came from net/http's serializer while the ordered writer did the sending, PayloadWire.Container
// would be a claim about bytes nobody wrote.
func TestTheRecordedContainerFollowsTheOrderedWriterWhenOrderIsRequired(t *testing.T) {
	addr, raw := triageSocketMirror(t)
	tmpl, slot := triageTemplateFor("http://"+addr, triage.KindHeader)
	tmpl.RequireHeaderOrder = true
	enc := EncodeSlotInto(tmpl, slot, triage.EncodeNone, []byte("aa'bb"), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("refused: %s", enc.Detail)
	}
	if !enc.Req.RequireHeaderOrder {
		t.Fatalf("the encode dropped the ordered declaration, so the probe would take the sorting path")
	}
	resp, err := enc.Send(context.Background())
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	got := raw()
	if len(enc.Wire.Container) == 0 {
		t.Fatalf("no container recorded, so a dropped byte would be invisible")
	}
	if !strings.Contains(got, string(enc.Wire.Container)) {
		t.Errorf("the recorded container %q is not in the bytes the ordered writer sent.\nwhole request:\n%s", enc.Wire.Container, got)
	}
}

// ---------------------------------------------------------------------------------------------
// HEADER ORDER: THE FIELD THAT DOCUMENTED ITSELF AS TRUE AND WAS NOT
// ---------------------------------------------------------------------------------------------

// Observation.ReqHeaders used to be documented as "ordered, duplicates preserved", with no
// condition attached, while AttachEncode filled it from the TEMPLATE on both send paths. On the
// default path net/http reorders the fields on the way out. So a classifier read an order that
// had never existed on any socket, recorded it confidently, and nothing said which path had been
// taken.
//
// This test measures the disagreement rather than asserting it, because the whole bug was
// somebody believing a sentence about net/http instead of running it. If a future toolchain stops
// reordering, the measurement says so and the test fails with a message explaining that the
// premise changed, rather than quietly passing on an assertion that no longer means anything.
func TestTheDefaultPathReordersHeadersAndTheObservationSaysSo(t *testing.T) {
	srv, _ := triageEchoServer(t)
	declared := [][2]string{
		{"x-Custom-Case", "one"},
		{"Z-Last", "two"},
		{"A-First", "three"},
		{"User-Agent", "triage-test"},
		{"M-Middle", "four"},
	}
	tmpl := RequestTemplate{Method: http.MethodGet, URL: srv.URL + "/probe?q=v", Headers: declared}
	slot := triage.Slot{Key: "query:q", Kind: triage.KindQuery, Name: "q", ServerReachable: true}

	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("payload"), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("encode refused: %s %s", enc.Reason, enc.Detail)
	}
	var obs triage.Observation
	if err := AttachEncode(&obs, enc); err != nil {
		t.Fatalf("attach: %v", err)
	}

	// THE PREMISE, MEASURED. The default path is not the declared order.
	if obs.ReqHeaderOrder != triage.HeaderOrderNetHTTPSorted {
		t.Fatalf("the observation records send path %q, want %q: a template that does not declare RequireHeaderOrder goes through net/http",
			obs.ReqHeaderOrder, triage.HeaderOrderNetHTTPSorted)
	}
	wire, ok := obs.WireHeaders()
	if !ok {
		t.Fatal("the wire order was not recorded on a delivered encode, so a class asking what actually went out gets nothing")
	}
	if len(wire) == 0 {
		t.Fatal("the recorded wire order is empty, so nothing was measured")
	}

	declaredNames := headerNamesOf(obs.ReqHeaders)
	wireNames := headerNamesOf(wire)
	if reflect.DeepEqual(declaredNames, wireNames) {
		t.Fatalf("the declared order %v and the measured wire order %v are the same on the DEFAULT path. This test exists because they were not, and the whole point of recording the path is that they disagree. If net/http has stopped sorting, say so deliberately rather than deleting this test",
			declaredNames, wireNames)
	}
	t.Logf("declared %v\nwire     %v", declaredNames, wireNames)

	// And the recorded order is the REAL one: Host first, then User-Agent, then byte-sorted.
	if len(wireNames) < 3 || wireNames[0] != "Host" || wireNames[1] != "User-Agent" {
		t.Errorf("the measured wire order starts %v; net/http writes Host then User-Agent first, so the measurement is not reading the serialized request", wireNames)
	}
	rest := append([]string(nil), wireNames[2:]...)
	sorted := append([]string(nil), rest...)
	sort.Strings(sorted)
	if !reflect.DeepEqual(rest, sorted) {
		t.Errorf("the fields after User-Agent are %v, which is not byte-sorted; the measurement is not reading what net/http wrote", rest)
	}

	// ReqHeaders is still the DECLARED list, duplicates and spelling preserved, because three
	// classes need to know what was asked for as well as what went out.
	if !reflect.DeepEqual(obs.ReqHeaders, declared) {
		t.Errorf("ReqHeaders = %v, want the declared list %v", obs.ReqHeaders, declared)
	}
}

// The ordered path makes ReqHeaders true, and the observation says which one it took.
func TestTheOrderedPathRecordsTheDeclaredOrderAsTheWireOrder(t *testing.T) {
	srv, _ := triageEchoServer(t)
	declared := [][2]string{
		{"x-Custom-Case", "one"},
		{"Z-Last", "two"},
		{"A-First", "three"},
		{"Content-Length", "0"},
		{"Transfer-Encoding", "chunked"},
	}
	tmpl := RequestTemplate{
		Method: http.MethodGet, URL: srv.URL + "/probe?q=v", Headers: declared,
		RequireHeaderOrder: true,
	}
	slot := triage.Slot{Key: "query:q", Kind: triage.KindQuery, Name: "q", ServerReachable: true}

	enc := EncodeSlotInto(tmpl, slot, triage.EncodeQuery, []byte("payload"), triage.SlotOverrides{})
	if !enc.Delivered {
		t.Fatalf("encode refused: %s %s", enc.Reason, enc.Detail)
	}
	var obs triage.Observation
	if err := AttachEncode(&obs, enc); err != nil {
		t.Fatalf("attach: %v", err)
	}

	if obs.ReqHeaderOrder != triage.HeaderOrderAsDeclared {
		t.Fatalf("send path = %q, want %q on a template declaring RequireHeaderOrder", obs.ReqHeaderOrder, triage.HeaderOrderAsDeclared)
	}
	if !obs.ReqHeaderOrder.DeclaredOrderHeld() {
		t.Error("DeclaredOrderHeld said false on the ordered path, so an HPP or smuggling class would emit cannot_determine on a request whose order was guaranteed")
	}
	wire, ok := obs.WireHeaders()
	if !ok {
		t.Fatal("the ordered path recorded no wire order")
	}
	// The ordered writer prepends Host when the template declares none, because a request is not
	// valid without one. That IS what went out, so it is what the observation records, and the
	// comparison drops exactly that one synthesized field rather than pretending it is absent.
	got := headerNamesOf(wire)
	if len(got) == 0 || got[0] != "Host" {
		t.Fatalf("the ordered path wrote %v; a template declaring no Host gets one written first", got)
	}
	// Content-Length before Transfer-Encoding is the whole smuggling probe, so the assertion is
	// on the order of those two and not merely on the set of names.
	if want := headerNamesOf(declared); !reflect.DeepEqual(got[1:], want) {
		t.Errorf("the ordered path put %v on the wire after Host, want the declared %v", got[1:], want)
	}
	if !reflect.DeepEqual(obs.ReqHeaders, declared) {
		t.Errorf("ReqHeaders = %v, want the declared list %v", obs.ReqHeaders, declared)
	}
}

// NOT KNOWING IS NOT CLEAN, applied to header order.
//
// The zero value of the new field is unrecorded, and every predicate on it answers "no" rather
// than "fine". A class that reads WireHeaders on an observation nobody measured gets a false, not
// an empty list it could mistake for a request with no headers.
func TestAnUnrecordedHeaderOrderNeverReadsAsMeasured(t *testing.T) {
	var zero triage.Observation
	if zero.ReqHeaderOrder != triage.HeaderOrderUnrecorded {
		t.Errorf("the zero value of ReqHeaderOrder is %q, want the unrecorded value", zero.ReqHeaderOrder)
	}
	if zero.ReqHeaderOrder.Recorded() {
		t.Error("an unrecorded header order reported as recorded")
	}
	if zero.ReqHeaderOrder.DeclaredOrderHeld() {
		t.Error("an unrecorded header order reported that the declared order held, which is how a smuggling class reasons about a list nothing ever sent")
	}
	if _, ok := zero.WireHeaders(); ok {
		t.Error("WireHeaders reported a measurement on a zero observation")
	}

	// And an observation carrying a path but no measured list still fails closed, because the two
	// fields are set together and a half-filled pair is a bug rather than a fact.
	half := triage.Observation{ReqHeaderOrder: triage.HeaderOrderAsDeclared}
	if _, ok := half.WireHeaders(); ok {
		t.Error("WireHeaders reported a measurement with no list behind it")
	}
}

// headerNamesOf is the field names in order, which is the property under test.
func headerNamesOf(h [][2]string) []string {
	out := make([]string, 0, len(h))
	for _, kv := range h {
		out = append(out, kv[0])
	}
	return out
}
