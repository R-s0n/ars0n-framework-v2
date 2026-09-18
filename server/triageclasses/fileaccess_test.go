package triageclasses

import (
	"bytes"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"

	"ars0n-framework-v2-server/utils/triage"
)

// Tests for the FILE-ACCESS FAMILY'S SHARED MECHANISM.
//
// WHAT CANNOT BE TESTED FROM HERE, STATED ONCE SO NOBODY READS THESE TESTS AS COVERING IT.
// Perturbed and Replay can only be constructed by a holder of the runner capability, which lives
// in server/utils/internal/triagecap and which this package cannot import BY DESIGN. So a test in
// this package cannot hand a classifier a ctx containing responses, which means Classify's
// oracle branches and Plan's ladder past round 0 are not exercisable here. What is exercised is
// (a) every detection RULE, directly, as the pure function it is, with the named false positives
// as first-class rows, and (b) every path through Classify that a ctx with NO responses can
// reach, which is exactly the set of paths where the bug being guarded against lives: a class
// that measured nothing and said clean. The gap is real and is reported rather than hidden;
// closing it needs a test hook in package triage that mints a Perturbed for a fixture.

const faTestMarker = triage.Marker("zqjdf3q000a1kx9m")

// The substitution contract has to render the exact bytes the catalogue rows specify, because
// this family is one where "close enough" sends a different payload. The overlong row is the
// reason the whole contract exists.
func TestTheSubstitutionContractRendersTheExactBytesEachCatalogueRowSpecifies(t *testing.T) {
	sub := faSubst{Value: "docs/report.pdf", Dir: "docs/", Ext: ".pdf", Script: "view.php", Sibling: "admin", OOB: "oob.example.net"}
	for _, tc := range []struct {
		name    string
		logical string
		want    string
	}{
		{"the self neutralising escape keeps the observed value", faTokMarker + "/../" + faTokValue,
			"zqjdf3q000a1kx9m/../docs/report.pdf"},
		{"the prefix preserving form keeps only the directory", faTokDir + "../../etc/passwd",
			"docs/../../etc/passwd"},
		{"the null truncation form appends the observed extension", "/etc/passwd\x00" + faTokExt,
			"/etc/passwd\x00.pdf"},
		{"the wrapper form names the application's own script", lfiFilterPrefix + faTokScript,
			lfiFilterPrefix + "view.php"},
		{"the remote include form names the collaborator", "http://" + faTokMarker + "." + faTokOOB + "/f.txt",
			"http://zqjdf3q000a1kx9m.oob.example.net/f.txt"},
		{"the sibling escape names a route and not a file", faTokSibling + "/../" + faTokValue,
			"admin/../docs/report.pdf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(faRender([]byte(tc.logical), faTestMarker, sub))
			if got != tc.want {
				t.Errorf("rendered %q, want %q", got, tc.want)
			}
		})
	}
}

// The base64 marker token must render the base64 of the marker and not the marker, because the
// entire data:// oracle rests on the plaintext never having been in the request.
func TestTheBase64MarkerTokenSendsTheEncodedFormAndNotThePlaintext(t *testing.T) {
	got := string(faRender([]byte("data://text/plain;base64,"+faTokMarkerB64), faTestMarker, faSubst{}))
	want := "data://text/plain;base64," + base64.StdEncoding.EncodeToString([]byte(faTestMarker))
	if got != want {
		t.Fatalf("rendered %q, want %q", got, want)
	}
	if strings.Contains(got, string(faTestMarker)) {
		t.Error("the rendered payload contains the plaintext marker, which destroys the data:// oracle: " +
			"the whole claim is that those sixteen bytes were never in the request")
	}
}

// ${m64} must not be eaten by ${m}. A substitution order bug here would send the raw marker where
// the base64 belongs and the oracle would silently become a reflection test.
func TestTheLongerMarkerTokenIsSubstitutedBeforeTheShorterOne(t *testing.T) {
	got := string(faRender([]byte(faTokMarkerB64), faTestMarker, faSubst{}))
	if got == string(faTestMarker)+"64}" {
		t.Fatal("${m} matched inside ${m64}, so the base64 token rendered as the raw marker followed by literal text")
	}
	if got != base64.StdEncoding.EncodeToString([]byte(faTestMarker)) {
		t.Fatalf("rendered %q", got)
	}
}

// THE FAIL-CLOSED GATE. This is the test that matters most in this file: a probe whose template
// was never substituted went out as a template and tested nothing, and it must never be counted.
func TestAProbeWhoseTemplateReachedTheWireIsNotHonestAndCannotBeCounted(t *testing.T) {
	for _, tc := range []struct {
		name string
		obs  triage.Observation
		want bool
	}{
		{
			name: "a fully rendered payload that the transport delivered is honest",
			obs: triage.Observation{
				Payload: triage.PayloadWire{
					Logical: []byte("../../etc/passwd"), Wire: []byte("..%2F..%2Fetc%2Fpasswd"),
					Survived: triage.WireSurvivalEncoded,
				},
			},
			want: true,
		},
		{
			name: "an unsubstituted collaborator token on the wire is not honest",
			obs: triage.Observation{
				Payload: triage.PayloadWire{
					Logical: []byte("http://m.${oob}/f.txt"), Wire: []byte("http://m.$%7Boob%7D/f.txt"),
					Survived: triage.WireSurvivalEncoded,
				},
			},
			want: false,
		},
		{
			name: "an unsubstituted token in the logical record is not honest even when the wire looks clean",
			obs: triage.Observation{
				Payload: triage.PayloadWire{
					Logical: []byte("/etc/passwd\x00${ext}"), Wire: []byte("harmless"),
					Survived: triage.WireSurvivalIntact,
				},
			},
			want: false,
		},
		{
			name: "a transport error is not honest",
			obs: triage.Observation{
				TransportErr: triage.TransportInvalidHeader,
				Payload:      triage.PayloadWire{Logical: []byte("x"), Wire: []byte("x"), Survived: triage.WireSurvivalRefused},
			},
			want: false,
		},
		{
			name: "an unrecorded wire survival is not honest, because nobody measured whether it arrived",
			obs: triage.Observation{
				Payload: triage.PayloadWire{Logical: []byte("x"), Wire: []byte("x")},
			},
			want: false,
		},
		{
			name: "a payload something else altered is not honest, because we would be scoring a different payload",
			obs: triage.Observation{
				Payload: triage.PayloadWire{Logical: []byte("x"), Wire: []byte("y"), Survived: triage.WireSurvivalAltered},
			},
			want: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			why, got := faWireIsHonest(tc.obs)
			if got != tc.want {
				t.Fatalf("faWireIsHonest = %v (%q), want %v", got, why, tc.want)
			}
			if !got && strings.TrimSpace(why) == "" {
				t.Error("refused with no reason, and an unknown with no reason is how a check that never ran becomes a clean")
			}
		})
	}
}

// The base64 candidate rule is the family's answer to "never search for the base64 of a
// signature", and the rows below are the exact cases that defeated the signature approach.
func TestTheBase64CandidateRuleDecodesRealRunsAndIgnoresTheApplicationsOwn(t *testing.T) {
	passwd := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n" +
		"bin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
	enc := base64.StdEncoding.EncodeToString([]byte(passwd))

	t.Run("a passwd read that came back base64 encoded is decoded and matched on the plaintext", func(t *testing.T) {
		body := []byte("<pre>" + enc + "</pre>")
		found := false
		for _, d := range faDecodedRuns(body, nil) {
			if p, _ := faMatchSignatures(lfiContent, d); len(p) > 0 {
				found = true
			}
		}
		if !found {
			t.Fatal("the base64 candidate rule did not recover a plaintext passwd from its base64, which is the single rule that replaced every base64 signature")
		}
	})

	t.Run("the same run present in the baseline is never decoded, which is what keeps a JWT out", func(t *testing.T) {
		body := []byte("<pre>" + enc + "</pre>")
		for _, d := range faDecodedRuns(body, [][]byte{body}) {
			if p, _ := faMatchSignatures(lfiContent, d); len(p) > 0 {
				t.Fatal("a run that the unperturbed response already carried was decoded and scored, so the application's own blobs are hits")
			}
		}
	})

	t.Run("a JWT and a PNG data URI produce zero hits", func(t *testing.T) {
		// NC-L7 as an offline fixture. A JWT decodes to {"alg", which matches no signature.
		jwt := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT","kid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
		png := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, 20))
		body := []byte(`<img src="data:image/png;base64,` + png + `"><script>t="` + jwt + `"</script>`)
		for _, d := range faDecodedRuns(body, nil) {
			if p, _ := faMatchSignatures(lfiContent, d); len(p) > 0 {
				t.Fatalf("a JWT or a PNG produced a content hit (%q), so the rule is matching noise", p[0].Name)
			}
		}
	})

	t.Run("the rule is bounded so a minified script cannot turn one response into thousands of decodes", func(t *testing.T) {
		var b bytes.Buffer
		for i := 0; i < 500; i++ {
			b.WriteString(strings.Repeat("A", 60) + string(rune('a'+i%26)) + strings.Repeat("B", 20) + " ")
		}
		if got := len(faDecodedRuns(b.Bytes(), nil)); got > faBase64MaxRuns*3 {
			t.Fatalf("decoded %d candidates, which is past the bound of %d runs at three phases each", got, faBase64MaxRuns*3)
		}
	})
}

// The echo strip is what keeps the two blind oracles in this family from firing on an endpoint
// that merely reflects the parameter. It is the one false positive those oracles are exposed to.
func TestTheEchoStripRemovesTheReflectedPayloadSoThreeLengthsStopLookingLikeThreeErrors(t *testing.T) {
	sent := []byte("/etc/shadow")
	body := []byte("<h1>Not found</h1><p>you asked for /etc/shadow</p>")
	got := faEchoStrip(body, sent)
	if bytes.Contains(got, sent) {
		t.Fatalf("the echo survived the strip: %q", got)
	}
	if !bytes.Contains(got, []byte("Not found")) {
		t.Fatalf("the strip removed more than the echo: %q", got)
	}

	t.Run("a run shorter than the floor is coincidence and is left alone", func(t *testing.T) {
		b := []byte("abcdefg and more")
		if !bytes.Equal(faEchoStrip(b, []byte("abcdefg")), b) {
			t.Error("a seven byte common run was stripped, and seven bytes is noise")
		}
	})
}

// faCompare must never call two bodies the same because they are both empty, and must never call
// a response different because a nonce moved. Both mistakes have shipped in this codebase.
func TestTheComparisonRefusesToGuessWhenItHasNothingToCompare(t *testing.T) {
	ok := func(id string, status, bodyLen int) triage.Observation {
		return triage.Observation{ObsID: id, Status: status, BodyLen: bodyLen, Body: bytes.Repeat([]byte("x"), bodyLen)}
	}
	for _, tc := range []struct {
		name string
		a, b triage.Observation
		want faCmp
	}{
		{"an unobserved side is unmeasured and not same", triage.Observation{}, ok("b", 200, 10), faCmpUnmeasured},
		{"two empty bodies are no_body and NOT same", ok("a", 204, 0), ok("b", 204, 0), faCmpNoBody},
		{"different statuses are different", ok("a", 200, 10), ok("b", 404, 10), faCmpDifferent},
		{"a truncated body is degraded, which can never produce a clean",
			triage.Observation{ObsID: "a", Status: 200, BodyLen: 10, BodyTruncated: true}, ok("b", 200, 10), faCmpDegraded},
		{"no projection at all is degraded, because comparing raw bodies would score a nonce as a finding",
			ok("a", 200, 10), ok("b", 200, 10), faCmpDegraded},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := faCompare(tc.a, tc.b); got != tc.want {
				t.Errorf("faCompare = %q, want %q", got, tc.want)
			}
		})
	}

	t.Run("equal normalised hashes are same and unequal ones are different", func(t *testing.T) {
		a := ok("a", 200, 10)
		b := ok("b", 200, 10)
		a.Proj.NormBodySHA256 = [32]byte{1}
		b.Proj.NormBodySHA256 = [32]byte{1}
		if got := faCompare(a, b); got != faCmpSame {
			t.Errorf("faCompare = %q, want same", got)
		}
		b.Proj.NormBodySHA256 = [32]byte{2}
		if got := faCompare(a, b); got != faCmpDifferent {
			t.Errorf("faCompare = %q, want different", got)
		}
	})
}

// The uniform block rule needs THREE distinct payloads, and it must be reached from one class's
// own probes rather than from a cross-class annotation.
func TestUniformBlockNeedsThreeDistinctPayloadsAndNotTwo(t *testing.T) {
	block := []byte("<h1>403 Forbidden</h1>")
	var sha [32]byte
	copy(sha[:], "block")
	mk := func(payload string) triage.Observation {
		return triage.Observation{
			ObsID: payload, Status: 403, Body: block, BodyLen: len(block), BodySHA256: sha,
			Payload: triage.PayloadWire{Wire: []byte(payload), Survived: triage.WireSurvivalIntact},
		}
	}
	if faUniformBlock([]triage.Observation{mk("a"), mk("b")}, nil) {
		t.Error("two identical responses read as a block, and an application with one error page produces that all day")
	}
	if !faUniformBlock([]triage.Observation{mk("a"), mk("b"), mk("c")}, nil) {
		t.Error("three distinct payloads collapsing onto one response did not read as a block")
	}
	t.Run("the same payload sent three times is one payload and not three", func(t *testing.T) {
		if faUniformBlock([]triage.Observation{mk("a"), mk("a"), mk("a")}, nil) {
			t.Error("one payload repeated read as three distinct payloads")
		}
	})
}

// The marker search has to find a marker the application transformed on the way out, or an
// escaping template engine turns a real hit into a clean.
func TestTheMarkerSearchFindsEveryTransformFormItClaimsTo(t *testing.T) {
	m := faTestMarker
	var ncr, u16 bytes.Buffer
	for _, c := range []byte(m) {
		ncr.WriteString("&#" + strconv.Itoa(int(c)) + ";")
		u16.Write([]byte{c, 0x00})
	}
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"raw", "before " + string(m) + " after", "raw"},
		{"case folded", "BEFORE " + strings.ToUpper(string(m)) + " AFTER", "case_folded"},
		{"numeric character references", "x" + ncr.String() + "y", "ncr_decimal"},
		{"utf16le", "x" + u16.String() + "y", "utf16le"},
		{"base64 at phase 0", "x" + base64.StdEncoding.EncodeToString([]byte(m)) + "y", "base64_phase0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form, ok := faByteForm([]byte(tc.body), []byte(m))
			if !ok {
				t.Fatalf("the %s form of the marker was not found, so an application that transforms on the way out turns a hit into a clean", tc.name)
			}
			if form != tc.want {
				t.Errorf("reported form %q, want %q", form, tc.want)
			}
		})
	}
	t.Run("a body without the marker reports nothing, which is what makes the positive rows mean something", func(t *testing.T) {
		if form, ok := faByteForm([]byte("nothing to see zqj here"), []byte(m)); ok {
			t.Errorf("found the marker in a body that does not contain it, as form %q. A detector that matches the anchor trigram alone fires on every negative control in the family", form)
		}
	})
}

// The eligibility rule declines three things and nothing else, and every decline carries a
// reason, because a slot with no verdict row and no explanation reads identically to a slot
// nobody wired up.
func TestEligibilityDeclinesOnlyTheThreeThingsItShouldAndAlwaysSaysWhy(t *testing.T) {
	for _, tc := range []struct {
		name string
		slot triage.Slot
		want bool
	}{
		{"an ordinary query slot is eligible", triage.Slot{Kind: triage.KindQuery, ServerReachable: true}, true},
		{"a fragment is not", triage.Slot{Kind: triage.KindFragment, ServerReachable: true}, false},
		{"a credential is not", triage.Slot{Kind: triage.KindQuery, ServerReachable: true,
			Constraints: triage.SlotConstraints{IsCredential: true}}, false},
		{"a slot the capture never saw leave the browser is not", triage.Slot{Kind: triage.KindQuery}, false},
		{"a numeric value is STILL eligible, because a shape guess that suppresses a probe is a silent zero",
			triage.Slot{Kind: triage.KindQuery, ServerReachable: true, ValueKind: triage.ValueNumeric, Value: "42"}, true},
		{"a uuid value is STILL eligible, for the same reason",
			triage.Slot{Kind: triage.KindQuery, ServerReachable: true, ValueKind: triage.ValueUUID}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := faEligibleSlot(tc.slot)
			if ok != tc.want {
				t.Fatalf("eligible = %v, want %v (reason %q)", ok, tc.want, reason)
			}
			if !ok && strings.TrimSpace(reason) == "" {
				t.Error("declined with no reason")
			}
		})
	}
}

// faSubstFor has to derive DIR and EXT the way the catalogue rows assume, including on a value
// with no directory at all, which is the common case and the one that makes T2L redundant.
func TestTheValueDerivationsMatchWhatTheCataloguesRowsAssume(t *testing.T) {
	for _, tc := range []struct{ value, dir, ext string }{
		{"docs/report.pdf", "docs/", ".pdf"},
		{"report.pdf", "", ".pdf"},
		{"report", "", ""},
		{"a/b/c/", "a/b/c/", ""},
		{"2024.01/report", "2024.01/", ""},
		{`C:\dir\file.txt`, "", ".txt"},
		{"", "", ""},
	} {
		t.Run("value "+tc.value, func(t *testing.T) {
			got := faSubstFor(triage.Slot{Value: tc.value})
			if got.Dir != tc.dir {
				t.Errorf("dir = %q, want %q", got.Dir, tc.dir)
			}
			if got.Ext != tc.ext {
				t.Errorf("ext = %q, want %q", got.Ext, tc.ext)
			}
		})
	}
}

// The Variant map writes every key even when the value is empty, because an absent key and an
// empty one are different facts and the runner must be able to tell them apart.
func TestTheVariantMapWritesEveryKeyEvenWhenTheValueIsEmpty(t *testing.T) {
	v := faVariant(faSubst{})
	for _, k := range []string{"v", "dir", "ext", "script", "sib", "oob", "encoder"} {
		if _, ok := v[k]; !ok {
			t.Errorf("key %q is absent, so the runner cannot tell a value this class did not supply from one that is genuinely empty", k)
		}
	}
}

// faDecodeNote is a shipped admission, not a comment, and it has to survive a refactor that
// "tidies up" an unused constant.
func TestTheMissingInflateStepIsNamedOnEveryLFIVerdictRatherThanHidden(t *testing.T) {
	v := lfiClassifier{}.Classify(triage.ClassifyCtx{PlanCtx: triage.PlanCtx{Slot: triage.Slot{Key: "query:f", Kind: triage.KindQuery, ServerReachable: true}}})
	if len(v) != 1 {
		t.Fatalf("got %d verdicts", len(v))
	}
	note, _ := v[0].Annotations["base64_rule"].(string)
	if !strings.Contains(note, "inflate") {
		t.Fatal("the verdict does not carry the note that the gzip and zlib inflate step is not " +
			"implemented, so an operator would read a clean as covering a gzipped file read that this " +
			"class cannot see")
	}
}
