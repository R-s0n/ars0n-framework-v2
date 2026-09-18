package triageclasses

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// THE FILE-ACCESS FAMILY: shared MECHANISM, and not one shared payload byte.
//
// Three classes live in this family and they are three classes on purpose. TRAVERSAL proves that
// input is concatenated into a path and that the resolved path leaves the directory the
// application intended. LFI proves that input names a file the process then opens, with no escape
// involved. RFI proves that input names a REMOTE file the process fetches AND puts in the
// response. They need different confirmation, they feed different tools, and php.net's own
// documented defaults are why the third one had to be split out: allow_url_include defaults to
// "0" and governs only include/require, while allow_url_fopen defaults to "1", so
// "URL file-access is disabled in the server configuration" refutes a remote include and says
// nothing at all about file_get_contents, fopen, copy, simplexml_load_file, DOMDocument::load or
// getimagesize. CATALOGUE ruling R8.
//
// WHAT THIS FILE HOLDS AND WHAT IT DOES NOT. It holds mechanism: token substitution, base64
// candidate decoding, echo stripping, response comparison, marker-form search. It holds NO
// payload bytes and NO signature table. Each class compiles its own copy of its own signatures
// (CATALOGUE A.2.1 says so in as many words) and declares its own payloads, because the isolation
// law is about what goes on the wire, not about which helper formatted it. A shared regexp that
// two classes both run over their OWN responses cannot make a hit ambiguous; a shared PAYLOAD
// can, and that is the distinction the law is drawing.

// ---------------------------------------------------------------------------------------------
// 1. THE SUBSTITUTION CONTRACT, AND WHY A CLASSIFIER NEEDS ONE AT ALL
// ---------------------------------------------------------------------------------------------
//
// A ProbeSpec's Logical bytes are fixed at declaration time, which is what makes the build-time
// isolation check possible: it compares bytes nobody can change at run time. But four of this
// family's payload shapes are not constant, and every one of them is load-bearing:
//
//	TR-T0   M/../V                        needs the slot's OBSERVED value, or the dot segments
//	                                      have nothing to cancel and the probe stops being
//	                                      self-neutralising, which is its entire purpose
//	TR-T2L  DIR(V)../../../etc/passwd     needs the value's directory prefix, which is the whole
//	                                      point of the start-of-path-validation variant
//	LFI-L10 /etc/passwd + NUL + EXT(V)    needs the extension the application appends
//	RFI-R1  http://M.<oob>/f.txt          needs the collaborator base, which is per run and per
//	                                      install
//
// So the family declares a token vocabulary. The class writes the token into Logical, puts the
// values the runner cannot know into ProbeRequest.Variant, and the runner substitutes before
// encoding. ProbeRequest.Variant is documented for exactly this ("the served OOB filename, the
// injected header name"), so this uses the shape that exists rather than inventing one.
//
// AND IT FAILS CLOSED, WHICH IS THE PART THAT MATTERS. If the runner does not substitute, the
// literal token goes out on the wire, the probe tests nothing, and the class would otherwise
// record a clean for a payload that was never sent. That is the exact bug this whole layer was
// built to stop. So every Classify in this family runs faUnsubstituted over the RECORDED WIRE
// BYTES of each of its own observations first, and any probe whose wire still carries a "${"
// yields cannot_determine (template_not_substituted): never clean, and never a finding either.
const (
	faTokMarker    = "${m}"      // this probe's own 16-byte marker, raw
	faTokMarkerB64 = "${m64}"    // this probe's own marker, standard base64
	faTokValue     = "${v}"      // the slot's observed value, verbatim
	faTokDir       = "${dir}"    // the observed value up to and including its last '/', empty if none
	faTokExt       = "${ext}"    // the observed value's extension including the dot, empty if none
	faTokScript    = "${script}" // the application's own script name, derived from the vector URL
	faTokSibling   = "${sib}"    // a sibling route name from the corpus, for the store-escape probe
	faTokOOB       = "${oob}"    // the configured out-of-band collaborator base host
)

// faTokenOpen is the two bytes every token in this family starts with. Detecting an unsubstituted
// token is a prefix test and not a list-membership test on purpose: a token this file has not
// heard of is still a token that went out raw, and refusing the ones we enumerated while passing
// the one somebody adds next month is the enumeration mistake the import guard's own comment
// spends thirty lines on.
const faTokenOpen = "${"

// faSubst is everything the runner has to know to render one of this family's payloads.
//
// It carries no response and no observation, so a classifier that builds one has not begun to
// hold state: it is constructed inside Plan from the ctx and handed straight back as a Variant
// map.
type faSubst struct {
	Value   string
	Dir     string
	Ext     string
	Script  string
	Sibling string
	OOB     string
	// Encoder names WHICH of the ProbeSpec's declared encoders this instance wants.
	//
	// ProbeRequest has a Spec, a Slot, a Marker and a Variant, and no encoder field, while
	// ProbeSpec.Encoders is a LIST. TRAVERSAL sends the same logical bytes at none, pct_twice and
	// iis_unicode and counts three tests, so "the runner picks one" and "the runner sends all of
	// them" are both wrong: the first loses two thirds of the encoder sweep silently and the
	// second sends pct_twice into a cookie where it buys nothing. Naming the encoder per instance
	// is the only shape that gets the recorded probe count right. Empty means the slot's own
	// natural encoder.
	Encoder string
}

// faSubstFor derives the value-shaped fields from a slot. Marker and marker-base64 are absent by
// design: a class never mints its own marker, and a class that could render one could render
// another class's stripe.
func faSubstFor(s triage.Slot) faSubst {
	v := s.Value
	out := faSubst{Value: v}
	if i := strings.LastIndexByte(v, '/'); i >= 0 {
		out.Dir = v[:i+1]
	}
	// The extension is taken from the LAST path element only, so a value like "2024.01/report"
	// does not yield ".01/report". path.Ext is not used: a slot value is not a filesystem path
	// and path.Ext does not split on a backslash, which this family's Windows payloads need.
	last := v
	if i := strings.LastIndexAny(v, `/\`); i >= 0 {
		last = v[i+1:]
	}
	if i := strings.LastIndexByte(last, '.'); i > 0 {
		out.Ext = last[i:]
	}
	return out
}

// faVariant renders the substitution as the Variant map a ProbeRequest carries.
//
// Empty values are still written. An absent key and a key whose value is the empty string are
// different facts: the first says the class forgot, the second says the slot's value genuinely
// has no directory prefix, and the runner must be able to tell those apart or a missing DIR
// becomes a silently skipped probe.
func faVariant(s faSubst) map[string]string {
	return map[string]string{
		"v":       s.Value,
		"dir":     s.Dir,
		"ext":     s.Ext,
		"script":  s.Script,
		"sib":     s.Sibling,
		"oob":     s.OOB,
		"encoder": s.Encoder,
	}
}

// faRender performs the substitution the runner is contracted to perform.
//
// It exists so the tests can assert the EXACT bytes that reach the wire for every payload in the
// family. A catalogue row saying what should be sent and a test that only checks the template are
// two different things, and the family whose payload carries a raw 0xC0 0xAE is not one where
// "close enough" is a safe distance.
func faRender(logical []byte, m triage.Marker, s faSubst) []byte {
	out := logical
	rep := func(tok, with string) {
		if bytes.Contains(out, []byte(tok)) {
			out = bytes.ReplaceAll(out, []byte(tok), []byte(with))
		}
	}
	// Longest token first, so ${m64} is never eaten by ${m}.
	rep(faTokMarkerB64, base64.StdEncoding.EncodeToString([]byte(m)))
	rep(faTokMarker, string(m))
	rep(faTokScript, s.Script)
	rep(faTokSibling, s.Sibling)
	rep(faTokDir, s.Dir)
	rep(faTokExt, s.Ext)
	rep(faTokOOB, s.OOB)
	rep(faTokValue, s.Value)
	return out
}

// faUnsubstituted reports the first token left in a byte run, which is the fail-closed check.
//
// It is run over the observation's RECORDED WIRE BYTES and over its recorded logical bytes, never
// over the ProbeSpec, because the ProbeSpec always has the token in it. What is being asked is
// what actually left the process.
func faUnsubstituted(b []byte) (string, bool) {
	i := bytes.Index(b, []byte(faTokenOpen))
	if i < 0 {
		return "", false
	}
	end := bytes.IndexByte(b[i:], '}')
	if end < 0 || end > 24 {
		return faTokenOpen, true
	}
	return string(b[i : i+end+1]), true
}

// faWireIsHonest is the whole fail-closed gate in one call. It answers "did the bytes this class
// asked for actually reach the wire", and every reason it can say no is a reason that must become
// an unknown rather than a clean.
//
// The four ways a probe gets recorded as sent while having tested nothing:
//
//	the transport refused it        Delivered() is false, or Survived is refused or dropped
//	a token was never substituted   the template shipped instead of the payload
//	something altered it in flight  Survived is altered, so we would be scoring a different payload
//	nothing was recorded at all     Survived is the zero value, so nobody measured
func faWireIsHonest(o triage.Observation) (string, bool) {
	if !o.Delivered() {
		return fmt.Sprintf("transport_error(%s)", o.TransportErr), false
	}
	if tok, bad := faUnsubstituted(o.Payload.Wire); bad {
		return "template_not_substituted(" + tok + " reached the wire)", false
	}
	if tok, bad := faUnsubstituted(o.Payload.Logical); bad {
		return "template_not_substituted(" + tok + " was never rendered)", false
	}
	switch o.Payload.Survived {
	case triage.WireSurvivalIntact, triage.WireSurvivalEncoded:
		return "", true
	case triage.WireSurvivalUnknown:
		return "wire_survival_unrecorded", false
	default:
		return "wire_survival(" + string(o.Payload.Survived) + ")", false
	}
}

// ---------------------------------------------------------------------------------------------
// 2. THE EXTENSION SURFACE: ORACLE CASES, CONFIRMERS, EVIDENCERS, SETTLE
// ---------------------------------------------------------------------------------------------
//
// Package triage's Classifier interface is five methods and none of them is OracleCases,
// Confirmers, Evidencers or Settle. Those are declared here, in the classifier package, with
// family-private types, for two reasons. The runner cannot call them yet, so putting them in
// package triage would be putting an unused shape into a package this file may not edit. And when
// the runner does grow them, what it needs is exactly this data, one rename away.
//
// They are not decoration. OracleCases is the list of routes the oracle container owes this class
// before its detectors can be called VERIFIED, and CATALOGUE 6.1's whole argument is that the
// SILENT route is the one doing the verifying: a detector only ever observed firing scores the
// same as one that always returns true.

type faOracleExpect string

const (
	// faExpectPositive: this route must make the named detector FIRE.
	faExpectPositive faOracleExpect = "positive"
	// faExpectNegative: this route must make the named detector STAY SILENT. A class with no
	// negative case has not been tested, it has been demonstrated.
	faExpectNegative faOracleExpect = "negative"
)

// faOracleCase is one route the oracle container owes this class.
type faOracleCase struct {
	Name   string
	Route  string
	Expect faOracleExpect
	// Probes names which of this class's own probes the case exercises.
	Probes []triage.ProbeID
	// WantState is the state the class must reach on that route. For a negative case it is
	// frequently NOT clean: /dom/csp and /pp/frozen exist precisely because "the probe did
	// nothing" and "the probe could not run" render identically and mean opposite things.
	WantState triage.TriageState
	// Exists records whether docker/oracle already serves the route, so the oracle pass gets a
	// build list rather than a wish list.
	Exists bool
	Why    string
}

// faConfirmer is a named second measurement that raises or kills a hit.
type faConfirmer struct {
	Name   string
	Probes []triage.ProbeID
	Rule   string
}

// faEvidencer names one thing this class extracts and hands to the operator and to the tool.
type faEvidencer struct {
	Name string
	Kind string // content | error_path | differential | callback | annotation
	What string
}

// faNoSettle is the embedded no-op for a class with no deferred out-of-band check.
//
// It is a method and not an absence so that every class in the family answers the same question
// the same way, and so a reader can see which classes deliberately have nothing to wait for.
type faNoSettle struct{}

// Settle reports that this class has nothing to wait for. TRAVERSAL and LFI are both decided
// entirely from responses that arrive in band, so a deferred pass would have nothing to read.
func (faNoSettle) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }

// ---------------------------------------------------------------------------------------------
// 3. SIGNATURE MATCHING
// ---------------------------------------------------------------------------------------------

// faSignature is one anchored content signature.
type faSignature struct {
	Name string
	Re   *regexp.Regexp
	// Corroborating marks a signature that is NEVER enough on its own. A single "[fonts]" line
	// appears in many ini files and a colon-separated CSV export looks like half of /etc/passwd,
	// so these count only alongside a primary.
	Corroborating bool
}

// faSigHit is a match, with enough offset detail for an operator to find it in the body.
type faSigHit struct {
	Name    string
	Offset  int
	Length  int
	Matched []byte
}

// faMatchSignatures runs a table over a body and returns every primary and corroborating hit.
//
// DISABLED is not the same as SILENT and the caller must be able to tell them apart, so a
// signature present in the baseline is removed by the caller BEFORE the table gets here and the
// caller records which ones it removed. A function that silently skipped them would make "the
// signature was disabled for this endpoint" and "the signature did not match" the same return
// value, and those are a cannot_determine and a clean respectively.
func faMatchSignatures(sigs []faSignature, body []byte) (primary []faSigHit, corroborating []faSigHit) {
	for _, s := range sigs {
		loc := s.Re.FindIndex(body)
		if loc == nil {
			continue
		}
		h := faSigHit{Name: s.Name, Offset: loc[0], Length: loc[1] - loc[0], Matched: body[loc[0]:loc[1]]}
		if s.Corroborating {
			corroborating = append(corroborating, h)
		} else {
			primary = append(primary, h)
		}
	}
	return primary, corroborating
}

// faDisabledByBaseline returns the signatures that must not be used on this endpoint, because
// they already match an unperturbed response.
//
// CATALOGUE FP1, and it is the most common false positive in this whole family: an API
// documentation page showing /etc/passwd, a security-training page, a WAF's own rule catalogue.
// The rule is not "subtract the baseline from the body"; it is "this detector is unusable here",
// and if every detector is unusable the verdict is cannot_determine (signature_in_baseline).
func faDisabledByBaseline(sigs []faSignature, baselines [][]byte) (live []faSignature, disabled []string) {
	for _, s := range sigs {
		hit := false
		for _, b := range baselines {
			if len(b) > 0 && s.Re.Match(b) {
				hit = true
				break
			}
		}
		if hit {
			disabled = append(disabled, s.Name)
			continue
		}
		live = append(live, s)
	}
	return live, disabled
}

// ---------------------------------------------------------------------------------------------
// 4. THE BASE64 CANDIDATE RULE
// ---------------------------------------------------------------------------------------------
//
// VERIFIED, and it is the single most useful detection rule in this family's research: never
// search a response for the base64 of a signature. lfimap's own shipped constant
// c2FtcGxlIEhPU1RTIGZpbGUgIHVzZWQgYnkgTWljcm9zbw decodes to "sample HOSTS file  used by Microso",
// with TWO spaces where the real Windows hosts file has one, and the real file's UTF-8 BOM shifts
// the base64 phase on top of that. A signature built by guessing the plaintext and encoding it is
// wrong more often than it is right.
//
// So: find candidate runs, decode each at all three phase offsets in both alphabets, and run the
// PLAINTEXT signatures on the decoded bytes. That removes the phase problem, the whitespace-guess
// problem and the BOM problem at once.
var faBase64RunRe = regexp.MustCompile(`[A-Za-z0-9+/=_-]{64,}`)

// faBase64MaxRuns bounds the work per response. A page of minified JavaScript is thousands of long
// alphanumeric runs and decoding all of them is a denial of service against ourselves.
const faBase64MaxRuns = 64

// faDecodeNote is what a class records when the base64 rule ran with a known piece missing.
const faDecodeNote = "base64_inflate_not_attempted: the catalogue asks for one gzip or zlib inflate " +
	"of each decoded run, and compress/zlib and compress/gzip are not on the classifier import " +
	"allow-list. A response that base64s a GZIPPED file read is therefore a false negative in this " +
	"family until package triage grows a reviewed inflate helper. Named rather than hidden."

// faDecodedRuns returns the decoded plaintext of every candidate base64 run in body that does not
// appear in any baseline sample.
//
// The baseline filter is what keeps the application's own JWTs, session blobs, CSRF tokens and
// image data URIs out of the candidate set, and it is why NC-L7 (a response containing a JWT and a
// PNG data URI must produce zero hits) is a control this family can actually pass.
func faDecodedRuns(body []byte, baselines [][]byte) [][]byte {
	runs := faBase64RunRe.FindAll(body, -1)
	out := make([][]byte, 0, len(runs))
	seen := map[string]bool{}
	for _, r := range runs {
		if len(out) >= faBase64MaxRuns {
			break
		}
		inBaseline := false
		for _, b := range baselines {
			if bytes.Contains(b, r) {
				inBaseline = true
				break
			}
		}
		if inBaseline {
			continue
		}
		for phase := 0; phase < 3 && phase < len(r); phase++ {
			d, ok := faDecodeB64(r[phase:])
			if !ok || len(d) == 0 {
				continue
			}
			k := string(d)
			if seen[k] {
				continue
			}
			seen[k] = true
			out = append(out, d)
		}
	}
	return out
}

// faDecodeB64 decodes with padding errors tolerated and both alphabets tried, because a real
// response truncates, pads inconsistently, and uses the URL alphabet about as often as the
// standard one.
func faDecodeB64(r []byte) ([]byte, bool) {
	s := strings.TrimRight(string(r), "=")
	// A run shorter than 12 base64 characters cannot hold a signature worth matching and is almost
	// always a fragment of an identifier.
	if len(s) < 12 {
		return nil, false
	}
	// RawStdEncoding refuses a trailing partial group, so trim to a whole number of quanta rather
	// than rejecting the run: a base64 blob embedded in a longer alphanumeric identifier is exactly
	// the shape a real php://filter response has.
	if n := len(s) % 4; n != 0 {
		s = s[:len(s)-n]
	}
	if len(s) < 12 {
		return nil, false
	}
	if d, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return d, true
	}
	if d, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return d, true
	}
	return nil, false
}

// ---------------------------------------------------------------------------------------------
// 5. THE ECHO STRIP
// ---------------------------------------------------------------------------------------------

// faEchoMinRun is the foundations 5.3 floor: a common run shorter than this is coincidence.
const faEchoMinRun = 8

// faEchoStrip removes from the response the longest run of at least faEchoMinRun bytes that the
// response shares with what was sent.
//
// WHY EVERY BLIND COMPARISON IN THIS FAMILY GOES THROUGH IT. The errno oracle compares the
// responses to /etc/shadow, /etc/ and /etc/<marker>. Those three payloads have different lengths
// and different bytes, so an application that merely echoes the parameter produces three different
// responses and the oracle fires on an endpoint that never opened a file. That is FP-L7 and it is
// the one false positive the blind oracle is genuinely exposed to. Stripping the echo first is
// what makes the remaining difference evidence about the filesystem.
//
// It is seeded from the SENT bytes rather than computed as a true longest common substring,
// because the sent bytes are short and the body is up to 512 KiB, and an O(n*m) table over that
// pair is a denial of service against the scanner.
func faEchoStrip(body, sent []byte) []byte {
	run := faLongestEcho(body, sent)
	if len(run) < faEchoMinRun {
		return body
	}
	return bytes.ReplaceAll(body, run, nil)
}

// faLongestEcho finds the longest shared run, or nil.
func faLongestEcho(body, sent []byte) []byte {
	if len(sent) < faEchoMinRun || len(body) == 0 {
		return nil
	}
	var best []byte
	for i := 0; i+faEchoMinRun <= len(sent); i++ {
		seed := sent[i : i+faEchoMinRun]
		at := bytes.Index(body, seed)
		if at < 0 {
			continue
		}
		n := faEchoMinRun
		for i+n < len(sent) && at+n < len(body) && sent[i+n] == body[at+n] {
			n++
		}
		if n > len(best) {
			best = sent[i : i+n]
		}
	}
	return best
}

// ---------------------------------------------------------------------------------------------
// 6. RESPONSE COMPARISON
// ---------------------------------------------------------------------------------------------

type faCmp string

const (
	faCmpSame      faCmp = "same"
	faCmpDifferent faCmp = "different"
	// faCmpNoBody: a 204 or an empty body on both sides. NOT "identical bodies, therefore same":
	// there are no bodies to be identical, so the body differential is unusable and a class with no
	// other oracle owes a cannot_determine (no_body).
	faCmpNoBody faCmp = "no_body"
	// faCmpDegraded: truncated, over the cap, or the projection never ran. CATALOGUE 4.2 caps a
	// degraded comparison at suspicious and forbids it producing clean.
	faCmpDegraded faCmp = "degraded"
	// faCmpUnmeasured: one side was never observed. Distinct from degraded because nothing was even
	// attempted.
	faCmpUnmeasured faCmp = "unmeasured"
)

// faCompare is this family's use of the foundations 5.4 comparison.
//
// It prefers the normalised body hash, which has the volatile regions and the marker forms
// removed, and falls back to the structural projection. It NEVER compares raw bodies when no
// normalised form exists: an endpoint with a request id in the footer differs from itself on every
// request, and a class scoring that as "different" would report a finding on every slot of every
// noisy application. With no projection at all the honest answer is degraded, which can never
// produce a clean.
func faCompare(a, b triage.Observation) faCmp {
	if a.ObsID == "" || b.ObsID == "" {
		return faCmpUnmeasured
	}
	if !a.Delivered() || !b.Delivered() {
		return faCmpUnmeasured
	}
	if a.BodyTruncated || b.BodyTruncated {
		return faCmpDegraded
	}
	if a.Status != b.Status {
		return faCmpDifferent
	}
	if a.BodyLen == 0 && b.BodyLen == 0 {
		return faCmpNoBody
	}
	var zero [32]byte
	if a.Proj.NormBodySHA256 != zero && b.Proj.NormBodySHA256 != zero {
		if a.Proj.NormBodySHA256 == b.Proj.NormBodySHA256 {
			return faCmpSame
		}
		return faCmpDifferent
	}
	if a.Proj.StructSHA256 != zero && b.Proj.StructSHA256 != zero {
		if a.Proj.StructSHA256 == b.Proj.StructSHA256 {
			return faCmpSame
		}
		return faCmpDifferent
	}
	return faCmpDegraded
}

// faCompareStripped is faCompare with the echo removed from both sides first, which is what the
// blind oracles in this family actually need.
//
// It works on the raw bodies because the echo strip is defined over raw bytes, and it is used ONLY
// to decide whether the residual difference is explained by the echo. A "same after strip" answer
// downgrades a differential to masked_only rather than killing it, because the application may be
// echoing and reading at the same time.
func faCompareStripped(a, b triage.Observation) faCmp {
	if a.ObsID == "" || b.ObsID == "" || !a.Delivered() || !b.Delivered() {
		return faCmpUnmeasured
	}
	if a.BodyTruncated || b.BodyTruncated {
		return faCmpDegraded
	}
	if a.Status != b.Status {
		return faCmpDifferent
	}
	sa := faEchoStrip(a.Body, a.Payload.Wire)
	sb := faEchoStrip(b.Body, b.Payload.Wire)
	if len(sa) == 0 && len(sb) == 0 {
		return faCmpNoBody
	}
	if bytes.Equal(sa, sb) {
		return faCmpSame
	}
	return faCmpDifferent
}

// ---------------------------------------------------------------------------------------------
// 7. MARKER FORMS
// ---------------------------------------------------------------------------------------------

// faMarkerForm searches a body for a marker in each transform form the foundations' part 2.5
// search set names, and returns which form was found.
//
// The forms matter to two rules in this family and to nothing else. The data:// rule needs to know
// the 16 plaintext bytes came back when only their base64 was sent, and the RFI content rule needs
// to know the 32 served bytes came back when only a URL was sent. A detector searching for the raw
// form alone would miss an application that HTML-escapes or uppercases on the way out, and neither
// of those is exotic.
func faMarkerForm(body []byte, m triage.Marker) (string, bool) {
	if m == "" {
		return "", false
	}
	return faByteForm(body, []byte(m))
}

// faByteForm is the same search over an arbitrary needle, which RFI needs because the bytes its
// collaborator serves are the marker TWICE and that doubled run is what proves inclusion. Keeping
// one implementation means the marker search and the served-content search can never drift into
// disagreeing about what "present" means.
func faByteForm(body, raw []byte) (string, bool) {
	if len(raw) == 0 || len(body) == 0 {
		return "", false
	}
	if bytes.Contains(body, raw) {
		return "raw", true
	}
	if bytes.Contains(bytes.ToLower(body), bytes.ToLower(raw)) {
		return "case_folded", true
	}
	// NCR, decimal and hexadecimal. An HTML escaper that numeric-references everything is common in
	// template engines configured for maximum paranoia.
	var dec, hexb bytes.Buffer
	for _, c := range raw {
		dec.WriteString("&#" + strconv.Itoa(int(c)) + ";")
		hexb.WriteString("&#x" + strconv.FormatInt(int64(c), 16) + ";")
	}
	if bytes.Contains(body, dec.Bytes()) {
		return "ncr_decimal", true
	}
	if bytes.Contains(bytes.ToLower(body), bytes.ToLower(hexb.Bytes())) {
		return "ncr_hex", true
	}
	// UTF-16LE, which is what a .NET or Java response re-encoding a byte array looks like.
	u16 := make([]byte, 0, len(raw)*2)
	for _, c := range raw {
		u16 = append(u16, c, 0x00)
	}
	if bytes.Contains(body, u16) {
		return "utf16le", true
	}
	// Base64 at all three phases. Not the base64 of a guess: the base64 of the exact 16 bytes, with
	// the phase-affected head and tail quanta trimmed so only the stable middle is matched.
	for phase := 0; phase < 3; phase++ {
		padded := append(bytes.Repeat([]byte{'A'}, phase), raw...)
		e := base64.StdEncoding.EncodeToString(padded)
		if len(e) > 8 && bytes.Contains(body, []byte(e[4:len(e)-4])) {
			return "base64_phase" + strconv.Itoa(phase), true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------------------------
// 8. UNIFORM BLOCK
// ---------------------------------------------------------------------------------------------

// faUniformBlockMin is the foundations 5.8 floor, and it is three for a reason: two identical
// responses to two payloads is a coincidence an application with one error page produces all day.
const faUniformBlockMin = 3

// faUniformBlock reports whether at least three of THIS CLASS'S OWN distinct payloads produced
// byte-identical responses that are not the baseline.
//
// It takes only this class's own observations. CATALOGUE /clean/waf exists to prove each class
// reaches this state from its own three payloads: a cross-class "everything got blocked"
// annotation is reported to the operator and contributes to no verdict, because a class that
// inferred "I was blocked" from another class's block has read another class's response.
func faUniformBlock(own []triage.Observation, baseline []byte) bool {
	byBody := map[string]map[string]bool{} // response body hash -> set of distinct sent payloads
	for _, o := range own {
		if !o.Delivered() || len(o.Body) == 0 {
			continue
		}
		if len(baseline) > 0 && bytes.Equal(o.Body, baseline) {
			continue
		}
		k := string(o.BodySHA256[:])
		if byBody[k] == nil {
			byBody[k] = map[string]bool{}
		}
		byBody[k][string(o.Payload.Wire)] = true
	}
	for _, payloads := range byBody {
		if len(payloads) >= faUniformBlockMin {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------------------------
// 9. READING THIS CLASS'S OWN RESPONSES
// ---------------------------------------------------------------------------------------------

// faOwnObs is one of this class's own probe responses, resolved through the vault.
type faOwnObs struct {
	ProbeID triage.ProbeID
	Ordinal uint64
	Marker  triage.Marker
	Obs     triage.Observation
	// Err is set when the vault refused the read. It is kept rather than dropped because a refused
	// read is a measurement that did not happen, and a class that silently skipped it would count
	// one fewer probe and could still report clean.
	Err error
}

// faOwn resolves ctx.Own into a slice, preserving refusals.
//
// The vault hands back (Perturbed, Observation, error) one at a time and the error is the
// interesting case: it means the set and the vault entry disagree about who owns a response, and
// that is exactly when a class must stop asserting anything.
func faOwn(own triage.OwnedResponses) []faOwnObs {
	out := make([]faOwnObs, 0, own.Len())
	for i := 0; i < own.Len(); i++ {
		p, o, err := own.At(i)
		out = append(out, faOwnObs{
			ProbeID: p.ProbeID(),
			Ordinal: p.Ordinal(),
			Marker:  p.Marker(),
			Obs:     o,
			Err:     err,
		})
	}
	return out
}

// faFind returns the first response to a named probe.
func faFind(all []faOwnObs, id triage.ProbeID) (faOwnObs, bool) {
	for _, o := range all {
		if o.ProbeID == id {
			return o, true
		}
	}
	return faOwnObs{}, false
}

// faOrdinals collects the ordinals behind a verdict. A clean verdict with an empty result here is
// a hard error in ClassVerdict.Validate, which is the invariant stopping a class from claiming a
// measurement it never made.
func faOrdinals(all []faOwnObs) []uint64 {
	out := make([]uint64, 0, len(all))
	for _, o := range all {
		out = append(out, o.Ordinal)
	}
	return out
}

// faObsOf projects the observations out of a resolved own-set, for the helpers that take them.
func faObsOf(all []faOwnObs) []triage.Observation {
	out := make([]triage.Observation, 0, len(all))
	for _, o := range all {
		out = append(out, o.Obs)
	}
	return out
}

// faBaselineBodies gathers every unperturbed body this class is allowed to see.
//
// THIS IS A KNOWN SHORTFALL AND IT IS NAMED RATHER THAN PAPERED OVER. The catalogue's
// baseline-absence rule is "absent from all FIVE baseline samples". PlanCtx gives a classifier a
// BaselineModel (carrying the derived volatile map and the gate, but no bodies) plus two Replays:
// the route control and, at classify time, the post-baseline. So two bodies, not five. Two catches
// the common case, a documentation page that always shows /etc/passwd, and does not catch a page
// that shows it on one render in five. Every class in this family annotates the count it actually
// had, so nobody reads a clean as having been checked against five samples when it was two.
func faBaselineBodies(ctx triage.ClassifyCtx) [][]byte {
	var out [][]byte
	if ctx.Route.Resolved() {
		if b := ctx.Route.Obs().Body; len(b) > 0 {
			out = append(out, b)
		}
	}
	if ctx.PostBaseline.Resolved() {
		if b := ctx.PostBaseline.Obs().Body; len(b) > 0 {
			out = append(out, b)
		}
	}
	return out
}

// faEligibleSlot is the family's shared eligibility rule, and it is deliberately almost empty.
//
// CATALOGUE 3.2 puts TRAVERSAL, LFI and RFI in the "no gate at all" row: every non-credential,
// server-reachable slot on a vector whose route control resolved. Value shape and parameter name
// ORDER the ladder and never suppress it. A shape guess that suppresses a probe is a silent zero,
// and a parameter named "id" that turns out to be a template name is exactly the bug this layer
// exists for.
func faEligibleSlot(s triage.Slot) (string, bool) {
	if s.Kind == triage.KindFragment {
		return "fragment: never transmitted, so no server-side path is built from it", false
	}
	if s.Constraints.IsCredential {
		return "is_credential: perturbing a credential logs the session out and measures the login page", false
	}
	if !s.ServerReachable {
		return "slot_not_server_reachable: the capture shows this value never leaves the browser", false
	}
	return "", true
}

// faOrderingHint is the ordering key from CATALOGUE A.7. Higher runs first. It NEVER suppresses.
func faOrderingHint(s triage.Slot, nameRe *regexp.Regexp) int {
	switch {
	case strings.ContainsAny(s.Value, `/\`) || faHasExt(s.Value):
		return 4
	case s.ValueKind == triage.ValuePathLike || s.ValueKind == triage.ValueURLLike:
		return 3
	case nameRe != nil && nameRe.MatchString(s.Name):
		return 2
	default:
		return 1
	}
}

func faHasExt(v string) bool {
	last := v
	if i := strings.LastIndexAny(v, `/\`); i >= 0 {
		last = v[i+1:]
	}
	i := strings.LastIndexByte(last, '.')
	return i > 0 && i < len(last)-1 && len(last)-i <= 6
}

// faReq builds one ProbeRequest. The Marker field is left at its zero value ON PURPOSE: the runner
// mints it from this class's ordinal stripe, and a class that filled it in could name an ordinal
// belonging to another class and have its probe attributed there.
func faReq(id triage.ProbeID, slot triage.SlotKey, sub faSubst) triage.ProbeRequest {
	return triage.ProbeRequest{Spec: id, Slot: slot, Variant: faVariant(sub)}
}
