package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Response fingerprinting: deciding whether two responses are the same page.
//
// Exact body hashing does not work, and the reason is the exact false positive this whole feature
// exists to kill. A login page carrying a CSRF token is a different byte sequence on every request.
// Measured against a controlled target, three fetches of one login page produced three different
// exact hashes, so naive dedup reports three unique endpoints where there is one page.
//
// simhash of the token stream solves it. The same measurement put those three fetches at Hamming
// distance 1 from each other while genuinely different pages sat at 21 or more. That gap is wide,
// so a threshold in the middle is safe from both directions.
//
// simhash alone is not enough to RULE SOMETHING OUT, though, and this is the important asymmetry.
// Two pages can be structurally identical and semantically different: an admin panel and a user
// panel rendered from the same template differ in the data, not the shape. So a rule-out requires
// agreement on every discriminator as well, and anything short of that is "indistinguishable",
// which is reported and kept rather than deleted.

type ResponseFingerprint struct {
	Status        int      `json:"status"`
	StatusClass   string   `json:"status_class"`
	CTFamily      string   `json:"ct_family"`
	DecodedSize   int      `json:"decoded_size"`
	StructureHash string   `json:"structure_hash"`
	Simhash       uint64   `json:"-"`
	SimhashHex    string   `json:"simhash"`
	HeaderShape   string   `json:"header_shape"`
	Title         string   `json:"title"`
	FormActions   []string `json:"form_actions,omitempty"`
	InputNames    []string `json:"input_names,omitempty"`
	ScriptBases   []string `json:"script_bases,omitempty"`
	JSONKeys      []string `json:"json_keys,omitempty"`
	Location      string   `json:"location,omitempty"`
	Empty         bool     `json:"empty"`
	Opaque        bool     `json:"opaque"`
}

// Volatile spans that legitimately change between two fetches of the same page. Masked before any
// hashing so token drift does not read as a different page.
//
// This library is fixed on purpose. Learning masks from the corpus was considered and rejected:
// a learned mask can cover exactly the span that distinguishes /account/1001 from /account/1002,
// which turns two real endpoints into one and loses the more interesting of the pair.
var volatilePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(csrf|xsrf|authenticity)[_-]?token["']?\s*[:=]\s*["'][^"']{4,}["']`),
	regexp.MustCompile(`(?i)name=["'](csrf|xsrf|_token|authenticity_token|__RequestVerificationToken)[^>]*value=["'][^"']*["']`),
	regexp.MustCompile(`(?i)\bnonce=["']?[A-Za-z0-9+/=_-]{8,}["']?`),
	regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`),
	regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z?`),
	regexp.MustCompile(`\b\d{13}\b`),
	regexp.MustCompile(`\b\d{10}\b`),
	regexp.MustCompile(`(?i)integrity=["']sha(256|384|512)-[A-Za-z0-9+/=]+["']`),
	regexp.MustCompile(`(?i)[?&](v|ver|version|_|cb|t|ts)=[A-Za-z0-9._-]{4,}`),
	regexp.MustCompile(`(?i)data-reactid=["'][^"']*["']`),
	regexp.MustCompile(`(?i)"buildId":"[^"]+"`),
	regexp.MustCompile(`(?i)\bsession[_-]?id["']?\s*[:=]\s*["'][^"']+["']`),
}

var (
	reTitle      = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reFormAction = regexp.MustCompile(`(?i)<form[^>]*\baction=["']([^"']*)["']`)
	reInputName  = regexp.MustCompile(`(?i)<(?:input|select|textarea)[^>]*\bname=["']([^"']+)["']`)
	reScriptSrc  = regexp.MustCompile(`(?i)<script[^>]*\bsrc=["']([^"']+)["']`)
	reTagName    = regexp.MustCompile(`(?i)<([a-z][a-z0-9]*)\b`)
	reWordToken  = regexp.MustCompile(`[A-Za-z0-9_]{2,}`)
)

// Status classes that mean the request was refused by something in front of the application.
var blockStatuses = map[int]bool{401: true, 403: true, 406: true, 418: true, 429: true, 451: true}

// Markers that a bot manager or WAF, rather than the application, produced the body.
var challengeMarkers = []string{
	"just a moment", "checking your browser", "cf-browser-verification", "cf_chl_",
	"attention required", "access denied", "request blocked", "incapsula", "imperva",
	"you have been blocked", "ddos protection", "captcha", "px-captcha", "datadome",
	"akamai reference", "reference #", "the requested url was rejected",
}

// BuildFingerprint reduces one response to the comparison surface.
func BuildFingerprint(resp ScanResponse) ResponseFingerprint {
	fp := ResponseFingerprint{
		Status:      resp.Status,
		StatusClass: statusClass(resp.Status),
		CTFamily:    contentTypeFamily(resp.ContentType),
		DecodedSize: resp.BodyBytes,
		HeaderShape: headerShape(resp),
		Location:    resp.Location,
	}

	body := resp.Body
	if strings.TrimSpace(body) == "" {
		fp.Empty = true
		fp.StructureHash = "empty"
		return fp
	}

	switch fp.CTFamily {
	case "image", "binary", "font", "media":
		// A binary body is never fingerprinted from its contents. Entropy over a font produces
		// noise, and a rule-out derived from noise is worse than no verdict.
		fp.Opaque = true
		fp.StructureHash = "opaque:" + fp.CTFamily + ":" + sizeBucket(resp.BodyBytes)
		return fp
	}

	masked := maskVolatile(body)

	switch fp.CTFamily {
	case "html":
		fp.StructureHash = htmlStructureHash(masked)
		fp.Title = fingerprintTitle(body)
		fp.FormActions = uniqueSortedMatches(reFormAction, body, 20)
		fp.InputNames = uniqueSortedMatches(reInputName, body, 40)
		fp.ScriptBases = scriptBasenames(body, 20)
	case "json":
		fp.StructureHash, fp.JSONKeys = jsonStructureHash(masked)
	default:
		fp.StructureHash = "text:" + hashString(masked)
	}

	fp.Simhash = simhash64(masked)
	fp.SimhashHex = strconv.FormatUint(fp.Simhash, 16)
	return fp
}

func maskVolatile(body string) string {
	for _, re := range volatilePatterns {
		body = re.ReplaceAllString(body, "\x00MASK\x00")
	}
	return body
}

// htmlStructureHash hashes the shape of the document with all text and attribute values removed,
// so two renderings of one template collide and two different templates do not.
//
// Nodes are sampled evenly across the whole document rather than truncated at the head. Truncating
// makes two long pages collide on their shared navigation chrome, which is precisely the case where
// a wrong answer is expensive.
func htmlStructureHash(body string) string {
	tags := reTagName.FindAllStringSubmatch(body, -1)
	if len(tags) == 0 {
		return "html:notags:" + sizeBucket(len(body))
	}

	const maxNodes = 4000
	step := 1
	if len(tags) > maxNodes {
		step = len(tags) / maxNodes
	}

	var b strings.Builder
	var prev string
	run := 0
	for i := 0; i < len(tags); i += step {
		name := strings.ToLower(tags[i][1])
		if name == prev {
			run++
			continue
		}
		if prev != "" {
			b.WriteString(prev)
			b.WriteByte(':')
			b.WriteString(runBucket(run))
			b.WriteByte(',')
		}
		prev = name
		run = 1
	}
	if prev != "" {
		b.WriteString(prev + ":" + runBucket(run))
	}
	return "html:" + hashString(b.String())
}

// runBucket coarsens repeat counts so a table with 11 rows and one with 40 are the same shape,
// while one row and forty are not.
func runBucket(n int) string {
	switch {
	case n <= 1:
		return "1"
	case n <= 3:
		return "2-3"
	case n <= 10:
		return "4-10"
	case n <= 50:
		return "11-50"
	}
	return "50+"
}

// jsonStructureHash hashes the sorted key paths plus the values of the fields that carry meaning
// in an error response. A differing error message is a structural difference: {"error":"not found"}
// and {"error":"forbidden"} are not the same answer.
func jsonStructureHash(body string) (string, []string) {
	var parsed interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return "json:unparseable:" + sizeBucket(len(body)), nil
	}
	paths := map[string]bool{}
	var meaningful []string
	collectJSONPaths(parsed, "", paths, &meaningful, 0)

	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sort.Strings(meaningful)

	top := keys
	if len(top) > 60 {
		top = top[:60]
	}
	return "json:" + hashString(strings.Join(keys, ",")+"|"+strings.Join(meaningful, ",")), top
}

var meaningfulJSONKeys = map[string]bool{
	"error": true, "message": true, "code": true, "status": true, "type": true,
	"detail": true, "title": true, "reason": true, "errors": true,
}

func collectJSONPaths(v interface{}, prefix string, out map[string]bool, meaningful *[]string, depth int) {
	if depth > 8 || len(out) > 400 {
		return
	}
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out[p] = true
			if meaningfulJSONKeys[strings.ToLower(k)] {
				if s, ok := val.(string); ok && len(s) < 200 {
					*meaningful = append(*meaningful, k+"="+s)
				}
			}
			collectJSONPaths(val, p, out, meaningful, depth+1)
		}
	case []interface{}:
		// Array indices collapse: a list of 3 and a list of 300 have the same shape.
		if len(t) > 0 {
			collectJSONPaths(t[0], prefix+"[]", out, meaningful, depth+1)
		}
	}
}

// simhash64 over word-token shingles. Small localised edits move few bits; a different document
// moves many.
func simhash64(s string) uint64 {
	tokens := reWordToken.FindAllString(s, -1)
	if len(tokens) == 0 {
		return 0
	}
	var vector [64]int
	for i := 0; i < len(tokens); i++ {
		shingle := strings.ToLower(tokens[i])
		if i+1 < len(tokens) {
			shingle += " " + strings.ToLower(tokens[i+1])
		}
		h := fnv64(shingle)
		for bit := 0; bit < 64; bit++ {
			if h&(1<<uint(bit)) != 0 {
				vector[bit]++
			} else {
				vector[bit]--
			}
		}
	}
	var out uint64
	for bit := 0; bit < 64; bit++ {
		if vector[bit] > 0 {
			out |= 1 << uint(bit)
		}
	}
	return out
}

func fnv64(s string) uint64 {
	const offset = 14695981039346656037
	const prime = 1099511628211
	h := uint64(offset)
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

// HammingDistance counts differing bits between two simhashes.
func HammingDistance(a, b uint64) int { return bits.OnesCount64(a ^ b) }

// SimhashThreshold is the distance below which two bodies are treated as the same page.
//
// Calibrated against a controlled target: the same login page with a fresh CSRF token per request
// measured 0 to 1, byte-identical shells measured 0, and genuinely different pages measured 21 to
// 24. Six sits in the empty middle of that gap with margin on both sides.
const SimhashThreshold = 6

// MatchesReference reports whether a response is the same page as a reference, conjunctively.
//
// Every clause must agree. Structural similarity alone is never enough: an admin panel and a user
// dashboard built from one template are structurally identical and are not the same page, and
// ruling the admin panel out because it looks like the dashboard is the worst failure this code
// can produce. The discriminators are what separate them.
func MatchesReference(fp, ref ResponseFingerprint) bool {
	// Never rule anything out on these: too little signal to be wrong about safely.
	if fp.Opaque || ref.Opaque {
		return false
	}
	if fp.DecodedSize < 64 || fp.Status == 204 || fp.Status == 304 {
		return false
	}
	if fp.CTFamily == "json" && fp.DecodedSize < 512 {
		return false
	}
	if fp.StatusClass != ref.StatusClass || fp.CTFamily != ref.CTFamily {
		return false
	}

	structural := fp.StructureHash == ref.StructureHash
	if !structural && fp.Simhash != 0 && ref.Simhash != 0 {
		structural = HammingDistance(fp.Simhash, ref.Simhash) <= SimhashThreshold
	}
	if !structural {
		return false
	}

	// Every discriminator present on both sides must agree.
	if fp.Title != "" && ref.Title != "" && fp.Title != ref.Title {
		return false
	}
	if !sliceEqual(fp.FormActions, ref.FormActions) {
		return false
	}
	if !sliceEqual(fp.InputNames, ref.InputNames) {
		return false
	}
	if !sliceEqual(fp.ScriptBases, ref.ScriptBases) {
		return false
	}
	if !sliceEqual(fp.JSONKeys, ref.JSONKeys) {
		return false
	}
	// Location is compared whole, query included. See LocationsEquivalent.
	if fp.Location != ref.Location {
		return false
	}
	return true
}

// sliceEqual treats an empty side as "not observed" rather than as a difference, so a discriminator
// missing from one response does not by itself force a mismatch.
func sliceEqual(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return true
	}
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ResponsesEquivalent reports whether two responses are the same answer.
//
// This is NOT MatchesReference, and the difference matters. MatchesReference is used to rule an
// endpoint out, so it refuses to match anything too small or too opaque to be sure about: being
// wrong there deletes a real endpoint. Here, matching IS the finding, as in "this endpoint returned
// the same bytes with and without a session", so the same conservatism would suppress exactly the
// result worth having. A 68 byte JSON object of personal data served to an anonymous caller is the
// bug, and MatchesReference would refuse to see it because it is under 512 bytes.
func ResponsesEquivalent(a, b ResponseFingerprint) bool {
	if a.StatusClass != b.StatusClass || a.CTFamily != b.CTFamily {
		return false
	}
	if a.Location != b.Location {
		return false
	}
	if a.StructureHash != "" && a.StructureHash == b.StructureHash {
		// Structure alone is not enough for two responses of the same shape carrying different
		// data, so sizes have to agree closely too.
		return absInt(a.DecodedSize-b.DecodedSize) <= 16
	}
	if a.Simhash != 0 && b.Simhash != 0 {
		return HammingDistance(a.Simhash, b.Simhash) <= 2 &&
			absInt(a.DecodedSize-b.DecodedSize) <= 16
	}
	return a.DecodedSize == b.DecodedSize && a.DecodedSize > 0
}

// LocationsEquivalent compares two redirect targets byte for byte, query included.
//
// The query is the whole point. A redirect to /login?next=%2Fadmin%2Fusers proves the router
// parsed and recognised the requested path, which means the endpoint exists and is behind auth.
// Normalising the query away before comparing turns that proof into "everything redirects to
// /login", which is exactly the false positive this feature was built to eliminate.
func LocationsEquivalent(a, b string) bool { return a == b }

// LooksLikeAuthRedirect reports a Location pointing at an authentication flow.
func LooksLikeAuthRedirect(location string) bool {
	l := strings.ToLower(location)
	for _, marker := range []string{"login", "signin", "sign-in", "sso", "/auth", "oauth",
		"account/login", "session/new", "authorize"} {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

// IsChallengeBody reports a body produced by a bot manager or WAF rather than the application.
func IsChallengeBody(body string) bool {
	l := strings.ToLower(body)
	if len(l) > 20000 {
		l = l[:20000]
	}
	for _, marker := range challengeMarkers {
		if strings.Contains(l, marker) {
			return true
		}
	}
	return false
}

func IsBlockStatus(status int) bool { return blockStatuses[status] }

func statusClass(status int) string {
	switch {
	case status == 0:
		return "error"
	case status < 200:
		return "1xx"
	case status < 300:
		return "2xx"
	case status < 400:
		return "3xx"
	case status < 500:
		return "4xx"
	}
	return "5xx"
}

func contentTypeFamily(ct string) string {
	l := strings.ToLower(ct)
	switch {
	case l == "":
		return "empty"
	case strings.Contains(l, "json"):
		return "json"
	case strings.Contains(l, "html"):
		return "html"
	case strings.Contains(l, "javascript"), strings.Contains(l, "ecmascript"):
		return "js"
	case strings.Contains(l, "css"):
		return "css"
	case strings.Contains(l, "xml"):
		return "xml"
	case strings.HasPrefix(l, "image/"):
		return "image"
	case strings.HasPrefix(l, "font/"), strings.Contains(l, "font-woff"):
		return "font"
	case strings.HasPrefix(l, "video/"), strings.HasPrefix(l, "audio/"):
		return "media"
	case strings.HasPrefix(l, "text/"):
		return "text"
	}
	return "binary"
}

// headerShape captures which headers are present, not their values, so a Set-Cookie with a fresh
// session id does not make two identical pages look different.
func headerShape(resp ScanResponse) string {
	if resp.Header == nil {
		return ""
	}
	names := make([]string, 0, len(resp.Header))
	for name := range resp.Header {
		lower := strings.ToLower(name)
		if lower == "date" || lower == "age" || lower == "expires" || lower == "set-cookie" ||
			lower == "content-length" || strings.HasPrefix(lower, "x-request-id") ||
			strings.HasPrefix(lower, "x-trace") || strings.HasPrefix(lower, "cf-ray") {
			continue
		}
		names = append(names, lower)
	}
	sort.Strings(names)
	return hashString(strings.Join(names, ","))
}

func sizeBucket(n int) string {
	switch {
	case n == 0:
		return "0"
	case n < 512:
		return "<512"
	case n < 4096:
		return "<4k"
	case n < 32768:
		return "<32k"
	case n < 262144:
		return "<256k"
	}
	return ">=256k"
}

func fingerprintTitle(body string) string {
	m := reTitle.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	t := strings.TrimSpace(m[1])
	if len(t) > 200 {
		t = t[:200]
	}
	return t
}

func uniqueSortedMatches(re *regexp.Regexp, body string, cap int) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		v := strings.TrimSpace(m[1])
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= cap {
			break
		}
	}
	sort.Strings(out)
	return out
}

// scriptBasenames keeps the file name and drops the cache-busting hash, so app.4f21c.js and
// app.9ba07.js after a redeploy are the same script.
func scriptBasenames(body string, cap int) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range reScriptSrc.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		src := m[1]
		if i := strings.IndexAny(src, "?#"); i >= 0 {
			src = src[:i]
		}
		if i := strings.LastIndex(src, "/"); i >= 0 {
			src = src[i+1:]
		}
		parts := strings.Split(src, ".")
		if len(parts) >= 3 {
			// name.<hash>.js -> name.js
			src = parts[0] + "." + parts[len(parts)-1]
		}
		if src == "" || seen[src] {
			continue
		}
		seen[src] = true
		out = append(out, src)
		if len(out) >= cap {
			break
		}
	}
	sort.Strings(out)
	return out
}

func hashString(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:12])
}

// FingerprintSummary renders a fingerprint for an operator-facing reason string.
func FingerprintSummary(fp ResponseFingerprint) string {
	return fmt.Sprintf("%d %s, %d bytes", fp.Status, fp.CTFamily, fp.DecodedSize)
}
