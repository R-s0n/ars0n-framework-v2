package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Endpoint identity: the single place that decides when two observed URLs are the same endpoint.
//
// Six sources feed consolidation (manual crawl, katana, gospider, linkfinder, gau, waybackurls) and
// they spell the same resource half a dozen ways. If identity is decided ad hoc at each call site
// the same page arrives as four rows, an operator sees 4,000 endpoints where there are 400, and
// every downstream count is wrong.
//
// Two rules shape what follows, and both are deliberate.
//
// Scheme is NOT part of identity. http://host/a and https://host/a are one endpoint observed over
// two transports; the schemes are recorded so the difference is not lost.
//
// Path case IS part of identity, and index files are NOT folded. `/Admin` and `/admin` differing is
// the classic proxy-versus-origin authorisation bypass: nginx denies `/admin` and the IIS origin
// serves `/Admin`. Folding them by "helpful" normalisation destroys the finding. They are kept as
// separate rows and linked by case_group_key so the pair can be handed forward as a lead.

// EndpointIdentity is everything canonicalisation derives from one observed URL.
type EndpointIdentity struct {
	Key            string // sha256 of the identity tuple; the join key for every downstream table
	CanonicalURL   string // display URL, canonical scheme
	Scheme         string
	Host           string
	Port           int // 0 when the scheme default
	CanonicalPath  string
	IdentityQuery  string // only identity-bearing query params, sorted
	ClientRoute    string // hash-bang or hash-slash SPA route, identity-bearing
	TemplatedPath  string // /user/{id}
	TemplateKey    string
	CaseGroupKey   string
	Method         string
	Flags          map[string]bool
	DroppedParams  map[string]string // tracking params removed, kept so the removal is auditable
	ValueParams    map[string]string // value-bearing params: name -> first observed value
	ContentClass   string            // page | api | static | unknown
	IndexSiblingOf string
}

// Tracking and cache-busting parameters. Present or absent, they address the same resource, and
// keeping them multiplies one endpoint into thousands of rows.
var trackingParams = map[string]bool{
	"utm_source": true, "utm_medium": true, "utm_campaign": true, "utm_term": true,
	"utm_content": true, "utm_id": true, "utm_source_platform": true,
	"gclid": true, "gclsrc": true, "dclid": true, "fbclid": true, "msclkid": true,
	"mc_cid": true, "mc_eid": true, "igshid": true, "twclid": true, "ttclid": true,
	"_ga": true, "_gl": true, "_gid": true, "yclid": true, "wbraid": true, "gbraid": true,
	"ref": true, "referrer": true, "referer": true, "source": true,
	"cb": true, "cachebust": true, "cache_bust": true, "nocache": true, "no_cache": true,
	"rand": true, "random": true, "_": true, "__": true,
}

// Parameters that select which resource is addressed rather than how it is rendered. Two URLs
// differing only in one of these are different endpoints.
var identityBearingParams = map[string]bool{
	"id": true, "uuid": true, "guid": true, "key": true, "name": true, "slug": true,
	"page_id": true, "post_id": true, "user_id": true, "account_id": true, "org_id": true,
	"file": true, "path": true, "action": true, "cmd": true, "do": true, "op": true,
	"module": true, "controller": true, "route": true, "view": true, "template": true,
	"type": true, "kind": true, "resource": true, "endpoint": true, "method": true,
	"format": true, "output": true, "export": true, "download": true,
	"query": true, "q": true, "search": true, "url": true, "uri": true, "redirect": true,
	"next": true, "return": true, "callback": true, "target": true, "dest": true,
}

var (
	reNumericSeg = regexp.MustCompile(`^\d+$`)
	reUUIDSeg    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reObjectID   = regexp.MustCompile(`(?i)^[0-9a-f]{24}$`)
	reHexSeg     = regexp.MustCompile(`(?i)^[0-9a-f]{16,}$`)
	reLongB64    = regexp.MustCompile(`^[A-Za-z0-9_-]{22,}$`)
	reDateSeg    = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	reMatrixSeg  = regexp.MustCompile(`;[^/]*`)
	reNonceValue = regexp.MustCompile(`^(\d{10,13}|[0-9a-f]{16,})$`)
	reMultiSlash = regexp.MustCompile(`/{2,}`)
)

// Extensions whose responses are files rather than application surface. They are still stored, but
// validating and investigating thousands of images buys nothing.
var staticExtensions = map[string]bool{
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".webp": true,
	".ico": true, ".bmp": true, ".tiff": true, ".avif": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".css": true, ".map": true, ".mp4": true, ".webm": true, ".mp3": true, ".wav": true,
	".pdf": true, ".zip": true, ".gz": true, ".tar": true, ".rar": true, ".7z": true,
}

var apiPathHints = []string{"/api/", "/api.", "/graphql", "/gql", "/rest/", "/v1/", "/v2/", "/v3/",
	"/rpc", "/jsonrpc", "/_next/data/", "/wp-json/", "/services/", "/svc/", "/bff/"}

// CanonicalizeEndpoint turns one observed URL plus verb into an identity.
//
// defaultScheme is the scheme the scope target itself uses, so a scheme-relative or bare host URL
// adopts the target's transport rather than being blindly forced to https, which the previous
// implementation did and which broke every http-only target.
func CanonicalizeEndpoint(rawURL, method, defaultScheme string) (EndpointIdentity, bool) {
	id := EndpointIdentity{
		Flags:         map[string]bool{},
		DroppedParams: map[string]string{},
		ValueParams:   map[string]string{},
		Method:        normalizeMethod(method),
	}

	raw := strings.TrimSpace(rawURL)
	if raw == "" || strings.ContainsRune(raw, 0) {
		return id, false
	}
	// A NUL anywhere, or a control character, means a corrupted row rather than a URL.
	for _, r := range raw {
		if r < 0x20 && r != '\t' {
			return id, false
		}
	}

	if defaultScheme != "http" && defaultScheme != "https" {
		defaultScheme = "https"
	}

	switch {
	case strings.HasPrefix(raw, "//"):
		raw = defaultScheme + ":" + raw
	case !strings.Contains(raw, "://"):
		// Reject anything carrying a non-http scheme rather than prefixing it into nonsense.
		if i := strings.Index(raw, ":"); i > 0 && !strings.Contains(raw[:i], "/") {
			if _, err := strconv.Atoi(raw[i+1:]); err != nil {
				return id, false // mailto:, javascript:, data:, android-app: and friends
			}
		}
		raw = defaultScheme + "://" + raw
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return id, false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return id, false
	}

	if u.User != nil {
		id.Flags["had_userinfo"] = true
		u.User = nil
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return id, false
	}
	id.Host = host

	// An explicit default port and an implicit one address the same server. A non-default port is
	// a different service and stays.
	if p := u.Port(); p != "" {
		n, convErr := strconv.Atoi(p)
		if convErr == nil && !isDefaultPort(u.Scheme, n) {
			id.Port = n
		}
	}

	id.Scheme = u.Scheme
	// EscapedPath, not Path. url.Parse decodes %2F into Path, which silently turns an encoded
	// traversal into a real one and merges an ACL-bypass primitive with the thing it bypasses.
	id.CanonicalPath, id.Flags = canonicalizePath(u.EscapedPath(), id.Flags)
	id.IdentityQuery = id.splitQuery(u.Query())
	id.ClientRoute = clientRouteFrom(u.Fragment)
	if id.ClientRoute == "" && u.Fragment != "" {
		id.Flags["had_fragment"] = true
	}

	id.CaseGroupKey = strings.ToLower(id.CanonicalPath)
	id.TemplatedPath = templatePath(id.CanonicalPath)
	id.ContentClass = classifyContent(id.CanonicalPath)
	if base := indexSibling(id.CanonicalPath); base != "" {
		id.IndexSiblingOf = base
	}

	hostPort := id.Host
	if id.Port != 0 {
		hostPort = id.Host + ":" + strconv.Itoa(id.Port)
	}
	id.CanonicalURL = id.Scheme + "://" + hostPort + id.CanonicalPath
	if id.IdentityQuery != "" {
		id.CanonicalURL += "?" + id.IdentityQuery
	}
	if id.ClientRoute != "" {
		id.CanonicalURL += "#" + id.ClientRoute
	}

	// Scheme is deliberately absent from the identity tuple.
	id.Key = hashIdentity(strings.Join([]string{
		hostPort, id.CanonicalPath, id.IdentityQuery, id.ClientRoute, id.Method,
	}, "\x00"))
	id.TemplateKey = hashIdentity(strings.Join([]string{
		hostPort, id.TemplatedPath, queryNamesOf(id.IdentityQuery), id.Method,
	}, "\x00"))

	return id, true
}

func hashIdentity(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

func isDefaultPort(scheme string, port int) bool {
	return (scheme == "https" && port == 443) || (scheme == "http" && port == 80)
}

func normalizeMethod(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if m == "" {
		return "GET"
	}
	return m
}

// canonicalizePath applies RFC 3986 dot-segment removal and the small set of rewrites that are
// safe. Case folding and index-file folding are deliberately absent; see the file comment.
func canonicalizePath(p string, flags map[string]bool) (string, map[string]bool) {
	if p == "" {
		return "/", flags
	}

	if reMatrixSeg.MatchString(p) {
		flags["had_matrix_params"] = true
		p = reMatrixSeg.ReplaceAllString(p, "")
	}
	if strings.Contains(p, "..") || strings.Contains(p, "/./") {
		flags["had_dot_segments"] = true
	}
	p = removeDotSegments(p)

	if reMultiSlash.MatchString(p) {
		flags["had_duplicate_slashes"] = true
		p = reMultiSlash.ReplaceAllString(p, "/")
	}

	p = normalizePercentEncoding(p)

	if len(p) > 1 && strings.HasSuffix(p, "/") {
		flags["observed_trailing_slash"] = true
		p = strings.TrimRight(p, "/")
	}
	if p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if len(p) > 2048 {
		flags["path_truncated"] = true
		p = p[:2048]
	}
	return p, flags
}

// normalizePercentEncoding decodes only unreserved characters and uppercases the rest.
//
// %2F, %5C, %2E and %25 are never decoded. Decoding them changes which resource the path addresses
// and is itself a path-traversal and ACL-bypass primitive, so a normaliser that "helpfully" decodes
// them merges an attack surface into the thing it bypasses.
func normalizePercentEncoding(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] != '%' || i+2 >= len(p) {
			b.WriteByte(p[i])
			continue
		}
		hexPair := strings.ToUpper(p[i+1 : i+3])
		v, err := strconv.ParseUint(hexPair, 16, 8)
		if err != nil {
			b.WriteByte(p[i])
			continue
		}
		c := byte(v)
		switch {
		case c == '/' || c == '\\' || c == '.' || c == '%' || c == 0:
			b.WriteString("%" + hexPair)
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '~':
			b.WriteByte(c)
		default:
			b.WriteString("%" + hexPair)
		}
		i += 2
	}
	return b.String()
}

func removeDotSegments(p string) string {
	var out []string
	for _, seg := range strings.Split(p, "/") {
		switch seg {
		case ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, seg)
		}
	}
	joined := strings.Join(out, "/")
	if !strings.HasPrefix(joined, "/") {
		joined = "/" + joined
	}
	return joined
}

// splitQuery sorts query parameters into three buckets: tracking noise that is dropped, params
// that select a resource and therefore belong in the identity, and everything else, whose names
// are recorded but whose values are not part of identity.
//
// This is what stops /search?q=shoes and /search?q=hats being two endpoints while keeping
// /index.php?page=admin distinct from /index.php?page=home.
func (id *EndpointIdentity) splitQuery(q url.Values) string {
	var identity []string
	for name, values := range q {
		lower := strings.ToLower(name)
		value := ""
		if len(values) > 0 {
			value = values[0]
		}

		switch {
		case trackingParams[lower], lower == "t" && reNonceValue.MatchString(value),
			lower == "v" && reNonceValue.MatchString(value),
			lower == "ts" && reNonceValue.MatchString(value):
			id.DroppedParams[name] = "tracking"
		case identityBearingParams[lower]:
			identity = append(identity, name+"="+value)
			id.ValueParams[name] = value
		default:
			// The name is surface, the value is not identity.
			id.ValueParams[name] = value
		}
	}
	sort.Strings(identity)
	return strings.Join(identity, "&")
}

func queryNamesOf(identityQuery string) string {
	if identityQuery == "" {
		return ""
	}
	var names []string
	for _, pair := range strings.Split(identityQuery, "&") {
		if i := strings.Index(pair, "="); i >= 0 {
			names = append(names, pair[:i])
		} else {
			names = append(names, pair)
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

// clientRouteFrom keeps a fragment only when it is an SPA route. #/dashboard and #!/users address
// different views; #section-3 is a scroll anchor on the same page.
func clientRouteFrom(fragment string) string {
	if strings.HasPrefix(fragment, "/") || strings.HasPrefix(fragment, "!") {
		return fragment
	}
	return ""
}

// templatePath replaces segments that look like object identifiers with {id}, so /user/1,
// /user/2 ... /user/9000 collapse into one group. The concrete URL is kept as well: the group is
// for reasoning about scale, not a replacement for the real thing.
func templatePath(p string) string {
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		if isIdentifierSegment(seg) {
			segs[i] = "{id}"
		}
	}
	return strings.Join(segs, "/")
}

func isIdentifierSegment(seg string) bool {
	// A file name is not an identifier even when its stem is numeric: 2024.pdf is a document.
	if strings.Contains(seg, ".") && !reDateSeg.MatchString(seg) {
		return false
	}
	switch {
	case reNumericSeg.MatchString(seg):
		return true
	case reUUIDSeg.MatchString(seg), reObjectID.MatchString(seg), reHexSeg.MatchString(seg):
		return true
	case reDateSeg.MatchString(seg):
		return true
	case reLongB64.MatchString(seg) && strings.IndexFunc(seg, func(r rune) bool {
		return r >= '0' && r <= '9'
	}) >= 0:
		// A long opaque token with at least one digit. A long lowercase word is a slug and is real
		// surface, so it must not be templated away.
		return !isWordLike(seg)
	}
	return false
}

func isWordLike(s string) bool {
	letters := 0
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') {
			letters++
		}
	}
	return float64(letters)/float64(len(s)) > 0.75
}

func classifyContent(p string) string {
	lower := strings.ToLower(p)
	if ext := pathExtension(lower); ext != "" {
		if staticExtensions[ext] {
			return "static"
		}
		if ext == ".js" {
			// A bundle is a file, but it is the richest source of endpoints on a modern target,
			// so it is not lumped in with images.
			return "script"
		}
		if ext == ".json" || ext == ".xml" {
			return "api"
		}
	}
	for _, hint := range apiPathHints {
		if strings.Contains(lower, hint) {
			return "api"
		}
	}
	return "page"
}

func pathExtension(p string) string {
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	if i := strings.LastIndex(base, "."); i > 0 {
		return base[i:]
	}
	return ""
}

// indexSibling reports the directory an index file serves, so /docs and /docs/index.html can be
// linked without being merged. They can differ: a proxy rule matching one and not the other is a
// finding, not a normalisation problem.
func indexSibling(p string) string {
	base := p
	dir := "/"
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
		dir = p[:i]
		if dir == "" {
			dir = "/"
		}
	}
	lower := strings.ToLower(base)
	for _, name := range []string{"index.html", "index.htm", "index.php", "index.jsp",
		"index.asp", "index.aspx", "default.html", "default.htm", "default.asp", "default.aspx"} {
		if lower == name {
			return dir
		}
	}
	return ""
}

// EndpointDirectory is the family a per-directory not-found control belongs to. Validate measures
// one control per directory because a catch-all is frequently scoped to a route prefix: /api/*
// returns JSON 404 while /* returns the SPA shell, and a single global control describes neither.
func EndpointDirectory(canonicalPath string) string {
	i := strings.LastIndex(canonicalPath, "/")
	if i <= 0 {
		return "/"
	}
	return canonicalPath[:i]
}

// ExtensionClass groups paths whose not-found response is likely to differ in kind.
func ExtensionClass(canonicalPath string) string {
	ext := pathExtension(strings.ToLower(canonicalPath))
	switch ext {
	case "":
		return "none"
	case ".json", ".xml":
		return "data"
	case ".js":
		return "script"
	}
	if staticExtensions[ext] {
		return "static"
	}
	return "page"
}
