package utils

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The search language behind Replay Request.
//
// A repeater is only useful if the operator can find the one request out of several thousand that
// they want to edit. Scrolling a flat list of 2,700 captures is not finding, so this parses a small
// query language into an AST and compiles it to a parameterised SQL predicate against
// manual_crawl_captures.
//
// Two rules govern everything below.
//
// First, EVERY operator-supplied value is a bound parameter. Not one of them is interpolated into
// the SQL text. The input to this parser is untrusted by construction (it is a search box in a tool
// whose whole job is finding injection flaws), and the only structural text that reaches the
// database is drawn from the fixed tables in this file.
//
// Second, a malformed query must fail loudly. An empty result set and a broken query look identical
// in a list view, so a parse failure carries the position it happened at and what was expected, and
// the caller turns that into a message rather than an empty list.

// CaptureQueryError is a parse or compile failure with the offset the operator can look at.
// Position is 1-indexed into the query string, because it is shown to a human, not used as an index.
type CaptureQueryError struct {
	Position int
	Message  string
}

func (e *CaptureQueryError) Error() string {
	return fmt.Sprintf("%s at position %d", e.Message, e.Position)
}

func queryErr(pos int, format string, args ...interface{}) *CaptureQueryError {
	return &CaptureQueryError{Position: pos + 1, Message: fmt.Sprintf(format, args...)}
}

// ---------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------

type captureFieldKind int

const (
	captureFieldText captureFieldKind = iota
	captureFieldNumeric
	captureFieldBool
)

// captureField describes how one queryable name becomes a SQL expression.
//
// A numeric field carries both forms because both are wanted: `status >= 400` has to compare
// numbers or 5 sorts above 400, while `status ~ 40` has to compare text. Keeping the pair here
// rather than branching at compile time is what lets every operator in the documented list work on
// every field in the documented list, which is the only way the parser and the UI help can agree.
type captureField struct {
	kind captureFieldKind
	// text is the expression as text. Non-NULL for every field whose column the recorder always
	// fills, so NOT has well-defined meaning on them. The two response-body fields are the
	// deliberate exception and are documented where they are defined: they stay NULL when nothing
	// was recorded, so a comparison against them is UNKNOWN and drops the row rather than
	// answering a question nobody has the data for.
	text string
	// number is the expression as a number. Only set when kind is captureFieldNumeric.
	number string
}

// The path of a URL with the query string and fragment removed. Derived from `url` rather than read
// from the `endpoint` column because `endpoint` is whatever the recording extension chose to store,
// and the operator is looking at the URL.
const captureSQLPath = `COALESCE(NULLIF(substring(url from '^[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*([^?#]*)'), ''), '/')`

// Everything after the first '?', fragment excluded.
const captureSQLQuery = `COALESCE(substring(url from '\?([^#]*)'), '')`

// The substring after the last dot of the last path segment. Anchored on $ and excluding '/' so
// that /v1.0/users has no extension, which is what an operator filtering `ext = js` means.
var captureSQLExt = `lower(COALESCE(substring(` + captureSQLPath + ` from '\.([^./]+)$'), ''))`

// capture_host is defined as a SQL function in database.go and used by every other feature that
// splits traffic by host. Reusing it keeps `host ~ x` here and the host counts elsewhere from
// drifting apart.
const captureSQLHost = `capture_host(url)`

var captureFields = map[string]captureField{
	"method": {kind: captureFieldText, text: `COALESCE(method,'')`},
	"status": {kind: captureFieldNumeric, number: `COALESCE(status_code,0)`, text: `COALESCE(status_code::text,'')`},
	"host":   {kind: captureFieldText, text: captureSQLHost},
	"domain": {kind: captureFieldText, text: captureSQLHost},
	"path":   {kind: captureFieldText, text: captureSQLPath},
	"url":    {kind: captureFieldText, text: `COALESCE(url,'')`},
	"query":  {kind: captureFieldText, text: captureSQLQuery},
	"mime":   {kind: captureFieldText, text: `COALESCE(mime_type,'')`},
	"ext":    {kind: captureFieldText, text: captureSQLExt},
	"body":   {kind: captureFieldText, text: `COALESCE(post_data,'')`},
	// resp.body and size are the two fields backed by a column the recorder does not always fill:
	// on the corpus these were written against, 43% of rows have no stored response body at all.
	//
	// They are therefore the ONE pair left deliberately NULL rather than COALESCEd to a neutral
	// value. COALESCE(response_body,'') makes `resp.body !~ password` answer "no password here" for
	// every capture nobody recorded, and COALESCE(length(...),0) makes `size < 5000` report a 40KB
	// HTML page as small and `size = 0` return a hundred responses that were never measured. Both
	// are the same lie: an unrecorded body is unknown, not empty, and a search box in a security
	// tool must not assert a fact it never observed.
	//
	// NULLIF, not a bare column: the recorder writes an EMPTY STRING for a body it did not keep,
	// never a NULL. Checked on the live table, where all 100 of the unrecorded rows on the test
	// target are '' and none are NULL. Relying on NULL alone would leave every one of these
	// comparisons behaving exactly as it did before, which is the shape of a fix that passes a
	// SQL-text unit test and changes nothing at all about what the operator is told.
	//
	// A genuinely zero-length body is indistinguishable from an unrecorded one in this schema, so
	// both are treated as unknown. Refusing to answer for a 204 is the cheap half of refusing to
	// answer for the 100 rows nobody stored.
	"resp.body": {kind: captureFieldText, text: `NULLIF(response_body,'')`},
	// octet_length, not length: the documented unit is bytes, and 538 rows table-wide hold a
	// multibyte body whose character count is not its byte count.
	"size": {kind: captureFieldNumeric,
		number: `octet_length(NULLIF(response_body,''))`,
		text:   `octet_length(NULLIF(response_body,''))::text`},
	"time":          {kind: captureFieldNumeric, number: `COALESCE(duration_ms,0)`, text: `COALESCE(duration_ms,0)::text`},
	"status_class":  {kind: captureFieldNumeric, number: `(COALESCE(status_code,0)/100)`, text: `(COALESCE(status_code,0)/100)::text`},
	"resource_type": {kind: captureFieldText, text: `COALESCE(resource_type,'')`},
	"initiator":     {kind: captureFieldText, text: `COALESCE(initiator,'')`},
	"is_direct":     {kind: captureFieldBool, text: `COALESCE(is_direct,false)`},
	"graphql":       {kind: captureFieldText, text: `COALESCE(graphql_operation,'')`},
}

// CaptureQueryFieldNames returns the documented field list, sorted, for error messages and for
// anything that wants to show the operator what they may type.
func CaptureQueryFieldNames() []string {
	names := make([]string, 0, len(captureFields)+5)
	for name := range captureFields {
		names = append(names, name)
	}
	names = append(names, "header.<name>", "resp.header.<name>", "param.<name>",
		"has:header.<name>", "has:param.<name>")
	sortStrings(names)
	return names
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// ---------------------------------------------------------------------------
// JSONB accessors
// ---------------------------------------------------------------------------

// jsonbObjectSQL guards jsonb_each_text, which raises an error on a JSON value that is not an
// object. Every capture writes an object into these columns, but a single malformed legacy row
// would otherwise fail the whole search rather than just missing from it.
func jsonbObjectSQL(column string) string {
	return fmt.Sprintf(`(CASE WHEN jsonb_typeof(%s) = 'object' THEN %s ELSE '{}'::jsonb END)`, column, column)
}

// captureHeaderValueSQL reads one header out of a JSONB column.
//
// The name is lower-cased by the parser before it gets here, because that is how the recorder
// stores header keys. The case-insensitive scan is the fallback rather than the only path: the
// direct ->> lookup hits the common case without expanding the object, and COALESCE does not
// evaluate the subquery unless the direct lookup missed. Any row that stored `Content-Type` instead
// of `content-type` is still found, which matters because a header the operator can see in the
// capture pane but cannot filter on reads as a broken search box.
func captureHeaderValueSQL(column, param string) string {
	return fmt.Sprintf(
		`COALESCE(%s->>%s, (SELECT h.value FROM jsonb_each_text(%s) AS h(key, value) WHERE lower(h.key) = %s LIMIT 1), '')`,
		column, param, jsonbObjectSQL(column), param)
}

func captureHeaderPresenceSQL(column, param string) string {
	return fmt.Sprintf(
		`EXISTS (SELECT 1 FROM jsonb_each_text(%s) AS h(key, value) WHERE lower(h.key) = %s)`,
		jsonbObjectSQL(column), param)
}

// captureParamValueSQL looks in the GET parameters first and the POST parameters second.
//
// Taking the first one that exists, rather than OR-ing two comparisons, is what makes the negative
// operators mean anything: `param.id != 5` compiled as an OR would match every capture that has no
// `id` at all, because the missing half compares empty-string against "5" and wins.
//
// Parameter names are matched case-sensitively, unlike header names, because HTTP parameter names
// are case-sensitive and `param.ID` and `param.id` really can be two different parameters.
func captureParamValueSQL(param string) string {
	return fmt.Sprintf(`COALESCE(get_params->>%s, post_params->>%s, '')`, param, param)
}

func captureParamPresenceSQL(param string) string {
	return fmt.Sprintf(
		`(EXISTS (SELECT 1 FROM jsonb_each_text(%s) AS g(key, value) WHERE g.key = %s) `+
			`OR EXISTS (SELECT 1 FROM jsonb_each_text(%s) AS p(key, value) WHERE p.key = %s))`,
		jsonbObjectSQL("get_params"), param, jsonbObjectSQL("post_params"), param)
}

// ---------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------

type captureNode interface {
	compile(b *captureArgs) (string, error)
}

// captureArgs hands out placeholders and collects the values they stand for. Nothing else may put a
// value into the generated SQL.
type captureArgs struct {
	args []interface{}
	next int
}

func (a *captureArgs) add(v interface{}) string {
	a.args = append(a.args, v)
	p := fmt.Sprintf("$%d", a.next)
	a.next++
	return p
}

type captureAndNode struct{ left, right captureNode }
type captureOrNode struct{ left, right captureNode }
type captureNotNode struct{ child captureNode }

func (n *captureAndNode) compile(b *captureArgs) (string, error) {
	l, err := n.left.compile(b)
	if err != nil {
		return "", err
	}
	r, err := n.right.compile(b)
	if err != nil {
		return "", err
	}
	return "(" + l + " AND " + r + ")", nil
}

func (n *captureOrNode) compile(b *captureArgs) (string, error) {
	l, err := n.left.compile(b)
	if err != nil {
		return "", err
	}
	r, err := n.right.compile(b)
	if err != nil {
		return "", err
	}
	return "(" + l + " OR " + r + ")", nil
}

func (n *captureNotNode) compile(b *captureArgs) (string, error) {
	c, err := n.child.compile(b)
	if err != nil {
		return "", err
	}
	return "(NOT " + c + ")", nil
}

// captureBareNode is a term with no field: a substring hunt across url, method and status.
type captureBareNode struct{ value string }

func (n *captureBareNode) compile(b *captureArgs) (string, error) {
	p := b.add(n.value)
	return fmt.Sprintf(
		`(strpos(lower(COALESCE(url,'')), lower(%s)) > 0 `+
			`OR strpos(lower(COALESCE(method,'')), lower(%s)) > 0 `+
			`OR strpos(COALESCE(status_code::text,''), %s) > 0)`, p, p, p), nil
}

// capturePresenceNode is has:header.<name> or has:param.<name>.
type capturePresenceNode struct {
	kind string // "header" or "param"
	name string
}

func (n *capturePresenceNode) compile(b *captureArgs) (string, error) {
	p := b.add(n.name)
	if n.kind == "header" {
		return captureHeaderPresenceSQL("headers", p), nil
	}
	return captureParamPresenceSQL(p), nil
}

// captureTermNode is field OP value.
type captureTermNode struct {
	field string // as typed, for error messages
	resolvedField
	op    string
	value string
	pos   int // 0-indexed offset of the field, for errors raised at compile time
}

func (n *captureTermNode) compile(b *captureArgs) (string, error) {
	// A JSONB-backed field binds its key before its value, so header.cookie ~ session binds
	// "cookie" then "session". The key has to be a parameter for the same reason the value does.
	textSQL, numberSQL := n.textSQL, n.numSQL
	if n.jsonKey != "" {
		textSQL = strings.ReplaceAll(textSQL, captureHeaderParamMarker, b.add(n.jsonKey))
	}

	switch n.kind {
	case captureFieldBool:
		var truth bool
		switch strings.ToLower(n.value) {
		case "true":
			truth = true
		case "false":
			truth = false
		default:
			return "", queryErr(n.pos, "field %q is a boolean; expected true or false, got %q", n.field, n.value)
		}
		if n.op != "=" && n.op != "!=" {
			return "", queryErr(n.pos, "field %q is a boolean; only = and != apply, got %q", n.field, n.op)
		}
		p := b.add(truth)
		if n.op == "=" {
			return fmt.Sprintf("(%s = %s)", textSQL, p), nil
		}
		return fmt.Sprintf("(%s <> %s)", textSQL, p), nil

	case captureFieldNumeric:
		switch n.op {
		case ">", "<", ">=", "<=", "=", "!=":
			num, err := parseCaptureNumber(n.value)
			if err != nil {
				return "", queryErr(n.pos, "field %q is numeric; expected a number, got %q", n.field, n.value)
			}
			sqlOp := n.op
			if sqlOp == "!=" {
				sqlOp = "<>"
			}
			p := b.add(num)
			return fmt.Sprintf("(%s %s %s)", numberSQL, sqlOp, p), nil
		}
		// Everything else falls through to a text comparison on the number's own digits, so
		// `status ~ 40` and `status =~ ^4` do what they look like they do.
		return compileCaptureText(textSQL, n.op, n.value, n.pos, b)

	default:
		switch n.op {
		case ">", "<", ">=", "<=":
			return "", queryErr(n.pos,
				"operator %q needs a numeric field; %q is text (numeric fields are status, size, time, status_class)",
				n.op, n.field)
		}
		return compileCaptureText(textSQL, n.op, n.value, n.pos, b)
	}
}

func parseCaptureNumber(v string) (interface{}, error) {
	if i, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
		return i, nil
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return nil, err
	}
	return f, nil
}

// compileCaptureText renders one text comparison.
//
// left()/right() rather than LIKE for the prefix and suffix operators: LIKE would need the value
// escaped for % and _, and a search box that silently treats a underscore as a wildcard is a
// surprise nobody asked for. strpos() for contains, for the same reason.
func compileCaptureText(expr, op, value string, pos int, b *captureArgs) (string, error) {
	switch op {
	case "=":
		p := b.add(value)
		return fmt.Sprintf("(lower(%s) = lower(%s))", expr, p), nil
	case "!=":
		p := b.add(value)
		return fmt.Sprintf("(lower(%s) <> lower(%s))", expr, p), nil
	case "~":
		p := b.add(value)
		return fmt.Sprintf("(strpos(lower(%s), lower(%s)) > 0)", expr, p), nil
	case "!~":
		p := b.add(value)
		return fmt.Sprintf("(strpos(lower(%s), lower(%s)) = 0)", expr, p), nil
	case "^=":
		p := b.add(value)
		return fmt.Sprintf("(left(lower(%s), length(lower(%s))) = lower(%s))", expr, p, p), nil
	case "$=":
		p := b.add(value)
		return fmt.Sprintf("(right(lower(%s), length(lower(%s))) = lower(%s))", expr, p, p), nil
	case "=~":
		// Compiled in Go before it is ever sent. PostgreSQL would reject a bad pattern too, but as a
		// database error carrying a SQLSTATE, which surfaces as "search failed" and tells the
		// operator nothing about which of their brackets is unbalanced.
		//
		// Go's regexp is RE2 and PostgreSQL's ~* is a backtracking POSIX ARE, so the two are not the
		// same language: a backreference passes there and is refused here. Refusing the smaller
		// language is the safe direction, since the alternative is accepting a pattern that can pin
		// a database core.
		if _, err := regexp.Compile(value); err != nil {
			return "", queryErr(pos, "invalid regular expression %q: %v", value, err)
		}
		p := b.add(value)
		return fmt.Sprintf("(%s ~* %s)", expr, p), nil
	}
	return "", queryErr(pos, "unknown operator %q", op)
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

type captureQueryParser struct {
	input string
	pos   int
}

// BuildCaptureFilter parses a Replay Request search and returns a SQL boolean expression together
// with the values its placeholders stand for.
//
// startArg is the number of the first placeholder to hand out, so a caller that has already bound
// $1 to the scope target passes 2. An empty query compiles to TRUE with no arguments, which is what
// makes "show me everything" the same code path as a filtered list.
func BuildCaptureFilter(query string, startArg int) (string, []interface{}, error) {
	if strings.TrimSpace(query) == "" {
		return "TRUE", nil, nil
	}
	if startArg < 1 {
		startArg = 1
	}

	p := &captureQueryParser{input: query}
	node, err := p.parseOr()
	if err != nil {
		return "", nil, err
	}
	p.skipSpaces()
	if !p.eof() {
		return "", nil, queryErr(p.pos, "unexpected %q; expected AND, OR or the end of the query",
			string(p.input[p.pos]))
	}

	args := &captureArgs{next: startArg}
	sql, err := node.compile(args)
	if err != nil {
		return "", nil, err
	}
	return sql, args.args, nil
}

func (p *captureQueryParser) eof() bool { return p.pos >= len(p.input) }

func (p *captureQueryParser) skipSpaces() {
	for p.pos < len(p.input) {
		switch p.input[p.pos] {
		case ' ', '\t', '\n', '\r':
			p.pos++
		default:
			return
		}
	}
}

func isCaptureOperatorChar(c byte) bool {
	switch c {
	case '=', '!', '~', '^', '$', '>', '<':
		return true
	}
	return false
}

// isCaptureWordChar bounds a field name or a bare term. Operator characters end a word so that
// `status>=400` parses without spaces, which is how people actually type into a search box.
func isCaptureWordChar(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '(', ')', '"':
		return false
	}
	return !isCaptureOperatorChar(c)
}

func (p *captureQueryParser) peekWord() string {
	i := p.pos
	for i < len(p.input) && isCaptureWordChar(p.input[i]) {
		i++
	}
	return p.input[p.pos:i]
}

func (p *captureQueryParser) readWord() string {
	w := p.peekWord()
	p.pos += len(w)
	return w
}

func isCaptureKeyword(w string) bool {
	switch strings.ToUpper(w) {
	case "AND", "OR", "NOT":
		return true
	}
	return false
}

// matchKeyword consumes the given boolean keyword if it is what comes next.
func (p *captureQueryParser) matchKeyword(kw string) bool {
	save := p.pos
	p.skipSpaces()
	w := p.peekWord()
	if strings.EqualFold(w, kw) {
		p.pos += len(w)
		return true
	}
	p.pos = save
	return false
}

func (p *captureQueryParser) parseOr() (captureNode, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		if !p.matchKeyword("OR") {
			return left, nil
		}
		orPos := p.pos - len("OR")
		p.skipSpaces()
		if p.eof() {
			return nil, queryErr(orPos, `expected a term after "OR" but the query ended`)
		}
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &captureOrNode{left: left, right: right}
	}
}

func (p *captureQueryParser) parseAnd() (captureNode, error) {
	left, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for {
		save := p.pos
		p.skipSpaces()
		if p.eof() || p.input[p.pos] == ')' {
			p.pos = save
			return left, nil
		}
		// OR binds looser, so it ends this run rather than joining it.
		if strings.EqualFold(p.peekWord(), "OR") {
			p.pos = save
			return left, nil
		}
		andPos := p.pos
		explicit := p.matchKeyword("AND")
		if explicit {
			p.skipSpaces()
			if p.eof() {
				return nil, queryErr(andPos, `expected a term after "AND" but the query ended`)
			}
		}
		right, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		left = &captureAndNode{left: left, right: right}
	}
}

func (p *captureQueryParser) parseUnary() (captureNode, error) {
	notPos := p.pos
	if p.matchKeyword("NOT") {
		p.skipSpaces()
		if p.eof() {
			return nil, queryErr(notPos, `expected a term after "NOT" but the query ended`)
		}
		child, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		return &captureNotNode{child: child}, nil
	}
	return p.parsePrimary()
}

func (p *captureQueryParser) parsePrimary() (captureNode, error) {
	p.skipSpaces()
	if p.eof() {
		return nil, queryErr(p.pos, "expected a term but the query ended")
	}
	switch p.input[p.pos] {
	case '(':
		openPos := p.pos
		p.pos++
		inner, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skipSpaces()
		if p.eof() || p.input[p.pos] != ')' {
			return nil, queryErr(p.pos, `expected ")" (the group opened at position %d is still open)`, openPos+1)
		}
		p.pos++
		return inner, nil
	case ')':
		return nil, queryErr(p.pos, `unexpected ")" with no matching "("`)
	}
	return p.parseTerm()
}

func (p *captureQueryParser) parseTerm() (captureNode, error) {
	start := p.pos

	// A quoted head is always a bare text search. It is the escape hatch for searching for something
	// that happens to be spelled like a field or a keyword.
	if p.input[p.pos] == '"' {
		value, err := p.readQuoted()
		if err != nil {
			return nil, err
		}
		return &captureBareNode{value: value}, nil
	}

	word := p.readWord()
	if word == "" {
		return nil, queryErr(start, "unexpected %q; expected a field, a search word or \"(\"",
			string(p.input[start]))
	}
	if isCaptureKeyword(word) {
		return nil, queryErr(start, "expected a term but found %q", strings.ToUpper(word))
	}

	if strings.HasPrefix(strings.ToLower(word), "has:") {
		return p.presenceTerm(word, start)
	}

	// Decide between "field OP value" and a bare word by looking for an operator.
	afterWord := p.pos
	p.skipSpaces()
	op, opStart, err := p.readOperator()
	if err != nil {
		return nil, err
	}
	if op == "" {
		p.pos = afterWord
		if err := p.rejectMissingOperator(word, start); err != nil {
			return nil, err
		}
		return &captureBareNode{value: word}, nil
	}

	resolved, err := resolveCaptureField(word, start)
	if err != nil {
		return nil, err
	}

	value, err := p.readValue(op, opStart)
	if err != nil {
		return nil, err
	}

	return &captureTermNode{
		field:         word,
		resolvedField: resolved,
		op:            op,
		value:         value,
		pos:           start,
	}, nil
}

// rejectMissingOperator catches `path login`, where a known field name is followed by another word
// and no operator.
//
// Left alone that parses as two bare terms and returns nothing, which is the failure mode this
// language exists to avoid: the operator sees an empty list and blames the data. A bare word that
// happens to name a field is still allowed everywhere it is unambiguous, so `graphql` on its own
// and `graphql AND status = 200` both search for the text.
func (p *captureQueryParser) rejectMissingOperator(word string, start int) error {
	save := p.pos
	defer func() { p.pos = save }()

	if _, known := captureFields[strings.ToLower(word)]; !known {
		return nil
	}
	p.skipSpaces()
	if p.eof() || !isCaptureWordChar(p.input[p.pos]) {
		return nil
	}
	next := p.peekWord()
	if isCaptureKeyword(next) {
		return nil
	}
	return queryErr(p.pos,
		"expected an operator after field %q (one of = != ~ !~ ^= $= =~ > < >= <=); "+
			"quote it as %q to search for the word instead", word, word)
}

func (p *captureQueryParser) presenceTerm(word string, start int) (captureNode, error) {
	rest := word[len("has:"):]
	lower := strings.ToLower(rest)
	switch {
	case strings.HasPrefix(lower, "header."):
		name := strings.ToLower(rest[len("header."):])
		if name == "" {
			return nil, queryErr(start, `expected a header name after "has:header."`)
		}
		return &capturePresenceNode{kind: "header", name: name}, nil
	case strings.HasPrefix(lower, "param."):
		name := rest[len("param."):]
		if name == "" {
			return nil, queryErr(start, `expected a parameter name after "has:param."`)
		}
		return &capturePresenceNode{kind: "param", name: name}, nil
	}
	return nil, queryErr(start,
		`has: tests for a header or a parameter; expected has:header.<name> or has:param.<name>, got %q`, word)
}

// readOperator returns "" when what comes next is not an operator at all, and an error when it
// looks like one but is not spelled like any of them.
func (p *captureQueryParser) readOperator() (string, int, error) {
	if p.eof() {
		return "", p.pos, nil
	}
	start := p.pos
	c := p.input[p.pos]
	if !isCaptureOperatorChar(c) {
		return "", start, nil
	}
	second := byte(0)
	if p.pos+1 < len(p.input) {
		second = p.input[p.pos+1]
	}

	var op string
	switch {
	case c == '!' && second == '=':
		op = "!="
	case c == '!' && second == '~':
		op = "!~"
	case c == '^' && second == '=':
		op = "^="
	case c == '$' && second == '=':
		op = "$="
	case c == '=' && second == '~':
		op = "=~"
	case c == '>' && second == '=':
		op = ">="
	case c == '<' && second == '=':
		op = "<="
	case c == '=':
		op = "="
	case c == '~':
		op = "~"
	case c == '>':
		op = ">"
	case c == '<':
		op = "<"
	}
	if op == "" {
		return "", start, queryErr(start,
			"%q is not an operator; expected one of = != ~ !~ ^= $= =~ > < >= <=", string(c))
	}
	p.pos += len(op)

	// A second operator character riding directly on the first is a typo, not a value. Without this
	// `method ~~ POST` searches for methods containing a tilde and returns nothing at all.
	if p.pos < len(p.input) && isCaptureOperatorChar(p.input[p.pos]) {
		return "", start, queryErr(start,
			"%q is not an operator; expected one of = != ~ !~ ^= $= =~ > < >= <=",
			op+string(p.input[p.pos]))
	}
	return op, start, nil
}

// readValue reads the right-hand side of a comparison. Double quotes are the only way to include a
// space or a closing parenthesis.
func (p *captureQueryParser) readValue(op string, opPos int) (string, error) {
	p.skipSpaces()
	if p.eof() {
		return "", queryErr(opPos, "expected a value after %q but the query ended", op)
	}
	if p.input[p.pos] == '"' {
		return p.readQuoted()
	}
	start := p.pos
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ')' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return "", queryErr(start, "expected a value after %q, found %q", op, string(p.input[start]))
	}
	// A whole second operator standing where the value should be is a typo, not a search term.
	// `method = = POST` otherwise parses cleanly as `method` equals the literal "=" followed by a
	// bare term, which matches nothing and returns an empty result. An empty result and a broken
	// query look identical in the search box, so the one case we can be certain about is refused by
	// name. Only an EXACT operator is refused: a value that merely starts with one, like `>=3`, is
	// still a legitimate search, and quoting stays the escape hatch for searching for `"="` itself.
	if token := p.input[start:p.pos]; isCaptureOperatorToken(token) {
		return "", queryErr(start,
			"expected a value after %q but found the operator %q; quote it as %q to search for that text",
			op, token, `"`+token+`"`)
	}
	return p.input[start:p.pos], nil
}

// isCaptureOperatorToken reports whether a whole token is one of the comparison operators.
func isCaptureOperatorToken(token string) bool {
	switch token {
	case "=", "!=", "~", "!~", "^=", "$=", "=~", ">", "<", ">=", "<=":
		return true
	}
	return false
}

// readQuoted reads a double-quoted string. Backslash escapes \" and \\ so a value can contain a
// quote; every other backslash is kept, because a regular expression is full of them and doubling
// them all up in the search box would be miserable.
func (p *captureQueryParser) readQuoted() (string, error) {
	openPos := p.pos
	p.pos++ // opening quote
	var sb strings.Builder
	for p.pos < len(p.input) {
		c := p.input[p.pos]
		if c == '\\' && p.pos+1 < len(p.input) {
			next := p.input[p.pos+1]
			if next == '"' || next == '\\' {
				sb.WriteByte(next)
				p.pos += 2
				continue
			}
		}
		if c == '"' {
			p.pos++
			return sb.String(), nil
		}
		sb.WriteByte(c)
		p.pos++
	}
	return "", queryErr(openPos, "unterminated quoted value; expected a closing double quote")
}

// resolvedField is a field name turned into the SQL that reads it. jsonKey is set only for the
// header and parameter families, where the name the operator typed is itself a value to bind.
type resolvedField struct {
	kind    captureFieldKind
	textSQL string
	numSQL  string
	jsonKey string
}

// The JSONB accessors need the key as a bound parameter, but the placeholder number is not known
// until compile time, so the expression is built with this marker and the marker is swapped for the
// real placeholder once the key has been bound. It is deliberately not valid SQL, so a path that
// forgets to substitute it fails at the database rather than silently matching nothing.
const captureHeaderParamMarker = "<<KEY>>"

// resolveCaptureField turns a typed field name into the SQL that reads it.
func resolveCaptureField(word string, pos int) (resolvedField, error) {
	lower := strings.ToLower(word)

	if f, ok := captureFields[lower]; ok {
		return resolvedField{kind: f.kind, textSQL: f.text, numSQL: f.number}, nil
	}

	switch {
	case strings.HasPrefix(lower, "resp.header."):
		// Header names are lower-cased before lookup because that is how the recorder stores them.
		name := strings.ToLower(word[len("resp.header."):])
		if name == "" {
			return resolvedField{}, queryErr(pos, `expected a header name after "resp.header."`)
		}
		return resolvedField{
			kind:    captureFieldText,
			textSQL: captureHeaderValueSQL("response_headers", captureHeaderParamMarker),
			jsonKey: name,
		}, nil
	case strings.HasPrefix(lower, "header."):
		name := strings.ToLower(word[len("header."):])
		if name == "" {
			return resolvedField{}, queryErr(pos, `expected a header name after "header."`)
		}
		return resolvedField{
			kind:    captureFieldText,
			textSQL: captureHeaderValueSQL("headers", captureHeaderParamMarker),
			jsonKey: name,
		}, nil
	case strings.HasPrefix(lower, "param."):
		// Case preserved: HTTP parameter names are case-sensitive.
		name := word[len("param."):]
		if name == "" {
			return resolvedField{}, queryErr(pos, `expected a parameter name after "param."`)
		}
		return resolvedField{
			kind:    captureFieldText,
			textSQL: captureParamValueSQL(captureHeaderParamMarker),
			jsonKey: name,
		}, nil
	}

	return resolvedField{}, queryErr(pos, "unknown field %q; valid fields are %s",
		word, strings.Join(CaptureQueryFieldNames(), ", "))
}
