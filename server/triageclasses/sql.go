package triageclasses

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// The SQL injection triage classifier. CATALOGUE 1.4, 2.1, 3.1, 6.1, and iso-query class 1.
//
// WHAT THIS CLASS IS FOR. It answers "point sqlmap here", never "this is vulnerable". A confirming
// run of sqlmap against one vector is about 1690 requests and 28 minutes. This class spends
// between 3 and 22 purpose-built requests on a slot and hands back a label, so the operator can
// say "scan every slot labelled SQL with sqlmap and ghauri" instead of scanning all 362.
//
// THE STRONGEST ORACLE IS THIS RUN'S MARKER INSIDE A DBMS PARSER ERROR, and the reason it is the
// strongest is that it needs NO BASELINE. The marker is minted for this probe, in this run, so the
// baseline cannot contain it. That is what makes the oracle survive /clean/dberror, an application
// whose every response, baseline included, already carries a PSQLException. Every statistical
// detector ever written reports that endpoint as injectable on the first payload, and subtraction
// cannot fix it, because subtraction still cannot separate "a DBMS error appeared because of my
// payload" from "a DBMS error appears whenever this endpoint is perturbed".
//
// WHAT THIS CLASS DELIBERATELY DOES NOT SEND, AND WHY THAT IS NOT SHARING. SQLiDetector ships in
// this framework and runs separately with its own 14 payloads ('123 ”123 `123 ")123 "))123 `)123
// `))123 '))123 ')123"123 []123 ""123 '"123 "'123 \123) and its own 153 error signatures. Not one
// of those 14 byte strings appears here, and not because another tool "covers it": they are a
// different mechanism. Every one of them REPLACES the observed value (verified in exurl's
// split.py: url.replace(pv, paramEqual + replaceMe)), it is GET query only (core/app.py calls
// requests.get), and it has no baseline at all. So on the measured corpus it reaches 30 of 218
// vectors, it cannot reach a body, a cookie, a header or a path segment, and on any endpoint that
// short-circuits when the id does not resolve it never reaches SQL in the first place. Ruling R2
// deleted the old "SQLiDetector's job" delegation for exactly that reason and gave the parenthesis
// payloads back to this class. Every payload below leads with the observed value V, so the query
// still runs.
//
// WHAT THIS CLASS ADDS THAT A QUOTE LADDER CANNOT REACH AT ALL:
//
//	MSSQL bracket identifiers        ORDER BY [<input>] is injectable through ] and nothing else
//	MySQL backtick identifiers       ORDER BY `<input>` likewise
//	ORDER BY, GROUP BY, LIMIT        no quote is syntactically available in the vulnerable position
//	numeric arithmetic               V+4093-4093 carries NO metacharacter, so it passes every
//	                                 quote filter and every WAF quote rule
//	the parenthesis contexts         WHERE (LOWER(name)='<in>') and IN (<in>) need V') or V)
//	the balanced-delimiter repair    the single thing that separates a SQL parse error from an
//	                                 input validator that rejects one quote and accepts two
//
// AND THE HIGHEST-VALUE NEGATIVE IN THE WHOLE CLASS IS THE INT CAST. An application that parses an
// integer and discards the tail makes 1' read byte for byte identical to 1. Every scanner on earth
// records that as clean. It is not clean. SQL-C5 plus the SQL-C6 influence control turns it into
// not_exploitable (casted) with evidence, which is a statement the operator can act on, and when
// the influence control does not move the response either it becomes cannot_determine
// (parameter_inert), because then we have not learned that the value is cast, we have learned that
// the value does nothing at all.
type sqlClassifier struct{}

func init() { triage.RegisterClassifier(sqlClassifier{}) }

func (sqlClassifier) ID() triage.ClassID { return triage.ClassSQL }

// ---------------------------------------------------------------------------------------------
// THE CONSTANTS THIS CLASS OWNS
// ---------------------------------------------------------------------------------------------

const (
	// sqlMarkerTemplate is the marker literal written into the declared payload bytes. The RUNNER
	// mints the real marker per probe and substitutes it in place; this literal exists so the
	// isolation table has concrete bytes to compare and so a reader can see exactly where in the
	// payload the marker sits.
	//
	// IT IS NOT THE LITERAL THE CATALOGUE PRINTS, AND THAT IS A CORRECTION, NOT A DIVERGENCE.
	// CATALOGUE 1.4 heads the section "Marker zqj4f3q000a1kx9m", whose ordinal digits 000a1k read
	// 13016 in base36 and 13016 mod 64 is 24, which is ClassDeser. Ruling R12 requires
	// ordinal mod 64 == class id, and triage.CheckPayloadIsolation enforces it (I1d-plain): the
	// catalogue's own literal would fail the build as a foreign marker in a SQL payload. The
	// literals in section 1 vary byte 3, which is the RUN ID, not the ordinal, so they are
	// illustrative and none of the 27 satisfies the stripe. This one is minted properly:
	// anchor zqj, run id sql0, ordinal 000004 (4 mod 64 == ClassSQL), checksum ju8 over the first
	// thirteen bytes. sql_test.go recomputes all three parts rather than trusting this comment.
	sqlMarkerTemplate = "zqjsql0000004ju8"

	// The boolean arm's operands. 4093 is prime and 4093*7 == 28651; the false arm is 28652, one
	// away, so a page that differs because of the DIGIT COUNT rather than the truth value cannot
	// produce the differential.
	sqlTrueExpr  = "(4093*7)=28651"
	sqlFalseExpr = "(4093*7)=28652"

	// sqlOrdinalLiteral is this class's owned integer, used where no marker can be carried. It is
	// large enough that no real SELECT list has that many columns, so the ordinal-range phrase it
	// provokes names OUR number and can be attributed without a marker.
	sqlOrdinalLiteral = "4093772"

	// sqlJunkTail is appended to the marker in the junk control and the flow probe. It is four
	// digits, so both payloads stay purely alphanumeric and cannot break a statement in any
	// dialect, and it makes those two payloads SQL's own bytes rather than a bare marker.
	//
	// WHY THAT MATTERS: a bare V-then-marker payload is also XPATH's XP-NC1 and is the obvious
	// shape for several other classes' inert controls. Two classes shipping byte-equal payloads
	// fails triage.CheckPayloadIsolation at build time, by design, and correctly so: if the bare
	// form were blocked or rejected, neither class could tell whose payload had been refused.
	sqlJunkTail = "4093"

	// sqlPhraseWindow is how far the marker may sit from the engine phrase and still count as the
	// same error. 120 bytes, from CATALOGUE 1.4, and the reason it is not larger is /clean/echoparser:
	// a page that echoes the payload AND separately contains the words "SQL syntax" further down
	// must not fire.
	sqlPhraseWindow = 120
)

// sqlVariant keys are the per-request directives this class hands the runner. They are named
// constants rather than inline strings because the runner has to honour them and a typo in one
// would silently produce a payload that tests something other than what was asked.
const (
	// sqlVarMarkerInPayload is "yes" when the runner must substitute the minted marker for
	// sqlMarkerTemplate inside the payload bytes, and "no" when it must NOT write the marker into
	// the value at all.
	//
	// "no" is not an optimisation. The differential probes (the boolean arm, the LIKE arm, the
	// ordinal probe and the influence control) are complete SQL fragments whose semantics depend
	// on the value staying exactly what it is: appending a marker to V' AND (4093*7)=28651 AND
	// 'a'='a breaks the trailing quote repair and turns the true arm into a syntax error, at which
	// point cmp(A1, baseline) can never be "same" and the detector can never fire. Those probes
	// are still fully attributable, because the ordinal lives in the ProbeRequest and in the
	// Perturbed handle, not in the bytes. What they give up is the in-body marker oracle, and they
	// were never scored on it.
	sqlVarMarkerInPayload = "sql_marker_in_payload"
	// sqlVarValuePosition is "lead" when the observed value comes first (every probe but one) and
	// "trail" when the payload comes first. SQL-MP is the only "trail" probe and it exists
	// precisely because every other payload in this class leads with V.
	sqlVarValuePosition = "sql_value_position"
	// sqlVarValueTransform names a transform applied to the observed value itself rather than an
	// append. Only SQL-C6 uses it.
	sqlVarValueTransform = "sql_value_transform"
	// sqlVarMarkerForm is "percent_bytes" for the decode probe, where the marker goes on the wire
	// as its own percent escapes and the question is whether the application decodes them.
	sqlVarMarkerForm = "sql_marker_form"
	// sqlVarWhitespaceForm records that a payload substitutes /**/ for SP, so a null result can be
	// reported as whitespace_form_unproven on an engine we have not identified.
	sqlVarWhitespaceForm = "sql_whitespace_form"
)

const (
	sqlValueLead      = "lead"
	sqlValueTrail     = "trail"
	sqlMarkerYes      = "yes"
	sqlMarkerNo       = "no"
	sqlDigitsToNine   = "digits_to_nine"
	sqlPercentBytes   = "percent_bytes"
	sqlWhitespaceComm = "comment"
)

// The probe ids. Named constants because Plan, Classify, the ladder tables and the tests all refer
// to them and a mistyped string literal in one of those places is a probe that silently never runs.
const (
	sqlDEC triage.ProbeID = "SQL-DEC"
	sqlU1  triage.ProbeID = "SQL-U1"
	sqlQ1  triage.ProbeID = "SQL-Q1"
	sqlQ2  triage.ProbeID = "SQL-Q2"
	sqlD1P triage.ProbeID = "SQL-D1"
	sqlD2P triage.ProbeID = "SQL-D2"
	sqlB1  triage.ProbeID = "SQL-B1"
	sqlB2  triage.ProbeID = "SQL-B2"
	sqlK1  triage.ProbeID = "SQL-K1"
	sqlK2  triage.ProbeID = "SQL-K2"
	sqlP1  triage.ProbeID = "SQL-P1"
	sqlP2  triage.ProbeID = "SQL-P2"
	sqlP3  triage.ProbeID = "SQL-P3"
	sqlP4  triage.ProbeID = "SQL-P4"
	sqlC1  triage.ProbeID = "SQL-C1"
	sqlC2  triage.ProbeID = "SQL-C2"
	sqlC3  triage.ProbeID = "SQL-C3"
	sqlC4  triage.ProbeID = "SQL-C4"
	sqlC5  triage.ProbeID = "SQL-C5"
	sqlC6  triage.ProbeID = "SQL-C6"
	sqlA1  triage.ProbeID = "SQL-A1"
	sqlA2  triage.ProbeID = "SQL-A2"
	sqlA3  triage.ProbeID = "SQL-A3"
	sqlA4  triage.ProbeID = "SQL-A4"
	sqlA5  triage.ProbeID = "SQL-A5"
	sqlA1w triage.ProbeID = "SQL-A1w"
	sqlA2w triage.ProbeID = "SQL-A2w"
	sqlL1  triage.ProbeID = "SQL-L1"
	sqlL2  triage.ProbeID = "SQL-L2"
	sqlNC1 triage.ProbeID = "SQL-NC1"
	sqlMP  triage.ProbeID = "SQL-MP"
	sqlS1  triage.ProbeID = "SQL-S1"
)

// sqlPercentEncodeBytes renders s as one percent escape per byte, lowercase hex.
//
// It is computed rather than written out as a literal so the decode probe's bytes cannot drift
// from sqlMarkerTemplate. A hand-typed %7a%71%6a... with one wrong nibble is a decode probe that
// measures nothing and reports decode_depth unknown forever.
func sqlPercentEncodeBytes(s string) []byte {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		fmt.Fprintf(&b, "%%%02x", s[i])
	}
	return []byte(b.String())
}

// ---------------------------------------------------------------------------------------------
// THE PROBE TABLE
// ---------------------------------------------------------------------------------------------

// sqlEveryPoint is the insertion points the class reaches with its general payloads. The fragment
// is absent because the fragment is never transmitted.
func sqlEveryPoint() []triage.SlotKind {
	return []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindHeader, triage.KindCookie, triage.KindPath}
}

// sqlPercentRelevantPoints are the slots where a percent escape is a question at all. On a JSON
// string, a header value or a multipart part value no payload in this class needs percent
// encoding, so the decode probe there would buy nothing.
func sqlPercentRelevantPoints() []triage.SlotKind {
	return []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie}
}

func sqlAllEncoders() []triage.EncoderMode {
	return []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
		triage.EncodePathSegment, triage.EncodeHeaderValue, triage.EncodeCookie,
		triage.EncodeMultipartValue, triage.EncodeXMLCDATA,
	}
}

// Probes is every payload this class will ever send. CATALOGUE 1.4.
//
// THE ORDER OF THE ROWS IS THE ORDER OF THE ARGUMENT, not the order of the ladder: each break is
// followed immediately by the balanced control that proves the break was consumed as syntax rather
// than rejected as input. A break with no control is a detector nobody has watched stay silent.
func (sqlClassifier) Probes() []triage.ProbeSpec {
	m := sqlMarkerTemplate
	all := sqlEveryPoint()

	spec := func(id triage.ProbeID, logical string, notes string) triage.ProbeSpec {
		return triage.ProbeSpec{
			ID: id, Class: triage.ClassSQL, Logical: []byte(logical),
			Encoders: sqlAllEncoders(), Points: all,
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: notes,
		}
	}
	control := func(p triage.ProbeSpec) triage.ProbeSpec { p.IsControl = true; return p }
	at := func(p triage.ProbeSpec, pos triage.MarkerPos) triage.ProbeSpec { p.MarkerPos = pos; return p }

	return []triage.ProbeSpec{
		// The decode probe, ruling R6b. It is THIS CLASS'S OWN probe and not a shared gate: it
		// modifies the value, so it is a payload, so it belongs to exactly one class. Its three
		// outcomes are all deterministic from one request: the decoded marker comes back
		// (decode_depth 1), the literal percent text comes back (decode_depth 0), or neither
		// (decode_depth unknown, which is NOT zero and is a different verdict downstream).
		{
			ID: sqlDEC, Class: triage.ClassSQL,
			Logical:  sqlPercentEncodeBytes(m),
			Encoders: []triage.EncoderMode{triage.EncodeLiteralPct},
			Points:   sqlPercentRelevantPoints(),
			// The marker is on the wire as percent escapes, so its position is the end of the
			// appended text and the form is declared in the variant.
			MarkerPos: triage.MarkerSuffix, Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "ruling R6b: the class's own decode probe. On a path slot it also answers the pct question: a 404 or 400 where the route control passed at the observed value is pct_rejected FOR THIS CLASS",
		},

		// THE UNREPAIRED BREAK, and the reason it is a separate probe from SQL-Q1 rather than a
		// variant of it. Every other delimiter payload in this class closes the literal and
		// REOPENS it, which is right and which the boolean arm depends on: without the repair the
		// true arm of the pair is a syntax error, cmp(A1,baseline)==same is unreachable and the
		// differential can never be read. The consequence nobody wrote down is that the class then
		// has no payload that can leave a literal OPEN, so it can never provoke an
		// unterminated-literal error, and two phrases in its own strong catalogue,
		// pg.unterminated_quoted and mssql.unclosed_quotation, sit there watching for an error
		// nothing this class sends is able to cause. sql_test.go now fails the build if the count
		// of unbalanced-quote payloads is anything other than one.
		//
		// MEASURED, and this is the whole defect. Against the oracle's deliberately vulnerable
		// /sqli?id=1, SQL-Q1 comes back HTTP 200 and 87 bytes: the statement it built is
		// lexically complete, so the application never errors and never echoes. SQL-U1 comes back
		// HTTP 500 and 267 bytes carrying
		//
		//	org.postgresql.util.PSQLException: ERROR: unterminated quoted string at or near "'"
		//	  Query: SELECT name, price FROM products WHERE id = '1'<marker>'
		//
		// which is this class's strongest oracle exactly as designed: THIS RUN'S marker quoted
		// back inside a DBMS parser error, needing no baseline. The class was blind to its own
		// flagship signal on a positive control, and every real application that prints a driver
		// exception with the statement in it was blind the same way.
		//
		// ITS CONTROL IS SQL-Q2, which is these bytes with the delimiter doubled and nothing else
		// changed. That is a tighter pair than SQL-Q1 and SQL-Q2: if both error identically the
		// quote never reached the parser, and if only this one errors the quote was consumed as
		// syntax. It is one request, it needs no baseline, and it is in rung 0 for that reason.
		at(spec(sqlU1, "'"+m, "the unrepaired break: close the literal, drop the marker as a bare token and do NOT reopen. The only payload in this class that can produce pg.unterminated_quoted, mysql 1064 on an unterminated string, mssql.unclosed_quotation or sqlite.unrecognized_token, and the only one that reaches the echoed-statement line of a driver exception page. VERIFIED against the oracle /sqli: HTTP 500 with the marker inside the Query line, where SQL-Q1 is HTTP 200 and silent"), triage.MarkerSuffix),

		// The delimiter ladder. Four delimiters, two payloads each: the break closes the literal,
		// drops the marker as a bare token and reopens so the statement stays lexically complete;
		// the control doubles the delimiter so the marker stays INSIDE the literal.
		spec(sqlQ1, "'"+m+"'", "single-quote break. VERIFIED PostgreSQL 18 (syntax error at or near \"<marker>\") and MariaDB 11.8.9 (1064 near '<marker>'')"),
		at(control(spec(sqlQ2, "''"+m, "the doubled-quote control. VERIFIED silent in a string context on PG 18 and MariaDB 11.8.9. If it produces the SAME parse error as SQL-Q1 the quote never reached SQL and the verdict drops to cannot_determine (metachar_not_delivered)")), triage.MarkerSuffix),

		spec(sqlD1P, `"`+m+`"`, "double quote: a string delimiter on MySQL without ANSI_QUOTES, an identifier delimiter on PostgreSQL, Oracle, MSSQL and SQLite. Reachable in a JSON string slot, where a raw double quote arrives as \\\" and reaches the application as a literal one"),
		at(control(spec(sqlD2P, `""`+m, "the doubled double-quote control, and a free context classifier: silence means \" is a string delimiter, an unknown-column error naming the marker means it is an identifier delimiter")), triage.MarkerSuffix),

		spec(sqlB1, "`"+m+"`", "backtick identifier break, MySQL family and SQLite. VERIFIED MariaDB 11.8.9. No quote payload reaches ORDER BY `<input>`"),
		at(control(spec(sqlB2, "``"+m, "the doubled-backtick control. VERIFIED MariaDB 11.8.9 answers Unknown column 'name`<marker>' in 'ORDER BY', which is the identifier-context signal rather than a failure")), triage.MarkerSuffix),

		spec(sqlK1, "]"+m+"[", "MSSQL bracket identifier break. Microsoft Learn, Database Identifiers: a right bracket is escaped by doubling it and bracket delimiters always work regardless of SET QUOTED_IDENTIFIER, so ORDER BY [<input>] is injectable through ] and through nothing else. UNVERIFIED: no MSSQL was available"),
		at(control(spec(sqlK2, "]]"+m, "the doubled-bracket control. UNVERIFIED for the same reason")), triage.MarkerSuffix),

		// The parenthesis contexts, ruling R2. WHERE (LOWER(name)='<in>') and IN (<in>) need the
		// closing paren; without it the true arm of the boolean pair is an arity error, both arms
		// differ from baseline, cmp(A1,baseline)==same is unreachable, and the slot reads clean.
		spec(sqlP1, "')"+m+"('", "ruling R2: the quoted parenthesis context, WHERE (LOWER(name)='<in>')"),
		at(control(spec(sqlP2, "'')"+m, "ruling R2: the quoted paren control")), triage.MarkerSuffix),
		spec(sqlP3, ")"+m+"(", "ruling R2: the unquoted parenthesis context, IN (<in>) with a numeric list"),
		at(control(spec(sqlP4, "))"+m, "ruling R2: the unquoted paren control")), triage.MarkerSuffix),

		// The non-delimiter contexts, where no quote ever appears. These are the rows a quote
		// ladder cannot reach at all, and they are whitespace free except SQL-C3.
		at(spec(sqlC1, ","+m, "ORDER BY, GROUP BY, an IN list. Whitespace free, so it works on a cookie with decode_depth 0. VERIFIED PG 18 column \"<marker>\" does not exist; MariaDB Unknown column '<marker>' in 'ORDER BY'"), triage.MarkerSuffix),
		at(spec(sqlC2, "+"+m, "a numeric expression in WHERE, LIMIT or OFFSET. Whitespace free. The plus must go out as %2B on query, form and cookie or it becomes a space; in a path segment a plus is a literal plus and needs no encoding"), triage.MarkerSuffix),
		at(spec(sqlC3, " "+m, "a bare trailing token after ORDER BY col, after LIMIT n, after a WHERE term. VERIFIED PG 18, MariaDB 11.8.9 and SQLite 3.50.4"), triage.MarkerSuffix),

		{
			ID: sqlC4, Class: triage.ClassSQL,
			Logical:  []byte("," + sqlOrdinalLiteral),
			Encoders: sqlAllEncoders(), Points: all,
			MarkerPos: triage.MarkerSuffix, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "the ORDER BY / GROUP BY POSITION slot. It carries no marker because the position must stay a bare integer; attribution is by this class's own owned literal 4093772 inside the ordinal-range phrase, and the route control is checked for that literal's absence first. On SQLite the reply leaks the SELECT-list arity",
		},

		at(spec(sqlC5, ".4"+m, "the cast detector, digits-only V. VERIFIED PG 18 trailing junk after numeric literal at or near \"1.4<marker>\". If the application parses an int and discards the tail this comes back EQUAL to the baseline, which is the case SQL-C6 exists to interpret"), triage.MarkerSuffix),
		{
			ID: sqlC6, Class: triage.ClassSQL,
			// Deliberately empty: this control does not APPEND anything. It replaces every ASCII
			// digit of the observed value with 9, same length, no metacharacter anywhere. The
			// isolation check permits an empty payload on a control for exactly this shape.
			Logical:  nil,
			Encoders: sqlAllEncoders(), Points: all,
			MarkerPos: triage.MarkerSuffix, Tier: triage.TierFull, Risk: triage.RiskR0, IsControl: true,
			Notes: "the influence control for SQL-C5. Same length, all digits replaced by 9, no metacharacter. If this does not move the response then SQL-C5 sitting at baseline says nothing about casting and the verdict is parameter_inert, not casted",
		},

		// The boolean and arithmetic arm, for endpoints that never show an error at all. This is
		// the only detector that can see /sqli/blind and /sqli/status200.
		at(spec(sqlA1, "' AND "+sqlTrueExpr+" AND 'a'='a", "the true arm. VERIFIED PG 18 and MariaDB 11.8.9 return the row"), triage.MarkerSuffix),
		at(spec(sqlA2, "' AND "+sqlFalseExpr+" AND 'a'='a", "the false arm. VERIFIED PG 18 and MariaDB 11.8.9 return none"), triage.MarkerSuffix),
		at(control(spec(sqlA3, "' AND 28651 28652 AND 'a'='a", "the invalid-syntax control: two integers separated by a space are not an expression, so this must NOT look like the true arm. VERIFIED a syntax error on PG 18 and MariaDB 11.8.9")), triage.MarkerSuffix),
		at(spec(sqlA4, "+4093-4093", "the numeric true arm. It contains NO metacharacter at all, so it passes every quote filter and every WAF quote rule, and it is the only probe in this class that does"), triage.MarkerSuffix),
		at(spec(sqlA5, "+4093-4094", "the numeric false arm"), triage.MarkerSuffix),

		{
			ID: sqlA1w, Class: triage.ClassSQL,
			Logical:   []byte("'/**/AND/**/" + sqlTrueExpr + "/**/AND/**/'a'='a"),
			Encoders:  []triage.EncoderMode{triage.EncodeCookie},
			Points:    []triage.SlotKind{triage.KindCookie},
			MarkerPos: triage.MarkerSuffix, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "the whitespace-free true arm, for a cookie whose decode_depth is 0 and which therefore cannot carry %20. VERIFIED PG 18 and MariaDB 11.8.9. UNVERIFIED on Oracle, MSSQL and SQLite, so a null result here is cannot_determine (whitespace_form_unproven) on an unidentified engine rather than clean",
		},
		{
			ID: sqlA2w, Class: triage.ClassSQL,
			Logical:   []byte("'/**/AND/**/" + sqlFalseExpr + "/**/AND/**/'a'='a"),
			Encoders:  []triage.EncoderMode{triage.EncodeCookie},
			Points:    []triage.SlotKind{triage.KindCookie},
			MarkerPos: triage.MarkerSuffix, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "the whitespace-free false arm",
		},

		// The LIKE arm. A search parameter built into a LIKE pattern needs no syntax break at all,
		// so nothing else in this class can see it.
		at(spec(sqlL1, "%", "LIKE widening. The percent must go out as %25 on query, form, path and cookie: a bare percent followed by non-hex is rejected by many HTTP stacks and that 400 looks exactly like a signal"), triage.MarkerSuffix),
		at(control(spec(sqlL2, `\%`, "the escaped LIKE control, which must NOT widen. VERIFIED PG 18: name like 'ali%' returns alice, name like 'ali\\%' returns nothing")), triage.MarkerSuffix),

		// The junk control. This is research-sqli rank 0, owned here as SQL's own probe rather
		// than borrowed from anybody: if a plain alphanumeric suffix already errors, then every
		// D1 result on this slot is junk_sensitive and the marker oracle is void here.
		at(control(spec(sqlNC1, m+sqlJunkTail, "the junk control: purely alphanumeric, no metacharacter of any kind, cannot break a statement in any dialect. If it produces an ENGINE_PHRASE the endpoint errors on any modified value and every D1 verdict on this slot becomes cannot_determine (junk_sensitive)")), triage.MarkerInline),

		// The marker-first probe. Every other payload in this class leads with V, so a field limit
		// shorter than len(V)+17 blinds D1 completely and the class would report clean on a slot
		// it never actually measured.
		{
			ID: sqlMP, Class: triage.ClassSQL,
			Logical:  []byte(m + " "),
			Encoders: sqlAllEncoders(), Points: all,
			MarkerPos: triage.MarkerPrefix, Tier: triage.TierFull, Risk: triage.RiskR0,
			Notes: "marker first, then a space, then the observed value. Planned only on a slot whose FieldLimit is known and below len(V)+20, because that is exactly the slot where every other payload's marker is truncated away",
		},

		// The second-order FLOW probe. It is NOT a detection probe and can never be a finding.
		{
			ID: sqlS1, Class: triage.ClassSQL,
			Logical:   []byte(m + sqlOrdinalLiteral),
			Encoders:  []triage.EncoderMode{triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString},
			Points:    []triage.SlotKind{triage.KindQuery, triage.KindBody},
			MarkerPos: triage.MarkerPrefix, Tier: triage.TierOptIn, Risk: triage.RiskR2,
			Notes: "the flow probe. Purely alphanumeric, so it survives an allow-list and cannot break any statement. Detection of second-order SQL injection is NOT ATTEMPTED: storing V'M' would leave a record that raises a 500 for every later reader including other users, which is the one thing the safety rule forbids outright. This writes an inert token and the output is the label second_order_flow_observed, which is informational and is never a finding. Planned only when the runner has budgeted a mutating request, and never on DELETE",
		},
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY. CATALOGUE 3.1, the SQL row.
// ---------------------------------------------------------------------------------------------

// Reaches says which insertion points this class reaches and on what condition.
//
// Every non-always answer carries a reason, because a ReachNever with no reason produces a slot
// with no verdict row and no explanation, and an operator cannot tell "ruled out because the
// mechanism cannot exist here" from "nobody wired this up". Those are the same pixel and
// completely different facts.
func (sqlClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery, triage.KindHeader:
		// No gate at all. Every non-credential slot on a vector whose route control resolved.
		// A quote, a comma, a backtick, a bracket, a space and a plus are all legal in a header
		// value raw, and no payload here needs CR, LF or NUL, so the header row's impossible set
		// never binds this class.
		return triage.Reachability{Reach: triage.ReachAlways}

	case triage.KindCookie:
		// Every byte this class needs is deliverable: the equals sign and the single quote are
		// legal raw, the comma, the double quote and the backslash go percent-encoded, and the
		// only payload needing a space has a /**/ substitute for a cookie that does not decode.
		return triage.Reachability{Reach: triage.ReachAlways}

	case triage.KindBody:
		switch {
		case strings.Contains(string(mt), "json"):
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "a JSON STRING slot carries every payload, because a raw double quote is delivered as \\\" and reaches the application as a literal one; " +
					"a JSON CONTAINER node is not this class's shape at all, since SQL has no payload that is a JSON object and that encoder belongs to NOSQL; " +
					"a number, boolean or null slot is probed coerced, and a 400 on the coerced form alone is type_rejection and never clean",
			}
		case strings.Contains(string(mt), "graphql"):
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "a GraphQL variable is a JSON string slot and every payload reaches it, but the STATUS CODE is not an input to any rule here: " +
					"a GraphQL endpoint answers 200 for a syntax error and 200 for success, so a class grading a GraphQL slot on status reports every probe as clean",
			}
		case strings.Contains(string(mt), "xml"):
			return triage.Reachability{
				Reach:  triage.ReachConditional,
				Reason: "XML element text carries every payload once the ampersand and the less-than are entity-escaped, which is the declared xml_cdata encoder mode; the whole-document slot is not this class's, since a SQL payload is not a document",
			}
		case strings.Contains(string(mt), "multipart"):
			return triage.Reachability{
				Reach:  triage.ReachConditional,
				Reason: "a multipart part VALUE is nearly unconstrained and carries every payload, subject to the boundary not occurring in the payload; the filename and the part Content-Type are not SQL sinks",
			}
		default:
			return triage.Reachability{
				Reach:  triage.ReachConditional,
				Reason: "a urlencoded form field carries every payload under the strict WHATWG set, where only alphanumerics and star, dash, dot and underscore survive raw and the plus must be sent as %2B or SQL-C2 becomes a space",
			}
		}

	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "gated on THIS class's own decode probe, never on a shared one: the quote, the comma and the plus are legal raw in a path segment and the plus is a literal plus there, " +
				"but a space must be %20 and a semicolon must be %3B or a Servlet container truncates the segment, so a router that rejects percent escapes makes the slot pct_rejected for this class rather than clean",
		}

	case triage.KindFragment:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "RFC 3986 section 3.5 makes the fragment a client-side reference that every browser strips before the request goes out, so no server-side SQL statement can ever see it",
		}

	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "this class reaches only the five server-side insertion points; an unrecognised slot kind is refused rather than guessed at",
		}
	}
}

// ---------------------------------------------------------------------------------------------
// THE LADDER. CATALOGUE 2.1 and iso-query 1.7.
// ---------------------------------------------------------------------------------------------

// sqlIdentifierSlotNames is the strongest prior for an identifier or ordinal context, which is
// exactly the context every other tool misses because no quote is syntactically available there.
//
// IT ORDERS THE LADDER AND NEVER SUPPRESSES IT. A shape guess that suppresses a probe is a silent
// zero, and this codebase has removed several.
var sqlIdentifierSlotNames = map[string]bool{
	"sort": true, "order": true, "order_by": true, "orderby": true, "column": true,
	"col": true, "field": true, "group_by": true, "groupby": true, "limit": true,
	"offset": true, "page_size": true, "pagesize": true, "dir": true, "direction": true,
}

func sqlAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// sqlLadderFor returns the rungs for a slot, in order. Round 0 is the controls and the cheap
// context reads; each later rung is sent only if no early exit has fired.
func sqlLadderFor(slot triage.Slot) [][]triage.ProbeID {
	numeric := sqlAllDigits(slot.Value) || slot.ValueKind == triage.ValueNumeric
	name := strings.ToLower(strings.TrimSpace(slot.Name))
	identifierish := sqlIdentifierSlotNames[name] || slot.ValueKind == triage.ValueEnumLike

	// Rung 0 is the same for every shape: the junk control first, because if the endpoint errors
	// on a plain alphanumeric suffix then every marker-in-error verdict on this slot is void and
	// there is no point spending the other twenty requests.
	//
	// SQL-U1 IS IN RUNG 0 AND IT IS THE ONE DETECTION PROBE THAT IS, which is an ordering claim
	// and not a convenience. It is a single request, it is the class's strongest oracle, and it
	// is the only oracle here that needs no baseline, no reflection and no second request to
	// mean something. Putting it behind the shape-specific rungs costs a numeric slot five
	// requests before the one payload that answers the commonest error-based shape, and a slot
	// whose budget runs out in between reports an absence instead of a finding. Its result is
	// still read AFTER the junk control, because sqlDecide checks junk_sensitive before it looks
	// at any positive, so sending them together buys a round trip and concedes no ordering.
	rung0 := []triage.ProbeID{sqlNC1, sqlDEC, sqlU1}

	switch {
	case numeric:
		// The cast pair leads, because on a real corpus the int cast is the single most common
		// answer on a numeric slot and proving it costs two requests.
		return [][]triage.ProbeID{
			rung0,
			{sqlC5, sqlC6},
			{sqlA4, sqlA5, sqlA3},
			{sqlC2, sqlC1, sqlC3},
			{sqlQ1, sqlQ2, sqlD1P, sqlD2P},
			{sqlP3, sqlP4, sqlP1, sqlP2},
			{sqlB1, sqlB2, sqlK1, sqlK2, sqlC4},
			{sqlL1, sqlL2},
		}
	case identifierish:
		return [][]triage.ProbeID{
			rung0,
			{sqlC1, sqlC4},
			{sqlC3, sqlD1P, sqlD2P},
			{sqlB1, sqlB2, sqlK1, sqlK2},
			{sqlQ1, sqlQ2, sqlP1, sqlP2, sqlP3, sqlP4},
			{sqlC2, sqlC5, sqlC6},
			{sqlA1, sqlA2, sqlA3},
			{sqlL1, sqlL2},
		}
	default:
		// Free text, UUID, hex, date, empty and unknown all take the delimiter ladder first.
		return [][]triage.ProbeID{
			rung0,
			{sqlQ1, sqlQ2},
			{sqlD1P, sqlD2P, sqlL1, sqlL2},
			{sqlC1, sqlC3, sqlP1, sqlP2},
			{sqlB1, sqlB2, sqlK1, sqlK2, sqlP3, sqlP4},
			{sqlA1, sqlA2, sqlA3},
			{sqlC2, sqlC4},
		}
	}
}

// sqlBreakControls pairs each break with the control that proves it. A break whose control was not
// sent can never reach grade high, and a break whose control reproduced the SAME parse error is
// not a break at all: the delimiter never reached the parser.
var sqlBreakControls = map[triage.ProbeID]triage.ProbeID{
	// SQL-U1 and SQL-Q2 are the same bytes with the delimiter doubled, which is the tightest
	// break-and-control pair in the class: nothing else differs between them.
	sqlU1:  sqlQ2,
	sqlQ1:  sqlQ2,
	sqlD1P: sqlD2P,
	sqlB1:  sqlB2,
	sqlK1:  sqlK2,
	sqlP1:  sqlP2,
	sqlP3:  sqlP4,
}

// Plan is the ladder. It is called repeatedly until it returns nil.
//
// EVERY EARLY EXIT HERE ENDS THE CLASS WITH A STATEMENT, never with a shortened clean. X2 stops on
// a junk-sensitive slot and says so; X3 stops on a uniform block and says so; X4 stops on a proven
// cast and says so. The one exit that stops on a POSITIVE is X1, and it still sends the control
// and a repeat with a fresh marker first, because a hit nobody reproduced is a suspicion.
func (c sqlClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if !sqlSlotIsProbeable(ctx.Slot) {
		return nil
	}
	if ctx.Prelude.Failed() {
		// Every probe would fail validation identically, which reads as a stable endpoint with no
		// differential, which reads as clean. Send nothing and let Classify say why.
		return nil
	}
	if !ctx.Route.Resolved() {
		return nil
	}
	if ctx.Budget.Exhausted() {
		return nil
	}

	ev := sqlGather(ctx)
	if ev.err != "" {
		return nil
	}
	return sqlNextRequests(ctx, ev)
}

// sqlNextRequests is the ladder proper, split out from Plan so it can be driven from a test with
// a hand-built evidence set. A triage.Replay cannot be constructed outside package triage, so a
// test that had to go through Plan could only ever exercise the route-unresolved path, and every
// early exit in this class would ship unverified.
func sqlNextRequests(ctx triage.PlanCtx, ev *sqlEvidence) []triage.ProbeRequest {
	// X2: the junk control fired. The marker oracle is void on this slot.
	if ev.junkSensitive {
		return nil
	}
	// X3: a uniform block. Three of this class's own distinct payloads coming back byte-identical
	// and not equal to the route control is a WAF answering everything the same way.
	if ev.uniformBlock {
		return nil
	}
	// X4: the cast is proven. The delimiter ladder and the boolean arm cannot add anything, and
	// the verdict is a statement rather than an absence.
	if ev.castProven() {
		return nil
	}

	// X1: a break hit D1. Send its control, then the break again so the effect is reproduced with
	// a FRESH marker, which is what separates grade high from grade medium.
	if hit, ok := ev.firstD1Break(); ok {
		var out []triage.ProbeRequest
		if ctl, has := sqlBreakControls[hit]; has && ev.count(ctl) == 0 {
			out = append(out, sqlRequest(ctl, ctx.Slot))
		}
		if ev.count(hit) < 2 {
			out = append(out, sqlRequest(hit, ctx.Slot))
		}
		return out
	}

	// The boolean arm needs the A1, A2, A1 alternation: a page that simply differs on every second
	// request produces the same shape as a working boolean injection, and only the repeat kills it.
	if ev.booleanPairLooksTrue() && ev.count(sqlA1) < 2 {
		return []triage.ProbeRequest{sqlRequest(sqlA1, ctx.Slot)}
	}
	if ev.numericPairLooksTrue() && ev.count(sqlA4) < 2 {
		return []triage.ProbeRequest{sqlRequest(sqlA4, ctx.Slot)}
	}

	for _, rung := range sqlLadderFor(ctx.Slot) {
		var out []triage.ProbeRequest
		for _, id := range rung {
			if ev.count(id) > 0 {
				continue
			}
			if reason := sqlSkipReason(id, ctx); reason != "" {
				continue
			}
			out = append(out, sqlRequest(id, ctx.Slot))
		}
		if len(out) > 0 {
			return out
		}
	}

	// The marker-first probe, only where it is the difference between a measurement and a blind
	// spot: a field limit shorter than the end of the marker in every other payload.
	if sqlNeedsMarkerFirst(ctx.Slot) && ev.count(sqlMP) == 0 {
		return []triage.ProbeRequest{sqlRequest(sqlMP, ctx.Slot)}
	}
	// The flow probe, only when the operator budgeted a mutating request.
	if sqlFlowProbeAllowed(ctx) && ev.count(sqlS1) == 0 {
		return []triage.ProbeRequest{sqlRequest(sqlS1, ctx.Slot)}
	}
	return nil
}

// sqlSlotIsProbeable is the two rules that apply to every class and are not this class's to argue
// with: a credential slot is never probed by anybody, and a fragment reaches no server.
func sqlSlotIsProbeable(s triage.Slot) bool {
	if s.Constraints.IsCredential {
		return false
	}
	if s.Kind == triage.KindFragment || !s.ServerReachable {
		return false
	}
	if s.Wrapper == triage.WrapSigned || s.Wrapper == triage.WrapJWT {
		return false
	}
	return true
}

func sqlNeedsMarkerFirst(s triage.Slot) bool {
	lim := s.Constraints.FieldLimit
	return lim > 0 && lim < len(s.Value)+20
}

func sqlFlowProbeAllowed(ctx triage.PlanCtx) bool {
	m := strings.ToUpper(strings.TrimSpace(ctx.Slot.Method))
	if m == "" || m == "GET" || m == "HEAD" || m == "OPTIONS" || m == "DELETE" {
		return false
	}
	return ctx.Budget.RemainingMutating > 0
}

// sqlSkipReason says why a declared probe is not planned on this slot, or "" when it is. Every
// reason returned here ends up in ClassVerdict.Untested, because a class that quietly plans fewer
// probes on one slot than another is the shape of a silent zero.
func sqlSkipReason(id triage.ProbeID, ctx triage.PlanCtx) string {
	s := ctx.Slot
	cookieNoDecode := s.Kind == triage.KindCookie && s.Constraints.DecodeDepth == 0

	switch id {
	case sqlDEC:
		switch s.Kind {
		case triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie:
			return ""
		default:
			return "not_planned (no_percent_question): no payload in this class needs a percent escape in a header value, so a decode probe here would measure nothing"
		}
	case sqlA1w, sqlA2w:
		if cookieNoDecode {
			return ""
		}
		return "not_planned (whitespace_available): the /**/ substitution is only for a cookie that does not percent-decode, and this slot carries a space"
	case sqlA1, sqlA2:
		if cookieNoDecode {
			return "not_reachable (decode_depth_0): the boolean arm needs a space this cookie cannot carry, and SQL-A1w and SQL-A2w are sent in its place"
		}
		return ""
	case sqlC3:
		if cookieNoDecode {
			return "not_reachable (decode_depth_0): SQL-C3 is a space followed by the marker and this cookie does not percent-decode, so the space cannot be delivered. SQL-C1 and SQL-C2 are whitespace free and reach the same contexts"
		}
		return ""
	case sqlC5, sqlC6, sqlA4, sqlA5:
		if !sqlAllDigits(s.Value) && s.ValueKind != triage.ValueNumeric {
			return "not_planned (not_a_numeric_value): the cast detector and the numeric boolean arm are defined against a digits-only observed value, and against anything else they test a different thing while looking like the same probe"
		}
		return ""
	case sqlMP:
		if !sqlNeedsMarkerFirst(s) {
			return "not_planned (marker_not_truncated): no field limit shorter than the end of the marker in the other payloads was measured on this slot"
		}
		return ""
	case sqlS1:
		if !sqlFlowProbeAllowed(ctx) {
			return "not_probed (second_order_write_declined): the flow probe writes a value that persists, so it is sent only on a mutating verb the operator budgeted, and never on DELETE"
		}
		return ""
	case sqlL1, sqlL2:
		if s.Kind == triage.KindPath && s.Constraints.PctRejected {
			return "not_reachable (pct_rejected): the LIKE arm needs a percent sign, which must go out as %25, and this path segment's router rejected percent escapes"
		}
		return ""
	}
	return ""
}

// sqlRequest builds one ProbeRequest. The class NEVER mints a marker: the runner does, from this
// class's ordinal stripe, which is what makes attribution arithmetic rather than a convention
// every class has to remember.
func sqlRequest(id triage.ProbeID, slot triage.Slot) triage.ProbeRequest {
	v := map[string]string{
		sqlVarMarkerInPayload: sqlMarkerYes,
		sqlVarValuePosition:   sqlValueLead,
	}
	switch id {
	case sqlDEC:
		v[sqlVarMarkerForm] = sqlPercentBytes
	case sqlC4, sqlC6, sqlA1, sqlA2, sqlA3, sqlA4, sqlA5, sqlA1w, sqlA2w, sqlL1, sqlL2:
		// See sqlVarMarkerInPayload: these are complete fragments or value transforms whose
		// semantics break if a marker is appended, and they are attributed by ordinal instead.
		v[sqlVarMarkerInPayload] = sqlMarkerNo
	case sqlMP:
		v[sqlVarValuePosition] = sqlValueTrail
	}
	if id == sqlC6 {
		v[sqlVarValueTransform] = sqlDigitsToNine
	}
	if id == sqlA1w || id == sqlA2w {
		v[sqlVarWhitespaceForm] = sqlWhitespaceComm
	}
	return triage.ProbeRequest{Spec: id, Slot: slot.Key, Variant: v}
}

// ---------------------------------------------------------------------------------------------
// THE DETECTORS
// ---------------------------------------------------------------------------------------------

// sqlEnginePhrase is one regex plus the name that goes in the evidence. The set must NOT match a
// page that merely discusses SQL and must not match a bare driver name, which is why none of the
// X.*?Y shapes from sqlmap's errors.xml is in here.
type sqlEnginePhrase struct {
	name string
	re   *regexp.Regexp
}

// sqlEnginePhrases is the strong catalogue: every entry is a parser or planner message that names
// a token, which is what lets the marker land inside it.
//
// EVERY QUOTE IN EVERY PATTERN IS PRECEDED BY AN OPTIONAL BACKSLASH, and that is not decoration.
// CATALOGUE 1.4 writes the set against raw text, which is what a server-rendered page carries. A
// JSON API carries the same message JSON-escaped, so PostgreSQL's
//
//	ERROR:  syntax error at or near "zqj..."
//
// arrives as
//
//	{"error":"ERROR:  syntax error at or near \"zqj...\""}
//
// and a pattern ending in a bare quote matches neither the escaped form nor anything else in that
// body. The measured corpus is 218 vectors of a JSON API, so the catalogue's literal set would
// have been blind on the majority of it and every one of those slots would have read clean. The
// optional backslash costs nothing on a raw body and recovers the whole JSON case.
// sqlQuoteForms is A SINGLE QUOTE AS IT CAN ACTUALLY REACH US, and sqlDQuoteForms is the same for
// a double quote. Every strong phrase that anchors on the quote a driver puts around the offending
// token is built from these instead of from a literal quote, and that is the whole difference
// between a detector and a blind spot on the commonest error page there is.
//
// THE MEASUREMENT THAT FORCED THIS. The oracle's /sqli/mssql and /sqli/mysql are LIVE INJECTIONS:
// ORDER BY [<input>] and ORDER BY `<input>`, the two contexts a quote ladder cannot reach at all,
// and the two contexts SQL-K1 and SQL-B1 exist for. Both answer HTTP 500 with a real driver
// message carrying this run's marker. This class reported CLEAN on both. A clean on a live
// injection is the worst answer it can give: the operator does not point sqlmap there and the bug
// is never found.
//
// The payload was right, the probe was sent, the marker came back sitting against the phrase, and
// the phrase did not match, because the page is SERVER-RENDERED HTML and the driver's quote
// arrives as an ENTITY:
//
//	Incorrect syntax near 'zqjsql0000004ju8['         is what the driver wrote
//	Incorrect syntax near &#39;zqjsql0000004ju8[&#39;. is what this class receives
//
// The catalogue had already learned half of this lesson. The optional backslash on every quote
// was added because a JSON API carries the same message as \" and the literal set was blind on
// 218 measured vectors. HTML ESCAPING IS THE SAME DEFECT IN A SECOND ENCODING, and it is the
// larger half: html.EscapeString in Go, htmlspecialchars with ENT_QUOTES in PHP, html.escape in
// Python, Jinja and Twig autoescaping, JSTL's <c:out> and every XML serialiser all do it, and a
// framework debug page is exactly where an unhandled driver exception gets rendered. Nine of the
// eighteen strong phrases end in a quote, so nine of eighteen were unreachable on any escaped
// page, and every one of those slots read clean.
//
// The forms are the ones real escapers emit: the bare character, the JSON backslash form, the
// decimal entity with any number of leading zeros, the hex entity in either case, and the named
// entity. Nothing here widens the PROSE half of any pattern, which is what keeps the catalogue
// from matching a page that merely discusses SQL.
const (
	sqlQuoteForms  = `(?:'|\\'|&(?:#0*39|#[xX]0*27|apos);)`
	sqlDQuoteForms = `(?:"|\\"|&(?:#0*34|#[xX]0*22|quot);)`
)

var sqlEnginePhrases = []sqlEnginePhrase{
	{"pg.syntax_error_at_or_near", regexp.MustCompile(`(?i)syntax error at or near ` + sqlDQuoteForms)},
	{"pg.column_does_not_exist", regexp.MustCompile(`(?i)column ` + sqlDQuoteForms + `[^\n]{1,200}?does not exist`)},
	{"pg.unterminated_quoted", regexp.MustCompile(`(?i)unterminated quoted (string|identifier) at or near`)},
	{"pg.trailing_junk_numeric", regexp.MustCompile(`(?i)trailing junk after numeric literal at or near`)},
	{"pg.order_by_position", regexp.MustCompile(`(?i)(ORDER|GROUP) BY position \d+ is not in select list`)},
	{"pg.invalid_input_syntax", regexp.MustCompile(`(?i)invalid input syntax for type (bigint|integer|numeric|uuid|boolean|date|timestamp): ` + sqlDQuoteForms)},
	{"mysql.right_syntax_near", regexp.MustCompile(`(?i)right syntax to use near ` + sqlQuoteForms)},
	{"mysql.unknown_column_in", regexp.MustCompile(`(?i)Unknown column ` + sqlQuoteForms + `[^\n]{1,200}?in ` + sqlQuoteForms + `(ORDER BY|GROUP BY|WHERE|HAVING|field list|order clause|having clause|on clause)`)},
	{"mysql.undeclared_variable", regexp.MustCompile(`(?i)Undeclared variable: `)},
	{"sqlite.no_such_column", regexp.MustCompile(`(?i)no such column: `)},
	{"sqlite.near_syntax_error", regexp.MustCompile(`(?i)near ` + sqlDQuoteForms + `[^\n]{1,200}?: syntax error`)},
	{"sqlite.unrecognized_token", regexp.MustCompile(`(?i)unrecognized token: ` + sqlDQuoteForms)},
	{"sqlite.order_by_term_range", regexp.MustCompile(`(?i)\d+(st|nd|rd|th) (ORDER|GROUP) BY term out of range`)},
	{"mssql.incorrect_syntax_near", regexp.MustCompile(`(?i)Incorrect syntax near ` + sqlQuoteForms)},
	{"mssql.invalid_column_name", regexp.MustCompile(`(?i)Invalid column name ` + sqlQuoteForms)},
	{"mssql.unclosed_quotation", regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`)},
	{"mssql.order_by_position_range", regexp.MustCompile(`(?i)The (ORDER BY|GROUP BY) position number \d+ is out of range`)},
	{"oracle.ora_parse", regexp.MustCompile(`(?i)\bORA-(00904|00933|00907|01756|01785|00920|00936)\b`)},
}

// sqlWeakPhrases is the catalogue that may ONLY raise an existing hit from suspicious to finding.
// On its own it produces nothing at all, because every one of these was measured firing on
// ordinary pages: a driver name in a stack trace, a framework banner, a page about databases.
var sqlWeakPhrases = []sqlEnginePhrase{
	{"weak.driver_sqlserver", regexp.MustCompile(`(?i)Driver.{0,40}SQL[\-_ ]*Server`)},
	{"weak.oracle_driver", regexp.MustCompile(`(?i)Oracle.{0,40}Driver`)},
	{"weak.oledb_sqlserver", regexp.MustCompile(`(?i)OLE DB.{0,40}SQL Server`)},
	{"weak.postgresql_error", regexp.MustCompile(`(?i)PostgreSQL.{0,40}ERROR`)},
	{"weak.db2_sql_error", regexp.MustCompile(`(?i)DB2 SQL error`)},
	{"weak.sybase_message", regexp.MustCompile(`(?i)Sybase message`)},
	{"weak.generic_sql_word", regexp.MustCompile(`(?i)SQL (warning|error|syntax)`)},
}

// sqlEngineFingerprints reads the engine off probes that were already sent for detection, so
// identification is free. The label is what makes the operator's sqlmap run cheaper than a cold
// start: --dbms saves the whole fingerprint phase.
//
// These carry the SAME quote forms as the strong catalogue, for the same measured reason: on
// /sqli/mssql and /sqli/mysql the driver message is entity-escaped, so a fingerprint anchored on
// a literal quote named no engine on two routes whose engine is printed in the first line of the
// reply, and the operator was handed a finding with no --dbms to go with it.
var sqlEngineFingerprints = []struct {
	engine string
	re     *regexp.Regexp
}{
	{"postgresql", regexp.MustCompile(`(?i)(syntax error at or near ` + sqlDQuoteForms + `|trailing junk after numeric literal|(ORDER|GROUP) BY position \d+ is not in select list|unterminated quoted (string|identifier)|invalid input syntax for type)`)},
	{"mysql", regexp.MustCompile(`(?i)(right syntax to use near ` + sqlQuoteForms + `|Unknown column ` + sqlQuoteForms + `[^\n]{1,128}?in ` + sqlQuoteForms + `|Undeclared variable: )`)},
	{"sqlite", regexp.MustCompile(`(?i)(no such column: |near ` + sqlDQuoteForms + `[^\n]{1,128}?: syntax error|unrecognized token: ` + sqlDQuoteForms + `|\d+(st|nd|rd|th) (ORDER|GROUP) BY term out of range)`)},
	{"mssql", regexp.MustCompile(`(?i)(Incorrect syntax near ` + sqlQuoteForms + `|Invalid column name ` + sqlQuoteForms + `|Unclosed quotation mark after the character string|The (ORDER BY|GROUP BY) position number \d+ is out of range)`)},
	{"oracle", regexp.MustCompile(`(?i)\bORA-\d{5}\b`)},
}

// sqlD1Result is one evaluation of the primary oracle against one response.
type sqlD1Result struct {
	Fired      bool
	Phrase     string
	PhraseAt   int
	Matched    []byte
	MarkerAt   int
	MarkerForm string
	Marker     triage.Marker
	// Why is set when a phrase matched but the hit was REFUSED, so the refusal is visible rather
	// than looking like an absence.
	Why string
}

// sqlEvalD1 is the primary oracle: an engine phrase with THIS RUN'S marker inside a 120-byte
// window of it, on the same logical line.
//
// THE FOUR REFUSALS ARE THE DETECTOR. Without them this is a substring search:
//
//	the marker is absent          the phrase is the application's own content, not our error.
//	                              This is the entire /clean/dberror case.
//	the run id is not ours        a cached or replayed body from an earlier run. stale_marker.
//	the ordinal stripe is not ours another class's marker landed here. A hit for nobody (R12).
//	the marker is further than    the payload was echoed next to prose that mentions SQL.
//	120 bytes or on another line  This is the /clean/echoparser case.
func sqlEvalD1(obs triage.Observation) sqlD1Result {
	body := obs.Body
	if len(body) == 0 {
		return sqlD1Result{Why: "no_body"}
	}
	var out sqlD1Result
	for _, p := range sqlEnginePhrases {
		loc := p.re.FindIndex(body)
		if loc == nil {
			continue
		}
		out.Phrase = p.name
		out.PhraseAt = loc[0]
		out.Matched = append([]byte(nil), body[loc[0]:loc[1]]...)

		for _, h := range sqlMarkerHits(obs) {
			if !sqlWithinWindow(body, loc[0], loc[1], h.Offset, h.Offset+h.Length) {
				out.Why = "phrase_and_marker_not_the_same_error: the marker is more than 120 bytes from the phrase, or across a blank line, or on a line that is not a driver echoing the statement back. The payload was echoed on a page that also mentions a database, which is not the same as the database complaining about the payload"
				continue
			}
			switch {
			case !h.Marker.BelongsTo(triage.ClassSQL):
				out.Why = "foreign_marker_observed: the marker in the error belongs to another class's ordinal stripe, so it is a hit for nobody"
			case h.Marker.RunID() != obs.RunID:
				out.Why = "stale_marker: the marker in the error was minted by a different run, so the body is cached or replayed"
			case h.Marker.Integrity() == triage.MarkerCorrupted:
				out.Why = "marker_corrupted: something rewrote the middle of the marker, so attribution is unsafe"
				out.Fired = true
				out.MarkerAt = h.Offset
				out.MarkerForm = h.Form
				out.Marker = h.Marker
			default:
				out.Fired = true
				out.Why = ""
				out.MarkerAt = h.Offset
				out.MarkerForm = h.Form
				out.Marker = h.Marker
				return out
			}
		}
		if out.Why == "" {
			out.Why = "marker_absent_from_phrase: the engine phrase is in this response but THIS RUN'S marker is not next to it, which is the application's own content and not our error"
		}
	}
	return out
}

// sqlMarkerHits prefers the shared transform search recorded at capture, and falls back to a
// literal and uppercase scan of the body when nothing recorded any.
//
// The fallback is deliberately narrow. The shared search covers eleven transforms including the
// three base64 alignments and UTF-16LE; this class does not reimplement them, and a body whose
// only marker is base64-encoded and which arrived with no recorded hits is reported as undecided
// rather than searched badly.
func sqlMarkerHits(obs triage.Observation) []triage.MarkerHit {
	if len(obs.Proj.MarkerHits) > 0 {
		return obs.Proj.MarkerHits
	}
	if obs.Marker == "" {
		return nil
	}
	var out []triage.MarkerHit
	raw := []byte(obs.Marker)
	for i := 0; ; {
		j := bytes.Index(obs.Body[i:], raw)
		if j < 0 {
			break
		}
		out = append(out, triage.MarkerHit{Form: "raw", Offset: i + j, Length: len(raw), Marker: obs.Marker})
		i += j + len(raw)
	}
	up := bytes.ToUpper(raw)
	for i := 0; ; {
		j := bytes.Index(obs.Body[i:], up)
		if j < 0 {
			break
		}
		out = append(out, triage.MarkerHit{Form: "upper", Offset: i + j, Length: len(up), CaseTransform: "upper", Marker: obs.Marker})
		i += j + len(up)
	}
	return out
}

// sqlStatementEchoLabel matches the start of a line on which a database driver quotes the
// SUBMITTED STATEMENT back. Every label here is a real driver's own wording:
//
//	Query:       the PostgreSQL JDBC driver's PSQLException detail
//	LINE n:      the PostgreSQL server context line, printed by psql, psycopg and pgx
//	CONTEXT:     the PostgreSQL server message field that carries the failing statement
//	DETAIL:      likewise, and it is where the offending VALUE usually appears
//	SQL:         Hibernate and MySQL Connector/J
//	Statement:   the JDBC statement echo
//	SQLSTATE[    PDO, whose message is the statement's neighbour on the same block
//
// An optional single opening tag is allowed before the label because a server-rendered page wraps
// each line of the block, and refusing that would make the rule work on a text/plain body and
// fail on the same error in HTML.
var sqlStatementEchoLabel = regexp.MustCompile(`(?i)^[\t ]*(?:<[a-z/][^>\n]{0,40}>)?[\t ]*(LINE\s+\d+|Query|SQL|Statement|SQLSTATE|CONTEXT|DETAIL)\s*[:\[]`)

// sqlWithinWindow decides whether a marker and an engine phrase are THE SAME ERROR.
//
// The distance rule is 120 bytes and it is unchanged. What is new is the second way to associate
// them, and it closes a false negative measured on the class's own positive control.
//
// THE SAME-LINE RULE ALONE ONLY EVER SAW A SINGLE-LINE MySQL 1064. A driver exception is a BLOCK:
// the first line names the complaint and a later line quotes the statement back with our marker
// in it. That is the layout of PSQLException, of psycopg, of PDO and of Hibernate, and it is what
// the oracle's /sqli route returns. Requiring the same line refused every one of them, so the
// class's strongest oracle could not fire on the commonest error page on the web.
//
// WHAT IT IS STILL REFUSED. The relaxation is not "allow newlines". The marker's own line must
// LOOK like a driver echoing a statement, the two must be inside one block with no blank line
// between them, and the 120 bytes still bind. So a marker sitting alone on the next line is still
// refused, which is the /clean/echoparser family and the stack-trace-plus-template case the
// same-line rule was written for: those lines carry no driver label.
func sqlWithinWindow(body []byte, phraseStart, phraseEnd, markerStart, markerEnd int) bool {
	lo, hi := phraseEnd, markerStart
	if markerEnd <= phraseStart {
		lo, hi = markerEnd, phraseStart
	} else if markerStart < phraseEnd && markerEnd > phraseStart {
		return true // they overlap: the marker is inside the matched phrase
	}
	if lo < 0 || hi > len(body) || lo > hi {
		return false
	}
	if hi-lo > sqlPhraseWindow {
		return false
	}
	between := body[lo:hi]
	if !bytes.ContainsRune(between, '\n') {
		return true
	}
	// A blank line is a block boundary in a rendered page and in a plain-text log alike, so two
	// things either side of one are not the same error.
	if bytes.Contains(between, []byte("\n\n")) || bytes.Contains(between, []byte("\n\r\n")) {
		return false
	}
	return sqlStatementEchoLabel.Match(sqlLineAt(body, markerStart))
}

// sqlLineAt returns the whole line the given offset sits on, without its terminator.
func sqlLineAt(body []byte, off int) []byte {
	if off < 0 || off > len(body) {
		return nil
	}
	start := bytes.LastIndexByte(body[:off], '\n') + 1
	end := bytes.IndexByte(body[off:], '\n')
	if end < 0 {
		end = len(body)
	} else {
		end += off
	}
	return body[start:end]
}

// sqlWeakSignature reports whether the weak catalogue matched. It NEVER produces a verdict by
// itself; it only raises a hit this class's own strong oracle already made.
func sqlWeakSignature(body []byte) (string, bool) {
	for _, p := range sqlWeakPhrases {
		if p.re.Match(body) {
			return p.name, true
		}
	}
	return "", false
}

func sqlIdentifyEngine(body []byte) string {
	for _, f := range sqlEngineFingerprints {
		if f.re.Match(body) {
			return f.engine
		}
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// THE COMPARISON
// ---------------------------------------------------------------------------------------------

type sqlCmp string

const (
	// sqlCmpUnusable is the ZERO VALUE on purpose. An unmeasured comparison must never read as
	// "same", because "same" is what the boolean arm's true arm needs and a default of same would
	// manufacture the true half of the differential out of nothing.
	sqlCmpUnusable  sqlCmp = ""
	sqlCmpSame      sqlCmp = "same"
	sqlCmpDifferent sqlCmp = "different"
)

// sqlCompare differences one probe response against the route control.
//
// It uses the projections rather than raw bytes wherever they exist, because the normalised body
// has the volatile regions and every marker form removed: comparing raw bytes on a page carrying a
// request id and our own echoed marker reports "different" for every probe ever sent.
func sqlCompare(probe, control triage.Observation) sqlCmp {
	if !probe.Delivered() || !control.Delivered() {
		return sqlCmpUnusable
	}
	if probe.Status != control.Status {
		return sqlCmpDifferent
	}
	var zero [32]byte
	if probe.Proj.NormBodySHA256 != zero && control.Proj.NormBodySHA256 != zero {
		if probe.Proj.NormBodySHA256 == control.Proj.NormBodySHA256 {
			return sqlCmpSame
		}
		return sqlCmpDifferent
	}
	// The shape-only route: a JSON API whose body varies but whose array cardinalities do not.
	// /data/results.__len__ going from 12 to 0 and back is the cleanest boolean oracle a JSON API
	// offers, and it survives a body that carries a timestamp.
	if probe.Proj.JSONParsed && control.Proj.JSONParsed {
		if sqlSameStrings(probe.Proj.JSONCards, control.Proj.JSONCards) &&
			sqlSameStrings(probe.Proj.JSONKeySet, control.Proj.JSONKeySet) {
			return sqlCmpSame
		}
		return sqlCmpDifferent
	}
	if probe.BodyLen == 0 && control.BodyLen == 0 {
		// No body at all on either side. That is not "identical bodies, therefore same".
		return sqlCmpUnusable
	}
	if probe.BodyTruncated || control.BodyTruncated {
		return sqlCmpUnusable
	}
	if probe.BodySHA256 == control.BodySHA256 {
		return sqlCmpSame
	}
	return sqlCmpDifferent
}

func sqlSameStrings(a, b []string) bool {
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

// ---------------------------------------------------------------------------------------------
// THE EVIDENCE SET
// ---------------------------------------------------------------------------------------------

type sqlSeen struct {
	probe   triage.ProbeID
	ordinal uint64
	marker  triage.Marker
	obs     triage.Observation
	d1      sqlD1Result
	cmp     sqlCmp
}

type sqlEvidence struct {
	byProbe map[triage.ProbeID][]sqlSeen
	all     []sqlSeen
	control triage.Observation
	haveCtl bool

	junkSensitive bool
	uniformBlock  bool
	// uniformInert names the metacharacter-free probe of this class that shares a collapsed
	// response bucket with three or more others. It is what turns "a filter answered" into "the
	// application answers every unrecognised value the same way", and it is reported rather than
	// dropped because the collapse itself is a fact about the endpoint.
	uniformInert triage.ProbeID
	decodeDepth  int
	echoedAny    bool
	engine       string
	weakSeen     string
	// err is set when the runner handed this class a response it could not read. It is loud on
	// purpose: it means the vault and the filter disagree, and a verdict drawn after that would be
	// a verdict about somebody else's probe.
	err string
}

func sqlGather(ctx triage.PlanCtx) *sqlEvidence {
	ev := &sqlEvidence{byProbe: map[triage.ProbeID][]sqlSeen{}, decodeDepth: -1}
	if ctx.Route.Resolved() {
		ev.control = ctx.Route.Obs()
		ev.haveCtl = true
	}
	for i := 0; i < ctx.Own.Len(); i++ {
		p, o, err := ctx.Own.At(i)
		if err != nil {
			ev.err = err.Error()
			return ev
		}
		// The probe id, the ordinal and the marker come from the HANDLE, which resolves through
		// the vault, and never from the observation's own stamped fields. A mis-stamped
		// observation is exactly the case the vault exists to survive.
		s := sqlSeen{probe: p.ProbeID(), ordinal: p.Ordinal(), marker: p.Marker(), obs: o}
		s.d1 = sqlEvalD1(o)
		if ev.haveCtl {
			s.cmp = sqlCompare(o, ev.control)
		}
		ev.byProbe[s.probe] = append(ev.byProbe[s.probe], s)
		ev.all = append(ev.all, s)

		if len(sqlMarkerHits(o)) > 0 {
			ev.echoedAny = true
		}
		if e := sqlIdentifyEngine(o.Body); e != "" && ev.engine == "" {
			ev.engine = e
		}
		if w, ok := sqlWeakSignature(o.Body); ok && ev.weakSeen == "" {
			ev.weakSeen = w
		}
		if s.probe == sqlNC1 && s.d1.Fired {
			ev.junkSensitive = true
		}
		if s.probe == sqlDEC {
			ev.decodeDepth = sqlDecodeDepth(o)
		}
	}
	ev.uniformBlock, ev.uniformInert = sqlUniformBlock(ev)
	return ev
}

// sqlDecodeDepth reads the three deterministic outcomes of this class's own decode probe.
// Unknown is -1 and it is NOT zero: zero is a measurement saying the slot does not decode, and the
// two produce different verdicts downstream.
func sqlDecodeDepth(o triage.Observation) int {
	if len(sqlMarkerHits(o)) > 0 {
		return 1
	}
	if bytes.Contains(bytes.ToLower(o.Body), sqlPercentEncodeBytes(string(o.Marker))) {
		return 0
	}
	return -1
}

// sqlInertPayloads are the probes in this class whose bytes carry NO metacharacter of any kind.
//
// SQL-NC1 is the marker followed by four digits, purely alphanumeric, and it cannot break a
// statement in any dialect. SQL-C6 appends nothing at all: it replaces every ASCII digit of the
// observed value with a 9, same length, no punctuation. A filter that is refusing metacharacters
// has nothing to refuse in either of them, which is what makes them able to answer a question no
// other probe in this class can answer.
var sqlInertPayloads = map[triage.ProbeID]bool{sqlNC1: true, sqlC6: true}

// sqlUnreadableBreak is THE SAFETY NET UNDER THE ERROR ORACLE, and it exists because of the one
// shape this class must never produce: a payload that visibly broke the server, and a verdict of
// clean.
//
// The error oracle needs a phrase from the strong catalogue AND this run's marker beside it.
// When neither is readable the oracle has learned NOTHING, and until now that fell straight
// through to the arm's clean. There are three ordinary ways to get there and none of them is the
// endpoint being sound:
//
//	the driver's message is not in the catalogue      Informix, Firebird, Teradata, HANA, an ORM
//	                                                  that wraps the driver text in its own
//	the application catches the exception and         a bare "Something went wrong" 500 carries
//	renders its own error page                        no phrase and no marker at all
//	the phrase is encoded in a form we do not read    the defect this same commit just fixed for
//	                                                  HTML entities, and the next encoding is out
//	                                                  there
//
// MEASURED: /sqli/mssql and /sqli/mysql answered HTTP 500 to the bracket and the backtick and
// HTTP 200 to everything else including SQL-NC1, this class's own purely alphanumeric control,
// and the class reported parser_error CLEAN on both. The catalogue fix makes those two routes
// readable; this gate is what catches the next one that is not.
//
// THE CONDITION IS DELIBERATELY NARROW, because a gate that fires often is a gate the operator
// learns to skip:
//
//	the probe carries a metacharacter of this class   an inert probe proves nothing about syntax
//	its response is 5xx                               a 4xx is a REJECTION, which is input
//	                                                  validation, and blocked, uniform_block and
//	                                                  metachar_not_delivered already own that.
//	                                                  /clean/validate answers 400 and stays out
//	SQL-NC1 or SQL-C6, which carry no metacharacter   otherwise the endpoint errors on any
//	anywhere, did NOT get a 5xx                       modified value and junk_sensitive owns it.
//	                                                  /clean/junk stays out
//	the route control did not get a 5xx               /clean/always500 is not a break
//
// It returns the first such probe in send order, its status and the metacharacter-free witness
// that makes the comparison mean something, so the verdict can name all three.
func (ev *sqlEvidence) unreadableBreak() (triage.ProbeID, int, string, bool) {
	haveRouteControl := ev.haveCtl && ev.control.Delivered()
	if haveRouteControl && ev.control.Status >= 500 {
		return "", 0, "", false
	}
	witness := ""
	for _, s := range ev.all {
		if !sqlInertPayloads[s.probe] || !s.obs.Delivered() {
			continue
		}
		if s.obs.Status >= 500 {
			return "", 0, "", false
		}
		if witness == "" {
			witness = string(s.probe) + ", which is this class's own payload with no metacharacter in it,"
		}
	}
	if witness == "" {
		if !haveRouteControl {
			// Nothing without a metacharacter was measured on this slot at all, so a 5xx cannot
			// be attributed to the metacharacter rather than to the request. Saying so would be
			// inventing the comparison this gate is made of.
			return "", 0, "", false
		}
		witness = "the route control, taken at the observed value,"
	}
	for _, s := range ev.all {
		if sqlInertPayloads[s.probe] || s.probe == sqlDEC || !s.obs.Delivered() {
			continue
		}
		if s.obs.Status >= 500 {
			return s.probe, s.obs.Status, witness, true
		}
	}
	return "", 0, "", false
}

// sqlUniformBlock is this class's OWN uniform-block rule. Three or more of this class's distinct
// payloads producing byte-identical responses that are not the control is a WAF answering
// everything the same way, and no other class is consulted about it.
//
// A BUCKET HOLDING ONE OF THIS CLASS'S METACHARACTER-FREE PAYLOADS IS NOT A BLOCK, and the
// version without that condition was the most expensive false negative in this file. Consider the
// commonest shape on the web: a lookup parameter whose observed value selects a record. The
// control returns the record; every other value, quote-laden or not, returns one byte-identical
// "nothing found" page. Three of this class's payloads land in that bucket after four requests,
// the old rule called it a filter, X3 stopped the ladder, and the delimiter ladder and the
// BOOLEAN ARM were never sent. The boolean arm is the only detector here that can see an endpoint
// suppressing its errors, and a lookup parameter is exactly where a blind boolean injection
// lives, so the early exit removed the one detector that shape needs and the operator was told a
// filter had answered. Measured against the oracle at /sqli?id=1: SQL-NC1, SQL-DEC, SQL-C5 and
// SQL-C6 all return the same 87-byte "0 products matched" page while the control returns the
// 146-byte row, and the class returned blocked after four of its twenty-three probes.
//
// SQL-NC1 in that bucket settles it in the other direction. It carries no metacharacter, so a
// metacharacter filter cannot be what produced its response, so the shared page is the
// application's own answer to any value it does not recognise and the ladder must continue.
// It returns the probe that disproved the filter so the verdict can name it rather than silently
// declining to fire.
func sqlUniformBlock(ev *sqlEvidence) (blocked bool, disprovedBy triage.ProbeID) {
	if !ev.haveCtl {
		return false, ""
	}
	type bucket struct {
		probes map[triage.ProbeID]bool
		inert  triage.ProbeID
	}
	counts := map[[32]byte]*bucket{}
	for _, s := range ev.all {
		if !s.obs.Delivered() || s.obs.BodyLen == 0 {
			continue
		}
		if s.cmp != sqlCmpDifferent {
			continue
		}
		b := counts[s.obs.BodySHA256]
		if b == nil {
			b = &bucket{probes: map[triage.ProbeID]bool{}}
			counts[s.obs.BodySHA256] = b
		}
		b.probes[s.probe] = true
		if sqlInertPayloads[s.probe] && b.inert == "" {
			b.inert = s.probe
		}
	}
	var disproved triage.ProbeID
	for _, b := range counts {
		if len(b.probes) < 3 {
			continue
		}
		if b.inert != "" {
			// Not a block, and the fact is worth reporting rather than dropping: several of this
			// class's payloads DID collapse onto one response, and the reason is the application
			// rather than a filter.
			if disproved == "" {
				disproved = b.inert
			}
			continue
		}
		return true, ""
	}
	return false, disproved
}

func (ev *sqlEvidence) count(id triage.ProbeID) int { return len(ev.byProbe[id]) }

func (ev *sqlEvidence) first(id triage.ProbeID) (sqlSeen, bool) {
	if s := ev.byProbe[id]; len(s) > 0 {
		return s[0], true
	}
	return sqlSeen{}, false
}

// firstD1Break returns the first BREAK probe whose response fired the primary oracle. Controls are
// excluded: a control firing is not a hit, it is a broken detector, and it is handled separately.
func (ev *sqlEvidence) firstD1Break() (triage.ProbeID, bool) {
	// SQL-U1 leads because it is the break that leaves the literal open, so when it and a repaired
	// break both fired it is the one whose error names what happened.
	order := []triage.ProbeID{sqlU1, sqlQ1, sqlD1P, sqlB1, sqlK1, sqlP1, sqlP3, sqlC1, sqlC2, sqlC3, sqlC5, sqlMP}
	for _, id := range order {
		for _, s := range ev.byProbe[id] {
			if s.d1.Fired {
				return id, true
			}
		}
	}
	return "", false
}

// castProven is early exit X4: the cast detector sits at baseline AND the influence control moved
// the response. Both halves are required. The influence control is what separates "the value is
// cast to an integer" from "the value does nothing at all", and those are two different verdicts.
func (ev *sqlEvidence) castProven() bool {
	c5, ok5 := ev.first(sqlC5)
	c6, ok6 := ev.first(sqlC6)
	return ok5 && ok6 && c5.cmp == sqlCmpSame && c6.cmp == sqlCmpDifferent
}

func (ev *sqlEvidence) parameterInert() bool {
	c5, ok5 := ev.first(sqlC5)
	c6, ok6 := ev.first(sqlC6)
	return ok5 && ok6 && c5.cmp == sqlCmpSame && c6.cmp == sqlCmpSame
}

func (ev *sqlEvidence) booleanPairLooksTrue() bool {
	a1, ok1 := ev.first(sqlA1)
	a2, ok2 := ev.first(sqlA2)
	if !ok1 || !ok2 {
		a1, ok1 = ev.first(sqlA1w)
		a2, ok2 = ev.first(sqlA2w)
	}
	return ok1 && ok2 && a1.cmp == sqlCmpSame && a2.cmp == sqlCmpDifferent
}

func (ev *sqlEvidence) numericPairLooksTrue() bool {
	a4, ok4 := ev.first(sqlA4)
	a5, ok5 := ev.first(sqlA5)
	return ok4 && ok5 && a4.cmp == sqlCmpSame && a5.cmp == sqlCmpDifferent
}

// d2Confirmed is the full boolean rule: the true arm matches the control, the false arm does not,
// the invalid-syntax control does NOT look like the true arm, and the true arm reproduced on a
// second send. One half alone proves nothing, because any payload can break a page.
func (ev *sqlEvidence) d2Confirmed() (triage.ProbeID, bool) {
	check := func(t, f triage.ProbeID) bool {
		ts := ev.byProbe[t]
		fs := ev.byProbe[f]
		a3, okA3 := ev.first(sqlA3)
		if len(ts) < 2 || len(fs) < 1 || !okA3 {
			return false
		}
		if a3.cmp == sqlCmpSame {
			return false // the control looks TRUE, so the detector is not verified here
		}
		for _, s := range ts {
			if s.cmp != sqlCmpSame {
				return false
			}
		}
		return fs[0].cmp == sqlCmpDifferent
	}
	if check(sqlA1, sqlA2) {
		return sqlA1, true
	}
	if check(sqlA1w, sqlA2w) {
		return sqlA1w, true
	}
	if check(sqlA4, sqlA5) {
		return sqlA4, true
	}
	return "", false
}

// d3Widened is the LIKE rule: the bare percent widened and the escaped one did not. Both halves
// are required, because a bare percent widening on an endpoint that already does prefix search
// (which is most search endpoints) means nothing at all.
func (ev *sqlEvidence) d3Widened() bool {
	l1, ok1 := ev.first(sqlL1)
	l2, ok2 := ev.first(sqlL2)
	return ok1 && ok2 && l1.cmp == sqlCmpDifferent && l2.cmp == sqlCmpSame
}

// controlReproducedTheError is the metachar_not_delivered check. If the doubled delimiter produces
// the SAME engine phrase as the break, the delimiter never reached SQL: something else in the
// request path is erroring, and reading that as a break is a false positive with a marker in it.
func (ev *sqlEvidence) controlReproducedTheError(hit triage.ProbeID) bool {
	ctl, ok := sqlBreakControls[hit]
	if !ok {
		return false
	}
	h, okH := ev.first(hit)
	c, okC := ev.first(ctl)
	if !okH || !okC || !c.d1.Fired {
		return false
	}
	// An unknown-column phrase from the control is the IDENTIFIER-CONTEXT SIGNAL and is expected,
	// not a failure. Only the same PARSE error is disqualifying.
	if c.d1.Phrase == "mysql.unknown_column_in" || c.d1.Phrase == "pg.column_does_not_exist" ||
		c.d1.Phrase == "mssql.invalid_column_name" || c.d1.Phrase == "sqlite.no_such_column" {
		return false
	}
	return c.d1.Phrase == h.d1.Phrase
}

// anyControlFired is the detector_unverified rule from CATALOGUE 4.4: if any of a class's negative
// controls fires, that class's verdicts on that slot become cannot_determine, and the run is
// flagged. A detector that has been shown firing on its own negative control is broken.
// IT IS SCOPED TO THE ARM THE CONTROL BELONGS TO, and the first version was not.
//
// SQL-A3 matching the control is only a broken detector when the boolean pair otherwise looked
// TRUE. On an endpoint that ignores the parameter entirely, A1, A2 and A3 all match the control
// and nothing is wrong with the detector: nothing is wrong with anything, the value is inert, and
// that is a different verdict with a different reason. The unscoped version turned every inert
// slot in the corpus into detector_unverified and hid nine other reasons behind it, which the
// table test caught on the first run.
func (ev *sqlEvidence) anyControlFired() (triage.ProbeID, bool) {
	if a3, ok := ev.first(sqlA3); ok && a3.cmp == sqlCmpSame {
		if ev.booleanPairLooksTrue() || ev.numericPairLooksTrue() {
			return sqlA3, true
		}
	}
	return "", false
}

// likeArmUnreadable is the LIKE pair's OWN ambiguity, and it is deliberately not in
// anyControlFired.
//
// THE FALSE NEGATIVE THIS SPLIT EXISTS FOR, measured against the oracle. The old rule read "the
// bare percent moved the response and the escaped percent moved it too" as this class's negative
// control FIRING, and anyControlFired returns a class-wide cannot_determine (detector_unverified)
// from rule 3, which is BEFORE any positive is looked at. Both halves move the response on every
// endpoint whose value selects a record, because every value that is not the one on record gets
// the same "nothing found" page, and that is most of the web. So a slot carrying a live parser
// break was reported as a broken detector and sqlmap was never pointed at it. /xss, /lfi and
// /ssti on the oracle all landed there, for a class none of them can even exhibit.
//
// It is also not what the words say. A control fires when the detector's own negative produces
// the detector's positive reading, which is why the SQL-A3 half is scoped to "the boolean pair
// otherwise looked TRUE". The LIKE detector's positive reading is d3Widened, which REQUIRES the
// escaped percent to have stayed put, so the two conditions are mutually exclusive: when this
// holds, the LIKE arm has claimed nothing that could be withdrawn. What has actually happened is
// that the LIKE arm cannot be read on this slot, which is a fact about one arm and is reported
// as its own row, alongside the arms that could be read.
func (ev *sqlEvidence) likeArmUnreadable() bool {
	l1, ok1 := ev.first(sqlL1)
	l2, ok2 := ev.first(sqlL2)
	return ok1 && ok2 && l1.cmp == sqlCmpDifferent && l2.cmp == sqlCmpDifferent
}

// ---------------------------------------------------------------------------------------------
// THE VERDICT
// ---------------------------------------------------------------------------------------------

func sqlLabel(engine string) triage.TriageLabel {
	l := triage.TriageLabel{
		Tools: []string{"sqlmap", "ghauri", "sqlidetector"},
		Hints: map[string]string{},
	}
	if engine != "" {
		l.Engine = engine
		l.Dialect = engine
		// --dbms saves sqlmap the whole fingerprint phase, which is the point of reading the
		// engine off probes that were sent for detection anyway.
		l.Hints["sqlmap_dbms"] = engine
	}
	return l
}

func sqlOrdinalsOf(ss ...sqlSeen) []uint64 {
	out := make([]uint64, 0, len(ss))
	for _, s := range ss {
		out = append(out, s.ordinal)
	}
	return out
}

func (ev *sqlEvidence) allOrdinals() []uint64 {
	out := make([]uint64, 0, len(ev.all))
	for _, s := range ev.all {
		out = append(out, s.ordinal)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// sqlUntested lists every declared probe this class did not send on this slot, with a reason.
func sqlUntested(c sqlClassifier, ctx triage.ClassifyCtx, ev *sqlEvidence) []triage.ProbeSkip {
	var out []triage.ProbeSkip
	for _, p := range c.Probes() {
		if ev.count(p.ID) > 0 {
			continue
		}
		reason := sqlSkipReason(p.ID, ctx.PlanCtx)
		if reason == "" {
			reason = "not_run (early_exit): the ladder stopped before this rung because an earlier probe settled the slot. It was not sent and it is not clean"
		}
		out = append(out, triage.ProbeSkip{ProbeID: p.ID, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProbeID < out[j].ProbeID })
	return out
}

// Classify is the verdict. It is called once, after Plan returns nil or the budget is exhausted.
//
// THE ORDER OF THE RULES IS THE WHOLE DESIGN. Everything that can make a measurement meaningless
// is checked BEFORE anything that could report a pass, so there is no path from "we could not
// tell" to "clean". The last rule is the only one that may say clean, and it carries its own
// preconditions rather than being the fallthrough.
func (c sqlClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	slot := ctx.Slot
	v := func(state triage.TriageState, reason string) triage.ClassVerdict {
		return triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: slot.Key, State: state, Reason: reason}
	}

	// 1. The two rules that are not this class's to argue with.
	if slot.Constraints.IsCredential {
		return []triage.ClassVerdict{v(triage.StateNotProbed,
			"is_credential: injecting into an Authorization header or a session cookie produces a 401 that is a perfect differential against the baseline and looks exactly like a finding, so no class probes one")}
	}
	if slot.Kind == triage.KindFragment || !slot.ServerReachable {
		return []triage.ClassVerdict{v(triage.StateNotApplicable,
			"fragment: RFC 3986 section 3.5 makes the fragment a client-side reference that is never transmitted, so no SQL statement on the server can ever see this slot")}
	}
	if slot.Wrapper == triage.WrapSigned || slot.Wrapper == triage.WrapJWT {
		return []triage.ClassVerdict{v(triage.StateCannotDetermine,
			"signed_wrapper: the observed value carries a signature, so a perturbed value is rejected by the signature check before any SQL statement is built, and a silent result would say nothing about the query")}
	}
	if r := c.Reaches(slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return []triage.ClassVerdict{v(triage.StateNotApplicable, r.Reason)}
	}

	// 2. Everything that stops a measurement from happening at all.
	if ctx.Prelude.Failed() {
		return []triage.ClassVerdict{v(triage.StateCannotDetermine,
			fmt.Sprintf("prelude_failed (%s): the vector needs a token this run could not obtain, so every probe would fail validation identically, which reads as a stable endpoint with no differential, which reads as clean", ctx.Prelude))}
	}
	if !ctx.Route.Resolved() {
		return []triage.ClassVerdict{v(triage.StateCannotDetermine,
			"route_unresolved: the composed URL at its observed value never produced a control, so there is nothing to difference against and no probe was sent")}
	}

	ev := sqlGather(ctx.PlanCtx)
	drifted := false
	if ctx.PostBaseline.Resolved() && ev.haveCtl {
		drifted = sqlCompare(ctx.PostBaseline.Obs(), ev.control) == sqlCmpDifferent
	}
	return sqlDecide(ctx, ev, drifted)
}

// sqlDecide is the verdict proper, split out from Classify for the same reason sqlNextRequests is
// split out from Plan: triage.Replay and triage.OwnedResponses cannot be built outside package
// triage, so a test that had to go through Classify could reach only the first three refusals and
// every rule below them would ship unverified. The split is the difference between a detector
// that has been watched staying silent and one that has not.
func sqlDecide(ctx triage.ClassifyCtx, ev *sqlEvidence, drifted bool) []triage.ClassVerdict {
	slot := ctx.Slot
	v := func(state triage.TriageState, reason string) triage.ClassVerdict {
		return triage.ClassVerdict{Class: triage.ClassSQL, SlotKey: slot.Key, State: state, Reason: reason}
	}
	c := sqlClassifier{}

	if ev.err != "" {
		return []triage.ClassVerdict{v(triage.StateCannotDetermine,
			"runner_bug: this class was handed a response it could not read ("+ev.err+"). That means the vault and the filter disagree about provenance, and a verdict drawn after it would be a verdict about somebody else's probe")}
	}
	if len(ev.all) == 0 {
		return []triage.ClassVerdict{v(triage.StateNotPlanned,
			"no probe was derived for this slot: the ladder produced nothing, which is a named non-test and not a pass. If this slot should have been probed, that is a bug in sqlLadderFor")}
	}

	ordinals := ev.allOrdinals()
	untested := sqlUntested(c, ctx, ev)
	anno := map[string]any{
		"decode_depth":  ev.decodeDepth,
		"probes_sent":   len(ev.all),
		"value_origin":  string(slot.ValueOrigin),
		"stability":     ctx.Baseline.Stable,
		"sqlidetector":  "corroboration_only: a SQLiDetector hit on this parameter never licenses a finding this class did not make itself",
		"stacked_query": "standing gap: a stacked-statement injection whose first statement is unaffected has only a time-based or out-of-band oracle, and both are excluded from the default pass",
	}
	if !ev.echoedAny {
		// CATALOGUE 4.5 rule 2: this class's clean carries its own preconditions and they are
		// printed. We cannot separate "correctly parameterised" from "the quote was stripped
		// before it reached the query" when nothing came back.
		anno["quote_survival_unproven"] = true
	}
	if ev.weakSeen != "" {
		anno["weak_signature"] = ev.weakSeen
	}
	if ev.uniformInert != "" {
		// The collapse happened and it is reported. What it is NOT is a filter: the probe named
		// here carries no metacharacter and produced the same response, so the shared page is the
		// application's answer to any value it does not recognise.
		anno["uniform_response_bucket"] = fmt.Sprintf(
			"three or more of this class's payloads produced one identical non-control response, and %s, "+
				"which carries no metacharacter of any kind, produced it too. That rules out a metacharacter "+
				"filter and reads as a lookup parameter answering every unrecognised value the same way, so "+
				"the ladder ran on rather than stopping", ev.uniformInert)
	}

	// Drift. A slot whose post-baseline disagrees with its pre-baseline moved under us.
	if drifted {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"drift: the post-baseline taken after the last probe disagrees with the control taken before the first, so the endpoint changed under the measurement and every differential on this slot is about the change rather than the payload"),
			ordinals, untested, anno, ev)}
	}

	// 3. The controls, before anything that could report a pass.
	if ev.junkSensitive {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"junk_sensitive: this class's own junk control, which is the marker followed by four digits and carries no metacharacter of any kind, already produced a DBMS parser error. The endpoint errors on any modified value, so the marker-in-error oracle cannot distinguish a break from a rejection on this slot"),
			ordinals, untested, anno, ev)}
	}
	if ev.uniformBlock {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"blocked: three or more of THIS class's distinct payloads came back byte-identical and different from the control, which is a filter answering everything the same way. No other class was consulted and none needs to be"),
			ordinals, untested, anno, ev)}
	}
	if id, fired := ev.anyControlFired(); fired {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			fmt.Sprintf("detector_unverified: this class's negative control %s fired on this slot. A detector that has been shown firing on its own negative control is broken, and every verdict it would produce here is withdrawn rather than downgraded", id)),
			ordinals, untested, anno, ev)}
	}

	// 4. The positives, strongest oracle first.
	if hit, ok := ev.firstD1Break(); ok {
		if ev.controlReproducedTheError(hit) {
			return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
				fmt.Sprintf("metachar_not_delivered: %s produced a parser error and so did its balanced control %s, with the same phrase. A doubled delimiter is consumed as an escape by every engine, so if both error the delimiter never reached SQL and something earlier in the request path is erroring", hit, sqlBreakControls[hit])),
				ordinals, untested, anno, ev)}
		}
		return []triage.ClassVerdict{sqlD1Verdict(v, hit, ev, ordinals, untested, anno)}
	}
	if arm, ok := ev.d2Confirmed(); ok {
		return []triage.ClassVerdict{sqlD2Verdict(v, arm, ev, ctx, ordinals, untested, anno)}
	}

	// 5. The negatives that are statements rather than absences.
	if ev.castProven() {
		c5, _ := ev.first(sqlC5)
		c6, _ := ev.first(sqlC6)
		out := sqlFill(v(triage.StateNotExploitable,
			"casted: SQL-C5 appended .4 and a marker to a digits-only value and the response was identical to the control, while SQL-C6, which replaces every digit with a 9 and carries no metacharacter at all, moved it. "+
				"The application parses an integer and discards the tail, so 1' and 1 are the same request. That is a defence, it is named, and it is not a clean"),
			ordinals, untested, anno, ev)
		out.Ordinals = sqlOrdinalsOf(c5, c6)
		out.Oracle = "cast_detector"
		return []triage.ClassVerdict{out}
	}
	if ev.parameterInert() {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"parameter_inert: SQL-C5 matched the control and so did SQL-C6, the all-nines influence control. The value does not move the response at all, so we have not learned that it is cast, we have learned that nothing we can say through this slot is observable"),
			ordinals, untested, anno, ev)}
	}
	if ev.d3Widened() {
		out := sqlFill(v(triage.StateSuspicious, ""), ordinals, untested, anno, ev)
		out.Oracle = "like_widening"
		out.Grade = triage.GradeLow
		out.Reason = ""
		l1, _ := ev.first(sqlL1)
		l2, _ := ev.first(sqlL2)
		out.Ordinals = sqlOrdinalsOf(l1, l2)
		out.Label = sqlLabel(ev.engine)
		out.Label.Hints["like_context"] = "the bare percent widened the result and the escaped percent did not, so the value reaches a LIKE pattern. That is not a parser break and it is never a finding on its own"
		return []triage.ClassVerdict{out}
	}

	// 6. Clean, and only with its preconditions.
	return sqlNegativeVerdicts(v, ctx, ev, ordinals, untested, anno)
}

// sqlFill attaches the common fields. It exists so that no return path can forget the ordinals,
// which is the field whose absence on a clean is a hard error.
func sqlFill(base triage.ClassVerdict, ordinals []uint64, untested []triage.ProbeSkip, anno map[string]any, ev *sqlEvidence) triage.ClassVerdict {
	base.Ordinals = ordinals
	base.Untested = untested
	base.Annotations = anno
	base.Label = sqlLabel(ev.engine)
	return base
}

func sqlD1Verdict(v func(triage.TriageState, string) triage.ClassVerdict, hit triage.ProbeID, ev *sqlEvidence,
	ordinals []uint64, untested []triage.ProbeSkip, anno map[string]any) triage.ClassVerdict {

	hits := ev.byProbe[hit]
	var fired []sqlSeen
	for _, s := range hits {
		if s.d1.Fired {
			fired = append(fired, s)
		}
	}
	out := sqlFill(v(triage.StateFinding, ""), ordinals, untested, anno, ev)
	out.Oracle = "parser_error"
	out.Ordinals = sqlOrdinalsOf(fired...)

	first := fired[0]
	out.Evidence = triage.TriageEvidence{
		Ordinal:    first.ordinal,
		ObsID:      first.obs.ObsID,
		Matched:    first.d1.Matched,
		Offset:     first.d1.PhraseAt,
		Length:     len(first.d1.Matched),
		Phrase:     first.d1.Phrase,
		Wire:       first.obs.Payload,
		MarkerForm: first.d1.MarkerForm,
	}

	// Grade. High needs the guard asserted AND the effect reproduced with a FRESH marker, which is
	// what a second send of the same spec gives, because the runner mints per request.
	reproduced := len(fired) >= 2 && fired[0].marker != fired[1].marker
	_, hasControl := ev.first(sqlBreakControls[hit])
	switch {
	case first.d1.Marker.Integrity() == triage.MarkerCorrupted:
		out.State = triage.StateSuspicious
		out.Grade = triage.GradeLow
		anno["marker_integrity"] = "corrupted"
	case reproduced && hasControl:
		out.Grade = triage.GradeHigh
	case reproduced || hasControl:
		out.Grade = triage.GradeMedium
	default:
		out.State = triage.StateSuspicious
		out.Grade = triage.GradeMedium
	}
	if first.d1.MarkerForm != "" && first.d1.MarkerForm != "raw" {
		// A re-encoded marker form is still a hit, and it is still capped: the sink transformed
		// our bytes on the way out, so the exact bytes the parser saw are not the ones we sent.
		if out.Grade == triage.GradeHigh {
			out.Grade = triage.GradeMedium
		}
	}
	if !first.obs.Payload.Survived.Proven() {
		// We do not know the payload reached the wire intact, so we do not know what produced the
		// error. That caps the claim rather than voiding it, because the marker is still ours.
		if out.Grade == triage.GradeHigh {
			out.Grade = triage.GradeMedium
		}
		anno["wire_survival"] = string(first.obs.Payload.Survived)
	}
	if ev.weakSeen != "" && out.State == triage.StateSuspicious && out.Grade == triage.GradeMedium {
		// The weak catalogue may raise an existing hit and may never make one.
		out.State = triage.StateFinding
	}
	out.Label = sqlLabel(ev.engine)
	out.Label.Hints["probe"] = string(hit)
	out.Label.Hints["technique"] = "error_based"
	return out
}

func sqlD2Verdict(v func(triage.TriageState, string) triage.ClassVerdict, arm triage.ProbeID, ev *sqlEvidence,
	ctx triage.ClassifyCtx, ordinals []uint64, untested []triage.ProbeSkip, anno map[string]any) triage.ClassVerdict {

	out := sqlFill(v(triage.StateFinding, ""), ordinals, untested, anno, ev)
	out.Oracle = "boolean_differential"
	true1, _ := ev.first(arm)
	out.Ordinals = sqlOrdinalsOf(true1)
	out.Evidence = triage.TriageEvidence{
		Ordinal: true1.ordinal,
		ObsID:   true1.obs.ObsID,
		Phrase:  "true arm matched the control, false arm did not, invalid-syntax control did not look true, true arm reproduced",
		Wire:    true1.obs.Payload,
	}
	switch {
	case ctx.Baseline.Degraded:
		out.State = triage.StateSuspicious
		out.Grade = triage.GradeLow
	case ctx.Baseline.Stable:
		out.Grade = triage.GradeHigh
	default:
		out.State = triage.StateSuspicious
		out.Grade = triage.GradeMedium
	}
	if arm == sqlA1w {
		anno["whitespace_form"] = "comment"
	}
	out.Label = sqlLabel(ev.engine)
	out.Label.Hints["probe"] = string(arm)
	out.Label.Hints["technique"] = "boolean_blind"
	return out
}

// sqlNegativeVerdicts is the only path that may produce clean, and it produces MORE THAN ONE row
// whenever the arms did not all get to run.
//
// CATALOGUE 4.5 rule 1: there is no path from any unknown to clean, at any layer. So a slot where
// the error oracle ran and stayed silent while the boolean arm could not run at all emits TWO
// rows, and neither stands for the other: the aggregate then reads "partially tested" and names
// the half that was not. Folding them into one clean is exactly the bug this layer exists to stop.
func sqlNegativeVerdicts(v func(triage.TriageState, string) triage.ClassVerdict, ctx triage.ClassifyCtx,
	ev *sqlEvidence, ordinals []uint64, untested []triage.ProbeSkip, anno map[string]any) []triage.ClassVerdict {

	var out []triage.ClassVerdict

	// The blanket disqualifiers first: if one of these holds, nothing about this slot is clean.
	switch {
	case ctx.Baseline.Degraded:
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"too_volatile (degraded): the comparison was degraded, so a silent differential says nothing and the strongest verdict available is a suspicion"),
			ordinals, untested, anno, ev)}
	case ctx.Slot.ValueOrigin == triage.ValueCanary:
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"canary_resource: the observed value was fabricated, so these probes were sent at a resource that does not exist. A scan of a 404 that comes back with nothing found is not a clean scan of the endpoint"),
			ordinals, untested, anno, ev)}
	case ctx.Slot.ValueOrigin == triage.ValueSynthesized:
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"canary_resource (synthesized): the value was invented to have something to perturb, so the statement the application built is not the statement a real request builds"),
			ordinals, untested, anno, ev)}

	// Ruling R6c: decode_depth may DOWNGRADE and may never SUPPRESS. The payloads were all sent,
	// and the downgrade covers the whole slot rather than one arm, because a slot that does not
	// percent-decode does not percent-decode for the boolean arm either. decode_depth >= 1 only
	// removes this downgrade; it is never a way to reach a clean faster.
	case sqlPercentRelevant(ctx.Slot.Kind) && ev.decodeDepth == 0:
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"decode_depth_0: this class's own decode probe came back as literal percent text, so the slot does not percent-decode. Every payload was sent anyway, and their silence is undecided rather than clean, because a percent-encoded quote that was never decoded never reached the parser"),
			ordinals, untested, anno, ev)}
	case sqlPercentRelevant(ctx.Slot.Kind) && ev.decodeDepth < 0:
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine, sqlDecodeUnknownReason(ev)),
			ordinals, untested, anno, ev)}
	}

	// Transport. A probe that never left is not a probe that came back quiet.
	var delivered int
	for _, s := range ev.all {
		if s.obs.Delivered() {
			delivered++
		}
	}
	if delivered == 0 {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"blocked (transport): not one probe on this slot reached the application, so nothing was measured. A transport refusal is could-not-send, never a quiet response"),
			ordinals, untested, anno, ev)}
	}

	// Truncation. Every payload but SQL-MP leads with the observed value, so a field limit shorter
	// than the end of the marker blinds the primary oracle completely.
	if sqlNeedsMarkerFirst(ctx.Slot) && ev.count(sqlMP) == 0 {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			fmt.Sprintf("truncated: this slot truncates at %d bytes, every payload in this class leads with the %d-byte observed value, and the marker-first probe was not sent, so the primary oracle could not see its own marker on any probe",
				ctx.Slot.Constraints.FieldLimit, len(ctx.Slot.Value))),
			ordinals, untested, anno, ev)}
	}

	// Wire survival. If nothing proves the payload reached the wire as asked, the silence could be
	// Go's own cookie sanitiser eating the quote rather than the application defending.
	unproven := 0
	for _, s := range ev.all {
		if !s.obs.Payload.Survived.Proven() {
			unproven++
		}
	}
	if unproven == len(ev.all) {
		return []triage.ClassVerdict{sqlFill(v(triage.StateCannotDetermine,
			"metachar_stripped (wire survival unproven): no probe on this slot recorded its payload surviving to the wire, and net/http's cookie writer silently drops the semicolon, the double quote and the backslash, which are this class's probe characters. A silence with no wire record cannot be told from a mangled send"),
			ordinals, untested, anno, ev)}
	}

	// The error oracle's own clean.
	errorArmOrdinals := ev.arm(sqlU1, sqlQ1, sqlQ2, sqlD1P, sqlD2P, sqlB1, sqlB2, sqlK1, sqlK2, sqlP1, sqlP2, sqlP3, sqlP4, sqlC1, sqlC2, sqlC3, sqlC4, sqlC5, sqlNC1, sqlMP)
	brokeProbe, brokeStatus, brokeWitness, brokeUnread := ev.unreadableBreak()
	switch {
	case len(errorArmOrdinals) == 0:
		out = append(out, sqlFill(v(triage.StateNotRun,
			"not_run: no break probe was sent on this slot, so the marker-in-parser-error oracle never ran here"),
			ordinals, untested, anno, ev))
	case brokeUnread:
		// The break broke something and the oracle could not read what. That is an UNREAD
		// MEASUREMENT, and reporting it as an absence of the vulnerability is the failure this
		// whole layer exists to stop.
		row := sqlFill(v(triage.StateCannotDetermine, fmt.Sprintf(
			"break_error_unreadable: %s carries this class's own metacharacter and the endpoint answered HTTP %d, while %s did not. "+
				"Something in that payload broke the server, and no phrase in the strong catalogue was readable in the reply, so the "+
				"marker-in-parser-error oracle has nothing to read on this slot. That is an unread measurement, not an absence of the "+
				"vulnerability, and the next move is to look at the body of that response by hand",
			brokeProbe, brokeStatus, brokeWitness)), ordinals, untested, anno, ev)
		row.Oracle = "parser_error"
		row.Ordinals = errorArmOrdinals
		out = append(out, row)
	default:
		cl := sqlFill(v(triage.StateClean, ""), ordinals, untested, anno, ev)
		cl.Oracle = "parser_error"
		cl.Ordinals = errorArmOrdinals
		cl.Reason = ""
		out = append(out, cl)
	}

	// The boolean arm's own row. It is separate because it is the ONLY detector that can see an
	// endpoint which suppresses errors, so its absence is a real gap and must not hide inside a
	// clean produced by the error oracle.
	boolOrdinals := ev.arm(sqlA1, sqlA2, sqlA3, sqlA4, sqlA5, sqlA1w, sqlA2w)
	switch {
	case len(boolOrdinals) == 0:
		out = append(out, sqlFill(v(triage.StateNotRun,
			"not_run (early_exit): the boolean arm was not sent on this slot. It is the only detector in this class that can see an endpoint which suppresses errors, so its absence is a gap and not a pass"),
			ordinals, untested, anno, ev))
	case !ctx.Baseline.Stable:
		reason := ctx.Baseline.GateReason
		if reason == "" {
			reason = "too_volatile"
		}
		out = append(out, sqlFill(v(triage.StateCannotDetermine,
			fmt.Sprintf("%s: the stability gate did not pass on this endpoint, so the boolean differential cannot be read. The error oracle still ran because it needs no baseline, and these two facts are reported separately because neither stands for the other", reason)),
			ordinals, untested, anno, ev))
	default:
		cl := sqlFill(v(triage.StateClean, ""), ordinals, untested, anno, ev)
		cl.Oracle = "boolean_differential"
		cl.Ordinals = boolOrdinals
		cl.Reason = ""
		out = append(out, cl)
	}

	// The LIKE arm's own row, and ONLY when it has something to say. It gets no clean and no
	// not_run row, because it is rank 5 and never a finding on its own, so its absence is not a
	// coverage gap the way a missing boolean arm is. What it does get is a row when it RAN and
	// could not be read, so that fact survives instead of either vanishing or, as it used to,
	// withdrawing every other verdict on the slot.
	if ev.likeArmUnreadable() {
		l1, _ := ev.first(sqlL1)
		l2, _ := ev.first(sqlL2)
		row := sqlFill(v(triage.StateCannotDetermine,
			"like_arm_unreadable: the bare percent moved the response and the escaped percent moved it too, so nothing separates a LIKE pattern widening from a slot where every value that is not the one on record returns the same page. The LIKE arm is undecided here; it is not a broken detector, and it withdraws nothing from the arms that could be read"),
			ordinals, untested, anno, ev)
		row.Oracle = "like_widening"
		row.Ordinals = sqlOrdinalsOf(l1, l2)
		out = append(out, row)
	}

	// The whitespace caveat, on a cookie that could only carry the comment form against an engine
	// we never identified.
	if ev.count(sqlA1w) > 0 && ev.engine == "" {
		for i := range out {
			if out[i].Oracle == "boolean_differential" && out[i].State == triage.StateClean {
				out[i].State = triage.StateCannotDetermine
				out[i].Grade = triage.GradeUnrated
				out[i].Reason = "whitespace_form_unproven: the boolean arm could only be delivered in its /**/ form, which is VERIFIED on PostgreSQL 18 and MariaDB 11.8.9 and UNVERIFIED on Oracle, MSSQL and SQLite, and no engine was identified on this slot"
			}
		}
	}

	if ctx.Budget.Exhausted() {
		for i := range out {
			if out[i].State == triage.StateClean {
				out[i].State = triage.StateCannotDetermine
				out[i].Grade = triage.GradeUnrated
				out[i].Reason = "probe_budget_exhausted: the ladder was cut short by the budget, so the silence covers only the probes that were sent and the rest are listed as untested"
			}
		}
	}
	return out
}

// sqlDecodeUnknownReason separates the three ways decode_depth ends up unknown, because they are
// three different facts and the operator's next move differs for each.
//
// The reason string used to be one sentence for all three: "this class's own decode probe
// returned neither the decoded marker nor the literal percent text". On a slot where SQL-DEC was
// never sent that sentence describes an outcome of a measurement that did not happen, which is
// the same failure this whole layer exists to stop, one level up: a report of a result where
// there is no result. And on an endpoint that echoes NOTHING it frames a property of the oracle
// as a property of the slot. Measured against the oracle, the static index at / and /sqli?id=hello
// both reflect nothing at all, so SQL-DEC could not answer on either, and both read as though the
// decode question had been asked and come back ambiguous.
func sqlDecodeUnknownReason(ev *sqlEvidence) string {
	switch {
	case ev.count(sqlDEC) == 0:
		return "decode_depth_not_measured: SQL-DEC, this class's own decode probe, was never sent on this slot, so there is no decode result at all. That is a gap in what ran and not an ambiguous reading of what ran"
	case !ev.echoedAny:
		return "decode_depth_unknown (no_reflection): this endpoint echoed nothing back on any probe in this class, so SQL-DEC could not answer whether the slot percent-decodes and neither could anything else. The marker-in-parser-error oracle needs the same echo, so it was structurally unavailable here rather than silent: this slot needs a differential tool, not a louder payload"
	default:
		return "decode_depth_unknown: this class's own decode probe returned neither the decoded marker nor the literal percent text, so nobody knows whether this slot decodes. Unknown is not zero and neither of them is clean"
	}
}

func sqlPercentRelevant(k triage.SlotKind) bool {
	switch k {
	case triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie:
		return true
	}
	return false
}

// arm returns the ordinals of the probes in one detector's arm that actually ran.
func (ev *sqlEvidence) arm(ids ...triage.ProbeID) []uint64 {
	var out []uint64
	for _, id := range ids {
		for _, s := range ev.byProbe[id] {
			out = append(out, s.ordinal)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

// sqlConfirmer is one first-hit to confirmation mapping. Every confirmation in this class is a
// DIFFERENT payload from this class, never a re-read of another probe's response and never
// another class's probe.
type sqlConfirmer struct {
	Hit     triage.ProbeID
	Confirm []triage.ProbeID
	Proves  string
}

// Confirmers is CATALOGUE 1.3 for this class.
func (sqlClassifier) Confirmers() []sqlConfirmer {
	return []sqlConfirmer{
		{sqlU1, []triage.ProbeID{sqlQ2, sqlU1}, "SQL-Q2 is SQL-U1 with the delimiter doubled and nothing else changed, so silence from it proves the quote was consumed as syntax and the same unterminated-literal error from it proves the quote never reached the parser. The repeat of SQL-U1 carries a FRESH marker, which is what separates grade high from a suspicion nobody reproduced"},
		{sqlQ1, []triage.ProbeID{sqlQ2, sqlQ1}, "silence or an unknown-column error naming the marker proves the doubled quote was consumed as an escape, which is the definition of a string literal context. The same parse error from both means the quote never reached SQL. The repeat of SQL-Q1 carries a FRESH marker, which is what grade high requires"},
		{sqlD1P, []triage.ProbeID{sqlD2P}, "silence means the double quote is a string delimiter (MySQL without ANSI_QUOTES, or SQLite); an unknown-column error naming the marker means it is an identifier delimiter (PostgreSQL, Oracle, MSSQL, SQLite, or MySQL in ANSI mode). Either way the context is identified for free"},
		{sqlB1, []triage.ProbeID{sqlB2}, "as the double quote, for the MySQL and SQLite backtick identifier"},
		{sqlK1, []triage.ProbeID{sqlK2}, "as the double quote, for the MSSQL bracket identifier. UNVERIFIED: no MSSQL was available"},
		{sqlP1, []triage.ProbeID{sqlP2}, "the quoted parenthesis control must stay silent; if it errors identically the paren never reached the parser"},
		{sqlP3, []triage.ProbeID{sqlP4}, "as SQL-P1, for the unquoted paren"},
		{sqlC1, []triage.ProbeID{sqlC4}, "an ordinal-out-of-range message confirms the slot is an ORDER BY or GROUP BY POSITION and, on SQLite, hands over the SELECT-list arity for free"},
		{sqlC2, []triage.ProbeID{sqlC4}, "as SQL-C1"},
		{sqlC3, []triage.ProbeID{sqlC4}, "as SQL-C1"},
		{sqlA1, []triage.ProbeID{sqlA3, sqlA1}, "the A1, A2, A1 alternation must reproduce, which kills a page that simply differs on every second request, and SQL-A3 must not look like the true arm, because two integers separated by a space are not an expression"},
		{sqlA4, []triage.ProbeID{sqlA3, sqlA4}, "as SQL-A1, for the numeric arm that carries no metacharacter"},
		{sqlL1, []triage.ProbeID{sqlL2}, "the escaped percent must not widen. Without this half, every search endpoint that already does prefix matching reports as a LIKE injection"},
		{sqlC5, []triage.ProbeID{sqlC6}, "the all-nines value must move the response. If it does not, the parameter has no influence at all and the verdict is parameter_inert rather than casted, and those are two different facts"},
	}
}

// sqlEvidencer describes one oracle: what it fires on, what rank it is, and the ceiling grade it
// can reach. It is here so the grading rule is data a reader can check against CATALOGUE 4.2
// rather than a switch statement buried in Classify.
type sqlEvidencer struct {
	Oracle   string
	Rank     int
	Ceiling  triage.TriageGrade
	Records  string
	NeedsBTL bool // does this oracle need a baseline at all
}

func (sqlClassifier) Evidencers() []sqlEvidencer {
	return []sqlEvidencer{
		{
			Oracle: "parser_error", Rank: 2, Ceiling: triage.GradeHigh, NeedsBTL: false,
			Records: "the engine phrase name, the matched substring, the marker and its transform form, the byte offset, the probe ordinal and the wire bytes that went out. It needs no baseline, because the baseline cannot contain a marker minted for this probe in this run, which is what makes it the only oracle that survives an application whose every response already carries a PSQLException",
		},
		{
			Oracle: "boolean_differential", Rank: 3, Ceiling: triage.GradeHigh, NeedsBTL: true,
			Records: "the true arm, the false arm, the invalid-syntax control and the repeat of the true arm, each with its comparison against the route control. It is the only detector here that can see an endpoint which suppresses every error, and it is the first thing a volatile endpoint takes away",
		},
		{
			Oracle: "cast_detector", Rank: 4, Ceiling: triage.GradeUnrated, NeedsBTL: true,
			Records: "SQL-C5 at the control and SQL-C6 away from it. It produces a NEGATIVE with a reason, which is the rarest thing in this catalogue: not_exploitable (casted) is a statement the operator can act on, unlike an absence of signal",
		},
		{
			Oracle: "like_widening", Rank: 5, Ceiling: triage.GradeLow, NeedsBTL: true,
			Records: "the bare percent widening and the escaped percent not widening. Never a finding on its own: a percent that widens proves the value reaches a pattern, not that it reaches the parser",
		},
		{
			Oracle: "second_order_flow", Rank: 0, Ceiling: triage.GradeUnrated, NeedsBTL: false,
			Records: "the write slot, the read vectors and the marker. Informational only and never a finding, because detecting second-order injection would mean storing a payload that raises a 500 for every later reader, including other people using the application",
		},
	}
}

// sqlOracleCase is one route in the oracle container this class must be verified against, and
// whether the class must FIRE on it or STAY SILENT.
//
// THE SILENT ROUTES ARE THE ONES THAT ACTUALLY TEST THE DETECTOR. A detector that fires on every
// route scores one hundred per cent, and so does one that always returns true.
type sqlOracleCase struct {
	Route  string
	Expect string // "positive" or "negative"
	Probes []triage.ProbeID
	Why    string
	Exists bool // is the route already in docker/oracle
}

const (
	sqlExpectPositive = "positive"
	sqlExpectNegative = "negative"
)

func (sqlClassifier) OracleCases() []sqlOracleCase {
	return []sqlOracleCase{
		{"/sqli", sqlExpectPositive, []triage.ProbeID{sqlU1, sqlQ2}, "the existing route: error, boolean and time behaviours on a single-quoted string context. MEASURED: it answers HTTP 500 with the marker inside the echoed statement to SQL-U1 and HTTP 200 with nothing to SQL-Q1, because the repaired break leaves the statement lexically complete. SQL-U1 is the probe that makes this positive control positive", true},
		{"/sqli/identquote", sqlExpectPositive, []triage.ProbeID{sqlD1P, sqlD2P}, "a double-quoted IDENTIFIER context, so SQL-D2 answers with an unknown-column error naming the marker rather than with silence, which is how the context classifier is exercised", false},
		{"/sqli/mysql", sqlExpectPositive, []triage.ProbeID{sqlB1, sqlB2}, "ORDER BY `<input>` on MySQL or SQLite. No quote payload from any tool reaches this sink. NOW LIVE and MEASURED: it answers HTTP 500 to SQL-B1 with an entity-escaped MySQL 1064 carrying the marker, which this class could not read and reported CLEAN on. WHAT THE ROUTE STILL OWES: it errors on the mere PRESENCE of a backtick, so SQL-B2, the doubled-backtick control, gets the IDENTICAL 1064 and the honest reading of that pair is metachar_not_delivered. A real MySQL consumes `` as an escape and answers Unknown column 'name`<marker>' in 'ORDER BY', which is the identifier-context signal this class already whitelists, and only then does the pair resolve to a finding", true},
		{"/sqli/mssql", sqlExpectPositive, []triage.ProbeID{sqlK1, sqlK2}, "ORDER BY [<input>] with brackets only, the one context nothing in a quote ladder reaches. NOW LIVE and MEASURED: it answers HTTP 500 to SQL-K1 with an entity-escaped Msg 102 carrying the marker, which this class could not read and reported CLEAN on. WHAT THE ROUTE STILL OWES: it errors on the mere PRESENCE of a right bracket, so SQL-K2, the doubled-bracket control, gets the IDENTICAL Msg 102 and the honest reading of that pair is metachar_not_delivered. A real SQL Server consumes ]] as an escape and answers Invalid column name 'name]<marker>', which is the identifier-context signal this class already whitelists, and only then does the pair resolve to a finding", true},
		{"/sqli/orderby", sqlExpectPositive, []triage.ProbeID{sqlC1, sqlC3, sqlC4}, "an ordinal context with no quote anywhere, so the comma, the bare token and the position probe are the only three things that can reach it", false},
		{"/sqli/limit", sqlExpectPositive, []triage.ProbeID{sqlC2, sqlC3}, "LIMIT <input>, the one context where no quote, no comma and no identifier is syntactically available", false},
		{"/sqli/paren", sqlExpectPositive, []triage.ProbeID{sqlP1, sqlP2, sqlP3, sqlP4}, "ruling R2: WHERE (LOWER(name)='<in>') and IN (<in>). Without the closing paren the boolean arm's true form is an arity error and the slot reads clean", false},
		{"/sqli/blind", sqlExpectPositive, []triage.ProbeID{sqlA1, sqlA2, sqlA3}, "errors suppressed, 200 on everything, so only the boolean arm can see it", false},
		{"/sqli/status200", sqlExpectPositive, []triage.ProbeID{sqlA4, sqlA5, sqlA3}, "the numeric arm against an endpoint that never changes its status, proving the detector does not read status", false},
		{"/sqli/like", sqlExpectPositive, []triage.ProbeID{sqlL1, sqlL2}, "a LIKE pattern built from the value, where the escaped form must not widen", false},

		{"/clean/dberror", sqlExpectNegative, []triage.ProbeID{sqlU1, sqlQ1, sqlD1P, sqlC1}, "EVERY response including the baseline carries a PSQLException. This is the whole reason the marker-in-parser-error oracle exists, and every statistical detector ever written fails here on the first payload", false},
		{"/clean/echoparser", sqlExpectNegative, []triage.ProbeID{sqlU1, sqlQ1}, "echoes the payload into a page that also says SQL syntax MORE THAN 120 bytes away. This is the test for the window, and a detector that searches the whole body fails it", false},
		{"/clean/intcast", sqlExpectNegative, []triage.ProbeID{sqlC5, sqlC6}, "parses an int and discards the tail, so the verdict must be not_exploitable (casted) and NOT clean. The influence control must move the response", false},
		{"/clean/validate", sqlExpectNegative, []triage.ProbeID{sqlU1, sqlQ1, sqlQ2, sqlNC1}, "rejects any value containing a quote with a 400. Both the break and the control error identically, so the verdict must be metachar_not_delivered rather than a finding", false},
		{"/clean/junk", sqlExpectNegative, []triage.ProbeID{sqlNC1}, "errors on any modified value, including a purely alphanumeric one. The junk control must fire and the class must stop with junk_sensitive after one request", false},
		{"/clean/inert", sqlExpectNegative, []triage.ProbeID{sqlC5, sqlC6}, "discards the parameter entirely, so SQL-C5 and SQL-C6 both match the control and the verdict must be parameter_inert, which is NOT casted and NOT clean", false},
		{"/clean/waf", sqlExpectNegative, []triage.ProbeID{sqlQ1, sqlD1P, sqlB1}, "an identical block page for every payload. Three of this class's own distinct payloads reaching it must give cannot_determine (blocked), reached without consulting any other class", true},
		{"/clean/noisy", sqlExpectNegative, []triage.ProbeID{sqlA1, sqlA2, sqlA3}, "a fresh request id and nonce on every call. Without this route the boolean differential is untested, and a detector comparing raw bytes reports every endpoint as injectable", true},
		{"/clean/empty204", sqlExpectNegative, []triage.ProbeID{sqlA1, sqlA2}, "204 with no body on baseline and on probes. The comparison must be unusable, not same: identical empty bodies are not evidence of anything", true},
		{"/clean/echo", sqlExpectNegative, []triage.ProbeID{sqlQ1, sqlC1, sqlL1}, "reflects the input with no database behind it. Reflection is not injection", true},
		{"/clean/drift", sqlExpectNegative, []triage.ProbeID{sqlA1, sqlA2}, "serves version A then version B, so the post-baseline disagrees with the control and every differential in the window must become cannot_determine (drift)", true},
	}
}

// Settle is the deferred out-of-band check, and this class has none, so it is a no-op that says so.
//
// It is here rather than absent because the reason is worth writing down: the only SQL mechanisms
// that need a deferred check are the out-of-band exfiltration ones (a DNS lookup built from a
// subquery) and second-order injection. The first is exploitation rather than triage and is not in
// this class's payload set at all. The second is refused on safety grounds: the value that would
// have to be stored raises a 500 for every later reader of that row, including other people using
// the application, and the flow probe writes an inert alphanumeric token instead. So there is
// nothing to come back for, and a Settle that returned a verdict would be inventing one.
func (sqlClassifier) Settle(triage.ClassifyCtx) []triage.ClassVerdict { return nil }
