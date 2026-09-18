package triageclasses

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// ELI: EXPRESSION LANGUAGE INJECTION. CATALOGUE 1.2, iso-eval class 2 of 3.
//
// A SEPARATE CLASS FROM SSTI, AND THE REASON IS NOT TIDINESS. The four dialects here (OGNL, SpEL,
// MVEL, JSP/Jakarta EL) are reached through sinks that are not template files: a Struts tag
// attribute, a SpelExpressionParser call on a raw string, a Hibernate Validator constraint
// message, a JSF value binding, a Drools or Camunda rule. No template file exists on any of those
// paths, so no template engine fingerprint matches and no template error signature appears. An
// SSTI-only battery walks past every one of them and records clean.
//
// =================================================================================================
// THE STRONGEST ORACLE IN THIS CLASS, AND WHY IT IS STRONGER THAN "SOMETHING EVALUATED"
// =================================================================================================
//
// 1900000000 + 1900000000 is 3800000000 in Python, in JavaScript, in Ruby, in PHP and in a JVM
// long. It is -494967296 ONLY where the arithmetic is a Java 32-bit signed int:
//
//	3800000000 - 4294967296 = -494967296
//
// So the answer does not merely prove that an evaluator ran. It proves WHICH TYPE SYSTEM ran, in
// one request, with no second probe and no fingerprint table. A Jinja2 or Twig evaluator handed
// the same expression answers 3800000000, and that is a DIFFERENT state in this file
// (el_overflow_unwrapped, capped at suspicious), never a finding, because "a template engine did
// arbitrary-precision arithmetic" is SSTI's finding to make from SSTI's own probes, not this
// class's to claim.
//
// Two further properties fall out of the same choice and both were deliberate:
//
//   - The payload contains no `*` in the arithmetic itself. The multiplication operator is the
//     single most signatured byte in template injection, so a WAF rule on `7*7` does not see this.
//   - The operands differ from SSTImap's own Java plugins, which use 2000000000+2000000000 and
//     expect -294967296 (plugins/java/ognl.py, plugins/java/spring_el.py,
//     plugins/generic/java_el_generic.py). The operator runs SSTImap against the same slot AFTER
//     this triage pass, and the two runs have to be distinguishable in the target's own logs.
//
// =================================================================================================
// THE ISOLATION LAW, AS IT APPLIES HERE
// =================================================================================================
//
// SSTI and ELI rhyme syntactically: both send `${...}`. They share not one byte of payload.
// SSTI never sends valueOf, T(, @java.lang or a negative expected answer; ELI never sends a bare
// `a*b`. The registry check proves it at build time rather than leaving it to this comment.
//
// Two places where the law cost this file something real, both recorded rather than optimised
// away:
//
//   - The empty-expression negative control. The obvious bytes are `${}`, and SSTI-NC3 owns those
//     bytes. So this class controls on `%{}`, `@{}` and `${{}}` instead, which are ELI-exclusive
//     delimiters testing exactly the same property (a valid delimiter with nothing inside must not
//     fire the computation or the string rule). Three requests where two would have done. The
//     alternative was shipping a payload byte-equal to another class's, which is the one thing
//     this layer refuses.
//   - Ruling R1. An earlier design had ELI read SSTI's signature catalogue so it could say
//     "a FreeMarker error, not mine". That coupling is deleted. This file contains ELI signatures
//     and nothing else, and where the response is plainly perturbed with none of them present the
//     answer is cannot_determine (unattributed_error), reached from this class's own ELE and ELS1
//     probes. It is never foreign_error, because that state required knowing another class exists.
//
// =================================================================================================
// WHAT THIS CLASS HONESTLY CANNOT DO, DECLARED AT BIRTH
// =================================================================================================
//
//   - The OGNL-in-parameter-NAME sink, which is the highest-value OGNL sink in Struts history
//     (S2-016, S2-032). The slot model replaces VALUES and the name_slot encoder does not exist
//     (CATALOGUE blocker B3). Every query and form verdict carries untested: ["param_name_ognl"]
//     so the gap is visible in the report, and the label routes the sink to nuclei-dast's Struts
//     template set in the meantime.
//   - A fully blind EL sink: no reflection, exceptions swallowed. This class has NO out-of-band
//     payload and no timing oracle, so the honest answer is cannot_determine (no_reflection).
//     Not clean. CATALOGUE 7.1 names it as an admission and this file makes it one.
//   - Non-JVM EL-alikes (Angular $parse is the CSTI class; JEXL and friends are out of scope).
//     Recorded as untested: ["non_jvm_el"] on every verdict rather than silently absent.
type eliClassifier struct{}

func init() { triage.RegisterClassifier(eliClassifier{}) }

func (eliClassifier) ID() triage.ClassID { return triage.ClassELI }

// -------------------------------------------------------------------------------------------
// 1. THE CONSTANTS, AND THE GUARDS THEY HAVE TO SATISFY
// -------------------------------------------------------------------------------------------

const (
	// eliOperand and eliWrapped are the int32 overflow pair. See the header for the derivation.
	eliOperand = "1900000000"
	eliWrapped = "-494967296"
	// eliUnwrapped is the answer a non-JVM-int evaluator gives. It is a SEPARATE, WEAKER state and
	// never a finding: see eliMatchUnwrapped.
	eliUnwrapped = "3800000000"
	// eliGrouped is the locale-grouped rendering. Standard EL output goes through
	// Integer.toString and never groups, so this is a SECONDARY form capped at suspicious; it
	// exists because a value routed through a formatter would otherwise be a silent false
	// negative, and a false negative is the expensive error.
	eliGrouped = "-494,967,296"

	// The confirmation draw. Different operands, different answer, same delimiter and same body,
	// so a confirmation that reproduces cannot be a cached copy of the first response.
	eliOperand2 = "1800000000"
	eliWrapped2 = "-694967296"

	// The string oracle. 'qmkvbnkw'.replace('k','7') is qm7vbn7w. The guard that matters:
	// qm7vbn7w is NOT a substring of the expression that computes it, so an echo of the payload
	// can never satisfy the rule. eliStrPartial is one of the two k replaced, which is
	// replaceFirst semantics: real evidence of method invocation, but a different mechanism, so
	// it is suspicious and not a finding.
	eliStrToken   = "qmkvbnkw"
	eliStrAnswer  = "qm7vbn7w"
	eliStrPartial = "qm7vbnkw"
	eliStrUpper   = "QMKVBNKW"
)

// The five dialect bodies. Three of them exist because the syntax for reaching Integer.valueOf
// differs per dialect and a single body silently misses two of the four.
const (
	// eliBodyGen reaches JUEL, Jakarta EL, JSP EL, MVEL, and SpEL as well. No class name, no
	// reflection, no T(), no @. (1) is an autoboxed Integer literal and valueOf is its static
	// method reached through the instance, which every JVM EL implementation resolves. It is the
	// form most likely to survive a WAF and a method allow-list, and it is the ONLY body that
	// works under a SpEL SimpleEvaluationContext, which blocks T() and is what most hardened
	// Spring applications run. Shipping only eliBodySpel would miss all of them.
	eliBodyGen = `1*((1).valueOf('` + eliOperand + `')+` + eliOperand + `)`
	// eliBodySpel: T(...) is SpEL's type operator and exists in no other dialect, so a hit here
	// identifies the dialect as well as detecting it.
	eliBodySpel = `T(java.lang.Integer).valueOf('` + eliOperand + `')+` + eliOperand
	// eliBodyOgnl: @class@member is OGNL's static-access syntax and exists in no other dialect.
	// The leading 1* forces integer arithmetic rather than string concatenation, which is what
	// SSTImap's OGNL plugin does for the same reason.
	eliBodyOgnl = `1*(@java.lang.Integer@valueOf('` + eliOperand + `')+` + eliOperand + `)`
	// eliBodyStr is the independent oracle. It proves method invocation with no arithmetic and no
	// class name, so it survives a method allow-list on valueOf and a WAF rule on java.lang, both
	// of which kill the overflow oracle outright. At 27 bytes it is also the only body that fits a
	// short field. Shape borrowed from the Burp Suite EL detection vector
	// gk6q${"zkz".toString().replace("k", "x")}doap2.
	eliBodyStr = `'` + eliStrToken + `'.replace('k','7')`
	// eliBodyErr is the error oracle and the ruling R1 disambiguator. Every dialect answers a
	// method-not-found with an exception that names the dialect.
	eliBodyErr = `(1).zqjNoSuchMethod()`

	// The confirmation and identification bodies.
	eliBodyGenConfirm  = `1*((1).valueOf('` + eliOperand2 + `')+` + eliOperand2 + `)`
	eliBodySpelConfirm = `T(java.lang.Integer).valueOf('` + eliOperand2 + `')+` + eliOperand2
	eliBodyOgnlConfirm = `1*(@java.lang.Integer@valueOf('` + eliOperand2 + `')+` + eliOperand2 + `)`
	eliBodyStrUpper    = `'` + eliStrToken + `'.toUpperCase()`
	// eliBodyVersion reads java.version. It is a READ with no side effect: it writes nothing,
	// starts no process and touches no file. It is sent once per vector and only after a confirmed
	// finding, because the JVM major version decides which gadget chains a later exploitation step
	// can use and that is worth exactly one request once.
	eliBodyVersion = `(1).getClass().forName('java.lang.System').getProperty('java.version')`
)

// Probe ids. They are constants rather than string literals at the use site so that Plan cannot
// name a probe Probes() does not declare; PlannedProbesAreDeclared would catch that at run time,
// and this catches it at compile time.
const (
	eliProbeCensus = triage.ProbeID("ELI-E0")
	eliProbeDecode = triage.ProbeID("ELI-DEC")

	eliProbeEL1  = triage.ProbeID("ELI-EL1")  // ${ }   generic body
	eliProbeEL2  = triage.ProbeID("ELI-EL2")  // #{ }   SpEL body
	eliProbeEL3  = triage.ProbeID("ELI-EL3")  // %{ }   OGNL body
	eliProbeEL4  = triage.ProbeID("ELI-EL4")  // *{ }   SpEL body
	eliProbeEL5  = triage.ProbeID("ELI-EL5")  // @{ }   generic body
	eliProbeEL6  = triage.ProbeID("ELI-EL6")  // bare, NO MARKER
	eliProbeEL6m = triage.ProbeID("ELI-EL6m") // bare inside a quoted literal
	eliProbeEL7  = triage.ProbeID("ELI-EL7")  // __${ }__ Thymeleaf preprocessing
	eliProbeEL8  = triage.ProbeID("ELI-EL8")  // ${{ }}

	eliProbeELS1 = triage.ProbeID("ELI-ELS1") // string oracle through ${ }
	eliProbeELS2 = triage.ProbeID("ELI-ELS2") // string oracle through %{ }
	eliProbeELE  = triage.ProbeID("ELI-ELE")  // error oracle

	eliProbeCF1  = triage.ProbeID("ELI-CF1")
	eliProbeCF2  = triage.ProbeID("ELI-CF2")
	eliProbeCF3  = triage.ProbeID("ELI-CF3")
	eliProbeCF4  = triage.ProbeID("ELI-CF4")
	eliProbeCF5  = triage.ProbeID("ELI-CF5")
	eliProbeCF6  = triage.ProbeID("ELI-CF6")
	eliProbeCF6m = triage.ProbeID("ELI-CF6m")
	eliProbeCF7  = triage.ProbeID("ELI-CF7")
	eliProbeCF8  = triage.ProbeID("ELI-CF8")
	eliProbeELS3 = triage.ProbeID("ELI-ELS3") // string-oracle confirmation, a SECOND method

	eliProbeIDSpelDollar = triage.ProbeID("ELI-ID-SPEL-DOLLAR")
	eliProbeIDOgnlDollar = triage.ProbeID("ELI-ID-OGNL-DOLLAR")
	eliProbeIDSpelAt     = triage.ProbeID("ELI-ID-SPEL-AT")
	eliProbeIDOgnlAt     = triage.ProbeID("ELI-ID-OGNL-AT")
	eliProbeIDSpelBare   = triage.ProbeID("ELI-ID-SPEL-BARE")
	eliProbeIDOgnlBare   = triage.ProbeID("ELI-ID-OGNL-BARE")

	eliProbeJVM = triage.ProbeID("ELI-ELJ")

	eliProbeNC1  = triage.ProbeID("ELI-NC1")
	eliProbeNC2  = triage.ProbeID("ELI-NC2")
	eliProbeNC3  = triage.ProbeID("ELI-NC3")
	eliProbeNC4  = triage.ProbeID("ELI-NC4")
	eliProbeNC5a = triage.ProbeID("ELI-NC5a")
	eliProbeNC5b = triage.ProbeID("ELI-NC5b")
	eliProbeNC5c = triage.ProbeID("ELI-NC5c")
)

// The oracle names that go on ClassVerdict.Oracle. One string per rule, so the report can group by
// mechanism and the operator can tell "the arithmetic worked" from "a method resolved".
const (
	eliOracleOverflow  = "el_overflow"
	eliOracleGrouped   = "el_overflow_grouped"
	eliOracleUnwrapped = "el_overflow_unwrapped"
	eliOracleString    = "el_string"
	eliOraclePartial   = "el_string_partial"
	eliOracleError     = "el_error"
)

// eliUntestedAlways is on EVERY verdict this class emits, clean included. Both are real holes and
// both are invisible unless they are written down on every row: a report that names a gap only on
// the rows where something else also happened is a report that hides it on the quiet rows, which
// are the majority.
func eliUntestedAlways() []triage.ProbeSkip {
	return []triage.ProbeSkip{
		{
			ProbeID: "ELI-EL3N",
			Reason: "param_name_ognl: the OGNL value stack takes the parameter NAME (S2-016, S2-032) and the " +
				"slot model replaces values. The name_slot encoder does not exist (CATALOGUE blocker B3), so this " +
				"sink was not tested at all; the label routes it to nuclei-dast's Struts template set",
		},
		{
			ProbeID: "ELI-NONJVM",
			Reason: "non_jvm_el: JEXL and other non-JVM EL-alikes have no payload in this class. Angular's $parse " +
				"is the CSTI class's mechanism and is not covered here either",
		},
	}
}

// -------------------------------------------------------------------------------------------
// 2. PROBES
// -------------------------------------------------------------------------------------------

// The insertion points. Fragment is absent from every one of them because every dialect in this
// class runs on the server and a fragment is never transmitted.
var (
	eliPointsAll  = []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindHeader, triage.KindCookie}
	eliPointsPct  = []triage.SlotKind{triage.KindHeader, triage.KindCookie, triage.KindQuery, triage.KindBody, triage.KindPath}
	eliPointsDec  = []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie}
	eliPointsName = []triage.SlotKind{triage.KindQuery, triage.KindBody}
)

// eliProbe is the shared shape. Every ELI payload is logical bytes with the marker at the PREFIX,
// so a field that truncates at 16 bytes still leaves the probe attributable and "truncated" stays
// distinguishable from "absent".
func eliProbe(id triage.ProbeID, logical string, points []triage.SlotKind, tier triage.ProbeTier, notes string) triage.ProbeSpec {
	return triage.ProbeSpec{
		ID:      id,
		Class:   triage.ClassELI,
		Logical: []byte(logical),
		// The encoder list is what the runner may use. A class never percent-encodes and never
		// JSON-escapes: it declares modes and emits logical bytes. The two traps of CATALOGUE 1.2
		// (% must become %25 on Q/F/P, + must become %2B on Q/F and stay literal on P) are the
		// ENCODER's job and are asserted on the observation before scoring, not performed here.
		Encoders: []triage.EncoderMode{
			triage.EncodeQuery, triage.EncodeForm, triage.EncodePathSegment,
			triage.EncodeHeaderValue, triage.EncodeCookie,
			triage.EncodeJSONString, triage.EncodeMultipartValue, triage.EncodeXMLCDATA,
		},
		Points:    points,
		MarkerPos: triage.MarkerPrefix,
		Tier:      tier,
		// R1: every payload here writes a value the application already accepts into a field it
		// already reads. Nothing creates a record, nothing deletes one, nothing forks, nothing
		// writes to disk, nothing loops and nothing touches a third party.
		Risk:  triage.RiskR1,
		Notes: notes,
	}
}

func eliControl(id triage.ProbeID, logical string, notes string) triage.ProbeSpec {
	p := eliProbe(id, logical, eliPointsAll, triage.TierFull, notes)
	p.IsControl = true
	return p
}

// Probes is every payload this class will ever send.
//
// It is long on purpose. CATALOGUE 2.1 for this class: "No early exit on nothing yet. EL1 silent
// says nothing about EL6." Five of the fourteen typical probes exist because a DIFFERENT
// configuration kills each of the others: a SimpleEvaluationContext kills T(), a valueOf
// allow-list kills the arithmetic and leaves the string oracle, a java.lang WAF rule kills both
// named-class bodies and leaves the generic one, Thymeleaf preprocessing is reached by none of
// EL1, EL2 or EL4, and a bare-expression sink is reached by no delimiter at all.
func (eliClassifier) Probes() []triage.ProbeSpec {
	return []triage.ProbeSpec{
		// ---- census and this class's OWN decode control (ruling R6: no shared perturbed gates)
		eliProbe(eliProbeCensus, `-eli-census`, eliPointsAll, triage.TierReduced,
			"the class's own reflection census. The payload is an inert suffix and not the bare marker alone because "+
				"a probe with zero logical bytes fails the isolation check (it would send nothing and then record clean). "+
				"The suffix is 11 bytes, so a FieldLimit anywhere from 16 up still returns an attributable marker"),
		{
			ID:      eliProbeDecode,
			Class:   triage.ClassELI,
			Logical: []byte(`%65%6c%69%64%65%63%30%32`),
			// literal_pct: the runner writes the % through unencoded, which is the entire point of
			// a decode probe.
			Encoders:  []triage.EncoderMode{triage.EncodeLiteralPct},
			Points:    eliPointsDec,
			MarkerPos: triage.MarkerPrefix,
			Tier:      triage.TierReduced,
			Risk:      triage.RiskR0,
			Overrides: triage.SlotOverrides{RawPercent: true},
			Notes: "THIS CLASS'S OWN decode probe, ruling R6. The percent text decodes to elidec02, a token that " +
				"belongs to no other class, so a response carrying it raw proves decode_depth >= 1 for ELI without " +
				"borrowing a measurement any other class made. Before R6 one bad %78 measurement suppressed probes " +
				"in twelve classes at once",
		},

		// ---- the delimiter battery, one hypothesis each
		eliProbe(eliProbeEL1, `${`+eliBodyGen+`}`, eliPointsAll, triage.TierReduced,
			"JSP EL, JUEL, Jakarta EL, Hibernate Validator message interpolation, Struts ${}, Thymeleaf standard "+
				"expression in a th: attribute. The primary, and the generic body so a hardened Spring context still answers"),
		eliProbe(eliProbeEL2, `#{`+eliBodySpel+`}`, eliPointsAll, triage.TierFull,
			"SpEL template parser and JSF deferred EL. T( identifies SpEL on the spot"),
		eliProbe(eliProbeEL3, `%{`+eliBodyOgnl+`}`, eliPointsPct, triage.TierReduced,
			"OGNL on the Struts 2 value stack. Header and cookie are listed FIRST because % is legal raw in a "+
				"field-vchar and inside cookie-octet, so those two slots deliver %{ without depending on the encoder "+
				"getting %25 right, which is this class's single most likely silent failure"),
		eliProbe(eliProbeEL4, `*{`+eliBodySpel+`}`, eliPointsAll, triage.TierFull,
			"Thymeleaf selection expression, which is SpEL"),
		eliProbe(eliProbeEL5, `@{`+eliBodyGen+`}`, eliPointsAll, triage.TierFull,
			"MVEL2 template. Nothing else in the battery reaches @{ }"),
		eliProbe(eliProbeEL6, eliBodyGen, eliPointsAll, triage.TierReduced,
			"THE BARE EXPRESSION SINK, and it carries NO MARKER: SpelExpressionParser.parseExpression(userInput), an "+
				"OGNL value-stack lookup, an MVEL rule condition. A 16-byte marker prefix makes the value "+
				"<marker>1*(...), which is a parse error in every dialect, so the probe would test nothing. "+
				"Attribution falls back to the probe ordinal on the observation plus the baseline-absence guard, and "+
				"the verdict is capped at medium for exactly that reason. iso-eval ELI 6 calls this the single most "+
				"commonly missed EL sink and it is why this class exists separately from SSTI"),
		eliProbe(eliProbeEL6m, `'+(`+eliBodyGen+`)+'`, eliPointsAll, triage.TierFull,
			"the bare sink when the value lands inside a quoted string literal. '+ and +' close and reopen the "+
				"literal, which is SSTImap's level 1 Java closure, and it restores the marker anchor the bare probe loses"),
		eliProbe(eliProbeEL7, `__${`+eliBodySpel+`}__`, eliPointsAll, triage.TierFull,
			"Thymeleaf PREPROCESSING. A __...__ expression is evaluated in SpEL before the surrounding expression and "+
				"is reachable from ordinary text in several Thymeleaf configurations. EL1, EL2 and EL4 all miss it"),
		eliProbe(eliProbeEL8, `${{`+eliBodySpel+`}}`, eliPointsAll, triage.TierFull,
			"the doubled-brace form HackTricks records as evaluating in some EL configurations"),

		// ---- the independent string oracle
		eliProbe(eliProbeELS1, `${`+eliBodyStr+`}`, eliPointsAll, triage.TierReduced,
			"INDEPENDENT of the arithmetic. A SpEL SimpleEvaluationContext, a method allow-list on valueOf, or a WAF "+
				"rule on java.lang kills the overflow oracle and leaves this one standing; a WAF rule on .replace( "+
				"does the reverse. Running only one of the two is a false negative on whichever configuration the "+
				"other would have caught"),
		eliProbe(eliProbeELS2, `%{`+eliBodyStr+`}`, eliPointsPct, triage.TierFull,
			"the string oracle through OGNL's delimiter"),

		// ---- the error oracle, which is also the ruling R1 disambiguator
		eliProbe(eliProbeELE, `${`+eliBodyErr+`}`, eliPointsAll, triage.TierFull,
			"the error oracle. Every dialect answers a method-not-found with an exception that NAMES the dialect, so "+
				"this rule identifies as well as detects. It is also this class's own R1 disambiguator: when the "+
				"response is plainly perturbed and none of this class's own rules fired, ELE and ELS1 are what decide, "+
				"and no other class's signature catalogue is ever consulted"),

		// ---- confirmations. Fresh operands, so a reproduced answer cannot be a cached body.
		eliProbe(eliProbeCF1, `${`+eliBodyGenConfirm+`}`, eliPointsAll, triage.TierFull, "confirms EL1: -694967296"),
		eliProbe(eliProbeCF2, `#{`+eliBodySpelConfirm+`}`, eliPointsAll, triage.TierFull, "confirms EL2"),
		eliProbe(eliProbeCF3, `%{`+eliBodyOgnlConfirm+`}`, eliPointsPct, triage.TierFull, "confirms EL3"),
		eliProbe(eliProbeCF4, `*{`+eliBodySpelConfirm+`}`, eliPointsAll, triage.TierFull, "confirms EL4"),
		eliProbe(eliProbeCF5, `@{`+eliBodyGenConfirm+`}`, eliPointsAll, triage.TierFull, "confirms EL5"),
		eliProbe(eliProbeCF6, eliBodyGenConfirm, eliPointsAll, triage.TierFull, "confirms EL6. Also carries no marker"),
		eliProbe(eliProbeCF6m, `'+(`+eliBodyGenConfirm+`)+'`, eliPointsAll, triage.TierFull, "confirms EL6m"),
		eliProbe(eliProbeCF7, `__${`+eliBodySpelConfirm+`}__`, eliPointsAll, triage.TierFull, "confirms EL7"),
		eliProbe(eliProbeCF8, `${{`+eliBodySpelConfirm+`}}`, eliPointsAll, triage.TierFull, "confirms EL8"),
		eliProbe(eliProbeELS3, `${`+eliBodyStrUpper+`}`, eliPointsAll, triage.TierFull,
			"confirms the string oracle with a SECOND, different method. Two distinct method invocations is evidence "+
				"of an expression evaluator; only .replace() resolving is a String.format or a message interpolator "+
				"with a narrow API, which is suspicious (limited_api) and not a finding"),

		// ---- dialect identification, sent only after a generic-body hit
		eliProbe(eliProbeIDSpelDollar, `${`+eliBodySpel+`}`, eliPointsAll, triage.TierFull, "identifies SpEL on the ${ } delimiter"),
		eliProbe(eliProbeIDOgnlDollar, `${`+eliBodyOgnl+`}`, eliPointsAll, triage.TierFull, "identifies OGNL on the ${ } delimiter"),
		eliProbe(eliProbeIDSpelAt, `@{`+eliBodySpel+`}`, eliPointsAll, triage.TierFull, "identifies SpEL on the @{ } delimiter"),
		eliProbe(eliProbeIDOgnlAt, `@{`+eliBodyOgnl+`}`, eliPointsAll, triage.TierFull, "identifies OGNL on the @{ } delimiter"),
		eliProbe(eliProbeIDSpelBare, eliBodySpel, eliPointsAll, triage.TierFull, "identifies SpEL at a bare sink"),
		eliProbe(eliProbeIDOgnlBare, eliBodyOgnl, eliPointsAll, triage.TierFull, "identifies OGNL at a bare sink"),

		// ---- the one post-confirmation read
		eliProbe(eliProbeJVM, `${`+eliBodyVersion+`}`, eliPointsAll, triage.TierOptIn,
			"reads java.version, once per vector, ONLY after a confirmed finding. Read-only: writes nothing, starts "+
				"no process, touches no file. The JVM major version decides which gadget chains apply later"),

		// ---- the negative controls. A detector never shown to STAY SILENT is not verified.
		eliControl(eliProbeNC1, `x24x7B1x2A((1).valueOf(x27`+eliOperand+`x27)PLUS`+eliOperand+`)x7D`,
			"inert echo: every delimiter and operator byte replaced by a letter sequence, same length band, same "+
				"alphabet. If EL_OVERFLOW fires on this, it is matching -494967296 unanchored"),
		eliControl(eliProbeNC2, eliWrapped,
			"the answer sent as literal text adjacent to the marker. The regex WILL match; the answer_not_in_wire "+
				"guard must suppress it. This control verifies the GUARD, not the regex, and the guard is the thing "+
				"that stops every echoing endpoint reading as a finding"),
		eliControl(eliProbeNC3, eliStrAnswer,
			"the same, for the string oracle"),
		eliControl(eliProbeNC4, eliUnwrapped,
			"the UNWRAPPED answer, sent. It must fire neither EL_OVERFLOW nor el_overflow_unwrapped, because it was "+
				"transmitted rather than computed"),
		eliControl(eliProbeNC5a, `%{}`,
			"empty expression, OGNL delimiter. An ERROR here is a legitimate EL_ERROR hit and is not a failure of the "+
				"control; what must not happen is a computation or string match"),
		eliControl(eliProbeNC5b, `@{}`,
			"empty expression, MVEL delimiter"),
		eliControl(eliProbeNC5c, `${{}}`,
			"empty expression, doubled brace. These three carry ELI-EXCLUSIVE delimiters on purpose: the obvious "+
				"bytes for an empty-expression control are ${} and SSTI-NC3 owns them, and two classes shipping "+
				"byte-equal payloads is the isolation law's first violation. Three requests where two would have "+
				"done, and the reason is written here rather than optimised away"),
	}
}

// -------------------------------------------------------------------------------------------
// 3. REACHABILITY
// -------------------------------------------------------------------------------------------

// Reaches. CATALOGUE 3.1, ELI row.
//
// THERE IS NO STACK GATE AND THAT IS DELIBERATE (iso-eval ELI 7). The tempting rule is "only probe
// when the banner says Java". It is refused for three measured reasons: a reverse proxy, a CDN or
// an API gateway supplies Server and X-Powered-By on most modern deployments so the banner
// describes the edge and not the origin; a Node front end proxying to a Spring service is one of
// the most common shapes in this corpus and the crawl sees the Node banner; and the whole class
// costs about fourteen requests, which is the trade the brief asks for explicitly. Java-stack
// signals ORDER this class's queue (see eliOrderingScore) and never suppress it.
func (eliClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindQuery:
		return triage.Reachability{Reach: triage.ReachAlways}

	case triage.KindHeader:
		return triage.Reachability{Reach: triage.ReachAlways}

	case triage.KindCookie:
		return triage.Reachability{Reach: triage.ReachAlways}

	case triage.KindPath:
		return triage.Reachability{Reach: triage.ReachAlways}

	case triage.KindBody:
		switch mt {
		case "application/json":
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "a JSON STRING leaf is always reached and is the best point for this class (nothing needs " +
					"escaping); a container NODE is never reached, because an expression sink takes a string and not " +
					"an object; a number, boolean or null leaf is reached only as json_string_coerced, and a 400 on " +
					"the coerced form alone is type_rejection and never clean",
			}
		case "application/graphql":
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "a GraphQL variable is reachable, but every judgement must come from /errors, the " +
					"extensions/code set and whether /data went null. A GraphQL endpoint answers 200 to a syntax " +
					"error, so a class that grades this slot on status reports every probe as clean",
			}
		case "application/xml", "text/xml", "application/soap+xml":
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "XML element text is reached raw: no ELI payload contains < or &, so no escaping and no " +
					"xml_cdata mode is needed. Whole-document replacement is not reached, because the leaf slots " +
					"already cover it",
			}
		default:
			return triage.Reachability{Reach: triage.ReachAlways}
		}

	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "not_applicable (fragment): RFC 3986 section 3.5 makes the fragment a client-side reference that " +
				"the browser strips before the request goes out, and every dialect in this class (OGNL, SpEL, MVEL, " +
				"JSP and Jakarta EL) runs on the server. There is nothing here to reach",
		}
	}

	return triage.Reachability{
		Reach: triage.ReachNever,
		Reason: "slot kind " + string(k) + " is not in the closed set this class was written against, and guessing " +
			"at a new one would be a probe nobody reasoned about",
	}
}

// -------------------------------------------------------------------------------------------
// 4. THE LADDER
// -------------------------------------------------------------------------------------------

// eliGate is a foundations-level reason this class sent nothing. It is a value and not a bool so
// the verdict can name WHICH gate closed, because "no probes" with no reason is how a check that
// never ran becomes a clean.
type eliGate struct {
	State  triage.TriageState
	Reason string
}

// eliCheckGates runs the preconditions that are decided before a byte is sent.
func eliCheckGates(ctx triage.PlanCtx) (eliGate, bool) {
	s := ctx.Slot
	if s.Kind == triage.KindFragment || !s.ServerReachable {
		return eliGate{triage.StateNotApplicable,
			"fragment: the bytes never leave the browser, and every dialect in this class runs on the server"}, true
	}
	if s.Constraints.IsCredential {
		return eliGate{triage.StateNotProbed,
			"credential_slot: injecting into an Authorization header or a session cookie produces a 401 that is a " +
				"differential against baseline and looks exactly like a finding. No class probes one"}, true
	}
	if ctx.Prelude.Failed() {
		return eliGate{triage.StateCannotDetermine,
			fmt.Sprintf("prelude_failed (%s): an unobtained or unmeasured token makes every probe fail validation "+
				"identically, which reads as a stable endpoint with no differential, which reads as clean",
				eliPreludeName(ctx.Prelude))}, true
	}
	if s.Wrapper == triage.WrapSigned {
		return eliGate{triage.StateCannotDetermine,
			"signed_wrapper: the slot carries a signed, serialised value (javax.faces.ViewState and its relatives). " +
				"A modified value fails its MAC before any expression parser sees it, so a null result here is not " +
				"evidence about the sink"}, true
	}
	if ctx.Baseline.Degraded {
		return eliGate{triage.StateCannotDetermine,
			"baseline_degraded: the baseline body was over the cap, truncated or failed to tokenize, so the " +
				"absence guards this class's two computation rules depend on cannot be evaluated"}, true
	}
	if ctx.Budget.Exhausted() {
		return eliGate{triage.StateNotRun,
			"probe_budget_exhausted: the per-slot or per-run cap was already spent before this class reached the " +
				"slot, so nothing was sent"}, true
	}
	return eliGate{}, false
}

// eliRouteGate is the ROUTE control check, and it is deliberately separate from eliCheckGates and
// applied last.
//
// TWO REASONS, AND THE SECOND IS ABOUT BEING ABLE TO TEST ANY OF THIS. The first is ordering: every
// gate above is decidable from the capture alone and costs nothing, while the route control costs
// a request, so the free refusals belong in front of it. The second is that triage.Replay can only
// be constructed by the triage package holding the runner capability, so no test in this package
// can ever hand a classifier a RESOLVED route. Folded into eliCheckGates, this one condition would
// make every other gate, and the whole of Plan, unreachable from a test: the first assertion would
// always come back route_unresolved and the other twelve would ship unexercised.
func eliRouteGate(ctx triage.PlanCtx) (eliGate, bool) {
	if !ctx.Route.Resolved() {
		return eliGate{triage.StateCannotDetermine,
			"route_unresolved: with no control response at the slot's observed value there is nothing to difference " +
				"against, so no oracle in this class can be baseline-subtracted"}, true
	}
	return eliGate{}, false
}

func eliPreludeName(p triage.PreludeState) string {
	if p == triage.PreludeUnknown {
		return "unmeasured"
	}
	return string(p)
}

// Plan is the ladder of CATALOGUE 2.1 for this class.
//
// Round 0: the census and this class's own decode control.
// Round 1: EL1, the primary.
// Round 2: the rest of the battery, unless round 1 already produced a confirmed hit.
// Round 3: confirmation, dialect identification and THE NEGATIVE CONTROLS, which are sent on a hit
//
//	because a detector that fired and was never shown staying silent has not been verified.
//
// Round 4 and later: nil.
//
// THERE IS NO EARLY EXIT ON "NOTHING YET". EL1 being silent says nothing whatever about EL6, which
// reaches a completely different sink shape. The only early exit is a CONFIRMED hit, and it stops
// the delimiter battery only after the two identification probes have run.
func (c eliClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if _, closed := eliCheckGates(ctx); closed {
		return nil
	}
	if _, closed := eliRouteGate(ctx); closed {
		return nil
	}
	hit, _ := eliFirstOverflowHit(ctx.Own)
	return eliPlanRound(ctx, hit, eliAnyStringHit(ctx.Own))
}

// eliPlanRound is the round dispatch, split out for the same reason eliVerdict is: ClassifyCtx.Own
// and a resolved Route can only be built by the triage package with the runner capability, so a
// ladder left inline would be reachable from a test only in the shape where it correctly returns
// nothing. The two facts the ladder needs from this class's own responses are passed in.
func eliPlanRound(ctx triage.PlanCtx, overflowHit triage.ProbeID, stringHit bool) []triage.ProbeRequest {
	switch ctx.Round {
	case 0:
		return eliRequests(ctx, eliProbeCensus, eliProbeDecode)

	case 1:
		return eliRequests(ctx, eliProbeEL1)

	case 2:
		if overflowHit != "" {
			// A computation hit on the primary. Go straight to confirmation and identification,
			// and record by NAME every delimiter that was therefore not sent: the operator running
			// sstimap afterwards wants to know which ones are still open.
			return eliRequests(ctx, eliConfirmFor(overflowHit))
		}
		return eliRequests(ctx, eliBatteryOrder(ctx)...)

	case 3:
		var want []triage.ProbeID
		if overflowHit != "" {
			want = append(want, eliIdentifyFor(overflowHit)...)
			if cf := eliConfirmFor(overflowHit); cf != "" && !eliWasSent(ctx.Own, cf) {
				want = append(want, cf)
			}
		}
		if stringHit {
			want = append(want, eliProbeELS3)
		}
		if len(want) == 0 {
			return nil
		}
		// Every hit drags the control set along with it. CATALOGUE 1.2: a class whose control
		// fires has not proven its detector silent, and all of its verdicts on that slot become
		// cannot_determine (detector_unverified).
		want = append(want, eliProbeNC1, eliProbeNC2, eliProbeNC3, eliProbeNC4,
			eliProbeNC5a, eliProbeNC5b, eliProbeNC5c)
		return eliRequests(ctx, want...)
	}

	return nil
}

// eliBatteryOrder is the full battery in send order. The order is a PREFERENCE and never a filter:
// when the budget truncates the list, the probes that fall off are named in Untested, not dropped
// silently.
func eliBatteryOrder(ctx triage.PlanCtx) []triage.ProbeID {
	base := []triage.ProbeID{
		eliProbeEL3, eliProbeEL6, eliProbeELS1, // the reduced set's remainder: OGNL, bare sink, string oracle
		eliProbeEL2, eliProbeEL4, eliProbeEL5, eliProbeEL7, eliProbeEL8,
		eliProbeEL6m, eliProbeELS2, eliProbeELE,
	}
	if eliOrderingPrefersOgnl(ctx) {
		return base
	}
	if eliOrderingPrefersSpel(ctx) {
		// A Spring or JSF signal moves the SpEL-bodied delimiters forward. It changes nothing
		// about WHICH probes are sent, only the order they are sent in, which matters only when
		// the budget truncates.
		return []triage.ProbeID{
			eliProbeEL2, eliProbeEL4, eliProbeELS1, eliProbeEL7, eliProbeEL8,
			eliProbeEL6, eliProbeEL3, eliProbeEL5, eliProbeEL6m, eliProbeELS2, eliProbeELE,
		}
	}
	return base
}

// eliOrderingPrefersOgnl and eliOrderingPrefersSpel read the CAPTURE and the slot name only. They
// read no probe result, this class's or anybody's, so they cannot be a gate wearing a hat.
func eliOrderingPrefersOgnl(ctx triage.PlanCtx) bool {
	u := strings.ToLower(ctx.Vector.ComposedURL)
	return strings.Contains(u, ".do") || strings.Contains(u, ".action")
}

func eliOrderingPrefersSpel(ctx triage.PlanCtx) bool {
	u := strings.ToLower(ctx.Vector.ComposedURL)
	for _, s := range []string{".jsf", ".faces", ".xhtml", ".jsp"} {
		if strings.Contains(u, s) {
			return true
		}
	}
	return false
}

// eliRequests turns probe ids into requests, capped at what the budget will actually pay for. The
// cap is applied here rather than by the runner so the class KNOWS which probes it gave up, and
// Classify names them.
func eliRequests(ctx triage.PlanCtx, ids ...triage.ProbeID) []triage.ProbeRequest {
	out := make([]triage.ProbeRequest, 0, len(ids))
	room := ctx.Budget.RemainingPerSlot
	for _, id := range ids {
		if id == "" {
			continue
		}
		if ctx.Budget.PerSlot > 0 && len(out) >= room {
			break
		}
		r := triage.ProbeRequest{Spec: id, Slot: ctx.Slot.Key, Variant: eliVariantFor(id)}
		out = append(out, r)
	}
	return out
}

// eliVariantFor carries the per-instance values. The one that matters is marker_placement on the
// two bare-expression probes.
//
// THE BARE PROBES MUST GO OUT WITH NO MARKER AND THERE IS NO MarkerPos VALUE THAT SAYS SO. MarkerPos
// is prefix, suffix or inline, and all three attach one. So the requirement is declared in the
// Variant, and Classify VERIFIES it on the wire rather than trusting it: if a marker is found in
// the bytes that actually went out for EL6, the expression was corrupted into a parse error, the
// probe tested nothing, and the verdict is cannot_determine (bare_expression_marker_attached).
// Fail-closed, because the alternative is a silent clean on the single most commonly missed EL sink.
func eliVariantFor(id triage.ProbeID) map[string]string {
	v := map[string]string{"operand": eliOperand, "expected": eliWrapped}
	if eliIsConfirmProbe(id) {
		v["operand"], v["expected"] = eliOperand2, eliWrapped2
	}
	if eliIsBareProbe(id) {
		// CF6 is BOTH a confirmation and a bare probe, which is why this is two independent
		// predicates and not one switch: an earlier version wrote it as a switch and the compiler
		// caught the duplicate case, which is a nicer way to find it than a confirmation quietly
		// going out with a marker attached.
		v["marker_placement"] = "omitted"
	}
	return v
}

// eliConfirmFor maps a firing probe to the confirmation that uses the SAME delimiter and the SAME
// body with fresh operands. Same delimiter matters: a confirmation on a different delimiter proves
// a different sink and says nothing about the one that fired.
func eliConfirmFor(id triage.ProbeID) triage.ProbeID {
	switch id {
	case eliProbeEL1:
		return eliProbeCF1
	case eliProbeEL2:
		return eliProbeCF2
	case eliProbeEL3:
		return eliProbeCF3
	case eliProbeEL4:
		return eliProbeCF4
	case eliProbeEL5:
		return eliProbeCF5
	case eliProbeEL6:
		return eliProbeCF6
	case eliProbeEL6m:
		return eliProbeCF6m
	case eliProbeEL7:
		return eliProbeCF7
	case eliProbeEL8:
		return eliProbeCF8
	}
	return ""
}

// eliIdentifyFor returns the two dialect-identification probes for the delimiter that fired, and
// only where the body that fired was the GENERIC one. A hit on EL2 already carries T(, so SpEL is
// identified and spending two more requests would tell the operator nothing.
func eliIdentifyFor(id triage.ProbeID) []triage.ProbeID {
	switch id {
	case eliProbeEL1:
		return []triage.ProbeID{eliProbeIDSpelDollar, eliProbeIDOgnlDollar}
	case eliProbeEL5:
		return []triage.ProbeID{eliProbeIDSpelAt, eliProbeIDOgnlAt}
	case eliProbeEL6, eliProbeEL6m:
		return []triage.ProbeID{eliProbeIDSpelBare, eliProbeIDOgnlBare}
	}
	return nil
}

// -------------------------------------------------------------------------------------------
// 5. THE DETECTORS
// -------------------------------------------------------------------------------------------

// eliHit is one rule firing on one observation.
type eliHit struct {
	Probe    triage.ProbeID
	Ordinal  uint64
	Oracle   string
	Dialect  string
	Phrase   string
	Matched  []byte
	Offset   int
	Anchored bool // was the answer adjacent to this probe's own marker
}

// eliAsciiLowerEq compares two byte slices ignoring ASCII case. It is written out rather than done
// with bytes.ToLower because ToLower can CHANGE THE LENGTH of a non-ASCII input (U+0130 becomes two
// bytes), and every offset this file reports would then be wrong by an amount that depends on the
// page's content.
func eliAsciiLowerEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// eliFindMarker returns every offset at which the marker appears, in any ASCII case transform. The
// case transforms are part of the foundations 2.5 search set and they are real: an application that
// upper-cases a display name returns the marker as ZQJ... and a case-sensitive search misses the hit.
func eliFindMarker(hay []byte, marker string) []int {
	if len(marker) == 0 || len(hay) < len(marker) {
		return nil
	}
	m := []byte(marker)
	var out []int
	for i := 0; i+len(m) <= len(hay); i++ {
		if eliAsciiLowerEq(hay[i:i+len(m)], m) {
			out = append(out, i)
		}
	}
	return out
}

func eliIsAlnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func eliIsSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// eliAdjacent implements the whole adjacency rule in one place, because it is the detection rule.
//
//	(?<![0-9a-zA-Z]) marker [\s]{0,8} answer (?![0-9])
//
// Go's regexp has no lookbehind, so the boundaries are checked by hand. They are not decoration:
// without the trailing digit check, -4949672960 matches; without the leading one, a longer token
// ending in the marker matches; without the whitespace cap, the marker at the top of the page and
// the number at the bottom match.
//
// The last parameter is the maximum whitespace gap. 8 is the catalogue's number.
func eliAdjacent(hay []byte, marker, answer string, gap int) (int, bool) {
	a := []byte(answer)
	for _, at := range eliFindMarker(hay, marker) {
		if at > 0 && eliIsAlnum(hay[at-1]) {
			continue
		}
		p := at + len(marker)
		for w := 0; w < gap && p < len(hay) && eliIsSpace(hay[p]); w++ {
			p++
		}
		if p+len(a) > len(hay) || !bytes.Equal(hay[p:p+len(a)], a) {
			continue
		}
		end := p + len(a)
		if end < len(hay) && hay[end] >= '0' && hay[end] <= '9' {
			continue
		}
		return p, true
	}
	return 0, false
}

// eliSentBytes is everything this probe put on the wire, which is what the answer_not_in_wire guard
// is computed over.
//
// IT IS DELIBERATELY WIDE. Logical is what the class asked for, Wire is what the encoder produced,
// Container is the whole serialized container (the Cookie line, the query string, the JSON body),
// and the request target and body are included on top. A guard that only looked at Wire would miss
// an application that echoes the raw query string, and the class would then read its own request
// back as a computed answer. Being wide can only SUPPRESS a match, and a suppressed true positive
// costs a scanner run while an accepted false positive costs the operator's trust in every row.
func eliSentBytes(o triage.Observation) []byte {
	var b []byte
	b = append(b, o.Payload.Logical...)
	b = append(b, ' ')
	b = append(b, o.Payload.Wire...)
	b = append(b, ' ')
	b = append(b, o.Payload.Container...)
	b = append(b, ' ')
	b = append(b, []byte(o.ReqWireURL)...)
	b = append(b, ' ')
	b = append(b, o.ReqBody...)
	return b
}

// eliHaystacks is body plus every response header value. The rules search headers too, on purpose:
// an EL expression interpolated into a Location or a Set-Cookie is a real sink, and the echo of the
// payload into a header can never contain the computed answer, so the extra surface adds coverage
// without adding a false positive mode.
func eliHaystacks(o triage.Observation) [][]byte {
	out := [][]byte{o.Body}
	for _, h := range o.RespHeaders {
		out = append(out, []byte(h[1]))
	}
	return out
}

// eliMatchOverflow is rule E-D1, the primary.
//
// MUST NOT MATCH, and each of these has a test row:
//   - 3800000000, the unwrapped answer. A different evaluator, a different state, never this one.
//   - the verbatim echo of the payload, which contains 1900000000 twice and -494967296 never.
//   - -4949672960, 1-494967296, or the digits inside a longer run.
//   - the answer when this probe SENT it (NC2), which is the answer_not_in_wire guard.
//   - the answer when the unperturbed baseline already carried it.
func eliMatchOverflow(o triage.Observation, marker, answer string, baseline []byte) (eliHit, bool) {
	if len(baseline) > 0 && bytes.Contains(baseline, []byte(answer)) {
		return eliHit{}, false
	}
	if bytes.Contains(eliSentBytes(o), []byte(answer)) {
		return eliHit{}, false
	}
	if marker != "" {
		for _, hay := range eliHaystacks(o) {
			if at, ok := eliAdjacent(hay, marker, answer, 8); ok {
				return eliHit{Oracle: eliOracleOverflow, Matched: []byte(answer), Offset: at, Anchored: true}, true
			}
		}
		// The locale-grouped rendering. Standard EL output does not group, so this is SECONDARY
		// and its caller caps it at suspicious. It exists so a value routed through a formatter is
		// not a silent zero.
		for _, hay := range eliHaystacks(o) {
			if at, ok := eliAdjacent(hay, marker, eliGrouped, 8); ok {
				return eliHit{Oracle: eliOracleGrouped, Matched: []byte(eliGrouped), Offset: at, Anchored: true}, true
			}
		}
		return eliHit{}, false
	}

	// The bare probe has no marker to anchor to. Attribution is the probe ordinal on the
	// observation plus the two absence guards above, and the caller caps the grade at medium.
	for _, hay := range eliHaystacks(o) {
		if at := bytes.Index(hay, []byte(answer)); at >= 0 {
			end := at + len(answer)
			if end < len(hay) && hay[end] >= '0' && hay[end] <= '9' {
				continue
			}
			if at > 0 && eliIsAlnum(hay[at-1]) {
				continue
			}
			return eliHit{Oracle: eliOracleOverflow, Matched: []byte(answer), Offset: at, Anchored: false}, true
		}
	}
	return eliHit{}, false
}

// eliMatchUnwrapped is the DISTINCT, WEAKER state. 3800000000 means arithmetic was evaluated by
// something that is not a Java 32-bit int: Python, JavaScript, Ruby, PHP, or a JVM long. That is a
// real observation and it is worth recording, and it is NOT this class's finding. CATALOGUE 1.2
// NC4 sends the literal 3800000000 and requires that this returns false for it, which is why the
// wire guard runs first.
func eliMatchUnwrapped(o triage.Observation, marker string, baseline []byte) (eliHit, bool) {
	if len(baseline) > 0 && bytes.Contains(baseline, []byte(eliUnwrapped)) {
		return eliHit{}, false
	}
	if bytes.Contains(eliSentBytes(o), []byte(eliUnwrapped)) {
		return eliHit{}, false
	}
	if marker == "" {
		return eliHit{}, false
	}
	for _, hay := range eliHaystacks(o) {
		if at, ok := eliAdjacent(hay, marker, eliUnwrapped, 8); ok {
			return eliHit{Oracle: eliOracleUnwrapped, Matched: []byte(eliUnwrapped), Offset: at, Anchored: true}, true
		}
	}
	return eliHit{}, false
}

// eliMatchString is rule E-D2, and it is INDEPENDENT of E-D1 rather than a corroboration of it.
//
// MUST NOT MATCH: the echo 'qmkvbnkw'.replace('k','7'), which contains qmkvbnkw and 7 and never
// qm7vbn7w; and the answer when this probe sent it (NC3). A PARTIAL replacement qm7vbnkw is a
// different mechanism (replaceFirst) and is returned as its own oracle, capped at suspicious.
func eliMatchString(o triage.Observation, marker string, baseline []byte) (eliHit, bool) {
	sent := eliSentBytes(o)
	if marker == "" {
		return eliHit{}, false
	}
	if !(len(baseline) > 0 && bytes.Contains(baseline, []byte(eliStrAnswer))) && !bytes.Contains(sent, []byte(eliStrAnswer)) {
		for _, hay := range eliHaystacks(o) {
			if at, ok := eliAdjacent(hay, marker, eliStrAnswer, 8); ok {
				end := at + len(eliStrAnswer)
				if end < len(hay) && eliIsAlnum(hay[end]) {
					continue
				}
				return eliHit{Oracle: eliOracleString, Matched: []byte(eliStrAnswer), Offset: at, Anchored: true}, true
			}
		}
	}
	if !(len(baseline) > 0 && bytes.Contains(baseline, []byte(eliStrPartial))) && !bytes.Contains(sent, []byte(eliStrPartial)) {
		for _, hay := range eliHaystacks(o) {
			if at, ok := eliAdjacent(hay, marker, eliStrPartial, 8); ok {
				return eliHit{Oracle: eliOraclePartial, Matched: []byte(eliStrPartial), Offset: at, Anchored: true}, true
			}
		}
	}
	// The toUpperCase confirmation resolves a SECOND method, which is what separates an expression
	// evaluator from a String.format or a message interpolator with a narrow API.
	if !bytes.Contains(sent, []byte(eliStrUpper)) && !(len(baseline) > 0 && bytes.Contains(baseline, []byte(eliStrUpper))) {
		for _, hay := range eliHaystacks(o) {
			if at, ok := eliAdjacent(hay, marker, eliStrUpper, 8); ok {
				return eliHit{Oracle: eliOracleString, Matched: []byte(eliStrUpper), Offset: at, Anchored: true}, true
			}
		}
	}
	return eliHit{}, false
}

// eliSignature is one row of THIS CLASS'S OWN error catalogue. Ruling R1: a class never reads, and
// never needs to know the existence of, another class's signature catalogue, not even to fail
// closed. There is no FreeMarker, no Jinja2, no Velocity and no Twig literal anywhere in this file.
type eliSignature struct {
	ID      string
	Literal string
	Dialect string
}

// eliSignatures identifies the dialect as well as detecting it, which is the property that makes
// the error oracle worth its one request even though it is only rank 4.
var eliSignatures = []eliSignature{
	{"spel.eval", "org.springframework.expression.spel.SpelEvaluationException", "spel"},
	{"spel.parse", "org.springframework.expression.spel.SpelParseException", "spel"},
	{"spel.e1004", "EL1004E", "spel"},
	{"spel.e1007", "EL1007E", "spel"},
	{"spel.e1008", "EL1008E", "spel"},
	// EL1027E is quoted from memory of the Spring source and was NOT confirmed against SpelMessage
	// in the research pass. It is kept because a false positive here costs a scanner run and a
	// false negative costs the bug, and it is marked so nobody later reads the list as uniformly
	// verified. EL1004E, EL1007E and EL1008E are the three to rely on.
	{"spel.e1027.unverified", "EL1027E", "spel"},
	{"ognl.base", "ognl.OgnlException", "ognl"},
	{"ognl.parse", "ognl.ParseException", "ognl"},
	{"ognl.nosuchprop", "ognl.NoSuchPropertyException", "ognl"},
	{"ognl.methodfail", "ognl.MethodFailedException", "ognl"},
	{"ognl.expsyntax", "ognl.ExpressionSyntaxException", "ognl"},
	{"struts.report", "Struts Problem Report", "ognl"},
	{"mvel.compile", "org.mvel2.CompileException", "mvel"},
	{"mvel.propacc", "org.mvel2.PropertyAccessException", "mvel"},
	{"mvel.unresolved", "org.mvel2.UnresolveablePropertyException", "mvel"},
	{"juel.el.javax", "javax.el.ELException", "juel"},
	{"juel.el.jakarta", "jakarta.el.ELException", "jakarta_el"},
	{"juel.propnotfound.javax", "javax.el.PropertyNotFoundException", "juel"},
	{"juel.propnotfound.jakarta", "jakarta.el.PropertyNotFoundException", "jakarta_el"},
	{"juel.methodnotfound.javax", "javax.el.MethodNotFoundException", "juel"},
	{"juel.methodnotfound.jakarta", "jakarta.el.MethodNotFoundException", "jakarta_el"},
	{"juel.parse.tomcat", "org.apache.el.parser.ParseException", "juel"},
	{"juel.parse.glassfish", "com.sun.el.parser.ParseException", "juel"},
	{"hv.interp", "HV000149", "jakarta_el"},
}

// eliMatchError is rule E-D3, and it is BASELINE-DIFFERENCED, always.
//
// A Struts application with struts.devMode=true prints a Problem Report on every bad request
// including the ones in the baseline. Without the subtraction this class reports a finding on every
// slot of every such application, forever. The subtraction is per signature, not per response: a
// baseline carrying ognl.OgnlException disables ognl.base for that endpoint and leaves ognl.parse
// live, because the second one is still new information.
func eliMatchError(o triage.Observation, baseline []byte) (eliHit, bool) {
	for _, s := range eliSignatures {
		lit := []byte(s.Literal)
		if len(baseline) > 0 && bytes.Contains(baseline, lit) {
			continue
		}
		for _, hay := range eliHaystacks(o) {
			if at := bytes.Index(hay, lit); at >= 0 {
				return eliHit{
					Oracle: eliOracleError, Dialect: s.Dialect, Phrase: s.ID,
					Matched: lit, Offset: at, Anchored: false,
				}, true
			}
		}
	}
	return eliHit{}, false
}

// -------------------------------------------------------------------------------------------
// 6. READING THIS CLASS'S OWN RESPONSES
// -------------------------------------------------------------------------------------------

// eliOwn is one of this class's own probe observations, unpacked. Note the type it comes from:
// OwnedResponses, which only the triage package can build and which holds this class's partition
// and nothing else. There is no code path in this file through which another class's response can
// arrive, and there is no field on PlanCtx that could carry one.
type eliOwn struct {
	Probe   triage.ProbeID
	Ordinal uint64
	Marker  string
	Obs     triage.Observation
}

func eliOwnedProbes(own triage.OwnedResponses) ([]eliOwn, error) {
	out := make([]eliOwn, 0, own.Len())
	for i := 0; i < own.Len(); i++ {
		p, o, err := own.At(i)
		if err != nil {
			return nil, err
		}
		out = append(out, eliOwn{Probe: p.ProbeID(), Ordinal: p.Ordinal(), Marker: string(p.Marker()), Obs: o})
	}
	return out, nil
}

func eliWasSent(own triage.OwnedResponses, id triage.ProbeID) bool {
	for i := 0; i < own.Len(); i++ {
		p, _, err := own.At(i)
		if err == nil && p.ProbeID() == id {
			return true
		}
	}
	return false
}

// eliFirstOverflowHit is what the LADDER asks: did any computation probe fire. It is deliberately
// conservative about the baseline, which Plan does not have in a usable form: it passes nil, so the
// baseline-absence guard is not applied here. That can only make Plan send MORE probes (a
// confirmation and two identification probes), never fewer, and the guard is applied properly in
// Classify where the baseline is in hand.
func eliFirstOverflowHit(own triage.OwnedResponses) (triage.ProbeID, uint64) {
	for i := 0; i < own.Len(); i++ {
		p, o, err := own.At(i)
		if err != nil {
			continue
		}
		if _, ok := eliMatchOverflow(o, string(p.Marker()), eliWrapped, nil); ok {
			return p.ProbeID(), p.Ordinal()
		}
	}
	return "", 0
}

func eliAnyStringHit(own triage.OwnedResponses) bool {
	for i := 0; i < own.Len(); i++ {
		p, o, err := own.At(i)
		if err != nil {
			continue
		}
		if _, ok := eliMatchString(o, string(p.Marker()), nil); ok {
			return true
		}
	}
	return false
}

// -------------------------------------------------------------------------------------------
// 7. THE VERDICT
// -------------------------------------------------------------------------------------------

// eliArm names the three INDEPENDENT oracle arms. A clean requires that at least one probe from
// each arm was delivered with its payload proven on the wire, because the three fail for different
// reasons: a method allow-list kills the overflow arm and leaves the string arm, a WAF rule on
// .replace( does the reverse, and the error arm depends on neither. A clean drawn from one arm is a
// statement about one arm dressed up as a statement about the class.
type eliArm string

const (
	eliArmOverflow eliArm = "overflow"
	eliArmString   eliArm = "string"
	eliArmError    eliArm = "error"
)

func eliArmOf(id triage.ProbeID) eliArm {
	switch id {
	case eliProbeELS1, eliProbeELS2, eliProbeELS3:
		return eliArmString
	case eliProbeELE:
		return eliArmError
	case eliProbeEL1, eliProbeEL2, eliProbeEL3, eliProbeEL4, eliProbeEL5,
		eliProbeEL6, eliProbeEL6m, eliProbeEL7, eliProbeEL8,
		eliProbeCF1, eliProbeCF2, eliProbeCF3, eliProbeCF4, eliProbeCF5,
		eliProbeCF6, eliProbeCF6m, eliProbeCF7, eliProbeCF8,
		eliProbeIDSpelDollar, eliProbeIDOgnlDollar, eliProbeIDSpelAt,
		eliProbeIDOgnlAt, eliProbeIDSpelBare, eliProbeIDOgnlBare:
		return eliArmOverflow
	}
	return ""
}

// Classify. One verdict per slot, and it is capable of exactly one green answer under exactly the
// conditions listed on eliCleanPreconditions. Every other route out of this function is an unknown
// with a reason that names what stopped the measurement.
func (c eliClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key

	// 1. The gates, first, because they are the reason there are no ordinals to report.
	if g, closed := eliCheckGates(ctx.PlanCtx); closed {
		return eliOne(key, g.State, g.Reason, nil, "")
	}
	if g, closed := eliRouteGate(ctx.PlanCtx); closed {
		return eliOne(key, g.State, g.Reason, nil, "")
	}

	owned, err := eliOwnedProbes(ctx.Own)
	if err != nil {
		// OwnedResponses.At re-checks the marker stripe on every read. It failing means a
		// foreign response reached this class's partition, which is a layer bug and never a
		// measurement, so it is loud rather than quiet.
		return eliOne(key, triage.StateCannotDetermine,
			"runner_bug: reading this class's own responses failed the ownership re-check ("+err.Error()+
				"), so nothing in hand can be scored", nil, "")
	}
	return eliVerdict(ctx, owned)
}

// eliVerdict is the scoring core, split out from Classify for one reason that is about testing and
// is worth stating: OwnedResponses can only be built by the triage package with the runner
// capability, so a test in this package can never populate ClassifyCtx.Own. Left inline, every
// rule in this class would be reachable from a test only through a ctx holding zero responses,
// which is to say the detectors would ship verified on the empty case alone. The unpacking stays
// in Classify, where the ownership re-check runs; everything after it is a pure function of this
// class's own observations and is exercised row by row in eli_test.go.
func eliVerdict(ctx triage.ClassifyCtx, owned []eliOwn) []triage.ClassVerdict {
	key := ctx.Slot.Key
	if len(owned) == 0 {
		return eliOne(key, triage.StateNotPlanned,
			"no_probe_derived: the gates were open and the ladder still produced no request for this slot, which is "+
				"a planning bug and is reported rather than rendered as an untested blank", nil, "")
	}

	ordinals := make([]uint64, 0, len(owned))
	for _, o := range owned {
		ordinals = append(ordinals, o.Ordinal)
	}
	sort.Slice(ordinals, func(i, j int) bool { return ordinals[i] < ordinals[j] })

	baseline := ctx.Route.Obs().Body

	// 2. Drift. The post-baseline disagreeing with the pre-baseline means the slot moved under the
	// probes, and every differential taken across that window is about the drift.
	if ctx.PostBaseline.Resolved() && ctx.Route.Resolved() {
		pre, post := ctx.Route.Obs(), ctx.PostBaseline.Obs()
		if pre.Status != post.Status {
			return eliOne(key, triage.StateCannotDetermine,
				fmt.Sprintf("drift: the endpoint answered %d before the probes and %d after, so nothing measured "+
					"in between is attributable to a payload", pre.Status, post.Status), ordinals, "")
		}
	}

	// 3. A control that fired means the detector was never shown staying silent on this slot, and
	// every verdict here becomes an unknown. This outranks a hit: a detector that fires on its own
	// inert echo has not detected anything.
	if ctl, fired := eliFiredControl(owned, baseline); fired {
		return eliOne(key, triage.StateCannotDetermine,
			"detector_unverified: negative control "+string(ctl.Probe)+" fired "+ctl.Oracle+
				", so this class's detector is matching something other than a computed answer on this slot and "+
				"none of its other rows here can be trusted", ordinals, "")
	}

	// 4. The two silent killers of CATALOGUE 1.2, asserted BEFORE any result is scored. A failed
	// assertion is a loud runner bug, never a finding and never a clean: a %{ probe whose percent
	// went out raw produces a 400 on every request, which reads as a WAF block when in fact the
	// slot was never tested.
	if bad, why := eliWireAssertionFailed(ctx.Slot, owned); bad != "" {
		return eliOne(key, triage.StateCannotDetermine,
			"runner_bug: "+string(bad)+" "+why, ordinals, "")
	}

	// 5. The bare-expression probes must reach the wire WITHOUT a marker. If one did not, it tested
	// a parse error rather than a sink, and the single most commonly missed EL sink is untested.
	if bad := eliBareProbeCarriedAMarker(owned); bad != "" {
		return eliOne(key, triage.StateCannotDetermine,
			"bare_expression_marker_attached: "+string(bad)+" went out with a marker in its bytes. A 16-byte prefix "+
				"makes the value <marker>1*(...), which is a parse error in every dialect, so the bare-expression "+
				"sink was not tested at all. The runner must honour Variant[\"marker_placement\"]=\"omitted\"",
			ordinals, "")
	}

	// 6. Uniform block, computed from THIS class's own payloads only (foundations 5.8).
	if eliUniformBlock(owned, baseline) {
		return eliOne(key, triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct payloads produced byte-identical responses that "+
				"differ from the baseline, which is a filter answering rather than the application", ordinals, "")
	}

	// 7. The oracles, strongest first.
	hits := eliScoreAll(owned, baseline)

	if h, ok := eliPick(hits, eliOracleOverflow); ok {
		confirmed := eliConfirmedOverflow(owned, baseline)
		grade := triage.GradeHigh
		state := triage.StateFinding
		why := "el_overflow: the int32 wrap " + eliWrapped + " appeared adjacent to this probe's own marker, the " +
			"answer was absent from the baseline and absent from the bytes sent"
		switch {
		case !confirmed:
			state, grade = triage.StateSuspicious, triage.GradeMedium
			why += ", but the fresh-operand confirmation did not reproduce it, so it is not promoted to a finding"
		case !h.Anchored:
			// EL6 has no marker by construction, so it can never reach high. CATALOGUE 4.2.
			grade = triage.GradeMedium
			why = "el_overflow at a BARE expression sink: " + eliWrapped + " appeared with no marker anchor " +
				"(the probe carries none by construction), absent from baseline and from the wire, reproduced " +
				"with fresh operands. Capped at medium because attribution rests on the probe ordinal alone"
		}
		return eliFinding(key, state, grade, eliOracleOverflow, why, ordinals, h, eliDialect(hits, owned, baseline))
	}

	if h, ok := eliPick(hits, eliOracleString); ok {
		state, grade := triage.StateFinding, triage.GradeHigh
		why := "el_string: 'qmkvbnkw'.replace('k','7') returned " + eliStrAnswer + " adjacent to this probe's own " +
			"marker, absent from baseline and from the wire. A method resolved and ran, which is an expression " +
			"evaluator and not a formatter"
		if !eliWasSentIn(owned, eliProbeELS3) {
			state, grade = triage.StateSuspicious, triage.GradeMedium
			why += ". The second-method confirmation (toUpperCase) was not sent, so a narrow-API interpolator is " +
				"not yet ruled out"
		}
		return eliFinding(key, state, grade, eliOracleString, why, ordinals, h, eliDialect(hits, owned, baseline))
	}

	if h, ok := eliPick(hits, eliOracleGrouped); ok {
		return eliFinding(key, triage.StateSuspicious, triage.GradeMedium, eliOracleGrouped,
			"el_overflow, locale-grouped: "+eliGrouped+" appeared adjacent to the marker. Standard EL output goes "+
				"through Integer.toString and does not group, so the value passed through a formatter as well and "+
				"the chain is less certain. Suspicious, not a finding",
			ordinals, h, eliDialect(hits, owned, baseline))
	}

	if h, ok := eliPick(hits, eliOraclePartial); ok {
		return eliFinding(key, triage.StateSuspicious, triage.GradeMedium, eliOraclePartial,
			"el_string_partial: "+eliStrPartial+" came back, which is one of the two replacements applied. That is "+
				"replaceFirst semantics, so a method ran but not the one asked for, and the result is reported as "+
				"its own weaker state rather than rounded up to the finding",
			ordinals, h, eliDialect(hits, owned, baseline))
	}

	if h, ok := eliPick(hits, eliOracleUnwrapped); ok {
		return eliFinding(key, triage.StateSuspicious, triage.GradeMedium, eliOracleUnwrapped,
			"el_overflow_unwrapped: the answer came back as "+eliUnwrapped+", which is arbitrary-precision or long "+
				"arithmetic and NOT a Java 32-bit int. Something evaluated the expression; it was not a JVM EL "+
				"engine, so this class refuses to claim the dialect. A non-JVM evaluator that computed arithmetic "+
				"is a template-engine finding and SSTI's own probes are what must establish it",
			ordinals, h, "")
	}

	if h, ok := eliPick(hits, eliOracleError); ok {
		return eliFinding(key, triage.StateSuspicious, triage.GradeMedium, eliOracleError,
			"parsed_not_evaluated: the response carries "+h.Phrase+", a "+h.Dialect+" exception absent from the "+
				"baseline, so an expression parser saw the payload and refused it. Neither computation oracle fired, "+
				"so evaluation is not established. Still worth pointing the tool at: the parser is reachable",
			ordinals, h, h.Dialect)
	}

	// 8. Nothing fired. Now the question is whether this class is entitled to say clean, and the
	// default answer is no.
	if reason, ok := eliCleanBlocked(ctx, owned); !ok {
		return eliOne(key, triage.StateCannotDetermine, reason, ordinals, "")
	}

	v := eliOne(key, triage.StateClean,
		"clean: this class's own probes reached the wire with their payloads proven intact, its bare marker came "+
			"back so the slot demonstrably reflects, all three independent oracle arms (int32 overflow, string "+
			"method, dialect error signature) ran, and every one of them stayed silent",
		ordinals, "")
	v[0].Label = triage.TriageLabel{
		Tools: []string{"nuclei-dast"},
		Hints: map[string]string{
			"why_a_tool_still": "the parameter-name OGNL sink is structurally untested here, so the Struts template " +
				"set is still worth a pass even on a clean row",
		},
	}
	return v
}

// eliCleanBlocked lists every reason this class may NOT say clean, each with the sentence that
// goes on the verdict. The list is the class's honesty, so it is written out rather than folded
// into one boolean.
func eliCleanBlocked(ctx triage.ClassifyCtx, owned []eliOwn) (string, bool) {
	// The census probe has to have come back. A marker that did not come back is only clean when
	// you can show the request arrived and the field was wide enough; otherwise the class has no
	// evidence the sink was ever handed the bytes.
	census, sent := eliFind(owned, eliProbeCensus)
	if !sent {
		return "census_not_sent: this class's own reflection census never went out, so there is no evidence the " +
			"slot reflects anything and no basis for reading a silent oracle as a silent application", false
	}
	if !census.Obs.Delivered() {
		return "transport_refused (" + string(census.Obs.TransportErr) + "): the census request did not reach the " +
			"application, so nothing about this slot was measured", false
	}
	if !eliMarkerCameBack(census) {
		return "no_reflection: this class's own bare marker came back ABSENT in every transform form, so both " +
			"computation oracles are structurally blind here. This class has no out-of-band payload and no timing " +
			"oracle, so a fully blind EL sink is honestly undecidable and is NOT clean", false
	}

	// Every probe that went out has to have gone out intact. WireSurvivalUnknown is not survived.
	for _, o := range owned {
		if !o.Obs.Delivered() {
			return "transport_refused (" + string(o.Obs.TransportErr) + ") on " + string(o.Probe) +
				": a refusal at send time is could-not-send and is never a quiet response", false
		}
		if !o.Obs.Payload.Survived.Proven() {
			return "payload_not_proven_on_wire: " + string(o.Probe) + " recorded survival " +
				string(o.Obs.Payload.Survived) + " (" + o.Obs.Payload.Describe() + "). Go's cookie sanitizer " +
				"silently drops the double quote, the backslash and the semicolon, and an unproven payload is " +
				"indistinguishable after the fact from a payload the application defended against", false
		}
	}

	// All three arms, or it is not a statement about the class.
	arms := map[eliArm]bool{}
	for _, o := range owned {
		if a := eliArmOf(o.Probe); a != "" {
			arms[a] = true
		}
	}
	for _, want := range []eliArm{eliArmOverflow, eliArmString, eliArmError} {
		if !arms[want] {
			return "arm_not_delivered (" + string(want) + "): the three oracle arms fail for different reasons (a " +
				"method allow-list on valueOf kills the overflow arm and leaves the string arm; a WAF rule on " +
				".replace( does the reverse), so a silence from the arms that did run is not a silence from this " +
				"class", false
		}
	}

	// A canary-valued slot is a probe at a resource that does not exist, and a tool pointed at a
	// 404 that finds nothing is not a clean scan of the endpoint.
	switch ctx.Slot.ValueOrigin {
	case triage.ValueCanary:
		return "canary_resource: the slot's value was fabricated because the capture carried none and the evidence " +
			"URL could not supply one, so every probe landed on a resource that does not exist", false
	case triage.ValueSynthesized:
		return "synthesized_value: the slot's value was invented rather than observed, so the route the probes took " +
			"through the application is not the route a real request takes", false
	}

	if !ctx.Baseline.Stable {
		return "endpoint_not_stable (" + eliGateReason(ctx.Baseline) + "): the baseline model did not pass its " +
			"stability gate, so a silent oracle cannot be separated from an endpoint that changes on its own", false
	}
	return "", true
}

func eliGateReason(b triage.BaselineModel) string {
	if b.GateReason == "" {
		if b.Samples == 0 {
			return "no_model"
		}
		return "unnamed"
	}
	return b.GateReason
}

// eliMarkerCameBack asks the reflection question through the runner's own marker search first,
// because that search covers the encoded transform forms (NCR, percent, base64 at three
// alignments, UTF-16LE) that a raw substring scan in this file cannot see. The raw scan is the
// fallback for an observation whose projections were never filled in.
func eliMarkerCameBack(o eliOwn) bool {
	for _, h := range o.Obs.Proj.MarkerHits {
		if h.Marker.BelongsTo(triage.ClassELI) {
			return true
		}
	}
	for _, hay := range eliHaystacks(o.Obs) {
		if len(eliFindMarker(hay, o.Marker)) > 0 {
			return true
		}
	}
	return false
}

func eliFind(owned []eliOwn, id triage.ProbeID) (eliOwn, bool) {
	for _, o := range owned {
		if o.Probe == id {
			return o, true
		}
	}
	return eliOwn{}, false
}

func eliWasSentIn(owned []eliOwn, id triage.ProbeID) bool {
	_, ok := eliFind(owned, id)
	return ok
}

// eliScoreAll runs every rule over every own observation. Controls are excluded here: they are
// scored separately by eliFiredControl, and a control that fires voids the slot rather than
// contributing a hit.
func eliScoreAll(owned []eliOwn, baseline []byte) []eliHit {
	var out []eliHit
	for _, o := range owned {
		if eliIsControlProbe(o.Probe) {
			continue
		}
		answer := eliWrapped
		if eliIsConfirmProbe(o.Probe) {
			answer = eliWrapped2
		}
		marker := o.Marker
		if eliIsBareProbe(o.Probe) {
			marker = ""
		}
		if h, ok := eliMatchOverflow(o.Obs, marker, answer, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			out = append(out, h)
		}
		if h, ok := eliMatchString(o.Obs, o.Marker, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			out = append(out, h)
		}
		if h, ok := eliMatchUnwrapped(o.Obs, o.Marker, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			out = append(out, h)
		}
		if h, ok := eliMatchError(o.Obs, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			out = append(out, h)
		}
	}
	return out
}

func eliPick(hits []eliHit, oracle string) (eliHit, bool) {
	for _, h := range hits {
		if h.Oracle == oracle {
			return h, true
		}
	}
	return eliHit{}, false
}

// eliConfirmedOverflow requires a CONFIRMATION probe, which carries fresh operands, to have
// produced its own different answer. A confirmation that reproduces the FIRST answer is a cached
// body, not a reproduction, which is why the operands change rather than only the marker.
func eliConfirmedOverflow(owned []eliOwn, baseline []byte) bool {
	for _, o := range owned {
		if !eliIsConfirmProbe(o.Probe) {
			continue
		}
		marker := o.Marker
		if eliIsBareProbe(o.Probe) {
			marker = ""
		}
		if _, ok := eliMatchOverflow(o.Obs, marker, eliWrapped2, baseline); ok {
			return true
		}
	}
	return false
}

// eliDialect resolves the dialect from, in order: an error signature that named one, then which
// identification body evaluated. Neither available leaves jvm_el_unidentified, which is still a
// usable label because sstimap's java_el_generic plugin takes it.
func eliDialect(hits []eliHit, owned []eliOwn, baseline []byte) string {
	for _, h := range hits {
		if h.Oracle == eliOracleError && h.Dialect != "" {
			return h.Dialect
		}
	}
	for _, o := range owned {
		switch o.Probe {
		case eliProbeIDSpelDollar, eliProbeIDSpelAt, eliProbeIDSpelBare:
			m := o.Marker
			if o.Probe == eliProbeIDSpelBare {
				m = ""
			}
			if _, ok := eliMatchOverflow(o.Obs, m, eliWrapped, baseline); ok {
				return "spel"
			}
		case eliProbeIDOgnlDollar, eliProbeIDOgnlAt, eliProbeIDOgnlBare:
			m := o.Marker
			if o.Probe == eliProbeIDOgnlBare {
				m = ""
			}
			if _, ok := eliMatchOverflow(o.Obs, m, eliWrapped, baseline); ok {
				return "ognl"
			}
		}
	}
	for _, o := range owned {
		if o.Probe == eliProbeEL5 {
			if _, ok := eliMatchOverflow(o.Obs, o.Marker, eliWrapped, baseline); ok {
				return "mvel"
			}
		}
	}
	return "jvm_el_unidentified"
}

func eliIsControlProbe(id triage.ProbeID) bool {
	switch id {
	case eliProbeNC1, eliProbeNC2, eliProbeNC3, eliProbeNC4, eliProbeNC5a, eliProbeNC5b, eliProbeNC5c:
		return true
	}
	return false
}

func eliIsConfirmProbe(id triage.ProbeID) bool {
	switch id {
	case eliProbeCF1, eliProbeCF2, eliProbeCF3, eliProbeCF4, eliProbeCF5,
		eliProbeCF6, eliProbeCF6m, eliProbeCF7, eliProbeCF8:
		return true
	}
	return false
}

func eliIsBareProbe(id triage.ProbeID) bool {
	switch id {
	case eliProbeEL6, eliProbeCF6, eliProbeIDSpelBare, eliProbeIDOgnlBare:
		return true
	}
	return false
}

// eliFiredControl scores the negative controls. NC2, NC3 and NC4 send the answers as literal text,
// so the regex WILL match them and the answer_not_in_wire guard is what must suppress it; that is
// the property being verified, and it is the guard and not the regex that stops every echoing
// endpoint reading as a finding.
//
// NC5a, NC5b and NC5c are empty expressions. An ERROR from one of them is a legitimate E-D3 hit and
// is deliberately NOT treated as a control failure.
func eliFiredControl(owned []eliOwn, baseline []byte) (eliHit, bool) {
	for _, o := range owned {
		if !eliIsControlProbe(o.Probe) {
			continue
		}
		if h, ok := eliMatchOverflow(o.Obs, o.Marker, eliWrapped, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			return h, true
		}
		if h, ok := eliMatchString(o.Obs, o.Marker, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			return h, true
		}
		if h, ok := eliMatchUnwrapped(o.Obs, o.Marker, baseline); ok {
			h.Probe, h.Ordinal = o.Probe, o.Ordinal
			return h, true
		}
	}
	return eliHit{}, false
}

// eliWireAssertionFailed is the two silent killers of CATALOGUE 1.2, checked against what actually
// went out rather than against what the encoder believes it produced.
//
//	%  must be %25 on query, form and path. Go's QueryUnescape errors on %{, Java's URLDecoder
//	   throws, and the 400 that results looks exactly like a WAF block on every probe.
//	+  must be %2B on query and form, and must stay LITERAL on a path. Unencoded on a query it
//	   decodes to SPACE and the expression becomes 1900000000 1900000000, which is a parse error,
//	   and the class then records an error where it should have recorded an evaluation.
func eliWireAssertionFailed(slot triage.Slot, owned []eliOwn) (triage.ProbeID, string) {
	needsEscaping := slot.Kind == triage.KindQuery || slot.Kind == triage.KindPath ||
		(slot.Kind == triage.KindBody && slot.BodyMedia == triage.BodyForm)
	if !needsEscaping {
		return "", ""
	}
	for _, o := range owned {
		w := o.Obs.Payload.Wire
		if len(w) == 0 {
			continue
		}
		if bytes.Contains(w, []byte("%{")) {
			return o.Probe, "went out with a RAW %{ on a " + string(slot.Kind) + " slot. Go's QueryUnescape " +
				"errors on it, Java's URLDecoder throws, and the resulting 400 on every probe reads as a WAF " +
				"block when in fact nothing was tested. The percent must be %25 here"
		}
		// Every + in every ELI payload is the addition operator, so on a query or form slot a raw
		// + anywhere in the payload's wire bytes is the bug. Matching the literal
		// "1900000000+1900000000" would have been the obvious check and it is wrong: the generic
		// body renders as valueOf('1900000000')+1900000000, so the two operands are never adjacent
		// and the check would have passed on the exact payload it exists to protect.
		if slot.Kind != triage.KindPath && bytes.IndexByte(w, '+') >= 0 {
			return o.Probe, "went out with a RAW + on a " + string(slot.Kind) + " slot. PHP, " +
				"Python parse_qs, Go ParseQuery, Java and Rails all decode that to SPACE, so the expression " +
				"arrives as two integers separated by a space and every dialect answers with a parse error. " +
				"The plus must be %2B here"
		}
	}
	return "", ""
}

// eliBareProbeCarriedAMarker verifies the one thing no type in the layer can express: that the two
// bare-expression probes went out with no marker attached.
func eliBareProbeCarriedAMarker(owned []eliOwn) triage.ProbeID {
	for _, o := range owned {
		if !eliIsBareProbe(o.Probe) {
			continue
		}
		if o.Marker == "" {
			continue
		}
		for _, w := range [][]byte{o.Obs.Payload.Logical, o.Obs.Payload.Wire} {
			if len(eliFindMarker(w, o.Marker)) > 0 {
				return o.Probe
			}
		}
	}
	return ""
}

// eliUniformBlock is foundations 5.8 over THIS CLASS'S OWN payloads only. Three or more distinct
// payloads producing byte-identical responses that DIFFER FROM THE BASELINE is a filter answering,
// not the application.
//
// TWO DETAILS THAT ARE THE WHOLE CHECK. It returns false outright when there is no baseline in
// hand, because without one "three identical responses" is indistinguishable from a stable page
// answering three probes the same way, and calling that a block would turn every quiet endpoint
// into an unknown. And it keys on the BODY BYTES rather than on BodySHA256: the SHA is filled in
// at capture and its zero value is a real 32-byte key, so an observation whose SHA was never
// computed would group with every other one and manufacture a block out of nothing.
func eliUniformBlock(owned []eliOwn, baseline []byte) bool {
	if len(baseline) == 0 {
		return false
	}
	counts := map[string]int{}
	for _, o := range owned {
		if o.Probe == eliProbeCensus || o.Probe == eliProbeDecode {
			continue
		}
		if len(o.Obs.Body) == 0 {
			continue
		}
		if bytes.Equal(o.Obs.Body, baseline) {
			continue
		}
		counts[string(o.Obs.Body)]++
	}
	for _, n := range counts {
		if n >= 3 {
			return true
		}
	}
	return false
}

// eliOne builds the single verdict this class emits per slot. Every row, clean included, carries
// the two structural gaps in Untested.
func eliOne(key triage.SlotKey, st triage.TriageState, reason string, ordinals []uint64, dialect string) []triage.ClassVerdict {
	v := triage.ClassVerdict{
		Class:    triage.ClassELI,
		SlotKey:  key,
		State:    st,
		Reason:   reason,
		Ordinals: ordinals,
		Untested: eliUntestedAlways(),
		Annotations: map[string]any{
			"class_arms":         []string{string(eliArmOverflow), string(eliArmString), string(eliArmError)},
			"oob_oracle_exists":  false,
			"timing_oracle_used": false,
		},
	}
	if dialect != "" {
		v.Label.Dialect = dialect
	}
	return []triage.ClassVerdict{v}
}

// eliFinding builds a positive verdict with its evidence and the tool label. The label is the whole
// point of this layer: "point sstimap at this slot with THIS engine plugin" is worth more than the
// verdict word.
func eliFinding(key triage.SlotKey, st triage.TriageState, grade triage.TriageGrade, oracle, reason string,
	ordinals []uint64, h eliHit, dialect string) []triage.ClassVerdict {
	v := eliOne(key, st, reason, ordinals, dialect)
	v[0].Grade = grade
	v[0].Oracle = oracle
	v[0].Evidence = triage.TriageEvidence{
		Ordinal: h.Ordinal,
		Matched: h.Matched,
		Offset:  h.Offset,
		Length:  len(h.Matched),
		Phrase:  h.Phrase,
	}
	v[0].Label = eliLabelFor(dialect, oracle, h.Probe)
	return v
}

// eliLabelFor is CATALOGUE 1.0's tools column, resolved per dialect. Where no tool has a plugin for
// the dialect the label SAYS SO rather than pointing at a tool with nothing for it, because a tool
// run that was never going to find anything and then finds nothing is the exact shape of a false
// clean one layer down.
func eliLabelFor(dialect, oracle string, probe triage.ProbeID) triage.TriageLabel {
	l := triage.TriageLabel{Dialect: dialect, Engine: "jvm_el", Hints: map[string]string{}}
	switch dialect {
	case "ognl":
		l.Tools = []string{"sstimap", "nuclei-dast"}
		l.Hints["sstimap_engine"] = "ognl"
		l.Hints["nuclei_templates"] = "struts"
	case "spel":
		l.Tools = []string{"sstimap", "nuclei-dast"}
		l.Hints["sstimap_engine"] = "spring_el"
	case "juel", "jakarta_el":
		l.Tools = []string{"sstimap"}
		l.Hints["sstimap_engine"] = "java_el_generic"
	case "mvel":
		l.Tools = []string{"nuclei-dast"}
		l.Hints["no_plugin"] = "sstimap ships no MVEL plugin, so this needs nuclei-dast and a manual session. " +
			"Saying so beats naming a tool that has nothing for the dialect"
	default:
		l.Tools = []string{"sstimap", "nuclei-dast"}
		l.Hints["sstimap_engine"] = "java_el_generic"
		l.Hints["then_try"] = "ognl, spring_el"
	}
	l.Hints["oracle"] = oracle
	l.Hints["delimiter"] = eliDelimiterOf(probe)
	l.Hints["probe"] = string(probe)
	return l
}

func eliDelimiterOf(id triage.ProbeID) string {
	switch id {
	case eliProbeEL1, eliProbeELS1, eliProbeELE, eliProbeCF1, eliProbeELS3,
		eliProbeIDSpelDollar, eliProbeIDOgnlDollar, eliProbeJVM:
		return "${}"
	case eliProbeEL2, eliProbeCF2:
		return "#{}"
	case eliProbeEL3, eliProbeELS2, eliProbeCF3:
		return "%{}"
	case eliProbeEL4, eliProbeCF4:
		return "*{}"
	case eliProbeEL5, eliProbeCF5, eliProbeIDSpelAt, eliProbeIDOgnlAt:
		return "@{}"
	case eliProbeEL7, eliProbeCF7:
		return "__${}__"
	case eliProbeEL8, eliProbeCF8:
		return "${{}}"
	case eliProbeEL6, eliProbeEL6m, eliProbeCF6, eliProbeCF6m, eliProbeIDSpelBare, eliProbeIDOgnlBare:
		return "bare"
	}
	return ""
}

// -------------------------------------------------------------------------------------------
// 8. THE DECLARATIONS THE ORACLE PASS AND THE REPORT READ
// -------------------------------------------------------------------------------------------
//
// Confirmers, Evidencers and OracleCases are NOT on the triage.Classifier interface; the interface
// is ID, Probes, Reaches, Plan and Classify and nothing else. They are declared here as this
// class's own types, with class-prefixed names, so that twenty-six sibling files in the same
// package can each declare their own without colliding. When the layer grows a shared vocabulary
// for them, these move to it unchanged in content.

// eliConfirmer is one row of iso-eval ELI 3: what fired, what is sent next, what that confirms and
// what it downgrades to when it does not reproduce.
type eliConfirmer struct {
	After      triage.ProbeID
	Send       []triage.ProbeID
	Confirms   string
	Downgrades string
}

func (eliClassifier) Confirmers() []eliConfirmer {
	return []eliConfirmer{
		{
			After: eliProbeEL1, Send: []triage.ProbeID{eliProbeCF1, eliProbeIDSpelDollar, eliProbeIDOgnlDollar},
			Confirms: "the SAME delimiter with fresh operands 1800000000+1800000000 expecting " + eliWrapped2 +
				", so a reproduction cannot be a cached copy of the first response; then the two identification " +
				"bodies, whichever fires names the dialect in one step",
			Downgrades: "the OLD answer coming back is a cached body: cannot_determine (stale_marker). No answer " +
				"at all: suspicious, because one measurement is not a measurement",
		},
		{
			After: eliProbeEL6, Send: []triage.ProbeID{eliProbeCF6, eliProbeIDSpelBare, eliProbeIDOgnlBare},
			Confirms:   "the bare sink with fresh operands. Never reaches high: the probe carries no marker anchor",
			Downgrades: "no reproduction: suspicious at medium",
		},
		{
			After: eliProbeELS1, Send: []triage.ProbeID{eliProbeELS3},
			Confirms: "a SECOND, different method resolving (toUpperCase returning " + eliStrUpper + "). Two " +
				"distinct method invocations is an expression evaluator",
			Downgrades: "only replace() working is a String.format or a message interpolator with a narrow API: " +
				"suspicious (limited_api)",
		},
		{
			After: eliProbeELE, Send: []triage.ProbeID{eliProbeCF1},
			Confirms:   "the computation probe for the dialect the error named; a hit upgrades suspicious to finding",
			Downgrades: "nothing fires: the parser saw the expression and refused it, suspicious (parsed_not_evaluated)",
		},
		{
			After: eliProbeEL2, Send: []triage.ProbeID{eliProbeCF2},
			Confirms:   "SpEL through #{} with fresh operands. No identification probes needed: T( already named it",
			Downgrades: "no reproduction: suspicious",
		},
	}
}

// eliEvidencer is one oracle this class owns: its rank, the grade a clean fire earns, and the
// sentence that goes in front of the operator.
type eliEvidencer struct {
	Oracle string
	Rank   int
	Grade  triage.TriageGrade
	What   string
}

func (eliClassifier) Evidencers() []eliEvidencer {
	return []eliEvidencer{
		{eliOracleOverflow, 1, triage.GradeHigh,
			"deterministic computation AND a type-system proof in one request: " + eliWrapped + " is " +
				eliOperand + "+" + eliOperand + " only in Java 32-bit signed int arithmetic"},
		{eliOracleString, 1, triage.GradeHigh,
			"method invocation: 'qmkvbnkw'.replace('k','7') returning " + eliStrAnswer + ". Independent of the " +
				"arithmetic and survives a valueOf allow-list"},
		{eliOracleGrouped, 1, triage.GradeMedium,
			"the same answer rendered with locale grouping, which means a formatter sat in the chain. Capped at " +
				"suspicious because standard EL output does not group"},
		{eliOraclePartial, 1, triage.GradeMedium,
			"one of two replacements applied, which is replaceFirst semantics: a method ran, not the one asked for"},
		{eliOracleUnwrapped, 1, triage.GradeMedium,
			"arithmetic evaluated but NOT in a Java int (" + eliUnwrapped + "). Something is an evaluator and it " +
				"is not a JVM EL engine, so this class refuses to claim it"},
		{eliOracleError, 4, triage.GradeMedium,
			"a dialect-naming exception absent from the baseline. Rank 4 because it proves the parser was reached " +
				"and not that the expression evaluated, and it is baseline-differenced because a Struts devMode " +
				"application prints a Problem Report on every bad request including the baseline's"},
	}
}

// eliOracleCase is one route in the oracle control set, CATALOGUE 6.1. Expect is "positive" when
// this class MUST fire there and "negative" when it MUST stay silent.
//
// THE NEGATIVE ROUTES ARE THE ONES THAT ACTUALLY TEST THE DETECTOR. A detector that fires on every
// route scores one hundred per cent and is worthless. CATALOGUE 6.1's own note on this class is
// blunt about the current state of the rig: ELI has NO positive control today, so its detectors
// have only ever been observed staying silent, which is exactly as unverified as only ever being
// observed firing.
type eliOracleCase struct {
	Route  string
	Expect string
	Probes []triage.ProbeID
	Why    string
}

func (eliClassifier) OracleCases() []eliOracleCase {
	return []eliOracleCase{
		{
			Route: "/eli", Expect: "positive",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeEL6, eliProbeELS1, eliProbeCF1},
			Why: "MISSING AND REQUIRED. A closed grammar that recognises 1*((1).valueOf('<int>')+<int>), computes " +
				"the sum in int32 and renders it WRAPPED, and recognises '<tok>'.replace('<a>','<b>'). No evaluator, " +
				"no reflection: it is a string rewrite over two integers and one method name, in the same spirit as " +
				"the existing /ssti handler. Without it this class's detectors have never been seen firing",
		},
		{
			Route: "/eli/spel", Expect: "positive",
			Probes: []triage.ProbeID{eliProbeEL2, eliProbeIDSpelDollar},
			Why: "the same grammar extended with T(java.lang.Integer).valueOf, so the SpEL identification arm is " +
				"exercised independently of the generic one and the dialect label is tested rather than assumed",
		},
		{
			Route: "/eli/ognl", Expect: "positive",
			Probes: []triage.ProbeID{eliProbeEL3, eliProbeELS2, eliProbeIDOgnlDollar},
			Why: "the same grammar extended with @java.lang.Integer@valueOf, reached through %{ }. It must be " +
				"exercised over a HEADER and a COOKIE slot as well as a query slot, because the %25 rule is this " +
				"class's most likely silent failure and the header and cookie paths are the ones that do not depend " +
				"on the encoder getting it right",
		},
		{
			Route: "/eli/longmath", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeCF1},
			Why: "MISSING AND REQUIRED, and it is the most valuable negative in the set. The same grammar computing " +
				"in a 64-bit long, so the response carries " + eliUnwrapped + " and NOT " + eliWrapped + ". The " +
				"verdict must be suspicious (el_overflow_unwrapped) and must NOT be a finding. An implementation " +
				"that only looks for the wrapped answer records CLEAN on a real long-typed JVM EL sink, and an " +
				"implementation that accepts either records a finding it cannot support",
		},
		{
			Route: "/eli/echo", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeNC2, eliProbeNC3, eliProbeNC4},
			Why: "an endpoint that echoes the parameter verbatim. NC2, NC3 and NC4 send the answers as literal text, " +
				"so the adjacency regex WILL match and the answer_not_in_wire guard is the only thing that suppresses " +
				"it. This route verifies the GUARD, and the guard is what stops every echoing endpoint in the world " +
				"reading as an ELI finding",
		},
		{
			Route: "/eli/hardened", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeEL2, eliProbeEL3, eliProbeELS1, eliProbeELE},
			Why: "MISSING AND REQUIRED. An endpoint that reflects the payload verbatim with no evaluator anywhere. " +
				"Every probe must stay silent AND the verdict must be clean with ordinals, not cannot_determine: " +
				"this is the route that proves this class can reach a legitimate clean at all, which is the half " +
				"of the contract a fire-only rig never tests",
		},
		{
			Route: "/ssti", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeEL2, eliProbeEL4, eliProbeELS1},
			Why: "EXISTS TODAY. FreeMarker only, no EL evaluator, so every ELI probe correctly returns nothing. It " +
				"is a real negative and it is currently the ONLY control this class has, which is the gap /eli fills",
		},
		{
			Route: "/clean/echo", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeELS1, eliProbeELE},
			Why:    "EXISTS TODAY. Reflection is not injection, and this is where that is proven for this class",
		},
		{
			Route: "/clean/dberror", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeELE},
			Why: "EXISTS TODAY. A baseline that always carries an exception. No ELI signature is present, so the " +
				"error oracle must stay silent, and a response that differs from baseline with none of this class's " +
				"own signatures is cannot_determine (unattributed_error), which is ruling R1's replacement state",
		},
		{
			Route: "/clean/waf", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeEL3, eliProbeELS1},
			Why: "EXISTS TODAY. An identical 403 to every payload. Three of THIS class's own distinct payloads must " +
				"reach uniform_block and the verdict must be cannot_determine (blocked), never clean",
		},
		{
			Route: "/eli/devmode", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeELE},
			Why: "MISSING AND REQUIRED. A baseline that already carries 'Struts Problem Report' on every request, " +
				"which is what struts.devMode=true does. The signature must be disabled for that endpoint by " +
				"baseline differencing while the other OGNL signatures stay live. Without this route the class " +
				"reports a finding on every slot of every devMode application forever",
		},
		{
			Route: "fixture: a response body carrying SSTI's own expected answer", Expect: "negative",
			Probes: []triage.ProbeID{eliProbeEL1, eliProbeELS1},
			Why: "CATALOGUE 1.2 NC6, and it is a FIXTURE and not a probe on purpose: the body has to contain another " +
				"class's marker, and a ProbeSpec carrying one fails isolation check I1d at build time. It asserts " +
				"that the two classes' expected answers are provably disjoint. It lives in eli_test.go",
		},
	}
}

// Settle is the no-op. This class has NO deferred out-of-band check to make, because it has no
// out-of-band payload at all: there is no callback, no collaborator subdomain, no delayed
// read-back sweep and no stored write. That is also why a fully blind EL sink (no reflection,
// exceptions swallowed) is honestly cannot_determine (no_reflection) here and not clean, and the
// absence is declared as a method rather than left as a silence.
func (eliClassifier) Settle(triage.ClassifyCtx) []triage.ProbeRequest { return nil }
