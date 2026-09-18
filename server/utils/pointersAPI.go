package utils

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jackc/pgx/v5"

	"ars0n-framework-v2-server/utils/triage"
)

// THE POINTER LAYER. Several evidence sources in, one ranked list of "spend an hour here" out.
//
// A POINTER IS NOT A FINDING. A finding says "this is vulnerable". A pointer says "there is
// evidence this vector MAY be vulnerable to this attack class, so it is worth testing deeply", and
// it names WHICH tool to point at it. It exists because the framework ships 31 confirmation
// scanners and sqlmap alone spends around 1690 requests on ONE vector: nobody can run everything
// on everything, so something has to choose, and the choice has to be explainable.
//
// =================================================================================================
// THE RULE THIS FILE IS BUILT AROUND: ABSENCE OF A POINTER IS NOT ABSENCE OF RISK
// =================================================================================================
//
// MEASURED on the engaged corpus, 2026-09-18: 1764 reflection probe rows, of which 34 are
// reflected_observed, 16 are not_reflected, and 1714 are unknown (1555 is_credential, 110 error,
// 49 probe_refused). A screen that lists 34 pointers and says nothing else invites the reading
// "the other vectors are fine", which is false and is exactly the false negative this layer exists
// to prevent. So Coverage is returned on EVERY response, never behind a filter and never behind a
// toggle, and it is computed over the WHOLE corpus.
//
// THE COUNTS ARE COMPUTED BEFORE THE FILTER IS APPLIED, for the same reason. This was caught in
// review once already on the reflection panel: "0 blocked while filtered to XSS High is not a fact
// about the target". So `count` is the filtered list length, `total` is the corpus, and every map
// under `counts` is over everything.
//
// NOTHING IS RE-DERIVED HERE. The XSS grade comes from XSSCandidateGrade, the evidence ranking from
// EvidenceRank, the delivery half of severity from ReflectionInsertionPointDeliverable and
// FindingDeliveryNote, the unproven-payload gate from triageUnprovenFidelity, and the attack class
// vocabulary from triage.ClassID. A second copy of any of them is how this codebase got two screens
// disagreeing about the same row.

// ---------------------------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------------------------

// The three sources that can produce a pointer today. Carried on every pointer, because the
// operator cannot judge a pointer without knowing where it came from.
const (
	// PointerSourceReflection is the reflection probe: vector_reflection_probes.
	PointerSourceReflection = "reflection_probe"
	// PointerSourceFinding is a vector_findings row a tool wrote on an earlier scan.
	PointerSourceFinding = "vector_finding"
	// PointerSourceTriage is a triage_verdicts row, written by the Investigate triage run.
	//
	// WHETHER THIS SOURCE HAS ANYTHING TO SAY IS A FACT ABOUT THE DATA, never a claim made here.
	// PointerTriageCoverage derives it from triage_runs and triage_verdicts and says so on every
	// response. This comment used to read "empty today: the triage runner is built and not yet
	// wired", and it stayed that way after the runner was wired, which is how a screen comes to
	// tell an operator with real verdicts that their triage results do not exist. A sentence that
	// has to be edited when the system changes is a sentence that will be wrong, and wrong here
	// means a false negative.
	PointerSourceTriage = "triage_verdict"
)

// Pointer strength NAMES THE EVIDENCE rather than grading it on an invented scale.
//
// "delta_checked" against "passive_echo" is a fact about what was done. "high" against "low" would
// be this file's opinion, and the operator cannot audit an opinion. The order is EvidenceRank's,
// which is the one ranking in the codebase, so these labels cannot drift away from the sort.
const (
	PointerStrengthDeltaChecked  = "delta_checked"  // EvidenceRank 5
	PointerStrengthToolReported  = "tool_reported"  // EvidenceRank 4
	PointerStrengthProbeObserved = "probe_observed" // EvidenceRank 3
	PointerStrengthPriorFinding  = "prior_finding"  // EvidenceRank 2
	PointerStrengthPassiveEcho   = "passive_echo"   // EvidenceRank 1
	PointerStrengthUnattributed  = "unattributed"   // EvidenceRank 0
)

// PointerStrengthOrder is the strength vocabulary most-worth-an-hour first, as data, so the client
// reads the order rather than re-typing it.
func PointerStrengthOrder() []string {
	return []string{
		PointerStrengthDeltaChecked, PointerStrengthToolReported, PointerStrengthProbeObserved,
		PointerStrengthPriorFinding, PointerStrengthPassiveEcho, PointerStrengthUnattributed,
	}
}

// PointerSourceOrder is the source vocabulary, as data.
func PointerSourceOrder() []string {
	return []string{PointerSourceReflection, PointerSourceFinding, PointerSourceTriage}
}

// pointerStrengthFor turns an EvidenceRank into its label. An unknown rank falls to unattributed
// rather than to the top, because a rank nobody assigned is not evidence anybody checked.
func pointerStrengthFor(rank int) string {
	switch rank {
	case 5:
		return PointerStrengthDeltaChecked
	case 4:
		return PointerStrengthToolReported
	case 3:
		return PointerStrengthProbeObserved
	case 2:
		return PointerStrengthPriorFinding
	case 1:
		return PointerStrengthPassiveEcho
	}
	return PointerStrengthUnattributed
}

// pointerStrengthWhy is the one-sentence account of what that strength means. It is the honest half
// of the ranking: a delta-checked hit showed the payload CHANGED something, a bare signature match
// showed a string is present and that string may have been in the baseline all along.
func pointerStrengthWhy(rank int) string {
	switch rank {
	case 5:
		return "A probe this framework sent, differenced against a measured baseline, so the payload changed something."
	case 4:
		return "An external scanner reported it and ran its own comparison, which we cannot inspect."
	case 3:
		return "A probe this framework sent, with no baseline difference behind it, so a string being present is all it shows."
	case 2:
		return "A tool flagged this vector on an earlier scan. That is a pointer, not a measurement of the application today."
	case 1:
		return "The value came back in a response the crawl had already stored. Nothing dangerous was ever sent, so the encoding is untested."
	}
	return "The evidence names no source, which is the shape of a finding nobody can reproduce."
}

// ---------------------------------------------------------------------------------------------
// Attack classes
// ---------------------------------------------------------------------------------------------

// FOUR CLASSES HAVE NO triage.ClassID and are spelled here: the triage catalogue models injection
// and its neighbours, and secret exposure, access control and request smuggling are not
// injections. They are NOT dropped for that. A dropped pointer is the false negative this whole
// layer exists to prevent, so they carry their own name, and a tool nobody has mapped still becomes
// a pointer under pointerClassUnclassified with its tool name kept.
const (
	pointerClassSecret        = "SECRET"
	pointerClassAccessBypass  = "ACCESS-BYPASS"
	pointerClassSmuggling     = "SMUGGLING"
	pointerClassUnclassified  = "UNCLASSIFIED"
	pointerClassLabelUnmapped = "Unclassified: this tool has no attack class mapping yet"
	pointerNoToolReason       = "No confirmation tool is mapped for this class, so the next step is a hand review of the request and response."
)

// pointerToolClass maps the tool that wrote a vector_findings row to the attack class a pointer
// from it belongs to.
//
// THE CLASS NAMES ARE triage.ClassID's, not this file's. One vocabulary across the three sources is
// what lets the operator filter "show me everything that says SQL" and get the reflection rows, the
// prior findings and the triage verdicts in one list.
var pointerToolClass = map[string]string{
	// XSS. dalfox is split by kind in pointerClassForFinding, because its A findings are DOM and
	// its V and R are not.
	"xssfuzz": triage.ClassXSSReflected.String(),
	"domdig":  triage.ClassXSSDOM.String(),
	"pphack":  triage.ClassPPClient.String(),
	// Injection.
	"sqlmap":       triage.ClassSQL.String(),
	"ghauri":       triage.ClassSQL.String(),
	"sqlidetector": triage.ClassSQL.String(),
	"commix":       triage.ClassCMDI.String(),
	"sstimap":      triage.ClassSSTI.String(),
	"tinja":        triage.ClassSSTI.String(),
	// File and path.
	"lfimap":  triage.ClassLFI.String(),
	"lfihunt": triage.ClassLFI.String(),
	// Cache.
	"wcvs":      triage.ClassCache.String(),
	"cacheboom": triage.ClassCache.String(),
	// GraphQL.
	"graphql-cop":  triage.ClassGraphQL.String(),
	"clairvoyance": triage.ClassGraphQL.String(),
	"graphw00f":    triage.ClassGraphQL.String(),
	// Secret exposure.
	"mantra":       pointerClassSecret,
	"trufflehog":   pointerClassSecret,
	"snallygaster": pointerClassSecret,
	"git-dumper":   pointerClassSecret,
	"gittools":     pointerClassSecret,
	// Access control.
	"nomore403": pointerClassAccessBypass,
	"forbidden": pointerClassAccessBypass,
	// Smuggling.
	"smugglex":   pointerClassSmuggling,
	"http2smugl": pointerClassSmuggling,
	// SSRF.
	"ssrfmap":    triage.ClassSSRF.String(),
	"recollapse": triage.ClassSSRF.String(),
}

// pointerClassLabels is the human name per class, for a list the operator reads rather than parses.
var pointerClassLabels = map[string]string{
	triage.ClassXSSReflected.String(): "Reflected XSS",
	triage.ClassXSSDOM.String():       "DOM XSS",
	triage.ClassXSSStored.String():    "Stored XSS",
	triage.ClassSQL.String():          "SQL injection",
	triage.ClassNoSQL.String():        "NoSQL injection",
	triage.ClassCMDI.String():         "Command injection",
	triage.ClassSSTI.String():         "Server side template injection",
	triage.ClassCSTI.String():         "Client side template injection",
	triage.ClassLFI.String():          "Local file inclusion",
	triage.ClassRFI.String():          "Remote file inclusion",
	triage.ClassTraversal.String():    "Path traversal",
	triage.ClassXXE.String():          "XML external entity",
	triage.ClassSSRF.String():         "Server side request forgery",
	triage.ClassRedirect.String():     "Open redirect",
	triage.ClassCRLF.String():         "CRLF injection",
	triage.ClassHostHeader.String():   "Host header attack",
	triage.ClassCache.String():        "Web cache poisoning",
	triage.ClassPPServer.String():     "Server side prototype pollution",
	triage.ClassPPClient.String():     "Client side prototype pollution",
	triage.ClassDeser.String():        "Insecure deserialization",
	triage.ClassMassAssign.String():   "Mass assignment",
	triage.ClassHPP.String():          "HTTP parameter pollution",
	triage.ClassGraphQL.String():      "GraphQL abuse",
	pointerClassSecret:                "Exposed secret",
	pointerClassAccessBypass:          "Access control bypass",
	pointerClassSmuggling:             "Request smuggling",
	pointerClassUnclassified:          pointerClassLabelUnmapped,
}

// pointerClassLabel names a class, falling back to the class id itself rather than to blank: a row
// with no label still has to be readable.
func pointerClassLabel(class string) string {
	if label, ok := pointerClassLabels[class]; ok {
		return label
	}
	return class
}

// pointerClassForFinding decides which attack class a prior finding points at.
//
// dalfox is keyed on kind because its four types are not one class: an A finding is a static
// source-to-sink path in JavaScript, which is DOM XSS, while V and R are reflection. Sending an A
// to the reflected bucket would point the operator at dalfox again instead of at a browser.
func pointerClassForFinding(tool, kind string) string {
	t := strings.ToLower(strings.TrimSpace(tool))
	if t == "dalfox" {
		if strings.TrimSpace(kind) == "A" {
			return triage.ClassXSSDOM.String()
		}
		return triage.ClassXSSReflected.String()
	}
	if t == "nuclei-dast" || t == "nuclei" {
		k := strings.ToLower(strings.TrimSpace(kind))
		switch {
		case strings.Contains(k, "redirect"):
			return triage.ClassRedirect.String()
		case strings.Contains(k, "ssrf"):
			return triage.ClassSSRF.String()
		case strings.Contains(k, "xss"):
			return triage.ClassXSSReflected.String()
		case strings.Contains(k, "sql"):
			return triage.ClassSQL.String()
		}
		return pointerClassUnclassified
	}
	if class, ok := pointerToolClass[t]; ok {
		return class
	}
	return pointerClassUnclassified
}

// pointerVectorURL is the last-resort URL for a pointer whose source row carries none.
//
// A POINTER WITH NO URL IS NOT ACTIONABLE. One real row on the measured corpus has it: an xssfuzz
// finding stored with an empty url column on a vector whose evidence_url was also null, so the
// operator got "spend an hour here" with no here. The vector's own scheme, domain and path are
// always populated, so they are composed rather than left blank. The composition is a URL, not a
// request: it carries no query string and no payload, and the reproduction on the detail endpoint
// is where the real bytes are.
func pointerVectorURL(scheme, domain, path string) string {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return ""
	}
	scheme = strings.TrimSpace(scheme)
	if scheme == "" {
		scheme = "https"
	}
	path = strings.TrimSpace(path)
	if path == "" {
		path = "/"
	}
	return scheme + "://" + domain + path
}

// THE URL PROVENANCE VOCABULARY. A URL on this screen is either bytes somebody recorded or bytes
// this file assembled, and the two look identical in a text box.
const (
	// PointerURLFromProbe is the active reflection probe's own request URL. Captured.
	PointerURLFromProbe = "probe_request_url"
	// PointerURLFromTool is the URL the tool stored on its finding. Captured.
	PointerURLFromTool = "tool_reported_url"
	// PointerURLFromVector is attack_vectors.evidence_url, the URL the crawl recorded. Captured.
	PointerURLFromVector = "vector_evidence_url"
	// PointerURLComposed is scheme + domain + path, assembled here because no source row had one.
	PointerURLComposed = "composed_from_vector"
	// PointerURLNone is no URL at all, which is a pointer nobody can act on and has to say so.
	PointerURLNone = "none"

	pointerComposedURLNote = "This URL was composed from the vector's scheme, domain and path because no source row " +
		"stored one. It is where to look, not a request anybody sent: it carries no query string and no payload."
	pointerNoURLNote = "No source row stored a URL and the vector had no host to compose one from, so this pointer " +
		"names an attack class without naming a place. Read the vector's captured request."
)

// pointerURLWithOrigin picks the most captured URL available and SAYS which one it picked.
//
// The order is captured-before-composed, and within captured it is row-before-vector: the row's own
// URL is the request the evidence came from, while the vector's evidence_url is the request the
// crawl happened to record. The composition is the last resort and is labelled as one.
func pointerURLWithOrigin(rowURL, rowOrigin, vectorEvidenceURL, scheme, domain, path string) (string, string, string) {
	if u := strings.TrimSpace(rowURL); u != "" {
		return u, rowOrigin, ""
	}
	if u := strings.TrimSpace(vectorEvidenceURL); u != "" {
		return u, PointerURLFromVector, ""
	}
	if u := pointerVectorURL(scheme, domain, path); u != "" {
		return u, PointerURLComposed, pointerComposedURLNote
	}
	return "", PointerURLNone, pointerNoURLNote
}

// pointerReflectionURL is pointerURLWithOrigin with the passive rule in front of it.
//
// THE PROBE URL BELONGS TO THE ACTIVE PASS ONLY. vector_reflection_probes is keyed
// (vector_id, parameter), so the passive pass overwrites status, evidence and detail on a row whose
// probe_url and canary still hold an EARLIER ACTIVE ATTEMPT's values. MEASURED on the engaged
// corpus: 19 of the 34 passive rows carry a probe_url containing a canary such as
// rs0nR4f657925<>"'rs0nE, and all 34 carry a stale canary column. Handing either to the operator
// beside passive evidence shows them a request that was never sent for what they are reading, so a
// passive pointer never sees probe_url and never sees canary.
func pointerReflectionURL(evidenceSource, probeURL, vectorEvidenceURL, scheme, domain, path string) (string, string, string) {
	if evidenceSource == "passive" {
		return pointerURLWithOrigin("", "", vectorEvidenceURL, scheme, domain, path)
	}
	return pointerURLWithOrigin(probeURL, PointerURLFromProbe, vectorEvidenceURL, scheme, domain, path)
}

// pointerClassVictimDelivered names the classes where DELIVERY is part of severity at all.
//
// THE RULE IS NOT THIS FILE'S INVENTION and gating the wrong classes is an overclaim in the other
// direction. vectorExplain.go's findingVictimDelivered comment states it: everything outside the
// XSS family is exploited by the attacker sending their OWN request, so a cookie or body vector is
// exactly as reachable as a query one and there is no gate to apply.
//
// THIS WAS MEASURED WRONG FIRST. Without it, ReflectionInsertionPointDeliverable was asked about
// every class, so an exposed credential in env.js came back deliverable:false and was ranked below
// an equally strong pointer "an attacker can trigger with a link", which is a category error: a
// secret in a JavaScript bundle is read by fetching the file.
func pointerClassVictimDelivered(class string) bool {
	switch class {
	case triage.ClassXSSReflected.String(), triage.ClassXSSDOM.String(),
		triage.ClassXSSStored.String(), triage.ClassCSTI.String(), triage.ClassPPClient.String():
		return true
	}
	return false
}

// pointerDeliverable answers "can an attacker put a value here" for the class that is actually
// being pointed at, which is the only question the delivery gate was written to answer.
func pointerDeliverable(class, insertionPoint string) bool {
	if !pointerClassVictimDelivered(class) {
		return true
	}
	return ReflectionInsertionPointDeliverable(insertionPoint)
}

// pointerDeliveryNote is FindingDeliveryNote with the class gate in front of it, so a note about
// cookies the victim's browser sets never lands on a server side class.
func pointerDeliveryNote(class, tool, insertionPoint string) string {
	if !pointerClassVictimDelivered(class) {
		return ""
	}
	return FindingDeliveryNote(tool, insertionPoint)
}

// pointerNextTool is the WHICH TOOL half of a pointer. A pointer that does not name the next move
// is a sentence, not an instruction.
func pointerNextTool(class string) (string, string) {
	switch class {
	case triage.ClassXSSReflected.String():
		return "dalfox", "Dalfox drives the reflection towards an executable position and reports the context it landed in."
	case triage.ClassXSSDOM.String():
		return "domdig", "Only domdig runs a real browser, and a DOM sink is invisible to every request-level check."
	case triage.ClassXSSStored.String():
		return "dalfox", "Dalfox, because the echo may surface on a different page than the one that took the input."
	case triage.ClassSQL.String():
		return "sqlmap", "Sqlmap is the confirmation run, around 1690 requests on one vector, which is why it needs pointing."
	case triage.ClassNoSQL.String():
		return "sqlmap", "Sqlmap covers the NoSQL operators once the vector is narrowed to one parameter."
	case triage.ClassCMDI.String():
		return "commix", "Commix separates a results-based injection from a timing artefact, which a signature cannot."
	case triage.ClassSSTI.String():
		return "sstimap", "SSTImap fingerprints the engine before it claims injection, which is what turns a suspicious arithmetic echo into a finding."
	case triage.ClassCSTI.String():
		return "sstimap", "SSTImap covers the client side template engines from the same vector."
	case triage.ClassLFI.String(), triage.ClassRFI.String(), triage.ClassTraversal.String():
		return "lfimap", "LFImap sends the traversal and wrapper set this insertion point allows."
	case triage.ClassCache.String():
		return "wcvs", "WCVS discovers the cache key per endpoint, so it has to be aimed at one URL."
	case triage.ClassRedirect.String():
		return "nuclei-dast", "Nuclei DAST is the detector here, and REcollapse follows it once a finding gates it."
	case triage.ClassSSRF.String():
		return "ssrfmap", "SSRFmap needs a request that reaches an outbound fetch, which is what this pointer is claiming."
	case triage.ClassGraphQL.String():
		return "graphql-cop", "Graphql-cop enumerates the introspection and batching surface for this endpoint."
	case triage.ClassPPClient.String():
		return "pphack", "Pphack checks whether the polluted property reaches a gadget in the page."
	case pointerClassAccessBypass:
		return "nomore403", "Nomore403 replays the refused request through the bypass set, and a soft 403 is checked rather than assumed."
	case pointerClassSmuggling:
		return "smugglex", "Smugglex distinguishes a desync from a timeout, and a timeout read as a desync is this section's known trap."
	case pointerClassSecret:
		return "", "A secret is confirmed by reading it and using it, not by another scanner. The response body is the evidence."
	}
	return "", pointerNoToolReason
}

// ---------------------------------------------------------------------------------------------
// The pointer
// ---------------------------------------------------------------------------------------------

// Pointer is one "spend an hour here", with enough on it to judge without opening anything else.
type Pointer struct {
	// ID is "<source>:<row uuid>" and is what the detail endpoint resolves. It is built from the
	// source row's own primary key rather than from a hash of the content, so it survives a
	// re-render and cannot collide across sources.
	ID     string `json:"id"`
	Source string `json:"source"`
	// SourceDetail names the run or the tool inside that source, because "reflection_probe" alone
	// does not tell the operator whether a request was sent.
	SourceDetail string `json:"source_detail"`

	AttackClass      string `json:"attack_class"`
	AttackClassLabel string `json:"attack_class_label"`

	// Grade is the SOURCE's own grade, carried unchanged. For a reflection row it is
	// XSSCandidateGrade's answer, for a prior finding it is the tool's severity, for a triage
	// verdict it is triage's grade. GradeSource says which, so two grades in one list cannot be
	// mistaken for one scale.
	Grade       string `json:"grade"`
	GradeSource string `json:"grade_source"`

	Strength     string `json:"strength"`
	StrengthRank int    `json:"strength_rank"`
	DeltaChecked bool   `json:"delta_checked"`

	// Rank is the 1-based position in the FULL ranked list, assigned before any filter runs, so a
	// filtered view still shows where a pointer sits among everything.
	Rank      int    `json:"rank"`
	WhyRanked string `json:"why_ranked"`

	VectorID string `json:"vector_id"`
	Method   string `json:"method"`
	URL      string `json:"url"`
	// URLOrigin says whether the URL above was CAPTURED or COMPOSED, and a reproduction built from
	// a composed URL that silently claims to be the real request is how an operator wastes an hour.
	// URLNote is the sentence version, set only when there is something to warn about.
	URLOrigin      string `json:"url_origin"`
	URLNote        string `json:"url_note,omitempty"`
	Domain         string `json:"domain"`
	Path           string `json:"path"`
	InsertionPoint string `json:"insertion_point"`
	Parameter      string `json:"parameter"`
	// SlotKey is the triage addressing scheme's key. Empty for the two sources that predate it.
	SlotKey string `json:"slot_key"`

	// Rule is what fired, named so the operator can disagree with it.
	Rule string `json:"rule"`
	// Evidence is what came back. A snippet, never the whole response: the detail endpoint carries
	// the bytes.
	Evidence    string `json:"evidence"`
	HTTPStatus  int    `json:"http_status"`
	ContentType string `json:"content_type"`

	Deliverable  bool   `json:"deliverable"`
	DeliveryNote string `json:"delivery_note,omitempty"`

	NextTool       string `json:"next_tool"`
	NextToolReason string `json:"next_tool_reason"`

	DetailURL string `json:"detail_url"`

	// severity is the source's own severity word, used only to break ties inside a strength band.
	// Not serialised: Grade already carries it for the sources that have one, and a second severity
	// field is a second thing to disagree.
	severity string
	// rowID is the source row's primary key, kept so the detail endpoint can fetch the bytes
	// without re-parsing ID.
	rowID string
}

// pointerSeverityWeight orders severities inside one strength band. An unrecognised word sorts last
// rather than first: a severity nobody assigned is not a claim of urgency.
func pointerSeverityWeight(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high", XSSCandidateHigh:
		return 4
	case XSSCandidateChain:
		return 3
	case "medium", XSSCandidateLow:
		return 2
	case "low":
		return 1
	}
	return 0
}

// rankPointers sorts most-worth-an-hour first and stamps Rank and WhyRanked.
//
// THE SORT IS EvidenceRank FIRST, always. A delta-checked native hit outranks a bare signature
// match whatever severity word the signature carried, because severity is a claim about impact IF
// TRUE and strength is how likely it is to be true at all. Severity only breaks ties inside a band.
// The last two keys make the order total: a ranking that changes between two identical requests is
// a ranking nobody can cite.
func rankPointers(pointers []Pointer) {
	sort.SliceStable(pointers, func(i, j int) bool {
		a, b := pointers[i], pointers[j]
		if a.StrengthRank != b.StrengthRank {
			return a.StrengthRank > b.StrengthRank
		}
		wa, wb := pointerSeverityWeight(a.severity), pointerSeverityWeight(b.severity)
		if wa != wb {
			return wa > wb
		}
		// A pointer an attacker can trigger with a link is worth more of an hour than one that
		// needs a chain demonstrated first. The same rule the XSS grade uses, applied to every class.
		if a.Deliverable != b.Deliverable {
			return a.Deliverable
		}
		if a.AttackClass != b.AttackClass {
			return a.AttackClass < b.AttackClass
		}
		return a.ID < b.ID
	})
	for i := range pointers {
		pointers[i].Rank = i + 1
		pointers[i].WhyRanked = pointerWhyRanked(pointers[i], len(pointers))
	}
}

// pointerWhyRanked is the short field that makes the order auditable. A ranking nobody can explain
// is a ranking nobody trusts.
func pointerWhyRanked(p Pointer, total int) string {
	parts := []string{fmt.Sprintf("%d of %d.", p.Rank, total), pointerStrengthWhy(p.StrengthRank)}
	if strings.TrimSpace(p.severity) != "" && pointerSeverityWeight(p.severity) > 0 {
		parts = append(parts, fmt.Sprintf("Its own source grades it %s, which breaks the tie inside that band.",
			strings.ToLower(strings.TrimSpace(p.severity))))
	}
	if !p.Deliverable {
		parts = append(parts, "Ranked below an equally strong pointer an attacker can trigger with a link.")
	}
	return strings.Join(parts, " ")
}

// ---------------------------------------------------------------------------------------------
// The attack path
// ---------------------------------------------------------------------------------------------

// PointerAttackPath is how attacker-controlled input reaches the sink, and what happens next.
type PointerAttackPath struct {
	// Entry is where the attacker puts the value.
	Entry string `json:"entry"`
	// Reaches is what the evidence shows happening to it.
	Reaches string `json:"reaches"`
	// Deliverable is the half of severity that is not execution: can an attacker put the value there.
	Deliverable  bool   `json:"deliverable"`
	DeliveryNote string `json:"delivery_note,omitempty"`
	// PossibleAttacks is what an attacker could do next IF the class confirms. Conditional on
	// purpose: this is a pointer, and stating it as a consequence would make it a finding.
	PossibleAttacks []string `json:"possible_attacks"`
	// Next names the tool with the vector already selected for it.
	Next PointerNextStep `json:"next"`
}

// PointerNextStep carries the tool AND the selection, so the operator does not re-find the vector.
type PointerNextStep struct {
	Tool           string `json:"tool"`
	Reason         string `json:"reason"`
	VectorID       string `json:"vector_id"`
	InsertionPoint string `json:"insertion_point"`
	Parameter      string `json:"parameter"`
}

// pointerPossibleAttacks is what the class buys an attacker if it confirms. One line each, phrased
// as a conditional, because nothing here has been confirmed.
func pointerPossibleAttacks(class string, deliverable bool) []string {
	var out []string
	switch class {
	case triage.ClassXSSReflected.String(), triage.ClassXSSDOM.String(),
		triage.ClassXSSStored.String(), triage.ClassCSTI.String(), triage.ClassPPClient.String():
		out = []string{
			"Script in the victim's origin: session theft where the cookie is reachable, and actions taken as the victim where it is not.",
			"A chain into account takeover if the page exposes an email or password change.",
		}
		if !deliverable {
			out = append(out, "Nothing at all until the chain that sets this value is named and demonstrated.")
		}
	case triage.ClassSQL.String(), triage.ClassNoSQL.String():
		out = []string{
			"Reading rows the account is not entitled to, starting with the table this endpoint queries.",
			"Stacked statements or file primitives where the driver allows them, which is the difference between an afternoon and a critical.",
		}
	case triage.ClassCMDI.String():
		out = []string{"Command execution on the host, and from there whatever credentials the container holds."}
	case triage.ClassSSTI.String():
		out = []string{
			"Template evaluation, which is code execution on most engines once the engine is fingerprinted.",
			"Reading application configuration through the template context before any escape is attempted.",
		}
	case triage.ClassLFI.String(), triage.ClassRFI.String(), triage.ClassTraversal.String():
		out = []string{
			"Reading files the process can read, which on a container usually means the environment and any mounted secret.",
			"Escalation to execution where a log or upload path can be included.",
		}
	case triage.ClassSSRF.String():
		out = []string{
			"Requests issued from inside the network boundary, with the cloud metadata service as the first stop.",
			"Reaching internal services that are unauthenticated because they were never meant to be reachable.",
		}
	case triage.ClassRedirect.String():
		out = []string{
			"Credential phishing on the real domain, and token theft where an OAuth redirect_uri accepts this host.",
		}
	case triage.ClassCache.String():
		out = []string{"A poisoned entry served to every other user of the cache, which turns a self-only bug into a stored one."}
	case pointerClassSecret:
		out = []string{
			"Direct use of the credential against whatever issued it, with the blast radius set by that service and not by this host.",
		}
	case pointerClassAccessBypass:
		out = []string{"Reaching the resource the access control refused, as an identity that should not have it."}
	case pointerClassSmuggling:
		out = []string{"Requests from other users poisoned on a shared front end connection, which is a stored attack on everyone behind it."}
	default:
		out = []string{"Not stated: this attack class has no catalogued consequence yet, so read the request and response."}
	}
	return out
}

// pointerAttackPath assembles the path. The delivery half REUSES the framework's one copy:
// ReflectionInsertionPointDeliverable answers whether an attacker can put the value there, and
// FindingDeliveryNote names the chain when they cannot.
//
// FindingDeliveryNote IS CALLED WITH THE TOOL THIS POINTER RECOMMENDS, not with a placeholder. That
// is the honest reading of the gate: the note describes what a finding from THAT tool at THIS
// insertion point would and would not mean, and the tool being recommended is exactly the tool
// whose finding the operator will read next. For a class whose findings are not victim-delivered
// the note is empty, which is the same answer that file gives everywhere else.
func pointerAttackPath(p Pointer) PointerAttackPath {
	deliverable := pointerDeliverable(p.AttackClass, p.InsertionPoint)
	note := pointerDeliveryNote(p.AttackClass, p.NextTool, p.InsertionPoint)

	where := strings.TrimSpace(p.InsertionPoint)
	if where == "" {
		where = "an unrecorded insertion point"
	}
	named := strings.TrimSpace(p.Parameter)
	if named == "" {
		named = strings.TrimSpace(p.SlotKey)
	}
	entry := fmt.Sprintf("The attacker controls the %s value", where)
	if named != "" {
		entry += " " + named
	}
	entry += fmt.Sprintf(" on %s %s.", strings.ToUpper(firstNonEmpty(p.Method, "GET")),
		firstNonEmpty(p.URL, p.Path, "the vector below"))
	// A composed URL in a sentence about what the attacker controls reads as a captured request,
	// and an operator who spends an hour reproducing an inferred URL has been misled by this file.
	switch p.URLOrigin {
	case PointerURLComposed:
		entry += " That URL was composed from the vector, not captured from a request."
	case PointerURLNone:
		entry += " No source row recorded a URL for it."
	}

	reaches := strings.TrimSpace(p.Rule)
	if ct := strings.TrimSpace(p.ContentType); ct != "" {
		reaches += fmt.Sprintf(" The response was %s.", ct)
	}

	return PointerAttackPath{
		Entry:           entry,
		Reaches:         strings.TrimSpace(reaches),
		Deliverable:     deliverable,
		DeliveryNote:    note,
		PossibleAttacks: pointerPossibleAttacks(p.AttackClass, deliverable),
		Next: PointerNextStep{
			Tool: p.NextTool, Reason: p.NextToolReason, VectorID: p.VectorID,
			InsertionPoint: p.InsertionPoint, Parameter: p.Parameter,
		},
	}
}

// ---------------------------------------------------------------------------------------------
// Coverage: what is NOT in the pointer list, and why
// ---------------------------------------------------------------------------------------------

// PointerCoverage is returned on EVERY response and is never filtered. See the file header: 1714 of
// 1764 probe rows on the measured corpus are unknown, and a list of 34 pointers with no denominator
// beside it reads as "the rest are fine".
type PointerCoverage struct {
	Vectors    PointerVectorCoverage     `json:"vectors"`
	Reflection PointerReflectionCoverage `json:"reflection"`
	Findings   PointerFindingCoverage    `json:"findings"`
	Triage     PointerTriageCoverage     `json:"triage"`
	// Headline is the one sentence the card shows beside the count.
	Headline string `json:"headline"`
}

// PointerVectorCoverage is the denominator in the unit the operator selects for a scan.
//
// THE THREE NUMBERS ARE NOT "TESTED" AND "UNTESTED", and the first version of this struct was.
// It counted a vector as examined whenever it carried any reflection_status at all, which reported
// 218 examined and 0 unexamined on a corpus where 186 vectors have no conclusion of any kind: they
// carry is_credential, error or probe_refused, which are records of NOT having measured. That is
// the exact false clean this file exists to prevent, arriving through the coverage block.
// THE SECOND THING THIS STRUCT GOT WRONG, and the reason ConcludedBy exists: Concluded and Unknown
// were derived from reflectionGradeCountsDetailed ALONE. Two vectors on the measured corpus carry a
// tool's finding and a reflection_status of error, so they graded xss_unknown and were counted
// among the 186 "no conclusion from any source" while a tool had already reported a finding on
// them. A vector carrying a pointer is by definition concluded by SOME source, so the headline
// sentence was false. It erred safe, and a coverage number nobody can reconcile is still a coverage
// number nobody trusts.
type PointerVectorCoverage struct {
	Total int `json:"total"`
	// WithPointer is how many distinct vectors IN THIS CORPUS carry at least one pointer.
	WithPointer int `json:"with_pointer"`
	// Concluded is the UNION: how many vectors any source reached an actual claim about, either way.
	Concluded int `json:"concluded"`
	// Unknown is Total minus Concluded: how many vectors nothing has concluded anything about.
	// NOT CLEAN.
	Unknown int `json:"unknown"`
	// ConcludedBySource says WHICH SOURCE concluded what. The reflection entry is every vector the
	// probe reached a grade on, negatives included, because a measured negative is a conclusion.
	// The other entries are vectors carrying a pointer from that source. THE ENTRIES OVERLAP and do
	// not sum to Concluded: two sources can conclude about one vector, and Concluded is the union.
	ConcludedBySource map[string]int `json:"concluded_by_source"`
	// PointersWithoutVector is how many pointers name no vector at all. MEASURED: 7 of the 9
	// finding pointers here, from mantra, trufflehog and nomore403, which store a URL and no
	// vector. They are in the list and in no vector denominator, so without this the headline's
	// arithmetic cannot be reconciled by the operator reading it.
	PointersWithoutVector int `json:"pointers_without_vector"`
	// PointersOffCorpus is how many pointers name a vector that is not in this target's live
	// corpus, which is what a deleted vector with a surviving finding looks like.
	PointersOffCorpus int `json:"pointers_off_corpus"`
	// ByGrade is the vector-level grade breakdown, from the server's own derivation.
	ByGrade map[string]int `json:"by_grade"`
}

// PointerReflectionCoverage is the probe corpus, whole.
type PointerReflectionCoverage struct {
	ProbeRows int            `json:"probe_rows"`
	ByStatus  map[string]int `json:"by_status"`
	ByGrade   map[string]int `json:"by_grade"`
	// Unknown is every row that is neither a candidate nor a measured negative. NOT KNOWING IS NOT
	// CLEAN, so this sits beside the pointers rather than being folded into them.
	Unknown         int            `json:"unknown"`
	UnknownByReason map[string]int `json:"unknown_by_reason"`
	RunStatus       string         `json:"run_status"`
}

// PointerFindingCoverage says how a large stored finding count became a small pointer count.
type PointerFindingCoverage struct {
	Rows            int `json:"rows"`
	Pointers        int `json:"pointers"`
	ExcludedCanary  int `json:"excluded_canary"`
	ExcludedDismiss int `json:"excluded_dismissed"`
	// CanaryHost is the host the exclusion matched on, so the operator can check it against the
	// oracle they actually run rather than against a literal in this file.
	CanaryHost string `json:"canary_host"`
	// RowsByTool and CanaryByTool are the exclusion PER TOOL. The exclusion is large enough
	// (390 of 415 on the measured corpus) that "trust me" is not an acceptable account of it, and
	// per tool is the resolution at which an operator can see that dalfox is 223 of 223 control
	// while mantra is 0 of 17 and therefore entirely about their target.
	RowsByTool   map[string]int `json:"rows_by_tool"`
	CanaryByTool map[string]int `json:"canary_by_tool"`
	// CanaryUncheckable counts findings with no URL from any source, so the control filter could
	// not be applied to them at all. NOT KNOWING IS NOT CLEAN and it is not a silent drop either:
	// they are kept as pointers and counted here.
	CanaryUncheckable int `json:"canary_uncheckable"`
	// Note names the canary exclusion in words, because it is large and surprising.
	Note string `json:"note"`
}

// PointerTriageCoverage says what the triage source contributed, DERIVED ENTIRELY FROM THE ROWS.
//
// EVERY FIELD HERE IS A COUNT OR A COLUMN, and Status and Note are computed from them by
// triageCoverageStatus and triageCoverageNote at the moment the collector returns. Nothing in this
// struct states what the triage runner is or is not. That is not a style rule: this struct used to
// carry the sentence "the triage runner is built and not yet wired", and it kept saying so on
// every target with no run of its own long after the runner was wired and probing. An operator who
// reads that decides not to press the button, and never sees the verdicts the runner would have
// produced. That is a false negative shipped by a comment.
//
// A ZERO STILL NEEDS A REASON BESIDE IT. "0 triage pointers" is produced by six different
// situations: the tables could not be read, no run was ever started, a run is still going, a run
// was cancelled, a run ended in an error, or a run finished and concluded nothing positive. Only
// the last is anything like a clean, and Status names which one it is.
type PointerTriageCoverage struct {
	RunID string `json:"run_id"`
	// Status is DERIVED by triageCoverageStatus from the fields below. See the vocabulary under it.
	Status string `json:"status"`
	// RunStatus is triage_runs.status exactly as the runner wrote it: running, completed, cancelled
	// or error. Carried raw beside the derived Status so an operator can check the derivation
	// rather than take it on trust.
	RunStatus string `json:"run_status"`
	RunPhase  string `json:"run_phase"`
	StartedAt string `json:"started_at"`
	// PlannedPairs, CompletedPairs and ProbesSent are the run's own progress counters. A run that
	// reached 3 of 77 pairs has not measured this target, and without these three numbers that run
	// and an exhaustive one both render as "0 positive".
	PlannedPairs   int `json:"planned_pairs"`
	CompletedPairs int `json:"completed_pairs"`
	ProbesSent     int `json:"probes_sent"`
	Slots          int `json:"slots"`
	Pairs          int `json:"coverage_pairs"`
	Verdicts       int `json:"verdicts"`
	Positive       int `json:"positive"`
	Unknown        int `json:"unknown"`
	// PayloadUnproven counts verdicts whose probe cannot be shown to have reached the wire as
	// asked. Those are NEITHER pointers NOR cleans: they are unknowns. The gate is
	// triageUnprovenFidelity, used rather than reimplemented.
	PayloadUnproven int `json:"payload_unproven"`
	// ReadError is set when a query against the triage tables failed. NOT KNOWING IS NOT CLEAN: an
	// unreadable table used to return exactly the zeros an unused one returns, so a missing
	// migration and a target nobody has triaged were indistinguishable on the card.
	ReadError string `json:"read_error,omitempty"`
	Note      string `json:"note"`
}

// The Status vocabulary. Every value is derived from rows; none of them describes the code.
const (
	// PointerTriageNoRun means triage_runs holds no run for this scope target.
	PointerTriageNoRun = "no_run_yet"
	// PointerTriageRunning means the newest run has not reached a terminal status, so its counts
	// are a snapshot of work still in progress.
	PointerTriageRunning = "running"
	// PointerTriageCancelled and PointerTriageRunFailed mean the newest run stopped early, so
	// everything it did not reach is unmeasured.
	PointerTriageCancelled = "cancelled"
	PointerTriageRunFailed = "run_error"
	// PointerTriageRead means the newest run finished and its verdicts were read.
	PointerTriageRead = "read"
	// PointerTriageUnreadable means a query failed. It is the one status that must never be
	// treated as a count of anything.
	PointerTriageUnreadable = "read_failed"
)

// HasRun answers "has triage ever run on this target" FROM triage_runs. The screen asks this
// function rather than reading a sentence, which is the whole point: the answer changes when the
// data changes and nobody has to remember to edit anything.
func (c PointerTriageCoverage) HasRun() bool { return c.RunID != "" }

// HasVerdicts answers "did that run record anything" FROM triage_verdicts. A run with no verdict
// is a run that measured nothing, which is not the same as a run that found nothing.
func (c PointerTriageCoverage) HasVerdicts() bool { return c.Verdicts > 0 }

// Measured is the only question the rest of the screen is entitled to ask before treating a zero
// from this source as meaningful: a run that was read in full, finished, and recorded verdicts.
// Everything else is an absence of evidence.
func (c PointerTriageCoverage) Measured() bool {
	return c.ReadError == "" && c.HasRun() && c.RunStatus == "completed" && c.HasVerdicts()
}

// ---------------------------------------------------------------------------------------------
// The list endpoint
// ---------------------------------------------------------------------------------------------

// pointerCounts are the totals. Computed over EVERY pointer, before any filter, always.
type pointerCounts struct {
	ByAttackClass    map[string]int `json:"by_attack_class"`
	BySource         map[string]int `json:"by_source"`
	ByGrade          map[string]int `json:"by_grade"`
	ByInsertionPoint map[string]int `json:"by_insertion_point"`
	ByStrength       map[string]int `json:"by_strength"`
}

func countPointers(pointers []Pointer) pointerCounts {
	c := pointerCounts{
		ByAttackClass: map[string]int{}, BySource: map[string]int{}, ByGrade: map[string]int{},
		ByInsertionPoint: map[string]int{}, ByStrength: map[string]int{},
	}
	for _, p := range pointers {
		c.ByAttackClass[p.AttackClass]++
		c.BySource[p.Source]++
		if p.Grade != "" {
			c.ByGrade[p.Grade]++
		}
		point := p.InsertionPoint
		if point == "" {
			point = "unrecorded"
		}
		c.ByInsertionPoint[point]++
		c.ByStrength[p.Strength]++
	}
	// Every source is present even at zero. An absent key reads as "not a thing"; a zero reads as
	// "nothing found there yet", and those are different facts.
	for _, s := range PointerSourceOrder() {
		if _, ok := c.BySource[s]; !ok {
			c.BySource[s] = 0
		}
	}
	return c
}

// GetAttackVectorPointers answers GET /attack-vectors/{scope_target_id}/pointers.
//
// Filters: ?attack_class=, ?source=, ?grade=, ?insertion_point=, each a comma separated list,
// parsed with the same csvSet the reflection results endpoint uses. The filter narrows `pointers`
// and NOTHING else: `total`, `counts` and `coverage` are the corpus.
func GetAttackVectorPointers(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]

	pointers, coverage, err := buildPointers(r.Context(), scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "pointers_failed", err.Error())
		return
	}
	counts := countPointers(pointers)

	q := r.URL.Query()
	wantClass := csvSet(q.Get("attack_class"))
	wantSource := csvSet(q.Get("source"))
	wantGrade := csvSet(q.Get("grade"))
	wantPoint := csvSet(q.Get("insertion_point"))

	filtered := []Pointer{}
	for _, p := range pointers {
		if len(wantClass) > 0 && !wantClass[p.AttackClass] {
			continue
		}
		if len(wantSource) > 0 && !wantSource[p.Source] {
			continue
		}
		if len(wantGrade) > 0 && !wantGrade[p.Grade] {
			continue
		}
		if len(wantPoint) > 0 && !wantPoint[p.InsertionPoint] {
			continue
		}
		filtered = append(filtered, p)
	}

	json.NewEncoder(w).Encode(map[string]any{
		"scope_target_id": scopeTargetID,
		"pointers":        filtered,
		"count":           len(filtered),
		"total":           len(pointers),
		"filters_applied": map[string][]string{
			"attack_class": setKeys(wantClass), "source": setKeys(wantSource),
			"grade": setKeys(wantGrade), "insertion_point": setKeys(wantPoint),
		},
		"counts":   counts,
		"coverage": coverage,
		"vocabulary": map[string]any{
			"sources":        PointerSourceOrder(),
			"strength_order": PointerStrengthOrder(),
			"class_labels":   pointerClassLabels,
		},
	})
}

// setKeys renders a filter set back as a sorted list, so the response says what it filtered on.
func setKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------------------------
// The detail endpoint
// ---------------------------------------------------------------------------------------------

// PointerEvidenceBlob is one side of the wire, with its provenance attached.
//
// ORIGIN IS ALWAYS CARRIED. "These are bytes the target sent" and "these are bytes this framework
// composed for you to send" look identical in a text box and are not the same claim, and this
// project has been misled by exactly that before.
type PointerEvidenceBlob struct {
	Raw    string `json:"raw"`
	Origin string `json:"origin"`
	Note   string `json:"note,omitempty"`
}

// PointerBaseline is the comparison that makes the evidence mean something, and it says plainly
// when there was not one.
type PointerBaseline struct {
	Compared bool   `json:"compared"`
	What     string `json:"what"`
}

// PointerRule is the rule that fired, and the limit of what it established.
type PointerRule struct {
	Fired           string `json:"fired"`
	Means           string `json:"means"`
	DidNotEstablish string `json:"did_not_establish"`
}

// PointerGrade is the grade, where it came from, and why it is that and not something else.
type PointerGrade struct {
	Value  string `json:"value"`
	Source string `json:"source"`
	Why    string `json:"why"`
}

// PointerDetail is everything needed to reproduce the pointer by hand and decide whether to spend
// the hour on it.
type PointerDetail struct {
	Pointer  Pointer             `json:"pointer"`
	Request  PointerEvidenceBlob `json:"request"`
	Response PointerEvidenceBlob `json:"response"`
	Baseline PointerBaseline     `json:"baseline"`
	Rule     PointerRule         `json:"rule"`
	Grade    PointerGrade        `json:"grade"`
	Path     PointerAttackPath   `json:"attack_path"`
	// Explain is the hard-coded reference for the tool behind a prior finding, including the
	// what-it-did-not-prove field. Absent for the sources that have no tool behind them.
	Explain *FindingExplanation `json:"explain,omitempty"`
	// Reproduction is the framework's existing reproduction builder, so this screen and the
	// findings modal hand the operator the same curl rather than two.
	Reproduction *FindingReproduction `json:"reproduction,omitempty"`
}

// GetAttackVectorPointerDetail answers GET /attack-vectors/{scope_target_id}/pointers/{pointer_id}.
//
// The whole list is rebuilt to answer one pointer. That is deliberate: Rank is a property of the
// list and not of the row, and answering from the row alone would hand the operator a pointer whose
// "3 of 41" disagreed with the screen they clicked it from.
func GetAttackVectorPointerDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	scopeTargetID := mux.Vars(r)["scope_target_id"]
	pointerID := mux.Vars(r)["pointer_id"]

	pointers, _, err := buildPointers(r.Context(), scopeTargetID)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "pointers_failed", err.Error())
		return
	}
	var found *Pointer
	for i := range pointers {
		if pointers[i].ID == pointerID {
			found = &pointers[i]
			break
		}
	}
	if found == nil {
		writeJSONError(w, http.StatusNotFound, "pointer_not_found",
			"No pointer with that id on this scope target. Pointers are derived, so one disappears when the row behind it is deleted or re-scanned.")
		return
	}

	detail, err := buildPointerDetail(r.Context(), *found)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "detail_failed", err.Error())
		return
	}
	json.NewEncoder(w).Encode(detail)
}

// ---------------------------------------------------------------------------------------------
// Assembly
// ---------------------------------------------------------------------------------------------

// buildPointers reads every source and returns one ranked list plus the coverage that gives it
// context. The two are built together and returned together, because a caller that could get one
// without the other would eventually ship a screen that did.
func buildPointers(ctx context.Context, scopeTargetID string) ([]Pointer, PointerCoverage, error) {
	var cov PointerCoverage
	pointers := []Pointer{}

	reflectionPointers, reflectionCov, err := collectReflectionPointers(ctx, scopeTargetID)
	if err != nil {
		return nil, cov, err
	}
	pointers = append(pointers, reflectionPointers...)
	cov.Reflection = reflectionCov

	findingPointers, findingCov, err := collectFindingPointers(ctx, scopeTargetID)
	if err != nil {
		return nil, cov, err
	}
	pointers = append(pointers, findingPointers...)
	cov.Findings = findingCov

	triagePointers, triageCov, err := collectTriagePointers(ctx, scopeTargetID)
	if err != nil {
		return nil, cov, err
	}
	pointers = append(pointers, triagePointers...)
	cov.Triage = triageCov

	rankPointers(pointers)
	for i := range pointers {
		pointers[i].DetailURL = fmt.Sprintf("/attack-vectors/%s/pointers/%s", scopeTargetID, pointers[i].ID)
	}

	vectorCov, err := pointerVectorCoverage(ctx, scopeTargetID, pointers)
	if err != nil {
		return nil, cov, err
	}
	cov.Vectors = vectorCov
	cov.Headline = pointerCoverageHeadline(len(pointers), cov)
	return pointers, cov, nil
}

// pointerCoverageHeadline is the one sentence that has to sit beside the count. One sentence: the
// operator has said twice that this UI gets overbuilt, and a paragraph of warning gets skipped.
func pointerCoverageHeadline(total int, cov PointerCoverage) string {
	// The pointers that sit in no vector denominator, named rather than left for the operator to
	// discover by finding that 43 pointers do not fit across 28 vectors.
	offCorpus := ""
	if n := cov.Vectors.PointersWithoutVector + cov.Vectors.PointersOffCorpus; n > 0 {
		offCorpus = fmt.Sprintf(", plus %d on no vector in this corpus", n)
	}
	return fmt.Sprintf(
		"%d pointers across %d of %d vectors%s. %d vectors have no conclusion from any source (concluded: %s), and %d of %d probe rows are unknown rather than clean.",
		total, cov.Vectors.WithPointer, cov.Vectors.Total, offCorpus,
		cov.Vectors.Unknown, pointerConcludedPhrase(cov.Vectors.ConcludedBySource),
		cov.Reflection.Unknown, cov.Reflection.ProbeRows)
}

// pointerSourceLabel is the source's name in a sentence. The constants are wire values and read
// like them.
func pointerSourceLabel(source string) string {
	switch source {
	case PointerSourceReflection:
		return "reflection probe"
	case PointerSourceFinding:
		return "prior finding"
	case PointerSourceTriage:
		return "triage"
	}
	return source
}

// pointerConcludedPhrase names which source concluded what, in PointerSourceOrder and including
// the zeros, because a source that is absent from the phrase reads as a source that does not
// exist.
//
// A ZERO HERE IS NOT SELF EXPLANATORY and must never be read as one. "triage 0" is produced by a
// target nobody has run triage on, by a run still in flight, by a run that was cancelled or
// errored, and by a run that finished and concluded nothing positive. Which of those it is lives
// in coverage.triage.status and coverage.triage.note, both derived from the rows by
// triageCoverageStatus and triageCoverageNote.
func pointerConcludedPhrase(by map[string]int) string {
	parts := make([]string, 0, len(by))
	for _, source := range PointerSourceOrder() {
		parts = append(parts, fmt.Sprintf("%s %d", pointerSourceLabel(source), by[source]))
	}
	return strings.Join(parts, ", ")
}

// pointerVectorCoverage counts vectors, not rows, because a vector is the unit the operator selects
// for a scan.
//
// THE GRADE BREAKDOWN COMES FROM reflectionGradeCountsDetailed, the same function the reflection
// status endpoint reads. Concluded and Unknown are derived from it rather than from a second SQL
// CASE expression, so the pointers card and the XSS card cannot report different denominators for
// the same corpus.
func pointerVectorCoverage(ctx context.Context, scopeTargetID string, pointers []Pointer) (PointerVectorCoverage, error) {
	// The empty shape, returned on the error paths below so a caller never gets nil maps.
	out := PointerVectorCoverage{ByGrade: map[string]int{}, ConcludedBySource: map[string]int{}}

	// One pass over the corpus for the denominator AND the per-vector reflection status, so the
	// union below can be taken by identity rather than by subtracting two counts that were never
	// counting the same vectors.
	rows, err := dbPool.Query(ctx, `
		SELECT id::text, COALESCE(reflection_status,'')
		FROM attack_vectors
		WHERE scope_target_id = $1 AND deleted_at IS NULL`, scopeTargetID)
	if err != nil {
		return out, fmt.Errorf("pointers: vector coverage: %w", err)
	}
	defer rows.Close()
	status := map[string]string{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			return out, fmt.Errorf("pointers: scan vector coverage row: %w", err)
		}
		status[id] = st
	}
	if err := rows.Err(); err != nil {
		return out, fmt.Errorf("pointers: read vector coverage rows: %w", err)
	}
	// The grade breakdown stays reflectionGradeCountsDetailed's, the same function the reflection
	// status endpoint reads, so the two cards cannot report different grades for one corpus. Its
	// unknown count and Total minus ConcludedBySource[reflection] are the same number by
	// construction: both are XSSCandidateGrade over the same statuses.
	byGrade, _ := reflectionGradeCountsDetailed(ctx, scopeTargetID)

	out = pointerVectorCoverageFrom(status, pointers)
	for grade, n := range byGrade {
		out.ByGrade[grade] = n
	}
	return out, nil
}

// pointerVectorCoverageFrom is the arithmetic on its own, with the corpus as a map from vector id
// to reflection status, so the union can be tested without a database. Everything the headline
// asserts is decided here.
func pointerVectorCoverageFrom(status map[string]string, pointers []Pointer) PointerVectorCoverage {
	out := PointerVectorCoverage{ByGrade: map[string]int{}, ConcludedBySource: map[string]int{}}
	for _, s := range PointerSourceOrder() {
		// Every source present even at zero, for the reason countPointers gives: an absent key
		// reads as "not a thing" and a zero reads as "nothing found there yet".
		out.ConcludedBySource[s] = 0
	}
	out.Total = len(status)

	concluded := map[string]bool{}
	for id, st := range status {
		if pointerStatusConcluded(st) {
			concluded[id] = true
			out.ConcludedBySource[PointerSourceReflection]++
		}
	}

	withPointer := map[string]bool{}
	bySource := map[string]map[string]bool{}
	for _, p := range pointers {
		id := strings.TrimSpace(p.VectorID)
		if id == "" {
			out.PointersWithoutVector++
			continue
		}
		if _, ok := status[id]; !ok {
			out.PointersOffCorpus++
			continue
		}
		withPointer[id] = true
		// A POINTER IS A CONCLUSION. Its source looked at this vector and said "there is evidence
		// here", which is the opposite of not knowing, whatever the reflection probe made of it.
		concluded[id] = true
		if bySource[p.Source] == nil {
			bySource[p.Source] = map[string]bool{}
		}
		bySource[p.Source][id] = true
	}
	for source, ids := range bySource {
		if source == PointerSourceReflection {
			// Already counted above, and counted wider: the probe concluded on the vectors it
			// graded a measured negative too, and those carry no pointer.
			continue
		}
		out.ConcludedBySource[source] = len(ids)
	}

	out.WithPointer = len(withPointer)
	out.Concluded = len(concluded)
	out.Unknown = out.Total - out.Concluded
	return out
}

// pointerStatusConcluded answers "did the reflection probe reach a claim about this vector", and it
// answers it BY CALLING THE GRADE FUNCTION rather than by listing the statuses again.
//
// The empty content type and nil survived set are safe inputs for this one question. Every branch
// of XSSCandidateGrade that reads them is already inside a status that concludes: the raw branch
// chooses between high, chain and low, and no value of either can turn a concluding status into
// xss_unknown. TestConcludedIsStatusAloneWhateverTheContentType locks that invariant, because if
// the grade rule ever gains a content-type path to unknown, this would start calling an unknown a
// conclusion, which is the false clean the whole file exists to prevent.
func pointerStatusConcluded(status string) bool {
	return XSSCandidateGrade(status, "", nil, "") != XSSCandidateUnknown
}

// ---------------------------------------------------------------------------------------------
// Source 1: the reflection probe
// ---------------------------------------------------------------------------------------------

// collectReflectionPointers turns reflection probe rows into XSS pointers, and counts everything
// that did not become one.
//
// THE GRADE COMES FROM XSSCandidateGrade, the same call the reflection results endpoint makes on
// the same columns. It is not re-derived here: a second derivation is how this codebase got two
// screens disagreeing about one row.
//
// A ROW IS A POINTER WHEN ITS GRADE IS ABOVE none. xss_candidate_none is a measured negative and
// xss_unknown is not a claim either way, so neither points anywhere. The unknowns are not dropped:
// they are counted in UnknownByReason under the status that produced them, which on this corpus is
// 1555 is_credential, 110 error and 49 probe_refused.
func collectReflectionPointers(ctx context.Context, scopeTargetID string) ([]Pointer, PointerReflectionCoverage, error) {
	cov := PointerReflectionCoverage{
		ByStatus: map[string]int{}, ByGrade: map[string]int{}, UnknownByReason: map[string]int{},
		RunStatus: "never_run",
	}
	_ = dbPool.QueryRow(ctx, `
		SELECT status FROM vector_reflection_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).Scan(&cov.RunStatus)

	rows, err := dbPool.Query(ctx, `
		SELECT p.id::text, p.vector_id::text, COALESCE(p.parameter,''),
		       COALESCE(p.insertion_point,''), p.status, COALESCE(p.survived, ARRAY[]::text[]),
		       COALESCE(p.content_type,''), p.http_status, COALESCE(p.evidence,''),
		       COALESCE(p.detail,''), COALESCE(p.probe_url,''), COALESCE(p.evidence_source,'active'),
		       COALESCE(av.method,'GET'), COALESCE(av.domain,''), COALESCE(av.path,'/'),
		       COALESCE(av.evidence_url,''), COALESCE(av.scheme,'https')
		FROM vector_reflection_probes p
		JOIN attack_vectors av ON av.id = p.vector_id
		WHERE p.scope_target_id = $1 AND av.deleted_at IS NULL`, scopeTargetID)
	if err != nil {
		return nil, cov, fmt.Errorf("pointers: reflection rows: %w", err)
	}
	defer rows.Close()

	out := []Pointer{}
	for rows.Next() {
		var id, vectorID, param, point, status, contentType, evidence, detail string
		var probeURL, evidenceSource, method, domain, path, evidenceURL, scheme string
		var survived []string
		var httpStatus int
		if err := rows.Scan(&id, &vectorID, &param, &point, &status, &survived, &contentType,
			&httpStatus, &evidence, &detail, &probeURL, &evidenceSource,
			&method, &domain, &path, &evidenceURL, &scheme); err != nil {
			return nil, cov, fmt.Errorf("pointers: scan reflection row: %w", err)
		}
		cov.ProbeRows++
		cov.ByStatus[status]++

		grade := XSSCandidateGrade(status, contentType, survived, point)
		cov.ByGrade[grade]++
		if grade == XSSCandidateUnknown {
			cov.Unknown++
			cov.UnknownByReason[status]++
			continue
		}
		if grade == XSSCandidateNone {
			continue
		}

		// PROVENANCE IS THE PASS THAT PRODUCED THE ROW, not a guess from the status. A passive row
		// is a value the crawl already sent found in a body the crawl already stored, which is
		// ProvenancePassiveCorpus by that constant's own definition. An active row is a canary this
		// framework sent and read back, and a canary that comes back CANNOT have been in the
		// baseline, so it is the delta EvidenceRank's top rank is about.
		provenance := ProvenanceNativeProbe
		deltaChecked := true
		sourceDetail := "active reflection pass: a canary was sent and read back"
		if evidenceSource == "passive" {
			provenance = ProvenancePassiveCorpus
			deltaChecked = false
			sourceDetail = "passive reflection pass: no request was sent, the value was found in a stored response"
		}
		// pointerReflectionURL carries the stale-probe_url rule. See its comment: a passive row's
		// probe_url is an earlier active attempt's canary URL on 19 of the 34 passive rows here.
		pointerURL, urlOrigin, urlNote := pointerReflectionURL(
			evidenceSource, probeURL, evidenceURL, scheme, domain, path)
		rank := EvidenceRank(provenance, deltaChecked)

		class := triage.ClassXSSReflected.String()
		nextTool, nextReason := pointerNextTool(class)
		p := Pointer{
			ID:               PointerSourceReflection + ":" + id,
			Source:           PointerSourceReflection,
			SourceDetail:     sourceDetail,
			AttackClass:      class,
			AttackClassLabel: pointerClassLabel(class),
			Grade:            grade,
			GradeSource:      "XSSCandidateGrade, the server's own reflection grade, carried unchanged",
			Strength:         pointerStrengthFor(rank),
			StrengthRank:     rank,
			DeltaChecked:     deltaChecked,
			VectorID:         vectorID,
			Method:           method,
			URL:              pointerURL,
			URLOrigin:        urlOrigin,
			URLNote:          urlNote,
			Domain:           domain,
			Path:             path,
			InsertionPoint:   point,
			Parameter:        param,
			Rule:             reflectionPointerRule(status, evidenceSource),
			Evidence:         evidence,
			HTTPStatus:       httpStatus,
			ContentType:      contentType,
			Deliverable:      pointerDeliverable(class, point),
			DeliveryNote:     pointerDeliveryNote(class, nextTool, point),
			NextTool:         nextTool,
			NextToolReason:   nextReason,
			severity:         grade,
			rowID:            id,
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, cov, fmt.Errorf("pointers: read reflection rows: %w", err)
	}
	return out, cov, nil
}

// reflectionPointerRule states what fired, in the words of the pass that fired it.
func reflectionPointerRule(status, evidenceSource string) string {
	switch status {
	case ReflectionRaw:
		return "The canary came back with at least one of < > \" ' intact, in a response a browser parses as markup."
	case ReflectionObserved:
		if evidenceSource == "passive" {
			return "A value the crawl sent was found echoed in the response the crawl stored. The escaping was never tested, because nothing dangerous was ever sent."
		}
		return "The input was observed echoed in the response."
	case ReflectionEncoded:
		return "The canary came back encoded."
	}
	return "Reflection probe status " + status + "."
}

// ---------------------------------------------------------------------------------------------
// Source 2: findings a tool already wrote
// ---------------------------------------------------------------------------------------------

// collectFindingPointers turns prior vector_findings rows into pointers.
//
// TWO EXCLUSIONS, BOTH COUNTED IN COVERAGE RATHER THAN SILENT.
//
//  1. THE POSITIVE CONTROL. Every run first fires the tool at the oracle container, a service this
//     framework runs and knows is vulnerable, to prove the tool works before believing its zero.
//     MEASURED on this corpus: 390 of 415 stored findings are oracle hits, including 223 of 223
//     dalfox, 126 of 126 sqlmap, 21 of 21 domdig and 8 of 9 xssfuzz. Listing those as pointers
//     would hand the operator 390 "spend an hour here" rows pointing at the framework's own test
//     fixture. findingIsCanary is the same filter the findings modal uses, called rather than
//     copied, and it is applied to the URL THE POINTER WILL CARRY so a row with an empty url
//     column cannot slip through it. The count is reported per tool in coverage rather than
//     dropped silently.
//
//  2. A DISMISSED FINDING. Triage means "worth testing deeply", and the operator has already said
//     this one is not. Severity is NOT the same as pointer strength, so a dismissed critical is
//     still not a pointer and an undismissed info still is one.
func collectFindingPointers(ctx context.Context, scopeTargetID string) ([]Pointer, PointerFindingCoverage, error) {
	cov := PointerFindingCoverage{
		CanaryHost:   canaryHost(),
		RowsByTool:   map[string]int{},
		CanaryByTool: map[string]int{},
	}
	rows, err := dbPool.Query(ctx, `
		SELECT f.id::text, COALESCE(f.vector_id::text,''), f.tool, f.kind, f.severity,
		       f.confidence, f.insertion_point, f.param, f.payload, f.method, f.url, f.evidence,
		       f.detection_method, f.triage, f.raw_request, f.raw_response,
		       COALESCE(av.domain,''), COALESCE(av.path,''), COALESCE(av.method,''),
		       COALESCE(av.raw_request,''), COALESCE(av.evidence_url,''),
		       COALESCE(av.scheme,'https')
		FROM vector_findings f
		JOIN vector_scans s ON s.id = f.scan_id
		LEFT JOIN attack_vectors av ON av.id = f.vector_id
		WHERE s.scope_target_id = $1`, scopeTargetID)
	if err != nil {
		return nil, cov, fmt.Errorf("pointers: finding rows: %w", err)
	}
	defer rows.Close()

	out := []Pointer{}
	for rows.Next() {
		var f struct {
			ID, VectorID, Tool, Kind, Severity, Confidence  string
			Point, Param, Payload, Method, URL, Evidence    string
			DetectionMethod, Triage, RawReq, RawResp        string
			Domain, VecPath, VecMethod, VecRawReq, VecEvURL string
			VecScheme                                       string
		}
		if err := rows.Scan(&f.ID, &f.VectorID, &f.Tool, &f.Kind, &f.Severity, &f.Confidence,
			&f.Point, &f.Param, &f.Payload, &f.Method, &f.URL, &f.Evidence, &f.DetectionMethod,
			&f.Triage, &f.RawReq, &f.RawResp, &f.Domain, &f.VecPath, &f.VecMethod,
			&f.VecRawReq, &f.VecEvURL, &f.VecScheme); err != nil {
			return nil, cov, fmt.Errorf("pointers: scan finding row: %w", err)
		}
		cov.Rows++
		cov.RowsByTool[f.Tool]++

		// THE CONTROL FILTER IS APPLIED TO THE URL THE POINTER WILL CARRY, not to the finding's own
		// url column. A finding stored with an empty url was invisible to findingIsCanary and came
		// back false, so a control hit whose runner forgot to store a URL would have been listed as
		// a pointer at the framework's own test fixture. The effective URL is resolved first and
		// the host check runs on that, so the exclusion holds for every tool rather than only for
		// the tools that happen to fill the column.
		pointerURL, urlOrigin, urlNote := pointerURLWithOrigin(
			f.URL, PointerURLFromTool, f.VecEvURL, f.VecScheme, f.Domain, f.VecPath)
		if findingIsCanary(pointerURL) {
			cov.ExcludedCanary++
			cov.CanaryByTool[f.Tool]++
			continue
		}
		if urlOrigin == PointerURLNone {
			// No URL from any source, so the control could not be checked either way. Kept, and
			// counted, because dropping it would be the false negative and hiding it would be the
			// false clean.
			cov.CanaryUncheckable++
		}
		if strings.EqualFold(strings.TrimSpace(f.Triage), "dismissed") {
			cov.ExcludedDismiss++
			continue
		}

		// ProvenancePriorFinding by that constant's own definition: a vector_findings row from an
		// earlier scan, useful as a pointer and worthless as a measurement of the application as it
		// is today. Which is exactly what this list is for.
		rank := EvidenceRank(ProvenancePriorFinding, false)
		class := pointerClassForFinding(f.Tool, f.Kind)
		nextTool, nextReason := pointerNextTool(class)
		point := strings.TrimSpace(f.Point)

		p := Pointer{
			ID:               PointerSourceFinding + ":" + f.ID,
			Source:           PointerSourceFinding,
			SourceDetail:     fmt.Sprintf("%s reported %s on an earlier scan", f.Tool, firstNonEmpty(f.Kind, "a finding")),
			AttackClass:      class,
			AttackClassLabel: pointerClassLabel(class),
			Grade:            strings.TrimSpace(f.Severity),
			GradeSource:      f.Tool + "'s own severity, stored unchanged. It is the tool's claim about impact if true, not a measure of how likely it is to be true.",
			Strength:         pointerStrengthFor(rank),
			StrengthRank:     rank,
			DeltaChecked:     false,
			VectorID:         f.VectorID,
			Method:           firstNonEmpty(f.Method, f.VecMethod, "GET"),
			URL:              pointerURL,
			URLOrigin:        urlOrigin,
			URLNote:          urlNote,
			Domain:           f.Domain,
			Path:             f.VecPath,
			InsertionPoint:   point,
			Parameter:        f.Param,
			Rule:             findingPointerRule(f.Tool, f.Kind, f.DetectionMethod),
			Evidence:         f.Evidence,
			ContentType:      "",
			Deliverable:      pointerDeliverable(class, point),
			DeliveryNote:     pointerDeliveryNote(class, firstNonEmpty(nextTool, f.Tool), point),
			NextTool:         nextTool,
			NextToolReason:   nextReason,
			severity:         f.Severity,
			rowID:            f.ID,
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, cov, fmt.Errorf("pointers: read finding rows: %w", err)
	}
	cov.Pointers = len(out)
	cov.Note = pointerCanaryNote(cov)
	return out, cov, nil
}

// pointerCanaryNote states the exclusion WITH ITS ARITHMETIC, per tool, because an exclusion this
// large is the one number on the card an operator is entitled to disbelieve. On the measured corpus
// it reads: 390 of 415 stored findings were the positive control at oracle:8000 (dalfox 223 of 223,
// sqlmap 126 of 126, domdig 21 of 21, xssfuzz 8 of 9, ghauri 4 of 4, and so on).
func pointerCanaryNote(cov PointerFindingCoverage) string {
	note := fmt.Sprintf(
		"The positive control fires every tool at the framework's own oracle container first, so those hits prove the tool works and are never pointers. %d of %d stored findings here were that control, matched on host %s.",
		cov.ExcludedCanary, cov.Rows, firstNonEmpty(cov.CanaryHost, "an unset canary host"))
	tools := make([]string, 0, len(cov.RowsByTool))
	for tool := range cov.RowsByTool {
		tools = append(tools, tool)
	}
	sort.Slice(tools, func(i, j int) bool {
		if cov.RowsByTool[tools[i]] != cov.RowsByTool[tools[j]] {
			return cov.RowsByTool[tools[i]] > cov.RowsByTool[tools[j]]
		}
		return tools[i] < tools[j]
	})
	parts := make([]string, 0, len(tools))
	for _, tool := range tools {
		parts = append(parts, fmt.Sprintf("%s %d of %d", tool, cov.CanaryByTool[tool], cov.RowsByTool[tool]))
	}
	if len(parts) > 0 {
		note += " Per tool: " + strings.Join(parts, ", ") + "."
	}
	if cov.CanaryUncheckable > 0 {
		note += fmt.Sprintf(" %d finding(s) carry no URL from any source, so the control filter could not be applied to them. They are kept as pointers rather than dropped.",
			cov.CanaryUncheckable)
	}
	if cov.CanaryHost == "" {
		note += " ARS0N_CANARY_HOST is unset, so nothing could be excluded as the control."
	}
	return note
}

// findingPointerRule states what fired, using the tool's own vocabulary and its stable axis.
// vectorKindLabel is the framework's existing renderer for a kind, called rather than copied, and
// detection_method is named beside it because dalfox's own integrator guidance says the method is
// the stable field and the type letter is not.
func findingPointerRule(tool, kind, detectionMethod string) string {
	rule := fmt.Sprintf("%s reported %s", tool, vectorKindLabel(tool, kind))
	if d := strings.TrimSpace(detectionMethod); d != "" {
		rule += fmt.Sprintf(", by detection method %s", d)
	}
	return rule + "."
}

// ---------------------------------------------------------------------------------------------
// Source 3: triage verdicts
// ---------------------------------------------------------------------------------------------

// collectTriagePointers reads the triage tables and reports, from those rows alone, what triage
// did and did not measure on this target.
//
// NOTHING IN THIS FUNCTION DESCRIBES THE STATE OF THE TRIAGE RUNNER. The status and the sentence
// the operator reads are both computed by triageCoverageStatus and triageCoverageNote from the
// counters, AFTER they have been filled, which is why they cannot fall out of date.
//
// THREE RULES, all of them from triage's own vocabulary rather than from this file:
//
//   - Only a POSITIVE state is a pointer. triage.TriageState.Kind is the authority, and
//     StateFinding's own meaning row reads "point the tool here".
//   - A verdict whose payload is unproven is NEITHER a pointer NOR a clean. It is an unknown, and
//     it is counted as one. The gate is triageUnprovenFidelity, the one definition in the store,
//     interpolated rather than rewritten.
//   - is_unknown is triage's own column, written from the Go rule table, so it is read and not
//     recomputed.
func collectTriagePointers(ctx context.Context, scopeTargetID string) ([]Pointer, PointerTriageCoverage, error) {
	var cov PointerTriageCoverage

	// THE RUN ROW, WITH ITS PROGRESS COLUMNS, in one query. The previous version selected the id
	// alone and then described the source in prose, which is how the prose came to disagree with
	// the database.
	err := dbPool.QueryRow(ctx, `
		SELECT id::text, status, phase, planned_pairs, completed_pairs, probes_sent, created_at::text
		FROM triage_runs WHERE scope_target_id = $1
		ORDER BY created_at DESC LIMIT 1`, scopeTargetID).
		Scan(&cov.RunID, &cov.RunStatus, &cov.RunPhase, &cov.PlannedPairs, &cov.CompletedPairs,
			&cov.ProbesSent, &cov.StartedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No run on this target. Not an error and not a clean: the derived note says which, and
		// names the button that would fix it.
		return []Pointer{}, triageCoverageFinish(cov), nil
	case err != nil:
		// AN UNREADABLE TABLE IS NOT AN EMPTY ONE, and this is the path that used to be folded
		// into the one above: any failure at all, a missing migration or a dead connection
		// included, returned exactly the zeros a target nobody had triaged returns. Reported
		// rather than returned as an error, because the other two sources have real pointers to
		// show and failing the whole endpoint would hide those as well.
		cov.ReadError = err.Error()
		return []Pointer{}, triageCoverageFinish(cov), nil
	}
	runUUID := cov.RunID

	// The counters. A failure here is recorded rather than dropped: this was a bare underscore
	// assignment, so counts nobody could read rendered as zero slots, zero pairs, zero verdicts.
	if err := dbPool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM triage_slots WHERE run_id = $1),
		       (SELECT count(*) FROM triage_coverage WHERE run_id = $1),
		       (SELECT count(*) FROM triage_verdicts WHERE run_id = $1),
		       (SELECT count(*) FROM triage_verdicts WHERE run_id = $1 AND is_unknown)`,
		runUUID).Scan(&cov.Slots, &cov.Pairs, &cov.Verdicts, &cov.Unknown); err != nil {
		cov.ReadError = err.Error()
	}

	unprovenForThisPair := `
			SELECT count(*) FROM triage_fidelity fid
			WHERE fid.run_id = v.run_id AND fid.vector_id = v.vector_id
			  AND fid.slot_key = v.slot_key AND fid.class_id = v.class_id
			  AND ` + triageUnprovenFidelity

	rows, err := dbPool.Query(ctx, `
		SELECT v.id::text, v.vector_id, v.slot_key, v.class_id, v.class_name, v.arm, v.state,
		       v.state_kind, v.is_unknown, v.reason, v.grade, v.oracle, v.provenance,
		       v.provenance_detail, v.delta_checked, COALESCE(v.evidence_phrase,''),
		       (`+unprovenForThisPair+`),
		       COALESCE(av.method,'GET'), COALESCE(av.domain,''), COALESCE(av.path,''),
		       COALESCE(av.evidence_url,''), COALESCE(av.insertion_point,''),
		       COALESCE(av.scheme,'https')
		FROM triage_verdicts v
		LEFT JOIN attack_vectors av ON av.id::text = v.vector_id
		WHERE v.run_id = $1`, runUUID)
	if err != nil {
		return nil, cov, fmt.Errorf("pointers: triage verdicts: %w", err)
	}
	defer rows.Close()

	out := []Pointer{}
	for rows.Next() {
		var id, vectorID, slotKey, className, arm, state, stateKind, reason, grade string
		var oracle, provenance, provenanceDetail, phrase string
		var method, domain, path, evidenceURL, vectorPoint, scheme string
		var classID int16
		var isUnknown, deltaChecked bool
		var unproven int
		if err := rows.Scan(&id, &vectorID, &slotKey, &classID, &className, &arm, &state,
			&stateKind, &isUnknown, &reason, &grade, &oracle, &provenance, &provenanceDetail,
			&deltaChecked, &phrase, &unproven, &method, &domain, &path, &evidenceURL,
			&vectorPoint, &scheme); err != nil {
			return nil, cov, fmt.Errorf("pointers: scan triage verdict: %w", err)
		}
		if unproven > 0 {
			// NEITHER A POINTER NOR A CLEAN. The payload cannot be shown to have reached the wire
			// as asked, so whatever the class concluded is an unknown, and it is counted as one.
			cov.PayloadUnproven++
			continue
		}
		if isUnknown || triage.TriageState(state).Kind() != triage.StateKindPositive {
			continue
		}
		cov.Positive++

		rank := EvidenceRank(TriageProvenance(provenance), deltaChecked)
		class := firstNonEmpty(className, triage.ClassID(classID).String())
		nextTool, nextReason := pointerNextTool(class)
		point := firstNonEmpty(triageSlotInsertionPoint(slotKey), vectorPoint)
		// A triage verdict stores no URL of its own: the request it sent is in triage_fidelity and
		// the detail endpoint reads it from there. So the list URL is the vector's, captured or
		// composed, and it says which.
		pointerURL, urlOrigin, urlNote := pointerURLWithOrigin("", "", evidenceURL, scheme, domain, path)

		out = append(out, Pointer{
			ID:               PointerSourceTriage + ":" + id,
			Source:           PointerSourceTriage,
			SourceDetail:     fmt.Sprintf("triage class %s, state %s, provenance %s", class, state, firstNonEmpty(provenance, "unnamed")),
			AttackClass:      class,
			AttackClassLabel: pointerClassLabel(class),
			Grade:            grade,
			GradeSource:      "triage's own grade, written by the classifier and carried unchanged",
			Strength:         pointerStrengthFor(rank),
			StrengthRank:     rank,
			DeltaChecked:     deltaChecked,
			VectorID:         vectorID,
			Method:           method,
			URL:              pointerURL,
			URLOrigin:        urlOrigin,
			URLNote:          urlNote,
			Domain:           domain,
			Path:             path,
			InsertionPoint:   point,
			Parameter:        triageSlotName(slotKey),
			SlotKey:          slotKey,
			Rule:             triagePointerRule(class, state, arm, oracle, reason),
			Evidence:         phrase,
			Deliverable:      pointerDeliverable(class, point),
			DeliveryNote:     pointerDeliveryNote(class, nextTool, point),
			NextTool:         nextTool,
			NextToolReason:   nextReason,
			severity:         string(grade),
			rowID:            id,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, cov, fmt.Errorf("pointers: read triage verdicts: %w", err)
	}
	return out, triageCoverageFinish(cov), nil
}

// triageCoverageFinish stamps the derived Status and Note onto the coverage block. It is called on
// every return path and nowhere else, so the sentence an operator reads is always computed from
// the counters as they finally stand rather than written before they were filled.
func triageCoverageFinish(cov PointerTriageCoverage) PointerTriageCoverage {
	cov.Status = triageCoverageStatus(cov)
	cov.Note = triageCoverageNote(cov)
	return cov
}

// triageCoverageStatus DERIVES the status from the rows that were read. The order matters: a read
// that failed outranks anything the numbers appear to say, because numbers nobody could read are
// not zeros.
func triageCoverageStatus(cov PointerTriageCoverage) string {
	switch {
	case cov.ReadError != "":
		return PointerTriageUnreadable
	case !cov.HasRun():
		return PointerTriageNoRun
	case cov.RunStatus == "running":
		return PointerTriageRunning
	case cov.RunStatus == "cancelled":
		return PointerTriageCancelled
	case cov.RunStatus == "error":
		return PointerTriageRunFailed
	}
	return PointerTriageRead
}

// triageCoverageNote WRITES THE SENTENCE FROM THE NUMBERS.
//
// There is no literal here that asserts anything about the triage runner, and there must never be
// one: the sentence this function replaced said the runner was "built and not yet wired" and went
// on saying it after the runner was wired and probing. Every branch below is selected by data, so
// the day the data changes the sentence changes with it.
func triageCoverageNote(cov PointerTriageCoverage) string {
	switch triageCoverageStatus(cov) {
	case PointerTriageUnreadable:
		what := "The triage tables"
		if cov.HasRun() {
			what = "Triage run " + cov.RunID
		}
		return fmt.Sprintf("%s could not be read in full (%s), so the triage numbers here are incomplete. An unread count is not a zero, and nothing in this source is a clean result.",
			what, cov.ReadError)
	case PointerTriageNoRun:
		return "No triage run has been started for this scope target, so no pointer in this list comes from triage. Press Investigate to run the classifiers. That is a gap in coverage, not a clean result."
	}

	note := fmt.Sprintf(
		"Triage run %s (%s): %d slots, %d covered pairs, %d verdicts, of which %d positive became pointers, %d are unknown and %d rest on a payload that cannot be shown to have reached the wire. %d probes sent across %d of %d planned pairs.",
		cov.RunID, cov.RunStatus, cov.Slots, cov.Pairs, cov.Verdicts, cov.Positive, cov.Unknown,
		cov.PayloadUnproven, cov.ProbesSent, cov.CompletedPairs, cov.PlannedPairs)

	switch triageCoverageStatus(cov) {
	case PointerTriageRunning:
		phase := strings.TrimSpace(cov.RunPhase)
		if phase == "" {
			phase = "an unnamed phase"
		}
		note += fmt.Sprintf(" The run is still going (%s), so these counts are a snapshot and every pair it has not reached yet is unmeasured rather than clean.", phase)
	case PointerTriageCancelled:
		note += " The run was cancelled before it finished, so every pair it did not reach is unmeasured rather than clean."
	case PointerTriageRunFailed:
		note += " The run ended in an error, so every pair it did not reach is unmeasured rather than clean."
	default:
		switch {
		case !cov.HasVerdicts():
			note += " The run finished and recorded no verdict at all, which is a gap in coverage and not a clean result."
		case cov.Positive == 0:
			note += " The run finished and reached no positive state, so triage contributed no pointer. Read that against the unknown count above rather than as a clean bill."
		}
	}
	return note
}

// triagePointerRule states what fired, in triage's own words.
func triagePointerRule(class, state, arm, oracle, reason string) string {
	rule := fmt.Sprintf("Triage class %s reached state %s", class, state)
	if a := strings.TrimSpace(arm); a != "" {
		rule += " on arm " + a
	}
	if o := strings.TrimSpace(oracle); o != "" {
		rule += fmt.Sprintf(", oracle %s", o)
	}
	rule += "."
	if r := strings.TrimSpace(reason); r != "" {
		rule += " Reason: " + r
	}
	return rule
}

// triageSlotInsertionPoint reads the insertion point out of a slot key such as "query:sort" or
// "path:2:*".
//
// IT VALIDATES AGAINST THE PROBED POINTS rather than returning whatever sits before the first
// colon. Four triage classes address something larger than a slot (a host, a vector, a container, a
// body document) and their key is not a slot grammar at all, so parsing one of those as an
// insertion point would invent a point that does not exist. An unrecognised prefix returns empty,
// and the caller falls back to the vector's own recorded point.
func triageSlotInsertionPoint(slotKey string) string {
	prefix := slotKey
	if i := strings.IndexByte(slotKey, ':'); i >= 0 {
		prefix = slotKey[:i]
	}
	prefix = strings.ToLower(strings.TrimSpace(prefix))
	for _, known := range ReflectionProbedPoints() {
		if prefix == known {
			return prefix
		}
	}
	return ""
}

// triageSlotName reads the parameter name out of a slot key, and returns empty when the key is not
// a slot grammar, for the reason triageSlotInsertionPoint records.
func triageSlotName(slotKey string) string {
	if triageSlotInsertionPoint(slotKey) == "" {
		return ""
	}
	if i := strings.IndexByte(slotKey, ':'); i >= 0 {
		return slotKey[i+1:]
	}
	return ""
}

// ---------------------------------------------------------------------------------------------
// The detail
// ---------------------------------------------------------------------------------------------

// buildPointerDetail fetches the bytes behind one pointer and assembles the full record.
func buildPointerDetail(ctx context.Context, p Pointer) (PointerDetail, error) {
	d := PointerDetail{Pointer: p, Path: pointerAttackPath(p)}
	switch p.Source {
	case PointerSourceReflection:
		return reflectionPointerDetail(ctx, p, d)
	case PointerSourceFinding:
		return findingPointerDetail(ctx, p, d)
	case PointerSourceTriage:
		return triagePointerDetail(ctx, p, d)
	}
	return d, fmt.Errorf("pointers: unknown source %q", p.Source)
}

// reflectionPointerDetail fills in the reflection pointer's evidence.
//
// THE RESPONSE IS A SNIPPET AND IS LABELLED AS ONE. vector_reflection_probes stores a window around
// the match rather than the whole body, and calling that "the response" would let an operator
// conclude from its absence that something was not in the response.
//
// THE CANARY COLUMN IS READ AND THEN USED ONLY ON THE ACTIVE BRANCH, for the reason
// pointerReflectionURL records: the passive pass overwrites status, evidence and detail on a row
// keyed (vector_id, parameter) and leaves probe_url and canary holding an earlier active attempt's
// values. All 34 passive rows on the measured corpus carry such a canary. Nothing this function
// emits for a passive row may come from either column.
func reflectionPointerDetail(ctx context.Context, p Pointer, d PointerDetail) (PointerDetail, error) {
	var evidenceSource, canary, detail, vectorRawRequest string
	err := dbPool.QueryRow(ctx, `
		SELECT COALESCE(pr.evidence_source,'active'), COALESCE(pr.canary,''), COALESCE(pr.detail,''),
		       COALESCE(av.raw_request,'')
		FROM vector_reflection_probes pr
		JOIN attack_vectors av ON av.id = pr.vector_id
		WHERE pr.id = $1`, p.rowID).Scan(&evidenceSource, &canary, &detail, &vectorRawRequest)
	if err != nil {
		return d, fmt.Errorf("pointers: reflection detail: %w", err)
	}

	d.Request = PointerEvidenceBlob{
		Raw:    vectorRawRequest,
		Origin: FindingRequestOrigin(vectorRawRequest),
		Note: "The vector's captured request, which is where the real cookies, headers and body are. " +
			"It is not the probe's own request: the probe substitutes one value into this.",
	}
	if evidenceSource == "passive" {
		d.Response = PointerEvidenceBlob{
			Raw:    p.Evidence,
			Origin: "evidence_snippet",
			Note:   "A window around the match in a response the crawl had already stored. Not the whole body.",
		}
		d.Baseline = PointerBaseline{
			Compared: false,
			What: "None. The passive pass compares nothing: it looks for a value the crawl already sent in a response the crawl already stored. " +
				"That is why this ranks at the bottom of the evidence order.",
		}
	} else {
		d.Response = PointerEvidenceBlob{
			Raw:    p.Evidence,
			Origin: "evidence_snippet",
			Note:   "A window around the canary in the probe's own response. Not the whole body.",
		}
		d.Baseline = PointerBaseline{
			Compared: true,
			What: "The canary " + canary + ". A unique token the application had never seen cannot have been in the response before the probe sent it, " +
				"so finding it there is a measured difference and not a signature match.",
		}
	}

	d.Rule = PointerRule{
		Fired: p.Rule,
		Means: "This input reaches the response body. Whether it reaches it in a position that executes is the next question, and it is the one this probe did not ask.",
		DidNotEstablish: "Execution. " + detail +
			" Nothing here says a browser parses the payload as markup, and on a passive row nothing dangerous was ever sent.",
	}
	d.Grade = PointerGrade{
		Value:  p.Grade,
		Source: p.GradeSource,
		Why:    reflectionGradeWhy(p),
	}
	return d, nil
}

// reflectionGradeWhy explains the grade in terms of the three things XSSCandidateGrade reads: the
// status, whether the content type renders, and whether the insertion point is attacker-deliverable.
func reflectionGradeWhy(p Pointer) string {
	renders := ReflectionContentTypeRenders(p.ContentType)
	parts := []string{fmt.Sprintf("Graded %s.", p.Grade)}
	if renders {
		parts = append(parts, fmt.Sprintf("A browser parses %s as markup, so there is somewhere for a payload to render.",
			firstNonEmpty(p.ContentType, "a response with no content type, which is MIME sniffed")))
	} else {
		parts = append(parts, fmt.Sprintf("A browser does not render %s, so a payload here has nowhere to execute unless the content type can be moved.", p.ContentType))
	}
	if !p.Deliverable {
		parts = append(parts, "The insertion point is one the victim's own browser sets, so this is self-XSS until a chain is named.")
	}
	return strings.Join(parts, " ")
}

// findingPointerDetail fills in a prior finding's evidence, reusing the framework's own
// reproduction builder and explanation reference so this screen and the findings modal agree.
func findingPointerDetail(ctx context.Context, p Pointer, d PointerDetail) (PointerDetail, error) {
	var tool, kind, payload, rawReq, rawResp, evidence, vecRawReq, vecEvURL string
	err := dbPool.QueryRow(ctx, `
		SELECT f.tool, f.kind, f.payload, f.raw_request, f.raw_response, f.evidence,
		       COALESCE(av.raw_request,''), COALESCE(av.evidence_url,'')
		FROM vector_findings f
		LEFT JOIN attack_vectors av ON av.id = f.vector_id
		WHERE f.id = $1`, p.rowID).
		Scan(&tool, &kind, &payload, &rawReq, &rawResp, &evidence, &vecRawReq, &vecEvURL)
	if err != nil {
		return d, fmt.Errorf("pointers: finding detail: %w", err)
	}

	repro := BuildFindingReproduction(FindingForRepro{
		Tool: tool, Kind: kind, Method: p.Method, InsertionPoint: p.InsertionPoint,
		Param: p.Parameter, Payload: payload, URL: p.URL, Evidence: evidence,
		RawRequest: rawReq, VectorRawRequest: vecRawReq, VectorEvidenceURL: vecEvURL,
	})
	explain := ExplainFindingForVector(tool, kind, p.InsertionPoint)

	requestOrigin := FindingRequestOrigin(rawReq)
	responseOrigin := FindingResponseOrigin(rawResp)
	requestNote := findingEvidenceNote(tool, requestOrigin, responseOrigin)
	// THE REPRODUCTION IS BUILT FROM p.URL, so when that URL was composed rather than captured the
	// curl below is an inferred request and has to say so here, where the operator is about to
	// copy it. Papering over the empty url column is the right thing for this screen to do and a
	// silent paper over is not.
	if strings.TrimSpace(p.URLNote) != "" {
		requestNote = strings.TrimSpace(requestNote + " " + p.URLNote)
	}
	d.Request = PointerEvidenceBlob{
		Raw: rawReq, Origin: requestOrigin, Note: requestNote,
	}
	d.Response = PointerEvidenceBlob{Raw: rawResp, Origin: responseOrigin}
	d.Baseline = PointerBaseline{
		Compared: false,
		What: tool + " ran its own comparison and this framework did not see it. " +
			"That is why a prior finding ranks below a probe whose baseline is on hand, however severe the tool called it.",
	}
	d.Rule = PointerRule{
		Fired:           p.Rule,
		Means:           explain.WhatItProved,
		DidNotEstablish: explain.WhatItDidNotProve,
	}
	d.Grade = PointerGrade{
		Value:  p.Grade,
		Source: p.GradeSource,
		Why:    strings.TrimSpace(explain.SeverityNote),
	}
	d.Explain = &explain
	d.Reproduction = &repro
	return d, nil
}

// triagePointerDetail fills in a triage verdict's evidence: the wire record of the probe the
// verdict cites, which is the answer to "did what we asked for actually go out" and the reason a
// triage pointer can be trusted further than a signature match.
func triagePointerDetail(ctx context.Context, p Pointer, d PointerDetail) (PointerDetail, error) {
	var reason, provenance, provenanceDetail, phrase, markerForm string
	var deltaChecked bool
	var evidenceOrdinal int64
	err := dbPool.QueryRow(ctx, `
		SELECT v.reason, v.provenance, v.provenance_detail, COALESCE(v.evidence_phrase,''),
		       COALESCE(v.evidence_marker_form,''), v.delta_checked, v.evidence_ordinal
		FROM triage_verdicts v WHERE v.id = $1`, p.rowID).
		Scan(&reason, &provenance, &provenanceDetail, &phrase, &markerForm, &deltaChecked,
			&evidenceOrdinal)
	if err != nil {
		return d, fmt.Errorf("pointers: triage detail: %w", err)
	}

	// The wire record for the probe this verdict cites. It is the answer to "did what we asked for
	// actually go out", and it is the reason a triage pointer can be trusted more than a signature.
	var logical, wire, container []byte
	var survived, containerName, transportErr string
	var httpStatus int
	_ = dbPool.QueryRow(ctx, `
		SELECT fid.logical, fid.wire, fid.container, fid.survived, fid.container_name,
		       fid.transport_err, fid.http_status
		FROM triage_fidelity fid
		JOIN triage_verdicts v ON v.run_id = fid.run_id
		WHERE v.id = $1 AND fid.ordinal = v.evidence_ordinal
		ORDER BY fid.attempt DESC LIMIT 1`, p.rowID).
		Scan(&logical, &wire, &container, &survived, &containerName, &transportErr, &httpStatus)

	d.Request = PointerEvidenceBlob{
		Raw:    string(container),
		Origin: "triage_fidelity_container",
		Note: fmt.Sprintf("The serialized %s as it was handed to the transport. Asked for %d bytes, %d reached the wire, survival %q.",
			firstNonEmpty(containerName, "container"), len(logical), len(wire), survived),
	}
	d.Response = PointerEvidenceBlob{
		Raw:    phrase,
		Origin: "evidence_phrase",
		Note:   fmt.Sprintf("The classifier's own evidence phrase, marker form %q, HTTP %d.", markerForm, httpStatus),
	}
	d.Baseline = PointerBaseline{
		Compared: deltaChecked,
		What: map[bool]string{
			true:  "The response was differenced against a measured baseline, which is what separates a payload changing something from a string being present.",
			false: "No baseline difference. A string matched, and that string may have been in the baseline all along.",
		}[deltaChecked],
	}
	d.Rule = PointerRule{
		Fired:           p.Rule,
		Means:           firstNonEmpty(provenanceDetail, "Recorded by "+firstNonEmpty(provenance, "an unnamed source")+"."),
		DidNotEstablish: "Confirmation. A positive triage state is a reason to point a tool here, not a finding.",
	}
	d.Grade = PointerGrade{Value: p.Grade, Source: p.GradeSource, Why: reason}
	return d, nil
}
