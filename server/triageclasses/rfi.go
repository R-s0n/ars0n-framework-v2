package triageclasses

import (
	"bytes"
	"regexp"
	"strconv"

	"ars0n-framework-v2-server/utils/triage"
)

// CLASS RFI (id 15). REMOTE FILE INCLUSION: the server fetches a URL WE named AND puts the
// fetched content in its response.
//
// WHY THIS IS ITS OWN CLASS AND NOT A NOTE ON LFI. The design this replaced said the RFI question
// was "answered for free" by the PHP signature "URL file-access is disabled in the server
// configuration", at no request cost. That is the forbidden reasoning with the request-saving
// justification attached, and it is also substantively wrong. VERIFIED against php.net's
// Filesystem and Streams configuration pages: allow_url_include defaults to "0" and governs ONLY
// include, include_once, require and require_once. allow_url_fopen defaults to "1". So that
// signature refutes a remote INCLUDE and says nothing whatever about file_get_contents, fopen,
// copy, simplexml_load_file, DOMDocument::load or getimagesize, every one of which fetches a
// remote URL by default. A whole live class would have been recorded as dead by one string in
// another class's response.
//
// WHY IT IS NOT SSRF EITHER. SSRF's oracle is "the server fetched it". This class's oracle is
// "the server fetched it AND put the content in the response", which is a different finding with
// a different fix and a different severity. A callback on its own belongs to SSRF, and this class
// says so on the label rather than absorbing it. IT NEVER READS SSRF'S CALLBACK RECORD: what it
// reads is ClassifyCtx.Callbacks, which the runner has already filtered to this class's own
// ordinal stripe.
//
// WHAT IT NEEDS AND WILL NOT PRETEND TO HAVE. The collaborator must be able to SERVE CONTENT. The
// framework's own out-of-band oracle container can; webhook.site cannot. Without one this class
// can never reach its finding, and it says so on every row it writes.
//
// =================================================================================================
// THE IN-BAND TIER, AND THE DEFECT IT REPLACES
// =================================================================================================
// Until now, "no content-serving collaborator" meant ZERO REQUESTS. Plan refused on ctx.OOB alone,
// so on a build whose runner ingests no callback at all this class recorded planned=0 sent=0 on
// every slot of every vector for the whole life of the target, behind an enabled checkbox. An
// operator who switches RFI on and sees nothing reads that as "no remote file inclusion here". It
// is not. It is "nobody looked", and that is the false negative this entire layer exists to stop.
//
// SO THE CLASS IS SPLIT INTO TWO TIERS, and each one states exactly what it can conclude.
//
//	OOB TIER (R1..R4 + NC1, five requests). Needs a collaborator that RECORDS a fetch and SERVES
//	content. Only this tier can reach StateFinding (the served bytes came back) and only this tier
//	can reach StateClean (the fetch is proven and the inclusion is disproven).
//
//	IN-BAND TIER (H0 + H1 + H2, three requests). Needs NOTHING. Every byte it sends points at a
//	host under .invalid, which RFC 6761 section 6.4 guarantees never resolves, so no packet ever
//	leaves for a third party and no fetch can succeed. What it measures is the ERROR: a stack that
//	passes our value to include(), file_get_contents, fopen, URL.openStream, requests.get or
//	http.Get and is handed an unresolvable remote URL says so, in band, in words. PHP names the
//	wrapper and the configuration directive; Java throws UnknownHostException; Node returns
//	getaddrinfo ENOTFOUND; Go says no such host. That is direct evidence that this slot reaches a
//	URL fetcher, which is the single most useful thing triage can tell a scanner, and it costs
//	three requests and no infrastructure.
//
// WHAT THE IN-BAND TIER MAY NEVER SAY, AND THIS IS THE PART THAT MATTERS. It may never say
// finding: an error proves an attempt, not an inclusion, and inclusion is this class's whole
// claim. It may never say clean: an application that fetches silently and discards the body
// produces exactly the same silence as one that never fetched, and telling those apart is what
// the collaborator was for. Its ceiling is suspicious and its floor is cannot_determine, and
// every row it writes carries oob_half_missing so no aggregate can read it as coverage of the
// inclusion question.

type rfiClassifier struct{}

func init() { triage.RegisterClassifier(rfiClassifier{}) }

func (rfiClassifier) ID() triage.ClassID { return triage.ClassRFI }

// ---------------------------------------------------------------------------------------------
// PAYLOADS
// ---------------------------------------------------------------------------------------------

const (
	rfiR1  triage.ProbeID = "RFI-R1"
	rfiR2  triage.ProbeID = "RFI-R2"
	rfiR3  triage.ProbeID = "RFI-R3"
	rfiR4  triage.ProbeID = "RFI-R4"
	rfiNC1 triage.ProbeID = "RFI-NC1"

	// The in-band tier. H0 is its control and it is the reason the tier can conclude anything:
	// it carries the same bytes with the SCHEME REMOVED, so it is a relative path and not a
	// remote URL. An application that errors identically on both is an application that dislikes
	// the string, not one that tried to fetch it.
	rfiH0 triage.ProbeID = "RFI-H0"
	rfiH1 triage.ProbeID = "RFI-H1"
	rfiH2 triage.ProbeID = "RFI-H2"
)

// rfiInBandHost is the suffix every in-band payload points at.
//
// IT IS UNRESOLVABLE ON PURPOSE AND THAT IS THE FEATURE, NOT A COMPROMISE. RFC 6761 section 6.4
// reserves .invalid and guarantees it never resolves, so this tier cannot cause a fetch to
// anywhere, cannot leak the target's data to a third party, and cannot be confused with a real
// collaborator hit. A name resolution that FAILS is precisely the event that makes a fetching
// stack print the error this tier reads.
const rfiInBandHost = ".rfi-inband.invalid"

// rfiServedFile and rfiServedForm are the contract with the collaborator, carried on the request
// so the runner configures the OOB container per probe rather than from a global.
//
// THE SERVED BYTES ARE THE MARKER TWICE AND NOTHING ELSE. No code of any kind: not PHP, not
// JavaScript, not a shell line. If the target includes it as source it executes nothing, and if
// it prints it we get thirty-two bytes we can attribute exactly. A remote-include proof that
// shipped executable code would be a remote-include exploit, and this is triage.
const (
	rfiServedFile = "/f.txt"
	rfiServedForm = "marker_twice"
)

var rfiValuePoints = []triage.SlotKind{
	triage.KindQuery, triage.KindBody, triage.KindPath, triage.KindHeader, triage.KindCookie,
}

var rfiValueEncoders = []triage.EncoderMode{
	triage.EncodeQuery, triage.EncodeForm, triage.EncodeJSONString, triage.EncodePathSegment,
	triage.EncodeHeaderValue, triage.EncodeCookie, triage.EncodeMultipartValue,
}

func (rfiClassifier) Probes() []triage.ProbeSpec {
	c := triage.ClassRFI
	return []triage.ProbeSpec{
		{
			ID: rfiR1, Class: c, Logical: []byte("http://" + faTokMarker + "." + faTokOOB + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the plain http remote include. The marker is the DNS LABEL, so a DNS-only " +
				"callback is still attributable to this exact probe on this exact slot",
		},
		{
			ID: rfiR2, Class: c, Logical: []byte("https://" + faTokMarker + "." + faTokOOB + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "AN HTTPS-ONLY FETCHER IS WHY THIS IS NOT GATED ON R1. A stack that refuses plain " +
				"http produces no callback for R1 at all, so promoting R2 only after R1's callback would " +
				"be an intra-class shared gate that silently converts the most common hardened " +
				"configuration into a clean. All four payloads are sent unconditionally; the cost model " +
				"already budgets five requests for this class",
		},
		{
			ID: rfiR3, Class: c, Logical: []byte("//" + faTokMarker + "." + faTokOOB + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0,
			Notes: "the scheme-relative form, for a sink that prepends its own scheme and rejects " +
				"anything that already has one. It is also the form that survives a validator checking " +
				"that the value does not start with http",
		},
		{
			ID: rfiR4, Class: c, Logical: []byte("http://" + faTokMarker + "." + faTokOOB + rfiServedFile + "%00" + faTokExt),
			Encoders:  rfiValueEncoders,
			Points:    []triage.SlotKind{triage.KindQuery, triage.KindBody, triage.KindPath},
			MarkerPos: triage.MarkerInline, Tier: triage.TierFull, Risk: triage.RiskR0,
			Embeds: []triage.ProbeID{rfiR1},
			Notes: "legacy extension truncation on a remote URL. The %00 here is PERCENT TEXT and not " +
				"a raw NUL byte, because it must survive as three characters inside a URL for the target " +
				"to decode; that is why this probe, unlike the null-truncation probes in the sibling " +
				"classes, is deliverable in a header or a cookie in principle and is still restricted " +
				"here to the three points where an appended extension is a real pattern. It declares " +
				"Embeds on R1 because it contains R1's twenty-four bytes verbatim, and a silent " +
				"containment is the thing the isolation check refuses",
		},
		{
			ID: rfiNC1, Class: c, Logical: []byte("http://" + faTokMarker + ".nxnc.invalid" + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "the unresolvable twin. RFC 6761 section 6.4 reserves .invalid and guarantees it " +
				"never resolves, so this MUST produce no callback and no content hit. If a callback " +
				"arrives for it, something in the path is resolving names for us (a corporate resolver " +
				"with a wildcard, a captive portal, a scanning proxy) and every out-of-band conclusion " +
				"on this run is void. If a CONTENT hit arrives for it, the content detector is matching " +
				"something other than the served bytes",
		},

		// ------------------------------------------------------------------------------------
		// THE IN-BAND TIER. No collaborator, no callback, no packet to any third party.
		// ------------------------------------------------------------------------------------
		{
			ID: rfiH0, Class: c, Logical: []byte(faTokMarker + rfiInBandHost + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0, IsControl: true,
			Notes: "the in-band tier's control: H1's bytes with the SCHEME REMOVED, so it is a " +
				"relative path and no fetcher treats it as remote. It is what makes an error on H1 " +
				"mean something. An application that rejects long dotted strings, that 500s on any " +
				"unknown filename, or that prints a stack trace for every bad value errors here too, " +
				"and the tier then reports error_not_specific_to_a_remote_url instead of a suspicion. " +
				"Without this control every strict input validator in the world is a remote fetcher",
		},
		{
			ID: rfiH1, Class: c, Logical: []byte("http://" + faTokMarker + rfiInBandHost + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0, Embeds: []triage.ProbeID{rfiH0},
			Notes: "the in-band remote URL over plain http. The host is under .invalid and can never " +
				"resolve, so this cannot fetch anything; the DNS failure is the point, because a stack " +
				"that tried to fetch says so in band and one that never touched the value says nothing. " +
				"It declares Embeds on H0 because it contains H0's bytes verbatim",
		},
		{
			ID: rfiH2, Class: c, Logical: []byte("https://" + faTokMarker + rfiInBandHost + rfiServedFile),
			Encoders: rfiValueEncoders, Points: rfiValuePoints, MarkerPos: triage.MarkerInline,
			Tier: triage.TierReduced, Risk: triage.RiskR0, Embeds: []triage.ProbeID{rfiH0},
			Notes: "the same over https, for the same reason R2 exists and is not gated on R1: a stack " +
				"that refuses plain http never reaches its fetcher for H1 at all, and PHP's wrapper " +
				"message names the SCHEME it disabled, so http and https produce different sentences",
		},
	}
}

// ---------------------------------------------------------------------------------------------
// THE IN-BAND SIGNATURE TABLE
// ---------------------------------------------------------------------------------------------

// rfiFetchSigs is this class's OWN copy of its own signatures, per CATALOGUE A.2.1. It is not
// shared with LFI or TRAVERSAL and it must not be: those two look for the CONTENTS of a file, and
// every phrase here is about a name that could not be resolved or a wrapper that was refused.
//
// The primaries are all remote-specific. "No such file or directory" is deliberately absent: it
// is what a LOCAL open of a relative path produces, which is H0's expected outcome, and putting
// it here would make the control fire on every file-handling endpoint in existence.
var rfiFetchSigs = []faSignature{
	{Name: "php_url_wrapper_disabled", Re: regexp.MustCompile(`(?i)URL file-access is disabled in the server configuration|wrapper is disabled in the server configuration|allow_url_(include|fopen)`)},
	{Name: "php_no_suitable_wrapper", Re: regexp.MustCompile(`(?i)no suitable wrapper could be found`)},
	{Name: "php_stream_remote_failure", Re: regexp.MustCompile(`(?i)failed to open stream:\s*(HTTP request failed|operation failed|php_network_getaddresses|Name or service not known|Temporary failure in name resolution|No route to host|Connection refused|Network is unreachable)`)},
	{Name: "php_getaddrinfo", Re: regexp.MustCompile(`(?i)php_network_getaddresses:\s*getaddrinfo`)},
	{Name: "java_unknown_host", Re: regexp.MustCompile(`(?i)java\.net\.UnknownHostException`)},
	{Name: "node_getaddrinfo", Re: regexp.MustCompile(`(?i)getaddrinfo\s+(ENOTFOUND|EAI_AGAIN)`)},
	{Name: "python_urlopen_error", Re: regexp.MustCompile(`(?i)<urlopen error|urllib\.error\.URLError|requests\.exceptions\.ConnectionError|NewConnectionError|Failed to establish a new connection`)},
	{Name: "go_no_such_host", Re: regexp.MustCompile(`(?i)dial tcp: lookup |lookup [^\s]+ on [^\s]+: no such host|: no such host`)},
	{Name: "curl_resolve_failure", Re: regexp.MustCompile(`(?i)Could not resolve host|curl:\s*\(6\)|CURLE_COULDNT_RESOLVE_HOST`)},
	{Name: "dotnet_resolve_failure", Re: regexp.MustCompile(`(?i)The remote name could not be resolved|System\.Net\.WebException|NameResolutionFailure`)},
	{Name: "generic_resolve_failure", Re: regexp.MustCompile(`(?i)Name or service not known|Temporary failure in name resolution|nodename nor servname provided|EAI_NONAME`)},

	// Corroborating. Each one says "a fetch or an open happened somewhere near here" and none of
	// them says the target was remote, so none is ever enough on its own.
	{Name: "failed_to_open_stream", Re: regexp.MustCompile(`(?i)failed to open stream`), Corroborating: true},
	{Name: "php_fetch_sink_named", Re: regexp.MustCompile(`(?i)\b(file_get_contents|fopen|simplexml_load_file|getimagesize|DOMDocument::load|readfile|copy)\s*\(`), Corroborating: true},
	{Name: "php_include_sink_named", Re: regexp.MustCompile(`(?i)\b(include|include_once|require|require_once)\s*\(`), Corroborating: true},
	{Name: "java_malformed_url", Re: regexp.MustCompile(`(?i)java\.net\.MalformedURLException|no protocol:`), Corroborating: true},
}

// rfiErrorProximity is how far from a signature hit this class's marker may sit and still count
// the error as NAMING OUR URL. Half a kilobyte covers a PHP warning that prints the whole URL, a
// Java stack frame and a JSON error envelope, and stops short of crediting a page that reflects
// the value in a form field at the top and happens to carry an unrelated error banner at the
// bottom.
const rfiErrorProximity = 512

// rfiOOBUsable reports whether the collaborator can do BOTH halves of this class's real oracle.
// Anything less and the OOB tier is not run at all: half an oracle produces SSRF's evidence under
// this class's name, which is the boundary this class was split out to keep.
func rfiOOBUsable(o triage.OOBConfig) bool {
	return o.Mode != triage.OOBNone && o.Base != "" && o.ServesContent
}

// ---------------------------------------------------------------------------------------------
// REACHABILITY
// ---------------------------------------------------------------------------------------------

// Reaches. Every answer here is CONDITIONAL, including the ones the sibling classes call always,
// and the condition is the same one everywhere: a collaborator that can serve content.
//
// That is not pedantry. A class whose reachability says "always" and whose Plan then sends
// nothing because the infrastructure is absent has told the operator it covered a slot it never
// touched. Saying conditional here, and cannot_determine (no_content_collaborator) in the
// verdict, keeps the two statements agreeing.
func (rfiClassifier) Reaches(k triage.SlotKind, mt triage.MediaType) triage.Reachability {
	base := "this class's FINDING needs a collaborator that can SERVE CONTENT, and with a DNS-only, " +
		"callback-only or absent collaborator it can never reach one; what it runs instead is the in-band " +
		"tier, three requests at an unresolvable .invalid host that read the fetch error rather than the " +
		"fetch, whose ceiling is suspicious and which reports cannot_determine rather than clean"
	switch k {
	case triage.KindQuery, triage.KindHeader:
		return triage.Reachability{Reach: triage.ReachConditional, Reason: base}
	case triage.KindCookie:
		return triage.Reachability{
			Reach:  triage.ReachConditional,
			Reason: base + "; ':' '/' '@' '#' and '=' are all cookie-octet so the URL is deliverable raw",
		}
	case triage.KindBody:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: base + "; a JSON string slot takes the URL unchanged, a JSON number slot is " +
				"json_string_coerced only and a 400 there is type_rejection and never clean, and a " +
				"multipart filename takes only the forms that cannot become a write target. Media type " +
				"seen: " + string(mt),
		}
	case triage.KindPath:
		return triage.Reachability{
			Reach: triage.ReachConditional,
			Reason: base + "; and additionally every payload needs '//' inside a segment, which means " +
				"%2F%2F, so a segment that rejects the percent-encoded slash makes this class " +
				"not_reachable (path_slash) rather than clean",
		}
	case triage.KindFragment:
		return triage.Reachability{
			Reach: triage.ReachNever,
			Reason: "the fragment is never transmitted, so the server never sees the URL and a browser " +
				"fetching it would be the browser's own request. Calling that a remote include would be " +
				"a fabricated finding",
		}
	default:
		return triage.Reachability{
			Reach:  triage.ReachNever,
			Reason: "slot kind " + string(k) + " is not in the model this class was written against",
		}
	}
}

// ---------------------------------------------------------------------------------------------
// PLAN
// ---------------------------------------------------------------------------------------------

// Plan sends five requests with a content-serving collaborator, and three without one.
//
// IT NO LONGER SENDS NONE. Sending nothing was the honest answer to a question nobody had asked
// yet: "can this class prove a remote include". It was the dishonest answer to the question the
// operator is actually asking, which is "is there anything here", because a class that sends
// nothing and a class that found nothing look identical in every aggregate the report draws. The
// in-band tier below sends three requests that need no infrastructure at all, and the verdicts
// from it can never claim what only the collaborator could establish.
func (rfiClassifier) Plan(ctx triage.PlanCtx) []triage.ProbeRequest {
	return rfiPlanLadder(rfiPlanInput{
		Slot:          ctx.Slot,
		RouteResolved: ctx.Route.Resolved(),
		PreludeFailed: ctx.Prelude.Failed(),
		BudgetOut:     ctx.Budget.Exhausted(),
		Round:         ctx.Round,
		OOB:           ctx.OOB,
	})
}

// rfiPlanInput is the part of PlanCtx this class reads, lifted out so the ladder is testable.
//
// A classifier test cannot build a resolved Replay: NewReplay takes the runner capability and
// that type lives in an internal package, which is exactly the isolation this layer wanted. The
// consequence is that a ladder reading ctx.Route directly can only ever be tested on the
// unresolved path, so "with a collaborator it plans five and without one it plans three" would
// have been asserted nowhere. Hence this struct.
type rfiPlanInput struct {
	Slot          triage.Slot
	RouteResolved bool
	PreludeFailed bool
	BudgetOut     bool
	Round         int
	OOB           triage.OOBConfig
}

func rfiPlanLadder(in rfiPlanInput) []triage.ProbeRequest {
	if _, ok := faEligibleSlot(in.Slot); !ok {
		return nil
	}
	if !in.RouteResolved || in.PreludeFailed || in.BudgetOut {
		return nil
	}
	if in.Round != 0 {
		return nil
	}

	sub := faSubstFor(in.Slot)
	key := in.Slot.Key

	// THE IN-BAND TIER, and the control goes out FIRST in the list so a budget that bites
	// mid-slot takes a payload and leaves the control, rather than leaving two payloads with
	// nothing to compare them against.
	//
	// IT CARRIES NO oob_file AND NO oob_serve. Nothing serves these; the host cannot resolve. A
	// Variant key naming a collaborator file would tell the runner to configure an out-of-band
	// container that does not exist, and a runner that quietly did nothing with it would leave
	// this tier looking configured when it is not.
	if !rfiOOBUsable(in.OOB) {
		ids := rfiInBandProbeIDs()
		out := make([]triage.ProbeRequest, 0, len(ids))
		for _, id := range ids {
			r := faReq(id, key, sub)
			r.Variant["rfi_tier"] = rfiTierInBand
			out = append(out, r)
		}
		return out
	}

	sub.OOB = in.OOB.Base
	ids := rfiProbeIDsFor(in.Slot.Kind)
	out := make([]triage.ProbeRequest, 0, len(ids))
	for _, id := range ids {
		r := faReq(id, key, sub)
		// The collaborator contract rides on the request. NC1 gets it too, deliberately: if the
		// unresolvable host somehow serves, we want to find out from the control and not from a
		// finding.
		r.Variant["oob_file"] = rfiServedFile
		r.Variant["oob_serve"] = rfiServedForm
		r.Variant["rfi_tier"] = rfiTierOOB
		out = append(out, r)
	}
	return out
}

// The two tiers, written onto every ProbeRequest so the stored row, the runner log and the report
// all name the same thing and a verdict can be audited against the tier that produced it.
const (
	rfiTierOOB    = "oob_collaborator"
	rfiTierInBand = "in_band_fetch_error"
)

// ---------------------------------------------------------------------------------------------
// CLASSIFY
// ---------------------------------------------------------------------------------------------

// Classify. This class has the narrowest clean in the family and that is correct.
//
// CLEAN REQUIRES A CALLBACK THAT ARRIVED AND CONTENT THAT DID NOT. That combination proves the
// server fetched our URL and did NOT put the body in its response, which is the only way to
// demonstrate that remote inclusion specifically does not happen. Silence everywhere is not that
// proof: it is consistent with a fetch we could not see, a grace window that was too short, and a
// sink that never ran. So silence is cannot_determine, and the reason says which half is missing.
func (c rfiClassifier) Classify(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	key := ctx.Slot.Key
	ann := map[string]any{}
	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return []triage.ClassVerdict{{
			Class: triage.ClassRFI, SlotKey: key, State: state, Reason: reason,
			Grade: grade, Oracle: oracle, Ordinals: ords, Annotations: ann, Label: rfiLabel(ann),
		}}
	}

	if reason, ok := faEligibleSlot(ctx.Slot); !ok {
		return one(triage.StateNotApplicable, reason, "", triage.GradeUnrated, nil)
	}
	if r := c.Reaches(ctx.Slot.Kind, ctx.Vector.MediaType); r.Reach == triage.ReachNever {
		return one(triage.StateNotReachable, r.Reason, "", triage.GradeUnrated, nil)
	}
	if !rfiOOBUsable(ctx.OOB) {
		return c.classifyInBand(ctx, key)
	}

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		switch {
		case !ctx.Route.Resolved():
			return one(triage.StateCannotDetermine,
				"route_unresolved: the composed URL at its observed value did not resolve",
				"", triage.GradeUnrated, nil)
		case ctx.Prelude.Failed():
			return one(triage.StateCannotDetermine,
				"prelude_failed: the vector needs a token this run could not obtain",
				"", triage.GradeUnrated, nil)
		case ctx.Budget.Exhausted():
			return one(triage.StateNotRun,
				"probe_budget_exhausted: the cap was reached before this class sent anything",
				"", triage.GradeUnrated, nil)
		default:
			return one(triage.StateNotPlanned,
				"no remote-include probe was derived for this slot and no reason above applies",
				"", triage.GradeUnrated, nil)
		}
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")",
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	var honest []faOwnObs
	var skips []triage.ProbeSkip
	for _, o := range own {
		if why, ok := faWireIsHonest(o.Obs); !ok {
			skips = append(skips, triage.ProbeSkip{ProbeID: o.ProbeID, Reason: why})
			continue
		}
		honest = append(honest, o)
	}
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	ann["oob_mode"] = string(ctx.OOB.Mode)
	ann["oob_grace_window"] = ctx.OOB.GraceWindow.String()
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every URL was refused, altered or left unsubstituted, and the "+
				"one that matters most is the collaborator base: an unsubstituted ${oob} sends a request "+
				"to a host that does not exist and produces exactly the silence a clean would be built on",
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	// THE CONTROL FIRST, because everything after it depends on the out-of-band channel meaning
	// what we think it means.
	if nc1, ok := faFind(honest, rfiNC1); ok {
		if rfiCallbackFor(ctx.Callbacks, nc1.Marker) {
			ann["control_that_fired"] = "RFI-NC1 (callback)"
			v := one(triage.StateCannotDetermine,
				"detector_unverified (egress_resolver): a callback arrived for a host under .invalid, "+
					"which RFC 6761 guarantees never resolves. Something between us and the target is "+
					"resolving or fetching names on our behalf, so no out-of-band conclusion on this slot "+
					"is safe",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
		if _, hit := faByteForm(nc1.Obs.Body, rfiServedBytes(nc1.Marker)); hit {
			ann["control_that_fired"] = "RFI-NC1 (content)"
			v := one(triage.StateCannotDetermine,
				"detector_unverified: the served-content detector fired on a URL whose host cannot "+
					"resolve, so it is matching something other than bytes our collaborator served",
				"", triage.GradeUnrated, ords)
			v[0].Untested = skips
			return v
		}
	}

	if faUniformBlock(faObsOf(honest), nil) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct URLs produced byte-identical "+
				"non-baseline responses, so a filter answered and no fetch was attempted",
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// F-D2, THE ONLY ORACLE NO SSRF PROBE CAN PRODUCE: the served content in the response.
	for _, o := range honest {
		if o.ProbeID == rfiNC1 {
			continue
		}
		served := rfiServedBytes(o.Marker)
		if len(served) == 0 {
			continue
		}
		// The guard that makes this a finding rather than a reflection: the thirty-two bytes were
		// never in the request. The request carried a URL in which the marker appears ONCE.
		if bytes.Contains(o.Obs.Payload.Wire, served) || bytes.Contains(o.Obs.Payload.Logical, served) {
			ann["answer_in_wire"] = true
			continue
		}
		form, hit := faByteForm(o.Obs.Body, served)
		if !hit {
			continue
		}
		ann["winning_probe"] = string(o.ProbeID)
		ann["marker_form"] = form
		ann["callback_seen"] = rfiCallbackFor(ctx.Callbacks, o.Marker)
		v := one(triage.StateFinding,
			"rfi_content_included: the thirty-two bytes our collaborator served at "+rfiServedFile+
				" came back in the response, and they were never in the request, which carried a URL and "+
				"not a body. The server fetched a remote file we named and put its contents in its own "+
				"output. This is the whole reason this class exists: no SSRF probe can produce it",
			"served_content", triage.GradeHigh, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{Ordinal: o.Ordinal, MarkerForm: form, Phrase: "served_content_echoed"}
		return v
	}

	// F-D1 on its own: a fetch happened and the content did not come back.
	var fetched []triage.ProbeID
	for _, o := range honest {
		if o.ProbeID == rfiNC1 {
			continue
		}
		if rfiCallbackFor(ctx.Callbacks, o.Marker) {
			fetched = append(fetched, o.ProbeID)
		}
	}
	if len(fetched) > 0 {
		ann["probes_that_called_back"] = fetched
		// THE CLEAN. A callback proves the fetch happened; the absence of the served bytes proves
		// the fetch was not included. Both halves measured, so this is the one state in this class
		// that asserts something about the application.
		ann["clean_preconditions"] = []string{
			"the collaborator can serve content and did serve it at " + rfiServedFile,
			"a callback arrived for at least one of this class's own probes, so the fetch is proven to have happened",
			"the unresolvable .invalid control produced neither a callback nor a content hit",
			"the served thirty-two bytes were absent from the response in every transform form searched",
		}
		v := one(triage.StateClean,
			"the server fetched the URL this slot named, and the bytes our collaborator served did "+
				"NOT appear in the response. The fetch is proven and the inclusion is disproven, which "+
				"is the only shape in which this class can honestly say clean. THE FETCH ITSELF MAY BE "+
				"SSRF: that is SSRF's class, SSRF's probes and SSRF's verdict, and the label says so",
			"callback_without_content", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	// Nothing at all. That is not a clean and it never can be.
	if ctx.OOB.Mode == triage.OOBHTTPPath {
		ann["oob_no_dns"] = true
	}
	v := one(triage.StateCannotDetermine,
		"no_fetch_observed: no callback arrived for any of this class's own probes and the served "+
			"bytes did not appear. That is consistent with three different worlds: the sink never ran, "+
			"the sink ran and the collaborator's grace window was too short, and the sink ran over a "+
			"channel this collaborator mode cannot see. Silence distinguishes none of them, so this is "+
			"an unknown. A clean here would be a claim about a fetch we never proved did not happen",
		"", triage.GradeUnrated, ords)
	v[0].Untested = skips
	return v
}

// ---------------------------------------------------------------------------------------------
// THE IN-BAND TIER
// ---------------------------------------------------------------------------------------------

// rfiInBandRead is one in-band observation after the honesty filter, plus what this class's own
// signature table found in it.
type rfiInBandRead struct {
	obs           faOwnObs
	primary       []faSigHit
	corroborating []faSigHit
	markerPresent bool
	markerForm    string
	// NamedInError is the strong form of attribution: a primary hit sits within
	// rfiErrorProximity bytes of this probe's own marker, so the error is about OUR url and not
	// about something else on the page.
	namedInError bool
}

// classifyInBand scores the three-request tier.
//
// ITS CEILING IS SUSPICIOUS AND ITS FLOOR IS cannot_determine, and every exit says so. There is
// no path through this function to StateFinding or StateClean, because neither is observable
// without a collaborator that serves content, and a class that reached either from an error
// message would be asserting an inclusion it never saw.
func (c rfiClassifier) classifyInBand(ctx triage.ClassifyCtx, key triage.SlotKey) []triage.ClassVerdict {
	ann := map[string]any{
		"rfi_tier":           rfiTierInBand,
		"oob_half_missing":   true,
		"oob_mode":           string(ctx.OOB.Mode),
		"oob_serves_content": ctx.OOB.ServesContent,
	}
	ceiling := rfiInBandCeiling(ctx.OOB)
	ann["missing_half"] = rfiMissingHalf(ctx.OOB)

	one := func(state triage.TriageState, reason, oracle string, grade triage.TriageGrade, ords []uint64) []triage.ClassVerdict {
		return []triage.ClassVerdict{{
			Class: triage.ClassRFI, SlotKey: key, State: state, Reason: reason,
			Grade: grade, Oracle: oracle, Ordinals: ords, Annotations: ann, Label: rfiLabel(ann),
		}}
	}

	own := faOwn(ctx.Own)
	if len(own) == 0 {
		switch {
		case !ctx.Route.Resolved():
			return one(triage.StateCannotDetermine,
				"route_unresolved: the composed URL at its observed value did not resolve."+ceiling,
				"", triage.GradeUnrated, nil)
		case ctx.Prelude.Failed():
			return one(triage.StateCannotDetermine,
				"prelude_failed: the vector needs a token this run could not obtain."+ceiling,
				"", triage.GradeUnrated, nil)
		case ctx.Budget.Exhausted():
			return one(triage.StateNotRun,
				"probe_budget_exhausted: the cap was reached before this class sent anything."+ceiling,
				"", triage.GradeUnrated, nil)
		default:
			return one(triage.StateNotPlanned,
				"no in-band probe was derived for this slot and no reason above applies."+ceiling,
				"", triage.GradeUnrated, nil)
		}
	}
	for _, o := range own {
		if o.Err != nil {
			return one(triage.StateCannotDetermine,
				"foreign_observation: the vault refused one of this class's own reads ("+o.Err.Error()+")."+ceiling,
				"", triage.GradeUnrated, faOrdinals(own))
		}
	}

	var skips []triage.ProbeSkip
	var honest []faOwnObs
	for _, o := range own {
		if why, ok := faWireIsHonest(o.Obs); !ok {
			skips = append(skips, triage.ProbeSkip{ProbeID: o.ProbeID, Reason: why})
			continue
		}
		honest = append(honest, o)
	}
	ann["probes_sent"] = len(own)
	ann["probes_on_the_wire"] = len(honest)
	if len(honest) == 0 {
		v := one(triage.StateCannotDetermine,
			"no_probe_reached_the_wire: every in-band URL was refused, altered or left unsubstituted, so the "+
				"application was never asked whether it fetches a remote URL."+ceiling,
			"", triage.GradeUnrated, faOrdinals(own))
		v[0].Untested = skips
		return v
	}
	ords := faOrdinals(honest)

	// FP1. A signature that already matches an unperturbed body is unusable on this endpoint: a
	// PHP documentation page printing "allow_url_include" would otherwise make every slot on it a
	// remote fetcher. Disabled is not silent and the operator is told which ones went.
	baselines := faBaselineBodies(ctx)
	ann["baseline_samples_available"] = len(baselines)
	live, disabled := faDisabledByBaseline(rfiFetchSigs, baselines)
	if len(disabled) > 0 {
		ann["signatures_disabled_by_baseline"] = disabled
	}
	primaryLive := false
	for _, s := range live {
		if !s.Corroborating {
			primaryLive = true
			break
		}
	}
	if !primaryLive {
		v := one(triage.StateCannotDetermine,
			"signature_in_baseline: every remote-fetch error phrase this class can recognise already appears in "+
				"this endpoint's own unperturbed response, so the detector is unusable here and its silence would "+
				"mean nothing. Disabled: "+joinStrings(disabled, ", ")+"."+ceiling,
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	reads := make(map[triage.ProbeID]rfiInBandRead, len(honest))
	for _, o := range honest {
		reads[o.ProbeID] = rfiReadInBand(o, live)
	}

	// THE CONTROL IS NAMED ON THE ROW WHETHER IT FIRED OR WENT MISSING. A tier whose control did
	// not come back has no differential, and the row has to say so rather than quietly scoring
	// the remote probes on their own.
	if _, ok := reads[rfiH0]; !ok {
		ann["control_missing"] = "RFI-H0"
	}

	if faUniformBlock(faObsOf(honest), nil) {
		v := one(triage.StateCannotDetermine,
			"blocked: three or more of this class's own distinct values produced byte-identical non-baseline "+
				"responses, so a filter answered and the application's own fetcher was never reached."+ceiling,
			"", triage.GradeUnrated, ords)
		v[0].Untested = skips
		return v
	}

	out := rfiJudgeInBand(reads)
	if len(out.ControlFired) > 0 {
		ann["control_that_fired"] = "RFI-H0"
		ann["control_signatures"] = joinStrings(out.ControlFired, ", ")
	}
	state, grade := rfiStateForOutcome(out.Key)
	switch out.Key {
	case rfiOutcomeFetchAttempted:
		w := reads[out.Winner]
		ann["probes_that_errored"] = joinStrings(out.Fired, ", ")
		ann["winning_signature"] = out.Hit.Name
		ann["winning_probe"] = string(out.Winner)
		if len(w.corroborating) > 0 {
			ann["corroborating"] = w.corroborating[0].Name
		}
		attribution := "unattributed_to_our_url: the error does not print this probe's marker within " +
			"512 bytes of the phrase, so it is attributed to the probe by the control differential alone"
		if out.Named {
			grade = triage.GradeMedium
			attribution = "named_in_error: the phrase sits within 512 bytes of this probe's own marker, so the " +
				"error is about the URL we sent and not about something else on the page"
		}
		ann["attribution"] = attribution
		v := one(state,
			"remote_fetch_attempted ("+out.Hit.Name+"): "+string(out.Winner)+" named an unresolvable remote URL and the "+
				"response carries a remote-fetch error that the scheme-stripped control RFI-H0 did not produce and "+
				"the unperturbed baseline does not contain. That is direct evidence that this slot reaches a URL "+
				"fetcher or a file include. IT IS NOT REMOTE FILE INCLUSION: an error proves an attempt, and this "+
				"tier has no way to see whether a fetched body would be echoed."+ceiling,
			"fetch_error", grade, ords)
		v[0].Untested = skips
		v[0].Evidence = triage.TriageEvidence{
			Ordinal: w.obs.Ordinal, MarkerForm: w.markerForm,
			Phrase: "remote_fetch_error", Matched: out.Hit.Matched,
		}
		return v

	case rfiOutcomeErrorNotRemote:
		v := one(state,
			"error_not_specific_to_a_remote_url: this endpoint produced the same error phrase for the "+
				"scheme-stripped control as for the remote URLs, so it is an error about the value and not about a "+
				"fetch. The remote-fetch question is unanswered here, not answered no."+ceiling,
			"", grade, ords)
		v[0].Untested = skips
		return v

	default:
		// A status differential is recorded and NEVER scored. It fires on every input validator
		// that dislikes a URL, so promoting it would hand the operator a page of parameters that
		// reject colons. It is on the row because a human reading one row can use it and an
		// aggregate cannot.
		if st := rfiStatusDifferential(reads); st != "" {
			ann["status_differential"] = st
		}
		v := one(state,
			"no_fetch_error_observed: the remote URLs produced no recognised remote-fetch error that the control "+
				"did not also produce. That is consistent with an application that never touches the value, one that "+
				"fetches and swallows the exception, one that fetches through a client this table has no phrase for, "+
				"and one whose error page this class never saw. Silence distinguishes none of them, so it is an "+
				"unknown and never a clean."+ceiling,
			"", grade, ords)
		v[0].Untested = skips
		return v
	}
}

// The three outcomes the in-band oracle can reach, named so the state mapping below is a table a
// test can walk rather than a switch spread over a hundred lines of prose.
const (
	rfiOutcomeFetchAttempted = "remote_fetch_attempted"
	rfiOutcomeErrorNotRemote = "error_not_specific_to_a_remote_url"
	rfiOutcomeNoError        = "no_fetch_error_observed"
)

// rfiInBandOutcome is what the in-band oracle decided, with nothing rendered yet.
type rfiInBandOutcome struct {
	Key          string
	Winner       triage.ProbeID
	Hit          faSigHit
	Named        bool
	Fired        []string
	ControlFired []string
}

// rfiJudgeInBand is the in-band oracle itself: a primary signature that fired on a REMOTE URL and
// did NOT fire on the scheme-stripped control.
//
// Both remote probes are read rather than the first one that hits, because http and https
// reaching different code paths is itself useful to the operator, and the winner is preferred to
// be one whose error NAMES our URL: the same evidence at two confidences, and taking the first
// hit would throw away the better one at random.
func rfiJudgeInBand(reads map[triage.ProbeID]rfiInBandRead) rfiInBandOutcome {
	out := rfiInBandOutcome{Key: rfiOutcomeNoError}
	controlFired := map[string]bool{}
	if h0, ok := reads[rfiH0]; ok {
		for _, hit := range h0.primary {
			controlFired[hit.Name] = true
			out.ControlFired = append(out.ControlFired, hit.Name)
		}
	}
	for _, id := range []triage.ProbeID{rfiH1, rfiH2} {
		r, ok := reads[id]
		if !ok {
			continue
		}
		for _, hit := range r.primary {
			if controlFired[hit.Name] {
				continue
			}
			out.Fired = append(out.Fired, string(id)+":"+hit.Name)
			if out.Winner == "" || (!out.Named && r.namedInError) {
				out.Winner, out.Hit, out.Named = id, hit, r.namedInError
			}
		}
	}
	switch {
	case out.Winner != "":
		out.Key = rfiOutcomeFetchAttempted
	case len(controlFired) > 0:
		out.Key = rfiOutcomeErrorNotRemote
	}
	return out
}

// rfiStateForOutcome is the in-band tier's CEILING, written as one total function so a test can
// walk every outcome and assert that not one of them is a finding and not one of them is a clean.
// A ceiling asserted in prose is a ceiling nobody can check.
func rfiStateForOutcome(key string) (triage.TriageState, triage.TriageGrade) {
	switch key {
	case rfiOutcomeFetchAttempted:
		// Suspicious, never finding: an error proves an ATTEMPT, and this class's finding is an
		// INCLUSION. The grade is raised to medium by the caller when the error names our URL.
		return triage.StateSuspicious, triage.GradeLow
	default:
		// Everything else is an unknown. There is deliberately no clean and no not_exploitable
		// branch: without a collaborator, an application that fetches silently and one that never
		// fetched produce the same bytes.
		return triage.StateCannotDetermine, triage.GradeUnrated
	}
}

// rfiInBandOutcomes lists every outcome, so the ceiling test cannot pass by walking a set that
// somebody forgot to extend.
func rfiInBandOutcomes() []string {
	return []string{rfiOutcomeFetchAttempted, rfiOutcomeErrorNotRemote, rfiOutcomeNoError}
}

// rfiMissingHalf names which half of this class's real oracle is absent, because "we have no
// collaborator" and "we have one that cannot serve content" are two different things to fix and
// the operator is the one who has to fix them.
func rfiMissingHalf(o triage.OOBConfig) string {
	switch {
	case o.Mode == triage.OOBNone || o.Base == "":
		return "no_collaborator"
	case !o.ServesContent:
		return "no_content_collaborator"
	default:
		return ""
	}
}

// rfiInBandCeiling is the sentence appended to EVERY in-band verdict. It names the missing half
// and states, in the row itself, that nothing here is evidence of absence.
func rfiInBandCeiling(o triage.OOBConfig) string {
	half := rfiMissingHalf(o)
	detail := "no collaborator is configured at all"
	if half == "no_content_collaborator" {
		detail = "the configured collaborator records callbacks and cannot SERVE content"
	}
	return " " + half + ": THE FINDING THIS CLASS EXISTS FOR IS OUT OF REACH ON THIS RUN. Proving remote file " +
		"inclusion means seeing bytes a host under our control served come back in the response, and " + detail +
		". A callback alone is SSRF's finding and this class does not borrow it. Nothing on this row is evidence " +
		"that this target does not include remote files"
}

// rfiReadInBand applies this class's own signature table to one of its own observations. It is
// one function so the production path and the fixtures cannot drift: a test that rebuilt the
// read by hand would be asserting against its own copy of the rules.
func rfiReadInBand(o faOwnObs, sigs []faSignature) rfiInBandRead {
	r := rfiInBandRead{obs: o}
	r.primary, r.corroborating = faMatchSignatures(sigs, o.Obs.Body)
	if form, ok := faByteForm(o.Obs.Body, []byte(o.Marker)); ok {
		r.markerPresent, r.markerForm = true, form
	}
	r.namedInError = rfiHitNearMarker(o.Obs.Body, o.Marker, r.primary)
	return r
}

// rfiHitNearMarker reports whether any primary hit sits within rfiErrorProximity bytes of this
// probe's own marker, which is what tells "the error names OUR url" apart from "the page reflects
// our value somewhere and also carries an error".
func rfiHitNearMarker(body []byte, m triage.Marker, hits []faSigHit) bool {
	if m == "" || len(hits) == 0 {
		return false
	}
	low := bytes.ToLower(body)
	needle := bytes.ToLower([]byte(m))
	for _, h := range hits {
		from := 0
		for {
			rel := bytes.Index(low[from:], needle)
			if rel < 0 {
				break
			}
			off := from + rel
			from = off + 1
			d := off - h.Offset
			if d < 0 {
				d = -d
			}
			if d <= rfiErrorProximity {
				return true
			}
		}
	}
	return false
}

// rfiStatusDifferential describes, in one short string, how the remote URLs' status codes differ
// from the scheme-stripped control's. It is an annotation and never an oracle.
func rfiStatusDifferential(reads map[triage.ProbeID]rfiInBandRead) string {
	h0, ok := reads[rfiH0]
	if !ok {
		return ""
	}
	out := ""
	for _, id := range []triage.ProbeID{rfiH1, rfiH2} {
		r, ok := reads[id]
		if !ok || r.obs.Obs.Status == h0.obs.Obs.Status {
			continue
		}
		if out != "" {
			out += "; "
		}
		out += string(id) + " " + strconv.Itoa(r.obs.Obs.Status) + " vs RFI-H0 " + strconv.Itoa(h0.obs.Obs.Status)
	}
	return out
}

// Settle is the deferred pass, and this is the ONE class in the family that genuinely needs one.
//
// WHY. An out-of-band callback is the only evidence RFI's weaker oracle has, and it arrives on a
// different connection at a time nobody controls: a queued job, a thumbnailer, a virus scanner or
// a link unfurler can fetch the URL minutes after the response came back. Classifying at response
// time and never looking again turns every asynchronous fetcher into a cannot_determine, and on a
// second pass it becomes a clean or a finding with the same probes and no extra requests. The
// sibling classes embed the no-op because a file read either came back in the response or did not.
//
// It re-runs Classify against the ctx it is handed, which now carries the callbacks that arrived
// during the grace window. It sends nothing.
func (c rfiClassifier) Settle(ctx triage.ClassifyCtx) []triage.ClassVerdict {
	if ctx.Callbacks.Len() == 0 {
		return nil
	}
	out := c.Classify(ctx)
	for i := range out {
		if out[i].Annotations == nil {
			out[i].Annotations = map[string]any{}
		}
		out[i].Annotations["settled_after_grace_window"] = true
		out[i].Annotations["callbacks_at_settle"] = ctx.Callbacks.Len()
	}
	return out
}

// rfiProbeIDsFor is the per-slot payload list, kept as DATA so a test can assert the property
// that matters without a ctx nobody outside package triage can build: all four remote forms go
// out together and none of them waits on another one's callback.
// rfiInBandProbeIDs is the in-band tier's payload list, kept as DATA for the same reason the OOB
// list is: a test can assert that the control is in it and goes first without building a ctx.
func rfiInBandProbeIDs() []triage.ProbeID { return []triage.ProbeID{rfiH0, rfiH1, rfiH2} }

func rfiProbeIDsFor(k triage.SlotKind) []triage.ProbeID {
	ids := []triage.ProbeID{rfiR1, rfiR2, rfiR3, rfiNC1}
	switch k {
	case triage.KindQuery, triage.KindBody, triage.KindPath:
		ids = append(ids, rfiR4)
	}
	return ids
}

// rfiServedBytes is the exact content the collaborator serves for one probe: this probe's own
// marker, twice, and nothing else.
func rfiServedBytes(m triage.Marker) []byte {
	if m == "" {
		return nil
	}
	return []byte(string(m) + string(m))
}

// rfiCallbackFor asks whether a callback arrived for one probe's marker.
//
// It iterates ClassifyCtx.Callbacks, which the runner has already filtered to this class's own
// ordinal stripe, and it checks the marker anyway. A record whose marker is not this probe's is
// not this probe's evidence even when it is this class's, because attributing a callback to the
// wrong probe attributes a finding to the wrong slot.
func rfiCallbackFor(cbs triage.OwnedCallbacks, m triage.Marker) bool {
	if m == "" {
		return false
	}
	for i := 0; i < cbs.Len(); i++ {
		rec, err := cbs.At(i)
		if err != nil {
			continue
		}
		if rec.Marker == m {
			return true
		}
	}
	return false
}

func rfiLabel(ann map[string]any) triage.TriageLabel {
	if t, _ := ann["rfi_tier"].(string); t == rfiTierInBand {
		hints := map[string]string{
			"tier": "in_band_fetch_error. Three requests at an unresolvable .invalid host, no collaborator, " +
				"no callback and no packet to any third party. It reads the ERROR a fetching stack prints, not the fetch",
			"what_is_out_of_reach": "remote file inclusion itself. Proving it means seeing bytes a host under our " +
				"control served come back in the response, which needs a collaborator that can SERVE content. This " +
				"run has none, so this class cannot reach a finding or a clean and its rows say so",
			"what_a_suspicion_here_means": "the slot reaches a URL fetcher or a file include. Point ssrfmap and " +
				"lfimap at it, and configure a content-serving collaborator to settle the inclusion question",
			"php_note": "allow_url_include off refutes a remote INCLUDE only. allow_url_fopen defaults to on, and " +
				"file_get_contents, fopen, copy, simplexml_load_file, DOMDocument::load and getimagesize all fetch a " +
				"remote URL by default, so a wrapper-disabled message is a pointer and not a refutation",
		}
		if v, ok := ann["winning_signature"].(string); ok {
			hints["error_signature"] = v
		}
		if v, ok := ann["status_differential"].(string); ok {
			hints["status_differential"] = v
		}
		return triage.TriageLabel{Tools: []string{"ssrfmap", "lfimap"}, Hints: hints}
	}
	hints := map[string]string{
		"ownership": "a callback with no content is SSRF's finding, not this class's. This class " +
			"never reads SSRF's callback record and never claims SSRF's result, and SSRF must establish " +
			"its own with its own probes",
		"served_bytes": "the collaborator serves this probe's marker twice at " + rfiServedFile +
			", thirty-two bytes with no code of any kind, so a target that includes it executes nothing",
		"php_note": "allow_url_include off refutes a remote INCLUDE only. allow_url_fopen defaults to " +
			"on, and file_get_contents, fopen, copy, simplexml_load_file, DOMDocument::load and " +
			"getimagesize all fetch a remote URL by default, so this class still runs",
	}
	if v, ok := ann["probes_that_called_back"]; ok {
		hints["fetch_proven_by"] = triageSprint(v)
	}
	return triage.TriageLabel{Tools: []string{"lfimap", "ssrfmap"}, Hints: hints}
}

// triageSprint is a tiny local formatter so the label does not need fmt for one call site.
func triageSprint(v any) string {
	if ids, ok := v.([]triage.ProbeID); ok {
		parts := make([]string, 0, len(ids))
		for _, id := range ids {
			parts = append(parts, string(id))
		}
		return joinStrings(parts, ", ")
	}
	return ""
}

func joinStrings(parts []string, sep string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += sep
		}
		out += p
	}
	return out
}

// ---------------------------------------------------------------------------------------------
// CONFIRMERS, EVIDENCERS, ORACLE CASES
// ---------------------------------------------------------------------------------------------

func (rfiClassifier) Confirmers() []faConfirmer {
	return []faConfirmer{
		{
			Name: "fresh_marker_fresh_file", Probes: []triage.ProbeID{rfiR1},
			Rule: "re-send the winning payload with a FRESH marker, which means a fresh DNS label and " +
				"a fresh thirty-two served bytes. A cached response, a stale callback from an earlier run " +
				"and a coincidental string all fail this and a live inclusion passes it",
		},
		{
			Name: "unresolvable_twin", Probes: []triage.ProbeID{rfiNC1},
			Rule: "the .invalid host must produce neither a callback nor a content hit. A callback " +
				"there means something in the path resolves names for us and every out-of-band " +
				"conclusion on the run is void",
		},
		{
			Name: "scheme_stripped_twin", Probes: []triage.ProbeID{rfiH0, rfiH1, rfiH2},
			Rule: "the in-band tier's control carries the same bytes with no scheme, so it is a relative " +
				"path and not a remote URL. A remote-fetch phrase that fires on BOTH is a phrase about the " +
				"string, and the tier reports error_not_specific_to_a_remote_url rather than a suspicion. " +
				"Without this the tier calls every strict input validator a remote fetcher",
		},
		{
			Name: "error_names_our_url", Probes: []triage.ProbeID{rfiH1, rfiH2},
			Rule: "the strong form of the in-band hit: the error phrase sits within 512 bytes of this " +
				"probe's own marker, so the message is about the URL we sent. A hit without it is still " +
				"reported and is graded low, because the control differential alone attributes it to the " +
				"probe and not to the URL",
		},
		{
			Name: "answer_not_in_wire", Probes: []triage.ProbeID{rfiR1, rfiR2, rfiR3, rfiR4},
			Rule: "the thirty-two served bytes must be absent from the request. The request carried a " +
				"URL in which the marker appears once, so the doubled run can only have come from the " +
				"collaborator. This is asserted per probe and not assumed",
		},
	}
}

func (rfiClassifier) Evidencers() []faEvidencer {
	return []faEvidencer{
		{Name: "served_content_echoed", Kind: "content", What: "the served thirty-two bytes and the transform form they came back in"},
		{Name: "callback_record", Kind: "callback", What: "protocol, source IP and source ASN of the fetch, which is what tells the operator whether the fetcher is the application or a third-party unfurler"},
		{Name: "winning_scheme", Kind: "annotation", What: "http, https or scheme-relative, which says whether the sink prepends its own scheme and whether it refuses plain http"},
		{Name: "extension_truncation", Kind: "annotation", What: "R4 succeeding where R1 fails means the sink appends an extension, which is the single most useful thing the tool can be told"},
		{Name: "remote_fetch_error", Kind: "error_path", What: "the in-band tier's phrase and the bytes that matched: which stack fetched (PHP wrapper, java.net, getaddrinfo, curl, Go) and, when the phrase names the URL, that the value reached the fetcher unmodified"},
		{Name: "scheme_asymmetry", Kind: "annotation", What: "H1 erroring where H2 does not, or the reverse, says the sink refuses one scheme, which is exactly what decides whether the OOB tier needs https when a collaborator is built"},
		{Name: "status_differential", Kind: "differential", What: "the remote URLs' status against the scheme-stripped control's. Recorded and never scored: it fires on every validator that dislikes a colon"},
	}
}

// OracleCases. /rfi/fetchonly is the route that keeps this class from absorbing SSRF's findings,
// and it is also the only route on which this class can produce a clean.
func (rfiClassifier) OracleCases() []faOracleCase {
	return []faOracleCase{
		{
			Name: "remote_include", Route: "/rfi/include", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{rfiR1}, WantState: triage.StateFinding,
			Why: "fetches the URL and includes the body in its response. Needs the local fake " +
				"collaborator to be SERVING, not just recording, which is the piece the oracle container " +
				"does not have today",
		},
		{
			Name: "fetch_and_discard", Route: "/rfi/fetchonly", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{rfiR1, rfiNC1}, WantState: triage.StateClean,
			Why: "fetches the URL and throws the body away. The callback arrives and the content does " +
				"not, so the verdict must be clean and the label must say the fetch itself may be SSRF's " +
				"finding. THIS IS THE ROUTE THAT KEEPS THIS CLASS FROM ABSORBING SSRF'S RESULTS, and it " +
				"is simultaneously the only route where clean is the correct answer, so it verifies both " +
				"halves of the boundary at once",
		},
		{
			Name: "https_only_fetcher", Route: "/rfi/httpsonly", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{rfiR1, rfiR2}, WantState: triage.StateFinding,
			Why: "refuses plain http and includes over https. R1 produces nothing at all here, so this " +
				"route is what proves R2 is not gated on R1: a class that promoted R2 only after R1's " +
				"callback would report cannot_determine on a live remote include",
		},
		{
			Name: "no_content_collaborator", Route: "(configuration, not a route)", Expect: faExpectNegative, Exists: false,
			Probes: rfiInBandProbeIDs(), WantState: triage.StateCannotDetermine,
			Why: "run the class with a collaborator that records callbacks and cannot serve, or with none " +
				"at all. It must send the THREE in-band probes and no more, it must never reach a finding " +
				"or a clean, and every row must carry oob_half_missing. The count is the assertion: five " +
				"requests here means the class tried its OOB tier with half an oracle, and zero means it " +
				"went back to answering nothing at all behind an enabled checkbox",
		},
		{
			Name: "inband_wrapper_disabled", Route: "/rfi/inband-include", Expect: faExpectPositive, Exists: false,
			Probes: []triage.ProbeID{rfiH0, rfiH1}, WantState: triage.StateSuspicious,
			Why: "a route that passes the value to an include and prints the PHP warning naming the URL " +
				"and allow_url_include. H1 must fire, the scheme-stripped H0 must NOT, and the verdict must " +
				"be suspicious and never a finding: the warning proves the value reached an include, and no " +
				"content was ever echoed, which is what a finding would require",
		},
		{
			Name: "inband_validator_hates_the_string", Route: "/rfi/inband-reject", Expect: faExpectNegative, Exists: false,
			Probes: rfiInBandProbeIDs(), WantState: triage.StateCannotDetermine,
			Why: "a route that 500s with a stack trace for ANY value containing a dot-separated host, " +
				"remote or not. H0 produces the same phrase as H1, so the tier must report " +
				"error_not_specific_to_a_remote_url. THIS IS THE ROUTE THAT KEEPS THE IN-BAND TIER FROM " +
				"CALLING EVERY STRICT INPUT VALIDATOR A REMOTE FETCHER, and without it the control is " +
				"decoration",
		},
		{
			Name: "resolver_answers_invalid", Route: "(configuration, not a route)", Expect: faExpectNegative, Exists: false,
			Probes: []triage.ProbeID{rfiNC1}, WantState: triage.StateCannotDetermine,
			Why: "run behind a resolver that answers for .invalid, as a captive portal and several " +
				"corporate resolvers do. The control must fire and the whole slot must become " +
				"detector_unverified, because otherwise every out-of-band verdict in the run is built on " +
				"a channel that answers for anything",
		},
		{
			Name: "reflection_is_not_inclusion", Route: "/clean/echo", Expect: faExpectNegative, Exists: true,
			Probes: []triage.ProbeID{rfiR1, rfiNC1}, WantState: triage.StateCannotDetermine,
			Why: "reflects the URL and fetches nothing. The marker comes back ONCE, in the echoed URL, " +
				"and the detector looks for it TWICE and unaccompanied by the URL, so it must stay " +
				"silent. The verdict is no_fetch_observed and NOT clean, because nothing proved the " +
				"absence of a fetch",
		},
	}
}
