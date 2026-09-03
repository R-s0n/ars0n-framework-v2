package utils

import (
	"encoding/json"
	"net/http"
	"sort"

	"github.com/gorilla/mux"
)

// THE METHODOLOGY AN EXPERIENCED HUNTER WOULD BRING, available to whoever is driving.
//
// WHY THIS FILE EXISTS. The framework already carried this knowledge, in the Help Me Learn modals,
// and it was reachable only by a human clicking an accordion in a browser. An AI operating the same
// framework through the MCP server got the tool descriptions and nothing else: no ordering, no sense
// of which step matters, no idea what a real hunter does first.
//
// That produced a concrete, expensive failure. On the first full engagement the fuzzing flow was
// built as ten steps that fuzzed query parameters, headers and cookies against endpoints that were
// ALREADY KNOWN. Not one step put FUZZ in the path. Content discovery at the web root, which is the
// first thing anyone does on day one, never ran at all. As a direct consequence /admin was never
// requested, never returned its 403, never entered any table, and the entire access-bypass section
// had nothing to work on. The framework was not missing the capability: ffuf-wordlist-5000.txt ships
// with the framework and its fourth line is literally "admin". Nobody asked.
//
// So the knowledge lives here, in Go, served over the API, and read by BOTH the client and the MCP
// server. One source of truth. An operator, human or otherwise, that is about to run a step can ask
// what the step is for, what to do first, and what people habitually get wrong.

// MethodologyStep is the guidance for one step of a workflow.
type MethodologyStep struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Stage locates this step in the overall methodology, so a caller can tell whether they are
	// skipping ahead.
	Stage string `json:"stage"`
	// Order is the position within the workflow. Callers that want to know what to do next sort by it.
	Order int `json:"order"`
	// Why the step exists at all, in terms of what it changes about the rest of the engagement.
	Why string `json:"why"`
	// DoFirst is the ordered opening moves. Deliberately opinionated: "it depends" is useless to
	// someone deciding what to run in the next thirty seconds.
	DoFirst []string `json:"do_first"`
	// HowHuntersWorkIt is what separates a competent pass from going through the motions.
	HowHuntersWorkIt []string `json:"how_hunters_work_it"`
	// CommonMistakes are the failures actually observed, on this framework, against real targets.
	CommonMistakes []string `json:"common_mistakes"`
	// Prerequisites names the steps whose output this one consumes, so a caller can tell when they are
	// about to run something that will find nothing because its input is empty.
	Prerequisites []string `json:"prerequisites,omitempty"`
	Tools         []string `json:"tools,omitempty"`
	References    []string `json:"references,omitempty"`
}

// MethodologyFor returns the guidance for one step, and whether it exists.
func MethodologyFor(key string) (MethodologyStep, bool) {
	step, ok := methodologySteps[key]
	return step, ok
}

// GetMethodology answers GET /methodology and GET /methodology/{step}.
func GetMethodology(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if key := mux.Vars(r)["step"]; key != "" {
		step, ok := MethodologyFor(key)
		if !ok {
			writeJSONError(w, http.StatusNotFound, "unknown_step",
				"No methodology guidance for step "+key+". Call /methodology for the list.")
			return
		}
		json.NewEncoder(w).Encode(step)
		return
	}

	out := make([]MethodologyStep, 0, len(methodologySteps))
	for _, step := range methodologySteps {
		out = append(out, step)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Order < out[j].Order })
	json.NewEncoder(w).Encode(map[string]any{
		"steps": out,
		"note": "The URL workflow in the order it is meant to be run. A step whose prerequisites are " +
			"empty will complete successfully and find nothing, which is the single most common way " +
			"to waste an engagement.",
	})
}

var methodologySteps = map[string]MethodologyStep{
	"manual-crawl": {
		Key: "manual-crawl", Title: "Manual crawling", Stage: "Mapping", Order: 10,
		Why: "Everything downstream inherits the gaps of this step, silently. A feature you never " +
			"exercise produces no captured request, so it becomes no attack vector, so every scanner " +
			"reports clean on it forever. Automated tools find what exists; only a human working the " +
			"application understands what matters.",
		DoFirst: []string{
			"Browse the whole application through the capture extension, logged in, as a real user.",
			"SUBMIT every form, do not just visit the page holding it. A form you look at and do not " +
				"submit produces no body vector.",
			"Exercise every role you can obtain, and note what each can reach.",
			"Write down every object identifier you see: order numbers, user ids, document ids.",
		},
		HowHuntersWorkIt: []string{
			"They spend longer here than feels comfortable, because this is where the business logic " +
				"is learned and business logic is where the valuable bugs are.",
			"They look for the trust decisions: anywhere the application decides who may see or do what.",
			"They watch the traffic, not the page. The interesting request is often one the interface " +
				"never mentions.",
		},
		CommonMistakes: []string{
			"Clicking links and never submitting forms, which yields query vectors and almost no body " +
				"vectors.",
			"Missing widgets that are not forms. On the reference target the newsletter signup was a " +
				"div with data-action driving an XHR, so it produced ZERO captured rows, became no " +
				"vector, and reported clean in every section while holding a real XSS.",
		},
		Tools: []string{"browser extension capture"},
	},

	"content-discovery": {
		Key: "content-discovery", Title: "Content discovery: fuzzing for hidden paths",
		Stage: "Mapping", Order: 20,
		Why: "This is day one of bug bounty hunting and it is the step that finds what nothing links " +
			"to. Crawling finds what the application advertises; archives find what it used to " +
			"advertise. Neither finds the admin panel nobody links to, the backup file, the staging " +
			"route or the forgotten API version. Those are the least protected things on the target " +
			"precisely because nobody remembers they are there.",
		DoFirst: []string{
			"FUZZ THE WEB ROOT FIRST: https://target/FUZZ. Before parameters, before headers, before " +
				"anything clever. This is the first command of the engagement.",
			"Start with a SMALL curated list (common.txt or quickhits.txt) to learn the target's " +
				"response shapes and set filters, before spending tens of thousands of requests.",
			"Read the baseline: what does a definitely-missing path return? If every miss is a 200 " +
				"carrying a themed not-found page, matching on status finds nothing and you must " +
				"filter on size, words or lines instead.",
			"Then run a larger list (raft-medium-directories, then raft-large) with the filters tuned.",
			"Recurse into what you find, with a bounded depth.",
			"Re-run with extensions for the stack you identified: -e .php,.bak,.old,.zip,.sql,.json.",
		},
		HowHuntersWorkIt: []string{
			"They tailor the wordlist to the target rather than always reaching for the biggest one. " +
				"A list matched to the framework in use finds more with fewer requests than a generic " +
				"million-line list.",
			"They treat 401 and 403 as FINDINGS, not as noise. A 403 means the resource exists and is " +
				"being withheld, which is the single best input to an access-control bypass attempt.",
			"They fuzz extensions separately from directories, because the two produce different " +
				"baselines and mixing them ruins the filters for both.",
			"They repeat content discovery on every host and every discovered directory prefix, not " +
				"just once at the apex.",
			"They run it again later in the engagement, because a path learned from a JavaScript file " +
				"or an error message suggests siblings worth trying.",
		},
		CommonMistakes: []string{
			"NOT RUNNING IT AT ALL. On the reference engagement the fuzzing flow contained ten steps " +
				"and every one of them fuzzed parameters, headers or cookies on endpoints that were " +
				"already known. No step ever put FUZZ in the path, so /admin was never requested, and " +
				"the entire access-bypass section had zero targets as a direct result.",
			"Trusting -ac blindly. Auto-calibration suppresses responses that resemble the baseline, " +
				"and on a target whose real content resembles its own not-found page it will filter " +
				"away genuine findings.",
			"Fuzzing only the apex and never the discovered subdirectories.",
			"Reading a wall of 404s as 'nothing here' when the filter was simply wrong.",
		},
		Prerequisites: []string{},
		Tools:         []string{"ffuf"},
		References: []string{
			"https://codingo.com/posts/2020-08-29-everything-you-need-to-know-about-ffuf/",
			"https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content",
		},
	},

	"archive-discovery": {
		Key: "archive-discovery", Title: "Archive and JavaScript mining", Stage: "Mapping", Order: 30,
		Why: "Public archives remember URLs the application no longer advertises, and JavaScript " +
			"files name endpoints no crawler will ever reach by following links. Together they " +
			"recover the deprecated and the undocumented, which tend to be the least maintained.",
		DoFirst: []string{
			"Run the archive tools and the JavaScript miner together; they overlap very little.",
			"Read the JavaScript by hand as well as running the extractor. Regexes find literal " +
				"strings; a human finds the endpoint assembled from three variables.",
			"Feed anything you learn back into content discovery as new prefixes to fuzz.",
		},
		HowHuntersWorkIt: []string{
			"They treat an old API version found in an archive as a priority target: it is still " +
				"deployed often enough to matter and is rarely maintained.",
			"They diff the JavaScript between visits, because a new bundle names new endpoints.",
		},
		CommonMistakes: []string{
			"Accepting an empty archive result as fact. A tool that returns nothing and exits zero " +
				"looks identical to a domain with no history.",
			"Letting one archive tool stand in for the rest. On the reference target excluding one " +
				"provider cost 85 percent of the archive surface.",
		},
		Tools: []string{"waybackurls", "gau", "katana", "gospider", "linkfinder"},
	},

	"parameter-discovery": {
		Key: "parameter-discovery", Title: "Hidden parameter enumeration", Stage: "Mapping", Order: 40,
		Why: "A parameter the developer never documented is a parameter nobody reviewed for injection " +
			"or for authorization. A single endpoint with three hidden parameters is four things to " +
			"test, not one.",
		DoFirst: []string{
			"Run this AFTER content discovery, not instead of it. Parameters are found on endpoints, " +
				"so the endpoint list bounds what this can possibly cover.",
			"Point it at endpoints that plausibly branch on input, not at static pages.",
			"Match each discovered parameter to the bug class its NAME suggests: id to IDOR, url to " +
				"SSRF, file to traversal, debug or admin to a logic flaw.",
		},
		HowHuntersWorkIt: []string{
			"They test magic parameters explicitly: debug, test, admin, is_admin, role, preview, set " +
				"to 1 or true, which unlock behaviour rather than injecting anything.",
			"They run two tools, because the diffing strategies and wordlists differ and each finds " +
				"what the other misses.",
		},
		CommonMistakes: []string{
			"Running parameter discovery as the FIRST fuzzing step, which is what happened on the " +
				"reference engagement. It is a mapping step for endpoints you already have, and it " +
				"cannot discover an endpoint.",
		},
		Prerequisites: []string{"content-discovery", "archive-discovery"},
		Tools:         []string{"arjun", "x8", "ffuf"},
	},

	"consolidate-vectors": {
		Key: "consolidate-vectors", Title: "Consolidate attack vectors", Stage: "Planning", Order: 50,
		Why: "This is the list every scanner below will run against, so its gaps become their blind " +
			"spots. It is the last cheap moment to notice that a whole class of input was never " +
			"captured.",
		DoFirst: []string{
			"Check the count at EACH of the five insertion points. A zero means every tool will report " +
				"nothing wrong with that insertion point, because nothing was ever sent there.",
			"Compare the list against the application's features from memory. Anything missing is a " +
				"hole you can still close by crawling it or adding the vector by hand.",
			"Look for a response cookie whose value echoes a request parameter: that is the same " +
				"injectable input arriving by a second, untested route.",
		},
		HowHuntersWorkIt: []string{
			"They treat a suspiciously small vector count as evidence about their own crawl rather " +
				"than as evidence the application is simple.",
		},
		CommonMistakes: []string{
			"Reading a healthy total as coverage. On the reference target there were 19 cookie " +
				"vectors, which looks fine, and every one was a cookie the browser happened to be " +
				"carrying. The cookie that mattered was one the server built from an injectable " +
				"parameter, and it was not among them.",
		},
		Prerequisites: []string{"manual-crawl", "content-discovery", "parameter-discovery"},
	},

	"vector-scanning": {
		Key: "vector-scanning", Title: "Running the vulnerability scanners", Stage: "Testing", Order: 60,
		Why: "This is where the automated tools finally run. Their output is only worth what their " +
			"input covered, and every one of them fails OPEN: given an argument it does not " +
			"understand, a scanner exits having tested nothing and the result is recorded as clean.",
		DoFirst: []string{
			"Confirm the session is live and will stay live. A scan that outlives its session records " +
				"every remaining vector as clean against a login wall.",
			"Check the scan verdict, not the finding count. A run reporting zero findings is only a " +
				"result if it finished the work it said it would.",
			"Read the What Ran tab on anything surprising. A scan of fifty vectors that finished in " +
				"forty seconds did not test fifty vectors.",
		},
		HowHuntersWorkIt: []string{
			"They confirm every finding by hand before reporting it, because a scanner's confidence " +
				"label is a claim about its own heuristic and not about the application.",
			"They read what a tool did NOT test as carefully as what it did.",
		},
		CommonMistakes: []string{
			"Believing a clean result from a tool that never sent a request. Measured repeatedly on " +
				"this framework: a rejected option, a cached verdict, a lost session and an empty " +
				"argument all produce a confident, fast, entirely empty scan.",
		},
		Prerequisites: []string{"consolidate-vectors"},
	},

	"access-bypass": {
		Key: "access-bypass", Title: "Access control bypass", Stage: "Testing", Order: 70,
		Why: "A 403 means the resource exists and is being withheld, which is the most promising " +
			"starting position on a target. The bypass usually comes from a disagreement between " +
			"where the rule is applied and where the routing decision is made.",
		DoFirst: []string{
			"Get some 401s and 403s first. This section is empty without them, and they come from " +
				"CONTENT DISCOVERY. If no path fuzzing has run, there is nothing here to do.",
			"For every candidate take the negative control: fetch the finding's own URL with no added " +
				"header and compare. Most candidates die at this step.",
			"Compare bodies, never status codes.",
		},
		HowHuntersWorkIt: []string{
			"They name the privileged string: something in the body the denial withheld. Without one " +
				"there is a status code and no finding.",
			"When a technique works they immediately try it against every other protected path.",
		},
		CommonMistakes: []string{
			"Having no targets and concluding the target is well protected. On the reference " +
				"engagement there were ZERO 401 or 403 responses anywhere in the database, because no " +
				"path fuzzing had run, while an unauthenticated header bypass on /admin was real and " +
				"was eventually found by hand.",
		},
		Prerequisites: []string{"content-discovery"},
		Tools:         []string{"nomore403", "forbidden"},
	},

	"threat-model": {
		Key: "threat-model", Title: "STRIDE threat modelling", Stage: "Analysis", Order: 80,
		Why: "Access control and business logic bugs have no signature a scanner can match: a " +
			"successful attack looks like an ordinary 200. They are only findable if the intended " +
			"rule was written down first.",
		DoFirst: []string{
			"Record the mechanisms, objects and controls before writing threats. A threat referencing " +
				"nothing concrete cannot be tested.",
			"Work spoofing and elevation of privilege first: those are the categories the tools cannot " +
				"help with at all.",
			"Write each threat so it names one endpoint and one test.",
		},
		HowHuntersWorkIt: []string{
			"They treat every threat as a hypothesis with a test attached, and close the ones that " +
				"fail so the model records coverage rather than only findings.",
		},
		CommonMistakes: []string{
			"Writing threats too vaguely to test. 'The API might have authorization problems' cannot " +
				"be acted on; 'a standard user can read another user's order by changing orderId' can " +
				"be checked in one request.",
		},
		Prerequisites: []string{"manual-crawl"},
	},
}

// GetAttackVectorModel answers GET /attack-vector-model: the taxonomy the framework is built on.
//
// Served rather than described in prose because it is the vocabulary everything else uses, and an
// operator who has not got it will use the tools without understanding what a "vector" is or why two
// requests that look different are the same one.
func GetAttackVectorModel(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"injection_attack_vector": map[string]any{
			"definition": "The unique combination of four things in an HTTP request: the HTTP verb, " +
				"the domain and port, the endpoint, and the injection point.",
			"implication": "Two requests differing only in the VALUE sent are the SAME vector. Two " +
				"differing in which parameters are in play, or in where the payload goes, are " +
				"DIFFERENT vectors. This is exactly the identity attack_vectors keys on, so the " +
				"table is this definition made literal.",
			"why_it_matters": "It is what stops a crawl of forty requests with forty search terms " +
				"being read as forty things to test, and what stops one path with a query vector and " +
				"a body vector being collapsed into one.",
		},
		"logic_attack_vector": map[string]any{
			"definition": "One of four things, none of which a scanner can find.",
			"types": []map[string]string{
				{"type": "Overly complex mechanism",
					"why": "The more requests and parameters a mechanism needs, the more chances there " +
						"are for one of them to be skippable or reorderable."},
				{"type": "Database query using an id from the HTTP request",
					"why": "If the caller supplies the identifier the server fetches by, the only thing " +
						"stopping an IDOR is an ownership check that is easy to forget."},
				{"type": "Granular access controls",
					"why": "The more precise the permissions, the harder they are to enforce " +
						"consistently, and the likelier one route was missed."},
				{"type": "Hacky implementation",
					"why": "Anything that looks like it was built under time pressure. Developers are " +
						"not lazy; they shipped a ticket and moved on, and the shortcut is the bug."},
			},
		},
		"insertion_points": map[string]any{
			"points": VectorInsertionPoints,
			"note": "Query and body get tested constantly and hardened accordingly. Header, cookie " +
				"and path are the ones that get skipped, which is exactly why input arriving there " +
				"is often unfiltered. A point with zero vectors will be reported clean by every tool " +
				"in every section, because nothing was ever sent there.",
		},
		"ffuf_purposes": FuzzFlowPurposes,
		"working_principle": map[string]string{
			"name": "Ebb and flow",
			"detail": "Work down the recon methodology until you have three to five attack vectors on " +
				"a target. Test them, but not for too long. When you get stuck, put a pin in them and " +
				"go back to an earlier part of recon: try new tools and techniques, anything that " +
				"expands your knowledge of the attack surface. Then pick three to five new vectors " +
				"and try again.",
		},
		"source": "rs0n (Harrison Richardson), DEFCON 32 Bug Bounty Village workshop. This framework " +
			"is an implementation of that methodology.",
	})
}

// GetToolGuidance answers GET /tool-guidance: what a scanner proves and how it lies.
//
// Backed by the same hard-coded content the results modal renders, so the AI and the human are told
// the same thing about the same finding rather than two teams maintaining two explanations.
func GetToolGuidance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	tool := r.URL.Query().Get("tool")
	kind := r.URL.Query().Get("kind")

	if tool != "" {
		explanation := ExplainFinding(tool, kind)
		if explanation.Title == "" {
			writeJSONError(w, http.StatusNotFound, "no_guidance",
				"No hard-coded guidance for tool "+tool+". That is a known gap rather than a "+
					"statement that the tool is simple: guidance exists for some tools and not others.")
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"tool": tool, "kind": kind, "guidance": explanation})
		return
	}

	// The whole catalogue, so a caller can see which tools have guidance and which do not.
	out := map[string]any{}
	for key := range findingExplanations {
		out[key] = findingExplanations[key].Title
	}
	json.NewEncoder(w).Encode(map[string]any{
		"available": out,
		"note": "Ask for one tool to get the full guidance: what it proved, what it did NOT prove, " +
			"what a false positive looks like, how to validate it by hand, and the severity framing. " +
			"Every tool here fails open, so a clean result from one is only worth what its specific " +
			"failure modes allow.",
	})
}
