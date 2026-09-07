// Lessons for the URL workflow sections that had no Help Me Learn content: Authentication,
// Authorization, HTTP Request Flows, Consolidate Attack Vectors, the twelve attack-tool sections,
// and Threat Model Results. Same shape as data/lessons.js (title, overview, sections[],
// practicalTips[], furtherReading[]) and merged into that export, so every consumer sees one flat
// lessons object.
//
// The tool sections are written from what these tools actually did against a live target during
// this project rather than from their README files. Where a tool has a failure mode that reads as
// a clean result, that failure mode is stated in the lesson, because a learner who does not know
// about it will read "0 findings" as "no vulnerability".

export const urlWorkflowLessons = {
  // ---------------------------------------------------------------------------------------------
  // HTTP Request Flows
  //
  // Written from what the five buttons on the Request Flow Replay card actually do, including the
  // numbers the server enforces (the loop caps, the rate ceiling, the verb filter), because a lesson
  // that describes a cap the code does not have is worse than no lesson.
  // ---------------------------------------------------------------------------------------------
  urlRequestFlowsMethodology: {
    title: "Request Flows: Why a Single Request Is the Wrong Unit",
    overview: "One click in a browser is almost never one request. This section groups the requests that belong together, so you can see a mechanism before you try to test any part of it, and so the steps that only work in sequence can be replayed in sequence.",
    sections: [
      {
        title: "One Click, Half a Dozen Requests",
        icon: "fa-diagram-project",
        content: [
          "Submit a login form and the browser does not send one request. It sends the POST, receives a 302, follows it with a GET of the page it lands on, and then runs whatever that page's JavaScript asks for: a session check, a profile fetch, a feature-flag call, three analytics beacons. Six or seven requests, one user action, and only two of them are interesting.",
          "Bigger mechanisms are worse. An OAuth handshake is typically four redirects across three hosts, tied together by a state parameter minted on the first and validated on the last. A password reset is a POST, an email, a GET carrying a token in the query string, and a second POST that consumes it. A checkout is a quote, a payment intent, a confirmation, and a webhook you never see at all.",
          "Test any one of those requests on its own and you are usually testing nothing. Replaying the OAuth callback without the request that minted the state gets you an error page. Replaying the second half of a reset without the first gets you an expired token. The sequence is the thing under test, so the sequence has to be the unit you work with."
        ],
        keyPoints: [
          "A form submit is a POST, a redirect, a page load, and the requests that page fires",
          "An OAuth handshake is several redirects across several hosts, tied together by one parameter",
          "Requests that only make sense in order cannot be judged one at a time",
          "The interesting request is usually the second or third in the group, not the first"
        ]
      },
      {
        title: "You Cannot Choose What You Cannot See Grouped",
        icon: "fa-sitemap",
        content: [
          "The capture corpus from a manual crawl is a flat list, in time order, of everything the browser did. On a real target that is thousands of rows, roughly ninety per cent of them scripts, stylesheets, fonts, images, and analytics pings. Scrolling that to work out which POST went with which redirect is not analysis, it is archaeology.",
          "Flow reconstruction reads the same rows a second time and draws them as a graph: the navigation that started it, the redirects it followed, and the requests the page issued afterwards, with an edge for each relationship and the reason that edge was drawn. Nothing is sent to the target to build this. It is a second reading of what the crawl already stored.",
          "The noise is hidden rather than deleted. The graph shows the request types that carry application behaviour and puts the rest behind a count and a toggle, because a diagram that omits things silently is worse than no diagram. When the header says 398 of 2,723 shown, you know exactly how much you are not looking at, and one click shows the rest."
        ],
        keyPoints: [
          "The raw capture list is time-ordered and mostly subresources",
          "A flow is drawn from stored captures; building one sends nothing",
          "Every edge carries the reason it was drawn, so you can weigh it yourself",
          "Hidden requests are counted and one toggle away, never dropped"
        ]
      }
    ],
    practicalTips: [
      "Crawl the feature end to end first; a flow can only ever contain what was captured",
      "Start with the flows that contain a redirect chain, since that is where state gets carried and dropped",
      "Read the edge reasons before trusting a grouping, especially on script-initiated requests",
      "Turn the hidden requests on once per flow to check nothing interesting was filtered away",
      "A flow with a single node is usually a page you loaded directly rather than a mechanism",
      "Note which request in the flow carries the decision; that is the one you will be editing later"
    ],
    furtherReading: [
      {
        title: "MDN - HTTP redirections",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
        description: "What the browser does with a 302, and why the chain matters"
      },
      {
        title: "PortSwigger - OAuth 2.0 authentication vulnerabilities",
        url: "https://portswigger.net/web-security/oauth",
        description: "A worked example of a mechanism that is only testable as a sequence"
      }
    ]
  },

  urlRequestFlowsDetection: {
    title: "Passive and Active Flow Detection",
    overview: "There are two ways to end up with a flow. Passive reconstructs what the browser already did, from captures you already have. Active sends requests to discovered endpoints to find routing nobody ever clicked. They find different things, and a flow found by both is a different fact from a flow found by either.",
    sections: [
      {
        title: "Passive: A Second Reading of the Crawl",
        icon: "fa-eye",
        content: [
          "Passive detection sends nothing at all. It groups the captures already stored for this target into flows: a navigation, the redirects it followed, and the requests the page issued afterwards. Everything it shows you is something a browser genuinely did while you were driving it, in the order it happened.",
          "That is its strength and its ceiling. The flows are real, they are authenticated if your crawl was, and the bodies are the bodies the application actually received. But a feature you never used produces no flow, exactly as a form you never submitted produces no attack vector. Passive coverage measures your crawling, not the application.",
          "So the first thing to do with the flow list is compare it against what you know the application does. A target with a password reset, an invite flow, and a checkout, showing three flows in the list, is not telling you the application is small. It is telling you where to go and crawl next."
        ],
        keyPoints: [
          "Passive detection is a read of stored captures and puts no traffic on the target",
          "The flows are real requests with real bodies, authenticated if your crawl was",
          "A feature you never exercised produces no flow",
          "Judge the flow list against the features you know exist, not against itself"
        ]
      },
      {
        title: "Active: Asking About Routes Nobody Walked",
        icon: "fa-satellite-dish",
        content: [
          "Active detection sends real requests to the endpoints already discovered on this target, with the verbs you choose, and reads what comes back: what redirects where, what a POST does to a route you only ever saw as a GET, which endpoints answer at all. It finds routing that exists but that nothing in your crawl ever triggered.",
          "A flow can carry both labels. When active detection reaches a flow that passive reconstruction already found, it is marked as found by both, and that agreement is information: the route is real and reachable without a browser session driving it. A flow marked active only is the more interesting kind, because nobody browsed it, which often means nobody hardened it either.",
          "Because it sends traffic, it is fenced. A host marked out of scope is never contacted, on the original endpoint and again on every redirect destination, and no setting on the run overrides that. Exclusions you wrote with a reason are enforced the same way. The verb filter runs against the verb each endpoint was observed with, so a GET-only run never invents a GET for something only ever seen as a POST. And the dry run is there to tell you what would go out, in what order, how many requests, and what is being skipped and why, before anything is sent."
        ],
        keyPoints: [
          "Active detection is the only part of this card that puts traffic on the target",
          "Passive only, active only, and both are three different statements about a flow",
          "Out of scope is enforced on the endpoint and on every redirect destination",
          "The verb selection is yours; the scope boundary is not"
        ]
      }
    ],
    practicalTips: [
      "Crawl first, then read the passive flows; active detection is worth more once the corpus is real",
      "Read the endpoint number on the card before running: it is what a run would send to, not what is ticked",
      "Start with GET only and a low rate, then widen once you have seen what comes back",
      "Treat active-only flows as your priority list, since nobody browsed them",
      "Ask for the dry run and read the skip reasons; that is where the surprises are",
      "Re-open the flow list after each crawl, since it is rebuilt from captures every time you look"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Test HTTP Methods",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
        description: "Why sending a verb an endpoint was never observed with is worth doing"
      },
      {
        title: "OWASP WSTG - Information Gathering",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/",
        description: "Mapping the surface before attacking any part of it"
      }
    ]
  },

  urlRequestFlowsRepeater: {
    title: "Replay Requests: What a Repeater Is For",
    overview: "A repeater takes one request the target already answered, lets you change any byte of it, and sends it again so you can compare the two responses. It is the most used tool in web testing and the whole idea fits in one sentence: change one thing, resend, see what moved.",
    sections: [
      {
        title: "Change One Thing, Send It Again, Compare",
        icon: "fa-rotate-right",
        content: [
          "If you have never used one: a repeater is not a scanner and it knows nothing about vulnerabilities. It is a text editor for an HTTP request with a send button next to it. On the left is the corpus of requests the crawl recorded, filtered by a small query language. Pick one and its exact bytes appear in the editor: request line, headers, blank line, body. Change something, press replay, and the raw response comes back beside it, status line and headers included.",
          "The discipline is to change one thing at a time. Change the user identifier in the path and nothing else, and the difference between the two responses was caused by the identifier. Change the identifier and a header together and you have learned something you cannot defend in a report. This is why the repeater outranks any scanner for real work: it produces evidence with a single stateable cause.",
          "Byte exactness is the other half of it. Nothing here reformats the request, re-orders headers, pretty-prints the body, or trims whitespace, because a tool that tidies your payload changes what the target receives. The one thing normalised is the line terminator, and only because a browser text box forces it; the editor puts the carriage returns back to match the style the request was loaded with, and there is a control to change that deliberately rather than by accident."
        ],
        keyPoints: [
          "A repeater is an editor for one request plus a send button, and nothing more",
          "Change one thing per send, or the comparison proves nothing",
          "The response is shown raw, because sometimes the exact bytes are the finding",
          "Nothing is reformatted behind your back: what is in the editor is what goes out"
        ]
      },
      {
        title: "Versions: Keeping Several Variants of One Request",
        icon: "fa-clone",
        content: [
          "In most repeaters an edit destroys the previous text, so testing four variants of one request means four tabs or a scratch file. Here every edit is written down as a version. The request the target originally answered is kept as the immutable original, and each save records the version it was edited from, so the column beside the editor is a small history you can click back through.",
          "That changes how you work. You can hold the clean baseline, the one with the identifier swapped, the one with the header removed, and the one carrying the payload, all against the same request, and come back to any of them tomorrow. When you write the finding, the version that demonstrated it is still there byte for byte instead of being reconstructed from memory.",
          "Versions are created when the bytes actually differ, and at the moments where an edit would otherwise be lost: when you press replay, when you click another version or another request, after a few seconds of not typing, and when the modal closes. Not per keystroke, and not when the bytes are unchanged. Closing is safe rather than destructive, which is why there is no prompt on the way out."
        ],
        keyPoints: [
          "The observed request is never overwritten by an edit",
          "Each version records which version it was edited from",
          "Edits are saved on replay, on switching away, after an idle pause, and on close",
          "Identical bytes create no version, so the column stays readable"
        ]
      }
    ],
    practicalTips: [
      "Send the request unmodified first; a baseline you did not capture is a comparison you cannot make",
      "Change one field per version, so the version itself records what you changed",
      "Watch the response size and time as well as the status; a 200 that is forty bytes shorter is a signal",
      "Use the query on the sitemap to find the request rather than scrolling a few thousand rows",
      "Keep the version that proves the bug: it is most of your reproduction steps already written",
      "If a response looks impossible, re-read your request bytes before blaming the target"
    ],
    furtherReading: [
      {
        title: "MDN - HTTP messages",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages",
        description: "What the bytes in the editor actually are, line by line"
      },
      {
        title: "PortSwigger - Burp Repeater",
        url: "https://portswigger.net/burp/documentation/desktop/tools/repeater",
        description: "The same tool in another product, documented at length"
      }
    ]
  },

  urlRequestFlowsReplaying: {
    title: "Replaying a Whole Flow, and Editing One Request Inside It",
    overview: "The repeater replays one request. This replays the sequence, in the order it was captured, and sends your edited version of any step in place of the original. That combination is what makes a multi-step mechanism testable at all.",
    sections: [
      {
        title: "Why the Sequence Has to Run",
        icon: "fa-list-ol",
        content: [
          "Most of what you want to test is step three of four. Step three needs a session step one established, a CSRF token step two handed out, and an identifier the application minted somewhere along the way. Replayed alone it fails, and it fails in a way that looks like the application refusing you rather than like a missing prerequisite. People abandon real findings at exactly this point.",
          "Running the whole flow removes the ambiguity. Steps one and two run as captured and do their job, step three arrives with everything it expects, and now the response to step three means something. This is also the shape almost every access-control test takes: establish an identity, obtain a reference, then use the reference in a way the rules say should be refused.",
          "A detected flow runs linearly, in the order the requests were captured. There are no conditions and no branching in one, because a detected flow is a reading of history and history did not branch. When you need it to make decisions, the same flow copies into the Request Flow Builder as editable steps."
        ],
        keyPoints: [
          "Step three usually cannot be tested without steps one and two",
          "A failed lone replay is often a missing prerequisite, not a refusal",
          "Detected flows replay linearly, in capture order, with no branching",
          "Copy the flow into the builder when it needs to react to what comes back"
        ]
      },
      {
        title: "Your Edit Is What Gets Sent",
        icon: "fa-pen-to-square",
        content: [
          "Any node in the graph opens as raw bytes, and saving creates a version exactly as the repeater does. Nothing is overwritten: the observed request stays as the original, and the picker walks back through everything you saved. That is what makes editing inside a flow safe enough to be useful, because you are never one keystroke away from losing what the target originally received.",
          "When the flow runs, the version each step will send is chosen explicitly, named on the node, counted in the header, listed in the dry run, and sent as an explicit pairing rather than left to a default at the far end. Quietly sending the original bytes after somebody spent ten minutes editing them is the worst outcome available here, so the run tells you what it is carrying and expects you to have read it.",
          "The run opens on a dry run, for the same reason Detect Flows does. The first click asks what would be sent, in what order, how many requests, and which steps are skipped and why. Sending is a second, deliberately different click. Change the configuration and the plan is invalidated, because a dry run of a different configuration is not evidence about this one. Results then land on the graph itself as each node's badge, with one toggle back to the captured statuses, because what happened during the crawl and what happened during your run are two different facts and must never be read as one."
        ],
        keyPoints: [
          "Editing a step inside a flow creates a version; the original is kept",
          "The run states which version every step will send, before it sends anything",
          "The first click is a dry run; sending is a separate, differently labelled click",
          "Run results replace the captured badges on the graph and toggle back"
        ]
      }
    ],
    practicalTips: [
      "Replay the flow unmodified once and confirm it still works before you change anything",
      "Read the dry run's skipped list; a step skipped for a good reason changes what the run proves",
      "Edit only the step you are testing and leave the rest as captured, so the cause is unambiguous",
      "A flow captured an hour ago may already be stale, since tokens and identifiers expire",
      "When a run fails at step one, fix the session before you look at anything else",
      "Note which step a proving version belongs to; a version out of its sequence is not a repro"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Testing for Bypassing Authorization Schema",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema",
        description: "The tests that need a sequence rather than a single request"
      },
      {
        title: "OWASP WSTG - Business Logic Testing",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/10-Business_Logic_Testing/",
        description: "Where the order of the requests is itself the vulnerability"
      }
    ]
  },

  urlRequestFlowsBuilder: {
    title: "The Request Flow Builder: Flows That Make Decisions",
    overview: "The builder is where you assemble a flow by hand: these requests, in this order, with the token step two captured carried into step three, and rules that decide what happens next based on what came back.",
    sections: [
      {
        title: "Assembling a Flow, and Carrying Values Between Steps",
        icon: "fa-screwdriver-wrench",
        content: [
          "There are two ways to start: empty, or by copying a detected flow in as editable steps. The second is the one that actually gets used, because retyping a login by hand when the crawl already recorded it is work for nothing.",
          "The point of a built flow is the wiring. A step can capture a value out of its response, from the body, a header, or a cookie, and a later step references it with a placeholder. That is how a CSRF token minted in step one reaches the POST in step two, and how an identifier the application invented in step two reaches the request in step four. Without it a hand-built flow is just four requests that happen to be next to each other.",
          "A placeholder whose value never arrives is the classic silent failure: step two's capture does not fire, step three sends the literal placeholder text, and the target answers with something plausible. So an unresolved reference is reported on the step, naming the step that was supposed to produce the value, while you are still typing, and the send is refused rather than made. Steps seeded from captures that change state arrive disarmed for a related reason: a captured body carries a real identifier, and replaying one can mean the application texts or emails a real person."
        ],
        keyPoints: [
          "Seed from a detected flow rather than retyping a login",
          "A step captures a value; a later step references it by placeholder",
          "An unresolved placeholder is named before the run, not discovered after it",
          "Seeded state-changing steps start disarmed until a human arms them"
        ]
      },
      {
        title: "Conditionals: When the Response Decides What Happens Next",
        icon: "fa-code-branch",
        content: [
          "A straight line stops being enough as soon as the target can answer in more than one way. A login returning 200 with a session goes one way; the same login returning 302 to a device-verification page has to go another. A condition on a step is a rule of the form: look at the response, and if this is true, do that.",
          "The vocabulary is deliberately small, because a dropdown cannot produce a syntax error at two in the morning. A field (the status, one named header, the body, the body size, the response time), an operator, and an action: continue, go to a named step, retry this step, stop the run, or fail the run. Rules are tried top to bottom and the first match wins, so ordering is meaning. A rule for status at least 400 placed above a rule for status exactly 403 means the second can never fire, and the builder says so rather than letting you discover it mid-run.",
          "The last row is the catch-all: what to do when none of the rules above matched. It can only ever be last, and that is enforced rather than suggested, because a catch-all in the middle makes every rule beneath it dead. There is also no test for a header being absent, because an absent header matches nothing at all, not even is-not. Test for the header being present, and put what you wanted for the missing case in the catch-all."
        ],
        keyPoints: [
          "A condition is a field, an operator, and an action, chosen from small lists",
          "Rules are tried top to bottom and the first match wins, so ordering is meaning",
          "The catch-all is always last, and the builder keeps it there",
          "There is no absent test: check for present, and handle the rest in the catch-all"
        ]
      },
      {
        title: "Loop Caps, and Why They Are Not Settings",
        icon: "fa-shield-halved",
        content: [
          "A goto that points backwards closes a loop. That is legitimate, because a bounded retry is a real thing to build, and it is also exactly how you accidentally send a live programme thousands of requests in a minute. A loop against a live target is a denial of service, and denial of service is out of scope on every programme this framework is pointed at.",
          "So the flow's graph is walked while you are authoring it, and a cycle is named the moment the goto that closes it is picked. The caps that would stop a runaway are printed next to the run button rather than discovered by hitting one: a budget of executed steps, a per-step execution cap, a retry cap, and a wall-clock limit. The budget counts executions and not steps, so a four-step flow that goes round five times has executed twenty.",
          "None of them is a checkbox, and there is no control anywhere that turns one off. When a run stops it says why: which cap fired, or that a condition stopped it, or that the flow simply finished. A run that ends with no stated reason is how an operator concludes the target is broken when the fault was in their own flow."
        ],
        keyPoints: [
          "A backwards goto is allowed; an unbounded one is not survivable on a live target",
          "Cycles are named while you author them, not discovered while they run",
          "The caps sit next to the run button and cannot be disabled",
          "Every run states why it stopped, and names the cap when a cap fired"
        ]
      }
    ],
    practicalTips: [
      "Seed from a detected flow and delete what you do not need, rather than building from nothing",
      "Wire the value capture and replay the flow once before you add a single condition",
      "Order rules from most specific to most general, because the first match wins",
      "Give every branching step a catch-all, so an unexpected response has somewhere to go",
      "Bound your retries deliberately instead of relying on the caps to stop you",
      "Read the run trace: it says which condition matched on each execution"
    ],
    furtherReading: [
      {
        title: "RE2 syntax",
        url: "https://github.com/google/re2/wiki/Syntax",
        description: "The regular expression dialect the matches operator accepts"
      },
      {
        title: "PortSwigger - Race conditions",
        url: "https://portswigger.net/web-security/race-conditions",
        description: "A bug class where the order and timing of a sequence is the vulnerability"
      }
    ]
  },

  urlRequestFlowsEngagement: {
    title: "Configure: Engagement Rules Belong to the Programme",
    overview: "Before anything on this card sends a request, this is where you say what it may touch and what every request has to carry. The custom header and the rate limit are per target because programmes differ, and getting them wrong is a rules violation rather than a matter of taste.",
    sections: [
      {
        title: "The Header Is Not a Preference",
        icon: "fa-id-badge",
        content: [
          "Programmes tell you how to identify your traffic, and they do not all say the same thing. One requires a header naming the programme and your handle on every single request, because their security operations centre reads unlabelled probing as an attack and will block you or escalate it. Another wants a tag appended to a real browser User-Agent instead, and caps you at forty-five requests a minute. A third asks for neither.",
          "One global header and one global rate limit, shared by every target, makes switching programmes something you have to remember to do, and forgetting means sending unlabelled traffic to a programme whose brief says the label is mandatory. That is not a mistake you get to explain afterwards. So every field on this screen belongs to this target, and falls back to the global setting only when this target has not overridden it. Which of those two is happening is printed next to the field, on every field, always.",
          "There is a preview of exactly what a request will carry, and it says plainly when no programme header is set. A half-configured header is a blocked save rather than a warning, because a value with no name is not a header at all, and a name that is not a legal token does not produce a header either; it produces a malformed request that some servers answer with a 400."
        ],
        keyPoints: [
          "Identification requirements differ per programme and are mandatory where stated",
          "The header, the User-Agent and the rate limit are per target, not global",
          "Every field says whether it is this target's value or the global fallback",
          "A name with no value, or an illegal header name, is refused rather than sent"
        ]
      },
      {
        title: "Scoping, and the Difference Between a Deselection and an Exclusion",
        icon: "fa-lock",
        content: [
          "The endpoint list here is scoping. Everything is selected by default, because the corpus is the corpus, and unticking an endpoint says not this one, not today. It is a checkbox and it behaves like one; tick it back on whenever you want.",
          "An exclusion is a completely different statement. It is a safety rule with a written reason, made in Detect Flows, enforced by the server on the endpoint and again on every redirect destination. An endpoint is on that list because requesting it texts a one-time code to a real customer, or cancels a real order. So excluded rows have no checkbox at all: there is a padlock, the rule that matched, and the reason somebody wrote. Removing one is done where it was written, deliberately, with a confirmation, so that nobody skimming this screen can text a stranger with a stray click.",
          "Three things are true whatever you configure here: a host outside this target's scope is never contacted, the rate limit applies, and conditional flows are capped. They are listed on the screen as fixed edges rather than as cautions, so you know where the boundaries are instead of hunting for a setting that does not exist."
        ],
        keyPoints: [
          "A deselection is scoping and reversible; an exclusion is a safety rule with a reason",
          "Excluded rows have no checkbox at all, deliberately",
          "Exclusions are enforced on redirect destinations as well as on the endpoint itself",
          "Scope, the rate limit, and the execution caps hold whatever else is configured"
        ]
      }
    ],
    practicalTips: [
      "Read the programme brief and set this screen before you run anything, not after the first run",
      "Set the header the moment you add the target, while the brief is still in front of you",
      "Use the preview to confirm what a request will actually carry rather than assuming",
      "Cap the rate at whatever the brief says, not at whatever the target survives",
      "Write an exclusion, with the reason, for anything that emails, texts, charges or cancels",
      "Re-check this screen after switching programmes: a header naming the wrong one is worse than none"
    ],
    furtherReading: [
      {
        title: "RFC 9110 - Field Names",
        url: "https://www.rfc-editor.org/rfc/rfc9110#name-field-names",
        description: "What is and is not a legal header name"
      },
      {
        title: "MDN - User-Agent",
        url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/User-Agent",
        description: "The header most programmes ask you to tag your traffic with"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Authentication
  // ---------------------------------------------------------------------------------------------
  urlAuthenticationMethodology: {
    title: "Authentication: Why Testing Logged In Changes Everything",
    overview: "Almost every interesting feature in an application sits behind a login. If your tools test as an anonymous visitor, they test the login wall and nothing else. This section is where you give the framework a real session so the rest of the workflow runs as a user who is allowed in.",
    sections: [
      {
        title: "The Attack Surface Behind the Login",
        icon: "fa-door-open",
        content: [
          "An anonymous crawl of a typical application reaches the marketing pages, the login form, the password reset flow, and very little else. The account settings, the order history, the file uploads, the admin panel, and the API that drives all of them are invisible. That invisible portion is usually the large majority of the application, and it is where the high-value bugs live.",
          "Authenticated testing is therefore not an optimisation, it is the difference between testing a small fraction of the target and testing the target. Broken access control, IDOR, business-logic flaws, and privilege escalation are all defined in terms of an authenticated identity: you cannot find a bug about what user A may do to user B's data if you are not logged in as either of them.",
          "This is also why programs that provide test credentials expect you to use them. A report that only covers the unauthenticated surface is a report about the smallest and most heavily reviewed part of the application."
        ],
        keyPoints: [
          "Most of an application's functionality is only reachable with a session",
          "Access-control bug classes are defined in terms of an authenticated identity",
          "An unauthenticated scan of an authenticated app mostly tests the login page",
          "Two accounts are better than one: many bugs are only visible as A acting on B"
        ]
      },
      {
        title: "The Failure Mode That Looks Like Good News",
        icon: "fa-triangle-exclamation",
        content: [
          "When a session expires mid-scan, most security tools do not stop. They keep sending payloads, keep receiving the login page or a 302 back to it, keep seeing no evidence of injection, and keep recording every vector as clean. The scan finishes early, reports zero findings, and looks like a target with no bugs.",
          "This is the single most expensive failure in automated web testing, because a false clean is invisible. A crash is loud and gets fixed; a silent clean gets believed. During this project a scanner reported 53 attack vectors as free of cross-site scripting against an application whose own documentation lists four separate XSS vulnerabilities, purely because its session marker stopped matching partway through.",
          "The defences are the counts on this card and the session checks the framework runs during a scan. Active tokens is the number that matters: a long list of session tokens with zero active is exactly the state that produces a page of confident, worthless clean results."
        ],
        keyPoints: [
          "Tools rarely detect that they have been logged out; they just find nothing",
          "A scan that finishes suspiciously fast with zero findings is a session problem until proven otherwise",
          "Watch the Active count, not the total token count",
          "Re-check the session before you believe a clean result, not after you report it"
        ]
      }
    ],
    practicalTips: [
      "Capture the session before you launch any scan, not after the first one comes back empty",
      "Get two accounts at the same privilege level if the program allows it, so you can test A against B",
      "Note which cookie or header actually carries the identity; there are usually several and only one matters",
      "If a scan finishes far faster than expected, check the session before you read the results",
      "Log in again by hand after a long scan and confirm you are still authenticated",
      "Never use a real customer's credentials, only accounts the program has given you or that you created for testing"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Authentication Testing",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/",
        description: "The full catalogue of authentication test cases"
      },
      {
        title: "OWASP WSTG - Session Management Testing",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/",
        description: "How sessions are issued, carried, and broken"
      }
    ]
  },

  urlAuthenticationFlows: {
    title: "Auth Flows: Recording and Replaying a Login",
    overview: "An auth flow is the recorded sequence of requests that turns credentials into a session. Storing the flow rather than just the resulting token is what lets the framework mint a fresh session when the old one dies, instead of quietly testing a login wall for the next three hours.",
    sections: [
      {
        title: "A Token Is a Snapshot, a Flow Is a Recipe",
        icon: "fa-record-vinyl",
        content: [
          "If you paste a session cookie into a scanner, you have given it a snapshot that is already ageing. Sessions expire on a timer, on idle, on a new login elsewhere, on a deploy, and sometimes for no visible reason at all. When that snapshot goes stale the scanner has no way to get another one.",
          "An auth flow is the recipe instead: the exact requests, in order, that produce a session. Typically that is a GET of the login page to pick up a CSRF token and a session cookie, then a POST of the credentials plus that token, then whatever redirect the application uses to hand you the authenticated session. Record it once and the framework can run it again whenever it needs to.",
          "Because each stored token is tied to the flow that produced it, refreshing is a single action rather than a manual re-login and a round of copy and paste into every tool's configuration."
        ],
        keyPoints: [
          "Tokens expire; the flow that makes them does not",
          "A flow is usually three requests: fetch the form, post credentials, follow the redirect",
          "CSRF tokens and initial cookies must be carried between the steps of the flow",
          "Tying a token to its flow is what makes automatic refresh possible"
        ]
      },
      {
        title: "Recorded Versus Manual Flows",
        icon: "fa-keyboard",
        content: [
          "Recording with the browser extension is the accurate option: you log in normally and the extension captures exactly what the browser sent, including headers you would never have thought to copy, the precise body encoding, and any intermediate redirect. For anything involving JavaScript, multi-step logins, or single sign-on, recording is the only realistic approach.",
          "Writing the flow by hand is the precise option: you spell out each request yourself. It is the right choice for a simple form login or an API that takes a JSON body and returns a bearer token, and it is far easier to read and adjust later.",
          "Whichever you use, replay the flow before you rely on it. A flow that has never been replayed is an assumption. Replaying it once tells you the steps are complete, the extraction of the token works, and the resulting session is genuinely authenticated."
        ],
        keyPoints: [
          "Record when the login involves JavaScript, SSO, or several steps",
          "Write it by hand when it is a simple form post or a token API",
          "Replay every flow at least once before trusting it in a scan",
          "Check the replay lands on authenticated content, not the login page again"
        ]
      }
    ],
    practicalTips: [
      "Replay a new flow immediately, and confirm the response is authenticated content rather than the form",
      "Watch for a CSRF token that must be read from step one and posted in step two; that is the most common reason a hand-written flow fails",
      "Some applications rotate the session cookie on login, so capture the cookie from the response, not the request",
      "If the application uses SSO, record rather than hand-write; the redirect chain is longer than it looks",
      "Keep one flow per account so you can test one user acting on another user's data",
      "Re-record the flow after the target deploys; login forms change more often than you would expect"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Testing for Bypassing Authentication Schema",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema",
        description: "What the login flow itself can get wrong"
      },
      {
        title: "PortSwigger - Authentication Vulnerabilities",
        url: "https://portswigger.net/web-security/authentication",
        description: "Free labs covering the common authentication flaws"
      }
    ]
  },

  urlAuthenticationSessions: {
    title: "Session Tokens: Keeping the Scan Logged In",
    overview: "Session tokens are what every other tool in this workflow actually sends. This lesson covers what a token really is, why a valid token can still fail, and how to tell a genuine clean result from a scan that spent an hour talking to a login page.",
    sections: [
      {
        title: "What Carries Your Identity",
        icon: "fa-id-card",
        content: [
          "Identity travels in one of a few places: a session cookie, an Authorization header carrying a bearer token or JWT, a custom header the application invented, or occasionally a query parameter. Knowing which one actually decides who you are matters, because a response usually sets several cookies and only one of them is the session.",
          "The quickest way to find out is to remove one at a time and re-send an authenticated request. The one whose removal logs you out is the session. The rest are analytics, preferences, load-balancer routing, or CSRF material.",
          "That test also tells you something useful about the application. If removing the CSRF cookie does not break a state-changing request, you have found a CSRF issue before you have run a single tool."
        ],
        keyPoints: [
          "Several cookies come back on login; usually one is the session",
          "Remove one at a time and re-send to find which is which",
          "Bearer tokens and JWTs live in the Authorization header, not the cookie jar",
          "A JWT is readable by anyone: decode it and see what the server is trusting"
        ]
      },
      {
        title: "Why a Valid Token Can Still Fail",
        icon: "fa-network-wired",
        content: [
          "A token that works perfectly in your browser can be rejected by the target when a tool sends it, and the reason is often infrastructure rather than the application. Load-balanced deployments frequently keep session state on a specific backend and use a companion routing cookie to send you back to it. Send the session cookie without the routing cookie and you land on a different backend that has never heard of your session.",
          "The symptom is confusing: the token is genuinely valid, the login is genuinely current, and the target still answers as if you were anonymous. During this project exactly that produced a session that read as not honoured while the same credentials worked fine in a browser, because the AWS load balancer's companion cookie was not being sent alongside the session.",
          "Other causes worth knowing: the application binds the session to the User-Agent or IP that created it, the token is single-use and rotates on each request, or a WAF is stripping the header before the application ever sees it."
        ],
        keyPoints: [
          "Send every cookie the browser sends, not just the one you think is the session",
          "Load balancers use companion routing cookies that are easy to drop and fatal to omit",
          "Some applications bind a session to the User-Agent, so changing it logs you out",
          "A valid token plus an anonymous response is an infrastructure clue, not a dead end"
        ]
      }
    ],
    practicalTips: [
      "Check the Active count before every scan; a full token list with zero active is the danger state",
      "Send the whole cookie jar rather than hand-picking the one cookie you believe matters",
      "If a tool lets you set a session-check pattern, point it at a string that only appears when logged in",
      "Prefer a string like a username or a logout link as the marker, not something on every page",
      "Refresh the session between long scans rather than hoping one token survives all of them",
      "When a scan returns zero findings, re-run the session check before you write anything down"
    ],
    furtherReading: [
      {
        title: "OWASP Session Management Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        description: "How sessions should be issued, stored, and expired"
      },
      {
        title: "PortSwigger - JWT Attacks",
        url: "https://portswigger.net/web-security/jwt",
        description: "What to look for once you can read the token you are holding"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Authorization
  // ---------------------------------------------------------------------------------------------
  urlAuthorizationMethodology: {
    title: "Authorization: Writing Down What Should Be Refused",
    overview: "Authentication asks who you are; authorization asks what you may do. This section is where you model the application's own rules, because a broken access control is only detectable if you know what the correct answer was supposed to be.",
    sections: [
      {
        title: "You Cannot Detect a Violation Without a Rule",
        icon: "fa-scale-balanced",
        content: [
          "Every other bug class has an observable signature. Injection produces an error, a delay, or a callback. Cross-site scripting produces script execution. Broken access control produces a perfectly normal HTTP 200 with someone else's data in it, and there is nothing about that response that looks wrong to a scanner.",
          "That is why access control is consistently at the top of the OWASP Top Ten and consistently missing from automated scan output. The tool has no idea that order 0254791 belongs to another customer. You do, but only if you wrote it down first.",
          "Modelling the rules turns an invisible bug class into a checklist. Once you have recorded that a standard user must not read another user's order, testing it is mechanical: log in as one user, request the other user's order, and compare the answer with the rule you recorded."
        ],
        keyPoints: [
          "A successful access-control attack looks like a completely normal response",
          "Scanners cannot infer intent, so they cannot find this class on their own",
          "Recording the intended rule is what converts a 200 into a finding",
          "This is the highest-value bug class you can only find by preparing first"
        ]
      },
      {
        title: "The Three Questions to Answer Per Action",
        icon: "fa-list-check",
        content: [
          "For each meaningful action in the application, answer three things. Who is allowed to do it? Who is explicitly forbidden from doing it? And how does the server work out which of those you are?",
          "The third question is the one people skip, and it is where the bugs are. If the server decides you are an administrator by reading a role field from a JWT that it never verifies, or from a hidden form field, or from a cookie you can edit, then the first two answers do not matter because the caller controls the input to the decision.",
          "Work through the roles you can actually obtain, then the roles you cannot. Anonymous, standard user, and a second standard user are usually available to you and cover most of the interesting boundaries. Administrator normally is not, but you should still record what it may do, because proving a standard user can reach an administrator-only action is exactly the finding you want."
        ],
        keyPoints: [
          "Allowed, forbidden, and how the server tells the difference",
          "How the server decides is where the vulnerability usually is",
          "Two accounts at the same level test the horizontal boundary",
          "Record administrator rules even without an administrator account; that is the target"
        ]
      }
    ],
    practicalTips: [
      "Model the rules before you scan; afterwards you will rationalise whatever the tool reported",
      "Focus on actions with real consequences: money, personal data, permissions, deletion",
      "Record the forbidden cells especially, since violating one is automatically a finding",
      "Test every boundary in both directions, including whether an admin action leaks to a normal user",
      "Do not stop at read access; check create, update, and delete separately, as they are often guarded differently",
      "Note which endpoints only hide the control in the interface, since the API behind it is often unguarded"
    ],
    furtherReading: [
      {
        title: "OWASP Top 10 - Broken Access Control",
        url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        description: "Why this class sits at number one"
      },
      {
        title: "OWASP Authorization Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        description: "How authorization is supposed to be built, which tells you how it breaks"
      }
    ]
  },

  urlAuthorizationIdentity: {
    title: "Client Identity Patterns and Attacker-Controlled IDs",
    overview: "Before testing access control you need to know how the server works out who is asking, and crucially how much of that the caller supplies. An identifier the caller controls is where IDOR testing starts, and the Attacker-Controlled IDs count on this card is a direct measure of that surface.",
    sections: [
      {
        title: "Where the Server Gets Your Identity",
        icon: "fa-fingerprint",
        content: [
          "There are broadly three sources. The session is the safe one: the server looks up who you are from a token it issued and you cannot forge. A claim inside a token is riskier: a JWT carrying a role or a user id is fine if the signature is verified and disastrous if it is not. A parameter is the dangerous one: the request itself names the user, account, or object being acted on.",
          "Parameter-based identity is not automatically a bug. Applications legitimately pass object ids around all the time. It becomes a bug when the server uses that id to fetch the object and never checks that the object belongs to the caller. Since the id is right there in the URL or body, testing it is trivial.",
          "This is why the Attacker-Controlled IDs count is called out separately on the card. It is the number of places where the caller supplies the identifier the server acts on, which is a direct measure of your insecure direct object reference surface."
        ],
        keyPoints: [
          "Session lookup, token claim, and request parameter are the three sources",
          "Parameter-supplied identity is where IDOR lives",
          "An unverified JWT claim is a parameter wearing a disguise",
          "Count the places the caller names the object; that is your worklist"
        ]
      },
      {
        title: "Identifiers That Invite Enumeration",
        icon: "fa-hashtag",
        content: [
          "The shape of an identifier tells you how to attack it. Sequential integers are the easiest: if your order is 1043 then 1042 belongs to somebody else, and the whole dataset is a for loop away. Short numeric ids, incrementing database keys, and predictable reference numbers all behave this way.",
          "Random UUIDs are much harder to guess, but guessing is only one route. Ids leak constantly through search results, exported files, notification emails, autocomplete endpoints, error messages, shared links, and API responses that return more fields than the interface displays. An unguessable id that the application hands you is just as usable as a guessable one.",
          "During this project an unauthenticated request to an order-details endpoint with a plausible order number returned a real customer's personal data. The id was not secret, the endpoint simply never asked whether the caller was entitled to that order."
        ],
        keyPoints: [
          "Sequential ids can be enumerated directly",
          "Random ids still leak through search, exports, emails, and verbose API responses",
          "Unguessable is not the same as authorized",
          "Try removing authentication entirely; some object endpoints never check at all"
        ]
      }
    ],
    practicalTips: [
      "Collect real object ids from a second account rather than guessing, so your test is unambiguous",
      "Test the API directly, not the interface; the button may be hidden while the endpoint stays open",
      "Try the same object id with no session at all, which is the strongest version of the finding",
      "Decode any JWT you are given and check whether a role or id claim is being trusted",
      "Watch for ids in responses the interface never displays; those are leaks in their own right",
      "Keep evidence from both accounts, since a report has to show whose data you reached"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Insecure Direct Object References",
        url: "https://portswigger.net/web-security/access-control/idor",
        description: "The canonical explanation with labs"
      },
      {
        title: "OWASP API Security Top 10 - Broken Object Level Authorization",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/",
        description: "The same bug as it appears in APIs, where it is most common"
      }
    ]
  },

  urlAuthorizationControls: {
    title: "Policy, Role, and Discretionary Access Controls",
    overview: "Applications enforce access in three broadly different ways, and each fails differently. Recording which model an action uses tells you which attack to try, and the Forbidden Actions count tells you which cells produce a finding the moment they are violated.",
    sections: [
      {
        title: "Three Models, Three Failure Modes",
        icon: "fa-sitemap",
        content: [
          "Role-based access control assigns permissions to named roles and users to roles: administrators may delete, editors may publish, viewers may read. It fails when the role is decided from something the caller controls, when a route is forgotten in the role table, or when the interface hides an action while the endpoint behind it stays open.",
          "Policy-based access control evaluates rules against attributes at request time: this user may approve a refund under five hundred dollars during business hours from a corporate network. It fails at the edges of those attributes, so you attack the boundary values, the missing attribute, and the case the policy author did not consider.",
          "Discretionary access control lets the owner of an object grant access to others, which is how sharing features work. It fails when a share link never expires, when revoking access leaves an old grant behind, when the share can be escalated from read to write, or when a share can be created for an object you do not own."
        ],
        keyPoints: [
          "Role-based fails at forgotten routes and caller-controlled role values",
          "Policy-based fails at boundary conditions and missing attributes",
          "Discretionary fails at revocation, expiry, and escalation of a grant",
          "Most real applications mix all three, so identify the model per action"
        ]
      },
      {
        title: "Forbidden Cells Are the Finding",
        icon: "fa-ban",
        content: [
          "When you fill in the access-control grids, some cells say allowed and some say forbidden. The forbidden cells are worth more than the rest put together, because there is no ambiguity about what a successful request means. If the model says a standard user must not delete another user's account and a standard user deletes another user's account, that is a finding and there is nothing to argue about.",
          "Allowed cells still matter, but as a control arm rather than as a target. They tell you what a normal successful response looks like, which is what you compare against when you are deciding whether a suspicious 200 really contained privileged content.",
          "Be specific when recording a forbidden action. Naming the action, the role, and the object gives you a test you can run and a sentence you can put in a report. A vague rule like users should not access admin things produces neither."
        ],
        keyPoints: [
          "A violated forbidden cell needs no further interpretation",
          "Allowed cells give you the baseline a real bypass must beat",
          "Record role, action, and object together so the rule is testable",
          "Vague rules cannot be tested and cannot be reported"
        ]
      }
    ],
    practicalTips: [
      "Start from the most destructive actions: delete, transfer, change email, change permissions",
      "Check whether the server enforces the rule or only the interface hides the button",
      "For role-based systems, look for routes that exist but were left out of the permission table",
      "For policy-based systems, test the boundary exactly: the limit, one over, and one under",
      "For sharing features, revoke a share and immediately re-use the old link",
      "Re-test after any change of state; permissions often fail to re-evaluate on an existing session"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Access Control Vulnerabilities",
        url: "https://portswigger.net/web-security/access-control",
        description: "Vertical, horizontal, and context-dependent access control with labs"
      },
      {
        title: "OWASP API Security Top 10 - Broken Function Level Authorization",
        url: "https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/",
        description: "Role-based failures at the endpoint level"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Consolidate Attack Vectors
  // ---------------------------------------------------------------------------------------------
  urlAttackVectorsMethodology: {
    title: "What an Attack Vector Is and Why It Is the Unit of Testing",
    overview: "Everything upstream produced URLs, endpoints, and parameter names. This step folds all of it into one list of attack vectors, where a vector is a single testable thing: one request carrying user-controlled input, with one place a payload goes. Every scanner in the sections below runs against this list.",
    sections: [
      {
        title: "From a List of URLs to a List of Tests",
        icon: "fa-crosshairs",
        content: [
          "A URL is not a test. The same path can accept different verbs, different parameter combinations, and input in several different places, and each of those is a separate thing to check with separate behaviour behind it. Conversely the same URL captured forty times during a crawl with forty different search terms is one test, not forty.",
          "An attack vector resolves that. Its identity is the verb, the host, the path, the set of parameters in play, and the single insertion point being targeted. Two captures that agree on all of those are the same vector no matter how different the values looked, and two captures that differ on any of them are different vectors even if the URL looks identical.",
          "That definition is what makes the numbers on this card mean something. Unique Attack Vectors is the real size of the testable surface, not the size of your crawl log."
        ],
        keyPoints: [
          "Identity is verb plus host plus path plus parameter set plus insertion point",
          "Different values for the same parameter are the same vector",
          "The same path with a different parameter set is a different vector",
          "The count here is the true size of the surface, after deduplication"
        ]
      },
      {
        title: "Why the Parameter Set Is Part of the Identity",
        icon: "fa-code-branch",
        content: [
          "It is tempting to key a vector on the path and a single parameter name, but applications routinely branch on which parameters are present. A search endpoint called with a term alone may run one query; called with a term and a category filter it may run a completely different one, joining another table and reaching code the first path never touches.",
          "Treating those as the same vector means testing one and assuming the other. Treating them as different vectors costs more requests and finds bugs that only exist on the second code path. That is why the parameter set, not just the parameter under test, is part of the key.",
          "The same logic applies to the verb. A GET and a POST to the same path frequently run different handlers with different validation, and an application that carefully sanitises its GET parameters may do nothing at all for the body of a POST."
        ],
        keyPoints: [
          "Applications branch on which parameters are present, not just their values",
          "Two parameter sets on one path can reach entirely different code",
          "GET and POST to the same path are usually different handlers",
          "Over-merging vectors is a silent loss of coverage"
        ]
      }
    ],
    practicalTips: [
      "Consolidate after every discovery step, so later scans include what you just found",
      "Read the vector list before scanning; it is the last chance to notice a whole feature is missing",
      "Add vectors manually when you know an input exists that no tool captured, such as a form you never submitted",
      "Sort by parameter name to spot the interesting ones quickly: url, redirect, file, id, template, cmd",
      "If the count looks small for the size of the application, the crawl is incomplete, not the app simple",
      "Notes on a vector survive into results, so record why one looked interesting while you still remember"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Identify Application Entry Points",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/06-Identify_Application_Entry_Points",
        description: "The systematic way to enumerate every input an application accepts"
      }
    ]
  },

  urlAttackVectorsInsertionPoints: {
    title: "The Five Insertion Points",
    overview: "A payload can go in five places: the query string, the request body, a header, a cookie, or the path itself. Each is a separate vector because each reaches different code, and the ones nobody tests are the ones nobody sanitised.",
    sections: [
      {
        title: "Query, Body, Header, Cookie, Path",
        icon: "fa-location-crosshairs",
        content: [
          "Query and body are the obvious two and get the vast majority of attention, both from testers and from the developers who wrote the validation. Header, cookie, and path are the ones that get skipped, which is precisely why they are worth testing: input that arrives somewhere unexpected is input that was probably never filtered.",
          "Headers are a rich surface. X-Forwarded-For and X-Forwarded-Host end up in logs, in generated URLs, and in cache keys. Referer and User-Agent get written to analytics tables, frequently by concatenating them into a query. Custom application headers are often parsed with far less care than a form field.",
          "Cookies are read on essentially every request and are trusted more than they should be, because developers reason that the server set them. The path is the fifth, and it matters for anything that maps a URL segment onto a filesystem path, a template name, or a database lookup."
        ],
        keyPoints: [
          "Query and body are tested constantly and hardened accordingly",
          "Headers reach logs, generated URLs, and cache keys",
          "Cookies are trusted because the server set them, which is not a guarantee",
          "Path segments matter wherever a URL maps onto a file, template, or record"
        ]
      },
      {
        title: "Coverage Gaps Look Exactly Like Clean Results",
        icon: "fa-magnifying-glass-chart",
        content: [
          "If your vector list contains no header vectors and no path vectors, then every scan you run will report nothing wrong with headers or paths. Not because they are safe, but because nothing was ever sent there. On the ginandjuice.shop target used to develop this workflow, the consolidated list contained zero of each, and the resulting reports were technically accurate and completely misleading.",
          "This happens because insertion points are derived from what was captured. A crawl records the headers the browser chose to send, which is a small and unremarkable set, and paths only become vectors when something in the discovery phase suggests the segment is dynamic.",
          "The fix is to add them deliberately. Pick the endpoints that plausibly consume a header, add the vector by hand, and scan it. A short list of hand-picked header vectors on the right endpoints beats a large list of query vectors on pages that only render static content."
        ],
        keyPoints: [
          "Zero vectors for an insertion point means zero coverage, not zero risk",
          "Crawls rarely produce header or path vectors on their own",
          "Check the spread of insertion points before you start scanning",
          "Add the missing ones by hand on endpoints where they make sense"
        ]
      }
    ],
    practicalTips: [
      "Count vectors per insertion point before scanning and treat any zero as a coverage gap",
      "Add X-Forwarded-For, X-Forwarded-Host, Referer, and User-Agent vectors on endpoints that log or generate URLs",
      "Cookie vectors are worth adding wherever a cookie clearly holds application data rather than a session",
      "Path vectors matter most on routes that end in an identifier or a name",
      "Not every tool supports every insertion point; check before assuming a section covered one",
      "A tool that cannot reach an insertion point should be recorded as untested there, not as clean"
    ],
    furtherReading: [
      {
        title: "PortSwigger - HTTP Host Header Attacks",
        url: "https://portswigger.net/web-security/host-header",
        description: "What goes wrong when a header is trusted"
      },
      {
        title: "OWASP WSTG - Testing for HTTP Parameter Pollution",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/04-Testing_for_HTTP_Parameter_Pollution",
        description: "Where the same parameter arrives in more than one place"
      }
    ]
  },

  urlAttackVectorsSources: {
    title: "Where Vectors Come From and What Gets Lost",
    overview: "Four sources feed this list: the manual crawl, the discovered endpoints, the hidden-parameter tools, and the fuzzer. Each contributes something the others cannot, and each loses something in the process. Knowing which is which tells you where your blind spots are.",
    sections: [
      {
        title: "The Four Sources",
        icon: "fa-diagram-project",
        content: [
          "The manual crawl is the highest-quality source. It contributes real requests, with real headers and real bodies, captured from an authenticated browser doing things a crawler cannot do. It is also the only source that produces full request bytes, which is what later reproduction steps are built from.",
          "Discovered endpoints come from crawling and archive mining and contribute breadth: pages nobody linked to any more, old API versions, and routes the application no longer advertises. They usually arrive as a URL and nothing else, so their parameter sets are thin.",
          "Hidden-parameter tools contribute parameters that exist but are never shown, which is often the most valuable single addition to the list. The fuzzer contributes paths and names that nothing links to at all. Together they cover the two kinds of hidden thing: an input nobody mentions and a resource nobody links."
        ],
        keyPoints: [
          "The manual crawl gives depth, authentication, and full request bytes",
          "Endpoint discovery gives breadth and history",
          "Parameter enumeration finds inputs the application never advertises",
          "Fuzzing finds resources nothing links to"
        ]
      },
      {
        title: "What Consolidation Cannot Recover",
        icon: "fa-circle-exclamation",
        content: [
          "Consolidation deduplicates and merges, but it cannot invent what was never captured. A form you did not submit during the manual crawl produces no body vector, and no amount of consolidating will conjure one. On the reference target a newsletter subscribe form was never submitted during the crawl, so it never became a vector, so every scanner reported clean on it, and it turned out to hold a real cross-site scripting vulnerability.",
          "The lesson is that the vector list inherits the gaps of everything upstream. Reading it critically is the cheapest quality check in the workflow: pull up the application, list its features from memory, and confirm each one appears. Anything missing is a hole you can still fix by crawling that feature or adding the vector by hand.",
          "This is also the moment to notice imbalance. A hundred query vectors and two body vectors on an application full of forms means the crawl mostly clicked links rather than submitting them."
        ],
        keyPoints: [
          "A feature you never exercised produces no vector and always reports clean",
          "The vector list inherits every gap from every upstream step",
          "Compare the list against the features you know exist, from memory",
          "Imbalance between insertion points usually reveals how the crawl was done"
        ]
      }
    ],
    practicalTips: [
      "Go back and submit every form you skipped, then re-consolidate before scanning",
      "Sanity-check the list against the application's own navigation, feature by feature",
      "Authenticated crawl data is the most valuable input here, so capture it first",
      "Re-consolidate after each discovery tool rather than once at the end",
      "Add high-value vectors manually when you know the input exists but nothing captured it",
      "Treat a suspiciously small vector count as evidence about your crawl, not about the target"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Map Execution Paths Through Application",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/07-Map_Execution_Paths_Through_Application",
        description: "Making sure your map covers the application rather than the parts you happened to visit"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Threat Model Results
  // ---------------------------------------------------------------------------------------------
  urlThreatModelResultsMethodology: {
    title: "Reading the Threat Model by Category",
    overview: "The six STRIDE categories on this page are not a report, they are a worklist. Each threat you recorded names a place to test and a specific thing to try, and this is how to work through them without drowning.",
    sections: [
      {
        title: "A Threat Is a Hypothesis",
        icon: "fa-flask",
        content: [
          "Nothing on this page is a finding yet. A threat is a statement that something might be possible: that this endpoint might accept a forged identity, that this parameter might let you modify data you do not own, that this action might leave no audit trail. Each one is a hypothesis with a test attached.",
          "That framing matters because it tells you what to do next. You do not report a threat, you test it. The result of the test is either a finding with evidence, or a threat you can close as not present, and both outcomes are progress.",
          "It also means the model is only as good as its specificity. A threat that says the API might have authorization problems cannot be tested. A threat that says a standard user might be able to read another user's order by changing the order identifier can be tested in one request, and that is the level of detail worth writing."
        ],
        keyPoints: [
          "A threat is a hypothesis with a test, not a finding",
          "Testing it yields either evidence or a closed threat",
          "Both outcomes are progress worth recording",
          "Specific threats are testable; vague ones are not"
        ]
      },
      {
        title: "What Each Category Is Good For",
        icon: "fa-layer-group",
        content: [
          "Spoofing and elevation of privilege are where the highest-value findings usually are, because they cover authentication and authorization, and those are the classes automated tools cannot find on their own. Work these first.",
          "Tampering and information disclosure map most directly onto what the tool sections above already scanned for, so use them to check coverage: a tampering threat against a parameter no scanner tested is a gap you can close immediately.",
          "Repudiation and denial of service are the two most often skipped. Repudiation is genuinely hard to test from outside, since you cannot see the logs, but it is worth recording where an action leaves no visible trace. Denial of service is usually out of scope, and where it is, the right move is to record the threat and not test it."
        ],
        keyPoints: [
          "Spoofing and elevation of privilege hold the highest-value findings",
          "Tampering and information disclosure double as a coverage check on the scans",
          "Repudiation is hard to test externally but worth recording",
          "Denial of service is usually out of scope; record it and stop"
        ]
      }
    ],
    practicalTips: [
      "Work spoofing and elevation of privilege first; the tools cannot help you there",
      "Use tampering and disclosure threats to find vectors the scans never covered",
      "Close threats explicitly when you test them and find nothing",
      "Rewrite any threat you cannot turn into a single concrete test",
      "Do not test denial of service unless the program says you may",
      "Revisit the model after scanning; results usually suggest threats you did not think of"
    ],
    furtherReading: [
      {
        title: "Microsoft - The STRIDE Threat Model",
        url: "https://learn.microsoft.com/en-us/previous-versions/commerce-server/ee823878(v=cs.20)",
        description: "The original framing of the six categories"
      },
      {
        title: "OWASP Threat Modeling",
        url: "https://owasp.org/www-community/Threat_Modeling",
        description: "Threat modelling as a practice rather than a document"
      }
    ]
  },

  urlThreatModelResultsAttacks: {
    title: "Using the Possible Attacks Reference",
    overview: "Each category has a Possible Attacks list: the concrete attack techniques that fall under that letter of STRIDE. It exists to turn an abstract category into specific things to try against the specific endpoints you have recorded.",
    sections: [
      {
        title: "From a Category to a Technique",
        icon: "fa-list-check",
        content: [
          "Knowing that an endpoint has a spoofing threat does not tell you what to send. The attack list closes that gap by naming the techniques that fall under the category, so instead of thinking about spoofing in the abstract you are working through session fixation, token forgery, weak credential recovery, and the rest.",
          "This is most useful when you are new to a category, and it stays useful as a completeness check. Working down a list of techniques and asking whether each applies to this endpoint catches the ones you would have skipped because they did not occur to you.",
          "It is also where the connection to the tool sections becomes obvious. Many of the techniques listed under tampering and information disclosure are exactly what the scanners above automate, which tells you which threats can be checked with a scan and which need you."
        ],
        keyPoints: [
          "The list turns a category into named techniques you can actually send",
          "Working the list is a completeness check against your own blind spots",
          "Some techniques map onto scans; others need manual testing",
          "The mapping tells you where your time is best spent"
        ]
      },
      {
        title: "Applicability Before Effort",
        icon: "fa-filter",
        content: [
          "Not every technique applies to every application. An attack against a token format the target does not use is not worth an hour, and a list is a prompt rather than a checklist to complete exhaustively. Filter by what you know about the application from the manual crawl and the mechanisms you recorded.",
          "The fastest filter is the mechanism. If you recorded that the application uses session cookies rather than bearer tokens, the token-specific techniques drop away immediately. If you recorded that it has a file upload, the upload techniques become relevant even though no scan flagged anything.",
          "Where a technique clearly applies but you cannot test it from where you are, record that. A threat marked as applicable but untestable externally is more useful than one silently skipped, because it tells the program where to look with the access you do not have."
        ],
        keyPoints: [
          "A technique that does not match the application's mechanisms is not worth time",
          "Filter using the mechanisms you recorded during preparation",
          "The presence of a mechanism can make a technique relevant even with no scan hit",
          "Record applicable but untestable threats rather than dropping them"
        ]
      }
    ],
    practicalTips: [
      "Read the attack list before testing a category, not after",
      "Filter by the mechanisms you recorded rather than trying everything",
      "Note which techniques the scans already covered so you do not repeat them",
      "Record techniques you cannot test externally rather than skipping them silently",
      "Add threats as you go; the list will remind you of things the crawl missed",
      "Link each threat to a specific endpoint so it stays testable"
    ],
    furtherReading: [
      {
        title: "OWASP Web Security Testing Guide",
        url: "https://owasp.org/www-project-web-security-testing-guide/",
        description: "A test case for essentially every technique in these lists"
      }
    ]
  },

  urlThreatModelResultsPrioritization: {
    title: "Turning the Model Into a Test Plan and a Report",
    overview: "The model is finished when it stops being a document and becomes an ordered list of things to do. This is how to order it, and how the threats that turned out to be real become a report someone will act on.",
    sections: [
      {
        title: "Ordering by Impact and Reachability",
        icon: "fa-ranking-star",
        content: [
          "Order threats by two things: how bad it would be if true, and how likely you are to be able to demonstrate it. A critical threat you cannot reach from your position is worth less of your time than a high one you can test in five minutes, even though it scores higher on paper.",
          "Reachability is the factor people forget. A threat against an administrative function you have no account for may be untestable directly, but the same threat is often reachable indirectly, through an access-control bypass or an endpoint that was never protected in the first place. That indirect route is usually where the interesting work is.",
          "Anything touching money, personal data, authentication, or permissions goes near the top by default. Everything else has to earn its place above them."
        ],
        keyPoints: [
          "Order by impact if true, then by whether you can demonstrate it",
          "A quick high-severity test beats a slow critical one you cannot reach",
          "Untestable directly often means testable indirectly",
          "Money, personal data, authentication, and permissions come first"
        ]
      },
      {
        title: "From Confirmed Threat to Report",
        icon: "fa-file-signature",
        content: [
          "A confirmed threat already contains most of a good report: the endpoint, the mechanism, the object at risk, the steps, and the impact assessment. What has to be added is the evidence, which means the actual requests and responses that show the thing happening.",
          "The impact wording is where the model pays off most. Because you assessed impact when you wrote the threat, you can describe consequences in terms of the application's own data and users rather than in generic language, and that is what makes a triager treat a report as serious.",
          "Threats that turned out not to be present are worth keeping rather than deleting. They record what you checked, which stops you re-testing the same thing next month and makes it obvious what a follow-up engagement should cover."
        ],
        keyPoints: [
          "A confirmed threat is most of a report already",
          "Evidence is the part that has to be added",
          "Impact described in the application's own terms lands better than generic wording",
          "Keep closed threats; they record your coverage"
        ]
      }
    ],
    practicalTips: [
      "Order the list before you start testing rather than working through it as written",
      "Re-order after each session, since findings change what looks promising",
      "Attach evidence to a threat as soon as you confirm it, while the detail is fresh",
      "Describe impact using the application's own data and users",
      "Keep threats you disproved, with a note on how you checked",
      "Feed anything you learn back into the model rather than only into the report"
    ],
    furtherReading: [
      {
        title: "OWASP Risk Rating Methodology",
        url: "https://owasp.org/www-community/OWASP_Risk_Rating_Methodology",
        description: "A defensible way to order threats by likelihood and impact"
      },
      {
        title: "OWASP Threat Modeling Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html",
        description: "Keeping a model useful rather than letting it become a document"
      }
    ]
  }
};
