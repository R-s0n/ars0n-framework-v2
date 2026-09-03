// Lessons for the attack tool sections whose bugs live in how requests are routed, cached, parsed,
// and refused: open redirect and SSRF, web cache poisoning and deception, request smuggling, and
// 403 bypass. Merged into the main lessons export.

export const attackToolsProtocolLessons = {
  // ---------------------------------------------------------------------------------------------
  // Open Redirect and SSRF
  // ---------------------------------------------------------------------------------------------
  urlRedirectSsrfMethodology: {
    title: "Open Redirect and SSRF: Who Makes the Request",
    overview: "These two are grouped because they start from the same input, a parameter holding a URL, and diverge on who follows it. If the browser follows it you have an open redirect. If the server follows it you have server-side request forgery, which is a far more serious problem.",
    sections: [
      {
        title: "The Same Parameter, Two Very Different Bugs",
        icon: "fa-route",
        content: [
          "An open redirect sends the user's browser somewhere you chose. On its own the impact is modest and many programs treat it as low severity or informational. It becomes serious in combination: stealing an OAuth code or token through a redirect_uri, making a phishing link that starts on the real domain, or chaining into a more damaging flow.",
          "SSRF means the server fetches a URL you supplied. That matters because the server sits somewhere you do not: inside the network, able to reach internal services, administrative interfaces, and on cloud platforms the instance metadata endpoint that hands out credentials. The same parameter that produced a low-severity redirect can produce a critical finding if it is the server that follows it.",
          "So the first question for any URL-shaped parameter is which of the two you are looking at. A redirect response tells you the browser was sent; a callback arriving at your collector from the target's infrastructure tells you the server went."
        ],
        keyPoints: [
          "Open redirect moves the browser; SSRF moves the server",
          "Redirect impact comes from chaining, especially with OAuth",
          "SSRF reaches internal services and cloud metadata",
          "Determine which one you have before assessing severity"
        ]
      },
      {
        title: "Where URL Parameters Hide",
        icon: "fa-magnifying-glass",
        content: [
          "The obvious names are url, redirect, next, return, returnUrl, callback, continue, dest, destination, and redirect_uri. Beyond names, look for features that inherently take a URL: webhooks, link previews, avatar or image import by URL, PDF generation from a page, RSS or feed readers, integrations, and any health check or connectivity test.",
          "Import and preview features are the richest SSRF surface because fetching a remote URL is their entire purpose, and the developer's mental model is that the URL is a document rather than an instruction to make a request from inside the network.",
          "Do not stop at the query string. URL-shaped values arrive in JSON bodies, in headers, and occasionally in path segments, and the body cases are frequently less well validated than the query ones because they were added later."
        ],
        keyPoints: [
          "Look past the obvious names to features that fetch a URL by design",
          "Webhooks, previews, imports, and PDF generation are prime SSRF surface",
          "JSON bodies are often less validated than query strings",
          "A URL in a header is worth testing too"
        ]
      }
    ],
    practicalTips: [
      "Set up an out-of-band collector before you start; most SSRF is blind",
      "Watch whether the redirect target appears in a Location header or is fetched server-side",
      "Test the cloud metadata address where the program permits it, since it is the highest-impact case",
      "Try alternative encodings and formats when a plain external URL is blocked",
      "For redirects, check whether protocol-relative or scheme-changed URLs survive filtering",
      "Record the source address of any callback, since it often exposes internal infrastructure"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Server-Side Request Forgery",
        url: "https://portswigger.net/web-security/ssrf",
        description: "SSRF including blind cases and filter bypasses"
      },
      {
        title: "OWASP SSRF Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        description: "The defences, which map directly onto the bypasses worth trying"
      }
    ]
  },

  urlRedirectSsrfTools: {
    title: "Nuclei DAST, REcollapse, and SSRFmap",
    overview: "These three are a pipeline rather than three alternatives. Nuclei is the detector, REcollapse generates the mutations that get past a filter, and SSRFmap is the exploitation stage that only makes sense once something has been found.",
    sections: [
      {
        title: "Detector, Mutator, Exploiter",
        icon: "fa-diagram-project",
        content: [
          "Nuclei running in DAST mode is the detector. It injects template-driven payloads into your vectors and matches the responses, and it is what actually finds the open redirects and the SSRF candidates in this section. Everything else follows from what it reports.",
          "REcollapse is a mutation generator. Its purpose is defeating input filters by systematically varying encodings, unicode normalisation, and byte-level tricks, on the basis that a filter which blocks an obvious payload frequently accepts a normalised variant that the backend later interprets the same way. It is most valuable on a parameter you already believe is interesting but which rejects the direct payload.",
          "SSRFmap is the exploitation stage. Once a request is known to be forgeable, it works through what can be reached from there, including internal services and cloud metadata. Running it before something has been found is wasted time, which is why it is gated behind a finding."
        ],
        keyPoints: [
          "Nuclei DAST is the detector that drives this section",
          "REcollapse generates filter-bypassing mutations for a parameter that resists direct payloads",
          "SSRFmap is exploitation and only makes sense after a finding",
          "Run them in that order rather than all at once"
        ]
      },
      {
        title: "The Matcher Trap",
        icon: "fa-triangle-exclamation",
        content: [
          "Nuclei can be configured to emit a result for every request it makes, including the ones that did not match, annotating each with whether the match succeeded. If whatever reads that output ignores the annotation, every non-match becomes a finding. During this project that produced 53 fabricated high-severity findings in a single run, all of them from requests that had explicitly not matched.",
          "The second half of the same trap is a weak matcher. An open-redirect template whose matcher is satisfied by the literal text of a Location header will fire on every response that redirects anywhere at all, including entirely normal redirects to the site's own pages. A matcher has to check that the destination is the attacker-controlled one, not merely that a redirect happened.",
          "Both were fixed here, but the lesson generalises: when a scanner reports a large number of identical high-severity findings across unrelated vectors, the matcher is the first thing to doubt. Real vulnerabilities are not evenly distributed."
        ],
        keyPoints: [
          "A non-match annotated as a non-match is not a finding",
          "A matcher must confirm the destination, not merely that a redirect occurred",
          "Many identical high-severity findings across unrelated vectors means a broken matcher",
          "Real vulnerabilities cluster; fabricated ones are uniform"
        ]
      }
    ],
    practicalTips: [
      "Configure the collector before running, since blind SSRF produces nothing without one",
      "Treat a run where nearly every vector reports the same finding as a matcher problem",
      "Use REcollapse on parameters that look interesting but reject direct payloads",
      "Do not run SSRFmap speculatively; it is for confirmed forgeable requests",
      "Confirm one redirect finding by hand before triaging the rest of the batch",
      "Keep the callback identifier unique per vector so attribution is unambiguous"
    ],
    furtherReading: [
      {
        title: "Nuclei",
        url: "https://github.com/projectdiscovery/nuclei",
        description: "Template-driven scanning, including DAST mode"
      },
      {
        title: "REcollapse",
        url: "https://github.com/0xacb/recollapse",
        description: "Generating mutations that survive input filters"
      }
    ]
  },

  urlRedirectSsrfValidation: {
    title: "Confirming a Redirect and Confirming a Forged Request",
    overview: "These two findings are confirmed in completely different ways. A redirect is confirmed by reading a response header; SSRF is confirmed by something arriving at a host you control. Mixing them up is how a low-severity finding gets reported as critical.",
    sections: [
      {
        title: "Confirming an Open Redirect",
        icon: "fa-arrow-right-from-bracket",
        content: [
          "Send the request without following redirects and read the Location header. If it points at your chosen external destination, that is the finding, and the raw response is the evidence. Following redirects automatically hides exactly the thing you are trying to see, which is why a confirmation request should be sent with redirect following turned off.",
          "Be careful about what the destination actually is. A Location header pointing back at the application's own domain is not an open redirect, no matter how much attacker-controlled text is in the path. What makes it a finding is that the caller controls where the browser ends up going, which means a different origin.",
          "When assessing severity, look for the chain. An open redirect on a plain marketing page is minor. The same bug on a parameter that a login or OAuth flow uses to decide where to send the user afterwards is how tokens get stolen, and that is a different report entirely."
        ],
        keyPoints: [
          "Turn off redirect following, then read the Location header",
          "The destination must be a different origin to count",
          "Raw response headers are the evidence",
          "Severity comes from where the parameter is used, especially in auth flows"
        ]
      },
      {
        title: "Confirming SSRF",
        icon: "fa-satellite-dish",
        content: [
          "The proof is a request arriving at infrastructure you control, from the target. Use a unique subdomain or path per test so you can attribute it, and record the source address, the timestamp, and the full request that arrived. That source address is often interesting in its own right, since it can reveal internal ranges or the cloud provider.",
          "A DNS lookup alone is weaker evidence than a full HTTP request, because some environments resolve names without fetching. It still demonstrates the name reached a resolver on the target's side, which is worth reporting, but say which one you observed rather than describing both as the same thing.",
          "For blind cases, the response body is usually useless and the callback is everything. That means an unreachable collector turns every blind SSRF into a silent clean result, so test that the collector is reachable before you conclude a target is not vulnerable."
        ],
        keyPoints: [
          "A callback from the target's infrastructure is the proof",
          "Use a unique identifier per vector for attribution",
          "A DNS lookup is weaker than a full HTTP request; say which you saw",
          "An unreachable collector makes every blind case report clean"
        ]
      }
    ],
    practicalTips: [
      "Send confirmation requests with redirect following disabled",
      "Use a unique callback hostname per vector",
      "Record the callback source address, which often exposes internal infrastructure",
      "Verify the collector is reachable before trusting a clean blind result",
      "Check whether the redirect parameter is used in an authentication flow before setting severity",
      "Keep the raw response headers; a screenshot of a browser landing page proves less"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Blind SSRF",
        url: "https://portswigger.net/web-security/ssrf/blind",
        description: "Detecting and exploiting SSRF with no response to read"
      },
      {
        title: "OWASP WSTG - Testing for Client-Side URL Redirect",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
        description: "The redirect side, done methodically"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Web Cache Poisoning and Deception
  // ---------------------------------------------------------------------------------------------
  urlCacheMethodology: {
    title: "Web Cache Poisoning and Deception",
    overview: "Caches sit in front of most applications and decide which stored response to serve using only part of the request. Everything they ignore is unkeyed input, and unkeyed input that still changes the response is the entire basis of cache poisoning.",
    sections: [
      {
        title: "The Cache Key Is the Whole Story",
        icon: "fa-key",
        content: [
          "A cache decides whether two requests are the same by hashing part of them, typically the method, the host, and the path, and often not much else. Everything outside that key is unkeyed: most headers, sometimes some query parameters, sometimes the whole query string.",
          "Poisoning happens when unkeyed input still influences the response. You send a request whose unkeyed part contains your payload, the cache stores the poisoned response under the ordinary key, and every subsequent visitor to that normal URL is served your content. That is why cache poisoning is a stored attack even though nothing was written to the application's database.",
          "Cache deception is the mirror image. You persuade the cache to store a response that contains someone else's private data under a URL you can then request, usually by appending something that makes the cache treat a dynamic page as a static asset while the application still serves the personalised version."
        ],
        keyPoints: [
          "The cache key is usually method, host, and path, and little else",
          "Unkeyed input that changes the response is the vulnerability",
          "Poisoning serves your content to other users from a normal URL",
          "Deception stores another user's private response where you can fetch it"
        ]
      },
      {
        title: "Testing Without Poisoning Real Users",
        icon: "fa-shield-halved",
        content: [
          "This is the class where careless testing does visible damage. A poisoned response can be served to real visitors for as long as the cache retains it, which can be hours. That is not a theoretical concern, it is the ordinary consequence of a successful test.",
          "The discipline is to work on a URL nobody else uses. Adding a unique, meaningless query parameter usually produces a distinct cache entry that only you will request, which lets you demonstrate the same behaviour without affecting the site's real traffic. Prove the mechanism there, then describe in the report what it would mean on a real path.",
          "Keep payloads harmless, keep the affected entry identifiable, and tell the program what you did so they can purge it. A cache poisoning report that includes the cache key you affected is much easier for a defender to clean up."
        ],
        keyPoints: [
          "A successful poison affects real visitors until the entry expires",
          "Use a unique query parameter to get a private cache entry to test on",
          "Keep payloads harmless and identifiable",
          "Tell the program which entry to purge"
        ]
      }
    ],
    practicalTips: [
      "Read the cache response headers first; they tell you whether a cache is present and whether you hit it",
      "Add a unique query parameter so your tests land on their own cache entry",
      "Test headers that plausibly influence the response, especially forwarding and host headers",
      "For deception, look for URL forms that make a dynamic page look like a static asset",
      "Confirm a hit is genuinely cached by requesting it again from a clean session",
      "Report the affected cache key so the target can purge it"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Web Cache Poisoning",
        url: "https://portswigger.net/web-security/web-cache-poisoning",
        description: "The definitive material on unkeyed input and cache keys"
      },
      {
        title: "PortSwigger - Web Cache Deception",
        url: "https://portswigger.net/web-security/web-cache-deception",
        description: "The mirror-image attack against personalised responses"
      }
    ]
  },

  urlCacheTools: {
    title: "WCVS and CacheBoom",
    overview: "Both automate the search for unkeyed input, sending candidate headers and parameters and watching for a poisoned response. Two properties of how they run matter more than their feature lists: they work on URLs rather than on parameter vectors, and they are prone to losing their own output.",
    sections: [
      {
        title: "URL Scanners, Not Vector Scanners",
        icon: "fa-link",
        content: [
          "Most tools in this workflow test a specific parameter at a specific insertion point. These two do not; they take a URL and vary the request around it, mostly headers, looking for anything unkeyed that changes the response. That is the right model for this bug class, because the payload usually goes in a header the vector list never captured.",
          "The consequence is that the unit of work here is the URL, so the same page reached through several vectors collapses into one scan. It also means the value comes from choosing which URLs to test rather than from having a large vector list. Cacheable pages are what matter, and the response headers tell you which those are.",
          "It also means a clean result covers the headers the tool chose to try, not every possible unkeyed input. A header specific to this application's own infrastructure will not be in anyone's default list."
        ],
        keyPoints: [
          "These tools vary the request around a URL rather than testing one parameter",
          "The unit of work is the URL, so pick cacheable pages deliberately",
          "Coverage is limited to the header list the tool carries",
          "Application-specific headers need to be added by hand"
        ]
      },
      {
        title: "Two Ways They Report Nothing",
        icon: "fa-ghost",
        content: [
          "The first is output buffering. These tools produce their results on standard output, and when that output is captured without being flushed properly the findings can be lost after the tool has already found them. The scan succeeds, the tool prints its result, and the result never reaches whatever was reading it. The visible outcome is a clean scan.",
          "The second is a cache that was never hit. If the responses were not cached during the test, no amount of unkeyed input will produce a poisoned hit, and the tool will correctly report nothing. That is a statement about the test conditions, not about the target's cache behaviour.",
          "Both are worth checking before accepting a clean result, and the check is the same in each case: look at the response headers for one of the URLs tested and confirm a cache was actually in play."
        ],
        keyPoints: [
          "Output lost in buffering looks exactly like a clean scan",
          "If nothing was cached during the test, nothing can be poisoned",
          "Check cache headers on a tested URL before believing a clean result",
          "A clean result covers the headers tried, not all possible unkeyed input"
        ]
      }
    ],
    practicalTips: [
      "Pick URLs that are demonstrably cacheable rather than scanning everything",
      "Check the cache status headers before and after a run",
      "Add application-specific headers to the candidate list where you can",
      "Re-run a promising URL by hand to confirm a hit is reproducible",
      "Use a unique query parameter while testing so you do not poison shared entries",
      "Treat an empty result on a page with no cache headers as untested rather than clean"
    ],
    furtherReading: [
      {
        title: "Web Cache Vulnerability Scanner",
        url: "https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner",
        description: "The scanner behind the WCVS card"
      },
      {
        title: "PortSwigger - Cache Key Flaws",
        url: "https://portswigger.net/web-security/web-cache-poisoning/exploiting-design-flaws",
        description: "How cache key handling itself becomes the vulnerability"
      }
    ]
  },

  urlCacheValidation: {
    title: "Proving a Cache Was Actually Poisoned",
    overview: "The claim in a cache poisoning report is that another person will receive your content. Proving that means showing the poisoned response came out of the cache for a request that did not contain your payload.",
    sections: [
      {
        title: "The Three-Request Proof",
        icon: "fa-clipboard-check",
        content: [
          "First, request the URL normally and record the clean response. Second, send the poisoning request with your unkeyed payload. Third, request the URL normally again, from a fresh session and ideally a different network, and show that the response now contains your payload even though this request never carried it.",
          "That third request is the entire finding. Without it you have only shown that a header changes the response, which is interesting but is not a cache vulnerability. With it you have shown that the change persists for other people.",
          "Cache status headers strengthen the evidence considerably. A response marked as a cache hit on the third request is direct confirmation the content came from the cache rather than being regenerated."
        ],
        keyPoints: [
          "Clean request, poisoning request, then a clean request that shows the payload",
          "The third request is the finding; the first two are setup",
          "Use a fresh session and a different network for the third request",
          "Cache status headers confirm the response came from the cache"
        ]
      },
      {
        title: "Cleaning Up",
        icon: "fa-broom",
        content: [
          "Once proved, the poisoned entry is still live. Tell the program exactly which URL and which cache key you affected so they can purge it, and say when you did it. This is not just courtesy; it is the difference between a report that reads as responsible research and one that reads as an incident.",
          "Where the cache respects a purge or a short time-to-live, note that too. A poison that expires in sixty seconds is a different severity from one that persists for a day, and the duration is part of the impact assessment.",
          "Keep your payload boring. Something that visibly proves control without doing anything harmful is all that is needed, and it makes the cleanup conversation much simpler."
        ],
        keyPoints: [
          "The poisoned entry stays live until it expires or is purged",
          "Report the exact URL and key so it can be cleaned up",
          "Persistence duration is part of the severity",
          "A harmless payload makes the whole report easier to handle"
        ]
      }
    ],
    practicalTips: [
      "Always include the third, clean request in your evidence",
      "Capture cache status headers on every request in the sequence",
      "Verify from a different session and network so nothing is attributable to your own state",
      "Note how long the poison persisted",
      "Tell the program which entry to purge, and when you poisoned it",
      "Keep the payload obviously harmless and clearly yours"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Exploiting Cache Poisoning",
        url: "https://portswigger.net/web-security/web-cache-poisoning/exploiting",
        description: "Turning unkeyed input into a demonstrated impact"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Request Smuggling
  // ---------------------------------------------------------------------------------------------
  urlSmugglingMethodology: {
    title: "Request Smuggling and Desync",
    overview: "When a front-end proxy and a back-end server disagree about where one request ends and the next begins, you can hide a second request inside the first. The back end then attaches your hidden request to whoever's connection comes next, which is what makes this class so severe.",
    sections: [
      {
        title: "A Disagreement About Length",
        icon: "fa-scissors",
        content: [
          "HTTP has two ways to say how long a body is: a Content-Length header, and chunked transfer encoding. When a request contains both, the specification says what should happen, but a front end and a back end can still resolve it differently. One reads to the length, the other reads to the terminating chunk, and the bytes between the two interpretations become the start of what the back end considers the next request.",
          "That leftover is the smuggled request. It sits at the front of the connection waiting for the next real request to be appended to it, so the next user's request gets combined with your prefix. Depending on the shape, this lets you redirect other users' requests, poison a shared cache, capture other people's request data, or reach endpoints the front end would have refused.",
          "HTTP/2 introduces its own version. When a front end speaks HTTP/2 and downgrades to HTTP/1.1 for the back end, the length information has to be rewritten, and errors in that rewriting produce the same desynchronisation."
        ],
        keyPoints: [
          "The bug is a disagreement about where a request ends",
          "The leftover bytes become a prefix on the next user's request",
          "Impact includes hijacking other users' requests and bypassing front-end controls",
          "HTTP/2 downgrade introduces a second family of the same problem"
        ]
      },
      {
        title: "The Class Most Likely to Cause Damage",
        icon: "fa-triangle-exclamation",
        content: [
          "Everything about this class affects other people by design. The mechanism is attaching your content to somebody else's connection, so a successful test is a successful interference with real users. On a busy production system, a smuggled prefix can be picked up by an ordinary visitor within seconds.",
          "It can also break things outright. A desynchronised connection can cause errors for unrelated users, and repeated testing can leave a pool of connections in a bad state. This is the section where the safest useful thing is often to establish that the desync exists and stop there.",
          "Many bug bounty programs place restrictions on this class for exactly these reasons. Check the program rules before testing, keep the volume low, and prefer timing-based detection over exploitation that involves capturing another person's request."
        ],
        keyPoints: [
          "A successful test interferes with real users by design",
          "Desynchronised connections can break unrelated traffic",
          "Establish that the desync exists rather than exploiting it fully",
          "Check the program rules first; this class is often restricted"
        ]
      }
    ],
    practicalTips: [
      "Read the program rules before testing this class at all",
      "Prefer timing-based detection to exploitation involving other users' requests",
      "Test outside peak hours where you have any choice about it",
      "Keep the number of attempts low; this is not a class to brute force",
      "Stop as soon as the desync is established rather than chaining further",
      "Report promptly, since a discovered desync is actively dangerous to the target"
    ],
    furtherReading: [
      {
        title: "PortSwigger - HTTP Request Smuggling",
        url: "https://portswigger.net/web-security/request-smuggling",
        description: "The definitive material, including safe detection methodology"
      },
      {
        title: "PortSwigger - Advanced Request Smuggling",
        url: "https://portswigger.net/web-security/request-smuggling/advanced",
        description: "HTTP/2 downgrade and the newer variants"
      }
    ]
  },

  urlSmugglingTools: {
    title: "smugglex and http2smugl",
    overview: "smugglex probes the classic HTTP/1.1 length disagreements; http2smugl targets the HTTP/2 downgrade family. Both detect primarily by timing, which is the source of both their usefulness and their false positives.",
    sections: [
      {
        title: "Two Families, Two Tools",
        icon: "fa-toolbox",
        content: [
          "smugglex works the traditional ground: requests carrying both a Content-Length and a chunked encoding, in the various orderings and obfuscations that make a front end and a back end resolve them differently. It sends probe requests and measures how the connection behaves.",
          "http2smugl targets what happens at the HTTP/2 to HTTP/1.1 boundary. Because the front end must translate length information when it downgrades, there is a separate set of ways to make the two ends disagree, and they do not overlap much with the HTTP/1.1 cases.",
          "They deduplicate their work by endpoint rather than by parameter, because this bug lives in the connection handling rather than in any parameter. That means a small number of well-chosen endpoints is the right input, not the full vector list."
        ],
        keyPoints: [
          "smugglex: classic HTTP/1.1 length disagreements",
          "http2smugl: the HTTP/2 downgrade family",
          "The two families barely overlap, so run both",
          "The unit of work is the endpoint, not the parameter"
        ]
      },
      {
        title: "Why Timing Detection Produces False Positives",
        icon: "fa-clock",
        content: [
          "The core detection technique is a request crafted so that a vulnerable server will wait for bytes that never arrive, producing a timeout, while a correctly behaving server responds normally. That makes a timeout the signal, and a timeout has many innocent causes.",
          "There are at least four ways to get a timeout that is not a desync: the target is simply slow under load, a rate limiter has started delaying you, a WAF is holding the connection, or the network between you and the target hiccupped. All four look identical to the tool.",
          "The consequence is that a single timing-based hit is a lead, not a finding. Repeating the probe, taking a baseline against a request that should not desync, and confirming the behaviour is consistent are what separate a real desync from a slow afternoon."
        ],
        keyPoints: [
          "The detection signal is a timeout, which has innocent causes",
          "Load, rate limiting, WAF behaviour, and network jitter all produce timeouts",
          "A single timing hit is a lead, not a finding",
          "Repeat with a baseline before believing it"
        ]
      }
    ],
    practicalTips: [
      "Run both tools; the HTTP/1.1 and HTTP/2 families are largely disjoint",
      "Feed a small set of chosen endpoints rather than the full vector list",
      "Repeat every timing-based hit several times before treating it as real",
      "Take a baseline with an equivalent request that should not desync",
      "Watch for rate limiting starting mid-run, which will produce a cluster of false hits",
      "Keep total request volume low, since this class is disruptive"
    ],
    furtherReading: [
      {
        title: "http2smugl",
        url: "https://github.com/neex/http2smugl",
        description: "HTTP/2 downgrade smuggling detection"
      },
      {
        title: "PortSwigger - Finding Request Smuggling",
        url: "https://portswigger.net/web-security/request-smuggling/finding",
        description: "The timing methodology and how to avoid fooling yourself with it"
      }
    ]
  },

  urlSmugglingValidation: {
    title: "Separating a Real Desync From a Slow Server",
    overview: "Because detection is timing-based, most reported smuggling candidates are not vulnerabilities. This lesson is the discipline that tells the difference, and the reason to stop as soon as it does.",
    sections: [
      {
        title: "The Differential Test",
        icon: "fa-code-compare",
        content: [
          "The evidence for a desync is not that one request was slow. It is that a request crafted to desynchronise behaves differently from an otherwise identical request crafted not to, consistently, across repetitions. That differential is what rules out load and jitter, because both would affect the two variants equally.",
          "Run both variants interleaved rather than in blocks, so a change in the target's condition partway through cannot masquerade as a difference between them. Repeat enough times that the pattern is unmistakable, and record the timings rather than describing them.",
          "If the difference disappears when you interleave, or if both variants slow down together, you were measuring the target's mood rather than its parsing."
        ],
        keyPoints: [
          "The evidence is a consistent difference between two crafted variants",
          "Interleave the variants so conditions affect both equally",
          "Repeat enough times that the pattern is unambiguous",
          "Record actual timings, not impressions"
        ]
      },
      {
        title: "Stopping at the Right Point",
        icon: "fa-hand",
        content: [
          "Once the differential holds up, you have enough for a report. The next step in a full exploitation chain involves capturing another user's request or poisoning something shared, and both of those affect real people. In most programs that is beyond what you are authorised to do, and it is rarely necessary to establish severity.",
          "A good smuggling report describes the front-end and back-end disagreement, shows the differential evidence, and explains what the desync would permit, without having done it. Triagers for this class understand the mechanism and do not need you to have hijacked a real session to take it seriously.",
          "Report quickly. An exploitable desync on a production system is dangerous while it exists, and unlike most findings, somebody else stumbling onto it can cause real damage without meaning to."
        ],
        keyPoints: [
          "The differential evidence is enough; full exploitation is not required",
          "Capturing another user's request is usually outside authorisation",
          "Describe what the desync permits rather than demonstrating it on real users",
          "Report quickly; this class is dangerous while it remains open"
        ]
      }
    ],
    practicalTips: [
      "Interleave your two variants rather than running them in blocks",
      "Record raw timings and include them in the report",
      "Re-test from a different network to rule out a problem on your side",
      "Check whether a rate limiter engaged during the run",
      "Stop at the differential; do not chain into other users' traffic",
      "Report immediately rather than continuing to explore"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Request Smuggling Exploitation",
        url: "https://portswigger.net/web-security/request-smuggling/exploiting",
        description: "What a desync permits, which is what you describe rather than perform"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // 403 and Access Control Bypass
  // ---------------------------------------------------------------------------------------------
  urlAccessBypassMethodology: {
    title: "403 Bypass: When the Check and the Route Disagree",
    overview: "A 403 means something refused you. This section tries to find a way to ask for the same thing that the refusing component does not recognise as the same request, which is almost always a split between where the check is applied and where the routing decision is made.",
    sections: [
      {
        title: "Why the Bypass Exists at All",
        icon: "fa-door-closed",
        content: [
          "In a typical deployment the access rule and the routing live in different places. A proxy, a WAF, or a gateway decides that requests to an administrative path are refused, and an application server decides which handler actually runs. If those two components normalise the request differently, a request can look forbidden to one and ordinary to the other, or the reverse.",
          "The most productive family exploits the header. Several forwarding headers exist specifically so a proxy can tell a back end what the original request was, and where a back end trusts one of those headers to determine the route while the front end applies its rules to the literal path, you can be refused on one path and served another.",
          "The second family exploits normalisation. Trailing slashes, case, encoded characters, doubled separators, and path segment tricks can all produce two strings that one component considers different and the other considers the same. A third family simply changes the verb, on the basis that the rule was written for GET and the handler accepts more than that."
        ],
        keyPoints: [
          "The rule and the routing usually live in different components",
          "Forwarding headers let a back end route on something the front end did not check",
          "Normalisation differences make one path look like two",
          "Rules written for one verb often miss the others"
        ]
      },
      {
        title: "What Makes It a Real Finding",
        icon: "fa-bullseye",
        content: [
          "The finding is not a status code change. It is reaching protected content. A 200 proves something answered, and the thing that answered is very often an ordinary allowed page that has nothing to do with the resource you were refused.",
          "So the standard of proof is naming the privileged string: something in the response body that the denial withheld and that only an authorised caller should see. A username, an administrative control, a record, a piece of data. If you cannot point at such a string, you have a status code and not a finding.",
          "During this project this section produced three candidates against one target. One was real, returning administrative content to an anonymous caller through a forwarding header. The other two were the ordinary public homepage and about page returned with a header that had done nothing at all."
        ],
        keyPoints: [
          "A changed status code is not access",
          "Name a string in the body that the denial withheld",
          "Byte length differing from the denial page proves nothing",
          "Expect most candidates in this class to be false positives"
        ]
      }
    ],
    practicalTips: [
      "Collect the 403 endpoints first; without them this section has nothing to work on",
      "Compare bodies, never status codes alone",
      "Try the successful technique against other protected paths; it usually generalises",
      "Test every verb, not only GET",
      "A soft 403 that returns 200 with a denial page will fool status-based tools",
      "If the interface hides an action, test the endpoint behind it directly"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Access Control Vulnerabilities",
        url: "https://portswigger.net/web-security/access-control",
        description: "Including the header and method-based bypasses"
      },
      {
        title: "CWE-284: Improper Access Control",
        url: "https://cwe.mitre.org/data/definitions/284.html",
        description: "The formal classification for reports"
      }
    ]
  },

  urlAccessBypassTools: {
    title: "nomore403 and Forbidden",
    overview: "Both take a refused URL and re-send it many ways: header injection, path mutation, verb changes, and alternative sources. They differ in coverage and in output, and they share a reporting weakness that makes their results look far stronger than they are.",
    sections: [
      {
        title: "What They Try",
        icon: "fa-toolbox",
        content: [
          "Both tools work through a matrix of techniques. Forwarding headers that name an alternative path or host, path mutations covering slashes and case and encoding, alternative HTTP verbs, and header values that claim a different origin address. Forbidden organises these into named families that can be run selectively, which matters because a full run is slow.",
          "Running only some families is a common configuration, and it is where a misleading clean result comes from: families that were never run are untested, not clean. If a section reports no bypass but only two of the available families executed, the honest summary is that most of the technique space was not explored.",
          "The tools are also sensitive to how they are invoked. Both validate their own arguments, and Forbidden in particular will print a complaint and exit successfully without writing a report, which is indistinguishable from a clean scan unless something reads its output."
        ],
        keyPoints: [
          "Headers, path mutations, verbs, and origin claims are the four broad families",
          "Families that were not run are untested rather than clean",
          "Forbidden can refuse its arguments and still exit successfully",
          "An exit code is not a reliable signal for either tool"
        ]
      },
      {
        title: "The Baseline They Do Not Take",
        icon: "fa-triangle-exclamation",
        content: [
          "This is the single most important thing to understand about both tools. Their only content baseline is the original denial. They compare a candidate response against the 403 page, and if it differs enough they report a bypass. What they never do is fetch the URL they actually requested without the added header, and compare against that.",
          "That omission is why so many findings in this section are false. If the tool requests an ordinary public page with an extra header, the header does nothing, and the ordinary page comes back, the response differs from the denial page in both status and length, so it is reported as a bypass. Nothing was bypassed; a public page was fetched.",
          "The fix is a step the tools do not perform for you: fetch the finding's own URL with no added header, and compare the finding against that. If they are identical, the header did nothing and the finding is dead. That one request eliminates most of what this section reports."
        ],
        keyPoints: [
          "Both tools compare only against the denial page",
          "Neither fetches the plain version of the URL it actually requested",
          "An allowed page plus a useless header looks exactly like a bypass",
          "The negative control is the step that kills most of these findings"
        ]
      }
    ],
    practicalTips: [
      "Run every technique family, and record which ones actually executed",
      "Always take the negative control before triaging a candidate",
      "Check that the tool produced a report at all rather than trusting its exit",
      "Watch for soft 403s that return 200 with a denial body, which break length comparisons",
      "When a technique works, try it against every other protected path",
      "Treat a section with no 403 endpoints as having nothing to test, not as clean"
    ],
    furtherReading: [
      {
        title: "nomore403",
        url: "https://github.com/devploit/nomore403",
        description: "Bypass technique matrix for 403 responses"
      },
      {
        title: "PortSwigger - Bypassing Access Controls",
        url: "https://portswigger.net/web-security/access-control#bypassing-access-controls",
        description: "The techniques these tools automate, explained"
      }
    ]
  },

  urlAccessBypassValidation: {
    title: "The Negative Control",
    overview: "Most findings in this section die to one extra request. This is that request, why it works, and what to do with the candidates that survive it.",
    sections: [
      {
        title: "Three Requests, In This Order",
        icon: "fa-clipboard-check",
        content: [
          "First, request the protected path plainly and confirm it is still refused. Record the status and the length. Second, request the finding's own URL with no added header. This is the control, and it is the request nobody makes. Third, send the finding's request exactly as reported.",
          "Now compare the third response against the second, before you compare it against the first. If the third is identical to the control, the added header changed nothing and the finding is a false positive: the tool only noticed that an allowed page differs from a denial page.",
          "If the third differs from the control, you have something. Then compare it against the first, the denial, and identify what it contains that the denial withheld. That is the finding, and that string is what goes in the report."
        ],
        keyPoints: [
          "Denial, control, then the finding's own request",
          "Compare against the control first, not against the denial",
          "Identical to the control means the header did nothing",
          "Only after it beats the control does the comparison against the denial matter"
        ]
      },
      {
        title: "Reporting the Survivors",
        icon: "fa-file-signature",
        content: [
          "A surviving finding should name the technique, the protected resource, and the privileged content that came back. Naming the technique matters because the fix is different for each: a trusted forwarding header is fixed in the proxy configuration, a normalisation difference is fixed by aligning the two components, and a verb gap is fixed in the access rule itself.",
          "Include all three requests and responses. A triager who can see the denial, the control, and the bypass side by side can confirm the finding in under a minute, and this is a class where triagers have seen a great many false positives and are appropriately sceptical.",
          "Then generalise before you submit. A technique that works on one protected path very often works on all of them, and a report covering the whole administrative surface is worth considerably more than one covering a single URL."
        ],
        keyPoints: [
          "Name the technique, since it determines the fix",
          "Include the denial, the control, and the bypass in the evidence",
          "Point at the specific privileged content that came back",
          "Test the technique against every protected path before submitting"
        ]
      }
    ],
    practicalTips: [
      "Never skip the control request, even when the finding looks obvious",
      "Compare bodies rather than lengths; pages vary in size on their own",
      "Quote the privileged string in the report rather than describing it",
      "Try the working technique across the whole protected surface",
      "Note whether the bypass works unauthenticated, which raises the severity",
      "Where a finding fails the control, dismiss it explicitly so it does not resurface"
    ],
    furtherReading: [
      {
        title: "OWASP Top 10 - Broken Access Control",
        url: "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
        description: "Context and severity framing for the report"
      }
    ]
  }
};
