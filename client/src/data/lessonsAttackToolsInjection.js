// Lessons for the injection-class attack tool sections: XSS, SQL and NoSQL injection, command
// injection and SSTI, and local file inclusion. Merged into the main lessons export.
//
// Each tool lesson names the specific way that tool reports nothing when it has in fact tested
// nothing, because that is the failure a learner will hit and misread first.

export const attackToolsInjectionLessons = {
  // ---------------------------------------------------------------------------------------------
  // Cross-Site Scripting
  // ---------------------------------------------------------------------------------------------
  urlXssMethodology: {
    title: "Cross-Site Scripting: What You Are Actually Looking For",
    overview: "XSS is the ability to run your JavaScript in someone else's browser session on the target's origin. This section runs three tools that look for it in three different ways, and understanding the difference between them is what stops you reporting a reflection as a vulnerability.",
    sections: [
      {
        title: "Reflection Is Not Execution",
        icon: "fa-arrows-turn-to-dots",
        content: [
          "The most common mistake in XSS testing is treating an echo as a finding. If you send a payload and see it come back in the response body, you have proved the application reflects input. You have not proved a browser will execute it. The same string is inert inside an attribute value, inside a JavaScript string literal, inside a comment, or when the characters that matter have been encoded.",
          "What makes it a vulnerability is context: your input landing somewhere the browser will parse as code, with the characters that break out of the surrounding syntax surviving intact. That is why the framework records an insertion point and a context for each finding rather than just a match.",
          "The practical consequence is that every reflection-based finding needs one more step before you believe it. Open it in a real browser and see whether the script actually runs. That step takes ten seconds and it is the difference between a valid report and a duplicate-closed-as-informative."
        ],
        keyPoints: [
          "Seeing your payload in the response only proves reflection",
          "Context decides whether reflection becomes execution",
          "Encoding of quotes and angle brackets is usually what kills a payload",
          "Confirm in a browser before reporting anything reflection-based"
        ]
      },
      {
        title: "The Three Shapes of XSS",
        icon: "fa-shapes",
        content: [
          "Reflected XSS travels in the request and comes straight back in the response, so exploiting it means getting the victim to make that request. It is the easiest to find and the weakest by itself, since it needs a delivery mechanism.",
          "Stored XSS is written to the server and served to whoever loads the affected page later. It is the most valuable because it needs no delivery: the victim simply uses the application normally. It is also the hardest to test responsibly, because the payload persists and can reach real users, so keep stored payloads inert and clean up after yourself.",
          "DOM-based XSS never involves the server's response body at all. Client-side JavaScript reads something attacker-controlled, often the URL fragment, and writes it into a dangerous sink. Because the payload can live after the hash and never reach the server, server-side scanners are blind to it, which is why this section includes a tool that drives a real browser."
        ],
        keyPoints: [
          "Reflected needs delivery; stored does not, which is why stored is worth more",
          "DOM-based happens entirely in the browser and can bypass server-side detection",
          "A fragment payload may never appear in any server log or response",
          "Keep stored payloads harmless; real users can hit them"
        ]
      }
    ],
    practicalTips: [
      "Prove execution in a browser rather than trusting a reflection match",
      "Use a distinctive marker string first to find where input lands, then craft the payload for that context",
      "For stored XSS use something inert that proves execution without disrupting the application",
      "Check the URL fragment for DOM XSS; it never reaches the server",
      "A payload blocked by a WAF is not the same as an application that encodes properly",
      "Look for the sink, not just the source: document.write, innerHTML, and eval are where it lands"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Cross-Site Scripting",
        url: "https://portswigger.net/web-security/cross-site-scripting",
        description: "The most complete free XSS material, with labs for each context"
      },
      {
        title: "OWASP XSS Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        description: "The defences, which tells you exactly what you are trying to defeat"
      }
    ]
  },

  urlXssTools: {
    title: "Dalfox, DOMDig, and xssFuzz: Three Different Questions",
    overview: "These three tools do not overlap as much as their descriptions suggest. One analyses reflection and context, one drives a real browser to catch DOM sinks, and one does a straightforward substring check. Knowing which question each answers tells you what a result from it is worth.",
    sections: [
      {
        title: "What Each Tool Actually Does",
        icon: "fa-toolbox",
        content: [
          "Dalfox is the workhorse. It sends payloads, finds where they land, works out the surrounding context, and reports a verified finding when the payload escapes that context. It also performs static analysis of the response and can report a finding type that means the parameter looks dangerous without any payload having been proven to fire.",
          "DOMDig drives a real Chromium browser. It loads the page, interacts with it, and watches whether attacker-controlled data reaches a dangerous DOM sink. This is the only one of the three that can find DOM-based XSS, and it is correspondingly slower.",
          "xssFuzz is the simplest: it sends payloads and checks whether the payload string appears in the response. That is a plain substring test with no understanding of context whatsoever. It is fast and it casts a wide net, and every one of its hits needs manual confirmation because a payload echoed inside an encoded attribute matches just as happily as one that executes."
        ],
        keyPoints: [
          "Dalfox: payload plus context analysis, the best single default",
          "DOMDig: real browser, the only one that finds DOM-based XSS",
          "xssFuzz: substring match, wide net, every hit needs checking",
          "Their findings are not interchangeable and should not be compared directly"
        ]
      },
      {
        title: "Reading Dalfox Finding Types",
        icon: "fa-tags",
        content: [
          "Dalfox labels its findings by type and the labels matter more than the severity. A verified finding means a payload was sent and the tool determined it escaped its surrounding context. That is the strongest thing the tool says and it is still worth confirming in a browser, because current Dalfox versions do not ship a headless browser of their own for the general case.",
          "An analysis finding is static: the tool looked at the response and concluded the parameter is reflected somewhere risky. No payload was proven to fire, and there may be no interesting exchange to show. Treat these as leads to test by hand rather than as findings.",
          "There is one exception worth knowing. When a finding's detection method is out-of-band, something in the target genuinely called back to the collector. That is not a reflection heuristic, that is real execution, and it is the strongest signal any of these tools produce."
        ],
        keyPoints: [
          "Verified means the payload escaped its context, which is strong but still worth confirming",
          "Analysis findings are static reasoning with no payload fired",
          "An out-of-band detection is real execution and outranks everything else",
          "Read the type, not the severity, when triaging"
        ]
      }
    ],
    practicalTips: [
      "Run all three; they miss different things and agreement between them raises confidence",
      "Give DOMDig time, since driving a browser is much slower than sending requests",
      "Treat every xssFuzz hit as unconfirmed until you have looked at the surrounding context",
      "Blind XSS needs a collector, so configure the callback before running rather than after",
      "If a run finishes far faster than the others, suspect it aborted rather than that it found nothing",
      "Check the run status and not only the finding count, since an aborted run reports zero findings"
    ],
    furtherReading: [
      {
        title: "Dalfox",
        url: "https://github.com/hahwul/dalfox",
        description: "Parameter analysis and XSS scanner"
      },
      {
        title: "DOMDig",
        url: "https://github.com/fcavallarin/domdig",
        description: "DOM XSS scanner built on a real browser"
      }
    ]
  },

  urlXssValidation: {
    title: "Validating an XSS Finding Before You Report It",
    overview: "An XSS report that cannot be reproduced is worse than no report. This lesson is the checklist that turns a scanner hit into something a triager can confirm in one click, and the specific failure modes that make these tools report zero when they tested nothing.",
    sections: [
      {
        title: "The Confirmation Sequence",
        icon: "fa-clipboard-check",
        content: [
          "Start by reproducing the exact request the tool sent, unchanged. If it does not reflect any more, the finding was transient or the application has changed and there is nothing to report. Then load it in a real browser rather than a command-line client, because execution is a browser behaviour and curl will happily show you a payload that no browser would run.",
          "Look at where the payload lands in the page source and confirm the characters that matter survived. If your quotes came back as encoded entities, the reflection is inert regardless of what the tool concluded. Then simplify: strip the payload down to the smallest thing that still fires, which makes the report clearer and proves you understand the context.",
          "Finally check whether it survives a page reload from a fresh session. A payload that only fires in your already-poisoned browser state is not a vulnerability another person can reproduce."
        ],
        keyPoints: [
          "Reproduce the exact request first, before changing anything",
          "Use a browser; execution is a browser behaviour",
          "Confirm the syntax-breaking characters were not encoded",
          "Reduce the payload to its minimum before writing the report"
        ]
      },
      {
        title: "When Zero Findings Means Nothing Was Tested",
        icon: "fa-ghost",
        content: [
          "These scanners have session checks, and when the marker they were told to look for stops appearing they abort. The abort is recorded in the run metadata, not in the findings, so the visible result is a completed scan with zero findings. During this project that produced 53 attack vectors reported as free of XSS against an application that documents four separate XSS vulnerabilities.",
          "A second version of the same trap is a rejected command line. If a tool is handed an option it does not accept, it prints a usage message and exits without sending a single request. Nothing was tested, and without a check on the tool's output that reads as a clean scan.",
          "The framework now flags both, but the habit is worth keeping regardless of tooling: a scan that finished unusually fast, or reported clean on a target you have reason to believe is vulnerable, should be re-run and re-checked before it is believed."
        ],
        keyPoints: [
          "An aborted run reports zero findings and looks like a clean scan",
          "A rejected command line sends no requests at all",
          "Unusually fast completion is the most reliable warning sign",
          "Verify the session is still live before accepting a clean result"
        ]
      }
    ],
    practicalTips: [
      "Reproduce in a browser, in a private window, from a fresh session",
      "Screenshot or record the execution; triagers close reports they cannot reproduce",
      "Minimise the payload before reporting so the root cause is obvious",
      "Say which context the payload broke out of, since that is what needs fixing",
      "For stored XSS, note where the payload persists so it can be cleaned up",
      "Re-check the session before accepting any clean XSS result"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Cross-Site Scripting Contexts",
        url: "https://portswigger.net/web-security/cross-site-scripting/contexts",
        description: "Why the same payload fires in one place and not another"
      },
      {
        title: "OWASP WSTG - Testing for Reflected XSS",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting",
        description: "The methodical version of the confirmation sequence"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // SQL and NoSQL Injection
  // ---------------------------------------------------------------------------------------------
  urlSqliMethodology: {
    title: "SQL Injection: Still the One That Ends Engagements",
    overview: "SQL injection means the application built a query by pasting your input into it, so you can change what the query does. It is decades old, still present, and still the fastest route from one parameter to the entire database. This section runs three tools that find it in different ways.",
    sections: [
      {
        title: "Why It Still Exists",
        icon: "fa-database",
        content: [
          "Parameterised queries have been the standard fix for twenty years, and most of an application will use them. Injection survives in the places that did not fit the pattern: a dynamic ORDER BY, a search filter assembled from optional clauses, a legacy report generator, a migration script that became a feature, or a stored procedure that concatenates internally.",
          "That is why finding it is a matter of coverage rather than cleverness. The vulnerable parameter is rarely the obvious login field, because the login field was hardened first. It is the category filter, the sort column, the export format, the internal admin search that nobody reviewed.",
          "It also explains why hidden parameters matter so much here. A parameter the developer forgot to document is a parameter nobody reviewed for injection either."
        ],
        keyPoints: [
          "Most of the application is parameterised; the exceptions are where the bug lives",
          "Dynamic ORDER BY and optional filter clauses are classic weak points",
          "The obvious inputs were hardened first, so look at the unglamorous ones",
          "Hidden parameters are disproportionately likely to be unreviewed"
        ]
      },
      {
        title: "What a Finding Is Actually Worth",
        icon: "fa-gem",
        content: [
          "Impact ranges enormously within this one bug class. Retrieving one extra row from one table is a real finding but a modest one. Reading arbitrary tables, including credentials or personal data, is severe. Writing to the database, reading files from the host, or achieving code execution through a stacked query is critical.",
          "The technique the tool used tells you roughly where on that scale you are. A blind technique proves the query is injectable but returns no data by itself. A UNION or error-based technique actually brings data back into the response. Time-based blind is the slowest and often the only one available, and it proves control without proving reach.",
          "Report what you proved, and stop escalating once impact is established. Enumerating a schema is usually enough to demonstrate severity; dumping a production customer table is not required and is very likely outside what the program authorised."
        ],
        keyPoints: [
          "Blind proves injectability; UNION and error-based prove data retrieval",
          "Time-based is slow and proves control without proving reach",
          "Schema enumeration is normally enough to establish severity",
          "Do not dump real customer data to prove a point"
        ]
      }
    ],
    practicalTips: [
      "Prioritise filters, sort parameters, search, and export options over login forms",
      "Include hidden parameters in your testing; they are less likely to have been reviewed",
      "Note the DBMS as soon as the tool fingerprints it, since it changes every subsequent payload",
      "Stop at proof of impact rather than mass extraction",
      "Test JSON bodies too, not only query strings, since NoSQL injection lives there",
      "Keep the raw request and response for the report; a technique name is not evidence"
    ],
    furtherReading: [
      {
        title: "PortSwigger - SQL Injection",
        url: "https://portswigger.net/web-security/sql-injection",
        description: "The complete free course with labs per technique"
      },
      {
        title: "OWASP SQL Injection Prevention Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        description: "The defences and therefore the gaps"
      }
    ]
  },

  urlSqliTools: {
    title: "sqlmap, Ghauri, and SQLiDetector",
    overview: "sqlmap is the exhaustive one, Ghauri is the fast one, and SQLiDetector is the cheap first pass. They disagree often, and the disagreements are informative rather than a sign one of them is broken.",
    sections: [
      {
        title: "Three Different Trade-offs",
        icon: "fa-scale-unbalanced",
        content: [
          "sqlmap is the most thorough SQL injection tool available. It supports a huge range of database systems and techniques, fingerprints the backend, and can escalate all the way to reading files and running commands where the configuration allows. The cost is time: a full run against many vectors takes hours, and its default settings deliberately test less than it is capable of.",
          "Ghauri covers the same core techniques with far less overhead and finishes dramatically faster. It is an excellent second opinion precisely because its internals differ, so a parameter one tool dismisses is sometimes confirmed by the other.",
          "SQLiDetector is not an exploitation tool at all. It sends payloads and matches database error signatures in the response. That makes it fast and useful as a first sweep, but an error signature only means the application surfaced a database exception, which many applications do for entirely non-injectable reasons."
        ],
        keyPoints: [
          "sqlmap: most thorough, slowest, escalates furthest",
          "Ghauri: same core techniques, much faster, good second opinion",
          "SQLiDetector: error-signature matching, a first pass not a confirmation",
          "Disagreement between them is normal and worth investigating"
        ]
      },
      {
        title: "Two Traps That Report Clean",
        icon: "fa-triangle-exclamation",
        content: [
          "The first is the session cache. Ghauri caches results keyed by host, so a second run against the same host can return instantly with the cached verdict from the first run, including a verdict produced by a broken earlier configuration. Unless the cache is flushed, you are reading history rather than a scan. This framework now forces a flush on every run; if you run these tools by hand, do it yourself.",
          "The second is the rejected option. These tools validate their arguments and exit before sending anything if one is wrong. A fractional value for an option that only accepts whole seconds is enough. During this project that produced 53 vectors reported clean in forty seconds having sent zero requests, against a target with confirmed SQL injection.",
          "Both traps share one signature: a scan that completes far faster than the work would take. Treat suspicious speed as the primary warning sign, because the finding count will look identical either way."
        ],
        keyPoints: [
          "Flush the session cache or you may be reading an old verdict",
          "A rejected option means the tool exited without sending a request",
          "Both look exactly like a fast clean scan",
          "Compare the runtime against the number of vectors as a sanity check"
        ]
      }
    ],
    practicalTips: [
      "Run SQLiDetector first as a cheap sweep, then the heavier tools on what it flags",
      "Always flush the session cache between runs, especially after changing settings",
      "Raise the level and risk settings deliberately when a vector looks promising rather than globally",
      "Mark the exact injection point when a request has several parameters",
      "Compare sqlmap and Ghauri on the same vector before dismissing a suspicious parameter",
      "Check runtime against vector count; a scan that finished too fast tested nothing"
    ],
    furtherReading: [
      {
        title: "sqlmap",
        url: "https://github.com/sqlmapproject/sqlmap",
        description: "The reference tool, with extensive documentation of its techniques"
      },
      {
        title: "Ghauri",
        url: "https://github.com/r0oth3x49/ghauri",
        description: "A faster alternative covering the same core techniques"
      }
    ]
  },

  urlSqliTechniques: {
    title: "Reading the Technique Behind a SQL Injection Finding",
    overview: "Every SQL injection finding names a technique, and that name tells you what was proved, how to reproduce it by hand, and how severe the finding actually is. This is how to read them.",
    sections: [
      {
        title: "The Five Techniques",
        icon: "fa-list-ol",
        content: [
          "Boolean-based blind injects a condition and watches whether the page changes between a true and a false version. It proves the query is under your control but returns no data directly; extracting anything means asking one yes-or-no question at a time. To reproduce it by hand you send both versions and show that the responses differ.",
          "UNION query appends a second SELECT so its results come back in the normal response. This is the strongest everyday result because data visibly crosses into the page. Error-based is similar in effect: it provokes a database error that contains the data you asked for, which requires the application to surface errors.",
          "Time-based blind makes the database sleep when a condition is true, so you read the answer from the response time. It is slow and noisy but it works when nothing is reflected at all. Stacked queries execute a second statement entirely, which is the most dangerous because it can write rather than only read."
        ],
        keyPoints: [
          "Boolean-based: page differs between true and false, no data returned directly",
          "UNION and error-based: data actually appears in the response",
          "Time-based: the answer is in the response time, slow but universal",
          "Stacked: a second statement runs, so writes become possible"
        ]
      },
      {
        title: "Reproducing and Reporting It",
        icon: "fa-flask-vial",
        content: [
          "A report that says a tool reported SQL injection is not evidence. What a triager needs is the request, the response, and the reasoning that connects them. For a boolean-based finding that means two requests side by side, one with a true condition and one with a false one, and a visible difference between the responses.",
          "For a time-based finding it means timings: a baseline request, a request with a sleep, and the measured difference, ideally repeated so it is clearly not network jitter. For UNION or error-based it means the data itself appearing in the response, redacted if it is real personal information.",
          "Add the database fingerprint if the tool determined one. Naming the backend correctly shows the finding is understood rather than copied out of a scanner, and it helps the recipient reproduce it on their own systems."
        ],
        keyPoints: [
          "Show two requests and the difference, not the tool's verdict",
          "For time-based, show repeated timings so jitter is ruled out",
          "Redact real data while still proving retrieval",
          "Name the database if it was fingerprinted"
        ]
      }
    ],
    practicalTips: [
      "Reproduce by hand before reporting; a tool name is not a proof of concept",
      "For boolean-based, pick a condition whose true and false forms differ obviously",
      "For time-based, repeat the measurement at least three times",
      "Redact personal data in evidence but keep enough to show it was retrieved",
      "Mention the technique explicitly, since it determines the severity",
      "If two tools disagree, test the disputed vector by hand rather than averaging them"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Blind SQL Injection",
        url: "https://portswigger.net/web-security/sql-injection/blind",
        description: "How to extract data when nothing comes back directly"
      },
      {
        title: "OWASP WSTG - Testing for SQL Injection",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection",
        description: "The manual methodology behind what the tools automate"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Command Injection and SSTI
  // ---------------------------------------------------------------------------------------------
  urlCmdiMethodology: {
    title: "Command Injection and Template Injection: Straight to Execution",
    overview: "These two classes are grouped because they share an outcome. Command injection runs your input as a shell command; server-side template injection runs it as template code that usually reaches the same place. Both mean code execution on the server, which is the top of the severity scale.",
    sections: [
      {
        title: "Where They Come From",
        icon: "fa-terminal",
        content: [
          "Command injection appears wherever an application shells out. Converting an image, generating a PDF, pinging a host, resolving DNS, extracting an archive, running a network diagnostic, calling a command-line utility because there was no library: each of these builds a command string, and if user input reaches that string unescaped the shell will happily treat it as more command.",
          "Template injection appears when user input is used to build a template rather than being passed into one as data. The classic case is a customisable email or a rendered error message where the developer concatenated a name into the template source. Modern template engines are powerful enough that reaching the template language usually means reaching the runtime behind it.",
          "Both are much rarer than injection into a database, and both are worth far more when found. They are also the two classes where a careless payload can genuinely damage a target, so the payloads you choose matter."
        ],
        keyPoints: [
          "Command injection follows anything that shells out to a utility",
          "Template injection follows input used to build a template rather than fill one",
          "Both usually mean code execution on the server",
          "Rarer than SQL injection and considerably more valuable"
        ]
      },
      {
        title: "Testing Without Breaking Anything",
        icon: "fa-shield-halved",
        content: [
          "The safe proof for command injection is a delay or a callback, not a destructive command. A sleep proves the shell ran your input and costs the target a few seconds. A DNS or HTTP callback to a collector you control proves it and gives you a timestamped record. Neither reads anything sensitive nor changes anything.",
          "For template injection the safe proof is arithmetic. A payload that makes the template evaluate a simple sum and return the answer proves you reached the template engine, because a plain string would come back unchanged. Once that works, identifying which engine it is tells you how far the injection reaches.",
          "Never use a destructive command as a proof of concept, and never read files unrelated to the demonstration. Sleep, echo, arithmetic, and callbacks are enough to establish critical severity, and they keep the engagement inside what the program authorised."
        ],
        keyPoints: [
          "Prove command injection with a sleep or an out-of-band callback",
          "Prove template injection with arithmetic that returns a computed answer",
          "Identify the engine before escalating further",
          "Destructive payloads are never necessary and are frequently out of scope"
        ]
      }
    ],
    practicalTips: [
      "Focus on parameters that name a host, a file, a format, or a command",
      "Try shell metacharacters one at a time so you can tell which one survives filtering",
      "Set up an out-of-band collector before scanning; blind cases are common here",
      "Use arithmetic as the first template payload, since it is unambiguous and harmless",
      "Stop escalating once you have proved execution; the severity is already maximal",
      "Be careful with sleeps on production systems, and keep them short"
    ],
    furtherReading: [
      {
        title: "PortSwigger - OS Command Injection",
        url: "https://portswigger.net/web-security/os-command-injection",
        description: "Including the blind cases and how to detect them safely"
      },
      {
        title: "PortSwigger - Server-Side Template Injection",
        url: "https://portswigger.net/web-security/server-side-template-injection",
        description: "Engine identification and exploitation per engine"
      }
    ]
  },

  urlCmdiTools: {
    title: "Commix, SSTImap, and TInjA",
    overview: "Commix automates command injection, SSTImap automates template injection with exploitation, and TInjA detects and identifies the template engine. They are only useful on vectors that could plausibly reach a shell or a template, so vector selection matters more here than in most sections.",
    sections: [
      {
        title: "What Each One Is For",
        icon: "fa-toolbox",
        content: [
          "Commix specialises in command injection. It tries a wide range of separators, encodings, and injection styles, handles both result-based and blind cases, and can escalate to an interactive pseudo-terminal once it succeeds. It also has a session cache that will return an old verdict on a repeat run, so a flush belongs in every invocation.",
          "SSTImap detects template injection and then exploits it, identifying the engine and offering file read and code execution where the engine allows it. It covers the common Python, Ruby, Java, and JavaScript engines.",
          "TInjA is the detection specialist. It focuses on working out whether a template engine is reachable and which one it is, across a large set of engines. It is quicker than SSTImap and a good first pass, with SSTImap following up on whatever it flags."
        ],
        keyPoints: [
          "Commix: command injection, broad payload coverage, can escalate to a shell",
          "SSTImap: template injection detection plus exploitation per engine",
          "TInjA: fast engine detection, a good first pass before SSTImap",
          "Flush caches between runs or you will re-read an old verdict"
        ]
      },
      {
        title: "Not Every Vector Is Eligible",
        icon: "fa-filter",
        content: [
          "These tools cannot meaningfully test every attack vector, and running them everywhere wastes hours. A parameter that only ever holds a numeric page index is not going to reach a shell. The vectors worth spending time on are the ones whose names or values suggest a filename, a hostname, a command, a format, a template, or a rendered message.",
          "Header vectors need particular care. Only certain headers plausibly reach a shell or a template, so a section that reports clean across every header is often reporting that nothing eligible was tested rather than that the headers are safe.",
          "This is the section where reading the skipped list matters as much as reading the findings. A vector that was skipped was not tested, and a skipped vector is not a clean vector."
        ],
        keyPoints: [
          "Numeric and enum parameters rarely reach a shell or a template",
          "Prioritise parameters naming files, hosts, commands, formats, or templates",
          "Only some headers are plausible carriers",
          "Read the skipped list; skipped is not clean"
        ]
      }
    ],
    practicalTips: [
      "Select vectors deliberately rather than running these across everything",
      "Configure an out-of-band collector first, since blind command injection is common",
      "Run TInjA before SSTImap to narrow down where to spend the expensive scan",
      "Flush the session cache on every run",
      "Keep sleeps short, and avoid running them repeatedly against production",
      "Check the skipped list to understand what a clean result actually covered"
    ],
    furtherReading: [
      {
        title: "Commix",
        url: "https://github.com/commixproject/commix",
        description: "Automated command injection with blind support"
      },
      {
        title: "SSTImap",
        url: "https://github.com/vladko312/SSTImap",
        description: "Template injection detection and exploitation"
      }
    ]
  },

  urlCmdiValidation: {
    title: "Confirming Execution Rather Than Coincidence",
    overview: "Both of these classes are usually detected by a side effect: a delay, a callback, or a computed value. Each of those has an innocent explanation, so confirming the finding means ruling the innocent explanation out.",
    sections: [
      {
        title: "Ruling Out the Boring Explanation",
        icon: "fa-stopwatch",
        content: [
          "A slow response is the weakest of the three signals, because applications are slow for many reasons. To turn a delay into evidence, vary it. If a five second sleep produces a five second delay and a ten second sleep produces a ten second delay, and a request without the payload returns promptly, the delay is under your control and that is the finding. A single slow response is not.",
          "A callback is the strongest signal, because a request arriving at a host you own from the target's infrastructure has no innocent explanation. Use a unique identifier per test so you can tell which vector caused which callback, and record the source address and timestamp.",
          "A computed value is the cleanest proof for template injection. If the response contains the result of arithmetic you sent rather than the arithmetic itself, something evaluated it. Make the operands unusual so the result cannot appear by chance."
        ],
        keyPoints: [
          "Vary the sleep duration and show the delay tracks it",
          "Always take a no-payload baseline for timing comparisons",
          "A callback from the target's infrastructure has no innocent explanation",
          "Use unusual operands so a computed result cannot be a coincidence"
        ]
      },
      {
        title: "How These Scans Report Nothing",
        icon: "fa-ghost",
        content: [
          "There are three ways to get a clean result here that means nothing. Every eligible vector was skipped, so the scan tested an empty list. The tool returned a cached verdict from a previous run rather than scanning. Or the tool refused its command line and exited before sending anything.",
          "All three produce the same visible outcome: a completed scan with no findings. The distinguishing signals are the runtime, the number of vectors actually attempted, and the skipped list. A section that reports clean across twenty vectors in ten seconds did not test twenty vectors.",
          "Out-of-band findings have their own version of this. If the collector was not configured, or the target cannot reach it, a blind command injection produces no callback and therefore no finding. That is a limitation of the setup, not a property of the target."
        ],
        keyPoints: [
          "Skipped, cached, and refused all look identical to clean",
          "Compare runtime against the number of vectors as a sanity check",
          "A missing collector turns every blind case into a silent clean",
          "Confirm the collector is reachable before trusting an out-of-band clean result"
        ]
      }
    ],
    practicalTips: [
      "Take a baseline timing before every timing-based test",
      "Repeat timing tests at least three times to rule out network variance",
      "Use a unique callback identifier per vector so attribution is unambiguous",
      "Test that your collector is reachable from the target before relying on it",
      "Record the callback source address; it often reveals internal infrastructure",
      "Report the safe proof, not an escalation you did not need"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Testing for Command Injection",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/12-Testing_for_Command_Injection",
        description: "The manual methodology and safe proofs"
      },
      {
        title: "PortSwigger - Blind OS Command Injection",
        url: "https://portswigger.net/web-security/os-command-injection#blind-os-command-injection-vulnerabilities",
        description: "Detecting execution when nothing comes back in the response"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Local File Inclusion
  // ---------------------------------------------------------------------------------------------
  urlLfiMethodology: {
    title: "Local File Inclusion and Path Traversal",
    overview: "If a parameter names a file and the application does not constrain where that name can point, you can read files the application never meant to serve. On some stacks the same bug becomes code execution, which is why it is worth chasing beyond the first configuration file you retrieve.",
    sections: [
      {
        title: "Reading Versus Including",
        icon: "fa-file-lines",
        content: [
          "Path traversal is the read case: the application opens the file you named and sends it back. Traversal sequences walk out of the intended directory and into the rest of the filesystem. What you get is disclosure, which is valuable when the file contains credentials, configuration, source code, or keys.",
          "File inclusion is the execution case. On stacks where naming a file causes it to be interpreted rather than merely read, PHP being the classic example, controlling the filename can mean controlling what code runs. That turns a disclosure bug into remote code execution and changes the severity completely.",
          "The distinction matters when you are deciding how far to push. On a stack where inclusion executes, it is worth establishing whether execution is reachable. On a stack where it only reads, the finding is the disclosure and the useful next step is finding the most sensitive file you can reach."
        ],
        keyPoints: [
          "Traversal reads; inclusion can execute",
          "PHP is the classic stack where inclusion means execution",
          "Severity depends on which of the two you are dealing with",
          "On a read-only stack, impact comes from which file you reach"
        ]
      },
      {
        title: "Where the Parameters Are",
        icon: "fa-signs-post",
        content: [
          "The obvious names are file, path, page, template, document, doc, folder, and view. Beyond names, look at behaviour: any endpoint that downloads, exports, previews, renders, or attaches something is naming a file somewhere, even if the parameter is called id.",
          "Language and theme selectors are a frequently missed case, because they map a short user-supplied string onto a file path and are rarely thought of as file handling at all. Log viewers, backup downloaders, and report exporters are others.",
          "Filters are common and often incomplete. An application that strips one level of traversal can be defeated by nesting; one that appends an extension can sometimes be defeated by a null byte on older stacks; one that blocks a literal sequence may miss its encoded form. The tools in this section try these systematically, which is their main advantage over manual testing."
        ],
        keyPoints: [
          "Look for names like file, path, page, template, and doc",
          "Anything that downloads, exports, previews, or renders names a file",
          "Language and theme selectors map user input onto paths",
          "Filters are usually incomplete rather than absent"
        ]
      }
    ],
    practicalTips: [
      "Start with a file that certainly exists and is harmless to read as your probe",
      "Try encoded and double-encoded traversal when the plain form is filtered",
      "Test both directions: absolute paths as well as relative traversal",
      "On PHP, remember that wrappers can turn a read into something more",
      "Read what you retrieve; configuration files often contain credentials for other systems",
      "Do not retrieve customer data to prove the point when a configuration file will do"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Path Traversal",
        url: "https://portswigger.net/web-security/file-path-traversal",
        description: "Traversal with labs covering the common filters and bypasses"
      },
      {
        title: "PortSwigger - File Upload and Inclusion",
        url: "https://portswigger.net/web-security/file-upload",
        description: "Where inclusion becomes execution"
      }
    ]
  },

  urlLfiTools: {
    title: "LFImap and LFIHunt",
    overview: "Both automate the same idea, sending traversal and inclusion payloads and looking for signs a file came back, but they differ in coverage and in how they are driven. Their most important shared property is that a badly formed target URL makes both report nothing.",
    sections: [
      {
        title: "The Two Tools",
        icon: "fa-toolbox",
        content: [
          "LFImap is the broader of the two. It covers traversal, PHP wrappers, remote inclusion, and log-poisoning routes to execution, and it tries a wide set of filter bypasses automatically. It is the better default when you want coverage.",
          "LFIHunt is more focused and includes a batch mode that is not obvious from its main interface, which makes it useful across many vectors at once. It overlaps heavily with LFImap on plain traversal and diverges on the more exotic techniques.",
          "Neither tool understands your application. They will test whatever parameter they are pointed at, so the value you get is largely determined by whether you pointed them at parameters that plausibly name a file."
        ],
        keyPoints: [
          "LFImap: wider technique coverage including wrappers and log poisoning",
          "LFIHunt: focused, with a batch mode worth using across many vectors",
          "They overlap on plain traversal and differ on exotic techniques",
          "Neither understands context; vector selection is your job"
        ]
      },
      {
        title: "The Query String Trap",
        icon: "fa-link-slash",
        content: [
          "The most common way to get a worthless clean result here is a malformed target URL. If the parameter under test is not correctly marked, or the query string is assembled wrongly, the tool sends payloads to the wrong place and correctly reports that nothing came back. During this project a query-string handling bug did exactly that and it affected every section that shared the same code path, not just this one.",
          "The symptom is a uniform clean result across vectors that should behave differently. Real applications are inconsistent; when every single vector returns exactly the same verdict in exactly the same way, suspect the harness rather than the target.",
          "The check is to take one vector, run the tool's own command by hand with a payload you know should produce a visible difference, and confirm the request went where you expected. One manual run is usually enough to expose the problem."
        ],
        keyPoints: [
          "A malformed target URL sends payloads nowhere and reports clean",
          "Uniform results across dissimilar vectors indicate a harness problem",
          "Run one vector by hand to confirm requests land where you expect",
          "This class of bug affects every section sharing the code path"
        ]
      }
    ],
    practicalTips: [
      "Point these tools only at parameters that plausibly name a file",
      "Verify one vector by hand before trusting a whole clean section",
      "Use LFIHunt's batch mode when you have many candidate vectors",
      "Try both tools on a promising vector, since their technique coverage differs",
      "Watch for uniform results across dissimilar vectors as a sign of a configuration problem",
      "Check the skipped list, since a skipped vector is untested rather than clean"
    ],
    furtherReading: [
      {
        title: "LFImap",
        url: "https://github.com/hansmach1ne/LFImap",
        description: "Local and remote file inclusion scanner"
      },
      {
        title: "OWASP WSTG - Testing for Local File Inclusion",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion",
        description: "The manual methodology behind the automation"
      }
    ]
  },

  urlLfiValidation: {
    title: "Proving a File Was Actually Read",
    overview: "An LFI finding is only convincing if the response demonstrably contains file content the application would never have served. This is how to establish that cleanly, and how to judge the impact once you have.",
    sections: [
      {
        title: "Evidence That Holds Up",
        icon: "fa-file-shield",
        content: [
          "The proof is content, not a status code. A 200 response proves the endpoint answered; it says nothing about what it answered with. What you want is recognisable file content in the response body that the application has no legitimate reason to include, together with the baseline response for the same endpoint without the traversal so the difference is obvious.",
          "Choose your demonstration file carefully. Something universally present and entirely uninteresting makes the cleanest proof of concept, because it establishes the vulnerability without exposing anything sensitive in your report. Prove the capability first, then assess reach separately.",
          "Once the capability is proved, the impact question is which files are reachable. Application configuration is usually the highest-value target because it tends to hold database credentials, API keys, and secrets for other systems, which is how a file read becomes a much larger finding."
        ],
        keyPoints: [
          "The evidence is recognisable file content, not a status code",
          "Always include the baseline response for comparison",
          "Use a harmless well-known file for the proof of concept",
          "Assess impact by which files are reachable, especially configuration"
        ]
      },
      {
        title: "Escalation and Restraint",
        icon: "fa-hand",
        content: [
          "On a stack where inclusion executes, it is legitimate to establish whether execution is reachable, because that changes the severity from high to critical and the program needs to know. Establish it, document it, and stop.",
          "Restraint matters more here than in most classes because file read is trivially over-exploitable. Reading a configuration file to demonstrate impact is proportionate; walking the filesystem, retrieving customer data, or pulling private keys is not, and it will usually breach the program's rules.",
          "If what you retrieve contains live credentials, do not use them. Note in the report that they were exposed, redact them in your evidence, and let the program rotate them. Using recovered credentials is a separate act that almost no program authorises."
        ],
        keyPoints: [
          "Establishing that execution is reachable is worth doing, then stop",
          "Configuration files demonstrate impact proportionately",
          "Do not walk the filesystem or retrieve personal data",
          "Never use credentials you recover; report them redacted"
        ]
      }
    ],
    practicalTips: [
      "Show the baseline and the traversal response side by side",
      "Pick a harmless well-known file for the proof of concept",
      "Redact any secret you happen to retrieve, and say that you have",
      "Note the operating system, since it changes which paths are worth trying",
      "If the response is truncated, say so, since partial content is still proof",
      "Stop at proof of impact rather than demonstrating everything you could reach"
    ],
    furtherReading: [
      {
        title: "OWASP - Path Traversal",
        url: "https://owasp.org/www-community/attacks/Path_Traversal",
        description: "The attack, its variants, and its defences"
      }
    ]
  }
};
