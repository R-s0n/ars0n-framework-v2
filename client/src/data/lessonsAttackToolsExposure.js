// Lessons for the attack tool sections about things the target exposes rather than things you
// inject: GraphQL, sensitive data leaks, exposed git directories, and the miscellaneous section
// (file upload bypass, JWT analysis, prototype pollution). Merged into the main lessons export.

export const attackToolsExposureLessons = {
  // ---------------------------------------------------------------------------------------------
  // GraphQL
  // ---------------------------------------------------------------------------------------------
  urlGraphqlMethodology: {
    title: "GraphQL: One Endpoint, A Very Different Attack Surface",
    overview: "A GraphQL API puts the whole schema behind a single endpoint and lets the caller compose the query. That collapses the usual per-endpoint testing model and creates a set of problems REST APIs do not have, starting with the fact that the API will often describe itself to you on request.",
    sections: [
      {
        title: "Why the Usual Model Does Not Apply",
        icon: "fa-project-diagram",
        content: [
          "In a REST API each route is a separate thing to find and a separate thing to protect, and your job as a tester starts with enumerating routes. In GraphQL there is usually one route, and what varies is the query sent to it. Enumerating paths tells you almost nothing; enumerating the schema tells you everything.",
          "That changes where the bugs are. Authorization is the biggest one: the resolver for each field has to make its own access decision, and it is very easy for a developer to protect a top-level query while leaving a nested field that reaches the same data unguarded. A query that walks from an object you may see to a related object you may not is the archetypal GraphQL access-control bug.",
          "Availability is the second. Because the caller composes the query, the caller decides how expensive it is. Deeply nested queries, recursive relationships, and large batched requests let a single request cost the server far more than the client, which is why query depth and complexity limits exist and why their absence is a finding."
        ],
        keyPoints: [
          "One endpoint, so route enumeration is replaced by schema enumeration",
          "Every field needs its own authorization check and often does not have one",
          "Nested fields frequently bypass protection applied at the top level",
          "The caller controls query cost, which makes denial of service cheap"
        ]
      },
      {
        title: "Introspection Is the Front Door",
        icon: "fa-door-open",
        content: [
          "GraphQL includes a standard mechanism for asking the server to describe its own schema. When introspection is enabled you can retrieve every type, field, argument, mutation, and deprecation note in one request, which hands you the complete map of the API including the parts no client uses.",
          "That is not automatically a vulnerability, and plenty of public APIs enable it deliberately. It matters because of what it accelerates: internal mutations, administrative fields, and deprecated operations that were never removed all become visible immediately, and each of those is a testing lead.",
          "When introspection is disabled, the schema is not secret so much as inconvenient. Field names can be recovered by guessing against the server's own suggestion messages, which is what one of the tools in this section automates. Treat a disabled introspection endpoint as a speed bump rather than a control."
        ],
        keyPoints: [
          "Introspection returns the full schema in a single request",
          "It exposes internal, administrative, and deprecated operations",
          "Enabled introspection is a lead multiplier, not automatically a finding",
          "Disabled introspection can still be recovered field by field"
        ]
      }
    ],
    practicalTips: [
      "Try introspection first; if it works, read the mutation list before anything else",
      "Look for nested paths that reach data the top-level query protects",
      "Test every mutation you find, since mutations change state and are often less reviewed",
      "Check for depth and complexity limits by nesting a query deliberately",
      "Watch error messages, which frequently suggest valid field names",
      "Aliases let you repeat an operation many times in one request, which matters for rate limits"
    ],
    furtherReading: [
      {
        title: "PortSwigger - GraphQL API Vulnerabilities",
        url: "https://portswigger.net/web-security/graphql",
        description: "Introspection, suggestions, and access control with labs"
      },
      {
        title: "OWASP GraphQL Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
        description: "The defences, and therefore the checklist"
      }
    ]
  },

  urlGraphqlTools: {
    title: "graphql-cop, Clairvoyance, and graphw00f",
    overview: "graphw00f identifies the engine, graphql-cop audits the endpoint for common misconfigurations, and Clairvoyance rebuilds a schema when introspection is switched off. They run against endpoints rather than parameters, so the endpoint list is what determines coverage.",
    sections: [
      {
        title: "Fingerprint, Audit, Recover",
        icon: "fa-toolbox",
        content: [
          "graphw00f fingerprints the server implementation. That matters more than it sounds, because implementations differ substantially in which protections they apply by default, how they handle batching, what their error messages reveal, and which known issues apply. Knowing the engine turns a generic checklist into a specific one.",
          "graphql-cop runs a set of audit checks against the endpoint: whether introspection is available, whether the server accepts GET for mutations, whether batching is allowed, whether field suggestions leak names, and similar. It is fast and it is the best first pass on a newly discovered endpoint.",
          "Clairvoyance is the recovery tool. When introspection is disabled it uses the server's own suggestion messages to work out valid field names and rebuilds an approximate schema. It is slower and noisier than introspection but it turns a closed door into an inconvenience."
        ],
        keyPoints: [
          "graphw00f: engine identification, which narrows every later check",
          "graphql-cop: fast misconfiguration audit, the natural first pass",
          "Clairvoyance: schema recovery when introspection is disabled",
          "All three work per endpoint, so the endpoint list determines coverage"
        ]
      },
      {
        title: "Reading the Results Carefully",
        icon: "fa-magnifying-glass",
        content: [
          "Audit tools in this space have a tendency to report a known issue against an engine on the basis of a fingerprint rather than on the basis of a test. A claim that a specific published vulnerability is present should be treated as a hypothesis about the version, and confirmed independently before it goes anywhere near a report.",
          "Denial of service checks are usually excluded by default and should stay excluded unless the program explicitly permits them, because the test is the attack. Note that these exclusions are matched by name, so a checklist entry that is spelled differently will not be caught by the exclusion.",
          "Finally, remember that a misconfiguration is not always a vulnerability. Introspection enabled on a public API that documents its schema anyway is a note, not a finding. What matters is what it exposes that was not meant to be exposed."
        ],
        keyPoints: [
          "A version-based vulnerability claim needs independent confirmation",
          "Denial of service checks are the attack; leave them off unless permitted",
          "Exclusions match by name, so a differently spelled check slips through",
          "Introspection on a documented public API is a note, not a finding"
        ]
      }
    ],
    practicalTips: [
      "Find the endpoint first; it is often at a conventional path but not always",
      "Run graphw00f before the others so the audit is interpreted in context",
      "Confirm any version-based claim yourself before reporting it",
      "Keep denial of service checks disabled unless the program allows them",
      "If introspection is off, try Clairvoyance rather than assuming the schema is hidden",
      "Test mutations by hand once the schema is known; that is where the impact is"
    ],
    furtherReading: [
      {
        title: "graphw00f",
        url: "https://github.com/dolevf/graphw00f",
        description: "GraphQL engine fingerprinting"
      },
      {
        title: "Clairvoyance",
        url: "https://github.com/nikitastupin/clairvoyance",
        description: "Schema recovery without introspection"
      }
    ]
  },

  urlGraphqlValidation: {
    title: "Turning a GraphQL Misconfiguration Into a Finding",
    overview: "Most GraphQL scan output is configuration observations. This lesson is about which of those actually matter and how to develop one into something with demonstrated impact.",
    sections: [
      {
        title: "From Observation to Impact",
        icon: "fa-arrow-trend-up",
        content: [
          "Introspection enabled is an observation. Introspection enabled plus a mutation that lets a standard user change another user's role is a finding, and the second half is the part that requires you rather than the tool. The path from one to the other is reading the schema and testing the operations it reveals.",
          "Start with mutations, since they change state and are consistently less reviewed than queries. Then look for fields that reach across ownership boundaries: a query for your own object that exposes a nested user, organisation, or payment object is the classic shape. Then check whether the same nested route works with an identifier belonging to someone else.",
          "For availability findings, demonstrate cost rather than damage. Showing that a modestly nested query takes many seconds establishes that no complexity limit exists, without needing to take anything down."
        ],
        keyPoints: [
          "A configuration observation is the start of the work, not the end",
          "Mutations first; they change state and get less review",
          "Look for nested fields that cross an ownership boundary",
          "For cost issues, demonstrate expense rather than causing an outage"
        ]
      },
      {
        title: "Evidence That Travels",
        icon: "fa-file-code",
        content: [
          "A GraphQL report should contain the exact query, the exact response, and the identity the query was sent as. Because everything happens at one endpoint, the query text is the whole proof of concept, and a report that describes it in prose rather than quoting it is hard to act on.",
          "Where the finding is an access-control problem, include both sides: the query as the authorised user and the same query as the unauthorised one, so the difference is visible. Redact the actual personal data while leaving the structure intact.",
          "Say which engine it is if graphw00f identified it. Implementation matters for the fix, and it demonstrates that the finding was investigated rather than copied from a scanner summary."
        ],
        keyPoints: [
          "Quote the exact query and response; the query is the proof of concept",
          "For access control, show the same query under two identities",
          "Redact personal data while keeping the structure visible",
          "Name the engine, since it affects the remediation"
        ]
      }
    ],
    practicalTips: [
      "Retrieve the schema first, then read the mutations before anything else",
      "Test nested field access with another account's identifier",
      "Use aliases to check whether rate limiting counts requests or operations",
      "Demonstrate query cost with timings rather than by causing an outage",
      "Quote queries verbatim in the report",
      "Check whether GET is accepted for mutations, since that enables cross-site request forgery"
    ],
    furtherReading: [
      {
        title: "PortSwigger - Working with GraphQL",
        url: "https://portswigger.net/web-security/graphql/what-is-graphql",
        description: "The mechanics you need in order to write the proof of concept"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Sensitive Data Leaks
  // ---------------------------------------------------------------------------------------------
  urlSensitiveLeakMethodology: {
    title: "Sensitive Data Leaks and Exposed Secrets",
    overview: "This section looks for things the target published without meaning to: files left on the web root, secrets committed into JavaScript, credentials in configuration. There is no injection involved, which is what makes these findings so easy to confirm and so easy to over-claim.",
    sections: [
      {
        title: "Three Ways Things Leak",
        icon: "fa-faucet-drip",
        content: [
          "Files get left where the web server will serve them. Backups, database dumps, editor swap files, deployment archives, version control metadata, and configuration files with the wrong extension all end up publicly readable because the deployment copied a directory rather than a build.",
          "Secrets get compiled into client-side code. Anything the browser needs, the browser has, and developers routinely embed API keys, tokens, and internal endpoints in JavaScript on the assumption that minification hides them. It does not; it makes them slightly less legible.",
          "Data gets returned by APIs that send more than the interface displays. An endpoint that returns a full user object so the page can show a display name is handing out email addresses, roles, internal identifiers, and sometimes password hashes to anyone who reads the response rather than the rendered page."
        ],
        keyPoints: [
          "Files left in the web root by a directory-copy deployment",
          "Secrets embedded in client-side JavaScript, where minification hides nothing",
          "APIs returning more fields than the interface renders",
          "None of these require an attack, only that you look"
        ]
      },
      {
        title: "Not Every Secret Is a Finding",
        icon: "fa-scale-balanced",
        content: [
          "Client-side code legitimately contains keys that are meant to be public. Analytics identifiers, publishable payment keys, map tokens, and public application identifiers are all designed to be visible, and reporting one as a leaked credential is a well-known way to waste a triager's time.",
          "What determines whether a key matters is what it can do. A key that only identifies the application is a note; a key that can read data, spend money, or act on behalf of the account is a finding. The distinction is about capability, not about whether the string looks secret.",
          "The same applies to files. An exposed configuration file with no secrets in it is a hardening issue. The same file containing a live database password is critical. Read what you find before deciding what it is worth."
        ],
        keyPoints: [
          "Many client-side keys are public by design",
          "Capability decides severity, not appearance",
          "Read the file rather than reporting its existence",
          "A key that identifies is a note; a key that acts is a finding"
        ]
      }
    ],
    practicalTips: [
      "Read the JavaScript rather than only running a scanner over it",
      "Check whether a discovered key is a publishable one before reporting it",
      "Compare API responses against what the interface shows, field by field",
      "Look for backup and archive extensions on paths you already know",
      "Note the deployment pattern; one exposed file usually means others",
      "Never use a credential you find, and say in the report that you did not"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Review Webpage Content for Information Leakage",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/05-Review_Webpage_Content_for_Information_Leakage",
        description: "Systematically reading what the client already has"
      },
      {
        title: "OWASP Secrets Management Cheat Sheet",
        url: "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html",
        description: "How secrets should be handled, which explains how they escape"
      }
    ]
  },

  urlSensitiveLeakTools: {
    title: "snallygaster, Mantra, and TruffleHog",
    overview: "snallygaster probes for files that should not be served, Mantra reads JavaScript for embedded credentials, and TruffleHog matches and verifies secret patterns. They complement each other because they look in three different places.",
    sections: [
      {
        title: "Three Different Places to Look",
        icon: "fa-toolbox",
        content: [
          "snallygaster works on the server side. It requests a long list of paths that indicate a misconfigured deployment, covering version control metadata, backups, core dumps, configuration files, editor artefacts, and framework debug endpoints. It is fast per host and its value comes from the breadth of its list rather than any cleverness.",
          "Mantra works on the client side. It reads JavaScript files and hunts for embedded credentials and tokens, which is where the modern version of this problem mostly lives now that so much application logic ships to the browser.",
          "TruffleHog is the pattern matcher, and its distinguishing feature is verification: for many providers it can actually check whether a discovered credential is live. That single capability separates a real finding from a string that merely matches a regular expression, and it is the difference between a report a triager accepts immediately and one they close."
        ],
        keyPoints: [
          "snallygaster: server-side file exposure across a broad path list",
          "Mantra: credentials embedded in client-side JavaScript",
          "TruffleHog: pattern matching with live verification for many providers",
          "Verification is what converts a match into a finding"
        ]
      },
      {
        title: "How These Scans Under-Report",
        icon: "fa-ghost",
        content: [
          "These tools take directory prefixes and file paths as their targets rather than parameters, so the quality of the input list determines coverage completely. Point them only at the site root and they check the site root. Applications deployed under a path prefix will look clean while their real directory is untested.",
          "Secret detection is also bounded by its pattern library. A credential in a format nobody has written a rule for will not be found, which is a particular problem for internal and bespoke systems. Reading the JavaScript yourself remains worthwhile even after a clean scan.",
          "Finally, a verified-live check that fails is not the same as a credential that is not live. Network restrictions, rate limits, and providers with no verification support all produce an unverified result for a perfectly valid key."
        ],
        keyPoints: [
          "Coverage is entirely determined by the directory list you supply",
          "Applications under a path prefix are missed if only the root is scanned",
          "A bespoke credential format will not match any pattern library",
          "Unverified does not mean invalid"
        ]
      }
    ],
    practicalTips: [
      "Feed the directory prefixes you discovered, not only the site root",
      "Read the JavaScript by hand as well; pattern libraries miss bespoke formats",
      "Prefer verified findings when triaging, but do not dismiss unverified ones outright",
      "Check the age of any exposed file; old backups often predate current security controls",
      "Report a live credential immediately, since exposure is ongoing",
      "Do not use a credential to prove it works when the tool has already verified it"
    ],
    furtherReading: [
      {
        title: "snallygaster",
        url: "https://github.com/hannob/snallygaster",
        description: "Scanner for files that should not be publicly served"
      },
      {
        title: "TruffleHog",
        url: "https://github.com/trufflesecurity/trufflehog",
        description: "Secret detection with live credential verification"
      }
    ]
  },

  urlSensitiveLeakValidation: {
    title: "Confirming a Leak Without Making It Worse",
    overview: "These findings are trivially confirmable and correspondingly easy to over-exploit. The line between demonstrating a leak and helping yourself to what leaked is the thing to get right.",
    sections: [
      {
        title: "Establish Access, Then Stop",
        icon: "fa-hand",
        content: [
          "For an exposed file the confirmation is a single unauthenticated request that returns the content. Record the request, the status, and enough of the response to show what it is. That is the finding complete; downloading an entire database dump is not required to prove a database dump is downloadable.",
          "For a credential, the confirmation is knowing what it can do, not doing it. If a verification check has already established the key is live, quote that. If it has not, describe the key's apparent scope from where it was found rather than exercising it, because using someone's credential is a separate action that programs almost never authorise.",
          "For an over-sharing API, the confirmation is the response body with the extra fields visible, next to the interface that does not display them. Redact real values while leaving the field names intact, since the field names are the finding."
        ],
        keyPoints: [
          "One unauthenticated request that returns the content is enough",
          "Do not download bulk data to prove it is downloadable",
          "Describe a credential's scope rather than exercising it",
          "For over-sharing APIs, the field names are the finding"
        ]
      },
      {
        title: "Handling What You Find",
        icon: "fa-lock",
        content: [
          "If you retrieve something containing real personal data, stop reading it. Note what categories of data were present, redact the specifics, and say clearly in the report that you did not retain a copy. That last sentence matters both legally and for the program's own incident handling.",
          "Live credentials should be reported with urgency rather than sat on while you explore further. An exposed key is being exposed to everyone else at the same time, and the window between your discovery and the rotation is a window in which someone less careful may find it.",
          "Delete what you downloaded once the report is filed, and say that you have. A report that ends with a clear statement about what was accessed, what was retained, and what was destroyed is far easier for a program to close."
        ],
        keyPoints: [
          "Note the categories of data, redact the specifics, retain nothing",
          "Report live credentials immediately rather than exploring further",
          "Delete downloaded material and say so",
          "Clear handling statements make the report easier to accept"
        ]
      }
    ],
    practicalTips: [
      "Confirm with an unauthenticated request from a clean session",
      "Capture enough of the file to identify it, not all of it",
      "Redact secrets in evidence but show enough structure to identify the type",
      "Report live credentials as urgent, ahead of the rest of your findings",
      "State explicitly what you accessed, retained, and deleted",
      "Check whether the same misconfiguration exposes other files on the same host"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Testing for Old Backup and Unreferenced Files",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
        description: "The methodical version of what snallygaster automates"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Exposed Git Directories
  // ---------------------------------------------------------------------------------------------
  urlExposedGitMethodology: {
    title: "Exposed Git Directories: The Whole Repository in Public",
    overview: "When a deployment copies a working directory rather than building from one, the version control metadata comes along. If the web server serves that directory, anyone can reconstruct the source code, the configuration, and the entire commit history including the things that were deleted.",
    sections: [
      {
        title: "Why It Is So Much Worse Than One File",
        icon: "fa-code-branch",
        content: [
          "An exposed configuration file gives you that file. An exposed repository gives you the application: every source file, every configuration template, every deployment script, and the full history of changes with author names, timestamps, and commit messages.",
          "The history is the part people underestimate. Secrets are committed by accident constantly, noticed, and removed in a later commit. Removing them from the current files does not remove them from the history, so a repository that looks clean today can contain a live database password from eighteen months ago. Recovering deleted commits is a routine part of exploiting this finding.",
          "Source access also converts the rest of the engagement. Every other bug class becomes easier when you can read the code: you can see exactly which parameters are handled, where the validation is, which routes exist, and which access checks were forgotten."
        ],
        keyPoints: [
          "You get the source, the configuration, and the full history",
          "Deleted secrets remain recoverable from old commits",
          "Commit messages and author names are their own disclosure",
          "Source access makes every other bug class easier to find"
        ]
      },
      {
        title: "How It Happens and Where to Look",
        icon: "fa-magnifying-glass",
        content: [
          "The cause is nearly always a deployment that copies a directory. Someone clones or pulls on the server, or rsyncs a working copy, and the metadata directory comes with it. Because it starts with a dot, it is invisible in ordinary directory listings and easy to forget.",
          "The check is a single request for a known metadata file. If it comes back with the expected content rather than the application's not-found page, the directory is being served, and the rest is mechanical recovery.",
          "Do not stop at the site root. Applications deployed under a path prefix have their metadata under that prefix, and an application composed of several deployed components can expose one while the others are fine. Check every directory prefix you discovered."
        ],
        keyPoints: [
          "The cause is deploying a working copy rather than a build",
          "One request for a known metadata file confirms it",
          "Check every directory prefix, not only the site root",
          "Multi-component deployments can expose one part and not others"
        ]
      }
    ],
    practicalTips: [
      "Check every directory prefix you found during discovery, not only the root",
      "Confirm the response is genuine metadata rather than a catch-all page",
      "The same deployment mistake exposes other metadata directories too, so check for them",
      "Look at the commit history for secrets before looking at the current files",
      "Read the deployment scripts; they name infrastructure the rest of the recon missed",
      "Report quickly, since the exposure is complete and ongoing"
    ],
    furtherReading: [
      {
        title: "OWASP WSTG - Review Webserver Metafiles",
        url: "https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
        description: "Configuration and deployment testing including exposed metadata"
      }
    ]
  },

  urlExposedGitTools: {
    title: "git-dumper and GitTools",
    overview: "Both reconstruct a repository from an exposed metadata directory over plain HTTP. They differ in approach and in what they recover, and the difference matters most when directory listing is disabled.",
    sections: [
      {
        title: "Reconstructing Without Directory Listing",
        icon: "fa-toolbox",
        content: [
          "The straightforward case is a server with directory listing enabled, where the whole directory can simply be walked and downloaded. That is uncommon on modern servers, so both tools are built for the harder case: the files exist and are individually retrievable, but nothing will tell you their names.",
          "The technique is to start from the files whose names are fixed, parse them, and follow the references they contain. The index and the reference files name commits, commits name trees, trees name blobs, and each of those is fetched by its own hash-derived path. From a handful of known filenames the tools recover the entire object graph.",
          "git-dumper does this end to end and produces a working repository. GitTools is a set of separate utilities covering finding, dumping, and extracting, which is more flexible when a dump is partial and you want to work with what was recovered."
        ],
        keyPoints: [
          "Directory listing is usually disabled, so the tools follow object references",
          "Fixed filenames provide the entry point into the object graph",
          "git-dumper produces a working repository end to end",
          "GitTools is modular, which helps with partial recoveries"
        ]
      },
      {
        title: "What Recovery Misses",
        icon: "fa-puzzle-piece",
        content: [
          "Recovery is frequently incomplete, and a partial result is still valuable. Objects may have been packed in ways that make some unreachable, the server may block some paths, or the exposed directory may itself be pruned. A dump that recovers most of the tree still gives you most of the source.",
          "Ignored files are not in the repository at all. A production configuration file excluded from version control will not be recovered, which is a reminder that this finding and the file-exposure finding complement each other rather than replacing each other.",
          "Objects that were never packed are recoverable individually, and that is exactly where deleted secrets live. If a tool reports partial success, it is worth extracting whatever objects were recovered and reading them, rather than treating an incomplete dump as a failure."
        ],
        keyPoints: [
          "Partial recovery is normal and still valuable",
          "Ignored files were never in the repository to begin with",
          "Loose objects are where deleted content is usually found",
          "An incomplete dump is worth reading rather than discarding"
        ]
      }
    ],
    practicalTips: [
      "Run both tools if the first produces a partial result; their approaches differ",
      "Search the recovered history for secrets before reading the current files",
      "Look at deleted and amended commits specifically",
      "Read deployment and infrastructure files; they name systems recon did not find",
      "Keep the recovered repository out of anywhere it could be published",
      "Delete it once the report is filed, and say so"
    ],
    furtherReading: [
      {
        title: "git-dumper",
        url: "https://github.com/arthaud/git-dumper",
        description: "Reconstructing a repository from an exposed metadata directory"
      },
      {
        title: "GitTools",
        url: "https://github.com/internetwache/GitTools",
        description: "Finder, dumper, and extractor as separate utilities"
      }
    ]
  },

  urlExposedGitValidation: {
    title: "Reporting an Exposed Repository Responsibly",
    overview: "This is one of the highest-impact findings you can report and one of the easiest to mishandle, because confirming it means downloading the target's source code onto your machine.",
    sections: [
      {
        title: "Proving It Without Publishing It",
        icon: "fa-file-shield",
        content: [
          "The proof is that the metadata is publicly retrievable, which is a single request and its response. You do not need to include source code in the report to establish that the source code is exposed, and including it creates a copy of the target's intellectual property in a ticketing system.",
          "Where the history contains live credentials, that is a second and more urgent finding. Report it as such, redacted, and identify which system the credential is for so it can be rotated. Do not use it.",
          "Say plainly what you did: that you confirmed the exposure, whether you reconstructed the repository, what you looked at, and that you deleted it. Programs are used to this finding and the handling statement is what makes the difference between a straightforward triage and an awkward one."
        ],
        keyPoints: [
          "A single request and response proves the exposure",
          "Do not paste source code into the report",
          "Live credentials from the history are a separate, urgent finding",
          "State what you accessed and that you deleted it"
        ]
      },
      {
        title: "What to Do With the Access Meanwhile",
        icon: "fa-scale-balanced",
        content: [
          "Reading the source to understand the application is legitimate research within the scope you have been given, and it will make the rest of your testing far more effective. Where it leads you to another vulnerability, report that vulnerability on its own merits with a working proof of concept, rather than as a code-reading observation.",
          "There is a line, and it is around what you do with what you learn. Understanding the authentication logic so you can test it is research. Extracting customer data from a database whose credentials you recovered is not, and no program treats it as such.",
          "Report the exposure promptly rather than mining it for weeks. The exposure is live the entire time, and a finding that sat unreported while you extracted value from it reads very differently from one reported the day it was found."
        ],
        keyPoints: [
          "Reading the source to guide testing is legitimate",
          "Report resulting bugs with their own proof of concept",
          "Never use recovered credentials against live systems",
          "Report the exposure promptly rather than mining it first"
        ]
      }
    ],
    practicalTips: [
      "Prove the exposure with one request rather than with an attached archive",
      "Grep the history for credentials before anything else",
      "Report any live credential as a separate, urgent item",
      "Do not paste proprietary source into a report or a chat",
      "Delete the reconstructed repository after filing, and say so",
      "File the exposure the day you find it"
    ],
    furtherReading: [
      {
        title: "OWASP - Information Exposure",
        url: "https://owasp.org/www-community/Improper_Error_Handling",
        description: "Framing for disclosure findings and their impact"
      }
    ]
  },

  // ---------------------------------------------------------------------------------------------
  // Miscellaneous
  // ---------------------------------------------------------------------------------------------
  urlMiscMethodology: {
    title: "Miscellaneous: Upload Bypass, JWT, and Prototype Pollution",
    overview: "Three bug classes that do not fit the other sections and do not resemble each other. What they share is that each depends on a specific mechanism being present, so the first question in each case is whether the target has that mechanism at all.",
    sections: [
      {
        title: "Three Unrelated Mechanisms",
        icon: "fa-shapes",
        content: [
          "File upload bypass is about defeating the checks on what may be uploaded. The severity depends entirely on what happens to the file afterwards: an upload stored in object storage and served as a download is low risk, while one written into a directory the web server will execute from is remote code execution.",
          "JWT problems are about how a token is verified. The classic failures are accepting an unsigned token, accepting an algorithm the caller chose, confusing a symmetric algorithm with an asymmetric one, or simply not verifying the signature at all. Since the token is readable by anyone holding it, working out what the server trusts is straightforward.",
          "Client-side prototype pollution is about JavaScript object semantics. If attacker-controlled keys are merged into an object without filtering, a special key can modify the prototype that every other object inherits from, changing the behaviour of code that never touched the input."
        ],
        keyPoints: [
          "Upload severity depends on where the file lands and whether it executes",
          "JWT failures are all about what the server verifies",
          "Prototype pollution changes behaviour in code that never saw the input",
          "Each requires its specific mechanism to be present at all"
        ]
      },
      {
        title: "Pollution Needs a Gadget",
        icon: "fa-gears",
        content: [
          "Prototype pollution deserves a note of its own because it is routinely over-claimed. Proving that you can set a property on the prototype proves the merge is unsafe. It does not prove any impact, because impact requires a gadget: some other piece of code that reads the polluted property and does something dangerous with it.",
          "Without a gadget, the finding is a weakness. With one, it can be cross-site scripting or worse. The gap between those two is entirely about what else is on the page, which means the work of turning pollution into a finding is reading the application's own JavaScript and its libraries for code that reads configuration-style properties without checking they were set deliberately.",
          "Report it accordingly. Saying that a property can be polluted and that a specific gadget in a specific library turns that into script execution is a strong report. Saying that prototype pollution was detected is not."
        ],
        keyPoints: [
          "Setting a prototype property proves the merge is unsafe, nothing more",
          "Impact requires a gadget that reads the polluted property",
          "Finding the gadget means reading the page's own scripts and libraries",
          "Name the gadget in the report or the finding stays a weakness"
        ]
      }
    ],
    practicalTips: [
      "For uploads, find out where the file is served from before assessing severity",
      "Decode every JWT you are given and look at what claims it carries",
      "Test whether a JWT signature is verified at all before trying anything clever",
      "For pollution, look for a gadget before writing anything down",
      "These sections only apply where the mechanism exists; skip them where it does not",
      "Check whether uploaded content is served from the same origin, which changes the impact"
    ],
    furtherReading: [
      {
        title: "PortSwigger - File Upload Vulnerabilities",
        url: "https://portswigger.net/web-security/file-upload",
        description: "Bypass techniques and what makes an upload dangerous"
      },
      {
        title: "PortSwigger - Prototype Pollution",
        url: "https://portswigger.net/web-security/prototype-pollution",
        description: "Sources, sinks, and gadgets with labs"
      }
    ]
  },

  urlMiscTools: {
    title: "Upload_Bypass, jwt_tool, and pphack",
    overview: "Three tools for three unrelated jobs. Each has a specific configuration requirement that, if missed, produces confident output about nothing, and those requirements are the most important thing to know about them.",
    sections: [
      {
        title: "What Each Needs to Work",
        icon: "fa-toolbox",
        content: [
          "Upload_Bypass works through combinations of extension, content type, magic bytes, and filename tricks against an upload endpoint. Its critical requirement is a marker that tells it what a successful upload looks like. Without one it cannot distinguish success from rejection, and an unmarked run will report every attempt as a finding.",
          "jwt_tool analyses and manipulates tokens: decoding, checking for the standard verification failures, and generating tampered variants. Note that it configures its own proxy settings, which can be surprising if traffic suddenly stops appearing where you expected it.",
          "pphack drives a headless browser to detect client-side prototype pollution. Because it needs a real browser and real page execution, it is slower than the others, and because it depends on page timing it is not deterministic."
        ],
        keyPoints: [
          "Upload_Bypass needs a success marker or it invents findings",
          "jwt_tool sets up its own proxy configuration",
          "pphack drives a real browser, so it is slow and timing-dependent",
          "Each has a setup requirement that changes what its output means"
        ]
      },
      {
        title: "The Coin Flip",
        icon: "fa-dice",
        content: [
          "pphack's non-determinism is worth stating precisely because it is easy to misread. Whether the page's own scripts have merged the payload into the prototype by the moment the tool looks is a race. Measured against a target that pphack reports as vulnerable when run directly, it produced a hit in three runs out of six.",
          "At one run per vector that is a coin flip, and a section reporting clean across two dozen vectors on a target with documented prototype pollution is the expected outcome rather than a surprise. The framework now retries when a run comes back empty, which converts a coin flip into something usable.",
          "The general lesson applies beyond this tool: a detector that depends on timing needs repetition, and a single empty run from one is not evidence of anything. Where you are running such a tool by hand, run it several times before concluding."
        ],
        keyPoints: [
          "pphack's detection is a race against the page's own scripts",
          "Measured at three hits in six identical runs against the same target",
          "One run per vector reports roughly half of what is there as clean",
          "Timing-dependent detectors need repetition, not a single run"
        ]
      }
    ],
    practicalTips: [
      "Set the upload success marker before running Upload_Bypass, not after",
      "Decode tokens by hand as well; the interesting claim is often obvious",
      "Run pphack more than once before accepting an empty result",
      "Check where an uploaded file ends up, since that determines severity",
      "For JWTs, test the unsigned and algorithm-confusion cases first, as they are quick",
      "Verify jwt_tool's proxy configuration if traffic is not appearing where you expect"
    ],
    furtherReading: [
      {
        title: "jwt_tool",
        url: "https://github.com/ticarpi/jwt_tool",
        description: "Token analysis and the standard verification attacks"
      },
      {
        title: "OWASP - Unrestricted File Upload",
        url: "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        description: "What makes an upload dangerous and how the checks are bypassed"
      }
    ]
  },

  urlMiscValidation: {
    title: "Validating Uploads, Tokens, and Pollution",
    overview: "Each of these three classes is confirmed differently, and each has a specific way of looking like a finding when it is not. This is the check for each.",
    sections: [
      {
        title: "The Three Confirmations",
        icon: "fa-clipboard-check",
        content: [
          "For an upload, accepting the file is not the finding. The finding is what happens to it afterwards, so the confirmation is retrieving it: request the stored file and see whether it is served, whether it is served from the application's own origin, and whether it is interpreted rather than downloaded. A file accepted and stored somewhere inert is a weak finding at best.",
          "For a JWT, the confirmation is that the server accepts a token you modified. Change a claim, send it, and see whether the server acts on the change. If it rejects the token, the signature is being verified and there is nothing here regardless of what the token contains.",
          "For prototype pollution, the confirmation has two parts: that the property can be set, and that some code reads it and does something as a result. Only the second part is impact, and it is the part that needs to appear in the report."
        ],
        keyPoints: [
          "For uploads, retrieve the file; acceptance alone is not the finding",
          "For JWTs, modify a claim and see whether the server acts on it",
          "For pollution, show the property is set and that something reads it",
          "In all three cases the second step is the one that establishes impact"
        ]
      },
      {
        title: "The Specific False Positives",
        icon: "fa-ghost",
        content: [
          "An upload tool without a success marker reports everything as successful, because it has no way to recognise a rejection. That produces a long list of confident findings from a run in which nothing was uploaded at all, and it is the single most common failure in this section.",
          "A JWT finding based only on the token's contents is not a finding. Plenty of tokens carry a role or an administrator flag, and that is entirely normal; what matters is whether the signature is verified. Reporting the presence of a privileged claim without demonstrating that a modified token is accepted is a common and easily avoided mistake.",
          "A pollution finding without a gadget is a weakness rather than a vulnerability. It is still worth reporting on some programs, but it should be described as what it is, and an empty result from a single timing-dependent run should not be described as anything at all."
        ],
        keyPoints: [
          "An unmarked upload run reports every attempt as a success",
          "A privileged claim in a token is normal; an accepted forgery is the finding",
          "Pollution without a gadget is a weakness, and should be labelled as one",
          "A single empty run from a timing-dependent detector proves nothing"
        ]
      }
    ],
    practicalTips: [
      "Always retrieve the uploaded file and note the URL and content type it is served with",
      "Clean up uploaded test files, and tell the program where they are",
      "Modify a JWT claim and confirm the server acts on it before reporting anything",
      "Name the specific gadget when reporting prototype pollution",
      "Re-run timing-dependent detectors several times before recording a clean result",
      "Describe a weakness as a weakness; over-claiming costs credibility on later reports"
    ],
    furtherReading: [
      {
        title: "PortSwigger - JWT Attacks",
        url: "https://portswigger.net/web-security/jwt",
        description: "The verification failures and how to test each one"
      },
      {
        title: "PortSwigger - Prototype Pollution Gadgets",
        url: "https://portswigger.net/web-security/prototype-pollution/client-side",
        description: "Finding the gadget that turns pollution into impact"
      }
    ]
  }
};
