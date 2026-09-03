// Lessons for the URL workflow sections that had no Help Me Learn content: Authentication,
// Authorization, Consolidate Attack Vectors, the twelve attack-tool sections, and Threat Model
// Results. Same shape as data/lessons.js (title, overview, sections[], practicalTips[],
// furtherReading[]) and merged into that export, so every consumer sees one flat lessons object.
//
// The tool sections are written from what these tools actually did against a live target during
// this project rather than from their README files. Where a tool has a failure mode that reads as
// a clean result, that failure mode is stated in the lesson, because a learner who does not know
// about it will read "0 findings" as "no vulnerability".

export const urlWorkflowLessons = {
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
