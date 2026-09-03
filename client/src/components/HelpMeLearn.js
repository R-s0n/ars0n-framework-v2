import React, { useState } from 'react';
import { Accordion, ListGroup } from 'react-bootstrap';
import LearnMoreModal from '../modals/LearnMoreModal';
import { lessons } from '../data/lessons';

const HelpMeLearn = ({ section }) => {
  const [showLearnMoreModal, setShowLearnMoreModal] = useState(false);
  const [currentLesson, setCurrentLesson] = useState(null);

  const handleLearnMoreClick = (lessonKey) => {
    setCurrentLesson(lessons[lessonKey]);
    setShowLearnMoreModal(true);
  };

  const handleCloseLearnMoreModal = () => {
    setShowLearnMoreModal(false);
    setCurrentLesson(null);
  };

  const sections = {
    urlManualCrawling: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at, and why do we start URL testing by crawling the app manually?",
          lessonKey: "urlManualCrawlingMethodology",
          answers: [
            "We've moved from the recon phases (finding domains, subdomains, and live web servers) into the URL phase, where we focus on a single chosen application and map everything it does before testing it for bugs. Manual crawling is the very first step: you use the application the way a real user would, by hand.",
            "The goal is to build a model — in your head and in your notes — of how the app works: its pages, features, user roles, and the requests the browser sends behind the scenes. Automated tools are powerful but they don't understand business logic; you do. Time spent here is what separates hunters who find high-impact bugs from those who only find what a scanner reports.",
            "Practically, you browse the target through an intercepting proxy (like Caido or Burp Suite) so every request and response is captured. This 'walk-through' fills your proxy history, seeds the automated crawlers with real (and authenticated) traffic, and reveals features that spidering tools would never reach on their own — multi-step flows, anything behind a login, and JavaScript-driven actions."
          ]
        },
        {
          question: "How do I use an intercepting proxy (Caido or Burp Suite) to explore and capture the application?",
          lessonKey: "urlManualCrawlingProxy",
          answers: [
            "An intercepting proxy sits between your browser and the target. Your browser is configured to send traffic through the proxy (e.g., 127.0.0.1:8080), and the proxy records every request/response pair. Because HTTPS is encrypted, you install the proxy's CA certificate in your browser once so it can read and log the traffic.",
            "With the proxy running, simply use the app: sign up, log in, change settings, upload a file, run a search, make a test purchase, open every menu. Each action generates requests that land in the proxy's HTTP history and sitemap — the exact API calls, parameters, headers, cookies, and tokens the application relies on.",
            "As you go, send interesting requests to the Replay/Repeater tool so you can modify and resend them without clicking through the UI again. Note the authentication material (session cookies, Bearer tokens); you'll reuse it so your automated scans run as a logged-in user, which dramatically expands the reachable attack surface.",
            "The Ars0n Framework complements this: it can install a browser extension and capture your manual crawl, feeding those real requests and discovered endpoints into the rest of the URL workflow — so the automated tools build on top of your human exploration instead of starting blind."
          ]
        },
        {
          question: "What should I look for and document while manually crawling, as a complete beginner?",
          lessonKey: "urlManualCrawlingMapping",
          answers: [
            "Map the features and roles first: what can an anonymous visitor do, a normal user, and an admin? Note anywhere the app makes a trust decision (who can see, do, or change what). Broken access control and IDOR — among the most common and valuable bugs — hide exactly at these boundaries.",
            "Catalog the objects the app manipulates: user IDs, order numbers, document IDs, account numbers, API keys. Anywhere you see a number or ID in a URL or request body, ask 'what happens if I change it to someone else's?' Write these down; they become your test cases.",
            "Watch the proxy history for the 'plumbing': API base paths (like /api/v1/…), authentication flows (login, password reset, OAuth redirects), file uploads, and any request that reflects your input back into the page. These are the mechanisms you'll later attack with the automated tools and manual payloads.",
            "Keep short notes as you go — a running list of interesting endpoints, parameters, and 'that felt weird' moments. This document is the bridge from recon to actual hunting; every later step (endpoint discovery, brute forcing, parameter enumeration, threat modeling) builds on the understanding you capture here."
          ]
        }
      ]
    },
    urlDiscovery: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at, and what are we trying to accomplish with URL and endpoint discovery?",
          lessonKey: "urlDiscoveryMethodology",
          answers: [
            "We're in the URL/Endpoint Discovery phase — expanding the map of the single target application from the handful of pages you clicked through into the full set of URLs, API routes, and resources the app exposes. Manual crawling gave you depth; this step gives you breadth.",
            "The objective is a comprehensive list of endpoints to test. Every URL, parameter, and API route is a potential place for a bug. Modern apps hide most of their surface in JavaScript, in old archived pages, and in routes that aren't linked from the homepage — so we combine several tools that each find endpoints a different way.",
            "There are two complementary techniques here: active crawling (a tool loads the app and follows links/JavaScript, like Katana and GoSpider) and passive discovery (a tool asks public archives what URLs have ever been seen for this domain, like Waybackurls and GAU). Together they surface far more than either alone, including forgotten and deprecated endpoints that are often the least protected."
          ]
        },
        {
          question: "How do Katana, LinkFinder, Waybackurls, GAU, and GoSpider each discover endpoints differently?",
          lessonKey: "urlDiscoveryTools",
          answers: [
            "Katana is a fast, modern crawler (from ProjectDiscovery) that loads pages, parses HTML and JavaScript, and can even drive a headless browser to follow dynamically-generated links. It's your primary active crawler for discovering the app's current, live structure.",
            "GoSpider is another active crawler that's good at pulling URLs out of a page's links, forms, robots.txt, sitemaps, and inline JavaScript — a useful second opinion alongside Katana because different crawlers catch different things.",
            "Waybackurls and GAU (GetAllUrls) are passive: they query public archives (the Wayback Machine, Common Crawl, URLScan, and others) for every URL ever recorded for the domain. This is how you find old, deprecated, and forgotten endpoints — including ones developers took out of the UI but never actually removed from the server.",
            "LinkFinder specializes in JavaScript: it parses the app's JS files and extracts the endpoints, API paths, and routes referenced inside them. Because single-page apps define most of their API surface in JavaScript, LinkFinder often reveals API endpoints that no crawler would reach by clicking around."
          ]
        },
        {
          question: "How do I run these tools together and turn the raw results into a useful list of targets?",
          lessonKey: "urlDiscoveryWorkflow",
          answers: [
            "Run the active and passive tools together so their results complement each other: crawlers (Katana, GoSpider) map the live app, archive tools (Waybackurls, GAU) recover history, and LinkFinder mines the JavaScript. The framework runs each and stores the endpoints it finds against your target.",
            "Raw output is always noisy and full of duplicates — the same URL with different query values, static assets (.png, .css, .woff), and out-of-scope third-party URLs. Consolidation and filtering (the next step in this workflow) deduplicate and normalize everything into a clean, unique endpoint list you can actually work through.",
            "Once consolidated, read the list looking for the interesting stuff: API routes (/api/, /graphql, /v1/), admin and internal paths, anything that takes parameters, file-handling endpoints, and old versioned routes. These are the endpoints you'll feed into brute forcing, parameter enumeration, and manual testing.",
            "Think of this phase as building your worklist. You're not testing for bugs yet — you're making sure that when you do, you test the whole application, not just the parts that happen to be linked from the front page."
          ]
        }
      ]
    },
    urlTargetEndpoints: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is this consolidated endpoint inventory, and why is it the center of the URL workflow?",
          lessonKey: "urlTargetEndpointsMethodology",
          answers: [
            "This is your unified attack-surface inventory for the target application: every endpoint discovered by crawling, archive mining, JavaScript analysis, and brute forcing, deduplicated and gathered in one place. It's the single source of truth you'll work from for the rest of the engagement.",
            "It matters because scattered results are useless results. Five tools each producing their own output means you lose track of what's been found, what's been tested, and what's important. Consolidating into one reviewable list is what turns raw discovery into an actionable testing plan.",
            "Think of it as the bridge between 'finding the app's surface' and 'actually hunting for bugs.' Everything upstream (discovery, brute forcing) feeds into this inventory; everything downstream (parameter enumeration, manual testing, threat modeling) draws targets out of it."
          ]
        },
        {
          question: "How do I read and understand the endpoint attack surface in front of me?",
          lessonKey: "urlTargetEndpointsAnalysis",
          answers: [
            "Group the endpoints into functional buckets so a big list becomes comprehensible: authentication (login, logout, reset, oauth), account/profile management, the core business features (whatever the app is actually for), file handling (upload/download/export), search and filtering, and API/admin/internal routes. Structure reveals where the interesting behavior lives.",
            "Pay attention to the shape of each endpoint: which HTTP methods it accepts (GET vs POST/PUT/DELETE — write methods change state and are higher-risk), whether it takes parameters, whether it returns data or performs an action, and what status codes it gives. These properties tell you what kind of testing each endpoint invites.",
            "Look for the standouts: routes that reference object IDs (IDOR candidates), endpoints that take a URL or filename as input (SSRF, path traversal, open redirect), anything that reflects your input, old API versions, and admin/debug paths. The inventory is where these patterns become visible across the whole app at once."
          ]
        },
        {
          question: "How do I decide which endpoints to test first?",
          lessonKey: "urlTargetEndpointsPrioritization",
          answers: [
            "Prioritize by potential impact. Endpoints that touch money, personal data, authentication, or admin functionality are worth testing before a static marketing page. If a bug there would matter, it's higher priority. Ask 'what's the worst thing that could go wrong at this endpoint?' and start where the answer is worst.",
            "Prioritize by likelihood too. Endpoints with parameters, write methods, object IDs, file handling, or clear trust boundaries are more likely to hold a bug than a parameterless static route. High-impact and high-likelihood endpoints are where you spend your time first.",
            "Cross-reference with your manual-crawl notes and threat model. The endpoint that looked interesting while you were clicking around, the object IDs you wrote down, the mechanism you flagged — those observations, combined with the full inventory here, tell you exactly where to point parameter enumeration and manual testing.",
            "Finally, use the inventory to track progress. As you test endpoints, note what you've covered and what you've found. On a large app you won't test everything, so a deliberate, prioritized pass over the inventory is how you make sure your limited time goes to the highest-value targets."
          ]
        }
      ]
    },
    // Parameter enumeration and endpoint/header/cookie brute forcing are one card row now, so
    // their lessons are one accordion: the tools differ, the question they answer does not.
    urlHiddenAttackVectorFuzzingChunking: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at, and why do hidden parameters matter so much?",
          lessonKey: "urlParameterMethodology",
          answers: [
            "We're in the Parameter Enumeration phase. We have a list of endpoints; now we discover the hidden input parameters each one secretly accepts. Applications frequently support parameters that aren't shown in any form, link, or documentation — the backend still reads them, it just doesn't advertise them.",
            "Hidden parameters matter because a parameter the developer forgot to secure — or didn't expect anyone to find — is exactly where bugs live. A hidden debug=true that enables verbose errors, an admin=1 that unlocks privileged behavior, an internal id or redirect parameter that isn't validated because 'nobody knows it's there' — these are classic high-impact findings.",
            "Every parameter is an input, and every input is a potential injection or logic-flaw point. Finding parameters the developer didn't mean to expose dramatically widens the attack surface of each endpoint — a single URL with three hidden parameters is really four things to test, not one."
          ]
        },
        {
          question: "How do Arjun and x8 discover hidden parameters differently?",
          lessonKey: "urlParameterTools",
          answers: [
            "Both work by the same core idea: send the endpoint many candidate parameter names from a wordlist and watch for a change in the response. If adding ?debug=xyz changes the response — different length, different status, reflected value, different behavior — that parameter is probably real and processed by the backend.",
            "Arjun is a fast, accurate Python tool that's smart about this diffing: it sends parameters in chunks, establishes a stable baseline, and reports the names that genuinely affect the response. It handles GET, POST, JSON, and XML bodies and is a great default choice.",
            "x8 is a high-accuracy Rust tool that excels at precise response comparison and can inject parameters into the query string, body, or headers. It's particularly good at cutting through noise on responses that change slightly on their own, and it verifies its findings to reduce false positives.",
            "Running both is worthwhile because they use different wordlists and diffing strategies, so each can surface parameters the other misses."
          ]
        },
        {
          question: "How do I turn a discovered parameter into an actual vulnerability?",
          lessonKey: "urlParameterExploitation",
          answers: [
            "A discovered parameter is a lead, not a bug. Once you know an endpoint accepts, say, a hidden user_id or file or url parameter, you test it like any other input — but now you're testing an input the developer probably never hardened, which raises your odds considerably.",
            "Match the parameter to a vulnerability class by what it looks like it does. A parameter naming an object (id, user, account, order) invites IDOR — try other users' values. One taking a URL (url, redirect, next, callback) invites SSRF and open redirect. One taking a file or path invites path traversal. One that reflects into the page invites XSS. One in a database-driven feature invites SQL/NoSQL injection.",
            "Also test for behavior-changing parameters, not just injection: debug, test, admin, is_admin, role, preview, and similar names can unlock hidden functionality, verbose errors, or privileged views when set to true/1. These 'magic parameters' are pure logic bugs and often high impact.",
            "Feed confirmed parameters back into your proxy and test them manually and deliberately. Parameter discovery's job is to hand you inputs the application didn't want you to know about; your job is to try each one against the vulnerability class it suggests."
          ]
        },
      ]
    },
    // Split where the workflow splits. The first three items are about parameters an endpoint reads
    // but never advertises, which is what Arjun and x8 chase a batch at a time; these are about
    // finding things nothing links to at all, one request per word, which is FFUF's job and now its
    // own section.
    urlHiddenAttackVectorFuzzingBruteForce: {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why does fuzzing for hidden PATHS come before everything else, and what happens when it is skipped?",
          lessonKey: "urlContentDiscoveryMethodology",
          answers: [
            "Crawling finds what the application advertises and archives find what it used to advertise. Neither finds the thing nobody links to, and the thing nobody links to is usually the least protected thing on the target: the admin panel, the staging route, the old API version, the backup file left in the web root.",
            "It goes first because every later step is bounded by the endpoint list. Parameter enumeration finds hidden inputs on endpoints you already have. The access-control sections need endpoints that already answered 401 or 403. The scanners run against attack vectors, and vectors are built from endpoints. Miss the admin panel here and nothing downstream can find it.",
            "The cost of skipping it is invisible, which is why it is worth stating plainly. On this framework's first full engagement the fuzzing phase ran ten steps against parameters, headers and cookies and never once put FUZZ in the path. The access bypass section ended with zero targets, because nothing had ever requested a path that returns a 403, on a target where an unauthenticated admin bypass was real. Nothing errored. It just reported clean."
          ]
        },
        {
          question: "How do I drive FFUF well: calibration, filtering, recursion and pacing?",
          lessonKey: "urlContentDiscoveryFfuf",
          answers: [
            "Baseline first, filters second, volume last. Before sending thousands of requests, request something that certainly does not exist and read what comes back. If a miss is a 404, matching on status is enough. If a miss is a 200 carrying a themed not-found page, status matching finds everything and tells you nothing, and you filter on size, words or lines instead with -fs, -fw or -fl.",
            "Auto-calibration (-ac) sends random paths first, measures the response, and filters anything matching it. It is the right default on a soft-404 target and it can silently hide real findings that resemble the baseline. Run a calibrated and an uncalibrated pass on anything important and compare the counts.",
            "Then extensions, recursion and pacing. Use -e to hunt backups and configuration (.bak, .old, .zip, .sql), which are the highest-value hits in content discovery. Use -recursion with a bounded -recursion-depth, because unbounded recursion multiplies your request count by the number of directories you find. Use -rate and -p to stay inside what the target tolerates; on production, tuning the flags is worth far more than raw threads, because a scan that gets you blocked returns nothing."
          ]
        },
        {
          question: "Which wordlist should I use, and does bigger mean better?",
          lessonKey: "urlContentDiscoveryWordlists",
          answers: [
            "No. A list matched to the target finds more with fewer requests than a generic million-line list, and it finishes in time to act on. Start small with common.txt or quickhits.txt to learn the response shapes and set the filters, then move to raft-medium-directories and raft-medium-files as the working default, and raft-large only when the target justifies the time.",
            "Once you know the stack, use a list built for it, and fuzz extensions matched to it rather than every extension you can think of. The same request budget spent on a matched list finds substantially more.",
            "Build target-specific lists as you go from the application's own vocabulary: its pages, its JavaScript, its error messages. Internal naming is consistent and almost never appears in a public wordlist. And delete stale uploaded lists, because a list assembled for a previous target quietly costs coverage on this one."
          ]
        },
        {
          question: "Why do we also brute-force for hidden endpoints, headers, and cookies?",
          lessonKey: "urlBruteForcingMethodology",
          answers: [
            "We're in the Endpoint Brute Forcing phase. Crawling and archive mining found the endpoints the app links to or has been seen using; brute forcing finds the ones nobody links to at all — by taking a wordlist of common paths and filenames and asking the server, one by one, 'does /admin exist? does /backup.zip exist? does /api/internal exist?'",
            "This matters because the most sensitive things are often the least advertised: admin panels, backup files, config files, staging endpoints, debug interfaces, and forgotten API routes. If the server responds to /.git/config or /backup.sql, you've found something no crawler ever would have.",
            "Brute forcing is active and noisy — you're sending many requests to the target — so it's the phase where you most need to be deliberate: respect the program's rules, avoid hammering the target, and be aware of WAFs and rate limits (which is exactly why the WAF Probe runs first)."
          ]
        },
        {
          question: "How do WAF Probe and FFUF work together in this step?",
          lessonKey: "urlBruteForcingTools",
          answers: [
            "FFUF (Fuzz Faster U Fool) is the brute-forcer: it takes a wordlist and a target URL with a FUZZ keyword (e.g., https://target/FUZZ), sends a request for every word, and shows you which paths return interesting responses. It's extremely fast and highly configurable — threads, rate limits, matchers, and filters.",
            "The danger is that fast, aggressive fuzzing against a protected target gets you blocked: a WAF returns 403 to everything, or a rate limiter throttles you, and your results become useless (or your IP gets banned). Tuning FFUF blind is guesswork.",
            "That's what WAF Probe solves. It probes the target first to detect whether a WAF is present (and which vendor), how the target rate-limits, and what a blocked response looks like — then recommends a safe FFUF configuration (request rate, delay, threads, response filters) and lets you apply it with one click. Run WAF Probe, apply its recommendations, then run FFUF tuned to the target.",
            "In short: WAF Probe is reconnaissance for your fuzzing, and FFUF is the fuzzing. Using them in that order means you fuzz effectively without tripping defenses — the difference between clean results and a banned IP."
          ]
        },
        {
          question: "How do I choose wordlists, tune FFUF, and interpret results responsibly?",
          lessonKey: "urlBruteForcingWorkflow",
          answers: [
            "Wordlist choice is everything. Start with a general content-discovery list (like SecLists' common.txt or the raft lists), then get specific: if the app is PHP, add .php extensions; if you found an /api, fuzz it with API-specific wordlists. A targeted wordlist finds more with fewer requests than a giant generic one.",
            "Tune FFUF to the target: set the request rate and delay based on the WAF Probe's recommendation, pick a sensible thread count, and use matchers/filters so you see signal, not noise. The key skill is filtering out the 'baseline' response — if every missing page returns a 200 with a 1,024-byte 'not found' template, filter that size so real hits stand out.",
            "Interpret results by looking at status codes and response sizes together. 200 is an obvious hit; 401/403 can mean 'this exists but you're not authorized' (still a lead — maybe it's bypassable); 301/302 redirects reveal structure; and anomalous sizes flag pages that behave differently. Every interesting hit becomes a new endpoint to test manually.",
            "Above all, hunt responsibly: stay in scope, keep request rates reasonable, prefer smaller targeted wordlists over brute-forcing the entire internet's worth of paths, and stop if you're clearly being blocked rather than escalating. Good hunters are welcome back; ones who knock over targets are not."
          ]
        }
      ]
    },
    urlAuthentication: {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why does it matter so much that the scans run as a logged-in user?",
          lessonKey: "urlAuthenticationMethodology",
          answers: [
            "Almost every interesting feature of an application sits behind a login. An unauthenticated crawl reaches the marketing pages, the login form, and very little else, so an unauthenticated scan of an authenticated application mostly tests the login wall. The account settings, the order history, the uploads, and the API behind all of them stay invisible.",
            "The bug classes worth the most are defined in terms of an authenticated identity. You cannot find a flaw about what user A may do to user B's data if you are not logged in as either of them, which is also why two accounts at the same privilege level are worth more than one.",
            "The failure mode here is quiet rather than loud. When a session dies mid-scan, most tools keep sending payloads, keep receiving the login page, keep seeing no evidence of anything, and record every vector as clean. The scan finishes early, reports nothing, and looks like a target with no bugs."
          ]
        },
        {
          question: "What is an auth flow, and why store the flow instead of just the session token?",
          lessonKey: "urlAuthenticationFlows",
          answers: [
            "A token is a snapshot that is already ageing. Sessions expire on a timer, on idle, on a login elsewhere, and on a deploy, and once a pasted token goes stale a scanner has no way to get another one.",
            "An auth flow is the recipe instead: the exact requests, in order, that turn credentials into a session. Typically that is fetching the login page to pick up a CSRF token, posting the credentials with it, and following the redirect. Recorded once, it can be replayed whenever a fresh session is needed.",
            "Record with the browser extension when the login involves JavaScript, single sign-on, or several steps, since the extension captures exactly what the browser sent. Write the flow by hand when it is a simple form post or a token API. Either way, replay it once before you rely on it, because a flow that has never been replayed is an assumption."
          ]
        },
        {
          question: "How do I tell a real clean result from a scan that spent an hour talking to a login page?",
          lessonKey: "urlAuthenticationSessions",
          answers: [
            "Watch the Active count rather than the total. A long list of session tokens with zero active is exactly the state that produces pages of confident, worthless clean results.",
            "A valid token can still fail for reasons that have nothing to do with the application. Load-balanced deployments often keep session state on one backend and use a companion routing cookie to send you back to it; send the session cookie without the routing cookie and you land somewhere that has never heard of your session. Sending the whole cookie jar rather than the one cookie you think matters avoids most of this.",
            "The practical habit is to distrust speed. A scan that finished far faster than the work should have taken, or that reported clean on something you have reason to believe is vulnerable, should have its session re-checked before you write anything down."
          ]
        }
      ]
    },
    urlAuthorization: {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why do I have to model the access rules before testing rather than just scanning?",
          lessonKey: "urlAuthorizationMethodology",
          answers: [
            "Every other bug class has an observable signature. Injection produces an error, a delay, or a callback; cross-site scripting produces script execution. Broken access control produces a completely normal HTTP 200 with somebody else's data in it, and there is nothing about that response that looks wrong to a scanner.",
            "That is why this class sits at the top of the OWASP Top Ten and is almost entirely missing from automated scan output. The tool has no idea that an order number belongs to another customer. You do, but only if you wrote it down first.",
            "For each meaningful action, answer three questions: who is allowed, who is explicitly forbidden, and how does the server work out which of those you are. The third one is where the bugs are, because if the server decides you are an administrator by reading a value the caller supplies, the first two answers do not matter."
          ]
        },
        {
          question: "What are Client Identity Patterns and why is the Attacker-Controlled IDs count called out?",
          lessonKey: "urlAuthorizationIdentity",
          answers: [
            "There are three places a server can get your identity. From the session, which is safe because it looks you up from a token it issued. From a claim inside a token, which is fine if the signature is verified and disastrous if it is not. Or from a parameter in the request itself, which is the dangerous one.",
            "Parameter-supplied identity is not automatically a bug, since applications pass object identifiers around all the time. It becomes one when the server uses that identifier to fetch the object and never checks the object belongs to the caller. Because the identifier is right there in the URL or body, testing it is trivial, which is why that count is a direct measure of your IDOR surface.",
            "Do not assume an unguessable identifier is safe. Random identifiers leak constantly through search results, exports, notification emails, shared links, and API responses that return more fields than the interface displays. Unguessable is not the same as authorized."
          ]
        },
        {
          question: "What is the difference between policy, role, and discretionary access controls?",
          lessonKey: "urlAuthorizationControls",
          answers: [
            "Role-based control assigns permissions to named roles: administrators may delete, editors may publish, viewers may read. It fails when the role is decided from something the caller controls, when a route is left out of the permission table, or when the interface hides a button while the endpoint behind it stays open.",
            "Policy-based control evaluates rules against attributes at request time, such as approving a refund under a limit during business hours. It fails at the edges, so you attack the boundary value, the missing attribute, and the case the policy author did not consider. Discretionary control lets an owner share an object, and it fails at revocation, expiry, and escalation of a grant.",
            "The forbidden cells are worth more than all the rest put together, because there is no ambiguity about what a successful request means. If the model says a standard user must not delete another user's account and one does, that is a finding and there is nothing to argue about."
          ]
        }
      ]
    },
    urlConsolidateAttackVectors: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What exactly is an attack vector, and why is it the unit everything below tests?",
          lessonKey: "urlAttackVectorsMethodology",
          answers: [
            "A URL is not a test. The same path can accept different verbs, different parameter combinations, and input in several different places, and each of those reaches different code. Meanwhile the same URL captured forty times during a crawl with forty different search terms is one test, not forty.",
            "A vector resolves that. Its identity is the verb, the host, the path, the set of parameters in play, and the single insertion point being targeted. Two captures agreeing on all of those are the same vector regardless of how different the values looked, and two differing on any of them are different vectors even when the URL looks identical.",
            "The parameter set is part of the identity because applications branch on which parameters are present, not just their values. A search called with a term alone may run one query; called with a term and a category filter it may run a completely different one that reaches code the first never touched."
          ]
        },
        {
          question: "What are the five insertion points and why do the unusual ones matter most?",
          lessonKey: "urlAttackVectorsInsertionPoints",
          answers: [
            "A payload can go in the query string, the request body, a header, a cookie, or the path. Query and body get the overwhelming majority of attention from testers, and therefore from the developers who wrote the validation, which is precisely why the other three are worth your time: input arriving somewhere unexpected is input that was probably never filtered.",
            "Headers reach logs, generated URLs, and cache keys. Cookies get trusted because the server set them, which is not a guarantee of anything. Path segments matter wherever a URL maps onto a file, a template, or a record.",
            "Check the spread before you scan. If the list contains zero header vectors and zero path vectors, every scan below will report nothing wrong with headers or paths, not because they are safe but because nothing was ever sent there. That is a coverage gap that reads exactly like a clean result."
          ]
        },
        {
          question: "Where do vectors come from, and what does consolidation fail to recover?",
          lessonKey: "urlAttackVectorsSources",
          answers: [
            "Four sources feed this list. The manual crawl gives depth, authentication, and full request bytes. Endpoint discovery gives breadth and history. The hidden-parameter tools find inputs the application never advertises. The fuzzer finds resources nothing links to.",
            "Consolidation deduplicates and merges, but it cannot invent what was never captured. A form you did not submit during the crawl produces no body vector, and no amount of consolidating will conjure one. On the reference target a subscribe form was never submitted, so it never became a vector, so every scanner reported clean on it, and it held a real cross-site scripting vulnerability.",
            "So read the list critically before scanning. Pull up the application, list its features from memory, and confirm each one appears. Anything missing is a hole you can still close by crawling that feature or adding the vector by hand, and it is far cheaper to fix now than to discover later."
          ]
        }
      ]
    },
    'attackTools:xss': {
      title: "Help Me Learn!",
      items: [
        {
          question: "What am I actually looking for, and why is a reflected payload not yet a finding?",
          lessonKey: "urlXssMethodology",
          answers: [
            "Cross-site scripting is the ability to run your JavaScript in someone else's browser session on the target's origin. The most common mistake is treating an echo as a finding: seeing your payload come back in the response proves the application reflects input, not that a browser will execute it.",
            "What makes it a vulnerability is context. The same string is inert inside an attribute value, inside a JavaScript string literal, inside a comment, or when the characters that matter have been encoded. Your input has to land somewhere the browser parses as code, with the syntax-breaking characters surviving intact.",
            "The three shapes matter for impact. Reflected travels in the request and needs a delivery mechanism. Stored is written to the server and served to whoever loads the page, so it needs no delivery and is worth more. DOM-based happens entirely in the browser, can live after the URL fragment, and may never reach the server at all."
          ]
        },
        {
          question: "How do Dalfox, DOMDig, and xssFuzz differ, and how do I read their findings?",
          lessonKey: "urlXssTools",
          answers: [
            "They answer three different questions. Dalfox sends payloads, works out where they land and what context surrounds them, and reports a verified finding when the payload escapes that context. DOMDig drives a real Chromium browser and is the only one of the three that can find DOM-based XSS. xssFuzz checks whether the payload string appears in the response, which is a plain substring test with no understanding of context at all.",
            "Read the Dalfox finding type rather than the severity. Verified means a payload was sent and appeared to escape its context. An analysis finding is static reasoning with no payload fired, so treat it as a lead to test by hand.",
            "There is one exception that outranks everything: when the detection method is out-of-band, something in the target genuinely called back to your collector. That is not a reflection heuristic, that is real execution."
          ]
        },
        {
          question: "How do I confirm an XSS finding, and when does zero findings mean nothing was tested?",
          lessonKey: "urlXssValidation",
          answers: [
            "Reproduce the exact request first, unchanged. Then load it in a real browser rather than a command-line client, because execution is a browser behaviour and curl will happily show you a payload no browser would run. Confirm the characters that matter were not encoded, then reduce the payload to the smallest thing that still fires.",
            "These scanners abort when their session marker stops matching, and the abort is recorded in the run metadata rather than in the findings. The visible result is a completed scan with zero findings. During this project that produced 53 vectors reported as free of XSS against an application that documents four separate XSS vulnerabilities.",
            "A rejected command line does the same thing: the tool prints a usage message and exits without sending a single request. In both cases the warning sign is speed. A scan that finished far faster than the work should have taken tested less than you think."
          ]
        }
      ]
    },
    'attackTools:sqli': {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why does SQL injection still exist, and what is a finding actually worth?",
          lessonKey: "urlSqliMethodology",
          answers: [
            "Parameterised queries have been the standard fix for twenty years and most of an application will use them. Injection survives in the places that did not fit the pattern: a dynamic sort column, a search filter assembled from optional clauses, a legacy report generator, a stored procedure that concatenates internally.",
            "That is why finding it is about coverage rather than cleverness. The vulnerable parameter is rarely the login field, because the login field was hardened first. It is the category filter, the export format, the internal search nobody reviewed. Hidden parameters are disproportionately likely to be unreviewed for the same reason.",
            "Impact varies enormously inside this one class. Retrieving one extra row is modest; reading arbitrary tables is severe; writing to the database or reaching the host is critical. Schema enumeration is normally enough to establish severity, and dumping a production customer table is neither required nor authorised."
          ]
        },
        {
          question: "How do sqlmap, Ghauri, and SQLiDetector differ, and what makes them report a false clean?",
          lessonKey: "urlSqliTools",
          answers: [
            "sqlmap is the most thorough tool available and the slowest, and it can escalate to reading files and running commands where the configuration allows. Ghauri covers the same core techniques far faster and makes an excellent second opinion because its internals differ. SQLiDetector is not an exploitation tool at all; it matches database error signatures, which is a useful first sweep but only means the application surfaced an exception.",
            "Two traps produce a clean result that means nothing. Ghauri caches results by host, so a repeat run can return an old verdict instantly, including one produced by a broken earlier configuration. This framework forces a flush every run; if you run these tools by hand, do it yourself.",
            "The second is a rejected option. A fractional value where the tool only accepts whole seconds is enough. During this project that produced 53 vectors reported clean in forty seconds having sent zero requests, against a target with confirmed SQL injection. Both traps look identical to a fast clean scan, so compare runtime against vector count."
          ]
        },
        {
          question: "What does the technique named on a finding tell me?",
          lessonKey: "urlSqliTechniques",
          answers: [
            "Boolean-based blind injects a condition and watches whether the page differs between the true and false versions. It proves the query is under your control but returns no data by itself. Time-based blind reads the answer from the response time and is slow but works when nothing is reflected.",
            "UNION query appends a second SELECT so its results come back in the response, and error-based provokes a database error containing the data you asked for. These are the strongest everyday results because data visibly crosses into the page. Stacked queries execute a second statement entirely, which is the most dangerous because writes become possible.",
            "Reproduce it before reporting. For boolean-based that means two requests side by side with a visible difference; for time-based it means repeated timings against a baseline so jitter is ruled out; for UNION it means the data itself, redacted if it is real. A tool's verdict is not evidence."
          ]
        }
      ]
    },
    'attackTools:cmdi': {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why are command injection and template injection grouped together?",
          lessonKey: "urlCmdiMethodology",
          answers: [
            "They share an outcome. Command injection appears wherever an application shells out, which is more places than you would expect: converting an image, generating a PDF, pinging a host, extracting an archive, calling a command-line utility because there was no library. Template injection appears when user input is used to build a template rather than being passed into one as data.",
            "Modern template engines are powerful enough that reaching the template language usually means reaching the runtime behind it, so both classes end at code execution on the server. Both are much rarer than injection into a database and worth far more when found.",
            "They are also the two classes where a careless payload does real damage. The safe proof for command injection is a delay or an out-of-band callback; for template injection it is arithmetic that comes back as a computed answer. Destructive payloads are never necessary and are frequently out of scope."
          ]
        },
        {
          question: "What do Commix, SSTImap, and TInjA each do, and which vectors are worth running them on?",
          lessonKey: "urlCmdiTools",
          answers: [
            "Commix specialises in command injection, trying a wide range of separators and encodings, handling blind cases, and escalating to an interactive shell once it succeeds. SSTImap detects template injection and then exploits it per engine. TInjA is the detection specialist, working out whether a template engine is reachable and which one, which makes it a good fast first pass before SSTImap.",
            "These tools cannot meaningfully test every vector and running them everywhere wastes hours. A parameter holding a numeric page index is not going to reach a shell. Spend the time on parameters whose names or values suggest a filename, a hostname, a command, a format, a template, or a rendered message.",
            "This is the section where the skipped list matters as much as the findings. A vector that was skipped was not tested, and a skipped vector is not a clean vector."
          ]
        },
        {
          question: "How do I confirm execution rather than a coincidence?",
          lessonKey: "urlCmdiValidation",
          answers: [
            "A slow response is the weakest signal because applications are slow for many reasons. Turn a delay into evidence by varying it: if a five second sleep gives a five second delay and a ten second sleep gives ten, against a prompt no-payload baseline, the delay is under your control.",
            "A callback is the strongest signal, since a request arriving at a host you own from the target's infrastructure has no innocent explanation. Use a unique identifier per vector so attribution is unambiguous, and record the source address, which often reveals internal infrastructure.",
            "Three things produce a meaningless clean result here: every eligible vector was skipped, the tool returned a cached verdict, or the tool refused its command line. A fourth is a collector that was never reachable, which turns every blind case into a silent clean."
          ]
        }
      ]
    },
    'attackTools:redirect-ssrf': {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why are open redirect and SSRF in the same section when their severity is so different?",
          lessonKey: "urlRedirectSsrfMethodology",
          answers: [
            "They start from the same input, a parameter holding a URL, and diverge on who follows it. If the browser follows it you have an open redirect, whose impact is modest alone and serious in combination: stealing an OAuth code through a redirect_uri, or a phishing link that starts on the real domain.",
            "If the server follows it you have server-side request forgery, and that matters because the server sits somewhere you do not. It can reach internal services, administrative interfaces, and on cloud platforms the instance metadata endpoint that hands out credentials. The same parameter can be low or critical depending on which of the two it is.",
            "Look past the obvious parameter names to features that fetch a URL by design: webhooks, link previews, image import by URL, PDF generation, feed readers, and connectivity tests. Those are the richest SSRF surface, because fetching a remote URL is their whole purpose."
          ]
        },
        {
          question: "How do Nuclei DAST, REcollapse, and SSRFmap fit together?",
          lessonKey: "urlRedirectSsrfTools",
          answers: [
            "They are a pipeline rather than three alternatives. Nuclei in DAST mode is the detector that actually finds the redirects and SSRF candidates. REcollapse is a mutation generator for defeating input filters, most useful on a parameter you already believe is interesting but which rejects direct payloads. SSRFmap is the exploitation stage and only makes sense once something has been found.",
            "Nuclei can be configured to emit a result for every request including non-matches, annotated as such. If whatever reads that output ignores the annotation, every non-match becomes a finding. During this project that produced 53 fabricated high-severity findings in one run.",
            "The other half of the trap is a weak matcher. An open-redirect check satisfied by the mere presence of a redirect will fire on every ordinary redirect on the site. When a scanner reports many identical high-severity findings across unrelated vectors, doubt the matcher: real vulnerabilities are not evenly distributed."
          ]
        },
        {
          question: "How do I confirm each of the two findings?",
          lessonKey: "urlRedirectSsrfValidation",
          answers: [
            "For a redirect, send the request with redirect following turned off and read the Location header. Following redirects automatically hides exactly the thing you are trying to see. The destination has to be a different origin to count, and the severity comes from where the parameter is used, especially if a login or OAuth flow decides where to send the user with it.",
            "For SSRF, the proof is a request arriving at infrastructure you control, from the target. Use a unique hostname per vector, and record the source address and timestamp. A DNS lookup alone is weaker evidence than a full HTTP request, so say which one you observed rather than describing both as the same thing.",
            "Most SSRF is blind, so an unreachable collector turns every case into a silent clean. Test that the collector is reachable before you conclude a target is not vulnerable."
          ]
        }
      ]
    },
    'attackTools:lfi': {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is the difference between reading a file and including one?",
          lessonKey: "urlLfiMethodology",
          answers: [
            "Path traversal is the read case: the application opens the file you named and sends it back, and traversal sequences walk out of the intended directory. What you get is disclosure, which is valuable when the file holds credentials, configuration, source, or keys.",
            "File inclusion is the execution case. On stacks where naming a file causes it to be interpreted rather than merely read, PHP being the classic example, controlling the filename can mean controlling what code runs. That changes the severity completely, so it is worth establishing which of the two you are dealing with.",
            "Look for names like file, path, page, template, and doc, but also for behaviour: anything that downloads, exports, previews, renders, or attaches is naming a file somewhere. Language and theme selectors are a frequently missed case because they map a short user string onto a path and are rarely thought of as file handling at all."
          ]
        },
        {
          question: "What do LFImap and LFIHunt do, and what makes them report a false clean?",
          lessonKey: "urlLfiTools",
          answers: [
            "LFImap is the broader tool, covering traversal, PHP wrappers, remote inclusion, and log-poisoning routes to execution, with a wide set of filter bypasses tried automatically. LFIHunt is more focused and includes a batch mode that is useful across many vectors at once. They overlap on plain traversal and diverge on the exotic techniques.",
            "The most common way to get a worthless clean result here is a malformed target URL. If the parameter is not correctly marked, the tool sends payloads to the wrong place and correctly reports that nothing came back. During this project a query-string handling bug did exactly that, and it affected every section sharing the same code path.",
            "The symptom is uniform results across vectors that should behave differently. Real applications are inconsistent, so when every vector returns exactly the same verdict in exactly the same way, suspect the harness rather than the target and run one vector by hand to check."
          ]
        },
        {
          question: "How do I prove a file was really read, and how far should I take it?",
          lessonKey: "urlLfiValidation",
          answers: [
            "The proof is content, not a status code. A 200 proves the endpoint answered and says nothing about what it answered with. Show recognisable file content the application has no legitimate reason to include, alongside the baseline response for the same endpoint without the traversal.",
            "Use a harmless, universally present file for the proof of concept so you establish the capability without exposing anything sensitive in the report. Then assess impact separately by working out which files are reachable, since application configuration usually holds the database credentials and API keys that turn a file read into something much larger.",
            "Restraint matters more here than in most classes because this is trivially over-exploitable. Reading one configuration file to demonstrate impact is proportionate; walking the filesystem or retrieving customer data is not. If you recover live credentials, redact them, report them, and do not use them."
          ]
        }
      ]
    },
    'attackTools:cache': {
      title: "Help Me Learn!",
      items: [
        {
          question: "What makes cache poisoning possible, and how is deception different?",
          lessonKey: "urlCacheMethodology",
          answers: [
            "A cache decides whether two requests are the same by hashing part of them, typically the method, host, and path, and often little else. Everything outside that key is unkeyed, and unkeyed input that still changes the response is the entire vulnerability.",
            "You send a request whose unkeyed part carries your payload, the cache stores the poisoned response under the ordinary key, and every subsequent visitor to that normal URL gets your content. That is why this is a stored attack even though nothing was written to the application's database.",
            "Deception is the mirror image: you persuade the cache to store a response containing someone else's private data under a URL you can then request, usually by making a dynamic page look like a static asset to the cache while the application still serves the personalised version."
          ]
        },
        {
          question: "How do WCVS and CacheBoom work, and how do they lose findings?",
          lessonKey: "urlCacheTools",
          answers: [
            "Unlike most tools here they do not test a parameter at an insertion point. They take a URL and vary the request around it, mostly headers, looking for anything unkeyed that changes the response. That is the right model for this class, because the payload usually goes in a header the vector list never captured, but it means the unit of work is the URL and you should choose cacheable pages deliberately.",
            "They produce results on standard output, and when that output is captured without being flushed properly the findings can be lost after the tool has already found them. The scan succeeds, the tool prints its result, and nothing reaches whatever was reading it. The visible outcome is a clean scan.",
            "The second silent failure is a cache that was never hit during the test. If nothing was cached, nothing can be poisoned, and the tool correctly reports nothing. Check the cache headers on a tested URL before believing a clean result."
          ]
        },
        {
          question: "How do I prove a cache was poisoned without affecting real users?",
          lessonKey: "urlCacheValidation",
          answers: [
            "The proof is three requests. A clean request recorded as the baseline, the poisoning request carrying your unkeyed payload, then a clean request from a fresh session showing your payload in a response that never carried it. That third request is the entire finding; the first two are setup.",
            "This is the class where careless testing does visible damage, because a poisoned response is served to real visitors until the entry expires. Work on a URL nobody else uses by adding a unique meaningless query parameter, which normally produces a distinct cache entry only you will request.",
            "Keep the payload harmless and identifiable, capture the cache status headers throughout, and tell the program which entry you affected and when so they can purge it. A report that names the affected cache key is far easier for a defender to clean up."
          ]
        }
      ]
    },
    'attackTools:smuggling': {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is a desync, and why is this the class to be most careful with?",
          lessonKey: "urlSmugglingMethodology",
          answers: [
            "HTTP has two ways to say how long a body is, a Content-Length header and chunked transfer encoding. When a front-end proxy and a back-end server resolve a conflict between them differently, the bytes between the two interpretations become the start of what the back end considers the next request.",
            "That leftover sits at the front of the connection waiting for the next real request to be appended to it, so the next user's request gets combined with your prefix. That is what lets this class redirect other users' requests, poison a shared cache, capture request data, or reach endpoints the front end would have refused.",
            "Everything about it affects other people by design, and a desynchronised connection can break traffic for unrelated users. Many programs restrict this class for exactly that reason, so read the rules first, keep the volume low, and prefer establishing that the desync exists over exploiting it."
          ]
        },
        {
          question: "What do smugglex and http2smugl cover, and why do they produce false positives?",
          lessonKey: "urlSmugglingTools",
          answers: [
            "smugglex works the classic ground of requests carrying both a Content-Length and a chunked encoding in the orderings and obfuscations that make two ends disagree. http2smugl targets what happens when a front end speaks HTTP/2 and downgrades to HTTP/1.1 for the back end, where length information has to be rewritten. The two families barely overlap, so run both.",
            "Both detect primarily by timing: a request crafted so a vulnerable server waits for bytes that never arrive produces a timeout, while a correct server responds normally. That makes a timeout the signal, and a timeout has many innocent causes.",
            "There are at least four: the target is slow under load, a rate limiter has started delaying you, a WAF is holding the connection, or the network hiccupped. All four look identical to the tool, so a single timing-based hit is a lead rather than a finding."
          ]
        },
        {
          question: "How do I tell a real desync from a slow server?",
          lessonKey: "urlSmugglingValidation",
          answers: [
            "The evidence is not that one request was slow. It is that a request crafted to desynchronise behaves differently from an otherwise identical request crafted not to, consistently across repetitions. That differential rules out load and jitter, because both would affect the two variants equally.",
            "Interleave the two variants rather than running them in blocks, so a change in the target's condition partway through cannot masquerade as a difference between them. Repeat until the pattern is unmistakable and record the actual timings rather than your impressions.",
            "Once the differential holds up you have enough to report. Full exploitation involves capturing another user's request or poisoning something shared, both of which affect real people and are usually beyond what you are authorised to do. Describe what the desync permits instead, and report it quickly, because it is dangerous while it exists."
          ]
        }
      ]
    },
    'attackTools:access-bypass': {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why is a 403 bypass possible at all, and what makes one a real finding?",
          lessonKey: "urlAccessBypassMethodology",
          answers: [
            "In a typical deployment the access rule and the routing live in different components. A proxy or gateway decides that requests to an administrative path are refused, and an application server decides which handler runs. If the two normalise the request differently, one can see a forbidden path where the other sees an ordinary one.",
            "The most productive family exploits forwarding headers, which exist so a proxy can tell a back end what the original request was. Where a back end routes on such a header while the front end applies its rules to the literal path, you get refused on one path and served another. Other families exploit normalisation differences such as slashes, case, and encoding, or simply change the verb.",
            "The finding is not a status code change, it is reaching protected content. The standard of proof is naming a privileged string in the body that the denial withheld: a username, an administrative control, a record. Without one you have a status code, not a finding."
          ]
        },
        {
          question: "What do nomore403 and Forbidden actually compare against?",
          lessonKey: "urlAccessBypassTools",
          answers: [
            "Both work through a matrix of techniques: forwarding headers, path mutations, alternative verbs, and origin claims. Families that were not run are untested rather than clean, so record which ones actually executed before reading a clean result as meaningful.",
            "The critical thing to understand is their baseline. Their only content baseline is the original denial. They compare a candidate against the 403 page and report a bypass if it differs enough. What they never do is fetch the URL they actually requested without the added header and compare against that.",
            "That omission is why so many findings here are false. If the tool requests an ordinary public page with an extra header that does nothing, the public page comes back, it differs from the denial page in both status and length, and it gets reported as a bypass. Nothing was bypassed; a public page was fetched."
          ]
        },
        {
          question: "What is the negative control, and why does it kill most of these findings?",
          lessonKey: "urlAccessBypassValidation",
          answers: [
            "Three requests in this order. First the protected path plainly, confirming it is still refused. Second the finding's own URL with no added header, which is the control and the request nobody makes. Third the finding's request exactly as reported.",
            "Compare the third against the control before comparing it against the denial. If it is identical to the control, the header changed nothing and the finding is dead, because the tool only noticed that an allowed page differs from a denial page. On the reference target, two of three reported bypasses were exactly this.",
            "If it survives, then compare against the denial and identify what came back that the denial withheld. Name the technique in the report, since it determines the fix, include all three exchanges so a sceptical triager can confirm in a minute, and try the working technique against every other protected path before submitting."
          ]
        }
      ]
    },
    'attackTools:graphql': {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why does GraphQL need its own section when it is just one endpoint?",
          lessonKey: "urlGraphqlMethodology",
          answers: [
            "That is exactly why. In a REST API each route is a separate thing to find and protect, so testing starts with enumerating routes. In GraphQL there is usually one route and what varies is the query, so enumerating paths tells you almost nothing while enumerating the schema tells you everything.",
            "Authorization is the biggest consequence. Each field's resolver has to make its own access decision, and it is very easy to protect a top-level query while leaving a nested field that reaches the same data unguarded. A query walking from an object you may see to a related object you may not is the archetypal GraphQL bug.",
            "Introspection is the front door: when it is enabled the server describes its entire schema on request, exposing internal mutations, administrative fields, and deprecated operations nobody removed. When it is disabled the schema is not secret so much as inconvenient, since field names can be recovered from the server's own suggestion messages."
          ]
        },
        {
          question: "What do graphw00f, graphql-cop, and Clairvoyance each contribute?",
          lessonKey: "urlGraphqlTools",
          answers: [
            "graphw00f fingerprints the server implementation, which matters more than it sounds because implementations differ in which protections they apply by default, how they handle batching, and what their errors reveal. Run it first so everything after is interpreted in context.",
            "graphql-cop audits the endpoint for common misconfigurations: introspection availability, whether GET is accepted for mutations, whether batching is allowed, whether field suggestions leak names. It is fast and makes the natural first pass. Clairvoyance is the recovery tool that rebuilds an approximate schema when introspection is off.",
            "Read the results carefully. Audit tools in this space tend to claim a known vulnerability based on a fingerprint rather than a test, so confirm any version-based claim yourself. Denial of service checks are the attack, so leave them disabled unless the program permits them, and note that exclusions match by name so a differently spelled check slips through."
          ]
        },
        {
          question: "How do I turn a misconfiguration into a finding with real impact?",
          lessonKey: "urlGraphqlValidation",
          answers: [
            "Introspection enabled is an observation. Introspection enabled plus a mutation that lets a standard user change another user's role is a finding, and the second half is the part that requires you rather than the tool.",
            "Start with mutations, since they change state and get less review than queries. Then look for fields that cross an ownership boundary, and test the same nested route with an identifier belonging to someone else. For availability issues demonstrate cost rather than damage: showing a modestly nested query takes many seconds establishes that no complexity limit exists without taking anything down.",
            "Because everything happens at one endpoint, the query text is the whole proof of concept. Quote it verbatim along with the response and the identity it was sent as, and for access-control findings show the same query under two identities so the difference is visible."
          ]
        }
      ]
    },
    'attackTools:sensitive-leak': {
      title: "Help Me Learn!",
      items: [
        {
          question: "How does sensitive data end up publicly readable in the first place?",
          lessonKey: "urlSensitiveLeakMethodology",
          answers: [
            "Three ways. Files get left where the web server will serve them, because a deployment copied a directory rather than a build: backups, database dumps, editor swap files, deployment archives, and configuration with the wrong extension. Secrets get compiled into client-side code, because anything the browser needs the browser has and minification hides nothing.",
            "The third is APIs returning more than the interface displays. An endpoint that returns a full user object so the page can show a display name is handing out email addresses, roles, internal identifiers, and sometimes password hashes to anyone who reads the response rather than the rendered page.",
            "Not every secret is a finding. Analytics identifiers, publishable payment keys, and map tokens are public by design, and reporting one as a leaked credential is a known way to waste a triager's time. Capability decides severity: a key that identifies is a note, a key that can read data or spend money is a finding."
          ]
        },
        {
          question: "What do snallygaster, Mantra, and TruffleHog each look at?",
          lessonKey: "urlSensitiveLeakTools",
          answers: [
            "Three different places. snallygaster works server-side, requesting a long list of paths that indicate a misconfigured deployment. Mantra works client-side, reading JavaScript for embedded credentials, which is where most of this problem lives now that so much logic ships to the browser. TruffleHog is the pattern matcher, and its distinguishing feature is verification: for many providers it can check whether a discovered credential is actually live.",
            "Verification is what converts a match into a finding, and it is the difference between a report a triager accepts immediately and one they close. But an unverified result is not the same as an invalid credential, since network restrictions and unsupported providers both produce one.",
            "Coverage is entirely determined by the directory list you supply. Point these at the site root only and they check the site root, so an application deployed under a path prefix will look clean while its real directory is untested."
          ]
        },
        {
          question: "How do I confirm a leak without making it worse?",
          lessonKey: "urlSensitiveLeakValidation",
          answers: [
            "For an exposed file, one unauthenticated request that returns the content is the whole proof. You do not need to download an entire database dump to establish that a database dump is downloadable.",
            "For a credential, the confirmation is knowing what it can do rather than doing it. If a verification check has already established it is live, quote that; otherwise describe its apparent scope from where it was found. Using someone's credential is a separate action that programs almost never authorise.",
            "If you retrieve real personal data, stop reading it. Note the categories, redact the specifics, and say clearly that you retained no copy. Report live credentials with urgency rather than sitting on them while you explore, because the exposure window is open to everyone else at the same time."
          ]
        }
      ]
    },
    'attackTools:exposed-git': {
      title: "Help Me Learn!",
      items: [
        {
          question: "Why is an exposed repository so much worse than one exposed file?",
          lessonKey: "urlExposedGitMethodology",
          answers: [
            "An exposed configuration file gives you that file. An exposed repository gives you the application: every source file, every configuration template, every deployment script, and the full history of changes with author names, timestamps, and commit messages.",
            "The history is the part people underestimate. Secrets get committed by accident, noticed, and removed in a later commit, but removing them from the current files does not remove them from the history. A repository that looks clean today can contain a live database password from eighteen months ago, so recovering deleted commits is routine here.",
            "Source access also converts the rest of the engagement, because every other bug class gets easier when you can read the code and see exactly which parameters are handled, where the validation is, and which access checks were forgotten."
          ]
        },
        {
          question: "How do git-dumper and GitTools rebuild a repository over plain HTTP?",
          lessonKey: "urlExposedGitTools",
          answers: [
            "Directory listing is usually disabled, so the tools cannot simply walk the directory. Instead they start from the files whose names are fixed, parse them, and follow the references inside: the index and reference files name commits, commits name trees, trees name blobs, and each is fetched by its own hash-derived path. From a handful of known filenames they recover the whole object graph.",
            "git-dumper does this end to end and produces a working repository. GitTools is modular, covering finding, dumping, and extracting separately, which is more useful when a dump is partial and you want to work with what was recovered.",
            "Partial recovery is normal and still valuable. Files excluded from version control were never in the repository, but loose objects that were never packed are recoverable individually, and that is exactly where deleted content lives. An incomplete dump is worth reading, not discarding."
          ]
        },
        {
          question: "How do I report this responsibly given that confirming it means downloading their source?",
          lessonKey: "urlExposedGitValidation",
          answers: [
            "The proof is that the metadata is publicly retrievable, which is a single request and its response. You do not need to include source code to establish that source code is exposed, and including it puts a copy of the target's intellectual property into a ticketing system.",
            "Where the history contains live credentials, that is a second and more urgent finding. Report it redacted, identify which system it is for so it can be rotated, and do not use it. Reading the source to guide your testing is legitimate research; extracting data from a database whose credentials you recovered is not.",
            "Say plainly what you did: that you confirmed the exposure, whether you reconstructed the repository, what you looked at, and that you deleted it. File it the day you find it rather than mining it for weeks, since the exposure is live the entire time."
          ]
        }
      ]
    },
    'attackTools:misc': {
      title: "Help Me Learn!",
      items: [
        {
          question: "What connects file upload bypass, JWT analysis, and prototype pollution?",
          lessonKey: "urlMiscMethodology",
          answers: [
            "Nothing, other than not fitting the other sections. Upload bypass is about defeating checks on what may be uploaded, and its severity depends entirely on what happens to the file afterwards: stored in object storage is low risk, written where the web server will execute it is remote code execution.",
            "JWT problems are all about what the server verifies. The classic failures are accepting an unsigned token, accepting an algorithm the caller chose, confusing symmetric with asymmetric, or not verifying the signature at all. Since anyone holding the token can read it, working out what the server trusts is straightforward.",
            "Prototype pollution is JavaScript object semantics: attacker-controlled keys merged into an object without filtering can modify the prototype every other object inherits from, changing the behaviour of code that never touched the input. It is routinely over-claimed, because setting a prototype property proves the merge is unsafe and nothing more. Impact needs a gadget."
          ]
        },
        {
          question: "What does each of Upload_Bypass, jwt_tool, and pphack need to work?",
          lessonKey: "urlMiscTools",
          answers: [
            "Upload_Bypass needs a marker telling it what a successful upload looks like. Without one it cannot distinguish success from rejection, and an unmarked run reports every attempt as a finding. jwt_tool configures its own proxy settings, which is surprising if traffic suddenly stops appearing where you expected it.",
            "pphack drives a headless browser, so it is slow, and because it depends on page timing it is not deterministic. Whether the page's own scripts have merged the payload into the prototype by the moment it looks is a race.",
            "That race was measured against a target pphack reports as vulnerable when run directly: three hits in six identical runs. At one run per vector that is a coin flip, so a clean result across two dozen vectors on a target with documented pollution is the expected outcome rather than a surprise. Timing-dependent detectors need repetition, not a single run."
          ]
        },
        {
          question: "How do I validate each of these three, and what are their specific false positives?",
          lessonKey: "urlMiscValidation",
          answers: [
            "For an upload, acceptance is not the finding. Retrieve the stored file and check whether it is served, from which origin, and whether it is interpreted rather than downloaded. For a JWT, modify a claim and see whether the server acts on the change; if it rejects the token, the signature is verified and there is nothing here regardless of what the token contains.",
            "For pollution, show both that the property can be set and that some code reads it and does something as a result. Only the second part is impact, and it is the part that has to appear in the report.",
            "The specific false positives: an unmarked upload run reports everything as successful; a privileged claim inside a token is entirely normal and only an accepted forgery is a finding; and pollution without a named gadget is a weakness rather than a vulnerability, which is how it should be described."
          ]
        }
      ]
    },
    urlThreatModelResults: {
      title: "Help Me Learn!",
      items: [
        {
          question: "How do I work through these six categories without drowning?",
          lessonKey: "urlThreatModelResultsMethodology",
          answers: [
            "Nothing on this page is a finding yet. A threat is a statement that something might be possible, which makes it a hypothesis with a test attached. You do not report a threat, you test it, and the result is either a finding with evidence or a threat you can close. Both are progress.",
            "That also means the model is only as good as its specificity. A threat saying the API might have authorization problems cannot be tested; one saying a standard user might read another user's order by changing the order identifier can be tested in a single request.",
            "Work spoofing and elevation of privilege first, because they cover authentication and authorization and those are the classes the tools above cannot find on their own. Use tampering and information disclosure as a coverage check on the scans you already ran. Repudiation is hard to test externally but worth recording, and denial of service is usually out of scope, so record it and stop."
          ]
        },
        {
          question: "What is the Possible Attacks list for?",
          lessonKey: "urlThreatModelResultsAttacks",
          answers: [
            "Knowing an endpoint has a spoofing threat does not tell you what to send. The attack list closes that gap by naming the concrete techniques under each category, so instead of thinking about spoofing in the abstract you work through session fixation, token forgery, weak credential recovery, and the rest.",
            "It is most useful when a category is new to you, and it stays useful as a completeness check: working down the list and asking whether each technique applies catches the ones you would have skipped because they never occurred to you.",
            "Filter by what you already know. If you recorded that the application uses session cookies rather than bearer tokens, the token-specific techniques drop away immediately. Where a technique clearly applies but you cannot test it from where you are, record that rather than skipping it silently, because it tells the program where to look with the access you do not have."
          ]
        },
        {
          question: "How do I turn the model into a test plan and then into a report?",
          lessonKey: "urlThreatModelResultsPrioritization",
          answers: [
            "Order by two things: how bad it would be if true, and whether you can actually demonstrate it. A critical threat you cannot reach is worth less of your time than a high one you can test in five minutes. Anything touching money, personal data, authentication, or permissions goes near the top by default.",
            "Reachability is the factor people forget. A threat against an administrative function you have no account for may be untestable directly but reachable indirectly, through an access-control bypass or an endpoint that was never protected in the first place. That indirect route is usually where the interesting work is.",
            "A confirmed threat is already most of a report: the endpoint, the mechanism, the object at risk, the steps, and the impact assessment. Add the evidence and you are done. Keep the threats you disproved rather than deleting them, since they record what you checked and stop you re-testing the same thing next month."
          ]
        }
      ]
    },
    amass: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish?",
          lessonKey: "amassEnumMethodology",
          answers: [
            "We're in the Subdomain Enumeration phase of the Bug Bounty Hunting methodology, specifically focused on discovering all subdomains associated with a single target domain to map the complete attack surface for that domain.",
            "Our goal is to find a comprehensive list of subdomains for the target root domain that point to live web servers, APIs, applications, and services. Each discovered subdomain represents a potential target for vulnerability assessment and bug bounty testing.",
            "This phase transforms a single root domain into a detailed map of all discoverable digital assets associated with that domain, providing the foundation for systematic security testing and vulnerability discovery across the target's subdomain infrastructure."
          ]
        },
        {
          question: "What is Amass and how does it systematically discover subdomains?",
          lessonKey: "amassEnumCapabilities",
          answers: [
            "Amass is a comprehensive subdomain enumeration framework that combines passive reconnaissance, active DNS queries, and data source integration to systematically discover subdomains associated with target domains through multiple discovery vectors and techniques.",
            "The tool employs both passive techniques (querying external databases, certificate transparency logs, search engines) and active techniques (DNS brute-forcing, zone transfers, DNS record analysis) to ensure comprehensive subdomain discovery coverage.",
            "Amass integrates dozens of data sources including certificate transparency logs, DNS databases, search engines, threat intelligence feeds, and public datasets to maximize subdomain discovery while maintaining stealth and avoiding detection by target infrastructure.",
            "The framework provides intelligent result correlation, confidence scoring, and infrastructure mapping that helps distinguish between legitimate organizational subdomains and false positives, enabling effective analysis of large result sets."
          ]
        },
        {
          question: "How do I analyze and utilize Amass enumeration results effectively?",
          lessonKey: "amassEnumAnalysis",
          answers: [
            "Scan History provides chronological tracking of enumeration activities, enabling comparison of results across different time periods and helping identify new subdomains or changes in the target's infrastructure over time.",
            "Raw Results contain the complete enumeration output with detailed metadata including IP addresses, DNS record types, data sources, and confidence scores that provide comprehensive intelligence for subsequent analysis and testing activities.",
            "DNS Records offer detailed technical information about discovered subdomains including A records, CNAME records, MX records, and other DNS configurations that reveal infrastructure patterns, hosting relationships, and potential security boundaries.",
            "Infrastructure View provides organizational analysis of discovered assets including technology identification, hosting provider analysis, and network relationship mapping that helps understand the target's architecture and identify high-value testing targets."
          ]
        }
      ]
    },
    subdomainScraping: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what complementary discovery do subdomain scraping tools provide?",
          lessonKey: "subdomainScrapingMethodology",
          answers: [
            "We're in the Passive Subdomain Discovery phase, which complements Amass enumeration by leveraging additional data sources and discovery techniques that might reveal subdomains missed by traditional DNS enumeration methods.",
            "Subdomain scraping tools use diverse discovery vectors including web crawling, JavaScript analysis, search engine queries, public dataset mining, and certificate transparency analysis to find subdomains through non-DNS methods.",
            "This phase ensures comprehensive subdomain coverage by accessing different data sources and using varied discovery techniques, often revealing subdomains that are referenced in web content, documentation, or public databases but not directly discoverable through DNS queries."
          ]
        },
        {
          question: "How do the different subdomain scraping tools provide unique discovery capabilities?",
          lessonKey: "subdomainScrapingTools",
          answers: [
            "Gau (GetAllUrls) discovers URLs and endpoints from web archives, providing historical subdomain information and revealing URL patterns that might indicate additional subdomains or services not currently active but historically significant.",
            "Passive OSINT aggregates multiple free, key-less public sources (RapidDNS, URLScan.io, AlienVault OTX, HackerTarget) to discover subdomains that other observers have already recorded, without scraping search engines or sending any traffic to the target.",
            "Assetfinder specializes in fast DNS-based subdomain enumeration using multiple resolvers and data sources, providing rapid discovery of DNS-resolvable subdomains with minimal infrastructure impact.",
            "Certificate Transparency Log (CTL) searches reveal subdomains that have been issued SSL certificates, including internal or non-public subdomains that organizations secure with certificates but don't publicly advertise."
          ]
        },
        {
          question: "How do I systematically utilize subdomain scraping tools and prepare for consolidation?",
          lessonKey: "subdomainScrapingWorkflow",
          answers: [
            "Start with parallel execution of multiple tools to maximize discovery coverage: run Gau for historical URL discovery, Passive OSINT for multi-source passive aggregation, Assetfinder for DNS enumeration, and CTL for certificate analysis simultaneously.",
            "After completing tool execution, analyze results in their respective modals to understand what each tool discovered and identify patterns or unique findings that might warrant additional investigation or reveal organizational infrastructure characteristics.",
            "Document discovery sources and context for each subdomain to help with validation and prioritization decisions during subsequent consolidation and live web server discovery phases.",
            "This systematic discovery workflow prepares comprehensive subdomain lists from multiple passive sources that will be consolidated and validated for live web services in the next phase of the methodology."
          ]
        }
      ]
    },
    consolidationRound1: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and why is the first consolidation round critical?",
          lessonKey: "consolidationRound1Methodology",
          answers: [
            "We're at the First Consolidation and Live Web Server Discovery phase, which represents the critical transition from raw subdomain discovery to verified, accessible targets after completing passive subdomain scraping with multiple tools.",
            "This round consolidates all subdomains discovered through Amass enumeration and passive scraping tools (Gau, Passive OSINT, Assetfinder, CTL) into a single deduplicated list, eliminating redundancy while preserving valuable discovery metadata.",
            "The live web server discovery component uses Httpx to systematically probe all consolidated subdomains to identify which ones actually host active web services, transforming raw subdomain lists into actionable testing targets.",
            "This phase is critical because it establishes the baseline of confirmed live web servers before proceeding to more aggressive discovery techniques, ensuring that subsequent brute-force testing builds upon a solid foundation of verified assets."
          ]
        },
        {
          question: "How does the consolidation process systematically organize and deduplicate discoveries?",
          lessonKey: "consolidationRound1Process",
          answers: [
            "The consolidation process combines subdomain discoveries from all passive sources (Amass, Gau, Passive OSINT, Assetfinder, CTL) into a unified dataset while maintaining source attribution to understand which discovery methods were most effective for the target organization.",
            "Intelligent deduplication removes exact duplicates and normalizes subdomain formats while preserving discovery context and confidence indicators that help prioritize targets based on the reliability and frequency of discovery across multiple sources.",
            "Source correlation analysis identifies subdomains discovered by multiple tools, which typically indicates higher confidence in organizational ownership and legitimacy, helping focus subsequent analysis on the most reliable discovered assets.",
            "The systematic approach ensures that no discovered subdomains are lost during consolidation while organizing the results in a format that enables effective analysis and prioritization for live web server discovery."
          ]
        },
        {
          question: "How does Httpx efficiently discover and analyze live web services?",
          lessonKey: "consolidationRound1Httpx",
          answers: [
            "Httpx performs high-speed HTTP probing across all consolidated subdomains to identify which ones host active web services, using intelligent request handling and concurrent processing to efficiently validate large subdomain lists.",
            "The tool gathers comprehensive metadata during probing including HTTP status codes, response headers, page titles, technology indicators, and security configurations that provide valuable intelligence for subsequent target prioritization and analysis.",
            "Httpx includes advanced filtering and analysis capabilities that help categorize discovered live services by functionality, technology stack, and security posture, enabling effective identification of high-value targets for security assessment.",
            "The systematic validation process transforms raw subdomain intelligence into a verified inventory of live web servers with detailed metadata that serves as the foundation for strategic target selection and vulnerability assessment planning."
          ]
        }
      ]
    },
    bruteForce: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and why is brute-force subdomain discovery essential?",
          lessonKey: "bruteForceMethodology",
          answers: [
            "We're in the Active Subdomain Discovery phase, which systematically tests potential subdomain names against the target domain to discover subdomains that weren't found through passive reconnaissance or public data sources.",
            "Brute-force discovery is essential because it can find hidden, internal, or forgotten subdomains that organizations don't publicly advertise but still maintain for development, testing, administration, or legacy purposes.",
            "This aggressive discovery technique complements passive methods by systematically testing common subdomain patterns, organizational naming conventions, and wordlist-based combinations to ensure comprehensive coverage of the target's subdomain space.",
            "Brute-force discovery often reveals high-value targets including development environments, staging servers, administrative interfaces, and internal tools that may have weaker security controls due to their intended non-public nature."
          ]
        },
        {
          question: "How do brute-force subdomain discovery tools systematically find hidden subdomains?",
          lessonKey: "bruteForceTools",
          answers: [
            "Subfinder combines multiple data sources with DNS brute-forcing capabilities, using both passive reconnaissance and active enumeration to discover subdomains through comprehensive coverage of available intelligence sources and systematic testing.",
            "ShuffleDNS specializes in high-performance DNS brute-forcing using optimized resolver management, concurrent query handling, and intelligent wordlist processing to efficiently test thousands of potential subdomain combinations against target domains.",
            "CeWL (Custom Word List) generates targeted wordlists by crawling target websites and extracting words that might be used in subdomain naming conventions, creating organization-specific wordlists that improve brute-force effectiveness.",
            "GoSpider performs intelligent web crawling to discover subdomains referenced in JavaScript files, HTML content, and web application resources, finding subdomains through application analysis rather than traditional DNS techniques."
          ]
        },
        {
          question: "How do I optimize brute-force discovery and manage the systematic workflow?",
          lessonKey: "bruteForceWorkflow",
          answers: [
            "Execute tools in strategic sequence: start with Subfinder for baseline discovery, use ShuffleDNS for systematic brute-forcing, generate custom wordlists with CeWL based on target content, and employ GoSpider for application-level subdomain discovery.",
            "Monitor tool execution and adjust parameters based on target responsiveness and DNS infrastructure characteristics to optimize discovery speed while avoiding overwhelming target systems or triggering security monitoring.",
            "After completing brute-force discovery, systematically review results in tool-specific modals to understand discovery patterns, identify interesting findings, and validate that discovered subdomains represent legitimate organizational assets.",
            "Use the Consolidate function to combine brute-force discoveries with previous passive discoveries, then perform Httpx validation to create a comprehensive, verified list of live web servers across all discovered subdomains."
          ]
        }
      ]
    },
    consolidationRound2: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and how does the second consolidation build upon previous discoveries?",
          lessonKey: "consolidationRound2Methodology",
          answers: [
            "We're at the Second Consolidation and Live Web Server Discovery phase, which combines the results from passive discovery methods with newly discovered subdomains from active brute-force enumeration to create an expanded and comprehensive target list.",
            "This round consolidates previous discoveries from Round 1 with new subdomains found through brute-force techniques (Subfinder, ShuffleDNS, CeWL, GoSpider), ensuring that both passive and active discovery results are systematically integrated.",
            "The second Httpx validation identifies live web services among newly discovered subdomains while updating the comprehensive inventory of all accessible targets, providing expanded attack surface coverage for security assessment.",
            "This phase builds strategic value by revealing hidden and internal subdomains that weren't discoverable through passive methods, often including development environments and administrative interfaces with potentially weaker security controls."
          ]
        },
        {
          question: "How does the second consolidation integrate active discovery results with existing intelligence?",
          lessonKey: "consolidationRound2Integration",
          answers: [
            "The integration process merges brute-force discoveries with the existing consolidated subdomain list while maintaining discovery source attribution and confidence scoring to understand the effectiveness of different enumeration strategies.",
            "Cross-validation between passive and active discoveries helps identify subdomains found through multiple methods, which typically indicates higher confidence and greater potential significance for security testing priorities.",
            "The systematic approach ensures that newly discovered subdomains from brute-force testing are properly validated and categorized alongside existing discoveries, maintaining comprehensive coverage while avoiding duplication of effort.",
            "Enhanced metadata correlation combines intelligence from both passive and active sources to build comprehensive profiles of discovered assets including discovery confidence, source diversity, and potential organizational significance."
          ]
        },
        {
          question: "What strategic value does the second round of live web server discovery provide?",
          lessonKey: "consolidationRound2Value",
          answers: [
            "The second Httpx validation often reveals hidden and internal subdomains discovered through brute-force testing that represent high-value targets including development environments, staging servers, and administrative interfaces not found through passive discovery.",
            "Expanded live service inventory provides broader attack surface coverage and reveals organizational infrastructure patterns that help understand technology deployment strategies and potential security boundaries within the target organization.",
            "The cumulative intelligence from two rounds of discovery and validation enables more sophisticated target prioritization based on discovery patterns, service characteristics, and potential security significance for vulnerability assessment activities.",
            "This phase often provides the critical mass of verified targets needed for comprehensive security assessment while revealing organizational assets that might have been missed through passive discovery alone."
          ]
        }
      ]
    },
    javascriptDiscovery: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what unique discovery capabilities does JavaScript analysis provide?",
          lessonKey: "javascriptDiscoveryMethodology",
          answers: [
            "We're in the Application-Level Asset Discovery phase, which analyzes web applications, JavaScript files, and client-side code to discover subdomains, endpoints, and infrastructure references that aren't discoverable through traditional DNS or network-based reconnaissance.",
            "JavaScript analysis provides unique discovery capabilities because modern web applications often contain references to internal APIs, development environments, staging servers, and infrastructure components embedded in client-side code that developers might not realize are exposed.",
            "This discovery method complements DNS-based techniques by finding subdomains and services that are dynamically loaded, referenced through application logic, or embedded in configuration files and scripts that aren't linked through traditional web navigation or DNS records.",
            "Application-level discovery often reveals high-value targets including API endpoints, internal tools, development environments, and administrative interfaces that may have relaxed security controls or contain sensitive functionality."
          ]
        },
        {
          question: "How do JavaScript discovery tools systematically analyze applications for hidden assets?",
          lessonKey: "javascriptDiscoveryTools",
          answers: [
            "GoSpider performs intelligent web application crawling that analyzes JavaScript files, HTML content, and embedded resources to discover subdomain references, API endpoints, and infrastructure components through comprehensive application mapping and content analysis.",
            "Subdomainizer specializes in extracting subdomains from JavaScript files, web content, and application resources using pattern matching and content analysis to identify domain references that might not be discoverable through traditional enumeration techniques.",
            "Nuclei Screenshot provides visual documentation of discovered assets by capturing screenshots of web applications and services, enabling rapid visual assessment of discovered subdomains and helping identify interesting applications for deeper investigation.",
            "These tools work synergistically to provide both discovery capabilities (finding hidden assets) and analysis capabilities (understanding application functionality and prioritizing targets for security assessment)."
          ]
        },
        {
          question: "How do I systematically execute JavaScript discovery and analyze application-level findings?",
          lessonKey: "javascriptDiscoveryWorkflow",
          answers: [
            "Begin with GoSpider crawling of discovered live web servers to systematically analyze JavaScript files, HTML content, and application resources across all identified subdomains and web applications.",
            "Execute Subdomainizer analysis on crawled content to extract additional subdomain references, API endpoints, and infrastructure components that might be embedded in application code or configuration files.",
            "Use Nuclei Screenshot to capture visual evidence of discovered applications and services, providing rapid visual assessment capabilities and documentation for subsequent manual analysis and testing activities.",
            "After completing JavaScript discovery, consolidate all discovered subdomains and endpoints with previous findings, perform final Httpx validation to identify live services, and analyze results to prioritize targets based on functionality, technology stack, and potential security impact."
          ]
        }
      ]
    },
    consolidationRound3: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and why is the final consolidation round strategically important?",
          lessonKey: "consolidationRound3Methodology",
          answers: [
            "We're at the Final Consolidation and Live Web Server Discovery phase, which represents the culmination of comprehensive subdomain discovery by integrating application-level findings with all previous passive and active enumeration results.",
            "This round consolidates discoveries from JavaScript analysis and web content extraction with the complete inventory from previous rounds, ensuring that application-embedded references and dynamically loaded subdomains are included in the final target list.",
            "The final Httpx validation provides the most comprehensive verification of all discovered subdomains, creating the definitive inventory of live web services that will guide strategic decision-making at the Wildcard Decision Point.",
            "This phase is strategically important because it ensures complete attack surface coverage by incorporating subdomains that are only discoverable through application analysis, often revealing internal APIs and development resources not found through other methods."
          ]
        },
        {
          question: "How does the final consolidation achieve comprehensive attack surface coverage?",
          lessonKey: "consolidationRound3Completeness",
          answers: [
            "The final consolidation integrates subdomains discovered through three distinct methodologies: passive reconnaissance (Amass, scraping tools), active enumeration (brute-force techniques), and application analysis (JavaScript content extraction).",
            "Application-level discoveries often reveal unique assets including internal APIs, development environments, and infrastructure references embedded in client-side code that represent high-value targets not discoverable through traditional DNS-based techniques.",
            "The comprehensive approach ensures that no significant subdomain discovery vector is overlooked, providing complete visibility into the target's discoverable attack surface across all available reconnaissance methodologies and data sources.",
            "Cross-correlation analysis across all three discovery phases helps identify the most reliable and significant targets while providing confidence assessment based on discovery frequency and source diversity."
          ]
        },
        {
          question: "How does the final live web server discovery prepare for strategic decision-making?",
          lessonKey: "consolidationRound3Preparation",
          answers: [
            "The final Httpx validation creates the definitive inventory of live web services with comprehensive metadata that serves as the foundation for strategic target selection and vulnerability assessment planning at the Decision Point.",
            "Enhanced metadata collection during the final validation includes detailed technology identification, security posture analysis, and functionality assessment that enables sophisticated target prioritization based on potential security impact and testing value.",
            "The systematic organization of all discovered live services by functionality, technology stack, and discovery confidence provides the intelligence framework needed for informed decision-making about scope target selection and resource allocation.",
            "This comprehensive live service inventory enables strategic assessment of the complete discoverable attack surface, ensuring that subsequent testing decisions are based on complete organizational visibility rather than partial intelligence."
          ]
        }
      ]
    },
    decisionPoint: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what strategic decisions must be made at the Decision Point?",
          lessonKey: "wildcardDecisionMethodology",
          answers: [
            "We're at the Wildcard Decision Point, which represents the culmination of comprehensive subdomain discovery where all reconnaissance results are evaluated to make strategic decisions about target selection and vulnerability assessment priorities for the discovered attack surface.",
            "At this critical juncture, we must transform raw subdomain discovery data into actionable testing strategy by evaluating discovered assets based on their potential security impact, business importance, and likelihood of containing vulnerabilities.",
            "The Decision Point requires balancing comprehensive coverage with focused testing by selecting targets that maximize the potential for finding significant vulnerabilities while considering factors like application functionality, technology stack, and organizational importance.",
            "This phase transforms reconnaissance intelligence into strategic testing decisions that will guide all subsequent vulnerability assessment activities and determine the success of the security testing engagement."
          ]
        },
        {
          question: "How do I systematically evaluate and prioritize discovered subdomains for security testing?",
          lessonKey: "wildcardDecisionEvaluation",
          answers: [
            "Start by analyzing the consolidated list of live web servers to understand the complete attack surface: categorize discoveries by functionality (administrative interfaces, APIs, customer applications), technology stack (frameworks, platforms, services), and organizational context (development, production, legacy).",
            "Use the ROI (Return on Investment) Report to systematically evaluate targets based on security indicators including missing security headers, interesting technologies, unusual configurations, and response characteristics that suggest potential vulnerabilities or security weaknesses.",
            "Prioritize assets that demonstrate high-value characteristics including administrative functionality, development environment indicators, interesting technology stacks, weak security configurations, or unusual response patterns that suggest potential security issues.",
            "Cross-reference technical findings with business intelligence about the target organization to understand which discovered assets might handle sensitive data, provide critical functionality, or represent important business operations that would have significant impact if compromised."
          ]
        },
        {
          question: "What criteria should guide target selection and scope management decisions?",
          lessonKey: "wildcardDecisionCriteria",
          answers: [
            "Focus on assets that provide the greatest potential for significant security findings: administrative interfaces with elevated access, development environments with relaxed security controls, legacy applications with outdated technologies, and services with interesting or unusual configurations.",
            "Consider the business context and potential impact of discovered assets: customer-facing applications that could affect user data, internal tools that might provide access to sensitive information, and integration points that could enable lateral movement or privilege escalation.",
            "Balance comprehensive testing coverage with resource limitations by selecting a diverse mix of high-confidence targets likely to yield findings and exploratory targets that might reveal unexpected vulnerabilities or provide insights into organizational security practices.",
            "Use the 'Add URL Scope Target' functionality strategically to create a manageable set of testing targets that represent the most promising opportunities for vulnerability discovery while ensuring systematic coverage of different attack surface categories."
          ]
        }
      ]
    },
         companyNetworkRanges: {
       title: "Help Me Learn!",
       items: [
         {
           question: "What stage of the methodology are we at and what are we trying to accomplish?",
           lessonKey: "reconnaissancePhase",
           answers: [
             "This workflow is part of the Reconnaissance (Recon) phase of the Bug Bounty Hunting methodology, specifically focused on discovering on-premises infrastructure and network assets.",
             "We have identified a target company and now our goal is to find bug bounty targets (web servers or other services) that are running on on-premises assets. We're going from a company name to a list of network ranges that we can use to find live IP addresses later.",
             "This approach helps us discover the organization's complete on-premises attack surface, including data centers, internal networks, and infrastructure components that might contain vulnerable services or applications not visible through public domain reconnaissance."
           ]
         },
         {
           question: "How do ASNs and network ranges help us understand an organization's complete attack surface?",
           lessonKey: "asnNetworkRanges",
           answers: [
             "Autonomous System Numbers (ASNs) are unique identifiers assigned to networks that operate under a single administrative domain. They represent routing domains on the internet and help identify which organization controls specific IP address ranges.",
             "Network ranges are blocks of IP addresses that belong to an organization, typically defined by CIDR notation (e.g., 192.168.1.0/24). These ranges represent the organization's on-premises infrastructure, data centers, and network boundaries.",
             "In bug bounty hunting, understanding ASNs and network ranges is crucial because they reveal the complete attack surface beyond just public-facing domains. This includes internal services, development environments, admin interfaces, and infrastructure components that might be vulnerable but not publicly advertised."
           ]
         },
         {
           question: "What are Amass Intel and Metabigor, and how do they discover network infrastructure?",
           lessonKey: "amassIntelMetabigor",
           answers: [
             "Amass Intel is a specialized module of the Amass framework that focuses on gathering intelligence about organizations' network infrastructure. It queries various data sources including WHOIS records, DNS databases, and routing registries to discover ASN information, IP address ranges, and associated domains that belong to the target organization.",
             "Metabigor is an OSINT tool that specializes in discovering network ranges and infrastructure information through multiple techniques. It searches through public databases, routing registries, and internet registries to find IP ranges, subnets, and network blocks associated with target organizations, often uncovering infrastructure that isn't publicly advertised.",
             "Both tools work by querying authoritative sources like Regional Internet Registries (RIRs), routing databases, and public records to map out an organization's complete network footprint. They complement each other by using different data sources and discovery methods to ensure comprehensive coverage of the target's infrastructure."
           ]
         }
       ]
     },
         companyLiveWebServers: {
       title: "Help Me Learn!",
       items: [
         {
           question: "Where are we in the bug bounty methodology and what's our objective?",
           lessonKey: "liveWebServersMethodology",
           answers: [
             "We're in the Network Infrastructure Discovery phase, specifically focused on converting discovered network ranges into live, accessible web servers that could be bug bounty targets.",
             "Our goal is to find active web services running on IP addresses within the organization's network ranges. We're looking for web servers, APIs, admin panels, and other HTTP/HTTPS services that weren't discovered through domain-based reconnaissance.",
             "This phase bridges the gap between having network ranges (IP blocks) and having specific targets (URLs) that can be tested for vulnerabilities. We're essentially scanning the organization's on-premises infrastructure for live web services."
           ]
         },
         {
           question: "How does the IP/Port scanning workflow discover live web servers from network ranges?",
           lessonKey: "ipPortScanningProcess",
           answers: [
             "The process starts by taking consolidated network ranges (CIDR blocks) and systematically probing each IP address within those ranges to identify live hosts using TCP connect probes on common ports like 80, 443, 22, and others.",
             "Once live IP addresses are identified, the system performs targeted port scanning on web-specific ports (80, 443, 8080, 8443, 3000, etc.) to discover which hosts are running web services.",
             "For each discovered web service, the system makes HTTP/HTTPS requests to gather metadata including status codes, page titles, server headers, technologies, and response characteristics to build a comprehensive inventory of live web servers."
           ]
         },
         {
           question: "What tools and techniques are used in this discovery process?",
           lessonKey: "liveWebServerTools",
           answers: [
             "The workflow uses custom IP/Port scanning tools that perform TCP connect scans across network ranges, testing both host discovery ports and web service ports to identify active services.",
             "After discovering live web servers, the Gather Metadata function uses tools like Katana for web crawling and content analysis to extract additional information about the discovered services, including page content, links, and potential entry points.",
             "The entire process is designed to be efficient and respectful, using rate limiting, timeouts, and concurrent connection limits to avoid overwhelming target infrastructure while still providing comprehensive coverage."
           ]
         }
       ]
     },
    companyRootDomainDiscovery: {
      title: "Help Me Learn!",
      items: [
        {
          question: "Where are we in the bug bounty methodology and what are we trying to discover?",
          lessonKey: "rootDomainMethodology",
          answers: [
            "We're in the Root Domain Discovery phase of the reconnaissance methodology, specifically focused on identifying all primary domains owned or controlled by the target organization without requiring premium API access.",
            "Our goal is to discover the complete domain portfolio of the organization, including primary business domains, subsidiary domains, acquisition-related domains, and alternative domains used for different business units or purposes.",
            "This phase expands our attack surface beyond any single domain provided in the scope, helping us discover forgotten domains, development environments, or subsidiary assets that might have weaker security controls."
          ]
        },
        {
          question: "How do Google Dorking, CRT, and Reverse WHOIS discover organizational domains?",
          lessonKey: "noApiKeyTools",
          answers: [
            "Google Dorking uses sophisticated search operators to query search engines for domains, subdomains, and organizational mentions in public documents, job postings, news articles, and other indexed content that might reveal additional domains owned by the organization.",
            "Certificate Transparency (CRT) searches public certificate logs that record all SSL/TLS certificates issued for domains. This reveals domains that have obtained certificates, including internal or non-public domains that organizations might not advertise but still secure with SSL.",
            "Reverse WHOIS performs lookups using organizational information like company names, email addresses, or phone numbers from domain registration records to find other domains registered by the same entity or using the same contact information."
          ]
        },
        {
          question: "What types of domains should we prioritize and investigate further?",
          lessonKey: "rootDomainPrioritization",
          answers: [
            "Focus on domains that might represent forgotten or legacy infrastructure, subsidiary companies, development environments, or alternative business units that could have different security postures than the main corporate domains.",
            "Prioritize domains with unusual naming conventions, geographical indicators, or technology-specific patterns that might indicate internal tools, admin interfaces, or specialized business functions.",
            "Look for domains that might be less monitored or maintained, such as acquisition-related domains, legacy brand domains, or domains used for specific business initiatives that might have been deprioritized over time."
          ]
        }
      ]
    },
    companyRootDomainDiscoveryAPI: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish?",
          lessonKey: "apiKeyMethodologyPosition",
          answers: [
            "We're in the Advanced Root Domain Discovery phase of the reconnaissance methodology, using premium API-based tools to discover organizational domains that aren't findable through free public sources.",
            "Our goal is to leverage specialized databases and intelligence services to find additional root domains, subsidiary domains, and infrastructure information that requires paid access to comprehensive data sources.",
            "This phase complements the free tools by accessing premium databases, proprietary intelligence feeds, and specialized search capabilities that often reveal domains missed by public sources, providing a more complete view of the organization's digital footprint."
          ]
        },
        {
          question: "What are the API-based tools and why do they provide better intelligence than free sources?",
          lessonKey: "apiKeyToolsCapabilities",
          answers: [
            "SecurityTrails provides comprehensive DNS intelligence, historical DNS records, and domain relationships from their massive database of internet infrastructure changes over time. Their API access reveals patterns and connections not visible through standard DNS queries.",
            "GitHub Recon searches millions of public repositories for organizational mentions, domain references, and infrastructure details that developers might have inadvertently exposed in code, configuration files, or documentation.",
            "Shodan offers internet-wide scanning data and device discovery, revealing internet-connected infrastructure, services, and devices associated with the organization's IP ranges and domains.",
            "Censys provides certificate transparency data, internet-wide scanning results, and device fingerprinting that can reveal domains, subdomains, and infrastructure not discoverable through traditional reconnaissance methods."
          ]
        },
        {
          question: "How do I prioritize and analyze results from premium API sources?",
          lessonKey: "apiKeyResultsPrioritization",
          answers: [
            "Focus on domains and infrastructure that appear in multiple API sources, as cross-validation from different premium databases increases confidence in the findings and suggests active or important organizational assets.",
            "Prioritize domains with recent activity, certificate issuance, or infrastructure changes, as these often indicate active development projects, new business initiatives, or recently acquired assets that might have integration vulnerabilities.",
            "Look for patterns that suggest forgotten or legacy infrastructure, development environments, or subsidiary assets that might have weaker security controls due to different management or oversight levels.",
            "Pay special attention to domains and services that appear in code repositories or have associated infrastructure details, as these often represent internal tools, APIs, or services that weren't intended for public discovery."
          ]
        }
      ]
    },
    companySubdomainEnumeration: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish?",
          lessonKey: "companyDNSEnumerationMethodology",
          answers: [
            "We're in the Company-Wide Subdomain Enumeration phase, which systematically discovers all subdomains across the organization's entire validated domain portfolio rather than focusing on individual domains.",
            "Our goal is to create a comprehensive map of all web applications, services, and digital assets that exist as subdomains across every root domain owned by the target organization, providing complete attack surface visibility.",
            "This phase bridges the gap between having a list of organizational root domains and having specific testable targets (URLs) by discovering the actual web services and applications running on those domains' subdomains."
          ]
        },
        {
          question: "How do company-wide DNS enumeration tools systematically discover organizational subdomains?",
          lessonKey: "companyDNSEnumerationTools",
          answers: [
            "Amass Enum Company performs comprehensive subdomain enumeration across multiple organizational domains simultaneously, using passive reconnaissance, active DNS queries, and external data sources to discover subdomains at scale while maintaining efficiency through intelligent resource management.",
            "DNSx Company provides DNS resolution and validation services that verify discovered subdomains, resolve their IP addresses, and gather metadata about hosting infrastructure, response times, and service availability across the entire organizational domain portfolio.",
            "Katana Company performs intelligent web crawling and content analysis across organizational domains to discover additional subdomains through JavaScript analysis, link extraction, and application mapping that reveals assets not found through traditional DNS enumeration."
          ]
        },
        {
          question: "How do I analyze and prioritize results from company-wide subdomain enumeration?",
          lessonKey: "companyDNSEnumerationAnalysis",
          answers: [
            "Start by categorizing discovered subdomains by patterns and functions: development environments (dev-, staging-, test-), administrative interfaces (admin-, portal-, mgmt-), geographical regions, and business units to understand the organizational structure and identify high-value targets.",
            "Use technology detection and response analysis to identify subdomains running interesting technologies, unusual configurations, or services that might indicate development environments, legacy systems, or specialized business applications with potentially weaker security controls.",
            "Prioritize subdomains that suggest elevated access or sensitive functionality, such as administrative panels, API endpoints, internal tools, monitoring dashboards, or services with unusual authentication requirements that could provide significant impact if compromised.",
            "Cross-reference subdomain discovery results with business intelligence about the organization to understand which subdomains might serve critical business functions, contain sensitive data, or represent integration points with internal corporate systems."
          ]
        }
      ]
    },
    companyBruteForceCrawl: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish?",
          lessonKey: "cloudEnumerationMethodology",
          answers: [
            "We're in the Cloud Asset Discovery phase, which focuses on identifying cloud-based infrastructure, services, and resources belonging to the target organization across major cloud platforms including AWS, Azure, and Google Cloud Platform.",
            "Our goal is to discover cloud storage buckets, API endpoints, serverless functions, databases, and other cloud services that might be misconfigured, publicly accessible, or contain sensitive organizational data that wasn't found through traditional domain-based reconnaissance.",
            "This phase complements on-premises infrastructure discovery by targeting the organization's cloud footprint, which often contains development environments, backup systems, data stores, and business applications that may have different security postures than traditional infrastructure."
          ]
        },
        {
          question: "How do Cloud Enum and Katana work together to discover organizational cloud assets?",
          lessonKey: "cloudEnumerationTools",
          answers: [
            "Cloud Enum performs systematic brute-force enumeration across AWS, Azure, and Google Cloud platforms using organizational names, domain patterns, and common service naming conventions to discover cloud storage buckets, databases, and services that might be publicly accessible or misconfigured.",
            "The tool tests thousands of potential cloud resource names based on organizational patterns, geographic indicators, business unit names, and common cloud service configurations to identify resources that the organization might not realize are publicly discoverable.",
            "Katana Company provides intelligent web crawling that analyzes organizational web applications, JavaScript files, and configuration data to discover cloud service endpoints, API URLs, and cloud resource references that developers might have embedded in client-side code or documentation.",
            "Together, these tools provide both systematic infrastructure-level discovery (Cloud Enum) and application-context discovery (Katana) to ensure comprehensive coverage of the organization's cloud attack surface across multiple discovery vectors."
          ]
        },
        {
          question: "What types of cloud assets should I prioritize for security assessment?",
          lessonKey: "cloudAssetPrioritization",
          answers: [
            "Focus on misconfigured cloud storage services (S3 buckets, Azure Blob storage, Google Cloud Storage) that might be publicly readable or writable, as these often contain sensitive data, backups, or configuration files that provide valuable intelligence or direct access to organizational information.",
            "Prioritize cloud APIs, serverless functions, and microservices that might have weak authentication, authorization bypasses, or business logic flaws, particularly those that appear to be development or testing endpoints with potentially relaxed security controls.",
            "Target cloud databases, data warehouses, and analytics services that might be exposed or have weak access controls, as these often contain aggregated business data, customer information, or operational intelligence that represents high-impact findings.",
            "Look for cloud management interfaces, monitoring dashboards, and administrative tools that might provide elevated access to cloud infrastructure or reveal information about organizational architecture, security controls, and operational procedures."
          ]
        }
      ]
    },
    companyConsolidateRootDomains: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish?",
          lessonKey: "consolidationMethodologyPosition",
          answers: [
            "We're in the Root Domain Consolidation phase, which sits between domain discovery and systematic subdomain enumeration. This is a critical quality control step that ensures we have a clean, validated list of organizational domains.",
            "Our goal is to process all discovered root domains from various sources (Google Dorking, CRT, Reverse WHOIS, API tools) into a single, deduplicated, and validated list that represents the organization's actual digital footprint.",
            "This phase prevents wasted effort on invalid domains, reduces false positives in later scanning phases, and ensures that subsequent subdomain enumeration and vulnerability assessment activities are focused on legitimate organizational assets."
          ]
        },
        {
          question: "How does the consolidation workflow systematically process discovered domains?",
          lessonKey: "consolidationWorkflowSteps",
          answers: [
            "The workflow starts with Trim Root Domains to remove obviously invalid entries, duplicates, and domains that don't belong to the target organization. This includes filtering out unrelated domains, parked domains, and domains with suspicious registration patterns.",
            "Next, the Consolidate function combines all remaining domains from different discovery sources into a single deduplicated list, removing exact duplicates and normalizing domain formats to ensure consistency across the dataset.",
            "The Investigate step involves validating domain ownership through WHOIS analysis, website content verification, SSL certificate examination, and business relationship analysis to confirm each domain legitimately belongs to the target organization.",
            "Finally, Add Wildcard Target converts verified domains into scope targets for systematic subdomain enumeration, ensuring that only validated organizational domains proceed to the next phase of reconnaissance."
          ]
        },
        {
          question: "What criteria should guide domain validation and prioritization decisions?",
          lessonKey: "consolidationDomainValidation",
          answers: [
            "Verify organizational ownership through multiple indicators: WHOIS registration data matching known organizational information, website content referencing the target organization, SSL certificates issued to the organization, and DNS infrastructure patterns consistent with organizational assets.",
            "Prioritize domains that represent different business functions, geographic regions, or subsidiary relationships, as these often provide unique attack surface areas that might not be covered by primary corporate domains.",
            "Focus on domains that show signs of active use but potentially less security attention, such as development environments, legacy brand domains, acquisition-related domains, or specialized business function domains that might have weaker security controls.",
            "Consider the potential scope and impact of each domain when deciding inclusion priority - domains that might provide access to sensitive data, internal systems, or critical business functions should be prioritized for subdomain enumeration and testing."
          ]
        }
      ]
    },
    companyDecisionPoint: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what is the strategic importance of the Full Attack Surface Decision Point?",
          lessonKey: "attackSurfaceDecisionMethodology",
          answers: [
            "We're at the Full Attack Surface Decision Point, which represents the culmination of comprehensive reconnaissance where we evaluate all discovered organizational assets to make strategic decisions about scope target selection and vulnerability assessment priorities.",
            "This decision point differs from earlier phases because we now have complete visibility into the organization's digital footprint: network ranges, root domains, subdomains, cloud assets, and live web servers across all business units, subsidiaries, and infrastructure types.",
            "The strategic importance lies in transforming raw reconnaissance data into actionable testing strategy by selecting targets that maximize the potential for finding significant vulnerabilities while considering factors like business impact, technical feasibility, and responsible disclosure requirements."
          ]
        },
        {
          question: "How do I evaluate and consolidate the complete organizational attack surface?",
          lessonKey: "attackSurfaceConsolidation",
          answers: [
            "Start by consolidating all discovered assets into categories: on-premises infrastructure (network ranges, live web servers), cloud resources (storage, APIs, services), domain-based assets (subdomains, web applications), and specialized systems (admin panels, development environments, monitoring tools).",
            "Use the attack surface visualization and analysis tools to identify patterns, relationships, and potential high-value targets across the entire organizational infrastructure, looking for assets that might provide pivot opportunities or access to critical business systems.",
            "Cross-reference technical findings with business intelligence about the organization to understand which assets serve critical functions, contain sensitive data, or represent key business processes that would have significant impact if compromised.",
            "Apply risk-based prioritization that considers both technical factors (technology stack, security posture, configuration) and business factors (data sensitivity, operational criticality, regulatory compliance) to focus testing efforts on the most promising targets."
          ]
        },
        {
          question: "What criteria should guide my selection of scope targets for comprehensive organizational testing?",
          lessonKey: "attackSurfaceTargetSelection",
          answers: [
            "Prioritize assets that represent unique attack vectors not covered by typical security assessments: subsidiary domains, development environments, cloud storage systems, admin interfaces, and legacy infrastructure that might have weaker security controls or less monitoring coverage.",
            "Focus on assets that could provide significant business impact if compromised: systems handling sensitive data, critical business applications, customer-facing services, and infrastructure components that could affect multiple business units or services.",
            "Consider assets that demonstrate organizational technology patterns or security practices: if you find vulnerabilities in one business unit's applications, similar issues might exist across other organizational assets with similar technology stacks or management practices.",
            "Balance breadth and depth in target selection by including a mix of high-confidence targets likely to yield findings and exploratory targets that might reveal unexpected vulnerabilities or provide insights into organizational security practices and architecture."
          ]
        }
      ]
    },
    companyNucleiScanning: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish with company-wide vulnerability scanning?",
          lessonKey: "nucleiScanningMethodology",
          answers: [
            "We're in the Automated Vulnerability Assessment phase, where we systematically test all discovered organizational assets for known vulnerabilities, misconfigurations, and security issues using comprehensive scanning templates and techniques.",
            "Our goal is to identify security vulnerabilities across the organization's complete attack surface using automated tools that can efficiently test thousands of targets for thousands of potential issues, providing broad coverage that would be impossible through manual testing alone.",
            "This phase transforms our reconnaissance findings into actionable security intelligence by systematically probing discovered assets for exploitable vulnerabilities, misconfigurations, and security weaknesses that could lead to successful bug bounty submissions."
          ]
        },
        {
          question: "How does Nuclei provide comprehensive vulnerability assessment across organizational infrastructure?",
          lessonKey: "nucleiScanningCapabilities",
          answers: [
            "Nuclei uses a template-based scanning approach with thousands of community-maintained YAML templates that test for specific vulnerabilities, misconfigurations, and security issues across web applications, APIs, cloud services, and infrastructure components.",
            "The tool's template system covers the complete spectrum of security issues: OWASP Top 10 vulnerabilities, CVE-based exploits, technology-specific misconfigurations, cloud security issues, and proprietary application vulnerabilities discovered by the security research community.",
            "Nuclei's scanning engine is designed for scale and efficiency, using concurrent request handling, intelligent rate limiting, and optimized request patterns to scan large organizational attack surfaces without overwhelming target infrastructure or triggering security monitoring systems.",
            "The platform provides detailed result analysis with severity ratings, impact assessments, and remediation guidance that helps prioritize findings based on business risk and technical impact, enabling effective triage of vulnerabilities across large-scale organizational assessments."
          ]
        },
        {
          question: "How do I configure Nuclei for effective company-wide scanning and analyze results strategically?",
          lessonKey: "nucleiScanningStrategy",
          answers: [
            "Configure target selection based on your reconnaissance findings and business intelligence: prioritize high-value assets like admin interfaces and development environments, include representative samples from each organizational domain and technology stack, and ensure coverage across different business units and geographical regions.",
            "Select vulnerability templates strategically based on discovered technologies, organizational patterns, and target characteristics: use web application templates for customer-facing sites, cloud security templates for discovered cloud assets, and infrastructure templates for admin interfaces and internal systems.",
            "Implement responsible scanning practices with appropriate rate limiting, timeouts, and concurrent request controls to avoid overwhelming target infrastructure while still achieving comprehensive coverage of the organizational attack surface.",
            "Analyze results systematically by categorizing findings by severity and impact, correlating vulnerabilities across similar organizational assets, identifying patterns that might indicate systematic security issues, and prioritizing findings that provide the greatest potential for significant security impact and successful bug bounty submissions."
          ]
        }
      ]
    },
    wildcardNucleiScanning: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at and what are we trying to accomplish with wildcard vulnerability scanning?",
          lessonKey: "wildcardNucleiScanningMethodology",
          answers: [
            "We're in the Automated Vulnerability Assessment phase for wildcard domains, where we systematically test all discovered live web servers for known vulnerabilities, misconfigurations, and security issues using Nuclei's comprehensive scanning templates.",
            "After completing subdomain enumeration, consolidation, and HTTPX probing across multiple rounds, we now have a curated list of live web servers. This phase transforms that recon into actionable security findings by scanning each live server for exploitable weaknesses.",
            "By focusing exclusively on confirmed live web servers, we maximize scan efficiency and minimize noise. Every target has already been validated as responsive, ensuring our vulnerability scanning efforts are directed at real, accessible attack surface."
          ]
        },
        {
          question: "How should I configure Nuclei scanning for wildcard domain targets?",
          lessonKey: "wildcardNucleiScanningStrategy",
          answers: [
            "Start with broad template categories like CVEs, vulnerabilities, and exposures to get comprehensive coverage across all live web servers. As you identify interesting technologies and patterns, refine your approach with individual template selection.",
            "Use the Individual Templates browser tab to search for and select specific templates targeting technologies you've discovered during metadata gathering. This precision approach lets you focus on the most relevant checks for each target's technology stack.",
            "Configure advanced settings like rate limiting and concurrency based on target sensitivity. For bug bounty programs, respect scope boundaries and rate limits. Use exclusion tags like 'dos' and 'intrusive' to avoid disruptive tests unless explicitly permitted.",
            "Leverage the Exclusions tab to skip templates that generate excessive noise for your targets, and use the Advanced Filtering options like protocol types and template conditions to fine-tune which templates run against your specific target set."
          ]
        }
      ]
    },
    threatModeling: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What is STRIDE threat modeling and how does it enhance bug bounty hunting?",
          lessonKey: "strideMethodologyOverview",
          answers: [
            "STRIDE is a systematic threat modeling framework developed by Microsoft that categorizes security threats into six types: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege.",
            "For bug bounty hunters, STRIDE provides a structured approach to identifying security vulnerabilities by thinking like an attacker and systematically considering each threat category against application mechanisms, objects, and security controls.",
            "By documenting threats using the STRIDE framework, you create a comprehensive attack surface map that connects discovered mechanisms, notable objects, and security controls with specific exploitation scenarios, ensuring no vulnerability class is overlooked.",
            "This methodology transforms reactive vulnerability hunting into proactive security analysis, helping you discover complex attack chains, business logic flaws, and security gaps that automated scanners typically miss."
          ]
        },
        {
          question: "How do I systematically document application questions, mechanisms, objects, and controls for effective threat modeling?",
          lessonKey: "stridePreparationSteps",
          answers: [
            "Start with Application Questions to understand the business context, data flows, authentication architecture, and technology stack. This foundational knowledge reveals where sensitive operations occur and which components handle critical data.",
            "Document Mechanisms by identifying specific application behaviors like authentication flows, data validation, API operations, and state transitions. Each mechanism represents a potential attack surface where STRIDE threats can be applied.",
            "Catalog Notable Objects including user accounts, API tokens, sensitive data structures, session identifiers, and business entities. These objects become the targets in your threat scenarios, helping you identify what attackers might want to compromise.",
            "Define Security Controls such as authentication systems, authorization checks, input validation, encryption, rate limiting, and monitoring. Understanding existing controls helps you identify gaps and determine how threats might bypass protections."
          ]
        },
        {
          question: "How do I apply each STRIDE category to discover vulnerabilities?",
          lessonKey: "strideCategories",
          answers: [
            "Spoofing threats target authentication and identity verification. Ask: Can attackers impersonate users, services, or systems? Look for weak authentication, missing multi-factor authentication, predictable session tokens, or credential stuffing opportunities.",
            "Tampering threats focus on data integrity. Ask: Can attackers modify data in transit or at rest? Examine input validation, API parameter tampering, client-side controls, database manipulation, and file integrity protections.",
            "Repudiation threats concern logging and accountability. Ask: Can attackers deny their actions? Evaluate audit logging, transaction records, cryptographic signatures, and evidence preservation for critical operations.",
            "Information Disclosure threats involve data confidentiality. Ask: Can attackers access unauthorized information? Investigate API data leakage, directory traversal, verbose error messages, OSINT exposure, and insecure data storage.",
            "Denial of Service threats target availability. Ask: Can attackers make systems unavailable? Test rate limiting, resource exhaustion, algorithmic complexity attacks, and infrastructure resilience.",
            "Elevation of Privilege threats involve authorization bypass. Ask: Can attackers gain unauthorized access? Analyze authorization checks, privilege escalation paths, role-based access control flaws, and trust boundary violations."
          ]
        },
        {
          question: "How do I create effective threat scenarios that lead to bug bounty findings?",
          lessonKey: "threatScenarioCreation",
          answers: [
            "Each threat should identify a specific URL or endpoint where the vulnerability exists, connecting your threat model to concrete testable targets discovered during reconnaissance.",
            "Select the mechanism being exploited (authentication flow, API operation, data validation) and optionally the target object (user account, API token, data structure) to clearly define the attack surface and what's being compromised.",
            "Document step-by-step exploitation instructions that another security researcher could follow to reproduce the attack. Include specific API requests, parameter manipulations, timing requirements, and observable outcomes.",
            "Assess impact across three dimensions: customer data compromise (privacy violations, data theft), attacker scope expansion (lateral movement, privilege escalation), and company reputation damage (regulatory fines, public disclosure impact).",
            "Map affected security controls to each threat, explaining how existing protections fail or are bypassed. This demonstrates security gap awareness and helps prioritize remediation efforts based on control effectiveness."
          ]
        },
        {
          question: "How do cloud infrastructure and OSINT fit into STRIDE threat modeling?",
          lessonKey: "cloudOsintThreatModeling",
          answers: [
            "Cloud services introduce unique threats across all STRIDE categories: spoofed IAM credentials, tampered S3 bucket policies, missing CloudTrail logs (repudiation), exposed storage buckets (information disclosure), API throttling bypasses (DoS), and privilege escalation through misconfigured IAM roles.",
            "Document cloud-specific mechanisms like serverless functions, container orchestration, cloud storage operations, and managed service interactions. Each cloud service type has distinct security boundaries and threat vectors.",
            "OSINT (Open Source Intelligence) primarily feeds Information Disclosure threats: exposed credentials in GitHub, leaked API keys in public documents, employee information on LinkedIn, and infrastructure details in job postings. These findings can enable other STRIDE threat categories.",
            "Consider the cloud shared responsibility model in your threat analysis: identify which security controls are managed by the cloud provider versus the application, revealing gaps where neither party has implemented sufficient protection.",
            "Catalog cloud-specific notable objects like IAM roles, security groups, API gateway configurations, and encryption keys. These objects become targets for threats and help you map cloud attack paths that span multiple services."
          ]
        }
      ]
    }
  };

  const currentSection = sections[section];

  if (!currentSection) return null;

  return (
    <>
      <Accordion data-bs-theme="dark" className="mb-3">
        <Accordion.Item eventKey="0">
          <Accordion.Header className="fs-5">{currentSection.title}</Accordion.Header>
          <Accordion.Body className="bg-dark">
            <ListGroup as="ul" variant="flush">
              {currentSection.items.map((item, index) => (
                <ListGroup.Item key={index} as="li" className="bg-dark text-danger">
                  <span className="fs-5">
                    {item.question}
                    {item.lessonKey && lessons[item.lessonKey] && (
                      <span 
                        className="text-white ms-2"
                        style={{ cursor: 'pointer' }}
                        onClick={() => handleLearnMoreClick(item.lessonKey)}
                      >
                        [Learn More]
                      </span>
                    )}
                  </span>
                  <ListGroup as="ul" variant="flush" className="mt-2">
                    {item.answers.map((answer, answerIndex) => (
                      <ListGroup.Item key={answerIndex} as="li" className="bg-dark text-white fst-italic fs-6">
                        {answer}
                      </ListGroup.Item>
                    ))}
                  </ListGroup>
                </ListGroup.Item>
              ))}
            </ListGroup>
          </Accordion.Body>
        </Accordion.Item>
      </Accordion>

      <LearnMoreModal
        show={showLearnMoreModal}
        handleClose={handleCloseLearnMoreModal}
        lesson={currentLesson}
      />
    </>
  );
};

export default HelpMeLearn; 