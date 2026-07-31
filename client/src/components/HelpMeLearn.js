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
    urlEndpointBruteForcing: {
      title: "Help Me Learn!",
      items: [
        {
          question: "What stage of the methodology are we at, and why do we brute-force for hidden endpoints?",
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
    urlParameterEnumeration: {
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
          question: "How do Arjun, parameth, and x8 discover hidden parameters differently?",
          lessonKey: "urlParameterTools",
          answers: [
            "All three work by the same core idea: send the endpoint many candidate parameter names from a wordlist and watch for a change in the response. If adding ?debug=xyz changes the response — different length, different status, reflected value, different behavior — that parameter is probably real and processed by the backend.",
            "Arjun is a fast, accurate Python tool that's smart about this diffing: it sends parameters in chunks, establishes a stable baseline, and reports the names that genuinely affect the response. It handles GET, POST, JSON, and XML bodies and is a great default choice.",
            "x8 is a high-accuracy Rust tool that excels at precise response comparison and can inject parameters into the query string, body, or headers. It's particularly good at cutting through noise on responses that change slightly on their own, and it verifies its findings to reduce false positives.",
            "parameth is an older tool that brute-forces GET/POST parameters by monitoring response size and content changes. Running more than one tool is worthwhile because they use different wordlists and diffing strategies, so each can surface parameters the others miss."
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
            "Sublist3r leverages multiple search engines and public data sources to discover subdomains through search result analysis, finding subdomains mentioned in indexed content, documentation, and public websites.",
            "Assetfinder specializes in fast DNS-based subdomain enumeration using multiple resolvers and data sources, providing rapid discovery of DNS-resolvable subdomains with minimal infrastructure impact.",
            "Certificate Transparency Log (CTL) searches reveal subdomains that have been issued SSL certificates, including internal or non-public subdomains that organizations secure with certificates but don't publicly advertise."
          ]
        },
        {
          question: "How do I systematically utilize subdomain scraping tools and prepare for consolidation?",
          lessonKey: "subdomainScrapingWorkflow",
          answers: [
            "Start with parallel execution of multiple tools to maximize discovery coverage: run Gau for historical URL discovery, Sublist3r for search engine intelligence, Assetfinder for DNS enumeration, and CTL for certificate analysis simultaneously.",
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
            "This round consolidates all subdomains discovered through Amass enumeration and passive scraping tools (Gau, Sublist3r, Assetfinder, CTL) into a single deduplicated list, eliminating redundancy while preserving valuable discovery metadata.",
            "The live web server discovery component uses Httpx to systematically probe all consolidated subdomains to identify which ones actually host active web services, transforming raw subdomain lists into actionable testing targets.",
            "This phase is critical because it establishes the baseline of confirmed live web servers before proceeding to more aggressive discovery techniques, ensuring that subsequent brute-force testing builds upon a solid foundation of verified assets."
          ]
        },
        {
          question: "How does the consolidation process systematically organize and deduplicate discoveries?",
          lessonKey: "consolidationRound1Process",
          answers: [
            "The consolidation process combines subdomain discoveries from all passive sources (Amass, Gau, Sublist3r, Assetfinder, CTL) into a unified dataset while maintaining source attribution to understand which discovery methods were most effective for the target organization.",
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