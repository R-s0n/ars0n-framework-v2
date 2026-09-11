# Comprehensive Bug Bounty Writeups Collection

> Curated from Pentester Land, Medium/InfoSec Write-ups, HackerOne disclosures, PortSwigger Research, Assetnote, ProjectDiscovery, and independent researcher blogs. Last updated: March 2026.

---

## 1. Account Takeover Chains

### 1. Zero-Click Account Takeover in Half an Hour
- **Author**: Furkan Uyar (@spettyial)
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: Account Takeover (Zero-Click)
- **Summary**: Researcher discovered a zero-click account takeover vulnerability that required no user interaction. The flaw allowed complete takeover of any user account by exploiting a logic error in the session management system. The attack could be executed within minutes of identifying the target.
- **Key Technique**: Exploiting session token generation flaws that allowed prediction and replay of authentication tokens without user interaction.
- **Source**: https://medium.com/@spettyial/zero-click-account-takeover-i-found-it-in-half-an-hour-444e737f0919

### 2. ChatGPT Account Takeover via Web Cache Deception
- **Author**: Nagli (Harel Security Research)
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: OpenAI (ChatGPT)
- **Vulnerability Type**: Web Cache Deception / Account Takeover
- **Summary**: A web cache deception vulnerability in ChatGPT allowed full account takeover. The attacker crafted a .css path to the session endpoint and sent the link to a victim. When clicked, the response containing credentials was cached by the CDN, allowing the attacker to extract access tokens, names, and email addresses for unauthorized account access.
- **Key Technique**: Wildcard web cache deception using path traversal URL parser confusion to cache authenticated session responses on CDN edge nodes.
- **Source**: https://nokline.github.io/bugbounty/2024/02/04/ChatGPT-ATO.html

### 3. From Curiosity to $10,000: Critical Account Takeover Bug
- **Author**: Rahul Gairola
- **Severity**: Critical
- **Bounty**: $10,000
- **Target**: Private Program
- **Vulnerability Type**: Account Takeover
- **Summary**: Researcher discovered a critical account takeover vulnerability by investigating the password reset flow. The flaw allowed an attacker to reset any user's password and gain complete control of their account. The vulnerability was in the token validation mechanism of the forgot password feature.
- **Key Technique**: Exploiting weak token validation in the password reset flow to take over arbitrary accounts.
- **Source**: https://medium.com/@rahulgairola/from-curiosity-to-10-000-how-i-found-a-critical-account-takeover-bug-ca6dd169c36b

### 4. OAuth Token Leak Chained with Authentication Bypass
- **Author**: Whitehat (Cyber Security Write-ups)
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: OAuth Token Leak / Authentication Bypass
- **Summary**: Researcher discovered an OAuth token leak vulnerability that, when chained with an authentication bypass, allowed complete account takeover. The OAuth implementation leaked access tokens through insecure redirect_uri handling, and the researcher chained multiple vulnerabilities to escalate the impact.
- **Key Technique**: Chaining an open redirect on the OAuth redirect_uri parameter with token interception to steal OAuth access tokens from other users.
- **Source**: https://cybersecuritywriteups.com/how-i-found-an-oauth-token-leak-bypassed-authentication-and-chained-multiple-vulnerabilities-d6095aa303a0

### 5. Chained Bugs to Leak Victim's Uber FB OAuth Token
- **Author**: Undisclosed (HackerOne Report #202781)
- **Severity**: Critical
- **Bounty**: $8,000
- **Target**: Uber
- **Vulnerability Type**: OAuth Token Theft
- **Summary**: The researcher discovered a vulnerability chain that leaked victims' Facebook OAuth tokens used with Uber. By exploiting a misconfigured OAuth application that allowed any URL following a specific format as a redirect_uri, combined with parameter manipulation, the attacker could steal Facebook access tokens.
- **Key Technique**: Abusing OAuth redirect_uri validation bypass combined with Facebook's OAuth flow to intercept access tokens via a controlled domain.
- **Source**: https://hackerone.com/reports/202781

### 6. The $12,000 2FA Bypass -- So Simple, Yet So Critical
- **Author**: Rahul Gairola
- **Severity**: Critical
- **Bounty**: $12,000
- **Target**: Private Program
- **Vulnerability Type**: 2FA Bypass / Account Takeover
- **Summary**: Researcher bypassed two-factor authentication by exploiting the absence of rate limiting on the 2FA verification API. This allowed brute-forcing the 2FA code, effectively bypassing the second authentication factor and achieving account takeover on any account.
- **Key Technique**: Brute-forcing 2FA verification codes due to missing rate limiting, using Burp Suite Intruder to rapidly test all possible code combinations.
- **Source**: https://medium.com/@rahulgairola/the-12-000-2fa-bypass-so-simple-yet-so-critical-e3f7d7e5751c

### 7. Breaking the Chain: Exploiting OAuth and Forgot Password for ATO
- **Author**: Bugcrowd Research
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Multiple Programs
- **Vulnerability Type**: OAuth + Password Reset Chain
- **Summary**: This writeup demonstrates how OAuth misconfigurations combined with flaws in the forgot password feature can be chained for account takeover. Many ATOs occur because of predictable password tokens, IDOR in reset endpoints, or insecure OAuth redirect handling.
- **Key Technique**: Chaining OAuth redirect bypass with forgot password token prediction to achieve full account takeover without user interaction.
- **Source**: https://www.bugcrowd.com/blog/breaking-the-chain-exploiting-oauth-and-forgot-password-for-account-takeover/

### 8. JWT Flaw Leading to Full Account Takeover
- **Author**: Kailasv
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: JWT Authentication Bypass
- **Summary**: The researcher exploited a JWT implementation flaw where logged-out sessions remained valid. By manipulating the JWT token and exploiting missing signature validation, the attacker could bypass authentication and take over any account on the platform.
- **Key Technique**: Exploiting JWT tokens that remained valid after logout combined with missing signature verification to forge authentication tokens.
- **Source**: https://medium.com/@kailasv678/logged-out-but-still-in-how-i-exploited-a-jwt-flaw-to-bypass-authentication-5e062396923f

### 9. Account Takeover via AWS Cognito Misconfiguration
- **Author**: Undisclosed (HackerOne)
- **Severity**: Critical
- **Bounty**: $6,000
- **Target**: Private Program
- **Vulnerability Type**: Cloud Misconfiguration / ATO
- **Summary**: AWS Cognito was misconfigured to allow unauthorized user attribute modification, enabling attackers to change email addresses and phone numbers of other users. This effectively allowed complete account takeover by resetting credentials through the modified contact information.
- **Key Technique**: Exploiting overly permissive AWS Cognito user pool settings that allowed unauthenticated modification of user attributes.
- **Source**: https://github.com/devanshbatham/Awesome-Bugbounty-Writeups

### 10. Self-XSS in Facebook Payments Leading to Account Takeover
- **Author**: Undisclosed (Facebook Bug Bounty)
- **Severity**: High
- **Bounty**: $7,500
- **Target**: Facebook (Meta)
- **Vulnerability Type**: Self-XSS / Account Takeover Chain
- **Summary**: A self-XSS vulnerability in Facebook's payments flow was chained with other techniques to escalate from a low-impact self-XSS to a full account takeover. The researcher demonstrated how the XSS could be triggered in a victim's context by exploiting the payment processing workflow.
- **Key Technique**: Escalating self-XSS through the Facebook payments flow by combining it with CSRF and login/logout sequences to execute JavaScript in the victim's authenticated session.
- **Source**: https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups

---

## 2. Critical Severity Findings ($10,000+)

### 11. Dependency Confusion: Hacking Apple, Microsoft, and Dozens More
- **Author**: Alex Birsan
- **Severity**: Critical
- **Bounty**: $130,000+ (combined across companies)
- **Target**: Apple, Microsoft, Uber, Tesla, Shopify, Yelp, and 30+ others
- **Vulnerability Type**: Supply Chain / Dependency Confusion
- **Summary**: Birsan discovered that npm, pip, and other package managers would prioritize public packages over private internal ones when the public version had a higher version number. By creating malicious packages with the same names as internal packages used by major tech companies, he achieved code execution in development and production environments of 35+ organizations.
- **Key Technique**: Publishing higher-versioned public packages matching internal package names, exploiting package manager resolution logic to achieve supply chain compromise.
- **Source**: https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610

### 12. $50,000 Bounty: GitHub Access Token in Shopify Electron App
- **Author**: Augustozanellato
- **Severity**: Critical
- **Bounty**: $50,000
- **Target**: Shopify
- **Vulnerability Type**: Credential Exposure / Information Disclosure
- **Summary**: A GitHub Personal Access Token (PAT) belonging to a Shopify employee was found embedded in a publicly available macOS desktop application built with Electron. The .env file containing the GH_TOKEN was shipped inside the production build, providing access to Shopify's GitHub repositories.
- **Key Technique**: Reverse engineering an Electron application's ASAR package to discover environment files with hardcoded credentials shipped in production builds.
- **Source**: https://infosecwriteups.com/50-000-bounty-github-access-token-c29cb6f00182

### 13. HTTP Request Smuggling Earning $70K+ in Bounties
- **Author**: James Kettle (PortSwigger)
- **Severity**: Critical
- **Bounty**: $70,000+ (combined)
- **Target**: Multiple (including PayPal, Netflix)
- **Vulnerability Type**: HTTP Request Smuggling / Desync
- **Summary**: James Kettle revived HTTP request smuggling attacks by demonstrating how differences in front-end and back-end server parsing of HTTP headers could allow malicious requests to bypass security, hijack sessions, poison caches, and compromise systems. PayPal paid $18,900 and $20,000 for individual issues; Netflix paid their maximum $20,000.
- **Key Technique**: Exploiting Content-Length vs Transfer-Encoding header disagreements between front-end proxies and back-end servers to inject requests into other users' sessions.
- **Source**: https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn

### 14. HTTP/2 Request Smuggling Earning $200K+ in Two Weeks
- **Author**: James Kettle (PortSwigger)
- **Severity**: Critical
- **Bounty**: $200,000+ (combined)
- **Target**: Multiple major platforms
- **Vulnerability Type**: HTTP/2 Desync / Request Smuggling
- **Summary**: Kettle demonstrated a new class of desync attacks exploiting HTTP/2 downgrade proxies. By sending specially crafted HTTP/2 requests that were incorrectly translated to HTTP/1.1 by intermediary proxies, he achieved request smuggling on platforms previously considered immune. This research earned over $200K in bounties in just two weeks.
- **Key Technique**: Exploiting HTTP/2 to HTTP/1.1 downgrade translation errors in reverse proxies to achieve request smuggling and session hijacking.
- **Source**: https://portswigger.net/research/http2

### 15. Leaking the Email of Any YouTube User for $10,000
- **Author**: brutecat
- **Severity**: High
- **Bounty**: $10,000
- **Target**: Google (YouTube)
- **Vulnerability Type**: Information Disclosure
- **Summary**: The researcher discovered a way to leak the email address of any YouTube user through Google's infrastructure. This vulnerability exposed the personal email addresses of millions of YouTube users, creating significant privacy implications.
- **Key Technique**: Exploiting Google's internal user ID resolution systems to map YouTube channel IDs to associated Gmail addresses.
- **Source**: https://github.com/xdavidhu/awesome-google-vrp-writeups

### 16. Hacking Google's Bug Tracking System for $15,600
- **Author**: Alex Birsan
- **Severity**: High
- **Bounty**: $15,600
- **Target**: Google (Issue Tracker)
- **Vulnerability Type**: Authorization Bypass
- **Summary**: Birsan found vulnerabilities in Google's own bug tracking system (Buganizer/Issue Tracker) that allowed unauthorized access to internal bug reports. The researcher chained multiple access control flaws to read restricted security reports within Google's internal systems.
- **Key Technique**: Exploiting authorization flaws in Google's Issue Tracker to access restricted internal bug reports and security vulnerabilities.
- **Source**: https://github.com/xdavidhu/awesome-google-vrp-writeups

### 17. Google Cloudshell RCE for $6,000
- **Author**: Pranav Venkat
- **Severity**: Critical
- **Bounty**: $6,000
- **Target**: Google Cloud
- **Vulnerability Type**: Remote Code Execution
- **Summary**: The researcher discovered a remote code execution vulnerability in Google Cloudshell that allowed executing arbitrary commands on Google's infrastructure. The vulnerability was in the Cloudshell environment's handling of user input.
- **Key Technique**: Exploiting input handling flaws in the Google Cloudshell environment to achieve arbitrary command execution on Google's cloud infrastructure.
- **Source**: https://github.com/xdavidhu/awesome-google-vrp-writeups

### 18. $5,000 Google Maps XSS via Protobuf Fiddling
- **Author**: Marin Moulinier
- **Severity**: High
- **Bounty**: $5,000
- **Target**: Google Maps
- **Vulnerability Type**: Cross-Site Scripting (XSS)
- **Summary**: By analyzing and manipulating Protobuf-encoded data in Google Maps API requests, the researcher injected malicious JavaScript that executed in the context of the Google Maps domain. The XSS was possible because the application decoded Protobuf data without proper sanitization.
- **Key Technique**: Reverse engineering Google Maps Protobuf data format to inject XSS payloads through serialized binary protocol buffers.
- **Source**: https://github.com/xdavidhu/awesome-google-vrp-writeups

### 19. Sam Curry: Hacking 16 Car Manufacturers
- **Author**: Sam Curry and team
- **Severity**: Critical
- **Bounty**: $100,000+ (estimated combined)
- **Target**: Kia, Hyundai, Honda, Toyota, BMW, Mercedes-Benz, Ferrari, Porsche, and more
- **Vulnerability Type**: API Security / Authorization Bypass / RCE
- **Summary**: Curry's team discovered critical vulnerabilities in 16 automotive manufacturers allowing remote lock/unlock, engine start/stop, tracking, and full account takeover using only VIN numbers. They gained SSO access to BMW and Mercedes-Benz internal systems including dealer portals, GitHub, and Slack. A SQL injection in Spireon's admin portal affected 15 million vehicles.
- **Key Technique**: Exploiting poorly secured telematics APIs and internal SSO systems to achieve remote physical control of vehicles and access to manufacturer internal networks.
- **Source**: https://samcurry.net/web-hackers-vs-the-auto-industry

### 20. Tesla Blind XSS via Vehicle Nickname ($10,000)
- **Author**: Sam Curry
- **Severity**: Critical (P1)
- **Bounty**: $10,000
- **Target**: Tesla
- **Vulnerability Type**: Blind Cross-Site Scripting
- **Summary**: After cracking his Tesla Model 3 windshield, Curry set his vehicle's nickname to an XSS Hunter payload. When a Tesla support agent opened his service ticket, the payload executed within Tesla's internal support dashboard (garage.vn.teslamotors.com), exposing internal tooling. Tesla triaged it as P1 and pushed a hotfix within 12 hours.
- **Key Technique**: Using XSS Hunter payloads in user-controlled vehicle name fields that rendered unsanitized in internal admin dashboards.
- **Source**: https://samcurry.net/cracking-my-windshield-and-earning-10000-on-the-tesla-bug-bounty-program

### 21. SSRF in Shopify Exchange Leading to ROOT Access
- **Author**: Undisclosed (HackerOne Report #341876)
- **Severity**: Critical
- **Bounty**: $25,000
- **Target**: Shopify
- **Vulnerability Type**: SSRF / Root Access
- **Summary**: A Server-Side Request Forgery vulnerability in Shopify's Exchange marketplace was exploited to access the AWS metadata endpoint (169.254.169.254), ultimately leading to root-level access on the server. The researcher escalated from basic SSRF to full infrastructure compromise.
- **Key Technique**: Leveraging SSRF to access AWS EC2 instance metadata service and retrieve IAM role credentials for privilege escalation to root.
- **Source**: https://hackerone.com/reports/341876

### 22. Zoom Vulnerability Rewarded with $15,000
- **Author**: Undisclosed
- **Severity**: Critical
- **Bounty**: $15,000
- **Target**: Zoom
- **Vulnerability Type**: Undisclosed (patched January 2024)
- **Summary**: A critical vulnerability was discovered in Zoom's platform that was reported in October 2023. The vulnerability was fully patched and verified by January 2024. The finding earned a $15,000 bounty from Zoom's security program.
- **Key Technique**: Undisclosed pending full patch verification.
- **Source**: https://pentester.land/writeups/

### 23. PII Disclosure of Apple Users ($10,000)
- **Author**: Ahmad Halabi
- **Severity**: High
- **Bounty**: $10,000
- **Target**: Apple
- **Vulnerability Type**: Information Disclosure / PII Leak
- **Summary**: The researcher discovered a vulnerability in an Apple web service that exposed personally identifiable information of Apple users. The PII disclosure included sensitive user data that could be accessed without proper authorization, earning a $10,000 bounty.
- **Key Technique**: Exploiting authorization flaws in Apple's web services to access user PII without proper authentication checks.
- **Source**: https://ahmdhalabi.medium.com/pii-disclosure-of-apple-users-10k-d1e3d29bae36

### 24. Hacking Kia: Remote Control with Just a License Plate
- **Author**: Sam Curry
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Kia
- **Vulnerability Type**: API Security / Authorization Bypass
- **Summary**: Curry discovered that Kia's connected vehicle API allowed attackers to remotely lock, unlock, start/stop engines, access 360-view cameras, and view live images from any Kia vehicle using only the VIN number (derivable from a license plate). Additionally, the flaw allowed full account takeover and PII disclosure including name, phone, email, and physical address.
- **Key Technique**: Exploiting Kia's telematics API endpoints that relied solely on VIN numbers for authorization without proper ownership verification.
- **Source**: https://samcurry.net/hacking-kia

---

## 3. Clever Chains and Escalations

### 25. SSRF to Server Takeover (Full PoC)
- **Author**: Malvin Valerian
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: SSRF to RCE
- **Summary**: The researcher escalated a basic SSRF vulnerability to complete server takeover by accessing the AWS metadata endpoint, retrieving IAM credentials, and using those credentials to execute commands on the underlying infrastructure. The writeup includes a complete proof of concept.
- **Key Technique**: SSRF -> AWS metadata (169.254.169.254) -> IAM credential extraction -> AWS CLI abuse for full server compromise.
- **Source**: https://medium.com/@malvinval/ssrf-to-server-takeover-poc-bug-bounty-writeup-82d6715e333d

### 26. $8,000 XSS to RCE in Opera Browser
- **Author**: Opera Security Team
- **Severity**: Critical
- **Bounty**: $8,000
- **Target**: Opera Browser
- **Vulnerability Type**: XSS to RCE Chain
- **Summary**: A cross-site scripting vulnerability in Opera's My Flow feature was escalated to remote code execution. The My Flow system bridges Opera browser and mobile devices, and the XSS allowed execution of arbitrary code on the user's system through the browser's privileged internal pages.
- **Key Technique**: Exploiting XSS in Opera's internal My Flow system which had elevated privileges, allowing escalation from DOM manipulation to arbitrary code execution on the host system.
- **Source**: https://blogs.opera.com/security/2021/09/8000-bug-bounty-highlight-xss-to-rce-in-the-opera-browser/

### 27. RCE via Unclaimed Node Package ($2,500)
- **Author**: Fuleki Ioan (@p0lyxena)
- **Severity**: Critical
- **Bounty**: $2,500
- **Target**: Private Program
- **Vulnerability Type**: Dependency Confusion / RCE
- **Summary**: The researcher discovered that a company's application referenced an npm package that had never been claimed on the public registry. By creating a package with the same name and embedding malicious preinstall scripts, the researcher achieved remote code execution when the company's CI/CD pipeline installed dependencies.
- **Key Technique**: Claiming unclaimed npm package names referenced in internal package.json files to execute arbitrary code through npm preinstall hooks.
- **Source**: https://medium.com/@p0lyxena/2-500-bug-bounty-write-up-remote-code-execution-rce-via-unclaimed-node-package-6b9108d10643

### 28. Exploiting Race Conditions for Infinite Discounts
- **Author**: Aditya Bhatt
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: E-commerce Platform (Private Program)
- **Vulnerability Type**: Race Condition / Business Logic
- **Summary**: By sending concurrent requests to the coupon application endpoint, the researcher was able to apply the same discount coupon multiple times, stacking discounts beyond the intended limit. Out of 50 simultaneous requests, 2-3 would bypass the deduction logic due to TOCTOU race conditions.
- **Key Technique**: Using Burp Suite Intruder to send dozens of simultaneous coupon application requests, exploiting the time gap between balance check and balance deduction.
- **Source**: https://infosecwriteups.com/bug-bounty-race-exploiting-race-conditions-for-infinite-discounts-a2cb2f233804

### 29. TOCTOU Race Condition Leading to Broken Authentication
- **Author**: Irsyad Muhammad Fawwaz
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: Race Condition / Authentication Bypass
- **Summary**: A TOCTOU race condition in the password reset flow allowed an attacker to reset another user's password by racing two requests in a single session. The time gap between the security check and the password change action was exploitable with precise timing.
- **Key Technique**: Exploiting the time-of-check to time-of-use gap in password reset flows by sending parallel requests to change both the email and trigger the reset simultaneously.
- **Source**: https://infosecwriteups.com/time-of-check-time-of-use-toctou-race-condition-leads-to-broken-authentication-critical-finding-b55993c92abc

### 30. Glassdoor Cache Poisoning via URL Parser Confusion
- **Author**: Harel Security Research (NokLine)
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: Glassdoor
- **Vulnerability Type**: Web Cache Poisoning
- **Summary**: By abusing URL parser confusion between the application server and the caching layer, the researcher achieved web cache poisoning on Glassdoor. The attack allowed injecting malicious content into cached responses served to other users, effectively turning a parser discrepancy into a stored attack.
- **Key Technique**: Exploiting differences in URL normalization between CDN cache key computation and backend routing to cache poisoned responses for legitimate URLs.
- **Source**: https://nokline.github.io/bugbounty/2022/09/02/Glassdoor-Cache-Poisoning.html

### 31. SQL Injection in WordPress Plugins (CVE-2024-32139)
- **Author**: Peng Zhou
- **Severity**: Critical
- **Bounty**: Undisclosed (Patchstack competition)
- **Target**: WordPress Plugins
- **Vulnerability Type**: SQL Injection
- **Summary**: Two SQL injection vulnerabilities were discovered in WordPress plugins under strict "magic" restrictions that normally prevent exploitation. The researcher found creative ways to make the injections exploitable despite WordPress's built-in protections, resulting in CVE-2024-32139 and CVE-2024-38755.
- **Key Technique**: Bypassing WordPress's prepared statements and magic quotes restrictions to achieve exploitable SQL injection through creative payload construction.
- **Source**: https://medium.com/@zpbrent/how-i-make-two-sql-injections-exploitable-under-the-magic-restricts-in-wordpress-817cd60dc80a

### 32. ServiceNow Exploit Chain (3 CVEs)
- **Author**: Adam Kues (Assetnote)
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: ServiceNow
- **Vulnerability Type**: Authentication Bypass / RCE Chain
- **Summary**: Assetnote researcher Adam Kues spent over a month discovering an exploit chain in ServiceNow combining three vulnerabilities (CVE-2024-4879, CVE-2024-5178, CVE-2024-5217) that allowed unauthenticated access to the full database and MID server. The chain bypassed authentication controls to achieve complete system compromise.
- **Key Technique**: Chaining an authentication bypass with server-side template injection and file read vulnerability to achieve full database access and remote code execution.
- **Source**: https://www.assetnote.io/resources/blog/a-deep-dive-into-three-servicenow-vulnerabilities-with-adam-kues

### 33. Next.js Middleware Authorization Bypass (CVE-2025-29927)
- **Author**: ProjectDiscovery Research
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Next.js (Vercel)
- **Vulnerability Type**: Authorization Bypass
- **Summary**: A critical vulnerability in Next.js middleware allowed bypassing authorization checks implemented in middleware. This affected all applications using Next.js middleware for authentication and authorization, potentially exposing protected routes and API endpoints to unauthorized users.
- **Key Technique**: Exploiting a flaw in Next.js middleware execution order to bypass authentication checks and access protected routes directly.
- **Source**: https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass

### 34. $9,000 in One Month: PayU Payment Bypass
- **Author**: Milad Safdari (Eulex)
- **Severity**: Critical
- **Bounty**: $9,000 (combined)
- **Target**: Multiple platforms using PayU
- **Vulnerability Type**: Payment Bypass / Business Logic
- **Summary**: The researcher discovered a payment bypass vulnerability in PayU's payment processing system. By modifying the payment status parameter to "Succeed" in transit, invoices were generated without actual payment. The initial $3,000 bounty was multiplied across multiple platforms using the same PayU integration for a total of $9,000.
- **Key Technique**: Intercepting and modifying PayU payment callback parameters to change transaction status from pending to succeeded, bypassing server-side payment verification.
- **Source**: https://eulex.medium.com/how-i-made-9-000-in-one-month-from-bug-bounty-9403147b4d07

### 35. Apple Developer Stored XSS ($5,000)
- **Author**: Youssef Desouki (Zombie Hack)
- **Severity**: High
- **Bounty**: $5,000
- **Target**: Apple Developer Portal
- **Vulnerability Type**: Stored Cross-Site Scripting
- **Summary**: A stored XSS vulnerability was discovered across multiple Apple Developer domains that allowed arbitrary JavaScript execution. The vulnerability was fully patched and resolved through collaboration with Apple's Product Security team, earning official acknowledgment and a $5,000 bounty.
- **Key Technique**: Injecting persistent JavaScript payloads into Apple Developer portal fields that rendered unsanitized across multiple Apple subdomains.
- **Source**: https://medium.com/@ZombieHack/apple-developer-stored-xss-5-000-bounty-writeup-2025-cc34a030a5bf

---

## 4. Cloud/Infrastructure Findings

### 36. SSRF Worth $4,913 -- Highest Bounty Ever (at the time)
- **Author**: Sayaan Alam (TechFenix)
- **Severity**: Critical
- **Bounty**: $4,913
- **Target**: Private Program
- **Vulnerability Type**: SSRF
- **Summary**: The researcher discovered a Server-Side Request Forgery vulnerability that allowed accessing internal services and AWS metadata. By retrieving AWS access keys and tokens from the metadata endpoint, the researcher demonstrated full infrastructure compromise potential.
- **Key Technique**: Bypassing SSRF URL filtering using DNS rebinding and IP address format tricks (decimal IP, IPv6 compressed/expanded) to reach the AWS metadata endpoint.
- **Source**: https://medium.com/techfenix/ssrf-server-side-request-forgery-worth-4913-my-highest-bounty-ever-7d733bb368cb

### 37. AWS S3 Bucket Takeover via JavaScript File
- **Author**: JSMon Security Blog
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: Subdomain Takeover / S3 Bucket Misconfiguration
- **Summary**: The researcher discovered an S3 bucket takeover by analyzing JavaScript files that referenced an S3 bucket that no longer existed. By registering the abandoned bucket name, the researcher gained control over scripts loaded by the target application, enabling potential XSS and phishing attacks.
- **Key Technique**: Mining JavaScript files for S3 bucket references, identifying deleted buckets via "NoSuchBucket" errors, and claiming them to serve malicious content under the legitimate domain.
- **Source**: https://blogs.jsmon.sh/s3-bucket-takeover-via-javascript-file/

### 38. S3 Bucket Misconfiguration: From Basics to Pawn
- **Author**: Bug Bounty POC
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: Multiple Programs
- **Vulnerability Type**: S3 Bucket Misconfiguration
- **Summary**: Comprehensive writeup detailing how misconfigured S3 bucket permissions allow unauthorized read/write access. By identifying buckets with public ACLs, the researcher could upload malicious files, modify existing content, and potentially compromise applications loading resources from the affected buckets.
- **Key Technique**: Using AWS CLI tools to enumerate and test S3 bucket permissions, exploiting overly permissive bucket policies for read/write access to sensitive data.
- **Source**: https://bugbountypoc.com/s3-bucket-misconfiguration-from-basics-to-pawn/

### 39. Subdomain Takeover via Unclaimed S3 Bucket on HackerOne
- **Author**: Undisclosed (HackerOne Report #121461)
- **Severity**: High
- **Bounty**: $2,000
- **Target**: Private Program
- **Vulnerability Type**: Subdomain Takeover
- **Summary**: A CNAME DNS record pointed to an AWS S3 bucket that had been deleted. The researcher registered a new S3 bucket with the same name, gaining control of the subdomain and the ability to serve arbitrary content under the target's domain.
- **Key Technique**: Identifying dangling CNAME records pointing to nonexistent S3 buckets and claiming those bucket names to serve controlled content under the victim's domain.
- **Source**: https://hackerone.com/reports/121461

### 40. Remote Code Execution in Cloudflare's cdnjs
- **Author**: Referenced in Awesome-Bugbounty-Writeups
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Cloudflare (cdnjs)
- **Vulnerability Type**: Remote Code Execution
- **Summary**: A critical RCE vulnerability was discovered in Cloudflare's cdnjs infrastructure, which serves JavaScript libraries to millions of websites. The vulnerability could have been exploited to inject malicious code into the supply chain of countless web applications.
- **Key Technique**: Exploiting the package processing pipeline in cdnjs to achieve code execution on Cloudflare's infrastructure through specially crafted library packages.
- **Source**: https://github.com/devanshbatham/Awesome-Bugbounty-Writeups

### 41. How I Made $15K from GitHub Secret Leaks
- **Author**: Tillson Galloway
- **Severity**: High-Critical (varies)
- **Bounty**: $15,000 (combined)
- **Target**: Multiple Companies
- **Vulnerability Type**: Credential Exposure / Information Disclosure
- **Summary**: The researcher systematically searched GitHub for leaked API keys, passwords, and access tokens across multiple organizations. By using targeted search dorks and automated scanning, they identified valid credentials that provided access to company infrastructure, earning $15,000 in combined bounties.
- **Key Technique**: Using GitHub search dorks (filename:.env, password, api_key, etc.) and automated tools like truffleHog to discover leaked secrets in public repositories and commit histories.
- **Source**: https://tillsongalloway.com/finding-sensitive-information-on-github/index.html

### 42. Stealing Users' OAuth Tokens (GSA Bounty)
- **Author**: Undisclosed (HackerOne Report #665651)
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: GSA (U.S. General Services Administration)
- **Severity**: High
- **Vulnerability Type**: OAuth Token Theft
- **Summary**: The researcher discovered a vulnerability in a GSA application that allowed stealing OAuth tokens from authenticated users. The flaw in the OAuth implementation leaked access tokens through insecure handling of redirect parameters.
- **Key Technique**: Manipulating OAuth redirect_uri parameters to redirect token delivery to an attacker-controlled endpoint, capturing authenticated session tokens.
- **Source**: https://hackerone.com/reports/665651

---

## 5. API Security Findings

### 43. Disclosure of Payment Transactions via GraphQL Query (176 upvotes)
- **Author**: Undisclosed (HackerOne)
- **Severity**: Critical
- **Bounty**: $10,000+
- **Target**: Shopify
- **Vulnerability Type**: GraphQL Information Disclosure
- **Summary**: A GraphQL query allowed unauthorized access to payment transaction data. The researcher discovered that the GraphQL endpoint lacked proper authorization checks, enabling any authenticated user to query sensitive financial information of other merchants through introspection and crafted queries.
- **Key Technique**: Using GraphQL introspection to discover hidden queries and mutations, then crafting unauthorized queries to access other users' payment data.
- **Source**: https://github.com/reddelexc/hackerone-reports

### 44. $1,000 Bug Using Simple GraphQL Introspection Query
- **Author**: Piyush Kumawat (securitycipher)
- **Severity**: Medium
- **Bounty**: $1,000
- **Target**: Private Program
- **Vulnerability Type**: GraphQL Information Disclosure
- **Summary**: The researcher earned $1,000 by discovering that a production GraphQL endpoint had introspection enabled. This exposed the entire API schema including all queries, mutations, types, and hidden endpoints. The disclosed schema revealed sensitive operations that were not intended to be public.
- **Key Technique**: Sending a standard GraphQL introspection query (__schema) to enumerate the complete API schema and identify sensitive hidden mutations and queries.
- **Source**: https://infosecwriteups.com/1000-bug-using-simple-graphql-introspection-query-b68da8260877

### 45. GraphQL Bug Resulting in Authentication Bypass
- **Author**: HackerOne Blog
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: Authentication Bypass via GraphQL
- **Summary**: A GraphQL endpoint allowed unauthenticated users to invoke sensitive mutations including user creation with admin privileges. The researcher used introspection to discover the createUser mutation accepted a role parameter, enabling privilege escalation to admin without authentication.
- **Key Technique**: Exploiting broken access control on GraphQL mutations to create admin-level accounts using exposed createUser(role: "ADMIN") mutation.
- **Source**: https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass

### 46. SSRF Vulnerability via Analytics Reports
- **Author**: Undisclosed (HackerOne Report #2262382)
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: SSRF via Analytics
- **Summary**: A Server-Side Request Forgery vulnerability was discovered in the analytics report generation feature. The endpoint accepted URLs for data sources that could be manipulated to access internal services and cloud metadata endpoints.
- **Key Technique**: Injecting internal URLs into analytics report data source parameters to force server-side requests to internal infrastructure and metadata endpoints.
- **Source**: https://hackerone.com/reports/2262382

### 47. IDOR Allowing Deletion of CMS and User Data (P1)
- **Author**: jedus0r
- **Severity**: Critical (P1)
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: IDOR
- **Summary**: The researcher found two IDOR vulnerabilities in the same program. The first allowed deletion of a CMS for all customers (P3), while the second was escalated to P1 by demonstrating it allowed deletion of all website users and collection of their personal data including email, phone, and names.
- **Key Technique**: Manipulating object IDs in API requests to access and delete other users' CMS data and collect PII across the entire platform.
- **Source**: https://infosecwriteups.com/idor-insecure-direct-object-references-my-first-p1-in-bugbounty-fb01f50e25df

### 48. Blind SQL Injection in U.S. Department of Defense
- **Author**: Undisclosed (HackerOne Report #2597543)
- **Severity**: Critical
- **Bounty**: N/A (Government Disclosure Program)
- **Target**: U.S. Department of Defense
- **Vulnerability Type**: Blind SQL Injection
- **Summary**: A blind SQL injection vulnerability was discovered in a U.S. Department of Defense web application. The researcher demonstrated data extraction through time-based blind injection techniques, proving the ability to retrieve sensitive data from the backend database.
- **Key Technique**: Using time-based blind SQL injection with conditional SLEEP statements to extract database contents one character at a time from a government web application.
- **Source**: https://hackerone.com/reports/2597543

### 49. IDOR in Banking Application
- **Author**: Referenced in WebAsha Technologies
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Banking Application
- **Vulnerability Type**: IDOR
- **Summary**: An IDOR vulnerability in a banking application allowed attackers to access other users' financial data by modifying transaction IDs in API calls. The researcher intercepted API requests and changed the transaction identifiers, successfully viewing other customers' transaction histories and account details.
- **Key Technique**: Intercepting and modifying transaction ID parameters in banking API endpoints to access other users' financial records without authorization checks.
- **Source**: https://www.webasha.com/blog/what-is-an-example-of-a-real-bug-bounty-report-where-idor-was-used-to-exploit-a-banking-application

### 50. API Key Leakage and Source Code Disclosure in Healthcare E-Commerce
- **Author**: Avinash Jain (@logicbomb)
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: India's Largest E-Commerce Healthcare Company
- **Vulnerability Type**: API Key Leak / Source Code Disclosure
- **Summary**: The researcher discovered exposed API keys and source code in India's largest healthcare e-commerce company. The leaked API keys provided access to backend services, and the source code disclosure revealed internal architecture, credentials, and business logic that could be exploited for further attacks.
- **Key Technique**: Analyzing JavaScript source files, .env files, and public repositories to discover hardcoded API keys and leaked source code with embedded credentials.
- **Source**: https://infosecwriteups.com/bugbounty-api-keys-leakage-source-code-disclosure-in-indias-largest-e-commerce-health-care-c75967392c7e

### 51. Google Maps API Key Disclosure
- **Author**: Vedant Roy
- **Severity**: Medium
- **Bounty**: Undisclosed
- **Target**: Private Program (using Google Maps)
- **Vulnerability Type**: API Key Disclosure
- **Summary**: The researcher found exposed Google Maps API keys in a bug bounty target's frontend code. The unrestricted API keys could be used to make API calls at the target's expense, potentially resulting in significant financial impact through API abuse and quota exhaustion.
- **Key Technique**: Extracting Google Maps API keys from frontend JavaScript and demonstrating impact by showing the keys had no IP or referrer restrictions, allowing abuse from any source.
- **Source**: https://medium.com/@vedantroy/bug-bounty-write-up-api-key-disclosure-google-maps-74c5ad9b19d4

### 52. How Neo Found an SSRF in Faraday
- **Author**: ProjectDiscovery Research
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: Faraday
- **Vulnerability Type**: SSRF
- **Summary**: ProjectDiscovery's AI-powered scanner Neo discovered an SSRF vulnerability in Faraday, a popular security tool. The finding demonstrated how automated vulnerability detection can identify issues that manual testing might miss, particularly in security tools themselves.
- **Key Technique**: AI-powered automated vulnerability detection identifying SSRF in web application import functionality that accepted user-controlled URLs.
- **Source**: https://projectdiscovery.io/blog/how-neo-found-an-ssrf-vulnerability-in-faraday-and-why-it-matters-for-every-team-that-ships-code

---

## 6. Client-Side Attacks

### 53. Critical XSS on Public Bug Bounty Program
- **Author**: 1day
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Public Program
- **Vulnerability Type**: Cross-Site Scripting (XSS)
- **Summary**: The researcher found a critical XSS vulnerability on a public bug bounty program by discovering an unauthenticated stored XSS that could be chained with a credential harvesting attack. The XSS silently redirected victims to a cloned login page for phishing.
- **Key Technique**: Escalating stored XSS by injecting JavaScript that silently redirected authenticated users to a credential-harvesting clone of the login page.
- **Source**: https://1-day.medium.com/how-i-found-a-critical-xss-on-a-public-bug-bounty-program-27d492117f61

### 54. Prototype Pollution Vulnerability ($4,000)
- **Author**: S1r1us
- **Severity**: High
- **Bounty**: $4,000
- **Target**: Private Program
- **Vulnerability Type**: Prototype Pollution
- **Summary**: The researcher discovered a prototype pollution vulnerability by sending a crafted JSON payload that polluted Object.prototype in the application. This allowed injecting properties into all JavaScript objects, which could be leveraged for XSS, authentication bypass, or denial of service.
- **Key Technique**: Sending JSON payloads with __proto__ keys to pollute JavaScript's global Object prototype, affecting application behavior across all inheriting objects.
- **Source**: https://blog.s1r1us.ninja/research/PP

### 55. First Bounty: Prototype Pollution ($175)
- **Author**: 1-day
- **Severity**: Medium
- **Bounty**: $175
- **Target**: Private Program
- **Vulnerability Type**: Prototype Pollution
- **Summary**: The researcher's first bug bounty was a prototype pollution vulnerability that allowed manipulating the application's behavior by injecting properties into JavaScript's prototype chain. While the bounty was modest, the finding demonstrated the impact of client-side prototype chain manipulation.
- **Key Technique**: Identifying user input that flows into deep merge operations without __proto__ sanitization, enabling prototype pollution.
- **Source**: https://1-day.medium.com/175-prototype-pollution-vulnerability-my-first-bounty-197738a32330

### 56. Web Cache Deception on Private Bug Bounty Program
- **Author**: snoopy
- **Severity**: High
- **Bounty**: $500+
- **Target**: Private Program
- **Vulnerability Type**: Web Cache Deception
- **Summary**: The researcher exploited web cache deception to expose authenticated user data. By appending static file extensions to authenticated URLs, the CDN cached responses containing sensitive session data that could be accessed by any unauthenticated user.
- **Key Technique**: Appending .css or .js extensions to authenticated endpoints to trick CDN caching rules into caching dynamic authenticated responses as static content.
- **Source**: https://medium.com/@snoopy101/web-cache-deception-attack-on-a-private-bug-bounty-program-52872cbdeedc

### 57. Web Cache Poisoning Leading to Stored XSS (Postmates)
- **Author**: Undisclosed (HackerOne Report #492841)
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: Postmates
- **Vulnerability Type**: Web Cache Poisoning / XSS
- **Summary**: A web cache poisoning vulnerability in Postmates allowed the attacker to inject malicious content into cached responses. By manipulating unkeyed headers, the poisoned response containing XSS payload was served to all subsequent users requesting the same URL.
- **Key Technique**: Identifying unkeyed HTTP headers (not included in cache key computation) and injecting XSS payloads through them to poison cached responses.
- **Source**: https://hackerone.com/reports/492841

### 58. Injecting {{6*200}} to $1,200 (SSTI)
- **Author**: Gaurav Narwani
- **Severity**: High
- **Bounty**: $1,200
- **Target**: Private Program
- **Vulnerability Type**: Server-Side Template Injection
- **Summary**: By injecting the template expression {{6*200}} and receiving 1200 in the response, the researcher confirmed SSTI vulnerability. The finding was escalated to demonstrate code execution capability and earned $1,200 -- coincidentally matching the template multiplication result.
- **Key Technique**: Detecting SSTI by injecting mathematical expressions in template syntax ({{7*7}}, ${7*7}) and observing server-evaluated results in responses.
- **Source**: https://gauravnarwani.com/injecting-6200-to-1200/

### 59. Browser-Powered Desync: New Class of Request Smuggling
- **Author**: James Kettle (PortSwigger)
- **Severity**: Critical
- **Bounty**: Included in $200K+ total
- **Target**: Multiple platforms
- **Vulnerability Type**: Browser-Powered Request Smuggling
- **Summary**: Kettle demonstrated a new class of HTTP desync attacks that could be triggered directly from a victim's browser, eliminating the need for a man-in-the-middle position. This browser-powered desync attack affects users visiting a malicious webpage and can poison their connections to legitimate sites.
- **Key Technique**: Using client-side JavaScript to trigger CL.0 desync attacks through cross-origin requests, hijacking the victim's subsequent requests to legitimate websites.
- **Source**: https://portswigger.net/daily-swig/browser-powered-desync-new-class-of-http-request-smuggling-attacks-showcased-at-black-hat-usa

### 60. Simple 2FA Bypass Using PortSwigger Technique ($2,500)
- **Author**: Mukilan Baskaran
- **Severity**: High
- **Bounty**: $2,500
- **Target**: Private Program
- **Vulnerability Type**: 2FA Bypass
- **Summary**: The researcher applied a 2FA bypass technique learned from PortSwigger's Web Security Academy to a live bug bounty target. The bypass involved manipulating the response from the 2FA verification endpoint, changing the success flag from false to true.
- **Key Technique**: Intercepting the 2FA verification response and modifying the JSON "success" field from false to true, bypassing the client-side 2FA enforcement.
- **Source**: https://mukibas37.medium.com/simple-2fa-bypass-portswigger-writeup-how-i-used-this-method-for-a-real-time-bug-and-earned-2-500-d18b5e317c3a

---

## 7. Server-Side Attacks

### 61. SQL Injection in GraphQL Endpoint (170 upvotes)
- **Author**: Undisclosed (HackerOne)
- **Severity**: Critical
- **Bounty**: $10,000+
- **Target**: Major Platform (HackerOne Disclosed)
- **Vulnerability Type**: SQL Injection
- **Summary**: A SQL injection vulnerability was discovered in a GraphQL endpoint where user input in GraphQL variables was passed directly to SQL queries without parameterization. The researcher demonstrated full database extraction capability through the GraphQL API.
- **Key Technique**: Injecting SQL payloads through GraphQL query variables that were concatenated into backend SQL queries without proper parameterization.
- **Source**: https://github.com/reddelexc/hackerone-reports

### 62. SQL Injection Leading to Bounty: Critical Finding
- **Author**: Arrhenius Paelongan
- **Severity**: Critical
- **Bounty**: Undisclosed (described as "$$$ Bounty")
- **Target**: Private Program
- **Vulnerability Type**: SQL Injection
- **Summary**: The researcher discovered a critical SQL injection vulnerability by testing input parameters that were not properly sanitized. The injection allowed extracting database contents, demonstrating the ability to retrieve sensitive user data and administrative credentials.
- **Key Technique**: Identifying injection points in search and filter parameters, using UNION-based and Boolean-based SQL injection techniques for data extraction.
- **Source**: https://medium.com/@arrheniuspaelongan09/sql-injection-leads-to-bounty-how-i-found-a-critical-bug-cbacc35a2f19

### 63. Boolean-Based SQL Injection (Bug Bounty Series)
- **Author**: Cyb3r M!nds
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: Boolean-Based Blind SQL Injection
- **Summary**: The researcher exploited a Boolean-based blind SQL injection where the application returned different responses for true and false conditions. By constructing binary search queries, sensitive data was extracted one bit at a time from the database.
- **Key Technique**: Using Boolean conditions in SQL queries to determine true/false states from application response differences, enabling binary search data extraction.
- **Source**: https://cyb3rmind.medium.com/4-bug-bounty-series-exploiting-boolean-based-sql-injection-3455d800892e

### 64. RCE Found in Hosting Platform
- **Author**: Sancho Godinho
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Hosting Platform
- **Vulnerability Type**: Remote Code Execution
- **Summary**: The researcher discovered an RCE vulnerability in a hosting platform by manipulating the package.json file. By adding "i" and "install" keys to the scripts object, the malicious commands were executed during the npm installation process on the hosting provider's servers.
- **Key Technique**: Exploiting npm lifecycle scripts (preinstall/postinstall) in package.json to achieve arbitrary command execution during automated deployment processes.
- **Source**: https://infosecwriteups.com/how-i-found-an-rce-vulnerability-in-a-hosting-platform-9d5604a1d9b9

### 65. Remote Code Execution in Slack Desktop App
- **Author**: Undisclosed (HackerOne Report #783877)
- **Severity**: Critical
- **Bounty**: $1,750
- **Target**: Slack
- **Vulnerability Type**: Remote Code Execution
- **Summary**: A remote code execution vulnerability was discovered in Slack's desktop application. The vulnerability allowed an attacker to execute arbitrary code on a victim's machine through the Slack desktop client by exploiting the Electron framework's handling of certain content.
- **Key Technique**: Exploiting Electron framework's node integration and improper Content Security Policy in Slack's desktop app to achieve OS-level code execution.
- **Source**: https://hackerone.com/reports/783877

### 66. CVE-2024-34102: Adobe Commerce/Magento XXE (CVSS 9.8)
- **Author**: Security Researchers
- **Severity**: Critical (CVSS 9.8)
- **Bounty**: Undisclosed
- **Target**: Adobe Commerce / Magento
- **Vulnerability Type**: Pre-Authentication XXE
- **Summary**: A critical pre-authentication XML External Entity injection vulnerability was found in Adobe Commerce/Magento (CVE-2024-34102) with a CVSS score of 9.8. The vulnerability allowed unauthenticated attackers to read arbitrary files and potentially achieve RCE on e-commerce platforms powered by Magento.
- **Key Technique**: Exploiting pre-authentication XML parsing in Magento's API endpoints to inject external entity definitions for file disclosure and SSRF.
- **Source**: https://portswigger.net/research

### 67. CVE-2024-30043: SharePoint XXE Injection
- **Author**: Undisclosed
- **Severity**: High
- **Bounty**: Undisclosed (Microsoft MSRC)
- **Target**: Microsoft SharePoint
- **Vulnerability Type**: XXE Injection
- **Summary**: An XML eXternal Entity injection vulnerability was discovered in Microsoft SharePoint (CVE-2024-30043) that allowed attackers to read files and perform SSRF through SharePoint's XML parsing functionality. Microsoft patched the vulnerability through their regular security update cycle.
- **Key Technique**: Injecting malicious XML with external entity definitions into SharePoint's document processing features to exfiltrate server-side files.
- **Source**: https://pentester.land/writeups/

### 68. Remote Deserialization Bug in Microsoft RDP Client ($5,000)
- **Author**: Undisclosed
- **Severity**: Critical
- **Bounty**: $5,000
- **Target**: Microsoft (CVE-2021-38666)
- **Vulnerability Type**: Remote Deserialization / RCE
- **Summary**: A remote deserialization vulnerability was found in Microsoft's RDP (Remote Desktop Protocol) client through the Smart Card Extension. The vulnerability allowed a malicious RDP server to execute arbitrary code on the connecting client's machine.
- **Key Technique**: Exploiting insecure deserialization in the RDP client's Smart Card Extension to achieve client-side remote code execution when connecting to a malicious RDP server.
- **Source**: https://writeups.io/

### 69. Dependabot Core TOCTOU Race Condition
- **Author**: Adnan Khan
- **Severity**: High
- **Bounty**: Undisclosed
- **Target**: GitHub (Dependabot)
- **Vulnerability Type**: TOCTOU Race Condition
- **Summary**: A time-of-check to time-of-use race condition was discovered in Dependabot Core's CI pipeline. The vulnerability allowed attackers to modify files between the security check and the execution phase, potentially compromising GitHub's automated dependency update system.
- **Key Technique**: Exploiting the time gap between Dependabot's security validation check and its execution of the update action to inject malicious changes.
- **Source**: https://adnanthekhan.com/posts/dependabot-core-toctou-writeup/

### 70. Unrestricted File Upload to RCE
- **Author**: Shay Grant
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: Unrestricted File Upload / RCE
- **Summary**: The researcher bypassed file upload restrictions by manipulating the file extension in the request after client-side JavaScript validation. By uploading an ASHX web shell to a Windows/IIS server, full remote code execution was achieved on the target system.
- **Key Technique**: Bypassing client-side file extension validation using Burp Suite to change the extension to .ashx after the browser's JavaScript check, uploading a web shell for RCE.
- **Source**: https://medium.com/@shayboy123/how-i-gain-unrestricted-file-upload-remote-code-execution-bug-bounty-381d0aab0dad

### 71. Unrestricted File Upload Leading to SSRF and RCE
- **Author**: itsfading
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: File Upload -> SSRF -> RCE Chain
- **Summary**: The researcher chained an unrestricted file upload vulnerability with SSRF to achieve remote code execution. The uploaded file triggered server-side processing that could be manipulated to make internal requests, ultimately leading to code execution on the backend.
- **Key Technique**: Uploading specially crafted files that triggered server-side processing, exploiting the processing logic to achieve SSRF and pivoting to RCE.
- **Source**: https://itsfading.github.io/posts/Unrestricted-File-Upload-Leads-to-SSRF-and-RCE/

### 72. Apple RCE via File Upload
- **Author**: httpvoid
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Apple
- **Vulnerability Type**: Remote Code Execution
- **Summary**: The researcher achieved remote code execution on Apple's infrastructure through a file upload vulnerability. The writeup details the exploitation process and the collaboration with Apple's security team to resolve the issue.
- **Key Technique**: Exploiting Apple's file processing pipeline through malicious file uploads that triggered server-side code execution during processing.
- **Source**: https://github.com/httpvoid/writeups/blob/main/Apple-RCE.md

### 73. First Critical Bug: Unauthenticated File Upload to LFI
- **Author**: terp0x0
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Private Program
- **Vulnerability Type**: File Upload / LFI via Path Traversal
- **Summary**: The researcher's first critical bug bounty finding was an unauthenticated arbitrary file upload that, combined with path traversal, led to Local File Inclusion (LFI). The chain allowed reading sensitive server files and potentially achieving code execution through log poisoning or similar techniques.
- **Key Technique**: Exploiting an unauthenticated file upload endpoint with path traversal sequences (../) to write files to arbitrary locations and achieve LFI.
- **Source**: https://medium.com/@terp0x0/how-i-found-my-first-critical-bug-bounty-unauthenticated-arbitrary-file-upload-lead-to-lfi-via-5f33c80fc44f

### 74. Bypassing GitHub SAML Authentication
- **Author**: ProjectDiscovery Research
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: GitHub
- **Vulnerability Type**: SAML Authentication Bypass
- **Summary**: Researchers discovered a vulnerability that allowed bypassing GitHub's SAML authentication when encrypted assertions were in use. The flaw could allow unauthorized access to organizations using SAML SSO for authentication, compromising the security of enterprise GitHub accounts.
- **Key Technique**: Exploiting weaknesses in SAML encrypted assertion handling to forge authentication tokens and bypass enterprise SSO controls.
- **Source**: https://projectdiscovery.io/blog

### 75. IngressNightmare: Kubernetes Ingress Controller RCE (CVE-2025-1974)
- **Author**: Wiz Research Team (analyzed by ProjectDiscovery)
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Kubernetes Ingress-NGINX Controller
- **Vulnerability Type**: Remote Code Execution
- **Summary**: A critical vulnerability in Kubernetes Ingress-NGINX Controller allowed unauthenticated remote code execution. The vulnerability affected one of the most widely used Kubernetes ingress controllers, potentially compromising entire Kubernetes clusters across thousands of organizations.
- **Key Technique**: Exploiting the ingress controller's configuration injection to achieve code execution on the underlying nginx process with cluster-level permissions.
- **Source**: https://projectdiscovery.io/blog

---

## 8. Mobile App Findings

### 76. Hardcoded AWS/GCP Credentials in iOS Keychain
- **Author**: Mobile Bug Bounty Methodology Guide
- **Severity**: Critical
- **Bounty**: Varies
- **Target**: Multiple iOS Applications
- **Vulnerability Type**: Credential Exposure
- **Summary**: Security researchers found that multiple iOS applications stored AWS and GCP credentials in the iOS Keychain. Using Keychain-Dumper, researchers extracted cloud provider credentials that provided access to backend infrastructure, S3 buckets, and internal APIs.
- **Key Technique**: Using Keychain-Dumper on jailbroken devices to extract cloud provider credentials (AWS access keys, GCP service account keys) stored by applications in the iOS Keychain.
- **Source**: https://ivrodriguez.com/tips-for-mobile-bug-bounty-hunting/

### 77. Sensitive Data in UserDefaults .plist Configuration
- **Author**: Mobile Security Methodology
- **Severity**: High
- **Bounty**: Varies
- **Target**: Multiple iOS Applications
- **Vulnerability Type**: Insecure Data Storage
- **Summary**: Multiple iOS applications were found storing sensitive information including tokens, API keys, and user credentials in UserDefaults .plist configuration files. These files are stored unencrypted and can be accessed through device backups or on jailbroken devices, exposing authentication tokens and API credentials.
- **Key Technique**: Examining UserDefaults .plist files for sensitive data by searching for keywords like "secret", "crypt", "private", "token", "key", and "password" in the application's data directory.
- **Source**: https://ivrodriguez.com/tips-for-mobile-bug-bounty-hunting/

### 78. Android Data Logging and Insecure Debugging
- **Author**: Mobile Security Researchers
- **Severity**: Medium-High
- **Bounty**: Varies
- **Target**: Multiple Android Applications
- **Vulnerability Type**: Information Disclosure
- **Summary**: Multiple Android applications were found logging sensitive data including authentication tokens, user credentials, and PII to logcat in debug builds that were shipped to production. Attackers with physical access or malware with READ_LOGS permission could harvest this sensitive data.
- **Key Technique**: Using adb logcat to capture sensitive data logged by applications in production, including session tokens, API keys, and user credentials exposed through verbose logging.
- **Source**: https://github.com/B3nac/Android-Reports-and-Resources

### 79. SSL Pinning Bypass Leading to API Key Theft
- **Author**: Multiple Android Security Researchers
- **Severity**: High
- **Bounty**: Varies
- **Target**: Multiple Android Applications
- **Vulnerability Type**: Insecure Transport / SSL Pinning Bypass
- **Summary**: By bypassing SSL certificate pinning using Frida scripts or Xposed Framework modules, researchers intercepted HTTPS traffic from mobile applications. This revealed hardcoded API keys, authentication tokens, and internal API endpoints that were assumed to be protected by transport-layer encryption.
- **Key Technique**: Using Frida to hook SSL/TLS certificate validation methods at runtime, bypassing pinning to intercept and analyze all HTTPS traffic between the app and backend APIs.
- **Source**: https://github.com/Raunaksplanet/Learn-android-bug-bounty

### 80. Android HackerOne Disclosed Reports Collection
- **Author**: B3nac (GitHub)
- **Severity**: Various
- **Bounty**: Various
- **Target**: Multiple Android Applications
- **Vulnerability Type**: Various (Deep Links, Content Providers, WebView)
- **Summary**: A comprehensive collection of Android-specific HackerOne disclosed reports covering vulnerabilities including insecure deep link handling, exported content providers leaking data, WebView JavaScript injection, and insecure broadcast receivers. The collection demonstrates common vulnerability patterns in Android applications.
- **Key Technique**: Systematic testing of Android-specific attack surfaces: intent handlers, content providers, broadcast receivers, and WebView configurations.
- **Source**: https://github.com/B3nac/Android-Reports-and-Resources

### 81. Hacking a Crypto Exchange (IDOR)
- **Author**: mabdullah22
- **Severity**: Critical
- **Bounty**: Undisclosed
- **Target**: Cryptocurrency Exchange
- **Vulnerability Type**: IDOR / Account Takeover
- **Summary**: The researcher exploited an IDOR vulnerability in a cryptocurrency exchange's mobile API. By modifying user identifiers in API requests, they could access other users' wallets, view balances, and potentially initiate unauthorized transactions.
- **Key Technique**: Manipulating user ID parameters in the crypto exchange's mobile API to access other users' wallet information and transaction history without authorization.
- **Source**: https://steemit.com/cryptocurrency/@mabdullah22/how-i-hacked-a-crypto-exchange-bug-bounty-writeup

---

## 9. Methodology Writeups

### 82. NahamSec: Getting Started in Bug Bounty
- **Author**: NahamSec (Ben Sadeghipour)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: NahamSec's comprehensive guide covers building a systematic approach to bug bounty hunting. Key insights include forming a mental checklist, treating every "bugless" night as a learning opportunity, and approaching targets without considering other hunters. He emphasizes learning from disclosed reports and developing unique perspectives.
- **Key Technique**: Building a consistent testing methodology, starting with a single vulnerability class and expanding, and reading disclosed reports on HackerOne to learn patterns.
- **Source**: https://www.nahamsec.com/getting-started-in-bug-bounty

### 83. Jason Haddix: The Bug Hunter's Methodology v4
- **Author**: Jason Haddix (@jhaddix)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: TBHM is the de facto standard bug bounty methodology, covering Reconnaissance, Application Analysis, Mapping, Authorization/Sessions, Tactical Fuzzing, Privilege Escalation, Transport/Logic, Web Services, and Mobile Vulnerabilities. The methodology is updated annually and includes specific tool recommendations for each phase.
- **Key Technique**: Four-step recon methodology: subdomain enumeration (Amass, Subfinder), port scanning, content discovery, and technology fingerprinting before moving to vulnerability assessment.
- **Source**: https://github.com/jhaddix/tbhm

### 84. STOK & Tomnomnom: Reconnaissance Methods
- **Author**: STOK and Tom Hudson (Tomnomnom)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: STOK and Tomnomnom's reconnaissance methodology covers automated asset discovery, subdomain enumeration, and finding hidden attack surfaces. The approach uses custom-built Go tools for URL discovery, parameter mining, and JavaScript analysis to identify unique entry points that other hunters miss.
- **Key Technique**: Using tools like waybackurls, gf (grep-friendly patterns), and httprobe to discover forgotten endpoints, parameters, and JavaScript files that reveal hidden API endpoints.
- **Source**: https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters/blob/master/assets/talks.md

### 85. The "Ebb & Flow" Recon Methodology
- **Author**: R-s0n (DefCon 32 Bug Bounty Village)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: The Ebb & Flow methodology suggests hunting should move in and out of the recon methodology like ocean tides. Hunters should move through recon steps until they identify 3-5 attack vectors on a target URL, then test those vectors. When stuck, return to earlier recon phases to try new tools and techniques.
- **Key Technique**: Alternating between reconnaissance and testing phases, maintaining a dynamic workflow that adapts based on findings rather than following a rigid linear process.
- **Source**: https://github.com/R-s0n/bug-bounty-village-defcon32-workshop/blob/main/recon-methodology.md

### 86. NahamSec: Bug Bounty Full Time
- **Author**: NahamSec (Ben Sadeghipour)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: Career Methodology
- **Vulnerability Type**: N/A
- **Summary**: NahamSec shares insights on transitioning to full-time bug bounty hunting, covering income strategies, program selection, time management, and the mental aspects of hacking as a career. He discusses the realities of inconsistent income and strategies for maintaining motivation.
- **Key Technique**: Diversifying across multiple programs, building reputation on platforms for invite-only programs, and treating bug bounty as a business with consistent work schedules.
- **Source**: https://www.nahamsec.com/posts/hacking-full-time

### 87. Reaching 1000+ Reps on HackerOne
- **Author**: ibruteforce (BugBountyHunter.com)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: A detailed guide on reaching 1000+ reputation points on HackerOne by consistently finding valid bugs. The author shares strategies for program selection, report quality, communication with triagers, and maintaining a high signal-to-noise ratio in submissions.
- **Key Technique**: Focusing on programs with large scopes, writing clear reproduction steps, and building relationships with program teams through professional communication.
- **Source**: https://www.bugbountyhunter.com/articles/?on=hackingonbb

### 88. Building a Fast One-Shot Recon Script
- **Author**: ProjectDiscovery
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: ProjectDiscovery's guide to building an automated recon script that combines subdomain enumeration, port scanning, HTTP probing, and vulnerability detection in a single execution. The script uses Nuclei templates to automatically detect known vulnerabilities after asset discovery.
- **Key Technique**: Chaining subfinder, httpx, and nuclei in a bash script for rapid one-shot reconnaissance that discovers assets and immediately tests for known vulnerabilities.
- **Source**: https://projectdiscovery.io/blog/building-one-shot-recon

### 89. How to Research & Reverse Web Vulnerabilities 101
- **Author**: ProjectDiscovery
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: A methodology guide for analyzing and reversing disclosed CVEs to understand vulnerability patterns. The approach involves picking a disclosed CVE, rebuilding the environment, tracing from patch to primitive, and searching for similar patterns in adjacent code. This pattern recognition methodology helps researchers discover new vulnerabilities independently.
- **Key Technique**: Reverse engineering patches by diffing before/after code changes, understanding the vulnerability primitive, and searching for the same pattern in related projects and forks.
- **Source**: https://projectdiscovery.io/blog/how-to-research-web-vulnerabilities

### 90. Bug Bounty Methodology 2025
- **Author**: amrelsagaei (GitHub)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: A comprehensive 2025 bug bounty methodology covering tools, techniques, and step-by-step processes for reconnaissance, enumeration, and testing. The guide includes modern tool recommendations and updated techniques for current web application architectures.
- **Key Technique**: Combining passive and active recon with automated scanning, followed by manual testing of identified attack surfaces using vulnerability-specific checklists.
- **Source**: https://github.com/amrelsagaei/Bug-Bounty-Hunting-Methodology-2025

### 91. The Best Bug Bounty Recon Methodology (2024)
- **Author**: HiveFive Community
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: A community-curated analysis of the best bug bounty recon methodologies. Top hunters have moved away from comprehensive recon frameworks and instead focus on finding high-impact bugs that others overlook. The key insight is that recon should serve testing, not replace it.
- **Key Technique**: Focusing recon on identifying unique attack surfaces rather than maximum breadth, prioritizing depth of testing on fewer targets over shallow scanning of many.
- **Source**: https://www.hivefive.community/p/the-best-bug-bounty-recon-methodology

### 92. Frans Rosen: The OG Bug Bounty King
- **Author**: Frans Rosen (Detectify)
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: Frans Rosen, co-founder of Detectify, shares his approach to bug bounty hunting including discovering S3 subdomain takeovers, exploiting edge cases in popular platforms, and building automated monitoring tools. His methodology emphasizes persistence, creativity, and building tools to scale hunting efforts.
- **Key Technique**: Building custom monitoring tools for continuous asset discovery, automated subdomain takeover detection, and systematic testing of edge cases in authentication flows.
- **Source**: https://bugbountyforum.com/blog/ama/fransrosen/

### 93. Recon Methodology for Bug Bounty Hunting
- **Author**: Md. Raihan
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: N/A
- **Summary**: A step-by-step recon methodology starting with asset discovery (root domains), subdomain enumeration, port scanning, technology fingerprinting, and content discovery. The guide emphasizes the importance of thorough reconnaissance as the foundation for successful vulnerability discovery.
- **Key Technique**: Layered reconnaissance approach: root domain discovery -> subdomain enumeration -> port scanning -> HTTP probing -> content discovery -> technology fingerprinting.
- **Source**: https://medium.com/@raihan408548/recon-for-bug-bounty-hunting-f466fce74709

### 94. Payment Bypass Guide: 69 Case Studies
- **Author**: Illoy Scizceneghposter
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: E-Commerce / Payment Systems
- **Vulnerability Type**: Business Logic / Payment Bypass
- **Summary**: A comprehensive guide covering 69 different case studies of payment bypass techniques in bug bounty programs. Techniques include price manipulation in hidden fields, negative value exploits, coupon stacking, race conditions in checkout flows, currency conversion manipulation, and step-skipping in multi-stage payment processes.
- **Key Technique**: Systematically testing each step of payment flows: price parameters, quantity fields, discount codes, currency selection, and checkout process ordering for logic flaws.
- **Source**: https://medium.com/@illoyscizceneghposter/payment-bypass-guide-for-bug-bounty-69-case-studies-15379b4f76fa

### 95. Hunting Business Logic Flaws the Right Way (2025)
- **Author**: Kailasv
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: Business Logic
- **Summary**: A 2025 guide to finding business logic vulnerabilities, which account for 45% of bounty payouts according to HackerOne data. The guide covers techniques for testing multi-step workflows, payment processes, role-based access controls, and state management flaws that automated scanners cannot detect.
- **Key Technique**: Manually testing workflow state transitions, role boundary enforcement, and business rule validation by manipulating request sequences and parameter values outside expected ranges.
- **Source**: https://medium.com/@kailasv678/bug-bounty-in-2025-hunting-business-logic-flaws-the-right-way-614aba550f7b

### 96. Cracking JWTs: A Bug Bounty Hunting Guide (7 Parts)
- **Author**: Aditya Bhatt
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: JWT Security
- **Summary**: A comprehensive 7-part guide covering JWT vulnerability hunting including signature bypass, algorithm confusion (RS256 -> HS256), key brute-forcing, token replay attacks, and JWK header injection. Each part includes practical labs and real-world application scenarios.
- **Key Technique**: Testing JWT implementations for missing signature verification, algorithm confusion attacks, weak signing keys, and expired token acceptance.
- **Source**: https://infosecwriteups.com/cracking-jwts-a-bug-bounty-hunting-guide-99d6c21d78c9

### 97. Complete Mobile App Hacking Guide for Bug Bounty (2026)
- **Author**: BugHunter's Journal
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: Mobile Applications
- **Vulnerability Type**: N/A
- **Summary**: A comprehensive guide for mobile app bug bounty hunting covering both Android and iOS platforms. Topics include static analysis, dynamic testing, SSL pinning bypass, deep link exploitation, and API testing through mobile app proxying. The guide covers tools like Frida, Objection, and MobSF.
- **Key Technique**: Combining static APK/IPA analysis with runtime instrumentation using Frida to discover and exploit vulnerabilities in mobile application logic and data storage.
- **Source**: https://medium.com/@bughuntersjournal/the-complete-mobile-app-hacking-guide-for-bug-bounty-hunters-2026-edition-962aaa6f3c3c

### 98. OAuth Vulnerabilities for Bug Bounty (2025, Parts I & II)
- **Author**: Muhammad Shahzaib
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: OAuth Security
- **Summary**: A two-part guide to finding OAuth vulnerabilities in bug bounty programs, covering redirect_uri bypass techniques, token leakage via referrer headers, state parameter CSRF, open redirect chaining, and scope escalation. The guide includes practical testing workflows for each OAuth grant type.
- **Key Technique**: Systematically testing OAuth redirect_uri parameter for bypasses (subdomain matching, path traversal, parameter pollution) and checking for token leakage in URL fragments and referrer headers.
- **Source**: https://medium.com/@shahzaiblang2842/oauth-vulnerabilities-part-i-bug-bounty-2k25-61489bee174d

### 99. YesWeHack: Ultimate Guide to HTTP Request Smuggling
- **Author**: YesWeHack Learn Bug Bounty
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: HTTP Request Smuggling
- **Summary**: A comprehensive guide to finding and exploiting HTTP request smuggling vulnerabilities, covering CL.TE, TE.CL, and TE.TE variants. The guide explains how front-end/back-end server disagreements on request boundaries can be exploited for cache poisoning, session hijacking, and request routing attacks.
- **Key Technique**: Testing for request smuggling by sending ambiguous Content-Length and Transfer-Encoding headers to identify front-end/back-end parsing disagreements.
- **Source**: https://www.yeswehack.com/learn-bug-bounty/http-request-smuggling-guide-vulnerabilities

### 100. YesWeHack: XSS Attacks -- The Ultimate Guide
- **Author**: YesWeHack Learn Bug Bounty
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: Cross-Site Scripting
- **Summary**: A comprehensive guide covering all XSS attack types (reflected, stored, DOM-based), filter bypass techniques, and escalation methods. Topics include WAF bypass using HTML comments, encoding tricks, and event handler fuzzing. The guide emphasizes escalating XSS impact through session hijacking, credential theft, and admin action execution.
- **Key Technique**: Systematic fuzzing of input reflection points with context-aware payloads, bypassing WAFs through encoding, HTML comment injection, and alternative event handlers.
- **Source**: https://www.yeswehack.com/learn-bug-bounty/xss-attacks-exploitation-ultimate-guide

### 101. PortSwigger: Top 10 Web Hacking Techniques (Annual)
- **Author**: PortSwigger Research Community
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Research
- **Vulnerability Type**: Various
- **Summary**: PortSwigger's annual community-driven initiative to identify the most innovative web security research published each year. Now in its 19th edition, the list highlights novel attack classes, creative exploitation techniques, and groundbreaking research that shapes the future of web security testing and bug bounty hunting.
- **Key Technique**: Community nomination and voting process that surfaces the most impactful new attack techniques discovered each year.
- **Source**: https://portswigger.net/research/top-10-web-hacking-techniques-of-2025

### 102. Exploiting Exposed Tokens and API Keys (2023 Edition)
- **Author**: Kongsec
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: Credential Exposure
- **Summary**: A comprehensive guide to finding and exploiting exposed API keys and tokens across various services. Covers AWS, Slack, Google, and other API keys, emphasizing that companies rarely impose IP restrictions on APIs. Includes validation techniques using KeyHacks and nuclei templates to test whether discovered keys are still active.
- **Key Technique**: Using tools like truffleHog, gitleaks, and nuclei templates to discover exposed API keys in JavaScript files, .env files, and Git commit histories, then validating keys using service-specific API calls.
- **Source**: https://kongsec.medium.com/exploiting-exposed-tokens-and-api-keys-edition-2023-e894a3af7dcd

### 103. Bug Bounty Leaked Credentials Methodology
- **Author**: TruffleSecurity
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: Credential Exposure
- **Summary**: TruffleSecurity's guide to hunting leaked credentials in bug bounty programs, covering GitHub dork searches, JavaScript analysis, mobile app reverse engineering, and cloud metadata enumeration. The guide provides specific search patterns and automated tools for comprehensive credential hunting.
- **Key Technique**: Automated scanning of public repositories, JavaScript bundles, and mobile application binaries for leaked API keys, passwords, and service credentials using truffleHog and custom regex patterns.
- **Source**: https://trufflesecurity.com/blog/bug-bounty-hunting-leaked-credentials

### 104. SSTI Advanced Exploitation Guide
- **Author**: Intigriti Research
- **Severity**: N/A (Methodology)
- **Bounty**: N/A
- **Target**: General Methodology
- **Vulnerability Type**: Server-Side Template Injection
- **Summary**: Advanced guide for detecting and exploiting SSTI across different template engines including Jinja2, Mako, Twig, and Freemarker. Covers detection using mathematical expressions, escalation to file read and RCE, and engine-specific payload construction for maximum impact.
- **Key Technique**: Injecting engine-specific template expressions ({{7*7}} for Jinja2, #{7*7} for Thymeleaf, ${7*7} for Freemarker) to detect and identify the template engine, then escalating with engine-specific RCE payloads.
- **Source**: https://www.intigriti.com/researchers/blog/hacking-tools/exploiting-server-side-template-injection-ssti

### 105. My First 150 Days Bug Bounty Hunting ($5,650)
- **Author**: 3NVZ
- **Severity**: N/A (Methodology)
- **Bounty**: $5,650
- **Target**: Various Programs
- **Vulnerability Type**: Various
- **Summary**: A detailed account of 150 days of bug bounty hunting, documenting the journey from beginner to earning $5,650 with additional payouts pending. The author breaks down their time investment (approximately $9.80/hour), learning curve, tools used, and the types of vulnerabilities discovered at each stage of growth.
- **Key Technique**: Starting with simpler vulnerability classes (subdomain takeovers, information disclosure) and progressively tackling more complex bugs (injection, logic flaws) as skills develop.
- **Source**: https://medium.com/@YourFinalSin/my-first-150-days-bug-bounty-hunting-034623c89836

---

## Reference Resources

### Curated Writeup Collections
- **Pentester Land Writeups Directory**: https://pentester.land/writeups/
- **Awesome-Bugbounty-Writeups (GitHub)**: https://github.com/devanshbatham/Awesome-Bugbounty-Writeups
- **HackerOne Top Disclosed Reports**: https://github.com/reddelexc/hackerone-reports
- **Bug Bounty POC**: https://bugbountypoc.com/
- **Writeups.io**: https://writeups.io/
- **InfoSec Write-ups (Medium)**: https://infosecwriteups.com/
- **Google VRP Writeups**: https://github.com/xdavidhu/awesome-google-vrp-writeups
- **Facebook Bug Bounty Writeups**: https://github.com/jaiswalakshansh/Facebook-BugBounty-Writeups
- **Android Reports and Resources**: https://github.com/B3nac/Android-Reports-and-Resources
- **Medium Bug Bounty Writeups (auto-updated)**: https://github.com/rix4uni/medium-writeups

### Top Researcher Blogs
- **Sam Curry**: https://samcurry.net/
- **James Kettle (PortSwigger)**: https://jameskettle.com/
- **Harel Security Research (NokLine)**: https://nokline.github.io/
- **Pethuraj's Blog**: https://www.pethuraj.com/blog/
- **S1r1us Research**: https://blog.s1r1us.ninja/
- **Assetnote Research**: https://www.assetnote.io/resources/research
- **ProjectDiscovery Blog**: https://projectdiscovery.io/blog
- **PortSwigger Research**: https://portswigger.net/research

### Learning Platforms
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **NahamSec Resources for Beginners**: https://github.com/nahamsec/Resources-for-Beginner-Bug-Bounty-Hunters
- **YesWeHack Learn Bug Bounty**: https://www.yeswehack.com/learn-bug-bounty
- **Intigriti Hackademy**: https://www.intigriti.com/researchers/hackademy
- **BugBountyHunter.com**: https://www.bugbountyhunter.com/
- **HackTricks**: https://book.hacktricks.xyz/

### Bug Bounty Platforms
- **HackerOne**: https://www.hackerone.com/ ($81M paid in 2024-2025)
- **Bugcrowd**: https://www.bugcrowd.com/
- **Intigriti**: https://www.intigriti.com/
- **YesWeHack**: https://www.yeswehack.com/
- **Immunefi** (Web3): https://immunefi.com/
