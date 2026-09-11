# Miscellaneous Bug Bounty Reports (CSRF, Open Redirect, Subdomain Takeover, XXE, etc.)

> A collection of accepted/disclosed bug bounty reports covering vulnerability types not in the other categories: CSRF, Open Redirect, Subdomain Takeover, XXE, CORS Misconfiguration, and more.

---

## CSRF (Cross-Site Request Forgery) Reports

### 1. Login CSRF on HackerOne
- **Severity:** Medium
- **Vulnerability Type:** Login CSRF
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500
- **Description:** The authenticity_token (CSRF token) was not properly verified on HackerOne's login page, allowing attackers to log users into the attacker's account via CSRF. This is a login CSRF attack where the victim unknowingly authenticates into the attacker's session.
- **How It Was Found:** Testing the login form by removing or manipulating the CSRF token and observing if the login request was still processed.
- **Impact:** The attacker could trick the victim into logging into the attacker's account, potentially capturing sensitive data the victim enters while thinking they're in their own account.
- **Key Takeaway:** Login CSRF is often overlooked. Test if CSRF tokens are validated on login forms. Login CSRF can be chained with self-XSS for higher impact.
- **Source:** https://hackerone.com/reports/834366

### 2. CSRF - Close Account (U.S. Department of Defense)
- **Severity:** High
- **Vulnerability Type:** CSRF
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** A CSRF vulnerability allowed an attacker to close a victim's account by tricking them into visiting a malicious page. The account closure endpoint lacked CSRF protection.
- **How It Was Found:** Checking sensitive state-changing endpoints for CSRF token validation.
- **Impact:** Account destruction - attackers could permanently close any user's account through CSRF.
- **Key Takeaway:** Destructive actions (account deletion, data deletion) should always be tested for CSRF. These are high-impact even if the base CSRF severity is medium.
- **Source:** https://hackerone.com/reports/856518

### 3. CSRF on Federalist API (All Endpoints) via Flash
- **Severity:** High
- **Vulnerability Type:** CSRF via Flash
- **Platform:** HackerOne
- **Program:** U.S. General Services Administration
- **Bounty:** $0 (VDP)
- **Description:** Cross-Site Request Forgery on the Federalist API affecting all endpoints, exploited using a Flash file hosted on the attacker's server to bypass SameSite cookie restrictions.
- **How It Was Found:** Testing API endpoints for CSRF protection, then using Flash-based CSRF techniques to bypass browser protections.
- **Impact:** Full API access through CSRF - any authenticated action could be performed on behalf of the victim.
- **Key Takeaway:** Even with SameSite cookies, CSRF may be possible through Flash, subdomains, or other bypass techniques. Test all API endpoints for CSRF, not just form-based actions.
- **Source:** Referenced in HackerOne CSRF disclosures

### 4. Argo CD CSRF Leads to Kubernetes Cluster Compromise
- **Severity:** Critical
- **Vulnerability Type:** CSRF
- **Platform:** HackerOne
- **Program:** Argo CD (Internet Bug Bounty)
- **Bounty:** $4,660
- **Description:** A CSRF vulnerability in Argo CD could be exploited to compromise Kubernetes clusters. An attacker could trick an authenticated Argo CD admin into performing actions that modify cluster configurations.
- **How It Was Found:** Analyzing Argo CD's API for CSRF protection and finding endpoints that accepted state-changing requests without CSRF tokens.
- **Impact:** Full Kubernetes cluster compromise through CSRF attacks on Argo CD administrators.
- **Key Takeaway:** DevOps and infrastructure management tools (Argo CD, Jenkins, Kubernetes Dashboard) are high-value CSRF targets because CSRF can lead to infrastructure compromise.
- **Source:** Referenced in HackerOne CSRF disclosures

### 5. Exfiltrate GDrive Access Token via CSRF to Dropbox
- **Severity:** High
- **Vulnerability Type:** CSRF leading to Token Theft
- **Platform:** HackerOne
- **Program:** Dropbox
- **Bounty:** $1,728
- **Description:** A CSRF vulnerability could be used to exfiltrate Google Drive access tokens when a user had connected their GDrive to Dropbox. The CSRF could trigger an OAuth flow that leaked the access token.
- **How It Was Found:** Analyzing the OAuth integration between Dropbox and Google Drive for CSRF vulnerabilities in the token exchange flow.
- **Impact:** Theft of Google Drive access tokens, allowing access to the victim's Google Drive files.
- **Key Takeaway:** OAuth integration points between services are prime CSRF targets. Test if OAuth flows can be initiated or manipulated via CSRF to steal tokens.
- **Source:** Referenced in HackerOne CSRF disclosures

### 6. CSRF to Account Takeover via Social Account Linking
- **Severity:** Critical
- **Vulnerability Type:** CSRF / Account Takeover
- **Platform:** HackerOne
- **Program:** Bumble
- **Bounty:** $5,000+
- **Description:** A CSRF vulnerability allowed an attacker to link their Gmail, Facebook, or other social account to a victim's Bumble account, effectively hijacking the entire account. The social account linking endpoint lacked CSRF protection.
- **How It Was Found:** Testing the social account linking/unlinking flow for CSRF protection.
- **Impact:** Full account takeover by linking attacker's social account to the victim's profile.
- **Key Takeaway:** Social account linking/unlinking endpoints are high-impact CSRF targets. If you can link your social account to a victim's account via CSRF, you can then log in as them using your social account.
- **Source:** https://hackerone.com/reports/127703

### 7. CSRF to Information Disclosure on Password Reset (Mozilla)
- **Severity:** Medium
- **Vulnerability Type:** CSRF
- **Platform:** HackerOne
- **Program:** Mozilla
- **Bounty:** $0 (VDP)
- **Description:** A CSRF vulnerability on Mozilla's password reset functionality could trigger password reset emails to be sent, leaking information about which email addresses had registered accounts.
- **How It Was Found:** Testing password reset endpoints for CSRF protection.
- **Impact:** Email address enumeration and potential harassment through repeated password reset emails.
- **Key Takeaway:** Even non-destructive CSRF can have impact. Password reset CSRF can be used for account enumeration and user harassment.
- **Source:** Referenced in HackerOne CSRF disclosures

### 8. HackerOne Reports Escalation to JIRA is CSRF Vulnerable
- **Severity:** Medium
- **Vulnerability Type:** CSRF
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500
- **Description:** The functionality to escalate HackerOne reports to JIRA was vulnerable to CSRF, allowing an attacker to trigger report escalation to JIRA on behalf of an authenticated user.
- **How It Was Found:** Testing the JIRA integration endpoints for CSRF token validation.
- **Impact:** Unauthorized escalation of vulnerability reports to external tracking systems.
- **Key Takeaway:** Integration endpoints between platforms (JIRA, Slack, email) often lack CSRF protection because they're added later and may bypass the main CSRF framework.
- **Source:** Referenced in HackerOne CSRF disclosures

### 9. CSRF on Khan Academy Signup
- **Severity:** Medium
- **Vulnerability Type:** CSRF
- **Platform:** HackerOne
- **Program:** Khan Academy
- **Bounty:** $500+
- **Description:** Khan Academy's `/signup/email` API endpoint was vulnerable to CSRF attacks, allowing takeover of accounts associated with unconfirmed email addresses.
- **How It Was Found:** Testing the signup/registration flow for CSRF protection on state-changing endpoints.
- **Impact:** Account takeover for users with unconfirmed email addresses.
- **Key Takeaway:** Registration and email verification endpoints should be tested for CSRF. Accounts in partially-confirmed states are especially vulnerable.
- **Source:** https://hackerone.com/reports/419891

### 10. CSRF Vulnerable Request on Phabricator
- **Severity:** Medium
- **Vulnerability Type:** CSRF
- **Platform:** HackerOne
- **Program:** Phabricator
- **Bounty:** $300+
- **Description:** A request on Phabricator's code collaboration platform was found to be vulnerable to CSRF, allowing unauthorized actions on behalf of authenticated users.
- **How It Was Found:** Systematically testing state-changing requests for CSRF token validation.
- **Impact:** Unauthorized actions on the code review and project management platform.
- **Key Takeaway:** Developer tools and code collaboration platforms should be tested for CSRF on all state-changing endpoints, including less obvious ones like settings changes and preferences.
- **Source:** https://hackerone.com/reports/513137

---

## Subdomain Takeover Reports

### 11. Subdomain Takeover #4 at info.hacker.one (HackerOne)
- **Severity:** High
- **Vulnerability Type:** Subdomain Takeover
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A researcher was able to takeover the subdomain info.hacker.one through a vulnerable endpoint at UnbouncePages App. The DNS CNAME pointed to Unbounce but the page was not configured, allowing the researcher to claim it.
- **How It Was Found:** Scanning for CNAME records pointing to third-party services, then checking if the third-party service endpoint was unclaimed.
- **Impact:** Full control over content served from info.hacker.one, potential for phishing, cookie theft (same-site cookies), and credential harvesting.
- **Key Takeaway:** Subdomain takeover on security platforms is particularly impactful. Subdomains inherit trust from the parent domain, enabling phishing and cookie theft.
- **Source:** https://hackerone.com/reports/220002

### 12. Subdomain Takeover #2 at HackerOne
- **Severity:** High
- **Vulnerability Type:** Subdomain Takeover
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** A second subdomain takeover on HackerOne's infrastructure, demonstrating that even security-focused organizations can have dangling DNS records.
- **How It Was Found:** DNS enumeration and CNAME analysis of HackerOne's subdomains.
- **Impact:** Content control on a HackerOne subdomain.
- **Key Takeaway:** Repeat subdomain takeover findings on the same organization are common because new services are constantly being added and removed. Regular monitoring is needed.
- **Source:** https://hackerone.com/reports/209004

### 13. Sub-Domain Takeover at Consensys
- **Severity:** High
- **Vulnerability Type:** Subdomain Takeover
- **Platform:** HackerOne
- **Program:** Consensys
- **Bounty:** $1,000+
- **Description:** A subdomain belonging to Consensys (blockchain/Ethereum company) was vulnerable to takeover through a dangling DNS CNAME record.
- **How It Was Found:** Subdomain enumeration followed by CNAME analysis and checking for unclaimed third-party service endpoints.
- **Impact:** Phishing attacks targeting blockchain/cryptocurrency users with a trusted domain.
- **Key Takeaway:** Blockchain and cryptocurrency companies are high-value subdomain takeover targets because the trust associated with their domains can be leveraged for financial fraud.
- **Source:** https://hackerone.com/reports/1717626

### 14. Potential Subdomain Takeover on IBM.com
- **Severity:** High
- **Vulnerability Type:** Subdomain Takeover
- **Platform:** HackerOne
- **Program:** IBM
- **Bounty:** $500+
- **Description:** A potential subdomain takeover was identified on an IBM.com subdomain, reported through IBM's HackerOne program.
- **How It Was Found:** Scanning IBM's large domain infrastructure for dangling CNAME records.
- **Impact:** Control over content on an IBM subdomain, potential for phishing and trust exploitation.
- **Key Takeaway:** Large enterprises with thousands of subdomains are the best targets for subdomain takeover. Use tools like subfinder, sublist3r, and can-i-take-over-xyz to automate discovery.
- **Source:** Referenced in HackerOne IBM disclosures

### 15. Subdomain Takeover via Various Services
- **Severity:** Medium-High
- **Vulnerability Type:** Subdomain Takeover
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $200-$2,000
- **Description:** Common services vulnerable to subdomain takeover include: GitHub Pages, Heroku, AWS S3, Azure, Unbounce, Tumblr, Shopify, Fastly, Ghost, Surge.sh, and many more. Each has different fingerprints for identifying unclaimed endpoints.
- **How It Was Found:** Using tools like subjack, nuclei (subdomain takeover templates), and can-i-take-over-xyz to check CNAME records against known vulnerable services.
- **Impact:** Content control on trusted subdomains, enabling phishing, cookie theft, and reputation damage.
- **Key Takeaway:** Maintain a list of services vulnerable to subdomain takeover (can-i-take-over-xyz GitHub repo). Automate CNAME checking across all discovered subdomains. New services become vulnerable regularly.
- **Source:** https://corneacristian.medium.com/top-25-subdomain-takeover-bug-bounty-reports-f6e386ba4413

---

## Open Redirect Reports

### 16. Open Redirect on Tumblr Logout Endpoint
- **Severity:** Low-Medium
- **Vulnerability Type:** Open Redirect
- **Platform:** HackerOne
- **Program:** Tumblr (Automattic)
- **Bounty:** $200+
- **Description:** Tumblr's logout endpoint accepted a redirect_to parameter that wasn't sufficiently validated, allowing attackers to redirect users to malicious sites after logging out.
- **How It Was Found:** Testing redirect parameters (redirect_to, return_url, next, etc.) on authentication-related endpoints.
- **Impact:** Phishing attacks using Tumblr's trusted domain, potential OAuth token theft through redirect manipulation.
- **Key Takeaway:** Logout endpoints with redirect parameters are commonly vulnerable to open redirect. Test all authentication flow endpoints for redirect manipulation.
- **Source:** Referenced in HackerOne open redirect disclosures

### 17. Open Redirect Collection (4 Reports Analysis)
- **Severity:** Low-Medium
- **Vulnerability Type:** Open Redirect
- **Platform:** HackerOne
- **Program:** Various
- **Bounty:** $100-$500
- **Description:** An analysis of 4 open redirect reports on HackerOne, documenting different bypass techniques and the validation methods used by various programs. Techniques included: URL encoding, double encoding, using // prefix, and using @ symbol.
- **How It Was Found:** Testing redirect parameters with various bypass payloads: //evil.com, /\evil.com, //evil.com%2f%2f, https://evil.com@legitimate.com, etc.
- **Impact:** Phishing enablement and potential OAuth token theft.
- **Key Takeaway:** Open redirects are low severity alone but can be chained with OAuth flows, SSRF, or XSS for higher impact. Always try to chain open redirects with other vulnerabilities.
- **Source:** https://medium.com/@halfcircassian/bug-bounty-in-2025-part-3-investigating-4-open-redirect-reports-at-hackerone-so-you-dont-have-499948a0e6b1

### 18. Open Redirect to Account Takeover via OAuth
- **Severity:** High
- **Vulnerability Type:** Open Redirect + OAuth Token Theft
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** Open redirects chained with OAuth flows to steal authorization codes or access tokens. By manipulating the redirect_uri in OAuth flows to include an open redirect, attackers could capture OAuth tokens sent to the redirect URL.
- **How It Was Found:** Finding an open redirect on the OAuth client's domain, then using it as the redirect_uri in the OAuth authorization flow.
- **Impact:** Account takeover through stolen OAuth tokens.
- **Key Takeaway:** Open redirects on domains that are OAuth redirect_uri targets are especially valuable. Always check if an open redirect can be chained with OAuth to steal tokens.
- **Source:** Multiple bug bounty reports

---

## XXE (XML External Entity) Reports

### 19. XXE via SVG File Upload
- **Severity:** High
- **Vulnerability Type:** XXE
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** SVG files containing XML External Entity declarations were processed by the server, allowing file read, SSRF, and potentially RCE. The SVG parser processed external entity references in uploaded SVG images.
- **How It Was Found:** Uploading SVG files containing XXE payloads (<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>) and checking if the entity was resolved.
- **Impact:** Server-side file read, SSRF, and potential denial of service.
- **Key Takeaway:** Any feature that processes XML-based files (SVG, DOCX, XLSX, XML, SOAP) should be tested for XXE. SVG uploads are the most commonly overlooked XXE vector.
- **Source:** Multiple bug bounty reports

### 20. XXE via DOCX/XLSX File Upload
- **Severity:** High
- **Vulnerability Type:** XXE
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Office document formats (DOCX, XLSX, PPTX) are ZIP archives containing XML files. By modifying the internal XML files to include XXE payloads, attackers could achieve server-side file read when the application parsed these documents.
- **How It Was Found:** Unzipping Office documents, modifying internal XML files (e.g., [Content_Types].xml, document.xml) to include XXE payloads, re-zipping, and uploading.
- **Impact:** Server-side file read, SSRF, and information disclosure.
- **Key Takeaway:** Any file upload that accepts Office formats should be tested for XXE. Use tools like oxml_xxe to automate XXE payload injection into Office documents.
- **Source:** Multiple bug bounty reports, referenced in Cristian Cornea's Top 25 XXE Reports

### 21. XXE in SOAP/XML API Endpoints
- **Severity:** High
- **Vulnerability Type:** XXE
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$10,000
- **Description:** SOAP web services and XML-based API endpoints that accept XML input are vulnerable to XXE when the XML parser processes external entities. Including XXE payloads in SOAP request bodies could extract server files.
- **How It Was Found:** Identifying XML/SOAP endpoints and injecting XXE payloads into the XML body.
- **Impact:** Server-side file read, SSRF, and potential RCE.
- **Key Takeaway:** Legacy SOAP services are prime XXE targets. Convert JSON APIs to XML (changing Content-Type to application/xml) to test if the server accepts XML input even when not documented.
- **Source:** Multiple bug bounty reports

---

## CORS Misconfiguration Reports

### 22. CORS Misconfiguration Allowing Credential Theft
- **Severity:** High
- **Vulnerability Type:** CORS Misconfiguration
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Misconfigured CORS policies that reflect the Origin header in Access-Control-Allow-Origin with Access-Control-Allow-Credentials: true, allowing any domain to read authenticated responses from the vulnerable API.
- **How It Was Found:** Sending requests with different Origin headers and checking if the response reflects the origin with credentials allowed.
- **Impact:** Cross-origin data theft including session tokens, personal data, and API responses.
- **Key Takeaway:** Test CORS by setting Origin: https://evil.com and checking if it's reflected in the response. Also test: null origin, subdomain variations, and URL parser differentials.
- **Source:** Multiple bug bounty reports

### 23. CORS with Subdomain Wildcard
- **Severity:** Medium
- **Vulnerability Type:** CORS Misconfiguration
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** CORS policies that whitelist all subdomains (*.example.com) can be exploited if any subdomain has XSS or can be taken over. The attacker uses the trusted subdomain to make cross-origin requests.
- **How It Was Found:** Testing CORS with various subdomain-based origins, then looking for XSS or subdomain takeover on any subdomain to exploit the CORS policy.
- **Impact:** Data theft from the main domain using a compromised subdomain.
- **Key Takeaway:** CORS subdomain wildcards create a dependency between the main domain's security and the security of ALL subdomains. Chain with subdomain takeover or XSS for exploitation.
- **Source:** Multiple bug bounty reports

---

## HTTP Request Smuggling Reports

### 24. HTTP Request Smuggling (CL.TE / TE.CL)
- **Severity:** Critical
- **Vulnerability Type:** HTTP Request Smuggling
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $5,000-$25,000
- **Description:** HTTP request smuggling vulnerabilities where differences in how front-end and back-end servers parse HTTP requests (Content-Length vs Transfer-Encoding) allow attackers to smuggle additional requests. This can lead to: cache poisoning, session hijacking, and bypassing security controls.
- **How It Was Found:** Using Burp Suite's HTTP Request Smuggler extension to detect CL.TE and TE.CL desync vulnerabilities between load balancers and application servers.
- **Impact:** Cache poisoning affecting all users, bypassing WAF and access controls, session hijacking.
- **Key Takeaway:** HTTP request smuggling is underreported but extremely high-impact. Use the HTTP Request Smuggler Burp extension for automated detection. Targets behind load balancers/reverse proxies are most likely vulnerable.
- **Source:** Multiple bug bounty reports and James Kettle's research

### 25. HTTP/2 Request Smuggling (H2.CL Desync)
- **Severity:** Critical
- **Vulnerability Type:** HTTP/2 Desync
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $5,000-$25,000
- **Description:** HTTP/2 request smuggling (H2.CL or H2.TE desync) where the HTTP/2 front-end and HTTP/1.1 back-end disagree on request boundaries. This is more prevalent than HTTP/1.1 smuggling because HTTP/2 downgrades are common.
- **How It Was Found:** Testing HTTP/2 endpoints for request smuggling using techniques from James Kettle's research.
- **Impact:** Same as HTTP/1.1 smuggling but affects more modern infrastructure.
- **Key Takeaway:** HTTP/2 to HTTP/1.1 downgrade is the new frontier for request smuggling. Many CDNs and load balancers perform this downgrade, creating desync opportunities.
- **Source:** James Kettle's research and multiple bug bounty reports

---

## Denial of Service Reports

### 26. ReDoS (Regular Expression Denial of Service)
- **Severity:** Medium
- **Vulnerability Type:** ReDoS / DoS
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$3,000
- **Description:** Regular expressions with catastrophic backtracking that can be triggered by specially crafted input, causing the server to hang or consume excessive CPU. Common in input validation, search features, and text processing.
- **How It Was Found:** Analyzing source code or JavaScript files for vulnerable regex patterns, then crafting inputs that trigger exponential backtracking.
- **Impact:** Application-level denial of service, potentially affecting all users.
- **Key Takeaway:** Look for regex patterns with nested quantifiers (e.g., (a+)+ or (a|a)*) in JavaScript source code. Use tools like regexploit for automated detection.
- **Source:** Multiple bug bounty reports

### 27. GraphQL Denial of Service via Nested Queries
- **Severity:** Medium
- **Vulnerability Type:** DoS
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** GraphQL APIs that don't limit query depth or complexity can be overwhelmed by deeply nested queries that cause exponential database joins or recursive resolution.
- **How It Was Found:** Sending deeply nested GraphQL queries and monitoring response times.
- **Impact:** Application-level denial of service through resource exhaustion.
- **Key Takeaway:** Test GraphQL APIs for: query depth limits, query complexity limits, and batch query limits. A simple nested query can bring down an entire application.
- **Source:** Multiple bug bounty reports

---

## Cache Poisoning Reports

### 28. Web Cache Poisoning via Unkeyed Headers
- **Severity:** High
- **Vulnerability Type:** Cache Poisoning
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $2,000-$10,000
- **Description:** Web cache poisoning through unkeyed headers (headers not included in the cache key but that affect the response). By manipulating headers like X-Forwarded-Host, X-Forwarded-Scheme, or custom headers, attackers could poison the cache with malicious responses served to all users.
- **How It Was Found:** Using Param Miner (Burp Extension) to discover unkeyed headers that influence the response, then crafting poisoned responses.
- **Impact:** XSS, redirect, or other attacks served from cache to all users of the affected page.
- **Key Takeaway:** Web cache poisoning is a growing attack surface. Use Param Miner to discover unkeyed headers and parameters. Focus on CDN-cached pages with dynamic content.
- **Source:** James Kettle's research and multiple bug bounty reports

---

## Clickjacking Reports

### 29. Clickjacking on Sensitive Actions
- **Severity:** Low-Medium
- **Vulnerability Type:** Clickjacking
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $100-$1,000
- **Description:** Missing X-Frame-Options or Content-Security-Policy frame-ancestors headers allowing the application to be framed. Combined with social engineering, attackers could trick users into clicking buttons that perform sensitive actions.
- **How It Was Found:** Checking for X-Frame-Options and CSP frame-ancestors headers on sensitive pages, then creating proof-of-concept HTML pages that frame the vulnerable page.
- **Impact:** Unauthorized actions performed by tricked users (settings changes, account modifications, purchases).
- **Key Takeaway:** Clickjacking is low severity unless combined with a sensitive action. Focus on: payment buttons, account deletion, settings changes, and permission grants. Many programs consider clickjacking informational.
- **Source:** Multiple bug bounty reports

---

## Path Traversal Reports

### 30. Path Traversal / Local File Inclusion
- **Severity:** High-Critical
- **Vulnerability Type:** Path Traversal / LFI
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$10,000
- **Description:** Path traversal vulnerabilities allowing reading of arbitrary files from the server through manipulated file paths in URL parameters, upload paths, or template includes. Common payloads: ../../../etc/passwd, ..%2f..%2f..%2fetc%2fpasswd.
- **How It Was Found:** Testing file-related parameters (filename, path, template, page, include) with directory traversal sequences, using various encoding bypasses.
- **Impact:** Reading sensitive files (configuration, source code, credentials, SSH keys) from the server.
- **Key Takeaway:** Path traversal is especially impactful when it can read: /etc/passwd, .env files, application source code, or AWS credentials (~/.aws/credentials). Test with various encoding: URL encoding, double encoding, UTF-8 overlong encoding, and null byte injection.
- **Source:** Multiple bug bounty reports

---

## Additional Reports (Expanded Collection)

### CSRF Reports (Additional)

### 31. CSRF Leading to Leakage of CSRF Token + Stored XSS + Account Takeover
- **Severity**: Critical
- **Bounty**: $1,100
- **Program**: Badoo
- **Platform**: HackerOne
- **Description**: A chained vulnerability where a CSRF token leakage vulnerability was combined with stored XSS to achieve full account takeover. The CSRF token was exposed in an API response, allowing the attacker to craft CSRF attacks that injected persistent XSS.
- **How Found**: Discovering CSRF token leakage in API responses, then chaining it with a stored XSS vector to create a wormable account takeover attack.
- **Impact**: Wormable account takeover affecting all users who viewed the attacker's profile.
- **Key Takeaway**: CSRF token leakage can amplify other vulnerabilities. Look for CSRF tokens in URL parameters, referrer headers, and API responses that can be captured cross-origin.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPCSRF.md

### 32. CSRF to Change Email Address Without Confirmation (Automattic)
- **Severity**: High
- **Bounty**: $750
- **Program**: Automattic
- **Platform**: HackerOne
- **Description**: A CSRF vulnerability allowed changing a user's email address on WordPress.com without email confirmation. The email change endpoint lacked CSRF protection, enabling account takeover.
- **How Found**: Testing the email change endpoint for CSRF protection by attempting to submit the request from an external page.
- **Impact**: Account takeover by changing the victim's email to attacker-controlled, then resetting the password.
- **Key Takeaway**: Email change endpoints without CSRF protection are essentially account takeover vulnerabilities. Always test email/password change endpoints for CSRF.
- **Source**: Referenced in HackerOne Automattic disclosures

### 33. CSRF in Webhook Configuration (GitLab)
- **Severity**: Medium
- **Bounty**: $1,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: Webhook configuration endpoints in GitLab were vulnerable to CSRF, allowing an attacker to add malicious webhook URLs to a victim's project, receiving all event notifications (push, merge, issue updates).
- **How Found**: Testing the webhook creation endpoint for CSRF token validation by crafting a cross-origin POST request.
- **Impact**: Data exfiltration through attacker-controlled webhooks receiving all project events, including code changes and confidential issue data.
- **Key Takeaway**: Webhook and integration configuration endpoints are high-value CSRF targets because they establish persistent data exfiltration channels.
- **Source**: Referenced in GitLab HackerOne disclosures

### 34. CSRF on Account Settings Leading to Notification Bypass (Twitter/X)
- **Severity**: Medium
- **Bounty**: $1,120
- **Program**: Twitter/X
- **Platform**: HackerOne
- **Description**: A CSRF vulnerability on Twitter's account settings allowed an attacker to modify notification preferences, effectively silencing security alerts that would warn the victim about suspicious activity.
- **How Found**: Testing account settings endpoints for CSRF protection and finding that notification preferences could be changed via cross-origin requests.
- **Impact**: Disabling security notifications to facilitate further attacks without the victim being alerted.
- **Key Takeaway**: CSRF on settings endpoints can be a stealth enabler for other attacks. Disabling notifications or security features via CSRF supports longer persistence.
- **Source**: Referenced in Twitter/X HackerOne disclosures

### XXE Reports (Additional)

### 35. XXE on sms-be-vip.twitter.com via Cloudhopper SXMP Servlet
- **Severity**: High
- **Bounty**: $10,080
- **Program**: Twitter/X
- **Platform**: HackerOne
- **Description**: An XXE vulnerability in the Cloudhopper SXMP servlet on sms-be-vip.twitter.com allowed reading local files from Twitter's infrastructure. The XML parser in the SMS processing pipeline did not disable external entity resolution.
- **How Found**: Identifying the SXMP (Short Message eXchange Protocol) endpoint and sending XML payloads with external entity declarations to read server files.
- **Impact**: Reading arbitrary files from Twitter's SMS processing infrastructure, including configuration files and credentials.
- **Key Takeaway**: SMS and messaging infrastructure often uses XML-based protocols (SXMP, SMPP) that are vulnerable to XXE. Look for non-web XML processing endpoints.
- **Source**: https://hackerone.com/reports/248668

### 36. XXE in Site Audit Exposing File Contents (Semrush)
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Semrush
- **Platform**: HackerOne
- **Description**: The Site Audit function in Semrush was vulnerable to XXE when parsing sitemap.xml files. An attacker could host a malicious sitemap.xml with XXE payloads that would be processed when Semrush crawled the site.
- **How Found**: Setting up a test website with a malicious sitemap.xml containing XXE payloads, then triggering a Semrush site audit on that domain.
- **Impact**: Reading files from Semrush's crawling infrastructure, potentially accessing credentials and internal configuration.
- **Key Takeaway**: Web crawlers and scanners that process XML (sitemaps, RSS feeds, SVG) are XXE targets. The attack vector is hosting the malicious XML on your own server.
- **Source**: https://hackerone.com/reports/312543

### 37. Blind XXE via PowerPoint File Upload (Open-Xchange)
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Open-Xchange
- **Platform**: HackerOne
- **Description**: Uploading a specially crafted PowerPoint (PPTX) file with XXE payloads in its internal XML files triggered a blind XXE vulnerability. The server parsed the PPTX's XML components without disabling external entities.
- **How Found**: Creating a PPTX file, unzipping it, modifying internal XML files to include XXE payloads with out-of-band (OOB) exfiltration, re-zipping, and uploading.
- **Impact**: Server-side file reading and SSRF through the document processing pipeline.
- **Key Takeaway**: Any file upload accepting Office formats (DOCX, XLSX, PPTX) is a potential XXE vector. Use the oxml_xxe tool to automate payload injection into Office documents.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPXXE.md

### 38. XXE in XML Parser (drchrono)
- **Severity**: High
- **Bounty**: $700
- **Program**: drchrono
- **Platform**: HackerOne
- **Description**: An XML parser in drchrono's healthcare platform was vulnerable to XXE, allowing an attacker to read files from the server. Healthcare platforms processing XML (HL7, CCDA, FHIR) are particularly sensitive XXE targets.
- **How Found**: Identifying XML-accepting endpoints and injecting standard XXE payloads to test for entity resolution.
- **Impact**: Reading sensitive healthcare data and server configuration files from a healthcare platform.
- **Key Takeaway**: Healthcare applications often process XML formats (HL7, CCDA, FHIR) and are high-value XXE targets due to the sensitivity of patient data.
- **Source**: https://hackerone.com/reports/55431

### 39. XXE in DoD Website via File Upload
- **Severity**: High
- **Bounty**: N/A (VDP)
- **Program**: U.S. Department of Defense
- **Platform**: HackerOne
- **Description**: A Department of Defense website was vulnerable to XXE through its file upload functionality. The uploaded XML files were parsed without disabling external entity resolution, allowing server file access.
- **How Found**: Uploading XML files with XXE payloads through the file upload feature and checking for entity resolution in the response or through OOB channels.
- **Impact**: Reading files from DoD server infrastructure, potential access to sensitive government data.
- **Key Takeaway**: Government and military websites often use legacy XML processing that is vulnerable to XXE. VDP programs accept these findings even without monetary bounty.
- **Source**: https://hackerone.com/reports/227880

### 40. XXE Injection via SVG Leading to SSRF (Zivver)
- **Severity**: High
- **Bounty**: $0 (VDP)
- **Program**: Zivver
- **Platform**: HackerOne
- **Description**: SVG image uploads on Zivver's secure email platform were vulnerable to XXE. The SVG parser resolved external entities, allowing both local file reading and SSRF to internal services.
- **How Found**: Uploading SVG files containing XXE payloads that referenced internal URLs and local files through entity declarations.
- **Impact**: SSRF to internal services and reading local files through the SVG processing pipeline.
- **Key Takeaway**: SVG uploads are the most commonly overlooked XXE vector. Any image upload that accepts SVG should be tested with XXE payloads embedded in the SVG XML.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPXXE.md

### 41. Multiple XXE Endpoints (Pornhub)
- **Severity**: Critical
- **Bounty**: $2,500
- **Program**: Pornhub
- **Platform**: HackerOne
- **Description**: Multiple endpoints on Pornhub's platform were vulnerable to XXE injection, allowing reading of arbitrary files from the server. The XML parsing library across multiple services did not disable external entity resolution.
- **How Found**: Systematically testing all XML-accepting endpoints for XXE by injecting entity declarations in XML request bodies.
- **Impact**: Reading arbitrary server files across multiple services, including configuration files with database credentials.
- **Key Takeaway**: When one endpoint is vulnerable to XXE, test all other XML-accepting endpoints in the same application. The same misconfigured parser is likely used across the platform.
- **Source**: https://github.com/reddelexc/hackerone-reports/blob/master/tops_by_bug_type/TOPXXE.md

### Subdomain Takeover Reports (Additional)

### 42. Subdomain Takeover via Heroku (Uber)
- **Severity**: High
- **Bounty**: $3,000
- **Program**: Uber
- **Platform**: HackerOne
- **Description**: An Uber subdomain had a CNAME record pointing to Heroku, but the Heroku app had been deleted. An attacker could register the same Heroku app name and serve arbitrary content on Uber's subdomain.
- **How Found**: Enumerating Uber's subdomains, checking CNAME records, and identifying a dangling CNAME pointing to an unclaimed Heroku endpoint.
- **Impact**: Full control over content served on an Uber subdomain, enabling phishing, cookie theft, and credential harvesting.
- **Key Takeaway**: Heroku is one of the most common subdomain takeover targets. Check if the CNAME target returns "No such app" or similar error messages.
- **Source**: Referenced in subdomain takeover writeup collections

### 43. Subdomain Takeover via AWS S3 Bucket (Starbucks)
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: A Starbucks subdomain had a CNAME pointing to an AWS S3 bucket that no longer existed. Creating an S3 bucket with the same name allowed serving arbitrary content from the Starbucks subdomain.
- **How Found**: Scanning Starbucks subdomains for CNAME records pointing to S3, then checking if the S3 bucket was unclaimed (404 NoSuchBucket response).
- **Impact**: Phishing attacks from a trusted Starbucks domain, potential cookie theft for same-site cookies.
- **Key Takeaway**: AWS S3 subdomain takeovers are common when the bucket name matches the CNAME. Look for "NoSuchBucket" responses from S3-pointed CNAMEs.
- **Source**: Referenced in Starbucks HackerOne disclosures

### 44. Subdomain Takeover via Azure (Microsoft)
- **Severity**: High
- **Bounty**: $2,000
- **Program**: Microsoft
- **Platform**: MSRC
- **Description**: A Microsoft subdomain pointed to an Azure service that was deprovisioned. By claiming the Azure resource with the matching name, an attacker could serve content on Microsoft's subdomain.
- **How Found**: Enumerating Microsoft subdomains and checking Azure-pointed CNAMEs for unclaimed resources. Azure returns specific error pages for unclaimed resources.
- **Impact**: Hosting attacker content on a Microsoft subdomain, enabling highly credible phishing attacks.
- **Key Takeaway**: Azure, AWS, and GCP all have subdomain takeover vectors. Each cloud provider has specific fingerprints for unclaimed resources. Maintain a fingerprint database.
- **Source**: Referenced in MSRC vulnerability disclosures

### 45. Subdomain Takeover via GitHub Pages (Multiple Programs)
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Subdomains pointing to GitHub Pages where the CNAME file was not configured in the repository, or the repository was deleted. Claiming the GitHub Pages endpoint allowed content hosting on the target subdomain.
- **How Found**: Checking GitHub Pages-pointed CNAMEs for the "There isn't a GitHub Pages site here" error page, indicating an unclaimed endpoint.
- **Impact**: Content hosting on trusted subdomains for phishing and trust exploitation.
- **Key Takeaway**: GitHub Pages is the easiest subdomain takeover to exploit. The fingerprint is clear: "There isn't a GitHub Pages site here." Automated tools like subjack can detect this at scale.
- **Source**: Multiple bug bounty reports

### CORS Misconfiguration Reports (Additional)

### 46. CORS Misconfiguration Allowing Bitcoin Theft (Cryptocurrency Exchange)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Multiple (Crypto Exchanges)
- **Platform**: Various
- **Description**: A cryptocurrency exchange reflected the Origin header in Access-Control-Allow-Origin with credentials allowed, enabling any website to read authenticated API responses including wallet addresses and initiate transactions.
- **How Found**: Testing the API with Origin: https://evil.com and checking if the response included Access-Control-Allow-Origin: https://evil.com with Access-Control-Allow-Credentials: true.
- **Impact**: Cross-origin theft of cryptocurrency by reading wallet data and session tokens from authenticated API responses.
- **Key Takeaway**: CORS misconfigurations on financial platforms are critical because they enable cross-origin theft. The PortSwigger research "Exploiting CORS for Bitcoins and Bounties" documents this class of attack.
- **Source**: https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties

### 47. CORS with Null Origin Bypass
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: CORS policies that whitelisted the "null" origin could be exploited using sandboxed iframes (sandbox attribute without allow-same-origin), which send requests with Origin: null.
- **How Found**: Testing CORS with Origin: null and observing if the response included Access-Control-Allow-Origin: null. Then exploiting via a sandboxed iframe.
- **Impact**: Cross-origin data theft using the null origin bypass technique.
- **Key Takeaway**: Always test CORS with Origin: null in addition to arbitrary origins. The null origin can be triggered by sandboxed iframes, data: URIs, and local file:// pages.
- **Source**: Multiple bug bounty reports

### 48. CORS Misconfiguration via URL Parser Differential
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: CORS origin validation using regex or string matching could be bypassed through URL parser differentials. Origins like evil.com.example.com or example.com.evil.com could pass validation that checked for "example.com" in the origin.
- **How Found**: Testing CORS with crafted origins that contain the target domain as a substring: example.com.evil.com, evil-example.com, examplecom.evil.com.
- **Impact**: Cross-origin data theft through origin validation bypass.
- **Key Takeaway**: Test CORS with origin variations: prefix matching bypass (evil.example.com), suffix matching bypass (example.com.evil.com), and special character injection (example.com%00.evil.com).
- **Source**: Multiple bug bounty reports

### Open Redirect Reports (Additional)

### 49. Open Redirect on GitLab OAuth Leading to Account Takeover (Vercel)
- **Severity**: High
- **Bounty**: $2,500
- **Program**: Vercel
- **Platform**: HackerOne
- **Description**: An open redirect on GitLab's OAuth flow could be chained with Vercel's OAuth integration to steal authorization codes. The redirect_uri validation on the OAuth endpoint was insufficient, allowing attacker-controlled redirects.
- **How Found**: Finding an open redirect in the OAuth callback URL validation, then using it to redirect the authorization code to an attacker-controlled server.
- **Impact**: Account takeover through stolen OAuth authorization codes.
- **Key Takeaway**: Open redirects on OAuth providers or clients are critical because they can steal authorization codes. Always check redirect_uri validation for bypass techniques.
- **Source**: Referenced in HackerOne open redirect disclosures

### 50. Open Redirect via Unicode Character Bypass
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Open redirect protections could be bypassed using Unicode characters that were normalized differently by the validation logic and the redirect handler. Characters like fullwidth solidus or similar-looking Unicode characters bypassed URL validation.
- **How Found**: Testing redirect parameters with Unicode variants of common bypass characters: fullwidth /, reversed solidus, and other Unicode normalization attacks.
- **Impact**: Redirect to attacker-controlled domains, enabling phishing and token theft.
- **Key Takeaway**: Unicode normalization differences between validation and execution are a powerful bypass technique. Test with Unicode variants of /, @, #, and \ characters.
- **Source**: Multiple bug bounty reports

### 51. Open Redirect on Expedia Group
- **Severity**: Medium
- **Bounty**: $300
- **Program**: Expedia Group
- **Platform**: HackerOne
- **Description**: An open redirect vulnerability on Expedia's platform allowed redirecting users to arbitrary external URLs through a redirect parameter that did not properly validate the destination.
- **How Found**: Testing redirect parameters on authentication and navigation endpoints with external URLs using various bypass techniques.
- **Impact**: Phishing attacks using Expedia's trusted domain to redirect users to malicious sites.
- **Key Takeaway**: Travel and e-commerce sites with many redirect parameters (booking confirmation, login, partner redirects) are common open redirect targets.
- **Source**: https://hackerone.com/reports/1788006

### 52. Open Redirect Vulnerability in Node.js (Internet Bug Bounty)
- **Severity**: Medium
- **Bounty**: $600
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: An open redirect vulnerability in Node.js's HTTP handling could redirect users to arbitrary domains when using certain URL parsing behaviors. The URL parser treated certain inputs differently than expected.
- **How Found**: Analyzing Node.js URL parsing behavior and finding inputs that caused unexpected redirects through parser quirks.
- **Impact**: Applications using Node.js's URL parsing for redirect validation could be exploited for open redirects.
- **Key Takeaway**: URL parser quirks in web frameworks can create open redirect vulnerabilities. Test how the framework handles edge cases: backslash as separator, tab/newline characters, and authority parsing.
- **Source**: https://hackerone.com/reports/1865991

### HTTP Smuggling/Desync Reports (Additional)

### 53. HTTP Request Smuggling on Basecamp via HTTP/2
- **Severity**: Critical
- **Bounty**: $7,500
- **Program**: Basecamp
- **Platform**: HackerOne
- **Description**: An HTTP/2 request smuggling vulnerability allowed poisoning Basecamp's cache with malicious responses. The HTTP/2 front-end and HTTP/1.1 back-end disagreed on request boundaries, enabling request injection.
- **How Found**: Using HTTP/2-specific smuggling techniques to send requests that the front-end processed as one request but the back-end split into two.
- **Impact**: Cache poisoning affecting all Basecamp users, potential for XSS and credential theft through cached malicious responses.
- **Key Takeaway**: HTTP/2 smuggling is more prevalent than HTTP/1.1 smuggling because many modern architectures downgrade HTTP/2 to HTTP/1.1. Test all HTTP/2 endpoints for H2.CL and H2.TE desync.
- **Source**: https://hackerone.com/reports/919175

### 54. HTTP Request Smuggling on Helium
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Helium
- **Platform**: HackerOne
- **Description**: An HTTP request smuggling vulnerability on Helium's infrastructure allowed injecting requests into other users' connections through a CL.TE desync between the front-end and back-end servers.
- **How Found**: Using the HTTP Request Smuggler Burp extension to detect CL.TE desync, then crafting smuggled requests to demonstrate impact.
- **Impact**: Cross-user request injection, potential for session hijacking and data theft.
- **Key Takeaway**: IoT and blockchain platforms (like Helium) often have web infrastructure vulnerable to smuggling. Don't limit smuggling tests to traditional web applications.
- **Source**: https://hackerone.com/reports/867952

### 55. HTTP Request Smuggling via X-Forwarded-Host Cache Poisoning
- **Severity**: High
- **Bounty**: $3,000-$10,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: HTTP request smuggling chained with cache poisoning through the X-Forwarded-Host header. The smuggled request included an X-Forwarded-Host header that was reflected in cached responses, redirecting all subsequent users.
- **How Found**: Smuggling requests that included cache-poisoning headers (X-Forwarded-Host, X-Forwarded-Scheme) and checking if the poisoned response was cached and served to other users.
- **Impact**: Mass redirect of all users visiting the cached page, enabling large-scale phishing.
- **Key Takeaway**: Request smuggling + cache poisoning is a devastating combination. After confirming smuggling, try to poison the cache with redirect or XSS payloads via unkeyed headers.
- **Source**: Multiple bug bounty reports and James Kettle's research

### Cache Poisoning Reports (Additional)

### 56. Web Cache Poisoning via X-Forwarded-Scheme
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Web applications that used the X-Forwarded-Scheme header to determine the protocol (HTTP vs HTTPS) could be cache-poisoned by sending requests with X-Forwarded-Scheme: http. This caused cached responses to redirect users to HTTP, enabling downgrade attacks.
- **How Found**: Using Param Miner to discover that X-Forwarded-Scheme was an unkeyed header that influenced the response, then poisoning the cache with HTTP redirects.
- **Impact**: SSL/TLS stripping for all users accessing the cached page, enabling man-in-the-middle attacks.
- **Key Takeaway**: X-Forwarded-Scheme, X-Forwarded-Proto, and X-Forwarded-Port are common unkeyed headers that can trigger protocol downgrades in cached responses.
- **Source**: James Kettle's cache poisoning research

### 57. Web Cache Deception Attack
- **Severity**: High
- **Bounty**: $2,000-$10,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Web cache deception where appending a static file extension to a dynamic URL (e.g., /account/settings.css) caused CDNs to cache the authenticated response. Any user requesting the same URL would receive the cached private data.
- **How Found**: Appending static file extensions (.css, .js, .jpg) to authenticated dynamic URLs and checking if the response was cached by the CDN.
- **Impact**: Exposure of private user data (account details, tokens) to any subsequent visitor of the cached URL.
- **Key Takeaway**: Web cache deception is different from cache poisoning. Test by appending static extensions to authenticated pages: /profile.css, /settings.js, /account.png.
- **Source**: Multiple bug bounty reports

### Prototype Pollution Reports

### 58. Prototype Pollution in Lodash (CVE-2019-10744)
- **Severity**: High
- **Bounty**: $3,000+
- **Program**: Internet Bug Bounty / Node.js ecosystem
- **Platform**: HackerOne
- **Description**: Lodash v4.17.15 and earlier had a prototype pollution vulnerability through the defaultsDeep function. An attacker could inject properties into Object.prototype through a crafted input, affecting all objects in the application.
- **How Found**: Analyzing Lodash's merge/defaults functions for unsafe recursive property assignment that could pollute Object.prototype.
- **Impact**: Denial of service, property injection across all objects, potential RCE in certain application contexts.
- **Key Takeaway**: JavaScript libraries that perform deep object merging (lodash, jQuery.extend, merge-deep) are prototype pollution targets. Check package.json for vulnerable library versions.
- **Source**: Referenced in HackerOne Internet Bug Bounty disclosures

### 59. Prototype Pollution Leading to RCE via Handlebars
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Multiple
- **Platform**: Various
- **Description**: Prototype pollution chained with Handlebars template engine to achieve remote code execution. By polluting Object.prototype with a carefully crafted payload, the Handlebars compiler could be manipulated to execute arbitrary code.
- **How Found**: Discovering a prototype pollution vector, then analyzing the application's template engine for gadgets that could be triggered through polluted prototype properties.
- **Impact**: Remote code execution on the server through prototype pollution gadget chains.
- **Key Takeaway**: Prototype pollution alone is often medium severity, but chaining with template engines (Handlebars, Pug, EJS) or other gadgets can escalate to RCE. Always look for gadget chains.
- **Source**: Multiple bug bounty reports and Michail Shcherbakov's research

### 60. Client-Side Prototype Pollution to XSS
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Client-side prototype pollution through URL fragments or query parameters that were parsed into objects using vulnerable merge operations. The polluted prototype properties were then used in innerHTML or script creation, leading to XSS.
- **How Found**: Testing URL parameters with prototype pollution payloads (__proto__[test]=value, constructor.prototype.test=value) and checking if polluted properties appeared in DOM operations.
- **Impact**: Cross-site scripting through client-side prototype pollution, affecting all users who visit the crafted URL.
- **Key Takeaway**: Client-side prototype pollution through URL parameters is a growing attack surface. Use tools like PPScan or manual testing with __proto__ in query parameters.
- **Source**: Multiple bug bounty reports

### GraphQL Reports

### 61. GraphQL Authentication Bypass via Alternate Channel (HackerOne Blog)
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Undisclosed
- **Platform**: HackerOne
- **Description**: A GraphQL endpoint served as an alternate authentication channel that bypassed the main application's access controls. By using GraphQL mutations, an attacker could escalate privileges to administrative access and alter front-page promotional content.
- **How Found**: Discovering the GraphQL endpoint through API enumeration, then testing mutations for authorization enforcement compared to the REST API.
- **Impact**: Full administrative access through GraphQL privilege escalation, allowing content manipulation on the main website.
- **Key Takeaway**: GraphQL endpoints often have different (weaker) authorization than REST APIs. Always compare authorization enforcement between GraphQL and REST for the same operations.
- **Source**: https://www.hackerone.com/blog/how-graphql-bug-resulted-authentication-bypass

### 62. GraphQL Introspection Leaks Sensitive Schema Information (HackerOne)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: GraphQL introspection was enabled on a HackerOne endpoint, leaking the complete schema including hidden queries, mutations, and types that revealed internal data structures and undocumented functionality.
- **How Found**: Sending a standard GraphQL introspection query ({__schema{types{name,fields{name,type{name}}}}}) to discover the full API schema.
- **Impact**: Information disclosure of internal API structure, enabling targeted attacks on hidden endpoints and undocumented mutations.
- **Key Takeaway**: Always check if GraphQL introspection is enabled. Even if disabled, try field suggestion attacks and tools like clairvoyance for schema reconstruction.
- **Source**: https://hackerone.com/reports/291531

### 63. Confidential Data Exposure via GraphQL (HackerOne)
- **Severity**: High
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: Two researchers independently discovered that confidential data about users and private programs could be queried through a GraphQL endpoint. The GraphQL resolver did not enforce the same access controls as the UI.
- **How Found**: Testing GraphQL queries for data that should be access-controlled, finding that private program details and user information were accessible to unauthorized users.
- **Impact**: Exposure of confidential bug bounty program information and user data.
- **Key Takeaway**: GraphQL resolvers must enforce authorization at every field level. Test if private/confidential data is accessible through alternative GraphQL queries.
- **Source**: https://hackerone.com/reports/489146

### 64. SQL Injection in GraphQL Endpoint (HackerOne)
- **Severity**: Critical
- **Bounty**: $2,500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: The embedded_submission_form_uuid parameter in the /graphql endpoint was vulnerable to SQL injection. An attacker could extract information from the database through the GraphQL query parameter.
- **How Found**: Fuzzing GraphQL query parameters with SQL injection payloads and observing database error messages in the responses.
- **Impact**: Full database access through SQL injection in a GraphQL parameter.
- **Key Takeaway**: GraphQL parameters are just as vulnerable to injection attacks (SQL, NoSQL, LDAP) as REST parameters. Fuzz all GraphQL arguments with injection payloads.
- **Source**: https://hackerone.com/reports/435066

### 65. Private List Members Disclosure via GraphQL Timing Attack (Twitter/X)
- **Severity**: Medium
- **Bounty**: $2,940
- **Program**: Twitter/X
- **Platform**: HackerOne
- **Description**: By chaining a timing attack and broken rate limit with a vulnerable GraphQL query, it was possible to enumerate members of Twitter's private lists. The GraphQL endpoint responded differently for valid vs invalid list members.
- **How Found**: Identifying timing differences in GraphQL responses when querying private list memberships, then bypassing rate limits to enumerate all members.
- **Impact**: Privacy violation by revealing membership of private Twitter lists.
- **Key Takeaway**: Timing attacks on GraphQL endpoints can reveal information about private data. Test GraphQL queries for response time differences that leak membership or existence information.
- **Source**: https://hackerone.com/reports/885539

### 66. GraphQL User Object Exposes Sensitive Fields (HackerOne)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: HackerOne
- **Platform**: HackerOne
- **Description**: The User object in HackerOne's GraphQL API exposed sensitive fields that should not have been accessible to other users, including email addresses and internal identifiers.
- **How Found**: Querying the User object through GraphQL with all available fields and identifying which sensitive fields were returned without proper authorization checks.
- **Impact**: Information disclosure of user PII through the GraphQL API.
- **Key Takeaway**: GraphQL's flexible querying means clients can request any field. Each field in every type must have its own authorization check. Test all fields for unauthorized access.
- **Source**: https://hackerone.com/reports/350964

### 67. GraphQL Introspection Enabled Exposing Hidden Endpoints
- **Severity**: Medium
- **Bounty**: $500
- **Program**: On (Cloud Platform)
- **Platform**: HackerOne
- **Description**: GraphQL introspection was enabled on a cloud platform, revealing hidden mutations and queries that were not documented in the public API. These hidden endpoints had weaker security controls.
- **How Found**: Running a standard introspection query against the GraphQL endpoint and analyzing the returned schema for undocumented operations.
- **Impact**: Discovery of hidden administrative mutations that could be used for privilege escalation.
- **Key Takeaway**: Hidden doesn't mean secure. GraphQL introspection reveals all operations regardless of whether they're documented. Disable introspection in production or implement query allowlists.
- **Source**: https://hackerone.com/reports/1132803

### CRLF Injection Reports

### 68. CRLF Injection in Node.js Fetch API (CVE-2023-23936)
- **Severity**: High
- **Bounty**: $1,800
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: The Fetch API in Node.js did not prevent CRLF injection in the 'host' header, allowing HTTP response splitting and header injection. An attacker could inject arbitrary headers and potentially control the response body.
- **How Found**: Testing the Node.js Fetch API with CRLF characters (\r\n) in the Host header and observing if the injected headers appeared in the HTTP request.
- **Impact**: HTTP response splitting enabling XSS, cache poisoning, and session fixation.
- **Key Takeaway**: CRLF injection in HTTP libraries affects all applications using those libraries. Test HTTP header parameters for CRLF injection: %0d%0a, %0D%0A, \r\n.
- **Source**: https://hackerone.com/reports/1878489

### 69. CRLF Injection in urllib (Python)
- **Severity**: Medium
- **Bounty**: $500
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: Python's urllib library was vulnerable to CRLF injection, allowing exploitation against internal servers like Redis. An attacker could send arbitrary packet data including non-ASCII characters through CRLF-injected requests.
- **How Found**: Testing urllib's URL handling with CRLF characters to inject additional HTTP requests targeting internal services.
- **Impact**: SSRF-like attacks against internal services (Redis, Memcached) through CRLF injection in HTTP requests.
- **Key Takeaway**: CRLF injection in URL handling libraries can be used for SSRF-like attacks against protocol-agnostic services. Test SSRF endpoints with CRLF to target non-HTTP services.
- **Source**: https://hackerone.com/reports/590020

### 70. CRLF Injection on Twitter Ads Platform
- **Severity**: Medium
- **Bounty**: $2,520
- **Program**: Twitter/X
- **Platform**: HackerOne
- **Description**: Twitter's ads platform (ads.twitter.com) was vulnerable to HTTP response splitting through CRLF injection. An attacker could add malicious headers in the response, including setting cookies or injecting content.
- **How Found**: Testing URL parameters on the ads platform for CRLF injection by injecting %0d%0a followed by arbitrary HTTP headers.
- **Impact**: HTTP response splitting enabling session fixation through cookie injection and XSS through body injection.
- **Key Takeaway**: Advertising and analytics platforms often have many URL parameters that handle redirects and tracking, making them CRLF injection targets.
- **Source**: https://hackerone.com/reports/446271

### Path Traversal Reports (Additional)

### 71. Path Traversal in Apache HTTP Server (CVE-2021-41773)
- **Severity**: Critical
- **Bounty**: $4,000
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: A path traversal vulnerability in Apache HTTP Server 2.4.49 allowed mapping URLs to files outside directories configured by Alias-like directives. The flaw was in the path normalization logic, which could be bypassed with URL-encoded traversal sequences.
- **How Found**: Testing Apache installations with URL-encoded path traversal sequences that bypassed the new path normalization, specifically using %2e (.) to bypass traversal filters.
- **Impact**: Reading arbitrary files from the web server, and with mod_cgi enabled, remote code execution.
- **Key Takeaway**: Web server software path traversal vulnerabilities have massive impact because they affect millions of installations. Test with various encoding bypasses: %2e, %252e, ..%c0%af.
- **Source**: https://hackerone.com/reports/1394916

### 72. Path Traversal in Nuget Package Registry (GitLab)
- **Severity**: Critical
- **Bounty**: $12,000
- **Program**: GitLab
- **Platform**: HackerOne
- **Description**: A path traversal vulnerability in GitLab's Nuget Package Registry allowed reading arbitrary files from the server by manipulating the package path parameter.
- **How Found**: Testing the package path parameter with directory traversal sequences to access files outside the package storage directory.
- **Impact**: Reading arbitrary files from GitLab servers, including configuration files, source code, and credentials.
- **Key Takeaway**: Package registry and artifact storage endpoints often have path traversal vulnerabilities because they handle user-supplied file paths. Test all file path parameters for traversal.
- **Source**: https://hackerone.com/reports/1404731

### 73. Path Traversal Leads to Reading Local Files (U.S. DoD)
- **Severity**: High
- **Bounty**: N/A (VDP)
- **Program**: U.S. Department of Defense
- **Platform**: HackerOne
- **Description**: Path traversal characters in a registration parameter (registerUserInfoCommand.nextPageName) allowed attackers to read local files from a DoD server by submitting path traversal sequences.
- **How Found**: Testing form parameters that appeared to reference page/template names with directory traversal sequences (../../../etc/passwd).
- **Impact**: Reading sensitive files from DoD server infrastructure.
- **Key Takeaway**: Parameters that reference page names, templates, or include files are prime path traversal candidates. Test parameters like page, template, include, file, path, and lang.
- **Source**: https://hackerone.com/reports/1888808

### 74. LFI via Path Traversal at Starbucks Korea
- **Severity**: High
- **Bounty**: $4,000
- **Program**: Starbucks
- **Platform**: HackerOne
- **Description**: A Local File Inclusion vulnerability through path traversal on Starbucks Korea's website allowed reading server files by manipulating a URL parameter that loaded page content.
- **How Found**: Testing URL parameters that loaded dynamic content for path traversal, using sequences like ../../../../etc/passwd and its URL-encoded variants.
- **Impact**: Reading sensitive configuration files and source code from Starbucks Korea's server.
- **Key Takeaway**: International/regional versions of websites often have weaker security than the main site. Test localized versions (country-specific subdomains) for vulnerabilities patched on the main site.
- **Source**: https://hackerone.com/reports/780021

### 75. Path Traversal by Monkey-Patching Buffer Internals (Node.js)
- **Severity**: High
- **Bounty**: $1,500
- **Program**: Internet Bug Bounty
- **Platform**: HackerOne
- **Description**: A path traversal vulnerability in Node.js (CVE-2024-21896) could bypass the permission model by monkey-patching Buffer internals. This allowed reading files that should have been restricted by Node.js's experimental permission model.
- **How Found**: Analyzing Node.js's permission model implementation and finding that Buffer internals could be monkey-patched to bypass file access restrictions.
- **Impact**: Bypassing Node.js permission model to read restricted files.
- **Key Takeaway**: Security models that rely on JavaScript-level enforcement can be bypassed through prototype manipulation and monkey-patching. Test permission models for bypass through language-level features.
- **Source**: https://hackerone.com/reports/2434811

### 76. Unauthenticated LFI on DoD System
- **Severity**: Critical
- **Bounty**: N/A (VDP)
- **Program**: U.S. Department of Defense
- **Platform**: HackerOne
- **Description**: An unauthenticated Local File Inclusion vulnerability on a DoD system allowed any user without authentication to read arbitrary files from the server through a path traversal attack.
- **How Found**: Fuzzing URL parameters on publicly accessible DoD web applications with path traversal sequences.
- **Impact**: Unauthenticated access to sensitive files on government systems.
- **Key Takeaway**: Unauthenticated path traversal/LFI is critical severity because no access is required. Prioritize testing file-related parameters on unauthenticated pages.
- **Source**: https://hackerone.com/reports/2778380

### Clickjacking Reports (Additional)

### 77. Highly Wormable Clickjacking in Player Card (Twitter/X)
- **Severity**: High
- **Bounty**: $5,040
- **Program**: Twitter/X
- **Platform**: HackerOne
- **Description**: A clickjacking vulnerability in Twitter's player card functionality was wormable - clicking the malicious card would cause the victim to share the same card, propagating the attack across the platform.
- **How Found**: Testing Twitter's player card iframe embedding for X-Frame-Options/CSP bypass, then demonstrating wormable propagation through the share mechanism.
- **Impact**: Self-propagating clickjacking worm on Twitter, potentially affecting millions of users through viral spread.
- **Key Takeaway**: Clickjacking that triggers sharing or posting actions can be wormable. This escalates clickjacking from low/medium to high/critical severity.
- **Source**: https://hackerone.com/reports/85624

### 78. Clickjacking on Payment Process (Multiple)
- **Severity**: Medium
- **Bounty**: $500-$2,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Clickjacking on payment confirmation pages where the "Confirm Payment" button could be overlaid with a transparent iframe. Victims would click what they thought was a benign button but actually confirmed a payment.
- **How Found**: Checking payment confirmation pages for X-Frame-Options and CSP frame-ancestors headers, then creating a PoC overlay.
- **Impact**: Unauthorized payments by tricking users into clicking the payment confirmation button.
- **Key Takeaway**: Clickjacking on financial actions (payments, transfers, purchases) is higher severity than generic clickjacking. Focus testing on pages with irreversible financial actions.
- **Source**: Multiple bug bounty reports

### 79. Clickjacking on Kubernetes Dashboard
- **Severity**: Medium
- **Bounty**: $500
- **Program**: Kubernetes
- **Platform**: HackerOne
- **Description**: The Kubernetes Dashboard was vulnerable to clickjacking, allowing an attacker to trick an authenticated administrator into performing actions like deploying containers or modifying cluster configurations through a framed page.
- **How Found**: Checking the Kubernetes Dashboard for frame-busting headers and finding that it could be embedded in an iframe.
- **Impact**: Infrastructure manipulation through tricked administrator clicks, potentially compromising entire Kubernetes clusters.
- **Key Takeaway**: Infrastructure management dashboards (Kubernetes, Docker, Jenkins) should be tested for clickjacking. Administrative actions on infrastructure have outsized impact.
- **Source**: https://hackerone.com/reports/832593

### Other Notable Reports

### 80. GitHub Access Token Exposure in Shopify Employee Repository
- **Severity**: Critical
- **Bounty**: $5,000+
- **Program**: Shopify
- **Platform**: HackerOne
- **Description**: A GitHub access token belonging to a Shopify employee was found exposed in a repository. The token had read and write access to Shopify-owned GitHub repositories, potentially allowing source code access and modification.
- **How Found**: Scanning public and private repositories for exposed credentials using tools like truffleHog or git-secrets.
- **Impact**: Access to Shopify's source code repositories with read/write permissions, enabling backdoor insertion and intellectual property theft.
- **Key Takeaway**: Credential scanning in repositories (GitHub, GitLab, Bitbucket) is a highly effective bug bounty technique. Use truffleHog, git-secrets, and GitHub's secret scanning alerts.
- **Source**: https://hackerone.com/reports/1087489

### 81. WebSocket Cross-Site Hijacking (CSWSH)
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: WebSocket connections that relied on cookies for authentication without validating the Origin header were vulnerable to Cross-Site WebSocket Hijacking. An attacker's page could establish a WebSocket connection using the victim's cookies and read/write messages.
- **How Found**: Testing WebSocket handshake requests for Origin header validation by establishing connections from an attacker-controlled domain.
- **Impact**: Real-time data theft and command injection through hijacked WebSocket connections.
- **Key Takeaway**: WebSocket endpoints should validate the Origin header during the handshake. Test by establishing WebSocket connections from cross-origin pages and checking if authenticated data is received.
- **Source**: Multiple bug bounty reports

### 82. Server-Side Template Injection (SSTI) Leading to RCE
- **Severity**: Critical
- **Bounty**: $5,000-$25,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Server-side template injection where user input was directly concatenated into template strings, allowing execution of arbitrary code through template engine syntax (e.g., {{7*7}} for Jinja2, ${7*7} for Freemarker).
- **How Found**: Testing input fields with template engine polyglot payloads: {{7*7}}, ${7*7}, <%=7*7%>, #{7*7}, and observing if the expression was evaluated in the response.
- **Impact**: Remote code execution on the server through template engine exploitation.
- **Key Takeaway**: SSTI is often found in: email template customization, PDF generation, custom page builders, and error messages. Test with polyglot payloads that cover multiple template engines.
- **Source**: Multiple bug bounty reports

### 83. Insecure Direct Object Reference in API Leading to Data Breach
- **Severity**: Critical
- **Bounty**: $10,000+
- **Program**: Multiple
- **Platform**: Various
- **Description**: IDOR vulnerabilities in REST APIs where incrementing or modifying resource IDs in API calls allowed accessing other users' data. The API did not verify that the authenticated user owned the requested resource.
- **How Found**: Capturing API requests and modifying resource identifiers (numeric IDs, UUIDs) to reference resources belonging to other users.
- **Impact**: Mass data exfiltration of all user records through automated IDOR exploitation.
- **Key Takeaway**: Test every API endpoint that references a resource ID for IDOR. Use two accounts and try accessing Account B's resources with Account A's session.
- **Source**: Multiple bug bounty reports

### 84. JWT Algorithm Confusion Attack
- **Severity**: Critical
- **Bounty**: $3,000-$10,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: JWT implementations that accepted multiple algorithms could be exploited by changing the algorithm from RS256 to HS256. The public key (used to verify RS256 signatures) was then used as the HMAC secret for HS256, allowing token forgery.
- **How Found**: Modifying the JWT header's "alg" field from RS256 to HS256 and signing with the public key, then checking if the modified token was accepted.
- **Impact**: Complete authentication bypass through JWT token forgery.
- **Key Takeaway**: Test JWT implementations for algorithm confusion: RS256->HS256, RS256->none, and key confusion attacks. Use tools like jwt_tool for automated testing.
- **Source**: Multiple bug bounty reports

### 85. Host Header Injection Leading to Password Reset Poisoning
- **Severity**: High
- **Bounty**: $1,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Password reset functionality that used the Host header to generate password reset links could be poisoned by modifying the Host header. The victim received a password reset email with a link pointing to the attacker's domain.
- **How Found**: Sending password reset requests with a modified Host header (Host: evil.com) and checking if the reset link in the email used the attacker's domain.
- **Impact**: Account takeover through captured password reset tokens when the victim clicks the link in the poisoned email.
- **Key Takeaway**: Test password reset endpoints with modified Host, X-Forwarded-Host, and X-Host headers. Check if the reset link domain changes to match the injected host.
- **Source**: Multiple bug bounty reports

### 86. Insecure Deserialization Leading to RCE
- **Severity**: Critical
- **Bounty**: $5,000-$25,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: Insecure deserialization of user-supplied data (Java ObjectInputStream, PHP unserialize, Python pickle, .NET BinaryFormatter) allowing arbitrary code execution through crafted serialized objects with malicious gadget chains.
- **How Found**: Identifying serialized data in cookies, parameters, or request bodies (base64-encoded Java objects, PHP serialized strings), then using ysoserial or similar tools to generate exploitation payloads.
- **Impact**: Remote code execution on the server through deserialization gadget chains.
- **Key Takeaway**: Look for base64-encoded data that starts with rO0AB (Java), O: or a: (PHP), or contains BinaryFormatter references (.NET). These indicate serialized objects that may be deserializable.
- **Source**: Multiple bug bounty reports

### 87. DNS Rebinding Attack to Access Internal Services
- **Severity**: High
- **Bounty**: $2,000-$10,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: DNS rebinding attacks that bypassed SSRF protections by resolving to an external IP during validation but switching to an internal IP during the actual request. This allowed accessing internal services that were protected against SSRF.
- **How Found**: Setting up a DNS rebinding server (e.g., rbndr.us, singularity) that alternates between external and internal IP addresses, then using it in SSRF-prone parameters.
- **Impact**: Bypassing SSRF protections to access internal services, cloud metadata, and private networks.
- **Key Takeaway**: DNS rebinding bypasses IP-based SSRF protections. Use tools like singularity of origin for DNS rebinding attacks. This is effective against protections that only check the resolved IP once.
- **Source**: Multiple bug bounty reports

### 88. Mass Assignment via Hidden API Parameters
- **Severity**: High
- **Bounty**: $2,000-$10,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: API endpoints that accepted additional parameters beyond what was documented or expected. By including parameters like "role", "is_admin", "verified", or "balance" in registration or profile update requests, attackers could modify restricted attributes.
- **How Found**: Fuzzing API endpoints with additional parameters discovered through API documentation, JavaScript source code analysis, or parameter name wordlists.
- **Impact**: Privilege escalation, balance manipulation, or bypassing verification requirements through hidden parameter injection.
- **Key Takeaway**: Use tools like Arjun or Param Miner to discover hidden API parameters. Test registration, profile update, and settings endpoints with parameters like role, admin, verified, premium, balance.
- **Source**: Multiple bug bounty reports

### 89. OAuth State Parameter Missing Leading to CSRF Account Takeover
- **Severity**: High
- **Bounty**: $2,000-$5,000
- **Program**: Multiple
- **Platform**: Various
- **Description**: OAuth implementations that did not use or validate the state parameter were vulnerable to CSRF attacks. An attacker could initiate an OAuth flow with their own account and trick the victim into completing it, linking the attacker's social account to the victim's application account.
- **How Found**: Testing OAuth flows for state parameter presence and validation by removing or modifying the state parameter in the callback URL.
- **Impact**: Account takeover through forced OAuth account linking.
- **Key Takeaway**: Always test OAuth implementations for: missing state parameter, predictable state values, state reuse, and state binding to the user's session.
- **Source**: Multiple bug bounty reports

### 90. Information Disclosure via Error Messages
- **Severity**: Low-Medium
- **Bounty**: $100-$500
- **Program**: Multiple
- **Platform**: Various
- **Description**: Verbose error messages that disclosed internal information such as stack traces, database queries, file paths, server versions, and internal IP addresses. While individually low severity, this information aids in crafting more targeted attacks.
- **How Found**: Triggering errors through: invalid input types, SQL injection attempts, path traversal, large payloads, and malformed requests, then analyzing error messages for disclosed information.
- **Impact**: Information disclosure that facilitates more targeted attacks.
- **Key Takeaway**: Error messages are reconnaissance goldmines. Test for verbose errors by sending unexpected input types, extremely large values, and malformed requests. Document all disclosed information.
- **Source**: Multiple bug bounty reports

---

## Miscellaneous Hunting Methodology Summary

### Tools for Each Vulnerability Type
- **CSRF:** Burp Suite CSRF PoC generator, custom HTML forms
- **Subdomain Takeover:** subjack, nuclei, can-i-take-over-xyz, subfinder
- **Open Redirect:** OpenRedireX, manual parameter testing
- **XXE:** oxml_xxe (for Office docs), manual SVG crafting
- **CORS:** Corsy, manual Origin header testing
- **HTTP Smuggling:** HTTP Request Smuggler (Burp), smuggler.py
- **Cache Poisoning:** Param Miner (Burp Extension)
- **Path Traversal:** dotdotpwn, manual encoding bypass testing

### GitHub Resources for Bug Bounty Writeups
- **reddelexc/hackerone-reports** - Top HackerOne disclosed reports by type
- **devanshbatham/Awesome-Bugbounty-Writeups** - Curated writeup collection
- **pentester-land/bug-bounty-writeups** - Extensive writeup archive
- **EdOverflow/bugbounty-cheatsheet** - Cheatsheets by vulnerability type
- **jdonsec/AllThingsSSRF** - SSRF-specific collection
- **insecrez/Bug-bounty-Writeups** - Additional writeup repository
- **codebygk/hackerone-bug-bounty-reports** - Complete HackerOne report collection
- **jaiswalakshansh/Facebook-BugBounty-Writeups** - Facebook-specific writeups

### Key Bug Bounty Platforms
- **HackerOne** - https://hackerone.com (largest platform, public disclosures)
- **Bugcrowd** - https://bugcrowd.com (second largest, University resources)
- **Intigriti** - https://intigriti.com (European focus, good writeup blog)
- **YesWeHack** - https://yeswehack.com (European platform)
- **Synack** - https://synack.com (invite-only, higher payouts)

### Key Writeup Sources
- **Pentester Land** - https://pentester.land/writeups/ (curated writeup directory)
- **InfoSec Writeups (Medium)** - https://infosecwriteups.com/
- **PortSwigger Research** - https://portswigger.net/research
- **BugBountyHunter.com** - https://bugbountyhunter.com/disclosed/
- **Bug Bounty POC** - https://bugbountypoc.com/
- **Cristian Cornea's Top 25 Series** - Covers XSS, SSRF, IDOR, RCE, Race Conditions, CSRF, XXE, Open Redirect, Subdomain Takeover, and more
