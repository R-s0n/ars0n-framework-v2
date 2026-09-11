# Information Disclosure Bug Bounty Reports

> A collection of accepted/disclosed Information Disclosure vulnerability reports from bug bounty programs. Information disclosure is the third most common vulnerability type on HackerOne, representing ~10% of all findings.

---

### 1. GraphQL Endpoint Leaks PII of All Users (HackerOne)
- **Severity:** Critical
- **Vulnerability Type:** Information Disclosure via GraphQL
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $20,000
- **Description:** The GraphQL endpoint on HackerOne did not have access controls implemented properly, allowing any attacker to access personally identifiable information of HackerOne users including email addresses, backup hash codes, and phone numbers. The vulnerability was discovered on January 31, 2019.
- **How It Was Found:** Testing GraphQL queries with introspection to discover available fields, then querying user data fields that should be restricted.
- **Impact:** Exposure of PII (email, phone, backup codes) for all HackerOne users - a platform specifically designed for security researchers.
- **Key Takeaway:** GraphQL APIs frequently over-expose data. Use introspection to discover all available fields, then test if sensitive fields are accessible without proper authorization. Even security-focused platforms can have these issues.
- **Source:** https://hackerone.com/reports/489146

### 2. Sensitive Information Disclosure on X/Twitter
- **Severity:** High
- **Vulnerability Type:** Sensitive Information Disclosure
- **Platform:** HackerOne
- **Program:** X / xAI (formerly Twitter)
- **Bounty:** $2,940+
- **Description:** Sensitive information was disclosed through Twitter's API or web interface, exposing data that should have been restricted to authorized users only.
- **How It Was Found:** Testing API endpoints with different authentication levels and analyzing response data for sensitive fields that shouldn't be exposed.
- **Impact:** Exposure of sensitive user data from one of the largest social media platforms.
- **Key Takeaway:** Large platforms with complex APIs often expose more data than intended. Compare API responses between authenticated/unauthenticated requests and between different user roles.
- **Source:** https://hackerone.com/reports/268888

### 3. Information Disclosure in /skills Endpoint (HackerOne)
- **Severity:** Medium
- **Vulnerability Type:** Information Disclosure
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $500+
- **Description:** The /skills endpoint on HackerOne disclosed information that should not have been publicly accessible. The endpoint exposed internal data about users' skill assessments.
- **How It Was Found:** Enumerating API endpoints and testing each for information disclosure.
- **Impact:** Exposure of internal HackerOne user skill/assessment data.
- **Key Takeaway:** Enumerate all API endpoints systematically. Hidden or undocumented endpoints often lack proper access controls and expose sensitive data.
- **Source:** https://hackerone.com/reports/188719

### 4. Undisclosed Report Leak (HackerOne)
- **Severity:** Critical
- **Vulnerability Type:** Information Disclosure
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $10,000+
- **Description:** A vulnerability allowed leaking of undisclosed bug bounty reports. This is particularly severe because it exposed unpatched vulnerabilities being tracked on the HackerOne platform, providing attackers with detailed exploit information.
- **How It Was Found:** Testing report access controls and finding a way to view reports that should be restricted.
- **Impact:** Exposure of undisclosed (unpatched) vulnerability reports, potentially enabling attacks on affected companies.
- **Key Takeaway:** Report/document access controls are critical targets. Test if report IDs can be enumerated or predicted, and if access controls properly restrict visibility to authorized users only.
- **Source:** https://hackerone.com/reports/1826141

### 5. Sensitive API Key Leakage (AWS VDP)
- **Severity:** High
- **Vulnerability Type:** API Key Leakage
- **Platform:** HackerOne
- **Program:** AWS VDP
- **Bounty:** N/A (VDP)
- **Description:** AWS Access Keys and Secret Keys were leaked in a public GitHub repository associated with AWS projects. The leaked credentials could provide access to AWS services.
- **How It Was Found:** GitHub dorking - searching public repositories for exposed AWS credentials using search queries like "AKIA" (AWS access key prefix).
- **Impact:** Potential unauthorized access to AWS infrastructure using leaked credentials.
- **Key Takeaway:** GitHub dorking is a highly effective recon technique. Search for: AKIA (AWS), ghp_ (GitHub), sk- (Stripe), SG. (SendGrid), and other API key prefixes in public repositories.
- **Source:** https://hackerone.com/reports/3017105

### 6. Public and Secret API Key Leaked via Source Code (Omise)
- **Severity:** High
- **Vulnerability Type:** API Key Leakage in Source Code
- **Platform:** HackerOne
- **Program:** Omise
- **Bounty:** $500+
- **Description:** Secret keys of Omise payment accounts were discovered leaked in source code, providing access to payment processing capabilities.
- **How It Was Found:** Reviewing JavaScript source files and public repositories for hardcoded API keys.
- **Impact:** Potential unauthorized payment processing using leaked Omise API keys.
- **Key Takeaway:** Payment processor API keys are high-impact findings. Always check JavaScript files, source maps, and public repositories for payment-related credentials (Stripe, Omise, Braintree, etc.).
- **Source:** https://hackerone.com/reports/508024

### 7. Non-Revoked API Key Disclosure (Stripo Inc)
- **Severity:** Medium
- **Vulnerability Type:** API Key Disclosure
- **Platform:** HackerOne
- **Program:** Stripo Inc
- **Bounty:** $500+
- **Description:** Non-revoked API keys were discovered exposed, and the keys were still valid and could be used to access the service's API with full permissions.
- **How It Was Found:** Testing discovered API keys to verify they were still active and determining the scope of access they provided.
- **Impact:** Unauthorized API access using disclosed credentials.
- **Key Takeaway:** When you find exposed API keys, always verify if they're still active. Report both the exposure and the fact that the keys haven't been rotated/revoked.
- **Source:** https://hackerone.com/reports/1047125

### 8. Sensitive Information in GitHub Repository (Liberapay)
- **Severity:** High
- **Vulnerability Type:** Sensitive Data in Public Repository
- **Platform:** HackerOne
- **Program:** Liberapay
- **Bounty:** $500+
- **Description:** Sensitive data including AWS IDs and configuration details were leaked in Liberapay's public GitHub repository, potentially providing access to their cloud infrastructure.
- **How It Was Found:** Manual review of the organization's public GitHub repositories for sensitive data in configuration files, environment examples, and commit history.
- **Impact:** Exposure of cloud infrastructure credentials for the open-source donation platform.
- **Key Takeaway:** Check not just current files but also commit history (git log, git diff). Secrets that were committed and then removed are still visible in git history. Use tools like truffleHog or gitleaks.
- **Source:** https://hackerone.com/reports/837733

### 9. AWS Credentials Disclosure (U.S. Department of Defense)
- **Severity:** High
- **Vulnerability Type:** Cloud Credential Exposure
- **Platform:** HackerOne
- **Program:** U.S. Department of Defense
- **Bounty:** N/A (VDP)
- **Description:** A config.json file containing sensitive AWS information was discovered on a DoD web property, exposing cloud infrastructure credentials.
- **How It Was Found:** Directory/file enumeration on DoD web servers, testing common configuration file paths.
- **Impact:** Potential access to DoD AWS infrastructure using exposed credentials.
- **Key Takeaway:** Always check for common configuration files: config.json, .env, settings.py, application.yml, wp-config.php, etc. Use wordlists specifically designed for configuration file discovery.
- **Source:** https://hackerone.com/reports/1704035

### 10. AWS Access Keys Leaked in Docker Image (Mozilla)
- **Severity:** High
- **Vulnerability Type:** Cloud Credential Exposure in Container
- **Platform:** HackerOne
- **Program:** Mozilla
- **Bounty:** $500+
- **Description:** A Docker image associated with Mozilla's Common Voice project contained exposed AWS access keys, AWS secret keys, and database credentials embedded in the container layers.
- **How It Was Found:** Pulling public Docker images and analyzing all layers for sensitive data using tools like dive or docker history.
- **Impact:** Access to Mozilla's AWS infrastructure and databases.
- **Key Takeaway:** Public Docker images are an underexplored attack surface. Use tools like dive to inspect container layers, and search for secrets in environment variables, configuration files, and build artifacts within containers.
- **Source:** https://hackerone.com/reports/2401648

### 11. Sensitive Information Leak via JavaScript File (Reddit)
- **Severity:** Medium
- **Vulnerability Type:** Information Disclosure in JavaScript
- **Platform:** HackerOne
- **Program:** Reddit
- **Bounty:** $500+
- **Description:** Sensitive information including API keys and PayPal keys were leaked through a JavaScript file meant for developers. The file was accessible to all users and contained credentials that should have been server-side only.
- **How It Was Found:** Analyzing JavaScript files loaded by the web application for hardcoded secrets and sensitive configuration data.
- **Impact:** Exposure of Reddit's API credentials and payment processing keys.
- **Key Takeaway:** Always analyze JavaScript files for secrets. Use browser developer tools, JS beautifiers, and source map extractors. Search for patterns like: apiKey, secret, password, token, credential in JS files.
- **Source:** https://hackerone.com/reports/2353237

### 12. Google API Key Leaked (FetLife)
- **Severity:** Medium
- **Vulnerability Type:** API Key Exposure
- **Platform:** HackerOne
- **Program:** FetLife
- **Bounty:** $500+
- **Description:** A Google API key was leaked and tested to be vulnerable to exploitation through the Geocode API. The key was found exposed in client-side code.
- **How It Was Found:** Inspecting client-side JavaScript for Google API keys, then testing the key against all Google APIs to determine exploitable services.
- **Impact:** Unauthorized use of Google APIs at the target's expense (API billing abuse) and potential data access.
- **Key Takeaway:** When you find a Google API key, test it against all Google APIs using keyhacks or similar tools. Google API keys can be restricted by service and referrer, but many are unrestricted.
- **Source:** https://hackerone.com/reports/1065041

### 13. Valid API Key Leak (GSA Bounty - data.gov)
- **Severity:** Medium
- **Vulnerability Type:** API Key Exposure
- **Platform:** HackerOne
- **Program:** GSA Bounty
- **Bounty:** $500+
- **Description:** A valid API key for api.data.gov was leaked, providing unauthorized access to government data APIs.
- **How It Was Found:** Testing API endpoints and discovering exposed API keys in responses or documentation.
- **Impact:** Unauthorized access to government API data.
- **Key Takeaway:** Government bug bounty programs (GSA, DoD) often have information disclosure vulnerabilities in API configurations and documentation endpoints.
- **Source:** https://hackerone.com/reports/266449

### 14. Public and Secret API Keys (Top Echelon Software)
- **Severity:** High
- **Vulnerability Type:** API Key Exposure
- **Platform:** HackerOne
- **Program:** Top Echelon Software
- **Bounty:** $500+
- **Description:** Both public and secret API keys were found exposed, providing full API access to the platform.
- **How It Was Found:** Reviewing public-facing code and API documentation for leaked credentials.
- **Impact:** Unauthorized API access with full permissions.
- **Key Takeaway:** SaaS platforms often expose API keys in their client-side code, public documentation, or example code. Always check these sources.
- **Source:** https://hackerone.com/reports/1051029

### 15. AWS Keys and User Cookies Leak via librsvg (Basecamp)
- **Severity:** High
- **Vulnerability Type:** Information Disclosure via Memory Leak
- **Platform:** HackerOne
- **Program:** Basecamp
- **Bounty:** $8,868
- **Description:** An uninitialized memory leak in an outdated version of the librsvg library used by Basecamp allowed a malicious actor to gain access to sensitive information such as AWS keys and user cookies from server memory.
- **How It Was Found:** Crafting malicious SVG files that triggered the memory leak in librsvg, causing the server to return uninitialized memory contents in the response.
- **Impact:** Exposure of AWS credentials, user session cookies, and potentially other sensitive data from server memory.
- **Key Takeaway:** Memory leak vulnerabilities in image processing libraries can expose server secrets. Test SVG and image processing features with crafted files designed to trigger memory leaks. Outdated libraries are particularly vulnerable.
- **Source:** Referenced in HackerOne blog about information disclosure

### 16. Source Code Disclosure via .git Exposure
- **Severity:** High
- **Vulnerability Type:** Source Code Disclosure
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$5,000
- **Description:** Exposed .git directories on production web servers allow attackers to download the complete source code, including configuration files, hardcoded credentials, and proprietary business logic.
- **How It Was Found:** Testing for /.git/HEAD and /.git/config on target domains. Using tools like git-dumper to reconstruct the repository.
- **Impact:** Complete source code exposure including embedded secrets, database credentials, and API keys.
- **Key Takeaway:** Always test for exposed .git directories. Use tools like git-dumper, GitHack, or manual checks for /.git/HEAD. Also check for: .svn, .hg, .DS_Store, and backup files (.bak, ~).
- **Source:** Multiple bug bounty reports

### 17. Environment File Exposure (.env)
- **Severity:** Critical
- **Vulnerability Type:** Configuration File Exposure
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $1,000-$10,000
- **Description:** Exposed .env files on production servers containing database credentials, API keys, application secrets, mail server credentials, and third-party service tokens.
- **How It Was Found:** Directly accessing /.env on target domains. Using wordlists to discover environment files at various paths.
- **Impact:** Complete application compromise through exposed production credentials.
- **Key Takeaway:** .env file exposure is one of the highest-impact, lowest-effort findings. Always check for /.env, /.env.production, /.env.local, and similar files. Automate this check across all discovered subdomains.
- **Source:** Multiple bug bounty reports

### 18. Server Status/Debug Pages Exposure
- **Severity:** Medium
- **Vulnerability Type:** Information Disclosure
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $500-$2,000
- **Description:** Server status pages, debug endpoints, and monitoring dashboards left exposed on production servers, revealing internal architecture, software versions, database connections, and request patterns.
- **How It Was Found:** Checking common debug/status paths: /server-status, /debug, /actuator, /elmah, /trace, /phpinfo.php, /metrics, /health, /_debug.
- **Impact:** Internal architecture disclosure, software version enumeration for targeted exploits.
- **Key Takeaway:** Check for framework-specific debug endpoints: Spring Boot Actuator (/actuator), Django Debug (/debug), PHP Info (/phpinfo.php), Apache Server Status (/server-status), and Kubernetes endpoints (/metrics).
- **Source:** Multiple bug bounty reports

### 19. Stack Trace Information Disclosure
- **Severity:** Low-Medium
- **Vulnerability Type:** Error-based Information Disclosure
- **Platform:** Various
- **Program:** Multiple
- **Bounty:** $100-$500
- **Description:** Applications returning detailed stack traces in error responses, revealing: framework versions, file paths, database connection strings, internal IP addresses, and code structure.
- **How It Was Found:** Triggering errors through: malformed input, invalid parameters, accessing non-existent resources, and sending unexpected data types.
- **Impact:** Information useful for crafting more targeted attacks against the application.
- **Key Takeaway:** While low severity alone, stack traces provide valuable reconnaissance data. Document them and use the information (paths, versions, internal IPs) to find more impactful vulnerabilities.
- **Source:** Multiple bug bounty reports

### 20. Partial Disclosure via Export Feature (HackerOne)
- **Severity:** High
- **Vulnerability Type:** Information Disclosure
- **Platform:** HackerOne
- **Program:** HackerOne
- **Bounty:** $10,000
- **Description:** The "Export as .zip" feature on HackerOne allowed partial disclosure of report activity. The export included data from reports that the user should not have had access to view.
- **How It Was Found:** Testing the export/download functionality to see if it included data beyond the user's authorized access scope.
- **Impact:** Leak of private report activity data from HackerOne's vulnerability disclosure platform.
- **Key Takeaway:** Export, download, and backup features often include more data than the UI shows. Always compare exported data against what's visible in the UI - exports may bypass access controls.
- **Source:** Referenced in HackerOne Top 100 Paid Reports

---

## Information Disclosure Hunting Methodology Summary

### Tools Commonly Used
- **truffleHog** - Git repository secret scanning
- **gitleaks** - Secret detection in git repos
- **git-dumper** - Download exposed .git directories
- **LinkFinder** - Extract endpoints from JavaScript files
- **SecretFinder** - Find secrets in JavaScript files
- **Nuclei** - Template-based info disclosure scanning
- **keyhacks** - API key validation
- **dive** - Docker image layer analysis

### Common Information Disclosure Locations
1. JavaScript files (API keys, endpoints, secrets)
2. Source maps (.map files)
3. Configuration files (.env, config.json, etc.)
4. Public repositories (GitHub, GitLab, Bitbucket)
5. Docker images and container registries
6. Debug/status pages
7. Error messages and stack traces
8. API responses (over-exposed data)
9. GraphQL introspection
10. Export/download features
11. Backup files (.bak, .old, ~)
12. Documentation endpoints (/swagger, /api-docs)
